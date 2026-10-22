# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-22

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 696 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 696 |
| Unique family labels | 16 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 53 |
| CoinMiner | 9 |
| AgentTesla | 8 |
| XWorm | 7 |
| RemcosRAT | 4 |
| Prometei | 4 |
| Formbook | 3 |
| DonutLoader | 2 |
| Mirai | 2 |
| RustyStealer | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 49 |
| js | 29 |
| hta | 7 |
| elf | 6 |
| vbs | 3 |
| msi | 2 |
| dll | 1 |
| zip | 1 |
| sh | 1 |
| 7z | 1 |

## Per-Sample Analysis

### Sample 1: `3abb5c118d4c9659`

| Field | Value |
|---|---|
| SHA-256 | `3abb5c118d4c965918f8b7c44240800e91f9b9ace127f31c9eb423d26b2e83e6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:57:47` |
| Reporter | `Bitsight` |
| Tags | `b89d843f29af2eed09805e9767a1165f, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cff9f44d1960f8a3813dad1a4927c96b` |
| SHA-1 | `d9d0943bb9f04e572a076f4c8f4ddaefe4da13ff` |
| SHA-256 | `3abb5c118d4c965918f8b7c44240800e91f9b9ace127f31c9eb423d26b2e83e6` |
| SHA3-384 | `8d38903fe0c5ab5f735c7141a10ee222adb63c22cd12e5346f682fdadfe5032881bbfd80fafc96dc42680e3770c0aa49` |
| IMPHASH | `8b6718def50cf784367cbc35beae8b5f` |
| TLSH | `T11B479E51B30B55F2FA434C3785F6AB7F7B35EE9CCDB0C45AE4243816B662C0A869C291` |
| SSDEEP | `196608:XGb+nINub6xKueyqLEbrdU19v0qqXFXi+Y4vSlKbWH93II9TZbkhPXfnJih8d3i:XtINbKiOOC1REYcSld93DPbkhPX8h8Ji` |
| ICON-DHASH | `b2b2b270f0b2aae0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_3abb5c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3abb5c118d4c965918f8b7c44240800e91f9b9ace127f31c9eb423d26b2e83e6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:57:47"
  condition:
    hash.sha256(0, filesize) == "3abb5c118d4c965918f8b7c44240800e91f9b9ace127f31c9eb423d26b2e83e6"
}
```

### Sample 2: `518e6f31fb564e55`

| Field | Value |
|---|---|
| SHA-256 | `518e6f31fb564e5542f81afd0117e22db06e37e41094a675666748b5684908a2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:57:42` |
| Reporter | `Bitsight` |
| Tags | `d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90b3cb5574978f799637175440fa16b1` |
| SHA-1 | `f78e435ffb262df6381d9ec68c0703ce86fdf242` |
| SHA-256 | `518e6f31fb564e5542f81afd0117e22db06e37e41094a675666748b5684908a2` |
| SHA3-384 | `6fc055b0ed4fd8db0d7964442f72fa34bda216d699f45edce034138730c576ec923a449951197652791f946f292c1852` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1A2471229A78711FFC32682305568B361FD2E9E64A104CD3AD7A9D27D3CB1C2E68C57E1` |
| SSDEEP | `786432:gLLLLLLLLLLLLLLLLLLLLLLLLLLLLLvRVwCCuVFjy68tubn+ChU:gLLLLLLLLLLLLLLLLLLLLLLLLLLLLLfm` |
| ICON-DHASH | `68e1d8d2dededea2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_518e6f31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "518e6f31fb564e5542f81afd0117e22db06e37e41094a675666748b5684908a2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:57:42"
  condition:
    hash.sha256(0, filesize) == "518e6f31fb564e5542f81afd0117e22db06e37e41094a675666748b5684908a2"
}
```

### Sample 3: `657ae1b645a957f7`

| Field | Value |
|---|---|
| SHA-256 | `657ae1b645a957f7eedc135c1313705287299ddcee2a48ada12cd4a1890b0472` |
| Family label | `unknown` |
| File name | `Zjckk0.hta` |
| File type | `hta` |
| First seen | `2026-10-22 04:57:26` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ceb589e1c4b98de60a31898d69e6cd8` |
| SHA-1 | `6ce675f2402e8297a26e61be246855179449122b` |
| SHA-256 | `657ae1b645a957f7eedc135c1313705287299ddcee2a48ada12cd4a1890b0472` |
| SHA3-384 | `465dcfb54a9dd64da8e8231b81c375d183d50a69f930facd11495027c0b576c413c5a015cd6b22533c9f8b54a5deb292` |
| TLSH | `T1ED42185CAE9171B0EA1707CEB3AF28690228A0C7240DC484F94CDEE87F467DC4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzjbqFtCvSfRUM:sXX+/DV7k/3iFtFRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_657ae1b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "657ae1b645a957f7eedc135c1313705287299ddcee2a48ada12cd4a1890b0472"
    family = "unknown"
    file_name = "Zjckk0.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:57:26"
  condition:
    hash.sha256(0, filesize) == "657ae1b645a957f7eedc135c1313705287299ddcee2a48ada12cd4a1890b0472"
}
```

### Sample 4: `6693ae9274c9c218`

| Field | Value |
|---|---|
| SHA-256 | `6693ae9274c9c218b9d5ff34714d848c53d5ce86af3b7e45b11092c14af8eeaa` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:52:09` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23ea7a6c5e3713c850c301c11feaedb0` |
| SHA-1 | `3272c85c07aff8fc8e84ab40ef12bd9979a397a7` |
| SHA-256 | `6693ae9274c9c218b9d5ff34714d848c53d5ce86af3b7e45b11092c14af8eeaa` |
| SHA3-384 | `4b164d03ce749115683f7f1dc84e6e8f071d990a3b233ab2d8fbed3b2423d413d90692cc90bf33f47a6e8de2099117a1` |
| IMPHASH | `cab689c1923db5f193818ba0c4e014b9` |
| TLSH | `T1F347AF51B30B05F6FF474C3645F9AB2F7B39E2DCC9B4C55AE8282426B6A2C1B45DC290` |
| SSDEEP | `393216:faN7FWzRDqd8JTLkGNUFFQd7tRDuH8fWzV:SNOqdSLUrabfu` |
| ICON-DHASH | `69e09c96969ee869` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_6693ae92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6693ae9274c9c218b9d5ff34714d848c53d5ce86af3b7e45b11092c14af8eeaa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:52:09"
  condition:
    hash.sha256(0, filesize) == "6693ae9274c9c218b9d5ff34714d848c53d5ce86af3b7e45b11092c14af8eeaa"
}
```

### Sample 5: `43794938628413be`

| Field | Value |
|---|---|
| SHA-256 | `43794938628413beb07fc0d0d7033bf610c0b2536374d65b9c9156fd4e04a619` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:47:16` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5717d8f8ab43c905b0e31832761804df` |
| SHA-1 | `b8ee06453879f423a045e89238eb2b930ed0718c` |
| SHA-256 | `43794938628413beb07fc0d0d7033bf610c0b2536374d65b9c9156fd4e04a619` |
| SHA3-384 | `3993bd729f228fd56a0e6a92240d2a393a245486728e0c244c6e810a6922daf968bdcbf416e0ada518f4d4ba2aa47f01` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T18B36225DB75364EFC36BC2302038A761FC6CED6468049A3AA258D5FE7EB0C6E18D56D0` |
| SSDEEP | `49152:c2aaa4TNg+rssUDwtg144eA3ZIJOgFPmHG5Os:cvOesUDwy1piAgFU9s` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_43794938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43794938628413beb07fc0d0d7033bf610c0b2536374d65b9c9156fd4e04a619"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:47:16"
  condition:
    hash.sha256(0, filesize) == "43794938628413beb07fc0d0d7033bf610c0b2536374d65b9c9156fd4e04a619"
}
```

### Sample 6: `2c96e15a4937a52c`

| Field | Value |
|---|---|
| SHA-256 | `2c96e15a4937a52c49d72f652f7b29eccbebe381c824ffe4599427e9c43145ff` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:47:15` |
| Reporter | `Bitsight` |
| Tags | `d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1efa7bcb8398d9b00b95e4abed8db9b` |
| SHA-1 | `b6876736aab2475488e93c83db454a27e51882c6` |
| SHA-256 | `2c96e15a4937a52c49d72f652f7b29eccbebe381c824ffe4599427e9c43145ff` |
| SHA3-384 | `24be1e22ed0f504f2f168437f51832f2e731d6cb86cc554f6c01e2d5de516e0200ed23bfb6212feda291391586e76b5f` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T18C471229638751EBD36A8230597CB761FD2EDA64A148CD3AD79DC17C3DB1C2E28C12E1` |
| SSDEEP | `393216:AnDE2sZ+HEFb9ZERneJDyBoEePJu/ZCNJUb/Tc9R4neqbb:ADoZHQeJDIo1Po/Zgcrbb` |
| ICON-DHASH | `34f0d4c4dcd4c0d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_2c96e15a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c96e15a4937a52c49d72f652f7b29eccbebe381c824ffe4599427e9c43145ff"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:47:15"
  condition:
    hash.sha256(0, filesize) == "2c96e15a4937a52c49d72f652f7b29eccbebe381c824ffe4599427e9c43145ff"
}
```

### Sample 7: `7680367b549cecea`

| Field | Value |
|---|---|
| SHA-256 | `7680367b549ceceac66de8e7204c0efa42aeb12044736ae131cc022c08ea901b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:43:46` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ffc7240ec3a0f941043b0720f680336` |
| SHA-1 | `ace71a4235e522c80bddcfed704bb3888cae9049` |
| SHA-256 | `7680367b549ceceac66de8e7204c0efa42aeb12044736ae131cc022c08ea901b` |
| SHA3-384 | `d59deebfc4305f54418cb93293fe24cb09c37ac57f85597a34ba40451ae349e69ff026eb5353383a7dd51480b23159f4` |
| IMPHASH | `07fbfb225bd4c799d133f3c0cbbf0ab5` |
| TLSH | `T10A47A051B30B05F6FF434C3645F9AB2F7B39E2DC8974C55AE428242ABAA3C1B45DC291` |
| SSDEEP | `196608:2rncNPzoJ7iQQsvxRMmPUTQkMDeIx3rMDee9NNr20JrVFjlQL8CjmyXnbGDUyAa4:2SI7RNLdIVIBHe395jlQYCjTrldToO3` |
| ICON-DHASH | `68f0e8e8e8f8f864` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_7680367b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7680367b549ceceac66de8e7204c0efa42aeb12044736ae131cc022c08ea901b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:43:46"
  condition:
    hash.sha256(0, filesize) == "7680367b549ceceac66de8e7204c0efa42aeb12044736ae131cc022c08ea901b"
}
```

### Sample 8: `7255e4518c564e44`

| Field | Value |
|---|---|
| SHA-256 | `7255e4518c564e44c5969159e4837b32d7663d61a14e7c7eea41e300281ecd8c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:38:58` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ebe3a90ced42bffdd8ac736ea52e872` |
| SHA-1 | `c185aed3c609dec73ac1fd4229f0c4514fbf4ca5` |
| SHA-256 | `7255e4518c564e44c5969159e4837b32d7663d61a14e7c7eea41e300281ecd8c` |
| SHA3-384 | `a2527f573f97183d4bc09f5e876ebc4b91937685dbd2eecefb80c0a9e90d04ebf40a6c5aec93ffbb5d9a3272aba2a01a` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1D7471229A74752DFC2668230657C7761FC2EDA64A108CD3AC7ADD17D3CB1C2E68C16E2` |
| SSDEEP | `786432:ykoQg8nOYfV0qyiis23+0BvWWWWWWWWWWWWWWWWWWWWJ:W8uqynl1BvWWWWWWWWWWWWWWWWWWWWJ` |
| ICON-DHASH | `ccecc0b0c6ce8aa0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_7255e451
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7255e4518c564e44c5969159e4837b32d7663d61a14e7c7eea41e300281ecd8c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:38:58"
  condition:
    hash.sha256(0, filesize) == "7255e4518c564e44c5969159e4837b32d7663d61a14e7c7eea41e300281ecd8c"
}
```

### Sample 9: `a118143f763076e1`

| Field | Value |
|---|---|
| SHA-256 | `a118143f763076e136fc76d724fa038eef2be77485441132f661b35e60e793c7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:36:42` |
| Reporter | `Bitsight` |
| Tags | `d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68cd5dbfdec1ed3398757b042ae44357` |
| SHA-1 | `5d544cc040a9c6eb5864cf561f9340b7b9449213` |
| SHA-256 | `a118143f763076e136fc76d724fa038eef2be77485441132f661b35e60e793c7` |
| SHA3-384 | `1692044c61125e2ef93269a4e78f715ba331ad104ccc37b25a7760efc17701a8bdb62d3cb9eea603a138d43f9a1955b9` |
| IMPHASH | `f68931e4dca7c1698e29ab2a7d066c64` |
| TLSH | `T19847AF51F30B05F6FF434C3645F96B2F7B39E2DC89B4C55AE8282426BAA2C1B45DC291` |
| SSDEEP | `393216:9DSd+ZRspLk0SUX0uNrbvVrp1S+9R0jWn:5KdWUZr5rW+POI` |
| ICON-DHASH | `a44626a6feb6f068` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_a118143f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a118143f763076e136fc76d724fa038eef2be77485441132f661b35e60e793c7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:36:42"
  condition:
    hash.sha256(0, filesize) == "a118143f763076e136fc76d724fa038eef2be77485441132f661b35e60e793c7"
}
```

### Sample 10: `0429da8788c6e83d`

| Field | Value |
|---|---|
| SHA-256 | `0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8` |
| Family label | `unknown` |
| File name | `0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8.exe` |
| File type | `dll` |
| First seen | `2026-10-22 04:34:28` |
| Reporter | `Tuxxin` |
| Tags | `dll, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be24bad876ca05fdfa06ce271a9b9a19` |
| SHA-1 | `f98cfd1581e04ff6db7fcfe87de490643aa52ec0` |
| SHA-256 | `0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8` |
| SHA3-384 | `a0c35cb44cc01fdc3f48631f365d59009aa0947be5fa34048849c2aaef7d3f9e7bfa10737f26ff88984cff796c171a01` |
| IMPHASH | `c900fb0ea41d2f103a0e49dfffec4411` |
| TLSH | `T1A5053A23B221C8A1E2252BB917B6133879B883552C748D13DFE4FDB1BCB1563CB5A50E` |
| SSDEEP | `24576:G/4ckiTbjSc7OClo8TgOqDq98inHPIZNnr5Zi82xWNIkMYtDIdCO8cuKavExS:Gwajecw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_0429da87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8"
    family = "unknown"
    file_name = "0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8.exe"
    file_type = "dll"
    first_seen = "2026-10-22 04:34:28"
  condition:
    hash.sha256(0, filesize) == "0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8"
}
```

### Sample 11: `5385aa4f7cab53dc`

| Field | Value |
|---|---|
| SHA-256 | `5385aa4f7cab53dced79c1d73cbcc7b5e209705293781731b4aa94faf560378d` |
| Family label | `unknown` |
| File name | `teach.hta` |
| File type | `hta` |
| First seen | `2026-10-22 04:33:40` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a05b142132883d099de468ef7398bb1` |
| SHA-1 | `df48e4f8c7d7aad15d9c95532edf6ddcf182ee7b` |
| SHA-256 | `5385aa4f7cab53dced79c1d73cbcc7b5e209705293781731b4aa94faf560378d` |
| SHA3-384 | `a556c16cb7a3bc605d4b27368c50712f96e868d5e3df7c38caaca1ee5d06fba4df0524b76832b74120afecafa86ea97a` |
| TLSH | `T1EF42085CAED1A1A0FA1707DEB3AF24690228A0C7240DC484F94CDDE87F46BDD4A57B56` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtC3SeRUM:sXX+/DV7k/3IFtoRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_5385aa4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5385aa4f7cab53dced79c1d73cbcc7b5e209705293781731b4aa94faf560378d"
    family = "unknown"
    file_name = "teach.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:33:40"
  condition:
    hash.sha256(0, filesize) == "5385aa4f7cab53dced79c1d73cbcc7b5e209705293781731b4aa94faf560378d"
}
```

### Sample 12: `4adb8b4f38f0199a`

| Field | Value |
|---|---|
| SHA-256 | `4adb8b4f38f0199a238831a9c8892bae329b8737e5c00d26eaf072b8b4e43106` |
| Family label | `unknown` |
| File name | `DAS_London_2026_Programme.zip` |
| File type | `zip` |
| First seen | `2026-10-22 04:33:06` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1dcc40ddf65d338fd250de1b280db1a` |
| SHA-1 | `0d53708e600f4aa8f7e5b6daedd34126f764e21a` |
| SHA-256 | `4adb8b4f38f0199a238831a9c8892bae329b8737e5c00d26eaf072b8b4e43106` |
| SHA3-384 | `38fb1fc4adbaec5be1d542c8b7f9fd8d6a3bb47cbbf14d55e45b22c4abe04cf2f2080f8633492f4883f3bae9e87432be` |
| TLSH | `T10AC42365CC17229B4B22607F1C44D37AAEB16233B010F84B96693DB21EAD9E56EF171C` |
| SSDEEP | `12288:D2nmjG3l6ggy/rUqhRIQefCaCP/KgeMW883mEIi7nX8Wx6FG:Dp63l6jqhRIUyMWcEN7nNxkG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_4adb8b4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4adb8b4f38f0199a238831a9c8892bae329b8737e5c00d26eaf072b8b4e43106"
    family = "unknown"
    file_name = "DAS_London_2026_Programme.zip"
    file_type = "zip"
    first_seen = "2026-10-22 04:33:06"
  condition:
    hash.sha256(0, filesize) == "4adb8b4f38f0199a238831a9c8892bae329b8737e5c00d26eaf072b8b4e43106"
}
```

### Sample 13: `57f4a4237a2b796d`

| Field | Value |
|---|---|
| SHA-256 | `57f4a4237a2b796dc8a4b49df6dd2d769ac170124544d5c5e3508b741e912d64` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:31:54` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4efe21e94e934d11d189a5033c88ff6` |
| SHA-1 | `1e5bfa55dce6ef95c8c30e49eee10632c56a3c1a` |
| SHA-256 | `57f4a4237a2b796dc8a4b49df6dd2d769ac170124544d5c5e3508b741e912d64` |
| SHA3-384 | `885e89e3365a59820eb37d323db6049c8754533c3092333baf012ecb1e4ae3ef364d42cc9567e3183ebfafcf60203f04` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T164470229A34BC2DBC2168230D56867F1FC2E9D64E5048D7BD799BD7D3CB1C2A28C52E1` |
| SSDEEP | `393216:hZQTC+42VSnCKhuCQJA8CRCZNC/hoz3yZE7E3KSb/Oj:Hk1muCQK8yC3C/civ6` |
| ICON-DHASH | `d4c4e4c4c4c4d4c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_57f4a423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57f4a4237a2b796dc8a4b49df6dd2d769ac170124544d5c5e3508b741e912d64"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:31:54"
  condition:
    hash.sha256(0, filesize) == "57f4a4237a2b796dc8a4b49df6dd2d769ac170124544d5c5e3508b741e912d64"
}
```

### Sample 14: `9b8b09939d0f2ee4`

| Field | Value |
|---|---|
| SHA-256 | `9b8b09939d0f2ee47d6211c24f6a217b0bb75a0693c3d8771aa7384199f462bf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:31:35` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0543307e03b1c203da429090b553ed4` |
| SHA-1 | `c76a708b9989931e6905f3eb2b27bd0f3c6aed64` |
| SHA-256 | `9b8b09939d0f2ee47d6211c24f6a217b0bb75a0693c3d8771aa7384199f462bf` |
| SHA3-384 | `48807e01d369c83542205c625870ae221620f4f35d6208f0fabec0e46388434be33c915d30ff19ea909689831d861df9` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T12B26232EBB6714DBC31B4270593866A5FD2DAE383144DE39C754E0BD3CA6C2E68C52E1` |
| SSDEEP | `24576:9XqlhrqIGhTXhEhod1sFAAkSL6E3zuKkNqWaMeox8b/uWvr9tmYbTv9d6MakFY:sCTEo/gZL1DpeqWaMi/uyrPz76Mak+` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_9b8b0993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b8b09939d0f2ee47d6211c24f6a217b0bb75a0693c3d8771aa7384199f462bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:31:35"
  condition:
    hash.sha256(0, filesize) == "9b8b09939d0f2ee47d6211c24f6a217b0bb75a0693c3d8771aa7384199f462bf"
}
```

### Sample 15: `ae3ffc422756fc80`

| Field | Value |
|---|---|
| SHA-256 | `ae3ffc422756fc80ae1a999f2dff86e8624b0fef48b8ca5241a8fd75aabb7139` |
| Family label | `unknown` |
| File name | `fuck_niggers_8.hta` |
| File type | `hta` |
| First seen | `2026-10-22 04:29:38` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2d77ad40511bcba159c0df1803acd94` |
| SHA-1 | `a166189f7de30643de352a9cac9fa261cf3450eb` |
| SHA-256 | `ae3ffc422756fc80ae1a999f2dff86e8624b0fef48b8ca5241a8fd75aabb7139` |
| SHA3-384 | `d032c46415ec8b10ca19283941417d7c18e6cd4eac08608c6b5a63d0c3afce9de8ae9fcb444868ff64575be58fd4f69f` |
| TLSH | `T1D5422A4CAED1B2B0EA0307DEB7AF28690228A0D72409C484F54CDDE87F4A7DD4A57B56` |
| SSDEEP | `192:shHNsGeTHQpD+da6+888+UV7tDoj/pxzCbqFtCSSIRUzH3:shX+/DV7k/3RFtPRUzH3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_ae3ffc42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae3ffc422756fc80ae1a999f2dff86e8624b0fef48b8ca5241a8fd75aabb7139"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:29:38"
  condition:
    hash.sha256(0, filesize) == "ae3ffc422756fc80ae1a999f2dff86e8624b0fef48b8ca5241a8fd75aabb7139"
}
```

### Sample 16: `fa9fe2e09ef917f1`

| Field | Value |
|---|---|
| SHA-256 | `fa9fe2e09ef917f1dde379d35f0c235f7b0b7c45aa4483d47e9f4b27ac8b61a8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:28:27` |
| Reporter | `Bitsight` |
| Tags | `b89d843f29af2eed09805e9767a1165f, c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53ad22960ad6a620929ef40dc0341bc5` |
| SHA-1 | `6d0f8c7f5a298a57a85498c9a4eac1e40cb1a686` |
| SHA-256 | `fa9fe2e09ef917f1dde379d35f0c235f7b0b7c45aa4483d47e9f4b27ac8b61a8` |
| SHA3-384 | `52b0c10bf48326210a011b241962bf7b438cd263366a623530bb9b426bc13faa06d1efb7109126dbb862ca3e53a2e3bd` |
| IMPHASH | `b5b817630f2cce2d94b13308207a1991` |
| TLSH | `T18557AF51F30B05F6FF435C3645F9AB2F7B39E2DC89B4C556E828242ABA62C1B45CC291` |
| SSDEEP | `393216:3V5yq0QLoKWuNoHuWUuNr3TkTuOSYWFLUgb+gcqXtmL3z:FwQoLDDT7Y7gK7` |
| ICON-DHASH | `68e8e8e8f8f8e868` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_fa9fe2e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa9fe2e09ef917f1dde379d35f0c235f7b0b7c45aa4483d47e9f4b27ac8b61a8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:28:27"
  condition:
    hash.sha256(0, filesize) == "fa9fe2e09ef917f1dde379d35f0c235f7b0b7c45aa4483d47e9f4b27ac8b61a8"
}
```

### Sample 17: `09a07d2b5b6807b3`

| Field | Value |
|---|---|
| SHA-256 | `09a07d2b5b6807b3b84f5921b7686dd9bbb398156aff145d42d7e0f6b16552b5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:25:50` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b0d70e5069c09e493a28c5bc6911045` |
| SHA-1 | `76a867c5a985a1e3272a128307cee1907701f536` |
| SHA-256 | `09a07d2b5b6807b3b84f5921b7686dd9bbb398156aff145d42d7e0f6b16552b5` |
| SHA3-384 | `65562b0b1269d72a176ff5acbe75c752d35e8d3cdd437df8e84d77a457c793415010aa590842b01c856fcc662cf62d37` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1BC471229A74B41DFC36A8270597CB361FD2E99646208CD3AC79DC1BD3DB1C2E68C52E1` |
| SSDEEP | `393216:s/HF8rnjRXWsXLzd5ztGqe2e+rNpMkHoCYhXZTGpogwPkgXWbYm:s6jRv1Gqe9+5ptHoRJLk` |
| ICON-DHASH | `69f0b4d2eadae868` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_09a07d2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09a07d2b5b6807b3b84f5921b7686dd9bbb398156aff145d42d7e0f6b16552b5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:25:50"
  condition:
    hash.sha256(0, filesize) == "09a07d2b5b6807b3b84f5921b7686dd9bbb398156aff145d42d7e0f6b16552b5"
}
```

### Sample 18: `f4d5edf20c2bd45c`

| Field | Value |
|---|---|
| SHA-256 | `f4d5edf20c2bd45c2851f128c3ba36e1f72b6db0256ab58695b7c74155740592` |
| Family label | `unknown` |
| File name | `bot.exe` |
| File type | `exe` |
| First seen | `2026-10-22 04:24:36` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a000188c1a36ff6aaa661d3341bd8ab` |
| SHA-1 | `0880200a9901e7ab7250dc60d6c4f05faa50592c` |
| SHA-256 | `f4d5edf20c2bd45c2851f128c3ba36e1f72b6db0256ab58695b7c74155740592` |
| SHA3-384 | `8b2c83f69eaca85bae6dc465d29311f6a2869770a37df6f85fa9c5892fe7e9b62e197919db61d47e252d8f5729be2acd` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T10C564803ECA519E9C1AED271C9669253BB317C891B2127D71B60F2382F77BD4ADB8350` |
| SSDEEP | `49152:A08VFzeMCABZwmIo8ZT3FO46xlPErnk7wB8ATbYB5FdGMBPRyKhK5KwPswClD5E:A9x7NIhSlPED9by5FdYPOE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_f4d5edf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d5edf20c2bd45c2851f128c3ba36e1f72b6db0256ab58695b7c74155740592"
    family = "unknown"
    file_name = "bot.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:24:36"
  condition:
    hash.sha256(0, filesize) == "f4d5edf20c2bd45c2851f128c3ba36e1f72b6db0256ab58695b7c74155740592"
}
```

### Sample 19: `d803331dab484a40`

| Field | Value |
|---|---|
| SHA-256 | `d803331dab484a405d5aa81e7c7df7b56e0f6ef7e0c91e6a38a82a437453574c` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:19:48` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5128498f056094b6260afecfcad57f4d` |
| SHA-1 | `54f04e27966b07bee0ddaf5cd1815851b46cc649` |
| SHA-256 | `d803331dab484a405d5aa81e7c7df7b56e0f6ef7e0c91e6a38a82a437453574c` |
| SHA3-384 | `f83a6812b36d024c024fecb22037b60a67b49fe30838764c7e192eadd36aaa87c571df53efb60d4d4fcc33459d38c8b6` |
| IMPHASH | `2379a16f3b26c3a7fc63087b9fbd0412` |
| TLSH | `T11347AF51B30B05F6FF434C3645F9AB2F7B39E2DC8974C55AE428242ABAA2C1F45DC291` |
| SSDEEP | `393216:3lLT2Ubczm+R6clm4MOpftlL/ksGnZhhP//e1YePutm+X:d6JDB7L/khZD/2lu5X` |
| ICON-DHASH | `68c8b4e4ccd8f068` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_019_d803331d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d803331dab484a405d5aa81e7c7df7b56e0f6ef7e0c91e6a38a82a437453574c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:19:48"
  condition:
    hash.sha256(0, filesize) == "d803331dab484a405d5aa81e7c7df7b56e0f6ef7e0c91e6a38a82a437453574c"
}
```

### Sample 20: `0e3392e6bf176620`

| Field | Value |
|---|---|
| SHA-256 | `0e3392e6bf176620e49f37376257f090fba94f8d5b8bf841113e494a0f0e56ab` |
| Family label | `RevStealer` |
| File name | `gM9anpOuZNKX8zHj.exe` |
| File type | `exe` |
| First seen | `2026-10-22 04:19:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fc25011a6c1244075771fda85f3f81a` |
| SHA-1 | `c775f86b254c643412f7a7ef7caab2e9e685c24b` |
| SHA-256 | `0e3392e6bf176620e49f37376257f090fba94f8d5b8bf841113e494a0f0e56ab` |
| SHA3-384 | `fc15ae1cf5059c7e1ed6b2fe28d6b61d6aece656e26c0c20f495077dd962f007c8543680dfbf94ff87ed218ebc27ba39` |
| IMPHASH | `001b63852a413bf6eef528d920bb10b4` |
| TLSH | `T1BCD5239AFCB702B4F83BC7774697606D71293B6147B05D5B3ACD1B202CA26182C763B6` |
| SSDEEP | `49152:DfCiXIbETmsRUoHkYq4g5148rUp62N+apHPWLHFttknh+T40/4RQq5kPD4JP1:DfZXIbsmsWoEl4g5148S/oWPwLtkzRQo` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_020_0e3392e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3392e6bf176620e49f37376257f090fba94f8d5b8bf841113e494a0f0e56ab"
    family = "RevStealer"
    file_name = "gM9anpOuZNKX8zHj.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:19:43"
  condition:
    hash.sha256(0, filesize) == "0e3392e6bf176620e49f37376257f090fba94f8d5b8bf841113e494a0f0e56ab"
}
```

### Sample 21: `7e2e689411d97d6c`

| Field | Value |
|---|---|
| SHA-256 | `7e2e689411d97d6c43cad212d3eb11c7dc06062e3137ccd5d6ad156396872e9c` |
| Family label | `unknown` |
| File name | `fuck_niggers_8.hta` |
| File type | `hta` |
| First seen | `2026-10-22 04:17:29` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2440d712bcf46bc0db3131ae4fe7b2e` |
| SHA-1 | `2501964253a8f10d02387db9830853704ef2b405` |
| SHA-256 | `7e2e689411d97d6c43cad212d3eb11c7dc06062e3137ccd5d6ad156396872e9c` |
| SHA3-384 | `efaea148b92ee963b9c76cefea482554a42db4cedcb6d7328d0ec75a5ce0972e5f7fc5c27d456b13396bdc2efb302bac` |
| TLSH | `T11742195CAED161B0EB1707DEB7AF24690228A0C7240DC484F54CEDE8BF46BDC4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtC3S5pRUM:sXX+/DV7k/3IFtpRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_7e2e6894
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e2e689411d97d6c43cad212d3eb11c7dc06062e3137ccd5d6ad156396872e9c"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:17:29"
  condition:
    hash.sha256(0, filesize) == "7e2e689411d97d6c43cad212d3eb11c7dc06062e3137ccd5d6ad156396872e9c"
}
```

### Sample 22: `9a657127746347ff`

| Field | Value |
|---|---|
| SHA-256 | `9a657127746347ffa09592d0c03400ed7ee24c4cbc89bc447a4900b96cdff184` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:16:33` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9878237eab189ba45dcb600291deb15` |
| SHA-1 | `44c0764a58c9cffea44c0f13cd4842bf0f592764` |
| SHA-256 | `9a657127746347ffa09592d0c03400ed7ee24c4cbc89bc447a4900b96cdff184` |
| SHA3-384 | `49387f6d52d0fd6ad7961dcbc05b1375966edc56cf9032aa8c4adc6743e841167c66aafeb50b657ce721ece82f464d58` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T100471229638701FBC3668270597CB761FD2E9964A508CD3AD7A9C1BD3CB1C2E68C53E1` |
| SSDEEP | `393216:NVwk/8ujGTl7r8U8h7loB64os9X7/MEXH6NQOXR3PNmRyVqJPW:f0RT1iloBJoAXDMEKeCVqJPW` |
| ICON-DHASH | `69c88e96968ecc61` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_9a657127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a657127746347ffa09592d0c03400ed7ee24c4cbc89bc447a4900b96cdff184"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:16:33"
  condition:
    hash.sha256(0, filesize) == "9a657127746347ffa09592d0c03400ed7ee24c4cbc89bc447a4900b96cdff184"
}
```

### Sample 23: `72f1a91566f9a644`

| Field | Value |
|---|---|
| SHA-256 | `72f1a91566f9a644b5795e23caa003780a4869fa903607fbe705382c19c545af` |
| Family label | `unknown` |
| File name | `Acrobat_Set-Up_7474.vbs` |
| File type | `vbs` |
| First seen | `2026-10-22 04:16:14` |
| Reporter | `abuse_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `674644c5e8e89fbd13b1e85631222b92` |
| SHA-1 | `71bdc656e3b615abb31a5084170aeb7891e1ec6d` |
| SHA-256 | `72f1a91566f9a644b5795e23caa003780a4869fa903607fbe705382c19c545af` |
| SHA3-384 | `b211ad5fbc9144e4132ae4b5590c60d426c7678e118cfcd83c41dc6c17913552ff24af262cb028a1428fe8b8469c47de` |
| TLSH | `T12C61510F7C4B41A2DC79C1078B1A3A5FCAC3166B161000B9FABC94492F3166FC6F91A7` |
| SSDEEP | `96:NGaSGf5r2cZlfwG8EstCg1/TAnIf2N/X6TG0iW:0aZtHfaPCCeIf2mG0T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_72f1a915
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72f1a91566f9a644b5795e23caa003780a4869fa903607fbe705382c19c545af"
    family = "unknown"
    file_name = "Acrobat_Set-Up_7474.vbs"
    file_type = "vbs"
    first_seen = "2026-10-22 04:16:14"
  condition:
    hash.sha256(0, filesize) == "72f1a91566f9a644b5795e23caa003780a4869fa903607fbe705382c19c545af"
}
```

### Sample 24: `0d1fe0823d6f3a16`

| Field | Value |
|---|---|
| SHA-256 | `0d1fe0823d6f3a163723cd35bc20b47e8d21d7bffecf1673a42d6065dd4a00da` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:16:14` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4baab94b14977479003df69f620e4f23` |
| SHA-1 | `cc91ac4a3aefb3eec3837194bdb5b416c2c84c28` |
| SHA-256 | `0d1fe0823d6f3a163723cd35bc20b47e8d21d7bffecf1673a42d6065dd4a00da` |
| SHA3-384 | `babe388d351b84a32d42a8dfd3131ae1b6c14c64c376ca88cce1a62095343ce475a8da0ad891318db1735c81049db753` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T19126232FA34751EBC3878230469953F6B9789E6490844A3BCA0DD07D3DB1E1EDCE6792` |
| SSDEEP | `49152:nPS8Utsxt6aVjOLfV8GgloEx1QNw1qv5ffXkoABlu:hCs3rYfVJglD1QmU5HXylu` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_0d1fe082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d1fe0823d6f3a163723cd35bc20b47e8d21d7bffecf1673a42d6065dd4a00da"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:16:14"
  condition:
    hash.sha256(0, filesize) == "0d1fe0823d6f3a163723cd35bc20b47e8d21d7bffecf1673a42d6065dd4a00da"
}
```

### Sample 25: `0a0dfd88a061dc8a`

| Field | Value |
|---|---|
| SHA-256 | `0a0dfd88a061dc8ad13f65954c0c961120bade8ad92f946d10c4bc0bc9c1cf80` |
| Family label | `SnakeKeylogger` |
| File name | `Fiyat Teklifi Talebi_22102026.vbs` |
| File type | `vbs` |
| First seen | `2026-10-22 04:16:11` |
| Reporter | `abuse_ch` |
| Tags | `geo, SnakeKeylogger, TUR, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96964bbcfdd00fcf80cab71072f4aa71` |
| SHA-1 | `0f6e5c5388bebfae43ebbd3c76cefbcc7d45bcb1` |
| SHA-256 | `0a0dfd88a061dc8ad13f65954c0c961120bade8ad92f946d10c4bc0bc9c1cf80` |
| SHA3-384 | `dc352adcf7c0bfcd49f2c5ff0702131f8cad4a50be83ab12360293299277bb48949574ed1d5c7868d6cb2be7bd873204` |
| TLSH | `T18EE3F16459443FD3A9BD02DF8A5ED86F073510229B99E6883C9F7A8A2773363EF0D405` |
| SSDEEP | `3072:ebo9leNNRTSLjE1iA7absrhlU4w0FovBwGfhK8TeNcKhTj0K5ffFHYBHwES2A:11jEM7bYhlUH0UwGJDW7Ic2A` |

#### Technical Assessment

- The sample is tracked as `SnakeKeylogger` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnakeKeylogger_025_0a0dfd88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a0dfd88a061dc8ad13f65954c0c961120bade8ad92f946d10c4bc0bc9c1cf80"
    family = "SnakeKeylogger"
    file_name = "Fiyat Teklifi Talebi_22102026.vbs"
    file_type = "vbs"
    first_seen = "2026-10-22 04:16:11"
  condition:
    hash.sha256(0, filesize) == "0a0dfd88a061dc8ad13f65954c0c961120bade8ad92f946d10c4bc0bc9c1cf80"
}
```

### Sample 26: `2adf323e3f0472d6`

| Field | Value |
|---|---|
| SHA-256 | `2adf323e3f0472d671cc8dfa35fe49f06783d6e74b0ce4bd2cd208a710cb0db3` |
| Family label | `RemcosRAT` |
| File name | `Requisition.vbs` |
| File type | `vbs` |
| First seen | `2026-10-22 04:16:05` |
| Reporter | `abuse_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `987262918d652cb5ee909ce7a3f48e26` |
| SHA-1 | `f8746668b6baa7b9389cbaaa25172450285863b7` |
| SHA-256 | `2adf323e3f0472d671cc8dfa35fe49f06783d6e74b0ce4bd2cd208a710cb0db3` |
| SHA3-384 | `2a1af469bb9aa3bac7f573b7990cf112a98a05e08c56cf604d8ab81e92f73830c4cc6b6484a19bc330ed7ff354f8f7b0` |
| TLSH | `T10FF3411A0735836579E36E6CEC60C9097B43E38AB338850C74E997485BE74D194E2FAF` |
| SSDEEP | `1536:5uxYi9wCTebx5ELbfof4OSce8Z2Gafihur7E6F5eVhNHTueqsHb+K7f2PWF1aVBj:5O8E` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_026_2adf323e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2adf323e3f0472d671cc8dfa35fe49f06783d6e74b0ce4bd2cd208a710cb0db3"
    family = "RemcosRAT"
    file_name = "Requisition.vbs"
    file_type = "vbs"
    first_seen = "2026-10-22 04:16:05"
  condition:
    hash.sha256(0, filesize) == "2adf323e3f0472d671cc8dfa35fe49f06783d6e74b0ce4bd2cd208a710cb0db3"
}
```

### Sample 27: `9c7fdfa3ee3373c6`

| Field | Value |
|---|---|
| SHA-256 | `9c7fdfa3ee3373c67b9861d3074a0c318aeceba4741f4527aff634f17faddb67` |
| Family label | `AgentTesla` |
| File name | `NEW ORDER.js` |
| File type | `js` |
| First seen | `2026-10-22 04:15:56` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `290f2d12ea38ceb1fa958c072031a903` |
| SHA-1 | `5c516555cfab2ac173dd44738f02a9cb91e117d7` |
| SHA-256 | `9c7fdfa3ee3373c67b9861d3074a0c318aeceba4741f4527aff634f17faddb67` |
| SHA3-384 | `69127226a090cced1ee96c5f6300067801841a7326781a9b4f4451f2e912c302e0a1ba59963192547e8570008ee5f12d` |
| TLSH | `T1B5950213DE06FE8E5878185E9E91CCC538639A06C0B4A1F1348F69EFE95FB05356E26C` |
| SSDEEP | `24576:L7LayZFYtSDhicGXe9N08FwdBfAapitLlzIhNG+4p6Ip0FpZrQwKCN5fHyWEN32s:L78cqXesdBfr1G/Kb+N32faq0t5` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_027_9c7fdfa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7fdfa3ee3373c67b9861d3074a0c318aeceba4741f4527aff634f17faddb67"
    family = "AgentTesla"
    file_name = "NEW ORDER.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:56"
  condition:
    hash.sha256(0, filesize) == "9c7fdfa3ee3373c67b9861d3074a0c318aeceba4741f4527aff634f17faddb67"
}
```

### Sample 28: `17530a344b6f52af`

| Field | Value |
|---|---|
| SHA-256 | `17530a344b6f52afe7e163f2762172ed18a16185535c8668ac9d6b3b46ff3e69` |
| Family label | `unknown` |
| File name | `Recibo de pago del Banco Banorte.js` |
| File type | `js` |
| First seen | `2026-10-22 04:15:46` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33877d7a2059b12b496e1ea0a1c6c47b` |
| SHA-1 | `02213a2689f2556104767c65f14c66bfac78b9f6` |
| SHA-256 | `17530a344b6f52afe7e163f2762172ed18a16185535c8668ac9d6b3b46ff3e69` |
| SHA3-384 | `e64625879c33d0df5cee0ffa28e298e65fd5d123e4f3a5188bc9e935290ee327e249f2e2d63483ed8521c15227fa0a34` |
| TLSH | `T1CE730874FD7105364E937B68FE9646B1C5EB8211862F8060E99F830D903BDACF77815A` |
| SSDEEP | `1536:Ud52SLJC6U2zPvjnN5JUVh2CG2YVabVh1KAbg1pogvE:USQH1jj3Sb2CG2YVNA81VM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_17530a34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17530a344b6f52afe7e163f2762172ed18a16185535c8668ac9d6b3b46ff3e69"
    family = "unknown"
    file_name = "Recibo de pago del Banco Banorte.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:46"
  condition:
    hash.sha256(0, filesize) == "17530a344b6f52afe7e163f2762172ed18a16185535c8668ac9d6b3b46ff3e69"
}
```

### Sample 29: `1941eee5464cb563`

| Field | Value |
|---|---|
| SHA-256 | `1941eee5464cb563a892fc2a7161abf8c7803b9d75f4d76a0a175c35c5732534` |
| Family label | `XWorm` |
| File name | `Cataloge..js` |
| File type | `js` |
| First seen | `2026-10-22 04:15:43` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62418cc6de2f1edf6804e8af8c82a7b7` |
| SHA-1 | `53cf7cce16c75b7cd2acbf7e605a9383098ddbe6` |
| SHA-256 | `1941eee5464cb563a892fc2a7161abf8c7803b9d75f4d76a0a175c35c5732534` |
| SHA3-384 | `bdea33b34c8a22822264c962113a2e629dfdc4cd1b48b038d202e8ffbc131512838303ea8faf27a783a9f29d9af833cc` |
| TLSH | `T1E9D5622EDBB04EAE76EE19EC1C52C2D6CFDDD586C1948DCBF176A261BF544A60680330` |
| SSDEEP | `49152:zpF/MYQhYHMgDn23uI+XcTor8ZmNUVU2VjoEcmLv0/u4OJjguf4R6scoxVNF0FwD:zpF/MYQhYHMgj23uI+XcTowZmNOUejod` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_029_1941eee5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1941eee5464cb563a892fc2a7161abf8c7803b9d75f4d76a0a175c35c5732534"
    family = "XWorm"
    file_name = "Cataloge..js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:43"
  condition:
    hash.sha256(0, filesize) == "1941eee5464cb563a892fc2a7161abf8c7803b9d75f4d76a0a175c35c5732534"
}
```

### Sample 30: `cdaf1b6cac86e2ab`

| Field | Value |
|---|---|
| SHA-256 | `cdaf1b6cac86e2ab5f06b3a02faa9f909c26e251836c90faf5e61aca491be6b1` |
| Family label | `XWorm` |
| File name | `PO-NO-103A-103A-B11200-722-GCIT-2288.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:15:40` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79148b6277d11b2dcdde30426a136de8` |
| SHA-1 | `18cb3be1aa2b2d311b16a8ecfb5c0e987f07388c` |
| SHA-256 | `cdaf1b6cac86e2ab5f06b3a02faa9f909c26e251836c90faf5e61aca491be6b1` |
| SHA3-384 | `f57ee16d108ac6bd932fa496773a873d994386f61ae07e2cbd41dec6d5feae2de95f4055c33f71956f209a6e97a080b0` |
| TLSH | `T1E716094E33807432512E971EC236AA308715983BB19FDF2A35A83554BF7C6A6530EDDB` |
| SSDEEP | `98304:QgJHSsh55AQtItylHGQON5+DEfoQhWqovePhWBUqbndceuDFzJ6u9P:QgpN3iCWAHG5rSEfoQhWqs+hWBbceuD1` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_030_cdaf1b6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdaf1b6cac86e2ab5f06b3a02faa9f909c26e251836c90faf5e61aca491be6b1"
    family = "XWorm"
    file_name = "PO-NO-103A-103A-B11200-722-GCIT-2288.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:15:40"
  condition:
    hash.sha256(0, filesize) == "cdaf1b6cac86e2ab5f06b3a02faa9f909c26e251836c90faf5e61aca491be6b1"
}
```

### Sample 31: `7b37b779c34cf156`

| Field | Value |
|---|---|
| SHA-256 | `7b37b779c34cf1567c822c24ee7e6ab0d84ce2a513e5eac5bdaa63a46b929e58` |
| Family label | `AgentTesla` |
| File name | `SHIPMENT DETAILS AND DOCUMENTS.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:15:37` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e67fff8dc83c9bb395de6a942ada400c` |
| SHA-1 | `d84f2ba42e1f2e861de3c2129a05437cc5ab69ce` |
| SHA-256 | `7b37b779c34cf1567c822c24ee7e6ab0d84ce2a513e5eac5bdaa63a46b929e58` |
| SHA3-384 | `a4a8439ba1fd007b30943e595fb930d2b16084351070b355f8e69494b07c065a3d661aacbca5cc4f4763fd5bc1fb2318` |
| TLSH | `T1CE3682588224637A512EB29CC0297D42A535748B2D6CBA3D3DE82850FFFD307B64B6DD` |
| SSDEEP | `98304:nWHtG0N9cgyESw/1iLr8dwU7QmrlR3oTXLC+Qcb+hPhOZRDvm6MnYmUIiAKfvfXz:WUgrBR3Nhpq0nhUdAKfnXUmxV18i7n8s` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_031_7b37b779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b37b779c34cf1567c822c24ee7e6ab0d84ce2a513e5eac5bdaa63a46b929e58"
    family = "AgentTesla"
    file_name = "SHIPMENT DETAILS AND DOCUMENTS.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:15:37"
  condition:
    hash.sha256(0, filesize) == "7b37b779c34cf1567c822c24ee7e6ab0d84ce2a513e5eac5bdaa63a46b929e58"
}
```

### Sample 32: `13866f897489f085`

| Field | Value |
|---|---|
| SHA-256 | `13866f897489f08554617dce9143fcc8e8b6b1cc76e6d3732da018a30dcdde64` |
| Family label | `unknown` |
| File name | `13866f897489f085.js` |
| File type | `js` |
| First seen | `2026-10-22 04:15:26` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2281bd53d1f7d996dc25ad25edd9c5e5` |
| SHA-1 | `52556e2940dfb78ec06b53a561fff1396e506f9b` |
| SHA-256 | `13866f897489f08554617dce9143fcc8e8b6b1cc76e6d3732da018a30dcdde64` |
| SHA3-384 | `db6b81e2479422e6bcaf12fde7e85d4bed8a47d7ca7102e80fdc0c0945259a113b8c0a52243b0de9cb1fc0feb0e5fc19` |
| TLSH | `T15B337DEEA38026DC5CB4CCE7A53706AD63F8DB076C14326DB38BAE51B45F7109960729` |
| SSDEEP | `768:gM3zThFJqWx7EyYPWtBBYBS/8XuxzddhycF45cNR83V4VJwCB39E/ynXGY/9aMk:Hz9qQEyruiDyTcNaKldXG7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_13866f89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13866f897489f08554617dce9143fcc8e8b6b1cc76e6d3732da018a30dcdde64"
    family = "unknown"
    file_name = "13866f897489f085.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:26"
  condition:
    hash.sha256(0, filesize) == "13866f897489f08554617dce9143fcc8e8b6b1cc76e6d3732da018a30dcdde64"
}
```

### Sample 33: `497befff3913668d`

| Field | Value |
|---|---|
| SHA-256 | `497befff3913668d098d346093f5b3647dcfb6b9924783b25b01d7bc038779bc` |
| Family label | `RemcosRAT` |
| File name | `Swift_Transaction7398.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:15:19` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `850e4433ced1da0c185f1121006fff4f` |
| SHA-1 | `5b25855757ce5e98ecb6ff3004898d1f81167fc9` |
| SHA-256 | `497befff3913668d098d346093f5b3647dcfb6b9924783b25b01d7bc038779bc` |
| SHA3-384 | `c53a273f560485fa95657af86bd73ac41552943ea755ec64f82df1cb5ce0d9b034199bf113ab7f5b5a23c1e230b3e5eb` |
| TLSH | `T1D56630785B2662B13125670E52B5DD9CA49D30236CC1CF263C3A628F7A9C8076B7E7F1` |
| SSDEEP | `196608:gDnHaUBLv6VYPuFI8wiAY7wpVFZKrkV9aQ62Lqo8eD2eP2wWZ:InHhdHFpYrwaF2LJ8q2QWZ` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_033_497befff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "497befff3913668d098d346093f5b3647dcfb6b9924783b25b01d7bc038779bc"
    family = "RemcosRAT"
    file_name = "Swift_Transaction7398.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:15:19"
  condition:
    hash.sha256(0, filesize) == "497befff3913668d098d346093f5b3647dcfb6b9924783b25b01d7bc038779bc"
}
```

### Sample 34: `0c5486f06620e26e`

| Field | Value |
|---|---|
| SHA-256 | `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` |
| Family label | `unknown` |
| File name | `nfs` |
| File type | `elf` |
| First seen | `2026-10-22 04:15:15` |
| Reporter | `idknerdyshit` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b61a098fc62a2c2696e196dca78da71a` |
| SHA-1 | `c472dab4ff7c16782a8037f988d4daa6d4bdb343` |
| SHA-256 | `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` |
| SHA3-384 | `d27fcabdc3087072aab026dc33daeb4ab29f7cfadf01e7663aaff1507e9c5f57ecf8906ac463c3f7290940033649c452` |
| TLSH | `T197043A02B58194FED0C6C1708FAFD137A772F49D62307E9E3B942F692E26E215E1A750` |
| TELFHASH | `t1fd71bd301ee5b92862d3cb16b307aa2dfc7a0521a4e7b1e8ae57aad0cc561c51d27062` |
| SSDEEP | `3072:zjKH2VJga3zK7zRe6Dy0murBDp/OrdZhaPEj8RK6TybKOwNahJlhT2:fiFv00XrL/OBaPHLTybl/K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_0c5486f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
    family = "unknown"
    file_name = "nfs"
    file_type = "elf"
    first_seen = "2026-10-22 04:15:15"
  condition:
    hash.sha256(0, filesize) == "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
}
```

### Sample 35: `72b104e2e5039619`

| Field | Value |
|---|---|
| SHA-256 | `72b104e2e5039619b46264f6010929703c0e18fb435fd1b1e68afeb936d301a7` |
| Family label | `AgentTesla` |
| File name | `Quotation.js` |
| File type | `js` |
| First seen | `2026-10-22 04:15:01` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `355d714c7dff8292ac962985fed61744` |
| SHA-1 | `869d98fcea79167c26f295bd93c9ed0f250fffd1` |
| SHA-256 | `72b104e2e5039619b46264f6010929703c0e18fb435fd1b1e68afeb936d301a7` |
| SHA3-384 | `b3f7aeb2c21f88248d91dffb5eb065ff07ae8ef256de82d8ef36dbd790fea8d7274511ae88caa475b16c3b6faca50e7d` |
| TLSH | `T18CA3013D1D6B123B5AF5C719D5C61A0BF1A724573231AE0884EF539A5BA3243BCC236E` |
| SSDEEP | `384:rMd5/Z/ovACNELSGcuOYajRgBfPuyPJuGLGMMG4OHS5qNvjJSSrZeZ5e1nxlFM2E:iqbhgFrY/qfb4ryC3rfMaFqwL7` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_035_72b104e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b104e2e5039619b46264f6010929703c0e18fb435fd1b1e68afeb936d301a7"
    family = "AgentTesla"
    file_name = "Quotation.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:01"
  condition:
    hash.sha256(0, filesize) == "72b104e2e5039619b46264f6010929703c0e18fb435fd1b1e68afeb936d301a7"
}
```

### Sample 36: `6401841ee99220dc`

| Field | Value |
|---|---|
| SHA-256 | `6401841ee99220dcdee1ab02914226afca075c15e82bead40746eff81325e9cf` |
| Family label | `Formbook` |
| File name | `RFQ_Order_Request_EXW_pdf.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:58` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b6bab4edb1b786f9c527b6a98ef2370` |
| SHA-1 | `c9bd091c689478ba0ef51a83a8bc78eea88907c5` |
| SHA-256 | `6401841ee99220dcdee1ab02914226afca075c15e82bead40746eff81325e9cf` |
| SHA3-384 | `8773bc53e6b5d29d5e241e6e21c91587d09a4d9fcf13c41f23c071122983c66deece085881d57e746ace4fa7b7aaf527` |
| TLSH | `T163468E6C90EF72E3703A02136AC1BD9D8511490F6E4A8F717D38D6DF9B6C68B164EA31` |
| SSDEEP | `98304:EN3+RUh9buARDpa9hoEuoG+oD5PcAdGRnCOejTxdgCwSHSz16MAoWjh8ZsCkLDMp:ih5u+l+iV0Rn7ejNdg8H64og8uRAPspu` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_036_6401841e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6401841ee99220dcdee1ab02914226afca075c15e82bead40746eff81325e9cf"
    family = "Formbook"
    file_name = "RFQ_Order_Request_EXW_pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:58"
  condition:
    hash.sha256(0, filesize) == "6401841ee99220dcdee1ab02914226afca075c15e82bead40746eff81325e9cf"
}
```

### Sample 37: `2bff9eeb072e4d37`

| Field | Value |
|---|---|
| SHA-256 | `2bff9eeb072e4d37e129e9d37eb7c866051be1ace3d8702fc7ddac0953ea8dcd` |
| Family label | `XWorm` |
| File name | `MT 103 USD 65660.01.js` |
| File type | `js` |
| First seen | `2026-10-22 04:14:55` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `065cdc313b853fb3cac3d5bdb146ebc2` |
| SHA-1 | `09b92cc4230ca50f10953ee35cec7458191de67b` |
| SHA-256 | `2bff9eeb072e4d37e129e9d37eb7c866051be1ace3d8702fc7ddac0953ea8dcd` |
| SHA3-384 | `f3d452af4ef7583053df3b214d5e84e1317274500b3903147ae73ab087c367cbd2a5fb5e9882f1cd5c51322fa7034045` |
| TLSH | `T1E5A3543DAD9A123B8AF9C759C1C61907F15396973135AD0D84EF53898BA3283BCC532E` |
| SSDEEP | `768:HNfPhmziQ0kdcmVeD0zBNVlBqEa6H65ITWhQ:HFPQmQ0YcmVrB/lBqEa6H6vQ` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_037_2bff9eeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bff9eeb072e4d37e129e9d37eb7c866051be1ace3d8702fc7ddac0953ea8dcd"
    family = "XWorm"
    file_name = "MT 103 USD 65660.01.js"
    file_type = "js"
    first_seen = "2026-10-22 04:14:55"
  condition:
    hash.sha256(0, filesize) == "2bff9eeb072e4d37e129e9d37eb7c866051be1ace3d8702fc7ddac0953ea8dcd"
}
```

### Sample 38: `8e2dd5512aff7942`

| Field | Value |
|---|---|
| SHA-256 | `8e2dd5512aff7942a8c3a08d5227d387f8b0244b1c429d09608ace21cc6317b1` |
| Family label | `unknown` |
| File name | `RFQ-GN0948.js` |
| File type | `js` |
| First seen | `2026-10-22 04:14:52` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57eb988dc15d4b40cf2dbaece9646602` |
| SHA-1 | `b9bb4250e00f28fe63e2185e4343ee4d57631ca7` |
| SHA-256 | `8e2dd5512aff7942a8c3a08d5227d387f8b0244b1c429d09608ace21cc6317b1` |
| SHA3-384 | `175b3f1abb07e93c8dc2c8444587116aad36b4236e47a8a0d3dcc2ba47e5994eebb5ca61c8e8820edbd1ca52c9704da1` |
| TLSH | `T100A3133D1D69023B56FAC75CC4C5094BF0A3996776316C4D94EFA3898BA3283B9C136E` |
| SSDEEP | `384:QTFD27dIkdAlx0c9NpZLHM7eVWA2B2czFGPL2Po0rX1Irx2T2xwy465s4MJ9MSTR:4MDodQXACx5ImIcyOJOpMiaEqY4Zvp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_8e2dd551
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e2dd5512aff7942a8c3a08d5227d387f8b0244b1c429d09608ace21cc6317b1"
    family = "unknown"
    file_name = "RFQ-GN0948.js"
    file_type = "js"
    first_seen = "2026-10-22 04:14:52"
  condition:
    hash.sha256(0, filesize) == "8e2dd5512aff7942a8c3a08d5227d387f8b0244b1c429d09608ace21cc6317b1"
}
```

### Sample 39: `a340ead3b283edfc`

| Field | Value |
|---|---|
| SHA-256 | `a340ead3b283edfc401a385156d231675a67e092fb3c77cd2fcaae3a0376027f` |
| Family label | `AgentTesla` |
| File name | `RFQ LIST.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:49` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a28c9f6f9d19268679c4998bcc175a0` |
| SHA-1 | `7682a372731212b52282c74ea03be67192bac270` |
| SHA-256 | `a340ead3b283edfc401a385156d231675a67e092fb3c77cd2fcaae3a0376027f` |
| SHA3-384 | `970e364216196e3a841ebb3a8de225c32278b44417fa29ee0275d58688995ea7dd0fe3bb74676c2943770316f9e5f1a0` |
| TLSH | `T189363FCB23A5613233B1575DC73AA8709537A4CBA1A5CF20369CF3157EAE907530EAD2` |
| SSDEEP | `98304:fl9O4KImraeQickZA93zpYJctjJZ8tmH2CYryOE4NboZ8hK7IwJSXPvIcjfm9gyE:fl9xKImraeQicaA93zpYJctdmtmH2CY5` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_039_a340ead3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a340ead3b283edfc401a385156d231675a67e092fb3c77cd2fcaae3a0376027f"
    family = "AgentTesla"
    file_name = "RFQ LIST.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:49"
  condition:
    hash.sha256(0, filesize) == "a340ead3b283edfc401a385156d231675a67e092fb3c77cd2fcaae3a0376027f"
}
```

### Sample 40: `937bbe04d64445eb`

| Field | Value |
|---|---|
| SHA-256 | `937bbe04d64445ebbff80cd851f739c45e6516dd172bcc0d5af8b94ef2fc528f` |
| Family label | `AgentTesla` |
| File name | `SOA ITS-AH 2026 (09.26).JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:46` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c725baf5ee932ae78f0953607c54949` |
| SHA-1 | `4f9504e948e60f95d340c3e9aede50a6504ab56b` |
| SHA-256 | `937bbe04d64445ebbff80cd851f739c45e6516dd172bcc0d5af8b94ef2fc528f` |
| SHA3-384 | `1815600b7e65652966e48f15192f229bcad9740209a0d1ef33c373429d1a4fc3f88c5fa7c97eff5a4c46509c21694b3e` |
| TLSH | `T12336EB4B228051BD3329579D8135FD20EC0D990329A5CBBE379CED147A7CE0F5B8A6DA` |
| SSDEEP | `98304:bQmD9keabfzGXFW0tn0N28X9GDcZuej6v8mxcldvmTC+K5TtVPi6XX+b746J:bQmD2bLGXFWPA8X9GYZueldtTP66XX+H` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_040_937bbe04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937bbe04d64445ebbff80cd851f739c45e6516dd172bcc0d5af8b94ef2fc528f"
    family = "AgentTesla"
    file_name = "SOA ITS-AH 2026 (09.26).JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:46"
  condition:
    hash.sha256(0, filesize) == "937bbe04d64445ebbff80cd851f739c45e6516dd172bcc0d5af8b94ef2fc528f"
}
```

### Sample 41: `846f554b4be26787`

| Field | Value |
|---|---|
| SHA-256 | `846f554b4be26787b8a4ed2642526de9c04631e66180b00e5cac5601a8731afc` |
| Family label | `MassLogger` |
| File name | `Purchase Order 0138801.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:41` |
| Reporter | `abuse_ch` |
| Tags | `js, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c6b112d0371e388425cc2700b122bb7` |
| SHA-1 | `5205070f78d1434d820cc003cbf803022bc32b8c` |
| SHA-256 | `846f554b4be26787b8a4ed2642526de9c04631e66180b00e5cac5601a8731afc` |
| SHA3-384 | `e5591fb33b3f678c4b8abab730eefea257b7770a31deb2e8722bd2f6b57c2aefd457f10d8eaed7b40ad5ba1573689215` |
| TLSH | `T172268E483B54B3434069D71A65857984C7288B0BA148DF233EBE78D9DFBEE06A2C7774` |
| SSDEEP | `98304:N2MmDuB6YjIhqG9836q6DnU6aXWI7wgp4+HS2ILdhzFWAHMaBEwYU9NF2:NQDuDi93aXWEXfI8EzJNF2` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_041_846f554b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "846f554b4be26787b8a4ed2642526de9c04631e66180b00e5cac5601a8731afc"
    family = "MassLogger"
    file_name = "Purchase Order 0138801.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:41"
  condition:
    hash.sha256(0, filesize) == "846f554b4be26787b8a4ed2642526de9c04631e66180b00e5cac5601a8731afc"
}
```

### Sample 42: `f0c9b0514bce405b`

| Field | Value |
|---|---|
| SHA-256 | `f0c9b0514bce405b21604b9fae6e2b3e59ac36c41cc73e629929a35eec3c9e95` |
| Family label | `RemcosRAT` |
| File name | `rsonbkgd.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:36` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3023797a6faba1fac0cbe0b49d2f52e9` |
| SHA-1 | `b182869b31d9928a0124054ced69ba8b44553a8a` |
| SHA-256 | `f0c9b0514bce405b21604b9fae6e2b3e59ac36c41cc73e629929a35eec3c9e95` |
| SHA3-384 | `5b72895255ea39a8467b53d6ef80fc3b9f3d795a3706c56875c9e3d6cbec7dcff42c06a7d05fc2422c30e501637e276b` |
| TLSH | `T16056C7891585D13DFB33FBCF4125A8A0E02AA5832D614728759FFF15FA3E924E593E02` |
| SSDEEP | `98304:UUV/yaB7q/LSzQJ6Xj7J/NOuKT3Gxp+FbfmxIPxt3+jzbF/m3p4l+L9HQLv0ym44:UUV/yaB7q/LSzQJ6Xj7J/NOuKT3Gxp+z` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_042_f0c9b051
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0c9b0514bce405b21604b9fae6e2b3e59ac36c41cc73e629929a35eec3c9e95"
    family = "RemcosRAT"
    file_name = "rsonbkgd.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:36"
  condition:
    hash.sha256(0, filesize) == "f0c9b0514bce405b21604b9fae6e2b3e59ac36c41cc73e629929a35eec3c9e95"
}
```

### Sample 43: `d1b93e9e32e7eb7b`

| Field | Value |
|---|---|
| SHA-256 | `d1b93e9e32e7eb7b56549b8cf464251ef7c1581fdf6b90ac5c6a4381b3e77aa4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:14:16` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6b2b2be9802058905b4804ded6a8b50` |
| SHA-1 | `e14fd252c7f4371ef78f62d4d0f8eb7fb343862b` |
| SHA-256 | `d1b93e9e32e7eb7b56549b8cf464251ef7c1581fdf6b90ac5c6a4381b3e77aa4` |
| SHA3-384 | `92174d2f41d8986d1c881f1cd77d37c11dd80d3839ec6c8e978b2df5a093fefde1a411eb5515da810532a9956473f79f` |
| IMPHASH | `a47dec6c5c84de6de9dea0fb98e93422` |
| TLSH | `T16E47A051B30B05F6FF434C3645F9AB2F7B39E2DC8974C55AE428242ABAA2C1F45DC291` |
| SSDEEP | `393216:vCobF1wG13MfhzYf9BxocfxI5yM1MDzfIw8wDP1DO:vBAw8f58HMO/2w5DO` |
| ICON-DHASH | `c0a4a292a2b2a2c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_d1b93e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b93e9e32e7eb7b56549b8cf464251ef7c1581fdf6b90ac5c6a4381b3e77aa4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:14:16"
  condition:
    hash.sha256(0, filesize) == "d1b93e9e32e7eb7b56549b8cf464251ef7c1581fdf6b90ac5c6a4381b3e77aa4"
}
```

### Sample 44: `fdbc09388712bcd1`

| Field | Value |
|---|---|
| SHA-256 | `fdbc09388712bcd18702fbb30fbbdc338ee89c80a8971bbedacd7e427f327932` |
| Family label | `RemcosRAT` |
| File name | `myqvcivp.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:10` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d4f32deb66ce50c369a8c79748956d7` |
| SHA-1 | `be23b6e3f3210cb45e6d2320cf3409ed6b671c47` |
| SHA-256 | `fdbc09388712bcd18702fbb30fbbdc338ee89c80a8971bbedacd7e427f327932` |
| SHA3-384 | `6a1d82a68517a2b65754dd7a92e5702b7a3b4caf2d6c4b20e69f11966a49a1da85d62cfbc868c46df5f38a04960ac598` |
| TLSH | `T1E55698CA198DF522B311768FC965BC32E009BD032D45C638FD9CE5946A3C98C67276BE` |
| SSDEEP | `98304:o8x4zNGY14XBvmbmTUtehh36QLKMTe9rmOmlidXoYOgy49+jmYVoQTwKumKulIkL:o8x4zNGY14XBvmbmTUtehh36QLKMTe9A` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_044_fdbc0938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdbc09388712bcd18702fbb30fbbdc338ee89c80a8971bbedacd7e427f327932"
    family = "RemcosRAT"
    file_name = "myqvcivp.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:10"
  condition:
    hash.sha256(0, filesize) == "fdbc09388712bcd18702fbb30fbbdc338ee89c80a8971bbedacd7e427f327932"
}
```

### Sample 45: `d92b9d306bf69395`

| Field | Value |
|---|---|
| SHA-256 | `d92b9d306bf693953239f78062281d6cf0c252753a0b86d231c8e5520a5f308e` |
| Family label | `Formbook` |
| File name | `New_Purchase_Order_[PO_02081].JS` |
| File type | `js` |
| First seen | `2026-10-22 04:14:03` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa5cd6bf51d68bec2b2f61c5151b4fa6` |
| SHA-1 | `59c26ae8ce7a93755c428d0b75733a1647efd995` |
| SHA-256 | `d92b9d306bf693953239f78062281d6cf0c252753a0b86d231c8e5520a5f308e` |
| SHA3-384 | `5864f0a839d1986585b5bd89ce654d264cb07ecf36263e181c2341f69ecb3423b9eb10c8bb7bcbad07a1680fbe6209ed` |
| TLSH | `T1C8266ECF3B9551B2372557DD0536EFA1D40A98832485CB20B5BCF194BB3CA269B0BED2` |
| SSDEEP | `98304:tQln2oadHFl0zwNa6DG65J8t1Aprl6siQiONVHqpcgVkXWfjkid1t1d28bUYJ:U2oadvFSG0ApruQigpnlXWfjkiPzd28x` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_045_d92b9d30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d92b9d306bf693953239f78062281d6cf0c252753a0b86d231c8e5520a5f308e"
    family = "Formbook"
    file_name = "New_Purchase_Order_[PO_02081].JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:03"
  condition:
    hash.sha256(0, filesize) == "d92b9d306bf693953239f78062281d6cf0c252753a0b86d231c8e5520a5f308e"
}
```

### Sample 46: `70e4d14bc5c0a61d`

| Field | Value |
|---|---|
| SHA-256 | `70e4d14bc5c0a61d0f274c621bce68c878a9588d1caf76912260c825c4c99830` |
| Family label | `XWorm` |
| File name | `payment swift الدفعة 567 .pdf.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:59` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc27591b8da085f6e0463535461dac8b` |
| SHA-1 | `8cfe7ae731e5b45f1aa1655fc1f849a6b173e47b` |
| SHA-256 | `70e4d14bc5c0a61d0f274c621bce68c878a9588d1caf76912260c825c4c99830` |
| SHA3-384 | `05c7d37138c2e4ff06ca38f0199e219ac7ff1ae5754bacb4db8648863b10dc16303da07aa5fd17660fc3246b4b9d0c42` |
| TLSH | `T1BE162C691389D9333321FB5D4227ACA09427960725DDCB2834BCF196FA3C9875A277F2` |
| SSDEEP | `98304:0XMznV6hQZu9qPEijWARLu6SEkcEbbBCtCvQpi01OoHevcxU4kTythUYv6caf6cy:0XMznVYQQ9hijWARLu7bcEbbBCtCvQpr` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_046_70e4d14b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e4d14bc5c0a61d0f274c621bce68c878a9588d1caf76912260c825c4c99830"
    family = "XWorm"
    file_name = "payment swift الدفعة 567 .pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:59"
  condition:
    hash.sha256(0, filesize) == "70e4d14bc5c0a61d0f274c621bce68c878a9588d1caf76912260c825c4c99830"
}
```

### Sample 47: `ef451da37f748734`

| Field | Value |
|---|---|
| SHA-256 | `ef451da37f7487345e5330a0905ffcb3509f7522a5bb7bbb89be1f05c19980f9` |
| Family label | `XWorm` |
| File name | `doc20261022_90000110011po.js` |
| File type | `js` |
| First seen | `2026-10-22 04:13:56` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcc22ae30e1becf47b1b50fbc7c8f84f` |
| SHA-1 | `d789179c781ac1e1e97d128ace09002ebc9b569c` |
| SHA-256 | `ef451da37f7487345e5330a0905ffcb3509f7522a5bb7bbb89be1f05c19980f9` |
| SHA3-384 | `833ffa728bca60bba64d1c04cf50ccc082906e68fe63b514ab9ffca07d54ddb888a9b7ce1556e345a243f795c2399f96` |
| TLSH | `T107A3203D5D69023B97F9C319D4DA190BF16365573132AE4D90EF43894BA3283BAC632E` |
| SSDEEP | `384:HoIQh6jSDUgqx11/9hz7sNw7jwP9AVj3tM1LnO72o/aaNhN4L8QhYXcRlr0AKYaU:2iImwmyjtll9cszDQQWfN/hFR+J` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_047_ef451da3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef451da37f7487345e5330a0905ffcb3509f7522a5bb7bbb89be1f05c19980f9"
    family = "XWorm"
    file_name = "doc20261022_90000110011po.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:56"
  condition:
    hash.sha256(0, filesize) == "ef451da37f7487345e5330a0905ffcb3509f7522a5bb7bbb89be1f05c19980f9"
}
```

### Sample 48: `4e01506195fae2b2`

| Field | Value |
|---|---|
| SHA-256 | `4e01506195fae2b2bd8e8b04ff51985abd42bd06fcfcfaf9bea9f9184d1f5388` |
| Family label | `DonutLoader` |
| File name | `NEW_PO_NOVA_TRADE.js` |
| File type | `js` |
| First seen | `2026-10-22 04:13:51` |
| Reporter | `abuse_ch` |
| Tags | `DonutLoader, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5044024d3049e806f3b7bf3025a8b6b` |
| SHA-1 | `42c0288f8bd96701a90fadb5fba8ca5375acd180` |
| SHA-256 | `4e01506195fae2b2bd8e8b04ff51985abd42bd06fcfcfaf9bea9f9184d1f5388` |
| SHA3-384 | `40ec89276f60f4b5a0ad57b94fea4464786a12925acc14be7657e56296e1f25bb4ebd61f7044b17dfa9cd97ecc303f9d` |
| TLSH | `T158F5931ECF329E9A38A91ECC3E65C5D196DEFB4AC1747DCB63519A10E3684D148CEA30` |
| SSDEEP | `98304:j3rhC48JWzy2B2PCq4nctSE5C3yMW9eqwadBinmmKjlqQxIJa6cWp/b9YH8nppZ+:j3448JWzuNTimqQOg6X9YgNPAairdLQ0` |

#### Technical Assessment

- The sample is tracked as `DonutLoader` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DonutLoader_048_4e015061
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e01506195fae2b2bd8e8b04ff51985abd42bd06fcfcfaf9bea9f9184d1f5388"
    family = "DonutLoader"
    file_name = "NEW_PO_NOVA_TRADE.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:51"
  condition:
    hash.sha256(0, filesize) == "4e01506195fae2b2bd8e8b04ff51985abd42bd06fcfcfaf9bea9f9184d1f5388"
}
```

### Sample 49: `5416e3b192f69d02`

| Field | Value |
|---|---|
| SHA-256 | `5416e3b192f69d02b51747067e80b8395c7c30a5ddd0cfe23aa38bf893b233a6` |
| Family label | `unknown` |
| File name | `TelnetTime.sh` |
| File type | `sh` |
| First seen | `2026-10-22 04:13:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b91448bc5bc0b62bf5908fb2c56690c5` |
| SHA-1 | `87c6d433b61391d22527bfe738f334e8f44baefb` |
| SHA-256 | `5416e3b192f69d02b51747067e80b8395c7c30a5ddd0cfe23aa38bf893b233a6` |
| SHA3-384 | `ec9d3209f18e1be2b6bd357720f273c5f96022b1b29ad246cf20d8f49aba3d6042c45de9ea30ad283aaad360b8838d32` |
| TLSH | `T1A34144CB1794F220C077C11A33F66C9D4809F5D3ADE61B5CD8C69A7A6E40088F24E7D4` |
| SSDEEP | `24:N8Nz4eseMxz46+Az4npz46yY6yuqz4ttz4Oxz4uTeuT8z4ENz4wTz4npzl:N8CeseT6GnWvYvu5tiOOuyuXECwYnj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_5416e3b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5416e3b192f69d02b51747067e80b8395c7c30a5ddd0cfe23aa38bf893b233a6"
    family = "unknown"
    file_name = "TelnetTime.sh"
    file_type = "sh"
    first_seen = "2026-10-22 04:13:46"
  condition:
    hash.sha256(0, filesize) == "5416e3b192f69d02b51747067e80b8395c7c30a5ddd0cfe23aa38bf893b233a6"
}
```

### Sample 50: `b15b1e9a2608f121`

| Field | Value |
|---|---|
| SHA-256 | `b15b1e9a2608f1211ace68af1bf79716398f865d09c3160100b3a13e2d0e9c19` |
| Family label | `AveMariaRAT` |
| File name | `TELEX HBL DOCUMENTS 03.js` |
| File type | `js` |
| First seen | `2026-10-22 04:13:42` |
| Reporter | `abuse_ch` |
| Tags | `AveMariaRAT, js, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f1f08ce06c7cca5a4df5609f3389cd` |
| SHA-1 | `9a4124e9bc19f8047ba67932511ebc13ac8c0fca` |
| SHA-256 | `b15b1e9a2608f1211ace68af1bf79716398f865d09c3160100b3a13e2d0e9c19` |
| SHA3-384 | `5898eeb4e75a1a856a3a0647f53e9c5629bbb00d8ccefbe7ddf89458da16a73af8141566e00b4148939a55e0a5d8dab0` |
| TLSH | `T11D651207CD06FD4A5D78985EAE94CD84F863AB02C0B4A1F5348F6CEFEA4B915386F158` |
| SSDEEP | `24576:cM88ShGaw3a3D5vmuvwpYXXytglCk+49TWp4KypSmyN/sGlyQYNfB6EnrAs4p1:cPhDXhCjO5pqqjG` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_050_b15b1e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b15b1e9a2608f1211ace68af1bf79716398f865d09c3160100b3a13e2d0e9c19"
    family = "AveMariaRAT"
    file_name = "TELEX HBL DOCUMENTS 03.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:42"
  condition:
    hash.sha256(0, filesize) == "b15b1e9a2608f1211ace68af1bf79716398f865d09c3160100b3a13e2d0e9c19"
}
```

### Sample 51: `bbe3b7927fca9e76`

| Field | Value |
|---|---|
| SHA-256 | `bbe3b7927fca9e766d0f150a58c064a92b334f9363d7f565fefcd4726a71ed77` |
| Family label | `Formbook` |
| File name | `SOA - 31-AUGUST-31-OCTOBER-2026.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:36` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dece63e8bed79e7dd6e3a81b50742e9` |
| SHA-1 | `f0d6283567effef173b48343f337bf36b43f97ab` |
| SHA-256 | `bbe3b7927fca9e766d0f150a58c064a92b334f9363d7f565fefcd4726a71ed77` |
| SHA3-384 | `de262bc4325e88f550dff3a78911bfbee5f6021f2487064969d3a3ee452c03f70f1573be3c7b6efcb4b13b24c4ba51a4` |
| TLSH | `T10A26818819C27F43407A423AEAAFB5948511F80B7412D520769A6F9CBF3CE66FB47533` |
| SSDEEP | `98304:OCiVHf5xFAp6+fHrJviSUzzJJo8yuAEZ6uedwpyaAiXhgQfxkSdb3gTVPl:OrxFA8+PrJqSUzzJO8yuljedAX9xPmPl` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_051_bbe3b792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbe3b7927fca9e766d0f150a58c064a92b334f9363d7f565fefcd4726a71ed77"
    family = "Formbook"
    file_name = "SOA - 31-AUGUST-31-OCTOBER-2026.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:36"
  condition:
    hash.sha256(0, filesize) == "bbe3b7927fca9e766d0f150a58c064a92b334f9363d7f565fefcd4726a71ed77"
}
```

### Sample 52: `9fb0a1a7ebacb4f6`

| Field | Value |
|---|---|
| SHA-256 | `9fb0a1a7ebacb4f6a65a995f5bb30020dc25f2fd5589a2303970bb805a1b242a` |
| Family label | `DonutLoader` |
| File name | `Payment_Receipt_Ref-548921.pdf.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:33` |
| Reporter | `abuse_ch` |
| Tags | `DonutLoader, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9acd963a20ac104036de34eb4db53256` |
| SHA-1 | `580689f0606ecb879c29e7adf673da5112baa89e` |
| SHA-256 | `9fb0a1a7ebacb4f6a65a995f5bb30020dc25f2fd5589a2303970bb805a1b242a` |
| SHA3-384 | `84792d15c3808b1b0eb3f28f83ec482a20d7bc5a2747cd15a33e4102840f6d1e5b19cc2ee867814ab023e5ddd4951bd0` |
| TLSH | `T1C6665D6D1B065432B62F672FC5B5CE689C15200B0985EF3E39781183FB6A90B936EDF1` |
| SSDEEP | `196608:pZtfrulb92GhzlCx6ywWVJYaNFHyuKNFSNmcaKKe0J2BQ3f6FIUiTgK:pZtfwiHyNxK/0J2BQv6FcTgK` |

#### Technical Assessment

- The sample is tracked as `DonutLoader` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DonutLoader_052_9fb0a1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb0a1a7ebacb4f6a65a995f5bb30020dc25f2fd5589a2303970bb805a1b242a"
    family = "DonutLoader"
    file_name = "Payment_Receipt_Ref-548921.pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:33"
  condition:
    hash.sha256(0, filesize) == "9fb0a1a7ebacb4f6a65a995f5bb30020dc25f2fd5589a2303970bb805a1b242a"
}
```

### Sample 53: `b6f5979acd8233a7`

| Field | Value |
|---|---|
| SHA-256 | `b6f5979acd8233a7ed33a88a077338a7d098882909c97a8708cf23be21fea05b` |
| Family label | `AgentTesla` |
| File name | `Accommodation and rooming list.xlsx.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:30` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d01707fa03b1cbbae079d98dfa6f2468` |
| SHA-1 | `91d8fb75927e6ac2df4f598a94c5333011145c5c` |
| SHA-256 | `b6f5979acd8233a7ed33a88a077338a7d098882909c97a8708cf23be21fea05b` |
| SHA3-384 | `ab653d6dd909d9c14872ae670b3bedde44916c6ca346b911cb40e1ff3469e24523f6d802e5c006044949061927efae74` |
| TLSH | `T166466DFE1387A2E2B4E42C375BCA5D8EA5545A87DE128C7A373810539F5EE43D92C630` |
| SSDEEP | `98304:souhxVREuCyOaZHc8Kvne00YYOZrDTQ4NZqVyM3AWUyEloZl+6L9GZhzW3/cKx07:s74nlTxZYyM3q5loZU6IZhzWMMhIL` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_053_b6f5979a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6f5979acd8233a7ed33a88a077338a7d098882909c97a8708cf23be21fea05b"
    family = "AgentTesla"
    file_name = "Accommodation and rooming list.xlsx.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:30"
  condition:
    hash.sha256(0, filesize) == "b6f5979acd8233a7ed33a88a077338a7d098882909c97a8708cf23be21fea05b"
}
```

### Sample 54: `3fc8ec0cdef68b92`

| Field | Value |
|---|---|
| SHA-256 | `3fc8ec0cdef68b926d72bf638fe3baf6e87791117babd112937402c2d5032aad` |
| Family label | `XWorm` |
| File name | `payment swift الدفعة 567 .pdf.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:26` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f1b1dbdd40a2fa9c459d1c18c315983` |
| SHA-1 | `01457594bb3e97027dbbe891cafa3837f85910dd` |
| SHA-256 | `3fc8ec0cdef68b926d72bf638fe3baf6e87791117babd112937402c2d5032aad` |
| SHA3-384 | `32100eff96ad3281d99db4ad74024639298dc50513eaf00301e7ca5ec2eb50f6596e32f86163f880bb1aa447071bc7ac` |
| TLSH | `T11E164149328051AA3BB3575E7135EA90C917860B34418F33F59CFB36BA3E907623769E` |
| SSDEEP | `98304:LcDAD3dcvKIuA5e3YwgDmf7Nntkf/Uys/chchtAnp975aCTgKvi17yZMeFg7Uxl+:LcDk3aCIuA5e3YwgSf7Nntkf/Uys/chS` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_054_3fc8ec0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc8ec0cdef68b926d72bf638fe3baf6e87791117babd112937402c2d5032aad"
    family = "XWorm"
    file_name = "payment swift الدفعة 567 .pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:26"
  condition:
    hash.sha256(0, filesize) == "3fc8ec0cdef68b926d72bf638fe3baf6e87791117babd112937402c2d5032aad"
}
```

### Sample 55: `ccc5d56d5d8214fb`

| Field | Value |
|---|---|
| SHA-256 | `ccc5d56d5d8214fba97012bab7026b4eb6fbb32c08bf9d1b32f5a2978644a674` |
| Family label | `AgentTesla` |
| File name | `Courier Tracking Details.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:23` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e298f3edcd5ec1e8ed9545cd5b50fd0` |
| SHA-1 | `f7831acf9dc83429c5c34f3ebdebe61aced4a76f` |
| SHA-256 | `ccc5d56d5d8214fba97012bab7026b4eb6fbb32c08bf9d1b32f5a2978644a674` |
| SHA3-384 | `bd958f7cfc0f0c948e37669bb877d351a321c50c62e3bc94ffec9e85d33ec174055dbe0abfaa5f7660d565bcaf248df5` |
| TLSH | `T17A467E7E962B726475BE562FF0E95D408914F8839CA48EBE31780197BB6C7134B0C6B3` |
| SSDEEP | `98304:qb59Ay8RIajcmILlRTByglLDFSYEt1nle2u1WeeBwUyzCeoEy4GH4eXERaZzvBlv:u59AyR2cmUR9zLDwYEt1nU2Fz6VzHy4y` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_055_ccc5d56d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccc5d56d5d8214fba97012bab7026b4eb6fbb32c08bf9d1b32f5a2978644a674"
    family = "AgentTesla"
    file_name = "Courier Tracking Details.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:23"
  condition:
    hash.sha256(0, filesize) == "ccc5d56d5d8214fba97012bab7026b4eb6fbb32c08bf9d1b32f5a2978644a674"
}
```

### Sample 56: `687248c21164a212`

| Field | Value |
|---|---|
| SHA-256 | `687248c21164a212ef2860d3f496e4e00f6147e26fed9bfba014ebf6f9b6798e` |
| Family label | `unknown` |
| File name | `Order-Inv-oct7483549.js` |
| File type | `js` |
| First seen | `2026-10-22 04:13:13` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59ca4bd1b84d8e74637f9d589e85e435` |
| SHA-1 | `e17076a3ef4bcd27c3dcd86133d9d3deaaa4d697` |
| SHA-256 | `687248c21164a212ef2860d3f496e4e00f6147e26fed9bfba014ebf6f9b6798e` |
| SHA3-384 | `673039bf5f719dc69c3c7871ea00235780f43294f6407e66474325bb1044f62c5bc16550f78dd473ec842f75287d681c` |
| TLSH | `T1BCF1E189AE569029DEF6F33DCF298609E72704170906E259B4DC82A45FB109D83ECDFD` |
| SSDEEP | `192:NsgIyrPOeo/WslT1bZFl/HyNSRmfiqFaUXsbwwb4:SgIgOBTdZGs8G4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_687248c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "687248c21164a212ef2860d3f496e4e00f6147e26fed9bfba014ebf6f9b6798e"
    family = "unknown"
    file_name = "Order-Inv-oct7483549.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:13"
  condition:
    hash.sha256(0, filesize) == "687248c21164a212ef2860d3f496e4e00f6147e26fed9bfba014ebf6f9b6798e"
}
```

### Sample 57: `6478d9c9dbfbbc28`

| Field | Value |
|---|---|
| SHA-256 | `6478d9c9dbfbbc282bbc35738fb0f501c91e8b419dc322f8b5c6ad37f09d7a5c` |
| Family label | `unknown` |
| File name | `MV SEA LADY QUOTATION FORM.js` |
| File type | `js` |
| First seen | `2026-10-22 04:13:08` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d6e572393123d1c521111bbfc2adfbb` |
| SHA-1 | `e69c878d62d47dace6f49251b0fabbd0b9f215ef` |
| SHA-256 | `6478d9c9dbfbbc282bbc35738fb0f501c91e8b419dc322f8b5c6ad37f09d7a5c` |
| SHA3-384 | `6105fa17aea5fe1bc33f584866c0ddc99b60aa521c6a8170e454cb9b7ee5680f6315a2e6ec35cb1810eb51f1a9e83191` |
| TLSH | `T15BB2B8449A81748053366B7ABB0AA8E4F77B096B01844A47B97CB494EFB0D1CDFE4DF1` |
| SSDEEP | `384:acdDOlU5DE7/GvxDm1kgRZ5/9gVG9EVw6kuKVIMtM8xNan89suITnjTJlYikmXd:aGDOlU5WGvxiRZ5/9gVGGVw6kuKVIMMT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_6478d9c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6478d9c9dbfbbc282bbc35738fb0f501c91e8b419dc322f8b5c6ad37f09d7a5c"
    family = "unknown"
    file_name = "MV SEA LADY QUOTATION FORM.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:08"
  condition:
    hash.sha256(0, filesize) == "6478d9c9dbfbbc282bbc35738fb0f501c91e8b419dc322f8b5c6ad37f09d7a5c"
}
```

### Sample 58: `89a674d148c2de10`

| Field | Value |
|---|---|
| SHA-256 | `89a674d148c2de101dce51a236184bcdc5f4dd50ff86e46c21fcdfc5ca767776` |
| Family label | `AgentTesla` |
| File name | `wpxcobcb.JS` |
| File type | `js` |
| First seen | `2026-10-22 04:13:05` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af241287afcb6cbbdc776d9f078b32a7` |
| SHA-1 | `0522e760a1d18601b7e478b7ed31668cbbad4f37` |
| SHA-256 | `89a674d148c2de101dce51a236184bcdc5f4dd50ff86e46c21fcdfc5ca767776` |
| SHA3-384 | `1f1f16d2dd8e0fc49d503900ed175445af399648b471cc318a28cbc1a4ffb76dd1497fd1d6030a59b059ff1126f3c337` |
| TLSH | `T1A4463C7C330ED63035BE561FE1EFED528585100B2A869E3E36782253FB6E5272A0D5B1` |
| SSDEEP | `98304:7lpsTTSaTBDHMuRffkvvguh/8KVgVx9pstVwQK1E8FnnLSbtgxrLgCpgt9CdQQkw:7lSv5bDkg8f6RstVwQ78FOYXRpgt98QA` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_058_89a674d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89a674d148c2de101dce51a236184bcdc5f4dd50ff86e46c21fcdfc5ca767776"
    family = "AgentTesla"
    file_name = "wpxcobcb.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:05"
  condition:
    hash.sha256(0, filesize) == "89a674d148c2de101dce51a236184bcdc5f4dd50ff86e46c21fcdfc5ca767776"
}
```

### Sample 59: `0387b0b7fa441b29`

| Field | Value |
|---|---|
| SHA-256 | `0387b0b7fa441b29d87d7dd9eb053c9d8db14e78bbaae226c32c4c6abcca0599` |
| Family label | `XWorm` |
| File name | `Halkbank_Ekstre_620_01100333.hta` |
| File type | `hta` |
| First seen | `2026-10-22 04:12:30` |
| Reporter | `abuse_ch` |
| Tags | `geo, Halkbank, hta, TUR, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8df4beeb87341e644c8ca8eb6a769f32` |
| SHA-1 | `954825504387188782b3126f5c6c99d69ba5669f` |
| SHA-256 | `0387b0b7fa441b29d87d7dd9eb053c9d8db14e78bbaae226c32c4c6abcca0599` |
| SHA3-384 | `64c6f769866feb1c8934eebf538b6138dbfd7d1b6827b7e9a87f87c8a64aec82c6453dd3bf22b0f79c8a7ed3db2666ef` |
| TLSH | `T1FC7202C6CEB6E7C2501F1962632665C8A3650C4A93416EEFB61ED4BE3F95D400A22F3C` |
| SSDEEP | `384:bfuPzqZtyLuPzqZtyLuPzqZtySyu3F6uPzqZtyLuPzqZtyLuPzqZty7:bG2tr2tr2t5b2tr2tr2t6` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_059_0387b0b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0387b0b7fa441b29d87d7dd9eb053c9d8db14e78bbaae226c32c4c6abcca0599"
    family = "XWorm"
    file_name = "Halkbank_Ekstre_620_01100333.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:12:30"
  condition:
    hash.sha256(0, filesize) == "0387b0b7fa441b29d87d7dd9eb053c9d8db14e78bbaae226c32c4c6abcca0599"
}
```

### Sample 60: `d4bed78fc6b7d399`

| Field | Value |
|---|---|
| SHA-256 | `d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b` |
| Family label | `Mirai` |
| File name | `d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b.elf` |
| File type | `elf` |
| First seen | `2026-10-22 04:12:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75984e3674b427bfc624f4a5ec012117` |
| SHA-1 | `17598a7f6450b80c54afb7f8a67625ad85b5cc85` |
| SHA-256 | `d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b` |
| SHA3-384 | `c88f29be9200718405bbe3d070756e9522ea6f473e5a68f209e0fb84f65533b6087730c6cbc86e7ab8b5b8cd08846dc0` |
| TLSH | `T194D3B64F7E229F6DF36C86344BB78B35A355239633A0C585D2ACDA005E6034E586FFA4` |
| TELFHASH | `t176214c188d3812f49bb52d9d66ecef72e4a170df0a225e338d00e96d9a6dd419d01c2c` |
| SSDEEP | `1536:rQ0A3K9SB2ywBruWKuWZNWg9F1cIBkml5mLg6qLy8KWlfi3N+ncpPUVe2St2LBvB:MxK9gwBUF/ka3yhWY3N+nMPYLBvB3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_d4bed78f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b"
    family = "Mirai"
    file_name = "d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b.elf"
    file_type = "elf"
    first_seen = "2026-10-22 04:12:14"
  condition:
    hash.sha256(0, filesize) == "d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b"
}
```

### Sample 61: `48f9598e8729ab0d`

| Field | Value |
|---|---|
| SHA-256 | `48f9598e8729ab0d24ea4159e910b59f39029acabcc84351b408e9ea342dd747` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:08:59` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e789851233c0e8c438cce23624ebe946` |
| SHA-1 | `0bcc12fbed24d34af950b9d3cba01c87198544a6` |
| SHA-256 | `48f9598e8729ab0d24ea4159e910b59f39029acabcc84351b408e9ea342dd747` |
| SHA3-384 | `4a7a2b3fec7bca279b7cadda9d453b327f9424eb837cf7fec18403b36b024ae2a0ad19e8b9782a5fb00da3b96ce18f20` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T11B471229A38742DFC3668230697DB761FD2D8964A108CD3AD799D5BD3CB1C2E68C13E1` |
| SSDEEP | `393216:1RSw6RUhwWBcJNbdcFiJTTlrKJ1vZX7SNvdnmITriT:1R1qrbdcwJ3l+J1tuaT` |
| ICON-DHASH | `68e4b0f2e0f8d860` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_48f9598e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f9598e8729ab0d24ea4159e910b59f39029acabcc84351b408e9ea342dd747"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:08:59"
  condition:
    hash.sha256(0, filesize) == "48f9598e8729ab0d24ea4159e910b59f39029acabcc84351b408e9ea342dd747"
}
```

### Sample 62: `2548b7c1bda26e55`

| Field | Value |
|---|---|
| SHA-256 | `2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502` |
| Family label | `RustyStealer` |
| File name | `WindowsDefender.msi` |
| File type | `exe` |
| First seen | `2026-10-22 04:04:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, msi, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b78cd901b6a1f67221e95172577aeadf` |
| SHA-1 | `82f96d39ab46df33636f2353a23dfb42a12188cf` |
| SHA-256 | `2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502` |
| SHA3-384 | `5255b84cd24c5c3367266aa99ec8fc9bb0b62a51e7eec23c87ea3356e6f1dfe01f63a47fed5d1a77924a712549371c58` |
| IMPHASH | `36b74bc25e206376df7a9e5994e70816` |
| TLSH | `T124D538617B5A99EDC19BC07483468672693270DB0F35BAFF44C486383E6AAF51F3C258` |
| SSDEEP | `49152:zpUaV313IwdBCa0KAXrlnXrIZ9aYRhnQXpYf8vqCU2vtAImrBzYG+q:l59wa0y2RuBj+q` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_062_2548b7c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502"
    family = "RustyStealer"
    file_name = "WindowsDefender.msi"
    file_type = "exe"
    first_seen = "2026-10-22 04:04:43"
  condition:
    hash.sha256(0, filesize) == "2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502"
}
```

### Sample 63: `be8dbcf25f2b83fb`

| Field | Value |
|---|---|
| SHA-256 | `be8dbcf25f2b83fb1ee2af5683d6fc867656b37d19119a447a228a3ace5fb612` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:04:23` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9dc4f1990c0fc46a4c3c48caa81a712` |
| SHA-1 | `419461b972f6dd0e83fafb051a77ef0c88f6ea98` |
| SHA-256 | `be8dbcf25f2b83fb1ee2af5683d6fc867656b37d19119a447a228a3ace5fb612` |
| SHA3-384 | `590b8a4b4d09bdbe891d485c6496f38b0649d33a26c7fcf7de1d4ae90a8252c4b83a3faf751b3646c3852690ae0c4f98` |
| IMPHASH | `535ee7a1a3cddc1834e2a3597917d5b8` |
| TLSH | `T195379E51B70F09F2FA435C3645FAAB2F7B36E2DC8DB0C559E4243826B692C1B86DC191` |
| SSDEEP | `393216:roIBdRoo2CAwQPbjj8iCWudpufRiCqr63bNKD4T+a:9zRmpwnfzufRz6WQD4TD` |
| ICON-DHASH | `69cc9c9e8686c479` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_063_be8dbcf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be8dbcf25f2b83fb1ee2af5683d6fc867656b37d19119a447a228a3ace5fb612"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:04:23"
  condition:
    hash.sha256(0, filesize) == "be8dbcf25f2b83fb1ee2af5683d6fc867656b37d19119a447a228a3ace5fb612"
}
```

### Sample 64: `eda7de5855def39b`

| Field | Value |
|---|---|
| SHA-256 | `eda7de5855def39b672cb603c522054b827cdb5597c5b3c84e9a65b60d91deac` |
| Family label | `QuasarRAT` |
| File name | `30beedc7b8d9c91c8575191eb064226f.exe` |
| File type | `exe` |
| First seen | `2026-10-22 04:03:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30beedc7b8d9c91c8575191eb064226f` |
| SHA-1 | `9466127f0fef879a1ab73c29d714586d67189c0f` |
| SHA-256 | `eda7de5855def39b672cb603c522054b827cdb5597c5b3c84e9a65b60d91deac` |
| SHA3-384 | `0068db9afff9ecfc6c1216f4d0826e39c95552732386fc052c4915a0f03920ec95641cee0c070eb773dbe8d72ba4c385` |
| IMPHASH | `e59d00b0d90522ee1a983f13d4ff7e50` |
| TLSH | `T10596017D1AA85FE6E346F23C351A5C60BFC50CB10F9E6841720ACAF1FD68571A6C988D` |
| SSDEEP | `196608:Tp1b+wzozD3qqbVvKiwiX7nmDfOcghrN+Qil/geLn+7:91TqbYiwQmwKlR8` |
| ICON-DHASH | `aa38ce868282b882` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_064_eda7de58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda7de5855def39b672cb603c522054b827cdb5597c5b3c84e9a65b60d91deac"
    family = "QuasarRAT"
    file_name = "30beedc7b8d9c91c8575191eb064226f.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:03:18"
  condition:
    hash.sha256(0, filesize) == "eda7de5855def39b672cb603c522054b827cdb5597c5b3c84e9a65b60d91deac"
}
```

### Sample 65: `65e1ec6eb44e5208`

| Field | Value |
|---|---|
| SHA-256 | `65e1ec6eb44e5208f160eb7875f73c8f53392c4994970e6b9f48e3ab2e0d21ab` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:01:34` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4675d81e83bfbef22a62ffebaf8f0f4` |
| SHA-1 | `38f6347d71ebc958b878b6c0248e8daf3faa24ce` |
| SHA-256 | `65e1ec6eb44e5208f160eb7875f73c8f53392c4994970e6b9f48e3ab2e0d21ab` |
| SHA3-384 | `6469b0d0a1807568c74e1ddba3aad401245332841072a98e5bc66bd14c6fa731a4cce66ecb79de1ebde2a7e9fe310dbd` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1B4471229638752DFC3268270596C7761FC2E9964A208DD7BD7ADC17D3CB1C2E68C12E2` |
| SSDEEP | `393216:qSk+ia02C2agxeOjp+yn6t5B3oqk7GtOKpYutJI8IU8uP0:g+EUv+ynI5BoL7G5KSP0` |
| ICON-DHASH | `68f0c8e8c8c8f468` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_65e1ec6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65e1ec6eb44e5208f160eb7875f73c8f53392c4994970e6b9f48e3ab2e0d21ab"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:01:34"
  condition:
    hash.sha256(0, filesize) == "65e1ec6eb44e5208f160eb7875f73c8f53392c4994970e6b9f48e3ab2e0d21ab"
}
```

### Sample 66: `5cdf2668ee291040`

| Field | Value |
|---|---|
| SHA-256 | `5cdf2668ee2910407f2acd69fcdc565817e2f748c372f4ea187d1077719c8ea6` |
| Family label | `unknown` |
| File name | `fuck_niggers_44.hta` |
| File type | `hta` |
| First seen | `2026-10-22 04:01:26` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `539b8766c4be412d872b67621624402e` |
| SHA-1 | `0d5cbb7bf6964ad0402bea4386872b095ccd39e9` |
| SHA-256 | `5cdf2668ee2910407f2acd69fcdc565817e2f748c372f4ea187d1077719c8ea6` |
| SHA3-384 | `326e8c55875876b88ac9db0ec3a5720b4e3b7d83a1d09dd8b8f4f96029be444bff96b7c83bacb9040744b2c922917b79` |
| TLSH | `T15142195CAED161B0EB1707DEB7AF24690228A0C7240DC484F54CEDE87F4ABDC4A56B57` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzNbqFtCgSEpRUM:sXX+/DV7k/3IFtVRUM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_5cdf2668
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cdf2668ee2910407f2acd69fcdc565817e2f748c372f4ea187d1077719c8ea6"
    family = "unknown"
    file_name = "fuck_niggers_44.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:01:26"
  condition:
    hash.sha256(0, filesize) == "5cdf2668ee2910407f2acd69fcdc565817e2f748c372f4ea187d1077719c8ea6"
}
```

### Sample 67: `223c99c66b750084`

| Field | Value |
|---|---|
| SHA-256 | `223c99c66b750084ad673dca01480fd01e644807bcb7bacdbc1ecde85600bd99` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 04:01:20` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1da8a70d5e8225847efe6a1280982241` |
| SHA-1 | `c963a7c10f7c807b3b41c3815214f3cd0b22bfb4` |
| SHA-256 | `223c99c66b750084ad673dca01480fd01e644807bcb7bacdbc1ecde85600bd99` |
| SHA3-384 | `ef1d940738da182a7964adccfb1b1adaa832fe6b8ab0663066987453dc6a7b7a38b3a6d6eab5c124d75893540c353185` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T11036232A678780EFC397927050AD7762FF2DDD24A9848C38C699E2BD3E71C1E14C46E5` |
| SSDEEP | `49152:B/iF4/7Sh7KSRrtLugYjjNe8mEZfPn0jqykyaaFkSDEENpwht6wNA:xiFfV3dujc8/Zn0jq8aaFkTELwhHA` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_223c99c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "223c99c66b750084ad673dca01480fd01e644807bcb7bacdbc1ecde85600bd99"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:01:20"
  condition:
    hash.sha256(0, filesize) == "223c99c66b750084ad673dca01480fd01e644807bcb7bacdbc1ecde85600bd99"
}
```

### Sample 68: `58dffd262bb9b3c8`

| Field | Value |
|---|---|
| SHA-256 | `58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582` |
| Family label | `unknown` |
| File name | `vlc-3.0.23-win64_crypted.exe` |
| File type | `exe` |
| First seen | `2026-10-22 04:00:44` |
| Reporter | `Thekalebmiller` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9234bea364e01ce9a1364fca142ac415` |
| SHA-1 | `9c4266b80025e52fffc66ae37fa65f07ed440b54` |
| SHA-256 | `58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582` |
| SHA3-384 | `f644be82e6306cc79d00a96df0034cdb8c6988bff098a521851a622a651436941e735035f69c7afab57faf933e6981e5` |
| IMPHASH | `555aba33e471c8bf2b9fc3922635a660` |
| TLSH | `T129C3D061858BC1E7E52E427DE527258BC5303D0893709DBF93B06E2E7D96D406BBA20F` |
| SSDEEP | `3072:z/KExfFaWsbiQ2k9Hc3/nl6LAHkzI1UfgEA6IIyRZ:DKExfVs2/k96kAD` |
| ICON-DHASH | `30b2b2f069f0d48a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_58dffd26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582"
    family = "unknown"
    file_name = "vlc-3.0.23-win64_crypted.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:00:44"
  condition:
    hash.sha256(0, filesize) == "58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582"
}
```

### Sample 69: `e431ed40fb621acb`

| Field | Value |
|---|---|
| SHA-256 | `e431ed40fb621acba0e0d27fde4abe0d8ffca2968ca96561ed194334593e3976` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:59:41` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9659b05bf6a6371e2906182fe10a7662` |
| SHA-1 | `f21d1e9c001625bc7742f5d7444ec35c2c126435` |
| SHA-256 | `e431ed40fb621acba0e0d27fde4abe0d8ffca2968ca96561ed194334593e3976` |
| SHA3-384 | `bf583b54285f8beea7f4bbd1342a23aa40255cc1191b85577b5e5632b91bee0040ad14f6f931a51bbd489b12a5a241d8` |
| IMPHASH | `27e54e8506f211c9fbb285b697de3d49` |
| TLSH | `T173A733608CD4F93BE01315B5FB24899EF182DB591ABCC5C7A639AB1B36A0D05C54F8CB` |
| SSDEEP | `786432:jSAcyv9b6pGw+VRTpEYeyIZncMKuEXiIY:Xcyv9up35Y5IZcVuhI` |
| ICON-DHASH | `30b2b2f069f0d48a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_e431ed40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e431ed40fb621acba0e0d27fde4abe0d8ffca2968ca96561ed194334593e3976"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:59:41"
  condition:
    hash.sha256(0, filesize) == "e431ed40fb621acba0e0d27fde4abe0d8ffca2968ca96561ed194334593e3976"
}
```

### Sample 70: `623e15ebdeed96fc`

| Field | Value |
|---|---|
| SHA-256 | `623e15ebdeed96fce459f07444cfbbb0fa3def8486b045c0b4e70befbe640c91` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:56:55` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77f07f68e604e949f00bedf590a09de0` |
| SHA-1 | `940d41f94574d0d02f81873420a413e30daa3f58` |
| SHA-256 | `623e15ebdeed96fce459f07444cfbbb0fa3def8486b045c0b4e70befbe640c91` |
| SHA3-384 | `20d56d82a44f0531ae33e081c8c04cfdd8f418dc40222e068d0b67d32ec5fdc8631958afb0ed2ea75a832b32966cb0d4` |
| IMPHASH | `76cc27f3aad86f454da9727f5b11719e` |
| TLSH | `T151379E91B70F19F2FA475C3745F6AB2F7B36E2DC8D70C559E8343826B692C0A869C190` |
| SSDEEP | `393216:nuDL8xJytTLdywboJ7+v0MdXrfiIGA7XJASlB9M8VWv05I0U7bRRC3gG+YZ1F6ja:uDL82TLdywboJ7+v0MdXrfxGcXJASlBb` |
| ICON-DHASH | `78e0f2d8e8ecdc60` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_070_623e15eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "623e15ebdeed96fce459f07444cfbbb0fa3def8486b045c0b4e70befbe640c91"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:56:55"
  condition:
    hash.sha256(0, filesize) == "623e15ebdeed96fce459f07444cfbbb0fa3def8486b045c0b4e70befbe640c91"
}
```

### Sample 71: `a76e63b7dbf2aa5d`

| Field | Value |
|---|---|
| SHA-256 | `a76e63b7dbf2aa5d1b04f46c23ac5869bcc6544c38c99de6ca72a0595743102e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:54:16` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7671031cfd0f8f1238c64217c49aa4a` |
| SHA-1 | `a6a258871887fe45d40b0a2aacd10bf92e731efe` |
| SHA-256 | `a76e63b7dbf2aa5d1b04f46c23ac5869bcc6544c38c99de6ca72a0595743102e` |
| SHA3-384 | `6a339439c8eb528a29f49048a8fb2036e420e609a7a021757946dcfc91d786c5977a1e0e54629b89adf2b8c5f894c05f` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T19B57122D678B01DFC36A8230597C6761FD6EDA646508DD3AC7A9C1BD3CB1C2E64C12E2` |
| SSDEEP | `393216:O7HHIyiaoO+56lv7jtdT4hdbTsMrg+6r1dJuO6gLbuEJ:O0Sz7jtl4jbYMrypAEJ` |
| ICON-DHASH | `01d4f8968698daca` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_a76e63b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a76e63b7dbf2aa5d1b04f46c23ac5869bcc6544c38c99de6ca72a0595743102e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:54:16"
  condition:
    hash.sha256(0, filesize) == "a76e63b7dbf2aa5d1b04f46c23ac5869bcc6544c38c99de6ca72a0595743102e"
}
```

### Sample 72: `30e727c0414d4b8d`

| Field | Value |
|---|---|
| SHA-256 | `30e727c0414d4b8d1f7b40a63a1371fcee246ac8c9eb32c3840e25bf63cf3497` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:50:35` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d28822bd4af65ab16644f344e5364caa` |
| SHA-1 | `76ef729c26b0ac6c2526564363a2f9a7533de2a6` |
| SHA-256 | `30e727c0414d4b8d1f7b40a63a1371fcee246ac8c9eb32c3840e25bf63cf3497` |
| SHA3-384 | `3e1381ae510fdea3010906bb84a8af4ee0d08f24328fdc0d4c37c844a2a62fecafe71bda48bc613ef96b12462c805d42` |
| IMPHASH | `4a0766ad8ab5950dac78233750c56f78` |
| TLSH | `T170379F91B70B05F2FA475C3785F6AB2F7B36E6DC8D70C559E8243816B6A2C0B86DC190` |
| SSDEEP | `393216:ZtqebMt8kv7lfy+R6YSu12tVlgF3vflfGWfhzh:ZtDMt8YBymZSui8F3Z15t` |
| ICON-DHASH | `c2c4c4c4c0c4c4a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_30e727c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e727c0414d4b8d1f7b40a63a1371fcee246ac8c9eb32c3840e25bf63cf3497"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:50:35"
  condition:
    hash.sha256(0, filesize) == "30e727c0414d4b8d1f7b40a63a1371fcee246ac8c9eb32c3840e25bf63cf3497"
}
```

### Sample 73: `95b32434fe39c8bd`

| Field | Value |
|---|---|
| SHA-256 | `95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:48:14` |
| Reporter | `Bitsight` |
| Tags | `d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07b99bab65206777d3bcc1100c881d53` |
| SHA-1 | `9157a7fd81371a4faa910b8df8b54c86748035be` |
| SHA-256 | `95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb` |
| SHA3-384 | `23345c8cacf20927b579430b804f851cfb4190b4ba37866fccc20b5863f307c1ea13ebb25e1dd95ee1338d430d7d142e` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T159571229A78701DFC3668230597C7761FD6D89A4A208CD3AD799C6BD3DB1C2E28C53E1` |
| SSDEEP | `393216:gYloGaHt0qhC5YMuMDutORHVQo5WnKx+TLDvqkrhrWcY:gYlgpZMDuQR1QcWnP/nY` |
| ICON-DHASH | `68f0f0c4c0c4cc70` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_95b32434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:48:14"
  condition:
    hash.sha256(0, filesize) == "95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb"
}
```

### Sample 74: `0507e4c85849697c`

| Field | Value |
|---|---|
| SHA-256 | `0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:47:56` |
| Reporter | `Bitsight` |
| Tags | `d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0875c403b8638907cfe71ff98fc9f8a7` |
| SHA-1 | `dbb9fd86f03b2cd42a5d83c45f6be279e5a530f8` |
| SHA-256 | `0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c` |
| SHA3-384 | `814ffc8921a95036e503a1cee619af80180a50811d2f2e8fc6bdf6fd22ba4a6bd582c20a17548391bac58873ed94e6cc` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T15936232A772346DFC7A78230216D7BA1E9289D442844AD39CBA8F5BD3EF1C5D50C87E1` |
| SSDEEP | `49152:zYCtdE2E/pSzWsXIo2+vDjYiTY9EM80a7GaunLH:zRtd5hzWsYavvYif0acr` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_0507e4c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:47:56"
  condition:
    hash.sha256(0, filesize) == "0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c"
}
```

### Sample 75: `41e1ca8515fb9aad`

| Field | Value |
|---|---|
| SHA-256 | `41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:47:46` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, CoinMiner, d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `672788c9307473e4e9b170b173b5b858` |
| SHA-1 | `4101fcb3639f3008451db4970d4dd393ef366292` |
| SHA-256 | `41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d` |
| SHA3-384 | `d552105a758af4a73162acb4ef92e3da4bcd37cbb86a31676fe29b21a74127ae1f23da24aa204ad91a519ad65a018eac` |
| IMPHASH | `b9fb49ef7a6c6370c3e6466481683588` |
| TLSH | `T1BC379E91B70F09F2FA475C3785F6AA2F3B76E1DC8DB0C559F4343856E29280A86EC191` |
| SSDEEP | `393216:PqgnVy/FRFiN3JTwhF2zaHejsHg5GWXKzK+fv:Px8/FR4wF2za+j9GIaK4v` |
| ICON-DHASH | `69e8ccccc4cce871` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_075_41e1ca85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:47:46"
  condition:
    hash.sha256(0, filesize) == "41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d"
}
```

### Sample 76: `1fffae3cb845be03`

| Field | Value |
|---|---|
| SHA-256 | `1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.PUA.Tool.VulnDriver.26.17.17960` |
| File type | `exe` |
| First seen | `2026-10-22 03:47:19` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02bc1c0439a973fa8ca1f7c6696658c0` |
| SHA-1 | `c669a07c8ad725f1d48aed994a874fe84405ca40` |
| SHA-256 | `1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b` |
| SHA3-384 | `37c596c33b5ca26e0dc9f54f0e199deecb2c666ac5f0e0c4ba815ccee4581587918828331035ef88b213c870fddf2212` |
| IMPHASH | `70d95d244db4c9ba22a801a149570551` |
| TLSH | `T126A48D5193F84A56D7AA2F31E5F1A9784736A90534B2CB2E59293FD40C237848E323DF` |
| SSDEEP | `6144:Z3DY9G1HR2TDNDVjfnIMx8R/wxrMsVmEd6xMtk7pIefpahwdpNo:v1x2BVj8R/wxozPfp5Ti` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_1fffae3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b"
    family = "unknown"
    file_name = "SecuriteInfo.com.PUA.Tool.VulnDriver.26.17.17960"
    file_type = "exe"
    first_seen = "2026-10-22 03:47:19"
  condition:
    hash.sha256(0, filesize) == "1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b"
}
```

### Sample 77: `706cc7d2b5dccf4b`

| Field | Value |
|---|---|
| SHA-256 | `706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1` |
| Family label | `Prometei` |
| File name | `706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1` |
| File type | `elf` |
| First seen | `2026-10-22 03:44:37` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6645b831bbeadbed4bce169979016a5b` |
| SHA-1 | `9917572abf94e9886e13fec2b9d5ac755a0fba4f` |
| SHA-256 | `706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1` |
| SHA3-384 | `b59a833b68a153bb4565034e2bb9da9d2ee261f7154188e1d109c954853c415a2abc5ed8e88e85f1b59a0b27f6f24e63` |
| TLSH | `T19AA423EF776D8D3DF62AE674FB994342C420647054D6248B9F6E5BC88230983092D76F` |
| SSDEEP | `6144:T0QXWJDXKRRBkJyEYxGpCH+aXOWYLr+G+0zgT6kUPrXH6sYvOffPlY7girs47kFG:otJDkjyyVGpCif+G0nGrKK3P+blSoHV` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_077_706cc7d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1"
    family = "Prometei"
    file_name = "706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1"
    file_type = "elf"
    first_seen = "2026-10-22 03:44:37"
  condition:
    hash.sha256(0, filesize) == "706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1"
}
```

### Sample 78: `6ec4916adf65beaa`

| Field | Value |
|---|---|
| SHA-256 | `6ec4916adf65beaa26bb4944cbb4bb80cf33a716f5bcd8177750428c665cddce` |
| Family label | `Prometei` |
| File name | `b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745` |
| File type | `elf` |
| First seen | `2026-10-22 03:44:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f2065811ba397599bd7cfc32bc94b3c` |
| SHA-1 | `8366c7b6ac15914fd1de64ece28961143d87017a` |
| SHA-256 | `6ec4916adf65beaa26bb4944cbb4bb80cf33a716f5bcd8177750428c665cddce` |
| SHA3-384 | `7daf9585d6e83a9b5ca139ea54bda0f7c4ff4d4722a9f8d73e06b1199c0f01a5694d471b948deff1d82d4028d29df9db` |
| TLSH | `T11D166D6AB2B354FCC15BD03097AFC6636835B4B50131BC7B36809A352E72E605B6DF62` |
| TELFHASH | `t1290252701eb6b831b3a7d9067343d8746d336c1926f835f4291276d4de59a808cbb8b3` |
| SSDEEP | `98304:y7qMUgZMVbooDl00X+qg+kqn+JEhf94Z9JgYVVjpZP:77Dp94Z9Jg2jj` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_078_6ec4916a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ec4916adf65beaa26bb4944cbb4bb80cf33a716f5bcd8177750428c665cddce"
    family = "Prometei"
    file_name = "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
    file_type = "elf"
    first_seen = "2026-10-22 03:44:30"
  condition:
    hash.sha256(0, filesize) == "6ec4916adf65beaa26bb4944cbb4bb80cf33a716f5bcd8177750428c665cddce"
}
```

### Sample 79: `9ac8d3b7c365839c`

| Field | Value |
|---|---|
| SHA-256 | `9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb` |
| Family label | `unknown` |
| File name | `9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb` |
| File type | `7z` |
| First seen | `2026-10-22 03:44:19` |
| Reporter | `c2hunter` |
| Tags | `7z, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71297cbb898c7aefd04a9516a40bd47b` |
| SHA-1 | `8d4893e5d3dff7159d5e3bfecc289bb1cc9d89a6` |
| SHA-256 | `9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb` |
| SHA3-384 | `9c64a42756004c369a0620d9407e4d5d5966b914c52ae17f77168e10686f76a35261ad0f82a5deea95387091d60c4b11` |
| TLSH | `T117B53313E34F7FD2048E6564ED843807A007341FDB5B3221E54D3A2A85EBEF59A7A85B` |
| SSDEEP | `49152:4SBvzzJXofjU8dGeL81I001aDyTB6c75wDw9RpWIShegaKU2b:V3Nor7dk0AYErrcg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_9ac8d3b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb"
    family = "unknown"
    file_name = "9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb"
    file_type = "7z"
    first_seen = "2026-10-22 03:44:19"
  condition:
    hash.sha256(0, filesize) == "9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb"
}
```

### Sample 80: `b6be1a0a286bf132`

| Field | Value |
|---|---|
| SHA-256 | `b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379` |
| Family label | `unknown` |
| File name | `b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379` |
| File type | `exe` |
| First seen | `2026-10-22 03:44:14` |
| Reporter | `c2hunter` |
| Tags | `exe, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f69589a7081f375429c7c3cec166665` |
| SHA-1 | `cfdba7c7dd48eeea5af754c0324620575ed02fc7` |
| SHA-256 | `b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379` |
| SHA3-384 | `b73b5f552fc0f0fcf4be1501dfddc01cb5e0c42debb44db3e028df2c5faa8024008cfc2f4b47ae5ed326e64f971526d0` |
| IMPHASH | `966f66d590d26a3af13ea18480fb301e` |
| TLSH | `T1AA34BE63A478EAAFDD9D2F334C8A990763B62FD5C880217E1C90750EFD1B9086F75522` |
| SSDEEP | `6144:HyL5UhfCk9J8GNWAcmsy223vi7H3fFZAFwFlkhF1dYRyHCY:E5sf8GNGmoMeH3tUTzdY4i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_b6be1a0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379"
    family = "unknown"
    file_name = "b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379"
    file_type = "exe"
    first_seen = "2026-10-22 03:44:14"
  condition:
    hash.sha256(0, filesize) == "b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379"
}
```

### Sample 81: `b34dc6f21a5254c2`

| Field | Value |
|---|---|
| SHA-256 | `b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745` |
| Family label | `Prometei` |
| File name | `b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745` |
| File type | `elf` |
| First seen | `2026-10-22 03:44:11` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9298ba879c1979cccd00a6b1fce09ae` |
| SHA-1 | `c185d735f0e61601498cfb7b8986f52fbeecd002` |
| SHA-256 | `b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745` |
| SHA3-384 | `20fa3631d81285993b9f03c2d80c1c76e2303cccc791565772476dd723ff8ffe0e745c2103d433dadad999ed36f4f28c` |
| TLSH | `T1CD8533FEE06903F2F967A16903547FF15042E4735CFFB4CA4BA0D6A05A3A9DD8762206` |
| SSDEEP | `49152:T3I40XlSbi5Taa2K5Iq/7Y+gWmrqMgC/WGXSCNo:TOXlKiUo/k+gDquukSgo` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_081_b34dc6f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
    family = "Prometei"
    file_name = "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
    file_type = "elf"
    first_seen = "2026-10-22 03:44:11"
  condition:
    hash.sha256(0, filesize) == "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
}
```

### Sample 82: `c6e33d5b4a7fa461`

| Field | Value |
|---|---|
| SHA-256 | `c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37` |
| Family label | `Prometei` |
| File name | `c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37` |
| File type | `exe` |
| First seen | `2026-10-22 03:44:04` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4872d86e8c280487690c5cdcfdbd228` |
| SHA-1 | `f6ed3298f0d5fa41e1bf0a0c5f1a675ffa1350e9` |
| SHA-256 | `c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37` |
| SHA3-384 | `da51de081230cc0c0937e8f228265f32c8aae43046328d832510b1f04817d1b7ce81f293dfc34b72a2e074af2eaa7e0b` |
| IMPHASH | `11d7574f4124bae26b618543eea709ef` |
| TLSH | `T12C746B01335EEAE6F12B187050687A376DBCD534E12F18F2F7C55C8A346CAC192A5B9B` |
| SSDEEP | `6144:EIzgc6Zod8ZVtMjKYEXDWn+IfpahiXe7WMtILM9:ucR8ZVtMjKYASn+IxahiEt39` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_082_c6e33d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37"
    family = "Prometei"
    file_name = "c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37"
    file_type = "exe"
    first_seen = "2026-10-22 03:44:04"
  condition:
    hash.sha256(0, filesize) == "c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37"
}
```

### Sample 83: `146023243d56a97d`

| Field | Value |
|---|---|
| SHA-256 | `146023243d56a97de6782daf39ef79715fd12ef3efd8554e9fd1021940a23ea3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:42:19` |
| Reporter | `Bitsight` |
| Tags | `19ccb70dbc12ef919d5869277e598933, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56313cb4d5fe6b86a46e278ee0fbba1e` |
| SHA-1 | `c25d1fb522c1369b8173d91a803f85280855497b` |
| SHA-256 | `146023243d56a97de6782daf39ef79715fd12ef3efd8554e9fd1021940a23ea3` |
| SHA3-384 | `96d712a8c49c6af73fccab2a78a8bdc63f8546642d38a32f425f8b0adaaccc4ee1949b7c16c1295ae809e0ac8c5819c2` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T14B571229A79711DFD3268230597CB761FD2EC964A208CD3AC799C5BD3DB1C2E24C52E2` |
| SSDEEP | `393216:zHHHHHHHHHPXCONg23kZRGzY1qiFMU7tJXqLJdC6EEHPDmCvZYLIsVln2:zHHHHHHHHH/HUueFMUZJaLS6EG6hn2` |
| ICON-DHASH | `1f3b2b2b23233b1b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_14602324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "146023243d56a97de6782daf39ef79715fd12ef3efd8554e9fd1021940a23ea3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:42:19"
  condition:
    hash.sha256(0, filesize) == "146023243d56a97de6782daf39ef79715fd12ef3efd8554e9fd1021940a23ea3"
}
```

### Sample 84: `a9969fcef2ad4865`

| Field | Value |
|---|---|
| SHA-256 | `a9969fcef2ad4865519c7325ca458c3d586c5937fd3ada51c3eef684c4334560` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:38:36` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f59e5fb20de0581d2660794b7ca35445` |
| SHA-1 | `c8969d3dba58e68a142e69be7a04ff33b6d81f96` |
| SHA-256 | `a9969fcef2ad4865519c7325ca458c3d586c5937fd3ada51c3eef684c4334560` |
| SHA3-384 | `5e5304871c5185129ac6a81869f1c7e11d63dfa866280b56c7d92b7ed88631ffcfa61de3956a47a1321f9d9ad4df932d` |
| IMPHASH | `c0ddc82c6cd1e4bf3d72ad1d7d3d0b4b` |
| TLSH | `T15457AF51B30B44F6FB434C3685F9AB7F7B35EA9CC974C557E428382ABA72C1A458C290` |
| SSDEEP | `393216:wKmXzcgmgzEhYGsRWENhOipiCiUqLCXeJH1QcKyg3+:R0igxGuACi5uXSXKyg3+` |
| ICON-DHASH | `e4e4a4a0b0b4b0b9` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_084_a9969fce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9969fcef2ad4865519c7325ca458c3d586c5937fd3ada51c3eef684c4334560"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:38:36"
  condition:
    hash.sha256(0, filesize) == "a9969fcef2ad4865519c7325ca458c3d586c5937fd3ada51c3eef684c4334560"
}
```

### Sample 85: `18d0c7d0078e3106`

| Field | Value |
|---|---|
| SHA-256 | `18d0c7d0078e310617ffc4e75d93becfafc6434e6aef839a9587aaa2ca39ecfa` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:36:04` |
| Reporter | `Bitsight` |
| Tags | `d852ede598d72f2b3a4050576466ec62, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc835182790618fa9c05bd00d1436b6e` |
| SHA-1 | `2427c187e1217080afa2e91b4add31ea8aad799f` |
| SHA-256 | `18d0c7d0078e310617ffc4e75d93becfafc6434e6aef839a9587aaa2ca39ecfa` |
| SHA3-384 | `ccd57cca1f92f5af9bc1abae108c5a6122f06f592b1bcbcc8c497f8f7aaadfe0b1a7959ec4a2649f8d185de3c8579903` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T1C836232D730B51DFD79B82701868A761FD3D9E58A244C93EC289E07E7DB2C2E65C16E0` |
| SSDEEP | `49152:nY27H5VOb4JdTZVXS2lWvDj8+GKllFdsjqdkMN38HYkqzOvVo:ndtVRzri2lWvDo+G83sjqdkIsHnq6vVo` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_18d0c7d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18d0c7d0078e310617ffc4e75d93becfafc6434e6aef839a9587aaa2ca39ecfa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:36:04"
  condition:
    hash.sha256(0, filesize) == "18d0c7d0078e310617ffc4e75d93becfafc6434e6aef839a9587aaa2ca39ecfa"
}
```

### Sample 86: `766113abb85d8186`

| Field | Value |
|---|---|
| SHA-256 | `766113abb85d8186721076f23422f6b7b5e773c06fd3451343f751568b4b091e` |
| Family label | `unknown` |
| File name | `fuck_niggers_30.hta` |
| File type | `hta` |
| First seen | `2026-10-22 03:35:24` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `633dea7478ea64b22c5caaa552263497` |
| SHA-1 | `ede1845d0d299b3a448f3798d8221d645aca7f8d` |
| SHA-256 | `766113abb85d8186721076f23422f6b7b5e773c06fd3451343f751568b4b091e` |
| SHA3-384 | `eccb3a20ecf895d7cfe2bdac662ab7a27f4dc4f4d93f9da7265d92fcf601fe054a8f1a2721e563887063040a2633edb8` |
| TLSH | `T1C1422B4CAED1A1B0FA1707DEB3AF24690268A0C32009C484F54CDDE87F4A7DC4A57B5B` |
| SSDEEP | `192:sRHNsGeTHQpD+da6+888+UV7tDoj/pxzmbqFtCySm9RUzHH:sRX+/DV7k/3dFtbRUzHH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_766113ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766113abb85d8186721076f23422f6b7b5e773c06fd3451343f751568b4b091e"
    family = "unknown"
    file_name = "fuck_niggers_30.hta"
    file_type = "hta"
    first_seen = "2026-10-22 03:35:24"
  condition:
    hash.sha256(0, filesize) == "766113abb85d8186721076f23422f6b7b5e773c06fd3451343f751568b4b091e"
}
```

### Sample 87: `5c195f4179826554`

| Field | Value |
|---|---|
| SHA-256 | `5c195f41798265546fdf058f2b4c4a2f35f88532b60b1d3976ae27f58aaec8ad` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:33:13` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9426f43acb32e29486d15777200ac0a` |
| SHA-1 | `93eddf1e2aecad78e9761aec95651874d1087429` |
| SHA-256 | `5c195f41798265546fdf058f2b4c4a2f35f88532b60b1d3976ae27f58aaec8ad` |
| SHA3-384 | `264936b370bea2c0a96dc92a34a4f533a17ca62b10f950a1c65329604f0b710a9ae32dabc36a630ba13f82adbff5bf82` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1F1471229A34B01DFC32A8230597C6761FD6EDA64A248DD3ED799D17D3CB1C2E24C62E1` |
| SSDEEP | `393216:IFDUKHWTczfbPP0VdvQiqnY2spXfnxu/S4gOZQVmCbk2/AQlfue1:I9L2TyfjmT2spPnc/rgOuJQe1` |
| ICON-DHASH | `69d0f4e0d0d4e069` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_5c195f41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c195f41798265546fdf058f2b4c4a2f35f88532b60b1d3976ae27f58aaec8ad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:33:13"
  condition:
    hash.sha256(0, filesize) == "5c195f41798265546fdf058f2b4c4a2f35f88532b60b1d3976ae27f58aaec8ad"
}
```

### Sample 88: `72d191ea359d563f`

| Field | Value |
|---|---|
| SHA-256 | `72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-22 03:30:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6747be22d3b904c54a5d4ba53d1ccbff` |
| SHA-1 | `bdac5417b642b74343ebd01c7dcf6d5262e24d54` |
| SHA-256 | `72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f` |
| SHA3-384 | `864617a9231187591900165aa26a5fb6d9789cbc11e3a1406ce73ef30e3089cae334a808213d6a3d6233be621107c531` |
| TLSH | `T15E556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmr:OSCX9B9tGNnD+pb0qAYPWTM2wza6+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_72d191ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-22 03:30:52"
  condition:
    hash.sha256(0, filesize) == "72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f"
}
```

### Sample 89: `acb4328b2d6bfa66`

| Field | Value |
|---|---|
| SHA-256 | `acb4328b2d6bfa66ff3d396fb80e266e684876057382ed768393c69d8174f3ed` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:29:29` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32daafa759bce140a3318b97e4b8fbca` |
| SHA-1 | `dd2932fde160456cc0257d9929548e2571f20f8a` |
| SHA-256 | `acb4328b2d6bfa66ff3d396fb80e266e684876057382ed768393c69d8174f3ed` |
| SHA3-384 | `b6583a7ec10e22048c427206c760ba807a91e4e1c79a9aaec29f9ff717beecdb9ab2fe034f2930d4815edf2c2fb3ee1e` |
| IMPHASH | `1e0c02926537dd0c9e62ee48ce396853` |
| TLSH | `T1B847A051B70B05F6FF434C3645F9AB2F7B39E2DC8974C55AE428242ABAA2C1F45DC290` |
| SSDEEP | `393216:9Hhmg0DqJ+zp6zOjefzbQ47UJRPhR/E9PCUCKAOOf7:lYB9iOjEzbQ47UJRPh1waBOOj` |
| ICON-DHASH | `69f09c8c84ccf069` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_089_acb4328b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acb4328b2d6bfa66ff3d396fb80e266e684876057382ed768393c69d8174f3ed"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:29:29"
  condition:
    hash.sha256(0, filesize) == "acb4328b2d6bfa66ff3d396fb80e266e684876057382ed768393c69d8174f3ed"
}
```

### Sample 90: `9b7237bcbebe1808`

| Field | Value |
|---|---|
| SHA-256 | `9b7237bcbebe18085bc6322d165d65188150cf5219c03672971cf8d6b7b0dd30` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:25:30` |
| Reporter | `Bitsight` |
| Tags | `b89d843f29af2eed09805e9767a1165f, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad6e79c10d82822410626659d6f29a22` |
| SHA-1 | `470f455a7dfc87af9dce876dd2617abfc7eaddc7` |
| SHA-256 | `9b7237bcbebe18085bc6322d165d65188150cf5219c03672971cf8d6b7b0dd30` |
| SHA3-384 | `66b59e780734f1426de41e30ef65dfcbd60e3056229685d5a1e92f9e1de286cea83fda52e958bf7af1b1f6d722f8b71f` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T15D471229A34B51DBC366823069BC7761FD2DD964A208DD3AD79AC57D3CB0C2E28C53E1` |
| SSDEEP | `393216:fmAIRosse8VWHtbpkii1WJrh2w1meAzUNdbhJ3W5D/wv:fuMYpkieWFhr1mLYmG` |
| ICON-DHASH | `68e498ece4d8e468` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_9b7237bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b7237bcbebe18085bc6322d165d65188150cf5219c03672971cf8d6b7b0dd30"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:25:30"
  condition:
    hash.sha256(0, filesize) == "9b7237bcbebe18085bc6322d165d65188150cf5219c03672971cf8d6b7b0dd30"
}
```

### Sample 91: `c92d2ba2be0710a1`

| Field | Value |
|---|---|
| SHA-256 | `c92d2ba2be0710a1f68be422410d21a5df7ef38a407e317d270568e86f968e6e` |
| Family label | `Adware.OfferCore` |
| File name | `c92d2ba2be0710a1.bin` |
| File type | `exe` |
| First seen | `2026-10-22 03:25:08` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13dcc9a1ac392b788f0f2f0ae1c96ea7` |
| SHA-1 | `bf35c761048c57164ddf80ac6c7537346f8af2bd` |
| SHA-256 | `c92d2ba2be0710a1f68be422410d21a5df7ef38a407e317d270568e86f968e6e` |
| SHA3-384 | `60108e695bad85170e82ea055605e02b4ecea9e6ce75c37d32c04143780240844be3afd4fe45efddec8ce02d06b035e9` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1B7A5D03FB28B653EE06E5A3A79B2E110583B7A6165138C5696F4C88CCF254701E3F787` |
| SSDEEP | `24576:iXNrSLScusMmOvjjhzvL3kYVgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXc64dM:tuI2h7HcTeynRkfg7ve+AhrWzOUG` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_091_c92d2ba2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c92d2ba2be0710a1f68be422410d21a5df7ef38a407e317d270568e86f968e6e"
    family = "Adware.OfferCore"
    file_name = "c92d2ba2be0710a1.bin"
    file_type = "exe"
    first_seen = "2026-10-22 03:25:08"
  condition:
    hash.sha256(0, filesize) == "c92d2ba2be0710a1f68be422410d21a5df7ef38a407e317d270568e86f968e6e"
}
```

### Sample 92: `7115bc90e9340ed8`

| Field | Value |
|---|---|
| SHA-256 | `7115bc90e9340ed8df5a83986f93256aa947c3a507cd60d63679b5cead98afbf` |
| Family label | `RustyStealer` |
| File name | `7115bc90e9340ed8.bin` |
| File type | `exe` |
| First seen | `2026-10-22 03:24:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe1f63f48b60e228af9c2b908c86249c` |
| SHA-1 | `b89f4cd0c5ba5af47bdaf3d691aa01007f1f441d` |
| SHA-256 | `7115bc90e9340ed8df5a83986f93256aa947c3a507cd60d63679b5cead98afbf` |
| SHA3-384 | `c7bf497c1b6fd7c0af35417a8244acf10b485f2416a5046a92f9aabd5411ef7971f9b351d3074c964045139dce486c85` |
| IMPHASH | `d436939e4edad1b901cb7ffa9ab98595` |
| TLSH | `T122956C03F69580FCC55EC07887479632EA22BC8D092576EB2BD09B653E76F909F0DB19` |
| SSDEEP | `49152:lt1+Q8HJUk5j3rwsWPVO2xiNWAXIU6isA60L:lbfI7MBxUC+sO` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_092_7115bc90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7115bc90e9340ed8df5a83986f93256aa947c3a507cd60d63679b5cead98afbf"
    family = "RustyStealer"
    file_name = "7115bc90e9340ed8.bin"
    file_type = "exe"
    first_seen = "2026-10-22 03:24:59"
  condition:
    hash.sha256(0, filesize) == "7115bc90e9340ed8df5a83986f93256aa947c3a507cd60d63679b5cead98afbf"
}
```

### Sample 93: `72340d984e5018ea`

| Field | Value |
|---|---|
| SHA-256 | `72340d984e5018ea2763ab0125354ecbab45261bf3d9f241bca875b0ed2c9998` |
| Family label | `unknown` |
| File name | `72340d984e5018ea.bin` |
| File type | `msi` |
| First seen | `2026-10-22 03:24:51` |
| Reporter | `Tuxxin` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `449d6415d57aea346e9cfd765b51108f` |
| SHA-1 | `8fb5cd02d8ed88373010c1db6b53d7eb58df565d` |
| SHA-256 | `72340d984e5018ea2763ab0125354ecbab45261bf3d9f241bca875b0ed2c9998` |
| SHA3-384 | `604f1ed3ed55a247d40d3d4f2caf4cc866946673457a838d0a9d8f89127276f9586b98f24b0723e8e11b74ec9686d230` |
| TLSH | `T18435B0E83540EF5CD3B54BB205FF76DD8DE01D33963079685422B2826D3A7F92D6A80A` |
| SSDEEP | `12288:byvJCdiPB5bDg1CkTPMyAouhyV70SvqrPOG1XtbCItT65Iq5Hb21+4KI0F3iJFN1:upEBObUV1SjOG1XtbxGdbN4KYmLo+2R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_72340d98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72340d984e5018ea2763ab0125354ecbab45261bf3d9f241bca875b0ed2c9998"
    family = "unknown"
    file_name = "72340d984e5018ea.bin"
    file_type = "msi"
    first_seen = "2026-10-22 03:24:51"
  condition:
    hash.sha256(0, filesize) == "72340d984e5018ea2763ab0125354ecbab45261bf3d9f241bca875b0ed2c9998"
}
```

### Sample 94: `b36d3ad13456b95f`

| Field | Value |
|---|---|
| SHA-256 | `b36d3ad13456b95f05c4b237c5799a01884fd5121b793acbb5e1c50bb0f64405` |
| Family label | `unknown` |
| File name | `b36d3ad13456b95f.bin` |
| File type | `msi` |
| First seen | `2026-10-22 03:24:42` |
| Reporter | `Tuxxin` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `650283f1efd1071401f4588b4878947a` |
| SHA-1 | `c3e5424f460215b268d48edaeb59136af3a00238` |
| SHA-256 | `b36d3ad13456b95f05c4b237c5799a01884fd5121b793acbb5e1c50bb0f64405` |
| SHA3-384 | `3a393159c0c22c83d290b3fe5101f055d1ab0f2bc394de3c279c2963937bf1b3a31b536ce622f95516243d40cfca59b2` |
| TLSH | `T1C4C4234578CBCECBF64AAF712BFAA7014454DE881B22DB8720543AD3A73239579513E8` |
| SSDEEP | `12288:55EXvB3X16r1mirA/9RtBEJXu3e+IU+VrTdqAPSk4p9Wd6:55KHI5prABom4JLSrad` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_b36d3ad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36d3ad13456b95f05c4b237c5799a01884fd5121b793acbb5e1c50bb0f64405"
    family = "unknown"
    file_name = "b36d3ad13456b95f.bin"
    file_type = "msi"
    first_seen = "2026-10-22 03:24:42"
  condition:
    hash.sha256(0, filesize) == "b36d3ad13456b95f05c4b237c5799a01884fd5121b793acbb5e1c50bb0f64405"
}
```

### Sample 95: `b4a60551ca30298c`

| Field | Value |
|---|---|
| SHA-256 | `b4a60551ca30298c4e8f225aea012cdc34aaaaf640d9c7ee0818860c74ffab19` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:23:46` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afaf3d534dfdb96401493ff3a8b27f26` |
| SHA-1 | `7afc0158fe33c770fbee71818b703f775a6aa3e2` |
| SHA-256 | `b4a60551ca30298c4e8f225aea012cdc34aaaaf640d9c7ee0818860c74ffab19` |
| SHA3-384 | `4fad0d4f9e89a732ef87894bfe696410483f59d713b0b241ed2183fa8635b22e56419e0fc3710d01779556da54dc123c` |
| IMPHASH | `f8721d3342bb63625ebe4887f9ee94bc` |
| TLSH | `T1BE57AF51B30B55F6FA434C3685F9AB7F7B35EE9CC874C557E428382AB9B2C1A458C280` |
| SSDEEP | `393216:p61bIHOGJ6hxM35+yM1GIe5sg2aheUGHLW:p6RIuGJKMpYsV5sg2ahvCW` |
| ICON-DHASH | `7071793268dcdcd4` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_095_b4a60551
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4a60551ca30298c4e8f225aea012cdc34aaaaf640d9c7ee0818860c74ffab19"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:23:46"
  condition:
    hash.sha256(0, filesize) == "b4a60551ca30298c4e8f225aea012cdc34aaaaf640d9c7ee0818860c74ffab19"
}
```

### Sample 96: `41ad249f4d3f2ee1`

| Field | Value |
|---|---|
| SHA-256 | `41ad249f4d3f2ee1e13fa60544d5ead4eb12de75404de60c2ff43f6e1fd8425b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:18:15` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13f7116c89a6f6031778d8cbf193b93b` |
| SHA-1 | `8d76b7939bff058c7822f498a5a570837e91d859` |
| SHA-256 | `41ad249f4d3f2ee1e13fa60544d5ead4eb12de75404de60c2ff43f6e1fd8425b` |
| SHA3-384 | `1a0d330eed5eb5e25720fc810c63cf54779daad383f78dc7eb7feda42e4d3fd9190a1231ddc8c477c23079866f3ab86a` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1D0471229A38B52DFC36A8270557C7761FD2EC964A504CD3AC799C1BD3DB1C2E28C52E2` |
| SSDEEP | `393216:GkwpSfU/jL1dfuJewzG1AsRuv2bU85iUpgDn6ZS/TXL42Cu1p:sSfotU41AsIvIUEiUg6buP` |
| ICON-DHASH | `68c8d0f0e0ecec70` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_41ad249f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41ad249f4d3f2ee1e13fa60544d5ead4eb12de75404de60c2ff43f6e1fd8425b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:18:15"
  condition:
    hash.sha256(0, filesize) == "41ad249f4d3f2ee1e13fa60544d5ead4eb12de75404de60c2ff43f6e1fd8425b"
}
```

### Sample 97: `b9c25bd6b70a019d`

| Field | Value |
|---|---|
| SHA-256 | `b9c25bd6b70a019d08aadff9e6bb677c11ea5c9ae8ecb2f49a1d8a6da216fc98` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:17:42` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `221f272bfc2987e61dc013b83cffbfc5` |
| SHA-1 | `a59b28f3aafa372af3c8db70ea70bf1482bb265c` |
| SHA-256 | `b9c25bd6b70a019d08aadff9e6bb677c11ea5c9ae8ecb2f49a1d8a6da216fc98` |
| SHA3-384 | `9ca96d06adcbfdf520aab9ecdf5ca2b113d0bf01af2b1519dac99531fab9e5b45cc042e8bacbd715cf0bb5fc79827925` |
| IMPHASH | `b2f76a377810c3911d9a29c066358593` |
| TLSH | `T1B526231D779711EFC3AB823404A86B61FA694D5461948B39C2ACE1FD3EB1D1F18D87E0` |
| SSDEEP | `49152:DJH5pFSloHk6qb8J+lDH79O0qTk1CGUCvmHN0U8ta:DJb/3qA+VH79Or9GUCOHev4` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_b9c25bd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c25bd6b70a019d08aadff9e6bb677c11ea5c9ae8ecb2f49a1d8a6da216fc98"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:17:42"
  condition:
    hash.sha256(0, filesize) == "b9c25bd6b70a019d08aadff9e6bb677c11ea5c9ae8ecb2f49a1d8a6da216fc98"
}
```

### Sample 98: `45fde449a55e964d`

| Field | Value |
|---|---|
| SHA-256 | `45fde449a55e964d31b7be280e6b2a3df03bf29e09c2c2a3c3293db49e6a4f5e` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:14:44` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e756878d2cf546fc171b519cff0d67c` |
| SHA-1 | `7e9065e4042264c6d3c1cb07243ba27c817e1a54` |
| SHA-256 | `45fde449a55e964d31b7be280e6b2a3df03bf29e09c2c2a3c3293db49e6a4f5e` |
| SHA3-384 | `faec73360b12a3656ef661b9b2bcbd915f7be8585e0330624aa8ccb563b9cfb4cb63bbbf9f6d4388535345095927919a` |
| IMPHASH | `b09f6a241ce9357f12a61533e6d99a82` |
| TLSH | `T10B579E51B30B85F6FA434836C5F96BBF7A39DE9CC874C557E4243C2ABA72C1A458C281` |
| SSDEEP | `393216:rhJV5BVfq4YXLQLlwgtwGK6MCwjsAdBGzV7VYVy:HV5nfZblwgR29GRVd` |
| ICON-DHASH | `c0a4a2b2b2b2a280` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_098_45fde449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45fde449a55e964d31b7be280e6b2a3df03bf29e09c2c2a3c3293db49e6a4f5e"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:14:44"
  condition:
    hash.sha256(0, filesize) == "45fde449a55e964d31b7be280e6b2a3df03bf29e09c2c2a3c3293db49e6a4f5e"
}
```

### Sample 99: `937b0ccd38d543b7`

| Field | Value |
|---|---|
| SHA-256 | `937b0ccd38d543b7fcb265901443601506623452067b4c0df3ec75117c06f02b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:09:21` |
| Reporter | `Bitsight` |
| Tags | `55001da20373e92a4261b69e9f1087ac, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb1f59d4c92c85d725c34700ce131ec4` |
| SHA-1 | `6c788889c4502f15d0e701d678a283fc45c82b61` |
| SHA-256 | `937b0ccd38d543b7fcb265901443601506623452067b4c0df3ec75117c06f02b` |
| SHA3-384 | `e59cb2208bf78710702033cfe17828e334461031e3cd4f8a5228d17201902ac90ed53406777c98e9a141684fd41afdac` |
| IMPHASH | `4fe6c4e15a8fb4ff217154e90e8a41ed` |
| TLSH | `T1434702186347C2DBC36A8270D568A6F1FD2D9D64E108893BD399BD7D3CB1C2E58C62E1` |
| SSDEEP | `393216:UcPgzb+XLUyafqGtkVpgBzOLWxAnypxNnfsvrWNYFrJm1IE:ybDoVpgtOixCypPEmIE` |
| ICON-DHASH | `e4e4a4a0b0b4b0b9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_937b0ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937b0ccd38d543b7fcb265901443601506623452067b4c0df3ec75117c06f02b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:09:21"
  condition:
    hash.sha256(0, filesize) == "937b0ccd38d543b7fcb265901443601506623452067b4c0df3ec75117c06f02b"
}
```

### Sample 100: `e8d4d78f4dfc72d3`

| Field | Value |
|---|---|
| SHA-256 | `e8d4d78f4dfc72d389e7101cdcba866b7ac90094c3356de17b22ecb097c53f9c` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-22 03:05:57` |
| Reporter | `Bitsight` |
| Tags | `c1399bfb1be0a51415613edd6f0068c5, CoinMiner, dropped-by-Vidar, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ed04d94857e43eaff040ff4a0562061` |
| SHA-1 | `66e61309d2aa427bea49ce7b5b7d2b68eefd1b82` |
| SHA-256 | `e8d4d78f4dfc72d389e7101cdcba866b7ac90094c3356de17b22ecb097c53f9c` |
| SHA3-384 | `ba40580499f826550de18dc081e0fd7e48c73282c9d239c6a653814e7d799dc016800b8e5d0eb5e827ff8b2cb0493102` |
| IMPHASH | `cfa70d2129a3a23d9dbcca3193b8ee4e` |
| TLSH | `T11857AF50B30B45F6FA474C3685F9AB7F7B35EA9CC974C557E428382ABA72C1B458C280` |
| SSDEEP | `393216:ea5d543sPKfr5WsHCU1cS0xx7xXMLVcC5ZzEvoXPD5R:eEe4u1WO1jY7pxCDwvorT` |
| ICON-DHASH | `c0a29a8686829249` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_100_e8d4d78f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8d4d78f4dfc72d389e7101cdcba866b7ac90094c3356de17b22ecb097c53f9c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:05:57"
  condition:
    hash.sha256(0, filesize) == "e8d4d78f4dfc72d389e7101cdcba866b7ac90094c3356de17b22ecb097c53f9c"
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
 * Generated: 2026-10-22T05:00:58.861943+00:00
 */

rule MalwareBazaar_unknown_001_3abb5c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3abb5c118d4c965918f8b7c44240800e91f9b9ace127f31c9eb423d26b2e83e6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:57:47"
  condition:
    hash.sha256(0, filesize) == "3abb5c118d4c965918f8b7c44240800e91f9b9ace127f31c9eb423d26b2e83e6"
}

rule MalwareBazaar_unknown_002_518e6f31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "518e6f31fb564e5542f81afd0117e22db06e37e41094a675666748b5684908a2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:57:42"
  condition:
    hash.sha256(0, filesize) == "518e6f31fb564e5542f81afd0117e22db06e37e41094a675666748b5684908a2"
}

rule MalwareBazaar_unknown_003_657ae1b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "657ae1b645a957f7eedc135c1313705287299ddcee2a48ada12cd4a1890b0472"
    family = "unknown"
    file_name = "Zjckk0.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:57:26"
  condition:
    hash.sha256(0, filesize) == "657ae1b645a957f7eedc135c1313705287299ddcee2a48ada12cd4a1890b0472"
}

rule MalwareBazaar_unknown_004_6693ae92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6693ae9274c9c218b9d5ff34714d848c53d5ce86af3b7e45b11092c14af8eeaa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:52:09"
  condition:
    hash.sha256(0, filesize) == "6693ae9274c9c218b9d5ff34714d848c53d5ce86af3b7e45b11092c14af8eeaa"
}

rule MalwareBazaar_unknown_005_43794938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43794938628413beb07fc0d0d7033bf610c0b2536374d65b9c9156fd4e04a619"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:47:16"
  condition:
    hash.sha256(0, filesize) == "43794938628413beb07fc0d0d7033bf610c0b2536374d65b9c9156fd4e04a619"
}

rule MalwareBazaar_unknown_006_2c96e15a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c96e15a4937a52c49d72f652f7b29eccbebe381c824ffe4599427e9c43145ff"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:47:15"
  condition:
    hash.sha256(0, filesize) == "2c96e15a4937a52c49d72f652f7b29eccbebe381c824ffe4599427e9c43145ff"
}

rule MalwareBazaar_unknown_007_7680367b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7680367b549ceceac66de8e7204c0efa42aeb12044736ae131cc022c08ea901b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:43:46"
  condition:
    hash.sha256(0, filesize) == "7680367b549ceceac66de8e7204c0efa42aeb12044736ae131cc022c08ea901b"
}

rule MalwareBazaar_unknown_008_7255e451
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7255e4518c564e44c5969159e4837b32d7663d61a14e7c7eea41e300281ecd8c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:38:58"
  condition:
    hash.sha256(0, filesize) == "7255e4518c564e44c5969159e4837b32d7663d61a14e7c7eea41e300281ecd8c"
}

rule MalwareBazaar_unknown_009_a118143f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a118143f763076e136fc76d724fa038eef2be77485441132f661b35e60e793c7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:36:42"
  condition:
    hash.sha256(0, filesize) == "a118143f763076e136fc76d724fa038eef2be77485441132f661b35e60e793c7"
}

rule MalwareBazaar_unknown_010_0429da87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8"
    family = "unknown"
    file_name = "0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8.exe"
    file_type = "dll"
    first_seen = "2026-10-22 04:34:28"
  condition:
    hash.sha256(0, filesize) == "0429da8788c6e83d2774ea3feb60951ecc097d4a8c697efe617920ee47ab99d8"
}

rule MalwareBazaar_unknown_011_5385aa4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5385aa4f7cab53dced79c1d73cbcc7b5e209705293781731b4aa94faf560378d"
    family = "unknown"
    file_name = "teach.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:33:40"
  condition:
    hash.sha256(0, filesize) == "5385aa4f7cab53dced79c1d73cbcc7b5e209705293781731b4aa94faf560378d"
}

rule MalwareBazaar_unknown_012_4adb8b4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4adb8b4f38f0199a238831a9c8892bae329b8737e5c00d26eaf072b8b4e43106"
    family = "unknown"
    file_name = "DAS_London_2026_Programme.zip"
    file_type = "zip"
    first_seen = "2026-10-22 04:33:06"
  condition:
    hash.sha256(0, filesize) == "4adb8b4f38f0199a238831a9c8892bae329b8737e5c00d26eaf072b8b4e43106"
}

rule MalwareBazaar_unknown_013_57f4a423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57f4a4237a2b796dc8a4b49df6dd2d769ac170124544d5c5e3508b741e912d64"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:31:54"
  condition:
    hash.sha256(0, filesize) == "57f4a4237a2b796dc8a4b49df6dd2d769ac170124544d5c5e3508b741e912d64"
}

rule MalwareBazaar_unknown_014_9b8b0993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b8b09939d0f2ee47d6211c24f6a217b0bb75a0693c3d8771aa7384199f462bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:31:35"
  condition:
    hash.sha256(0, filesize) == "9b8b09939d0f2ee47d6211c24f6a217b0bb75a0693c3d8771aa7384199f462bf"
}

rule MalwareBazaar_unknown_015_ae3ffc42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae3ffc422756fc80ae1a999f2dff86e8624b0fef48b8ca5241a8fd75aabb7139"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:29:38"
  condition:
    hash.sha256(0, filesize) == "ae3ffc422756fc80ae1a999f2dff86e8624b0fef48b8ca5241a8fd75aabb7139"
}

rule MalwareBazaar_unknown_016_fa9fe2e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa9fe2e09ef917f1dde379d35f0c235f7b0b7c45aa4483d47e9f4b27ac8b61a8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:28:27"
  condition:
    hash.sha256(0, filesize) == "fa9fe2e09ef917f1dde379d35f0c235f7b0b7c45aa4483d47e9f4b27ac8b61a8"
}

rule MalwareBazaar_unknown_017_09a07d2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09a07d2b5b6807b3b84f5921b7686dd9bbb398156aff145d42d7e0f6b16552b5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:25:50"
  condition:
    hash.sha256(0, filesize) == "09a07d2b5b6807b3b84f5921b7686dd9bbb398156aff145d42d7e0f6b16552b5"
}

rule MalwareBazaar_unknown_018_f4d5edf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d5edf20c2bd45c2851f128c3ba36e1f72b6db0256ab58695b7c74155740592"
    family = "unknown"
    file_name = "bot.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:24:36"
  condition:
    hash.sha256(0, filesize) == "f4d5edf20c2bd45c2851f128c3ba36e1f72b6db0256ab58695b7c74155740592"
}

rule MalwareBazaar_CoinMiner_019_d803331d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d803331dab484a405d5aa81e7c7df7b56e0f6ef7e0c91e6a38a82a437453574c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:19:48"
  condition:
    hash.sha256(0, filesize) == "d803331dab484a405d5aa81e7c7df7b56e0f6ef7e0c91e6a38a82a437453574c"
}

rule MalwareBazaar_RevStealer_020_0e3392e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3392e6bf176620e49f37376257f090fba94f8d5b8bf841113e494a0f0e56ab"
    family = "RevStealer"
    file_name = "gM9anpOuZNKX8zHj.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:19:43"
  condition:
    hash.sha256(0, filesize) == "0e3392e6bf176620e49f37376257f090fba94f8d5b8bf841113e494a0f0e56ab"
}

rule MalwareBazaar_unknown_021_7e2e6894
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e2e689411d97d6c43cad212d3eb11c7dc06062e3137ccd5d6ad156396872e9c"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:17:29"
  condition:
    hash.sha256(0, filesize) == "7e2e689411d97d6c43cad212d3eb11c7dc06062e3137ccd5d6ad156396872e9c"
}

rule MalwareBazaar_unknown_022_9a657127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a657127746347ffa09592d0c03400ed7ee24c4cbc89bc447a4900b96cdff184"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:16:33"
  condition:
    hash.sha256(0, filesize) == "9a657127746347ffa09592d0c03400ed7ee24c4cbc89bc447a4900b96cdff184"
}

rule MalwareBazaar_unknown_023_72f1a915
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72f1a91566f9a644b5795e23caa003780a4869fa903607fbe705382c19c545af"
    family = "unknown"
    file_name = "Acrobat_Set-Up_7474.vbs"
    file_type = "vbs"
    first_seen = "2026-10-22 04:16:14"
  condition:
    hash.sha256(0, filesize) == "72f1a91566f9a644b5795e23caa003780a4869fa903607fbe705382c19c545af"
}

rule MalwareBazaar_unknown_024_0d1fe082
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d1fe0823d6f3a163723cd35bc20b47e8d21d7bffecf1673a42d6065dd4a00da"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:16:14"
  condition:
    hash.sha256(0, filesize) == "0d1fe0823d6f3a163723cd35bc20b47e8d21d7bffecf1673a42d6065dd4a00da"
}

rule MalwareBazaar_SnakeKeylogger_025_0a0dfd88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a0dfd88a061dc8ad13f65954c0c961120bade8ad92f946d10c4bc0bc9c1cf80"
    family = "SnakeKeylogger"
    file_name = "Fiyat Teklifi Talebi_22102026.vbs"
    file_type = "vbs"
    first_seen = "2026-10-22 04:16:11"
  condition:
    hash.sha256(0, filesize) == "0a0dfd88a061dc8ad13f65954c0c961120bade8ad92f946d10c4bc0bc9c1cf80"
}

rule MalwareBazaar_RemcosRAT_026_2adf323e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2adf323e3f0472d671cc8dfa35fe49f06783d6e74b0ce4bd2cd208a710cb0db3"
    family = "RemcosRAT"
    file_name = "Requisition.vbs"
    file_type = "vbs"
    first_seen = "2026-10-22 04:16:05"
  condition:
    hash.sha256(0, filesize) == "2adf323e3f0472d671cc8dfa35fe49f06783d6e74b0ce4bd2cd208a710cb0db3"
}

rule MalwareBazaar_AgentTesla_027_9c7fdfa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7fdfa3ee3373c67b9861d3074a0c318aeceba4741f4527aff634f17faddb67"
    family = "AgentTesla"
    file_name = "NEW ORDER.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:56"
  condition:
    hash.sha256(0, filesize) == "9c7fdfa3ee3373c67b9861d3074a0c318aeceba4741f4527aff634f17faddb67"
}

rule MalwareBazaar_unknown_028_17530a34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17530a344b6f52afe7e163f2762172ed18a16185535c8668ac9d6b3b46ff3e69"
    family = "unknown"
    file_name = "Recibo de pago del Banco Banorte.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:46"
  condition:
    hash.sha256(0, filesize) == "17530a344b6f52afe7e163f2762172ed18a16185535c8668ac9d6b3b46ff3e69"
}

rule MalwareBazaar_XWorm_029_1941eee5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1941eee5464cb563a892fc2a7161abf8c7803b9d75f4d76a0a175c35c5732534"
    family = "XWorm"
    file_name = "Cataloge..js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:43"
  condition:
    hash.sha256(0, filesize) == "1941eee5464cb563a892fc2a7161abf8c7803b9d75f4d76a0a175c35c5732534"
}

rule MalwareBazaar_XWorm_030_cdaf1b6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdaf1b6cac86e2ab5f06b3a02faa9f909c26e251836c90faf5e61aca491be6b1"
    family = "XWorm"
    file_name = "PO-NO-103A-103A-B11200-722-GCIT-2288.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:15:40"
  condition:
    hash.sha256(0, filesize) == "cdaf1b6cac86e2ab5f06b3a02faa9f909c26e251836c90faf5e61aca491be6b1"
}

rule MalwareBazaar_AgentTesla_031_7b37b779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b37b779c34cf1567c822c24ee7e6ab0d84ce2a513e5eac5bdaa63a46b929e58"
    family = "AgentTesla"
    file_name = "SHIPMENT DETAILS AND DOCUMENTS.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:15:37"
  condition:
    hash.sha256(0, filesize) == "7b37b779c34cf1567c822c24ee7e6ab0d84ce2a513e5eac5bdaa63a46b929e58"
}

rule MalwareBazaar_unknown_032_13866f89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13866f897489f08554617dce9143fcc8e8b6b1cc76e6d3732da018a30dcdde64"
    family = "unknown"
    file_name = "13866f897489f085.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:26"
  condition:
    hash.sha256(0, filesize) == "13866f897489f08554617dce9143fcc8e8b6b1cc76e6d3732da018a30dcdde64"
}

rule MalwareBazaar_RemcosRAT_033_497befff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "497befff3913668d098d346093f5b3647dcfb6b9924783b25b01d7bc038779bc"
    family = "RemcosRAT"
    file_name = "Swift_Transaction7398.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:15:19"
  condition:
    hash.sha256(0, filesize) == "497befff3913668d098d346093f5b3647dcfb6b9924783b25b01d7bc038779bc"
}

rule MalwareBazaar_unknown_034_0c5486f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
    family = "unknown"
    file_name = "nfs"
    file_type = "elf"
    first_seen = "2026-10-22 04:15:15"
  condition:
    hash.sha256(0, filesize) == "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
}

rule MalwareBazaar_AgentTesla_035_72b104e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b104e2e5039619b46264f6010929703c0e18fb435fd1b1e68afeb936d301a7"
    family = "AgentTesla"
    file_name = "Quotation.js"
    file_type = "js"
    first_seen = "2026-10-22 04:15:01"
  condition:
    hash.sha256(0, filesize) == "72b104e2e5039619b46264f6010929703c0e18fb435fd1b1e68afeb936d301a7"
}

rule MalwareBazaar_Formbook_036_6401841e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6401841ee99220dcdee1ab02914226afca075c15e82bead40746eff81325e9cf"
    family = "Formbook"
    file_name = "RFQ_Order_Request_EXW_pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:58"
  condition:
    hash.sha256(0, filesize) == "6401841ee99220dcdee1ab02914226afca075c15e82bead40746eff81325e9cf"
}

rule MalwareBazaar_XWorm_037_2bff9eeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bff9eeb072e4d37e129e9d37eb7c866051be1ace3d8702fc7ddac0953ea8dcd"
    family = "XWorm"
    file_name = "MT 103 USD 65660.01.js"
    file_type = "js"
    first_seen = "2026-10-22 04:14:55"
  condition:
    hash.sha256(0, filesize) == "2bff9eeb072e4d37e129e9d37eb7c866051be1ace3d8702fc7ddac0953ea8dcd"
}

rule MalwareBazaar_unknown_038_8e2dd551
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e2dd5512aff7942a8c3a08d5227d387f8b0244b1c429d09608ace21cc6317b1"
    family = "unknown"
    file_name = "RFQ-GN0948.js"
    file_type = "js"
    first_seen = "2026-10-22 04:14:52"
  condition:
    hash.sha256(0, filesize) == "8e2dd5512aff7942a8c3a08d5227d387f8b0244b1c429d09608ace21cc6317b1"
}

rule MalwareBazaar_AgentTesla_039_a340ead3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a340ead3b283edfc401a385156d231675a67e092fb3c77cd2fcaae3a0376027f"
    family = "AgentTesla"
    file_name = "RFQ LIST.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:49"
  condition:
    hash.sha256(0, filesize) == "a340ead3b283edfc401a385156d231675a67e092fb3c77cd2fcaae3a0376027f"
}

rule MalwareBazaar_AgentTesla_040_937bbe04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937bbe04d64445ebbff80cd851f739c45e6516dd172bcc0d5af8b94ef2fc528f"
    family = "AgentTesla"
    file_name = "SOA ITS-AH 2026 (09.26).JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:46"
  condition:
    hash.sha256(0, filesize) == "937bbe04d64445ebbff80cd851f739c45e6516dd172bcc0d5af8b94ef2fc528f"
}

rule MalwareBazaar_MassLogger_041_846f554b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "846f554b4be26787b8a4ed2642526de9c04631e66180b00e5cac5601a8731afc"
    family = "MassLogger"
    file_name = "Purchase Order 0138801.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:41"
  condition:
    hash.sha256(0, filesize) == "846f554b4be26787b8a4ed2642526de9c04631e66180b00e5cac5601a8731afc"
}

rule MalwareBazaar_RemcosRAT_042_f0c9b051
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0c9b0514bce405b21604b9fae6e2b3e59ac36c41cc73e629929a35eec3c9e95"
    family = "RemcosRAT"
    file_name = "rsonbkgd.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:36"
  condition:
    hash.sha256(0, filesize) == "f0c9b0514bce405b21604b9fae6e2b3e59ac36c41cc73e629929a35eec3c9e95"
}

rule MalwareBazaar_unknown_043_d1b93e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b93e9e32e7eb7b56549b8cf464251ef7c1581fdf6b90ac5c6a4381b3e77aa4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:14:16"
  condition:
    hash.sha256(0, filesize) == "d1b93e9e32e7eb7b56549b8cf464251ef7c1581fdf6b90ac5c6a4381b3e77aa4"
}

rule MalwareBazaar_RemcosRAT_044_fdbc0938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdbc09388712bcd18702fbb30fbbdc338ee89c80a8971bbedacd7e427f327932"
    family = "RemcosRAT"
    file_name = "myqvcivp.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:10"
  condition:
    hash.sha256(0, filesize) == "fdbc09388712bcd18702fbb30fbbdc338ee89c80a8971bbedacd7e427f327932"
}

rule MalwareBazaar_Formbook_045_d92b9d30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d92b9d306bf693953239f78062281d6cf0c252753a0b86d231c8e5520a5f308e"
    family = "Formbook"
    file_name = "New_Purchase_Order_[PO_02081].JS"
    file_type = "js"
    first_seen = "2026-10-22 04:14:03"
  condition:
    hash.sha256(0, filesize) == "d92b9d306bf693953239f78062281d6cf0c252753a0b86d231c8e5520a5f308e"
}

rule MalwareBazaar_XWorm_046_70e4d14b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e4d14bc5c0a61d0f274c621bce68c878a9588d1caf76912260c825c4c99830"
    family = "XWorm"
    file_name = "payment swift الدفعة 567 .pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:59"
  condition:
    hash.sha256(0, filesize) == "70e4d14bc5c0a61d0f274c621bce68c878a9588d1caf76912260c825c4c99830"
}

rule MalwareBazaar_XWorm_047_ef451da3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef451da37f7487345e5330a0905ffcb3509f7522a5bb7bbb89be1f05c19980f9"
    family = "XWorm"
    file_name = "doc20261022_90000110011po.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:56"
  condition:
    hash.sha256(0, filesize) == "ef451da37f7487345e5330a0905ffcb3509f7522a5bb7bbb89be1f05c19980f9"
}

rule MalwareBazaar_DonutLoader_048_4e015061
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e01506195fae2b2bd8e8b04ff51985abd42bd06fcfcfaf9bea9f9184d1f5388"
    family = "DonutLoader"
    file_name = "NEW_PO_NOVA_TRADE.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:51"
  condition:
    hash.sha256(0, filesize) == "4e01506195fae2b2bd8e8b04ff51985abd42bd06fcfcfaf9bea9f9184d1f5388"
}

rule MalwareBazaar_unknown_049_5416e3b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5416e3b192f69d02b51747067e80b8395c7c30a5ddd0cfe23aa38bf893b233a6"
    family = "unknown"
    file_name = "TelnetTime.sh"
    file_type = "sh"
    first_seen = "2026-10-22 04:13:46"
  condition:
    hash.sha256(0, filesize) == "5416e3b192f69d02b51747067e80b8395c7c30a5ddd0cfe23aa38bf893b233a6"
}

rule MalwareBazaar_AveMariaRAT_050_b15b1e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b15b1e9a2608f1211ace68af1bf79716398f865d09c3160100b3a13e2d0e9c19"
    family = "AveMariaRAT"
    file_name = "TELEX HBL DOCUMENTS 03.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:42"
  condition:
    hash.sha256(0, filesize) == "b15b1e9a2608f1211ace68af1bf79716398f865d09c3160100b3a13e2d0e9c19"
}

rule MalwareBazaar_Formbook_051_bbe3b792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbe3b7927fca9e766d0f150a58c064a92b334f9363d7f565fefcd4726a71ed77"
    family = "Formbook"
    file_name = "SOA - 31-AUGUST-31-OCTOBER-2026.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:36"
  condition:
    hash.sha256(0, filesize) == "bbe3b7927fca9e766d0f150a58c064a92b334f9363d7f565fefcd4726a71ed77"
}

rule MalwareBazaar_DonutLoader_052_9fb0a1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb0a1a7ebacb4f6a65a995f5bb30020dc25f2fd5589a2303970bb805a1b242a"
    family = "DonutLoader"
    file_name = "Payment_Receipt_Ref-548921.pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:33"
  condition:
    hash.sha256(0, filesize) == "9fb0a1a7ebacb4f6a65a995f5bb30020dc25f2fd5589a2303970bb805a1b242a"
}

rule MalwareBazaar_AgentTesla_053_b6f5979a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6f5979acd8233a7ed33a88a077338a7d098882909c97a8708cf23be21fea05b"
    family = "AgentTesla"
    file_name = "Accommodation and rooming list.xlsx.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:30"
  condition:
    hash.sha256(0, filesize) == "b6f5979acd8233a7ed33a88a077338a7d098882909c97a8708cf23be21fea05b"
}

rule MalwareBazaar_XWorm_054_3fc8ec0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc8ec0cdef68b926d72bf638fe3baf6e87791117babd112937402c2d5032aad"
    family = "XWorm"
    file_name = "payment swift الدفعة 567 .pdf.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:26"
  condition:
    hash.sha256(0, filesize) == "3fc8ec0cdef68b926d72bf638fe3baf6e87791117babd112937402c2d5032aad"
}

rule MalwareBazaar_AgentTesla_055_ccc5d56d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccc5d56d5d8214fba97012bab7026b4eb6fbb32c08bf9d1b32f5a2978644a674"
    family = "AgentTesla"
    file_name = "Courier Tracking Details.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:23"
  condition:
    hash.sha256(0, filesize) == "ccc5d56d5d8214fba97012bab7026b4eb6fbb32c08bf9d1b32f5a2978644a674"
}

rule MalwareBazaar_unknown_056_687248c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "687248c21164a212ef2860d3f496e4e00f6147e26fed9bfba014ebf6f9b6798e"
    family = "unknown"
    file_name = "Order-Inv-oct7483549.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:13"
  condition:
    hash.sha256(0, filesize) == "687248c21164a212ef2860d3f496e4e00f6147e26fed9bfba014ebf6f9b6798e"
}

rule MalwareBazaar_unknown_057_6478d9c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6478d9c9dbfbbc282bbc35738fb0f501c91e8b419dc322f8b5c6ad37f09d7a5c"
    family = "unknown"
    file_name = "MV SEA LADY QUOTATION FORM.js"
    file_type = "js"
    first_seen = "2026-10-22 04:13:08"
  condition:
    hash.sha256(0, filesize) == "6478d9c9dbfbbc282bbc35738fb0f501c91e8b419dc322f8b5c6ad37f09d7a5c"
}

rule MalwareBazaar_AgentTesla_058_89a674d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89a674d148c2de101dce51a236184bcdc5f4dd50ff86e46c21fcdfc5ca767776"
    family = "AgentTesla"
    file_name = "wpxcobcb.JS"
    file_type = "js"
    first_seen = "2026-10-22 04:13:05"
  condition:
    hash.sha256(0, filesize) == "89a674d148c2de101dce51a236184bcdc5f4dd50ff86e46c21fcdfc5ca767776"
}

rule MalwareBazaar_XWorm_059_0387b0b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0387b0b7fa441b29d87d7dd9eb053c9d8db14e78bbaae226c32c4c6abcca0599"
    family = "XWorm"
    file_name = "Halkbank_Ekstre_620_01100333.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:12:30"
  condition:
    hash.sha256(0, filesize) == "0387b0b7fa441b29d87d7dd9eb053c9d8db14e78bbaae226c32c4c6abcca0599"
}

rule MalwareBazaar_Mirai_060_d4bed78f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b"
    family = "Mirai"
    file_name = "d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b.elf"
    file_type = "elf"
    first_seen = "2026-10-22 04:12:14"
  condition:
    hash.sha256(0, filesize) == "d4bed78fc6b7d399c92f4483861f8194c96e80e5b5fe3823eb95524a99f34e2b"
}

rule MalwareBazaar_unknown_061_48f9598e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f9598e8729ab0d24ea4159e910b59f39029acabcc84351b408e9ea342dd747"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:08:59"
  condition:
    hash.sha256(0, filesize) == "48f9598e8729ab0d24ea4159e910b59f39029acabcc84351b408e9ea342dd747"
}

rule MalwareBazaar_RustyStealer_062_2548b7c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502"
    family = "RustyStealer"
    file_name = "WindowsDefender.msi"
    file_type = "exe"
    first_seen = "2026-10-22 04:04:43"
  condition:
    hash.sha256(0, filesize) == "2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502"
}

rule MalwareBazaar_CoinMiner_063_be8dbcf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be8dbcf25f2b83fb1ee2af5683d6fc867656b37d19119a447a228a3ace5fb612"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:04:23"
  condition:
    hash.sha256(0, filesize) == "be8dbcf25f2b83fb1ee2af5683d6fc867656b37d19119a447a228a3ace5fb612"
}

rule MalwareBazaar_QuasarRAT_064_eda7de58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda7de5855def39b672cb603c522054b827cdb5597c5b3c84e9a65b60d91deac"
    family = "QuasarRAT"
    file_name = "30beedc7b8d9c91c8575191eb064226f.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:03:18"
  condition:
    hash.sha256(0, filesize) == "eda7de5855def39b672cb603c522054b827cdb5597c5b3c84e9a65b60d91deac"
}

rule MalwareBazaar_unknown_065_65e1ec6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65e1ec6eb44e5208f160eb7875f73c8f53392c4994970e6b9f48e3ab2e0d21ab"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:01:34"
  condition:
    hash.sha256(0, filesize) == "65e1ec6eb44e5208f160eb7875f73c8f53392c4994970e6b9f48e3ab2e0d21ab"
}

rule MalwareBazaar_unknown_066_5cdf2668
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cdf2668ee2910407f2acd69fcdc565817e2f748c372f4ea187d1077719c8ea6"
    family = "unknown"
    file_name = "fuck_niggers_44.hta"
    file_type = "hta"
    first_seen = "2026-10-22 04:01:26"
  condition:
    hash.sha256(0, filesize) == "5cdf2668ee2910407f2acd69fcdc565817e2f748c372f4ea187d1077719c8ea6"
}

rule MalwareBazaar_unknown_067_223c99c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "223c99c66b750084ad673dca01480fd01e644807bcb7bacdbc1ecde85600bd99"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 04:01:20"
  condition:
    hash.sha256(0, filesize) == "223c99c66b750084ad673dca01480fd01e644807bcb7bacdbc1ecde85600bd99"
}

rule MalwareBazaar_unknown_068_58dffd26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582"
    family = "unknown"
    file_name = "vlc-3.0.23-win64_crypted.exe"
    file_type = "exe"
    first_seen = "2026-10-22 04:00:44"
  condition:
    hash.sha256(0, filesize) == "58dffd262bb9b3c815f1017735cfa214fbbb029af8bd4cbba42c3d8db218e582"
}

rule MalwareBazaar_unknown_069_e431ed40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e431ed40fb621acba0e0d27fde4abe0d8ffca2968ca96561ed194334593e3976"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:59:41"
  condition:
    hash.sha256(0, filesize) == "e431ed40fb621acba0e0d27fde4abe0d8ffca2968ca96561ed194334593e3976"
}

rule MalwareBazaar_CoinMiner_070_623e15eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "623e15ebdeed96fce459f07444cfbbb0fa3def8486b045c0b4e70befbe640c91"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:56:55"
  condition:
    hash.sha256(0, filesize) == "623e15ebdeed96fce459f07444cfbbb0fa3def8486b045c0b4e70befbe640c91"
}

rule MalwareBazaar_unknown_071_a76e63b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a76e63b7dbf2aa5d1b04f46c23ac5869bcc6544c38c99de6ca72a0595743102e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:54:16"
  condition:
    hash.sha256(0, filesize) == "a76e63b7dbf2aa5d1b04f46c23ac5869bcc6544c38c99de6ca72a0595743102e"
}

rule MalwareBazaar_unknown_072_30e727c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e727c0414d4b8d1f7b40a63a1371fcee246ac8c9eb32c3840e25bf63cf3497"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:50:35"
  condition:
    hash.sha256(0, filesize) == "30e727c0414d4b8d1f7b40a63a1371fcee246ac8c9eb32c3840e25bf63cf3497"
}

rule MalwareBazaar_unknown_073_95b32434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:48:14"
  condition:
    hash.sha256(0, filesize) == "95b32434fe39c8bd412102ba0da1a6275134c3ebb5285062c60e8559019a4cfb"
}

rule MalwareBazaar_unknown_074_0507e4c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:47:56"
  condition:
    hash.sha256(0, filesize) == "0507e4c85849697cb6badf890b3a07f064a32bae6ead797b0a88f2a56bac6a6c"
}

rule MalwareBazaar_CoinMiner_075_41e1ca85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:47:46"
  condition:
    hash.sha256(0, filesize) == "41e1ca8515fb9aad7333480c48b83ea0ac4bf070d7aa6b44995cf55106596d8d"
}

rule MalwareBazaar_unknown_076_1fffae3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b"
    family = "unknown"
    file_name = "SecuriteInfo.com.PUA.Tool.VulnDriver.26.17.17960"
    file_type = "exe"
    first_seen = "2026-10-22 03:47:19"
  condition:
    hash.sha256(0, filesize) == "1fffae3cb845be03b0a44489f86a568fa13671b9b1c7a4aeb8b6aedf09576a8b"
}

rule MalwareBazaar_Prometei_077_706cc7d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1"
    family = "Prometei"
    file_name = "706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1"
    file_type = "elf"
    first_seen = "2026-10-22 03:44:37"
  condition:
    hash.sha256(0, filesize) == "706cc7d2b5dccf4b842eb7aa59c4184cc3891c0f7297c7d2d33d9d15db1f89d1"
}

rule MalwareBazaar_Prometei_078_6ec4916a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ec4916adf65beaa26bb4944cbb4bb80cf33a716f5bcd8177750428c665cddce"
    family = "Prometei"
    file_name = "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
    file_type = "elf"
    first_seen = "2026-10-22 03:44:30"
  condition:
    hash.sha256(0, filesize) == "6ec4916adf65beaa26bb4944cbb4bb80cf33a716f5bcd8177750428c665cddce"
}

rule MalwareBazaar_unknown_079_9ac8d3b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb"
    family = "unknown"
    file_name = "9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb"
    file_type = "7z"
    first_seen = "2026-10-22 03:44:19"
  condition:
    hash.sha256(0, filesize) == "9ac8d3b7c365839ca9cd6510f76ec203735431a1f609d5e9e8387a7901b7cfbb"
}

rule MalwareBazaar_unknown_080_b6be1a0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379"
    family = "unknown"
    file_name = "b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379"
    file_type = "exe"
    first_seen = "2026-10-22 03:44:14"
  condition:
    hash.sha256(0, filesize) == "b6be1a0a286bf132edd8afc8c7c11c346b8c55507f939975f6f6c460391bd379"
}

rule MalwareBazaar_Prometei_081_b34dc6f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
    family = "Prometei"
    file_name = "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
    file_type = "elf"
    first_seen = "2026-10-22 03:44:11"
  condition:
    hash.sha256(0, filesize) == "b34dc6f21a5254c24029356e1129ad3d50ee670937d9d2f4c3107f4b05455745"
}

rule MalwareBazaar_Prometei_082_c6e33d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37"
    family = "Prometei"
    file_name = "c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37"
    file_type = "exe"
    first_seen = "2026-10-22 03:44:04"
  condition:
    hash.sha256(0, filesize) == "c6e33d5b4a7fa461743547db581a116ba0e5a2b12468510f2e4dade771d59b37"
}

rule MalwareBazaar_unknown_083_14602324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "146023243d56a97de6782daf39ef79715fd12ef3efd8554e9fd1021940a23ea3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:42:19"
  condition:
    hash.sha256(0, filesize) == "146023243d56a97de6782daf39ef79715fd12ef3efd8554e9fd1021940a23ea3"
}

rule MalwareBazaar_CoinMiner_084_a9969fce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9969fcef2ad4865519c7325ca458c3d586c5937fd3ada51c3eef684c4334560"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:38:36"
  condition:
    hash.sha256(0, filesize) == "a9969fcef2ad4865519c7325ca458c3d586c5937fd3ada51c3eef684c4334560"
}

rule MalwareBazaar_unknown_085_18d0c7d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18d0c7d0078e310617ffc4e75d93becfafc6434e6aef839a9587aaa2ca39ecfa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:36:04"
  condition:
    hash.sha256(0, filesize) == "18d0c7d0078e310617ffc4e75d93becfafc6434e6aef839a9587aaa2ca39ecfa"
}

rule MalwareBazaar_unknown_086_766113ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "766113abb85d8186721076f23422f6b7b5e773c06fd3451343f751568b4b091e"
    family = "unknown"
    file_name = "fuck_niggers_30.hta"
    file_type = "hta"
    first_seen = "2026-10-22 03:35:24"
  condition:
    hash.sha256(0, filesize) == "766113abb85d8186721076f23422f6b7b5e773c06fd3451343f751568b4b091e"
}

rule MalwareBazaar_unknown_087_5c195f41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c195f41798265546fdf058f2b4c4a2f35f88532b60b1d3976ae27f58aaec8ad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:33:13"
  condition:
    hash.sha256(0, filesize) == "5c195f41798265546fdf058f2b4c4a2f35f88532b60b1d3976ae27f58aaec8ad"
}

rule MalwareBazaar_Mirai_088_72d191ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-22 03:30:52"
  condition:
    hash.sha256(0, filesize) == "72d191ea359d563f97dc4b05d72a104837a4af131e9e626747761373c5f1f69f"
}

rule MalwareBazaar_CoinMiner_089_acb4328b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acb4328b2d6bfa66ff3d396fb80e266e684876057382ed768393c69d8174f3ed"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:29:29"
  condition:
    hash.sha256(0, filesize) == "acb4328b2d6bfa66ff3d396fb80e266e684876057382ed768393c69d8174f3ed"
}

rule MalwareBazaar_unknown_090_9b7237bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b7237bcbebe18085bc6322d165d65188150cf5219c03672971cf8d6b7b0dd30"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:25:30"
  condition:
    hash.sha256(0, filesize) == "9b7237bcbebe18085bc6322d165d65188150cf5219c03672971cf8d6b7b0dd30"
}

rule MalwareBazaar_Adware_OfferCore_091_c92d2ba2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c92d2ba2be0710a1f68be422410d21a5df7ef38a407e317d270568e86f968e6e"
    family = "Adware.OfferCore"
    file_name = "c92d2ba2be0710a1.bin"
    file_type = "exe"
    first_seen = "2026-10-22 03:25:08"
  condition:
    hash.sha256(0, filesize) == "c92d2ba2be0710a1f68be422410d21a5df7ef38a407e317d270568e86f968e6e"
}

rule MalwareBazaar_RustyStealer_092_7115bc90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7115bc90e9340ed8df5a83986f93256aa947c3a507cd60d63679b5cead98afbf"
    family = "RustyStealer"
    file_name = "7115bc90e9340ed8.bin"
    file_type = "exe"
    first_seen = "2026-10-22 03:24:59"
  condition:
    hash.sha256(0, filesize) == "7115bc90e9340ed8df5a83986f93256aa947c3a507cd60d63679b5cead98afbf"
}

rule MalwareBazaar_unknown_093_72340d98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72340d984e5018ea2763ab0125354ecbab45261bf3d9f241bca875b0ed2c9998"
    family = "unknown"
    file_name = "72340d984e5018ea.bin"
    file_type = "msi"
    first_seen = "2026-10-22 03:24:51"
  condition:
    hash.sha256(0, filesize) == "72340d984e5018ea2763ab0125354ecbab45261bf3d9f241bca875b0ed2c9998"
}

rule MalwareBazaar_unknown_094_b36d3ad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b36d3ad13456b95f05c4b237c5799a01884fd5121b793acbb5e1c50bb0f64405"
    family = "unknown"
    file_name = "b36d3ad13456b95f.bin"
    file_type = "msi"
    first_seen = "2026-10-22 03:24:42"
  condition:
    hash.sha256(0, filesize) == "b36d3ad13456b95f05c4b237c5799a01884fd5121b793acbb5e1c50bb0f64405"
}

rule MalwareBazaar_CoinMiner_095_b4a60551
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4a60551ca30298c4e8f225aea012cdc34aaaaf640d9c7ee0818860c74ffab19"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:23:46"
  condition:
    hash.sha256(0, filesize) == "b4a60551ca30298c4e8f225aea012cdc34aaaaf640d9c7ee0818860c74ffab19"
}

rule MalwareBazaar_unknown_096_41ad249f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41ad249f4d3f2ee1e13fa60544d5ead4eb12de75404de60c2ff43f6e1fd8425b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:18:15"
  condition:
    hash.sha256(0, filesize) == "41ad249f4d3f2ee1e13fa60544d5ead4eb12de75404de60c2ff43f6e1fd8425b"
}

rule MalwareBazaar_unknown_097_b9c25bd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c25bd6b70a019d08aadff9e6bb677c11ea5c9ae8ecb2f49a1d8a6da216fc98"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:17:42"
  condition:
    hash.sha256(0, filesize) == "b9c25bd6b70a019d08aadff9e6bb677c11ea5c9ae8ecb2f49a1d8a6da216fc98"
}

rule MalwareBazaar_CoinMiner_098_45fde449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45fde449a55e964d31b7be280e6b2a3df03bf29e09c2c2a3c3293db49e6a4f5e"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:14:44"
  condition:
    hash.sha256(0, filesize) == "45fde449a55e964d31b7be280e6b2a3df03bf29e09c2c2a3c3293db49e6a4f5e"
}

rule MalwareBazaar_unknown_099_937b0ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937b0ccd38d543b7fcb265901443601506623452067b4c0df3ec75117c06f02b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:09:21"
  condition:
    hash.sha256(0, filesize) == "937b0ccd38d543b7fcb265901443601506623452067b4c0df3ec75117c06f02b"
}

rule MalwareBazaar_CoinMiner_100_e8d4d78f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8d4d78f4dfc72d389e7101cdcba866b7ac90094c3356de17b22ecb097c53f9c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-22 03:05:57"
  condition:
    hash.sha256(0, filesize) == "e8d4d78f4dfc72d389e7101cdcba866b7ac90094c3356de17b22ecb097c53f9c"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

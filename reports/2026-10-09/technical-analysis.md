# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-09

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 665 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 665 |
| Unique family labels | 12 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 51 |
| unknown | 28 |
| ValleyRAT | 4 |
| Formbook | 3 |
| RemcosRAT | 3 |
| Vidar | 3 |
| RemusStealer | 2 |
| SilentNet | 2 |
| PureLogsStealer | 1 |
| Gh0stRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 66 |
| exe | 16 |
| sh | 5 |
| js | 4 |
| jar | 3 |
| vbs | 2 |
| macho | 2 |
| dll | 1 |
| apk | 1 |

## Per-Sample Analysis

### Sample 1: `53634069057acb00`

| Field | Value |
|---|---|
| SHA-256 | `53634069057acb00055ca4a90a3a5d2f40f3931b40d7cf7322c66b8a9f0dc13f` |
| Family label | `PureLogsStealer` |
| File name | `Enquiry_AG-012-F2026_Specifications.js` |
| File type | `js` |
| First seen | `2026-10-09 06:18:01` |
| Reporter | `lowmal3` |
| Tags | `js, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96ad674939839dadc1ae24c7e74130bf` |
| SHA-1 | `310adf9db3a38c075de1a43b0e9921d35be755c2` |
| SHA-256 | `53634069057acb00055ca4a90a3a5d2f40f3931b40d7cf7322c66b8a9f0dc13f` |
| SHA3-384 | `e379012e467b4475524bc4a7789f14444221d48dda96c4f061b87e0322c54173f50b7fb1a9aa96f7a93c626d7c87fb23` |
| TLSH | `T1C76522610605875B8A6CE7E82A1F17090DF8898173DCCED8E7A9DB81AF7D781C1F4E58` |
| SSDEEP | `24576:A4Uo8IKfQGuYrELCzr4dPb/sRAUL71HTdgsQwPvUgKGp4aUMhaLVLe1Vrr383lhV:A4JR/njuyfU8sQcxKnLyr3Qn` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_001_53634069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53634069057acb00055ca4a90a3a5d2f40f3931b40d7cf7322c66b8a9f0dc13f"
    family = "PureLogsStealer"
    file_name = "Enquiry_AG-012-F2026_Specifications.js"
    file_type = "js"
    first_seen = "2026-10-09 06:18:01"
  condition:
    hash.sha256(0, filesize) == "53634069057acb00055ca4a90a3a5d2f40f3931b40d7cf7322c66b8a9f0dc13f"
}
```

### Sample 2: `384b954cd0b20f18`

| Field | Value |
|---|---|
| SHA-256 | `384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c` |
| Family label | `unknown` |
| File name | `vcimanagement.mips` |
| File type | `elf` |
| First seen | `2026-10-09 06:17:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32b949b0d112aaa71c38e5b56c61b65f` |
| SHA-1 | `73d136285129da3a7556624b593b06d5e5f489c6` |
| SHA-256 | `384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c` |
| SHA3-384 | `c1d6c631849744750a6ff07e7410805f900422bfb601e7f404d81b9021a84910dc4b7d78e891afdf7fcd4995d662faca` |
| TLSH | `T1E414951B2F228F6EF269877047F38D219B5876D61AE1D684E1ACD5101F602CE641FFB8` |
| TELFHASH | `t1ba418e180e7817a066395c9d059dff3ad6a731eb7e162c338e51e8aaa769b435d20c0c` |
| SSDEEP | `1536:qnAGokPMiA9ah33YUWsS7bSY/4iDLCXp6sT8e0AmOSCDSxBbTxfXdPexkIW7/:n0KN7uY/4iD0x7SC+VXZexkIW7/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_384b954c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c"
    family = "unknown"
    file_name = "vcimanagement.mips"
    file_type = "elf"
    first_seen = "2026-10-09 06:17:43"
  condition:
    hash.sha256(0, filesize) == "384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c"
}
```

### Sample 3: `75b4aaa700bec814`

| Field | Value |
|---|---|
| SHA-256 | `75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1` |
| Family label | `unknown` |
| File name | `vcimanagement.sh4` |
| File type | `elf` |
| First seen | `2026-10-09 06:17:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b2bb5789301ae56b3a124c7710c9f1d` |
| SHA-1 | `3199e4522f93adbad05421d618e212323c7fc1c2` |
| SHA-256 | `75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1` |
| SHA3-384 | `1058abbcf92a8512f1e325d912288759d2bdc3638cba3a7c2f9495ed547f00f0c705ccfd32da9f8f1ccda6344afcc200` |
| TLSH | `T1B6D32963DD26AF5AC112A4F4B2F28F781B03BC6689571AE9A076DAF44143DCDF4083B4` |
| SSDEEP | `1536:dDKV083Ez7Tz74khI7xcsNCWdK8FZa7ZopU5K6a6qWkicWII8OdP:d2683Ob4aI1c428yR5ZpqWNcW1FP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_75b4aaa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1"
    family = "unknown"
    file_name = "vcimanagement.sh4"
    file_type = "elf"
    first_seen = "2026-10-09 06:17:41"
  condition:
    hash.sha256(0, filesize) == "75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1"
}
```

### Sample 4: `a4e54b021c695604`

| Field | Value |
|---|---|
| SHA-256 | `a4e54b021c69560422159eb4cdf54a27c92ef4feafb5516b4c9976d23d1c088a` |
| Family label | `Mirai` |
| File name | `qtm.x86` |
| File type | `elf` |
| First seen | `2026-10-09 06:13:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05214440e921fad4b2e2ae2506d8f1ae` |
| SHA-1 | `42ac18ea71db9fafca1755e83a97e39fc5d79551` |
| SHA-256 | `a4e54b021c69560422159eb4cdf54a27c92ef4feafb5516b4c9976d23d1c088a` |
| SHA3-384 | `3d69cd6acb5512aa8fe470712a4e9ca3c15305c38ca2808844fa4b0dfe3b18024ff90c290f20debaf83dc1434f3766da` |
| TLSH | `T1F804F84732BA7198CDE9C43872A543BDDB94F09713BAAB8ED7855DE0BD14440B92C393` |
| TELFHASH | `t1ac4187065291387657e45e02cb8c2d3f79d722c3ad9f38af5be046820ca4fc21ae1830` |
| SSDEEP | `3072:bKdXwZ/nGNemFduVvh/EBPfbwBYgxP2URiVxNkrun25D9UmEkIFxd:cmJVp/EFjwBYgxP2URiVJth` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_a4e54b02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e54b021c69560422159eb4cdf54a27c92ef4feafb5516b4c9976d23d1c088a"
    family = "Mirai"
    file_name = "qtm.x86"
    file_type = "elf"
    first_seen = "2026-10-09 06:13:28"
  condition:
    hash.sha256(0, filesize) == "a4e54b021c69560422159eb4cdf54a27c92ef4feafb5516b4c9976d23d1c088a"
}
```

### Sample 5: `189d9cb288563823`

| Field | Value |
|---|---|
| SHA-256 | `189d9cb2885638238f19f4dd911ac1ed72a16703cdf5a84985b0d3de4f0ba6f9` |
| Family label | `Mirai` |
| File name | `lol.sh` |
| File type | `sh` |
| First seen | `2026-10-09 06:10:01` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7513fe851c8e3904402cbd03f3f01205` |
| SHA-1 | `db7e345ecf5cca2184499aa10152662cf3e15302` |
| SHA-256 | `189d9cb2885638238f19f4dd911ac1ed72a16703cdf5a84985b0d3de4f0ba6f9` |
| SHA3-384 | `cd944d3121cd65ebf75479ff728341548a0cdb46e4b0b78be248297b9346479a22f9bf3d771f82d4051239e5cc612b30` |
| TLSH | `T1614184866251C676DF5EC81AFA648E0CF5C05E821851FF08DDFAA1F3D58DE982012E6B` |
| SSDEEP | `24:5ji6r3+l6r3JfF6r3/dU6r3hvF6r31e1Gu6r3aB+aquy6r3rm:p3+63JS3/33hva31e1GD3awaquP3rm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_189d9cb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189d9cb2885638238f19f4dd911ac1ed72a16703cdf5a84985b0d3de4f0ba6f9"
    family = "Mirai"
    file_name = "lol.sh"
    file_type = "sh"
    first_seen = "2026-10-09 06:10:01"
  condition:
    hash.sha256(0, filesize) == "189d9cb2885638238f19f4dd911ac1ed72a16703cdf5a84985b0d3de4f0ba6f9"
}
```

### Sample 6: `dc7815509fa8976e`

| Field | Value |
|---|---|
| SHA-256 | `dc7815509fa8976eaca782547f3f64471e875b37536a8aefc6b81222c4ac8646` |
| Family label | `unknown` |
| File name | `telnet.sh` |
| File type | `sh` |
| First seen | `2026-10-09 06:09:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9cfb65b9c7ed1b514fd4802e0ab40e4` |
| SHA-1 | `9b5ce6ab843e43f693662b7c7778ddfdf7ac792f` |
| SHA-256 | `dc7815509fa8976eaca782547f3f64471e875b37536a8aefc6b81222c4ac8646` |
| SHA3-384 | `0b6e6b7ada23de625930cee3aa5a65a705d81657b85469563ba01635708af5d56560dce5eb02064b717648ee81213994` |
| TLSH | `T10411808CE21BD5F55594E814B383529CC7C05B0949921BC8FE6FF17C742C48EB239266` |
| SSDEEP | `24:iPo+elnvDTOnOX+Kh/xxUhmI8OQLEmhBg75JePByPwW:iLcvOOX/rxOgBuDePcPb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_dc781550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc7815509fa8976eaca782547f3f64471e875b37536a8aefc6b81222c4ac8646"
    family = "unknown"
    file_name = "telnet.sh"
    file_type = "sh"
    first_seen = "2026-10-09 06:09:58"
  condition:
    hash.sha256(0, filesize) == "dc7815509fa8976eaca782547f3f64471e875b37536a8aefc6b81222c4ac8646"
}
```

### Sample 7: `da7cac6a41fb5317`

| Field | Value |
|---|---|
| SHA-256 | `da7cac6a41fb53171db401c5a952bcf1a4796068fd07c0900027dc5919cd4a7c` |
| Family label | `Mirai` |
| File name | `wj0s.arm` |
| File type | `elf` |
| First seen | `2026-10-09 06:09:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46cbc90be448e448bb1485e7370d3367` |
| SHA-1 | `908e1abab6c5e9c23ca73a6394c32e0b1f755c6a` |
| SHA-256 | `da7cac6a41fb53171db401c5a952bcf1a4796068fd07c0900027dc5919cd4a7c` |
| SHA3-384 | `4d29b33fe27ad16160dcb3bc0d4b7b0ab252b217e2ba790910f8b3b3b0fb603afe57069c890a35f097a915981bc4ba7d` |
| TLSH | `T1B374E893E240CE9AC26018B5721F7388774743BAD9E67143FA15EE31BB9E54F023A8D5` |
| SSDEEP | `6144:GG2lEdFRNNnkko8v7RcB0q3WrHguPqwE47lz2mj8j7HL+FkCXwGUBzJaMVBLm7ql:pdto8vQ0wW8K7xiSw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_da7cac6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da7cac6a41fb53171db401c5a952bcf1a4796068fd07c0900027dc5919cd4a7c"
    family = "Mirai"
    file_name = "wj0s.arm"
    file_type = "elf"
    first_seen = "2026-10-09 06:09:52"
  condition:
    hash.sha256(0, filesize) == "da7cac6a41fb53171db401c5a952bcf1a4796068fd07c0900027dc5919cd4a7c"
}
```

### Sample 8: `360fc4f17c71e1a1`

| Field | Value |
|---|---|
| SHA-256 | `360fc4f17c71e1a1b101778fd20f0b3c090bc6297e94d045bcb68bb432f313a1` |
| Family label | `unknown` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-09 06:02:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9966c3cf1c4be7cd0ef796f2be70b0cb` |
| SHA-1 | `162532e8359cc68e902a94ffa5c8a538fdc41ea0` |
| SHA-256 | `360fc4f17c71e1a1b101778fd20f0b3c090bc6297e94d045bcb68bb432f313a1` |
| SHA3-384 | `9e148a20b992c88a0e04db9bf51f9ac61263bbc36dd0781fec7469ad59caca95feaa66a6ec5fd21cbd9d18817663d985` |
| TLSH | `T1CF145B0AB6C1A0FDC8DAC27847AFA536EA32F44D0234B54F1B949E262F5DE306B1C755` |
| TELFHASH | `t1f0619a742e95395c21ebc64eb20eed6dfc7204418ee6b5ea9e577ec8de037c80d52052` |
| SSDEEP | `3072:uBa80trk90w0laLy77PNBPY7rHQo/PZ9Mgv7ZRu2JGO3Kkoz:uBf0trk90w/LI4LPRTLjo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_360fc4f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "360fc4f17c71e1a1b101778fd20f0b3c090bc6297e94d045bcb68bb432f313a1"
    family = "unknown"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-09 06:02:36"
  condition:
    hash.sha256(0, filesize) == "360fc4f17c71e1a1b101778fd20f0b3c090bc6297e94d045bcb68bb432f313a1"
}
```

### Sample 9: `37530b711f22e6fd`

| Field | Value |
|---|---|
| SHA-256 | `37530b711f22e6fd20ecad05961fa5fd6ee6afa2e60ab01931bda4819c4229ba` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-09 06:02:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55d34ed816c369b57654b71fbcea2e0a` |
| SHA-1 | `0afb52409a135a3918b403055162c2b6e39db9dd` |
| SHA-256 | `37530b711f22e6fd20ecad05961fa5fd6ee6afa2e60ab01931bda4819c4229ba` |
| SHA3-384 | `fe161b51b3c0aedfe17cb9f207d68d2a2b5f7879f72541980ee117d983434f521e82cdca74bafa1ed4682179fafdda6f` |
| TLSH | `T1CCE49D987B8D7D43E3C7F33DCF8A8A71322BB5E99352D2A23501425DD4C6EA9CBA0541` |
| SSDEEP | `12288:ZofJageWkgc+dF8NYdLZ9YDmhheEssDTYilik50PjlbIs5t8CO:ZbKkgc+dwk9YDmhhebuY4itj65` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_37530b71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37530b711f22e6fd20ecad05961fa5fd6ee6afa2e60ab01931bda4819c4229ba"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-09 06:02:34"
  condition:
    hash.sha256(0, filesize) == "37530b711f22e6fd20ecad05961fa5fd6ee6afa2e60ab01931bda4819c4229ba"
}
```

### Sample 10: `b38ed72f2f3f4764`

| Field | Value |
|---|---|
| SHA-256 | `b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c` |
| Family label | `Mirai` |
| File name | `vcimanagement.ppc` |
| File type | `elf` |
| First seen | `2026-10-09 05:50:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30e92abd6d258463ae46175147ef9501` |
| SHA-1 | `763794d07826d7d53f6d28235005684377cb7e26` |
| SHA-256 | `b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c` |
| SHA3-384 | `1ed88b40c68c8c0aa25570e5b664f718003dbd3075586b247b9359c54eaf415d27ca1f77e45c09ef5c751fce54953393` |
| TLSH | `T1DDE30702770D0E03D2632DF0277B1BE0939BFD5628B5A684741FBEC992B1DB26446ED9` |
| SSDEEP | `1536:Wls7rP483tQLBFLJdaxlYZ6gx5BsqPuM6EgFHl2RfVtcDL/vArllwSoS4SqqVdnh:/78j1Jax1OPeIg5cJVsAr5F+k` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_b38ed72f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c"
    family = "Mirai"
    file_name = "vcimanagement.ppc"
    file_type = "elf"
    first_seen = "2026-10-09 05:50:36"
  condition:
    hash.sha256(0, filesize) == "b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c"
}
```

### Sample 11: `60324938d01641de`

| Field | Value |
|---|---|
| SHA-256 | `60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm7` |
| File type | `elf` |
| First seen | `2026-10-09 05:50:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c37e4e048bac7a51a8be972aa575b4a` |
| SHA-1 | `47f402208c7cf3af0800e503c66ca2dfecafeaf8` |
| SHA-256 | `60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e` |
| SHA3-384 | `f2d0b1d489a176e03cd3b981900e18d4a0323d5ada84dab9c0646db1d113845c3f45f3959417d35192c76bf716a678ba` |
| TLSH | `T114C3F745B9829B01D5D732FEFA9F419833536BACE3FE7101D9209F6123CA69B0B63512` |
| TELFHASH | `t11bd0a776c754d4eef9c75e61827b031609f5b58b12010c40a7bc5d9d43164137c05431` |
| SSDEEP | `3072:Ob4KNbLRj24Vj/qbh9XHaDlq1s8dc+5nfU9OF+v:z4x/qlFHaDlq1s8+ifaOF+v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_60324938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-10-09 05:50:33"
  condition:
    hash.sha256(0, filesize) == "60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e"
}
```

### Sample 12: `9303a4a918d93f36`

| Field | Value |
|---|---|
| SHA-256 | `9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm6` |
| File type | `elf` |
| First seen | `2026-10-09 05:50:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3471461a7e72be9be6500eaf7f360e2f` |
| SHA-1 | `f6285653ed700cf3f7fcd7592e13387dcaeba55e` |
| SHA-256 | `9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203` |
| SHA3-384 | `b806224f6788755f58d32b5da3dcbed15add37b537007007d7c810ce42d5b75369546d9cac8d598405cfe6edb4959695` |
| TLSH | `T18AF30942B9828F16C5C211BEFF5E418937137F78D3DE72029D24AFA0378A5EB097A516` |
| TELFHASH | `t138d0a73fef4858fca5d58274815b28642ae5b1e866121a30d5ad3f5f81a6052e06ce22` |
| SSDEEP | `3072:fVjUNeLWrOF/5JnX7BUJeafq4mZR/MWWTnRe3Wnpm:5F/XX9U0ay4iaWWFe3Wnpm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_9303a4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203"
    family = "Mirai"
    file_name = "vcimanagement.arm6"
    file_type = "elf"
    first_seen = "2026-10-09 05:50:31"
  condition:
    hash.sha256(0, filesize) == "9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203"
}
```

### Sample 13: `774acba8544be239`

| Field | Value |
|---|---|
| SHA-256 | `774acba8544be239131e88caed2937694e7b709f273be199ad9d2f29968dd1c7` |
| Family label | `Formbook` |
| File name | `Files 0019002610.pdf.js` |
| File type | `js` |
| First seen | `2026-10-09 05:49:38` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f495fb212030cc81caa1f907aea2006` |
| SHA-1 | `5fcf58991cfe9f8cd466e923cc52afb36238f4c7` |
| SHA-256 | `774acba8544be239131e88caed2937694e7b709f273be199ad9d2f29968dd1c7` |
| SHA3-384 | `e949ddfac9765b0baba5778e35d2174242e6814f9208554626b4f5a5ecd599ff5938ec1492766283e6a5b2a8414015a8` |
| TLSH | `T156C2FD408685748453336B3BEA2BA8E4F7770A6B01804907B97C7495EFF5A09DFE0DB6` |
| SSDEEP | `768:4MGJRZC0v5jrfw3HBbGsD3GFyHmrbJDYGFfnMo5cPWjWJ05TNVeO0y0l/6Qx+:4MbbeBz5/tNVkw` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_013_774acba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774acba8544be239131e88caed2937694e7b709f273be199ad9d2f29968dd1c7"
    family = "Formbook"
    file_name = "Files 0019002610.pdf.js"
    file_type = "js"
    first_seen = "2026-10-09 05:49:38"
  condition:
    hash.sha256(0, filesize) == "774acba8544be239131e88caed2937694e7b709f273be199ad9d2f29968dd1c7"
}
```

### Sample 14: `51b2a2243840c068`

| Field | Value |
|---|---|
| SHA-256 | `51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224` |
| Family label | `Mirai` |
| File name | `disssh4` |
| File type | `elf` |
| First seen | `2026-10-09 05:46:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ebbc34ea82c9ed3db52ed2a9473bfa7` |
| SHA-1 | `1b68ccf1d8724c4a57f02d0f1847749471c7b3a6` |
| SHA-256 | `51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224` |
| SHA3-384 | `f9880edb3e4ebe3f464bab701bc479aed872dafeaac7ff5862d23d233b6060c7a3a9b39541d6539aaccfddf984f64977` |
| TLSH | `T1D2048DA2D8647E98C265E2B0F1B1DF782B23969146075FBF5977C2B44083D8CF605BB8` |
| SSDEEP | `3072:tC9s/mRZBLfvX97y+gTQlX8lKYHJz74kFlz335RQPOW4DcjzXp:tC9s/mRZNX9W+g8eKYHJz74kFNSb4D8Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_51b2a224
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-09 05:46:30"
  condition:
    hash.sha256(0, filesize) == "51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224"
}
```

### Sample 15: `22949b40865c3d6c`

| Field | Value |
|---|---|
| SHA-256 | `22949b40865c3d6c9a2c7d7eae97c964b5fde63c1727ce74773d7aeb20be347a` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full.exe` |
| File type | `exe` |
| First seen | `2026-10-09 05:44:59` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4073eb55fca304f6aa94d9643286a503` |
| SHA-1 | `db9d8725ab59d62827275531ce7216b3b9fe1e42` |
| SHA-256 | `22949b40865c3d6c9a2c7d7eae97c964b5fde63c1727ce74773d7aeb20be347a` |
| SHA3-384 | `112b76f938bffd0a3e849a237ca028e3adc4e1f5b20c848f75253d3d9837edb039fd3d9fb02e1e0db06ed650102c4698` |
| IMPHASH | `abf73dc5794b54a40e3ea5c9332fa07f` |
| TLSH | `T18A255A89BB7B1AFEFF64B1751443EE37B41E259841ED09FA002D36700B93C9166FA468` |
| SSDEEP | `12288:lqpPkHptRKxku/oo6QRWP6mRdiorFTOnmEdE8HFJ4GAwhuskcVlAzNsVthb32PIp:l+cHDl3QR46mDOmveFivwhufNQf3/p` |
| ICON-DHASH | `d488dcf0b2e886d0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_22949b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22949b40865c3d6c9a2c7d7eae97c964b5fde63c1727ce74773d7aeb20be347a"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.exe"
    file_type = "exe"
    first_seen = "2026-10-09 05:44:59"
  condition:
    hash.sha256(0, filesize) == "22949b40865c3d6c9a2c7d7eae97c964b5fde63c1727ce74773d7aeb20be347a"
}
```

### Sample 16: `1981072e76c686da`

| Field | Value |
|---|---|
| SHA-256 | `1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b` |
| Family label | `Mirai` |
| File name | `vcimanagement.mpsl` |
| File type | `elf` |
| First seen | `2026-10-09 05:42:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `328418541c9d8129ecce148c3334a38d` |
| SHA-1 | `4e3d63f436a6704039019c4383f20043489a80b1` |
| SHA-256 | `1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b` |
| SHA3-384 | `5acb8417793389dca63f0bb755560a3a52a7384c80a6a2a0a2d82a60b1e29f3d56d16f747c89dfa91377157ee4d07c46` |
| TLSH | `T14614D706AB520FFBD86BDD3702F90B0128CCB81B26A53B757674D924F50A98B4AD3D74` |
| SSDEEP | `3072:8GocmqjPM+tjyOyDaDRRK+x2ojrrzBewL6Um+vrU2:1ocBNyYKmj/NnqK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_1981072e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b"
    family = "Mirai"
    file_name = "vcimanagement.mpsl"
    file_type = "elf"
    first_seen = "2026-10-09 05:42:32"
  condition:
    hash.sha256(0, filesize) == "1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b"
}
```

### Sample 17: `8008767e83e3baa5`

| Field | Value |
|---|---|
| SHA-256 | `8008767e83e3baa563ee9880881518dde6b43ae99f8c5585c05d61936f9d01dd` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-09 05:34:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b2fa36a8b6f7a1160fb37bd793e057c` |
| SHA-1 | `53cc74eacba652d34ccc0d35927b1c4b5d15bbfa` |
| SHA-256 | `8008767e83e3baa563ee9880881518dde6b43ae99f8c5585c05d61936f9d01dd` |
| SHA3-384 | `d9cf9e2b5374c29a08a58cdd57281c0ce3adc9fc3c88c2a8a08d1eaf13ce9ce5bf2c592707539c29fb40378431e8bbb4` |
| TLSH | `T1B934C747BE79EEC5C8BC4E70A759C7395044A0C6A2B6A59EF7B49FC8E7182003E1E1C5` |
| SSDEEP | `3072:sOEs/IGNemODY7shSHE5y8hS4Aj0/FR5g73kbNKHXHCqVsVC6HPwJojEnB+0o:s3s2G0yAS4Aj0P57b03iqVsVC6Hon+0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_8008767e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8008767e83e3baa563ee9880881518dde6b43ae99f8c5585c05d61936f9d01dd"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-09 05:34:50"
  condition:
    hash.sha256(0, filesize) == "8008767e83e3baa563ee9880881518dde6b43ae99f8c5585c05d61936f9d01dd"
}
```

### Sample 18: `606a58ec83b4767b`

| Field | Value |
|---|---|
| SHA-256 | `606a58ec83b4767b4e7806903f2daa0eaf9e40d8299d84d881ccba490ffc20c2` |
| Family label | `unknown` |
| File name | `disspoor` |
| File type | `elf` |
| First seen | `2026-10-09 05:31:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `557bf0ab0b66bf583b578d10079c32d9` |
| SHA-1 | `0a21c38f6c1d8ab2483631d2b6b8190c5c2b7791` |
| SHA-256 | `606a58ec83b4767b4e7806903f2daa0eaf9e40d8299d84d881ccba490ffc20c2` |
| SHA3-384 | `2a9dd231f47ef44816b9a37d88aec9b81d62d995e0326f836199da9683843486fb1b44a857e0b161837c4e637c33b272` |
| TLSH | `T17B147D01B31C0947E1632EF03B3F27D1D3EE9A9125F5EA452A0FBA498272D322589DDD` |
| SSDEEP | `6144:r+hISpQEHxEHsUwFV7+xuwCA0HrqvzoXJ:zuxEMUwFV7rwBvz6J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_606a58ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "606a58ec83b4767b4e7806903f2daa0eaf9e40d8299d84d881ccba490ffc20c2"
    family = "unknown"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-09 05:31:23"
  condition:
    hash.sha256(0, filesize) == "606a58ec83b4767b4e7806903f2daa0eaf9e40d8299d84d881ccba490ffc20c2"
}
```

### Sample 19: `a1bca91d3e2bd012`

| Field | Value |
|---|---|
| SHA-256 | `a1bca91d3e2bd012c3e0dbe88e09062848c1cff602c990a541d7b1c9224ad16e` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-09 05:24:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f580dd02245d3833e58444954d688bf9` |
| SHA-1 | `e9dbd2ac6728dc6324de807bab1487ecdde0b1b2` |
| SHA-256 | `a1bca91d3e2bd012c3e0dbe88e09062848c1cff602c990a541d7b1c9224ad16e` |
| SHA3-384 | `091240e2883821675761f1d348a247993c14c2163ec18e301172e12a733bdca9b0c293469d9a47225de284e2bfa46b73` |
| TLSH | `T1C234E967BAB6FFD8C8A5C5306571C3B44182ACE21AF5955DF361EB8CEE241007E1E2D2` |
| SSDEEP | `3072:8nwvn/IGNemO5dqgFOfsW1oGZ6pjD/+pKXwPuA2fRPGavTv7gnD5NoWS3zaQ+:AwvnqfesW1bMDmK5AOPXynqaQ+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_a1bca91d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1bca91d3e2bd012c3e0dbe88e09062848c1cff602c990a541d7b1c9224ad16e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-09 05:24:21"
  condition:
    hash.sha256(0, filesize) == "a1bca91d3e2bd012c3e0dbe88e09062848c1cff602c990a541d7b1c9224ad16e"
}
```

### Sample 20: `d724dc8b5d6bb230`

| Field | Value |
|---|---|
| SHA-256 | `d724dc8b5d6bb230f42a3ec0d5f71ccb8c8e9a88025756074b36961709ed1384` |
| Family label | `Mirai` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-09 05:24:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ce7776ff0d0f458ae393acf0ae0fd1b` |
| SHA-1 | `d26d5c590d5e41df6c1980ea9d02079cf4e760f7` |
| SHA-256 | `d724dc8b5d6bb230f42a3ec0d5f71ccb8c8e9a88025756074b36961709ed1384` |
| SHA3-384 | `f03c489bfbc0eeb5b4c075cd3c67683df13272f512ca14c4b6c82f602c751efe66c8b828ef77395805ce94bccc844792` |
| TLSH | `T174142A45F8509B23C7C5667BFB6E428C372B53B8D2EA31039E115F24379B46B0E7A642` |
| TELFHASH | `t1d5d02b32cc4010d4b724419eccfe722433a9b9251745c02a92da7f69ae93c55e430c47` |
| SSDEEP | `3072:9sPHRetYqCpZhroNlDqIUi6LWlYvVPoBVOrkY5lbM4mh8bQTzCw3TaM:CPmRCp/roixLWlYv1oLOvvbM4U8b2zCs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_d724dc8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d724dc8b5d6bb230f42a3ec0d5f71ccb8c8e9a88025756074b36961709ed1384"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-09 05:24:18"
  condition:
    hash.sha256(0, filesize) == "d724dc8b5d6bb230f42a3ec0d5f71ccb8c8e9a88025756074b36961709ed1384"
}
```

### Sample 21: `c0863e8dbb46099a`

| Field | Value |
|---|---|
| SHA-256 | `c0863e8dbb46099ae4897fbdbf2dac14e0e2e2871d0595ee38d37b3fc44f3b36` |
| Family label | `Mirai` |
| File name | `dissarm7` |
| File type | `elf` |
| First seen | `2026-10-09 05:20:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b7976e736049ff7e64fd5600b2c7251` |
| SHA-1 | `13dad3adc79aa304cc880f1ddd9f42456505e2f6` |
| SHA-256 | `c0863e8dbb46099ae4897fbdbf2dac14e0e2e2871d0595ee38d37b3fc44f3b36` |
| SHA3-384 | `6513fa670699f1f5dac88ddfa7a27f971a9ee3d559a497645ca14c247fd0464fd61e87a59cf52441a848ad1cd4aff3e9` |
| TLSH | `T1A4041849FC81AF10D5D536BAFA1E4189336757B8E3FA7112DE245B2023CA92F0F7A512` |
| TELFHASH | `t124b09288080069c967830001e9fc2323e204f0675b48080652d07c6eba72725c832806` |
| SSDEEP | `3072:5Kvi6+uLyU+AZMKBaRw/+ePnn0WtlZaHMthGhGlN9f0d934/OlacW:MvD+icAKmPnnT3ZaHMPGhGlNB63SOla3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_c0863e8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0863e8dbb46099ae4897fbdbf2dac14e0e2e2871d0595ee38d37b3fc44f3b36"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-09 05:20:52"
  condition:
    hash.sha256(0, filesize) == "c0863e8dbb46099ae4897fbdbf2dac14e0e2e2871d0595ee38d37b3fc44f3b36"
}
```

### Sample 22: `e867fc47c809868e`

| Field | Value |
|---|---|
| SHA-256 | `e867fc47c809868e46bbef459c4146b0ed111697d7672ce4c6623322afa2a1f4` |
| Family label | `Mirai` |
| File name | `adissarm5` |
| File type | `elf` |
| First seen | `2026-10-09 05:17:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `252f33e587c7fa9125789766550bc249` |
| SHA-1 | `bd94d7bbc69796f6f025dbe74dca2ed0f19103e5` |
| SHA-256 | `e867fc47c809868e46bbef459c4146b0ed111697d7672ce4c6623322afa2a1f4` |
| SHA3-384 | `86a620be2f86f9a82e007e79d491e29f3709d663f1cc29890455de8068a8ab595d2b0e0cb821683d84714b3d25a1c7eb` |
| TLSH | `T158142A85FC419F16C6C1667BFB2E428C372B53B8D3EE31069E116F24379B46A0E76642` |
| TELFHASH | `t16101d010ce481adc7af84156c9fd621bea58709c3b170001a97cfe6bc953c97b030a0e` |
| SSDEEP | `3072:L+M1KpS12bi8XKqNoMD7YZNDQVf7OuU7YVvkA8fM/4kQ+a+ZYAkmd14rT:LZ11wbi/qNoMxVfSumec30/4j+aaYANk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_e867fc47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e867fc47c809868e46bbef459c4146b0ed111697d7672ce4c6623322afa2a1f4"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-09 05:17:11"
  condition:
    hash.sha256(0, filesize) == "e867fc47c809868e46bbef459c4146b0ed111697d7672ce4c6623322afa2a1f4"
}
```

### Sample 23: `25089d27e69ec64c`

| Field | Value |
|---|---|
| SHA-256 | `25089d27e69ec64c5d5887f8f67303db883fe0c373df6a8805ad960a313b1777` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm` |
| File type | `elf` |
| First seen | `2026-10-09 05:17:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fce2a7659f87e2005eaffce84fccd2d` |
| SHA-1 | `924d11bfe09762ecb0c4d57b8248304f6179b64d` |
| SHA-256 | `25089d27e69ec64c5d5887f8f67303db883fe0c373df6a8805ad960a313b1777` |
| SHA3-384 | `a0871bf01240288ef1fb9853ea4423765d2f587a864447891cc235874f239e24598a9d43dc5b0db8f02aa4dcf34e3267` |
| TLSH | `T1D5E3E742BD419F13C6C322FBFBDE42893B267B69D6EE3102D9216FA0378A5D60937151` |
| TELFHASH | `t1f9d0c2338b4428e8b3eb461211b9711e4efd75bc1545496073fc2ee6091368275ae823` |
| SSDEEP | `3072:KyQ83fdwwOhiv9fkJqyJ4NruGJ9G7fkni+oK:Kf83FwrGfkJnJ4NNJUDknirK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_25089d27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25089d27e69ec64c5d5887f8f67303db883fe0c373df6a8805ad960a313b1777"
    family = "Mirai"
    file_name = "vcimanagement.arm"
    file_type = "elf"
    first_seen = "2026-10-09 05:17:08"
  condition:
    hash.sha256(0, filesize) == "25089d27e69ec64c5d5887f8f67303db883fe0c373df6a8805ad960a313b1777"
}
```

### Sample 24: `f2700a394f0511ad`

| Field | Value |
|---|---|
| SHA-256 | `f2700a394f0511ad48a420043258657b3c2617c3d7a1f377204e8f3b7540bb5a` |
| Family label | `RemcosRAT` |
| File name | `CONTRACT DRAFT-EGP-25006-SG1-SLO-GS-0349.vbs` |
| File type | `vbs` |
| First seen | `2026-10-09 05:15:34` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77c07825ed6e0e225d342aedcfa77f7b` |
| SHA-1 | `4c9ff108ea6e61b2acbe9a8205f33be018eade46` |
| SHA-256 | `f2700a394f0511ad48a420043258657b3c2617c3d7a1f377204e8f3b7540bb5a` |
| SHA3-384 | `c44f71846b835caaeb2450a8e701aaa4c940f36b92c923973890789b2f86e00d74b76721a7116a8b11a8b76d1f4a07a0` |
| TLSH | `T1CA634A10DE7801164E4B1BE6FC9E0A65CDBECB15422650B1FEFD274D5002AACB3FD669` |
| SSDEEP | `768:OiaXLt+0MmNKWfDkrP5LqHV/CrkaVxOi2t400cMYHryIOHvKzaQpzIMKzFw5Y/RZ:JGxMJtRWzVKQpPiuY/RU88GOeD2dnAkO` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_024_f2700a39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2700a394f0511ad48a420043258657b3c2617c3d7a1f377204e8f3b7540bb5a"
    family = "RemcosRAT"
    file_name = "CONTRACT DRAFT-EGP-25006-SG1-SLO-GS-0349.vbs"
    file_type = "vbs"
    first_seen = "2026-10-09 05:15:34"
  condition:
    hash.sha256(0, filesize) == "f2700a394f0511ad48a420043258657b3c2617c3d7a1f377204e8f3b7540bb5a"
}
```

### Sample 25: `b74cb10109cbd5d8`

| Field | Value |
|---|---|
| SHA-256 | `b74cb10109cbd5d8dbfb3d2b34016991f69430fb9fc6553ddf7371a0e189c2ae` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-09 05:03:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24722bd1a63fff82557ef8197cf9d5fd` |
| SHA-1 | `f6f2bb2e0a54ea3e595aa4be85fd4d6c53361da2` |
| SHA-256 | `b74cb10109cbd5d8dbfb3d2b34016991f69430fb9fc6553ddf7371a0e189c2ae` |
| SHA3-384 | `900c2c950dbae53e49c80da56c219d167a9e12cede524d4d06e3635d87bd238797ef5e111fbf05f2779284d98810c824` |
| TLSH | `T1C2F44AA6BD5298A0C4D45ABAF71DC2DC334353B9C3EA7206CD06C73469CE9594D3ABC2` |
| TELFHASH | `t170f02b520554dcdfb1e84117742b87a5e420883ca8ac27a631e3b83ec383d3061e7fa6` |
| SSDEEP | `12288:1W2D7rMX7ioodnk6zuIk5KtemU5dEVWyT8eP9I:1kX03U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_b74cb101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b74cb10109cbd5d8dbfb3d2b34016991f69430fb9fc6553ddf7371a0e189c2ae"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-09 05:03:03"
  condition:
    hash.sha256(0, filesize) == "b74cb10109cbd5d8dbfb3d2b34016991f69430fb9fc6553ddf7371a0e189c2ae"
}
```

### Sample 26: `178ee12744a15f48`

| Field | Value |
|---|---|
| SHA-256 | `178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a` |
| Family label | `unknown` |
| File name | `dissmips` |
| File type | `elf` |
| First seen | `2026-10-09 04:47:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22cb330c4b9bfffe5a1126ba0564d615` |
| SHA-1 | `ebf28a6b51190dc00b525fcd70cd0fb3cc164a40` |
| SHA-256 | `178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a` |
| SHA3-384 | `2523f5b02bde1361d853d97d371251ce6341c8e13f3f74ac15d10d459738b481f2c855cd31c967d0664d067ba43c2a0b` |
| TLSH | `T14B44C64E6E618F7DF2B8873447B74B34976932D727E1D685E1ACD2101E2024E681FFA8` |
| TELFHASH | `t1f44194181d7813f0a2356c5d45ddff76d6a330eb7e266c238b11e86aab79a435d10c0c` |
| SSDEEP | `6144:Tx9A2nviAyczH9jMI9/5JLTTuqUAz7q8VWmZR:QYvtychMy/dUYR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_178ee127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a"
    family = "unknown"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-09 04:47:32"
  condition:
    hash.sha256(0, filesize) == "178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a"
}
```

### Sample 27: `3ea03e28c0a5a8c8`

| Field | Value |
|---|---|
| SHA-256 | `3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617` |
| Family label | `Formbook` |
| File name | `Swift_Copy_IF01200022823419.exe` |
| File type | `exe` |
| First seen | `2026-10-09 04:37:52` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17c4d6e51c52e59ada1d644411d33015` |
| SHA-1 | `86ca4d6d00752507b1f12faf1bb55af0a6ec5db1` |
| SHA-256 | `3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617` |
| SHA3-384 | `4194b36c670883a7bfa871e40f299f07f85fbb7f1f46e34dedcf064165099e1a6a9dd1e343593537e9ebd13a952ddc42` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D005DF00326BCD13D1B65BB106E1D3708BB42E95E622D3978FE66EE77A267C158C0793` |
| SSDEEP | `12288:J0qG0iBn3vu6SZzpX8zm/ntg9UlmygxJNl6qBgkZzE6tGOxyS+Cob0YmKO:bQB3vtKX8Mt+ygxkql4q0bbJO` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_027_3ea03e28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
    family = "Formbook"
    file_name = "Swift_Copy_IF01200022823419.exe"
    file_type = "exe"
    first_seen = "2026-10-09 04:37:52"
  condition:
    hash.sha256(0, filesize) == "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
}
```

### Sample 28: `2524ca7fb873708b`

| Field | Value |
|---|---|
| SHA-256 | `2524ca7fb873708b0e994ca5f6f18db95fcd5bc59c7e54eb5426b91658759142` |
| Family label | `unknown` |
| File name | `client.jar` |
| File type | `jar` |
| First seen | `2026-10-09 03:53:51` |
| Reporter | `rc4` |
| Tags | `jar, runelite, runelure, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e47ffac29696de3c8d72bc0c78e33a71` |
| SHA-1 | `e1d9dcfcbc1f46b2be64d0b17c3bf3abf5f6eab0` |
| SHA-256 | `2524ca7fb873708b0e994ca5f6f18db95fcd5bc59c7e54eb5426b91658759142` |
| SHA3-384 | `fe1509d7edfd31b9963ff77255029b2711ae435eb20d6832b7541b7aeda9407adf648bbbb6b82e8cdfcf8e55f06a7d68` |
| TLSH | `T119670223D908F63DE936433AE0420592B95F17ECD80F90A564F029FAAD05D4D7FA1BE9` |
| SSDEEP | `393216:OLVsAkL2YgKzSwAjOxtPCvJsnlWKVSreRYQx8tnWNdksh+W64ILJa0cM2UROOqw1:0V3kL2f+S+AxslW2RR6WRILJaHMZQOOU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_2524ca7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2524ca7fb873708b0e994ca5f6f18db95fcd5bc59c7e54eb5426b91658759142"
    family = "unknown"
    file_name = "client.jar"
    file_type = "jar"
    first_seen = "2026-10-09 03:53:51"
  condition:
    hash.sha256(0, filesize) == "2524ca7fb873708b0e994ca5f6f18db95fcd5bc59c7e54eb5426b91658759142"
}
```

### Sample 29: `ce5e8dde18aef81f`

| Field | Value |
|---|---|
| SHA-256 | `ce5e8dde18aef81faf1afb127da44e470d512f5f4f6a0d8d100361ba818fc043` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-09 03:36:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8b4c90abf992f45e7111145113469bd` |
| SHA-1 | `498a0e68131728ae7ad702930c3cc26d889b03d5` |
| SHA-256 | `ce5e8dde18aef81faf1afb127da44e470d512f5f4f6a0d8d100361ba818fc043` |
| SHA3-384 | `00ffbecf2c0c39a692013c6a92ea979a96cb47afcb8f2bfdcb9583ec928a54b4634c68917d7aba4651af802df6293355` |
| TLSH | `T109B4E059F2462E42C5E7E539188AC6810799E46F23F383022B43A5BB387D7B74F39749` |
| SSDEEP | `12288:7H3yJt4yhpRtf16IBaRh7YboApZCR9Vgpu/BMIkB:wh5N6I+hCoAyqIk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_ce5e8dde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce5e8dde18aef81faf1afb127da44e470d512f5f4f6a0d8d100361ba818fc043"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-09 03:36:33"
  condition:
    hash.sha256(0, filesize) == "ce5e8dde18aef81faf1afb127da44e470d512f5f4f6a0d8d100361ba818fc043"
}
```

### Sample 30: `cf90ad8eef1b73e6`

| Field | Value |
|---|---|
| SHA-256 | `cf90ad8eef1b73e674f5dbbc12f8bbc4ee0ebc2b9485ddf5ef3cf5ce863f5333` |
| Family label | `ValleyRAT` |
| File name | `ZillberReleyHost.exe` |
| File type | `exe` |
| First seen | `2026-10-09 03:24:25` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcd580118706ee497e645311915996b0` |
| SHA-1 | `3243fb84a11143e574696e23eb114b4467275c35` |
| SHA-256 | `cf90ad8eef1b73e674f5dbbc12f8bbc4ee0ebc2b9485ddf5ef3cf5ce863f5333` |
| SHA3-384 | `26c9fe933d27ac8bad74404ebace8e6564402f83fbc952e2d7e1140d3c9bef545013982ec702809462d3de9f78d500a6` |
| IMPHASH | `230a8cb70f5fc6f4574e4c22b6277a01` |
| TLSH | `T199672310EAD782B5C65127F905796ADEF4765E1C032418FBFFD92D0EA079BF484B02A2` |
| SSDEEP | `786432:CguB4HZNU3SCPSqcvJj5xRD5znOQTlfwuUeRADS3:1uSZeCOg/5znlTlfwuLcW` |
| ICON-DHASH | `133b7b63634b5943` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_030_cf90ad8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf90ad8eef1b73e674f5dbbc12f8bbc4ee0ebc2b9485ddf5ef3cf5ce863f5333"
    family = "ValleyRAT"
    file_name = "ZillberReleyHost.exe"
    file_type = "exe"
    first_seen = "2026-10-09 03:24:25"
  condition:
    hash.sha256(0, filesize) == "cf90ad8eef1b73e674f5dbbc12f8bbc4ee0ebc2b9485ddf5ef3cf5ce863f5333"
}
```

### Sample 31: `e292d65b13465344`

| Field | Value |
|---|---|
| SHA-256 | `e292d65b134653448ef4bcad23eaae8b08abefcbfcd360c3f0cd74adfee33495` |
| Family label | `ValleyRAT` |
| File name | `instdoload.1.3.13.exe` |
| File type | `exe` |
| First seen | `2026-10-09 03:23:02` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b85b33c6c8ac7242fb09c70c5c583a11` |
| SHA-1 | `e698540a6d357a092fac2f55f853731c7eeca504` |
| SHA-256 | `e292d65b134653448ef4bcad23eaae8b08abefcbfcd360c3f0cd74adfee33495` |
| SHA3-384 | `9a3a52e560f827636f0a390690529a843f978309a87589001d6b653a89130522c4fec52c7938d3c5cefc491c8c73b331` |
| IMPHASH | `e611cb40dae30a74fa3f15a0e816a66a` |
| TLSH | `T193972C02B6468CC6F54852F45897FAA423FDFCB48AD5C31732E4671EAF9E28C0E83595` |
| SSDEEP | `49152:sF335nW2J++1hhWugAx8z/TdqRD4a85Ejr9CbHd5nYeWgRm:G5L3XLgAm9EHUvm` |
| ICON-DHASH | `a2838983a27464b4` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_031_e292d65b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e292d65b134653448ef4bcad23eaae8b08abefcbfcd360c3f0cd74adfee33495"
    family = "ValleyRAT"
    file_name = "instdoload.1.3.13.exe"
    file_type = "exe"
    first_seen = "2026-10-09 03:23:02"
  condition:
    hash.sha256(0, filesize) == "e292d65b134653448ef4bcad23eaae8b08abefcbfcd360c3f0cd74adfee33495"
}
```

### Sample 32: `84fd7e7de84bf908`

| Field | Value |
|---|---|
| SHA-256 | `84fd7e7de84bf9080ec938f944b81807faa769ab2e27a4d0a5f8596ff6dc0072` |
| Family label | `ValleyRAT` |
| File name | `fdsfsffdsf.shop_313.exe` |
| File type | `exe` |
| First seen | `2026-10-09 03:20:58` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `345bd23aae7e28c9b249b81a245f6c8d` |
| SHA-1 | `eef695b8dfbe7783c81cd127c525543835cef9ec` |
| SHA-256 | `84fd7e7de84bf9080ec938f944b81807faa769ab2e27a4d0a5f8596ff6dc0072` |
| SHA3-384 | `1bb95432aa27ca6fd220fd1ac99e7002d8d7cb17870057e673abeb5055a92d36763c5b48a3c16bdc5e05ed35412d5d7f` |
| IMPHASH | `5df5eac7d1a8cb68f8fe700b326611bf` |
| TLSH | `T19046E07FF1A5C17AC1EED13AD1A38B05E433B0760B33C2E752D40A668E0A9D55E7E660` |
| SSDEEP | `98304:DN2yeSEOf51tnXTxQ9LMF6ebZGaL0nDHPBQod:5LeS3f5PnXdQKPFL07BPd` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_032_84fd7e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84fd7e7de84bf9080ec938f944b81807faa769ab2e27a4d0a5f8596ff6dc0072"
    family = "ValleyRAT"
    file_name = "fdsfsffdsf.shop_313.exe"
    file_type = "exe"
    first_seen = "2026-10-09 03:20:58"
  condition:
    hash.sha256(0, filesize) == "84fd7e7de84bf9080ec938f944b81807faa769ab2e27a4d0a5f8596ff6dc0072"
}
```

### Sample 33: `f12f4f3fa2bca271`

| Field | Value |
|---|---|
| SHA-256 | `f12f4f3fa2bca2716be80804bf35c6ef988c67af7a3a08e048ae65058833f58f` |
| Family label | `RemcosRAT` |
| File name | `FedEx Shipment Documents.js` |
| File type | `js` |
| First seen | `2026-10-09 02:57:33` |
| Reporter | `threatcat_ch` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24a551d5307706c6cd3c6f8b4eafd5da` |
| SHA-1 | `877a79dc5c22bd87a384514c45f379245aecdcdf` |
| SHA-256 | `f12f4f3fa2bca2716be80804bf35c6ef988c67af7a3a08e048ae65058833f58f` |
| SHA3-384 | `5d01c723945ec3c26e49973520f1b35f4a9807736c98630e9d89739e45c8a350babe04532c5c7bfc065cf7bd4075ccbf` |
| TLSH | `T16A664967B6B1B99D5F6888A4D027DD22DCEDC0DB17A59F4E9BCE2A006073353231B931` |
| SSDEEP | `384:rs0Rq4wXnuEFRNBILNrM2r4xXTdUnAz4u0+5jdLMkWK3W+Jauu/40y09hpkHIn5l:rs05Ulq7Yt5OzFU1i` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_033_f12f4f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12f4f3fa2bca2716be80804bf35c6ef988c67af7a3a08e048ae65058833f58f"
    family = "RemcosRAT"
    file_name = "FedEx Shipment Documents.js"
    file_type = "js"
    first_seen = "2026-10-09 02:57:33"
  condition:
    hash.sha256(0, filesize) == "f12f4f3fa2bca2716be80804bf35c6ef988c67af7a3a08e048ae65058833f58f"
}
```

### Sample 34: `b426e063f6e71de0`

| Field | Value |
|---|---|
| SHA-256 | `b426e063f6e71de0d8c7bd6b1ed9c342e3aed4e16ff9d0b50154c67b899f8541` |
| Family label | `ValleyRAT` |
| File name | `F7D83D241F4A45EA7A97EA74A1016DFF.exe` |
| File type | `exe` |
| First seen | `2026-10-09 02:40:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7d83d241f4a45ea7a97ea74a1016dff` |
| SHA-1 | `c9e48064269a7f70a93ebc71ccc393e602f40f06` |
| SHA-256 | `b426e063f6e71de0d8c7bd6b1ed9c342e3aed4e16ff9d0b50154c67b899f8541` |
| SHA3-384 | `802d9d688756c407708374d510ccd2ffcfa0e0c1309941f280b57ef5c3cd6c367a7b1910699c0173aef4b5d259710291` |
| IMPHASH | `027ea80e8125c6dda271246922d4c3b0` |
| TLSH | `T163251202FAD484F2E4221D35452DBB54A5BCBA300F24CA5FA7D44D6EAE361E17632DB3` |
| SSDEEP | `24576:UmoO8itH/ZQBZawx6rynxeNPoYHF6/qCR4XgW8PxmANz2Kk:f1Z0aws8e+eeqQOCPvNNk` |
| ICON-DHASH | `cdabae6fe6e7eaec` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_034_b426e063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b426e063f6e71de0d8c7bd6b1ed9c342e3aed4e16ff9d0b50154c67b899f8541"
    family = "ValleyRAT"
    file_name = "F7D83D241F4A45EA7A97EA74A1016DFF.exe"
    file_type = "exe"
    first_seen = "2026-10-09 02:40:16"
  condition:
    hash.sha256(0, filesize) == "b426e063f6e71de0d8c7bd6b1ed9c342e3aed4e16ff9d0b50154c67b899f8541"
}
```

### Sample 35: `4ddf228dbf2223bf`

| Field | Value |
|---|---|
| SHA-256 | `4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8785f219f20197b32c9f` |
| Family label | `Gh0stRAT` |
| File name | `4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8.dll` |
| File type | `dll` |
| First seen | `2026-10-09 02:20:12` |
| Reporter | `abuse_ch` |
| Tags | `dll, Gh0stRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4653e27bd4f0979d1676f06ec4ba55e` |
| SHA-1 | `4cce9403c9717c81969888552bc75165f02f5dc1` |
| SHA-256 | `4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8785f219f20197b32c9f` |
| SHA3-384 | `21ea82258f316edffe1d317f6dae7fefe5ff9265a2ce80600fcd409c057ccd5a6daac33df119d817df32e27addd43320` |
| IMPHASH | `71134859cea34c19044d4341cef3641d` |
| TLSH | `T1A304AF00B9D081B1E3FF017C08F99B76A63FB5344B60ADE77394AEBA1D342D15A3558A` |
| SSDEEP | `3072:AeI6vHBR/J5Qlrr67BZjo24Z/o1KU5mQtsfARNN+6ED4ywLt7NewhrAhsRBT:Iqn/o677jBzBoq2UNN+6C4NLt1rAhsf` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_035_4ddf228d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8785f219f20197b32c9f"
    family = "Gh0stRAT"
    file_name = "4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8.dll"
    file_type = "dll"
    first_seen = "2026-10-09 02:20:12"
  condition:
    hash.sha256(0, filesize) == "4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8785f219f20197b32c9f"
}
```

### Sample 36: `99ef0d24c29b2122`

| Field | Value |
|---|---|
| SHA-256 | `99ef0d24c29b2122a3ecad4a0b9f9dc9677a4838d0c41a5ab567b1acddee0524` |
| Family label | `unknown` |
| File name | `DivX.exe` |
| File type | `exe` |
| First seen | `2026-10-09 02:19:44` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7405df8ee3cc0dd7da7a972166c61eab` |
| SHA-1 | `62c0d4afafba87f8211486704b834baa308e63ea` |
| SHA-256 | `99ef0d24c29b2122a3ecad4a0b9f9dc9677a4838d0c41a5ab567b1acddee0524` |
| SHA3-384 | `7e75db750690770cbb51c0c6f5165e2f3e4f3c36e54403b3b98efd7704828d6b02767fcb25aae4109d2393d88e5816b3` |
| IMPHASH | `8eaf50ddfa1b6fb3f7d2c117590c7850` |
| TLSH | `T1CA255C3EEB734DFEF889A437221240165FF1F21E47D0AB6E873E961589056802FF8656` |
| SSDEEP | `24576:tKGb2DSdWBc6OTkifybphxRdNyr9W+kZI:tj2DVBpOTk0Ip5/+kZ` |
| ICON-DHASH | `e897f16969719f3b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_99ef0d24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ef0d24c29b2122a3ecad4a0b9f9dc9677a4838d0c41a5ab567b1acddee0524"
    family = "unknown"
    file_name = "DivX.exe"
    file_type = "exe"
    first_seen = "2026-10-09 02:19:44"
  condition:
    hash.sha256(0, filesize) == "99ef0d24c29b2122a3ecad4a0b9f9dc9677a4838d0c41a5ab567b1acddee0524"
}
```

### Sample 37: `4f3179dce42f5c01`

| Field | Value |
|---|---|
| SHA-256 | `4f3179dce42f5c010b80304931d67fca6f5fcccbdd916b51785bc43a832af6d4` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-09 02:16:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `701235b6551adda5bc081bd02bfeb9be` |
| SHA-1 | `70fef7213989a0560e65bce00281fea4cf5abaf0` |
| SHA-256 | `4f3179dce42f5c010b80304931d67fca6f5fcccbdd916b51785bc43a832af6d4` |
| SHA3-384 | `1d0ff1382b90d4fcfcf8330bd1c4e46356ef04a8df16d76080d7dd7784e16fd456eb4b1ae4a54d2eee47faab90c43c30` |
| TLSH | `T13E04F74772BA7194CDE9C03872A503BDDB94F09713BAAB8EDB955DD0BD18440B92C393` |
| TELFHASH | `t112412900e2543e7a5be54a03465d7d3f6ddb20a3a65b09c997e88f810876fc23a9143f` |
| SSDEEP | `3072:o82aqMmGNemiCwYrxPsRRAYgxP2UjfXDLgA5uMDsn5c8JUSFxp:o82aqMPlhs/AYgxP2UzDLJ0v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_4f3179dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f3179dce42f5c010b80304931d67fca6f5fcccbdd916b51785bc43a832af6d4"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-09 02:16:36"
  condition:
    hash.sha256(0, filesize) == "4f3179dce42f5c010b80304931d67fca6f5fcccbdd916b51785bc43a832af6d4"
}
```

### Sample 38: `2c24769688bb6658`

| Field | Value |
|---|---|
| SHA-256 | `2c24769688bb6658599eed56478b3320d32d79a55da0da144079c146b7ea82d4` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm5` |
| File type | `elf` |
| First seen | `2026-10-09 01:51:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a0faa929ff4b741a8b04552eea48d61` |
| SHA-1 | `d66e64357d0e5dde6f497817b3fd7978d8a2d4cc` |
| SHA-256 | `2c24769688bb6658599eed56478b3320d32d79a55da0da144079c146b7ea82d4` |
| SHA3-384 | `ea5851be0cf2fede0841e527e9927cc7136cc9b55a7b0015674b854802544956f13cbf7fe4cd6bf998a42ab5d90187b4` |
| TLSH | `T17723B5D2BC83A95FC5D017BBEA8EC6893326B7D8D2DE7313C8115E5077CA2460D27A60` |
| TELFHASH | `t11ce0ab00fd3d4f1889e3aa70ecac47a09512222390b64b10cfa0cae0883f259e70cd6f` |
| SSDEEP | `768:Yi/OQDpoeeseAzo0yEcaycowczxc8EE6clQZa5mwYss6zvRmVhECGJayFrG:vashUrMaS5uliZw1GudgydG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_2c247696
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c24769688bb6658599eed56478b3320d32d79a55da0da144079c146b7ea82d4"
    family = "Mirai"
    file_name = "vcimanagement.arm5"
    file_type = "elf"
    first_seen = "2026-10-09 01:51:45"
  condition:
    hash.sha256(0, filesize) == "2c24769688bb6658599eed56478b3320d32d79a55da0da144079c146b7ea82d4"
}
```

### Sample 39: `01ec79ca328f90e0`

| Field | Value |
|---|---|
| SHA-256 | `01ec79ca328f90e03dd0c9ab0c115bacc279fa5eccea4cc03e4676dc9da78399` |
| Family label | `RemusStealer` |
| File name | `Bootrsraptler_42.2.63286.exe` |
| File type | `exe` |
| First seen | `2026-10-09 01:50:30` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e4e02fb56c5d5f6b825b83f78543b45` |
| SHA-1 | `7b8bf5e97e85caa5ef9889b78d6a72ea476d242a` |
| SHA-256 | `01ec79ca328f90e03dd0c9ab0c115bacc279fa5eccea4cc03e4676dc9da78399` |
| SHA3-384 | `f676b988178496dfc0e187dbf954943fc71b6765e6afa11b2c0d2134cd8c13ec55c1c0bfb985aa0d6d97ebf4962801c9` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1B586D407234C40DCD8ABEF71C5B0566461B03DAE52353B6F8EE56E642F1A3586BEDB02` |
| SSDEEP | `49152:xlEsII1cUvsVuAzM+bNQi6LFqWnJIeqpjsq1hs6Bheu:t1cqhWFWqIu` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_039_01ec79ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ec79ca328f90e03dd0c9ab0c115bacc279fa5eccea4cc03e4676dc9da78399"
    family = "RemusStealer"
    file_name = "Bootrsraptler_42.2.63286.exe"
    file_type = "exe"
    first_seen = "2026-10-09 01:50:30"
  condition:
    hash.sha256(0, filesize) == "01ec79ca328f90e03dd0c9ab0c115bacc279fa5eccea4cc03e4676dc9da78399"
}
```

### Sample 40: `61fba4eb0df49bb5`

| Field | Value |
|---|---|
| SHA-256 | `61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b` |
| Family label | `Mirai` |
| File name | `61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b.elf` |
| File type | `elf` |
| First seen | `2026-10-09 01:45:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a28b265da1d76b6d1b308851e5de17df` |
| SHA-1 | `95a60f15b7c7b37298d3825fbf32753cc1d1d872` |
| SHA-256 | `61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b` |
| SHA3-384 | `8001df54dd934e3fc1b992ff743bd7475549367f7efda9b642c3ca99913cf0b1e2dfbe0055b5ae2afa0eabf8e102f34f` |
| TLSH | `T11CC31A89FC808B11D5D525BAFE1E518D33534BBCE3FA7113DE149B2A678A86B0E3B501` |
| SSDEEP | `3072:xxFRA9/leVsHQGE+QsDpZtGe70cjEbnaLnSCLoCF0QPe8zILlW5VC:kNQcDDpO00c0naLnSCLo+0f8MLN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_61fba4eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b"
    family = "Mirai"
    file_name = "61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b.elf"
    file_type = "elf"
    first_seen = "2026-10-09 01:45:47"
  condition:
    hash.sha256(0, filesize) == "61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b"
}
```

### Sample 41: `2fb5a098919a7e2c`

| Field | Value |
|---|---|
| SHA-256 | `2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7` |
| Family label | `Mirai` |
| File name | `2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7.elf` |
| File type | `elf` |
| First seen | `2026-10-09 01:45:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f59ac98c07d26813ad7995523185a94d` |
| SHA-1 | `f808e2273f44be1bc4da49180b84508655fd8108` |
| SHA-256 | `2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7` |
| SHA3-384 | `46a9e3fc0fcc2163a8cbf290423769b69a3248029155d2f2b2ced639d95b26d7237b3721bc91f554c75410aa9c31454d` |
| TLSH | `T1E2B31A86BC81C612C5E261B7FB1F92CD372643A8D3E67113DD18AB29774B8670E3B251` |
| TELFHASH | `t10e71ed2afb581f9c6be8046442ef5017daad34de4b221442ce6dab4f5b52dc2b03e812` |
| SSDEEP | `1536:grMr91a+tpt1jOa3wem3SrQ++zGP9kt9J8aCXddJ3kUFvTfx8xRc:grKMopjjwL3gQNcet9J8rLdTfxV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_2fb5a098
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7"
    family = "Mirai"
    file_name = "2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7.elf"
    file_type = "elf"
    first_seen = "2026-10-09 01:45:40"
  condition:
    hash.sha256(0, filesize) == "2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7"
}
```

### Sample 42: `639dd1de39bccb79`

| Field | Value |
|---|---|
| SHA-256 | `639dd1de39bccb7984585c453b482145a6ad7353007a8ea3cdbf01a65076e151` |
| Family label | `unknown` |
| File name | `Services.apk` |
| File type | `apk` |
| First seen | `2026-10-09 01:43:09` |
| Reporter | `adliwahid` |
| Tags | `signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fa054f6ba0eb084c07c83f1eb947096` |
| SHA-1 | `9546530f12f70ce5783b4e3cb5df68faae80e1bf` |
| SHA-256 | `639dd1de39bccb7984585c453b482145a6ad7353007a8ea3cdbf01a65076e151` |
| SHA3-384 | `f646475a6041f84d097cab580d23826585932a03f5df6906d20ee211673796f315b0423949e4b09aa6398d6acdc1ca64` |
| TLSH | `T1D38533814B281C87EE862DB8E8AB106521315C7745540F6FDB0AB76EB3DDFF9650CAE0` |
| SSDEEP | `49152:zZk8d/gHUXbh+R3vi0YuCBfjW2UYEFxfN54KL:zZk4/gHUXc3vi5BQYEH4Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_639dd1de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "639dd1de39bccb7984585c453b482145a6ad7353007a8ea3cdbf01a65076e151"
    family = "unknown"
    file_name = "Services.apk"
    file_type = "apk"
    first_seen = "2026-10-09 01:43:09"
  condition:
    hash.sha256(0, filesize) == "639dd1de39bccb7984585c453b482145a6ad7353007a8ea3cdbf01a65076e151"
}
```

### Sample 43: `c55e5baca2162ac5`

| Field | Value |
|---|---|
| SHA-256 | `c55e5baca2162ac54e70de00a3d25b8a9a54617965eb36d1d7080f7d2e0460d7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-09 01:41:47` |
| Reporter | `Bitsight` |
| Tags | `BB3.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac27ed9369c79339759263f46f1535e6` |
| SHA-1 | `0777914900b56dc42dfcbdaca092983d7be6077b` |
| SHA-256 | `c55e5baca2162ac54e70de00a3d25b8a9a54617965eb36d1d7080f7d2e0460d7` |
| SHA3-384 | `ec8b37421d350c93b583dc2efd074b84e26a3b8797457c5c5953e58b81047879de9f83e337d31f553d834a3215803c8a` |
| IMPHASH | `0915a35a36d8f6dad250ca7065e4d9ab` |
| TLSH | `T1878612263ED844ACD0DB94F455160507D2F9B012037B9BDFD6E109BB8FAAAF46E3A710` |
| SSDEEP | `196608:xChuBGmVGvizOtZg4xk5ipVxrLpfCYuVeXjXMrSoaQ:IQBrGGf4mehaVyM+PQ` |
| ICON-DHASH | `a65c74d4e47c8c26` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_c55e5bac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c55e5baca2162ac54e70de00a3d25b8a9a54617965eb36d1d7080f7d2e0460d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-09 01:41:47"
  condition:
    hash.sha256(0, filesize) == "c55e5baca2162ac54e70de00a3d25b8a9a54617965eb36d1d7080f7d2e0460d7"
}
```

### Sample 44: `99410c62ffbaf607`

| Field | Value |
|---|---|
| SHA-256 | `99410c62ffbaf607a62c2badf53d84ae450cb187f3b211fb8b89dd640c687a4e` |
| Family label | `unknown` |
| File name | `macho_99410c62ffba.bin` |
| File type | `macho` |
| First seen | `2026-10-09 01:30:03` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93c40fa2bf3f5c8162ebb0dd9a0194a8` |
| SHA-1 | `c3966d289ccafeaba3d14921ad55d97e99294c36` |
| SHA-256 | `99410c62ffbaf607a62c2badf53d84ae450cb187f3b211fb8b89dd640c687a4e` |
| SHA3-384 | `1bc871a46841015d0111fd162976dd9a0378e7f64618ebe2b9a599ccca7ac8f57c166b574f2249780c62cb5845f3d896` |
| TLSH | `T1C9450240DFA689A6F4CCDB301E2B0F33DE2172A086C511DE62621B895D377D3F56B269` |
| SSDEEP | `24576:Ah//Uihf2BLLtSYL5F8WB3IQLpOnVjtSWxV:2HUciL5CmIS+xV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_99410c62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99410c62ffbaf607a62c2badf53d84ae450cb187f3b211fb8b89dd640c687a4e"
    family = "unknown"
    file_name = "macho_99410c62ffba.bin"
    file_type = "macho"
    first_seen = "2026-10-09 01:30:03"
  condition:
    hash.sha256(0, filesize) == "99410c62ffbaf607a62c2badf53d84ae450cb187f3b211fb8b89dd640c687a4e"
}
```

### Sample 45: `5529d9ff7d84cb7a`

| Field | Value |
|---|---|
| SHA-256 | `5529d9ff7d84cb7a8db1f2d0ef9d50ff03488a7469d4ff156276521e30dd2d9d` |
| Family label | `Mirai` |
| File name | `morte.sh4` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50dabd72140382dd9838fd06998671f2` |
| SHA-1 | `4d21f94f8c5d31d985e724e5007361023d94d077` |
| SHA-256 | `5529d9ff7d84cb7a8db1f2d0ef9d50ff03488a7469d4ff156276521e30dd2d9d` |
| SHA3-384 | `e88287ccc70c04eaab746ec8bc9f8babb7a4aad7b826a1bcf3bc7313096fdd465c021820ebf6c0817c94bd04b951e3a8` |
| TLSH | `T12B339E73C42E7DD4E65982B8B9204B785B63D40296837EF59A4AC6974083FECF5093F2` |
| SSDEEP | `768:7/zz/6Ozr+52iMka8wtAi7I53qlDIBPQ37X5QoDXeB74eXC6Aoa4CC0wE:7/v6a61a8wtA1qIi3zmQXsXPbCC0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_5529d9ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5529d9ff7d84cb7a8db1f2d0ef9d50ff03488a7469d4ff156276521e30dd2d9d"
    family = "Mirai"
    file_name = "morte.sh4"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:36"
  condition:
    hash.sha256(0, filesize) == "5529d9ff7d84cb7a8db1f2d0ef9d50ff03488a7469d4ff156276521e30dd2d9d"
}
```

### Sample 46: `77840f54cad6ff1b`

| Field | Value |
|---|---|
| SHA-256 | `77840f54cad6ff1badd14a0301f4b508bd657059a55bd83adb9e5c9116fb060e` |
| Family label | `Mirai` |
| File name | `mirai.mips` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b4bc5de6a9eb12e175be53664297cc3` |
| SHA-1 | `7318d17d31fabc5dc227db14fc47f1f3ab197301` |
| SHA-256 | `77840f54cad6ff1badd14a0301f4b508bd657059a55bd83adb9e5c9116fb060e` |
| SHA3-384 | `e89b3eddc75894f57ff34fc8aa87526b7131ecb146852136735375b5582bf8f08680976716226cf6ec4b3bdf79fb6d1f` |
| TLSH | `T1BA73840E2E619FBCFBAD863587B34E209248339226E1D545D19CFA011E7034E746FBA9` |
| TELFHASH | `t13d014f58483c13f083815d9e6becff75e4a140ef99261f37ce00e99be6215429d01c2c` |
| SSDEEP | `1536:G4Z8LUay6+vl/R1KIdysUmR9EiYHXw7d11VqkkFjDETni:B6ry6+vdGIdysUKH11VzkNDIni` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_77840f54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77840f54cad6ff1badd14a0301f4b508bd657059a55bd83adb9e5c9116fb060e"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:33"
  condition:
    hash.sha256(0, filesize) == "77840f54cad6ff1badd14a0301f4b508bd657059a55bd83adb9e5c9116fb060e"
}
```

### Sample 47: `91fbcdb39cc834ce`

| Field | Value |
|---|---|
| SHA-256 | `91fbcdb39cc834cebb0898e90b0ef8eebaffef9ee24c8c04ab1b4c3fb94d5bbc` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fd236e9b9e9a0e657598512095ec8f0` |
| SHA-1 | `cc87b331e13d643a46262c463eaaeadc7b426b30` |
| SHA-256 | `91fbcdb39cc834cebb0898e90b0ef8eebaffef9ee24c8c04ab1b4c3fb94d5bbc` |
| SHA3-384 | `80521b32c5c2050301208dab0ab691ad55acb0ff25642d2e6e9fc555ccf1b3d710172cb9c1156c054d2ac58a1e4066eb` |
| TLSH | `T1D1436B0272280A47E1525FF4393F27E083FEE99121F4F5892A0FDA464276F77158AF99` |
| SSDEEP | `768:UYfPffzWfQuxL/j4oy9RTcEYyrm/EkCx7qn5yQCGEgvM3f/3iRtZAIsYsZJxxEH:UUSfVj4oKJryE32yQTJvM3fqJDsXxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_91fbcdb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91fbcdb39cc834cebb0898e90b0ef8eebaffef9ee24c8c04ab1b4c3fb94d5bbc"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:30"
  condition:
    hash.sha256(0, filesize) == "91fbcdb39cc834cebb0898e90b0ef8eebaffef9ee24c8c04ab1b4c3fb94d5bbc"
}
```

### Sample 48: `4df9902f81140d91`

| Field | Value |
|---|---|
| SHA-256 | `4df9902f81140d914a156af18f77534bcc4d1ad577ca91af97dfafb961aa72b4` |
| Family label | `Mirai` |
| File name | `morte.m68k` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3b5333230ace877f48e6ebcc5df038d` |
| SHA-1 | `9f23d591cd77f15cbda9bef3a6dff255e2149b42` |
| SHA-256 | `4df9902f81140d914a156af18f77534bcc4d1ad577ca91af97dfafb961aa72b4` |
| SHA3-384 | `866ce33fee194016375b092bde1f67392aaa2244b67b632fb30e8b0f23ec00475c3fb301a8d5dec0f12cb55825f311ad` |
| TLSH | `T198435DD6B800DE7CF94BEB7A80260A09FA35721154A30F27B267FD93AD721564C6BD07` |
| SSDEEP | `1536:TtCdFUWySs6CANPo75G4jsCktnSygjVQstg8x:as7ANmGvLJuQqD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_4df9902f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4df9902f81140d914a156af18f77534bcc4d1ad577ca91af97dfafb961aa72b4"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:27"
  condition:
    hash.sha256(0, filesize) == "4df9902f81140d914a156af18f77534bcc4d1ad577ca91af97dfafb961aa72b4"
}
```

### Sample 49: `7a8de9672d3697af`

| Field | Value |
|---|---|
| SHA-256 | `7a8de9672d3697af7c6d30b286764b2790e8c448d0b05ed3d6fa5b6c6d8f8525` |
| Family label | `unknown` |
| File name | `rathole-v048-armv7` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0adb0345fdac2e67839766e143c34d5` |
| SHA-1 | `548dd7a0d03593fc03c14c6776ba0c3f8ba6a815` |
| SHA-256 | `7a8de9672d3697af7c6d30b286764b2790e8c448d0b05ed3d6fa5b6c6d8f8525` |
| SHA3-384 | `d7ff1ff7fdfde1ea68d58e807161480e58bd8fe0d1fd375fd28998aa5d534d4c12a4ebb5fd92bfc7fd3c5c188d9ddcf1` |
| TLSH | `T1A4166C9AFD429E42C8D825FAF96A81987303C7BCC3DAB2139B018735798F4A40F79755` |
| TELFHASH | `t1fe31045af7b41d8ca7e64488c3a6c02e5bf835cd1b0031a78a48671f6a93dc3b11ec23` |
| SSDEEP | `49152:E6xwYCCRHLdfAdfavbQkb6TYCZNUr8J8Osq5bFPDuBg:p8cLd0favb/b6VZNU4eOsq5xuG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_7a8de967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a8de9672d3697af7c6d30b286764b2790e8c448d0b05ed3d6fa5b6c6d8f8525"
    family = "unknown"
    file_name = "rathole-v048-armv7"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:25"
  condition:
    hash.sha256(0, filesize) == "7a8de9672d3697af7c6d30b286764b2790e8c448d0b05ed3d6fa5b6c6d8f8525"
}
```

### Sample 50: `cc0ab18f186304db`

| Field | Value |
|---|---|
| SHA-256 | `cc0ab18f186304dbb698dc167a9fd4e2582efa487e83eeed40b6a972cd141b2a` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `001cde7ac1bf5ff2f210d1e968097094` |
| SHA-1 | `b20edf2ed93565f8a4bf31658095688031ac3ea2` |
| SHA-256 | `cc0ab18f186304dbb698dc167a9fd4e2582efa487e83eeed40b6a972cd141b2a` |
| SHA3-384 | `3a4adf05df320ae5c3afa6160581480b6ceb3315c55785023ac5ac44e80973cbc344f7c083a645f28ed211fa9b75fff6` |
| TLSH | `T1CD73931ABF650FF7E86FCC378AE91B45248D641A21993B7A7D34D418B24B24F49E3870` |
| SSDEEP | `1536:P2Vu+dSbFTBJRc4gRGUUpDVB8DuPSwteQHBD:uVu+dSbBBLgRGlpLeE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_cc0ab18f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc0ab18f186304dbb698dc167a9fd4e2582efa487e83eeed40b6a972cd141b2a"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:24"
  condition:
    hash.sha256(0, filesize) == "cc0ab18f186304dbb698dc167a9fd4e2582efa487e83eeed40b6a972cd141b2a"
}
```

### Sample 51: `793cfc2d1054179c`

| Field | Value |
|---|---|
| SHA-256 | `793cfc2d1054179c987a21dfe328a6419d37e362584b8083c2b91500f31f1fe7` |
| Family label | `Mirai` |
| File name | `morte.arc` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11d27d679df4176d63ecfed4039f7c27` |
| SHA-1 | `0ddea7378507a1cc0316d6fe0f949b3bc0af85ef` |
| SHA-256 | `793cfc2d1054179c987a21dfe328a6419d37e362584b8083c2b91500f31f1fe7` |
| SHA3-384 | `cae1d2baa6db874dedf56d5ea9281d7dd37e1640fc0014946b6e53e7f33033a8f83fc2aed2cda337d18acaf24335bd1c` |
| TLSH | `T15673840E2E619FBCFBAD863587B34E209248339226E1D545D19CFA011E7034E746FBA9` |
| TELFHASH | `t13d014f58483c13f083815d9e6becff75e4a140ef99261f37ce00e99be6215429d01c2c` |
| SSDEEP | `1536:G4Z8LUay6+vl/R1KIdysUmR9EiYHXw7d11VqkkFjDETCi:B6ry6+vdGIdysUKH11VzkNDICi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_793cfc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "793cfc2d1054179c987a21dfe328a6419d37e362584b8083c2b91500f31f1fe7"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:20"
  condition:
    hash.sha256(0, filesize) == "793cfc2d1054179c987a21dfe328a6419d37e362584b8083c2b91500f31f1fe7"
}
```

### Sample 52: `bff1a0106509646f`

| Field | Value |
|---|---|
| SHA-256 | `bff1a0106509646f73c8aa2be4372668291b2204ad9a5ca1a622d5f30941dc5b` |
| Family label | `Mirai` |
| File name | `morte.spc` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c968096ea5e801425ab18558e945e5e8` |
| SHA-1 | `bb7072da98ef0d862aa6ceba486b9b5a9669be65` |
| SHA-256 | `bff1a0106509646f73c8aa2be4372668291b2204ad9a5ca1a622d5f30941dc5b` |
| SHA3-384 | `4b635a9323911e5676de5bc5495b8b21c1f0870565700f46cd3ad4b6bcdab26093febd82407995b4f3d4421de35d7a78` |
| TLSH | `T15C534B22A8B92E13C0E5F57B22F78324B2F5170E24A8C66E7C760F8EFF1855065576B1` |
| SSDEEP | `768:o7TS61ooq9fg/po5FCIQboIVT+5JPdIei2py6WlxOO+hBCBFEI:gTS61tSfg/peC7boIVTIJPdId8hC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_bff1a010
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bff1a0106509646f73c8aa2be4372668291b2204ad9a5ca1a622d5f30941dc5b"
    family = "Mirai"
    file_name = "morte.spc"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:17"
  condition:
    hash.sha256(0, filesize) == "bff1a0106509646f73c8aa2be4372668291b2204ad9a5ca1a622d5f30941dc5b"
}
```

### Sample 53: `703d34a8d6a70eed`

| Field | Value |
|---|---|
| SHA-256 | `703d34a8d6a70eedbb3bd431fb90990bb4a9f0da873d0e9ed9941ce3ea4a5556` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9aded04ccc15bafafb2d84e745696c18` |
| SHA-1 | `fd73c4b1800487e79e250b337843a6f8a9dc3a04` |
| SHA-256 | `703d34a8d6a70eedbb3bd431fb90990bb4a9f0da873d0e9ed9941ce3ea4a5556` |
| SHA3-384 | `a0dae48b24e54476906887b91b78e5766fa7c1b1bed24ae10789e8a5d4a0a217a52bb903edb75e61f52997cac115b105` |
| TLSH | `T19663F75AB8918A01C5C513BAFE2E118D331753ACD3DFB2139E106F60778A96F0E7B952` |
| TELFHASH | `t194218b728ee909ecab81c389d1cb70299ddc31b86f25105eda5e3b4a52b35c67526024` |
| SSDEEP | `1536:2ZnCgeJ4lisAxQAz7mSSrt3B7nxczKqCY6Vyh2fGEsr2Fwi2LlIjiVRCCZWzy:dgXNAHmN1B1czKRVXfGEM2aRCCZWz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_703d34a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "703d34a8d6a70eedbb3bd431fb90990bb4a9f0da873d0e9ed9941ce3ea4a5556"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:14"
  condition:
    hash.sha256(0, filesize) == "703d34a8d6a70eedbb3bd431fb90990bb4a9f0da873d0e9ed9941ce3ea4a5556"
}
```

### Sample 54: `a2340ba1546cea74`

| Field | Value |
|---|---|
| SHA-256 | `a2340ba1546cea741ea17fb6d84a51e39cfde541838836f801833d6a99999bc6` |
| Family label | `Mirai` |
| File name | `mirai.x86` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe3d23e476d470ed2f5f3022ccea6635` |
| SHA-1 | `7d7abf17e5598431f2ac232eb01dd67b52452724` |
| SHA-256 | `a2340ba1546cea741ea17fb6d84a51e39cfde541838836f801833d6a99999bc6` |
| SHA3-384 | `8aa77a6677438534cf7463098aa62b2c26020aa31e6a90cefaed8a658d608d553e1eec0dbe941a888db0bfbe52472301` |
| TLSH | `T18C435BC5D563D9FCDC1015393077FF725676E93F1028EACBD7A8A932A982A02D80728D` |
| TELFHASH | `t16a1190fb2d7e0dd5f7d98840830e2f701939e63b29a0736005319a5422a3dd052fac7d` |
| SSDEEP | `1536:d6EwVWibZ6uzpNrmvFtWbFR7WCTZVZt+xc:QVWYZ6uzv4FKFR7WoZVZQq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_a2340ba1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2340ba1546cea741ea17fb6d84a51e39cfde541838836f801833d6a99999bc6"
    family = "Mirai"
    file_name = "mirai.x86"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:11"
  condition:
    hash.sha256(0, filesize) == "a2340ba1546cea741ea17fb6d84a51e39cfde541838836f801833d6a99999bc6"
}
```

### Sample 55: `f7dcabc1ecd5d8ce`

| Field | Value |
|---|---|
| SHA-256 | `f7dcabc1ecd5d8ce5f956488ce37563bcdd8a1d29c5d9b080377984e99edb9df` |
| Family label | `Mirai` |
| File name | `mirai.arm` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0fe82f6236ef3efa7ac4779580613a9` |
| SHA-1 | `15ae710ebfafdaa9b535910b94cbb1ad02f13eae` |
| SHA-256 | `f7dcabc1ecd5d8ce5f956488ce37563bcdd8a1d29c5d9b080377984e99edb9df` |
| SHA3-384 | `a93a9bdfead37c966eedb191c407dc55d43affc3a4c85716e765e221eedcd0c15e25b7c01729366e003634964be89d94` |
| TLSH | `T1CC531855BCE18A12CAD422B6FA2E418D332663E8D1DF3207DD216F1177CA82F0E7B556` |
| TELFHASH | `t1f2019c2682951eec77e4c385d25e6155d4d93ada370021ef996e935f41628c2741b049` |
| SSDEEP | `1536:hQXM23Z+J1A6jclE3Big0bVrL2yBCtt5K+Txt5:h6n+J1bjUlvYbK+Txz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_f7dcabc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7dcabc1ecd5d8ce5f956488ce37563bcdd8a1d29c5d9b080377984e99edb9df"
    family = "Mirai"
    file_name = "mirai.arm"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:08"
  condition:
    hash.sha256(0, filesize) == "f7dcabc1ecd5d8ce5f956488ce37563bcdd8a1d29c5d9b080377984e99edb9df"
}
```

### Sample 56: `cc41fea5a9b0a072`

| Field | Value |
|---|---|
| SHA-256 | `cc41fea5a9b0a072b9f0a36a7610a682acbae747ce65265d0f43ccb4b184d8d9` |
| Family label | `Mirai` |
| File name | `morte.arm5` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1b0e2eb0d2f59a5661127df5cffb953` |
| SHA-1 | `53c0c33ce511a76633620de7798a0a248407ccb4` |
| SHA-256 | `cc41fea5a9b0a072b9f0a36a7610a682acbae747ce65265d0f43ccb4b184d8d9` |
| SHA3-384 | `0e6ba63a8e062975e6c3b4a1646f32b2889e43338fa5d55357ee14b3e7056372ceeafe0b20dfec2d9cab4ce07d778086` |
| TLSH | `T16E332856BCD29A6AC5D423B6FA2E519E3321A3E8D1CF3217DC204B1437CA51E0DB7B91` |
| TELFHASH | `t120e02600bc658b5988d79a74ad9d07b49901621254668b14cf10d6f0983f458a308e5a` |
| SSDEEP | `1536:tfznFR4PmYm/Y0oBsDSLRb+eADL6rL2yBCNt5sYk:1rX4fm/Y02IkvkbsYk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_cc41fea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc41fea5a9b0a072b9f0a36a7610a682acbae747ce65265d0f43ccb4b184d8d9"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:05"
  condition:
    hash.sha256(0, filesize) == "cc41fea5a9b0a072b9f0a36a7610a682acbae747ce65265d0f43ccb4b184d8d9"
}
```

### Sample 57: `bbc090045e917125`

| Field | Value |
|---|---|
| SHA-256 | `bbc090045e9171257096fbeef4bb6696ea9787a4d38b44a1cb16adaf1202401f` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-10-09 01:26:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25f662b97f1edc78ed07a62475bfcd49` |
| SHA-1 | `4730bb861eacc7146710b8157f9650f358d4f995` |
| SHA-256 | `bbc090045e9171257096fbeef4bb6696ea9787a4d38b44a1cb16adaf1202401f` |
| SHA3-384 | `e4685fa48c7d2bdf7bad4d4c4f218b63d7b59e2cc56e8e74830f836581efc156cbd7d80ff61c02487b0d821bfbb5ab82` |
| TLSH | `T186435BC5D563D9FCDC1015393077FF725676E93F1028EACBD7A8A932A982A02D80728D` |
| TELFHASH | `t16a1190fb2d7e0dd5f7d98840830e2f701939e63b29a0736005319a5422a3dd052fac7d` |
| SSDEEP | `1536:d6EwVWibZ6uzpNrmvFtWbFR7WCTZVZt+xc:QVWYZ6uzv4FKFR7WoZVZQq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_bbc09004
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbc090045e9171257096fbeef4bb6696ea9787a4d38b44a1cb16adaf1202401f"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:02"
  condition:
    hash.sha256(0, filesize) == "bbc090045e9171257096fbeef4bb6696ea9787a4d38b44a1cb16adaf1202401f"
}
```

### Sample 58: `0419e82dd1b5ed80`

| Field | Value |
|---|---|
| SHA-256 | `0419e82dd1b5ed807540b2be4ba98789965b2e3a6011ab180a950dc5c58c7245` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-10-09 01:25:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da34af1c57fc6aac910820e864f92c2d` |
| SHA-1 | `8f0f270e33d6b0ba6a0ace260ea9dd43f74b3cdb` |
| SHA-256 | `0419e82dd1b5ed807540b2be4ba98789965b2e3a6011ab180a950dc5c58c7245` |
| SHA3-384 | `d06d9111febb2009fe0c867f427701e9eeb5f6615c58a9396b5fdc51ce4a8463fa272db30d73691e136cac18ed0980f9` |
| TLSH | `T189531855BCE18A12CAD422B6FA2E418D332663E8D1DF3207DD216F1177CA82F0E7B556` |
| TELFHASH | `t1f2019c2682951eec77e4c385d25e6155d4d93ada370021ef996e935f41628c2741b049` |
| SSDEEP | `1536:hQXM23Z+J1A6jclE3Big0bVrL2yBCtt5K+Txt5:h6n+J1bjUlvYbK+Txz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_0419e82d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0419e82dd1b5ed807540b2be4ba98789965b2e3a6011ab180a950dc5c58c7245"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-10-09 01:25:58"
  condition:
    hash.sha256(0, filesize) == "0419e82dd1b5ed807540b2be4ba98789965b2e3a6011ab180a950dc5c58c7245"
}
```

### Sample 59: `b10daff5af0638ea`

| Field | Value |
|---|---|
| SHA-256 | `b10daff5af0638ea0b47cc205fac28f3a8246cbd0dad1f22a11055c90e375fc3` |
| Family label | `Mirai` |
| File name | `mirai.arm5n` |
| File type | `elf` |
| First seen | `2026-10-09 01:25:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ad22cc59138d9eaf4feb63eff7cee9e` |
| SHA-1 | `a680abad3c7b702522d167c6b974ff3650e8477d` |
| SHA-256 | `b10daff5af0638ea0b47cc205fac28f3a8246cbd0dad1f22a11055c90e375fc3` |
| SHA3-384 | `6af967219737f581d18f998eb56e9ba7af7605ee4db94fe49f300d981bd29d6abca1e483f1e5a04c86037cea3bf927ae` |
| TLSH | `T184332856BCD29A6AC5D423B6FA2E519E3321A3E8D1CF3217DC204B1437CA51E0DB7B91` |
| TELFHASH | `t120e02600bc658b5988d79a74ad9d07b49901621254668b14cf10d6f0983f458a308e5a` |
| SSDEEP | `1536:tfznFR4PmYm/Y0oBsDSLRb+eADL6rL2yBCNt5sYV:1rX4fm/Y02IkvkbsYV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_b10daff5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b10daff5af0638ea0b47cc205fac28f3a8246cbd0dad1f22a11055c90e375fc3"
    family = "Mirai"
    file_name = "mirai.arm5n"
    file_type = "elf"
    first_seen = "2026-10-09 01:25:56"
  condition:
    hash.sha256(0, filesize) == "b10daff5af0638ea0b47cc205fac28f3a8246cbd0dad1f22a11055c90e375fc3"
}
```

### Sample 60: `5bdb3811a749e3af`

| Field | Value |
|---|---|
| SHA-256 | `5bdb3811a749e3af3e5832bdc778a45a43146ed66df97cfd715cbeadd872e379` |
| Family label | `unknown` |
| File name | `rathole-v048-armv7` |
| File type | `elf` |
| First seen | `2026-10-09 01:25:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43eebca4d9ad2ef67743901983ff0d7f` |
| SHA-1 | `9ccdf52c743708185b412e74b53fbf32556dc333` |
| SHA-256 | `5bdb3811a749e3af3e5832bdc778a45a43146ed66df97cfd715cbeadd872e379` |
| SHA3-384 | `4d5ac165f51d2f1d0abc4b67c354ab61944d9a27d6145b0bcca927e44c6f9c24450b4ca2a2cb6f22c06de13ea730b528` |
| TLSH | `T1207533755C8C8C0D6889247BF1BA9C1F7D69D39343BCF809E1AAAF5FD5B85389083819` |
| TELFHASH | `t1b990024248d0c19b15150fe5cc9435c51506a315860970108157c0435c1107d9c93855` |
| SSDEEP | `24576:IamXGQJzETYWGn/fWxX0CbhGTPwtHPukSxhPH5RCo2commvWZs2BLeeE2XBJ9JXS:IvWQJIcWcMX0C9GTIZPuzhPH5D2co5Oy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_5bdb3811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bdb3811a749e3af3e5832bdc778a45a43146ed66df97cfd715cbeadd872e379"
    family = "unknown"
    file_name = "rathole-v048-armv7"
    file_type = "elf"
    first_seen = "2026-10-09 01:25:52"
  condition:
    hash.sha256(0, filesize) == "5bdb3811a749e3af3e5832bdc778a45a43146ed66df97cfd715cbeadd872e379"
}
```

### Sample 61: `f12b4f28fa18b2cc`

| Field | Value |
|---|---|
| SHA-256 | `f12b4f28fa18b2cc0291cc8a146ae9e4ee0c772adf06cdda0b45fe9eb12dc3f3` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-09 01:12:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e29ee8854afa786c9f1f738735f464b` |
| SHA-1 | `8c89a2952ef84cde2a75abce1f9fea2631ae4989` |
| SHA-256 | `f12b4f28fa18b2cc0291cc8a146ae9e4ee0c772adf06cdda0b45fe9eb12dc3f3` |
| SHA3-384 | `a702755b7877dbc8497eaf06689d563c488d3f04c12ba2981f447a780469695539ba0df700345282923548d4c5a00826` |
| TLSH | `T190545B02F5A2C6F0F35601B441AEEB2F8F215815A4B3DB53EFC42D26E463964322B779` |
| TELFHASH | `t17a51c71a7b744ef2f3e1a8f022c3542738fe0d1baadb3dd41a805627dc90642447e959` |
| SSDEEP | `6144:0gcXOo6KMMUn7UyWJMJ7wMPd06cXGgO2inje6gu:MXOxjJMMV06cWgp6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_f12b4f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12b4f28fa18b2cc0291cc8a146ae9e4ee0c772adf06cdda0b45fe9eb12dc3f3"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-09 01:12:15"
  condition:
    hash.sha256(0, filesize) == "f12b4f28fa18b2cc0291cc8a146ae9e4ee0c772adf06cdda0b45fe9eb12dc3f3"
}
```

### Sample 62: `aa684c1bf96f4c4a`

| Field | Value |
|---|---|
| SHA-256 | `aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3` |
| Family label | `Mirai` |
| File name | `aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3.elf` |
| File type | `elf` |
| First seen | `2026-10-09 01:05:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a7869f5334afb63737d26f3770b4284` |
| SHA-1 | `d9a3e975cb75fa1ee52a44b05b04a20062e6b40f` |
| SHA-256 | `aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3` |
| SHA3-384 | `cb160bfab53f2b6cf7e17a86ec184e10584693ce5eee3ba5beaa0df93f7c7a966538b0a23bcf7f383654bb8470c5818f` |
| TLSH | `T1D4B3198ABC84C602C5E161B6FB1F92CD376643A8D3E67113DD18AF29774B8670E3B641` |
| TELFHASH | `t18cf07826cf844ddcb2e444a950aa7706021c3a852f61498666fcc99f8635a96b03985c` |
| SSDEEP | `1536:YhGE+t/adgcKW1MpCXTO+pMDmFPtOTJOFRJKlQvunu1CH2fx8xRQ:YP+9UgC1BDO+iDaFOTJOFpviL2fx5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_aa684c1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3"
    family = "Mirai"
    file_name = "aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3.elf"
    file_type = "elf"
    first_seen = "2026-10-09 01:05:41"
  condition:
    hash.sha256(0, filesize) == "aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3"
}
```

### Sample 63: `3800a41b441e6080`

| Field | Value |
|---|---|
| SHA-256 | `3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d` |
| Family label | `Vidar` |
| File name | `3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d.exe` |
| File type | `exe` |
| First seen | `2026-10-09 00:58:56` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3064c11606319b47a0e30edd4cac21e3` |
| SHA-1 | `d12f0f5c10536e8ddb74a7dcc5422c32e4639384` |
| SHA-256 | `3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d` |
| SHA3-384 | `df304af6b4654d6b9d7c42bf4f1bb972fbf120129de8318f8189c70ac96f177e5cb1356760b206ce6eb9144cd8810ef3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15466C85871C410EDDA8E837608F45DBE27B21DBF1613A68A0799BAE12F13BD65F20D4C` |
| SSDEEP | `24576:FUUi3UOPwBqpMyHFqMPypAbVCOWS1qegyHWw37xiIqFOz1:FniEOPcqpPHsMPy1w3Mw` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_063_3800a41b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d"
    family = "Vidar"
    file_name = "3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d.exe"
    file_type = "exe"
    first_seen = "2026-10-09 00:58:56"
  condition:
    hash.sha256(0, filesize) == "3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d"
}
```

### Sample 64: `aecef9efaad031a5`

| Field | Value |
|---|---|
| SHA-256 | `aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995` |
| Family label | `Vidar` |
| File name | `aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995.exe` |
| File type | `exe` |
| First seen | `2026-10-09 00:58:40` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a48bdee475d7b4b1fb298a7a0477a1a8` |
| SHA-1 | `214b94da576ed344820222edd216f333a4d02b37` |
| SHA-256 | `aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995` |
| SHA3-384 | `f28885aa19b6467966efb8d7ab9d961945326bac25f8834b6e6e2c4c0a3080a61fb25696fbcfa6a5bb4d56655b524466` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10486E95971C410EDCA8EC37608F45DBE23B22DBB1623A68A0755BBA13F13BD65F24D48` |
| SSDEEP | `24576:pD7EpJDrf6qe4M0p/rgIxUfvjXYzMD+TzmF3kp1hDfym+wLYhesFWu7ZiER:pkpJDD6qtpT2TPwLiDV` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_064_aecef9ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995"
    family = "Vidar"
    file_name = "aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995.exe"
    file_type = "exe"
    first_seen = "2026-10-09 00:58:40"
  condition:
    hash.sha256(0, filesize) == "aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995"
}
```

### Sample 65: `ba0a5a40fac99dcb`

| Field | Value |
|---|---|
| SHA-256 | `ba0a5a40fac99dcbb4fd902650d3049c033fb52b31c2b0cd5e8276345bb49b7c` |
| Family label | `unknown` |
| File name | `Tezzyhub.exe` |
| File type | `exe` |
| First seen | `2026-10-09 00:58:35` |
| Reporter | `NyxIndius` |
| Tags | `exe, Wiper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2023781fc683a99bffe403001d4c73a3` |
| SHA-1 | `6917620fd249db47fd1354161d81a8e8e29feac0` |
| SHA-256 | `ba0a5a40fac99dcbb4fd902650d3049c033fb52b31c2b0cd5e8276345bb49b7c` |
| SHA3-384 | `13c9a392542af3566f7b147cd3fb70e6bea2459da43ed2c47bc6bc3dc024e19b814873433aa3b6edd8c51782238b761d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BA32C61DB3E88924D2BE4B3618B7D21087B0F4138E2BCB1E1DE958FD2D277146966F91` |
| SSDEEP | `192:XyUdQ0oWELaakSRoCG9QuvOP7X0n0E49w6Ijnj3th:z9oWE3voCGKuiX+0j93m5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_ba0a5a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba0a5a40fac99dcbb4fd902650d3049c033fb52b31c2b0cd5e8276345bb49b7c"
    family = "unknown"
    file_name = "Tezzyhub.exe"
    file_type = "exe"
    first_seen = "2026-10-09 00:58:35"
  condition:
    hash.sha256(0, filesize) == "ba0a5a40fac99dcbb4fd902650d3049c033fb52b31c2b0cd5e8276345bb49b7c"
}
```

### Sample 66: `5e3f5df112be21b0`

| Field | Value |
|---|---|
| SHA-256 | `5e3f5df112be21b05e0f50da7d6868fd62d843da044cb1993c314dde69ad19e2` |
| Family label | `unknown` |
| File name | `klogd-164-v5te` |
| File type | `elf` |
| First seen | `2026-10-09 00:57:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebd63299adb9b76fd28de78a3682dd91` |
| SHA-1 | `57b8e0ea11ea90efee6f62cf83b12993823ee484` |
| SHA-256 | `5e3f5df112be21b05e0f50da7d6868fd62d843da044cb1993c314dde69ad19e2` |
| SHA3-384 | `a441dd4b223e8c86456e5647773e86ee59c3e8e2c72c31311b4eae3f70eed9e5f0fc9b93d008dab356c7906e7731ba36` |
| TLSH | `T1C2C52AABFC429E42C4C425B6F96EC2D8334783F8C3D6B2029E05C635799F59A0E79B15` |
| TELFHASH | `t1edc09208bb1090dd3ac11389c4b732abd1ee14e7630018e8d32abd6f5e01cb83956e33` |
| SSDEEP | `24576:T7UFkdHTMOGyoHJOD/iUhNJKBqtX3Xh/PL517C0DBi1uZQn652EPAZTXMXH1EOau:Upit//j5Pigky0Gd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_5e3f5df1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e3f5df112be21b05e0f50da7d6868fd62d843da044cb1993c314dde69ad19e2"
    family = "unknown"
    file_name = "klogd-164-v5te"
    file_type = "elf"
    first_seen = "2026-10-09 00:57:32"
  condition:
    hash.sha256(0, filesize) == "5e3f5df112be21b05e0f50da7d6868fd62d843da044cb1993c314dde69ad19e2"
}
```

### Sample 67: `4d90b19f8a3c2241`

| Field | Value |
|---|---|
| SHA-256 | `4d90b19f8a3c224131db8f6e96a99a970b044c6392a4654ccd82fa8bce4adcb9` |
| Family label | `RemcosRAT` |
| File name | `Abu Dhabi Police GHQ Ticket and Evidence of Offence .vbs` |
| File type | `vbs` |
| First seen | `2026-10-09 00:52:38` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40ebeef9b901cadd0f721ed9d85ea98d` |
| SHA-1 | `557e03a85cc1806464e43fe26dae803a858d8fea` |
| SHA-256 | `4d90b19f8a3c224131db8f6e96a99a970b044c6392a4654ccd82fa8bce4adcb9` |
| SHA3-384 | `3f9067d1559950c522bb58443b82c6a71f9cbf77655d9113857cfb3e8b4c531681e79aa7f92554c3e163c6701de250a8` |
| TLSH | `T10B636D21EE3406968F0317E9FC590A66CD7DC235532254B4FEED630D50126ACE3BE2BA` |
| SSDEEP | `1536:JGUT5JaE0O/vQLB2zoYJhA88eHey2dwcLj399:7QLO/vQaVJj5ey2dwcLL` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_067_4d90b19f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d90b19f8a3c224131db8f6e96a99a970b044c6392a4654ccd82fa8bce4adcb9"
    family = "RemcosRAT"
    file_name = "Abu Dhabi Police GHQ Ticket and Evidence of Offence .vbs"
    file_type = "vbs"
    first_seen = "2026-10-09 00:52:38"
  condition:
    hash.sha256(0, filesize) == "4d90b19f8a3c224131db8f6e96a99a970b044c6392a4654ccd82fa8bce4adcb9"
}
```

### Sample 68: `b077215af833ac80`

| Field | Value |
|---|---|
| SHA-256 | `b077215af833ac80e92a57f8ab2613217e87f7f7aa9ed16ce9497f08de54d5f0` |
| Family label | `AsyncRAT` |
| File name | `D3MANDA.RAD-2026-107067-00..js` |
| File type | `js` |
| First seen | `2026-10-09 00:48:20` |
| Reporter | `cypherpunk472` |
| Tags | `AsyncRAT, js, xworm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c10522964bea89d360d438b975c64cd` |
| SHA-1 | `50371be5ba9c3d126e3d472c8edd1992f1d04f8e` |
| SHA-256 | `b077215af833ac80e92a57f8ab2613217e87f7f7aa9ed16ce9497f08de54d5f0` |
| SHA3-384 | `8d34b2bccf0ed22093380f2429bb49ba6c8f9b0fc0d0583a1621f3a9ece5b06bf1499ebbddf1bee9db5fb194adb78c46` |
| TLSH | `T115C62348035A123C72AD95E9946E0012E4FAEBC6DD3C625688BBE5DFF41FC40597A33B` |
| SSDEEP | `98304:PAaEaJsFas7UiaqFH4TV+ppYn9rMPCszpMT0nQiwB6ZA9MoKSaO:P8s4pq8pynl+CXT0ID9v3aO` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_068_b077215a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b077215af833ac80e92a57f8ab2613217e87f7f7aa9ed16ce9497f08de54d5f0"
    family = "AsyncRAT"
    file_name = "D3MANDA.RAD-2026-107067-00..js"
    file_type = "js"
    first_seen = "2026-10-09 00:48:20"
  condition:
    hash.sha256(0, filesize) == "b077215af833ac80e92a57f8ab2613217e87f7f7aa9ed16ce9497f08de54d5f0"
}
```

### Sample 69: `4e2d3b193a9bfb9f`

| Field | Value |
|---|---|
| SHA-256 | `4e2d3b193a9bfb9f3a369a251a1b722450fa13d8fc193d3c872ebf1062783fde` |
| Family label | `Formbook` |
| File name | `PO50A-051141161_ORDER_DETAIL.com` |
| File type | `exe` |
| First seen | `2026-10-09 00:23:24` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f1d42cb6725d8194145cff1d3683634` |
| SHA-1 | `d9c19f966ff9cadfb515586114754d7ddf2381e7` |
| SHA-256 | `4e2d3b193a9bfb9f3a369a251a1b722450fa13d8fc193d3c872ebf1062783fde` |
| SHA3-384 | `f85421e911e655fcc006cfc355f9391aa5a195a7226d1ea0f6e4fe98429cc9247d250a080117aa36af8c7e788f035ea7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12C15D04432ABEC03D4724BB009E1D37087B96F95E521E3574FE66ED77A26BC26484B83` |
| SSDEEP | `12288:WlQE+W8AQEUd6SZzpX8zmt/C7Ra3r40wChB94Ux5eq8sewIk0YPgHKf6sk+KDXeL:4QTYKX8L7IsMxd8eCYPNfD4z/93` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_069_4e2d3b19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e2d3b193a9bfb9f3a369a251a1b722450fa13d8fc193d3c872ebf1062783fde"
    family = "Formbook"
    file_name = "PO50A-051141161_ORDER_DETAIL.com"
    file_type = "exe"
    first_seen = "2026-10-09 00:23:24"
  condition:
    hash.sha256(0, filesize) == "4e2d3b193a9bfb9f3a369a251a1b722450fa13d8fc193d3c872ebf1062783fde"
}
```

### Sample 70: `6afc6978ec9752ab`

| Field | Value |
|---|---|
| SHA-256 | `6afc6978ec9752ab4558a6c9cb1b62124619fe2bec6f727b09309f7a323d0eee` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-10-09 00:17:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90122868f1cb205ebf5dc41ced6621fd` |
| SHA-1 | `31a87a452c2f668d96ac1a569e8cf44ad10c958b` |
| SHA-256 | `6afc6978ec9752ab4558a6c9cb1b62124619fe2bec6f727b09309f7a323d0eee` |
| SHA3-384 | `076a2861c58196fda252e674a0291e269e950ea144168ec9343301a959849cb72a319aa40cbacf5efc6c3a230d0479ce` |
| TLSH | `T12C259D41F7F50166E68092358662D7A07A13D7A628E4020FCF618EEBEF531B91F85CF6` |
| SSDEEP | `12288:aW0t6mGDeeymHF7N84jaCnzPtls9oCZPjaGUy3qs3lB0S45xdbBaw5gP9ZYJS:aW7yeyoBNpzPiomnUsB5YPtiA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_6afc6978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6afc6978ec9752ab4558a6c9cb1b62124619fe2bec6f727b09309f7a323d0eee"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-09 00:17:17"
  condition:
    hash.sha256(0, filesize) == "6afc6978ec9752ab4558a6c9cb1b62124619fe2bec6f727b09309f7a323d0eee"
}
```

### Sample 71: `9d7bb13d6ceee4ed`

| Field | Value |
|---|---|
| SHA-256 | `9d7bb13d6ceee4ed10a90bd9c260e926613ee05bd5949b71051f40d38883f714` |
| Family label | `SilentNet` |
| File name | `KryptonClient.jar` |
| File type | `jar` |
| First seen | `2026-10-09 00:12:34` |
| Reporter | `NyxIndius` |
| Tags | `jar, python, silentnet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53fbf1c0455cc842f31aadb8d36af84d` |
| SHA-1 | `6b5944d066040e96fbf8f15c82d4ded6000be237` |
| SHA-256 | `9d7bb13d6ceee4ed10a90bd9c260e926613ee05bd5949b71051f40d38883f714` |
| SHA3-384 | `71bbc5008333328affd6a5b8d5b3278d1c36f51eedb2dc5b4c4f68a3202c060caca7c7ec3241397a7e6b40098c2cbf4a` |
| TLSH | `T1BF1733F2876B15E8ABE318141F42D048D7DE33ABD927402D48B39F7C9AD9D41CA50AF6` |
| SSDEEP | `393216:sQHrITeAWGR0gQcJplg5kGcSCtXvbdbQvsilxrSt:DIbJQcJpdDtXvbdUllFi` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_071_9d7bb13d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d7bb13d6ceee4ed10a90bd9c260e926613ee05bd5949b71051f40d38883f714"
    family = "SilentNet"
    file_name = "KryptonClient.jar"
    file_type = "jar"
    first_seen = "2026-10-09 00:12:34"
  condition:
    hash.sha256(0, filesize) == "9d7bb13d6ceee4ed10a90bd9c260e926613ee05bd5949b71051f40d38883f714"
}
```

### Sample 72: `f08ab1a87db1149f`

| Field | Value |
|---|---|
| SHA-256 | `f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342` |
| Family label | `unknown` |
| File name | `f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342` |
| File type | `sh` |
| First seen | `2026-10-09 00:02:01` |
| Reporter | `spydisec` |
| Tags | `cowrie, dropper, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e99fe0590f0add516bb57fe8dd8aba8` |
| SHA-1 | `be9bc337e44177ce063cadf7cc48b51a03160384` |
| SHA-256 | `f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342` |
| SHA3-384 | `5eb5b8a5c9e996ec396022ae5e6e4fa24122f2e6417b8f621d0176f16b763394ec4b1a5ab7e879e80ed10ce97946134f` |
| TLSH | `T115A1A9F56055A130F85781652A547CF6C18BA2D75AA2C583B39F2D40EB9AFE4FF38301` |
| SSDEEP | `96:HsKBiqTamLrDCkxwqyWuIRJxQHPGiGJKuedMDHWv1YAGXtln7oMOtWqX:HsOORaoMDHFttOtWe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_f08ab1a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342"
    family = "unknown"
    file_name = "f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342"
    file_type = "sh"
    first_seen = "2026-10-09 00:02:01"
  condition:
    hash.sha256(0, filesize) == "f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342"
}
```

### Sample 73: `3a810e0fbee30b2a`

| Field | Value |
|---|---|
| SHA-256 | `3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f` |
| Family label | `Gafgyt` |
| File name | `3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f` |
| File type | `sh` |
| First seen | `2026-10-09 00:01:53` |
| Reporter | `spydisec` |
| Tags | `cowrie, dropper, Gafgyt, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49641f58d77d1249bffc31a6f162505f` |
| SHA-1 | `685de5a0db5c6ef6b103e065a9a50107478cd4af` |
| SHA-256 | `3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f` |
| SHA3-384 | `9b6ed57183f7bce7930c94dd1e693a404d75d47b8c72d8bee2f92f8455fb9b730357e026139fc6ded932804773fdf085` |
| TLSH | `T1D3E04F9A6CB0E021EADFDA18F3D7B9F46A83441D795C5A70A1869C300718D75313AE7A` |
| SSDEEP | `6:hbpkS7W6plR59LN8XOWLXigV2JOWLXiTkhQy+D0acIa0k2A2InHAKb:dpLSOWLyI2JOWLyoL+Dc32A2NC` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_073_3a810e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f"
    family = "Gafgyt"
    file_name = "3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f"
    file_type = "sh"
    first_seen = "2026-10-09 00:01:53"
  condition:
    hash.sha256(0, filesize) == "3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f"
}
```

### Sample 74: `9135f4d24e45365b`

| Field | Value |
|---|---|
| SHA-256 | `9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c` |
| Family label | `unknown` |
| File name | `9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c.bin` |
| File type | `macho` |
| First seen | `2026-10-09 00:00:46` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42bc18e69fed0270ad331caac75a896f` |
| SHA-1 | `5f95e045a8dc3bc1f1f7f6afebeefdaca5ae8a27` |
| SHA-256 | `9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c` |
| SHA3-384 | `04b894fe73e1108beb59db563520cf798608fcb23959f4093dd83c5ce7b0c24c8b4348a0d7530e43dd1e9053b65f6979` |
| TLSH | `T102F42AAB527AA4D4EC4732747B8A3BF7EE40B47663F5E4A9AA42513448F3374913021F` |
| SSDEEP | `12288:tU7wAcpxXAIIETE1UWLwJrr1nuwyiPUcyvmByHaRR1L+:tU7RyAOTtovPaRW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_9135f4d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c"
    family = "unknown"
    file_name = "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c.bin"
    file_type = "macho"
    first_seen = "2026-10-09 00:00:46"
  condition:
    hash.sha256(0, filesize) == "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c"
}
```

### Sample 75: `4ca810ed33db741b`

| Field | Value |
|---|---|
| SHA-256 | `4ca810ed33db741b86f8b3c07eec620456c23d4bf8737ed58781eba3c5b47029` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-08 23:38:52` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6986cda4d9478cd2743c764500115e0b` |
| SHA-1 | `b4c415868766339b45e6de311b52a403908fbf14` |
| SHA-256 | `4ca810ed33db741b86f8b3c07eec620456c23d4bf8737ed58781eba3c5b47029` |
| SHA3-384 | `1d19ab53d13338092851ef42b719b301182fe57230ab514ec60fe847f747fdc638eafe2da3356603f06585fb2fca6642` |
| IMPHASH | `80166b90e8e23191097047e5d12a5630` |
| TLSH | `T14725D0DCB78A2F76FB7AD4724A8145618F127B463BE054FF225D2A240F079C18EF5229` |
| SSDEEP | `24576:83/W0HtT7Q9Lf/SInODr5tvQe25Y/exBK9:0/WERQlf/fnCr5tvQ9xs` |
| ICON-DHASH | `4cb2694d4d69b24c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_4ca810ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ca810ed33db741b86f8b3c07eec620456c23d4bf8737ed58781eba3c5b47029"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 23:38:52"
  condition:
    hash.sha256(0, filesize) == "4ca810ed33db741b86f8b3c07eec620456c23d4bf8737ed58781eba3c5b47029"
}
```

### Sample 76: `f7a365217cee3078`

| Field | Value |
|---|---|
| SHA-256 | `f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34` |
| Family label | `unknown` |
| File name | `f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34` |
| File type | `sh` |
| First seen | `2026-10-08 23:35:20` |
| Reporter | `boehm` |
| Tags | `cowrie, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `448fe561e100889eeae1b52cd558812e` |
| SHA-1 | `42ab563b9b685fc065735d5e6967cb61be435db0` |
| SHA-256 | `f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34` |
| SHA3-384 | `581accf399b98367c0621e559b814f45056235b911200cebfc7a182e8d0699fb61ac06ef638b0adf2d2de6e1049db7e8` |
| TLSH | `T1A4E151E4E7B9D920B3D9D8196CC58D5329D77C3EC673190AF26BCE00A30E58B281A716` |
| SSDEEP | `192:OrIyC/6x35nHrWfo/5vYpYl+Uoqj5MNXbG:TyJnHv5v4V6erG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_f7a36521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34"
    family = "unknown"
    file_name = "f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34"
    file_type = "sh"
    first_seen = "2026-10-08 23:35:20"
  condition:
    hash.sha256(0, filesize) == "f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34"
}
```

### Sample 77: `1751d5c748f1af5d`

| Field | Value |
|---|---|
| SHA-256 | `1751d5c748f1af5d9229a43a3d9916a6b7cb21ed32af31d251e1c854053e108b` |
| Family label | `Mirai` |
| File name | `Space.x86` |
| File type | `elf` |
| First seen | `2026-10-08 23:30:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceef0c7df2695363cd5769f7510334e4` |
| SHA-1 | `2f2b2465edbf3646179720bd8fcb2bb6fb5ff024` |
| SHA-256 | `1751d5c748f1af5d9229a43a3d9916a6b7cb21ed32af31d251e1c854053e108b` |
| SHA3-384 | `16ffa1bedb9a24022d9bc59b82be1fc5056e9c30015d4510d4bd6b1b232ec06899784239f18463d732a30aaa9772ae40` |
| TLSH | `T166634BC9F983D4B6E857093010BBFF639DB3D6BE2168DA43C3A855369D12502F416E6C` |
| TELFHASH | `t1432137f76e1e48f8f3d49840c39eaa851a2ad677086136a445b2cdc036e7dd194bdc39` |
| SSDEEP | `1536:ltWizyApqj4PfWjF7lOvZOWsIyq3XkZSYX:ltFyA0j4HWBJOvwfIyqsX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_1751d5c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1751d5c748f1af5d9229a43a3d9916a6b7cb21ed32af31d251e1c854053e108b"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-08 23:30:47"
  condition:
    hash.sha256(0, filesize) == "1751d5c748f1af5d9229a43a3d9916a6b7cb21ed32af31d251e1c854053e108b"
}
```

### Sample 78: `caa464e61f4adda0`

| Field | Value |
|---|---|
| SHA-256 | `caa464e61f4adda038fd4c979b8d939ef1564e038baa925f9c90e5a803d41804` |
| Family label | `Mirai` |
| File name | `Space.x86_64` |
| File type | `elf` |
| First seen | `2026-10-08 23:30:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `511ff8eb710c0ae15d975b0d0296688b` |
| SHA-1 | `e54b0ecf6a284b14c6c58be0c8fdf1ef9deff647` |
| SHA-256 | `caa464e61f4adda038fd4c979b8d939ef1564e038baa925f9c90e5a803d41804` |
| SHA3-384 | `48fa8f30dd7ec1f64439aafbd2f31aa08dfc7f6037cd73efe9ea42d13cd9f380b2c3abe83bfb0e37a84dc5ae9549b819` |
| TLSH | `T1BB733A57BA4080FEC499C03843BEBA36D87274FE1379729A13D4FE366D46E601E29C54` |
| TELFHASH | `t1d32133b039591da0e0ebe468b305e1661d391aa004e2b8f3d9b790f6eb517870db9427` |
| SSDEEP | `1536:BzIDxEwvZ8bouGctIb/+w4HnC+8l8AnzcUs:BUxEyZCXtIf4HT8l8AzcUs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_caa464e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa464e61f4adda038fd4c979b8d939ef1564e038baa925f9c90e5a803d41804"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 23:30:43"
  condition:
    hash.sha256(0, filesize) == "caa464e61f4adda038fd4c979b8d939ef1564e038baa925f9c90e5a803d41804"
}
```

### Sample 79: `b2273c5a22de129a`

| Field | Value |
|---|---|
| SHA-256 | `b2273c5a22de129ad1b886fcc1b9a3e3862389b5843a6c68d93554189efb8c2e` |
| Family label | `Mirai` |
| File name | `Space.i686` |
| File type | `elf` |
| First seen | `2026-10-08 23:30:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a660b5089a4a8f90d9f3de2fc1e011c` |
| SHA-1 | `e9e9151a54b2507049f976fac0d26e9fe4d681fc` |
| SHA-256 | `b2273c5a22de129ad1b886fcc1b9a3e3862389b5843a6c68d93554189efb8c2e` |
| SHA3-384 | `36a9c8b6525366bbce3d92987f6d9cf1e080e7100f56fb5bc87e965ea219fe32460aed5dbbef36de33292bfa63aff895` |
| TLSH | `T1AF733985F987C6F2D407483042ABFB3FCB32D8A511B19B4DDF569F35DA33502AA22649` |
| TELFHASH | `t1c121bffb1dbe08fda7d89940c25e6fe22826c77b556036b00563c6353367ea144a8c3d` |
| SSDEEP | `1536:8A9Uqtm/qzBpeKm2XpQmj7qWSICRzBbkivom3aJ2XdLNn:8A9U7KBcKm2Xp3jnrCRzBbVvfXdLN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_b2273c5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2273c5a22de129ad1b886fcc1b9a3e3862389b5843a6c68d93554189efb8c2e"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-10-08 23:30:38"
  condition:
    hash.sha256(0, filesize) == "b2273c5a22de129ad1b886fcc1b9a3e3862389b5843a6c68d93554189efb8c2e"
}
```

### Sample 80: `550183dc18026b2b`

| Field | Value |
|---|---|
| SHA-256 | `550183dc18026b2bd9be81c2ef1a32b64ccad2732d0268b29aef33acc73b9b4e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62fd5e8acda106ff5dbef167b99b8829` |
| SHA-1 | `ffaaf05d875de9c199f236e3a6df5901184f873e` |
| SHA-256 | `550183dc18026b2bd9be81c2ef1a32b64ccad2732d0268b29aef33acc73b9b4e` |
| SHA3-384 | `54e6f9adc0bde6ce659bac168bbb28da6542e139d66e02b8faf49f32b467f73acac567768dada53895992bed49c5b2f5` |
| TLSH | `T1A403094AF9818B12C9E115BAFE2E524D3313077CE3EF72266E106E34679757B0B3A815` |
| TELFHASH | `t12bf0592002449de865fc4445de7ed4827041abb636bc380b7be3bd6d832b5a1b03009e` |
| SSDEEP | `768:dtnvcGn539x6CfbVU6nfnfhpgD5mkcIYS6igHGBF3KAM:dtnfn53mCLnfnf4g3IWiqGP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_550183dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "550183dc18026b2bd9be81c2ef1a32b64ccad2732d0268b29aef33acc73b9b4e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:27"
  condition:
    hash.sha256(0, filesize) == "550183dc18026b2bd9be81c2ef1a32b64ccad2732d0268b29aef33acc73b9b4e"
}
```

### Sample 81: `3330f9f5be2b0b4f`

| Field | Value |
|---|---|
| SHA-256 | `3330f9f5be2b0b4fb0bffc7ceb770deb2dbbc798dcf421d55812700ad76e2f0b` |
| Family label | `Mirai` |
| File name | `Space.arc` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:23` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `036b240027d9142b5784817d08c1ec22` |
| SHA-1 | `f1fd8d9ece88ef7ae0ae88bc7e829c33b63fb4bd` |
| SHA-256 | `3330f9f5be2b0b4fb0bffc7ceb770deb2dbbc798dcf421d55812700ad76e2f0b` |
| SHA3-384 | `4be936501a3052608ad82b904b11f317d4c3fe7e0c5451fcc5f5f9907366d6a481a6e814a9c6335d14c321316ce20ec9` |
| TLSH | `T141B3AEEBF64715A2C85243F013C79F8E3E232290AE57E4E76D1E167B19760DB1D0AB81` |
| SSDEEP | `1536:pcdlYSuiBMW3zC8aRGGTtJM/qrlpmxJ6nDgD//LWW:8YSZ3e8ZE3MYlphDgD/q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_3330f9f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3330f9f5be2b0b4fb0bffc7ceb770deb2dbbc798dcf421d55812700ad76e2f0b"
    family = "Mirai"
    file_name = "Space.arc"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:23"
  condition:
    hash.sha256(0, filesize) == "3330f9f5be2b0b4fb0bffc7ceb770deb2dbbc798dcf421d55812700ad76e2f0b"
}
```

### Sample 82: `36324af604669401`

| Field | Value |
|---|---|
| SHA-256 | `36324af60466940192d18de84a07ac6d897a163bf4a5d296257f10856a95d6e7` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `771820d9449b6b582fa3ce6dd69f0d9e` |
| SHA-1 | `490a1264f9e8b1a2d5d17368767424c97db8af31` |
| SHA-256 | `36324af60466940192d18de84a07ac6d897a163bf4a5d296257f10856a95d6e7` |
| SHA3-384 | `c872c33abbb53d46ed91888daf3973d9ef4fab4f378431a475fd2dc6e2a5bc0b4a05208458dd241418494fe14a449a36` |
| TLSH | `T1E723074AFD805F00D9E525BAFA1E524D33934B7CE3FE7111AE219B2523D6A2B0F76811` |
| TELFHASH | `t18cf09e104a856cedf3d2190ad38e76439912aaea3f746c8633ebbc075337f82053029d` |
| SSDEEP | `1536:JlnQq62buDyyyyyyyyoPog/giG1QiX2lHMibAZ2nUfy:L6QP/giG1cJAZ2Uq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_36324af6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36324af60466940192d18de84a07ac6d897a163bf4a5d296257f10856a95d6e7"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:22"
  condition:
    hash.sha256(0, filesize) == "36324af60466940192d18de84a07ac6d897a163bf4a5d296257f10856a95d6e7"
}
```

### Sample 83: `e8ce0703b89472af`

| Field | Value |
|---|---|
| SHA-256 | `e8ce0703b89472af190b043ff6990ad166a7251ebe1b3fc9621b2796827719af` |
| Family label | `Mirai` |
| File name | `Space.x86` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:21` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c353a70fc94cfb058da65395c4838592` |
| SHA-1 | `b68db3556a62ad4b4712f35bf34c2ad4bb8d71bf` |
| SHA-256 | `e8ce0703b89472af190b043ff6990ad166a7251ebe1b3fc9621b2796827719af` |
| SHA3-384 | `545c41481c2983ce14698781be40518a52fe7279f4ad6e640fc847d910dde8d298ffd5ec5e00992778975604f0d5e739` |
| TLSH | `T17FF2E19724B98108917E217D1C6BFD8E84B09655C16DC8F24F987433D513FAC39A479F` |
| SSDEEP | `768:ZCkGi0D/4BfI7dZnRh7/IN0BIesyoXKot5V4oEAIptK76cBkAcRnbcuyD7UHQRjt:ZBGbyqhXrTBrQX4oEX46bnouy8HyZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_e8ce0703
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ce0703b89472af190b043ff6990ad166a7251ebe1b3fc9621b2796827719af"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:21"
  condition:
    hash.sha256(0, filesize) == "e8ce0703b89472af190b043ff6990ad166a7251ebe1b3fc9621b2796827719af"
}
```

### Sample 84: `577351cb939eda8d`

| Field | Value |
|---|---|
| SHA-256 | `577351cb939eda8db3c9debe35731085c4b12e723995565e4d445844249fb72e` |
| Family label | `Mirai` |
| File name | `Space.x86_64` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:19` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2599a7a9b155a4189a26955b30c65da6` |
| SHA-1 | `7da235dfc397a0f18c5f427e10b9ffb9b46a2c52` |
| SHA-256 | `577351cb939eda8db3c9debe35731085c4b12e723995565e4d445844249fb72e` |
| SHA3-384 | `c57955b49d48cc82a94a37c05fe9254f07862da084a0792ebb9127fe80a183d56e045a76beea996b93fc7646d0d34358` |
| TLSH | `T15EF2F131C1FEE8BCC03EB579085C5B45F485E5122B6637760569A1BA9EF78C13E01B81` |
| SSDEEP | `768:JwS0nQr9tpJEu0annIBqVqVHmwIHWUFtGtzXKTdr+IUx0nZg:gOX80VqVi2otGtzXS+BMZg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_577351cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "577351cb939eda8db3c9debe35731085c4b12e723995565e4d445844249fb72e"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:19"
  condition:
    hash.sha256(0, filesize) == "577351cb939eda8db3c9debe35731085c4b12e723995565e4d445844249fb72e"
}
```

### Sample 85: `faec6566b4578663`

| Field | Value |
|---|---|
| SHA-256 | `faec6566b457866387e647b16235b747bff7404a06e95048474189d59a2ad81e` |
| Family label | `Mirai` |
| File name | `Space.i686` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:16` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c0ef0bc3fd0c3aa5555a7a878b2e3c2` |
| SHA-1 | `ae50f95ba1fed099987304cd9485b2584d965073` |
| SHA-256 | `faec6566b457866387e647b16235b747bff7404a06e95048474189d59a2ad81e` |
| SHA3-384 | `7f5728e14ae203c7827e5d32dcc018dff081579354c7c90ae81e949dd2d2abf89e9e124428ad28a71b863e17d9c541ac` |
| TLSH | `T1B1F2F1B1C176CA1CD73D82F944DD6E0D3C44D818AE04F0B6EF8478A38616FA5ADB1B99` |
| SSDEEP | `768:PW/zEpEYEgHE+Tc70R1cVC9owNnTAz9okfwy8CNBnbcuyD7UHQRjK:u4B1E+TcAYC9owui/CNBnouy8Hym` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_faec6566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faec6566b457866387e647b16235b747bff7404a06e95048474189d59a2ad81e"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:16"
  condition:
    hash.sha256(0, filesize) == "faec6566b457866387e647b16235b747bff7404a06e95048474189d59a2ad81e"
}
```

### Sample 86: `37fb141242998ee6`

| Field | Value |
|---|---|
| SHA-256 | `37fb141242998ee64251670fd41c6a9005680d81e8a4b9839064b9eb203fa4f3` |
| Family label | `Mirai` |
| File name | `Space` |
| File type | `elf` |
| First seen | `2026-10-08 23:29:14` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `126f0ddde02c7f88aea1494afb1c2929` |
| SHA-1 | `a80497bac927948eb13db98eb7c9cd77d9e72e5e` |
| SHA-256 | `37fb141242998ee64251670fd41c6a9005680d81e8a4b9839064b9eb203fa4f3` |
| SHA3-384 | `c4886659fb9f56b8dbcb77bc68010b44d663038f2ffe5bd012ac174638feec5ccb71881f227155cf75a0473a2c7c83ff` |
| TLSH | `T1C4F2E17123ADE8BCD43AB9BB45481F4C7DE3E4764A890B6A7019E0955EB3C813A1A6C1` |
| SSDEEP | `768:twS0nQr9tpJEu6+F2QKnEgWWX+sWF0tKsevFohB2WI+fUx0nZ1:sOXU1WoZwYlIdMZ1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_37fb1412
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37fb141242998ee64251670fd41c6a9005680d81e8a4b9839064b9eb203fa4f3"
    family = "Mirai"
    file_name = "Space"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:14"
  condition:
    hash.sha256(0, filesize) == "37fb141242998ee64251670fd41c6a9005680d81e8a4b9839064b9eb203fa4f3"
}
```

### Sample 87: `33ea1acbfd8fe260`

| Field | Value |
|---|---|
| SHA-256 | `33ea1acbfd8fe260fc4394f34652f90509f602e6da51a97a0c75fd39006fb30f` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-08 23:28:20` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdd962a1807df4ee04227c596a258c9e` |
| SHA-1 | `66c028eb19e3721170074d4af090a7b839407a19` |
| SHA-256 | `33ea1acbfd8fe260fc4394f34652f90509f602e6da51a97a0c75fd39006fb30f` |
| SHA3-384 | `393ea9423e1926668cb56f84503c61bcc99d5bc787fbd1842765d9530c6abcc9f91a0d545f2d815f2e866a93fe440ed3` |
| TLSH | `T1A7B26C86BD814517CEE52276FA2E928C37655B74E2FF3303AA261F642742A1F0F3A505` |
| TELFHASH | `t158115711864c8d9eb240856ce1ad46031626e1ba3c7e3a62bdfb981f810bcf39471926` |
| SSDEEP | `384:9m2m2FfIMN9og36J0qQ87+2eZvaBcjQOFphM4VXx5oVF5Bi6vW6OFx4e:9/y1Z887+zvaOPFXMOoTi6vWY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_33ea1acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33ea1acbfd8fe260fc4394f34652f90509f602e6da51a97a0c75fd39006fb30f"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:20"
  condition:
    hash.sha256(0, filesize) == "33ea1acbfd8fe260fc4394f34652f90509f602e6da51a97a0c75fd39006fb30f"
}
```

### Sample 88: `3ad99b41929cbbbd`

| Field | Value |
|---|---|
| SHA-256 | `3ad99b41929cbbbde9c2f97c4ab10065af1f8fcad08e2c443975f4d83c561c89` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-08 23:28:18` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1d46b0bb2a4e77bf781c0222a6abdb2` |
| SHA-1 | `258966d44394b321f27aff5070b307621722aa33` |
| SHA-256 | `3ad99b41929cbbbde9c2f97c4ab10065af1f8fcad08e2c443975f4d83c561c89` |
| SHA3-384 | `365a30321364b5800888b2dd78271a5ca47d86df4c8da8821e2ecb5f108fd8750ea73055d63d5cc3bba426cdd5b36ca4` |
| TLSH | `T198B25C86FD414917CEE11136FA2E828C37654BB4E2EF3307AB261F742746A1A0F36549` |
| TELFHASH | `t1e7117d514588ccade1c081aef06d93128516a1663c7d3c62f8ff580cd273df22831969` |
| SSDEEP | `384:Ja1e4fKt9Jz2Skeb1TGdAy31p1mS/5aP5BTM60XFx4eu:JSePRz2S5NGWi1PZETM6t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_3ad99b41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ad99b41929cbbbde9c2f97c4ab10065af1f8fcad08e2c443975f4d83c561c89"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:18"
  condition:
    hash.sha256(0, filesize) == "3ad99b41929cbbbde9c2f97c4ab10065af1f8fcad08e2c443975f4d83c561c89"
}
```

### Sample 89: `242b9b5614d4eb7a`

| Field | Value |
|---|---|
| SHA-256 | `242b9b5614d4eb7a645c8deca0356ee9d6226395c6ed94469a694ee90faa5d8c` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-08 23:28:15` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5650f177d561ccbff522cb9d04ef2ca` |
| SHA-1 | `c59cf19e7c29dc0a5dcb9a5539abcc02bf3493b3` |
| SHA-256 | `242b9b5614d4eb7a645c8deca0356ee9d6226395c6ed94469a694ee90faa5d8c` |
| SHA3-384 | `6f896dbbbf133614984d5c31388b43394e993936c8e5bcd0415cbcdef663b3f9a1a001aab195ae7537037f1b019acb02` |
| TLSH | `T14892C03987A5C6A1C0E00835D82B484BA77366F4C0F5709523B36B50FB92556D7AF097` |
| SSDEEP | `384:Ahs8o6sY6uP+jW2OFl45q3IDnxvxhClF03uqmdGU57ptVGq8rscX:A9xP0WJybrT3uq3Uir1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_242b9b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "242b9b5614d4eb7a645c8deca0356ee9d6226395c6ed94469a694ee90faa5d8c"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:15"
  condition:
    hash.sha256(0, filesize) == "242b9b5614d4eb7a645c8deca0356ee9d6226395c6ed94469a694ee90faa5d8c"
}
```

### Sample 90: `6f70689f8ecdfb7d`

| Field | Value |
|---|---|
| SHA-256 | `6f70689f8ecdfb7dd540cb83d8a462e1de8846c182ababbf6c0c3fcfdcf24987` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-08 23:28:13` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3391ca9ec050c38ab1b8ebc3e00f3fb5` |
| SHA-1 | `5d3883bbf3b18171287985c8784c07f514d84931` |
| SHA-256 | `6f70689f8ecdfb7dd540cb83d8a462e1de8846c182ababbf6c0c3fcfdcf24987` |
| SHA3-384 | `7b1f5bbac79d8d737d7b66a4adada5eafe868e67969fd9d7cc39332adc37e9631ef5fc298b0bd08236db91579050a12b` |
| TLSH | `T170B2E07A915C6D63D2843837AC3C518E36950AB943EA70E3399A4B52B3920B753F21CB` |
| SSDEEP | `768:iUXK3Br035XJCuk9rtb8h2n7GEl5q3Uir+:RMCouYrtQ8iyl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_6f70689f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f70689f8ecdfb7dd540cb83d8a462e1de8846c182ababbf6c0c3fcfdcf24987"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:13"
  condition:
    hash.sha256(0, filesize) == "6f70689f8ecdfb7dd540cb83d8a462e1de8846c182ababbf6c0c3fcfdcf24987"
}
```

### Sample 91: `0886e17b38d09ef7`

| Field | Value |
|---|---|
| SHA-256 | `0886e17b38d09ef7b0855a2394dd33454939edb3f33a43096c93e0dccfe6a81c` |
| Family label | `unknown` |
| File name | `lgtvx64` |
| File type | `elf` |
| First seen | `2026-10-08 23:27:30` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cc7c27267fb8eb1f2b87e37ac128c0b` |
| SHA-1 | `b60d36468d8290d518fd192cef2fc94294b65684` |
| SHA-256 | `0886e17b38d09ef7b0855a2394dd33454939edb3f33a43096c93e0dccfe6a81c` |
| SHA3-384 | `c57e1117546a7f6f50159309b278491783ea8ca69206f51ba05f1ed3fae9b627e78f222cbfe9a6c89726a3a30dc9a153` |
| TLSH | `T1D3362843F85091E8C1EED1308662D292BA317C895F3163D36B50FBB92B76BD4AE79314` |
| TELFHASH | `t1c39212758abc74b6a26bc960f37370b4d23718b163e474b140276d92efe1d891c9ac27` |
| GIMPHASH | `4577d66a329aca2ee162012ecea383847b93ec537a5fa738bb378b2f5e00211e` |
| SSDEEP | `49152:4/fNunPrb/TIvO90dL3BmAFd4A64nsfJClbXwibGgRV87V/5DdU3JCATV3T9KK5l:Kirtmz3EH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_0886e17b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0886e17b38d09ef7b0855a2394dd33454939edb3f33a43096c93e0dccfe6a81c"
    family = "unknown"
    file_name = "lgtvx64"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:30"
  condition:
    hash.sha256(0, filesize) == "0886e17b38d09ef7b0855a2394dd33454939edb3f33a43096c93e0dccfe6a81c"
}
```

### Sample 92: `f8b973a2386d9095`

| Field | Value |
|---|---|
| SHA-256 | `f8b973a2386d9095f12e0e6192b77c1b7e2408a4c48f56b33f9e3ef362a9935b` |
| Family label | `unknown` |
| File name | `lgtvarm64` |
| File type | `elf` |
| First seen | `2026-10-08 23:27:27` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b490f15d5602287c1db5c612f459b4e5` |
| SHA-1 | `4fab048294891a8292cae92f1e4ae17112c85643` |
| SHA-256 | `f8b973a2386d9095f12e0e6192b77c1b7e2408a4c48f56b33f9e3ef362a9935b` |
| SHA3-384 | `be21395b0a3b51d45f364bd4cc5a33acb5a7abc2b05295cbef3174ad1503ade33835b630331bb00e6ce72d3cc4b813ec` |
| TLSH | `T1BF265C25BD1EE563E6C837707B7582C4323EBC489F41D2236605BBBE59F67588F12222` |
| GIMPHASH | `b9feb453e3f427da38244bb2e552092ef1000b51384eb9da1135c2ec2f43fe7c` |
| SSDEEP | `49152:k9cUOt4V6kVRdKSZ//nAJVTO5ERwrsmec7TNB1:qcUOt4V6kDdJZ//nAEER8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_f8b973a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b973a2386d9095f12e0e6192b77c1b7e2408a4c48f56b33f9e3ef362a9935b"
    family = "unknown"
    file_name = "lgtvarm64"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:27"
  condition:
    hash.sha256(0, filesize) == "f8b973a2386d9095f12e0e6192b77c1b7e2408a4c48f56b33f9e3ef362a9935b"
}
```

### Sample 93: `f304c1bfc082214a`

| Field | Value |
|---|---|
| SHA-256 | `f304c1bfc082214a49bc57db5cf41acb86b11a5a192a56d29a2cae5035753418` |
| Family label | `unknown` |
| File name | `lgtvarmv7` |
| File type | `elf` |
| First seen | `2026-10-08 23:27:24` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dd23df441996f034066f747d9a4dc1f` |
| SHA-1 | `1f7c636f2c88ffaafba3b3eefe000f47d200e09e` |
| SHA-256 | `f304c1bfc082214a49bc57db5cf41acb86b11a5a192a56d29a2cae5035753418` |
| SHA3-384 | `a22b3dbcbd06f2c08ac60e9d51ad16e6b26bc1fa959bb50f607cc1a858cd1ebe44059b96f7873bbdd7a4a44e8a034d00` |
| TLSH | `T176261A97B8918643C0E4367ABCBEC1C432672EB99B9752576D04FE3D3ABE1990E35304` |
| GIMPHASH | `3c667ff82606d7565877db98555e4d0c5d7b1393d62d636eb9f98abcf6a4554c` |
| SSDEEP | `49152:nGeXT1J4Y386ALrlw+gKvsh7twm6mxKCU1F1z:vXTD4Ys6ALrl02f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_f304c1bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f304c1bfc082214a49bc57db5cf41acb86b11a5a192a56d29a2cae5035753418"
    family = "unknown"
    file_name = "lgtvarmv7"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:24"
  condition:
    hash.sha256(0, filesize) == "f304c1bfc082214a49bc57db5cf41acb86b11a5a192a56d29a2cae5035753418"
}
```

### Sample 94: `163cb287fd8f81c1`

| Field | Value |
|---|---|
| SHA-256 | `163cb287fd8f81c13901eb4ddaea2db326213f4d2095e0e64321b9afd8300480` |
| Family label | `unknown` |
| File name | `lgtv32` |
| File type | `elf` |
| First seen | `2026-10-08 23:27:21` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a601b0d73496cc1002460c739b986fdc` |
| SHA-1 | `f9730637a195c1f3b842104a1318814284be3ce8` |
| SHA-256 | `163cb287fd8f81c13901eb4ddaea2db326213f4d2095e0e64321b9afd8300480` |
| SHA3-384 | `3232f96b7c5f1f587bd68bce65b9e28973c3e0e1f8ac8b852a9302690b29c39d70eed2acf46bde523dd8d13d4308902f` |
| TLSH | `T1D4261810FECB94F6D5031E3054BBE2AF67316D054B24EB87EA007F6AE9776921D32219` |
| TELFHASH | `t159b29c73159da4eca7f0841797af7620cef6e02716e0387119f2b8c0eab3d535a26874` |
| GIMPHASH | `cf6e6ae34ea56a05248f934e9075959d9fa46722bab9ab7dfd125ff847894473` |
| SSDEEP | `49152:p8BrM0w3mGKFQHbqq7CdGadgmMrE8i7lPpTA7zFz/hlzC2ezA5ZMi0Ux2isMt48k:p8qW7y/+dGSA7z5/hxCKuJTc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_163cb287
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163cb287fd8f81c13901eb4ddaea2db326213f4d2095e0e64321b9afd8300480"
    family = "unknown"
    file_name = "lgtv32"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:21"
  condition:
    hash.sha256(0, filesize) == "163cb287fd8f81c13901eb4ddaea2db326213f4d2095e0e64321b9afd8300480"
}
```

### Sample 95: `f8ce88a265e20c96`

| Field | Value |
|---|---|
| SHA-256 | `f8ce88a265e20c968d475680ca712ff43d5f81caf94cd17d63fd30e92c6928eb` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-10-08 23:26:48` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76dc83fa3aaadb20361f05f6ea62c653` |
| SHA-1 | `521dbe46b3ea243fc8880c763f7b7988017c56d5` |
| SHA-256 | `f8ce88a265e20c968d475680ca712ff43d5f81caf94cd17d63fd30e92c6928eb` |
| SHA3-384 | `f1e8a32293238ce468241eb3c5d725ada6bff3c28a0ab98ce17579a14758733f9ad8970e8c4312031e8dbc3d0e2524ff` |
| TLSH | `T172B3023E63F0761EED20383156CFAD689827905D35196D07FA466C7C24BFE2EA162C1A` |
| SSDEEP | `3072:8xwpDrr5CjB6vY39dmJ1GG4un4ImW2DV:8+pDQjhEJ1r9qW2D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_f8ce88a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ce88a265e20c968d475680ca712ff43d5f81caf94cd17d63fd30e92c6928eb"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-10-08 23:26:48"
  condition:
    hash.sha256(0, filesize) == "f8ce88a265e20c968d475680ca712ff43d5f81caf94cd17d63fd30e92c6928eb"
}
```

### Sample 96: `4807236cfb7d8305`

| Field | Value |
|---|---|
| SHA-256 | `4807236cfb7d8305e246c519b46ca558704a239b17c9eef9545ab7bb79154229` |
| Family label | `unknown` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-10-08 23:26:46` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70311f89f41fdb5a5fc16e8ece6114ab` |
| SHA-1 | `147d3106852657f1bba0aa37083ac3f22f62d157` |
| SHA-256 | `4807236cfb7d8305e246c519b46ca558704a239b17c9eef9545ab7bb79154229` |
| SHA3-384 | `5baac11d0b1da40ab32c70a59c25f42ca901264d79a9310bfed0ad7e0fdc6f2c554de9087271bfb89fb77d521c6937aa` |
| TLSH | `T17FB30223F7C35E4FF9851B308BDBEE8614565C88762779417220BD12CD3EAB67A20587` |
| SSDEEP | `1536:8xwEkEKIJe+LcBPuubVLeqa6b/+TnaQ1GrToqWyGUEU+gUzYzvoOQ7kc5xg:8xwEkaTnGMqaS/+baEMDWxBioOWke2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_4807236c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4807236cfb7d8305e246c519b46ca558704a239b17c9eef9545ab7bb79154229"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-10-08 23:26:46"
  condition:
    hash.sha256(0, filesize) == "4807236cfb7d8305e246c519b46ca558704a239b17c9eef9545ab7bb79154229"
}
```

### Sample 97: `eb367b7ba3be78fa`

| Field | Value |
|---|---|
| SHA-256 | `eb367b7ba3be78fa066f7c6a28e11f5f165b001312bec229cef7aee310f4d9b1` |
| Family label | `unknown` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-10-08 23:26:44` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47e06d34af0aea9b87207f86d7e87b67` |
| SHA-1 | `1cf1de96f01c4491409117289f3ed3d0a1a7bc0d` |
| SHA-256 | `eb367b7ba3be78fa066f7c6a28e11f5f165b001312bec229cef7aee310f4d9b1` |
| SHA3-384 | `0fe1b9f865b8345f1f86a752e157e3a9c7bc3633a357ab6e1ada2146d39e2c9c884b76d0faaec92ff5b1c6b87b76d0de` |
| TLSH | `T19EB30201D7E2CFE6E1C7087689EF2902746994CDF4132D229B123D762D7ABB54F299A0` |
| SSDEEP | `3072:8JwGRyw7z7T/xxRaEUIAtSQHPOwcaE8zYP7:8WMyM7dfaE/AoQvX1E8kD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_eb367b7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb367b7ba3be78fa066f7c6a28e11f5f165b001312bec229cef7aee310f4d9b1"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-10-08 23:26:44"
  condition:
    hash.sha256(0, filesize) == "eb367b7ba3be78fa066f7c6a28e11f5f165b001312bec229cef7aee310f4d9b1"
}
```

### Sample 98: `38dbcfe9e766a0b1`

| Field | Value |
|---|---|
| SHA-256 | `38dbcfe9e766a0b1a15c90e021febb42d75fd103328a6e1361fbb75ea1664f7e` |
| Family label | `Vidar` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-08 23:20:34` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e136fadd3494833f1c7d073df3a0772f` |
| SHA-1 | `91f5336715a543f9cbc45cbda6471b2a38aba4b8` |
| SHA-256 | `38dbcfe9e766a0b1a15c90e021febb42d75fd103328a6e1361fbb75ea1664f7e` |
| SHA3-384 | `d4796c262b0dfe1b4b0ccea402a32504509544eaac78fd7d47bd8f5255f012b85607ff188d4f3d7595a62b2598734ef8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T18666D85871C410EDCA8E837648F45DBE23B21DBB1613A78A0799BBE12F13BD65F24D48` |
| SSDEEP | `24576:VV/Qr/6Rak++7O66NIaopqaDckeDfym+wp8SGXkMStf5yWmWk:VV4r/6wk++2NSwewpQBSmV1` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_098_38dbcfe9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38dbcfe9e766a0b1a15c90e021febb42d75fd103328a6e1361fbb75ea1664f7e"
    family = "Vidar"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-08 23:20:34"
  condition:
    hash.sha256(0, filesize) == "38dbcfe9e766a0b1a15c90e021febb42d75fd103328a6e1361fbb75ea1664f7e"
}
```

### Sample 99: `f6bbc27e48c8e8ae`

| Field | Value |
|---|---|
| SHA-256 | `f6bbc27e48c8e8aeb83dd944086d5ba9655f5c170672241e5d3e1c5d8f6e3d48` |
| Family label | `SilentNet` |
| File name | `mod.jar` |
| File type | `jar` |
| First seen | `2026-10-08 23:08:59` |
| Reporter | `NyxIndius` |
| Tags | `jar, Silentnet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2d1b320cd2f68e9d43dc13c90a1cfe7` |
| SHA-1 | `4b6dd292764e4f131b6d4be0acfa6951aad48685` |
| SHA-256 | `f6bbc27e48c8e8aeb83dd944086d5ba9655f5c170672241e5d3e1c5d8f6e3d48` |
| SHA3-384 | `30c7f79441984d97e305ec3b76373cbfd3976d3f1c42be6a4d6a94aa024c90416f1005a761ae1accafdd5267d44618b8` |
| TLSH | `T1E0B53365B9573D01DD0A60F597D3B699E8066CCECF628EDE731AFF1B8838C483664A01` |
| SSDEEP | `49152:BCfq1TT5QDDud2m/mvom5e1oFK8qDdwzxKSnCEiIlX0E+gn5GJDTM:oq1MDu4+tm5e1os8ncfEkJC` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_099_f6bbc27e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6bbc27e48c8e8aeb83dd944086d5ba9655f5c170672241e5d3e1c5d8f6e3d48"
    family = "SilentNet"
    file_name = "mod.jar"
    file_type = "jar"
    first_seen = "2026-10-08 23:08:59"
  condition:
    hash.sha256(0, filesize) == "f6bbc27e48c8e8aeb83dd944086d5ba9655f5c170672241e5d3e1c5d8f6e3d48"
}
```

### Sample 100: `de007a3bc1cfcdf8`

| Field | Value |
|---|---|
| SHA-256 | `de007a3bc1cfcdf8985690b5127eb099292a3edfd6f4f7b462c65229011a669b` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-08 22:59:18` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abf4a82fc36da0c8918f7e8b7185d97c` |
| SHA-1 | `f18cee29bcd426cb80a02f0195eaf68f08d8e225` |
| SHA-256 | `de007a3bc1cfcdf8985690b5127eb099292a3edfd6f4f7b462c65229011a669b` |
| SHA3-384 | `2d82cdd105760d9409757af32c6b9ccba52b6e9ad8f12e260428b462bad107c40b02143b0a414b768a4883ae0906de79` |
| IMPHASH | `672bff0d668d8425dce5b5bf2bf7b41e` |
| TLSH | `T12DE33A5B73A530F9E277923885A61A42F77278310751AFEF0360467A1E633D09E3BB61` |
| SSDEEP | `3072:MWlssEIrEwrxwTWxqLflso/Gadg21on+/n:G3yxFsz9dJ` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_100_de007a3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de007a3bc1cfcdf8985690b5127eb099292a3edfd6f4f7b462c65229011a669b"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 22:59:18"
  condition:
    hash.sha256(0, filesize) == "de007a3bc1cfcdf8985690b5127eb099292a3edfd6f4f7b462c65229011a669b"
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
 * Generated: 2026-10-09T06:18:47.735122+00:00
 */

rule MalwareBazaar_PureLogsStealer_001_53634069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53634069057acb00055ca4a90a3a5d2f40f3931b40d7cf7322c66b8a9f0dc13f"
    family = "PureLogsStealer"
    file_name = "Enquiry_AG-012-F2026_Specifications.js"
    file_type = "js"
    first_seen = "2026-10-09 06:18:01"
  condition:
    hash.sha256(0, filesize) == "53634069057acb00055ca4a90a3a5d2f40f3931b40d7cf7322c66b8a9f0dc13f"
}

rule MalwareBazaar_unknown_002_384b954c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c"
    family = "unknown"
    file_name = "vcimanagement.mips"
    file_type = "elf"
    first_seen = "2026-10-09 06:17:43"
  condition:
    hash.sha256(0, filesize) == "384b954cd0b20f18eb7b3efbf98e0a1c6e7f599e73800ffd44f89a48e3156c5c"
}

rule MalwareBazaar_unknown_003_75b4aaa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1"
    family = "unknown"
    file_name = "vcimanagement.sh4"
    file_type = "elf"
    first_seen = "2026-10-09 06:17:41"
  condition:
    hash.sha256(0, filesize) == "75b4aaa700bec8144f5a30708fb10058b165d41034e7323c34f5f4bedead84a1"
}

rule MalwareBazaar_Mirai_004_a4e54b02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e54b021c69560422159eb4cdf54a27c92ef4feafb5516b4c9976d23d1c088a"
    family = "Mirai"
    file_name = "qtm.x86"
    file_type = "elf"
    first_seen = "2026-10-09 06:13:28"
  condition:
    hash.sha256(0, filesize) == "a4e54b021c69560422159eb4cdf54a27c92ef4feafb5516b4c9976d23d1c088a"
}

rule MalwareBazaar_Mirai_005_189d9cb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189d9cb2885638238f19f4dd911ac1ed72a16703cdf5a84985b0d3de4f0ba6f9"
    family = "Mirai"
    file_name = "lol.sh"
    file_type = "sh"
    first_seen = "2026-10-09 06:10:01"
  condition:
    hash.sha256(0, filesize) == "189d9cb2885638238f19f4dd911ac1ed72a16703cdf5a84985b0d3de4f0ba6f9"
}

rule MalwareBazaar_unknown_006_dc781550
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc7815509fa8976eaca782547f3f64471e875b37536a8aefc6b81222c4ac8646"
    family = "unknown"
    file_name = "telnet.sh"
    file_type = "sh"
    first_seen = "2026-10-09 06:09:58"
  condition:
    hash.sha256(0, filesize) == "dc7815509fa8976eaca782547f3f64471e875b37536a8aefc6b81222c4ac8646"
}

rule MalwareBazaar_Mirai_007_da7cac6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da7cac6a41fb53171db401c5a952bcf1a4796068fd07c0900027dc5919cd4a7c"
    family = "Mirai"
    file_name = "wj0s.arm"
    file_type = "elf"
    first_seen = "2026-10-09 06:09:52"
  condition:
    hash.sha256(0, filesize) == "da7cac6a41fb53171db401c5a952bcf1a4796068fd07c0900027dc5919cd4a7c"
}

rule MalwareBazaar_unknown_008_360fc4f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "360fc4f17c71e1a1b101778fd20f0b3c090bc6297e94d045bcb68bb432f313a1"
    family = "unknown"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-09 06:02:36"
  condition:
    hash.sha256(0, filesize) == "360fc4f17c71e1a1b101778fd20f0b3c090bc6297e94d045bcb68bb432f313a1"
}

rule MalwareBazaar_Mirai_009_37530b71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37530b711f22e6fd20ecad05961fa5fd6ee6afa2e60ab01931bda4819c4229ba"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-09 06:02:34"
  condition:
    hash.sha256(0, filesize) == "37530b711f22e6fd20ecad05961fa5fd6ee6afa2e60ab01931bda4819c4229ba"
}

rule MalwareBazaar_Mirai_010_b38ed72f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c"
    family = "Mirai"
    file_name = "vcimanagement.ppc"
    file_type = "elf"
    first_seen = "2026-10-09 05:50:36"
  condition:
    hash.sha256(0, filesize) == "b38ed72f2f3f4764e3d0c6e12d574e0754fe29729f247087c1e8314c9156e77c"
}

rule MalwareBazaar_Mirai_011_60324938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-10-09 05:50:33"
  condition:
    hash.sha256(0, filesize) == "60324938d01641de82b11bd0fd91d10f93f9b79bc40f031709d82337fb8a241e"
}

rule MalwareBazaar_Mirai_012_9303a4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203"
    family = "Mirai"
    file_name = "vcimanagement.arm6"
    file_type = "elf"
    first_seen = "2026-10-09 05:50:31"
  condition:
    hash.sha256(0, filesize) == "9303a4a918d93f360dc885fcaa68a50e021362e3b182d4ffd176eba4d6118203"
}

rule MalwareBazaar_Formbook_013_774acba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "774acba8544be239131e88caed2937694e7b709f273be199ad9d2f29968dd1c7"
    family = "Formbook"
    file_name = "Files 0019002610.pdf.js"
    file_type = "js"
    first_seen = "2026-10-09 05:49:38"
  condition:
    hash.sha256(0, filesize) == "774acba8544be239131e88caed2937694e7b709f273be199ad9d2f29968dd1c7"
}

rule MalwareBazaar_Mirai_014_51b2a224
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-09 05:46:30"
  condition:
    hash.sha256(0, filesize) == "51b2a2243840c0681167405e2ebbf9f5ac05105f94dc005d335897952d962224"
}

rule MalwareBazaar_unknown_015_22949b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22949b40865c3d6c9a2c7d7eae97c964b5fde63c1727ce74773d7aeb20be347a"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.exe"
    file_type = "exe"
    first_seen = "2026-10-09 05:44:59"
  condition:
    hash.sha256(0, filesize) == "22949b40865c3d6c9a2c7d7eae97c964b5fde63c1727ce74773d7aeb20be347a"
}

rule MalwareBazaar_Mirai_016_1981072e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b"
    family = "Mirai"
    file_name = "vcimanagement.mpsl"
    file_type = "elf"
    first_seen = "2026-10-09 05:42:32"
  condition:
    hash.sha256(0, filesize) == "1981072e76c686dacae199ef1df3485874d3af313ec2203f32182019c110eb4b"
}

rule MalwareBazaar_Mirai_017_8008767e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8008767e83e3baa563ee9880881518dde6b43ae99f8c5585c05d61936f9d01dd"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-09 05:34:50"
  condition:
    hash.sha256(0, filesize) == "8008767e83e3baa563ee9880881518dde6b43ae99f8c5585c05d61936f9d01dd"
}

rule MalwareBazaar_unknown_018_606a58ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "606a58ec83b4767b4e7806903f2daa0eaf9e40d8299d84d881ccba490ffc20c2"
    family = "unknown"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-09 05:31:23"
  condition:
    hash.sha256(0, filesize) == "606a58ec83b4767b4e7806903f2daa0eaf9e40d8299d84d881ccba490ffc20c2"
}

rule MalwareBazaar_Mirai_019_a1bca91d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1bca91d3e2bd012c3e0dbe88e09062848c1cff602c990a541d7b1c9224ad16e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-09 05:24:21"
  condition:
    hash.sha256(0, filesize) == "a1bca91d3e2bd012c3e0dbe88e09062848c1cff602c990a541d7b1c9224ad16e"
}

rule MalwareBazaar_Mirai_020_d724dc8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d724dc8b5d6bb230f42a3ec0d5f71ccb8c8e9a88025756074b36961709ed1384"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-09 05:24:18"
  condition:
    hash.sha256(0, filesize) == "d724dc8b5d6bb230f42a3ec0d5f71ccb8c8e9a88025756074b36961709ed1384"
}

rule MalwareBazaar_Mirai_021_c0863e8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0863e8dbb46099ae4897fbdbf2dac14e0e2e2871d0595ee38d37b3fc44f3b36"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-09 05:20:52"
  condition:
    hash.sha256(0, filesize) == "c0863e8dbb46099ae4897fbdbf2dac14e0e2e2871d0595ee38d37b3fc44f3b36"
}

rule MalwareBazaar_Mirai_022_e867fc47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e867fc47c809868e46bbef459c4146b0ed111697d7672ce4c6623322afa2a1f4"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-09 05:17:11"
  condition:
    hash.sha256(0, filesize) == "e867fc47c809868e46bbef459c4146b0ed111697d7672ce4c6623322afa2a1f4"
}

rule MalwareBazaar_Mirai_023_25089d27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25089d27e69ec64c5d5887f8f67303db883fe0c373df6a8805ad960a313b1777"
    family = "Mirai"
    file_name = "vcimanagement.arm"
    file_type = "elf"
    first_seen = "2026-10-09 05:17:08"
  condition:
    hash.sha256(0, filesize) == "25089d27e69ec64c5d5887f8f67303db883fe0c373df6a8805ad960a313b1777"
}

rule MalwareBazaar_RemcosRAT_024_f2700a39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2700a394f0511ad48a420043258657b3c2617c3d7a1f377204e8f3b7540bb5a"
    family = "RemcosRAT"
    file_name = "CONTRACT DRAFT-EGP-25006-SG1-SLO-GS-0349.vbs"
    file_type = "vbs"
    first_seen = "2026-10-09 05:15:34"
  condition:
    hash.sha256(0, filesize) == "f2700a394f0511ad48a420043258657b3c2617c3d7a1f377204e8f3b7540bb5a"
}

rule MalwareBazaar_Mirai_025_b74cb101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b74cb10109cbd5d8dbfb3d2b34016991f69430fb9fc6553ddf7371a0e189c2ae"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-09 05:03:03"
  condition:
    hash.sha256(0, filesize) == "b74cb10109cbd5d8dbfb3d2b34016991f69430fb9fc6553ddf7371a0e189c2ae"
}

rule MalwareBazaar_unknown_026_178ee127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a"
    family = "unknown"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-09 04:47:32"
  condition:
    hash.sha256(0, filesize) == "178ee12744a15f48fb6ebfba3191af933b59b4c6a86f430175bc3a87a0d2710a"
}

rule MalwareBazaar_Formbook_027_3ea03e28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
    family = "Formbook"
    file_name = "Swift_Copy_IF01200022823419.exe"
    file_type = "exe"
    first_seen = "2026-10-09 04:37:52"
  condition:
    hash.sha256(0, filesize) == "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
}

rule MalwareBazaar_unknown_028_2524ca7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2524ca7fb873708b0e994ca5f6f18db95fcd5bc59c7e54eb5426b91658759142"
    family = "unknown"
    file_name = "client.jar"
    file_type = "jar"
    first_seen = "2026-10-09 03:53:51"
  condition:
    hash.sha256(0, filesize) == "2524ca7fb873708b0e994ca5f6f18db95fcd5bc59c7e54eb5426b91658759142"
}

rule MalwareBazaar_Mirai_029_ce5e8dde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce5e8dde18aef81faf1afb127da44e470d512f5f4f6a0d8d100361ba818fc043"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-09 03:36:33"
  condition:
    hash.sha256(0, filesize) == "ce5e8dde18aef81faf1afb127da44e470d512f5f4f6a0d8d100361ba818fc043"
}

rule MalwareBazaar_ValleyRAT_030_cf90ad8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf90ad8eef1b73e674f5dbbc12f8bbc4ee0ebc2b9485ddf5ef3cf5ce863f5333"
    family = "ValleyRAT"
    file_name = "ZillberReleyHost.exe"
    file_type = "exe"
    first_seen = "2026-10-09 03:24:25"
  condition:
    hash.sha256(0, filesize) == "cf90ad8eef1b73e674f5dbbc12f8bbc4ee0ebc2b9485ddf5ef3cf5ce863f5333"
}

rule MalwareBazaar_ValleyRAT_031_e292d65b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e292d65b134653448ef4bcad23eaae8b08abefcbfcd360c3f0cd74adfee33495"
    family = "ValleyRAT"
    file_name = "instdoload.1.3.13.exe"
    file_type = "exe"
    first_seen = "2026-10-09 03:23:02"
  condition:
    hash.sha256(0, filesize) == "e292d65b134653448ef4bcad23eaae8b08abefcbfcd360c3f0cd74adfee33495"
}

rule MalwareBazaar_ValleyRAT_032_84fd7e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84fd7e7de84bf9080ec938f944b81807faa769ab2e27a4d0a5f8596ff6dc0072"
    family = "ValleyRAT"
    file_name = "fdsfsffdsf.shop_313.exe"
    file_type = "exe"
    first_seen = "2026-10-09 03:20:58"
  condition:
    hash.sha256(0, filesize) == "84fd7e7de84bf9080ec938f944b81807faa769ab2e27a4d0a5f8596ff6dc0072"
}

rule MalwareBazaar_RemcosRAT_033_f12f4f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12f4f3fa2bca2716be80804bf35c6ef988c67af7a3a08e048ae65058833f58f"
    family = "RemcosRAT"
    file_name = "FedEx Shipment Documents.js"
    file_type = "js"
    first_seen = "2026-10-09 02:57:33"
  condition:
    hash.sha256(0, filesize) == "f12f4f3fa2bca2716be80804bf35c6ef988c67af7a3a08e048ae65058833f58f"
}

rule MalwareBazaar_ValleyRAT_034_b426e063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b426e063f6e71de0d8c7bd6b1ed9c342e3aed4e16ff9d0b50154c67b899f8541"
    family = "ValleyRAT"
    file_name = "F7D83D241F4A45EA7A97EA74A1016DFF.exe"
    file_type = "exe"
    first_seen = "2026-10-09 02:40:16"
  condition:
    hash.sha256(0, filesize) == "b426e063f6e71de0d8c7bd6b1ed9c342e3aed4e16ff9d0b50154c67b899f8541"
}

rule MalwareBazaar_Gh0stRAT_035_4ddf228d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8785f219f20197b32c9f"
    family = "Gh0stRAT"
    file_name = "4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8.dll"
    file_type = "dll"
    first_seen = "2026-10-09 02:20:12"
  condition:
    hash.sha256(0, filesize) == "4ddf228dbf2223bf9fd2348440eda53ca45de1ca1a2d8785f219f20197b32c9f"
}

rule MalwareBazaar_unknown_036_99ef0d24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ef0d24c29b2122a3ecad4a0b9f9dc9677a4838d0c41a5ab567b1acddee0524"
    family = "unknown"
    file_name = "DivX.exe"
    file_type = "exe"
    first_seen = "2026-10-09 02:19:44"
  condition:
    hash.sha256(0, filesize) == "99ef0d24c29b2122a3ecad4a0b9f9dc9677a4838d0c41a5ab567b1acddee0524"
}

rule MalwareBazaar_Mirai_037_4f3179dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f3179dce42f5c010b80304931d67fca6f5fcccbdd916b51785bc43a832af6d4"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-09 02:16:36"
  condition:
    hash.sha256(0, filesize) == "4f3179dce42f5c010b80304931d67fca6f5fcccbdd916b51785bc43a832af6d4"
}

rule MalwareBazaar_Mirai_038_2c247696
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c24769688bb6658599eed56478b3320d32d79a55da0da144079c146b7ea82d4"
    family = "Mirai"
    file_name = "vcimanagement.arm5"
    file_type = "elf"
    first_seen = "2026-10-09 01:51:45"
  condition:
    hash.sha256(0, filesize) == "2c24769688bb6658599eed56478b3320d32d79a55da0da144079c146b7ea82d4"
}

rule MalwareBazaar_RemusStealer_039_01ec79ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ec79ca328f90e03dd0c9ab0c115bacc279fa5eccea4cc03e4676dc9da78399"
    family = "RemusStealer"
    file_name = "Bootrsraptler_42.2.63286.exe"
    file_type = "exe"
    first_seen = "2026-10-09 01:50:30"
  condition:
    hash.sha256(0, filesize) == "01ec79ca328f90e03dd0c9ab0c115bacc279fa5eccea4cc03e4676dc9da78399"
}

rule MalwareBazaar_Mirai_040_61fba4eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b"
    family = "Mirai"
    file_name = "61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b.elf"
    file_type = "elf"
    first_seen = "2026-10-09 01:45:47"
  condition:
    hash.sha256(0, filesize) == "61fba4eb0df49bb5408ba96109a26cf7a64a2d123a4afff7b01b1a72f3d2c75b"
}

rule MalwareBazaar_Mirai_041_2fb5a098
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7"
    family = "Mirai"
    file_name = "2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7.elf"
    file_type = "elf"
    first_seen = "2026-10-09 01:45:40"
  condition:
    hash.sha256(0, filesize) == "2fb5a098919a7e2cc0ab7f2fddd8d082ff363650e7863341287527c608c642d7"
}

rule MalwareBazaar_unknown_042_639dd1de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "639dd1de39bccb7984585c453b482145a6ad7353007a8ea3cdbf01a65076e151"
    family = "unknown"
    file_name = "Services.apk"
    file_type = "apk"
    first_seen = "2026-10-09 01:43:09"
  condition:
    hash.sha256(0, filesize) == "639dd1de39bccb7984585c453b482145a6ad7353007a8ea3cdbf01a65076e151"
}

rule MalwareBazaar_unknown_043_c55e5bac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c55e5baca2162ac54e70de00a3d25b8a9a54617965eb36d1d7080f7d2e0460d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-09 01:41:47"
  condition:
    hash.sha256(0, filesize) == "c55e5baca2162ac54e70de00a3d25b8a9a54617965eb36d1d7080f7d2e0460d7"
}

rule MalwareBazaar_unknown_044_99410c62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99410c62ffbaf607a62c2badf53d84ae450cb187f3b211fb8b89dd640c687a4e"
    family = "unknown"
    file_name = "macho_99410c62ffba.bin"
    file_type = "macho"
    first_seen = "2026-10-09 01:30:03"
  condition:
    hash.sha256(0, filesize) == "99410c62ffbaf607a62c2badf53d84ae450cb187f3b211fb8b89dd640c687a4e"
}

rule MalwareBazaar_Mirai_045_5529d9ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5529d9ff7d84cb7a8db1f2d0ef9d50ff03488a7469d4ff156276521e30dd2d9d"
    family = "Mirai"
    file_name = "morte.sh4"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:36"
  condition:
    hash.sha256(0, filesize) == "5529d9ff7d84cb7a8db1f2d0ef9d50ff03488a7469d4ff156276521e30dd2d9d"
}

rule MalwareBazaar_Mirai_046_77840f54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77840f54cad6ff1badd14a0301f4b508bd657059a55bd83adb9e5c9116fb060e"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:33"
  condition:
    hash.sha256(0, filesize) == "77840f54cad6ff1badd14a0301f4b508bd657059a55bd83adb9e5c9116fb060e"
}

rule MalwareBazaar_Mirai_047_91fbcdb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91fbcdb39cc834cebb0898e90b0ef8eebaffef9ee24c8c04ab1b4c3fb94d5bbc"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:30"
  condition:
    hash.sha256(0, filesize) == "91fbcdb39cc834cebb0898e90b0ef8eebaffef9ee24c8c04ab1b4c3fb94d5bbc"
}

rule MalwareBazaar_Mirai_048_4df9902f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4df9902f81140d914a156af18f77534bcc4d1ad577ca91af97dfafb961aa72b4"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:27"
  condition:
    hash.sha256(0, filesize) == "4df9902f81140d914a156af18f77534bcc4d1ad577ca91af97dfafb961aa72b4"
}

rule MalwareBazaar_unknown_049_7a8de967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a8de9672d3697af7c6d30b286764b2790e8c448d0b05ed3d6fa5b6c6d8f8525"
    family = "unknown"
    file_name = "rathole-v048-armv7"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:25"
  condition:
    hash.sha256(0, filesize) == "7a8de9672d3697af7c6d30b286764b2790e8c448d0b05ed3d6fa5b6c6d8f8525"
}

rule MalwareBazaar_Mirai_050_cc0ab18f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc0ab18f186304dbb698dc167a9fd4e2582efa487e83eeed40b6a972cd141b2a"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:24"
  condition:
    hash.sha256(0, filesize) == "cc0ab18f186304dbb698dc167a9fd4e2582efa487e83eeed40b6a972cd141b2a"
}

rule MalwareBazaar_Mirai_051_793cfc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "793cfc2d1054179c987a21dfe328a6419d37e362584b8083c2b91500f31f1fe7"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:20"
  condition:
    hash.sha256(0, filesize) == "793cfc2d1054179c987a21dfe328a6419d37e362584b8083c2b91500f31f1fe7"
}

rule MalwareBazaar_Mirai_052_bff1a010
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bff1a0106509646f73c8aa2be4372668291b2204ad9a5ca1a622d5f30941dc5b"
    family = "Mirai"
    file_name = "morte.spc"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:17"
  condition:
    hash.sha256(0, filesize) == "bff1a0106509646f73c8aa2be4372668291b2204ad9a5ca1a622d5f30941dc5b"
}

rule MalwareBazaar_Mirai_053_703d34a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "703d34a8d6a70eedbb3bd431fb90990bb4a9f0da873d0e9ed9941ce3ea4a5556"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:14"
  condition:
    hash.sha256(0, filesize) == "703d34a8d6a70eedbb3bd431fb90990bb4a9f0da873d0e9ed9941ce3ea4a5556"
}

rule MalwareBazaar_Mirai_054_a2340ba1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2340ba1546cea741ea17fb6d84a51e39cfde541838836f801833d6a99999bc6"
    family = "Mirai"
    file_name = "mirai.x86"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:11"
  condition:
    hash.sha256(0, filesize) == "a2340ba1546cea741ea17fb6d84a51e39cfde541838836f801833d6a99999bc6"
}

rule MalwareBazaar_Mirai_055_f7dcabc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7dcabc1ecd5d8ce5f956488ce37563bcdd8a1d29c5d9b080377984e99edb9df"
    family = "Mirai"
    file_name = "mirai.arm"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:08"
  condition:
    hash.sha256(0, filesize) == "f7dcabc1ecd5d8ce5f956488ce37563bcdd8a1d29c5d9b080377984e99edb9df"
}

rule MalwareBazaar_Mirai_056_cc41fea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc41fea5a9b0a072b9f0a36a7610a682acbae747ce65265d0f43ccb4b184d8d9"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:05"
  condition:
    hash.sha256(0, filesize) == "cc41fea5a9b0a072b9f0a36a7610a682acbae747ce65265d0f43ccb4b184d8d9"
}

rule MalwareBazaar_Mirai_057_bbc09004
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbc090045e9171257096fbeef4bb6696ea9787a4d38b44a1cb16adaf1202401f"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-10-09 01:26:02"
  condition:
    hash.sha256(0, filesize) == "bbc090045e9171257096fbeef4bb6696ea9787a4d38b44a1cb16adaf1202401f"
}

rule MalwareBazaar_Mirai_058_0419e82d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0419e82dd1b5ed807540b2be4ba98789965b2e3a6011ab180a950dc5c58c7245"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-10-09 01:25:58"
  condition:
    hash.sha256(0, filesize) == "0419e82dd1b5ed807540b2be4ba98789965b2e3a6011ab180a950dc5c58c7245"
}

rule MalwareBazaar_Mirai_059_b10daff5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b10daff5af0638ea0b47cc205fac28f3a8246cbd0dad1f22a11055c90e375fc3"
    family = "Mirai"
    file_name = "mirai.arm5n"
    file_type = "elf"
    first_seen = "2026-10-09 01:25:56"
  condition:
    hash.sha256(0, filesize) == "b10daff5af0638ea0b47cc205fac28f3a8246cbd0dad1f22a11055c90e375fc3"
}

rule MalwareBazaar_unknown_060_5bdb3811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bdb3811a749e3af3e5832bdc778a45a43146ed66df97cfd715cbeadd872e379"
    family = "unknown"
    file_name = "rathole-v048-armv7"
    file_type = "elf"
    first_seen = "2026-10-09 01:25:52"
  condition:
    hash.sha256(0, filesize) == "5bdb3811a749e3af3e5832bdc778a45a43146ed66df97cfd715cbeadd872e379"
}

rule MalwareBazaar_unknown_061_f12b4f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12b4f28fa18b2cc0291cc8a146ae9e4ee0c772adf06cdda0b45fe9eb12dc3f3"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-09 01:12:15"
  condition:
    hash.sha256(0, filesize) == "f12b4f28fa18b2cc0291cc8a146ae9e4ee0c772adf06cdda0b45fe9eb12dc3f3"
}

rule MalwareBazaar_Mirai_062_aa684c1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3"
    family = "Mirai"
    file_name = "aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3.elf"
    file_type = "elf"
    first_seen = "2026-10-09 01:05:41"
  condition:
    hash.sha256(0, filesize) == "aa684c1bf96f4c4aa06295c39bd7a08ae3a12b042e1d5407f921f665d6fb20d3"
}

rule MalwareBazaar_Vidar_063_3800a41b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d"
    family = "Vidar"
    file_name = "3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d.exe"
    file_type = "exe"
    first_seen = "2026-10-09 00:58:56"
  condition:
    hash.sha256(0, filesize) == "3800a41b441e60803ac9ee6f700555619888b0b7a882ef557325f2b6b7843b2d"
}

rule MalwareBazaar_Vidar_064_aecef9ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995"
    family = "Vidar"
    file_name = "aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995.exe"
    file_type = "exe"
    first_seen = "2026-10-09 00:58:40"
  condition:
    hash.sha256(0, filesize) == "aecef9efaad031a5d0a5ec25d49138708f93a69bc50a7cee73fc2352ba19a995"
}

rule MalwareBazaar_unknown_065_ba0a5a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba0a5a40fac99dcbb4fd902650d3049c033fb52b31c2b0cd5e8276345bb49b7c"
    family = "unknown"
    file_name = "Tezzyhub.exe"
    file_type = "exe"
    first_seen = "2026-10-09 00:58:35"
  condition:
    hash.sha256(0, filesize) == "ba0a5a40fac99dcbb4fd902650d3049c033fb52b31c2b0cd5e8276345bb49b7c"
}

rule MalwareBazaar_unknown_066_5e3f5df1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e3f5df112be21b05e0f50da7d6868fd62d843da044cb1993c314dde69ad19e2"
    family = "unknown"
    file_name = "klogd-164-v5te"
    file_type = "elf"
    first_seen = "2026-10-09 00:57:32"
  condition:
    hash.sha256(0, filesize) == "5e3f5df112be21b05e0f50da7d6868fd62d843da044cb1993c314dde69ad19e2"
}

rule MalwareBazaar_RemcosRAT_067_4d90b19f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d90b19f8a3c224131db8f6e96a99a970b044c6392a4654ccd82fa8bce4adcb9"
    family = "RemcosRAT"
    file_name = "Abu Dhabi Police GHQ Ticket and Evidence of Offence .vbs"
    file_type = "vbs"
    first_seen = "2026-10-09 00:52:38"
  condition:
    hash.sha256(0, filesize) == "4d90b19f8a3c224131db8f6e96a99a970b044c6392a4654ccd82fa8bce4adcb9"
}

rule MalwareBazaar_AsyncRAT_068_b077215a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b077215af833ac80e92a57f8ab2613217e87f7f7aa9ed16ce9497f08de54d5f0"
    family = "AsyncRAT"
    file_name = "D3MANDA.RAD-2026-107067-00..js"
    file_type = "js"
    first_seen = "2026-10-09 00:48:20"
  condition:
    hash.sha256(0, filesize) == "b077215af833ac80e92a57f8ab2613217e87f7f7aa9ed16ce9497f08de54d5f0"
}

rule MalwareBazaar_Formbook_069_4e2d3b19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e2d3b193a9bfb9f3a369a251a1b722450fa13d8fc193d3c872ebf1062783fde"
    family = "Formbook"
    file_name = "PO50A-051141161_ORDER_DETAIL.com"
    file_type = "exe"
    first_seen = "2026-10-09 00:23:24"
  condition:
    hash.sha256(0, filesize) == "4e2d3b193a9bfb9f3a369a251a1b722450fa13d8fc193d3c872ebf1062783fde"
}

rule MalwareBazaar_Mirai_070_6afc6978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6afc6978ec9752ab4558a6c9cb1b62124619fe2bec6f727b09309f7a323d0eee"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-09 00:17:17"
  condition:
    hash.sha256(0, filesize) == "6afc6978ec9752ab4558a6c9cb1b62124619fe2bec6f727b09309f7a323d0eee"
}

rule MalwareBazaar_SilentNet_071_9d7bb13d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d7bb13d6ceee4ed10a90bd9c260e926613ee05bd5949b71051f40d38883f714"
    family = "SilentNet"
    file_name = "KryptonClient.jar"
    file_type = "jar"
    first_seen = "2026-10-09 00:12:34"
  condition:
    hash.sha256(0, filesize) == "9d7bb13d6ceee4ed10a90bd9c260e926613ee05bd5949b71051f40d38883f714"
}

rule MalwareBazaar_unknown_072_f08ab1a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342"
    family = "unknown"
    file_name = "f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342"
    file_type = "sh"
    first_seen = "2026-10-09 00:02:01"
  condition:
    hash.sha256(0, filesize) == "f08ab1a87db1149fad8a33977080dbc569974146c2479047fc99c489ffa0e342"
}

rule MalwareBazaar_Gafgyt_073_3a810e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f"
    family = "Gafgyt"
    file_name = "3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f"
    file_type = "sh"
    first_seen = "2026-10-09 00:01:53"
  condition:
    hash.sha256(0, filesize) == "3a810e0fbee30b2af13c04f12c51f5cba936c64077aea2a334e53b125920fd7f"
}

rule MalwareBazaar_unknown_074_9135f4d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c"
    family = "unknown"
    file_name = "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c.bin"
    file_type = "macho"
    first_seen = "2026-10-09 00:00:46"
  condition:
    hash.sha256(0, filesize) == "9135f4d24e45365b9680df64f6d0f51dba3a4ff7b740ca1cff3bc6b9998c474c"
}

rule MalwareBazaar_unknown_075_4ca810ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ca810ed33db741b86f8b3c07eec620456c23d4bf8737ed58781eba3c5b47029"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 23:38:52"
  condition:
    hash.sha256(0, filesize) == "4ca810ed33db741b86f8b3c07eec620456c23d4bf8737ed58781eba3c5b47029"
}

rule MalwareBazaar_unknown_076_f7a36521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34"
    family = "unknown"
    file_name = "f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34"
    file_type = "sh"
    first_seen = "2026-10-08 23:35:20"
  condition:
    hash.sha256(0, filesize) == "f7a365217cee30786abd3117313585bd27dbd4177194775e9899ff252e6e1a34"
}

rule MalwareBazaar_Mirai_077_1751d5c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1751d5c748f1af5d9229a43a3d9916a6b7cb21ed32af31d251e1c854053e108b"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-08 23:30:47"
  condition:
    hash.sha256(0, filesize) == "1751d5c748f1af5d9229a43a3d9916a6b7cb21ed32af31d251e1c854053e108b"
}

rule MalwareBazaar_Mirai_078_caa464e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa464e61f4adda038fd4c979b8d939ef1564e038baa925f9c90e5a803d41804"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 23:30:43"
  condition:
    hash.sha256(0, filesize) == "caa464e61f4adda038fd4c979b8d939ef1564e038baa925f9c90e5a803d41804"
}

rule MalwareBazaar_Mirai_079_b2273c5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2273c5a22de129ad1b886fcc1b9a3e3862389b5843a6c68d93554189efb8c2e"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-10-08 23:30:38"
  condition:
    hash.sha256(0, filesize) == "b2273c5a22de129ad1b886fcc1b9a3e3862389b5843a6c68d93554189efb8c2e"
}

rule MalwareBazaar_Mirai_080_550183dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "550183dc18026b2bd9be81c2ef1a32b64ccad2732d0268b29aef33acc73b9b4e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:27"
  condition:
    hash.sha256(0, filesize) == "550183dc18026b2bd9be81c2ef1a32b64ccad2732d0268b29aef33acc73b9b4e"
}

rule MalwareBazaar_Mirai_081_3330f9f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3330f9f5be2b0b4fb0bffc7ceb770deb2dbbc798dcf421d55812700ad76e2f0b"
    family = "Mirai"
    file_name = "Space.arc"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:23"
  condition:
    hash.sha256(0, filesize) == "3330f9f5be2b0b4fb0bffc7ceb770deb2dbbc798dcf421d55812700ad76e2f0b"
}

rule MalwareBazaar_Mirai_082_36324af6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36324af60466940192d18de84a07ac6d897a163bf4a5d296257f10856a95d6e7"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:22"
  condition:
    hash.sha256(0, filesize) == "36324af60466940192d18de84a07ac6d897a163bf4a5d296257f10856a95d6e7"
}

rule MalwareBazaar_Mirai_083_e8ce0703
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ce0703b89472af190b043ff6990ad166a7251ebe1b3fc9621b2796827719af"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:21"
  condition:
    hash.sha256(0, filesize) == "e8ce0703b89472af190b043ff6990ad166a7251ebe1b3fc9621b2796827719af"
}

rule MalwareBazaar_Mirai_084_577351cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "577351cb939eda8db3c9debe35731085c4b12e723995565e4d445844249fb72e"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:19"
  condition:
    hash.sha256(0, filesize) == "577351cb939eda8db3c9debe35731085c4b12e723995565e4d445844249fb72e"
}

rule MalwareBazaar_Mirai_085_faec6566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faec6566b457866387e647b16235b747bff7404a06e95048474189d59a2ad81e"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:16"
  condition:
    hash.sha256(0, filesize) == "faec6566b457866387e647b16235b747bff7404a06e95048474189d59a2ad81e"
}

rule MalwareBazaar_Mirai_086_37fb1412
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37fb141242998ee64251670fd41c6a9005680d81e8a4b9839064b9eb203fa4f3"
    family = "Mirai"
    file_name = "Space"
    file_type = "elf"
    first_seen = "2026-10-08 23:29:14"
  condition:
    hash.sha256(0, filesize) == "37fb141242998ee64251670fd41c6a9005680d81e8a4b9839064b9eb203fa4f3"
}

rule MalwareBazaar_Mirai_087_33ea1acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33ea1acbfd8fe260fc4394f34652f90509f602e6da51a97a0c75fd39006fb30f"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:20"
  condition:
    hash.sha256(0, filesize) == "33ea1acbfd8fe260fc4394f34652f90509f602e6da51a97a0c75fd39006fb30f"
}

rule MalwareBazaar_Mirai_088_3ad99b41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ad99b41929cbbbde9c2f97c4ab10065af1f8fcad08e2c443975f4d83c561c89"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:18"
  condition:
    hash.sha256(0, filesize) == "3ad99b41929cbbbde9c2f97c4ab10065af1f8fcad08e2c443975f4d83c561c89"
}

rule MalwareBazaar_Mirai_089_242b9b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "242b9b5614d4eb7a645c8deca0356ee9d6226395c6ed94469a694ee90faa5d8c"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:15"
  condition:
    hash.sha256(0, filesize) == "242b9b5614d4eb7a645c8deca0356ee9d6226395c6ed94469a694ee90faa5d8c"
}

rule MalwareBazaar_Mirai_090_6f70689f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f70689f8ecdfb7dd540cb83d8a462e1de8846c182ababbf6c0c3fcfdcf24987"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-08 23:28:13"
  condition:
    hash.sha256(0, filesize) == "6f70689f8ecdfb7dd540cb83d8a462e1de8846c182ababbf6c0c3fcfdcf24987"
}

rule MalwareBazaar_unknown_091_0886e17b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0886e17b38d09ef7b0855a2394dd33454939edb3f33a43096c93e0dccfe6a81c"
    family = "unknown"
    file_name = "lgtvx64"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:30"
  condition:
    hash.sha256(0, filesize) == "0886e17b38d09ef7b0855a2394dd33454939edb3f33a43096c93e0dccfe6a81c"
}

rule MalwareBazaar_unknown_092_f8b973a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b973a2386d9095f12e0e6192b77c1b7e2408a4c48f56b33f9e3ef362a9935b"
    family = "unknown"
    file_name = "lgtvarm64"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:27"
  condition:
    hash.sha256(0, filesize) == "f8b973a2386d9095f12e0e6192b77c1b7e2408a4c48f56b33f9e3ef362a9935b"
}

rule MalwareBazaar_unknown_093_f304c1bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f304c1bfc082214a49bc57db5cf41acb86b11a5a192a56d29a2cae5035753418"
    family = "unknown"
    file_name = "lgtvarmv7"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:24"
  condition:
    hash.sha256(0, filesize) == "f304c1bfc082214a49bc57db5cf41acb86b11a5a192a56d29a2cae5035753418"
}

rule MalwareBazaar_unknown_094_163cb287
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163cb287fd8f81c13901eb4ddaea2db326213f4d2095e0e64321b9afd8300480"
    family = "unknown"
    file_name = "lgtv32"
    file_type = "elf"
    first_seen = "2026-10-08 23:27:21"
  condition:
    hash.sha256(0, filesize) == "163cb287fd8f81c13901eb4ddaea2db326213f4d2095e0e64321b9afd8300480"
}

rule MalwareBazaar_unknown_095_f8ce88a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ce88a265e20c968d475680ca712ff43d5f81caf94cd17d63fd30e92c6928eb"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-10-08 23:26:48"
  condition:
    hash.sha256(0, filesize) == "f8ce88a265e20c968d475680ca712ff43d5f81caf94cd17d63fd30e92c6928eb"
}

rule MalwareBazaar_unknown_096_4807236c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4807236cfb7d8305e246c519b46ca558704a239b17c9eef9545ab7bb79154229"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-10-08 23:26:46"
  condition:
    hash.sha256(0, filesize) == "4807236cfb7d8305e246c519b46ca558704a239b17c9eef9545ab7bb79154229"
}

rule MalwareBazaar_unknown_097_eb367b7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb367b7ba3be78fa066f7c6a28e11f5f165b001312bec229cef7aee310f4d9b1"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-10-08 23:26:44"
  condition:
    hash.sha256(0, filesize) == "eb367b7ba3be78fa066f7c6a28e11f5f165b001312bec229cef7aee310f4d9b1"
}

rule MalwareBazaar_Vidar_098_38dbcfe9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38dbcfe9e766a0b1a15c90e021febb42d75fd103328a6e1361fbb75ea1664f7e"
    family = "Vidar"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-08 23:20:34"
  condition:
    hash.sha256(0, filesize) == "38dbcfe9e766a0b1a15c90e021febb42d75fd103328a6e1361fbb75ea1664f7e"
}

rule MalwareBazaar_SilentNet_099_f6bbc27e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6bbc27e48c8e8aeb83dd944086d5ba9655f5c170672241e5d3e1c5d8f6e3d48"
    family = "SilentNet"
    file_name = "mod.jar"
    file_type = "jar"
    first_seen = "2026-10-08 23:08:59"
  condition:
    hash.sha256(0, filesize) == "f6bbc27e48c8e8aeb83dd944086d5ba9655f5c170672241e5d3e1c5d8f6e3d48"
}

rule MalwareBazaar_RemusStealer_100_de007a3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de007a3bc1cfcdf8985690b5127eb099292a3edfd6f4f7b462c65229011a669b"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 22:59:18"
  condition:
    hash.sha256(0, filesize) == "de007a3bc1cfcdf8985690b5127eb099292a3edfd6f4f7b462c65229011a669b"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

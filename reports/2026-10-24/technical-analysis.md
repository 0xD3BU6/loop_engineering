# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-24

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 667 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 667 |
| Unique family labels | 11 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 47 |
| Mirai | 35 |
| SalatStealer | 7 |
| RustyStealer | 3 |
| DDoSAgent | 2 |
| Adware.OfferCore | 1 |
| ConnectWise | 1 |
| GoToResolve | 1 |
| CoinMiner | 1 |
| RemusStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 42 |
| exe | 30 |
| macho | 14 |
| msi | 4 |
| js | 2 |
| sh | 2 |
| ps1 | 1 |
| 7z | 1 |
| bat | 1 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `f5cfe0cf4f22c4ca`

| Field | Value |
|---|---|
| SHA-256 | `f5cfe0cf4f22c4cabae5ac6d031e83986f6942a5d3178dcd6ee91231f4600520` |
| Family label | `unknown` |
| File name | `f5cfe0cf4f22c4ca.js` |
| File type | `js` |
| First seen | `2026-10-24 04:45:45` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ae26fd76b60605d29112e5100a06a17` |
| SHA-1 | `bfb4c69b4b6ce584e27cb59af7b17283e8ed7d55` |
| SHA-256 | `f5cfe0cf4f22c4cabae5ac6d031e83986f6942a5d3178dcd6ee91231f4600520` |
| SHA3-384 | `dc124f0b67b26439511feaa60434392cb407c4b973b686039c112fe1f2470fed8a6bfcd1c17c41590b9f825a2d7e455c` |
| TLSH | `T178A45DC57186B0E6A7D704E698BF4248F63459043809C460F0ACFDDA3A669DBB273F5E` |
| SSDEEP | `12288:TS5Ars3PpzX1OfgNxn3OdAkqpFOlTvSH7ZyMwmPwH5n:TS5Ar/AOlTvSIZn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_f5cfe0cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5cfe0cf4f22c4cabae5ac6d031e83986f6942a5d3178dcd6ee91231f4600520"
    family = "unknown"
    file_name = "f5cfe0cf4f22c4ca.js"
    file_type = "js"
    first_seen = "2026-10-24 04:45:45"
  condition:
    hash.sha256(0, filesize) == "f5cfe0cf4f22c4cabae5ac6d031e83986f6942a5d3178dcd6ee91231f4600520"
}
```

### Sample 2: `f9a52c71cf014bdf`

| Field | Value |
|---|---|
| SHA-256 | `f9a52c71cf014bdfe827b0e8c60e6c41caac4e498b46d998f4a1c40b6eb37ff9` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.i686` |
| File type | `elf` |
| First seen | `2026-10-24 04:13:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5a2c5d2852771bb77890521b8bd3571` |
| SHA-1 | `79935be78602b79bd73493d8c904e2e954d81dcd` |
| SHA-256 | `f9a52c71cf014bdfe827b0e8c60e6c41caac4e498b46d998f4a1c40b6eb37ff9` |
| SHA3-384 | `ba8d5d2b5916f5037ec33eb683c3b0d933fc2d821766476c54d742d6fa7d873a40576e65d00f19624ef99e11d6467ff9` |
| TLSH | `T1E8931981F8C745F6C807493450A7F33FCE32E47A813196ADEF99AF36DA77601911229A` |
| TELFHASH | `t1ed1106f6f53a0de8a7e09807ef0d6b90dc0eb9bf7160659206fb601536630a461b8d38` |
| SSDEEP | `1536:8qut0gR4/HEI2E1pMphR66rAm1XJmdfptWxix9FMWYOa5XYV9QAgeDqn:8quugR4H2E1pMrR66rAmJQ0UxwDXe9QB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_f9a52c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9a52c71cf014bdfe827b0e8c60e6c41caac4e498b46d998f4a1c40b6eb37ff9"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.i686"
    file_type = "elf"
    first_seen = "2026-10-24 04:13:43"
  condition:
    hash.sha256(0, filesize) == "f9a52c71cf014bdfe827b0e8c60e6c41caac4e498b46d998f4a1c40b6eb37ff9"
}
```

### Sample 3: `3ab069c4c650c4ff`

| Field | Value |
|---|---|
| SHA-256 | `3ab069c4c650c4ff1c8fa4dde90c8691b316a0aadf5693d56ec29370b6dc9d2c` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-24 04:09:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68bb51b9fe9d4f1ab95f9b8452f4b6f0` |
| SHA-1 | `2734503886a37d5d0866b734ab1533c8b1b0908c` |
| SHA-256 | `3ab069c4c650c4ff1c8fa4dde90c8691b316a0aadf5693d56ec29370b6dc9d2c` |
| SHA3-384 | `96621e524d3d82610bb6b739c658b3fc6574218a86a5b74be7d43d30cfa0e6d59348252c8e1ed857b33cdbb027af1f60` |
| TLSH | `T19C556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmH:OSCX9B9tGNnD+pb0qAYPWTM2wza6y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_3ab069c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab069c4c650c4ff1c8fa4dde90c8691b316a0aadf5693d56ec29370b6dc9d2c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 04:09:40"
  condition:
    hash.sha256(0, filesize) == "3ab069c4c650c4ff1c8fa4dde90c8691b316a0aadf5693d56ec29370b6dc9d2c"
}
```

### Sample 4: `ba44d153f9a5892c`

| Field | Value |
|---|---|
| SHA-256 | `ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.spc` |
| File type | `elf` |
| First seen | `2026-10-24 04:05:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3518eb01ecc62a4bcc78db5bdb14bee0` |
| SHA-1 | `87855456d45e71c97454a06f454c9e073c704a40` |
| SHA-256 | `ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787` |
| SHA3-384 | `9599881443d192f1fca362a5e4c00768515c274f566076403bc508c6c623a4274af5c2e647494c004bd1cc874b14001c` |
| TLSH | `T14B934A25687A2E17C8D4A23E11F78752F2F5370E24B0C66E7D760F8EFF15680A5462B2` |
| SSDEEP | `1536:1KFdSaiZ2vPhnKORFS5P+lSMrhJ3HWwJnV6WOXPauvAs8:WNrZKl1NM9J32wJnV6WOXbvY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_ba44d153
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.spc"
    file_type = "elf"
    first_seen = "2026-10-24 04:05:41"
  condition:
    hash.sha256(0, filesize) == "ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787"
}
```

### Sample 5: `40f4b0593bec556d`

| Field | Value |
|---|---|
| SHA-256 | `40f4b0593bec556d663b11046e1e54488044eddbf314341b3ac4f5d733eb2de9` |
| Family label | `Mirai` |
| File name | `MMaaRRiiOisecTanee.sh4` |
| File type | `elf` |
| First seen | `2026-10-24 03:57:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca234c6a6fc10d1c875fd77bdc2fe2cd` |
| SHA-1 | `25cce6b7da60e418bd855300ee2844939243ee1e` |
| SHA-256 | `40f4b0593bec556d663b11046e1e54488044eddbf314341b3ac4f5d733eb2de9` |
| SHA3-384 | `e311664298885aa5f7a3ea31b0a298de694c0f5f5f226c1473da65f7ccf11d0b7aa58d7dd872ba45f7b24424f25e6653` |
| TLSH | `T1DA739D75D0B86D98C5048A34A6ACD9B88B17A404A7A33FF2C681CF650447EFCF6157FA` |
| SSDEEP | `1536://kM1TnB8BwtVNYDe2tGvESrFRwUpKsPEQfCT8D:/MMJneB48jSpqYxPEQf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_40f4b059
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f4b0593bec556d663b11046e1e54488044eddbf314341b3ac4f5d733eb2de9"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.sh4"
    file_type = "elf"
    first_seen = "2026-10-24 03:57:38"
  condition:
    hash.sha256(0, filesize) == "40f4b0593bec556d663b11046e1e54488044eddbf314341b3ac4f5d733eb2de9"
}
```

### Sample 6: `a56f66cc45cd083f`

| Field | Value |
|---|---|
| SHA-256 | `a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2` |
| Family label | `unknown` |
| File name | `2be0cf0161e40183.bin` |
| File type | `elf` |
| First seen | `2026-10-24 03:26:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a6d7958a03e265cbf4271a5111c8195` |
| SHA-1 | `7d25dec6dc3faffba9819efa7e23d4f448aad07e` |
| SHA-256 | `a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2` |
| SHA3-384 | `2df161f53cecee5af9e8d5cc817b2959a27fc5d42b10874b52a20464155b093d6968373eaccd04428942f0e3d3b29471` |
| TLSH | `T195662712FECB14F6E903193104BBA27F27315D058B24EB87EB407E29FD7B6A55932219` |
| TELFHASH | `t1942186b590f638452094052a8ec20c615f06a4e86776552b894f6ffa67c7ac48df312a` |
| SSDEEP | `98304:/UB3H3Ng3uFkoG2I4dky07hVS19aWHyE6l:/43Ng3PoG2IXVS19RfW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_a56f66cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2"
    family = "unknown"
    file_name = "2be0cf0161e40183.bin"
    file_type = "elf"
    first_seen = "2026-10-24 03:26:24"
  condition:
    hash.sha256(0, filesize) == "a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2"
}
```

### Sample 7: `d1ab5c35e09e0d0b`

| Field | Value |
|---|---|
| SHA-256 | `d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af` |
| Family label | `RustyStealer` |
| File name | `d1ab5c35e09e0d0b.bin` |
| File type | `exe` |
| First seen | `2026-10-24 03:26:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4902f4ba2bd67972289fbd9ce15ba560` |
| SHA-1 | `b0da124d0516528253f93109f57ab11c2ddc6c0b` |
| SHA-256 | `d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af` |
| SHA3-384 | `6c37100df2f94e7910062d27a2d36766c3c048365f622ead78009b250af07a9a3c0d23ec8825b5e88a01d82ff475f654` |
| IMPHASH | `8350bff92a4ce77b7f869c99c2e7eb1c` |
| TLSH | `T18C957C03E69581FCD49EC078C7579632EA22BC8E0920B6BB27D09B253E66F505F1DB1D` |
| SSDEEP | `24576:n+APnoYvzI6DwUGGD4UQ6ZbKvDuhxlu+W5LWH99FjaNNEqdOmTVIH06iy9FM:nFno8k6NKUQ6xju++KH99Far9BIU6is` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_007_d1ab5c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af"
    family = "RustyStealer"
    file_name = "d1ab5c35e09e0d0b.bin"
    file_type = "exe"
    first_seen = "2026-10-24 03:26:05"
  condition:
    hash.sha256(0, filesize) == "d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af"
}
```

### Sample 8: `bdff003f47f176d4`

| Field | Value |
|---|---|
| SHA-256 | `bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36` |
| Family label | `RustyStealer` |
| File name | `bdff003f47f176d4.bin` |
| File type | `exe` |
| First seen | `2026-10-24 03:25:55` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `491fee22edfa785911d113c4118c7a30` |
| SHA-1 | `61b08489f490887c33c95bcc133041f138ef16ea` |
| SHA-256 | `bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36` |
| SHA3-384 | `450a927b0c2ab1f9694fde753fbccbc3a1a1e8d83e63d3cdf7774b962fe1bf5e903b35a6df1ff3c1858efebd20696616` |
| IMPHASH | `8350bff92a4ce77b7f869c99c2e7eb1c` |
| TLSH | `T16B957C47E69580FCD49EC078C3579732EA22BC8D0920B6AB27D09B653E76F506F0DB19` |
| SSDEEP | `24576:6+APnoYtzk6DwUGGD4UQ6ZbKvDuhxlu+W5LWH99FjaNNdGVqdOmTVIH06iy9FM:6Fno+I6NKUQ6xju++KH99FarFBIU6is` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_008_bdff003f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36"
    family = "RustyStealer"
    file_name = "bdff003f47f176d4.bin"
    file_type = "exe"
    first_seen = "2026-10-24 03:25:55"
  condition:
    hash.sha256(0, filesize) == "bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36"
}
```

### Sample 9: `2be0cf0161e40183`

| Field | Value |
|---|---|
| SHA-256 | `2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d` |
| Family label | `unknown` |
| File name | `2be0cf0161e40183.bin` |
| File type | `elf` |
| First seen | `2026-10-24 03:25:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai, upx, xorddos` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81ce3645e577572099f2343a597ed2c0` |
| SHA-1 | `0b75703934f99f5b0527b3bb46a8c5e4bd4e81ba` |
| SHA-256 | `2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d` |
| SHA3-384 | `1679bf6ceabebeda83d9a5614dcbc46618e9378b4f67a9ac22f8f55e25fd91f51a92a62897944202f45bc7931ba21a1d` |
| TLSH | `T160D533D5D3C7147EAC23877772F20857661CA4BFA26E1C5FBB9B5E4684BA18080D08BD` |
| TELFHASH | `t14aa002d159ce4addc1613c5dc02369144006974f399a1f1343a18b79fa8de2033c2af5` |
| SSDEEP | `49152:txKWy9EaRaP+e1EHI3i5Ha/DRf2ov+lIx8M1LEtMbwTz72Dfv:vKWy2P+e1EHqWH2FF+lcbcK4z72Dfv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_2be0cf01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d"
    family = "unknown"
    file_name = "2be0cf0161e40183.bin"
    file_type = "elf"
    first_seen = "2026-10-24 03:25:46"
  condition:
    hash.sha256(0, filesize) == "2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d"
}
```

### Sample 10: `d65fec3809cf4341`

| Field | Value |
|---|---|
| SHA-256 | `d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0` |
| Family label | `RustyStealer` |
| File name | `d65fec3809cf4341.bin` |
| File type | `exe` |
| First seen | `2026-10-24 03:25:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fde2e6448bd610d74350aa22d857ea2` |
| SHA-1 | `451557402efaf5cfac916540e21840bd7c8eb8ed` |
| SHA-256 | `d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0` |
| SHA3-384 | `a2f41f30c8194db60b060890a093ad220c7b0860d4ae920a83c25e94ebec50a493bf6f9135e2edd08d7a783bcbe0cf3a` |
| IMPHASH | `603a12af845feb44eeaee4af0f3efa0b` |
| TLSH | `T172A57D07E69580E8D59EC078C3579633EA22B88D0920B6BB27D09B353E3AF515F1DB1D` |
| SSDEEP | `49152:2yq6nhizXRpuk+XZDh5KyR7F/2v76WwIU6istJ6:2ydQgJF+v7TP+s` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_010_d65fec38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0"
    family = "RustyStealer"
    file_name = "d65fec3809cf4341.bin"
    file_type = "exe"
    first_seen = "2026-10-24 03:25:35"
  condition:
    hash.sha256(0, filesize) == "d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0"
}
```

### Sample 11: `b1bf43f0327f500b`

| Field | Value |
|---|---|
| SHA-256 | `b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7` |
| Family label | `unknown` |
| File name | `redtail.arm7` |
| File type | `elf` |
| First seen | `2026-10-24 03:23:11` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09617212d5cde5d840d860b9604a438e` |
| SHA-1 | `c300b3bd27aa646188e0a1922f54a9287ab64803` |
| SHA-256 | `b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7` |
| SHA3-384 | `9ead7164e626e9d87e2222dc526098206f9a1d7f7bf00eed32db36eb3664b0cdf23258d9dc09a7903e9338d81e9cfee0` |
| TLSH | `T119A42387850B59E7ED4B78EEC88CC9B724149154F88CFE127EA676E2531FC97411B60C` |
| SSDEEP | `12288:5MD5fD8ji3GmN8wL45SDHJZuH+Q7M0xyHCsQ5Z+eD0a:5MVf5G045SzJ+M0xyHyZ+W` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_b1bf43f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7"
    family = "unknown"
    file_name = "redtail.arm7"
    file_type = "elf"
    first_seen = "2026-10-24 03:23:11"
  condition:
    hash.sha256(0, filesize) == "b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7"
}
```

### Sample 12: `edcd4de69b7e4c14`

| Field | Value |
|---|---|
| SHA-256 | `edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90` |
| Family label | `Mirai` |
| File name | `bix.sh` |
| File type | `elf` |
| First seen | `2026-10-24 03:22:39` |
| Reporter | `adliwahid` |
| Tags | `Dakkatoni, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25e3a3b7d8b2a95a967538f331577c46` |
| SHA-1 | `31cd482000f10047d9bd53698953bb3c8e8d15ae` |
| SHA-256 | `edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90` |
| SHA3-384 | `4d5eb5a78d8e99f21ac1c5d3913757727d386475a5b03b71dc3f435da2611d0edb7251dfc4205bae27bb0fa91c12ddf5` |
| TLSH | `T1EB6401CBEB11BC3BD940077125AB0B5DF7B8DA9A82C7E180F294C55E3CBA285B7911C5` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ10xioqa5POdOQ33QE:p3lOYoaja8xzx/0wsxzSiKPqOJE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_edcd4de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90"
    family = "Mirai"
    file_name = "bix.sh"
    file_type = "elf"
    first_seen = "2026-10-24 03:22:39"
  condition:
    hash.sha256(0, filesize) == "edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90"
}
```

### Sample 13: `da54c10718b4649e`

| Field | Value |
|---|---|
| SHA-256 | `da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303` |
| Family label | `Mirai` |
| File name | `lv.sh` |
| File type | `sh` |
| First seen | `2026-10-24 03:21:09` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed422f2302ff32c86fcabe9fdc95dd79` |
| SHA-1 | `8eb6580333b38399afd58600016e157efd58a9f4` |
| SHA-256 | `da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303` |
| SHA3-384 | `5576ea4cd8d03b4a27b0264be0a400796ac88ba4011c1ac2d1a645f1b4807176c5958a8de7faedb6e398853171883a5e` |
| TLSH | `T11131ACF5D156C131E14A063C6A0AB2A427CA0D11FAB4D14F78FE8E486B4E998BC59B33` |
| SSDEEP | `24:UE3CqEpXALxL6D91lXDOjtpsX2ClHyDzN0UH9HeZuCp+LXLrLexXkSjbB:058tczDstpsmCVIfd6eLXLrLexbjV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_da54c107
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303"
    family = "Mirai"
    file_name = "lv.sh"
    file_type = "sh"
    first_seen = "2026-10-24 03:21:09"
  condition:
    hash.sha256(0, filesize) == "da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303"
}
```

### Sample 14: `96082e1bb5350495`

| Field | Value |
|---|---|
| SHA-256 | `96082e1bb5350495ce83fe6ad1c26cfde4c31171c0f200bc68585d2d08f3d9ef` |
| Family label | `unknown` |
| File name | `96082e1bb5350495.bin` |
| File type | `exe` |
| First seen | `2026-10-24 02:26:16` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74a980406f8b15986960ca7de5bd45a1` |
| SHA-1 | `707f283d5fed6838027dc8c3b30535d77f7f83d0` |
| SHA-256 | `96082e1bb5350495ce83fe6ad1c26cfde4c31171c0f200bc68585d2d08f3d9ef` |
| SHA3-384 | `70330510f857012354700dcd01457f606934a1cb59a71ac97160cb975c829e9d92f8e244a196a954d6eca3170d97b2c1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EED63378ABBD0C83D2F763B06A6692834A3021478E01CA48775D165C1FADF0FD976B5B` |
| SSDEEP | `393216:nz8yoCt3G3PafufiSrRoHCX2Eo1jgxFnfKX:zHoCt3G3y8iCRmjkxFnfk` |
| ICON-DHASH | `e464a4a4b5d1e0c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_96082e1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96082e1bb5350495ce83fe6ad1c26cfde4c31171c0f200bc68585d2d08f3d9ef"
    family = "unknown"
    file_name = "96082e1bb5350495.bin"
    file_type = "exe"
    first_seen = "2026-10-24 02:26:16"
  condition:
    hash.sha256(0, filesize) == "96082e1bb5350495ce83fe6ad1c26cfde4c31171c0f200bc68585d2d08f3d9ef"
}
```

### Sample 15: `8c35b7d47f658322`

| Field | Value |
|---|---|
| SHA-256 | `8c35b7d47f65832206369e00760fea41bf20e023596cd2dad966d02bafa93151` |
| Family label | `Adware.OfferCore` |
| File name | `8c35b7d47f658322.bin` |
| File type | `exe` |
| First seen | `2026-10-24 02:26:01` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cec00169239d26be042583a4686a7443` |
| SHA-1 | `aa3fe7778d9051e21b2c743c721ccffdb1a4ac2b` |
| SHA-256 | `8c35b7d47f65832206369e00760fea41bf20e023596cd2dad966d02bafa93151` |
| SHA3-384 | `c58ba3aa74a3c8fb1de2d1af605d1742b5e8743dd7b2b9ef146f386baab0030f7b6898808859a9991588f879271ce1fa` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1A9A5D03FB28B653EE06E5A3A7A72E210583B7A6165138C5696F4C84CCF254701E3F787` |
| SSDEEP | `24576:AXNrSLScusMmOvjjhzvLt71KBTdgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXcQ:/uI2h4TdHcTeynRkfg7ve+AhrWzOUe` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_015_8c35b7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c35b7d47f65832206369e00760fea41bf20e023596cd2dad966d02bafa93151"
    family = "Adware.OfferCore"
    file_name = "8c35b7d47f658322.bin"
    file_type = "exe"
    first_seen = "2026-10-24 02:26:01"
  condition:
    hash.sha256(0, filesize) == "8c35b7d47f65832206369e00760fea41bf20e023596cd2dad966d02bafa93151"
}
```

### Sample 16: `ef67a672ece71861`

| Field | Value |
|---|---|
| SHA-256 | `ef67a672ece71861f810bdff3e9bdbf5bc14daa347861bed3ce1d1dddb68031c` |
| Family label | `unknown` |
| File name | `ef67a672ece71861.bin` |
| File type | `exe` |
| First seen | `2026-10-24 01:24:19` |
| Reporter | `Tuxxin` |
| Tags | `babar, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74bb598c262cab9ebd8a58f20a895055` |
| SHA-1 | `54aec96ccef8d1f0bf94e3276f4f5c09ecf30d4a` |
| SHA-256 | `ef67a672ece71861f810bdff3e9bdbf5bc14daa347861bed3ce1d1dddb68031c` |
| SHA3-384 | `8ef00347ce23b9aeb627500481275d788c9b43e37af2956f1cb811d3c2dd578787991fed5f03121e47656a12fdfc48b9` |
| IMPHASH | `d2c343dfa64814708e628846a41e3e94` |
| TLSH | `T106E63342FA9B49E3E98F14B0599572EBC31D3F84DC14D8B2D654BE87EC32B71B049688` |
| SSDEEP | `393216:31KzB6u3Yiv3wEUV3m7yYzNvjl09eE4OdsI:s0uoivJ2p2VjiiI` |
| ICON-DHASH | `800e2b37132b0ec0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_ef67a672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef67a672ece71861f810bdff3e9bdbf5bc14daa347861bed3ce1d1dddb68031c"
    family = "unknown"
    file_name = "ef67a672ece71861.bin"
    file_type = "exe"
    first_seen = "2026-10-24 01:24:19"
  condition:
    hash.sha256(0, filesize) == "ef67a672ece71861f810bdff3e9bdbf5bc14daa347861bed3ce1d1dddb68031c"
}
```

### Sample 17: `26e0644cf7ad60cc`

| Field | Value |
|---|---|
| SHA-256 | `26e0644cf7ad60cc0d8aebe5381251eacc124860a969cb5db5c8aab83c86a2b3` |
| Family label | `unknown` |
| File name | `26e0644cf7ad60cc.bin` |
| File type | `exe` |
| First seen | `2026-10-24 01:24:07` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fa9c0a151cf3638c103765f158af242` |
| SHA-1 | `a2518f469044df9fa50e4f509ee39e673c3d5532` |
| SHA-256 | `26e0644cf7ad60cc0d8aebe5381251eacc124860a969cb5db5c8aab83c86a2b3` |
| SHA3-384 | `aaebf9b2abcf235a9c4bff9beedae31d188e96998843ab96e1195c10de89b45b215dc8dbec374b0904f06a9d43f0003e` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T188763807ECA558E8C1AED23489769513BF70BC494B3127D71B90F6242F76BE0ADB9384` |
| SSDEEP | `49152:uep6lLA4hkJl9CaCegH4ChMzvoIz/JCPSth3MR92d5DUM7X4a3NVtxaGDOjkKCKr:u99mDxCOzr9KEoEoa7DsA2TEo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_26e0644c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e0644cf7ad60cc0d8aebe5381251eacc124860a969cb5db5c8aab83c86a2b3"
    family = "unknown"
    file_name = "26e0644cf7ad60cc.bin"
    file_type = "exe"
    first_seen = "2026-10-24 01:24:07"
  condition:
    hash.sha256(0, filesize) == "26e0644cf7ad60cc0d8aebe5381251eacc124860a969cb5db5c8aab83c86a2b3"
}
```

### Sample 18: `ec742d1bb8e067b6`

| Field | Value |
|---|---|
| SHA-256 | `ec742d1bb8e067b6acb1acb1dbbbcbd8f5505e47a3561bfbd5b4068771d4d5b7` |
| Family label | `ConnectWise` |
| File name | `ec742d1bb8e067b6.bin` |
| File type | `msi` |
| First seen | `2026-10-24 01:23:55` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10f1bd06de6a136e2d969c8662f31fd9` |
| SHA-1 | `7003c1d37a5c484c72ab722540a2e6dd1a39dfba` |
| SHA-256 | `ec742d1bb8e067b6acb1acb1dbbbcbd8f5505e47a3561bfbd5b4068771d4d5b7` |
| SHA3-384 | `09ee4da0b5a93d0b0de620d2e27bffef484e9f762688e533100cd72a127efcb4be15cfff2d618e74331d8e5a98c75212` |
| TLSH | `T158D623116BF89278F0F22A35E876A0B1A5377D525E22D12E2324791E2C75EC0C9B3777` |
| SSDEEP | `196608:KHxcp9ym3nltDUJVlHxcp9ym3iHxcp9ym38Hxcp9ym3vHxcp9ym33Hxcp9ym3kHp:YGplp2GpwGpaGp5GphGpCGpy` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_018_ec742d1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec742d1bb8e067b6acb1acb1dbbbcbd8f5505e47a3561bfbd5b4068771d4d5b7"
    family = "ConnectWise"
    file_name = "ec742d1bb8e067b6.bin"
    file_type = "msi"
    first_seen = "2026-10-24 01:23:55"
  condition:
    hash.sha256(0, filesize) == "ec742d1bb8e067b6acb1acb1dbbbcbd8f5505e47a3561bfbd5b4068771d4d5b7"
}
```

### Sample 19: `b1332b2c5de9f56d`

| Field | Value |
|---|---|
| SHA-256 | `b1332b2c5de9f56d125cb23606a44b82d51250b5c0e199b6ade154681bb8197e` |
| Family label | `unknown` |
| File name | `b1332b2c5de9f56d.bin` |
| File type | `macho` |
| First seen | `2026-10-24 01:23:44` |
| Reporter | `Tuxxin` |
| Tags | `amos, macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `675080ca624edb240c91e8c697b03915` |
| SHA-1 | `fdca16b952686c007aadf099f56bbd994971672b` |
| SHA-256 | `b1332b2c5de9f56d125cb23606a44b82d51250b5c0e199b6ade154681bb8197e` |
| SHA3-384 | `8585ee54ecc684b288911e43356a231944aa2efe9ad7d597391f57832568d9049413a976d96720a8aac93af303224c5b` |
| TLSH | `T1B5944B072E7D5F0BD0C671309A4E8C9B0F83B43316B0AC9CBA95867957A8C716B1E797` |
| SSDEEP | `6144:fQO2miEsT3jYgYJLpUbs2tzC18Wdkyhf57rqJdrvYJExSazA:f72miRT3jYgYJLpUbs2tzC3dk6h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_b1332b2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1332b2c5de9f56d125cb23606a44b82d51250b5c0e199b6ade154681bb8197e"
    family = "unknown"
    file_name = "b1332b2c5de9f56d.bin"
    file_type = "macho"
    first_seen = "2026-10-24 01:23:44"
  condition:
    hash.sha256(0, filesize) == "b1332b2c5de9f56d125cb23606a44b82d51250b5c0e199b6ade154681bb8197e"
}
```

### Sample 20: `0bde7e85c0d4d2f3`

| Field | Value |
|---|---|
| SHA-256 | `0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d` |
| Family label | `unknown` |
| File name | `macho_0bde7e85c0d4.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:46:03` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `940ca0817784d851e0d9b89d2564376d` |
| SHA-1 | `4d02c36224aa714c8c07f8a5466bc71f95940d62` |
| SHA-256 | `0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d` |
| SHA3-384 | `ff12e2f8fe55cd7a08ece16eaec989a156e292f2c0ef08dcea3e97eddc7661903110808962e5c057b1da0b80c90507af` |
| TLSH | `T18A95F1501E7E5316D4F720328B28CF4E1560A7A16B48B9E59A29F2462C382D3F7E77C7` |
| SSDEEP | `49152:csdl/YFCWmDXYzDhqdRAUUs6Im8W2HBU3o:c2l/YbOfJH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_0bde7e85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d"
    family = "unknown"
    file_name = "macho_0bde7e85c0d4.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:46:03"
  condition:
    hash.sha256(0, filesize) == "0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d"
}
```

### Sample 21: `fb3a907fa1c573b1`

| Field | Value |
|---|---|
| SHA-256 | `fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23` |
| Family label | `unknown` |
| File name | `macho_fb3a907fa1c5.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:43:12` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baa27623bfc0583be3ea2c331a97563b` |
| SHA-1 | `aa862f0a6bdc720295d919b948545ef81c7e4598` |
| SHA-256 | `fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23` |
| SHA3-384 | `2409edc53631a2f68de0d0615264f8360e6cb1546ccc08e3ed4a271e48f9e4644f5727698fa11fc870cba1e2528a5e65` |
| TLSH | `T1C195F1148E1F609AD40621339C990F1980F4AC80CD4CEFEE5391B7A6DE3B79367566BB` |
| SSDEEP | `24576:WyLEl3OTlG3jNE77dwpHBy3o80NeFejaePkXpELggv+4HnOmXpJpnFvvTiu0LmRX:WxWENhNHnpvFvv2Q9H/xh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_fb3a907f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23"
    family = "unknown"
    file_name = "macho_fb3a907fa1c5.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:43:12"
  condition:
    hash.sha256(0, filesize) == "fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23"
}
```

### Sample 22: `11387a0d240ca6a1`

| Field | Value |
|---|---|
| SHA-256 | `11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d` |
| Family label | `unknown` |
| File name | `macho_11387a0d240c.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:40:25` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ee5ab4fb1fc5de02be7c22460e16675` |
| SHA-1 | `bbc62d64bf1aaefb3dcc3d726c8a5d4692017212` |
| SHA-256 | `11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d` |
| SHA3-384 | `3b88cb571a52979506b434d8d5d4ced9cac9758b35935e8cc13c52f46631c2fd5093cb585b1f9b8a023ec550e7f09677` |
| TLSH | `T101A5E0204E1F3186D00611739C990F9C85B468B0CD0EEDEA9741B36AEE3A7D777626B7` |
| SSDEEP | `24576:5E8zAtqMjQ2puLRDiQxJC7yQd3sweLllgljEDdeaZvGgtJAI53rZv3tF4D+s4NPQ:UM84C7Bs9BCEDFgBS9bg274lH8AvVwBY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_11387a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d"
    family = "unknown"
    file_name = "macho_11387a0d240c.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:40:25"
  condition:
    hash.sha256(0, filesize) == "11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d"
}
```

### Sample 23: `d2ec7a876540ce8f`

| Field | Value |
|---|---|
| SHA-256 | `d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db` |
| Family label | `unknown` |
| File name | `macho_d2ec7a876540.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:37:27` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc354e03871a9d4609c229c7937c0bc3` |
| SHA-1 | `6df8c1aa50c820d13784f221cce14aa5f5f968bf` |
| SHA-256 | `d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db` |
| SHA3-384 | `a96b9b4178e1e59a0c8230684760a87c0b5cb1840de9e9092930057e1deaf5632c16a5c702927923ff953643934a6571` |
| TLSH | `T12C95F150666D222BD8C433B39C100F4555E067889BE8B7FC6225AF9B3D36773B573262` |
| SSDEEP | `24576:YeFd/T70t7NTd2o1GmLJoIGvn9eRC1m0Mu3NsB023VcZSSDBGIUFnXKrStm:Td/Utf/LMMC0M3NsmsuZSOsWSk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d2ec7a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db"
    family = "unknown"
    file_name = "macho_d2ec7a876540.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:37:27"
  condition:
    hash.sha256(0, filesize) == "d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db"
}
```

### Sample 24: `003bcc4fb74050c5`

| Field | Value |
|---|---|
| SHA-256 | `003bcc4fb74050c564d7bcd6246d2ee13d1403eff1bb78cfcfe5945d4f499d67` |
| Family label | `unknown` |
| File name | `macho_003bcc4fb740.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:34:38` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8df34833186f4c8b6b02d06b6e0d7612` |
| SHA-1 | `6d91c6e94d3524e96d4a3609ed0070f4c3fa2405` |
| SHA-256 | `003bcc4fb74050c564d7bcd6246d2ee13d1403eff1bb78cfcfe5945d4f499d67` |
| SHA3-384 | `e9838cd028b2fed2064726ab0bc553293ac089681ca23d3540319cfbfd0ca765e739671d10a7fb8926f556602efb58da` |
| TLSH | `T1F5A5F15C6676166EF4833232C9105FD1A0606BA01B8479FA6E1CC3396E71AD3F9B3736` |
| SSDEEP | `49152:iRyd6aecs45QMNf/sf27aoi9ysR5gp0csqm:iyNcfKfeyY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_003bcc4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "003bcc4fb74050c564d7bcd6246d2ee13d1403eff1bb78cfcfe5945d4f499d67"
    family = "unknown"
    file_name = "macho_003bcc4fb740.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:34:38"
  condition:
    hash.sha256(0, filesize) == "003bcc4fb74050c564d7bcd6246d2ee13d1403eff1bb78cfcfe5945d4f499d67"
}
```

### Sample 25: `840ebbef896ec2cc`

| Field | Value |
|---|---|
| SHA-256 | `840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd` |
| Family label | `unknown` |
| File name | `macho_840ebbef896e.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:31:38` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60bd2eec336b0af3fd98e988546922bf` |
| SHA-1 | `cfd0d9d726c06710e073b66da0fd9cb93b24be76` |
| SHA-256 | `840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd` |
| SHA3-384 | `300d5b345389d6fa4487772f8056d10b831f2c89335474538f2ff020f2aebde63fba3be6f9fdfe452ae8df2f9f340dff` |
| TLSH | `T1C7A5E0809B6B5147DA4E50739CDA4B1984B57081CE85DEE96301B38BCD3A3E377A70FA` |
| SSDEEP | `24576:oH+6PJaOJUlYBfD/n04rT04kI292i8sHP9AoJnjSdscprxzLD7sczI:qtUlGnTdk1YuP9AoJnjwpnI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_840ebbef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd"
    family = "unknown"
    file_name = "macho_840ebbef896e.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:31:38"
  condition:
    hash.sha256(0, filesize) == "840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd"
}
```

### Sample 26: `6015a6d3a00d5771`

| Field | Value |
|---|---|
| SHA-256 | `6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16` |
| Family label | `unknown` |
| File name | `macho_6015a6d3a00d.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:28:35` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc1f801d987f67ceba628bceca8d23eb` |
| SHA-1 | `74b59f3032dacaca52d273560a0810514bd79bd5` |
| SHA-256 | `6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16` |
| SHA3-384 | `53b954e0facf4003a6b43fbab993cce1246aa9abe41f69e0decc67e64c44887dfb3ef49da275dc1c989092b53a9c76f7` |
| TLSH | `T13CA5E0409E1FE19BF40A1073AC9A4F58457020A0CE49DEEA6741F3A9DE367E3B712677` |
| SSDEEP | `49152:dcA1kCv22F9+XdQ7WaGAQmhA6A9NmqFuG6PVe1w4soJO78a:dca3FPGAVA6SAeu3PV77/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_6015a6d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16"
    family = "unknown"
    file_name = "macho_6015a6d3a00d.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:28:35"
  condition:
    hash.sha256(0, filesize) == "6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16"
}
```

### Sample 27: `188e826185574033`

| Field | Value |
|---|---|
| SHA-256 | `188e8261855740338dcfd6bfbcbbb3380658276fc733300829087eab66818696` |
| Family label | `SalatStealer` |
| File name | `12784917afb2b0f5.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:26:00` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4d9f03e6ed5705a3c76085003708672` |
| SHA-1 | `53da7d738c6ac27c3896c92e61cb950c44fbb92e` |
| SHA-256 | `188e8261855740338dcfd6bfbcbbb3380658276fc733300829087eab66818696` |
| SHA3-384 | `774dc158e63d58b68cd805801364331c818f4e30cdc63cd0c022f7381a3e9c6c8efd949068678b1293596e91314001c3` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T170C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Q:yBkKr5rszpNDy+Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_027_188e8261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "188e8261855740338dcfd6bfbcbbb3380658276fc733300829087eab66818696"
    family = "SalatStealer"
    file_name = "12784917afb2b0f5.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:26:00"
  condition:
    hash.sha256(0, filesize) == "188e8261855740338dcfd6bfbcbbb3380658276fc733300829087eab66818696"
}
```

### Sample 28: `121f6d62851254b7`

| Field | Value |
|---|---|
| SHA-256 | `121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb` |
| Family label | `SalatStealer` |
| File name | `f01781bf62e0a384.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:25:52` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8043f0e17526caaafa67488dd5dff9d` |
| SHA-1 | `f310d8bf3615ce2877a519640775d56f8a29c493` |
| SHA-256 | `121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb` |
| SHA3-384 | `7cd3a0511cba3fff4a9536bbe11cf406aab9984e60f407746336fc4fd25ff102ff67d57c8a98447dcb5a4249b20be1fa` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T102C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+z:yBkKr5rszpNDy+z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_028_121f6d62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb"
    family = "SalatStealer"
    file_name = "f01781bf62e0a384.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:25:52"
  condition:
    hash.sha256(0, filesize) == "121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb"
}
```

### Sample 29: `0bb6aca14af0fb51`

| Field | Value |
|---|---|
| SHA-256 | `0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3` |
| Family label | `unknown` |
| File name | `macho_0bb6aca14af0.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:25:46` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f369d4c05890ed8e82040c33e1a9cf58` |
| SHA-1 | `b42a0f00f46166b43cb3d4a855eef16b75d89bb5` |
| SHA-256 | `0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3` |
| SHA3-384 | `903c217c695e90b8f7ddab999723afd52a2858b41e87834fedf84335f9a7982ad67f5dc50c02b8ce3b30b3179954004f` |
| TLSH | `T18785E020E76A5266D84CA071CC104F590B906689DAD8E7E8F2EDC3573D342E3B67F25E` |
| SSDEEP | `24576:TAJz1KUOexDbwG8xRDfzG6VcDOXhKWWPdL2sgkGocL9VnoT9zDt/Nq6rebwXhEg8:TOpoG6VXKWSdL2lkGocL9VoRq6rbEg8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_0bb6aca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3"
    family = "unknown"
    file_name = "macho_0bb6aca14af0.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:25:46"
  condition:
    hash.sha256(0, filesize) == "0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3"
}
```

### Sample 30: `d1ecb7411b7d55b5`

| Field | Value |
|---|---|
| SHA-256 | `d1ecb7411b7d55b5e8016e0f0a9359bc39f85e33ce6a5ea7985863ccb2d152c8` |
| Family label | `SalatStealer` |
| File name | `79f3a3dd483248bc.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:25:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a44b09d78e4e6dc952800197203744b6` |
| SHA-1 | `d6b4745eba53e6b4fcfe176b6e3b444b0f0258b0` |
| SHA-256 | `d1ecb7411b7d55b5e8016e0f0a9359bc39f85e33ce6a5ea7985863ccb2d152c8` |
| SHA3-384 | `6406848c39cad2129554d3cc92041445e05aa24264aa10a9a58191ac93b95022ab22ccdce507eb6bc8a0781cf0308639` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+V:yBkKr5rszpNDy+V` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_030_d1ecb741
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ecb7411b7d55b5e8016e0f0a9359bc39f85e33ce6a5ea7985863ccb2d152c8"
    family = "SalatStealer"
    file_name = "79f3a3dd483248bc.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:25:43"
  condition:
    hash.sha256(0, filesize) == "d1ecb7411b7d55b5e8016e0f0a9359bc39f85e33ce6a5ea7985863ccb2d152c8"
}
```

### Sample 31: `f866b357edfe87a5`

| Field | Value |
|---|---|
| SHA-256 | `f866b357edfe87a5c735185737680779975c2659b1a26c6cccd81514705d1013` |
| Family label | `unknown` |
| File name | `20e1245cf23bc8d0.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:25:32` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a94aba32949a893bcf2c8bf7c63c165` |
| SHA-1 | `2a5130fc7e2e0e2f8a1c124994a2deabc1321e18` |
| SHA-256 | `f866b357edfe87a5c735185737680779975c2659b1a26c6cccd81514705d1013` |
| SHA3-384 | `097914d4dbab494025eaa4f7123f13eceb68043509015cb4c0c23b62b7d9257354ad9caa5d4af75101bd36645f8b9f37` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CCC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+m:yBkKr5rszpNDy+m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_f866b357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f866b357edfe87a5c735185737680779975c2659b1a26c6cccd81514705d1013"
    family = "unknown"
    file_name = "20e1245cf23bc8d0.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:25:32"
  condition:
    hash.sha256(0, filesize) == "f866b357edfe87a5c735185737680779975c2659b1a26c6cccd81514705d1013"
}
```

### Sample 32: `12784917afb2b0f5`

| Field | Value |
|---|---|
| SHA-256 | `12784917afb2b0f5adafb44b94c3ef3019ccf6a991fcfe9033415bb45a5d931c` |
| Family label | `SalatStealer` |
| File name | `12784917afb2b0f5.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:24:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33f9988ad3a9c08af73fceb0779ca7eb` |
| SHA-1 | `7c9c6cf9c61c113f530fd993e1703897d8c0790c` |
| SHA-256 | `12784917afb2b0f5adafb44b94c3ef3019ccf6a991fcfe9033415bb45a5d931c` |
| SHA3-384 | `b1a361c43ed22563aed49ef2fb66263769eed47e7aef689702e9d611eb6badf7ecd22ba39b83fa1a240f0ddebaf8f3d5` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1F7F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oc:iJiafuIO7rhWEES41` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_032_12784917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12784917afb2b0f5adafb44b94c3ef3019ccf6a991fcfe9033415bb45a5d931c"
    family = "SalatStealer"
    file_name = "12784917afb2b0f5.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:56"
  condition:
    hash.sha256(0, filesize) == "12784917afb2b0f5adafb44b94c3ef3019ccf6a991fcfe9033415bb45a5d931c"
}
```

### Sample 33: `f01781bf62e0a384`

| Field | Value |
|---|---|
| SHA-256 | `f01781bf62e0a3846c288da5483ace08c63492a632762173f4ba6107799128a6` |
| Family label | `SalatStealer` |
| File name | `f01781bf62e0a384.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:24:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30067aa7ba1c1dd67256eb3df1c36d10` |
| SHA-1 | `3d94d292b23f88b225f2fbaccaf3bd1515e4b90b` |
| SHA-256 | `f01781bf62e0a3846c288da5483ace08c63492a632762173f4ba6107799128a6` |
| SHA3-384 | `6e8995a2c0bd7db86cc9e5a5b14b9ffde0032101ac949d5649e2c7ccc65f309ebe365a90c23ea5aecc4c98bb6f8e1bd7` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T19CF5335BF5AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0882BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OX:iJiafuIO7rhWEES4i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_f01781bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f01781bf62e0a3846c288da5483ace08c63492a632762173f4ba6107799128a6"
    family = "SalatStealer"
    file_name = "f01781bf62e0a384.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:46"
  condition:
    hash.sha256(0, filesize) == "f01781bf62e0a3846c288da5483ace08c63492a632762173f4ba6107799128a6"
}
```

### Sample 34: `79f3a3dd483248bc`

| Field | Value |
|---|---|
| SHA-256 | `79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7` |
| Family label | `SalatStealer` |
| File name | `79f3a3dd483248bc.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:24:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50c15494ee156198110244e418400e22` |
| SHA-1 | `8259f98526e20c1b379b361995a6af8f7cf9a57f` |
| SHA-256 | `79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7` |
| SHA3-384 | `92424d93b445c9a5e29a63456ed28d989c7c709ca17d56ddcaeb3902db850de882bfe524206b19c9de895bffcc455bfa` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T196F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O5:iJiafuIO7rhWEES4C` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_034_79f3a3dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7"
    family = "SalatStealer"
    file_name = "79f3a3dd483248bc.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:36"
  condition:
    hash.sha256(0, filesize) == "79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7"
}
```

### Sample 35: `20e1245cf23bc8d0`

| Field | Value |
|---|---|
| SHA-256 | `20e1245cf23bc8d0946dab9b8747dd189acef5cf09546257e7fc298a7c6717fd` |
| Family label | `SalatStealer` |
| File name | `20e1245cf23bc8d0.bin` |
| File type | `exe` |
| First seen | `2026-10-24 00:24:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a60999eedf5fa4eafba99d74af02030e` |
| SHA-1 | `fd61aabc00889c5072aff88a86d170e38b66b03e` |
| SHA-256 | `20e1245cf23bc8d0946dab9b8747dd189acef5cf09546257e7fc298a7c6717fd` |
| SHA3-384 | `aa7730bf60f90b5c7ca2efb400c7aa5b213c84858b845d46cbcc80ebbb2ea95c50fbf867efcce0bb0c55113c5f08a2d7` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T100F5335BF5AF4BB3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0842BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OS:iJiafuIO7rhWEES4h` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_035_20e1245c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20e1245cf23bc8d0946dab9b8747dd189acef5cf09546257e7fc298a7c6717fd"
    family = "SalatStealer"
    file_name = "20e1245cf23bc8d0.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:26"
  condition:
    hash.sha256(0, filesize) == "20e1245cf23bc8d0946dab9b8747dd189acef5cf09546257e7fc298a7c6717fd"
}
```

### Sample 36: `ff72b39a559646d5`

| Field | Value |
|---|---|
| SHA-256 | `ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3` |
| Family label | `unknown` |
| File name | `macho_ff72b39a5596.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:22:56` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4c9d6806fc9a1a1ff126e66f438681b` |
| SHA-1 | `be76bfdc09c19629b81c5b95249aaa7093e2611e` |
| SHA-256 | `ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3` |
| SHA3-384 | `3bf4bc5aca7212fa52d28f394eafe88563fd8c45fbcb87a5d71f1daf7b63f3dfdcea3b24f983ce5f9e1c00df6a38ef55` |
| TLSH | `T1749501905A6F61B9D84624F65F010FD532D0A2A0EA487AFB2624D7793C316C779E33B3` |
| SSDEEP | `49152:MDydehPebX7Nz2kRbluNmYIwJcsDlSUCKbdjNM:MDydYeMNmYLJ/Do` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_ff72b39a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3"
    family = "unknown"
    file_name = "macho_ff72b39a5596.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:22:56"
  condition:
    hash.sha256(0, filesize) == "ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3"
}
```

### Sample 37: `5670d4f79411fd5c`

| Field | Value |
|---|---|
| SHA-256 | `5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a` |
| Family label | `unknown` |
| File name | `macho_5670d4f79411.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:20:07` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e3d262bfe58a16be587f1094f0a6c3b` |
| SHA-1 | `4fa46e507141cd725a1060d265873bbb68718574` |
| SHA-256 | `5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a` |
| SHA3-384 | `b0ebe61e189b38b0459f4df11f687d96b1e2285b88876b0235521b5390e910c84705a0dec92ad71a81ffc194540ea985` |
| TLSH | `T15E850250573601A6EF8134729C901FE95DF0BA805E48BBFA72308BCA6D76653F17722B` |
| SSDEEP | `24576:HCKWVK5/+gZ1gbkdqHYAOOvcOMnrIlzJO9qCDoNwP2b9z3HxrAHOKeKtGA2nL1:d1lOTlz6DoNwP2tRKo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_5670d4f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a"
    family = "unknown"
    file_name = "macho_5670d4f79411.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:20:07"
  condition:
    hash.sha256(0, filesize) == "5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a"
}
```

### Sample 38: `b61faf483a13cc25`

| Field | Value |
|---|---|
| SHA-256 | `b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352` |
| Family label | `unknown` |
| File name | `macho_b61faf483a13.bin` |
| File type | `macho` |
| First seen | `2026-10-24 00:17:15` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `749bb5978633a451e43007217d275cf1` |
| SHA-1 | `d3eae96fe303b0826112e15bb1f826eea82e8e84` |
| SHA-256 | `b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352` |
| SHA3-384 | `ad0e2ff19961f986085c82be7a5feb54ad62ead08d0b5b344b2d06fc4b20e780c8080091078eda4a1adb3a198a3754f9` |
| TLSH | `T10295F1646D7A525AD4892873DFE04F0145A0A7836ADCB6E4DE25C307AD36E93F2B3313` |
| SSDEEP | `24576:P5OtH3HQq/Ufjv5p573rryEgw3+3KfrWCNq6+ZZpZzCFjj7A7vXzcySc3ungV/kN:BoX3c9nbUT3KT6ZZLzCRjMbM1ngs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_b61faf48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352"
    family = "unknown"
    file_name = "macho_b61faf483a13.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:17:15"
  condition:
    hash.sha256(0, filesize) == "b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352"
}
```

### Sample 39: `0ed065d88f132e43`

| Field | Value |
|---|---|
| SHA-256 | `0ed065d88f132e4356c99545955f749be9519f8783d7390e98e8ec8656bc2d4b` |
| Family label | `unknown` |
| File name | `new.txt` |
| File type | `elf` |
| First seen | `2026-10-23 23:50:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b086e4f81a872443df9e694a5d613b56` |
| SHA-1 | `19a694b90115a2e060664ea05a47d23356dc4851` |
| SHA-256 | `0ed065d88f132e4356c99545955f749be9519f8783d7390e98e8ec8656bc2d4b` |
| SHA3-384 | `1b16efaceb22141f844109af581182dc48d18c447706cd733dddb46f5a0419467f273465eb5a85f94bf09eead007133d` |
| TLSH | `T1A9662712FECB14F6E903193104BBA27F27315D058B24EB87EB407E29FD7B6A55932219` |
| TELFHASH | `t1942186b590f638452094052a8ec20c615f06a4e86776552b894f6ffa67c7ac48df312a` |
| SSDEEP | `98304:zUB3H3Ng3uFkoG2I4dky07hVS19aWHyE6l:z43Ng3PoG2IXVS19RfW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_0ed065d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ed065d88f132e4356c99545955f749be9519f8783d7390e98e8ec8656bc2d4b"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 23:50:25"
  condition:
    hash.sha256(0, filesize) == "0ed065d88f132e4356c99545955f749be9519f8783d7390e98e8ec8656bc2d4b"
}
```

### Sample 40: `5efa2d854e5a9ffe`

| Field | Value |
|---|---|
| SHA-256 | `5efa2d854e5a9ffec32ea81525d24875075e1017dce93cd18a4df6d703c7fd11` |
| Family label | `unknown` |
| File name | `new.txt` |
| File type | `elf` |
| First seen | `2026-10-23 23:49:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f5d80486ffce936ed5768a44288322` |
| SHA-1 | `7e2b1ddb22132b06617db7988d985e5e297c0961` |
| SHA-256 | `5efa2d854e5a9ffec32ea81525d24875075e1017dce93cd18a4df6d703c7fd11` |
| SHA3-384 | `d3e2661b3ac6af00adfe099feaf38de77100a79cd8272d16628cbb923f144920b94a4a8d48086ead8f37478f2f31cb37` |
| TLSH | `T144D53376A0ED5BA1491ECD1771BB61A30487D8FF4FB5CC8E5E5A834AACB9F03E00A055` |
| TELFHASH | `t14aa002d159ce4addc1613c5dc02369144006974f399a1f1343a18b79fa8de2033c2af5` |
| SSDEEP | `49152:8KDumpxNZBwd6ZCZxFKxV8suDsERFGpdbK020O0TulgWt4nffN:8fGju6Z22qevWiffN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_5efa2d85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efa2d854e5a9ffec32ea81525d24875075e1017dce93cd18a4df6d703c7fd11"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 23:49:40"
  condition:
    hash.sha256(0, filesize) == "5efa2d854e5a9ffec32ea81525d24875075e1017dce93cd18a4df6d703c7fd11"
}
```

### Sample 41: `6f714f70d511efb4`

| Field | Value |
|---|---|
| SHA-256 | `6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-23 23:33:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97d7499d7f7c3c26b32999908e0683cb` |
| SHA-1 | `9931e4037b0d1607b474712391f0bf871c6ee2bf` |
| SHA-256 | `6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a` |
| SHA3-384 | `548f6f95ed4516b6c49b93cfd3e57fd0d5c841f23c25a1617fe06e82e5c5df7519850ad1da19bfffdcd0769f56dedbe1` |
| TLSH | `T127556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmN:OSCX9B9tGNnD+pb0qAYPWTM2wza6c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_6f714f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-23 23:33:42"
  condition:
    hash.sha256(0, filesize) == "6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a"
}
```

### Sample 42: `e3ccd986aa9ecd55`

| Field | Value |
|---|---|
| SHA-256 | `e3ccd986aa9ecd55ed9918635b544ac7c2d3d11cdb3ab19e7d1f7879d720d655` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-23 23:31:09` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10279663d1607d5e32872610723c0ea0` |
| SHA-1 | `0349e3f2d6e87b2944d8c33fd091f4ccd8989cda` |
| SHA-256 | `e3ccd986aa9ecd55ed9918635b544ac7c2d3d11cdb3ab19e7d1f7879d720d655` |
| SHA3-384 | `403156f0cdb6b7af17645f9d1af080251b4a2cf868821882565114cfeb58ae1aedecb26e1fe953afe3b3fac2d90fb8a2` |
| IMPHASH | `d9f3caa80a97c4dc34a6823d51c1a833` |
| TLSH | `T17845CF73BEC009C8D9358EF876555528DD9338121A207CEB82BBF2C70AA56D19B316DF` |
| SSDEEP | `24576:JjXhCltzrVJMzBVrtLR9MVSn/lpNfAIn7x7u:z42FVddRu` |
| ICON-DHASH | `20189a585e4e2c12` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_e3ccd986
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3ccd986aa9ecd55ed9918635b544ac7c2d3d11cdb3ab19e7d1f7879d720d655"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-23 23:31:09"
  condition:
    hash.sha256(0, filesize) == "e3ccd986aa9ecd55ed9918635b544ac7c2d3d11cdb3ab19e7d1f7879d720d655"
}
```

### Sample 43: `7f6e711385a4ec77`

| Field | Value |
|---|---|
| SHA-256 | `7f6e711385a4ec779286c9e2f035fda3b86e75ce2d50725dcd8facb6c07b4116` |
| Family label | `unknown` |
| File name | `7f6e711385a4ec77.ps1` |
| File type | `ps1` |
| First seen | `2026-10-23 23:30:41` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6638abd616a4553f434f75856d8b6ff` |
| SHA-1 | `fa714f7dfd48a93541d6b06fa48da3c907c7d11a` |
| SHA-256 | `7f6e711385a4ec779286c9e2f035fda3b86e75ce2d50725dcd8facb6c07b4116` |
| SHA3-384 | `c0d80c6d9ac8adc51901f2d4ec2119169939c1895a4bce55b74b85d1df099ffab399bdad4e225f2ce924495d50dd334b` |
| TLSH | `T193D46D347E412EFF5BB820C248D6811C563C3279DA686CF669CB0CA2394D77627B79B1` |
| SSDEEP | `12288:2emJTs4ul9pLNZOSV0qrgmkB8xAKGoN8G2U:27kZO/8xTj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_7f6e7113
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f6e711385a4ec779286c9e2f035fda3b86e75ce2d50725dcd8facb6c07b4116"
    family = "unknown"
    file_name = "7f6e711385a4ec77.ps1"
    file_type = "ps1"
    first_seen = "2026-10-23 23:30:41"
  condition:
    hash.sha256(0, filesize) == "7f6e711385a4ec779286c9e2f035fda3b86e75ce2d50725dcd8facb6c07b4116"
}
```

### Sample 44: `619e999480704dde`

| Field | Value |
|---|---|
| SHA-256 | `619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-23 23:25:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2666715cecc06995d20625257545ba7c` |
| SHA-1 | `987ace21f98d6ce45fae774e34fde878aa770e1e` |
| SHA-256 | `619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba` |
| SHA3-384 | `a7065bfd9151cd6cf1be847b87d6e795b28ced3a035a626e3a53e9e0677dcf0865476cf46b1e845b3f8a8a0b7a7429f8` |
| TLSH | `T1B7556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmW:OSCX9B9tGNnD+pb0qAYPWTM2wza6n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_619e9994
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-23 23:25:46"
  condition:
    hash.sha256(0, filesize) == "619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba"
}
```

### Sample 45: `226bd33caa93d3ed`

| Field | Value |
|---|---|
| SHA-256 | `226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5` |
| Family label | `Mirai` |
| File name | `manta.armv7l` |
| File type | `elf` |
| First seen | `2026-10-23 23:25:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08f3aef041783f6db06c859189b2ec20` |
| SHA-1 | `2b3e8df8376fddb981124c35a1ba2dc846e4b639` |
| SHA-256 | `226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5` |
| SHA3-384 | `0642119da656900a88d1999324fa1bdedcd60550fd64f9c5e07acbeec79b716c878eaa2037747b263f7a89f6e97c418f` |
| TLSH | `T17E25E15AE6032F45C8C696BB5C46CA914651D86B32F29F0A5F8369FB387CE316F38350` |
| SSDEEP | `12288:LQlZwvuqPoyEj/HkuccxSLkTAtjAvpY8m1KIu/CV3ndzrzQpi6oPjvgV5QPGNz61:L2K60eSLkSea8m10/S3dz/7Pjv7rk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_226bd33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
    family = "Mirai"
    file_name = "manta.armv7l"
    file_type = "elf"
    first_seen = "2026-10-23 23:25:43"
  condition:
    hash.sha256(0, filesize) == "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
}
```

### Sample 46: `c15a21e69b3142e5`

| Field | Value |
|---|---|
| SHA-256 | `c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77` |
| Family label | `unknown` |
| File name | `macho_c15a21e69b31.bin` |
| File type | `macho` |
| First seen | `2026-10-23 23:22:28` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9ad7b248a84f38a7d4d9e25779d4b68` |
| SHA-1 | `a32bffef1f0ac5c1244c7fad91ae4988dae5f98e` |
| SHA-256 | `c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77` |
| SHA3-384 | `f69f5ec1ce91c35ce6e2005e5a2740445ab15ed0bb8bb459b82f503a6240189c66fc0c54b0861a701148d339b750badb` |
| TLSH | `T19585E134D3DE9164D4717832E8101BA4ACF0AD911A4CAFF9172ACB237E36687A577372` |
| SSDEEP | `24576:alFCtcthQJ1zNdAtiAwmHxlBeLIOjJvMhcy4B74qiY/VLT6TU:cZ6csApkLIuvMGyWMqrGTU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_c15a21e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77"
    family = "unknown"
    file_name = "macho_c15a21e69b31.bin"
    file_type = "macho"
    first_seen = "2026-10-23 23:22:28"
  condition:
    hash.sha256(0, filesize) == "c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77"
}
```

### Sample 47: `0f832acaae076974`

| Field | Value |
|---|---|
| SHA-256 | `0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05` |
| Family label | `Mirai` |
| File name | `manta.m68k` |
| File type | `elf` |
| First seen | `2026-10-23 23:21:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65857b704e3b8695eb7ebf28d3a6bc26` |
| SHA-1 | `f3f5f36982ce38827cc3760aa7dbe7cde87e5854` |
| SHA-256 | `0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05` |
| SHA3-384 | `565e1ff44aedc3083424176404114c0e3578d26b312430ff3ced366c59636c7f5670307a242a04f01ac8dd77f23c2a47` |
| TLSH | `T12845AD82670C3D6FE293753E84814E06AD28EF5091836F1752E9F65A7B736761F3C282` |
| SSDEEP | `24576:Y+Tj1Wq9tphLRl23k/fHr3ATJ1Fg2PwfMjA8VsH:Y+fIq9tPS3wDATJ1TjAf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_0f832aca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05"
    family = "Mirai"
    file_name = "manta.m68k"
    file_type = "elf"
    first_seen = "2026-10-23 23:21:45"
  condition:
    hash.sha256(0, filesize) == "0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05"
}
```

### Sample 48: `2973d2d69a0d9ef0`

| Field | Value |
|---|---|
| SHA-256 | `2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-10-23 23:09:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `975ca32d5edb617aca5f72d84b9a07d8` |
| SHA-1 | `d91adffb9023a85d499641765dd79c92e81df434` |
| SHA-256 | `2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef` |
| SHA3-384 | `cb59fc943b96e920610d9939a7d99aaed9f05a6bd8c469f98534e2c42a36548ab2a676ed3c99efcc82e7f9f5b0798231` |
| TLSH | `T12544F90AAB610FFBECABDD3702E91B0525CCA41622A53F367674D918F54A64F0AD3C74` |
| SSDEEP | `3072:afkGfvLCULJ3s6HT8zjjWfYVIpiLtTISv:OmURTTsnWsde` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_2973d2d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-23 23:09:43"
  condition:
    hash.sha256(0, filesize) == "2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef"
}
```

### Sample 49: `97fdba0b9d0588d2`

| Field | Value |
|---|---|
| SHA-256 | `97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-10-23 23:05:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97c0fae8b69d84e5a18bc80879f26b4b` |
| SHA-1 | `700500cf4befc60fab497af6412558d4d2f917af` |
| SHA-256 | `97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7` |
| SHA3-384 | `423471cdae3e7d96aac7f7385f8bd5db8338777f675d20ff374dd6cd0c72c39ed7f42ef8123f99683df49f4e9c4176f2` |
| TLSH | `T1FB932A91B981965EC6D063BFFA4E538D333663E8C3DE7013DD168A21738B51F0A36A91` |
| TELFHASH | `t1a0f0ac04ba7a8e1a48e2a670dcb807a09447522360a21725ef5acad0cc3e558f308d5d` |
| SSDEEP | `1536:Rn0gUXGTGR/BAT860DjRXGFwgHyNwtdu1HcjoPaWmPwmnIyd7Zh:upXGK6D0DjRXGFPyNlUaah7z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_97fdba0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-10-23 23:05:45"
  condition:
    hash.sha256(0, filesize) == "97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7"
}
```

### Sample 50: `1826b5c073569dba`

| Field | Value |
|---|---|
| SHA-256 | `1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-23 23:01:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc54fb8a5061bd556a8701fa7aa40b7e` |
| SHA-1 | `fa334c108219187f885cf171c9877f570c21f4e5` |
| SHA-256 | `1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2` |
| SHA3-384 | `11815b59eefd7f0c286846fb6eb0e5b55d53aacf0fc27f1af5b017585da8340f0fb0113d960794bae922de46f1e15768` |
| TLSH | `T1AFD37DD1E643E1F5E99201F1103BB3219B76E436947BF751C76B7D329C62900AA2B36C` |
| TELFHASH | `t1b76118f97eaa0dd9b7905803d24d2b317c4aab7b2860367305f319b5377664141bbc39` |
| SSDEEP | `1536:9PX/ci125+o8T8D4coHOS8JpcZhsIXP6VK065izZzJoeLN0cogIHE4SSXXNMEjTg:9/od8LOFpcZp/6U06MToYNPogo7tr4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_1826b5c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-23 23:01:46"
  condition:
    hash.sha256(0, filesize) == "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
}
```

### Sample 51: `f0c49d9a504002a1`

| Field | Value |
|---|---|
| SHA-256 | `f0c49d9a504002a1305b4d79e5f427c813355ff92536429d8ce0819f773fabe9` |
| Family label | `Mirai` |
| File name | `manta.sh4` |
| File type | `elf` |
| First seen | `2026-10-23 22:57:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29399d5d046cc3ab1b0b04af1d9a9395` |
| SHA-1 | `ae0dbafeed7047beaf1758d7578484f52be90613` |
| SHA-256 | `f0c49d9a504002a1305b4d79e5f427c813355ff92536429d8ce0819f773fabe9` |
| SHA3-384 | `d1edd835d2a39c008e76f717c18fcbb6d00a1f8abaeb3cd09405dcac96abb1ca5c72570df252a95fae09cc591c40892a` |
| TLSH | `T1E055CFA3F131AD9BC02646B42478E2304B0AB896237771C4F7EAD2591C97AD1BF5D3B1` |
| SSDEEP | `24576:xnm7zDt9OuYDcvRBE2GzpUD708N7a/WXbiZJUb0r/:lmveNojE2xI8kWr+A0r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_f0c49d9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0c49d9a504002a1305b4d79e5f427c813355ff92536429d8ce0819f773fabe9"
    family = "Mirai"
    file_name = "manta.sh4"
    file_type = "elf"
    first_seen = "2026-10-23 22:57:44"
  condition:
    hash.sha256(0, filesize) == "f0c49d9a504002a1305b4d79e5f427c813355ff92536429d8ce0819f773fabe9"
}
```

### Sample 52: `638fe6527fcaeb06`

| Field | Value |
|---|---|
| SHA-256 | `638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-23 22:47:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02a81b120f942000289ac2241e736d12` |
| SHA-1 | `19a8314997811c779f172953b4563927ac3e756b` |
| SHA-256 | `638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c` |
| SHA3-384 | `710c204fd6f44504df9d979f8b69c3aa7d45f629c3fd27ebb90eaddf883f8cacd686875cb069975f87abe6edec65bf9a` |
| TLSH | `T1E1143A45F8815A17C6C612BBFB4E428D372A57A8D3EE7103DD265F21378B96B0E3B241` |
| TELFHASH | `t197a01248230e015070d45101c2b04d8e6844a1142304014108122c3ca097013d027005` |
| SSDEEP | `3072:dedfT+1AnwxCVmX04BpoDola6EDqV484iEfqqqyXpz/GySH:fywB8JBuV484i6qqqyR/Gb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_638fe652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-23 22:47:48"
  condition:
    hash.sha256(0, filesize) == "638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c"
}
```

### Sample 53: `1212bfc031aa5dac`

| Field | Value |
|---|---|
| SHA-256 | `1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d` |
| Family label | `unknown` |
| File name | `3574378_13_-setup.msi` |
| File type | `msi` |
| First seen | `2026-10-23 22:41:21` |
| Reporter | `Miaoumap24` |
| Tags | `exe, infostealer, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2a73c72e2f8796e783838254af44723` |
| SHA-1 | `b97096159eb1c2ddf660a2ebef625a61c794588f` |
| SHA-256 | `1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d` |
| SHA3-384 | `7c60b1ecaf8c618ef4e7d975d92b308dfcdf9a02aa23fb6048e6359060155d051740729a1e9cf1ee13933ed2fd22c0b5` |
| TLSH | `T1C6265BB93F81C294ECA62E1B0812CADF03297C29EDCE437265F9745E25D5D9E0364DAC` |
| SSDEEP | `49152:cz1izUT1bXONold1ggxkhoJ9QRMPmdRSbnLcpk12T0gV6QbXByh:esU5bXONor5aQ7ud6Lm02wgQQQh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_1212bfc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d"
    family = "unknown"
    file_name = "3574378_13_-setup.msi"
    file_type = "msi"
    first_seen = "2026-10-23 22:41:21"
  condition:
    hash.sha256(0, filesize) == "1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d"
}
```

### Sample 54: `b1b5dd6e77801cd1`

| Field | Value |
|---|---|
| SHA-256 | `b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-10-23 22:37:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd785cb9dbc1d8fd4ef63aab20e9431f` |
| SHA-1 | `b44ef114f0e2e300e5063113ca68635b5b4c33eb` |
| SHA-256 | `b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed` |
| SHA3-384 | `2221da7aef14682ac3b910c657b77675e833c26e0095b9c0e5378987559b24fb5e5930352d797f1b15f18b53932e13df` |
| TLSH | `T1D2F38C63C8396E58D658A4F8F4B1AF781B2394A5C1D32FA99967C3718047ECCF5093B8` |
| SSDEEP | `3072:wjHikizC8+3GDQH3eb0P4HNgpSv9Wus5Zo3De:wjIqiyOb0PI9Iucoa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_b1b5dd6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-10-23 22:37:40"
  condition:
    hash.sha256(0, filesize) == "b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed"
}
```

### Sample 55: `e2ea41d1deab665e`

| Field | Value |
|---|---|
| SHA-256 | `e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-23 22:37:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afc64391e7528ac8365e76e9ac70c9f2` |
| SHA-1 | `c9ad9b535ebdfb370d4112dfbc1f710914eeedf6` |
| SHA-256 | `e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022` |
| SHA3-384 | `3ef304d623f850535ab8c310fc51ab5c679dc5bd6c06f37f942979cfb1e060ad9190869d814a765c36e792aa1c7b2092` |
| TLSH | `T14E042B02B31C0947D1632EF43A3B27E0D3EF9AA220F5F644754FAA899172D365589DCE` |
| SSDEEP | `3072:dgWvQXkueX2v4pihDE1xvZ7iG3eo+NcMKcd8x:Q0JGoiK1xvVN3ejN0dx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_e2ea41d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-23 22:37:38"
  condition:
    hash.sha256(0, filesize) == "e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022"
}
```

### Sample 56: `a20170667b22b377`

| Field | Value |
|---|---|
| SHA-256 | `a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-10-23 22:33:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `663e352f0d0877a51895395dba745395` |
| SHA-1 | `917e0388dc8886cb3f4a6a0d56615f16f31a4896` |
| SHA-256 | `a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a` |
| SHA3-384 | `719e2b4d73dd23079e320147c73b62b7dc2db3ca48c2db0088ef628864c2ef1a43fcd260f81eb7a9dd7b9219ddec9e9e` |
| TLSH | `T12A145BC3F900DDBDF80BE37B88134915B130B7A214A26A37B257797BAC3A1951477E86` |
| SSDEEP | `6144:OJQgWBMeiFUhOhS2Cb4LjwIL5L5ayhNyT:OJHJeoLTbe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_a2017066
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-10-23 22:33:39"
  condition:
    hash.sha256(0, filesize) == "a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a"
}
```

### Sample 57: `9aba42d500b0941a`

| Field | Value |
|---|---|
| SHA-256 | `9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775` |
| Family label | `Mirai` |
| File name | `manta.aarch64` |
| File type | `elf` |
| First seen | `2026-10-23 22:31:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `059a82b66f520b98c36a0b91a719d60b` |
| SHA-1 | `108ed95d0539a5fa2905bc0aaa6df15dc24da548` |
| SHA-256 | `9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775` |
| SHA3-384 | `9a95b63957a3b65e448882c51fd9ab71c7587c7f3e5d7943b4b0160e7074174c56eeeb5c996ea42855d776e3ec94bb80` |
| TLSH | `T1B6757D6CFD0F3D41D3CAF27CCB4EC3D5B12BB1A8C21750A33992020DD59A9A9DAB2955` |
| SSDEEP | `12288:zBelSLPoxEFdSvwx2iagM9LpMLUwKiXqLcMlfuu0CMB5/BjlvwmNiayDaotnxtk+:zsli/SvwxEXXiahupCARBxvhY7Z5tsm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_9aba42d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775"
    family = "Mirai"
    file_name = "manta.aarch64"
    file_type = "elf"
    first_seen = "2026-10-23 22:31:40"
  condition:
    hash.sha256(0, filesize) == "9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775"
}
```

### Sample 58: `14a75070ab15d4e2`

| Field | Value |
|---|---|
| SHA-256 | `14a75070ab15d4e2b74399aca5c16dc762018d0b48d94b18aa77f8947a013a0f` |
| Family label | `unknown` |
| File name | `_WRFVL2CLdcf8.tmp.7z` |
| File type | `7z` |
| First seen | `2026-10-23 22:28:40` |
| Reporter | `cypherpunk472` |
| Tags | `7z, infected` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31f1c5263755f75c29dd4ab81a8577ae` |
| SHA-1 | `30231c80506de65eca2eebde506926d6d3395f91` |
| SHA-256 | `14a75070ab15d4e2b74399aca5c16dc762018d0b48d94b18aa77f8947a013a0f` |
| SHA3-384 | `89e539c7317c9e6a529d363d9096e8b2b25d5a388d3ee0b719e393aa2fbdde6ed5ed6b29282320125e6dd5515088ffc3` |
| TLSH | `T19655335643E52422852F8705CD189023A186FF3DE70CB2D7ED37EA9816DC6EA5C6FC68` |
| SSDEEP | `24576:oJDiY7GblbiKqd+lOSziGEGA1buG+XVNuaBCoRQcv2qDHP+1iVNHdq:oMYS5b8d+4siNGApGNuaRQceqDTVtd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_14a75070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14a75070ab15d4e2b74399aca5c16dc762018d0b48d94b18aa77f8947a013a0f"
    family = "unknown"
    file_name = "_WRFVL2CLdcf8.tmp.7z"
    file_type = "7z"
    first_seen = "2026-10-23 22:28:40"
  condition:
    hash.sha256(0, filesize) == "14a75070ab15d4e2b74399aca5c16dc762018d0b48d94b18aa77f8947a013a0f"
}
```

### Sample 59: `b5e7c5dfa2888d05`

| Field | Value |
|---|---|
| SHA-256 | `b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-10-23 22:27:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cc1d3d1faa949e003607985c12d41f0` |
| SHA-1 | `eb74edc491a8af54e7948d03096dbacd01122f4f` |
| SHA-256 | `b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766` |
| SHA3-384 | `0755cfb33745f8289fc3e685cbd74d9540ba6e92280e26e0e2cac29c8eb50915995418a386e30cee688ed7988f528ba8` |
| TLSH | `T1A2441A46FA404A17C4D627B9FA9F42453333E7A893EB7306D9286FB03BC775A0E62505` |
| TELFHASH | `t1f0412d718b345526aaa1dd14e9fa93b2251edb175384fe33df25c88c180949fe92bc0f` |
| SSDEEP | `6144:OO0jL70XiTdhSFY+7u1TavAvbmOKoBLkf9xVXNSyV/Gnmm2CbHs:5UL70yTdhJ+7u1TavAvbmOKoJMDH/SmD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_b5e7c5df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-10-23 22:27:35"
  condition:
    hash.sha256(0, filesize) == "b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766"
}
```

### Sample 60: `c76ed9ab219d002e`

| Field | Value |
|---|---|
| SHA-256 | `c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a` |
| Family label | `Mirai` |
| File name | `c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a` |
| File type | `elf` |
| First seen | `2026-10-23 22:24:13` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3f3cba6b96ab86b687c9c17c5bb4ba4` |
| SHA-1 | `6e7e076813c662b925646849b3c1c4f75c62eaa7` |
| SHA-256 | `c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a` |
| SHA3-384 | `44373386f64edfda515f1698f8065b0f84c15164dbdafbd5dd274abbdb126c5b78364c6565a8c1e5d32afbf7753ae36e` |
| TLSH | `T13173B71D2E618FADF7A8C23547B78F21939C378627E1D685E29CD6001F6034E645FBA8` |
| TELFHASH | `t108110908993863f49bb51d996bedff75e49170ef47215e378e00e9ae5a2dc429a00c1c` |
| SSDEEP | `1536:4iOT1XOVgCdSQ0HAunYWR9KqZKpoLGexNGz:4PTVOxdSQ0+qZKpoLNGz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_c76ed9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a"
    family = "Mirai"
    file_name = "c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a"
    file_type = "elf"
    first_seen = "2026-10-23 22:24:13"
  condition:
    hash.sha256(0, filesize) == "c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a"
}
```

### Sample 61: `308ee11f9b4fa861`

| Field | Value |
|---|---|
| SHA-256 | `308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08` |
| Family label | `Mirai` |
| File name | `308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08` |
| File type | `elf` |
| First seen | `2026-10-23 22:24:06` |
| Reporter | `spydisec` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f470ff7c5be17f752705df0d3010deb` |
| SHA-1 | `f33cd32db5b7eaf8f454db30f0d0f2fc84766566` |
| SHA-256 | `308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08` |
| SHA3-384 | `1798504104e3ed9588cb1723bc061e37457f9d794370c7f531b3b3a2e4a848286358b78817d6fc82f5ac7ee21cf6d87b` |
| TLSH | `T1B9532991BC919A13C6D012B7FB6E428D332757A8D2EE73039C266F11378792F0E67652` |
| TELFHASH | `t1ad018ea0968907ccb3c0d509d1ca5217c71e31ad4e21251c17d87eae02b75c17635436` |
| SSDEEP | `768:2Z6XMQwnZpkW/hDqx9eY1RMXdssh7LREp4P+CEo/NRjn3b1azMrASELOoRZXn8V/:HXgnZpZ/8RMH3REoXLfr4LXzX8SOEvO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_308ee11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08"
    family = "Mirai"
    file_name = "308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08"
    file_type = "elf"
    first_seen = "2026-10-23 22:24:06"
  condition:
    hash.sha256(0, filesize) == "308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08"
}
```

### Sample 62: `0d23bcb2e85eba59`

| Field | Value |
|---|---|
| SHA-256 | `0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932` |
| Family label | `Mirai` |
| File name | `0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932` |
| File type | `elf` |
| First seen | `2026-10-23 22:23:59` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bc3ddc9459104c7cb9765addd8a0483` |
| SHA-1 | `763a8245fc6fb8c87dd990a38c9d44ad6ea05903` |
| SHA-256 | `0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932` |
| SHA3-384 | `728f8f73f3b5dcc73c1119dc0095c48a1e9ec4ea0b08397461600bb0b63f9e54278015a4be4acab0ba0856cfe00c881b` |
| TLSH | `T1BB83F715BB904FBBEC6FCD370AA9170134CC591A22A97B3A7934C91CF64F54B06E3968` |
| SSDEEP | `1536:eGCdmM8Sk3OMK9BHLH7Y+qvCeWNa+aZ79NaHE+Z:eGCdmM39PNa+ainZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_0d23bcb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
    family = "Mirai"
    file_name = "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
    file_type = "elf"
    first_seen = "2026-10-23 22:23:59"
  condition:
    hash.sha256(0, filesize) == "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
}
```

### Sample 63: `7eaf8ecbbabcf053`

| Field | Value |
|---|---|
| SHA-256 | `7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f` |
| Family label | `Mirai` |
| File name | `7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f` |
| File type | `elf` |
| First seen | `2026-10-23 22:23:52` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, i386, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81b39bdf55289199d804251373b203f4` |
| SHA-1 | `97423f2cc67adb1e99af6cf3b098e89fc0804842` |
| SHA-256 | `7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f` |
| SHA3-384 | `abb2bca954d1c150652ce50a83fd30eed92f30c7a77eb33473a18fd968c9eae80b9ab2aa69c0e9d3c35063dbd4c88708` |
| TLSH | `T1E3333AC49647E8F5FC560A752073E7738BB3F93E0129D997D368A532B862A01E60739C` |
| TELFHASH | `t1b921a2bb2e7648fd73d1ac48c31a26e3163ad2771aa032f545b66d9133f1ed480a4836` |
| SSDEEP | `1536:5NaTy+zeC/aqfWb2FySj0F4dP0J5rZ3WasqTgjw7Sa:6e+zR/3fWU64d8vrUasMiw5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_7eaf8ecb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f"
    family = "Mirai"
    file_name = "7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f"
    file_type = "elf"
    first_seen = "2026-10-23 22:23:52"
  condition:
    hash.sha256(0, filesize) == "7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f"
}
```

### Sample 64: `1b302ac2b21c2f21`

| Field | Value |
|---|---|
| SHA-256 | `1b302ac2b21c2f21695e2989ddf8d2b30582691880fd935dbd6eec5b35f4ad77` |
| Family label | `unknown` |
| File name | `macho_1b302ac2b21c.bin` |
| File type | `macho` |
| First seen | `2026-10-23 22:22:42` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fda2bf57039d359568a5eafe064c509` |
| SHA-1 | `b26c29236a4f7728bab76bc02af6c55d9a2d02a5` |
| SHA-256 | `1b302ac2b21c2f21695e2989ddf8d2b30582691880fd935dbd6eec5b35f4ad77` |
| SHA3-384 | `50879394ceced45da4b818cb9df9a9899b4c9c1938149e99502c2fec7d665e0f4b812cb350f48fae069017c39dd7e1e2` |
| TLSH | `T145A5F120152A2239D5CAF531AD01CFD9A4B0E6A01A4C79EB6B21D7617C336C3B5B7B37` |
| SSDEEP | `24576:Igpdj7ODHCbOMmfJhx1ZiMgEaOnfeahqAsj5PmPDj4ERb3C9c3qmD/vxHzI6IQo9:jyMOrllgG5PP4Y3Sc31ZLIya` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_1b302ac2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b302ac2b21c2f21695e2989ddf8d2b30582691880fd935dbd6eec5b35f4ad77"
    family = "unknown"
    file_name = "macho_1b302ac2b21c.bin"
    file_type = "macho"
    first_seen = "2026-10-23 22:22:42"
  condition:
    hash.sha256(0, filesize) == "1b302ac2b21c2f21695e2989ddf8d2b30582691880fd935dbd6eec5b35f4ad77"
}
```

### Sample 65: `8112b3afd6d0ec3d`

| Field | Value |
|---|---|
| SHA-256 | `8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-23 22:17:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd09c584022e4589943348f8e57b4b50` |
| SHA-1 | `d0dbddffcf4fd29aae53d96e2d0bb3cb3d4ef3b1` |
| SHA-256 | `8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59` |
| SHA3-384 | `cd49043a4ea3e86507318af50d6ac8d649cf8e051f75893a5e46d560ea43e9a219936a768b3678482f014a8590971020` |
| TLSH | `T1D9141956F8819F15C5C156BEFE0E528D33231BBCE2DE7202DD24AF60378A96B0A3B515` |
| TELFHASH | `t1e3a00172eb4a2a6ce7958e6144e486153a9a781e17505d42cb00a554a98ba6a2412503` |
| SSDEEP | `3072:GEgaFkvDiO/UicdPhxJU02zuoXQBAcSTaTngFCsc3bWKLCAensicTyu:pkvDiMNipxJrZoXlcIaoO3b7Zes//` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_8112b3af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-23 22:17:39"
  condition:
    hash.sha256(0, filesize) == "8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59"
}
```

### Sample 66: `f120b3dac18a1383`

| Field | Value |
|---|---|
| SHA-256 | `f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0` |
| Family label | `Mirai` |
| File name | `f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0` |
| File type | `sh` |
| First seen | `2026-10-23 22:08:57` |
| Reporter | `spydisec` |
| Tags | `cowrie, dropper, honeypot, Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a59c39e6fbfde3bba347097c4ac67115` |
| SHA-1 | `87150286778a49ab09e236245f5820461b3ac1f7` |
| SHA-256 | `f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0` |
| SHA3-384 | `b6e37f8402cfa0e666f900ff9eaf621d7e8e367432ca8b998f6760eebe9ae5a925c29922717474c66d8e735b1769ca38` |
| TLSH | `T18511E7A92252D435EDE39725F2A5CB196645F4AA50CC2D088DDE3DE0D08ED4CF78EF42` |
| SSDEEP | `12:q0FZf1WTf1l4/r+0FZf1BTf1z4/r+0FZf1wTf1pf4/r+0FZf1n7Tf10i4/rw:vp1S1GXp1t18Xp1M1pAXp1nX10jM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_f120b3da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0"
    family = "Mirai"
    file_name = "f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0"
    file_type = "sh"
    first_seen = "2026-10-23 22:08:57"
  condition:
    hash.sha256(0, filesize) == "f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0"
}
```

### Sample 67: `a56ca8d8d4b4f8d9`

| Field | Value |
|---|---|
| SHA-256 | `a56ca8d8d4b4f8d99280631393936621bb915abc90b8c2643b03e0369e3e240d` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-10-23 22:05:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29325d9ddfd94a229d19a90fe3a2391a` |
| SHA-1 | `d06c26a35e9300b0082d558bb4c51cdd55826dcb` |
| SHA-256 | `a56ca8d8d4b4f8d99280631393936621bb915abc90b8c2643b03e0369e3e240d` |
| SHA3-384 | `218f5dbf19093199fa113bd58b5d527c21359396baa3c49dd8c9891ac123ed5b35dc5dd04dc5e81f394a8518d35ae3c2` |
| TLSH | `T1AF34A60E6F228F3DF2A9877447F78E25975C23D726E1D681D2ACD1101E6438E641FBA8` |
| TELFHASH | `t11c41a1581d7817b4a2656c9d449dff6bd2a330eb7e162c238b50e86eeb69f834d10c0c` |
| SSDEEP | `3072:RLkQfQlO4sS2INF3NPhFoKhEiKcWaPU7xh62T8Tul0W5:RLkQfMsDyFTFOx1t7O2TqHW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_a56ca8d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56ca8d8d4b4f8d99280631393936621bb915abc90b8c2643b03e0369e3e240d"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-10-23 22:05:41"
  condition:
    hash.sha256(0, filesize) == "a56ca8d8d4b4f8d99280631393936621bb915abc90b8c2643b03e0369e3e240d"
}
```

### Sample 68: `c3b829a8e64408cf`

| Field | Value |
|---|---|
| SHA-256 | `c3b829a8e64408cff55ea1ab8cb557d029a15978f7e91e3add6044a84434ba57` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-10-23 21:59:13` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `207a20387a3767ce9e968dd6c5b39e23` |
| SHA-1 | `5c91ce20265a8ba704b78198e09997c2a43cb89c` |
| SHA-256 | `c3b829a8e64408cff55ea1ab8cb557d029a15978f7e91e3add6044a84434ba57` |
| SHA3-384 | `883a50f65f9ff0703bfef729d11b24344dbf8497426494595ad99f4651c1079a786741b66993804d3ae3d8472b5fad82` |
| TLSH | `T14F835AC5E6C3D8F5EE0705342066F337A132D9B84168FEE7FB54A6729431AA4704A78E` |
| TELFHASH | `t1db31b1f526360cd4a7d02852f64e23207e48db7f682076d316b32935223ee8243abc39` |
| SSDEEP | `1536:xK48MBPRQiF0l0Sth+MaUO2k70c0gio1LSCHTkYFLjeRImAdSunQRH:xBDPQi6l0Stogz80c0do1LNzRj2RALc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_c3b829a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3b829a8e64408cff55ea1ab8cb557d029a15978f7e91e3add6044a84434ba57"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-10-23 21:59:13"
  condition:
    hash.sha256(0, filesize) == "c3b829a8e64408cff55ea1ab8cb557d029a15978f7e91e3add6044a84434ba57"
}
```

### Sample 69: `1d40d231fcc6ad7c`

| Field | Value |
|---|---|
| SHA-256 | `1d40d231fcc6ad7c005a049c6f0d38d494ca0551ddc15d211c5d30f8d4bd27aa` |
| Family label | `unknown` |
| File name | `stage2.js` |
| File type | `js` |
| First seen | `2026-10-23 21:50:46` |
| Reporter | `skocherhan` |
| Tags | `download-transunionbiba-lat, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34c446168f2f61c894579e4a3b961447` |
| SHA-1 | `b4a4d4f7e4c3d9dbc3f273e5fcb0f056714bbc46` |
| SHA-256 | `1d40d231fcc6ad7c005a049c6f0d38d494ca0551ddc15d211c5d30f8d4bd27aa` |
| SHA3-384 | `706c91eea21afd9080c5e661ee96eabe3b58caa0b05c03e9790ce9866a0dd199c3366ba6afddbb19974197b9b7bd31e7` |
| TLSH | `T1BA1240768C12D4E3EA62158C633F0592623585670CA7D7213ACDE2E4BF1ADBD508F2E9` |
| SSDEEP | `192:coplSd64Q9NzFnqZ7JL+7zAKRcMRRmEcsdQ7:co3VoZ7JLY71R8dF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_1d40d231
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d40d231fcc6ad7c005a049c6f0d38d494ca0551ddc15d211c5d30f8d4bd27aa"
    family = "unknown"
    file_name = "stage2.js"
    file_type = "js"
    first_seen = "2026-10-23 21:50:46"
  condition:
    hash.sha256(0, filesize) == "1d40d231fcc6ad7c005a049c6f0d38d494ca0551ddc15d211c5d30f8d4bd27aa"
}
```

### Sample 70: `6103dcb39b6c5119`

| Field | Value |
|---|---|
| SHA-256 | `6103dcb39b6c5119bb257073de64149766fe3359323f9bf6f714f5ef714cc14c` |
| Family label | `Mirai` |
| File name | `manta.i686` |
| File type | `elf` |
| First seen | `2026-10-23 21:49:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8fef2d2bf141ba880e2fe9ac8db74d9` |
| SHA-1 | `b4c1a1a597ddce12bf7d4f279c51767868289b41` |
| SHA-256 | `6103dcb39b6c5119bb257073de64149766fe3359323f9bf6f714f5ef714cc14c` |
| SHA3-384 | `51ce36390ec9acba844fce3fd05bc3e6ef0783c386406a7e365748ffb5f84b395eb20060b5e491efc0daa54aa4d68c25` |
| TLSH | `T1E2858D8AEBD2D4B1F26340B0068FDBE2096466355003D9F7FF4A1D6A7436B915B1B33A` |
| TELFHASH | `t1ed8220b32bbd58ec6bf09505974f6610dee6e63719e038b145fb6cc026b2d425e71838` |
| SSDEEP | `24576:WWjKooIaFUK+XG8MeViLVuzttObxjGsz/eahfEhX4f2z9Op+kX8zptcFhxa35nEa:WW3aIyLitOb1hfEhIYAIa6RHTQG+Z4X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_6103dcb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6103dcb39b6c5119bb257073de64149766fe3359323f9bf6f714f5ef714cc14c"
    family = "Mirai"
    file_name = "manta.i686"
    file_type = "elf"
    first_seen = "2026-10-23 21:49:40"
  condition:
    hash.sha256(0, filesize) == "6103dcb39b6c5119bb257073de64149766fe3359323f9bf6f714f5ef714cc14c"
}
```

### Sample 71: `6ba5cc0bd8d377bc`

| Field | Value |
|---|---|
| SHA-256 | `6ba5cc0bd8d377bce422c8b45cc49f7c3843e1160033378e286357db5b5ba2d8` |
| Family label | `unknown` |
| File name | `new.txt` |
| File type | `elf` |
| First seen | `2026-10-23 21:48:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e625243aba2dfeefb3f525db3fcee4d6` |
| SHA-1 | `9751572dc947a40e6a11b649b94bef836c3f2d21` |
| SHA-256 | `6ba5cc0bd8d377bce422c8b45cc49f7c3843e1160033378e286357db5b5ba2d8` |
| SHA3-384 | `a1cd99f5e595ac94a2ed87a4adf2e406a8ba41819576c3df42d184b41526e7cdd87458426776d3163177eb72e3a54736` |
| TLSH | `T124662712FECB14F6E903193104BBA27F27315D058B24EB87EB407E29FD7B6A55932219` |
| TELFHASH | `t1942186b590f638452094052a8ec20c615f06a4e86776552b894f6ffa67c7ac48df312a` |
| SSDEEP | `98304:rUB3H3Ng3uFkoG2I4dky07hVS19aWHyE6l:r43Ng3PoG2IXVS19RfW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_6ba5cc0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ba5cc0bd8d377bce422c8b45cc49f7c3843e1160033378e286357db5b5ba2d8"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 21:48:27"
  condition:
    hash.sha256(0, filesize) == "6ba5cc0bd8d377bce422c8b45cc49f7c3843e1160033378e286357db5b5ba2d8"
}
```

### Sample 72: `19e4b77737c683d3`

| Field | Value |
|---|---|
| SHA-256 | `19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e` |
| Family label | `unknown` |
| File name | `new.txt` |
| File type | `elf` |
| First seen | `2026-10-23 21:47:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f77918307a241f6161a4bd6f1736489` |
| SHA-1 | `90976777316556bd045fa0093d6e56cd2d5004aa` |
| SHA-256 | `19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e` |
| SHA3-384 | `590ca3c553d13b22ed9115c77f739edee9fd4ca8eedd2539cb49385612f53f45b5eab785790504c2d10efd3dbc0ad35b` |
| TLSH | `T1D8D5332FE2A279954EA34D743E7D55E1D3A7722282334D877880E29F483A363EEC445D` |
| TELFHASH | `t14aa002d159ce4addc1613c5dc02369144006974f399a1f1343a18b79fa8de2033c2af5` |
| SSDEEP | `49152:CU+lXrmfzO33zEnVefglETopYm4+2n5rwFRE54qoKcwW9mYrft:CUimfm3Wkfgfpm+/FRE5iKTAmKft` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_19e4b777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 21:47:44"
  condition:
    hash.sha256(0, filesize) == "19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e"
}
```

### Sample 73: `f3edc42211737a96`

| Field | Value |
|---|---|
| SHA-256 | `f3edc42211737a96b81499f494f8d3603fde011b0959824780ebfa77a90ae736` |
| Family label | `Mirai` |
| File name | `manta.x86_64` |
| File type | `elf` |
| First seen | `2026-10-23 21:43:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5f1d73843888c4decd8632b859bfaa3` |
| SHA-1 | `5445160a4ea407d06d8c07ce0a349771f2ee8657` |
| SHA-256 | `f3edc42211737a96b81499f494f8d3603fde011b0959824780ebfa77a90ae736` |
| SHA3-384 | `1f1ce9af08eecf3c371743d24d39f55c7f1b920373c3695dbc4af51b15cb54875607dabe9a85ef6bdc89b247e70d40e3` |
| TLSH | `T11F857E1BB6E2A4BCC05BC030479FC6529A75F0B521327D7B37C49A313E66DA15B2DB22` |
| TELFHASH | `t103625f3108ba7462b2dbd412f353f4b86c7318b656f875b116736dcadde9e800c7a81a` |
| SSDEEP | `24576:hPQgpaMOHGI/1Ho4tM0te9pJ5+EM0jz3cwvoXIRHNWguv9KVCYlyM5ulo4Th9dy7:Wte9pJEn0jAwvYsNWBFKyM5uO4ThS/T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_f3edc422
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3edc42211737a96b81499f494f8d3603fde011b0959824780ebfa77a90ae736"
    family = "Mirai"
    file_name = "manta.x86_64"
    file_type = "elf"
    first_seen = "2026-10-23 21:43:45"
  condition:
    hash.sha256(0, filesize) == "f3edc42211737a96b81499f494f8d3603fde011b0959824780ebfa77a90ae736"
}
```

### Sample 74: `91015a7c0e203d60`

| Field | Value |
|---|---|
| SHA-256 | `91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca` |
| Family label | `Mirai` |
| File name | `manta.ppc` |
| File type | `elf` |
| First seen | `2026-10-23 21:43:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6692d160279c7d6363a16f8e32cd3403` |
| SHA-1 | `bb6f15cb35b37aac1bf3aeb30842c588080d646d` |
| SHA-256 | `91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca` |
| SHA3-384 | `e6124f0f5b9f38699f4790f3b3bc9b971158da51111426ef8c1cb81f1064bb691f6809c6fc9583e74f34873fee0472fc` |
| TLSH | `T1FB855C42FB098573CE430DF05A7F03E9E354655344B9E2292B0FAB272661A3AE5D738D` |
| SSDEEP | `24576:DdgF5Z/xsaGVjJIP0mY1pLBNIljH6ZEi7T8wo6SK9tfdSrj:DdcZpsaGVBmY1pLBNGHo7T8wo6SOdSrj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_91015a7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca"
    family = "Mirai"
    file_name = "manta.ppc"
    file_type = "elf"
    first_seen = "2026-10-23 21:43:43"
  condition:
    hash.sha256(0, filesize) == "91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca"
}
```

### Sample 75: `2c1af748b3109569`

| Field | Value |
|---|---|
| SHA-256 | `2c1af748b310956938189d47375b4b05f9d85ade6c5abdb52392b9f5b97a131f` |
| Family label | `DDoSAgent` |
| File name | `diddysbot-amd64` |
| File type | `elf` |
| First seen | `2026-10-23 21:38:26` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3455e6f6fc0ed1dda1182b528c53ee8` |
| SHA-1 | `7443d46da2538b6d0717b55b47f7f5b609705cf9` |
| SHA-256 | `2c1af748b310956938189d47375b4b05f9d85ade6c5abdb52392b9f5b97a131f` |
| SHA3-384 | `350db4e20fb26ef6f65aa48b91dbaffd3740ec6d32ca29868e379285aed0f560ca41014ced55ef857539a8c4786566fd` |
| TLSH | `T17B563943ECA545A8C0AED630C6629653BA717C885B3027D33F90F7792F76BD0AA79710` |
| TELFHASH | `t19d526d7559bd34b5b656da21f363b574967319a123f438b11063ac81ffc0e802caac7b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:M5K4X/syafoxWSwGC5HD05Hrgg0i53sMPKlnHoKHn+5EXGI9YRruC0P4iSyqM:ElsU05kHrgg0TDcEXSQQit` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_075_2c1af748
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c1af748b310956938189d47375b4b05f9d85ade6c5abdb52392b9f5b97a131f"
    family = "DDoSAgent"
    file_name = "diddysbot-amd64"
    file_type = "elf"
    first_seen = "2026-10-23 21:38:26"
  condition:
    hash.sha256(0, filesize) == "2c1af748b310956938189d47375b4b05f9d85ade6c5abdb52392b9f5b97a131f"
}
```

### Sample 76: `cfe0d25a1580916d`

| Field | Value |
|---|---|
| SHA-256 | `cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8` |
| Family label | `unknown` |
| File name | `cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8.exe` |
| File type | `exe` |
| First seen | `2026-10-23 21:37:32` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab133da759e361df9726c0242b61089b` |
| SHA-1 | `557ae6113a92cb947f6ca50468928901d619492c` |
| SHA-256 | `cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8` |
| SHA3-384 | `7927d85ae7fda3681844107346d6b5a76767659ea61e3f1b4290e3e1a8ac170a5afe3ece25a9b892b6539efba54d5568` |
| IMPHASH | `1a1e75f46f8fe92732efc0f6aa5ac353` |
| TLSH | `T1E9355B5177C55FB8F817A5BA83828231A6A17C6322F3D4FD798F42E3E5018548EF852E` |
| SSDEEP | `12288:tE0/PcsiI4pJYOCKJvOVi5nuiQs1clVp1eCiz+tPoyetKnNjUhzNrPoQUAP:tT/PMwcvOkuHNlZP/nNohzNrPx` |
| ICON-DHASH | `1032317969696000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_cfe0d25a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8"
    family = "unknown"
    file_name = "cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:37:32"
  condition:
    hash.sha256(0, filesize) == "cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8"
}
```

### Sample 77: `13d1dce34932712d`

| Field | Value |
|---|---|
| SHA-256 | `13d1dce34932712d2881f198e09746e0614b3b819fbc0812ed554b0035a92d59` |
| Family label | `DDoSAgent` |
| File name | `diddysbot-amd64` |
| File type | `elf` |
| First seen | `2026-10-23 21:37:14` |
| Reporter | `skocherhan` |
| Tags | `141-98-10-25, elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c29ed13c9c2b23786635566704063baa` |
| SHA-1 | `dfa4e9dabc6addeae0272e4676e74e768230bd1c` |
| SHA-256 | `13d1dce34932712d2881f198e09746e0614b3b819fbc0812ed554b0035a92d59` |
| SHA3-384 | `129ffc4fc1cba0ca26f87077547386d41629d25af2fbe9a5efcb22699e82c4f8ba4c1525c4b5ee26bedec4ab7ac42a7f` |
| TLSH | `T12995337EB90AB370C1D07FF24263742B4F8854DCADAE24A125463D464FE885B7A62BD4` |
| SSDEEP | `49152:WxrItweLMiyZFeecIdlb0WdRlWY6wFj5ydik4AlT0J3SVey:WxrfeLMiyZrVbrWY6qwdijvJqey` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_077_13d1dce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13d1dce34932712d2881f198e09746e0614b3b819fbc0812ed554b0035a92d59"
    family = "DDoSAgent"
    file_name = "diddysbot-amd64"
    file_type = "elf"
    first_seen = "2026-10-23 21:37:14"
  condition:
    hash.sha256(0, filesize) == "13d1dce34932712d2881f198e09746e0614b3b819fbc0812ed554b0035a92d59"
}
```

### Sample 78: `1e0bc3cab7b9207e`

| Field | Value |
|---|---|
| SHA-256 | `1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5` |
| Family label | `GoToResolve` |
| File name | `unattended-updater.exe` |
| File type | `exe` |
| First seen | `2026-10-23 21:29:53` |
| Reporter | `Flashcard8778` |
| Tags | `exe, GoToResolve, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a031f4d9e5c6e499bb4a364a0c51d318` |
| SHA-1 | `d066dabf47e9741faa8a4861b4e5f8d5c45fa25b` |
| SHA-256 | `1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5` |
| SHA3-384 | `66d56ddfe5f618a3c6788837f75b2d3a62a12901b501191d0a7a8331b17664e261c3de4e3ea0dee9e9df563d634a376f` |
| IMPHASH | `5189ce5f57ad974cac3971c024a8b454` |
| TLSH | `T1DA871217A2E602E4D5BAC079CA675507EBB17C0613306BDF12A4A2966F73AF01D3F325` |
| SSDEEP | `786432:jp79iDJ3/JfwcI9j5eAsW4Ykk2bxFz+ASxIVeYIyZ1aYjWtvLU:jd0JPJXWjgAs3LbxFz+PN9y2Q0U` |
| ICON-DHASH | `d4f0cccc96f0f0d4` |

#### Technical Assessment

- The sample is tracked as `GoToResolve` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoToResolve_078_1e0bc3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5"
    family = "GoToResolve"
    file_name = "unattended-updater.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:29:53"
  condition:
    hash.sha256(0, filesize) == "1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5"
}
```

### Sample 79: `2de8d333a5fce9c4`

| Field | Value |
|---|---|
| SHA-256 | `2de8d333a5fce9c4ade604dbcc09c7fa31d456da844aefe8160d05d2e38c9a90` |
| Family label | `unknown` |
| File name | `happyfun.msi` |
| File type | `msi` |
| First seen | `2026-10-23 21:20:58` |
| Reporter | `Flashcard8778` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45ccbbcb5f23a3630a0e65e93b05c5ee` |
| SHA-1 | `83d66f9f48aa2709fe0974ad61b596db40ed96c2` |
| SHA-256 | `2de8d333a5fce9c4ade604dbcc09c7fa31d456da844aefe8160d05d2e38c9a90` |
| SHA3-384 | `15463b3deb8028a87c94cc5b6d1f97056f94164491a74c518d8a5762c43a43c34fcaa7b026a1d3f7361b447b33981660` |
| TLSH | `T1CB872217A1E601A4D5BAC078CA6B5617EBB17C4613306BCF12A8B2956F73BF0193F325` |
| SSDEEP | `786432:iAEEzAQOSiC9t2RmYXZqt7S8kR4SdRQ21l99rTp7V9A3y+hBtGHlFX:iaAQ9QUMIt+8kJC21l99P90yYcD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_2de8d333
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2de8d333a5fce9c4ade604dbcc09c7fa31d456da844aefe8160d05d2e38c9a90"
    family = "unknown"
    file_name = "happyfun.msi"
    file_type = "msi"
    first_seen = "2026-10-23 21:20:58"
  condition:
    hash.sha256(0, filesize) == "2de8d333a5fce9c4ade604dbcc09c7fa31d456da844aefe8160d05d2e38c9a90"
}
```

### Sample 80: `5f177c003d73e20b`

| Field | Value |
|---|---|
| SHA-256 | `5f177c003d73e20b5135c9e60964ac8e56aeb0cc28b132e8a70e877181224c8d` |
| Family label | `unknown` |
| File name | `Adobe_acrobat_installer_win64.bat` |
| File type | `bat` |
| First seen | `2026-10-23 21:20:06` |
| Reporter | `Flashcard8778` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38451746eed8ebe20994a41092737bf4` |
| SHA-1 | `c82bd53a3a52919329007432995799c6f7d7839d` |
| SHA-256 | `5f177c003d73e20b5135c9e60964ac8e56aeb0cc28b132e8a70e877181224c8d` |
| SHA3-384 | `957c3f571f5855de974f6a272dd61feb0ca9df2847fa647318b6fa1e31f7d447ced895d6c40ce01252648de896803354` |
| TLSH | `T1F501DD072A0665F537FECA4811A2178D97CAC2C20BC392CFB925B329300E61BD681586` |
| SSDEEP | `12:wb4u4sd3/8XI1kUM8YFAHG31et8qx98OP8Xo8Wb8Com8V78TN8q7BuDV9MdRgHad:wKDD8YmHGQt8C98K8Xo8U8Cv8x8R8WBD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5f177c00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f177c003d73e20b5135c9e60964ac8e56aeb0cc28b132e8a70e877181224c8d"
    family = "unknown"
    file_name = "Adobe_acrobat_installer_win64.bat"
    file_type = "bat"
    first_seen = "2026-10-23 21:20:06"
  condition:
    hash.sha256(0, filesize) == "5f177c003d73e20b5135c9e60964ac8e56aeb0cc28b132e8a70e877181224c8d"
}
```

### Sample 81: `0da001fb45bfd95b`

| Field | Value |
|---|---|
| SHA-256 | `0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23` |
| Family label | `Mirai` |
| File name | `0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23.elf` |
| File type | `elf` |
| First seen | `2026-10-23 21:08:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `729debb4ae94cffbedd63e041b900f0d` |
| SHA-1 | `7588f2f5749420ced4d72854b97a91d9e6e5f2af` |
| SHA-256 | `0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23` |
| SHA3-384 | `5f46994c0b0734c0c1013c7080ee0679ab110e5f492663e88d4aa2a5705bff371d704221b07f834b8b15db89593c8363` |
| TLSH | `T108756C136B718F68F361D17045F38A976AA9119716F284CA83BCD2103E50A6E6C5FFE8` |
| TELFHASH | `t114f1bbda297513d8a7545d4d06ddef318da328df3ae60c238e11e48ee71bb835e21c29` |
| SSDEEP | `24576:SRTJl0Pwl+VfBzYb9zqN+4GIaH5s4+hWH8bLHWJ2psoZhQB/+4OH:S54D8MDAs4+hWH8MoeB/6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_0da001fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23"
    family = "Mirai"
    file_name = "0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23.elf"
    file_type = "elf"
    first_seen = "2026-10-23 21:08:59"
  condition:
    hash.sha256(0, filesize) == "0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23"
}
```

### Sample 82: `d697dcdd468a5b87`

| Field | Value |
|---|---|
| SHA-256 | `d697dcdd468a5b87b450e5c4bdfe1eb0e117c3012b4101865221ef208b37242e` |
| Family label | `unknown` |
| File name | `ryjku.dll` |
| File type | `exe` |
| First seen | `2026-10-23 21:03:54` |
| Reporter | `anonymous` |
| Tags | `exe, WARDENstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc659cbb17511fc027b9ca0708068fe3` |
| SHA-1 | `fdd53d081e1c3de133b7fe49580b6273e943fc0b` |
| SHA-256 | `d697dcdd468a5b87b450e5c4bdfe1eb0e117c3012b4101865221ef208b37242e` |
| SHA3-384 | `f5547370f0bd18c7325bf9386b5df16ebb7c321cdbb7e426ca22ae844986b762a0c713b1d8daeb1f4960ba275fd47186` |
| IMPHASH | `9618de8bb9b0e040b69ecffce842db25` |
| TLSH | `T16BE40206B6954AE8C425C27C8A075B1ADAB3BC2147546AEF17C5A73E1E337E4873CF21` |
| SSDEEP | `12288:6p4Wm04yc1lmFmJdvkmqJSPbH4OK1JYlY0LMeL86aajf:62bmevNOSPT4fqZLHL86aajf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_d697dcdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d697dcdd468a5b87b450e5c4bdfe1eb0e117c3012b4101865221ef208b37242e"
    family = "unknown"
    file_name = "ryjku.dll"
    file_type = "exe"
    first_seen = "2026-10-23 21:03:54"
  condition:
    hash.sha256(0, filesize) == "d697dcdd468a5b87b450e5c4bdfe1eb0e117c3012b4101865221ef208b37242e"
}
```

### Sample 83: `47c0d206cc928145`

| Field | Value |
|---|---|
| SHA-256 | `47c0d206cc9281453d3b71cac972945c1f2f4721e1b5332396ad812b60a4c867` |
| Family label | `unknown` |
| File name | `ytjtyj.exe` |
| File type | `exe` |
| First seen | `2026-10-23 21:03:41` |
| Reporter | `anonymous` |
| Tags | `exe, WARDENstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa0c60cb9b3fed5432bb2ab46393484c` |
| SHA-1 | `ea8130ff4863a54c67e85df5b5fefe4b48097fb6` |
| SHA-256 | `47c0d206cc9281453d3b71cac972945c1f2f4721e1b5332396ad812b60a4c867` |
| SHA3-384 | `f8303f32d979b4186d657d365c26cd4f473f54eafbb67df1673be4738e0d939410b988b3ad2a96208f62bbc95a56aa80` |
| IMPHASH | `d22cb25f898d2c0c7871b0cb22a39ac6` |
| TLSH | `T148C44B13F3A681DCD42AC8B583569133F6743C8D4630B6BB5BA46E652F36B90DB2DB04` |
| SSDEEP | `12288:KK/Fv6T4cRZB5bNhZ1xa07unDjfr5SCr/G5gt+:p9yThbNhroiu35+o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_47c0d206
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c0d206cc9281453d3b71cac972945c1f2f4721e1b5332396ad812b60a4c867"
    family = "unknown"
    file_name = "ytjtyj.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:03:41"
  condition:
    hash.sha256(0, filesize) == "47c0d206cc9281453d3b71cac972945c1f2f4721e1b5332396ad812b60a4c867"
}
```

### Sample 84: `d0018cd3ddfcb900`

| Field | Value |
|---|---|
| SHA-256 | `d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511` |
| Family label | `unknown` |
| File name | `bgbnrtn.exe` |
| File type | `exe` |
| First seen | `2026-10-23 21:03:21` |
| Reporter | `anonymous` |
| Tags | `exe, WARDENstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d643145a05bc39c671986d73bf57e1c6` |
| SHA-1 | `51b0fea3cb4dd12ad9f6565c5e616563a67a7c36` |
| SHA-256 | `d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511` |
| SHA3-384 | `71f09f21446c1b470855fb6346efa142f4099b19c9bfd34a98795798f4476098f57a9f530c2019f26fe9012ee0b53075` |
| IMPHASH | `1573cf7d031c716af67fe20acc73f901` |
| TLSH | `T12345ACB7A3751DB8F86985FBC5614B35BB3128721FE104AE458C1285CB2A7F08EF56E0` |
| SSDEEP | `12288:DJ0tzlpWbs6EkTp5SVQ9XkBc4qyYD3NxAFj98npGWRVzqpKPhL4A044QdqmcOKfO:lCzlItYQOcp3898RVziJA0JQnsC7` |
| ICON-DHASH | `d0ec3a72729a6713` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_d0018cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511"
    family = "unknown"
    file_name = "bgbnrtn.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:03:21"
  condition:
    hash.sha256(0, filesize) == "d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511"
}
```

### Sample 85: `a91554620e9ca25f`

| Field | Value |
|---|---|
| SHA-256 | `a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0` |
| Family label | `Mirai` |
| File name | `a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0.elf` |
| File type | `elf` |
| First seen | `2026-10-23 20:57:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bd77e851f22db25ab54d607b09860a4` |
| SHA-1 | `03131d47cddcde709ef1f198568e40eebb49b70b` |
| SHA-256 | `a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0` |
| SHA3-384 | `eedfa8af384f193376124bdb780e939377226ccc613ae004e50c4d74879ca467f0f0bbcf989d1801f0620e96fac42302` |
| TLSH | `T17FC3180ABFB15EBBD4AFCD3345AA470A28DC460621B53B766574D81CF21B28F56E3C60` |
| SSDEEP | `1536:uitW8YsBFxAN9bQhGXtgJPvUgxwtQydojYdjb8nTg5fMoO95aqyhAexVnDk2cvO1:uUbytgJPvUZc0DktObk0X63nv1W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_a9155462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0"
    family = "Mirai"
    file_name = "a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0.elf"
    file_type = "elf"
    first_seen = "2026-10-23 20:57:35"
  condition:
    hash.sha256(0, filesize) == "a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0"
}
```

### Sample 86: `48db2ddcc81839bb`

| Field | Value |
|---|---|
| SHA-256 | `48db2ddcc81839bbd26c206696a47dc772fb7892603616da09657cd976533f69` |
| Family label | `unknown` |
| File name | `MicroSip.exe` |
| File type | `exe` |
| First seen | `2026-10-23 20:37:13` |
| Reporter | `smica83` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0469ef66217caf2da44e5924cf0a40a8` |
| SHA-1 | `6ad230e48333e488814ec2b7a973e395f301083a` |
| SHA-256 | `48db2ddcc81839bbd26c206696a47dc772fb7892603616da09657cd976533f69` |
| SHA3-384 | `1254f360d6fb2bd2780e6f58500500067a0973464c7313707d9cd4c3dedb926893e663bd54d403bf491740aaed8409db` |
| IMPHASH | `8714c0e28f108fd3445d8230b0328a62` |
| TLSH | `T1C0B41B11B744ECA9D062B1BD4A4BC9C6D7337A850720AAD723D0F67B1F269844DBEBC1` |
| SSDEEP | `6144:XHgKGUhX6nz3DliEwcy9ct/AJzu2Qh6k68U0KeXUsDi4eYTdQI98hCI9Ec9dcEPY:3+Gmry9IAR0KCeYTdQC8Ew7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_48db2ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48db2ddcc81839bbd26c206696a47dc772fb7892603616da09657cd976533f69"
    family = "unknown"
    file_name = "MicroSip.exe"
    file_type = "exe"
    first_seen = "2026-10-23 20:37:13"
  condition:
    hash.sha256(0, filesize) == "48db2ddcc81839bbd26c206696a47dc772fb7892603616da09657cd976533f69"
}
```

### Sample 87: `d2d95c5534efcea6`

| Field | Value |
|---|---|
| SHA-256 | `d2d95c5534efcea6c63843cde59b617ac5b97e057d908298191468d5e3b7635a` |
| Family label | `unknown` |
| File name | `AzureCobalt57-77b11081.msi` |
| File type | `msi` |
| First seen | `2026-10-23 20:28:25` |
| Reporter | `smica83` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e385d8cb024874172c45d47abda42efb` |
| SHA-1 | `e33ceb404db0d3d3d7dcdb1768a4d3012dc2cb04` |
| SHA-256 | `d2d95c5534efcea6c63843cde59b617ac5b97e057d908298191468d5e3b7635a` |
| SHA3-384 | `e3b469f8363b7522864701d17b229f2fd9dd7cf0e4917c8b79fe8cd7f56750eed51bfd0e012d1433c20057ff98023fd2` |
| TLSH | `T171C7338288326E5BC62C453997B24300DBBA3D71BB02866637F0B11D5D7F7D13A79AC6` |
| SSDEEP | `786432:+ME+O3I9nQNXqhZBOAiG4p1Tz117Jow3eBAuFqh0uSO7s5WptW8HMGuhhypT9n:2eTqAiGm1P117JReB9vO7smQaMGXpTR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_d2d95c55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d95c5534efcea6c63843cde59b617ac5b97e057d908298191468d5e3b7635a"
    family = "unknown"
    file_name = "AzureCobalt57-77b11081.msi"
    file_type = "msi"
    first_seen = "2026-10-23 20:28:25"
  condition:
    hash.sha256(0, filesize) == "d2d95c5534efcea6c63843cde59b617ac5b97e057d908298191468d5e3b7635a"
}
```

### Sample 88: `48175649a0a7e1a2`

| Field | Value |
|---|---|
| SHA-256 | `48175649a0a7e1a2bc7ff7cd0f5ee5216a720dd3bc5a1f9ab522c649d3b2780b` |
| Family label | `Mirai` |
| File name | `manta.armv6l` |
| File type | `elf` |
| First seen | `2026-10-23 20:01:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a232ef2199c66cca009587bfee2d54a2` |
| SHA-1 | `761c6507c78210410f3a5cd2ec2649337d4c3670` |
| SHA-256 | `48175649a0a7e1a2bc7ff7cd0f5ee5216a720dd3bc5a1f9ab522c649d3b2780b` |
| SHA3-384 | `fce02637dbe3d80b3bff3b39272afa4e1a1412e67f4731a924b2e9a37acb5f9563849c22a3f0d0d5e3588e15efd9348d` |
| TLSH | `T193551965F880DFA1C6C06A7AF75D83A873134775D1EB7106CA198B343BF786E0A3A641` |
| TELFHASH | `t1ed0110729fcc1ecce3eac30059690253411836385348813dae79560c6b2b8c07b250b4` |
| SSDEEP | `24576:YI0YoGnHos1SnPlshKWrMzYtchHoKvbdZjr:lHo6SW5srB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_48175649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48175649a0a7e1a2bc7ff7cd0f5ee5216a720dd3bc5a1f9ab522c649d3b2780b"
    family = "Mirai"
    file_name = "manta.armv6l"
    file_type = "elf"
    first_seen = "2026-10-23 20:01:54"
  condition:
    hash.sha256(0, filesize) == "48175649a0a7e1a2bc7ff7cd0f5ee5216a720dd3bc5a1f9ab522c649d3b2780b"
}
```

### Sample 89: `c5d7e40a23719096`

| Field | Value |
|---|---|
| SHA-256 | `c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424` |
| Family label | `CoinMiner` |
| File name | `c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424.exe` |
| File type | `exe` |
| First seen | `2026-10-23 20:00:14` |
| Reporter | `KodaDr` |
| Tags | `Coinminer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `331d183a570848a2da3d0d1164da65fe` |
| SHA-1 | `69ef58178acfe9c281398a513687508afa104e85` |
| SHA-256 | `c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424` |
| SHA3-384 | `152acb73484b72b91b8c4bc9901fcc12312299e547c01ca361c7e5a385c34609dc4652b19eb4e93d2d00cb1f3bd39b06` |
| IMPHASH | `ad7d6e6e7106e4f6a5a57165dff0f59d` |
| TLSH | `T1DDD52387A28906F8DC13E0389259D331E732756447B6E8DB03A097617E67CD4AE3EF61` |
| SSDEEP | `49152:vO2jUAzWmSa50UWsquRg23wf01o2Xssvj8Hd+/SYJZ/2:1jUWpjWsvLwfOp8e8w/Si` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_089_c5d7e40a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424"
    family = "CoinMiner"
    file_name = "c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424.exe"
    file_type = "exe"
    first_seen = "2026-10-23 20:00:14"
  condition:
    hash.sha256(0, filesize) == "c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424"
}
```

### Sample 90: `7e481bc464442bee`

| Field | Value |
|---|---|
| SHA-256 | `7e481bc464442beec22caa8745e760c59354b6d6bf35f13602492df1eb9e502e` |
| Family label | `Mirai` |
| File name | `manta.mipsel` |
| File type | `elf` |
| First seen | `2026-10-23 19:59:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `986d4c2cc2ecb1d9601e7d8d02462f81` |
| SHA-1 | `1c3286b9ce67a09dc4f2107170368ef638f9c236` |
| SHA-256 | `7e481bc464442beec22caa8745e760c59354b6d6bf35f13602492df1eb9e502e` |
| SHA3-384 | `e870db8c153edb0359258d279b6d7332065e488d94a9a085599c4f216c9092e86982df0d04e32ede299d44822fcaddc2` |
| TLSH | `T10E757B02CF480FEFD8ABCD70863EC35719EE8D9702D6AA7551BC8D487A5961A4BC748C` |
| SSDEEP | `24576:+ICYAVTSHTRIDrTNKp9N+8i7hdAEQhq5ryt1UmQNN/7giAWSUFSFNevw+RNyMlDO:R4Xsp9N+FytwNadWJD7J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_7e481bc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e481bc464442beec22caa8745e760c59354b6d6bf35f13602492df1eb9e502e"
    family = "Mirai"
    file_name = "manta.mipsel"
    file_type = "elf"
    first_seen = "2026-10-23 19:59:52"
  condition:
    hash.sha256(0, filesize) == "7e481bc464442beec22caa8745e760c59354b6d6bf35f13602492df1eb9e502e"
}
```

### Sample 91: `b3c1d7ad6100e0c4`

| Field | Value |
|---|---|
| SHA-256 | `b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea` |
| Family label | `unknown` |
| File name | `app.jar` |
| File type | `jar` |
| First seen | `2026-10-23 19:41:12` |
| Reporter | `wok` |
| Tags | `jar, java, RAT, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b34f7b3879b236107b74108690436933` |
| SHA-1 | `1793ab69bb10ef4e394860b37df2ff8c250a7bb3` |
| SHA-256 | `b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea` |
| SHA3-384 | `946a23f3c1cf7948f202b6bf4ac113b44f52b5b4ea0019b22a2f7ff496c2e9d0e1bd3ceee77c853f9fdf33e2299bd0b6` |
| TLSH | `T1CF761317BDDBC468EEB755B791C38281646E25A8AC0B917E03D05DC68E60C8B035EFF9` |
| SSDEEP | `196608:upOs2khI0DIzNjhBMYYrsyg9w64Vz6E/7BOmroMouvbx:upr2e7DF/BDBDrorKV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_b3c1d7ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea"
    family = "unknown"
    file_name = "app.jar"
    file_type = "jar"
    first_seen = "2026-10-23 19:41:12"
  condition:
    hash.sha256(0, filesize) == "b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea"
}
```

### Sample 92: `0590fd1d1bd94f03`

| Field | Value |
|---|---|
| SHA-256 | `0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a` |
| Family label | `unknown` |
| File name | `uno-setup-1.0.0.exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:37:42` |
| Reporter | `wok` |
| Tags | `dropper, exe, RAT, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb0f0c86a41a7dad8d642b11199af134` |
| SHA-1 | `facde401445d5833a6079a9109a2c2eb3f5da148` |
| SHA-256 | `0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a` |
| SHA3-384 | `7d02ca6b7078951d7e1f9a38c34528696165d3697cde791fd8077dd3029fa6a0c5adc358b17bbb24650d8a939b658c6a` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T168583354B9ECA8BAF58A8034F553E3393D5BAE9F5520506B42CFBD9B3A71B0D4C0412B` |
| SSDEEP | `3145728:GQe4DoxfPF/8C+nvnTSYWoSurHJ/9bXhVt+7vl385ySor0lz3:g4DYRGnvnTvSuVVXhVuls5yQlD` |
| ICON-DHASH | `e0b09cca52d4f830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_0590fd1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a"
    family = "unknown"
    file_name = "uno-setup-1.0.0.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:37:42"
  condition:
    hash.sha256(0, filesize) == "0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a"
}
```

### Sample 93: `782b519154f11ae2`

| Field | Value |
|---|---|
| SHA-256 | `782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898` |
| Family label | `unknown` |
| File name | `4.zip` |
| File type | `zip` |
| First seen | `2026-10-23 19:14:38` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a14b3c54e502e21d947bffc4b0eda479` |
| SHA-1 | `8ec54aa2252469a4a7dd06993655d5c403649acb` |
| SHA-256 | `782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898` |
| SHA3-384 | `369624487153933f9080dc0c7274a8d89897ec1622071ca07ccdf3e307e07c9141693c1f69fe67a530bdd200255f5074` |
| TLSH | `T130D423B89A41016F53873226594985F4736B64431EA5F2C3BA7D0A763C034C7EA6FF87` |
| SSDEEP | `12288:MKRihLXUfmmA79nOek1y2XbCar1Cr7MQD/7dhR/:MPhLkfmzZnOZJdkr7MQDTdL/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_782b5191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898"
    family = "unknown"
    file_name = "4.zip"
    file_type = "zip"
    first_seen = "2026-10-23 19:14:38"
  condition:
    hash.sha256(0, filesize) == "782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898"
}
```

### Sample 94: `eea8223c913f9149`

| Field | Value |
|---|---|
| SHA-256 | `eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:12:46` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acb226599f597fe5f4b46b46ebceb246` |
| SHA-1 | `59d48b983eec0e016573216551daa7f5f5939791` |
| SHA-256 | `eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4` |
| SHA3-384 | `a9a6cf70b7a3f21833d17442a053a60e2737e084c1b975b46cd0ecb7fbe5ef45ad411e7087856675fdb05c3ed2c30ab3` |
| IMPHASH | `42c515ed0ef26e9448fe55fe3367a6b1` |
| TLSH | `T10F350652A332DDB8FC714238A8D6951214611033E4D73852E3FF36B50D9E62B7EFA929` |
| SSDEEP | `24576:jexUjlYnmNu+wUaxPOfJxTWPv6I34mOt:jc2+nmN7gbHn` |
| ICON-DHASH | `ffff716969f1ffff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_eea8223c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:12:46"
  condition:
    hash.sha256(0, filesize) == "eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4"
}
```

### Sample 95: `744f82adda79c794`

| Field | Value |
|---|---|
| SHA-256 | `744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2` |
| Family label | `RemusStealer` |
| File name | `ХLосitуХ64-v.8.807.exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:12:04` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Remus, RemusStealer, signed, Stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee5f5e9971a0b6bf60f49411d43ecdf8` |
| SHA-1 | `22dbca80786e472454fd780bbdb8e682ceef3713` |
| SHA-256 | `744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2` |
| SHA3-384 | `28537459d551aa646cf57aa7c8ac98ae8d4efc07c755cf95b2e7b0606cc25e3f463d02c0d163181b516a112c70085966` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16CE54A13BFA19078D4A6E235C8B74266B6B4BC4C5B3633E31E21BA342F727D09975B14` |
| SSDEEP | `24576:Hb8JR+lbxMwi5hZw8Ds7hhdLEM5NYRzoZ9HuQljcCul0HDfyDYqbYGfNBYAyZp:HOR+vM11wv7fdLEGNRPHrlg7CqbhW` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_095_744f82ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2"
    family = "RemusStealer"
    file_name = "ХLосitуХ64-v.8.807.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:12:04"
  condition:
    hash.sha256(0, filesize) == "744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2"
}
```

### Sample 96: `ed79c96c27657f7e`

| Field | Value |
|---|---|
| SHA-256 | `ed79c96c27657f7ea08a57b20bfeb1e0a8ca24c459dce98b8c1b74e5d9a9faae` |
| Family label | `unknown` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:09:57` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `429000990842d334df49dec819921cdb` |
| SHA-1 | `6e0881537e54ac5eb9d074959bd7214270b59c14` |
| SHA-256 | `ed79c96c27657f7ea08a57b20bfeb1e0a8ca24c459dce98b8c1b74e5d9a9faae` |
| SHA3-384 | `de37ea2b6316d3a4d3f7482262d7f1463bb62061a962daffad001cb4a30eea84d56e119eab3faad74e20b1582ac277d0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T172064A12BFE19179E4A6E235C8A74156B7F47C4C5B3A23E31E11BA342E723D09979F08` |
| SSDEEP | `49152:kVaYjjbJnawSKNWGkcWu3srqykczYt+ZMEo5AqbhQ:kzu7T+y3zw+AVQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_ed79c96c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed79c96c27657f7ea08a57b20bfeb1e0a8ca24c459dce98b8c1b74e5d9a9faae"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:09:57"
  condition:
    hash.sha256(0, filesize) == "ed79c96c27657f7ea08a57b20bfeb1e0a8ca24c459dce98b8c1b74e5d9a9faae"
}
```

### Sample 97: `ddf234d3c2de22d1`

| Field | Value |
|---|---|
| SHA-256 | `ddf234d3c2de22d1d57677e475eac83d6c6585caa64586ab40e1e5e1b77c0eb3` |
| Family label | `unknown` |
| File name | `IconLib.dll` |
| File type | `dll` |
| First seen | `2026-10-23 19:09:31` |
| Reporter | `Alex_sev` |
| Tags | `autoit, dll, loader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d72cb7fd979075592ad96b35b63f6553` |
| SHA-1 | `4de87d29dc37ba8f1cbb095c3615ec02a0fbd48d` |
| SHA-256 | `ddf234d3c2de22d1d57677e475eac83d6c6585caa64586ab40e1e5e1b77c0eb3` |
| SHA3-384 | `6f0556bb99a3e9ca2dc009b595ff70eebd95fdc38a6f9698d772b805925602501c9627fceec2b37b4ad1f16785a1fef7` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T1E61633511004B499C3DFDF7F64B6B4D90772AAA2B2E5C118BE1D32744EA4FE20D5BE81` |
| SSDEEP | `49152:IibBiwdk2Ai/T7R6r3/OoKAZyqLyERF0Kx0YGA7NzxtQXegLOS9WMpIt5Gy8Jl42:/bBiwdkGgrWoEJQMKNzkugL8tvGq05ea` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_ddf234d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddf234d3c2de22d1d57677e475eac83d6c6585caa64586ab40e1e5e1b77c0eb3"
    family = "unknown"
    file_name = "IconLib.dll"
    file_type = "dll"
    first_seen = "2026-10-23 19:09:31"
  condition:
    hash.sha256(0, filesize) == "ddf234d3c2de22d1d57677e475eac83d6c6585caa64586ab40e1e5e1b77c0eb3"
}
```

### Sample 98: `a58c639a10831e63`

| Field | Value |
|---|---|
| SHA-256 | `a58c639a10831e63e3cd237614d5c7b7a52eecdc576cfd2ec37d3ccaf3caa6e7` |
| Family label | `unknown` |
| File name | `Chronical-Boot_V2.exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:09:05` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Stealer, Vidar, VidarStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01ab970e35894f7aae5974d16799d75d` |
| SHA-1 | `c618d443aa71463824b4b302ae2c097e256362d1` |
| SHA-256 | `a58c639a10831e63e3cd237614d5c7b7a52eecdc576cfd2ec37d3ccaf3caa6e7` |
| SHA3-384 | `3ff525eb7e21f0a8dcad0465b0e89026114210a62e692b81ba28c58ec258eb17f79ca8c454b15d7d748c618a34538cee` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C116AF0BBC900999C5AAAB36857341627E707C489B3663D76F80B7BD3F72BC65934B04` |
| SSDEEP | `98304:efDJPXtlTzWq1FVGbaRsB1Rf78oI9M+PP:ebRX//NwdA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_a58c639a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a58c639a10831e63e3cd237614d5c7b7a52eecdc576cfd2ec37d3ccaf3caa6e7"
    family = "unknown"
    file_name = "Chronical-Boot_V2.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:09:05"
  condition:
    hash.sha256(0, filesize) == "a58c639a10831e63e3cd237614d5c7b7a52eecdc576cfd2ec37d3ccaf3caa6e7"
}
```

### Sample 99: `a5d4f63e443a39d7`

| Field | Value |
|---|---|
| SHA-256 | `a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b` |
| Family label | `AokigaharaStealer` |
| File name | `glaicier.exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:07:52` |
| Reporter | `AmadeyHunter` |
| Tags | `Aokigahara, AokigaharaStealer, exe, signed, Stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9453806028e89be7dddd9777027f8487` |
| SHA-1 | `bffbe29481217057dfe5afa0e244254e3a71f41f` |
| SHA-256 | `a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b` |
| SHA3-384 | `3dc2d075c301956faf6118bc38da12f280c6cf1058f6f1d01b7df762974ffb241eef781eab5b5356d4d6a6f2376963d9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C5D57E0BBC9449A8D59AAB358A7241627A74BC488B3133DB7FC0B3783F72BC15979744` |
| SSDEEP | `49152:B2RyaPkU90ZdEwaQzwTR/NIK2SNlq86dN:BEkDZFfzw4K2AsPD` |

#### Technical Assessment

- The sample is tracked as `AokigaharaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AokigaharaStealer_099_a5d4f63e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b"
    family = "AokigaharaStealer"
    file_name = "glaicier.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:07:52"
  condition:
    hash.sha256(0, filesize) == "a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b"
}
```

### Sample 100: `ab0e12344f718096`

| Field | Value |
|---|---|
| SHA-256 | `ab0e12344f7180962f5f0ed940d7001747ec937d6304ef305d1bcad9954f6835` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-10-23 19:07:45` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5af9dfcfac90341ea35277ab4a299885` |
| SHA-1 | `cd2cba02c0dbe4407fa8a2eb1c79bef926ed2938` |
| SHA-256 | `ab0e12344f7180962f5f0ed940d7001747ec937d6304ef305d1bcad9954f6835` |
| SHA3-384 | `de6ca3efeee694c138e69f5bc08bf9c7eef454ea99ed62d0e0c5a9b83e7c2c6a1d197ef888381027d314dde387478a11` |
| IMPHASH | `2122844571285783370de4f94ccae46b` |
| TLSH | `T1ED354BFA2316E9FAD5D6723469408ECA3613E601963265764F36B8F7D43C3C2F0B61A4` |
| SSDEEP | `24576:TOW16OXmR/UcoVI+tBL47VPlBzQTgn7/iO:qWo2/coVF4BlBzQTCv` |
| ICON-DHASH | `0012696165640800` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_ab0e1234
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab0e12344f7180962f5f0ed940d7001747ec937d6304ef305d1bcad9954f6835"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:07:45"
  condition:
    hash.sha256(0, filesize) == "ab0e12344f7180962f5f0ed940d7001747ec937d6304ef305d1bcad9954f6835"
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
 * Generated: 2026-10-24T04:46:34.856437+00:00
 */

rule MalwareBazaar_unknown_001_f5cfe0cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5cfe0cf4f22c4cabae5ac6d031e83986f6942a5d3178dcd6ee91231f4600520"
    family = "unknown"
    file_name = "f5cfe0cf4f22c4ca.js"
    file_type = "js"
    first_seen = "2026-10-24 04:45:45"
  condition:
    hash.sha256(0, filesize) == "f5cfe0cf4f22c4cabae5ac6d031e83986f6942a5d3178dcd6ee91231f4600520"
}

rule MalwareBazaar_Mirai_002_f9a52c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9a52c71cf014bdfe827b0e8c60e6c41caac4e498b46d998f4a1c40b6eb37ff9"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.i686"
    file_type = "elf"
    first_seen = "2026-10-24 04:13:43"
  condition:
    hash.sha256(0, filesize) == "f9a52c71cf014bdfe827b0e8c60e6c41caac4e498b46d998f4a1c40b6eb37ff9"
}

rule MalwareBazaar_Mirai_003_3ab069c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab069c4c650c4ff1c8fa4dde90c8691b316a0aadf5693d56ec29370b6dc9d2c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-24 04:09:40"
  condition:
    hash.sha256(0, filesize) == "3ab069c4c650c4ff1c8fa4dde90c8691b316a0aadf5693d56ec29370b6dc9d2c"
}

rule MalwareBazaar_Mirai_004_ba44d153
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.spc"
    file_type = "elf"
    first_seen = "2026-10-24 04:05:41"
  condition:
    hash.sha256(0, filesize) == "ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787"
}

rule MalwareBazaar_Mirai_005_40f4b059
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f4b0593bec556d663b11046e1e54488044eddbf314341b3ac4f5d733eb2de9"
    family = "Mirai"
    file_name = "MMaaRRiiOisecTanee.sh4"
    file_type = "elf"
    first_seen = "2026-10-24 03:57:38"
  condition:
    hash.sha256(0, filesize) == "40f4b0593bec556d663b11046e1e54488044eddbf314341b3ac4f5d733eb2de9"
}

rule MalwareBazaar_unknown_006_a56f66cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2"
    family = "unknown"
    file_name = "2be0cf0161e40183.bin"
    file_type = "elf"
    first_seen = "2026-10-24 03:26:24"
  condition:
    hash.sha256(0, filesize) == "a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2"
}

rule MalwareBazaar_RustyStealer_007_d1ab5c35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af"
    family = "RustyStealer"
    file_name = "d1ab5c35e09e0d0b.bin"
    file_type = "exe"
    first_seen = "2026-10-24 03:26:05"
  condition:
    hash.sha256(0, filesize) == "d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af"
}

rule MalwareBazaar_RustyStealer_008_bdff003f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36"
    family = "RustyStealer"
    file_name = "bdff003f47f176d4.bin"
    file_type = "exe"
    first_seen = "2026-10-24 03:25:55"
  condition:
    hash.sha256(0, filesize) == "bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36"
}

rule MalwareBazaar_unknown_009_2be0cf01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d"
    family = "unknown"
    file_name = "2be0cf0161e40183.bin"
    file_type = "elf"
    first_seen = "2026-10-24 03:25:46"
  condition:
    hash.sha256(0, filesize) == "2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d"
}

rule MalwareBazaar_RustyStealer_010_d65fec38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0"
    family = "RustyStealer"
    file_name = "d65fec3809cf4341.bin"
    file_type = "exe"
    first_seen = "2026-10-24 03:25:35"
  condition:
    hash.sha256(0, filesize) == "d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0"
}

rule MalwareBazaar_unknown_011_b1bf43f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7"
    family = "unknown"
    file_name = "redtail.arm7"
    file_type = "elf"
    first_seen = "2026-10-24 03:23:11"
  condition:
    hash.sha256(0, filesize) == "b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7"
}

rule MalwareBazaar_Mirai_012_edcd4de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90"
    family = "Mirai"
    file_name = "bix.sh"
    file_type = "elf"
    first_seen = "2026-10-24 03:22:39"
  condition:
    hash.sha256(0, filesize) == "edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90"
}

rule MalwareBazaar_Mirai_013_da54c107
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303"
    family = "Mirai"
    file_name = "lv.sh"
    file_type = "sh"
    first_seen = "2026-10-24 03:21:09"
  condition:
    hash.sha256(0, filesize) == "da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303"
}

rule MalwareBazaar_unknown_014_96082e1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96082e1bb5350495ce83fe6ad1c26cfde4c31171c0f200bc68585d2d08f3d9ef"
    family = "unknown"
    file_name = "96082e1bb5350495.bin"
    file_type = "exe"
    first_seen = "2026-10-24 02:26:16"
  condition:
    hash.sha256(0, filesize) == "96082e1bb5350495ce83fe6ad1c26cfde4c31171c0f200bc68585d2d08f3d9ef"
}

rule MalwareBazaar_Adware_OfferCore_015_8c35b7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c35b7d47f65832206369e00760fea41bf20e023596cd2dad966d02bafa93151"
    family = "Adware.OfferCore"
    file_name = "8c35b7d47f658322.bin"
    file_type = "exe"
    first_seen = "2026-10-24 02:26:01"
  condition:
    hash.sha256(0, filesize) == "8c35b7d47f65832206369e00760fea41bf20e023596cd2dad966d02bafa93151"
}

rule MalwareBazaar_unknown_016_ef67a672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef67a672ece71861f810bdff3e9bdbf5bc14daa347861bed3ce1d1dddb68031c"
    family = "unknown"
    file_name = "ef67a672ece71861.bin"
    file_type = "exe"
    first_seen = "2026-10-24 01:24:19"
  condition:
    hash.sha256(0, filesize) == "ef67a672ece71861f810bdff3e9bdbf5bc14daa347861bed3ce1d1dddb68031c"
}

rule MalwareBazaar_unknown_017_26e0644c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26e0644cf7ad60cc0d8aebe5381251eacc124860a969cb5db5c8aab83c86a2b3"
    family = "unknown"
    file_name = "26e0644cf7ad60cc.bin"
    file_type = "exe"
    first_seen = "2026-10-24 01:24:07"
  condition:
    hash.sha256(0, filesize) == "26e0644cf7ad60cc0d8aebe5381251eacc124860a969cb5db5c8aab83c86a2b3"
}

rule MalwareBazaar_ConnectWise_018_ec742d1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec742d1bb8e067b6acb1acb1dbbbcbd8f5505e47a3561bfbd5b4068771d4d5b7"
    family = "ConnectWise"
    file_name = "ec742d1bb8e067b6.bin"
    file_type = "msi"
    first_seen = "2026-10-24 01:23:55"
  condition:
    hash.sha256(0, filesize) == "ec742d1bb8e067b6acb1acb1dbbbcbd8f5505e47a3561bfbd5b4068771d4d5b7"
}

rule MalwareBazaar_unknown_019_b1332b2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1332b2c5de9f56d125cb23606a44b82d51250b5c0e199b6ade154681bb8197e"
    family = "unknown"
    file_name = "b1332b2c5de9f56d.bin"
    file_type = "macho"
    first_seen = "2026-10-24 01:23:44"
  condition:
    hash.sha256(0, filesize) == "b1332b2c5de9f56d125cb23606a44b82d51250b5c0e199b6ade154681bb8197e"
}

rule MalwareBazaar_unknown_020_0bde7e85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d"
    family = "unknown"
    file_name = "macho_0bde7e85c0d4.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:46:03"
  condition:
    hash.sha256(0, filesize) == "0bde7e85c0d4d2f39996772a6348b1bee4717349afa648a301f182529429c81d"
}

rule MalwareBazaar_unknown_021_fb3a907f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23"
    family = "unknown"
    file_name = "macho_fb3a907fa1c5.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:43:12"
  condition:
    hash.sha256(0, filesize) == "fb3a907fa1c573b1d5604fb511c9c9c04d3f8b75bbdacd1402c31b53b5393a23"
}

rule MalwareBazaar_unknown_022_11387a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d"
    family = "unknown"
    file_name = "macho_11387a0d240c.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:40:25"
  condition:
    hash.sha256(0, filesize) == "11387a0d240ca6a184d4fd7524e63661012b26a51926ba6562fd7d966ad1b23d"
}

rule MalwareBazaar_unknown_023_d2ec7a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db"
    family = "unknown"
    file_name = "macho_d2ec7a876540.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:37:27"
  condition:
    hash.sha256(0, filesize) == "d2ec7a876540ce8f4096e004a42db4cb541383a2bd85087169bc96fda4c875db"
}

rule MalwareBazaar_unknown_024_003bcc4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "003bcc4fb74050c564d7bcd6246d2ee13d1403eff1bb78cfcfe5945d4f499d67"
    family = "unknown"
    file_name = "macho_003bcc4fb740.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:34:38"
  condition:
    hash.sha256(0, filesize) == "003bcc4fb74050c564d7bcd6246d2ee13d1403eff1bb78cfcfe5945d4f499d67"
}

rule MalwareBazaar_unknown_025_840ebbef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd"
    family = "unknown"
    file_name = "macho_840ebbef896e.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:31:38"
  condition:
    hash.sha256(0, filesize) == "840ebbef896ec2ccff40ce45096b63a6145665244077626d78509d7fdc32f6dd"
}

rule MalwareBazaar_unknown_026_6015a6d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16"
    family = "unknown"
    file_name = "macho_6015a6d3a00d.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:28:35"
  condition:
    hash.sha256(0, filesize) == "6015a6d3a00d5771932ce7abf625a53c0bc4ba6b2353bd7e033f2434d708fe16"
}

rule MalwareBazaar_SalatStealer_027_188e8261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "188e8261855740338dcfd6bfbcbbb3380658276fc733300829087eab66818696"
    family = "SalatStealer"
    file_name = "12784917afb2b0f5.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:26:00"
  condition:
    hash.sha256(0, filesize) == "188e8261855740338dcfd6bfbcbbb3380658276fc733300829087eab66818696"
}

rule MalwareBazaar_SalatStealer_028_121f6d62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb"
    family = "SalatStealer"
    file_name = "f01781bf62e0a384.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:25:52"
  condition:
    hash.sha256(0, filesize) == "121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb"
}

rule MalwareBazaar_unknown_029_0bb6aca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3"
    family = "unknown"
    file_name = "macho_0bb6aca14af0.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:25:46"
  condition:
    hash.sha256(0, filesize) == "0bb6aca14af0fb513500770ca601c5b66e46c47e565f6e87c31f0c293fa8f5e3"
}

rule MalwareBazaar_SalatStealer_030_d1ecb741
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ecb7411b7d55b5e8016e0f0a9359bc39f85e33ce6a5ea7985863ccb2d152c8"
    family = "SalatStealer"
    file_name = "79f3a3dd483248bc.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:25:43"
  condition:
    hash.sha256(0, filesize) == "d1ecb7411b7d55b5e8016e0f0a9359bc39f85e33ce6a5ea7985863ccb2d152c8"
}

rule MalwareBazaar_unknown_031_f866b357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f866b357edfe87a5c735185737680779975c2659b1a26c6cccd81514705d1013"
    family = "unknown"
    file_name = "20e1245cf23bc8d0.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:25:32"
  condition:
    hash.sha256(0, filesize) == "f866b357edfe87a5c735185737680779975c2659b1a26c6cccd81514705d1013"
}

rule MalwareBazaar_SalatStealer_032_12784917
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12784917afb2b0f5adafb44b94c3ef3019ccf6a991fcfe9033415bb45a5d931c"
    family = "SalatStealer"
    file_name = "12784917afb2b0f5.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:56"
  condition:
    hash.sha256(0, filesize) == "12784917afb2b0f5adafb44b94c3ef3019ccf6a991fcfe9033415bb45a5d931c"
}

rule MalwareBazaar_SalatStealer_033_f01781bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f01781bf62e0a3846c288da5483ace08c63492a632762173f4ba6107799128a6"
    family = "SalatStealer"
    file_name = "f01781bf62e0a384.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:46"
  condition:
    hash.sha256(0, filesize) == "f01781bf62e0a3846c288da5483ace08c63492a632762173f4ba6107799128a6"
}

rule MalwareBazaar_SalatStealer_034_79f3a3dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7"
    family = "SalatStealer"
    file_name = "79f3a3dd483248bc.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:36"
  condition:
    hash.sha256(0, filesize) == "79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7"
}

rule MalwareBazaar_SalatStealer_035_20e1245c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20e1245cf23bc8d0946dab9b8747dd189acef5cf09546257e7fc298a7c6717fd"
    family = "SalatStealer"
    file_name = "20e1245cf23bc8d0.bin"
    file_type = "exe"
    first_seen = "2026-10-24 00:24:26"
  condition:
    hash.sha256(0, filesize) == "20e1245cf23bc8d0946dab9b8747dd189acef5cf09546257e7fc298a7c6717fd"
}

rule MalwareBazaar_unknown_036_ff72b39a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3"
    family = "unknown"
    file_name = "macho_ff72b39a5596.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:22:56"
  condition:
    hash.sha256(0, filesize) == "ff72b39a559646d5a546eba3c939994ce9c3ed28efe200fa7929018c11292dd3"
}

rule MalwareBazaar_unknown_037_5670d4f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a"
    family = "unknown"
    file_name = "macho_5670d4f79411.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:20:07"
  condition:
    hash.sha256(0, filesize) == "5670d4f79411fd5cb2ec03c2b5ed81b44e2b0681a72de5d9ce0de4001066d02a"
}

rule MalwareBazaar_unknown_038_b61faf48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352"
    family = "unknown"
    file_name = "macho_b61faf483a13.bin"
    file_type = "macho"
    first_seen = "2026-10-24 00:17:15"
  condition:
    hash.sha256(0, filesize) == "b61faf483a13cc25f7b90129cb7088cd498560a09c1a014b5ca72ab713814352"
}

rule MalwareBazaar_unknown_039_0ed065d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ed065d88f132e4356c99545955f749be9519f8783d7390e98e8ec8656bc2d4b"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 23:50:25"
  condition:
    hash.sha256(0, filesize) == "0ed065d88f132e4356c99545955f749be9519f8783d7390e98e8ec8656bc2d4b"
}

rule MalwareBazaar_unknown_040_5efa2d85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efa2d854e5a9ffec32ea81525d24875075e1017dce93cd18a4df6d703c7fd11"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 23:49:40"
  condition:
    hash.sha256(0, filesize) == "5efa2d854e5a9ffec32ea81525d24875075e1017dce93cd18a4df6d703c7fd11"
}

rule MalwareBazaar_Mirai_041_6f714f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-23 23:33:42"
  condition:
    hash.sha256(0, filesize) == "6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a"
}

rule MalwareBazaar_unknown_042_e3ccd986
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3ccd986aa9ecd55ed9918635b544ac7c2d3d11cdb3ab19e7d1f7879d720d655"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-23 23:31:09"
  condition:
    hash.sha256(0, filesize) == "e3ccd986aa9ecd55ed9918635b544ac7c2d3d11cdb3ab19e7d1f7879d720d655"
}

rule MalwareBazaar_unknown_043_7f6e7113
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f6e711385a4ec779286c9e2f035fda3b86e75ce2d50725dcd8facb6c07b4116"
    family = "unknown"
    file_name = "7f6e711385a4ec77.ps1"
    file_type = "ps1"
    first_seen = "2026-10-23 23:30:41"
  condition:
    hash.sha256(0, filesize) == "7f6e711385a4ec779286c9e2f035fda3b86e75ce2d50725dcd8facb6c07b4116"
}

rule MalwareBazaar_Mirai_044_619e9994
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-23 23:25:46"
  condition:
    hash.sha256(0, filesize) == "619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba"
}

rule MalwareBazaar_Mirai_045_226bd33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
    family = "Mirai"
    file_name = "manta.armv7l"
    file_type = "elf"
    first_seen = "2026-10-23 23:25:43"
  condition:
    hash.sha256(0, filesize) == "226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5"
}

rule MalwareBazaar_unknown_046_c15a21e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77"
    family = "unknown"
    file_name = "macho_c15a21e69b31.bin"
    file_type = "macho"
    first_seen = "2026-10-23 23:22:28"
  condition:
    hash.sha256(0, filesize) == "c15a21e69b3142e50d4e42a4203741d924795b44a6a3907dcaf2a5dec0ae9d77"
}

rule MalwareBazaar_Mirai_047_0f832aca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05"
    family = "Mirai"
    file_name = "manta.m68k"
    file_type = "elf"
    first_seen = "2026-10-23 23:21:45"
  condition:
    hash.sha256(0, filesize) == "0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05"
}

rule MalwareBazaar_Mirai_048_2973d2d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-23 23:09:43"
  condition:
    hash.sha256(0, filesize) == "2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef"
}

rule MalwareBazaar_Mirai_049_97fdba0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-10-23 23:05:45"
  condition:
    hash.sha256(0, filesize) == "97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7"
}

rule MalwareBazaar_Mirai_050_1826b5c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-23 23:01:46"
  condition:
    hash.sha256(0, filesize) == "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
}

rule MalwareBazaar_Mirai_051_f0c49d9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0c49d9a504002a1305b4d79e5f427c813355ff92536429d8ce0819f773fabe9"
    family = "Mirai"
    file_name = "manta.sh4"
    file_type = "elf"
    first_seen = "2026-10-23 22:57:44"
  condition:
    hash.sha256(0, filesize) == "f0c49d9a504002a1305b4d79e5f427c813355ff92536429d8ce0819f773fabe9"
}

rule MalwareBazaar_Mirai_052_638fe652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-23 22:47:48"
  condition:
    hash.sha256(0, filesize) == "638fe6527fcaeb06f6199c59c4cdd1a76fe15777951ed9223866655c250f000c"
}

rule MalwareBazaar_unknown_053_1212bfc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d"
    family = "unknown"
    file_name = "3574378_13_-setup.msi"
    file_type = "msi"
    first_seen = "2026-10-23 22:41:21"
  condition:
    hash.sha256(0, filesize) == "1212bfc031aa5dac0e236a57d591c7c36d6847a3596c6e150b7e0899d4e92a5d"
}

rule MalwareBazaar_Mirai_054_b1b5dd6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-10-23 22:37:40"
  condition:
    hash.sha256(0, filesize) == "b1b5dd6e77801cd112ec598f32662628664125ff7d008911d3aa75feb09959ed"
}

rule MalwareBazaar_Mirai_055_e2ea41d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-23 22:37:38"
  condition:
    hash.sha256(0, filesize) == "e2ea41d1deab665e2f47974523d7d88f1496a24080fadeba706388d310148022"
}

rule MalwareBazaar_Mirai_056_a2017066
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-10-23 22:33:39"
  condition:
    hash.sha256(0, filesize) == "a20170667b22b3776fdcb9098320cc6cb306556d9f8387e5ee11da31ed09643a"
}

rule MalwareBazaar_Mirai_057_9aba42d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775"
    family = "Mirai"
    file_name = "manta.aarch64"
    file_type = "elf"
    first_seen = "2026-10-23 22:31:40"
  condition:
    hash.sha256(0, filesize) == "9aba42d500b0941aad7bb39b5423e89311a6a8639ba6e3be1648bf7b0f28a775"
}

rule MalwareBazaar_unknown_058_14a75070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14a75070ab15d4e2b74399aca5c16dc762018d0b48d94b18aa77f8947a013a0f"
    family = "unknown"
    file_name = "_WRFVL2CLdcf8.tmp.7z"
    file_type = "7z"
    first_seen = "2026-10-23 22:28:40"
  condition:
    hash.sha256(0, filesize) == "14a75070ab15d4e2b74399aca5c16dc762018d0b48d94b18aa77f8947a013a0f"
}

rule MalwareBazaar_Mirai_059_b5e7c5df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-10-23 22:27:35"
  condition:
    hash.sha256(0, filesize) == "b5e7c5dfa2888d052a75d93a9dfba6ecfc723670aba1994b6d79feee5af74766"
}

rule MalwareBazaar_Mirai_060_c76ed9ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a"
    family = "Mirai"
    file_name = "c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a"
    file_type = "elf"
    first_seen = "2026-10-23 22:24:13"
  condition:
    hash.sha256(0, filesize) == "c76ed9ab219d002e3ecfd84f8cf8456e165d9265efeeecdf52b5665e6d18999a"
}

rule MalwareBazaar_Mirai_061_308ee11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08"
    family = "Mirai"
    file_name = "308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08"
    file_type = "elf"
    first_seen = "2026-10-23 22:24:06"
  condition:
    hash.sha256(0, filesize) == "308ee11f9b4fa86146be71ac81669dbecabf960097da111ef62dbae17e740b08"
}

rule MalwareBazaar_Mirai_062_0d23bcb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
    family = "Mirai"
    file_name = "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
    file_type = "elf"
    first_seen = "2026-10-23 22:23:59"
  condition:
    hash.sha256(0, filesize) == "0d23bcb2e85eba59d7b40cdaef8ad8290834caf4ac00260f567cf5d037e78932"
}

rule MalwareBazaar_Mirai_063_7eaf8ecb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f"
    family = "Mirai"
    file_name = "7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f"
    file_type = "elf"
    first_seen = "2026-10-23 22:23:52"
  condition:
    hash.sha256(0, filesize) == "7eaf8ecbbabcf05392af010ee8e0f79e13036203ca36908721257fec5ea72a5f"
}

rule MalwareBazaar_unknown_064_1b302ac2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b302ac2b21c2f21695e2989ddf8d2b30582691880fd935dbd6eec5b35f4ad77"
    family = "unknown"
    file_name = "macho_1b302ac2b21c.bin"
    file_type = "macho"
    first_seen = "2026-10-23 22:22:42"
  condition:
    hash.sha256(0, filesize) == "1b302ac2b21c2f21695e2989ddf8d2b30582691880fd935dbd6eec5b35f4ad77"
}

rule MalwareBazaar_Mirai_065_8112b3af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-23 22:17:39"
  condition:
    hash.sha256(0, filesize) == "8112b3afd6d0ec3dc0386078e9b84266a8d0e50db4cc7cd4c57991164451da59"
}

rule MalwareBazaar_Mirai_066_f120b3da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0"
    family = "Mirai"
    file_name = "f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0"
    file_type = "sh"
    first_seen = "2026-10-23 22:08:57"
  condition:
    hash.sha256(0, filesize) == "f120b3dac18a138330e33f871a13b1dde5e78380e6398b56604bf51fbff5a0a0"
}

rule MalwareBazaar_Mirai_067_a56ca8d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56ca8d8d4b4f8d99280631393936621bb915abc90b8c2643b03e0369e3e240d"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-10-23 22:05:41"
  condition:
    hash.sha256(0, filesize) == "a56ca8d8d4b4f8d99280631393936621bb915abc90b8c2643b03e0369e3e240d"
}

rule MalwareBazaar_Mirai_068_c3b829a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3b829a8e64408cff55ea1ab8cb557d029a15978f7e91e3add6044a84434ba57"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-10-23 21:59:13"
  condition:
    hash.sha256(0, filesize) == "c3b829a8e64408cff55ea1ab8cb557d029a15978f7e91e3add6044a84434ba57"
}

rule MalwareBazaar_unknown_069_1d40d231
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d40d231fcc6ad7c005a049c6f0d38d494ca0551ddc15d211c5d30f8d4bd27aa"
    family = "unknown"
    file_name = "stage2.js"
    file_type = "js"
    first_seen = "2026-10-23 21:50:46"
  condition:
    hash.sha256(0, filesize) == "1d40d231fcc6ad7c005a049c6f0d38d494ca0551ddc15d211c5d30f8d4bd27aa"
}

rule MalwareBazaar_Mirai_070_6103dcb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6103dcb39b6c5119bb257073de64149766fe3359323f9bf6f714f5ef714cc14c"
    family = "Mirai"
    file_name = "manta.i686"
    file_type = "elf"
    first_seen = "2026-10-23 21:49:40"
  condition:
    hash.sha256(0, filesize) == "6103dcb39b6c5119bb257073de64149766fe3359323f9bf6f714f5ef714cc14c"
}

rule MalwareBazaar_unknown_071_6ba5cc0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ba5cc0bd8d377bce422c8b45cc49f7c3843e1160033378e286357db5b5ba2d8"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 21:48:27"
  condition:
    hash.sha256(0, filesize) == "6ba5cc0bd8d377bce422c8b45cc49f7c3843e1160033378e286357db5b5ba2d8"
}

rule MalwareBazaar_unknown_072_19e4b777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-23 21:47:44"
  condition:
    hash.sha256(0, filesize) == "19e4b77737c683d34e3660af6e057a442e76881bd0a2fd5f534105f4f243fe9e"
}

rule MalwareBazaar_Mirai_073_f3edc422
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3edc42211737a96b81499f494f8d3603fde011b0959824780ebfa77a90ae736"
    family = "Mirai"
    file_name = "manta.x86_64"
    file_type = "elf"
    first_seen = "2026-10-23 21:43:45"
  condition:
    hash.sha256(0, filesize) == "f3edc42211737a96b81499f494f8d3603fde011b0959824780ebfa77a90ae736"
}

rule MalwareBazaar_Mirai_074_91015a7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca"
    family = "Mirai"
    file_name = "manta.ppc"
    file_type = "elf"
    first_seen = "2026-10-23 21:43:43"
  condition:
    hash.sha256(0, filesize) == "91015a7c0e203d60cee50a6775c2b8f59c1c49dc2d95390767f1d278bb6a9eca"
}

rule MalwareBazaar_DDoSAgent_075_2c1af748
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c1af748b310956938189d47375b4b05f9d85ade6c5abdb52392b9f5b97a131f"
    family = "DDoSAgent"
    file_name = "diddysbot-amd64"
    file_type = "elf"
    first_seen = "2026-10-23 21:38:26"
  condition:
    hash.sha256(0, filesize) == "2c1af748b310956938189d47375b4b05f9d85ade6c5abdb52392b9f5b97a131f"
}

rule MalwareBazaar_unknown_076_cfe0d25a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8"
    family = "unknown"
    file_name = "cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:37:32"
  condition:
    hash.sha256(0, filesize) == "cfe0d25a1580916d323007c65eea483dbbcde46ec172000a39363b4167c15ad8"
}

rule MalwareBazaar_DDoSAgent_077_13d1dce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13d1dce34932712d2881f198e09746e0614b3b819fbc0812ed554b0035a92d59"
    family = "DDoSAgent"
    file_name = "diddysbot-amd64"
    file_type = "elf"
    first_seen = "2026-10-23 21:37:14"
  condition:
    hash.sha256(0, filesize) == "13d1dce34932712d2881f198e09746e0614b3b819fbc0812ed554b0035a92d59"
}

rule MalwareBazaar_GoToResolve_078_1e0bc3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5"
    family = "GoToResolve"
    file_name = "unattended-updater.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:29:53"
  condition:
    hash.sha256(0, filesize) == "1e0bc3cab7b9207ec929857870027cd5c740e437173b9ebd6955d539c66a0fb5"
}

rule MalwareBazaar_unknown_079_2de8d333
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2de8d333a5fce9c4ade604dbcc09c7fa31d456da844aefe8160d05d2e38c9a90"
    family = "unknown"
    file_name = "happyfun.msi"
    file_type = "msi"
    first_seen = "2026-10-23 21:20:58"
  condition:
    hash.sha256(0, filesize) == "2de8d333a5fce9c4ade604dbcc09c7fa31d456da844aefe8160d05d2e38c9a90"
}

rule MalwareBazaar_unknown_080_5f177c00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f177c003d73e20b5135c9e60964ac8e56aeb0cc28b132e8a70e877181224c8d"
    family = "unknown"
    file_name = "Adobe_acrobat_installer_win64.bat"
    file_type = "bat"
    first_seen = "2026-10-23 21:20:06"
  condition:
    hash.sha256(0, filesize) == "5f177c003d73e20b5135c9e60964ac8e56aeb0cc28b132e8a70e877181224c8d"
}

rule MalwareBazaar_Mirai_081_0da001fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23"
    family = "Mirai"
    file_name = "0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23.elf"
    file_type = "elf"
    first_seen = "2026-10-23 21:08:59"
  condition:
    hash.sha256(0, filesize) == "0da001fb45bfd95bf22ec20b02f85948b9aaf28bde4a13e63c04d04adb3eff23"
}

rule MalwareBazaar_unknown_082_d697dcdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d697dcdd468a5b87b450e5c4bdfe1eb0e117c3012b4101865221ef208b37242e"
    family = "unknown"
    file_name = "ryjku.dll"
    file_type = "exe"
    first_seen = "2026-10-23 21:03:54"
  condition:
    hash.sha256(0, filesize) == "d697dcdd468a5b87b450e5c4bdfe1eb0e117c3012b4101865221ef208b37242e"
}

rule MalwareBazaar_unknown_083_47c0d206
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c0d206cc9281453d3b71cac972945c1f2f4721e1b5332396ad812b60a4c867"
    family = "unknown"
    file_name = "ytjtyj.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:03:41"
  condition:
    hash.sha256(0, filesize) == "47c0d206cc9281453d3b71cac972945c1f2f4721e1b5332396ad812b60a4c867"
}

rule MalwareBazaar_unknown_084_d0018cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511"
    family = "unknown"
    file_name = "bgbnrtn.exe"
    file_type = "exe"
    first_seen = "2026-10-23 21:03:21"
  condition:
    hash.sha256(0, filesize) == "d0018cd3ddfcb900f6ccb5e0a13acaeaccf3868a95b7fcdee74377563ea6f511"
}

rule MalwareBazaar_Mirai_085_a9155462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0"
    family = "Mirai"
    file_name = "a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0.elf"
    file_type = "elf"
    first_seen = "2026-10-23 20:57:35"
  condition:
    hash.sha256(0, filesize) == "a91554620e9ca25fc024cf20768060da5ccaef1121d1e27230e55a9a1f7624e0"
}

rule MalwareBazaar_unknown_086_48db2ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48db2ddcc81839bbd26c206696a47dc772fb7892603616da09657cd976533f69"
    family = "unknown"
    file_name = "MicroSip.exe"
    file_type = "exe"
    first_seen = "2026-10-23 20:37:13"
  condition:
    hash.sha256(0, filesize) == "48db2ddcc81839bbd26c206696a47dc772fb7892603616da09657cd976533f69"
}

rule MalwareBazaar_unknown_087_d2d95c55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d95c5534efcea6c63843cde59b617ac5b97e057d908298191468d5e3b7635a"
    family = "unknown"
    file_name = "AzureCobalt57-77b11081.msi"
    file_type = "msi"
    first_seen = "2026-10-23 20:28:25"
  condition:
    hash.sha256(0, filesize) == "d2d95c5534efcea6c63843cde59b617ac5b97e057d908298191468d5e3b7635a"
}

rule MalwareBazaar_Mirai_088_48175649
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48175649a0a7e1a2bc7ff7cd0f5ee5216a720dd3bc5a1f9ab522c649d3b2780b"
    family = "Mirai"
    file_name = "manta.armv6l"
    file_type = "elf"
    first_seen = "2026-10-23 20:01:54"
  condition:
    hash.sha256(0, filesize) == "48175649a0a7e1a2bc7ff7cd0f5ee5216a720dd3bc5a1f9ab522c649d3b2780b"
}

rule MalwareBazaar_CoinMiner_089_c5d7e40a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424"
    family = "CoinMiner"
    file_name = "c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424.exe"
    file_type = "exe"
    first_seen = "2026-10-23 20:00:14"
  condition:
    hash.sha256(0, filesize) == "c5d7e40a23719096fe6b3535e0b078130df12afb128ec166be7f6b24bee09424"
}

rule MalwareBazaar_Mirai_090_7e481bc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e481bc464442beec22caa8745e760c59354b6d6bf35f13602492df1eb9e502e"
    family = "Mirai"
    file_name = "manta.mipsel"
    file_type = "elf"
    first_seen = "2026-10-23 19:59:52"
  condition:
    hash.sha256(0, filesize) == "7e481bc464442beec22caa8745e760c59354b6d6bf35f13602492df1eb9e502e"
}

rule MalwareBazaar_unknown_091_b3c1d7ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea"
    family = "unknown"
    file_name = "app.jar"
    file_type = "jar"
    first_seen = "2026-10-23 19:41:12"
  condition:
    hash.sha256(0, filesize) == "b3c1d7ad6100e0c4f7ff6c58221ea9e72d1bad22ef61ed454cf4c2c9b55d39ea"
}

rule MalwareBazaar_unknown_092_0590fd1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a"
    family = "unknown"
    file_name = "uno-setup-1.0.0.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:37:42"
  condition:
    hash.sha256(0, filesize) == "0590fd1d1bd94f0332231753d356547c7511d58404096eca0c37ca93577ec62a"
}

rule MalwareBazaar_unknown_093_782b5191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898"
    family = "unknown"
    file_name = "4.zip"
    file_type = "zip"
    first_seen = "2026-10-23 19:14:38"
  condition:
    hash.sha256(0, filesize) == "782b519154f11ae211cae0e8c4f0c9d8ca1c078d904684bc8923b978c6813898"
}

rule MalwareBazaar_unknown_094_eea8223c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:12:46"
  condition:
    hash.sha256(0, filesize) == "eea8223c913f91493dd3ecaaf519153fc9d7b4724091019aa8ce1a1bdcd514b4"
}

rule MalwareBazaar_RemusStealer_095_744f82ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2"
    family = "RemusStealer"
    file_name = "ХLосitуХ64-v.8.807.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:12:04"
  condition:
    hash.sha256(0, filesize) == "744f82adda79c794c3462ded64800cd9a50f47fb9f198c95e0235abe341944f2"
}

rule MalwareBazaar_unknown_096_ed79c96c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed79c96c27657f7ea08a57b20bfeb1e0a8ca24c459dce98b8c1b74e5d9a9faae"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:09:57"
  condition:
    hash.sha256(0, filesize) == "ed79c96c27657f7ea08a57b20bfeb1e0a8ca24c459dce98b8c1b74e5d9a9faae"
}

rule MalwareBazaar_unknown_097_ddf234d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddf234d3c2de22d1d57677e475eac83d6c6585caa64586ab40e1e5e1b77c0eb3"
    family = "unknown"
    file_name = "IconLib.dll"
    file_type = "dll"
    first_seen = "2026-10-23 19:09:31"
  condition:
    hash.sha256(0, filesize) == "ddf234d3c2de22d1d57677e475eac83d6c6585caa64586ab40e1e5e1b77c0eb3"
}

rule MalwareBazaar_unknown_098_a58c639a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a58c639a10831e63e3cd237614d5c7b7a52eecdc576cfd2ec37d3ccaf3caa6e7"
    family = "unknown"
    file_name = "Chronical-Boot_V2.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:09:05"
  condition:
    hash.sha256(0, filesize) == "a58c639a10831e63e3cd237614d5c7b7a52eecdc576cfd2ec37d3ccaf3caa6e7"
}

rule MalwareBazaar_AokigaharaStealer_099_a5d4f63e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b"
    family = "AokigaharaStealer"
    file_name = "glaicier.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:07:52"
  condition:
    hash.sha256(0, filesize) == "a5d4f63e443a39d7bd7b43b11c42d630f7da0a15f518c8e0bee8b9514b1b343b"
}

rule MalwareBazaar_unknown_100_ab0e1234
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab0e12344f7180962f5f0ed940d7001747ec937d6304ef305d1bcad9954f6835"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-10-23 19:07:45"
  condition:
    hash.sha256(0, filesize) == "ab0e12344f7180962f5f0ed940d7001747ec937d6304ef305d1bcad9954f6835"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

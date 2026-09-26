# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-26

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 654 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 654 |
| Unique family labels | 7 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 75 |
| unknown | 19 |
| VShell | 2 |
| PythonStealer | 1 |
| ConnectWise | 1 |
| QuasarRAT | 1 |
| Prometei | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 78 |
| exe | 19 |
| msi | 1 |
| unknown | 1 |
| macho | 1 |

## Per-Sample Analysis

### Sample 1: `cab97645f8ecf0f4`

| Field | Value |
|---|---|
| SHA-256 | `cab97645f8ecf0f472ad0b32a35bb97c7261d704a25642ec7a8fee4fd8045ac2` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-26 04:58:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5535a97270eb550d5071028c64264eba` |
| SHA-1 | `aa3373c478bf66f1305aee4ed680cbc8da1d3cc7` |
| SHA-256 | `cab97645f8ecf0f472ad0b32a35bb97c7261d704a25642ec7a8fee4fd8045ac2` |
| SHA3-384 | `4ce2a3a8095c1d1d749746cd96b8ee87020f592f49bf4f129c2f845c25cf6b960dd2da0c99364c8fa4dafc84404bb398` |
| TLSH | `T144456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:J4dghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HV/:JiWWpjxuNJI6ShgkzV/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_cab97645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab97645f8ecf0f472ad0b32a35bb97c7261d704a25642ec7a8fee4fd8045ac2"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-26 04:58:37"
  condition:
    hash.sha256(0, filesize) == "cab97645f8ecf0f472ad0b32a35bb97c7261d704a25642ec7a8fee4fd8045ac2"
}
```

### Sample 2: `86b55e10570fb781`

| Field | Value |
|---|---|
| SHA-256 | `86b55e10570fb781814109cc2a191ed48f3ac9a59a3cc1aaa3da47b3c469cc00` |
| Family label | `Mirai` |
| File name | `stub.armv6l` |
| File type | `elf` |
| First seen | `2026-09-26 04:55:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `609ecc409f0aa4726ef9ac52cb2cd425` |
| SHA-1 | `21469339c4c15883f2faf7b3df0a43180fed3b00` |
| SHA-256 | `86b55e10570fb781814109cc2a191ed48f3ac9a59a3cc1aaa3da47b3c469cc00` |
| SHA3-384 | `3e1087491a3fc126ee5208467b854a45d570f0237e902de36fcddad59cf9e41dd08534aac6c522d90e0bd108d4a332e2` |
| TLSH | `T154D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiI:YCp7mXtni6aBh321eSiVWKF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_86b55e10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86b55e10570fb781814109cc2a191ed48f3ac9a59a3cc1aaa3da47b3c469cc00"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-26 04:55:23"
  condition:
    hash.sha256(0, filesize) == "86b55e10570fb781814109cc2a191ed48f3ac9a59a3cc1aaa3da47b3c469cc00"
}
```

### Sample 3: `84d4ea5df3286d49`

| Field | Value |
|---|---|
| SHA-256 | `84d4ea5df3286d493c6774bee44220eb5b00e3a114ca4242a9e9a9fdd5da4525` |
| Family label | `Mirai` |
| File name | `bot.armv5tel` |
| File type | `elf` |
| First seen | `2026-09-26 04:55:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d51dec3a22002e973af2202d7e8d47d5` |
| SHA-1 | `a2f3c7e92458df9bb1003b840c2dc69babffc7bc` |
| SHA-256 | `84d4ea5df3286d493c6774bee44220eb5b00e3a114ca4242a9e9a9fdd5da4525` |
| SHA3-384 | `a7948ce51dfd0b22842727ae040533db9abfb7128cdb7e3cb434299e5eb1a0c0a49d6af9b147c2ae541ff709b62aa529` |
| TLSH | `T13B254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:y7mNVvHPP+SmAC+Mvf9p4WrKqyj657yD/hGnm1:nDMXDu9j657yDAm1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_84d4ea5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d4ea5df3286d493c6774bee44220eb5b00e3a114ca4242a9e9a9fdd5da4525"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-26 04:55:21"
  condition:
    hash.sha256(0, filesize) == "84d4ea5df3286d493c6774bee44220eb5b00e3a114ca4242a9e9a9fdd5da4525"
}
```

### Sample 4: `52b787aa76d8318a`

| Field | Value |
|---|---|
| SHA-256 | `52b787aa76d8318a8603092e2c35d1ab946bab1ccb1dbc34c998406d5ccaf72a` |
| Family label | `Mirai` |
| File name | `stub.mips64` |
| File type | `elf` |
| First seen | `2026-09-26 04:51:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834c745384de83d560ef40d9cc016ed3` |
| SHA-1 | `56d30fd250ccc1fcf096a3d4e1fdbb41530c9474` |
| SHA-256 | `52b787aa76d8318a8603092e2c35d1ab946bab1ccb1dbc34c998406d5ccaf72a` |
| SHA3-384 | `12cb079a5f7ab123c930034e75418a9735d7426929733ecb25f83400e9f61e4406cbf62f607d40ebe61ef9c1bfcb2e6f` |
| TLSH | `T1BDF48D273B21DF65D355D67049F3C7914AE920A20AE340D6B2A8C3287E6172D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxVRU:o7Vh4t+9B1do/w7iG+SQiZa0JTxPU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_52b787aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52b787aa76d8318a8603092e2c35d1ab946bab1ccb1dbc34c998406d5ccaf72a"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-26 04:51:33"
  condition:
    hash.sha256(0, filesize) == "52b787aa76d8318a8603092e2c35d1ab946bab1ccb1dbc34c998406d5ccaf72a"
}
```

### Sample 5: `8d83c03f3f7ecc1f`

| Field | Value |
|---|---|
| SHA-256 | `8d83c03f3f7ecc1f5959777509e50be9af4dd026753136a453783ad011b13df4` |
| Family label | `Mirai` |
| File name | `stub.arm` |
| File type | `elf` |
| First seen | `2026-09-26 04:48:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0fa5cebc937f7c39831237b3e861ce9` |
| SHA-1 | `092545ea9a7533eb9fbb6b4c539a3b5a4cf63e4f` |
| SHA-256 | `8d83c03f3f7ecc1f5959777509e50be9af4dd026753136a453783ad011b13df4` |
| SHA3-384 | `57d23f6b4139ba3f7551399e9d4b195ab883f7e4c45082d1c111fb6ce594362f792f912d600d96cd29117586317c64ac` |
| TLSH | `T1D0D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKi4:YCp7mXtni6aBh321eSiVWKn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_8d83c03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d83c03f3f7ecc1f5959777509e50be9af4dd026753136a453783ad011b13df4"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-26 04:48:19"
  condition:
    hash.sha256(0, filesize) == "8d83c03f3f7ecc1f5959777509e50be9af4dd026753136a453783ad011b13df4"
}
```

### Sample 6: `a3c964b776312cfe`

| Field | Value |
|---|---|
| SHA-256 | `a3c964b776312cfe37275cd15b2bc08473b9f0326e24a7d4519285c4fcdf7b6a` |
| Family label | `Mirai` |
| File name | `stub.i386` |
| File type | `elf` |
| First seen | `2026-09-26 04:44:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11e7f467b007528d8cbb4b05f2b17a7e` |
| SHA-1 | `4e7e3336e4593bba57332b57be2f07a9573b7bb5` |
| SHA-256 | `a3c964b776312cfe37275cd15b2bc08473b9f0326e24a7d4519285c4fcdf7b6a` |
| SHA3-384 | `71f65afa8be910691fdb697f4d5f30644a6039ac7708a745c5033c7137aa79264486d0e41d8f818bca92c11fa6e069f1` |
| TLSH | `T1B5157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/L:7NP46S4QVs7l6A5Zji59k0jZz06FYRsO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_a3c964b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c964b776312cfe37275cd15b2bc08473b9f0326e24a7d4519285c4fcdf7b6a"
    family = "Mirai"
    file_name = "stub.i386"
    file_type = "elf"
    first_seen = "2026-09-26 04:44:37"
  condition:
    hash.sha256(0, filesize) == "a3c964b776312cfe37275cd15b2bc08473b9f0326e24a7d4519285c4fcdf7b6a"
}
```

### Sample 7: `21f8dbfdfd6806c4`

| Field | Value |
|---|---|
| SHA-256 | `21f8dbfdfd6806c4f1c882ebf6f53bd147ba1b7011a4528d9a1fe3506de141bc` |
| Family label | `Mirai` |
| File name | `bot.i586` |
| File type | `elf` |
| First seen | `2026-09-26 04:44:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `546fc57ebfa4e6bb3e9dbad4c24cf0f5` |
| SHA-1 | `f189ab88f0074c710fb77654b812fbe167b2c68e` |
| SHA-256 | `21f8dbfdfd6806c4f1c882ebf6f53bd147ba1b7011a4528d9a1fe3506de141bc` |
| SHA3-384 | `8a77a116baa165aa5b6856ccf4ab4b6e0c4cd5166875fc436efb78931d8958b3c4dc206423d1bccd54e6cd0ccb514f79` |
| TLSH | `T195355C5BB2B374BCC557C830879BCA62BD35B46502226E7BB5C4DA302E26E701719F72` |
| TELFHASH | `t1dce1be794ff634b466d6ca24b312f1b58a33242766ec35f426229d89ef84fc14c56c2b` |
| SSDEEP | `24576:r4ohwkQML46dOsBvTkgqG/igzRLb7lqtqA8UtjYlR:rSo46dQgq4iWbpqtqmtCR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_21f8dbfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21f8dbfdfd6806c4f1c882ebf6f53bd147ba1b7011a4528d9a1fe3506de141bc"
    family = "Mirai"
    file_name = "bot.i586"
    file_type = "elf"
    first_seen = "2026-09-26 04:44:35"
  condition:
    hash.sha256(0, filesize) == "21f8dbfdfd6806c4f1c882ebf6f53bd147ba1b7011a4528d9a1fe3506de141bc"
}
```

### Sample 8: `eb0cd52a079f83a6`

| Field | Value |
|---|---|
| SHA-256 | `eb0cd52a079f83a68b9505637d83c49efd6826962b82c654e46405ed59ea5d6c` |
| Family label | `Mirai` |
| File name | `stub.aarch64_be` |
| File type | `elf` |
| First seen | `2026-09-26 04:44:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32bb7400848268602e819eed2a7fe604` |
| SHA-1 | `7b66522c849417ea6634c8c59243556be63e2a81` |
| SHA-256 | `eb0cd52a079f83a68b9505637d83c49efd6826962b82c654e46405ed59ea5d6c` |
| SHA3-384 | `e8c0185dfae34b1ced9711269537ae93114b00da122b0a805900db1644db44cb5f3d4bcfbce94909a61fd00980c20dcb` |
| TLSH | `T1C2F46C5DFD5F3D43C2C6E23ADB8AC3957227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHzu:qaReBKRU9r1aOnQfkH6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_eb0cd52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb0cd52a079f83a68b9505637d83c49efd6826962b82c654e46405ed59ea5d6c"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-26 04:44:33"
  condition:
    hash.sha256(0, filesize) == "eb0cd52a079f83a68b9505637d83c49efd6826962b82c654e46405ed59ea5d6c"
}
```

### Sample 9: `16d7ee5d4727b276`

| Field | Value |
|---|---|
| SHA-256 | `16d7ee5d4727b276ba3dc51229f0a0897dd1a88fee5b3f2b172f181b58c8768b` |
| Family label | `Mirai` |
| File name | `stub.x86-64` |
| File type | `elf` |
| First seen | `2026-09-26 04:41:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df7dd198ad71dd5d50ac57708dc4f6ad` |
| SHA-1 | `376a0b0c542bc0f1bd04320fba55c060df5be7a1` |
| SHA-256 | `16d7ee5d4727b276ba3dc51229f0a0897dd1a88fee5b3f2b172f181b58c8768b` |
| SHA3-384 | `09b8ed25f4ee64095879a69ef3a34c122568a794a15ebe7bddd23d4a476cc2274e4abc153e4f33c409878e0a226bd45e` |
| TLSH | `T14D157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/s:7NP46S4QVs7l6A5Zji59k0jZz06FYRs5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_16d7ee5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16d7ee5d4727b276ba3dc51229f0a0897dd1a88fee5b3f2b172f181b58c8768b"
    family = "Mirai"
    file_name = "stub.x86-64"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:20"
  condition:
    hash.sha256(0, filesize) == "16d7ee5d4727b276ba3dc51229f0a0897dd1a88fee5b3f2b172f181b58c8768b"
}
```

### Sample 10: `3627bbf4c4bcb835`

| Field | Value |
|---|---|
| SHA-256 | `3627bbf4c4bcb835fc728173781f84211e57300318a6beaa13f64116a18c14d9` |
| Family label | `Mirai` |
| File name | `bot.x64` |
| File type | `elf` |
| First seen | `2026-09-26 04:41:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de3d61dad652bed239e5b3eaab20ba77` |
| SHA-1 | `f9199e6dd613d57d979e0779f01b54871dd2655e` |
| SHA-256 | `3627bbf4c4bcb835fc728173781f84211e57300318a6beaa13f64116a18c14d9` |
| SHA3-384 | `1f57ff82df3a241f8fb1a5175de6cec472a747d2baa6adf91e0802196f85c951811ef1036edf93658c8b1534724041a4` |
| TLSH | `T1C6355C5BB2B374BCC557C830879BCA62BD35B46502226E7BB5C4DA302E26E701719F72` |
| TELFHASH | `t1dce1be794ff634b466d6ca24b312f1b58a33242766ec35f426229d89ef84fc14c56c2b` |
| SSDEEP | `24576:r4ohwkQML46dOsBvTkgqG/igzRLb7lqtqA8UtjYlB:rSo46dQgq4iWbpqtqmtCB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_3627bbf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3627bbf4c4bcb835fc728173781f84211e57300318a6beaa13f64116a18c14d9"
    family = "Mirai"
    file_name = "bot.x64"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:18"
  condition:
    hash.sha256(0, filesize) == "3627bbf4c4bcb835fc728173781f84211e57300318a6beaa13f64116a18c14d9"
}
```

### Sample 11: `8f85a62cad85d46d`

| Field | Value |
|---|---|
| SHA-256 | `8f85a62cad85d46d212461252690f9728f194df53a24983743bd26b3778f889e` |
| Family label | `Mirai` |
| File name | `bot.i486` |
| File type | `elf` |
| First seen | `2026-09-26 04:41:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3da28eb24dc8823f241a646fd097beaa` |
| SHA-1 | `216194c0de2150d3a374251401816d38e098f045` |
| SHA-256 | `8f85a62cad85d46d212461252690f9728f194df53a24983743bd26b3778f889e` |
| SHA3-384 | `0d93852b0e5800f17ed328b7fae0db20635c071bbbfdc189885f3595b66bb489a38375556cfab7ed90d6501e0fbb4c0e` |
| TLSH | `T1FF355C5BB2B374BCC557C830879BCA62BD35B46502226E7BB5C4DA302E26E701719F72` |
| TELFHASH | `t1dce1be794ff634b466d6ca24b312f1b58a33242766ec35f426229d89ef84fc14c56c2b` |
| SSDEEP | `24576:r4ohwkQML46dOsBvTkgqG/igzRLb7lqtqA8UtjYlD:rSo46dQgq4iWbpqtqmtCD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_8f85a62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f85a62cad85d46d212461252690f9728f194df53a24983743bd26b3778f889e"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:16"
  condition:
    hash.sha256(0, filesize) == "8f85a62cad85d46d212461252690f9728f194df53a24983743bd26b3778f889e"
}
```

### Sample 12: `93ae3ef0392e007e`

| Field | Value |
|---|---|
| SHA-256 | `93ae3ef0392e007e3615aeba32c1a35adc07193dbce66de0519864ec8843db5d` |
| Family label | `Mirai` |
| File name | `bot.i386` |
| File type | `elf` |
| First seen | `2026-09-26 04:41:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b0223d7b2887e4d55edd4f37dd843b8` |
| SHA-1 | `9219e274ce732920f61f2a1d2a6559a6110e3a12` |
| SHA-256 | `93ae3ef0392e007e3615aeba32c1a35adc07193dbce66de0519864ec8843db5d` |
| SHA3-384 | `eeda7384292d86af1bf63738a61278823f76c366a5b3308bb87d6347994f9e36143e5ebb44653dd9760e1e533a2fff9c` |
| TLSH | `T1AF355C5BB2B374BCC557C830879BCA62BD35B46502226E7BB5C4DA302E26E701719F72` |
| TELFHASH | `t1dce1be794ff634b466d6ca24b312f1b58a33242766ec35f426229d89ef84fc14c56c2b` |
| SSDEEP | `24576:r4ohwkQML46dOsBvTkgqG/igzRLb7lqtqA8UtjYlt:rSo46dQgq4iWbpqtqmtCt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_93ae3ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93ae3ef0392e007e3615aeba32c1a35adc07193dbce66de0519864ec8843db5d"
    family = "Mirai"
    file_name = "bot.i386"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:15"
  condition:
    hash.sha256(0, filesize) == "93ae3ef0392e007e3615aeba32c1a35adc07193dbce66de0519864ec8843db5d"
}
```

### Sample 13: `47a13f49ae346a6a`

| Field | Value |
|---|---|
| SHA-256 | `47a13f49ae346a6a67679e6a3fb56ddd123f4e67d4e590897694405c6b5f5afc` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-09-26 04:37:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9160794621286567b6a0a1eafdb26b85` |
| SHA-1 | `02cfb9beb18ce5df55a2fe410228ad7a010d8dcb` |
| SHA-256 | `47a13f49ae346a6a67679e6a3fb56ddd123f4e67d4e590897694405c6b5f5afc` |
| SHA3-384 | `e56bc1bc22f95cf0e037bbfb0b8036b979ec4aed240df2231ce140fe8dde67b1369d70ad8e955b8a3d9d1324cd7b1c96` |
| TLSH | `T1E3357D633F11DF69E314D67088F3C6517AD510A31AE24096B26CC3283E61A6E6D9FFE4` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:KnV297uxYWRvlU5Dc4re3gd5/qYDi+rwpTJ5Y1xTCnOKW8g:Kn8+lUy4re3gdxr+5cxTCnzg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_47a13f49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47a13f49ae346a6a67679e6a3fb56ddd123f4e67d4e590897694405c6b5f5afc"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-26 04:37:41"
  condition:
    hash.sha256(0, filesize) == "47a13f49ae346a6a67679e6a3fb56ddd123f4e67d4e590897694405c6b5f5afc"
}
```

### Sample 14: `f4f1e022e1c02518`

| Field | Value |
|---|---|
| SHA-256 | `f4f1e022e1c0251837c70a9316791076fb3d4039f822c9d00c6ecc1b44f0bff5` |
| Family label | `Mirai` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-09-26 04:37:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `170604e3e81670d20d99c63edc8ee541` |
| SHA-1 | `301f7d23028306b7c17d56c90125cff42cdb63ce` |
| SHA-256 | `f4f1e022e1c0251837c70a9316791076fb3d4039f822c9d00c6ecc1b44f0bff5` |
| SHA3-384 | `2100885db9277c62e9ea79ea21d6d860740ec7a3f225af8c79b1bb78f7dd689f57e9818e929a27951e70b9956c61ed4f` |
| TLSH | `T1FA355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:GZvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW8o:q6QS97FixxxxTCnzo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_f4f1e022
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f1e022e1c0251837c70a9316791076fb3d4039f822c9d00c6ecc1b44f0bff5"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-26 04:37:39"
  condition:
    hash.sha256(0, filesize) == "f4f1e022e1c0251837c70a9316791076fb3d4039f822c9d00c6ecc1b44f0bff5"
}
```

### Sample 15: `1357eddc2b6c22d6`

| Field | Value |
|---|---|
| SHA-256 | `1357eddc2b6c22d696e9fff43e1b6c837b455e5d981a9ef86bdc051d5746b036` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-26 04:28:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df3c8f550e64bcf0578746f7c8e0e7a8` |
| SHA-1 | `82b2c137acc5f51f1cfad04a1eba3bb6e72746b0` |
| SHA-256 | `1357eddc2b6c22d696e9fff43e1b6c837b455e5d981a9ef86bdc051d5746b036` |
| SHA3-384 | `a1b8644650682ed8d4399f23df03287ba67dacd622653c23b0c3cc06f3c113b3a34f8a788e146650d9974eedf046b4c8` |
| TLSH | `T1AF342855F890EEA2C6D1267ABB4D438C33171779C3DA7102CD249F3976EA88B0B3A546` |
| TELFHASH | `t121e06191cb7a1b94b5d4c02722f57e05046c38d43b006ddee808361f5e42e4631d6c34` |
| SSDEEP | `6144:7K0K5QeywW70HJqsOwgIThkKFdyshfdwiR8qtdb:27QeywW70pqhkdys1j8Gdb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_1357eddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1357eddc2b6c22d696e9fff43e1b6c837b455e5d981a9ef86bdc051d5746b036"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-26 04:28:19"
  condition:
    hash.sha256(0, filesize) == "1357eddc2b6c22d696e9fff43e1b6c837b455e5d981a9ef86bdc051d5746b036"
}
```

### Sample 16: `99859b2887aa8d3b`

| Field | Value |
|---|---|
| SHA-256 | `99859b2887aa8d3b9433047e15a4f48e038aee82dbac896ac6c37d274e12ae94` |
| Family label | `Mirai` |
| File name | `bot.armv8` |
| File type | `elf` |
| First seen | `2026-09-26 04:27:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea39f328fe9144436f1618bcdfd767ff` |
| SHA-1 | `9b433897a314a07122588b25fd754bf054de3891` |
| SHA-256 | `99859b2887aa8d3b9433047e15a4f48e038aee82dbac896ac6c37d274e12ae94` |
| SHA3-384 | `d97c7372e005e840e25af4df8a7dba4ed1bc9f2fcfc28c59f550c6cea3f5b1e3e1791608d4fd3e20900195cd6b101879` |
| TLSH | `T10D456C5DFD0F3C43D2CAE23EDB4A83E47127B0D4D66311A336C2035DE68999D8B9295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:J4dghjWVQmLjFl1KQeu5fY4SJa6Shgk2g/HVu:JiWWpjxuNJI6ShgkzVu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_99859b28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99859b2887aa8d3b9433047e15a4f48e038aee82dbac896ac6c37d274e12ae94"
    family = "Mirai"
    file_name = "bot.armv8"
    file_type = "elf"
    first_seen = "2026-09-26 04:27:42"
  condition:
    hash.sha256(0, filesize) == "99859b2887aa8d3b9433047e15a4f48e038aee82dbac896ac6c37d274e12ae94"
}
```

### Sample 17: `78a5f7a55c4d6386`

| Field | Value |
|---|---|
| SHA-256 | `78a5f7a55c4d6386e87af0993f634519d2d6c7494ba728db3abd33895b72eeff` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-26 04:27:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44b3c3800d2dc23ba04055e5f7deb5d1` |
| SHA-1 | `0a0f0e4c2fa573821d2132f2c9728f64d4a11d5b` |
| SHA-256 | `78a5f7a55c4d6386e87af0993f634519d2d6c7494ba728db3abd33895b72eeff` |
| SHA3-384 | `5382cf8e97b6a209c1db134a632cf4bcd81314f4f5b54f65ee676082b6734a215fc84abb016cc80cda9da557c9d88ddd` |
| TLSH | `T10BB312B387CC8960443069A5693A146E647A11BFF27EE013B24041BA7EF2E65137FDDA` |
| SSDEEP | `1536:/6KU43hfkDOZ3FcDp+de5gnF7K6PR7GYytMo3RKdylXoYyeStuS+VeuyLqPxEqK+:/xHCDiFyviXoBKcaeSUeXBO3szqhddtH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_78a5f7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a5f7a55c4d6386e87af0993f634519d2d6c7494ba728db3abd33895b72eeff"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-26 04:27:40"
  condition:
    hash.sha256(0, filesize) == "78a5f7a55c4d6386e87af0993f634519d2d6c7494ba728db3abd33895b72eeff"
}
```

### Sample 18: `de8482f9d7a9f378`

| Field | Value |
|---|---|
| SHA-256 | `de8482f9d7a9f378b610b934613b2fe2d1f3a3a0d9a0c247b5233aa8a5886142` |
| Family label | `Mirai` |
| File name | `bot.amd64` |
| File type | `elf` |
| First seen | `2026-09-26 04:27:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17c46f8222ae707b82582cf23ccf82c8` |
| SHA-1 | `565c0689e47eafabede802696eb3f2a14fcfe545` |
| SHA-256 | `de8482f9d7a9f378b610b934613b2fe2d1f3a3a0d9a0c247b5233aa8a5886142` |
| SHA3-384 | `ccf74279f3a5c1c7b6a6f5e2f0750696ee41a4bab3ba97aabe11ccdfa4a17a6b3c27ccdabcc7fc05d17dd840c5c149db` |
| TLSH | `T1CC355C5BB2B374BCC557C830879BCA62BD35B46502226E7BB5C4DA302E26E701719F72` |
| TELFHASH | `t1dce1be794ff634b466d6ca24b312f1b58a33242766ec35f426229d89ef84fc14c56c2b` |
| SSDEEP | `24576:r4ohwkQML46dOsBvTkgqG/igzRLb7lqtqA8UtjYlu:rSo46dQgq4iWbpqtqmtCu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_de8482f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de8482f9d7a9f378b610b934613b2fe2d1f3a3a0d9a0c247b5233aa8a5886142"
    family = "Mirai"
    file_name = "bot.amd64"
    file_type = "elf"
    first_seen = "2026-09-26 04:27:39"
  condition:
    hash.sha256(0, filesize) == "de8482f9d7a9f378b610b934613b2fe2d1f3a3a0d9a0c247b5233aa8a5886142"
}
```

### Sample 19: `5bb258c9527684f8`

| Field | Value |
|---|---|
| SHA-256 | `5bb258c9527684f86673d35ff2c8ef03e5530d4582162b967d9c5398c18e9afa` |
| Family label | `Mirai` |
| File name | `bot.mips64el` |
| File type | `elf` |
| First seen | `2026-09-26 04:24:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07d7f2b92758bb7736830c19619818b6` |
| SHA-1 | `09ed556627dd4cd77163f4810560a8277252c790` |
| SHA-256 | `5bb258c9527684f86673d35ff2c8ef03e5530d4582162b967d9c5398c18e9afa` |
| SHA3-384 | `105b07f35b3d40585078d83f1cbd6b3c8021f3cf253d9eed9037646a209fefd162028643b3d8a98db38a9479c3e333fd` |
| TLSH | `T17B355C46EF406FEBC49FCD30492EC31721EDE8CB42D5A62971BC4A8C7A5D3590AD3698` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:GZvR6ZM35dQ4ZmHd7dcCoLJTxwpTmVXxTCnOKW8P:q6QS97FixxxxTCnzP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_5bb258c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb258c9527684f86673d35ff2c8ef03e5530d4582162b967d9c5398c18e9afa"
    family = "Mirai"
    file_name = "bot.mips64el"
    file_type = "elf"
    first_seen = "2026-09-26 04:24:19"
  condition:
    hash.sha256(0, filesize) == "5bb258c9527684f86673d35ff2c8ef03e5530d4582162b967d9c5398c18e9afa"
}
```

### Sample 20: `154a3fbc2715a142`

| Field | Value |
|---|---|
| SHA-256 | `154a3fbc2715a142d4d541165d961bbe6a39be00c227d77a96a5ab17c31bf482` |
| Family label | `Mirai` |
| File name | `stub.i586` |
| File type | `elf` |
| First seen | `2026-09-26 04:24:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bb92c3790631f5e346f00c5b19c8337` |
| SHA-1 | `63b72fc3735ff8bc45701788d655f067baec64ad` |
| SHA-256 | `154a3fbc2715a142d4d541165d961bbe6a39be00c227d77a96a5ab17c31bf482` |
| SHA3-384 | `f0b95e4941da43902bd025f390ab00a2ce1e3b6bcd12588b86425837279210aa02f96c38ef75636542598cebc4cca12a` |
| TLSH | `T12D157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/f:7NP46S4QVs7l6A5Zji59k0jZz06FYRs6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_154a3fbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "154a3fbc2715a142d4d541165d961bbe6a39be00c227d77a96a5ab17c31bf482"
    family = "Mirai"
    file_name = "stub.i586"
    file_type = "elf"
    first_seen = "2026-09-26 04:24:18"
  condition:
    hash.sha256(0, filesize) == "154a3fbc2715a142d4d541165d961bbe6a39be00c227d77a96a5ab17c31bf482"
}
```

### Sample 21: `37756a23cb3099fd`

| Field | Value |
|---|---|
| SHA-256 | `37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604` |
| Family label | `unknown` |
| File name | `37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604` |
| File type | `elf` |
| First seen | `2026-09-26 04:18:05` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ce1a297fbaca28d2f4b98d9aebc7a9e` |
| SHA-1 | `78d136a74ca9ba9df44454369b8e5912d74e0d1d` |
| SHA-256 | `37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604` |
| SHA3-384 | `38a0502084c7ccc4b37cdbd45bf607180f2580dbdc0f147068d8ad244ce3c72bf6f9eb9b2bbd3eeb98842802594f3908` |
| TLSH | `T110B30211D3230D0BC43538FABA2AE7152D862E79248A415D46F9E97B4FB705CE9F6213` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxI:biMYFJvw6Yh0b1gKobtCGCmCRlrG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_37756a23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604"
    family = "unknown"
    file_name = "37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604"
    file_type = "elf"
    first_seen = "2026-09-26 04:18:05"
  condition:
    hash.sha256(0, filesize) == "37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604"
}
```

### Sample 22: `41a2f6c2e4b60261`

| Field | Value |
|---|---|
| SHA-256 | `41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d` |
| Family label | `Mirai` |
| File name | `41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d` |
| File type | `elf` |
| First seen | `2026-09-26 04:17:58` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7d65d663ecc7642255be3a26b6a0ce6` |
| SHA-1 | `215c742fb1daa762250bb6b5ae8c5dc172ac1f17` |
| SHA-256 | `41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d` |
| SHA3-384 | `616e0909dcb2b0906bd7b5f139239967e61573033d1b3dd1122ec81b56a7d38d97cb1ec65f73404e6803ea4d156f03b0` |
| TLSH | `T16AB3089ABCD19E5945D413BBBA6E918E330323B4D1DF7103DD141F18B6CA94F0E7A682` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQge:T2s/gAWuboqsJ9xcJxspJBqQge` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_41a2f6c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d"
    family = "Mirai"
    file_name = "41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d"
    file_type = "elf"
    first_seen = "2026-09-26 04:17:58"
  condition:
    hash.sha256(0, filesize) == "41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d"
}
```

### Sample 23: `b24cb5bd4cc125fd`

| Field | Value |
|---|---|
| SHA-256 | `b24cb5bd4cc125fd92d9fa8301d23012fcbbb9b7962ebb7cbcd3f932854b7ca7` |
| Family label | `PythonStealer` |
| File name | `load.exe` |
| File type | `exe` |
| First seen | `2026-09-26 03:29:22` |
| Reporter | `NyxIndius` |
| Tags | `exe, PythonStealer, xmr` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75df4acf2391120b8c0747ccf8c66253` |
| SHA-1 | `374a8775ae0dea1f910dbe8d5b9e1328fb8d476b` |
| SHA-256 | `b24cb5bd4cc125fd92d9fa8301d23012fcbbb9b7962ebb7cbcd3f932854b7ca7` |
| SHA3-384 | `3cc53bb6b4ba5b0782da79fddb86dd02e367c1e69513ea6bd82cb0ced7e33a2b082dc56d5efd20b684935f5dffb02604` |
| IMPHASH | `d771ea0e1824cb6584f385f3e76a6e0e` |
| TLSH | `T1546633A8D26255F9D46B8479A1C60621FFB1B0285B2589DF1B505B8C3F374F84E3AF83` |
| SSDEEP | `196608:shPofq5nF1wuNYyOvXrGCwkIPp0raskYyI2gblT:sF6KDNYy2rGxrYbB2g5` |

#### Technical Assessment

- The sample is tracked as `PythonStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PythonStealer_023_b24cb5bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b24cb5bd4cc125fd92d9fa8301d23012fcbbb9b7962ebb7cbcd3f932854b7ca7"
    family = "PythonStealer"
    file_name = "load.exe"
    file_type = "exe"
    first_seen = "2026-09-26 03:29:22"
  condition:
    hash.sha256(0, filesize) == "b24cb5bd4cc125fd92d9fa8301d23012fcbbb9b7962ebb7cbcd3f932854b7ca7"
}
```

### Sample 24: `abfdb30a698e7cbd`

| Field | Value |
|---|---|
| SHA-256 | `abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195` |
| Family label | `Mirai` |
| File name | `abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195` |
| File type | `elf` |
| First seen | `2026-09-26 03:18:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d6fa80241b93debfc7e4cca9d8f2ae5` |
| SHA-1 | `3cf3859da703e5a33e1cf94ee4d7726621d528e9` |
| SHA-256 | `abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195` |
| SHA3-384 | `8f76482ac8fc8103c8f05e55ec190274e57f82fda9476ef11d723a557dd798c542fa9a84a55ccca4dd7f29c0991ff7a9` |
| TLSH | `T103E3188FFD81AE6546C1277BFA2E418A331327B4D1EB71139D041F2876CA94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rm2:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_abfdb30a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195"
    family = "Mirai"
    file_name = "abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195"
    file_type = "elf"
    first_seen = "2026-09-26 03:18:18"
  condition:
    hash.sha256(0, filesize) == "abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195"
}
```

### Sample 25: `5640640a625e8191`

| Field | Value |
|---|---|
| SHA-256 | `5640640a625e819189af4b0cfaa20280be6526b40032d8a5b8f0d58abed8fe23` |
| Family label | `Mirai` |
| File name | `stub.mips` |
| File type | `elf` |
| First seen | `2026-09-26 03:14:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d71bbc8f9a9a1b185656667be3983c0e` |
| SHA-1 | `c42fdb103affa4a9b1cbe9249de691ad54a40e3e` |
| SHA-256 | `5640640a625e819189af4b0cfaa20280be6526b40032d8a5b8f0d58abed8fe23` |
| SHA3-384 | `0294f623cc252bb64a5f09208fac9ecfe43bc4109e98faad9f75ed7f5fc8d5190fb919783cf540666ee3a35bd29b0eb3` |
| TLSH | `T163F48D273B21DF65D355D67049F3C7914AE920A20AE340D6B268C3287E61B2D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxVK:o7Vh4t+9B1do/w7iG+SQiZa0JTxc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_5640640a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5640640a625e819189af4b0cfaa20280be6526b40032d8a5b8f0d58abed8fe23"
    family = "Mirai"
    file_name = "stub.mips"
    file_type = "elf"
    first_seen = "2026-09-26 03:14:23"
  condition:
    hash.sha256(0, filesize) == "5640640a625e819189af4b0cfaa20280be6526b40032d8a5b8f0d58abed8fe23"
}
```

### Sample 26: `b43ad7b84d22f811`

| Field | Value |
|---|---|
| SHA-256 | `b43ad7b84d22f811e29dda2c880b8acab9455faf6babd6641651a7b1c01246db` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 03:13:04` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, payload_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec86c848971eefb1f5ce4c2e024025cf` |
| SHA-1 | `89f46bbd3e088ce1de5d7da4bf15d970b921002d` |
| SHA-256 | `b43ad7b84d22f811e29dda2c880b8acab9455faf6babd6641651a7b1c01246db` |
| SHA3-384 | `04f18453da2e1a8d644df1cea2aae63634671448c20f5f23ff4760db047e0dbf01c7956672e6e34847b70fc3d431f2af` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T184C51209E7E405F8E0B7E574CD534912E7727C4A07A1EBDF0764A9A61F233A09E3A712` |
| SSDEEP | `49152:rKA5/fBj2IAetcxWrTBtf4SSNnJH6SNl9Ww58vKIDySK:rKAMIzBXSLUwWiIDySK` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_b43ad7b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b43ad7b84d22f811e29dda2c880b8acab9455faf6babd6641651a7b1c01246db"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 03:13:04"
  condition:
    hash.sha256(0, filesize) == "b43ad7b84d22f811e29dda2c880b8acab9455faf6babd6641651a7b1c01246db"
}
```

### Sample 27: `7e8e91c4a91cdb8f`

| Field | Value |
|---|---|
| SHA-256 | `7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b` |
| Family label | `unknown` |
| File name | `7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b.exe` |
| File type | `exe` |
| First seen | `2026-09-26 03:10:54` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb62e6744695653be2f70f9db55f439a` |
| SHA-1 | `eed928fbbd4cc86daf4d41809e2a421fea700124` |
| SHA-256 | `7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b` |
| SHA3-384 | `f32d51ef5225e3c423c3627fc76b7927e213aee9a04c5879ba6aec8bc81fcf7322696b34cf5f5465f5abee6c0a33eae7` |
| IMPHASH | `0651e7b7e46e7402b9783dc8fa9770de` |
| TLSH | `T163723995B3810DF6CAA9003BC9E36E16E576F6585781A3CF2360162F0F267E1783EA41` |
| SSDEEP | `192:QfepyBtUls8TloqnyyI2oZHQQP/WO2XZ8nb22gIjBcrSDZptX+:QGpy7Ss6o89H6HQQPuppDICSDZpc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_7e8e91c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b"
    family = "unknown"
    file_name = "7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b.exe"
    file_type = "exe"
    first_seen = "2026-09-26 03:10:54"
  condition:
    hash.sha256(0, filesize) == "7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b"
}
```

### Sample 28: `8f45c730d72bfdc0`

| Field | Value |
|---|---|
| SHA-256 | `8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca` |
| Family label | `ConnectWise` |
| File name | `8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca.msi` |
| File type | `msi` |
| First seen | `2026-09-26 03:10:29` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48d5a21ff29701aac28cb4010de993fc` |
| SHA-1 | `56f4a937160cf5ccd9e7add240cf9790d50a4a01` |
| SHA-256 | `8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca` |
| SHA3-384 | `bcc2b8f42cc454dcd1bd99e0920082307667b56e6f613a99c6a40862449393ced2579391542744170eb1400ad306014c` |
| TLSH | `T1580733211BF8C855EAB30B75FA7B86B44637BC51A912D05F13A03E1D1932E819EA3377` |
| SSDEEP | `393216:s6ohU+8bjJ8bQq9ySZ8EE6ohU+8bjJ8P6ohU+8bjJ8O6ohU+8bjJ8:Toh0bjI9ySZzroh0bjroh0bjeoh0bj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_028_8f45c730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca"
    family = "ConnectWise"
    file_name = "8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca.msi"
    file_type = "msi"
    first_seen = "2026-09-26 03:10:29"
  condition:
    hash.sha256(0, filesize) == "8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca"
}
```

### Sample 29: `745bcfeebdb96a60`

| Field | Value |
|---|---|
| SHA-256 | `745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06` |
| Family label | `unknown` |
| File name | `745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06.bin` |
| File type | `unknown` |
| First seen | `2026-09-26 03:10:02` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f183593bee56194eb0bca5823ee8167` |
| SHA-256 | `745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_745bcfee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06"
    family = "unknown"
    file_name = "745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06.bin"
    file_type = "unknown"
    first_seen = "2026-09-26 03:10:02"
  condition:
    hash.sha256(0, filesize) == "745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06"
}
```

### Sample 30: `d21734f1c87a44eb`

| Field | Value |
|---|---|
| SHA-256 | `d21734f1c87a44eb9610fb14c2cf8016bdc49032851877b7fc2c0257a9e83adb` |
| Family label | `Mirai` |
| File name | `stub.aarch64_be` |
| File type | `elf` |
| First seen | `2026-09-26 02:56:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc75b84f04ad41ff8a0c0ac87126fe4c` |
| SHA-1 | `1c0cd30272c1342639111e471ea37a0fb5b440a8` |
| SHA-256 | `d21734f1c87a44eb9610fb14c2cf8016bdc49032851877b7fc2c0257a9e83adb` |
| SHA3-384 | `d71b7285d1d9eed3faa8a23b9679819eb7819b0fdaef189af8561016726851ae4db189b4970a182734decb7df98aa234` |
| TLSH | `T183F46C5DFD5F3D43C2C6E23ADB8AC3957227B0D8D61311A321C1021DE6CADAD8B5299E` |
| SSDEEP | `12288:qaOMNE5N3B76xF+y0ZdNd7JOSwa5YAmdlStnWtVfkHzX:qaReBKRU9r1aOnQfkHr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_d21734f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d21734f1c87a44eb9610fb14c2cf8016bdc49032851877b7fc2c0257a9e83adb"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-26 02:56:44"
  condition:
    hash.sha256(0, filesize) == "d21734f1c87a44eb9610fb14c2cf8016bdc49032851877b7fc2c0257a9e83adb"
}
```

### Sample 31: `09f4692a8a209c45`

| Field | Value |
|---|---|
| SHA-256 | `09f4692a8a209c454c20eb5010b0b41efac4648dcdf2f6b0d149fbbc9e801a8c` |
| Family label | `unknown` |
| File name | `libcurl.dll` |
| File type | `exe` |
| First seen | `2026-09-26 02:51:07` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65370fd05ccb96bb55d1b022c1d9b734` |
| SHA-1 | `1d389138518e4fdb09721a1fdb8d555424096793` |
| SHA-256 | `09f4692a8a209c454c20eb5010b0b41efac4648dcdf2f6b0d149fbbc9e801a8c` |
| SHA3-384 | `2bb72e309b4b7448fb1a63a772346cf0d48fa7651af63390467f91a4f44ef5bd3b06365ce546c87c4a00e4f296739d75` |
| IMPHASH | `7f7894abed60f1478deaa870109fe97c` |
| TLSH | `T17CC59E818ED7095AFFB31031DC4F2780CABC76C0966518B545AC86B539B8ED98AFD24F` |
| SSDEEP | `24576:jD/htG8jSj6b9yHENmsqyxkJfcEXGW8lg6t7qHZUCC17jC7Yb4AbftSuH0SKJdVd:jD/csqx6lgiq8UYjsuareLqmV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_09f4692a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09f4692a8a209c454c20eb5010b0b41efac4648dcdf2f6b0d149fbbc9e801a8c"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-09-26 02:51:07"
  condition:
    hash.sha256(0, filesize) == "09f4692a8a209c454c20eb5010b0b41efac4648dcdf2f6b0d149fbbc9e801a8c"
}
```

### Sample 32: `c9455e29708db34f`

| Field | Value |
|---|---|
| SHA-256 | `c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78` |
| Family label | `Mirai` |
| File name | `c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78` |
| File type | `elf` |
| First seen | `2026-09-26 02:19:21` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2a08618fd6b53843a77557407fbd7d8` |
| SHA-1 | `d11b2f3247f88976f10e0339ee40b72c6df08ea5` |
| SHA-256 | `c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78` |
| SHA3-384 | `72278d8592b9ce6d2f3ee2dac94d45fd7fd9d4af38efe69c45a6cf88a8a3182b06a0b31339dbf851146929a28d097920` |
| TLSH | `T11414198AFD81AF1585C527BBFE2E418A331317B8D2EE71129D145F2877CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNg:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_c9455e29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78"
    family = "Mirai"
    file_name = "c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78"
    file_type = "elf"
    first_seen = "2026-09-26 02:19:21"
  condition:
    hash.sha256(0, filesize) == "c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78"
}
```

### Sample 33: `dcda374329eb90c9`

| Field | Value |
|---|---|
| SHA-256 | `dcda374329eb90c9065b2886654d14f2ab4533b8817389541fe621274f96af93` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 02:13:40` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bedc54c8896c53a1b0e0d46591b772f4` |
| SHA-1 | `ac44184801cb059301869c32a42aebad1cd194f2` |
| SHA-256 | `dcda374329eb90c9065b2886654d14f2ab4533b8817389541fe621274f96af93` |
| SHA3-384 | `8fd88337b28b2dbe05da2331ce71b7555aab1dda5cbf2521f1f04a7760237bb5aef4390945bb144c5419de6c120311e9` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1D157332AE7F0097EE253C4B9CDD38C11E7B97CCA6392A99B47B054711FA73609C29B11` |
| SSDEEP | `786432:QDzNEFBGS31TVC1TTPAcYU7a+viFm9u6s:QDyB31BCFTQ5k9ns` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_dcda3743
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcda374329eb90c9065b2886654d14f2ab4533b8817389541fe621274f96af93"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 02:13:40"
  condition:
    hash.sha256(0, filesize) == "dcda374329eb90c9065b2886654d14f2ab4533b8817389541fe621274f96af93"
}
```

### Sample 34: `4be29060aa863f9b`

| Field | Value |
|---|---|
| SHA-256 | `4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9` |
| Family label | `VShell` |
| File name | `4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9.exe` |
| File type | `exe` |
| First seen | `2026-09-26 02:05:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15ac0aa266ff66a975c0711b40f28915` |
| SHA-1 | `1b0cdc4f3ec5f58133213cd5d73acc705ff1ecb6` |
| SHA-256 | `4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9` |
| SHA3-384 | `4d29b91a01e59e3038052d2bf6a9635dc38381662c87edb9253419dfad8783b36fab29fed5f4ea74f6b36bc1754b2d41` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A691D64270B988E7E85C81BB4C0FB8A0B919740A41C483A60338A5993E3957BF47CB0E` |
| SSDEEP | `48:6IIF9BlQaexPGgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMPv70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_034_4be29060
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9"
    family = "VShell"
    file_name = "4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9.exe"
    file_type = "exe"
    first_seen = "2026-09-26 02:05:04"
  condition:
    hash.sha256(0, filesize) == "4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9"
}
```

### Sample 35: `ff4e059d3f8c4285`

| Field | Value |
|---|---|
| SHA-256 | `ff4e059d3f8c4285958c7dcddb1ce9084ea490e8269c514fbc2d3a1403914c9c` |
| Family label | `QuasarRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 01:44:30` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `931a60569590d37c6df6fafc7e8a93cf` |
| SHA-1 | `9a8c27798f6b5b0f9b672ed569aa028cbbc45467` |
| SHA-256 | `ff4e059d3f8c4285958c7dcddb1ce9084ea490e8269c514fbc2d3a1403914c9c` |
| SHA3-384 | `b3a80cd83f008df13650951cf83414f53ab3e1d19e542ae8cd98f0a37e3a2a993eebcfda939ec69c61b9322003604c4c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17A342304CBDEE65AE56006318DD781CB012CBA37FE77D50D6920B1CB6F6192DC7892BA` |
| SSDEEP | `6144:m26+X70DfPJxIezeTPz6R+TJqGVDJf6AgJH6ImjGlNbaYpU:7972QeaOR+lq2EjZAjwNbF` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_035_ff4e059d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff4e059d3f8c4285958c7dcddb1ce9084ea490e8269c514fbc2d3a1403914c9c"
    family = "QuasarRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:44:30"
  condition:
    hash.sha256(0, filesize) == "ff4e059d3f8c4285958c7dcddb1ce9084ea490e8269c514fbc2d3a1403914c9c"
}
```

### Sample 36: `5946e502f0f7bee0`

| Field | Value |
|---|---|
| SHA-256 | `5946e502f0f7bee0f29b829c7f5b72d584e90188de8863d3713fb6c503ac778c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 01:44:21` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c6ba3364a761ec8bb9b815feb69605b` |
| SHA-1 | `486da0d5a0c49fa23521307e427f827f9162785f` |
| SHA-256 | `5946e502f0f7bee0f29b829c7f5b72d584e90188de8863d3713fb6c503ac778c` |
| SHA3-384 | `f7910bd9bf773f2a78ce4cc858fcf64e58698fce30e305b9a245b87758dff1ab6f0e8452d6e30c5b97baaec6e6358573` |
| IMPHASH | `74ed3f2870ba7a48a326fa1e5eaf311d` |
| TLSH | `T16D25BFF1327D93D3E1A18DB04F8A8670B6F135AC98D0670E60F59B1E9BD23901C5D9EA` |
| SSDEEP | `24576:WlnmjacwvOfvv29xPmSnbWRnBbw2onJzn:WlnmjacwvOnu/uSnKRw2` |
| ICON-DHASH | `d4a6a494a48484a4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_5946e502
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5946e502f0f7bee0f29b829c7f5b72d584e90188de8863d3713fb6c503ac778c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:44:21"
  condition:
    hash.sha256(0, filesize) == "5946e502f0f7bee0f29b829c7f5b72d584e90188de8863d3713fb6c503ac778c"
}
```

### Sample 37: `49cf9dbaef457a2c`

| Field | Value |
|---|---|
| SHA-256 | `49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23` |
| Family label | `Prometei` |
| File name | `49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23` |
| File type | `elf` |
| First seen | `2026-09-26 01:37:01` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9064f0bd31fba20188c60365f30ff40e` |
| SHA-1 | `1d6ef637aeae6abbe2083ded7ec29e5e9e1bda36` |
| SHA-256 | `49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23` |
| SHA3-384 | `ddddad656fe3840d18e57930451d55ac76378723cb42bf480db3c31e881b743810cbfae4c0f609855289350c000dacf9` |
| TLSH | `T15EA423B4F9219E8F6DD769B91B24C31DE182C172589D4C2313AE95A34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdo:Fs6pyCC/Ya2hpi6T6N4m` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_037_49cf9dba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23"
    family = "Prometei"
    file_name = "49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23"
    file_type = "elf"
    first_seen = "2026-09-26 01:37:01"
  condition:
    hash.sha256(0, filesize) == "49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23"
}
```

### Sample 38: `8848de61718a3144`

| Field | Value |
|---|---|
| SHA-256 | `8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2` |
| Family label | `Mirai` |
| File name | `8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2` |
| File type | `elf` |
| First seen | `2026-09-26 01:17:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a519012b113c25d17c5b6bd5c2a2824` |
| SHA-1 | `2cd923f6b4941640be9afd2ebe3a02a5b32db4e7` |
| SHA-256 | `8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2` |
| SHA3-384 | `6d48ff01ab0f760c4ae1b81ecbe4a8e08522871399bbdd53c6fb268174afe6f9aa9a627c20447320b1acac543e1883cc` |
| TLSH | `T13BB19E016F83465BCD052A780943E400FB950BB578878F09517EE3C593EB8BD1EAB329` |
| SSDEEP | `96:TOUIfPQrfsss1RzSdql2kyRZzESToxTK1kwII8Idfr0dnAuvGw:T5Iftsqwtk4NoxTK1p8IdfrJuvt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_8848de61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2"
    family = "Mirai"
    file_name = "8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2"
    file_type = "elf"
    first_seen = "2026-09-26 01:17:18"
  condition:
    hash.sha256(0, filesize) == "8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2"
}
```

### Sample 39: `673b8bcf8b836f02`

| Field | Value |
|---|---|
| SHA-256 | `673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31` |
| Family label | `Mirai` |
| File name | `673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31` |
| File type | `elf` |
| First seen | `2026-09-26 01:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87d8b643423a4baf2a19da9b03676b37` |
| SHA-1 | `8b0a1d4b0af9213ff8cab16774776f253680f5e0` |
| SHA-256 | `673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31` |
| SHA3-384 | `8330ae3592e78a440006013ddf0b824bf8c00eebdd67f8bf2dc4e23ad296630527b79468c09d5c806231228cc4fd5f06` |
| TLSH | `T189F3199EFD81AE6546C127BBFE2E418A331317B4D2EB71129D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSD4:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_673b8bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31"
    family = "Mirai"
    file_name = "673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31"
    file_type = "elf"
    first_seen = "2026-09-26 01:17:13"
  condition:
    hash.sha256(0, filesize) == "673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31"
}
```

### Sample 40: `34f683a56d01c12e`

| Field | Value |
|---|---|
| SHA-256 | `34f683a56d01c12eb8dba9117402ecee7a8a04d740e65c4a46d2341fe1b52ee5` |
| Family label | `unknown` |
| File name | `macho_34f683a56d01.bin` |
| File type | `macho` |
| First seen | `2026-09-26 01:15:17` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ae534073f6f43211c4a595dc36539d5` |
| SHA-1 | `53bc712c7b06d1facd87fca99f034353ed8ad18e` |
| SHA-256 | `34f683a56d01c12eb8dba9117402ecee7a8a04d740e65c4a46d2341fe1b52ee5` |
| SHA3-384 | `6f7ade5fa4783d8daccc630d7839a95c38bf76df742eb0d8c67a8c7e30ac6bdd56de22d9e09b3b69d8c00ae68ffb3374` |
| TLSH | `T1BA35F100CE6694E6F5CCDE302B269AB79E71391049891BEA57A22F48CE333D3F51725D` |
| SSDEEP | `24576:6tY97WfNXUeJFttFu5cT4YkVvmo63g9dDtPuTiVYqj:WoWJlNtFElmx3g/tPP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_34f683a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34f683a56d01c12eb8dba9117402ecee7a8a04d740e65c4a46d2341fe1b52ee5"
    family = "unknown"
    file_name = "macho_34f683a56d01.bin"
    file_type = "macho"
    first_seen = "2026-09-26 01:15:17"
  condition:
    hash.sha256(0, filesize) == "34f683a56d01c12eb8dba9117402ecee7a8a04d740e65c4a46d2341fe1b52ee5"
}
```

### Sample 41: `576b1934db203a45`

| Field | Value |
|---|---|
| SHA-256 | `576b1934db203a45e0ba66325f99761b92256069adfe513aaf29b73ff473e994` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 01:11:21` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, payload_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa84c1f6d23d0fb67dd8406915d6394b` |
| SHA-1 | `7e89256649728a4e8ece027e0d73944b8e6443f3` |
| SHA-256 | `576b1934db203a45e0ba66325f99761b92256069adfe513aaf29b73ff473e994` |
| SHA3-384 | `9e76c6c63bc4c8778cb58fd88cde1e4bce269c677e0438ea0ed3c943156ae2d39baebf923c70f28167ae48100d2b7614` |
| IMPHASH | `d429e8a43cbbbac5062d9e353826ed6f` |
| TLSH | `T171959D99F38B00A5ED96ED39D194D12FE497B40422B8DFA77BD83FCC16018DE1C6A621` |
| SSDEEP | `49152:Gl+8Afh6s5UvUJAgB+0HlkgjWMknI/AK:11frUjgjlFyTK` |
| ICON-DHASH | `c8926662cc6992e4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_576b1934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576b1934db203a45e0ba66325f99761b92256069adfe513aaf29b73ff473e994"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:11:21"
  condition:
    hash.sha256(0, filesize) == "576b1934db203a45e0ba66325f99761b92256069adfe513aaf29b73ff473e994"
}
```

### Sample 42: `d418ac6af6706816`

| Field | Value |
|---|---|
| SHA-256 | `d418ac6af6706816e0c23e60c24cb29925026ee193e4655648025d7ccd7c900b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 01:11:01` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, exe, payload_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb2d350ba8be9a878f2d9743d894f077` |
| SHA-1 | `dce9b03b261c07a448c1ddaeaba8f8f08e43f707` |
| SHA-256 | `d418ac6af6706816e0c23e60c24cb29925026ee193e4655648025d7ccd7c900b` |
| SHA3-384 | `8c52eb770a6c04d3ea1d1f79e68a085019a2405f02ed67cf99e71028a35c530acf1b8e24ccd7551c803892224bfb8673` |
| IMPHASH | `75f0ceb6e3dba569194c7cbff1ac5ae9` |
| TLSH | `T11786D8DAAB614F42E667687B1328CF2173B3E03129971F87B14299E46D9CFD90D2314E` |
| SSDEEP | `98304:I/s6BFq11/MEIBHVFGCdnuxFPXVn4Kh65ayTGSRc0klh1:I0LjCdn+FPN90E` |
| ICON-DHASH | `2b952a956a955295` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d418ac6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d418ac6af6706816e0c23e60c24cb29925026ee193e4655648025d7ccd7c900b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:11:01"
  condition:
    hash.sha256(0, filesize) == "d418ac6af6706816e0c23e60c24cb29925026ee193e4655648025d7ccd7c900b"
}
```

### Sample 43: `138fa81c9e10aa77`

| Field | Value |
|---|---|
| SHA-256 | `138fa81c9e10aa77a2c7b27c5eeac03cee9af14b29f599679980e451fa6788c3` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-09-26 01:06:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f2b5227483a26b995671ee582734697` |
| SHA-1 | `12acd2f45c5b372c04ad364328d15b2445a84530` |
| SHA-256 | `138fa81c9e10aa77a2c7b27c5eeac03cee9af14b29f599679980e451fa6788c3` |
| SHA3-384 | `28b9529d5d4a85a2ecfdf34004bb244ba2b7e911e3ed17453105892ce3e8b8a23dfb0dc442ecbbddb308fd71de097235` |
| TLSH | `T122831995B8814B12D5D512BEFA1E118E3323177CE3DE73129E206F24778B96B0E7B612` |
| TELFHASH | `t13e11d0101ecc8edc97f0cf59834a73a27a073676db5239594bab752f83021d1761602f` |
| SSDEEP | `1536:ijnJbiILiU66im0nDIPsSDvauDVhQ/MYi60PmzysO7NA52Y0s/hG:aHLUTDIkSDvau+0PmzysOBAY1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_138fa81c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "138fa81c9e10aa77a2c7b27c5eeac03cee9af14b29f599679980e451fa6788c3"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-26 01:06:39"
  condition:
    hash.sha256(0, filesize) == "138fa81c9e10aa77a2c7b27c5eeac03cee9af14b29f599679980e451fa6788c3"
}
```

### Sample 44: `026fd2ca1011f46e`

| Field | Value |
|---|---|
| SHA-256 | `026fd2ca1011f46ecf8513ef9e7c74b5e7b9a0fca4dc818fecc5da4a20942b26` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-09-26 01:06:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad274224ef1a996f87d6fd2efa74256b` |
| SHA-1 | `62346a2f941ace34cf4d0053678faf45e8295a66` |
| SHA-256 | `026fd2ca1011f46ecf8513ef9e7c74b5e7b9a0fca4dc818fecc5da4a20942b26` |
| SHA3-384 | `f7625cfa0a3ef904b2ca3a8c2cb825142e5d128e439e09dd79ff4c028f08e15503dbed0df5b9db6a2300ee1cb5b55006` |
| TLSH | `T12EA3F506BB650FF7DC6FCD3706A9070225CCA51B22B83B767674C928B50B65B4AE3874` |
| SSDEEP | `1536:LvGefaZSdtUq4/xl4ExO29zyN0ZNhdZp54crFCZeLs/h5J:LOefaZSdg59zm0Hr6eoJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_026fd2ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "026fd2ca1011f46ecf8513ef9e7c74b5e7b9a0fca4dc818fecc5da4a20942b26"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-26 01:06:35"
  condition:
    hash.sha256(0, filesize) == "026fd2ca1011f46ecf8513ef9e7c74b5e7b9a0fca4dc818fecc5da4a20942b26"
}
```

### Sample 45: `c552d114f51a0c10`

| Field | Value |
|---|---|
| SHA-256 | `c552d114f51a0c106c51c84997e884249faf4bb26177069dadb5cdfdf3acbedf` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-09-26 01:06:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f50c5a47be77dd22c9b3aa7127572ba` |
| SHA-1 | `07647de34007a19d17fc7e783babedf627d65544` |
| SHA-256 | `c552d114f51a0c106c51c84997e884249faf4bb26177069dadb5cdfdf3acbedf` |
| SHA3-384 | `38878067e31dc44a88b1898cdb4cad518254c7990d3ff3493387b17175844b0c9a52144450b06a0b2c8befae41109f17` |
| TLSH | `T166632A91BD819B13C6D0227BFB5E428E372653A8D2EE72079D216F2137C786B0E77641` |
| TELFHASH | `t18b412f7453540add1fe0c759838fa239b99e39f9af1038a98a2e7f5b82435c1b11843b` |
| SSDEEP | `1536:zGYi7YUGCsKrBhSlCkTDYPSnJjCR86s/hX:zGYDUfYCkQKn4I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_c552d114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c552d114f51a0c106c51c84997e884249faf4bb26177069dadb5cdfdf3acbedf"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-26 01:06:33"
  condition:
    hash.sha256(0, filesize) == "c552d114f51a0c106c51c84997e884249faf4bb26177069dadb5cdfdf3acbedf"
}
```

### Sample 46: `67dbba47c2a15f0f`

| Field | Value |
|---|---|
| SHA-256 | `67dbba47c2a15f0f1d004923a41f2ee8e912405cb0decff0dd9d4ae268df692c` |
| Family label | `unknown` |
| File name | `SpiralCircus_Setup.exe` |
| File type | `exe` |
| First seen | `2026-09-26 01:06:08` |
| Reporter | `iamaachum` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c1fa8f2e99f9eda130e3904626ce1b1` |
| SHA-1 | `b44579d5276e2a11dd711d56e2682600e56c65b6` |
| SHA-256 | `67dbba47c2a15f0f1d004923a41f2ee8e912405cb0decff0dd9d4ae268df692c` |
| SHA3-384 | `56542234ffe1dc20e3bc2db0e88245d3f294d456562f2cec295dff0cd7ff105bbf1680b89976c2dd73c6f7ab3ec30fd0` |
| IMPHASH | `1f23f452093b5c1ff091a2f9fb4fa3e9` |
| TLSH | `T18EC733A775C199FCCB93583A803033B6E64DDD01C3F614DCA352A29CE6B99D9ED50BA0` |
| SSDEEP | `1572864:0YpvuitESS09Qpkh/7USjZ+PTBnooPvZu:zp2itESS02a7ULPTxrHZu` |
| ICON-DHASH | `00000080a090486e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_67dbba47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67dbba47c2a15f0f1d004923a41f2ee8e912405cb0decff0dd9d4ae268df692c"
    family = "unknown"
    file_name = "SpiralCircus_Setup.exe"
    file_type = "exe"
    first_seen = "2026-09-26 01:06:08"
  condition:
    hash.sha256(0, filesize) == "67dbba47c2a15f0f1d004923a41f2ee8e912405cb0decff0dd9d4ae268df692c"
}
```

### Sample 47: `e0d329a3dec10ae8`

| Field | Value |
|---|---|
| SHA-256 | `e0d329a3dec10ae8ecd3ea90593f3e329c0629ebda75ab2316aafc34dfd0c91e` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-09-26 01:05:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ed9a93f5499fbde499e8e3f0abe5f4b` |
| SHA-1 | `a6c964b2f734e58bbeeca7582b8dbdbc8be0c829` |
| SHA-256 | `e0d329a3dec10ae8ecd3ea90593f3e329c0629ebda75ab2316aafc34dfd0c91e` |
| SHA3-384 | `4d18563d57483c537910d540629605405955a4d00dfd3c696785282441ac56b0d12996b91b0c894e07bb27cd38b57d94` |
| TLSH | `T13103F16AD5C7EFA4C3315832DAF140200FDBE7FE91ED30058B109A78B8E296756B564B` |
| SSDEEP | `768:cPjSxHiUtOtWQDe8/3jmGmTbR0/MIT6NjZ2c0EPYhC+S9q3UEL2q:crSwUtqDTqGPTqjgIPCHL7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_e0d329a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d329a3dec10ae8ecd3ea90593f3e329c0629ebda75ab2316aafc34dfd0c91e"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:32"
  condition:
    hash.sha256(0, filesize) == "e0d329a3dec10ae8ecd3ea90593f3e329c0629ebda75ab2316aafc34dfd0c91e"
}
```

### Sample 48: `8027010d89c5f204`

| Field | Value |
|---|---|
| SHA-256 | `8027010d89c5f20498bb64cc31c920d13e547186084c83d3c71b8ce1ccdc8a49` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-09-26 01:05:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1102c81a2a73bccb13b3da12253f182c` |
| SHA-1 | `3f24d9825b55e52a875850dda2d7e7f68122da62` |
| SHA-256 | `8027010d89c5f20498bb64cc31c920d13e547186084c83d3c71b8ce1ccdc8a49` |
| SHA3-384 | `29dde1a17cfd87a0e07597526797b056524a388abffb680f12c1afbbd8d091bcf2664200000d6cac1b2cc1415f9d9d18` |
| TLSH | `T147735C32B9751D2BC4D0A87A61F30325F2F2478A25ACCA1A7D720D8EBF6565032477F9` |
| SSDEEP | `1536:jP+SbCGR18pspTH1mDQ2tXXUN95s0xwlWptCMR8/pW:zf4yVYpENP1x6MoW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_8027010d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8027010d89c5f20498bb64cc31c920d13e547186084c83d3c71b8ce1ccdc8a49"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:30"
  condition:
    hash.sha256(0, filesize) == "8027010d89c5f20498bb64cc31c920d13e547186084c83d3c71b8ce1ccdc8a49"
}
```

### Sample 49: `5e871e0b378818f9`

| Field | Value |
|---|---|
| SHA-256 | `5e871e0b378818f970f9c66a04ca0edb9ecfa9d9cb3f4c84d5d450774530a5b0` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-09-26 01:05:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55bbd88efd7552dcbb1e9f0da3654836` |
| SHA-1 | `6f2f76e1bab41b23046e3dbc2196637032115835` |
| SHA-256 | `5e871e0b378818f970f9c66a04ca0edb9ecfa9d9cb3f4c84d5d450774530a5b0` |
| SHA3-384 | `8facc3a2ad268540a8bcf251906457c97004bd26a9d88156d085b81140d02afff0b907194a92ece3492df07075cd7647` |
| TLSH | `T1F003E19ED9A0ACC6C94E1CFF165D432A8E0971E213A7C78CE2044CCC7BAF85372198A5` |
| SSDEEP | `768:LVyIwYjG0JFpDlVHC4wT3IMM+kn4QKuFG//WN:LVyYjXJHlRLwT3IMMxouM4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_5e871e0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e871e0b378818f970f9c66a04ca0edb9ecfa9d9cb3f4c84d5d450774530a5b0"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:29"
  condition:
    hash.sha256(0, filesize) == "5e871e0b378818f970f9c66a04ca0edb9ecfa9d9cb3f4c84d5d450774530a5b0"
}
```

### Sample 50: `18841145b15bdb56`

| Field | Value |
|---|---|
| SHA-256 | `18841145b15bdb567cb82218dc6785248a4732df508777d6316af925e5c586ed` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-09-26 01:05:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `807ea81303ba4b828bdb4218ea6c554a` |
| SHA-1 | `dedb6b4956ee96d7e1e682574119f40a926b9c12` |
| SHA-256 | `18841145b15bdb567cb82218dc6785248a4732df508777d6316af925e5c586ed` |
| SHA3-384 | `056c5547ee59df83e0ef872aa4c07f01d4a21cba4928f4425e4e9ad161af73a23bc1673c252078860976067a532c8de4` |
| TLSH | `T14BE2F1B17385AC7ACDF0B87FCF7481C592122B78A1353C635920966076B39561DBFE21` |
| SSDEEP | `768:9Ud82887nrYGHuhN3ZPXGubfUMGYUs3UozH:9Ud8L87sGHkvGugMGWzH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_18841145
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18841145b15bdb567cb82218dc6785248a4732df508777d6316af925e5c586ed"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:27"
  condition:
    hash.sha256(0, filesize) == "18841145b15bdb567cb82218dc6785248a4732df508777d6316af925e5c586ed"
}
```

### Sample 51: `12e48cbda8754709`

| Field | Value |
|---|---|
| SHA-256 | `12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529` |
| Family label | `unknown` |
| File name | `12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529.bin` |
| File type | `exe` |
| First seen | `2026-09-26 01:03:14` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e98b7c52744e5bb2d2476e2852d4989` |
| SHA-1 | `bdecc89bd73749eee8034ab6f67d6f1e0ec1c255` |
| SHA-256 | `12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529` |
| SHA3-384 | `f3d551fc8d40722e8d5b7214351a8529d5584d76a994e2136e73e267a674325c9db989015a455cc775ba3d4c8ad43712` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T191A66A03AA6481A5C495EF38C4B753663B74BC88873533E72E51EE742F223D1AEB5B44` |
| SSDEEP | `49152:dW8Spifybo2DPeGQ7fMWELJ52plN0WtvwNUOr4w9Sv/2H6sbecTa2xLWrQguia2r:dW82P0YPQ7URd52plm9I2TbcNPXnAc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_12e48cbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529"
    family = "unknown"
    file_name = "12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529.bin"
    file_type = "exe"
    first_seen = "2026-09-26 01:03:14"
  condition:
    hash.sha256(0, filesize) == "12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529"
}
```

### Sample 52: `eb034f148ad141e8`

| Field | Value |
|---|---|
| SHA-256 | `eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363` |
| Family label | `unknown` |
| File name | `eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363.bin` |
| File type | `exe` |
| First seen | `2026-09-26 01:03:11` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f222122d8ca5a7d6ac5412d811e93a9` |
| SHA-1 | `dfc642a6acd7a9ede3c6f0094939608f8f719c59` |
| SHA-256 | `eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363` |
| SHA3-384 | `0654fbaff2351800603f8f3eec66845f7a58fab75e496e5ad56fa2ef0f64ef449e66e711ba4c90f611282f6627dcce22` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T17B467D063D9290A8D0D9EE3084765216BF347CDD8B3933E76FA1A6742E223D39D79B14` |
| SSDEEP | `49152:vyQyx+rb3t8Mh2VbJux8fViYLb9ICYMpsrOQSl7IPSXQ5Z/WxKiA6ZwI9DR6O0Jk:jLrb680LfVii9ICHfoSTxKCzwGfd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_eb034f14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363"
    family = "unknown"
    file_name = "eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363.bin"
    file_type = "exe"
    first_seen = "2026-09-26 01:03:11"
  condition:
    hash.sha256(0, filesize) == "eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363"
}
```

### Sample 53: `3d8a22b4d6c4b436`

| Field | Value |
|---|---|
| SHA-256 | `3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7` |
| Family label | `unknown` |
| File name | `3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7.bin` |
| File type | `exe` |
| First seen | `2026-09-26 01:03:09` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd498a91c6766df7e3e15a96f0a9feb2` |
| SHA-1 | `3a2f06e8198cbd688332c15677a97c7197b2ccec` |
| SHA-256 | `3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7` |
| SHA3-384 | `e7fe3905a39f1f42221d398b0cc6b87730f6581ae0a95a8aa88987edcc013a61711376d3e7f5ed2a88387f9fbdee7d4e` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T153466D073D929598C0D9AA31C46A6616BF35BCCC8B3933E71FA0A6743E663C35C79B14` |
| SSDEEP | `49152:F72HUu0OlfCTAG+U/ze9lX4ADFlGb3mmNqozRPg0DhOkTLb4JWLrVqGTz21OPb/:RCUuHue9loeFo82g0kk/b4cXdH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_3d8a22b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7"
    family = "unknown"
    file_name = "3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7.bin"
    file_type = "exe"
    first_seen = "2026-09-26 01:03:09"
  condition:
    hash.sha256(0, filesize) == "3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7"
}
```

### Sample 54: `06a692324852555d`

| Field | Value |
|---|---|
| SHA-256 | `06a692324852555d671621a35281899d0809628c36ee28a43ad2ddcf156f813e` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d06a298188796a3bc430476bce89339b` |
| SHA-1 | `41a192576de98dfef59d9b2b1e6f65a40674dbd2` |
| SHA-256 | `06a692324852555d671621a35281899d0809628c36ee28a43ad2ddcf156f813e` |
| SHA3-384 | `94c7df7a7c7f90a9c7e66eb5c420cf6451f260c070e39f1b4ca99790ffb44d813235032aa4e282ab6fa70f78dca823cb` |
| TLSH | `T1CB733991BD815B13C6D012BBFB5E028E372653A8D2EF32138D266F21378796B0E77651` |
| TELFHASH | `t15551f4f6cb991aed2bd1c704c18e613eabcd35ad5b10386aca193b0b85435c1f10a836` |
| SSDEEP | `1536:yu2Z1jY80ld4ppG2jKnbhhz2HVPAV9sOvss/hfs:yu2X82jKtV29A3b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_06a69232
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06a692324852555d671621a35281899d0809628c36ee28a43ad2ddcf156f813e"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:57"
  condition:
    hash.sha256(0, filesize) == "06a692324852555d671621a35281899d0809628c36ee28a43ad2ddcf156f813e"
}
```

### Sample 55: `00eb5f7e22e90c0c`

| Field | Value |
|---|---|
| SHA-256 | `00eb5f7e22e90c0caf47f2434b7f866f415f61a190f94da452aaf64df03aaa47` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a776578b4ed24ddb0aac7fafabd1fd20` |
| SHA-1 | `f928f5f6d4d7302d7d106f5be8ddce00241ae633` |
| SHA-256 | `00eb5f7e22e90c0caf47f2434b7f866f415f61a190f94da452aaf64df03aaa47` |
| SHA3-384 | `01ba0c9562a42a68e8f8150fad35245b32b0b7bdd36b5caaab68895ee11a0ec96d1c616cf5d3fb4c8a7047a1f8280536` |
| TLSH | `T18F535BC5AA47D8F6FD5602711173EB378632F13A1129DA87C7A9ED32BC52900EA1739C` |
| TELFHASH | `t11f31b0fa6dee09fcb3d4a808c75a6fd31a7ae177156139b044b5585027f388081b5c3a` |
| SSDEEP | `1536:ahZerRy3lVDKvfb9IZG4R9bdx68QsP++CMq32UFSTGhk15uJnaroXf:ahqo3lVDKbd4bvP+zf2UMT2M5O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_00eb5f7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00eb5f7e22e90c0caf47f2434b7f866f415f61a190f94da452aaf64df03aaa47"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:52"
  condition:
    hash.sha256(0, filesize) == "00eb5f7e22e90c0caf47f2434b7f866f415f61a190f94da452aaf64df03aaa47"
}
```

### Sample 56: `51e8cc5e0dcd6dec`

| Field | Value |
|---|---|
| SHA-256 | `51e8cc5e0dcd6dec03ac00bf082dcc8cbe757df2bb581f4ec5ca7be9aa5dd7eb` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44bc66485b57bab631702f10f4bab092` |
| SHA-1 | `26eb4fc4e0c2585ea8be784e35fb2b7111215145` |
| SHA-256 | `51e8cc5e0dcd6dec03ac00bf082dcc8cbe757df2bb581f4ec5ca7be9aa5dd7eb` |
| SHA3-384 | `5addc24d267679c2d352b2d0f7392fb7aa06240f62ce8282b397606f63a73276dea7abb9e7e03d1053917a83bb049053` |
| TLSH | `T106A3C91E6E218FBDF369C33047B78E21A79837D626E1D685E26CD6011E6034E641FFA4` |
| TELFHASH | `t173217f5c4d7412e48b321d9e2baeff76e19030de0b326d378e11aaadba6d9425d00c1c` |
| SSDEEP | `1536:yk8NZJjWAaVPWcve4meOeuCyTPHvwIp/read7Q1Qs/Rd/uP:WZJjBaVOzhHvlp/o1F/c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_51e8cc5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51e8cc5e0dcd6dec03ac00bf082dcc8cbe757df2bb581f4ec5ca7be9aa5dd7eb"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:48"
  condition:
    hash.sha256(0, filesize) == "51e8cc5e0dcd6dec03ac00bf082dcc8cbe757df2bb581f4ec5ca7be9aa5dd7eb"
}
```

### Sample 57: `9d899b1d90a38c29`

| Field | Value |
|---|---|
| SHA-256 | `9d899b1d90a38c290da074e516c657738b87d99ffaafb931a6eb9c72cff1d5b0` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e4c89febb7e5027ff1de2fa29605811` |
| SHA-1 | `0200a68e4086b06222b30739e97c625dc8d95ccb` |
| SHA-256 | `9d899b1d90a38c290da074e516c657738b87d99ffaafb931a6eb9c72cff1d5b0` |
| SHA3-384 | `e3ffd1db067510017c0ec455f9f4c61ec85788a8f764dd78c195f212b477a4b0cf3401a94b78ed75e239d25422b3bf7a` |
| TLSH | `T15EF2F1B409DE4917CEE888BB8826C5C275BF5FF9F6C42075181181BEA527096B7E10CB` |
| SSDEEP | `768:ZkbNfB2uZnay/H/FqpS/l+0GY+Mzfh5peDs3UozX:Zkbf2/OHtqpS/U/x65hzX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_9d899b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d899b1d90a38c290da074e516c657738b87d99ffaafb931a6eb9c72cff1d5b0"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:05"
  condition:
    hash.sha256(0, filesize) == "9d899b1d90a38c290da074e516c657738b87d99ffaafb931a6eb9c72cff1d5b0"
}
```

### Sample 58: `19db829e93bfd90e`

| Field | Value |
|---|---|
| SHA-256 | `19db829e93bfd90e0818900fab52c7e538f9aefd768a57a0054394b9f6501a6a` |
| Family label | `Mirai` |
| File name | `sora.x86` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `608fa8327469b410aed0d272266489b4` |
| SHA-1 | `cd139bfc4cb885fa779dfab165168cb830eab869` |
| SHA-256 | `19db829e93bfd90e0818900fab52c7e538f9aefd768a57a0054394b9f6501a6a` |
| SHA3-384 | `f87274c3179141a249bd0c5560945e9caed0b28bc0162b33249583e2eefc73b799ddf686d1b900738de7f9b6826c010d` |
| TLSH | `T148234BC0A682F9F1EC11457C307BA7725E77F43AA03AEDDFD7D9A423A841602960729D` |
| TELFHASH | `t1a31186b72e690decb3e16858c35e22d2195ad23f597133e54222d42532a6fc2947ec3e` |
| SSDEEP | `1536:Ovmt6GStZRjrMcPzOubN8wEToP9dIYfQ5Igomv4ao:O5GS1HMcPCuhOToP7I7iavjo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_19db829e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19db829e93bfd90e0818900fab52c7e538f9aefd768a57a0054394b9f6501a6a"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:04"
  condition:
    hash.sha256(0, filesize) == "19db829e93bfd90e0818900fab52c7e538f9aefd768a57a0054394b9f6501a6a"
}
```

### Sample 59: `118dce2dc67733f7`

| Field | Value |
|---|---|
| SHA-256 | `118dce2dc67733f762aa1c0961cb2c0b4d83735bc9c9a099fc545ef4fb3f2a50` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d70845847b6d7c173735d44cd8acbf9` |
| SHA-1 | `dfe77d06e6fc37be4d64c82ffb25699f78aa616c` |
| SHA-256 | `118dce2dc67733f762aa1c0961cb2c0b4d83735bc9c9a099fc545ef4fb3f2a50` |
| SHA3-384 | `9155c98d8a1d2564ca6ebde6a64e9b43a53c51483b1319662aa5e4b1568db1c259cf2436d28d6e8d77d724db15f4f7ac` |
| TLSH | `T1B9539C73C8296E54D19582B4B871CB781B63B48082471FFA5BD9C2BA9083DFCF6093B4` |
| SSDEEP | `1536:JaDwtqKcomlIFZCXaZMYfPkYPigpK2mP5A/iabC0c/v38Bs/n8a:JwacomlITCXaZMYXkYagQ2mgiabgXMla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_118dce2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "118dce2dc67733f762aa1c0961cb2c0b4d83735bc9c9a099fc545ef4fb3f2a50"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:02"
  condition:
    hash.sha256(0, filesize) == "118dce2dc67733f762aa1c0961cb2c0b4d83735bc9c9a099fc545ef4fb3f2a50"
}
```

### Sample 60: `f839d7ea8cea6fa2`

| Field | Value |
|---|---|
| SHA-256 | `f839d7ea8cea6fa2bac1d04edf7f7f0caac562dee9ca8b557dc06d914f4c6d4c` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-09-26 01:02:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `738d427e1bac4525ada1b77a2a9989cc` |
| SHA-1 | `432f3bd7d20f1c305d1630f2895f8d06bf3a82ee` |
| SHA-256 | `f839d7ea8cea6fa2bac1d04edf7f7f0caac562dee9ca8b557dc06d914f4c6d4c` |
| SHA3-384 | `aabdefa6d0786eb25609f9230660b2b0d817e11cd92b41220e8599d9915bcb445b2f67e3589861b58be0fd2c72ead76a` |
| TLSH | `T1D8C32B46EA408B13C5D617B7FAAF41453322DB5493DB730689285FF43F87A9E0E27A06` |
| TELFHASH | `t1c121e4b1471a56246665cfec8ddd73aa022c83155386df33df21c4ec640909de535c8f` |
| SSDEEP | `3072:K8PXmy9MpxJXM93N30yDShgFKeqBC+nbHM/9trM/:pPXmy9Mmb0yDShg4er+nzM/9trM/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_f839d7ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f839d7ea8cea6fa2bac1d04edf7f7f0caac562dee9ca8b557dc06d914f4c6d4c"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:00"
  condition:
    hash.sha256(0, filesize) == "f839d7ea8cea6fa2bac1d04edf7f7f0caac562dee9ca8b557dc06d914f4c6d4c"
}
```

### Sample 61: `2226ab1b193ea613`

| Field | Value |
|---|---|
| SHA-256 | `2226ab1b193ea6135e193431d1aae563ea7638bba39ac63a6268cfc73bb84dbf` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a0c753b1ef1ed161fafbbb59a9eaa4c` |
| SHA-1 | `848954d5c5d9b8c1a5b28538968aeaf9e5e252e3` |
| SHA-256 | `2226ab1b193ea6135e193431d1aae563ea7638bba39ac63a6268cfc73bb84dbf` |
| SHA3-384 | `9ca1526e95b56ad765a396a6d3243a2987fa1a6bce66c609edb556820a69ad391999d48bc90e23bd960a541dcc148562` |
| TLSH | `T17DE2F26A51ECF12CE44E903BC32FA98E31E65D11BE17C69424C476DADF611F920B6833` |
| SSDEEP | `768:g32bRAqg2vQzSPMjFY8AFOEPB6ZSq7xnwNQBUt:DbRAp2v4ECF+FvB6ZSonwN2W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_2226ab1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2226ab1b193ea6135e193431d1aae563ea7638bba39ac63a6268cfc73bb84dbf"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:59"
  condition:
    hash.sha256(0, filesize) == "2226ab1b193ea6135e193431d1aae563ea7638bba39ac63a6268cfc73bb84dbf"
}
```

### Sample 62: `b9e699f2452858a7`

| Field | Value |
|---|---|
| SHA-256 | `b9e699f2452858a725e308303c5829c206813a39603480d366ba83344754354f` |
| Family label | `Mirai` |
| File name | `sora.arm5` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `973328a8ed2c971fbf10d28fd5d7c6f6` |
| SHA-1 | `b31d16eaf174fe97692e39b7044d1861cbd22bb3` |
| SHA-256 | `b9e699f2452858a725e308303c5829c206813a39603480d366ba83344754354f` |
| SHA3-384 | `f1b851b3bc93b67bbd28781cab91f4f26d41bdbf932d50ae77cc4e78d169ce5b288adaa5494db20e87125e2e5861de50` |
| TLSH | `T1DA23F7C27942B629C3D157BBEE9F014E335497DCD1EA3353C8281B947A8AA0F0D67B46` |
| TELFHASH | `t19ce07200ec798b288cdbaab4ad9d07b8ca012212606b4b10cf10daf4c83f448f30ce5a` |
| SSDEEP | `768:GHEwscmmayqpSNRuCRvFtS1ug1/njv2DoCerCGme0Cfi5reSU7wCVy/rCxHghW1s:GVmOWSNRcxjvqe0C65rnvhW05qpRJY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_b9e699f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9e699f2452858a725e308303c5829c206813a39603480d366ba83344754354f"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:57"
  condition:
    hash.sha256(0, filesize) == "b9e699f2452858a725e308303c5829c206813a39603480d366ba83344754354f"
}
```

### Sample 63: `e4afc15b78f26c3c`

| Field | Value |
|---|---|
| SHA-256 | `e4afc15b78f26c3cd1fa5a03daf005bf8bc8f627947a8a38afa4d8aac4b4856b` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dbf59616dbcffa706f3ba79dd970230` |
| SHA-1 | `ccb78c5d0d588daa440b9a58b4bbf1c95402febc` |
| SHA-256 | `e4afc15b78f26c3cd1fa5a03daf005bf8bc8f627947a8a38afa4d8aac4b4856b` |
| SHA3-384 | `935451bdde89a678d882263983de7d0846a9512ff458a4f66e24f321723dda23c8c441fdb3b7d42454193cfa3c946035` |
| TLSH | `T17AF2E078A20189DDD179D6FA03EC4370B2290FA0F4128C6FF66E59A63DE65E534272D8` |
| SSDEEP | `768:4NYKyukZoTMKeFDedFYONsIyHrINP1pHElHlPMqMUMkLE0pucPjrWJgGlzDpbuRA:iYdWleFidFzbyLQP1OpMqMapCVJu+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_e4afc15b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4afc15b78f26c3cd1fa5a03daf005bf8bc8f627947a8a38afa4d8aac4b4856b"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:56"
  condition:
    hash.sha256(0, filesize) == "e4afc15b78f26c3cd1fa5a03daf005bf8bc8f627947a8a38afa4d8aac4b4856b"
}
```

### Sample 64: `3032ac2b1cac644b`

| Field | Value |
|---|---|
| SHA-256 | `3032ac2b1cac644b787d2ebdd3653adc79e1b25779a020e6a1bc123059362e39` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5279db913a519de03ce64750b9093c0` |
| SHA-1 | `448ed155e1a6870f7e0e7b49cfc52ec1f9ba2c2d` |
| SHA-256 | `3032ac2b1cac644b787d2ebdd3653adc79e1b25779a020e6a1bc123059362e39` |
| SHA3-384 | `c7357ed4ffa7be0928bbec4f90618b3ffc3ef8d115187ccb20407d8866f683aa47e8f62e35d40e3cad93edcd4c586faa` |
| TLSH | `T1AE832A97F400EDBDF80AD77B4453090AB270A3A105830F36A39BB963FD721A45967EC6` |
| SSDEEP | `1536:quKG91H4CgWxYRyRqwwrzPQtav8FjWtFUo/V6OXZJ7/aNSOFmA7ExtX1dT:q5GTPxYRyRqwazPQta6Q9VXXz4FmA7ux` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_3032ac2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3032ac2b1cac644b787d2ebdd3653adc79e1b25779a020e6a1bc123059362e39"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:54"
  condition:
    hash.sha256(0, filesize) == "3032ac2b1cac644b787d2ebdd3653adc79e1b25779a020e6a1bc123059362e39"
}
```

### Sample 65: `785bb0a6d1855471`

| Field | Value |
|---|---|
| SHA-256 | `785bb0a6d18554716328ad01afbfcd1d14880a9beaa17bb4e21254408677ade3` |
| Family label | `Mirai` |
| File name | `sora.m68k` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `338331a9fb8caa616cff6c63cdc1b71d` |
| SHA-1 | `e5ed714bb1720b917c526fa6714a8310282db4bb` |
| SHA-256 | `785bb0a6d18554716328ad01afbfcd1d14880a9beaa17bb4e21254408677ade3` |
| SHA3-384 | `d8a5a46a412a7a529ab119aa55fd52546c1f0fc79b37afe349a8729a4a84c7c5ecc0fc77663aaf2df3a7b40b62b9e245` |
| TLSH | `T1A5333BD6B902AD7CF99BE6BE80270E0AB13123541053073777EBFC937E321949956E4A` |
| SSDEEP | `768:8CeKEfhe5XdrbejRIcfFMQ/5MdgFHj0iPuvWeffpqmUJTXr6Lu380Db:dsfIBZeRtJrFj0imvppqmUJP6Lc8W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_785bb0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "785bb0a6d18554716328ad01afbfcd1d14880a9beaa17bb4e21254408677ade3"
    family = "Mirai"
    file_name = "sora.m68k"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:53"
  condition:
    hash.sha256(0, filesize) == "785bb0a6d18554716328ad01afbfcd1d14880a9beaa17bb4e21254408677ade3"
}
```

### Sample 66: `d08708e0a752b6e8`

| Field | Value |
|---|---|
| SHA-256 | `d08708e0a752b6e8120c2bb83c926b8af848a73bcd34e5e1c7073144cee98b77` |
| Family label | `Mirai` |
| File name | `sora.mips` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13de1c7c0596d5f557cca70c8ed375ab` |
| SHA-1 | `dd1947704edf54a69395cb7c1f9a19b6650f5f55` |
| SHA-256 | `d08708e0a752b6e8120c2bb83c926b8af848a73bcd34e5e1c7073144cee98b77` |
| SHA3-384 | `67dc4d63c60af659fe2b517d5b923b8279727ae557d26a190bfa4fcf55968057d25449925e0d9e0b1749836f0d89500d` |
| TLSH | `T10463960A3E218FBEFBAC863847B74A219658339626F1C5C5E15CEE015E7034E745FB98` |
| TELFHASH | `t1b4016d58843817f093814c9d6becff76e09140df59625e3b8d00e99adb26a468d01d2c` |
| SSDEEP | `1536:j9NLNxDu9H/hpVBi6yFG4W0vK0pErAnGzUNPKkifR:xNL/Dw7jB4W0CEELINPKkCR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_d08708e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d08708e0a752b6e8120c2bb83c926b8af848a73bcd34e5e1c7073144cee98b77"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:51"
  condition:
    hash.sha256(0, filesize) == "d08708e0a752b6e8120c2bb83c926b8af848a73bcd34e5e1c7073144cee98b77"
}
```

### Sample 67: `7992dd0aa384aace`

| Field | Value |
|---|---|
| SHA-256 | `7992dd0aa384aaceab957f49763b863c8ff623300f155a26301a27121fddbfec` |
| Family label | `Mirai` |
| File name | `sora.sh4` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba1b4a7fc2d830d341c038b390818452` |
| SHA-1 | `c9f5863877cbaa020e5d272542fae5401e326529` |
| SHA-256 | `7992dd0aa384aaceab957f49763b863c8ff623300f155a26301a27121fddbfec` |
| SHA3-384 | `871ada7628f2452add7fc4c2327bd2e84984c285c0875af14c6de7c46c2c88438faa36ec9f3867b6a79c0d9382433bd8` |
| TLSH | `T1CE337CB5C579EDE8D1144A78BE248E749723E100C6932EFADA44C6A99083EFCF5583F4` |
| SSDEEP | `768:jaixFwtLSYAagMo0ebfELRv0X3pyWfs3I9ICJUU/qMCqKomQRCvp:jaQFwtOGBv0XJfs3kICJt/qMF/RCvp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_7992dd0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7992dd0aa384aaceab957f49763b863c8ff623300f155a26301a27121fddbfec"
    family = "Mirai"
    file_name = "sora.sh4"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:50"
  condition:
    hash.sha256(0, filesize) == "7992dd0aa384aaceab957f49763b863c8ff623300f155a26301a27121fddbfec"
}
```

### Sample 68: `0c8f55b3624744ed`

| Field | Value |
|---|---|
| SHA-256 | `0c8f55b3624744ed83e804240dfbc52d9e2a7c2bca8bfabf0930be699d6d52df` |
| Family label | `Mirai` |
| File name | `sora.arm6` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64fcda3f8a20bd7499253375bc49051d` |
| SHA-1 | `8fa4dd2fd8cc7986279c02f18bb3ac577eb64a13` |
| SHA-256 | `0c8f55b3624744ed83e804240dfbc52d9e2a7c2bca8bfabf0930be699d6d52df` |
| SHA3-384 | `d2e787460458e97aff354fbead291857fd3d2e66d0a514c68cfbe92b5061d144ea54c35a7017fd56d85373583108a871` |
| TLSH | `T1E5530A85B8819A25C6D113BBFE1F018E3316975CE2DE73128D145F647BCBD5F0E2AA0A` |
| TELFHASH | `t16b117a721e8b2e8c1be8c148815b845959ac32f51b1522accf2d9f2315e30c1b71a837` |
| SSDEEP | `1536:YdnWpBh3cLDNoATqrjjG5yAMQ1fwnWmLdI8niD7noKWp:lH3+po+qr24XQtwm7noKWp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_0c8f55b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c8f55b3624744ed83e804240dfbc52d9e2a7c2bca8bfabf0930be699d6d52df"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:48"
  condition:
    hash.sha256(0, filesize) == "0c8f55b3624744ed83e804240dfbc52d9e2a7c2bca8bfabf0930be699d6d52df"
}
```

### Sample 69: `7c2b457545aad2ab`

| Field | Value |
|---|---|
| SHA-256 | `7c2b457545aad2ab304719df171448313b8e39040b91883c1dcad6b378f350bc` |
| Family label | `Mirai` |
| File name | `sora.ppc` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83c0454122233377ba78bf5697a06b0d` |
| SHA-1 | `0bcc87eaf553363d2b71a36b32eee7e37e6f53d0` |
| SHA-256 | `7c2b457545aad2ab304719df171448313b8e39040b91883c1dcad6b378f350bc` |
| SHA3-384 | `26ff6a5978bc9878f4944c9be2875b7412d0017e8a07ab333d518a621b06d8eb19e85abec2659a74035d6b265c8b1b22` |
| TLSH | `T1E7332B027228094FF9D61EF0353F0FE093AFE98024E0B585694EEB458676F771586F89` |
| SSDEEP | `768:opgPdUwOe1Po/7wni3RiAPSnPfvPKTCtjcxt8mizjrvVwipnpBX9QeP3:D1FOe1Po/kcE92Fomi6wvXeO3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_7c2b4575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c2b457545aad2ab304719df171448313b8e39040b91883c1dcad6b378f350bc"
    family = "Mirai"
    file_name = "sora.ppc"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:46"
  condition:
    hash.sha256(0, filesize) == "7c2b457545aad2ab304719df171448313b8e39040b91883c1dcad6b378f350bc"
}
```

### Sample 70: `316c53cf3e214df1`

| Field | Value |
|---|---|
| SHA-256 | `316c53cf3e214df1268b0bfce7761a22d867f519f99fb50ededf743e6199598b` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-09-26 01:01:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51c87f4f31187955e4e61bfdfec11ba5` |
| SHA-1 | `1112655829c1d12f24f9c5df38b7314a54247e05` |
| SHA-256 | `316c53cf3e214df1268b0bfce7761a22d867f519f99fb50ededf743e6199598b` |
| SHA3-384 | `7b90b358f88545da7cbf978132337cded117eaff9cd6f420f558cc8dd227706aafd8414e6a8bdf228ca34c9c274753aa` |
| TLSH | `T1FB4308817881A626C7D05377FA5F018D33199798E0EE33578C296FA07B8AD1F0D6B74A` |
| TELFHASH | `t10131c2b7499607ec2be4d3c466cf61298aae34fd3b00257cce1da79f42535c1b01ac16` |
| SSDEEP | `768:30ESWRYSaG0wBXAy9abThYrB2dPsnjVB5uEBwLRLWmPrqRh/8qkJSULwCVy/rCxc:dSaP0waejVEWYA0J8fhWfM5t0d7oHm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_316c53cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "316c53cf3e214df1268b0bfce7761a22d867f519f99fb50ededf743e6199598b"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:45"
  condition:
    hash.sha256(0, filesize) == "316c53cf3e214df1268b0bfce7761a22d867f519f99fb50ededf743e6199598b"
}
```

### Sample 71: `65e5f373448c5b9c`

| Field | Value |
|---|---|
| SHA-256 | `65e5f373448c5b9c628508b13bfd951ac53d656ddbba13143373292a0b3dde11` |
| Family label | `unknown` |
| File name | `dcd` |
| File type | `exe` |
| First seen | `2026-09-26 00:39:55` |
| Reporter | `iamaachum` |
| Tags | `134-122-204-169, 156-247-41-94, exe, KHM` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bc65d1c5cad6cb99db62b21f4a20813` |
| SHA-1 | `b9de4c4808901cdc84b8d3ac1b8fa423864c0d62` |
| SHA-256 | `65e5f373448c5b9c628508b13bfd951ac53d656ddbba13143373292a0b3dde11` |
| SHA3-384 | `7a67a0ea6e5c6e947807efca9e7e76a4615757d1821b82df61d55ac95217cc7ec50316d5ee8ff0f341c14796e16803db` |
| IMPHASH | `b5e84c13fad4746d56bfe40f133a0087` |
| TLSH | `T1D2456B07E2A360FCC52BC274475BAB72B931B8141134BEBF9594DB312E62E50672EB35` |
| SSDEEP | `24576:eyOKZxkuusuUD7FWKJ3VsSUvbnSpF3OFnh:eyOKZTVuIFv3VsPvbSpFonh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_65e5f373
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65e5f373448c5b9c628508b13bfd951ac53d656ddbba13143373292a0b3dde11"
    family = "unknown"
    file_name = "dcd"
    file_type = "exe"
    first_seen = "2026-09-26 00:39:55"
  condition:
    hash.sha256(0, filesize) == "65e5f373448c5b9c628508b13bfd951ac53d656ddbba13143373292a0b3dde11"
}
```

### Sample 72: `76dbfc90cc9071ae`

| Field | Value |
|---|---|
| SHA-256 | `76dbfc90cc9071aecfccf8fc7a866aa4c5cc5e26a229d9ab887eee67256435b3` |
| Family label | `unknown` |
| File name | `ការបង្ការការឆបោកតាម Telegram.com` |
| File type | `exe` |
| First seen | `2026-09-26 00:39:01` |
| Reporter | `iamaachum` |
| Tags | `134-122-204-169, 156-247-41-94, com, KHM` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58dcca92f169a9d3da4c7c986ebababe` |
| SHA-1 | `ee6ba8bf7a43f6fc7281ec0d9f6e108afba448a1` |
| SHA-256 | `76dbfc90cc9071aecfccf8fc7a866aa4c5cc5e26a229d9ab887eee67256435b3` |
| SHA3-384 | `91e42bc55047eb51c0d196c0ed5b8ae8351669ae906f359c42ba3a1e0112813d59823a3c8da7110150efd6d3557f5aca` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T17AA5D03FB28B653EE06E5A367A76E220543B7A6165124C16D6F4C88CCF250B01E3F797` |
| SSDEEP | `24576:GXVrSLScusMmOvjjhzvLhckbJn+EViUd+Sh97V6K8pmFH7BPNQ3ArPkBJultjK1Y:puI2hmkbJnLVfoSL3rdf/rVltjkY` |
| ICON-DHASH | `714d0f4fc4e84d55` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_76dbfc90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76dbfc90cc9071aecfccf8fc7a866aa4c5cc5e26a229d9ab887eee67256435b3"
    family = "unknown"
    file_name = "ការបង្ការការឆបោកតាម Telegram.com"
    file_type = "exe"
    first_seen = "2026-09-26 00:39:01"
  condition:
    hash.sha256(0, filesize) == "76dbfc90cc9071aecfccf8fc7a866aa4c5cc5e26a229d9ab887eee67256435b3"
}
```

### Sample 73: `c4e97efa91be535b`

| Field | Value |
|---|---|
| SHA-256 | `c4e97efa91be535b453d9dc55d8a30376bed95c8fb5d7a8f1743cc4d3858a9dd` |
| Family label | `Mirai` |
| File name | `stub.i486` |
| File type | `elf` |
| First seen | `2026-09-26 00:34:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db9f031eeae4b88595e1467fd18d734b` |
| SHA-1 | `b344be2fb296e0e0836c32122c41676f0fa6dbf9` |
| SHA-256 | `c4e97efa91be535b453d9dc55d8a30376bed95c8fb5d7a8f1743cc4d3858a9dd` |
| SHA3-384 | `78a8147fd09d7ad179564fc4b6a9a9cdb6cf649be21aca944b7ded169e733d4a694943a95c1000dd48a031b48e81851e` |
| TLSH | `T122157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/0:7NP46S4QVs7l6A5Zji59k0jZz06FYRsr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_c4e97efa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4e97efa91be535b453d9dc55d8a30376bed95c8fb5d7a8f1743cc4d3858a9dd"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-26 00:34:42"
  condition:
    hash.sha256(0, filesize) == "c4e97efa91be535b453d9dc55d8a30376bed95c8fb5d7a8f1743cc4d3858a9dd"
}
```

### Sample 74: `bd38b14882a3f505`

| Field | Value |
|---|---|
| SHA-256 | `bd38b14882a3f50561d87d191c9ca241d65162deba46c3016cf8deef0a6d0f94` |
| Family label | `Mirai` |
| File name | `bot.armv7` |
| File type | `elf` |
| First seen | `2026-09-26 00:34:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `331235c9bc82902aff967df17354e45f` |
| SHA-1 | `91f13bed24f7d9eae947a81270906daba2ae1094` |
| SHA-256 | `bd38b14882a3f50561d87d191c9ca241d65162deba46c3016cf8deef0a6d0f94` |
| SHA3-384 | `2be4540f4f8ff4c2839a357de99cb357724a6281aaf0871b4b47f2d8eab1d23e9ec80dccfc106a1545289b8b39b32b6d` |
| TLSH | `T1B9254C55F890DF63C9C46B7AFA5E82A833234778C3D7720699148B343B97A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:y7mNVvHPP+SmAC+Mvf9p4WrKqyj657yD/hGnmK:nDMXDu9j657yDAmK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_bd38b148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd38b14882a3f50561d87d191c9ca241d65162deba46c3016cf8deef0a6d0f94"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-09-26 00:34:40"
  condition:
    hash.sha256(0, filesize) == "bd38b14882a3f50561d87d191c9ca241d65162deba46c3016cf8deef0a6d0f94"
}
```

### Sample 75: `97098330e1939d0f`

| Field | Value |
|---|---|
| SHA-256 | `97098330e1939d0f3b44a39b8cbdb505d79f7ca6f073191e5b314927988da87c` |
| Family label | `Mirai` |
| File name | `stub.x64` |
| File type | `elf` |
| First seen | `2026-09-26 00:34:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `500ae7a9922db286fddbcb1faad9cb64` |
| SHA-1 | `ebcae15d8791db8f9e549140169bb891561b63cb` |
| SHA-256 | `97098330e1939d0f3b44a39b8cbdb505d79f7ca6f073191e5b314927988da87c` |
| SHA3-384 | `bbbc5afa18787a325814d2648cddafb3987dfdbd48da3a0a2115397f61d2a4f5841de3f7543e3eca601d1332004c63c1` |
| TLSH | `T16C157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/P:7NP46S4QVs7l6A5Zji59k0jZz06FYRsi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_97098330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97098330e1939d0f3b44a39b8cbdb505d79f7ca6f073191e5b314927988da87c"
    family = "Mirai"
    file_name = "stub.x64"
    file_type = "elf"
    first_seen = "2026-09-26 00:34:38"
  condition:
    hash.sha256(0, filesize) == "97098330e1939d0f3b44a39b8cbdb505d79f7ca6f073191e5b314927988da87c"
}
```

### Sample 76: `91abd176e15c92d1`

| Field | Value |
|---|---|
| SHA-256 | `91abd176e15c92d1aca81f74ac8a1d180db8104c9f615c96a68dd78b48a49eff` |
| Family label | `Mirai` |
| File name | `stub.arm7n` |
| File type | `elf` |
| First seen | `2026-09-26 00:31:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ffa3371d0f574f4f1169ebac417ff2f` |
| SHA-1 | `880a7e686d567f2aad4904607f5fac7337e24eb4` |
| SHA-256 | `91abd176e15c92d1aca81f74ac8a1d180db8104c9f615c96a68dd78b48a49eff` |
| SHA3-384 | `da88b5da0da03cd46a4da3bd86190b6553db6011718f994cee033817bf55d855c85540cee019ee7feb74758bdfa95441` |
| TLSH | `T141D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKic:YCp7mXtni6aBh321eSiVWKz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_91abd176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91abd176e15c92d1aca81f74ac8a1d180db8104c9f615c96a68dd78b48a49eff"
    family = "Mirai"
    file_name = "stub.arm7n"
    file_type = "elf"
    first_seen = "2026-09-26 00:31:27"
  condition:
    hash.sha256(0, filesize) == "91abd176e15c92d1aca81f74ac8a1d180db8104c9f615c96a68dd78b48a49eff"
}
```

### Sample 77: `9642ad84eac95f71`

| Field | Value |
|---|---|
| SHA-256 | `9642ad84eac95f712ecd25cc21f619acc38bd21e00e48a543df0db3908b84317` |
| Family label | `Mirai` |
| File name | `stub.i486` |
| File type | `elf` |
| First seen | `2026-09-26 00:31:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3191f2f0e676774e051020165d10591` |
| SHA-1 | `af4bdc663152ba86bbb938dfac59e758707f692d` |
| SHA-256 | `9642ad84eac95f712ecd25cc21f619acc38bd21e00e48a543df0db3908b84317` |
| SHA3-384 | `7784df6ddb47167a002b9551143b2f30a596cff12fbe8b384c718da8fb117d9dbc105faf2a67d8a4e68855d0dc3b0b91` |
| TLSH | `T1CB157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/7:7NP46S4QVs7l6A5Zji59k0jZz06FYRs+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_9642ad84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9642ad84eac95f712ecd25cc21f619acc38bd21e00e48a543df0db3908b84317"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-26 00:31:25"
  condition:
    hash.sha256(0, filesize) == "9642ad84eac95f712ecd25cc21f619acc38bd21e00e48a543df0db3908b84317"
}
```

### Sample 78: `492be8058dca4014`

| Field | Value |
|---|---|
| SHA-256 | `492be8058dca4014eb9390b44d5bd39aa2d3fa7733c97daa2baf1b0479d00d3d` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-26 00:29:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abc6cd7dee477a7fb45aae5c626354eb` |
| SHA-1 | `31809117df1e4d056d2c676a786b4bb0cbfe6911` |
| SHA-256 | `492be8058dca4014eb9390b44d5bd39aa2d3fa7733c97daa2baf1b0479d00d3d` |
| SHA3-384 | `08e9dcf1a23b9f99fbd6ced5c413c214237539b7e643edf0a8a650fa113e314fc38ab5d9563cbdcae7af65b56965d911` |
| TLSH | `T192745B89DF691FEBE86FCE710A5D031719DD9C9B82F47B385A7CCC48B19A20545E3828` |
| SSDEEP | `6144:aLVKHnZ5Im9Oo5t2kDF1m4syA3s+tsBdQdYU0krT9M9tCvuxDFk1pEyD58oYdmJ:O/mxJ9AcJdQdYU0kwDFimyD58RdmJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_492be805
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "492be8058dca4014eb9390b44d5bd39aa2d3fa7733c97daa2baf1b0479d00d3d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-26 00:29:23"
  condition:
    hash.sha256(0, filesize) == "492be8058dca4014eb9390b44d5bd39aa2d3fa7733c97daa2baf1b0479d00d3d"
}
```

### Sample 79: `7f6e20ab5e83d081`

| Field | Value |
|---|---|
| SHA-256 | `7f6e20ab5e83d08108a437a704a2fa161ebec83ecf541883a62ef2314ead2505` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-26 00:28:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1c4edad5371ca6a5856b989fc991550` |
| SHA-1 | `deefb0038b19524371d08ec67242ca2c1f7bd65a` |
| SHA-256 | `7f6e20ab5e83d08108a437a704a2fa161ebec83ecf541883a62ef2314ead2505` |
| SHA3-384 | `db4ab8e55242328393052a1f18217efe66d7318a2c043ef0fbd3d1e77ba3904217a8301a19dee2888bc4960b2a968fb5` |
| TLSH | `T141E3135E33AA506BC9CF0FBD372E6A5EAF80D6D129287F47D745C2048BE56837285138` |
| SSDEEP | `3072:b/Ohk7adeqMbpCt7yyjh2TDcKr0U/kW5kzGs7s4Ev+bxoSsj:b/OuOdxypahYDhr0U/kWazRfs+/A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_7f6e20ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f6e20ab5e83d08108a437a704a2fa161ebec83ecf541883a62ef2314ead2505"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-26 00:28:15"
  condition:
    hash.sha256(0, filesize) == "7f6e20ab5e83d08108a437a704a2fa161ebec83ecf541883a62ef2314ead2505"
}
```

### Sample 80: `1a6598b1751b1389`

| Field | Value |
|---|---|
| SHA-256 | `1a6598b1751b1389dad24241b5e7592692e979a32d92031ac8d9a3114c4e1733` |
| Family label | `Mirai` |
| File name | `stub.mpsl` |
| File type | `elf` |
| First seen | `2026-09-26 00:28:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `564f1e6588e59d0fae58cef570c10f25` |
| SHA-1 | `6c35903ce1a071c87f3e36e363490e52bb06b790` |
| SHA-256 | `1a6598b1751b1389dad24241b5e7592692e979a32d92031ac8d9a3114c4e1733` |
| SHA3-384 | `863835f3cb58680ebd8f64920f1b4907b2686f95656eda4106de65e57b71a342f3d10bb297d0fffe0d79e07ff809a30b` |
| TLSH | `T1E8F45C07FF815FEBC09FCD30852EC31721E9D48656C1A62A72FC4A8CBA5D6694BE3494` |
| SSDEEP | `12288:cAsRZePvWEwcj1b4D7QAEjYHZ6fxd8mg2cSAH07FFMk/mKsuSxzOTl1aplHPPhGM:GZwv1jJ4/9UZnQ28N+0JTxGy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_1a6598b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a6598b1751b1389dad24241b5e7592692e979a32d92031ac8d9a3114c4e1733"
    family = "Mirai"
    file_name = "stub.mpsl"
    file_type = "elf"
    first_seen = "2026-09-26 00:28:13"
  condition:
    hash.sha256(0, filesize) == "1a6598b1751b1389dad24241b5e7592692e979a32d92031ac8d9a3114c4e1733"
}
```

### Sample 81: `334a7d8fb058a3e5`

| Field | Value |
|---|---|
| SHA-256 | `334a7d8fb058a3e599c93a5999fa1bca985c989514ade747be7e46768e54bba9` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-09-26 00:25:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a996fd183e26259bf92070948468f23` |
| SHA-1 | `995ef23f35d85463cf8eae1951280959d6b3f149` |
| SHA-256 | `334a7d8fb058a3e599c93a5999fa1bca985c989514ade747be7e46768e54bba9` |
| SHA3-384 | `a19ac47b18c0da713acbf14160db1411c14bec3575a0c2d7bc3c008984da00eb4d4b11449d1d38355a140c12a6f4897e` |
| TLSH | `T172441855F890DBA2C6C12B7AFB4D4388331B1B79D3DE7102CD149F3967EA94B0A3A542` |
| TELFHASH | `t1c9e0680247b82b1c82f82016a2977a1c489c2c9a37322cc10f84be8b1f2a78170f9e31` |
| SSDEEP | `6144:nZJw5kY6dofC1B+Ibo+w+eJb5kZMwbzSAYXQEjBV+HCjR8qtdb:xdoKtoZfb5kZb3EV798Gdb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_334a7d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "334a7d8fb058a3e599c93a5999fa1bca985c989514ade747be7e46768e54bba9"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-09-26 00:25:36"
  condition:
    hash.sha256(0, filesize) == "334a7d8fb058a3e599c93a5999fa1bca985c989514ade747be7e46768e54bba9"
}
```

### Sample 82: `85720f4b122ff936`

| Field | Value |
|---|---|
| SHA-256 | `85720f4b122ff936549e03075651eade1a8a381ac2ef79869d4c09c5c89ea94e` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-09-26 00:24:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1126d88d1e0b444a42393ec47dfda7b9` |
| SHA-1 | `7033651b3e462f3218937cd9407850611780919f` |
| SHA-256 | `85720f4b122ff936549e03075651eade1a8a381ac2ef79869d4c09c5c89ea94e` |
| SHA3-384 | `d0bf6f4c4601e1b5fa632507113048fc4073300d5095ccd07941c2a44d7b7fc49424670851c729b8bfe77c791bdb9bef` |
| TLSH | `T114B3125543176882E6660D77F79448CCCEA370A020FA778B6155FC2DE01349C3EA7AFA` |
| SSDEEP | `3072:tQ0eVmLAqCnXnvQ+rMEdBsXDfE0Tow+b2HMIEIbEzqPXfz9:tjeQL9WpIE0To6MTbzOXfz9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_85720f4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85720f4b122ff936549e03075651eade1a8a381ac2ef79869d4c09c5c89ea94e"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-09-26 00:24:40"
  condition:
    hash.sha256(0, filesize) == "85720f4b122ff936549e03075651eade1a8a381ac2ef79869d4c09c5c89ea94e"
}
```

### Sample 83: `8c8d7a7d186b9be1`

| Field | Value |
|---|---|
| SHA-256 | `8c8d7a7d186b9be17dde465d8dbbb8cf5bf02ac22e3418a82743d8db88413df4` |
| Family label | `Mirai` |
| File name | `stub.armv7` |
| File type | `elf` |
| First seen | `2026-09-26 00:24:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef457bff664d26cded73c0d6904c775b` |
| SHA-1 | `c925c96b1276c55d378df691708033cb2f8ac061` |
| SHA-256 | `8c8d7a7d186b9be17dde465d8dbbb8cf5bf02ac22e3418a82743d8db88413df4` |
| SHA3-384 | `c48f00dc9c28bf9f9e6a0b1ccf65d5bef92e58fd44a22f28b4b4e4ecc0ddbcee469cfcc5615a5e0054bf89ef9fb92005` |
| TLSH | `T187D44A55F8809F63C9C52A36F64E826833274779C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiK:YCp7mXtni6aBh321eSiVWKl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_8c8d7a7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c8d7a7d186b9be17dde465d8dbbb8cf5bf02ac22e3418a82743d8db88413df4"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-26 00:24:39"
  condition:
    hash.sha256(0, filesize) == "8c8d7a7d186b9be17dde465d8dbbb8cf5bf02ac22e3418a82743d8db88413df4"
}
```

### Sample 84: `4c6da38f097af893`

| Field | Value |
|---|---|
| SHA-256 | `4c6da38f097af893a122a7f24e2788a31a91c0d97b4ea24dab0aded0b97725a0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 00:19:42` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b80665895bb19a7498261aba50b0d22` |
| SHA-1 | `72ac0988b9fe4633f4a68689bac005ca8e33f2db` |
| SHA-256 | `4c6da38f097af893a122a7f24e2788a31a91c0d97b4ea24dab0aded0b97725a0` |
| SHA3-384 | `4e2bab56863c4febcf8279cdd6ec7af655fbc9b50240caa788c6429280df873731c5f9498b995944c1bc82b18fa3aa69` |
| IMPHASH | `9cd46dc61e0c4396bc0c037bbf524ed8` |
| TLSH | `T163E4E1F1368601F1F2F99D3388815A55D3F27D23AA206ADFE6A541093E63FC95E39B01` |
| SSDEEP | `12288:Y9rhf0Cw6OOcR3r9Qnkb9h6XTbhr/hxw4zpZ43s9OP:YSpR7dph6tLL4OO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_4c6da38f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6da38f097af893a122a7f24e2788a31a91c0d97b4ea24dab0aded0b97725a0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 00:19:42"
  condition:
    hash.sha256(0, filesize) == "4c6da38f097af893a122a7f24e2788a31a91c0d97b4ea24dab0aded0b97725a0"
}
```

### Sample 85: `44c8879351cfd1d3`

| Field | Value |
|---|---|
| SHA-256 | `44c8879351cfd1d3c19d8472c848ad67696dff583c5fd13f88781dc1b6e6e826` |
| Family label | `Mirai` |
| File name | `stub.armv7l` |
| File type | `elf` |
| First seen | `2026-09-26 00:17:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c9b1cabd6c41884ce4107a20ce8eb92` |
| SHA-1 | `5aa1776d296cac55b58152a4f1b0ddb4f856b8c6` |
| SHA-256 | `44c8879351cfd1d3c19d8472c848ad67696dff583c5fd13f88781dc1b6e6e826` |
| SHA3-384 | `a6bd8294ca0de8b77693e9cb147abf1a7f81a506ac0e399ae5e2e0f60c33ebaa96a0189bb9f1ec587d61d2e54074c7db` |
| TLSH | `T189D44A55F8809F63C9C52A36F64E866833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKiG:YCp7mXtni6aBh321eSiVWKH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_44c88793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44c8879351cfd1d3c19d8472c848ad67696dff583c5fd13f88781dc1b6e6e826"
    family = "Mirai"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-26 00:17:47"
  condition:
    hash.sha256(0, filesize) == "44c8879351cfd1d3c19d8472c848ad67696dff583c5fd13f88781dc1b6e6e826"
}
```

### Sample 86: `1fd7b99e9baef306`

| Field | Value |
|---|---|
| SHA-256 | `1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3` |
| Family label | `unknown` |
| File name | `1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3` |
| File type | `elf` |
| First seen | `2026-09-26 00:17:29` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `621ae7d02ae4f69b5b8c5a4b7474496e` |
| SHA-1 | `19684c1551bac2b9f66464ce2f9962b660e33618` |
| SHA-256 | `1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3` |
| SHA3-384 | `b412dfe846e73e37182375a84c4615bc4a2a2b281192b01668229b3e2711ce9a184f678cd2701cc9812e2035f957701d` |
| TLSH | `T1FB7302017F25ED0BDF100C733ADC8E9E8DB9AA5B4AABB0B569E1948F57911C9BC53304` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFWy:phNlHuBafLeBtfCzptaj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_1fd7b99e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3"
    family = "unknown"
    file_name = "1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3"
    file_type = "elf"
    first_seen = "2026-09-26 00:17:29"
  condition:
    hash.sha256(0, filesize) == "1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3"
}
```

### Sample 87: `7929485168041284`

| Field | Value |
|---|---|
| SHA-256 | `7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28` |
| Family label | `Mirai` |
| File name | `7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28` |
| File type | `elf` |
| First seen | `2026-09-26 00:17:23` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7749ea5327e7c70bb3bf4267d4274de5` |
| SHA-1 | `d78ee1d2c5816b07bf4e212a81c7a4f993f747a0` |
| SHA-256 | `7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28` |
| SHA3-384 | `acce30dce8c0538f6fee65fa9c59dfedc6309457f41c6f7fefa31f12a34f3f6cdc4becabfead68f560c9612b01a8072a` |
| TLSH | `T100242A8AFC81AF2595C526BBFE2E428A331317B8D2EB71129D145F2477CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqf:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_79294851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28"
    family = "Mirai"
    file_name = "7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28"
    file_type = "elf"
    first_seen = "2026-09-26 00:17:23"
  condition:
    hash.sha256(0, filesize) == "7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28"
}
```

### Sample 88: `83d47d7194084ccb`

| Field | Value |
|---|---|
| SHA-256 | `83d47d7194084ccb7e559f70b48c54942ce6fcaea20108cd99a77e2ea5797e66` |
| Family label | `Mirai` |
| File name | `stub.armv6l` |
| File type | `elf` |
| First seen | `2026-09-26 00:14:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `286e92cb071413bbe57661929ecbdfb2` |
| SHA-1 | `2e8ccd4de814721142753d3eb3572ae43d5944f6` |
| SHA-256 | `83d47d7194084ccb7e559f70b48c54942ce6fcaea20108cd99a77e2ea5797e66` |
| SHA3-384 | `1d1022a4289f1684ec2c41d8727b4bd407f07e58e80bf47c76bbef97197e53bf41a49cb1037f34b2994e32505504a052` |
| TLSH | `T136D44A55F8809F63C9C52A36F64E826833274778C7E7730689144B383BA7A6F0F3A645` |
| SSDEEP | `12288:F2ctKrS0XUwn67ayLtLiXRU2zzi6aNjodD6pmkVf32cgpeSa9VWKie:YCp7mXtni6aBh321eSiVWKx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_83d47d71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83d47d7194084ccb7e559f70b48c54942ce6fcaea20108cd99a77e2ea5797e66"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-26 00:14:23"
  condition:
    hash.sha256(0, filesize) == "83d47d7194084ccb7e559f70b48c54942ce6fcaea20108cd99a77e2ea5797e66"
}
```

### Sample 89: `f48f8b013584613c`

| Field | Value |
|---|---|
| SHA-256 | `f48f8b013584613ca260642e6e3cec5ec177401dca7bca407fec74680f164725` |
| Family label | `Mirai` |
| File name | `bot.arm7n` |
| File type | `elf` |
| First seen | `2026-09-26 00:14:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37f867b313723853a9a137a35c3a7ddc` |
| SHA-1 | `0a6f129dd66409d2fd3ef248a1c73ca3500b0e65` |
| SHA-256 | `f48f8b013584613ca260642e6e3cec5ec177401dca7bca407fec74680f164725` |
| SHA3-384 | `2c480362053c5545687d21ba3056ef04e3cbb099116b7d37cb614da17585b84c704daadd009af40cf6a201ff1b60d506` |
| TLSH | `T159254B54F8909F63C9D46B7AF65E82A833234778C3E7720699148B343BD7A1F0B3A645` |
| TELFHASH | `t1a1a012171044c50d46274f044ca5020100421833e8593d561f0caa00802100002188da` |
| SSDEEP | `24576:9U6qxN5SUZo+SgwCv2QX9p4WNhYix3j657yD/hGnm0:y372cDHj657yDAm0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_f48f8b01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48f8b013584613ca260642e6e3cec5ec177401dca7bca407fec74680f164725"
    family = "Mirai"
    file_name = "bot.arm7n"
    file_type = "elf"
    first_seen = "2026-09-26 00:14:22"
  condition:
    hash.sha256(0, filesize) == "f48f8b013584613ca260642e6e3cec5ec177401dca7bca407fec74680f164725"
}
```

### Sample 90: `4f76efb499c3f611`

| Field | Value |
|---|---|
| SHA-256 | `4f76efb499c3f611d28a928b0ecb07b6ecda4512284aee900db6ccce98e47499` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-26 00:14:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8af897b383f9b4ab07bb3d1a39962209` |
| SHA-1 | `a1a88ae733054977f5000f61ee1d436621fb5b10` |
| SHA-256 | `4f76efb499c3f611d28a928b0ecb07b6ecda4512284aee900db6ccce98e47499` |
| SHA3-384 | `a1b6fb6b0399d0fd8c2aa5e4091058b797bf93f25b1694dbacc02d9d1ef7d20776cd5f09e73ea8f25ba126f9a1e84ceb` |
| TLSH | `T177456C5DFD0F3C43C2CAE239DB4A83E57127B0D4D66311A336C2035DE68999DCBA295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:eI3yyaIpOlTgrNY6cyyu5fYESZJ56Shgk2g/HVT:Cqp7rxqNFF6ShgkzVT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_4f76efb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f76efb499c3f611d28a928b0ecb07b6ecda4512284aee900db6ccce98e47499"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-26 00:14:20"
  condition:
    hash.sha256(0, filesize) == "4f76efb499c3f611d28a928b0ecb07b6ecda4512284aee900db6ccce98e47499"
}
```

### Sample 91: `7bd943a401430293`

| Field | Value |
|---|---|
| SHA-256 | `7bd943a40143029342d4de9829a012eb96c2f7b11f8b4e03fcb05827e1421cd5` |
| Family label | `Mirai` |
| File name | `stub.mipsel` |
| File type | `elf` |
| First seen | `2026-09-26 00:10:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dc291a3f6a6065376ec56e2a14c6120` |
| SHA-1 | `17e8f97987e880210075b95b6a7d59cbfe715f5e` |
| SHA-256 | `7bd943a40143029342d4de9829a012eb96c2f7b11f8b4e03fcb05827e1421cd5` |
| SHA3-384 | `402fc2725f74938d562b045ad89cd758e3208ea003754abb7e62373ed0a7abb82e73799ce38b172bb8b3049d19b80aa8` |
| TLSH | `T1E6F45B07FF815FEBC09FCD30852EC31721E9D48656C1A62A72FC4A8CBA5D6694BE3494` |
| SSDEEP | `12288:cAsRZePvWEwcj1b4D7QAEjYHZ6fxd8mg2cSAH07FFMk/mKsuSxzOTl1aplHPPhGb:GZwv1jJ4/9UZnQ28N+0JTxy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_7bd943a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bd943a40143029342d4de9829a012eb96c2f7b11f8b4e03fcb05827e1421cd5"
    family = "Mirai"
    file_name = "stub.mipsel"
    file_type = "elf"
    first_seen = "2026-09-26 00:10:50"
  condition:
    hash.sha256(0, filesize) == "7bd943a40143029342d4de9829a012eb96c2f7b11f8b4e03fcb05827e1421cd5"
}
```

### Sample 92: `15e04b5c91bf4962`

| Field | Value |
|---|---|
| SHA-256 | `15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f` |
| Family label | `VShell` |
| File name | `15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f.exe` |
| File type | `exe` |
| First seen | `2026-09-26 00:09:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59121e38473c690956cce8a0bcbf71e2` |
| SHA-1 | `0030732af9123c70c39455bd4011e74f486b963b` |
| SHA-256 | `15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f` |
| SHA3-384 | `fc1c92909382eaad053d5729f0f6925dccf7ec41574986ed3afee7f032c99a865503cb460130694e7be59f87cfe17790` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12A91C64170B989E7E85D81BF4D0FB8A4B919780A41C483A64338A5993E3A57BF57CB0E` |
| SSDEEP | `48:6IIF9BlQaexWgZ07An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaM/d0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_092_15e04b5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f"
    family = "VShell"
    file_name = "15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f.exe"
    file_type = "exe"
    first_seen = "2026-09-26 00:09:48"
  condition:
    hash.sha256(0, filesize) == "15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f"
}
```

### Sample 93: `0d8a798b76629336`

| Field | Value |
|---|---|
| SHA-256 | `0d8a798b76629336fa7518cdebc37f4d78a5731481c0aa7f45075104ad6a03e8` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-26 00:08:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fb2a974048bdd4b55eae0d7bafcdb91` |
| SHA-1 | `b8230ab6c4e9bdeb3c3e069c1ea864b7c7f135dd` |
| SHA-256 | `0d8a798b76629336fa7518cdebc37f4d78a5731481c0aa7f45075104ad6a03e8` |
| SHA3-384 | `d510eb6530b0caaa4ad725254c88d79c53c5a22a67203d5e5e586508ce8dbd804270f45aa730bc5edd935af643694aee` |
| TLSH | `T16E344985FB93C1F1E95B0AB0002FEB6F6F315A2A8025DA4AE7542D31EC75702961F76C` |
| TELFHASH | `t167b1aab23d7d19ed73e0a946a30f2b52ee0ad677582171f605f232d532f29429370879` |
| SSDEEP | `6144:ekMxcKE238Q1dRE4BbTsWNhbbV2XF8yEdU:ekqnJRE4BbwWNhbZOF8/dU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_0d8a798b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d8a798b76629336fa7518cdebc37f4d78a5731481c0aa7f45075104ad6a03e8"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-26 00:08:13"
  condition:
    hash.sha256(0, filesize) == "0d8a798b76629336fa7518cdebc37f4d78a5731481c0aa7f45075104ad6a03e8"
}
```

### Sample 94: `a1cd581c687e1f8d`

| Field | Value |
|---|---|
| SHA-256 | `a1cd581c687e1f8d9995d50b4200b6db4010c2c7d76b5b48642ae4ed0a55019e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-26 00:07:31` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43f14a2f33a1f7f4c60ccf995576799e` |
| SHA-1 | `44f8946a19fc76a510ad088f1cb853a12c69f395` |
| SHA-256 | `a1cd581c687e1f8d9995d50b4200b6db4010c2c7d76b5b48642ae4ed0a55019e` |
| SHA3-384 | `974540697608c015cd2acf779f8f53bd974055e459021ae9ae249692a2606f3c5283ebd3a41b03e51db726c21f7dda8a` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1ECA63348E7F505FDD0B3E478CDA24C21F772B84A4762DBDB136025AA5E236E09D3AB11` |
| SSDEEP | `196608:rf9zIkduo+u3Nzko4drZUoftl1VX4VWVTchhcHJkc8zfQuD+Ak8ePwWEvNpUSY7h:JUk4o+u3Nw/HLf31yWVTchhcHJkVzfq3` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_a1cd581c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1cd581c687e1f8d9995d50b4200b6db4010c2c7d76b5b48642ae4ed0a55019e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 00:07:31"
  condition:
    hash.sha256(0, filesize) == "a1cd581c687e1f8d9995d50b4200b6db4010c2c7d76b5b48642ae4ed0a55019e"
}
```

### Sample 95: `c1016a11e425109c`

| Field | Value |
|---|---|
| SHA-256 | `c1016a11e425109c99048f9e77102b6fcaa82086eb32387f42bb905a43291fa7` |
| Family label | `Mirai` |
| File name | `stub.amd64` |
| File type | `elf` |
| First seen | `2026-09-26 00:07:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a99e8357a6230060d97cdd53b8b8cf1e` |
| SHA-1 | `11e3d9ed1189663f57c04a574094f20948503852` |
| SHA-256 | `c1016a11e425109c99048f9e77102b6fcaa82086eb32387f42bb905a43291fa7` |
| SHA3-384 | `2118ba21d9fb2ffded7ce65afd33b91a9e54def284827d201f8c79bc67c5ab94d6a7cd9fc4acccb032b7daaf7288ee7f` |
| TLSH | `T1C9157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/O:7NP46S4QVs7l6A5Zji59k0jZz06FYRsN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_c1016a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1016a11e425109c99048f9e77102b6fcaa82086eb32387f42bb905a43291fa7"
    family = "Mirai"
    file_name = "stub.amd64"
    file_type = "elf"
    first_seen = "2026-09-26 00:07:25"
  condition:
    hash.sha256(0, filesize) == "c1016a11e425109c99048f9e77102b6fcaa82086eb32387f42bb905a43291fa7"
}
```

### Sample 96: `43c3e818d7605115`

| Field | Value |
|---|---|
| SHA-256 | `43c3e818d7605115c65ac208b0113ab9e7e8121a002002e1fa3213e7456b3356` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-26 00:07:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `814bd7e4c678e1dd54557057600f40f5` |
| SHA-1 | `a205b57cb1081d36c3c4c003b62157da3f737818` |
| SHA-256 | `43c3e818d7605115c65ac208b0113ab9e7e8121a002002e1fa3213e7456b3356` |
| SHA3-384 | `c7ff378504742088e5203d9e38ad48414246c59ed87a9e9395b24ed7f86a29999b43b90d5d38033e7400cb1213023000` |
| TLSH | `T12BC3125D2E46AF26F57818B61C2267E0E1E0C77ECD0C06C99B1AB359FDB8950375CA83` |
| SSDEEP | `3072:EUf4IvFVQ1MGuRPCGswY5mM3kYDrOTjw/7L8wY/youtY:lAIvpGuRQvmMlDrOw8wY6oSY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_43c3e818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43c3e818d7605115c65ac208b0113ab9e7e8121a002002e1fa3213e7456b3356"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-26 00:07:23"
  condition:
    hash.sha256(0, filesize) == "43c3e818d7605115c65ac208b0113ab9e7e8121a002002e1fa3213e7456b3356"
}
```

### Sample 97: `01de6c11916c6222`

| Field | Value |
|---|---|
| SHA-256 | `01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017` |
| Family label | `Mirai` |
| File name | `01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017.elf` |
| File type | `elf` |
| First seen | `2026-09-26 00:04:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5aadacb0aca9f375c65496dd0daef9d4` |
| SHA-1 | `b34f0ebfbd924572360718e8ad85103d26d793c5` |
| SHA-256 | `01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017` |
| SHA3-384 | `39f1cc58c730501cd60e4c6ffd3a04a123b0f28b1f9259f67e2c4537b9995c6bccfc85b58a8d9cc304a8b11a6b8f1193` |
| TLSH | `T179124147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5vlTTej6TNJ9V0Nddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTzTTfTpVsdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_01de6c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017"
    family = "Mirai"
    file_name = "01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017.elf"
    file_type = "elf"
    first_seen = "2026-09-26 00:04:53"
  condition:
    hash.sha256(0, filesize) == "01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017"
}
```

### Sample 98: `6c87ad5723f2c0a0`

| Field | Value |
|---|---|
| SHA-256 | `6c87ad5723f2c0a0b0e38364dff736c3e2a2bad110a56655bcda6b5198c7b63d` |
| Family label | `Mirai` |
| File name | `stub.mips64` |
| File type | `elf` |
| First seen | `2026-09-26 00:03:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa8183b6a5f79286f95c8647757a2e06` |
| SHA-1 | `6f2a39b34af1a812fa2118a72ae8ff7259db7735` |
| SHA-256 | `6c87ad5723f2c0a0b0e38364dff736c3e2a2bad110a56655bcda6b5198c7b63d` |
| SHA3-384 | `ae218ff04379cb16bad2642d4b4413a0b1a200d5a16dd78f7ba7ab3b1db7557c3be1cebff985a0d35ff5f8d3cf0b8858` |
| TLSH | `T1C8F48D273B21DF65D355D67049F3C7914AE920A20AE340D6B2A8C3287E6172D2D9FFE4` |
| SSDEEP | `12288:4EO7hT7XQRW4tWl9B11U+bs/w7iGtgpiGGhQi3BF1PNMBHUJTxV7X:o7Vh4t+9B1do/w7iG+SQiZa0JTxx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_6c87ad57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c87ad5723f2c0a0b0e38364dff736c3e2a2bad110a56655bcda6b5198c7b63d"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-26 00:03:57"
  condition:
    hash.sha256(0, filesize) == "6c87ad5723f2c0a0b0e38364dff736c3e2a2bad110a56655bcda6b5198c7b63d"
}
```

### Sample 99: `f2f977ebf269dad3`

| Field | Value |
|---|---|
| SHA-256 | `f2f977ebf269dad31035e38d00ae9ee59fa3d9896cb8e207c7c4b84c72c419ff` |
| Family label | `Mirai` |
| File name | `bot.aarch64_be` |
| File type | `elf` |
| First seen | `2026-09-26 00:03:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a96ae0e4a96145b3b69d6d76b2c261a6` |
| SHA-1 | `5e8c1fa45d48e77e498351780e967df2942b1b40` |
| SHA-256 | `f2f977ebf269dad31035e38d00ae9ee59fa3d9896cb8e207c7c4b84c72c419ff` |
| SHA3-384 | `3ca57aefef6c86ac31f7731b7fa624a542f165c37638b69a76b6157238bb3c3ec0db956beed14f39e8bfcb0dbab2b184` |
| TLSH | `T11D456C5DFD0F3C43C2CAE239DB4A83E57127B0D4D66311A336C2035DE68999DCBA295A` |
| TELFHASH | `t193b012071484c50c45779b514ca5034910419833e85b3e962f0cfa40402100803488ea` |
| SSDEEP | `24576:eI3yyaIpOlTgrNY6cyyu5fYESZJ56Shgk2g/HVQ:Cqp7rxqNFF6ShgkzVQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_f2f977eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2f977ebf269dad31035e38d00ae9ee59fa3d9896cb8e207c7c4b84c72c419ff"
    family = "Mirai"
    file_name = "bot.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-26 00:03:55"
  condition:
    hash.sha256(0, filesize) == "f2f977ebf269dad31035e38d00ae9ee59fa3d9896cb8e207c7c4b84c72c419ff"
}
```

### Sample 100: `65c1c1a30e7bb817`

| Field | Value |
|---|---|
| SHA-256 | `65c1c1a30e7bb8173b17fca69be16c0b81f94d08b3d4d88b66c1d00d4079124b` |
| Family label | `Mirai` |
| File name | `bot.x86-64` |
| File type | `elf` |
| First seen | `2026-09-25 23:49:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c19b136a9c51a54827396672d5b7491` |
| SHA-1 | `86c036ccd0b2561f7ef1c7b4c0431bcdca814d85` |
| SHA-256 | `65c1c1a30e7bb8173b17fca69be16c0b81f94d08b3d4d88b66c1d00d4079124b` |
| SHA3-384 | `b56eae24ffd382f115f6dd05419e22751649a86eb0d2202e23c37ca4f040ebf6ce3b3e870ad3396cca99dfc636ed4633` |
| TLSH | `T1E3355C5BB6A374BCC157C830879BDA62BD35B46502226E7BB5C4CB302E26E701719F72` |
| TELFHASH | `t1e4e18b784ff934b866d6da10b312f1754b331427a6ed36b42a22ad94ef40fc14d62c2b` |
| SSDEEP | `24576:GHBjjBSS46nHS60F1qhB8/eJViDRj5Soiq8Utq1cfd:qjQS46nQqheecRdSoiUEOfd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_65c1c1a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65c1c1a30e7bb8173b17fca69be16c0b81f94d08b3d4d88b66c1d00d4079124b"
    family = "Mirai"
    file_name = "bot.x86-64"
    file_type = "elf"
    first_seen = "2026-09-25 23:49:01"
  condition:
    hash.sha256(0, filesize) == "65c1c1a30e7bb8173b17fca69be16c0b81f94d08b3d4d88b66c1d00d4079124b"
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
 * Generated: 2026-09-26T05:08:14.774909+00:00
 */

rule MalwareBazaar_Mirai_001_cab97645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab97645f8ecf0f472ad0b32a35bb97c7261d704a25642ec7a8fee4fd8045ac2"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-26 04:58:37"
  condition:
    hash.sha256(0, filesize) == "cab97645f8ecf0f472ad0b32a35bb97c7261d704a25642ec7a8fee4fd8045ac2"
}

rule MalwareBazaar_Mirai_002_86b55e10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86b55e10570fb781814109cc2a191ed48f3ac9a59a3cc1aaa3da47b3c469cc00"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-26 04:55:23"
  condition:
    hash.sha256(0, filesize) == "86b55e10570fb781814109cc2a191ed48f3ac9a59a3cc1aaa3da47b3c469cc00"
}

rule MalwareBazaar_Mirai_003_84d4ea5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d4ea5df3286d493c6774bee44220eb5b00e3a114ca4242a9e9a9fdd5da4525"
    family = "Mirai"
    file_name = "bot.armv5tel"
    file_type = "elf"
    first_seen = "2026-09-26 04:55:21"
  condition:
    hash.sha256(0, filesize) == "84d4ea5df3286d493c6774bee44220eb5b00e3a114ca4242a9e9a9fdd5da4525"
}

rule MalwareBazaar_Mirai_004_52b787aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52b787aa76d8318a8603092e2c35d1ab946bab1ccb1dbc34c998406d5ccaf72a"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-26 04:51:33"
  condition:
    hash.sha256(0, filesize) == "52b787aa76d8318a8603092e2c35d1ab946bab1ccb1dbc34c998406d5ccaf72a"
}

rule MalwareBazaar_Mirai_005_8d83c03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d83c03f3f7ecc1f5959777509e50be9af4dd026753136a453783ad011b13df4"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-26 04:48:19"
  condition:
    hash.sha256(0, filesize) == "8d83c03f3f7ecc1f5959777509e50be9af4dd026753136a453783ad011b13df4"
}

rule MalwareBazaar_Mirai_006_a3c964b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c964b776312cfe37275cd15b2bc08473b9f0326e24a7d4519285c4fcdf7b6a"
    family = "Mirai"
    file_name = "stub.i386"
    file_type = "elf"
    first_seen = "2026-09-26 04:44:37"
  condition:
    hash.sha256(0, filesize) == "a3c964b776312cfe37275cd15b2bc08473b9f0326e24a7d4519285c4fcdf7b6a"
}

rule MalwareBazaar_Mirai_007_21f8dbfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21f8dbfdfd6806c4f1c882ebf6f53bd147ba1b7011a4528d9a1fe3506de141bc"
    family = "Mirai"
    file_name = "bot.i586"
    file_type = "elf"
    first_seen = "2026-09-26 04:44:35"
  condition:
    hash.sha256(0, filesize) == "21f8dbfdfd6806c4f1c882ebf6f53bd147ba1b7011a4528d9a1fe3506de141bc"
}

rule MalwareBazaar_Mirai_008_eb0cd52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb0cd52a079f83a68b9505637d83c49efd6826962b82c654e46405ed59ea5d6c"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-26 04:44:33"
  condition:
    hash.sha256(0, filesize) == "eb0cd52a079f83a68b9505637d83c49efd6826962b82c654e46405ed59ea5d6c"
}

rule MalwareBazaar_Mirai_009_16d7ee5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16d7ee5d4727b276ba3dc51229f0a0897dd1a88fee5b3f2b172f181b58c8768b"
    family = "Mirai"
    file_name = "stub.x86-64"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:20"
  condition:
    hash.sha256(0, filesize) == "16d7ee5d4727b276ba3dc51229f0a0897dd1a88fee5b3f2b172f181b58c8768b"
}

rule MalwareBazaar_Mirai_010_3627bbf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3627bbf4c4bcb835fc728173781f84211e57300318a6beaa13f64116a18c14d9"
    family = "Mirai"
    file_name = "bot.x64"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:18"
  condition:
    hash.sha256(0, filesize) == "3627bbf4c4bcb835fc728173781f84211e57300318a6beaa13f64116a18c14d9"
}

rule MalwareBazaar_Mirai_011_8f85a62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f85a62cad85d46d212461252690f9728f194df53a24983743bd26b3778f889e"
    family = "Mirai"
    file_name = "bot.i486"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:16"
  condition:
    hash.sha256(0, filesize) == "8f85a62cad85d46d212461252690f9728f194df53a24983743bd26b3778f889e"
}

rule MalwareBazaar_Mirai_012_93ae3ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93ae3ef0392e007e3615aeba32c1a35adc07193dbce66de0519864ec8843db5d"
    family = "Mirai"
    file_name = "bot.i386"
    file_type = "elf"
    first_seen = "2026-09-26 04:41:15"
  condition:
    hash.sha256(0, filesize) == "93ae3ef0392e007e3615aeba32c1a35adc07193dbce66de0519864ec8843db5d"
}

rule MalwareBazaar_Mirai_013_47a13f49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47a13f49ae346a6a67679e6a3fb56ddd123f4e67d4e590897694405c6b5f5afc"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-26 04:37:41"
  condition:
    hash.sha256(0, filesize) == "47a13f49ae346a6a67679e6a3fb56ddd123f4e67d4e590897694405c6b5f5afc"
}

rule MalwareBazaar_Mirai_014_f4f1e022
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f1e022e1c0251837c70a9316791076fb3d4039f822c9d00c6ecc1b44f0bff5"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-26 04:37:39"
  condition:
    hash.sha256(0, filesize) == "f4f1e022e1c0251837c70a9316791076fb3d4039f822c9d00c6ecc1b44f0bff5"
}

rule MalwareBazaar_Mirai_015_1357eddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1357eddc2b6c22d696e9fff43e1b6c837b455e5d981a9ef86bdc051d5746b036"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-26 04:28:19"
  condition:
    hash.sha256(0, filesize) == "1357eddc2b6c22d696e9fff43e1b6c837b455e5d981a9ef86bdc051d5746b036"
}

rule MalwareBazaar_Mirai_016_99859b28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99859b2887aa8d3b9433047e15a4f48e038aee82dbac896ac6c37d274e12ae94"
    family = "Mirai"
    file_name = "bot.armv8"
    file_type = "elf"
    first_seen = "2026-09-26 04:27:42"
  condition:
    hash.sha256(0, filesize) == "99859b2887aa8d3b9433047e15a4f48e038aee82dbac896ac6c37d274e12ae94"
}

rule MalwareBazaar_Mirai_017_78a5f7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a5f7a55c4d6386e87af0993f634519d2d6c7494ba728db3abd33895b72eeff"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-26 04:27:40"
  condition:
    hash.sha256(0, filesize) == "78a5f7a55c4d6386e87af0993f634519d2d6c7494ba728db3abd33895b72eeff"
}

rule MalwareBazaar_Mirai_018_de8482f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de8482f9d7a9f378b610b934613b2fe2d1f3a3a0d9a0c247b5233aa8a5886142"
    family = "Mirai"
    file_name = "bot.amd64"
    file_type = "elf"
    first_seen = "2026-09-26 04:27:39"
  condition:
    hash.sha256(0, filesize) == "de8482f9d7a9f378b610b934613b2fe2d1f3a3a0d9a0c247b5233aa8a5886142"
}

rule MalwareBazaar_Mirai_019_5bb258c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb258c9527684f86673d35ff2c8ef03e5530d4582162b967d9c5398c18e9afa"
    family = "Mirai"
    file_name = "bot.mips64el"
    file_type = "elf"
    first_seen = "2026-09-26 04:24:19"
  condition:
    hash.sha256(0, filesize) == "5bb258c9527684f86673d35ff2c8ef03e5530d4582162b967d9c5398c18e9afa"
}

rule MalwareBazaar_Mirai_020_154a3fbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "154a3fbc2715a142d4d541165d961bbe6a39be00c227d77a96a5ab17c31bf482"
    family = "Mirai"
    file_name = "stub.i586"
    file_type = "elf"
    first_seen = "2026-09-26 04:24:18"
  condition:
    hash.sha256(0, filesize) == "154a3fbc2715a142d4d541165d961bbe6a39be00c227d77a96a5ab17c31bf482"
}

rule MalwareBazaar_unknown_021_37756a23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604"
    family = "unknown"
    file_name = "37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604"
    file_type = "elf"
    first_seen = "2026-09-26 04:18:05"
  condition:
    hash.sha256(0, filesize) == "37756a23cb3099fd560dc4e03725b5f4ce45fec7529eb70d36b5a1077fd86604"
}

rule MalwareBazaar_Mirai_022_41a2f6c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d"
    family = "Mirai"
    file_name = "41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d"
    file_type = "elf"
    first_seen = "2026-09-26 04:17:58"
  condition:
    hash.sha256(0, filesize) == "41a2f6c2e4b60261e85c933e6c1242a02126862566139076dcf5b2c45c0cc89d"
}

rule MalwareBazaar_PythonStealer_023_b24cb5bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b24cb5bd4cc125fd92d9fa8301d23012fcbbb9b7962ebb7cbcd3f932854b7ca7"
    family = "PythonStealer"
    file_name = "load.exe"
    file_type = "exe"
    first_seen = "2026-09-26 03:29:22"
  condition:
    hash.sha256(0, filesize) == "b24cb5bd4cc125fd92d9fa8301d23012fcbbb9b7962ebb7cbcd3f932854b7ca7"
}

rule MalwareBazaar_Mirai_024_abfdb30a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195"
    family = "Mirai"
    file_name = "abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195"
    file_type = "elf"
    first_seen = "2026-09-26 03:18:18"
  condition:
    hash.sha256(0, filesize) == "abfdb30a698e7cbd617f0ef01071ea335572dee422cb190560b3d897c105b195"
}

rule MalwareBazaar_Mirai_025_5640640a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5640640a625e819189af4b0cfaa20280be6526b40032d8a5b8f0d58abed8fe23"
    family = "Mirai"
    file_name = "stub.mips"
    file_type = "elf"
    first_seen = "2026-09-26 03:14:23"
  condition:
    hash.sha256(0, filesize) == "5640640a625e819189af4b0cfaa20280be6526b40032d8a5b8f0d58abed8fe23"
}

rule MalwareBazaar_unknown_026_b43ad7b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b43ad7b84d22f811e29dda2c880b8acab9455faf6babd6641651a7b1c01246db"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 03:13:04"
  condition:
    hash.sha256(0, filesize) == "b43ad7b84d22f811e29dda2c880b8acab9455faf6babd6641651a7b1c01246db"
}

rule MalwareBazaar_unknown_027_7e8e91c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b"
    family = "unknown"
    file_name = "7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b.exe"
    file_type = "exe"
    first_seen = "2026-09-26 03:10:54"
  condition:
    hash.sha256(0, filesize) == "7e8e91c4a91cdb8f94f85ef7bd1c96b4f8acf9505767cb4295c15b8305b1293b"
}

rule MalwareBazaar_ConnectWise_028_8f45c730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca"
    family = "ConnectWise"
    file_name = "8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca.msi"
    file_type = "msi"
    first_seen = "2026-09-26 03:10:29"
  condition:
    hash.sha256(0, filesize) == "8f45c730d72bfdc047ef5aeba58e12641e88d983c0938ad3fcf9c61219b87eca"
}

rule MalwareBazaar_unknown_029_745bcfee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06"
    family = "unknown"
    file_name = "745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06.bin"
    file_type = "unknown"
    first_seen = "2026-09-26 03:10:02"
  condition:
    hash.sha256(0, filesize) == "745bcfeebdb96a601a4d51786d8b7ae61df4463d9379d51dd8553de859a43b06"
}

rule MalwareBazaar_Mirai_030_d21734f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d21734f1c87a44eb9610fb14c2cf8016bdc49032851877b7fc2c0257a9e83adb"
    family = "Mirai"
    file_name = "stub.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-26 02:56:44"
  condition:
    hash.sha256(0, filesize) == "d21734f1c87a44eb9610fb14c2cf8016bdc49032851877b7fc2c0257a9e83adb"
}

rule MalwareBazaar_unknown_031_09f4692a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09f4692a8a209c454c20eb5010b0b41efac4648dcdf2f6b0d149fbbc9e801a8c"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-09-26 02:51:07"
  condition:
    hash.sha256(0, filesize) == "09f4692a8a209c454c20eb5010b0b41efac4648dcdf2f6b0d149fbbc9e801a8c"
}

rule MalwareBazaar_Mirai_032_c9455e29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78"
    family = "Mirai"
    file_name = "c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78"
    file_type = "elf"
    first_seen = "2026-09-26 02:19:21"
  condition:
    hash.sha256(0, filesize) == "c9455e29708db34f4ea87e250100d39fff5d6c51d6dd843675ef3b4f8f29dd78"
}

rule MalwareBazaar_unknown_033_dcda3743
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcda374329eb90c9065b2886654d14f2ab4533b8817389541fe621274f96af93"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 02:13:40"
  condition:
    hash.sha256(0, filesize) == "dcda374329eb90c9065b2886654d14f2ab4533b8817389541fe621274f96af93"
}

rule MalwareBazaar_VShell_034_4be29060
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9"
    family = "VShell"
    file_name = "4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9.exe"
    file_type = "exe"
    first_seen = "2026-09-26 02:05:04"
  condition:
    hash.sha256(0, filesize) == "4be29060aa863f9baf0707d723b1284f920456cacf39841b79bd3ab867bf04c9"
}

rule MalwareBazaar_QuasarRAT_035_ff4e059d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff4e059d3f8c4285958c7dcddb1ce9084ea490e8269c514fbc2d3a1403914c9c"
    family = "QuasarRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:44:30"
  condition:
    hash.sha256(0, filesize) == "ff4e059d3f8c4285958c7dcddb1ce9084ea490e8269c514fbc2d3a1403914c9c"
}

rule MalwareBazaar_unknown_036_5946e502
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5946e502f0f7bee0f29b829c7f5b72d584e90188de8863d3713fb6c503ac778c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:44:21"
  condition:
    hash.sha256(0, filesize) == "5946e502f0f7bee0f29b829c7f5b72d584e90188de8863d3713fb6c503ac778c"
}

rule MalwareBazaar_Prometei_037_49cf9dba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23"
    family = "Prometei"
    file_name = "49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23"
    file_type = "elf"
    first_seen = "2026-09-26 01:37:01"
  condition:
    hash.sha256(0, filesize) == "49cf9dbaef457a2cba724ed3fc3bed08951103a363dc819dda896ebb4b89ed23"
}

rule MalwareBazaar_Mirai_038_8848de61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2"
    family = "Mirai"
    file_name = "8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2"
    file_type = "elf"
    first_seen = "2026-09-26 01:17:18"
  condition:
    hash.sha256(0, filesize) == "8848de61718a3144e0befa74064092215ef2432c7f2d10eaa0eaaaebf8d7dbe2"
}

rule MalwareBazaar_Mirai_039_673b8bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31"
    family = "Mirai"
    file_name = "673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31"
    file_type = "elf"
    first_seen = "2026-09-26 01:17:13"
  condition:
    hash.sha256(0, filesize) == "673b8bcf8b836f02f7f185a3628248eb40285d6124bc70b278566f6e5c33fa31"
}

rule MalwareBazaar_unknown_040_34f683a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34f683a56d01c12eb8dba9117402ecee7a8a04d740e65c4a46d2341fe1b52ee5"
    family = "unknown"
    file_name = "macho_34f683a56d01.bin"
    file_type = "macho"
    first_seen = "2026-09-26 01:15:17"
  condition:
    hash.sha256(0, filesize) == "34f683a56d01c12eb8dba9117402ecee7a8a04d740e65c4a46d2341fe1b52ee5"
}

rule MalwareBazaar_unknown_041_576b1934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576b1934db203a45e0ba66325f99761b92256069adfe513aaf29b73ff473e994"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:11:21"
  condition:
    hash.sha256(0, filesize) == "576b1934db203a45e0ba66325f99761b92256069adfe513aaf29b73ff473e994"
}

rule MalwareBazaar_unknown_042_d418ac6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d418ac6af6706816e0c23e60c24cb29925026ee193e4655648025d7ccd7c900b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 01:11:01"
  condition:
    hash.sha256(0, filesize) == "d418ac6af6706816e0c23e60c24cb29925026ee193e4655648025d7ccd7c900b"
}

rule MalwareBazaar_Mirai_043_138fa81c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "138fa81c9e10aa77a2c7b27c5eeac03cee9af14b29f599679980e451fa6788c3"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-26 01:06:39"
  condition:
    hash.sha256(0, filesize) == "138fa81c9e10aa77a2c7b27c5eeac03cee9af14b29f599679980e451fa6788c3"
}

rule MalwareBazaar_Mirai_044_026fd2ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "026fd2ca1011f46ecf8513ef9e7c74b5e7b9a0fca4dc818fecc5da4a20942b26"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-26 01:06:35"
  condition:
    hash.sha256(0, filesize) == "026fd2ca1011f46ecf8513ef9e7c74b5e7b9a0fca4dc818fecc5da4a20942b26"
}

rule MalwareBazaar_Mirai_045_c552d114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c552d114f51a0c106c51c84997e884249faf4bb26177069dadb5cdfdf3acbedf"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-26 01:06:33"
  condition:
    hash.sha256(0, filesize) == "c552d114f51a0c106c51c84997e884249faf4bb26177069dadb5cdfdf3acbedf"
}

rule MalwareBazaar_unknown_046_67dbba47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67dbba47c2a15f0f1d004923a41f2ee8e912405cb0decff0dd9d4ae268df692c"
    family = "unknown"
    file_name = "SpiralCircus_Setup.exe"
    file_type = "exe"
    first_seen = "2026-09-26 01:06:08"
  condition:
    hash.sha256(0, filesize) == "67dbba47c2a15f0f1d004923a41f2ee8e912405cb0decff0dd9d4ae268df692c"
}

rule MalwareBazaar_Mirai_047_e0d329a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d329a3dec10ae8ecd3ea90593f3e329c0629ebda75ab2316aafc34dfd0c91e"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:32"
  condition:
    hash.sha256(0, filesize) == "e0d329a3dec10ae8ecd3ea90593f3e329c0629ebda75ab2316aafc34dfd0c91e"
}

rule MalwareBazaar_Mirai_048_8027010d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8027010d89c5f20498bb64cc31c920d13e547186084c83d3c71b8ce1ccdc8a49"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:30"
  condition:
    hash.sha256(0, filesize) == "8027010d89c5f20498bb64cc31c920d13e547186084c83d3c71b8ce1ccdc8a49"
}

rule MalwareBazaar_Mirai_049_5e871e0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e871e0b378818f970f9c66a04ca0edb9ecfa9d9cb3f4c84d5d450774530a5b0"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:29"
  condition:
    hash.sha256(0, filesize) == "5e871e0b378818f970f9c66a04ca0edb9ecfa9d9cb3f4c84d5d450774530a5b0"
}

rule MalwareBazaar_Mirai_050_18841145
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18841145b15bdb567cb82218dc6785248a4732df508777d6316af925e5c586ed"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-26 01:05:27"
  condition:
    hash.sha256(0, filesize) == "18841145b15bdb567cb82218dc6785248a4732df508777d6316af925e5c586ed"
}

rule MalwareBazaar_unknown_051_12e48cbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529"
    family = "unknown"
    file_name = "12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529.bin"
    file_type = "exe"
    first_seen = "2026-09-26 01:03:14"
  condition:
    hash.sha256(0, filesize) == "12e48cbda8754709214b9bca2656add17cded1e2494280a46c9a714a98e8b529"
}

rule MalwareBazaar_unknown_052_eb034f14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363"
    family = "unknown"
    file_name = "eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363.bin"
    file_type = "exe"
    first_seen = "2026-09-26 01:03:11"
  condition:
    hash.sha256(0, filesize) == "eb034f148ad141e8ffd40f9107649caf0a923c2f988e943f0163fa0fa52b5363"
}

rule MalwareBazaar_unknown_053_3d8a22b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7"
    family = "unknown"
    file_name = "3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7.bin"
    file_type = "exe"
    first_seen = "2026-09-26 01:03:09"
  condition:
    hash.sha256(0, filesize) == "3d8a22b4d6c4b43688658788facc7373c284d61fbc1815e988d3ebbc55676ff7"
}

rule MalwareBazaar_Mirai_054_06a69232
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06a692324852555d671621a35281899d0809628c36ee28a43ad2ddcf156f813e"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:57"
  condition:
    hash.sha256(0, filesize) == "06a692324852555d671621a35281899d0809628c36ee28a43ad2ddcf156f813e"
}

rule MalwareBazaar_Mirai_055_00eb5f7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00eb5f7e22e90c0caf47f2434b7f866f415f61a190f94da452aaf64df03aaa47"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:52"
  condition:
    hash.sha256(0, filesize) == "00eb5f7e22e90c0caf47f2434b7f866f415f61a190f94da452aaf64df03aaa47"
}

rule MalwareBazaar_Mirai_056_51e8cc5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51e8cc5e0dcd6dec03ac00bf082dcc8cbe757df2bb581f4ec5ca7be9aa5dd7eb"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:48"
  condition:
    hash.sha256(0, filesize) == "51e8cc5e0dcd6dec03ac00bf082dcc8cbe757df2bb581f4ec5ca7be9aa5dd7eb"
}

rule MalwareBazaar_Mirai_057_9d899b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d899b1d90a38c290da074e516c657738b87d99ffaafb931a6eb9c72cff1d5b0"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:05"
  condition:
    hash.sha256(0, filesize) == "9d899b1d90a38c290da074e516c657738b87d99ffaafb931a6eb9c72cff1d5b0"
}

rule MalwareBazaar_Mirai_058_19db829e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19db829e93bfd90e0818900fab52c7e538f9aefd768a57a0054394b9f6501a6a"
    family = "Mirai"
    file_name = "sora.x86"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:04"
  condition:
    hash.sha256(0, filesize) == "19db829e93bfd90e0818900fab52c7e538f9aefd768a57a0054394b9f6501a6a"
}

rule MalwareBazaar_Mirai_059_118dce2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "118dce2dc67733f762aa1c0961cb2c0b4d83735bc9c9a099fc545ef4fb3f2a50"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:02"
  condition:
    hash.sha256(0, filesize) == "118dce2dc67733f762aa1c0961cb2c0b4d83735bc9c9a099fc545ef4fb3f2a50"
}

rule MalwareBazaar_Mirai_060_f839d7ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f839d7ea8cea6fa2bac1d04edf7f7f0caac562dee9ca8b557dc06d914f4c6d4c"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-09-26 01:02:00"
  condition:
    hash.sha256(0, filesize) == "f839d7ea8cea6fa2bac1d04edf7f7f0caac562dee9ca8b557dc06d914f4c6d4c"
}

rule MalwareBazaar_Mirai_061_2226ab1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2226ab1b193ea6135e193431d1aae563ea7638bba39ac63a6268cfc73bb84dbf"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:59"
  condition:
    hash.sha256(0, filesize) == "2226ab1b193ea6135e193431d1aae563ea7638bba39ac63a6268cfc73bb84dbf"
}

rule MalwareBazaar_Mirai_062_b9e699f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9e699f2452858a725e308303c5829c206813a39603480d366ba83344754354f"
    family = "Mirai"
    file_name = "sora.arm5"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:57"
  condition:
    hash.sha256(0, filesize) == "b9e699f2452858a725e308303c5829c206813a39603480d366ba83344754354f"
}

rule MalwareBazaar_Mirai_063_e4afc15b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4afc15b78f26c3cd1fa5a03daf005bf8bc8f627947a8a38afa4d8aac4b4856b"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:56"
  condition:
    hash.sha256(0, filesize) == "e4afc15b78f26c3cd1fa5a03daf005bf8bc8f627947a8a38afa4d8aac4b4856b"
}

rule MalwareBazaar_Mirai_064_3032ac2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3032ac2b1cac644b787d2ebdd3653adc79e1b25779a020e6a1bc123059362e39"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:54"
  condition:
    hash.sha256(0, filesize) == "3032ac2b1cac644b787d2ebdd3653adc79e1b25779a020e6a1bc123059362e39"
}

rule MalwareBazaar_Mirai_065_785bb0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "785bb0a6d18554716328ad01afbfcd1d14880a9beaa17bb4e21254408677ade3"
    family = "Mirai"
    file_name = "sora.m68k"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:53"
  condition:
    hash.sha256(0, filesize) == "785bb0a6d18554716328ad01afbfcd1d14880a9beaa17bb4e21254408677ade3"
}

rule MalwareBazaar_Mirai_066_d08708e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d08708e0a752b6e8120c2bb83c926b8af848a73bcd34e5e1c7073144cee98b77"
    family = "Mirai"
    file_name = "sora.mips"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:51"
  condition:
    hash.sha256(0, filesize) == "d08708e0a752b6e8120c2bb83c926b8af848a73bcd34e5e1c7073144cee98b77"
}

rule MalwareBazaar_Mirai_067_7992dd0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7992dd0aa384aaceab957f49763b863c8ff623300f155a26301a27121fddbfec"
    family = "Mirai"
    file_name = "sora.sh4"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:50"
  condition:
    hash.sha256(0, filesize) == "7992dd0aa384aaceab957f49763b863c8ff623300f155a26301a27121fddbfec"
}

rule MalwareBazaar_Mirai_068_0c8f55b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c8f55b3624744ed83e804240dfbc52d9e2a7c2bca8bfabf0930be699d6d52df"
    family = "Mirai"
    file_name = "sora.arm6"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:48"
  condition:
    hash.sha256(0, filesize) == "0c8f55b3624744ed83e804240dfbc52d9e2a7c2bca8bfabf0930be699d6d52df"
}

rule MalwareBazaar_Mirai_069_7c2b4575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c2b457545aad2ab304719df171448313b8e39040b91883c1dcad6b378f350bc"
    family = "Mirai"
    file_name = "sora.ppc"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:46"
  condition:
    hash.sha256(0, filesize) == "7c2b457545aad2ab304719df171448313b8e39040b91883c1dcad6b378f350bc"
}

rule MalwareBazaar_Mirai_070_316c53cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "316c53cf3e214df1268b0bfce7761a22d867f519f99fb50ededf743e6199598b"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-09-26 01:01:45"
  condition:
    hash.sha256(0, filesize) == "316c53cf3e214df1268b0bfce7761a22d867f519f99fb50ededf743e6199598b"
}

rule MalwareBazaar_unknown_071_65e5f373
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65e5f373448c5b9c628508b13bfd951ac53d656ddbba13143373292a0b3dde11"
    family = "unknown"
    file_name = "dcd"
    file_type = "exe"
    first_seen = "2026-09-26 00:39:55"
  condition:
    hash.sha256(0, filesize) == "65e5f373448c5b9c628508b13bfd951ac53d656ddbba13143373292a0b3dde11"
}

rule MalwareBazaar_unknown_072_76dbfc90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76dbfc90cc9071aecfccf8fc7a866aa4c5cc5e26a229d9ab887eee67256435b3"
    family = "unknown"
    file_name = "ការបង្ការការឆបោកតាម Telegram.com"
    file_type = "exe"
    first_seen = "2026-09-26 00:39:01"
  condition:
    hash.sha256(0, filesize) == "76dbfc90cc9071aecfccf8fc7a866aa4c5cc5e26a229d9ab887eee67256435b3"
}

rule MalwareBazaar_Mirai_073_c4e97efa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4e97efa91be535b453d9dc55d8a30376bed95c8fb5d7a8f1743cc4d3858a9dd"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-26 00:34:42"
  condition:
    hash.sha256(0, filesize) == "c4e97efa91be535b453d9dc55d8a30376bed95c8fb5d7a8f1743cc4d3858a9dd"
}

rule MalwareBazaar_Mirai_074_bd38b148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd38b14882a3f50561d87d191c9ca241d65162deba46c3016cf8deef0a6d0f94"
    family = "Mirai"
    file_name = "bot.armv7"
    file_type = "elf"
    first_seen = "2026-09-26 00:34:40"
  condition:
    hash.sha256(0, filesize) == "bd38b14882a3f50561d87d191c9ca241d65162deba46c3016cf8deef0a6d0f94"
}

rule MalwareBazaar_Mirai_075_97098330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97098330e1939d0f3b44a39b8cbdb505d79f7ca6f073191e5b314927988da87c"
    family = "Mirai"
    file_name = "stub.x64"
    file_type = "elf"
    first_seen = "2026-09-26 00:34:38"
  condition:
    hash.sha256(0, filesize) == "97098330e1939d0f3b44a39b8cbdb505d79f7ca6f073191e5b314927988da87c"
}

rule MalwareBazaar_Mirai_076_91abd176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91abd176e15c92d1aca81f74ac8a1d180db8104c9f615c96a68dd78b48a49eff"
    family = "Mirai"
    file_name = "stub.arm7n"
    file_type = "elf"
    first_seen = "2026-09-26 00:31:27"
  condition:
    hash.sha256(0, filesize) == "91abd176e15c92d1aca81f74ac8a1d180db8104c9f615c96a68dd78b48a49eff"
}

rule MalwareBazaar_Mirai_077_9642ad84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9642ad84eac95f712ecd25cc21f619acc38bd21e00e48a543df0db3908b84317"
    family = "Mirai"
    file_name = "stub.i486"
    file_type = "elf"
    first_seen = "2026-09-26 00:31:25"
  condition:
    hash.sha256(0, filesize) == "9642ad84eac95f712ecd25cc21f619acc38bd21e00e48a543df0db3908b84317"
}

rule MalwareBazaar_Mirai_078_492be805
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "492be8058dca4014eb9390b44d5bd39aa2d3fa7733c97daa2baf1b0479d00d3d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-26 00:29:23"
  condition:
    hash.sha256(0, filesize) == "492be8058dca4014eb9390b44d5bd39aa2d3fa7733c97daa2baf1b0479d00d3d"
}

rule MalwareBazaar_Mirai_079_7f6e20ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f6e20ab5e83d08108a437a704a2fa161ebec83ecf541883a62ef2314ead2505"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-26 00:28:15"
  condition:
    hash.sha256(0, filesize) == "7f6e20ab5e83d08108a437a704a2fa161ebec83ecf541883a62ef2314ead2505"
}

rule MalwareBazaar_Mirai_080_1a6598b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a6598b1751b1389dad24241b5e7592692e979a32d92031ac8d9a3114c4e1733"
    family = "Mirai"
    file_name = "stub.mpsl"
    file_type = "elf"
    first_seen = "2026-09-26 00:28:13"
  condition:
    hash.sha256(0, filesize) == "1a6598b1751b1389dad24241b5e7592692e979a32d92031ac8d9a3114c4e1733"
}

rule MalwareBazaar_Mirai_081_334a7d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "334a7d8fb058a3e599c93a5999fa1bca985c989514ade747be7e46768e54bba9"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-09-26 00:25:36"
  condition:
    hash.sha256(0, filesize) == "334a7d8fb058a3e599c93a5999fa1bca985c989514ade747be7e46768e54bba9"
}

rule MalwareBazaar_Mirai_082_85720f4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85720f4b122ff936549e03075651eade1a8a381ac2ef79869d4c09c5c89ea94e"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-09-26 00:24:40"
  condition:
    hash.sha256(0, filesize) == "85720f4b122ff936549e03075651eade1a8a381ac2ef79869d4c09c5c89ea94e"
}

rule MalwareBazaar_Mirai_083_8c8d7a7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c8d7a7d186b9be17dde465d8dbbb8cf5bf02ac22e3418a82743d8db88413df4"
    family = "Mirai"
    file_name = "stub.armv7"
    file_type = "elf"
    first_seen = "2026-09-26 00:24:39"
  condition:
    hash.sha256(0, filesize) == "8c8d7a7d186b9be17dde465d8dbbb8cf5bf02ac22e3418a82743d8db88413df4"
}

rule MalwareBazaar_unknown_084_4c6da38f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6da38f097af893a122a7f24e2788a31a91c0d97b4ea24dab0aded0b97725a0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 00:19:42"
  condition:
    hash.sha256(0, filesize) == "4c6da38f097af893a122a7f24e2788a31a91c0d97b4ea24dab0aded0b97725a0"
}

rule MalwareBazaar_Mirai_085_44c88793
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44c8879351cfd1d3c19d8472c848ad67696dff583c5fd13f88781dc1b6e6e826"
    family = "Mirai"
    file_name = "stub.armv7l"
    file_type = "elf"
    first_seen = "2026-09-26 00:17:47"
  condition:
    hash.sha256(0, filesize) == "44c8879351cfd1d3c19d8472c848ad67696dff583c5fd13f88781dc1b6e6e826"
}

rule MalwareBazaar_unknown_086_1fd7b99e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3"
    family = "unknown"
    file_name = "1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3"
    file_type = "elf"
    first_seen = "2026-09-26 00:17:29"
  condition:
    hash.sha256(0, filesize) == "1fd7b99e9baef30640086e421ce86a3b1d2e7f3c36d32ee82822ac822a58cdf3"
}

rule MalwareBazaar_Mirai_087_79294851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28"
    family = "Mirai"
    file_name = "7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28"
    file_type = "elf"
    first_seen = "2026-09-26 00:17:23"
  condition:
    hash.sha256(0, filesize) == "7929485168041284757427091a13724a67f0f92d7b1980fcd472d32c9ea7ed28"
}

rule MalwareBazaar_Mirai_088_83d47d71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83d47d7194084ccb7e559f70b48c54942ce6fcaea20108cd99a77e2ea5797e66"
    family = "Mirai"
    file_name = "stub.armv6l"
    file_type = "elf"
    first_seen = "2026-09-26 00:14:23"
  condition:
    hash.sha256(0, filesize) == "83d47d7194084ccb7e559f70b48c54942ce6fcaea20108cd99a77e2ea5797e66"
}

rule MalwareBazaar_Mirai_089_f48f8b01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48f8b013584613ca260642e6e3cec5ec177401dca7bca407fec74680f164725"
    family = "Mirai"
    file_name = "bot.arm7n"
    file_type = "elf"
    first_seen = "2026-09-26 00:14:22"
  condition:
    hash.sha256(0, filesize) == "f48f8b013584613ca260642e6e3cec5ec177401dca7bca407fec74680f164725"
}

rule MalwareBazaar_Mirai_090_4f76efb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f76efb499c3f611d28a928b0ecb07b6ecda4512284aee900db6ccce98e47499"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-26 00:14:20"
  condition:
    hash.sha256(0, filesize) == "4f76efb499c3f611d28a928b0ecb07b6ecda4512284aee900db6ccce98e47499"
}

rule MalwareBazaar_Mirai_091_7bd943a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bd943a40143029342d4de9829a012eb96c2f7b11f8b4e03fcb05827e1421cd5"
    family = "Mirai"
    file_name = "stub.mipsel"
    file_type = "elf"
    first_seen = "2026-09-26 00:10:50"
  condition:
    hash.sha256(0, filesize) == "7bd943a40143029342d4de9829a012eb96c2f7b11f8b4e03fcb05827e1421cd5"
}

rule MalwareBazaar_VShell_092_15e04b5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f"
    family = "VShell"
    file_name = "15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f.exe"
    file_type = "exe"
    first_seen = "2026-09-26 00:09:48"
  condition:
    hash.sha256(0, filesize) == "15e04b5c91bf4962d00817e8bb740d5816696bd0e959bf9726c9170d6d6ee78f"
}

rule MalwareBazaar_Mirai_093_0d8a798b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d8a798b76629336fa7518cdebc37f4d78a5731481c0aa7f45075104ad6a03e8"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-26 00:08:13"
  condition:
    hash.sha256(0, filesize) == "0d8a798b76629336fa7518cdebc37f4d78a5731481c0aa7f45075104ad6a03e8"
}

rule MalwareBazaar_unknown_094_a1cd581c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1cd581c687e1f8d9995d50b4200b6db4010c2c7d76b5b48642ae4ed0a55019e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-26 00:07:31"
  condition:
    hash.sha256(0, filesize) == "a1cd581c687e1f8d9995d50b4200b6db4010c2c7d76b5b48642ae4ed0a55019e"
}

rule MalwareBazaar_Mirai_095_c1016a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1016a11e425109c99048f9e77102b6fcaa82086eb32387f42bb905a43291fa7"
    family = "Mirai"
    file_name = "stub.amd64"
    file_type = "elf"
    first_seen = "2026-09-26 00:07:25"
  condition:
    hash.sha256(0, filesize) == "c1016a11e425109c99048f9e77102b6fcaa82086eb32387f42bb905a43291fa7"
}

rule MalwareBazaar_Mirai_096_43c3e818
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43c3e818d7605115c65ac208b0113ab9e7e8121a002002e1fa3213e7456b3356"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-26 00:07:23"
  condition:
    hash.sha256(0, filesize) == "43c3e818d7605115c65ac208b0113ab9e7e8121a002002e1fa3213e7456b3356"
}

rule MalwareBazaar_Mirai_097_01de6c11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017"
    family = "Mirai"
    file_name = "01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017.elf"
    file_type = "elf"
    first_seen = "2026-09-26 00:04:53"
  condition:
    hash.sha256(0, filesize) == "01de6c11916c6222622e2758dc17a8c59cc0ca9624a924356350e69f9259d017"
}

rule MalwareBazaar_Mirai_098_6c87ad57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c87ad5723f2c0a0b0e38364dff736c3e2a2bad110a56655bcda6b5198c7b63d"
    family = "Mirai"
    file_name = "stub.mips64"
    file_type = "elf"
    first_seen = "2026-09-26 00:03:57"
  condition:
    hash.sha256(0, filesize) == "6c87ad5723f2c0a0b0e38364dff736c3e2a2bad110a56655bcda6b5198c7b63d"
}

rule MalwareBazaar_Mirai_099_f2f977eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2f977ebf269dad31035e38d00ae9ee59fa3d9896cb8e207c7c4b84c72c419ff"
    family = "Mirai"
    file_name = "bot.aarch64_be"
    file_type = "elf"
    first_seen = "2026-09-26 00:03:55"
  condition:
    hash.sha256(0, filesize) == "f2f977ebf269dad31035e38d00ae9ee59fa3d9896cb8e207c7c4b84c72c419ff"
}

rule MalwareBazaar_Mirai_100_65c1c1a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65c1c1a30e7bb8173b17fca69be16c0b81f94d08b3d4d88b66c1d00d4079124b"
    family = "Mirai"
    file_name = "bot.x86-64"
    file_type = "elf"
    first_seen = "2026-09-25 23:49:01"
  condition:
    hash.sha256(0, filesize) == "65c1c1a30e7bb8173b17fca69be16c0b81f94d08b3d4d88b66c1d00d4079124b"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

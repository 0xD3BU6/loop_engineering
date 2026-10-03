# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-03

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 570 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 570 |
| Unique family labels | 6 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 54 |
| Mirai | 40 |
| Prometei | 2 |
| RemusStealer | 2 |
| WannaCry | 1 |
| AsyncRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 47 |
| unknown | 19 |
| exe | 11 |
| zip | 9 |
| sh | 5 |
| macho | 5 |
| js | 2 |
| pdf | 1 |
| cmd | 1 |

## Per-Sample Analysis

### Sample 1: `383f6b988e0571e0`

| Field | Value |
|---|---|
| SHA-256 | `383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9` |
| Family label | `WannaCry` |
| File name | `383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9` |
| File type | `exe` |
| First seen | `2026-10-03 05:15:24` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e3047fc96e4a267b77694aa363accb2` |
| SHA-1 | `0fd330919866404dd42eabcc1454f7fd03e9ac18` |
| SHA-256 | `383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9` |
| SHA3-384 | `3a469e1b42ad9f9437d4c2a9c7888ff5b951a47730794a2817f2b4ca8720f618e78cac7117f7a06f7dc34364a16c3523` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14336E00A33AC80BCD456423598A35E35E7B3BC565278970F5B58CB6A0E63390BF78B17` |
| SSDEEP | `6144:jIYVTH5DgSgmE9l9yUqIYVTH5DgSg8ajldktM0XXrC2QhMV9qEBLIwYQuy8DLq12:jbLgmvbLgPlu7QhMbpIMu7L5N` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_001_383f6b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9"
    family = "WannaCry"
    file_name = "383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9"
    file_type = "exe"
    first_seen = "2026-10-03 05:15:24"
  condition:
    hash.sha256(0, filesize) == "383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9"
}
```

### Sample 2: `a3da040aab40b054`

| Field | Value |
|---|---|
| SHA-256 | `a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e` |
| Family label | `unknown` |
| File name | `a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e.bin` |
| File type | `unknown` |
| First seen | `2026-10-03 04:29:47` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d116b7320e608884fe7a046e21e6ba7` |
| SHA-256 | `a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_a3da040a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e"
    family = "unknown"
    file_name = "a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e.bin"
    file_type = "unknown"
    first_seen = "2026-10-03 04:29:47"
  condition:
    hash.sha256(0, filesize) == "a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e"
}
```

### Sample 3: `0683dae34749be13`

| Field | Value |
|---|---|
| SHA-256 | `0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7` |
| Family label | `unknown` |
| File name | `0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7.bin` |
| File type | `zip` |
| First seen | `2026-10-03 04:29:43` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3a15df0186d483065f1cdd0bb2dfeeb` |
| SHA-1 | `31eddc0387a07b2ffff06454b68eadcdddae37ed` |
| SHA-256 | `0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7` |
| SHA3-384 | `d4272659168c2fabd3a14398b3d894e3ca8b62557fe9abbab081de13614ac3d05b86d54683685c547afd578e9adb5215` |
| TLSH | `T1BA152275E6A98851CE1BA1748DCEC65913C24197B314286EEF6C72A8303DEC07B72EE5` |
| SSDEEP | `24576:yO3ROQgxSC62f9wsai5PBTYqPO0uEyaEekwqBO535If:yOC621hbBTYqPnry9NwqB43E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_0683dae3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7"
    family = "unknown"
    file_name = "0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:29:43"
  condition:
    hash.sha256(0, filesize) == "0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7"
}
```

### Sample 4: `de9d9663fa7293fc`

| Field | Value |
|---|---|
| SHA-256 | `de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e` |
| Family label | `unknown` |
| File name | `de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e.bin` |
| File type | `unknown` |
| First seen | `2026-10-03 04:29:37` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `201b1329b5e0a4da9a56610617ecda8b` |
| SHA-256 | `de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_de9d9663
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e"
    family = "unknown"
    file_name = "de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e.bin"
    file_type = "unknown"
    first_seen = "2026-10-03 04:29:37"
  condition:
    hash.sha256(0, filesize) == "de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e"
}
```

### Sample 5: `2e7044f87cdbca22`

| Field | Value |
|---|---|
| SHA-256 | `2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f` |
| Family label | `unknown` |
| File name | `2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f.bin` |
| File type | `zip` |
| First seen | `2026-10-03 04:29:33` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e27edd9b83a7178f54b0004349e87232` |
| SHA-1 | `9ae89711afda81bc3fb54b1dcbc0c3c68a8e2d33` |
| SHA-256 | `2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f` |
| SHA3-384 | `9bf3e8ddf96b361cfc381a81cd0de47b79bd1a3b9272281e7939b97fbe59dc6f7b2b6f4cc75cfda1e293307ab2a57b4f` |
| TLSH | `T13F1733E71777D966A528EDA7B37464FC2040186ECEB4C94AFAF91BE841274C20E0F653` |
| SSDEEP | `393216:csaXRdKzwZc4QhGu2yHFIB5+b8QFxDkeTtLoLgkJ6n54iam4SuRh:CXRIz8QhPlkW8oSoEgkc4y4d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_2e7044f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f"
    family = "unknown"
    file_name = "2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:29:33"
  condition:
    hash.sha256(0, filesize) == "2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f"
}
```

### Sample 6: `bda14fdc645f229c`

| Field | Value |
|---|---|
| SHA-256 | `bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4` |
| Family label | `unknown` |
| File name | `bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4.bin` |
| File type | `zip` |
| First seen | `2026-10-03 04:29:26` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85834520af133e4324a6ada3857c3d71` |
| SHA-1 | `044db03ceb17449b246c65e4361f7d0c96a9a12d` |
| SHA-256 | `bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4` |
| SHA3-384 | `632acee9c1599b8213c9b2811dc3b0ac2004ffa565153c330ff0c8a2053e223035e890d9bd0d656edc9b441d69eb665e` |
| TLSH | `T16B82D1338F953923EA6C21E764DD553E1B0BE13832394484E852EFB3E32356AC29529C` |
| SSDEEP | `384:6Ux46SBDUWOHkuTVfc4fwb5d4Kb/Fr4wwJoWhcazcO46N:hoB9OHkuJ04c5OK5twJoBazc56N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_bda14fdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4"
    family = "unknown"
    file_name = "bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:29:26"
  condition:
    hash.sha256(0, filesize) == "bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4"
}
```

### Sample 7: `566b6a879e20c3d3`

| Field | Value |
|---|---|
| SHA-256 | `566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab` |
| Family label | `unknown` |
| File name | `566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab.bin` |
| File type | `zip` |
| First seen | `2026-10-03 04:28:39` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e25c957ecb49d58499def9cc333d38db` |
| SHA-1 | `bee5964bf03179b280369926f9a58637f2218e51` |
| SHA-256 | `566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab` |
| SHA3-384 | `ccec3f2195d33feb7e1542a1e30ee348f6402085ee48696fd9ca094055985715235fd2dfde4690ee0f7c0e17fa7aa7c9` |
| TLSH | `T1624533750B95EBA4403B1A00F98332273F9FBE4DA6F1CA9C0228478B575AF77D616C19` |
| SSDEEP | `24576:2tt244AAc1Y+EKI1H+2EFpSvgFs8AmgA4Bd5cl72gCFCBLL8AIkmO:234Aa+bdFs8AmMO72JFCP8AMO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_566b6a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab"
    family = "unknown"
    file_name = "566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:28:39"
  condition:
    hash.sha256(0, filesize) == "566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab"
}
```

### Sample 8: `92f886f400e93c9c`

| Field | Value |
|---|---|
| SHA-256 | `92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5` |
| Family label | `unknown` |
| File name | `92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5.exe` |
| File type | `unknown` |
| First seen | `2026-10-03 04:28:34` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40e6e22237336d05e72e9d0ebde6fa06` |
| SHA-256 | `92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_92f886f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5"
    family = "unknown"
    file_name = "92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 04:28:34"
  condition:
    hash.sha256(0, filesize) == "92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5"
}
```

### Sample 9: `1cfbf1bad6c7128b`

| Field | Value |
|---|---|
| SHA-256 | `1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3` |
| Family label | `unknown` |
| File name | `1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3.exe` |
| File type | `exe` |
| First seen | `2026-10-03 04:28:29` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acd58f8208045f572e5372ffac1f440d` |
| SHA-1 | `3bb5c06d69d5dead27c79b91e67e197abadf164e` |
| SHA-256 | `1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3` |
| SHA3-384 | `12509916395abffde8251055e5765289f8b476b442a3c599a70e315bf8068422503756dd9f7529ea83ba90422bf0e88c` |
| IMPHASH | `b27b6d6a3d1d1600b810fbd4b1463073` |
| TLSH | `T13F434A8AA75680B9D06B807DC9B31F56E676F05617A06BCF23A0836E2F377D0447B712` |
| SSDEEP | `1536:nvofWCdIxuDAABEKGmckVPxIiTymwzNj:v/CeuDAA2KFckVPxIiTyDzNj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_1cfbf1ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3"
    family = "unknown"
    file_name = "1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3.exe"
    file_type = "exe"
    first_seen = "2026-10-03 04:28:29"
  condition:
    hash.sha256(0, filesize) == "1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3"
}
```

### Sample 10: `69567223a283fc2c`

| Field | Value |
|---|---|
| SHA-256 | `69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb` |
| Family label | `unknown` |
| File name | `69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb.exe` |
| File type | `exe` |
| First seen | `2026-10-03 04:28:25` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4439b2be6a17f4f3b588d274ce83e9d6` |
| SHA-1 | `df6e6ed7f7e0813014b2df4f48d64365e561644d` |
| SHA-256 | `69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb` |
| SHA3-384 | `20475b87a57982556cb1f1d97aa56c57206ec45ad921f29e5a4da9bd32309f3157c00b4127f3f68d2a69aea9454c3b72` |
| IMPHASH | `2c0c41dde14e4dc2184848efb150d6ed` |
| TLSH | `T1EE036C25A255C0B9D926833988631E7FB363F12D0323178F62725ADD4E237ED4CE92E1` |
| SSDEEP | `768:d/HneuYy9cWZuzhAYEAitREmQtDAwhO+em8rlc7k64nKKb:tHeJymWozh2z8tDA7mO64nKKb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_69567223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb"
    family = "unknown"
    file_name = "69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb.exe"
    file_type = "exe"
    first_seen = "2026-10-03 04:28:25"
  condition:
    hash.sha256(0, filesize) == "69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb"
}
```

### Sample 11: `3242094dacc034bb`

| Field | Value |
|---|---|
| SHA-256 | `3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b` |
| Family label | `unknown` |
| File name | `3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b.exe` |
| File type | `unknown` |
| First seen | `2026-10-03 04:28:21` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `390fcf2ec62afb4d8432ccefe22b2092` |
| SHA-256 | `3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_3242094d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b"
    family = "unknown"
    file_name = "3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 04:28:21"
  condition:
    hash.sha256(0, filesize) == "3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b"
}
```

### Sample 12: `7629fe856487cf2a`

| Field | Value |
|---|---|
| SHA-256 | `7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7` |
| Family label | `unknown` |
| File name | `7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7` |
| File type | `elf` |
| First seen | `2026-10-03 04:24:59` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fab34fa608b47ac9a7e619f7a1d89a06` |
| SHA-1 | `907b7b1d5fe61695b9bc0e1c0e603bf1d218f714` |
| SHA-256 | `7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7` |
| SHA3-384 | `09784360210772aa3b692cb8658d813512872c6a5cedcf324d34583dc46a04e0e28769bb9ad0d24c1d92fec475f16789` |
| TLSH | `T14263F886BC918A9655C423BBBA7D81CE331337B8D2DF7103DD141F18B6CA94F0E6A952` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4if3LEm:T2s/ITo7WCkybotgsJ913DhrbW4UYm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_7629fe85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7"
    family = "unknown"
    file_name = "7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7"
    file_type = "elf"
    first_seen = "2026-10-03 04:24:59"
  condition:
    hash.sha256(0, filesize) == "7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7"
}
```

### Sample 13: `f43e44009d35dd25`

| Field | Value |
|---|---|
| SHA-256 | `f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f` |
| Family label | `Prometei` |
| File name | `f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f` |
| File type | `elf` |
| First seen | `2026-10-03 04:23:11` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0568e08e42311aa1bd35b0ad404c3444` |
| SHA-1 | `2c9cc8ca53dc577e2809d1850935b315bea2012a` |
| SHA-256 | `f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f` |
| SHA3-384 | `c361e067bcd48286b2cfdb8ec92d134db7d3558118b5e154a5db6006c3577c88c9215a78e86fc935968a0ef1ddcd7868` |
| TLSH | `T1E3A423F4F9219E8F6DD769B91B24831DE182C172589D4C2313AE94A34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsds:Fs6pyCC/Ya2hpi6T6N4S` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_013_f43e4400
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f"
    family = "Prometei"
    file_name = "f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f"
    file_type = "elf"
    first_seen = "2026-10-03 04:23:11"
  condition:
    hash.sha256(0, filesize) == "f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f"
}
```

### Sample 14: `67aad942831fde69`

| Field | Value |
|---|---|
| SHA-256 | `67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11` |
| Family label | `Mirai` |
| File name | `67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11` |
| File type | `elf` |
| First seen | `2026-10-03 03:38:36` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `551dbaa7cece67f0b26307ad842b42e8` |
| SHA-1 | `5b5083a0a73195224376d3fa64bbe675cdc8b88c` |
| SHA-256 | `67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11` |
| SHA3-384 | `9bf255b59ab1185ec6f23e5a06f503c41df7af0a94d62e31ddb9e92cc3c9fb5033450509834c85694ee55be49acb4736` |
| TLSH | `T12B24198AFC81AF5595C127BBFE2E418A331317B8E2EE71129D145F2477CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqh:T2s/bW+UmJqBxAuaPRhVabEDSDP99zB5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_67aad942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11"
    family = "Mirai"
    file_name = "67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11"
    file_type = "elf"
    first_seen = "2026-10-03 03:38:36"
  condition:
    hash.sha256(0, filesize) == "67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11"
}
```

### Sample 15: `fa76b2af590fa1fc`

| Field | Value |
|---|---|
| SHA-256 | `fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20` |
| Family label | `unknown` |
| File name | `fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20.bin` |
| File type | `zip` |
| First seen | `2026-10-03 02:18:05` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b78800cbda5d7e0a2bb33980abc65f34` |
| SHA-1 | `a7c3a3696bebec14256a842e14777c979a6a2c21` |
| SHA-256 | `fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20` |
| SHA3-384 | `446172ddbe3e0872f10ccbf4659b398fab12c5cec5a3248b6c0a5ddf40e425656a044703f3cf37f16db4b656f363aa3f` |
| TLSH | `T11E21E42C8A499046C83AF332A002F3C99ACDC652F009FE323F1EA6C204995C8A30380B` |
| SSDEEP | `24:9Uxz63kooBAuNlBrDTN4yU4aM0pwWPD8qXzhWoRFRGCKJ/zyRvezx0:9S63kJC6BrN4k01Thh+zAezm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_fa76b2af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20"
    family = "unknown"
    file_name = "fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20.bin"
    file_type = "zip"
    first_seen = "2026-10-03 02:18:05"
  condition:
    hash.sha256(0, filesize) == "fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20"
}
```

### Sample 16: `c591f581a245fccf`

| Field | Value |
|---|---|
| SHA-256 | `c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208` |
| Family label | `Mirai` |
| File name | `c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208` |
| File type | `elf` |
| First seen | `2026-10-03 02:17:29` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acc026e73cba4d01b483502fee1b16ad` |
| SHA-1 | `27626f275cf04c4f176b4be2b5fca63df2048231` |
| SHA-256 | `c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208` |
| SHA3-384 | `fe40583d25f1fe7757ae5012ee272bff36f3137aaed0f874670218eef38ae04a36aa5b07bd5e68d7345edff84036d87a` |
| TLSH | `T16234298AFC81AF65D5D422BBFE2E428A331317B8D2EB71129D145F2476CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOT:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_c591f581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208"
    family = "Mirai"
    file_name = "c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208"
    file_type = "elf"
    first_seen = "2026-10-03 02:17:29"
  condition:
    hash.sha256(0, filesize) == "c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208"
}
```

### Sample 17: `c2f5532f3209dce0`

| Field | Value |
|---|---|
| SHA-256 | `c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34` |
| Family label | `unknown` |
| File name | `s` |
| File type | `sh` |
| First seen | `2026-10-03 02:11:20` |
| Reporter | `boredchilada2` |
| Tags | `cve-2026-88771, freebsd, loader, netscaler, persistence, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c43855a8f86bfc665c509fffbe117ed` |
| SHA-1 | `96f4cffb3f37a759d61376cea4ac77f1a953b00e` |
| SHA-256 | `c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34` |
| SHA3-384 | `d13403f0ce7aae4c7fac70ef6adbc172c1bc543f517f4e251fa7fe2b285d8a3e769ce417d0f44fc49f704c5b27fa112e` |
| TLSH | `T181F05457D639FD7179CC4D1CF45819442EC741EB58E53D64D1C2BE0E757C19811B0310` |
| SSDEEP | `6:hUPPk6WhKLBg+ihcP2HGvfHIjKNv8SKcyAKzRIJt0dAM8cDFCjvC2B6ZMbxfAWnp:76WFYfHI48SNK90tjswfAaLiCb33` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_c2f5532f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34"
    family = "unknown"
    file_name = "s"
    file_type = "sh"
    first_seen = "2026-10-03 02:11:20"
  condition:
    hash.sha256(0, filesize) == "c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34"
}
```

### Sample 18: `2708183630293217`

| Field | Value |
|---|---|
| SHA-256 | `270818363029321786e16e2102c550a1edc7bd6fde172ed6c620ad1958c36ac8` |
| Family label | `unknown` |
| File name | `s` |
| File type | `sh` |
| First seen | `2026-10-03 02:10:57` |
| Reporter | `boredchilada2` |
| Tags | `cve-2026-88771, freebsd, loader, netscaler, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89f5992bc171e2244804d5a42fd9e63b` |
| SHA-1 | `1d3ccbf666435c8891da173f53c0eaa4dc981490` |
| SHA-256 | `270818363029321786e16e2102c550a1edc7bd6fde172ed6c620ad1958c36ac8` |
| SHA3-384 | `03e294c186cef3d82734bbdbee2cc0234e1406db8791b8f24c0aeba0778ed2407cfb10e310310d0b1ae3d5d7c8e2d493` |
| TLSH | `T1F6E0C2F751346EB12D1C44A87E2E8DAA71C7129DDCC87C02D0E1686A3534A54F2D9B12` |
| SSDEEP | `6:hUPPIKCVisANnDaQAP2HGvaEiZDaYFNMvqQEsHGv6GFFFd:UC3GLAOYaRFwqQ3Y6GFV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_27081836
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "270818363029321786e16e2102c550a1edc7bd6fde172ed6c620ad1958c36ac8"
    family = "unknown"
    file_name = "s"
    file_type = "sh"
    first_seen = "2026-10-03 02:10:57"
  condition:
    hash.sha256(0, filesize) == "270818363029321786e16e2102c550a1edc7bd6fde172ed6c620ad1958c36ac8"
}
```

### Sample 19: `7d9a6cad78a3980c`

| Field | Value |
|---|---|
| SHA-256 | `7d9a6cad78a3980c83676dd626e7bdd6c4d397ac64f35aa01d4e4a98679cab72` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1132e17e67464e7d26a44b71dedab1b3` |
| SHA-1 | `78215f87f8e21536c6e91c6eff95f6a8d33f05ea` |
| SHA-256 | `7d9a6cad78a3980c83676dd626e7bdd6c4d397ac64f35aa01d4e4a98679cab72` |
| SHA3-384 | `4d48a33f381a9bdaaaa07a5a9b3dc0490b00d41b3f46d38cfd048e7d3ea9b006ea1860803a1e9d4125b6a3b29870e508` |
| TLSH | `T16D141B0295518B57C5C21BBABB9B425937336F2493DB3302EA24BFB42F86B9D1E3D111` |
| TELFHASH | `t188716298943d06d9de631c15a8a85be34987f12922d4bf19ff26cdc4085e42df268e0f` |
| SSDEEP | `6144:0/yptIAsaTgWurK8O8R4mWdtvXZRO5Q40ss:06ptlsasWTG4mWdtvX3O5Q40ss` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_7d9a6cad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d9a6cad78a3980c83676dd626e7bdd6c4d397ac64f35aa01d4e4a98679cab72"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:27"
  condition:
    hash.sha256(0, filesize) == "7d9a6cad78a3980c83676dd626e7bdd6c4d397ac64f35aa01d4e4a98679cab72"
}
```

### Sample 20: `fe81f791dc2c956f`

| Field | Value |
|---|---|
| SHA-256 | `fe81f791dc2c956f7df44e76122ae5c13cc714d26592ae02751307e8714de6a8` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93728652cc3e5a8d12c63375ed59fa5a` |
| SHA-1 | `68f13089712ebcb740ff390596ecfc66a9dac243` |
| SHA-256 | `fe81f791dc2c956f7df44e76122ae5c13cc714d26592ae02751307e8714de6a8` |
| SHA3-384 | `c5d7caaf6e78da73f3ce0d0c4c1ec93fc22ee22450b20821ebe37c1637d362c09520284a3d9d1884a0667051811f2b59` |
| TLSH | `T175042993B904DEF6F40EA77604D34B257231BB660A531A32B31B797A9E3A2C43427F45` |
| TELFHASH | `t1e8717458953c05d9de631c19a8ad5be34987f12a22e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:VvYj5epGAylclFDhWphvjgnHbhN9sDLtnwyNvmRGIDOn2m2mDS5IwD:KYrylaFDUpdgnML+yNvmRGIDOn2m2mDK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_fe81f791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe81f791dc2c956f7df44e76122ae5c13cc714d26592ae02751307e8714de6a8"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:25"
  condition:
    hash.sha256(0, filesize) == "fe81f791dc2c956f7df44e76122ae5c13cc714d26592ae02751307e8714de6a8"
}
```

### Sample 21: `ee1667c977ac4224`

| Field | Value |
|---|---|
| SHA-256 | `ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdaa18731b924c2a43751715389792d7` |
| SHA-1 | `2c8e14794209cc571a13ff776a6ee1e85662c63f` |
| SHA-256 | `ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96` |
| SHA3-384 | `a9f104d9ed178c5f2021b3eb07f34ce612dd94b9ec83ae9a69be22c750987c84a1875da2d3611c05a736464857b5f289` |
| TLSH | `T129734B46E352C072D4830B7012E7D7398231EEB21716CE1BE71CBFB59A32685B1A976D` |
| TELFHASH | `t1e02160e0e23985144df64644c8cc0658c64be6296cc0ab22db75cf6589b961e432bf7f` |
| SSDEEP | `1536:AXPtK974GoqOFWR7poZ2sAUh31gAy0rwiJPhO1GL:AftKJ4G+FPZ9KInP01y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_ee1667c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:24"
  condition:
    hash.sha256(0, filesize) == "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96"
}
```

### Sample 22: `e148526ff5d3a132`

| Field | Value |
|---|---|
| SHA-256 | `e148526ff5d3a132a147359a7164f30b8f84f8cd4920b1e94974cf6dc6b4d996` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a7d7d0e5168ce6762e96f45e007e42f` |
| SHA-1 | `959d9d5e08023df27115db0a5a8e1c17fe1d59ae` |
| SHA-256 | `e148526ff5d3a132a147359a7164f30b8f84f8cd4920b1e94974cf6dc6b4d996` |
| SHA3-384 | `b4fedd57c77d0338586f367edeed87eb0d975eb9f5ccfa8022c0c2180780d27f0958bdc43cd3239e6f42381f1ae2944f` |
| TLSH | `T13324A62A3A11EFBFF56C873107F38A6097D521963AE19746F26CD71C1E2028D681F7A4` |
| TELFHASH | `t1e8717458953c05d9de631c19a8ad5be34987f12a22e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `6144:AgzXA4Ye5ipIYzyOzvn1qGGbpt49v3fz1We:bzXnYeoPzvn1qGGbpt49v3fz1We` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_e148526f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e148526ff5d3a132a147359a7164f30b8f84f8cd4920b1e94974cf6dc6b4d996"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:22"
  condition:
    hash.sha256(0, filesize) == "e148526ff5d3a132a147359a7164f30b8f84f8cd4920b1e94974cf6dc6b4d996"
}
```

### Sample 23: `2a8c2c1c3333f35a`

| Field | Value |
|---|---|
| SHA-256 | `2a8c2c1c3333f35a2feac67d048342fbb6e8e5c129d536c67a1115ed72e0065b` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `253f327e2ff6b2ddc37da6b0d053b077` |
| SHA-1 | `4de80cb1e8377fef710f419357342a70990f09df` |
| SHA-256 | `2a8c2c1c3333f35a2feac67d048342fbb6e8e5c129d536c67a1115ed72e0065b` |
| SHA3-384 | `b8457119c6e83afac21c14ef66e314d686fe1ce76bc3eff2eaf35cfa3a79e90a1cf606bb8c03c6c082df3fa4769daa3a` |
| TLSH | `T14FF32B03771C0A83C1676EF03AF717F183ABE91116A6A640F61EFE845332EB06559F99` |
| TELFHASH | `t1b5717458943c05d9de630c19a4a95be30887f12922e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:PQd8VUMxjAGTx7L7YTBMM6vpRvIDOn2l2mDS5IwD:P2MxjAOx73UBV6vpRvIDOn2l2mDS5IwD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_2a8c2c1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a8c2c1c3333f35a2feac67d048342fbb6e8e5c129d536c67a1115ed72e0065b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:21"
  condition:
    hash.sha256(0, filesize) == "2a8c2c1c3333f35a2feac67d048342fbb6e8e5c129d536c67a1115ed72e0065b"
}
```

### Sample 24: `a476654140f2734e`

| Field | Value |
|---|---|
| SHA-256 | `a476654140f2734ef4dbe54001da31d260feb706c6508e96df2dd4be9ddc31a0` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd52b2e62f7a360172f28b8b9dc44e97` |
| SHA-1 | `1d2299e40c210b1c807a9ff70a77142ef4be65da` |
| SHA-256 | `a476654140f2734ef4dbe54001da31d260feb706c6508e96df2dd4be9ddc31a0` |
| SHA3-384 | `f8abe0c59ca5f61696f174b856a726a00900fbc62c93b46ad9fefaed31a0dece059c97c886bc6aea42c2393bfe426358` |
| TLSH | `T1BF0429032591CAFBC4D69FB41BDBD4618523F83A1B36720AB3A4BCA51F0DED86E1D614` |
| TELFHASH | `t1ad716358953d05d9de631c19a8a95be34987f12e22e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:yvvBYW7G+6xxcIK6u8AMPmkUsyHYYkW+j74s9IB8wR62Zc1uvXXGFVfr5eNsZn5c:EuRHJaE0vXXGFVfr5eNsZn55wD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_a4766541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a476654140f2734ef4dbe54001da31d260feb706c6508e96df2dd4be9ddc31a0"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:19"
  condition:
    hash.sha256(0, filesize) == "a476654140f2734ef4dbe54001da31d260feb706c6508e96df2dd4be9ddc31a0"
}
```

### Sample 25: `ec9a838423f6a16f`

| Field | Value |
|---|---|
| SHA-256 | `ec9a838423f6a16ff80301cd09ca0333bc07ab5c24b40e6cb7bef46a7ecac25b` |
| Family label | `Mirai` |
| File name | `powerpc-440fp` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0287cb3f69f1848bbc013e3df147e9c3` |
| SHA-1 | `45e7e6ea2eae3039452358bab0944c4e531d7410` |
| SHA-256 | `ec9a838423f6a16ff80301cd09ca0333bc07ab5c24b40e6cb7bef46a7ecac25b` |
| SHA3-384 | `661d0bd53351f680c01d77897fe803637d3da2c1de01e9d64ca9d8da7ec6749391d50345d21cb16e39816f367496787f` |
| TLSH | `T18BF32B13671C0A83D05B6EF03AF717F18397A91125E7A640F20EFE845772EB0A51AF89` |
| TELFHASH | `t1b5717458943c05d9de630c19a4a95be30887f12922e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:dfbfJXmxT33vbRlM3rpUqtL6vpRvIDOn2l2mDS5IwD:t9mxT33tlMbpdtL6vpRvIDOn2l2mDS5X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_ec9a8384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec9a838423f6a16ff80301cd09ca0333bc07ab5c24b40e6cb7bef46a7ecac25b"
    family = "Mirai"
    file_name = "powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:17"
  condition:
    hash.sha256(0, filesize) == "ec9a838423f6a16ff80301cd09ca0333bc07ab5c24b40e6cb7bef46a7ecac25b"
}
```

### Sample 26: `d1f4e34e1a3d5be2`

| Field | Value |
|---|---|
| SHA-256 | `d1f4e34e1a3d5be26a70f56d0709c54bdd6caf5f8dbd6ca84f041b27e8532461` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4229616e3a63cf2d85dc75e981f786d1` |
| SHA-1 | `308f01fca2c9ea218ea791b7cb345789b624f500` |
| SHA-256 | `d1f4e34e1a3d5be26a70f56d0709c54bdd6caf5f8dbd6ca84f041b27e8532461` |
| SHA3-384 | `8f7055cf3bf6dfd53152dce5855e23c6bd4bd32e7b19aa55ac6e5d7b0a78355f0c1c52c2ec2cba4bbf2abd565801968a` |
| TLSH | `T138E33B41A657CAF7C8830FF612A75A660633E8395F2B8E45F32DBDB44B065CCB209758` |
| TELFHASH | `t1ad716358953d05d9de631c19a8a95be34987f12e22e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:8vMKLyH4aKj3Zrm+X3g/Tt4/rv5XGyWOrw9NhDn5AwR:EyOrn8Tt6v5XGyWOrw9NhDn5AwR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_d1f4e34e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1f4e34e1a3d5be26a70f56d0709c54bdd6caf5f8dbd6ca84f041b27e8532461"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:15"
  condition:
    hash.sha256(0, filesize) == "d1f4e34e1a3d5be26a70f56d0709c54bdd6caf5f8dbd6ca84f041b27e8532461"
}
```

### Sample 27: `b44c1284d7f2e4c4`

| Field | Value |
|---|---|
| SHA-256 | `b44c1284d7f2e4c40d8c370fed99af3933d1605cdb5bfdc93ea0100d347433a3` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d64a818178625ebde045f3b49463088` |
| SHA-1 | `135af569db8823f9a060cdaf2b1becc5abf44e0f` |
| SHA-256 | `b44c1284d7f2e4c40d8c370fed99af3933d1605cdb5bfdc93ea0100d347433a3` |
| SHA3-384 | `3c996d0afb7ee2a934fd681d7acbfec5172f1f92afb0abd22985af29f96f15d05bf590f0e1654d9eac67d9956fd67d3c` |
| TLSH | `T14C041A05EA405B57C1D22BBAFACB434633339B54A7E733059528ABB43FC679E4F22506` |
| TELFHASH | `t10a318396623c42659db11c18cc9847b60047e72627c0fb25ff2accc8182f40ae637d1b` |
| SSDEEP | `3072:sBHVxHCjfyad4aaePY8z6TaxmNEPXYjLmDM/R2dHr2zOpnI:6zG6ad4aaePY8ulEPXQCDM/RHOpI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_b44c1284
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b44c1284d7f2e4c40d8c370fed99af3933d1605cdb5bfdc93ea0100d347433a3"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:14"
  condition:
    hash.sha256(0, filesize) == "b44c1284d7f2e4c40d8c370fed99af3933d1605cdb5bfdc93ea0100d347433a3"
}
```

### Sample 28: `9c2f72796f72e5a0`

| Field | Value |
|---|---|
| SHA-256 | `9c2f72796f72e5a06c6a23e648f0685cecbe0f3624fc8e73886c3c9ae6f7537a` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a8a22773b67700962d908e28057adee` |
| SHA-1 | `72de243a10c64c0bb9496e550966e89d0d4cc198` |
| SHA-256 | `9c2f72796f72e5a06c6a23e648f0685cecbe0f3624fc8e73886c3c9ae6f7537a` |
| SHA3-384 | `e806e080e286be6c0b9f54ea0148385d58b6deb2281d1d33d4ceec2ec4f516aba3b76dd5e292d4ac752baa2f87ec5ae0` |
| TLSH | `T12BE3190398655FE7C196AFB566E75A750703EC110B4B1F8AB23AEAF4060B9CCF809774` |
| TELFHASH | `t1f2717358943c05d9de630c19a8a95be30887f12a22e5bb19ff16cdc4085e42cf228e0f` |
| SSDEEP | `3072:TagER6ax3yJWhVFACPrWhjQMqrTtDgTD4vOLvIIOnZT2uDS51wr:Ta56ax3yE156hjPqrT1rvOLvIIOnZT2w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_9c2f7279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c2f72796f72e5a06c6a23e648f0685cecbe0f3624fc8e73886c3c9ae6f7537a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:12"
  condition:
    hash.sha256(0, filesize) == "9c2f72796f72e5a06c6a23e648f0685cecbe0f3624fc8e73886c3c9ae6f7537a"
}
```

### Sample 29: `a199b97450fe8a1d`

| Field | Value |
|---|---|
| SHA-256 | `a199b97450fe8a1d60209237801321d88cf5f3dd720183f196477f427eaa2d89` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8fccd27b9d2552b63c7e6872447ba01` |
| SHA-1 | `f6802f7e48b4e58e95411e16731634c0e6ae5097` |
| SHA-256 | `a199b97450fe8a1d60209237801321d88cf5f3dd720183f196477f427eaa2d89` |
| SHA3-384 | `d3e0548d6fae274ab25928b8981ebd13a17868ac7be85db38508cf5e7b06da11b0b7088dbc7f9353a3d14178f0060c88` |
| TLSH | `T1F7E34A42A652CAF3D5C30FB612E757220633E83A1B2BDE45F32DBCB45E45588F21666C` |
| TELFHASH | `t1ad716358953d05d9de631c19a8a95be34987f12e22e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:TOFrafcNUv2eYukm7622wcvxXGyWOrw9NhDn5AwR:8W+/m76tvxXGyWOrw9NhDn5AwR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_a199b974
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a199b97450fe8a1d60209237801321d88cf5f3dd720183f196477f427eaa2d89"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:11"
  condition:
    hash.sha256(0, filesize) == "a199b97450fe8a1d60209237801321d88cf5f3dd720183f196477f427eaa2d89"
}
```

### Sample 30: `cda0e3cecf5cb049`

| Field | Value |
|---|---|
| SHA-256 | `cda0e3cecf5cb049a3c9589d7e88d72f1fb102bf5037080bc579f05cecaa3c6c` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff325db2dd15494e32ac89817689ff8b` |
| SHA-1 | `ebe82efb4edd76e24b0583827100bae3d188de94` |
| SHA-256 | `cda0e3cecf5cb049a3c9589d7e88d72f1fb102bf5037080bc579f05cecaa3c6c` |
| SHA3-384 | `05e001c9901765f951ef76e0b6a4b4e1353521855f58a4b625d65461334e1381ef169496edfbcd41f9e41091effa8bdd` |
| TLSH | `T1E7040B45B8104B57C6C32BBAF79F42993B336B1897DB3301EA28BEB42F4679D1D29111` |
| TELFHASH | `t1e8717458953c05d9de631c19a8ad5be34987f12a22e5bb19ff26cdc4085e42cf228e0f` |
| SSDEEP | `3072:2KOfWuFQz4w8eHyIAvPFh0G+AN4t9lVB+ZvIRGjAgZGu4aw3l+vwD:ozSz4w8Qy1vNh0G+BVwZvIRGjAgZGu4L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_cda0e3ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cda0e3cecf5cb049a3c9589d7e88d72f1fb102bf5037080bc579f05cecaa3c6c"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:09"
  condition:
    hash.sha256(0, filesize) == "cda0e3cecf5cb049a3c9589d7e88d72f1fb102bf5037080bc579f05cecaa3c6c"
}
```

### Sample 31: `8a287d808ee09800`

| Field | Value |
|---|---|
| SHA-256 | `8a287d808ee098002248f03563da082e0939f9532d211c569c1937de62ef2cb9` |
| Family label | `Mirai` |
| File name | `Space.spc` |
| File type | `elf` |
| First seen | `2026-10-03 02:02:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5473e66af5793a3c2bf44c93ebd3c5a1` |
| SHA-1 | `ae3c9daeeda31fc29672e9bd9a0d6e52745e8aa8` |
| SHA-256 | `8a287d808ee098002248f03563da082e0939f9532d211c569c1937de62ef2cb9` |
| SHA3-384 | `93daff82ca9442c352758001f285e8504097036a2a15c51b9d710487b60794bfc514b50dec77400304e16b3b8cb44b73` |
| TLSH | `T100735C31F976192BC0D4A03A21F74727B6F297CA21A8861F3E710F9DBF655402A43EB5` |
| SSDEEP | `1536:1FzM8MMeTCyKZ74S/Xr+tlzDTYm5o8JAhQLt7OVi:/LIWq/jYOzJeVi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_8a287d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a287d808ee098002248f03563da082e0939f9532d211c569c1937de62ef2cb9"
    family = "Mirai"
    file_name = "Space.spc"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:07"
  condition:
    hash.sha256(0, filesize) == "8a287d808ee098002248f03563da082e0939f9532d211c569c1937de62ef2cb9"
}
```

### Sample 32: `97df330410c814e0`

| Field | Value |
|---|---|
| SHA-256 | `97df330410c814e0db3eeb988af0dbde105b776baf1b3af08516341a778cde3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-10-03 01:55:19` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8046da12f4625d5f6cc8b6464b0a94a2` |
| SHA-256 | `97df330410c814e0db3eeb988af0dbde105b776baf1b3af08516341a778cde3e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_97df3304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97df330410c814e0db3eeb988af0dbde105b776baf1b3af08516341a778cde3e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-10-03 01:55:19"
  condition:
    hash.sha256(0, filesize) == "97df330410c814e0db3eeb988af0dbde105b776baf1b3af08516341a778cde3e"
}
```

### Sample 33: `fcb6a359b4364406`

| Field | Value |
|---|---|
| SHA-256 | `fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd` |
| Family label | `Mirai` |
| File name | `fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd` |
| File type | `elf` |
| First seen | `2026-10-03 01:49:41` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b9d3d1dc5e3b2770a9255170edc7cb4` |
| SHA-1 | `97baccf60512f7422a974a5a2b8c787cc0734bd1` |
| SHA-256 | `fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd` |
| SHA3-384 | `4379976be78e98c0920bfaa096c0503f539fa7f2f620bccdf90bf2cf2d8a491fd842ed8a182342af19556a56d276197e` |
| TLSH | `T1FC242A8AFC81AF2595C526BBFE2E428A331317B8D2EB71129D145F2477CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqq0:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_fcb6a359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd"
    family = "Mirai"
    file_name = "fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd"
    file_type = "elf"
    first_seen = "2026-10-03 01:49:41"
  condition:
    hash.sha256(0, filesize) == "fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd"
}
```

### Sample 34: `0db9ec1267fc0883`

| Field | Value |
|---|---|
| SHA-256 | `0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4` |
| Family label | `unknown` |
| File name | `0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4` |
| File type | `elf` |
| First seen | `2026-10-03 01:20:34` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5258b7d7fc363a59f4759e870b63c85f` |
| SHA-1 | `8c49ccefe4b86419cd7c7f387e776a83139958c1` |
| SHA-256 | `0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4` |
| SHA3-384 | `715f715bc2de953e0d7e698e3ff2a421597c8394524195c381b4a5eed24c7a618a57d7cc8bc5a35f58b3c329c6debbb4` |
| TLSH | `T180D3120E1ADDF01AFB3A423B2593F5D4C0BE1712BE0D6C976959A391F13227441AB4E7` |
| SSDEEP | `3072:nnVfHJiRhTlgh+fnPpf1H2VPIKMLNl4dSH8dHvPMNOzT1DSJw14SI8W9:BHJqjgAnPpf1WVPIKMLbLcJgOf1+mn9q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_0db9ec12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4"
    family = "unknown"
    file_name = "0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4"
    file_type = "elf"
    first_seen = "2026-10-03 01:20:34"
  condition:
    hash.sha256(0, filesize) == "0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4"
}
```

### Sample 35: `d6f7bc7b338e388b`

| Field | Value |
|---|---|
| SHA-256 | `d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90` |
| Family label | `unknown` |
| File name | `d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90.exe` |
| File type | `exe` |
| First seen | `2026-10-03 01:18:06` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b30ad062b0587874083c9fc3823ed01c` |
| SHA-1 | `210c4af073faa3e7aa86b7f2fcc4f81ad74f3955` |
| SHA-256 | `d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90` |
| SHA3-384 | `2a13f48380dea01d9df8b803a6dea8871cfdce9db877030e76eb72c452f2ad0621133f9e7bff59a69a054fb9bdb54e99` |
| IMPHASH | `53e4e12437621212a425d294842d0a96` |
| TLSH | `T136957C0053E44649D33B893CC5728412EF727E1B577292DF89A0AE992B77BC0877A736` |
| SSDEEP | `24576:1MhONwvVvyNa7jsIYV9xZ2T4p62w14yhP:WvVvyNa7kET5rv1` |
| ICON-DHASH | `00000002000002c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_d6f7bc7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90"
    family = "unknown"
    file_name = "d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90.exe"
    file_type = "exe"
    first_seen = "2026-10-03 01:18:06"
  condition:
    hash.sha256(0, filesize) == "d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90"
}
```

### Sample 36: `e839d72d6c03b1b0`

| Field | Value |
|---|---|
| SHA-256 | `e839d72d6c03b1b08a3f01d8ebd907e3c96ebe8fc576f928270635b6636a41cc` |
| Family label | `unknown` |
| File name | `clickfix.exe` |
| File type | `exe` |
| First seen | `2026-10-03 01:14:17` |
| Reporter | `nextpro` |
| Tags | `exe, sliver` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a9f47151a6546a78373185317473356` |
| SHA-1 | `169fbe6a4c4a371c4b3f5c1180e058beecd1403d` |
| SHA-256 | `e839d72d6c03b1b08a3f01d8ebd907e3c96ebe8fc576f928270635b6636a41cc` |
| SHA3-384 | `f2a6ac3190613d4c30e7bc0295bc6cdbffffc0395226aa4b55e24a91c7f0a53740e2f57633f05ead93ccd6b45cb6b4dc` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T179972963F8D21A94D8EEC170D6728137BBA178690B7C13D70690E3241F3BBE09AB6755` |
| SSDEEP | `393216:MsZsAhbPsslhazMNcxjE8qD3AsM/Dz3fo3vnR4sYblbjrON:MY4ocZYYg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_e839d72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e839d72d6c03b1b08a3f01d8ebd907e3c96ebe8fc576f928270635b6636a41cc"
    family = "unknown"
    file_name = "clickfix.exe"
    file_type = "exe"
    first_seen = "2026-10-03 01:14:17"
  condition:
    hash.sha256(0, filesize) == "e839d72d6c03b1b08a3f01d8ebd907e3c96ebe8fc576f928270635b6636a41cc"
}
```

### Sample 37: `18616fe26c8f6c92`

| Field | Value |
|---|---|
| SHA-256 | `18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6` |
| Family label | `unknown` |
| File name | `install.sh` |
| File type | `sh` |
| First seen | `2026-10-03 01:12:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab6b06d679a000a4901997b5d65a953a` |
| SHA-1 | `dc2b4a8a71e200c9a52511876158b8b6aa38b56c` |
| SHA-256 | `18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6` |
| SHA3-384 | `9d4bbdc706d63cc6666322195919fe301b6e2350c6528e4c94ab941f9c87af5c70a6ade648d9a1d722c604b982d82c3a` |
| TLSH | `T10783B522784559B425CCDE6C49FA1C902739C00BCA1A2D2CF05EE5D83F76A78F5FA2D9` |
| SSDEEP | `1536:mUEDcQPyTuvb6jes5lRUH5Dvf003RwOEo6uD:mW0E5lRUHV003RwOEo6s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_18616fe2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-10-03 01:12:13"
  condition:
    hash.sha256(0, filesize) == "18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6"
}
```

### Sample 38: `c66f9881bed79a55`

| Field | Value |
|---|---|
| SHA-256 | `c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b` |
| Family label | `unknown` |
| File name | `c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b.bin` |
| File type | `macho` |
| First seen | `2026-10-03 01:07:59` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4d182ca304c331a15b1c25a13db0d1a` |
| SHA-1 | `dd2632ac778898c2766b87031af4539a03357820` |
| SHA-256 | `c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b` |
| SHA3-384 | `b126e7bb9167c23d0050586085e4b4a3ddd57c9fe598905fc5201424a59303c92f6b1640d51ba9ce463834279084e12c` |
| TLSH | `T1A2769E50BD2C1C25F6C6F2BD9E8A4BA0B15BF8A04670C2DB793741ADDD917A1903DB32` |
| SSDEEP | `98304:X1Qnp40oASZADVwdDtExbTAco1LkDC3aERlIK4JevJeihlz:ip40oAS2aBts1KAm3aaIKDV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_c66f9881
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b"
    family = "unknown"
    file_name = "c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b.bin"
    file_type = "macho"
    first_seen = "2026-10-03 01:07:59"
  condition:
    hash.sha256(0, filesize) == "c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b"
}
```

### Sample 39: `1242552e288c55d3`

| Field | Value |
|---|---|
| SHA-256 | `1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f` |
| Family label | `Mirai` |
| File name | `1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f` |
| File type | `elf` |
| First seen | `2026-10-03 00:52:02` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ae81c3565733541690f74ac0cf63783` |
| SHA-1 | `6ab9d64de954c6cacb706edd9d851a117931dfd0` |
| SHA-256 | `1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f` |
| SHA3-384 | `9f67dfe62ca28d5dc5cda06a2c89206b3f626c683b0d7aba9c7cad0ab89507be2891a6b893c742fac13d21123d3ddb3b` |
| TLSH | `T1D7B3079BBC91EE694AC0137BFE2E418E330727B4D1DF71139D141F58B68A94F0E6A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggW:T2s/gAWuboqsJ9xcJxspJBqQgD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_1242552e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f"
    family = "Mirai"
    file_name = "1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f"
    file_type = "elf"
    first_seen = "2026-10-03 00:52:02"
  condition:
    hash.sha256(0, filesize) == "1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f"
}
```

### Sample 40: `c98e5215787ff8bb`

| Field | Value |
|---|---|
| SHA-256 | `c98e5215787ff8bbe2a79d4afb6d6ef27d96ac75273bf220b915779c8f4b0192` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-10-03 00:40:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72537698846e50085560083c582c34ba` |
| SHA-1 | `a756a8ddc55faf7c91dd5388e60e1ad5996021ca` |
| SHA-256 | `c98e5215787ff8bbe2a79d4afb6d6ef27d96ac75273bf220b915779c8f4b0192` |
| SHA3-384 | `6c27c66fa49006a304b17077721cc5ea1ddb340753fe3e6dda2d1a89b13f03afb1facba5fe43d0c45cd1e289fbed2e52` |
| TLSH | `T1D3D34B05730C0A57D1633EB03A3F27E1D3EFAAD121E4F641255F9A8AA271D325586ECE` |
| SSDEEP | `1536:5/7DXIulWXYnnxfYKZN1dPcreLQNeltTlBvAndSI82aXcqxEMBWei:d4Xix3NLXQNgtcn8di` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_c98e5215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c98e5215787ff8bbe2a79d4afb6d6ef27d96ac75273bf220b915779c8f4b0192"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-03 00:40:00"
  condition:
    hash.sha256(0, filesize) == "c98e5215787ff8bbe2a79d4afb6d6ef27d96ac75273bf220b915779c8f4b0192"
}
```

### Sample 41: `c26605c768197314`

| Field | Value |
|---|---|
| SHA-256 | `c26605c768197314a1b59d03e5065e4b6cb0f6ef4177d13e41e4cf4cebab7300` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-10-03 00:38:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc03613f009e51848a9747cfbe5f9d93` |
| SHA-1 | `2dc84bfbaf2f06f78c22296bc3b942a87b4fd23a` |
| SHA-256 | `c26605c768197314a1b59d03e5065e4b6cb0f6ef4177d13e41e4cf4cebab7300` |
| SHA3-384 | `9c6b697e9fa4ad82c9f3da121d28ad993027ed61b70c8e11f78d43e4a9bc42ae9d51b0df451eef6cd61ac415435b4365` |
| TLSH | `T167D31A45FC409F23C5D622BBFB5E428D3B2A17A8D3EF720799255F21378685B0E36A41` |
| TELFHASH | `t1c7f0ab3088982c8c3ae54c5405ec7a7fbd9df03ad8602e97d7494edbd2139e7b40913a` |
| SSDEEP | `1536:xCgRJ/BWoN93yKyfy3f/iqkA9hXH4wf+puT9NFAe8HDCWL+PvTF29IlH3wywl5ND:xBHHKqk2XYwQurFAeMVEL40fU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_c26605c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c26605c768197314a1b59d03e5065e4b6cb0f6ef4177d13e41e4cf4cebab7300"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-10-03 00:38:00"
  condition:
    hash.sha256(0, filesize) == "c26605c768197314a1b59d03e5065e4b6cb0f6ef4177d13e41e4cf4cebab7300"
}
```

### Sample 42: `2426afcd37003221`

| Field | Value |
|---|---|
| SHA-256 | `2426afcd370032216331814d58ac157395c155aeb42f6ba3822ff4b40c86c600` |
| Family label | `Mirai` |
| File name | `Space` |
| File type | `elf` |
| First seen | `2026-10-03 00:36:25` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20e6bbd7a88fa52106d993742b9c11f4` |
| SHA-1 | `edee0f7849ad6c8d3e4b4db045ec102df4590323` |
| SHA-256 | `2426afcd370032216331814d58ac157395c155aeb42f6ba3822ff4b40c86c600` |
| SHA3-384 | `c1c829d3e5e60f8fd73e519f7f4fdc73660d96b912872b7229b1718220e87065b67669df693864414e72dcd15ff55d05` |
| TLSH | `T1E9634BC9ED83C4F6F856093410B7BF639D72D6BE2168CE03C3A995329D66503E912E9C` |
| TELFHASH | `t15621e4fb2e6b19e8b3d19c04c3196b911a6de27b046033e585b29ce821e6ec19039c39` |
| SSDEEP | `1536:R7jlAzJVRQiAAQ1VD88FeurxCuNjXTqHV5AZSoVp:R+zJIiAAQ1h84NrwQjXTq1yVp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_2426afcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2426afcd370032216331814d58ac157395c155aeb42f6ba3822ff4b40c86c600"
    family = "Mirai"
    file_name = "Space"
    file_type = "elf"
    first_seen = "2026-10-03 00:36:25"
  condition:
    hash.sha256(0, filesize) == "2426afcd370032216331814d58ac157395c155aeb42f6ba3822ff4b40c86c600"
}
```

### Sample 43: `7451d2df5fa394be`

| Field | Value |
|---|---|
| SHA-256 | `7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef` |
| Family label | `unknown` |
| File name | `7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef.dll` |
| File type | `unknown` |
| First seen | `2026-10-03 00:36:04` |
| Reporter | `Kejult` |
| Tags | `CVE-2017-0147, dll, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a87e88ede8167dcb09574ee3a271e4f` |
| SHA-256 | `7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_7451d2df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef"
    family = "unknown"
    file_name = "7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef.dll"
    file_type = "unknown"
    first_seen = "2026-10-03 00:36:04"
  condition:
    hash.sha256(0, filesize) == "7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef"
}
```

### Sample 44: `3ba3ff1127b8f5b4`

| Field | Value |
|---|---|
| SHA-256 | `3ba3ff1127b8f5b40e8a97329f9684059220ed22baa53def1febf8072626d4d4` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-10-03 00:33:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `019f83c3adac3e24d274eaad00fca8e0` |
| SHA-1 | `5404db56ee1a9298ecacd04a70638db66a8a8418` |
| SHA-256 | `3ba3ff1127b8f5b40e8a97329f9684059220ed22baa53def1febf8072626d4d4` |
| SHA3-384 | `10d72a727ab3efe7823b0f7cce98f61581343d1e05c87e331a4ec8c525b58ea4c0327e82c45c16bfec1345e8f5dff8be` |
| TLSH | `T121D30945FC505B23C6C622BBFB5E428D3B2A17A9D3EF720799215F21378A46B0D3B641` |
| TELFHASH | `t1caf0552889886c883af84c910ddd3a7fb8adb436849128a6a70a4e96d1536e3b40543a` |
| SSDEEP | `1536:Sbh4S/9LFsd69yCyjyghRR04A4K+Ik81wfCB+TraCEXJdCFadc16lIRluzwywV5D:SFl86mL04C+IT1w8+iCEX/jKY7j6VB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_3ba3ff11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ba3ff1127b8f5b40e8a97329f9684059220ed22baa53def1febf8072626d4d4"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-10-03 00:33:58"
  condition:
    hash.sha256(0, filesize) == "3ba3ff1127b8f5b40e8a97329f9684059220ed22baa53def1febf8072626d4d4"
}
```

### Sample 45: `75300610d2c17b6e`

| Field | Value |
|---|---|
| SHA-256 | `75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc` |
| Family label | `unknown` |
| File name | `75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc.sh` |
| File type | `unknown` |
| First seen | `2026-10-03 00:29:09` |
| Reporter | `Kejult` |
| Tags | `BackDoor, sh, Shell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b794e197b55e5eab133f3fc8d268adf1` |
| SHA-256 | `75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_75300610
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc"
    family = "unknown"
    file_name = "75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc.sh"
    file_type = "unknown"
    first_seen = "2026-10-03 00:29:09"
  condition:
    hash.sha256(0, filesize) == "75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc"
}
```

### Sample 46: `d5d9e754f2bc9e9d`

| Field | Value |
|---|---|
| SHA-256 | `d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa` |
| Family label | `unknown` |
| File name | `d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa.exe` |
| File type | `exe` |
| First seen | `2026-10-03 00:28:23` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4b2d22dab4b4e6f1506f5c0e09bdb72` |
| SHA-1 | `37308522e68b9fcd01b69e91bc0cc148d15db5c8` |
| SHA-256 | `d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa` |
| SHA3-384 | `ff6d70b8ce31885fe57f8586b3d967832c6185ec61f37e3fbb84893f3838196cef4e416f3df8165567130caf5e535d23` |
| IMPHASH | `07d88635cbb4b876a327d4460f48d129` |
| TLSH | `T17A16338FECE6E1B4D83B43B4FE5207DC8527C75ECF1FD09AA469429E44AF00B5695282` |
| SSDEEP | `98304:St+wahoXyp30UusJTWu6T+Ulln1OFCjdqlHo:o+wLBsRsZdZjdqlHo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_d5d9e754
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa"
    family = "unknown"
    file_name = "d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa.exe"
    file_type = "exe"
    first_seen = "2026-10-03 00:28:23"
  condition:
    hash.sha256(0, filesize) == "d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa"
}
```

### Sample 47: `068a7e1cbc2094d5`

| Field | Value |
|---|---|
| SHA-256 | `068a7e1cbc2094d515d396b24d9ce6608b2002bf237256105fa9650484f2803e` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-10-03 00:27:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0294e375927c6fa523a5ec824ef92920` |
| SHA-1 | `fd66aaa1a5b2cbbb5ea150984281ed822503852c` |
| SHA-256 | `068a7e1cbc2094d515d396b24d9ce6608b2002bf237256105fa9650484f2803e` |
| SHA3-384 | `6d426cb9d3f5e1a35a79c0fe5765ebdc8ff61adac48e46e045ae8e57f345cd8b7d2bee98bc3dd362d2183824f778f19b` |
| TLSH | `T164E35B07B5C184FEC4DAC1744FAAF63A9D32B49D1238B16B27D4AB221E9DE305F1DA50` |
| TELFHASH | `t18651bdb4396539a8b1f3f691b309e9669d321d5009e130e6de7374e58f25bc80e21823` |
| SSDEEP | `3072:fKITKg2utulWncl2pOTkKq+YIsdmJ2guSQdqStEAVuCu9b5:fK0Kg2utulWnc0V0spgSiH9b5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_068a7e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "068a7e1cbc2094d515d396b24d9ce6608b2002bf237256105fa9650484f2803e"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-10-03 00:27:56"
  condition:
    hash.sha256(0, filesize) == "068a7e1cbc2094d515d396b24d9ce6608b2002bf237256105fa9650484f2803e"
}
```

### Sample 48: `75a512a7acd86a80`

| Field | Value |
|---|---|
| SHA-256 | `75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f` |
| Family label | `unknown` |
| File name | `75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f.elf` |
| File type | `elf` |
| First seen | `2026-10-03 00:27:20` |
| Reporter | `Kejult` |
| Tags | `CoinMiner, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00c050e437f1a6041b128ae16517ac86` |
| SHA-1 | `31d1a5295120b7a3d0b7ee82f6ec0a88653b4345` |
| SHA-256 | `75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f` |
| SHA3-384 | `c86498343707b0170dff453239277d91cea4b81a0abfa8b19a5ea3026dae4db436e701a473775d8377fc8b834cc72a41` |
| TLSH | `T12637CF77914338E9E5A98DB4D01025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQC:cqYUQuVDt0TZEx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_75a512a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f"
    family = "unknown"
    file_name = "75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f.elf"
    file_type = "elf"
    first_seen = "2026-10-03 00:27:20"
  condition:
    hash.sha256(0, filesize) == "75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f"
}
```

### Sample 49: `7389513d31284341`

| Field | Value |
|---|---|
| SHA-256 | `7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1` |
| Family label | `Prometei` |
| File name | `7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1` |
| File type | `elf` |
| First seen | `2026-10-03 00:23:06` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fef957f5241d3d563458f39d420b5b9` |
| SHA-1 | `201e818698ee4f4b035b49877ea50c3ede0604c6` |
| SHA-256 | `7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1` |
| SHA3-384 | `e6aa45cb2db53d1fa812761323ef8a4205bb0e70e44487df17c3c1b4c4ed322a896a9f7957538ab1081ffa48acfba9eb` |
| TLSH | `T166A423B4F9219E9F6DD769B91B24831DE182C172589D4C2313AE94E34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdq:Fs6pyCC/Ya2hpi6T6N4Q` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_049_7389513d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1"
    family = "Prometei"
    file_name = "7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1"
    file_type = "elf"
    first_seen = "2026-10-03 00:23:06"
  condition:
    hash.sha256(0, filesize) == "7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1"
}
```

### Sample 50: `bffecd40374eb278`

| Field | Value |
|---|---|
| SHA-256 | `bffecd40374eb2788c47a1adea38cb24eb05812f93a561ee503549879617a42c` |
| Family label | `unknown` |
| File name | `3cdb5ff86c49e550410b2dbcadd1004c.exe` |
| File type | `unknown` |
| First seen | `2026-10-03 00:20:05` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cdb5ff86c49e550410b2dbcadd1004c` |
| SHA-256 | `bffecd40374eb2788c47a1adea38cb24eb05812f93a561ee503549879617a42c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_bffecd40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bffecd40374eb2788c47a1adea38cb24eb05812f93a561ee503549879617a42c"
    family = "unknown"
    file_name = "3cdb5ff86c49e550410b2dbcadd1004c.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 00:20:05"
  condition:
    hash.sha256(0, filesize) == "bffecd40374eb2788c47a1adea38cb24eb05812f93a561ee503549879617a42c"
}
```

### Sample 51: `372a17ab8c80c4d0`

| Field | Value |
|---|---|
| SHA-256 | `372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4` |
| Family label | `unknown` |
| File name | `372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4.bin` |
| File type | `unknown` |
| First seen | `2026-10-03 00:18:33` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90c2f3bfc8eab0b7dfef7987c549b987` |
| SHA-256 | `372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_372a17ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4"
    family = "unknown"
    file_name = "372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4.bin"
    file_type = "unknown"
    first_seen = "2026-10-03 00:18:33"
  condition:
    hash.sha256(0, filesize) == "372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4"
}
```

### Sample 52: `bf44090998d03a3a`

| Field | Value |
|---|---|
| SHA-256 | `bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257` |
| Family label | `unknown` |
| File name | `bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257.bin` |
| File type | `zip` |
| First seen | `2026-10-03 00:13:22` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acce8788e1f12571ed0b85bd329515c3` |
| SHA-1 | `51b301c0bf99af48afae07426837e7d7f7536dba` |
| SHA-256 | `bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257` |
| SHA3-384 | `a9e4f0c719f17bed3d162ed908189914b4240496c4bbe556ae211030ba0727c7cd64f34d5bc9bdc521903a7547b45075` |
| TLSH | `T1166633FE96011CAEC22F6972E5C5216FC1F0792D44FCD0DA16474BA89622EDD6A38D33` |
| SSDEEP | `196608:QbapblOOJKWl3FS2TjN2qaxbe4Zx2iXz/ntmvFhyjmHk:QbaPOzWl9TJEBjZx2MtCyaHk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_bf440909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257"
    family = "unknown"
    file_name = "bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257.bin"
    file_type = "zip"
    first_seen = "2026-10-03 00:13:22"
  condition:
    hash.sha256(0, filesize) == "bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257"
}
```

### Sample 53: `2d96839426e3400d`

| Field | Value |
|---|---|
| SHA-256 | `2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1` |
| Family label | `unknown` |
| File name | `2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1.exe` |
| File type | `unknown` |
| First seen | `2026-10-03 00:13:17` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b594082ac29b4464f1a75ba48c13f0d` |
| SHA-256 | `2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_2d968394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1"
    family = "unknown"
    file_name = "2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 00:13:17"
  condition:
    hash.sha256(0, filesize) == "2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1"
}
```

### Sample 54: `a2b38e3080c9a3c5`

| Field | Value |
|---|---|
| SHA-256 | `a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-03 00:09:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf1e9f720453a45bb931749e6efc44ae` |
| SHA-1 | `b9ae0c3ce892a9ce43b1d767870231cf41e81e8d` |
| SHA-256 | `a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3` |
| SHA3-384 | `3644e7654d91b24bb372194763ff0b279ec823ed09a200c9a2472eed37b0bd8d0f6be71653e88b7c8bb0a6da3f765876` |
| TLSH | `T18314F755BC918F66C6C656BBFF4E828D372A27A8D3EA3103DD255F24378B45A0E3B101` |
| SSDEEP | `6144:CTw5OED3S6Cpu0WF4EsZ+b42Cp92ZiuKflK9l:CTyOts0w45Ab4Zp9uU9K9l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_a2b38e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-03 00:09:59"
  condition:
    hash.sha256(0, filesize) == "a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3"
}
```

### Sample 55: `2e538429e81c49a1`

| Field | Value |
|---|---|
| SHA-256 | `2e538429e81c49a167f49c949eff7f8fb43b0c5af985a394bd7e4ca0669739b5` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-10-03 00:06:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `572221085829beb447d11530107b9211` |
| SHA-1 | `be72d5ae8832e0b84b3f15eaea96050832c524c8` |
| SHA-256 | `2e538429e81c49a167f49c949eff7f8fb43b0c5af985a394bd7e4ca0669739b5` |
| SHA3-384 | `1364b859572a66d78274358aa8248f57e58556e856cc0a37c4a6c6ac019010e46dabd93a34da78028826a03531e2b807` |
| TLSH | `T13764C60ABB620EFBE86FCE3B06F90B0624CC655722953F753574DA1CB54A50B4AE3C64` |
| SSDEEP | `6144:Kv/YlkHeOAOah0zMQxDzuQgSZRuYOHkOiaN8:Kv/YlkHeOAOah0YQxDzuZ0vOHkq8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_2e538429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e538429e81c49a167f49c949eff7f8fb43b0c5af985a394bd7e4ca0669739b5"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-03 00:06:10"
  condition:
    hash.sha256(0, filesize) == "2e538429e81c49a167f49c949eff7f8fb43b0c5af985a394bd7e4ca0669739b5"
}
```

### Sample 56: `dc4f2d231061b28e`

| Field | Value |
|---|---|
| SHA-256 | `dc4f2d231061b28e24d4c7a85ea4904f6704059d271587f0f0c1951993be7775` |
| Family label | `unknown` |
| File name | `macho_dc4f2d231061.bin` |
| File type | `macho` |
| First seen | `2026-10-03 00:03:25` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59b93bc4981ef127fd9e872c5c3e2ec5` |
| SHA-1 | `d8b8f296d17ab2005dbf74d1e56da41a8f0c11e6` |
| SHA-256 | `dc4f2d231061b28e24d4c7a85ea4904f6704059d271587f0f0c1951993be7775` |
| SHA3-384 | `0f862043315f58cfbf2d648f4a12c82e051ee2428021d76430d39614114c7d73f14785af9aea839f17173738e8ceec22` |
| TLSH | `T12545F100CF76549AF58CEA30396B17774E247570864EA0CF53A66A988D3A3E3F16731E` |
| SSDEEP | `12288:seQWXLcIVmKAKnIsVr6rbV/4UICS0R/wSyhMMSiMplH2Str+YPrarbVnaUY0asRR:OrKAJWWwSyhMG2rURawzsmyW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_dc4f2d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc4f2d231061b28e24d4c7a85ea4904f6704059d271587f0f0c1951993be7775"
    family = "unknown"
    file_name = "macho_dc4f2d231061.bin"
    file_type = "macho"
    first_seen = "2026-10-03 00:03:25"
  condition:
    hash.sha256(0, filesize) == "dc4f2d231061b28e24d4c7a85ea4904f6704059d271587f0f0c1951993be7775"
}
```

### Sample 57: `4458ab2eb26c8c15`

| Field | Value |
|---|---|
| SHA-256 | `4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382` |
| Family label | `unknown` |
| File name | `macho_4458ab2eb26c.bin` |
| File type | `macho` |
| First seen | `2026-10-03 00:03:25` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93682fb10afccdd44a8151a9b4a1b820` |
| SHA-1 | `db9c63f8b364b063ce892d9dbb6a92a903974e76` |
| SHA-256 | `4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382` |
| SHA3-384 | `6145ccb99fed0c98872ba1cce9b1c9c2fbed40ad79c70004f797b000bcf5ddf031809539e61f982c8053a159e51fb32b` |
| TLSH | `T15A4502014E7294AAF6CCDA34322BDA278D61B170854A15EF63A25F988D343F3F51B35B` |
| SSDEEP | `24576:U3JwB+mxbXxUMul211mx6sRj2KQrTj50WC5Ev:UO4SuMu2c6Mzk6WCW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_4458ab2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382"
    family = "unknown"
    file_name = "macho_4458ab2eb26c.bin"
    file_type = "macho"
    first_seen = "2026-10-03 00:03:25"
  condition:
    hash.sha256(0, filesize) == "4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382"
}
```

### Sample 58: `9b5b7a6722b364ee`

| Field | Value |
|---|---|
| SHA-256 | `9b5b7a6722b364ee439fd71e154ee59bdda62fbebf9114401c9f2651b46e3655` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-10-02 23:55:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c58a60cb16e3f2a52036ddb0d103146e` |
| SHA-1 | `fc094fb2567b971e72da4d013a6a4f6b7b010139` |
| SHA-256 | `9b5b7a6722b364ee439fd71e154ee59bdda62fbebf9114401c9f2651b46e3655` |
| SHA3-384 | `714247077cafc4a6056f58fa628864d3ae0f7375cf6bfe634310784e999c83de675231b4242ce38f4b154bba9b7bf91c` |
| TLSH | `T17C935CC5F283D4F2ED5305B15036F7335732F1AA1129DA53E36DA936ACA1500D71ABAC` |
| TELFHASH | `t143511cff1e760cecb7e09904c71e17b62a1ad7bb152036b501b3986522f6dc590bac39` |
| SSDEEP | `1536:U8Gkv3ykfh35lXtyHd64onj7abZtBMKNQZS2FzIM62:Upkfykfp7Xt+ddyHabXBvmwKIM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_9b5b7a67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b5b7a6722b364ee439fd71e154ee59bdda62fbebf9114401c9f2651b46e3655"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-10-02 23:55:54"
  condition:
    hash.sha256(0, filesize) == "9b5b7a6722b364ee439fd71e154ee59bdda62fbebf9114401c9f2651b46e3655"
}
```

### Sample 59: `7705a0ce4ff92473`

| Field | Value |
|---|---|
| SHA-256 | `7705a0ce4ff924737575446b03f4b34d95d3650552ca5495ff6e5e103d68cff2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-02 23:53:55` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec6b6e28d2d75136f83ed1948ce43457` |
| SHA-1 | `1cad117c5e26276d742dae12a5dc9f9d338e651d` |
| SHA-256 | `7705a0ce4ff924737575446b03f4b34d95d3650552ca5495ff6e5e103d68cff2` |
| SHA3-384 | `71194a59dec48e849872fd750ca62ff538d92f18b4f1510865d454b2326c27202e5534bf855db858b209f629f1e99a44` |
| IMPHASH | `ff30e3be4c33e8cda9a10c7ce7282898` |
| TLSH | `T1C9869F03F66581E8C06EC1B5C35A9637E772B88E0920B7AF67E41B212F66F506F1D349` |
| SSDEEP | `98304:66m7RhdX/zZIoFXBZY5EF0dTRvPGPcWGgvZNjiz8Qx8Q7oZ+ZGhOODzlAC:YhdPzqFPAGUZNj4MhNzlAC` |
| ICON-DHASH | `f8336565514933cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_7705a0ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7705a0ce4ff924737575446b03f4b34d95d3650552ca5495ff6e5e103d68cff2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 23:53:55"
  condition:
    hash.sha256(0, filesize) == "7705a0ce4ff924737575446b03f4b34d95d3650552ca5495ff6e5e103d68cff2"
}
```

### Sample 60: `88ef20d6ef76a46c`

| Field | Value |
|---|---|
| SHA-256 | `88ef20d6ef76a46c70a2a29f41a91cdb95408902ff4ca778ff248ec78ff122df` |
| Family label | `unknown` |
| File name | `check1.sh` |
| File type | `sh` |
| First seen | `2026-10-02 23:48:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d123b27b962cb9559c97ebab9e9658a` |
| SHA-1 | `fcd06f69e557e8859e9216cad4b8f0c3e01ba29b` |
| SHA-256 | `88ef20d6ef76a46c70a2a29f41a91cdb95408902ff4ca778ff248ec78ff122df` |
| SHA3-384 | `0dda8bf9cf5f7e4c0402121217c1bf362dc5489d57b132031b322c607cae3b610bed02e731667c44afa211c06e9f5a1a` |
| TLSH | `T17F1192815626AC762CDC811D72E6945E5042022F065F3F9CB8DEA8B70F5C540F0A0BB4` |
| SSDEEP | `24:VUeYj+H1JAEDMK9CFdYhEnHQBYw9I5dApMApARiJ83AnQZaZl1cSRs/:VUeYj+H1JjDMK9CnYhEYSeMeuiJ8wOjJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_88ef20d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ef20d6ef76a46c70a2a29f41a91cdb95408902ff4ca778ff248ec78ff122df"
    family = "unknown"
    file_name = "check1.sh"
    file_type = "sh"
    first_seen = "2026-10-02 23:48:00"
  condition:
    hash.sha256(0, filesize) == "88ef20d6ef76a46c70a2a29f41a91cdb95408902ff4ca778ff248ec78ff122df"
}
```

### Sample 61: `6e03f1ce7db58a8e`

| Field | Value |
|---|---|
| SHA-256 | `6e03f1ce7db58a8e89f749d2030d2a4c99c6a1916c2308b54255d59d645b74ba` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-02 23:46:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5512b6e993f9ccad35a4e7753059c120` |
| SHA-1 | `3dbd7135d646711c4fbe1c64ce5f3d0dcac66b22` |
| SHA-256 | `6e03f1ce7db58a8e89f749d2030d2a4c99c6a1916c2308b54255d59d645b74ba` |
| SHA3-384 | `8fc535a414efa8f6561e3729a86573b004802a924951c9bcfb12441af9a246765b7c2b984b0050b23da196b78ef66572` |
| TLSH | `T16F460897B8D24942C4E4367BBCBD81C433631EBA9B8652566D05FE3C3ABE1D90E38354` |
| TELFHASH | `t1dee02b96ca8c27cc66d786a9429501658ead38f84620bba48ecfb35b1901440b0cd47a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:iXUyku/8phKC9t/0xiEQrMCiT23YHYy2I5EN:akH9tfd3YHVEN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_6e03f1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e03f1ce7db58a8e89f749d2030d2a4c99c6a1916c2308b54255d59d645b74ba"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-02 23:46:01"
  condition:
    hash.sha256(0, filesize) == "6e03f1ce7db58a8e89f749d2030d2a4c99c6a1916c2308b54255d59d645b74ba"
}
```

### Sample 62: `8f5606d46a9e39f9`

| Field | Value |
|---|---|
| SHA-256 | `8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77` |
| Family label | `Mirai` |
| File name | `8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77` |
| File type | `elf` |
| First seen | `2026-10-02 23:37:35` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75ea11c181e2ed809373b64f96cb4de6` |
| SHA-1 | `aa8ef3df4cad198651cb3acd6af2b7c1981825fb` |
| SHA-256 | `8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77` |
| SHA3-384 | `970b0da8015a39d2e18454b976c314bf11ec9a12c9cb3b6e084a119ccd8ae829fd452fcf56dff49ee39183ae4959b467` |
| TLSH | `T112041A8AFD81AF1586C527BBFE2E418A331317B8D2EE71129D141F2877CA94F0E76542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDPn:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_8f5606d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77"
    family = "Mirai"
    file_name = "8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77"
    file_type = "elf"
    first_seen = "2026-10-02 23:37:35"
  condition:
    hash.sha256(0, filesize) == "8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77"
}
```

### Sample 63: `917ff018b3ac8741`

| Field | Value |
|---|---|
| SHA-256 | `917ff018b3ac87413e2210dd8b3beab5e642990c9656d257c8ebfae48b86a9ad` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-10-02 23:32:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b399a892c02b97ecb36d5126d315723` |
| SHA-1 | `22c9eb4edc4d9e2d72145f470b456596e1927450` |
| SHA-256 | `917ff018b3ac87413e2210dd8b3beab5e642990c9656d257c8ebfae48b86a9ad` |
| SHA3-384 | `ea4699e704aa29bc7bcbb8f1f9eb663bfd1576dfccf5b18b44c04ae5be4c44b3936db32dd82f1a9671ecadf3d8cd1a5b` |
| TLSH | `T107E32AD7F900DABEF80AE33648530806B130BBD211925B373357796BED3A1991977E86` |
| SSDEEP | `3072:3uLxvGEdHe9bVEkzr37XVbWroOVOjbi9LI0VynPeRw:36Ny1VEkzz7EroML5ynGRw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_917ff018
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "917ff018b3ac87413e2210dd8b3beab5e642990c9656d257c8ebfae48b86a9ad"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-10-02 23:32:05"
  condition:
    hash.sha256(0, filesize) == "917ff018b3ac87413e2210dd8b3beab5e642990c9656d257c8ebfae48b86a9ad"
}
```

### Sample 64: `a138a9724a77dad1`

| Field | Value |
|---|---|
| SHA-256 | `a138a9724a77dad169312f39e94269413555448ec89ffc73b55a51cb4ccc3e25` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-02 23:32:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d95ae130c333b9e80a7bfa00827769c` |
| SHA-1 | `c12bea6850c049d3cfbd79af1fd6d8aad2e52396` |
| SHA-256 | `a138a9724a77dad169312f39e94269413555448ec89ffc73b55a51cb4ccc3e25` |
| SHA3-384 | `920923184c9424907adec91cea5886803deb8bf9da85713d7bc7cee0932b2e6ee43ec07be7a9f7d27035ee25ac8d8e4f` |
| TLSH | `T191463911FECB14F2E9031A3115ABA26F63315D058F24EBD7EB547F29F97B6A10832249` |
| TELFHASH | `t1a0d2dfb3159d94ec67e0840396af7620cff6e03726f0787159f7b8c09672d53aa26878` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:KMsA/tLT7mqifjb04RD+aDdVFshaTVfhd1AA4mh0Alc0BtViMVgxyENFqZ5Eu:lb/tLTqJj7RDsA1h/6Alc0BNcnqPEu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_a138a972
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a138a9724a77dad169312f39e94269413555448ec89ffc73b55a51cb4ccc3e25"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-02 23:32:03"
  condition:
    hash.sha256(0, filesize) == "a138a9724a77dad169312f39e94269413555448ec89ffc73b55a51cb4ccc3e25"
}
```

### Sample 65: `14896331c3585918`

| Field | Value |
|---|---|
| SHA-256 | `14896331c3585918ef42074368d2a9033e8d84e0e30dc669d17dccb74e052f00` |
| Family label | `Mirai` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-10-02 23:29:55` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fdaf0614336ff33861762137cd82db3` |
| SHA-1 | `0978653ad336aca667fe8384d86cb406c4fb8ffd` |
| SHA-256 | `14896331c3585918ef42074368d2a9033e8d84e0e30dc669d17dccb74e052f00` |
| SHA3-384 | `d4dad315948257139a17e7f720356f333c791eb084fb8a324443d382d6cab4374179a2c0a2a1e1c8453246b689c095b9` |
| TLSH | `T1B141B98BA2E090B3C46EFD41F35494C4E0DD8EC361E7AEBCF8B45562589920CF196F66` |
| SSDEEP | `48:ZscUrtCZaAIq6wpOpP8/SiKPpUKP8S2v9w2v4+7sJHph8kXt:KF6DIHvz9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_14896331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14896331c3585918ef42074368d2a9033e8d84e0e30dc669d17dccb74e052f00"
    family = "Mirai"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-10-02 23:29:55"
  condition:
    hash.sha256(0, filesize) == "14896331c3585918ef42074368d2a9033e8d84e0e30dc669d17dccb74e052f00"
}
```

### Sample 66: `319247509e503f1b`

| Field | Value |
|---|---|
| SHA-256 | `319247509e503f1b2b9efaf0b422e50fce59cd078ac3a683b41f44933a08dd58` |
| Family label | `Mirai` |
| File name | `android_arm64` |
| File type | `elf` |
| First seen | `2026-10-02 23:27:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c706ba800d85bf053a36a07c81321da` |
| SHA-1 | `d50c8c9f652b3da370fc47ae73b05b1d64e95283` |
| SHA-256 | `319247509e503f1b2b9efaf0b422e50fce59cd078ac3a683b41f44933a08dd58` |
| SHA3-384 | `1a6e0536dd249aa59014eb05475a7bad961916518e002f25d62937febe2031e525d321d0417868b9583f17814abc4772` |
| TLSH | `T1CF26286DFC0DE452EEC863746BA187D232397C84CF42D6136221FA6EB5F73949E52122` |
| GIMPHASH | `4e4e737435fb152839b5e52f4f64d9b3b3b992e6cde986ec91835a220e8215bd` |
| SSDEEP | `24576:TL9aBkFeereoGtZb4hcp9scEZJn77TBWJYvifAOXEletssv+tXk59yjy/7j7rfLz:ToBSrApvYKrkosgT5EUT8+I/0dQB1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_31924750
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "319247509e503f1b2b9efaf0b422e50fce59cd078ac3a683b41f44933a08dd58"
    family = "Mirai"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-10-02 23:27:57"
  condition:
    hash.sha256(0, filesize) == "319247509e503f1b2b9efaf0b422e50fce59cd078ac3a683b41f44933a08dd58"
}
```

### Sample 67: `7cbe938005ad2851`

| Field | Value |
|---|---|
| SHA-256 | `7cbe938005ad28519a08d978e64f3108a593876232e6a4c9a8b3db228ac3091f` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-10-02 23:23:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63081ccb239c6c70d41dd4e1a6dfaadd` |
| SHA-1 | `cddb79462c39b5be8901f244b4d74a23a79d1bc5` |
| SHA-256 | `7cbe938005ad28519a08d978e64f3108a593876232e6a4c9a8b3db228ac3091f` |
| SHA3-384 | `a49b42ee0611bfcc410c5e2aef72813d8ccb0a6513d649981317b52e29ad73a1d9f82585f5ed7062a9f6d3f585b3f0a4` |
| TLSH | `T1CE142B46EA404B13C0D627B9F6EF42463333E76497E773069524ABB43F8679E4F22A05` |
| TELFHASH | `t1063120b19779112aaaa1dc24ddec47b3652ac7171300ff32df26c0cc281a44af62ac4f` |
| SSDEEP | `3072:0Bt0yPgT2VMWSMx25HaPMM4C5WQOSpGALkS+hxUo1M/RkzGIW:g0TwMWfk5HaPMM4C80LkS+XZ1M/RYGB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_7cbe9380
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cbe938005ad28519a08d978e64f3108a593876232e6a4c9a8b3db228ac3091f"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-10-02 23:23:58"
  condition:
    hash.sha256(0, filesize) == "7cbe938005ad28519a08d978e64f3108a593876232e6a4c9a8b3db228ac3091f"
}
```

### Sample 68: `13e2d4fe752561dc`

| Field | Value |
|---|---|
| SHA-256 | `13e2d4fe752561dcfc13f45c9302e8bb3d6ac89405af144b3144e04d1579b64e` |
| Family label | `Mirai` |
| File name | `main_mips` |
| File type | `elf` |
| First seen | `2026-10-02 23:22:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c85010a0e3d1b546fbe871b9c03801ea` |
| SHA-1 | `92354f07eaa6161e5920e49bd26e2f62d3b27c5e` |
| SHA-256 | `13e2d4fe752561dcfc13f45c9302e8bb3d6ac89405af144b3144e04d1579b64e` |
| SHA3-384 | `970db0061c44c6f2d020248390f1c4e49e36606d7aae594f81c565a5dcc25532b67a530f3c676480bf1ba6850b742e65` |
| TLSH | `T15C04971E6E228F7DF668873147B78E25976C23D627E1D641E1ACC1102E2439E641FFAC` |
| TELFHASH | `t1e64196181e7817b4a3356c4a199cff3796a730db7e126d378e11f86aab79a835d10c0c` |
| SSDEEP | `3072:/wgcoVAi6F3g4W0qCSM/ExddTqN08vY2ZXWi:/wgcoVVkTNIjq9vbZXWi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_13e2d4fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13e2d4fe752561dcfc13f45c9302e8bb3d6ac89405af144b3144e04d1579b64e"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-10-02 23:22:01"
  condition:
    hash.sha256(0, filesize) == "13e2d4fe752561dcfc13f45c9302e8bb3d6ac89405af144b3144e04d1579b64e"
}
```

### Sample 69: `fed71588688e9b44`

| Field | Value |
|---|---|
| SHA-256 | `fed71588688e9b44f975c184ee74acd701f84a05c23fa84b3c75f748e75ef39f` |
| Family label | `Mirai` |
| File name | `amd64` |
| File type | `elf` |
| First seen | `2026-10-02 23:22:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca1b26ac2beadec62b7a074f226f243a` |
| SHA-1 | `c13f6b491e1f55d29418b407884c5716190dc42f` |
| SHA-256 | `fed71588688e9b44f975c184ee74acd701f84a05c23fa84b3c75f748e75ef39f` |
| SHA3-384 | `81ca403d3017e0ba980b1ddf36f5d04963ffd8257a6841305240cfad8850ec7d932e8bb3d1820cb364bdac6a897dbde4` |
| TLSH | `T1A2465B17ECA159E5C0EEE63086629253BA71BC485B3123D72F50F7382F76BD06AB9740` |
| TELFHASH | `t18752ac7459bd34b5b6aac911f3a3b4b4963318a576f434f41023a980ffc1e805cea87b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:gAB6Ydd60o0uanvjjVax8/ZPSv7QAh6TRks8cdDRe8eI4zgNSy1n8P6A/DMSHKQ0:gAFTpBVPNCs8qReXFazL7SksqE0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_fed71588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fed71588688e9b44f975c184ee74acd701f84a05c23fa84b3c75f748e75ef39f"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-10-02 23:22:00"
  condition:
    hash.sha256(0, filesize) == "fed71588688e9b44f975c184ee74acd701f84a05c23fa84b3c75f748e75ef39f"
}
```

### Sample 70: `2f6088d935286e13`

| Field | Value |
|---|---|
| SHA-256 | `2f6088d935286e13b3711d51cce302340bff48d82475cb89bfc75d7f05ebede2` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-10-02 23:21:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0ed0e15d53fa08c6359ec045703599d` |
| SHA-1 | `ea131573c9d8e4f9d5745b8a76c21511769205a0` |
| SHA-256 | `2f6088d935286e13b3711d51cce302340bff48d82475cb89bfc75d7f05ebede2` |
| SHA3-384 | `8bc5020d7b8f0036ef8c9779eb239e2f35c3668e6edda61161bcaddd99ecb507b4a71e90b8b4564cec297ddd429ce598` |
| TLSH | `T1D3E31A46F8809B12D5D111BAFE1E124E37231B78E3DF72129D246B747B8A97B0E3B905` |
| TELFHASH | `t196d0c206de1836d82fa0204a829de12797e0a98a3f051c0a87e69f4f8812ae53d0589e` |
| SSDEEP | `3072:GbJLYCcfSUII56+tkGHbTEaiSKb/P1HcJYLsXwo:4LnbvR+tkCb4auLxcJYLsXwo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_2f6088d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6088d935286e13b3711d51cce302340bff48d82475cb89bfc75d7f05ebede2"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-10-02 23:21:58"
  condition:
    hash.sha256(0, filesize) == "2f6088d935286e13b3711d51cce302340bff48d82475cb89bfc75d7f05ebede2"
}
```

### Sample 71: `681817158553beed`

| Field | Value |
|---|---|
| SHA-256 | `681817158553beede00a5fd1225912d3e0740c6337853a62f65927e8f0f12010` |
| Family label | `unknown` |
| File name | `boss` |
| File type | `elf` |
| First seen | `2026-10-02 23:20:00` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89a79361860c083b866fc87fc60acd44` |
| SHA-1 | `790094344464c3eb69d3edffa0cdd609d5d66e70` |
| SHA-256 | `681817158553beede00a5fd1225912d3e0740c6337853a62f65927e8f0f12010` |
| SHA3-384 | `140f9db3a2b65e456f32f1c39ee73632863cb6f13163e23e864ce2bbe11d2b45f55e313da7788d8c809151c39f382975` |
| TLSH | `T165B57C177CE118AAC0AA93328DB251A27BB1FC490B7123D72E50B3782F727D45E75798` |
| TELFHASH | `t1f6b00121eb906524a6b1da0a6a533e48b46a31e5b0756164299f6101b61c64526d3004` |
| SSDEEP | `49152:6+79iGrojuvj3pBho9Z/EaQJottSsAd7Mgy:rJ/PsAZMd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_68181715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "681817158553beede00a5fd1225912d3e0740c6337853a62f65927e8f0f12010"
    family = "unknown"
    file_name = "boss"
    file_type = "elf"
    first_seen = "2026-10-02 23:20:00"
  condition:
    hash.sha256(0, filesize) == "681817158553beede00a5fd1225912d3e0740c6337853a62f65927e8f0f12010"
}
```

### Sample 72: `01be4a4dbee15e0f`

| Field | Value |
|---|---|
| SHA-256 | `01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42` |
| Family label | `unknown` |
| File name | `01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 23:18:03` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4168b8f7086eca0cbbd9ccb27e3b4d63` |
| SHA-256 | `01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_01be4a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42"
    family = "unknown"
    file_name = "01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 23:18:03"
  condition:
    hash.sha256(0, filesize) == "01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42"
}
```

### Sample 73: `750922eb0a7eb9fd`

| Field | Value |
|---|---|
| SHA-256 | `750922eb0a7eb9fdac0405bd2aaee3932b2ce82f6609ba0a7c443a5c861007ca` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-10-02 23:17:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `540d40ddd6ca8589506079966a7adc91` |
| SHA-1 | `924c3ebc1a93dddfc30cff7bb1b70666f23535e2` |
| SHA-256 | `750922eb0a7eb9fdac0405bd2aaee3932b2ce82f6609ba0a7c443a5c861007ca` |
| SHA3-384 | `c56344595e2e45d3b3b757cee35dca3f2167627bce103f8d6dc78bbca313cd63ef08295e98d24c3779b957a111800358` |
| TLSH | `T19004E91AAB510FFBDCAFDD3706E9070139CC654B22A53B363674D528F54A50B4AE3CA8` |
| SSDEEP | `1536:NrQXTqDSFBOzjgpbICPEIwfvKgm/carSODrSvGughiXus/Z4ukT7McCU5YuLOlo0:JDk4gpbRZd/Pc//iRCUtLifd5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_750922eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "750922eb0a7eb9fdac0405bd2aaee3932b2ce82f6609ba0a7c443a5c861007ca"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-02 23:17:57"
  condition:
    hash.sha256(0, filesize) == "750922eb0a7eb9fdac0405bd2aaee3932b2ce82f6609ba0a7c443a5c861007ca"
}
```

### Sample 74: `d5dc4b7d2756198b`

| Field | Value |
|---|---|
| SHA-256 | `d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462` |
| Family label | `unknown` |
| File name | `d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 23:13:09` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10583566ee46c512aea62541083122cf` |
| SHA-256 | `d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_d5dc4b7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462"
    family = "unknown"
    file_name = "d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 23:13:09"
  condition:
    hash.sha256(0, filesize) == "d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462"
}
```

### Sample 75: `608f566ed3a2432a`

| Field | Value |
|---|---|
| SHA-256 | `608f566ed3a2432a756772e789cabce55561cf47a5c5c166ac61060a2906c8d6` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-02 23:05:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8d76f0e07191359b3216576a08d11dd` |
| SHA-1 | `db6045eaafbfe4499c5ae9d83097c6b9b6d587e5` |
| SHA-256 | `608f566ed3a2432a756772e789cabce55561cf47a5c5c166ac61060a2906c8d6` |
| SHA3-384 | `2dd397e2ff52b8ba47dbc19b943a3360e61858556f4d1ae04025b7548d9bb8b5c26503b9302f88cd6b3d0c8c217f67d7` |
| TLSH | `T1C5261A57B8918A43C4E4267ABCBDC1C433672EB99B9722576D00FE3D3ABE1990E35704` |
| TELFHASH | `t1f890028a24455198b25444180814f06ed050517d551f2974c56148048209dd510d1c5b` |
| GIMPHASH | `69788f45be79c81dafe952bf647cc321d85f345475523a7a4b714c321147722e` |
| SSDEEP | `49152:TDPmrqixkgJutCxp3bWHfyIEMw6mx2YU1F1:XPmPxkyutc3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_608f566e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608f566ed3a2432a756772e789cabce55561cf47a5c5c166ac61060a2906c8d6"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-02 23:05:58"
  condition:
    hash.sha256(0, filesize) == "608f566ed3a2432a756772e789cabce55561cf47a5c5c166ac61060a2906c8d6"
}
```

### Sample 76: `230f9377c60d8545`

| Field | Value |
|---|---|
| SHA-256 | `230f9377c60d8545d99f41876fa3bd0ff0557b3ae0d39565159cc5b78c936fde` |
| Family label | `unknown` |
| File name | `3475ebc4c8d569fe27690e4a5ed80076.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 23:00:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3475ebc4c8d569fe27690e4a5ed80076` |
| SHA-256 | `230f9377c60d8545d99f41876fa3bd0ff0557b3ae0d39565159cc5b78c936fde` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_230f9377
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230f9377c60d8545d99f41876fa3bd0ff0557b3ae0d39565159cc5b78c936fde"
    family = "unknown"
    file_name = "3475ebc4c8d569fe27690e4a5ed80076.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 23:00:12"
  condition:
    hash.sha256(0, filesize) == "230f9377c60d8545d99f41876fa3bd0ff0557b3ae0d39565159cc5b78c936fde"
}
```

### Sample 77: `4d8efc4528dd2088`

| Field | Value |
|---|---|
| SHA-256 | `4d8efc4528dd2088d72c68fa693ea22a2fc5946820aab9745ed77f85fa9265d4` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-02 22:54:21` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, RemusStealer, signed, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebe14cc775229b3fc11ca51fc65d4500` |
| SHA-1 | `2d7f716b6e06a5a76e22d45e1622c44c10aa05c0` |
| SHA-256 | `4d8efc4528dd2088d72c68fa693ea22a2fc5946820aab9745ed77f85fa9265d4` |
| SHA3-384 | `09a297327b11154543cae781519ab2af886c2f0166c74af83e08e23382291c797d1a60e97c73fbf0f6fa30f961eaa575` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T17A96A103374C00DCC853EE7480B19A7961B07CDD95357A4B9EA57EA42F2A3946BFEB06` |
| SSDEEP | `49152:4Px8zBjGtgyg9kYkHSvuBiE+AReOYPygaxKW0WPHKYlhnl:lN9z4nl` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_077_4d8efc45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d8efc4528dd2088d72c68fa693ea22a2fc5946820aab9745ed77f85fa9265d4"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:54:21"
  condition:
    hash.sha256(0, filesize) == "4d8efc4528dd2088d72c68fa693ea22a2fc5946820aab9745ed77f85fa9265d4"
}
```

### Sample 78: `049b268f6fe7dee8`

| Field | Value |
|---|---|
| SHA-256 | `049b268f6fe7dee81651ff0d3ddc72b205f465c9aba3e57e9222fe9c5eadff88` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-02 22:53:44` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14e73b958f688f529144dbd881608f72` |
| SHA-1 | `f14b16929621b537dba11a79ecfe8bc2544b42b1` |
| SHA-256 | `049b268f6fe7dee81651ff0d3ddc72b205f465c9aba3e57e9222fe9c5eadff88` |
| SHA3-384 | `0679df20bcba13c2b40ed240cc51cdab637f6840dbff3e2e25605409f448b6ece420cb404d96be76fc381795f3477028` |
| IMPHASH | `672bff0d668d8425dce5b5bf2bf7b41e` |
| TLSH | `T160E33A4B73A530F9E267D23885A21642F77278311B619BDF03A0477A1E233D59E3BB61` |
| SSDEEP | `3072:G3vFnk/Z2riGlYup6WUo1QMe42KgW1oH/Lbw:G3v6yR6WE4tqo` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_078_049b268f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049b268f6fe7dee81651ff0d3ddc72b205f465c9aba3e57e9222fe9c5eadff88"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:53:44"
  condition:
    hash.sha256(0, filesize) == "049b268f6fe7dee81651ff0d3ddc72b205f465c9aba3e57e9222fe9c5eadff88"
}
```

### Sample 79: `f663aaab15536ac4`

| Field | Value |
|---|---|
| SHA-256 | `f663aaab15536ac4bf5b2f7547470c256faf171149d3ede5dd0199e762bf2792` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-10-02 22:53:38` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d81498ffdbcc8d72fab7cd46f9352918` |
| SHA-256 | `f663aaab15536ac4bf5b2f7547470c256faf171149d3ede5dd0199e762bf2792` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_f663aaab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f663aaab15536ac4bf5b2f7547470c256faf171149d3ede5dd0199e762bf2792"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-10-02 22:53:38"
  condition:
    hash.sha256(0, filesize) == "f663aaab15536ac4bf5b2f7547470c256faf171149d3ede5dd0199e762bf2792"
}
```

### Sample 80: `48bb8a6a2867528f`

| Field | Value |
|---|---|
| SHA-256 | `48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00` |
| Family label | `unknown` |
| File name | `48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00.bin` |
| File type | `zip` |
| First seen | `2026-10-02 22:48:31` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a076710ce3fac18540ec3c47fc264efc` |
| SHA-1 | `3c9606da4eecdb12e544d1549d90f11a894c5d76` |
| SHA-256 | `48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00` |
| SHA3-384 | `8ff81bb4dc3e4007eb2ba73ae575c9385334f1e4bf93c57b9ebe368a2d154f97441981326381a6adf9eb88667a0fb612` |
| TLSH | `T16784230C26AE204EFA99800ABD0A3AB901DD0C3E5FF9A54F5D75C89D68D6E4CFD4F154` |
| SSDEEP | `6144:9BYVj2sHzAkqfQVrDaSGhFndfDGxDUzXIPayLHTDpk+YRR+0vS0C3Oaub:9BwasTATQZsFEUzYCaTDpk+J060ZaK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_48bb8a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00"
    family = "unknown"
    file_name = "48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00.bin"
    file_type = "zip"
    first_seen = "2026-10-02 22:48:31"
  condition:
    hash.sha256(0, filesize) == "48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00"
}
```

### Sample 81: `53a00597ffb492b2`

| Field | Value |
|---|---|
| SHA-256 | `53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a` |
| Family label | `unknown` |
| File name | `53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 22:48:25` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b71f15d52e7f24d0258192da922e23f3` |
| SHA-256 | `53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_53a00597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a"
    family = "unknown"
    file_name = "53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 22:48:25"
  condition:
    hash.sha256(0, filesize) == "53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a"
}
```

### Sample 82: `f0b5bc2220408f6d`

| Field | Value |
|---|---|
| SHA-256 | `f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e` |
| Family label | `unknown` |
| File name | `f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 22:48:21` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19c3c98ee43c72f82beab71d5d875e6f` |
| SHA-256 | `f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_f0b5bc22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e"
    family = "unknown"
    file_name = "f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 22:48:21"
  condition:
    hash.sha256(0, filesize) == "f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e"
}
```

### Sample 83: `fd925cbfbeaeaac0`

| Field | Value |
|---|---|
| SHA-256 | `fd925cbfbeaeaac0cc2b5a30a5d89f0e44a341d8eb907f022805ce5bd0c05262` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-10-02 22:47:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89c8cfa43a48b64725dc0c61d666aba6` |
| SHA-1 | `8e596455321f179a49b66bc8a9b476d6c4202b9c` |
| SHA-256 | `fd925cbfbeaeaac0cc2b5a30a5d89f0e44a341d8eb907f022805ce5bd0c05262` |
| SHA3-384 | `538a57bef19a74948b9ee4c652e2daf7c03214eebae8686c5df12a7d1ee8e056c20dd9df50a2348437b07cabd11b14ce` |
| TLSH | `T1CDC36B73D8262F58D529D0B0B0B18F781F53A991914B5FBB1AB6C2B44087D8DF605BF8` |
| SSDEEP | `1536:McTVDdrsjiiQKmV1KcJli3MgACi+KdkYD7sOL9ET6eEdW52CyvfWEWF:McJde7QNVUqliXAfxdt19ECdWUCS7O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_fd925cbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd925cbfbeaeaac0cc2b5a30a5d89f0e44a341d8eb907f022805ce5bd0c05262"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-02 22:47:55"
  condition:
    hash.sha256(0, filesize) == "fd925cbfbeaeaac0cc2b5a30a5d89f0e44a341d8eb907f022805ce5bd0c05262"
}
```

### Sample 84: `018c84e8df20153f`

| Field | Value |
|---|---|
| SHA-256 | `018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d` |
| Family label | `unknown` |
| File name | `018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d` |
| File type | `elf` |
| First seen | `2026-10-02 22:42:42` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `396fd95a88d55d234e68e90392acedb5` |
| SHA-1 | `4d7186d0ba53817af88a9449ea1bdda592041df2` |
| SHA-256 | `018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d` |
| SHA3-384 | `1c43b18d6e8856edb6d5d8c705bdcfa69c485e97a585989873236349c8cb4fe56e1a255ce77d419fc27db82afd8f17e3` |
| TLSH | `T1AFB3124AFF359D0A8B0009B31BDE9E9E9C6D7B6B42CBB4A469C1954F53D01CE7D93204` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+VW:phNlHuBafLeBtfCzpta8xlBIOdVW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_018c84e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d"
    family = "unknown"
    file_name = "018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d"
    file_type = "elf"
    first_seen = "2026-10-02 22:42:42"
  condition:
    hash.sha256(0, filesize) == "018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d"
}
```

### Sample 85: `18c6d69109732425`

| Field | Value |
|---|---|
| SHA-256 | `18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27` |
| Family label | `Mirai` |
| File name | `18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27` |
| File type | `elf` |
| First seen | `2026-10-02 22:42:35` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6098a3dbe92d6689ce76a6c0d779ff7e` |
| SHA-1 | `c5f7ae15c6a441ace5a76445511207586971bb3d` |
| SHA-256 | `18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27` |
| SHA3-384 | `4f106932872f44dab5699a619cd70d30b61c1ac8227078043bbde56a7bd46339f5f9971891785b4beceba47972ca4683` |
| TLSH | `T19704198AFD81AF5585C527BBFE2E418A331317B8D2EE71129D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDPV:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_18c6d691
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27"
    family = "Mirai"
    file_name = "18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27"
    file_type = "elf"
    first_seen = "2026-10-02 22:42:35"
  condition:
    hash.sha256(0, filesize) == "18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27"
}
```

### Sample 86: `5187141cdfa53a30`

| Field | Value |
|---|---|
| SHA-256 | `5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937` |
| Family label | `unknown` |
| File name | `5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937` |
| File type | `elf` |
| First seen | `2026-10-02 22:25:31` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b1b86faf0bfbef069e8316349bb8fb4` |
| SHA-1 | `c9799b51f0a9aeab98047630bd68598825b04777` |
| SHA-256 | `5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937` |
| SHA3-384 | `33fa48f352977ee7b02ab9e6e4662b501905279d539d0fd60d1385b9991b6221f09e37958aa250c9f8614527ae5bd4dd` |
| TLSH | `T15227CE77914338E9E5A98DB4D01025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQL:cqYUQuVDt0TZEI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_5187141c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937"
    family = "unknown"
    file_name = "5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937"
    file_type = "elf"
    first_seen = "2026-10-02 22:25:31"
  condition:
    hash.sha256(0, filesize) == "5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937"
}
```

### Sample 87: `a9c759ea8ea13df9`

| Field | Value |
|---|---|
| SHA-256 | `a9c759ea8ea13df937b0d7dc7971aec13028f8953a26c620c2f6b7009fb9fea8` |
| Family label | `unknown` |
| File name | `2fb43e665156aa6153b0f6ec8ece9ce8.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 22:20:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fb43e665156aa6153b0f6ec8ece9ce8` |
| SHA-256 | `a9c759ea8ea13df937b0d7dc7971aec13028f8953a26c620c2f6b7009fb9fea8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_a9c759ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9c759ea8ea13df937b0d7dc7971aec13028f8953a26c620c2f6b7009fb9fea8"
    family = "unknown"
    file_name = "2fb43e665156aa6153b0f6ec8ece9ce8.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 22:20:04"
  condition:
    hash.sha256(0, filesize) == "a9c759ea8ea13df937b0d7dc7971aec13028f8953a26c620c2f6b7009fb9fea8"
}
```

### Sample 88: `b7971b42ff2d71e9`

| Field | Value |
|---|---|
| SHA-256 | `b7971b42ff2d71e9ca71cb85b42e3105456204a3ca133ddc79b7f37938065464` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-02 22:17:51` |
| Reporter | `Bitsight` |
| Tags | `579cd0, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4d64e757fb48fd7292e284b34bf563d` |
| SHA-1 | `0c32e6af8d92293da882ad4d10cd89d828a96571` |
| SHA-256 | `b7971b42ff2d71e9ca71cb85b42e3105456204a3ca133ddc79b7f37938065464` |
| SHA3-384 | `06eb729f9a8cd94c5e4f5052afa7b2347f61813ae81f7a9126164fbbdb6374766dff4a09178691632fbdf95cb116c918` |
| IMPHASH | `c6cda690056e5ae86457a7af7e9f6d47` |
| TLSH | `T12C05CF27F99941E4CFBDB07724ADB2009788B712AFA7B07D3A8F34473051C9BA569706` |
| SSDEEP | `24576:cEKSWolOmzspGGmVqoPjCE8WEQP6AF1FNYo:KSWolSpOVqoPjCuEuh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_b7971b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7971b42ff2d71e9ca71cb85b42e3105456204a3ca133ddc79b7f37938065464"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:17:51"
  condition:
    hash.sha256(0, filesize) == "b7971b42ff2d71e9ca71cb85b42e3105456204a3ca133ddc79b7f37938065464"
}
```

### Sample 89: `d39be9b1c8bdca49`

| Field | Value |
|---|---|
| SHA-256 | `d39be9b1c8bdca49b3d814849ae507df280c6fe967e5c08fadfdc81d6f2f1cbc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-02 22:13:15` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX10.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06d5333f7d48aede561155bc021ebadd` |
| SHA-1 | `b64bc5e7c9b85a2415866a9ad058dbeef93df01d` |
| SHA-256 | `d39be9b1c8bdca49b3d814849ae507df280c6fe967e5c08fadfdc81d6f2f1cbc` |
| SHA3-384 | `9686a655c10be1b3737344c990e2e413b95b3928d04787d49d68459ba27686dfaa5f83839a8d37a9b8399cc2b2fa54ec` |
| IMPHASH | `1c8506581759e6cc7d372a1695f4abcd` |
| TLSH | `T110C69D19FBA914F9E177C17CC9530905EA72BC460761ABCF23A05AA61F236E09E3F711` |
| SSDEEP | `6144:Y0D2u8nLpFNNvvDqz3blJYZYE1jm1euRQzJpGKAx0:uu+K30ZYAmvKF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_d39be9b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d39be9b1c8bdca49b3d814849ae507df280c6fe967e5c08fadfdc81d6f2f1cbc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:13:15"
  condition:
    hash.sha256(0, filesize) == "d39be9b1c8bdca49b3d814849ae507df280c6fe967e5c08fadfdc81d6f2f1cbc"
}
```

### Sample 90: `74e553523ca8afec`

| Field | Value |
|---|---|
| SHA-256 | `74e553523ca8afec8e56befc4b2f8edbf62fd5ead04c44ade595fc99ecc56ad0` |
| Family label | `unknown` |
| File name | `Bin.zip` |
| File type | `zip` |
| First seen | `2026-10-02 22:09:26` |
| Reporter | `TeamNAIT` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21c86ab2986abbb3f076ade2c4ac12b3` |
| SHA-256 | `74e553523ca8afec8e56befc4b2f8edbf62fd5ead04c44ade595fc99ecc56ad0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_74e55352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e553523ca8afec8e56befc4b2f8edbf62fd5ead04c44ade595fc99ecc56ad0"
    family = "unknown"
    file_name = "Bin.zip"
    file_type = "zip"
    first_seen = "2026-10-02 22:09:26"
  condition:
    hash.sha256(0, filesize) == "74e553523ca8afec8e56befc4b2f8edbf62fd5ead04c44ade595fc99ecc56ad0"
}
```

### Sample 91: `54bce16e7f24ca76`

| Field | Value |
|---|---|
| SHA-256 | `54bce16e7f24ca7683a29fadd0f9b6d6a838c16f797dc610f5ec5b63fa6cc532` |
| Family label | `unknown` |
| File name | `RFQ.hta` |
| File type | `unknown` |
| First seen | `2026-10-02 22:01:12` |
| Reporter | `rifteyy` |
| Tags | `action1, downloader, rmm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ef63197210f7e4c19fd11757e4a04bb` |
| SHA-1 | `d0e1248704917deae6eaa9267f1127a6b35f6034` |
| SHA-256 | `54bce16e7f24ca7683a29fadd0f9b6d6a838c16f797dc610f5ec5b63fa6cc532` |
| SHA3-384 | `51fd4933f3e2e94cc39c1b9a9cbc48eaa56d11cb6fdd48a5bab49de47c7605fce9d367bea99b3033e9d1a1c81207b425` |
| TLSH | `T1347152A3644C5168A6B163295B9ED444FABBD5620704F6F0F0C8E7801E2897543BBEFD` |
| SSDEEP | `96:OEh0NnMKAi/Hju6exAL6Jnu6Aqirwcf0iJP:T0NnMKN/HjzeOuJnu6AqKwVC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_54bce16e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54bce16e7f24ca7683a29fadd0f9b6d6a838c16f797dc610f5ec5b63fa6cc532"
    family = "unknown"
    file_name = "RFQ.hta"
    file_type = "unknown"
    first_seen = "2026-10-02 22:01:12"
  condition:
    hash.sha256(0, filesize) == "54bce16e7f24ca7683a29fadd0f9b6d6a838c16f797dc610f5ec5b63fa6cc532"
}
```

### Sample 92: `245f16270bf0dfec`

| Field | Value |
|---|---|
| SHA-256 | `245f16270bf0dfece1ac13f06e2554d059f82b6bc53b1f19b0d835f409b5d80f` |
| Family label | `unknown` |
| File name | `payment-receipt.pdf` |
| File type | `pdf` |
| First seen | `2026-10-02 22:00:10` |
| Reporter | `rifteyy` |
| Tags | `action1, fake-receipt, fake-update, pdf, rmm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5754058e75aa7cc6377c87000e20bb97` |
| SHA-1 | `b09f2053acf98eef4475f9394945170386b50b42` |
| SHA-256 | `245f16270bf0dfece1ac13f06e2554d059f82b6bc53b1f19b0d835f409b5d80f` |
| SHA3-384 | `579827b417dc122ecd6a3b12d62a5e0e06e084322af4d320ec243edf231f0277e57a5cc74d87e4cd589a31656a5bb33b` |
| TLSH | `T15D040717CC184987A57987BDBE171FBC6F1D3E18E8863BEB11310E867A706225C5F06A` |
| SSDEEP | `3072:/eg7Lq4tQz/oli0r7UjPXIHRewnN5wONOwXBaztzTt:h7LqeQz0i0k0HReoWHN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `pdf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_245f1627
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245f16270bf0dfece1ac13f06e2554d059f82b6bc53b1f19b0d835f409b5d80f"
    family = "unknown"
    file_name = "payment-receipt.pdf"
    file_type = "pdf"
    first_seen = "2026-10-02 22:00:10"
  condition:
    hash.sha256(0, filesize) == "245f16270bf0dfece1ac13f06e2554d059f82b6bc53b1f19b0d835f409b5d80f"
}
```

### Sample 93: `81d47792fc2ed00b`

| Field | Value |
|---|---|
| SHA-256 | `81d47792fc2ed00ba990d0e6a21b6df184bb309a2315a20d1dd2ee214cadd67e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-02 21:49:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4cfd1d9773fea519fe91d2caa96a60a` |
| SHA-1 | `480675d7157f832e2783d97ad091f16da05cf3e0` |
| SHA-256 | `81d47792fc2ed00ba990d0e6a21b6df184bb309a2315a20d1dd2ee214cadd67e` |
| SHA3-384 | `9ef3c1a1c95f1136e70dcdd1d99fc4877d373bef01b90b0901767451fd685be9713d999b232a56aa44152bede2eb972a` |
| TLSH | `T189262957B8928683C4E4367AA8BDC1C433631EB99B9723576D04FE3D3ABE1990E35314` |
| TELFHASH | `t1aec04cc51a3c32469347c900476a2516b7a761f0146461e8ee57a9175f67842b0998be` |
| GIMPHASH | `69788f45be79c81dafe952bf647cc321d85f345475523a7a4b714c321147722e` |
| SSDEEP | `49152:bk/x9iMG54PamkCK65OUV4FXhw1ofFrI5lsU1F1:I/xUMGKXkCK6P6rI5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_81d47792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81d47792fc2ed00ba990d0e6a21b6df184bb309a2315a20d1dd2ee214cadd67e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-02 21:49:17"
  condition:
    hash.sha256(0, filesize) == "81d47792fc2ed00ba990d0e6a21b6df184bb309a2315a20d1dd2ee214cadd67e"
}
```

### Sample 94: `f1d56c7182c6436b`

| Field | Value |
|---|---|
| SHA-256 | `f1d56c7182c6436b26d47f0a64e297ee5b32a4002e6e589add0f5ff10b55c5f2` |
| Family label | `unknown` |
| File name | `videodriver` |
| File type | `macho` |
| First seen | `2026-10-02 21:44:24` |
| Reporter | `smica83` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb9f9b367f0b07219dea84abf080ab8e` |
| SHA-1 | `37f13251a3d7dc79371277c71d0b82952e6d5bad` |
| SHA-256 | `f1d56c7182c6436b26d47f0a64e297ee5b32a4002e6e589add0f5ff10b55c5f2` |
| SHA3-384 | `87884c409f1ec89743c82152015ea28e3b10ded6570f3000f0836adb02a612371f15d6e7362951867200089cd7d5da4f` |
| TLSH | `T115F6AF91BC3C7D62E2C961B65F674294323DBC844F81CB166614FB3CAEF27548B22792` |
| SSDEEP | `196608:NaO5Q1CJ6IPpQzRBoV2ryMwNS+ngwbNLILQKEU:NaO5dJDPp8R6V2KDgn0xU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_f1d56c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d56c7182c6436b26d47f0a64e297ee5b32a4002e6e589add0f5ff10b55c5f2"
    family = "unknown"
    file_name = "videodriver"
    file_type = "macho"
    first_seen = "2026-10-02 21:44:24"
  condition:
    hash.sha256(0, filesize) == "f1d56c7182c6436b26d47f0a64e297ee5b32a4002e6e589add0f5ff10b55c5f2"
}
```

### Sample 95: `fd7985d10d4d7b11`

| Field | Value |
|---|---|
| SHA-256 | `fd7985d10d4d7b110e3e1f9cd0aa05abdadca4df11a82d907141612968970c25` |
| Family label | `unknown` |
| File name | `CamDriverUpdate` |
| File type | `macho` |
| First seen | `2026-10-02 21:42:34` |
| Reporter | `smica83` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57ecafc6033b435559e037b036cfc504` |
| SHA-1 | `c11246800d6ea13fb2b677d05fb105022f056870` |
| SHA-256 | `fd7985d10d4d7b110e3e1f9cd0aa05abdadca4df11a82d907141612968970c25` |
| SHA3-384 | `463b469316c4764374672cbf56eccda0c957fa6d9610b3cbe8ad0ccf06059d8ce314f24794129681c8a3d8de5dcf43cc` |
| TLSH | `T1B6C42863D3405460C2B955B4879F4344AB25FA289732072FB7A48292DFFA2845F6FEC6` |
| SSDEEP | `12288:21pwoioAe29EtQLyTjaVjAik6ZiJqQLyTja:2GoAe29Et56ZiJq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_fd7985d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7985d10d4d7b110e3e1f9cd0aa05abdadca4df11a82d907141612968970c25"
    family = "unknown"
    file_name = "CamDriverUpdate"
    file_type = "macho"
    first_seen = "2026-10-02 21:42:34"
  condition:
    hash.sha256(0, filesize) == "fd7985d10d4d7b110e3e1f9cd0aa05abdadca4df11a82d907141612968970c25"
}
```

### Sample 96: `99a4f10d374c096e`

| Field | Value |
|---|---|
| SHA-256 | `99a4f10d374c096e576e6b2e82594ce53ff1d429c545d10dbf3647c4ae79ac9a` |
| Family label | `unknown` |
| File name | `ReciboParticular_02-10-2026.5853035696.js` |
| File type | `js` |
| First seen | `2026-10-02 21:37:44` |
| Reporter | `smica83` |
| Tags | `js, KREMLIN, REF9334` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf0317fcac72f4f2ac9eadb0ef27cde0` |
| SHA-1 | `a4adf782f751daed811f82fc76bfc9ee4e00d6a1` |
| SHA-256 | `99a4f10d374c096e576e6b2e82594ce53ff1d429c545d10dbf3647c4ae79ac9a` |
| SHA3-384 | `03cb5e4877adbe5652101ca671f4ca217c604ab6a2612cbc58e8cee7552fd9db6d2a9758a783fea8c10f36faac057729` |
| TLSH | `T1E3036CD2C4C0FF54AC01A6DD172B22155CE852EEE919A331BAEDE37A8FD487512DDB40` |
| SSDEEP | `768:wL2H8r6Bzi2lCd0MDV9A5/G+DxT0GVDmzi/IAkQ4g95O:wCceZCdTfApDxTIAkd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_99a4f10d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a4f10d374c096e576e6b2e82594ce53ff1d429c545d10dbf3647c4ae79ac9a"
    family = "unknown"
    file_name = "ReciboParticular_02-10-2026.5853035696.js"
    file_type = "js"
    first_seen = "2026-10-02 21:37:44"
  condition:
    hash.sha256(0, filesize) == "99a4f10d374c096e576e6b2e82594ce53ff1d429c545d10dbf3647c4ae79ac9a"
}
```

### Sample 97: `51538a2683287a88`

| Field | Value |
|---|---|
| SHA-256 | `51538a2683287a88871c37be515268c34048e1e84b30eecea23164f864e4ecd4` |
| Family label | `unknown` |
| File name | `Supply_Product_Purchase_Order.cmd` |
| File type | `cmd` |
| First seen | `2026-10-02 21:33:27` |
| Reporter | `smica83` |
| Tags | `cmd` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdf6f83e25933718e0b2c311ca8b9b9e` |
| SHA-1 | `de032e9e7e14c39be33ff65cee119abd2c26122c` |
| SHA-256 | `51538a2683287a88871c37be515268c34048e1e84b30eecea23164f864e4ecd4` |
| SHA3-384 | `5f77831127b4bb633ac12f5e629d73f1f08a8a9fe314b1e3eb2c17ab25632f62ba5b46a17c7c8f70c4745a8e4a9e0200` |
| TLSH | `T12A556C3C0D3A29D76F6C2EBCE5143E3A0BD01087854A171FB296B94536EAD4281EDB77` |
| SSDEEP | `24576:072lP0l+M7bH4ccBJWjCQtMP3ZjLAJgae8N:RJz4/N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_51538a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51538a2683287a88871c37be515268c34048e1e84b30eecea23164f864e4ecd4"
    family = "unknown"
    file_name = "Supply_Product_Purchase_Order.cmd"
    file_type = "cmd"
    first_seen = "2026-10-02 21:33:27"
  condition:
    hash.sha256(0, filesize) == "51538a2683287a88871c37be515268c34048e1e84b30eecea23164f864e4ecd4"
}
```

### Sample 98: `00575262fc54fb8a`

| Field | Value |
|---|---|
| SHA-256 | `00575262fc54fb8a46fe59c5abc2b9c5229491da480df9f74aa6acb6954b24f7` |
| Family label | `AsyncRAT` |
| File name | `NFe91648916160316975616710-27-09-2026.pdf.js` |
| File type | `js` |
| First seen | `2026-10-02 21:29:10` |
| Reporter | `smica83` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dee19a60dc57ff33a9a9a9896b0902a` |
| SHA-1 | `113b28fbf77728c99f8c210f4424a007597b005a` |
| SHA-256 | `00575262fc54fb8a46fe59c5abc2b9c5229491da480df9f74aa6acb6954b24f7` |
| SHA3-384 | `217fd7de13a5b90c500966e80e02d42cec50a95433e63e7653bf6abe2258a9675cc23baf06f5ba3ecbf14e5ad96894e9` |
| TLSH | `T16FF5F1C9BE6C57AA2F3ADC82117E9D6F3933AD93C450D694A164724ED302200B7F5E6C` |
| SSDEEP | `49152:Y4yPhbkqZXuer0XHCTjCHYML2CbP7Ra9BtdFAPo8VY:U` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_098_00575262
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00575262fc54fb8a46fe59c5abc2b9c5229491da480df9f74aa6acb6954b24f7"
    family = "AsyncRAT"
    file_name = "NFe91648916160316975616710-27-09-2026.pdf.js"
    file_type = "js"
    first_seen = "2026-10-02 21:29:10"
  condition:
    hash.sha256(0, filesize) == "00575262fc54fb8a46fe59c5abc2b9c5229491da480df9f74aa6acb6954b24f7"
}
```

### Sample 99: `708eb15888514e46`

| Field | Value |
|---|---|
| SHA-256 | `708eb15888514e4675cb7501abcccde0ad2df369e518730d96594ff77d67fa73` |
| Family label | `unknown` |
| File name | `7ZSfxMod_x86.exe` |
| File type | `unknown` |
| First seen | `2026-10-02 21:26:53` |
| Reporter | `smica83` |
| Tags | `apt, Gamaredon, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a30c5d73737a637058fcf8468541a2f` |
| SHA-256 | `708eb15888514e4675cb7501abcccde0ad2df369e518730d96594ff77d67fa73` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_708eb158
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "708eb15888514e4675cb7501abcccde0ad2df369e518730d96594ff77d67fa73"
    family = "unknown"
    file_name = "7ZSfxMod_x86.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 21:26:53"
  condition:
    hash.sha256(0, filesize) == "708eb15888514e4675cb7501abcccde0ad2df369e518730d96594ff77d67fa73"
}
```

### Sample 100: `30a54c0221e7ade4`

| Field | Value |
|---|---|
| SHA-256 | `30a54c0221e7ade433636c205e508aaa1006f4df93870ade8fb15db995b98704` |
| Family label | `unknown` |
| File name | `eStatement_2026-10-01-155243639385945794.zip` |
| File type | `zip` |
| First seen | `2026-10-02 21:23:00` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2105ee8ebbfa9847b7fb5dfc6abbb9da` |
| SHA-1 | `cbecdae4ec26f1993aa08f6cbfd24d7f5e451b45` |
| SHA-256 | `30a54c0221e7ade433636c205e508aaa1006f4df93870ade8fb15db995b98704` |
| SHA3-384 | `328bdb55076414ba2d5ee83f9835cf09f1be363159ec57e55433d0215c7d201fa30a5f8ada4db0f648d44a6ca44527f1` |
| TLSH | `T19A8312B5A2A7B3E9C8F401B502FAFEFED63216D4A516C88F466DD32674D8A3C0C74146` |
| SSDEEP | `1536:B9rM3KICELrxocYIqOSFD7xitI+P1bDTnU3aR/tO75/XJYfFOh/NB0+WpW8b95vF:D43KZELKcYASVxiOWD7U3oO7oFmNB0+O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_30a54c02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30a54c0221e7ade433636c205e508aaa1006f4df93870ade8fb15db995b98704"
    family = "unknown"
    file_name = "eStatement_2026-10-01-155243639385945794.zip"
    file_type = "zip"
    first_seen = "2026-10-02 21:23:00"
  condition:
    hash.sha256(0, filesize) == "30a54c0221e7ade433636c205e508aaa1006f4df93870ade8fb15db995b98704"
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
 * Generated: 2026-10-03T05:26:31.954483+00:00
 */

rule MalwareBazaar_WannaCry_001_383f6b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9"
    family = "WannaCry"
    file_name = "383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9"
    file_type = "exe"
    first_seen = "2026-10-03 05:15:24"
  condition:
    hash.sha256(0, filesize) == "383f6b988e0571e090ae3ec4fac8ec2a35e781fb0312086d66a0900400952cd9"
}

rule MalwareBazaar_unknown_002_a3da040a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e"
    family = "unknown"
    file_name = "a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e.bin"
    file_type = "unknown"
    first_seen = "2026-10-03 04:29:47"
  condition:
    hash.sha256(0, filesize) == "a3da040aab40b054014f57bd68987c03b451344d5d00d8dc68dbc7af8af0e98e"
}

rule MalwareBazaar_unknown_003_0683dae3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7"
    family = "unknown"
    file_name = "0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:29:43"
  condition:
    hash.sha256(0, filesize) == "0683dae34749be13ed9c48fe8e71ada678c7189bc51bd373a5e69405458d62d7"
}

rule MalwareBazaar_unknown_004_de9d9663
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e"
    family = "unknown"
    file_name = "de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e.bin"
    file_type = "unknown"
    first_seen = "2026-10-03 04:29:37"
  condition:
    hash.sha256(0, filesize) == "de9d9663fa7293fca6e75ffd75f69b2119269020dc0985b3d11b2c7f0af9af2e"
}

rule MalwareBazaar_unknown_005_2e7044f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f"
    family = "unknown"
    file_name = "2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:29:33"
  condition:
    hash.sha256(0, filesize) == "2e7044f87cdbca22208a00614dc292bb29f9b5f8cf602af91684a809c7d85b1f"
}

rule MalwareBazaar_unknown_006_bda14fdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4"
    family = "unknown"
    file_name = "bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:29:26"
  condition:
    hash.sha256(0, filesize) == "bda14fdc645f229c83c61815717e03e61ecec50e555c114fa8997eb2983848f4"
}

rule MalwareBazaar_unknown_007_566b6a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab"
    family = "unknown"
    file_name = "566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab.bin"
    file_type = "zip"
    first_seen = "2026-10-03 04:28:39"
  condition:
    hash.sha256(0, filesize) == "566b6a879e20c3d3eac8e692e233cf946879d47f14c577fdc343b06a11b1beab"
}

rule MalwareBazaar_unknown_008_92f886f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5"
    family = "unknown"
    file_name = "92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 04:28:34"
  condition:
    hash.sha256(0, filesize) == "92f886f400e93c9c95689ffa2fc3c9c789b3b29e02455737a28cc2d26f5b0ec5"
}

rule MalwareBazaar_unknown_009_1cfbf1ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3"
    family = "unknown"
    file_name = "1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3.exe"
    file_type = "exe"
    first_seen = "2026-10-03 04:28:29"
  condition:
    hash.sha256(0, filesize) == "1cfbf1bad6c7128ba8e8580ec22f33d2996d1bad27eda6c44b5286dc9dbea3e3"
}

rule MalwareBazaar_unknown_010_69567223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb"
    family = "unknown"
    file_name = "69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb.exe"
    file_type = "exe"
    first_seen = "2026-10-03 04:28:25"
  condition:
    hash.sha256(0, filesize) == "69567223a283fc2c254ae97f43ea36de66a345e1a3a5790f241d579dd3406ddb"
}

rule MalwareBazaar_unknown_011_3242094d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b"
    family = "unknown"
    file_name = "3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 04:28:21"
  condition:
    hash.sha256(0, filesize) == "3242094dacc034bbfc5c6a1a62a9fdc234b0cee22cb07b2ae44485b6cfe85a4b"
}

rule MalwareBazaar_unknown_012_7629fe85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7"
    family = "unknown"
    file_name = "7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7"
    file_type = "elf"
    first_seen = "2026-10-03 04:24:59"
  condition:
    hash.sha256(0, filesize) == "7629fe856487cf2a9581ac4d5040cf0603f7f47c6db5eb5cecadddef9c13e6a7"
}

rule MalwareBazaar_Prometei_013_f43e4400
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f"
    family = "Prometei"
    file_name = "f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f"
    file_type = "elf"
    first_seen = "2026-10-03 04:23:11"
  condition:
    hash.sha256(0, filesize) == "f43e44009d35dd253fae8c0a5c36a3bc53d93a468d6e4f068ab3e9e46478b05f"
}

rule MalwareBazaar_Mirai_014_67aad942
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11"
    family = "Mirai"
    file_name = "67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11"
    file_type = "elf"
    first_seen = "2026-10-03 03:38:36"
  condition:
    hash.sha256(0, filesize) == "67aad942831fde6969bedfbe7285410cc3f7047b3f8f13a7deb68a4adc4ddf11"
}

rule MalwareBazaar_unknown_015_fa76b2af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20"
    family = "unknown"
    file_name = "fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20.bin"
    file_type = "zip"
    first_seen = "2026-10-03 02:18:05"
  condition:
    hash.sha256(0, filesize) == "fa76b2af590fa1fcc46ca38ec83ef40aa02616021bb88fb35106504342b3ac20"
}

rule MalwareBazaar_Mirai_016_c591f581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208"
    family = "Mirai"
    file_name = "c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208"
    file_type = "elf"
    first_seen = "2026-10-03 02:17:29"
  condition:
    hash.sha256(0, filesize) == "c591f581a245fccfc6405945c161c71bcb466db0b83318c4838fabe22234f208"
}

rule MalwareBazaar_unknown_017_c2f5532f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34"
    family = "unknown"
    file_name = "s"
    file_type = "sh"
    first_seen = "2026-10-03 02:11:20"
  condition:
    hash.sha256(0, filesize) == "c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34"
}

rule MalwareBazaar_unknown_018_27081836
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "270818363029321786e16e2102c550a1edc7bd6fde172ed6c620ad1958c36ac8"
    family = "unknown"
    file_name = "s"
    file_type = "sh"
    first_seen = "2026-10-03 02:10:57"
  condition:
    hash.sha256(0, filesize) == "270818363029321786e16e2102c550a1edc7bd6fde172ed6c620ad1958c36ac8"
}

rule MalwareBazaar_Mirai_019_7d9a6cad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d9a6cad78a3980c83676dd626e7bdd6c4d397ac64f35aa01d4e4a98679cab72"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:27"
  condition:
    hash.sha256(0, filesize) == "7d9a6cad78a3980c83676dd626e7bdd6c4d397ac64f35aa01d4e4a98679cab72"
}

rule MalwareBazaar_Mirai_020_fe81f791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe81f791dc2c956f7df44e76122ae5c13cc714d26592ae02751307e8714de6a8"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:25"
  condition:
    hash.sha256(0, filesize) == "fe81f791dc2c956f7df44e76122ae5c13cc714d26592ae02751307e8714de6a8"
}

rule MalwareBazaar_Mirai_021_ee1667c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:24"
  condition:
    hash.sha256(0, filesize) == "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96"
}

rule MalwareBazaar_Mirai_022_e148526f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e148526ff5d3a132a147359a7164f30b8f84f8cd4920b1e94974cf6dc6b4d996"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:22"
  condition:
    hash.sha256(0, filesize) == "e148526ff5d3a132a147359a7164f30b8f84f8cd4920b1e94974cf6dc6b4d996"
}

rule MalwareBazaar_Mirai_023_2a8c2c1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a8c2c1c3333f35a2feac67d048342fbb6e8e5c129d536c67a1115ed72e0065b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:21"
  condition:
    hash.sha256(0, filesize) == "2a8c2c1c3333f35a2feac67d048342fbb6e8e5c129d536c67a1115ed72e0065b"
}

rule MalwareBazaar_Mirai_024_a4766541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a476654140f2734ef4dbe54001da31d260feb706c6508e96df2dd4be9ddc31a0"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:19"
  condition:
    hash.sha256(0, filesize) == "a476654140f2734ef4dbe54001da31d260feb706c6508e96df2dd4be9ddc31a0"
}

rule MalwareBazaar_Mirai_025_ec9a8384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec9a838423f6a16ff80301cd09ca0333bc07ab5c24b40e6cb7bef46a7ecac25b"
    family = "Mirai"
    file_name = "powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:17"
  condition:
    hash.sha256(0, filesize) == "ec9a838423f6a16ff80301cd09ca0333bc07ab5c24b40e6cb7bef46a7ecac25b"
}

rule MalwareBazaar_Mirai_026_d1f4e34e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1f4e34e1a3d5be26a70f56d0709c54bdd6caf5f8dbd6ca84f041b27e8532461"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:15"
  condition:
    hash.sha256(0, filesize) == "d1f4e34e1a3d5be26a70f56d0709c54bdd6caf5f8dbd6ca84f041b27e8532461"
}

rule MalwareBazaar_Mirai_027_b44c1284
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b44c1284d7f2e4c40d8c370fed99af3933d1605cdb5bfdc93ea0100d347433a3"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:14"
  condition:
    hash.sha256(0, filesize) == "b44c1284d7f2e4c40d8c370fed99af3933d1605cdb5bfdc93ea0100d347433a3"
}

rule MalwareBazaar_Mirai_028_9c2f7279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c2f72796f72e5a06c6a23e648f0685cecbe0f3624fc8e73886c3c9ae6f7537a"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:12"
  condition:
    hash.sha256(0, filesize) == "9c2f72796f72e5a06c6a23e648f0685cecbe0f3624fc8e73886c3c9ae6f7537a"
}

rule MalwareBazaar_Mirai_029_a199b974
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a199b97450fe8a1d60209237801321d88cf5f3dd720183f196477f427eaa2d89"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:11"
  condition:
    hash.sha256(0, filesize) == "a199b97450fe8a1d60209237801321d88cf5f3dd720183f196477f427eaa2d89"
}

rule MalwareBazaar_Mirai_030_cda0e3ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cda0e3cecf5cb049a3c9589d7e88d72f1fb102bf5037080bc579f05cecaa3c6c"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:09"
  condition:
    hash.sha256(0, filesize) == "cda0e3cecf5cb049a3c9589d7e88d72f1fb102bf5037080bc579f05cecaa3c6c"
}

rule MalwareBazaar_Mirai_031_8a287d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a287d808ee098002248f03563da082e0939f9532d211c569c1937de62ef2cb9"
    family = "Mirai"
    file_name = "Space.spc"
    file_type = "elf"
    first_seen = "2026-10-03 02:02:07"
  condition:
    hash.sha256(0, filesize) == "8a287d808ee098002248f03563da082e0939f9532d211c569c1937de62ef2cb9"
}

rule MalwareBazaar_unknown_032_97df3304
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97df330410c814e0db3eeb988af0dbde105b776baf1b3af08516341a778cde3e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-10-03 01:55:19"
  condition:
    hash.sha256(0, filesize) == "97df330410c814e0db3eeb988af0dbde105b776baf1b3af08516341a778cde3e"
}

rule MalwareBazaar_Mirai_033_fcb6a359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd"
    family = "Mirai"
    file_name = "fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd"
    file_type = "elf"
    first_seen = "2026-10-03 01:49:41"
  condition:
    hash.sha256(0, filesize) == "fcb6a359b4364406268ee53f45de175b7469ff5a2277d7dae11b3e1df0ebe0cd"
}

rule MalwareBazaar_unknown_034_0db9ec12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4"
    family = "unknown"
    file_name = "0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4"
    file_type = "elf"
    first_seen = "2026-10-03 01:20:34"
  condition:
    hash.sha256(0, filesize) == "0db9ec1267fc088302d7dd480ee8fd4a84a28252ba114b730fa3c8a526d4e2b4"
}

rule MalwareBazaar_unknown_035_d6f7bc7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90"
    family = "unknown"
    file_name = "d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90.exe"
    file_type = "exe"
    first_seen = "2026-10-03 01:18:06"
  condition:
    hash.sha256(0, filesize) == "d6f7bc7b338e388b3399eb19bb7010ea671131d2e42d94a1bc939cae261ecd90"
}

rule MalwareBazaar_unknown_036_e839d72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e839d72d6c03b1b08a3f01d8ebd907e3c96ebe8fc576f928270635b6636a41cc"
    family = "unknown"
    file_name = "clickfix.exe"
    file_type = "exe"
    first_seen = "2026-10-03 01:14:17"
  condition:
    hash.sha256(0, filesize) == "e839d72d6c03b1b08a3f01d8ebd907e3c96ebe8fc576f928270635b6636a41cc"
}

rule MalwareBazaar_unknown_037_18616fe2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-10-03 01:12:13"
  condition:
    hash.sha256(0, filesize) == "18616fe26c8f6c92db6daa2dcd7cd53c5143ee69ecfd26d8ea6dc9b2c78607a6"
}

rule MalwareBazaar_unknown_038_c66f9881
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b"
    family = "unknown"
    file_name = "c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b.bin"
    file_type = "macho"
    first_seen = "2026-10-03 01:07:59"
  condition:
    hash.sha256(0, filesize) == "c66f9881bed79a550e18d54b9ae5cf03b91a0e881efdbf7962db2e58de0b4f7b"
}

rule MalwareBazaar_Mirai_039_1242552e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f"
    family = "Mirai"
    file_name = "1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f"
    file_type = "elf"
    first_seen = "2026-10-03 00:52:02"
  condition:
    hash.sha256(0, filesize) == "1242552e288c55d36da13247db880781a40a7d05e0816f917e4602a81f3e010f"
}

rule MalwareBazaar_Mirai_040_c98e5215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c98e5215787ff8bbe2a79d4afb6d6ef27d96ac75273bf220b915779c8f4b0192"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-03 00:40:00"
  condition:
    hash.sha256(0, filesize) == "c98e5215787ff8bbe2a79d4afb6d6ef27d96ac75273bf220b915779c8f4b0192"
}

rule MalwareBazaar_Mirai_041_c26605c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c26605c768197314a1b59d03e5065e4b6cb0f6ef4177d13e41e4cf4cebab7300"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-10-03 00:38:00"
  condition:
    hash.sha256(0, filesize) == "c26605c768197314a1b59d03e5065e4b6cb0f6ef4177d13e41e4cf4cebab7300"
}

rule MalwareBazaar_Mirai_042_2426afcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2426afcd370032216331814d58ac157395c155aeb42f6ba3822ff4b40c86c600"
    family = "Mirai"
    file_name = "Space"
    file_type = "elf"
    first_seen = "2026-10-03 00:36:25"
  condition:
    hash.sha256(0, filesize) == "2426afcd370032216331814d58ac157395c155aeb42f6ba3822ff4b40c86c600"
}

rule MalwareBazaar_unknown_043_7451d2df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef"
    family = "unknown"
    file_name = "7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef.dll"
    file_type = "unknown"
    first_seen = "2026-10-03 00:36:04"
  condition:
    hash.sha256(0, filesize) == "7451d2df5fa394be6113f056013050ca2853a40231222204cbd289beb7dd46ef"
}

rule MalwareBazaar_Mirai_044_3ba3ff11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ba3ff1127b8f5b40e8a97329f9684059220ed22baa53def1febf8072626d4d4"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-10-03 00:33:58"
  condition:
    hash.sha256(0, filesize) == "3ba3ff1127b8f5b40e8a97329f9684059220ed22baa53def1febf8072626d4d4"
}

rule MalwareBazaar_unknown_045_75300610
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc"
    family = "unknown"
    file_name = "75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc.sh"
    file_type = "unknown"
    first_seen = "2026-10-03 00:29:09"
  condition:
    hash.sha256(0, filesize) == "75300610d2c17b6e65766babd1878ef1d933eabeb78e50b9487fbb1a9572b7fc"
}

rule MalwareBazaar_unknown_046_d5d9e754
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa"
    family = "unknown"
    file_name = "d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa.exe"
    file_type = "exe"
    first_seen = "2026-10-03 00:28:23"
  condition:
    hash.sha256(0, filesize) == "d5d9e754f2bc9e9d8c91c0a15cc99639ad45547a7e233e5b15d5376d5061bbaa"
}

rule MalwareBazaar_Mirai_047_068a7e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "068a7e1cbc2094d515d396b24d9ce6608b2002bf237256105fa9650484f2803e"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-10-03 00:27:56"
  condition:
    hash.sha256(0, filesize) == "068a7e1cbc2094d515d396b24d9ce6608b2002bf237256105fa9650484f2803e"
}

rule MalwareBazaar_unknown_048_75a512a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f"
    family = "unknown"
    file_name = "75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f.elf"
    file_type = "elf"
    first_seen = "2026-10-03 00:27:20"
  condition:
    hash.sha256(0, filesize) == "75a512a7acd86a80d2ff5c180c80d1a852e7391aeeacc1ebcfae9e344b5c940f"
}

rule MalwareBazaar_Prometei_049_7389513d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1"
    family = "Prometei"
    file_name = "7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1"
    file_type = "elf"
    first_seen = "2026-10-03 00:23:06"
  condition:
    hash.sha256(0, filesize) == "7389513d3128434123e67c9e429f1d4357d8159842ea5737f147bcc825cca9a1"
}

rule MalwareBazaar_unknown_050_bffecd40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bffecd40374eb2788c47a1adea38cb24eb05812f93a561ee503549879617a42c"
    family = "unknown"
    file_name = "3cdb5ff86c49e550410b2dbcadd1004c.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 00:20:05"
  condition:
    hash.sha256(0, filesize) == "bffecd40374eb2788c47a1adea38cb24eb05812f93a561ee503549879617a42c"
}

rule MalwareBazaar_unknown_051_372a17ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4"
    family = "unknown"
    file_name = "372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4.bin"
    file_type = "unknown"
    first_seen = "2026-10-03 00:18:33"
  condition:
    hash.sha256(0, filesize) == "372a17ab8c80c4d0789d09eb6d3c1995d56cf15cb820889de827ffb70b5f18e4"
}

rule MalwareBazaar_unknown_052_bf440909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257"
    family = "unknown"
    file_name = "bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257.bin"
    file_type = "zip"
    first_seen = "2026-10-03 00:13:22"
  condition:
    hash.sha256(0, filesize) == "bf44090998d03a3a2764a620dfd2e6a3cfaefb5a9570fac1bb70cab1d0f0a257"
}

rule MalwareBazaar_unknown_053_2d968394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1"
    family = "unknown"
    file_name = "2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1.exe"
    file_type = "unknown"
    first_seen = "2026-10-03 00:13:17"
  condition:
    hash.sha256(0, filesize) == "2d96839426e3400d9273eb9621889e74f847b503a2c9ef73ae8148f80a1eb2a1"
}

rule MalwareBazaar_Mirai_054_a2b38e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-03 00:09:59"
  condition:
    hash.sha256(0, filesize) == "a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3"
}

rule MalwareBazaar_Mirai_055_2e538429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e538429e81c49a167f49c949eff7f8fb43b0c5af985a394bd7e4ca0669739b5"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-03 00:06:10"
  condition:
    hash.sha256(0, filesize) == "2e538429e81c49a167f49c949eff7f8fb43b0c5af985a394bd7e4ca0669739b5"
}

rule MalwareBazaar_unknown_056_dc4f2d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc4f2d231061b28e24d4c7a85ea4904f6704059d271587f0f0c1951993be7775"
    family = "unknown"
    file_name = "macho_dc4f2d231061.bin"
    file_type = "macho"
    first_seen = "2026-10-03 00:03:25"
  condition:
    hash.sha256(0, filesize) == "dc4f2d231061b28e24d4c7a85ea4904f6704059d271587f0f0c1951993be7775"
}

rule MalwareBazaar_unknown_057_4458ab2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382"
    family = "unknown"
    file_name = "macho_4458ab2eb26c.bin"
    file_type = "macho"
    first_seen = "2026-10-03 00:03:25"
  condition:
    hash.sha256(0, filesize) == "4458ab2eb26c8c155cf530136e0a7cf1ddee41f26547a56bc093d61a83c0a382"
}

rule MalwareBazaar_Mirai_058_9b5b7a67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b5b7a6722b364ee439fd71e154ee59bdda62fbebf9114401c9f2651b46e3655"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-10-02 23:55:54"
  condition:
    hash.sha256(0, filesize) == "9b5b7a6722b364ee439fd71e154ee59bdda62fbebf9114401c9f2651b46e3655"
}

rule MalwareBazaar_unknown_059_7705a0ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7705a0ce4ff924737575446b03f4b34d95d3650552ca5495ff6e5e103d68cff2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 23:53:55"
  condition:
    hash.sha256(0, filesize) == "7705a0ce4ff924737575446b03f4b34d95d3650552ca5495ff6e5e103d68cff2"
}

rule MalwareBazaar_unknown_060_88ef20d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ef20d6ef76a46c70a2a29f41a91cdb95408902ff4ca778ff248ec78ff122df"
    family = "unknown"
    file_name = "check1.sh"
    file_type = "sh"
    first_seen = "2026-10-02 23:48:00"
  condition:
    hash.sha256(0, filesize) == "88ef20d6ef76a46c70a2a29f41a91cdb95408902ff4ca778ff248ec78ff122df"
}

rule MalwareBazaar_Mirai_061_6e03f1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e03f1ce7db58a8e89f749d2030d2a4c99c6a1916c2308b54255d59d645b74ba"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-02 23:46:01"
  condition:
    hash.sha256(0, filesize) == "6e03f1ce7db58a8e89f749d2030d2a4c99c6a1916c2308b54255d59d645b74ba"
}

rule MalwareBazaar_Mirai_062_8f5606d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77"
    family = "Mirai"
    file_name = "8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77"
    file_type = "elf"
    first_seen = "2026-10-02 23:37:35"
  condition:
    hash.sha256(0, filesize) == "8f5606d46a9e39f923ad43d7673cd296c48c5366ac8ec85f615531d4b48fde77"
}

rule MalwareBazaar_Mirai_063_917ff018
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "917ff018b3ac87413e2210dd8b3beab5e642990c9656d257c8ebfae48b86a9ad"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-10-02 23:32:05"
  condition:
    hash.sha256(0, filesize) == "917ff018b3ac87413e2210dd8b3beab5e642990c9656d257c8ebfae48b86a9ad"
}

rule MalwareBazaar_Mirai_064_a138a972
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a138a9724a77dad169312f39e94269413555448ec89ffc73b55a51cb4ccc3e25"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-02 23:32:03"
  condition:
    hash.sha256(0, filesize) == "a138a9724a77dad169312f39e94269413555448ec89ffc73b55a51cb4ccc3e25"
}

rule MalwareBazaar_Mirai_065_14896331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14896331c3585918ef42074368d2a9033e8d84e0e30dc669d17dccb74e052f00"
    family = "Mirai"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-10-02 23:29:55"
  condition:
    hash.sha256(0, filesize) == "14896331c3585918ef42074368d2a9033e8d84e0e30dc669d17dccb74e052f00"
}

rule MalwareBazaar_Mirai_066_31924750
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "319247509e503f1b2b9efaf0b422e50fce59cd078ac3a683b41f44933a08dd58"
    family = "Mirai"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-10-02 23:27:57"
  condition:
    hash.sha256(0, filesize) == "319247509e503f1b2b9efaf0b422e50fce59cd078ac3a683b41f44933a08dd58"
}

rule MalwareBazaar_Mirai_067_7cbe9380
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cbe938005ad28519a08d978e64f3108a593876232e6a4c9a8b3db228ac3091f"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-10-02 23:23:58"
  condition:
    hash.sha256(0, filesize) == "7cbe938005ad28519a08d978e64f3108a593876232e6a4c9a8b3db228ac3091f"
}

rule MalwareBazaar_Mirai_068_13e2d4fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13e2d4fe752561dcfc13f45c9302e8bb3d6ac89405af144b3144e04d1579b64e"
    family = "Mirai"
    file_name = "main_mips"
    file_type = "elf"
    first_seen = "2026-10-02 23:22:01"
  condition:
    hash.sha256(0, filesize) == "13e2d4fe752561dcfc13f45c9302e8bb3d6ac89405af144b3144e04d1579b64e"
}

rule MalwareBazaar_Mirai_069_fed71588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fed71588688e9b44f975c184ee74acd701f84a05c23fa84b3c75f748e75ef39f"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-10-02 23:22:00"
  condition:
    hash.sha256(0, filesize) == "fed71588688e9b44f975c184ee74acd701f84a05c23fa84b3c75f748e75ef39f"
}

rule MalwareBazaar_Mirai_070_2f6088d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6088d935286e13b3711d51cce302340bff48d82475cb89bfc75d7f05ebede2"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-10-02 23:21:58"
  condition:
    hash.sha256(0, filesize) == "2f6088d935286e13b3711d51cce302340bff48d82475cb89bfc75d7f05ebede2"
}

rule MalwareBazaar_unknown_071_68181715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "681817158553beede00a5fd1225912d3e0740c6337853a62f65927e8f0f12010"
    family = "unknown"
    file_name = "boss"
    file_type = "elf"
    first_seen = "2026-10-02 23:20:00"
  condition:
    hash.sha256(0, filesize) == "681817158553beede00a5fd1225912d3e0740c6337853a62f65927e8f0f12010"
}

rule MalwareBazaar_unknown_072_01be4a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42"
    family = "unknown"
    file_name = "01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 23:18:03"
  condition:
    hash.sha256(0, filesize) == "01be4a4dbee15e0f07ddf8be467da3d683cc57f245cbba93a9263f56c1249a42"
}

rule MalwareBazaar_Mirai_073_750922eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "750922eb0a7eb9fdac0405bd2aaee3932b2ce82f6609ba0a7c443a5c861007ca"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-02 23:17:57"
  condition:
    hash.sha256(0, filesize) == "750922eb0a7eb9fdac0405bd2aaee3932b2ce82f6609ba0a7c443a5c861007ca"
}

rule MalwareBazaar_unknown_074_d5dc4b7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462"
    family = "unknown"
    file_name = "d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 23:13:09"
  condition:
    hash.sha256(0, filesize) == "d5dc4b7d2756198be64935eda8439510daa497cbda607b34d6b055d729f44462"
}

rule MalwareBazaar_Mirai_075_608f566e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608f566ed3a2432a756772e789cabce55561cf47a5c5c166ac61060a2906c8d6"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-02 23:05:58"
  condition:
    hash.sha256(0, filesize) == "608f566ed3a2432a756772e789cabce55561cf47a5c5c166ac61060a2906c8d6"
}

rule MalwareBazaar_unknown_076_230f9377
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230f9377c60d8545d99f41876fa3bd0ff0557b3ae0d39565159cc5b78c936fde"
    family = "unknown"
    file_name = "3475ebc4c8d569fe27690e4a5ed80076.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 23:00:12"
  condition:
    hash.sha256(0, filesize) == "230f9377c60d8545d99f41876fa3bd0ff0557b3ae0d39565159cc5b78c936fde"
}

rule MalwareBazaar_RemusStealer_077_4d8efc45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d8efc4528dd2088d72c68fa693ea22a2fc5946820aab9745ed77f85fa9265d4"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:54:21"
  condition:
    hash.sha256(0, filesize) == "4d8efc4528dd2088d72c68fa693ea22a2fc5946820aab9745ed77f85fa9265d4"
}

rule MalwareBazaar_RemusStealer_078_049b268f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049b268f6fe7dee81651ff0d3ddc72b205f465c9aba3e57e9222fe9c5eadff88"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:53:44"
  condition:
    hash.sha256(0, filesize) == "049b268f6fe7dee81651ff0d3ddc72b205f465c9aba3e57e9222fe9c5eadff88"
}

rule MalwareBazaar_unknown_079_f663aaab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f663aaab15536ac4bf5b2f7547470c256faf171149d3ede5dd0199e762bf2792"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-10-02 22:53:38"
  condition:
    hash.sha256(0, filesize) == "f663aaab15536ac4bf5b2f7547470c256faf171149d3ede5dd0199e762bf2792"
}

rule MalwareBazaar_unknown_080_48bb8a6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00"
    family = "unknown"
    file_name = "48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00.bin"
    file_type = "zip"
    first_seen = "2026-10-02 22:48:31"
  condition:
    hash.sha256(0, filesize) == "48bb8a6a2867528fb7b3abe5271affce295c22efe67c5ac339bc370b632dbb00"
}

rule MalwareBazaar_unknown_081_53a00597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a"
    family = "unknown"
    file_name = "53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 22:48:25"
  condition:
    hash.sha256(0, filesize) == "53a00597ffb492b24624e142b0b726f6fa455b958dcd5fe39acaa74b78aec34a"
}

rule MalwareBazaar_unknown_082_f0b5bc22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e"
    family = "unknown"
    file_name = "f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 22:48:21"
  condition:
    hash.sha256(0, filesize) == "f0b5bc2220408f6d2bfc260071d1f596bf198c2c8fbe32feb672b9bfdbed290e"
}

rule MalwareBazaar_Mirai_083_fd925cbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd925cbfbeaeaac0cc2b5a30a5d89f0e44a341d8eb907f022805ce5bd0c05262"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-02 22:47:55"
  condition:
    hash.sha256(0, filesize) == "fd925cbfbeaeaac0cc2b5a30a5d89f0e44a341d8eb907f022805ce5bd0c05262"
}

rule MalwareBazaar_unknown_084_018c84e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d"
    family = "unknown"
    file_name = "018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d"
    file_type = "elf"
    first_seen = "2026-10-02 22:42:42"
  condition:
    hash.sha256(0, filesize) == "018c84e8df20153f207253feac34a5889fa1a4441d21a0df8d4e04bd0933a81d"
}

rule MalwareBazaar_Mirai_085_18c6d691
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27"
    family = "Mirai"
    file_name = "18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27"
    file_type = "elf"
    first_seen = "2026-10-02 22:42:35"
  condition:
    hash.sha256(0, filesize) == "18c6d69109732425015d243652855e838899ccf44efe6593b44626e31be5be27"
}

rule MalwareBazaar_unknown_086_5187141c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937"
    family = "unknown"
    file_name = "5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937"
    file_type = "elf"
    first_seen = "2026-10-02 22:25:31"
  condition:
    hash.sha256(0, filesize) == "5187141cdfa53a30fa730b6a5f76a628fc7726b339d528ad613f4cb0b3381937"
}

rule MalwareBazaar_unknown_087_a9c759ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9c759ea8ea13df937b0d7dc7971aec13028f8953a26c620c2f6b7009fb9fea8"
    family = "unknown"
    file_name = "2fb43e665156aa6153b0f6ec8ece9ce8.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 22:20:04"
  condition:
    hash.sha256(0, filesize) == "a9c759ea8ea13df937b0d7dc7971aec13028f8953a26c620c2f6b7009fb9fea8"
}

rule MalwareBazaar_unknown_088_b7971b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7971b42ff2d71e9ca71cb85b42e3105456204a3ca133ddc79b7f37938065464"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:17:51"
  condition:
    hash.sha256(0, filesize) == "b7971b42ff2d71e9ca71cb85b42e3105456204a3ca133ddc79b7f37938065464"
}

rule MalwareBazaar_unknown_089_d39be9b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d39be9b1c8bdca49b3d814849ae507df280c6fe967e5c08fadfdc81d6f2f1cbc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 22:13:15"
  condition:
    hash.sha256(0, filesize) == "d39be9b1c8bdca49b3d814849ae507df280c6fe967e5c08fadfdc81d6f2f1cbc"
}

rule MalwareBazaar_unknown_090_74e55352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e553523ca8afec8e56befc4b2f8edbf62fd5ead04c44ade595fc99ecc56ad0"
    family = "unknown"
    file_name = "Bin.zip"
    file_type = "zip"
    first_seen = "2026-10-02 22:09:26"
  condition:
    hash.sha256(0, filesize) == "74e553523ca8afec8e56befc4b2f8edbf62fd5ead04c44ade595fc99ecc56ad0"
}

rule MalwareBazaar_unknown_091_54bce16e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54bce16e7f24ca7683a29fadd0f9b6d6a838c16f797dc610f5ec5b63fa6cc532"
    family = "unknown"
    file_name = "RFQ.hta"
    file_type = "unknown"
    first_seen = "2026-10-02 22:01:12"
  condition:
    hash.sha256(0, filesize) == "54bce16e7f24ca7683a29fadd0f9b6d6a838c16f797dc610f5ec5b63fa6cc532"
}

rule MalwareBazaar_unknown_092_245f1627
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245f16270bf0dfece1ac13f06e2554d059f82b6bc53b1f19b0d835f409b5d80f"
    family = "unknown"
    file_name = "payment-receipt.pdf"
    file_type = "pdf"
    first_seen = "2026-10-02 22:00:10"
  condition:
    hash.sha256(0, filesize) == "245f16270bf0dfece1ac13f06e2554d059f82b6bc53b1f19b0d835f409b5d80f"
}

rule MalwareBazaar_Mirai_093_81d47792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81d47792fc2ed00ba990d0e6a21b6df184bb309a2315a20d1dd2ee214cadd67e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-02 21:49:17"
  condition:
    hash.sha256(0, filesize) == "81d47792fc2ed00ba990d0e6a21b6df184bb309a2315a20d1dd2ee214cadd67e"
}

rule MalwareBazaar_unknown_094_f1d56c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d56c7182c6436b26d47f0a64e297ee5b32a4002e6e589add0f5ff10b55c5f2"
    family = "unknown"
    file_name = "videodriver"
    file_type = "macho"
    first_seen = "2026-10-02 21:44:24"
  condition:
    hash.sha256(0, filesize) == "f1d56c7182c6436b26d47f0a64e297ee5b32a4002e6e589add0f5ff10b55c5f2"
}

rule MalwareBazaar_unknown_095_fd7985d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7985d10d4d7b110e3e1f9cd0aa05abdadca4df11a82d907141612968970c25"
    family = "unknown"
    file_name = "CamDriverUpdate"
    file_type = "macho"
    first_seen = "2026-10-02 21:42:34"
  condition:
    hash.sha256(0, filesize) == "fd7985d10d4d7b110e3e1f9cd0aa05abdadca4df11a82d907141612968970c25"
}

rule MalwareBazaar_unknown_096_99a4f10d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a4f10d374c096e576e6b2e82594ce53ff1d429c545d10dbf3647c4ae79ac9a"
    family = "unknown"
    file_name = "ReciboParticular_02-10-2026.5853035696.js"
    file_type = "js"
    first_seen = "2026-10-02 21:37:44"
  condition:
    hash.sha256(0, filesize) == "99a4f10d374c096e576e6b2e82594ce53ff1d429c545d10dbf3647c4ae79ac9a"
}

rule MalwareBazaar_unknown_097_51538a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51538a2683287a88871c37be515268c34048e1e84b30eecea23164f864e4ecd4"
    family = "unknown"
    file_name = "Supply_Product_Purchase_Order.cmd"
    file_type = "cmd"
    first_seen = "2026-10-02 21:33:27"
  condition:
    hash.sha256(0, filesize) == "51538a2683287a88871c37be515268c34048e1e84b30eecea23164f864e4ecd4"
}

rule MalwareBazaar_AsyncRAT_098_00575262
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00575262fc54fb8a46fe59c5abc2b9c5229491da480df9f74aa6acb6954b24f7"
    family = "AsyncRAT"
    file_name = "NFe91648916160316975616710-27-09-2026.pdf.js"
    file_type = "js"
    first_seen = "2026-10-02 21:29:10"
  condition:
    hash.sha256(0, filesize) == "00575262fc54fb8a46fe59c5abc2b9c5229491da480df9f74aa6acb6954b24f7"
}

rule MalwareBazaar_unknown_099_708eb158
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "708eb15888514e4675cb7501abcccde0ad2df369e518730d96594ff77d67fa73"
    family = "unknown"
    file_name = "7ZSfxMod_x86.exe"
    file_type = "unknown"
    first_seen = "2026-10-02 21:26:53"
  condition:
    hash.sha256(0, filesize) == "708eb15888514e4675cb7501abcccde0ad2df369e518730d96594ff77d67fa73"
}

rule MalwareBazaar_unknown_100_30a54c02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30a54c0221e7ade433636c205e508aaa1006f4df93870ade8fb15db995b98704"
    family = "unknown"
    file_name = "eStatement_2026-10-01-155243639385945794.zip"
    file_type = "zip"
    first_seen = "2026-10-02 21:23:00"
  condition:
    hash.sha256(0, filesize) == "30a54c0221e7ade433636c205e508aaa1006f4df93870ade8fb15db995b98704"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

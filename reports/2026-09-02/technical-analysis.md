# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-02

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 609 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 609 |
| Unique family labels | 12 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 60 |
| Mirai | 24 |
| Vidar | 6 |
| AgentTesla | 2 |
| RatonRAT | 1 |
| ValleyRAT | 1 |
| DCRat | 1 |
| AsyncRAT | 1 |
| Prometei | 1 |
| NanoCore | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 31 |
| elf | 25 |
| sh | 22 |
| apk | 8 |
| unknown | 6 |
| jar | 3 |
| hta | 2 |
| dll | 1 |
| ps1 | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `abcdf531d86451ab`

| Field | Value |
|---|---|
| SHA-256 | `abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530` |
| Family label | `unknown` |
| File name | `abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530.exe` |
| File type | `exe` |
| First seen | `2026-09-02 04:23:55` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c84ac5fef6a85788d318a2c102695628` |
| SHA-1 | `f3dd558bf910098207f1e65fb8df17662433a8ad` |
| SHA-256 | `abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530` |
| SHA3-384 | `3fb02834ae1d425b5cbf0692f760b9a655c3eca3a680af8e83aafd484fd64af33509225f80eeb5098656eeb00e461a2a` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T17A05DF18A65974D8D46655F784C1371DAA3ABE0432C05DCA3ACFB2B16E317E0EDDBE20` |
| SSDEEP | `12288:qVrlmF0joZH7dW4z8yVgnWB2Q1RWAyDX3oTulqTyMHhYSpj5GL:jF0EZHVdVt0DobyMHm1` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_abcdf531
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530"
    family = "unknown"
    file_name = "abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530.exe"
    file_type = "exe"
    first_seen = "2026-09-02 04:23:55"
  condition:
    hash.sha256(0, filesize) == "abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530"
}
```

### Sample 2: `2c786f7009cc5e1f`

| Field | Value |
|---|---|
| SHA-256 | `2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b` |
| Family label | `Vidar` |
| File name | `2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b.exe` |
| File type | `exe` |
| First seen | `2026-09-02 04:17:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, Vidar, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c57391593bb9d975cd014089eca9cf38` |
| SHA-1 | `2dd409f171e9de0eb9c531a63236939a6ec91e21` |
| SHA-256 | `2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b` |
| SHA3-384 | `91612e5f82fe8fcb9cca217564b9faef9e88f2603724f6eab5f996d692f60e18bc10a65a98c6812f08d427a9c1e5fe5c` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T18105CE04A65574D8E46605F384C2771CAA26BE0572D05ECA3ECF76726E327E0EDDBE20` |
| SSDEEP | `24576:SRWQPHq19nRcCbx+r8HWcusqiLuKO2PXb9:mWhXnzbx+r88Shzb9` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_002_2c786f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b"
    family = "Vidar"
    file_name = "2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b.exe"
    file_type = "exe"
    first_seen = "2026-09-02 04:17:08"
  condition:
    hash.sha256(0, filesize) == "2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b"
}
```

### Sample 3: `7c8936eea9268692`

| Field | Value |
|---|---|
| SHA-256 | `7c8936eea92686924155c03b15400323ec6f9a3ff5e9d21deeb95bfb6e9d52f9` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-02 03:58:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `326300644720fd0dc56c930059537406` |
| SHA-1 | `ac9fc0a8fd89a05dca04579fabd228f588610e8a` |
| SHA-256 | `7c8936eea92686924155c03b15400323ec6f9a3ff5e9d21deeb95bfb6e9d52f9` |
| SHA3-384 | `753d6f2e0b4c82e06f78131944c9f33ff1e72cc8804a23e6ce57990f2405514f9b4aa39ca8eee39eafdda488958d9aa8` |
| TLSH | `T19331589E55104A710103CA9E73B33148B18DA6FB2C9FDBD4D95C4EA992883CDF2B1B5A` |
| SSDEEP | `24:U2MHWWvZWw8iQ/QC0q7FqPZ6PLh5uoPA6esAEpfm3mq:828UoC0q7Fq4PLh5SL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_7c8936ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8936eea92686924155c03b15400323ec6f9a3ff5e9d21deeb95bfb6e9d52f9"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-02 03:58:41"
  condition:
    hash.sha256(0, filesize) == "7c8936eea92686924155c03b15400323ec6f9a3ff5e9d21deeb95bfb6e9d52f9"
}
```

### Sample 4: `4e222513d31b3a7f`

| Field | Value |
|---|---|
| SHA-256 | `4e222513d31b3a7f06ed50143316a7a8d616148107281c701b7a3957a4fb3760` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-09-02 03:50:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b152ed02b73ac3a6de6d8ef264202c30` |
| SHA-1 | `183b533eae1356636910cc8c7a390594aa7e3caf` |
| SHA-256 | `4e222513d31b3a7f06ed50143316a7a8d616148107281c701b7a3957a4fb3760` |
| SHA3-384 | `a93adb2c68bb3b75f91b20aea000720cb0f9266a8e74ae9321535762ea6b3b317f32ae68085b65b3e2d60c888ec177da` |
| TLSH | `T1B55152C517620A753C539DC377AFCC447488AAFE68C29E56A9ED34E4464ECC9B084B63` |
| SSDEEP | `24:pKQTdtirX35ZYduVB0lP8xfuDX74bHhxXP:pKQRyXJeUYlP4fuP4bHhx/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_4e222513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e222513d31b3a7f06ed50143316a7a8d616148107281c701b7a3957a4fb3760"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-09-02 03:50:43"
  condition:
    hash.sha256(0, filesize) == "4e222513d31b3a7f06ed50143316a7a8d616148107281c701b7a3957a4fb3760"
}
```

### Sample 5: `97a99d7235071210`

| Field | Value |
|---|---|
| SHA-256 | `97a99d72350712109fb4f341bb6a4b6b7fd0f6ba962e4fc4ed0ab5fe74701ec6` |
| Family label | `unknown` |
| File name | `htarg2.hta` |
| File type | `hta` |
| First seen | `2026-09-02 03:46:54` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a599718164f2b1b46288a75d429cba6` |
| SHA-1 | `d0ef216d0ebe3d9ba6cead33199a6005ccdb15df` |
| SHA-256 | `97a99d72350712109fb4f341bb6a4b6b7fd0f6ba962e4fc4ed0ab5fe74701ec6` |
| SHA3-384 | `707df31380b4a415c8233b2ed3b6afddf2fce58fa28830892ede9b029590acaffdcfe3b83ff252b4c38b837b86487a57` |
| TLSH | `T1ADC2925442F21425455360359FBF6F44776A8A23658CAC08BDCC9580BFAE9B38EF7BE0` |
| SSDEEP | `768:wZBsjBjrAyhtbgt4MiIO/5/9SLv2BI2IzQZ:cMMyBHIm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_97a99d72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a99d72350712109fb4f341bb6a4b6b7fd0f6ba962e4fc4ed0ab5fe74701ec6"
    family = "unknown"
    file_name = "htarg2.hta"
    file_type = "hta"
    first_seen = "2026-09-02 03:46:54"
  condition:
    hash.sha256(0, filesize) == "97a99d72350712109fb4f341bb6a4b6b7fd0f6ba962e4fc4ed0ab5fe74701ec6"
}
```

### Sample 6: `dd54c3a168367b2c`

| Field | Value |
|---|---|
| SHA-256 | `dd54c3a168367b2c9226ceba83e2ec8b330b46c995db952c8b699bb85e6a7d03` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-02 03:46:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f23eb9c3680b7f78e8e1fc68429bea97` |
| SHA-1 | `688cdd0196c99da5aacd7cb219c92fcf876b90cb` |
| SHA-256 | `dd54c3a168367b2c9226ceba83e2ec8b330b46c995db952c8b699bb85e6a7d03` |
| SHA3-384 | `0a1e6f58014100631d27ec70a4c992e70eafa0dea40d4524ca9812449ae5346315225103a7768a74da13b2f2797911b5` |
| TLSH | `T17C13F1B297321E78C336A479CBB5D4D65229187C91AD30B757E0C3AB06B260A78F9063` |
| SSDEEP | `768:A1alP6Ywm4ZcAIiHJ7FThpTPlZntrbxMsBZWAUB2TD61VlnpVd0zNWGSD9q3UEx:AI7wm4RJ7phpTPPntXxMOZmBBnFDd6I+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_dd54c3a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd54c3a168367b2c9226ceba83e2ec8b330b46c995db952c8b699bb85e6a7d03"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-02 03:46:52"
  condition:
    hash.sha256(0, filesize) == "dd54c3a168367b2c9226ceba83e2ec8b330b46c995db952c8b699bb85e6a7d03"
}
```

### Sample 7: `4fb582653120dfc7`

| Field | Value |
|---|---|
| SHA-256 | `4fb582653120dfc75f067c83f58825a07c335b672912bd0c0882dcd1c4576343` |
| Family label | `unknown` |
| File name | `gocl` |
| File type | `sh` |
| First seen | `2026-09-02 03:38:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95ed0a04dbfad95e9d8070eea814a0aa` |
| SHA-1 | `4b373b5d6936a01b206455de0568ddb129867ed8` |
| SHA-256 | `4fb582653120dfc75f067c83f58825a07c335b672912bd0c0882dcd1c4576343` |
| SHA3-384 | `1173e3fae672abd25b2b2ec20eb198df28a4fedb60d417e3dfd777af1d1e8bf667913a84665192cef002ee6e073ae05b` |
| TLSH | `T1255161D527620A763D539DC337BF8C443488AAEF28C2AE56A9ED34E4454ECCAF184753` |
| SSDEEP | `24:pKQT9ttijtX3ZtZItdetVB0tVtnt8ht3tetDX7otbHRthtX5:pKQbcXzwamntG9APGbHr7p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_4fb58265
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fb582653120dfc75f067c83f58825a07c335b672912bd0c0882dcd1c4576343"
    family = "unknown"
    file_name = "gocl"
    file_type = "sh"
    first_seen = "2026-09-02 03:38:43"
  condition:
    hash.sha256(0, filesize) == "4fb582653120dfc75f067c83f58825a07c335b672912bd0c0882dcd1c4576343"
}
```

### Sample 8: `dd5e6012f32aab4c`

| Field | Value |
|---|---|
| SHA-256 | `dd5e6012f32aab4c61b485df7056b539fe7da45e4bd2267b972fd9dca45cf0b0` |
| Family label | `RatonRAT` |
| File name | `E39ED5AB22CCB772F31C6F939B8F9875.exe` |
| File type | `exe` |
| First seen | `2026-09-02 03:35:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, RatonRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e39ed5ab22ccb772f31c6f939b8f9875` |
| SHA-1 | `c627c22bb54f008a918429b9d66569f3f811540c` |
| SHA-256 | `dd5e6012f32aab4c61b485df7056b539fe7da45e4bd2267b972fd9dca45cf0b0` |
| SHA3-384 | `4f3749e84ae6e624cd38a41f04277a368b196dd20215a57d84b617b8a32b741591d7b49ff993fe035386a841aaaf1dd9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11D27CF2839FB501D7173FF557EE879DADD9F76732606A85B1081030B4A22E80EE9293D` |
| SSDEEP | `49152:Y6ZU9dt8SHwXxAQ856FL4bX8mdAajqwrmso0o6BjsjGfd+c5Wnjtv/F+U0AoztXD:hZ` |

#### Technical Assessment

- The sample is tracked as `RatonRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RatonRAT_008_dd5e6012
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd5e6012f32aab4c61b485df7056b539fe7da45e4bd2267b972fd9dca45cf0b0"
    family = "RatonRAT"
    file_name = "E39ED5AB22CCB772F31C6F939B8F9875.exe"
    file_type = "exe"
    first_seen = "2026-09-02 03:35:17"
  condition:
    hash.sha256(0, filesize) == "dd5e6012f32aab4c61b485df7056b539fe7da45e4bd2267b972fd9dca45cf0b0"
}
```

### Sample 9: `e370308419f516d8`

| Field | Value |
|---|---|
| SHA-256 | `e370308419f516d838706ad6cc467957d3b044316e2dd0e34bc11c186c0549e2` |
| Family label | `ValleyRAT` |
| File name | `EE00A6550765FADEF5FEBA0AAAAA08D0.dll` |
| File type | `dll` |
| First seen | `2026-09-02 03:35:12` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee00a6550765fadef5feba0aaaaa08d0` |
| SHA-1 | `13f31a7f7efdfebc82fcf550e74d63ea8c26bb03` |
| SHA-256 | `e370308419f516d838706ad6cc467957d3b044316e2dd0e34bc11c186c0549e2` |
| SHA3-384 | `6dfef5e04b50019200adc4fc77baab8aeb9439827c1074eec527ddf55f46bcd1a2da1245f1dc99662b2e37b60232ced1` |
| IMPHASH | `d5822bbb610a74c0ffb83554d889e5a4` |
| TLSH | `T1C4868D1377D0D8AAE2668374C581E6BD862D5D200FD882C376CF3E3739738916E646E6` |
| SSDEEP | `98304:zD+JUmYkINt0mvSVyX6LiJMQj0sCJjMl084eOMBBuBBI0/z0XqhS3tvpF80sEE:3+82iJMQjsM14eOMPkBI2aqhctn` |
| ICON-DHASH | `8660a2b2b5d861a4` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_009_e3703084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e370308419f516d838706ad6cc467957d3b044316e2dd0e34bc11c186c0549e2"
    family = "ValleyRAT"
    file_name = "EE00A6550765FADEF5FEBA0AAAAA08D0.dll"
    file_type = "dll"
    first_seen = "2026-09-02 03:35:12"
  condition:
    hash.sha256(0, filesize) == "e370308419f516d838706ad6cc467957d3b044316e2dd0e34bc11c186c0549e2"
}
```

### Sample 10: `337383182a47e38d`

| Field | Value |
|---|---|
| SHA-256 | `337383182a47e38d6a961223a537c7a41e2267f5f12ca474d61ff1b854801617` |
| Family label | `DCRat` |
| File name | `44D0D337F28453D669F10960FC2B6A55.exe` |
| File type | `exe` |
| First seen | `2026-09-02 03:35:07` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44d0d337f28453d669f10960fc2b6a55` |
| SHA-1 | `dcf17c1ba00663ec39465a7ed4d78845e796f9ef` |
| SHA-256 | `337383182a47e38d6a961223a537c7a41e2267f5f12ca474d61ff1b854801617` |
| SHA3-384 | `6afa3dee31a7ba44dd093062c920aa2c53cc28d1887bc69ff0e0f7cbfb9eedba0ddb9d2392e064985a2fcb7370003994` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19D0509017E46CE51F0591233C2EF894847B0AD6166A6E31B7EBA3B7E15123A77C0D9CB` |
| SSDEEP | `12288:BYKtDFX8bxMN1+lWM/CR6oYe2M3vaT+LaGT1ONYPQIWFRw:B1pFX8bxNUQCR6reBL3gNYPQDy` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_010_33738318
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "337383182a47e38d6a961223a537c7a41e2267f5f12ca474d61ff1b854801617"
    family = "DCRat"
    file_name = "44D0D337F28453D669F10960FC2B6A55.exe"
    file_type = "exe"
    first_seen = "2026-09-02 03:35:07"
  condition:
    hash.sha256(0, filesize) == "337383182a47e38d6a961223a537c7a41e2267f5f12ca474d61ff1b854801617"
}
```

### Sample 11: `98ec6a83a3133197`

| Field | Value |
|---|---|
| SHA-256 | `98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555` |
| Family label | `unknown` |
| File name | `98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555.bin` |
| File type | `exe` |
| First seen | `2026-09-02 03:31:20` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `389055b0def3f57fc15695e1e7623534` |
| SHA-1 | `a12c6aaccc3dcb8a22ba3bfe5d19f49417ce5136` |
| SHA-256 | `98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555` |
| SHA3-384 | `3ee09635528af7ef33ba6a0846793827dd78db92b9ce33d6b20b37c05a2bdaab55115801706636fe7727aeb48d71a392` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10E86BE037B81C1B0D496EA7AC4B6415177B87C4D833433AB6EA5A9303F263D1B67AF64` |
| SSDEEP | `98304:+yhg0v/sH7wSkSUx3TSQ9n1Z76br5M4vIMPKm:+yhrXq7kbTt1Abd/LPKm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_98ec6a83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555"
    family = "unknown"
    file_name = "98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555.bin"
    file_type = "exe"
    first_seen = "2026-09-02 03:31:20"
  condition:
    hash.sha256(0, filesize) == "98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555"
}
```

### Sample 12: `0dba4b85fa20faee`

| Field | Value |
|---|---|
| SHA-256 | `0dba4b85fa20faee019dfe6d6ac86a5832dfe9f7a02cf1186e2790461c165fa1` |
| Family label | `unknown` |
| File name | `htaallofus.hta` |
| File type | `hta` |
| First seen | `2026-09-02 03:28:31` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `226921f1f3afae1995a82d36480a35a5` |
| SHA-1 | `e70aee18879fe0b6c2c44660df4a10638eb27b4c` |
| SHA-256 | `0dba4b85fa20faee019dfe6d6ac86a5832dfe9f7a02cf1186e2790461c165fa1` |
| SHA3-384 | `689f5055fd207d13d43c724fc9f7fc36b14d726c2c9bb45dfb292e2fffa7dc5b812dc9ff7b9ea789dccb19b36c88ff4b` |
| TLSH | `T160C2835982F20821055770359EBF6E4876795A23654CEC0CBD8C9940BF6E9B38DF7BE0` |
| SSDEEP | `768:wZBsjBjrAyhtbgt4MiIO/5/9SLTHDf4Slf4SaQZ:cMMvjfvlfvam` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_0dba4b85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dba4b85fa20faee019dfe6d6ac86a5832dfe9f7a02cf1186e2790461c165fa1"
    family = "unknown"
    file_name = "htaallofus.hta"
    file_type = "hta"
    first_seen = "2026-09-02 03:28:31"
  condition:
    hash.sha256(0, filesize) == "0dba4b85fa20faee019dfe6d6ac86a5832dfe9f7a02cf1186e2790461c165fa1"
}
```

### Sample 13: `281e48fd0032c7d0`

| Field | Value |
|---|---|
| SHA-256 | `281e48fd0032c7d066cf86248f169701fb74dffe85bffef98447ca37acd50267` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-02 03:27:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ff75fd3b18570491ca46e9a7492ebf1` |
| SHA-1 | `fc972e65b96e63c09e5ffebdefcdd2293c7c5ccb` |
| SHA-256 | `281e48fd0032c7d066cf86248f169701fb74dffe85bffef98447ca37acd50267` |
| SHA3-384 | `2c9b6581047b1140747506f3c4c032d5a28fc3cc1337b9337c91d5ecac508677fc15c4055fa239d8d37dabf31d0ecf9c` |
| TLSH | `T17BC27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:Ly8vCB+25j6es8RW9FYpMSUpi+20qUpi+20YQX:28l25JAd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_281e48fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "281e48fd0032c7d066cf86248f169701fb74dffe85bffef98447ca37acd50267"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 03:27:04"
  condition:
    hash.sha256(0, filesize) == "281e48fd0032c7d066cf86248f169701fb74dffe85bffef98447ca37acd50267"
}
```

### Sample 14: `bcac04bb75d63a10`

| Field | Value |
|---|---|
| SHA-256 | `bcac04bb75d63a10dfeaffb52116b3488ebe1427c484027aa763830df6f00710` |
| Family label | `unknown` |
| File name | `k.sh` |
| File type | `sh` |
| First seen | `2026-09-02 03:24:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84e2c6bbe7f035f58354e8677c27dfac` |
| SHA-1 | `7e97693d82ff38abe59a8ea9f7e559c885108614` |
| SHA-256 | `bcac04bb75d63a10dfeaffb52116b3488ebe1427c484027aa763830df6f00710` |
| SHA3-384 | `1199276230f9ca2ef0e0cd481cce73abc1a4eb1f4ccfd912554f558ebd25fce76e2997a26e2de211697df30a9de6a247` |
| TLSH | `T1EE5150C917620EB53C53ADC337AF8C457488AAEE28C29E55A9ED34E4454ECCEF085B53` |
| SSDEEP | `24:pKQTFti7X3JZKdAVBuN38hnADX7qbHxhXl:pKQBsX5QOKN3qnAPqbHxh1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_bcac04bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcac04bb75d63a10dfeaffb52116b3488ebe1427c484027aa763830df6f00710"
    family = "unknown"
    file_name = "k.sh"
    file_type = "sh"
    first_seen = "2026-09-02 03:24:00"
  condition:
    hash.sha256(0, filesize) == "bcac04bb75d63a10dfeaffb52116b3488ebe1427c484027aa763830df6f00710"
}
```

### Sample 15: `5319410a75d9d84c`

| Field | Value |
|---|---|
| SHA-256 | `5319410a75d9d84c4d22c5d31cb4b1458940c139043e6c024d211c193402dc7f` |
| Family label | `unknown` |
| File name | `mdndwrciuiidpoppymgzselulrrl` |
| File type | `unknown` |
| First seen | `2026-09-02 03:23:41` |
| Reporter | `BastianHein_` |
| Tags | `Data` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f6d54871a5884ddd22a4706f6103c5e` |
| SHA-256 | `5319410a75d9d84c4d22c5d31cb4b1458940c139043e6c024d211c193402dc7f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_5319410a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5319410a75d9d84c4d22c5d31cb4b1458940c139043e6c024d211c193402dc7f"
    family = "unknown"
    file_name = "mdndwrciuiidpoppymgzselulrrl"
    file_type = "unknown"
    first_seen = "2026-09-02 03:23:41"
  condition:
    hash.sha256(0, filesize) == "5319410a75d9d84c4d22c5d31cb4b1458940c139043e6c024d211c193402dc7f"
}
```

### Sample 16: `9e1ff143e38bdb3c`

| Field | Value |
|---|---|
| SHA-256 | `9e1ff143e38bdb3c8ce3e876f87ff343080ca2765c4b64b530857cd2d0c8efc6` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-02 03:16:40` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4d2368ae5c4ea08138785c3aa5bbba7` |
| SHA-256 | `9e1ff143e38bdb3c8ce3e876f87ff343080ca2765c4b64b530857cd2d0c8efc6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_9e1ff143
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e1ff143e38bdb3c8ce3e876f87ff343080ca2765c4b64b530857cd2d0c8efc6"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 03:16:40"
  condition:
    hash.sha256(0, filesize) == "9e1ff143e38bdb3c8ce3e876f87ff343080ca2765c4b64b530857cd2d0c8efc6"
}
```

### Sample 17: `fdd1b1e07b75c332`

| Field | Value |
|---|---|
| SHA-256 | `fdd1b1e07b75c332526ca0ffc9463ad1b6ddcfa09fa2aefe69d8afdf60759104` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-02 03:14:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5d20533e82028319e35ac3991c9049e` |
| SHA-1 | `5d3042ffc005a7acce70e15f82890e0be3c500ba` |
| SHA-256 | `fdd1b1e07b75c332526ca0ffc9463ad1b6ddcfa09fa2aefe69d8afdf60759104` |
| SHA3-384 | `c6bae76d37b4cb9acc02ae06b1dfd3d1b7bd0bb316e3cb551a9ee8805cfe72e0be14b6a8e1aeae806cdb129d49b4dd1d` |
| TLSH | `T136236D651A857C24AA98C4371D7E2F0CBDAD43E6324492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:fXRWNGxVqx9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ZlxU6cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_fdd1b1e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd1b1e07b75c332526ca0ffc9463ad1b6ddcfa09fa2aefe69d8afdf60759104"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 03:14:40"
  condition:
    hash.sha256(0, filesize) == "fdd1b1e07b75c332526ca0ffc9463ad1b6ddcfa09fa2aefe69d8afdf60759104"
}
```

### Sample 18: `04c50ef404477631`

| Field | Value |
|---|---|
| SHA-256 | `04c50ef404477631936fad3b6ad741d8c6eb498c5fe957b1dca734ebf9bb5796` |
| Family label | `AsyncRAT` |
| File name | `ps_Vef9thK1xPcU_1788247758514.ps1` |
| File type | `ps1` |
| First seen | `2026-09-02 03:11:53` |
| Reporter | `BastianHein_` |
| Tags | `AsyncRAT, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17dea164467470c2ba754eeca3cdfe42` |
| SHA-1 | `73f2dde7797b01034ce2b131cf3cd2c132f72827` |
| SHA-256 | `04c50ef404477631936fad3b6ad741d8c6eb498c5fe957b1dca734ebf9bb5796` |
| SHA3-384 | `973c53c1b4c2dc5e3bcd604d83995a96dadc11c8a50256a08059ebf49b13377eb2644d10617d6106bb0b0d6b25b36963` |
| TLSH | `T124840AF87928FFC7962916B7D8197C20097B5732A01E51C49A29784A0FA7BFE9D0FC41` |
| SSDEEP | `6144:eWbK7VCU1eEGvUo+h0AkUS0LAGt24f0U/KDm5d5Qw6PSLJzDnnmv:v8APoSB` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_018_04c50ef4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04c50ef404477631936fad3b6ad741d8c6eb498c5fe957b1dca734ebf9bb5796"
    family = "AsyncRAT"
    file_name = "ps_Vef9thK1xPcU_1788247758514.ps1"
    file_type = "ps1"
    first_seen = "2026-09-02 03:11:53"
  condition:
    hash.sha256(0, filesize) == "04c50ef404477631936fad3b6ad741d8c6eb498c5fe957b1dca734ebf9bb5796"
}
```

### Sample 19: `92df18d9fdb738a1`

| Field | Value |
|---|---|
| SHA-256 | `92df18d9fdb738a1e71605232d9cfeaef76b43442b861632c6739476cd126daa` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-02 03:00:38` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f930d4b41b616e873e23b2eaa1abce2` |
| SHA-256 | `92df18d9fdb738a1e71605232d9cfeaef76b43442b861632c6739476cd126daa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_92df18d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92df18d9fdb738a1e71605232d9cfeaef76b43442b861632c6739476cd126daa"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 03:00:38"
  condition:
    hash.sha256(0, filesize) == "92df18d9fdb738a1e71605232d9cfeaef76b43442b861632c6739476cd126daa"
}
```

### Sample 20: `05c534335612b6c3`

| Field | Value |
|---|---|
| SHA-256 | `05c534335612b6c3278f957ab0f40fa1f25f6e26488790416f87720ea04dfce5` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-02 02:54:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `986764a1605929323220eaa0fc4c1e5b` |
| SHA-1 | `6155c90ba0e240791801b81b94f9357f27e8180c` |
| SHA-256 | `05c534335612b6c3278f957ab0f40fa1f25f6e26488790416f87720ea04dfce5` |
| SHA3-384 | `3ad7df43203b5577f66ca4624ab2a6fd95f5279fa09fbc14834fadf5130cc1fc92a7b7d135c46dae65057a5b2705e4c1` |
| TLSH | `T159235B651A857C14AA98C4361D7F2F0CB9AD43E6320452EE7FCF3CF28C5AAAD910572D` |
| SSDEEP | `768:At6Utd8/K9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Aecr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_05c53433
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05c534335612b6c3278f957ab0f40fa1f25f6e26488790416f87720ea04dfce5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 02:54:37"
  condition:
    hash.sha256(0, filesize) == "05c534335612b6c3278f957ab0f40fa1f25f6e26488790416f87720ea04dfce5"
}
```

### Sample 21: `defea42799ac63b0`

| Field | Value |
|---|---|
| SHA-256 | `defea42799ac63b024fba18364bb199923faf5a1cf44ad0c1825fdcde0e18f77` |
| Family label | `unknown` |
| File name | `Meteor-Client-1.21.11-87-meteorclient.cc.jar` |
| File type | `jar` |
| First seen | `2026-09-02 02:54:00` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0269ad70b131e6c994a14b6bb71608e8` |
| SHA-256 | `defea42799ac63b024fba18364bb199923faf5a1cf44ad0c1825fdcde0e18f77` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_defea427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "defea42799ac63b024fba18364bb199923faf5a1cf44ad0c1825fdcde0e18f77"
    family = "unknown"
    file_name = "Meteor-Client-1.21.11-87-meteorclient.cc.jar"
    file_type = "jar"
    first_seen = "2026-09-02 02:54:00"
  condition:
    hash.sha256(0, filesize) == "defea42799ac63b024fba18364bb199923faf5a1cf44ad0c1825fdcde0e18f77"
}
```

### Sample 22: `cf9782def5ca04fa`

| Field | Value |
|---|---|
| SHA-256 | `cf9782def5ca04fa493ba640a4ab10a75288554a3f883fede8431a525f550c3c` |
| Family label | `unknown` |
| File name | `Meteor-GUI-addon-2_2_0.jar` |
| File type | `jar` |
| First seen | `2026-09-02 02:53:52` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcde1b78cb8af3f6712bfe91efca00f7` |
| SHA-256 | `cf9782def5ca04fa493ba640a4ab10a75288554a3f883fede8431a525f550c3c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_cf9782de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf9782def5ca04fa493ba640a4ab10a75288554a3f883fede8431a525f550c3c"
    family = "unknown"
    file_name = "Meteor-GUI-addon-2_2_0.jar"
    file_type = "jar"
    first_seen = "2026-09-02 02:53:52"
  condition:
    hash.sha256(0, filesize) == "cf9782def5ca04fa493ba640a4ab10a75288554a3f883fede8431a525f550c3c"
}
```

### Sample 23: `d460ba58bb99d868`

| Field | Value |
|---|---|
| SHA-256 | `d460ba58bb99d868d5010862d1a157f37ced69f230662f1db73d3d7358989645` |
| Family label | `unknown` |
| File name | `Leakestan-Addon-V6.jar` |
| File type | `jar` |
| First seen | `2026-09-02 02:53:36` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5589953fee9896e1bedbf816422b0547` |
| SHA-256 | `d460ba58bb99d868d5010862d1a157f37ced69f230662f1db73d3d7358989645` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d460ba58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d460ba58bb99d868d5010862d1a157f37ced69f230662f1db73d3d7358989645"
    family = "unknown"
    file_name = "Leakestan-Addon-V6.jar"
    file_type = "jar"
    first_seen = "2026-09-02 02:53:36"
  condition:
    hash.sha256(0, filesize) == "d460ba58bb99d868d5010862d1a157f37ced69f230662f1db73d3d7358989645"
}
```

### Sample 24: `d226baf09ee2071f`

| Field | Value |
|---|---|
| SHA-256 | `d226baf09ee2071fd90a2e413d384a98768fd9188314414cf4179aaa1f834a52` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-02 02:52:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abea89835af762cf40f50462a6c4bc69` |
| SHA-1 | `a07aece9fc86238c4d7e9d2154ab1b572e35b0b4` |
| SHA-256 | `d226baf09ee2071fd90a2e413d384a98768fd9188314414cf4179aaa1f834a52` |
| SHA3-384 | `d37709ee6ccc3e1121895c3f9fc4b7861768f1066db564db06fc9922c9cfd3914cce98211aa116e52f3c9419fdca3e9b` |
| TLSH | `T1F8C28D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:U8vCB+25j6es8Ru9FYpMSUpi+20qUpi+20YQX:U8l25JId2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_d226baf0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d226baf09ee2071fd90a2e413d384a98768fd9188314414cf4179aaa1f834a52"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 02:52:36"
  condition:
    hash.sha256(0, filesize) == "d226baf09ee2071fd90a2e413d384a98768fd9188314414cf4179aaa1f834a52"
}
```

### Sample 25: `7c83eaa84cbf4f5b`

| Field | Value |
|---|---|
| SHA-256 | `7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f` |
| Family label | `unknown` |
| File name | `7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f.bin` |
| File type | `exe` |
| First seen | `2026-09-02 02:36:31` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `981ab1ef2193514f56e37e8ed322837e` |
| SHA-1 | `b23111ec2f200f9797ae7130a323e70685a24885` |
| SHA-256 | `7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f` |
| SHA3-384 | `4cadd85dc841c97099311f2a13827b71f562a751b6350a38301e72fb1c7e844adbb1c8c84d2f17e54e1d6835c16e393a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T18B666B073E9181B5E05AC63995BB5252AB30BC0C9F7673D32E50B2751F723E07AB9B48` |
| SSDEEP | `49152:4/TRQOefUFeN2EQr/2uPXjaECBF1tG4QaTzdttttattta87PGA5oUmlfB6W3Ew5v:4sQjaECBF184QtXo7lp33HBb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_7c83eaa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f"
    family = "unknown"
    file_name = "7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f.bin"
    file_type = "exe"
    first_seen = "2026-09-02 02:36:31"
  condition:
    hash.sha256(0, filesize) == "7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f"
}
```

### Sample 26: `1dd8bce285a28968`

| Field | Value |
|---|---|
| SHA-256 | `1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39` |
| Family label | `Vidar` |
| File name | `1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39.bin` |
| File type | `exe` |
| First seen | `2026-09-02 02:36:29` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cea0892394ac5e26c48336c1b89629ed` |
| SHA-1 | `6dc72501038e40c90aca22445f827916e4b0e536` |
| SHA-256 | `1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39` |
| SHA3-384 | `80a30a6e58abdb8cedb0219b63aeee8ae69455bd719f0c62060dc850d1b2a7e14d3dd76caed51fc6dfbc46ac34fa87ed` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16B668C073E9041B9E44ECA3990BB1256AB74BC0C9B7673D32D50B6701F767E42AF9B48` |
| SSDEEP | `98304:6ct0vFDB1sRbyWfB70+Z6EY7zD3tEbba+Rwfv6E:6ct0vFDB1sd/NYh7zD9Eb++Rwn6E` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_026_1dd8bce2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39"
    family = "Vidar"
    file_name = "1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39.bin"
    file_type = "exe"
    first_seen = "2026-09-02 02:36:29"
  condition:
    hash.sha256(0, filesize) == "1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39"
}
```

### Sample 27: `d188167a5f520c91`

| Field | Value |
|---|---|
| SHA-256 | `d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba` |
| Family label | `Mirai` |
| File name | `d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba.elf` |
| File type | `elf` |
| First seen | `2026-09-02 02:32:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b36bab5d1394874bce1f30ae5ba80be` |
| SHA-1 | `23f8f1d3ac1157f70bc9c156eaaaeb46f40b7b59` |
| SHA-256 | `d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba` |
| SHA3-384 | `d795aebc792555f07de784a5ee5527a65c9ee31a722a1e86c48226d79c04bd5c6f60a4fdedbc6418fd07d8c53f943ea7` |
| TLSH | `T15BE3188BAA2D0793C4A759F13D6B37F48B9CE93012A522C5D20AEFC017779B51432F5A` |
| TELFHASH | `t196312e314a3196116fa1c9589cee53a7282e82222284ef73ee35c4cc54090ebf637c0f` |
| SSDEEP | `1536:9ITldMQOT9rK/xp7JTvSvWIK/QAqnext2jol65JqL8BbseurAFEPH22wJd5lqJ:UJTvSG/P2jo05N68Gv22wz5lqJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_d188167a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba"
    family = "Mirai"
    file_name = "d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba.elf"
    file_type = "elf"
    first_seen = "2026-09-02 02:32:55"
  condition:
    hash.sha256(0, filesize) == "d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba"
}
```

### Sample 28: `a96a70bacff99009`

| Field | Value |
|---|---|
| SHA-256 | `a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097` |
| Family label | `Mirai` |
| File name | `a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097.elf` |
| File type | `elf` |
| First seen | `2026-09-02 02:28:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74885e2354ddc33c0b8def383a61d0a1` |
| SHA-1 | `8352171db9afc4550ac3eee9030950681c1d0d75` |
| SHA-256 | `a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097` |
| SHA3-384 | `5bec7e31752853c9a4e40c8b75ff662c77d289aea47e71e31e9b04d540279c8070a90609079cf544bd827391e56f519d` |
| TLSH | `T116354A16F2B370ADC093C139479BDBB2A939F07902126D7B32C19A353946EA05F19F67` |
| TELFHASH | `t1b6712465293c12d999a2ac0488b56bd3548bd2393358ea1afb77cdc818ce89df135c0f` |
| SSDEEP | `24576:GQJD3Hkr22MwUXb5wAU30xWgX6X1HvHt1H0s:DF3Hkr22Ml5w1yWU6X1HzH0s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_a96a70ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097"
    family = "Mirai"
    file_name = "a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097.elf"
    file_type = "elf"
    first_seen = "2026-09-02 02:28:35"
  condition:
    hash.sha256(0, filesize) == "a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097"
}
```

### Sample 29: `8fe5e64400bf61f5`

| Field | Value |
|---|---|
| SHA-256 | `8fe5e64400bf61f51ae8174ed1494925593c51be91d3a50be7e0a53b50a1c1d9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-02 02:28:32` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `627db80b20a4f26ca9136ea6d44d41d3` |
| SHA-1 | `5338f8b758a790bc76ede09690fd91e95f8abab3` |
| SHA-256 | `8fe5e64400bf61f51ae8174ed1494925593c51be91d3a50be7e0a53b50a1c1d9` |
| SHA3-384 | `e613908497dac40153067b0bad8ca57fd1009419c0de0b52817fa196475b748db99a1957b4cae9a9b57aa21af6efaa6a` |
| TLSH | `T1AB6508404E8298EAFBE36211D84F8381E6EE37C1472508B38D6D57A93675BC94DBB14F` |
| SSDEEP | `12288:bkh+v4YWX6RiJmlyqKoAHhMfy1rTbdefoqabZdy3Ot49ymsDNC33suHUM55SIcGm:bkwW+yIAHhGglei4dYH4UAGGm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_8fe5e644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fe5e64400bf61f51ae8174ed1494925593c51be91d3a50be7e0a53b50a1c1d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 02:28:32"
  condition:
    hash.sha256(0, filesize) == "8fe5e64400bf61f51ae8174ed1494925593c51be91d3a50be7e0a53b50a1c1d9"
}
```

### Sample 30: `591b9630e46777ed`

| Field | Value |
|---|---|
| SHA-256 | `591b9630e46777ed975fdc28780d8c29886b4903b85d145dd0ed55f9cdd4c7e9` |
| Family label | `unknown` |
| File name | `mPVJOUsu7vCH.plmn` |
| File type | `unknown` |
| First seen | `2026-09-02 02:05:30` |
| Reporter | `Summerbanquet` |
| Tags | `dropper, encrypted, installer, renpy, xor` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e8cfde758af2782a66b16c1793acbab` |
| SHA-256 | `591b9630e46777ed975fdc28780d8c29886b4903b85d145dd0ed55f9cdd4c7e9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_591b9630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "591b9630e46777ed975fdc28780d8c29886b4903b85d145dd0ed55f9cdd4c7e9"
    family = "unknown"
    file_name = "mPVJOUsu7vCH.plmn"
    file_type = "unknown"
    first_seen = "2026-09-02 02:05:30"
  condition:
    hash.sha256(0, filesize) == "591b9630e46777ed975fdc28780d8c29886b4903b85d145dd0ed55f9cdd4c7e9"
}
```

### Sample 31: `ecbf9e6de52105be`

| Field | Value |
|---|---|
| SHA-256 | `ecbf9e6de52105be852593472611a21989effc7d4e73acb4a0d0a01347a8d079` |
| Family label | `unknown` |
| File name | `8xzp2GYia.exe` |
| File type | `exe` |
| First seen | `2026-09-02 02:05:22` |
| Reporter | `Summerbanquet` |
| Tags | `4ddig, dropper, exe, renpy, tenorshare, userdatacollect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8d87c051555c6ff0337065ff828f7c6` |
| SHA-256 | `ecbf9e6de52105be852593472611a21989effc7d4e73acb4a0d0a01347a8d079` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_ecbf9e6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecbf9e6de52105be852593472611a21989effc7d4e73acb4a0d0a01347a8d079"
    family = "unknown"
    file_name = "8xzp2GYia.exe"
    file_type = "exe"
    first_seen = "2026-09-02 02:05:22"
  condition:
    hash.sha256(0, filesize) == "ecbf9e6de52105be852593472611a21989effc7d4e73acb4a0d0a01347a8d079"
}
```

### Sample 32: `99b5add0795fe9e2`

| Field | Value |
|---|---|
| SHA-256 | `99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e` |
| Family label | `unknown` |
| File name | `99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e.exe` |
| File type | `exe` |
| First seen | `2026-09-02 01:52:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `194bd8eedb00fd6a6ee9d1dc558f1dce` |
| SHA-1 | `3c80d2fd80426ca333f02fe197634ef0a10be0e5` |
| SHA-256 | `99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e` |
| SHA3-384 | `abde5bf2e5b124b31629679f02758e636cc830e7029b878f36f9c343463de50730d62fd7f438b4e4acea71317d74362f` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T128D523CA64F64A74D833C7769F53F86DB07C3B814AB28D977B8C2A504D626506C393B2` |
| SSDEEP | `49152:8a/zh28nydPrrIEGhkN/WKyxCk9EpT6MbI0/rWaQRekVcGI3mJPkJt8e5WEGN7c7:8Q128ydTMELJWZ9EBPI8WbDuGI3APy3N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_99b5add0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e"
    family = "unknown"
    file_name = "99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e.exe"
    file_type = "exe"
    first_seen = "2026-09-02 01:52:09"
  condition:
    hash.sha256(0, filesize) == "99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e"
}
```

### Sample 33: `b95be1e0cc70ac1e`

| Field | Value |
|---|---|
| SHA-256 | `b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea` |
| Family label | `unknown` |
| File name | `b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea.exe` |
| File type | `exe` |
| First seen | `2026-09-02 01:32:37` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1d271074cea3651385460a87c370aeb` |
| SHA-1 | `aaa7ef8731d868773b7d8331dba821ca38463e54` |
| SHA-256 | `b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea` |
| SHA3-384 | `4a0bad05cbb3e90ca23e8e0da8e67c1af538bb0be051d9e7470454805612d5714e107b8c847766692a5c4c74055f728d` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T1A43633E6A5C68078D085C3F04A9325ADB33FBF6986647D0FB9CC1D094DABD58623D782` |
| SSDEEP | `98304:RetwbMMmvZwBVYLZ1hJAOCiwhPqv8vLxSE1C8A6FZb/x73rn:RenneobAOCidMtbVfb/xzrn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_b95be1e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea"
    family = "unknown"
    file_name = "b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea.exe"
    file_type = "exe"
    first_seen = "2026-09-02 01:32:37"
  condition:
    hash.sha256(0, filesize) == "b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea"
}
```

### Sample 34: `548ccd5fb7078a61`

| Field | Value |
|---|---|
| SHA-256 | `548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065` |
| Family label | `Prometei` |
| File name | `548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065` |
| File type | `elf` |
| First seen | `2026-09-02 01:03:44` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cf2b674a18e019b136716daec59cd97` |
| SHA-1 | `f8db0c799bbda6453c2df4f87cdd59b5e294a9b4` |
| SHA-256 | `548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065` |
| SHA3-384 | `83b0f63087a70ebc428ded79a8289efad1db0b0390366339c0b937b59b591e6c06c286fd405feec42548ceb485201cf2` |
| TLSH | `T1E5A423B4F9219E9F6DD769B91B24831DE182C172589D4C2313AE94A34F3D732AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdx:Fs6pyCC/Ya2hpi6T6N4z` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_034_548ccd5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065"
    family = "Prometei"
    file_name = "548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065"
    file_type = "elf"
    first_seen = "2026-09-02 01:03:44"
  condition:
    hash.sha256(0, filesize) == "548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065"
}
```

### Sample 35: `82ae5ea133f03ac7`

| Field | Value |
|---|---|
| SHA-256 | `82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2` |
| Family label | `unknown` |
| File name | `82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2.bin` |
| File type | `sh` |
| First seen | `2026-09-02 00:32:07` |
| Reporter | `Tuxxin` |
| Tags | `script, sh, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ee6e5e194ce693123c88d8c7dea37a7` |
| SHA-1 | `f3f47b818c647686f123cbe7dd807f69d25caca4` |
| SHA-256 | `82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2` |
| SHA3-384 | `1ed19b569a329a40900253a94043db9da08f53a54c411901c6c6a598defdda0031acfa8889e41a9c37c2577189a40364` |
| TLSH | `T12E110ACF00D14C7128564DDBF7939924B586C5CE19C74EC9628B1E25F098D047869F6E` |
| SSDEEP | `24:EIbr5zOt+MB0k0+kdzP5nP5nkdz0IHkdzYZIHkdzYSkdC:xr5CEA0k0+kdzPdP9kdzHHkdzYZIHkdn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_82ae5ea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2"
    family = "unknown"
    file_name = "82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2.bin"
    file_type = "sh"
    first_seen = "2026-09-02 00:32:07"
  condition:
    hash.sha256(0, filesize) == "82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2"
}
```

### Sample 36: `f609e8d696848460`

| Field | Value |
|---|---|
| SHA-256 | `f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac` |
| Family label | `Vidar` |
| File name | `f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac.bin` |
| File type | `exe` |
| First seen | `2026-09-02 00:16:36` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17a06d209a2d60a1dbe2e71f3693548d` |
| SHA-1 | `ec53bc860173a0937929e70d994a8bcbb6ce8954` |
| SHA-256 | `f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac` |
| SHA3-384 | `0c4f82987eb3c744cb6e12617b8b7cb481792e959c67d86dfb59172d8cd50025b06a9b16c85e4f6a576cfe06a888eb3c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17FC67B17AD6602E4C9A5D778C4B742427778B8498B3133E36E10BAB42F767D0BEB9314` |
| SSDEEP | `49152:sdExKx5+W6gbAidlQEJ7CASalVL5wB9LGoi9gfRKQpi7LhLXLedn0k0yrTfp7ZIr:sN60hP4JGfQwo7Z/LGqQanyUGJL+IP` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_036_f609e8d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac"
    family = "Vidar"
    file_name = "f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac.bin"
    file_type = "exe"
    first_seen = "2026-09-02 00:16:36"
  condition:
    hash.sha256(0, filesize) == "f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac"
}
```

### Sample 37: `af43118256344a1c`

| Field | Value |
|---|---|
| SHA-256 | `af43118256344a1ce971c6d1910722f5d9ead1dee0f9ce7aedd18a6e9e53146a` |
| Family label | `AgentTesla` |
| File name | `factura de compra.js` |
| File type | `js` |
| First seen | `2026-09-02 00:07:39` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a0c44006c5d2a258bd33b9f592bf201` |
| SHA-1 | `11fe8ca71c238077066d106e28f0d86fa0c1d00c` |
| SHA-256 | `af43118256344a1ce971c6d1910722f5d9ead1dee0f9ce7aedd18a6e9e53146a` |
| SHA3-384 | `c140e28f40601869226baf53017ec2902be8a2ef750c92ada77b50e435b93d75b5cf8723a74998b8631ffc3207a43bc7` |
| TLSH | `T1C4B41206B3D7B93843E94A23A03EF95E41E942A04C5EF6CC8E55FCD44F9DB4A857282D` |
| SSDEEP | `12288:k4NZ7C1LxfTKNsYwetliQ6dw1KmcedqbjUOkE9AxH:kOZC1dfTxYweHIw1EedIzUH` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_037_af431182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af43118256344a1ce971c6d1910722f5d9ead1dee0f9ce7aedd18a6e9e53146a"
    family = "AgentTesla"
    file_name = "factura de compra.js"
    file_type = "js"
    first_seen = "2026-09-02 00:07:39"
  condition:
    hash.sha256(0, filesize) == "af43118256344a1ce971c6d1910722f5d9ead1dee0f9ce7aedd18a6e9e53146a"
}
```

### Sample 38: `96812d2a00a6ced7`

| Field | Value |
|---|---|
| SHA-256 | `96812d2a00a6ced73e1eae84ed4791ec6b7b687e89fa097183b843042dd9d70b` |
| Family label | `NanoCore` |
| File name | `C856731038D020706AAAA7DA2A8E46A5.exe` |
| File type | `exe` |
| First seen | `2026-09-02 00:05:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c856731038d020706aaaa7da2a8e46a5` |
| SHA-1 | `691a4174b77f58bf7ef07cf95250d5aedfbdff28` |
| SHA-256 | `96812d2a00a6ced73e1eae84ed4791ec6b7b687e89fa097183b843042dd9d70b` |
| SHA3-384 | `ddeb52d424faef7d7f4f660a90aab1466261eee7029f46b8ad8907415d4ea6089dd3cea14e8197a724d1945a1cbea6ac` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F214CF257BA94A2FE2DE86B9701251538379C2E398C3F7EE28D854B34F663E506071C3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5TEN/wjwJsvle+o9f/l:MLV6BtpmkxElep1` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_038_96812d2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96812d2a00a6ced73e1eae84ed4791ec6b7b687e89fa097183b843042dd9d70b"
    family = "NanoCore"
    file_name = "C856731038D020706AAAA7DA2A8E46A5.exe"
    file_type = "exe"
    first_seen = "2026-09-02 00:05:06"
  condition:
    hash.sha256(0, filesize) == "96812d2a00a6ced73e1eae84ed4791ec6b7b687e89fa097183b843042dd9d70b"
}
```

### Sample 39: `1b723594e574c00a`

| Field | Value |
|---|---|
| SHA-256 | `1b723594e574c00aac2c946ff738a0454f7c24f6ebc84ae45a6af9628b08cb96` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 23:57:10` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b70dffebf111dc575795f0b9da73f01` |
| SHA-1 | `ab2179c9cae5c512b50368eec018c728a4390e85` |
| SHA-256 | `1b723594e574c00aac2c946ff738a0454f7c24f6ebc84ae45a6af9628b08cb96` |
| SHA3-384 | `4523c69183e6967af795e5a6a90cf13753befb3249d8379a091035474fb92e612a447e4cdf8bb54e95f8e5a3cd26980a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T141963907EDA549E8C1A9D23486629113BB71BC485B3123D72FA0F7782F76BD06EB9350` |
| SSDEEP | `98304:CSKK+N1oCdOthPIn6+qOkd+rykA4dI/EH:CVx1ouOthwuV+rykAWH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_1b723594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b723594e574c00aac2c946ff738a0454f7c24f6ebc84ae45a6af9628b08cb96"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 23:57:10"
  condition:
    hash.sha256(0, filesize) == "1b723594e574c00aac2c946ff738a0454f7c24f6ebc84ae45a6af9628b08cb96"
}
```

### Sample 40: `a0df2239d79f25e1`

| Field | Value |
|---|---|
| SHA-256 | `a0df2239d79f25e184bc5f6eefa7130bd01d8a5dc59b7ffbfb84c7b676c2a2e1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 23:35:30` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91fdcaabfc774a9026bdc39bd3d2f69d` |
| SHA-1 | `411959d76bd7b01504a95517f98bb76b06275cf4` |
| SHA-256 | `a0df2239d79f25e184bc5f6eefa7130bd01d8a5dc59b7ffbfb84c7b676c2a2e1` |
| SHA3-384 | `74bb5d68231022421634fe0e9d875bcd140e59e3c20fc63a27a6554a4c77d41f154f66c042e7fe7c5cf4d63b34619ec9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T146964947EC6549E8C1A9D23486329162BB71BC485B3123D72BA0F7782F77BD06EB9350` |
| SSDEEP | `98304:rvNBqOiYI72kEdNMyCuiozJ7d+ryklsdoEn:r1BSYI73EdN/BdJ+ryklkn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_a0df2239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0df2239d79f25e184bc5f6eefa7130bd01d8a5dc59b7ffbfb84c7b676c2a2e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 23:35:30"
  condition:
    hash.sha256(0, filesize) == "a0df2239d79f25e184bc5f6eefa7130bd01d8a5dc59b7ffbfb84c7b676c2a2e1"
}
```

### Sample 41: `2f4348bb0f04eb8b`

| Field | Value |
|---|---|
| SHA-256 | `2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0` |
| Family label | `unknown` |
| File name | `2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0.exe` |
| File type | `exe` |
| First seen | `2026-09-01 23:07:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97f1abb216dd1d9e2b2b4b7c673965af` |
| SHA-1 | `bbea5b3f29625347e44b164cdb399ec3df6504cb` |
| SHA-256 | `2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0` |
| SHA3-384 | `fbc8f052855308d1f157f2535b466ee8afe536fe8d4b67ce0c9856abafafbb77c1172c45ab59dd054e2152254d533881` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T12ED52398FCA759B5E473C3FB8283607EB0697B844A618D5B36CC1B412E46A147C7A339` |
| SSDEEP | `49152:7UeZNer6Otn6H5NcZvHF8i9xScrzO4IKvJucvcsnucwi1qfiJfiPe8P7hrxERs0:Bb3Ota5NcFFj9x7rAgN3qKfclS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_2f4348bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0"
    family = "unknown"
    file_name = "2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0.exe"
    file_type = "exe"
    first_seen = "2026-09-01 23:07:36"
  condition:
    hash.sha256(0, filesize) == "2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0"
}
```

### Sample 42: `3d10f5aa66dbf90a`

| Field | Value |
|---|---|
| SHA-256 | `3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac` |
| Family label | `Vidar` |
| File name | `3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac.bin` |
| File type | `exe` |
| First seen | `2026-09-01 22:58:55` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef77cbff6f7e2157c38d27fea5b927ac` |
| SHA-1 | `5b84234672c3f2219f8c6c1124cc9e7240eb3b55` |
| SHA-256 | `3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac` |
| SHA3-384 | `0b7680020467678de2771d71bc3818cab9dba73fb0c0c98a557d6101be94e29d87c51339dbcc658e7c1e7d32752e2ae0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T191C66B03A96502E5C9AAD778C5F74242777878488B3233E36E10BAB42F757D0BEB6714` |
| SSDEEP | `49152:wJW7mTvJ+qY1qPQQEXG58VyysDQz9IP+FD2hg5RhFCaoHOkUhFe07IHbNMURptXk:wjgqod4cyy33+1HarU7WwVaHN0jfBA` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_042_3d10f5aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac"
    family = "Vidar"
    file_name = "3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:58:55"
  condition:
    hash.sha256(0, filesize) == "3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac"
}
```

### Sample 43: `57f406023f5ac9e5`

| Field | Value |
|---|---|
| SHA-256 | `57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11` |
| Family label | `unknown` |
| File name | `57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11.bin` |
| File type | `exe` |
| First seen | `2026-09-01 22:58:51` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6553bac9717b08d09db81cf9d47361e8` |
| SHA-1 | `3c0c6f56c903c2714d10754b46d5a73a8947e146` |
| SHA-256 | `57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11` |
| SHA3-384 | `42f217896f23d7ff126dae49282951bc4951bbc8e3063067702796a6b248bea742a2c3629d5667a8366df8e23013071b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T119F59D0B7C9148EAD46EA33288765165BB35BC094B3623D72E90B6793F727D0EC36B50` |
| SSDEEP | `49152:Olko47u4Ns0oaTaIYWUmtUFqO8Vmzk2htuSABezCq7oj:OKjI1QOimIKcjezVI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_57f40602
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11"
    family = "unknown"
    file_name = "57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:58:51"
  condition:
    hash.sha256(0, filesize) == "57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11"
}
```

### Sample 44: `921ae4b0d4344348`

| Field | Value |
|---|---|
| SHA-256 | `921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6` |
| Family label | `unknown` |
| File name | `921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6.bin` |
| File type | `exe` |
| First seen | `2026-09-01 22:43:50` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbfdc0774c54d016bf35923d3c5603ae` |
| SHA-1 | `8026788ad7f9ea95083c3e8610b173bf6559f87f` |
| SHA-256 | `921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6` |
| SHA3-384 | `0f3847c8b4306b1d88f25b4f77c858de8aebcf00c28afcd004f17bb1177e62a7683019960b325a4b547fcbd8772e28a1` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T125369C03BEA588F0C0DAE235C57262817778BC5D473237EB2E20AA393E367D15A75761` |
| SSDEEP | `49152:TtJfRMNuG8tTB/s7oaKgG/sdEjGzllIDXeNv8TuqBvjPZ6GAoQF6NJ66z:TZY7saJZqBvixk66z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_921ae4b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6"
    family = "unknown"
    file_name = "921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:43:50"
  condition:
    hash.sha256(0, filesize) == "921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6"
}
```

### Sample 45: `f43019ee4884c1c2`

| Field | Value |
|---|---|
| SHA-256 | `f43019ee4884c1c23ff804808fdb30691b151eb4a7ae6521d6757fde03a32833` |
| Family label | `AgentTesla` |
| File name | `Lista de productos.exe` |
| File type | `exe` |
| First seen | `2026-09-01 22:42:21` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `148e99089ecbe9cffadddd4f8f0114b2` |
| SHA-1 | `70cacfdb8e224c1f19eb529de04ca2ef4c0aa24e` |
| SHA-256 | `f43019ee4884c1c23ff804808fdb30691b151eb4a7ae6521d6757fde03a32833` |
| SHA3-384 | `7a721746d8d4d2ff04427b87db63cc50910595d8d559403150d81de48b185696a008b690a37da1062c5bbb2f594f65aa` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FFF47D6536608664CBB94B3A59638104673C5086ABFFC7023AF71DBCACC3BD649493B7` |
| SSDEEP | `6144:yxR3GVtv6Ktq1ilHK3rsjv5+MZm4zWXDB2/8k2FU9fX+XgkKqOWQkXBx6/mKPrUT:cRheROAb3Em5ll/UTG5ygAoG` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_045_f43019ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43019ee4884c1c23ff804808fdb30691b151eb4a7ae6521d6757fde03a32833"
    family = "AgentTesla"
    file_name = "Lista de productos.exe"
    file_type = "exe"
    first_seen = "2026-09-01 22:42:21"
  condition:
    hash.sha256(0, filesize) == "f43019ee4884c1c23ff804808fdb30691b151eb4a7ae6521d6757fde03a32833"
}
```

### Sample 46: `9f55da59b17b2279`

| Field | Value |
|---|---|
| SHA-256 | `9f55da59b17b2279c84367b88a25db30de0727ccfccc11535057fb9bcc89d194` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-01 22:41:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59f06b656afad5b8ac0a2f8321dbf839` |
| SHA-1 | `187940c8b3e73180a2227a96ed9bcd47e0b083ff` |
| SHA-256 | `9f55da59b17b2279c84367b88a25db30de0727ccfccc11535057fb9bcc89d194` |
| SHA3-384 | `ad77cdb66597aff5eae6727aaa392a49c6062e42facc2b46d51e801bb100587076e84659e1e524d9bd68df5ec6e3cac7` |
| TLSH | `T18F141D6AAB615FB7EC1ECE3702DA0512114C965D12EA1F6FB674C828E38BD4F48E3D44` |
| TELFHASH | `t169310e31463156116fa1c9589cee53a7292e82266644ef73ee35c5cc54090ebf637c0f` |
| SSDEEP | `3072:ilhxUM6B7IzVH0+FWF5vKIlgdW9sm+E4jS0Nd+r8J:iDxT6KzVHVI5vKIVsmB4jS0Nd+r8J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_9f55da59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f55da59b17b2279c84367b88a25db30de0727ccfccc11535057fb9bcc89d194"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-01 22:41:08"
  condition:
    hash.sha256(0, filesize) == "9f55da59b17b2279c84367b88a25db30de0727ccfccc11535057fb9bcc89d194"
}
```

### Sample 47: `1741f284682816da`

| Field | Value |
|---|---|
| SHA-256 | `1741f284682816da4d8cdd1fd6bbff3262c44266ce5a35224dcc0f97991ee897` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-01 22:28:47` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7879c02ad94e2bd2c8fafaad47062a` |
| SHA-256 | `1741f284682816da4d8cdd1fd6bbff3262c44266ce5a35224dcc0f97991ee897` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_1741f284
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1741f284682816da4d8cdd1fd6bbff3262c44266ce5a35224dcc0f97991ee897"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 22:28:47"
  condition:
    hash.sha256(0, filesize) == "1741f284682816da4d8cdd1fd6bbff3262c44266ce5a35224dcc0f97991ee897"
}
```

### Sample 48: `65be921e09dc27a0`

| Field | Value |
|---|---|
| SHA-256 | `65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0` |
| Family label | `Vidar` |
| File name | `65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0.bin` |
| File type | `exe` |
| First seen | `2026-09-01 22:24:39` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07ec1d0d4f4b2029430ba43303cfde85` |
| SHA-1 | `b9d338eeaaef4ad7ba2ca7d759ec97928d5de04a` |
| SHA-256 | `65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0` |
| SHA3-384 | `c6e0167ca4a1d797281caa5f9a56f7efa8fe2d44309c3ed1009af94e978551f416bbc7a00dca5932763f520b7be95f18` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F1967C037B519594C196EE38C0A64A55A138BC8DC73537EB3EA1AEB47F217C29237F84` |
| SSDEEP | `49152:T6S0jKAk+VrVagSd1wixUmvnwT+io2c3VcHmyWGP2A2g/McHZoRvJwUc0:T0dxqxbP8c3VctP27cHuRvGi` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_048_65be921e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0"
    family = "Vidar"
    file_name = "65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:24:39"
  condition:
    hash.sha256(0, filesize) == "65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0"
}
```

### Sample 49: `10d4a7e6b370aba9`

| Field | Value |
|---|---|
| SHA-256 | `10d4a7e6b370aba96dab9da75d56b3fd3e53938423cd7f302790b59fc42b3f97` |
| Family label | `unknown` |
| File name | `ruck` |
| File type | `sh` |
| First seen | `2026-09-01 22:20:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f692344f03c5fec20f49424c8a6de1df` |
| SHA-1 | `9791e5c2e1002827505243c7ea0f465b5e46925b` |
| SHA-256 | `10d4a7e6b370aba96dab9da75d56b3fd3e53938423cd7f302790b59fc42b3f97` |
| SHA3-384 | `21a49eac4d0e03b288f1e347a041ba40131275ad2d5b115697af77f58225bdb0a97ae605de2c72a4addb9bfe927ba694` |
| TLSH | `T1415191C417620A763C539DC337AF8C443188AAFE28C29E25A9EC74E4054EDCAF1C4B53` |
| SSDEEP | `48:pKQvt8tXHtYt2t6tDtltat1totPatbH/tPtr:pJt8tXHtYt2t6tDtltat1totPatbftP5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_10d4a7e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10d4a7e6b370aba96dab9da75d56b3fd3e53938423cd7f302790b59fc42b3f97"
    family = "unknown"
    file_name = "ruck"
    file_type = "sh"
    first_seen = "2026-09-01 22:20:36"
  condition:
    hash.sha256(0, filesize) == "10d4a7e6b370aba96dab9da75d56b3fd3e53938423cd7f302790b59fc42b3f97"
}
```

### Sample 50: `85ef43be0fd87c2d`

| Field | Value |
|---|---|
| SHA-256 | `85ef43be0fd87c2d98a1e71f055e376a3b6702b6a5279f84aacda4bc57e9b41a` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-01 22:13:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95b33675dc05887240503061919cf7b8` |
| SHA-1 | `c28e0d914496d3020f45cb768a11961b98e8fe38` |
| SHA-256 | `85ef43be0fd87c2d98a1e71f055e376a3b6702b6a5279f84aacda4bc57e9b41a` |
| SHA3-384 | `ff6d64ffc508100d056ebbfbd2dfbcb648022c1f51c2a594b471a02cbd7e494ca0ab7854b89e777521b2cf9e0cb8b8ba` |
| TLSH | `T1BD043A46AA818A17C1D31779FA9F42463333A764D3DB73069928AFF43F8679E0E63501` |
| TELFHASH | `t19131ef3147316515aeb1da54ace953b3152e86266284eb73de35c4cc940a0ebe637c4f` |
| SSDEEP | `3072:EWfxWR3bV4DWJx2lVgMpkRvYTzaIiULTEHGr0Hx1SmWU2zURygWo/g0M/9VFp:EjV4DWP2lVgMpyczaIiULTt0HKmx2oRQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_85ef43be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ef43be0fd87c2d98a1e71f055e376a3b6702b6a5279f84aacda4bc57e9b41a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-01 22:13:26"
  condition:
    hash.sha256(0, filesize) == "85ef43be0fd87c2d98a1e71f055e376a3b6702b6a5279f84aacda4bc57e9b41a"
}
```

### Sample 51: `15ad30836554afa7`

| Field | Value |
|---|---|
| SHA-256 | `15ad30836554afa7786618ce3e07957031b2f73473b4e871e6b579a63e5ff386` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-01 22:13:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ff11fad90576c8db08e151b2a3ce5f3` |
| SHA-1 | `c1e48dae948257e357b4df9653f3379c54020f4c` |
| SHA-256 | `15ad30836554afa7786618ce3e07957031b2f73473b4e871e6b579a63e5ff386` |
| SHA3-384 | `9f1d48de229cbd360a5dd1ce795d282e0e96305121c3e9b3845989a38ac528ec8db28962b3b0fd5cdcab3485420b9fac` |
| TLSH | `T1D9236D661A857C14AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10971D` |
| SSDEEP | `768:mXRWNGxVH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ClxCcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_15ad3083
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ad30836554afa7786618ce3e07957031b2f73473b4e871e6b579a63e5ff386"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 22:13:24"
  condition:
    hash.sha256(0, filesize) == "15ad30836554afa7786618ce3e07957031b2f73473b4e871e6b579a63e5ff386"
}
```

### Sample 52: `4125fe7e5b34d5a2`

| Field | Value |
|---|---|
| SHA-256 | `4125fe7e5b34d5a2d5db97a5b00d0c73dc1cfc1c13a73cd986616828f5051b95` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-01 22:13:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67eabf7dcdad1030585393bedb06e2c7` |
| SHA-1 | `d73234e3526961b63ea2da0043601d0b3055df68` |
| SHA-256 | `4125fe7e5b34d5a2d5db97a5b00d0c73dc1cfc1c13a73cd986616828f5051b95` |
| SHA3-384 | `e66e952e1a839026eb6df5d4c2f87839fca62a6ceb17ef012baf1f6095b7f8196aee8c84b772afd1f40ab1b2e1114307` |
| TLSH | `T19A143039BE217F7EE3A882310BF62FB4C35611C626929781E2BDC6545EB428C4C9F754` |
| TELFHASH | `t169310e31463156116fa1c9589cee53a7292e82266644ef73ee35c5cc54090ebf637c0f` |
| SSDEEP | `3072:4RPi4G+IFcTr0gv15U+RF9LzYwkkC6e2N/2WEDiat9zsVfjgo0Nd+r8J:4RKNduaTzsVrgo0Nd+r8J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_4125fe7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4125fe7e5b34d5a2d5db97a5b00d0c73dc1cfc1c13a73cd986616828f5051b95"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 22:13:23"
  condition:
    hash.sha256(0, filesize) == "4125fe7e5b34d5a2d5db97a5b00d0c73dc1cfc1c13a73cd986616828f5051b95"
}
```

### Sample 53: `4c1df8578967cb24`

| Field | Value |
|---|---|
| SHA-256 | `4c1df8578967cb249ebb3ab7998f8cb754638002e22d2bcb95bb80f7b090c437` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-09-01 22:10:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7d8cc6ae11792d6071d89abbc49c3f2` |
| SHA-1 | `e42f63f66f7424cb5a09734ee5288d61e1d62428` |
| SHA-256 | `4c1df8578967cb249ebb3ab7998f8cb754638002e22d2bcb95bb80f7b090c437` |
| SHA3-384 | `53fe5e80d9d345cee965e359aecd360e569303c7f74053d6de181568551e5d01577f943b87113d356bf1200bef432e58` |
| TLSH | `T126F3C448ED24973BC2E273FAE78903CD373A0A58A7D773219D352A752BC9B546D39120` |
| TELFHASH | `t169310e31463156116fa1c9589cee53a7292e82266644ef73ee35c5cc54090ebf637c0f` |
| SSDEEP | `3072:xNqQ0JLylfJrrpL8qrbekkFQoNvXaHiyLKr30GWZKHJ:xNJ2LyTr99benQoNvaCr30GWZKHJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_4c1df857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c1df8578967cb249ebb3ab7998f8cb754638002e22d2bcb95bb80f7b090c437"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-01 22:10:45"
  condition:
    hash.sha256(0, filesize) == "4c1df8578967cb249ebb3ab7998f8cb754638002e22d2bcb95bb80f7b090c437"
}
```

### Sample 54: `503dca2a79244bb2`

| Field | Value |
|---|---|
| SHA-256 | `503dca2a79244bb2ad2dbeae2bdab48613fe6d16d4b4d8b16646c816c82c65cb` |
| Family label | `unknown` |
| File name | `ruckus.sh` |
| File type | `sh` |
| First seen | `2026-09-01 22:10:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3876857962bd54c1d1937a7600c817aa` |
| SHA-1 | `3c424d54c5cdb531d7bc92508d168846a90052a0` |
| SHA-256 | `503dca2a79244bb2ad2dbeae2bdab48613fe6d16d4b4d8b16646c816c82c65cb` |
| SHA3-384 | `3fbb66fb72263de71701c8872b127961555da5785468f036d7a05f0cb9230498cdb305622ceb670d9073339d3050d638` |
| TLSH | `T1B5518FC817A20A763C53ADC337AF8C447088AEEE28C29E15E9EC74E4054EDCAB0C4753` |
| SSDEEP | `24:pKQTxtiXX3NZwdOVBMJr817ODX7QbHl1Xn:pKQVyXd+swJrQ7OPQbHl1X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_503dca2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "503dca2a79244bb2ad2dbeae2bdab48613fe6d16d4b4d8b16646c816c82c65cb"
    family = "unknown"
    file_name = "ruckus.sh"
    file_type = "sh"
    first_seen = "2026-09-01 22:10:40"
  condition:
    hash.sha256(0, filesize) == "503dca2a79244bb2ad2dbeae2bdab48613fe6d16d4b4d8b16646c816c82c65cb"
}
```

### Sample 55: `4aa60d3b9b7cc7c4`

| Field | Value |
|---|---|
| SHA-256 | `4aa60d3b9b7cc7c494a3e4daaab89735d1ef2fed27eff9838ad5780d585a2919` |
| Family label | `unknown` |
| File name | `sdt` |
| File type | `sh` |
| First seen | `2026-09-01 22:07:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db9135d30e3b40b01a8e5ccc9f18c254` |
| SHA-1 | `d44e14f213c187dd5d46c18ed7238e6b025e6828` |
| SHA-256 | `4aa60d3b9b7cc7c494a3e4daaab89735d1ef2fed27eff9838ad5780d585a2919` |
| SHA3-384 | `15dc406a92dd72899b417856834a393b2e2b1cd7deb3ce56cb40cc925fd76f3fbe3431dc9d6cec829b24c09e36878863` |
| TLSH | `T1BE519FC413624EB53C63ADD377AF8C443188AAEE28C29E15AAEC34E4454ECCEF084753` |
| SSDEEP | `24:pKQTA8tii8X3M8ZR8dr8VBd8Y8G8808W8r8DX7x8bHk808XNn:pKQJ0XxYWilXCHIPCbH5pd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_4aa60d3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aa60d3b9b7cc7c494a3e4daaab89735d1ef2fed27eff9838ad5780d585a2919"
    family = "unknown"
    file_name = "sdt"
    file_type = "sh"
    first_seen = "2026-09-01 22:07:03"
  condition:
    hash.sha256(0, filesize) == "4aa60d3b9b7cc7c494a3e4daaab89735d1ef2fed27eff9838ad5780d585a2919"
}
```

### Sample 56: `314a49ed66522f20`

| Field | Value |
|---|---|
| SHA-256 | `314a49ed66522f202101b625c9cc85b6ef3cc6af528e49ea06da2701aa7af8a4` |
| Family label | `unknown` |
| File name | `av.sh` |
| File type | `sh` |
| First seen | `2026-09-01 21:54:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a598a498189e616fe1237f8eb2345a1` |
| SHA-1 | `2ec8f48b9f4ae8bae64224110cc29a668287b7df` |
| SHA-256 | `314a49ed66522f202101b625c9cc85b6ef3cc6af528e49ea06da2701aa7af8a4` |
| SHA3-384 | `d472efe83fe6712fd6f0f18dd9c26ff892b87fe03b99405ea128ac0232be46ca8dd6a7d06bd2ef4e20a4f0b67aa46749` |
| TLSH | `T1D05170C517620EB63C53ADC337AF8C443588ABEE28C29E55A9ED34E4454ECCEB484B53` |
| SSDEEP | `24:pKQTxtijX3VZEdWVBY5P8N/WDX7kbHdNXL:pKQtSXFm4E5Pk/WPkbHdNb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_314a49ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "314a49ed66522f202101b625c9cc85b6ef3cc6af528e49ea06da2701aa7af8a4"
    family = "unknown"
    file_name = "av.sh"
    file_type = "sh"
    first_seen = "2026-09-01 21:54:50"
  condition:
    hash.sha256(0, filesize) == "314a49ed66522f202101b625c9cc85b6ef3cc6af528e49ea06da2701aa7af8a4"
}
```

### Sample 57: `a52f1911e4a5f078`

| Field | Value |
|---|---|
| SHA-256 | `a52f1911e4a5f078d789fab74a0b727d05a8ac4fb670a33c9d8bcf387bf5b33c` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-01 21:54:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `386307fb503ad57bc5440055e0a86428` |
| SHA-1 | `a6f3554cfbd0dd7a172041d74f02341f5b6b36c5` |
| SHA-256 | `a52f1911e4a5f078d789fab74a0b727d05a8ac4fb670a33c9d8bcf387bf5b33c` |
| SHA3-384 | `e690e761bceb47b98c19f4e8ee61e5b0046a3508274675e9b2c6e44e13b679b989063a9a7194f9713ab8cf41815f37a7` |
| TLSH | `T16DE31893FC01EEBAF40BD63A49C70A297734EB564B43162673177967A9361C12C23F46` |
| TELFHASH | `t169310e31463156116fa1c9589cee53a7292e82266644ef73ee35c5cc54090ebf637c0f` |
| SSDEEP | `3072:3XLxT01DMJtpLUX+Flo78j6l3BaVm/unN8ufPE2wKflGJ:nmMJtlUuq46lRatnN8ufPE2wKflGJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_a52f1911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a52f1911e4a5f078d789fab74a0b727d05a8ac4fb670a33c9d8bcf387bf5b33c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-01 21:54:48"
  condition:
    hash.sha256(0, filesize) == "a52f1911e4a5f078d789fab74a0b727d05a8ac4fb670a33c9d8bcf387bf5b33c"
}
```

### Sample 58: `8b8e663ee2b2d946`

| Field | Value |
|---|---|
| SHA-256 | `8b8e663ee2b2d946f75fcc5622763afe5a020e994f3b935ec7c0b0f83bcbcf0d` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-01 21:52:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28c3469fc943ccd97e902da068fef753` |
| SHA-1 | `f7f32aa465868331e01a79406a58e75d33da65e1` |
| SHA-256 | `8b8e663ee2b2d946f75fcc5622763afe5a020e994f3b935ec7c0b0f83bcbcf0d` |
| SHA3-384 | `14c94d175cc3e8d35be8298b04927a03c793e8efcb2d1a7cfec8d1cfe8f4754c9abc54a8d15bd42bfca3e834773653b2` |
| TLSH | `T1F3E3294AA4A26FFBD095B9756DBB5E34070DF8501B4F1AC6743CAAB0078F5CAB00F664` |
| TELFHASH | `t134310e31463156116fa1c9589cee53a7292e82266244ef73ee35c5cc54090ebf637c0f` |
| SSDEEP | `3072:Xma9Ow8mPTi4kUo3rJ+iRMxGK9ALIG/AvykQX7ePiF/XyXt8dcul2mcPUjlNJ:XmTP3AiyMIG/AvyXV9+t8dc8bcPUjlNJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_8b8e663e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b8e663ee2b2d946f75fcc5622763afe5a020e994f3b935ec7c0b0f83bcbcf0d"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-01 21:52:33"
  condition:
    hash.sha256(0, filesize) == "8b8e663ee2b2d946f75fcc5622763afe5a020e994f3b935ec7c0b0f83bcbcf0d"
}
```

### Sample 59: `2b208d76e495001a`

| Field | Value |
|---|---|
| SHA-256 | `2b208d76e495001a3c3f687a49b7692f7f2ba2bf62d0798665b13d1d3c79214f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-01 21:50:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `852d5fd1451087eaf3058fcfbfe13de0` |
| SHA-1 | `d282d7e56c275388aab2f504a7bf406c3d5f2d28` |
| SHA-256 | `2b208d76e495001a3c3f687a49b7692f7f2ba2bf62d0798665b13d1d3c79214f` |
| SHA3-384 | `9f02c1e4a17858486bd910cdb22e4b566083c5a41ae08a787c74fbec724f1488624c11270dddea4332e401917175353a` |
| TLSH | `T1C1235C661A857C14AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10971D` |
| SSDEEP | `768:2XRWNGxV79GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ylxqcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_2b208d76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b208d76e495001a3c3f687a49b7692f7f2ba2bf62d0798665b13d1d3c79214f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 21:50:10"
  condition:
    hash.sha256(0, filesize) == "2b208d76e495001a3c3f687a49b7692f7f2ba2bf62d0798665b13d1d3c79214f"
}
```

### Sample 60: `51e0e80af7100b9a`

| Field | Value |
|---|---|
| SHA-256 | `51e0e80af7100b9a2b296aa3e171e247a65276b9d19228c837c3c20e3ccadb27` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-01 21:50:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4145dbc06262668e05e1392717a623d` |
| SHA-1 | `447930c82da28a61f2ae4430a48a6247db532aaf` |
| SHA-256 | `51e0e80af7100b9a2b296aa3e171e247a65276b9d19228c837c3c20e3ccadb27` |
| SHA3-384 | `65412ff5aa4843e95a895cd26f19118d4de1f5b389d7da2e6fc145013de31cf667d5299976fc5518c5444533a2e1b6b9` |
| TLSH | `T1AE04D83F2B231F63C0DA257141D76232ACBAD70834AC4BD7ACD06C6D2F1A99835566ED` |
| TELFHASH | `t1c2312030463155116fa1ca589cee57a7292e82222644ef73ee35c5cc54090ebf63bc0f` |
| SSDEEP | `3072:akC6LYhQw6gVK2mNlEml/qeGgKN5+8KGl8J:akCNhQw6gV2PEk/qe4N5+8KGl8J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_51e0e80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51e0e80af7100b9a2b296aa3e171e247a65276b9d19228c837c3c20e3ccadb27"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-01 21:50:09"
  condition:
    hash.sha256(0, filesize) == "51e0e80af7100b9a2b296aa3e171e247a65276b9d19228c837c3c20e3ccadb27"
}
```

### Sample 61: `4e06f71b325f9f47`

| Field | Value |
|---|---|
| SHA-256 | `4e06f71b325f9f47397f3319fa9e6d8156062eccfd3c2f40d265864d93e23822` |
| Family label | `unknown` |
| File name | `li` |
| File type | `sh` |
| First seen | `2026-09-01 21:50:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f46b57629b132da22be3d848b80c2a51` |
| SHA-1 | `067e0a6c6b1ebd10435f8ce16e7d1513c97cf0bd` |
| SHA-256 | `4e06f71b325f9f47397f3319fa9e6d8156062eccfd3c2f40d265864d93e23822` |
| SHA3-384 | `3852b7a85460a4ff355082e7300bdbcd21c07da04bb1cf4f795f5a4c17f6fd982f658b68374e3f67347cb258b9c8c414` |
| TLSH | `T13A515ED517620AB53C53ADC337AF8C447588AAFF28C29E59A9ED34E4494ECCAB084753` |
| SSDEEP | `24:pKQTZtiXX3dZod+VBsBT81j+DX7IbHl1XH:pKQVaXtuMoBTIj+PIbHl13` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_4e06f71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e06f71b325f9f47397f3319fa9e6d8156062eccfd3c2f40d265864d93e23822"
    family = "unknown"
    file_name = "li"
    file_type = "sh"
    first_seen = "2026-09-01 21:50:07"
  condition:
    hash.sha256(0, filesize) == "4e06f71b325f9f47397f3319fa9e6d8156062eccfd3c2f40d265864d93e23822"
}
```

### Sample 62: `d1ebe6c654f0fc5e`

| Field | Value |
|---|---|
| SHA-256 | `d1ebe6c654f0fc5e3b42ec77b4cf2d87dd74b5b63c1ffc1d5e5a6d2cb0359fb9` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-01 21:50:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dccf71c46e0de992276c7bcd0fe16b3` |
| SHA-1 | `dea7237752b523d25c77ea808677381cb068ff66` |
| SHA-256 | `d1ebe6c654f0fc5e3b42ec77b4cf2d87dd74b5b63c1ffc1d5e5a6d2cb0359fb9` |
| SHA3-384 | `6e252f248dc9766f1e1776ddfaa70dc7e3824bf691d5dcf0a3fdcb327e34f5b2ef6d79e142d661f68a1ccd0c2a5e9a3b` |
| TLSH | `T13B04F808D965673FC7E263FEEB4A428D33370B58A7D7332199342A752BC67986D39120` |
| TELFHASH | `t1f1310031463555156ea1c9549ce953a7252e86262284eb73ef35c5cc94090ebe637c0f` |
| SSDEEP | `3072:wp77dSw7XJJDTqd8R+HafNvFWN0V38HCo1BWl+kHQKZM:i77dp7z9R0a1vi0VgCo1BWrM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_d1ebe6c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ebe6c654f0fc5e3b42ec77b4cf2d87dd74b5b63c1ffc1d5e5a6d2cb0359fb9"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-01 21:50:06"
  condition:
    hash.sha256(0, filesize) == "d1ebe6c654f0fc5e3b42ec77b4cf2d87dd74b5b63c1ffc1d5e5a6d2cb0359fb9"
}
```

### Sample 63: `fb72ce24396d58ca`

| Field | Value |
|---|---|
| SHA-256 | `fb72ce24396d58ca38a10fa06e1e995223ab204a58446a4caacb3ca8f8a106c3` |
| Family label | `unknown` |
| File name | `lll` |
| File type | `sh` |
| First seen | `2026-09-01 21:30:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e4445508f60172afed97abca6b22b38` |
| SHA-1 | `5f1521a9f2bb75cb0f0e69c91a9ae514b4ca6500` |
| SHA-256 | `fb72ce24396d58ca38a10fa06e1e995223ab204a58446a4caacb3ca8f8a106c3` |
| SHA3-384 | `afe568d691066825768641f89d2333d2cb5d161584ab07347a9d187ae476485ed4801c87bb49b577e83cd1558216971c` |
| TLSH | `T1BC515DC517620AB53C53ADC377AF8C447488AAFE68C29E59B9ED34E4494ECCAF084753` |
| SSDEEP | `24:pKQTKti8X3WZVdvVBRSQ8uAvDX71bH+uXs:pKQOzXG/xVSQ1AvP1bH+u8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_fb72ce24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb72ce24396d58ca38a10fa06e1e995223ab204a58446a4caacb3ca8f8a106c3"
    family = "unknown"
    file_name = "lll"
    file_type = "sh"
    first_seen = "2026-09-01 21:30:47"
  condition:
    hash.sha256(0, filesize) == "fb72ce24396d58ca38a10fa06e1e995223ab204a58446a4caacb3ca8f8a106c3"
}
```

### Sample 64: `9d78d3425f030dc2`

| Field | Value |
|---|---|
| SHA-256 | `9d78d3425f030dc288aa4836fcd8506008365233ce3345d3724bf598bede6228` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-01 21:26:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94d965bff0f1ae361f128206885b3b2a` |
| SHA-1 | `4bea1beed74037ab241d8c3f66afc503fb7b8e83` |
| SHA-256 | `9d78d3425f030dc288aa4836fcd8506008365233ce3345d3724bf598bede6228` |
| SHA3-384 | `ed00f23a8a68d850a3208e3f2b6254c1c229deaf487586252dc03083c399159ae37c99a01a026249fc792d4c4fa5276e` |
| TLSH | `T1EBC27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3CB19C11F9CD618B1A` |
| SSDEEP | `768:RG8vCB+25j6es8Rh09FYpMSUpi+20qUpi+20YQX:RG8l25JhSd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_9d78d342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d78d3425f030dc288aa4836fcd8506008365233ce3345d3724bf598bede6228"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 21:26:52"
  condition:
    hash.sha256(0, filesize) == "9d78d3425f030dc288aa4836fcd8506008365233ce3345d3724bf598bede6228"
}
```

### Sample 65: `567564ca8951af7b`

| Field | Value |
|---|---|
| SHA-256 | `567564ca8951af7b4d8d3f16d6dfef87b30fab048482dbfa5e878897e90e6814` |
| Family label | `unknown` |
| File name | `gocl` |
| File type | `sh` |
| First seen | `2026-09-01 21:24:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c59da6b48ce08ebef39f8ef6db23d57a` |
| SHA-1 | `0b31d858683f926dccf13c5083058d2c664a5c6a` |
| SHA-256 | `567564ca8951af7b4d8d3f16d6dfef87b30fab048482dbfa5e878897e90e6814` |
| SHA3-384 | `d147968f44431f347f5b7749139170be2efe26d37e8f1ba87680ce76c99b225968ebfd278c2260e93769d284abf54774` |
| TLSH | `T1B3518ED523420F713DA39CE723BA9C0835889EEF54C66E1AA5F938E4854ED81F180753` |
| SSDEEP | `24:vguLFifLC/ctLXxoLYL5HSL5FNLsWL4LXHLuLZ2LS8FLlL5fdV:vgggC/EMa65bsI6bgZoS8JpFj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_567564ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "567564ca8951af7b4d8d3f16d6dfef87b30fab048482dbfa5e878897e90e6814"
    family = "unknown"
    file_name = "gocl"
    file_type = "sh"
    first_seen = "2026-09-01 21:24:43"
  condition:
    hash.sha256(0, filesize) == "567564ca8951af7b4d8d3f16d6dfef87b30fab048482dbfa5e878897e90e6814"
}
```

### Sample 66: `6938ce6a856e17db`

| Field | Value |
|---|---|
| SHA-256 | `6938ce6a856e17dbc4026262136bfb6f6d226055d295c13f1681597993274df2` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-01 21:23:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47ea4ca573ae718a18b9d3cf5d540fda` |
| SHA-1 | `41f2db613546b758259cc550e406c026e88aa22e` |
| SHA-256 | `6938ce6a856e17dbc4026262136bfb6f6d226055d295c13f1681597993274df2` |
| SHA3-384 | `fa2a71e451b1a6d2b06884b4efb1b15d5930df728e10a0b1eaa1a96fb4ce001a2f8cc369421521a2a620edfb58a4ad4a` |
| TLSH | `T11DA42A8C97F19BDFE06DDD3063296A171CBE493770E377A6A17DE86232AB14405E7820` |
| SSDEEP | `6144:SFPWLROGFs9R++I3eLxTaN6+gDyyOdI7/4CPyLFDr2Lao9a9dG:hdOGFsa+Rx+N6hCQ0yLao9a9dG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_6938ce6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6938ce6a856e17dbc4026262136bfb6f6d226055d295c13f1681597993274df2"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-01 21:23:18"
  condition:
    hash.sha256(0, filesize) == "6938ce6a856e17dbc4026262136bfb6f6d226055d295c13f1681597993274df2"
}
```

### Sample 67: `ac7942ba8d1d88a1`

| Field | Value |
|---|---|
| SHA-256 | `ac7942ba8d1d88a14a6d70d975fce9c88b82c159dae4636101727584832360c7` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-01 21:22:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e5d50c9837262148cb6add193727ff9` |
| SHA-1 | `a19c085ba7f1c48c59dd24e6365c309337772d85` |
| SHA-256 | `ac7942ba8d1d88a14a6d70d975fce9c88b82c159dae4636101727584832360c7` |
| SHA3-384 | `2bf49570974c7b057ce3dff0877de1b7710632be1656598e535be5623364b14f9c65e33991e8740aea708452cc6562da` |
| TLSH | `T1B3E312CC49A49697CAF55230A8DC127FCB097951AA69C35DA3A8CFC4E711703B4EC2EC` |
| SSDEEP | `3072:aEv0oEdx4Mos3hkPBaKBVmCae3xrb9RCoxqvdttw5FLk4VlXBFtfx5BVrcemLH1a:a4MLipaKBYCaixrbPdYwC4zRF5bbka` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_ac7942ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac7942ba8d1d88a14a6d70d975fce9c88b82c159dae4636101727584832360c7"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-01 21:22:42"
  condition:
    hash.sha256(0, filesize) == "ac7942ba8d1d88a14a6d70d975fce9c88b82c159dae4636101727584832360c7"
}
```

### Sample 68: `40b643468356c0fd`

| Field | Value |
|---|---|
| SHA-256 | `40b643468356c0fd751893647ad0dc9e2a0019427e4f5f0e2f6e559efcecb977` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 21:20:16` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b135d924f409aeb7be55feacd68e946f` |
| SHA-1 | `a7b0d89d2f4f846e38ce3c4ea904d16113fda9ea` |
| SHA-256 | `40b643468356c0fd751893647ad0dc9e2a0019427e4f5f0e2f6e559efcecb977` |
| SHA3-384 | `a1a8c5d51137ae484407903a46029949ef5c4d912dd7d24d6038969ff4bcf3b5614a1ca86d7a67a6bbd5dd2737ca84f3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A1667C0B3E8081A5E49ED63995B75252AB34BC4C9F7633D72D50B2301F763E42BB9B48` |
| SSDEEP | `98304:JjxkpalhmhcBwROSWaUVJTOdTEo3qYScS4y:JtmalhccBwRNUnToQky` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_40b64346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b643468356c0fd751893647ad0dc9e2a0019427e4f5f0e2f6e559efcecb977"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 21:20:16"
  condition:
    hash.sha256(0, filesize) == "40b643468356c0fd751893647ad0dc9e2a0019427e4f5f0e2f6e559efcecb977"
}
```

### Sample 69: `2a5b41f30fdc6cf6`

| Field | Value |
|---|---|
| SHA-256 | `2a5b41f30fdc6cf62934d9f0cd9ce9ad77871699b0e0a23c4f1d4f70f90116d0` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-01 21:18:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `060416d6aa570bb8b5a04c0cd1b7277d` |
| SHA-1 | `c09810a1e0356fb202f6353cf90b93ab6896cf7c` |
| SHA-256 | `2a5b41f30fdc6cf62934d9f0cd9ce9ad77871699b0e0a23c4f1d4f70f90116d0` |
| SHA3-384 | `5e20ae9ceee5ae005a31ba546683e3dcdcbec66b267282a2b818335a0892fd77daf3f4916ae28154d60651db3385b56a` |
| TLSH | `T1D3313EDF02105E711503DA9E73A73548B18DA1EB289FC7D49C094EDD9A8978CF226B49` |
| SSDEEP | `12:USI6SwXFFd6rgwQSUU76U0B9jxz6tEwFr6Vt3aGaBr6aTgeGPteufpwSr6Lwx6b1:LCwXFWgZUz0B9KEjMZib7mxeaJmFBg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_2a5b41f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a5b41f30fdc6cf62934d9f0cd9ce9ad77871699b0e0a23c4f1d4f70f90116d0"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-01 21:18:41"
  condition:
    hash.sha256(0, filesize) == "2a5b41f30fdc6cf62934d9f0cd9ce9ad77871699b0e0a23c4f1d4f70f90116d0"
}
```

### Sample 70: `29e114749b1ac3f2`

| Field | Value |
|---|---|
| SHA-256 | `29e114749b1ac3f2dfed0ad6345834b718f6410695805b7be7cc30a93ac5ed78` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-01 21:16:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01e10e1a318eb09fbb3b5b4b64a25b0e` |
| SHA-1 | `bdf46e38c1216233c64cf7bc43f136121b00c8d2` |
| SHA-256 | `29e114749b1ac3f2dfed0ad6345834b718f6410695805b7be7cc30a93ac5ed78` |
| SHA3-384 | `9c3f1ad728d707726df77bad71e053ebed9c854d018e79df0fcac8ed76842ef2a4071b89775b84630d2051e83131313d` |
| TLSH | `T1E1F3C448ED14977BC3E277FAE78903CE373A4A58A7D733219E311A742BC97546D29220` |
| TELFHASH | `t169310e31463156116fa1c9589cee53a7292e82266644ef73ee35c5cc54090ebf637c0f` |
| SSDEEP | `3072:eNGe0JMXlfnMjpppqupcmZNg1oBLaagyCfHVfKBzJ:eN/2MXVMFtpc+g1oBLaPHVfKBzJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_29e11474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29e114749b1ac3f2dfed0ad6345834b718f6410695805b7be7cc30a93ac5ed78"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-01 21:16:44"
  condition:
    hash.sha256(0, filesize) == "29e114749b1ac3f2dfed0ad6345834b718f6410695805b7be7cc30a93ac5ed78"
}
```

### Sample 71: `57b1e438ea9864ef`

| Field | Value |
|---|---|
| SHA-256 | `57b1e438ea9864efa7ce4c5f310d039d618d52fa352dcd992d7f042591bf4b74` |
| Family label | `Mirai` |
| File name | `s390x` |
| File type | `elf` |
| First seen | `2026-09-01 21:16:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27aea885acbc4052488bb7c45184660d` |
| SHA-1 | `48d659b0c03fd53d94ae5743df283deca6305e16` |
| SHA-256 | `57b1e438ea9864efa7ce4c5f310d039d618d52fa352dcd992d7f042591bf4b74` |
| SHA3-384 | `dca881be8b9423b7c9cfdfd2f13ba99f1525f9b419321d11f2c89bbf23195aacc3ad13386b5f2d4d56d57dd0099bcf75` |
| TLSH | `T15284F8CC51B0E3CED064AD32D32579A79967123724837A8C61DEEB7B12F724606B9E31` |
| SSDEEP | `6144:bUQdl3QTOyBB2Q2Q17+3WchtsnoRd6558LwxFCO:b5nyBBCQ170hPD65M2IO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_57b1e438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57b1e438ea9864efa7ce4c5f310d039d618d52fa352dcd992d7f042591bf4b74"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-09-01 21:16:43"
  condition:
    hash.sha256(0, filesize) == "57b1e438ea9864efa7ce4c5f310d039d618d52fa352dcd992d7f042591bf4b74"
}
```

### Sample 72: `3081380240ce27ef`

| Field | Value |
|---|---|
| SHA-256 | `3081380240ce27efb753ce0fe2a25fe3cadce5d925f55d707c9853a9e6dc67be` |
| Family label | `Mirai` |
| File name | `5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4.elf` |
| File type | `elf` |
| First seen | `2026-09-01 21:13:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9205fd7f93c35693a4d6057ce8cc560` |
| SHA-1 | `074660a7afa085cd7ae0bd858ad05f3747a3455e` |
| SHA-256 | `3081380240ce27efb753ce0fe2a25fe3cadce5d925f55d707c9853a9e6dc67be` |
| SHA3-384 | `ce80032918217427e4aab2267b59b53cce4f9cfd20ac2f43bd46eaab61916ac370e091ac547cf0f0be10a3f9b382fd42` |
| TLSH | `T19274094892F2E2FDE198DA305316BC1BAD3275363077724E729EE97313B665046EDB20` |
| TELFHASH | `t1a461453018d67454b283c6017347d27ada3a1ce181ed76f85b53acf0eef5ac24da3826` |
| SSDEEP | `6144:t9xoKSR9FJKZj5JtwnZyEFkWRECt7Hqkf9O9Ua9AO:TxdtwZy4kwECJHz9O9Ua9AO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_30813802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3081380240ce27efb753ce0fe2a25fe3cadce5d925f55d707c9853a9e6dc67be"
    family = "Mirai"
    file_name = "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4.elf"
    file_type = "elf"
    first_seen = "2026-09-01 21:13:15"
  condition:
    hash.sha256(0, filesize) == "3081380240ce27efb753ce0fe2a25fe3cadce5d925f55d707c9853a9e6dc67be"
}
```

### Sample 73: `ead146ff50c9b98c`

| Field | Value |
|---|---|
| SHA-256 | `ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c` |
| Family label | `Mirai` |
| File name | `ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c.elf` |
| File type | `elf` |
| First seen | `2026-09-01 21:13:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cacf9494edf806afabcb0a4009e4519f` |
| SHA-1 | `d4030e43936413607f6fb3b0f2120ba143f05470` |
| SHA-256 | `ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c` |
| SHA3-384 | `592282743333611154a47a0c046aaa2fe4553a1014e87e582c311c54ceee4ce2bdd43ff17a6062259c8549c1dd084b16` |
| TLSH | `T18F742B88A2F5FBDEE259FD3983017C0B6C2987367483758560AEF96313B71850AF9D60` |
| SSDEEP | `6144:5nVPOpX7RQvjhGHH/6z5dvRbQilGiBDPVRpwAvDviKL:+pajE+5rHlH+qDvi0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_ead146ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c"
    family = "Mirai"
    file_name = "ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c.elf"
    file_type = "elf"
    first_seen = "2026-09-01 21:13:08"
  condition:
    hash.sha256(0, filesize) == "ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c"
}
```

### Sample 74: `5d9b849863383550`

| Field | Value |
|---|---|
| SHA-256 | `5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4` |
| Family label | `Mirai` |
| File name | `5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4.elf` |
| File type | `elf` |
| First seen | `2026-09-01 21:13:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffeb214a0d783c1be29b79d5c3b3ac3a` |
| SHA-1 | `df15b901a09c5efe844247300b7d7d45fe0705e0` |
| SHA-256 | `5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4` |
| SHA3-384 | `12adb09892dd535b06d31d594a2269ff69f6573e03e4aad5b565eb250a3b16c2d612474a80bc3a6d4b112e17db43a005` |
| TLSH | `T129C312B34D510F38D856BE75F8294A8AD483D8DD20D589F728D8A67F86F3B400537A2E` |
| SSDEEP | `3072:TIVs9JfRxSm1Il+St1msFpyIH7iI3VngijJn+t07QX1Ck:TIy9Jfrd1vumQp5vhgidCh11` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_5d9b8498
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4"
    family = "Mirai"
    file_name = "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4.elf"
    file_type = "elf"
    first_seen = "2026-09-01 21:13:01"
  condition:
    hash.sha256(0, filesize) == "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4"
}
```

### Sample 75: `3846c7915cef375e`

| Field | Value |
|---|---|
| SHA-256 | `3846c7915cef375ef299531f75075279eb97834a331fb2b06330504fb79a73dd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 21:04:20` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2df9c6104f7bbbea2616536c415fd70e` |
| SHA-1 | `b4e2882e26b495ac6750f6b80c0214a473644a8d` |
| SHA-256 | `3846c7915cef375ef299531f75075279eb97834a331fb2b06330504fb79a73dd` |
| SHA3-384 | `5a1e4aa1cb8e31664800571a66f26044420934815d2f100477497b1cbd5c203706ba3e08ec5ca76488d9543ab5ecfc21` |
| IMPHASH | `92f0f7aa4a6391931022407f86031058` |
| TLSH | `T168C4021AFBA505F9C46687BA48550B51BEB2B8425FA447EF03A109072F17BDC4F3E7A0` |
| SSDEEP | `12288:dKoOZh1iRhhAgfcjEBizpuvpogGH71Ov4FCEEt:daZXAnf09zp0pE7bFQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_3846c791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3846c7915cef375ef299531f75075279eb97834a331fb2b06330504fb79a73dd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 21:04:20"
  condition:
    hash.sha256(0, filesize) == "3846c7915cef375ef299531f75075279eb97834a331fb2b06330504fb79a73dd"
}
```

### Sample 76: `9b350fa4e59c1296`

| Field | Value |
|---|---|
| SHA-256 | `9b350fa4e59c1296478c88c8526de8ea412640e50f995dce7982b1be40f3f132` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-01 21:00:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22d7ae30c34073c0c2dc4126d4e0ea65` |
| SHA-1 | `eb52310f90fbc2ff4dbe3c515a1c46a970d5cfae` |
| SHA-256 | `9b350fa4e59c1296478c88c8526de8ea412640e50f995dce7982b1be40f3f132` |
| SHA3-384 | `a8c1195d33abb3737b80d0a8df5d78cb23fdf208fe16f62d30f853796d7dc38eabe9278986f67112c9b4e80ae2eceea9` |
| TLSH | `T1CBC34B01BB81D5B3E14316F512D7CF120431F53B1A6B894AF3693CB6BA69184B326FAD` |
| TELFHASH | `t110313131473166116fa1c9549cee57a3252e82262244ef33ef35c58c94090ebe637c0f` |
| SSDEEP | `3072:mh9m3O3S5ltB4FCwuIPXAb1sPoCQk9YJlbj:mhdS/tBuf+1sPPT9YJlbj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_9b350fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b350fa4e59c1296478c88c8526de8ea412640e50f995dce7982b1be40f3f132"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-01 21:00:45"
  condition:
    hash.sha256(0, filesize) == "9b350fa4e59c1296478c88c8526de8ea412640e50f995dce7982b1be40f3f132"
}
```

### Sample 77: `24c27d732059bdaf`

| Field | Value |
|---|---|
| SHA-256 | `24c27d732059bdaf57c525c3910eddd3df1db9485656db4edf15a719a9ac1eac` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-01 20:58:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35fc47b7579abeefcb06f5c37a51545e` |
| SHA-1 | `916c0007b787badfbdd8a9a8e3ad220b27a169e0` |
| SHA-256 | `24c27d732059bdaf57c525c3910eddd3df1db9485656db4edf15a719a9ac1eac` |
| SHA3-384 | `001312f72884d824309ed1dfcbc12d9f9331cd1fd93898c8a5e21301cfbd2e060b87795022247f1ba5e5cd6f26541081` |
| TLSH | `T102C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:48vCB+25j6es8RjZ9FYpMSUpi+20qUpi+20YQX:48l25Jj/d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_24c27d73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24c27d732059bdaf57c525c3910eddd3df1db9485656db4edf15a719a9ac1eac"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 20:58:32"
  condition:
    hash.sha256(0, filesize) == "24c27d732059bdaf57c525c3910eddd3df1db9485656db4edf15a719a9ac1eac"
}
```

### Sample 78: `0ebdc575eb95d609`

| Field | Value |
|---|---|
| SHA-256 | `0ebdc575eb95d60911b14e2fe5563f1390ce14aeb71fac65b3126c540742d9d3` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-01 20:56:40` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5caf8881f24dc65294f252b691de0d8b` |
| SHA-256 | `0ebdc575eb95d60911b14e2fe5563f1390ce14aeb71fac65b3126c540742d9d3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_0ebdc575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ebdc575eb95d60911b14e2fe5563f1390ce14aeb71fac65b3126c540742d9d3"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 20:56:40"
  condition:
    hash.sha256(0, filesize) == "0ebdc575eb95d60911b14e2fe5563f1390ce14aeb71fac65b3126c540742d9d3"
}
```

### Sample 79: `170d46202f09e9b3`

| Field | Value |
|---|---|
| SHA-256 | `170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01` |
| Family label | `unknown` |
| File name | `170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01.bin` |
| File type | `exe` |
| First seen | `2026-09-01 20:55:59` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6eb58bba50732638a3a17e5a23f55678` |
| SHA-1 | `a4af68cb38e8f99ce1df74e2950f7d1c1949e0b3` |
| SHA-256 | `170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01` |
| SHA3-384 | `866b1402bc2d3f2e8ed43be37eb9331a1b8a6be510d8df35f439b687cfc4ded3dc26c128a63d804001fbf2427697b82e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FA864A077A9151B4D099AE30C07E9213BB65BCCCC73533A31E606A741F797E0BAB6B19` |
| SSDEEP | `49152:VrC6fB2e3pPfTtkBIL4EuQ9lpfPtSDTdJ7aVgkVBVY0kgnsTxvfBT+neBsC7qcAH:Vrpj9qFQf16J7a8hTBXz7UM+yWl8yd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_170d4620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01"
    family = "unknown"
    file_name = "170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01.bin"
    file_type = "exe"
    first_seen = "2026-09-01 20:55:59"
  condition:
    hash.sha256(0, filesize) == "170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01"
}
```

### Sample 80: `30e0026d26c79943`

| Field | Value |
|---|---|
| SHA-256 | `30e0026d26c7994333a3661f3a4f7d2a663e551eddf6356df5c5d838819cf064` |
| Family label | `Mirai` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-09-01 20:48:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4186127cf19c6724a62644a231e4831c` |
| SHA-1 | `e57ec6f493b0bec0abebf0187657f9ca03a1b6ed` |
| SHA-256 | `30e0026d26c7994333a3661f3a4f7d2a663e551eddf6356df5c5d838819cf064` |
| SHA3-384 | `283d7ac8bd36caff8da2228cb64750254be95ec87425033f340250477a8d66b08428e3557b39f788bc84a6c8de3ec928` |
| TLSH | `T182841A5463F1D2DAD244E971D3227F16ABB2063630B7B28B324EB67313B326545DEE60` |
| SSDEEP | `6144:Dw/eRawvsmj9m2bsxzSSCZMOkiNfUj8kibQ8F7IIf4s2rxyDq1dG:30m4cPH3GigdG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_30e0026d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e0026d26c7994333a3661f3a4f7d2a663e551eddf6356df5c5d838819cf064"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-09-01 20:48:09"
  condition:
    hash.sha256(0, filesize) == "30e0026d26c7994333a3661f3a4f7d2a663e551eddf6356df5c5d838819cf064"
}
```

### Sample 81: `487d71cde80b2bae`

| Field | Value |
|---|---|
| SHA-256 | `487d71cde80b2bae91c6f2b408703c5c4d57d91653a28f725f776e58fff03a61` |
| Family label | `unknown` |
| File name | `k.sh` |
| File type | `sh` |
| First seen | `2026-09-01 20:48:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7afa14a7c1cd7feec217313e24f6f84a` |
| SHA-1 | `3eec018999f3ce64ad592224ac1d166b73a642fc` |
| SHA-256 | `487d71cde80b2bae91c6f2b408703c5c4d57d91653a28f725f776e58fff03a61` |
| SHA3-384 | `7104f584106e171805d2a9762b97d030a79b5e7cbdf3e33aa0919c05bd0bb5036447aa8665b86db4a3c1c6c2a6f5da01` |
| TLSH | `T1D7518EC917420F703CA39DE733BA9C053588AEEF54C66E19A5F938F4868ED81B081B53` |
| SSDEEP | `24:vgAFihC/cDXx2m5HU5FjsIGXJAZoS8b75fdB:vgAAC/U8mG5ZsIGZAZoS8b7Fj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_487d71cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "487d71cde80b2bae91c6f2b408703c5c4d57d91653a28f725f776e58fff03a61"
    family = "unknown"
    file_name = "k.sh"
    file_type = "sh"
    first_seen = "2026-09-01 20:48:07"
  condition:
    hash.sha256(0, filesize) == "487d71cde80b2bae91c6f2b408703c5c4d57d91653a28f725f776e58fff03a61"
}
```

### Sample 82: `5f9f09ba0b922e4d`

| Field | Value |
|---|---|
| SHA-256 | `5f9f09ba0b922e4d9f892c200eb365b6fcc00b06a991bf160ac4ee0eb0910e69` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-01 20:48:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e19bd68eee9eafdf29e17108d11b322` |
| SHA-1 | `289586d9e8272ff6dd0e39c9ba9c84c19d3646c9` |
| SHA-256 | `5f9f09ba0b922e4d9f892c200eb365b6fcc00b06a991bf160ac4ee0eb0910e69` |
| SHA3-384 | `0d1345af9f48ce3854d69fa5641dbb297d4197027ce377f8de7e37730e1357499595388acd99c32bb825ec1669739a52` |
| TLSH | `T1EC354A16F2B370ADC093C139479BD7B2A939F07902126D7B32C19A35394AEA05F19F67` |
| TELFHASH | `t1b6712465293c12d999a2ac0488b56bd3548bd2393358ea1afb77cdc818ce89df135c0f` |
| SSDEEP | `24576:Xu23llpsIbaMspVClAjvE8X6X1HvHt1H0s:T3llpsIbUpOYvEw6X1HzH0s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_5f9f09ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f9f09ba0b922e4d9f892c200eb365b6fcc00b06a991bf160ac4ee0eb0910e69"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-01 20:48:05"
  condition:
    hash.sha256(0, filesize) == "5f9f09ba0b922e4d9f892c200eb365b6fcc00b06a991bf160ac4ee0eb0910e69"
}
```

### Sample 83: `78de3c26964e83c1`

| Field | Value |
|---|---|
| SHA-256 | `78de3c26964e83c10f83a7ad3e8399b00efe2702dcf4d27d60cd177cdde517e2` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 20:27:53` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX1.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2335e7a4aa514be564a97c6cf5cd249` |
| SHA-1 | `8722a8b5de9279d0a79dce8258ee5908df4d93c5` |
| SHA-256 | `78de3c26964e83c10f83a7ad3e8399b00efe2702dcf4d27d60cd177cdde517e2` |
| SHA3-384 | `b126e72356edb567f90916eefb0fc0c7f5621c3cbf40478a18ccad8295fdf89d8d1bdf2803301af7307e07d36997a38c` |
| IMPHASH | `03cc13f2892a8bb4db3404549c3b67ea` |
| TLSH | `T18505A02AA39270FDC12781B4C2DB6372E533F83E13E05A6A3794DB713E6CC714A59A15` |
| SSDEEP | `12288:OBVL1aQvGI3n409do+A1k3DE50kVsFCmG4+FQ:egQvGQ4qnA1kzE5IDGNFQ` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_083_78de3c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78de3c26964e83c10f83a7ad3e8399b00efe2702dcf4d27d60cd177cdde517e2"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 20:27:53"
  condition:
    hash.sha256(0, filesize) == "78de3c26964e83c10f83a7ad3e8399b00efe2702dcf4d27d60cd177cdde517e2"
}
```

### Sample 84: `8fc81201abdede01`

| Field | Value |
|---|---|
| SHA-256 | `8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6` |
| Family label | `Mirai` |
| File name | `8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6.elf` |
| File type | `elf` |
| First seen | `2026-09-01 20:23:17` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `024399b1ef6290f10b062a8fcbd5d1dd` |
| SHA-1 | `151e777e427a87851402afb75582b1ade13334d0` |
| SHA-256 | `8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6` |
| SHA3-384 | `7276722bb65b963d5fac7e4772e377d5e57a8dd891d46eb6d2b6ee4df705efd28e583fad977e5ef40e24b01a55ac2a66` |
| TLSH | `T17C455B16B2B370ADC193C039478FD7B2993AF0790212AD7B72899A353F06DA05B19F57` |
| TELFHASH | `t1df715765253c12d5d9a29c0488b56bd3548bd2393358ea2afb77cdc818ce8adf135c0f` |
| SSDEEP | `24576:SS6/z/Apm8yU9Y4ixEVa6olEssMOgh5oX1gy9m1XcXlyv6tgkEE:u/z/ApmOY4qlEssMOgh5oXQpcXlytkEE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_8fc81201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6"
    family = "Mirai"
    file_name = "8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6.elf"
    file_type = "elf"
    first_seen = "2026-09-01 20:23:17"
  condition:
    hash.sha256(0, filesize) == "8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6"
}
```

### Sample 85: `c3b75a86f2ba1e08`

| Field | Value |
|---|---|
| SHA-256 | `c3b75a86f2ba1e087a983534bc576392ff43d3b1eb309ae2b7f50c7a01a8114d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 20:07:59` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2b6020fff86044a4c3b229a3af9807c` |
| SHA-1 | `0f358366052b1bb3b02a741ceff93d3d85166e54` |
| SHA-256 | `c3b75a86f2ba1e087a983534bc576392ff43d3b1eb309ae2b7f50c7a01a8114d` |
| SHA3-384 | `4b45b286dedc157bf099b0ffbfef2de1249d067af595e10715138f142b020a2d6936b8eb96c1f9131f78350baf6fb1b3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1EF667B0B3E9081A5E05E963585BB5252AB34BC4C9F7673D32E80B2341F763D47BBAB44` |
| SSDEEP | `98304:mq/hpfWK5rYyOeGnNvOlw373E6h9TTSiz:mqJp1BYyOeGQ491z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_c3b75a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3b75a86f2ba1e087a983534bc576392ff43d3b1eb309ae2b7f50c7a01a8114d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 20:07:59"
  condition:
    hash.sha256(0, filesize) == "c3b75a86f2ba1e087a983534bc576392ff43d3b1eb309ae2b7f50c7a01a8114d"
}
```

### Sample 86: `9a362e54c5fe38a7`

| Field | Value |
|---|---|
| SHA-256 | `9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50` |
| Family label | `unknown` |
| File name | `9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50.exe` |
| File type | `exe` |
| First seen | `2026-09-01 19:47:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caa7c76bacef9c1f69cb50b5dd2ba3d2` |
| SHA-1 | `18d93b62c49e93d7063a1bed3a5abf5266c43dde` |
| SHA-256 | `9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50` |
| SHA3-384 | `fc7222ed80d99828ab54fc3bed1aa5946dd3f247de541c15612740622711a40d828411bdda2908b4bc70b9a8333fbfb1` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T11CD5235A7EF21D75E876C772CF83F0AEB0283B4586718E977E8D6A008D025909CB5379` |
| SSDEEP | `49152:TtXO7uLd3KrpDRJCyngi1kmX6JwbbNpeoMLPgBwfyDVbqYHBNoJf:VhYr5rCjSkmKJwbbP55wqxn/oJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_9a362e54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50"
    family = "unknown"
    file_name = "9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50.exe"
    file_type = "exe"
    first_seen = "2026-09-01 19:47:08"
  condition:
    hash.sha256(0, filesize) == "9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50"
}
```

### Sample 87: `6af5634511b96d2f`

| Field | Value |
|---|---|
| SHA-256 | `6af5634511b96d2f4e92255fab614aa1eb5f0fb8963375f2c0b7e82ebeac4982` |
| Family label | `unknown` |
| File name | `IndusInd_Credit_Card.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:36:10` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Indusind Credit Card, Malware, signed, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `670a3439a911840c4e092711bff819ba` |
| SHA-1 | `61fc1e0a88a69dc65aa2586831615312d7508fd8` |
| SHA-256 | `6af5634511b96d2f4e92255fab614aa1eb5f0fb8963375f2c0b7e82ebeac4982` |
| SHA3-384 | `f6b512325550e5d4e84cdfd40d1ab24845818e48234a4f4fcc2aec428e3fd665210f47d014bc89f30e9f21dbcbe35fc5` |
| TLSH | `T19E663332E369D532C8B2DB34F6142337F02182A31D57B66A76769385CBF288D6BCC855` |
| SSDEEP | `196608:NwdJ0WlOfWBdugNPYSRndjOWfsphsYZjZk6K5r:NTmRnd508YDk6K5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_6af56345
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6af5634511b96d2f4e92255fab614aa1eb5f0fb8963375f2c0b7e82ebeac4982"
    family = "unknown"
    file_name = "IndusInd_Credit_Card.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:36:10"
  condition:
    hash.sha256(0, filesize) == "6af5634511b96d2f4e92255fab614aa1eb5f0fb8963375f2c0b7e82ebeac4982"
}
```

### Sample 88: `39cf634622d15b51`

| Field | Value |
|---|---|
| SHA-256 | `39cf634622d15b5139c8646de73d0e69191cc89c4ff3fe6ebfbe71c672a2200f` |
| Family label | `unknown` |
| File name | `Tiktok18.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:28:57` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, Malware, Riskware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28690b255ab84b168b0df6b9f05d8454` |
| SHA-1 | `1914ed2287d6b65823218c667b0e3eb4b296c6aa` |
| SHA-256 | `39cf634622d15b5139c8646de73d0e69191cc89c4ff3fe6ebfbe71c672a2200f` |
| SHA3-384 | `01fd28e87d072479ab399b36f3102e721eb14e64a58497f7177bbd589819e909b713d54ec028c88f9a5af299af89111a` |
| TLSH | `T1ED273396FB40969EF8B58A3398714671D1C38E758F87C287384473BC68376E84F16AD8` |
| SSDEEP | `393216:CtccCO+el0wCMNwavUCFq1aRflpfXESBeiZm/UPnrfCENIrcYW10Jfh:Ctc0pv7vUCFUYL/ESBeOPnFNIrXt3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_39cf6346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cf634622d15b5139c8646de73d0e69191cc89c4ff3fe6ebfbe71c672a2200f"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:28:57"
  condition:
    hash.sha256(0, filesize) == "39cf634622d15b5139c8646de73d0e69191cc89c4ff3fe6ebfbe71c672a2200f"
}
```

### Sample 89: `c3291f11a31a8574`

| Field | Value |
|---|---|
| SHA-256 | `c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d` |
| Family label | `CoinMiner` |
| File name | `c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d.exe` |
| File type | `exe` |
| First seen | `2026-09-01 19:27:26` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8a5cf6d161981974fbac563bacf6b40` |
| SHA-1 | `088167b1ccaff235cf8095f54bd07339057a4a11` |
| SHA-256 | `c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d` |
| SHA3-384 | `8d59327bdd827a716cbfecdfc5f22dd1c08a10c2806dcf6c73e9b75cf138a6f04734438599ceb44cf543e940b61cb9f2` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T126363389A9CBC9B4E447C3F95193617DF23E779944A4FC0B3ADC69508E6BE0809BDB40` |
| SSDEEP | `98304:+3EWhWy+P8LAwdcdih4I2LBbJvc3njbshYIQq2tFgc6ys0SlxpHLgFUShdrWPgMy:h1DkLTdx2LBbJv20erX6D0SPpHL8ZYHk` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_089_c3291f11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d"
    family = "CoinMiner"
    file_name = "c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d.exe"
    file_type = "exe"
    first_seen = "2026-09-01 19:27:26"
  condition:
    hash.sha256(0, filesize) == "c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d"
}
```

### Sample 90: `9ecda8119716ad4a`

| Field | Value |
|---|---|
| SHA-256 | `9ecda8119716ad4a113788fc50589e068f078be02423b6b0859fc5f1f29d5cda` |
| Family label | `unknown` |
| File name | `Tiktok18.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:25:24` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, Malware, Riskware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ca2f30c961ddb2f2c462ee267dccbb2` |
| SHA-1 | `a43292190bc541927f0dd55d7f45348b99b48920` |
| SHA-256 | `9ecda8119716ad4a113788fc50589e068f078be02423b6b0859fc5f1f29d5cda` |
| SHA3-384 | `c835817b3f3facf71a85ed8765cf63a0cceb3c00f824c1f3005da72e690983356bc75f79e8ad8719a24ef3dc31157a0f` |
| TLSH | `T19127236EFB8095ABF8BA863749B18771E5074DA64F4382C72815733C68731E44F16EE8` |
| SSDEEP | `393216:TKxXQ8VfFRCoQ2o2zF+RimUk9gmdXCbCC7+s9wStgOE+xJ:TKxXHVjCodlk9/+CkGTY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_9ecda811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ecda8119716ad4a113788fc50589e068f078be02423b6b0859fc5f1f29d5cda"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:25:24"
  condition:
    hash.sha256(0, filesize) == "9ecda8119716ad4a113788fc50589e068f078be02423b6b0859fc5f1f29d5cda"
}
```

### Sample 91: `f84154829462767e`

| Field | Value |
|---|---|
| SHA-256 | `f84154829462767e464f41dd63d1513547e728eced3af90a6561f1e7e1611723` |
| Family label | `unknown` |
| File name | `Tiktok18.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:19:02` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, Malware, Riskware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3bb065761470a2b1f98211900b2676c` |
| SHA-1 | `217cd2e3bf4970025d8c2b8032cc2afd7105b97e` |
| SHA-256 | `f84154829462767e464f41dd63d1513547e728eced3af90a6561f1e7e1611723` |
| SHA3-384 | `a8bd8828c1f1705c82328c996072c46beac85e71fa0aa3d3bc91b447eef704cc5a5c51356cce6a58880e35cf471b9954` |
| TLSH | `T13B27239AFB859AABC8F6863309F16A71110B9CA58F4796C76C00733C69775F50F06EC8` |
| SSDEEP | `393216:041eahKVcj9iJpySr4JU0UIoK0TTgPXYsns/E067+33Qvj:041eah4cjUpDr4JUmNGgXhoMo3Qb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_f8415482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f84154829462767e464f41dd63d1513547e728eced3af90a6561f1e7e1611723"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:19:02"
  condition:
    hash.sha256(0, filesize) == "f84154829462767e464f41dd63d1513547e728eced3af90a6561f1e7e1611723"
}
```

### Sample 92: `f885885e1abba77b`

| Field | Value |
|---|---|
| SHA-256 | `f885885e1abba77b387706cba13aa51ab632b4d525b8e78c16db0f4ad6396a4e` |
| Family label | `unknown` |
| File name | `release.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:17:07` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Malware, Riskware, SpyAgent, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa58a57efee91e83fb37d7d4f9edf92f` |
| SHA-1 | `34666840b8745e033778782ed18b0b315060dc4d` |
| SHA-256 | `f885885e1abba77b387706cba13aa51ab632b4d525b8e78c16db0f4ad6396a4e` |
| SHA3-384 | `f907f7e9c0ed0ff1271f2f11e34b62141d2c282e38d89568bf7c0b405be51fdffc6b8ed033e790b94d52f68f6db3ce4b` |
| TLSH | `T163372387FB88592BC4F753B645761721154B4E228B47DBC7AD54323C28BB6D02F8EAC8` |
| SSDEEP | `393216:M6W4Pq67mpqNQ3o7+bYsGi1/nEToPkTXsKI9DEtVj5EIfWmjnWl7yWbpZT/Q:o4J7oY7+bYRSqosDWDEfj5CpVQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_f885885e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f885885e1abba77b387706cba13aa51ab632b4d525b8e78c16db0f4ad6396a4e"
    family = "unknown"
    file_name = "release.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:17:07"
  condition:
    hash.sha256(0, filesize) == "f885885e1abba77b387706cba13aa51ab632b4d525b8e78c16db0f4ad6396a4e"
}
```

### Sample 93: `1e27a6aa8b48f295`

| Field | Value |
|---|---|
| SHA-256 | `1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8` |
| Family label | `Vidar` |
| File name | `1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8.bin` |
| File type | `exe` |
| First seen | `2026-09-01 19:14:47` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14a10b8f842d41a55b84a71bd668cfd6` |
| SHA-1 | `e742728a52e365d4fe0535adc1f4c89d0a47eea5` |
| SHA-256 | `1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8` |
| SHA3-384 | `36b6e9f4f06fdbd8b6e5333ff02ef1ba3a78ef2ad34d4f0486694964077d760f0eb706fc750a010ee15071a2e7e92b0d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1AC767B0B3A5646E5C5AAD639C57A9223BA307C4CCB3173E72E40A2742F327D179B6F14` |
| SSDEEP | `49152:dexRMCPHu/Bfj59Y51NxdoXRAafH7v7TkroWbgLNFWuJKsDGgGGxTCLLA6P7pTwI:dFN5ImNFNpDGgGGxT8LA6tMiv` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_093_1e27a6aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8"
    family = "Vidar"
    file_name = "1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8.bin"
    file_type = "exe"
    first_seen = "2026-09-01 19:14:47"
  condition:
    hash.sha256(0, filesize) == "1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8"
}
```

### Sample 94: `4d9724d7b0782295`

| Field | Value |
|---|---|
| SHA-256 | `4d9724d7b0782295deec078bf0f6e8da05af94d758332afa7fc0a8a0543228e9` |
| Family label | `unknown` |
| File name | `Tiktok18.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:10:46` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, Malware, Riskware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d3c5d5a5289636503abc978f9cb1224` |
| SHA-1 | `394142d92836ff069d02d4358021f1f2b06e86cb` |
| SHA-256 | `4d9724d7b0782295deec078bf0f6e8da05af94d758332afa7fc0a8a0543228e9` |
| SHA3-384 | `bae1778a51cd00e813b14074b09b8b3353260a522fed7f49a137c9a4ad30dcf574c6a2b76bd44473316e66ed76af76d1` |
| TLSH | `T14F27235ABB829A69FCF6423369B156B2E0076C764F4796F72810733D39731E40F49AC8` |
| SSDEEP | `393216:TtUinBBWWugo499YEI9fRXVIyD7bLMdJZBN880IZOXmkT/4gLwL:Tpn3vua9abLLMDZBNpO3/rwL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_4d9724d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d9724d7b0782295deec078bf0f6e8da05af94d758332afa7fc0a8a0543228e9"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:10:46"
  condition:
    hash.sha256(0, filesize) == "4d9724d7b0782295deec078bf0f6e8da05af94d758332afa7fc0a8a0543228e9"
}
```

### Sample 95: `b02b8e6feac8c147`

| Field | Value |
|---|---|
| SHA-256 | `b02b8e6feac8c1474f6676b24528567fab2048dcb362037ee9f9c05b1b592a3c` |
| Family label | `unknown` |
| File name | `TikTok18+.apk` |
| File type | `apk` |
| First seen | `2026-09-01 19:08:50` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56529d9bb1eca98804bb312c99af34e1` |
| SHA-1 | `a4d13581644f0208d8382ecda079e1a992769fe4` |
| SHA-256 | `b02b8e6feac8c1474f6676b24528567fab2048dcb362037ee9f9c05b1b592a3c` |
| SHA3-384 | `b230a1a39bfdc18bfab2f80db4998351d8f18436440b4d970324624049f4f27f2a80dd288b511e75c8e623586e73b4b6` |
| TLSH | `T14535E03C44C424A0D35C9FF34D4A1B1ACD76238B5A4B672A7E35A1560DCFA8706A27FB` |
| SSDEEP | `24576:ekQwU8gIhNQrAHqD8YiN6HK/CLdLcBVPdARo6Sx7/:pxUyQAHjYimK/Wc666a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_b02b8e6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b02b8e6feac8c1474f6676b24528567fab2048dcb362037ee9f9c05b1b592a3c"
    family = "unknown"
    file_name = "TikTok18+.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:08:50"
  condition:
    hash.sha256(0, filesize) == "b02b8e6feac8c1474f6676b24528567fab2048dcb362037ee9f9c05b1b592a3c"
}
```

### Sample 96: `261b597bc35aa529`

| Field | Value |
|---|---|
| SHA-256 | `261b597bc35aa52903878cfe1ad49e2a58ce157b6a3e3f513c019d7af8217d7a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-01 18:48:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85d55c218725919223762eb44da2453a` |
| SHA-1 | `8e74cb2c2f63e3d4c3e83801ab7e435a6294dada` |
| SHA-256 | `261b597bc35aa52903878cfe1ad49e2a58ce157b6a3e3f513c019d7af8217d7a` |
| SHA3-384 | `3fd5c182ae6b0feaec2125f38461a983046860656125b8e19e390d79452e5d62dd6f59abf98e14ce5dc6ce79aedd75ce` |
| TLSH | `T115A4F98953F1DFD9F268E93003736E1B5DB6063735D3A186E16EE92233A524844AFE70` |
| TELFHASH | `t16af01c28283813b4d2c09c5e56ecff20e8a1a4dba8b62d27c950c969e775e874d00d3c` |
| SSDEEP | `6144:tfXv0t0G01I8IHVRyZHP7l+BMpOM8HVNNqbqfXqPjX4evj:tvLITw5g+OVXX2joevj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_261b597b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "261b597bc35aa52903878cfe1ad49e2a58ce157b6a3e3f513c019d7af8217d7a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 18:48:18"
  condition:
    hash.sha256(0, filesize) == "261b597bc35aa52903878cfe1ad49e2a58ce157b6a3e3f513c019d7af8217d7a"
}
```

### Sample 97: `a9f09a07b91e4810`

| Field | Value |
|---|---|
| SHA-256 | `a9f09a07b91e48105ed9ea1a02596e2b6d049f37587a06e8e77346fe4faf68af` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-01 18:48:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `281e13d1303356e0a87041fc19854ae9` |
| SHA-1 | `7d87f34d7cbc7a4562307f97f54d3e148dd9bb56` |
| SHA-256 | `a9f09a07b91e48105ed9ea1a02596e2b6d049f37587a06e8e77346fe4faf68af` |
| SHA3-384 | `fad103541a3aa17c4660de6558ccc0ec9e215c5e062e6c593d01247c127e444a8a63f26f63aedcf923076ab9b5621def` |
| TLSH | `T152E31397CB9912FBC09367784A611B502D560FC49C02E0061DCAF3E64A7B2FA78C97E7` |
| SSDEEP | `3072:1olj1/wvBzIHbR/WeoIREFYEOaWCeoNSgGnwjWn4WboDDVWGoPuB0cI0VF:1imUVPEJO7CeyLHOGXIGoPVcIqF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_a9f09a07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9f09a07b91e48105ed9ea1a02596e2b6d049f37587a06e8e77346fe4faf68af"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 18:48:02"
  condition:
    hash.sha256(0, filesize) == "a9f09a07b91e48105ed9ea1a02596e2b6d049f37587a06e8e77346fe4faf68af"
}
```

### Sample 98: `9467952bee004db6`

| Field | Value |
|---|---|
| SHA-256 | `9467952bee004db674874989e651da8220cc6d267503d0c6ea39811e1dfc16ec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-01 18:40:36` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ee8e8739059c82b3ff8be68bc0a87ef` |
| SHA-1 | `bef5554ff2b5048e32953ad11c885de730c26eaa` |
| SHA-256 | `9467952bee004db674874989e651da8220cc6d267503d0c6ea39811e1dfc16ec` |
| SHA3-384 | `fde6733657af939583f686017b07dc0f77bc0eebe8faa65d620231577b56a3279885643c698d3a8f32b61238c8974ba0` |
| TLSH | `T1F77558F498BB5366D9564BB2DB9D8417FAF634283E71100FCB20E7E36A124992B1F311` |
| SSDEEP | `24576:0H1zvGyaweeO19GMK0PuwTjZU7K3yJdsmMAU:0H1zey5k1IMKiXerk` |
| ICON-DHASH | `727272620e727272` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_9467952b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9467952bee004db674874989e651da8220cc6d267503d0c6ea39811e1dfc16ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 18:40:36"
  condition:
    hash.sha256(0, filesize) == "9467952bee004db674874989e651da8220cc6d267503d0c6ea39811e1dfc16ec"
}
```

### Sample 99: `f80f8214cf32d0fe`

| Field | Value |
|---|---|
| SHA-256 | `f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c` |
| Family label | `unknown` |
| File name | `f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c.bin` |
| File type | `exe` |
| First seen | `2026-09-01 18:35:14` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d0a446f28f2c74438a6f653842e567e` |
| SHA-1 | `548b42d1acf75ae53b5b38ea84b665c249cb4ccf` |
| SHA-256 | `f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c` |
| SHA3-384 | `95d51e4a6952e3bd32f5f9d9c30c64e7af0818576aa5cd840e0c2d2602755711f1a4b4717d951aa6c729b67a5d188dc8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19EF65A07BE8641E0D59ADA35C0BB2721BB35BC4CCB3477AB2E9061B02F653D16EB5B44` |
| SSDEEP | `98304:ZMNVivUzQ7qpS8Im3YBD/4VUtWduX+HM7XPdB3F5yzxU9b:ZMVivUE7qpH13YDxb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_f80f8214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c"
    family = "unknown"
    file_name = "f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c.bin"
    file_type = "exe"
    first_seen = "2026-09-01 18:35:14"
  condition:
    hash.sha256(0, filesize) == "f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c"
}
```

### Sample 100: `c1202a1501f1f6ce`

| Field | Value |
|---|---|
| SHA-256 | `c1202a1501f1f6cedec89fcd1904cee6fbfc6ca41ed12bb6dabdb047e37ee022` |
| Family label | `unknown` |
| File name | `OP61BfIKeJ65Cp5tyYSjThUQsaGPv2BY_mParivahan_6_.apk` |
| File type | `apk` |
| First seen | `2026-09-01 18:27:37` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, GOI, Malware, mParivahan, Riskware, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be31c5af4b0d0b8cc4e784eb739ece78` |
| SHA-1 | `a1912a4efd6b74e115e4deabe5476d515a362da5` |
| SHA-256 | `c1202a1501f1f6cedec89fcd1904cee6fbfc6ca41ed12bb6dabdb047e37ee022` |
| SHA3-384 | `68da4a2339c04928243ac346ab48a50c4ff49a2c03958fb9e05a2af95767d6e021aa340ac19364df6bd52d33b2aea21f` |
| TLSH | `T148960157FB88A97AC4F3833609766325250B9C218B539297A904723C79F76D05FCAECC` |
| SSDEEP | `196608:EcEyINJrBwLmebhFXvBwS/nZeWGgku08/KpcmC:wyINJ+DFfBwmntGQWZC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_c1202a15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1202a1501f1f6cedec89fcd1904cee6fbfc6ca41ed12bb6dabdb047e37ee022"
    family = "unknown"
    file_name = "OP61BfIKeJ65Cp5tyYSjThUQsaGPv2BY_mParivahan_6_.apk"
    file_type = "apk"
    first_seen = "2026-09-01 18:27:37"
  condition:
    hash.sha256(0, filesize) == "c1202a1501f1f6cedec89fcd1904cee6fbfc6ca41ed12bb6dabdb047e37ee022"
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
 * Generated: 2026-09-02T04:43:48.719376+00:00
 */

rule MalwareBazaar_unknown_001_abcdf531
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530"
    family = "unknown"
    file_name = "abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530.exe"
    file_type = "exe"
    first_seen = "2026-09-02 04:23:55"
  condition:
    hash.sha256(0, filesize) == "abcdf531d86451ab05ab7faf02a85f7c987a3069401110726f52de0d38532530"
}

rule MalwareBazaar_Vidar_002_2c786f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b"
    family = "Vidar"
    file_name = "2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b.exe"
    file_type = "exe"
    first_seen = "2026-09-02 04:17:08"
  condition:
    hash.sha256(0, filesize) == "2c786f7009cc5e1fba5471a88b23b34dce6e1578ee9f664ec62bf48227ba384b"
}

rule MalwareBazaar_unknown_003_7c8936ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8936eea92686924155c03b15400323ec6f9a3ff5e9d21deeb95bfb6e9d52f9"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-02 03:58:41"
  condition:
    hash.sha256(0, filesize) == "7c8936eea92686924155c03b15400323ec6f9a3ff5e9d21deeb95bfb6e9d52f9"
}

rule MalwareBazaar_unknown_004_4e222513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e222513d31b3a7f06ed50143316a7a8d616148107281c701b7a3957a4fb3760"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-09-02 03:50:43"
  condition:
    hash.sha256(0, filesize) == "4e222513d31b3a7f06ed50143316a7a8d616148107281c701b7a3957a4fb3760"
}

rule MalwareBazaar_unknown_005_97a99d72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a99d72350712109fb4f341bb6a4b6b7fd0f6ba962e4fc4ed0ab5fe74701ec6"
    family = "unknown"
    file_name = "htarg2.hta"
    file_type = "hta"
    first_seen = "2026-09-02 03:46:54"
  condition:
    hash.sha256(0, filesize) == "97a99d72350712109fb4f341bb6a4b6b7fd0f6ba962e4fc4ed0ab5fe74701ec6"
}

rule MalwareBazaar_Mirai_006_dd54c3a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd54c3a168367b2c9226ceba83e2ec8b330b46c995db952c8b699bb85e6a7d03"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-02 03:46:52"
  condition:
    hash.sha256(0, filesize) == "dd54c3a168367b2c9226ceba83e2ec8b330b46c995db952c8b699bb85e6a7d03"
}

rule MalwareBazaar_unknown_007_4fb58265
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fb582653120dfc75f067c83f58825a07c335b672912bd0c0882dcd1c4576343"
    family = "unknown"
    file_name = "gocl"
    file_type = "sh"
    first_seen = "2026-09-02 03:38:43"
  condition:
    hash.sha256(0, filesize) == "4fb582653120dfc75f067c83f58825a07c335b672912bd0c0882dcd1c4576343"
}

rule MalwareBazaar_RatonRAT_008_dd5e6012
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd5e6012f32aab4c61b485df7056b539fe7da45e4bd2267b972fd9dca45cf0b0"
    family = "RatonRAT"
    file_name = "E39ED5AB22CCB772F31C6F939B8F9875.exe"
    file_type = "exe"
    first_seen = "2026-09-02 03:35:17"
  condition:
    hash.sha256(0, filesize) == "dd5e6012f32aab4c61b485df7056b539fe7da45e4bd2267b972fd9dca45cf0b0"
}

rule MalwareBazaar_ValleyRAT_009_e3703084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e370308419f516d838706ad6cc467957d3b044316e2dd0e34bc11c186c0549e2"
    family = "ValleyRAT"
    file_name = "EE00A6550765FADEF5FEBA0AAAAA08D0.dll"
    file_type = "dll"
    first_seen = "2026-09-02 03:35:12"
  condition:
    hash.sha256(0, filesize) == "e370308419f516d838706ad6cc467957d3b044316e2dd0e34bc11c186c0549e2"
}

rule MalwareBazaar_DCRat_010_33738318
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "337383182a47e38d6a961223a537c7a41e2267f5f12ca474d61ff1b854801617"
    family = "DCRat"
    file_name = "44D0D337F28453D669F10960FC2B6A55.exe"
    file_type = "exe"
    first_seen = "2026-09-02 03:35:07"
  condition:
    hash.sha256(0, filesize) == "337383182a47e38d6a961223a537c7a41e2267f5f12ca474d61ff1b854801617"
}

rule MalwareBazaar_unknown_011_98ec6a83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555"
    family = "unknown"
    file_name = "98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555.bin"
    file_type = "exe"
    first_seen = "2026-09-02 03:31:20"
  condition:
    hash.sha256(0, filesize) == "98ec6a83a313319730bd143f6ce63ddce4389f638ad598c630faeac804755555"
}

rule MalwareBazaar_unknown_012_0dba4b85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dba4b85fa20faee019dfe6d6ac86a5832dfe9f7a02cf1186e2790461c165fa1"
    family = "unknown"
    file_name = "htaallofus.hta"
    file_type = "hta"
    first_seen = "2026-09-02 03:28:31"
  condition:
    hash.sha256(0, filesize) == "0dba4b85fa20faee019dfe6d6ac86a5832dfe9f7a02cf1186e2790461c165fa1"
}

rule MalwareBazaar_unknown_013_281e48fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "281e48fd0032c7d066cf86248f169701fb74dffe85bffef98447ca37acd50267"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 03:27:04"
  condition:
    hash.sha256(0, filesize) == "281e48fd0032c7d066cf86248f169701fb74dffe85bffef98447ca37acd50267"
}

rule MalwareBazaar_unknown_014_bcac04bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcac04bb75d63a10dfeaffb52116b3488ebe1427c484027aa763830df6f00710"
    family = "unknown"
    file_name = "k.sh"
    file_type = "sh"
    first_seen = "2026-09-02 03:24:00"
  condition:
    hash.sha256(0, filesize) == "bcac04bb75d63a10dfeaffb52116b3488ebe1427c484027aa763830df6f00710"
}

rule MalwareBazaar_unknown_015_5319410a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5319410a75d9d84c4d22c5d31cb4b1458940c139043e6c024d211c193402dc7f"
    family = "unknown"
    file_name = "mdndwrciuiidpoppymgzselulrrl"
    file_type = "unknown"
    first_seen = "2026-09-02 03:23:41"
  condition:
    hash.sha256(0, filesize) == "5319410a75d9d84c4d22c5d31cb4b1458940c139043e6c024d211c193402dc7f"
}

rule MalwareBazaar_unknown_016_9e1ff143
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e1ff143e38bdb3c8ce3e876f87ff343080ca2765c4b64b530857cd2d0c8efc6"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 03:16:40"
  condition:
    hash.sha256(0, filesize) == "9e1ff143e38bdb3c8ce3e876f87ff343080ca2765c4b64b530857cd2d0c8efc6"
}

rule MalwareBazaar_unknown_017_fdd1b1e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd1b1e07b75c332526ca0ffc9463ad1b6ddcfa09fa2aefe69d8afdf60759104"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 03:14:40"
  condition:
    hash.sha256(0, filesize) == "fdd1b1e07b75c332526ca0ffc9463ad1b6ddcfa09fa2aefe69d8afdf60759104"
}

rule MalwareBazaar_AsyncRAT_018_04c50ef4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04c50ef404477631936fad3b6ad741d8c6eb498c5fe957b1dca734ebf9bb5796"
    family = "AsyncRAT"
    file_name = "ps_Vef9thK1xPcU_1788247758514.ps1"
    file_type = "ps1"
    first_seen = "2026-09-02 03:11:53"
  condition:
    hash.sha256(0, filesize) == "04c50ef404477631936fad3b6ad741d8c6eb498c5fe957b1dca734ebf9bb5796"
}

rule MalwareBazaar_unknown_019_92df18d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92df18d9fdb738a1e71605232d9cfeaef76b43442b861632c6739476cd126daa"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-02 03:00:38"
  condition:
    hash.sha256(0, filesize) == "92df18d9fdb738a1e71605232d9cfeaef76b43442b861632c6739476cd126daa"
}

rule MalwareBazaar_unknown_020_05c53433
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05c534335612b6c3278f957ab0f40fa1f25f6e26488790416f87720ea04dfce5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-02 02:54:37"
  condition:
    hash.sha256(0, filesize) == "05c534335612b6c3278f957ab0f40fa1f25f6e26488790416f87720ea04dfce5"
}

rule MalwareBazaar_unknown_021_defea427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "defea42799ac63b024fba18364bb199923faf5a1cf44ad0c1825fdcde0e18f77"
    family = "unknown"
    file_name = "Meteor-Client-1.21.11-87-meteorclient.cc.jar"
    file_type = "jar"
    first_seen = "2026-09-02 02:54:00"
  condition:
    hash.sha256(0, filesize) == "defea42799ac63b024fba18364bb199923faf5a1cf44ad0c1825fdcde0e18f77"
}

rule MalwareBazaar_unknown_022_cf9782de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf9782def5ca04fa493ba640a4ab10a75288554a3f883fede8431a525f550c3c"
    family = "unknown"
    file_name = "Meteor-GUI-addon-2_2_0.jar"
    file_type = "jar"
    first_seen = "2026-09-02 02:53:52"
  condition:
    hash.sha256(0, filesize) == "cf9782def5ca04fa493ba640a4ab10a75288554a3f883fede8431a525f550c3c"
}

rule MalwareBazaar_unknown_023_d460ba58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d460ba58bb99d868d5010862d1a157f37ced69f230662f1db73d3d7358989645"
    family = "unknown"
    file_name = "Leakestan-Addon-V6.jar"
    file_type = "jar"
    first_seen = "2026-09-02 02:53:36"
  condition:
    hash.sha256(0, filesize) == "d460ba58bb99d868d5010862d1a157f37ced69f230662f1db73d3d7358989645"
}

rule MalwareBazaar_unknown_024_d226baf0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d226baf09ee2071fd90a2e413d384a98768fd9188314414cf4179aaa1f834a52"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-02 02:52:36"
  condition:
    hash.sha256(0, filesize) == "d226baf09ee2071fd90a2e413d384a98768fd9188314414cf4179aaa1f834a52"
}

rule MalwareBazaar_unknown_025_7c83eaa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f"
    family = "unknown"
    file_name = "7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f.bin"
    file_type = "exe"
    first_seen = "2026-09-02 02:36:31"
  condition:
    hash.sha256(0, filesize) == "7c83eaa84cbf4f5bcde0d3d7c636b817e710fc33dbe0ba69f912f906bf93bb9f"
}

rule MalwareBazaar_Vidar_026_1dd8bce2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39"
    family = "Vidar"
    file_name = "1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39.bin"
    file_type = "exe"
    first_seen = "2026-09-02 02:36:29"
  condition:
    hash.sha256(0, filesize) == "1dd8bce285a289682e1a21e9e81d9254f091c21bc189682f4afdb82a666bba39"
}

rule MalwareBazaar_Mirai_027_d188167a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba"
    family = "Mirai"
    file_name = "d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba.elf"
    file_type = "elf"
    first_seen = "2026-09-02 02:32:55"
  condition:
    hash.sha256(0, filesize) == "d188167a5f520c91143254ebb985715cb590440e9632a39c57201cf5abe69bba"
}

rule MalwareBazaar_Mirai_028_a96a70ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097"
    family = "Mirai"
    file_name = "a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097.elf"
    file_type = "elf"
    first_seen = "2026-09-02 02:28:35"
  condition:
    hash.sha256(0, filesize) == "a96a70bacff9900918d254ec9b369047a200d51d528be268c9e2155dffb34097"
}

rule MalwareBazaar_unknown_029_8fe5e644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fe5e64400bf61f51ae8174ed1494925593c51be91d3a50be7e0a53b50a1c1d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-02 02:28:32"
  condition:
    hash.sha256(0, filesize) == "8fe5e64400bf61f51ae8174ed1494925593c51be91d3a50be7e0a53b50a1c1d9"
}

rule MalwareBazaar_unknown_030_591b9630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "591b9630e46777ed975fdc28780d8c29886b4903b85d145dd0ed55f9cdd4c7e9"
    family = "unknown"
    file_name = "mPVJOUsu7vCH.plmn"
    file_type = "unknown"
    first_seen = "2026-09-02 02:05:30"
  condition:
    hash.sha256(0, filesize) == "591b9630e46777ed975fdc28780d8c29886b4903b85d145dd0ed55f9cdd4c7e9"
}

rule MalwareBazaar_unknown_031_ecbf9e6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecbf9e6de52105be852593472611a21989effc7d4e73acb4a0d0a01347a8d079"
    family = "unknown"
    file_name = "8xzp2GYia.exe"
    file_type = "exe"
    first_seen = "2026-09-02 02:05:22"
  condition:
    hash.sha256(0, filesize) == "ecbf9e6de52105be852593472611a21989effc7d4e73acb4a0d0a01347a8d079"
}

rule MalwareBazaar_unknown_032_99b5add0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e"
    family = "unknown"
    file_name = "99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e.exe"
    file_type = "exe"
    first_seen = "2026-09-02 01:52:09"
  condition:
    hash.sha256(0, filesize) == "99b5add0795fe9e24197f9067151b7b1cfc050db6f74596c087a2ccebed6bd7e"
}

rule MalwareBazaar_unknown_033_b95be1e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea"
    family = "unknown"
    file_name = "b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea.exe"
    file_type = "exe"
    first_seen = "2026-09-02 01:32:37"
  condition:
    hash.sha256(0, filesize) == "b95be1e0cc70ac1ed3ca87a0c01b7d44d920fc38f0703eb1f820e6c4e411bcea"
}

rule MalwareBazaar_Prometei_034_548ccd5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065"
    family = "Prometei"
    file_name = "548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065"
    file_type = "elf"
    first_seen = "2026-09-02 01:03:44"
  condition:
    hash.sha256(0, filesize) == "548ccd5fb7078a614c857fbcb278d38d1672430a29de9c70291a5cc33801d065"
}

rule MalwareBazaar_unknown_035_82ae5ea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2"
    family = "unknown"
    file_name = "82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2.bin"
    file_type = "sh"
    first_seen = "2026-09-02 00:32:07"
  condition:
    hash.sha256(0, filesize) == "82ae5ea133f03ac753e74a7d777f5f7e1c4b654c618b6d88ce03e5e4da9898d2"
}

rule MalwareBazaar_Vidar_036_f609e8d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac"
    family = "Vidar"
    file_name = "f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac.bin"
    file_type = "exe"
    first_seen = "2026-09-02 00:16:36"
  condition:
    hash.sha256(0, filesize) == "f609e8d69684846032e7ae713b428e450556330ca65894bb3a0eaf49758f66ac"
}

rule MalwareBazaar_AgentTesla_037_af431182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af43118256344a1ce971c6d1910722f5d9ead1dee0f9ce7aedd18a6e9e53146a"
    family = "AgentTesla"
    file_name = "factura de compra.js"
    file_type = "js"
    first_seen = "2026-09-02 00:07:39"
  condition:
    hash.sha256(0, filesize) == "af43118256344a1ce971c6d1910722f5d9ead1dee0f9ce7aedd18a6e9e53146a"
}

rule MalwareBazaar_NanoCore_038_96812d2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96812d2a00a6ced73e1eae84ed4791ec6b7b687e89fa097183b843042dd9d70b"
    family = "NanoCore"
    file_name = "C856731038D020706AAAA7DA2A8E46A5.exe"
    file_type = "exe"
    first_seen = "2026-09-02 00:05:06"
  condition:
    hash.sha256(0, filesize) == "96812d2a00a6ced73e1eae84ed4791ec6b7b687e89fa097183b843042dd9d70b"
}

rule MalwareBazaar_unknown_039_1b723594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b723594e574c00aac2c946ff738a0454f7c24f6ebc84ae45a6af9628b08cb96"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 23:57:10"
  condition:
    hash.sha256(0, filesize) == "1b723594e574c00aac2c946ff738a0454f7c24f6ebc84ae45a6af9628b08cb96"
}

rule MalwareBazaar_unknown_040_a0df2239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0df2239d79f25e184bc5f6eefa7130bd01d8a5dc59b7ffbfb84c7b676c2a2e1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 23:35:30"
  condition:
    hash.sha256(0, filesize) == "a0df2239d79f25e184bc5f6eefa7130bd01d8a5dc59b7ffbfb84c7b676c2a2e1"
}

rule MalwareBazaar_unknown_041_2f4348bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0"
    family = "unknown"
    file_name = "2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0.exe"
    file_type = "exe"
    first_seen = "2026-09-01 23:07:36"
  condition:
    hash.sha256(0, filesize) == "2f4348bb0f04eb8bd5f416ab396831fdf6198f74d23ebfa03a4a4bc9a0023fe0"
}

rule MalwareBazaar_Vidar_042_3d10f5aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac"
    family = "Vidar"
    file_name = "3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:58:55"
  condition:
    hash.sha256(0, filesize) == "3d10f5aa66dbf90ab7b1f3736bd9b3f3bf52b4b241a3eb67ba8a0c35d53f2fac"
}

rule MalwareBazaar_unknown_043_57f40602
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11"
    family = "unknown"
    file_name = "57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:58:51"
  condition:
    hash.sha256(0, filesize) == "57f406023f5ac9e575c7c9e7befd31c42cd0699904a38cbd612b7cf72dcabf11"
}

rule MalwareBazaar_unknown_044_921ae4b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6"
    family = "unknown"
    file_name = "921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:43:50"
  condition:
    hash.sha256(0, filesize) == "921ae4b0d4344348a744504a68a434bf82e941a3575172be4bf6f929c08b89c6"
}

rule MalwareBazaar_AgentTesla_045_f43019ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43019ee4884c1c23ff804808fdb30691b151eb4a7ae6521d6757fde03a32833"
    family = "AgentTesla"
    file_name = "Lista de productos.exe"
    file_type = "exe"
    first_seen = "2026-09-01 22:42:21"
  condition:
    hash.sha256(0, filesize) == "f43019ee4884c1c23ff804808fdb30691b151eb4a7ae6521d6757fde03a32833"
}

rule MalwareBazaar_Mirai_046_9f55da59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f55da59b17b2279c84367b88a25db30de0727ccfccc11535057fb9bcc89d194"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-01 22:41:08"
  condition:
    hash.sha256(0, filesize) == "9f55da59b17b2279c84367b88a25db30de0727ccfccc11535057fb9bcc89d194"
}

rule MalwareBazaar_unknown_047_1741f284
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1741f284682816da4d8cdd1fd6bbff3262c44266ce5a35224dcc0f97991ee897"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 22:28:47"
  condition:
    hash.sha256(0, filesize) == "1741f284682816da4d8cdd1fd6bbff3262c44266ce5a35224dcc0f97991ee897"
}

rule MalwareBazaar_Vidar_048_65be921e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0"
    family = "Vidar"
    file_name = "65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0.bin"
    file_type = "exe"
    first_seen = "2026-09-01 22:24:39"
  condition:
    hash.sha256(0, filesize) == "65be921e09dc27a0e34a9ce31ad9cbb99854a4d7b4be828e158b19ac849332d0"
}

rule MalwareBazaar_unknown_049_10d4a7e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10d4a7e6b370aba96dab9da75d56b3fd3e53938423cd7f302790b59fc42b3f97"
    family = "unknown"
    file_name = "ruck"
    file_type = "sh"
    first_seen = "2026-09-01 22:20:36"
  condition:
    hash.sha256(0, filesize) == "10d4a7e6b370aba96dab9da75d56b3fd3e53938423cd7f302790b59fc42b3f97"
}

rule MalwareBazaar_Mirai_050_85ef43be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ef43be0fd87c2d98a1e71f055e376a3b6702b6a5279f84aacda4bc57e9b41a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-01 22:13:26"
  condition:
    hash.sha256(0, filesize) == "85ef43be0fd87c2d98a1e71f055e376a3b6702b6a5279f84aacda4bc57e9b41a"
}

rule MalwareBazaar_unknown_051_15ad3083
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ad30836554afa7786618ce3e07957031b2f73473b4e871e6b579a63e5ff386"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 22:13:24"
  condition:
    hash.sha256(0, filesize) == "15ad30836554afa7786618ce3e07957031b2f73473b4e871e6b579a63e5ff386"
}

rule MalwareBazaar_Mirai_052_4125fe7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4125fe7e5b34d5a2d5db97a5b00d0c73dc1cfc1c13a73cd986616828f5051b95"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 22:13:23"
  condition:
    hash.sha256(0, filesize) == "4125fe7e5b34d5a2d5db97a5b00d0c73dc1cfc1c13a73cd986616828f5051b95"
}

rule MalwareBazaar_Mirai_053_4c1df857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c1df8578967cb249ebb3ab7998f8cb754638002e22d2bcb95bb80f7b090c437"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-01 22:10:45"
  condition:
    hash.sha256(0, filesize) == "4c1df8578967cb249ebb3ab7998f8cb754638002e22d2bcb95bb80f7b090c437"
}

rule MalwareBazaar_unknown_054_503dca2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "503dca2a79244bb2ad2dbeae2bdab48613fe6d16d4b4d8b16646c816c82c65cb"
    family = "unknown"
    file_name = "ruckus.sh"
    file_type = "sh"
    first_seen = "2026-09-01 22:10:40"
  condition:
    hash.sha256(0, filesize) == "503dca2a79244bb2ad2dbeae2bdab48613fe6d16d4b4d8b16646c816c82c65cb"
}

rule MalwareBazaar_unknown_055_4aa60d3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aa60d3b9b7cc7c494a3e4daaab89735d1ef2fed27eff9838ad5780d585a2919"
    family = "unknown"
    file_name = "sdt"
    file_type = "sh"
    first_seen = "2026-09-01 22:07:03"
  condition:
    hash.sha256(0, filesize) == "4aa60d3b9b7cc7c494a3e4daaab89735d1ef2fed27eff9838ad5780d585a2919"
}

rule MalwareBazaar_unknown_056_314a49ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "314a49ed66522f202101b625c9cc85b6ef3cc6af528e49ea06da2701aa7af8a4"
    family = "unknown"
    file_name = "av.sh"
    file_type = "sh"
    first_seen = "2026-09-01 21:54:50"
  condition:
    hash.sha256(0, filesize) == "314a49ed66522f202101b625c9cc85b6ef3cc6af528e49ea06da2701aa7af8a4"
}

rule MalwareBazaar_Mirai_057_a52f1911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a52f1911e4a5f078d789fab74a0b727d05a8ac4fb670a33c9d8bcf387bf5b33c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-01 21:54:48"
  condition:
    hash.sha256(0, filesize) == "a52f1911e4a5f078d789fab74a0b727d05a8ac4fb670a33c9d8bcf387bf5b33c"
}

rule MalwareBazaar_Mirai_058_8b8e663e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b8e663ee2b2d946f75fcc5622763afe5a020e994f3b935ec7c0b0f83bcbcf0d"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-01 21:52:33"
  condition:
    hash.sha256(0, filesize) == "8b8e663ee2b2d946f75fcc5622763afe5a020e994f3b935ec7c0b0f83bcbcf0d"
}

rule MalwareBazaar_unknown_059_2b208d76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b208d76e495001a3c3f687a49b7692f7f2ba2bf62d0798665b13d1d3c79214f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-01 21:50:10"
  condition:
    hash.sha256(0, filesize) == "2b208d76e495001a3c3f687a49b7692f7f2ba2bf62d0798665b13d1d3c79214f"
}

rule MalwareBazaar_Mirai_060_51e0e80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51e0e80af7100b9a2b296aa3e171e247a65276b9d19228c837c3c20e3ccadb27"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-01 21:50:09"
  condition:
    hash.sha256(0, filesize) == "51e0e80af7100b9a2b296aa3e171e247a65276b9d19228c837c3c20e3ccadb27"
}

rule MalwareBazaar_unknown_061_4e06f71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e06f71b325f9f47397f3319fa9e6d8156062eccfd3c2f40d265864d93e23822"
    family = "unknown"
    file_name = "li"
    file_type = "sh"
    first_seen = "2026-09-01 21:50:07"
  condition:
    hash.sha256(0, filesize) == "4e06f71b325f9f47397f3319fa9e6d8156062eccfd3c2f40d265864d93e23822"
}

rule MalwareBazaar_Mirai_062_d1ebe6c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ebe6c654f0fc5e3b42ec77b4cf2d87dd74b5b63c1ffc1d5e5a6d2cb0359fb9"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-01 21:50:06"
  condition:
    hash.sha256(0, filesize) == "d1ebe6c654f0fc5e3b42ec77b4cf2d87dd74b5b63c1ffc1d5e5a6d2cb0359fb9"
}

rule MalwareBazaar_unknown_063_fb72ce24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb72ce24396d58ca38a10fa06e1e995223ab204a58446a4caacb3ca8f8a106c3"
    family = "unknown"
    file_name = "lll"
    file_type = "sh"
    first_seen = "2026-09-01 21:30:47"
  condition:
    hash.sha256(0, filesize) == "fb72ce24396d58ca38a10fa06e1e995223ab204a58446a4caacb3ca8f8a106c3"
}

rule MalwareBazaar_unknown_064_9d78d342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d78d3425f030dc288aa4836fcd8506008365233ce3345d3724bf598bede6228"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 21:26:52"
  condition:
    hash.sha256(0, filesize) == "9d78d3425f030dc288aa4836fcd8506008365233ce3345d3724bf598bede6228"
}

rule MalwareBazaar_unknown_065_567564ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "567564ca8951af7b4d8d3f16d6dfef87b30fab048482dbfa5e878897e90e6814"
    family = "unknown"
    file_name = "gocl"
    file_type = "sh"
    first_seen = "2026-09-01 21:24:43"
  condition:
    hash.sha256(0, filesize) == "567564ca8951af7b4d8d3f16d6dfef87b30fab048482dbfa5e878897e90e6814"
}

rule MalwareBazaar_Mirai_066_6938ce6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6938ce6a856e17dbc4026262136bfb6f6d226055d295c13f1681597993274df2"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-01 21:23:18"
  condition:
    hash.sha256(0, filesize) == "6938ce6a856e17dbc4026262136bfb6f6d226055d295c13f1681597993274df2"
}

rule MalwareBazaar_Mirai_067_ac7942ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac7942ba8d1d88a14a6d70d975fce9c88b82c159dae4636101727584832360c7"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-01 21:22:42"
  condition:
    hash.sha256(0, filesize) == "ac7942ba8d1d88a14a6d70d975fce9c88b82c159dae4636101727584832360c7"
}

rule MalwareBazaar_unknown_068_40b64346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b643468356c0fd751893647ad0dc9e2a0019427e4f5f0e2f6e559efcecb977"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 21:20:16"
  condition:
    hash.sha256(0, filesize) == "40b643468356c0fd751893647ad0dc9e2a0019427e4f5f0e2f6e559efcecb977"
}

rule MalwareBazaar_unknown_069_2a5b41f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a5b41f30fdc6cf62934d9f0cd9ce9ad77871699b0e0a23c4f1d4f70f90116d0"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-01 21:18:41"
  condition:
    hash.sha256(0, filesize) == "2a5b41f30fdc6cf62934d9f0cd9ce9ad77871699b0e0a23c4f1d4f70f90116d0"
}

rule MalwareBazaar_Mirai_070_29e11474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29e114749b1ac3f2dfed0ad6345834b718f6410695805b7be7cc30a93ac5ed78"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-01 21:16:44"
  condition:
    hash.sha256(0, filesize) == "29e114749b1ac3f2dfed0ad6345834b718f6410695805b7be7cc30a93ac5ed78"
}

rule MalwareBazaar_Mirai_071_57b1e438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57b1e438ea9864efa7ce4c5f310d039d618d52fa352dcd992d7f042591bf4b74"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-09-01 21:16:43"
  condition:
    hash.sha256(0, filesize) == "57b1e438ea9864efa7ce4c5f310d039d618d52fa352dcd992d7f042591bf4b74"
}

rule MalwareBazaar_Mirai_072_30813802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3081380240ce27efb753ce0fe2a25fe3cadce5d925f55d707c9853a9e6dc67be"
    family = "Mirai"
    file_name = "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4.elf"
    file_type = "elf"
    first_seen = "2026-09-01 21:13:15"
  condition:
    hash.sha256(0, filesize) == "3081380240ce27efb753ce0fe2a25fe3cadce5d925f55d707c9853a9e6dc67be"
}

rule MalwareBazaar_Mirai_073_ead146ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c"
    family = "Mirai"
    file_name = "ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c.elf"
    file_type = "elf"
    first_seen = "2026-09-01 21:13:08"
  condition:
    hash.sha256(0, filesize) == "ead146ff50c9b98cfb9bedb664830f5340d5f56f95f8ee7a05b04859d1b1ef2c"
}

rule MalwareBazaar_Mirai_074_5d9b8498
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4"
    family = "Mirai"
    file_name = "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4.elf"
    file_type = "elf"
    first_seen = "2026-09-01 21:13:01"
  condition:
    hash.sha256(0, filesize) == "5d9b849863383550748d8997bc0f9eb52ec0753d5244499d85c301515d2438e4"
}

rule MalwareBazaar_unknown_075_3846c791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3846c7915cef375ef299531f75075279eb97834a331fb2b06330504fb79a73dd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 21:04:20"
  condition:
    hash.sha256(0, filesize) == "3846c7915cef375ef299531f75075279eb97834a331fb2b06330504fb79a73dd"
}

rule MalwareBazaar_Mirai_076_9b350fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b350fa4e59c1296478c88c8526de8ea412640e50f995dce7982b1be40f3f132"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-01 21:00:45"
  condition:
    hash.sha256(0, filesize) == "9b350fa4e59c1296478c88c8526de8ea412640e50f995dce7982b1be40f3f132"
}

rule MalwareBazaar_unknown_077_24c27d73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24c27d732059bdaf57c525c3910eddd3df1db9485656db4edf15a719a9ac1eac"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-01 20:58:32"
  condition:
    hash.sha256(0, filesize) == "24c27d732059bdaf57c525c3910eddd3df1db9485656db4edf15a719a9ac1eac"
}

rule MalwareBazaar_unknown_078_0ebdc575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ebdc575eb95d60911b14e2fe5563f1390ce14aeb71fac65b3126c540742d9d3"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-01 20:56:40"
  condition:
    hash.sha256(0, filesize) == "0ebdc575eb95d60911b14e2fe5563f1390ce14aeb71fac65b3126c540742d9d3"
}

rule MalwareBazaar_unknown_079_170d4620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01"
    family = "unknown"
    file_name = "170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01.bin"
    file_type = "exe"
    first_seen = "2026-09-01 20:55:59"
  condition:
    hash.sha256(0, filesize) == "170d46202f09e9b3a5cbb5e2056123838e7370e5f4e5edf7f4c4497d47842d01"
}

rule MalwareBazaar_Mirai_080_30e0026d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e0026d26c7994333a3661f3a4f7d2a663e551eddf6356df5c5d838819cf064"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-09-01 20:48:09"
  condition:
    hash.sha256(0, filesize) == "30e0026d26c7994333a3661f3a4f7d2a663e551eddf6356df5c5d838819cf064"
}

rule MalwareBazaar_unknown_081_487d71cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "487d71cde80b2bae91c6f2b408703c5c4d57d91653a28f725f776e58fff03a61"
    family = "unknown"
    file_name = "k.sh"
    file_type = "sh"
    first_seen = "2026-09-01 20:48:07"
  condition:
    hash.sha256(0, filesize) == "487d71cde80b2bae91c6f2b408703c5c4d57d91653a28f725f776e58fff03a61"
}

rule MalwareBazaar_Mirai_082_5f9f09ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f9f09ba0b922e4d9f892c200eb365b6fcc00b06a991bf160ac4ee0eb0910e69"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-01 20:48:05"
  condition:
    hash.sha256(0, filesize) == "5f9f09ba0b922e4d9f892c200eb365b6fcc00b06a991bf160ac4ee0eb0910e69"
}

rule MalwareBazaar_RemusStealer_083_78de3c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78de3c26964e83c10f83a7ad3e8399b00efe2702dcf4d27d60cd177cdde517e2"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 20:27:53"
  condition:
    hash.sha256(0, filesize) == "78de3c26964e83c10f83a7ad3e8399b00efe2702dcf4d27d60cd177cdde517e2"
}

rule MalwareBazaar_Mirai_084_8fc81201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6"
    family = "Mirai"
    file_name = "8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6.elf"
    file_type = "elf"
    first_seen = "2026-09-01 20:23:17"
  condition:
    hash.sha256(0, filesize) == "8fc81201abdede0100dfe26b6ce247db56bc160dc57dc24a2cb58c16a8ab55a6"
}

rule MalwareBazaar_unknown_085_c3b75a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3b75a86f2ba1e087a983534bc576392ff43d3b1eb309ae2b7f50c7a01a8114d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 20:07:59"
  condition:
    hash.sha256(0, filesize) == "c3b75a86f2ba1e087a983534bc576392ff43d3b1eb309ae2b7f50c7a01a8114d"
}

rule MalwareBazaar_unknown_086_9a362e54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50"
    family = "unknown"
    file_name = "9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50.exe"
    file_type = "exe"
    first_seen = "2026-09-01 19:47:08"
  condition:
    hash.sha256(0, filesize) == "9a362e54c5fe38a72bf48e3fd7e35cb20e52f85e4e0cfb4b9b152c324714ad50"
}

rule MalwareBazaar_unknown_087_6af56345
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6af5634511b96d2f4e92255fab614aa1eb5f0fb8963375f2c0b7e82ebeac4982"
    family = "unknown"
    file_name = "IndusInd_Credit_Card.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:36:10"
  condition:
    hash.sha256(0, filesize) == "6af5634511b96d2f4e92255fab614aa1eb5f0fb8963375f2c0b7e82ebeac4982"
}

rule MalwareBazaar_unknown_088_39cf6346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cf634622d15b5139c8646de73d0e69191cc89c4ff3fe6ebfbe71c672a2200f"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:28:57"
  condition:
    hash.sha256(0, filesize) == "39cf634622d15b5139c8646de73d0e69191cc89c4ff3fe6ebfbe71c672a2200f"
}

rule MalwareBazaar_CoinMiner_089_c3291f11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d"
    family = "CoinMiner"
    file_name = "c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d.exe"
    file_type = "exe"
    first_seen = "2026-09-01 19:27:26"
  condition:
    hash.sha256(0, filesize) == "c3291f11a31a8574a725402f364a5ad332836782c6e2b57cca19f670e82eff9d"
}

rule MalwareBazaar_unknown_090_9ecda811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ecda8119716ad4a113788fc50589e068f078be02423b6b0859fc5f1f29d5cda"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:25:24"
  condition:
    hash.sha256(0, filesize) == "9ecda8119716ad4a113788fc50589e068f078be02423b6b0859fc5f1f29d5cda"
}

rule MalwareBazaar_unknown_091_f8415482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f84154829462767e464f41dd63d1513547e728eced3af90a6561f1e7e1611723"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:19:02"
  condition:
    hash.sha256(0, filesize) == "f84154829462767e464f41dd63d1513547e728eced3af90a6561f1e7e1611723"
}

rule MalwareBazaar_unknown_092_f885885e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f885885e1abba77b387706cba13aa51ab632b4d525b8e78c16db0f4ad6396a4e"
    family = "unknown"
    file_name = "release.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:17:07"
  condition:
    hash.sha256(0, filesize) == "f885885e1abba77b387706cba13aa51ab632b4d525b8e78c16db0f4ad6396a4e"
}

rule MalwareBazaar_Vidar_093_1e27a6aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8"
    family = "Vidar"
    file_name = "1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8.bin"
    file_type = "exe"
    first_seen = "2026-09-01 19:14:47"
  condition:
    hash.sha256(0, filesize) == "1e27a6aa8b48f29511e3568755e0761811a169cae721aeaa5d4ed5ca092fe7e8"
}

rule MalwareBazaar_unknown_094_4d9724d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d9724d7b0782295deec078bf0f6e8da05af94d758332afa7fc0a8a0543228e9"
    family = "unknown"
    file_name = "Tiktok18.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:10:46"
  condition:
    hash.sha256(0, filesize) == "4d9724d7b0782295deec078bf0f6e8da05af94d758332afa7fc0a8a0543228e9"
}

rule MalwareBazaar_unknown_095_b02b8e6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b02b8e6feac8c1474f6676b24528567fab2048dcb362037ee9f9c05b1b592a3c"
    family = "unknown"
    file_name = "TikTok18+.apk"
    file_type = "apk"
    first_seen = "2026-09-01 19:08:50"
  condition:
    hash.sha256(0, filesize) == "b02b8e6feac8c1474f6676b24528567fab2048dcb362037ee9f9c05b1b592a3c"
}

rule MalwareBazaar_Mirai_096_261b597b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "261b597bc35aa52903878cfe1ad49e2a58ce157b6a3e3f513c019d7af8217d7a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 18:48:18"
  condition:
    hash.sha256(0, filesize) == "261b597bc35aa52903878cfe1ad49e2a58ce157b6a3e3f513c019d7af8217d7a"
}

rule MalwareBazaar_Mirai_097_a9f09a07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9f09a07b91e48105ed9ea1a02596e2b6d049f37587a06e8e77346fe4faf68af"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-01 18:48:02"
  condition:
    hash.sha256(0, filesize) == "a9f09a07b91e48105ed9ea1a02596e2b6d049f37587a06e8e77346fe4faf68af"
}

rule MalwareBazaar_unknown_098_9467952b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9467952bee004db674874989e651da8220cc6d267503d0c6ea39811e1dfc16ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-01 18:40:36"
  condition:
    hash.sha256(0, filesize) == "9467952bee004db674874989e651da8220cc6d267503d0c6ea39811e1dfc16ec"
}

rule MalwareBazaar_unknown_099_f80f8214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c"
    family = "unknown"
    file_name = "f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c.bin"
    file_type = "exe"
    first_seen = "2026-09-01 18:35:14"
  condition:
    hash.sha256(0, filesize) == "f80f8214cf32d0fef1cae4efd394216672e840fede150008cfad52de228aee0c"
}

rule MalwareBazaar_unknown_100_c1202a15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1202a1501f1f6cedec89fcd1904cee6fbfc6ca41ed12bb6dabdb047e37ee022"
    family = "unknown"
    file_name = "OP61BfIKeJ65Cp5tyYSjThUQsaGPv2BY_mParivahan_6_.apk"
    file_type = "apk"
    first_seen = "2026-09-01 18:27:37"
  condition:
    hash.sha256(0, filesize) == "c1202a1501f1f6cedec89fcd1904cee6fbfc6ca41ed12bb6dabdb047e37ee022"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

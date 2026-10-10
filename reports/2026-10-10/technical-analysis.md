# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-10

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 666 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 666 |
| Unique family labels | 11 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 54 |
| unknown | 29 |
| VShell | 4 |
| Vidar | 4 |
| QuasarRAT | 2 |
| RemcosRAT | 2 |
| ACRStealer | 1 |
| PureCrypter | 1 |
| AMOS | 1 |
| Babadeda | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 64 |
| exe | 28 |
| sh | 4 |
| ps1 | 1 |
| jar | 1 |
| macho | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `d5102a93f27c365d`

| Field | Value |
|---|---|
| SHA-256 | `d5102a93f27c365d5a1d57e82d0d4571d558ff846c50efd7896905fc736148ea` |
| Family label | `QuasarRAT` |
| File name | `DF6F9CE4475DA25B324829509EF5C186.exe` |
| File type | `exe` |
| First seen | `2026-10-10 06:00:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df6f9ce4475da25b324829509ef5c186` |
| SHA-1 | `906a01862b47d1cac17b33ffa9e4074375aeb902` |
| SHA-256 | `d5102a93f27c365d5a1d57e82d0d4571d558ff846c50efd7896905fc736148ea` |
| SHA3-384 | `cc098a2460c3ee9acc581e5c42db785e24a5fd180f916eb13a39bbb6a8a4b9f9ef85d9d84b0c6fcfbe07c93cf70bd2a9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17DF55A643BFC6F37D1AE97B2E1B1105663F4F82AA363EB1B1181A2791C53B514C413AB` |
| SSDEEP | `49152:mFUSTkjn4Hhz4Whf3xGmthZpqfcXXDcLGldHHB72eh2NT:mFUSC4Hhz4Whf3xGmthZsEM` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_001_d5102a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5102a93f27c365d5a1d57e82d0d4571d558ff846c50efd7896905fc736148ea"
    family = "QuasarRAT"
    file_name = "DF6F9CE4475DA25B324829509EF5C186.exe"
    file_type = "exe"
    first_seen = "2026-10-10 06:00:08"
  condition:
    hash.sha256(0, filesize) == "d5102a93f27c365d5a1d57e82d0d4571d558ff846c50efd7896905fc736148ea"
}
```

### Sample 2: `abb018512ef40ba5`

| Field | Value |
|---|---|
| SHA-256 | `abb018512ef40ba5e9aca1ca6fccc4572de60eb23fc79ba798cdc549f63ac27b` |
| Family label | `Mirai` |
| File name | `rainii686` |
| File type | `elf` |
| First seen | `2026-10-10 05:56:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79e9da8d36f40c7de205c0d4b10038e6` |
| SHA-1 | `5b9cd5a3013a24831eff202629c548698a9fef95` |
| SHA-256 | `abb018512ef40ba5e9aca1ca6fccc4572de60eb23fc79ba798cdc549f63ac27b` |
| SHA3-384 | `ce4b2289482651202a6c34056630b020d339c9cedb51798a57e3e4c571f61a4caf9876b76fa594b1da3d97d2cc4e9f90` |
| TLSH | `T1C8B33B80FA8BD1F5D90345B4C0AAB33FDB31971D4031CAAADF999E76E923B416916348` |
| TELFHASH | `t135413bb9ee6608e5abc09803b2ce5311ed1d6b6b242437f60ab715b032a348143bdc35` |
| SSDEEP | `3072:xyMUVcx1LyqhZWFHLP96mF1GrkC/EwzxLQ:xyMUVg1LyqhZ4HLPBF1G5XJQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_abb01851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb018512ef40ba5e9aca1ca6fccc4572de60eb23fc79ba798cdc549f63ac27b"
    family = "Mirai"
    file_name = "rainii686"
    file_type = "elf"
    first_seen = "2026-10-10 05:56:04"
  condition:
    hash.sha256(0, filesize) == "abb018512ef40ba5e9aca1ca6fccc4572de60eb23fc79ba798cdc549f63ac27b"
}
```

### Sample 3: `2b3d9dac838a334b`

| Field | Value |
|---|---|
| SHA-256 | `2b3d9dac838a334b4b702da4b9aba1cdae67a3c3b71ca74eecba6c881f19f7a1` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-10-10 05:52:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d821db968fdfc413dcf45169d9e6100` |
| SHA-1 | `9b682b06fab712adb9a418f975d11e18e1119f85` |
| SHA-256 | `2b3d9dac838a334b4b702da4b9aba1cdae67a3c3b71ca74eecba6c881f19f7a1` |
| SHA3-384 | `e08ea5a77e6426cf62e21679d2411e8970a16011b8c83f9c66f9ba8b977b1a16e5cf9f5e5868d72ce1706354db9d821b` |
| TLSH | `T1B331868D3EB061F2B1088A47F2585789B317C3DCFC72D938D8E9C4A9A4D770C691A755` |
| SSDEEP | `48:/jSFSdmveYTQIwgbITcWU9A0bAZ4W8P2sQLW3mO0sQWNcLIR:/O8dmveYTQIwgbITcWU9AMAZ4W8P2sQM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_2b3d9dac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b3d9dac838a334b4b702da4b9aba1cdae67a3c3b71ca74eecba6c881f19f7a1"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-10-10 05:52:33"
  condition:
    hash.sha256(0, filesize) == "2b3d9dac838a334b4b702da4b9aba1cdae67a3c3b71ca74eecba6c881f19f7a1"
}
```

### Sample 4: `1d306cb7e2bae9d3`

| Field | Value |
|---|---|
| SHA-256 | `1d306cb7e2bae9d3a8eccbeff9521cb10b0ef124092035b625bba7853df2620b` |
| Family label | `unknown` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-10-10 05:52:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4b4f6e93d00f3a4bb599bec01f43199` |
| SHA-1 | `89c2c0dea953ba22a1532e8666ef3200500e95c9` |
| SHA-256 | `1d306cb7e2bae9d3a8eccbeff9521cb10b0ef124092035b625bba7853df2620b` |
| SHA3-384 | `00310be020c6c2ae44726d1efb63f6e82c2aba59582a3ad068c64b7548952713a4afbf979b95a1f033d998f69953fa70` |
| TLSH | `T1FA4152CE3AA061F0904C8946B1496B08B25BC7DCBC62DA7CDCCDC4BA6597F1CB11AF48` |
| SSDEEP | `48:IjSFhdm4ePTnIHgb/TDW79X0bXZvWjPFsnLl31ObsnWNcLIR:IOjdm4ePTnIHgb/TDW79XMXZvWjPFsna` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_1d306cb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d306cb7e2bae9d3a8eccbeff9521cb10b0ef124092035b625bba7853df2620b"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-10-10 05:52:31"
  condition:
    hash.sha256(0, filesize) == "1d306cb7e2bae9d3a8eccbeff9521cb10b0ef124092035b625bba7853df2620b"
}
```

### Sample 5: `1a09814dcd1a18ad`

| Field | Value |
|---|---|
| SHA-256 | `1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74` |
| Family label | `Mirai` |
| File name | `eclipse.mips` |
| File type | `elf` |
| First seen | `2026-10-10 05:42:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `018f2d5b57cdd3fa656bc8ee6ac6163b` |
| SHA-1 | `acce5a44419c6a23deb854dfd948db419cc232d6` |
| SHA-256 | `1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74` |
| SHA3-384 | `9026fe640334b1e9ba325ed366d62bd8729981c84b62cb1defad104ffd18bb8f58fa60711c47f6bd069ae11d5e22d841` |
| TLSH | `T1E8C5F7475E31CF4CF7A4C2359AF34974D7A862DA06A68684D1BCF2146F20B4F640FBA9` |
| TELFHASH | `t1646236e7187912e8a2c5f88ed19ee6140e6354be7ee238337a10d54fd767ac60d24c35` |
| SSDEEP | `24576:QNOgf4ydZXJW/8ST7ZMCYnXjEuI5OWQ+hpHsadRWAwvPSIqB7vdrZA:Q8wVc8YMRguShxJwvPS77XA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_1a09814d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-10-10 05:42:28"
  condition:
    hash.sha256(0, filesize) == "1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74"
}
```

### Sample 6: `d3f4547481e4ca3f`

| Field | Value |
|---|---|
| SHA-256 | `d3f4547481e4ca3fb6437981e1bc30fbe283573b89fe6698dd463894a8d11e3a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-10 05:37:19` |
| Reporter | `Bitsight` |
| Tags | `BB2.file, dropped-by-GCleaner, exe, F, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7b0862929b33881edb395cdebef783e` |
| SHA-1 | `9837b10be2a4bed4f14a69cc668f43eba54da509` |
| SHA-256 | `d3f4547481e4ca3fb6437981e1bc30fbe283573b89fe6698dd463894a8d11e3a` |
| SHA3-384 | `0315c33fa4ab1356fb4ffa3bc6c62aa21d353afc519ea35edb573e4a3a9d43ea5ac766ffcbac6854611ff6042c07f428` |
| IMPHASH | `9271107527c4151b05b1d61c8b7a1b71` |
| TLSH | `T11C161221B3998B65CD4F727E25B8BC09DB487E055F67747C7F8E390BA48AC81247824B` |
| SSDEEP | `49152:H8KWguXB2gGBl4UWivPVj1tvb0YnsRLC/bFLnIqLoErknip2smzV:HiBG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_d3f45474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f4547481e4ca3fb6437981e1bc30fbe283573b89fe6698dd463894a8d11e3a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-10 05:37:19"
  condition:
    hash.sha256(0, filesize) == "d3f4547481e4ca3fb6437981e1bc30fbe283573b89fe6698dd463894a8d11e3a"
}
```

### Sample 7: `b3d283ad82c2328c`

| Field | Value |
|---|---|
| SHA-256 | `b3d283ad82c2328cb09a8f3dee94c3c4813cad98f7680554dec8122d1c32ea63` |
| Family label | `Mirai` |
| File name | `eclipse.m68k` |
| File type | `elf` |
| First seen | `2026-10-10 05:25:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5411832ad3cf43adb34670cbe8c4a8a` |
| SHA-1 | `a79e319412fafe59e602603532597fe735aae88f` |
| SHA-256 | `b3d283ad82c2328cb09a8f3dee94c3c4813cad98f7680554dec8122d1c32ea63` |
| SHA3-384 | `89d94a33ba4b02c2f638867097ffb14d43f214b72e3627a4921f4e4847cff01aef2517f10b44ce11406bc3d3675ef8ba` |
| TLSH | `T1F9E308D7F900D9FAF80AE33748530909B130BBA649925A336257353FED3E1991477E8A` |
| SSDEEP | `3072:E6lc1yZ6fQeGFu71llGVig9ErTB7ADVUjbiELrYvyadjkvV:PKIrs1SVKx7AML0vyaWd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_b3d283ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3d283ad82c2328cb09a8f3dee94c3c4813cad98f7680554dec8122d1c32ea63"
    family = "Mirai"
    file_name = "eclipse.m68k"
    file_type = "elf"
    first_seen = "2026-10-10 05:25:20"
  condition:
    hash.sha256(0, filesize) == "b3d283ad82c2328cb09a8f3dee94c3c4813cad98f7680554dec8122d1c32ea63"
}
```

### Sample 8: `caf01f78fba289bd`

| Field | Value |
|---|---|
| SHA-256 | `caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123` |
| Family label | `unknown` |
| File name | `caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123` |
| File type | `elf` |
| First seen | `2026-10-10 05:22:58` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ce26bd79716996977d322e943a31ce9` |
| SHA-1 | `6bd25d083589c52e56e98be0d59b6ab35b542a65` |
| SHA-256 | `caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123` |
| SHA3-384 | `55e0ac53f5a1a9f9468de3d3bebaad6bd297aa845c5b32588478727dc2288f8136bc7f86b99940ad62969ed8707906f8` |
| TLSH | `T152668D13FC9569EAC1EAA2318A729152BB71BC492B3123D72B50F3382F77BC45979344` |
| TELFHASH | `t1adf33122dcb2bfab1fc403376cb6d5c45357c04b0996bba95fa08375d4eb188847936a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:hf6BAzq7Rn9HQEqP+iTxZWuN5LTK6ewax9+VtMtvEDbuES:hfXzan7jiXdX2pxlVwbVS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_caf01f78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123"
    family = "unknown"
    file_name = "caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123"
    file_type = "elf"
    first_seen = "2026-10-10 05:22:58"
  condition:
    hash.sha256(0, filesize) == "caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123"
}
```

### Sample 9: `d9854ad4b04e65a8`

| Field | Value |
|---|---|
| SHA-256 | `d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161` |
| Family label | `unknown` |
| File name | `d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161.exe` |
| File type | `exe` |
| First seen | `2026-10-10 05:10:47` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce5749df7a24a0de9f418ee0f9317223` |
| SHA-1 | `bd45052e95bf8b70f2eec72e594df60e413c7a59` |
| SHA-256 | `d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161` |
| SHA3-384 | `63f13ca1169b325c218c35fb1fdb384c9351adc9d460430bc64bb1e8a3f30b2b4bba9bf7c5beb06035449edb347c1de2` |
| IMPHASH | `46ce5c12b293febbeb513b196aa7f843` |
| TLSH | `T1135633BF4FCE366BFFC668326161B615057C682F12182525C71C4E5EB87820FE94A3E6` |
| SSDEEP | `98304:pLV0hrXFe+Znl7lVJnFwojFBNYUOHB5qwe4HyphFYW/RocjA+EbcQZdeZ+2:pLq2mlD9OonNaHT93yr56IF` |
| ICON-DHASH | `1c62656d6d65621c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_d9854ad4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161"
    family = "unknown"
    file_name = "d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161.exe"
    file_type = "exe"
    first_seen = "2026-10-10 05:10:47"
  condition:
    hash.sha256(0, filesize) == "d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161"
}
```

### Sample 10: `26acdf091d7a9bcf`

| Field | Value |
|---|---|
| SHA-256 | `26acdf091d7a9bcf72b056561bc69221de623d43097499a777f59cab859b88a1` |
| Family label | `QuasarRAT` |
| File name | `A6A09B6E372BF40B716D2BF3237C2902.exe` |
| File type | `exe` |
| First seen | `2026-10-10 04:25:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, QuasarRAT, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6a09b6e372bf40b716d2bf3237c2902` |
| SHA-1 | `5d5c5f7e3be6c4e74de331adfdbb17a62ef2ab9a` |
| SHA-256 | `26acdf091d7a9bcf72b056561bc69221de623d43097499a777f59cab859b88a1` |
| SHA3-384 | `0726a858f82b5741f83f28db29be26e8ef2edea76ddd1be073bdff1d816589a6da89519deae9c0751299e010f737a98c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14AE55B143BF85F23E1BBE27395B0441667F0EC2AB3A3EB1B1191677E1C53B4059426AB` |
| SSDEEP | `49152:fvDI22SsaNYfdPBldt698dBcjHo4DnEDHSk/OrPoGdTTTHHB72eh2NT:fv822SsaNYfdPBldt6+dBcjHo4DBz` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_010_26acdf09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26acdf091d7a9bcf72b056561bc69221de623d43097499a777f59cab859b88a1"
    family = "QuasarRAT"
    file_name = "A6A09B6E372BF40B716D2BF3237C2902.exe"
    file_type = "exe"
    first_seen = "2026-10-10 04:25:06"
  condition:
    hash.sha256(0, filesize) == "26acdf091d7a9bcf72b056561bc69221de623d43097499a777f59cab859b88a1"
}
```

### Sample 11: `d2e638270df17ec3`

| Field | Value |
|---|---|
| SHA-256 | `d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be` |
| Family label | `unknown` |
| File name | `d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be.exe` |
| File type | `exe` |
| First seen | `2026-10-10 04:13:37` |
| Reporter | `Kejult` |
| Tags | `defendertamper, dropper, exe, KillAV, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed2905d75898b4e2734a056fb86b2e0e` |
| SHA-1 | `a948cc33b972d77a0dbad83929640a7cf086e15e` |
| SHA-256 | `d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be` |
| SHA3-384 | `ac713806f98443605aba43c7e339dea5541985bda9eb42cb176a34b55e17760a7113e37c68cc38f828f5c67e688a860f` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T17348F01663E111AAD577D178C7AB6203EB72B40713308BDB329C43652F73AE45E7AB60` |
| SSDEEP | `1572864:1Pp36F/iKRzko0EL9uXpXFxAI/MZqNrGZVOc4XIoC3MnluZQrZ/:1PpIlkheuXpX/z/5NivOcC7hlTrh` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_d2e63827
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be"
    family = "unknown"
    file_name = "d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be.exe"
    file_type = "exe"
    first_seen = "2026-10-10 04:13:37"
  condition:
    hash.sha256(0, filesize) == "d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be"
}
```

### Sample 12: `3a62ba9d46cb84d3`

| Field | Value |
|---|---|
| SHA-256 | `3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729` |
| Family label | `unknown` |
| File name | `3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729.exe` |
| File type | `exe` |
| First seen | `2026-10-10 04:11:58` |
| Reporter | `Kejult` |
| Tags | `BypassUAC, exe, injector, loader, trojan, UACbypass` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `855af3e93af1316e28b74e841a175e78` |
| SHA-1 | `a30edefb07795ffb786776fa9546d6a53f84aca2` |
| SHA-256 | `3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729` |
| SHA3-384 | `c8129d0d266bac8cb837f36f2f389e62e6015f0310455adf1cfb2f9a0fb0b87687d41ee1fffc271f7d07280dd926c35d` |
| IMPHASH | `694a10f92efdb5ba9c32ad08fff67a41` |
| TLSH | `T18CB4F863F6232589ED53817C8C279306ACBA3D412668EA73153EDDC33A35F970B5E609` |
| SSDEEP | `6144:ZjMBZudk1Da/Bmrs+X4dLZzJwlGqBwbq/3IoV9WfQ7rgQ68tKQlgjpHg9LSQe9El:pWZud+av+Xy8djRKsZXL4YB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_3a62ba9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729"
    family = "unknown"
    file_name = "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729.exe"
    file_type = "exe"
    first_seen = "2026-10-10 04:11:58"
  condition:
    hash.sha256(0, filesize) == "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729"
}
```

### Sample 13: `c589ea48755c88a0`

| Field | Value |
|---|---|
| SHA-256 | `c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6` |
| Family label | `unknown` |
| File name | `c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6` |
| File type | `elf` |
| First seen | `2026-10-10 03:52:39` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot, trojan.` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf2d93f9c156ddce6f86d17ef6b8977f` |
| SHA-1 | `54b8cb02a93dff9e95e2537f9f11875280d1d0bc` |
| SHA-256 | `c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6` |
| SHA3-384 | `b250797687f5a144de2eb823865c5ef2fc0fd20df03d1f8d481280ad257c1a97ae27185be5fda79b5b9000abd4777225` |
| TLSH | `T19337CF77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQt:cqYUQuVDt0TZE6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_c589ea48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6"
    family = "unknown"
    file_name = "c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6"
    file_type = "elf"
    first_seen = "2026-10-10 03:52:39"
  condition:
    hash.sha256(0, filesize) == "c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6"
}
```

### Sample 14: `54e56dcd07a5771d`

| Field | Value |
|---|---|
| SHA-256 | `54e56dcd07a5771dd529ed962e25d875efab0089d9b7b9ab249fcce7e46acae3` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-10 03:28:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8d2bcaad6a6e80536ffef91057d9694` |
| SHA-1 | `56a73b500588a013bd0122eaefd6ebebf4851b57` |
| SHA-256 | `54e56dcd07a5771dd529ed962e25d875efab0089d9b7b9ab249fcce7e46acae3` |
| SHA3-384 | `fe4ad14950687c7c13615c7db5efd78054272f6df2d804da4b8a0b2b0103c9d65c98671493bda6e61115092a8de37711` |
| TLSH | `T179C4298963B1DFDDF324D93103736E576DB6023331D3A685E16EE92227A124858AFE70` |
| TELFHASH | `t101f0da1c183822f1d2c59d5d57edff34d8a081d709762e27c954e8aa97255858c01d6c` |
| SSDEEP | `6144:dWF6sjLqYaIxzNxAOSCKT6L8uc1SmjpeoFBntv5kZOESK4YYadAW4oiBZCNXELTc:ejIIaKKycx1xaOCA3fCRELA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_54e56dcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54e56dcd07a5771dd529ed962e25d875efab0089d9b7b9ab249fcce7e46acae3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 03:28:27"
  condition:
    hash.sha256(0, filesize) == "54e56dcd07a5771dd529ed962e25d875efab0089d9b7b9ab249fcce7e46acae3"
}
```

### Sample 15: `64baec6013414eac`

| Field | Value |
|---|---|
| SHA-256 | `64baec6013414eacd268a91e105e652b8e125e231821100c619d0060a79c37da` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e87f8994131af60286f5a60d4881688d` |
| SHA-1 | `31300923f89b893b44ded06f4fe5674ca526a492` |
| SHA-256 | `64baec6013414eacd268a91e105e652b8e125e231821100c619d0060a79c37da` |
| SHA3-384 | `1fc62c87c68ee7d664f72177aa6bd53d2913ec3a1af482fb45672ac7ed4487b40126e6d9163a37371cafc0ffb8fb560c` |
| TLSH | `T154942A88E1E0E7DAD2D4EA75B31D790D77230735F1D73146E519AE3223EB0890ABE921` |
| TELFHASH | `t1def0dc1c4c9ca2f0e38e329985551006396b2c88837314c60f06ba6eefa34e669e0d81` |
| SSDEEP | `6144:ZQl962ow9uYOp8biJgTCcoHGok4cmnifFN7bRU5FXouOwqCJwhz25DMFva9zz:ZfsO+b21zHGJZy31JG5la9zz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_64baec60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64baec6013414eacd268a91e105e652b8e125e231821100c619d0060a79c37da"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:47"
  condition:
    hash.sha256(0, filesize) == "64baec6013414eacd268a91e105e652b8e125e231821100c619d0060a79c37da"
}
```

### Sample 16: `3fa7e27442f328fc`

| Field | Value |
|---|---|
| SHA-256 | `3fa7e27442f328fc3f5f905bc5bf1444626cbf6dc02afd289bbca783200f43d8` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2effec4dd43215460ea593a8ad7139c2` |
| SHA-1 | `88991838f0c4027975dc37d089c8125f9fdcd64e` |
| SHA-256 | `3fa7e27442f328fc3f5f905bc5bf1444626cbf6dc02afd289bbca783200f43d8` |
| SHA3-384 | `c50a0bf2026303ecf51d66de86de2b2a8a5378f9cf52bb651c59c02fe997aaa2e50daf1c1643729a0a82ff1f40289f9b` |
| TLSH | `T1B2941A88E1E0E7DAD2D4EA75B31D794D3B230735B0D73146E51DAA3223EB1890ABED11` |
| TELFHASH | `t131f097049c4c37e8e74500910abe8136e98e1e0aae36bcf58280b59e0926e1368f2800` |
| SSDEEP | `6144:cz0AbHuxUUE9UxLi2A/ByZ6u1HHbhPyXX+ClQIoI/zwn3rjGe3If31Ja9Tzl9m:fxUfUti2A/BywH+e+frjzwa9Tz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_3fa7e274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa7e27442f328fc3f5f905bc5bf1444626cbf6dc02afd289bbca783200f43d8"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:44"
  condition:
    hash.sha256(0, filesize) == "3fa7e27442f328fc3f5f905bc5bf1444626cbf6dc02afd289bbca783200f43d8"
}
```

### Sample 17: `b5a0f571387cc53c`

| Field | Value |
|---|---|
| SHA-256 | `b5a0f571387cc53c1f817b322e543ab8ef2078bd0e61e1a2fa4fcabe9f43a7fb` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee92f4fe97cb9911225b4422c7c2f021` |
| SHA-1 | `87916078eedfe8e4a787a8ea552b64b2d0f4987a` |
| SHA-256 | `b5a0f571387cc53c1f817b322e543ab8ef2078bd0e61e1a2fa4fcabe9f43a7fb` |
| SHA3-384 | `3f350a7a7fc70d41fa201c3fa28142516441f0eb4a8f00c882a29e19fe6480a44d4eb08f81381e9e12f49dcc1327bc0e` |
| TLSH | `T1A6942A8862B5FBDEE296FE7993017C0A5C298B317883354570AEF97313B72410AF9D61` |
| SSDEEP | `6144:n1VV2uR9uBjI0QQvzFRHKYUR+OBqvX42gV8KpzCLeeBvxc/ae8nsQ:1+BnzFUYt4qvXgj8te8sQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_b5a0f571
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5a0f571387cc53c1f817b322e543ab8ef2078bd0e61e1a2fa4fcabe9f43a7fb"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:42"
  condition:
    hash.sha256(0, filesize) == "b5a0f571387cc53c1f817b322e543ab8ef2078bd0e61e1a2fa4fcabe9f43a7fb"
}
```

### Sample 18: `aba60b306f7287a1`

| Field | Value |
|---|---|
| SHA-256 | `aba60b306f7287a105aebfefe45c151b8e77ceaa0b528ab5d5553094baf4cc07` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbdbe63859a973e564d6c392f0abd59b` |
| SHA-1 | `d6a82bb54b55f46919ba9a09daba8a76846aafa0` |
| SHA-256 | `aba60b306f7287a105aebfefe45c151b8e77ceaa0b528ab5d5553094baf4cc07` |
| SHA3-384 | `48e4f7a60614704d8f12f05acb79985d577717b1227a7c779e3c1aa34c4c8237bb0d25d0daceb4d2df8233b793b2a93a` |
| TLSH | `T1E0942A88F1E0E7DAD2D4EA75B31D794D37230736E1DB3146A519AF3223EB0490ABD921` |
| TELFHASH | `t1acf05c920d591ef9d7bb50c5365a7178099e14881b533ce91208b45eee11442acf2c16` |
| SSDEEP | `6144:rFRLaq3zIiUEyWNhJuzxkoF1pObBuU18te3N/+w+66OhG7nX9vFga9Yz:rXDIiUj8hs7Hsn6gcvaa9Yz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_aba60b30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba60b306f7287a105aebfefe45c151b8e77ceaa0b528ab5d5553094baf4cc07"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:39"
  condition:
    hash.sha256(0, filesize) == "aba60b306f7287a105aebfefe45c151b8e77ceaa0b528ab5d5553094baf4cc07"
}
```

### Sample 19: `fc3b7ce58553134f`

| Field | Value |
|---|---|
| SHA-256 | `fc3b7ce58553134fbfdd03464508534f0cdc35d40f3d6d63e52751befe0265b9` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eccc4893aa892999836b41c13b493d1f` |
| SHA-1 | `e7d28f8a560893130b52edd641efe1dff6665af0` |
| SHA-256 | `fc3b7ce58553134fbfdd03464508534f0cdc35d40f3d6d63e52751befe0265b9` |
| SHA3-384 | `4d3da04a4f9a8ff0a4b18e2642e8ab81c0535c5d58bfc34da7283ff223a122af29d89ab83ae005772db48697bdab0cd4` |
| TLSH | `T1BF0412BD4911F583CE8401B533AB4F01AAF91BA6A3BBAD57052FA54C0F0624D6DF3798` |
| SSDEEP | `3072:wSZjvQP/J6CHmC/xge4GUXENI0qMIKcUppeZRsXvWpJ0KtqyjV7:hCPkCbU4XjFuRavUJUyR7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_fc3b7ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc3b7ce58553134fbfdd03464508534f0cdc35d40f3d6d63e52751befe0265b9"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:36"
  condition:
    hash.sha256(0, filesize) == "fc3b7ce58553134fbfdd03464508534f0cdc35d40f3d6d63e52751befe0265b9"
}
```

### Sample 20: `347ff4da8029c5ae`

| Field | Value |
|---|---|
| SHA-256 | `347ff4da8029c5aede97394b6cb3a59b267e3b6916d4d4e6561e5a248ea56f44` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29cebbf92ea5af5974d4dbd3c5a8b575` |
| SHA-1 | `26d03a35f39d6dce3ef4fcf04b0ba6c115a8bcc2` |
| SHA-256 | `347ff4da8029c5aede97394b6cb3a59b267e3b6916d4d4e6561e5a248ea56f44` |
| SHA3-384 | `62a495d62d4fdd0a1cb21dd9cac177c1b889c96432852004319ac2cc57efa0031ceb1ed4c928c5441028a988de04de3e` |
| TLSH | `T1CE941A88F1E0E7DAD2D4AA75B31D790E3B230736E1D73146E519EB3223EB1490ABD911` |
| TELFHASH | `t181f027a41a3a4d72c3b9c4c8b2197458594f6c496b6b3cd18991709f8e1258235f2c32` |
| SSDEEP | `6144:H3TSqGb2KrEdUKSBDkQrUfO5uhbTHAzLisGAbP+qoxtISN/awS6fOh63c/X2FJaW:XmJEd8KffMuhLULiiUfguPa94zB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_347ff4da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "347ff4da8029c5aede97394b6cb3a59b267e3b6916d4d4e6561e5a248ea56f44"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:33"
  condition:
    hash.sha256(0, filesize) == "347ff4da8029c5aede97394b6cb3a59b267e3b6916d4d4e6561e5a248ea56f44"
}
```

### Sample 21: `762a6ad0a16496eb`

| Field | Value |
|---|---|
| SHA-256 | `762a6ad0a16496eb59595002af5fef4e75e53466ff983808ce40ea296701541a` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-10 03:27:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7debc256408c8d20fec7bab40df8701` |
| SHA-1 | `bfda76c2100579034b8197119b980e1627ca3d1e` |
| SHA-256 | `762a6ad0a16496eb59595002af5fef4e75e53466ff983808ce40ea296701541a` |
| SHA3-384 | `7d6c96b85517f7c6f2c69109d75e0e92671dbb5973f5c7d635bb57dc31e96d967820e944a9e1a0130f2e5ce151e07b7c` |
| TLSH | `T17DA41A44B3B1D3CBD244DE7053362A279B6A467238E7B189610FBB7313B327545DABA0` |
| SSDEEP | `6144:M79y84eKE8HEi9WdZyqbfmKPegjCZrycnBxViQgqoXaJtqZc5JW0bEz7yNY3eCEx:KfD1QrviNXaJO0w3eCEsK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_762a6ad0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "762a6ad0a16496eb59595002af5fef4e75e53466ff983808ce40ea296701541a"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:31"
  condition:
    hash.sha256(0, filesize) == "762a6ad0a16496eb59595002af5fef4e75e53466ff983808ce40ea296701541a"
}
```

### Sample 22: `323ce5bba5660a9a`

| Field | Value |
|---|---|
| SHA-256 | `323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526` |
| Family label | `unknown` |
| File name | `323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526.exe` |
| File type | `exe` |
| First seen | `2026-10-10 03:25:04` |
| Reporter | `Kejult` |
| Tags | `defendertamper, dropper, exe, KillAV, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba005f34d5f56fab5facb9edc4af11d3` |
| SHA-1 | `404015568ef0338c471f0b88b313c23ccd89dfe6` |
| SHA-256 | `323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526` |
| SHA3-384 | `201419734778ed434cd3ff240f945cf9a26b9f11a127e5b52b03c62af430ad6fd814488ceaad3c4927bc3f83d95b1e07` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T18548F01663A111AAD577D178C7AB6203EB72B40713308BDB329C43652F73AE45E7BB60` |
| SSDEEP | `1572864:1Pp36F/iKRzro0EL9uXpXFxAI/MZqNrGZVOc4XIoC3MnluZQrZQ:1PpIlrheuXpX/z/5NivOcC7hlTrC` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_323ce5bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526"
    family = "unknown"
    file_name = "323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526.exe"
    file_type = "exe"
    first_seen = "2026-10-10 03:25:04"
  condition:
    hash.sha256(0, filesize) == "323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526"
}
```

### Sample 23: `70d84f8053a4da10`

| Field | Value |
|---|---|
| SHA-256 | `70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9` |
| Family label | `unknown` |
| File name | `70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9` |
| File type | `elf` |
| First seen | `2026-10-10 03:22:33` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `587daeae7c590ba8ac70bb01230742da` |
| SHA-1 | `b39d6caf2b8bcae790d5c658f13a38e4f4eefc07` |
| SHA-256 | `70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9` |
| SHA3-384 | `79d7e1b371ec5f8e44ed19a3ed0ecd94ab5dc46a46f34b2a3264a7bfed20bf28a85ac171149c5580d6a7c8e1d1801a94` |
| TLSH | `T1C2867C73945624D8E1ADC974D51412427EE8388B573863CBBEC476F65BBABE48E38330` |
| SSDEEP | `49152:cSk1vGE1pFrb/T/vO90dL3BmAFd4A64nsfJvWSIsWWKbeJMJpn14PE9Z7rYPVnab:sXyWSpV+Wu7rI3JEJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_70d84f80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9"
    family = "unknown"
    file_name = "70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9"
    file_type = "elf"
    first_seen = "2026-10-10 03:22:33"
  condition:
    hash.sha256(0, filesize) == "70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9"
}
```

### Sample 24: `c371d3578b519c2a`

| Field | Value |
|---|---|
| SHA-256 | `c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b` |
| Family label | `unknown` |
| File name | `c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b.exe` |
| File type | `exe` |
| First seen | `2026-10-10 03:14:13` |
| Reporter | `Kejult` |
| Tags | `BypassUAC, exe, injector, Loader, trojan, UACbypass` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e551111c16e817cfa7d8353b6e803fd` |
| SHA-1 | `45c621800957a1f6604e05caf571b4158d06aa48` |
| SHA-256 | `c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b` |
| SHA3-384 | `a7dacd94dcd070881772288768f9980d900296748434929c15bb7554cca213673230b2c95345d3fa94f78c066b780724` |
| IMPHASH | `694a10f92efdb5ba9c32ad08fff67a41` |
| TLSH | `T190E4C66AEF922189ED43F03EE8072A43947E39C401909DF6564749837AD07B747AD6CF` |
| SSDEEP | `6144:fu1AQsJ/cK8VZ2fI56kaoANF5piPFMPAJkM3xycKW2KQcMkks2WxhxzDXbBiyCr7:fu+QmYp56doA/5TckMNtLJTghrj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_c371d357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b"
    family = "unknown"
    file_name = "c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b.exe"
    file_type = "exe"
    first_seen = "2026-10-10 03:14:13"
  condition:
    hash.sha256(0, filesize) == "c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b"
}
```

### Sample 25: `77415566cdc9a0f0`

| Field | Value |
|---|---|
| SHA-256 | `77415566cdc9a0f0d16347961f5eacca934a73cb4e00c834b782962e9de8d417` |
| Family label | `RemcosRAT` |
| File name | `56E705CF656CCE54945C7941442A6624.exe` |
| File type | `exe` |
| First seen | `2026-10-10 02:40:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56e705cf656cce54945c7941442a6624` |
| SHA-1 | `83bd590fbc2fa412433e6bd76fee16b379ac6557` |
| SHA-256 | `77415566cdc9a0f0d16347961f5eacca934a73cb4e00c834b782962e9de8d417` |
| SHA3-384 | `e1f749a57b7c52db5aae1b850b14759d444d2cea0a93a95fd1dbe0adf04aa3df33b1000a9c787c55b658aba9ceed041a` |
| IMPHASH | `117b0e98fcd98802425109064482959b` |
| TLSH | `T14DB4AF01BAF1C1B2D57664700939EB35DEBCBC210C359D2B63D61E9ABE301519B3AB72` |
| SSDEEP | `12288:bcF3UU0AViEhkwkhoo+/TUszmXxr1svZ9txt:P1AViE/kHszmXWZB` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_025_77415566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77415566cdc9a0f0d16347961f5eacca934a73cb4e00c834b782962e9de8d417"
    family = "RemcosRAT"
    file_name = "56E705CF656CCE54945C7941442A6624.exe"
    file_type = "exe"
    first_seen = "2026-10-10 02:40:07"
  condition:
    hash.sha256(0, filesize) == "77415566cdc9a0f0d16347961f5eacca934a73cb4e00c834b782962e9de8d417"
}
```

### Sample 26: `cc4407b98559e654`

| Field | Value |
|---|---|
| SHA-256 | `cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f` |
| Family label | `unknown` |
| File name | `cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f` |
| File type | `elf` |
| First seen | `2026-10-10 02:22:22` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84672e1ba66769fbee84b1e6b3752901` |
| SHA-1 | `2e5550660f1e03bb9441d4e516395b1a1bf6f913` |
| SHA-256 | `cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f` |
| SHA3-384 | `316bb7cfe243c0cccacb358b272aed0e1a52e2e6b13128e23b1154b5bbaba6a4a6fd87c51740ae31d9c59c10958c297e` |
| TLSH | `T1E9E2D044AEA483CBCD84DC3F1E8C1731E6BE9A51BE05943043E59175DB73DA1DAB3294` |
| SSDEEP | `384:GaiAgXHo4zkejSudOylMns6PmUipfaES8TR057HUkOeZHoc4wLFhedUGKrmiUCDL:GfI4zlmuIruFUZ+47HU49oc2UIFCPI1o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_cc4407b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f"
    family = "unknown"
    file_name = "cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f"
    file_type = "elf"
    first_seen = "2026-10-10 02:22:22"
  condition:
    hash.sha256(0, filesize) == "cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f"
}
```

### Sample 27: `79ada3e5bddf5a6f`

| Field | Value |
|---|---|
| SHA-256 | `79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873` |
| Family label | `VShell` |
| File name | `79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873.exe` |
| File type | `exe` |
| First seen | `2026-10-10 02:20:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfe0826ecc3baeb9e74e361adbcd34bd` |
| SHA-1 | `06277d663bba5b94d3c968c263eaf257c307de92` |
| SHA-256 | `79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873` |
| SHA3-384 | `0b6e4f9d0a2f47320bcca7992f02f8a81d92bb8ababb12a4dbc9e4562ea457d892c61b7d42cfc0d38295e10678090246` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1A991A5C5F757E6B2EC1C17F500A3B9A8C4682E14927CAB568FE16F0C7C111AA3D2DA52` |
| SSDEEP | `48:6I7lwe7oh08SjJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1e09tq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_027_79ada3e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873"
    family = "VShell"
    file_name = "79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873.exe"
    file_type = "exe"
    first_seen = "2026-10-10 02:20:43"
  condition:
    hash.sha256(0, filesize) == "79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873"
}
```

### Sample 28: `6dfba6f825841868`

| Field | Value |
|---|---|
| SHA-256 | `6dfba6f8258418683002d77be91fba1abe8527baab12a1013e161bc394f959f8` |
| Family label | `Mirai` |
| File name | `eclipse.x86_64` |
| File type | `elf` |
| First seen | `2026-10-10 02:16:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de76a2c3611b5c45fd5cd6d1930934e5` |
| SHA-1 | `7e31b771fcf720041185ab3e9d60c1f57c54da6c` |
| SHA-256 | `6dfba6f8258418683002d77be91fba1abe8527baab12a1013e161bc394f959f8` |
| SHA3-384 | `9e25fb5049a6815c612d786edb74b5bb45eedbdec7e3bd8f1a09699796e98cc13bbbdb086117e5e947fffc85fbf3366f` |
| TLSH | `T1F2B57B83E9D580FEC49EC134566F81326F75F48C5670BB9B5391EB713A2AEA06E1C780` |
| TELFHASH | `t188020eb04af534f5b2dbda1af363f1756a360465a1fc35b06a226c95df88e840c76823` |
| SSDEEP | `49152:oLLWDsq30ZihQNkA3h5KBrQagxMdNIVIU6iB36vsZLtstS4p0kpA:MCDsq300kDpaNX+Uvzp0T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_6dfba6f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dfba6f8258418683002d77be91fba1abe8527baab12a1013e161bc394f959f8"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-10-10 02:16:03"
  condition:
    hash.sha256(0, filesize) == "6dfba6f8258418683002d77be91fba1abe8527baab12a1013e161bc394f959f8"
}
```

### Sample 29: `00e9fd3aafdda7a6`

| Field | Value |
|---|---|
| SHA-256 | `00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e` |
| Family label | `ACRStealer` |
| File name | `00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e.ps1` |
| File type | `ps1` |
| First seen | `2026-10-10 02:12:57` |
| Reporter | `Kejult` |
| Tags | `ACRStealer, ArcStealer, dropper, obfuscated, ps1, Stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb1cb320125d95949bb0c6caaf6724a7` |
| SHA-1 | `52b1dd760abe110d79e1f454930327ad5b3d4a86` |
| SHA-256 | `00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e` |
| SHA3-384 | `134c1f2ef1ea8d8bf2e46f366ea2fd0e0aadb6f7010f4553f86345e21f087dcae9182ac1dbbe7a79b2d88ef51516c805` |
| TLSH | `T1A924742539C0A765128DDCB72C814C1D9AC9F436E3876C1D79CF59C5AF47AB88AEC838` |
| SSDEEP | `6144:nUv1AcjU/MVXfDGBxpwwI3s7sLbvExcjhE78BVgTYA/eoLpQTV:Uv1AwopwwUL5` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_029_00e9fd3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e"
    family = "ACRStealer"
    file_name = "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e.ps1"
    file_type = "ps1"
    first_seen = "2026-10-10 02:12:57"
  condition:
    hash.sha256(0, filesize) == "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e"
}
```

### Sample 30: `c51c6272590c97dc`

| Field | Value |
|---|---|
| SHA-256 | `c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6` |
| Family label | `Mirai` |
| File name | `c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6.elf` |
| File type | `elf` |
| First seen | `2026-10-10 02:12:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d787abf943aa71b25d025cff44b7cc76` |
| SHA-1 | `5582749fa856e66fac74ba00da2a3481b16702e3` |
| SHA-256 | `c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6` |
| SHA3-384 | `24d448da7c5184f53590bf629c2636cad1818071873ae210c456fffddfcdf31ac73c9fc0bbbbb2ebf60327c3dc9d0c78` |
| TLSH | `T1DB245BC3F900DEBAF80AE73748130506B130F7B604925A776257357BED7A19A187BE86` |
| SSDEEP | `6144:XwIQF34neevsN9yYJXWRbLUQ3r8NMKLivK11:XwIQyxvWirLvKf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_c51c6272
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6"
    family = "Mirai"
    file_name = "c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6.elf"
    file_type = "elf"
    first_seen = "2026-10-10 02:12:13"
  condition:
    hash.sha256(0, filesize) == "c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6"
}
```

### Sample 31: `f07a46a944884523`

| Field | Value |
|---|---|
| SHA-256 | `f07a46a94488452359b84a012af599d7144d4124b7c2aeed0045bb9a29bef858` |
| Family label | `Mirai` |
| File name | `2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757.elf` |
| File type | `elf` |
| First seen | `2026-10-10 02:11:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a1673ee517b713c038feebaeb002722` |
| SHA-1 | `9f3bc156ece537311dc7b14d178360c955db81c4` |
| SHA-256 | `f07a46a94488452359b84a012af599d7144d4124b7c2aeed0045bb9a29bef858` |
| SHA3-384 | `f665926af51a23b631621f12bb5216a069279ab487de9d4e841c8fcf2313a5d53f6c8ad2f18d728ed782eb681d646f97` |
| TLSH | `T1AD141856FC419F16CAC116BBFB5E428D372B07A8D2EE71039E255F20378B86B0E3A541` |
| TELFHASH | `t1b8e0c212e3e410e2b1e154554aeb133696b5b51d2937593484b96f8fb993d909813813` |
| SSDEEP | `6144:Ona56k2I0oTkQgxAc/fwQ5DHjRGwU+QwOUDITmy5P3:WS6k27SkzycgQhjYwU+5zwmi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_f07a46a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f07a46a94488452359b84a012af599d7144d4124b7c2aeed0045bb9a29bef858"
    family = "Mirai"
    file_name = "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757.elf"
    file_type = "elf"
    first_seen = "2026-10-10 02:11:17"
  condition:
    hash.sha256(0, filesize) == "f07a46a94488452359b84a012af599d7144d4124b7c2aeed0045bb9a29bef858"
}
```

### Sample 32: `2a6aef7706f26d98`

| Field | Value |
|---|---|
| SHA-256 | `2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757` |
| Family label | `Mirai` |
| File name | `2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757.elf` |
| File type | `elf` |
| First seen | `2026-10-10 02:11:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `336886b8c9cecdc3ce8ee486b664a9bb` |
| SHA-1 | `edee8b8b1128605c6a1a67e450b7fae05e64236e` |
| SHA-256 | `2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757` |
| SHA3-384 | `7821c597785351b2154d275c5d73d7714200d943eca682e09ae83b8b892fa4df175d497845fef7990d1d2932ec558f2d` |
| TLSH | `T15A730221D456992C94B44438EC7FC44B7A9B0C9DD7B0713FAD509214FAF6A21E0BCD6E` |
| SSDEEP | `1536:b0Ue5+VEMZzOr89jHhbjJCVBHte9lpWRFSuMNL1v5U9tL6u56yG3RvRdze:oV+VEmzk83jEKpWFSV1KjerjdLy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_2a6aef77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757"
    family = "Mirai"
    file_name = "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757.elf"
    file_type = "elf"
    first_seen = "2026-10-10 02:11:05"
  condition:
    hash.sha256(0, filesize) == "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757"
}
```

### Sample 33: `5a0da401ff83bb72`

| Field | Value |
|---|---|
| SHA-256 | `5a0da401ff83bb724aadb46aa91e877df6dc288dc82af68641a3acbaa1434c96` |
| Family label | `Mirai` |
| File name | `eclipse.sh4` |
| File type | `elf` |
| First seen | `2026-10-10 01:53:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf8671b2a66b2ce7c6e05840c2c18f61` |
| SHA-1 | `3f8ac83683910207f4f540f0c6c8c52714614fef` |
| SHA-256 | `5a0da401ff83bb724aadb46aa91e877df6dc288dc82af68641a3acbaa1434c96` |
| SHA3-384 | `2b0489859b59bb61934337a5fca2fbedbcd3ef936802ccc247bfda8a3bd53c9b5413ffb9a878396c77838633086fefff` |
| TLSH | `T10BB58D32C8256FC8C121D6B5E535CF794F23A95052572FBAAAA3C67C0087E89B7067F4` |
| SSDEEP | `49152:ZL8Y0pLL3wwPdZMdyYg60RBuFKXSGgxWqFaqJudJVvPdW:qem3JVdW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_5a0da401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a0da401ff83bb724aadb46aa91e877df6dc288dc82af68641a3acbaa1434c96"
    family = "Mirai"
    file_name = "eclipse.sh4"
    file_type = "elf"
    first_seen = "2026-10-10 01:53:23"
  condition:
    hash.sha256(0, filesize) == "5a0da401ff83bb724aadb46aa91e877df6dc288dc82af68641a3acbaa1434c96"
}
```

### Sample 34: `58f2dc5c76ba67a0`

| Field | Value |
|---|---|
| SHA-256 | `58f2dc5c76ba67a005df92d9f2287dda6af177dcb387dcbac74944323c85e7be` |
| Family label | `Mirai` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-10-10 01:53:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba1feb30d4ae6e53b39f548fda819e64` |
| SHA-1 | `2b1bdc448054e14932cbbc3b4ff6b7dcc6b45927` |
| SHA-256 | `58f2dc5c76ba67a005df92d9f2287dda6af177dcb387dcbac74944323c85e7be` |
| SHA3-384 | `050681035a1b4f9aa538397d9ea7cb7966c4976be285ba648827c21ec8a4627577346c7403e806a2d0feaa6b5736fc64` |
| TLSH | `T153941A54A3F1D2DAD244ADB493227F16AFB2053634B7B246324EB77313B327548DAE60` |
| SSDEEP | `6144:C76GF64ddCPC5l/AlBNPDQPR69L7n+zClpKyeHyysG:Cx3zARVbKXsG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_58f2dc5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58f2dc5c76ba67a005df92d9f2287dda6af177dcb387dcbac74944323c85e7be"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-10 01:53:21"
  condition:
    hash.sha256(0, filesize) == "58f2dc5c76ba67a005df92d9f2287dda6af177dcb387dcbac74944323c85e7be"
}
```

### Sample 35: `1b79ac93016a8127`

| Field | Value |
|---|---|
| SHA-256 | `1b79ac93016a812762c5c16ce36a7d3405a7b6ecd15eca24f1ca6031b0098911` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-10 01:43:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaccbd9c746f0c5f4e2dfd3b910fa537` |
| SHA-1 | `dfa082b8ebde52d6a428e831e963504c4cbf601c` |
| SHA-256 | `1b79ac93016a812762c5c16ce36a7d3405a7b6ecd15eca24f1ca6031b0098911` |
| SHA3-384 | `8f0e6e037726860de66f97c82f730762048eaf4e66cc0443cfe2fbd2cd7637981fb093663d64a53d9998fab35985e19f` |
| TLSH | `T11D041859FD819F01E9D526BAFE5E428933530BBCE3EE71029E245F2423CA95B0F3A505` |
| TELFHASH | `t1b711ef6acd1808f8bbcd005986fe7433a56571e467085498c49aed3dfd633e8703082f` |
| SSDEEP | `3072:khndivHV2UcftYAxZw27aCmFo8ZOI+QIH//rQUiu0UgmWg3fDarpjdFZMFtgh2Gt:khn4vHV2UetjxZweoFkPpjB08WgvDarL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_1b79ac93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b79ac93016a812762c5c16ce36a7d3405a7b6ecd15eca24f1ca6031b0098911"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 01:43:16"
  condition:
    hash.sha256(0, filesize) == "1b79ac93016a812762c5c16ce36a7d3405a7b6ecd15eca24f1ca6031b0098911"
}
```

### Sample 36: `6dda01bc822dcff5`

| Field | Value |
|---|---|
| SHA-256 | `6dda01bc822dcff5a081176b611e85c3324bfe642f224ace9942b8cf7d1ce0a0` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-10 01:42:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ee35d379a737bf98b1772b9f5c93cf2` |
| SHA-1 | `a6720696521c552660ec5f7aa74adc82894ce13b` |
| SHA-256 | `6dda01bc822dcff5a081176b611e85c3324bfe642f224ace9942b8cf7d1ce0a0` |
| SHA3-384 | `829ca0dae9d604ec3e40022c42897966f41bfe29f5824b121c343974f130401efdc3077b79d93660c2e06f7ce00484d3` |
| TLSH | `T11B730220F27863B1C6678C73B8FFE960A050B5F1800997E5595D12693FC98E45FB839B` |
| SSDEEP | `1536:gg3d0sp5olE+rU3XYjoDZEBfKsnqUkA7mKewClR0X5cLI:h0sXwEEYXYjsEnqUt7mljR0qLI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_6dda01bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dda01bc822dcff5a081176b611e85c3324bfe642f224ace9942b8cf7d1ce0a0"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 01:42:38"
  condition:
    hash.sha256(0, filesize) == "6dda01bc822dcff5a081176b611e85c3324bfe642f224ace9942b8cf7d1ce0a0"
}
```

### Sample 37: `8e550ed90921aa2a`

| Field | Value |
|---|---|
| SHA-256 | `8e550ed90921aa2a7c6d4b5a03fb8cb6d5e45ef9d1705baaea6c41bab5ae4ed6` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-10 01:36:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `552c39e05d60a085e46e51fdbc641445` |
| SHA-1 | `5d148b2d465d1cd56e737c492a41568e217b99cc` |
| SHA-256 | `8e550ed90921aa2a7c6d4b5a03fb8cb6d5e45ef9d1705baaea6c41bab5ae4ed6` |
| SHA3-384 | `b4b91cc718521893a4de50680f4f37ea0295d829f3ce2cdc58d1db83e564f6508eab618afc605b4156f26ae19e18870e` |
| TLSH | `T112D3F965F880DE61C6D2267AFB9D438933231B78C3DE7102DD14AF3436EA95B0B3A546` |
| TELFHASH | `t139e0c012cfc81bfcf3e29c61c7a0656c93f735e42b15e0b4893848735c64881312643b` |
| SSDEEP | `3072:MJ1HagyT4RjE19MBUeD8I2zu+U8yZ2LVpefZrz+TV8bTO3dK:MJfh69zI2zu+U8yZ2LnefgV8bes` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_8e550ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e550ed90921aa2a7c6d4b5a03fb8cb6d5e45ef9d1705baaea6c41bab5ae4ed6"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 01:36:21"
  condition:
    hash.sha256(0, filesize) == "8e550ed90921aa2a7c6d4b5a03fb8cb6d5e45ef9d1705baaea6c41bab5ae4ed6"
}
```

### Sample 38: `526118535dbe7204`

| Field | Value |
|---|---|
| SHA-256 | `526118535dbe72042e5e5c329b31dec47de1d1e7be02c26a1f329c8287dbbc8b` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-10 01:35:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `802a25cdb841a8dad83e12ff260bf346` |
| SHA-1 | `e5cb86979bd929a48453519eb49833173bd8be53` |
| SHA-256 | `526118535dbe72042e5e5c329b31dec47de1d1e7be02c26a1f329c8287dbbc8b` |
| SHA3-384 | `9815045df64232202d76deaad4282ec2a00563ecc4dbc72859c86f89dae12f99b662b6af1679746a504f90cd9c4080bc` |
| TLSH | `T18553023DF118CEC0B231723DC6BD16517056A9F2F9B935978232A76C72CB60F57A818A` |
| SSDEEP | `1536:yPcuAvJS1I4VFIy+Rs8nrzLFeAoZqf7o1jA+X8fS:yPk34VFg6+r/7o1DX86` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_52611853
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "526118535dbe72042e5e5c329b31dec47de1d1e7be02c26a1f329c8287dbbc8b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 01:35:28"
  condition:
    hash.sha256(0, filesize) == "526118535dbe72042e5e5c329b31dec47de1d1e7be02c26a1f329c8287dbbc8b"
}
```

### Sample 39: `4969607e53fb15d4`

| Field | Value |
|---|---|
| SHA-256 | `4969607e53fb15d4681f663d521ea0e70f565ed83ffd1042e9c2f2d77a9f5112` |
| Family label | `Mirai` |
| File name | `riscv32` |
| File type | `elf` |
| First seen | `2026-10-10 01:25:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba3a29aba659506fc9c4ef0b0ea0d7e5` |
| SHA-1 | `98a36eae0c27a867160947784fc0817139286aeb` |
| SHA-256 | `4969607e53fb15d4681f663d521ea0e70f565ed83ffd1042e9c2f2d77a9f5112` |
| SHA3-384 | `bb528381868e27ca904431741782dca568c87ae7549a0d8286136ec499f6c9a4110bd085a9450306fcf8a841ca55a13c` |
| TLSH | `T1A0842A8CA2F1E3DEE158EA7553217C0B4D72463B3493728A319EB97313BA1944AF9D70` |
| SSDEEP | `6144:zJI32GTNtQ7PEAN5cycRufUHN4fU4YqYug0267a9v/:tEjmMA8eUHKfUFqfEya9v/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_4969607e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4969607e53fb15d4681f663d521ea0e70f565ed83ffd1042e9c2f2d77a9f5112"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-10-10 01:25:14"
  condition:
    hash.sha256(0, filesize) == "4969607e53fb15d4681f663d521ea0e70f565ed83ffd1042e9c2f2d77a9f5112"
}
```

### Sample 40: `ad10f4c694e060e8`

| Field | Value |
|---|---|
| SHA-256 | `ad10f4c694e060e8cf9066c8156e03c3eef0a413c125c51e64baceca732c4f31` |
| Family label | `Vidar` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-10 01:21:31` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79af7efda58aaa0562bbd3b98ae65a18` |
| SHA-1 | `19a5d6aa69f753aa541f7797cc8538b63f11ef0a` |
| SHA-256 | `ad10f4c694e060e8cf9066c8156e03c3eef0a413c125c51e64baceca732c4f31` |
| SHA3-384 | `0004ef78eede1c0a581a08e5cb8df7f13728761b01bfb070917cabc43d4e1622d3e0decf8ed9ef8f3600b389298a0911` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16876D95971C410EDCA8E837648F45DBE23B22DBF1613A78A0759BBE12F13BE65B10D48` |
| SSDEEP | `24576:6fqGF77Hg1nbBIBVqUFfV79KA9pfybuwSKfE9t:6ffl7AxtIBVqUB7wSl` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_040_ad10f4c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad10f4c694e060e8cf9066c8156e03c3eef0a413c125c51e64baceca732c4f31"
    family = "Vidar"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-10 01:21:31"
  condition:
    hash.sha256(0, filesize) == "ad10f4c694e060e8cf9066c8156e03c3eef0a413c125c51e64baceca732c4f31"
}
```

### Sample 41: `ac97ff69a8b5da0b`

| Field | Value |
|---|---|
| SHA-256 | `ac97ff69a8b5da0b04c14ed85945931c6218823d829192f2d7bcfa022b6b65b9` |
| Family label | `Vidar` |
| File name | `___L__it__64-v.3.449.exe` |
| File type | `exe` |
| First seen | `2026-10-10 01:19:56` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7c45671c68e5100f7191de9106af5a8` |
| SHA-1 | `1d789d594126b9cfd934dc99dcb89ad5f012a869` |
| SHA-256 | `ac97ff69a8b5da0b04c14ed85945931c6218823d829192f2d7bcfa022b6b65b9` |
| SHA3-384 | `3a395ebc9f7175272eb39fdf1cde3ac148ce5c24bbbb8c918704612fbf9c3ca5f84ab654d4086d07136f659e8ddc8768` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16266C85971C414EDCA8E837608F45DBE23F21DBB1623A68A0795FBA02F13BD65F24D48` |
| SSDEEP | `49152:MNmF1iMDLn7agM4QoeqRCWgJl8X6fN41w8Ay+JF7dTCShB7ZmzWmSlGA0zsgaIZp:MaKDS` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_041_ac97ff69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac97ff69a8b5da0b04c14ed85945931c6218823d829192f2d7bcfa022b6b65b9"
    family = "Vidar"
    file_name = "___L__it__64-v.3.449.exe"
    file_type = "exe"
    first_seen = "2026-10-10 01:19:56"
  condition:
    hash.sha256(0, filesize) == "ac97ff69a8b5da0b04c14ed85945931c6218823d829192f2d7bcfa022b6b65b9"
}
```

### Sample 42: `90feb8a42116a868`

| Field | Value |
|---|---|
| SHA-256 | `90feb8a42116a8687589bcf05e1eb6ad645f55a777931b0436ea58c9e58a97cb` |
| Family label | `Mirai` |
| File name | `android-arm64` |
| File type | `elf` |
| First seen | `2026-10-10 01:17:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6613e2baade9b7b93c6739f64d3a256b` |
| SHA-1 | `72da504a1c91664ee800bcdccef388bee3e29de9` |
| SHA-256 | `90feb8a42116a8687589bcf05e1eb6ad645f55a777931b0436ea58c9e58a97cb` |
| SHA3-384 | `50bff62dbacbec92bec838f03ff40bc9e2d28323509dfe3cbd97c89f3c0eb64adc15bc0305db2e62415495e35433ef0a` |
| TLSH | `T1B9844B4CD1F5E3DEE288F67852157D169C32317A31A3728A720FA56B53EB28449EDE30` |
| TELFHASH | `t12411bd46ad79d6ae6d938a20aca967b09113da223171c320ef10ced4ac3e515f20de4f` |
| SSDEEP | `6144:3n5a9RuYvJ4br6vdhf1LbKDpvqnoaOFW7:3n5a9Ho6vdhsRqnou` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_90feb8a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90feb8a42116a8687589bcf05e1eb6ad645f55a777931b0436ea58c9e58a97cb"
    family = "Mirai"
    file_name = "android-arm64"
    file_type = "elf"
    first_seen = "2026-10-10 01:17:34"
  condition:
    hash.sha256(0, filesize) == "90feb8a42116a8687589bcf05e1eb6ad645f55a777931b0436ea58c9e58a97cb"
}
```

### Sample 43: `5a052f7071b9e66a`

| Field | Value |
|---|---|
| SHA-256 | `5a052f7071b9e66a6f73473244f9b632c19885f9f73fb5871c364731ddecc306` |
| Family label | `unknown` |
| File name | `qp0tnnr.jar` |
| File type | `jar` |
| First seen | `2026-10-10 01:16:27` |
| Reporter | `NyxIndius` |
| Tags | `jar, Silentnet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7df5c5357230de58ccace873802fa3fe` |
| SHA-1 | `4f3fd77e9b6c28d9cbcb48e74d984a8bc95bc145` |
| SHA-256 | `5a052f7071b9e66a6f73473244f9b632c19885f9f73fb5871c364731ddecc306` |
| SHA3-384 | `9116074afadcad219c532246780b66e109af00460ccb58806b36b14865384b210ffe253dc732c6fda1234279006e451d` |
| TLSH | `T1E91533280148FD77DEB9BB6C521141AAD8AFC5064696BC67AFAFF000558BCC0F1E96D3` |
| SSDEEP | `24576:/HSHMQ/YFtwv3GSA2f8WYeA+FvV8aGeW5ykSlUg8kmjiD:2MQsTQ8z+FvVqemxg8w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_5a052f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a052f7071b9e66a6f73473244f9b632c19885f9f73fb5871c364731ddecc306"
    family = "unknown"
    file_name = "qp0tnnr.jar"
    file_type = "jar"
    first_seen = "2026-10-10 01:16:27"
  condition:
    hash.sha256(0, filesize) == "5a052f7071b9e66a6f73473244f9b632c19885f9f73fb5871c364731ddecc306"
}
```

### Sample 44: `0203fcb09d396bed`

| Field | Value |
|---|---|
| SHA-256 | `0203fcb09d396bed27adaf248ee33aca03c9e048bfd98555e966b30b122d426a` |
| Family label | `Mirai` |
| File name | `android-arm` |
| File type | `elf` |
| First seen | `2026-10-10 01:09:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6b014d193e7b40c5f50f56507fba542` |
| SHA-1 | `0faef8108fb66c43b76b7ac3cae074d2891caa3c` |
| SHA-256 | `0203fcb09d396bed27adaf248ee33aca03c9e048bfd98555e966b30b122d426a` |
| SHA3-384 | `055a05ae3753965f3c2846aac991f890d6198161dac554e3ae86dae80cc66fd55c8f5201f8b39fa2589366030173f56d` |
| TLSH | `T177840A88B1F1E3CDD1D8E9757219BC893A63533AB1DB3146650EEB3223EF14945B9A30` |
| TELFHASH | `t12611bd46ad79d6ae6d938a20aca927b09113da223171c320ef10ced4ac3e515f20de4f` |
| SSDEEP | `6144:o748a9iKyBJ1S/fgJv1VxX29Ra6lmU3Orr:o748a9iKyBJ0I7xXSRUrr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_0203fcb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0203fcb09d396bed27adaf248ee33aca03c9e048bfd98555e966b30b122d426a"
    family = "Mirai"
    file_name = "android-arm"
    file_type = "elf"
    first_seen = "2026-10-10 01:09:35"
  condition:
    hash.sha256(0, filesize) == "0203fcb09d396bed27adaf248ee33aca03c9e048bfd98555e966b30b122d426a"
}
```

### Sample 45: `5f706fe4ff04ef74`

| Field | Value |
|---|---|
| SHA-256 | `5f706fe4ff04ef74710bc422a938e3b5d452ef739c1d9e6a06592c1742567c53` |
| Family label | `Mirai` |
| File name | `riscv64` |
| File type | `elf` |
| First seen | `2026-10-10 01:09:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fba2f44377422bcef180dc689ada5750` |
| SHA-1 | `f0767846843d77f3d1acd0019f3b8aee97d47909` |
| SHA-256 | `5f706fe4ff04ef74710bc422a938e3b5d452ef739c1d9e6a06592c1742567c53` |
| SHA3-384 | `5553c54ce97147beaa52f2ceaa4a6f87b47b570f2f0ae87c940318d4256adf8556000bcf1ac1f134c816a947c8e9acfe` |
| TLSH | `T15C742A8CD2F1E3CEE158EA7453247C1A5C72463A3097B28A719EB97313AB1944AFDD70` |
| SSDEEP | `6144:gXWDLUytKlZ1OoEAH6wUQ9tzrkxFYQZa9AQ:eWkytARDrUxF1Za9AQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_5f706fe4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f706fe4ff04ef74710bc422a938e3b5d452ef739c1d9e6a06592c1742567c53"
    family = "Mirai"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-10-10 01:09:32"
  condition:
    hash.sha256(0, filesize) == "5f706fe4ff04ef74710bc422a938e3b5d452ef739c1d9e6a06592c1742567c53"
}
```

### Sample 46: `83299e43d1c3b324`

| Field | Value |
|---|---|
| SHA-256 | `83299e43d1c3b324e9c3a5018822d502f203a3fbef7d8e640d4540fbf4b5c689` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-10 01:02:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d55e53becae494b4de8311d4154372b2` |
| SHA-1 | `1ba60dbd073f5d11ed5879e5cbabf91127807d46` |
| SHA-256 | `83299e43d1c3b324e9c3a5018822d502f203a3fbef7d8e640d4540fbf4b5c689` |
| SHA3-384 | `1d180d3568fb020e3c52208bdbe8154bb1c6c7956fe55fa797a48db729bd856b8142b6f24a1ed71e19bca6396bd64d32` |
| TLSH | `T1CA44C71AAB610FFBE8AFDD3306E90B0625CC640726A83F793574D914F54A64B4AD3C78` |
| SSDEEP | `3072:QsJB12gLxXhgJnRmLZfU+M8CGjGj2HGAVac2B99Y9mxXkjHCK:b15x16+MWlGAVEY2Xk2K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_83299e43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83299e43d1c3b324e9c3a5018822d502f203a3fbef7d8e640d4540fbf4b5c689"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-10 01:02:26"
  condition:
    hash.sha256(0, filesize) == "83299e43d1c3b324e9c3a5018822d502f203a3fbef7d8e640d4540fbf4b5c689"
}
```

### Sample 47: `6fc9a7c3206a9a25`

| Field | Value |
|---|---|
| SHA-256 | `6fc9a7c3206a9a25b325a5d2f18a555bf94d2b8d1bbf732105ab8fb6f362d72f` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-10-10 01:02:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `653ebee918a7e1d2712155f1c5e66e66` |
| SHA-1 | `0c8e64e46429aca81135e267d10048a47661aebc` |
| SHA-256 | `6fc9a7c3206a9a25b325a5d2f18a555bf94d2b8d1bbf732105ab8fb6f362d72f` |
| SHA3-384 | `f6b0ecedbab9e007d09d16a09da95831273b6ee0e84c9742dfa0ec3a4eb8a54b780cfa7e144335440460baafc03e2a78` |
| TLSH | `T1DD142856FD819F12D5C015BEFE1E528E33131B78E2DE72139E246F24678A8AB0F3A514` |
| TELFHASH | `t1bc11ab26fda928e8bfe500a1c6fe6633a99e71d923502021a49c8e8fdd43de23511c17` |
| SSDEEP | `6144:HLWs8u7GS+WAXBEXjEKbL89/0Lttxaa3eY5QsuxuyANqS:rWs8u7GvxB8okY+Ltnaa3j6vxuyAR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_6fc9a7c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fc9a7c3206a9a25b325a5d2f18a555bf94d2b8d1bbf732105ab8fb6f362d72f"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-10 01:02:22"
  condition:
    hash.sha256(0, filesize) == "6fc9a7c3206a9a25b325a5d2f18a555bf94d2b8d1bbf732105ab8fb6f362d72f"
}
```

### Sample 48: `34982876ca4776eb`

| Field | Value |
|---|---|
| SHA-256 | `34982876ca4776ebaca652e152141a226b6b6d03e0be32f1ba046629bde6d781` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-10 01:01:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42a2176f01b455d8b67f5a3b5587898d` |
| SHA-1 | `a04fbab93fc41b47fbf070a9f1f92e2ff836945b` |
| SHA-256 | `34982876ca4776ebaca652e152141a226b6b6d03e0be32f1ba046629bde6d781` |
| SHA3-384 | `d92531e4aa825028992040434a3a4da528d157a9fb31ec8daa1fb62ed756b8ecd7aeb453462c368ab5398ac3ffc9a2db` |
| TLSH | `T1B183029D3A99316A985E0D3E955F5FD59EA3B0C0F3E2B99C5130848DA690C422ACE4FC` |
| SSDEEP | `1536:1UpI7TJf3xK0T/0LrJpiyb17PQSf2/CAktFWyaDWSjPXZ37GFRP9T8:1Ue7TdE0T8LrJpp17PNOqftF2DWwPpLD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_34982876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34982876ca4776ebaca652e152141a226b6b6d03e0be32f1ba046629bde6d781"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-10 01:01:31"
  condition:
    hash.sha256(0, filesize) == "34982876ca4776ebaca652e152141a226b6b6d03e0be32f1ba046629bde6d781"
}
```

### Sample 49: `dc5dff4a23be303f`

| Field | Value |
|---|---|
| SHA-256 | `dc5dff4a23be303fe1d8d37fde70744f8be3237dd7dd41c4a1c96a523f032b1e` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-10-10 01:01:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e53c9ba3916f99a88bf190b63d4f331` |
| SHA-1 | `93b58f55bac973e85c1a540446e2407d4918fef4` |
| SHA-256 | `dc5dff4a23be303fe1d8d37fde70744f8be3237dd7dd41c4a1c96a523f032b1e` |
| SHA3-384 | `524fa926a490b14d8d29a09f2c1547b00f2a813d47723ad4a16cc24ed02e0f35b885a1e27dd817e9ca50d2e356dda0b6` |
| TLSH | `T12583128423E55BC2FFE4093E80AEA2A7552C6D7B75BED0071398800CB2477C54EE94AB` |
| SSDEEP | `1536:ZI8xe/R8RtmieqNxwhoABwd5NpxEE9NV3QFeQytLpb:u1/R8R7NxwhoZ5l/uQQILpb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_dc5dff4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5dff4a23be303fe1d8d37fde70744f8be3237dd7dd41c4a1c96a523f032b1e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-10 01:01:29"
  condition:
    hash.sha256(0, filesize) == "dc5dff4a23be303fe1d8d37fde70744f8be3237dd7dd41c4a1c96a523f032b1e"
}
```

### Sample 50: `8d18689c062bf9f1`

| Field | Value |
|---|---|
| SHA-256 | `8d18689c062bf9f17d699bd454dc2c1bbf72f96db6363fd470773155854510ca` |
| Family label | `unknown` |
| File name | `main.microblazebe` |
| File type | `elf` |
| First seen | `2026-10-10 00:58:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a4a083839899ded98564891ec416491` |
| SHA-1 | `20fc4f8238b2804e4ee7f1024d432f99f245a78e` |
| SHA-256 | `8d18689c062bf9f17d699bd454dc2c1bbf72f96db6363fd470773155854510ca` |
| SHA3-384 | `032a480274418130d485b87e91cb175f09a6ec154cdfaf34118350dd9dc669bc5c0a8301e136d6543d4a66bdf53b0375` |
| TLSH | `T131B38471F90667B1CC720A38579A2F096E7704199FEB16625E1F623DEE66810CB30F8D` |
| SSDEEP | `1536:0PcXoLTs/f5AOuuOuuuuuuuuuu6gLiFwvuEnsal/f/n/zt2N4UG3nH88nJPaam52:5oL46HSFwvnxV793cmPRiJ6qUP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_8d18689c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d18689c062bf9f17d699bd454dc2c1bbf72f96db6363fd470773155854510ca"
    family = "unknown"
    file_name = "main.microblazebe"
    file_type = "elf"
    first_seen = "2026-10-10 00:58:08"
  condition:
    hash.sha256(0, filesize) == "8d18689c062bf9f17d699bd454dc2c1bbf72f96db6363fd470773155854510ca"
}
```

### Sample 51: `b6ea43e7f0371f52`

| Field | Value |
|---|---|
| SHA-256 | `b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921` |
| Family label | `Vidar` |
| File name | `b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:55:41` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16687cfe65c4d3598ca0a880f9b0fca0` |
| SHA-1 | `980d8ddf9c7882ea0703b88c527ea4e5135bf994` |
| SHA-256 | `b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921` |
| SHA3-384 | `8b8d063da4837194b34fb52f26091db278c7c50982790c985114f6035009561b8fea8309ca13e3a37902584580f4b9b2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17A66D95871C410EDDA8E837608F45DBE23B21DBB1713A68A0759BBA53F13BE65F20D48` |
| SSDEEP | `24576:RFbzWgDYt/BcMqupwiixkSXwgbgYb1UegyH+wlEDsucqKWqy86:RFGgDYxStuGxXXwg8wlkKvyb` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_051_b6ea43e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921"
    family = "Vidar"
    file_name = "b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:55:41"
  condition:
    hash.sha256(0, filesize) == "b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921"
}
```

### Sample 52: `4dbc2a3dcbd0a5a7`

| Field | Value |
|---|---|
| SHA-256 | `4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688` |
| Family label | `Vidar` |
| File name | `4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:55:27` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2986bdb8dd1f62b11c1c57e58f00ae50` |
| SHA-1 | `24f8618ede8ebf037ca603114b5d917bd5c9966b` |
| SHA-256 | `4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688` |
| SHA3-384 | `b5b5f42eaa7dfab74787bf72079fbcf40f0b241456a7f66dc2611a326ac2551a9f4f8ae3972ef8bf497df55bb177423b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11566DA5871C414EDCA8E837608F45DBE23B21DBB1613A68A0759BBA53F13BE65F20D4C` |
| SSDEEP | `24576:jNeqwjuAnWdLOiLDY9yeKCa1gSl1UegyH+wlEDsuottW27:jNr4uAWxDLkPaCwlttD` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_052_4dbc2a3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688"
    family = "Vidar"
    file_name = "4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:55:27"
  condition:
    hash.sha256(0, filesize) == "4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688"
}
```

### Sample 53: `7056591ec2e5296b`

| Field | Value |
|---|---|
| SHA-256 | `7056591ec2e5296b23074efa4461c62bbb4ad189dfdbbde1a4445498c3efe638` |
| Family label | `Mirai` |
| File name | `dvr.sh` |
| File type | `sh` |
| First seen | `2026-10-10 00:55:08` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c4b57fe047cc61f6bac1d8e817b7d11` |
| SHA-1 | `785036e0ea887a954fa6bfae10947192cc446d72` |
| SHA-256 | `7056591ec2e5296b23074efa4461c62bbb4ad189dfdbbde1a4445498c3efe638` |
| SHA3-384 | `bb844d9f6eb4583afc57bbe82d34464cdc6cb1cbfa31f7278f382a9d4348d18b8e06e533d90004f6601bd688f67da734` |
| TLSH | `T165D062C5A0D82E2FD86A8C1D7557065194C764752773B7245C6425F35C83520B627F4E` |
| SSDEEP | `3:TFKxKvewOnQzas03VZ7KS/jVIhdgjzxLHakN3+EtjzxLHawVZ7KS/jqIhdgj4xL/:JkKVOsw7DZ5bN3j5/78I8O7kN3jO79` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_7056591e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7056591ec2e5296b23074efa4461c62bbb4ad189dfdbbde1a4445498c3efe638"
    family = "Mirai"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-10-10 00:55:08"
  condition:
    hash.sha256(0, filesize) == "7056591ec2e5296b23074efa4461c62bbb4ad189dfdbbde1a4445498c3efe638"
}
```

### Sample 54: `f427a2829f5f7962`

| Field | Value |
|---|---|
| SHA-256 | `f427a2829f5f796210b15a4d6eb5df2fd40a1c116877ff66e4c42eb4f5ec3fd3` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-10-10 00:55:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba46973a23fa0f72ec0b09d4cc9ab31c` |
| SHA-1 | `730420b745a37616481ef66b86141bc470f11053` |
| SHA-256 | `f427a2829f5f796210b15a4d6eb5df2fd40a1c116877ff66e4c42eb4f5ec3fd3` |
| SHA3-384 | `0196a8bea72231792a7fb82ce80e5914b5b14f0daea4ef903dd094ae9a55cf52d4a64e0331661e3f5265ac1e137d150e` |
| TLSH | `T133A43D8453E3D7CEF254E97043A27C2A6CB5073374E79587E27E693303A61A418EEDA1` |
| SSDEEP | `6144:9brYPsPHrbYSNyb1IvbNYv+L+pq8C75WYnkAaPOWrwqFRW3:BrYPKnDfvbNG+yg8QJdaPOWrwuRW3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_f427a282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f427a2829f5f796210b15a4d6eb5df2fd40a1c116877ff66e4c42eb4f5ec3fd3"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-10-10 00:55:01"
  condition:
    hash.sha256(0, filesize) == "f427a2829f5f796210b15a4d6eb5df2fd40a1c116877ff66e4c42eb4f5ec3fd3"
}
```

### Sample 55: `48722ba5a2d08b12`

| Field | Value |
|---|---|
| SHA-256 | `48722ba5a2d08b126b747a82e962556625ba80ea48533978cd4ca8e5fd4f6180` |
| Family label | `unknown` |
| File name | `main.i486` |
| File type | `elf` |
| First seen | `2026-10-10 00:54:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c124bbc905e9be8e2d200bbe7e7dea3` |
| SHA-1 | `cfb048eae232998fcc9218831bb6061a3f6e02db` |
| SHA-256 | `48722ba5a2d08b126b747a82e962556625ba80ea48533978cd4ca8e5fd4f6180` |
| SHA3-384 | `c1655d25feada18d95215abcff0c18e111f36c2d3f574d972de58034c1d0724017597d569bb1a66ca6b3589bab40040f` |
| TLSH | `T119E2C602EA93C472C50330B212F2DBB65931FAB76924D515C779AFB0EA151C1E2933BE` |
| TELFHASH | `t10f219a91bee605ecf6c16c5fa75e57c38b390ab30a2178ba44f537053bf22b2e221411` |
| SSDEEP | `384:fVNolTTqkLQOQ26W5Lb+2R6+vVO3vflrYAbuQll8jBf+4pLixkeXXi9aCpIUWr4q:2WkLQ9lsLn6sO3vflrRyuuZEnYIUB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_48722ba5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48722ba5a2d08b126b747a82e962556625ba80ea48533978cd4ca8e5fd4f6180"
    family = "unknown"
    file_name = "main.i486"
    file_type = "elf"
    first_seen = "2026-10-10 00:54:59"
  condition:
    hash.sha256(0, filesize) == "48722ba5a2d08b126b747a82e962556625ba80ea48533978cd4ca8e5fd4f6180"
}
```

### Sample 56: `4faca0c251d54100`

| Field | Value |
|---|---|
| SHA-256 | `4faca0c251d54100a37cfda9d33c396048bce26c79cf5e23b4ca14fd685b558c` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-10 00:52:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b521898b5be3bf059943fe3109e53b41` |
| SHA-1 | `9e6f8b42559b4ecd7c6985f93df2c612b3673ab2` |
| SHA-256 | `4faca0c251d54100a37cfda9d33c396048bce26c79cf5e23b4ca14fd685b558c` |
| SHA3-384 | `2234d090a5106daa92557fa790f1529e53780bb452b48098d0e85b8d02d8a46065b3010289a7f1e90ccfd5457de257f2` |
| TLSH | `T10C44A40A6A329F7DF7688B3447B74F30A75D23D616E1D684E1ACC1141E6025E682FFAC` |
| TELFHASH | `t1a551f6a809b903b4d2546c1d49edff2796e300ef3e1a2c339a50d86ee761b839c24c09` |
| SSDEEP | `6144:GlwqV568w8qaoUc7zqFYX5060BvxeyKVGFmqliS6Lry:GlxkdzqFYp060JxeyKVPry` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_4faca0c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4faca0c251d54100a37cfda9d33c396048bce26c79cf5e23b4ca14fd685b558c"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 00:52:19"
  condition:
    hash.sha256(0, filesize) == "4faca0c251d54100a37cfda9d33c396048bce26c79cf5e23b4ca14fd685b558c"
}
```

### Sample 57: `8d1aaf7b5343e6d1`

| Field | Value |
|---|---|
| SHA-256 | `8d1aaf7b5343e6d13828f68e65e165c394076751b83d01b3642758820c0641b5` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-10 00:52:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b79a52dfeb6941c70a669cf2f6e6061` |
| SHA-1 | `336133178c12338f963e92a88a98278013de6d7d` |
| SHA-256 | `8d1aaf7b5343e6d13828f68e65e165c394076751b83d01b3642758820c0641b5` |
| SHA3-384 | `28d2dca65867253c2d3301d96c697e23763c0c7645b995cd92a3ba9ff8a21d40959bda29b69bda5475b3e2bac007e104` |
| TLSH | `T16283127CD31108EDF87488BB679847117C1847A969029E254BB6F7C1DC4CDDEB8AB2B8` |
| SSDEEP | `1536:BmRYq8YSlNoq9vMXddcAtL0cQUYiZ4yICHjnAobFGxxTP7LtnAiI9SadAVJur:Z6SlN+Nqc+QqyAogxTPGr9SaiVQr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_8d1aaf7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d1aaf7b5343e6d13828f68e65e165c394076751b83d01b3642758820c0641b5"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 00:52:02"
  condition:
    hash.sha256(0, filesize) == "8d1aaf7b5343e6d13828f68e65e165c394076751b83d01b3642758820c0641b5"
}
```

### Sample 58: `e9875f2824240e97`

| Field | Value |
|---|---|
| SHA-256 | `e9875f2824240e97413fb19a8623153098c65b5d4f4918ead31631cab8c0a425` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-10 00:48:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b39e87bd8ec0b2cd6cde76bc25e30238` |
| SHA-1 | `625492340384a977420d5241a3dc5b9eab5b10be` |
| SHA-256 | `e9875f2824240e97413fb19a8623153098c65b5d4f4918ead31631cab8c0a425` |
| SHA3-384 | `7a0afd19c96bae87bf6075c129cd693a5f0f3654eba56cd4ca120e2f4b7485d56f9bc5e2a228dce2b9d61de7d5d43f0d` |
| TLSH | `T1F9941944B3B1D2CBD294DE7053362F679B6A863238E7F189610FBB7313B217445DAA60` |
| SSDEEP | `6144:JbhJs3jEZ61lBsliRTvP5OqFxsOiGEZtwFEW5C0tJ7hRGNi91ooVJiM:J4sli9RO3GpFEf04oVJiM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_e9875f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9875f2824240e97413fb19a8623153098c65b5d4f4918ead31631cab8c0a425"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-10 00:48:58"
  condition:
    hash.sha256(0, filesize) == "e9875f2824240e97413fb19a8623153098c65b5d4f4918ead31631cab8c0a425"
}
```

### Sample 59: `68f1e25924255b1b`

| Field | Value |
|---|---|
| SHA-256 | `68f1e25924255b1be60f3c1f05418dc50181cc8e8d95dce4280a6a8285465139` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-10 00:46:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `442f33358fbac06138167ad29aebc4be` |
| SHA-1 | `3dd7de00d0add592640b0443045848da60a6aed3` |
| SHA-256 | `68f1e25924255b1be60f3c1f05418dc50181cc8e8d95dce4280a6a8285465139` |
| SHA3-384 | `cd46701eb644049d155d1fffad43d4e20bdc0d6d47e5a15e9e6b896913a73b5cada0d25993fa29527aabacaf06788a29` |
| TLSH | `T123347C98FA0F6C41F2C2D3FDDE5C47E13A1775E3C73699B16D1212ACCAA38D99A90502` |
| SSDEEP | `6144:YStUlieEsVjmaZXkuMJZqKkG7UtHSgn1gAaoq:Y8UTEAOuwZrCDvao` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_68f1e259
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68f1e25924255b1be60f3c1f05418dc50181cc8e8d95dce4280a6a8285465139"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-10 00:46:28"
  condition:
    hash.sha256(0, filesize) == "68f1e25924255b1be60f3c1f05418dc50181cc8e8d95dce4280a6a8285465139"
}
```

### Sample 60: `1c39d5b7fd20f7d6`

| Field | Value |
|---|---|
| SHA-256 | `1c39d5b7fd20f7d696ca4697abc07a3e08e73496975df0e37a5da0c956e8316c` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-10 00:45:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd0b6acecb89f9a2fce8f4320b5b1494` |
| SHA-1 | `b9a4cf32f3f676506fb04dcc5f85d0ef9ebcdae0` |
| SHA-256 | `1c39d5b7fd20f7d696ca4697abc07a3e08e73496975df0e37a5da0c956e8316c` |
| SHA3-384 | `6fd651b825bb77be5f10a841c0688269a50015a1b68e489aea99c0237ee75611325870983d3f5714f03d1fccb67bebd1` |
| TLSH | `T1B7A312C0ED1F4B54D65865391EFEB26EF907A11BCC9F28878D21DABF66414721C9081D` |
| SSDEEP | `3072:3n7EBUMKM1JlZSctHmPhnduaT3wWXi1BOsO:rqUMbZSctHmJomSOt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_1c39d5b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c39d5b7fd20f7d696ca4697abc07a3e08e73496975df0e37a5da0c956e8316c"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-10 00:45:58"
  condition:
    hash.sha256(0, filesize) == "1c39d5b7fd20f7d696ca4697abc07a3e08e73496975df0e37a5da0c956e8316c"
}
```

### Sample 61: `5528b5e88656593e`

| Field | Value |
|---|---|
| SHA-256 | `5528b5e88656593ef5c680980621855ef84389efd06fb441a01ff3b48d8bdeb9` |
| Family label | `PureCrypter` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-10 00:43:24` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX0.file, PureCrypter` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6077f50c2ccb6e4b9263222adcc223e` |
| SHA-1 | `53d00c1228f702931ff7b4e55cdb433858edd491` |
| SHA-256 | `5528b5e88656593ef5c680980621855ef84389efd06fb441a01ff3b48d8bdeb9` |
| SHA3-384 | `a51788cfde259943a3880b86bfffb3508fc7deb64fbe3cb905d5ab3dfb8e8c88b3a35cb1424e4399fa09ac88411626fd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15FC46D2B36928E21C2890733C1DB850093E69A4376A7EB6F35C513DA1D423FEDA47797` |
| SSDEEP | `12288:0nYdRAqcY92s5skUSab+xkyFcz7JgVEn/+k3JJQeUGIVfUjIs:nSGOnbDy1Va2UPQeUGS8` |

#### Technical Assessment

- The sample is tracked as `PureCrypter` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureCrypter_061_5528b5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5528b5e88656593ef5c680980621855ef84389efd06fb441a01ff3b48d8bdeb9"
    family = "PureCrypter"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-10 00:43:24"
  condition:
    hash.sha256(0, filesize) == "5528b5e88656593ef5c680980621855ef84389efd06fb441a01ff3b48d8bdeb9"
}
```

### Sample 62: `08ca823c1ce7029d`

| Field | Value |
|---|---|
| SHA-256 | `08ca823c1ce7029d93d1fe08f258358e145acbda7183d2e6a18c9b548f96162f` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-10 00:42:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a100fb55904e5e57d343d9c2997dd4f` |
| SHA-1 | `ca72c108c338e395d152acfdaabaa196619dc207` |
| SHA-256 | `08ca823c1ce7029d93d1fe08f258358e145acbda7183d2e6a18c9b548f96162f` |
| SHA3-384 | `bf1c39e7359491be6e4c9a662c81c9fb5216e968c5d58a517477f9cc23990aed7e04c41c20eea75e0ca0339af6c69d6e` |
| TLSH | `T1BB84F988E1E0E7DAD2D4AA75B319790E3B230735B0D73146A51DFE3223EB1590AFD921` |
| TELFHASH | `t1ebe0f1044e5cb2dd3270e59464ad58c4348e3a2d3f8850bb8956f87f4d017c319d3403` |
| SSDEEP | `6144:cch2ujWEQteXsK0ycNZK+8JHbH/P2IeIjhBtwsNs/Da4zrjFxa9UJ:BQKDcNZKhJ7fP2ITds/DFLa9UJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_08ca823c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08ca823c1ce7029d93d1fe08f258358e145acbda7183d2e6a18c9b548f96162f"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-10 00:42:56"
  condition:
    hash.sha256(0, filesize) == "08ca823c1ce7029d93d1fe08f258358e145acbda7183d2e6a18c9b548f96162f"
}
```

### Sample 63: `4c5be7e5b0ef0f73`

| Field | Value |
|---|---|
| SHA-256 | `4c5be7e5b0ef0f7380a3c19cdc60244cef11fa0fa7dad8aa9ac4b0bd4f11c03f` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-10 00:42:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88791e78363c5c0a91c7a63632f4a1ce` |
| SHA-1 | `cc1a6e0f52f1c5081ddc478df813756e05c83cdb` |
| SHA-256 | `4c5be7e5b0ef0f7380a3c19cdc60244cef11fa0fa7dad8aa9ac4b0bd4f11c03f` |
| SHA3-384 | `35750707886db0c1577c3baaa2fbe3ab81bdb7a3f3b0b91ef0fd6d6a0dfc8f686584cd30430bdc139bc0df4fbb3b2c2d` |
| TLSH | `T183842A88E2E3E2FEF155D97013267A1B5D3246373053F28AF39E697392B614045EEA34` |
| TELFHASH | `t1f661b515ce96189df3a386c02df3d22a85b8824fcf9e968147417c772c5ea80c4ade87` |
| SSDEEP | `6144:WmKE/wTHJJJCtlE/kWax4nwAzXNDbTk7jLPa9CoU:WtAwlJJCCwAzXNDbTinPa9CoU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_4c5be7e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c5be7e5b0ef0f7380a3c19cdc60244cef11fa0fa7dad8aa9ac4b0bd4f11c03f"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-10 00:42:54"
  condition:
    hash.sha256(0, filesize) == "4c5be7e5b0ef0f7380a3c19cdc60244cef11fa0fa7dad8aa9ac4b0bd4f11c03f"
}
```

### Sample 64: `1420553605f47000`

| Field | Value |
|---|---|
| SHA-256 | `1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860` |
| Family label | `unknown` |
| File name | `1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:40:52` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d7ce55f98cc7dfb26f9d95dad64cb19` |
| SHA-1 | `72eda5445ad949c71b2623794ccc906a1ee87128` |
| SHA-256 | `1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860` |
| SHA3-384 | `69d17be74a18e38cbf034a9093453a79235005212082f636efdca2e535802bef4331638697b369f5a170ea062b0db8b4` |
| IMPHASH | `d5b1104f7bf955d6b89a47291d5b603b` |
| TLSH | `T1840733A877451DA5F4FB023CA9D0CA22A2F1B5242B95D7EF0BF00D6219632D4DF787A1` |
| SSDEEP | `393216:+0L1F2aqgIfUKOc0XEAphVtnIwQSg+nFoIykzBvxvF7X2:Lpst58KP0RphDBo+FoIygBJvF7` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_14205536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860"
    family = "unknown"
    file_name = "1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:40:52"
  condition:
    hash.sha256(0, filesize) == "1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860"
}
```

### Sample 65: `c54847abf0244aa9`

| Field | Value |
|---|---|
| SHA-256 | `c54847abf0244aa9dbf6e84e6f38cafae01086a8f2f2c74a8c4ad12bdfd6c54f` |
| Family label | `AMOS` |
| File name | `macho_c54847abf024.bin` |
| File type | `macho` |
| First seen | `2026-10-10 00:39:47` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c2841fa2ff63e21db10ee36b12531a3` |
| SHA-1 | `0af41e69779e2af9c69e6e7a5582916c34ca3d8b` |
| SHA-256 | `c54847abf0244aa9dbf6e84e6f38cafae01086a8f2f2c74a8c4ad12bdfd6c54f` |
| SHA3-384 | `fb5a1bcf03ed6d236019ebdd16275a69375eea324bd2eaac9957b7fba62d562b561a45e26031fedf55454111a9057c13` |
| TLSH | `T1DB5502118F3680A6F1CCDB303B2A8DBF5E606170854F16DB27926A958D353E3E1A735B` |
| SSDEEP | `24576:0N5LuR8zJ6hJQ5pz01sSXxIn746adSpob1YhbgpJ7KhQYJNCfxGi6T:0PLuR8QhL1hCaSGKhHhDOq` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_065_c54847ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c54847abf0244aa9dbf6e84e6f38cafae01086a8f2f2c74a8c4ad12bdfd6c54f"
    family = "AMOS"
    file_name = "macho_c54847abf024.bin"
    file_type = "macho"
    first_seen = "2026-10-10 00:39:47"
  condition:
    hash.sha256(0, filesize) == "c54847abf0244aa9dbf6e84e6f38cafae01086a8f2f2c74a8c4ad12bdfd6c54f"
}
```

### Sample 66: `c0bbb9a64c6ce4ac`

| Field | Value |
|---|---|
| SHA-256 | `c0bbb9a64c6ce4ac41f8186090b159951401bcf596015dce95df91a40b11828d` |
| Family label | `unknown` |
| File name | `main.riscv32` |
| File type | `elf` |
| First seen | `2026-10-10 00:33:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d4a42e1e214d7c776544b58bd1e8191` |
| SHA-1 | `e23e20504704a259ea1f9e02011f79f9c2a3bfb3` |
| SHA-256 | `c0bbb9a64c6ce4ac41f8186090b159951401bcf596015dce95df91a40b11828d` |
| SHA3-384 | `db2923f45ff9750bcb9459da11d1d50160966e8d7f79731209d107265ee1d246eb6286f52bfe9ef0a4c1370802a92d90` |
| TLSH | `T1A7A35B42DD2B4751D3F207B05BE96B4292A16F2235D37344D498FA38F96D0F862C2EE9` |
| SSDEEP | `3072:9QYeRNwKhtYXMtdXBwJR9YwxZFQMszm4W:KHNRUXudeR9YwxZqMsz9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_c0bbb9a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0bbb9a64c6ce4ac41f8186090b159951401bcf596015dce95df91a40b11828d"
    family = "unknown"
    file_name = "main.riscv32"
    file_type = "elf"
    first_seen = "2026-10-10 00:33:51"
  condition:
    hash.sha256(0, filesize) == "c0bbb9a64c6ce4ac41f8186090b159951401bcf596015dce95df91a40b11828d"
}
```

### Sample 67: `79e4ed8b30063eb0`

| Field | Value |
|---|---|
| SHA-256 | `79e4ed8b30063eb079c168ba82698f3d5fde70b973ebd5258c0272b88a0e0502` |
| Family label | `unknown` |
| File name | `main.mips32el` |
| File type | `elf` |
| First seen | `2026-10-10 00:33:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f95a4ae0d8096de444b22b01de7d55b5` |
| SHA-1 | `2584205160c87b955cbe9e07a94b6809e9d064d5` |
| SHA-256 | `79e4ed8b30063eb079c168ba82698f3d5fde70b973ebd5258c0272b88a0e0502` |
| SHA3-384 | `fc81a8300e9c088b9288f22629f36d5931144a42d653b25eb6665b4a727dc28decd134b01984f56129193f6ca0da01ec` |
| TLSH | `T136D30902ED816EF7C41EDD70452DC24A15D65CBA82F9922F71F8C98CBBBD70946E7888` |
| SSDEEP | `1536:KJL7iUfpGd483sqcd7sz2m9coyB3t1oIwN1Dhu34qn0bcdy1q5oWX2bAR7XLQErd:KF7lfpGSr7sz2mEt10cFxdy8uiUI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_79e4ed8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79e4ed8b30063eb079c168ba82698f3d5fde70b973ebd5258c0272b88a0e0502"
    family = "unknown"
    file_name = "main.mips32el"
    file_type = "elf"
    first_seen = "2026-10-10 00:33:48"
  condition:
    hash.sha256(0, filesize) == "79e4ed8b30063eb079c168ba82698f3d5fde70b973ebd5258c0272b88a0e0502"
}
```

### Sample 68: `bc3f5476149b3dfa`

| Field | Value |
|---|---|
| SHA-256 | `bc3f5476149b3dfa8e52e76fe1e252316bd2a9c0e5ddddc585cfb4def12fb89f` |
| Family label | `unknown` |
| File name | `main.e6500` |
| File type | `elf` |
| First seen | `2026-10-10 00:33:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e62db7774da2d415f2e6abf05655414a` |
| SHA-1 | `97550772a305ce59f52e9769726daa12b33210c8` |
| SHA-256 | `bc3f5476149b3dfa8e52e76fe1e252316bd2a9c0e5ddddc585cfb4def12fb89f` |
| SHA3-384 | `503f6e87719edc074a5d4e477f419e15d93a4aa7fced6ed294d0dbc6ac4d780977d53064a5f50e0f198cad18124ff979` |
| TLSH | `T114D32B51EF0CA80BC5756635A5372799F3A0B8D12170C91277052B6F2AF7232ACCBF5A` |
| SSDEEP | `3072:fRzi9nhWl12rChRpNqtGA2q2VCOcboQMNItzZ02:fRzqWSrHGrq2VTcGSa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_bc3f5476
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc3f5476149b3dfa8e52e76fe1e252316bd2a9c0e5ddddc585cfb4def12fb89f"
    family = "unknown"
    file_name = "main.e6500"
    file_type = "elf"
    first_seen = "2026-10-10 00:33:46"
  condition:
    hash.sha256(0, filesize) == "bc3f5476149b3dfa8e52e76fe1e252316bd2a9c0e5ddddc585cfb4def12fb89f"
}
```

### Sample 69: `54f9211ce2133537`

| Field | Value |
|---|---|
| SHA-256 | `54f9211ce2133537769fa2759e3a1ce2c2295eb561ed98b7b04777221ccf085d` |
| Family label | `Mirai` |
| File name | `mipsrouter` |
| File type | `elf` |
| First seen | `2026-10-10 00:31:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06503bc69a311fba592d8154d66ce305` |
| SHA-1 | `05e4d8ce50dcd82936c4db6736035e348a5577ba` |
| SHA-256 | `54f9211ce2133537769fa2759e3a1ce2c2295eb561ed98b7b04777221ccf085d` |
| SHA3-384 | `4838fac4b1e065ad4ec7c183461445f76fdf9c99e19343de61b3f1caeb790bddcc80b6d5f53d4094e9236a9cbb976b73` |
| TLSH | `T19064F80A3A329F7EF2698B7147F74F30979962D61BE2D684E1ACD5101F1038D681FB68` |
| TELFHASH | `t1cc813f55943d09e9af239c19a8a86bb34957e52a22d6bf29ff16ccc8044e42df118d0f` |
| SSDEEP | `6144:WlwqV568w8qaoUc7zqFYX5060BvxeyKVGFmqliS6LrP1rt2NVKJYHaICzRedd/Vb:WlxkdzqFYp060JxeyKVPrXKKJYHaICzi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_54f9211c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54f9211ce2133537769fa2759e3a1ce2c2295eb561ed98b7b04777221ccf085d"
    family = "Mirai"
    file_name = "mipsrouter"
    file_type = "elf"
    first_seen = "2026-10-10 00:31:24"
  condition:
    hash.sha256(0, filesize) == "54f9211ce2133537769fa2759e3a1ce2c2295eb561ed98b7b04777221ccf085d"
}
```

### Sample 70: `b1ca24b5a9b26c6f`

| Field | Value |
|---|---|
| SHA-256 | `b1ca24b5a9b26c6ff2f34d0063d18b86b362c1216ac1b8c982acfee884c3ba20` |
| Family label | `unknown` |
| File name | `eclipse.sh` |
| File type | `sh` |
| First seen | `2026-10-10 00:30:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56e1a90307b5ca7f4349475bef7409cf` |
| SHA-1 | `072aa5e9c54b23de985fed248002a492cd01e18a` |
| SHA-256 | `b1ca24b5a9b26c6ff2f34d0063d18b86b362c1216ac1b8c982acfee884c3ba20` |
| SHA3-384 | `380ebe37b625730c8ea0786d122bedadb70d9d3f9009129e766976a4be5f374853f3d3c917c930b0361bb565221ceca3` |
| TLSH | `T18DD0A7E560A4C5B57C9C6C29705E0072B6C148AF75CEBC0CC5E23CA6C89EC496049A67` |
| SSDEEP | `6:h9OnFflR0zfWxqG7bIgSUbQlaFLg5fWxqG7bIgSX0lBFpQeSV:Jf8qKOCxFM5f8qKOXMzY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_b1ca24b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1ca24b5a9b26c6ff2f34d0063d18b86b362c1216ac1b8c982acfee884c3ba20"
    family = "unknown"
    file_name = "eclipse.sh"
    file_type = "sh"
    first_seen = "2026-10-10 00:30:59"
  condition:
    hash.sha256(0, filesize) == "b1ca24b5a9b26c6ff2f34d0063d18b86b362c1216ac1b8c982acfee884c3ba20"
}
```

### Sample 71: `b0b2af0d3f774245`

| Field | Value |
|---|---|
| SHA-256 | `b0b2af0d3f774245eb60ec64e200cd2f178f9efd18c945a64010534e9f75241a` |
| Family label | `Mirai` |
| File name | `mipsrouter` |
| File type | `elf` |
| First seen | `2026-10-10 00:30:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c511ee662ff9dc7e835e1cf9f1cbb8d` |
| SHA-1 | `7b08e614ec0ac0f292d6c5a3bc24834e492a89f8` |
| SHA-256 | `b0b2af0d3f774245eb60ec64e200cd2f178f9efd18c945a64010534e9f75241a` |
| SHA3-384 | `152eae33898437ef8b18728743805c2d20865907340f9b4b45ee2ebad6f46b7e1221b7fc5fe23c17c0f7b5c3f7db180b` |
| TLSH | `T142A3127DC31219A8F89588BBA7984751281C4BA85C02EE255F76B781CC0CDCE6C9B3FC` |
| SSDEEP | `3072:E6SlN+Nqc+QqyAogxTPGr9SaoVQwD+nrAUr:E6SOqwD8TPGhS5QkV6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_b0b2af0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0b2af0d3f774245eb60ec64e200cd2f178f9efd18c945a64010534e9f75241a"
    family = "Mirai"
    file_name = "mipsrouter"
    file_type = "elf"
    first_seen = "2026-10-10 00:30:54"
  condition:
    hash.sha256(0, filesize) == "b0b2af0d3f774245eb60ec64e200cd2f178f9efd18c945a64010534e9f75241a"
}
```

### Sample 72: `61df29da73da82fc`

| Field | Value |
|---|---|
| SHA-256 | `61df29da73da82fc5c767946804189d1d94c105dd54b01ec786202e9b451bbc4` |
| Family label | `Mirai` |
| File name | `main.armv5-eabi` |
| File type | `elf` |
| First seen | `2026-10-10 00:24:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `128f22044e08c0fa19ca14598ea7a00d` |
| SHA-1 | `eec3cb683a04bdba1ae012e0d49d0c9a10c6d9c6` |
| SHA-256 | `61df29da73da82fc5c767946804189d1d94c105dd54b01ec786202e9b451bbc4` |
| SHA3-384 | `dd06fc2574e7aa3ff51154032fffeaf2886e7936d1349d7c5147e136fc60b759fe26959c37c4152d7bb81d1840bbb847` |
| TLSH | `T12A630999F8409735CBC075BAFA1D02DD33130FA8E2EA71158D35AB353BE7A194A3B542` |
| SSDEEP | `1536:R1GhlBxnQ4NGzgFgZNFMmFNGX6TWRlnJUwPoVn6A+d8kTNlL3zwLOYh0r:RQmtQon6A+dR3M3u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_61df29da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61df29da73da82fc5c767946804189d1d94c105dd54b01ec786202e9b451bbc4"
    family = "Mirai"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-10-10 00:24:54"
  condition:
    hash.sha256(0, filesize) == "61df29da73da82fc5c767946804189d1d94c105dd54b01ec786202e9b451bbc4"
}
```

### Sample 73: `e9f628ffa4e6acc0`

| Field | Value |
|---|---|
| SHA-256 | `e9f628ffa4e6acc0c7e0aae334d0bacb4235d0fdab513051d0a14c94b079121a` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-10-10 00:22:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b0a82cc59373dbc60716aa5ade1f882` |
| SHA-1 | `b0c6d3e5ce87e85ae51b595fbf7d51d781b51627` |
| SHA-256 | `e9f628ffa4e6acc0c7e0aae334d0bacb4235d0fdab513051d0a14c94b079121a` |
| SHA3-384 | `ea415a086de64a24a65b353f8a667be884f87c7d44d35af1a1d9adcaab1e226bb67172f7540e8edaf3a0d2de8703b7af` |
| TLSH | `T12C142B46AB809606C4FF1E76B61D0B89B326477CCBE7B2A1FC64DF3466CA5058E27503` |
| TELFHASH | `t186d0c2685bcc163cb2828085c029467a06a336601389318ccf099b2e1e03cd3382a833` |
| SSDEEP | `3072:u0L/n2pw9WZvrhG/Xt2zO2yZNiar1xLh3gif6hCMPtBRrDW7R6wr7H:u0Liw0TTzyNiar1xLRnhWtBRry7R6w3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_e9f628ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9f628ffa4e6acc0c7e0aae334d0bacb4235d0fdab513051d0a14c94b079121a"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-10-10 00:22:34"
  condition:
    hash.sha256(0, filesize) == "e9f628ffa4e6acc0c7e0aae334d0bacb4235d0fdab513051d0a14c94b079121a"
}
```

### Sample 74: `00fec85c279bcbc1`

| Field | Value |
|---|---|
| SHA-256 | `00fec85c279bcbc15134e4c3a82564ecb08764639e23cbb199233da09ea241d3` |
| Family label | `unknown` |
| File name | `main.e500mc` |
| File type | `elf` |
| First seen | `2026-10-10 00:21:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50e5b53134c43ee4e5b70e9e5add3871` |
| SHA-1 | `93e7fa8dfe03725e50723ec1cdd630f3ccb86913` |
| SHA-256 | `00fec85c279bcbc15134e4c3a82564ecb08764639e23cbb199233da09ea241d3` |
| SHA3-384 | `b3024c667bbbdbd6115d7ee30a94004e1301d6da030239b907ad62b759be9fe44cf78361aa44bc0aaeed89b7b5b99150` |
| TLSH | `T196D31A57FF0C4413C48369781E3B07EDF320BE5150B99516230A6A6F3BB2E326687B99` |
| SSDEEP | `1536:sEV3NVs96f5agl+1Q7FNX5EtWysyGyGyXz3e0+dNfAl6bu8rnQ:sEV3Nm9o5aglZ5NX7ysyGyjKywyUnQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_00fec85c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00fec85c279bcbc15134e4c3a82564ecb08764639e23cbb199233da09ea241d3"
    family = "unknown"
    file_name = "main.e500mc"
    file_type = "elf"
    first_seen = "2026-10-10 00:21:50"
  condition:
    hash.sha256(0, filesize) == "00fec85c279bcbc15134e4c3a82564ecb08764639e23cbb199233da09ea241d3"
}
```

### Sample 75: `52ded2b6af6c6493`

| Field | Value |
|---|---|
| SHA-256 | `52ded2b6af6c64932216537a1533a2961f3a621b9ffd51a20b64241f71fff2a8` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-10-10 00:21:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7049ae36cc6ed6c4d30ebe57a5ad535` |
| SHA-1 | `99ff4a4950f6f0617d1942b480690f7cbe4eefc1` |
| SHA-256 | `52ded2b6af6c64932216537a1533a2961f3a621b9ffd51a20b64241f71fff2a8` |
| SHA3-384 | `2b61b6c05ad4dc17bbc5aafbd9f46cb459e2eb0447ad8c49148bc44b9f3d03a53d4f9e5717ece11fecb4d7eaddfa48db` |
| TLSH | `T1D4631223192CDD61CDE08673EC0CDAC34A906AB6B571B5222F06CE9B04E355A32FE577` |
| SSDEEP | `1536:6OahfMA1k/WhKZE+w3IyvLcpZwqfcUks0QvKxE:SfvJwZEjvQE82Pq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_52ded2b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52ded2b6af6c64932216537a1533a2961f3a621b9ffd51a20b64241f71fff2a8"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-10-10 00:21:48"
  condition:
    hash.sha256(0, filesize) == "52ded2b6af6c64932216537a1533a2961f3a621b9ffd51a20b64241f71fff2a8"
}
```

### Sample 76: `72ee7b86e6159bf1`

| Field | Value |
|---|---|
| SHA-256 | `72ee7b86e6159bf19c1f9f19b9e3eb02d0cf7eb93c93ab39eef7014439ba7c92` |
| Family label | `Mirai` |
| File name | `main.sparc64` |
| File type | `elf` |
| First seen | `2026-10-10 00:18:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b38c3c3504a34073e6c66ecbc1b7521e` |
| SHA-1 | `4f807e865808831b2ba645cb36a61ae5b8512275` |
| SHA-256 | `72ee7b86e6159bf19c1f9f19b9e3eb02d0cf7eb93c93ab39eef7014439ba7c92` |
| SHA3-384 | `fd72e7717631a67bb608aecce27c7f31ca16923d0ba37c11c61eacbe3280f5e5c14d8e4fe47a310600a933630832129d` |
| TLSH | `T12D25AF523BF61860D64056358FE2D321B20ADBB974E54A479F508EEFDF032651E82CFA` |
| SSDEEP | `12288:ifNZdwo/DROzcv+AyTpN+8e6Rk1KX1lSDa5dCYyqU:IJwqOZL+TKXWy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_72ee7b86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72ee7b86e6159bf19c1f9f19b9e3eb02d0cf7eb93c93ab39eef7014439ba7c92"
    family = "Mirai"
    file_name = "main.sparc64"
    file_type = "elf"
    first_seen = "2026-10-10 00:18:48"
  condition:
    hash.sha256(0, filesize) == "72ee7b86e6159bf19c1f9f19b9e3eb02d0cf7eb93c93ab39eef7014439ba7c92"
}
```

### Sample 77: `b9b365c9df55864e`

| Field | Value |
|---|---|
| SHA-256 | `b9b365c9df55864e1426e864e60f9420257c1b451146451d67108d16ff5892fc` |
| Family label | `Mirai` |
| File name | `main.armv7l` |
| File type | `elf` |
| First seen | `2026-10-10 00:18:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a66f670758cd0c08a10df5d4eea8d5a` |
| SHA-1 | `b01d959def63ee8eb8b1a6f1b33b93d11a8c1ba4` |
| SHA-256 | `b9b365c9df55864e1426e864e60f9420257c1b451146451d67108d16ff5892fc` |
| SHA3-384 | `b1f2d51f468ce209ed3d3559b92c0b25d5588efe87c06535b6f945a76c97e0e0087ebd508f29bf081653be04bbd88d2f` |
| TLSH | `T1C553F849FA51AB05C9D232FAFB8E414E33176FA8E7F931219D305F9023C6ADB0A75521` |
| SSDEEP | `1536:URnS/6KhC4CzDMfN+fr+ti1KYyaXEEGlLyhDicbKYlPmZr:F/CzDMF+fr+ti1KYLBFbK0Pur` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_b9b365c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9b365c9df55864e1426e864e60f9420257c1b451146451d67108d16ff5892fc"
    family = "Mirai"
    file_name = "main.armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 00:18:46"
  condition:
    hash.sha256(0, filesize) == "b9b365c9df55864e1426e864e60f9420257c1b451146451d67108d16ff5892fc"
}
```

### Sample 78: `34e7bb86115ed921`

| Field | Value |
|---|---|
| SHA-256 | `34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff` |
| Family label | `Mirai` |
| File name | `34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:18:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48791c03d379bfe2fcef85f0479369d9` |
| SHA-1 | `6c1788dee6e6f49fce91e945641d04314211c5ad` |
| SHA-256 | `34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff` |
| SHA3-384 | `8e1bf36c4bcb3e21a52fcb086374f9e9e85d9cb3a47e6560b04103baa519884a12e8feee607100e77259523d5122ecbb` |
| TLSH | `T1A2A3AE02CD605CACE02A6EB210F58ABA4B23A545551B6EFB3847C2751047FD8F5AF7B8` |
| SSDEEP | `1536:iWI1sIZ7rqmGMF1usMMf5/ez+MKlJ3KtThLch8CjWkYY7Okfx8xR7:iWI1sIZ7e6F1usz5cmStCh8TkLqkfxm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_34e7bb86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff"
    family = "Mirai"
    file_name = "34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:18:04"
  condition:
    hash.sha256(0, filesize) == "34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff"
}
```

### Sample 79: `8d4fb5f3f54d19f3`

| Field | Value |
|---|---|
| SHA-256 | `8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb` |
| Family label | `Mirai` |
| File name | `8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:17:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84c1e24e72fef751bb77bb1d61ecf9fc` |
| SHA-1 | `17d37b336539c4fa000afbd970954102d632de07` |
| SHA-256 | `8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb` |
| SHA3-384 | `fc66deba63ce48f7906b0bf3932bdc8995dbceecf314e5c5286f415693dddc8931eaba193794efa0ba3558deca37c4ce` |
| TLSH | `T1F8D3D94F7E639F6DF36C82344BB78B25A755239233A0C585D2ACEA005E6034D58AFF94` |
| TELFHASH | `t1ef1158088d3852f497b51c9d6bedef71e4a170df06255e378d40fdaaaa2dd419e01c2c` |
| SSDEEP | `1536:jS5TjeZ2xWy3nqGSqGHTGSF7OU2w8izmhg/dzvNWLJVoxApeadx+Eyfx8xR+T:eteZE32P38i1/FNWL32FEyfxbT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_8d4fb5f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb"
    family = "Mirai"
    file_name = "8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:17:59"
  condition:
    hash.sha256(0, filesize) == "8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb"
}
```

### Sample 80: `9d294361a6c61ce1`

| Field | Value |
|---|---|
| SHA-256 | `9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7` |
| Family label | `Mirai` |
| File name | `9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:17:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6774e22f307601ab6c09f8ce7311976b` |
| SHA-1 | `0de87b750128c3c26b66e022af0e9b851e1a6382` |
| SHA-256 | `9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7` |
| SHA3-384 | `9d68f2e76ac017cfae71421a8949b939bf632d09a5c7f4278deff436808847f1b7b0d6db1b762f9d78a024f1b92c6203` |
| TLSH | `T154D3290ABFB15EFBD46FCD3341B94709299C190622A92B7A3574D81CF21B28F5AD3C64` |
| SSDEEP | `1536:uKzFAY3BexA59j3mVHi9lptfLxNlQ1mo/Xd4b8ERV5fMoO95aqyhAexHrWlHoVvx:uG/Si9lptfPr59vyJZggUkF28dfx0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_9d294361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7"
    family = "Mirai"
    file_name = "9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:17:09"
  condition:
    hash.sha256(0, filesize) == "9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7"
}
```

### Sample 81: `bb48f3d7057d2675`

| Field | Value |
|---|---|
| SHA-256 | `bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95` |
| Family label | `Mirai` |
| File name | `bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:17:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e34251778eb811e518a7693068d7c9cc` |
| SHA-1 | `bf7b4ffde5257be097d14eb4987f422a9290d2c2` |
| SHA-256 | `bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95` |
| SHA3-384 | `b763717f5f03e78cbf7cf3cc26e51b6cea46925cb9b4013e23710a5f671db3752599d36bcd9821de25f4945d972ed468` |
| TLSH | `T110B33BA7B400EC7EF80FD6B7C0570A16B520A3A54F522B27B216F963DE7D0A45C27E46` |
| SSDEEP | `3072:7Mk3HjRBnFVNSjufgPxMWkxRkExrG6fA4ecI6jIV4:77BnHcjs0kQOrGaAT6g4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_bb48f3d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95"
    family = "Mirai"
    file_name = "bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:17:04"
  condition:
    hash.sha256(0, filesize) == "bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95"
}
```

### Sample 82: `79f387555290301b`

| Field | Value |
|---|---|
| SHA-256 | `79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d` |
| Family label | `Mirai` |
| File name | `79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:16:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7db3992114f01081facc2e0e7f560e64` |
| SHA-1 | `58b4d4ccbdd06978449dd331a788ceb2bccdbfdb` |
| SHA-256 | `79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d` |
| SHA3-384 | `2926ec45782bd73be21c2c6f057a37eb9a06f57f4de3b1ebc9128dd56644a0dc021601be482095a7af7ae05e3242a5f3` |
| TLSH | `T137935B85D743D4FAEC49053C7077F3379272D9B90128FEE2F754AB726826A60610EA8D` |
| TELFHASH | `t1d9312bf9a66608e89bd09c02f30e1b60bc4ca77b256037b309f378343152981623bc3d` |
| SSDEEP | `1536:89MSyNvxzxV8Tzzp6+9Cm6Laro4BcqmZhlJPFb46o80BoR4H6Q/QRy:+lULV8nzp6+LLHyj/P263ioMJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_79f38755
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d"
    family = "Mirai"
    file_name = "79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:16:55"
  condition:
    hash.sha256(0, filesize) == "79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d"
}
```

### Sample 83: `d297ec1d8c823a65`

| Field | Value |
|---|---|
| SHA-256 | `d297ec1d8c823a65e341bec0ce462f05770684af0d62b87544dbf24ae48c6726` |
| Family label | `unknown` |
| File name | `694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:16:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cabe56ec7f6a1273c222fcb8a8d826d5` |
| SHA-1 | `cad533c7c423b6133fff239ddd9e06d728039a23` |
| SHA-256 | `d297ec1d8c823a65e341bec0ce462f05770684af0d62b87544dbf24ae48c6726` |
| SHA3-384 | `d458c91c684e46277d3edc512f65b6e34261f2f22dac6dcb0e5de86da7f1cb08ceb6375042ec3f7d8ca674441a65653a` |
| IMPHASH | `676d224d82f2a2594223d43c3d79b531` |
| TLSH | `T113F49E01B6C1C0F1D774193115AA7737AA7AEA570B14CFE3A394DE6D6D32280E93723A` |
| SSDEEP | `6144:g1ELpWP6CMO1sx3lQJriR/3CpVOxZyfGjpnLiSRXbAgu1QMw6f+6ssSHEUbbPVmU:g1EiL3mR/3CpYxMJ9uMzh0PVctDyeh` |
| ICON-DHASH | `d0d4064606ccc8e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_d297ec1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d297ec1d8c823a65e341bec0ce462f05770684af0d62b87544dbf24ae48c6726"
    family = "unknown"
    file_name = "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:16:40"
  condition:
    hash.sha256(0, filesize) == "d297ec1d8c823a65e341bec0ce462f05770684af0d62b87544dbf24ae48c6726"
}
```

### Sample 84: `e74195b041ab104a`

| Field | Value |
|---|---|
| SHA-256 | `e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6` |
| Family label | `unknown` |
| File name | `e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:16:09` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c347fc55b06f34a2f98d24e6e55ea13f` |
| SHA-1 | `268e3a9c2a79cf74b98f6cbbbb34cebda43a844b` |
| SHA-256 | `e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6` |
| SHA3-384 | `370f37d580ff133aa859dcbf5b2f562c9d9de5322850847939f2be14e16ff925b73ff9485c55053016d3ae1ac38121ab` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T170B5E03BB28B653EF06E5A357A73E214453BAA5165138C16D7E4C84CCF2A0B01E3F697` |
| SSDEEP | `24576:XXfPki0RBC19GXIV7GlXR6GVUIN0TCC7ZIxmmf01zs2y+gdp4SvMI9V7x4kKzOcC:BoOGlvVztZc5sgaMknKy3Y/61Ysme` |
| ICON-DHASH | `71f0a4a6268ecc61` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_e74195b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6"
    family = "unknown"
    file_name = "e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:16:09"
  condition:
    hash.sha256(0, filesize) == "e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6"
}
```

### Sample 85: `6e7b99771c824f44`

| Field | Value |
|---|---|
| SHA-256 | `6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173` |
| Family label | `unknown` |
| File name | `6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:16:01` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a496677d883acee77927d2361178495` |
| SHA-1 | `7598fbe29ff797180fd864e2df04bb9d1ac2f40f` |
| SHA-256 | `6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173` |
| SHA3-384 | `61224db89ccaaf970ac9aa8e0c306086fcc7a9eed367b40b921eb171b361291d0f40d2d5f3755038c61f5bcde22b2ffc` |
| IMPHASH | `3dbfd5036417dcb24384e0c523debbb5` |
| TLSH | `T12A355C33B2811C3BC022963A086757A0597FBD296EB6684B1EF47D4E4E362412F3F657` |
| SSDEEP | `24576:Uqw9lscsR92cPq0PB7S4kDbrY7ulpiCTXgPZ:t5N9SvY7ulRTXgh` |
| ICON-DHASH | `82d2b031f0e0e082` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_6e7b9977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173"
    family = "unknown"
    file_name = "6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:16:01"
  condition:
    hash.sha256(0, filesize) == "6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173"
}
```

### Sample 86: `694de315e03b651f`

| Field | Value |
|---|---|
| SHA-256 | `694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768` |
| Family label | `unknown` |
| File name | `694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:15:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c3561ae34697a2be570709a013adbb8` |
| SHA-1 | `8e22fe23694188944c2eb57537508ab6f46402be` |
| SHA-256 | `694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768` |
| SHA3-384 | `3b1ba96449330d6e9c84466b06de720ba79895914a7ae4a6928c138642e5c7e7667e6fb8f86a27fef8adbe603e936030` |
| IMPHASH | `fc4211025d2823f78625f41e8016b470` |
| TLSH | `T10A6412BEA3349526D01D0D3446C7C7B8AA296C538E258B0F9CB97F2F39B57443E5A48C` |
| SSDEEP | `6144:2RxsrpKgUNcwihRDBRpdIS6JeTnp9hdzQ8K2fEbD0FzF/fH:CUoejhRt6SQeTpD7K28f0pFn` |
| ICON-DHASH | `d0d4064606ccc8e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_694de315
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768"
    family = "unknown"
    file_name = "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:15:56"
  condition:
    hash.sha256(0, filesize) == "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768"
}
```

### Sample 87: `ffda934a9acd3bdf`

| Field | Value |
|---|---|
| SHA-256 | `ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540` |
| Family label | `Babadeda` |
| File name | `ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:15:51` |
| Reporter | `Tuxxin` |
| Tags | `Babadeda, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2ab98b7da779932e8fa25a279e59a8c` |
| SHA-1 | `619d11577b3ae4fb569856b132a4220ac4651489` |
| SHA-256 | `ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540` |
| SHA3-384 | `1d97a569d1a7abd5bcc9c1ee6eda021f6c1e5ce3f7906dedb8a7c5c5e3ba5fba81051679f1816747bcf6509dbafc9908` |
| IMPHASH | `5877688b4859ffd051f6be3b8e0cd533` |
| TLSH | `T12BC3AF45B3D241F7EAE10A7100A6716FE73663249724E8DBC34C3C929A53AD49A7C3F9` |
| SSDEEP | `3072:Eq6+ouCpk2mpcWJ0r+QNTBfAZKhp1MmcelXV:Eldk1cWQRNTBIZWPMmciV` |

#### Technical Assessment

- The sample is tracked as `Babadeda` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Babadeda_087_ffda934a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540"
    family = "Babadeda"
    file_name = "ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:15:51"
  condition:
    hash.sha256(0, filesize) == "ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540"
}
```

### Sample 88: `73cf6e88333ec08a`

| Field | Value |
|---|---|
| SHA-256 | `73cf6e88333ec08a93f1fad093478624d311070762576f8185a0371cb5c71d4c` |
| Family label | `Mirai` |
| File name | `main.armv7-eabihf` |
| File type | `elf` |
| First seen | `2026-10-10 00:15:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5d40fd355cfada0491cc57eb045389d` |
| SHA-1 | `a8d380a38d16222a2b1d89c718ed2ebae5381f26` |
| SHA-256 | `73cf6e88333ec08a93f1fad093478624d311070762576f8185a0371cb5c71d4c` |
| SHA3-384 | `97f905625b78a606c817a1c9c164159844982735d0bb21a4e2f790999afa43660bc0075b2efd2557bcf5a3d2c8475a26` |
| TLSH | `T1BC530A98F880D675CFD075BAF61D03DD73120FA8E2DA71118E219A353BE79194E3B942` |
| SSDEEP | `1536:NmSrLH0CFgSNHQCFjPN+Wgd3Iih9OtLHryQBz7xp+ySLwU1Z0r:N8vD9OtLHryQ/pZw1m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_73cf6e88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73cf6e88333ec08a93f1fad093478624d311070762576f8185a0371cb5c71d4c"
    family = "Mirai"
    file_name = "main.armv7-eabihf"
    file_type = "elf"
    first_seen = "2026-10-10 00:15:44"
  condition:
    hash.sha256(0, filesize) == "73cf6e88333ec08a93f1fad093478624d311070762576f8185a0371cb5c71d4c"
}
```

### Sample 89: `9eb445c9713aaa47`

| Field | Value |
|---|---|
| SHA-256 | `9eb445c9713aaa47cdcde4a44ee62fc6ace4bde23c240be047cc579f65d84cc1` |
| Family label | `unknown` |
| File name | `main.sparc` |
| File type | `elf` |
| First seen | `2026-10-10 00:15:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46ed69bf6918098855c83eba9afa4c86` |
| SHA-1 | `b10cb27b55b9fc317ce7a26fe76f7699d62f12db` |
| SHA-256 | `9eb445c9713aaa47cdcde4a44ee62fc6ace4bde23c240be047cc579f65d84cc1` |
| SHA3-384 | `9f54c3ba977d74927cb6c7cca82e69cdb181eb044691215ce0a7afcc1cfbb418e325c50ff454a3c784f9f3549386df23` |
| TLSH | `T15C43E86727230D23C0D6517592E34332B6FADB4628B88A5778A0AEDD5F185E032533FE` |
| SSDEEP | `768:9TsgmsdopxFdlP8Zm376+PdoeRKuck+EO+CrG5wN0t1ODj7yC:tO37pRKSL2N0t1ODj7yC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_9eb445c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb445c9713aaa47cdcde4a44ee62fc6ace4bde23c240be047cc579f65d84cc1"
    family = "unknown"
    file_name = "main.sparc"
    file_type = "elf"
    first_seen = "2026-10-10 00:15:42"
  condition:
    hash.sha256(0, filesize) == "9eb445c9713aaa47cdcde4a44ee62fc6ace4bde23c240be047cc579f65d84cc1"
}
```

### Sample 90: `cd7cf89608d3cccd`

| Field | Value |
|---|---|
| SHA-256 | `cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773` |
| Family label | `unknown` |
| File name | `cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:12:13` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95837df8829d551c99eb0eb84e8d5fed` |
| SHA-1 | `b046a3dda448f4a3b1d1bad281ee7abe9758d55e` |
| SHA-256 | `cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773` |
| SHA3-384 | `1e358c220704955c2cffde1fe465df0ecc35afe74ed427819111ea299ec17e5336792a5dfbac99675aa81464ce76bfd5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14685330E27A19525D4BE42B4AFAADF720A35D05C0F70D3461ECB11FCB919B38B85BE91` |
| SSDEEP | `49152:mAxgG2UEvuJLpeJG1yJU+E5Zu2vO+ZRmtorMFlpxq4:BxZ1FTte3+ZUtoETxz` |
| ICON-DHASH | `b28e6de9b3974cb2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_cd7cf896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773"
    family = "unknown"
    file_name = "cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:12:13"
  condition:
    hash.sha256(0, filesize) == "cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773"
}
```

### Sample 91: `1a7ba4e6b2691f9c`

| Field | Value |
|---|---|
| SHA-256 | `1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec` |
| Family label | `unknown` |
| File name | `1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:12:08` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d5944ce9ef4249c031d243ad7552b9c` |
| SHA-1 | `dc12be2b755de115a6e8421bf876ea04ff636542` |
| SHA-256 | `1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec` |
| SHA3-384 | `91a394c031c5c537a0d04a21f5fc050476f8c10c6bfb7c4b7cf0b5f02230cc9b8a6946e5d9c34268cb7375c9373e358f` |
| IMPHASH | `a29f49d8257b1b8574c219c7d406e104` |
| TLSH | `T183D64B53F66180E9C0AFC1B8835AA533EB72B88D093472AF5BD44B212F26F506F1D759` |
| SSDEEP | `98304:77uMCHJWoY4IRP4yWcx9vY9A5/Io8RJSZ7D5J+02C7aSc0rgyLjYm1lCY0qjEiPs:5oYBkzJQd2DUrzLDlC4fMg` |
| ICON-DHASH | `dc2e31cf0e1c66da` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_1a7ba4e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec"
    family = "unknown"
    file_name = "1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:12:08"
  condition:
    hash.sha256(0, filesize) == "1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec"
}
```

### Sample 92: `35b15d6c1af38f79`

| Field | Value |
|---|---|
| SHA-256 | `35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1` |
| Family label | `VShell` |
| File name | `35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:12:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d98562f29a6e4197c43d1db35192118` |
| SHA-1 | `43f4a114f561f14674e41819a6343ae15f17668d` |
| SHA-256 | `35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1` |
| SHA3-384 | `8005c0f23d7da36ad2c96c275556dedd917cfd848996948f5a53266e7f6de7116c93a27299da85556c1819dbbdf977e6` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12791C64270B989E7E85C81BF4C0FB8A4B91D740A41C483A74378A5953E3A57BF57CB0D` |
| SSDEEP | `48:6IIF9BlQaexxpgZ07An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMed0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_092_35b15d6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1"
    family = "VShell"
    file_name = "35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:12:01"
  condition:
    hash.sha256(0, filesize) == "35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1"
}
```

### Sample 93: `becef815900330a0`

| Field | Value |
|---|---|
| SHA-256 | `becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2` |
| Family label | `RuRAT` |
| File name | `becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2.msi` |
| File type | `msi` |
| First seen | `2026-10-10 00:11:56` |
| Reporter | `Tuxxin` |
| Tags | `msi, RuRAT, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1ae811c82f2ecc7d3ca7cb7fbbcd13b` |
| SHA-1 | `ff49a673aac7c53a31e5aec7c6ea3f6aac010b05` |
| SHA-256 | `becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2` |
| SHA3-384 | `771ac7e64d45b9a488513bc0bcfca574c097150db79768375ffee2a6b4c4b901d0bf361f4efa3130975d403eedbfcbfc` |
| TLSH | `T194672382F6804036DA67163256FADE38487DFC705F6123CF27D872396E728C15A3A65B` |
| SSDEEP | `393216:zY8phN9mDlEYxIqwFsRkwSasMPqwwVSelRz75HcV9WvSmnl5fIAtqPsvXCY8ryyB:zRiEQIqwFJ1aoHjRl8HWvnsAtM` |

#### Technical Assessment

- The sample is tracked as `RuRAT` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RuRAT_093_becef815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2"
    family = "RuRAT"
    file_name = "becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2.msi"
    file_type = "msi"
    first_seen = "2026-10-10 00:11:56"
  condition:
    hash.sha256(0, filesize) == "becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2"
}
```

### Sample 94: `b8d04987bf3df3be`

| Field | Value |
|---|---|
| SHA-256 | `b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52` |
| Family label | `Mirai` |
| File name | `b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:11:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3b4060c62400eb9260e8af470c08b02` |
| SHA-1 | `011f77e3030cf40d3e7e7616d68284401b760a16` |
| SHA-256 | `b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52` |
| SHA3-384 | `17619b89bac656541545440bdaf13d957c52864ca746d8623401914eb15ecae9be516196c80a1b2037f27002d5553fa0` |
| TLSH | `T1A5B35B21FD75682BC5C4617B15E34631F1B2439925BCDA5B7EA31D8CEF14220323FAAA` |
| SSDEEP | `1536:Ru6q+thGIpejVamG27Fa45WfATwUtAYtEeFKQp8zU9tflHHTgNWF5XgDsoEdtmkw:U6vujVNPf5ttF/FtsNkQoTRzS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_b8d04987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52"
    family = "Mirai"
    file_name = "b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:11:03"
  condition:
    hash.sha256(0, filesize) == "b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52"
}
```

### Sample 95: `71fef9435da5065e`

| Field | Value |
|---|---|
| SHA-256 | `71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4` |
| Family label | `unknown` |
| File name | `71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:10:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c7a8cf789b4c00cf8816fa9a8432f3` |
| SHA-1 | `e0501712206d33a9089c404dd9b7b0bd6ca832e6` |
| SHA-256 | `71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4` |
| SHA3-384 | `2472ed46d6da81a632b7590514d4ed99e57838c6e702838ff1d350cb6c34a5bd08b1033ac98d7096579b569a9e0eac5a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18EA3D004B6A4C17BDCBF1FFC9C7132045372E99AE639C69E2E88998D285774059A0F73` |
| SSDEEP | `3072:mz3EvugyrIODdaH1igdDuN5Sr5Thzgx9PSfWZ657:W3EGnrIeiZ20r51cx9KfWZ657` |
| ICON-DHASH | `69d486333186dc69` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_71fef943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4"
    family = "unknown"
    file_name = "71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:59"
  condition:
    hash.sha256(0, filesize) == "71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4"
}
```

### Sample 96: `12a43fee749a3596`

| Field | Value |
|---|---|
| SHA-256 | `12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984` |
| Family label | `VShell` |
| File name | `12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:10:53` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1de007ec15884a623391a3b13cb4596b` |
| SHA-1 | `e8ef5d81fcf677ad613ecf75975d2b6785cd68f2` |
| SHA-256 | `12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984` |
| SHA3-384 | `28b0821081b97946110c38c706a794f46377f2de169f457754d18f31a403ce7b2092f6d02da3303c1c7c296e1a739c14` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17591C64170B989E7E85C42BB4D0FB8A0B91D740A41C483A74378A5993E3A57BF5BCB0E` |
| SSDEEP | `48:6IIF9BlQaexsgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaM170cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_096_12a43fee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984"
    family = "VShell"
    file_name = "12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:53"
  condition:
    hash.sha256(0, filesize) == "12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984"
}
```

### Sample 97: `8ca3402d2d33cff1`

| Field | Value |
|---|---|
| SHA-256 | `8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559` |
| Family label | `VShell` |
| File name | `8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:10:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e32c55428f531e7c09b476f42c0cfc1` |
| SHA-1 | `92891caa5f220f8251a7b0e7b827d47a0493ce50` |
| SHA-256 | `8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559` |
| SHA3-384 | `66843d5b0f915920778f689e1852c73a899efc7a0570b35a3993f73f4d605276184f4211e6935001edb14d319b4da0f1` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14691C74170B989E7E85D457B4C0FB490B919740A41C483B60378A5953E3957BF57CB0D` |
| SSDEEP | `48:6IIF9BlQaexYgZv7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaM500cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_097_8ca3402d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559"
    family = "VShell"
    file_name = "8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:46"
  condition:
    hash.sha256(0, filesize) == "8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559"
}
```

### Sample 98: `9751fd974c94c2fc`

| Field | Value |
|---|---|
| SHA-256 | `9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1` |
| Family label | `Mirai` |
| File name | `9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:10:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee7e468cfac945389acdcea099c83bdb` |
| SHA-1 | `b1defb63d2ad192f839791517f883b4517e8ab7d` |
| SHA-256 | `9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1` |
| SHA3-384 | `bb0f6deb1fbab350c631d7b5afc55a3169cb4d930f87fa09c648fa704d6b44ae60203d699e351efabdec9124937ad0a4` |
| TLSH | `T12CB34A0277694407E2E70DB1293F6BF557EFD1A121A0A2C5690EEB4F8271E32158AFCD` |
| SSDEEP | `1536:vBSf3CP6/dUizhDZbkrLYIHiv2hYA9GoqQlmWQVw3Rakcqe94ksd+l/t1OVF38fZ:5SfndUQHa9ZQVg0QkI+Zhfx+g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_9751fd97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1"
    family = "Mirai"
    file_name = "9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:10:40"
  condition:
    hash.sha256(0, filesize) == "9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1"
}
```

### Sample 99: `086b643e503d0827`

| Field | Value |
|---|---|
| SHA-256 | `086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c` |
| Family label | `Mirai` |
| File name | `086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c.elf` |
| File type | `elf` |
| First seen | `2026-10-10 00:10:36` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4cfd0bce78f6f7f0ab04cc283253067` |
| SHA-1 | `5b3a7d01a7f1528f4473a669bfe770b18a24244a` |
| SHA-256 | `086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c` |
| SHA3-384 | `4e94c2fe4c4c5ca40ca453ea8c2a0fe206b896083b38caedbf7ad6d2e1ae62fbe629a438c4baba4f98d585dd94edc89f` |
| TLSH | `T1CFB31A8ABCC1C612C5E161B6FB1F92CD372643A8D3E67113DD18AB29774B8670E3B251` |
| TELFHASH | `t1fe712f2beb540f8c6be5465591df501ba6fd34de0b1214828e7dab1f5e42d82b03ec22` |
| SSDEEP | `1536:f7U9Rq+NRWWE7+GF+LBSDMZgYGE/9k7Eovvi1dddD07+v6fx8xR7:f7sqoRq7xq4M2ge7EovM8E6fxG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_086b643e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c"
    family = "Mirai"
    file_name = "086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:10:36"
  condition:
    hash.sha256(0, filesize) == "086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c"
}
```

### Sample 100: `11862191bdcfc8bb`

| Field | Value |
|---|---|
| SHA-256 | `11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d` |
| Family label | `RemcosRAT` |
| File name | `2c252bc8ecf99d3659df65af554c0c4d.exe` |
| File type | `exe` |
| First seen | `2026-10-10 00:10:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c252bc8ecf99d3659df65af554c0c4d` |
| SHA-1 | `c9acfe5840c11b540ae2c1959e68d68c880c7d28` |
| SHA-256 | `11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d` |
| SHA3-384 | `8305e6c17afbbb69e05b608221d1748265fdc08a5917a474d4807ecf102f59c85795fb78f71dd1b9ce3c4b2d84338000` |
| IMPHASH | `e77512f955eaf60ccff45e02d69234de` |
| TLSH | `T19BA4BF01BAD2C072D57654300C3AE775DEBDBD21283A897BB3D61D57FD30190A63AAB2` |
| SSDEEP | `12288:r13ak/mBXTG4/1v08KI7ZnMEF76JqmsvZQAmS:xak/mBXTV/R0nEF76gFZi` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_100_11862191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
    family = "RemcosRAT"
    file_name = "2c252bc8ecf99d3659df65af554c0c4d.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:06"
  condition:
    hash.sha256(0, filesize) == "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
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
 * Generated: 2026-10-10T06:01:15.398456+00:00
 */

rule MalwareBazaar_QuasarRAT_001_d5102a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5102a93f27c365d5a1d57e82d0d4571d558ff846c50efd7896905fc736148ea"
    family = "QuasarRAT"
    file_name = "DF6F9CE4475DA25B324829509EF5C186.exe"
    file_type = "exe"
    first_seen = "2026-10-10 06:00:08"
  condition:
    hash.sha256(0, filesize) == "d5102a93f27c365d5a1d57e82d0d4571d558ff846c50efd7896905fc736148ea"
}

rule MalwareBazaar_Mirai_002_abb01851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb018512ef40ba5e9aca1ca6fccc4572de60eb23fc79ba798cdc549f63ac27b"
    family = "Mirai"
    file_name = "rainii686"
    file_type = "elf"
    first_seen = "2026-10-10 05:56:04"
  condition:
    hash.sha256(0, filesize) == "abb018512ef40ba5e9aca1ca6fccc4572de60eb23fc79ba798cdc549f63ac27b"
}

rule MalwareBazaar_unknown_003_2b3d9dac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b3d9dac838a334b4b702da4b9aba1cdae67a3c3b71ca74eecba6c881f19f7a1"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-10-10 05:52:33"
  condition:
    hash.sha256(0, filesize) == "2b3d9dac838a334b4b702da4b9aba1cdae67a3c3b71ca74eecba6c881f19f7a1"
}

rule MalwareBazaar_unknown_004_1d306cb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d306cb7e2bae9d3a8eccbeff9521cb10b0ef124092035b625bba7853df2620b"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-10-10 05:52:31"
  condition:
    hash.sha256(0, filesize) == "1d306cb7e2bae9d3a8eccbeff9521cb10b0ef124092035b625bba7853df2620b"
}

rule MalwareBazaar_Mirai_005_1a09814d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-10-10 05:42:28"
  condition:
    hash.sha256(0, filesize) == "1a09814dcd1a18ad86c3789658bcb515dc241e3bcee3444be7dd48cf8a846f74"
}

rule MalwareBazaar_unknown_006_d3f45474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f4547481e4ca3fb6437981e1bc30fbe283573b89fe6698dd463894a8d11e3a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-10 05:37:19"
  condition:
    hash.sha256(0, filesize) == "d3f4547481e4ca3fb6437981e1bc30fbe283573b89fe6698dd463894a8d11e3a"
}

rule MalwareBazaar_Mirai_007_b3d283ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3d283ad82c2328cb09a8f3dee94c3c4813cad98f7680554dec8122d1c32ea63"
    family = "Mirai"
    file_name = "eclipse.m68k"
    file_type = "elf"
    first_seen = "2026-10-10 05:25:20"
  condition:
    hash.sha256(0, filesize) == "b3d283ad82c2328cb09a8f3dee94c3c4813cad98f7680554dec8122d1c32ea63"
}

rule MalwareBazaar_unknown_008_caf01f78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123"
    family = "unknown"
    file_name = "caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123"
    file_type = "elf"
    first_seen = "2026-10-10 05:22:58"
  condition:
    hash.sha256(0, filesize) == "caf01f78fba289bd565436b53801b2f9947eaa030c05df548727a48d46526123"
}

rule MalwareBazaar_unknown_009_d9854ad4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161"
    family = "unknown"
    file_name = "d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161.exe"
    file_type = "exe"
    first_seen = "2026-10-10 05:10:47"
  condition:
    hash.sha256(0, filesize) == "d9854ad4b04e65a89982328a63ea6157ca963a90125e1510ec364c1ac0737161"
}

rule MalwareBazaar_QuasarRAT_010_26acdf09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26acdf091d7a9bcf72b056561bc69221de623d43097499a777f59cab859b88a1"
    family = "QuasarRAT"
    file_name = "A6A09B6E372BF40B716D2BF3237C2902.exe"
    file_type = "exe"
    first_seen = "2026-10-10 04:25:06"
  condition:
    hash.sha256(0, filesize) == "26acdf091d7a9bcf72b056561bc69221de623d43097499a777f59cab859b88a1"
}

rule MalwareBazaar_unknown_011_d2e63827
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be"
    family = "unknown"
    file_name = "d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be.exe"
    file_type = "exe"
    first_seen = "2026-10-10 04:13:37"
  condition:
    hash.sha256(0, filesize) == "d2e638270df17ec368adfc71241b8743d5fa10c3f10a708ae90d4eb84ba8e2be"
}

rule MalwareBazaar_unknown_012_3a62ba9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729"
    family = "unknown"
    file_name = "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729.exe"
    file_type = "exe"
    first_seen = "2026-10-10 04:11:58"
  condition:
    hash.sha256(0, filesize) == "3a62ba9d46cb84d3e77a2a45285c6b354bdd7a7944ca30ad6d486939b5a0a729"
}

rule MalwareBazaar_unknown_013_c589ea48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6"
    family = "unknown"
    file_name = "c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6"
    file_type = "elf"
    first_seen = "2026-10-10 03:52:39"
  condition:
    hash.sha256(0, filesize) == "c589ea48755c88a02e6b15df979f85006d5572c47888740877630c53779750c6"
}

rule MalwareBazaar_Mirai_014_54e56dcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54e56dcd07a5771dd529ed962e25d875efab0089d9b7b9ab249fcce7e46acae3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 03:28:27"
  condition:
    hash.sha256(0, filesize) == "54e56dcd07a5771dd529ed962e25d875efab0089d9b7b9ab249fcce7e46acae3"
}

rule MalwareBazaar_Mirai_015_64baec60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64baec6013414eacd268a91e105e652b8e125e231821100c619d0060a79c37da"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:47"
  condition:
    hash.sha256(0, filesize) == "64baec6013414eacd268a91e105e652b8e125e231821100c619d0060a79c37da"
}

rule MalwareBazaar_Mirai_016_3fa7e274
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa7e27442f328fc3f5f905bc5bf1444626cbf6dc02afd289bbca783200f43d8"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:44"
  condition:
    hash.sha256(0, filesize) == "3fa7e27442f328fc3f5f905bc5bf1444626cbf6dc02afd289bbca783200f43d8"
}

rule MalwareBazaar_Mirai_017_b5a0f571
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5a0f571387cc53c1f817b322e543ab8ef2078bd0e61e1a2fa4fcabe9f43a7fb"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:42"
  condition:
    hash.sha256(0, filesize) == "b5a0f571387cc53c1f817b322e543ab8ef2078bd0e61e1a2fa4fcabe9f43a7fb"
}

rule MalwareBazaar_Mirai_018_aba60b30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba60b306f7287a105aebfefe45c151b8e77ceaa0b528ab5d5553094baf4cc07"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:39"
  condition:
    hash.sha256(0, filesize) == "aba60b306f7287a105aebfefe45c151b8e77ceaa0b528ab5d5553094baf4cc07"
}

rule MalwareBazaar_Mirai_019_fc3b7ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc3b7ce58553134fbfdd03464508534f0cdc35d40f3d6d63e52751befe0265b9"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:36"
  condition:
    hash.sha256(0, filesize) == "fc3b7ce58553134fbfdd03464508534f0cdc35d40f3d6d63e52751befe0265b9"
}

rule MalwareBazaar_Mirai_020_347ff4da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "347ff4da8029c5aede97394b6cb3a59b267e3b6916d4d4e6561e5a248ea56f44"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:33"
  condition:
    hash.sha256(0, filesize) == "347ff4da8029c5aede97394b6cb3a59b267e3b6916d4d4e6561e5a248ea56f44"
}

rule MalwareBazaar_Mirai_021_762a6ad0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "762a6ad0a16496eb59595002af5fef4e75e53466ff983808ce40ea296701541a"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-10 03:27:31"
  condition:
    hash.sha256(0, filesize) == "762a6ad0a16496eb59595002af5fef4e75e53466ff983808ce40ea296701541a"
}

rule MalwareBazaar_unknown_022_323ce5bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526"
    family = "unknown"
    file_name = "323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526.exe"
    file_type = "exe"
    first_seen = "2026-10-10 03:25:04"
  condition:
    hash.sha256(0, filesize) == "323ce5bba5660a9a223ff1a6a484b7bc4b86b9feb3b5056d559c6679be58b526"
}

rule MalwareBazaar_unknown_023_70d84f80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9"
    family = "unknown"
    file_name = "70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9"
    file_type = "elf"
    first_seen = "2026-10-10 03:22:33"
  condition:
    hash.sha256(0, filesize) == "70d84f8053a4da100e42c73e590a7bde3516c0d7915ddb36485eea2748eebce9"
}

rule MalwareBazaar_unknown_024_c371d357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b"
    family = "unknown"
    file_name = "c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b.exe"
    file_type = "exe"
    first_seen = "2026-10-10 03:14:13"
  condition:
    hash.sha256(0, filesize) == "c371d3578b519c2a63a96f45a3b3a98a53fc8802939b808ba0e1ee76071d037b"
}

rule MalwareBazaar_RemcosRAT_025_77415566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77415566cdc9a0f0d16347961f5eacca934a73cb4e00c834b782962e9de8d417"
    family = "RemcosRAT"
    file_name = "56E705CF656CCE54945C7941442A6624.exe"
    file_type = "exe"
    first_seen = "2026-10-10 02:40:07"
  condition:
    hash.sha256(0, filesize) == "77415566cdc9a0f0d16347961f5eacca934a73cb4e00c834b782962e9de8d417"
}

rule MalwareBazaar_unknown_026_cc4407b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f"
    family = "unknown"
    file_name = "cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f"
    file_type = "elf"
    first_seen = "2026-10-10 02:22:22"
  condition:
    hash.sha256(0, filesize) == "cc4407b98559e6544695f7ee5d2248ca00b3a3a92b6aef780e3743827f37b29f"
}

rule MalwareBazaar_VShell_027_79ada3e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873"
    family = "VShell"
    file_name = "79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873.exe"
    file_type = "exe"
    first_seen = "2026-10-10 02:20:43"
  condition:
    hash.sha256(0, filesize) == "79ada3e5bddf5a6ffb1977e4e0f50a13512a02e2ba786b96b86190498d175873"
}

rule MalwareBazaar_Mirai_028_6dfba6f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dfba6f8258418683002d77be91fba1abe8527baab12a1013e161bc394f959f8"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-10-10 02:16:03"
  condition:
    hash.sha256(0, filesize) == "6dfba6f8258418683002d77be91fba1abe8527baab12a1013e161bc394f959f8"
}

rule MalwareBazaar_ACRStealer_029_00e9fd3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e"
    family = "ACRStealer"
    file_name = "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e.ps1"
    file_type = "ps1"
    first_seen = "2026-10-10 02:12:57"
  condition:
    hash.sha256(0, filesize) == "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e"
}

rule MalwareBazaar_Mirai_030_c51c6272
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6"
    family = "Mirai"
    file_name = "c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6.elf"
    file_type = "elf"
    first_seen = "2026-10-10 02:12:13"
  condition:
    hash.sha256(0, filesize) == "c51c6272590c97dc57835e9ee27c3f96060dba964af8f6eab523de807706e2c6"
}

rule MalwareBazaar_Mirai_031_f07a46a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f07a46a94488452359b84a012af599d7144d4124b7c2aeed0045bb9a29bef858"
    family = "Mirai"
    file_name = "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757.elf"
    file_type = "elf"
    first_seen = "2026-10-10 02:11:17"
  condition:
    hash.sha256(0, filesize) == "f07a46a94488452359b84a012af599d7144d4124b7c2aeed0045bb9a29bef858"
}

rule MalwareBazaar_Mirai_032_2a6aef77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757"
    family = "Mirai"
    file_name = "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757.elf"
    file_type = "elf"
    first_seen = "2026-10-10 02:11:05"
  condition:
    hash.sha256(0, filesize) == "2a6aef7706f26d9830a7de7f80758ba8cf3ad43877216e15917467b854152757"
}

rule MalwareBazaar_Mirai_033_5a0da401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a0da401ff83bb724aadb46aa91e877df6dc288dc82af68641a3acbaa1434c96"
    family = "Mirai"
    file_name = "eclipse.sh4"
    file_type = "elf"
    first_seen = "2026-10-10 01:53:23"
  condition:
    hash.sha256(0, filesize) == "5a0da401ff83bb724aadb46aa91e877df6dc288dc82af68641a3acbaa1434c96"
}

rule MalwareBazaar_Mirai_034_58f2dc5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58f2dc5c76ba67a005df92d9f2287dda6af177dcb387dcbac74944323c85e7be"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-10 01:53:21"
  condition:
    hash.sha256(0, filesize) == "58f2dc5c76ba67a005df92d9f2287dda6af177dcb387dcbac74944323c85e7be"
}

rule MalwareBazaar_Mirai_035_1b79ac93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b79ac93016a812762c5c16ce36a7d3405a7b6ecd15eca24f1ca6031b0098911"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 01:43:16"
  condition:
    hash.sha256(0, filesize) == "1b79ac93016a812762c5c16ce36a7d3405a7b6ecd15eca24f1ca6031b0098911"
}

rule MalwareBazaar_Mirai_036_6dda01bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6dda01bc822dcff5a081176b611e85c3324bfe642f224ace9942b8cf7d1ce0a0"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 01:42:38"
  condition:
    hash.sha256(0, filesize) == "6dda01bc822dcff5a081176b611e85c3324bfe642f224ace9942b8cf7d1ce0a0"
}

rule MalwareBazaar_Mirai_037_8e550ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e550ed90921aa2a7c6d4b5a03fb8cb6d5e45ef9d1705baaea6c41bab5ae4ed6"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 01:36:21"
  condition:
    hash.sha256(0, filesize) == "8e550ed90921aa2a7c6d4b5a03fb8cb6d5e45ef9d1705baaea6c41bab5ae4ed6"
}

rule MalwareBazaar_Mirai_038_52611853
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "526118535dbe72042e5e5c329b31dec47de1d1e7be02c26a1f329c8287dbbc8b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 01:35:28"
  condition:
    hash.sha256(0, filesize) == "526118535dbe72042e5e5c329b31dec47de1d1e7be02c26a1f329c8287dbbc8b"
}

rule MalwareBazaar_Mirai_039_4969607e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4969607e53fb15d4681f663d521ea0e70f565ed83ffd1042e9c2f2d77a9f5112"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-10-10 01:25:14"
  condition:
    hash.sha256(0, filesize) == "4969607e53fb15d4681f663d521ea0e70f565ed83ffd1042e9c2f2d77a9f5112"
}

rule MalwareBazaar_Vidar_040_ad10f4c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad10f4c694e060e8cf9066c8156e03c3eef0a413c125c51e64baceca732c4f31"
    family = "Vidar"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-10 01:21:31"
  condition:
    hash.sha256(0, filesize) == "ad10f4c694e060e8cf9066c8156e03c3eef0a413c125c51e64baceca732c4f31"
}

rule MalwareBazaar_Vidar_041_ac97ff69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac97ff69a8b5da0b04c14ed85945931c6218823d829192f2d7bcfa022b6b65b9"
    family = "Vidar"
    file_name = "___L__it__64-v.3.449.exe"
    file_type = "exe"
    first_seen = "2026-10-10 01:19:56"
  condition:
    hash.sha256(0, filesize) == "ac97ff69a8b5da0b04c14ed85945931c6218823d829192f2d7bcfa022b6b65b9"
}

rule MalwareBazaar_Mirai_042_90feb8a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90feb8a42116a8687589bcf05e1eb6ad645f55a777931b0436ea58c9e58a97cb"
    family = "Mirai"
    file_name = "android-arm64"
    file_type = "elf"
    first_seen = "2026-10-10 01:17:34"
  condition:
    hash.sha256(0, filesize) == "90feb8a42116a8687589bcf05e1eb6ad645f55a777931b0436ea58c9e58a97cb"
}

rule MalwareBazaar_unknown_043_5a052f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a052f7071b9e66a6f73473244f9b632c19885f9f73fb5871c364731ddecc306"
    family = "unknown"
    file_name = "qp0tnnr.jar"
    file_type = "jar"
    first_seen = "2026-10-10 01:16:27"
  condition:
    hash.sha256(0, filesize) == "5a052f7071b9e66a6f73473244f9b632c19885f9f73fb5871c364731ddecc306"
}

rule MalwareBazaar_Mirai_044_0203fcb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0203fcb09d396bed27adaf248ee33aca03c9e048bfd98555e966b30b122d426a"
    family = "Mirai"
    file_name = "android-arm"
    file_type = "elf"
    first_seen = "2026-10-10 01:09:35"
  condition:
    hash.sha256(0, filesize) == "0203fcb09d396bed27adaf248ee33aca03c9e048bfd98555e966b30b122d426a"
}

rule MalwareBazaar_Mirai_045_5f706fe4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f706fe4ff04ef74710bc422a938e3b5d452ef739c1d9e6a06592c1742567c53"
    family = "Mirai"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-10-10 01:09:32"
  condition:
    hash.sha256(0, filesize) == "5f706fe4ff04ef74710bc422a938e3b5d452ef739c1d9e6a06592c1742567c53"
}

rule MalwareBazaar_Mirai_046_83299e43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83299e43d1c3b324e9c3a5018822d502f203a3fbef7d8e640d4540fbf4b5c689"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-10 01:02:26"
  condition:
    hash.sha256(0, filesize) == "83299e43d1c3b324e9c3a5018822d502f203a3fbef7d8e640d4540fbf4b5c689"
}

rule MalwareBazaar_Mirai_047_6fc9a7c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fc9a7c3206a9a25b325a5d2f18a555bf94d2b8d1bbf732105ab8fb6f362d72f"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-10 01:02:22"
  condition:
    hash.sha256(0, filesize) == "6fc9a7c3206a9a25b325a5d2f18a555bf94d2b8d1bbf732105ab8fb6f362d72f"
}

rule MalwareBazaar_Mirai_048_34982876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34982876ca4776ebaca652e152141a226b6b6d03e0be32f1ba046629bde6d781"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-10 01:01:31"
  condition:
    hash.sha256(0, filesize) == "34982876ca4776ebaca652e152141a226b6b6d03e0be32f1ba046629bde6d781"
}

rule MalwareBazaar_Mirai_049_dc5dff4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5dff4a23be303fe1d8d37fde70744f8be3237dd7dd41c4a1c96a523f032b1e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-10 01:01:29"
  condition:
    hash.sha256(0, filesize) == "dc5dff4a23be303fe1d8d37fde70744f8be3237dd7dd41c4a1c96a523f032b1e"
}

rule MalwareBazaar_unknown_050_8d18689c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d18689c062bf9f17d699bd454dc2c1bbf72f96db6363fd470773155854510ca"
    family = "unknown"
    file_name = "main.microblazebe"
    file_type = "elf"
    first_seen = "2026-10-10 00:58:08"
  condition:
    hash.sha256(0, filesize) == "8d18689c062bf9f17d699bd454dc2c1bbf72f96db6363fd470773155854510ca"
}

rule MalwareBazaar_Vidar_051_b6ea43e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921"
    family = "Vidar"
    file_name = "b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:55:41"
  condition:
    hash.sha256(0, filesize) == "b6ea43e7f0371f5278f7d56dbdea7da203fe51976f5ea3751aff0598d44d8921"
}

rule MalwareBazaar_Vidar_052_4dbc2a3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688"
    family = "Vidar"
    file_name = "4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:55:27"
  condition:
    hash.sha256(0, filesize) == "4dbc2a3dcbd0a5a711f45789a4367cd959fc0dcc37ddc1d6e335cb98925aa688"
}

rule MalwareBazaar_Mirai_053_7056591e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7056591ec2e5296b23074efa4461c62bbb4ad189dfdbbde1a4445498c3efe638"
    family = "Mirai"
    file_name = "dvr.sh"
    file_type = "sh"
    first_seen = "2026-10-10 00:55:08"
  condition:
    hash.sha256(0, filesize) == "7056591ec2e5296b23074efa4461c62bbb4ad189dfdbbde1a4445498c3efe638"
}

rule MalwareBazaar_Mirai_054_f427a282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f427a2829f5f796210b15a4d6eb5df2fd40a1c116877ff66e4c42eb4f5ec3fd3"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-10-10 00:55:01"
  condition:
    hash.sha256(0, filesize) == "f427a2829f5f796210b15a4d6eb5df2fd40a1c116877ff66e4c42eb4f5ec3fd3"
}

rule MalwareBazaar_unknown_055_48722ba5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48722ba5a2d08b126b747a82e962556625ba80ea48533978cd4ca8e5fd4f6180"
    family = "unknown"
    file_name = "main.i486"
    file_type = "elf"
    first_seen = "2026-10-10 00:54:59"
  condition:
    hash.sha256(0, filesize) == "48722ba5a2d08b126b747a82e962556625ba80ea48533978cd4ca8e5fd4f6180"
}

rule MalwareBazaar_Mirai_056_4faca0c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4faca0c251d54100a37cfda9d33c396048bce26c79cf5e23b4ca14fd685b558c"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 00:52:19"
  condition:
    hash.sha256(0, filesize) == "4faca0c251d54100a37cfda9d33c396048bce26c79cf5e23b4ca14fd685b558c"
}

rule MalwareBazaar_Mirai_057_8d1aaf7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d1aaf7b5343e6d13828f68e65e165c394076751b83d01b3642758820c0641b5"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 00:52:02"
  condition:
    hash.sha256(0, filesize) == "8d1aaf7b5343e6d13828f68e65e165c394076751b83d01b3642758820c0641b5"
}

rule MalwareBazaar_Mirai_058_e9875f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9875f2824240e97413fb19a8623153098c65b5d4f4918ead31631cab8c0a425"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-10 00:48:58"
  condition:
    hash.sha256(0, filesize) == "e9875f2824240e97413fb19a8623153098c65b5d4f4918ead31631cab8c0a425"
}

rule MalwareBazaar_Mirai_059_68f1e259
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68f1e25924255b1be60f3c1f05418dc50181cc8e8d95dce4280a6a8285465139"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-10 00:46:28"
  condition:
    hash.sha256(0, filesize) == "68f1e25924255b1be60f3c1f05418dc50181cc8e8d95dce4280a6a8285465139"
}

rule MalwareBazaar_Mirai_060_1c39d5b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c39d5b7fd20f7d696ca4697abc07a3e08e73496975df0e37a5da0c956e8316c"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-10 00:45:58"
  condition:
    hash.sha256(0, filesize) == "1c39d5b7fd20f7d696ca4697abc07a3e08e73496975df0e37a5da0c956e8316c"
}

rule MalwareBazaar_PureCrypter_061_5528b5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5528b5e88656593ef5c680980621855ef84389efd06fb441a01ff3b48d8bdeb9"
    family = "PureCrypter"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-10 00:43:24"
  condition:
    hash.sha256(0, filesize) == "5528b5e88656593ef5c680980621855ef84389efd06fb441a01ff3b48d8bdeb9"
}

rule MalwareBazaar_Mirai_062_08ca823c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08ca823c1ce7029d93d1fe08f258358e145acbda7183d2e6a18c9b548f96162f"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-10 00:42:56"
  condition:
    hash.sha256(0, filesize) == "08ca823c1ce7029d93d1fe08f258358e145acbda7183d2e6a18c9b548f96162f"
}

rule MalwareBazaar_Mirai_063_4c5be7e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c5be7e5b0ef0f7380a3c19cdc60244cef11fa0fa7dad8aa9ac4b0bd4f11c03f"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-10 00:42:54"
  condition:
    hash.sha256(0, filesize) == "4c5be7e5b0ef0f7380a3c19cdc60244cef11fa0fa7dad8aa9ac4b0bd4f11c03f"
}

rule MalwareBazaar_unknown_064_14205536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860"
    family = "unknown"
    file_name = "1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:40:52"
  condition:
    hash.sha256(0, filesize) == "1420553605f47000da910d53d6fe9f1835fe484e135f432f6ecf750733366860"
}

rule MalwareBazaar_AMOS_065_c54847ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c54847abf0244aa9dbf6e84e6f38cafae01086a8f2f2c74a8c4ad12bdfd6c54f"
    family = "AMOS"
    file_name = "macho_c54847abf024.bin"
    file_type = "macho"
    first_seen = "2026-10-10 00:39:47"
  condition:
    hash.sha256(0, filesize) == "c54847abf0244aa9dbf6e84e6f38cafae01086a8f2f2c74a8c4ad12bdfd6c54f"
}

rule MalwareBazaar_unknown_066_c0bbb9a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0bbb9a64c6ce4ac41f8186090b159951401bcf596015dce95df91a40b11828d"
    family = "unknown"
    file_name = "main.riscv32"
    file_type = "elf"
    first_seen = "2026-10-10 00:33:51"
  condition:
    hash.sha256(0, filesize) == "c0bbb9a64c6ce4ac41f8186090b159951401bcf596015dce95df91a40b11828d"
}

rule MalwareBazaar_unknown_067_79e4ed8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79e4ed8b30063eb079c168ba82698f3d5fde70b973ebd5258c0272b88a0e0502"
    family = "unknown"
    file_name = "main.mips32el"
    file_type = "elf"
    first_seen = "2026-10-10 00:33:48"
  condition:
    hash.sha256(0, filesize) == "79e4ed8b30063eb079c168ba82698f3d5fde70b973ebd5258c0272b88a0e0502"
}

rule MalwareBazaar_unknown_068_bc3f5476
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc3f5476149b3dfa8e52e76fe1e252316bd2a9c0e5ddddc585cfb4def12fb89f"
    family = "unknown"
    file_name = "main.e6500"
    file_type = "elf"
    first_seen = "2026-10-10 00:33:46"
  condition:
    hash.sha256(0, filesize) == "bc3f5476149b3dfa8e52e76fe1e252316bd2a9c0e5ddddc585cfb4def12fb89f"
}

rule MalwareBazaar_Mirai_069_54f9211c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54f9211ce2133537769fa2759e3a1ce2c2295eb561ed98b7b04777221ccf085d"
    family = "Mirai"
    file_name = "mipsrouter"
    file_type = "elf"
    first_seen = "2026-10-10 00:31:24"
  condition:
    hash.sha256(0, filesize) == "54f9211ce2133537769fa2759e3a1ce2c2295eb561ed98b7b04777221ccf085d"
}

rule MalwareBazaar_unknown_070_b1ca24b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1ca24b5a9b26c6ff2f34d0063d18b86b362c1216ac1b8c982acfee884c3ba20"
    family = "unknown"
    file_name = "eclipse.sh"
    file_type = "sh"
    first_seen = "2026-10-10 00:30:59"
  condition:
    hash.sha256(0, filesize) == "b1ca24b5a9b26c6ff2f34d0063d18b86b362c1216ac1b8c982acfee884c3ba20"
}

rule MalwareBazaar_Mirai_071_b0b2af0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0b2af0d3f774245eb60ec64e200cd2f178f9efd18c945a64010534e9f75241a"
    family = "Mirai"
    file_name = "mipsrouter"
    file_type = "elf"
    first_seen = "2026-10-10 00:30:54"
  condition:
    hash.sha256(0, filesize) == "b0b2af0d3f774245eb60ec64e200cd2f178f9efd18c945a64010534e9f75241a"
}

rule MalwareBazaar_Mirai_072_61df29da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61df29da73da82fc5c767946804189d1d94c105dd54b01ec786202e9b451bbc4"
    family = "Mirai"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-10-10 00:24:54"
  condition:
    hash.sha256(0, filesize) == "61df29da73da82fc5c767946804189d1d94c105dd54b01ec786202e9b451bbc4"
}

rule MalwareBazaar_Mirai_073_e9f628ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9f628ffa4e6acc0c7e0aae334d0bacb4235d0fdab513051d0a14c94b079121a"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-10-10 00:22:34"
  condition:
    hash.sha256(0, filesize) == "e9f628ffa4e6acc0c7e0aae334d0bacb4235d0fdab513051d0a14c94b079121a"
}

rule MalwareBazaar_unknown_074_00fec85c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00fec85c279bcbc15134e4c3a82564ecb08764639e23cbb199233da09ea241d3"
    family = "unknown"
    file_name = "main.e500mc"
    file_type = "elf"
    first_seen = "2026-10-10 00:21:50"
  condition:
    hash.sha256(0, filesize) == "00fec85c279bcbc15134e4c3a82564ecb08764639e23cbb199233da09ea241d3"
}

rule MalwareBazaar_Mirai_075_52ded2b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52ded2b6af6c64932216537a1533a2961f3a621b9ffd51a20b64241f71fff2a8"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-10-10 00:21:48"
  condition:
    hash.sha256(0, filesize) == "52ded2b6af6c64932216537a1533a2961f3a621b9ffd51a20b64241f71fff2a8"
}

rule MalwareBazaar_Mirai_076_72ee7b86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72ee7b86e6159bf19c1f9f19b9e3eb02d0cf7eb93c93ab39eef7014439ba7c92"
    family = "Mirai"
    file_name = "main.sparc64"
    file_type = "elf"
    first_seen = "2026-10-10 00:18:48"
  condition:
    hash.sha256(0, filesize) == "72ee7b86e6159bf19c1f9f19b9e3eb02d0cf7eb93c93ab39eef7014439ba7c92"
}

rule MalwareBazaar_Mirai_077_b9b365c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9b365c9df55864e1426e864e60f9420257c1b451146451d67108d16ff5892fc"
    family = "Mirai"
    file_name = "main.armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 00:18:46"
  condition:
    hash.sha256(0, filesize) == "b9b365c9df55864e1426e864e60f9420257c1b451146451d67108d16ff5892fc"
}

rule MalwareBazaar_Mirai_078_34e7bb86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff"
    family = "Mirai"
    file_name = "34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:18:04"
  condition:
    hash.sha256(0, filesize) == "34e7bb86115ed921f1f022db56226614c6aa7aa23d55feb3e5af60eb616d3cff"
}

rule MalwareBazaar_Mirai_079_8d4fb5f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb"
    family = "Mirai"
    file_name = "8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:17:59"
  condition:
    hash.sha256(0, filesize) == "8d4fb5f3f54d19f3c5b47bdfd928e58fabe37b40d8d105c458eabef910112ebb"
}

rule MalwareBazaar_Mirai_080_9d294361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7"
    family = "Mirai"
    file_name = "9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:17:09"
  condition:
    hash.sha256(0, filesize) == "9d294361a6c61ce1c1617f80b9bad73f82c949c2e455d3289138094652e3afd7"
}

rule MalwareBazaar_Mirai_081_bb48f3d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95"
    family = "Mirai"
    file_name = "bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:17:04"
  condition:
    hash.sha256(0, filesize) == "bb48f3d7057d2675a7cc6a589e5fb2402e30ec991971ad9b26003fad4758fa95"
}

rule MalwareBazaar_Mirai_082_79f38755
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d"
    family = "Mirai"
    file_name = "79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:16:55"
  condition:
    hash.sha256(0, filesize) == "79f387555290301b619d838a9c260854e91fd7f919850c1a44b9d690c75b339d"
}

rule MalwareBazaar_unknown_083_d297ec1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d297ec1d8c823a65e341bec0ce462f05770684af0d62b87544dbf24ae48c6726"
    family = "unknown"
    file_name = "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:16:40"
  condition:
    hash.sha256(0, filesize) == "d297ec1d8c823a65e341bec0ce462f05770684af0d62b87544dbf24ae48c6726"
}

rule MalwareBazaar_unknown_084_e74195b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6"
    family = "unknown"
    file_name = "e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:16:09"
  condition:
    hash.sha256(0, filesize) == "e74195b041ab104a259a7b5e0f587c1918ec0edf92f55c46bc561b63972cedd6"
}

rule MalwareBazaar_unknown_085_6e7b9977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173"
    family = "unknown"
    file_name = "6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:16:01"
  condition:
    hash.sha256(0, filesize) == "6e7b99771c824f44a0f75d749e86b5fea8f45e6bd9ce3c5abb656f7f06ef5173"
}

rule MalwareBazaar_unknown_086_694de315
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768"
    family = "unknown"
    file_name = "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:15:56"
  condition:
    hash.sha256(0, filesize) == "694de315e03b651ff309de1fa2ae82fe5e70fb84db0d6898761e23c356289768"
}

rule MalwareBazaar_Babadeda_087_ffda934a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540"
    family = "Babadeda"
    file_name = "ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:15:51"
  condition:
    hash.sha256(0, filesize) == "ffda934a9acd3bdf14128a14812049f0558d75b63677f346c16204427a483540"
}

rule MalwareBazaar_Mirai_088_73cf6e88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73cf6e88333ec08a93f1fad093478624d311070762576f8185a0371cb5c71d4c"
    family = "Mirai"
    file_name = "main.armv7-eabihf"
    file_type = "elf"
    first_seen = "2026-10-10 00:15:44"
  condition:
    hash.sha256(0, filesize) == "73cf6e88333ec08a93f1fad093478624d311070762576f8185a0371cb5c71d4c"
}

rule MalwareBazaar_unknown_089_9eb445c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb445c9713aaa47cdcde4a44ee62fc6ace4bde23c240be047cc579f65d84cc1"
    family = "unknown"
    file_name = "main.sparc"
    file_type = "elf"
    first_seen = "2026-10-10 00:15:42"
  condition:
    hash.sha256(0, filesize) == "9eb445c9713aaa47cdcde4a44ee62fc6ace4bde23c240be047cc579f65d84cc1"
}

rule MalwareBazaar_unknown_090_cd7cf896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773"
    family = "unknown"
    file_name = "cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:12:13"
  condition:
    hash.sha256(0, filesize) == "cd7cf89608d3cccd358648d9dd55c3852281898beab02e133ebe95450e167773"
}

rule MalwareBazaar_unknown_091_1a7ba4e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec"
    family = "unknown"
    file_name = "1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:12:08"
  condition:
    hash.sha256(0, filesize) == "1a7ba4e6b2691f9c9aaa349c6f8aab99010ea7c831a8509480f4db21f4cfc0ec"
}

rule MalwareBazaar_VShell_092_35b15d6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1"
    family = "VShell"
    file_name = "35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:12:01"
  condition:
    hash.sha256(0, filesize) == "35b15d6c1af38f79556e8b3e99486e5d8d34039e037675eca021c3503ec0a3b1"
}

rule MalwareBazaar_RuRAT_093_becef815
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2"
    family = "RuRAT"
    file_name = "becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2.msi"
    file_type = "msi"
    first_seen = "2026-10-10 00:11:56"
  condition:
    hash.sha256(0, filesize) == "becef815900330a003675673d1b0bdc907d8c2ab3d6779079a3ad246ad6125c2"
}

rule MalwareBazaar_Mirai_094_b8d04987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52"
    family = "Mirai"
    file_name = "b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:11:03"
  condition:
    hash.sha256(0, filesize) == "b8d04987bf3df3be130d397a7bef47d3396680a424505ffae489841588c95f52"
}

rule MalwareBazaar_unknown_095_71fef943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4"
    family = "unknown"
    file_name = "71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:59"
  condition:
    hash.sha256(0, filesize) == "71fef9435da5065eac44a7f1972238c2652bf918b38b0c6cb7d469049f5695a4"
}

rule MalwareBazaar_VShell_096_12a43fee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984"
    family = "VShell"
    file_name = "12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:53"
  condition:
    hash.sha256(0, filesize) == "12a43fee749a3596766958bfe9111e4874de2d90c4d7a5df2ebe5606694e0984"
}

rule MalwareBazaar_VShell_097_8ca3402d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559"
    family = "VShell"
    file_name = "8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:46"
  condition:
    hash.sha256(0, filesize) == "8ca3402d2d33cff125b3d7a9932208f4b1e9f0cf33c9bbbb8eed24fb6c650559"
}

rule MalwareBazaar_Mirai_098_9751fd97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1"
    family = "Mirai"
    file_name = "9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:10:40"
  condition:
    hash.sha256(0, filesize) == "9751fd974c94c2fc596ad4cd40b005fb15b7812bf236e4fee14368b5b2d1c9c1"
}

rule MalwareBazaar_Mirai_099_086b643e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c"
    family = "Mirai"
    file_name = "086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 00:10:36"
  condition:
    hash.sha256(0, filesize) == "086b643e503d08276a147e70df02cdb635cdf8fb8624edb168f9b7ee75f3022c"
}

rule MalwareBazaar_RemcosRAT_100_11862191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
    family = "RemcosRAT"
    file_name = "2c252bc8ecf99d3659df65af554c0c4d.exe"
    file_type = "exe"
    first_seen = "2026-10-10 00:10:06"
  condition:
    hash.sha256(0, filesize) == "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

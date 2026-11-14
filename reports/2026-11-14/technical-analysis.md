# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-14

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 679 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 679 |
| Unique family labels | 12 |
| Unique file types | 11 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 39 |
| Mirai | 20 |
| WARDENStealer | 13 |
| njrat | 8 |
| RevStealer | 8 |
| CoinMiner | 3 |
| ConnectWise | 3 |
| Arechclient2 | 2 |
| SnappyClient | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 47 |
| elf | 23 |
| msi | 6 |
| ps1 | 5 |
| sh | 5 |
| zip | 4 |
| macho | 4 |
| rtf | 2 |
| apk | 2 |
| iso | 1 |

## Per-Sample Analysis

### Sample 1: `705e26fbfd725f95`

| Field | Value |
|---|---|
| SHA-256 | `705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54` |
| Family label | `Mirai` |
| File name | `705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54` |
| File type | `elf` |
| First seen | `2026-11-14 06:38:53` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, Prometei, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acbdbaa2058a7b642ae4239dd810f2e1` |
| SHA-1 | `a7ac8da15cad03a2b5a9a9bb59bc063d94094de1` |
| SHA-256 | `705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54` |
| SHA3-384 | `72a87ed1c699a107b3e292f21c63279739abc17beb284fdeb7df15b7d331ee454f8c987473ab09e368ae26b2c71d98e2` |
| TLSH | `T184556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSm:SDjxB4m5n8XlaPWi+d+a4TjxQP4o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_705e26fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54"
    family = "Mirai"
    file_name = "705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54"
    file_type = "elf"
    first_seen = "2026-11-14 06:38:53"
  condition:
    hash.sha256(0, filesize) == "705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54"
}
```

### Sample 2: `f1d177fd6752b40f`

| Field | Value |
|---|---|
| SHA-256 | `f1d177fd6752b40fbb6a53a76d0a7de76819d73bd87c01bd6add0c37046e916d` |
| Family label | `njrat` |
| File name | `36C22C2F0A3A18E81EB0565729E55E51.exe` |
| File type | `exe` |
| First seen | `2026-11-14 06:35:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36c22c2f0a3a18e81eb0565729e55e51` |
| SHA-1 | `36e6c20adfbd327760f72a34d564ed9d2da24bb7` |
| SHA-256 | `f1d177fd6752b40fbb6a53a76d0a7de76819d73bd87c01bd6add0c37046e916d` |
| SHA3-384 | `6e5bcae929459171a44cb8a197e274fa684cb51b33e8c404b9622fcd15eb2b478de39748eb9287a7ffcf8decccfed4e8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E8B2E749B7A98708D2EE4A7849E3231147B1F3C7D880CB5B0DE610991E17BD62952FFE` |
| SSDEEP | `384:kW6uUSl4XM07KZARI/7whkumHIH1aOWQ+dcs//34LAZST7gDa:l6uUq4X97Ku21odWQuHqQa` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_002_f1d177fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d177fd6752b40fbb6a53a76d0a7de76819d73bd87c01bd6add0c37046e916d"
    family = "njrat"
    file_name = "36C22C2F0A3A18E81EB0565729E55E51.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:30"
  condition:
    hash.sha256(0, filesize) == "f1d177fd6752b40fbb6a53a76d0a7de76819d73bd87c01bd6add0c37046e916d"
}
```

### Sample 3: `38ada6ba9200ba8a`

| Field | Value |
|---|---|
| SHA-256 | `38ada6ba9200ba8ab44a59b541492e44dbfb806338cd60ea6cf18f70abac216f` |
| Family label | `njrat` |
| File name | `391d5c7fdafc8bf0eeaa1e28c4863d8e.exe` |
| File type | `exe` |
| First seen | `2026-11-14 06:35:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `391d5c7fdafc8bf0eeaa1e28c4863d8e` |
| SHA-1 | `a6f0dc3f900d7047bdb458ce919255f554cf03b3` |
| SHA-256 | `38ada6ba9200ba8ab44a59b541492e44dbfb806338cd60ea6cf18f70abac216f` |
| SHA3-384 | `cab9c16b3e6b46854b1ec0e8d169085d3572dbe367f17b78733e5505bf794165d0a26e24ae25d8af95aec08081b64d21` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T198A22A4E77688214D3AE1A7849E3232487F1F68BC951DF4B1CD910DA2F236D16642EFD` |
| SSDEEP | `384:KW6JUSlnXMTHmxMoa9fphsl0smHf3aOWQ+dcs//34LAZSTfyCdKxSh19bj:76JUqnXu649ROl03rWQuHqLj` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_003_38ada6ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38ada6ba9200ba8ab44a59b541492e44dbfb806338cd60ea6cf18f70abac216f"
    family = "njrat"
    file_name = "391d5c7fdafc8bf0eeaa1e28c4863d8e.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:18"
  condition:
    hash.sha256(0, filesize) == "38ada6ba9200ba8ab44a59b541492e44dbfb806338cd60ea6cf18f70abac216f"
}
```

### Sample 4: `c0f7fe5744fa2e2f`

| Field | Value |
|---|---|
| SHA-256 | `c0f7fe5744fa2e2f70e5ccd245f72a50f0e9ff3ee5f11010ac99bbcd6f329aa5` |
| Family label | `njrat` |
| File name | `23ff5d33a24096da70940a5e18ae890b.exe` |
| File type | `exe` |
| First seen | `2026-11-14 06:35:14` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23ff5d33a24096da70940a5e18ae890b` |
| SHA-1 | `bdf45f1d0b0f402448f29c5065af01c2a9213407` |
| SHA-256 | `c0f7fe5744fa2e2f70e5ccd245f72a50f0e9ff3ee5f11010ac99bbcd6f329aa5` |
| SHA3-384 | `eaac62ed8a5d8afbd6fabad4defe56d62603970630a2b2b391dd8f31dbe5a0551537529524ff0e7f5e9eea3a081de52c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17FA22A4E77688214D3AE1A7849E3232487B1F68BC951DF4B1CDA10DA2F236D16642EFD` |
| SSDEEP | `384:BW6JUSlnXMTHmxMoa9fphsl0smHf3aOWQ+dcs//34LAZSTfyCdKxSh19uj:Q6JUqnXu649ROl03rWQuHqej` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_004_c0f7fe57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0f7fe5744fa2e2f70e5ccd245f72a50f0e9ff3ee5f11010ac99bbcd6f329aa5"
    family = "njrat"
    file_name = "23ff5d33a24096da70940a5e18ae890b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:14"
  condition:
    hash.sha256(0, filesize) == "c0f7fe5744fa2e2f70e5ccd245f72a50f0e9ff3ee5f11010ac99bbcd6f329aa5"
}
```

### Sample 5: `5c4c829af18020ba`

| Field | Value |
|---|---|
| SHA-256 | `5c4c829af18020bade14bf27d8da16c636ed390ba459cf0965d7d374bf60e7c3` |
| Family label | `njrat` |
| File name | `1AC05AF367E3BDAEB1E5739321F389BB.exe` |
| File type | `exe` |
| First seen | `2026-11-14 06:35:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ac05af367e3bdaeb1e5739321f389bb` |
| SHA-1 | `27bb266bbea5e5f7f570d91083f1e473c67ffe6c` |
| SHA-256 | `5c4c829af18020bade14bf27d8da16c636ed390ba459cf0965d7d374bf60e7c3` |
| SHA3-384 | `4fd7491a9ed1aeca25e170c69c02d07fb018780f9e323efcc9e60ea46ec660d9d7ef3676a6af0a95dd38f2ef2d843d5a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T114A22A4E77688214D3AE1A7849E3232487F1F68BC951DF4B1CD910DA2F236D16642EFD` |
| SSDEEP | `384:4W6JUSlnXMTHmxMoa9fphsl0smHf3aOWQ+dcs//34LAZSTfyCdKxSh19Fj:J6JUqnXu649ROl03rWQuHq1j` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_005_5c4c829a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c4c829af18020bade14bf27d8da16c636ed390ba459cf0965d7d374bf60e7c3"
    family = "njrat"
    file_name = "1AC05AF367E3BDAEB1E5739321F389BB.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:09"
  condition:
    hash.sha256(0, filesize) == "5c4c829af18020bade14bf27d8da16c636ed390ba459cf0965d7d374bf60e7c3"
}
```

### Sample 6: `9f6fa0544c67bd2d`

| Field | Value |
|---|---|
| SHA-256 | `9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a` |
| Family label | `unknown` |
| File name | `9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a` |
| File type | `elf` |
| First seen | `2026-11-14 05:49:05` |
| Reporter | `honeyglass` |
| Tags | `elf, honeypot, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aae09f58a76ee11555d069c21da218b5` |
| SHA-1 | `5918fd176c1817288668222efcb022fc8cf8bae2` |
| SHA-256 | `9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a` |
| SHA3-384 | `390c9335272289db955db51ed182b2d18c8c8820d761174fec811680777641e00a6af19bd6bf2fe687d5bbaeb4d340c8` |
| TLSH | `T191D68C77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQN:cqYUQuVDt0TZEO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_9f6fa054
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a"
    family = "unknown"
    file_name = "9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a"
    file_type = "elf"
    first_seen = "2026-11-14 05:49:05"
  condition:
    hash.sha256(0, filesize) == "9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a"
}
```

### Sample 7: `293c02fd6ac3f30c`

| Field | Value |
|---|---|
| SHA-256 | `293c02fd6ac3f30c812d84fe9a0c07cd9377a864a5b18beb53532f5cfa5182cc` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 05:38:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac5e58d784d7471eb1156f77f7876182` |
| SHA-1 | `8519fe10ca340958b00764eb1756066479a49dcb` |
| SHA-256 | `293c02fd6ac3f30c812d84fe9a0c07cd9377a864a5b18beb53532f5cfa5182cc` |
| SHA3-384 | `e3de5583ae6b8f74b86b9f436924d79a93362bd595105440b4a718dda671b0c56743d2b8836c395129b95353bf784b66` |
| TLSH | `T1B7556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP4u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_293c02fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "293c02fd6ac3f30c812d84fe9a0c07cd9377a864a5b18beb53532f5cfa5182cc"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:38:06"
  condition:
    hash.sha256(0, filesize) == "293c02fd6ac3f30c812d84fe9a0c07cd9377a864a5b18beb53532f5cfa5182cc"
}
```

### Sample 8: `c06df0b480e58a40`

| Field | Value |
|---|---|
| SHA-256 | `c06df0b480e58a40690672cc8703304d357c7db9ce3a0a2fc36fe691b99b04e1` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 05:35:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ff0e843030dfa5aa19402755664ee3a` |
| SHA-1 | `af8d0ae42bc0e23c1a266c128fd13591b8829717` |
| SHA-256 | `c06df0b480e58a40690672cc8703304d357c7db9ce3a0a2fc36fe691b99b04e1` |
| SHA3-384 | `9bb3fc5bf9e00cae59b7ae9caac5246457b880ee4280e51ee7e7ee5c24581067a2f511af366a09334d6b429584a15da4` |
| TLSH | `T1CE556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSg:SDjxB4m5n8XlaPWi+d+a4TjxQP4W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_c06df0b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c06df0b480e58a40690672cc8703304d357c7db9ce3a0a2fc36fe691b99b04e1"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:35:05"
  condition:
    hash.sha256(0, filesize) == "c06df0b480e58a40690672cc8703304d357c7db9ce3a0a2fc36fe691b99b04e1"
}
```

### Sample 9: `8b39ee449a95bd8f`

| Field | Value |
|---|---|
| SHA-256 | `8b39ee449a95bd8faa401749f416948f8a2fe84833437e25a48880f960f92042` |
| Family label | `unknown` |
| File name | `8b39ee449a95bd8f.ps1` |
| File type | `ps1` |
| First seen | `2026-11-14 05:31:50` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e3649704ff72d2d5e90a07c4c34b9b8` |
| SHA-1 | `f540baa9939d3a542857502530e7bdbf042a9601` |
| SHA-256 | `8b39ee449a95bd8faa401749f416948f8a2fe84833437e25a48880f960f92042` |
| SHA3-384 | `a3895b8e2a90e33680c9565fbe68b86494c2f96fbeea3a494e0c25e44194705aa4f102ce1462379226f79ae00d458cf8` |
| TLSH | `T199D47E347A412EFF5BB820C248DA811C563C2679CA682DF669CB4CD3390D77627B79B1` |
| SSDEEP | `6144:BOYGn6GFtd6baZ+9aXGR6GQFaSHsZU7XHKKpsxPCWOqr9CfdpFaXyY3Kqc/22:UYGnorqVHS2XqK2CgBCfdpFaXZXc/22` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_8b39ee44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b39ee449a95bd8faa401749f416948f8a2fe84833437e25a48880f960f92042"
    family = "unknown"
    file_name = "8b39ee449a95bd8f.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 05:31:50"
  condition:
    hash.sha256(0, filesize) == "8b39ee449a95bd8faa401749f416948f8a2fe84833437e25a48880f960f92042"
}
```

### Sample 10: `166bcd1de1b46c70`

| Field | Value |
|---|---|
| SHA-256 | `166bcd1de1b46c709c49a1c4e914437ad0fff86bf7f15d9b975089a2cfa9613a` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 05:30:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97928ffa2a9aa341283fb1c2a7ab6341` |
| SHA-1 | `ff865a88a8438f92e052dd63bfc51857243f9b4f` |
| SHA-256 | `166bcd1de1b46c709c49a1c4e914437ad0fff86bf7f15d9b975089a2cfa9613a` |
| SHA3-384 | `02977d272e422002158d276f55b526fc58f8803eeecb1e762e86c3bb1d129565d1bc5843128a4f50cd8d5fe3754840d6` |
| TLSH | `T113556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSW:SDjxB4m5n8XlaPWi+d+a4TjxQP4I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_166bcd1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "166bcd1de1b46c709c49a1c4e914437ad0fff86bf7f15d9b975089a2cfa9613a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:30:04"
  condition:
    hash.sha256(0, filesize) == "166bcd1de1b46c709c49a1c4e914437ad0fff86bf7f15d9b975089a2cfa9613a"
}
```

### Sample 11: `13b556c8801c7912`

| Field | Value |
|---|---|
| SHA-256 | `13b556c8801c7912d3967e5f3014a23391f664fb9ee834df9257ba7b09cb0ffb` |
| Family label | `unknown` |
| File name | `pm` |
| File type | `elf` |
| First seen | `2026-11-14 05:28:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6794cab8a645674b2b9162713de1a41a` |
| SHA-1 | `4c1779136df851ec090a9f14416f2b89a1be5687` |
| SHA-256 | `13b556c8801c7912d3967e5f3014a23391f664fb9ee834df9257ba7b09cb0ffb` |
| SHA3-384 | `3fd9b7ac2b9a37d16bedbc508ef2707f51ebc470344d32bf2e461a9d7ef20c6b7cb4b6b09fb9b81d6465986f3e5ea624` |
| TLSH | `T1D5A733C98B724F059A7E3032D1DE2CA87D6135C668391DC75E8B6BE260CCF671929336` |
| SSDEEP | `786432:cHyV8PrU4zNFACLH0nyZLxvyLMEm4qVuaVKic3VxOL9GZnRFiouJ05645plb9GwM:+O0N+a0nYtO8pYxOmnfiLGc4h9GB/uE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_13b556c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13b556c8801c7912d3967e5f3014a23391f664fb9ee834df9257ba7b09cb0ffb"
    family = "unknown"
    file_name = "pm"
    file_type = "elf"
    first_seen = "2026-11-14 05:28:08"
  condition:
    hash.sha256(0, filesize) == "13b556c8801c7912d3967e5f3014a23391f664fb9ee834df9257ba7b09cb0ffb"
}
```

### Sample 12: `ec51bfb54e7bff0b`

| Field | Value |
|---|---|
| SHA-256 | `ec51bfb54e7bff0bfb40ab96a59d35994dceecff6323f8c718421823beb05d85` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 05:02:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eec99203c1f993e0071c780d38992df3` |
| SHA-1 | `63add493a38223118e362bc1dd49d58561b2dc7b` |
| SHA-256 | `ec51bfb54e7bff0bfb40ab96a59d35994dceecff6323f8c718421823beb05d85` |
| SHA3-384 | `9ddb6d5025de0a8e2b24ad4c39e039bfef693c4aacd91a356a461b06c04331d591723f7b8c3561a83a6ebd9806f1fef7` |
| TLSH | `T154556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS8:SDjxB4m5n8XlaPWi+d+a4TjxQP4m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_ec51bfb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec51bfb54e7bff0bfb40ab96a59d35994dceecff6323f8c718421823beb05d85"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:02:07"
  condition:
    hash.sha256(0, filesize) == "ec51bfb54e7bff0bfb40ab96a59d35994dceecff6323f8c718421823beb05d85"
}
```

### Sample 13: `9f778da58efe52cf`

| Field | Value |
|---|---|
| SHA-256 | `9f778da58efe52cfa14ac5ef5eab6312a5c545ac10f054e75d119e5dd9292f66` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 05:02:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e97425c0445f442b7c2d07cb52b1e44b` |
| SHA-1 | `c3d29481cd669483472724e66adc475ebebf12f3` |
| SHA-256 | `9f778da58efe52cfa14ac5ef5eab6312a5c545ac10f054e75d119e5dd9292f66` |
| SHA3-384 | `da24387e856ad52976caefa69cca097578b4eddc019193509548e891d7287cc16e1e06d08dd45e9bedc71506f65398dc` |
| TLSH | `T1E5556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSD:SDjxB4m5n8XlaPWi+d+a4TjxQP4x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_9f778da5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f778da58efe52cfa14ac5ef5eab6312a5c545ac10f054e75d119e5dd9292f66"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:02:05"
  condition:
    hash.sha256(0, filesize) == "9f778da58efe52cfa14ac5ef5eab6312a5c545ac10f054e75d119e5dd9292f66"
}
```

### Sample 14: `9fa1fa70fcc7bf86`

| Field | Value |
|---|---|
| SHA-256 | `9fa1fa70fcc7bf86a19a5292f8a9910d57349d3c1d17dc9297526625a3fe1e60` |
| Family label | `unknown` |
| File name | `Fontlayer.rtf` |
| File type | `rtf` |
| First seen | `2026-11-14 05:00:06` |
| Reporter | `abuse_ch` |
| Tags | `rtf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed8e95668be20dec93a5412657494613` |
| SHA-1 | `509d843dc2fb9d5baa14e5d4f46bd5eb2c886cd5` |
| SHA-256 | `9fa1fa70fcc7bf86a19a5292f8a9910d57349d3c1d17dc9297526625a3fe1e60` |
| SHA3-384 | `9bae326cafff10aa55b05484d90c20557e20cb84ef1db2fba5451c91cb9250d2a866572e43c40df52af2b76bec67bcc6` |
| TLSH | `T168D14130B8C7014285DE2DD73A43C4835778FB1B924B91FBA4E8E54CB2A6D3C9297E24` |
| SSDEEP | `96:c9kwquZunCMKcJJBjW64fOGqHzFta37ggw8tr7f4cgf9Rny96WWFM+z7aq6BeBx6:uZncJSfOGL37b5J7f4cgf/MmFt/d6E9+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rtf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_9fa1fa70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fa1fa70fcc7bf86a19a5292f8a9910d57349d3c1d17dc9297526625a3fe1e60"
    family = "unknown"
    file_name = "Fontlayer.rtf"
    file_type = "rtf"
    first_seen = "2026-11-14 05:00:06"
  condition:
    hash.sha256(0, filesize) == "9fa1fa70fcc7bf86a19a5292f8a9910d57349d3c1d17dc9297526625a3fe1e60"
}
```

### Sample 15: `1efa02c1dea0dbdc`

| Field | Value |
|---|---|
| SHA-256 | `1efa02c1dea0dbdc52610c873dca6d4c6caff4c456c0d606f558fadef02c4cb9` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 04:57:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09d9c023b9f49332c38292c1268d41a0` |
| SHA-1 | `b9e3c7fbefe3e75a35b4a348742e2fe966815e45` |
| SHA-256 | `1efa02c1dea0dbdc52610c873dca6d4c6caff4c456c0d606f558fadef02c4cb9` |
| SHA3-384 | `dfa6fae6c936a36955781d9b43ebd7711898cc13e9861f0d6c546e60339017f1e0759ca002bb7fcc6072e642ad132016` |
| TLSH | `T1AA556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSN:SDjxB4m5n8XlaPWi+d+a4TjxQP4P` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_1efa02c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1efa02c1dea0dbdc52610c873dca6d4c6caff4c456c0d606f558fadef02c4cb9"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 04:57:05"
  condition:
    hash.sha256(0, filesize) == "1efa02c1dea0dbdc52610c873dca6d4c6caff4c456c0d606f558fadef02c4cb9"
}
```

### Sample 16: `a9ce43c9d2f9d7e8`

| Field | Value |
|---|---|
| SHA-256 | `a9ce43c9d2f9d7e8990656e7c5b96e0fb7a65daabc1debfde86af1a0146353f6` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 04:54:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59ba6198f59b579ce3e269a72a2f94da` |
| SHA-1 | `0b6f0f32c1e997b3b5d274016bcb26c2a7a75db8` |
| SHA-256 | `a9ce43c9d2f9d7e8990656e7c5b96e0fb7a65daabc1debfde86af1a0146353f6` |
| SHA3-384 | `5ccda8c6731e68bf247609866a562086ce8cef9a818990c8bc509a72de7e04fac78db0ffa01880e284e1a065287cb699` |
| TLSH | `T1E3556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSx:SDjxB4m5n8XlaPWi+d+a4TjxQP4f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_a9ce43c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9ce43c9d2f9d7e8990656e7c5b96e0fb7a65daabc1debfde86af1a0146353f6"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 04:54:04"
  condition:
    hash.sha256(0, filesize) == "a9ce43c9d2f9d7e8990656e7c5b96e0fb7a65daabc1debfde86af1a0146353f6"
}
```

### Sample 17: `3f6d950304146e67`

| Field | Value |
|---|---|
| SHA-256 | `3f6d950304146e671ff9de563d3861b60112eed39b13fba4e8bd293750bdcff0` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-14 04:36:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aadcef95d343e62dc77ddd0109af26b3` |
| SHA-1 | `c2e02467f8af3d8e43bf4b57d0059fd6780be1b6` |
| SHA-256 | `3f6d950304146e671ff9de563d3861b60112eed39b13fba4e8bd293750bdcff0` |
| SHA3-384 | `62345ff95c4750917768e3f835e506cdbd74cab7c72c4a7aadf397509b5437ec8c8791269711bd723556b4c9431cacde` |
| TLSH | `T1A1231894B9829A16CAD0437BFE0E42DD3725A398E2DE3313DD225F6137CB92B0DA7151` |
| TELFHASH | `t1f4c02b279c0901e0b2d31a4ac22c67239a82804b49b32d14f3c82fdea89ad8274d8935` |
| SSDEEP | `768:mXYesyi5wPVQEkJVvOwxPFV4iRu6Jj3oSCA6gPj5+uB4Pl5Q1YL0xkbUFqBgEk9H:jZe4vrR476JdTPj5+uBaluZObUoBEH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_3f6d9503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f6d950304146e671ff9de563d3861b60112eed39b13fba4e8bd293750bdcff0"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-14 04:36:04"
  condition:
    hash.sha256(0, filesize) == "3f6d950304146e671ff9de563d3861b60112eed39b13fba4e8bd293750bdcff0"
}
```

### Sample 18: `db8ecda653be2e9d`

| Field | Value |
|---|---|
| SHA-256 | `db8ecda653be2e9df847966f2ef6fbfb7879423ab4459447883ab9c82473bfa7` |
| Family label | `Arechclient2` |
| File name | `eunewport.msi` |
| File type | `msi` |
| First seen | `2026-11-14 04:33:41` |
| Reporter | `iamaachum` |
| Tags | `212-43-144-80, Arechclient2, AsgardProtector, dropped-by-ACRStealer, msi, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad6a126de48213ba102fe30c61b34c5` |
| SHA-1 | `be8e1f305a26e2e47aa205ef0f1dcb9c33bc238c` |
| SHA-256 | `db8ecda653be2e9df847966f2ef6fbfb7879423ab4459447883ab9c82473bfa7` |
| SHA3-384 | `7f74be3ff03021cdaaa1f3386cdc178564da294167790f0690d1e09f3ac5b58423c24481a1e1dd4c68d70ea6675be27f` |
| TLSH | `T1A475332F28198138EA715E3E2D2F978E9608BC251B458A23F78DB12E5DB9CF771301D5` |
| SSDEEP | `49152:hWIr/Ctw8h6MAH8qfbSC6X0yB+rGc43iaG:mtdsMSTfGXrkKc4SaG` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_018_db8ecda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db8ecda653be2e9df847966f2ef6fbfb7879423ab4459447883ab9c82473bfa7"
    family = "Arechclient2"
    file_name = "eunewport.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:33:41"
  condition:
    hash.sha256(0, filesize) == "db8ecda653be2e9df847966f2ef6fbfb7879423ab4459447883ab9c82473bfa7"
}
```

### Sample 19: `a6611a44c32bc8ba`

| Field | Value |
|---|---|
| SHA-256 | `a6611a44c32bc8ba9194298db09c49f1914dffa5ae30a9acb60b2b0641dc802d` |
| Family label | `unknown` |
| File name | `saret.msi` |
| File type | `msi` |
| First seen | `2026-11-14 04:26:37` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28858c557194d7d7d62ed5ffb1206889` |
| SHA-1 | `f98fef150e0e0d720a33a252f2a9fbfbbcb3e95b` |
| SHA-256 | `a6611a44c32bc8ba9194298db09c49f1914dffa5ae30a9acb60b2b0641dc802d` |
| SHA3-384 | `4a8f5b5c242105c8ce22cb776ff87d9e2f1578231a760fa86d5191959d6497a775cf21f64ed865294ce68546a9cc08c7` |
| TLSH | `T17FB633FA749347F2CB09457A4B13BBC057593C7A629041828ABC7ADE5770EB07871EB2` |
| SSDEEP | `196608:hc5l64Wr2VzZiT+ghw6IMAcnpzDxYqIammTNep:h+64qcmgMAWHxYqQOw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_a6611a44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6611a44c32bc8ba9194298db09c49f1914dffa5ae30a9acb60b2b0641dc802d"
    family = "unknown"
    file_name = "saret.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:26:37"
  condition:
    hash.sha256(0, filesize) == "a6611a44c32bc8ba9194298db09c49f1914dffa5ae30a9acb60b2b0641dc802d"
}
```

### Sample 20: `414c9037dce45944`

| Field | Value |
|---|---|
| SHA-256 | `414c9037dce4594441fcf9e835ed11520ec9b6d434718913351ef6d6ba1f547e` |
| Family label | `Arechclient2` |
| File name | `port80.msi` |
| File type | `msi` |
| First seen | `2026-11-14 04:25:52` |
| Reporter | `iamaachum` |
| Tags | `145-63-136-141, Arechclient2, AsgardProtector, dropped-by-ACRStealer, msi, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `501238e875efc3ff4353f4deb2e3df98` |
| SHA-1 | `148edb93f4c137105cdb8ef0db51e870fdf55412` |
| SHA-256 | `414c9037dce4594441fcf9e835ed11520ec9b6d434718913351ef6d6ba1f547e` |
| SHA3-384 | `3cacd59e240d7fde0fe9c8b0afda40b7dd8d6d8eb349f2e5686a7c43759efafd6e0fa16a01003f92e96885d664260c62` |
| TLSH | `T17E3633ACB59A2717F4175131370C2932D72EDFA5A78A4347A6D6FE2C2F72EB4906024C` |
| SSDEEP | `98304:BdIgmwEx7PQ4aqGr1r0gmlxEOrtPb51rglvUFzF0mB9yVomXI8Yu9u7:IVx7Q4bfgms0tNh2UFKm18RA` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_020_414c9037
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "414c9037dce4594441fcf9e835ed11520ec9b6d434718913351ef6d6ba1f547e"
    family = "Arechclient2"
    file_name = "port80.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:25:52"
  condition:
    hash.sha256(0, filesize) == "414c9037dce4594441fcf9e835ed11520ec9b6d434718913351ef6d6ba1f547e"
}
```

### Sample 21: `10031cfa9d5c5bd0`

| Field | Value |
|---|---|
| SHA-256 | `10031cfa9d5c5bd08ff5dde4837902a56e7b33268cfc6710a8afcf150d960f54` |
| Family label | `unknown` |
| File name | `clsar.msi` |
| File type | `msi` |
| First seen | `2026-11-14 04:24:37` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f60b727015037e007170b1edf91cf97f` |
| SHA-1 | `d78452f634e8a52bc502e60cf00bda1c92c5f6c3` |
| SHA-256 | `10031cfa9d5c5bd08ff5dde4837902a56e7b33268cfc6710a8afcf150d960f54` |
| SHA3-384 | `1bc83d59c9ec494a44d5be7f19fb6061fff21f4d2d5fcbeccf0c87bb604a891716f115039903acacbb6ea24d2307a4b1` |
| TLSH | `T1FD0733EBB44707E4C5A86737422F418F4A187E3A57BB553B728477392532239A1AF338` |
| SSDEEP | `393216:CjOSfwDeL1NaNgiR7rOYSe8z79ebyGGNRK+Iqkf4:2OOfLHaN75V8X94yGGNom` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_10031cfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10031cfa9d5c5bd08ff5dde4837902a56e7b33268cfc6710a8afcf150d960f54"
    family = "unknown"
    file_name = "clsar.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:24:37"
  condition:
    hash.sha256(0, filesize) == "10031cfa9d5c5bd08ff5dde4837902a56e7b33268cfc6710a8afcf150d960f54"
}
```

### Sample 22: `9249268a2808ef5c`

| Field | Value |
|---|---|
| SHA-256 | `9249268a2808ef5c8a209a3cb1e378ffb341598a8e205c74b5911317e856dfcf` |
| Family label | `njrat` |
| File name | `C51D39BF1109C2E39CBCA82AC8747F51.exe` |
| File type | `exe` |
| First seen | `2026-11-14 04:05:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c51d39bf1109c2e39cbca82ac8747f51` |
| SHA-1 | `e27af31479a869818aedc47cf80c4810a0a7880b` |
| SHA-256 | `9249268a2808ef5c8a209a3cb1e378ffb341598a8e205c74b5911317e856dfcf` |
| SHA3-384 | `dcea0931550e5e6d87d06b55d44e362fca494b7dec019fdeb800045eb4000620facc9a7371a7d49bb631887a2f32c21f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18AB2D589B7B48614C2AE4E7848A3331547B0B3C7C941CB5B0DEA40991F17BD66912FFE` |
| SSDEEP | `384:pW63V0USlKXMWqJmXuJMx19hAUmH2dPZ6AaOWQ+dcs//34LAZSTnlV:463V0UqKXzqoXuJ8n6/aPMIWQuHqHV` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_022_9249268a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9249268a2808ef5c8a209a3cb1e378ffb341598a8e205c74b5911317e856dfcf"
    family = "njrat"
    file_name = "C51D39BF1109C2E39CBCA82AC8747F51.exe"
    file_type = "exe"
    first_seen = "2026-11-14 04:05:08"
  condition:
    hash.sha256(0, filesize) == "9249268a2808ef5c8a209a3cb1e378ffb341598a8e205c74b5911317e856dfcf"
}
```

### Sample 23: `e02a83e5315ba466`

| Field | Value |
|---|---|
| SHA-256 | `e02a83e5315ba466a90c277eec18beb3ac88b41216de4a13ca754b3c53b8a9ce` |
| Family label | `unknown` |
| File name | `ClientExt.zip` |
| File type | `zip` |
| First seen | `2026-11-14 03:48:59` |
| Reporter | `iamaachum` |
| Tags | `crx, dropped-by-CountLoader, undefined-vg` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eea929b34156f5a5048ed2f19f1f9fe7` |
| SHA-1 | `4fbe8bc1fd39073375cc155b96ca5406d4d4c057` |
| SHA-256 | `e02a83e5315ba466a90c277eec18beb3ac88b41216de4a13ca754b3c53b8a9ce` |
| SHA3-384 | `fa9856f876ddb820df036b6e315aa82234ce0c4e1d7aa4fe1b6d4b643e59b477e18bf128c315cf04c1d1e1086c546c23` |
| TLSH | `T1A4B312E1E567217CDA779F351A9286A69CBED32C30B0C722A23011416F79A9877F134F` |
| SSDEEP | `3072://Aidna1i1GSNRwo3ARXyhaF6ZYSKHBrjlctO://AiduiAu+gAVyUF+/a7cg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_e02a83e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e02a83e5315ba466a90c277eec18beb3ac88b41216de4a13ca754b3c53b8a9ce"
    family = "unknown"
    file_name = "ClientExt.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:48:59"
  condition:
    hash.sha256(0, filesize) == "e02a83e5315ba466a90c277eec18beb3ac88b41216de4a13ca754b3c53b8a9ce"
}
```

### Sample 24: `6750a40cbec4bed0`

| Field | Value |
|---|---|
| SHA-256 | `6750a40cbec4bed0ad8370c53bc8aea35afdc7d48d89ec314423787fcb3493f8` |
| Family label | `unknown` |
| File name | `PlannerExt.msi` |
| File type | `exe` |
| First seen | `2026-11-14 03:48:31` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-CountLoader, exe, undefined-vg` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e94c7b15beceefc01db3c458bb7ee210` |
| SHA-1 | `492f25006294c361e036490437050049e14a695a` |
| SHA-256 | `6750a40cbec4bed0ad8370c53bc8aea35afdc7d48d89ec314423787fcb3493f8` |
| SHA3-384 | `01a8b194c29bc437f54fed1da7bd798e1439c09243f09e571e15dc73ccf1ceadee7384350f10daba37dac96b43a264dc` |
| TLSH | `T1EF251716B6E79EB2D2890B33D2D36D0453E1D854271BE75B76CA2B6A1C037EE8D13207` |
| SSDEEP | `12288:NGyFsZZH3ga9rW3YTxdGiQmq6QN3gmc+a/Oej1AtaXaQHbEJSkk7j4/l22yP6Lj9:NxFgOaReMdQN36+c1AtiaOgejU2Ha` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_6750a40c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6750a40cbec4bed0ad8370c53bc8aea35afdc7d48d89ec314423787fcb3493f8"
    family = "unknown"
    file_name = "PlannerExt.msi"
    file_type = "exe"
    first_seen = "2026-11-14 03:48:31"
  condition:
    hash.sha256(0, filesize) == "6750a40cbec4bed0ad8370c53bc8aea35afdc7d48d89ec314423787fcb3493f8"
}
```

### Sample 25: `03b5abfd235a0f6a`

| Field | Value |
|---|---|
| SHA-256 | `03b5abfd235a0f6a5ec9e7c2cf7793c72bf83065e430b5502a033d42bcd64247` |
| Family label | `unknown` |
| File name | `planner.ps1` |
| File type | `ps1` |
| First seen | `2026-11-14 03:46:18` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-CountLoader, ps1, undefined-vg` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `710a10b91a7ecf21a3db0724055f6f63` |
| SHA-1 | `06055f7bb9efb9a65d754de8e6da571a6aa3e211` |
| SHA-256 | `03b5abfd235a0f6a5ec9e7c2cf7793c72bf83065e430b5502a033d42bcd64247` |
| SHA3-384 | `34030e131545723b65ab6e2c526a9a8193ec7f8a9fe30392784ff4418de39819864283663e763bb7a7a1b8da61d5b900` |
| TLSH | `T18672B68313419ABAF5CE27B7EC47150474F88829F99E0154FBBEBCD7A6AAC404638F45` |
| SSDEEP | `384:qTGcjmVuBUh+FHAv5AOq4tpReScTIrRGrPlJ64/yjTp:qqcCgBJgJWSJVGr64/yjTp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_03b5abfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03b5abfd235a0f6a5ec9e7c2cf7793c72bf83065e430b5502a033d42bcd64247"
    family = "unknown"
    file_name = "planner.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 03:46:18"
  condition:
    hash.sha256(0, filesize) == "03b5abfd235a0f6a5ec9e7c2cf7793c72bf83065e430b5502a033d42bcd64247"
}
```

### Sample 26: `4207523717b12dcb`

| Field | Value |
|---|---|
| SHA-256 | `4207523717b12dcbc8587bca72a7aca4a274823f3ca14c1e8ede7b2ca792798b` |
| Family label | `SnappyClient` |
| File name | `test.exe` |
| File type | `exe` |
| First seen | `2026-11-14 03:44:36` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-WARDENStealer, exe, kl-keepwqlo-rest, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `890afefecc2c1ef0fca404160082604f` |
| SHA-1 | `1206cb52fd113ba2ad8ba259c5a8682427c3f08e` |
| SHA-256 | `4207523717b12dcbc8587bca72a7aca4a274823f3ca14c1e8ede7b2ca792798b` |
| SHA3-384 | `dd0bf6c91187e1e2204de12698d4fb11cd6538ccbe42f2333f0183c4a198f2b8eb4f79c5137e082e35cdf1227f6011db` |
| IMPHASH | `5a6983d66b332fba3e2f7d42eab331a3` |
| TLSH | `T171068D1226C286F9E3415270AD88BABC47ACAAFC97FF54B777D40AC94D189C3752520F` |
| SSDEEP | `98304:F5Ce6SRSm7T5p1iRPenmciXjlt3Bvu8lHN3fj+pzQJfUHN:HNlRSm7tpoPrXjlKafj+0U` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_026_42075237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4207523717b12dcbc8587bca72a7aca4a274823f3ca14c1e8ede7b2ca792798b"
    family = "SnappyClient"
    file_name = "test.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:44:36"
  condition:
    hash.sha256(0, filesize) == "4207523717b12dcbc8587bca72a7aca4a274823f3ca14c1e8ede7b2ca792798b"
}
```

### Sample 27: `d61bb5af4b2b1aee`

| Field | Value |
|---|---|
| SHA-256 | `d61bb5af4b2b1aeeb7bd03c2afd2801d1a3c9bf8c9dab61ccf1dc7c1cd6fb1c4` |
| Family label | `CoinMiner` |
| File name | `vlc_play.exe` |
| File type | `exe` |
| First seen | `2026-11-14 03:43:34` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, corvusminer, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43525f10a89e521ba2884d308adefbf8` |
| SHA-1 | `129a73a6619d5b8184265f130e5e99a7776e5a4e` |
| SHA-256 | `d61bb5af4b2b1aeeb7bd03c2afd2801d1a3c9bf8c9dab61ccf1dc7c1cd6fb1c4` |
| SHA3-384 | `c8ce705902e12ff1594808f71cd0bc394e50b07b730828ebc0e948af6fa8152c6d6809e0601d62cd6cffe4dc31468179` |
| IMPHASH | `fa0131e48833912d7e50b30e750ff920` |
| TLSH | `T16CA6F007F8A109EAD1AEF13185366612FB717C841B3163D72A94B2683F72BD06DB4778` |
| SSDEEP | `98304:oxs0tbxL953+f83hBTxmUu04VKCahs3o9uRNRYyReEiJdfV:Wrb3+UxZxmUl4VKnuHRYtHz` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_027_d61bb5af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d61bb5af4b2b1aeeb7bd03c2afd2801d1a3c9bf8c9dab61ccf1dc7c1cd6fb1c4"
    family = "CoinMiner"
    file_name = "vlc_play.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:43:34"
  condition:
    hash.sha256(0, filesize) == "d61bb5af4b2b1aeeb7bd03c2afd2801d1a3c9bf8c9dab61ccf1dc7c1cd6fb1c4"
}
```

### Sample 28: `7beec4dee8c908d9`

| Field | Value |
|---|---|
| SHA-256 | `7beec4dee8c908d938abbf1d68cf759491a2ea3c3bbab6662162f668c5ea5e8b` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-14 03:31:11` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, rest-hazeldriftton-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cadd8865ac9b98d28dc7ac482d0a864` |
| SHA-1 | `633246836b345c93361ed6179668e111748f101a` |
| SHA-256 | `7beec4dee8c908d938abbf1d68cf759491a2ea3c3bbab6662162f668c5ea5e8b` |
| SHA3-384 | `9c7d9b1edfc751b0fe17f7d753c9b053fa2ea8b9b27b5b8012480c980f0ac9ae85aa289a5d83d8ecfb61a4b68bdf0bd1` |
| TLSH | `T14C87336CF8BDB84AF0B4677AC0855C7AE71DE542D7F42C5B8F2880857C8314E2F66896` |
| SSDEEP | `786432:ZxLL60ewFPRAls4vezOziNIyj+FWs4vGOPwjAF1D0V93wQUa+GXfRcpTVs4vV:Z4CF2nvEZ+WnvyI166IvR4VnvV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_7beec4de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7beec4dee8c908d938abbf1d68cf759491a2ea3c3bbab6662162f668c5ea5e8b"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:31:11"
  condition:
    hash.sha256(0, filesize) == "7beec4dee8c908d938abbf1d68cf759491a2ea3c3bbab6662162f668c5ea5e8b"
}
```

### Sample 29: `2e643fb2023f10c8`

| Field | Value |
|---|---|
| SHA-256 | `2e643fb2023f10c81c71ada63ed10f865ea5741e475505ce8514d88d8f82a670` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-14 03:30:19` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, console-mottlewickton-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d48ae1c5110f126cc415655bd8c15dc3` |
| SHA-1 | `ceb3981bc5918bfa8ae85080ed28035cfd5aef91` |
| SHA-256 | `2e643fb2023f10c81c71ada63ed10f865ea5741e475505ce8514d88d8f82a670` |
| SHA3-384 | `fdb63971a646aa7773114e917b19ea3a448f712475b3b424ac4a870422efcf1319eeb246e02fe5bd7d862e86869e24c6` |
| TLSH | `T1BAB73300AC9B8F42C42BB63ED0DA2B0FBA42E70356B7910B539C92591D73D725B56B4F` |
| SSDEEP | `786432:wlYYO9H+lYYO75UP8CM3OKlYYOaYUsZAM3/jkmgt47g3vTlYYOAjUsMAW/nQHbg7:w2YO9e2YO75UP8CYp2YOfN7kl47cb2YQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_2e643fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e643fb2023f10c81c71ada63ed10f865ea5741e475505ce8514d88d8f82a670"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:30:19"
  condition:
    hash.sha256(0, filesize) == "2e643fb2023f10c81c71ada63ed10f865ea5741e475505ce8514d88d8f82a670"
}
```

### Sample 30: `6f4ccc1718eddb12`

| Field | Value |
|---|---|
| SHA-256 | `6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2` |
| Family label | `WARDENStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-11-14 03:29:24` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fff315917c102d44430d45cdb48c926` |
| SHA-1 | `194f4b38b5cd11c5115af97b46156c156286d661` |
| SHA-256 | `6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2` |
| SHA3-384 | `893d11e924f2c9d90b36de6d415d5601e17639ec06d1be296924c8577fce1bfd4591429c2fc5a57cb134942832e3179a` |
| IMPHASH | `d79c8bb8be4d41a226a2d372ac497e67` |
| TLSH | `T152E4F1A2F69A89FCD027C13886125502FA797C15472069FB5384AB7E1F366D6CF3DB10` |
| SSDEEP | `12288:eDksJMjSezLbXkOivYmuaT3OVEVYkbY0EO8me+xk0ZUOEyMt6AcU:WJqSjOKBuVQls0Cm2OctrcU` |
| ICON-DHASH | `9671e0d4d4e87196` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_030_6f4ccc17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:29:24"
  condition:
    hash.sha256(0, filesize) == "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2"
}
```

### Sample 31: `3647f1dd11b4a28e`

| Field | Value |
|---|---|
| SHA-256 | `3647f1dd11b4a28e65e03c997b14f1507cfb07ffc412f4b5790dd2b4ec293f92` |
| Family label | `unknown` |
| File name | `Launcher14374.exe` |
| File type | `exe` |
| First seen | `2026-11-14 03:28:35` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79385e3c89f86ef1f45d66ad1d249b54` |
| SHA-1 | `33bb5f17c30d278694f63af25a4cbdf0a5a545c5` |
| SHA-256 | `3647f1dd11b4a28e65e03c997b14f1507cfb07ffc412f4b5790dd2b4ec293f92` |
| SHA3-384 | `6738fdecf2479e689d7772dc3b698f599b1e0fab22efe9dce3c026d239a5f0b90484bcf25e1ad5a30e668581b76140a9` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T10BF633D0BFA06C4BE9F95B3EF47167A712F72E85768E105CF2558B72E932622400B1E1` |
| SSDEEP | `393216:UFj9DMhVEAEJd+TuZmfA6Q87GtpjozOQJvhG:e9gXEATCEf/6/jozFvhG` |
| ICON-DHASH | `e9c9d1d0bce8d818` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_3647f1dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3647f1dd11b4a28e65e03c997b14f1507cfb07ffc412f4b5790dd2b4ec293f92"
    family = "unknown"
    file_name = "Launcher14374.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:28:35"
  condition:
    hash.sha256(0, filesize) == "3647f1dd11b4a28e65e03c997b14f1507cfb07ffc412f4b5790dd2b4ec293f92"
}
```

### Sample 32: `670c682101631a15`

| Field | Value |
|---|---|
| SHA-256 | `670c682101631a1544f4d0b566096f5a2ad9b8bd4967e015871524d406b5c78c` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-11-14 03:28:08` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69b9f5ab2ba45a1ccf20f4629d696544` |
| SHA-1 | `4be38d841e8816993f0455247f2d560bcedef674` |
| SHA-256 | `670c682101631a1544f4d0b566096f5a2ad9b8bd4967e015871524d406b5c78c` |
| SHA3-384 | `1288b437590c2c8bfc36914355047d1262040c73eebe6c027f6e75ed04476d2b63a3a106e6996158fab501d7fc3d8bb8` |
| TLSH | `T1ACF633D0BFA05C4BE9F95B3EF47167A712F72E85768A101CB25D8775EB32622400B2E1` |
| SSDEEP | `393216:sFj9DMhVEAEJd+TuZmfA6Q87GtpjozOQJvhG:m9gXEATCEf/6/jozFvhG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_670c6821
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "670c682101631a1544f4d0b566096f5a2ad9b8bd4967e015871524d406b5c78c"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-14 03:28:08"
  condition:
    hash.sha256(0, filesize) == "670c682101631a1544f4d0b566096f5a2ad9b8bd4967e015871524d406b5c78c"
}
```

### Sample 33: `8c0cee06c37e6290`

| Field | Value |
|---|---|
| SHA-256 | `8c0cee06c37e6290894b97914dc4b1144e52d8fc70507c572a8b3a3b9325089b` |
| Family label | `unknown` |
| File name | `Installer_L_X64_x86_2024.zip` |
| File type | `zip` |
| First seen | `2026-11-14 03:26:28` |
| Reporter | `iamaachum` |
| Tags | `HijackLoader, IDATLoader, new-label-club, SnappyClient, WARDENStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b70d3f70e6297cd8a6d3ce8440d6619d` |
| SHA-1 | `9b339a7f78b31c889d373b9202203adcd993b048` |
| SHA-256 | `8c0cee06c37e6290894b97914dc4b1144e52d8fc70507c572a8b3a3b9325089b` |
| SHA3-384 | `28b53561da6381d5a37f21b1054bf6ee555b08af58143b0d7d34f7abbc2d2fb6dc389761a27d964e64d47787b3f2b19d` |
| TLSH | `T15DD733ACAB9D408AD37B67B5A4C26A8DB065D60A4710FA3F425C21401CA77FF4F5BB07` |
| SSDEEP | `1572864:lCOTmC/dWPKz/AeG4IdtoCv8pW2jwp38eLOsG0wwSzCT:lRTmCg/e0toCwdjVeys5Szq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_8c0cee06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0cee06c37e6290894b97914dc4b1144e52d8fc70507c572a8b3a3b9325089b"
    family = "unknown"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:26:28"
  condition:
    hash.sha256(0, filesize) == "8c0cee06c37e6290894b97914dc4b1144e52d8fc70507c572a8b3a3b9325089b"
}
```

### Sample 34: `3c9b11a05c2d8701`

| Field | Value |
|---|---|
| SHA-256 | `3c9b11a05c2d8701da8afaffd9e9b68816191c0e107162dba6c3dc1fabc80c96` |
| Family label | `njrat` |
| File name | `69420AFE2FFE9D4E5C9DE7F811CB43B2.exe` |
| File type | `exe` |
| First seen | `2026-11-14 03:05:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69420afe2ffe9d4e5c9de7f811cb43b2` |
| SHA-1 | `95e51af6466899ab0a1f204716a1d7eac3accc58` |
| SHA-256 | `3c9b11a05c2d8701da8afaffd9e9b68816191c0e107162dba6c3dc1fabc80c96` |
| SHA3-384 | `391f18cfafef3f9b1e808fc537bf0e568d67963ebe9803dc81b9cef1becb73747993835abe6a2cd7389478bf299d33e3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12DA2E649B7A48209D2DD5AB848A3731847B0F3C7D981CB570DE610CA2F27BD16952FEE` |
| SSDEEP | `384:vW6RUSl62XMCVCzJZh1hSC8mHDaOWQ+dcs//34LAZSTizHiTSTCDnU:+6RUq62X/O7MCHXWQuHq9U` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_034_3c9b11a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c9b11a05c2d8701da8afaffd9e9b68816191c0e107162dba6c3dc1fabc80c96"
    family = "njrat"
    file_name = "69420AFE2FFE9D4E5C9DE7F811CB43B2.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:05:09"
  condition:
    hash.sha256(0, filesize) == "3c9b11a05c2d8701da8afaffd9e9b68816191c0e107162dba6c3dc1fabc80c96"
}
```

### Sample 35: `b533bbf00d28721b`

| Field | Value |
|---|---|
| SHA-256 | `b533bbf00d28721b87e58052a26ebdbd8183cafa0eb30f1ba639818a07cb0d6c` |
| Family label | `WARDENStealer` |
| File name | `file_patched.exe` |
| File type | `exe` |
| First seen | `2026-11-14 03:01:32` |
| Reporter | `iamaachum` |
| Tags | `de-pumped, exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2b9022fd77b4f7de9c9498db88aaca8` |
| SHA-1 | `ac3f87b82fff745ceda0ad9d0cd09bb4de22b61a` |
| SHA-256 | `b533bbf00d28721b87e58052a26ebdbd8183cafa0eb30f1ba639818a07cb0d6c` |
| SHA3-384 | `b650623f040fb15e8e9cae6ce28e221288bf9a5a3d9df1cbdcb7d8600c49dabdc8f246135e5d1a076575a3b7925ecbd7` |
| IMPHASH | `820c1c79cdfa735bd6a5ebc442efa425` |
| TLSH | `T15F678C42B3E80196E4BBD63889BB4A13EB72BC505B61C3CF1264961D1F737C16E39366` |
| SSDEEP | `393216:QwA6JnIZxvhxDqXE6Gm5vmChAbOazWmcfqpiu3A:/AkKhksWmcSpiu` |
| ICON-DHASH | `c492a2e8e8e0e896` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_035_b533bbf0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b533bbf00d28721b87e58052a26ebdbd8183cafa0eb30f1ba639818a07cb0d6c"
    family = "WARDENStealer"
    file_name = "file_patched.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:01:32"
  condition:
    hash.sha256(0, filesize) == "b533bbf00d28721b87e58052a26ebdbd8183cafa0eb30f1ba639818a07cb0d6c"
}
```

### Sample 36: `bf49eedeafd28b7b`

| Field | Value |
|---|---|
| SHA-256 | `bf49eedeafd28b7b0f2718aeae9f26e5f700229a0ad2d251a91a87a7c2c4f46c` |
| Family label | `WARDENStealer` |
| File name | `file.7z` |
| File type | `7z` |
| First seen | `2026-11-14 03:00:57` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-8081, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e31261289dfca12cf333b828715cf9f8` |
| SHA-1 | `b1998c1b6dde839748d3e0aa2592f1c437ff5f4c` |
| SHA-256 | `bf49eedeafd28b7b0f2718aeae9f26e5f700229a0ad2d251a91a87a7c2c4f46c` |
| SHA3-384 | `cf9fbd832664956199cde308fb9915b96eb541f2ba25ad67ba7aa219752a828cb93e8435c6145ee10e7e04b1798384e7` |
| TLSH | `T1B8E633122BBD60C851C8D4AAA5FEEE9CCBCCA002A414AD9742E35D779F35C5C16D84FA` |
| SSDEEP | `393216:Y8mrQTvpPGoagIpkfh/UeXOQnCWHl66QtHrK:yEhGoTNOQJARm` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_036_bf49eede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf49eedeafd28b7b0f2718aeae9f26e5f700229a0ad2d251a91a87a7c2c4f46c"
    family = "WARDENStealer"
    file_name = "file.7z"
    file_type = "7z"
    first_seen = "2026-11-14 03:00:57"
  condition:
    hash.sha256(0, filesize) == "bf49eedeafd28b7b0f2718aeae9f26e5f700229a0ad2d251a91a87a7c2c4f46c"
}
```

### Sample 37: `46080f4595775290`

| Field | Value |
|---|---|
| SHA-256 | `46080f459577529059ace98473cfd80693744444c8ef828ff5f7377eb10906a0` |
| Family label | `njrat` |
| File name | `2eef62668e8a3ef3124b823f990809c8.exe` |
| File type | `exe` |
| First seen | `2026-11-14 02:55:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eef62668e8a3ef3124b823f990809c8` |
| SHA-1 | `9f920216394dd90e679fc00760ac1b1d7f1bf74d` |
| SHA-256 | `46080f459577529059ace98473cfd80693744444c8ef828ff5f7377eb10906a0` |
| SHA3-384 | `996cd30336b2849be007414ac118e897ebe88f897c46961498fc65f02810c19bd6e55bf52d7d1ea6e32c9ea8fb24b9e1` |
| IMPHASH | `ab6770b0a8635b9d92a5838920cfe770` |
| TLSH | `T100D5333F8244DE5DCB51753C0B66E2FAF6161C0724016F92D26BBAFA8F5415BEE242C8` |
| SSDEEP | `49152:mBeVODQk/79BnSuoI09+HhyFGwf1HmznWRmxel/+q4Dp:MeVORZEHI0QHgswfBoesq4Dp` |
| ICON-DHASH | `c4ccb392f1f192cc` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_037_46080f45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46080f459577529059ace98473cfd80693744444c8ef828ff5f7377eb10906a0"
    family = "njrat"
    file_name = "2eef62668e8a3ef3124b823f990809c8.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:55:07"
  condition:
    hash.sha256(0, filesize) == "46080f459577529059ace98473cfd80693744444c8ef828ff5f7377eb10906a0"
}
```

### Sample 38: `4112a8b0d908bbff`

| Field | Value |
|---|---|
| SHA-256 | `4112a8b0d908bbffd9bef308a5c48cf692af00b7624443f56540c23a9e0a9a48` |
| Family label | `unknown` |
| File name | `4112a8b0d908bbff.ps1` |
| File type | `ps1` |
| First seen | `2026-11-14 02:47:00` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0434c4056b0be7b7ea027da707f7874` |
| SHA-1 | `e46c7d5b4a9b41ddae4281ee9c3471439e9bdfd6` |
| SHA-256 | `4112a8b0d908bbffd9bef308a5c48cf692af00b7624443f56540c23a9e0a9a48` |
| SHA3-384 | `184f1762615404653db591e38bf1eba201aef3e09e48754030e472f8c82d6dad772ae6cd2579dda084b72a6735f6f53e` |
| TLSH | `T1F8E47E347E062EFF5BAC20C248CA811C563832B8DA686DF56ACF4C96390D77917B7971` |
| SSDEEP | `12288:EhF4abtU2mWBOrCQ3YRY+pHBy/LYCATlxwoN0uhvCESadxziAhqOVb:gjmeWCtB88eoGgCESadxzBqGb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_4112a8b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4112a8b0d908bbffd9bef308a5c48cf692af00b7624443f56540c23a9e0a9a48"
    family = "unknown"
    file_name = "4112a8b0d908bbff.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 02:47:00"
  condition:
    hash.sha256(0, filesize) == "4112a8b0d908bbffd9bef308a5c48cf692af00b7624443f56540c23a9e0a9a48"
}
```

### Sample 39: `6084961e6a2430ff`

| Field | Value |
|---|---|
| SHA-256 | `6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963` |
| Family label | `ConnectWise` |
| File name | `6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963.msi` |
| File type | `msi` |
| First seen | `2026-11-14 02:46:11` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4fca7df8c0fd4e1d62d63fa967a84a1` |
| SHA-1 | `61dcb12c3289b28c820d899b3d251cd941b19f0b` |
| SHA-256 | `6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963` |
| SHA3-384 | `bb94418aecda1db9fa16edaf4733513cdbe564c79a3d7d05e4ff333597204c2ba5f466a6aa5540de388bd0621c1cbe3d` |
| TLSH | `T121E60112EBA84577F4A24A74BA3665938526AC37B811CC1E16DB741F1B33F718D32E32` |
| SSDEEP | `393216:4cVPOBdFcVPOccVPOUcVPObcVPOnwcVPOnMcVPOnt:4cVmBdFcVmccVmUcVmbcVmnwcVmnMcVg` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_039_6084961e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963"
    family = "ConnectWise"
    file_name = "6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963.msi"
    file_type = "msi"
    first_seen = "2026-11-14 02:46:11"
  condition:
    hash.sha256(0, filesize) == "6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963"
}
```

### Sample 40: `fdeed4bbb15996a5`

| Field | Value |
|---|---|
| SHA-256 | `fdeed4bbb15996a5a11f7038740cceefb80e89c7e2e0b9db7c74f18dded3c9e4` |
| Family label | `WARDENStealer` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-11-14 02:44:44` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, WARDENStealer, wooocommerce-shopping` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcde03f9d0f55392117d48657b12b946` |
| SHA-1 | `0d068140197f813e4f990d79b4d4fba6787cdeb5` |
| SHA-256 | `fdeed4bbb15996a5a11f7038740cceefb80e89c7e2e0b9db7c74f18dded3c9e4` |
| SHA3-384 | `783bb324d879d046c9c9483088eed2b90b58ad611e49d429696f774de31fb3347e7cd00b01dfb27eb0a222509e577f46` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T171E56A03BED140A8C066E739D9B79265BA20BC88573133E72F41BA393F267D19E79714` |
| SSDEEP | `24576:3xwHuZwH8kpHfsckkDzVi5Ofc1l9Va79TUr2i35kK4kN0WHqQ:BhHkNfN45Ofc1ha7opgWHT` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_040_fdeed4bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdeed4bbb15996a5a11f7038740cceefb80e89c7e2e0b9db7c74f18dded3c9e4"
    family = "WARDENStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:44:44"
  condition:
    hash.sha256(0, filesize) == "fdeed4bbb15996a5a11f7038740cceefb80e89c7e2e0b9db7c74f18dded3c9e4"
}
```

### Sample 41: `8219c601aec2465a`

| Field | Value |
|---|---|
| SHA-256 | `8219c601aec2465a74ab251cd5c03eb5689fa5e389192d96dfee218399aa67aa` |
| Family label | `WARDENStealer` |
| File name | `x86__setup_now.exe` |
| File type | `exe` |
| First seen | `2026-11-14 02:43:47` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, SpaxMedia, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6758782130ee8901dda3cb4e204d024` |
| SHA-1 | `9fa3225aa13a8fd1db70ed03ec5fdad60c8d1e57` |
| SHA-256 | `8219c601aec2465a74ab251cd5c03eb5689fa5e389192d96dfee218399aa67aa` |
| SHA3-384 | `4fc4f7c563a49690c76bcae90f355a616d5660a42570cd29953190450739c48b2bfc465e9e90c7fd992b516799f75438` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T154472207BCE145AED0AA9335C8A65183BB70BC494F3167D72E10B77C2E76BD09A7A314` |
| SSDEEP | `393216:uZGInIMMVBY12am1YVnCMhWwLs/0+kjCnYkGDj1vOV20WT1mmYOVXrGeKGMNrGnW:u4GIN7YIam1YdCWW9/YjSQJOVIyOX2` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_041_8219c601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8219c601aec2465a74ab251cd5c03eb5689fa5e389192d96dfee218399aa67aa"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:43:47"
  condition:
    hash.sha256(0, filesize) == "8219c601aec2465a74ab251cd5c03eb5689fa5e389192d96dfee218399aa67aa"
}
```

### Sample 42: `9eb2f990200ff479`

| Field | Value |
|---|---|
| SHA-256 | `9eb2f990200ff4796df5f1784586c995ac6bbfbacdc79db2bc1d60c9c37ea34f` |
| Family label | `unknown` |
| File name | `9eb2f990200ff479.ps1` |
| File type | `ps1` |
| First seen | `2026-11-14 02:42:41` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04887a01fa7e4a80afc4f10e7eb01cac` |
| SHA-1 | `d02a2d95183c97e283d2026dedbddde3e230a6a3` |
| SHA-256 | `9eb2f990200ff4796df5f1784586c995ac6bbfbacdc79db2bc1d60c9c37ea34f` |
| SHA3-384 | `ec1b6b42a5818ac4c3c25f776a1fabf5c2116c8674956d2a86ba160e30e1b22e221761b0ad6b0cf39fe17a86431f2abe` |
| TLSH | `T1A2D46E347A452EFF5BA850C244CAC11C563C36B5CA682CF26ACB0CA7390D77A17B79B5` |
| SSDEEP | `12288:5XZt6kug0+4OPRPITYAnemKxAXBbMZcO3:Ul+4ogTqAy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_9eb2f990
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb2f990200ff4796df5f1784586c995ac6bbfbacdc79db2bc1d60c9c37ea34f"
    family = "unknown"
    file_name = "9eb2f990200ff479.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 02:42:41"
  condition:
    hash.sha256(0, filesize) == "9eb2f990200ff4796df5f1784586c995ac6bbfbacdc79db2bc1d60c9c37ea34f"
}
```

### Sample 43: `70ffad5b7c728899`

| Field | Value |
|---|---|
| SHA-256 | `70ffad5b7c728899de393b96b697f83a5015d9a4ab70c336126832281c646509` |
| Family label | `WARDENStealer` |
| File name | `𝐒𝐄𝐓𝐔𝐏.exe` |
| File type | `exe` |
| First seen | `2026-11-14 02:41:33` |
| Reporter | `iamaachum` |
| Tags | `exe, signed, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b44bf93c783f9bf5e01eaae18073d7e2` |
| SHA-1 | `6aba524ad21987051876218357b54ac63be6bc36` |
| SHA-256 | `70ffad5b7c728899de393b96b697f83a5015d9a4ab70c336126832281c646509` |
| SHA3-384 | `1b5bf1d77de29e4139baa908c510a37d806bfd6e235dfa130218c9f99d0f84d90263eb05af6c143a70c7b37011014e61` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T168D57D077C9545B4C0DA9739886A9251B670BC448B7633E73F90BF782E723D22EB6B50` |
| SSDEEP | `24576:HaLPQARe+1IWBUBvwXkWlFxUATXiV8Kmx0S5R5Ai35kymOiSrujWD:6LoweQB42dlMATXieKoNp2WmM` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_043_70ffad5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ffad5b7c728899de393b96b697f83a5015d9a4ab70c336126832281c646509"
    family = "WARDENStealer"
    file_name = "𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:41:33"
  condition:
    hash.sha256(0, filesize) == "70ffad5b7c728899de393b96b697f83a5015d9a4ab70c336126832281c646509"
}
```

### Sample 44: `62c66deba94eb51f`

| Field | Value |
|---|---|
| SHA-256 | `62c66deba94eb51f268ff10c6d8565f5fc52a9cd67819d243f85b672ee13a872` |
| Family label | `WARDENStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-11-14 02:41:05` |
| Reporter | `iamaachum` |
| Tags | `exe, signed, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d821b5a1651471b42b5422682fbf90a6` |
| SHA-1 | `7cc25378c150c928ba8cb273799885f6fa60de6f` |
| SHA-256 | `62c66deba94eb51f268ff10c6d8565f5fc52a9cd67819d243f85b672ee13a872` |
| SHA3-384 | `2f3ae7c015c6971949135353fe499065201683e938e0edf7e668aa06f80939d3452a5d5b5929168a15797a0c765a0c25` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1D8F56B03BED150A8C06AEB39D9B79251BA60BC48573133E72F51FA782F267C19E79704` |
| SSDEEP | `24576:vDmffx/xrxHcuoOdse60KPpSfSj9ma4YRaMpE2k5s2i35kK4kN0e22yNEd:if5/NxQasnPpSWlHRaALkipge2a` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_044_62c66deb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c66deba94eb51f268ff10c6d8565f5fc52a9cd67819d243f85b672ee13a872"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:41:05"
  condition:
    hash.sha256(0, filesize) == "62c66deba94eb51f268ff10c6d8565f5fc52a9cd67819d243f85b672ee13a872"
}
```

### Sample 45: `ccd9426020014d08`

| Field | Value |
|---|---|
| SHA-256 | `ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607` |
| Family label | `unknown` |
| File name | `ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607` |
| File type | `elf` |
| First seen | `2026-11-14 02:26:40` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `884cdf832779fc0e4b431e30b1601b74` |
| SHA-1 | `1c8d7a5f736f71edd01413e1c16585ceebec550f` |
| SHA-256 | `ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607` |
| SHA3-384 | `fcd3af2a494b71abd457fb16a820fbeb409f5db28371f34727f26e04516e3d56abd2d60e874905fd25a6bc51ae528e21` |
| TLSH | `T1F237CF77814338E9E5A98DB4D41025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQc:cqYUQuVDt0TZEz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_ccd94260
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607"
    family = "unknown"
    file_name = "ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607"
    file_type = "elf"
    first_seen = "2026-11-14 02:26:40"
  condition:
    hash.sha256(0, filesize) == "ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607"
}
```

### Sample 46: `6fc2257aa8c38290`

| Field | Value |
|---|---|
| SHA-256 | `6fc2257aa8c382907a47853ad2a7f5326a923af5fc91e71cb030da50834ffe9b` |
| Family label | `Mirai` |
| File name | `6fc2257aa8c38290.bin` |
| File type | `elf` |
| First seen | `2026-11-14 02:25:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70be1467cca4862edbd3ab5dd28f617e` |
| SHA-1 | `6919529f55baf11af59ae3b79cffde5dc43c0de2` |
| SHA-256 | `6fc2257aa8c382907a47853ad2a7f5326a923af5fc91e71cb030da50834ffe9b` |
| SHA3-384 | `7958d822eef87b16d5e9d503d5d74ef54b6dfb2c7e3178a16ca6cab3a6f123cdf0da64e085f6db8799fc04001e130f55` |
| TLSH | `T110B32881BC918601C5D166B7FE6E54CC331613B8D3EB7217CA256B60378A81F0E3BA92` |
| TELFHASH | `t11d51016bff180bac6bc0c5f5928e81245bea3acd2735346a4b1de70f45d2dc1712e812` |
| SSDEEP | `3072:HnuZ0dS3N0Rcgp2Lw/d2yysrumhlhvD6pEwr7U9K5:HnuZ0c0RcgpL2E/2dr7Uq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_6fc2257a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fc2257aa8c382907a47853ad2a7f5326a923af5fc91e71cb030da50834ffe9b"
    family = "Mirai"
    file_name = "6fc2257aa8c38290.bin"
    file_type = "elf"
    first_seen = "2026-11-14 02:25:41"
  condition:
    hash.sha256(0, filesize) == "6fc2257aa8c382907a47853ad2a7f5326a923af5fc91e71cb030da50834ffe9b"
}
```

### Sample 47: `4b1178a7cf248884`

| Field | Value |
|---|---|
| SHA-256 | `4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70` |
| Family label | `WARDENStealer` |
| File name | `4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70.exe` |
| File type | `exe` |
| First seen | `2026-11-14 02:12:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84df9d2314d7be945b989ec5967b5ad2` |
| SHA-1 | `d20854cae980268390822f23cabe88b4eb7b7bd4` |
| SHA-256 | `4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70` |
| SHA3-384 | `6d73bad13e4e181d993f9e1b76515c192fee7d6b7317f131e8d1152ca7490c0c7c89152a4146b3c8f8bfb88cf5ec1d82` |
| IMPHASH | `63bcc21a82d71f7f8c5d75b44d5d2efc` |
| TLSH | `T1F1E40192FAD582E9C427D0398A156616EBB67C504B60D6FF4398673A1F33AE04F3DB10` |
| SSDEEP | `12288:Fe2/mvm412x9xff9sL/KQb/4xnttNIRPPMKy19Nxw4HeogEH+Xluj:F1uvsnsDatoRPvENxVHeZEeVm` |
| ICON-DHASH | `7fef9771f3abcdf7` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_047_4b1178a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70"
    family = "WARDENStealer"
    file_name = "4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:12:01"
  condition:
    hash.sha256(0, filesize) == "4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70"
}
```

### Sample 48: `ecd8152f3f608066`

| Field | Value |
|---|---|
| SHA-256 | `ecd8152f3f608066a7c0e88a3ef1c0c02e8245029d0bcfdd7b56c46e5f5f6a95` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-11-14 01:59:06` |
| Reporter | `pickledrick` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d5a50a34bc995a8908929a6f401e06f` |
| SHA-1 | `0109342bfa177e15df1717d095685da54a0ab6e8` |
| SHA-256 | `ecd8152f3f608066a7c0e88a3ef1c0c02e8245029d0bcfdd7b56c46e5f5f6a95` |
| SHA3-384 | `12be31d5ce699f5099402bf3fa8e7b55b57aabf8e88fa07bb0a28f4fec452834f05133eb74f465decd951d14d3da74bc` |
| TLSH | `T155412F95FE384B35768CC06DB94FAA4BDE87433F89B43D146007D884A53EA84629E722` |
| SSDEEP | `48:l0FAxB4T9aTYgaTbuJPIYfiYn22v0Ye+rtGF/WuhLDN94wQujLT7qmQBz5VF:OFOB4UU3n++Z2v06qWuJNaJCy1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ecd8152f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecd8152f3f608066a7c0e88a3ef1c0c02e8245029d0bcfdd7b56c46e5f5f6a95"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-14 01:59:06"
  condition:
    hash.sha256(0, filesize) == "ecd8152f3f608066a7c0e88a3ef1c0c02e8245029d0bcfdd7b56c46e5f5f6a95"
}
```

### Sample 49: `8971206646c120bb`

| Field | Value |
|---|---|
| SHA-256 | `8971206646c120bb5a019aace52d45a836d1e4aab317ebc42d79070d95e3fe8f` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 01:56:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e14ca249c8d19238ca855621acfa0cb5` |
| SHA-1 | `2c16119ae01193bffc6978bf92c76dd22c8e8726` |
| SHA-256 | `8971206646c120bb5a019aace52d45a836d1e4aab317ebc42d79070d95e3fe8f` |
| SHA3-384 | `abad9847d3c16043ead78d7eb0fcf9daefd5addcd1e675223bb558ebb5fb280d6e81a512469b46e44713dcfc0c4e47a5` |
| TLSH | `T11C556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSw:SDjxB4m5n8XlaPWi+d+a4TjxQP4O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_89712066
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8971206646c120bb5a019aace52d45a836d1e4aab317ebc42d79070d95e3fe8f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 01:56:04"
  condition:
    hash.sha256(0, filesize) == "8971206646c120bb5a019aace52d45a836d1e4aab317ebc42d79070d95e3fe8f"
}
```

### Sample 50: `2d352712cad9e47d`

| Field | Value |
|---|---|
| SHA-256 | `2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3` |
| Family label | `unknown` |
| File name | `2d352712cad9e47d.bin` |
| File type | `macho` |
| First seen | `2026-11-14 01:25:57` |
| Reporter | `Tuxxin` |
| Tags | `amos, macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `496f8faa8df140a08da90953904b94fd` |
| SHA-1 | `578cbd47b742de006593793c2c951ec47ec48772` |
| SHA-256 | `2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3` |
| SHA3-384 | `a9b07e6fa8bdacc7438145b2026e37e15b1846f73ee13452105c009b0de7f3b22df15a85e72ac393b02b12ab69a07721` |
| TLSH | `T195F42AAB527AA4D4EC4732747B8A3BF7EE40B47663F5E4A9AA42513448F3374913021F` |
| SSDEEP | `12288:tU7wAcpxXAIIETE1UWLwJrr1nuwyHPUcyvmByHaRR1L+:tU7RyAOTtXvPaRW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_2d352712
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3"
    family = "unknown"
    file_name = "2d352712cad9e47d.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:57"
  condition:
    hash.sha256(0, filesize) == "2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3"
}
```

### Sample 51: `ae4f1b9547db9063`

| Field | Value |
|---|---|
| SHA-256 | `ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8` |
| Family label | `unknown` |
| File name | `ae4f1b9547db9063.bin` |
| File type | `macho` |
| First seen | `2026-11-14 01:25:51` |
| Reporter | `Tuxxin` |
| Tags | `amos, macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ee89ae91b6e078cbce0c6f7b0b4cd3f` |
| SHA-1 | `4fbc830b8b9e8bca58c52322d07eb6a8be792cb9` |
| SHA-256 | `ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8` |
| SHA3-384 | `91d3640cacc9f3e5c4b3dae33df965a6f531874f2a142612e1beb56b379c62c36134f335847e8124b51a29374a35f032` |
| TLSH | `T102F42AAB527AA4D4EC4732747B8A3BF7EE40B47663F5E4A9AA42513448F3374913021F` |
| SSDEEP | `12288:tU7wAcpxXAIIETE1UWLwJrr1nuwyKPUcyvmByHaRR1L+:tU7RyAOTtMvPaRW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_ae4f1b95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8"
    family = "unknown"
    file_name = "ae4f1b9547db9063.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:51"
  condition:
    hash.sha256(0, filesize) == "ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8"
}
```

### Sample 52: `e5566d680f0c6484`

| Field | Value |
|---|---|
| SHA-256 | `e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4` |
| Family label | `unknown` |
| File name | `e5566d680f0c6484.bin` |
| File type | `macho` |
| First seen | `2026-11-14 01:25:41` |
| Reporter | `Tuxxin` |
| Tags | `amos, macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `748d5a2ad833596db6e84f1036bd2765` |
| SHA-1 | `313dbfc31ac0599a56f36a12336a24d7e80f2f12` |
| SHA-256 | `e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4` |
| SHA3-384 | `0d7e7796921afa0b363ce3f5275450def5050d10c7e1c94b4b4b53816ce9ef0cc7ac8cfd41c33fbbc86037bff904e678` |
| TLSH | `T13EF42AAB527AA4D4EC4732747B8A3BF7EE40B47663F5E4A9AA42513448F3374913021F` |
| SSDEEP | `12288:tU7wAcpxXAIIETE1UWLwJrr1nuwyLPUcyvmByHaRR1L+:tU7RyAOTtjvPaRW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_e5566d68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4"
    family = "unknown"
    file_name = "e5566d680f0c6484.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:41"
  condition:
    hash.sha256(0, filesize) == "e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4"
}
```

### Sample 53: `b4507d1dbf431ac6`

| Field | Value |
|---|---|
| SHA-256 | `b4507d1dbf431ac6e2de7668d3ede2ae4677774a7cbb0d127b2255c0ec1c7e66` |
| Family label | `unknown` |
| File name | `b4507d1dbf431ac6.bin` |
| File type | `macho` |
| First seen | `2026-11-14 01:25:31` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac238d00b5cbccb59bada8ba5cb5f953` |
| SHA-1 | `0a662831165bacc229c644054cc40332a3ad1a53` |
| SHA-256 | `b4507d1dbf431ac6e2de7668d3ede2ae4677774a7cbb0d127b2255c0ec1c7e66` |
| SHA3-384 | `45a1e2218052c97362289eff78ec65274e7b26d984eb3e088aaec3cc2adf484623b7f190fc85ef4d6c98320d6b737d9d` |
| TLSH | `T182F263239B1C5922C44C623C42BB6742A23AF1E145D577B74B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7wH14z1dgngS6BndngN/4B0:RUdp8j3jvpWK7g1MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_b4507d1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4507d1dbf431ac6e2de7668d3ede2ae4677774a7cbb0d127b2255c0ec1c7e66"
    family = "unknown"
    file_name = "b4507d1dbf431ac6.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:31"
  condition:
    hash.sha256(0, filesize) == "b4507d1dbf431ac6e2de7668d3ede2ae4677774a7cbb0d127b2255c0ec1c7e66"
}
```

### Sample 54: `17b7e1f0e3314c10`

| Field | Value |
|---|---|
| SHA-256 | `17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6` |
| Family label | `unknown` |
| File name | `17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6.exe` |
| File type | `exe` |
| First seen | `2026-11-14 01:16:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `042f609d7049d84f837574c67bcb59d3` |
| SHA-1 | `9b22b9b6cdbaf2a5ef206aa06d3bcccf76a3051b` |
| SHA-256 | `17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6` |
| SHA3-384 | `2b120ad41bd6bb7d13bcc4b49e0886e08468e7672fed0ddcbcf0b117366cd5deff7aac7b424e22b2e398cf167b546ae8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18CA46C166AEC1572C683A135EE9F6100EF35016B12185910BACDD1C87F92B6DC3FEBE6` |
| SSDEEP | `6144:LfDl5w45GMddRoa5mwWwJJ67IN/CIgU9sO8hqX6CXg7BIZU5lAXUoxl+/zdYwwmc:vG8L5pW88hlgI+USENfyNlCRpO` |
| ICON-DHASH | `648f1d25471303cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_17b7e1f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6"
    family = "unknown"
    file_name = "17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6.exe"
    file_type = "exe"
    first_seen = "2026-11-14 01:16:09"
  condition:
    hash.sha256(0, filesize) == "17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6"
}
```

### Sample 55: `71c941269ccac904`

| Field | Value |
|---|---|
| SHA-256 | `71c941269ccac9043df6dc06b2fcde1531861ae6f89e84c9a3712aa6894cb44b` |
| Family label | `unknown` |
| File name | `71c941269ccac904.ps1` |
| File type | `ps1` |
| First seen | `2026-11-14 01:11:59` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c603bcbe69a122f3bdab475c7020a6f5` |
| SHA-1 | `e9c486df3435371322eda72ab3e3ebdd58eec070` |
| SHA-256 | `71c941269ccac9043df6dc06b2fcde1531861ae6f89e84c9a3712aa6894cb44b` |
| SHA3-384 | `343e5e272b1b207d093255ba0c703fd5c5c19c591414c8f7746dfb52e558e4c3eb79602d6cfff81a66fcb261f124db3d` |
| TLSH | `T1EBD47E347E422DFF5BA820C348C6811C563C26B9DA682DF569CB4CA7390D77A17B79B0` |
| SSDEEP | `12288:ne4W/Hp0WsHH8szYu6EEb/6nc8Jh6vkplTmvF:/W/M8sihMHC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_71c94126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71c941269ccac9043df6dc06b2fcde1531861ae6f89e84c9a3712aa6894cb44b"
    family = "unknown"
    file_name = "71c941269ccac904.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 01:11:59"
  condition:
    hash.sha256(0, filesize) == "71c941269ccac9043df6dc06b2fcde1531861ae6f89e84c9a3712aa6894cb44b"
}
```

### Sample 56: `394b2b404ecdc32a`

| Field | Value |
|---|---|
| SHA-256 | `394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-11-14 00:41:27` |
| Reporter | `pickledrick` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7436ec07e9afcdac58bf32f5c3f79286` |
| SHA-1 | `a6bcfbba57409fe19ee716164067268151e8f1cd` |
| SHA-256 | `394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9` |
| SHA3-384 | `5b02f1bbf6b997b46b560da9904d418f3f4bc2e53568f7b7a616ff9c2314ee0529769901706a8ebf6962410c5042351d` |
| TLSH | `T1DEA133E5FD349D31706EC939B99E6666CE87193F09763D84705BAC182F2D50C621CA30` |
| SSDEEP | `96:AajFh4GVGcNaJCQOeM0S69qP2cDxT3npI1fT0:AajF/IL7R/9qg4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_394b2b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-14 00:41:27"
  condition:
    hash.sha256(0, filesize) == "394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9"
}
```

### Sample 57: `4cb918bdd53fd77c`

| Field | Value |
|---|---|
| SHA-256 | `4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b` |
| Family label | `unknown` |
| File name | `4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:38:30` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d111e1ee971736c8eb0c7b1bc0c2cf9` |
| SHA-1 | `1807e0f2317bb9d2d315db0063e631cc51e20b87` |
| SHA-256 | `4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b` |
| SHA3-384 | `01b2212da093f89533b53e600bafe5f017455c1deb8625e201015d8be3d29284a73a82576975385d9801990272c02ac6` |
| IMPHASH | `e03124e900f117238b21ddd52677df36` |
| TLSH | `T1AA14126DDA985BA7F71727B254D7CE393A3099470F23956B0AC0BC83388DBE41267B05` |
| SSDEEP | `3072:MVNFTJuqrt5mjViRUIAFF/ZF6ULUF5x9x2X2JTBkGK5RGUxCVfYW12XV:MFJZCjgAtNUT62JFoiAW4F` |
| ICON-DHASH | `9a78fcabacc061ac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_4cb918bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b"
    family = "unknown"
    file_name = "4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:38:30"
  condition:
    hash.sha256(0, filesize) == "4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b"
}
```

### Sample 58: `cf690ffe7647238a`

| Field | Value |
|---|---|
| SHA-256 | `cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e` |
| Family label | `unknown` |
| File name | `cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:37:37` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90a70db3c49703a44cca8d677bfe1b6f` |
| SHA-1 | `f3c49b621cd1a8656d3e1f7ba081f9513c79279f` |
| SHA-256 | `cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e` |
| SHA3-384 | `b6f11228135d2bcb57319a5496084d56bb6e35b39ed63db715e4f35804a5afabbe92a25ec7d972c68167c94e23077ca0` |
| IMPHASH | `a24e57cfb1e35030a9b4252bf1fa8b4b` |
| TLSH | `T1256633E56BD4CD28C5FB0BB155F04327F770BE715A6853098AC63E4A08B0B95DA34F2A` |
| SSDEEP | `98304:wZXn3dutXJk/5LPD0VR6I0dTiX+YPWW3IPo4yxWZlr8MzYqDchpu:wp3w4/5LCH0djmd8o4tZKMkqDY0` |
| ICON-DHASH | `fadadac2a2b8c4e4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_cf690ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e"
    family = "unknown"
    file_name = "cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:37:37"
  condition:
    hash.sha256(0, filesize) == "cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e"
}
```

### Sample 59: `ffbb2d190c87f983`

| Field | Value |
|---|---|
| SHA-256 | `ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69` |
| Family label | `WARDENStealer` |
| File name | `ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:37:30` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bde6d5aba98c766cc41fd79a0141153` |
| SHA-1 | `0f7e98f5ecd56c492cea20f43230eb73b4190230` |
| SHA-256 | `ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69` |
| SHA3-384 | `1d006c498826afb78c1e78002357b3ee9a2ea7d9c37649f746ecd88512556d2202c6d767226b495d564e295f5978c714` |
| IMPHASH | `9ac45f5f2a42dc27d259a54e7f56e836` |
| TLSH | `T1B965D037E99A41A8DEBAF176386CB204E7887B05CF93717D269F34873892C975462307` |
| SSDEEP | `24576:4Gnw+XBe6yrSdJ3nQVu3vlxDNAmtjVKvewBBhLXiIBPxXeRp:4GwsB0rS3nQVu3v7NeHBmp` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_059_ffbb2d19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69"
    family = "WARDENStealer"
    file_name = "ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:37:30"
  condition:
    hash.sha256(0, filesize) == "ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69"
}
```

### Sample 60: `a7f0dd6c6c8c0cdf`

| Field | Value |
|---|---|
| SHA-256 | `a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6` |
| Family label | `unknown` |
| File name | `a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:36:34` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a624161f056f3c0392d602338a5f467a` |
| SHA-1 | `18f3a7f71d45ebd170f21730aaf9c3467ac7d17f` |
| SHA-256 | `a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6` |
| SHA3-384 | `8729e95696443c8cae835b8a065887b7547c8d0f0cdbc4061f3bd5f67916ffb15a72a9d2df7de203911e284b69c2c686` |
| IMPHASH | `15c28a534fc7b848388193f8df5a9293` |
| TLSH | `T1BE35CF36E9AA41B8DFBDF173245CB340978CBB029FAB707C368E24877456C876566306` |
| SSDEEP | `24576:OEJd9Zgx9/SbvYflST2X2sDp4kdg7Y9ipt:OEJdv4tIvYflaU2Ep9r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_a7f0dd6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6"
    family = "unknown"
    file_name = "a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:34"
  condition:
    hash.sha256(0, filesize) == "a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6"
}
```

### Sample 61: `24052df8fe59a39b`

| Field | Value |
|---|---|
| SHA-256 | `24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b` |
| Family label | `unknown` |
| File name | `24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:36:28` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59f91c324bd2ce342834bff7b0416695` |
| SHA-1 | `35b7abdfae0bab27d5c736d7e423ac116dd6e6e8` |
| SHA-256 | `24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b` |
| SHA3-384 | `48b790626967e24038c4dbd9f9e3763b44b26fb8f23887a8b0596dfcf05252d0b31756a3b273d316f1669fb8bc149f36` |
| IMPHASH | `febf6f7c92096b447e451c14467f8e7a` |
| TLSH | `T1DC25BF36F99940E8DBBAB073256CB240D78DBB05AFA770BD3A8E35477492C976461303` |
| SSDEEP | `12288:PX1uI4z+21GcG2G6nZ/i1aYTu9x5FWS7T0bHUTDmXK0ub8HtzB4SOYs4ypO6bus4:PUIY++42GC/cTCfT0onmPASBPtRyk1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_24052df8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b"
    family = "unknown"
    file_name = "24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:28"
  condition:
    hash.sha256(0, filesize) == "24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b"
}
```

### Sample 62: `2ea911903802aac8`

| Field | Value |
|---|---|
| SHA-256 | `2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341` |
| Family label | `RevStealer` |
| File name | `2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:36:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a050b7cdc7ee533a637cb7cdf38ccaf` |
| SHA-1 | `8903b120b67d13cc694f028e1e7b5cd141636a54` |
| SHA-256 | `2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341` |
| SHA3-384 | `e9dac7f4c50b26c9b54b79c14c45f9f5240166194df3306a24ea911c5d38628018d356b05bc8c50df7c6f677e8478b74` |
| IMPHASH | `80809665711013f1bd93814069e02a29` |
| TLSH | `T163D5239978B20578D433C7B1CF83F56DB16A378A4AB44D8BB6CD2A419D939888C37770` |
| SSDEEP | `49152:gFvY1d0eeyu6fV3Ts34e6VRvQMvhTG9JWRUTE/k6jzotipwWeePvWgftpgqursam:gFvY307yu6fVAARnYfTE/k6jzQiReWvL` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_062_2ea91190
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341"
    family = "RevStealer"
    file_name = "2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:23"
  condition:
    hash.sha256(0, filesize) == "2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341"
}
```

### Sample 63: `9c7696e3b9f55045`

| Field | Value |
|---|---|
| SHA-256 | `9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376` |
| Family label | `ConnectWise` |
| File name | `9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:36:17` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0435bb0a9892093b9e6caa564fb7d55c` |
| SHA-1 | `d0a2be4551064c50cf519634dee3201cce08c5b6` |
| SHA-256 | `9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376` |
| SHA3-384 | `40694257911758517451b3aa762e48bcf6a710ac5e0e10fc274c349cb71e62ca902e087d7f324289c1e09b0149ce6063` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T17DD61211B3F59675D1FB0638E87AA3615A35BC014B12C7AF6794792A2D327C08E323B7` |
| SSDEEP | `393216:YFri04SOLtX1lFri04SOLmFri04SOLeFri04SOL1:YMrSOL5zMrSOLmMrSOLeMrSOL1` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_063_9c7696e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376"
    family = "ConnectWise"
    file_name = "9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:17"
  condition:
    hash.sha256(0, filesize) == "9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376"
}
```

### Sample 64: `d9bb4cb6977d8179`

| Field | Value |
|---|---|
| SHA-256 | `d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92` |
| Family label | `WARDENStealer` |
| File name | `d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:36:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12003c202d993685ce7f54663d9ae66b` |
| SHA-1 | `42f50db7ca63c3cc03938ceae4374bfbdd671a2c` |
| SHA-256 | `d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92` |
| SHA3-384 | `30de9d258ad60d0a7fc6d69899c4df23c624c97d1099ba08b569c36f6f6679fc73569ac8bac30d86e05751306f2faa27` |
| IMPHASH | `55f5fcb1326a3056693387f80bb5e1aa` |
| TLSH | `T13C05F192FA951ADCE439C5744289BA35A1263D231F2158FB57E0130E0F3DAD1EF3AB19` |
| SSDEEP | `12288:3SheBXLJ4EkCOsi3xqqb0L/75Ms7K6AAcvWFjsDwrhDNZXzZB5yBvdDhcpSR9sxe:ihoxfqb0LCZh5Wh9rhDNxcXDIG+D0i` |
| ICON-DHASH | `ea97f1696971df7f` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_064_d9bb4cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92"
    family = "WARDENStealer"
    file_name = "d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:09"
  condition:
    hash.sha256(0, filesize) == "d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92"
}
```

### Sample 65: `b797e3534789157c`

| Field | Value |
|---|---|
| SHA-256 | `b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240` |
| Family label | `WARDENStealer` |
| File name | `b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:33:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7652afac06acfaaacd56858a20e055ce` |
| SHA-1 | `0509f447aadf74b026c86d8d78f9fc58034a1c81` |
| SHA-256 | `b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240` |
| SHA3-384 | `a6953ad19bf279953eb5e346d649b98014743e2462f837a6c8e9bbe54f01f9e742a2bb1a5563431e0a3163cd80f50594` |
| IMPHASH | `53518e9fbf02e3a8c553da49405c047b` |
| TLSH | `T143F40197F69141FCC026C5388A151627FA7678550B10A7FF9394973A0E336EA8F3EB21` |
| SSDEEP | `12288:7A89XpLiRlUXKTitCDFlMX9hdr7jJx1wEHUUpum9QQSlBzdqfP02LjIxnp5:k89XpOlwjNhdr7jpLpVCrlB8nH2f` |
| ICON-DHASH | `ffdfe96d65d5ffff` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_065_b797e353
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240"
    family = "WARDENStealer"
    file_name = "b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:33:39"
  condition:
    hash.sha256(0, filesize) == "b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240"
}
```

### Sample 66: `d48d8c87335633e9`

| Field | Value |
|---|---|
| SHA-256 | `d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25` |
| Family label | `CoinMiner` |
| File name | `d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:33:30` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b51fca5697c50b4ad0abbd91a0d0fcf5` |
| SHA-1 | `a2f697c209de9d4e89384729b1a9b022e457180c` |
| SHA-256 | `d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25` |
| SHA3-384 | `389ed21cb0ecbce028241b98ea7828b165811478a39edb06984133ffed0f1b26995d411d2b0298acc703786cb4cbc900` |
| IMPHASH | `c83e4088ffb874d619bfe96efbf6964f` |
| TLSH | `T1EE7733D219EA0E48F465D3B1031265FFF1373BDD8035EC9ABD5AFC8429229609A3764B` |
| SSDEEP | `786432:K14B+wE86QcFX/Wy8yc2D9oPruk3QH9gfuC54S+9f2QtQg2OFEjbOQU:K1q16/tGz5329gfrMf3ueiWQU` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_066_d48d8c87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25"
    family = "CoinMiner"
    file_name = "d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:33:30"
  condition:
    hash.sha256(0, filesize) == "d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25"
}
```

### Sample 67: `a69452e56c7ec55b`

| Field | Value |
|---|---|
| SHA-256 | `a69452e56c7ec55b99e5b5ea24a35b299689c959ea4db02a435f304373b1c34e` |
| Family label | `unknown` |
| File name | `SMBC-Card.apk` |
| File type | `apk` |
| First seen | `2026-11-14 00:33:10` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e922e2bb6e2a1fa622d5068dffdc1e02` |
| SHA-1 | `3d7865675bfaaa24bc7f1ada545e3e23438bb86d` |
| SHA-256 | `a69452e56c7ec55b99e5b5ea24a35b299689c959ea4db02a435f304373b1c34e` |
| SHA3-384 | `415e1f2ade5753da319859adf3e08cd70c6fa9f835870baf3ae1c5aa524d8db787bb1d042ac9615ecbdfb754b43f75db` |
| TLSH | `T139272357FBC4997AC4F68335083A672069579C358B6392C7A904727C28F76E42F89ECC` |
| SSDEEP | `393216:ZTLgUQg9u7OnN4yY8RN9Iz/+mwxqPkCPFQuBsA8fL:Z/91uKN4IVxxqPkAFQxH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_a69452e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a69452e56c7ec55b99e5b5ea24a35b299689c959ea4db02a435f304373b1c34e"
    family = "unknown"
    file_name = "SMBC-Card.apk"
    file_type = "apk"
    first_seen = "2026-11-14 00:33:10"
  condition:
    hash.sha256(0, filesize) == "a69452e56c7ec55b99e5b5ea24a35b299689c959ea4db02a435f304373b1c34e"
}
```

### Sample 68: `ce1be8e1e7119519`

| Field | Value |
|---|---|
| SHA-256 | `ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51` |
| Family label | `RustyStealer` |
| File name | `ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:31:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3802a2f1a5be70d83afba972af67ffe` |
| SHA-1 | `2970ab14673626980da46a594d91ad4d83be969a` |
| SHA-256 | `ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51` |
| SHA3-384 | `aa91d2e785f795a1f8165f50a76a577fbf920810e65e8de2e990a65519153591aee147f5d831742aac6da0ad993f4cd1` |
| IMPHASH | `803f6891f411f161caeb1bb80583afaf` |
| TLSH | `T1CE9512177BAA96BCE10AC034530785B3AA73B8850522BDFF03F499743EA6D516F1D718` |
| SSDEEP | `24576:SN7RQ0n8Q8e0lIxhz3sv1E2zVqGB5A24P20xaRijtHbzSHwbd0IMgAMC39uu:SLQ0nb8es8uVq2YZxRiwZqtuu` |
| ICON-DHASH | `20000003f8c00081` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_068_ce1be8e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51"
    family = "RustyStealer"
    file_name = "ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:31:10"
  condition:
    hash.sha256(0, filesize) == "ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51"
}
```

### Sample 69: `c7f9ed3d6cda7e15`

| Field | Value |
|---|---|
| SHA-256 | `c7f9ed3d6cda7e15a4a532e7eff76318bd3efea75bb823cf2d14ef1b68c6f232` |
| Family label | `unknown` |
| File name | `my_rakuten_security_v3.apk` |
| File type | `apk` |
| First seen | `2026-11-14 00:30:45` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d062e3a7ce6f36bc78f097ffa0d3d86` |
| SHA-1 | `02183f06979bf8466e1a95ae116347130739d789` |
| SHA-256 | `c7f9ed3d6cda7e15a4a532e7eff76318bd3efea75bb823cf2d14ef1b68c6f232` |
| SHA3-384 | `79db25a0c8978535ef34751fb01dc98dd98f03fe2c764e19db2ee4aa3c1a280719b054a9603e2bc0bc030260788c793b` |
| TLSH | `T14C672367FF889979C4F6833108716325290B9C358B63D6DBA910323C68F72D46F89ADD` |
| SSDEEP | `786432:ky8t13VN6W9esDtPFpEqSSvRl1m5wV6LQS71c1tHNX:kyK6QvDtPPEWvRPmE60S7GNX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_c7f9ed3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7f9ed3d6cda7e15a4a532e7eff76318bd3efea75bb823cf2d14ef1b68c6f232"
    family = "unknown"
    file_name = "my_rakuten_security_v3.apk"
    file_type = "apk"
    first_seen = "2026-11-14 00:30:45"
  condition:
    hash.sha256(0, filesize) == "c7f9ed3d6cda7e15a4a532e7eff76318bd3efea75bb823cf2d14ef1b68c6f232"
}
```

### Sample 70: `b0cc539f7e795ad8`

| Field | Value |
|---|---|
| SHA-256 | `b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125` |
| Family label | `RevStealer` |
| File name | `b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:28:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb1746f5f5a99874f7e51b0d4d3a216f` |
| SHA-1 | `5808ae87aaa4ba1a26a3766f995a08413189a72c` |
| SHA-256 | `b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125` |
| SHA3-384 | `a69bf160c23bb8aed01dc98ce51c95c89dffd810a2875d16856fabd17b80dbe3041997e1c7aef2ec5642cd483f0cbf2b` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T1C2D5239AFEF615B4C836C3B65EA6E06CB11D7BC089B14E963ACC6B004D536A41D3637C` |
| SSDEEP | `49152:WyTyKJ/pUkNlGztLw68mPjl4owo5v4ZZD3edzY0yBdMfj+SuzgVsxoChX:WpKJ/Z2zu68mf5v4feJyBdS+3gVseCh` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_070_b0cc539f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125"
    family = "RevStealer"
    file_name = "b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:28:29"
  condition:
    hash.sha256(0, filesize) == "b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125"
}
```

### Sample 71: `ced186a8664f5ed9`

| Field | Value |
|---|---|
| SHA-256 | `ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900` |
| Family label | `AdaptixC2` |
| File name | `ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:26:12` |
| Reporter | `Tuxxin` |
| Tags | `AdaptixC2, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a293b28028115d676fca89e38fe8a441` |
| SHA-1 | `2195efcee5ba73a889c8420fc376099445d43b90` |
| SHA-256 | `ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900` |
| SHA3-384 | `56849d1bbf07ff8f909f15949f23fb13cd7c86cc4fec938732123ae77d1cc129623ec5d63430db624595ff3f2e6089bc` |
| IMPHASH | `2eb0e19e399049c7d933ef4e6502cd2a` |
| TLSH | `T108A35336D7B3C4ADC05EC638AB8794B3B9F07C5C4634751A4781A6213B5BD386BBE184` |
| SSDEEP | `1536:Nl/Y64qOyPcubw29RIax2GEhN6xAIkiyiq8w9Vn5YEENdLYZO6YKRrDIO9cY2bZ5:P2ebpAIusKc9vFZnKEn` |

#### Technical Assessment

- The sample is tracked as `AdaptixC2` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AdaptixC2_071_ced186a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900"
    family = "AdaptixC2"
    file_name = "ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:26:12"
  condition:
    hash.sha256(0, filesize) == "ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900"
}
```

### Sample 72: `e199d59a01c284d4`

| Field | Value |
|---|---|
| SHA-256 | `e199d59a01c284d44926fc7c497ee08c4e631de305cbd706bbb87800f0d770bd` |
| Family label | `unknown` |
| File name | `e199d59a01c284d4.bin` |
| File type | `exe` |
| First seen | `2026-11-14 00:24:36` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `785eca924bbae846083662a0634386bd` |
| SHA-1 | `491ef5e74356432e91e7c3cc748491bf2e8eccac` |
| SHA-256 | `e199d59a01c284d44926fc7c497ee08c4e631de305cbd706bbb87800f0d770bd` |
| SHA3-384 | `258085d8a61b7345cf38f48526b64ab0d24a9193d87548c97901896a567c17479e520c57d603db4cccc97b58f6c0266a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17F06BF022B65DE16D1B963B902B5C60012FD95088EFADB1BE3CC7DD72DD1746232B26B` |
| SSDEEP | `98304:jdFvtHubs/hyBsMKLielJsS1i+iEKAf8UrYv0CWvQBc:xHispyBspLi4JsS1PmA08YMCWvQB` |
| ICON-DHASH | `0c4d0c4d4d616923` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_e199d59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e199d59a01c284d44926fc7c497ee08c4e631de305cbd706bbb87800f0d770bd"
    family = "unknown"
    file_name = "e199d59a01c284d4.bin"
    file_type = "exe"
    first_seen = "2026-11-14 00:24:36"
  condition:
    hash.sha256(0, filesize) == "e199d59a01c284d44926fc7c497ee08c4e631de305cbd706bbb87800f0d770bd"
}
```

### Sample 73: `2683747e3aa55b68`

| Field | Value |
|---|---|
| SHA-256 | `2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-14 00:19:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4824587280383b17c08bb359cac24d6` |
| SHA-1 | `d743ba6c211ad1972ff51190c47282784b8ce061` |
| SHA-256 | `2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2` |
| SHA3-384 | `87f47aa355a294f08d2b22c954982e19fd84ce5e1f6d8aa06096b15fe3e9a01907eedbe1e21b0722dcd9bee23f4e6817` |
| TLSH | `T109556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSy:SDjxB4m5n8XlaPWi+d+a4TjxQP4E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_2683747e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 00:19:05"
  condition:
    hash.sha256(0, filesize) == "2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2"
}
```

### Sample 74: `b7f4cbde98525a79`

| Field | Value |
|---|---|
| SHA-256 | `b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5` |
| Family label | `WARDENStealer` |
| File name | `b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:18:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d5068606893fdd667ec18b2e27c4599` |
| SHA-1 | `0103b0ba3ff9fdc9a0e1a66bdef9f1acc5fcd999` |
| SHA-256 | `b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5` |
| SHA3-384 | `bcb1dcfd1d447ee5fb3377b12d3a58c61827301cf3bb55cc9b2fa0ecd90e05fa0f16231673b7d6866a72510eddd340f8` |
| IMPHASH | `9ad2ca4acbd84bc707ae0401abbce1e5` |
| TLSH | `T1C1E4F112F69953ECD02AC1B486555226E971BC590B216BFF2394672B2F337D08F3EB60` |
| SSDEEP | `12288:95vVYj3BzxFXjSt7kRScrFa6N/HqFRZlS7ln0dsglQ6g+RljO649bbSa3tH1rCxM:zvVYL5OkRFasKSn0dsugQljOJNSaDCxM` |
| ICON-DHASH | `1048b27171b24810` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_074_b7f4cbde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5"
    family = "WARDENStealer"
    file_name = "b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:18:29"
  condition:
    hash.sha256(0, filesize) == "b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5"
}
```

### Sample 75: `88ff3f71a48dc2c2`

| Field | Value |
|---|---|
| SHA-256 | `88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b` |
| Family label | `RevStealer` |
| File name | `88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:17:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bdee65ffa5c09eda6c74a4f3d4bee6d` |
| SHA-1 | `9a67c8e3a1347ef22695947d6f879e0fc91b9cbe` |
| SHA-256 | `88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b` |
| SHA3-384 | `74bd721030169075958a8ec754d814c595488fbdec6f58e4212acef456287453eb9494895983d03c3f2655a50e15c680` |
| IMPHASH | `80809665711013f1bd93814069e02a29` |
| TLSH | `T1C3D523487EF25AB5D877C3B18D82F47DB25A3B948B688E9B378C67005D438646C36339` |
| SSDEEP | `49152:zT75UJcirGS1YntYn5oEmNuXinZ9iAhtE0Rwwy+6L1ZBey5tnkJ8CyMFNLMeQbA/:zThijSnSn5oEmNfnaoG9wy1L1ZB7DnkY` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_075_88ff3f71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b"
    family = "RevStealer"
    file_name = "88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:17:28"
  condition:
    hash.sha256(0, filesize) == "88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b"
}
```

### Sample 76: `030cbc0898008d3b`

| Field | Value |
|---|---|
| SHA-256 | `030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515` |
| Family label | `unknown` |
| File name | `030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:16:13` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8766cfd6cd3a6077df250a095554471` |
| SHA-1 | `d38d5036685e81fb04c3e72acbb0adbff3818582` |
| SHA-256 | `030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515` |
| SHA3-384 | `20112f4a6b5988eb153360b054218be0dd4d60be81ad961dc261649d2560e4908a61f11ecdebbbbb69a1eea509a562f0` |
| IMPHASH | `9bd9bd78e1310e00496b15391d0dcdd5` |
| TLSH | `T118847DC2F1A405ECE067A17899B6B607FA75389D03504ACB73FC84653FD62E03EBA651` |
| SSDEEP | `6144:mxsjeKd7f7eCvneAVxDmMwqsH6XiNmHaJLA3hAHyUrJsVbnuCatR:pj77iqneAnM8h6DPMbna` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_030cbc08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515"
    family = "unknown"
    file_name = "030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:16:13"
  condition:
    hash.sha256(0, filesize) == "030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515"
}
```

### Sample 77: `8605176d7b9e6238`

| Field | Value |
|---|---|
| SHA-256 | `8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5` |
| Family label | `ConnectWise` |
| File name | `8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5.msi` |
| File type | `msi` |
| First seen | `2026-11-14 00:12:40` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5b237aa356611e814d345d828b11ace` |
| SHA-1 | `48507b204989e3229ff50a266a9bf9957dd2d831` |
| SHA-256 | `8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5` |
| SHA3-384 | `1f26f9f4d83a55e7b8931265fd40bb927395c722065a0687245cb0b582b7449823cb9ffefbd0415a064fabd399e7123b` |
| TLSH | `T1BCA6232523FD801AE8F75A7DED3682F45972BE64CE22C11E9328BD0D2974D4096727B3` |
| SSDEEP | `98304:dwJ4t1h0cG5FGJRPxow8OdwJ4t1h0cG5vwJ4t1h0cG5RwJ4t1h0cG5OwJ4t1h0cW:6Wh0cGwkWh0cGCWh0cG4Wh0cGRWh0cG` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_077_8605176d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5"
    family = "ConnectWise"
    file_name = "8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5.msi"
    file_type = "msi"
    first_seen = "2026-11-14 00:12:40"
  condition:
    hash.sha256(0, filesize) == "8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5"
}
```

### Sample 78: `fe2f1da409b64508`

| Field | Value |
|---|---|
| SHA-256 | `fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8` |
| Family label | `RevStealer` |
| File name | `fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:12:33` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e95064404181c29541515a590a1e71d1` |
| SHA-1 | `9e9f562b4a45eb1aabbbc404f1ecd3424068654a` |
| SHA-256 | `fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8` |
| SHA3-384 | `f1ed7a12302891aba08789fde9608b32ed7a984410150feea54da3237a13cd10399fae2ecfadc295a64020b6a0de1138` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T13DE52389FCF219B4E833C3B78593B07CB2197B844A354D9B3ACDA7505E236642C76276` |
| SSDEEP | `49152:WTUoCyjU01fug/MlBmbUMdBSweNlcgU0EeVGJP1FLxGDKPEpTcSHkoWvbnNtj62k:lJyAGfD/kmQ2sNaeYJN9xnspTcSHko4D` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_078_fe2f1da4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8"
    family = "RevStealer"
    file_name = "fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:12:33"
  condition:
    hash.sha256(0, filesize) == "fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8"
}
```

### Sample 79: `f426469d0938ef79`

| Field | Value |
|---|---|
| SHA-256 | `f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295` |
| Family label | `RevStealer` |
| File name | `f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:12:25` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8a243d77152dc6cf46c351441ea3165` |
| SHA-1 | `dddc1afb119fa58ef0c9cf653fcac8f42c47d7c5` |
| SHA-256 | `f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295` |
| SHA3-384 | `b5f2282ea2c25dabad01ba6bfda8061c91aaea04c6fc74c4f7ea4428e862a87ade985b5c16d1ce30f06878b60d3aa4e0` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T1FCD5238EFDB619B0E873C7B942A3647EF069770047A41C5BB7CC6B104E92A582D353B9` |
| SSDEEP | `49152:NnOV4i0V5BZeZHBIFfc8rYN3eZrYjDW1Pb2vHu4NX1XyJdihwjblTvCMJi5hISiq:NOC7V5e0fc8EJeZsjQuO4NX1XyJdihwx` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_079_f426469d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295"
    family = "RevStealer"
    file_name = "f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:12:25"
  condition:
    hash.sha256(0, filesize) == "f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295"
}
```

### Sample 80: `a454cac6c5e295a0`

| Field | Value |
|---|---|
| SHA-256 | `a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307` |
| Family label | `unknown` |
| File name | `a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:11:12` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9d8234affb85e685d5d097be184b55e` |
| SHA-1 | `6bf1c655c81b6efcfce9a7b7c6d7a9c4acf811d0` |
| SHA-256 | `a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307` |
| SHA3-384 | `239365a7e623e0c32bbd761ec7a831bebceddd7367adfbfcdbed1d047388f18d3628b81027379ca942c86e86a4601680` |
| IMPHASH | `c545cbd46cd454816ee104c051afa4df` |
| TLSH | `T1C1750917E76350ECC566D17487AB9273B931BC2D41347A7EAB84DF312B21F60922DB28` |
| SSDEEP | `24576:TDczUEevC30sVjZkWNwoy+pZaJPhiVFShEzU6Fe:XczUfvC3VsAwkpZaJPJU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_a454cac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307"
    family = "unknown"
    file_name = "a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:11:12"
  condition:
    hash.sha256(0, filesize) == "a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307"
}
```

### Sample 81: `d62601d11f25adce`

| Field | Value |
|---|---|
| SHA-256 | `d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f` |
| Family label | `ValleyRAT` |
| File name | `d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:08:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b05ab82e969f5f9e5b85ebf8d06b9f17` |
| SHA-1 | `7f3d4823a5bef0bb82019098e57697d0195e91b8` |
| SHA-256 | `d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f` |
| SHA3-384 | `ceefe7a1a4ef993fd0aa60d7ee3a14a1ed96db17bf84b3e49fbfd0b77c9a9626a9cf50bd2c608628adc5b69567300e6c` |
| IMPHASH | `fb51ede541a9ad63bf23d302e319d2a0` |
| TLSH | `T119D37D4733A450F9D4A78279C9A25A06E7B374660735A7CF17A086BA2F137D0BD3A331` |
| SSDEEP | `3072:qO55k/y5dAj+BMTYlgEQnB+Y+pek7+3OrFZeUqe6oT:qO5n5d56TYZQnB+Dpekyyqm` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_081_d62601d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f"
    family = "ValleyRAT"
    file_name = "d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:08:31"
  condition:
    hash.sha256(0, filesize) == "d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f"
}
```

### Sample 82: `60b22e07cd80d617`

| Field | Value |
|---|---|
| SHA-256 | `60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e` |
| Family label | `CoinMiner` |
| File name | `60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:08:24` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b91d4995253c30ad8cf7870fb7f5f48` |
| SHA-1 | `0ab9c42ee92c0d872bde106aaddecb6334d17ed1` |
| SHA-256 | `60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e` |
| SHA3-384 | `c06f61473a2e1b0c5aa068db298b6ef968db1a530b771b83a213275528a6c606b1b0592b4d5a95408f6af458ce96dca5` |
| IMPHASH | `59bd1de5370a3a1763ca4ab2cd4ba57f` |
| TLSH | `T1D926AD227DE08076C66303328E2CF27976EEB6751F3552C763981F2D6E701D26A38667` |
| SSDEEP | `98304:vcHwGA5gvSrGC3PtXtdcot2jglCZCWrLWas8qtDF1EI:vcHMBGC3PtXtT+Was8qtD/EI` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_082_60b22e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e"
    family = "CoinMiner"
    file_name = "60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:08:24"
  condition:
    hash.sha256(0, filesize) == "60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e"
}
```

### Sample 83: `2174253d9e78ed61`

| Field | Value |
|---|---|
| SHA-256 | `2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a` |
| Family label | `WARDENStealer` |
| File name | `2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:07:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afd3abf5ced28726d94a215bd17389ec` |
| SHA-1 | `0f84c9c18ed5b87b152dee3d20b8a4d06edb3020` |
| SHA-256 | `2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a` |
| SHA3-384 | `55321632d9177945925ab81bc11708bb9200aa6bbf19af88354f7b972a8b886923b3e93d027adac0d325f0f9b5aad4f4` |
| IMPHASH | `e0969ddb3d5cb5107478807ddcd4c08a` |
| TLSH | `T1D0E402D2F69682E8C026C57986221513F6B6BC59076057FF1394B77A1E37AD28F3CB20` |
| SSDEEP | `12288:ZC9QH2XIvKUTDzIDtjKrLcSBLzYAcICgeftlB+Cnle/SZmD6RjSDcmyp67:ZgIvKToRBwkCle/N6cgq` |
| ICON-DHASH | `304cb27171b24c20` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_083_2174253d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a"
    family = "WARDENStealer"
    file_name = "2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:07:21"
  condition:
    hash.sha256(0, filesize) == "2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a"
}
```

### Sample 84: `712f44b90c8a14c0`

| Field | Value |
|---|---|
| SHA-256 | `712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f` |
| Family label | `RevStealer` |
| File name | `712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:03:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf1a5d04194302c8032ae3e8958516bd` |
| SHA-1 | `a55896f3e814533e03c7b0a684f73406e9049c2b` |
| SHA-256 | `712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f` |
| SHA3-384 | `1973a52536ea8354b9fd6625255eccac13ebe3891c24b1683cbb455c0563fcaf768cfde7f9d540840959e5856f806621` |
| IMPHASH | `80809665711013f1bd93814069e02a29` |
| TLSH | `T1A4D523C6A9BA19F4C832C7F78F53E56DB06A7B804B608D1B7ACE2A009C535446C377B5` |
| SSDEEP | `49152:HxDYLX8NQP13xYZ/IWmlGPCPCsCzKztaLbuqFjgARGhcf0NTjwMK1UPsDKjqdQD:H6WI13x+/3Y2aCQtaLKojThOTjwMgYOk` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_084_712f44b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f"
    family = "RevStealer"
    file_name = "712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:03:26"
  condition:
    hash.sha256(0, filesize) == "712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f"
}
```

### Sample 85: `2bbba6f62ea49d98`

| Field | Value |
|---|---|
| SHA-256 | `2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7` |
| Family label | `RevStealer` |
| File name | `2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:01:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf3bf44b3261049861c36085a97bfd9f` |
| SHA-1 | `28e7431d343b49fd7300bb20fac99b07de641022` |
| SHA-256 | `2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7` |
| SHA3-384 | `49eb250b063a0ff5ee1805f84b864b74a49332270d1ccb4b6ca8d7e3d89eaf0ff06a054e3fa4108f9e61770cbb93c23b` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T116D52355BCBA18B0D437C7B18F82F03EB26977568B611E4E3ACE2A009D93549AC3537D` |
| SSDEEP | `49152:yYq2aqFqIZiCSRNmve7XuF+g5EyrWPkHp1YWnivngZo:yYSiqIZLSRsvKG+gcPkJ1YX` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_085_2bbba6f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7"
    family = "RevStealer"
    file_name = "2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:01:34"
  condition:
    hash.sha256(0, filesize) == "2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7"
}
```

### Sample 86: `8b6e5298a4a7e3da`

| Field | Value |
|---|---|
| SHA-256 | `8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69` |
| Family label | `RevStealer` |
| File name | `8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:01:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f011be3c56da0aa34eecd6ac6fba8b82` |
| SHA-1 | `26faf1933d276fb415b46e6574d8e038a46f6e32` |
| SHA-256 | `8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69` |
| SHA3-384 | `4dc46b25d211fec340d1ad5e20944bf8f9f23afb9eb3a9ca901bf529bae03adcb4e563d171e7946cbb0fc1bd09146673` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T18CD52299FDA21434F433C3B397A3607EB12A7B8047645D97B1C56B502D63A18AC3B37A` |
| SSDEEP | `49152:22pK5niEjuNFp32hdKVsTu9gtBKa212UY7qeZ+AytvBs3szaZyaRZM2nnktfuSv6:5EjuNFkhI6TuSTKa212UQ6A0PmVnkt56` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_086_8b6e5298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69"
    family = "RevStealer"
    file_name = "8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:01:29"
  condition:
    hash.sha256(0, filesize) == "8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69"
}
```

### Sample 87: `3382d23877735c74`

| Field | Value |
|---|---|
| SHA-256 | `3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48` |
| Family label | `unknown` |
| File name | `3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:01:21` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f11c8110ec00f4051a8e20c642b358d` |
| SHA-1 | `49aa69ca69ae26860e51730bdaecafbf6de45920` |
| SHA-256 | `3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48` |
| SHA3-384 | `245125a0749a0b42371fb02d400913e0d2a1f3dda51f41d8aa0e11d35edb427d646c3388d731ad2be82cdccfe4a02d0e` |
| IMPHASH | `28e6da99ab314e2e25ec1fbd7703a466` |
| TLSH | `T100558DEDD50809E6D40EE5B5CC71450FDE703D16062484BB6AF43A1A0E8FBE8AF7B616` |
| SSDEEP | `24576:K8lnP0gZS4+xUUfqpxL0zZ8dTDTS6ylnZYKsx/F:KGnjZSKppxAWHSBnE/` |
| ICON-DHASH | `4e3efcf091a14043` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_3382d238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48"
    family = "unknown"
    file_name = "3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:01:21"
  condition:
    hash.sha256(0, filesize) == "3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48"
}
```

### Sample 88: `0c93e7fdddca0d2b`

| Field | Value |
|---|---|
| SHA-256 | `0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be` |
| Family label | `njrat` |
| File name | `3817933FFC4096BE3CBAD2F690EC026F.exe` |
| File type | `exe` |
| First seen | `2026-11-14 00:00:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3817933ffc4096be3cbad2f690ec026f` |
| SHA-1 | `2900ac50dca3f3e6bbe41af908e78a6bfbb7c88d` |
| SHA-256 | `0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be` |
| SHA3-384 | `fcdba570d9e9acaefa9f2b826db698e62826499ac5d2cb6ff631e574165197aa9fb708108bc3d47e0c053e69efebf7e1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15DA2074EB7648619D3ED1AB809A2631447B1FA8B8951DF4B0CDA20CE2F337D06541BFE` |
| SSDEEP | `384:+W6eUSlLXMMvkJrbtrhCDmHiaOWQ+dcs//34LAZSTW1wxll:v6eUqLXBMRJc6uWQuHqfll` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_088_0c93e7fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be"
    family = "njrat"
    file_name = "3817933FFC4096BE3CBAD2F690EC026F.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:00:09"
  condition:
    hash.sha256(0, filesize) == "0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be"
}
```

### Sample 89: `7a0f3b21f69ef32d`

| Field | Value |
|---|---|
| SHA-256 | `7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134` |
| Family label | `unknown` |
| File name | `7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134.sh` |
| File type | `sh` |
| First seen | `2026-11-13 23:38:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66ac7ab1936f5276087839b26bb858bc` |
| SHA-1 | `ab95562a4dcad3baae68b8ba03c93f950b93e0cc` |
| SHA-256 | `7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134` |
| SHA3-384 | `b4e585bd93cf39f763a15c94ea8392a20483efd5144b4e68f07c91725005590bb4f8ebfc2836683260b35d3e2f89e66f` |
| TLSH | `T14022583B21F08B32D3C450C963A61A614E72A70B456614B5F4FE673AAF2C90335E7F61` |
| SSDEEP | `96:cCuxtB6csht+O+v1fsn+h4+tIiKqCTyOysuKNpUj4waYvjsBqJi4C:cCuxv6p4hvZ5m5FoKNpivs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_7a0f3b21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134"
    family = "unknown"
    file_name = "7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134.sh"
    file_type = "sh"
    first_seen = "2026-11-13 23:38:04"
  condition:
    hash.sha256(0, filesize) == "7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134"
}
```

### Sample 90: `bbf589c2a0b2fff1`

| Field | Value |
|---|---|
| SHA-256 | `bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5` |
| Family label | `unknown` |
| File name | `bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5.sh` |
| File type | `sh` |
| First seen | `2026-11-13 23:36:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ed23fbb5cab3695a78c72c91687464d` |
| SHA-1 | `fc400a8781b3af83d85ebeaeb6d8b84a60b45f2f` |
| SHA-256 | `bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5` |
| SHA3-384 | `40c382f951fb0178f7a0e197cb1ad7c07f63dd94a7ffb41fecf71e94f56b3c2f76c2e40cab11b517bd91ea1da56e7df1` |
| TLSH | `T10C52473721F08B3297D061C862771B615FB2960B456724B8F4FE5B269F2DA0370EBB61` |
| SSDEEP | `192:cCuKe6p4hvZ5mN9oKNpivvV6PFITVaHvNMc8nH:fp4hvZ5mN9oKNpivvQPFITVaHvNMc8nH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_bbf589c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5"
    family = "unknown"
    file_name = "bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5.sh"
    file_type = "sh"
    first_seen = "2026-11-13 23:36:04"
  condition:
    hash.sha256(0, filesize) == "bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5"
}
```

### Sample 91: `5999831c9aabcf49`

| Field | Value |
|---|---|
| SHA-256 | `5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 23:32:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c302df2bac878eb380ba4ea2dc1f3cbd` |
| SHA-1 | `de88b75bae727eb431c60fbb4df74183c9c97b5c` |
| SHA-256 | `5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071` |
| SHA3-384 | `281d83b505a2b306e9ab6d3943662b25fa213507640ee12f183924d417b4b30d2752ea9e768770a5c3193326af6a2dce` |
| TLSH | `T161556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSe:SDjxB4m5n8XlaPWi+d+a4TjxQP40` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_5999831c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:32:04"
  condition:
    hash.sha256(0, filesize) == "5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071"
}
```

### Sample 92: `ac12b28cadd1e882`

| Field | Value |
|---|---|
| SHA-256 | `ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 23:16:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b7d791247aa89d07d010a1e0454290a` |
| SHA-1 | `421a725cfc75decd4f6b54847d42f4a9163d1493` |
| SHA-256 | `ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c` |
| SHA3-384 | `3d53ee9ca7f1d810e2e7de9dfe38e2bbe8f68f81c9b28803ec0da67a26b44d1e5dfd19dd7f5199e35b38eb9d228b49bc` |
| TLSH | `T1FD556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSp:SDjxB4m5n8XlaPWi+d+a4TjxQP4X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_ac12b28c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:16:05"
  condition:
    hash.sha256(0, filesize) == "ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c"
}
```

### Sample 93: `e7b94212ac510714`

| Field | Value |
|---|---|
| SHA-256 | `e7b94212ac51071460b64c068d7def8a3141b30b763ae809de85e74e2ca40033` |
| Family label | `unknown` |
| File name | `Fontlayer.rtf` |
| File type | `rtf` |
| First seen | `2026-11-13 23:14:05` |
| Reporter | `abuse_ch` |
| Tags | `rtf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb3814040cb50b3f55ee425e859eafb8` |
| SHA-1 | `c0d19b610e9d36cf2db370eef7edb6acf7594512` |
| SHA-256 | `e7b94212ac51071460b64c068d7def8a3141b30b763ae809de85e74e2ca40033` |
| SHA3-384 | `1bc2ba9d0639ca5e34bfce3503d398bd0e08b35f078298ad7ea350ff7a0e1a0a52eaa5b0d5b5c07d45a5293b0add697b` |
| TLSH | `T10CD17731B8C3014588DA2DC73993C9971379FB17928B44FBA4E8E94C67AAC3CA583F44` |
| SSDEEP | `192:AelzyFfHR+EYAoR3DmEgUO+sAfcKqXqFcJVg8:LlzTEEDmEgUOzayJVg8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rtf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_e7b94212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7b94212ac51071460b64c068d7def8a3141b30b763ae809de85e74e2ca40033"
    family = "unknown"
    file_name = "Fontlayer.rtf"
    file_type = "rtf"
    first_seen = "2026-11-13 23:14:05"
  condition:
    hash.sha256(0, filesize) == "e7b94212ac51071460b64c068d7def8a3141b30b763ae809de85e74e2ca40033"
}
```

### Sample 94: `ab534e4a2614292f`

| Field | Value |
|---|---|
| SHA-256 | `ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9` |
| Family label | `unknown` |
| File name | `ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9.sh` |
| File type | `sh` |
| First seen | `2026-11-13 23:12:05` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62c293322ec5974775180508cc40653e` |
| SHA-1 | `6e9cf55615979034a0797bdaa83a4c56f32f50d5` |
| SHA-256 | `ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9` |
| SHA3-384 | `85c6e3556b53d8e557cfbfb37475fe65061b9529ed32a5e8f313e5ef0366a3e22ab405ec5569c05666b911d720ffd189` |
| TLSH | `T15C72587621F04B339B9055C4B3771BA14FB2961B456720B8F4FE1A259F5AB03B0EBB21` |
| SSDEEP | `192:cCu34hvZ5m5FG4j4HKNphvUh6/lxuFtRd+J:c4hvZ5m5FGGoKNphvUA/lxug` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_ab534e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9"
    family = "unknown"
    file_name = "ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9.sh"
    file_type = "sh"
    first_seen = "2026-11-13 23:12:05"
  condition:
    hash.sha256(0, filesize) == "ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9"
}
```

### Sample 95: `7993520ebfdedba8`

| Field | Value |
|---|---|
| SHA-256 | `7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 23:05:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82468b64019eb3b22c7a5c302d0883d4` |
| SHA-1 | `eedb31fc401939a672b385c622f9df2bd19838e6` |
| SHA-256 | `7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851` |
| SHA3-384 | `9088cf5c5e2ba8859efd5b9889068f0edba4518f379d5ad54853e96756bb46932b261f6deb09e0b063a5dac423a7a01c` |
| TLSH | `T115556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSo:SDjxB4m5n8XlaPWi+d+a4TjxQP4e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_7993520e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:05:06"
  condition:
    hash.sha256(0, filesize) == "7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851"
}
```

### Sample 96: `77a51a49cae68e81`

| Field | Value |
|---|---|
| SHA-256 | `77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 23:03:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2592922154490a7c5fdbe42912896f7` |
| SHA-1 | `bd5ca68df27bc62cbcfec17a5a36325c16bb7570` |
| SHA-256 | `77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568` |
| SHA3-384 | `d31df5c816eb46d70b8eba638f092674b3831820959118741f96e978be2554a3dd0b9d76501a62252b253e87195556b6` |
| TLSH | `T158556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP42` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_77a51a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:03:08"
  condition:
    hash.sha256(0, filesize) == "77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568"
}
```

### Sample 97: `12bc981ef4da1fde`

| Field | Value |
|---|---|
| SHA-256 | `12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-13 23:03:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54d86ef61a6ffded1f769e83bba85b0f` |
| SHA-1 | `eb63a7e311f6cda408389317cb0685f8e92c96f5` |
| SHA-256 | `12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da` |
| SHA3-384 | `72605a97f9343bb275973fee78bd123d47ec5683e3d1795602f399c13ae6846a29757f3b0fe4096036f7c93369742ed7` |
| TLSH | `T126556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSN:SDjxB4m5n8XlaPWi+d+a4TjxQP4X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_12bc981e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:03:06"
  condition:
    hash.sha256(0, filesize) == "12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da"
}
```

### Sample 98: `89eb05e0de1d4bee`

| Field | Value |
|---|---|
| SHA-256 | `89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf` |
| Family label | `Mirai` |
| File name | `nklarm7` |
| File type | `elf` |
| First seen | `2026-11-13 23:01:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e06d6c6665cf1c80580f15e505e5012f` |
| SHA-1 | `d291a7cdb36e51d5d83389f21af737cd1e0ef022` |
| SHA-256 | `89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf` |
| SHA3-384 | `c383bf2039cd5ed97459ffa0f5648681486eea40f35543b57afb7aded63ba722e789dabc2d2579e56bb34431f73099b1` |
| TLSH | `T1F7F33A8ABC819F11D5D525BAFE1E51CD33534BBCE3FA7102DE149B29278A86B0E3B501` |
| TELFHASH | `t1bfe02011444a58f7f89405c4c99f932794da7092738500f026f6ddfc4e764d51135507` |
| SSDEEP | `3072:2HbRAqIcZnwsePbEHW0Tk0dB9y2+zeGNTfLuLM10Z2X4jayVeXxUZVX7iRPEPc3i:SZePq9Tk0dB9yG00X2ojay8XxUZVX7+c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_89eb05e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf"
    family = "Mirai"
    file_name = "nklarm7"
    file_type = "elf"
    first_seen = "2026-11-13 23:01:11"
  condition:
    hash.sha256(0, filesize) == "89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf"
}
```

### Sample 99: `4d2c7e0df331abcb`

| Field | Value |
|---|---|
| SHA-256 | `4d2c7e0df331abcbe4f21525e667dd096462fd22811132dcbe891054f09cafa4` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-13 23:01:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a71f92cdcc73fa3f198d7f31758796a` |
| SHA-1 | `0289726440242f7e1a58acb4a0d463e1cba4a704` |
| SHA-256 | `4d2c7e0df331abcbe4f21525e667dd096462fd22811132dcbe891054f09cafa4` |
| SHA3-384 | `9e57e69ab29ec16eb946e14b0b0588ec029a62d8eebd827d52021d97d238d7c92091895d0ed05bc9f6801188fc5fa8b0` |
| TLSH | `T1E5D3AF12CD744D9CD03A5E71A0F4DAFA8B13A180946B2FF73D96C2694083EC8F55A7B8` |
| SSDEEP | `3072:NB9t39rHYLi2KFSOYnnAtTdrwVbENZ1q00xeq:NB99tHYLi2mSnlWXMdp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_4d2c7e0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d2c7e0df331abcbe4f21525e667dd096462fd22811132dcbe891054f09cafa4"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-13 23:01:08"
  condition:
    hash.sha256(0, filesize) == "4d2c7e0df331abcbe4f21525e667dd096462fd22811132dcbe891054f09cafa4"
}
```

### Sample 100: `78d5a590556ef5c9`

| Field | Value |
|---|---|
| SHA-256 | `78d5a590556ef5c948d4eb82dead8b90d31c6d20bfce5f0f23b2244ddf3d5ddd` |
| Family label | `Mirai` |
| File name | `splsh4` |
| File type | `elf` |
| First seen | `2026-11-13 23:01:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87e57c62366a301cf6d06002169e2eee` |
| SHA-1 | `0b1f0d8da7c7f507e5d53e1b9099388fc490d6db` |
| SHA-256 | `78d5a590556ef5c948d4eb82dead8b90d31c6d20bfce5f0f23b2244ddf3d5ddd` |
| SHA3-384 | `64ac88a83176a76ce83f800f30a0c97b504bc5b23384e54fcbf9d7a884eb9f587bbd56b4167bad002da51c21c51b1a67` |
| TLSH | `T122D3AF42CD705D98E07B6D3260709BB98B23A180815B2DFB3956C7695087ECCF5AB7F8` |
| SSDEEP | `3072:2pwJxJf3xWlVAv2gbx1ARtTFwsTsJBespJNhOO:2pw3l3xWlVS2USZSBnr9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_78d5a590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d5a590556ef5c948d4eb82dead8b90d31c6d20bfce5f0f23b2244ddf3d5ddd"
    family = "Mirai"
    file_name = "splsh4"
    file_type = "elf"
    first_seen = "2026-11-13 23:01:06"
  condition:
    hash.sha256(0, filesize) == "78d5a590556ef5c948d4eb82dead8b90d31c6d20bfce5f0f23b2244ddf3d5ddd"
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
 * Generated: 2026-11-14T06:41:42.858346+00:00
 */

rule MalwareBazaar_Mirai_001_705e26fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54"
    family = "Mirai"
    file_name = "705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54"
    file_type = "elf"
    first_seen = "2026-11-14 06:38:53"
  condition:
    hash.sha256(0, filesize) == "705e26fbfd725f95fcefe2034d88e0c1970983641704b230e8f4c46095749e54"
}

rule MalwareBazaar_njrat_002_f1d177fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d177fd6752b40fbb6a53a76d0a7de76819d73bd87c01bd6add0c37046e916d"
    family = "njrat"
    file_name = "36C22C2F0A3A18E81EB0565729E55E51.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:30"
  condition:
    hash.sha256(0, filesize) == "f1d177fd6752b40fbb6a53a76d0a7de76819d73bd87c01bd6add0c37046e916d"
}

rule MalwareBazaar_njrat_003_38ada6ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38ada6ba9200ba8ab44a59b541492e44dbfb806338cd60ea6cf18f70abac216f"
    family = "njrat"
    file_name = "391d5c7fdafc8bf0eeaa1e28c4863d8e.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:18"
  condition:
    hash.sha256(0, filesize) == "38ada6ba9200ba8ab44a59b541492e44dbfb806338cd60ea6cf18f70abac216f"
}

rule MalwareBazaar_njrat_004_c0f7fe57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0f7fe5744fa2e2f70e5ccd245f72a50f0e9ff3ee5f11010ac99bbcd6f329aa5"
    family = "njrat"
    file_name = "23ff5d33a24096da70940a5e18ae890b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:14"
  condition:
    hash.sha256(0, filesize) == "c0f7fe5744fa2e2f70e5ccd245f72a50f0e9ff3ee5f11010ac99bbcd6f329aa5"
}

rule MalwareBazaar_njrat_005_5c4c829a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c4c829af18020bade14bf27d8da16c636ed390ba459cf0965d7d374bf60e7c3"
    family = "njrat"
    file_name = "1AC05AF367E3BDAEB1E5739321F389BB.exe"
    file_type = "exe"
    first_seen = "2026-11-14 06:35:09"
  condition:
    hash.sha256(0, filesize) == "5c4c829af18020bade14bf27d8da16c636ed390ba459cf0965d7d374bf60e7c3"
}

rule MalwareBazaar_unknown_006_9f6fa054
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a"
    family = "unknown"
    file_name = "9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a"
    file_type = "elf"
    first_seen = "2026-11-14 05:49:05"
  condition:
    hash.sha256(0, filesize) == "9f6fa0544c67bd2d3c59f031c2d9ba107312772aaa7852ddb6cb6d9e94bbeb2a"
}

rule MalwareBazaar_Mirai_007_293c02fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "293c02fd6ac3f30c812d84fe9a0c07cd9377a864a5b18beb53532f5cfa5182cc"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:38:06"
  condition:
    hash.sha256(0, filesize) == "293c02fd6ac3f30c812d84fe9a0c07cd9377a864a5b18beb53532f5cfa5182cc"
}

rule MalwareBazaar_Mirai_008_c06df0b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c06df0b480e58a40690672cc8703304d357c7db9ce3a0a2fc36fe691b99b04e1"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:35:05"
  condition:
    hash.sha256(0, filesize) == "c06df0b480e58a40690672cc8703304d357c7db9ce3a0a2fc36fe691b99b04e1"
}

rule MalwareBazaar_unknown_009_8b39ee44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b39ee449a95bd8faa401749f416948f8a2fe84833437e25a48880f960f92042"
    family = "unknown"
    file_name = "8b39ee449a95bd8f.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 05:31:50"
  condition:
    hash.sha256(0, filesize) == "8b39ee449a95bd8faa401749f416948f8a2fe84833437e25a48880f960f92042"
}

rule MalwareBazaar_Mirai_010_166bcd1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "166bcd1de1b46c709c49a1c4e914437ad0fff86bf7f15d9b975089a2cfa9613a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:30:04"
  condition:
    hash.sha256(0, filesize) == "166bcd1de1b46c709c49a1c4e914437ad0fff86bf7f15d9b975089a2cfa9613a"
}

rule MalwareBazaar_unknown_011_13b556c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13b556c8801c7912d3967e5f3014a23391f664fb9ee834df9257ba7b09cb0ffb"
    family = "unknown"
    file_name = "pm"
    file_type = "elf"
    first_seen = "2026-11-14 05:28:08"
  condition:
    hash.sha256(0, filesize) == "13b556c8801c7912d3967e5f3014a23391f664fb9ee834df9257ba7b09cb0ffb"
}

rule MalwareBazaar_Mirai_012_ec51bfb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec51bfb54e7bff0bfb40ab96a59d35994dceecff6323f8c718421823beb05d85"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:02:07"
  condition:
    hash.sha256(0, filesize) == "ec51bfb54e7bff0bfb40ab96a59d35994dceecff6323f8c718421823beb05d85"
}

rule MalwareBazaar_Mirai_013_9f778da5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f778da58efe52cfa14ac5ef5eab6312a5c545ac10f054e75d119e5dd9292f66"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 05:02:05"
  condition:
    hash.sha256(0, filesize) == "9f778da58efe52cfa14ac5ef5eab6312a5c545ac10f054e75d119e5dd9292f66"
}

rule MalwareBazaar_unknown_014_9fa1fa70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fa1fa70fcc7bf86a19a5292f8a9910d57349d3c1d17dc9297526625a3fe1e60"
    family = "unknown"
    file_name = "Fontlayer.rtf"
    file_type = "rtf"
    first_seen = "2026-11-14 05:00:06"
  condition:
    hash.sha256(0, filesize) == "9fa1fa70fcc7bf86a19a5292f8a9910d57349d3c1d17dc9297526625a3fe1e60"
}

rule MalwareBazaar_Mirai_015_1efa02c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1efa02c1dea0dbdc52610c873dca6d4c6caff4c456c0d606f558fadef02c4cb9"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 04:57:05"
  condition:
    hash.sha256(0, filesize) == "1efa02c1dea0dbdc52610c873dca6d4c6caff4c456c0d606f558fadef02c4cb9"
}

rule MalwareBazaar_Mirai_016_a9ce43c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9ce43c9d2f9d7e8990656e7c5b96e0fb7a65daabc1debfde86af1a0146353f6"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 04:54:04"
  condition:
    hash.sha256(0, filesize) == "a9ce43c9d2f9d7e8990656e7c5b96e0fb7a65daabc1debfde86af1a0146353f6"
}

rule MalwareBazaar_Mirai_017_3f6d9503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f6d950304146e671ff9de563d3861b60112eed39b13fba4e8bd293750bdcff0"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-14 04:36:04"
  condition:
    hash.sha256(0, filesize) == "3f6d950304146e671ff9de563d3861b60112eed39b13fba4e8bd293750bdcff0"
}

rule MalwareBazaar_Arechclient2_018_db8ecda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db8ecda653be2e9df847966f2ef6fbfb7879423ab4459447883ab9c82473bfa7"
    family = "Arechclient2"
    file_name = "eunewport.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:33:41"
  condition:
    hash.sha256(0, filesize) == "db8ecda653be2e9df847966f2ef6fbfb7879423ab4459447883ab9c82473bfa7"
}

rule MalwareBazaar_unknown_019_a6611a44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6611a44c32bc8ba9194298db09c49f1914dffa5ae30a9acb60b2b0641dc802d"
    family = "unknown"
    file_name = "saret.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:26:37"
  condition:
    hash.sha256(0, filesize) == "a6611a44c32bc8ba9194298db09c49f1914dffa5ae30a9acb60b2b0641dc802d"
}

rule MalwareBazaar_Arechclient2_020_414c9037
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "414c9037dce4594441fcf9e835ed11520ec9b6d434718913351ef6d6ba1f547e"
    family = "Arechclient2"
    file_name = "port80.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:25:52"
  condition:
    hash.sha256(0, filesize) == "414c9037dce4594441fcf9e835ed11520ec9b6d434718913351ef6d6ba1f547e"
}

rule MalwareBazaar_unknown_021_10031cfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10031cfa9d5c5bd08ff5dde4837902a56e7b33268cfc6710a8afcf150d960f54"
    family = "unknown"
    file_name = "clsar.msi"
    file_type = "msi"
    first_seen = "2026-11-14 04:24:37"
  condition:
    hash.sha256(0, filesize) == "10031cfa9d5c5bd08ff5dde4837902a56e7b33268cfc6710a8afcf150d960f54"
}

rule MalwareBazaar_njrat_022_9249268a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9249268a2808ef5c8a209a3cb1e378ffb341598a8e205c74b5911317e856dfcf"
    family = "njrat"
    file_name = "C51D39BF1109C2E39CBCA82AC8747F51.exe"
    file_type = "exe"
    first_seen = "2026-11-14 04:05:08"
  condition:
    hash.sha256(0, filesize) == "9249268a2808ef5c8a209a3cb1e378ffb341598a8e205c74b5911317e856dfcf"
}

rule MalwareBazaar_unknown_023_e02a83e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e02a83e5315ba466a90c277eec18beb3ac88b41216de4a13ca754b3c53b8a9ce"
    family = "unknown"
    file_name = "ClientExt.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:48:59"
  condition:
    hash.sha256(0, filesize) == "e02a83e5315ba466a90c277eec18beb3ac88b41216de4a13ca754b3c53b8a9ce"
}

rule MalwareBazaar_unknown_024_6750a40c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6750a40cbec4bed0ad8370c53bc8aea35afdc7d48d89ec314423787fcb3493f8"
    family = "unknown"
    file_name = "PlannerExt.msi"
    file_type = "exe"
    first_seen = "2026-11-14 03:48:31"
  condition:
    hash.sha256(0, filesize) == "6750a40cbec4bed0ad8370c53bc8aea35afdc7d48d89ec314423787fcb3493f8"
}

rule MalwareBazaar_unknown_025_03b5abfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03b5abfd235a0f6a5ec9e7c2cf7793c72bf83065e430b5502a033d42bcd64247"
    family = "unknown"
    file_name = "planner.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 03:46:18"
  condition:
    hash.sha256(0, filesize) == "03b5abfd235a0f6a5ec9e7c2cf7793c72bf83065e430b5502a033d42bcd64247"
}

rule MalwareBazaar_SnappyClient_026_42075237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4207523717b12dcbc8587bca72a7aca4a274823f3ca14c1e8ede7b2ca792798b"
    family = "SnappyClient"
    file_name = "test.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:44:36"
  condition:
    hash.sha256(0, filesize) == "4207523717b12dcbc8587bca72a7aca4a274823f3ca14c1e8ede7b2ca792798b"
}

rule MalwareBazaar_CoinMiner_027_d61bb5af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d61bb5af4b2b1aeeb7bd03c2afd2801d1a3c9bf8c9dab61ccf1dc7c1cd6fb1c4"
    family = "CoinMiner"
    file_name = "vlc_play.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:43:34"
  condition:
    hash.sha256(0, filesize) == "d61bb5af4b2b1aeeb7bd03c2afd2801d1a3c9bf8c9dab61ccf1dc7c1cd6fb1c4"
}

rule MalwareBazaar_unknown_028_7beec4de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7beec4dee8c908d938abbf1d68cf759491a2ea3c3bbab6662162f668c5ea5e8b"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:31:11"
  condition:
    hash.sha256(0, filesize) == "7beec4dee8c908d938abbf1d68cf759491a2ea3c3bbab6662162f668c5ea5e8b"
}

rule MalwareBazaar_unknown_029_2e643fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e643fb2023f10c81c71ada63ed10f865ea5741e475505ce8514d88d8f82a670"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:30:19"
  condition:
    hash.sha256(0, filesize) == "2e643fb2023f10c81c71ada63ed10f865ea5741e475505ce8514d88d8f82a670"
}

rule MalwareBazaar_WARDENStealer_030_6f4ccc17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:29:24"
  condition:
    hash.sha256(0, filesize) == "6f4ccc1718eddb12fab554f0c19e908f0486fd734bb02c706534ad92860d5df2"
}

rule MalwareBazaar_unknown_031_3647f1dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3647f1dd11b4a28e65e03c997b14f1507cfb07ffc412f4b5790dd2b4ec293f92"
    family = "unknown"
    file_name = "Launcher14374.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:28:35"
  condition:
    hash.sha256(0, filesize) == "3647f1dd11b4a28e65e03c997b14f1507cfb07ffc412f4b5790dd2b4ec293f92"
}

rule MalwareBazaar_unknown_032_670c6821
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "670c682101631a1544f4d0b566096f5a2ad9b8bd4967e015871524d406b5c78c"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-14 03:28:08"
  condition:
    hash.sha256(0, filesize) == "670c682101631a1544f4d0b566096f5a2ad9b8bd4967e015871524d406b5c78c"
}

rule MalwareBazaar_unknown_033_8c0cee06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0cee06c37e6290894b97914dc4b1144e52d8fc70507c572a8b3a3b9325089b"
    family = "unknown"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-14 03:26:28"
  condition:
    hash.sha256(0, filesize) == "8c0cee06c37e6290894b97914dc4b1144e52d8fc70507c572a8b3a3b9325089b"
}

rule MalwareBazaar_njrat_034_3c9b11a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c9b11a05c2d8701da8afaffd9e9b68816191c0e107162dba6c3dc1fabc80c96"
    family = "njrat"
    file_name = "69420AFE2FFE9D4E5C9DE7F811CB43B2.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:05:09"
  condition:
    hash.sha256(0, filesize) == "3c9b11a05c2d8701da8afaffd9e9b68816191c0e107162dba6c3dc1fabc80c96"
}

rule MalwareBazaar_WARDENStealer_035_b533bbf0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b533bbf00d28721b87e58052a26ebdbd8183cafa0eb30f1ba639818a07cb0d6c"
    family = "WARDENStealer"
    file_name = "file_patched.exe"
    file_type = "exe"
    first_seen = "2026-11-14 03:01:32"
  condition:
    hash.sha256(0, filesize) == "b533bbf00d28721b87e58052a26ebdbd8183cafa0eb30f1ba639818a07cb0d6c"
}

rule MalwareBazaar_WARDENStealer_036_bf49eede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf49eedeafd28b7b0f2718aeae9f26e5f700229a0ad2d251a91a87a7c2c4f46c"
    family = "WARDENStealer"
    file_name = "file.7z"
    file_type = "7z"
    first_seen = "2026-11-14 03:00:57"
  condition:
    hash.sha256(0, filesize) == "bf49eedeafd28b7b0f2718aeae9f26e5f700229a0ad2d251a91a87a7c2c4f46c"
}

rule MalwareBazaar_njrat_037_46080f45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46080f459577529059ace98473cfd80693744444c8ef828ff5f7377eb10906a0"
    family = "njrat"
    file_name = "2eef62668e8a3ef3124b823f990809c8.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:55:07"
  condition:
    hash.sha256(0, filesize) == "46080f459577529059ace98473cfd80693744444c8ef828ff5f7377eb10906a0"
}

rule MalwareBazaar_unknown_038_4112a8b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4112a8b0d908bbffd9bef308a5c48cf692af00b7624443f56540c23a9e0a9a48"
    family = "unknown"
    file_name = "4112a8b0d908bbff.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 02:47:00"
  condition:
    hash.sha256(0, filesize) == "4112a8b0d908bbffd9bef308a5c48cf692af00b7624443f56540c23a9e0a9a48"
}

rule MalwareBazaar_ConnectWise_039_6084961e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963"
    family = "ConnectWise"
    file_name = "6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963.msi"
    file_type = "msi"
    first_seen = "2026-11-14 02:46:11"
  condition:
    hash.sha256(0, filesize) == "6084961e6a2430ff754d9e31a04bba9329e08e831a0fae36df4a5951af832963"
}

rule MalwareBazaar_WARDENStealer_040_fdeed4bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdeed4bbb15996a5a11f7038740cceefb80e89c7e2e0b9db7c74f18dded3c9e4"
    family = "WARDENStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:44:44"
  condition:
    hash.sha256(0, filesize) == "fdeed4bbb15996a5a11f7038740cceefb80e89c7e2e0b9db7c74f18dded3c9e4"
}

rule MalwareBazaar_WARDENStealer_041_8219c601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8219c601aec2465a74ab251cd5c03eb5689fa5e389192d96dfee218399aa67aa"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:43:47"
  condition:
    hash.sha256(0, filesize) == "8219c601aec2465a74ab251cd5c03eb5689fa5e389192d96dfee218399aa67aa"
}

rule MalwareBazaar_unknown_042_9eb2f990
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb2f990200ff4796df5f1784586c995ac6bbfbacdc79db2bc1d60c9c37ea34f"
    family = "unknown"
    file_name = "9eb2f990200ff479.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 02:42:41"
  condition:
    hash.sha256(0, filesize) == "9eb2f990200ff4796df5f1784586c995ac6bbfbacdc79db2bc1d60c9c37ea34f"
}

rule MalwareBazaar_WARDENStealer_043_70ffad5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ffad5b7c728899de393b96b697f83a5015d9a4ab70c336126832281c646509"
    family = "WARDENStealer"
    file_name = "𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:41:33"
  condition:
    hash.sha256(0, filesize) == "70ffad5b7c728899de393b96b697f83a5015d9a4ab70c336126832281c646509"
}

rule MalwareBazaar_WARDENStealer_044_62c66deb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c66deba94eb51f268ff10c6d8565f5fc52a9cd67819d243f85b672ee13a872"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:41:05"
  condition:
    hash.sha256(0, filesize) == "62c66deba94eb51f268ff10c6d8565f5fc52a9cd67819d243f85b672ee13a872"
}

rule MalwareBazaar_unknown_045_ccd94260
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607"
    family = "unknown"
    file_name = "ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607"
    file_type = "elf"
    first_seen = "2026-11-14 02:26:40"
  condition:
    hash.sha256(0, filesize) == "ccd9426020014d08aea3872e93756b3a35465cd41145a815a106d6a865463607"
}

rule MalwareBazaar_Mirai_046_6fc2257a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fc2257aa8c382907a47853ad2a7f5326a923af5fc91e71cb030da50834ffe9b"
    family = "Mirai"
    file_name = "6fc2257aa8c38290.bin"
    file_type = "elf"
    first_seen = "2026-11-14 02:25:41"
  condition:
    hash.sha256(0, filesize) == "6fc2257aa8c382907a47853ad2a7f5326a923af5fc91e71cb030da50834ffe9b"
}

rule MalwareBazaar_WARDENStealer_047_4b1178a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70"
    family = "WARDENStealer"
    file_name = "4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70.exe"
    file_type = "exe"
    first_seen = "2026-11-14 02:12:01"
  condition:
    hash.sha256(0, filesize) == "4b1178a7cf24888437012e347ba87329d9caa0caee75d9543b7e6e0ed03a7e70"
}

rule MalwareBazaar_unknown_048_ecd8152f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecd8152f3f608066a7c0e88a3ef1c0c02e8245029d0bcfdd7b56c46e5f5f6a95"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-14 01:59:06"
  condition:
    hash.sha256(0, filesize) == "ecd8152f3f608066a7c0e88a3ef1c0c02e8245029d0bcfdd7b56c46e5f5f6a95"
}

rule MalwareBazaar_Mirai_049_89712066
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8971206646c120bb5a019aace52d45a836d1e4aab317ebc42d79070d95e3fe8f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 01:56:04"
  condition:
    hash.sha256(0, filesize) == "8971206646c120bb5a019aace52d45a836d1e4aab317ebc42d79070d95e3fe8f"
}

rule MalwareBazaar_unknown_050_2d352712
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3"
    family = "unknown"
    file_name = "2d352712cad9e47d.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:57"
  condition:
    hash.sha256(0, filesize) == "2d352712cad9e47d9c8ce0b62589e7c09c2a5dd97bd35bf72140a252cc600ea3"
}

rule MalwareBazaar_unknown_051_ae4f1b95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8"
    family = "unknown"
    file_name = "ae4f1b9547db9063.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:51"
  condition:
    hash.sha256(0, filesize) == "ae4f1b9547db90636514df913a422eff22ebf1cf60712e1f1ec5753b6e26a9e8"
}

rule MalwareBazaar_unknown_052_e5566d68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4"
    family = "unknown"
    file_name = "e5566d680f0c6484.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:41"
  condition:
    hash.sha256(0, filesize) == "e5566d680f0c6484b51bceb7d737340bd43aff97164b24bff8b326d02c038af4"
}

rule MalwareBazaar_unknown_053_b4507d1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4507d1dbf431ac6e2de7668d3ede2ae4677774a7cbb0d127b2255c0ec1c7e66"
    family = "unknown"
    file_name = "b4507d1dbf431ac6.bin"
    file_type = "macho"
    first_seen = "2026-11-14 01:25:31"
  condition:
    hash.sha256(0, filesize) == "b4507d1dbf431ac6e2de7668d3ede2ae4677774a7cbb0d127b2255c0ec1c7e66"
}

rule MalwareBazaar_unknown_054_17b7e1f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6"
    family = "unknown"
    file_name = "17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6.exe"
    file_type = "exe"
    first_seen = "2026-11-14 01:16:09"
  condition:
    hash.sha256(0, filesize) == "17b7e1f0e3314c100450379888ed14e3da50f589f5dd93143dcfa43f94a456c6"
}

rule MalwareBazaar_unknown_055_71c94126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71c941269ccac9043df6dc06b2fcde1531861ae6f89e84c9a3712aa6894cb44b"
    family = "unknown"
    file_name = "71c941269ccac904.ps1"
    file_type = "ps1"
    first_seen = "2026-11-14 01:11:59"
  condition:
    hash.sha256(0, filesize) == "71c941269ccac9043df6dc06b2fcde1531861ae6f89e84c9a3712aa6894cb44b"
}

rule MalwareBazaar_unknown_056_394b2b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9"
    family = "unknown"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-14 00:41:27"
  condition:
    hash.sha256(0, filesize) == "394b2b404ecdc32a59028258c2781da857547c7c9cdbfe4eb27966979f3a22e9"
}

rule MalwareBazaar_unknown_057_4cb918bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b"
    family = "unknown"
    file_name = "4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:38:30"
  condition:
    hash.sha256(0, filesize) == "4cb918bdd53fd77c9b2ccaa34f56b7f24c628ae95be9770c7cd829cbc415be3b"
}

rule MalwareBazaar_unknown_058_cf690ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e"
    family = "unknown"
    file_name = "cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:37:37"
  condition:
    hash.sha256(0, filesize) == "cf690ffe7647238ad2744224327de38a6d23826eb8e8ecde32f0a37294fa2b0e"
}

rule MalwareBazaar_WARDENStealer_059_ffbb2d19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69"
    family = "WARDENStealer"
    file_name = "ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:37:30"
  condition:
    hash.sha256(0, filesize) == "ffbb2d190c87f9832e705692d0f9bba7a885672b842a8503279ac50bf0eb0a69"
}

rule MalwareBazaar_unknown_060_a7f0dd6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6"
    family = "unknown"
    file_name = "a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:34"
  condition:
    hash.sha256(0, filesize) == "a7f0dd6c6c8c0cdfc6f466151cb8d645c986125dfb1eccef3d917a538dbc9ef6"
}

rule MalwareBazaar_unknown_061_24052df8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b"
    family = "unknown"
    file_name = "24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:28"
  condition:
    hash.sha256(0, filesize) == "24052df8fe59a39b7c3e0306aa4f87f7c9eb295bc5c40b0939ba19942bb1e93b"
}

rule MalwareBazaar_RevStealer_062_2ea91190
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341"
    family = "RevStealer"
    file_name = "2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:23"
  condition:
    hash.sha256(0, filesize) == "2ea911903802aac88fd73cc65b271737eb4d05024c98cf5845675c503b472341"
}

rule MalwareBazaar_ConnectWise_063_9c7696e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376"
    family = "ConnectWise"
    file_name = "9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:17"
  condition:
    hash.sha256(0, filesize) == "9c7696e3b9f550450d4bdfc931cdb99ae7eb92689e5fd4c4ab4159d6f462a376"
}

rule MalwareBazaar_WARDENStealer_064_d9bb4cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92"
    family = "WARDENStealer"
    file_name = "d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:36:09"
  condition:
    hash.sha256(0, filesize) == "d9bb4cb6977d817979c51558d4e12da10b747ed87122b219a62a1ce64576da92"
}

rule MalwareBazaar_WARDENStealer_065_b797e353
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240"
    family = "WARDENStealer"
    file_name = "b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:33:39"
  condition:
    hash.sha256(0, filesize) == "b797e3534789157cff3ffb1299905648315d89316ff355d122c57e475be1a240"
}

rule MalwareBazaar_CoinMiner_066_d48d8c87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25"
    family = "CoinMiner"
    file_name = "d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:33:30"
  condition:
    hash.sha256(0, filesize) == "d48d8c87335633e9ccf35f6b2fcae5146cc357194ec3d9b4e74b94549b759a25"
}

rule MalwareBazaar_unknown_067_a69452e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a69452e56c7ec55b99e5b5ea24a35b299689c959ea4db02a435f304373b1c34e"
    family = "unknown"
    file_name = "SMBC-Card.apk"
    file_type = "apk"
    first_seen = "2026-11-14 00:33:10"
  condition:
    hash.sha256(0, filesize) == "a69452e56c7ec55b99e5b5ea24a35b299689c959ea4db02a435f304373b1c34e"
}

rule MalwareBazaar_RustyStealer_068_ce1be8e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51"
    family = "RustyStealer"
    file_name = "ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:31:10"
  condition:
    hash.sha256(0, filesize) == "ce1be8e1e7119519872fe26ef4f995e94bcc3bed6915d1eca22650c9688ade51"
}

rule MalwareBazaar_unknown_069_c7f9ed3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7f9ed3d6cda7e15a4a532e7eff76318bd3efea75bb823cf2d14ef1b68c6f232"
    family = "unknown"
    file_name = "my_rakuten_security_v3.apk"
    file_type = "apk"
    first_seen = "2026-11-14 00:30:45"
  condition:
    hash.sha256(0, filesize) == "c7f9ed3d6cda7e15a4a532e7eff76318bd3efea75bb823cf2d14ef1b68c6f232"
}

rule MalwareBazaar_RevStealer_070_b0cc539f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125"
    family = "RevStealer"
    file_name = "b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:28:29"
  condition:
    hash.sha256(0, filesize) == "b0cc539f7e795ad86e529ef0cdb6b95046dfd0e11bcd10397da4118fe21fd125"
}

rule MalwareBazaar_AdaptixC2_071_ced186a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900"
    family = "AdaptixC2"
    file_name = "ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:26:12"
  condition:
    hash.sha256(0, filesize) == "ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900"
}

rule MalwareBazaar_unknown_072_e199d59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e199d59a01c284d44926fc7c497ee08c4e631de305cbd706bbb87800f0d770bd"
    family = "unknown"
    file_name = "e199d59a01c284d4.bin"
    file_type = "exe"
    first_seen = "2026-11-14 00:24:36"
  condition:
    hash.sha256(0, filesize) == "e199d59a01c284d44926fc7c497ee08c4e631de305cbd706bbb87800f0d770bd"
}

rule MalwareBazaar_Mirai_073_2683747e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-14 00:19:05"
  condition:
    hash.sha256(0, filesize) == "2683747e3aa55b68c8ed60e118bb54312ca26a705513e0fcfcc633187d562cd2"
}

rule MalwareBazaar_WARDENStealer_074_b7f4cbde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5"
    family = "WARDENStealer"
    file_name = "b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:18:29"
  condition:
    hash.sha256(0, filesize) == "b7f4cbde98525a79c38d64322dba7d9d2289e4903ad5a245e80ea3a6cfcc7ef5"
}

rule MalwareBazaar_RevStealer_075_88ff3f71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b"
    family = "RevStealer"
    file_name = "88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:17:28"
  condition:
    hash.sha256(0, filesize) == "88ff3f71a48dc2c2caece93a579a2cc9fbf6552dad4889f1425881b6433c911b"
}

rule MalwareBazaar_unknown_076_030cbc08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515"
    family = "unknown"
    file_name = "030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:16:13"
  condition:
    hash.sha256(0, filesize) == "030cbc0898008d3b0da51f748221d093b664d5cb05eca5ef39fc5b7d3442d515"
}

rule MalwareBazaar_ConnectWise_077_8605176d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5"
    family = "ConnectWise"
    file_name = "8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5.msi"
    file_type = "msi"
    first_seen = "2026-11-14 00:12:40"
  condition:
    hash.sha256(0, filesize) == "8605176d7b9e62388acf1a3afc5db7e912709e525857203f5fe9f9ec5e3b9da5"
}

rule MalwareBazaar_RevStealer_078_fe2f1da4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8"
    family = "RevStealer"
    file_name = "fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:12:33"
  condition:
    hash.sha256(0, filesize) == "fe2f1da409b645088f91226eb730c677a37ec1134426f93c74e6afe2855b8bf8"
}

rule MalwareBazaar_RevStealer_079_f426469d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295"
    family = "RevStealer"
    file_name = "f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:12:25"
  condition:
    hash.sha256(0, filesize) == "f426469d0938ef79dfaf3c821ab6f4034608433de8058e3d8a5a681a81ff7295"
}

rule MalwareBazaar_unknown_080_a454cac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307"
    family = "unknown"
    file_name = "a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:11:12"
  condition:
    hash.sha256(0, filesize) == "a454cac6c5e295a00fd1c2f4278efd54534cc7883281bf3229f68f41a4272307"
}

rule MalwareBazaar_ValleyRAT_081_d62601d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f"
    family = "ValleyRAT"
    file_name = "d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:08:31"
  condition:
    hash.sha256(0, filesize) == "d62601d11f25adce7d33f699b80fbe6ab457d0941336627ebe2640cb2675222f"
}

rule MalwareBazaar_CoinMiner_082_60b22e07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e"
    family = "CoinMiner"
    file_name = "60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:08:24"
  condition:
    hash.sha256(0, filesize) == "60b22e07cd80d6171889f3a027168bb33dac7b7316223d4678bcf6d7f919d12e"
}

rule MalwareBazaar_WARDENStealer_083_2174253d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a"
    family = "WARDENStealer"
    file_name = "2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:07:21"
  condition:
    hash.sha256(0, filesize) == "2174253d9e78ed616c82cf2c7334817b3af400cf98c9ac2f348aedb0801d280a"
}

rule MalwareBazaar_RevStealer_084_712f44b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f"
    family = "RevStealer"
    file_name = "712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:03:26"
  condition:
    hash.sha256(0, filesize) == "712f44b90c8a14c071870cc0b7ce0328e594c117ac1004c1adfd99defd86145f"
}

rule MalwareBazaar_RevStealer_085_2bbba6f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7"
    family = "RevStealer"
    file_name = "2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:01:34"
  condition:
    hash.sha256(0, filesize) == "2bbba6f62ea49d9826492991a824c47a5562c9ed8be6eaeb8a9dec015b5bc0c7"
}

rule MalwareBazaar_RevStealer_086_8b6e5298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69"
    family = "RevStealer"
    file_name = "8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:01:29"
  condition:
    hash.sha256(0, filesize) == "8b6e5298a4a7e3da7bede6abc174af99bdbfc0282b1750410282050b83b38a69"
}

rule MalwareBazaar_unknown_087_3382d238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48"
    family = "unknown"
    file_name = "3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:01:21"
  condition:
    hash.sha256(0, filesize) == "3382d23877735c74a5ba39a53da2e6b23c1b8f8e790df6d41b1a05a5cef3cd48"
}

rule MalwareBazaar_njrat_088_0c93e7fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be"
    family = "njrat"
    file_name = "3817933FFC4096BE3CBAD2F690EC026F.exe"
    file_type = "exe"
    first_seen = "2026-11-14 00:00:09"
  condition:
    hash.sha256(0, filesize) == "0c93e7fdddca0d2bb2e9662a119a7ea1a6a433f1543749aa2a759cf4d8aba6be"
}

rule MalwareBazaar_unknown_089_7a0f3b21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134"
    family = "unknown"
    file_name = "7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134.sh"
    file_type = "sh"
    first_seen = "2026-11-13 23:38:04"
  condition:
    hash.sha256(0, filesize) == "7a0f3b21f69ef32dec83e199e1faee3188c0124a5454e60365f194564239e134"
}

rule MalwareBazaar_unknown_090_bbf589c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5"
    family = "unknown"
    file_name = "bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5.sh"
    file_type = "sh"
    first_seen = "2026-11-13 23:36:04"
  condition:
    hash.sha256(0, filesize) == "bbf589c2a0b2fff121f5f86a91b6c09f2a657b0bc13ac5db74d129ac65dfe2c5"
}

rule MalwareBazaar_Mirai_091_5999831c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:32:04"
  condition:
    hash.sha256(0, filesize) == "5999831c9aabcf492a5cf8264624360a8869b79f3963ecefa7979dbfd1a0b071"
}

rule MalwareBazaar_Mirai_092_ac12b28c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:16:05"
  condition:
    hash.sha256(0, filesize) == "ac12b28cadd1e88229275497112cc2dd928ff3e73b8ad7f7f27a34b39d485e7c"
}

rule MalwareBazaar_unknown_093_e7b94212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7b94212ac51071460b64c068d7def8a3141b30b763ae809de85e74e2ca40033"
    family = "unknown"
    file_name = "Fontlayer.rtf"
    file_type = "rtf"
    first_seen = "2026-11-13 23:14:05"
  condition:
    hash.sha256(0, filesize) == "e7b94212ac51071460b64c068d7def8a3141b30b763ae809de85e74e2ca40033"
}

rule MalwareBazaar_unknown_094_ab534e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9"
    family = "unknown"
    file_name = "ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9.sh"
    file_type = "sh"
    first_seen = "2026-11-13 23:12:05"
  condition:
    hash.sha256(0, filesize) == "ab534e4a2614292fcbe42b5ebe39b82fcefde4ac86bf11f63f5f8d492ceba8d9"
}

rule MalwareBazaar_Mirai_095_7993520e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:05:06"
  condition:
    hash.sha256(0, filesize) == "7993520ebfdedba8a56f655840f9a8ffdfd471bec02b1bbbe0a4506d35d46851"
}

rule MalwareBazaar_Mirai_096_77a51a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:03:08"
  condition:
    hash.sha256(0, filesize) == "77a51a49cae68e81c1148f1c9b80fce1a6281561e61bd781d1caf36a3bfee568"
}

rule MalwareBazaar_Mirai_097_12bc981e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-13 23:03:06"
  condition:
    hash.sha256(0, filesize) == "12bc981ef4da1fde32115aeb76ca379363ced137beb171b8323c3c7de4eaf6da"
}

rule MalwareBazaar_Mirai_098_89eb05e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf"
    family = "Mirai"
    file_name = "nklarm7"
    file_type = "elf"
    first_seen = "2026-11-13 23:01:11"
  condition:
    hash.sha256(0, filesize) == "89eb05e0de1d4bee2f8bb96898596e28c9cc2b87ef068f2376598581c9dececf"
}

rule MalwareBazaar_Mirai_099_4d2c7e0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d2c7e0df331abcbe4f21525e667dd096462fd22811132dcbe891054f09cafa4"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-13 23:01:08"
  condition:
    hash.sha256(0, filesize) == "4d2c7e0df331abcbe4f21525e667dd096462fd22811132dcbe891054f09cafa4"
}

rule MalwareBazaar_Mirai_100_78d5a590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d5a590556ef5c948d4eb82dead8b90d31c6d20bfce5f0f23b2244ddf3d5ddd"
    family = "Mirai"
    file_name = "splsh4"
    file_type = "elf"
    first_seen = "2026-11-13 23:01:06"
  condition:
    hash.sha256(0, filesize) == "78d5a590556ef5c948d4eb82dead8b90d31c6d20bfce5f0f23b2244ddf3d5ddd"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

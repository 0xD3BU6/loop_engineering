# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-04

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 626 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 626 |
| Unique family labels | 8 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 66 |
| Mirai | 22 |
| WannaCry | 4 |
| RemcosRAT | 3 |
| Formbook | 2 |
| SilentNet | 1 |
| XWorm | 1 |
| AgentTesla | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 28 |
| elf | 24 |
| apk | 16 |
| sh | 9 |
| zip | 6 |
| rar | 6 |
| js | 3 |
| 7z | 2 |
| unknown | 2 |
| hta | 2 |

## Per-Sample Analysis

### Sample 1: `4ae4d4f2faf96941`

| Field | Value |
|---|---|
| SHA-256 | `4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 03:47:58` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bedd45f963b7f078071bb6eeb1edcae` |
| SHA-1 | `fc778892bd31ad42e967890ca0d4e2a661897841` |
| SHA-256 | `4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d` |
| SHA3-384 | `fa8937007cb22a65e2aabdf7b068687532e1278a42e873a547dba0351a7bb27cfcad4048f48b012c5f3ceecca891a8dd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T197E6331896D411EEE2B38638FED26DA5E4A978610371C6CF1FA447D12E632E08D3D637` |
| SSDEEP | `393216:SsYkXVJgsRfKe9AbXMCHWUjXocuI3/PGTAI:SsdVnJKe9AbXMb8XdH/O7` |
| ICON-DHASH | `71f8fcdccce4f071` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_4ae4d4f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 03:47:58"
  condition:
    hash.sha256(0, filesize) == "4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d"
}
```

### Sample 2: `ce23b56615c9b062`

| Field | Value |
|---|---|
| SHA-256 | `ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface` |
| Family label | `unknown` |
| File name | `a.exe` |
| File type | `exe` |
| First seen | `2026-07-04 03:47:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, exe, eyuboglutv-com, LegionLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcfbe94f7ead20bb942b06ecb67937fd` |
| SHA-1 | `34250e233be1f6dfc22212b556503c625df02075` |
| SHA-256 | `ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface` |
| SHA3-384 | `69de43e14c6159bea983ec21ff9ebfc45d1f6addb2d38c9bfc05e69a54cb0a87fe2d2ac9df14d78ed33e46bdd6e08af9` |
| IMPHASH | `85bddbdc3c4b221d91aa501a1aedc0fc` |
| TLSH | `T14ED4026C1CD717EDC135C63842D3B33AF96EF7E12A254FD3C70292A96A35ED429A1A01` |
| SSDEEP | `12288:rFcwAHYHsQSzOLkvAFh8qKHeVg1Vuayk2REYlteoDUMYFrXILmJ2xWq8Nrb:rFSYMQStvA78qKs2VDeNltbDUMtCJ2o` |
| ICON-DHASH | `0b0787e270ac8603` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_ce23b566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface"
    family = "unknown"
    file_name = "a.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:47:31"
  condition:
    hash.sha256(0, filesize) == "ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface"
}
```

### Sample 3: `82d1751826ee9b99`

| Field | Value |
|---|---|
| SHA-256 | `82d1751826ee9b9914ba01955da3f573ea0cd1f90f8a0ed5e4a719a2d0be40d0` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-04 03:46:35` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, mx-pulsefit-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6c8e452c2dbbf2a5864bd0668318cfa` |
| SHA-1 | `0c8ec0920f02820b5d2266e5fd7fe24e76ece4ec` |
| SHA-256 | `82d1751826ee9b9914ba01955da3f573ea0cd1f90f8a0ed5e4a719a2d0be40d0` |
| SHA3-384 | `a42d03fb3a7347097a1b306878b76e314545432fb31a1b9419e51dbece2262b13a072f295472a538a7c8d140074c96a7` |
| TLSH | `T1009733AC70F5B85EF5E0427BC6C52CF6DB3CA440D79A3D9B8D2081567E8310E5BBA861` |
| SSDEEP | `786432:kTeAoLLBEpUT/vlmOhIrT1IrKJWuiJXXFLcJ:kyAoL9EiT/lIrTQWEqJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_82d17518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82d1751826ee9b9914ba01955da3f573ea0cd1f90f8a0ed5e4a719a2d0be40d0"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-04 03:46:35"
  condition:
    hash.sha256(0, filesize) == "82d1751826ee9b9914ba01955da3f573ea0cd1f90f8a0ed5e4a719a2d0be40d0"
}
```

### Sample 4: `3855f94e68b2b035`

| Field | Value |
|---|---|
| SHA-256 | `3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72` |
| Family label | `unknown` |
| File name | `set-up.exe` |
| File type | `exe` |
| First seen | `2026-07-04 03:44:56` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, AsgardProtector, exe, stream-pawpalace-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a23a1b44ccc709bcbbc23ee3cd6fb342` |
| SHA-1 | `e3abc5b9332579b9b99f490616d33ef7142e223a` |
| SHA-256 | `3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72` |
| SHA3-384 | `e59b2ccf37f6ebab4987ae4ce53b87f2c1e438f28e8ed8cb5b4cf05574fc997f2111c88b6aa9b0d8c705f3c2f6bbee92` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1F485231592F050D7E3B147B0889E925242B1BC311F2551AF22C4DEBE2F63AD8E539BE7` |
| SSDEEP | `49152:6uZjf8vFf0Btbti2Qqz0X+c2ddIp6GUCDiW:vj0YKqz0u7du6qd` |
| ICON-DHASH | `006286010b130c8c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_3855f94e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72"
    family = "unknown"
    file_name = "set-up.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:44:56"
  condition:
    hash.sha256(0, filesize) == "3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72"
}
```

### Sample 5: `d9d65ba90d1cb339`

| Field | Value |
|---|---|
| SHA-256 | `d9d65ba90d1cb339ebfda7ba9f422c475f5f733f4eeafe4dbdb8b666c3c262f4` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-04 03:42:21` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, stream-pawpalace-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90d1190e5e010c1fa6dfcdc08615a5fa` |
| SHA-1 | `458d3d0c2db4e190f59a340e04238f1f6a8e8c6a` |
| SHA-256 | `d9d65ba90d1cb339ebfda7ba9f422c475f5f733f4eeafe4dbdb8b666c3c262f4` |
| SHA3-384 | `308f4af341208aae80227aaca7548954b1f3835fdbadd4ac7434d97a07d6c9fad1f1e6c6b208e8a4ebe74833c0a6c4b9` |
| TLSH | `T1300722A9663D341BF8D09FFD54A638CC1163399818612F2B8F6F04B1F6737297C66862` |
| SSDEEP | `393216:GoMqq+g+jRcQ3ctO1D8FPEB+Jnl7DeUpHesS8Y2nv:Dq/0d3ctOwMUJnl7Dew/YIv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_d9d65ba9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d65ba90d1cb339ebfda7ba9f422c475f5f733f4eeafe4dbdb8b666c3c262f4"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-04 03:42:21"
  condition:
    hash.sha256(0, filesize) == "d9d65ba90d1cb339ebfda7ba9f422c475f5f733f4eeafe4dbdb8b666c3c262f4"
}
```

### Sample 6: `a8c981ac3b86c512`

| Field | Value |
|---|---|
| SHA-256 | `a8c981ac3b86c512d87a116ac8be45c41bb2f89d6a18c9c4354ade3859207529` |
| Family label | `unknown` |
| File name | `recuva_professional__technician_(2026)_full_español_[mega].7z` |
| File type | `7z` |
| First seen | `2026-07-04 03:40:33` |
| Reporter | `iamaachum` |
| Tags | `195-211-191-95, 7z, file-pumped, pw-3579, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0c14d06bf5714834775264a1f96b049` |
| SHA-1 | `de0be7552d6188b294b13597a0939ef0ce68d1a8` |
| SHA-256 | `a8c981ac3b86c512d87a116ac8be45c41bb2f89d6a18c9c4354ade3859207529` |
| SHA3-384 | `18edcb9d8ac39914a3a4a3aa9ddb32b800ced7052a8ff506f8aee547af947959de1b4408da20667978b1fb2ca6ef2e9f` |
| TLSH | `T10307332FD6F1502D7B03F14DB22B8AA9F466D23B0B96B71D0AB28405549FE04569FF23` |
| SSDEEP | `393216:GmHKaGZsPMRts6ASul0Wac4ndALVgY5BWFzz4djX6eoEOiII:Gvp8MRRUac4nmLVxBiz8djXpbL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_a8c981ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c981ac3b86c512d87a116ac8be45c41bb2f89d6a18c9c4354ade3859207529"
    family = "unknown"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-07-04 03:40:33"
  condition:
    hash.sha256(0, filesize) == "a8c981ac3b86c512d87a116ac8be45c41bb2f89d6a18c9c4354ade3859207529"
}
```

### Sample 7: `420ab59a03b591cc`

| Field | Value |
|---|---|
| SHA-256 | `420ab59a03b591cc1024218a80aa2a4b012fdd005c9ffe28c57ba17f9d93c6a2` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full.7z` |
| File type | `7z` |
| First seen | `2026-07-04 03:39:15` |
| Reporter | `iamaachum` |
| Tags | `139-59-137-44, 7z, file-pumped, pw-2252, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3e132f91533364c9123f0a2c48df3e7` |
| SHA-1 | `aec5741d614fb42b87a92e9adf7f5fc0caf2c8e3` |
| SHA-256 | `420ab59a03b591cc1024218a80aa2a4b012fdd005c9ffe28c57ba17f9d93c6a2` |
| SHA3-384 | `2fe920d428bbdb511fb4aa6342c4b440700360eaf2d28948e3a1ed23452c7d2e0dae8ca3a8ad01caadd3a6bc8ba0566a` |
| TLSH | `T16A0733C3FC918FE10E16A6AD89D6327B64CEB4E3C3C79B5C85BF4D5258C6001A61B876` |
| SSDEEP | `393216:Q7BwaMCcQkfJqLYVFcVsGXBZgxEvO0jTmcAZPLrQIwlh8G22uK+hKZN:KOayFBqMVFcV1DgxoOAJAlYr3lucN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_420ab59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420ab59a03b591cc1024218a80aa2a4b012fdd005c9ffe28c57ba17f9d93c6a2"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-07-04 03:39:15"
  condition:
    hash.sha256(0, filesize) == "420ab59a03b591cc1024218a80aa2a4b012fdd005c9ffe28c57ba17f9d93c6a2"
}
```

### Sample 8: `5a67fd7e1f3bd5d1`

| Field | Value |
|---|---|
| SHA-256 | `5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-07-04 03:37:32` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, exe, stream-luminfrastructure-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cd18949fe86667303cd19c683310d55` |
| SHA-1 | `6021e8847189f411d1a913228a0c73eb59c5ff25` |
| SHA-256 | `5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40` |
| SHA3-384 | `e9e0a7e42115d4818523711fc515f7cc7a2a3ccba62f270fe8b67d450c9dae72f8206c9745ba19e3c2214ccb63d5f199` |
| TLSH | `T18EB49C4AEAC382F1EC035677326FF32B6B665D1ACD79CBDEE7E56E40A952240100F251` |
| SSDEEP | `12288:w/rPjP4yBY/2qkBF/JlU11KYuYGDjgyKhrFgtJas/JTwJWBGK4Nou:w/rPkyBGPIzlHYG4ZatJasRTyWBGK4t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_5a67fd7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:37:32"
  condition:
    hash.sha256(0, filesize) == "5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40"
}
```

### Sample 9: `8cbe48fc14585b87`

| Field | Value |
|---|---|
| SHA-256 | `8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f` |
| Family label | `unknown` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-07-04 03:35:50` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, exe, proxy-fluxautomation-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4393ba303809c3ce1e5edcf4fa73d2f6` |
| SHA-1 | `0f06d82432a719e0079783e595dcd3f8277d1bd7` |
| SHA-256 | `8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f` |
| SHA3-384 | `6a19b920c00848599c8a601b74028b25ac7c104773befa1ea9e6307602e6114ccc444a711637a689a04b67c4b957aa67` |
| TLSH | `T1C5B48D49EAC282F3ED436977726FF32F6B629D0A8970C7DEDBE12D55A913E40410E241` |
| SSDEEP | `12288:2FYRrZk6zfPMyX5cBP2UJ9BcTQFZqoCaLKoxaqPcEhX3M:oYRrZkcXfcJ3iT4ZqGKokMcEhX3M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_8cbe48fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:35:50"
  condition:
    hash.sha256(0, filesize) == "8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f"
}
```

### Sample 10: `291c081c856ab085`

| Field | Value |
|---|---|
| SHA-256 | `291c081c856ab085cef02df6f3ac744944cc938d1e5e319b5c5b20d148d76648` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 02:52:51` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d43c9ef2c01a224adee8ea60872ea1c` |
| SHA-1 | `9a9a0ab6d16d087a32ffcb19d34c6262158d4b52` |
| SHA-256 | `291c081c856ab085cef02df6f3ac744944cc938d1e5e319b5c5b20d148d76648` |
| SHA3-384 | `2e77eb348a2578e6969d8023e51ec27a4663d50cb631ac36669cc0dc47339f51e2cc08783ffc144a7fccc17aad197cb1` |
| IMPHASH | `0d2dd6e03a631adfcd00af533a8d15e8` |
| TLSH | `T1B8D52A07E29328ECD56BE13482366732BD61BC5881327E7E5554F7302F79DB0932EA26` |
| SSDEEP | `49152:5odiePhExLauAMPjZ98wotnCh20QlEL6/Ewvl4TxsaNFc5Wgkw3:5Oh+majM4YELDFzrw` |
| ICON-DHASH | `113637393b363610` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_291c081c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "291c081c856ab085cef02df6f3ac744944cc938d1e5e319b5c5b20d148d76648"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 02:52:51"
  condition:
    hash.sha256(0, filesize) == "291c081c856ab085cef02df6f3ac744944cc938d1e5e319b5c5b20d148d76648"
}
```

### Sample 11: `5e4cb6e2b0947184`

| Field | Value |
|---|---|
| SHA-256 | `5e4cb6e2b0947184199d16f75a95da19e32ba730eeddf68dd6a2d65da7357e5e` |
| Family label | `Mirai` |
| File name | `SH4` |
| File type | `elf` |
| First seen | `2026-07-04 02:15:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dd58bcc36e40f30f12776ad5b564ff8` |
| SHA-1 | `e582e795b8d42affb76fb22b98127d7bdcec942a` |
| SHA-256 | `5e4cb6e2b0947184199d16f75a95da19e32ba730eeddf68dd6a2d65da7357e5e` |
| SHA3-384 | `c726bc759b380d730ec207f06467068b2b82621980cd445b812e79ac34d4f36bf3af949fd7cf7fb46c24b42efaa33293` |
| TLSH | `T1CFA34B8A88619FBAC015F0F164FA19311716B8655B5F0EE6B439AED4428F5CFB00FB78` |
| SSDEEP | `1536:C5ZYEMcGi3IXMlXCVKwK3eihJv4vPChnfhdn75h9p/0Is:CYYIX2XC8w2Jv4vPCL75h9p/0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_5e4cb6e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e4cb6e2b0947184199d16f75a95da19e32ba730eeddf68dd6a2d65da7357e5e"
    family = "Mirai"
    file_name = "SH4"
    file_type = "elf"
    first_seen = "2026-07-04 02:15:57"
  condition:
    hash.sha256(0, filesize) == "5e4cb6e2b0947184199d16f75a95da19e32ba730eeddf68dd6a2d65da7357e5e"
}
```

### Sample 12: `2bd0a82af6732a32`

| Field | Value |
|---|---|
| SHA-256 | `2bd0a82af6732a32911224e6392b234b61d6485875cea8d848a88a012591256a` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-04 02:11:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f16ad2f4100fcbf7a5a661c037188031` |
| SHA-1 | `dee7b3d3dfc3650677b1250652a0e6db2006eb4a` |
| SHA-256 | `2bd0a82af6732a32911224e6392b234b61d6485875cea8d848a88a012591256a` |
| SHA3-384 | `77e7061e5f5bd2cc36ed7d626676ab5f318fe135fb704aa318bddc3e0b9c155c1e0716e6c5c16e0249941da631306b41` |
| TLSH | `T14AD05EAB5173022110AA8869F5C6A410B155DBBE89C6A96DBA5B1471AF9434AF2C02A1` |
| SSDEEP | `6:hT80CIx4iSUyPLhHA5WQAulNXYq9DG+NjVsNXYrkJ:VlCIx4fpPL98Piq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_2bd0a82a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd0a82af6732a32911224e6392b234b61d6485875cea8d848a88a012591256a"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-04 02:11:58"
  condition:
    hash.sha256(0, filesize) == "2bd0a82af6732a32911224e6392b234b61d6485875cea8d848a88a012591256a"
}
```

### Sample 13: `8a9dc5e4d7bed616`

| Field | Value |
|---|---|
| SHA-256 | `8a9dc5e4d7bed616871882b6038941598aeecd64b4bde11fee2eb4ce1a8f7e7a` |
| Family label | `Mirai` |
| File name | `X86_64` |
| File type | `elf` |
| First seen | `2026-07-04 02:11:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d67986d6ebf22dcb35ba12be0b4565e2` |
| SHA-1 | `97149b0cf3915c985f9f6c299f7f3e374ebf1677` |
| SHA-256 | `8a9dc5e4d7bed616871882b6038941598aeecd64b4bde11fee2eb4ce1a8f7e7a` |
| SHA3-384 | `a6ef7af316077a30e2d6c91c26ef243d7f3180f1cd55c524a96bb49901aa29927eca27e126f22017eeae28c904c4cd51` |
| TLSH | `T12E936C276651C97FC40BE2F01BDF9962E822B87E0A31708A73D0BE516F5DCD19A19363` |
| TELFHASH | `t16b4188703d9e28a061e3a3327743d599a826193104f171eace72acf6dfa77900c760b7` |
| SSDEEP | `1536:AuEpyFf02hBrppintwYSuiLqZc1rB4n7lt8Kd+mZ2jJI2AUSYJe23PphauJuB50V:xEpV2hJL0DDwnt4Zrd+mQJ1AU7pPphal` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_8a9dc5e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9dc5e4d7bed616871882b6038941598aeecd64b4bde11fee2eb4ce1a8f7e7a"
    family = "Mirai"
    file_name = "X86_64"
    file_type = "elf"
    first_seen = "2026-07-04 02:11:57"
  condition:
    hash.sha256(0, filesize) == "8a9dc5e4d7bed616871882b6038941598aeecd64b4bde11fee2eb4ce1a8f7e7a"
}
```

### Sample 14: `3c0edd3c80f917d0`

| Field | Value |
|---|---|
| SHA-256 | `3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089` |
| Family label | `unknown` |
| File name | `src_0(1).apk` |
| File type | `apk` |
| First seen | `2026-07-04 02:01:50` |
| Reporter | `BastianHein_` |
| Tags | `apk, Bradesco, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d653bcfa007e73971995449155e02e2` |
| SHA-1 | `30aa5d2aa5f990ca81cf74797a79a0a177eaa086` |
| SHA-256 | `3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089` |
| SHA3-384 | `51d22fccad5306d4da8162fcc5db5533a52ed8e7f1a63a1c33a1eccc383b4080463e8540d8fc1e103c8614ce98371128` |
| TLSH | `T1F1B56B47FB08DA5BC0FB53F25A370B6615470E258B439AD75918363E2DB71D02E8AACC` |
| SSDEEP | `49152:S2ge98o/KrRhV8TxYqTz0cgjUAjE4vhUqdUg:So/KrRhVg0tNlZUqdP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_3c0edd3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089"
    family = "unknown"
    file_name = "src_0(1).apk"
    file_type = "apk"
    first_seen = "2026-07-04 02:01:50"
  condition:
    hash.sha256(0, filesize) == "3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089"
}
```

### Sample 15: `3063914cc10de86a`

| Field | Value |
|---|---|
| SHA-256 | `3063914cc10de86a689070151a61172fc17619e71d1bd643a3d0cf94b84e10a8` |
| Family label | `unknown` |
| File name | `src_0.apk` |
| File type | `apk` |
| First seen | `2026-07-04 02:01:38` |
| Reporter | `BastianHein_` |
| Tags | `apk, Bradesco` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82971dbafc4be2da0fd672000082b46f` |
| SHA-1 | `92feb5e1008d80c1c87de8152fecb8bdf83df9f0` |
| SHA-256 | `3063914cc10de86a689070151a61172fc17619e71d1bd643a3d0cf94b84e10a8` |
| SHA3-384 | `c8016a9988d4056c5b2078676076212a9356831ec7311c29f7a574c39c234bc7075e6b4925bdbc9c0b2435785b80dc05` |
| TLSH | `T1C205D003F267A85BF4F6C33616751236E5364D28CB43A786394967FA24BBDE80BC16C4` |
| SSDEEP | `12288:TegtEkTl1iZyVsM9wtfszX2pA9Gkk1yLZXNdkk1yLZXbcZrG5A3qEnqY8dg/Zajx:Tlwtf3y0kV9dkVwUO3bnT8dghUcU+1EL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_3063914c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3063914cc10de86a689070151a61172fc17619e71d1bd643a3d0cf94b84e10a8"
    family = "unknown"
    file_name = "src_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 02:01:38"
  condition:
    hash.sha256(0, filesize) == "3063914cc10de86a689070151a61172fc17619e71d1bd643a3d0cf94b84e10a8"
}
```

### Sample 16: `d8b3327efe0c98be`

| Field | Value |
|---|---|
| SHA-256 | `d8b3327efe0c98be433a7a73591facb031fadcad747ad99e4ac3ccd0e6751290` |
| Family label | `unknown` |
| File name | `res_obs_0.apk` |
| File type | `apk` |
| First seen | `2026-07-04 02:01:25` |
| Reporter | `BastianHein_` |
| Tags | `apk, Bradesco` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9825c7e439bfec4ed859e9652c14f5d` |
| SHA-1 | `2b8f973bb820f28c8f5576b7c506f324302bef96` |
| SHA-256 | `d8b3327efe0c98be433a7a73591facb031fadcad747ad99e4ac3ccd0e6751290` |
| SHA3-384 | `abe419bd291191935e824f40d5ae51d5cc508a57d53d49bf48443dca70dbb2ca7d9ae31228de41fe560a116008134b08` |
| TLSH | `T1F4A57C97FBC49DA9C8F393B14831532169479C318B53958BAC14367C68BB6D43F8AEC8` |
| SSDEEP | `49152:a1dLFo840jNjRT8UEmfehcRKSYPoA2ge9GsVDUU:a1dLO8LRgULfeWRtVV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_d8b3327e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8b3327efe0c98be433a7a73591facb031fadcad747ad99e4ac3ccd0e6751290"
    family = "unknown"
    file_name = "res_obs_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 02:01:25"
  condition:
    hash.sha256(0, filesize) == "d8b3327efe0c98be433a7a73591facb031fadcad747ad99e4ac3ccd0e6751290"
}
```

### Sample 17: `b459673b77209ff8`

| Field | Value |
|---|---|
| SHA-256 | `b459673b77209ff89a2833977b4de341a529722f1e4662451b514df220e13afc` |
| Family label | `unknown` |
| File name | `output_0.apk` |
| File type | `apk` |
| First seen | `2026-07-04 01:59:50` |
| Reporter | `BastianHein_` |
| Tags | `apk, Bradesco` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a57b5ddc38c5713ec0fdd1ab3194674c` |
| SHA-1 | `ce27e178715f75076562753d449411c3f55b848b` |
| SHA-256 | `b459673b77209ff89a2833977b4de341a529722f1e4662451b514df220e13afc` |
| SHA3-384 | `aeaf669406fd44e120547abd24f43121292bf2913966714c4269f6514e62888b34b07db0b8d027b344f3957860eace0a` |
| TLSH | `T1AFC7E006F6B6A89BC8F6C3321574113611371D29CB43F79A394967FD20BBDE84B82AD4` |
| SSDEEP | `24576:ClqtfybRFrduRmVduRMUO3bnT8dghUcU+1E3:CccRZduRmVduRMUSnT8drcF1E3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_b459673b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b459673b77209ff89a2833977b4de341a529722f1e4662451b514df220e13afc"
    family = "unknown"
    file_name = "output_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:59:50"
  condition:
    hash.sha256(0, filesize) == "b459673b77209ff89a2833977b4de341a529722f1e4662451b514df220e13afc"
}
```

### Sample 18: `61d4518fac40db1c`

| Field | Value |
|---|---|
| SHA-256 | `61d4518fac40db1cef72d8b6f9a14080d93ef53a6f6e55605ee12da87978a14f` |
| Family label | `unknown` |
| File name | `entry_added_0.apk` |
| File type | `apk` |
| First seen | `2026-07-04 01:58:59` |
| Reporter | `BastianHein_` |
| Tags | `apk, Bradesco` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c911693a0c7330930edc8cc69fa29b18` |
| SHA-1 | `09d2f7e937d769f1c5009e3674bac514ee009c25` |
| SHA-256 | `61d4518fac40db1cef72d8b6f9a14080d93ef53a6f6e55605ee12da87978a14f` |
| SHA3-384 | `25beb1f8c5c8d27919c716503b419002ea968936c3151b62fc0b7686cfd24d198b9fc926062fd3bd5946e2291fd4713b` |
| TLSH | `T1C1C7E006F6B6A89BC8F6C3321574113615371D29CB43F78A394967FD20BBDE84B82AD4` |
| SSDEEP | `24576:ClFtflbRFrduRmVduRMUO3bnT8dghUcU+1Er:CXPRZduRmVduRMUSnT8drcF1Er` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_61d4518f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61d4518fac40db1cef72d8b6f9a14080d93ef53a6f6e55605ee12da87978a14f"
    family = "unknown"
    file_name = "entry_added_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:58:59"
  condition:
    hash.sha256(0, filesize) == "61d4518fac40db1cef72d8b6f9a14080d93ef53a6f6e55605ee12da87978a14f"
}
```

### Sample 19: `fea09cb621507334`

| Field | Value |
|---|---|
| SHA-256 | `fea09cb621507334ff92f30e0455db20e0de38a86e8b3e38c434340cc4ca2112` |
| Family label | `unknown` |
| File name | `apksigner7474716956837711150.apk` |
| File type | `apk` |
| First seen | `2026-07-04 01:58:11` |
| Reporter | `BastianHein_` |
| Tags | `apk, Bradesco` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96f827bc8f130d2328a35e5bea7a4676` |
| SHA-1 | `5d150efc7e53b2c7ed0097e299710d6df544fef2` |
| SHA-256 | `fea09cb621507334ff92f30e0455db20e0de38a86e8b3e38c434340cc4ca2112` |
| SHA3-384 | `f07b50ae05b28606c2866df45217f6c6a1d0684fc4a021f85ccac7342c517df7c916b88298f13067d83fbe270c7edabe` |
| TLSH | `T1CBC7E006F6B6A89BC8F6C3321574113611371E19CB43E79A394967FD30BBDE84B82AD4` |
| SSDEEP | `24576:Clqtfy0RFrduRmVduRMUO3bnT8dghUcU+1EH:Cc3RZduRmVduRMUSnT8drcF1EH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_fea09cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fea09cb621507334ff92f30e0455db20e0de38a86e8b3e38c434340cc4ca2112"
    family = "unknown"
    file_name = "apksigner7474716956837711150.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:58:11"
  condition:
    hash.sha256(0, filesize) == "fea09cb621507334ff92f30e0455db20e0de38a86e8b3e38c434340cc4ca2112"
}
```

### Sample 20: `de40109b05faaca5`

| Field | Value |
|---|---|
| SHA-256 | `de40109b05faaca5c2715008b6d1af0ab53652a424346ff4ee2ade44c76b8c41` |
| Family label | `Mirai` |
| File name | `ARMV7L` |
| File type | `elf` |
| First seen | `2026-07-04 01:47:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f1ab01a3e337f1f786f452d2d4a1909` |
| SHA-1 | `ee5b257e21f3a3e4b1f85398c286cfce6d6b547d` |
| SHA-256 | `de40109b05faaca5c2715008b6d1af0ab53652a424346ff4ee2ade44c76b8c41` |
| SHA3-384 | `55583290f5d6ae83de9cee3389a9c788eccf7c44722814fc5310770e8235930c60598ec3299400612c58f3ad931255aa` |
| TLSH | `T1F8D30A4DE9506B19C6E271FBFB9E52CE33271FADE3EB3021C9304B9123C5A964A36511` |
| SSDEEP | `3072:HrO+ic8zkFaXDm2AOc5N3ZSzPvRNi+BTO5h9p/EI/:6LvIFaXK2Pc5N3czji+Ba5h8I/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_de40109b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de40109b05faaca5c2715008b6d1af0ab53652a424346ff4ee2ade44c76b8c41"
    family = "Mirai"
    file_name = "ARMV7L"
    file_type = "elf"
    first_seen = "2026-07-04 01:47:56"
  condition:
    hash.sha256(0, filesize) == "de40109b05faaca5c2715008b6d1af0ab53652a424346ff4ee2ade44c76b8c41"
}
```

### Sample 21: `f966b81a9ed9c9f0`

| Field | Value |
|---|---|
| SHA-256 | `f966b81a9ed9c9f025cb92f12cf4839a2ff37b8ca14133ae214a4f88c0efc56a` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-04 01:36:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ef302169ca6336d95c9a19a34e1546b` |
| SHA-1 | `5e8d0b5bc0058b4cc7c58d2271d2e6bc71690722` |
| SHA-256 | `f966b81a9ed9c9f025cb92f12cf4839a2ff37b8ca14133ae214a4f88c0efc56a` |
| SHA3-384 | `9892972274f594f7c874ff3ad3c3a38203423bd877a7be5626c8fea0de0b21862a9aed76b38fb005e4c0e1a536452b58` |
| TLSH | `T12B01AFC98910A820406D992E229765D0B410C3CE064B4FB47FDC5D3DF7DC91CB076F89` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkacC7AFwC2J2CWeCZsU88C60NauD:kXCKysE2hi0ziQvZohacEAygig130N7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_f966b81a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f966b81a9ed9c9f025cb92f12cf4839a2ff37b8ca14133ae214a4f88c0efc56a"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-04 01:36:59"
  condition:
    hash.sha256(0, filesize) == "f966b81a9ed9c9f025cb92f12cf4839a2ff37b8ca14133ae214a4f88c0efc56a"
}
```

### Sample 22: `6d32be92b12fa0a7`

| Field | Value |
|---|---|
| SHA-256 | `6d32be92b12fa0a7f39fb49c2870673cd8bd8e89374eff5255725711372e9bcc` |
| Family label | `Mirai` |
| File name | `POWERPC` |
| File type | `elf` |
| First seen | `2026-07-04 01:35:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e50737b8a3ea9dcc7ba771f4c7cc8a34` |
| SHA-1 | `16181348967bb36b9a9c6eb0bb708e06f454a070` |
| SHA-256 | `6d32be92b12fa0a7f39fb49c2870673cd8bd8e89374eff5255725711372e9bcc` |
| SHA3-384 | `7f7846d8525df351b0dd1280cbaccf4762b11bfdefcd3595b33b53703638b3b09c73b01ba9200bb497248e05d6dfaccd` |
| TLSH | `T156B3070FAB2D0B47C5A75AF03E3B27E0879DEA6211E452C5A41AFDC147318F62126FE5` |
| SSDEEP | `3072:dlpcCZVC9GKMo5zVDksU6NsBgSWKC5h9p/Vk:dlpcyVtKMo55wN6NsjWKC5htk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_6d32be92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d32be92b12fa0a7f39fb49c2870673cd8bd8e89374eff5255725711372e9bcc"
    family = "Mirai"
    file_name = "POWERPC"
    file_type = "elf"
    first_seen = "2026-07-04 01:35:59"
  condition:
    hash.sha256(0, filesize) == "6d32be92b12fa0a7f39fb49c2870673cd8bd8e89374eff5255725711372e9bcc"
}
```

### Sample 23: `25b2e83c211a98b0`

| Field | Value |
|---|---|
| SHA-256 | `25b2e83c211a98b07222e3706365cbf5da043062146d5258a70ff2da9185e0da` |
| Family label | `Mirai` |
| File name | `MIPS` |
| File type | `elf` |
| First seen | `2026-07-04 01:32:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e7e1a1b77aa6a7551fd2e31034a46c6` |
| SHA-1 | `84483c4aed8c11618f76a310d85f087485887dba` |
| SHA-256 | `25b2e83c211a98b07222e3706365cbf5da043062146d5258a70ff2da9185e0da` |
| SHA3-384 | `9b33010b010b2d818bfd8b8ae547f7c5edcc04de3a9606d7e008f6181fa067748ce7cac2b265111eaa43869b32c53010` |
| TLSH | `T124F3437E7E21AF7FE178863107F76EB0C35522D326E19281E16CDA085E7428D185F7A4` |
| TELFHASH | `t135318d1c897813f0a7754c9d17eeef7ae5a030df4a265d378e00e9adaa6dc825d00c1c` |
| SSDEEP | `1536:dCWwIgu1Q6oIumRb37l20ZkarXdQx/2EXfYIEqJOAFY+ey9k/Up2NUpDM7D2huoW:+VU+YpnKTwEN6t4t9xC5hdpPRJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_25b2e83c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25b2e83c211a98b07222e3706365cbf5da043062146d5258a70ff2da9185e0da"
    family = "Mirai"
    file_name = "MIPS"
    file_type = "elf"
    first_seen = "2026-07-04 01:32:56"
  condition:
    hash.sha256(0, filesize) == "25b2e83c211a98b07222e3706365cbf5da043062146d5258a70ff2da9185e0da"
}
```

### Sample 24: `903f7182ad5cb63e`

| Field | Value |
|---|---|
| SHA-256 | `903f7182ad5cb63e3db43df0b86f781665c55c2bd2e62b92782ec44c8d867146` |
| Family label | `Mirai` |
| File name | `ARMV4L` |
| File type | `elf` |
| First seen | `2026-07-04 01:28:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bf02230d4b9c70eedec4708cfd84b18` |
| SHA-1 | `61da530f17005ccfef9d5f03143f10d431433b5e` |
| SHA-256 | `903f7182ad5cb63e3db43df0b86f781665c55c2bd2e62b92782ec44c8d867146` |
| SHA3-384 | `fa31efd024756ff4cc16067cf5abbe36434daa14edf87ff1d07f634d53607af5d10672b002921e69f0ab3c8a7173a7cf` |
| TLSH | `T1E9B3F649FE04972AC3D2B2FBFB5D03CE362B1B6DA7EB31169A305E9133C5A951936110` |
| SSDEEP | `1536:q4w+Q4Jj0ybNcULq31VO40CikAc8rVpzdcxN+YMcw4YtOKOQGOYPbAb4xbaIvs5w:DeP1JawN/o4fVzAE9Ls5h9p/0+m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_903f7182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "903f7182ad5cb63e3db43df0b86f781665c55c2bd2e62b92782ec44c8d867146"
    family = "Mirai"
    file_name = "ARMV4L"
    file_type = "elf"
    first_seen = "2026-07-04 01:28:54"
  condition:
    hash.sha256(0, filesize) == "903f7182ad5cb63e3db43df0b86f781665c55c2bd2e62b92782ec44c8d867146"
}
```

### Sample 25: `bcb93b961d7188b3`

| Field | Value |
|---|---|
| SHA-256 | `bcb93b961d7188b32745b05b700959ba49d5b05ea870d9eeed2e2db63e8b7575` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-04 01:27:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daa3501c18296893f7a6928b91cbfec7` |
| SHA-1 | `a7648ce4b2ab87e898e28f2fbf943006162d2153` |
| SHA-256 | `bcb93b961d7188b32745b05b700959ba49d5b05ea870d9eeed2e2db63e8b7575` |
| SHA3-384 | `d92349f2277ba59e5852dbd031cd70aaa5b306d631193b46abae2e97bef517ca4435a7194532c624950e063fab887f31` |
| TLSH | `T15C01AFC988149C2040AE992D229764D4F410C3CE164B8F75BFAC7D39EBD891CB076F89` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkacC7mwC2t2CMeCZ6U88C6qX:kXCKysE2hi0ziQvZohacExkGU13qX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_bcb93b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcb93b961d7188b32745b05b700959ba49d5b05ea870d9eeed2e2db63e8b7575"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-04 01:27:53"
  condition:
    hash.sha256(0, filesize) == "bcb93b961d7188b32745b05b700959ba49d5b05ea870d9eeed2e2db63e8b7575"
}
```

### Sample 26: `e763dd5e7ae6b2d1`

| Field | Value |
|---|---|
| SHA-256 | `e763dd5e7ae6b2d1436f7f659dd4511e4bef24c5823fd0739dd1c9ec5154a4c0` |
| Family label | `unknown` |
| File name | `ۦۖ۫.apk` |
| File type | `apk` |
| First seen | `2026-07-04 01:24:20` |
| Reporter | `BastianHein_` |
| Tags | `apk, Hdfc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7646a146900df9a86102dd669ed4f59` |
| SHA-1 | `f3d95ff6f1de8c8933ac08d40c446d37a385f97a` |
| SHA-256 | `e763dd5e7ae6b2d1436f7f659dd4511e4bef24c5823fd0739dd1c9ec5154a4c0` |
| SHA3-384 | `3db2f8668b1a4219c1b861b751459c52ffb5498a93f25629ab2090a9431eb6211130464cdb336275a94bee651ac34d80` |
| TLSH | `T15C66128B9782922BC43C85BA4DA7333556179D1589F2430BE12C365CBD736F88FD8E98` |
| SSDEEP | `98304:FzaY+SUmS8vWVtNcjJSjeC1Zv0wplhSQnZ4sr/kzdt+LLYOY3oCz/Y1dqbpYuKK+:FGvZjx1qQlhzG4kH+4DoCrY1dQpYuA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_e763dd5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e763dd5e7ae6b2d1436f7f659dd4511e4bef24c5823fd0739dd1c9ec5154a4c0"
    family = "unknown"
    file_name = "ۦۖ۫.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:24:20"
  condition:
    hash.sha256(0, filesize) == "e763dd5e7ae6b2d1436f7f659dd4511e4bef24c5823fd0739dd1c9ec5154a4c0"
}
```

### Sample 27: `1ba4bb9f0990697f`

| Field | Value |
|---|---|
| SHA-256 | `1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a` |
| Family label | `unknown` |
| File name | `temp_info.apk` |
| File type | `apk` |
| First seen | `2026-07-04 01:24:04` |
| Reporter | `BastianHein_` |
| Tags | `apk, Hdfc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e98ac10945ac4ee27c0397677f5e5ec0` |
| SHA-1 | `d81a1fe640b844031f94dfcc55768dabce48910b` |
| SHA-256 | `1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a` |
| SHA3-384 | `cf293f8f87d15fd3bed856790abf65982b9316e97761e786beba38d2d331cec90275e6d5988f0f156b6583757184c5a1` |
| TLSH | `T16776014BF7C59B2BC53980BA4827323652575D0A8A93821BED2CB71C78735F45F88BD8` |
| SSDEEP | `196608:LedyVcRD2AZvVVNgl1XaD+ebY5pHKhNvMqg:LedXRbZvl2KbOoNvpg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_1ba4bb9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a"
    family = "unknown"
    file_name = "temp_info.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:24:04"
  condition:
    hash.sha256(0, filesize) == "1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a"
}
```

### Sample 28: `f6645b4590b974e3`

| Field | Value |
|---|---|
| SHA-256 | `f6645b4590b974e3c52db619a8c65a52d0a6671a73cf991a59e17725262c230d` |
| Family label | `Mirai` |
| File name | `Mozi.a` |
| File type | `elf` |
| First seen | `2026-07-04 01:20:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `835c1cb6a6314431648526cf32aec85f` |
| SHA-1 | `5f26cdf1e1b7d1c9b436e324e50e2f4c3f8d2bf4` |
| SHA-256 | `f6645b4590b974e3c52db619a8c65a52d0a6671a73cf991a59e17725262c230d` |
| SHA3-384 | `b04daf9a013bb75fb738b36f5d64679ca73025b4d4113b4ecf764305f8ec109cf8308cd399a7ebce636e0db4273c6742` |
| TLSH | `T1DE44398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJx:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_f6645b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6645b4590b974e3c52db619a8c65a52d0a6671a73cf991a59e17725262c230d"
    family = "Mirai"
    file_name = "Mozi.a"
    file_type = "elf"
    first_seen = "2026-07-04 01:20:58"
  condition:
    hash.sha256(0, filesize) == "f6645b4590b974e3c52db619a8c65a52d0a6671a73cf991a59e17725262c230d"
}
```

### Sample 29: `36669b2129c9bb80`

| Field | Value |
|---|---|
| SHA-256 | `36669b2129c9bb80926741214cf045703aafdeddf48604fcd348a41fb80ad9aa` |
| Family label | `Mirai` |
| File name | `ARMV5L` |
| File type | `elf` |
| First seen | `2026-07-04 01:18:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ce31ea2a4c520acaa195d6073c695ae` |
| SHA-1 | `aa7be359233e0b45511186df564611c35b97e738` |
| SHA-256 | `36669b2129c9bb80926741214cf045703aafdeddf48604fcd348a41fb80ad9aa` |
| SHA3-384 | `c4a80928338197d065300e78b07e4bb6c989308dac2e21befe29f2d744f5da684fd3fc36385c8aca9c718f98e4c1bf8c` |
| TLSH | `T1E7B3E749FD05A72AC3D2B1FBFB5D03CE362B1B6EA7EB31169A305E9133C4A951936110` |
| TELFHASH | `t184c08c860e7a1cc81094278d00cc622d4060ba8a6c20347c5cf94f1a80062d1e0135b7` |
| SSDEEP | `1536:rQgeQ4Jj0ybNcULF3FVRLMYwArQ9ztMJp72QQsYtO6PURLovn/0hXE5x5h9p/0om:ie6FTLowpesB0v/G0r5h9p/0om` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_36669b21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36669b2129c9bb80926741214cf045703aafdeddf48604fcd348a41fb80ad9aa"
    family = "Mirai"
    file_name = "ARMV5L"
    file_type = "elf"
    first_seen = "2026-07-04 01:18:58"
  condition:
    hash.sha256(0, filesize) == "36669b2129c9bb80926741214cf045703aafdeddf48604fcd348a41fb80ad9aa"
}
```

### Sample 30: `c5950c484b3fdf3f`

| Field | Value |
|---|---|
| SHA-256 | `c5950c484b3fdf3f64c019c49d04232845b156b18e30198e163e2a9c14bf05c0` |
| Family label | `Mirai` |
| File name | `ARMV6L` |
| File type | `elf` |
| First seen | `2026-07-04 01:14:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9596a0a627b55cc2ae738dfe072d5ae9` |
| SHA-1 | `d2262ff87a75bf0dc128b647ee2df880ddb18e92` |
| SHA-256 | `c5950c484b3fdf3f64c019c49d04232845b156b18e30198e163e2a9c14bf05c0` |
| SHA3-384 | `fef16298dae7d42abcf645dcc868c0297abeb90cf6b7e48341f52e5a634f494413f50ff1c8a32d84607be0abb92842ea` |
| TLSH | `T11DC3F849E9109729C3E272FBFB5952CF72271FACA3DB3126CA304F9123C56E61939521` |
| SSDEEP | `3072:vZ1bKcehaQECGkWR3fBzF/GTwv5h9p/VSC:zWzhaQExkWRrGUv5hNSC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_c5950c48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5950c484b3fdf3f64c019c49d04232845b156b18e30198e163e2a9c14bf05c0"
    family = "Mirai"
    file_name = "ARMV6L"
    file_type = "elf"
    first_seen = "2026-07-04 01:14:54"
  condition:
    hash.sha256(0, filesize) == "c5950c484b3fdf3f64c019c49d04232845b156b18e30198e163e2a9c14bf05c0"
}
```

### Sample 31: `b8db3025146cacb9`

| Field | Value |
|---|---|
| SHA-256 | `b8db3025146cacb9959e2e3c7b28f909478e1f8ed6e35c699c4b72cbcd311531` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-04 01:07:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d79bdc555e2f69fea9a4f68a8920412d` |
| SHA-1 | `8e0173c14b73aa2b7b7c3e7ecaf97079bedc6a3b` |
| SHA-256 | `b8db3025146cacb9959e2e3c7b28f909478e1f8ed6e35c699c4b72cbcd311531` |
| SHA3-384 | `53777aef0c241c3e85ff38d0ef11c09e314ba0415147d437b669da6acfda1e00000ff2c5acc8033290406d5c845ab054` |
| TLSH | `T118237D6516817C24AA99D4371D7F1F0CBDA983E6320492DD7FCA3CF28C59A9CD11872D` |
| SSDEEP | `768:TXRWNGxVB9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:tlx4cB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_b8db3025
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8db3025146cacb9959e2e3c7b28f909478e1f8ed6e35c699c4b72cbcd311531"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-04 01:07:54"
  condition:
    hash.sha256(0, filesize) == "b8db3025146cacb9959e2e3c7b28f909478e1f8ed6e35c699c4b72cbcd311531"
}
```

### Sample 32: `71a395a22d8ad742`

| Field | Value |
|---|---|
| SHA-256 | `71a395a22d8ad7421b7050c650187c771ea52d5820640b259d79dfcd8c4adb1b` |
| Family label | `unknown` |
| File name | `gg10` |
| File type | `elf` |
| First seen | `2026-07-04 01:01:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fde43e824b428e7eb557d0b6f88b750a` |
| SHA-1 | `401ba140a802f9a3e57f15ebe7344e19bfce35dd` |
| SHA-256 | `71a395a22d8ad7421b7050c650187c771ea52d5820640b259d79dfcd8c4adb1b` |
| SHA3-384 | `90d875e7500da042e376258b6333c61bca090f5f8949bc5e5d353d4c405c216a6cafda7cf20637af9ac26cbca1345163` |
| TLSH | `T156077B43ECA515E9C5A9D2308A739253BB71BC495B3127D32B90F3382E77BD0A9B9740` |
| TELFHASH | `t1ef32447509bd39b5b696da10b3a2b4f495371ca972f838b11023e995ffc5e801ce2837` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:jopv876YrwvTRZmbrZlal09s7VDgJyleBB0ovwNxlH9Iq1EYsKViiam5+uPxaaiF:jATXRA+lb7OJyw58QTKViq5YhFwTT8Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_71a395a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71a395a22d8ad7421b7050c650187c771ea52d5820640b259d79dfcd8c4adb1b"
    family = "unknown"
    file_name = "gg10"
    file_type = "elf"
    first_seen = "2026-07-04 01:01:59"
  condition:
    hash.sha256(0, filesize) == "71a395a22d8ad7421b7050c650187c771ea52d5820640b259d79dfcd8c4adb1b"
}
```

### Sample 33: `357d6a12b37bf725`

| Field | Value |
|---|---|
| SHA-256 | `357d6a12b37bf72550d9df5035f25157d3ca75e1a69e71783586ee4759ee7b45` |
| Family label | `unknown` |
| File name | `cleaned_apk_1205069634158871545.apk` |
| File type | `apk` |
| First seen | `2026-07-04 00:58:15` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2392f90a759489a5ea8c2ad11866e90` |
| SHA-1 | `c7e0aeb927ac547dc1e7446d3f4054a41cc4a6b8` |
| SHA-256 | `357d6a12b37bf72550d9df5035f25157d3ca75e1a69e71783586ee4759ee7b45` |
| SHA3-384 | `6fc916e49c20b4a71468a5f6c4dacf3db6d49e21aa597be3e4a77df3bbed1563bf43daf75392b8d594c8d2745efc8b70` |
| TLSH | `T1E5762352F759690EC8F3E3322D7552392066CC61DB03E387952873B829BFAE84F466D4` |
| SSDEEP | `196608:o/KNpYMFSOQzVztNAh18Wf8ht0VZdLDqAzqDS9AsiT5A:u6pIrpnWfGt0PqfT5A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_357d6a12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "357d6a12b37bf72550d9df5035f25157d3ca75e1a69e71783586ee4759ee7b45"
    family = "unknown"
    file_name = "cleaned_apk_1205069634158871545.apk"
    file_type = "apk"
    first_seen = "2026-07-04 00:58:15"
  condition:
    hash.sha256(0, filesize) == "357d6a12b37bf72550d9df5035f25157d3ca75e1a69e71783586ee4759ee7b45"
}
```

### Sample 34: `da258307c6105801`

| Field | Value |
|---|---|
| SHA-256 | `da258307c61058016d7e553c07f00dcc06c119ce40536db59d4f726c16d32fb2` |
| Family label | `Mirai` |
| File name | `SPARC` |
| File type | `elf` |
| First seen | `2026-07-04 00:54:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5ab643f9be750419a67048876cb7ed1` |
| SHA-1 | `87043dfea777c50ebbb2e0d06b90d70d6f9da69b` |
| SHA-256 | `da258307c61058016d7e553c07f00dcc06c119ce40536db59d4f726c16d32fb2` |
| SHA3-384 | `40b6115f0558683fc3f208444475436b59f71168bde718b216d223064b5b9d52a2946c17818e66c6bb27b83d415e5a09` |
| TLSH | `T1B3C3E73B2B231F23C0D520B252E30231F9B6D75938BC8797A8E12C9E6F1999435567ED` |
| SSDEEP | `1536:mYni2s0AtHK/lmFHvT6IF7S6nN95VEttRtKMYphaqJZAKG:Zi2shHKtSb6IF7SgNPyyMYphaqJZAn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_da258307
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da258307c61058016d7e553c07f00dcc06c119ce40536db59d4f726c16d32fb2"
    family = "Mirai"
    file_name = "SPARC"
    file_type = "elf"
    first_seen = "2026-07-04 00:54:54"
  condition:
    hash.sha256(0, filesize) == "da258307c61058016d7e553c07f00dcc06c119ce40536db59d4f726c16d32fb2"
}
```

### Sample 35: `2a51dabd7c6c63d8`

| Field | Value |
|---|---|
| SHA-256 | `2a51dabd7c6c63d88ae13ca65a8a01c99fae1d4913a08ace28910c6f47074323` |
| Family label | `Mirai` |
| File name | `MIPSEL` |
| File type | `elf` |
| First seen | `2026-07-04 00:50:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05eb772cbf83cc672c264693d3a0b6c0` |
| SHA-1 | `1471b6e2d38e59b7d5246bcdc8dd6a368315f435` |
| SHA-256 | `2a51dabd7c6c63d88ae13ca65a8a01c99fae1d4913a08ace28910c6f47074323` |
| SHA3-384 | `24d99b58bbd2191e32abcfb0adbd1953483c461f682fee33b5e9f02deb66f32238754e4a3445ace73a257507e94322af` |
| TLSH | `T11CF38556AB619EB7C80FCD3302A94A0210CCA65A52E93B6FB6B0C55CF34BD4F45E3D94` |
| SSDEEP | `3072:9fHHas7X1SHaE/X1qu22vsyRpTF8x6IYG5hdpPTV:9fHHCRpTF8x5YG5h7V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_2a51dabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a51dabd7c6c63d88ae13ca65a8a01c99fae1d4913a08ace28910c6f47074323"
    family = "Mirai"
    file_name = "MIPSEL"
    file_type = "elf"
    first_seen = "2026-07-04 00:50:56"
  condition:
    hash.sha256(0, filesize) == "2a51dabd7c6c63d88ae13ca65a8a01c99fae1d4913a08ace28910c6f47074323"
}
```

### Sample 36: `e65ee878453d6fa2`

| Field | Value |
|---|---|
| SHA-256 | `e65ee878453d6fa2005f27ad16ecab564cf371992db9e058d8bdd78bde54a99a` |
| Family label | `Mirai` |
| File name | `M68K` |
| File type | `elf` |
| First seen | `2026-07-04 00:36:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a99437a7a374333201b3b1a3ae6dcaf` |
| SHA-1 | `89386d09bfc582a1c0a17812d6880f4ee98abe16` |
| SHA-256 | `e65ee878453d6fa2005f27ad16ecab564cf371992db9e058d8bdd78bde54a99a` |
| SHA3-384 | `9abf9460f9e1d8c899b16302c458d8179fcee9b9dbafa7a048de44afea22e7264017f47956822ea17498cf7c65f7536f` |
| TLSH | `T1ACB308C7FD00EEB7F80AA77644930819B230BFB60D521AB6721778ABAD760D51427F85` |
| SSDEEP | `3072:6KQ00/UmBOfvNkwCy8KJbAcZ61s7uzHoJ3pZ2bdr:6KQTBQvNsy8ubAcZUK/J3Kbdr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_e65ee878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e65ee878453d6fa2005f27ad16ecab564cf371992db9e058d8bdd78bde54a99a"
    family = "Mirai"
    file_name = "M68K"
    file_type = "elf"
    first_seen = "2026-07-04 00:36:56"
  condition:
    hash.sha256(0, filesize) == "e65ee878453d6fa2005f27ad16ecab564cf371992db9e058d8bdd78bde54a99a"
}
```

### Sample 37: `7a5ddf0ddbe18b04`

| Field | Value |
|---|---|
| SHA-256 | `7a5ddf0ddbe18b048b75dfe5153fc8ee5b6b5e8d9832c96ac7ea18591d272cdb` |
| Family label | `Mirai` |
| File name | `I586` |
| File type | `elf` |
| First seen | `2026-07-04 00:33:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1145ed0ec42299ffff040f05d6a4a2c` |
| SHA-1 | `ba8752cc96f9263f0854eba4aea9e8ce3d4a31f3` |
| SHA-256 | `7a5ddf0ddbe18b048b75dfe5153fc8ee5b6b5e8d9832c96ac7ea18591d272cdb` |
| SHA3-384 | `06dc193e80333452b9a6c02a13717fcf71048374c313cd8057158c66b4acff75510d3d42dced85caa9aa1cf48593bff6` |
| TLSH | `T1BE932B52AA41CD73D40311F212E69F674932FA3F5867DA86E7A43C71EE190C19722BBC` |
| TELFHASH | `t1604159f62efd08e4b7d14808c24a1be22655a63b150072d646f36da233ebf869076c34` |
| SSDEEP | `1536:LtS61gJGdd59H7NxMIYw9baql+Axl7eEiXHGnrYae5a5hlpOBfUg:LtFUW9bNxQw9Rj7k3C8i5hlp4f3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_7a5ddf0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a5ddf0ddbe18b048b75dfe5153fc8ee5b6b5e8d9832c96ac7ea18591d272cdb"
    family = "Mirai"
    file_name = "I586"
    file_type = "elf"
    first_seen = "2026-07-04 00:33:56"
  condition:
    hash.sha256(0, filesize) == "7a5ddf0ddbe18b048b75dfe5153fc8ee5b6b5e8d9832c96ac7ea18591d272cdb"
}
```

### Sample 38: `c433957cc91e1766`

| Field | Value |
|---|---|
| SHA-256 | `c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab` |
| Family label | `unknown` |
| File name | `f` |
| File type | `unknown` |
| First seen | `2026-07-04 00:32:54` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02acf81019982d15cdf3029fb980071c` |
| SHA-256 | `c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_c433957c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab"
    family = "unknown"
    file_name = "f"
    file_type = "unknown"
    first_seen = "2026-07-04 00:32:54"
  condition:
    hash.sha256(0, filesize) == "c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab"
}
```

### Sample 39: `ffc708aed38519ea`

| Field | Value |
|---|---|
| SHA-256 | `ffc708aed38519ea8799e0cabebf6444934d1aa7db9f83a3c31b6847ed139b6d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 00:30:45` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f1d1749b5276e67c4555532b54934f6` |
| SHA-1 | `b587504d03c6cb256a2f7df10d9fc0f4cd9bcf8d` |
| SHA-256 | `ffc708aed38519ea8799e0cabebf6444934d1aa7db9f83a3c31b6847ed139b6d` |
| SHA3-384 | `9637813fac1b00ddebe7ac234d07a33e3a796fefd1f023715b9dc51ac33f564e8318768e9937dcc29acb418ccc157f24` |
| IMPHASH | `2afa5fb9b09d1f0b6a6865c5899d6e01` |
| TLSH | `T151E4F047BEA541FFE037813C85931A56FB72B91507209BEF0762422A1E17BD48D3ABB4` |
| SSDEEP | `12288:2EChIX9/ut2rNzf5+iwiPOOCT+zPVlU2mDV2:EhIt/H57UiwiPOMzPVe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_ffc708ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffc708aed38519ea8799e0cabebf6444934d1aa7db9f83a3c31b6847ed139b6d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 00:30:45"
  condition:
    hash.sha256(0, filesize) == "ffc708aed38519ea8799e0cabebf6444934d1aa7db9f83a3c31b6847ed139b6d"
}
```

### Sample 40: `380137fe3eb4ab4d`

| Field | Value |
|---|---|
| SHA-256 | `380137fe3eb4ab4dae0d26aa1b94a4b19a9c28b1d84697b6e80ff8cb93ec5dca` |
| Family label | `unknown` |
| File name | `Facturas Pagadas al Vencimiento.js` |
| File type | `js` |
| First seen | `2026-07-04 00:25:27` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f2a60bd69a32d50bd61d1e89ae977ca` |
| SHA-1 | `61df3514b9609e191f8c193b6fdb5429cb31ad15` |
| SHA-256 | `380137fe3eb4ab4dae0d26aa1b94a4b19a9c28b1d84697b6e80ff8cb93ec5dca` |
| SHA3-384 | `c3b63ea14cd845c85b4270e7a49751edd1db803d0fc6b5635ceb9bfa349dffe702892a67824ab02ca324d18e13a8ead9` |
| TLSH | `T1526315C33B480417EEEEE651CC093D4BCB7B81992891589BAE37CABC8D4E5DD14D5A2C` |
| SSDEEP | `384:uAPQrm/numUKZU+UO9+lr5asydp3/7yQKwy:7PWm/numUKZU+UO9+lYsc/7j4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_380137fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "380137fe3eb4ab4dae0d26aa1b94a4b19a9c28b1d84697b6e80ff8cb93ec5dca"
    family = "unknown"
    file_name = "Facturas Pagadas al Vencimiento.js"
    file_type = "js"
    first_seen = "2026-07-04 00:25:27"
  condition:
    hash.sha256(0, filesize) == "380137fe3eb4ab4dae0d26aa1b94a4b19a9c28b1d84697b6e80ff8cb93ec5dca"
}
```

### Sample 41: `5db55a1df1b4cd84`

| Field | Value |
|---|---|
| SHA-256 | `5db55a1df1b4cd848c772430af5afa07b6d16c3fc2d1fcc4e85a2ff698f918e5` |
| Family label | `unknown` |
| File name | `Setup_upd.exe` |
| File type | `exe` |
| First seen | `2026-07-04 00:24:53` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e0e2616faf78299847fcc71b4879446` |
| SHA-1 | `9ebcb9ed1dd04fcec33e8d733016f7e37bacb2a0` |
| SHA-256 | `5db55a1df1b4cd848c772430af5afa07b6d16c3fc2d1fcc4e85a2ff698f918e5` |
| SHA3-384 | `f0f2060af338eb12a77d4d90a839f040f704bf719c479eeb512c5003a390faa24878fbfc794a69e35ed2c89819db8c65` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T15F08335B1AAF82CFC25E78F810121B22EA48EBE93775154BFB1F84193CC52DE12596D3` |
| SSDEEP | `1572864:+t9IKPY28m42nIRWYx6ttcpCA21INJGnm2aTEohgwoFyy7:+UKAPjIIRWRttcy8UGTHEQy7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_5db55a1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db55a1df1b4cd848c772430af5afa07b6d16c3fc2d1fcc4e85a2ff698f918e5"
    family = "unknown"
    file_name = "Setup_upd.exe"
    file_type = "exe"
    first_seen = "2026-07-04 00:24:53"
  condition:
    hash.sha256(0, filesize) == "5db55a1df1b4cd848c772430af5afa07b6d16c3fc2d1fcc4e85a2ff698f918e5"
}
```

### Sample 42: `a166b4f2f9c55657`

| Field | Value |
|---|---|
| SHA-256 | `a166b4f2f9c5565737ba6512416030b2518c812cd0abb3af52749b5bebdd9625` |
| Family label | `Mirai` |
| File name | `I686` |
| File type | `elf` |
| First seen | `2026-07-04 00:12:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `651609e1ceb08d6fed3b0e9b3dbd43f9` |
| SHA-1 | `2e931d8966e8d84e1cea628a4d07880ad7355cae` |
| SHA-256 | `a166b4f2f9c5565737ba6512416030b2518c812cd0abb3af52749b5bebdd9625` |
| SHA3-384 | `1c64c0d55ca539c72549694c2fbe612dbf57aacf887c3f6c9b283ae53028984dbc36e4bda340ad4f6137d2cce6071a91` |
| TLSH | `T11E931C46E743CAB3C80305F212A7AA6F8A31FE3A8C66DD86FB543D94EF164C152117B5` |
| TELFHASH | `t10d410bf72ee508d8b7d15848c70e1bb52609e57f29103ada06f36da137dae819075c38` |
| SSDEEP | `1536:Mxx1nuXXnaLlzvNCBf5VAm2OOjyxf5+hVQnpspSJnzg15AWMM1khprDiUA+r+0Lr:Q1nuXXG5vNCBf5VAm2OOjyxf5+hVQnpd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_a166b4f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a166b4f2f9c5565737ba6512416030b2518c812cd0abb3af52749b5bebdd9625"
    family = "Mirai"
    file_name = "I686"
    file_type = "elf"
    first_seen = "2026-07-04 00:12:55"
  condition:
    hash.sha256(0, filesize) == "a166b4f2f9c5565737ba6512416030b2518c812cd0abb3af52749b5bebdd9625"
}
```

### Sample 43: `0a5d4b8f65eba399`

| Field | Value |
|---|---|
| SHA-256 | `0a5d4b8f65eba399f0b41ac648d939650ab6422ce4c715f8a1b5b99e1178678b` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-04 00:09:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20f0b966c8c5632e9235c9100900c0ab` |
| SHA-1 | `6fd505f885c8c8473c46753cf9a498f5001784e0` |
| SHA-256 | `0a5d4b8f65eba399f0b41ac648d939650ab6422ce4c715f8a1b5b99e1178678b` |
| SHA3-384 | `48c44f2454faceb9f5b4f95c5c00cf8d1be0049c46ac1ebb5c727c2f2dda89646e5914e5a965ee047afa9c5e6fbe61d0` |
| TLSH | `T180115ECB025CA3431A184D98BC7B98BD7991C2E671B7F651F285C8249EC92047C76B3B` |
| SSDEEP | `24:3J3UI9GBRsz3NIxOfXKh+WTfh+9Tks2UDp3IHZkiSMhO5ZhlHA:Bu9cXz08TkxsCZxFhMhlg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_0a5d4b8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a5d4b8f65eba399f0b41ac648d939650ab6422ce4c715f8a1b5b99e1178678b"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-04 00:09:55"
  condition:
    hash.sha256(0, filesize) == "0a5d4b8f65eba399f0b41ac648d939650ab6422ce4c715f8a1b5b99e1178678b"
}
```

### Sample 44: `27e3c9b676e96ef6`

| Field | Value |
|---|---|
| SHA-256 | `27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 23:54:29` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98006c884a359668964ba2fa91770f35` |
| SHA-1 | `e373a6356acc578039a720e6a4ad0d9929424f64` |
| SHA-256 | `27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266` |
| SHA3-384 | `a4f9dda404445c86bc4b1862245ba482a138afcaf7e342920fd75ed4b65f20a24bd45be088ad24d8e631dfc77e41c92c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11CD58D0B7DA009E9D4A6933249B751967B75BC588F3233D72E90B3382E72BD08D36794` |
| SSDEEP | `49152:+cCobsiyGNoGCiBNyJzXZ5RNQyjx453xJPgrb:+c65cmzp5Rf4533Ub` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_27e3c9b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:54:29"
  condition:
    hash.sha256(0, filesize) == "27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266"
}
```

### Sample 45: `6af02f9f08e5d6e9`

| Field | Value |
|---|---|
| SHA-256 | `6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 23:41:24` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c05ab37c2665353719dc535df55d6c4` |
| SHA-1 | `2801386033834bede5f00d5442192cdfd6fe31ce` |
| SHA-256 | `6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040` |
| SHA3-384 | `184c56288ec3b27967f0016aa6fdfaa3e35244f1468e43a0fd899ea467691fc1ac04f5b93645eebe8057343c5e0f771f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F5B68D03F9D540E9C05AD2758BAA8222BA71BC494B3177DF1A9077352FB6BE05F3A710` |
| SSDEEP | `49152:vrP7Fu9N/CRE6ceYo+HTbBsoyE2anHcRhfLQCVXcBRT4kWc/msgy654KUjESSsD+:vrBERnHc/DQjkv2NB8eg2dS2aZIF+` |
| ICON-DHASH | `f0f0b2caccc8e070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_6af02f9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:41:24"
  condition:
    hash.sha256(0, filesize) == "6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040"
}
```

### Sample 46: `0bf8f52b28291edc`

| Field | Value |
|---|---|
| SHA-256 | `0bf8f52b28291edc505a64962e6ce04387a9784fc5b18aeff53629adb1f72f56` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 23:21:51` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d6b27a00e79e8138b3d93b2c56b24d7` |
| SHA-1 | `e4571f7b27285ddc0e39d005a9f1109a9335820d` |
| SHA-256 | `0bf8f52b28291edc505a64962e6ce04387a9784fc5b18aeff53629adb1f72f56` |
| SHA3-384 | `d8ae466fd559804b3654579dde6ee370c033c7d6d7143a5f1f44d817f8dce0c89762bc84f6efd26953419dbdd43ee6d2` |
| IMPHASH | `13f79e8b30893cd8b53f6528763b9ff4` |
| TLSH | `T12925E04BB3E460EFD6A7973089764606D37278A18761CBEF329C42211F173D49E7AB21` |
| SSDEEP | `24576:RVP2hh0cMo02cVGjpo/jE27Ii8dwqOc5S:/28cjnNME27ZQwUS` |
| ICON-DHASH | `74e4d4d4ecf4d4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_0bf8f52b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bf8f52b28291edc505a64962e6ce04387a9784fc5b18aeff53629adb1f72f56"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:21:51"
  condition:
    hash.sha256(0, filesize) == "0bf8f52b28291edc505a64962e6ce04387a9784fc5b18aeff53629adb1f72f56"
}
```

### Sample 47: `b15fabb4f73fff2d`

| Field | Value |
|---|---|
| SHA-256 | `b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47` |
| Family label | `WannaCry` |
| File name | `b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47` |
| File type | `exe` |
| First seen | `2026-07-03 23:15:34` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58a7e2f088cb22dba94ec1ebf9aad4ac` |
| SHA-1 | `b145c4d4f24999d82b5fef79a79fb008791d11f8` |
| SHA-256 | `b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47` |
| SHA3-384 | `97eb4ddd8e4d7832498d6c4430cd5a0b318d87deeb6035af4c4bee9151a94daf989a1687bf4905075db275e1c0621601` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14C36228932AC80FCD5065274D4B74D25F2B3BC9A22BD870F9B948B660E13791BB34B57` |
| SSDEEP | `12288:jbLgD1bLgmluCtgQhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+DHe:jbLgBbLgurgQhfdmMSirYbcMNgef0Qe` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_047_b15fabb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47"
    family = "WannaCry"
    file_name = "b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47"
    file_type = "exe"
    first_seen = "2026-07-03 23:15:34"
  condition:
    hash.sha256(0, filesize) == "b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47"
}
```

### Sample 48: `9f42721255d8d62b`

| Field | Value |
|---|---|
| SHA-256 | `9f42721255d8d62b4595b9040a9a7d742c8fe2a5ff17745c8e250cd04928c480` |
| Family label | `unknown` |
| File name | `ۦۖ.apk` |
| File type | `apk` |
| First seen | `2026-07-03 23:00:54` |
| Reporter | `BastianHein_` |
| Tags | `apk, Mparivahan, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be1cb01a50034098af92777bafefcb75` |
| SHA-1 | `7cddcfe3639668bf180859d6f79d498e4f61418c` |
| SHA-256 | `9f42721255d8d62b4595b9040a9a7d742c8fe2a5ff17745c8e250cd04928c480` |
| SHA3-384 | `d81b709ee66c1dba7167560aa7f3af0c095c4890d3bb5db7a7d588358932e23bcdf94e85b47edb9590a935f66cee555d` |
| TLSH | `T131854A46F784AA2FC837913755AB5732114B4C4A8E83DBC36958770C28BB9E41F9DBC8` |
| SSDEEP | `24576:41GcCtLm7SsoF/CaTN8NTHvj3OmywiWSp:41qx7F/CaTN8NTH01p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_9f427212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f42721255d8d62b4595b9040a9a7d742c8fe2a5ff17745c8e250cd04928c480"
    family = "unknown"
    file_name = "ۦۖ.apk"
    file_type = "apk"
    first_seen = "2026-07-03 23:00:54"
  condition:
    hash.sha256(0, filesize) == "9f42721255d8d62b4595b9040a9a7d742c8fe2a5ff17745c8e250cd04928c480"
}
```

### Sample 49: `3c279bc94d37eeaf`

| Field | Value |
|---|---|
| SHA-256 | `3c279bc94d37eeaf2b81f78820ada90c8e40814e45818c7c5666ea8c49688d67` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 23:00:30` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f2cd1586b4ba7ea752f1565ec40054b` |
| SHA-1 | `227d392fd7934a429b2485a3381328e318215e85` |
| SHA-256 | `3c279bc94d37eeaf2b81f78820ada90c8e40814e45818c7c5666ea8c49688d67` |
| SHA3-384 | `d96deed2893bf78216e17f258e10c2b2f7d7f0d358fa92e396c20b0967b0b11a91ab638f601da47edd881fbe68ddc79b` |
| IMPHASH | `0743036683f1e0b2d10d2e3d2a175580` |
| TLSH | `T1A0C59D03E7A580EDD49AC138C71A8227FB72B88A1730B6DB57D48A253F67BA15F1D305` |
| SSDEEP | `49152:jFOAJFd5i4E/SXawspQ9PkhDlvfHOokeIf3qC:jFOai4EC/iOSqq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_3c279bc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c279bc94d37eeaf2b81f78820ada90c8e40814e45818c7c5666ea8c49688d67"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:00:30"
  condition:
    hash.sha256(0, filesize) == "3c279bc94d37eeaf2b81f78820ada90c8e40814e45818c7c5666ea8c49688d67"
}
```

### Sample 50: `536cb0e2ffffa40d`

| Field | Value |
|---|---|
| SHA-256 | `536cb0e2ffffa40d1ccd096eaaad43f094813bae15d8f6316dc35fb998d5e4cd` |
| Family label | `unknown` |
| File name | `ۦۖ۫.apk` |
| File type | `apk` |
| First seen | `2026-07-03 22:51:43` |
| Reporter | `BastianHein_` |
| Tags | `apk, Banker, Indusind Credit Card` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d20efa9cda3e0d0da16e5593bf3f7644` |
| SHA-1 | `b9804301439f239f31288ce89db8be84305c45e1` |
| SHA-256 | `536cb0e2ffffa40d1ccd096eaaad43f094813bae15d8f6316dc35fb998d5e4cd` |
| SHA3-384 | `c9f287cee1fc33d31246f02a2c92ee435a594bdc667ef143c5d726d4069c33006757625af27194150d8abdce25742ef7` |
| TLSH | `T17D56F1B57741D93BF8370532656A7231B78F9E168E8F8683A544320C69772DC0F9BAC8` |
| SSDEEP | `98304:p2MBNMhhsCvQHXLOw61sJD0J/faSUZFGTwCkwkFcajec9LOAiSt1A/LO8ftRrI9V:pRqTQ3LOw3YJ3wmlV4t9LO1STA/wV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_536cb0e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "536cb0e2ffffa40d1ccd096eaaad43f094813bae15d8f6316dc35fb998d5e4cd"
    family = "unknown"
    file_name = "ۦۖ۫.apk"
    file_type = "apk"
    first_seen = "2026-07-03 22:51:43"
  condition:
    hash.sha256(0, filesize) == "536cb0e2ffffa40d1ccd096eaaad43f094813bae15d8f6316dc35fb998d5e4cd"
}
```

### Sample 51: `dceebf2ce1186b22`

| Field | Value |
|---|---|
| SHA-256 | `dceebf2ce1186b22f60b7ee064670db88347761767ea8610a35e50e568b348b3` |
| Family label | `unknown` |
| File name | `output.apk` |
| File type | `apk` |
| First seen | `2026-07-03 22:51:10` |
| Reporter | `BastianHein_` |
| Tags | `apk, Banker, Indusind Credit Card` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee9ccb349a01601bafe3bc010a0f97e9` |
| SHA-1 | `ed3e8ead24e98fbe6377ce7e672500c3a4aa1d23` |
| SHA-256 | `dceebf2ce1186b22f60b7ee064670db88347761767ea8610a35e50e568b348b3` |
| SHA3-384 | `1c4c432462b8e45c9d13b1dda91cb88c326d8c405992ae809c2eb34fbe3ab6dc5c70403fc4a5c71d381015c9b1242a10` |
| TLSH | `T12A36CE4DB7F4DE2AC43A40362866523E625B9F478B428F43B944771D3BBB5E40E49BC8` |
| SSDEEP | `98304:dXO8ftRrowY3PFw0ba6Qdhb5x1vakE5FqXSh6BMUEy/:dzeFnba6cBokdMQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_dceebf2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dceebf2ce1186b22f60b7ee064670db88347761767ea8610a35e50e568b348b3"
    family = "unknown"
    file_name = "output.apk"
    file_type = "apk"
    first_seen = "2026-07-03 22:51:10"
  condition:
    hash.sha256(0, filesize) == "dceebf2ce1186b22f60b7ee064670db88347761767ea8610a35e50e568b348b3"
}
```

### Sample 52: `f5b43a3803a8149d`

| Field | Value |
|---|---|
| SHA-256 | `f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99` |
| Family label | `WannaCry` |
| File name | `f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99` |
| File type | `exe` |
| First seen | `2026-07-03 22:15:45` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ec808d23dc8b2775c37db0dabe09573` |
| SHA-1 | `b59e3977a75660c858475e89536b7920ab1f1a10` |
| SHA-256 | `f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99` |
| SHA3-384 | `86da11c1487481314c9eaac8ac3e277db76d8549323790b036a985c1f52bf64477d0b85568b54d69c97d6088300434c0` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T17636235932B885FCC006257984B78D57E7B37C9A13FE9B0F8B4086AA1E13755BF64B02` |
| SSDEEP | `49152:jnsnNQqMSPbcBVQej01INRx+TSqTdX1HkQo6SAA:DMWqPoBho1aRxcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_052_f5b43a38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99"
    family = "WannaCry"
    file_name = "f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99"
    file_type = "exe"
    first_seen = "2026-07-03 22:15:45"
  condition:
    hash.sha256(0, filesize) == "f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99"
}
```

### Sample 53: `b4f0148df9332a4c`

| Field | Value |
|---|---|
| SHA-256 | `b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8` |
| Family label | `WannaCry` |
| File name | `b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8.dll` |
| File type | `dll` |
| First seen | `2026-07-03 21:50:52` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7db0f7eda78daad224a3f787dedb0fae` |
| SHA-1 | `6334810a16733d1338daca7ac398c3907d441b8f` |
| SHA-256 | `b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8` |
| SHA3-384 | `1c62d534f2fd787baa65b5a8cbc5d9fe5a5162bc551bc71d7ec2bbf04c73b9541e1bcee508936a18ab578c4656fc43c8` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T14F3623567099C0F4C10566309C7BCEDEA6B63C69EDB9690FBBC07B6F1C33B56A600642` |
| SSDEEP | `24576:RbLguriJmMSirYbcMNgef0QeQjG/D8kIqRYoAdNLKz6626M+vbOSSqTPVX:RnZMSPbcBVQej/1INRx+TSqTdX` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_053_b4f0148d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8"
    family = "WannaCry"
    file_name = "b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8.dll"
    file_type = "dll"
    first_seen = "2026-07-03 21:50:52"
  condition:
    hash.sha256(0, filesize) == "b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8"
}
```

### Sample 54: `6eb5274407dd458d`

| Field | Value |
|---|---|
| SHA-256 | `6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd` |
| Family label | `unknown` |
| File name | `6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd` |
| File type | `elf` |
| First seen | `2026-07-03 21:31:34` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9b0e1e3d08a4319912b72023de3ab5c` |
| SHA-1 | `d551d742d0fded65ba7dc5abcb7fdce21365ff50` |
| SHA-256 | `6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd` |
| SHA3-384 | `c13795b26d77e690ec445a0af55985ada8d79f68ff5be6b05bff98adea0f7f78549ce43c8c9948491410a9047e5bd50e` |
| TLSH | `T1F157CF7792167CEDE9B98DB4C01015816DA878874778E3C7BAC870E6A6EB6D08D3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQM:cqYUQuVDt0TZEf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_6eb52744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd"
    family = "unknown"
    file_name = "6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd"
    file_type = "elf"
    first_seen = "2026-07-03 21:31:34"
  condition:
    hash.sha256(0, filesize) == "6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd"
}
```

### Sample 55: `da01b54e7d42de9f`

| Field | Value |
|---|---|
| SHA-256 | `da01b54e7d42de9f00fdac7f2123779363a13df7d40bdb72558c9618e13dc77b` |
| Family label | `unknown` |
| File name | `nuker.py` |
| File type | `unknown` |
| First seen | `2026-07-03 21:29:05` |
| Reporter | `Kejult` |
| Tags | `py, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20e77c1335b4de6ded919a8323ef77f6` |
| SHA-256 | `da01b54e7d42de9f00fdac7f2123779363a13df7d40bdb72558c9618e13dc77b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_da01b54e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da01b54e7d42de9f00fdac7f2123779363a13df7d40bdb72558c9618e13dc77b"
    family = "unknown"
    file_name = "nuker.py"
    file_type = "unknown"
    first_seen = "2026-07-03 21:29:05"
  condition:
    hash.sha256(0, filesize) == "da01b54e7d42de9f00fdac7f2123779363a13df7d40bdb72558c9618e13dc77b"
}
```

### Sample 56: `c17aff83c3fbddb8`

| Field | Value |
|---|---|
| SHA-256 | `c17aff83c3fbddb86fe5a40d7a654af5591b16522fb15c222bbf3d57b0b16748` |
| Family label | `unknown` |
| File name | `IndusindCreditCard.apk` |
| File type | `apk` |
| First seen | `2026-07-03 21:20:56` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Indusind Credit Card, Malware, Mirai, SpyAgent, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `375c6a1a21880dfe95b5a1df10ddc2fb` |
| SHA-1 | `78accb53302354bce6d6858045b1f6ad895e4938` |
| SHA-256 | `c17aff83c3fbddb86fe5a40d7a654af5591b16522fb15c222bbf3d57b0b16748` |
| SHA3-384 | `a857aed3a0e9d4802cad1eedb8b887b8098c750c3f2280336283bfec66e1fcb1e3d26b9ba2117026ef610d8b61ec3b4e` |
| TLSH | `T10696E031B7498A3BF9B6793868673271B20A6D5D4E4D82975A01F21C6DB71DC0F0BBC8` |
| SSDEEP | `196608:Im55YQthqiusGP9uNw9PM4ZTqRqU2oJr3y7beN5+:l55pT4P9uy9PM4lqRqUXJby7bX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_c17aff83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c17aff83c3fbddb86fe5a40d7a654af5591b16522fb15c222bbf3d57b0b16748"
    family = "unknown"
    file_name = "IndusindCreditCard.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:20:56"
  condition:
    hash.sha256(0, filesize) == "c17aff83c3fbddb86fe5a40d7a654af5591b16522fb15c222bbf3d57b0b16748"
}
```

### Sample 57: `addbd8770b53a50e`

| Field | Value |
|---|---|
| SHA-256 | `addbd8770b53a50e83c711143332c76e9160f920675e2de5591669d3b93f499b` |
| Family label | `unknown` |
| File name | `mparivahan-cefg.apk` |
| File type | `apk` |
| First seen | `2026-07-03 21:16:38` |
| Reporter | `jitesh` |
| Tags | `Android, apk, GOI, Malware, mParivahan, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1277596297b0084ad26986fc068081d` |
| SHA-1 | `8774ec604ae4199cc0174240e62d666965164adc` |
| SHA-256 | `addbd8770b53a50e83c711143332c76e9160f920675e2de5591669d3b93f499b` |
| SHA3-384 | `189db81a88e38cf6cc4f2a9618f0100ae49b73614fedd7b3563dc548a40c12f533dad52bdd96be0d0b968bd94b01cf3d` |
| TLSH | `T168C63382F35C543FC4B390360E9A4B7256599C0ACF96A34B91687B2C3C776D84E9AFD0` |
| SSDEEP | `196608:1o9EDfVzXnQ2JFBvrMcVnyn+6YPd6wuMwC1sPZoLICDjIGRJvL1c:1oKDhVbvlngXYPTPJKoLICDEeW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_addbd877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "addbd8770b53a50e83c711143332c76e9160f920675e2de5591669d3b93f499b"
    family = "unknown"
    file_name = "mparivahan-cefg.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:16:38"
  condition:
    hash.sha256(0, filesize) == "addbd8770b53a50e83c711143332c76e9160f920675e2de5591669d3b93f499b"
}
```

### Sample 58: `3a03b35a4c614d65`

| Field | Value |
|---|---|
| SHA-256 | `3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b` |
| Family label | `unknown` |
| File name | `TⲓⲕTⲟⲕⲣⲅⲓⲃⲁⲧ.apk` |
| File type | `apk` |
| First seen | `2026-07-03 21:13:44` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8ddfddc6469d2619e784bf88adfbd29` |
| SHA-1 | `bba517b3bfbcf28a6e0de7c6b002b5b7aa70c6c2` |
| SHA-256 | `3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b` |
| SHA3-384 | `2eef90909d38195034702a0894a8061d67d93538f3839d6911c59d59d21dda249b28f0215cb1cbb67468286b089d2621` |
| TLSH | `T15F562281FF46D82EC0B7443B1A860331665ADE1EC697A34795EC361C5C7BAC84FE8AD4` |
| SSDEEP | `98304:IsatFB3It8ABAdhkMb88zkrkRQZx0MOMvG5aXke9U3HbaLGQ0wM:IhP3q8AB0mMwkkwRKx0HaUe927wVM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_3a03b35a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b"
    family = "unknown"
    file_name = "TⲓⲕTⲟⲕⲣⲅⲓⲃⲁⲧ.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:13:44"
  condition:
    hash.sha256(0, filesize) == "3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b"
}
```

### Sample 59: `518f5438a21e9aa9`

| Field | Value |
|---|---|
| SHA-256 | `518f5438a21e9aa9a91f0dd589088e443fda111d8ada5ea67d1cf14d6645974c` |
| Family label | `unknown` |
| File name | `Sеks18+.apk` |
| File type | `apk` |
| First seen | `2026-07-03 21:12:15` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `633a412d244673fe619181df3a78e094` |
| SHA-1 | `a7ffe833dfd357387e56420ff8684cc6cb3db65f` |
| SHA-256 | `518f5438a21e9aa9a91f0dd589088e443fda111d8ada5ea67d1cf14d6645974c` |
| SHA3-384 | `76f02ce358ab0439c9c3c831bb1a6555af6460f45ce549cfefc2c064308e8ce6c5e572e1dfd0b3bf62eb63124032a2e3` |
| TLSH | `T1CD662382FF45D82ED4B780370A9247351265AD2EC693934395EC7A2C6C7BAC80FC9ED5` |
| SSDEEP | `98304:357u4q2N54XKlSNfo430cm6B9ahRPw7NEec2+4sS8QqTwj86YUx+7:Ja4BohTjahRPCEX2LsSokj86+7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_518f5438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "518f5438a21e9aa9a91f0dd589088e443fda111d8ada5ea67d1cf14d6645974c"
    family = "unknown"
    file_name = "Sеks18+.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:12:15"
  condition:
    hash.sha256(0, filesize) == "518f5438a21e9aa9a91f0dd589088e443fda111d8ada5ea67d1cf14d6645974c"
}
```

### Sample 60: `b04138725a86c8b0`

| Field | Value |
|---|---|
| SHA-256 | `b04138725a86c8b04773f8be7c1b5550b0048f845050d0aae3c04044a5fb3e70` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-03 20:20:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d813dcab81bc9734cb297b6fa75355bf` |
| SHA-1 | `e16739301df6d5b4db97210fff0aa07818faa24a` |
| SHA-256 | `b04138725a86c8b04773f8be7c1b5550b0048f845050d0aae3c04044a5fb3e70` |
| SHA3-384 | `43727826c0b2efbc5bcfe427abd22c68e7b1a0c80069d5e09669e2916eb20455e7fdbbe0b277c811a95e208c35eb2e05` |
| TLSH | `T15601AFC582006800806DDA6D72E75190B410C3CE4D4A0FA87F9C6A3DFB8C810F037FA4` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha4YagyjRPtMVrRYDk7:e9Qp+Ms4YbGZmYY7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_b0413872
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b04138725a86c8b04773f8be7c1b5550b0048f845050d0aae3c04044a5fb3e70"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-03 20:20:17"
  condition:
    hash.sha256(0, filesize) == "b04138725a86c8b04773f8be7c1b5550b0048f845050d0aae3c04044a5fb3e70"
}
```

### Sample 61: `c120ab59ac32c2bc`

| Field | Value |
|---|---|
| SHA-256 | `c120ab59ac32c2bcd14e0e091629bbdbd522381594261e3452ab11f5fd02bc57` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-03 20:11:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42f1681771c55b34b2caa76824559b7d` |
| SHA-1 | `d2b03843809f16478aedf3eef8a2764774fbe026` |
| SHA-256 | `c120ab59ac32c2bcd14e0e091629bbdbd522381594261e3452ab11f5fd02bc57` |
| SHA3-384 | `69329849b569a82ecfb79a5f535b4230cca4355aea03bb684096d9e6ba509cf1e89c43f96276bcaa7c9a2e2042becc03` |
| TLSH | `T1B6D09512131303B050B34447F1E6B500700007BFAC579A187103B4F05F5724CF4C0765` |
| SSDEEP | `6:hTFuRNRZDS8XqfjQAulNXYq4HvXDG+NjVsNXYrkJ:VQRdS8AsPiq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_c120ab59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c120ab59ac32c2bcd14e0e091629bbdbd522381594261e3452ab11f5fd02bc57"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-03 20:11:20"
  condition:
    hash.sha256(0, filesize) == "c120ab59ac32c2bcd14e0e091629bbdbd522381594261e3452ab11f5fd02bc57"
}
```

### Sample 62: `83017185a714532b`

| Field | Value |
|---|---|
| SHA-256 | `83017185a714532b3e54cd6a86bb46e95301cfc1e2b35324a5ed8eec326b35a9` |
| Family label | `unknown` |
| File name | `3_19_8_1601_22.12.2025.rar` |
| File type | `rar` |
| First seen | `2026-07-03 20:06:50` |
| Reporter | `smica83` |
| Tags | `CVE-2025-8088, rar, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1406c36bf90970e7c53eafa27b7da506` |
| SHA-1 | `817579f01631b4a098a69c4c2e11a9d2f37a3f7d` |
| SHA-256 | `83017185a714532b3e54cd6a86bb46e95301cfc1e2b35324a5ed8eec326b35a9` |
| SHA3-384 | `9ad3d654a9868296d7e108917044894b06155b7d8589acc3c3e7738d67316ac21736866cc157963952f953f726857bd8` |
| TLSH | `T152714C426F3C613EEE43C99DC26DEB01A9939F45BA9412D47E5804CAC11F1DFDB228E9` |
| SSDEEP | `96:ZS02jAmNBHIFu5rWmMDmsZKCBps/dOXzv:wEmhr2HKus1OXzv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_83017185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83017185a714532b3e54cd6a86bb46e95301cfc1e2b35324a5ed8eec326b35a9"
    family = "unknown"
    file_name = "3_19_8_1601_22.12.2025.rar"
    file_type = "rar"
    first_seen = "2026-07-03 20:06:50"
  condition:
    hash.sha256(0, filesize) == "83017185a714532b3e54cd6a86bb46e95301cfc1e2b35324a5ed8eec326b35a9"
}
```

### Sample 63: `f17876b82951bc09`

| Field | Value |
|---|---|
| SHA-256 | `f17876b82951bc093975ee015c959f34cbbd32ef0e3e76a047b0f07eecae4916` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 19:57:05` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1d9a9df9eb2e1a7de84d8e8ac3e7b33` |
| SHA-1 | `ef55c84e8a5ad330da73034aca36f652aab88dab` |
| SHA-256 | `f17876b82951bc093975ee015c959f34cbbd32ef0e3e76a047b0f07eecae4916` |
| SHA3-384 | `fb03b35c588b974e71b455ac93a90c0b74794c8eba6f5a0a27d3a662d0c9f9a630e2930b2834da2cf0f97347ee7dbea8` |
| IMPHASH | `13f79e8b30893cd8b53f6528763b9ff4` |
| TLSH | `T17F25F15736A012E7D233A37CC6561609EBB7B86657504BAF325C47B91F233C09E7AB20` |
| SSDEEP | `12288:FcyLRwncSL2hhi36gnkjtCqbjR6oJYkCuINN6bfr9wtynFrmhFP87pLMZ2ylOniV:dVE2hh0qsQjRReIeup2yFc81LMllOn5S` |
| ICON-DHASH | `74e4d4d4ecf4d4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_f17876b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f17876b82951bc093975ee015c959f34cbbd32ef0e3e76a047b0f07eecae4916"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 19:57:05"
  condition:
    hash.sha256(0, filesize) == "f17876b82951bc093975ee015c959f34cbbd32ef0e3e76a047b0f07eecae4916"
}
```

### Sample 64: `f0afa9d9fb7f3396`

| Field | Value |
|---|---|
| SHA-256 | `f0afa9d9fb7f33961413b4827fe2a41c0cf54b7aebe0acc89c097e655b4762d7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 19:55:39` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, signed, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca4f03ee4e5ef52ce86389ff0dca073f` |
| SHA-1 | `bedbbbeb9a24bd71d763cab65c88d610978a1f15` |
| SHA-256 | `f0afa9d9fb7f33961413b4827fe2a41c0cf54b7aebe0acc89c097e655b4762d7` |
| SHA3-384 | `4d62937caf1da0dbc225075835c9b5e89a42b3a2ef52bd9f3a898f40cf81ae5b746e2449bea613c3b99bfd5453b061cc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T116B6F1075D6891F9D268713288E7E081B575B80A5B3227D32E04A77C3E76FD2DC38B99` |
| SSDEEP | `196608:DkmYDpd4iUk7ObgE4J0WQd5TkJTAcKJnc8y1WgRAWrxS:DkmypGHTG0WQXdcKm8kLS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_f0afa9d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0afa9d9fb7f33961413b4827fe2a41c0cf54b7aebe0acc89c097e655b4762d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 19:55:39"
  condition:
    hash.sha256(0, filesize) == "f0afa9d9fb7f33961413b4827fe2a41c0cf54b7aebe0acc89c097e655b4762d7"
}
```

### Sample 65: `3aa68046fedf7a76`

| Field | Value |
|---|---|
| SHA-256 | `3aa68046fedf7a769161be75092ac65d7b9c7c20ea3b6fc2a0cc3547c783add2` |
| Family label | `unknown` |
| File name | `photo-220665512.zip` |
| File type | `zip` |
| First seen | `2026-07-03 19:55:37` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c927201d6fd149f0a03bab69d93571d` |
| SHA-1 | `52b03e1918f67c69f851e46c2a31920d6245ba09` |
| SHA-256 | `3aa68046fedf7a769161be75092ac65d7b9c7c20ea3b6fc2a0cc3547c783add2` |
| SHA3-384 | `564040f29cc3b983f4dfe9835f24571b09fa46ee7ec9ad2d7be6c16b1ccb884ce6724cec95bbca3981e554d7df65cd8e` |
| TLSH | `T1B272C1801F070DF6EF6EEEB7B38DA1527B0CAB9A4141C1B526057A8C4FAAB55178C631` |
| SSDEEP | `384:4c3dMawOeDQEcIqxcyOu7uNnee5jhzQDpaTkEYJ/N4y5:4c3dHDUvKaa4ee5dkDATg15` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_3aa68046
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aa68046fedf7a769161be75092ac65d7b9c7c20ea3b6fc2a0cc3547c783add2"
    family = "unknown"
    file_name = "photo-220665512.zip"
    file_type = "zip"
    first_seen = "2026-07-03 19:55:37"
  condition:
    hash.sha256(0, filesize) == "3aa68046fedf7a769161be75092ac65d7b9c7c20ea3b6fc2a0cc3547c783add2"
}
```

### Sample 66: `b570834a38ff9d5e`

| Field | Value |
|---|---|
| SHA-256 | `b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7` |
| Family label | `unknown` |
| File name | `WealthGAF_CRM_API_Documentation.zip` |
| File type | `zip` |
| First seen | `2026-07-03 19:52:05` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9b3d1df47a4544ecc605f60b30d6060` |
| SHA-1 | `b78861c648a71e4639071d70397ee9365414435e` |
| SHA-256 | `b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7` |
| SHA3-384 | `c3d2f3ced37810295b9d0d4884536e0cfbc8c545ae8141a9c4835f42a5e86224d6a8535d5f7db8a55b1281455797465f` |
| TLSH | `T13A41298996D42068EAEB9370B93A4E81CA7332F4F636F00432482CC16AAE14D065FA5D` |
| SSDEEP | `48:9oxKCip9v8QkeovLchXTWARl7p5NUZv63QXHHjLuGmA3N:6xKCKZ8NXqWE/tcHH13N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_b570834a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7"
    family = "unknown"
    file_name = "WealthGAF_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-07-03 19:52:05"
  condition:
    hash.sha256(0, filesize) == "b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7"
}
```

### Sample 67: `d1e6e3515ab24c34`

| Field | Value |
|---|---|
| SHA-256 | `d1e6e3515ab24c3403845bb89e0cebb1fff721632735dee1fe92e7be261a8d22` |
| Family label | `unknown` |
| File name | `Zoom_Meeting_Notes_docx.zip` |
| File type | `zip` |
| First seen | `2026-07-03 19:43:38` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bca62ec55d3f0a8870fb630f58e12b8` |
| SHA-1 | `d45b50833624bfe7297fb93c0483fb0f38c46737` |
| SHA-256 | `d1e6e3515ab24c3403845bb89e0cebb1fff721632735dee1fe92e7be261a8d22` |
| SHA3-384 | `d4e17792ca2e20770ae4dcfd7e7e9e1249803b651689525018d194206a6ba390f6502a1b624a394a846cec8b3eb43d8e` |
| TLSH | `T12C310A22697DB84CD461E7F68B7D23BF465AA5F38C8DA1D1220AFAF21C066C006305C4` |
| SSDEEP | `48:93IQ/HrVVeTWmQnohNKa19ByChioh4aQQVqlx0I72/Ho:FIQ/HClzDXyiVQgyGI72/Ho` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_d1e6e351
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e6e3515ab24c3403845bb89e0cebb1fff721632735dee1fe92e7be261a8d22"
    family = "unknown"
    file_name = "Zoom_Meeting_Notes_docx.zip"
    file_type = "zip"
    first_seen = "2026-07-03 19:43:38"
  condition:
    hash.sha256(0, filesize) == "d1e6e3515ab24c3403845bb89e0cebb1fff721632735dee1fe92e7be261a8d22"
}
```

### Sample 68: `b46f58cd9bbdcfde`

| Field | Value |
|---|---|
| SHA-256 | `b46f58cd9bbdcfdec0908e67229b484c6f8482523092dd627e0e97fec62e53a4` |
| Family label | `SilentNet` |
| File name | `MD2.exe` |
| File type | `exe` |
| First seen | `2026-07-03 19:37:30` |
| Reporter | `nanoave` |
| Tags | `exe, SilentNet, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `080e5a2094def756472bef0647b24c7a` |
| SHA-1 | `dbf6a7ae14570ea721b3dd05aa4569ddade1ffce` |
| SHA-256 | `b46f58cd9bbdcfdec0908e67229b484c6f8482523092dd627e0e97fec62e53a4` |
| SHA3-384 | `aa6afda8601ea19cc901b7311b8fdf29a99d60d2f19eac2c3b28aa983d241b93734a1654077c47992cebcdd40ded64bf` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T19E357C83EBE381D8C156C8B5535BF137F9627C8E4A157196ABC41E633E67B64E22CB00` |
| SSDEEP | `12288:fZ+OE4MmD6/Oyspc5EEBBBHGBgzGerwGbvvPqItNquB:fcb4M06WpoPrwMvP3f5` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_068_b46f58cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b46f58cd9bbdcfdec0908e67229b484c6f8482523092dd627e0e97fec62e53a4"
    family = "SilentNet"
    file_name = "MD2.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:37:30"
  condition:
    hash.sha256(0, filesize) == "b46f58cd9bbdcfdec0908e67229b484c6f8482523092dd627e0e97fec62e53a4"
}
```

### Sample 69: `11ab28dfe32b4bba`

| Field | Value |
|---|---|
| SHA-256 | `11ab28dfe32b4bba5c69ad37b1a898b519212036adec54d0cb306759126454d3` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-03 19:29:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d82deb8bdcbe9e6d28d0755ff271b39f` |
| SHA-1 | `1bcbf17a6be3dd7a0a3f22823f1f037432ca6fb3` |
| SHA-256 | `11ab28dfe32b4bba5c69ad37b1a898b519212036adec54d0cb306759126454d3` |
| SHA3-384 | `8ef90a7a2d46874bcb7945dff6ce2a32d2d5e447b8653a3a021512616c188c859f7461226e3ca3b9854b9399ade5d89c` |
| TLSH | `T186236C6516857C24AA99C4375C7F2F0CBDA983E6314491DDBFCA3CF28C49AACE21871D` |
| SSDEEP | `768:0r9NyXsZztCq9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:yHusZGcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_11ab28df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11ab28dfe32b4bba5c69ad37b1a898b519212036adec54d0cb306759126454d3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-03 19:29:19"
  condition:
    hash.sha256(0, filesize) == "11ab28dfe32b4bba5c69ad37b1a898b519212036adec54d0cb306759126454d3"
}
```

### Sample 70: `46f10062d69ebabb`

| Field | Value |
|---|---|
| SHA-256 | `46f10062d69ebabbfe405bbd79eae9e9243735997d4353ff771adbe8f4f66607` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-03 19:29:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b24e3aac943da76de9a14c40efbf991` |
| SHA-1 | `df6824c06da131ed55ef6cde34b1b5ecf0795c40` |
| SHA-256 | `46f10062d69ebabbfe405bbd79eae9e9243735997d4353ff771adbe8f4f66607` |
| SHA3-384 | `95e0e4c865e9183c7a5fe0cc9574d3ace253dfd10ae438e3e50dbe122b83a2bb48c47c38c91c12285b529a1555c72ad9` |
| TLSH | `T146E34C85B8C28A22C5D513BFF92E018E331267E8D2DE7212DD621F24778796B0F77A45` |
| TELFHASH | `t157e0e538f666067cb16748704a7ba63bf367301e9b153024c9da9e2dab276d11052725` |
| SSDEEP | `3072:/efSIqzlwrJuD8oThT7RB7aV/5VgkaU/U6FVmqzeee4o:rIqxw1ugoThXRBo5mkaKaqzW4o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_46f10062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f10062d69ebabbfe405bbd79eae9e9243735997d4353ff771adbe8f4f66607"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-03 19:29:17"
  condition:
    hash.sha256(0, filesize) == "46f10062d69ebabbfe405bbd79eae9e9243735997d4353ff771adbe8f4f66607"
}
```

### Sample 71: `94fa960157c205a7`

| Field | Value |
|---|---|
| SHA-256 | `94fa960157c205a74ee1a2a783d3208dd536f25adf2f39a05b0a282ac822fcc5` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-03 19:29:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19afe61327539a53ee3366b2625d6122` |
| SHA-1 | `130c62c6df530e3d1df342ee32b07085e2749058` |
| SHA-256 | `94fa960157c205a74ee1a2a783d3208dd536f25adf2f39a05b0a282ac822fcc5` |
| SHA3-384 | `6ce248dda7683f8aa12996ce9f8bb41a5dd77442627663b4abf404b9754fe7edb1e3248db4a97516f107ff124fe107aa` |
| TLSH | `T10EA3D692BCC2562BC5E523BEA67E518D3360B7E4C2DA7117D8A34B107B8651F0E63F84` |
| TELFHASH | `t1d9e06800fd699a1ca9d39670ed5902b6a2022233b61b0b11cfe4cbd0843b004b60de9e` |
| SSDEEP | `1536:VnsCDhqI8UTYLbkGqnXV/EI41Le7BLGVLXe/9tmhPJHYK0vUbYO3:VnsCDhqIYLbq2ewXKGHYKCU/3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_94fa9601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94fa960157c205a74ee1a2a783d3208dd536f25adf2f39a05b0a282ac822fcc5"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-03 19:29:16"
  condition:
    hash.sha256(0, filesize) == "94fa960157c205a74ee1a2a783d3208dd536f25adf2f39a05b0a282ac822fcc5"
}
```

### Sample 72: `cfbd2859a855c472`

| Field | Value |
|---|---|
| SHA-256 | `cfbd2859a855c47242fa0966147baacc11e4174ecb70910953f451711efffa92` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-03 19:27:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b26584718d5033ea6fd7176d298e602f` |
| SHA-1 | `e71a031db3d16015b8aca12474fda6a79f454974` |
| SHA-256 | `cfbd2859a855c47242fa0966147baacc11e4174ecb70910953f451711efffa92` |
| SHA3-384 | `53897606fd0e62c15da58e9a32e019d6e5175669d7c24a78446ed0d46a2df4a3a24e6c025abe3d5373c8c480af13149f` |
| TLSH | `T16B93F885BCC3452AC9D413BFB52E519E332173E5D2CE7212D8A30B653A8762B0E63F95` |
| TELFHASH | `t1d9e06800fd699a1ca9d39670ed5902b6a2022233b61b0b11cfe4cbd0843b004b60de9e` |
| SSDEEP | `1536:7PPOMkP1VibKMQ4UVicyyASz8WuZbfPRjRY5VGvhIMGpbHMzWT:6VGKhMN1+MMb5T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_cfbd2859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfbd2859a855c47242fa0966147baacc11e4174ecb70910953f451711efffa92"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:50"
  condition:
    hash.sha256(0, filesize) == "cfbd2859a855c47242fa0966147baacc11e4174ecb70910953f451711efffa92"
}
```

### Sample 73: `69cbe4f3ad816def`

| Field | Value |
|---|---|
| SHA-256 | `69cbe4f3ad816def514f1ec5c6cada7874be2d0230ebf89ec1aaff8179daa0d3` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-03 19:27:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9e6c6a4b2c306695dd177faa15055d0` |
| SHA-1 | `64618c69a12d740bd66666bf7c2e5ae06a58dbac` |
| SHA-256 | `69cbe4f3ad816def514f1ec5c6cada7874be2d0230ebf89ec1aaff8179daa0d3` |
| SHA3-384 | `235aa60e0e02a121f6265ee6171f02a90be94d2671807e609c56f2d89bd87764af56893d33a7980d4551486815f0ea40` |
| TLSH | `T1A9E33B9DB402AE7EFC0BD57E4CA70E15FA31E3B12153172A629BFD63A8321650D17E81` |
| SSDEEP | `3072:SwzwVQJr9BDFuYEPG934Lbw6hkodsdb50MHp5FEAYt:EI5uYEPGhd65sZ50MlEAYt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_69cbe4f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69cbe4f3ad816def514f1ec5c6cada7874be2d0230ebf89ec1aaff8179daa0d3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:49"
  condition:
    hash.sha256(0, filesize) == "69cbe4f3ad816def514f1ec5c6cada7874be2d0230ebf89ec1aaff8179daa0d3"
}
```

### Sample 74: `9fe304dca3df86aa`

| Field | Value |
|---|---|
| SHA-256 | `9fe304dca3df86aabe0f6df2ee36af044faddc91c6b234ece1f748ddcf0feaed` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-03 19:27:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9344934224cfd66e25112b774bd64b27` |
| SHA-1 | `f8e638e1d5941c2de862c553ef693cbc7d943b4d` |
| SHA-256 | `9fe304dca3df86aabe0f6df2ee36af044faddc91c6b234ece1f748ddcf0feaed` |
| SHA3-384 | `be758f9b763334df401d5be31592108dea6282da0e2ca334d70b48ffcfd79e74af0e1119256a400b8e1c500b96117fef` |
| TLSH | `T11BC38E32D5A4A9D4C0624135E462EA304F63E6C902971EBF2FD68A754087D64FF09BFB` |
| SSDEEP | `3072:byj5ZKoipZS9HBYHlmq1+r+BQ6BKKlz6B2E1E:bytZskhMl02Q6B5DE1E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_9fe304dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fe304dca3df86aabe0f6df2ee36af044faddc91c6b234ece1f748ddcf0feaed"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:47"
  condition:
    hash.sha256(0, filesize) == "9fe304dca3df86aabe0f6df2ee36af044faddc91c6b234ece1f748ddcf0feaed"
}
```

### Sample 75: `cf256778782901b1`

| Field | Value |
|---|---|
| SHA-256 | `cf256778782901b1d22145836ca1608163bf42c1c61055f455c3f4172b6c2a3c` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-03 19:27:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92d59fc5a23e58c526173686545134f1` |
| SHA-1 | `cf79f49db34b338710789382f3f64d33613f0e0e` |
| SHA-256 | `cf256778782901b1d22145836ca1608163bf42c1c61055f455c3f4172b6c2a3c` |
| SHA3-384 | `f08331a5fde00c664f33a71d59ed9c5d03610e840fa2c5dddff3f914134ac6bb93a1341a4d3a165465217f0ca7109724` |
| TLSH | `T14A04C50EAE618F7DF79983341BB78E219758338326E1C546E1ACD7115F9428E241FFA8` |
| TELFHASH | `t1312193484a7423e067345c991aadfb77e16030da7b226d378e11a5ab67ad9829e20c0c` |
| SSDEEP | `3072:x98b/DqKAuv5nPyZhFKLLj1kQnUqopYRE7X7kZYoMMRlGsvFb41LFJjKHZ/UZcpL:x98b/DqKAuv5nPyZhFKLLj1kQnUqopYD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_cf256778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf256778782901b1d22145836ca1608163bf42c1c61055f455c3f4172b6c2a3c"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:46"
  condition:
    hash.sha256(0, filesize) == "cf256778782901b1d22145836ca1608163bf42c1c61055f455c3f4172b6c2a3c"
}
```

### Sample 76: `aa7ce81bcdc86211`

| Field | Value |
|---|---|
| SHA-256 | `aa7ce81bcdc862114d7d8c192e50cd786afeab12a0d8da5593e7d48e0929d2d6` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-03 19:27:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aecff1da4f66c419840a9501025ab240` |
| SHA-1 | `cde75818e1893b89a01abc794cee65a3fc7f96ae` |
| SHA-256 | `aa7ce81bcdc862114d7d8c192e50cd786afeab12a0d8da5593e7d48e0929d2d6` |
| SHA3-384 | `3f77e3656c6546d968c60d6d1f1d0e5c0f8db4d7de34761475f85d41c74a780cd4df6588807046b9dbbc90a087bd5c14` |
| TLSH | `T16FD34C07722C0F07D5A20AB1263E5BE093FE95D111F4BB89691E6B5A5732E3B1482FCD` |
| SSDEEP | `3072:eiipkAST2h+SJ0I8bHFKJAhUZAs5yPZVfv3:6kDT2UE+HFyAhUZAs5yPzfv3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_aa7ce81b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa7ce81bcdc862114d7d8c192e50cd786afeab12a0d8da5593e7d48e0929d2d6"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:45"
  condition:
    hash.sha256(0, filesize) == "aa7ce81bcdc862114d7d8c192e50cd786afeab12a0d8da5593e7d48e0929d2d6"
}
```

### Sample 77: `66f20c6e83535b71`

| Field | Value |
|---|---|
| SHA-256 | `66f20c6e83535b714269058d69bfc620e1752526a10d6c851639825f55549659` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-03 19:27:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f690fe3d3343dd018806acb02b8e92ec` |
| SHA-1 | `a4cf4fea9023bc2a45f213d4c75b1fba2d814940` |
| SHA-256 | `66f20c6e83535b714269058d69bfc620e1752526a10d6c851639825f55549659` |
| SHA3-384 | `17ddbad3c98e8a828c51275a496ecad87b6face356aae9911cc157e71ef2465d78250d4b8e2ee5befa30eacde2c4b464` |
| TLSH | `T160B33AC1E64FD4F8D91641702267EB379B32FC76013EDA93D7A49B727C93A4198062AC` |
| TELFHASH | `t19b31d1f8fa661cdcabe09503e24ea761ed1de57b347021fd19f6266032b214192bdc35` |
| SSDEEP | `3072:KJFrpq7W7PTL9rH5crC3MFZnKOiKYWFiHGNIiP4r:OG7WDTL1H5crIMFZKOiUL4r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_66f20c6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66f20c6e83535b714269058d69bfc620e1752526a10d6c851639825f55549659"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:44"
  condition:
    hash.sha256(0, filesize) == "66f20c6e83535b714269058d69bfc620e1752526a10d6c851639825f55549659"
}
```

### Sample 78: `16f0b77fa4508cbf`

| Field | Value |
|---|---|
| SHA-256 | `16f0b77fa4508cbf1e11f11ff7d22bfc6b5c5ce997320ddeb58cbbdff6572605` |
| Family label | `unknown` |
| File name | `RTK_NIC_DRIVER_INSTALLER.sfx.exe` |
| File type | `exe` |
| First seen | `2026-07-03 19:15:47` |
| Reporter | `lschab` |
| Tags | `Dropper, exe, RTK` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb4f892713157b9a4db7ef66aa798826` |
| SHA-1 | `44dc47e80a9d6a8ba6d19c20d6521df28b2132f8` |
| SHA-256 | `16f0b77fa4508cbf1e11f11ff7d22bfc6b5c5ce997320ddeb58cbbdff6572605` |
| SHA3-384 | `22adcf7b7fb8d36e8a91a779fffd48ef1394bba1f97683c2ff16f7932680e07296ca725ccafdff0e6832ec3cea802e71` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1B93523427BD08CB9C7DB66B051826DF4D1A9F7350504864BBBD08E0AAFB9391FB4E127` |
| SSDEEP | `24576:P2yePUjJdPVOqP8sY3yQQ3KaJVn81V+2oDFRY0vV6kY:PpfNDOqPZFQMJeoDDYEV6kY` |
| ICON-DHASH | `5486b6d4cc2b8a82` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_16f0b77f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16f0b77fa4508cbf1e11f11ff7d22bfc6b5c5ce997320ddeb58cbbdff6572605"
    family = "unknown"
    file_name = "RTK_NIC_DRIVER_INSTALLER.sfx.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:15:47"
  condition:
    hash.sha256(0, filesize) == "16f0b77fa4508cbf1e11f11ff7d22bfc6b5c5ce997320ddeb58cbbdff6572605"
}
```

### Sample 79: `311294dee731688c`

| Field | Value |
|---|---|
| SHA-256 | `311294dee731688c8762cfa6e5865b8a989fcddb3166737f137416db6f46e515` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-03 19:13:45` |
| Reporter | `realmalcorex` |
| Tags | `exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2052462dc2ea99c770d696677bfa94e9` |
| SHA-256 | `311294dee731688c8762cfa6e5865b8a989fcddb3166737f137416db6f46e515` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_311294de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "311294dee731688c8762cfa6e5865b8a989fcddb3166737f137416db6f46e515"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:13:45"
  condition:
    hash.sha256(0, filesize) == "311294dee731688c8762cfa6e5865b8a989fcddb3166737f137416db6f46e515"
}
```

### Sample 80: `765bfb5d7829184a`

| Field | Value |
|---|---|
| SHA-256 | `765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce` |
| Family label | `unknown` |
| File name | `765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce.exe` |
| File type | `exe` |
| First seen | `2026-07-03 19:12:10` |
| Reporter | `realmalcorex` |
| Tags | `dropper, exe, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ab1af35ab18f2b8e8777b397a2cd4b` |
| SHA-256 | `765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_765bfb5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce"
    family = "unknown"
    file_name = "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:12:10"
  condition:
    hash.sha256(0, filesize) == "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce"
}
```

### Sample 81: `4f40cb6ebc6025a2`

| Field | Value |
|---|---|
| SHA-256 | `4f40cb6ebc6025a25428b99a475567d2907c83c788f99b24a46046d74e756fb4` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-03 19:11:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f88e824f8c10e6712c8e74fc8ee00f44` |
| SHA-1 | `9a193b47209fada133566e894794105d39e628f8` |
| SHA-256 | `4f40cb6ebc6025a25428b99a475567d2907c83c788f99b24a46046d74e756fb4` |
| SHA3-384 | `beb0d6e929814a7e789848fe45151d4e9f21ba7adfb4ccdd6d116a58fcf7dec94bdc798355149e4047acb069ee06b093` |
| TLSH | `T10D014CC98544680080ADD96D32E75454F820D3CA195A4F6ABF6C6A3DEB98814F067FA5` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha4Y9mjRztMVRYDIX:e9Qp+Ms4Y9y9IYcX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_4f40cb6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f40cb6ebc6025a25428b99a475567d2907c83c788f99b24a46046d74e756fb4"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-03 19:11:31"
  condition:
    hash.sha256(0, filesize) == "4f40cb6ebc6025a25428b99a475567d2907c83c788f99b24a46046d74e756fb4"
}
```

### Sample 82: `f5b1bc797b8693d7`

| Field | Value |
|---|---|
| SHA-256 | `f5b1bc797b8693d71954e2dbd9e077f512f23e1944c9f43fe7b860718c975b8f` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-07-03 19:09:17` |
| Reporter | `realmalcorex` |
| Tags | `dll, exe, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ec20b98f01fbc117e0b2b53898583fc` |
| SHA-256 | `f5b1bc797b8693d71954e2dbd9e077f512f23e1944c9f43fe7b860718c975b8f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_f5b1bc79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b1bc797b8693d71954e2dbd9e077f512f23e1944c9f43fe7b860718c975b8f"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-03 19:09:17"
  condition:
    hash.sha256(0, filesize) == "f5b1bc797b8693d71954e2dbd9e077f512f23e1944c9f43fe7b860718c975b8f"
}
```

### Sample 83: `f3e1e3c4397686ae`

| Field | Value |
|---|---|
| SHA-256 | `f3e1e3c4397686ae17308f1f5376a76eaacfe018b834a7d3f5512739be7d19b3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 19:03:56` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cae1448008c11d810dd0fc8bde721db6` |
| SHA-1 | `cc5fe809d81b9b599d3ffb964c2544f28c53e430` |
| SHA-256 | `f3e1e3c4397686ae17308f1f5376a76eaacfe018b834a7d3f5512739be7d19b3` |
| SHA3-384 | `32902aa46289435a1114beab35c3189b7a05c3536b682e07c39873f33318cf612f543e118dc4aad2e65d64fe9aaf41f1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A8564A07ECA545E9C0AEE230896B9253BB717C485F2123D32BA0F7286F76BD06E75750` |
| SSDEEP | `49152:mO3INVQGTfyPlc1Fqg8xVNXTYDnFqR6LKJSLwDNA6oOJlPV5T5Rzc/XnTfKiK9KE:mIVl9Y8R6OLFzTH4bbfE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_f3e1e3c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3e1e3c4397686ae17308f1f5376a76eaacfe018b834a7d3f5512739be7d19b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 19:03:56"
  condition:
    hash.sha256(0, filesize) == "f3e1e3c4397686ae17308f1f5376a76eaacfe018b834a7d3f5512739be7d19b3"
}
```

### Sample 84: `a88440ce83acf3cb`

| Field | Value |
|---|---|
| SHA-256 | `a88440ce83acf3cbc70960fca0fa1b152175c5d40249dce399dfd3e2f255d46e` |
| Family label | `unknown` |
| File name | `Mod Menu.exe` |
| File type | `exe` |
| First seen | `2026-07-03 19:01:23` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f01f911ce1441d4dd0167476bfbe414` |
| SHA-1 | `a264c7e9757939f1116f5d38e07704b6eec81cd3` |
| SHA-256 | `a88440ce83acf3cbc70960fca0fa1b152175c5d40249dce399dfd3e2f255d46e` |
| SHA3-384 | `581f573e18f1413c102cdf2ffd399c212f9782f958e12505efc0dcbe7f722afbeb7ba3a49b3ae8693932fcffe23f5808` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D9D58D0B6CE119E9C4AA573288B642A67B34BC064F3223E72E90B7783F767D15D75384` |
| SSDEEP | `49152:sBm9zNxAu6ImPyA2tl0hcEGkmetgaMjA9c1ffTcpFr4e:sBK9JAupp9agA9D9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_a88440ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a88440ce83acf3cbc70960fca0fa1b152175c5d40249dce399dfd3e2f255d46e"
    family = "unknown"
    file_name = "Mod Menu.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:01:23"
  condition:
    hash.sha256(0, filesize) == "a88440ce83acf3cbc70960fca0fa1b152175c5d40249dce399dfd3e2f255d46e"
}
```

### Sample 85: `2a13ab4f0f16e535`

| Field | Value |
|---|---|
| SHA-256 | `2a13ab4f0f16e535a4cf4193fb0ed1487ab9fe651cdbaceb3059b8035425dbfb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 18:49:00` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f13faa8f36644c4a897bb66c1d8203e` |
| SHA-1 | `0f9b8710916f470b44c1bb0e4a381539a9d04bdd` |
| SHA-256 | `2a13ab4f0f16e535a4cf4193fb0ed1487ab9fe651cdbaceb3059b8035425dbfb` |
| SHA3-384 | `d56b853d7e08c660b525d30a4a9e650960528cd2a480a587fc5c8aa14a80232121f1bc1807512fc0e7b821067c1532cf` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F4D59D07BCE009E9D8AA92314CB651967B75BC590F3627D32E90B7782F72BE09C35B44` |
| SSDEEP | `49152:4jt105bE5qsCAIiHtQdxXU847NMO1wsW1jpLgvyy:4j0I84taxXU8472O1kjxiyy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_2a13ab4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a13ab4f0f16e535a4cf4193fb0ed1487ab9fe651cdbaceb3059b8035425dbfb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 18:49:00"
  condition:
    hash.sha256(0, filesize) == "2a13ab4f0f16e535a4cf4193fb0ed1487ab9fe651cdbaceb3059b8035425dbfb"
}
```

### Sample 86: `f558a4bf6ef4b5fb`

| Field | Value |
|---|---|
| SHA-256 | `f558a4bf6ef4b5fb6773016bbb5d3ac32a619ce040f18c1cd27d2e3dded3dd89` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 18:42:50` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bf777f66683a71d31775b61f088b94f` |
| SHA-1 | `9a2a564f44c82aebe1393208aa1c8bbc38923e7e` |
| SHA-256 | `f558a4bf6ef4b5fb6773016bbb5d3ac32a619ce040f18c1cd27d2e3dded3dd89` |
| SHA3-384 | `978f905c9d029a86ddd29c989955753b83d86a9c8789786666a6c52f85191496593a2e31d220cb2597cb4e3e2310b314` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T169967D43ECA159E9C19AA2308AA39253BB717C444F3263D36B50F7382F76BD46EB5314` |
| SSDEEP | `98304:eIfOOyCCTXhlpgseSGAD6EJhUfmEa+wz9ZwYAMCa7mHA665G:e1Zhlp9eShD6cmDaRz9CYcAcE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_f558a4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f558a4bf6ef4b5fb6773016bbb5d3ac32a619ce040f18c1cd27d2e3dded3dd89"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 18:42:50"
  condition:
    hash.sha256(0, filesize) == "f558a4bf6ef4b5fb6773016bbb5d3ac32a619ce040f18c1cd27d2e3dded3dd89"
}
```

### Sample 87: `b9783c0434065058`

| Field | Value |
|---|---|
| SHA-256 | `b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e` |
| Family label | `WannaCry` |
| File name | `b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e` |
| File type | `exe` |
| First seen | `2026-07-03 18:15:39` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c766f29e987f4acf421154bb35193f2` |
| SHA-1 | `3c4e3332a3c1c355884437537908b41bfc7850df` |
| SHA-256 | `b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e` |
| SHA3-384 | `33bad4cff8879a4d75c963f9f3314964f45a49c6f5953871134b7df9886f343955f5ac8d65b8a820e6549e26269a637b` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T13736176897E24415D0A7C0F10112BE2DAB2F7D61A2786FC6C2D37E1FE8B36865D31A43` |
| SSDEEP | `24576:jbLg1bLgdeQhfdmMSirYbcMNgefuF8S9r7D:jnYnjQqMSPbcBp8S` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_087_b9783c04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e"
    family = "WannaCry"
    file_name = "b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e"
    file_type = "exe"
    first_seen = "2026-07-03 18:15:39"
  condition:
    hash.sha256(0, filesize) == "b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e"
}
```

### Sample 88: `286fc32a88aaae7d`

| Field | Value |
|---|---|
| SHA-256 | `286fc32a88aaae7d0a379231659b31e34b318f7accbb0b95ef04d19fb6664a61` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 18:10:10` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e84cbc8ada3fec312bbeb89cdf16899` |
| SHA-1 | `4987e49c708da735e65be23c7ec60c2a68110264` |
| SHA-256 | `286fc32a88aaae7d0a379231659b31e34b318f7accbb0b95ef04d19fb6664a61` |
| SHA3-384 | `673773b426092453c11797d92bc43a08ad06006f5b2552efa1c0d4a0411011b34078344561af6c13d35530a451252645` |
| IMPHASH | `a5ef44db574ab5725b21145405f45cb5` |
| TLSH | `T198E501027F40D502D1965E329AB6D7F86731FD4D9A5A834B30E3AE0BBDEA6D35D022C4` |
| SSDEEP | `49152:VqJlwIyNAxOeA8VPmV9jcKpbDS4DCvgBGMYMGi5OtL6eTcoyJPtT9lT+BX06:0DiyOz8Zy9vbDSCCYGx+5O0eSdT+BX06` |
| ICON-DHASH | `30f0c8ccccccf030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_286fc32a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "286fc32a88aaae7d0a379231659b31e34b318f7accbb0b95ef04d19fb6664a61"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 18:10:10"
  condition:
    hash.sha256(0, filesize) == "286fc32a88aaae7d0a379231659b31e34b318f7accbb0b95ef04d19fb6664a61"
}
```

### Sample 89: `bb35a00f5da453cf`

| Field | Value |
|---|---|
| SHA-256 | `bb35a00f5da453cf95d189e88873a7cb95d168aa69b80db07ea67fa2c35895d0` |
| Family label | `unknown` |
| File name | `RFQ_EMS-PFC-2026009530.js` |
| File type | `js` |
| First seen | `2026-07-03 18:03:42` |
| Reporter | `TomU` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7af9ed7817cc33c37294d6a2c4ae828e` |
| SHA-1 | `ad275d2e94e56ae8485ae8cce44f8c602db7592c` |
| SHA-256 | `bb35a00f5da453cf95d189e88873a7cb95d168aa69b80db07ea67fa2c35895d0` |
| SHA3-384 | `e1275ccbe85d007ff35e5783380393d175aadf4da109ebc481013bd8eac9f4833241f13190147b44ba3868f4c24d4100` |
| TLSH | `T13FA5AF7E1FCAB46AC03757268D6A3974DC009AB739DA04423E3B3BCCA714761E151EB6` |
| SSDEEP | `768:2BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBa:p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_bb35a00f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb35a00f5da453cf95d189e88873a7cb95d168aa69b80db07ea67fa2c35895d0"
    family = "unknown"
    file_name = "RFQ_EMS-PFC-2026009530.js"
    file_type = "js"
    first_seen = "2026-07-03 18:03:42"
  condition:
    hash.sha256(0, filesize) == "bb35a00f5da453cf95d189e88873a7cb95d168aa69b80db07ea67fa2c35895d0"
}
```

### Sample 90: `bac16a48407ea22b`

| Field | Value |
|---|---|
| SHA-256 | `bac16a48407ea22b8905e476bbb93fc0b5ecda8bb70364094479700e33cb15d1` |
| Family label | `Formbook` |
| File name | `New_Quote.exe` |
| File type | `exe` |
| First seen | `2026-07-03 18:03:39` |
| Reporter | `TomU` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d1d9fb7cbc129aaf5dfb93869f58d40` |
| SHA-1 | `01f5a80ad6ad4bac09728218fb610f49d55c7ad9` |
| SHA-256 | `bac16a48407ea22b8905e476bbb93fc0b5ecda8bb70364094479700e33cb15d1` |
| SHA3-384 | `f03569eb72a26254f2b110ac27225db09752dae4280b6541b402cd3719702b44573210c997211dd2aaa79407c07e9662` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B625DF1613E85B94F9BEE73895740100B7F6B803DB2ED76E6D8811ED5E31B81C692B23` |
| SSDEEP | `12288:eOoUslm2A83T3wkTMLsu7SuGHIqAGGSZeGRpQ6s7EwOz4RH6asxTkkk:eONslA83Tge0F7UHx5QiKczyWG` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_090_bac16a48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bac16a48407ea22b8905e476bbb93fc0b5ecda8bb70364094479700e33cb15d1"
    family = "Formbook"
    file_name = "New_Quote.exe"
    file_type = "exe"
    first_seen = "2026-07-03 18:03:39"
  condition:
    hash.sha256(0, filesize) == "bac16a48407ea22b8905e476bbb93fc0b5ecda8bb70364094479700e33cb15d1"
}
```

### Sample 91: `a6b79b9210ad2a32`

| Field | Value |
|---|---|
| SHA-256 | `a6b79b9210ad2a32e882432e419cc207269dcffdf0de25c5188f5317c66cb309` |
| Family label | `unknown` |
| File name | `지급_증빙09889778009.js` |
| File type | `js` |
| First seen | `2026-07-03 18:03:36` |
| Reporter | `TomU` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb37030436b9d18d325df07bf25b28a9` |
| SHA-1 | `4325f1552569f5becd4012dfb0c548555a5d5b01` |
| SHA-256 | `a6b79b9210ad2a32e882432e419cc207269dcffdf0de25c5188f5317c66cb309` |
| SHA3-384 | `ff8b998556973344d8e343eafededcec807658f41f408b05672f35ea7a6a60db650f25dad2e16e32c273e9c7dd6b8128` |
| TLSH | `T12A9502054EC42FB9CFAC6A1940BE150EE3A10ECE5556B58AFB33BD46FFE7A044117289` |
| SSDEEP | `24576:Tt5W2RDQtQLBXd/6KZOXmkWjgza6gIZX4cw4iXx7+BCI6mBQcCwcTqiV:BTR0QrtZOtag7IZ1DIbM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_a6b79b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b79b9210ad2a32e882432e419cc207269dcffdf0de25c5188f5317c66cb309"
    family = "unknown"
    file_name = "지급_증빙09889778009.js"
    file_type = "js"
    first_seen = "2026-07-03 18:03:36"
  condition:
    hash.sha256(0, filesize) == "a6b79b9210ad2a32e882432e419cc207269dcffdf0de25c5188f5317c66cb309"
}
```

### Sample 92: `404db5e6bd73b228`

| Field | Value |
|---|---|
| SHA-256 | `404db5e6bd73b2284fa19734a8335242c20c102321a54478887b939e96152f03` |
| Family label | `unknown` |
| File name | `RFQ_EMS-PFC-2026009530.rar` |
| File type | `rar` |
| First seen | `2026-07-03 18:03:34` |
| Reporter | `TomU` |
| Tags | `rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0fac6a909ae0e56137aafe35b246fd9` |
| SHA-1 | `ad939429f6116d34569ebecb8cf84793fdc72cac` |
| SHA-256 | `404db5e6bd73b2284fa19734a8335242c20c102321a54478887b939e96152f03` |
| SHA3-384 | `744df189fe00055bae762e0d85a45058bf6a923c43d577e325e8b98f47ba0a039a6821ea03af10be647f7bc82caeef51` |
| TLSH | `T1F103F2BDF1EB57F946AE24890F1A2B05063A3D5603AFE43A301B0EF870ED55BD98C512` |
| SSDEEP | `768:IchrF4XkskuzEAzeCACPFSbFiDQ27ogQwjRONxnQqU2BaSCDjb+qsl+QwxTEj:IchrF4XuYTiCxN+FEzMgQwVEOqU2BaJA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_404db5e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404db5e6bd73b2284fa19734a8335242c20c102321a54478887b939e96152f03"
    family = "unknown"
    file_name = "RFQ_EMS-PFC-2026009530.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:34"
  condition:
    hash.sha256(0, filesize) == "404db5e6bd73b2284fa19734a8335242c20c102321a54478887b939e96152f03"
}
```

### Sample 93: `7ff8cfa3044d0b95`

| Field | Value |
|---|---|
| SHA-256 | `7ff8cfa3044d0b95252edde70b999c0e642f260d5134f8889165db637043342a` |
| Family label | `Formbook` |
| File name | `New_Quote.rar` |
| File type | `rar` |
| First seen | `2026-07-03 18:03:31` |
| Reporter | `TomU` |
| Tags | `Formbook, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43faa20355f26c00e61dd84ab89a01c4` |
| SHA-1 | `734ab6d0c52225d6dc14365b795a3357e3c3d090` |
| SHA-256 | `7ff8cfa3044d0b95252edde70b999c0e642f260d5134f8889165db637043342a` |
| SHA3-384 | `bca67c8e8ee80481c8f3df12657380ec89cb74a8e5a3fd4a2ecdfc8fe9a1295ce12fbdbfa21a45657f0feeea0d15ee6c` |
| TLSH | `T157F423AB4F4264641A42F35CB600F7FE59D31CF82C0DCA63B327A15FFE6CA649A65091` |
| SSDEEP | `12288:cGAhTleGBoge7pDvrtzbLxp8FEmdl/roiGIClEbJgxImZTdJjzPXenENaO:cnyBvNcRl/rFGIDbixvdNzveENX` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_093_7ff8cfa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ff8cfa3044d0b95252edde70b999c0e642f260d5134f8889165db637043342a"
    family = "Formbook"
    file_name = "New_Quote.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:31"
  condition:
    hash.sha256(0, filesize) == "7ff8cfa3044d0b95252edde70b999c0e642f260d5134f8889165db637043342a"
}
```

### Sample 94: `5107be85b62d663b`

| Field | Value |
|---|---|
| SHA-256 | `5107be85b62d663bec44ea73324a7658e7cbdc8ec5fbb5953ef8051398610f8b` |
| Family label | `unknown` |
| File name | `_09889778009.rar` |
| File type | `rar` |
| First seen | `2026-07-03 18:03:17` |
| Reporter | `TomU` |
| Tags | `rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2143b66bdea3a291d30c67859e11d13` |
| SHA-1 | `8e5fc89017f3807a103698d76bc0917b3e2e88d9` |
| SHA-256 | `5107be85b62d663bec44ea73324a7658e7cbdc8ec5fbb5953ef8051398610f8b` |
| SHA3-384 | `86af6acebed0dee6f38f3eed2b49f0e8f70c5f0ef3849f9bf19a98135cc20972f64c3c7a0c47ee64c9f464441f3be0c6` |
| TLSH | `T1E255336BD73899B4303AEE565C7DFFADA91D48236B8B944952B3E00F50D27039EAF410` |
| SSDEEP | `24576:AiTVzckOlpChZH5ExgRGMtbiI3RyZuErpn+PIZRK+jRYFnuihgDy/Q2x0I8KC5Ep:AixaTChZ5EyDtWIDErh+PIZRKyquGAy3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_5107be85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5107be85b62d663bec44ea73324a7658e7cbdc8ec5fbb5953ef8051398610f8b"
    family = "unknown"
    file_name = "_09889778009.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:17"
  condition:
    hash.sha256(0, filesize) == "5107be85b62d663bec44ea73324a7658e7cbdc8ec5fbb5953ef8051398610f8b"
}
```

### Sample 95: `1145e36db0b83afa`

| Field | Value |
|---|---|
| SHA-256 | `1145e36db0b83afac59e0949e16fee00a65a6fd40ebcb4dc5f20e7690f3dec8c` |
| Family label | `XWorm` |
| File name | `SCAN_DOC_FILE_PR_0001000265.rar` |
| File type | `rar` |
| First seen | `2026-07-03 18:03:14` |
| Reporter | `TomU` |
| Tags | `rar, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9ce90d57ed01ac752d9f85be87041ff` |
| SHA-1 | `d9d0e6c215f10c7a4b8f8622b0d74cfe74c480bf` |
| SHA-256 | `1145e36db0b83afac59e0949e16fee00a65a6fd40ebcb4dc5f20e7690f3dec8c` |
| SHA3-384 | `9007e4a71ac4bc326b2e4532ebb80f1006d64ef52ccfe9224d807d1cf9188ac50f79f78d639ebe0d76491f04dc19bbf9` |
| TLSH | `T1901523D58721D603C85155FE9DF8B09E80AE5EBBF90C0844D476A3AFDF39618A99C23C` |
| SSDEEP | `24576:34vdXZdosi48s57a+bcZr4fe9pa6p3ZjIUcC9+RMf75:34VXZCd1s57a+Krf4eIcwS1` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_095_1145e36d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1145e36db0b83afac59e0949e16fee00a65a6fd40ebcb4dc5f20e7690f3dec8c"
    family = "XWorm"
    file_name = "SCAN_DOC_FILE_PR_0001000265.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:14"
  condition:
    hash.sha256(0, filesize) == "1145e36db0b83afac59e0949e16fee00a65a6fd40ebcb4dc5f20e7690f3dec8c"
}
```

### Sample 96: `839c56270979bc41`

| Field | Value |
|---|---|
| SHA-256 | `839c56270979bc4138b53a8372b59e63fb27ae9522f5b0b31d279efe2416f787` |
| Family label | `AgentTesla` |
| File name | `Order_Inquiry_#070126.tar.rar` |
| File type | `rar` |
| First seen | `2026-07-03 18:03:10` |
| Reporter | `TomU` |
| Tags | `AgentTesla, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1f5c8d7437eae187108c70dbbed067f` |
| SHA-1 | `a765dad3cef2b9d725b98329f3bf0aff8164188b` |
| SHA-256 | `839c56270979bc4138b53a8372b59e63fb27ae9522f5b0b31d279efe2416f787` |
| SHA3-384 | `65eb429ac1b5f14e8f4f5b7d3ae4df0c157d7b54b1ee324086c1740c3757826cab370676ce9e90c3f58ef361e165b370` |
| TLSH | `T17815334F63D2FCD2894083671509685CD972A43BAEEC24B6BF36E4F5330D67982B5B14` |
| SSDEEP | `24576:HC25oPhZw/z70JwqWg2Mhyc2dwBv18ixN9+:HC25oPh4hqWRxcqwBNh+` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_096_839c5627
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839c56270979bc4138b53a8372b59e63fb27ae9522f5b0b31d279efe2416f787"
    family = "AgentTesla"
    file_name = "Order_Inquiry_#070126.tar.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:10"
  condition:
    hash.sha256(0, filesize) == "839c56270979bc4138b53a8372b59e63fb27ae9522f5b0b31d279efe2416f787"
}
```

### Sample 97: `8834d1ae56d0eba9`

| Field | Value |
|---|---|
| SHA-256 | `8834d1ae56d0eba97eeabc0103ff7ed9d52974d821afda892a45eacbb18f6128` |
| Family label | `unknown` |
| File name | `107.173.143.45_128_givemebesttimeforbetterplacescomingforme.hta` |
| File type | `hta` |
| First seen | `2026-07-03 18:02:56` |
| Reporter | `TomU` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1328bf3e044c79a36d5992ba3f53ba5` |
| SHA-1 | `212654c4777e3f1ec7e2dfe6523971f569d42f63` |
| SHA-256 | `8834d1ae56d0eba97eeabc0103ff7ed9d52974d821afda892a45eacbb18f6128` |
| SHA3-384 | `0feb52e08e41f630053fd5ba7082b3d635896bc2642dbb13b955631ec3f2f689f5e87f04f189fca2e8ff1cbe7b5d4bb9` |
| TLSH | `T15B24355D39535E9E9AE1970CE2E2441F0FAEEF1DD260B7C82ED34BCEE24994076A4D04` |
| SSDEEP | `6144:qhWKS4Ji/9QPaCGAYz6pZ99iD6A0B9oiq0BMczHA5MpYqGTJ+0PzdjP1EhZpv4TI:8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_8834d1ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8834d1ae56d0eba97eeabc0103ff7ed9d52974d821afda892a45eacbb18f6128"
    family = "unknown"
    file_name = "107.173.143.45_128_givemebesttimeforbetterplacescomingforme.hta"
    file_type = "hta"
    first_seen = "2026-07-03 18:02:56"
  condition:
    hash.sha256(0, filesize) == "8834d1ae56d0eba97eeabc0103ff7ed9d52974d821afda892a45eacbb18f6128"
}
```

### Sample 98: `7777f9917be9ce17`

| Field | Value |
|---|---|
| SHA-256 | `7777f9917be9ce17233c35e1b38cbb34c45878c23e1b39d7956fa52cd7bb4983` |
| Family label | `RemcosRAT` |
| File name | `147.124.213.158_46_goodforbestpeoplesaroundonmybestthigns.hta` |
| File type | `hta` |
| First seen | `2026-07-03 18:02:53` |
| Reporter | `TomU` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97ac4d3415c0de5985c1f81ad2997fa9` |
| SHA-1 | `757cc90ae1863fd1dbe280e970099dd9ed4fa3e9` |
| SHA-256 | `7777f9917be9ce17233c35e1b38cbb34c45878c23e1b39d7956fa52cd7bb4983` |
| SHA3-384 | `332b0e386e08e93f4c3a8496756b941120fd77904e950afd5d8f16c368099ee15b5d0d20ae0537f5c8bc5e99659ce576` |
| TLSH | `T18B1430F335ECA5AA7B579E5302B2F162D1623BAA7A0345605294BE2313F0644FF0BC5D` |
| SSDEEP | `1536:FUYOzJwNsCvSFOFZpeJD9KU2d9vFoJhqWSsmbavKin6Xh6gHwoSCBfDlpHNNnTKk:F0zFa6hpPK` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_098_7777f991
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7777f9917be9ce17233c35e1b38cbb34c45878c23e1b39d7956fa52cd7bb4983"
    family = "RemcosRAT"
    file_name = "147.124.213.158_46_goodforbestpeoplesaroundonmybestthigns.hta"
    file_type = "hta"
    first_seen = "2026-07-03 18:02:53"
  condition:
    hash.sha256(0, filesize) == "7777f9917be9ce17233c35e1b38cbb34c45878c23e1b39d7956fa52cd7bb4983"
}
```

### Sample 99: `c1bb7171e2f0316f`

| Field | Value |
|---|---|
| SHA-256 | `c1bb7171e2f0316fc8f48b16387a1df989baea568b8c1632c687c6486fc2dd0d` |
| Family label | `RemcosRAT` |
| File name | `Annexure_-_Specifications.zip` |
| File type | `zip` |
| First seen | `2026-07-03 18:02:47` |
| Reporter | `TomU` |
| Tags | `RemcosRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2806ba2f7552e898a2fc0efa2161c965` |
| SHA-1 | `e1822eff6d482eb32a8c53c274b547a0649119cd` |
| SHA-256 | `c1bb7171e2f0316fc8f48b16387a1df989baea568b8c1632c687c6486fc2dd0d` |
| SHA3-384 | `54801b57073aec89c471d3f6dab880a0e01b3e3c8a70eb2d25996536d8dbaa0b490f323a0c2425c66d0f2e61a207670b` |
| TLSH | `T1BEB53311D22F844B31FF66239512FA456EA99383DC3F2C77343796E85A007CAC5ABA53` |
| SSDEEP | `49152:OoaseWrVvqr5L7CQzqwmkbEqOCIYHCD6CGBdGnx6q1UmC8Mm3llVotIb8S:OoaseCVytL/TErYHO6FBdE6q1+8T3llX` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_099_c1bb7171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1bb7171e2f0316fc8f48b16387a1df989baea568b8c1632c687c6486fc2dd0d"
    family = "RemcosRAT"
    file_name = "Annexure_-_Specifications.zip"
    file_type = "zip"
    first_seen = "2026-07-03 18:02:47"
  condition:
    hash.sha256(0, filesize) == "c1bb7171e2f0316fc8f48b16387a1df989baea568b8c1632c687c6486fc2dd0d"
}
```

### Sample 100: `a182f5d6317bf28a`

| Field | Value |
|---|---|
| SHA-256 | `a182f5d6317bf28aefa3169bf0cb356124ebf65721874f5e0ca61e6c1e52546a` |
| Family label | `RemcosRAT` |
| File name | `Requirement_document_2026010711864779153.vbs` |
| File type | `vbs` |
| First seen | `2026-07-03 18:02:37` |
| Reporter | `TomU` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `099cb5e0b84b815002eeee8a1c0f65a0` |
| SHA-1 | `40f32d8f8fc284b30c540b0f81b415f36e5ccb38` |
| SHA-256 | `a182f5d6317bf28aefa3169bf0cb356124ebf65721874f5e0ca61e6c1e52546a` |
| SHA3-384 | `ff6922d33ff41c7e4d444e0d36436be17d4cd6671322a9006534b87d54a914b1d433d37816c1b8096ed6d222c43bbab5` |
| TLSH | `T117A4DC34ADEA503972B3AE75CAD6B697E91FB6633B2F981D108103464723942EDC133D` |
| SSDEEP | `12288:fCo54re5E1jV8jcMHes/CkqUabNa8cJq+QR+:WS0W1` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_100_a182f5d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a182f5d6317bf28aefa3169bf0cb356124ebf65721874f5e0ca61e6c1e52546a"
    family = "RemcosRAT"
    file_name = "Requirement_document_2026010711864779153.vbs"
    file_type = "vbs"
    first_seen = "2026-07-03 18:02:37"
  condition:
    hash.sha256(0, filesize) == "a182f5d6317bf28aefa3169bf0cb356124ebf65721874f5e0ca61e6c1e52546a"
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
 * Generated: 2026-07-04T04:06:08.895608+00:00
 */

rule MalwareBazaar_unknown_001_4ae4d4f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 03:47:58"
  condition:
    hash.sha256(0, filesize) == "4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d"
}

rule MalwareBazaar_unknown_002_ce23b566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface"
    family = "unknown"
    file_name = "a.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:47:31"
  condition:
    hash.sha256(0, filesize) == "ce23b56615c9b0625799dca8c83558eb1016cce8aec1919dd52d31bf646eface"
}

rule MalwareBazaar_unknown_003_82d17518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82d1751826ee9b9914ba01955da3f573ea0cd1f90f8a0ed5e4a719a2d0be40d0"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-04 03:46:35"
  condition:
    hash.sha256(0, filesize) == "82d1751826ee9b9914ba01955da3f573ea0cd1f90f8a0ed5e4a719a2d0be40d0"
}

rule MalwareBazaar_unknown_004_3855f94e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72"
    family = "unknown"
    file_name = "set-up.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:44:56"
  condition:
    hash.sha256(0, filesize) == "3855f94e68b2b0353b8e318a2864b959631ecff88e90fddde4e5a77c69acac72"
}

rule MalwareBazaar_unknown_005_d9d65ba9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d65ba90d1cb339ebfda7ba9f422c475f5f733f4eeafe4dbdb8b666c3c262f4"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-04 03:42:21"
  condition:
    hash.sha256(0, filesize) == "d9d65ba90d1cb339ebfda7ba9f422c475f5f733f4eeafe4dbdb8b666c3c262f4"
}

rule MalwareBazaar_unknown_006_a8c981ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c981ac3b86c512d87a116ac8be45c41bb2f89d6a18c9c4354ade3859207529"
    family = "unknown"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-07-04 03:40:33"
  condition:
    hash.sha256(0, filesize) == "a8c981ac3b86c512d87a116ac8be45c41bb2f89d6a18c9c4354ade3859207529"
}

rule MalwareBazaar_unknown_007_420ab59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420ab59a03b591cc1024218a80aa2a4b012fdd005c9ffe28c57ba17f9d93c6a2"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-07-04 03:39:15"
  condition:
    hash.sha256(0, filesize) == "420ab59a03b591cc1024218a80aa2a4b012fdd005c9ffe28c57ba17f9d93c6a2"
}

rule MalwareBazaar_unknown_008_5a67fd7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:37:32"
  condition:
    hash.sha256(0, filesize) == "5a67fd7e1f3bd5d1bca01efa7bd91407635d0c69e4d8924b0c4c87296dc11d40"
}

rule MalwareBazaar_unknown_009_8cbe48fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-04 03:35:50"
  condition:
    hash.sha256(0, filesize) == "8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f"
}

rule MalwareBazaar_unknown_010_291c081c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "291c081c856ab085cef02df6f3ac744944cc938d1e5e319b5c5b20d148d76648"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 02:52:51"
  condition:
    hash.sha256(0, filesize) == "291c081c856ab085cef02df6f3ac744944cc938d1e5e319b5c5b20d148d76648"
}

rule MalwareBazaar_Mirai_011_5e4cb6e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e4cb6e2b0947184199d16f75a95da19e32ba730eeddf68dd6a2d65da7357e5e"
    family = "Mirai"
    file_name = "SH4"
    file_type = "elf"
    first_seen = "2026-07-04 02:15:57"
  condition:
    hash.sha256(0, filesize) == "5e4cb6e2b0947184199d16f75a95da19e32ba730eeddf68dd6a2d65da7357e5e"
}

rule MalwareBazaar_unknown_012_2bd0a82a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd0a82af6732a32911224e6392b234b61d6485875cea8d848a88a012591256a"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-04 02:11:58"
  condition:
    hash.sha256(0, filesize) == "2bd0a82af6732a32911224e6392b234b61d6485875cea8d848a88a012591256a"
}

rule MalwareBazaar_Mirai_013_8a9dc5e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9dc5e4d7bed616871882b6038941598aeecd64b4bde11fee2eb4ce1a8f7e7a"
    family = "Mirai"
    file_name = "X86_64"
    file_type = "elf"
    first_seen = "2026-07-04 02:11:57"
  condition:
    hash.sha256(0, filesize) == "8a9dc5e4d7bed616871882b6038941598aeecd64b4bde11fee2eb4ce1a8f7e7a"
}

rule MalwareBazaar_unknown_014_3c0edd3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089"
    family = "unknown"
    file_name = "src_0(1).apk"
    file_type = "apk"
    first_seen = "2026-07-04 02:01:50"
  condition:
    hash.sha256(0, filesize) == "3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089"
}

rule MalwareBazaar_unknown_015_3063914c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3063914cc10de86a689070151a61172fc17619e71d1bd643a3d0cf94b84e10a8"
    family = "unknown"
    file_name = "src_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 02:01:38"
  condition:
    hash.sha256(0, filesize) == "3063914cc10de86a689070151a61172fc17619e71d1bd643a3d0cf94b84e10a8"
}

rule MalwareBazaar_unknown_016_d8b3327e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8b3327efe0c98be433a7a73591facb031fadcad747ad99e4ac3ccd0e6751290"
    family = "unknown"
    file_name = "res_obs_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 02:01:25"
  condition:
    hash.sha256(0, filesize) == "d8b3327efe0c98be433a7a73591facb031fadcad747ad99e4ac3ccd0e6751290"
}

rule MalwareBazaar_unknown_017_b459673b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b459673b77209ff89a2833977b4de341a529722f1e4662451b514df220e13afc"
    family = "unknown"
    file_name = "output_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:59:50"
  condition:
    hash.sha256(0, filesize) == "b459673b77209ff89a2833977b4de341a529722f1e4662451b514df220e13afc"
}

rule MalwareBazaar_unknown_018_61d4518f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61d4518fac40db1cef72d8b6f9a14080d93ef53a6f6e55605ee12da87978a14f"
    family = "unknown"
    file_name = "entry_added_0.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:58:59"
  condition:
    hash.sha256(0, filesize) == "61d4518fac40db1cef72d8b6f9a14080d93ef53a6f6e55605ee12da87978a14f"
}

rule MalwareBazaar_unknown_019_fea09cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fea09cb621507334ff92f30e0455db20e0de38a86e8b3e38c434340cc4ca2112"
    family = "unknown"
    file_name = "apksigner7474716956837711150.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:58:11"
  condition:
    hash.sha256(0, filesize) == "fea09cb621507334ff92f30e0455db20e0de38a86e8b3e38c434340cc4ca2112"
}

rule MalwareBazaar_Mirai_020_de40109b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de40109b05faaca5c2715008b6d1af0ab53652a424346ff4ee2ade44c76b8c41"
    family = "Mirai"
    file_name = "ARMV7L"
    file_type = "elf"
    first_seen = "2026-07-04 01:47:56"
  condition:
    hash.sha256(0, filesize) == "de40109b05faaca5c2715008b6d1af0ab53652a424346ff4ee2ade44c76b8c41"
}

rule MalwareBazaar_unknown_021_f966b81a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f966b81a9ed9c9f025cb92f12cf4839a2ff37b8ca14133ae214a4f88c0efc56a"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-04 01:36:59"
  condition:
    hash.sha256(0, filesize) == "f966b81a9ed9c9f025cb92f12cf4839a2ff37b8ca14133ae214a4f88c0efc56a"
}

rule MalwareBazaar_Mirai_022_6d32be92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d32be92b12fa0a7f39fb49c2870673cd8bd8e89374eff5255725711372e9bcc"
    family = "Mirai"
    file_name = "POWERPC"
    file_type = "elf"
    first_seen = "2026-07-04 01:35:59"
  condition:
    hash.sha256(0, filesize) == "6d32be92b12fa0a7f39fb49c2870673cd8bd8e89374eff5255725711372e9bcc"
}

rule MalwareBazaar_Mirai_023_25b2e83c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25b2e83c211a98b07222e3706365cbf5da043062146d5258a70ff2da9185e0da"
    family = "Mirai"
    file_name = "MIPS"
    file_type = "elf"
    first_seen = "2026-07-04 01:32:56"
  condition:
    hash.sha256(0, filesize) == "25b2e83c211a98b07222e3706365cbf5da043062146d5258a70ff2da9185e0da"
}

rule MalwareBazaar_Mirai_024_903f7182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "903f7182ad5cb63e3db43df0b86f781665c55c2bd2e62b92782ec44c8d867146"
    family = "Mirai"
    file_name = "ARMV4L"
    file_type = "elf"
    first_seen = "2026-07-04 01:28:54"
  condition:
    hash.sha256(0, filesize) == "903f7182ad5cb63e3db43df0b86f781665c55c2bd2e62b92782ec44c8d867146"
}

rule MalwareBazaar_unknown_025_bcb93b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcb93b961d7188b32745b05b700959ba49d5b05ea870d9eeed2e2db63e8b7575"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-04 01:27:53"
  condition:
    hash.sha256(0, filesize) == "bcb93b961d7188b32745b05b700959ba49d5b05ea870d9eeed2e2db63e8b7575"
}

rule MalwareBazaar_unknown_026_e763dd5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e763dd5e7ae6b2d1436f7f659dd4511e4bef24c5823fd0739dd1c9ec5154a4c0"
    family = "unknown"
    file_name = "ۦۖ۫.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:24:20"
  condition:
    hash.sha256(0, filesize) == "e763dd5e7ae6b2d1436f7f659dd4511e4bef24c5823fd0739dd1c9ec5154a4c0"
}

rule MalwareBazaar_unknown_027_1ba4bb9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a"
    family = "unknown"
    file_name = "temp_info.apk"
    file_type = "apk"
    first_seen = "2026-07-04 01:24:04"
  condition:
    hash.sha256(0, filesize) == "1ba4bb9f0990697fa0c3b12ddf2d1f31ef385e14556c081f3f5e30dcbbf50f1a"
}

rule MalwareBazaar_Mirai_028_f6645b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6645b4590b974e3c52db619a8c65a52d0a6671a73cf991a59e17725262c230d"
    family = "Mirai"
    file_name = "Mozi.a"
    file_type = "elf"
    first_seen = "2026-07-04 01:20:58"
  condition:
    hash.sha256(0, filesize) == "f6645b4590b974e3c52db619a8c65a52d0a6671a73cf991a59e17725262c230d"
}

rule MalwareBazaar_Mirai_029_36669b21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36669b2129c9bb80926741214cf045703aafdeddf48604fcd348a41fb80ad9aa"
    family = "Mirai"
    file_name = "ARMV5L"
    file_type = "elf"
    first_seen = "2026-07-04 01:18:58"
  condition:
    hash.sha256(0, filesize) == "36669b2129c9bb80926741214cf045703aafdeddf48604fcd348a41fb80ad9aa"
}

rule MalwareBazaar_Mirai_030_c5950c48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5950c484b3fdf3f64c019c49d04232845b156b18e30198e163e2a9c14bf05c0"
    family = "Mirai"
    file_name = "ARMV6L"
    file_type = "elf"
    first_seen = "2026-07-04 01:14:54"
  condition:
    hash.sha256(0, filesize) == "c5950c484b3fdf3f64c019c49d04232845b156b18e30198e163e2a9c14bf05c0"
}

rule MalwareBazaar_unknown_031_b8db3025
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8db3025146cacb9959e2e3c7b28f909478e1f8ed6e35c699c4b72cbcd311531"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-04 01:07:54"
  condition:
    hash.sha256(0, filesize) == "b8db3025146cacb9959e2e3c7b28f909478e1f8ed6e35c699c4b72cbcd311531"
}

rule MalwareBazaar_unknown_032_71a395a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71a395a22d8ad7421b7050c650187c771ea52d5820640b259d79dfcd8c4adb1b"
    family = "unknown"
    file_name = "gg10"
    file_type = "elf"
    first_seen = "2026-07-04 01:01:59"
  condition:
    hash.sha256(0, filesize) == "71a395a22d8ad7421b7050c650187c771ea52d5820640b259d79dfcd8c4adb1b"
}

rule MalwareBazaar_unknown_033_357d6a12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "357d6a12b37bf72550d9df5035f25157d3ca75e1a69e71783586ee4759ee7b45"
    family = "unknown"
    file_name = "cleaned_apk_1205069634158871545.apk"
    file_type = "apk"
    first_seen = "2026-07-04 00:58:15"
  condition:
    hash.sha256(0, filesize) == "357d6a12b37bf72550d9df5035f25157d3ca75e1a69e71783586ee4759ee7b45"
}

rule MalwareBazaar_Mirai_034_da258307
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da258307c61058016d7e553c07f00dcc06c119ce40536db59d4f726c16d32fb2"
    family = "Mirai"
    file_name = "SPARC"
    file_type = "elf"
    first_seen = "2026-07-04 00:54:54"
  condition:
    hash.sha256(0, filesize) == "da258307c61058016d7e553c07f00dcc06c119ce40536db59d4f726c16d32fb2"
}

rule MalwareBazaar_Mirai_035_2a51dabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a51dabd7c6c63d88ae13ca65a8a01c99fae1d4913a08ace28910c6f47074323"
    family = "Mirai"
    file_name = "MIPSEL"
    file_type = "elf"
    first_seen = "2026-07-04 00:50:56"
  condition:
    hash.sha256(0, filesize) == "2a51dabd7c6c63d88ae13ca65a8a01c99fae1d4913a08ace28910c6f47074323"
}

rule MalwareBazaar_Mirai_036_e65ee878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e65ee878453d6fa2005f27ad16ecab564cf371992db9e058d8bdd78bde54a99a"
    family = "Mirai"
    file_name = "M68K"
    file_type = "elf"
    first_seen = "2026-07-04 00:36:56"
  condition:
    hash.sha256(0, filesize) == "e65ee878453d6fa2005f27ad16ecab564cf371992db9e058d8bdd78bde54a99a"
}

rule MalwareBazaar_Mirai_037_7a5ddf0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a5ddf0ddbe18b048b75dfe5153fc8ee5b6b5e8d9832c96ac7ea18591d272cdb"
    family = "Mirai"
    file_name = "I586"
    file_type = "elf"
    first_seen = "2026-07-04 00:33:56"
  condition:
    hash.sha256(0, filesize) == "7a5ddf0ddbe18b048b75dfe5153fc8ee5b6b5e8d9832c96ac7ea18591d272cdb"
}

rule MalwareBazaar_unknown_038_c433957c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab"
    family = "unknown"
    file_name = "f"
    file_type = "unknown"
    first_seen = "2026-07-04 00:32:54"
  condition:
    hash.sha256(0, filesize) == "c433957cc91e17664147cbbb9dabcee58a81747a4e4b3fdb233b6daedd8974ab"
}

rule MalwareBazaar_unknown_039_ffc708ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffc708aed38519ea8799e0cabebf6444934d1aa7db9f83a3c31b6847ed139b6d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 00:30:45"
  condition:
    hash.sha256(0, filesize) == "ffc708aed38519ea8799e0cabebf6444934d1aa7db9f83a3c31b6847ed139b6d"
}

rule MalwareBazaar_unknown_040_380137fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "380137fe3eb4ab4dae0d26aa1b94a4b19a9c28b1d84697b6e80ff8cb93ec5dca"
    family = "unknown"
    file_name = "Facturas Pagadas al Vencimiento.js"
    file_type = "js"
    first_seen = "2026-07-04 00:25:27"
  condition:
    hash.sha256(0, filesize) == "380137fe3eb4ab4dae0d26aa1b94a4b19a9c28b1d84697b6e80ff8cb93ec5dca"
}

rule MalwareBazaar_unknown_041_5db55a1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db55a1df1b4cd848c772430af5afa07b6d16c3fc2d1fcc4e85a2ff698f918e5"
    family = "unknown"
    file_name = "Setup_upd.exe"
    file_type = "exe"
    first_seen = "2026-07-04 00:24:53"
  condition:
    hash.sha256(0, filesize) == "5db55a1df1b4cd848c772430af5afa07b6d16c3fc2d1fcc4e85a2ff698f918e5"
}

rule MalwareBazaar_Mirai_042_a166b4f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a166b4f2f9c5565737ba6512416030b2518c812cd0abb3af52749b5bebdd9625"
    family = "Mirai"
    file_name = "I686"
    file_type = "elf"
    first_seen = "2026-07-04 00:12:55"
  condition:
    hash.sha256(0, filesize) == "a166b4f2f9c5565737ba6512416030b2518c812cd0abb3af52749b5bebdd9625"
}

rule MalwareBazaar_unknown_043_0a5d4b8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a5d4b8f65eba399f0b41ac648d939650ab6422ce4c715f8a1b5b99e1178678b"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-04 00:09:55"
  condition:
    hash.sha256(0, filesize) == "0a5d4b8f65eba399f0b41ac648d939650ab6422ce4c715f8a1b5b99e1178678b"
}

rule MalwareBazaar_unknown_044_27e3c9b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:54:29"
  condition:
    hash.sha256(0, filesize) == "27e3c9b676e96ef69a0043ebf547748ac7189207dc2100cc188ea024be596266"
}

rule MalwareBazaar_unknown_045_6af02f9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:41:24"
  condition:
    hash.sha256(0, filesize) == "6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040"
}

rule MalwareBazaar_unknown_046_0bf8f52b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bf8f52b28291edc505a64962e6ce04387a9784fc5b18aeff53629adb1f72f56"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:21:51"
  condition:
    hash.sha256(0, filesize) == "0bf8f52b28291edc505a64962e6ce04387a9784fc5b18aeff53629adb1f72f56"
}

rule MalwareBazaar_WannaCry_047_b15fabb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47"
    family = "WannaCry"
    file_name = "b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47"
    file_type = "exe"
    first_seen = "2026-07-03 23:15:34"
  condition:
    hash.sha256(0, filesize) == "b15fabb4f73fff2dd8dbb1a58e46423e9d33d985af34880d17e410b9ecd6bc47"
}

rule MalwareBazaar_unknown_048_9f427212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f42721255d8d62b4595b9040a9a7d742c8fe2a5ff17745c8e250cd04928c480"
    family = "unknown"
    file_name = "ۦۖ.apk"
    file_type = "apk"
    first_seen = "2026-07-03 23:00:54"
  condition:
    hash.sha256(0, filesize) == "9f42721255d8d62b4595b9040a9a7d742c8fe2a5ff17745c8e250cd04928c480"
}

rule MalwareBazaar_unknown_049_3c279bc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c279bc94d37eeaf2b81f78820ada90c8e40814e45818c7c5666ea8c49688d67"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 23:00:30"
  condition:
    hash.sha256(0, filesize) == "3c279bc94d37eeaf2b81f78820ada90c8e40814e45818c7c5666ea8c49688d67"
}

rule MalwareBazaar_unknown_050_536cb0e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "536cb0e2ffffa40d1ccd096eaaad43f094813bae15d8f6316dc35fb998d5e4cd"
    family = "unknown"
    file_name = "ۦۖ۫.apk"
    file_type = "apk"
    first_seen = "2026-07-03 22:51:43"
  condition:
    hash.sha256(0, filesize) == "536cb0e2ffffa40d1ccd096eaaad43f094813bae15d8f6316dc35fb998d5e4cd"
}

rule MalwareBazaar_unknown_051_dceebf2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dceebf2ce1186b22f60b7ee064670db88347761767ea8610a35e50e568b348b3"
    family = "unknown"
    file_name = "output.apk"
    file_type = "apk"
    first_seen = "2026-07-03 22:51:10"
  condition:
    hash.sha256(0, filesize) == "dceebf2ce1186b22f60b7ee064670db88347761767ea8610a35e50e568b348b3"
}

rule MalwareBazaar_WannaCry_052_f5b43a38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99"
    family = "WannaCry"
    file_name = "f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99"
    file_type = "exe"
    first_seen = "2026-07-03 22:15:45"
  condition:
    hash.sha256(0, filesize) == "f5b43a3803a8149dda677d208ba7ef5e0aa33640bcd3dd58924355f4fc54be99"
}

rule MalwareBazaar_WannaCry_053_b4f0148d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8"
    family = "WannaCry"
    file_name = "b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8.dll"
    file_type = "dll"
    first_seen = "2026-07-03 21:50:52"
  condition:
    hash.sha256(0, filesize) == "b4f0148df9332a4c3fdf19c71885867f7bff3f36641ba49dec8946ab366a64a8"
}

rule MalwareBazaar_unknown_054_6eb52744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd"
    family = "unknown"
    file_name = "6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd"
    file_type = "elf"
    first_seen = "2026-07-03 21:31:34"
  condition:
    hash.sha256(0, filesize) == "6eb5274407dd458da90fd988c04e30f5c14cf813fb4a4489b6a64eddc966a7fd"
}

rule MalwareBazaar_unknown_055_da01b54e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da01b54e7d42de9f00fdac7f2123779363a13df7d40bdb72558c9618e13dc77b"
    family = "unknown"
    file_name = "nuker.py"
    file_type = "unknown"
    first_seen = "2026-07-03 21:29:05"
  condition:
    hash.sha256(0, filesize) == "da01b54e7d42de9f00fdac7f2123779363a13df7d40bdb72558c9618e13dc77b"
}

rule MalwareBazaar_unknown_056_c17aff83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c17aff83c3fbddb86fe5a40d7a654af5591b16522fb15c222bbf3d57b0b16748"
    family = "unknown"
    file_name = "IndusindCreditCard.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:20:56"
  condition:
    hash.sha256(0, filesize) == "c17aff83c3fbddb86fe5a40d7a654af5591b16522fb15c222bbf3d57b0b16748"
}

rule MalwareBazaar_unknown_057_addbd877
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "addbd8770b53a50e83c711143332c76e9160f920675e2de5591669d3b93f499b"
    family = "unknown"
    file_name = "mparivahan-cefg.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:16:38"
  condition:
    hash.sha256(0, filesize) == "addbd8770b53a50e83c711143332c76e9160f920675e2de5591669d3b93f499b"
}

rule MalwareBazaar_unknown_058_3a03b35a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b"
    family = "unknown"
    file_name = "TⲓⲕTⲟⲕⲣⲅⲓⲃⲁⲧ.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:13:44"
  condition:
    hash.sha256(0, filesize) == "3a03b35a4c614d651954f8298d5bb75abe33223e0791bdc1b9bdb2af69d3009b"
}

rule MalwareBazaar_unknown_059_518f5438
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "518f5438a21e9aa9a91f0dd589088e443fda111d8ada5ea67d1cf14d6645974c"
    family = "unknown"
    file_name = "Sеks18+.apk"
    file_type = "apk"
    first_seen = "2026-07-03 21:12:15"
  condition:
    hash.sha256(0, filesize) == "518f5438a21e9aa9a91f0dd589088e443fda111d8ada5ea67d1cf14d6645974c"
}

rule MalwareBazaar_unknown_060_b0413872
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b04138725a86c8b04773f8be7c1b5550b0048f845050d0aae3c04044a5fb3e70"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-03 20:20:17"
  condition:
    hash.sha256(0, filesize) == "b04138725a86c8b04773f8be7c1b5550b0048f845050d0aae3c04044a5fb3e70"
}

rule MalwareBazaar_unknown_061_c120ab59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c120ab59ac32c2bcd14e0e091629bbdbd522381594261e3452ab11f5fd02bc57"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-03 20:11:20"
  condition:
    hash.sha256(0, filesize) == "c120ab59ac32c2bcd14e0e091629bbdbd522381594261e3452ab11f5fd02bc57"
}

rule MalwareBazaar_unknown_062_83017185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83017185a714532b3e54cd6a86bb46e95301cfc1e2b35324a5ed8eec326b35a9"
    family = "unknown"
    file_name = "3_19_8_1601_22.12.2025.rar"
    file_type = "rar"
    first_seen = "2026-07-03 20:06:50"
  condition:
    hash.sha256(0, filesize) == "83017185a714532b3e54cd6a86bb46e95301cfc1e2b35324a5ed8eec326b35a9"
}

rule MalwareBazaar_unknown_063_f17876b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f17876b82951bc093975ee015c959f34cbbd32ef0e3e76a047b0f07eecae4916"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 19:57:05"
  condition:
    hash.sha256(0, filesize) == "f17876b82951bc093975ee015c959f34cbbd32ef0e3e76a047b0f07eecae4916"
}

rule MalwareBazaar_unknown_064_f0afa9d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0afa9d9fb7f33961413b4827fe2a41c0cf54b7aebe0acc89c097e655b4762d7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 19:55:39"
  condition:
    hash.sha256(0, filesize) == "f0afa9d9fb7f33961413b4827fe2a41c0cf54b7aebe0acc89c097e655b4762d7"
}

rule MalwareBazaar_unknown_065_3aa68046
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aa68046fedf7a769161be75092ac65d7b9c7c20ea3b6fc2a0cc3547c783add2"
    family = "unknown"
    file_name = "photo-220665512.zip"
    file_type = "zip"
    first_seen = "2026-07-03 19:55:37"
  condition:
    hash.sha256(0, filesize) == "3aa68046fedf7a769161be75092ac65d7b9c7c20ea3b6fc2a0cc3547c783add2"
}

rule MalwareBazaar_unknown_066_b570834a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7"
    family = "unknown"
    file_name = "WealthGAF_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-07-03 19:52:05"
  condition:
    hash.sha256(0, filesize) == "b570834a38ff9d5e085dc48700332e536635d23e7cfb9b93fe65be1ffb85e0f7"
}

rule MalwareBazaar_unknown_067_d1e6e351
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e6e3515ab24c3403845bb89e0cebb1fff721632735dee1fe92e7be261a8d22"
    family = "unknown"
    file_name = "Zoom_Meeting_Notes_docx.zip"
    file_type = "zip"
    first_seen = "2026-07-03 19:43:38"
  condition:
    hash.sha256(0, filesize) == "d1e6e3515ab24c3403845bb89e0cebb1fff721632735dee1fe92e7be261a8d22"
}

rule MalwareBazaar_SilentNet_068_b46f58cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b46f58cd9bbdcfdec0908e67229b484c6f8482523092dd627e0e97fec62e53a4"
    family = "SilentNet"
    file_name = "MD2.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:37:30"
  condition:
    hash.sha256(0, filesize) == "b46f58cd9bbdcfdec0908e67229b484c6f8482523092dd627e0e97fec62e53a4"
}

rule MalwareBazaar_unknown_069_11ab28df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11ab28dfe32b4bba5c69ad37b1a898b519212036adec54d0cb306759126454d3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-03 19:29:19"
  condition:
    hash.sha256(0, filesize) == "11ab28dfe32b4bba5c69ad37b1a898b519212036adec54d0cb306759126454d3"
}

rule MalwareBazaar_Mirai_070_46f10062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f10062d69ebabbfe405bbd79eae9e9243735997d4353ff771adbe8f4f66607"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-03 19:29:17"
  condition:
    hash.sha256(0, filesize) == "46f10062d69ebabbfe405bbd79eae9e9243735997d4353ff771adbe8f4f66607"
}

rule MalwareBazaar_Mirai_071_94fa9601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94fa960157c205a74ee1a2a783d3208dd536f25adf2f39a05b0a282ac822fcc5"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-03 19:29:16"
  condition:
    hash.sha256(0, filesize) == "94fa960157c205a74ee1a2a783d3208dd536f25adf2f39a05b0a282ac822fcc5"
}

rule MalwareBazaar_Mirai_072_cfbd2859
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfbd2859a855c47242fa0966147baacc11e4174ecb70910953f451711efffa92"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:50"
  condition:
    hash.sha256(0, filesize) == "cfbd2859a855c47242fa0966147baacc11e4174ecb70910953f451711efffa92"
}

rule MalwareBazaar_Mirai_073_69cbe4f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69cbe4f3ad816def514f1ec5c6cada7874be2d0230ebf89ec1aaff8179daa0d3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:49"
  condition:
    hash.sha256(0, filesize) == "69cbe4f3ad816def514f1ec5c6cada7874be2d0230ebf89ec1aaff8179daa0d3"
}

rule MalwareBazaar_Mirai_074_9fe304dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fe304dca3df86aabe0f6df2ee36af044faddc91c6b234ece1f748ddcf0feaed"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:47"
  condition:
    hash.sha256(0, filesize) == "9fe304dca3df86aabe0f6df2ee36af044faddc91c6b234ece1f748ddcf0feaed"
}

rule MalwareBazaar_Mirai_075_cf256778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf256778782901b1d22145836ca1608163bf42c1c61055f455c3f4172b6c2a3c"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:46"
  condition:
    hash.sha256(0, filesize) == "cf256778782901b1d22145836ca1608163bf42c1c61055f455c3f4172b6c2a3c"
}

rule MalwareBazaar_Mirai_076_aa7ce81b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa7ce81bcdc862114d7d8c192e50cd786afeab12a0d8da5593e7d48e0929d2d6"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:45"
  condition:
    hash.sha256(0, filesize) == "aa7ce81bcdc862114d7d8c192e50cd786afeab12a0d8da5593e7d48e0929d2d6"
}

rule MalwareBazaar_Mirai_077_66f20c6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66f20c6e83535b714269058d69bfc620e1752526a10d6c851639825f55549659"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-03 19:27:44"
  condition:
    hash.sha256(0, filesize) == "66f20c6e83535b714269058d69bfc620e1752526a10d6c851639825f55549659"
}

rule MalwareBazaar_unknown_078_16f0b77f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16f0b77fa4508cbf1e11f11ff7d22bfc6b5c5ce997320ddeb58cbbdff6572605"
    family = "unknown"
    file_name = "RTK_NIC_DRIVER_INSTALLER.sfx.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:15:47"
  condition:
    hash.sha256(0, filesize) == "16f0b77fa4508cbf1e11f11ff7d22bfc6b5c5ce997320ddeb58cbbdff6572605"
}

rule MalwareBazaar_unknown_079_311294de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "311294dee731688c8762cfa6e5865b8a989fcddb3166737f137416db6f46e515"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:13:45"
  condition:
    hash.sha256(0, filesize) == "311294dee731688c8762cfa6e5865b8a989fcddb3166737f137416db6f46e515"
}

rule MalwareBazaar_unknown_080_765bfb5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce"
    family = "unknown"
    file_name = "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:12:10"
  condition:
    hash.sha256(0, filesize) == "765bfb5d7829184a23f615b871baebf893563d911dddd1d1c1a34604e5456cce"
}

rule MalwareBazaar_unknown_081_4f40cb6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f40cb6ebc6025a25428b99a475567d2907c83c788f99b24a46046d74e756fb4"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-03 19:11:31"
  condition:
    hash.sha256(0, filesize) == "4f40cb6ebc6025a25428b99a475567d2907c83c788f99b24a46046d74e756fb4"
}

rule MalwareBazaar_unknown_082_f5b1bc79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b1bc797b8693d71954e2dbd9e077f512f23e1944c9f43fe7b860718c975b8f"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-03 19:09:17"
  condition:
    hash.sha256(0, filesize) == "f5b1bc797b8693d71954e2dbd9e077f512f23e1944c9f43fe7b860718c975b8f"
}

rule MalwareBazaar_unknown_083_f3e1e3c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3e1e3c4397686ae17308f1f5376a76eaacfe018b834a7d3f5512739be7d19b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 19:03:56"
  condition:
    hash.sha256(0, filesize) == "f3e1e3c4397686ae17308f1f5376a76eaacfe018b834a7d3f5512739be7d19b3"
}

rule MalwareBazaar_unknown_084_a88440ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a88440ce83acf3cbc70960fca0fa1b152175c5d40249dce399dfd3e2f255d46e"
    family = "unknown"
    file_name = "Mod Menu.exe"
    file_type = "exe"
    first_seen = "2026-07-03 19:01:23"
  condition:
    hash.sha256(0, filesize) == "a88440ce83acf3cbc70960fca0fa1b152175c5d40249dce399dfd3e2f255d46e"
}

rule MalwareBazaar_unknown_085_2a13ab4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a13ab4f0f16e535a4cf4193fb0ed1487ab9fe651cdbaceb3059b8035425dbfb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 18:49:00"
  condition:
    hash.sha256(0, filesize) == "2a13ab4f0f16e535a4cf4193fb0ed1487ab9fe651cdbaceb3059b8035425dbfb"
}

rule MalwareBazaar_unknown_086_f558a4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f558a4bf6ef4b5fb6773016bbb5d3ac32a619ce040f18c1cd27d2e3dded3dd89"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 18:42:50"
  condition:
    hash.sha256(0, filesize) == "f558a4bf6ef4b5fb6773016bbb5d3ac32a619ce040f18c1cd27d2e3dded3dd89"
}

rule MalwareBazaar_WannaCry_087_b9783c04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e"
    family = "WannaCry"
    file_name = "b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e"
    file_type = "exe"
    first_seen = "2026-07-03 18:15:39"
  condition:
    hash.sha256(0, filesize) == "b9783c0434065058751b59f89948498ed8d08f93f6c5780cc0ce3a6d02bdf77e"
}

rule MalwareBazaar_unknown_088_286fc32a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "286fc32a88aaae7d0a379231659b31e34b318f7accbb0b95ef04d19fb6664a61"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 18:10:10"
  condition:
    hash.sha256(0, filesize) == "286fc32a88aaae7d0a379231659b31e34b318f7accbb0b95ef04d19fb6664a61"
}

rule MalwareBazaar_unknown_089_bb35a00f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb35a00f5da453cf95d189e88873a7cb95d168aa69b80db07ea67fa2c35895d0"
    family = "unknown"
    file_name = "RFQ_EMS-PFC-2026009530.js"
    file_type = "js"
    first_seen = "2026-07-03 18:03:42"
  condition:
    hash.sha256(0, filesize) == "bb35a00f5da453cf95d189e88873a7cb95d168aa69b80db07ea67fa2c35895d0"
}

rule MalwareBazaar_Formbook_090_bac16a48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bac16a48407ea22b8905e476bbb93fc0b5ecda8bb70364094479700e33cb15d1"
    family = "Formbook"
    file_name = "New_Quote.exe"
    file_type = "exe"
    first_seen = "2026-07-03 18:03:39"
  condition:
    hash.sha256(0, filesize) == "bac16a48407ea22b8905e476bbb93fc0b5ecda8bb70364094479700e33cb15d1"
}

rule MalwareBazaar_unknown_091_a6b79b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6b79b9210ad2a32e882432e419cc207269dcffdf0de25c5188f5317c66cb309"
    family = "unknown"
    file_name = "지급_증빙09889778009.js"
    file_type = "js"
    first_seen = "2026-07-03 18:03:36"
  condition:
    hash.sha256(0, filesize) == "a6b79b9210ad2a32e882432e419cc207269dcffdf0de25c5188f5317c66cb309"
}

rule MalwareBazaar_unknown_092_404db5e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404db5e6bd73b2284fa19734a8335242c20c102321a54478887b939e96152f03"
    family = "unknown"
    file_name = "RFQ_EMS-PFC-2026009530.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:34"
  condition:
    hash.sha256(0, filesize) == "404db5e6bd73b2284fa19734a8335242c20c102321a54478887b939e96152f03"
}

rule MalwareBazaar_Formbook_093_7ff8cfa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ff8cfa3044d0b95252edde70b999c0e642f260d5134f8889165db637043342a"
    family = "Formbook"
    file_name = "New_Quote.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:31"
  condition:
    hash.sha256(0, filesize) == "7ff8cfa3044d0b95252edde70b999c0e642f260d5134f8889165db637043342a"
}

rule MalwareBazaar_unknown_094_5107be85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5107be85b62d663bec44ea73324a7658e7cbdc8ec5fbb5953ef8051398610f8b"
    family = "unknown"
    file_name = "_09889778009.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:17"
  condition:
    hash.sha256(0, filesize) == "5107be85b62d663bec44ea73324a7658e7cbdc8ec5fbb5953ef8051398610f8b"
}

rule MalwareBazaar_XWorm_095_1145e36d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1145e36db0b83afac59e0949e16fee00a65a6fd40ebcb4dc5f20e7690f3dec8c"
    family = "XWorm"
    file_name = "SCAN_DOC_FILE_PR_0001000265.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:14"
  condition:
    hash.sha256(0, filesize) == "1145e36db0b83afac59e0949e16fee00a65a6fd40ebcb4dc5f20e7690f3dec8c"
}

rule MalwareBazaar_AgentTesla_096_839c5627
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839c56270979bc4138b53a8372b59e63fb27ae9522f5b0b31d279efe2416f787"
    family = "AgentTesla"
    file_name = "Order_Inquiry_#070126.tar.rar"
    file_type = "rar"
    first_seen = "2026-07-03 18:03:10"
  condition:
    hash.sha256(0, filesize) == "839c56270979bc4138b53a8372b59e63fb27ae9522f5b0b31d279efe2416f787"
}

rule MalwareBazaar_unknown_097_8834d1ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8834d1ae56d0eba97eeabc0103ff7ed9d52974d821afda892a45eacbb18f6128"
    family = "unknown"
    file_name = "107.173.143.45_128_givemebesttimeforbetterplacescomingforme.hta"
    file_type = "hta"
    first_seen = "2026-07-03 18:02:56"
  condition:
    hash.sha256(0, filesize) == "8834d1ae56d0eba97eeabc0103ff7ed9d52974d821afda892a45eacbb18f6128"
}

rule MalwareBazaar_RemcosRAT_098_7777f991
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7777f9917be9ce17233c35e1b38cbb34c45878c23e1b39d7956fa52cd7bb4983"
    family = "RemcosRAT"
    file_name = "147.124.213.158_46_goodforbestpeoplesaroundonmybestthigns.hta"
    file_type = "hta"
    first_seen = "2026-07-03 18:02:53"
  condition:
    hash.sha256(0, filesize) == "7777f9917be9ce17233c35e1b38cbb34c45878c23e1b39d7956fa52cd7bb4983"
}

rule MalwareBazaar_RemcosRAT_099_c1bb7171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1bb7171e2f0316fc8f48b16387a1df989baea568b8c1632c687c6486fc2dd0d"
    family = "RemcosRAT"
    file_name = "Annexure_-_Specifications.zip"
    file_type = "zip"
    first_seen = "2026-07-03 18:02:47"
  condition:
    hash.sha256(0, filesize) == "c1bb7171e2f0316fc8f48b16387a1df989baea568b8c1632c687c6486fc2dd0d"
}

rule MalwareBazaar_RemcosRAT_100_a182f5d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a182f5d6317bf28aefa3169bf0cb356124ebf65721874f5e0ca61e6c1e52546a"
    family = "RemcosRAT"
    file_name = "Requirement_document_2026010711864779153.vbs"
    file_type = "vbs"
    first_seen = "2026-07-03 18:02:37"
  condition:
    hash.sha256(0, filesize) == "a182f5d6317bf28aefa3169bf0cb356124ebf65721874f5e0ca61e6c1e52546a"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

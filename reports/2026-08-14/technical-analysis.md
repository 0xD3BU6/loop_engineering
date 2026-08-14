# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-14

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 669 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 669 |
| Unique family labels | 9 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 51 |
| unknown | 41 |
| SalatStealer | 2 |
| CoinMiner | 1 |
| WannaCry | 1 |
| SheetRAT | 1 |
| Vidar | 1 |
| LummaStealer | 1 |
| GhostPulse | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 50 |
| exe | 38 |
| sh | 7 |
| 7z | 3 |
| zip | 1 |
| iso | 1 |

## Per-Sample Analysis

### Sample 1: `18909faad7553046`

| Field | Value |
|---|---|
| SHA-256 | `18909faad7553046953dca1e904e782fda4cfdda2a35a02414c2d6eb44e1d61e` |
| Family label | `unknown` |
| File name | `sensi_tbk.sh` |
| File type | `sh` |
| First seen | `2026-08-14 02:58:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a7aa793fb303b70a814ecaf274587c8` |
| SHA-1 | `354547ae5f0c8e543b382f90e4c96ee4c877c5da` |
| SHA-256 | `18909faad7553046953dca1e904e782fda4cfdda2a35a02414c2d6eb44e1d61e` |
| SHA3-384 | `3c63c8d22f87d810ff6eea4df8faae9eb5fdeb6342da2d189f752c9389cc277c1f164d710d59b70b3cacd7481552f36b` |
| TLSH | `T1763106DA75D74D339E196C3912E46B4A75C1113F00512BE9B34C96779F0C964E06BD32` |
| SSDEEP | `48:kLC/rNLk91jpkxjSjPjHyC5MDAXbe7X0ux+u7xS:kuo91jGxjSjPjHygMDAXbT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_18909faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18909faad7553046953dca1e904e782fda4cfdda2a35a02414c2d6eb44e1d61e"
    family = "unknown"
    file_name = "sensi_tbk.sh"
    file_type = "sh"
    first_seen = "2026-08-14 02:58:48"
  condition:
    hash.sha256(0, filesize) == "18909faad7553046953dca1e904e782fda4cfdda2a35a02414c2d6eb44e1d61e"
}
```

### Sample 2: `2253f2e18dcdc930`

| Field | Value |
|---|---|
| SHA-256 | `2253f2e18dcdc93053d6dc04ebe3a7106be5075f359ef85e42da1e5c430d3cc5` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 02:52:36` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1124eb4ce72170ea049ccd9bc62325cb` |
| SHA-1 | `c0a99493900f3750a2a21172fe2b3fbd2e15dc5f` |
| SHA-256 | `2253f2e18dcdc93053d6dc04ebe3a7106be5075f359ef85e42da1e5c430d3cc5` |
| SHA3-384 | `b2150610e2829cd00739c3a72d1516028520568034b4dce81166fcb98896471e73ba165c85c3e261c0c90d5d1c0fdc6b` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1FCE6330CA6F162FEE933503CD8E21492F675F4690B76C4DB9B684772AE232D04D3E562` |
| SSDEEP | `393216:+oiIDqTHwEXEYnvFeDvSj0QqfL0WwY3zXMCHWUj8cuI3/PGTAI:+DQG5Ek0jxwOXMb8pH/O7` |
| ICON-DHASH | `f0f0dca68ac4f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_2253f2e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2253f2e18dcdc93053d6dc04ebe3a7106be5075f359ef85e42da1e5c430d3cc5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 02:52:36"
  condition:
    hash.sha256(0, filesize) == "2253f2e18dcdc93053d6dc04ebe3a7106be5075f359ef85e42da1e5c430d3cc5"
}
```

### Sample 3: `a8aa8fb051d230fd`

| Field | Value |
|---|---|
| SHA-256 | `a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c` |
| Family label | `unknown` |
| File name | `a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c.exe` |
| File type | `exe` |
| First seen | `2026-08-14 02:49:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7814fa4208c42b37135d56db64a6eed6` |
| SHA-1 | `7ba7e7e367455b4c377389b904b05db268cb0399` |
| SHA-256 | `a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c` |
| SHA3-384 | `45b3d96fdac8fe26325b455fbfec28afe10804241f055ecd9c0b6a859d2d7b20814798e5bb9dbb30bfca3e2ef299f1aa` |
| IMPHASH | `62a04abc11c4f31d37e5631ecf213d3c` |
| TLSH | `T168465A22558017E8E17FC179898A5E12FB31700913656BEF49D045A3EEA7AF0BE7F312` |
| SSDEEP | `98304:+BZmVvt0vJEEk1OgtksgohT3higkVgohT3higk:mZm/nJq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_a8aa8fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c"
    family = "unknown"
    file_name = "a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:49:05"
  condition:
    hash.sha256(0, filesize) == "a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c"
}
```

### Sample 4: `23d9c8b78e16d8b1`

| Field | Value |
|---|---|
| SHA-256 | `23d9c8b78e16d8b1db68fd04a4b133dd3649bb5c9f237ccf77f5b08d8ea8f8a6` |
| Family label | `unknown` |
| File name | `KeePass-2.61.1.exe` |
| File type | `exe` |
| First seen | `2026-08-14 02:33:04` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9becf4255266e2c6deddae16c1be39c3` |
| SHA-1 | `33fd681672a19d3438fc3abba6796dbdab5b5772` |
| SHA-256 | `23d9c8b78e16d8b1db68fd04a4b133dd3649bb5c9f237ccf77f5b08d8ea8f8a6` |
| SHA3-384 | `3ea22e0194390907fcd38a113f0b3993afc79502b435ab296e2191a8ff278d1ff274068102b5975b07e5b8d2c1e7c6e1` |
| IMPHASH | `4b200e917ee33d8e56206c360a98a2d3` |
| TLSH | `T161F72221358EC53AD92E05B09A6DAA6A962C6D760FB144D7B3DCBD5E2B304C31332F53` |
| SSDEEP | `1572864:/I55gii2OF6yuoq2VsF4Oyms+BlJVNP84GCubGTQCHoYchmhb0XgTqtdUo:FCF4n1eLNP8m4RqSIqYo` |
| ICON-DHASH | `70cc96969696d471` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_23d9c8b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23d9c8b78e16d8b1db68fd04a4b133dd3649bb5c9f237ccf77f5b08d8ea8f8a6"
    family = "unknown"
    file_name = "KeePass-2.61.1.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:33:04"
  condition:
    hash.sha256(0, filesize) == "23d9c8b78e16d8b1db68fd04a4b133dd3649bb5c9f237ccf77f5b08d8ea8f8a6"
}
```

### Sample 5: `6405dd6d75d35be3`

| Field | Value |
|---|---|
| SHA-256 | `6405dd6d75d35be336c264edcdf3c79d1285b66b5d168791c091132354b9446f` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-14 02:26:07` |
| Reporter | `iamaachum` |
| Tags | `exe, kolmods-com, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c33d431824ccc8d21c9cfb98c35b8e8e` |
| SHA-1 | `ab38a2caf81c4c7aaa668aedc3b716a7407cb2bf` |
| SHA-256 | `6405dd6d75d35be336c264edcdf3c79d1285b66b5d168791c091132354b9446f` |
| SHA3-384 | `37148e917e32037c837778761d2bab28d7e41eca37470d58fe6ffa73c23b2fc55c43e46b68f92320fd7ee57b91f75b3a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T140E59D0B6C9181E8C4AE673689B75119BB30BC4C4B7673D72EA0A6B42F723C15D7AF50` |
| SSDEEP | `49152:tot77HBjmdtQA7L5rYNUfJ0a5db4cXFusFzwSZujDfGcN:t8FwJJVvXuuyjbb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_6405dd6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6405dd6d75d35be336c264edcdf3c79d1285b66b5d168791c091132354b9446f"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:26:07"
  condition:
    hash.sha256(0, filesize) == "6405dd6d75d35be336c264edcdf3c79d1285b66b5d168791c091132354b9446f"
}
```

### Sample 6: `e11e65338860c6bd`

| Field | Value |
|---|---|
| SHA-256 | `e11e65338860c6bdcd6f2bc5f5d35f162c54df42ca63f0178ba3d481be0193ad` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-14 02:21:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb6bcf6c01625ae9ee0ece85544f97a9` |
| SHA-1 | `99865136295775ac41a18a8afa75d1f2ef27a42e` |
| SHA-256 | `e11e65338860c6bdcd6f2bc5f5d35f162c54df42ca63f0178ba3d481be0193ad` |
| SHA3-384 | `d0e0dd962c1920ba603d6f6811e6dda889e783172ec1dd9938940ea4634a3c718ea242ead0d731a5e5f07066feaf14a6` |
| TLSH | `T1BBE43955F880DF61C6C535B6F65D42A873074BB9D3EB72068A254B343BEB86B0F3A601` |
| TELFHASH | `t141f09e3676683d8463d621aa82a6e82a48b11f8643963590a7062c0e9fc3dd025e5933` |
| SSDEEP | `12288:Nnx34RWjzgsj0hiuaDh15bzpoj+UZW/ED3SlrNzqeK8pqP8qO:NGmgsCu11xzpi+f/EONzgb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_e11e6533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e11e65338860c6bdcd6f2bc5f5d35f162c54df42ca63f0178ba3d481be0193ad"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-14 02:21:28"
  condition:
    hash.sha256(0, filesize) == "e11e65338860c6bdcd6f2bc5f5d35f162c54df42ca63f0178ba3d481be0193ad"
}
```

### Sample 7: `8b6a1a72c7543206`

| Field | Value |
|---|---|
| SHA-256 | `8b6a1a72c7543206f7bf683ca5b01de3d21c7fb9bb6dfdcaaf271cbdac82aa51` |
| Family label | `Mirai` |
| File name | `pryznet.arm` |
| File type | `elf` |
| First seen | `2026-08-14 02:12:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03ac8023c8d07a5ee0e6b74c91975430` |
| SHA-1 | `2b4f191b5ed50d7eb876e8fce846ff501bfc822d` |
| SHA-256 | `8b6a1a72c7543206f7bf683ca5b01de3d21c7fb9bb6dfdcaaf271cbdac82aa51` |
| SHA3-384 | `a1044783792c7a2c38d2cfc44e3368a1b128bab48df22c53ff54e800d6f283571050a4eb87097a44358049e27e5e3f48` |
| TLSH | `T1ECB4CF67F6662D13C8E3DA3E15B782745273E64A13929306670EF17C39D223E4F1A6C4` |
| TELFHASH | `t1d111acf04b2b62115659cbdc9acdb35e152dc90a860bee37fd71407c60198ada42a88f` |
| SSDEEP | `12288:oDN1It8U8LNZMi+1GfUc5sk8pdDRbm29I4AqF7B5ns:oDNOtTf9GILI4JF7B5n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_8b6a1a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b6a1a72c7543206f7bf683ca5b01de3d21c7fb9bb6dfdcaaf271cbdac82aa51"
    family = "Mirai"
    file_name = "pryznet.arm"
    file_type = "elf"
    first_seen = "2026-08-14 02:12:57"
  condition:
    hash.sha256(0, filesize) == "8b6a1a72c7543206f7bf683ca5b01de3d21c7fb9bb6dfdcaaf271cbdac82aa51"
}
```

### Sample 8: `f975c5077bd77486`

| Field | Value |
|---|---|
| SHA-256 | `f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea` |
| Family label | `unknown` |
| File name | `f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea.exe` |
| File type | `exe` |
| First seen | `2026-08-14 02:04:02` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `491757de5a46115ed5d9ca8fa04414a4` |
| SHA-1 | `0ae98b6923dea5c1c2c6e027d8b234a3a833ccd1` |
| SHA-256 | `f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea` |
| SHA3-384 | `123cde8688911fbdb012bd873d31c772f0d2aed5ad16b83c3f1b6bf0c5e014931bb9c1b9286d3c7fb62051dadd1007e5` |
| IMPHASH | `4669c209bb88a8e57e3fa2dfb3d0021c` |
| TLSH | `T1EA465A22558017E8E17FC179898A5E12FF327009136567EF099045A3EEA7AF0BE7F352` |
| SSDEEP | `98304:HG8xo4tZLOuLPATULj2gohT3higkVgohT3higk:m8xnrJ+q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_f975c507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea"
    family = "unknown"
    file_name = "f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:04:02"
  condition:
    hash.sha256(0, filesize) == "f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea"
}
```

### Sample 9: `d56031341a68a3f2`

| Field | Value |
|---|---|
| SHA-256 | `d56031341a68a3f228450fb16ea51c28d2d699c1683529830c145b18e6596000` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-14 02:02:09` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1de4dd0ad9120ed7453b8133178d660` |
| SHA-1 | `6e3edfe1fd53ed3c15a7ad2472021c60ba5ea7fc` |
| SHA-256 | `d56031341a68a3f228450fb16ea51c28d2d699c1683529830c145b18e6596000` |
| SHA3-384 | `6a383e9742d051498971460ec55f9c5f5576c7a5f8c0f2015d2745e58fb69d31dcc616898f91bb51494d3b0aa15fb045` |
| TLSH | `T10CC28D966A867C44BDC98A3E4CBD2B5D6DF5C3D1324942AC3D8B3C719C11F9CC618B1A` |
| SSDEEP | `768:08vCB+25j6es8Rg9FYpMSUpi+20qUpi+20YQX:08l25Jmd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_d5603134
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d56031341a68a3f228450fb16ea51c28d2d699c1683529830c145b18e6596000"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 02:02:09"
  condition:
    hash.sha256(0, filesize) == "d56031341a68a3f228450fb16ea51c28d2d699c1683529830c145b18e6596000"
}
```

### Sample 10: `984f75b642647fc1`

| Field | Value |
|---|---|
| SHA-256 | `984f75b642647fc107514bf9aa33d5ee386193277ff58b01f9beb34d8ceb75fe` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-14 02:02:08` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39b4eb4bcce0f4f4983bfb9658b38103` |
| SHA-1 | `e6a53acc2cfc09fa6880357a44fa9c2cf4055d20` |
| SHA-256 | `984f75b642647fc107514bf9aa33d5ee386193277ff58b01f9beb34d8ceb75fe` |
| SHA3-384 | `97f0eff5bb5a2e482e15b5de48156224ec93df244ebc3f2ce905ba4b325e5ee4cf8397e82c24d534568ddb06307fc46b` |
| TLSH | `T1F7235C512A857C14AA98C8371D7F2F0CB9A943E6324452DE7FCF3CF68C4AA9D910972D` |
| SSDEEP | `768:YQFWzZx539GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:rkz2cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_984f75b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "984f75b642647fc107514bf9aa33d5ee386193277ff58b01f9beb34d8ceb75fe"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 02:02:08"
  condition:
    hash.sha256(0, filesize) == "984f75b642647fc107514bf9aa33d5ee386193277ff58b01f9beb34d8ceb75fe"
}
```

### Sample 11: `36bdf59bb5e719ed`

| Field | Value |
|---|---|
| SHA-256 | `36bdf59bb5e719eda9d2da8619cbb6827e5f9a2b9dd19806c704faa98c411360` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-14 01:55:56` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ed7e8aca1f11661eeaf8a01f1082f3b` |
| SHA-1 | `f1ddc671a4b06030f1e4314ac86b019acfeb7000` |
| SHA-256 | `36bdf59bb5e719eda9d2da8619cbb6827e5f9a2b9dd19806c704faa98c411360` |
| SHA3-384 | `d836077124426fabb336ed2e93912c4f6b0d1f711c0a9bca03bd99135cce45a18c2a76f31db6061ae686a454fc12e182` |
| TLSH | `T1F0319EDF44500A321512CD8D33A2344C618EE1E72DAFDBE4DD495EA993886DCF262F1E` |
| SSDEEP | `12:Uh65rhGpx6GpbLN3DIr6Di4wli6lWGrIDjx6jwrU0EgI6gOrnU46UQ5THi6a33C6:frYxgr4CfAaIy5T+uE9UA0+pjX5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_36bdf59b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36bdf59bb5e719eda9d2da8619cbb6827e5f9a2b9dd19806c704faa98c411360"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-14 01:55:56"
  condition:
    hash.sha256(0, filesize) == "36bdf59bb5e719eda9d2da8619cbb6827e5f9a2b9dd19806c704faa98c411360"
}
```

### Sample 12: `0e3cd256f1f3c143`

| Field | Value |
|---|---|
| SHA-256 | `0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98` |
| Family label | `unknown` |
| File name | `0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98.bin` |
| File type | `exe` |
| First seen | `2026-08-14 01:54:20` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0cc0ca281f90f853a6ffad03935dc9` |
| SHA-1 | `ac417a7152499a0d06e5b5e36516d19d0af13662` |
| SHA-256 | `0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98` |
| SHA3-384 | `0fe6fa38e624b3cc1025a03f28882651650155e4065e7c491bed6b486db22726475f9131ab2ea75cbb829c4a3f04e658` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15808AD0B7D9184E5C09EAB3189B7015ABB71BC494B3633D72DB0AA782F723D19D79B40` |
| SSDEEP | `49152:uBXkpFItKHwxLWfjoAN6fMi/LdTSBsYgwVm7ZkYGej:uSyTG60Ar7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_0e3cd256
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98"
    family = "unknown"
    file_name = "0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98.bin"
    file_type = "exe"
    first_seen = "2026-08-14 01:54:20"
  condition:
    hash.sha256(0, filesize) == "0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98"
}
```

### Sample 13: `13d9a5010daa3c2c`

| Field | Value |
|---|---|
| SHA-256 | `13d9a5010daa3c2c05da6e63d135732b17d861f7aea426b075898e967aa7d531` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 01:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c57e7a0c3175559c3ab4b8f0b20c7b03` |
| SHA-1 | `9420c2f186855c7dbf06da8770b085d98686410e` |
| SHA-256 | `13d9a5010daa3c2c05da6e63d135732b17d861f7aea426b075898e967aa7d531` |
| SHA3-384 | `738fd71afbb33c60583835a9e31359db15719bed666f03ecabc3c9682b6463f3c40e585167bbd95cf5d696c738d4b40f` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T160E6334CAED062EED9A3903DEBF25142D8B6B4220770CBDB539857316E673D0493DA27` |
| SSDEEP | `393216:wbIWvbS0VMNV9Rm+nlRXMCHWUjnDcuI3/PGTAI:wbZueMhk+nfXMb8ngH/O7` |
| ICON-DHASH | `b271e8cccce8f0b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_13d9a501
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13d9a5010daa3c2c05da6e63d135732b17d861f7aea426b075898e967aa7d531"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 01:52:33"
  condition:
    hash.sha256(0, filesize) == "13d9a5010daa3c2c05da6e63d135732b17d861f7aea426b075898e967aa7d531"
}
```

### Sample 14: `08f4d444d51993a9`

| Field | Value |
|---|---|
| SHA-256 | `08f4d444d51993a92e374193007440da52d5e9b375f7ad02fdaae7706280c1b1` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-14 01:51:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be84790945af67a336683635c7d55222` |
| SHA-1 | `9a7dcb7ea8c870ebe69712569eee359647f04cf8` |
| SHA-256 | `08f4d444d51993a92e374193007440da52d5e9b375f7ad02fdaae7706280c1b1` |
| SHA3-384 | `77b9ee7095b47bc16b3ed283c1a485bd95869a6eff85728c77b6d3de36d6ce80da1364e598fe753cf93903f4630099b6` |
| TLSH | `T1AFD4C70B6E228F6DF674873147F70B24EB6D23D627E1D580D1ADC5142F2128E592FBA8` |
| TELFHASH | `t197b14aa9193813f0a7545d8d4adcff329d6328ef3a561c339e60e89e971ba835e10c1c` |
| SSDEEP | `6144:tIQ62G3kAXssJK2ui7SP/h2Ez4RwlS87ZszC8co0m366cuN5ZYTy0COvotLX+HAh:GQKx/tui7jalTHQ9naNbxOqnwLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_08f4d444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f4d444d51993a92e374193007440da52d5e9b375f7ad02fdaae7706280c1b1"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-14 01:51:59"
  condition:
    hash.sha256(0, filesize) == "08f4d444d51993a92e374193007440da52d5e9b375f7ad02fdaae7706280c1b1"
}
```

### Sample 15: `f42b3277d3f04b17`

| Field | Value |
|---|---|
| SHA-256 | `f42b3277d3f04b17cb75ccdb8c9e0427db2a5c05fc40919fb3a9d4a2f5585e7f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-14 01:49:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb041ec54093c37afc316b7d26116a85` |
| SHA-1 | `33d9f534a754ec5329e425ee151714b7e9480a25` |
| SHA-256 | `f42b3277d3f04b17cb75ccdb8c9e0427db2a5c05fc40919fb3a9d4a2f5585e7f` |
| SHA3-384 | `f196e626216c6725224a902ad9836fcbd24cdc032c18a39445f81b78faf47fb934d0a145cf0e4a534e11979af7abed9c` |
| TLSH | `T1E4236C651A857C24AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:GXRWNGxVR9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ilxocr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_f42b3277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42b3277d3f04b17cb75ccdb8c9e0427db2a5c05fc40919fb3a9d4a2f5585e7f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 01:49:51"
  condition:
    hash.sha256(0, filesize) == "f42b3277d3f04b17cb75ccdb8c9e0427db2a5c05fc40919fb3a9d4a2f5585e7f"
}
```

### Sample 16: `1332d0c6a8400500`

| Field | Value |
|---|---|
| SHA-256 | `1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1` |
| Family label | `unknown` |
| File name | `1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:44:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27f61f45f1873b9a29c9e9a98cfe0253` |
| SHA-1 | `decc0a9b49d3bb2638d3cc9031eb1fe69f58c9a1` |
| SHA-256 | `1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1` |
| SHA3-384 | `35b22aa55d7e60496ebbd106f48476d44bed76220c4f8e3cf3d1d82aea19c4e5c7abf916be5e7a0cf9ebdf60b7ec0652` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T139D523DAA9F158B0C477C7B68F13E4ADB06D3B908F218E47F6DE2A00AD926585037771` |
| SSDEEP | `49152:zk2/gGxjBybUSbDPg/mNtfGJvNXayvaBsxbzh4W1iRy9DUvIqOI0U:zk2/30bUSbDPeahGBNVaBsbXsRyIEU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_1332d0c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1"
    family = "unknown"
    file_name = "1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:44:10"
  condition:
    hash.sha256(0, filesize) == "1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1"
}
```

### Sample 17: `411c4d388b54e659`

| Field | Value |
|---|---|
| SHA-256 | `411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f` |
| Family label | `CoinMiner` |
| File name | `411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:44:04` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23692ca87f42678c2f8a97331ae488d6` |
| SHA-1 | `f3f3d20f093bd53800560571280a9b9a145ef4f5` |
| SHA-256 | `411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f` |
| SHA3-384 | `c26b1e609ece571445003384b6ad927a4a2e267158f770e69c78a312fe66813d88195b08e6f9237ce33b61c3d0aa2578` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T151363355B8C6AAB6C067CBB88563A43E733E77A4C9A47C1B3BCC36054D26E042D3E754` |
| SSDEEP | `98304:Q4ZKHdUifbm1FgtLDz8IWVz7GlLy6VHyvNgFcPDhmMKjGPzjr5bACxcmK4Wjx:vY9UifbmYt3WVky6FyvNgFshRaG2HFf` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_017_411c4d38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f"
    family = "CoinMiner"
    file_name = "411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:44:04"
  condition:
    hash.sha256(0, filesize) == "411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f"
}
```

### Sample 18: `ae79cc20c0e9f55b`

| Field | Value |
|---|---|
| SHA-256 | `ae79cc20c0e9f55b3cb6993efc3fad68def359a303888c31c2f3625aa6449f29` |
| Family label | `Mirai` |
| File name | `dlr.arm7` |
| File type | `elf` |
| First seen | `2026-08-14 01:38:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b0c5e760e99be41375f80f8208d71a7` |
| SHA-1 | `52d371886bc7ea6d4a9fbd14ccb1e44b406209fc` |
| SHA-256 | `ae79cc20c0e9f55b3cb6993efc3fad68def359a303888c31c2f3625aa6449f29` |
| SHA3-384 | `154e317ed826d455fb620ddfbbbd16e5f2c6ae71fc2d014d6da6c9abff5b5be7bc8f337d551f846c8b031cdf9fba4491` |
| TLSH | `T154043B46A6418B13C0D61776FAAF424533229B68D3DF73068D28AFF43F87A5E4E63605` |
| TELFHASH | `t17521ee71572952116a75dda89ceeb3a7452883266389ef33df22c0dc640a09eda36c4f` |
| SSDEEP | `3072:DPVBJZj32VnTqG/Q2nsbqaX4+4XPBhjfSM4FcWOob/goM/9F5rqt:Dt932nTc20qaX4+4XPbjwKWFb/PM/9Dw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_ae79cc20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae79cc20c0e9f55b3cb6993efc3fad68def359a303888c31c2f3625aa6449f29"
    family = "Mirai"
    file_name = "dlr.arm7"
    file_type = "elf"
    first_seen = "2026-08-14 01:38:03"
  condition:
    hash.sha256(0, filesize) == "ae79cc20c0e9f55b3cb6993efc3fad68def359a303888c31c2f3625aa6449f29"
}
```

### Sample 19: `2b5e0d3ddef95144`

| Field | Value |
|---|---|
| SHA-256 | `2b5e0d3ddef9514457ec6a9f4942874d442f780602beb7da12df40be999b8db0` |
| Family label | `Mirai` |
| File name | `pryznet.x86_64` |
| File type | `elf` |
| First seen | `2026-08-14 01:38:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cae57ce8bcf0728188eb24058cddc04` |
| SHA-1 | `4afa911bcceea2ff423b2f47fed331266de4536b` |
| SHA-256 | `2b5e0d3ddef9514457ec6a9f4942874d442f780602beb7da12df40be999b8db0` |
| SHA3-384 | `aa3405a4cfb0dc02d54cabe070f37f38a77218ddebc2527a8c7f816eea3dbc11019ffbf2d912f308ff34644710ade29c` |
| TLSH | `T1A8258E46B2B334FDC057C030879BD772A936F46945222D7B22C4DA352EA6E701B29F76` |
| TELFHASH | `t17b11acf04b2b62115659cbdc9addb35e152dc90a860bee37fd71407c60198ade42a88f` |
| SSDEEP | `24576:O9fXJ0O1+vU1OpFOwWUlYIuY7SFOjJrAA:O+c1Op/WUlYIl5jp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_2b5e0d3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b5e0d3ddef9514457ec6a9f4942874d442f780602beb7da12df40be999b8db0"
    family = "Mirai"
    file_name = "pryznet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-14 01:38:02"
  condition:
    hash.sha256(0, filesize) == "2b5e0d3ddef9514457ec6a9f4942874d442f780602beb7da12df40be999b8db0"
}
```

### Sample 20: `c06c9ee4e6020894`

| Field | Value |
|---|---|
| SHA-256 | `c06c9ee4e6020894bc9fc3abebb953b889d15d6041518483568fc8587d8e96a6` |
| Family label | `Mirai` |
| File name | `pryznet.mips` |
| File type | `elf` |
| First seen | `2026-08-14 01:32:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50fa7bbb7e2ed6166339d7e4a5514892` |
| SHA-1 | `0ffd2d25633845ea40f4f5743209b40787989127` |
| SHA-256 | `c06c9ee4e6020894bc9fc3abebb953b889d15d6041518483568fc8587d8e96a6` |
| SHA3-384 | `57ec9932f288d44b3f5879046b0e9319ddfa5f39cd49c0ff336cb4e7dd86215591afbeb099984c876389086405746b49` |
| TLSH | `T128F46C5377318FA4E350D27501E3CB655AA921A20BE291C6A37CC7207B51B6C6C6FFE8` |
| TELFHASH | `t1d111acf04b2b62115659cbdc9acdb35e152dc90a860bee37fd71407c60198ada42a88f` |
| SSDEEP | `12288:8maiKcT40q4ANJuSU/ZDOxymf1LXo4RRLeKH35L/I0bN6NXG48pasKdMPL+iMp92:fK34ANISU/gymfdnRRLFL/I6N6NXYymH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_c06c9ee4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c06c9ee4e6020894bc9fc3abebb953b889d15d6041518483568fc8587d8e96a6"
    family = "Mirai"
    file_name = "pryznet.mips"
    file_type = "elf"
    first_seen = "2026-08-14 01:32:21"
  condition:
    hash.sha256(0, filesize) == "c06c9ee4e6020894bc9fc3abebb953b889d15d6041518483568fc8587d8e96a6"
}
```

### Sample 21: `ed597d3121d614ed`

| Field | Value |
|---|---|
| SHA-256 | `ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90` |
| Family label | `WannaCry` |
| File name | `ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90` |
| File type | `exe` |
| First seen | `2026-08-14 01:15:59` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bb26757f04aab5e6553d333f695183c` |
| SHA-1 | `740efda71ac13dcf6a673c581c1be4289424e348` |
| SHA-256 | `ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90` |
| SHA3-384 | `2331bd4222294f2f531671223e28358ded7ca8ab4244d2e6f515ad536f716494091e58dbb3aeabda39ce2cb98c757285` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T172E53358723CD1BCE10619B444B3CD26E7733C9657FE5A0F8B50866A1E13B5BBBA0B12` |
| SSDEEP | `49152:jnpnQQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvxJM0H9PAMEcaE8:D9zqPoBhz1aRxcSUDk36SAEdhvxWa9Pu` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_021_ed597d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90"
    family = "WannaCry"
    file_name = "ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90"
    file_type = "exe"
    first_seen = "2026-08-14 01:15:59"
  condition:
    hash.sha256(0, filesize) == "ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90"
}
```

### Sample 22: `b7bfc4ecaa4b636a`

| Field | Value |
|---|---|
| SHA-256 | `b7bfc4ecaa4b636a2b25d9a367d5b26d3d0447217b690426aef5a60eba904cef` |
| Family label | `SalatStealer` |
| File name | `Loader.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:11:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08827f6de57f1be66b6ac55499d08162` |
| SHA-1 | `f7a8511ae9dfd5eb7f1772c254a870ea068cb4e9` |
| SHA-256 | `b7bfc4ecaa4b636a2b25d9a367d5b26d3d0447217b690426aef5a60eba904cef` |
| SHA3-384 | `1b135956416389754d0d92517cc2beedb3320714cf5021d4c1037b39c9cc97143143963aae7772128bcef7e094fa1f25` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A9C66B11FACB58F5E903583140ABB27F63315D048B38CB9BEB143B6AF87B6A11976705` |
| SSDEEP | `98304:ZG8t0u7IqLzMinki6Cebs4Ddn3mXRz4kG20CdEa:37t5k3Cebzn3YlkXa` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_022_b7bfc4ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7bfc4ecaa4b636a2b25d9a367d5b26d3d0447217b690426aef5a60eba904cef"
    family = "SalatStealer"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:11:18"
  condition:
    hash.sha256(0, filesize) == "b7bfc4ecaa4b636a2b25d9a367d5b26d3d0447217b690426aef5a60eba904cef"
}
```

### Sample 23: `a60079b552cbeee8`

| Field | Value |
|---|---|
| SHA-256 | `a60079b552cbeee8d961c10bd1a0406a2ee0f0a9b62cd34076c64cb73bed032a` |
| Family label | `SalatStealer` |
| File name | `Loader.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:09:30` |
| Reporter | `iamaachum` |
| Tags | `exe, RUS, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c10235ef064dd5b4215f8c5898e65d6b` |
| SHA-1 | `90bd7a9aeae68fb481f480ecb1cb0c1dd9b3c748` |
| SHA-256 | `a60079b552cbeee8d961c10bd1a0406a2ee0f0a9b62cd34076c64cb73bed032a` |
| SHA3-384 | `7f0f960e7bc24927c713926ca70f50f90f52849adb26c6c547d7a731b398067b5b92bc8b66cff88cfb0cf19640ae83f0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T19BF53330BE4D9E26E7E6B0F1E1A51762FACC651B3E7C00FF184A95E138775A081918B6` |
| SSDEEP | `98304:OszATnfgETEfMtrB2/I4i5xXxiuCrIc7YttRn4a:TzETKMt92QJxCrIc7Yt3n4` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_023_a60079b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a60079b552cbeee8d961c10bd1a0406a2ee0f0a9b62cd34076c64cb73bed032a"
    family = "SalatStealer"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:09:30"
  condition:
    hash.sha256(0, filesize) == "a60079b552cbeee8d961c10bd1a0406a2ee0f0a9b62cd34076c64cb73bed032a"
}
```

### Sample 24: `92f8f069c032422e`

| Field | Value |
|---|---|
| SHA-256 | `92f8f069c032422eb6048ce1a648bd140dab9d3cfca5c855e2b56e1ac6f1cc7b` |
| Family label | `unknown` |
| File name | `pulse_launchеr.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:08:53` |
| Reporter | `iamaachum` |
| Tags | `91-92-47-228, exe, RUS, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da4dc2203770bb12d6a2d5b38a5880a0` |
| SHA-1 | `66daed03974ace9055154d3e818bd5ef957ef651` |
| SHA-256 | `92f8f069c032422eb6048ce1a648bd140dab9d3cfca5c855e2b56e1ac6f1cc7b` |
| SHA3-384 | `98f664216e95d06ff1055d14f6cf13d9722d08560e05680f6cbdcd768aaa565dc27a64f26b4ad665d093046594475da6` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D5E533F9937653CCDB2AA2353FC3F9542305C189BE9149D86174B250EB394E6FEC6228` |
| SSDEEP | `98304:0xPvhSPnC38hCUL7Ig5Us7gYyE35CXbbVtY8K04:0Pv4PEeIg5xgYR3EXbZm8Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_92f8f069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f8f069c032422eb6048ce1a648bd140dab9d3cfca5c855e2b56e1ac6f1cc7b"
    family = "unknown"
    file_name = "pulse_launchеr.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:08:53"
  condition:
    hash.sha256(0, filesize) == "92f8f069c032422eb6048ce1a648bd140dab9d3cfca5c855e2b56e1ac6f1cc7b"
}
```

### Sample 25: `cddd5e55137fa3c0`

| Field | Value |
|---|---|
| SHA-256 | `cddd5e55137fa3c041b5c3471a2b4eb8754663bbbe59eb0a4061461498b6a507` |
| Family label | `SheetRAT` |
| File name | `DeluxeLaunchеr-1.2.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:07:59` |
| Reporter | `iamaachum` |
| Tags | `91-92-47-228, exe, RUS, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a5ca858cd51dea094ab07ee1f52f89b` |
| SHA-1 | `77bb95457bf275e9e8d9494aae1a05df451ba928` |
| SHA-256 | `cddd5e55137fa3c041b5c3471a2b4eb8754663bbbe59eb0a4061461498b6a507` |
| SHA3-384 | `cd487fc0c76824a7510e8f81371101a5c02389b04a1b69a5bed753f7ec721b361177fe09a6434bb75f7cab52b5df040d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B05533865BE1442CE32DF6FEF9F6C89583779398B7802B5F0311A9583B039A1664CF46` |
| SSDEEP | `24576:DTL7ebCNRus5rKJUjCrvBOAbOu8ZLKqFJg1m1hzV904v:DviyDWU+rvBO/3pLHmm1f90` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_025_cddd5e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cddd5e55137fa3c041b5c3471a2b4eb8754663bbbe59eb0a4061461498b6a507"
    family = "SheetRAT"
    file_name = "DeluxeLaunchеr-1.2.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:07:59"
  condition:
    hash.sha256(0, filesize) == "cddd5e55137fa3c041b5c3471a2b4eb8754663bbbe59eb0a4061461498b6a507"
}
```

### Sample 26: `fbe1a132a4dda975`

| Field | Value |
|---|---|
| SHA-256 | `fbe1a132a4dda975e349ba6c6d29e79bf247f0f18a1aeec6d80ce16e7e92ccbb` |
| Family label | `unknown` |
| File name | `start.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:06:41` |
| Reporter | `iamaachum` |
| Tags | `91-92-47-228, exe, RUS, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0322baf8c0e2e6567934f5d94bde7e84` |
| SHA-1 | `c25932c7836bc7f749879efe68153c7d8084b852` |
| SHA-256 | `fbe1a132a4dda975e349ba6c6d29e79bf247f0f18a1aeec6d80ce16e7e92ccbb` |
| SHA3-384 | `7a828c4fc140e00258b288fabc1b936b240edd2746aa8b9f4540a1b80b9d297fa705bc146773df0e75e06094ce5edb7c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T167C439247F948608E590197E459E1A11C7AA91F226327303371AFF611D8ADDEDF2C3EB` |
| SSDEEP | `6144:lJCVxPDfssFMU23mGk6F0Ew+NtTkyxRFVgylVza9GvPswRXNpBdYu7zbfv/Rd7LA:ls9fssq3mSO6tbYITRXNJ/v7LcmsqA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_fbe1a132
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbe1a132a4dda975e349ba6c6d29e79bf247f0f18a1aeec6d80ce16e7e92ccbb"
    family = "unknown"
    file_name = "start.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:06:41"
  condition:
    hash.sha256(0, filesize) == "fbe1a132a4dda975e349ba6c6d29e79bf247f0f18a1aeec6d80ce16e7e92ccbb"
}
```

### Sample 27: `71b04e2d36fef06e`

| Field | Value |
|---|---|
| SHA-256 | `71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a` |
| Family label | `unknown` |
| File name | `71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a.exe` |
| File type | `exe` |
| First seen | `2026-08-14 01:03:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbbe48bb05baf9092fa8742046fe6bee` |
| SHA-1 | `bf095f4445294f8450deb87b470801ea5718013b` |
| SHA-256 | `71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a` |
| SHA3-384 | `659ba25a57a1f239b68f1824873aa5b18837ae18a246f184ebae7fe99984fca51abee638b819764cb010246ed5e82ba5` |
| IMPHASH | `f09d582385da70dc67d54c7a1e8bee42` |
| TLSH | `T1BEF5331EBB3CB076DCDF2E3208929A6AA734F77405B5B08E209FE55F8693123527452D` |
| SSDEEP | `98304:hHHbrl9PBo3fP6oCp5E2TowN7BH0nU7JkQXiM2q:NlI3C5EMFBUn2kOV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_71b04e2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a"
    family = "unknown"
    file_name = "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:03:58"
  condition:
    hash.sha256(0, filesize) == "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a"
}
```

### Sample 28: `9d435f7547926c12`

| Field | Value |
|---|---|
| SHA-256 | `9d435f7547926c1259d52301f8d95a28b0e39c0275a47d3b0e42cc81ef72e252` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-08-14 00:54:40` |
| Reporter | `iamaachum` |
| Tags | `dll, sigmagranni1-fun` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96270f372db337520cc6538ef7426e96` |
| SHA-1 | `8d67357e0995c58e24bffa1d7d0642e90ac45314` |
| SHA-256 | `9d435f7547926c1259d52301f8d95a28b0e39c0275a47d3b0e42cc81ef72e252` |
| SHA3-384 | `b31f671342f920f8dbf4b86991573e267956d2874df9a8947d2d91c31b30a8cda0f1c4688e4a2a9d28ea572ac9fe417b` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T161A67B07BC917DA5C09DE23589A78257BBF07C68873223E31E51BAB82F72BD05975720` |
| SSDEEP | `98304:xeqj/VL0SuL6h4iYeEddZuKCIffowPB25Ly8e5gUsk8naB:xbL0SuL6+iYbdTrHfFPM5W8OfsN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_9d435f75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d435f7547926c1259d52301f8d95a28b0e39c0275a47d3b0e42cc81ef72e252"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-08-14 00:54:40"
  condition:
    hash.sha256(0, filesize) == "9d435f7547926c1259d52301f8d95a28b0e39c0275a47d3b0e42cc81ef72e252"
}
```

### Sample 29: `e62e0e3e37a669e8`

| Field | Value |
|---|---|
| SHA-256 | `e62e0e3e37a669e8716d4447754c6db580ca3e71316566c0e41da8bbb5a06ff4` |
| Family label | `unknown` |
| File name | `Setup64x.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:53:17` |
| Reporter | `iamaachum` |
| Tags | `exe, RevStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1550b386b7db4d548a7683cb5064fe2b` |
| SHA-1 | `5f2f73ecb220f34c11c14138d56739b3986b108c` |
| SHA-256 | `e62e0e3e37a669e8716d4447754c6db580ca3e71316566c0e41da8bbb5a06ff4` |
| SHA3-384 | `901de3070b98f62a6899ef4342ac099ba06b41c4d663024a81866c7c2c6b4aa8c0bbc0360e253f3b52a307a344c79a24` |
| IMPHASH | `d9d3f36aa6086dc2cbd4e40b5eb08a69` |
| TLSH | `T19F0723D37FE5D1D8C4824D34568A87DD21E1FA8A84EA5A1F32CB5C03B970EC74E099B6` |
| SSDEEP | `196608:M5s8E6lYCCmB3nZj6msXg7el7xCZXdticFLkkd4CLNcgAbLkx4uD77FarOREN4Ym:M5CCCmRZj2SeCFPicJ1dPqgJhx/RUw` |
| ICON-DHASH | `30f8ccc4cc69b254` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_e62e0e3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e62e0e3e37a669e8716d4447754c6db580ca3e71316566c0e41da8bbb5a06ff4"
    family = "unknown"
    file_name = "Setup64x.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:53:17"
  condition:
    hash.sha256(0, filesize) == "e62e0e3e37a669e8716d4447754c6db580ca3e71316566c0e41da8bbb5a06ff4"
}
```

### Sample 30: `141797edd588fb14`

| Field | Value |
|---|---|
| SHA-256 | `141797edd588fb14901fb516ae21db77b6a265700fe6e2430143de5534b85988` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-14 00:52:37` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2de6a8a1734dfd749aad7d2df10bffc5` |
| SHA-1 | `54dc5fdd89548ba6caacf163e767995a7dfda81a` |
| SHA-256 | `141797edd588fb14901fb516ae21db77b6a265700fe6e2430143de5534b85988` |
| SHA3-384 | `3cb163436a02a536c6d140707b992ee23e413142c55f4c724e7f027c28c8e697143fc72d5bb73ba639c7daea203a0189` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1D8E6334C2AC041FDE573547CC9E51652D43CF8B94BB1CACBA7F8436AAE672E08D39612` |
| SSDEEP | `393216:FaTDJT3nlWfJc26cLcRZLBr31XMCHWUjlcuI3/PGTAI:FaHJLAc2fLwL1XMb8SH/O7` |
| ICON-DHASH | `fcf8f8f8f8f8e0c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_141797ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "141797edd588fb14901fb516ae21db77b6a265700fe6e2430143de5534b85988"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 00:52:37"
  condition:
    hash.sha256(0, filesize) == "141797edd588fb14901fb516ae21db77b6a265700fe6e2430143de5534b85988"
}
```

### Sample 31: `5db0ed2a28e28d60`

| Field | Value |
|---|---|
| SHA-256 | `5db0ed2a28e28d60c056ea6bc7410d6d4d013847994096629b7bc0257f46ea0a` |
| Family label | `Mirai` |
| File name | `pito.x86` |
| File type | `elf` |
| First seen | `2026-08-14 00:39:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3c1644367f6acd8443a96c08dc9defa` |
| SHA-1 | `a4da677ea4a766a3dd9d75cc94c3110cc1529f89` |
| SHA-256 | `5db0ed2a28e28d60c056ea6bc7410d6d4d013847994096629b7bc0257f46ea0a` |
| SHA3-384 | `d212eb9aec63d6b5ed751512e85f703f357e149b04350530bf5edb473fea60eb8bcff53d249f4d90324cfe172fe14f82` |
| TLSH | `T12C634AC4EA83D8F1FD6706B51137E77B4772F43A002ACA4BDB64A932BC66901D61729C` |
| TELFHASH | `t10031fafb0dbd08e9b7f8a404c31e1f52296aa577156536b14473ddf422e7ac280b9c39` |
| SSDEEP | `1536:tpMHBUndfPoX7h9scHlKl2V52i3pn+CZjYyR4G6CAiLyX:tpISdfPotZHlfD2i3x+CZcE42c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_5db0ed2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db0ed2a28e28d60c056ea6bc7410d6d4d013847994096629b7bc0257f46ea0a"
    family = "Mirai"
    file_name = "pito.x86"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:05"
  condition:
    hash.sha256(0, filesize) == "5db0ed2a28e28d60c056ea6bc7410d6d4d013847994096629b7bc0257f46ea0a"
}
```

### Sample 32: `0512cc0f9d328662`

| Field | Value |
|---|---|
| SHA-256 | `0512cc0f9d328662bb5917ccb4bcd7ec1be9c343d621f49873dcef4400f4fd33` |
| Family label | `Mirai` |
| File name | `pito.arm7` |
| File type | `elf` |
| First seen | `2026-08-14 00:39:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9ed5a2583115f7af300a2c676f5f407` |
| SHA-1 | `4083b2d0b283f1c7caa1d7686bd7d29e5719954d` |
| SHA-256 | `0512cc0f9d328662bb5917ccb4bcd7ec1be9c343d621f49873dcef4400f4fd33` |
| SHA3-384 | `4965c0535ce337e68bca9a24222d47993de14d6989eef2840b79b920361a4ebb649b5575e1973e65efd9690b19fb06c4` |
| TLSH | `T1FAB3F946A9419F12D4D631FAFBAE414933536FB8E3FA7101DD206F6023869DB0EB7612` |
| TELFHASH | `t106e02012d75c11f863c6454c85ee771d6da4a5d3645d19812c9acc2fd393e50302c938` |
| SSDEEP | `3072:g0U1+xqVarix/u7p2va+FbR1TFCV7Pfj0g0wqmFaff:g0UTsrix/SAva+FbR18V7PR0ioff` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_0512cc0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0512cc0f9d328662bb5917ccb4bcd7ec1be9c343d621f49873dcef4400f4fd33"
    family = "Mirai"
    file_name = "pito.arm7"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:04"
  condition:
    hash.sha256(0, filesize) == "0512cc0f9d328662bb5917ccb4bcd7ec1be9c343d621f49873dcef4400f4fd33"
}
```

### Sample 33: `548c8cb9348494a5`

| Field | Value |
|---|---|
| SHA-256 | `548c8cb9348494a5d07f978a7e37ecbe3976f657866a7467006ae0bfa99ec420` |
| Family label | `Mirai` |
| File name | `pito.arm5` |
| File type | `elf` |
| First seen | `2026-08-14 00:39:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60673886f744f83d3c7f77b6adc121c5` |
| SHA-1 | `f951f159fd0e6e92fd56ef7b0f575b9abcb8fbee` |
| SHA-256 | `548c8cb9348494a5d07f978a7e37ecbe3976f657866a7467006ae0bfa99ec420` |
| SHA3-384 | `9190f6494189740fe617f94a7fa12099627c70fea4c91a0cd565de75fdd151b855f759436a4f438933d0753fa06988ee` |
| TLSH | `T11C732991B9829613C5D0127BFF6E428D772A13ACE3EE72039E256F20378785B0E77651` |
| TELFHASH | `t12cf05ca6dd0c0ddc31d1125ce9b6333bd1757ca327793656476ad57d8812dd23435831` |
| SSDEEP | `1536:NYgwmaGQNN55GvWzqIQWyyooVSbmASAQ8dMdwxSFFeDK:agwQXWzqSoo0bmAxs3p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_548c8cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548c8cb9348494a5d07f978a7e37ecbe3976f657866a7467006ae0bfa99ec420"
    family = "Mirai"
    file_name = "pito.arm5"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:03"
  condition:
    hash.sha256(0, filesize) == "548c8cb9348494a5d07f978a7e37ecbe3976f657866a7467006ae0bfa99ec420"
}
```

### Sample 34: `f0aa4e722f27d724`

| Field | Value |
|---|---|
| SHA-256 | `f0aa4e722f27d724c26411764680da2f6b61c17d6dc726dc0b8a700e9f620dcd` |
| Family label | `Mirai` |
| File name | `pito.i486` |
| File type | `elf` |
| First seen | `2026-08-14 00:39:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a3fe90abcf1f61d71648af1cf1440ef` |
| SHA-1 | `702a79522e21e132fe7ed1ee6ddc3a87b0e5fb62` |
| SHA-256 | `f0aa4e722f27d724c26411764680da2f6b61c17d6dc726dc0b8a700e9f620dcd` |
| SHA3-384 | `ac697e1e7b0ce85078f647c8d27fe789ef4325fa6ddf2a653af0f5b995826cc23649288e014c5a556cdf43e68282c13d` |
| TLSH | `T13D834B44F383F5F0E94605B0015BF37E9A35AE262024DD6BDBD4FA73AD31A42E15A21C` |
| TELFHASH | `t12d41f5bb1eea0cd877d01501e31f63611e6ef43b19507aa142b25c9427ebfc292a9c3d` |
| SSDEEP | `1536:TafHOVPOtn2N5Jiddh3NkAO9Ub310Ix7x/oIu9sDmHsrI:WwOd25ShdV6QutsKk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_f0aa4e72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0aa4e722f27d724c26411764680da2f6b61c17d6dc726dc0b8a700e9f620dcd"
    family = "Mirai"
    file_name = "pito.i486"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:01"
  condition:
    hash.sha256(0, filesize) == "f0aa4e722f27d724c26411764680da2f6b61c17d6dc726dc0b8a700e9f620dcd"
}
```

### Sample 35: `c5c773ebcc22bb25`

| Field | Value |
|---|---|
| SHA-256 | `c5c773ebcc22bb2557d39ac0c7a841f5029987b0b465738c3b3b047b576060f7` |
| Family label | `Mirai` |
| File name | `pito.m68k` |
| File type | `elf` |
| First seen | `2026-08-14 00:39:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb36891698fe2b39c01880d38d0cc2fb` |
| SHA-1 | `2e644b2b3d1f41cfdd7d3b1999213bec5190f3ff` |
| SHA-256 | `c5c773ebcc22bb2557d39ac0c7a841f5029987b0b465738c3b3b047b576060f7` |
| SHA3-384 | `519da617b20fef9de57812853bd80ac7426087e9e3a5f58e370a7e0ad41d3af3a03b7064e64af2553840074127a6ed02` |
| TLSH | `T112934BD7F800DDBEF80EDB7B44570909B671B76106830F366357B967ED321A80A66E82` |
| SSDEEP | `1536:XIrBSmOvjZuSxwjgMLE1Mwc8Ft4p/L0G/fVDl3YnPBds90v2UY1Q:XIrMrZxIgMw1MwR46GvoU0v2/1Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_c5c773eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5c773ebcc22bb2557d39ac0c7a841f5029987b0b465738c3b3b047b576060f7"
    family = "Mirai"
    file_name = "pito.m68k"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:00"
  condition:
    hash.sha256(0, filesize) == "c5c773ebcc22bb2557d39ac0c7a841f5029987b0b465738c3b3b047b576060f7"
}
```

### Sample 36: `4a604b39bfe0e8d3`

| Field | Value |
|---|---|
| SHA-256 | `4a604b39bfe0e8d39f57b35cbe8c208cd70c6d5d8c55381121158932593b7870` |
| Family label | `Mirai` |
| File name | `pito.mipsel` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b66fd4d0dbaf140c9f1aef62d86c09e` |
| SHA-1 | `d975423e8733feb8893a525a3dca1e1ee50488fe` |
| SHA-256 | `4a604b39bfe0e8d39f57b35cbe8c208cd70c6d5d8c55381121158932593b7870` |
| SHA3-384 | `da4fce575a35a0915d8c8cab14bce88cb5f2bc672e1cd0c1c51873ace9b5fa18ff9e9b7c4564834b34ae1732c3d3b3b5` |
| TLSH | `T1F3B3F706AB600EFBDCAFDD374AE9170635CC651B22B96B363534D928F54B14B0AE3C64` |
| SSDEEP | `1536:1AvUsMhoaFoGYzkfNZ/iu3OAQSe2InSOnEncQZPK48OZm/jFKGXeHkV1m:SvibFoGFfPVeNnLEncQ8n5V1m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_4a604b39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a604b39bfe0e8d39f57b35cbe8c208cd70c6d5d8c55381121158932593b7870"
    family = "Mirai"
    file_name = "pito.mipsel"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:59"
  condition:
    hash.sha256(0, filesize) == "4a604b39bfe0e8d39f57b35cbe8c208cd70c6d5d8c55381121158932593b7870"
}
```

### Sample 37: `b1d28add138e8782`

| Field | Value |
|---|---|
| SHA-256 | `b1d28add138e87822668e24e78f67dab743c06d87fe4a9754f28e18ffc0031e1` |
| Family label | `Mirai` |
| File name | `pito.ppc` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b8edfca2797be6aa6a56f48d80bf29e` |
| SHA-1 | `9759e4932eea390a941ccd3c239db99d0f6335a1` |
| SHA-256 | `b1d28add138e87822668e24e78f67dab743c06d87fe4a9754f28e18ffc0031e1` |
| SHA3-384 | `3e7b59b4008a5b683362051f0a3c56c8f193b24450ed8b9a1887328bd7700063ba2d65764d1680a680ecfb6aabbd51ae` |
| TLSH | `T117834C42731C0E47C17759B42A3F67E193EE6AA021F4F688355F978A9271E321186FCE` |
| SSDEEP | `1536:qLAbwJVJuUcov4OxcQa7Ee8SG5qSBUmJP9n2c0DGR4ohkd:qxSodrj4hmSczGd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_b1d28add
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1d28add138e87822668e24e78f67dab743c06d87fe4a9754f28e18ffc0031e1"
    family = "Mirai"
    file_name = "pito.ppc"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:58"
  condition:
    hash.sha256(0, filesize) == "b1d28add138e87822668e24e78f67dab743c06d87fe4a9754f28e18ffc0031e1"
}
```

### Sample 38: `42320cd1431f7301`

| Field | Value |
|---|---|
| SHA-256 | `42320cd1431f7301e6b00c0d30a3caa43622b734b7f5c3787222f76ad05b3c84` |
| Family label | `Mirai` |
| File name | `pito.sparc` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18315824243862519c139bbcfdd018d5` |
| SHA-1 | `79acea6e665e9e1cec30c9af6ae8e54e5b1570ad` |
| SHA-256 | `42320cd1431f7301e6b00c0d30a3caa43622b734b7f5c3787222f76ad05b3c84` |
| SHA3-384 | `4b81efbec442ba1eaf1cb1c0f3fe2a056a959f53836bddc7a5c4d246bb938d32a21118f5c1558f924acd1b8da80b5aff` |
| TLSH | `T115833A3279750D2BC4C4A87A62F70725F2F3479A24ECCA1E3D610E8DBF64640265B6F9` |
| SSDEEP | `1536:BUS/TVfxweU6r/TcVd44iBRitEmNWq5MfEQxFttLE:HNvOd08WmNlnEE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_42320cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42320cd1431f7301e6b00c0d30a3caa43622b734b7f5c3787222f76ad05b3c84"
    family = "Mirai"
    file_name = "pito.sparc"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:57"
  condition:
    hash.sha256(0, filesize) == "42320cd1431f7301e6b00c0d30a3caa43622b734b7f5c3787222f76ad05b3c84"
}
```

### Sample 39: `a129b617f2909c57`

| Field | Value |
|---|---|
| SHA-256 | `a129b617f2909c5727aff206e4c10e6fba8a3243441ff9d5bcb45ff9712b911e` |
| Family label | `Mirai` |
| File name | `pito.sh4` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2515a20bd6b3f82863b941529b2f2537` |
| SHA-1 | `d7fcbf2d64bd8e93fbb2c460546c61f423edad3d` |
| SHA-256 | `a129b617f2909c5727aff206e4c10e6fba8a3243441ff9d5bcb45ff9712b911e` |
| SHA3-384 | `5373feaf3ef4e4da69fc7f2fc4ead37f993c2d57cd4fb12147da864db36098febe16f5ddef3f7df34d52c95a6239037e` |
| TLSH | `T1E4638E73E92AAD58D1948970F4B58FB82F63A5108A5B1FFA0A95C175D043EECF2053F8` |
| SSDEEP | `1536:pWwtuOBFcrSefg/jhiPDvLK32ZU73MXFnDCFanlMS7:pWaB6rSq0gu3vAXFnDVnKW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_a129b617
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a129b617f2909c5727aff206e4c10e6fba8a3243441ff9d5bcb45ff9712b911e"
    family = "Mirai"
    file_name = "pito.sh4"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:55"
  condition:
    hash.sha256(0, filesize) == "a129b617f2909c5727aff206e4c10e6fba8a3243441ff9d5bcb45ff9712b911e"
}
```

### Sample 40: `543af251df940d4a`

| Field | Value |
|---|---|
| SHA-256 | `543af251df940d4a853172e954152839eee260ec15d5164c88ffed40aa5c2c63` |
| Family label | `Mirai` |
| File name | `pito.arm6` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2aa4eaf6e31177ea27d5f531914ea07d` |
| SHA-1 | `23d0482a530872f0354741609c952fb35b6288d9` |
| SHA-256 | `543af251df940d4a853172e954152839eee260ec15d5164c88ffed40aa5c2c63` |
| SHA3-384 | `43f90714ebc4bbbe104273409749dbae0fabfa87616d2210f39cbc294830fd464468485b422c3597691e458d1ee0fd15` |
| TLSH | `T148932996B8824B11C5C512BFFE2E118E3313177CE3DE73129D246F24678A96B0E7B916` |
| TELFHASH | `t165e026c38b5819e8cbd2846a9c393309785634e17a293d976ddacfcfc6534903511638` |
| SSDEEP | `1536:NjknpsG0wT6Fepl3EVcBRvXKPGKYC/1VBa5coanatQRiyOYf55iOR5oot7WxM:NPyTrpqVcBxKPGK31VBa5SOYf5UOR5oX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_543af251
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "543af251df940d4a853172e954152839eee260ec15d5164c88ffed40aa5c2c63"
    family = "Mirai"
    file_name = "pito.arm6"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:54"
  condition:
    hash.sha256(0, filesize) == "543af251df940d4a853172e954152839eee260ec15d5164c88ffed40aa5c2c63"
}
```

### Sample 41: `7ac68d8967ad6c5e`

| Field | Value |
|---|---|
| SHA-256 | `7ac68d8967ad6c5ed092e2d3480187f3c29a36fd65d8b71ba6a5768809824a8b` |
| Family label | `Mirai` |
| File name | `pito.mips` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9b73f03f37dc1f1c94b4608340866ae` |
| SHA-1 | `b3c78171fd6c79fe1730c9ed77a76ed3419f7133` |
| SHA-256 | `7ac68d8967ad6c5ed092e2d3480187f3c29a36fd65d8b71ba6a5768809824a8b` |
| SHA3-384 | `d428538eaa649c29652aebc910adbaa4893e66315a9457cb713187a6271ef1e7f408f3e859794726f0a86030f9d0e4cd` |
| TLSH | `T186B3D95E6E628FBDF768C33447B78E21A39C33C626E1D685D16CD6005E6028E541FFA8` |
| TELFHASH | `t19721812c4a7423d067352c9d199dff7bd6a130ef66215c374e1168aaab7dc825f20c0c` |
| SSDEEP | `1536:kCYw1r/F9jP18HosNtlXwbjrNcIqkpnNyD80IXejtFXLRzw:kQ1r/FBP1871wbjOIqkC1IsLRzw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_7ac68d89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac68d8967ad6c5ed092e2d3480187f3c29a36fd65d8b71ba6a5768809824a8b"
    family = "Mirai"
    file_name = "pito.mips"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:53"
  condition:
    hash.sha256(0, filesize) == "7ac68d8967ad6c5ed092e2d3480187f3c29a36fd65d8b71ba6a5768809824a8b"
}
```

### Sample 42: `6285498d05dd12df`

| Field | Value |
|---|---|
| SHA-256 | `6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2` |
| Family label | `Mirai` |
| File name | `pito.arm4` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15d03c3d0f47e05ff8f6a204afb2ae5e` |
| SHA-1 | `24796465a581b2cbfd397c544e9024ca5c942dc0` |
| SHA-256 | `6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2` |
| SHA3-384 | `cb38c3bf14f1cc480594dd69c57a82ec1ea7b2d270bdec7a30bec03bf00ffebf0892631f72718beeec0b99ce260a1dda` |
| TLSH | `T160832A81B8825613C6C012BBFB6E428D772717A8E3EF72079D266F21378785B0E77651` |
| TELFHASH | `t18cf05cdbcc7c3cec33ca0549512ea310295575b0623439562f6e898f0013ce7b032536` |
| SSDEEP | `1536:hKhM5ixXmeyb4fl4k34V+PVvP5sDcggQrvHbhFRQi:hKhN9flVs+PtPWDcghP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_6285498d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2"
    family = "Mirai"
    file_name = "pito.arm4"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:51"
  condition:
    hash.sha256(0, filesize) == "6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2"
}
```

### Sample 43: `4258b8449e1da87a`

| Field | Value |
|---|---|
| SHA-256 | `4258b8449e1da87af25f94640a86e9c982c00c33cd82e1d806582c49790e7760` |
| Family label | `Mirai` |
| File name | `pito.ppc440` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c6c8148e4ec39084a1e04e49e18bb0e` |
| SHA-1 | `960ff157832e707e97bd629d447377934b5a32ba` |
| SHA-256 | `4258b8449e1da87af25f94640a86e9c982c00c33cd82e1d806582c49790e7760` |
| SHA3-384 | `9e9739ec7aa875f9ffdbf160685c7fb478bd255c7153b6ef7030ee0401df6dac52086665abb4b3c3ef2696bcea6c8867` |
| TLSH | `T16C835D43730C0A47D5670DB4263B57F183EA6AA121F8F689350E9F4A9671E328197FCE` |
| SSDEEP | `1536:5LVI2K06TNIYH4m69kHPlWHwxkCervFUqo9c9qdJc/7nrhtGfGPK:5F8qYYDkdDbeX9qdJorMCK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_4258b844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4258b8449e1da87af25f94640a86e9c982c00c33cd82e1d806582c49790e7760"
    family = "Mirai"
    file_name = "pito.ppc440"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:50"
  condition:
    hash.sha256(0, filesize) == "4258b8449e1da87af25f94640a86e9c982c00c33cd82e1d806582c49790e7760"
}
```

### Sample 44: `979ecedbf94eca29`

| Field | Value |
|---|---|
| SHA-256 | `979ecedbf94eca29beecfedc5fccfd78d7ba469e23ce36e15fafa29e96cfdcc5` |
| Family label | `unknown` |
| File name | `dp.sh` |
| File type | `sh` |
| First seen | `2026-08-14 00:38:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `216523d2c90397ba2a2035a868353457` |
| SHA-1 | `43db05de3e8f348dc429438fe10ea7458bae3c4b` |
| SHA-256 | `979ecedbf94eca29beecfedc5fccfd78d7ba469e23ce36e15fafa29e96cfdcc5` |
| SHA3-384 | `b5efff1eb4f46fe439e78c89fe9b7a32d0d86a144fcc1a65cb83807c486d03a462bc0ea38dbfee8d7cc2e89da7431341` |
| TLSH | `T1FB1132CD60695237C1FC9E1035AA8AC8D714939AD0FCC718F8DCBF21D9D694930D6E8A` |
| SSDEEP | `24:OGcGoGmMWGwlGgG5YGoGjYnHGjPNPWGjP0PR1GUlGo1G4G+7G/:Oj3DMWrP4YXn6NW6+R1tlf7LQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_979ecedb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "979ecedbf94eca29beecfedc5fccfd78d7ba469e23ce36e15fafa29e96cfdcc5"
    family = "unknown"
    file_name = "dp.sh"
    file_type = "sh"
    first_seen = "2026-08-14 00:38:49"
  condition:
    hash.sha256(0, filesize) == "979ecedbf94eca29beecfedc5fccfd78d7ba469e23ce36e15fafa29e96cfdcc5"
}
```

### Sample 45: `f49d4278471bf515`

| Field | Value |
|---|---|
| SHA-256 | `f49d4278471bf51500ebcf425c6289769377dc061d87bd62903fd4ff8030926d` |
| Family label | `Mirai` |
| File name | `pito.x64` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `679d60d8055316b7d52d67343305a632` |
| SHA-1 | `120af1b234713e0725b0dfcbd71531375c20da83` |
| SHA-256 | `f49d4278471bf51500ebcf425c6289769377dc061d87bd62903fd4ff8030926d` |
| SHA3-384 | `b8b4244e90e26fe6d3d9697544a9ecaf743278d6a342fab3f64c6d9c1b49cbd23c58daeb6af433ef2497129eecb4c6f9` |
| TLSH | `T19C735B03B5C190FCC589C178176EB23AD973747E0239B2AA63D0FB277E89E215E1E600` |
| TELFHASH | `t1833137753da619a0a0fbf6767353e1a408301b6511e170e2e877a8e7de613c61c7a437` |
| SSDEEP | `1536:hVWVomSMzMFZqu9bgwZYKXUSOsREkrVbb00+6RgB1k12B3+bRQjyd3Gck39:uVjJzMSIRZzXcsREGbb00+31k12B3SQn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_f49d4278
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f49d4278471bf51500ebcf425c6289769377dc061d87bd62903fd4ff8030926d"
    family = "Mirai"
    file_name = "pito.x64"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:48"
  condition:
    hash.sha256(0, filesize) == "f49d4278471bf51500ebcf425c6289769377dc061d87bd62903fd4ff8030926d"
}
```

### Sample 46: `38e726afc0cefc86`

| Field | Value |
|---|---|
| SHA-256 | `38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725` |
| Family label | `Mirai` |
| File name | `pito.i686` |
| File type | `elf` |
| First seen | `2026-08-14 00:38:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7f1dc09f6a672aca0c9b4e7248a1bde` |
| SHA-1 | `c4cfca6488d0a914a6a549ce53331ee4160b4484` |
| SHA-256 | `38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725` |
| SHA3-384 | `fef20594c419dc94a4c894463aee215e39a6a64e7ba07cb4236b7a641386b4715fbe103471a6ed7df4538208b482dd89` |
| TLSH | `T1F2733A81F68BC4F5E85748744037F33F8B32EA298071C66EDF69AE36CA63642911725C` |
| TELFHASH | `t12f31dafa1a7e4dedbbc4a444c30d9fd22d5ed77b192072a245224821239fd81907ec39` |
| SSDEEP | `1536:beRiDIILdIijxxSR5QbRLqQAeWtaMueVzCShiJaGaCHTx+sS:beRiMILCi+R5QbRLqQCEM/VuOiJXa2/S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_38e726af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725"
    family = "Mirai"
    file_name = "pito.i686"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:46"
  condition:
    hash.sha256(0, filesize) == "38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725"
}
```

### Sample 47: `b5a490d6e02e7f69`

| Field | Value |
|---|---|
| SHA-256 | `b5a490d6e02e7f69573ad2e815ba4d5512600e01d3c2b3654ea8b42defcc1d89` |
| Family label | `unknown` |
| File name | `Extracted_Certificates.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:30:43` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10920d370c0ceefc37f60a8bedd84f52` |
| SHA-1 | `057a55fe9fc6a14cae136face689521787b2780d` |
| SHA-256 | `b5a490d6e02e7f69573ad2e815ba4d5512600e01d3c2b3654ea8b42defcc1d89` |
| SHA3-384 | `bae202fd8b3fe694d171af7786a4783f9f2f2f8fc6333da99304ed1ed3548020dd8f578743854008cb6a8ede8b72daeb` |
| IMPHASH | `c5afd6d556425273741b60c59dffda7f` |
| TLSH | `T1DAF7335E39181AE3C96D0EB78700A04E37B9D0A847FAFD5BAA125737188A7744CE4D3D` |
| SSDEEP | `1572864:PuZUj4fYrGulsxS2h70Dx+QN+KsPLen6DEsYzwBkN:WmqQsxS2renbN` |
| ICON-DHASH | `6969794464647c5c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_b5a490d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5a490d6e02e7f69573ad2e815ba4d5512600e01d3c2b3654ea8b42defcc1d89"
    family = "unknown"
    file_name = "Extracted_Certificates.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:30:43"
  condition:
    hash.sha256(0, filesize) == "b5a490d6e02e7f69573ad2e815ba4d5512600e01d3c2b3654ea8b42defcc1d89"
}
```

### Sample 48: `96641c2e9be0fbb4`

| Field | Value |
|---|---|
| SHA-256 | `96641c2e9be0fbb4b59ef0e18755d795570b0125f9b0ea45d321d9d3380b32a8` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:25:28` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2cbd2f29db7000f15c1ace65036f9ec` |
| SHA-1 | `27a8cd3dcce1e94b6d5ba20b1d7ef35317117d2d` |
| SHA-256 | `96641c2e9be0fbb4b59ef0e18755d795570b0125f9b0ea45d321d9d3380b32a8` |
| SHA3-384 | `5d00eb7060e06bd904366bb8e2ae17fd3274a9ed3a6857c2545302e3c10487d37c98fef515d058a7184291048e0ea44b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D2C55A077C9044F9C09A673685B79A52BB35B84C8B3633DB2EE0A6782F763D14D79B04` |
| SSDEEP | `49152:8t5kTGIjdKLOgDAyp7sDuwngHS5DOHLbhSDI5F6:8Dk/q5ZX6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_96641c2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96641c2e9be0fbb4b59ef0e18755d795570b0125f9b0ea45d321d9d3380b32a8"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:25:28"
  condition:
    hash.sha256(0, filesize) == "96641c2e9be0fbb4b59ef0e18755d795570b0125f9b0ea45d321d9d3380b32a8"
}
```

### Sample 49: `a23626d45696bfba`

| Field | Value |
|---|---|
| SHA-256 | `a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a` |
| Family label | `Vidar` |
| File name | `a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a.bin` |
| File type | `exe` |
| First seen | `2026-08-14 00:22:16` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98798668351abdf6529a63b4c79add8a` |
| SHA-1 | `c3a84313319da494b27e56510f8968e283549be1` |
| SHA-256 | `a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a` |
| SHA3-384 | `cac4efca72a90c0e131c4aa4004375ee9d0ac41c773ec85123548a39049333789641247d68b0ac07bd0edd3e74d2fe03` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1EB268C13ADA548F9C0A6E335C8B7514ABA30B84C5B3427D32E90EE782FB23D15E36755` |
| SSDEEP | `49152:qEf7sjiJw1RwBr97A4AYg8a1wkiugrzJDku2nD4hpTDOlT4LVUqchxgHN47SoSqO:qUP528afMob4XiqLVUqchxgHhUC` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_049_a23626d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a"
    family = "Vidar"
    file_name = "a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a.bin"
    file_type = "exe"
    first_seen = "2026-08-14 00:22:16"
  condition:
    hash.sha256(0, filesize) == "a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a"
}
```

### Sample 50: `e0f43e3074c9f695`

| Field | Value |
|---|---|
| SHA-256 | `e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d` |
| Family label | `unknown` |
| File name | `e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d.bin` |
| File type | `zip` |
| First seen | `2026-08-14 00:09:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80fcd518e84ae7b9334785e62569b3c4` |
| SHA-1 | `25343eb0395c83068602151b2bf1fc8345655773` |
| SHA-256 | `e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d` |
| SHA3-384 | `57e0e31278e900348348d4b43e585038c952379bec2efb984ed7107518c69d5630dff7855accc328ea347bb56bc30752` |
| TLSH | `T1B60633E4E233EA83EE98007EB3766D622D5C72BE0818A306367395D44C49735159F9BF` |
| SSDEEP | `49152:llezEKiv/eyQVQi2uMaU5pF7yzBfD6WMxTBM8UfYC2H2dSHhigix:llS67WQi26cp5yzBL6TxTBLUAlavB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_e0f43e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d"
    family = "unknown"
    file_name = "e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d.bin"
    file_type = "zip"
    first_seen = "2026-08-14 00:09:34"
  condition:
    hash.sha256(0, filesize) == "e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d"
}
```

### Sample 51: `76083829cbb65dd4`

| Field | Value |
|---|---|
| SHA-256 | `76083829cbb65dd4739125300a772c8de357f2339daf98a8d5c2efa83aad7733` |
| Family label | `unknown` |
| File name | `recuva_professional__technician_(2026)_full_español_[mega].7z` |
| File type | `7z` |
| First seen | `2026-08-14 00:07:54` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-8426, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cda93a5f40c83f4663cb70c69a238afd` |
| SHA-1 | `89c86b5124b5f43146f8bbae3836cf41fce9f914` |
| SHA-256 | `76083829cbb65dd4739125300a772c8de357f2339daf98a8d5c2efa83aad7733` |
| SHA3-384 | `71c0c9b53416884e185cf3703dc90a2d9d8d598191e487c8d72c6f9c8e3895ecd61a9e11dd23a5dac7fadc2ef64fc483` |
| TLSH | `T10A063388444F45F1ADAF00DBCD9CBBF52CB359483A6A65E45689300F02D06F1DBAAF63` |
| SSDEEP | `98304:hGuvjNR1RumUkKSpbutBT1TnLFrW2LnpuTp0:hGuKm7KSpbutR1LLFr6Tp0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_76083829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76083829cbb65dd4739125300a772c8de357f2339daf98a8d5c2efa83aad7733"
    family = "unknown"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-08-14 00:07:54"
  condition:
    hash.sha256(0, filesize) == "76083829cbb65dd4739125300a772c8de357f2339daf98a8d5c2efa83aad7733"
}
```

### Sample 52: `5fd66b453a25310b`

| Field | Value |
|---|---|
| SHA-256 | `5fd66b453a25310b0dad14c68e8bfa27378c850357924f44a1097a199f035a81` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full.7z` |
| File type | `7z` |
| First seen | `2026-08-14 00:06:47` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-3728, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00ae1f94614efb0f7a71abb71479e4ad` |
| SHA-1 | `af536b2e6e363c318ed20c2c7d6224bc30c5c8e0` |
| SHA-256 | `5fd66b453a25310b0dad14c68e8bfa27378c850357924f44a1097a199f035a81` |
| SHA3-384 | `bcf773195f64757298be4ce3896cfbbb9bbbb6d417a72b988f053b44f33e0f46acafd871fb39ecd263ebe93705b435cb` |
| TLSH | `T1890733304E70EF4A994BC226534D97B2B6B035DA1D2D37F2081935BB642C5B986BFE43` |
| SSDEEP | `393216:amXm/M/8S3AIOHmu8vdVd0+E/lFOKspc9TRIskvspsF/lp:XXa88IAjmu8RNE/lFOKsp2TeskvsE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_5fd66b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fd66b453a25310b0dad14c68e8bfa27378c850357924f44a1097a199f035a81"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-08-14 00:06:47"
  condition:
    hash.sha256(0, filesize) == "5fd66b453a25310b0dad14c68e8bfa27378c850357924f44a1097a199f035a81"
}
```

### Sample 53: `0e1ce7d8e2c69cf2`

| Field | Value |
|---|---|
| SHA-256 | `0e1ce7d8e2c69cf2e00f93eb20b8dc0fb02c198214a4df44e61865a47e116153` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:04:56` |
| Reporter | `iamaachum` |
| Tags | `ChromElevator, exe, signed, up4pc-com, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38599a2684d31372e26bfc83deb1e4ef` |
| SHA-1 | `674772caa0b40edf3b9680f831ac60885183492a` |
| SHA-256 | `0e1ce7d8e2c69cf2e00f93eb20b8dc0fb02c198214a4df44e61865a47e116153` |
| SHA3-384 | `25b213b09e3f17bd181684cc123c32b573144ff4de3efc62e5c6038d0d29a92c7a00c802d404103403bb1da19d8b80a5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F1B633302DFB501EB273FE7A5AD879DAEA9FF223360654AD202113478A13941DED153E` |
| SSDEEP | `196608:efa3JFLuMe+OZZYwygaoRbyE+LQatF4Z0FQKfY/MwqzJZIFBleJmkfXv:h3/i2OZ1PaotyE+LVtFu0FQ02d0JZYTG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_0e1ce7d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e1ce7d8e2c69cf2e00f93eb20b8dc0fb02c198214a4df44e61865a47e116153"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:04:56"
  condition:
    hash.sha256(0, filesize) == "0e1ce7d8e2c69cf2e00f93eb20b8dc0fb02c198214a4df44e61865a47e116153"
}
```

### Sample 54: `00d3f42dc0c6527d`

| Field | Value |
|---|---|
| SHA-256 | `00d3f42dc0c6527d375f8b5430915ca27f0da7b9608e446d3e5f6c17082577a5` |
| Family label | `LummaStealer` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:03:48` |
| Reporter | `iamaachum` |
| Tags | `exe, LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8489bdc975f60b73d4ab815c37b2ff5b` |
| SHA-1 | `c2d00d27026118c56494bd3b2e580e9dbc1e9fff` |
| SHA-256 | `00d3f42dc0c6527d375f8b5430915ca27f0da7b9608e446d3e5f6c17082577a5` |
| SHA3-384 | `4da1243b27e41e236555796595e45b30a73178bf7def30032ff95c83fcb87a9067e1fb9a3600601471049f5d15a9c4b3` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T10FC55B21EEEA84F9DA031A3560A7A26F13367F045F39DFC7DF0469B4A7233A61463605` |
| SSDEEP | `49152:2CzQQmAoIL3a/byaaNuXEGlcXexT/VE8eiZhC/Eqq:RzQbAoIra/byagMWYqcP` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_054_00d3f42d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00d3f42dc0c6527d375f8b5430915ca27f0da7b9608e446d3e5f6c17082577a5"
    family = "LummaStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:03:48"
  condition:
    hash.sha256(0, filesize) == "00d3f42dc0c6527d375f8b5430915ca27f0da7b9608e446d3e5f6c17082577a5"
}
```

### Sample 55: `e61dd367859cf5e4`

| Field | Value |
|---|---|
| SHA-256 | `e61dd367859cf5e495a86ecaa7fa084ae84c1e38a049a68e03813e657651b192` |
| Family label | `GhostPulse` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:03:17` |
| Reporter | `iamaachum` |
| Tags | `exe, GhostPulse, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `473185c29ec075e7b84b255d1f742090` |
| SHA-1 | `d1b4e43e15b30f15d4da93f25b61f20e79d0bcee` |
| SHA-256 | `e61dd367859cf5e495a86ecaa7fa084ae84c1e38a049a68e03813e657651b192` |
| SHA3-384 | `3640901fbbf29ee3eaebcc9ba536f2a577b066bcc58ceb4272e9ff86c66ed2d61618c087caefc5aa0db8d170d8488f01` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T17B963381F380F1F5CD94847A5D12EB9AACB2F3690B906E4356C66E923EC7350570B2DB` |
| SSDEEP | `196608:+p3+ZwV3jDOk9Azh279Z1Sn8bX3htFhgVDrSSw62PxJldbhGTWq:+p3+WV3OXO1SnE30cH7T4yq` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `GhostPulse` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GhostPulse_055_e61dd367
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e61dd367859cf5e495a86ecaa7fa084ae84c1e38a049a68e03813e657651b192"
    family = "GhostPulse"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:03:17"
  condition:
    hash.sha256(0, filesize) == "e61dd367859cf5e495a86ecaa7fa084ae84c1e38a049a68e03813e657651b192"
}
```

### Sample 56: `e28c19d9dab46ec3`

| Field | Value |
|---|---|
| SHA-256 | `e28c19d9dab46ec3e8a44ad67b5aa5c0727299086aedc25df24b96738c42c58b` |
| Family label | `unknown` |
| File name | `LauncherV31182x64.exe` |
| File type | `exe` |
| First seen | `2026-08-14 00:01:51` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af1aece27721f73910b410db827c3fd5` |
| SHA-1 | `c2231044e9b8ddb191060edca0655cb40bf675c1` |
| SHA-256 | `e28c19d9dab46ec3e8a44ad67b5aa5c0727299086aedc25df24b96738c42c58b` |
| SHA3-384 | `efbba74308db83c2bfb374a16de53db57dc6bf81b4bcba054a7aeee031c32a11032d1b0b1bd75dd4c880c7705481cc32` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T1291733F964B5AF16D4E6DBBE67839095CF7CFC1145434EEA59F0B8AA4A14880303C4BD` |
| SSDEEP | `393216:0o1h1t7f/xtK1uULNsYmCekH/J3obKZD+zbZgNYHU022AUz:0AfxA3xsfkfVUlge002E` |
| ICON-DHASH | `c4e0f09edcc4f000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e28c19d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e28c19d9dab46ec3e8a44ad67b5aa5c0727299086aedc25df24b96738c42c58b"
    family = "unknown"
    file_name = "LauncherV31182x64.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:01:51"
  condition:
    hash.sha256(0, filesize) == "e28c19d9dab46ec3e8a44ad67b5aa5c0727299086aedc25df24b96738c42c58b"
}
```

### Sample 57: `411bceda1f4e1254`

| Field | Value |
|---|---|
| SHA-256 | `411bceda1f4e1254c4726686eadc60331092d319563e5b4d9c3ab0950719cf0a` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-08-14 00:01:24` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50a58037e275bb2eef6340c514a905a3` |
| SHA-1 | `365a655c7a5677982ecddd5fdd4fc27760daec67` |
| SHA-256 | `411bceda1f4e1254c4726686eadc60331092d319563e5b4d9c3ab0950719cf0a` |
| SHA3-384 | `7d84cd05f8d1371ad250fbf144d620d906944e6a9473f06c06d660fcb97021adb768831bec6d1d655998a35b3dc25cae` |
| TLSH | `T1AF1733F964B5AF16D4E6DBBE67839094CF7DFC1145434EEA69F8B8AA0B14480302C4BD` |
| SSDEEP | `393216:ao1h1t7f/xtK1uULNsYmCekH/J3obKZD+zbZgNYHU022AUz:aAfxA3xsfkfVUlge002E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_411bceda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "411bceda1f4e1254c4726686eadc60331092d319563e5b4d9c3ab0950719cf0a"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-14 00:01:24"
  condition:
    hash.sha256(0, filesize) == "411bceda1f4e1254c4726686eadc60331092d319563e5b4d9c3ab0950719cf0a"
}
```

### Sample 58: `1556696245609c75`

| Field | Value |
|---|---|
| SHA-256 | `1556696245609c75da850451ef8a44f421a89c8f563d77611fc66a9809d2cfd0` |
| Family label | `unknown` |
| File name | `vsdbg.dll` |
| File type | `exe` |
| First seen | `2026-08-14 00:00:27` |
| Reporter | `iamaachum` |
| Tags | `2-26-126-50, BlakcSeeStealer, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5402579e5a3bd0af2e274990ab50216f` |
| SHA-1 | `c9b8dcb580982b6a7f60dc2d43b76db54baa0caa` |
| SHA-256 | `1556696245609c75da850451ef8a44f421a89c8f563d77611fc66a9809d2cfd0` |
| SHA3-384 | `d87747aec5688d10919dc9a78df2b16ec67ba6cbc9ed0b89b90207edf29029ab14599ceea26d2cc194765eac3f74a1c3` |
| IMPHASH | `8ef3b94ee5a7392100386faabf23e935` |
| TLSH | `T1A426CF86B3C47AD9C412DD3A5714F232C1A2B9338EB6D0CA5E97C70A4ABAD514F3DB41` |
| SSDEEP | `98304:tU5Ng326Vcc1KppvxthiFVJFYRF+TWVL2Gwhg4IsTpQ7hmVC2de+pDMYVl9RmFCV:tUjg31e2K3v9+VJmR2bDTpQ7sVCwNL9z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_15566962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1556696245609c75da850451ef8a44f421a89c8f563d77611fc66a9809d2cfd0"
    family = "unknown"
    file_name = "vsdbg.dll"
    file_type = "exe"
    first_seen = "2026-08-14 00:00:27"
  condition:
    hash.sha256(0, filesize) == "1556696245609c75da850451ef8a44f421a89c8f563d77611fc66a9809d2cfd0"
}
```

### Sample 59: `65bc235bd5b82334`

| Field | Value |
|---|---|
| SHA-256 | `65bc235bd5b8233490738ad98ec08d0ee58c08de5ac6906d0ab36d791e1a622d` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:59:21` |
| Reporter | `iamaachum` |
| Tags | `exe, signed, Vidar, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6221e3225c261e98aab228546fe6e5f` |
| SHA-1 | `b166ea8236d392ebc5dba567fc65a446e8bb4bc5` |
| SHA-256 | `65bc235bd5b8233490738ad98ec08d0ee58c08de5ac6906d0ab36d791e1a622d` |
| SHA3-384 | `7875af470d6e30d348b6ac9b93ee531dab78b460e4078391fc179bad7af6bdd315425e7948c8b9e2e549b1413f17fde4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T119069C07BD9044E5D4D69B3289BB825277B1BC0C8B3523DB2EA1A6742F723C25E79F41` |
| SSDEEP | `49152:4+KV8yPJYgnqz4Zhzii3tm0V6q6QLYVu/HqknkXArytV777b:4Fl7x9Kq/EVSHqkkXAkZ77b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_65bc235b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65bc235bd5b8233490738ad98ec08d0ee58c08de5ac6906d0ab36d791e1a622d"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:59:21"
  condition:
    hash.sha256(0, filesize) == "65bc235bd5b8233490738ad98ec08d0ee58c08de5ac6906d0ab36d791e1a622d"
}
```

### Sample 60: `949d52a103ea1b3c`

| Field | Value |
|---|---|
| SHA-256 | `949d52a103ea1b3c8752abf5cdcdfe58363b157d031cb78c99f1e45029bfbcb5` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:58:43` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d91414f7be7ede4c3206db7cbea730ec` |
| SHA-1 | `91879b37f0896f053314fdfcf9536646d17f9a6f` |
| SHA-256 | `949d52a103ea1b3c8752abf5cdcdfe58363b157d031cb78c99f1e45029bfbcb5` |
| SHA3-384 | `b8b1c845db1539b6aa87a68af8a3c21f86f2ea87d98673e692c796c60703560b9db3d7fe94975f612f61938800adce47` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17A26BD077D9140E5C4EAAB31857782A27B61BC0C8B7933DB2E90AA782F723D25D75F44` |
| SSDEEP | `49152:ojvSoBbZbntyNT/a+a4cpWPtqVaiBVj2zNfMVNWs1PxceQdVP9Aj7U8KPhrmm4DA:oTTKaw3lqwi32G5A9ughrmm4LQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_949d52a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "949d52a103ea1b3c8752abf5cdcdfe58363b157d031cb78c99f1e45029bfbcb5"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:58:43"
  condition:
    hash.sha256(0, filesize) == "949d52a103ea1b3c8752abf5cdcdfe58363b157d031cb78c99f1e45029bfbcb5"
}
```

### Sample 61: `20ab165cf8018383`

| Field | Value |
|---|---|
| SHA-256 | `20ab165cf80183836bb2409bb7327a0c239cfff7ba7b71fdd327156e1552536f` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Program.RemoteAdmin.975.16531.24089` |
| File type | `exe` |
| First seen | `2026-08-13 23:57:40` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbca42d07f01f807ccc1689b0f3777d6` |
| SHA-1 | `f5109167ebdd19ad1bab887f548c39b3777fcd4e` |
| SHA-256 | `20ab165cf80183836bb2409bb7327a0c239cfff7ba7b71fdd327156e1552536f` |
| SHA3-384 | `2a824ecde921b0497f8fd7932c55dce64290dd5b3268d5f4c3f039cc9760ceb6e257574e9054300aa2b98bb842c0351e` |
| TLSH | `T16F72D07893C55C01CECD66B95368FF9893130C980BCBB1017424FBA5BFD85B924711B6` |
| SSDEEP | `384:kH8KLB+qIXH7UU9bjfC/Ygeq8XWssDR2hnIm2tWzwfd+EOIFE:kHZtvILJ2BLsSRNZfg0E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_20ab165c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20ab165cf80183836bb2409bb7327a0c239cfff7ba7b71fdd327156e1552536f"
    family = "unknown"
    file_name = "SecuriteInfo.com.Program.RemoteAdmin.975.16531.24089"
    file_type = "exe"
    first_seen = "2026-08-13 23:57:40"
  condition:
    hash.sha256(0, filesize) == "20ab165cf80183836bb2409bb7327a0c239cfff7ba7b71fdd327156e1552536f"
}
```

### Sample 62: `958746f27480e2d5`

| Field | Value |
|---|---|
| SHA-256 | `958746f27480e2d5c0ee87f7d31282229cdb4e6eaabc5a2e0a4b4cce56540927` |
| Family label | `Mirai` |
| File name | `2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:54:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f206897165b3f0116d262e0c28a9fb7` |
| SHA-1 | `174074403bfb0b088f9ea663c755bc0452d980a2` |
| SHA-256 | `958746f27480e2d5c0ee87f7d31282229cdb4e6eaabc5a2e0a4b4cce56540927` |
| SHA3-384 | `5b25fbebe84d784d2fbbaa05a1673f870dd2d12cfbfd5189bbfb91a56ff1097fe90318e6579e87bc667976fd849d60af` |
| TLSH | `T1E1932A91B8829623C6D0627BFB1E018D371653A8E2EE73038D256F61779BC1F0E77646` |
| TELFHASH | `t18361ff7befa81b9c6be98314d68d51199ffc345d1f1428938a0cb75b86126c3712e427` |
| SSDEEP | `1536:HcDXcMrO0WZhnU/R4VdFnS0j1Pu52vauNAYgr4aB5lbFwivRbY:HcDfp/KVd9tu5stNpgrxzdY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_958746f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "958746f27480e2d5c0ee87f7d31282229cdb4e6eaabc5a2e0a4b4cce56540927"
    family = "Mirai"
    file_name = "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:54:51"
  condition:
    hash.sha256(0, filesize) == "958746f27480e2d5c0ee87f7d31282229cdb4e6eaabc5a2e0a4b4cce56540927"
}
```

### Sample 63: `3dc0b9413feaa096`

| Field | Value |
|---|---|
| SHA-256 | `3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143` |
| Family label | `Mirai` |
| File name | `3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:54:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c1c41a4f1bc8cfee29b4f5284820ea4` |
| SHA-1 | `888c46e816a36904192bf74a2adafe6ee7b0cb84` |
| SHA-256 | `3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143` |
| SHA3-384 | `5c8647cabc6d20518f685483fa4b1419763424c5f3d3743b7c23f0975b7ce230b30e9337873b4b02da3655e8d1cc579e` |
| TLSH | `T1FD839E73CA286D64C0549AF474718D3C2763B04082A72FFBAAD9D6BA4047D9CF9163F9` |
| SSDEEP | `1536:jq4wtUt0FYigL5V2FkZq74bMbiHrvTzeKpMFgdKdnC01rNct6em:jq4r02igdV2FBuHrvTzRp9KdnN1NCC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_3dc0b941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143"
    family = "Mirai"
    file_name = "3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:54:07"
  condition:
    hash.sha256(0, filesize) == "3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143"
}
```

### Sample 64: `2d61c03914700905`

| Field | Value |
|---|---|
| SHA-256 | `2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee` |
| Family label | `Mirai` |
| File name | `2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:54:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45bcaba5fcfe3e84b20604141f2d8894` |
| SHA-1 | `290d06cae351b2c38d6690e6571ef312cfd550bc` |
| SHA-256 | `2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee` |
| SHA3-384 | `d72e8ea22fe55210b4b66ed118b38be0546eec7a9925b22775714d0ecc7ba1587f7139b7216b0bc2516bc1469370cd75` |
| TLSH | `T18313F171A7678B22D96CBAF1D9498EC6149189BC879B32553802405B3BD0F5F2B28BC6` |
| SSDEEP | `768:bmmE8P4R3YaJqpPxwaRutm4+8nYXFHyYyuOxtcpOVJfH1WRi1xsG1Ps3Uoz3M:5gJYSqpPxDRc8TFHyYyumtGIH1WRi1xv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_2d61c039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee"
    family = "Mirai"
    file_name = "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:54:03"
  condition:
    hash.sha256(0, filesize) == "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee"
}
```

### Sample 65: `8ab8ad238b5c4ff4`

| Field | Value |
|---|---|
| SHA-256 | `8ab8ad238b5c4ff4692cef4147d48ef9febd9d630120172e62d11aaefd905858` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-13 23:52:53` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2abf50b56d3e7f2ea66de206e894e42b` |
| SHA-1 | `5d761b5d11b01f822de76a0a8cd6af62d7cd2a3b` |
| SHA-256 | `8ab8ad238b5c4ff4692cef4147d48ef9febd9d630120172e62d11aaefd905858` |
| SHA3-384 | `29e2e581fe264fc4b781651bc527e41ab272dc90ba56dd4cc8889f3d44a7753346383e9c0faed25cc8c082223dd9e1ea` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T19AE6334DA6E015AFED73013C5DE29466F234F4290B79C6CB8BA843777E271E05A39A13` |
| SSDEEP | `393216:j8wwUAByeRZLZ5LkQFzVSYWkXMCHWUj4cuI3/PGTAI:j8f3RZYQFAYxXMb8NH/O7` |
| ICON-DHASH | `e8e864e0d8e8ec48` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_8ab8ad23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ab8ad238b5c4ff4692cef4147d48ef9febd9d630120172e62d11aaefd905858"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-13 23:52:53"
  condition:
    hash.sha256(0, filesize) == "8ab8ad238b5c4ff4692cef4147d48ef9febd9d630120172e62d11aaefd905858"
}
```

### Sample 66: `e76af4a6bad6251f`

| Field | Value |
|---|---|
| SHA-256 | `e76af4a6bad6251f523bd089dc9fcb832f96b3740e2b624b2d32b1d5a6d66442` |
| Family label | `Mirai` |
| File name | `b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:49:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0688862145d15bc2c720e2b56e91ef5` |
| SHA-1 | `986872a8e1b6e16a6178a5f86bc7ded5536b0239` |
| SHA-256 | `e76af4a6bad6251f523bd089dc9fcb832f96b3740e2b624b2d32b1d5a6d66442` |
| SHA3-384 | `6b445d1f21f653cd46a8c9a8119f140de0c3726c8683d121c68840d761f0a5fa0db70a16eeb0ef2eb2f225a42a0f2ad6` |
| TLSH | `T16A935C01B31C0A87E1635DB03A3F27E183AFEAD011F4F689655EAB469275E325186FCD` |
| SSDEEP | `1536:+nByQ+2VEAkykZnhpwC3rquUsIpwP2ltm4zOQfLDIbG6B45pze5YUR3V:+nByQ+2VEAkyIHqXlbdjDIqNpzOV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_e76af4a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76af4a6bad6251f523bd089dc9fcb832f96b3740e2b624b2d32b1d5a6d66442"
    family = "Mirai"
    file_name = "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:46"
  condition:
    hash.sha256(0, filesize) == "e76af4a6bad6251f523bd089dc9fcb832f96b3740e2b624b2d32b1d5a6d66442"
}
```

### Sample 67: `9eb301e6666d1174`

| Field | Value |
|---|---|
| SHA-256 | `9eb301e6666d1174febcdee441b0d7e3d7cabd2cf1da833658afe1c657a9848c` |
| Family label | `Mirai` |
| File name | `3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:49:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `907dc6780e662245d9356f10bc385698` |
| SHA-1 | `cc3cf21b8b84a0f75098c2a8e6fe2b1d3b393143` |
| SHA-256 | `9eb301e6666d1174febcdee441b0d7e3d7cabd2cf1da833658afe1c657a9848c` |
| SHA3-384 | `e267c8d3b5339933d6f77ae45dfd7fa2800cbfb103c4eda92d2a76670f3a3930aa06999ab8db0f29b4915ddf41b29c69` |
| TLSH | `T167C3C71E6E219FBDF768C33447B78A21E75833C626E1D685E2ACD6011E6038D641FFA4` |
| TELFHASH | `t1a7218e5c497422f49b355c992aaeff7be4a030df1a212d374e00a9a9abac9814e00c0c` |
| SSDEEP | `1536:9UiFbTeKVL36XoPnb9grqBSYfxp2j5dKEFkVHv7vDgHeTt6JwEnVI:NFbTDVLf/pgrOw5dKEFkVHv7DguEVI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_9eb301e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb301e6666d1174febcdee441b0d7e3d7cabd2cf1da833658afe1c657a9848c"
    family = "Mirai"
    file_name = "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:43"
  condition:
    hash.sha256(0, filesize) == "9eb301e6666d1174febcdee441b0d7e3d7cabd2cf1da833658afe1c657a9848c"
}
```

### Sample 68: `b66c851459467096`

| Field | Value |
|---|---|
| SHA-256 | `b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b` |
| Family label | `Mirai` |
| File name | `b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:49:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7e53d8d12081c78d2a7ec83aec3714c` |
| SHA-1 | `314101b3f14c7015c65706563aa0a77b0fe98afc` |
| SHA-256 | `b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b` |
| SHA3-384 | `1dabd5ec3c79f40d793781c85c79809da3f30df9ddd57900b8de68041649a2971e90afff349a469dfa907cdb678a0d82` |
| TLSH | `T16403E071A05638A6DBB68C215E24CA892FB9A55EF7335F9036810F1339470936325EDD` |
| SSDEEP | `768:JhvkUOaixhT77Jbl9PPOO3ttyQ3CQomV5a87ZhUJzIga8i5yW4uVcqgw09T:JpkUOaif7Jp5PhtysBRO8NhyzIga8i5Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_b66c8514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b"
    family = "Mirai"
    file_name = "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:08"
  condition:
    hash.sha256(0, filesize) == "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b"
}
```

### Sample 69: `3fde28b25714bbca`

| Field | Value |
|---|---|
| SHA-256 | `3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9` |
| Family label | `Mirai` |
| File name | `3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:49:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `811e903f4ccfc1aa78c9f38131dfe9a2` |
| SHA-1 | `b45bf360ff075d1e544258aaa0ab4e2b1f56633c` |
| SHA-256 | `3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9` |
| SHA3-384 | `3e85d8c03e34d76927e720efaa1bb256b7c2d0d46cac7077988b02b3b9a24e9cb6945eddccd748bdf91114c03ec2613f` |
| TLSH | `T12F13027D950104F4EC9B81F9EEC61BC807558B9B149188473454D4D7BFB29EC7071DE4` |
| SSDEEP | `768:iQ04PbWpvLwn2IWG+0cPoam5mycGVCY1D/ma6JhIIBKmV4AVXocNfzGliepJgGl0:iQ0ubWp6VWG+JgQ8wY1SaWiQthocNC5i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_3fde28b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9"
    family = "Mirai"
    file_name = "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:04"
  condition:
    hash.sha256(0, filesize) == "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9"
}
```

### Sample 70: `b96cb378d3168e5f`

| Field | Value |
|---|---|
| SHA-256 | `b96cb378d3168e5fdec28c9328e40f6b3901b79f3bc492d0954abe2493828f93` |
| Family label | `unknown` |
| File name | `xqAAE.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:45:17` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0006e2d85e5426120f40f8d8df8c1795` |
| SHA-1 | `875155bc32e1706a600db3c953f66560406cdb9e` |
| SHA-256 | `b96cb378d3168e5fdec28c9328e40f6b3901b79f3bc492d0954abe2493828f93` |
| SHA3-384 | `718ef84440d000db49bbcdb2945297a921257e4613ce75d3575b26fb3b923bcc1961c847838f1a68a557945e7cc113ab` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T147D559077D9040E5C4DAA731C47786A2BA60BC0C8B7933DB2E90A6782F723D25E79F45` |
| SSDEEP | `24576:hmwqRG3ez/eZVIsni76fHlx1MElji54nJSX16fiwF6/OmZMXAPj2wA/TBele5y96:hmD03W/uIsiruX432AMXa9V7S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_b96cb378
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96cb378d3168e5fdec28c9328e40f6b3901b79f3bc492d0954abe2493828f93"
    family = "unknown"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:45:17"
  condition:
    hash.sha256(0, filesize) == "b96cb378d3168e5fdec28c9328e40f6b3901b79f3bc492d0954abe2493828f93"
}
```

### Sample 71: `ecaae289bf636596`

| Field | Value |
|---|---|
| SHA-256 | `ecaae289bf636596c9f2e41f19fa4f0488587d57630018bf41f51e3e09c62d30` |
| Family label | `Mirai` |
| File name | `cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:44:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4976231750cd5ff4e2118b1ad654d8ac` |
| SHA-1 | `5f0de647508798bc9a6d1302df6fd86838f078e5` |
| SHA-256 | `ecaae289bf636596c9f2e41f19fa4f0488587d57630018bf41f51e3e09c62d30` |
| SHA3-384 | `96b88109e0f850f4c6ad53eeb5a637c0bcaaf85aa172609d155a5a863c54f6052b333bfeeab7baf82bb54a980bce0f9d` |
| TLSH | `T13EA31A96B8829B21D9C5167BFE1E008E3313177CE2EE73128D146F24778B96B0E77916` |
| TELFHASH | `t191210f613ba409ac77e4c714c18f20776bda34f80f11a6ba0a5e6317d2428d2f83d826` |
| SSDEEP | `1536:bsnGpvVMrxs2hlZ9fQP6514qYTHaZmkmQhsMwXi4L5s2x/y76LYjb:7tmxX5N/YTHaZO7La2x/yeLs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_ecaae289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecaae289bf636596c9f2e41f19fa4f0488587d57630018bf41f51e3e09c62d30"
    family = "Mirai"
    file_name = "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:44:54"
  condition:
    hash.sha256(0, filesize) == "ecaae289bf636596c9f2e41f19fa4f0488587d57630018bf41f51e3e09c62d30"
}
```

### Sample 72: `59e14d45e2520128`

| Field | Value |
|---|---|
| SHA-256 | `59e14d45e25201284f047fa430e7f84301edf3a7f1ad95ad0f8dd6f945275b19` |
| Family label | `unknown` |
| File name | `WindowsCodecs.dll` |
| File type | `exe` |
| First seen | `2026-08-13 23:44:52` |
| Reporter | `anonymous` |
| Tags | `ClickFix, ErrTraffic, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d908e5d211847d84906a5b90464dc5a4` |
| SHA-1 | `2bc8dcecebbadb925eb1d4681725f5b7fbc99fe3` |
| SHA-256 | `59e14d45e25201284f047fa430e7f84301edf3a7f1ad95ad0f8dd6f945275b19` |
| SHA3-384 | `8d74e12f9754e2fb3d6c46b9355500348d665ba4e39be255652f3b90e400d234693fbf1163e345aae7cc1f1f7c3866b0` |
| IMPHASH | `d20575a04dadb5c72bfc66e4a24fa0bb` |
| TLSH | `T146E2844F9F099665ED3E267951BA8DC2F378B1644331C8EB2D80981E0D42BCAD735EC9` |
| SSDEEP | `768:9vL0d1Pk9vCCqromnZzBeWUjuESb90sngUg/ijhAaA8KIQm:ydk9vC7rgH6Kc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_59e14d45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e14d45e25201284f047fa430e7f84301edf3a7f1ad95ad0f8dd6f945275b19"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-13 23:44:52"
  condition:
    hash.sha256(0, filesize) == "59e14d45e25201284f047fa430e7f84301edf3a7f1ad95ad0f8dd6f945275b19"
}
```

### Sample 73: `45148da9d1283d88`

| Field | Value |
|---|---|
| SHA-256 | `45148da9d1283d886118b60d07611d41d346d734a89fb44263ee8696f3bf053b` |
| Family label | `unknown` |
| File name | `ae_mixtwo_2.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:44:45` |
| Reporter | `iamaachum` |
| Tags | `exe, gcleaner, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17ad22af995ee858a4164452c2f80e4a` |
| SHA-1 | `e09da2824df6f1104b72c2b570be207ef3716f3d` |
| SHA-256 | `45148da9d1283d886118b60d07611d41d346d734a89fb44263ee8696f3bf053b` |
| SHA3-384 | `b30541725ed7bec8d67369f93d4939f9b4ad2b5923c3f49e55ebf0ae730a5df17135551d954ee57cf4467803c35bd8b3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E84525343AFA502AF1B3EF769AE474D6CA6FB7733B07645D1090038A4A13A41DED153A` |
| SSDEEP | `24576:KSiSdl5VWDWg26xdFo9L0hlxoJc5+Zm7mWMH1VvxamJ/hk:KZSJVWDsMy9QhUK7Exaek` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_45148da9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45148da9d1283d886118b60d07611d41d346d734a89fb44263ee8696f3bf053b"
    family = "unknown"
    file_name = "ae_mixtwo_2.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:44:45"
  condition:
    hash.sha256(0, filesize) == "45148da9d1283d886118b60d07611d41d346d734a89fb44263ee8696f3bf053b"
}
```

### Sample 74: `cc3572431079fbb6`

| Field | Value |
|---|---|
| SHA-256 | `cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d` |
| Family label | `Mirai` |
| File name | `cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:44:17` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edb7f4a0d51858397a119b4c56394153` |
| SHA-1 | `6275b75858afab3e173c6212a49983b164f2b9b2` |
| SHA-256 | `cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d` |
| SHA3-384 | `71fdee61d995b0f1f9b4837e7209041498e200852eff491db861ae50b686462e35f9026dc6813c61083892f58662b1d7` |
| TLSH | `T15113F1245ECF88E2C670B0BED16BA685A11EACF5F0F0E61317545BD9E861073E6A3187` |
| SSDEEP | `768:Ry0nhaSCazw1d/j+DDdqUCsbgEpfCJPXBEGrmf3jcxBaCDgW+FL7JhC/69q3UELt:c0ha5dpUpbHAPXB5rmTOBqW+FhYvLt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_cc357243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d"
    family = "Mirai"
    file_name = "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:44:17"
  condition:
    hash.sha256(0, filesize) == "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d"
}
```

### Sample 75: `2d94c9ec16c386af`

| Field | Value |
|---|---|
| SHA-256 | `2d94c9ec16c386af1665b3eeaa16e9cff8478136f1f5c001e00a4e35dd550bf9` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:44:12` |
| Reporter | `iamaachum` |
| Tags | `exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e34755b68490cf2b1e876da6c6d0135f` |
| SHA-1 | `b0c782b109d2cba64ae8a9e5cd8a2fe22145069b` |
| SHA-256 | `2d94c9ec16c386af1665b3eeaa16e9cff8478136f1f5c001e00a4e35dd550bf9` |
| SHA3-384 | `6e60e927d26c6a76ed865967d8a6a3d0c07744d629a8c6f7d80d5d2bbae1e7cb8425367dc4c2f6ef6300f2e39ba6c8c5` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1C3A5121DD7F405FDE0B3D174CA974916EB767C4A47B1E6CF03A0A9A61E232908D39B22` |
| SSDEEP | `49152:06xcx0yWje7pKUoFFLDb+9TwusxyQjyKg0Po1ReMXiS:06ILIUwrAsuLR0mReWF` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_2d94c9ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d94c9ec16c386af1665b3eeaa16e9cff8478136f1f5c001e00a4e35dd550bf9"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:44:12"
  condition:
    hash.sha256(0, filesize) == "2d94c9ec16c386af1665b3eeaa16e9cff8478136f1f5c001e00a4e35dd550bf9"
}
```

### Sample 76: `e98151a43afe3696`

| Field | Value |
|---|---|
| SHA-256 | `e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854` |
| Family label | `Mirai` |
| File name | `e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:44:12` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eea64936029719bcad3d0d15f2d3c8fc` |
| SHA-1 | `d28fa3b2e3511daece74eea9a6d7bfa522d8e07b` |
| SHA-256 | `e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854` |
| SHA3-384 | `75166d767514d4e175e6d5a9fb850ed44d17592a4baa0eb090a93b6f2fc0ff6f6f7cb3f626cf864f3d9e69eff8bfbad0` |
| TLSH | `T1DEA35B22B9791937C4D4A97B21F70321F2F2475A25A8CA2E7DB10E8DAF2470071577FA` |
| SSDEEP | `1536:UeuSGugij74876vapqHwX/2/gMamtpMN95kyf9csbOtvn:LvJdmva0FN/MNPvF6n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_e98151a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854"
    family = "Mirai"
    file_name = "e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:44:12"
  condition:
    hash.sha256(0, filesize) == "e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854"
}
```

### Sample 77: `97846a49e8314d0d`

| Field | Value |
|---|---|
| SHA-256 | `97846a49e8314d0d097da1590e04decb5e1570fdaf27157c91e211038dd5eeeb` |
| Family label | `unknown` |
| File name | `adb_patched.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:41:41` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, dallasbackstage-com, de-pumped, exe, LegionLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cebb279162fcab7a4c8d56010361d81` |
| SHA-1 | `7eb456bd26014231517e085dde50e4f131dfd816` |
| SHA-256 | `97846a49e8314d0d097da1590e04decb5e1570fdaf27157c91e211038dd5eeeb` |
| SHA3-384 | `044769ccc018a0a8ceb8ca77294d4a6957216a3be8c201b48a340aac64b7b1c9876a7ce31c8ab08e95d731323637d521` |
| IMPHASH | `17d07e325765cbee796dac7ba64fff66` |
| TLSH | `T1FED5C8806DE5006E5D9C8FFDCB58F3559AC5F28572288A8C903DD6CE2FEB8EC952C191` |
| SSDEEP | `24576:oA6d4XmECzfzFzPVy9Qhn1qIB0vupCJ2ofq:md1PRzyQXxavup82oS` |
| ICON-DHASH | `0b0787e270ac8603` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_97846a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97846a49e8314d0d097da1590e04decb5e1570fdaf27157c91e211038dd5eeeb"
    family = "unknown"
    file_name = "adb_patched.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:41:41"
  condition:
    hash.sha256(0, filesize) == "97846a49e8314d0d097da1590e04decb5e1570fdaf27157c91e211038dd5eeeb"
}
```

### Sample 78: `9adeb7f0c133c389`

| Field | Value |
|---|---|
| SHA-256 | `9adeb7f0c133c3890d17b6770bc5918ab3ab7a9595de9326ca9e08727bfb5a0b` |
| Family label | `unknown` |
| File name | `984.7z` |
| File type | `7z` |
| First seen | `2026-08-13 23:40:58` |
| Reporter | `iamaachum` |
| Tags | `7z, ClickFix, dallasbackstage-com, LegionLoader, pw-666` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67dfae6cd0188c8e38896879e033d7d1` |
| SHA-1 | `0b5e377216f24a0e6cf03b7511fcf8e9e5898636` |
| SHA-256 | `9adeb7f0c133c3890d17b6770bc5918ab3ab7a9595de9326ca9e08727bfb5a0b` |
| SHA3-384 | `a072e041f86190efb24776ac756a5ba8729e0543e6e584031c57267febb5fcb5fbed860511b96edc355735975c9d3729` |
| TLSH | `T18905333AB96CF52AD3D8922305517EBB26474A0F34312A9702CEB059FF5A7DDD8A4C90` |
| SSDEEP | `24576:GY/p+PzvKzKX72OQ3ZaoZRWHrHFu7UHmf9:Lp+PbKzKrk7RwbFu72S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_9adeb7f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9adeb7f0c133c3890d17b6770bc5918ab3ab7a9595de9326ca9e08727bfb5a0b"
    family = "unknown"
    file_name = "984.7z"
    file_type = "7z"
    first_seen = "2026-08-13 23:40:58"
  condition:
    hash.sha256(0, filesize) == "9adeb7f0c133c3890d17b6770bc5918ab3ab7a9595de9326ca9e08727bfb5a0b"
}
```

### Sample 79: `c4235331b054e326`

| Field | Value |
|---|---|
| SHA-256 | `c4235331b054e32688d276c0114c7e457d3b38250eaf9272883a9382ce54ea7c` |
| Family label | `Mirai` |
| File name | `71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:39:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87d913d37ce1db6fedb998bfcfd322bf` |
| SHA-1 | `16393bc5e8e260480c663935955a13bbfdcf3b39` |
| SHA-256 | `c4235331b054e32688d276c0114c7e457d3b38250eaf9272883a9382ce54ea7c` |
| SHA3-384 | `e1f38d43199645e57fa55a9af8ab3d512a2ee12bb5e7d8e8fb2471018341ed0ab1dd076ee19a7f98de88cae0e6f32cac` |
| TLSH | `T1CB931895BC819A12C6D02677FB2F018D371653A8E2EE33039D296F61779B81F0E77642` |
| TELFHASH | `t13f11e1518b901fccafe1c66485c9556609fd71bd2e22150214e93e979b57ac0b42282b` |
| SSDEEP | `1536:JQFGTSG2pEEN4Vm1BbkFMRKJbq9djMRSvp56BaRjZw0rHaANhFHnDGyy+:JQFQLmkFOKJbq04vp5qaRjZw07XHnS8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_c4235331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4235331b054e32688d276c0114c7e457d3b38250eaf9272883a9382ce54ea7c"
    family = "Mirai"
    file_name = "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:44"
  condition:
    hash.sha256(0, filesize) == "c4235331b054e32688d276c0114c7e457d3b38250eaf9272883a9382ce54ea7c"
}
```

### Sample 80: `0b11a7495fa0ad2d`

| Field | Value |
|---|---|
| SHA-256 | `0b11a7495fa0ad2da9f7e78039be4cbe5fd00345d67298e93f4b2bc368fcf352` |
| Family label | `Mirai` |
| File name | `04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:39:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `218e5dba8923d8373496dd1075cf4fb3` |
| SHA-1 | `75b018e9aea0829539d1c4b7fb876ac7c9ab387d` |
| SHA-256 | `0b11a7495fa0ad2da9f7e78039be4cbe5fd00345d67298e93f4b2bc368fcf352` |
| SHA3-384 | `b6ec31a440147ebb61242fadc2f70b847a0d8cee08aab19c11e0f9bc64c038fa71d84966389640a303b94764d51444c5` |
| TLSH | `T187C3E70ABB254EFBEC6FDD3746A91706358C640621A93F367A74D818F54B60B0AE3C74` |
| SSDEEP | `1536:BbcFti0/w+OXZ/JvRt7QlrbMrQjPx+JZvLtKqiCyPwZUqAMnkCfuFnoFSXH:BKv/w+4trhdiCAwAD2KH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_0b11a749
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b11a7495fa0ad2da9f7e78039be4cbe5fd00345d67298e93f4b2bc368fcf352"
    family = "Mirai"
    file_name = "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:41"
  condition:
    hash.sha256(0, filesize) == "0b11a7495fa0ad2da9f7e78039be4cbe5fd00345d67298e93f4b2bc368fcf352"
}
```

### Sample 81: `71a56c16e88c9bef`

| Field | Value |
|---|---|
| SHA-256 | `71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e` |
| Family label | `Mirai` |
| File name | `71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:39:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d680beb8a09dc0b10f847e6fade0d917` |
| SHA-1 | `3ed74875eeb92ce3c4492d94993329d9e1389e07` |
| SHA-256 | `71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e` |
| SHA3-384 | `afbaa3cbd5ac4e829af5202dfc4885318dce208bca5fee834bb2127f0708997da3804d8a96bcaaf1fdc146ee75581aad` |
| TLSH | `T19C03F160220DD9726FE11A78ED6F9705595660B8F0B472B7701C83186EEB4FEC3B924B` |
| SSDEEP | `768:kCzF11NKErc5ZYMtxB97BH8fOFw8EIwH3LnZ/qXXHYs3UozPl:nFVKEEZXtxZEOGIwH3LZyXXHNzPl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_71a56c16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e"
    family = "Mirai"
    file_name = "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:07"
  condition:
    hash.sha256(0, filesize) == "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e"
}
```

### Sample 82: `04dde07efaec2e50`

| Field | Value |
|---|---|
| SHA-256 | `04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef` |
| Family label | `Mirai` |
| File name | `04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:39:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `227ffcde3ec5386101b4eb4087fb7f2e` |
| SHA-1 | `b4a9d5b5821f272fde6e58339a6d5ae2e1b5f146` |
| SHA-256 | `04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef` |
| SHA3-384 | `855967aece21d51fba446108464cf417f9095648fe800690ddb3074074f3cce9f293844e8baa15fefb0a139c5272abcd` |
| TLSH | `T19D23F1CC80C17FC5CA9D6C36E29E8C919F4C120474BF2BACA3625E893DB66177D4D199` |
| SSDEEP | `768:4EQnnDG6BO7ls0gt6q1DXoyF84WDJ0kAVhHJg+TT+Q12MW0:4EsnDG6A7YUYjoc8rV07BJdP+0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_04dde07e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef"
    family = "Mirai"
    file_name = "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:02"
  condition:
    hash.sha256(0, filesize) == "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef"
}
```

### Sample 83: `e9290f77dbca2139`

| Field | Value |
|---|---|
| SHA-256 | `e9290f77dbca2139d0fa775fd29fc03009f1e316eaa86ceef0e0b1999a564c13` |
| Family label | `Mirai` |
| File name | `eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:34:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46856c98df95f441094fee1d4f9ea0db` |
| SHA-1 | `42891dd88c32e424ac73638f0022edb3f96bd0a5` |
| SHA-256 | `e9290f77dbca2139d0fa775fd29fc03009f1e316eaa86ceef0e0b1999a564c13` |
| SHA3-384 | `8e5727643f9c7158b3e32121f20f46105ed5129aa35fab943f633597dfd404f7ef2852b58e42eba851f3fe5629b7d6ae` |
| TLSH | `T1C4043C46EA418A53C4C6277AFA9F414533239B64D3EB330689187FF43F86B9E0E67605` |
| TELFHASH | `t1ad310f365a2245166a61dc14dce967b1251a46275680ee33ef2684cc240a08ae22bc4f` |
| SSDEEP | `3072:wVLv6M41MTRarg2sen1ynQ9X/HOGlVeGstN8oM/93a3hsie:wVLvc4Rarg2sen0nU/uG7eGstNHM/9Km` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_e9290f77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9290f77dbca2139d0fa775fd29fc03009f1e316eaa86ceef0e0b1999a564c13"
    family = "Mirai"
    file_name = "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:34:32"
  condition:
    hash.sha256(0, filesize) == "e9290f77dbca2139d0fa775fd29fc03009f1e316eaa86ceef0e0b1999a564c13"
}
```

### Sample 84: `eb9c029830935d18`

| Field | Value |
|---|---|
| SHA-256 | `eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c` |
| Family label | `Mirai` |
| File name | `eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:34:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c5b16b3d229cb61fc2be84550c1db61` |
| SHA-1 | `1a07798ec9b4c3967de1c1ddb0447ac757fb646c` |
| SHA-256 | `eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c` |
| SHA3-384 | `88964745c493d02e1dca4aea6fc4aca0d9bd23326ff419405c9ed7fa79e86f798c756d6d0aadb7b2130be4f1f52a0da1` |
| TLSH | `T168630217E4704663DBF289F697B5C4F3724B165433CB715F83A0DBA912E888991EEC06` |
| SSDEEP | `1536:ThgeiDS6BbLNzkq9lNqLHy9Hd2IyFJwcaLZLJLNRHBrTKZG7sR:FXiWQNQAmby992hFJwcaLZLBHpTKZGA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_eb9c0298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c"
    family = "Mirai"
    file_name = "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:34:06"
  condition:
    hash.sha256(0, filesize) == "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c"
}
```

### Sample 85: `a30bb2d9701ceab3`

| Field | Value |
|---|---|
| SHA-256 | `a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb` |
| Family label | `Mirai` |
| File name | `a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:34:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccd548dbf76e37e5e096f56bcd85a676` |
| SHA-1 | `3427a2ca1bc99db24e7c617f2b153019ccf54136` |
| SHA-256 | `a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb` |
| SHA3-384 | `0947fcd41ed4bad8442d138b21128f143a1d2ae9e10ff57940b6d4e589ac773d4d4adb4d9d66d23789cc90addf117442` |
| TLSH | `T142A34BD7F800DD7DF84ED77B44634A16B170B76109831F3A328BB9A3AD721985962F82` |
| SSDEEP | `3072:hImP1efsFIAqk9ItViHQFX2VrPJLgviHbV:ngfsFIYUX2VrJ9HbV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_a30bb2d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb"
    family = "Mirai"
    file_name = "a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:34:02"
  condition:
    hash.sha256(0, filesize) == "a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb"
}
```

### Sample 86: `9a25e7daef511ee2`

| Field | Value |
|---|---|
| SHA-256 | `9a25e7daef511ee2e91f1726a1f67a3c3a9229d04f76468fc8f56805d263b2c8` |
| Family label | `Mirai` |
| File name | `e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:24:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2ab3c82469a5738dc1732f9e29ad304` |
| SHA-1 | `060cbe0f2bc7c84e5007ed14e81c66e8f16b7ca8` |
| SHA-256 | `9a25e7daef511ee2e91f1726a1f67a3c3a9229d04f76468fc8f56805d263b2c8` |
| SHA3-384 | `5709caecc7d1d1ba794a5fe470fd85072e673550f6f4cfa9a497a5056bfc58815857e02aceae9588dc44e67e0bab4af8` |
| TLSH | `T184737CC57643E4F4EC6201792277E7335A36F43A102ADF83D7A9E932AC56A01E64739C` |
| TELFHASH | `t18141fdfa2d7e18e8b7d09848935e1f213e2de77725a075f141f3993022a3e8250b6c78` |
| SSDEEP | `1536:NFjD79Vfj2UUqy94q1VOinMlalY1fYc8G65Kjgr+QVLTninP23vdtJ:NFj/3fj2UKf1VOK4M+fYSjgZVLrouh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_9a25e7da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a25e7daef511ee2e91f1726a1f67a3c3a9229d04f76468fc8f56805d263b2c8"
    family = "Mirai"
    file_name = "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:24:39"
  condition:
    hash.sha256(0, filesize) == "9a25e7daef511ee2e91f1726a1f67a3c3a9229d04f76468fc8f56805d263b2c8"
}
```

### Sample 87: `e70745807f277cf0`

| Field | Value |
|---|---|
| SHA-256 | `e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6` |
| Family label | `Mirai` |
| File name | `e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6.elf` |
| File type | `elf` |
| First seen | `2026-08-13 23:24:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b62c40b07e45ac48e8a0a406ddc3011` |
| SHA-1 | `6e02d50b0f4a648a57786666bdc56cb98e6f28aa` |
| SHA-256 | `e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6` |
| SHA3-384 | `d3cbf04ee53ecd3ae50d7a9ae0ede2278a9f80db84aa222b7df0127bd0bbecad429a3bfc78c1786cce634fc9a509ea01` |
| TLSH | `T18503F116E6AFEE0155B43135386FB20B6210E64464C87195A9CCE174EE6EE2F692CAC3` |
| SSDEEP | `768:xcQsjJ3q8xOR5PSHqZ/Q4DEwLle2n3bUW7NUQN5WJqjDonbcuyD7UGQRjF:xiY8YdSy/wAn3bUWHinouy8Gyh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_e7074580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6"
    family = "Mirai"
    file_name = "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:24:10"
  condition:
    hash.sha256(0, filesize) == "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6"
}
```

### Sample 88: `1b0ec563cbabaa68`

| Field | Value |
|---|---|
| SHA-256 | `1b0ec563cbabaa68e37d081d9538c1b66652c389467294f495bdd5437fd2a1fa` |
| Family label | `unknown` |
| File name | `EdgeElevator.exe` |
| File type | `exe` |
| First seen | `2026-08-13 23:21:04` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e7457758a892d3043730893d5d2c085` |
| SHA-1 | `a66db4592392524926ff13aa980cfe65c25db0ba` |
| SHA-256 | `1b0ec563cbabaa68e37d081d9538c1b66652c389467294f495bdd5437fd2a1fa` |
| SHA3-384 | `c9a7ef4f13afd8e84850dafe71a5857a7824ebc9d92c9de259bc33faed9713c389ac825b01f82b64b77d06e7dbebb9da` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1D8176C17BCA119EAC0AEA2324973519A7B61BC441F3223D72E90B7782FB3BD09D75705` |
| SSDEEP | `24576:n9YMAIvLWkAVaOaqApHaDUZtpwRLnrPFRdnG6njpUXMdPmdN6xg3skxELLlIrS0Z:n91LWlVaOaqjDU/8ns6njSXJm8kq+i7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_1b0ec563
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b0ec563cbabaa68e37d081d9538c1b66652c389467294f495bdd5437fd2a1fa"
    family = "unknown"
    file_name = "EdgeElevator.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:21:04"
  condition:
    hash.sha256(0, filesize) == "1b0ec563cbabaa68e37d081d9538c1b66652c389467294f495bdd5437fd2a1fa"
}
```

### Sample 89: `6aa898f1a164c270`

| Field | Value |
|---|---|
| SHA-256 | `6aa898f1a164c270d0729b7dcec1f4359eb2f0c4109e690e7d3b09abdf7364ec` |
| Family label | `Mirai` |
| File name | `bot.ppc` |
| File type | `elf` |
| First seen | `2026-08-13 23:02:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67b698157090e329f7978a774579a4d6` |
| SHA-1 | `6a64a69e23ea904d1d239ebc3afc19adb4f53a42` |
| SHA-256 | `6aa898f1a164c270d0729b7dcec1f4359eb2f0c4109e690e7d3b09abdf7364ec` |
| SHA3-384 | `6180061fc0c6d459f68d642d1da943817c2f86ea724e653362698a5f3102ce03bf70c43f747606db346ea79185e6b5bc` |
| TLSH | `T108254A46FF1C4562C9430DF16A3F43D9F7257A4340F9922A370EAB572621E3A9AC7389` |
| SSDEEP | `24576:VM244wwZcWpFWuqJbxAij9+a7ysZTojyRFOGWlFkCFd8iJN67:VM244wwZcWOuqJbiij9bRZEjyRUGWlF6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_6aa898f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa898f1a164c270d0729b7dcec1f4359eb2f0c4109e690e7d3b09abdf7364ec"
    family = "Mirai"
    file_name = "bot.ppc"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:06"
  condition:
    hash.sha256(0, filesize) == "6aa898f1a164c270d0729b7dcec1f4359eb2f0c4109e690e7d3b09abdf7364ec"
}
```

### Sample 90: `ceaea5f689a22613`

| Field | Value |
|---|---|
| SHA-256 | `ceaea5f689a22613155872a732c36daa0ef2f588fee96b792411215adb5ec2a0` |
| Family label | `Mirai` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-08-13 23:02:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77905822eddf82d3924bb4eefd268cde` |
| SHA-1 | `3c5086d4fa0b138cbe62bd82b19396978718471b` |
| SHA-256 | `ceaea5f689a22613155872a732c36daa0ef2f588fee96b792411215adb5ec2a0` |
| SHA3-384 | `eade704e665162cae5a6489b011a99d3c5c3c7324bc3313908dbd2fbfc8fe8b441cb8d873492038564c487b1ef210136` |
| TLSH | `T1A2F42955F880DF61C6C129B6FB5D86AC33134779D3EB720689254B343BAB86B0F3A641` |
| TELFHASH | `t1efe026546c6d38bee281c2188112415c8a7c65a903312488c7c839280e1bf8a21f1d33` |
| SSDEEP | `12288:FfsYxttvwh+ms5Pvm8dJcELy9fICo4bs1MO40kjWvgpDdJv:zw25P+cJJLy9f3PCyjx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_ceaea5f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceaea5f689a22613155872a732c36daa0ef2f588fee96b792411215adb5ec2a0"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:04"
  condition:
    hash.sha256(0, filesize) == "ceaea5f689a22613155872a732c36daa0ef2f588fee96b792411215adb5ec2a0"
}
```

### Sample 91: `541155aeca277f0d`

| Field | Value |
|---|---|
| SHA-256 | `541155aeca277f0d11b3b83f2b9000b60210ffcb8fe99999d14a0665dfdceeed` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-08-13 23:02:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba843872e83364b1d6952fb65ebe4c99` |
| SHA-1 | `524b09f8925be1770c477fd58e2b1ec0ccfd7a1d` |
| SHA-256 | `541155aeca277f0d11b3b83f2b9000b60210ffcb8fe99999d14a0665dfdceeed` |
| SHA3-384 | `92804c5019e567fffb218d4c03ff3b9dec872846f19b911dac7875d1cdda828fd5132b69dfe40d52cedeb51ed6c09b62` |
| TLSH | `T13E056D5DFE4E3D41E3DBF278DB4E83E1A21FB194D32391A33982025CD486AE9CAB0555` |
| SSDEEP | `12288:oBLwCF1sJtSkrAJfhvQAG0ilihFfMdUD6CLQ96w5dwciNz:M1ySyAfy8YihV6JXC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_541155ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "541155aeca277f0d11b3b83f2b9000b60210ffcb8fe99999d14a0665dfdceeed"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:03"
  condition:
    hash.sha256(0, filesize) == "541155aeca277f0d11b3b83f2b9000b60210ffcb8fe99999d14a0665dfdceeed"
}
```

### Sample 92: `81a6b7afc8b8eee0`

| Field | Value |
|---|---|
| SHA-256 | `81a6b7afc8b8eee0301fe884359a05db347e09b8545bf2e3a2be4a9bde9edae5` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-08-13 23:02:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d814825f36a1c768f72c47621caa396b` |
| SHA-1 | `ab2386c98da1d0a8870f03e744c9201c96b92ec8` |
| SHA-256 | `81a6b7afc8b8eee0301fe884359a05db347e09b8545bf2e3a2be4a9bde9edae5` |
| SHA3-384 | `6c4eadada92f07c54af1d5585569c73c9198778c9f164d64c4374c555d9119a30ca4333259d88490f5f5018a28c0a617` |
| TLSH | `T16EB4E086F7472F42C8D7D9391847C1459A59E56763F383097F43A8BB38292B24F3878A` |
| SSDEEP | `12288:xNTGJM3a9gbqoDWZcI/rX6nVf30Gbk6FHuADJyQEg7n3gpCFGHI:xVfEGLHuAREP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_81a6b7af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81a6b7afc8b8eee0301fe884359a05db347e09b8545bf2e3a2be4a9bde9edae5"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:01"
  condition:
    hash.sha256(0, filesize) == "81a6b7afc8b8eee0301fe884359a05db347e09b8545bf2e3a2be4a9bde9edae5"
}
```

### Sample 93: `769b5c6f875497f6`

| Field | Value |
|---|---|
| SHA-256 | `769b5c6f875497f6ffa4129b44f47fdf9f186da0cf8359b2b55d14cd0ec9dd41` |
| Family label | `Mirai` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-08-13 23:01:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c2bd659add40a7fc4278c2caa9fcb3b` |
| SHA-1 | `93ce56b7b95840efc3570593b63bcb060be41699` |
| SHA-256 | `769b5c6f875497f6ffa4129b44f47fdf9f186da0cf8359b2b55d14cd0ec9dd41` |
| SHA3-384 | `d8b712ae9ed8856cfef1fc09c77aec4afd757648127d1bcfead2620ea9b4ddce5a08b94ed01529c98a151eb4b416c17b` |
| TLSH | `T13B256D06EF805FEBC46FCD30493EC30715EDA8C756D5A63A71FC4A8DBA5925A0AD3488` |
| SSDEEP | `12288:3GUJrgGeexB4z6f5H5Id/jAI8Krl9k/UhGVkVBbvutu/AapNfm3T9hO3G1qEvzo3:Kn3qKZ6vrZVoFWGVfxkfEe32y6M/W/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_769b5c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769b5c6f875497f6ffa4129b44f47fdf9f186da0cf8359b2b55d14cd0ec9dd41"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-08-13 23:01:59"
  condition:
    hash.sha256(0, filesize) == "769b5c6f875497f6ffa4129b44f47fdf9f186da0cf8359b2b55d14cd0ec9dd41"
}
```

### Sample 94: `4d665ce1ac6e85c4`

| Field | Value |
|---|---|
| SHA-256 | `4d665ce1ac6e85c429e004145d55bcc2e6a4d2eb24fb55a8b9864e8c1f97faeb` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-08-13 23:01:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `819898f757bb1362b77a446a46590ace` |
| SHA-1 | `0e8a76fd5769d35d2fa3a2c057dd2df700125d1f` |
| SHA-256 | `4d665ce1ac6e85c429e004145d55bcc2e6a4d2eb24fb55a8b9864e8c1f97faeb` |
| SHA3-384 | `c7129c0ec79571d6f21a906a16546808b999fd699ab3a95a7f7386e4161e6af158ddb1f4a26e5dbf10f939e4549afe0b` |
| TLSH | `T1A9257C1AE2B2F1BCD00BC03417DBCAA25535B47526313D7F36C5DA312EA6DE12369B26` |
| TELFHASH | `t193d17fb04afa39b4bad5c921b352f9b45a3229f651e536e019179d88efc4fd00c63c1b` |
| SSDEEP | `12288:Orn3LdtNgD0V+G/W5DCpxZ4SzChmDHMcL2YTdNJHpf5ZXYLjUuqipYoLayzsEa83:OdtNg/UW1CpxZ4FGsCDXoLBTpYPE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_4d665ce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d665ce1ac6e85c429e004145d55bcc2e6a4d2eb24fb55a8b9864e8c1f97faeb"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 23:01:58"
  condition:
    hash.sha256(0, filesize) == "4d665ce1ac6e85c429e004145d55bcc2e6a4d2eb24fb55a8b9864e8c1f97faeb"
}
```

### Sample 95: `dbc1ca156e64d63c`

| Field | Value |
|---|---|
| SHA-256 | `dbc1ca156e64d63c86210256623e28d163cbf2bc0da02813828adec3d6d8c9c5` |
| Family label | `Mirai` |
| File name | `bot.sh4` |
| File type | `elf` |
| First seen | `2026-08-13 23:01:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3ebf9098c15143e41b495b7215ad926` |
| SHA-1 | `6fa0f0e0ea5b4e28226fa9a7f01e6cdad3a681be` |
| SHA-256 | `dbc1ca156e64d63c86210256623e28d163cbf2bc0da02813828adec3d6d8c9c5` |
| SHA3-384 | `42307140f037fca5009e5e0b6b3c6a40c059b35da5e99ac050b9844ec10abb165bf9e478540986e370a4242bb2933ce4` |
| TLSH | `T185E4C093E1319EE5C53A4AB4147DF3344B01E6A313877181F6FE8284186F6A9BE9DB70` |
| SSDEEP | `12288:hlVCJDspZCZRQRCUpriQEyDIFxCMmDObWavAb9Qpc3Mv:hbyEZCZoBxIRh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_dbc1ca15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbc1ca156e64d63c86210256623e28d163cbf2bc0da02813828adec3d6d8c9c5"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-08-13 23:01:57"
  condition:
    hash.sha256(0, filesize) == "dbc1ca156e64d63c86210256623e28d163cbf2bc0da02813828adec3d6d8c9c5"
}
```

### Sample 96: `e9625f6ad35d4f3c`

| Field | Value |
|---|---|
| SHA-256 | `e9625f6ad35d4f3cc39833bc3af887840f7a00634326c94f5a426bbe1200ba48` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-13 22:58:30` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21c6d3e54ebd9cc63e265b1d2adaf86a` |
| SHA-1 | `04659a8b981939cb95d1304ae9e09d9ba3170f5d` |
| SHA-256 | `e9625f6ad35d4f3cc39833bc3af887840f7a00634326c94f5a426bbe1200ba48` |
| SHA3-384 | `4148e96de28aed672742e4609294892a1af5a93e0c669f1589504a4b9bae68431465f7b9fb42199d094967c22348a3b3` |
| IMPHASH | `21d587ce9df9b4780a02c6ce5f7831b1` |
| TLSH | `T157D5F0137F00D542D15A2E718AB4CBF86320FD48AE52879B34E6BE5BFDE96C25C066C4` |
| SSDEEP | `49152:yw0pZ0aaBCY6t5I7uhE+XpC5fz6JRcsPbkN5ROp//3/UnaYzH:yJpZ0aaB5C1XpCRWcsuGpn3uaYzH` |
| ICON-DHASH | `71e8c8c6c6ceec71` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_e9625f6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9625f6ad35d4f3cc39833bc3af887840f7a00634326c94f5a426bbe1200ba48"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 22:58:30"
  condition:
    hash.sha256(0, filesize) == "e9625f6ad35d4f3cc39833bc3af887840f7a00634326c94f5a426bbe1200ba48"
}
```

### Sample 97: `67df70e9753cc21c`

| Field | Value |
|---|---|
| SHA-256 | `67df70e9753cc21ce84551660c9fe4762af23436b0a7e26b007c93da919fc40b` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-13 22:57:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e3c514d0bc1ff347c39d4fc24e73b38` |
| SHA-1 | `d6ba5fb692eb7ef4c53b2487c75f03de0b094029` |
| SHA-256 | `67df70e9753cc21ce84551660c9fe4762af23436b0a7e26b007c93da919fc40b` |
| SHA3-384 | `f8844f4c1441c5eb5f5ee3e6b7d662ecef189c46f5e1585fc7e5a4b8e516b4f3d9f0d9f0e4f6edd76f2e190f270b0175` |
| TLSH | `T1C0A4E70AAF650EFBD82BCD3B06F91B1635CD644722953F353178D918BE4A60B4AD3C68` |
| SSDEEP | `6144:Y95xdjjKGsmpK4IbQM2UP+QerZX3ZknBmPrARrvYzQLcEKq:Y95xdjm4IR2UyHZkBUrA1Y/Xq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_67df70e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67df70e9753cc21ce84551660c9fe4762af23436b0a7e26b007c93da919fc40b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-13 22:57:43"
  condition:
    hash.sha256(0, filesize) == "67df70e9753cc21ce84551660c9fe4762af23436b0a7e26b007c93da919fc40b"
}
```

### Sample 98: `ea07e17417b3f101`

| Field | Value |
|---|---|
| SHA-256 | `ea07e17417b3f101380d7fc558f437fe43f225b91b393c5a047debf362173eda` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-08-13 22:39:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abc8e686002e60c1e05a4ed79347912c` |
| SHA-1 | `783b53524b1d20b681d30f046084c0af0f570305` |
| SHA-256 | `ea07e17417b3f101380d7fc558f437fe43f225b91b393c5a047debf362173eda` |
| SHA3-384 | `afca16ed47f0eb7832436ac1c97b6d2ee54d76faea85c87946c134217a63cce672df09db6d1bcb0485cbc0b1645bede0` |
| TLSH | `T1C1256B677721DFA5F314D17008F3C6515A9521A32AF240AAB2BCD7187E2162E2C6FFE4` |
| TELFHASH | `t11d51e018097817f493655c5d49edff3696a230ef7e1a2c278a20e86ee76af834d11c1c` |
| SSDEEP | `24576:54a/KMHAB2M1zVwsGUvIzS4M701tGtQbZNk:54a/a26zIzS4M7KG8E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_ea07e174
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea07e17417b3f101380d7fc558f437fe43f225b91b393c5a047debf362173eda"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-13 22:39:50"
  condition:
    hash.sha256(0, filesize) == "ea07e17417b3f101380d7fc558f437fe43f225b91b393c5a047debf362173eda"
}
```

### Sample 99: `d442b5376625db22`

| Field | Value |
|---|---|
| SHA-256 | `d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017` |
| Family label | `Mirai` |
| File name | `d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017` |
| File type | `sh` |
| First seen | `2026-08-13 22:23:28` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f21283d3b8ac3949c225b3b4540f24d9` |
| SHA-1 | `b7165a0b4b69faf3ce7610ac04fca65ba84789f6` |
| SHA-256 | `d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017` |
| SHA3-384 | `1360e045388b1a86fb37c0651bdebdd349684c43a997914333f540268774b7a8c4bfe1ef48f92fb4dc292bcebf48d0b2` |
| TLSH | `T18831109E41214B755502C99E73B2395CB18DAAFB6C8EC7C8C9880EED924878CF251F8D` |
| SSDEEP | `24:G38WsrxrXRtZ/dPHB7M3lTkSNWyWVHYUyUf2:G38WsrxrhtvPHB7ZI3U2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_d442b537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017"
    family = "Mirai"
    file_name = "d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017"
    file_type = "sh"
    first_seen = "2026-08-13 22:23:28"
  condition:
    hash.sha256(0, filesize) == "d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017"
}
```

### Sample 100: `39cef3a0e01334bf`

| Field | Value |
|---|---|
| SHA-256 | `39cef3a0e01334bf358bf0450209365bd5fbeff3b2ceea67684b7745e0c8f75c` |
| Family label | `unknown` |
| File name | `client_linux` |
| File type | `elf` |
| First seen | `2026-08-13 22:09:20` |
| Reporter | `meff` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4a63d94be80521f70bebcc1e95d1024` |
| SHA-256 | `39cef3a0e01334bf358bf0450209365bd5fbeff3b2ceea67684b7745e0c8f75c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_39cef3a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cef3a0e01334bf358bf0450209365bd5fbeff3b2ceea67684b7745e0c8f75c"
    family = "unknown"
    file_name = "client_linux"
    file_type = "elf"
    first_seen = "2026-08-13 22:09:20"
  condition:
    hash.sha256(0, filesize) == "39cef3a0e01334bf358bf0450209365bd5fbeff3b2ceea67684b7745e0c8f75c"
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
 * Generated: 2026-08-14T03:01:36.472460+00:00
 */

rule MalwareBazaar_unknown_001_18909faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18909faad7553046953dca1e904e782fda4cfdda2a35a02414c2d6eb44e1d61e"
    family = "unknown"
    file_name = "sensi_tbk.sh"
    file_type = "sh"
    first_seen = "2026-08-14 02:58:48"
  condition:
    hash.sha256(0, filesize) == "18909faad7553046953dca1e904e782fda4cfdda2a35a02414c2d6eb44e1d61e"
}

rule MalwareBazaar_unknown_002_2253f2e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2253f2e18dcdc93053d6dc04ebe3a7106be5075f359ef85e42da1e5c430d3cc5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 02:52:36"
  condition:
    hash.sha256(0, filesize) == "2253f2e18dcdc93053d6dc04ebe3a7106be5075f359ef85e42da1e5c430d3cc5"
}

rule MalwareBazaar_unknown_003_a8aa8fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c"
    family = "unknown"
    file_name = "a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:49:05"
  condition:
    hash.sha256(0, filesize) == "a8aa8fb051d230fd97bf9f440558d708fe11638f27f90e32fc7ca9f16109249c"
}

rule MalwareBazaar_unknown_004_23d9c8b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23d9c8b78e16d8b1db68fd04a4b133dd3649bb5c9f237ccf77f5b08d8ea8f8a6"
    family = "unknown"
    file_name = "KeePass-2.61.1.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:33:04"
  condition:
    hash.sha256(0, filesize) == "23d9c8b78e16d8b1db68fd04a4b133dd3649bb5c9f237ccf77f5b08d8ea8f8a6"
}

rule MalwareBazaar_unknown_005_6405dd6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6405dd6d75d35be336c264edcdf3c79d1285b66b5d168791c091132354b9446f"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:26:07"
  condition:
    hash.sha256(0, filesize) == "6405dd6d75d35be336c264edcdf3c79d1285b66b5d168791c091132354b9446f"
}

rule MalwareBazaar_Mirai_006_e11e6533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e11e65338860c6bdcd6f2bc5f5d35f162c54df42ca63f0178ba3d481be0193ad"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-14 02:21:28"
  condition:
    hash.sha256(0, filesize) == "e11e65338860c6bdcd6f2bc5f5d35f162c54df42ca63f0178ba3d481be0193ad"
}

rule MalwareBazaar_Mirai_007_8b6a1a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b6a1a72c7543206f7bf683ca5b01de3d21c7fb9bb6dfdcaaf271cbdac82aa51"
    family = "Mirai"
    file_name = "pryznet.arm"
    file_type = "elf"
    first_seen = "2026-08-14 02:12:57"
  condition:
    hash.sha256(0, filesize) == "8b6a1a72c7543206f7bf683ca5b01de3d21c7fb9bb6dfdcaaf271cbdac82aa51"
}

rule MalwareBazaar_unknown_008_f975c507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea"
    family = "unknown"
    file_name = "f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea.exe"
    file_type = "exe"
    first_seen = "2026-08-14 02:04:02"
  condition:
    hash.sha256(0, filesize) == "f975c5077bd774863457e039c3fda9463cc954d891fbf9546763bf38fbd755ea"
}

rule MalwareBazaar_unknown_009_d5603134
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d56031341a68a3f228450fb16ea51c28d2d699c1683529830c145b18e6596000"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-14 02:02:09"
  condition:
    hash.sha256(0, filesize) == "d56031341a68a3f228450fb16ea51c28d2d699c1683529830c145b18e6596000"
}

rule MalwareBazaar_unknown_010_984f75b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "984f75b642647fc107514bf9aa33d5ee386193277ff58b01f9beb34d8ceb75fe"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 02:02:08"
  condition:
    hash.sha256(0, filesize) == "984f75b642647fc107514bf9aa33d5ee386193277ff58b01f9beb34d8ceb75fe"
}

rule MalwareBazaar_Mirai_011_36bdf59b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36bdf59bb5e719eda9d2da8619cbb6827e5f9a2b9dd19806c704faa98c411360"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-14 01:55:56"
  condition:
    hash.sha256(0, filesize) == "36bdf59bb5e719eda9d2da8619cbb6827e5f9a2b9dd19806c704faa98c411360"
}

rule MalwareBazaar_unknown_012_0e3cd256
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98"
    family = "unknown"
    file_name = "0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98.bin"
    file_type = "exe"
    first_seen = "2026-08-14 01:54:20"
  condition:
    hash.sha256(0, filesize) == "0e3cd256f1f3c143fa097c9792f6990629f9b5706b707e6c5653d056e9f87f98"
}

rule MalwareBazaar_unknown_013_13d9a501
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13d9a5010daa3c2c05da6e63d135732b17d861f7aea426b075898e967aa7d531"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 01:52:33"
  condition:
    hash.sha256(0, filesize) == "13d9a5010daa3c2c05da6e63d135732b17d861f7aea426b075898e967aa7d531"
}

rule MalwareBazaar_Mirai_014_08f4d444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f4d444d51993a92e374193007440da52d5e9b375f7ad02fdaae7706280c1b1"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-14 01:51:59"
  condition:
    hash.sha256(0, filesize) == "08f4d444d51993a92e374193007440da52d5e9b375f7ad02fdaae7706280c1b1"
}

rule MalwareBazaar_unknown_015_f42b3277
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f42b3277d3f04b17cb75ccdb8c9e0427db2a5c05fc40919fb3a9d4a2f5585e7f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-14 01:49:51"
  condition:
    hash.sha256(0, filesize) == "f42b3277d3f04b17cb75ccdb8c9e0427db2a5c05fc40919fb3a9d4a2f5585e7f"
}

rule MalwareBazaar_unknown_016_1332d0c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1"
    family = "unknown"
    file_name = "1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:44:10"
  condition:
    hash.sha256(0, filesize) == "1332d0c6a8400500b92c6a278c663907a9d8cdc4353f7ac1edff6a4ab2d745c1"
}

rule MalwareBazaar_CoinMiner_017_411c4d38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f"
    family = "CoinMiner"
    file_name = "411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:44:04"
  condition:
    hash.sha256(0, filesize) == "411c4d388b54e659183b5d8e890bf78c7be73b866b7659617f422c978aa9f24f"
}

rule MalwareBazaar_Mirai_018_ae79cc20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae79cc20c0e9f55b3cb6993efc3fad68def359a303888c31c2f3625aa6449f29"
    family = "Mirai"
    file_name = "dlr.arm7"
    file_type = "elf"
    first_seen = "2026-08-14 01:38:03"
  condition:
    hash.sha256(0, filesize) == "ae79cc20c0e9f55b3cb6993efc3fad68def359a303888c31c2f3625aa6449f29"
}

rule MalwareBazaar_Mirai_019_2b5e0d3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b5e0d3ddef9514457ec6a9f4942874d442f780602beb7da12df40be999b8db0"
    family = "Mirai"
    file_name = "pryznet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-14 01:38:02"
  condition:
    hash.sha256(0, filesize) == "2b5e0d3ddef9514457ec6a9f4942874d442f780602beb7da12df40be999b8db0"
}

rule MalwareBazaar_Mirai_020_c06c9ee4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c06c9ee4e6020894bc9fc3abebb953b889d15d6041518483568fc8587d8e96a6"
    family = "Mirai"
    file_name = "pryznet.mips"
    file_type = "elf"
    first_seen = "2026-08-14 01:32:21"
  condition:
    hash.sha256(0, filesize) == "c06c9ee4e6020894bc9fc3abebb953b889d15d6041518483568fc8587d8e96a6"
}

rule MalwareBazaar_WannaCry_021_ed597d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90"
    family = "WannaCry"
    file_name = "ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90"
    file_type = "exe"
    first_seen = "2026-08-14 01:15:59"
  condition:
    hash.sha256(0, filesize) == "ed597d3121d614edf3aa79636783ce962732c579f2786c83c5585c43b6847a90"
}

rule MalwareBazaar_SalatStealer_022_b7bfc4ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7bfc4ecaa4b636a2b25d9a367d5b26d3d0447217b690426aef5a60eba904cef"
    family = "SalatStealer"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:11:18"
  condition:
    hash.sha256(0, filesize) == "b7bfc4ecaa4b636a2b25d9a367d5b26d3d0447217b690426aef5a60eba904cef"
}

rule MalwareBazaar_SalatStealer_023_a60079b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a60079b552cbeee8d961c10bd1a0406a2ee0f0a9b62cd34076c64cb73bed032a"
    family = "SalatStealer"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:09:30"
  condition:
    hash.sha256(0, filesize) == "a60079b552cbeee8d961c10bd1a0406a2ee0f0a9b62cd34076c64cb73bed032a"
}

rule MalwareBazaar_unknown_024_92f8f069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f8f069c032422eb6048ce1a648bd140dab9d3cfca5c855e2b56e1ac6f1cc7b"
    family = "unknown"
    file_name = "pulse_launchеr.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:08:53"
  condition:
    hash.sha256(0, filesize) == "92f8f069c032422eb6048ce1a648bd140dab9d3cfca5c855e2b56e1ac6f1cc7b"
}

rule MalwareBazaar_SheetRAT_025_cddd5e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cddd5e55137fa3c041b5c3471a2b4eb8754663bbbe59eb0a4061461498b6a507"
    family = "SheetRAT"
    file_name = "DeluxeLaunchеr-1.2.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:07:59"
  condition:
    hash.sha256(0, filesize) == "cddd5e55137fa3c041b5c3471a2b4eb8754663bbbe59eb0a4061461498b6a507"
}

rule MalwareBazaar_unknown_026_fbe1a132
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbe1a132a4dda975e349ba6c6d29e79bf247f0f18a1aeec6d80ce16e7e92ccbb"
    family = "unknown"
    file_name = "start.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:06:41"
  condition:
    hash.sha256(0, filesize) == "fbe1a132a4dda975e349ba6c6d29e79bf247f0f18a1aeec6d80ce16e7e92ccbb"
}

rule MalwareBazaar_unknown_027_71b04e2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a"
    family = "unknown"
    file_name = "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a.exe"
    file_type = "exe"
    first_seen = "2026-08-14 01:03:58"
  condition:
    hash.sha256(0, filesize) == "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a"
}

rule MalwareBazaar_unknown_028_9d435f75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d435f7547926c1259d52301f8d95a28b0e39c0275a47d3b0e42cc81ef72e252"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-08-14 00:54:40"
  condition:
    hash.sha256(0, filesize) == "9d435f7547926c1259d52301f8d95a28b0e39c0275a47d3b0e42cc81ef72e252"
}

rule MalwareBazaar_unknown_029_e62e0e3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e62e0e3e37a669e8716d4447754c6db580ca3e71316566c0e41da8bbb5a06ff4"
    family = "unknown"
    file_name = "Setup64x.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:53:17"
  condition:
    hash.sha256(0, filesize) == "e62e0e3e37a669e8716d4447754c6db580ca3e71316566c0e41da8bbb5a06ff4"
}

rule MalwareBazaar_unknown_030_141797ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "141797edd588fb14901fb516ae21db77b6a265700fe6e2430143de5534b85988"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-14 00:52:37"
  condition:
    hash.sha256(0, filesize) == "141797edd588fb14901fb516ae21db77b6a265700fe6e2430143de5534b85988"
}

rule MalwareBazaar_Mirai_031_5db0ed2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db0ed2a28e28d60c056ea6bc7410d6d4d013847994096629b7bc0257f46ea0a"
    family = "Mirai"
    file_name = "pito.x86"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:05"
  condition:
    hash.sha256(0, filesize) == "5db0ed2a28e28d60c056ea6bc7410d6d4d013847994096629b7bc0257f46ea0a"
}

rule MalwareBazaar_Mirai_032_0512cc0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0512cc0f9d328662bb5917ccb4bcd7ec1be9c343d621f49873dcef4400f4fd33"
    family = "Mirai"
    file_name = "pito.arm7"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:04"
  condition:
    hash.sha256(0, filesize) == "0512cc0f9d328662bb5917ccb4bcd7ec1be9c343d621f49873dcef4400f4fd33"
}

rule MalwareBazaar_Mirai_033_548c8cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548c8cb9348494a5d07f978a7e37ecbe3976f657866a7467006ae0bfa99ec420"
    family = "Mirai"
    file_name = "pito.arm5"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:03"
  condition:
    hash.sha256(0, filesize) == "548c8cb9348494a5d07f978a7e37ecbe3976f657866a7467006ae0bfa99ec420"
}

rule MalwareBazaar_Mirai_034_f0aa4e72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0aa4e722f27d724c26411764680da2f6b61c17d6dc726dc0b8a700e9f620dcd"
    family = "Mirai"
    file_name = "pito.i486"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:01"
  condition:
    hash.sha256(0, filesize) == "f0aa4e722f27d724c26411764680da2f6b61c17d6dc726dc0b8a700e9f620dcd"
}

rule MalwareBazaar_Mirai_035_c5c773eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5c773ebcc22bb2557d39ac0c7a841f5029987b0b465738c3b3b047b576060f7"
    family = "Mirai"
    file_name = "pito.m68k"
    file_type = "elf"
    first_seen = "2026-08-14 00:39:00"
  condition:
    hash.sha256(0, filesize) == "c5c773ebcc22bb2557d39ac0c7a841f5029987b0b465738c3b3b047b576060f7"
}

rule MalwareBazaar_Mirai_036_4a604b39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a604b39bfe0e8d39f57b35cbe8c208cd70c6d5d8c55381121158932593b7870"
    family = "Mirai"
    file_name = "pito.mipsel"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:59"
  condition:
    hash.sha256(0, filesize) == "4a604b39bfe0e8d39f57b35cbe8c208cd70c6d5d8c55381121158932593b7870"
}

rule MalwareBazaar_Mirai_037_b1d28add
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1d28add138e87822668e24e78f67dab743c06d87fe4a9754f28e18ffc0031e1"
    family = "Mirai"
    file_name = "pito.ppc"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:58"
  condition:
    hash.sha256(0, filesize) == "b1d28add138e87822668e24e78f67dab743c06d87fe4a9754f28e18ffc0031e1"
}

rule MalwareBazaar_Mirai_038_42320cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42320cd1431f7301e6b00c0d30a3caa43622b734b7f5c3787222f76ad05b3c84"
    family = "Mirai"
    file_name = "pito.sparc"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:57"
  condition:
    hash.sha256(0, filesize) == "42320cd1431f7301e6b00c0d30a3caa43622b734b7f5c3787222f76ad05b3c84"
}

rule MalwareBazaar_Mirai_039_a129b617
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a129b617f2909c5727aff206e4c10e6fba8a3243441ff9d5bcb45ff9712b911e"
    family = "Mirai"
    file_name = "pito.sh4"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:55"
  condition:
    hash.sha256(0, filesize) == "a129b617f2909c5727aff206e4c10e6fba8a3243441ff9d5bcb45ff9712b911e"
}

rule MalwareBazaar_Mirai_040_543af251
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "543af251df940d4a853172e954152839eee260ec15d5164c88ffed40aa5c2c63"
    family = "Mirai"
    file_name = "pito.arm6"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:54"
  condition:
    hash.sha256(0, filesize) == "543af251df940d4a853172e954152839eee260ec15d5164c88ffed40aa5c2c63"
}

rule MalwareBazaar_Mirai_041_7ac68d89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac68d8967ad6c5ed092e2d3480187f3c29a36fd65d8b71ba6a5768809824a8b"
    family = "Mirai"
    file_name = "pito.mips"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:53"
  condition:
    hash.sha256(0, filesize) == "7ac68d8967ad6c5ed092e2d3480187f3c29a36fd65d8b71ba6a5768809824a8b"
}

rule MalwareBazaar_Mirai_042_6285498d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2"
    family = "Mirai"
    file_name = "pito.arm4"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:51"
  condition:
    hash.sha256(0, filesize) == "6285498d05dd12dff276b0d60430b727448d6b79224015cb3674c179d70200a2"
}

rule MalwareBazaar_Mirai_043_4258b844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4258b8449e1da87af25f94640a86e9c982c00c33cd82e1d806582c49790e7760"
    family = "Mirai"
    file_name = "pito.ppc440"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:50"
  condition:
    hash.sha256(0, filesize) == "4258b8449e1da87af25f94640a86e9c982c00c33cd82e1d806582c49790e7760"
}

rule MalwareBazaar_unknown_044_979ecedb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "979ecedbf94eca29beecfedc5fccfd78d7ba469e23ce36e15fafa29e96cfdcc5"
    family = "unknown"
    file_name = "dp.sh"
    file_type = "sh"
    first_seen = "2026-08-14 00:38:49"
  condition:
    hash.sha256(0, filesize) == "979ecedbf94eca29beecfedc5fccfd78d7ba469e23ce36e15fafa29e96cfdcc5"
}

rule MalwareBazaar_Mirai_045_f49d4278
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f49d4278471bf51500ebcf425c6289769377dc061d87bd62903fd4ff8030926d"
    family = "Mirai"
    file_name = "pito.x64"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:48"
  condition:
    hash.sha256(0, filesize) == "f49d4278471bf51500ebcf425c6289769377dc061d87bd62903fd4ff8030926d"
}

rule MalwareBazaar_Mirai_046_38e726af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725"
    family = "Mirai"
    file_name = "pito.i686"
    file_type = "elf"
    first_seen = "2026-08-14 00:38:46"
  condition:
    hash.sha256(0, filesize) == "38e726afc0cefc86fa655c2ab69b3104356d0670f3a74f6dd53ba552b1b7a725"
}

rule MalwareBazaar_unknown_047_b5a490d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5a490d6e02e7f69573ad2e815ba4d5512600e01d3c2b3654ea8b42defcc1d89"
    family = "unknown"
    file_name = "Extracted_Certificates.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:30:43"
  condition:
    hash.sha256(0, filesize) == "b5a490d6e02e7f69573ad2e815ba4d5512600e01d3c2b3654ea8b42defcc1d89"
}

rule MalwareBazaar_unknown_048_96641c2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96641c2e9be0fbb4b59ef0e18755d795570b0125f9b0ea45d321d9d3380b32a8"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:25:28"
  condition:
    hash.sha256(0, filesize) == "96641c2e9be0fbb4b59ef0e18755d795570b0125f9b0ea45d321d9d3380b32a8"
}

rule MalwareBazaar_Vidar_049_a23626d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a"
    family = "Vidar"
    file_name = "a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a.bin"
    file_type = "exe"
    first_seen = "2026-08-14 00:22:16"
  condition:
    hash.sha256(0, filesize) == "a23626d45696bfbae0c7c188a492409ec29ca1acef48dfd828d0264a76a4f52a"
}

rule MalwareBazaar_unknown_050_e0f43e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d"
    family = "unknown"
    file_name = "e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d.bin"
    file_type = "zip"
    first_seen = "2026-08-14 00:09:34"
  condition:
    hash.sha256(0, filesize) == "e0f43e3074c9f695190c457dd978d6b703b35256d2562c164f32e5559bfeed1d"
}

rule MalwareBazaar_unknown_051_76083829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76083829cbb65dd4739125300a772c8de357f2339daf98a8d5c2efa83aad7733"
    family = "unknown"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-08-14 00:07:54"
  condition:
    hash.sha256(0, filesize) == "76083829cbb65dd4739125300a772c8de357f2339daf98a8d5c2efa83aad7733"
}

rule MalwareBazaar_unknown_052_5fd66b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fd66b453a25310b0dad14c68e8bfa27378c850357924f44a1097a199f035a81"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-08-14 00:06:47"
  condition:
    hash.sha256(0, filesize) == "5fd66b453a25310b0dad14c68e8bfa27378c850357924f44a1097a199f035a81"
}

rule MalwareBazaar_unknown_053_0e1ce7d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e1ce7d8e2c69cf2e00f93eb20b8dc0fb02c198214a4df44e61865a47e116153"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:04:56"
  condition:
    hash.sha256(0, filesize) == "0e1ce7d8e2c69cf2e00f93eb20b8dc0fb02c198214a4df44e61865a47e116153"
}

rule MalwareBazaar_LummaStealer_054_00d3f42d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00d3f42dc0c6527d375f8b5430915ca27f0da7b9608e446d3e5f6c17082577a5"
    family = "LummaStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:03:48"
  condition:
    hash.sha256(0, filesize) == "00d3f42dc0c6527d375f8b5430915ca27f0da7b9608e446d3e5f6c17082577a5"
}

rule MalwareBazaar_GhostPulse_055_e61dd367
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e61dd367859cf5e495a86ecaa7fa084ae84c1e38a049a68e03813e657651b192"
    family = "GhostPulse"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:03:17"
  condition:
    hash.sha256(0, filesize) == "e61dd367859cf5e495a86ecaa7fa084ae84c1e38a049a68e03813e657651b192"
}

rule MalwareBazaar_unknown_056_e28c19d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e28c19d9dab46ec3e8a44ad67b5aa5c0727299086aedc25df24b96738c42c58b"
    family = "unknown"
    file_name = "LauncherV31182x64.exe"
    file_type = "exe"
    first_seen = "2026-08-14 00:01:51"
  condition:
    hash.sha256(0, filesize) == "e28c19d9dab46ec3e8a44ad67b5aa5c0727299086aedc25df24b96738c42c58b"
}

rule MalwareBazaar_unknown_057_411bceda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "411bceda1f4e1254c4726686eadc60331092d319563e5b4d9c3ab0950719cf0a"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-14 00:01:24"
  condition:
    hash.sha256(0, filesize) == "411bceda1f4e1254c4726686eadc60331092d319563e5b4d9c3ab0950719cf0a"
}

rule MalwareBazaar_unknown_058_15566962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1556696245609c75da850451ef8a44f421a89c8f563d77611fc66a9809d2cfd0"
    family = "unknown"
    file_name = "vsdbg.dll"
    file_type = "exe"
    first_seen = "2026-08-14 00:00:27"
  condition:
    hash.sha256(0, filesize) == "1556696245609c75da850451ef8a44f421a89c8f563d77611fc66a9809d2cfd0"
}

rule MalwareBazaar_unknown_059_65bc235b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65bc235bd5b8233490738ad98ec08d0ee58c08de5ac6906d0ab36d791e1a622d"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:59:21"
  condition:
    hash.sha256(0, filesize) == "65bc235bd5b8233490738ad98ec08d0ee58c08de5ac6906d0ab36d791e1a622d"
}

rule MalwareBazaar_unknown_060_949d52a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "949d52a103ea1b3c8752abf5cdcdfe58363b157d031cb78c99f1e45029bfbcb5"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:58:43"
  condition:
    hash.sha256(0, filesize) == "949d52a103ea1b3c8752abf5cdcdfe58363b157d031cb78c99f1e45029bfbcb5"
}

rule MalwareBazaar_unknown_061_20ab165c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20ab165cf80183836bb2409bb7327a0c239cfff7ba7b71fdd327156e1552536f"
    family = "unknown"
    file_name = "SecuriteInfo.com.Program.RemoteAdmin.975.16531.24089"
    file_type = "exe"
    first_seen = "2026-08-13 23:57:40"
  condition:
    hash.sha256(0, filesize) == "20ab165cf80183836bb2409bb7327a0c239cfff7ba7b71fdd327156e1552536f"
}

rule MalwareBazaar_Mirai_062_958746f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "958746f27480e2d5c0ee87f7d31282229cdb4e6eaabc5a2e0a4b4cce56540927"
    family = "Mirai"
    file_name = "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:54:51"
  condition:
    hash.sha256(0, filesize) == "958746f27480e2d5c0ee87f7d31282229cdb4e6eaabc5a2e0a4b4cce56540927"
}

rule MalwareBazaar_Mirai_063_3dc0b941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143"
    family = "Mirai"
    file_name = "3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:54:07"
  condition:
    hash.sha256(0, filesize) == "3dc0b9413feaa096ce43898288eeefb4d51da21cbde3e575166ee9fa5bacd143"
}

rule MalwareBazaar_Mirai_064_2d61c039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee"
    family = "Mirai"
    file_name = "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:54:03"
  condition:
    hash.sha256(0, filesize) == "2d61c03914700905c0013c7f69be7ef1fd5b59d2e5509bd574d5e851a02db9ee"
}

rule MalwareBazaar_unknown_065_8ab8ad23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ab8ad238b5c4ff4692cef4147d48ef9febd9d630120172e62d11aaefd905858"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-13 23:52:53"
  condition:
    hash.sha256(0, filesize) == "8ab8ad238b5c4ff4692cef4147d48ef9febd9d630120172e62d11aaefd905858"
}

rule MalwareBazaar_Mirai_066_e76af4a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76af4a6bad6251f523bd089dc9fcb832f96b3740e2b624b2d32b1d5a6d66442"
    family = "Mirai"
    file_name = "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:46"
  condition:
    hash.sha256(0, filesize) == "e76af4a6bad6251f523bd089dc9fcb832f96b3740e2b624b2d32b1d5a6d66442"
}

rule MalwareBazaar_Mirai_067_9eb301e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb301e6666d1174febcdee441b0d7e3d7cabd2cf1da833658afe1c657a9848c"
    family = "Mirai"
    file_name = "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:43"
  condition:
    hash.sha256(0, filesize) == "9eb301e6666d1174febcdee441b0d7e3d7cabd2cf1da833658afe1c657a9848c"
}

rule MalwareBazaar_Mirai_068_b66c8514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b"
    family = "Mirai"
    file_name = "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:08"
  condition:
    hash.sha256(0, filesize) == "b66c8514594670967313b53182ccc296de043fa2bb19a446107b8a0b908eb96b"
}

rule MalwareBazaar_Mirai_069_3fde28b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9"
    family = "Mirai"
    file_name = "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:49:04"
  condition:
    hash.sha256(0, filesize) == "3fde28b25714bbca2ecf98bdb1254ee5b5e13c067849eac09bd6339b3c36a6b9"
}

rule MalwareBazaar_unknown_070_b96cb378
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b96cb378d3168e5fdec28c9328e40f6b3901b79f3bc492d0954abe2493828f93"
    family = "unknown"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:45:17"
  condition:
    hash.sha256(0, filesize) == "b96cb378d3168e5fdec28c9328e40f6b3901b79f3bc492d0954abe2493828f93"
}

rule MalwareBazaar_Mirai_071_ecaae289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecaae289bf636596c9f2e41f19fa4f0488587d57630018bf41f51e3e09c62d30"
    family = "Mirai"
    file_name = "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:44:54"
  condition:
    hash.sha256(0, filesize) == "ecaae289bf636596c9f2e41f19fa4f0488587d57630018bf41f51e3e09c62d30"
}

rule MalwareBazaar_unknown_072_59e14d45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e14d45e25201284f047fa430e7f84301edf3a7f1ad95ad0f8dd6f945275b19"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-13 23:44:52"
  condition:
    hash.sha256(0, filesize) == "59e14d45e25201284f047fa430e7f84301edf3a7f1ad95ad0f8dd6f945275b19"
}

rule MalwareBazaar_unknown_073_45148da9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45148da9d1283d886118b60d07611d41d346d734a89fb44263ee8696f3bf053b"
    family = "unknown"
    file_name = "ae_mixtwo_2.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:44:45"
  condition:
    hash.sha256(0, filesize) == "45148da9d1283d886118b60d07611d41d346d734a89fb44263ee8696f3bf053b"
}

rule MalwareBazaar_Mirai_074_cc357243
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d"
    family = "Mirai"
    file_name = "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:44:17"
  condition:
    hash.sha256(0, filesize) == "cc3572431079fbb69b0e9d79771feed3524480e662777605a1033ade4c3aeb1d"
}

rule MalwareBazaar_unknown_075_2d94c9ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d94c9ec16c386af1665b3eeaa16e9cff8478136f1f5c001e00a4e35dd550bf9"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:44:12"
  condition:
    hash.sha256(0, filesize) == "2d94c9ec16c386af1665b3eeaa16e9cff8478136f1f5c001e00a4e35dd550bf9"
}

rule MalwareBazaar_Mirai_076_e98151a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854"
    family = "Mirai"
    file_name = "e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:44:12"
  condition:
    hash.sha256(0, filesize) == "e98151a43afe36960c4d0a68f77b25b13f86607f20000fff3ec93a8ef51be854"
}

rule MalwareBazaar_unknown_077_97846a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97846a49e8314d0d097da1590e04decb5e1570fdaf27157c91e211038dd5eeeb"
    family = "unknown"
    file_name = "adb_patched.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:41:41"
  condition:
    hash.sha256(0, filesize) == "97846a49e8314d0d097da1590e04decb5e1570fdaf27157c91e211038dd5eeeb"
}

rule MalwareBazaar_unknown_078_9adeb7f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9adeb7f0c133c3890d17b6770bc5918ab3ab7a9595de9326ca9e08727bfb5a0b"
    family = "unknown"
    file_name = "984.7z"
    file_type = "7z"
    first_seen = "2026-08-13 23:40:58"
  condition:
    hash.sha256(0, filesize) == "9adeb7f0c133c3890d17b6770bc5918ab3ab7a9595de9326ca9e08727bfb5a0b"
}

rule MalwareBazaar_Mirai_079_c4235331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4235331b054e32688d276c0114c7e457d3b38250eaf9272883a9382ce54ea7c"
    family = "Mirai"
    file_name = "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:44"
  condition:
    hash.sha256(0, filesize) == "c4235331b054e32688d276c0114c7e457d3b38250eaf9272883a9382ce54ea7c"
}

rule MalwareBazaar_Mirai_080_0b11a749
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b11a7495fa0ad2da9f7e78039be4cbe5fd00345d67298e93f4b2bc368fcf352"
    family = "Mirai"
    file_name = "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:41"
  condition:
    hash.sha256(0, filesize) == "0b11a7495fa0ad2da9f7e78039be4cbe5fd00345d67298e93f4b2bc368fcf352"
}

rule MalwareBazaar_Mirai_081_71a56c16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e"
    family = "Mirai"
    file_name = "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:07"
  condition:
    hash.sha256(0, filesize) == "71a56c16e88c9bef1178312e727b68050628af02ff3d2789a62953c4cd8d352e"
}

rule MalwareBazaar_Mirai_082_04dde07e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef"
    family = "Mirai"
    file_name = "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:39:02"
  condition:
    hash.sha256(0, filesize) == "04dde07efaec2e504ef093bbd1592c651881ce52089543e0f24e2a529a1e01ef"
}

rule MalwareBazaar_Mirai_083_e9290f77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9290f77dbca2139d0fa775fd29fc03009f1e316eaa86ceef0e0b1999a564c13"
    family = "Mirai"
    file_name = "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:34:32"
  condition:
    hash.sha256(0, filesize) == "e9290f77dbca2139d0fa775fd29fc03009f1e316eaa86ceef0e0b1999a564c13"
}

rule MalwareBazaar_Mirai_084_eb9c0298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c"
    family = "Mirai"
    file_name = "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:34:06"
  condition:
    hash.sha256(0, filesize) == "eb9c029830935d18579ef3654d808d8360d55223869c67cd0c746bb3a609e39c"
}

rule MalwareBazaar_Mirai_085_a30bb2d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb"
    family = "Mirai"
    file_name = "a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:34:02"
  condition:
    hash.sha256(0, filesize) == "a30bb2d9701ceab3cd0a49fcc7d474ecc6fccb8311fbe23a465a89a55c69d0eb"
}

rule MalwareBazaar_Mirai_086_9a25e7da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a25e7daef511ee2e91f1726a1f67a3c3a9229d04f76468fc8f56805d263b2c8"
    family = "Mirai"
    file_name = "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:24:39"
  condition:
    hash.sha256(0, filesize) == "9a25e7daef511ee2e91f1726a1f67a3c3a9229d04f76468fc8f56805d263b2c8"
}

rule MalwareBazaar_Mirai_087_e7074580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6"
    family = "Mirai"
    file_name = "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6.elf"
    file_type = "elf"
    first_seen = "2026-08-13 23:24:10"
  condition:
    hash.sha256(0, filesize) == "e70745807f277cf046c8ec352b296f748a3fd497f4f0b2e0f6818e37608051a6"
}

rule MalwareBazaar_unknown_088_1b0ec563
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b0ec563cbabaa68e37d081d9538c1b66652c389467294f495bdd5437fd2a1fa"
    family = "unknown"
    file_name = "EdgeElevator.exe"
    file_type = "exe"
    first_seen = "2026-08-13 23:21:04"
  condition:
    hash.sha256(0, filesize) == "1b0ec563cbabaa68e37d081d9538c1b66652c389467294f495bdd5437fd2a1fa"
}

rule MalwareBazaar_Mirai_089_6aa898f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa898f1a164c270d0729b7dcec1f4359eb2f0c4109e690e7d3b09abdf7364ec"
    family = "Mirai"
    file_name = "bot.ppc"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:06"
  condition:
    hash.sha256(0, filesize) == "6aa898f1a164c270d0729b7dcec1f4359eb2f0c4109e690e7d3b09abdf7364ec"
}

rule MalwareBazaar_Mirai_090_ceaea5f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceaea5f689a22613155872a732c36daa0ef2f588fee96b792411215adb5ec2a0"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:04"
  condition:
    hash.sha256(0, filesize) == "ceaea5f689a22613155872a732c36daa0ef2f588fee96b792411215adb5ec2a0"
}

rule MalwareBazaar_Mirai_091_541155ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "541155aeca277f0d11b3b83f2b9000b60210ffcb8fe99999d14a0665dfdceeed"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:03"
  condition:
    hash.sha256(0, filesize) == "541155aeca277f0d11b3b83f2b9000b60210ffcb8fe99999d14a0665dfdceeed"
}

rule MalwareBazaar_Mirai_092_81a6b7af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81a6b7afc8b8eee0301fe884359a05db347e09b8545bf2e3a2be4a9bde9edae5"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-13 23:02:01"
  condition:
    hash.sha256(0, filesize) == "81a6b7afc8b8eee0301fe884359a05db347e09b8545bf2e3a2be4a9bde9edae5"
}

rule MalwareBazaar_Mirai_093_769b5c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769b5c6f875497f6ffa4129b44f47fdf9f186da0cf8359b2b55d14cd0ec9dd41"
    family = "Mirai"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-08-13 23:01:59"
  condition:
    hash.sha256(0, filesize) == "769b5c6f875497f6ffa4129b44f47fdf9f186da0cf8359b2b55d14cd0ec9dd41"
}

rule MalwareBazaar_Mirai_094_4d665ce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d665ce1ac6e85c429e004145d55bcc2e6a4d2eb24fb55a8b9864e8c1f97faeb"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-13 23:01:58"
  condition:
    hash.sha256(0, filesize) == "4d665ce1ac6e85c429e004145d55bcc2e6a4d2eb24fb55a8b9864e8c1f97faeb"
}

rule MalwareBazaar_Mirai_095_dbc1ca15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbc1ca156e64d63c86210256623e28d163cbf2bc0da02813828adec3d6d8c9c5"
    family = "Mirai"
    file_name = "bot.sh4"
    file_type = "elf"
    first_seen = "2026-08-13 23:01:57"
  condition:
    hash.sha256(0, filesize) == "dbc1ca156e64d63c86210256623e28d163cbf2bc0da02813828adec3d6d8c9c5"
}

rule MalwareBazaar_unknown_096_e9625f6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9625f6ad35d4f3cc39833bc3af887840f7a00634326c94f5a426bbe1200ba48"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-13 22:58:30"
  condition:
    hash.sha256(0, filesize) == "e9625f6ad35d4f3cc39833bc3af887840f7a00634326c94f5a426bbe1200ba48"
}

rule MalwareBazaar_Mirai_097_67df70e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67df70e9753cc21ce84551660c9fe4762af23436b0a7e26b007c93da919fc40b"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-13 22:57:43"
  condition:
    hash.sha256(0, filesize) == "67df70e9753cc21ce84551660c9fe4762af23436b0a7e26b007c93da919fc40b"
}

rule MalwareBazaar_Mirai_098_ea07e174
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea07e17417b3f101380d7fc558f437fe43f225b91b393c5a047debf362173eda"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-13 22:39:50"
  condition:
    hash.sha256(0, filesize) == "ea07e17417b3f101380d7fc558f437fe43f225b91b393c5a047debf362173eda"
}

rule MalwareBazaar_Mirai_099_d442b537
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017"
    family = "Mirai"
    file_name = "d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017"
    file_type = "sh"
    first_seen = "2026-08-13 22:23:28"
  condition:
    hash.sha256(0, filesize) == "d442b5376625db2254eac2e9dac7effe78d8b4e7c81f689a4401f754fde58017"
}

rule MalwareBazaar_unknown_100_39cef3a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cef3a0e01334bf358bf0450209365bd5fbeff3b2ceea67684b7745e0c8f75c"
    family = "unknown"
    file_name = "client_linux"
    file_type = "elf"
    first_seen = "2026-08-13 22:09:20"
  condition:
    hash.sha256(0, filesize) == "39cef3a0e01334bf358bf0450209365bd5fbeff3b2ceea67684b7745e0c8f75c"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

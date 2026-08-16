# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-16

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 652 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 652 |
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 78 |
| Mirai | 14 |
| CoinMiner | 2 |
| ValleyRAT | 2 |
| Vidar | 2 |
| LummaStealer | 1 |
| QuasarRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 49 |
| elf | 17 |
| sh | 14 |
| unknown | 9 |
| zip | 5 |
| ps1 | 4 |
| iso | 1 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `b41017f98f939385`

| Field | Value |
|---|---|
| SHA-256 | `b41017f98f93938550a6655981a500ca5a5a97ea9503e3de89948f8d3cab057b` |
| Family label | `unknown` |
| File name | `atom.dll` |
| File type | `exe` |
| First seen | `2026-08-16 01:58:23` |
| Reporter | `iamaachum` |
| Tags | `BlakcSeeStealer, dll, titatitato-net` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16165d3d6ccfd3404b2fd36dbb4cfa81` |
| SHA-1 | `f032e1b825b176def5a5ee56a0fc5579b5d17896` |
| SHA-256 | `b41017f98f93938550a6655981a500ca5a5a97ea9503e3de89948f8d3cab057b` |
| SHA3-384 | `f132b21bbd97ffdd95182e646f85f3aae215005e6a7b355c933fd8eb032229b91cff9dc6e3d2a7817fafe8d76b225982` |
| IMPHASH | `2d4dda0786e1ceafdd51569972dea026` |
| TLSH | `T1B086BE55A3C45AE9D416DA38CB14E332C2B2BD624A76C08B499AF70A1F77E514F3FB10` |
| SSDEEP | `196608:URobyBfr2lJOVqKXWcF5t2Q8X3ZYFTSRzOeYT9UMeN/I5us:URobyBfrLgU3KFnZE86eYTOMepx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_b41017f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b41017f98f93938550a6655981a500ca5a5a97ea9503e3de89948f8d3cab057b"
    family = "unknown"
    file_name = "atom.dll"
    file_type = "exe"
    first_seen = "2026-08-16 01:58:23"
  condition:
    hash.sha256(0, filesize) == "b41017f98f93938550a6655981a500ca5a5a97ea9503e3de89948f8d3cab057b"
}
```

### Sample 2: `e89c6c8b23135345`

| Field | Value |
|---|---|
| SHA-256 | `e89c6c8b23135345834621ae2d7ac0b8e29757219d08fcc9f4e47ded0b91c3e2` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:56:55` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b11e8d1afe0fe766c3e67e3379bd7ed` |
| SHA-1 | `4707928c5aefbc45a2d5bb7c0c2ec2dd9d12b3ad` |
| SHA-256 | `e89c6c8b23135345834621ae2d7ac0b8e29757219d08fcc9f4e47ded0b91c3e2` |
| SHA3-384 | `c32bc69320cf606a0e3dbe00e26517530a05a4a980009f123b911462c665331b844c519f1788e0e08e1ef9d759f80a66` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T157B539076D5081B6D4AAA73694B752A1BB31BC5CCB3233D32FA1A6743F723D25876B10` |
| SSDEEP | `24576:kjPBOdGfXaId994bBSb28OMw9rkeBgaxJSd1UOL2D0CxJgPfJgXhwULD:Y5OdGfXzdv4b0z2D0fJNi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_e89c6c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e89c6c8b23135345834621ae2d7ac0b8e29757219d08fcc9f4e47ded0b91c3e2"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:56:55"
  condition:
    hash.sha256(0, filesize) == "e89c6c8b23135345834621ae2d7ac0b8e29757219d08fcc9f4e47ded0b91c3e2"
}
```

### Sample 3: `c7d9c7f67b761688`

| Field | Value |
|---|---|
| SHA-256 | `c7d9c7f67b761688cfb67083b7e01381db90cb67adb06c8618889dfdff2396e8` |
| Family label | `unknown` |
| File name | `InstallerV14035x64.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:56:06` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8368a56d82bcb70487ee1bedf1d6bd35` |
| SHA-1 | `5ddf025fa119109f74ecb3495427e378637ed860` |
| SHA-256 | `c7d9c7f67b761688cfb67083b7e01381db90cb67adb06c8618889dfdff2396e8` |
| SHA3-384 | `8d30e582abed226339d3d693b870d66d6dfdabdad189ca4268fedc93f740d323e09410b9a47645b58bc51ba7d5b5c864` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T108E633E63D13F1A2DCE9C5F13239EB4B89830191CA0B707DBA593F6B6635D01076962B` |
| SSDEEP | `393216:JbDgNJjnIMn55jNbA0VzhMc3xpRkYql23AJ0Zvc:afPtbhVNMc3xpRkYqKxNc` |
| ICON-DHASH | `686c74f4c298e4e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_c7d9c7f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7d9c7f67b761688cfb67083b7e01381db90cb67adb06c8618889dfdff2396e8"
    family = "unknown"
    file_name = "InstallerV14035x64.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:56:06"
  condition:
    hash.sha256(0, filesize) == "c7d9c7f67b761688cfb67083b7e01381db90cb67adb06c8618889dfdff2396e8"
}
```

### Sample 4: `5436b9aec5ecd808`

| Field | Value |
|---|---|
| SHA-256 | `5436b9aec5ecd808c2b634586bab65c07e4de5a0e01fd7f952b1beb46335767c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-16 01:55:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `792660f2aecd1bd5ae62edfb19af7585` |
| SHA-1 | `fba0e5d848435c1f669b638f4556a87c7ea118f4` |
| SHA-256 | `5436b9aec5ecd808c2b634586bab65c07e4de5a0e01fd7f952b1beb46335767c` |
| SHA3-384 | `a3c998e01ac708b20e18da1c9716f8337d216a96ef1d8531e34518599fa4cf57c028a8c2d5e3005a9654e1b2b274ad91` |
| TLSH | `T178C28D956A867C44BEC98A3E4CBE2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:n28vCB+25j6es8RW9FYpMSUpi+20qUpi+20YQX:28l25JAd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_5436b9ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5436b9aec5ecd808c2b634586bab65c07e4de5a0e01fd7f952b1beb46335767c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-16 01:55:48"
  condition:
    hash.sha256(0, filesize) == "5436b9aec5ecd808c2b634586bab65c07e4de5a0e01fd7f952b1beb46335767c"
}
```

### Sample 5: `31098d6ed96cce3c`

| Field | Value |
|---|---|
| SHA-256 | `31098d6ed96cce3c4c78dc3880b6c43235bb370cbdf633fa586089ec1dd13247` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-08-16 01:55:44` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec68193e9ab5db241649de53c22e28bf` |
| SHA-1 | `9d84b5e933908e738620a1fce7900c619812d56f` |
| SHA-256 | `31098d6ed96cce3c4c78dc3880b6c43235bb370cbdf633fa586089ec1dd13247` |
| SHA3-384 | `ff5fe15061956ded3240e4d7180bc9c0731c3e0c0a95509c4d386d129da254b57232962820c454df10ace3ed9a7f7de0` |
| TLSH | `T10FE633E63D13B1A2DCE6C5F13239EB4B89830191CA0B706DBA5D3F6A6735D01076972B` |
| SSDEEP | `393216:kbDgNJjnIMn55jNbA0VzhMc3xpRkYql23AJ0Zvc:rfPtbhVNMc3xpRkYqKxNc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_31098d6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31098d6ed96cce3c4c78dc3880b6c43235bb370cbdf633fa586089ec1dd13247"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-16 01:55:44"
  condition:
    hash.sha256(0, filesize) == "31098d6ed96cce3c4c78dc3880b6c43235bb370cbdf633fa586089ec1dd13247"
}
```

### Sample 6: `90e3e19106fde055`

| Field | Value |
|---|---|
| SHA-256 | `90e3e19106fde055ee729f2a309f2519e84309c0275e27f806dc86496653f369` |
| Family label | `unknown` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:53:57` |
| Reporter | `iamaachum` |
| Tags | `72-56-74-89, exe, remahook-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f6848b5ad92af81c29567b64adf3db3` |
| SHA-1 | `997c643034c1fe4f7d22701a81df5d9ad987c045` |
| SHA-256 | `90e3e19106fde055ee729f2a309f2519e84309c0275e27f806dc86496653f369` |
| SHA3-384 | `e7d3a67f074d49899ae4b9db667bf727551eeff0b517cd5ffca0f7d8693b60c27b5107a0ec77ce5c976b544d27214662` |
| IMPHASH | `cba6a04e59320572c659515a5eed9fe2` |
| TLSH | `T19D069FD2CDE5DA73D049627DB0168F84BB3A5036B0D8DDBA0006A9D39352612F1F6BE7` |
| SSDEEP | `49152:j0BdoHjano1OAXOKU8Pmx4/g7Ksr52K5t11j9/2NMWKNpxp:op+FMH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_90e3e191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90e3e19106fde055ee729f2a309f2519e84309c0275e27f806dc86496653f369"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:53:57"
  condition:
    hash.sha256(0, filesize) == "90e3e19106fde055ee729f2a309f2519e84309c0275e27f806dc86496653f369"
}
```

### Sample 7: `81905d33a611d123`

| Field | Value |
|---|---|
| SHA-256 | `81905d33a611d1230db493f85f1da36c6c10e0be29148b8cfb72060ade4dd027` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-16 01:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1244f89ba4a6b12e3b885b58b66103a9` |
| SHA-1 | `a6af7c78098bd4c8f22215a6bacdc74145a5692c` |
| SHA-256 | `81905d33a611d1230db493f85f1da36c6c10e0be29148b8cfb72060ade4dd027` |
| SHA3-384 | `e37ca9edfa0cf6eefa2d1536482633e04b33fc99cd0ee683aaf62e872f32089a35e2017e7a9e93a28423c58fd5e4beeb` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T10BE633889AD021EDE5B3403CEBE16661EA79B8715771C6DB53EC42A47E132F0983D723` |
| SSDEEP | `393216:0XhUgxTyWMb4hjpc0+oaOu0P8ASXMCHWUjLcuI3/PGTAI:01IWR93y0P8DXMb8oH/O7` |
| ICON-DHASH | `71d88ea29ac6e471` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_81905d33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81905d33a611d1230db493f85f1da36c6c10e0be29148b8cfb72060ade4dd027"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-16 01:52:33"
  condition:
    hash.sha256(0, filesize) == "81905d33a611d1230db493f85f1da36c6c10e0be29148b8cfb72060ade4dd027"
}
```

### Sample 8: `6cad154538301583`

| Field | Value |
|---|---|
| SHA-256 | `6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba` |
| Family label | `unknown` |
| File name | `WindowsCodecs.dll` |
| File type | `exe` |
| First seen | `2026-08-16 01:51:35` |
| Reporter | `anonymous` |
| Tags | `ClickFix, ErrTraffic, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30a550f2c64f1acd6bb9621f194d3c41` |
| SHA-1 | `c5091cb20ee556f50323906f6d7fbd74a7a5f6f8` |
| SHA-256 | `6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba` |
| SHA3-384 | `e3b6812b3a40d6499b8943261c3ccb2971ab3d0650314a969933f47f51a3f0de01e9a5828f4bccc145a01e33cd37cff3` |
| IMPHASH | `92e90547a3ea267801c34c46f4b94d46` |
| TLSH | `T1A7E2954F9F099665ED3E267951BA8DC2F378B1644331C8EB2D80981E0D42BCAD735EC9` |
| SSDEEP | `768:xvL791ok9PCiqhimnZzBeWUjuESb90sngUg/ijhATBvOt7qQUe:byk9PCbhiH+7we` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_6cad1545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-16 01:51:35"
  condition:
    hash.sha256(0, filesize) == "6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba"
}
```

### Sample 9: `075c704d7a0ce2ce`

| Field | Value |
|---|---|
| SHA-256 | `075c704d7a0ce2ce66a8cd946a3b255896cd9d7b63f31068f960b98e89d154cc` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:50:55` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b32d1f9613f86ec5a94447fbf1166a1` |
| SHA-1 | `c6457e22b45656cf3835b3efd7deb460679cfef2` |
| SHA-256 | `075c704d7a0ce2ce66a8cd946a3b255896cd9d7b63f31068f960b98e89d154cc` |
| SHA3-384 | `41443283c196d7ab28906d9d4954f55e01471a3aa15be577ec141320c01dd80891b8a83f800c14fafc1dde37ba8f8449` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16F06AC077D9040E5C4AAAB31C5778262BB61BC0C8B7933DB2E90AA782F727D25D75F44` |
| SSDEEP | `49152:ojvSoBbZbntyNT/a+a4cpWPtqVa3kRAOn4rcirrTZZ:oTTKaw3lqwURAWucir5Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_075c704d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "075c704d7a0ce2ce66a8cd946a3b255896cd9d7b63f31068f960b98e89d154cc"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:50:55"
  condition:
    hash.sha256(0, filesize) == "075c704d7a0ce2ce66a8cd946a3b255896cd9d7b63f31068f960b98e89d154cc"
}
```

### Sample 10: `de6beb87a188da7e`

| Field | Value |
|---|---|
| SHA-256 | `de6beb87a188da7e565de2fa4a49bbb24a6e3723cb893b8812c5deb0375a722c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-16 01:40:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13b22c3a614aa0e11831113db9f80655` |
| SHA-1 | `99ddad36b7e844731cde1712c923850ec0081433` |
| SHA-256 | `de6beb87a188da7e565de2fa4a49bbb24a6e3723cb893b8812c5deb0375a722c` |
| SHA3-384 | `d2d697a5916f35cd47ea80741a1ca5fdffc53b4edf7e36822aefef72002649b5dfc797abf9a9ea1081b921f79bd04aee` |
| TLSH | `T162C28D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:58vCB+25j6es8Rgn9FYpMSUpi+20qUpi+20YQX:58l25Jud2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_de6beb87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6beb87a188da7e565de2fa4a49bbb24a6e3723cb893b8812c5deb0375a722c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-16 01:40:48"
  condition:
    hash.sha256(0, filesize) == "de6beb87a188da7e565de2fa4a49bbb24a6e3723cb893b8812c5deb0375a722c"
}
```

### Sample 11: `45183829a069e60c`

| Field | Value |
|---|---|
| SHA-256 | `45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15` |
| Family label | `unknown` |
| File name | `45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15` |
| File type | `elf` |
| First seen | `2026-08-16 01:30:33` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed5d545cd22e31a36a72cfd0a13684f1` |
| SHA-1 | `9e0af0154957f028e2925f94db5c9bc96861440c` |
| SHA-256 | `45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15` |
| SHA3-384 | `f8d0d6711ac1a10495006f72a29f95be6b789de8c20f632a91f0a26943c7acd4b36f920c13c9046e3405a8fc90a3f90b` |
| TLSH | `T118866C73945224D8E1ADC974D5141212BEB8388B573863CBBBC476F617BABE48E78730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ1:cqYUQuVDt0TZEe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_45183829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15"
    family = "unknown"
    file_name = "45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15"
    file_type = "elf"
    first_seen = "2026-08-16 01:30:33"
  condition:
    hash.sha256(0, filesize) == "45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15"
}
```

### Sample 12: `c6838b96ea38a6ad`

| Field | Value |
|---|---|
| SHA-256 | `c6838b96ea38a6ad9b3be9fcb630db0fb6eb14ec206998f49f1d3767aa8923db` |
| Family label | `unknown` |
| File name | `JupayoManager.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:27:37` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66de63904fcd5d1fc61985563c17b0a8` |
| SHA-1 | `98f0386953528dac42e3e13cd10f6e9699ac6b17` |
| SHA-256 | `c6838b96ea38a6ad9b3be9fcb630db0fb6eb14ec206998f49f1d3767aa8923db` |
| SHA3-384 | `14139c6cb20ca25a2bfa05209935e9100564a396e5c5c544146028f8b2c0eda5ee27b17449c786ad8eaef8f04db62b74` |
| IMPHASH | `de85a398477c39117ee5fd3f2278b959` |
| TLSH | `T19F7501D2DE9205F8D193593C416E2B5FE33834064B19A8BFB2DE01613F265AD45BCB2E` |
| SSDEEP | `49152:HlOitYd6466/8R02gfti0HqxLw/5lNtD:9M9FJH1/NtD` |
| ICON-DHASH | `0660e9e9e9e9e906` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_c6838b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6838b96ea38a6ad9b3be9fcb630db0fb6eb14ec206998f49f1d3767aa8923db"
    family = "unknown"
    file_name = "JupayoManager.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:27:37"
  condition:
    hash.sha256(0, filesize) == "c6838b96ea38a6ad9b3be9fcb630db0fb6eb14ec206998f49f1d3767aa8923db"
}
```

### Sample 13: `1db6b60a7989a6c1`

| Field | Value |
|---|---|
| SHA-256 | `1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad` |
| Family label | `unknown` |
| File name | `1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad.bin` |
| File type | `exe` |
| First seen | `2026-08-16 01:24:12` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7150cf90fe9b3a1cc2ce8a9060a7d23b` |
| SHA-1 | `2983fdf39bc257de7d8d20021fcc6f357d70095a` |
| SHA-256 | `1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad` |
| SHA3-384 | `5ba49e34401005045014e45cb480c6c2a2d69757725e5cb76ab2bd4211fc1fcef1dc12b01470a8b666f2d8d848862800` |
| IMPHASH | `42efe1abd8d48a3188e7e7b82e17c631` |
| TLSH | `T17706AF076F9046A6E4DAD339C4A612217334BC0CC33677E72EA4A6742F267D19E7AF50` |
| SSDEEP | `49152:gOa0AhLLotdl6YAAZaGDLbQidX91+wZg04dKtcU9OxH:OLL1DLItZEfxH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_1db6b60a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad"
    family = "unknown"
    file_name = "1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad.bin"
    file_type = "exe"
    first_seen = "2026-08-16 01:24:12"
  condition:
    hash.sha256(0, filesize) == "1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad"
}
```

### Sample 14: `f1476ee614a2db77`

| Field | Value |
|---|---|
| SHA-256 | `f1476ee614a2db779a721a7b19281c7e86248311119898d5cca2ea4f813c43a6` |
| Family label | `unknown` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:20:34` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22626e54bb117db096409e662c477349` |
| SHA-1 | `242e3ff26bda3b4201c4d6c23f7b080df100536d` |
| SHA-256 | `f1476ee614a2db779a721a7b19281c7e86248311119898d5cca2ea4f813c43a6` |
| SHA3-384 | `8cad67421ab604bd2c07fe1db530e5f7598cb33f2cdfe6b51dfe438cd734a4f2bde3835800d4a1e740d7da0c524c51b5` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T12085231526E280A5E06763718CFB8A270631BDB1DF6D8ADF35489A4F2E738C57636313` |
| SSDEEP | `24576:4DcQEnrtL3oy0m0DPXqJsENV1mk1tQ1Fh+zUbqqg/+Kj5hXF3ez4lomSaFq48YYc:eNIdMDPg7RT1SszUOqg/+MyOnSG38YY` |
| ICON-DHASH | `4cc8f0c29ab2aa70` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_f1476ee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1476ee614a2db779a721a7b19281c7e86248311119898d5cca2ea4f813c43a6"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:20:34"
  condition:
    hash.sha256(0, filesize) == "f1476ee614a2db779a721a7b19281c7e86248311119898d5cca2ea4f813c43a6"
}
```

### Sample 15: `cb1e15a47e40e7e1`

| Field | Value |
|---|---|
| SHA-256 | `cb1e15a47e40e7e1886531b829f4061c60b73ba4937e9161b4fc1fef846dfddb` |
| Family label | `unknown` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:19:51` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e496c36f3f7b9fb577fd06a1f62b105c` |
| SHA-1 | `bc154cf904b1d48ea12b805c56edd1d753981f0b` |
| SHA-256 | `cb1e15a47e40e7e1886531b829f4061c60b73ba4937e9161b4fc1fef846dfddb` |
| SHA3-384 | `7f58e4cc460c5c5213a9027deddd3cce541246841e2ddf6ca6b44eb8baaab5c77ba34995017146f03afc49ade7581a4f` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T136B55A07BE8041A5D49AE736C9B64251B270BC4C873137D72F91AAB42F727D2AE76F10` |
| SSDEEP | `24576:B5D5y2VJW6p2O8Em/ATZiX6WBYOu4S4t690ttnlqaUY80yY7:vE2VJW6pmEu+4XbYODhtNfB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_cb1e15a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb1e15a47e40e7e1886531b829f4061c60b73ba4937e9161b4fc1fef846dfddb"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:19:51"
  condition:
    hash.sha256(0, filesize) == "cb1e15a47e40e7e1886531b829f4061c60b73ba4937e9161b4fc1fef846dfddb"
}
```

### Sample 16: `b4e869d592baf437`

| Field | Value |
|---|---|
| SHA-256 | `b4e869d592baf4370f850cbe71c7ae653ac1078646ef6633a4e769f6752b4d2e` |
| Family label | `unknown` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:19:09` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d08c47be7eaace5d8117519d20cd72db` |
| SHA-1 | `032c74957fd1fdb9024733f8aece15278d30b498` |
| SHA-256 | `b4e869d592baf4370f850cbe71c7ae653ac1078646ef6633a4e769f6752b4d2e` |
| SHA3-384 | `950616beff90c618596a335ecb81e1051c67fae1a263eb67c61f268cfb8747fd547f8baaf87020d42be98a72c9dc197e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11CD57B07ACA148F6C0AAA33189B352517B70BC484B3627EB3E90B7382F767D05D79B55` |
| SSDEEP | `49152:rxru8nXP9dr1O0URC1vfcsPLHhz7DNYHWmV:rx6E/dzzyHl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_b4e869d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4e869d592baf4370f850cbe71c7ae653ac1078646ef6633a4e769f6752b4d2e"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:19:09"
  condition:
    hash.sha256(0, filesize) == "b4e869d592baf4370f850cbe71c7ae653ac1078646ef6633a4e769f6752b4d2e"
}
```

### Sample 17: `7f11d92a1fc25ba8`

| Field | Value |
|---|---|
| SHA-256 | `7f11d92a1fc25ba81f808b62a075ccdfe06d441fcaa5adad483afc7508ee5000` |
| Family label | `LummaStealer` |
| File name | `dollar.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:18:20` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, dist-binarypilot-cc, exe, not-LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `385f52df34c0e3f7f8f3602afedd70e3` |
| SHA-1 | `c96212fa882a2dc432e99b88fe62b7358d777b27` |
| SHA-256 | `7f11d92a1fc25ba81f808b62a075ccdfe06d441fcaa5adad483afc7508ee5000` |
| SHA3-384 | `6aaf7105e93fc4687f69980cefa41ae7460dd42f8845702c995fe1ad32e0d8d4faf394d62a1cb0d83e8a02c750e9bbf0` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E8F55B01FED784F6DC032A3154A7626F6335AD090F39DB97EE543A79EA73291086370A` |
| SSDEEP | `49152:5YKVdU5e113JH8ujxmEuHckO6xC9RbQxrXh:6iUE7WuVm3Hc19exLh` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_017_7f11d92a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f11d92a1fc25ba81f808b62a075ccdfe06d441fcaa5adad483afc7508ee5000"
    family = "LummaStealer"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:18:20"
  condition:
    hash.sha256(0, filesize) == "7f11d92a1fc25ba81f808b62a075ccdfe06d441fcaa5adad483afc7508ee5000"
}
```

### Sample 18: `3ed7f672f3f3f071`

| Field | Value |
|---|---|
| SHA-256 | `3ed7f672f3f3f0710bce5be789cf707c21e64ec24fc6ebe6f2153d462f287a71` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:16:23` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a17f28ebf42977baedda23165888b69` |
| SHA-1 | `711612fb87fcc226cce168ef2d1928663ad50ab5` |
| SHA-256 | `3ed7f672f3f3f0710bce5be789cf707c21e64ec24fc6ebe6f2153d462f287a71` |
| SHA3-384 | `9eed55b6dc78a1f788e459b6fe8ec1dd393e6f383b1eff39a35d75b6cfb36364205928983802a7a779c1035b7ab53695` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1DC061204EB5435AAFC729274CEB38AE1DE31380A036196EB1BD4755B1EFB1D1CB2A711` |
| SSDEEP | `98304:rKAfOh0Z0a5lpJqP5SNinafI9GLJ6riazFTdbvum8AD:rHqlEz0hSUUCRi6fbvb` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_3ed7f672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ed7f672f3f3f0710bce5be789cf707c21e64ec24fc6ebe6f2153d462f287a71"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:16:23"
  condition:
    hash.sha256(0, filesize) == "3ed7f672f3f3f0710bce5be789cf707c21e64ec24fc6ebe6f2153d462f287a71"
}
```

### Sample 19: `997acaae90f21aeb`

| Field | Value |
|---|---|
| SHA-256 | `997acaae90f21aebb154b75c2b2c787fa49e8d3d0cdf5c5893d6f7ddbb3d67b6` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:14:24` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `873486dafe9cea231a8c8ea79ec13849` |
| SHA-1 | `ba0ca40c195d8a71071daa03eb291c2fdc0496c0` |
| SHA-256 | `997acaae90f21aebb154b75c2b2c787fa49e8d3d0cdf5c5893d6f7ddbb3d67b6` |
| SHA3-384 | `e67ab036c88c5981946a6c57dc7b6fb93e9f143b39821e1d7fe7b6e1d10578dc788eed37151d447a41164565d94f2a5b` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T164061318ABA435BAFC729674CFB38BE0DA717807035195EB1794785B0EFB1D1CA26312` |
| SSDEEP | `98304:06IWd3osQEICM2xSzHJZClQhKC0135eOLbeekOaXFPQdyBf:0ed4+RMiS7ClQADeOLaOaydyBf` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_997acaae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "997acaae90f21aebb154b75c2b2c787fa49e8d3d0cdf5c5893d6f7ddbb3d67b6"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:14:24"
  condition:
    hash.sha256(0, filesize) == "997acaae90f21aebb154b75c2b2c787fa49e8d3d0cdf5c5893d6f7ddbb3d67b6"
}
```

### Sample 20: `09ee5443809176dc`

| Field | Value |
|---|---|
| SHA-256 | `09ee5443809176dcac8ddd954e2dca7c3ba1d0692fca9394d1f1c78e3d943f42` |
| Family label | `unknown` |
| File name | `OpenLink.ps1` |
| File type | `ps1` |
| First seen | `2026-08-16 01:12:39` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, ps1, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b3d5b2419f4d77a5828171e0b1c4707` |
| SHA-1 | `7e7a6081c35b68da1b736ddd46df618514eecc5b` |
| SHA-256 | `09ee5443809176dcac8ddd954e2dca7c3ba1d0692fca9394d1f1c78e3d943f42` |
| SHA3-384 | `3b4eae03bdfcf09e2bc2d09e9aa33ffef1f7bb1c068bd5c987f5877d7b910368f21d28a5c28c7e47f6e20cac02ba7e06` |
| TLSH | `T176D02213882F04736F2000898330327BF9C2626C53878202EC90888D340033E3DF8308` |
| SSDEEP | `6:SuKxVABeQXiVnXKbywlf3Ggk0ZapPX2xkVA2FfAqLez6MFM:ixVABPXiIZu50Zap+qVA2Foqiz6Mm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_09ee5443
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09ee5443809176dcac8ddd954e2dca7c3ba1d0692fca9394d1f1c78e3d943f42"
    family = "unknown"
    file_name = "OpenLink.ps1"
    file_type = "ps1"
    first_seen = "2026-08-16 01:12:39"
  condition:
    hash.sha256(0, filesize) == "09ee5443809176dcac8ddd954e2dca7c3ba1d0692fca9394d1f1c78e3d943f42"
}
```

### Sample 21: `5e38d605b7cadd90`

| Field | Value |
|---|---|
| SHA-256 | `5e38d605b7cadd90534ad48097fb0f40f03d962ae2f21f702d1609ae65a42a20` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:08:41` |
| Reporter | `iamaachum` |
| Tags | `ClickFraud, exe, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a94c32a3fa4263e38fc8b9c290dc037e` |
| SHA-1 | `412dc61e6dcc2220d6b46043123d25bee2b2a769` |
| SHA-256 | `5e38d605b7cadd90534ad48097fb0f40f03d962ae2f21f702d1609ae65a42a20` |
| SHA3-384 | `180f5f6712f84e4f7dfb1b49092f921d03f3712b1b7e5527f8ea9452f71a4fc0a73f06bd02bf05f9d2ab610cb6a96ba4` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T15A061205EBA430B9FCB79234CEB387E2DE257806076095E727D4A55B1EBB1D1CA2B311` |
| SSDEEP | `98304:rKAy+MotzzazKrocjZhzC4/kIiTLmXl89kbniJLpMod:rKuZuwNhz6IILX96Cld` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_5e38d605
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e38d605b7cadd90534ad48097fb0f40f03d962ae2f21f702d1609ae65a42a20"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:08:41"
  condition:
    hash.sha256(0, filesize) == "5e38d605b7cadd90534ad48097fb0f40f03d962ae2f21f702d1609ae65a42a20"
}
```

### Sample 22: `d82decfc37200dbb`

| Field | Value |
|---|---|
| SHA-256 | `d82decfc37200dbb03a77293bbd47df17e9f1bcd7ff51febdcadcf818b45b1a7` |
| Family label | `unknown` |
| File name | `xqAAE.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:05:00` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e2676e41e31466e37dd9a5d307c43dc` |
| SHA-1 | `e3dac7fdf399610b39cb33ca9e922d5fa5d1be90` |
| SHA-256 | `d82decfc37200dbb03a77293bbd47df17e9f1bcd7ff51febdcadcf818b45b1a7` |
| SHA3-384 | `2e64b2411a5562d1127f23053a860d29318dd371267f9d7aae1b58c620abcfbe95ea413e95df73b9db0325fd327b76e5` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T14A957D077C9045B6E49A933A89F61A81BB35B8180F3223CB3E90B67C3F72BD55A71754` |
| SSDEEP | `49152:Y7YiSfJDrw3rpxKjq1nBdCTCgdFGX9WUg4Ai+v8/r+iBAzonF2Vbpa3wtESudv9c:hJDUroJND` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_d82decfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d82decfc37200dbb03a77293bbd47df17e9f1bcd7ff51febdcadcf818b45b1a7"
    family = "unknown"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:05:00"
  condition:
    hash.sha256(0, filesize) == "d82decfc37200dbb03a77293bbd47df17e9f1bcd7ff51febdcadcf818b45b1a7"
}
```

### Sample 23: `a4e7500f5e360f33`

| Field | Value |
|---|---|
| SHA-256 | `a4e7500f5e360f33223c504da7c953894ff2053fec6f5b6a6ca772bc78a61742` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-16 01:03:32` |
| Reporter | `iamaachum` |
| Tags | `exe, GCleaner, RemusStealer, sfx, unluckytool-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f970b3cc1750863a65530f8b10fc1b7` |
| SHA-1 | `5cddabef22b54c78e8a79568a83b1e8c8ff2b747` |
| SHA-256 | `a4e7500f5e360f33223c504da7c953894ff2053fec6f5b6a6ca772bc78a61742` |
| SHA3-384 | `8813fa194041fa532c6affa141807414756df1f76b292883a8134916f20aa8f9acf63ec860e411deeb17b04a5dd67655` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1BAA51218D7B405FDE0B3D578CE574912EB76BC4A47B1E68F03A0A9A61F272A08D3D712` |
| SSDEEP | `49152:06xcx0yWXe7pKUoFFLDb+9Twus084y0zjp+/kPM:06ILIUwrAsut8/wN+/kPM` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_a4e7500f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e7500f5e360f33223c504da7c953894ff2053fec6f5b6a6ca772bc78a61742"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:03:32"
  condition:
    hash.sha256(0, filesize) == "a4e7500f5e360f33223c504da7c953894ff2053fec6f5b6a6ca772bc78a61742"
}
```

### Sample 24: `2dfe533cdd6c2ea5`

| Field | Value |
|---|---|
| SHA-256 | `2dfe533cdd6c2ea50640338fd3a53ffb5620e82009575bd27aa10be5e7444897` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-16 00:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cab81b8fa6b59e3b06b3aba29204a21` |
| SHA-1 | `a2d100f8c337b073b53f0b34c4b1c22581476178` |
| SHA-256 | `2dfe533cdd6c2ea50640338fd3a53ffb5620e82009575bd27aa10be5e7444897` |
| SHA3-384 | `72ce2bd9dee4ab5b281b1ca25bf9d3708fbe012a93c640dce908bfbc6fd49d0acfb79319209587bc1426b29f35677f71` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1F9E6330CBAE411FED973C03CD9E21592EAB8B9351B36C1DB47E447229E571F08938A67` |
| SSDEEP | `393216:Y2pLhljlQs3N45EVgb8EH0bPXMCHWUjWcuI3/PGTAI:YOnlj3N43bVH0DXMb8rH/O7` |
| ICON-DHASH | `d4b9fcbc8cc47030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_2dfe533c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dfe533cdd6c2ea50640338fd3a53ffb5620e82009575bd27aa10be5e7444897"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-16 00:52:30"
  condition:
    hash.sha256(0, filesize) == "2dfe533cdd6c2ea50640338fd3a53ffb5620e82009575bd27aa10be5e7444897"
}
```

### Sample 25: `5a41a16cd4756275`

| Field | Value |
|---|---|
| SHA-256 | `5a41a16cd4756275ce194a9495382d3cf340a2cc362de6492ac0ba6879be1d08` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-16 00:17:53` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4de4a42faf8cc55c8d155a112c4f1b7a` |
| SHA-1 | `cb3925719fe8b848fa5beea7de6d2cf54bf406ff` |
| SHA-256 | `5a41a16cd4756275ce194a9495382d3cf340a2cc362de6492ac0ba6879be1d08` |
| SHA3-384 | `123e7d012c7e0a2948166c8e8e84caf01669ff80d963a049524ea09e823a3b882830baf7d9ef1e2f1f3854c73e479582` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T142663A07EC6915E8C0AED5358AA39252BF317C495B2123D32BA0F6283F77BD06DB9750` |
| SSDEEP | `49152:og1b9sC9ngVbMBojaAY+HpqXq7XEH7zipS9N/t/6RmKOP2G5p2ITV+f9Uy5MKQKC:ogpPiC9/kltG2vrcwE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_5a41a16c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a41a16cd4756275ce194a9495382d3cf340a2cc362de6492ac0ba6879be1d08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-16 00:17:53"
  condition:
    hash.sha256(0, filesize) == "5a41a16cd4756275ce194a9495382d3cf340a2cc362de6492ac0ba6879be1d08"
}
```

### Sample 26: `7f75bfb1eeecded5`

| Field | Value |
|---|---|
| SHA-256 | `7f75bfb1eeecded58b0aca85a25efc6fb95dcf7e0105a2de22d59aacfab9df1b` |
| Family label | `unknown` |
| File name | `hutepkeazyauxbqsiykw.dll` |
| File type | `exe` |
| First seen | `2026-08-16 00:10:24` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57c68d6b3d958c4abe14743b663fb675` |
| SHA-1 | `19eebb85e98b6c76fc9c7a34a23261f9bcf0deb3` |
| SHA-256 | `7f75bfb1eeecded58b0aca85a25efc6fb95dcf7e0105a2de22d59aacfab9df1b` |
| SHA3-384 | `131368d1c75032574d37f55bb10015d6d7a13c9ee44673df302bf86dab78e6fad0bbac2e92b433dec3eb26155287e633` |
| IMPHASH | `545ab5f5e725852666113bb96037b688` |
| TLSH | `T1CD062C3227668A7AF57156B1293C992E542978710774B8CBD2984C3DDCB8AC30F36F27` |
| SSDEEP | `49152:X8JY14H9AIK4soeI/K/0yyqBW9SwP1gPnGw:+MIKhlPGw` |
| ICON-DHASH | `a2455d31716951a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_7f75bfb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f75bfb1eeecded58b0aca85a25efc6fb95dcf7e0105a2de22d59aacfab9df1b"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-16 00:10:24"
  condition:
    hash.sha256(0, filesize) == "7f75bfb1eeecded58b0aca85a25efc6fb95dcf7e0105a2de22d59aacfab9df1b"
}
```

### Sample 27: `f9964a8d9d01052d`

| Field | Value |
|---|---|
| SHA-256 | `f9964a8d9d01052d9bebe057deadd7ce9d794e8296e2a72229f8ae4aa62ae224` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-16 00:07:27` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d222549235db4112333d82e12f767d47` |
| SHA-1 | `12463a81a786b04fe4b3b7d1aa1222e589e5921d` |
| SHA-256 | `f9964a8d9d01052d9bebe057deadd7ce9d794e8296e2a72229f8ae4aa62ae224` |
| SHA3-384 | `7eb2117363be20c07763d822d0df4f9ba988ed06dc74b563359f5b87991e890caaba693053c4918b7565e2adc988aa0c` |
| IMPHASH | `bd6ac69ea8f6e3ade9b9834340f13265` |
| TLSH | `T196164A43F67690FCC16AC0788346A132FF32BC8948367AAB5BD09B353E65B406B1DB55` |
| SSDEEP | `49152:4zwYqdALwkbQB1bw/48Hgbbv5mAF71XXG8PTWUhs5zs4moSK7iSAEExYxIU6isz:4oNB8kFB1m8bPs5zs53+sz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_f9964a8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9964a8d9d01052d9bebe057deadd7ce9d794e8296e2a72229f8ae4aa62ae224"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-16 00:07:27"
  condition:
    hash.sha256(0, filesize) == "f9964a8d9d01052d9bebe057deadd7ce9d794e8296e2a72229f8ae4aa62ae224"
}
```

### Sample 28: `ac7f1d6c3d435a39`

| Field | Value |
|---|---|
| SHA-256 | `ac7f1d6c3d435a3961c1fc71307d7a9354ac2b84646abc3834e98272fcff7a9b` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-15 23:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c14ccc7a173139133e2d1ea618b94ca4` |
| SHA-1 | `24ce81a298ad9f6d8aa4cb6a800688006ad5cd06` |
| SHA-256 | `ac7f1d6c3d435a3961c1fc71307d7a9354ac2b84646abc3834e98272fcff7a9b` |
| SHA3-384 | `08b56bdc20e274bfef818a8966f2577687cd7e4162cf28862b67c2050b428b67d6e692c82230b952d9b2133fefe15dd9` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T14BE63348A6D007EFEEF3413CD69605A6E13E78754339D1EB63A8839A5E332E08D34567` |
| SSDEEP | `393216:kCZ5ws5wzZJFMLeY0TXMCHWUjMcuI3/PGTAI:XHwsyJq10TXMb8ZH/O7` |
| ICON-DHASH | `5479fcbccce4f032` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_ac7f1d6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac7f1d6c3d435a3961c1fc71307d7a9354ac2b84646abc3834e98272fcff7a9b"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-15 23:52:31"
  condition:
    hash.sha256(0, filesize) == "ac7f1d6c3d435a3961c1fc71307d7a9354ac2b84646abc3834e98272fcff7a9b"
}
```

### Sample 29: `74d90413c20a548c`

| Field | Value |
|---|---|
| SHA-256 | `74d90413c20a548c1849f9b9e42a947441055589ba06430cade9ab40d38f7539` |
| Family label | `unknown` |
| File name | `hutepkeazyauxbqsiykw.dll` |
| File type | `exe` |
| First seen | `2026-08-15 23:07:10` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06744ee71cc1fc348230cbfd5f8e8154` |
| SHA-1 | `bbe000c68049007704c63eda8f343b8620654d5a` |
| SHA-256 | `74d90413c20a548c1849f9b9e42a947441055589ba06430cade9ab40d38f7539` |
| SHA3-384 | `11a36cba9736fb2839103f0c977e9e635fdcb371d3141b7ee7f3e1b6e864c0ae2671f8ad0089a8eda5749e034e3a448e` |
| IMPHASH | `545ab5f5e725852666113bb96037b688` |
| TLSH | `T101062C3227668A7AF57156B1293C992E542978710774B8CBD2984C3DDCB8AC30F36F27` |
| SSDEEP | `49152:X8JY14H9AIK4soeI/K/0yyqBW9SwP1gPnG2:+MIKhlPG2` |
| ICON-DHASH | `a2455d31716951a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_74d90413
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74d90413c20a548c1849f9b9e42a947441055589ba06430cade9ab40d38f7539"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-15 23:07:10"
  condition:
    hash.sha256(0, filesize) == "74d90413c20a548c1849f9b9e42a947441055589ba06430cade9ab40d38f7539"
}
```

### Sample 30: `05a95ecd3164c572`

| Field | Value |
|---|---|
| SHA-256 | `05a95ecd3164c57248d473c93032981bb6004336c85fe888b42cd6294fcf9ede` |
| Family label | `unknown` |
| File name | `Gmail 2024.11.24.702067492.Release.zip` |
| File type | `zip` |
| First seen | `2026-08-15 22:56:34` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e7cce24ef14e494cd1ac4de00741e1b` |
| SHA-1 | `eb468bfab452179c897e80e12933299b78e3f1f9` |
| SHA-256 | `05a95ecd3164c57248d473c93032981bb6004336c85fe888b42cd6294fcf9ede` |
| SHA3-384 | `3338f35d6c0dadea2240bec12db2db41ad2626c69371fa14191a8c9b6f18296d31e39f8a2813d8731db646dcd9441bb8` |
| TLSH | `T1A0A733CE42638D0C3ECF84D4464BC550937AAEDDFEA29627169143CA220BFB4EB954F5` |
| SSDEEP | `786432:DsFZKiVq/khxd2pVpVf5IX68Mj8YyPcDWOKHYMzmx2xjH7thVcHaMd3EZ8heLf85:AUiw/Id2PpIX/MIfK/T8JBc6M+CeLU5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_05a95ecd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a95ecd3164c57248d473c93032981bb6004336c85fe888b42cd6294fcf9ede"
    family = "unknown"
    file_name = "Gmail 2024.11.24.702067492.Release.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:56:34"
  condition:
    hash.sha256(0, filesize) == "05a95ecd3164c57248d473c93032981bb6004336c85fe888b42cd6294fcf9ede"
}
```

### Sample 31: `8dd8e9290fed01c0`

| Field | Value |
|---|---|
| SHA-256 | `8dd8e9290fed01c0f7f9fb7e01264368ec8d53ae57b68ce73ad45facc26712f5` |
| Family label | `unknown` |
| File name | `BetterSurvival-CurseForge.zip` |
| File type | `zip` |
| First seen | `2026-08-15 22:53:38` |
| Reporter | `qvmt` |
| Tags | `Dev7Gang, dropper, microstealer, minecraft, modpack, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `337741007219c8ef0ba66f31ffdf5917` |
| SHA-1 | `bc7919c0e3666ce79e1eb95d6d8fe3e9715fa1ba` |
| SHA-256 | `8dd8e9290fed01c0f7f9fb7e01264368ec8d53ae57b68ce73ad45facc26712f5` |
| SHA3-384 | `683d8e17578075949e896b79bc412d4de20800298f75aa4d024bb4cd579ae022592ce89354bbb7416f26829d6ee1bf52` |
| TLSH | `T1EBB423058B19CBC9DC20F1FBC81A7835610BBE6FE7562A75B8E093F1850DC2E4B95B91` |
| SSDEEP | `12288:Gfb/fPhj2w8YiVJ3zFih6SjdfXkrPeb+5VJXPJUxpp:Gfb3Phj2w8nVFk6u9I2CHNQH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_8dd8e929
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dd8e9290fed01c0f7f9fb7e01264368ec8d53ae57b68ce73ad45facc26712f5"
    family = "unknown"
    file_name = "BetterSurvival-CurseForge.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:53:38"
  condition:
    hash.sha256(0, filesize) == "8dd8e9290fed01c0f7f9fb7e01264368ec8d53ae57b68ce73ad45facc26712f5"
}
```

### Sample 32: `4b00c7ebad267025`

| Field | Value |
|---|---|
| SHA-256 | `4b00c7ebad267025b84e7b4d1c996eaefec34a065913d73ee0070b119217d1be` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-08-15 22:52:39` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, dropped-by-OffLoader, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62880a1fb862a5daa8685846a387f379` |
| SHA-1 | `2a45af2503eb748407bc0536b982333b268f872d` |
| SHA-256 | `4b00c7ebad267025b84e7b4d1c996eaefec34a065913d73ee0070b119217d1be` |
| SHA3-384 | `d06454dce49baff12ba519267e51f37802ccfabfcc1050f96ccf516ae98c91b1dc011f45be3017bce2e968489f4d03b2` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1FF75231153F959B2E43A83B8D9E0C5936631FE529BB942CB22C8D85B5E237C2F635321` |
| SSDEEP | `24576:V8uWkRsNLTBaCu8ZnB16ev1RVNaZLS4I26G7HgMNdnq9lRe7l+CvAIyLZBeBJJer:VvtRsNLUCHB16c3aZGKtU9lReJ+AAMjz` |
| ICON-DHASH | `72b279f4e4d296e7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_4b00c7eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b00c7ebad267025b84e7b4d1c996eaefec34a065913d73ee0070b119217d1be"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-15 22:52:39"
  condition:
    hash.sha256(0, filesize) == "4b00c7ebad267025b84e7b4d1c996eaefec34a065913d73ee0070b119217d1be"
}
```

### Sample 33: `9f09fac52d7f1955`

| Field | Value |
|---|---|
| SHA-256 | `9f09fac52d7f1955d1fec98172c99a6f0d2781e9307fa828b4a7175622da5200` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-15 22:52:34` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29bb20812c23ec162fea4627d6afac1a` |
| SHA-1 | `0f7eeb00cf307945bff825c93dac0769ecc180b1` |
| SHA-256 | `9f09fac52d7f1955d1fec98172c99a6f0d2781e9307fa828b4a7175622da5200` |
| SHA3-384 | `1fe857c2c1b6dcdccd5706e351c177dce6e6a5baee8751c64710e9006aa9e7963320f8240a6b2b6199fcec1427948450` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T169E63348ABE004EAE933947CEAE21790FA76F8710731D4EB579445B1EA631F05C3A727` |
| SSDEEP | `393216:icwapYoC09TtitiJ0zlXMCHWUjFscuI3/PGTAI:SApCGiK0zlXMb8F5H/O7` |
| ICON-DHASH | `e4b960c0dcf97258` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_9f09fac5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f09fac52d7f1955d1fec98172c99a6f0d2781e9307fa828b4a7175622da5200"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-15 22:52:34"
  condition:
    hash.sha256(0, filesize) == "9f09fac52d7f1955d1fec98172c99a6f0d2781e9307fa828b4a7175622da5200"
}
```

### Sample 34: `a980cf0c37b5c96c`

| Field | Value |
|---|---|
| SHA-256 | `a980cf0c37b5c96ceeeab43c2dd8947851efb43985e7b2fb76e9ef855c9b383c` |
| Family label | `unknown` |
| File name | `Norton VPN 4.6.0.241211284.zip` |
| File type | `zip` |
| First seen | `2026-08-15 22:33:27` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8df1ddfc940a1e14b1071a126548db4` |
| SHA-1 | `34f462774d71acfc5492bcfc7b9cd913ad2a693b` |
| SHA-256 | `a980cf0c37b5c96ceeeab43c2dd8947851efb43985e7b2fb76e9ef855c9b383c` |
| SHA3-384 | `ff30b7ffde74365414c9347c569e9defba901b73358da0be3116d2f5f111f5593061904ed0fe7c11b8b4d7476e248ad3` |
| TLSH | `T10D083315A2A3DB076C83C684C5B79A85E1978693791C4CE1A388CA711791FC3F3F3A67` |
| SSDEEP | `1572864:F0PBXxUOjpG2u7WjEp5U1bodzSE6UM7WbMAqdAQ2MqKBncH8isxi3x/lNPhhBj+R:KPBXfjluqjEpkcTO7WE0Mqsnoh3x/lNo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_a980cf0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a980cf0c37b5c96ceeeab43c2dd8947851efb43985e7b2fb76e9ef855c9b383c"
    family = "unknown"
    file_name = "Norton VPN 4.6.0.241211284.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:33:27"
  condition:
    hash.sha256(0, filesize) == "a980cf0c37b5c96ceeeab43c2dd8947851efb43985e7b2fb76e9ef855c9b383c"
}
```

### Sample 35: `9af4e08d55020b41`

| Field | Value |
|---|---|
| SHA-256 | `9af4e08d55020b4182a411f547214d2092887a727f7ec5ae2ead8045bdccd579` |
| Family label | `unknown` |
| File name | `gang.jar` |
| File type | `jar` |
| First seen | `2026-08-15 22:32:04` |
| Reporter | `qvmt` |
| Tags | `cloudflare-worker, dev7gang, discord, infostealer, jar, java, Microstealer, Minecraft, rat, turkish` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e198b6cb97fd1662c6fd6d0cab8ea1c` |
| SHA-1 | `cf126a7264bdf97bd03e0439a4d73623c2dc18b7` |
| SHA-256 | `9af4e08d55020b4182a411f547214d2092887a727f7ec5ae2ead8045bdccd579` |
| SHA3-384 | `aa50a8956cb319f10950b672ee630f3054e233e150eaea6bfc4c187bc96e140ecb369fed2cb8a6f279b7139c6ee4beea` |
| TLSH | `T1F937232BA8DA8929DD7F6DF352C24563642F1ADBEC0B903D36F04DC15972E8B4352728` |
| SSDEEP | `393216:wW8aUyfqgNv9i4/NmvymepNbDzpL4/pKpSpNbaASo3a5vcwm8WHr47:drrv9R1ybScw+uASWtu7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_9af4e08d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9af4e08d55020b4182a411f547214d2092887a727f7ec5ae2ead8045bdccd579"
    family = "unknown"
    file_name = "gang.jar"
    file_type = "jar"
    first_seen = "2026-08-15 22:32:04"
  condition:
    hash.sha256(0, filesize) == "9af4e08d55020b4182a411f547214d2092887a727f7ec5ae2ead8045bdccd579"
}
```

### Sample 36: `c9571e626c47a576`

| Field | Value |
|---|---|
| SHA-256 | `c9571e626c47a576069be0c893bba4de8dc3762602329ab9c2e36ccc48883570` |
| Family label | `unknown` |
| File name | `Norton Password Manager 8.8.0.apk.zip` |
| File type | `zip` |
| First seen | `2026-08-15 22:26:00` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d30c352d8e6e5dfa8de7a13ca6d0141` |
| SHA-1 | `d83114e807bdc071d2a73e177cc9a832621c04f3` |
| SHA-256 | `c9571e626c47a576069be0c893bba4de8dc3762602329ab9c2e36ccc48883570` |
| SHA3-384 | `405a6673351d08ec6ffca4508cae4412afd1b0f360d4cbd2479a9007e62c84857105b89a9e3a0815118b2fa1fbac9172` |
| TLSH | `T12F1833A47C240A779D12E71FE8363E1C71ED0785BA2D7B8ED5EB4E254700AD8A4673C2` |
| SSDEEP | `1572864:U9QJW45YTdb76At1nCXETBwgFZ2YZ4gFq8YKNTXwjESkBIhpTeWCJbAq2bx3qkym:Um55YTpZUEyA2YZ4HjKJXwj7kARf/rtV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_c9571e62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9571e626c47a576069be0c893bba4de8dc3762602329ab9c2e36ccc48883570"
    family = "unknown"
    file_name = "Norton Password Manager 8.8.0.apk.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:26:00"
  condition:
    hash.sha256(0, filesize) == "c9571e626c47a576069be0c893bba4de8dc3762602329ab9c2e36ccc48883570"
}
```

### Sample 37: `394cead068f1b53b`

| Field | Value |
|---|---|
| SHA-256 | `394cead068f1b53b5811da091af6576eaa10d416068f5d985c5169f5cd9cd06f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 22:21:11` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81b0bc7693bc662fe6da4cce1f1517aa` |
| SHA-256 | `394cead068f1b53b5811da091af6576eaa10d416068f5d985c5169f5cd9cd06f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_394cead0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "394cead068f1b53b5811da091af6576eaa10d416068f5d985c5169f5cd9cd06f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 22:21:11"
  condition:
    hash.sha256(0, filesize) == "394cead068f1b53b5811da091af6576eaa10d416068f5d985c5169f5cd9cd06f"
}
```

### Sample 38: `4ef22d6fc5eb913c`

| Field | Value |
|---|---|
| SHA-256 | `4ef22d6fc5eb913c3e3c8e9a42dc9511285b8927524bb9831ba8de8f49960bd7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 22:21:04` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e246b54ff8a59d649c20e8e64027a598` |
| SHA-1 | `520fc63c9c9f0166ec36062b8d855718f6127a39` |
| SHA-256 | `4ef22d6fc5eb913c3e3c8e9a42dc9511285b8927524bb9831ba8de8f49960bd7` |
| SHA3-384 | `270103643c115e017ed884527cc4553ccfd99579d954d29eca00a031bf083b4565211246a95966e3d6a0c5f86c429568` |
| TLSH | `T15814EA4088B5CD071DD53FBC7C9B6E021E8A62C2A5F04907BB745A6836F49FE31DA64B` |
| SSDEEP | `3072:oe2utktU7avWMGJmJ4HmH7qv1XDY00jbZe8z8SdKr+xu5Lfb1BKZ/8ZL0fEoWQTS:oTddu5gxb8Vf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_4ef22d6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef22d6fc5eb913c3e3c8e9a42dc9511285b8927524bb9831ba8de8f49960bd7"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 22:21:04"
  condition:
    hash.sha256(0, filesize) == "4ef22d6fc5eb913c3e3c8e9a42dc9511285b8927524bb9831ba8de8f49960bd7"
}
```

### Sample 39: `2b7f489a23c21ae4`

| Field | Value |
|---|---|
| SHA-256 | `2b7f489a23c21ae46e1bb87c129a141bc1b7b7e1b9669cd83cedcbd1e9697b28` |
| Family label | `unknown` |
| File name | `hutepkeazyauxbqsiykw.dll` |
| File type | `exe` |
| First seen | `2026-08-15 22:07:03` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5295e774069a31cd3dee5bb6f5ddf718` |
| SHA-1 | `5dc785461f2c7d5d9ad1514490f1d424b93d59da` |
| SHA-256 | `2b7f489a23c21ae46e1bb87c129a141bc1b7b7e1b9669cd83cedcbd1e9697b28` |
| SHA3-384 | `72fb58525e05d0173ec04f3b6ed1c66f509e946e08828c3bba629184f83913dd0c8c86331422a8e15925f8bee4eeb455` |
| IMPHASH | `545ab5f5e725852666113bb96037b688` |
| TLSH | `T14E062C3227668A7AF57156B1293C992E542978710774B8CBD2984C3DDCB8AC30F36F27` |
| SSDEEP | `49152:X8JY14H9AIK4soeI/K/0yyqBW9SwP1gPnGC:+MIKhlPGC` |
| ICON-DHASH | `a2455d31716951a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_2b7f489a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b7f489a23c21ae46e1bb87c129a141bc1b7b7e1b9669cd83cedcbd1e9697b28"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-15 22:07:03"
  condition:
    hash.sha256(0, filesize) == "2b7f489a23c21ae46e1bb87c129a141bc1b7b7e1b9669cd83cedcbd1e9697b28"
}
```

### Sample 40: `cc57e487bbddc0c2`

| Field | Value |
|---|---|
| SHA-256 | `cc57e487bbddc0c26eccb758c92843e935a329cd706bbaa24537726f45a0de5d` |
| Family label | `unknown` |
| File name | `Norton Identity 1.86.apk.zip` |
| File type | `zip` |
| First seen | `2026-08-15 22:00:55` |
| Reporter | `anonymous` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fff2e2a3f65c14acab1a0a977dca29e` |
| SHA-1 | `cdb5487f8b90269d9af8c2089a7cb6d6ff71fabd` |
| SHA-256 | `cc57e487bbddc0c26eccb758c92843e935a329cd706bbaa24537726f45a0de5d` |
| SHA3-384 | `6cc1e5476c497e05dffe1ed56ce88b5d67505b8e1fbcb9bbbeaa8250bc6325f2d6b747ee1d399d7b04d29078c61cc185` |
| TLSH | `T126183326D1016E2FBDF69FE25C42848C1BF0D0B6B55992503AE800D75DC2B2FB6AE4D7` |
| SSDEEP | `1572864:lnip9aCDktMFPiL11C4zrR6TMjncqOLKYPjJxKbSBmegMNb8H8ur4D:li19kx1XrAcncvLXxDwnMNwT8D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_cc57e487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc57e487bbddc0c26eccb758c92843e935a329cd706bbaa24537726f45a0de5d"
    family = "unknown"
    file_name = "Norton Identity 1.86.apk.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:00:55"
  condition:
    hash.sha256(0, filesize) == "cc57e487bbddc0c26eccb758c92843e935a329cd706bbaa24537726f45a0de5d"
}
```

### Sample 41: `df159312ca87597d`

| Field | Value |
|---|---|
| SHA-256 | `df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab` |
| Family label | `unknown` |
| File name | `df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab.exe` |
| File type | `exe` |
| First seen | `2026-08-15 21:50:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65ffe90682aa5cf556327ac9a21e179c` |
| SHA-1 | `9c46f1ba9a5a1ae2be5ff2884ccfc3f30ac4c72c` |
| SHA-256 | `df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab` |
| SHA3-384 | `6a8a016fecf40c245165ebf709bfef8312a1f79b93e88a268cd8749ee929ad527875f021a2c223778266d4d86748a801` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T1FDD5235DBDE632F1F072C36B92A375FDB21A37418AA44C9E36887B101D2261D2D73369` |
| SSDEEP | `49152:kICNw5tymip4xbZWObh/E2wLiLKw4rVmvQ9adceMEj:kIkwmz4xbQObhwWiqQQceME` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_df159312
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab"
    family = "unknown"
    file_name = "df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab.exe"
    file_type = "exe"
    first_seen = "2026-08-15 21:50:10"
  condition:
    hash.sha256(0, filesize) == "df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab"
}
```

### Sample 42: `9b2a69e414035f34`

| Field | Value |
|---|---|
| SHA-256 | `9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0` |
| Family label | `unknown` |
| File name | `9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0.exe` |
| File type | `exe` |
| First seen | `2026-08-15 21:44:53` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc4d3c10e2b60645c9d4e98c9629bd23` |
| SHA-1 | `f969fead42ce7bb8cc5ab9a151fb5455b0ac292e` |
| SHA-256 | `9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0` |
| SHA3-384 | `b9654b40b1af0fa4834e849231b2b613b4afbf4130a5e72b2d0b378f84e8f4471c7e54ce0a14e5fa8a56884296947fae` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T106D5239AB8F31A74C437C7B25ED9E46E70287B804BA48CA3B7ECA9046D735441E35379` |
| SSDEEP | `49152:ERA0ARbrCv9l1APbQsdcNSsb5ezD+wWwAjYnq0FF5Rvv3Lxob+b2VHbO:r08g1U7cNPbczuwMYnqw5Rv+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_9b2a69e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0"
    family = "unknown"
    file_name = "9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0.exe"
    file_type = "exe"
    first_seen = "2026-08-15 21:44:53"
  condition:
    hash.sha256(0, filesize) == "9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0"
}
```

### Sample 43: `c2d74739b4901f63`

| Field | Value |
|---|---|
| SHA-256 | `c2d74739b4901f631cc38c49f1f4d1bf20fe1974d70ce1c441866faad6699a77` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 21:20:47` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa86b1e7df88e548321fa26286327f90` |
| SHA-256 | `c2d74739b4901f631cc38c49f1f4d1bf20fe1974d70ce1c441866faad6699a77` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_c2d74739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d74739b4901f631cc38c49f1f4d1bf20fe1974d70ce1c441866faad6699a77"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 21:20:47"
  condition:
    hash.sha256(0, filesize) == "c2d74739b4901f631cc38c49f1f4d1bf20fe1974d70ce1c441866faad6699a77"
}
```

### Sample 44: `4b45e9f2f4a8ec34`

| Field | Value |
|---|---|
| SHA-256 | `4b45e9f2f4a8ec346023246d7c0e4ae081c42289d53df7b621693eb893bf9d9a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 21:20:40` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a71f523e43f6477436babf58ddbff32` |
| SHA-256 | `4b45e9f2f4a8ec346023246d7c0e4ae081c42289d53df7b621693eb893bf9d9a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_4b45e9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b45e9f2f4a8ec346023246d7c0e4ae081c42289d53df7b621693eb893bf9d9a"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 21:20:40"
  condition:
    hash.sha256(0, filesize) == "4b45e9f2f4a8ec346023246d7c0e4ae081c42289d53df7b621693eb893bf9d9a"
}
```

### Sample 45: `18f35470bd811ed2`

| Field | Value |
|---|---|
| SHA-256 | `18f35470bd811ed20ed636f7a58b101428ab784ee1eff4ba902a4638b5e55823` |
| Family label | `unknown` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-15 21:00:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bca7093fb1ceadc096b9d0473d74dc2f` |
| SHA-1 | `19fc42d91e4132c890e4d1df94061dd0828b7d2e` |
| SHA-256 | `18f35470bd811ed20ed636f7a58b101428ab784ee1eff4ba902a4638b5e55823` |
| SHA3-384 | `1a291321b3fa132069aebf8fc3fa4cd03afc11134c4d93ff027ace91b37a9ce858f8794d42990e1c79693df411bf4cae` |
| TLSH | `T18F741759F880DB6186C539BAFA1D46AC730707B9D3EB71068E154B3437EB86B0F3A611` |
| SSDEEP | `6144:2E9BBcL28noUlu2pAcJYXG2BxBKDfamOTgZ9RI+iLu9fyhapJ54XHv1DLh2xy:V9BqL2Md3AsGmtOyRIRkVr4Noy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_18f35470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18f35470bd811ed20ed636f7a58b101428ab784ee1eff4ba902a4638b5e55823"
    family = "unknown"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-15 21:00:53"
  condition:
    hash.sha256(0, filesize) == "18f35470bd811ed20ed636f7a58b101428ab784ee1eff4ba902a4638b5e55823"
}
```

### Sample 46: `be9cb31ff1434c8d`

| Field | Value |
|---|---|
| SHA-256 | `be9cb31ff1434c8dd13ab72a3046b2c0383272f0c0a2bdf95c1e35045c8b1206` |
| Family label | `unknown` |
| File name | `KimiK3-Desktop.exe` |
| File type | `exe` |
| First seen | `2026-08-15 21:00:44` |
| Reporter | `Alex_sev` |
| Tags | `electron, exe, infostealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd99cac210dd56ad90279ac3fb7ad8b6` |
| SHA-1 | `2fc58f7c6e84ae9968958371d5f3f20c3cc897bb` |
| SHA-256 | `be9cb31ff1434c8dd13ab72a3046b2c0383272f0c0a2bdf95c1e35045c8b1206` |
| SHA3-384 | `681377ac05df6b34e7daf0c61ffb81e3dca40ae6f4f9ab29c7787d0ae4c2d64c8360c22f0101baa53d19d1378d3ff2b5` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1F1F7337CF234B6AFE7C19B7FA40614EAD3499DA60596142EBD3F24D378304809A2D91F` |
| SSDEEP | `1572864:xejOYfa8Qjo6duNjPt1a2C2Uh2Qr9xuTJdpdbdNSpzmnc7:x4mdduhF1a2Cfr9IRYpuc7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_be9cb31f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be9cb31ff1434c8dd13ab72a3046b2c0383272f0c0a2bdf95c1e35045c8b1206"
    family = "unknown"
    file_name = "KimiK3-Desktop.exe"
    file_type = "exe"
    first_seen = "2026-08-15 21:00:44"
  condition:
    hash.sha256(0, filesize) == "be9cb31ff1434c8dd13ab72a3046b2c0383272f0c0a2bdf95c1e35045c8b1206"
}
```

### Sample 47: `a3300d7839219589`

| Field | Value |
|---|---|
| SHA-256 | `a3300d78392195891d7498b4bd518dd7631f1108ecef6f290586a18d08410875` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-15 20:58:52` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2dbd7e39dd7fcf7364a3342a4e81920` |
| SHA-1 | `eb1a32e904a6a1a7a16990fc6f518bce8608d7c9` |
| SHA-256 | `a3300d78392195891d7498b4bd518dd7631f1108ecef6f290586a18d08410875` |
| SHA3-384 | `e88191177644faed8a60e62575b90f81ca19bfbdcf20542363ac0a435fcd9c4007110303405dee4c313c51204e309845` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T130E62237B28A753EE06E1A355AB7D210593B7A50AC138D1ED6E448ACCF251A03E3F747` |
| SSDEEP | `98304:VAX77EVBH6ImfB/NqyINdFsbMvYEJHrmR1c011Vzp0oRPcr6DJKHl3NK:U7EXaI6/NqyIpZvY91zpDI6DcHl3N` |
| ICON-DHASH | `94b4b5e4d060e4d8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_a3300d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3300d78392195891d7498b4bd518dd7631f1108ecef6f290586a18d08410875"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-15 20:58:52"
  condition:
    hash.sha256(0, filesize) == "a3300d78392195891d7498b4bd518dd7631f1108ecef6f290586a18d08410875"
}
```

### Sample 48: `1253cb1483d3bb5f`

| Field | Value |
|---|---|
| SHA-256 | `1253cb1483d3bb5f1e7e0cd3d53c722e4e2e69483b4070404c3ba75844994b39` |
| Family label | `unknown` |
| File name | `v2.4.1.exe` |
| File type | `exe` |
| First seen | `2026-08-15 20:58:08` |
| Reporter | `Alex_sev` |
| Tags | `electron, exe, infostealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d4635354dd6d6422ce85f80538c4872` |
| SHA-1 | `ebafb1579d78dafda3a7dd102d1cae6b25fabca4` |
| SHA-256 | `1253cb1483d3bb5f1e7e0cd3d53c722e4e2e69483b4070404c3ba75844994b39` |
| SHA3-384 | `0a2f899639c86d688b83db2ab23573003338c1b91abc9534d7fdcd03dc2011023f7f6d37ce4c2c44d035e154fafaf2b9` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T111183386AE52E17FE803C433E12D63FA534EE0965A138B9B223F54CEFCA1711675449B` |
| SSDEEP | `1572864:Qz2um44Hi2LLbv8+2P4zg1nNHG3cv4JW4/KMYAMvJmiftzjPzcsZM2AWUQriXyZ:QzTm4vwLblQR9NYJo+sUifljLcs22//` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_1253cb14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1253cb1483d3bb5f1e7e0cd3d53c722e4e2e69483b4070404c3ba75844994b39"
    family = "unknown"
    file_name = "v2.4.1.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:58:08"
  condition:
    hash.sha256(0, filesize) == "1253cb1483d3bb5f1e7e0cd3d53c722e4e2e69483b4070404c3ba75844994b39"
}
```

### Sample 49: `b199f70d109357f8`

| Field | Value |
|---|---|
| SHA-256 | `b199f70d109357f81c2f147318b424d91fd635449b19c9610f50e428a0c68e8e` |
| Family label | `unknown` |
| File name | `WindowsCodecs.dll` |
| File type | `exe` |
| First seen | `2026-08-15 20:56:39` |
| Reporter | `anonymous` |
| Tags | `ClickFix, ErrTraffic, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1a8d79d8ff317565789b1f1cb7de12a` |
| SHA-1 | `6098ef165b028473374f9a5f8612239dee3f1144` |
| SHA-256 | `b199f70d109357f81c2f147318b424d91fd635449b19c9610f50e428a0c68e8e` |
| SHA3-384 | `b10399efce5f7e91e1fef0e308641f9c3eace5e4fe102a256bb97e6ba31592118f14f3849d147350e786250314373750` |
| IMPHASH | `5f0c7d1f982df032661d8c3435af07cc` |
| TLSH | `T1FBE2730F5F099665ED3E267951BA8DC2F378B2644331C8EB6D80981E0D42BCAD735EC9` |
| SSDEEP | `768:OPL/F/k9fCyqYmnZzBeWUjuESb90sngUg/ijhAFMRQ:Mdk9fCrQHe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_b199f70d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b199f70d109357f81c2f147318b424d91fd635449b19c9610f50e428a0c68e8e"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-15 20:56:39"
  condition:
    hash.sha256(0, filesize) == "b199f70d109357f81c2f147318b424d91fd635449b19c9610f50e428a0c68e8e"
}
```

### Sample 50: `fdba2c8f46d4a461`

| Field | Value |
|---|---|
| SHA-256 | `fdba2c8f46d4a4617c2580b3bcaf106076c73b4f906756987b63c6492dedfa0c` |
| Family label | `unknown` |
| File name | `Setup_app.exe` |
| File type | `exe` |
| First seen | `2026-08-15 20:56:25` |
| Reporter | `Alex_sev` |
| Tags | `electron, exe, infostealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a301c14f61961f5b0803fc9a288b90a` |
| SHA-1 | `dd25a55c537539804b1e857751ff66cb2165e0b8` |
| SHA-256 | `fdba2c8f46d4a4617c2580b3bcaf106076c73b4f906756987b63c6492dedfa0c` |
| SHA3-384 | `c622046a7f4d9624d6611dcb77c1cf4a2ffdab9b83179e03631b55c89c9890307fc5a5d8bed029e87709fd96fa4d8550` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T11BF733E93F9CE4BDC074AA7673842C9F5A2E43600A4F5E714B7501DFA19A91C0E64B3E` |
| SSDEEP | `1572864:tejOYfnmFnXmx9tSVR0AsjwZ+uyFXIrNXPRZsY+V5E87:t4vdLtSVfsEZoXIr21U87` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_fdba2c8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdba2c8f46d4a4617c2580b3bcaf106076c73b4f906756987b63c6492dedfa0c"
    family = "unknown"
    file_name = "Setup_app.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:56:25"
  condition:
    hash.sha256(0, filesize) == "fdba2c8f46d4a4617c2580b3bcaf106076c73b4f906756987b63c6492dedfa0c"
}
```

### Sample 51: `4252c98558bda800`

| Field | Value |
|---|---|
| SHA-256 | `4252c98558bda800c93925ae8691d1c35d7db57cbc64eddc2451ddf1e780034c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-15 20:45:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7113c399410f8aa332725167d9e20a38` |
| SHA-1 | `974ad011978eb245ee0ca01f9148fea433502e31` |
| SHA-256 | `4252c98558bda800c93925ae8691d1c35d7db57cbc64eddc2451ddf1e780034c` |
| SHA3-384 | `3ac18e46ac519d10d104540fb127730a903d06a87d0bc394bbab2884798a2d1b3c8a65f81f97fafa6e76acddc8688dd9` |
| TLSH | `T156C27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:QR8vCB+25j6es8R/9FYpMSUpi+20qUpi+20YQX:QR8l25JJd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_4252c985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4252c98558bda800c93925ae8691d1c35d7db57cbc64eddc2451ddf1e780034c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:45:50"
  condition:
    hash.sha256(0, filesize) == "4252c98558bda800c93925ae8691d1c35d7db57cbc64eddc2451ddf1e780034c"
}
```

### Sample 52: `be5770a2afb56481`

| Field | Value |
|---|---|
| SHA-256 | `be5770a2afb56481bffd96417857e34d8d96c2b078434645d9aed990ca2c0764` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-15 20:37:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dff0606f48af91d3324ea216c9dde872` |
| SHA-1 | `ce07d9c1b3e9cf5c44eb1906e688f3cae5f72e44` |
| SHA-256 | `be5770a2afb56481bffd96417857e34d8d96c2b078434645d9aed990ca2c0764` |
| SHA3-384 | `8c11ed9b85fbe0464841f687cb6bb61326421e75fc56d18316c6d37302727f97b4ef16ed082bbcb7abecb7b47fcb717e` |
| TLSH | `T179236D661A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCB3CF28C5A69D911871D` |
| SSDEEP | `768:fXRWNGxVk9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Zlx3cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_be5770a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be5770a2afb56481bffd96417857e34d8d96c2b078434645d9aed990ca2c0764"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:37:50"
  condition:
    hash.sha256(0, filesize) == "be5770a2afb56481bffd96417857e34d8d96c2b078434645d9aed990ca2c0764"
}
```

### Sample 53: `71bcb1ff944476d0`

| Field | Value |
|---|---|
| SHA-256 | `71bcb1ff944476d06565e1b4ebc6aa74712ecfb8ef4dd0e581f440ebb87fff1e` |
| Family label | `Mirai` |
| File name | `ohshit.sh` |
| File type | `sh` |
| First seen | `2026-08-15 20:29:47` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64a547c9b1970e6ebdf9c1d2d10f39bc` |
| SHA-1 | `eb27c1575b8bfea55bb8787632f0b20eb8332cf0` |
| SHA-256 | `71bcb1ff944476d06565e1b4ebc6aa74712ecfb8ef4dd0e581f440ebb87fff1e` |
| SHA3-384 | `9d6b191815d0f7079e4a73fd8b2c3c958f140f8db48a1767a26a1cfaecf4bf84637f27973c070a1290da9797224091ca` |
| TLSH | `T190816492B572C5B1358F443EDF8F92907A83192F8D1ABD05B44E28542F3D57470B87B9` |
| SSDEEP | `96:VGaR6xmPOFQNDRz9u8m9D0k2N/Xb7xgLpY8CiKmkSSYbN0FbuQvMSW4Gl:cj7uZakSDbN0JuQvMMW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_71bcb1ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71bcb1ff944476d06565e1b4ebc6aa74712ecfb8ef4dd0e581f440ebb87fff1e"
    family = "Mirai"
    file_name = "ohshit.sh"
    file_type = "sh"
    first_seen = "2026-08-15 20:29:47"
  condition:
    hash.sha256(0, filesize) == "71bcb1ff944476d06565e1b4ebc6aa74712ecfb8ef4dd0e581f440ebb87fff1e"
}
```

### Sample 54: `4819d87fe9d0d048`

| Field | Value |
|---|---|
| SHA-256 | `4819d87fe9d0d0485fe85a3843a3e3ecd61ebe50a115dad01ec10275272be82a` |
| Family label | `unknown` |
| File name | `NPE.exe` |
| File type | `exe` |
| First seen | `2026-08-15 20:28:20` |
| Reporter | `anonymous` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddfc82cf4eab81965e3ec8ca8915b00a` |
| SHA-1 | `1e5b94be6922e6198afe39a7fc695db291bffcf6` |
| SHA-256 | `4819d87fe9d0d0485fe85a3843a3e3ecd61ebe50a115dad01ec10275272be82a` |
| SHA3-384 | `09d6c138b1bb323f5168011e85e4b8e28d06d6aa1beb6c9cb39fb294f13965746e3a5c927deb07a50d334662f2deebf1` |
| IMPHASH | `6e0dcaca7f0e80510d06b4087b95e6f7` |
| TLSH | `T18D076D16BAF040F4D1B6C2B8C5619A56FAB179861F32828F716C527B1F339B18D3E325` |
| SSDEEP | `196608:dm9mJUAMfMvgTz2ENNFV8pYrqNpEdYo1NTXPJb:sCMfMQz2Ev8+rqNp1yXPJb` |
| ICON-DHASH | `cc2e2b4d492b174d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_4819d87f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4819d87fe9d0d0485fe85a3843a3e3ecd61ebe50a115dad01ec10275272be82a"
    family = "unknown"
    file_name = "NPE.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:28:20"
  condition:
    hash.sha256(0, filesize) == "4819d87fe9d0d0485fe85a3843a3e3ecd61ebe50a115dad01ec10275272be82a"
}
```

### Sample 55: `01156f0a356a50cc`

| Field | Value |
|---|---|
| SHA-256 | `01156f0a356a50cc73e012fb88bfdd1a8e06f2db452424d1fe71ed2914b5b641` |
| Family label | `unknown` |
| File name | `hutepkeazyauxbqsiykw.dll` |
| File type | `exe` |
| First seen | `2026-08-15 20:21:13` |
| Reporter | `monitorsg` |
| Tags | `ClearFake, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e98ea046a7074d46db99bf8d6bf0ed9` |
| SHA-1 | `a50a0f6523d0c81ee6df780dedae9b0a5bf1980a` |
| SHA-256 | `01156f0a356a50cc73e012fb88bfdd1a8e06f2db452424d1fe71ed2914b5b641` |
| SHA3-384 | `9fa7e9f0c5a5f7c450e62e2b1b3d45bf92f88611a196a3086d9c44c0aff420479c1e3541a5a617d74cf50c3b8d3263d0` |
| IMPHASH | `545ab5f5e725852666113bb96037b688` |
| TLSH | `T1E6062C3227668A7AF57156B1293C992E542978710774B8CBD2984C3DDCB8AC30F36F27` |
| SSDEEP | `49152:X8JY14H9AIK4soeI/K/0yyqBW9SwP1gPnG6:+MIKhlPG6` |
| ICON-DHASH | `a2455d31716951a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_01156f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01156f0a356a50cc73e012fb88bfdd1a8e06f2db452424d1fe71ed2914b5b641"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-15 20:21:13"
  condition:
    hash.sha256(0, filesize) == "01156f0a356a50cc73e012fb88bfdd1a8e06f2db452424d1fe71ed2914b5b641"
}
```

### Sample 56: `9f18f8d711960456`

| Field | Value |
|---|---|
| SHA-256 | `9f18f8d711960456bb6b6dc8eb7d0853943f204b147c344dfb3e1eabf8f8004c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 20:20:24` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a202d456113678cb2ea44d7d5ec81bee` |
| SHA-256 | `9f18f8d711960456bb6b6dc8eb7d0853943f204b147c344dfb3e1eabf8f8004c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_9f18f8d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f18f8d711960456bb6b6dc8eb7d0853943f204b147c344dfb3e1eabf8f8004c"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 20:20:24"
  condition:
    hash.sha256(0, filesize) == "9f18f8d711960456bb6b6dc8eb7d0853943f204b147c344dfb3e1eabf8f8004c"
}
```

### Sample 57: `c76dacd838f61547`

| Field | Value |
|---|---|
| SHA-256 | `c76dacd838f6154778b347ccf7928eaab5ce0a17aceec8ff65bed775839fdc6d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 20:20:16` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c31f294c6a3a881c21f0fc6a93a6319` |
| SHA-256 | `c76dacd838f6154778b347ccf7928eaab5ce0a17aceec8ff65bed775839fdc6d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_c76dacd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76dacd838f6154778b347ccf7928eaab5ce0a17aceec8ff65bed775839fdc6d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 20:20:16"
  condition:
    hash.sha256(0, filesize) == "c76dacd838f6154778b347ccf7928eaab5ce0a17aceec8ff65bed775839fdc6d"
}
```

### Sample 58: `74e636d09c7a51ad`

| Field | Value |
|---|---|
| SHA-256 | `74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2` |
| Family label | `unknown` |
| File name | `74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2.exe` |
| File type | `exe` |
| First seen | `2026-08-15 20:19:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76a88cd201682a01feac1b9a7e57832e` |
| SHA-1 | `ed16d4afee0f43656cfacc8d5affd930548cf788` |
| SHA-256 | `74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2` |
| SHA3-384 | `ac1e71ae7f9f10d318e369a7112db02a5808b54406c38fc328d0a23da30fe1dd3018bf7f7da73788a693ef4ae9d0c676` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T170D523C9B9B32E74C467C3B28F82F53DB1597B848BA48E07F6CD6A049D62444587E372` |
| SSDEEP | `49152:0UUxc7Ngd5DTEQaRFgFC2SBrtEXNHGqfCBB4s+vPMFO9zFFp9ABBfsA2:d2dZsEgBrkHGT1FE3AB9n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_74e636d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2"
    family = "unknown"
    file_name = "74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:19:49"
  condition:
    hash.sha256(0, filesize) == "74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2"
}
```

### Sample 59: `04ef8195e31b65bf`

| Field | Value |
|---|---|
| SHA-256 | `04ef8195e31b65bf80ab31d7c97806e39bd90ef274a72708b55e8f6675ee72ed` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-15 20:17:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36dd0456a68e3b02a73322f0ef660b0f` |
| SHA-1 | `4d7a74c9c330163dd52b253efd05769eea45d4fe` |
| SHA-256 | `04ef8195e31b65bf80ab31d7c97806e39bd90ef274a72708b55e8f6675ee72ed` |
| SHA3-384 | `623a063617d5254b530b85a861ba7b5cde39108c22a4cefe955fbf50e5f452748633fd996659602701897d254604dd93` |
| TLSH | `T152236C651A857C149E98C4371D7E2F0CB9AD43E6321852DE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:7VEJVIhtM79GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:hEJ2MMcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_04ef8195
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef8195e31b65bf80ab31d7c97806e39bd90ef274a72708b55e8f6675ee72ed"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:17:43"
  condition:
    hash.sha256(0, filesize) == "04ef8195e31b65bf80ab31d7c97806e39bd90ef274a72708b55e8f6675ee72ed"
}
```

### Sample 60: `caa892bff7c26454`

| Field | Value |
|---|---|
| SHA-256 | `caa892bff7c2645416a867c85a9c3d58c491e4bb130b8894d19fc1233ce91bec` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-15 20:15:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b49f3260e3b44f5a83117e58998a2ebc` |
| SHA-1 | `c4439b124e688462b03d00cfc74d808a83fcc117` |
| SHA-256 | `caa892bff7c2645416a867c85a9c3d58c491e4bb130b8894d19fc1233ce91bec` |
| SHA3-384 | `6c21de13ee3dbf9110d624815e359e39e73d6f55beedfc28089659b3a3ee763d4d567477094123a65134c51816d3ab4d` |
| TLSH | `T135C27D966A867C44BEC94A3E4CBD2B0D6DF5C3D1324952AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:w8vCB+25j6es8Rdi9FYpMSUpi+20qUpi+20YQX:w8l25JSd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_caa892bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa892bff7c2645416a867c85a9c3d58c491e4bb130b8894d19fc1233ce91bec"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:15:47"
  condition:
    hash.sha256(0, filesize) == "caa892bff7c2645416a867c85a9c3d58c491e4bb130b8894d19fc1233ce91bec"
}
```

### Sample 61: `f91b79e3699ef2eb`

| Field | Value |
|---|---|
| SHA-256 | `f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef` |
| Family label | `unknown` |
| File name | `f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef.exe` |
| File type | `exe` |
| First seen | `2026-08-15 20:14:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afb477b02aa1cfb5dd7a9267a99f2c31` |
| SHA-1 | `5217d9312259ddd962672062fdf771ab59a557bc` |
| SHA-256 | `f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef` |
| SHA3-384 | `8e51a90dda8d9f1b63e429bd6f28c469e2ccd8c51a3fc34f731fac2960f8989656d42371266c08cc577d4f312396ca33` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1143633E699C21174C062C3B9895B35ADF13A7BB0C6617D2B39DC1E289E9FE05543E3C2` |
| SSDEEP | `98304:Cf0F9I3QIw22S6OGJy+6rp0/4tbEwxBF+7VeTW6mHXMVvmidAz5uuNhqtf:pF91ha8Jl6rpxAOHvTW6eXxlhqt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_f91b79e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef"
    family = "unknown"
    file_name = "f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:14:54"
  condition:
    hash.sha256(0, filesize) == "f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef"
}
```

### Sample 62: `70c037b40986a30f`

| Field | Value |
|---|---|
| SHA-256 | `70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae` |
| Family label | `Mirai` |
| File name | `70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae.elf` |
| File type | `elf` |
| First seen | `2026-08-15 19:54:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1635a17035cb498c4d3593c82e202c0c` |
| SHA-1 | `3825a31b8d7bd6a0b8ecad9640c554cd716300bc` |
| SHA-256 | `70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae` |
| SHA3-384 | `33bed5210f6f483647fec29e91202f20d833189ad2c97b443fb743c32b016d4bf76bd0ad7941d86a8c9fbd7285e70a8d` |
| TLSH | `T188C316827F829A41C3D0907FEB0AFD8D6715E397C2DFF7470D612F0365968660E6A922` |
| TELFHASH | `t199318f509f8c2de877e04e19438fb31b7c8235e6ea3369235dab654f4b23692b435439` |
| SSDEEP | `1536:T44jzW9gIrLdS3sJW2MWfhQJugIAFJtSJqYXtffa:T4hg93swohKugIAVSkYXtffa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_70c037b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae"
    family = "Mirai"
    file_name = "70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae.elf"
    file_type = "elf"
    first_seen = "2026-08-15 19:54:47"
  condition:
    hash.sha256(0, filesize) == "70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae"
}
```

### Sample 63: `263181e4a36604b7`

| Field | Value |
|---|---|
| SHA-256 | `263181e4a36604b77eb8795e7a048d991f191de8e5c2e3d77fc8454f801be886` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 19:17:35` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d888c9d03bd27d752c78106818502fa7` |
| SHA-256 | `263181e4a36604b77eb8795e7a048d991f191de8e5c2e3d77fc8454f801be886` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_263181e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "263181e4a36604b77eb8795e7a048d991f191de8e5c2e3d77fc8454f801be886"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 19:17:35"
  condition:
    hash.sha256(0, filesize) == "263181e4a36604b77eb8795e7a048d991f191de8e5c2e3d77fc8454f801be886"
}
```

### Sample 64: `3aef5773707bcd2a`

| Field | Value |
|---|---|
| SHA-256 | `3aef5773707bcd2ac1d33b4ab18be2341f4f6f40acf784837ebc9222770facf8` |
| Family label | `unknown` |
| File name | `Delta.ps1` |
| File type | `ps1` |
| First seen | `2026-08-15 19:13:26` |
| Reporter | `Alex_sev` |
| Tags | `countloader, generic, powershell, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `064ccf9046b8382154ac1f3b203dfa51` |
| SHA-1 | `82ccad5288b615f9a4b876b1152434cfccaff584` |
| SHA-256 | `3aef5773707bcd2ac1d33b4ab18be2341f4f6f40acf784837ebc9222770facf8` |
| SHA3-384 | `e1c6e33560039fd974f77208d37605a6db90cb1c53f2d0164ac478c814b08cd33f5e8b083a531a3b6dc23e02d1549fe7` |
| TLSH | `T1B33431832349E6BDE6CD0BAAAC4F1415A2F9C815F89F5258F7B17DC737AB9801434E81` |
| SSDEEP | `6144:o/tjrmYD3hr5nBc3oLwZK6LYZi54b3EubCOpCLC5soSpSIJe+sq0s95lme4b2L:d3BYA8Pn+s86b2L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_3aef5773
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aef5773707bcd2ac1d33b4ab18be2341f4f6f40acf784837ebc9222770facf8"
    family = "unknown"
    file_name = "Delta.ps1"
    file_type = "ps1"
    first_seen = "2026-08-15 19:13:26"
  condition:
    hash.sha256(0, filesize) == "3aef5773707bcd2ac1d33b4ab18be2341f4f6f40acf784837ebc9222770facf8"
}
```

### Sample 65: `1050e7ca3b05cc57`

| Field | Value |
|---|---|
| SHA-256 | `1050e7ca3b05cc57187f2ac7bed5ccb2b49150ac0ef4a8f4ee686dab61eaa330` |
| Family label | `unknown` |
| File name | `Data.ps1` |
| File type | `ps1` |
| First seen | `2026-08-15 19:11:53` |
| Reporter | `Alex_sev` |
| Tags | `countloader, generic, powershell, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82c671a0a90270e7ef85cb9a9cc879fd` |
| SHA-1 | `3ae8183472627a4a226c2eb8d57c2994e8f0a137` |
| SHA-256 | `1050e7ca3b05cc57187f2ac7bed5ccb2b49150ac0ef4a8f4ee686dab61eaa330` |
| SHA3-384 | `ae94b861b45ef4ad909d347fe359c1e7e5b7d3bb258f3ea73d62eec83d1c7f5ea647b72cef2c5e8ab6ec4c6b4a270b39` |
| TLSH | `T1953430822305E67CF2CE0AF2AC0B0464A1F9C915F99F5449B7B16DD77B7AA801934FC6` |
| SSDEEP | `6144:zJWX3fn2e5toAy+7Cdnkatz5W48RrEYnCvRr/FBQaPBKq+u2DnfHte:IfBYtzQTQYQzNqe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_1050e7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1050e7ca3b05cc57187f2ac7bed5ccb2b49150ac0ef4a8f4ee686dab61eaa330"
    family = "unknown"
    file_name = "Data.ps1"
    file_type = "ps1"
    first_seen = "2026-08-15 19:11:53"
  condition:
    hash.sha256(0, filesize) == "1050e7ca3b05cc57187f2ac7bed5ccb2b49150ac0ef4a8f4ee686dab61eaa330"
}
```

### Sample 66: `afbd387612dae6d6`

| Field | Value |
|---|---|
| SHA-256 | `afbd387612dae6d6d817231abb6465ad08ae34dd6c24568e2de89d9a3c5f30e0` |
| Family label | `unknown` |
| File name | `DRFa1X25.ps1` |
| File type | `ps1` |
| First seen | `2026-08-15 19:08:16` |
| Reporter | `Alex_sev` |
| Tags | `countloader, generic, powershell, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8977e2b68815d707abcab78f05f1f38` |
| SHA-1 | `2ca62a03ccb0f1d96dcdc6225a53820d9e460321` |
| SHA-256 | `afbd387612dae6d6d817231abb6465ad08ae34dd6c24568e2de89d9a3c5f30e0` |
| SHA3-384 | `2b1b32b8f97fb82b5c7a4ff1f41389e985012eae9790be5351c1c22da624f60337a1238e66203952e4db291a1a7375b0` |
| TLSH | `T12E243E932341E6B8F2CE1BE2A80B0459A1F9C815FD9F5548BBB2BDC7779BE401534E81` |
| SSDEEP | `6144:WUT9hTfCj4zj7siGWIK2kY6Qw25g9KAuZF0bzFLbd4MDnCG+GAAWb:pxwF023AuZC94Ynw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_afbd3876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afbd387612dae6d6d817231abb6465ad08ae34dd6c24568e2de89d9a3c5f30e0"
    family = "unknown"
    file_name = "DRFa1X25.ps1"
    file_type = "ps1"
    first_seen = "2026-08-15 19:08:16"
  condition:
    hash.sha256(0, filesize) == "afbd387612dae6d6d817231abb6465ad08ae34dd6c24568e2de89d9a3c5f30e0"
}
```

### Sample 67: `94620f612e74609a`

| Field | Value |
|---|---|
| SHA-256 | `94620f612e74609ad155ac854ca42b615e97361f0c6552e20ba902b690514a30` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-15 17:39:04` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fa093d68fdbae6102e675a397659e06` |
| SHA-1 | `21872c8cca8572c1e6d30039e2b20d4dccc8c854` |
| SHA-256 | `94620f612e74609ad155ac854ca42b615e97361f0c6552e20ba902b690514a30` |
| SHA3-384 | `0708180e0e8f55f81e85ad9c320466a7287e097eb7cc1286150b13ff9f906172a2260e54e517b6d375c36ece56093bea` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1B422D61E6E8B4231ED6108B0E6B58909553E4DE33785FAEBE333C5D70AD5E4184C16AF` |
| SSDEEP | `96:DdNomYz/9PYz/WkpUzm7Bs3AdynpDLRxef2AY2Ntm8EPFJxGE9mZ2FFh/C7tCEKO:joVWkzWBgtxeuAQPFJxTEZmFhEKcq` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_067_94620f61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94620f612e74609ad155ac854ca42b615e97361f0c6552e20ba902b690514a30"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-15 17:39:04"
  condition:
    hash.sha256(0, filesize) == "94620f612e74609ad155ac854ca42b615e97361f0c6552e20ba902b690514a30"
}
```

### Sample 68: `3bccecdca2ce3415`

| Field | Value |
|---|---|
| SHA-256 | `3bccecdca2ce3415df0774388ee45110c85073ea0f5e6b7ea8b00a6a1e334336` |
| Family label | `QuasarRAT` |
| File name | `vhgvgcjg.exe` |
| File type | `exe` |
| First seen | `2026-08-15 17:14:27` |
| Reporter | `skocherhan` |
| Tags | `exe, QuasarRAT, revengegrompegroups-pl` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd14398f6e74e048b0f0559bb66244a4` |
| SHA-1 | `16fc3feaa8ac81ac4ab5c716a45ac0a8d4572b26` |
| SHA-256 | `3bccecdca2ce3415df0774388ee45110c85073ea0f5e6b7ea8b00a6a1e334336` |
| SHA3-384 | `e803686edb76044df3c41ef749eaf11a4f5af27d2265530dcc3f6be9ec489921a0fa8e00c93177305c5dd2cc1b0abac7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14A1522D4D784C9A0CD2F2C34C828916116B2BE3355A3EB267A9D36C8567B3CD50DAF4B` |
| SSDEEP | `12288:OIZMMy2S2byNI/aBbBz6jDXBwHxkV5HQTh6LoOPtXmZXddp7Dux1xg4I7Oni:TZMPL2bEBdz+Bia3UoLZVOXh7K/Kwni` |
| ICON-DHASH | `fcf2939b9b8bc800` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_068_3bccecdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bccecdca2ce3415df0774388ee45110c85073ea0f5e6b7ea8b00a6a1e334336"
    family = "QuasarRAT"
    file_name = "vhgvgcjg.exe"
    file_type = "exe"
    first_seen = "2026-08-15 17:14:27"
  condition:
    hash.sha256(0, filesize) == "3bccecdca2ce3415df0774388ee45110c85073ea0f5e6b7ea8b00a6a1e334336"
}
```

### Sample 69: `d64ad56eca41d47c`

| Field | Value |
|---|---|
| SHA-256 | `d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea` |
| Family label | `Mirai` |
| File name | `pandora.x86_64` |
| File type | `elf` |
| First seen | `2026-08-15 17:04:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5f6c8a17a02275bc392dc86d600faaf` |
| SHA-1 | `1a6852ef32d1295ec25db0f032bb5677d3167c40` |
| SHA-256 | `d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea` |
| SHA3-384 | `b442dae879669ce7c6f848b66736abf82ac18167d9b1d261a495506a1f8f081913a021cf067cff5636cd4918d32121e6` |
| TLSH | `T1D4857C5AB2E324BCC057C430439FDB63AC35B46911227D7F2684DA352E66EB05B2DF62` |
| TELFHASH | `t1222299b088fa34b1a6d6c851f362f435aa7210f916e835b547626d84efd4f841c7a82f` |
| SSDEEP | `24576:V8Puh/DPZUnEi2GXW6wMu78xsfmxXWRMnCM3ElkR8Z4ywte+fg8M+U5TxG8rl83w:u5sfmxmO3OkRm4yl+fg8M+mTA86` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_d64ad56e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea"
    family = "Mirai"
    file_name = "pandora.x86_64"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:58"
  condition:
    hash.sha256(0, filesize) == "d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea"
}
```

### Sample 70: `17922edaad96218b`

| Field | Value |
|---|---|
| SHA-256 | `17922edaad96218b0cb61af51fb70955da7f9396418c4d83330fc80ce4c71a32` |
| Family label | `unknown` |
| File name | `scanner` |
| File type | `elf` |
| First seen | `2026-08-15 17:04:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17f3a1414abd51b5e68928d2ebae20cf` |
| SHA-1 | `00238970257d64d9008d834b39efa70ceadebaf4` |
| SHA-256 | `17922edaad96218b0cb61af51fb70955da7f9396418c4d83330fc80ce4c71a32` |
| SHA3-384 | `5d98b65e515b0c1b7b6d1f4ecb4791d18b9f2bb0d91d159cef1cd85f2d30cfd71a1aecc164a05552466f27e975c04e7b` |
| TLSH | `T149568C03FCA199AAC0EAA231897391527B71BC882B7123D72F50F77C6EB2BC45975744` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:wwtNYqZGU7Y8RD69M0ExOLT56nxrgge1mPp5dF:wwlEyNELixU10pF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_17922eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17922edaad96218b0cb61af51fb70955da7f9396418c4d83330fc80ce4c71a32"
    family = "unknown"
    file_name = "scanner"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:56"
  condition:
    hash.sha256(0, filesize) == "17922edaad96218b0cb61af51fb70955da7f9396418c4d83330fc80ce4c71a32"
}
```

### Sample 71: `e4369695ea1edf49`

| Field | Value |
|---|---|
| SHA-256 | `e4369695ea1edf4969558c295376c32d042599fb3348c2e5ea2b8563e46db1f3` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-08-15 17:04:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `285816e9e24482e9e4508b44cfaf8b91` |
| SHA-1 | `4cab8074c86e4f58dc0c2229c8e25e3576941e63` |
| SHA-256 | `e4369695ea1edf4969558c295376c32d042599fb3348c2e5ea2b8563e46db1f3` |
| SHA3-384 | `44cdc9a01d0ff888022e822aee08289c10c5c7a30c9168bccd89c5ec097ff62e4d73ee107d330a00c8a1632d11a7f284` |
| TLSH | `T139042A46AA414B13C0D627BAF6DF42463333AB5497E773069528AFB43F8279E4F13606` |
| TELFHASH | `t107311171667851269aa1dc64d9ed97b2252ac7172340ff36df26c0cc281a44af62ac0f` |
| SSDEEP | `3072:s9kPeAfXMO7YEc0aVLrC+dTmY8DRqhu838juouM/RYN/duC:6yeuMOUX0aVLrC+dTmHOu83sXuM/RKd9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_e4369695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4369695ea1edf4969558c295376c32d042599fb3348c2e5ea2b8563e46db1f3"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:54"
  condition:
    hash.sha256(0, filesize) == "e4369695ea1edf4969558c295376c32d042599fb3348c2e5ea2b8563e46db1f3"
}
```

### Sample 72: `0e8d4bbbe9ded460`

| Field | Value |
|---|---|
| SHA-256 | `0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-08-15 17:04:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bde74955dcb284416ef1f299060a467` |
| SHA-1 | `30db7a75586d06386e2be23d7855ea11a907b633` |
| SHA-256 | `0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1` |
| SHA3-384 | `bf87b32e9916f737289cccaca3f0506b78a00e64fa7be328f1d4ee9e8cceb849f1c8c2bdb597fd017362726f9b78269e` |
| TLSH | `T170E30A46B8818B12D5D111BAFE1E128E33231B78E2DE73029D246F65778A9BF0E3B515` |
| TELFHASH | `t162d0c2059e5821cc66c4451484dc211abed8b4adab16414c33acac48c626a913120b45` |
| SSDEEP | `3072:60WNcRHJUC2thzX3FTn4yaWDXhJW+DYugy:UyRpRozXVTn3agTDYugy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_0e8d4bbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:52"
  condition:
    hash.sha256(0, filesize) == "0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1"
}
```

### Sample 73: `92b2df9b3b1add87`

| Field | Value |
|---|---|
| SHA-256 | `92b2df9b3b1add879bb02447bf1a4484f7a3ce8058ae6f13228ec619714ecd4c` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-08-15 17:04:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6ca5a7345696e34bc13c9617ff0d08d` |
| SHA-1 | `0f570974125cdf63d772f4306821f3a59ce7fec5` |
| SHA-256 | `92b2df9b3b1add879bb02447bf1a4484f7a3ce8058ae6f13228ec619714ecd4c` |
| SHA3-384 | `e868f95ce0307802d042116cda64a268be9c267498f1e1af48b408144e4e4970773cf52450a0ab4b66a75774a11350d7` |
| TLSH | `T113C31B45FC504B23CAD522BBFB5E428D772A1769D3EE720399256F21378786B0E37602` |
| TELFHASH | `t16711107adf64cf0da7c1c19cc48eb26a067a34443f022402475c2e4b4f2299331a9452` |
| SSDEEP | `3072:K7IEKRsZ+OIW0H4mWRMe9hO7GMiq9PYQ:K7CR+7I5H4m4MeLO7Gvib` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_92b2df9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92b2df9b3b1add879bb02447bf1a4484f7a3ce8058ae6f13228ec619714ecd4c"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:51"
  condition:
    hash.sha256(0, filesize) == "92b2df9b3b1add879bb02447bf1a4484f7a3ce8058ae6f13228ec619714ecd4c"
}
```

### Sample 74: `6d31b81e8cc94e65`

| Field | Value |
|---|---|
| SHA-256 | `6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-08-15 17:04:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0899ec3e5c3565b3a1a9fe6b18ef9667` |
| SHA-1 | `a5fff94c3acba67dfbe16ccb08e4d1642f46dc46` |
| SHA-256 | `6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce` |
| SHA3-384 | `9952de916933416109ecd2780223bdbac38c8a97c53c2c0a151df2d7066b38cfdadaaf5c077118a6db655b09f88b1420` |
| TLSH | `T1E5E33BD7F900DDBEF80AE33748130909B230BBA154921B372257796BED3A1991973E87` |
| SSDEEP | `3072:U2y2z1f5JFZcw7OyApj0f4+oCiWNr1I6z5VxjbifLIr/iW+:UP2hIwqyAl0f4+ofWI6zCLbW+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_6d31b81e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:50"
  condition:
    hash.sha256(0, filesize) == "6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce"
}
```

### Sample 75: `9623c860ea32daf3`

| Field | Value |
|---|---|
| SHA-256 | `9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd` |
| Family label | `unknown` |
| File name | `9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd` |
| File type | `elf` |
| First seen | `2026-08-15 17:00:12` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98aec53d4662e7aa2f1fcfff4a6c38ba` |
| SHA-1 | `c89ae4b0b62280a6494a3927b385fa0fd03bcc7a` |
| SHA-256 | `9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd` |
| SHA3-384 | `7390000396801778e7049374f578f7ae11e6dc2f1f6df4903c3a5c195314f6da538c46a5439c91450ef4fafdf49a6b23` |
| TLSH | `T156665B73905614D8D1ADC974D5152213BEA8388B673873DBBBC076F11BBABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQm:cqYUQuVDt0TZEx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_9623c860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd"
    family = "unknown"
    file_name = "9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd"
    file_type = "elf"
    first_seen = "2026-08-15 17:00:12"
  condition:
    hash.sha256(0, filesize) == "9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd"
}
```

### Sample 76: `1a20a7ec6847d1ef`

| Field | Value |
|---|---|
| SHA-256 | `1a20a7ec6847d1efc48a930b9c9fde601c9d0f41c0876febedcff913dd80dc7c` |
| Family label | `ValleyRAT` |
| File name | `insoft_v10.0.18.exe` |
| File type | `exe` |
| First seen | `2026-08-15 16:53:20` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `678c7ec516d98417eae68e52cfaddee6` |
| SHA-1 | `15d6e150f7ed9dcee9248acd4a4779fde4b23b99` |
| SHA-256 | `1a20a7ec6847d1efc48a930b9c9fde601c9d0f41c0876febedcff913dd80dc7c` |
| SHA3-384 | `57cb55b3e1280001ba687fc51961a41555b01156506642c17474de5e8e25213c518770f02939cca333dff99c3568ffdf` |
| IMPHASH | `380560563ebacca1589d8d38ac610187` |
| TLSH | `T15287074ABB40CEE6E11A85B098A77B1163FEFD6147E1C30321C83B15DF1B29D4EA7598` |
| SSDEEP | `196608:eQnmE+fMeDKqTnrT+B7A6Z6dSBqtiEPFNPL12V5pvUFgAN:zKJnGBr4Xu7vUL` |
| ICON-DHASH | `c4e0b0a4cc74626a` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_076_1a20a7ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a20a7ec6847d1efc48a930b9c9fde601c9d0f41c0876febedcff913dd80dc7c"
    family = "ValleyRAT"
    file_name = "insoft_v10.0.18.exe"
    file_type = "exe"
    first_seen = "2026-08-15 16:53:20"
  condition:
    hash.sha256(0, filesize) == "1a20a7ec6847d1efc48a930b9c9fde601c9d0f41c0876febedcff913dd80dc7c"
}
```

### Sample 77: `7db44e145483e67e`

| Field | Value |
|---|---|
| SHA-256 | `7db44e145483e67e5fa9944a0d1e9df51e4cd6a0b50249cd882a38eca2443ec7` |
| Family label | `ValleyRAT` |
| File name | `insoft_v10.0.03.exe` |
| File type | `exe` |
| First seen | `2026-08-15 16:52:26` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4533a423f75743a34bed873c0606fc17` |
| SHA-1 | `b69960959a2a3027410b08b37cb233b1ef14d958` |
| SHA-256 | `7db44e145483e67e5fa9944a0d1e9df51e4cd6a0b50249cd882a38eca2443ec7` |
| SHA3-384 | `45cc7c968db5707a76e578ce0e9578044495dc2d304b88421207cfe96c136255447be85cb175bb8e7de71cc75b6c65cf` |
| IMPHASH | `380560563ebacca1589d8d38ac610187` |
| TLSH | `T17B87074ABB40CEE6E11A85B098A77B1163FEFD6147E1C30321C83B15DF1B29D4EA7598` |
| SSDEEP | `196608:xQnmE+fMeDKqTnrT+B7A6Z6dSBqtiEPFNPL12V5pvUFgAS:iKJnGBr4Xu7vUU` |
| ICON-DHASH | `c4e0b0a4cc74626a` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_077_7db44e14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7db44e145483e67e5fa9944a0d1e9df51e4cd6a0b50249cd882a38eca2443ec7"
    family = "ValleyRAT"
    file_name = "insoft_v10.0.03.exe"
    file_type = "exe"
    first_seen = "2026-08-15 16:52:26"
  condition:
    hash.sha256(0, filesize) == "7db44e145483e67e5fa9944a0d1e9df51e4cd6a0b50249cd882a38eca2443ec7"
}
```

### Sample 78: `45217ea08d8396e3`

| Field | Value |
|---|---|
| SHA-256 | `45217ea08d8396e3ec70d7e0414f90cf92618adb52fa72261678361658a07bf7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-15 16:48:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68c1ec28c21cd87e8f2350be6d7bc916` |
| SHA-1 | `a3b42b36dfcb1fd2971b1f32a0116771dc3d0fd0` |
| SHA-256 | `45217ea08d8396e3ec70d7e0414f90cf92618adb52fa72261678361658a07bf7` |
| SHA3-384 | `d0231e70d14b01056e4ece3293f43d36bc305487afb9a9dfd3c4847c6745957b739d992a1fc3b94c6fb46ee4bc0b693b` |
| TLSH | `T168235C6516867C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A69DD10971D` |
| SSDEEP | `768:M+e9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:M+Lcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_45217ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45217ea08d8396e3ec70d7e0414f90cf92618adb52fa72261678361658a07bf7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 16:48:54"
  condition:
    hash.sha256(0, filesize) == "45217ea08d8396e3ec70d7e0414f90cf92618adb52fa72261678361658a07bf7"
}
```

### Sample 79: `a8ce925aaa553b4d`

| Field | Value |
|---|---|
| SHA-256 | `a8ce925aaa553b4d8878d2bacff9047b0837b96597a80a54e038f14b68878ce5` |
| Family label | `Mirai` |
| File name | `mirai.i586` |
| File type | `elf` |
| First seen | `2026-08-15 16:39:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a449aa4d735c2f96901ceed69bef635` |
| SHA-1 | `61e20085728e09523f4b81d33a441c379eb8ef0c` |
| SHA-256 | `a8ce925aaa553b4d8878d2bacff9047b0837b96597a80a54e038f14b68878ce5` |
| SHA3-384 | `ef2bc79f51c8bd013dfcc1eca40bd96c60ceb203b58c7dc28d50651c48423a04bc1e5bc634b41f04102a9921a6ee9344` |
| TLSH | `T190B37DC2A746EEF4D85605F178A297718673C5B6C07FFD96C3DEC021A882A21B607C6C` |
| TELFHASH | `t17a112bb29e761dfcf1d06c0cc32e63f3a939c6a329615db144ba25413ff25508171931` |
| SSDEEP | `1536:8mt33Rvcycvrs7DTptsLjE6DxGr/iWevJiUME6tCWnvKyy:8mt3BUtvAXT0jRVIiWeRiUMEOY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_a8ce925a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ce925aaa553b4d8878d2bacff9047b0837b96597a80a54e038f14b68878ce5"
    family = "Mirai"
    file_name = "mirai.i586"
    file_type = "elf"
    first_seen = "2026-08-15 16:39:51"
  condition:
    hash.sha256(0, filesize) == "a8ce925aaa553b4d8878d2bacff9047b0837b96597a80a54e038f14b68878ce5"
}
```

### Sample 80: `bd8715a77f1dad85`

| Field | Value |
|---|---|
| SHA-256 | `bd8715a77f1dad85e48ba889d3d267a45e8bfdf618a8f7926008b0a4a89d6ee5` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-15 16:32:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0705bb5d5140db8808e237749e05c1b` |
| SHA-1 | `59314957c2cd909506543ae6d063341d9496b825` |
| SHA-256 | `bd8715a77f1dad85e48ba889d3d267a45e8bfdf618a8f7926008b0a4a89d6ee5` |
| SHA3-384 | `01fd6867d506344d4bded269e7d7650d09c587ff0d9f2502ef19ef4752463306934ec9b491b8818acf7727fba8198550` |
| TLSH | `T114D41855F880DF61C6C535B6F65D42A873074BB9D3EB72068A254B343BEB86B0F3A601` |
| SSDEEP | `12288:V9BqL2Md3AsGmtOyRIRkVr4NoOWPVgP/HwUllgmtjs8pqPm:VQAsrdckV4NXWWP/hgmom` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_bd8715a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd8715a77f1dad85e48ba889d3d267a45e8bfdf618a8f7926008b0a4a89d6ee5"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-15 16:32:50"
  condition:
    hash.sha256(0, filesize) == "bd8715a77f1dad85e48ba889d3d267a45e8bfdf618a8f7926008b0a4a89d6ee5"
}
```

### Sample 81: `0ac17b5ec73932d1`

| Field | Value |
|---|---|
| SHA-256 | `0ac17b5ec73932d1d3135ea38b0fc7dc598b3bb7941d32e0fb2160b882fdda8f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-15 16:26:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d201bd53496bce0cd92006771d1528e` |
| SHA-1 | `e96850fe91c147cbf435039fe03c23053e51cecc` |
| SHA-256 | `0ac17b5ec73932d1d3135ea38b0fc7dc598b3bb7941d32e0fb2160b882fdda8f` |
| SHA3-384 | `3b219907d61bc1021d19735fb773bf428b28fb5f7fc787241d302c74f5f9e5d559d252affc28672d477bb6c4b393c7db` |
| TLSH | `T1DCC27C966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:k8vCB+25j6es8RSo9FYpMSUpi+20qUpi+20YQX:k8l25Jld2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_0ac17b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ac17b5ec73932d1d3135ea38b0fc7dc598b3bb7941d32e0fb2160b882fdda8f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 16:26:49"
  condition:
    hash.sha256(0, filesize) == "0ac17b5ec73932d1d3135ea38b0fc7dc598b3bb7941d32e0fb2160b882fdda8f"
}
```

### Sample 82: `79399d2ccde8a358`

| Field | Value |
|---|---|
| SHA-256 | `79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19` |
| Family label | `Vidar` |
| File name | `79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19.bin` |
| File type | `exe` |
| First seen | `2026-08-15 16:26:22` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23bb983a4f9612a8c5174a31ac11f1f9` |
| SHA-1 | `68b4f56cab5bd0adeab70377eb15f8bcbfaa906c` |
| SHA-256 | `79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19` |
| SHA3-384 | `8ae026b58ec9c9b27dddb9c31b312c12cac0f9244466316e923b7e64b6d94af0d777c97e397b2d3acdd88e1b1556927c` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T16DF59D07BE6111A9C896E735D2A35B15B570BC0EC33937E71E61AA782F227C19DB9F00` |
| SSDEEP | `49152:+AVU5egQwEDn/GkGNPbkXdvmNV4Wxs0Ur7cEbc:++ezqXdvuT` |
| ICON-DHASH | `c86b94dcc9699668` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_082_79399d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19"
    family = "Vidar"
    file_name = "79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19.bin"
    file_type = "exe"
    first_seen = "2026-08-15 16:26:22"
  condition:
    hash.sha256(0, filesize) == "79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19"
}
```

### Sample 83: `c713bb386cb58f4e`

| Field | Value |
|---|---|
| SHA-256 | `c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4` |
| Family label | `Vidar` |
| File name | `c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4.bin` |
| File type | `exe` |
| First seen | `2026-08-15 16:15:11` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ee4ee8d50272ccde07e24eb9b8337cb` |
| SHA-1 | `574a023bbc7ed0f882f9f1db7a3e2ead6b356be9` |
| SHA-256 | `c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4` |
| SHA3-384 | `8f5df9e9a722f9125c7d1f7efec005941ae7d9688ddeb2f9a694d271244fea81af94b26bc8ff03ae6ff6b26b827141c8` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T15E068D877D504994E4A9E33A88A61191F630BC4D833537E72EC8B6762F317C2D9BAF14` |
| SSDEEP | `49152:pdhFgcKhbJo544Ck00IbRzHJd3QV4AND4q3ReSXUU6Hm6:yd0IPRzebMU` |
| ICON-DHASH | `62d8ada4da4ae4b9` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_083_c713bb38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4"
    family = "Vidar"
    file_name = "c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4.bin"
    file_type = "exe"
    first_seen = "2026-08-15 16:15:11"
  condition:
    hash.sha256(0, filesize) == "c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4"
}
```

### Sample 84: `7df1ad3f296151ca`

| Field | Value |
|---|---|
| SHA-256 | `7df1ad3f296151ca57f5041f4863d6309ec7c8e99918fd2c9c75be7b9e6cc64f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-15 16:03:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63e41d57a51eca8e694501ab029f04b6` |
| SHA-1 | `88105be701a10812a043eed8d3ca49639e845212` |
| SHA-256 | `7df1ad3f296151ca57f5041f4863d6309ec7c8e99918fd2c9c75be7b9e6cc64f` |
| SHA3-384 | `096b0d114556df90684091e79e68cf1e57f3ac6c9bcf7f07ffbbb19436d984e11d857e78d263014635d2fe0171787f47` |
| TLSH | `T1A9C27D956A967C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACC618B1A` |
| SSDEEP | `768:E8vCB+25j6es8RU9FYpMSUpi+20qUpi+20YQX:E8l25Jyd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_7df1ad3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7df1ad3f296151ca57f5041f4863d6309ec7c8e99918fd2c9c75be7b9e6cc64f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 16:03:58"
  condition:
    hash.sha256(0, filesize) == "7df1ad3f296151ca57f5041f4863d6309ec7c8e99918fd2c9c75be7b9e6cc64f"
}
```

### Sample 85: `7824e906e6bc2fe4`

| Field | Value |
|---|---|
| SHA-256 | `7824e906e6bc2fe40b62b7fed3990103dd894ac0e27367ac4509eb9e2209dbcf` |
| Family label | `unknown` |
| File name | `cat.sh` |
| File type | `sh` |
| First seen | `2026-08-15 15:47:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80cb96d9ab4cf0d5fe5195e7d942a897` |
| SHA-1 | `e1d58b9264a9130151600cedecacea29fb995c31` |
| SHA-256 | `7824e906e6bc2fe40b62b7fed3990103dd894ac0e27367ac4509eb9e2209dbcf` |
| SHA3-384 | `b7e9c2b61cf1d3758cf2291997798cabc8cc4d52a790a229a6aa5eda515b41f3e3a3a7e632c1c948d4533d408f5d82cb` |
| TLSH | `T13341BFCE10F055918384CEA1B2F24ED45666E5A93296CAB3DFC19FADA88DDC03135E3D` |
| SSDEEP | `24:ylfYdc9csFOEm2DNCVuy3svKpvkzdOd6d2dd2MtmmYbKLE2C1KW9asWDD:C4qL5CstgD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_7824e906
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7824e906e6bc2fe40b62b7fed3990103dd894ac0e27367ac4509eb9e2209dbcf"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-08-15 15:47:52"
  condition:
    hash.sha256(0, filesize) == "7824e906e6bc2fe40b62b7fed3990103dd894ac0e27367ac4509eb9e2209dbcf"
}
```

### Sample 86: `9430beeddeb4625b`

| Field | Value |
|---|---|
| SHA-256 | `9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1` |
| Family label | `unknown` |
| File name | `9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1.exe` |
| File type | `exe` |
| First seen | `2026-08-15 15:44:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52811d08d20cd94b5a242fd9d2adc247` |
| SHA-1 | `64b5d796ea0fa370c9f047e73654f13e325c2f5e` |
| SHA-256 | `9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1` |
| SHA3-384 | `131392cbea301dde64696df773d95d611e0e0ac754017f418e53cfa12bce3139dadf97990b702fc81f2cf1025d3636f2` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T11FD5226AFEB611B1E436C3B3869325BEB169778487309D5B71CC5B012D43868BC3A379` |
| SSDEEP | `49152:eiPYKFvVo0/D1joxIlE3/7Z0ozyxaligYSdl921lbSleM7Bo:ZW0/DZCz3/7Z0oNZzeO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_9430beed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1"
    family = "unknown"
    file_name = "9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1.exe"
    file_type = "exe"
    first_seen = "2026-08-15 15:44:51"
  condition:
    hash.sha256(0, filesize) == "9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1"
}
```

### Sample 87: `12419d8ededdec0e`

| Field | Value |
|---|---|
| SHA-256 | `12419d8ededdec0eaf1a62673d5d3a9810902385ae25881326cc3b8b331970da` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-15 15:43:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4da34aca873fc8a04688f4a6be48eff` |
| SHA-1 | `5bf2200431d35b90042e5bd6b266b27afe0df774` |
| SHA-256 | `12419d8ededdec0eaf1a62673d5d3a9810902385ae25881326cc3b8b331970da` |
| SHA3-384 | `c44c2809f77ec326918cb5fdd1bb14238696ff8f730dc65ab785ae791dd26ad85fd47125181367f7347181381bc09ee1` |
| TLSH | `T13F237D652A857C14AA98C4371D7E2F0CB9AD43E6320492EDBFCF3CF68C4A69D911871D` |
| SSDEEP | `768:RXOGVvK9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:tLncr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_12419d8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12419d8ededdec0eaf1a62673d5d3a9810902385ae25881326cc3b8b331970da"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 15:43:51"
  condition:
    hash.sha256(0, filesize) == "12419d8ededdec0eaf1a62673d5d3a9810902385ae25881326cc3b8b331970da"
}
```

### Sample 88: `34fe876495ae17e9`

| Field | Value |
|---|---|
| SHA-256 | `34fe876495ae17e947e2cfde048d48ab3b88d2b6e0168316c7faea7313363a12` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-08-15 15:39:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `349ff465b52c6245ff96c3066ac053b0` |
| SHA-1 | `811955e4c2c19afda0348a69af0c736f3d4c533b` |
| SHA-256 | `34fe876495ae17e947e2cfde048d48ab3b88d2b6e0168316c7faea7313363a12` |
| SHA3-384 | `2341601bc32d99f2349d35003a1a79ca828f09969268a09b6fafdef90a863b7950e9f22e35cd30ac6d5eef9f2c666328` |
| TLSH | `T1DDD097E3A23313B084E34C2AF6C26910F1009B7F4C84BBBEB80769302E40308F0C1398` |
| SSDEEP | `6:hTeeCwEVq7AulNXYq4HvXDG+NjVsNXYrkJ:VeI8q7Piq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_34fe8764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34fe876495ae17e947e2cfde048d48ab3b88d2b6e0168316c7faea7313363a12"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-08-15 15:39:52"
  condition:
    hash.sha256(0, filesize) == "34fe876495ae17e947e2cfde048d48ab3b88d2b6e0168316c7faea7313363a12"
}
```

### Sample 89: `1a92991e472345b6`

| Field | Value |
|---|---|
| SHA-256 | `1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044` |
| Family label | `unknown` |
| File name | `1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044.exe` |
| File type | `exe` |
| First seen | `2026-08-15 15:39:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b4e380bc59a52053245effa608ec528` |
| SHA-1 | `fdf22b7cb8b1b10c8972535dac013cd61088f6c5` |
| SHA-256 | `1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044` |
| SHA3-384 | `c5d98c35647a4d9d2800c1cbf1db2f0f8c7d17eacb4a9ad80842320040a2c0a8b5b16d9307148295a92149de5b329b05` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1A6D52389A4F619B0C433D7B19F82F56DB22D77118B348E1BBBCD2A108D639986C76374` |
| SSDEEP | `49152:WAGYsbEtTnJmtRhYJ2WB6NGpq3oEiH85ndpBro3fV8/n0QY:WAGTb8TnJmJWB6EpqYVHyndpRo3Nin0Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_1a92991e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044"
    family = "unknown"
    file_name = "1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044.exe"
    file_type = "exe"
    first_seen = "2026-08-15 15:39:45"
  condition:
    hash.sha256(0, filesize) == "1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044"
}
```

### Sample 90: `bb0eacdc7520edbd`

| Field | Value |
|---|---|
| SHA-256 | `bb0eacdc7520edbdb04dee384543e2caf6beeee3fbad2731dbc8ebe9f13f0fb5` |
| Family label | `Mirai` |
| File name | `mirai.mpsl` |
| File type | `elf` |
| First seen | `2026-08-15 15:06:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3200b149fae0eb99eeac35ab85a8c316` |
| SHA-1 | `432823d3506f7505a28abd0a3b2d253dd3d07d11` |
| SHA-256 | `bb0eacdc7520edbdb04dee384543e2caf6beeee3fbad2731dbc8ebe9f13f0fb5` |
| SHA3-384 | `56ab3a071492aecf26db30105b5373ddfb6c7ab40032e0093888f678cb60c4a3d411286f8e38816d9f81c71acff7131d` |
| TLSH | `T1C3D3F8796B210E97D4FACC3B51843B0C64DD651625AC6B35EEF0C628B64B18B0DEF874` |
| SSDEEP | `1536:bY3J5UhOOarQKjrr+RVHFggIAFJtSJqYXpsUEpm:bY3a9RQgIAVSkYXpLh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_bb0eacdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0eacdc7520edbdb04dee384543e2caf6beeee3fbad2731dbc8ebe9f13f0fb5"
    family = "Mirai"
    file_name = "mirai.mpsl"
    file_type = "elf"
    first_seen = "2026-08-15 15:06:50"
  condition:
    hash.sha256(0, filesize) == "bb0eacdc7520edbdb04dee384543e2caf6beeee3fbad2731dbc8ebe9f13f0fb5"
}
```

### Sample 91: `a79bc3298b6b2de3`

| Field | Value |
|---|---|
| SHA-256 | `a79bc3298b6b2de35d8f52b71a6d6545701f42b8cc1cfabfed24f62ed81801de` |
| Family label | `unknown` |
| File name | `WindowsCodecs.dll` |
| File type | `exe` |
| First seen | `2026-08-15 14:55:04` |
| Reporter | `anonymous` |
| Tags | `ClickFix, ErrTraffic, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7e1dae24e32c0c70aa7342faca54885` |
| SHA-1 | `802085c40e54aa1baa9c7ead165f0b50dca48853` |
| SHA-256 | `a79bc3298b6b2de35d8f52b71a6d6545701f42b8cc1cfabfed24f62ed81801de` |
| SHA3-384 | `6687946ea05a19e3160986997969501f25459bd61dcfb3c3cf43bc5cb85332faa799321ebe3f9ce6f062f7e7ad83fa06` |
| IMPHASH | `858250e2179c27243fdde991d8d6ec6d` |
| TLSH | `T1B9E2834F5F099665ED3E267951BA8DC2F378B2644331C8EB2D80981E0D42BCAD735EC9` |
| SSDEEP | `768:RPL/F/k9fCyqymnZzBeWUjuESb90sngUg/ijhAgH8Q:Rdk9fCryH+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_a79bc329
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79bc3298b6b2de35d8f52b71a6d6545701f42b8cc1cfabfed24f62ed81801de"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-15 14:55:04"
  condition:
    hash.sha256(0, filesize) == "a79bc3298b6b2de35d8f52b71a6d6545701f42b8cc1cfabfed24f62ed81801de"
}
```

### Sample 92: `59688106ddc46d7e`

| Field | Value |
|---|---|
| SHA-256 | `59688106ddc46d7ec9f7e7b00ccb511b9d249fe12ea98fec358dc838b518fa56` |
| Family label | `Mirai` |
| File name | `mirai.arm` |
| File type | `elf` |
| First seen | `2026-08-15 14:47:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c9c92a353936cae6e66ec96b7e1fa53` |
| SHA-1 | `eedfbb6b2b27ddd58574bdb47da5ea511af25be5` |
| SHA-256 | `59688106ddc46d7ec9f7e7b00ccb511b9d249fe12ea98fec358dc838b518fa56` |
| SHA3-384 | `2ca689630b49d6f158571bc288f5a4366c05cce2a28a7df5e0fc2026af4c186df58943fe6a65473de3a08f4e4e091d16` |
| TLSH | `T193C316423F819A51C3D1A17FEE0E718E6715D397C1EBF65F0DA11F026682B264E2B6C2` |
| TELFHASH | `t1e931c350df8c4adcb7e04e19c78da26b79c238e5dd2315224e9bae4f0712ad1b066439` |
| SSDEEP | `1536:yQJCowc68Ran0GLY+UUeJ06hx4bgIAFJtSJqYXUzGTGA4cRPxu:yQ9XanFUU6Dh+bgIAVSkYXUqTPk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_59688106
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59688106ddc46d7ec9f7e7b00ccb511b9d249fe12ea98fec358dc838b518fa56"
    family = "Mirai"
    file_name = "mirai.arm"
    file_type = "elf"
    first_seen = "2026-08-15 14:47:51"
  condition:
    hash.sha256(0, filesize) == "59688106ddc46d7ec9f7e7b00ccb511b9d249fe12ea98fec358dc838b518fa56"
}
```

### Sample 93: `4ad494ac04aa0969`

| Field | Value |
|---|---|
| SHA-256 | `4ad494ac04aa0969ab8deb6ff8bbe936f9471ff38f505e2c2808a0b5e8af848c` |
| Family label | `Mirai` |
| File name | `mirai.mips` |
| File type | `elf` |
| First seen | `2026-08-15 14:39:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee188f983ebc33dd7d116b0686e1fc27` |
| SHA-1 | `4b8a712dd17fc3b53314324649b81d1156b4e4d2` |
| SHA-256 | `4ad494ac04aa0969ab8deb6ff8bbe936f9471ff38f505e2c2808a0b5e8af848c` |
| SHA3-384 | `153d21213a7ae14e43a05207b490d087cf947efa02b1e6d2df9141d6ef5a426756da3ae98e6745ce5d1527025926cc55` |
| TLSH | `T1C6D3B4672A505FDEF258923393BF4A26970823A173B0DECBD72C96400D1C3795ADFA58` |
| TELFHASH | `t19d014f58843413b5d3860ddc6becfb76e45140df8a626e378c40fdaaeb119455d01c1c` |
| SSDEEP | `1536:mR7p3XE3XKSXlJ+Nk3bpIeXnEhKmRyHcgIAFJtSJqYXKusFCl39:M+yiyKncNOcgIAVSkYXKus0j` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_4ad494ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ad494ac04aa0969ab8deb6ff8bbe936f9471ff38f505e2c2808a0b5e8af848c"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-08-15 14:39:50"
  condition:
    hash.sha256(0, filesize) == "4ad494ac04aa0969ab8deb6ff8bbe936f9471ff38f505e2c2808a0b5e8af848c"
}
```

### Sample 94: `59035939cbb1988d`

| Field | Value |
|---|---|
| SHA-256 | `59035939cbb1988d8530155c6a6ee108e0296b620fa3a5edbb9cf898d0859d08` |
| Family label | `Mirai` |
| File name | `mirai.ppc` |
| File type | `elf` |
| First seen | `2026-08-15 14:22:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db4175111367356a9b794baae4cc8f36` |
| SHA-1 | `3a14785b9eb97e223a832bf075431359c9b7bd9c` |
| SHA-256 | `59035939cbb1988d8530155c6a6ee108e0296b620fa3a5edbb9cf898d0859d08` |
| SHA3-384 | `c3d602953d043dfb0a396ecdd80a25bf2c278e6e4c09dec81ae077a3df7926710923a5e4badcfc47233350122300334e` |
| TLSH | `T1F1C32A82263C199BE4D25DF0392397C497E9ACA024BCF6BB6D5AB1854030E72164FDDF` |
| SSDEEP | `1536:rkE+xXq0tmSCDKsgIAFJtSJqYXAGIFMScd4hXF8uiuGU2cWnq:rHitCD5gIAVSkYXlITcFC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_59035939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59035939cbb1988d8530155c6a6ee108e0296b620fa3a5edbb9cf898d0859d08"
    family = "Mirai"
    file_name = "mirai.ppc"
    file_type = "elf"
    first_seen = "2026-08-15 14:22:52"
  condition:
    hash.sha256(0, filesize) == "59035939cbb1988d8530155c6a6ee108e0296b620fa3a5edbb9cf898d0859d08"
}
```

### Sample 95: `2e60aaa4cd0bc283`

| Field | Value |
|---|---|
| SHA-256 | `2e60aaa4cd0bc283cfdbc5a04655026bfdb61779b34438cc4df59e38054fa814` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 14:16:53` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f52b326dcf06b685cb0d4c944f622db` |
| SHA-256 | `2e60aaa4cd0bc283cfdbc5a04655026bfdb61779b34438cc4df59e38054fa814` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_2e60aaa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e60aaa4cd0bc283cfdbc5a04655026bfdb61779b34438cc4df59e38054fa814"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 14:16:53"
  condition:
    hash.sha256(0, filesize) == "2e60aaa4cd0bc283cfdbc5a04655026bfdb61779b34438cc4df59e38054fa814"
}
```

### Sample 96: `e38c6482e4ade50e`

| Field | Value |
|---|---|
| SHA-256 | `e38c6482e4ade50e555803270d5a79e5f32a0f1453de2c6378982bf92668cd69` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-15 14:16:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a1e3e84b1c80afae9748f62d5dbe99e` |
| SHA-1 | `90a452fbcebf76d7d48dc3b811f8ae72b886b9dc` |
| SHA-256 | `e38c6482e4ade50e555803270d5a79e5f32a0f1453de2c6378982bf92668cd69` |
| SHA3-384 | `55c94da9f09791d6243e1dd4d0aea3eab68892ccef0c6bf3d56bd57185cb28a3d76d1e0d7a038550a213715cc333cfb3` |
| TLSH | `T15B237D552A857C14AA98C4371D7E2F0CB9AD43E6320452EDBFCF3CF68C4A69DA21871D` |
| SSDEEP | `768:2XOGVvH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:YL4cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_e38c6482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e38c6482e4ade50e555803270d5a79e5f32a0f1453de2c6378982bf92668cd69"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 14:16:51"
  condition:
    hash.sha256(0, filesize) == "e38c6482e4ade50e555803270d5a79e5f32a0f1453de2c6378982bf92668cd69"
}
```

### Sample 97: `5f310f2036e26b3b`

| Field | Value |
|---|---|
| SHA-256 | `5f310f2036e26b3b441f1a7c003384a93df7e3e092922d65d67f7e8739eb4f83` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-08-15 14:16:45` |
| Reporter | `Bitsight` |
| Tags | `babki, dropped-by-StealC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2cd663529b257b6048c1d9fc0749b6d` |
| SHA-256 | `5f310f2036e26b3b441f1a7c003384a93df7e3e092922d65d67f7e8739eb4f83` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_5f310f20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f310f2036e26b3b441f1a7c003384a93df7e3e092922d65d67f7e8739eb4f83"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 14:16:45"
  condition:
    hash.sha256(0, filesize) == "5f310f2036e26b3b441f1a7c003384a93df7e3e092922d65d67f7e8739eb4f83"
}
```

### Sample 98: `d0d4547f15a6d6f1`

| Field | Value |
|---|---|
| SHA-256 | `d0d4547f15a6d6f1b624a1b4ba745d0a167a614802b800542d394d99ce7b72e6` |
| Family label | `Mirai` |
| File name | `mirai.sh4` |
| File type | `elf` |
| First seen | `2026-08-15 14:15:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05861432a2ab6c0eb24e495349e7c265` |
| SHA-1 | `a41bd15b0ec94aa3f0b93f50bc75363320dd410e` |
| SHA-256 | `d0d4547f15a6d6f1b624a1b4ba745d0a167a614802b800542d394d99ce7b72e6` |
| SHA3-384 | `38189e09f2a8f67b9487b2f8873e5204caf13545e7146fe5bff592dbfa7c7963ff7f2b373f80f9780fe037ff18c2a0a4` |
| TLSH | `T193C34A5EED6B44D0D44500B364088BFC87B3B832524EADF946969D647403FFAFB293A8` |
| SSDEEP | `1536:LWe8ryCdw3yHXn9n0sJcCRmfgIAFJtSJqYXwaYsrbGME/:LWOF3+lJcGAgIAVSkYX66PC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_d0d4547f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0d4547f15a6d6f1b624a1b4ba745d0a167a614802b800542d394d99ce7b72e6"
    family = "Mirai"
    file_name = "mirai.sh4"
    file_type = "elf"
    first_seen = "2026-08-15 14:15:53"
  condition:
    hash.sha256(0, filesize) == "d0d4547f15a6d6f1b624a1b4ba745d0a167a614802b800542d394d99ce7b72e6"
}
```

### Sample 99: `cd4d9ce29b22ccd9`

| Field | Value |
|---|---|
| SHA-256 | `cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763` |
| Family label | `unknown` |
| File name | `cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763.exe` |
| File type | `exe` |
| First seen | `2026-08-15 14:14:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a252016bf277874e274a93c2403bae03` |
| SHA-1 | `00f2579a8c3f286baec64bc3f8abb4bb6451283c` |
| SHA-256 | `cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763` |
| SHA3-384 | `af08cf85b9589868c65af0c70d21736bd63c0c64b445ec6abca7977d69232fbeac2a75f73cb3442780ad71f472fce2d9` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1C7D5235AB8F649B5C435C7B28FD2F06EB06A77958A254EA3F2CC9E00CD579581C39B30` |
| SSDEEP | `49152:Nrd0Oax0A7OBhbZakbArDneNcjHBVwnbZGkBQlF90NZ/jIMWd7fhCdkz:NrqOaOA7OBVVmDe9tmLi+MA1Zz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_cd4d9ce2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763"
    family = "unknown"
    file_name = "cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763.exe"
    file_type = "exe"
    first_seen = "2026-08-15 14:14:43"
  condition:
    hash.sha256(0, filesize) == "cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763"
}
```

### Sample 100: `7aff13bfb7e02f94`

| Field | Value |
|---|---|
| SHA-256 | `7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760` |
| Family label | `CoinMiner` |
| File name | `7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760.exe` |
| File type | `exe` |
| First seen | `2026-08-15 14:09:43` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dba57404b491022f173ca04436c34d67` |
| SHA-1 | `ebb2f8fbffa61f055048586d04e06a603bee104a` |
| SHA-256 | `7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760` |
| SHA3-384 | `c9b2133216ac8bf28807db56432d905a6029e8f6dd7981d46d7dcd0cbdb4a424d43354ec022e74be5fbf829632c1383a` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T10636338A2CC6E474E04AC3E84953A47CF37D779289A07D1B36CD2B054DAEF6462363D5` |
| SSDEEP | `98304:m3bycz9hR4OL1aORGpdoaUe7ieRMYoLLC9Zreh6NyPJiyoDWzpqn2TUUkgP:m39zyOL16p3UDeafq9Ah6NsJiyoD8pqS` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_100_7aff13bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760"
    family = "CoinMiner"
    file_name = "7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760.exe"
    file_type = "exe"
    first_seen = "2026-08-15 14:09:43"
  condition:
    hash.sha256(0, filesize) == "7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760"
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
 * Generated: 2026-08-16T01:59:52.675732+00:00
 */

rule MalwareBazaar_unknown_001_b41017f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b41017f98f93938550a6655981a500ca5a5a97ea9503e3de89948f8d3cab057b"
    family = "unknown"
    file_name = "atom.dll"
    file_type = "exe"
    first_seen = "2026-08-16 01:58:23"
  condition:
    hash.sha256(0, filesize) == "b41017f98f93938550a6655981a500ca5a5a97ea9503e3de89948f8d3cab057b"
}

rule MalwareBazaar_unknown_002_e89c6c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e89c6c8b23135345834621ae2d7ac0b8e29757219d08fcc9f4e47ded0b91c3e2"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:56:55"
  condition:
    hash.sha256(0, filesize) == "e89c6c8b23135345834621ae2d7ac0b8e29757219d08fcc9f4e47ded0b91c3e2"
}

rule MalwareBazaar_unknown_003_c7d9c7f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7d9c7f67b761688cfb67083b7e01381db90cb67adb06c8618889dfdff2396e8"
    family = "unknown"
    file_name = "InstallerV14035x64.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:56:06"
  condition:
    hash.sha256(0, filesize) == "c7d9c7f67b761688cfb67083b7e01381db90cb67adb06c8618889dfdff2396e8"
}

rule MalwareBazaar_unknown_004_5436b9ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5436b9aec5ecd808c2b634586bab65c07e4de5a0e01fd7f952b1beb46335767c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-16 01:55:48"
  condition:
    hash.sha256(0, filesize) == "5436b9aec5ecd808c2b634586bab65c07e4de5a0e01fd7f952b1beb46335767c"
}

rule MalwareBazaar_unknown_005_31098d6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31098d6ed96cce3c4c78dc3880b6c43235bb370cbdf633fa586089ec1dd13247"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-16 01:55:44"
  condition:
    hash.sha256(0, filesize) == "31098d6ed96cce3c4c78dc3880b6c43235bb370cbdf633fa586089ec1dd13247"
}

rule MalwareBazaar_unknown_006_90e3e191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90e3e19106fde055ee729f2a309f2519e84309c0275e27f806dc86496653f369"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:53:57"
  condition:
    hash.sha256(0, filesize) == "90e3e19106fde055ee729f2a309f2519e84309c0275e27f806dc86496653f369"
}

rule MalwareBazaar_unknown_007_81905d33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81905d33a611d1230db493f85f1da36c6c10e0be29148b8cfb72060ade4dd027"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-16 01:52:33"
  condition:
    hash.sha256(0, filesize) == "81905d33a611d1230db493f85f1da36c6c10e0be29148b8cfb72060ade4dd027"
}

rule MalwareBazaar_unknown_008_6cad1545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-16 01:51:35"
  condition:
    hash.sha256(0, filesize) == "6cad154538301583429bf7ebe03f812afa33e4d2207ce54b2e488f3cc74e4eba"
}

rule MalwareBazaar_unknown_009_075c704d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "075c704d7a0ce2ce66a8cd946a3b255896cd9d7b63f31068f960b98e89d154cc"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:50:55"
  condition:
    hash.sha256(0, filesize) == "075c704d7a0ce2ce66a8cd946a3b255896cd9d7b63f31068f960b98e89d154cc"
}

rule MalwareBazaar_unknown_010_de6beb87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6beb87a188da7e565de2fa4a49bbb24a6e3723cb893b8812c5deb0375a722c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-16 01:40:48"
  condition:
    hash.sha256(0, filesize) == "de6beb87a188da7e565de2fa4a49bbb24a6e3723cb893b8812c5deb0375a722c"
}

rule MalwareBazaar_unknown_011_45183829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15"
    family = "unknown"
    file_name = "45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15"
    file_type = "elf"
    first_seen = "2026-08-16 01:30:33"
  condition:
    hash.sha256(0, filesize) == "45183829a069e60c58437947a9212423db974090ab8a56a0f28c491de093df15"
}

rule MalwareBazaar_unknown_012_c6838b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6838b96ea38a6ad9b3be9fcb630db0fb6eb14ec206998f49f1d3767aa8923db"
    family = "unknown"
    file_name = "JupayoManager.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:27:37"
  condition:
    hash.sha256(0, filesize) == "c6838b96ea38a6ad9b3be9fcb630db0fb6eb14ec206998f49f1d3767aa8923db"
}

rule MalwareBazaar_unknown_013_1db6b60a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad"
    family = "unknown"
    file_name = "1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad.bin"
    file_type = "exe"
    first_seen = "2026-08-16 01:24:12"
  condition:
    hash.sha256(0, filesize) == "1db6b60a7989a6c1dbba63d5a78463f5a4d4fbff75af27c281e1a93a11bfe4ad"
}

rule MalwareBazaar_unknown_014_f1476ee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1476ee614a2db779a721a7b19281c7e86248311119898d5cca2ea4f813c43a6"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:20:34"
  condition:
    hash.sha256(0, filesize) == "f1476ee614a2db779a721a7b19281c7e86248311119898d5cca2ea4f813c43a6"
}

rule MalwareBazaar_unknown_015_cb1e15a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb1e15a47e40e7e1886531b829f4061c60b73ba4937e9161b4fc1fef846dfddb"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:19:51"
  condition:
    hash.sha256(0, filesize) == "cb1e15a47e40e7e1886531b829f4061c60b73ba4937e9161b4fc1fef846dfddb"
}

rule MalwareBazaar_unknown_016_b4e869d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4e869d592baf4370f850cbe71c7ae653ac1078646ef6633a4e769f6752b4d2e"
    family = "unknown"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:19:09"
  condition:
    hash.sha256(0, filesize) == "b4e869d592baf4370f850cbe71c7ae653ac1078646ef6633a4e769f6752b4d2e"
}

rule MalwareBazaar_LummaStealer_017_7f11d92a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f11d92a1fc25ba81f808b62a075ccdfe06d441fcaa5adad483afc7508ee5000"
    family = "LummaStealer"
    file_name = "dollar.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:18:20"
  condition:
    hash.sha256(0, filesize) == "7f11d92a1fc25ba81f808b62a075ccdfe06d441fcaa5adad483afc7508ee5000"
}

rule MalwareBazaar_unknown_018_3ed7f672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ed7f672f3f3f0710bce5be789cf707c21e64ec24fc6ebe6f2153d462f287a71"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:16:23"
  condition:
    hash.sha256(0, filesize) == "3ed7f672f3f3f0710bce5be789cf707c21e64ec24fc6ebe6f2153d462f287a71"
}

rule MalwareBazaar_unknown_019_997acaae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "997acaae90f21aebb154b75c2b2c787fa49e8d3d0cdf5c5893d6f7ddbb3d67b6"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:14:24"
  condition:
    hash.sha256(0, filesize) == "997acaae90f21aebb154b75c2b2c787fa49e8d3d0cdf5c5893d6f7ddbb3d67b6"
}

rule MalwareBazaar_unknown_020_09ee5443
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09ee5443809176dcac8ddd954e2dca7c3ba1d0692fca9394d1f1c78e3d943f42"
    family = "unknown"
    file_name = "OpenLink.ps1"
    file_type = "ps1"
    first_seen = "2026-08-16 01:12:39"
  condition:
    hash.sha256(0, filesize) == "09ee5443809176dcac8ddd954e2dca7c3ba1d0692fca9394d1f1c78e3d943f42"
}

rule MalwareBazaar_unknown_021_5e38d605
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e38d605b7cadd90534ad48097fb0f40f03d962ae2f21f702d1609ae65a42a20"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:08:41"
  condition:
    hash.sha256(0, filesize) == "5e38d605b7cadd90534ad48097fb0f40f03d962ae2f21f702d1609ae65a42a20"
}

rule MalwareBazaar_unknown_022_d82decfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d82decfc37200dbb03a77293bbd47df17e9f1bcd7ff51febdcadcf818b45b1a7"
    family = "unknown"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:05:00"
  condition:
    hash.sha256(0, filesize) == "d82decfc37200dbb03a77293bbd47df17e9f1bcd7ff51febdcadcf818b45b1a7"
}

rule MalwareBazaar_unknown_023_a4e7500f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e7500f5e360f33223c504da7c953894ff2053fec6f5b6a6ca772bc78a61742"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-16 01:03:32"
  condition:
    hash.sha256(0, filesize) == "a4e7500f5e360f33223c504da7c953894ff2053fec6f5b6a6ca772bc78a61742"
}

rule MalwareBazaar_unknown_024_2dfe533c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dfe533cdd6c2ea50640338fd3a53ffb5620e82009575bd27aa10be5e7444897"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-16 00:52:30"
  condition:
    hash.sha256(0, filesize) == "2dfe533cdd6c2ea50640338fd3a53ffb5620e82009575bd27aa10be5e7444897"
}

rule MalwareBazaar_unknown_025_5a41a16c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a41a16cd4756275ce194a9495382d3cf340a2cc362de6492ac0ba6879be1d08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-16 00:17:53"
  condition:
    hash.sha256(0, filesize) == "5a41a16cd4756275ce194a9495382d3cf340a2cc362de6492ac0ba6879be1d08"
}

rule MalwareBazaar_unknown_026_7f75bfb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f75bfb1eeecded58b0aca85a25efc6fb95dcf7e0105a2de22d59aacfab9df1b"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-16 00:10:24"
  condition:
    hash.sha256(0, filesize) == "7f75bfb1eeecded58b0aca85a25efc6fb95dcf7e0105a2de22d59aacfab9df1b"
}

rule MalwareBazaar_unknown_027_f9964a8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9964a8d9d01052d9bebe057deadd7ce9d794e8296e2a72229f8ae4aa62ae224"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-16 00:07:27"
  condition:
    hash.sha256(0, filesize) == "f9964a8d9d01052d9bebe057deadd7ce9d794e8296e2a72229f8ae4aa62ae224"
}

rule MalwareBazaar_unknown_028_ac7f1d6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac7f1d6c3d435a3961c1fc71307d7a9354ac2b84646abc3834e98272fcff7a9b"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-15 23:52:31"
  condition:
    hash.sha256(0, filesize) == "ac7f1d6c3d435a3961c1fc71307d7a9354ac2b84646abc3834e98272fcff7a9b"
}

rule MalwareBazaar_unknown_029_74d90413
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74d90413c20a548c1849f9b9e42a947441055589ba06430cade9ab40d38f7539"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-15 23:07:10"
  condition:
    hash.sha256(0, filesize) == "74d90413c20a548c1849f9b9e42a947441055589ba06430cade9ab40d38f7539"
}

rule MalwareBazaar_unknown_030_05a95ecd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a95ecd3164c57248d473c93032981bb6004336c85fe888b42cd6294fcf9ede"
    family = "unknown"
    file_name = "Gmail 2024.11.24.702067492.Release.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:56:34"
  condition:
    hash.sha256(0, filesize) == "05a95ecd3164c57248d473c93032981bb6004336c85fe888b42cd6294fcf9ede"
}

rule MalwareBazaar_unknown_031_8dd8e929
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8dd8e9290fed01c0f7f9fb7e01264368ec8d53ae57b68ce73ad45facc26712f5"
    family = "unknown"
    file_name = "BetterSurvival-CurseForge.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:53:38"
  condition:
    hash.sha256(0, filesize) == "8dd8e9290fed01c0f7f9fb7e01264368ec8d53ae57b68ce73ad45facc26712f5"
}

rule MalwareBazaar_unknown_032_4b00c7eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b00c7ebad267025b84e7b4d1c996eaefec34a065913d73ee0070b119217d1be"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-15 22:52:39"
  condition:
    hash.sha256(0, filesize) == "4b00c7ebad267025b84e7b4d1c996eaefec34a065913d73ee0070b119217d1be"
}

rule MalwareBazaar_unknown_033_9f09fac5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f09fac52d7f1955d1fec98172c99a6f0d2781e9307fa828b4a7175622da5200"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-15 22:52:34"
  condition:
    hash.sha256(0, filesize) == "9f09fac52d7f1955d1fec98172c99a6f0d2781e9307fa828b4a7175622da5200"
}

rule MalwareBazaar_unknown_034_a980cf0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a980cf0c37b5c96ceeeab43c2dd8947851efb43985e7b2fb76e9ef855c9b383c"
    family = "unknown"
    file_name = "Norton VPN 4.6.0.241211284.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:33:27"
  condition:
    hash.sha256(0, filesize) == "a980cf0c37b5c96ceeeab43c2dd8947851efb43985e7b2fb76e9ef855c9b383c"
}

rule MalwareBazaar_unknown_035_9af4e08d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9af4e08d55020b4182a411f547214d2092887a727f7ec5ae2ead8045bdccd579"
    family = "unknown"
    file_name = "gang.jar"
    file_type = "jar"
    first_seen = "2026-08-15 22:32:04"
  condition:
    hash.sha256(0, filesize) == "9af4e08d55020b4182a411f547214d2092887a727f7ec5ae2ead8045bdccd579"
}

rule MalwareBazaar_unknown_036_c9571e62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9571e626c47a576069be0c893bba4de8dc3762602329ab9c2e36ccc48883570"
    family = "unknown"
    file_name = "Norton Password Manager 8.8.0.apk.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:26:00"
  condition:
    hash.sha256(0, filesize) == "c9571e626c47a576069be0c893bba4de8dc3762602329ab9c2e36ccc48883570"
}

rule MalwareBazaar_unknown_037_394cead0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "394cead068f1b53b5811da091af6576eaa10d416068f5d985c5169f5cd9cd06f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 22:21:11"
  condition:
    hash.sha256(0, filesize) == "394cead068f1b53b5811da091af6576eaa10d416068f5d985c5169f5cd9cd06f"
}

rule MalwareBazaar_unknown_038_4ef22d6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef22d6fc5eb913c3e3c8e9a42dc9511285b8927524bb9831ba8de8f49960bd7"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 22:21:04"
  condition:
    hash.sha256(0, filesize) == "4ef22d6fc5eb913c3e3c8e9a42dc9511285b8927524bb9831ba8de8f49960bd7"
}

rule MalwareBazaar_unknown_039_2b7f489a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b7f489a23c21ae46e1bb87c129a141bc1b7b7e1b9669cd83cedcbd1e9697b28"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-15 22:07:03"
  condition:
    hash.sha256(0, filesize) == "2b7f489a23c21ae46e1bb87c129a141bc1b7b7e1b9669cd83cedcbd1e9697b28"
}

rule MalwareBazaar_unknown_040_cc57e487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc57e487bbddc0c26eccb758c92843e935a329cd706bbaa24537726f45a0de5d"
    family = "unknown"
    file_name = "Norton Identity 1.86.apk.zip"
    file_type = "zip"
    first_seen = "2026-08-15 22:00:55"
  condition:
    hash.sha256(0, filesize) == "cc57e487bbddc0c26eccb758c92843e935a329cd706bbaa24537726f45a0de5d"
}

rule MalwareBazaar_unknown_041_df159312
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab"
    family = "unknown"
    file_name = "df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab.exe"
    file_type = "exe"
    first_seen = "2026-08-15 21:50:10"
  condition:
    hash.sha256(0, filesize) == "df159312ca87597dedf3d04c035c25716092f27a5fb2534f9ec773a5ddf239ab"
}

rule MalwareBazaar_unknown_042_9b2a69e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0"
    family = "unknown"
    file_name = "9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0.exe"
    file_type = "exe"
    first_seen = "2026-08-15 21:44:53"
  condition:
    hash.sha256(0, filesize) == "9b2a69e414035f34ba3ccddb8f4bf48f0640f65fe356de5fd7d5304933be3cc0"
}

rule MalwareBazaar_unknown_043_c2d74739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d74739b4901f631cc38c49f1f4d1bf20fe1974d70ce1c441866faad6699a77"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 21:20:47"
  condition:
    hash.sha256(0, filesize) == "c2d74739b4901f631cc38c49f1f4d1bf20fe1974d70ce1c441866faad6699a77"
}

rule MalwareBazaar_unknown_044_4b45e9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b45e9f2f4a8ec346023246d7c0e4ae081c42289d53df7b621693eb893bf9d9a"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 21:20:40"
  condition:
    hash.sha256(0, filesize) == "4b45e9f2f4a8ec346023246d7c0e4ae081c42289d53df7b621693eb893bf9d9a"
}

rule MalwareBazaar_unknown_045_18f35470
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18f35470bd811ed20ed636f7a58b101428ab784ee1eff4ba902a4638b5e55823"
    family = "unknown"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-15 21:00:53"
  condition:
    hash.sha256(0, filesize) == "18f35470bd811ed20ed636f7a58b101428ab784ee1eff4ba902a4638b5e55823"
}

rule MalwareBazaar_unknown_046_be9cb31f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be9cb31ff1434c8dd13ab72a3046b2c0383272f0c0a2bdf95c1e35045c8b1206"
    family = "unknown"
    file_name = "KimiK3-Desktop.exe"
    file_type = "exe"
    first_seen = "2026-08-15 21:00:44"
  condition:
    hash.sha256(0, filesize) == "be9cb31ff1434c8dd13ab72a3046b2c0383272f0c0a2bdf95c1e35045c8b1206"
}

rule MalwareBazaar_unknown_047_a3300d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3300d78392195891d7498b4bd518dd7631f1108ecef6f290586a18d08410875"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-15 20:58:52"
  condition:
    hash.sha256(0, filesize) == "a3300d78392195891d7498b4bd518dd7631f1108ecef6f290586a18d08410875"
}

rule MalwareBazaar_unknown_048_1253cb14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1253cb1483d3bb5f1e7e0cd3d53c722e4e2e69483b4070404c3ba75844994b39"
    family = "unknown"
    file_name = "v2.4.1.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:58:08"
  condition:
    hash.sha256(0, filesize) == "1253cb1483d3bb5f1e7e0cd3d53c722e4e2e69483b4070404c3ba75844994b39"
}

rule MalwareBazaar_unknown_049_b199f70d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b199f70d109357f81c2f147318b424d91fd635449b19c9610f50e428a0c68e8e"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-15 20:56:39"
  condition:
    hash.sha256(0, filesize) == "b199f70d109357f81c2f147318b424d91fd635449b19c9610f50e428a0c68e8e"
}

rule MalwareBazaar_unknown_050_fdba2c8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdba2c8f46d4a4617c2580b3bcaf106076c73b4f906756987b63c6492dedfa0c"
    family = "unknown"
    file_name = "Setup_app.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:56:25"
  condition:
    hash.sha256(0, filesize) == "fdba2c8f46d4a4617c2580b3bcaf106076c73b4f906756987b63c6492dedfa0c"
}

rule MalwareBazaar_unknown_051_4252c985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4252c98558bda800c93925ae8691d1c35d7db57cbc64eddc2451ddf1e780034c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:45:50"
  condition:
    hash.sha256(0, filesize) == "4252c98558bda800c93925ae8691d1c35d7db57cbc64eddc2451ddf1e780034c"
}

rule MalwareBazaar_unknown_052_be5770a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be5770a2afb56481bffd96417857e34d8d96c2b078434645d9aed990ca2c0764"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:37:50"
  condition:
    hash.sha256(0, filesize) == "be5770a2afb56481bffd96417857e34d8d96c2b078434645d9aed990ca2c0764"
}

rule MalwareBazaar_Mirai_053_71bcb1ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71bcb1ff944476d06565e1b4ebc6aa74712ecfb8ef4dd0e581f440ebb87fff1e"
    family = "Mirai"
    file_name = "ohshit.sh"
    file_type = "sh"
    first_seen = "2026-08-15 20:29:47"
  condition:
    hash.sha256(0, filesize) == "71bcb1ff944476d06565e1b4ebc6aa74712ecfb8ef4dd0e581f440ebb87fff1e"
}

rule MalwareBazaar_unknown_054_4819d87f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4819d87fe9d0d0485fe85a3843a3e3ecd61ebe50a115dad01ec10275272be82a"
    family = "unknown"
    file_name = "NPE.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:28:20"
  condition:
    hash.sha256(0, filesize) == "4819d87fe9d0d0485fe85a3843a3e3ecd61ebe50a115dad01ec10275272be82a"
}

rule MalwareBazaar_unknown_055_01156f0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01156f0a356a50cc73e012fb88bfdd1a8e06f2db452424d1fe71ed2914b5b641"
    family = "unknown"
    file_name = "hutepkeazyauxbqsiykw.dll"
    file_type = "exe"
    first_seen = "2026-08-15 20:21:13"
  condition:
    hash.sha256(0, filesize) == "01156f0a356a50cc73e012fb88bfdd1a8e06f2db452424d1fe71ed2914b5b641"
}

rule MalwareBazaar_unknown_056_9f18f8d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f18f8d711960456bb6b6dc8eb7d0853943f204b147c344dfb3e1eabf8f8004c"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 20:20:24"
  condition:
    hash.sha256(0, filesize) == "9f18f8d711960456bb6b6dc8eb7d0853943f204b147c344dfb3e1eabf8f8004c"
}

rule MalwareBazaar_unknown_057_c76dacd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76dacd838f6154778b347ccf7928eaab5ce0a17aceec8ff65bed775839fdc6d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 20:20:16"
  condition:
    hash.sha256(0, filesize) == "c76dacd838f6154778b347ccf7928eaab5ce0a17aceec8ff65bed775839fdc6d"
}

rule MalwareBazaar_unknown_058_74e636d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2"
    family = "unknown"
    file_name = "74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:19:49"
  condition:
    hash.sha256(0, filesize) == "74e636d09c7a51ad6dd8cb09c8ebc32961a7530cd24e6010947598c566c1f2d2"
}

rule MalwareBazaar_unknown_059_04ef8195
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef8195e31b65bf80ab31d7c97806e39bd90ef274a72708b55e8f6675ee72ed"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:17:43"
  condition:
    hash.sha256(0, filesize) == "04ef8195e31b65bf80ab31d7c97806e39bd90ef274a72708b55e8f6675ee72ed"
}

rule MalwareBazaar_unknown_060_caa892bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa892bff7c2645416a867c85a9c3d58c491e4bb130b8894d19fc1233ce91bec"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 20:15:47"
  condition:
    hash.sha256(0, filesize) == "caa892bff7c2645416a867c85a9c3d58c491e4bb130b8894d19fc1233ce91bec"
}

rule MalwareBazaar_unknown_061_f91b79e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef"
    family = "unknown"
    file_name = "f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef.exe"
    file_type = "exe"
    first_seen = "2026-08-15 20:14:54"
  condition:
    hash.sha256(0, filesize) == "f91b79e3699ef2eb397f65717116da36f978126b78786b260466fc9e1390afef"
}

rule MalwareBazaar_Mirai_062_70c037b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae"
    family = "Mirai"
    file_name = "70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae.elf"
    file_type = "elf"
    first_seen = "2026-08-15 19:54:47"
  condition:
    hash.sha256(0, filesize) == "70c037b40986a30fea6f9f2ae504eee508c4e1ca0bd859e8a78237d130758cae"
}

rule MalwareBazaar_unknown_063_263181e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "263181e4a36604b77eb8795e7a048d991f191de8e5c2e3d77fc8454f801be886"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 19:17:35"
  condition:
    hash.sha256(0, filesize) == "263181e4a36604b77eb8795e7a048d991f191de8e5c2e3d77fc8454f801be886"
}

rule MalwareBazaar_unknown_064_3aef5773
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aef5773707bcd2ac1d33b4ab18be2341f4f6f40acf784837ebc9222770facf8"
    family = "unknown"
    file_name = "Delta.ps1"
    file_type = "ps1"
    first_seen = "2026-08-15 19:13:26"
  condition:
    hash.sha256(0, filesize) == "3aef5773707bcd2ac1d33b4ab18be2341f4f6f40acf784837ebc9222770facf8"
}

rule MalwareBazaar_unknown_065_1050e7ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1050e7ca3b05cc57187f2ac7bed5ccb2b49150ac0ef4a8f4ee686dab61eaa330"
    family = "unknown"
    file_name = "Data.ps1"
    file_type = "ps1"
    first_seen = "2026-08-15 19:11:53"
  condition:
    hash.sha256(0, filesize) == "1050e7ca3b05cc57187f2ac7bed5ccb2b49150ac0ef4a8f4ee686dab61eaa330"
}

rule MalwareBazaar_unknown_066_afbd3876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afbd387612dae6d6d817231abb6465ad08ae34dd6c24568e2de89d9a3c5f30e0"
    family = "unknown"
    file_name = "DRFa1X25.ps1"
    file_type = "ps1"
    first_seen = "2026-08-15 19:08:16"
  condition:
    hash.sha256(0, filesize) == "afbd387612dae6d6d817231abb6465ad08ae34dd6c24568e2de89d9a3c5f30e0"
}

rule MalwareBazaar_CoinMiner_067_94620f61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94620f612e74609ad155ac854ca42b615e97361f0c6552e20ba902b690514a30"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-15 17:39:04"
  condition:
    hash.sha256(0, filesize) == "94620f612e74609ad155ac854ca42b615e97361f0c6552e20ba902b690514a30"
}

rule MalwareBazaar_QuasarRAT_068_3bccecdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bccecdca2ce3415df0774388ee45110c85073ea0f5e6b7ea8b00a6a1e334336"
    family = "QuasarRAT"
    file_name = "vhgvgcjg.exe"
    file_type = "exe"
    first_seen = "2026-08-15 17:14:27"
  condition:
    hash.sha256(0, filesize) == "3bccecdca2ce3415df0774388ee45110c85073ea0f5e6b7ea8b00a6a1e334336"
}

rule MalwareBazaar_Mirai_069_d64ad56e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea"
    family = "Mirai"
    file_name = "pandora.x86_64"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:58"
  condition:
    hash.sha256(0, filesize) == "d64ad56eca41d47cfb7f534623071dbdff25a49cdceae4dc9de6d7cdfa22e7ea"
}

rule MalwareBazaar_unknown_070_17922eda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17922edaad96218b0cb61af51fb70955da7f9396418c4d83330fc80ce4c71a32"
    family = "unknown"
    file_name = "scanner"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:56"
  condition:
    hash.sha256(0, filesize) == "17922edaad96218b0cb61af51fb70955da7f9396418c4d83330fc80ce4c71a32"
}

rule MalwareBazaar_Mirai_071_e4369695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4369695ea1edf4969558c295376c32d042599fb3348c2e5ea2b8563e46db1f3"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:54"
  condition:
    hash.sha256(0, filesize) == "e4369695ea1edf4969558c295376c32d042599fb3348c2e5ea2b8563e46db1f3"
}

rule MalwareBazaar_Mirai_072_0e8d4bbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:52"
  condition:
    hash.sha256(0, filesize) == "0e8d4bbbe9ded46090848a1a755e655f7c2771d48426b0bceecc9eb31d53ffa1"
}

rule MalwareBazaar_Mirai_073_92b2df9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92b2df9b3b1add879bb02447bf1a4484f7a3ce8058ae6f13228ec619714ecd4c"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:51"
  condition:
    hash.sha256(0, filesize) == "92b2df9b3b1add879bb02447bf1a4484f7a3ce8058ae6f13228ec619714ecd4c"
}

rule MalwareBazaar_Mirai_074_6d31b81e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-08-15 17:04:50"
  condition:
    hash.sha256(0, filesize) == "6d31b81e8cc94e6598e6bf13781df7bc13901ab3b0fc24fef12d4d71162a37ce"
}

rule MalwareBazaar_unknown_075_9623c860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd"
    family = "unknown"
    file_name = "9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd"
    file_type = "elf"
    first_seen = "2026-08-15 17:00:12"
  condition:
    hash.sha256(0, filesize) == "9623c860ea32daf38df770d354165d7c7802d337c8743c4288e3799ebcc8e0cd"
}

rule MalwareBazaar_ValleyRAT_076_1a20a7ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a20a7ec6847d1efc48a930b9c9fde601c9d0f41c0876febedcff913dd80dc7c"
    family = "ValleyRAT"
    file_name = "insoft_v10.0.18.exe"
    file_type = "exe"
    first_seen = "2026-08-15 16:53:20"
  condition:
    hash.sha256(0, filesize) == "1a20a7ec6847d1efc48a930b9c9fde601c9d0f41c0876febedcff913dd80dc7c"
}

rule MalwareBazaar_ValleyRAT_077_7db44e14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7db44e145483e67e5fa9944a0d1e9df51e4cd6a0b50249cd882a38eca2443ec7"
    family = "ValleyRAT"
    file_name = "insoft_v10.0.03.exe"
    file_type = "exe"
    first_seen = "2026-08-15 16:52:26"
  condition:
    hash.sha256(0, filesize) == "7db44e145483e67e5fa9944a0d1e9df51e4cd6a0b50249cd882a38eca2443ec7"
}

rule MalwareBazaar_unknown_078_45217ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45217ea08d8396e3ec70d7e0414f90cf92618adb52fa72261678361658a07bf7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 16:48:54"
  condition:
    hash.sha256(0, filesize) == "45217ea08d8396e3ec70d7e0414f90cf92618adb52fa72261678361658a07bf7"
}

rule MalwareBazaar_Mirai_079_a8ce925a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ce925aaa553b4d8878d2bacff9047b0837b96597a80a54e038f14b68878ce5"
    family = "Mirai"
    file_name = "mirai.i586"
    file_type = "elf"
    first_seen = "2026-08-15 16:39:51"
  condition:
    hash.sha256(0, filesize) == "a8ce925aaa553b4d8878d2bacff9047b0837b96597a80a54e038f14b68878ce5"
}

rule MalwareBazaar_Mirai_080_bd8715a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd8715a77f1dad85e48ba889d3d267a45e8bfdf618a8f7926008b0a4a89d6ee5"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-15 16:32:50"
  condition:
    hash.sha256(0, filesize) == "bd8715a77f1dad85e48ba889d3d267a45e8bfdf618a8f7926008b0a4a89d6ee5"
}

rule MalwareBazaar_unknown_081_0ac17b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ac17b5ec73932d1d3135ea38b0fc7dc598b3bb7941d32e0fb2160b882fdda8f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 16:26:49"
  condition:
    hash.sha256(0, filesize) == "0ac17b5ec73932d1d3135ea38b0fc7dc598b3bb7941d32e0fb2160b882fdda8f"
}

rule MalwareBazaar_Vidar_082_79399d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19"
    family = "Vidar"
    file_name = "79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19.bin"
    file_type = "exe"
    first_seen = "2026-08-15 16:26:22"
  condition:
    hash.sha256(0, filesize) == "79399d2ccde8a358e1f62b9422e4ba4d337d14b293f0d351b5f611549188cf19"
}

rule MalwareBazaar_Vidar_083_c713bb38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4"
    family = "Vidar"
    file_name = "c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4.bin"
    file_type = "exe"
    first_seen = "2026-08-15 16:15:11"
  condition:
    hash.sha256(0, filesize) == "c713bb386cb58f4e69960add340c8597fad9989cfb00a6bcfe2f4767dbf1cfc4"
}

rule MalwareBazaar_unknown_084_7df1ad3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7df1ad3f296151ca57f5041f4863d6309ec7c8e99918fd2c9c75be7b9e6cc64f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-15 16:03:58"
  condition:
    hash.sha256(0, filesize) == "7df1ad3f296151ca57f5041f4863d6309ec7c8e99918fd2c9c75be7b9e6cc64f"
}

rule MalwareBazaar_unknown_085_7824e906
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7824e906e6bc2fe40b62b7fed3990103dd894ac0e27367ac4509eb9e2209dbcf"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-08-15 15:47:52"
  condition:
    hash.sha256(0, filesize) == "7824e906e6bc2fe40b62b7fed3990103dd894ac0e27367ac4509eb9e2209dbcf"
}

rule MalwareBazaar_unknown_086_9430beed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1"
    family = "unknown"
    file_name = "9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1.exe"
    file_type = "exe"
    first_seen = "2026-08-15 15:44:51"
  condition:
    hash.sha256(0, filesize) == "9430beeddeb4625b87ca3fd1deb45141400c19c826c2140ccd2e264beea179f1"
}

rule MalwareBazaar_unknown_087_12419d8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12419d8ededdec0eaf1a62673d5d3a9810902385ae25881326cc3b8b331970da"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 15:43:51"
  condition:
    hash.sha256(0, filesize) == "12419d8ededdec0eaf1a62673d5d3a9810902385ae25881326cc3b8b331970da"
}

rule MalwareBazaar_unknown_088_34fe8764
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34fe876495ae17e947e2cfde048d48ab3b88d2b6e0168316c7faea7313363a12"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-08-15 15:39:52"
  condition:
    hash.sha256(0, filesize) == "34fe876495ae17e947e2cfde048d48ab3b88d2b6e0168316c7faea7313363a12"
}

rule MalwareBazaar_unknown_089_1a92991e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044"
    family = "unknown"
    file_name = "1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044.exe"
    file_type = "exe"
    first_seen = "2026-08-15 15:39:45"
  condition:
    hash.sha256(0, filesize) == "1a92991e472345b682a7001bd4ff4a91415599a8423d27921302c46b581cf044"
}

rule MalwareBazaar_Mirai_090_bb0eacdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0eacdc7520edbdb04dee384543e2caf6beeee3fbad2731dbc8ebe9f13f0fb5"
    family = "Mirai"
    file_name = "mirai.mpsl"
    file_type = "elf"
    first_seen = "2026-08-15 15:06:50"
  condition:
    hash.sha256(0, filesize) == "bb0eacdc7520edbdb04dee384543e2caf6beeee3fbad2731dbc8ebe9f13f0fb5"
}

rule MalwareBazaar_unknown_091_a79bc329
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79bc3298b6b2de35d8f52b71a6d6545701f42b8cc1cfabfed24f62ed81801de"
    family = "unknown"
    file_name = "WindowsCodecs.dll"
    file_type = "exe"
    first_seen = "2026-08-15 14:55:04"
  condition:
    hash.sha256(0, filesize) == "a79bc3298b6b2de35d8f52b71a6d6545701f42b8cc1cfabfed24f62ed81801de"
}

rule MalwareBazaar_Mirai_092_59688106
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59688106ddc46d7ec9f7e7b00ccb511b9d249fe12ea98fec358dc838b518fa56"
    family = "Mirai"
    file_name = "mirai.arm"
    file_type = "elf"
    first_seen = "2026-08-15 14:47:51"
  condition:
    hash.sha256(0, filesize) == "59688106ddc46d7ec9f7e7b00ccb511b9d249fe12ea98fec358dc838b518fa56"
}

rule MalwareBazaar_Mirai_093_4ad494ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ad494ac04aa0969ab8deb6ff8bbe936f9471ff38f505e2c2808a0b5e8af848c"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-08-15 14:39:50"
  condition:
    hash.sha256(0, filesize) == "4ad494ac04aa0969ab8deb6ff8bbe936f9471ff38f505e2c2808a0b5e8af848c"
}

rule MalwareBazaar_Mirai_094_59035939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59035939cbb1988d8530155c6a6ee108e0296b620fa3a5edbb9cf898d0859d08"
    family = "Mirai"
    file_name = "mirai.ppc"
    file_type = "elf"
    first_seen = "2026-08-15 14:22:52"
  condition:
    hash.sha256(0, filesize) == "59035939cbb1988d8530155c6a6ee108e0296b620fa3a5edbb9cf898d0859d08"
}

rule MalwareBazaar_unknown_095_2e60aaa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e60aaa4cd0bc283cfdbc5a04655026bfdb61779b34438cc4df59e38054fa814"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 14:16:53"
  condition:
    hash.sha256(0, filesize) == "2e60aaa4cd0bc283cfdbc5a04655026bfdb61779b34438cc4df59e38054fa814"
}

rule MalwareBazaar_unknown_096_e38c6482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e38c6482e4ade50e555803270d5a79e5f32a0f1453de2c6378982bf92668cd69"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-15 14:16:51"
  condition:
    hash.sha256(0, filesize) == "e38c6482e4ade50e555803270d5a79e5f32a0f1453de2c6378982bf92668cd69"
}

rule MalwareBazaar_unknown_097_5f310f20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f310f2036e26b3b441f1a7c003384a93df7e3e092922d65d67f7e8739eb4f83"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-08-15 14:16:45"
  condition:
    hash.sha256(0, filesize) == "5f310f2036e26b3b441f1a7c003384a93df7e3e092922d65d67f7e8739eb4f83"
}

rule MalwareBazaar_Mirai_098_d0d4547f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0d4547f15a6d6f1b624a1b4ba745d0a167a614802b800542d394d99ce7b72e6"
    family = "Mirai"
    file_name = "mirai.sh4"
    file_type = "elf"
    first_seen = "2026-08-15 14:15:53"
  condition:
    hash.sha256(0, filesize) == "d0d4547f15a6d6f1b624a1b4ba745d0a167a614802b800542d394d99ce7b72e6"
}

rule MalwareBazaar_unknown_099_cd4d9ce2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763"
    family = "unknown"
    file_name = "cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763.exe"
    file_type = "exe"
    first_seen = "2026-08-15 14:14:43"
  condition:
    hash.sha256(0, filesize) == "cd4d9ce29b22ccd9bc97d50d32923b84b44a2ce081b13124cda0a33523f86763"
}

rule MalwareBazaar_CoinMiner_100_7aff13bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760"
    family = "CoinMiner"
    file_name = "7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760.exe"
    file_type = "exe"
    first_seen = "2026-08-15 14:09:43"
  condition:
    hash.sha256(0, filesize) == "7aff13bfb7e02f948cd94a0bd44a4c37b1fe527367523846b0424ccf43f9b760"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

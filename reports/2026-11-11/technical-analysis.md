# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-11

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 694 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 694 |
| Unique family labels | 8 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 40 |
| SalatStealer | 39 |
| Mirai | 12 |
| WARDENStealer | 4 |
| RevStealer | 2 |
| Gafgyt | 1 |
| Arechclient2 | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 80 |
| elf | 14 |
| msi | 2 |
| zip | 2 |
| sh | 1 |
| iso | 1 |

## Per-Sample Analysis

### Sample 1: `e40b120a7862fd88`

| Field | Value |
|---|---|
| SHA-256 | `e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425` |
| Family label | `unknown` |
| File name | `e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425` |
| File type | `exe` |
| First seen | `2026-11-11 06:41:28` |
| Reporter | `c2hunter` |
| Tags | `exe, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c077e0ae504cbafafd2bbd93333212e4` |
| SHA-1 | `5350b9cde1b8e08a42c0ddc772e1e64ccdcbe6a5` |
| SHA-256 | `e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425` |
| SHA3-384 | `08a44f93fedb122d451d0e67fb60395c053735d78d631d7e64454adc7d0aa99fb1ac107ba8e94763a70b9ce8e6e85578` |
| IMPHASH | `899ad1596f9c6642245b3fb721bae585` |
| TLSH | `T10E34AE73A4BCEB9FDDD82F779C8B850713A62FD98890203E0D94751EFD2A5082E35616` |
| SSDEEP | `3072:baZcM3pgOPBdu/XkI8KCcMrnfaoaGmK8K7AzZIl/7Z0NWehnLCW9IPkPduwXFo3y:WWO6fPkhKCDahM90ZGyNhLCW9IMPdwy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_e40b120a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425"
    family = "unknown"
    file_name = "e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425"
    file_type = "exe"
    first_seen = "2026-11-11 06:41:28"
  condition:
    hash.sha256(0, filesize) == "e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425"
}
```

### Sample 2: `a8d439d55a0dc0f1`

| Field | Value |
|---|---|
| SHA-256 | `a8d439d55a0dc0f17afcde668d72539b7de88e03479b4a916e9073c4634d5dc3` |
| Family label | `Gafgyt` |
| File name | `a-r.m-7.Sakura` |
| File type | `elf` |
| First seen | `2026-11-11 06:39:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb6ccd07aa2dac2a9f7bd7b2386d1495` |
| SHA-1 | `4e3ff97032564f284cfdfc94688bdb248d2cfbd0` |
| SHA-256 | `a8d439d55a0dc0f17afcde668d72539b7de88e03479b4a916e9073c4634d5dc3` |
| SHA3-384 | `fca30e2af645cfdd89f33a9ed51b73c37531be527862e6e0ac2e117515e31180fbd2135ea2828d9f401ed3e57562e4af` |
| TLSH | `T1E4933947B71C0B53C59B59F12CEB3BF08B69B9A013E76185A50AEFD00372EB12512FA5` |
| TELFHASH | `t17011d04270bac91d2bb659245cbc42b5165536236381be75bf0ec5c45537002ba79e8f` |
| SSDEEP | `1536:gQO+DLzfC4XjHK5gBNcLiMChg8JBtcj+7wXRumXxVqDrstKfz9e:gdBqbNcLbbt+7GumXxVqDrIKfz9e` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_002_a8d439d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8d439d55a0dc0f17afcde668d72539b7de88e03479b4a916e9073c4634d5dc3"
    family = "Gafgyt"
    file_name = "a-r.m-7.Sakura"
    file_type = "elf"
    first_seen = "2026-11-11 06:39:04"
  condition:
    hash.sha256(0, filesize) == "a8d439d55a0dc0f17afcde668d72539b7de88e03479b4a916e9073c4634d5dc3"
}
```

### Sample 3: `21bb5cc4f1d06276`

| Field | Value |
|---|---|
| SHA-256 | `21bb5cc4f1d06276094476140eef9031cc341138920876d4f3c8fdeca82fe845` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `sh` |
| First seen | `2026-11-11 06:35:12` |
| Reporter | `pickledrick` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dcb7e6307cbe55769f3e674792327a5` |
| SHA-1 | `8f3b796a9762a2166342dc8662e82fb10b1b9447` |
| SHA-256 | `21bb5cc4f1d06276094476140eef9031cc341138920876d4f3c8fdeca82fe845` |
| SHA3-384 | `253657caa34cd15e414c743e15a195f42d796315f5aa364fb4875399f3325ef56eb53a7a6b88130554706835cbefcf3f` |
| TLSH | `T146217FE9FEB3D531370C492DF55A067DBBC78E3D09F83946905AAC90561C56C9018B37` |
| SSDEEP | `24:fev4q68Pb6ea55A5DsuIz5Y5Df35A5DsU5Y5Df1Gwpi:WgUPb6eaH6DnCyDfp6DNyDfHA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_21bb5cc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21bb5cc4f1d06276094476140eef9031cc341138920876d4f3c8fdeca82fe845"
    family = "Mirai"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-11 06:35:12"
  condition:
    hash.sha256(0, filesize) == "21bb5cc4f1d06276094476140eef9031cc341138920876d4f3c8fdeca82fe845"
}
```

### Sample 4: `b2144edce534cb5e`

| Field | Value |
|---|---|
| SHA-256 | `b2144edce534cb5e4072f66a27e029a357f2c629bb3437c1007051b77652f774` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-11 06:28:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fd14914ab065f3d441f176ea6444b41` |
| SHA-1 | `8dffe0da836f336b794284a1a8c04e5afa08097f` |
| SHA-256 | `b2144edce534cb5e4072f66a27e029a357f2c629bb3437c1007051b77652f774` |
| SHA3-384 | `c01778c878ab5153bb53671c898a2750bb7b4f57a8fb2390133c208387ef2b38160b0365b8feb91c48370835f721e3d9` |
| TLSH | `T1E3556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS8:SDjxB4m5n8XlaPWi+d+a4TjxQP46` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_b2144edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2144edce534cb5e4072f66a27e029a357f2c629bb3437c1007051b77652f774"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 06:28:04"
  condition:
    hash.sha256(0, filesize) == "b2144edce534cb5e4072f66a27e029a357f2c629bb3437c1007051b77652f774"
}
```

### Sample 5: `e3c5de25e23d08bc`

| Field | Value |
|---|---|
| SHA-256 | `e3c5de25e23d08bcba083fa7f12306dcc9abe741df27f3be0ddeff90b6c5ab8d` |
| Family label | `unknown` |
| File name | `0bee7c8bd9aea730.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:26:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29e900e83953647d4e7168e4fd163f9a` |
| SHA-1 | `e5e15fa0d12f687039ee3029a670c9a3646a4b48` |
| SHA-256 | `e3c5de25e23d08bcba083fa7f12306dcc9abe741df27f3be0ddeff90b6c5ab8d` |
| SHA3-384 | `88f5f00e47e4fa49ac1afd1f380f178e1ee5aec7b24ccd44da954f2ae9c2a7890a9d36e6a267827b46a5fa6b037654b2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D6C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_e3c5de25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3c5de25e23d08bcba083fa7f12306dcc9abe741df27f3be0ddeff90b6c5ab8d"
    family = "unknown"
    file_name = "0bee7c8bd9aea730.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:35"
  condition:
    hash.sha256(0, filesize) == "e3c5de25e23d08bcba083fa7f12306dcc9abe741df27f3be0ddeff90b6c5ab8d"
}
```

### Sample 6: `1ae78d73d9c742e8`

| Field | Value |
|---|---|
| SHA-256 | `1ae78d73d9c742e8f4c0684f4f22b8242ec2bb258e4eb4b2fc2bb982d4e2455e` |
| Family label | `unknown` |
| File name | `c3614cc181dea26e.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:26:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aef1b3f9d7f193f4f6aac9bdee99bd42` |
| SHA-1 | `6128e9a2c0b480a6fc4d5413d41aa8d0f2d24e4c` |
| SHA-256 | `1ae78d73d9c742e8f4c0684f4f22b8242ec2bb258e4eb4b2fc2bb982d4e2455e` |
| SHA3-384 | `0d09133f8022a99bda15204e1d7c80cad87d91d43e53a6167abc41df180aa9fcac10367c4628a81b60a63e1ed163c519` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T184C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+O:yBkKr5rszpNDy+O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_1ae78d73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae78d73d9c742e8f4c0684f4f22b8242ec2bb258e4eb4b2fc2bb982d4e2455e"
    family = "unknown"
    file_name = "c3614cc181dea26e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:30"
  condition:
    hash.sha256(0, filesize) == "1ae78d73d9c742e8f4c0684f4f22b8242ec2bb258e4eb4b2fc2bb982d4e2455e"
}
```

### Sample 7: `afdc6e80049ec18b`

| Field | Value |
|---|---|
| SHA-256 | `afdc6e80049ec18bc03269dfeb6137650bfd9caaf8f33d037bf1a855aae6616a` |
| Family label | `unknown` |
| File name | `1b7b026db4b15278.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:26:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `191dfaa5cc408fa0cac8c9f9be9e8e7c` |
| SHA-1 | `4a5b2a65cec8085ea5568fdfc657f3635b1f66d1` |
| SHA-256 | `afdc6e80049ec18bc03269dfeb6137650bfd9caaf8f33d037bf1a855aae6616a` |
| SHA3-384 | `bcf7781772b0b46ab12f800fc3aef831954d8faebbbbfd5f06c19a6f71fa94937f83ba6933222f4e3cdbdb62cf7df68c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T178C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+S:yBkKr5rszpNDy+S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_afdc6e80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afdc6e80049ec18bc03269dfeb6137650bfd9caaf8f33d037bf1a855aae6616a"
    family = "unknown"
    file_name = "1b7b026db4b15278.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:25"
  condition:
    hash.sha256(0, filesize) == "afdc6e80049ec18bc03269dfeb6137650bfd9caaf8f33d037bf1a855aae6616a"
}
```

### Sample 8: `d09be12468f12155`

| Field | Value |
|---|---|
| SHA-256 | `d09be12468f12155fdd0465d6912034c5e346119ff512373f1a904462cf9db19` |
| Family label | `unknown` |
| File name | `f3c02baf53bd71ff.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:26:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ade55f82bb772d7afe6a1f519a9cf08f` |
| SHA-1 | `fdbf7ea72c57cdd9a63d7c3458344b08b8b7d783` |
| SHA-256 | `d09be12468f12155fdd0465d6912034c5e346119ff512373f1a904462cf9db19` |
| SHA3-384 | `ce62fc2f13877c4e34fed63734869414f14f73e24741d82173a6c2a0fceead62d113d7083c129b1635b3c71bd908866d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E9C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_d09be124
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d09be12468f12155fdd0465d6912034c5e346119ff512373f1a904462cf9db19"
    family = "unknown"
    file_name = "f3c02baf53bd71ff.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:19"
  condition:
    hash.sha256(0, filesize) == "d09be12468f12155fdd0465d6912034c5e346119ff512373f1a904462cf9db19"
}
```

### Sample 9: `0bee7c8bd9aea730`

| Field | Value |
|---|---|
| SHA-256 | `0bee7c8bd9aea73097216c2793deb9da11e051d7b12e88ccbc38d17a78fddc63` |
| Family label | `SalatStealer` |
| File name | `0bee7c8bd9aea730.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3619259f5b79514fe8fbde47c3fe42f` |
| SHA-1 | `980009d680978bc3e40102ac1443eaf35314b5df` |
| SHA-256 | `0bee7c8bd9aea73097216c2793deb9da11e051d7b12e88ccbc38d17a78fddc63` |
| SHA3-384 | `fd13a3cc68da72ffe34d7aaa9aa7224931c69fddf81ea2031bfc9ba47c26652cbafb5dc6297409900abf362bdb9ba722` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C3F5335BF5AB4BB3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0846FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OD:iJiafuIO7rhWEES4a` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_009_0bee7c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bee7c8bd9aea73097216c2793deb9da11e051d7b12e88ccbc38d17a78fddc63"
    family = "SalatStealer"
    file_name = "0bee7c8bd9aea730.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:59"
  condition:
    hash.sha256(0, filesize) == "0bee7c8bd9aea73097216c2793deb9da11e051d7b12e88ccbc38d17a78fddc63"
}
```

### Sample 10: `c3614cc181dea26e`

| Field | Value |
|---|---|
| SHA-256 | `c3614cc181dea26e8ac128cf768619b0b3dbb4aacf07de5efefe8967ce47d783` |
| Family label | `SalatStealer` |
| File name | `c3614cc181dea26e.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cd18c030bb10bb0a8a7c10c9dd08005` |
| SHA-1 | `e552d8243f7723c4790f0d3f5dc4d53f9615a9e2` |
| SHA-256 | `c3614cc181dea26e8ac128cf768619b0b3dbb4aacf07de5efefe8967ce47d783` |
| SHA3-384 | `2adb71ce2a7d8d10a221f4b46ef32b1a513094eb0d356715736ef4f9569edb90a6567ad5c475c5263cb15502377b425c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T104F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oi:iJiafuIO7rhWEES4Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_010_c3614cc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3614cc181dea26e8ac128cf768619b0b3dbb4aacf07de5efefe8967ce47d783"
    family = "SalatStealer"
    file_name = "c3614cc181dea26e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:48"
  condition:
    hash.sha256(0, filesize) == "c3614cc181dea26e8ac128cf768619b0b3dbb4aacf07de5efefe8967ce47d783"
}
```

### Sample 11: `1b7b026db4b15278`

| Field | Value |
|---|---|
| SHA-256 | `1b7b026db4b15278bda9dce0d41a6440ed5946b787db0dad7da9570289105158` |
| Family label | `SalatStealer` |
| File name | `1b7b026db4b15278.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a5599a1c7b88822df4c9bd9003b0206` |
| SHA-1 | `cc44b2d6e27093db1aaec0a687575e552d4f12d1` |
| SHA-256 | `1b7b026db4b15278bda9dce0d41a6440ed5946b787db0dad7da9570289105158` |
| SHA3-384 | `9866bf114ef3d606c4cc06675185c6437cef18f263151dc8d8eed89a1c4d9433b96c792190b917e2d96f948f105e5bf5` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T114F5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O+:iJiafuIO7rhWEES43` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_011_1b7b026d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b7b026db4b15278bda9dce0d41a6440ed5946b787db0dad7da9570289105158"
    family = "SalatStealer"
    file_name = "1b7b026db4b15278.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:35"
  condition:
    hash.sha256(0, filesize) == "1b7b026db4b15278bda9dce0d41a6440ed5946b787db0dad7da9570289105158"
}
```

### Sample 12: `1dcef4b2676a892c`

| Field | Value |
|---|---|
| SHA-256 | `1dcef4b2676a892cc4c66d6e40a28ac2bad7ce0e06b2ef6905496630150103ec` |
| Family label | `unknown` |
| File name | `4d54b0f52cc8550f.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cba4f333bd0504d20893f948b87db89` |
| SHA-1 | `7e5781aa620c86a9067f40d1c8fbc7b49c1f461f` |
| SHA-256 | `1dcef4b2676a892cc4c66d6e40a28ac2bad7ce0e06b2ef6905496630150103ec` |
| SHA3-384 | `2555fccacaca585bf0b195380d39273f466eca07f643e974d121edc7e4a705c7c1acd9dc48cafa88f077685cdf22538e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T170C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+O:yBkKr5rszpNDy+O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_1dcef4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dcef4b2676a892cc4c66d6e40a28ac2bad7ce0e06b2ef6905496630150103ec"
    family = "unknown"
    file_name = "4d54b0f52cc8550f.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:33"
  condition:
    hash.sha256(0, filesize) == "1dcef4b2676a892cc4c66d6e40a28ac2bad7ce0e06b2ef6905496630150103ec"
}
```

### Sample 13: `6e54cacb597a0668`

| Field | Value |
|---|---|
| SHA-256 | `6e54cacb597a06688afe4975cb6a77bf3d9cf6f1a5d670a0c772a150eee7df81` |
| Family label | `unknown` |
| File name | `245438aab30ca463.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3ff28fcf3956dc8d90ad4c4b9f990e3` |
| SHA-1 | `550891597c8ae79081eb17fb23883b252190e2db` |
| SHA-256 | `6e54cacb597a06688afe4975cb6a77bf3d9cf6f1a5d670a0c772a150eee7df81` |
| SHA3-384 | `670eeb3799c4e4d6803253ef2b7914debf313f9b21e12afdd61da512534c5b80d716caf5cf38f98d942867925f5ce499` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T153C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+L:yBkKr5rszpNDy+L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_6e54cacb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e54cacb597a06688afe4975cb6a77bf3d9cf6f1a5d670a0c772a150eee7df81"
    family = "unknown"
    file_name = "245438aab30ca463.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:28"
  condition:
    hash.sha256(0, filesize) == "6e54cacb597a06688afe4975cb6a77bf3d9cf6f1a5d670a0c772a150eee7df81"
}
```

### Sample 14: `f3c02baf53bd71ff`

| Field | Value |
|---|---|
| SHA-256 | `f3c02baf53bd71ff4cfcce2c66accb60213e57673d916a7e22d9daf5c0b8c3c2` |
| Family label | `SalatStealer` |
| File name | `f3c02baf53bd71ff.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:23` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dfe6bc8d3990a9a70f755626e2ac437` |
| SHA-1 | `bd54fa5baceb00c976c087b497730706f3cc5f78` |
| SHA-256 | `f3c02baf53bd71ff4cfcce2c66accb60213e57673d916a7e22d9daf5c0b8c3c2` |
| SHA3-384 | `20ccf07e14721b8c7e08067e08f7b9ad8282be43fe38bc9099ed5c4048e1c9cbb65d9862110352db335e7d66c2c6d2ec` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C1F5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OS:iJiafuIO7rhWEES4X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_014_f3c02baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c02baf53bd71ff4cfcce2c66accb60213e57673d916a7e22d9daf5c0b8c3c2"
    family = "SalatStealer"
    file_name = "f3c02baf53bd71ff.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:23"
  condition:
    hash.sha256(0, filesize) == "f3c02baf53bd71ff4cfcce2c66accb60213e57673d916a7e22d9daf5c0b8c3c2"
}
```

### Sample 15: `6a98973a22487802`

| Field | Value |
|---|---|
| SHA-256 | `6a98973a22487802bf73ef44cc5dbd1ccf6b0e877824b0770d08e57172f544c1` |
| Family label | `unknown` |
| File name | `25d90d9bf76df911.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2df608f307ddf29c820d1637a986a76b` |
| SHA-1 | `bf0ebb3dc3d8b4183027d3ff998ba04e3dacc609` |
| SHA-256 | `6a98973a22487802bf73ef44cc5dbd1ccf6b0e877824b0770d08e57172f544c1` |
| SHA3-384 | `946863cabfd1276a2ac4d52a9f3b5b0b9e5d6446f898e163ed76b477d22cdb3e5604edb723dcfaa43a66efcfecff3979` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T128C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+2:yBkKr5rszpNDy+2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_6a98973a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a98973a22487802bf73ef44cc5dbd1ccf6b0e877824b0770d08e57172f544c1"
    family = "unknown"
    file_name = "25d90d9bf76df911.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:22"
  condition:
    hash.sha256(0, filesize) == "6a98973a22487802bf73ef44cc5dbd1ccf6b0e877824b0770d08e57172f544c1"
}
```

### Sample 16: `4d54b0f52cc8550f`

| Field | Value |
|---|---|
| SHA-256 | `4d54b0f52cc8550f3ac5018ea16b7b174a8e7503497cf07d6594a09f17b90232` |
| Family label | `SalatStealer` |
| File name | `4d54b0f52cc8550f.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:25:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4a3ec20c5edf1613dba6d8c3b5b9110` |
| SHA-1 | `9156a2459a87f6dfba671bcbb3e3dc78f76ff422` |
| SHA-256 | `4d54b0f52cc8550f3ac5018ea16b7b174a8e7503497cf07d6594a09f17b90232` |
| SHA3-384 | `ea85e388ce83e064eb6694c307e02b5008133dff1337e7887529c0ff8f448bc0163c5efb0d30933366b8cca94e7d636c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T182F5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OK:iJiafuIO7rhWEES4J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_016_4d54b0f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d54b0f52cc8550f3ac5018ea16b7b174a8e7503497cf07d6594a09f17b90232"
    family = "SalatStealer"
    file_name = "4d54b0f52cc8550f.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:11"
  condition:
    hash.sha256(0, filesize) == "4d54b0f52cc8550f3ac5018ea16b7b174a8e7503497cf07d6594a09f17b90232"
}
```

### Sample 17: `245438aab30ca463`

| Field | Value |
|---|---|
| SHA-256 | `245438aab30ca463a34d9b14122072f26bf9b6a7a84c5b406023328f8076639c` |
| Family label | `SalatStealer` |
| File name | `245438aab30ca463.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:24:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8581b09abb0ed921767f5e5e404d159` |
| SHA-1 | `57b9cce7f45a597ef7d6c8e13814f887646387b2` |
| SHA-256 | `245438aab30ca463a34d9b14122072f26bf9b6a7a84c5b406023328f8076639c` |
| SHA3-384 | `69e8a14864eff62d04544358c06af83d8efa6d542cdc9e309d3be9be933f360426a6b7e3cbc4890fe5760fdacd872a17` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T118F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Of:iJiafuIO7rhWEES4y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_017_245438aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245438aab30ca463a34d9b14122072f26bf9b6a7a84c5b406023328f8076639c"
    family = "SalatStealer"
    file_name = "245438aab30ca463.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:24:52"
  condition:
    hash.sha256(0, filesize) == "245438aab30ca463a34d9b14122072f26bf9b6a7a84c5b406023328f8076639c"
}
```

### Sample 18: `25d90d9bf76df911`

| Field | Value |
|---|---|
| SHA-256 | `25d90d9bf76df91180601fd1c49c81aaf2ffbfc0383591c70db5c47b2d11e92b` |
| Family label | `SalatStealer` |
| File name | `25d90d9bf76df911.bin` |
| File type | `exe` |
| First seen | `2026-11-11 06:24:40` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `145b1be65c138b85a1e72cb95b6952b9` |
| SHA-1 | `1a0be95ae43356db7de5b9f36716561f1d0fde39` |
| SHA-256 | `25d90d9bf76df91180601fd1c49c81aaf2ffbfc0383591c70db5c47b2d11e92b` |
| SHA3-384 | `7c04dff94089cc1710e59bbe94cf677b3806f9a3fa318d227844855c6eebad3c3160336cf4917b6ce1e8d35d313449cf` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1ECF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES4F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_018_25d90d9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d90d9bf76df91180601fd1c49c81aaf2ffbfc0383591c70db5c47b2d11e92b"
    family = "SalatStealer"
    file_name = "25d90d9bf76df911.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:24:40"
  condition:
    hash.sha256(0, filesize) == "25d90d9bf76df91180601fd1c49c81aaf2ffbfc0383591c70db5c47b2d11e92b"
}
```

### Sample 19: `eae2ce72c550077d`

| Field | Value |
|---|---|
| SHA-256 | `eae2ce72c550077dbb13efb57ef2e528e98ca1bdff10fc64be52ded8dc1a9a28` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-11 06:23:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd50c4c2d4b3c14f287006511fd45e78` |
| SHA-1 | `8f439257b3a1ca465f302db3b3efa907d160b936` |
| SHA-256 | `eae2ce72c550077dbb13efb57ef2e528e98ca1bdff10fc64be52ded8dc1a9a28` |
| SHA3-384 | `5d91c653f7aa04e9a820f007cd67de7753c7fd5906f6946638d1e106b685628af357de956a7dd00895324f001b5955da` |
| TLSH | `T1E076199BB9914942C4E83A77B8BE80C833630EB99B9716175D05FE383EBE5D90E34714` |
| TELFHASH | `t1fbd09704adeef3ecb2c240886530425e2bc830fc1000b3547fbeb2cf0e8022060e90ba` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vZEAv5WEV2kDKWtoQXXRgRPV+aeq8MDPopdzXgxq0Dl5E1:xEAsEV2kDKWtoQHuqLvMDPo7zX+bE1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_eae2ce72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae2ce72c550077dbb13efb57ef2e528e98ca1bdff10fc64be52ded8dc1a9a28"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 06:23:05"
  condition:
    hash.sha256(0, filesize) == "eae2ce72c550077dbb13efb57ef2e528e98ca1bdff10fc64be52ded8dc1a9a28"
}
```

### Sample 20: `e80b34bb4e2de536`

| Field | Value |
|---|---|
| SHA-256 | `e80b34bb4e2de5360a9e80a90fed0ea694e47deb223980e39982f9c7ccb7c531` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-11-11 05:45:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c469e6dc96bfd83b28f3e51c26ce600` |
| SHA-1 | `3eeec4289d602587135030dfb198b5f96ac285cb` |
| SHA-256 | `e80b34bb4e2de5360a9e80a90fed0ea694e47deb223980e39982f9c7ccb7c531` |
| SHA3-384 | `05cc2e66bbb050cb622c493f72d39c650b2d5eeb5ef9192b6acfd7377548dcf1901e4d9bb77b173b0c3655ec6e44b745` |
| TLSH | `T19A648C93B3C78FD2E22065B04AF3852DBDE9266609F7C497C376AD2103A11E47C1EE85` |
| SSDEEP | `3072:77U4GYILWRzO3o4uX9Vg453SVeTCEXl0/WgaNxXCri1DOATYhh6vxNuKWbrrztf6:WYpRvB735TLg2n1DO7mkpjzhoIwxsR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_e80b34bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e80b34bb4e2de5360a9e80a90fed0ea694e47deb223980e39982f9c7ccb7c531"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-11-11 05:45:04"
  condition:
    hash.sha256(0, filesize) == "e80b34bb4e2de5360a9e80a90fed0ea694e47deb223980e39982f9c7ccb7c531"
}
```

### Sample 21: `4ea4f8c30a3969d9`

| Field | Value |
|---|---|
| SHA-256 | `4ea4f8c30a3969d9439593e0b9f16275b14955fd353330c542278ff42c952fd5` |
| Family label | `unknown` |
| File name | `Noticefrom-TaxDepartmen.img` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:40` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2ca65fc69c19b4a27626824942e73cb` |
| SHA-1 | `db82ad818e20f741115d85c30eece22c667a509e` |
| SHA-256 | `4ea4f8c30a3969d9439593e0b9f16275b14955fd353330c542278ff42c952fd5` |
| SHA3-384 | `aa6d0ad8d901f7590508f9d76c3bc761f822d3f631619d0f6fe10fd55b7f5d89791883b163b18ae472cec0b60ce94fe5` |
| IMPHASH | `61d039ce1b0a8246410b491d436ccd74` |
| TLSH | `T127D5EC9C35EF8A5ED246BA380BFDEB4FC84BA476D04F3A9B11D05B434613D90AB45839` |
| SSDEEP | `24576:2ZJuakfrp0aeaxxkU+hdp7IKlWJ79dxLM45YKa+t6t6IHGu:2ZJuakjGdp7ICWJ79dxLxYKa+I6IHGu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_4ea4f8c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ea4f8c30a3969d9439593e0b9f16275b14955fd353330c542278ff42c952fd5"
    family = "unknown"
    file_name = "Noticefrom-TaxDepartmen.img"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:40"
  condition:
    hash.sha256(0, filesize) == "4ea4f8c30a3969d9439593e0b9f16275b14955fd353330c542278ff42c952fd5"
}
```

### Sample 22: `f64aab684e202296`

| Field | Value |
|---|---|
| SHA-256 | `f64aab684e202296b22f16e0d5b494b822c84c7614b1b5a27ad71ac8504d0ee6` |
| Family label | `unknown` |
| File name | `_00042` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:37` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf37cb82cb299568b3e2aafca8092cfb` |
| SHA-1 | `2633281a1e27505325fa788265ebe05c06fa70bd` |
| SHA-256 | `f64aab684e202296b22f16e0d5b494b822c84c7614b1b5a27ad71ac8504d0ee6` |
| SHA3-384 | `ec7a7988f4703a93c090744a366ceda3e408bcb10a51d6d31be42daf766f3972e9f0e3a949cf9e8b185690853523061d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15215F05423ADDB07E9B55BF00971D23923F47E8AA920D30A4ED6ACEB7832F406D54787` |
| SSDEEP | `24576:UKI6T2Cq5crplpOX2l98u1i86VfmxnGJF9c:jypRy/4Mxk4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_f64aab68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64aab684e202296b22f16e0d5b494b822c84c7614b1b5a27ad71ac8504d0ee6"
    family = "unknown"
    file_name = "_00042"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:37"
  condition:
    hash.sha256(0, filesize) == "f64aab684e202296b22f16e0d5b494b822c84c7614b1b5a27ad71ac8504d0ee6"
}
```

### Sample 23: `604484b0df68d2c2`

| Field | Value |
|---|---|
| SHA-256 | `604484b0df68d2c2f5aa4b75281fa8ef99250d3afd03736a64b3b3fe2136c593` |
| Family label | `unknown` |
| File name | `pd147996773.att` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:34` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4db5120d050d8ccd4adfb4760e59653` |
| SHA-1 | `b1f9015ee1c86115fcb8853e9a5174c3aa2e399c` |
| SHA-256 | `604484b0df68d2c2f5aa4b75281fa8ef99250d3afd03736a64b3b3fe2136c593` |
| SHA3-384 | `03ba2d7e68599288da0d2816364cef42c7dd3dc22d9b57e68297d48f65a18046d941033fe889172207ad24b8c4947513` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D115F05062A9EB07D9B457F51A71D23423B43E4AAA30D30B4FEAACEB3836F445D44397` |
| SSDEEP | `24576:0K4jhYIVBJmWZuwLAFcIDaK7kPl5eWF9c:rGfmYuwnSHm5eW4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_604484b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "604484b0df68d2c2f5aa4b75281fa8ef99250d3afd03736a64b3b3fe2136c593"
    family = "unknown"
    file_name = "pd147996773.att"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:34"
  condition:
    hash.sha256(0, filesize) == "604484b0df68d2c2f5aa4b75281fa8ef99250d3afd03736a64b3b3fe2136c593"
}
```

### Sample 24: `c07af04e7e02d271`

| Field | Value |
|---|---|
| SHA-256 | `c07af04e7e02d2715b9330a4a78b6be7c0c44b7ddec7738a5790b8a7eb374107` |
| Family label | `unknown` |
| File name | `_00021` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:31` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `946769cb593428a7bfe8c8ac78987a33` |
| SHA-1 | `cdfaa20d301bac9f66de4c2a6985c7cfd19473a6` |
| SHA-256 | `c07af04e7e02d2715b9330a4a78b6be7c0c44b7ddec7738a5790b8a7eb374107` |
| SHA3-384 | `89ebfccea53b0cca2a57ac109b5b842e33aa603f06cc42ac0d5639aacaaaceae82f0c97829bf8841c3f1730d5cbdc5b0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BAD4DF5463A9EF06D9795BF50A71D23813B43E4AA931D30A4FE6ADEB3432F40AD44393` |
| SSDEEP | `6144:34cvK31gQ6dwTmAdjSmr+XOS7FREYIQq/T9jA5JCIjMTKsBJ0blC8slaYzKj852J:jKFKilgFZm9A5JJjrqldI8BpF9c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_c07af04e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07af04e7e02d2715b9330a4a78b6be7c0c44b7ddec7738a5790b8a7eb374107"
    family = "unknown"
    file_name = "_00021"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:31"
  condition:
    hash.sha256(0, filesize) == "c07af04e7e02d2715b9330a4a78b6be7c0c44b7ddec7738a5790b8a7eb374107"
}
```

### Sample 25: `d9eca2aef9277205`

| Field | Value |
|---|---|
| SHA-256 | `d9eca2aef9277205b3afbbd4d4ec6097cc4fc0b8fc6d11dca3659a9340ac7e99` |
| Family label | `unknown` |
| File name | `0x7883934FBEA2DA57` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:28` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b546195cfab7690a68a9c44482f6267` |
| SHA-1 | `94dab53b6cbb6c34b37e0f8f9c3eb9b559403965` |
| SHA-256 | `d9eca2aef9277205b3afbbd4d4ec6097cc4fc0b8fc6d11dca3659a9340ac7e99` |
| SHA3-384 | `57fd8f378c89a0b12649c1fb5961ba629530136b31f5f86fb8c5983a4f2d92fe5bea7e525b2be0e7436a36038912bdc0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F215F05473A9EF06E9795BF10A71D27813B43E4AA521D30A4FEAACEB3832F416D44347` |
| SSDEEP | `24576:xKodF9YXrRa8UO57Uyx3oW+Pd6IJS3djxHqI:NaRNBoW+gIJidjZqI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_d9eca2ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9eca2aef9277205b3afbbd4d4ec6097cc4fc0b8fc6d11dca3659a9340ac7e99"
    family = "unknown"
    file_name = "0x7883934FBEA2DA57"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:28"
  condition:
    hash.sha256(0, filesize) == "d9eca2aef9277205b3afbbd4d4ec6097cc4fc0b8fc6d11dca3659a9340ac7e99"
}
```

### Sample 26: `cab9e7e4e7eb122d`

| Field | Value |
|---|---|
| SHA-256 | `cab9e7e4e7eb122de12f7bfdca618c1056a409e7505f6f051835bdfef9bc38a9` |
| Family label | `unknown` |
| File name | `52820a94fb444c72a5ff925687bec95e.MSG` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:25` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5b473460970fc5dd256528728f7c1f6` |
| SHA-1 | `edf88e6e168b962c6ff67259e66b24a1590f1b8f` |
| SHA-256 | `cab9e7e4e7eb122de12f7bfdca618c1056a409e7505f6f051835bdfef9bc38a9` |
| SHA3-384 | `a3bd3f70b64dd46cab878ffb9516f481ca881cdfa267e9ceb741a23dfdb3b1d40d3461fc2013fa70cbf263d15ed52436` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13D05E05462A9DF06D9796BF509B1D23813F57E8AA930D30A4FD6BCEB3822F006D54353` |
| SSDEEP | `24576:YKYYF9cvBNw2ebzkvTQH8V4HfzohxYmL27tw:D4vBNObzcTQcYzohCf7e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_cab9e7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab9e7e4e7eb122de12f7bfdca618c1056a409e7505f6f051835bdfef9bc38a9"
    family = "unknown"
    file_name = "52820a94fb444c72a5ff925687bec95e.MSG"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:25"
  condition:
    hash.sha256(0, filesize) == "cab9e7e4e7eb122de12f7bfdca618c1056a409e7505f6f051835bdfef9bc38a9"
}
```

### Sample 27: `548bb8dd7cb6a7d6`

| Field | Value |
|---|---|
| SHA-256 | `548bb8dd7cb6a7d6f42237e41f98fc70afedea03c65aadc4d3827fa5e57bb448` |
| Family label | `unknown` |
| File name | `md5001000192969.tmp` |
| File type | `exe` |
| First seen | `2026-11-11 05:31:22` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a1ef7ce7b5bbc539b1faa501e0b20df` |
| SHA-1 | `391dbb7c4000c0792d429343513f048014ebb35c` |
| SHA-256 | `548bb8dd7cb6a7d6f42237e41f98fc70afedea03c65aadc4d3827fa5e57bb448` |
| SHA3-384 | `f1449a2dbe31ac0fced9d894549511fdc4e475ee5fc53d48e6e94025b3babcfaeb7733d99f65ba463d76bcfb268c410a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11315E05463A9EB06E8795BF509B1D23813F17E4AA931D30A4FDAACEB7832F406D50353` |
| SSDEEP | `12288:sKFPLYpF9clROMhbSk4PAtC5f279NFj6NB+xmCsNVOMQtUR:sKlcF9c/bZC5f2RNFOv+ICsV4UR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_548bb8dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548bb8dd7cb6a7d6f42237e41f98fc70afedea03c65aadc4d3827fa5e57bb448"
    family = "unknown"
    file_name = "md5001000192969.tmp"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:22"
  condition:
    hash.sha256(0, filesize) == "548bb8dd7cb6a7d6f42237e41f98fc70afedea03c65aadc4d3827fa5e57bb448"
}
```

### Sample 28: `db5a117ba85458fc`

| Field | Value |
|---|---|
| SHA-256 | `db5a117ba85458fc772624493ad490ac59eba298708ba11720aa46d217ff27f1` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-11-11 05:27:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a59a4c27de3cceb562a0a38a0c6f105c` |
| SHA-1 | `1f93acc1cc19da4a76e11913ec78ad381563f150` |
| SHA-256 | `db5a117ba85458fc772624493ad490ac59eba298708ba11720aa46d217ff27f1` |
| SHA3-384 | `d6bad9cd563ab344f6e00cb292ef58a75a60c6c7d127751c96d5e7ee39f957d56301ff9e2db9e7ec6d34a3c16b3dd854` |
| TLSH | `T14A448D01FB184553C1825EB00A7B07B7D36E59912CF9F10D6A0ABF6A1732AF6A1CB7C5` |
| SSDEEP | `6144:cyCt+bQFeK+8Pgw1e8/hzCPx/XhGJBsU94SjeP/G+J5aY3/SZylR4w:NbQwp/XU9ANjR4w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_db5a117b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db5a117ba85458fc772624493ad490ac59eba298708ba11720aa46d217ff27f1"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-11 05:27:04"
  condition:
    hash.sha256(0, filesize) == "db5a117ba85458fc772624493ad490ac59eba298708ba11720aa46d217ff27f1"
}
```

### Sample 29: `62fee3c164b6aca4`

| Field | Value |
|---|---|
| SHA-256 | `62fee3c164b6aca4b1bdf2d0c162666adcb9fbc5c6eda7f0917bac2166ac9e12` |
| Family label | `unknown` |
| File name | `cfb4a4fe03cbeefd.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:26:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c002e5074a32084e22001e8c4ee6a909` |
| SHA-1 | `d118526c7d9c5c32b6c9f47399d467366ed3cee9` |
| SHA-256 | `62fee3c164b6aca4b1bdf2d0c162666adcb9fbc5c6eda7f0917bac2166ac9e12` |
| SHA3-384 | `a88de184a6a3b8b484efed0efa7b8805f3b5b2c406b307a1e3c2223a4f87387e4a1b71b5a801cdd1ba91a722901c2502` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T103C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+9:yBkKr5rszpNDy+9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_62fee3c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62fee3c164b6aca4b1bdf2d0c162666adcb9fbc5c6eda7f0917bac2166ac9e12"
    family = "unknown"
    file_name = "cfb4a4fe03cbeefd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:39"
  condition:
    hash.sha256(0, filesize) == "62fee3c164b6aca4b1bdf2d0c162666adcb9fbc5c6eda7f0917bac2166ac9e12"
}
```

### Sample 30: `e4c5fcfe2902dffc`

| Field | Value |
|---|---|
| SHA-256 | `e4c5fcfe2902dffc20eec1999e2cfa8fba7d4809682ea38a3266af6401f69ca0` |
| Family label | `unknown` |
| File name | `54700c5bdc9de74a.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:26:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd6822f3ebf373c752368616e58a7b43` |
| SHA-1 | `98bd3a28b2f3fb07503f59b7fe9861382914024e` |
| SHA-256 | `e4c5fcfe2902dffc20eec1999e2cfa8fba7d4809682ea38a3266af6401f69ca0` |
| SHA3-384 | `ee4beacda9103bf094c4c27c0ada26628c0f959709a0f2dbadae20d194b9db1ab6fcbf7c7efc82f81da4d5424cac6f89` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+8:yBkKr5rszpNDy+8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_e4c5fcfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4c5fcfe2902dffc20eec1999e2cfa8fba7d4809682ea38a3266af6401f69ca0"
    family = "unknown"
    file_name = "54700c5bdc9de74a.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:34"
  condition:
    hash.sha256(0, filesize) == "e4c5fcfe2902dffc20eec1999e2cfa8fba7d4809682ea38a3266af6401f69ca0"
}
```

### Sample 31: `af6236c77019dabd`

| Field | Value |
|---|---|
| SHA-256 | `af6236c77019dabd4c82fda176cfaf2c45a858ff395863bf2c367277896c3ea6` |
| Family label | `unknown` |
| File name | `ae8d52715f0a30f8.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:26:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa7d57302b1893a8239d98a1e64a9d70` |
| SHA-1 | `8c4df5bd653703fc42dd4f5dcc6695c28372c94d` |
| SHA-256 | `af6236c77019dabd4c82fda176cfaf2c45a858ff395863bf2c367277896c3ea6` |
| SHA3-384 | `a4abb0de4bcf93ac43a41b76c00179e5ac4f6e4caf2209a9898aa4d7b39a78e3f1b31dbb702863db2dc0eeed8f10fe6c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+j:yBkKr5rszpNDy+j` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_af6236c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af6236c77019dabd4c82fda176cfaf2c45a858ff395863bf2c367277896c3ea6"
    family = "unknown"
    file_name = "ae8d52715f0a30f8.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:27"
  condition:
    hash.sha256(0, filesize) == "af6236c77019dabd4c82fda176cfaf2c45a858ff395863bf2c367277896c3ea6"
}
```

### Sample 32: `374d0e8898a40eac`

| Field | Value |
|---|---|
| SHA-256 | `374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558` |
| Family label | `unknown` |
| File name | `466c512640001af3.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:26:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a38088c54bb339bd87b465b6788626d0` |
| SHA-1 | `3e51b1a5b6dcb74c053d8d0c010ec7c1a0cc2844` |
| SHA-256 | `374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558` |
| SHA3-384 | `b5e6a99414b18fac12f504173540f5da4e041475b9c58d35072c607101567ffd09b23bc428c62956fd8907863190b136` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T141C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+J:yBkKr5rszpNDy+J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_374d0e88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558"
    family = "unknown"
    file_name = "466c512640001af3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:20"
  condition:
    hash.sha256(0, filesize) == "374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558"
}
```

### Sample 33: `cfb4a4fe03cbeefd`

| Field | Value |
|---|---|
| SHA-256 | `cfb4a4fe03cbeefdd258e68031f40011cf9d06b142b8421c09d2e396d551dbf1` |
| Family label | `SalatStealer` |
| File name | `cfb4a4fe03cbeefd.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:55` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42a541da31ebba9af8171e6305a86716` |
| SHA-1 | `ae646907ad5467c479218d4c3a14dd94972e8f07` |
| SHA-256 | `cfb4a4fe03cbeefdd258e68031f40011cf9d06b142b8421c09d2e396d551dbf1` |
| SHA3-384 | `bfa73d8c99197e79d8643a83e24f65948f7d25177f1d5ddb909ce801d8c4407dd76c92fbceaf44b2aa17c09da0f95756` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T19CF5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OJ:iJiafuIO7rhWEES46` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_cfb4a4fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfb4a4fe03cbeefdd258e68031f40011cf9d06b142b8421c09d2e396d551dbf1"
    family = "SalatStealer"
    file_name = "cfb4a4fe03cbeefd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:55"
  condition:
    hash.sha256(0, filesize) == "cfb4a4fe03cbeefdd258e68031f40011cf9d06b142b8421c09d2e396d551dbf1"
}
```

### Sample 34: `54700c5bdc9de74a`

| Field | Value |
|---|---|
| SHA-256 | `54700c5bdc9de74a1b58977d20fd11b5c76772bdcc29b2095504a91d613d5c8c` |
| Family label | `SalatStealer` |
| File name | `54700c5bdc9de74a.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55d1242c1c8fda7539576b7a95ee91f6` |
| SHA-1 | `4a9099460077f85a40a8585efd95e19b3271a8aa` |
| SHA-256 | `54700c5bdc9de74a1b58977d20fd11b5c76772bdcc29b2095504a91d613d5c8c` |
| SHA3-384 | `a7aa146584d5928050998056f910adabe02b981b11b4e11854f989b1289fefd4ac05a50c7d1d537b1e1553dbaed0255f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T190F5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OQ:iJiafuIO7rhWEES4h` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_034_54700c5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54700c5bdc9de74a1b58977d20fd11b5c76772bdcc29b2095504a91d613d5c8c"
    family = "SalatStealer"
    file_name = "54700c5bdc9de74a.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:44"
  condition:
    hash.sha256(0, filesize) == "54700c5bdc9de74a1b58977d20fd11b5c76772bdcc29b2095504a91d613d5c8c"
}
```

### Sample 35: `18cda38460611ce7`

| Field | Value |
|---|---|
| SHA-256 | `18cda38460611ce703da077c3f574f3e1b45e957f154f58ec02461fe2f5207f0` |
| Family label | `unknown` |
| File name | `ffc2ef52575dd974.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd9bfb421df09106f2699a2c49cd5392` |
| SHA-1 | `4b62e77f534c17299d5c45a53bac072273e5f37a` |
| SHA-256 | `18cda38460611ce703da077c3f574f3e1b45e957f154f58ec02461fe2f5207f0` |
| SHA3-384 | `8d81051f4f1080623aa0bc654934a287f3ade573c4707a3f9258462e181a86d66bbf1297f7130c1b384013cb67a23a87` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D3C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+y:yBkKr5rszpNDy+y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_18cda384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cda38460611ce703da077c3f574f3e1b45e957f154f58ec02461fe2f5207f0"
    family = "unknown"
    file_name = "ffc2ef52575dd974.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:38"
  condition:
    hash.sha256(0, filesize) == "18cda38460611ce703da077c3f574f3e1b45e957f154f58ec02461fe2f5207f0"
}
```

### Sample 36: `8409db3459e8383f`

| Field | Value |
|---|---|
| SHA-256 | `8409db3459e8383ff3222f7e462bb1e3ccad71afd68ba1d18c643bd1d24d1dab` |
| Family label | `unknown` |
| File name | `2d2ba75bfc9809d5.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70f66a15249c521bbecde8669f011347` |
| SHA-1 | `e4e8b4ce4d8f5c79c5fc8af77708c91bda0a20e7` |
| SHA-256 | `8409db3459e8383ff3222f7e462bb1e3ccad71afd68ba1d18c643bd1d24d1dab` |
| SHA3-384 | `9728ef4991e074bab59a3d0a974002299ab48df747318ed6d49c4491c91b25bd79e04860835cb8e9fcf4d79617c60db5` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_8409db34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8409db3459e8383ff3222f7e462bb1e3ccad71afd68ba1d18c643bd1d24d1dab"
    family = "unknown"
    file_name = "2d2ba75bfc9809d5.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:33"
  condition:
    hash.sha256(0, filesize) == "8409db3459e8383ff3222f7e462bb1e3ccad71afd68ba1d18c643bd1d24d1dab"
}
```

### Sample 37: `ae8d52715f0a30f8`

| Field | Value |
|---|---|
| SHA-256 | `ae8d52715f0a30f8aa9388a32edc8b1447425149fc94653d63502c8afda0fed1` |
| Family label | `SalatStealer` |
| File name | `ae8d52715f0a30f8.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df59884db8b7f6dd7b4886a67e220076` |
| SHA-1 | `de353f1c874ae458cb960c8d713ca0da34d9b8b2` |
| SHA-256 | `ae8d52715f0a30f8aa9388a32edc8b1447425149fc94653d63502c8afda0fed1` |
| SHA3-384 | `9a7035ab46f760744849cb0b55d2ff91cea9340730046efdd0638b4138e0b8f604d00e5a78c28f2ff23e28d8e10fb8c6` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10AF5335BF1AB47B3F7D9A931561FC66458B09FE40A20D38AD4DBAA9F0882FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ov:iJiafuIO7rhWEES4Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_037_ae8d5271
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae8d52715f0a30f8aa9388a32edc8b1447425149fc94653d63502c8afda0fed1"
    family = "SalatStealer"
    file_name = "ae8d52715f0a30f8.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:32"
  condition:
    hash.sha256(0, filesize) == "ae8d52715f0a30f8aa9388a32edc8b1447425149fc94653d63502c8afda0fed1"
}
```

### Sample 38: `db775faaa5ad2de8`

| Field | Value |
|---|---|
| SHA-256 | `db775faaa5ad2de8e4a45a89f677f642d7225936479abc641e20c27676013f26` |
| Family label | `unknown` |
| File name | `88d5738faf554477.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a838765908c1d8268cd9cb2c085f19a7` |
| SHA-1 | `e7e531786dee75916c757195292d558b9bd18ffc` |
| SHA-256 | `db775faaa5ad2de8e4a45a89f677f642d7225936479abc641e20c27676013f26` |
| SHA3-384 | `da014ce7c0b68e7babf0bba149850172b454ea9ee71385a6628cfd51ec7220b70e563bb0509e3572d1bab42593ae7293` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Y:yBkKr5rszpNDy+Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_db775faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db775faaa5ad2de8e4a45a89f677f642d7225936479abc641e20c27676013f26"
    family = "unknown"
    file_name = "88d5738faf554477.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:28"
  condition:
    hash.sha256(0, filesize) == "db775faaa5ad2de8e4a45a89f677f642d7225936479abc641e20c27676013f26"
}
```

### Sample 39: `234a106f46d0274b`

| Field | Value |
|---|---|
| SHA-256 | `234a106f46d0274b059373f5138f328b48d930ba2f3ff8aa388d8e77d3c6868b` |
| Family label | `unknown` |
| File name | `aa048a86045403f4.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af4fda573563ed16eb48f5150bb1f0a4` |
| SHA-1 | `a818fa71c8686989237eaa63990ef864e5936596` |
| SHA-256 | `234a106f46d0274b059373f5138f328b48d930ba2f3ff8aa388d8e77d3c6868b` |
| SHA3-384 | `9047fedea71da6a7711db0a7fc2a6f6797e1316683d7dffccb4a01cc1cdd55f5590c19ef0f67a72c5897abd8216ab3a2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T175C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_234a106f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "234a106f46d0274b059373f5138f328b48d930ba2f3ff8aa388d8e77d3c6868b"
    family = "unknown"
    file_name = "aa048a86045403f4.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:22"
  condition:
    hash.sha256(0, filesize) == "234a106f46d0274b059373f5138f328b48d930ba2f3ff8aa388d8e77d3c6868b"
}
```

### Sample 40: `466c512640001af3`

| Field | Value |
|---|---|
| SHA-256 | `466c512640001af3e8b8b04bb3866d35c90fc729859500d7e8b9deeeced2ffc3` |
| Family label | `SalatStealer` |
| File name | `466c512640001af3.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1acd371ed54ad3b6f711c1e3b946f1bd` |
| SHA-1 | `2449934b4cae71f292b6165d25f44db9dccdbecf` |
| SHA-256 | `466c512640001af3e8b8b04bb3866d35c90fc729859500d7e8b9deeeced2ffc3` |
| SHA3-384 | `3a3b7956ebbe5bb8cfc01dbd17bd0ef98af17e14bcb2e89426712936ca3fbd7d658600283218eefcb16f15cfa36a500b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T171F5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OV:iJiafuIO7rhWEES4W` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_040_466c5126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "466c512640001af3e8b8b04bb3866d35c90fc729859500d7e8b9deeeced2ffc3"
    family = "SalatStealer"
    file_name = "466c512640001af3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:21"
  condition:
    hash.sha256(0, filesize) == "466c512640001af3e8b8b04bb3866d35c90fc729859500d7e8b9deeeced2ffc3"
}
```

### Sample 41: `ffc2ef52575dd974`

| Field | Value |
|---|---|
| SHA-256 | `ffc2ef52575dd9749253404813fff150e4eb60650f34375af5af1f529f9e64d8` |
| Family label | `SalatStealer` |
| File name | `ffc2ef52575dd974.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:25:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9d70a635899ffbb26f72d2f08f88eaf` |
| SHA-1 | `be3eaf758c9f1c2037b3f44a5e1c9ffade1a9b1f` |
| SHA-256 | `ffc2ef52575dd9749253404813fff150e4eb60650f34375af5af1f529f9e64d8` |
| SHA3-384 | `0237a545f30fc1330f3cdf9b203abc2d56637d0000f8ea9df803696c0628493d57309f58961b0d83e143d3154aa46bb2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10CF5335BF1AB47B3F7D9A835561FC66458B09FE40A20D38AD4DBAA9F0882FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oe:iJiafuIO7rhWEES4d` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_041_ffc2ef52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffc2ef52575dd9749253404813fff150e4eb60650f34375af5af1f529f9e64d8"
    family = "SalatStealer"
    file_name = "ffc2ef52575dd974.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:09"
  condition:
    hash.sha256(0, filesize) == "ffc2ef52575dd9749253404813fff150e4eb60650f34375af5af1f529f9e64d8"
}
```

### Sample 42: `2d2ba75bfc9809d5`

| Field | Value |
|---|---|
| SHA-256 | `2d2ba75bfc9809d5eb8ddab04acb29f43261248bb845cd0d16c4358230a7495d` |
| Family label | `SalatStealer` |
| File name | `2d2ba75bfc9809d5.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:24:57` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `696eead2c5a501af3ca0a008f0da22fb` |
| SHA-1 | `606afae60eb2ece93d8d9f4026142777d59e1bbe` |
| SHA-256 | `2d2ba75bfc9809d5eb8ddab04acb29f43261248bb845cd0d16c4358230a7495d` |
| SHA3-384 | `de435b8d6c0937bd520451decb669d23c71fb480392cf04f1f2cb6407cf959622cc4ffe044155e02b1dc6c5af3561526` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A8F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OP:iJiafuIO7rhWEES4s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_042_2d2ba75b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d2ba75bfc9809d5eb8ddab04acb29f43261248bb845cd0d16c4358230a7495d"
    family = "SalatStealer"
    file_name = "2d2ba75bfc9809d5.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:24:57"
  condition:
    hash.sha256(0, filesize) == "2d2ba75bfc9809d5eb8ddab04acb29f43261248bb845cd0d16c4358230a7495d"
}
```

### Sample 43: `88d5738faf554477`

| Field | Value |
|---|---|
| SHA-256 | `88d5738faf554477ace7ccc3f3a43ab0ec975ecde469ce562a656b18655765ea` |
| Family label | `SalatStealer` |
| File name | `88d5738faf554477.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:24:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf0c0f3241a9583a5e6823eb9c2e3033` |
| SHA-1 | `fcfd4090eadf150313e72c4adba10a0c1ca166ab` |
| SHA-256 | `88d5738faf554477ace7ccc3f3a43ab0ec975ecde469ce562a656b18655765ea` |
| SHA3-384 | `c0d61ac8399a43f5d15e3cc87cef63c4eaa76deb89ac4b159654ccbf7843332c7b5501ad7563e0d0372174dc149e12c2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T123F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ok:iJiafuIO7rhWEES4F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_043_88d5738f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88d5738faf554477ace7ccc3f3a43ab0ec975ecde469ce562a656b18655765ea"
    family = "SalatStealer"
    file_name = "88d5738faf554477.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:24:46"
  condition:
    hash.sha256(0, filesize) == "88d5738faf554477ace7ccc3f3a43ab0ec975ecde469ce562a656b18655765ea"
}
```

### Sample 44: `aa048a86045403f4`

| Field | Value |
|---|---|
| SHA-256 | `aa048a86045403f4dc84c21d077b5c4a934b2756bc9e9242a46133c96a1e8b2c` |
| Family label | `SalatStealer` |
| File name | `aa048a86045403f4.bin` |
| File type | `exe` |
| First seen | `2026-11-11 05:24:33` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e50a0271cfa29204ed879d8d1938629c` |
| SHA-1 | `18db361e864813285a3fd577a809a92037f66388` |
| SHA-256 | `aa048a86045403f4dc84c21d077b5c4a934b2756bc9e9242a46133c96a1e8b2c` |
| SHA3-384 | `03aa26c44966d1ec6882a967c1b4ed71fb1d4033088517eb4ffe2e6eca02df03ee90050911591db4d356414d7d2ead3f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14DF5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oy:iJiafuIO7rhWEES4j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_044_aa048a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa048a86045403f4dc84c21d077b5c4a934b2756bc9e9242a46133c96a1e8b2c"
    family = "SalatStealer"
    file_name = "aa048a86045403f4.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:24:33"
  condition:
    hash.sha256(0, filesize) == "aa048a86045403f4dc84c21d077b5c4a934b2756bc9e9242a46133c96a1e8b2c"
}
```

### Sample 45: `3146cbeda2e32e10`

| Field | Value |
|---|---|
| SHA-256 | `3146cbeda2e32e100db10ef2be13b6b2d6922b41da94ccd59a57edc3030d0eb0` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-11 05:17:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42378acb1da40129555a2989524c1e94` |
| SHA-1 | `64a6b41ae9fd29b43dea2fec75c1ac28ea4974a2` |
| SHA-256 | `3146cbeda2e32e100db10ef2be13b6b2d6922b41da94ccd59a57edc3030d0eb0` |
| SHA3-384 | `ed15af261f94ee22f30e213133550dc1e5bcb158e71399ff13aed16510d41927ba739422b271df3f164244c9aa549408` |
| TLSH | `T1CC343A02E1D2A0BDC187C134879BD677BA3178B521307E3F67D4EE312D75EA0626DA62` |
| TELFHASH | `t1ee619b3018d570b832e3c7013702eaa9ee365c15a1ed76b8ab13edf0fea57c10c92825` |
| SSDEEP | `6144:10Gf5AEDQWfkpp8rL9fs/nQQSNNMLl7xuj:10GpsSkpaUn/hLRA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_3146cbed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3146cbeda2e32e100db10ef2be13b6b2d6922b41da94ccd59a57edc3030d0eb0"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-11 05:17:04"
  condition:
    hash.sha256(0, filesize) == "3146cbeda2e32e100db10ef2be13b6b2d6922b41da94ccd59a57edc3030d0eb0"
}
```

### Sample 46: `b4b10c8daf783a3c`

| Field | Value |
|---|---|
| SHA-256 | `b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf` |
| Family label | `unknown` |
| File name | `8b2d30759910deac.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:25:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1236b25a3201ce5b29d6bc839740e406` |
| SHA-1 | `85d9a2e388c550ee34df5571196e799ed4988977` |
| SHA-256 | `b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf` |
| SHA3-384 | `0bc3d91afabb512225c607530328b9436890a009090df57f432fda603073f595c81faababd0acd827d5ae04e3ecdaef1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C2C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_b4b10c8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf"
    family = "unknown"
    file_name = "8b2d30759910deac.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:43"
  condition:
    hash.sha256(0, filesize) == "b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf"
}
```

### Sample 47: `1369c4076348ef5b`

| Field | Value |
|---|---|
| SHA-256 | `1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619` |
| Family label | `unknown` |
| File name | `15ea4e787116522d.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:25:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f96d1461df667e7c606b725142988a91` |
| SHA-1 | `ac932a448abb1b8bb14b1084bc409481ad80fea6` |
| SHA-256 | `1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619` |
| SHA3-384 | `7f2bfe6add528ca8aa80f5787aa06a61067b3a1af3456bcf089532414e19cb892344379e1f6949fb87f2b92e593e5f1b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18EC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE++:yBkKr5rszpNDy++` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_1369c407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619"
    family = "unknown"
    file_name = "15ea4e787116522d.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:38"
  condition:
    hash.sha256(0, filesize) == "1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619"
}
```

### Sample 48: `6d4f6858e88c370e`

| Field | Value |
|---|---|
| SHA-256 | `6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327` |
| Family label | `unknown` |
| File name | `a79cf601233522c3.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:25:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8f2dbe58a7725ba3cc37359d7e1ff90` |
| SHA-1 | `9da7f01e48d8522ac72daabfc7ac7ac23814f2cf` |
| SHA-256 | `6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327` |
| SHA3-384 | `ff82e07e63a64a325fc8d2e24c443f57401830bb89d2caeacabb97a86a6d0c53279781dbe32767d88756e84d57c79a9a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T17EC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+7:yBkKr5rszpNDy+7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_6d4f6858
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327"
    family = "unknown"
    file_name = "a79cf601233522c3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:31"
  condition:
    hash.sha256(0, filesize) == "6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327"
}
```

### Sample 49: `195288be3f11d536`

| Field | Value |
|---|---|
| SHA-256 | `195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38` |
| Family label | `unknown` |
| File name | `7aebd9afa430a390.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:25:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38c4d95211d73643fe7deb137ca294e9` |
| SHA-1 | `c29843fc12862446f2fa5e8cee94aa9033d80960` |
| SHA-256 | `195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38` |
| SHA3-384 | `c4d4b582661756ee24835f6dbac054edca5060e42440d3e034da50ca3bf2b10ffea240523172ec431def10aa6f3b2357` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T185C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+T:yBkKr5rszpNDy+T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_195288be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38"
    family = "unknown"
    file_name = "7aebd9afa430a390.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:24"
  condition:
    hash.sha256(0, filesize) == "195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38"
}
```

### Sample 50: `8b2d30759910deac`

| Field | Value |
|---|---|
| SHA-256 | `8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d` |
| Family label | `SalatStealer` |
| File name | `8b2d30759910deac.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bcf5ec9c224504113f05ceb5327eb27` |
| SHA-1 | `091189a8cb854697a5914e988df05bcfed9af8c6` |
| SHA-256 | `8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d` |
| SHA3-384 | `9cf1018f1974571cb539b74fffe8b9c43eaf3921b1519c9508859e3e32d650e121b32ad80fd76c7729942c9b907478a1` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T107F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OX:iJiafuIO7rhWEES4Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_050_8b2d3075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d"
    family = "SalatStealer"
    file_name = "8b2d30759910deac.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:52"
  condition:
    hash.sha256(0, filesize) == "8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d"
}
```

### Sample 51: `15ea4e787116522d`

| Field | Value |
|---|---|
| SHA-256 | `15ea4e787116522de1ec7f4f4871ee19ebec82218edbbcca89f6859da17eb9a0` |
| Family label | `SalatStealer` |
| File name | `15ea4e787116522d.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:40` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2c78b89abeafe8c683dd2b35de17f14` |
| SHA-1 | `b67f5b0afbf097b4b0df20ee79cfb4065b4fa32a` |
| SHA-256 | `15ea4e787116522de1ec7f4f4871ee19ebec82218edbbcca89f6859da17eb9a0` |
| SHA3-384 | `66a2779468613c54a7c2d83d29229a5129b066556a0ca21fc514c755bb947a174ab1f08b6eff8471545eda9696b48a6b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12AF5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES47` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_051_15ea4e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ea4e787116522de1ec7f4f4871ee19ebec82218edbbcca89f6859da17eb9a0"
    family = "SalatStealer"
    file_name = "15ea4e787116522d.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:40"
  condition:
    hash.sha256(0, filesize) == "15ea4e787116522de1ec7f4f4871ee19ebec82218edbbcca89f6859da17eb9a0"
}
```

### Sample 52: `6f41cc418e91d77d`

| Field | Value |
|---|---|
| SHA-256 | `6f41cc418e91d77d284813a959bfead1ecec20d6fc60be6078e7ea9e27ced201` |
| Family label | `unknown` |
| File name | `ac643417c2da18ad.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67d99dc52386814005ca239e1610de8f` |
| SHA-1 | `a0ee7621fecf4f925ed1f07344eeb3e563c7efeb` |
| SHA-256 | `6f41cc418e91d77d284813a959bfead1ecec20d6fc60be6078e7ea9e27ced201` |
| SHA3-384 | `02c83b56dd78684fd502f28b82b41d8fa5a65d6a920de1c7c63013086d3053f22aab915466e0178a2aac95b29f0770c1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T16AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+u:yBkKr5rszpNDy+u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_6f41cc41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f41cc418e91d77d284813a959bfead1ecec20d6fc60be6078e7ea9e27ced201"
    family = "unknown"
    file_name = "ac643417c2da18ad.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:33"
  condition:
    hash.sha256(0, filesize) == "6f41cc418e91d77d284813a959bfead1ecec20d6fc60be6078e7ea9e27ced201"
}
```

### Sample 53: `a79cf601233522c3`

| Field | Value |
|---|---|
| SHA-256 | `a79cf601233522c3306f8e6bb2ed5c9f98a9c67f782d8959fc2d10bda3a8673a` |
| Family label | `SalatStealer` |
| File name | `a79cf601233522c3.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df24addbc0b58f594afa70761595115e` |
| SHA-1 | `0b96d8096516f98aba55f75222daa10f27963142` |
| SHA-256 | `a79cf601233522c3306f8e6bb2ed5c9f98a9c67f782d8959fc2d10bda3a8673a` |
| SHA3-384 | `146c05a179404dcac7b17054fac167aa4baa0381a8b85c301858b6f9bf06cd8046b0f73b643d9c8965d74e65a1afc1eb` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T17BF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4On:iJiafuIO7rhWEES48` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_053_a79cf601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79cf601233522c3306f8e6bb2ed5c9f98a9c67f782d8959fc2d10bda3a8673a"
    family = "SalatStealer"
    file_name = "a79cf601233522c3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:29"
  condition:
    hash.sha256(0, filesize) == "a79cf601233522c3306f8e6bb2ed5c9f98a9c67f782d8959fc2d10bda3a8673a"
}
```

### Sample 54: `710f4c6a9ea4262c`

| Field | Value |
|---|---|
| SHA-256 | `710f4c6a9ea4262ceb36301b859f92fcd667aca69d5066754355d4eac7ff4438` |
| Family label | `unknown` |
| File name | `6c5d52181f9d7337.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95811ce724bd31ee81af7c17abc91d41` |
| SHA-1 | `1caed9ed8387d6046f49378132bb77ab45fe9b91` |
| SHA-256 | `710f4c6a9ea4262ceb36301b859f92fcd667aca69d5066754355d4eac7ff4438` |
| SHA3-384 | `731acae6c36cbbbb35bf31cfea1ee1274a6c2539ed646627b074e66b73aa99f68464618529020e8e6112aa736aa54b35` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T184C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+2:yBkKr5rszpNDy+2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_710f4c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "710f4c6a9ea4262ceb36301b859f92fcd667aca69d5066754355d4eac7ff4438"
    family = "unknown"
    file_name = "6c5d52181f9d7337.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:28"
  condition:
    hash.sha256(0, filesize) == "710f4c6a9ea4262ceb36301b859f92fcd667aca69d5066754355d4eac7ff4438"
}
```

### Sample 55: `451ee61c8ad80366`

| Field | Value |
|---|---|
| SHA-256 | `451ee61c8ad803667d9f466f35c2c949287c2e2bfdfdf4a40fbc3937deb2686e` |
| Family label | `unknown` |
| File name | `a96d75a2b93ce72b.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c72816cede7095f1f05b5e6dc70fda4` |
| SHA-1 | `4b7114ae4fa1de55569256c8b52776830bc1a5d1` |
| SHA-256 | `451ee61c8ad803667d9f466f35c2c949287c2e2bfdfdf4a40fbc3937deb2686e` |
| SHA3-384 | `e8647a58a179a0015c980c805a1b96f021325c851a815ce77a5dd98408d2adc3b370e5bd5afe2547fc4da4c6231c52ef` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T191C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_451ee61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451ee61c8ad803667d9f466f35c2c949287c2e2bfdfdf4a40fbc3937deb2686e"
    family = "unknown"
    file_name = "a96d75a2b93ce72b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:23"
  condition:
    hash.sha256(0, filesize) == "451ee61c8ad803667d9f466f35c2c949287c2e2bfdfdf4a40fbc3937deb2686e"
}
```

### Sample 56: `4203307358acd7cf`

| Field | Value |
|---|---|
| SHA-256 | `4203307358acd7cff3c165372cd299aa3fc4052c5d14af62812be49b4ec88aa1` |
| Family label | `unknown` |
| File name | `935186620847b198.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c835cfa6068b4263b45507a32a24575` |
| SHA-1 | `8bb1e09423d0f01873487cb5d01c2c995ff05a69` |
| SHA-256 | `4203307358acd7cff3c165372cd299aa3fc4052c5d14af62812be49b4ec88aa1` |
| SHA3-384 | `9d8ada16519d573cbe4d71964c3d4260bba46955924d35bb166e0206fe9c2a85b58d104320e82dd441a0577aaf4898e8` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1FCC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+N:yBkKr5rszpNDy+N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_42033073
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4203307358acd7cff3c165372cd299aa3fc4052c5d14af62812be49b4ec88aa1"
    family = "unknown"
    file_name = "935186620847b198.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:18"
  condition:
    hash.sha256(0, filesize) == "4203307358acd7cff3c165372cd299aa3fc4052c5d14af62812be49b4ec88aa1"
}
```

### Sample 57: `7aebd9afa430a390`

| Field | Value |
|---|---|
| SHA-256 | `7aebd9afa430a39010e142909f7c1cbfa3c9935673f11d27ff2c333cc4e30615` |
| Family label | `SalatStealer` |
| File name | `7aebd9afa430a390.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f4dd2334c22118e42167fb23af3e16a` |
| SHA-1 | `d6459c5b8b6a74689889fea34ea35b6d1b14d4c6` |
| SHA-256 | `7aebd9afa430a39010e142909f7c1cbfa3c9935673f11d27ff2c333cc4e30615` |
| SHA3-384 | `6a3cf8751b951152eca9ef6fcd53f744ebe575aeaed23b77bdbd9fe577dc390439b8664213ebc5267c23ddc52833df60` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A6F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Of:iJiafuIO7rhWEES4q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_057_7aebd9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aebd9afa430a39010e142909f7c1cbfa3c9935673f11d27ff2c333cc4e30615"
    family = "SalatStealer"
    file_name = "7aebd9afa430a390.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:18"
  condition:
    hash.sha256(0, filesize) == "7aebd9afa430a39010e142909f7c1cbfa3c9935673f11d27ff2c333cc4e30615"
}
```

### Sample 58: `ac643417c2da18ad`

| Field | Value |
|---|---|
| SHA-256 | `ac643417c2da18ad88c9978174b9094a8ad50d3d4e801d95c65718164b4015e3` |
| Family label | `SalatStealer` |
| File name | `ac643417c2da18ad.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:24:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `687e7179b75c7d72dadd18c8794b214b` |
| SHA-1 | `a2506a94685374c8a5d63535378e99c20d69662e` |
| SHA-256 | `ac643417c2da18ad88c9978174b9094a8ad50d3d4e801d95c65718164b4015e3` |
| SHA3-384 | `30d595086f9ecf1d5e64e43e6e494400e5fc022db9688c130e7755476c9b428d1be72836392183d29f1dd930df8f7f81` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T179F5335BF5AB47B3F7D9A835560FC66458F09FE40A20D38AD4DBAA9F0882BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES4z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_ac643417
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac643417c2da18ad88c9978174b9094a8ad50d3d4e801d95c65718164b4015e3"
    family = "SalatStealer"
    file_name = "ac643417c2da18ad.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:06"
  condition:
    hash.sha256(0, filesize) == "ac643417c2da18ad88c9978174b9094a8ad50d3d4e801d95c65718164b4015e3"
}
```

### Sample 59: `6c5d52181f9d7337`

| Field | Value |
|---|---|
| SHA-256 | `6c5d52181f9d733746cac4bfd9f6bb967bf6e2e679b063a3f333e7e0ea2aadfa` |
| Family label | `SalatStealer` |
| File name | `6c5d52181f9d7337.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:23:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3853bf72e76d40531eb0c6100547b04` |
| SHA-1 | `8fe06bb6c784d942924574be151a10e2c7331aba` |
| SHA-256 | `6c5d52181f9d733746cac4bfd9f6bb967bf6e2e679b063a3f333e7e0ea2aadfa` |
| SHA3-384 | `6ecd4967e21df042da58d1b1a87a5d58595d05f0fc41e2f8431d90f7824e7a59d06d6d65303d339a375d41f7b02f89ab` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T15DF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OC:iJiafuIO7rhWEES4Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_059_6c5d5218
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c5d52181f9d733746cac4bfd9f6bb967bf6e2e679b063a3f333e7e0ea2aadfa"
    family = "SalatStealer"
    file_name = "6c5d52181f9d7337.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:23:54"
  condition:
    hash.sha256(0, filesize) == "6c5d52181f9d733746cac4bfd9f6bb967bf6e2e679b063a3f333e7e0ea2aadfa"
}
```

### Sample 60: `a96d75a2b93ce72b`

| Field | Value |
|---|---|
| SHA-256 | `a96d75a2b93ce72b555bf5e1ae5fce4bbb328bf8d2a2809686b8f1469cc95e5d` |
| Family label | `SalatStealer` |
| File name | `a96d75a2b93ce72b.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:23:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f27135f58c1b12a7ebfef7603cffa129` |
| SHA-1 | `30970bfe6caf58d273b1cad051367d8a41f717d8` |
| SHA-256 | `a96d75a2b93ce72b555bf5e1ae5fce4bbb328bf8d2a2809686b8f1469cc95e5d` |
| SHA3-384 | `ba08239de4819bfdeddc61c20e41291a5fe8614a0ce7fd2af99ab303dbb6b508e7dccee728c15b16331ea83f98cab28a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T117F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oj:iJiafuIO7rhWEES4S` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_060_a96d75a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a96d75a2b93ce72b555bf5e1ae5fce4bbb328bf8d2a2809686b8f1469cc95e5d"
    family = "SalatStealer"
    file_name = "a96d75a2b93ce72b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:23:43"
  condition:
    hash.sha256(0, filesize) == "a96d75a2b93ce72b555bf5e1ae5fce4bbb328bf8d2a2809686b8f1469cc95e5d"
}
```

### Sample 61: `935186620847b198`

| Field | Value |
|---|---|
| SHA-256 | `935186620847b198d627d8ab52a8305196e9db46a5a6a520de39f3ec0f353998` |
| Family label | `SalatStealer` |
| File name | `935186620847b198.bin` |
| File type | `exe` |
| First seen | `2026-11-11 04:23:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3439985d02510d10e7270c0014a748bc` |
| SHA-1 | `b42ef75ef9e901c439bc59e08851a0a612cb69cc` |
| SHA-256 | `935186620847b198d627d8ab52a8305196e9db46a5a6a520de39f3ec0f353998` |
| SHA3-384 | `bd4f619959bc571a25476c4b5e975fdf530e07ee1285ae1d3e35f1e099155d355ebbc5adead60da4dcc71ccc5ebfc97d` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12CF5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OB:iJiafuIO7rhWEES4g` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_061_93518662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935186620847b198d627d8ab52a8305196e9db46a5a6a520de39f3ec0f353998"
    family = "SalatStealer"
    file_name = "935186620847b198.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:23:32"
  condition:
    hash.sha256(0, filesize) == "935186620847b198d627d8ab52a8305196e9db46a5a6a520de39f3ec0f353998"
}
```

### Sample 62: `a629ffcf3eac76dd`

| Field | Value |
|---|---|
| SHA-256 | `a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-11 04:17:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e9a6aacb7497ac21a60f25e5fb55ed6` |
| SHA-1 | `b3f893d96b73a14de7665b66061e3e380c77dc21` |
| SHA-256 | `a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7` |
| SHA3-384 | `6c9d0628b774fea1e446475288d90199422c6650322922e137590064598ca3e32e1ed275db40a729f12e1aa53594a171` |
| TLSH | `T14F556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS5:SDjxB4m5n8XlaPWi+d+a4TjxQP4b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_a629ffcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 04:17:04"
  condition:
    hash.sha256(0, filesize) == "a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7"
}
```

### Sample 63: `bf861394a11a6b8c`

| Field | Value |
|---|---|
| SHA-256 | `bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01` |
| Family label | `unknown` |
| File name | `bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01` |
| File type | `exe` |
| First seen | `2026-11-11 04:15:21` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0eeeaa712a4d488c7e3ae1f0a27b7951` |
| SHA-1 | `8474246a145c9bca2d5e3b5c13df6631b278fd15` |
| SHA-256 | `bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01` |
| SHA3-384 | `f2f346ffc4ee33d7717548f586c46f95db90eb07c20d2fad77b7797414bd906fa7378cb8537591bcf7b33d124b55d447` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T126363358727CD1FCE106197844A3CE26A7737C5667BE5B0F8B4086771E03B5ABBA0B12` |
| SSDEEP | `98304:DI8qPoBhz1aRxcSUDk36SAEdhvxWa9P5:DI8qPe1Cxcxk3ZAEUad` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_bf861394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01"
    family = "unknown"
    file_name = "bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01"
    file_type = "exe"
    first_seen = "2026-11-11 04:15:21"
  condition:
    hash.sha256(0, filesize) == "bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01"
}
```

### Sample 64: `2814ef4cddbe575b`

| Field | Value |
|---|---|
| SHA-256 | `2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-11 04:10:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `126232ec2b596bb55007b281416f86c4` |
| SHA-1 | `f75b47d7dce594c136750fa8ae87951974039de7` |
| SHA-256 | `2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830` |
| SHA3-384 | `0a771e1ef9180cd7ecbc2958bc4d567e8f4c0f47b758f3b997d1a3ea59ae950d0bdf468364009819a9e0b6653bda8279` |
| TLSH | `T113556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS3:SDjxB4m5n8XlaPWi+d+a4TjxQP45` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_2814ef4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 04:10:04"
  condition:
    hash.sha256(0, filesize) == "2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830"
}
```

### Sample 65: `4351a7e899a2d3d2`

| Field | Value |
|---|---|
| SHA-256 | `4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0` |
| Family label | `Arechclient2` |
| File name | `newcrytest.msi` |
| File type | `msi` |
| First seen | `2026-11-11 03:42:59` |
| Reporter | `iamaachum` |
| Tags | `65-108-133-85, Arechclient2, AsgardProtector, dropped-by-ACRStealer, msi, SectopRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02c5e1133d85b375e4bf3469b7e8f1c4` |
| SHA-1 | `c3873a5e9a04ae7b511cb5c7bdef8f93f540f812` |
| SHA-256 | `4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0` |
| SHA3-384 | `daeb12362d0714bede14f17a9bcbf3239153600538f9793de84b4ce4694a005786e63b59fc1820a5390bdf1524d8ec8f` |
| TLSH | `T12A65332032E4612CCD2A95B649B39352B55EAD9C1C0F250336D0B39B3FB51E52B39BED` |
| SSDEEP | `24576:bW8xfK4D3Go8wy7w+PTG0XeJG5dl7vByt3pklCFammpeWDFX4QBwO2g:bfZbS8+PTG0p5dl7vByVpYCNmpeWe8P2` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_065_4351a7e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0"
    family = "Arechclient2"
    file_name = "newcrytest.msi"
    file_type = "msi"
    first_seen = "2026-11-11 03:42:59"
  condition:
    hash.sha256(0, filesize) == "4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0"
}
```

### Sample 66: `4c6fc10b19f08431`

| Field | Value |
|---|---|
| SHA-256 | `4c6fc10b19f08431922034c9989c198a68dca8606d05670052a68646e9cdb0ce` |
| Family label | `unknown` |
| File name | `cdrt.msi` |
| File type | `msi` |
| First seen | `2026-11-11 03:34:42` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dce5ae979578bf66d7db07de49c914dc` |
| SHA-1 | `b9a0422076c0a0b861c0dc0d4b31d4769de6bfe9` |
| SHA-256 | `4c6fc10b19f08431922034c9989c198a68dca8606d05670052a68646e9cdb0ce` |
| SHA3-384 | `cef34653577c1786b1086328e3af578afe1e8bcee0395dc3579f31e66fefb537a3992e688de32b0e5f8ae687848ac0b6` |
| TLSH | `T1088633B07AD71FD2D22507FA9CAE05C1C6286C5B1378B621613CFD9C2E7296C61BCE58` |
| SSDEEP | `196608:QXKCoJZrRrz6o6kxg+hmmCqHMTTdbAlKbV:QXgZZ6XkxFDsTTdEgb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_4c6fc10b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6fc10b19f08431922034c9989c198a68dca8606d05670052a68646e9cdb0ce"
    family = "unknown"
    file_name = "cdrt.msi"
    file_type = "msi"
    first_seen = "2026-11-11 03:34:42"
  condition:
    hash.sha256(0, filesize) == "4c6fc10b19f08431922034c9989c198a68dca8606d05670052a68646e9cdb0ce"
}
```

### Sample 67: `0f64b4d5288f88f1`

| Field | Value |
|---|---|
| SHA-256 | `0f64b4d5288f88f16165eebe27242281ba80095380491cc77406ee647be614d7` |
| Family label | `CoinMiner` |
| File name | `vlc_1.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:33:01` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d09ba2728283a9d5cb53f87d74306f8` |
| SHA-1 | `68eedf36845d690f764e550f5538aa86ef0fc262` |
| SHA-256 | `0f64b4d5288f88f16165eebe27242281ba80095380491cc77406ee647be614d7` |
| SHA3-384 | `157c4459f77716fa00ebfd372aefff4ce39f514485f78a1f1fcef22adb54cc4a6b31f12af15991d5e549eea11deef1f6` |
| IMPHASH | `d9dd991ada2874bf09e24636e1688f1f` |
| TLSH | `T1C7A6F117E8A509F6C8AEE6318936A522BB707C455F3113D71A90B7A43F36BE0AC75334` |
| SSDEEP | `98304:6WZh8C6/xzwB8KSyY04nJ2W+8JIfLAz4rK1yB+TQH1EEby3O1JbY:6On650BRgjJ+8tzpSFH1EEbXE` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_067_0f64b4d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f64b4d5288f88f16165eebe27242281ba80095380491cc77406ee647be614d7"
    family = "CoinMiner"
    file_name = "vlc_1.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:33:01"
  condition:
    hash.sha256(0, filesize) == "0f64b4d5288f88f16165eebe27242281ba80095380491cc77406ee647be614d7"
}
```

### Sample 68: `8a9f25a07e36759f`

| Field | Value |
|---|---|
| SHA-256 | `8a9f25a07e36759fe1f31be58223008cc9f0310e109595cce64fcc793f19c47d` |
| Family label | `unknown` |
| File name | `gv.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:32:04` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-RemusStealer, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b3d79db503b89afc9099928b828680e` |
| SHA-1 | `e27807cbcefcb6ed045beff8fb10db2dcc36bda1` |
| SHA-256 | `8a9f25a07e36759fe1f31be58223008cc9f0310e109595cce64fcc793f19c47d` |
| SHA3-384 | `950ef9c43a76ff1b34ccbbfc5eff0c765ff2a1d09e556a39fabcd89d2f0c1d7920587f6f804fd9272dcb57eb005793fe` |
| IMPHASH | `1977f3d6552183e6e2dec9ec943b22ee` |
| TLSH | `T1FE16332BE34341FED91EC1748D9BE7BA20F2B01562186F3B5BC1CA677E906181A19F1D` |
| SSDEEP | `98304:+km+SZDW2oTqQ+8LpCCJSAWN7MbLEpaHqLqEFcVBsN/dvy3hpuSi:+klwZoT5oESAW6b4vGBy/Ohpu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_8a9f25a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9f25a07e36759fe1f31be58223008cc9f0310e109595cce64fcc793f19c47d"
    family = "unknown"
    file_name = "gv.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:32:04"
  condition:
    hash.sha256(0, filesize) == "8a9f25a07e36759fe1f31be58223008cc9f0310e109595cce64fcc793f19c47d"
}
```

### Sample 69: `4998bd8a1bc0f492`

| Field | Value |
|---|---|
| SHA-256 | `4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41` |
| Family label | `RevStealer` |
| File name | `4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:30:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `386260107c7b5d8fa027cd5afcd75d22` |
| SHA-1 | `24ac83a3c7528c55c69de208511b7a39e7429aea` |
| SHA-256 | `4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41` |
| SHA3-384 | `12ab277d9097dda927cbf99d6f0ceac84389a71556638206df94e03c39f09dbb802e1ce1e1686265b1ad9628acf61bbd` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T15CD52389FCD6A970E437C3B79393706DB12D37448A750C07BACA6B106D625286D3B37A` |
| SSDEEP | `49152:+4hEcuGZ/xmkoFaF4NaU9ShhKNww0FjIDncLFb7lJ6Z1pRpifVtUwK8pV1OFex:T/uGZ/xmHYF4VmAOF2fzWK8pV1Hx` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_069_4998bd8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41"
    family = "RevStealer"
    file_name = "4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:30:49"
  condition:
    hash.sha256(0, filesize) == "4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41"
}
```

### Sample 70: `f0b58db8437fa399`

| Field | Value |
|---|---|
| SHA-256 | `f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5` |
| Family label | `RevStealer` |
| File name | `f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:30:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1028b1c04e2599eb94e97ba94831d40` |
| SHA-1 | `6dbeab7b8b20cbe6bfc54c9a2b18efca44064b11` |
| SHA-256 | `f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5` |
| SHA3-384 | `f039e478adc273c77d0b55570b0f98cef85ff9700ccb04258e9cf01c47d8f7f069b8734042ca3265d61ab544d0c395af` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T11AD5235AB9B924B4DC36C3B1AFD2F46D706E7B4187654E43BB8CBD004E12654AC3A339` |
| SSDEEP | `49152:UfDk0hxBDulCbEBXCxAg6syTIWHzidw1DOR54S7yG+rSyHtrhLVvWblY0n:UI0HBDKCaXCl5yzqw1DOD4eL+xHth2C0` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_070_f0b58db8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5"
    family = "RevStealer"
    file_name = "f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:30:43"
  condition:
    hash.sha256(0, filesize) == "f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5"
}
```

### Sample 71: `d2c18f8cc79df2e1`

| Field | Value |
|---|---|
| SHA-256 | `d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-11 03:27:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `748488d2d5b7e993cfec823301754901` |
| SHA-1 | `128937f1cef16a079e78ff6bfc025403ddb7c0a6` |
| SHA-256 | `d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a` |
| SHA3-384 | `26b49da6549ea1b50ab8280f128b378533776292769a27012bb5c72085d24d015cfafc40aceee542d1b9f9628b42cf9e` |
| TLSH | `T1FE645B03E6D2B0BDC187C170879FD532BA7074A961307E7E6BD49E312D79EA0622DB61` |
| TELFHASH | `t1bb81f07008a6367576d7c211b303fd36ed3208e086ed76f16d236894ade9bc15de3815` |
| SSDEEP | `6144:9oAvl0iooB2z31DitSduoI/ouN+R82pkFR/j4hft:9oHAB2z36SduoQ+RZk/sNt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_d2c18f8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-11 03:27:52"
  condition:
    hash.sha256(0, filesize) == "d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a"
}
```

### Sample 72: `f3f0f2491c066b7f`

| Field | Value |
|---|---|
| SHA-256 | `f3f0f2491c066b7f984e810df7f5a4e29b5c43af3202b757b66124b8c3b6b9b1` |
| Family label | `SalatStealer` |
| File name | `b6dfbacd86c47441.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:27:48` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e44a3f42a394a2b7e3a2a202c99a2f0` |
| SHA-1 | `a65af2719261cb6fd1f943c80cc9b81b2db903bb` |
| SHA-256 | `f3f0f2491c066b7f984e810df7f5a4e29b5c43af3202b757b66124b8c3b6b9b1` |
| SHA3-384 | `b722dc3c5a2255dbb78cc950cabf1e5dddb2ab66df583fb73a57ffa9e665d6f1d3d11534d6d6af85eb7d38136afaa4d2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T19DC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Y:yBkKr5rszpNDy+Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_072_f3f0f249
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3f0f2491c066b7f984e810df7f5a4e29b5c43af3202b757b66124b8c3b6b9b1"
    family = "SalatStealer"
    file_name = "b6dfbacd86c47441.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:48"
  condition:
    hash.sha256(0, filesize) == "f3f0f2491c066b7f984e810df7f5a4e29b5c43af3202b757b66124b8c3b6b9b1"
}
```

### Sample 73: `2088e8179a868592`

| Field | Value |
|---|---|
| SHA-256 | `2088e8179a868592a6ee8732a7fe2f544ef682cfa2dc856ff43844729ccd6711` |
| Family label | `SalatStealer` |
| File name | `ad7a120dd5f49a3e.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:27:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08e7b26303f4dec43b82ddd20a73e698` |
| SHA-1 | `a509954782ef79676912ceeab0579b3ef820c9de` |
| SHA-256 | `2088e8179a868592a6ee8732a7fe2f544ef682cfa2dc856ff43844729ccd6711` |
| SHA3-384 | `fa90ff78e447623b921a101056d206a55ce2741bbad64111bd0207bd221652e81f8ccdbb7ba2828f81162b09a629fa3f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T16CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_073_2088e817
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2088e8179a868592a6ee8732a7fe2f544ef682cfa2dc856ff43844729ccd6711"
    family = "SalatStealer"
    file_name = "ad7a120dd5f49a3e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:43"
  condition:
    hash.sha256(0, filesize) == "2088e8179a868592a6ee8732a7fe2f544ef682cfa2dc856ff43844729ccd6711"
}
```

### Sample 74: `9c6a76e7cf6ba827`

| Field | Value |
|---|---|
| SHA-256 | `9c6a76e7cf6ba827fb6ffd772fa410f40b0808e82e7733a6701df729f10ba75e` |
| Family label | `SalatStealer` |
| File name | `e2289f43e9b8b71b.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:27:37` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45ff9e814d444a948c390bf21f0bcdbf` |
| SHA-1 | `177d7ab15ebcd9ff9d22044cb1a7b9f1a83acd10` |
| SHA-256 | `9c6a76e7cf6ba827fb6ffd772fa410f40b0808e82e7733a6701df729f10ba75e` |
| SHA3-384 | `0174f78c13d29685db2141ab82fe93866720331510030abee303229ddab117abf6c3624b178619da4b3409b0a867a237` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E6C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_074_9c6a76e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c6a76e7cf6ba827fb6ffd772fa410f40b0808e82e7733a6701df729f10ba75e"
    family = "SalatStealer"
    file_name = "e2289f43e9b8b71b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:37"
  condition:
    hash.sha256(0, filesize) == "9c6a76e7cf6ba827fb6ffd772fa410f40b0808e82e7733a6701df729f10ba75e"
}
```

### Sample 75: `edd388b680bcf1d0`

| Field | Value |
|---|---|
| SHA-256 | `edd388b680bcf1d051bb65941578fd6cb142607629c37d8dc27a3ce6c28d9fd1` |
| Family label | `SalatStealer` |
| File name | `692d3b0dccef48dd.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:27:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8b8bf3700a50a19c5a6ffd75ca523fc` |
| SHA-1 | `3cdb164fa94391b1324fc1fb2051ec1cadf6a734` |
| SHA-256 | `edd388b680bcf1d051bb65941578fd6cb142607629c37d8dc27a3ce6c28d9fd1` |
| SHA3-384 | `0517f5db5bb79f1eeaf699d8984bc899af63b10dbff6d1cad9439cbb1a3106e62e4eb7a24b957deba95cf4fd6d795ecf` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B0C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+t:yBkKr5rszpNDy+t` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_075_edd388b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edd388b680bcf1d051bb65941578fd6cb142607629c37d8dc27a3ce6c28d9fd1"
    family = "SalatStealer"
    file_name = "692d3b0dccef48dd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:31"
  condition:
    hash.sha256(0, filesize) == "edd388b680bcf1d051bb65941578fd6cb142607629c37d8dc27a3ce6c28d9fd1"
}
```

### Sample 76: `640116d122dcbb34`

| Field | Value |
|---|---|
| SHA-256 | `640116d122dcbb34b77cfe0844822582b52674cf28acc53df7882078a49b7ad7` |
| Family label | `WARDENStealer` |
| File name | `𝐒𝐄𝐓𝐔𝐏.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:27:20` |
| Reporter | `iamaachum` |
| Tags | `exe, signed, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa26da571caeccd697f6783339f30d4f` |
| SHA-1 | `0d174d07a71dc2b81f24a40136927bb408051931` |
| SHA-256 | `640116d122dcbb34b77cfe0844822582b52674cf28acc53df7882078a49b7ad7` |
| SHA3-384 | `e09ebe4b7cb12355e499e0583a647a4d7d0a33c028a81a5a97ce1bc8990c048a167780326717b57f2adb695fd41328f3` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1F5D57D07BD9451EEC497E335986751A27A72BC988B3273D76F40BA782E353C02EB5B04` |
| SSDEEP | `24576:crLuJNmdRm97mAhyF+8+mbyrS6JUhLd/HJ7lMD/7GEIHEhBPNrvlw00i35kfGPrz:csYdRy79P74yrcq19Gqphe7k` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_076_640116d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "640116d122dcbb34b77cfe0844822582b52674cf28acc53df7882078a49b7ad7"
    family = "WARDENStealer"
    file_name = "𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:20"
  condition:
    hash.sha256(0, filesize) == "640116d122dcbb34b77cfe0844822582b52674cf28acc53df7882078a49b7ad7"
}
```

### Sample 77: `d4482565a2e7c4b1`

| Field | Value |
|---|---|
| SHA-256 | `d4482565a2e7c4b1bd23a5cb9240eabbc094e09ccf79b89a60ff1467fb175773` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-11 03:27:07` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `050b6ab9f070434f6afb13b5c2a6e1c5` |
| SHA-1 | `4c1fba22ad24d349488d443f836bc3dcc70bb40e` |
| SHA-256 | `d4482565a2e7c4b1bd23a5cb9240eabbc094e09ccf79b89a60ff1467fb175773` |
| SHA3-384 | `a7610386b57f573697c4b83cd2b357ac5552a06d101cffc9f5daf11cb0a9673be64819625c17d1c56d6001bdfc5773e0` |
| TLSH | `T18676199BB9914942C4E83A77B8BE80C833630EB99B9716175D05FE383EBE5D90E34714` |
| TELFHASH | `t1fbd09704adeef3ecb2c240886530425e2bc830fc1000b3547fbeb2cf0e8022060e90ba` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vZEAv5WEV2kDKWtoQXXRgRPV+aeq8MDPopdzXgxq0Dl5EU:xEAsEV2kDKWtoQHuqLvMDPo7zX+bEU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_d4482565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4482565a2e7c4b1bd23a5cb9240eabbc094e09ccf79b89a60ff1467fb175773"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 03:27:07"
  condition:
    hash.sha256(0, filesize) == "d4482565a2e7c4b1bd23a5cb9240eabbc094e09ccf79b89a60ff1467fb175773"
}
```

### Sample 78: `6d6fd016c78e8f5d`

| Field | Value |
|---|---|
| SHA-256 | `6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-11 03:27:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08a09ecb76551fb03eaf66717e085e2a` |
| SHA-1 | `4242b5df102af546f3f6e0b9d84b14b987685f66` |
| SHA-256 | `6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2` |
| SHA3-384 | `6d4440836c75fdbefd74ce15e49008bc536477dc80393fd82f25d831d56e1ee38ac3eae77ed89528905d78206c24f822` |
| TLSH | `T103D312B3625CB7B9D86F51322CBC13CDA517546E51B8521F22C16EEF8A20F71B28721B` |
| SSDEEP | `3072:Y9J2uU/L9VRn3AcdHbGFP7+JBdgmP9nvMMdKhqIaPrvidOXZfv:IJ2j9TLd7GFP7+rq2vMMdiijMOXZ3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_6d6fd016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-11 03:27:04"
  condition:
    hash.sha256(0, filesize) == "6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2"
}
```

### Sample 79: `b6dfbacd86c47441`

| Field | Value |
|---|---|
| SHA-256 | `b6dfbacd86c47441a3343e64e7073e8bad456ca42913b21b1d98b0035b7fa212` |
| Family label | `SalatStealer` |
| File name | `b6dfbacd86c47441.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `839350efa6f869fb551b947b3e84acda` |
| SHA-1 | `8d1ac4768add720596327634828405224dda7f6a` |
| SHA-256 | `b6dfbacd86c47441a3343e64e7073e8bad456ca42913b21b1d98b0035b7fa212` |
| SHA3-384 | `604227941880d5aaa53e8e3f0d4231138b855b675d184ffc2fd97be17ffc849493981d24433bf52955d6b116222a59a0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T115F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OE:iJiafuIO7rhWEES4l` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_079_b6dfbacd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6dfbacd86c47441a3343e64e7073e8bad456ca42913b21b1d98b0035b7fa212"
    family = "SalatStealer"
    file_name = "b6dfbacd86c47441.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:54"
  condition:
    hash.sha256(0, filesize) == "b6dfbacd86c47441a3343e64e7073e8bad456ca42913b21b1d98b0035b7fa212"
}
```

### Sample 80: `914e50252b3cda59`

| Field | Value |
|---|---|
| SHA-256 | `914e50252b3cda59f225f1821bbbab7683a59792a5a8d220a46f1fa0b6f4322c` |
| Family label | `SalatStealer` |
| File name | `3d9c13c99ebac596.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `403f1c72d5396afe6fef4a33d0852bf5` |
| SHA-1 | `a3c48eb91c88f79a644207edaa046ce08dff9e2d` |
| SHA-256 | `914e50252b3cda59f225f1821bbbab7683a59792a5a8d220a46f1fa0b6f4322c` |
| SHA3-384 | `e5d8a6f69e5b9fa6f52d4e3ecf6c6eb9d3b0833d6248810f256bd7fad98ad6662621d459f3aa13bd78d2b06268123a26` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T11AC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+H:yBkKr5rszpNDy+H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_080_914e5025
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "914e50252b3cda59f225f1821bbbab7683a59792a5a8d220a46f1fa0b6f4322c"
    family = "SalatStealer"
    file_name = "3d9c13c99ebac596.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:43"
  condition:
    hash.sha256(0, filesize) == "914e50252b3cda59f225f1821bbbab7683a59792a5a8d220a46f1fa0b6f4322c"
}
```

### Sample 81: `ad7a120dd5f49a3e`

| Field | Value |
|---|---|
| SHA-256 | `ad7a120dd5f49a3e246721b0457cd600a35b94e74528c7f4d99c42a0eec5673d` |
| Family label | `SalatStealer` |
| File name | `ad7a120dd5f49a3e.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `495e5b26ef0788ebcb1ef3352ffbf3ca` |
| SHA-1 | `0ff3c0364ee34db7508bc68b28c78193a06e5046` |
| SHA-256 | `ad7a120dd5f49a3e246721b0457cd600a35b94e74528c7f4d99c42a0eec5673d` |
| SHA3-384 | `e9e31a6889bc385886e3742bd2fc98796fb116671f3de1e1bdcfcaecb249b707d113b4c12f5e5acf3f3d73afd4284be1` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T107F5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oq:iJiafuIO7rhWEES4P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_081_ad7a120d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad7a120dd5f49a3e246721b0457cd600a35b94e74528c7f4d99c42a0eec5673d"
    family = "SalatStealer"
    file_name = "ad7a120dd5f49a3e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:43"
  condition:
    hash.sha256(0, filesize) == "ad7a120dd5f49a3e246721b0457cd600a35b94e74528c7f4d99c42a0eec5673d"
}
```

### Sample 82: `6a090f40b1f7bd47`

| Field | Value |
|---|---|
| SHA-256 | `6a090f40b1f7bd476e574fd8bf7a7532330bd31a8d279922f341377497ab501f` |
| Family label | `SalatStealer` |
| File name | `df2f4162958da6b9.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9d766e8c62cee604303734941a3638d` |
| SHA-1 | `5d59d8ad1cb4a4e4ffbf1f769f8ff1026073e6e6` |
| SHA-256 | `6a090f40b1f7bd476e574fd8bf7a7532330bd31a8d279922f341377497ab501f` |
| SHA3-384 | `22ef3645ab79884e9c41511d7fb70bef0f126489a8fbea0eb6d2fce61b458e16bc90d32d5d7c74095f75389785826601` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+j:yBkKr5rszpNDy+j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_082_6a090f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a090f40b1f7bd476e574fd8bf7a7532330bd31a8d279922f341377497ab501f"
    family = "SalatStealer"
    file_name = "df2f4162958da6b9.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:38"
  condition:
    hash.sha256(0, filesize) == "6a090f40b1f7bd476e574fd8bf7a7532330bd31a8d279922f341377497ab501f"
}
```

### Sample 83: `4d3547ffe2f6a160`

| Field | Value |
|---|---|
| SHA-256 | `4d3547ffe2f6a160289c6ff00f8596be158b070e6f5862fd3c7d6321d323d307` |
| Family label | `SalatStealer` |
| File name | `4bd9fd518fcfb4f1.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:32` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eb1f7d4f464860e343fbba0f4665fd9` |
| SHA-1 | `a17cfbb655a3fc6397ef7ddc0e45389449ec5bfc` |
| SHA-256 | `4d3547ffe2f6a160289c6ff00f8596be158b070e6f5862fd3c7d6321d323d307` |
| SHA3-384 | `d9521833ac00c4ae43a0a8468757e8497932aad5c72a20870867006a386cae692c860d001e5e94b8a712d642219cadc4` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T14FC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Z:yBkKr5rszpNDy+Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_083_4d3547ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d3547ffe2f6a160289c6ff00f8596be158b070e6f5862fd3c7d6321d323d307"
    family = "SalatStealer"
    file_name = "4bd9fd518fcfb4f1.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:32"
  condition:
    hash.sha256(0, filesize) == "4d3547ffe2f6a160289c6ff00f8596be158b070e6f5862fd3c7d6321d323d307"
}
```

### Sample 84: `e2289f43e9b8b71b`

| Field | Value |
|---|---|
| SHA-256 | `e2289f43e9b8b71b5319c2caacf825b3d2972e83df01f8d84a4e1be41bfc615f` |
| Family label | `SalatStealer` |
| File name | `e2289f43e9b8b71b.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5894e244280d07e8069ed08a64bdc48d` |
| SHA-1 | `20729e0d31e23ed3e66ce94c385ffa28aa05c9eb` |
| SHA-256 | `e2289f43e9b8b71b5319c2caacf825b3d2972e83df01f8d84a4e1be41bfc615f` |
| SHA3-384 | `a847e65df54f99efd736d0fc738f0bedbe9ceae588d099ac20269fcdc4324360958e4b381475ec9d4b3c5f3a84ab2f07` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T170F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OM:iJiafuIO7rhWEES4N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_084_e2289f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2289f43e9b8b71b5319c2caacf825b3d2972e83df01f8d84a4e1be41bfc615f"
    family = "SalatStealer"
    file_name = "e2289f43e9b8b71b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:32"
  condition:
    hash.sha256(0, filesize) == "e2289f43e9b8b71b5319c2caacf825b3d2972e83df01f8d84a4e1be41bfc615f"
}
```

### Sample 85: `fa89a22118841e1c`

| Field | Value |
|---|---|
| SHA-256 | `fa89a22118841e1c20f357fec81d4ae60f465a88419889b568f17ec77aad942d` |
| Family label | `SalatStealer` |
| File name | `b99976dcc8c6042c.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc3db539eeeb18e7f52f39570adb8ded` |
| SHA-1 | `911f0d8b2c1c5b3e802908149ba2d1c49780cade` |
| SHA-256 | `fa89a22118841e1c20f357fec81d4ae60f465a88419889b568f17ec77aad942d` |
| SHA3-384 | `85eaff455f46c8ee6d62160bef62baf962ec7a5de1e04abb037bf56d40eacd762da225359218f2a6c81d7ae0fd12d89a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T121C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+k:yBkKr5rszpNDy+k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_fa89a221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa89a22118841e1c20f357fec81d4ae60f465a88419889b568f17ec77aad942d"
    family = "SalatStealer"
    file_name = "b99976dcc8c6042c.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:25"
  condition:
    hash.sha256(0, filesize) == "fa89a22118841e1c20f357fec81d4ae60f465a88419889b568f17ec77aad942d"
}
```

### Sample 86: `692d3b0dccef48dd`

| Field | Value |
|---|---|
| SHA-256 | `692d3b0dccef48dd2000ba456a692a524ced18729db28b3eb7874bb6b1bdcf39` |
| Family label | `SalatStealer` |
| File name | `692d3b0dccef48dd.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:20` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `638cbe23b0ecdcc3f865d7254b544ab0` |
| SHA-1 | `deb94cb0c55add5f3eac823c92a404facdcc7549` |
| SHA-256 | `692d3b0dccef48dd2000ba456a692a524ced18729db28b3eb7874bb6b1bdcf39` |
| SHA3-384 | `69ff80fa09b41d635601bf2581de04c0a86ca7477fbb5b6f2361df9706da23f2bda48fc32987e73a1c5e1b7af421e100` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T127F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OZ:iJiafuIO7rhWEES4Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_692d3b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692d3b0dccef48dd2000ba456a692a524ced18729db28b3eb7874bb6b1bdcf39"
    family = "SalatStealer"
    file_name = "692d3b0dccef48dd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:20"
  condition:
    hash.sha256(0, filesize) == "692d3b0dccef48dd2000ba456a692a524ced18729db28b3eb7874bb6b1bdcf39"
}
```

### Sample 87: `3d9c13c99ebac596`

| Field | Value |
|---|---|
| SHA-256 | `3d9c13c99ebac5964a0ce4d41786d98660554851583d5b461ff5e56cab63a410` |
| Family label | `SalatStealer` |
| File name | `3d9c13c99ebac596.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:26:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d6dc1ab113af828e7553b202c0993a5` |
| SHA-1 | `054ed6b8d4927eabf4e6309fbe151a73cbe316f2` |
| SHA-256 | `3d9c13c99ebac5964a0ce4d41786d98660554851583d5b461ff5e56cab63a410` |
| SHA3-384 | `34fc951a5a579a9264a294e58de82b10690b0fd5b506e91aa340441248501d58ed0a40b528b437bf3a9ee4949575b799` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1ECF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OT:iJiafuIO7rhWEES4K` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_3d9c13c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d9c13c99ebac5964a0ce4d41786d98660554851583d5b461ff5e56cab63a410"
    family = "SalatStealer"
    file_name = "3d9c13c99ebac596.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:09"
  condition:
    hash.sha256(0, filesize) == "3d9c13c99ebac5964a0ce4d41786d98660554851583d5b461ff5e56cab63a410"
}
```

### Sample 88: `df2f4162958da6b9`

| Field | Value |
|---|---|
| SHA-256 | `df2f4162958da6b95b83667f9a81b9976eb1d0d333c674ae6afb9a056e32d327` |
| Family label | `SalatStealer` |
| File name | `df2f4162958da6b9.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:25:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b3a399fe4f41374519cc534d8b4dba3` |
| SHA-1 | `70d0b860c201b0135e1838c0f06d3060b8ca4040` |
| SHA-256 | `df2f4162958da6b95b83667f9a81b9976eb1d0d333c674ae6afb9a056e32d327` |
| SHA3-384 | `7f1dabf1335aec52f4073047781834d3efbf5a1e8c30254f46dae200cae871ed2e71cecda745230a049e8aa3328c1369` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T180F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ov:iJiafuIO7rhWEES4I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_088_df2f4162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df2f4162958da6b95b83667f9a81b9976eb1d0d333c674ae6afb9a056e32d327"
    family = "SalatStealer"
    file_name = "df2f4162958da6b9.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:25:58"
  condition:
    hash.sha256(0, filesize) == "df2f4162958da6b95b83667f9a81b9976eb1d0d333c674ae6afb9a056e32d327"
}
```

### Sample 89: `4bd9fd518fcfb4f1`

| Field | Value |
|---|---|
| SHA-256 | `4bd9fd518fcfb4f1fb1b2ac9df7e9dc751e80215368015d5ab58c98b981cee68` |
| Family label | `SalatStealer` |
| File name | `4bd9fd518fcfb4f1.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:25:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80848991c95279f1898aa917dab5aea1` |
| SHA-1 | `ba43f8cf0fa2fa9b60b0df9de0190ae7bfd53139` |
| SHA-256 | `4bd9fd518fcfb4f1fb1b2ac9df7e9dc751e80215368015d5ab58c98b981cee68` |
| SHA3-384 | `920b18fd8203c59e97a44f1adce72a9e1903a4d7593f15ed1a2f33f3afb97d7518979abfdf4e99961ed6937f6a9af20b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1ADF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ol:iJiafuIO7rhWEES4S` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_089_4bd9fd51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd9fd518fcfb4f1fb1b2ac9df7e9dc751e80215368015d5ab58c98b981cee68"
    family = "SalatStealer"
    file_name = "4bd9fd518fcfb4f1.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:25:48"
  condition:
    hash.sha256(0, filesize) == "4bd9fd518fcfb4f1fb1b2ac9df7e9dc751e80215368015d5ab58c98b981cee68"
}
```

### Sample 90: `59b1072d546995aa`

| Field | Value |
|---|---|
| SHA-256 | `59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42` |
| Family label | `Mirai` |
| File name | `59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42.elf` |
| File type | `elf` |
| First seen | `2026-11-11 03:25:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9359329a4704021e1f67d6f66461ef25` |
| SHA-1 | `daf768d74578ad040112be10a3311626ee504e41` |
| SHA-256 | `59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42` |
| SHA3-384 | `e50d4f58ed494bf7c8853d4fd2bc98724a3f2cfbe1c286eb6c38a5e49db836d723cb338fd7efe907e725a04f1ebc0cef` |
| TLSH | `T1F8937DC0D283D8F2FD1A0174603BF337A671DAB90278FDE3E7649A379861950614AB9D` |
| TELFHASH | `t15431f3f666660cd8abc09d03f70a5b71ed1cabbfa12466d301f228643222481577fd3d` |
| SSDEEP | `1536:c+XnuQqlH/rWiPy5H2BsIcVqhHhPlMeb0UXtCk8YUR7jQaDNg9DIC04Sr:cqBg/Rq5osIcEOebdDgW0C0N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_59b1072d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42"
    family = "Mirai"
    file_name = "59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42.elf"
    file_type = "elf"
    first_seen = "2026-11-11 03:25:47"
  condition:
    hash.sha256(0, filesize) == "59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42"
}
```

### Sample 91: `07f1eda56e4252cb`

| Field | Value |
|---|---|
| SHA-256 | `07f1eda56e4252cbbf72847c2855d218c82f2d199259a569b8ca468a270f5742` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-11 03:25:37` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, panel-birchdaleham-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ef7b6166bf21bc936b6171bc94a1839` |
| SHA-1 | `edca5f00d8245a7dee8e07f320767b464fcc3185` |
| SHA-256 | `07f1eda56e4252cbbf72847c2855d218c82f2d199259a569b8ca468a270f5742` |
| SHA3-384 | `1806bdcec69813876c39ad0729fd592efbf719e732226694fc520537a28153175b20e213c686ceb68c95ee4cc2e0e782` |
| TLSH | `T14A87336CBCBAB94EF4E5677BC1C52C7AEB1DE441D6E83C9B8E2480453C8314A1F6AC51` |
| SSDEEP | `786432:p1aT5BykWYs4vkZOiPfeLjRFEs4v1O/1j/FJWsbYJDs4vsVvd3JYHpNquRt:p1yBBnve4DEnvMReDnvsVvP2quRt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_07f1eda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f1eda56e4252cbbf72847c2855d218c82f2d199259a569b8ca468a270f5742"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-11 03:25:37"
  condition:
    hash.sha256(0, filesize) == "07f1eda56e4252cbbf72847c2855d218c82f2d199259a569b8ca468a270f5742"
}
```

### Sample 92: `b99976dcc8c6042c`

| Field | Value |
|---|---|
| SHA-256 | `b99976dcc8c6042cb38662e1fe3de6d866e0bd778714087fd67fadd0a1f68a1f` |
| Family label | `SalatStealer` |
| File name | `b99976dcc8c6042c.bin` |
| File type | `exe` |
| First seen | `2026-11-11 03:25:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `112aa1eb6ee269f257a69da602a8dc3a` |
| SHA-1 | `bf7ccb777d7f4e143fa6ed59dfce2cbce56d2c13` |
| SHA-256 | `b99976dcc8c6042cb38662e1fe3de6d866e0bd778714087fd67fadd0a1f68a1f` |
| SHA3-384 | `08ab5c9a3a9db34aadc87e3651b609cd3eee82af85ddd08a428dd6c827e60a8bb5265f9389ea644093b3714a143822a4` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10CF5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Og:iJiafuIO7rhWEES4p` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_092_b99976dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b99976dcc8c6042cb38662e1fe3de6d866e0bd778714087fd67fadd0a1f68a1f"
    family = "SalatStealer"
    file_name = "b99976dcc8c6042c.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:25:36"
  condition:
    hash.sha256(0, filesize) == "b99976dcc8c6042cb38662e1fe3de6d866e0bd778714087fd67fadd0a1f68a1f"
}
```

### Sample 93: `a589532b0b7e1a90`

| Field | Value |
|---|---|
| SHA-256 | `a589532b0b7e1a900955c8e5dc87d1d8ec48b3d1d05e6415bd74e5e48ea56c23` |
| Family label | `WARDENStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:22:42` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e71c7505bab5309f597912de89117d7` |
| SHA-1 | `98858037bf9ebbd2721bdfb7bd7b15092ce4d57a` |
| SHA-256 | `a589532b0b7e1a900955c8e5dc87d1d8ec48b3d1d05e6415bd74e5e48ea56c23` |
| SHA3-384 | `44d990e382d2433e6c3b5fe41328fa2858fc4ad956c8468ba0691d8136f2dd3023797d441632146f92eff05e6f8474a2` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T11D267D176A9446BEC0EAD635C5BA16357A74BC48E33233DB1F527AB81F36BC06A34704` |
| SSDEEP | `49152:MWzY0ZIm2cWz4IKBQkMnG4ItVGrSQKghxHLgnWff4LUzBP3tGfUUMyXUFtr:l98FkMHsn6cibUe` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_093_a589532b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a589532b0b7e1a900955c8e5dc87d1d8ec48b3d1d05e6415bd74e5e48ea56c23"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:22:42"
  condition:
    hash.sha256(0, filesize) == "a589532b0b7e1a900955c8e5dc87d1d8ec48b3d1d05e6415bd74e5e48ea56c23"
}
```

### Sample 94: `8edc371dba96886c`

| Field | Value |
|---|---|
| SHA-256 | `8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb` |
| Family label | `unknown` |
| File name | `Launcher15894x64.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:21:15` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29d056cc1f780fe8157e998c47bbd38a` |
| SHA-1 | `28c525f4e4eed03bfc4de245c9e2d25c7296a4d2` |
| SHA-256 | `8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb` |
| SHA3-384 | `163c29723dadf5c1632063c3e7af8fb5a5156e741283e55263c30044195a5c155789906396210cd319856f485185e9df` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T128F633935AB3C4C1D8A9413854EA89B99217F63C72E0B3F51B14D1B2DE1C939CE73B62` |
| SSDEEP | `393216:P/Mi53KiLs3UotK8g34HIGRTajrI0BW8GzYt:si5dDokQ+sza` |
| ICON-DHASH | `71e84ce0c4c4c4c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_8edc371d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb"
    family = "unknown"
    file_name = "Launcher15894x64.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:21:15"
  condition:
    hash.sha256(0, filesize) == "8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb"
}
```

### Sample 95: `7db79169e437472f`

| Field | Value |
|---|---|
| SHA-256 | `7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-11-11 03:20:48` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc357b3937906fb48e8819d29415ad3a` |
| SHA-1 | `4ba4bfbf0dc2bc3f8eec968992c788fc1067473e` |
| SHA-256 | `7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1` |
| SHA3-384 | `7c24fd678c61097bfe3ece24569ffa8af92fd567a1ee79772a4f3f1c4e9a35aba2d5730b6a9821be4acba60e06687119` |
| TLSH | `T169F633935AB3C4C1D8A9413854EA89B99217F63C72E0B3F52B18D1B2DF5C835CE72B61` |
| SSDEEP | `393216:X/Mi53KiLs3UotK8g34HIGRTajrI0BW8GzYt:ki5dDokQ+sza` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_7db79169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-11 03:20:48"
  condition:
    hash.sha256(0, filesize) == "7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1"
}
```

### Sample 96: `31e044d3fbf6d6cc`

| Field | Value |
|---|---|
| SHA-256 | `31e044d3fbf6d6cc21f9fdff9560e058b07a8b3f47b35fa073289a75ee12646f` |
| Family label | `unknown` |
| File name | `Installer_L_X64_x86_2024.zip` |
| File type | `zip` |
| First seen | `2026-11-11 03:18:38` |
| Reporter | `iamaachum` |
| Tags | `HijackLoader, IDATLoader, new-label-club, SnappyClient, WARDENStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc2d9db604bb25ee58b15f42f2cfbd14` |
| SHA-1 | `37b8eebbedcd09dc09666d07d6cd1034ad1fb5f3` |
| SHA-256 | `31e044d3fbf6d6cc21f9fdff9560e058b07a8b3f47b35fa073289a75ee12646f` |
| SHA3-384 | `f428c602b1a6b98f08a7405a566ef7af7d3e0d8e98c23145b5d3f4b840848e9a19673b22224544a31aef274fa1a442a5` |
| TLSH | `T1AEE73360DF4E196AD25FBEF2D589172EE2A6D1589730E11F06F894413C933EA4F1B283` |
| SSDEEP | `1572864:a22L7I2+KDmtdj1WrF0s7JDIsZgz3Mk1Bu:aDatdBPs7JDBgbMSBu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_31e044d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31e044d3fbf6d6cc21f9fdff9560e058b07a8b3f47b35fa073289a75ee12646f"
    family = "unknown"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-11 03:18:38"
  condition:
    hash.sha256(0, filesize) == "31e044d3fbf6d6cc21f9fdff9560e058b07a8b3f47b35fa073289a75ee12646f"
}
```

### Sample 97: `eeb57f00c3d38886`

| Field | Value |
|---|---|
| SHA-256 | `eeb57f00c3d388864fad8d347e86ae143f47e41f6503853fdecac9ae4982bcfd` |
| Family label | `WARDENStealer` |
| File name | `x86__setup_now.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:16:53` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, SpaxMedia, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed5c85bb2a9414cec620f809b125eb68` |
| SHA-1 | `f113d584a8a5b26255c1459afcdb5ce174f01907` |
| SHA-256 | `eeb57f00c3d388864fad8d347e86ae143f47e41f6503853fdecac9ae4982bcfd` |
| SHA3-384 | `574b0d27b9c648be3eb9a1e65f2ec68afafd1a4d0eee9184da1783ca1d0f4d1b13f61646a312103a1a21edbf75a5bf31` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1B71712176AD44AAEC0E6D635C5BA16357A74BC48E33633DB1F526AB81F32BC0B934704` |
| SSDEEP | `393216:yMHw+XAr23Ih9OGf8ZWmsRZre0nA5Q8JAbYgcd2suwMQRt39II1XQJZw:tXcB9OGf8ZWmsRZre0AZFgEeO1X2a` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_097_eeb57f00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb57f00c3d388864fad8d347e86ae143f47e41f6503853fdecac9ae4982bcfd"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:16:53"
  condition:
    hash.sha256(0, filesize) == "eeb57f00c3d388864fad8d347e86ae143f47e41f6503853fdecac9ae4982bcfd"
}
```

### Sample 98: `92ebc788fce25f18`

| Field | Value |
|---|---|
| SHA-256 | `92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-11-11 03:16:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7930bd8ac31dfd0353b3393ceff9a1d8` |
| SHA-1 | `900195926284202208c26bbb43c274612e7f87ee` |
| SHA-256 | `92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6` |
| SHA3-384 | `0766e05ddbc094ea73d39702224fb7b74872ab900f74183f410ebe7def69fbcd687dbecd2427bfbca638c810c4230fef` |
| TLSH | `T1A4547C81B74C3EEEE2D32D7EC14B55066C1C8F10E8435D1160A9B98F1ABB7971F7A84A` |
| SSDEEP | `6144:KxCOoqxuYZ+qcX7HPaqQmpaBAic/rXkptMxqvsJ3/EH:b85uXbPm3GiE0rsaH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_92ebc788
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-11 03:16:04"
  condition:
    hash.sha256(0, filesize) == "92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6"
}
```

### Sample 99: `6444a4e18c9ca99b`

| Field | Value |
|---|---|
| SHA-256 | `6444a4e18c9ca99b5516e5365baac88bf4d62182e3630451b202c9bfb4ccbc0b` |
| Family label | `WARDENStealer` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-11-11 03:15:38` |
| Reporter | `iamaachum` |
| Tags | `exe, WARDENStealer, wooocommerce-shopping` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df00b5e813702c48c5d785360cf4bca2` |
| SHA-1 | `68cf2a6295d78a9c992eafda67927406159a3d24` |
| SHA-256 | `6444a4e18c9ca99b5516e5365baac88bf4d62182e3630451b202c9bfb4ccbc0b` |
| SHA3-384 | `17e48e38328e876a572f6adba8daa649831b7a5c05b5e05908e649076f4883c3f4606ad88064a0c59fd122f287b590cf` |
| IMPHASH | `8607f652e53c71e377c349125ec239f5` |
| TLSH | `T1DD05E1A5F3221BE9C97D81B58A6A9D8599653D121F3058FF1784234B0F323E0EF3A635` |
| SSDEEP | `24576:r3WTRGsm2APrhijSuVFFLUSKEz7pjoXQbHrhLJmpRcd/I:r3ARS2zzZS2wR` |
| ICON-DHASH | `2997696d6d699648` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_099_6444a4e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6444a4e18c9ca99b5516e5365baac88bf4d62182e3630451b202c9bfb4ccbc0b"
    family = "WARDENStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:15:38"
  condition:
    hash.sha256(0, filesize) == "6444a4e18c9ca99b5516e5365baac88bf4d62182e3630451b202c9bfb4ccbc0b"
}
```

### Sample 100: `8f17149c4abc1508`

| Field | Value |
|---|---|
| SHA-256 | `8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4` |
| Family label | `Mirai` |
| File name | `galaxy.arm7` |
| File type | `elf` |
| First seen | `2026-11-11 03:14:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dde0d74d9d9b56cbe3dc2a9a93f5b9e6` |
| SHA-1 | `253bcf14e2e0180dcefbe000b309b08985b07838` |
| SHA-256 | `8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4` |
| SHA3-384 | `aed5ebecde8b832b0b069c9752131065a80a8cef8150b7f61ad6e8ef482714fef474b079a2f57c8c48a9b08c512f573b` |
| TLSH | `T184142A46EA414B13C0D727BAFA9F4245333397A4D3E773069928ABB43B8779E4F22505` |
| TELFHASH | `t13831ed658b75062a59a1dd68c8eda7a2552d8b136344fe33df31c4cc240e48ee63bc4f` |
| SSDEEP | `6144:Cm4jyjDV1QIXasbkY4c3rVsP/GaUIM/R1upxA:Cm4jerQIXasbkY4cOmaUd/OG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_8f17149c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4"
    family = "Mirai"
    file_name = "galaxy.arm7"
    file_type = "elf"
    first_seen = "2026-11-11 03:14:05"
  condition:
    hash.sha256(0, filesize) == "8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4"
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
 * Generated: 2026-11-11T06:43:02.125365+00:00
 */

rule MalwareBazaar_unknown_001_e40b120a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425"
    family = "unknown"
    file_name = "e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425"
    file_type = "exe"
    first_seen = "2026-11-11 06:41:28"
  condition:
    hash.sha256(0, filesize) == "e40b120a7862fd88a9922ef6e7606a633dd34bb79c7784fc46df78ebd3621425"
}

rule MalwareBazaar_Gafgyt_002_a8d439d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8d439d55a0dc0f17afcde668d72539b7de88e03479b4a916e9073c4634d5dc3"
    family = "Gafgyt"
    file_name = "a-r.m-7.Sakura"
    file_type = "elf"
    first_seen = "2026-11-11 06:39:04"
  condition:
    hash.sha256(0, filesize) == "a8d439d55a0dc0f17afcde668d72539b7de88e03479b4a916e9073c4634d5dc3"
}

rule MalwareBazaar_Mirai_003_21bb5cc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21bb5cc4f1d06276094476140eef9031cc341138920876d4f3c8fdeca82fe845"
    family = "Mirai"
    file_name = "sample"
    file_type = "sh"
    first_seen = "2026-11-11 06:35:12"
  condition:
    hash.sha256(0, filesize) == "21bb5cc4f1d06276094476140eef9031cc341138920876d4f3c8fdeca82fe845"
}

rule MalwareBazaar_Mirai_004_b2144edc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2144edce534cb5e4072f66a27e029a357f2c629bb3437c1007051b77652f774"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 06:28:04"
  condition:
    hash.sha256(0, filesize) == "b2144edce534cb5e4072f66a27e029a357f2c629bb3437c1007051b77652f774"
}

rule MalwareBazaar_unknown_005_e3c5de25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3c5de25e23d08bcba083fa7f12306dcc9abe741df27f3be0ddeff90b6c5ab8d"
    family = "unknown"
    file_name = "0bee7c8bd9aea730.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:35"
  condition:
    hash.sha256(0, filesize) == "e3c5de25e23d08bcba083fa7f12306dcc9abe741df27f3be0ddeff90b6c5ab8d"
}

rule MalwareBazaar_unknown_006_1ae78d73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae78d73d9c742e8f4c0684f4f22b8242ec2bb258e4eb4b2fc2bb982d4e2455e"
    family = "unknown"
    file_name = "c3614cc181dea26e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:30"
  condition:
    hash.sha256(0, filesize) == "1ae78d73d9c742e8f4c0684f4f22b8242ec2bb258e4eb4b2fc2bb982d4e2455e"
}

rule MalwareBazaar_unknown_007_afdc6e80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afdc6e80049ec18bc03269dfeb6137650bfd9caaf8f33d037bf1a855aae6616a"
    family = "unknown"
    file_name = "1b7b026db4b15278.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:25"
  condition:
    hash.sha256(0, filesize) == "afdc6e80049ec18bc03269dfeb6137650bfd9caaf8f33d037bf1a855aae6616a"
}

rule MalwareBazaar_unknown_008_d09be124
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d09be12468f12155fdd0465d6912034c5e346119ff512373f1a904462cf9db19"
    family = "unknown"
    file_name = "f3c02baf53bd71ff.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:26:19"
  condition:
    hash.sha256(0, filesize) == "d09be12468f12155fdd0465d6912034c5e346119ff512373f1a904462cf9db19"
}

rule MalwareBazaar_SalatStealer_009_0bee7c8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bee7c8bd9aea73097216c2793deb9da11e051d7b12e88ccbc38d17a78fddc63"
    family = "SalatStealer"
    file_name = "0bee7c8bd9aea730.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:59"
  condition:
    hash.sha256(0, filesize) == "0bee7c8bd9aea73097216c2793deb9da11e051d7b12e88ccbc38d17a78fddc63"
}

rule MalwareBazaar_SalatStealer_010_c3614cc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3614cc181dea26e8ac128cf768619b0b3dbb4aacf07de5efefe8967ce47d783"
    family = "SalatStealer"
    file_name = "c3614cc181dea26e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:48"
  condition:
    hash.sha256(0, filesize) == "c3614cc181dea26e8ac128cf768619b0b3dbb4aacf07de5efefe8967ce47d783"
}

rule MalwareBazaar_SalatStealer_011_1b7b026d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b7b026db4b15278bda9dce0d41a6440ed5946b787db0dad7da9570289105158"
    family = "SalatStealer"
    file_name = "1b7b026db4b15278.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:35"
  condition:
    hash.sha256(0, filesize) == "1b7b026db4b15278bda9dce0d41a6440ed5946b787db0dad7da9570289105158"
}

rule MalwareBazaar_unknown_012_1dcef4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dcef4b2676a892cc4c66d6e40a28ac2bad7ce0e06b2ef6905496630150103ec"
    family = "unknown"
    file_name = "4d54b0f52cc8550f.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:33"
  condition:
    hash.sha256(0, filesize) == "1dcef4b2676a892cc4c66d6e40a28ac2bad7ce0e06b2ef6905496630150103ec"
}

rule MalwareBazaar_unknown_013_6e54cacb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e54cacb597a06688afe4975cb6a77bf3d9cf6f1a5d670a0c772a150eee7df81"
    family = "unknown"
    file_name = "245438aab30ca463.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:28"
  condition:
    hash.sha256(0, filesize) == "6e54cacb597a06688afe4975cb6a77bf3d9cf6f1a5d670a0c772a150eee7df81"
}

rule MalwareBazaar_SalatStealer_014_f3c02baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c02baf53bd71ff4cfcce2c66accb60213e57673d916a7e22d9daf5c0b8c3c2"
    family = "SalatStealer"
    file_name = "f3c02baf53bd71ff.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:23"
  condition:
    hash.sha256(0, filesize) == "f3c02baf53bd71ff4cfcce2c66accb60213e57673d916a7e22d9daf5c0b8c3c2"
}

rule MalwareBazaar_unknown_015_6a98973a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a98973a22487802bf73ef44cc5dbd1ccf6b0e877824b0770d08e57172f544c1"
    family = "unknown"
    file_name = "25d90d9bf76df911.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:22"
  condition:
    hash.sha256(0, filesize) == "6a98973a22487802bf73ef44cc5dbd1ccf6b0e877824b0770d08e57172f544c1"
}

rule MalwareBazaar_SalatStealer_016_4d54b0f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d54b0f52cc8550f3ac5018ea16b7b174a8e7503497cf07d6594a09f17b90232"
    family = "SalatStealer"
    file_name = "4d54b0f52cc8550f.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:25:11"
  condition:
    hash.sha256(0, filesize) == "4d54b0f52cc8550f3ac5018ea16b7b174a8e7503497cf07d6594a09f17b90232"
}

rule MalwareBazaar_SalatStealer_017_245438aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "245438aab30ca463a34d9b14122072f26bf9b6a7a84c5b406023328f8076639c"
    family = "SalatStealer"
    file_name = "245438aab30ca463.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:24:52"
  condition:
    hash.sha256(0, filesize) == "245438aab30ca463a34d9b14122072f26bf9b6a7a84c5b406023328f8076639c"
}

rule MalwareBazaar_SalatStealer_018_25d90d9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25d90d9bf76df91180601fd1c49c81aaf2ffbfc0383591c70db5c47b2d11e92b"
    family = "SalatStealer"
    file_name = "25d90d9bf76df911.bin"
    file_type = "exe"
    first_seen = "2026-11-11 06:24:40"
  condition:
    hash.sha256(0, filesize) == "25d90d9bf76df91180601fd1c49c81aaf2ffbfc0383591c70db5c47b2d11e92b"
}

rule MalwareBazaar_unknown_019_eae2ce72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eae2ce72c550077dbb13efb57ef2e528e98ca1bdff10fc64be52ded8dc1a9a28"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 06:23:05"
  condition:
    hash.sha256(0, filesize) == "eae2ce72c550077dbb13efb57ef2e528e98ca1bdff10fc64be52ded8dc1a9a28"
}

rule MalwareBazaar_Mirai_020_e80b34bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e80b34bb4e2de5360a9e80a90fed0ea694e47deb223980e39982f9c7ccb7c531"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-11-11 05:45:04"
  condition:
    hash.sha256(0, filesize) == "e80b34bb4e2de5360a9e80a90fed0ea694e47deb223980e39982f9c7ccb7c531"
}

rule MalwareBazaar_unknown_021_4ea4f8c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ea4f8c30a3969d9439593e0b9f16275b14955fd353330c542278ff42c952fd5"
    family = "unknown"
    file_name = "Noticefrom-TaxDepartmen.img"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:40"
  condition:
    hash.sha256(0, filesize) == "4ea4f8c30a3969d9439593e0b9f16275b14955fd353330c542278ff42c952fd5"
}

rule MalwareBazaar_unknown_022_f64aab68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64aab684e202296b22f16e0d5b494b822c84c7614b1b5a27ad71ac8504d0ee6"
    family = "unknown"
    file_name = "_00042"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:37"
  condition:
    hash.sha256(0, filesize) == "f64aab684e202296b22f16e0d5b494b822c84c7614b1b5a27ad71ac8504d0ee6"
}

rule MalwareBazaar_unknown_023_604484b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "604484b0df68d2c2f5aa4b75281fa8ef99250d3afd03736a64b3b3fe2136c593"
    family = "unknown"
    file_name = "pd147996773.att"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:34"
  condition:
    hash.sha256(0, filesize) == "604484b0df68d2c2f5aa4b75281fa8ef99250d3afd03736a64b3b3fe2136c593"
}

rule MalwareBazaar_unknown_024_c07af04e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07af04e7e02d2715b9330a4a78b6be7c0c44b7ddec7738a5790b8a7eb374107"
    family = "unknown"
    file_name = "_00021"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:31"
  condition:
    hash.sha256(0, filesize) == "c07af04e7e02d2715b9330a4a78b6be7c0c44b7ddec7738a5790b8a7eb374107"
}

rule MalwareBazaar_unknown_025_d9eca2ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9eca2aef9277205b3afbbd4d4ec6097cc4fc0b8fc6d11dca3659a9340ac7e99"
    family = "unknown"
    file_name = "0x7883934FBEA2DA57"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:28"
  condition:
    hash.sha256(0, filesize) == "d9eca2aef9277205b3afbbd4d4ec6097cc4fc0b8fc6d11dca3659a9340ac7e99"
}

rule MalwareBazaar_unknown_026_cab9e7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab9e7e4e7eb122de12f7bfdca618c1056a409e7505f6f051835bdfef9bc38a9"
    family = "unknown"
    file_name = "52820a94fb444c72a5ff925687bec95e.MSG"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:25"
  condition:
    hash.sha256(0, filesize) == "cab9e7e4e7eb122de12f7bfdca618c1056a409e7505f6f051835bdfef9bc38a9"
}

rule MalwareBazaar_unknown_027_548bb8dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "548bb8dd7cb6a7d6f42237e41f98fc70afedea03c65aadc4d3827fa5e57bb448"
    family = "unknown"
    file_name = "md5001000192969.tmp"
    file_type = "exe"
    first_seen = "2026-11-11 05:31:22"
  condition:
    hash.sha256(0, filesize) == "548bb8dd7cb6a7d6f42237e41f98fc70afedea03c65aadc4d3827fa5e57bb448"
}

rule MalwareBazaar_Mirai_028_db5a117b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db5a117ba85458fc772624493ad490ac59eba298708ba11720aa46d217ff27f1"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-11 05:27:04"
  condition:
    hash.sha256(0, filesize) == "db5a117ba85458fc772624493ad490ac59eba298708ba11720aa46d217ff27f1"
}

rule MalwareBazaar_unknown_029_62fee3c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62fee3c164b6aca4b1bdf2d0c162666adcb9fbc5c6eda7f0917bac2166ac9e12"
    family = "unknown"
    file_name = "cfb4a4fe03cbeefd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:39"
  condition:
    hash.sha256(0, filesize) == "62fee3c164b6aca4b1bdf2d0c162666adcb9fbc5c6eda7f0917bac2166ac9e12"
}

rule MalwareBazaar_unknown_030_e4c5fcfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4c5fcfe2902dffc20eec1999e2cfa8fba7d4809682ea38a3266af6401f69ca0"
    family = "unknown"
    file_name = "54700c5bdc9de74a.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:34"
  condition:
    hash.sha256(0, filesize) == "e4c5fcfe2902dffc20eec1999e2cfa8fba7d4809682ea38a3266af6401f69ca0"
}

rule MalwareBazaar_unknown_031_af6236c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af6236c77019dabd4c82fda176cfaf2c45a858ff395863bf2c367277896c3ea6"
    family = "unknown"
    file_name = "ae8d52715f0a30f8.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:27"
  condition:
    hash.sha256(0, filesize) == "af6236c77019dabd4c82fda176cfaf2c45a858ff395863bf2c367277896c3ea6"
}

rule MalwareBazaar_unknown_032_374d0e88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558"
    family = "unknown"
    file_name = "466c512640001af3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:26:20"
  condition:
    hash.sha256(0, filesize) == "374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558"
}

rule MalwareBazaar_SalatStealer_033_cfb4a4fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfb4a4fe03cbeefdd258e68031f40011cf9d06b142b8421c09d2e396d551dbf1"
    family = "SalatStealer"
    file_name = "cfb4a4fe03cbeefd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:55"
  condition:
    hash.sha256(0, filesize) == "cfb4a4fe03cbeefdd258e68031f40011cf9d06b142b8421c09d2e396d551dbf1"
}

rule MalwareBazaar_SalatStealer_034_54700c5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54700c5bdc9de74a1b58977d20fd11b5c76772bdcc29b2095504a91d613d5c8c"
    family = "SalatStealer"
    file_name = "54700c5bdc9de74a.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:44"
  condition:
    hash.sha256(0, filesize) == "54700c5bdc9de74a1b58977d20fd11b5c76772bdcc29b2095504a91d613d5c8c"
}

rule MalwareBazaar_unknown_035_18cda384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cda38460611ce703da077c3f574f3e1b45e957f154f58ec02461fe2f5207f0"
    family = "unknown"
    file_name = "ffc2ef52575dd974.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:38"
  condition:
    hash.sha256(0, filesize) == "18cda38460611ce703da077c3f574f3e1b45e957f154f58ec02461fe2f5207f0"
}

rule MalwareBazaar_unknown_036_8409db34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8409db3459e8383ff3222f7e462bb1e3ccad71afd68ba1d18c643bd1d24d1dab"
    family = "unknown"
    file_name = "2d2ba75bfc9809d5.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:33"
  condition:
    hash.sha256(0, filesize) == "8409db3459e8383ff3222f7e462bb1e3ccad71afd68ba1d18c643bd1d24d1dab"
}

rule MalwareBazaar_SalatStealer_037_ae8d5271
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae8d52715f0a30f8aa9388a32edc8b1447425149fc94653d63502c8afda0fed1"
    family = "SalatStealer"
    file_name = "ae8d52715f0a30f8.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:32"
  condition:
    hash.sha256(0, filesize) == "ae8d52715f0a30f8aa9388a32edc8b1447425149fc94653d63502c8afda0fed1"
}

rule MalwareBazaar_unknown_038_db775faa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db775faaa5ad2de8e4a45a89f677f642d7225936479abc641e20c27676013f26"
    family = "unknown"
    file_name = "88d5738faf554477.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:28"
  condition:
    hash.sha256(0, filesize) == "db775faaa5ad2de8e4a45a89f677f642d7225936479abc641e20c27676013f26"
}

rule MalwareBazaar_unknown_039_234a106f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "234a106f46d0274b059373f5138f328b48d930ba2f3ff8aa388d8e77d3c6868b"
    family = "unknown"
    file_name = "aa048a86045403f4.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:22"
  condition:
    hash.sha256(0, filesize) == "234a106f46d0274b059373f5138f328b48d930ba2f3ff8aa388d8e77d3c6868b"
}

rule MalwareBazaar_SalatStealer_040_466c5126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "466c512640001af3e8b8b04bb3866d35c90fc729859500d7e8b9deeeced2ffc3"
    family = "SalatStealer"
    file_name = "466c512640001af3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:21"
  condition:
    hash.sha256(0, filesize) == "466c512640001af3e8b8b04bb3866d35c90fc729859500d7e8b9deeeced2ffc3"
}

rule MalwareBazaar_SalatStealer_041_ffc2ef52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffc2ef52575dd9749253404813fff150e4eb60650f34375af5af1f529f9e64d8"
    family = "SalatStealer"
    file_name = "ffc2ef52575dd974.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:25:09"
  condition:
    hash.sha256(0, filesize) == "ffc2ef52575dd9749253404813fff150e4eb60650f34375af5af1f529f9e64d8"
}

rule MalwareBazaar_SalatStealer_042_2d2ba75b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d2ba75bfc9809d5eb8ddab04acb29f43261248bb845cd0d16c4358230a7495d"
    family = "SalatStealer"
    file_name = "2d2ba75bfc9809d5.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:24:57"
  condition:
    hash.sha256(0, filesize) == "2d2ba75bfc9809d5eb8ddab04acb29f43261248bb845cd0d16c4358230a7495d"
}

rule MalwareBazaar_SalatStealer_043_88d5738f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88d5738faf554477ace7ccc3f3a43ab0ec975ecde469ce562a656b18655765ea"
    family = "SalatStealer"
    file_name = "88d5738faf554477.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:24:46"
  condition:
    hash.sha256(0, filesize) == "88d5738faf554477ace7ccc3f3a43ab0ec975ecde469ce562a656b18655765ea"
}

rule MalwareBazaar_SalatStealer_044_aa048a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa048a86045403f4dc84c21d077b5c4a934b2756bc9e9242a46133c96a1e8b2c"
    family = "SalatStealer"
    file_name = "aa048a86045403f4.bin"
    file_type = "exe"
    first_seen = "2026-11-11 05:24:33"
  condition:
    hash.sha256(0, filesize) == "aa048a86045403f4dc84c21d077b5c4a934b2756bc9e9242a46133c96a1e8b2c"
}

rule MalwareBazaar_Mirai_045_3146cbed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3146cbeda2e32e100db10ef2be13b6b2d6922b41da94ccd59a57edc3030d0eb0"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-11 05:17:04"
  condition:
    hash.sha256(0, filesize) == "3146cbeda2e32e100db10ef2be13b6b2d6922b41da94ccd59a57edc3030d0eb0"
}

rule MalwareBazaar_unknown_046_b4b10c8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf"
    family = "unknown"
    file_name = "8b2d30759910deac.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:43"
  condition:
    hash.sha256(0, filesize) == "b4b10c8daf783a3cb2653ba088f78246d66f6fb6b8afa25bb649c2c3868058cf"
}

rule MalwareBazaar_unknown_047_1369c407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619"
    family = "unknown"
    file_name = "15ea4e787116522d.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:38"
  condition:
    hash.sha256(0, filesize) == "1369c4076348ef5b0e61a4fdedbb17a291a814f6251d228ec5f473ba27fe2619"
}

rule MalwareBazaar_unknown_048_6d4f6858
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327"
    family = "unknown"
    file_name = "a79cf601233522c3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:31"
  condition:
    hash.sha256(0, filesize) == "6d4f6858e88c370e8c8a277f12c6f0c4634a92c7351756f59633007cd14b5327"
}

rule MalwareBazaar_unknown_049_195288be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38"
    family = "unknown"
    file_name = "7aebd9afa430a390.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:25:24"
  condition:
    hash.sha256(0, filesize) == "195288be3f11d536161651018e4f2384280dc8752d2ac2042cdb6c5e58c02c38"
}

rule MalwareBazaar_SalatStealer_050_8b2d3075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d"
    family = "SalatStealer"
    file_name = "8b2d30759910deac.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:52"
  condition:
    hash.sha256(0, filesize) == "8b2d30759910deac9eb4d743fce135edd9da68ac987116cc0e1cbd5f7fb7f48d"
}

rule MalwareBazaar_SalatStealer_051_15ea4e78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ea4e787116522de1ec7f4f4871ee19ebec82218edbbcca89f6859da17eb9a0"
    family = "SalatStealer"
    file_name = "15ea4e787116522d.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:40"
  condition:
    hash.sha256(0, filesize) == "15ea4e787116522de1ec7f4f4871ee19ebec82218edbbcca89f6859da17eb9a0"
}

rule MalwareBazaar_unknown_052_6f41cc41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f41cc418e91d77d284813a959bfead1ecec20d6fc60be6078e7ea9e27ced201"
    family = "unknown"
    file_name = "ac643417c2da18ad.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:33"
  condition:
    hash.sha256(0, filesize) == "6f41cc418e91d77d284813a959bfead1ecec20d6fc60be6078e7ea9e27ced201"
}

rule MalwareBazaar_SalatStealer_053_a79cf601
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79cf601233522c3306f8e6bb2ed5c9f98a9c67f782d8959fc2d10bda3a8673a"
    family = "SalatStealer"
    file_name = "a79cf601233522c3.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:29"
  condition:
    hash.sha256(0, filesize) == "a79cf601233522c3306f8e6bb2ed5c9f98a9c67f782d8959fc2d10bda3a8673a"
}

rule MalwareBazaar_unknown_054_710f4c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "710f4c6a9ea4262ceb36301b859f92fcd667aca69d5066754355d4eac7ff4438"
    family = "unknown"
    file_name = "6c5d52181f9d7337.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:28"
  condition:
    hash.sha256(0, filesize) == "710f4c6a9ea4262ceb36301b859f92fcd667aca69d5066754355d4eac7ff4438"
}

rule MalwareBazaar_unknown_055_451ee61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451ee61c8ad803667d9f466f35c2c949287c2e2bfdfdf4a40fbc3937deb2686e"
    family = "unknown"
    file_name = "a96d75a2b93ce72b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:23"
  condition:
    hash.sha256(0, filesize) == "451ee61c8ad803667d9f466f35c2c949287c2e2bfdfdf4a40fbc3937deb2686e"
}

rule MalwareBazaar_unknown_056_42033073
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4203307358acd7cff3c165372cd299aa3fc4052c5d14af62812be49b4ec88aa1"
    family = "unknown"
    file_name = "935186620847b198.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:18"
  condition:
    hash.sha256(0, filesize) == "4203307358acd7cff3c165372cd299aa3fc4052c5d14af62812be49b4ec88aa1"
}

rule MalwareBazaar_SalatStealer_057_7aebd9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aebd9afa430a39010e142909f7c1cbfa3c9935673f11d27ff2c333cc4e30615"
    family = "SalatStealer"
    file_name = "7aebd9afa430a390.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:18"
  condition:
    hash.sha256(0, filesize) == "7aebd9afa430a39010e142909f7c1cbfa3c9935673f11d27ff2c333cc4e30615"
}

rule MalwareBazaar_SalatStealer_058_ac643417
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac643417c2da18ad88c9978174b9094a8ad50d3d4e801d95c65718164b4015e3"
    family = "SalatStealer"
    file_name = "ac643417c2da18ad.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:24:06"
  condition:
    hash.sha256(0, filesize) == "ac643417c2da18ad88c9978174b9094a8ad50d3d4e801d95c65718164b4015e3"
}

rule MalwareBazaar_SalatStealer_059_6c5d5218
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c5d52181f9d733746cac4bfd9f6bb967bf6e2e679b063a3f333e7e0ea2aadfa"
    family = "SalatStealer"
    file_name = "6c5d52181f9d7337.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:23:54"
  condition:
    hash.sha256(0, filesize) == "6c5d52181f9d733746cac4bfd9f6bb967bf6e2e679b063a3f333e7e0ea2aadfa"
}

rule MalwareBazaar_SalatStealer_060_a96d75a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a96d75a2b93ce72b555bf5e1ae5fce4bbb328bf8d2a2809686b8f1469cc95e5d"
    family = "SalatStealer"
    file_name = "a96d75a2b93ce72b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:23:43"
  condition:
    hash.sha256(0, filesize) == "a96d75a2b93ce72b555bf5e1ae5fce4bbb328bf8d2a2809686b8f1469cc95e5d"
}

rule MalwareBazaar_SalatStealer_061_93518662
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935186620847b198d627d8ab52a8305196e9db46a5a6a520de39f3ec0f353998"
    family = "SalatStealer"
    file_name = "935186620847b198.bin"
    file_type = "exe"
    first_seen = "2026-11-11 04:23:32"
  condition:
    hash.sha256(0, filesize) == "935186620847b198d627d8ab52a8305196e9db46a5a6a520de39f3ec0f353998"
}

rule MalwareBazaar_Mirai_062_a629ffcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 04:17:04"
  condition:
    hash.sha256(0, filesize) == "a629ffcf3eac76dd2265be84c7cf115b46131260976f29b9af960a32ed1a89a7"
}

rule MalwareBazaar_unknown_063_bf861394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01"
    family = "unknown"
    file_name = "bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01"
    file_type = "exe"
    first_seen = "2026-11-11 04:15:21"
  condition:
    hash.sha256(0, filesize) == "bf861394a11a6b8c3568ad36c595a8a658c6b053cc2e63ccc3efe1de89498f01"
}

rule MalwareBazaar_Mirai_064_2814ef4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 04:10:04"
  condition:
    hash.sha256(0, filesize) == "2814ef4cddbe575b6b3d956c75c738d411c1985df2a7e1aa2c5695d96f642830"
}

rule MalwareBazaar_Arechclient2_065_4351a7e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0"
    family = "Arechclient2"
    file_name = "newcrytest.msi"
    file_type = "msi"
    first_seen = "2026-11-11 03:42:59"
  condition:
    hash.sha256(0, filesize) == "4351a7e899a2d3d2b8fa465b2567857a03ecc48aef9b9a67bc8bbd8f67303ec0"
}

rule MalwareBazaar_unknown_066_4c6fc10b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6fc10b19f08431922034c9989c198a68dca8606d05670052a68646e9cdb0ce"
    family = "unknown"
    file_name = "cdrt.msi"
    file_type = "msi"
    first_seen = "2026-11-11 03:34:42"
  condition:
    hash.sha256(0, filesize) == "4c6fc10b19f08431922034c9989c198a68dca8606d05670052a68646e9cdb0ce"
}

rule MalwareBazaar_CoinMiner_067_0f64b4d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f64b4d5288f88f16165eebe27242281ba80095380491cc77406ee647be614d7"
    family = "CoinMiner"
    file_name = "vlc_1.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:33:01"
  condition:
    hash.sha256(0, filesize) == "0f64b4d5288f88f16165eebe27242281ba80095380491cc77406ee647be614d7"
}

rule MalwareBazaar_unknown_068_8a9f25a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9f25a07e36759fe1f31be58223008cc9f0310e109595cce64fcc793f19c47d"
    family = "unknown"
    file_name = "gv.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:32:04"
  condition:
    hash.sha256(0, filesize) == "8a9f25a07e36759fe1f31be58223008cc9f0310e109595cce64fcc793f19c47d"
}

rule MalwareBazaar_RevStealer_069_4998bd8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41"
    family = "RevStealer"
    file_name = "4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:30:49"
  condition:
    hash.sha256(0, filesize) == "4998bd8a1bc0f492b3e2b2e0a038599eeb337d8222d19dc01c0f19e234a6da41"
}

rule MalwareBazaar_RevStealer_070_f0b58db8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5"
    family = "RevStealer"
    file_name = "f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:30:43"
  condition:
    hash.sha256(0, filesize) == "f0b58db8437fa3995d3c7579f77d3f97d3b61bc920dd7a30398633755fb80cb5"
}

rule MalwareBazaar_Mirai_071_d2c18f8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-11 03:27:52"
  condition:
    hash.sha256(0, filesize) == "d2c18f8cc79df2e13cc823c5a947dee210b42915e21af09d3fda7fb2ff2cf37a"
}

rule MalwareBazaar_SalatStealer_072_f3f0f249
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3f0f2491c066b7f984e810df7f5a4e29b5c43af3202b757b66124b8c3b6b9b1"
    family = "SalatStealer"
    file_name = "b6dfbacd86c47441.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:48"
  condition:
    hash.sha256(0, filesize) == "f3f0f2491c066b7f984e810df7f5a4e29b5c43af3202b757b66124b8c3b6b9b1"
}

rule MalwareBazaar_SalatStealer_073_2088e817
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2088e8179a868592a6ee8732a7fe2f544ef682cfa2dc856ff43844729ccd6711"
    family = "SalatStealer"
    file_name = "ad7a120dd5f49a3e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:43"
  condition:
    hash.sha256(0, filesize) == "2088e8179a868592a6ee8732a7fe2f544ef682cfa2dc856ff43844729ccd6711"
}

rule MalwareBazaar_SalatStealer_074_9c6a76e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c6a76e7cf6ba827fb6ffd772fa410f40b0808e82e7733a6701df729f10ba75e"
    family = "SalatStealer"
    file_name = "e2289f43e9b8b71b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:37"
  condition:
    hash.sha256(0, filesize) == "9c6a76e7cf6ba827fb6ffd772fa410f40b0808e82e7733a6701df729f10ba75e"
}

rule MalwareBazaar_SalatStealer_075_edd388b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edd388b680bcf1d051bb65941578fd6cb142607629c37d8dc27a3ce6c28d9fd1"
    family = "SalatStealer"
    file_name = "692d3b0dccef48dd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:31"
  condition:
    hash.sha256(0, filesize) == "edd388b680bcf1d051bb65941578fd6cb142607629c37d8dc27a3ce6c28d9fd1"
}

rule MalwareBazaar_WARDENStealer_076_640116d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "640116d122dcbb34b77cfe0844822582b52674cf28acc53df7882078a49b7ad7"
    family = "WARDENStealer"
    file_name = "𝐒𝐄𝐓𝐔𝐏.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:27:20"
  condition:
    hash.sha256(0, filesize) == "640116d122dcbb34b77cfe0844822582b52674cf28acc53df7882078a49b7ad7"
}

rule MalwareBazaar_unknown_077_d4482565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4482565a2e7c4b1bd23a5cb9240eabbc094e09ccf79b89a60ff1467fb175773"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-11 03:27:07"
  condition:
    hash.sha256(0, filesize) == "d4482565a2e7c4b1bd23a5cb9240eabbc094e09ccf79b89a60ff1467fb175773"
}

rule MalwareBazaar_Mirai_078_6d6fd016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-11 03:27:04"
  condition:
    hash.sha256(0, filesize) == "6d6fd016c78e8f5d83ed91e5acdfb5214183de34ac62a89b2de049927ef347a2"
}

rule MalwareBazaar_SalatStealer_079_b6dfbacd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6dfbacd86c47441a3343e64e7073e8bad456ca42913b21b1d98b0035b7fa212"
    family = "SalatStealer"
    file_name = "b6dfbacd86c47441.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:54"
  condition:
    hash.sha256(0, filesize) == "b6dfbacd86c47441a3343e64e7073e8bad456ca42913b21b1d98b0035b7fa212"
}

rule MalwareBazaar_SalatStealer_080_914e5025
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "914e50252b3cda59f225f1821bbbab7683a59792a5a8d220a46f1fa0b6f4322c"
    family = "SalatStealer"
    file_name = "3d9c13c99ebac596.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:43"
  condition:
    hash.sha256(0, filesize) == "914e50252b3cda59f225f1821bbbab7683a59792a5a8d220a46f1fa0b6f4322c"
}

rule MalwareBazaar_SalatStealer_081_ad7a120d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad7a120dd5f49a3e246721b0457cd600a35b94e74528c7f4d99c42a0eec5673d"
    family = "SalatStealer"
    file_name = "ad7a120dd5f49a3e.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:43"
  condition:
    hash.sha256(0, filesize) == "ad7a120dd5f49a3e246721b0457cd600a35b94e74528c7f4d99c42a0eec5673d"
}

rule MalwareBazaar_SalatStealer_082_6a090f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a090f40b1f7bd476e574fd8bf7a7532330bd31a8d279922f341377497ab501f"
    family = "SalatStealer"
    file_name = "df2f4162958da6b9.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:38"
  condition:
    hash.sha256(0, filesize) == "6a090f40b1f7bd476e574fd8bf7a7532330bd31a8d279922f341377497ab501f"
}

rule MalwareBazaar_SalatStealer_083_4d3547ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d3547ffe2f6a160289c6ff00f8596be158b070e6f5862fd3c7d6321d323d307"
    family = "SalatStealer"
    file_name = "4bd9fd518fcfb4f1.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:32"
  condition:
    hash.sha256(0, filesize) == "4d3547ffe2f6a160289c6ff00f8596be158b070e6f5862fd3c7d6321d323d307"
}

rule MalwareBazaar_SalatStealer_084_e2289f43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2289f43e9b8b71b5319c2caacf825b3d2972e83df01f8d84a4e1be41bfc615f"
    family = "SalatStealer"
    file_name = "e2289f43e9b8b71b.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:32"
  condition:
    hash.sha256(0, filesize) == "e2289f43e9b8b71b5319c2caacf825b3d2972e83df01f8d84a4e1be41bfc615f"
}

rule MalwareBazaar_SalatStealer_085_fa89a221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa89a22118841e1c20f357fec81d4ae60f465a88419889b568f17ec77aad942d"
    family = "SalatStealer"
    file_name = "b99976dcc8c6042c.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:25"
  condition:
    hash.sha256(0, filesize) == "fa89a22118841e1c20f357fec81d4ae60f465a88419889b568f17ec77aad942d"
}

rule MalwareBazaar_SalatStealer_086_692d3b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "692d3b0dccef48dd2000ba456a692a524ced18729db28b3eb7874bb6b1bdcf39"
    family = "SalatStealer"
    file_name = "692d3b0dccef48dd.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:20"
  condition:
    hash.sha256(0, filesize) == "692d3b0dccef48dd2000ba456a692a524ced18729db28b3eb7874bb6b1bdcf39"
}

rule MalwareBazaar_SalatStealer_087_3d9c13c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d9c13c99ebac5964a0ce4d41786d98660554851583d5b461ff5e56cab63a410"
    family = "SalatStealer"
    file_name = "3d9c13c99ebac596.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:26:09"
  condition:
    hash.sha256(0, filesize) == "3d9c13c99ebac5964a0ce4d41786d98660554851583d5b461ff5e56cab63a410"
}

rule MalwareBazaar_SalatStealer_088_df2f4162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df2f4162958da6b95b83667f9a81b9976eb1d0d333c674ae6afb9a056e32d327"
    family = "SalatStealer"
    file_name = "df2f4162958da6b9.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:25:58"
  condition:
    hash.sha256(0, filesize) == "df2f4162958da6b95b83667f9a81b9976eb1d0d333c674ae6afb9a056e32d327"
}

rule MalwareBazaar_SalatStealer_089_4bd9fd51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd9fd518fcfb4f1fb1b2ac9df7e9dc751e80215368015d5ab58c98b981cee68"
    family = "SalatStealer"
    file_name = "4bd9fd518fcfb4f1.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:25:48"
  condition:
    hash.sha256(0, filesize) == "4bd9fd518fcfb4f1fb1b2ac9df7e9dc751e80215368015d5ab58c98b981cee68"
}

rule MalwareBazaar_Mirai_090_59b1072d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42"
    family = "Mirai"
    file_name = "59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42.elf"
    file_type = "elf"
    first_seen = "2026-11-11 03:25:47"
  condition:
    hash.sha256(0, filesize) == "59b1072d546995aa7ac598ce4355b32fad22f83179716d4480a683cbc2f48f42"
}

rule MalwareBazaar_unknown_091_07f1eda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f1eda56e4252cbbf72847c2855d218c82f2d199259a569b8ca468a270f5742"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-11 03:25:37"
  condition:
    hash.sha256(0, filesize) == "07f1eda56e4252cbbf72847c2855d218c82f2d199259a569b8ca468a270f5742"
}

rule MalwareBazaar_SalatStealer_092_b99976dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b99976dcc8c6042cb38662e1fe3de6d866e0bd778714087fd67fadd0a1f68a1f"
    family = "SalatStealer"
    file_name = "b99976dcc8c6042c.bin"
    file_type = "exe"
    first_seen = "2026-11-11 03:25:36"
  condition:
    hash.sha256(0, filesize) == "b99976dcc8c6042cb38662e1fe3de6d866e0bd778714087fd67fadd0a1f68a1f"
}

rule MalwareBazaar_WARDENStealer_093_a589532b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a589532b0b7e1a900955c8e5dc87d1d8ec48b3d1d05e6415bd74e5e48ea56c23"
    family = "WARDENStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:22:42"
  condition:
    hash.sha256(0, filesize) == "a589532b0b7e1a900955c8e5dc87d1d8ec48b3d1d05e6415bd74e5e48ea56c23"
}

rule MalwareBazaar_unknown_094_8edc371d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb"
    family = "unknown"
    file_name = "Launcher15894x64.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:21:15"
  condition:
    hash.sha256(0, filesize) == "8edc371dba96886ccfd530735ccd86929101706ec58ed14d782107fd877389fb"
}

rule MalwareBazaar_unknown_095_7db79169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-11 03:20:48"
  condition:
    hash.sha256(0, filesize) == "7db79169e437472ff9d24560a89c64259c618e1282f3e4b4cdec0bf4907e16e1"
}

rule MalwareBazaar_unknown_096_31e044d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31e044d3fbf6d6cc21f9fdff9560e058b07a8b3f47b35fa073289a75ee12646f"
    family = "unknown"
    file_name = "Installer_L_X64_x86_2024.zip"
    file_type = "zip"
    first_seen = "2026-11-11 03:18:38"
  condition:
    hash.sha256(0, filesize) == "31e044d3fbf6d6cc21f9fdff9560e058b07a8b3f47b35fa073289a75ee12646f"
}

rule MalwareBazaar_WARDENStealer_097_eeb57f00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb57f00c3d388864fad8d347e86ae143f47e41f6503853fdecac9ae4982bcfd"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:16:53"
  condition:
    hash.sha256(0, filesize) == "eeb57f00c3d388864fad8d347e86ae143f47e41f6503853fdecac9ae4982bcfd"
}

rule MalwareBazaar_Mirai_098_92ebc788
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-11 03:16:04"
  condition:
    hash.sha256(0, filesize) == "92ebc788fce25f187a9523e84842948faad17a25cb3d3c2dbda4d85c08629ac6"
}

rule MalwareBazaar_WARDENStealer_099_6444a4e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6444a4e18c9ca99b5516e5365baac88bf4d62182e3630451b202c9bfb4ccbc0b"
    family = "WARDENStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-11 03:15:38"
  condition:
    hash.sha256(0, filesize) == "6444a4e18c9ca99b5516e5365baac88bf4d62182e3630451b202c9bfb4ccbc0b"
}

rule MalwareBazaar_Mirai_100_8f17149c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4"
    family = "Mirai"
    file_name = "galaxy.arm7"
    file_type = "elf"
    first_seen = "2026-11-11 03:14:05"
  condition:
    hash.sha256(0, filesize) == "8f17149c4abc15085e4767c1b2349fa5c3bf9b9ad09edd335b7257950ca33de4"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

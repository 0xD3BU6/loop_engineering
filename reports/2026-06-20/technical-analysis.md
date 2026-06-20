# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-20

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 628 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 628 |
| Unique family labels | 8 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 68 |
| Mirai | 21 |
| CoinMiner | 4 |
| RustyStealer | 2 |
| RemusStealer | 2 |
| ConnectWise | 1 |
| AsyncRAT | 1 |
| Prometei | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 61 |
| exe | 18 |
| sh | 10 |
| zip | 5 |
| unknown | 3 |
| lnk | 2 |
| vbs | 1 |

## Per-Sample Analysis

### Sample 1: `a9303e3948a21247`

| Field | Value |
|---|---|
| SHA-256 | `a9303e3948a212476179499bf5e7aaf5df89fc490bf28c8ec15005bf8b023ee5` |
| Family label | `unknown` |
| File name | `Client.exe` |
| File type | `exe` |
| First seen | `2026-06-20 21:59:08` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1479d53b5b86ad090d66775f14fb03fc` |
| SHA-1 | `2acb65032e6581214fd927404d761dda32e0fd62` |
| SHA-256 | `a9303e3948a212476179499bf5e7aaf5df89fc490bf28c8ec15005bf8b023ee5` |
| SHA3-384 | `5798ec0beb4d5260d00961fe409b7347e0a252545e0ec91c2e323c3d04fa4bdec021c7b6ce10aec152a9865fe2bf795a` |
| IMPHASH | `cd40545a33dc365b00dc388241fa5c66` |
| TLSH | `T174E533A0FA96EEE6CA0843368E5F430E027DF68913495723552CB7251F632E07F8B957` |
| SSDEEP | `49152:wyJ269N6mK/B2PA1Jkjs8oUToH0teRQD7oNHDPrHI+xY8eoQfAHkfCuuRDzCjRo8:wkz6mKpXXjRUeE4NHDjxeookrzUc/8q8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_a9303e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9303e3948a212476179499bf5e7aaf5df89fc490bf28c8ec15005bf8b023ee5"
    family = "unknown"
    file_name = "Client.exe"
    file_type = "exe"
    first_seen = "2026-06-20 21:59:08"
  condition:
    hash.sha256(0, filesize) == "a9303e3948a212476179499bf5e7aaf5df89fc490bf28c8ec15005bf8b023ee5"
}
```

### Sample 2: `b1d863f55530e9f3`

| Field | Value |
|---|---|
| SHA-256 | `b1d863f55530e9f30b6d80d9930a638581e6c00674d5e25cb38b88911cc0ccba` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 21:56:32` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40cbcb6bf953f2953581757420fced18` |
| SHA-1 | `900beabe327834536b897d67287da1f3c54e0b2d` |
| SHA-256 | `b1d863f55530e9f30b6d80d9930a638581e6c00674d5e25cb38b88911cc0ccba` |
| SHA3-384 | `bf47bbb95596102de754907e4768ec25d87966c9f4180f9357dab58359584ab4347c06e06169c04594dd835f9df3808c` |
| IMPHASH | `64a82792ae217a318cbb528c890e0d46` |
| TLSH | `T1F1C61295A4D5C2FDC845C470E24829FDF0DA78594EBD593B7FCA88122971C48C8FABB2` |
| SSDEEP | `196608:ix/2hUd2I5mhmEaFF+dTDs6pOyVhNFrHMWQIFFkMMs2xHnUX3oUW2D1odA4MpOjx:i3dDDEoc86pOyVhTrHMgFPMJSX3dxh90` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_b1d863f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1d863f55530e9f30b6d80d9930a638581e6c00674d5e25cb38b88911cc0ccba"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:56:32"
  condition:
    hash.sha256(0, filesize) == "b1d863f55530e9f30b6d80d9930a638581e6c00674d5e25cb38b88911cc0ccba"
}
```

### Sample 3: `eb2cca230b99d059`

| Field | Value |
|---|---|
| SHA-256 | `eb2cca230b99d059355c3d4d2c35e9585aedd030c7477535b86bbc950d7ea2a9` |
| Family label | `CoinMiner` |
| File name | `client.exe` |
| File type | `exe` |
| First seen | `2026-06-20 21:55:32` |
| Reporter | `BlinkzSec` |
| Tags | `CoinMiner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9970201d525bfc80d9c3b1f011e4178` |
| SHA-1 | `2d8cd9d19e931872f9a9999db7e61c59f39808b1` |
| SHA-256 | `eb2cca230b99d059355c3d4d2c35e9585aedd030c7477535b86bbc950d7ea2a9` |
| SHA3-384 | `85dc8777689f25a14d6595bd2956d859e63d42b27eb284c488b01b4bc78c2d162988a89fe7d6ad820756dd62c0f0340c` |
| IMPHASH | `cd40545a33dc365b00dc388241fa5c66` |
| TLSH | `T18BE533D09BC3D9D7C641037E89A6461E2334E6850BD3CB1728B5A3760E366D07F87E6A` |
| SSDEEP | `49152:3hbmYcsGXSpUkCTIipshMVpFb4g8p6L54DNmg1ss1M7i+/htP+rX9kw5OP9htWMR:3hb3zUHr366LGNEv7i+5tP+JkwYLSlF+` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_003_eb2cca23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb2cca230b99d059355c3d4d2c35e9585aedd030c7477535b86bbc950d7ea2a9"
    family = "CoinMiner"
    file_name = "client.exe"
    file_type = "exe"
    first_seen = "2026-06-20 21:55:32"
  condition:
    hash.sha256(0, filesize) == "eb2cca230b99d059355c3d4d2c35e9585aedd030c7477535b86bbc950d7ea2a9"
}
```

### Sample 4: `a9b58569a98930eb`

| Field | Value |
|---|---|
| SHA-256 | `a9b58569a98930ebe0b68bddd9fb13e4ddc9e75530b283d07b853c97b6c13d8a` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-20 21:47:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be6f4554b3eb5284b188c8ffedf32897` |
| SHA-1 | `ba2a3ee966ebef320b85c3f14514f350c84b7675` |
| SHA-256 | `a9b58569a98930ebe0b68bddd9fb13e4ddc9e75530b283d07b853c97b6c13d8a` |
| SHA3-384 | `daf29f386d84f8401ed7c651f51256ee773482afcfc3bd6fa56a64fb4e0e9485cc3e03f7df6361c794f4c3fb3377cbda` |
| TLSH | `T158016FCA856069408129DA5D7AE7A6E0B420D3CE1A860B78BF9C193EF79C404F166F54` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkapCrNh/jCWeCCItcfqDC1XFCyuBFUauD:kXCKysE2hi0ziQvZohapoNFPDoFi87` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_a9b58569
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9b58569a98930ebe0b68bddd9fb13e4ddc9e75530b283d07b853c97b6c13d8a"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-20 21:47:43"
  condition:
    hash.sha256(0, filesize) == "a9b58569a98930ebe0b68bddd9fb13e4ddc9e75530b283d07b853c97b6c13d8a"
}
```

### Sample 5: `ec77a80a984c029b`

| Field | Value |
|---|---|
| SHA-256 | `ec77a80a984c029be6242314bce682b5234783801f4dbe449b250e0198bcbf26` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 21:45:55` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b73137186d169060ebaa1faa292ec49` |
| SHA-1 | `530a6d4e50f2f7a2dfdc2aa09e49c825bb185f2f` |
| SHA-256 | `ec77a80a984c029be6242314bce682b5234783801f4dbe449b250e0198bcbf26` |
| SHA3-384 | `b51f14cb541b920cec82ab04d180a3b174bef1218965180d1abfd7c227a2f7ff39f1d206ba9aac8be3549130706c537f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E863A6C875A78831D0BF9EB6E6D7624B5DB060737C01D2491CD216E2AA11EC6F90ECF6` |
| SSDEEP | `1536:TokUMg4r4apZm9LXfbSHYdR9bS8LP/AX:Tok048aTm9LvmeR9bSBX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_ec77a80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec77a80a984c029be6242314bce682b5234783801f4dbe449b250e0198bcbf26"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:45:55"
  condition:
    hash.sha256(0, filesize) == "ec77a80a984c029be6242314bce682b5234783801f4dbe449b250e0198bcbf26"
}
```

### Sample 6: `5122b2cc1fc99c60`

| Field | Value |
|---|---|
| SHA-256 | `5122b2cc1fc99c60330b863c94e09e82553eff28cbfba8496f30bea88465b77d` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 21:45:29` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60e777e3511e77ed3504aa4743edd945` |
| SHA-1 | `11fbd76ea1316ecc5aaf7face831b33ed0e0abd6` |
| SHA-256 | `5122b2cc1fc99c60330b863c94e09e82553eff28cbfba8496f30bea88465b77d` |
| SHA3-384 | `6a88ca9cc0bb220e5d2dc21cd9579cfbaa02eb034ed2b8d256bff860e20e71ffa4c652b342a55330092f1c3392040a4c` |
| IMPHASH | `3641b918fa6fcd6b6754b75fd2065c00` |
| TLSH | `T1CDF533D122C05AF8F1EAC535839C2D154A177675AF26B6EF138386103E3BAC65E3AD1C` |
| SSDEEP | `49152:WDJlJnWGWKwmZWz/gk7u+3vxcXhYuaV0tAQl3Cx7BMqQ:vR3jgk6+fxcXhYuayACyAv` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_006_5122b2cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5122b2cc1fc99c60330b863c94e09e82553eff28cbfba8496f30bea88465b77d"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:45:29"
  condition:
    hash.sha256(0, filesize) == "5122b2cc1fc99c60330b863c94e09e82553eff28cbfba8496f30bea88465b77d"
}
```

### Sample 7: `40345a358400cb77`

| Field | Value |
|---|---|
| SHA-256 | `40345a358400cb771088c33a9cf194946da95c2bb2d979e7be5e1c8c37facf33` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 21:45:09` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7408473f668d0e3563d8755b17fdf638` |
| SHA-1 | `d6c5f173cea005c5081c4f189477c1ade350cec3` |
| SHA-256 | `40345a358400cb771088c33a9cf194946da95c2bb2d979e7be5e1c8c37facf33` |
| SHA3-384 | `57adbe8b80ba6df1434ab886eadd7c6297103e260d32a839efafdffad061979708200558c411a62a8eb5f7f64df69a03` |
| IMPHASH | `3641b918fa6fcd6b6754b75fd2065c00` |
| TLSH | `T1CBF5330B44A936FECC96C630AB329E22452B79264BC616FF4B87513039B8CE55F794C7` |
| SSDEEP | `49152:zNUWVyxrlkHAmqy4x3994O/ujGT7wEFGdg0T/idBx8cHUQAIGzDoIwa4d8e8U:aWVyxrlkHLqxx8GT7oqx8cHHA9/nNe` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_007_40345a35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40345a358400cb771088c33a9cf194946da95c2bb2d979e7be5e1c8c37facf33"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:45:09"
  condition:
    hash.sha256(0, filesize) == "40345a358400cb771088c33a9cf194946da95c2bb2d979e7be5e1c8c37facf33"
}
```

### Sample 8: `52764c8c74bc2ec1`

| Field | Value |
|---|---|
| SHA-256 | `52764c8c74bc2ec19138f7bbaaeb30fc24f5384709409e756f3edb03848c67bb` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 21:44:49` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ed805decde82a5dba7cb9210d0b76ac` |
| SHA-1 | `26bd4d81a16ea2726cc7c645fd00a6427e3202d6` |
| SHA-256 | `52764c8c74bc2ec19138f7bbaaeb30fc24f5384709409e756f3edb03848c67bb` |
| SHA3-384 | `21e5e2b45000e918d669264146a8cf84bfb5895097f81dfba6efd8dc06bf4671fdbd6d5c495513dea3979ee1df307686` |
| IMPHASH | `3641b918fa6fcd6b6754b75fd2065c00` |
| TLSH | `T1EDF533C1B1D452FDC26DF8388BAEAF766406BA323F3349C772817946B6708946E10E57` |
| SSDEEP | `49152:ScUkaW5OSRRMxaZRupIU2AT9OTDfE4bxc3TspGAsOUzEJwRU+HqhPkDeDNbIZfXP:SLMI1O+JUE4A5zEkHcP0wCz` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_008_52764c8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52764c8c74bc2ec19138f7bbaaeb30fc24f5384709409e756f3edb03848c67bb"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:44:49"
  condition:
    hash.sha256(0, filesize) == "52764c8c74bc2ec19138f7bbaaeb30fc24f5384709409e756f3edb03848c67bb"
}
```

### Sample 9: `afac970888a621eb`

| Field | Value |
|---|---|
| SHA-256 | `afac970888a621eb5a408c1820d941839c28ce4fbc351dfa0d23402f04fcd3bc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 21:44:29` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b835dd01dbb7a0c03c62890338df8e7` |
| SHA-1 | `78fb18d81f24dfb070dee1c754dc801c66973045` |
| SHA-256 | `afac970888a621eb5a408c1820d941839c28ce4fbc351dfa0d23402f04fcd3bc` |
| SHA3-384 | `110e07be3a201951d4dae8c73c06bc5d0be54be4757c278f3ce78349e87cba7dc70d76d6275c13dc0456e62e2650833a` |
| IMPHASH | `25162c295acc7b35a7ed65cee17f3a6f` |
| TLSH | `T198E523867B44E047D61E5EB9E962C3AC2762FE1A9B58970B30D0BD1F7CC66E31D84183` |
| SSDEEP | `49152:tmu3B4Dk1D5xCFaqcKcUxg8aI1vOKc0vQqd5XeBVKVdpvoWoYolJoy7nHfEKhWM4:tmaXk+lUxUIM5qdsBVKVdpg7ncMv/bRa` |
| ICON-DHASH | `1030b2b27171694c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_afac9708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afac970888a621eb5a408c1820d941839c28ce4fbc351dfa0d23402f04fcd3bc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:44:29"
  condition:
    hash.sha256(0, filesize) == "afac970888a621eb5a408c1820d941839c28ce4fbc351dfa0d23402f04fcd3bc"
}
```

### Sample 10: `3660074f4a92b21d`

| Field | Value |
|---|---|
| SHA-256 | `3660074f4a92b21ddababd36837c86db20ccd883866bc1dbeed11ed081a1df3e` |
| Family label | `unknown` |
| File name | `kworkerd-netns` |
| File type | `elf` |
| First seen | `2026-06-20 21:37:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b6ae32d6a837b5f80e9f9ba47f70a07` |
| SHA-1 | `6474d5ae5228fd10f2b3073f8e53ddb5d72a0407` |
| SHA-256 | `3660074f4a92b21ddababd36837c86db20ccd883866bc1dbeed11ed081a1df3e` |
| SHA3-384 | `693dc8be63a2cce4f5b3eaa00fcd041fe0d90336bff1b696b5bc54fa1ddcc0ee7bbfca1e7cd17ad888f678e832952bc0` |
| TLSH | `T1E2D313DEF8169DABFB71D0FD858C0AA47B35863CCBC58B0A56C003E76912297746C5E8` |
| SSDEEP | `3072:6zk6D7aABiA4C02UmmV2cOn8aizwImaV1PB28+F0uvxQT976GgXV1:6zkouABiA0R5OnNusD0uvy76ll1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_3660074f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3660074f4a92b21ddababd36837c86db20ccd883866bc1dbeed11ed081a1df3e"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-06-20 21:37:39"
  condition:
    hash.sha256(0, filesize) == "3660074f4a92b21ddababd36837c86db20ccd883866bc1dbeed11ed081a1df3e"
}
```

### Sample 11: `61dda033ee6a52ac`

| Field | Value |
|---|---|
| SHA-256 | `61dda033ee6a52ace288049c4d5be53959a5dcd0467dcd4286f3c8203ff984a4` |
| Family label | `unknown` |
| File name | `kworkerd-irq` |
| File type | `elf` |
| First seen | `2026-06-20 21:27:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01942cdc6b2032dbe91a5fda4072d575` |
| SHA-1 | `ecc766f5c9a1c5f9f781fd1955b58e012a3129de` |
| SHA-256 | `61dda033ee6a52ace288049c4d5be53959a5dcd0467dcd4286f3c8203ff984a4` |
| SHA3-384 | `05e5fc529f4b4a5c4eef67d08e43cb89bce16d237ae1cace1147db1d9a12e83ca26a4c0e2069312c07a9dd56c40764a3` |
| TLSH | `T1BCA3123253222C21C124247E4D8916E5872C7B6A7CEB3A830796591AC7E71CF29FFE5D` |
| SSDEEP | `3072:8cujVe+UpCQQ9toPuFvZGdIzFLXYTAkan+TnTl:8Ve+UpCQQWumMFLXmAkanYx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_61dda033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61dda033ee6a52ace288049c4d5be53959a5dcd0467dcd4286f3c8203ff984a4"
    family = "unknown"
    file_name = "kworkerd-irq"
    file_type = "elf"
    first_seen = "2026-06-20 21:27:43"
  condition:
    hash.sha256(0, filesize) == "61dda033ee6a52ace288049c4d5be53959a5dcd0467dcd4286f3c8203ff984a4"
}
```

### Sample 12: `e6e09041ef99c529`

| Field | Value |
|---|---|
| SHA-256 | `e6e09041ef99c529827b12f93d988dc29320fffdb604fbebbfc7403cffae6baf` |
| Family label | `unknown` |
| File name | `kworkerd-cgroup` |
| File type | `elf` |
| First seen | `2026-06-20 21:23:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e5d59a5c4581af3bce8f73cac1ce2e` |
| SHA-1 | `eb3735257c0e387fdf77627b7dbd9d41c7c2c031` |
| SHA-256 | `e6e09041ef99c529827b12f93d988dc29320fffdb604fbebbfc7403cffae6baf` |
| SHA3-384 | `231ea3e854c487b6fc70d9f1801aa2f1280adb5a558b54b008938ea19919b7461c367a3f2feb3cbb9bd050b4c51d055a` |
| TLSH | `T1E1B3126DD4C279F6D31E62FE963688BA25CB1181A32A8D10C7C0E29474F252B7F412F6` |
| TELFHASH | `t1e4a0029254a8087016540551872a627a51e3cc03d5a70048568382920344e160aa7a92` |
| SSDEEP | `1536:Dh+Fy88PsZr9RO0VrDB6ETv7oXPYy55VuS9driXjMvp2/mBTU6ZdgWDhNI:DhpPsZZRbDBx7+54SajB/9wnD3I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_e6e09041
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6e09041ef99c529827b12f93d988dc29320fffdb604fbebbfc7403cffae6baf"
    family = "unknown"
    file_name = "kworkerd-cgroup"
    file_type = "elf"
    first_seen = "2026-06-20 21:23:40"
  condition:
    hash.sha256(0, filesize) == "e6e09041ef99c529827b12f93d988dc29320fffdb604fbebbfc7403cffae6baf"
}
```

### Sample 13: `c1e97858d11f97a0`

| Field | Value |
|---|---|
| SHA-256 | `c1e97858d11f97a0157f31aeb413c76ecd9cd96062929e2e659ae9e3c0dc78c4` |
| Family label | `unknown` |
| File name | `kworkerd` |
| File type | `elf` |
| First seen | `2026-06-20 21:15:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883ae61b18863aff8ca41f8cd678eba2` |
| SHA-1 | `8c553f41afa957680b155f7560a2f06621eac497` |
| SHA-256 | `c1e97858d11f97a0157f31aeb413c76ecd9cd96062929e2e659ae9e3c0dc78c4` |
| SHA3-384 | `a28852f65033faf1dfd3ae7dd6ea702b2dd7cd418138273fb07d26c394723b789dc99de6a428906c53b08acf45925bc2` |
| TLSH | `T158B30229E53C0981E53DD0F551BFE23066ADD4CBB2F81309F2C85CA02426CF1ADA7A5B` |
| SSDEEP | `3072:xd41MFk5CMmOeYtZ0m+yKCrCfofRtLIoa+laT:xd41Me6OxnKCrCw3LIslaT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_c1e97858
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e97858d11f97a0157f31aeb413c76ecd9cd96062929e2e659ae9e3c0dc78c4"
    family = "unknown"
    file_name = "kworkerd"
    file_type = "elf"
    first_seen = "2026-06-20 21:15:40"
  condition:
    hash.sha256(0, filesize) == "c1e97858d11f97a0157f31aeb413c76ecd9cd96062929e2e659ae9e3c0dc78c4"
}
```

### Sample 14: `691c25e6addecd53`

| Field | Value |
|---|---|
| SHA-256 | `691c25e6addecd537d5948e809346235694f18621322f847299f464c35613615` |
| Family label | `unknown` |
| File name | `kworkerd-rcu` |
| File type | `elf` |
| First seen | `2026-06-20 21:12:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d99c29abf7f5ccd93fc4d7e3a619c0b5` |
| SHA-1 | `dd92f51ab921b04ccb829640d3504003cac23560` |
| SHA-256 | `691c25e6addecd537d5948e809346235694f18621322f847299f464c35613615` |
| SHA3-384 | `3cbb199adaf30009c703b521fa627ce6b0589690f02ec58875ef19f732cc1b45c3f1f70a27f0cb1b9132a91151ed59ab` |
| TLSH | `T141745B4EDF750FBFC59ECE3012AE022715DE885A92F6673B61BCCD18B25A60446E3C58` |
| TELFHASH | `t16c41c988b43649bb7db65514cc151636d646f615f8b28f10ef1cc9814a2882a6949f8f` |
| SSDEEP | `6144:PlSrtfOw+gAapIWJt7ooEuEVxe06w2V08/HWsxbLT42MHyKJ:PlSAj3exzE6f/HWWfT4n7J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_691c25e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "691c25e6addecd537d5948e809346235694f18621322f847299f464c35613615"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-20 21:12:37"
  condition:
    hash.sha256(0, filesize) == "691c25e6addecd537d5948e809346235694f18621322f847299f464c35613615"
}
```

### Sample 15: `c1ddca8512611169`

| Field | Value |
|---|---|
| SHA-256 | `c1ddca8512611169717a8f9dec04cf8a5e5636d49fbbe33f6e80c7cfa8891023` |
| Family label | `unknown` |
| File name | `kworkerd-netns-rt` |
| File type | `elf` |
| First seen | `2026-06-20 21:12:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `374dd1a0c17e07b501e7537b01869d9d` |
| SHA-1 | `133732b9a349dff2a89c84572b8cae6f99757b5f` |
| SHA-256 | `c1ddca8512611169717a8f9dec04cf8a5e5636d49fbbe33f6e80c7cfa8891023` |
| SHA3-384 | `bc8d0b1fd4564f34f0438ca2877a1b16f47b12a7605d6dcdfa45189b15c2336a0445d3d7c2eb58e77a17832d1f915c99` |
| TLSH | `T1F074194AB7618FA4E378C13006F74BA6A6FE256616E244C5D33CEE107E9035CA81FF95` |
| TELFHASH | `t16c41c988b43649bb7db65514cc151636d646f615f8b28f10ef1cc9814a2882a6949f8f` |
| SSDEEP | `6144:jbsS2t4BTidyJpY+CDrVy8zzdyIwqrgt2A6sI0T5siYM+KBe:fsS0upcxza5KSde` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_c1ddca85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ddca8512611169717a8f9dec04cf8a5e5636d49fbbe33f6e80c7cfa8891023"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-06-20 21:12:35"
  condition:
    hash.sha256(0, filesize) == "c1ddca8512611169717a8f9dec04cf8a5e5636d49fbbe33f6e80c7cfa8891023"
}
```

### Sample 16: `c9ede3834a7beceb`

| Field | Value |
|---|---|
| SHA-256 | `c9ede3834a7beceb195f105766eed01c3cfbf146d7982bf659d3ff75ef7bafa0` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-20 21:11:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `123ae9e2bc9d4cd191e04fdbf61d64e4` |
| SHA-1 | `8b1a628ea29817678c8b1411bde385460382e9d8` |
| SHA-256 | `c9ede3834a7beceb195f105766eed01c3cfbf146d7982bf659d3ff75ef7bafa0` |
| SHA3-384 | `300b19f761b5defd5ed5c67b2610f847b5ec979dfc8b31ea6825ec83bd65f50e525733a502198ebae9622f5ca73150a0` |
| TLSH | `T183137D6566813C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C19A9CD21971D` |
| SSDEEP | `768:NXRWNGxV09GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:3lxnco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_c9ede383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9ede3834a7beceb195f105766eed01c3cfbf146d7982bf659d3ff75ef7bafa0"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-20 21:11:43"
  condition:
    hash.sha256(0, filesize) == "c9ede3834a7beceb195f105766eed01c3cfbf146d7982bf659d3ff75ef7bafa0"
}
```

### Sample 17: `ae5db9eb1406557f`

| Field | Value |
|---|---|
| SHA-256 | `ae5db9eb1406557f12e2d9b474b2519beba3b6fc6afdb8ded74f41d258ae82cd` |
| Family label | `unknown` |
| File name | `kworkerd-rcu` |
| File type | `elf` |
| First seen | `2026-06-20 21:11:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f2028446e827cbb89976b00df5cff7c` |
| SHA-1 | `2a5860757ce73860559de452e5e9f47b1a3a0867` |
| SHA-256 | `ae5db9eb1406557f12e2d9b474b2519beba3b6fc6afdb8ded74f41d258ae82cd` |
| SHA3-384 | `cdfffa4bfedbffd0301d4776bed9b3d373d4749a60a76acc5c3420087af9bd64a7da027eb3944f8e9fb015f19629cd43` |
| TLSH | `T1D0D312ACE813BD0CED1B07F3E996164B5583D49755758EA2C7228610A6F8E4EA4FC02E` |
| SSDEEP | `3072:PxjzrStHLrAb7hNbAGy6H6FTmRKdi1uywyDR1:5jMHHg6G1aF0KdcuSz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_ae5db9eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae5db9eb1406557f12e2d9b474b2519beba3b6fc6afdb8ded74f41d258ae82cd"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-20 21:11:41"
  condition:
    hash.sha256(0, filesize) == "ae5db9eb1406557f12e2d9b474b2519beba3b6fc6afdb8ded74f41d258ae82cd"
}
```

### Sample 18: `c9b09ab0ba66f76f`

| Field | Value |
|---|---|
| SHA-256 | `c9b09ab0ba66f76f8f4cfb00e34a941672dd84c4b535c3f328cf806d6a45cd9c` |
| Family label | `unknown` |
| File name | `kworkerd-netns-rt` |
| File type | `elf` |
| First seen | `2026-06-20 21:11:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `795adf4f8743adafec502c86f884e620` |
| SHA-1 | `d8f753d37d9b5969f1b0539a92c8b608703343b4` |
| SHA-256 | `c9b09ab0ba66f76f8f4cfb00e34a941672dd84c4b535c3f328cf806d6a45cd9c` |
| SHA3-384 | `7b9a04978700fbdf0b016a444de8a957c9fe30ac1a3548f55947ce13f8770c9476e78db1165b5147a72849c8878daaad` |
| TLSH | `T191D313CEF8169DABFB71D0FD858C0AA47B35863CCBC58B0A56C003E76912297746C5E9` |
| SSDEEP | `3072:6zk6D7aABiA4C02UmmV2cOn8aizwImaV1PB28+F0uvxQT976GgXVr:6zkouABiA0R5OnNusD0uvy76llr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_c9b09ab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9b09ab0ba66f76f8f4cfb00e34a941672dd84c4b535c3f328cf806d6a45cd9c"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-06-20 21:11:40"
  condition:
    hash.sha256(0, filesize) == "c9b09ab0ba66f76f8f4cfb00e34a941672dd84c4b535c3f328cf806d6a45cd9c"
}
```

### Sample 19: `b67542ebf7ea604c`

| Field | Value |
|---|---|
| SHA-256 | `b67542ebf7ea604cd661298d3e8dfb0e49592ea342267a4c1320363cd0afed50` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-20 21:09:36` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `494c35b1e8cf30ba061b5e8427935c02` |
| SHA-1 | `00d39e462c1b4ed7e528cac6c07a97075fe2a9f2` |
| SHA-256 | `b67542ebf7ea604cd661298d3e8dfb0e49592ea342267a4c1320363cd0afed50` |
| SHA3-384 | `3c3cb688853697dccf27a26df3b27cd77d74ff19f6f959f46e0e4f68208340f042002cb7a1f380d657cf74598d0a98cb` |
| TLSH | `T18F3181DA01245A396202EFEE77B32548701DC5EB285BC7A5DC4C0EDD52489CCB265BC9` |
| SSDEEP | `12:UxL6x5B15j69SOnX76UAgcy6z6iiAVKHx659ZMGlr6XX23w3i63/oJNWI6NWf4y2:eI5B1AnAghKjUGA23aNgmcfzQIW5KXVo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_b67542eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b67542ebf7ea604cd661298d3e8dfb0e49592ea342267a4c1320363cd0afed50"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-20 21:09:36"
  condition:
    hash.sha256(0, filesize) == "b67542ebf7ea604cd661298d3e8dfb0e49592ea342267a4c1320363cd0afed50"
}
```

### Sample 20: `d41fd9018d83a127`

| Field | Value |
|---|---|
| SHA-256 | `d41fd9018d83a1275535f8cbe0ee0b8cbfe440eeb0d9a29bc24a75643cf0a102` |
| Family label | `unknown` |
| File name | `kworkerd-irq-bal` |
| File type | `elf` |
| First seen | `2026-06-20 20:51:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45a5f8b3e999bc4953e29c84f1c6fd05` |
| SHA-1 | `450aa19cba5e4012c34539017607522965c0573d` |
| SHA-256 | `d41fd9018d83a1275535f8cbe0ee0b8cbfe440eeb0d9a29bc24a75643cf0a102` |
| SHA3-384 | `264ed0630938c571ae5296d19c613fea38935e6df0dc0e4fc8737eb34d658392c167f8ccecd55b44bad296e4e680525e` |
| TLSH | `T1DF3419A9BC40DB62C6E427BAFB4C429933134F74C3DD3506CD245F2976EB55B0A3A682` |
| SSDEEP | `6144:f1h8ueLcXsnrYFQkrdk9zJfahXW9WIWeswUfCVzIOa:AueLo2rYFQkrdk8XQLb5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_d41fd901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d41fd9018d83a1275535f8cbe0ee0b8cbfe440eeb0d9a29bc24a75643cf0a102"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-20 20:51:04"
  condition:
    hash.sha256(0, filesize) == "d41fd9018d83a1275535f8cbe0ee0b8cbfe440eeb0d9a29bc24a75643cf0a102"
}
```

### Sample 21: `33e1522d870d0d92`

| Field | Value |
|---|---|
| SHA-256 | `33e1522d870d0d929ac0a1733f746c58ba7abc8dcb1e9efc28d4393d4eb5d749` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-06-20 20:50:45` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04ffcb988fb2ba14f4dcbf15299291d6` |
| SHA-1 | `008fcf9fc9bc86f916a727a6649afb3662c516c0` |
| SHA-256 | `33e1522d870d0d929ac0a1733f746c58ba7abc8dcb1e9efc28d4393d4eb5d749` |
| SHA3-384 | `580852ea9138040e7fb3ca9368867e6ae044435c02aeb35c8277ac66b9d4a7c675728993037dd0410f6576273fb752a3` |
| TLSH | `T103337BB3CC366E68D04886B0B4209EB46763F144C2571FBF296ACA799093DACF9453F4` |
| SSDEEP | `768:waVIjRneC4q0hL9w1ECFHZKiTtFlaFoMWpyzChffVBfsGEVyI:waOjQC4dhO1EQKiTtGKMDzChwGqy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_33e1522d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33e1522d870d0d929ac0a1733f746c58ba7abc8dcb1e9efc28d4393d4eb5d749"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:45"
  condition:
    hash.sha256(0, filesize) == "33e1522d870d0d929ac0a1733f746c58ba7abc8dcb1e9efc28d4393d4eb5d749"
}
```

### Sample 22: `d991f08e6d422bca`

| Field | Value |
|---|---|
| SHA-256 | `d991f08e6d422bca943238a276b01aceff5d3f674c33531d6038a59a08c1a9e8` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-20 20:50:45` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `034c0e232e16c97c0164d427330dd75b` |
| SHA-1 | `bc40d879032cdac89e1706ca0aa1491029ed1136` |
| SHA-256 | `d991f08e6d422bca943238a276b01aceff5d3f674c33531d6038a59a08c1a9e8` |
| SHA3-384 | `72e1d4a4cc561a4556438eb69d6fbf37fe450e86ee3cac6ab71f29cddd91a41c7ba51d8495682a701de6b9f60a169f34` |
| TLSH | `T1AF83C506BF650FB7DC6FDD370AA9170535CC650B12A93B367934D828F64B24B4AE38A4` |
| SSDEEP | `1536:YEj3j8qHdM8xIiphtoedEs2PJINjLWTAZz3OVx4L1+Jt:YEbj8WdXoJkHMAq+1Et` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_d991f08e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d991f08e6d422bca943238a276b01aceff5d3f674c33531d6038a59a08c1a9e8"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:45"
  condition:
    hash.sha256(0, filesize) == "d991f08e6d422bca943238a276b01aceff5d3f674c33531d6038a59a08c1a9e8"
}
```

### Sample 23: `7f5f2aaa392cd577`

| Field | Value |
|---|---|
| SHA-256 | `7f5f2aaa392cd5770e6c2dff7d390e15c3e6c774886408e4cfb8b0b65cb31c32` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-20 20:50:43` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0f1ea9f8337212afac81bb51f9c82eb` |
| SHA-1 | `b0877f743594ebff558a254ef149f23f55064426` |
| SHA-256 | `7f5f2aaa392cd5770e6c2dff7d390e15c3e6c774886408e4cfb8b0b65cb31c32` |
| SHA3-384 | `4b3a129a3d1bbc06ec867fdd7159f597fd2cda7df119bdd6e3efcae1b60dcbd24f81ebe93b0f0543b11ae14c37687934` |
| TLSH | `T120533A41BC819617C6D022BBFB6E028D372663A8D2EF3303DE265F11778696B0E77651` |
| TELFHASH | `t11511c0504e4c07ecf750cf48838fa779794632b8ee132ab1de7b994b03075d0a217855` |
| SSDEEP | `1536:97fKQz+kCMLGNM81ysx9SuX2AwHMlml9KahRR:97Lz+Vysx9SuFll1a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_7f5f2aaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f5f2aaa392cd5770e6c2dff7d390e15c3e6c774886408e4cfb8b0b65cb31c32"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:43"
  condition:
    hash.sha256(0, filesize) == "7f5f2aaa392cd5770e6c2dff7d390e15c3e6c774886408e4cfb8b0b65cb31c32"
}
```

### Sample 24: `81ae285ab750dfbd`

| Field | Value |
|---|---|
| SHA-256 | `81ae285ab750dfbd504bea7e8f44e10b7e44dc634ace7dda017bb2de7ff2bd2a` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-06-20 20:50:43` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57a830b11f9d1d7e3f6a4c3b33001931` |
| SHA-1 | `7756e0dcfbbdbefd74ab7cb60ca5a6d591948ad8` |
| SHA-256 | `81ae285ab750dfbd504bea7e8f44e10b7e44dc634ace7dda017bb2de7ff2bd2a` |
| SHA3-384 | `63fdb128601bc7c646dfe1f4db29b58ff61d3f20234e87d77d50c79b019552f831693fd59f786fcacb0a8b4517c68f2a` |
| TLSH | `T1DF633AD7F800DDBDF80BE77B44570509B271A79101830F3A6797B963AC721A91867F86` |
| SSDEEP | `1536:0xOFzRJ94kegqXZqoi8Si7KEFV5lQToeBPH4VRSnguf:0wpxzqXZqo+5y5mToKTguf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_81ae285a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ae285ab750dfbd504bea7e8f44e10b7e44dc634ace7dda017bb2de7ff2bd2a"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:43"
  condition:
    hash.sha256(0, filesize) == "81ae285ab750dfbd504bea7e8f44e10b7e44dc634ace7dda017bb2de7ff2bd2a"
}
```

### Sample 25: `74394ecce3f159b8`

| Field | Value |
|---|---|
| SHA-256 | `74394ecce3f159b8a2ba94104976e18d32e8077c1df0b9f4b471128d96521b1d` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-20 20:50:42` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42c502d1ea99e9acfc395724556aea1b` |
| SHA-1 | `ac113c655221c2c03a26810ca31f083b5149731b` |
| SHA-256 | `74394ecce3f159b8a2ba94104976e18d32e8077c1df0b9f4b471128d96521b1d` |
| SHA3-384 | `608135af4578d0f0ead9cd8a4e6b39774f2d3805b4af4c1262ae16c845bf2b0427c3b3134ff4371c2b6864c47346ba68` |
| TLSH | `T16C533981BC819613C6D012BBFB6E038D372653A8D2EE3307DE269F11378692F0D6B655` |
| SSDEEP | `768:bQM3HGue09+OYIRopSsOpPG/ExcEwQ/NMmT33rxvMGdZm+uuim+01Vzswx7vlaI:p3mu79SPpSJPDwQbTHCGdZpqvEl7vla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_74394ecc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74394ecce3f159b8a2ba94104976e18d32e8077c1df0b9f4b471128d96521b1d"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:42"
  condition:
    hash.sha256(0, filesize) == "74394ecce3f159b8a2ba94104976e18d32e8077c1df0b9f4b471128d96521b1d"
}
```

### Sample 26: `b090e5a3b3c104c4`

| Field | Value |
|---|---|
| SHA-256 | `b090e5a3b3c104c446018af559c074adf42dc10a8c4e34270fa2228a1f2f82c5` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-20 20:50:42` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa96fc2dba74cbd95f6e58f59e304960` |
| SHA-1 | `72c53b03ead5730363e3c13991a582396dadaa90` |
| SHA-256 | `b090e5a3b3c104c446018af559c074adf42dc10a8c4e34270fa2228a1f2f82c5` |
| SHA3-384 | `44156c76f66b48b952a3045b324b32fcd820a5a338fdc788068f8c77d484f01e937f95b6a0b9f97b575127945ffc3231` |
| TLSH | `T1F0E33B46EA414B13C4D62775BAEF424533239B6493DB73069928BFF43F86B9E0E23605` |
| TELFHASH | `t1c2219b326b75512a6aa1cd60dded97b2512847126748bf33df22c0cc251e09ae62bc4f` |
| SSDEEP | `3072:JhkvVURs8Oa5gCxCi0OFcV4x/zvQkvXpioM/9QeO:DkvVas9a5gCxCi0+c+jQkvXvM/9QeO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_b090e5a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b090e5a3b3c104c446018af559c074adf42dc10a8c4e34270fa2228a1f2f82c5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:42"
  condition:
    hash.sha256(0, filesize) == "b090e5a3b3c104c446018af559c074adf42dc10a8c4e34270fa2228a1f2f82c5"
}
```

### Sample 27: `666abe7af5c43351`

| Field | Value |
|---|---|
| SHA-256 | `666abe7af5c43351abba61abe9eda5f99f6b84d7702ee36faefc345eddc54384` |
| Family label | `unknown` |
| File name | `a.sh` |
| File type | `sh` |
| First seen | `2026-06-20 20:50:41` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be7261f4b8536d8a4d7ca92eb249c60e` |
| SHA-1 | `0d3a8d7531556a56b1b3f2367a3fc24acdbb1485` |
| SHA-256 | `666abe7af5c43351abba61abe9eda5f99f6b84d7702ee36faefc345eddc54384` |
| SHA3-384 | `cc067d24dd12292516bbd199d8771ef89825876f672127d9a554fe70a4a5890b958fab53bf589a440f7815a7241d190a` |
| TLSH | `T12AD0C2A4736380DF042AEF58E441689110AB72C822B2D6BDB8165B6E9878D063DA495A` |
| SSDEEP | `3:GRFoLSDFSOdVMsMXuxAjoLSiOOdVv6axAjoLSfIOOdVYgxLoaxAjoLS6fDOdVVEL:SoLW6luSoLxB6aSoLKI+gNoaSoLfmi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_666abe7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "666abe7af5c43351abba61abe9eda5f99f6b84d7702ee36faefc345eddc54384"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-06-20 20:50:41"
  condition:
    hash.sha256(0, filesize) == "666abe7af5c43351abba61abe9eda5f99f6b84d7702ee36faefc345eddc54384"
}
```

### Sample 28: `f9f8567aaa807983`

| Field | Value |
|---|---|
| SHA-256 | `f9f8567aaa807983097deb4b7fb130cc2374ace1fb08a6a825324d892f11c140` |
| Family label | `unknown` |
| File name | `kworkerd-irq-bal` |
| File type | `elf` |
| First seen | `2026-06-20 20:49:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `218e81a644c5b44c5206499baf86ff55` |
| SHA-1 | `88771e27c46608545bd3fb6b091bc74d0f6c5789` |
| SHA-256 | `f9f8567aaa807983097deb4b7fb130cc2374ace1fb08a6a825324d892f11c140` |
| SHA3-384 | `c63a44625ab7334fd993a94bc5e81e914188abe6b4c8fff7c5fad8d450bcad2d1bb1bb1266429f07b641b7fb87926178` |
| TLSH | `T1F6A3123253222C21C124247E4D8916E5872C7B6A7CEB3A830796491AC7E71CF29FFE5D` |
| SSDEEP | `3072:8cujVe+UpCQQ9toPuFvZGdIzFLXYTAkan+TnTW:8Ve+UpCQQWumMFLXmAkanYa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_f9f8567a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9f8567aaa807983097deb4b7fb130cc2374ace1fb08a6a825324d892f11c140"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-20 20:49:34"
  condition:
    hash.sha256(0, filesize) == "f9f8567aaa807983097deb4b7fb130cc2374ace1fb08a6a825324d892f11c140"
}
```

### Sample 29: `5c2d1ffb8d00e3e9`

| Field | Value |
|---|---|
| SHA-256 | `5c2d1ffb8d00e3e93d60dc3294b08ce9afa08962d2658a67694b8f9c477e87d3` |
| Family label | `unknown` |
| File name | `kworkerd-softirq` |
| File type | `elf` |
| First seen | `2026-06-20 20:47:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4edf3bb35c31da2d595497d0bca39eeb` |
| SHA-1 | `ef9bb84bf5dd3942b480068f65d6fc8024a12e9d` |
| SHA-256 | `5c2d1ffb8d00e3e93d60dc3294b08ce9afa08962d2658a67694b8f9c477e87d3` |
| SHA3-384 | `a8e3a7447614968cce9554e3cc050ba6946d2aec07747fbcfaa1024bf8916cf7b2f314b4d6c960af2eea1f082dc6332e` |
| TLSH | `T19CA3122181A8FE50D4FCAE7755CAD0C71F1FC3A0242A36721589AEF3694029B23DD9DA` |
| SSDEEP | `3072:kioGWpBo3D4Guv2xqPYt+qhSZNUcbLGFBzfX:1s84GuvOqPwha/bLGnX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_5c2d1ffb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c2d1ffb8d00e3e93d60dc3294b08ce9afa08962d2658a67694b8f9c477e87d3"
    family = "unknown"
    file_name = "kworkerd-softirq"
    file_type = "elf"
    first_seen = "2026-06-20 20:47:37"
  condition:
    hash.sha256(0, filesize) == "5c2d1ffb8d00e3e93d60dc3294b08ce9afa08962d2658a67694b8f9c477e87d3"
}
```

### Sample 30: `5401b74c9a0d32fe`

| Field | Value |
|---|---|
| SHA-256 | `5401b74c9a0d32febbf9ecbaa6665ab839d66f53a54c06fb4f0ac14207a2c4a5` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-06-20 20:46:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d1013aefc85a0549486356845ad577f` |
| SHA-1 | `6c769de6f0e2c9bc989b47187c80185c9640ca5c` |
| SHA-256 | `5401b74c9a0d32febbf9ecbaa6665ab839d66f53a54c06fb4f0ac14207a2c4a5` |
| SHA3-384 | `65a8444fa1df876ec22543d3f5584dd59b8dd7b78b65ca682e8e0aac83623dde6022c4d7f7375c7eb8f21909ed093228` |
| TLSH | `T1F3437CC4AA83E4F5FC9701751033A73B5A72F4351069DA87C369D83BBC52A11EA2B39C` |
| TELFHASH | `t1ee31d5eb2daa08ecb7c4ac08c35f2e931a36d637067075f445b648a536f29c18479c7a` |
| SSDEEP | `1536:ZyN5z8bAOpvnd02e98v2POtI7iiBDBwJSz0RZ17+v2nzhNKSM:0N5wUOpvnReO2WtKwgz0r1K+nM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_5401b74c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5401b74c9a0d32febbf9ecbaa6665ab839d66f53a54c06fb4f0ac14207a2c4a5"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-20 20:46:43"
  condition:
    hash.sha256(0, filesize) == "5401b74c9a0d32febbf9ecbaa6665ab839d66f53a54c06fb4f0ac14207a2c4a5"
}
```

### Sample 31: `4b45fc7bd3f81203`

| Field | Value |
|---|---|
| SHA-256 | `4b45fc7bd3f81203fb9ff383f45b39dc9bc291437a141610b76cd9f3620ec308` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-06-20 20:45:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f03f5474424a38f56c3a0d7cfdd6586` |
| SHA-1 | `469ce56afa879c7163c52ae09d89d9cc6a339395` |
| SHA-256 | `4b45fc7bd3f81203fb9ff383f45b39dc9bc291437a141610b76cd9f3620ec308` |
| SHA3-384 | `7c0c08068a48e88076c2c6e81a4a46890a3800c29990fc20546d17d4e3093ff086ec930f09f8d22c121c2f5ed1f8be96` |
| TLSH | `T14CB32849FC809B01D5E42A7AFA5D51CD33270BF8E3EE7116DC255F2567CA91B0E3AA02` |
| TELFHASH | `t1f1c08ca2ab2caccdcbc62b0158e6381a29a239402200004072cccdaf4a24b81ac0ec0b` |
| SSDEEP | `3072:0n/W4ocXgOJrklCCQwN3OpiRTLCRn1KtPKzsgcQL6y:07heQs3OpQTLe1wPKzsg5L6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_4b45fc7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b45fc7bd3f81203fb9ff383f45b39dc9bc291437a141610b76cd9f3620ec308"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-06-20 20:45:36"
  condition:
    hash.sha256(0, filesize) == "4b45fc7bd3f81203fb9ff383f45b39dc9bc291437a141610b76cd9f3620ec308"
}
```

### Sample 32: `637cc40d3f134ef6`

| Field | Value |
|---|---|
| SHA-256 | `637cc40d3f134ef600020e513709b4389fe3c169206dcbbe34171b51528a0024` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-06-20 20:45:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3aa4b6c3048d319d7bd246d186b277a` |
| SHA-1 | `17e14e102565bbfe62f5eaf7297c491c5a26c97b` |
| SHA-256 | `637cc40d3f134ef600020e513709b4389fe3c169206dcbbe34171b51528a0024` |
| SHA3-384 | `0de50ef7c274c9dd5db910610023bd7614e5594af95bb76665ebc1ca724a4ca1bddcf8fe85711a58d5a424032b5d9e33` |
| TLSH | `T1B8E2F1A4F14D4202C097907D3EB93F872861636DF248C1DB8AE474A6785DBF02BDD55A` |
| SSDEEP | `768:wdaQJCBHEwTpA1kmtD3gTbjVcK5StFnbcuyD7UpUcs:urmEwTpAymtD3gT/Wnouy82` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_637cc40d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "637cc40d3f134ef600020e513709b4389fe3c169206dcbbe34171b51528a0024"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-20 20:45:35"
  condition:
    hash.sha256(0, filesize) == "637cc40d3f134ef600020e513709b4389fe3c169206dcbbe34171b51528a0024"
}
```

### Sample 33: `4c6c3fb40ded6139`

| Field | Value |
|---|---|
| SHA-256 | `4c6c3fb40ded613933d00a87000b065649322eec736018493bc607ce72c76017` |
| Family label | `ConnectWise` |
| File name | `Adobe_Acrobat_Reader_DC_Updater_Windows_installer_Win11_x86_x64_Win10-Win11_x64.vbs` |
| File type | `vbs` |
| First seen | `2026-06-20 20:41:55` |
| Reporter | `smica83` |
| Tags | `ConnectWise, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `671a415b70981898a6a51d0fd2f9322b` |
| SHA-1 | `9ebe2e5fab3e8c4670f32873572b14ff9fc5927c` |
| SHA-256 | `4c6c3fb40ded613933d00a87000b065649322eec736018493bc607ce72c76017` |
| SHA3-384 | `16be9e4d57119b5d17a0e946c2d703899bf564995c20f88e4e829f41efa007d83509863602c095021d177506cd678610` |
| TLSH | `T14234436E3283D90A6F768E4C429D8BC826F5E64DC5DF69C4C38094B5E7D84D720983BE` |
| SSDEEP | `6144:hDSQ/iWRROPtw3D+dDQtNHPTVMBvQ/8m4bCpgkLhzpw:MQ/RwPtwK1aNHPTVYvQkPOyMTw` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_033_4c6c3fb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6c3fb40ded613933d00a87000b065649322eec736018493bc607ce72c76017"
    family = "ConnectWise"
    file_name = "Adobe_Acrobat_Reader_DC_Updater_Windows_installer_Win11_x86_x64_Win10-Win11_x64.vbs"
    file_type = "vbs"
    first_seen = "2026-06-20 20:41:55"
  condition:
    hash.sha256(0, filesize) == "4c6c3fb40ded613933d00a87000b065649322eec736018493bc607ce72c76017"
}
```

### Sample 34: `76edebe707d788ac`

| Field | Value |
|---|---|
| SHA-256 | `76edebe707d788acf692af96e3276784d0501dd01eb272f08cbfb2e3a1c14d70` |
| Family label | `unknown` |
| File name | `init.sh` |
| File type | `sh` |
| First seen | `2026-06-20 20:41:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `741e9c3c08c78ecad01bb33367bb0a2b` |
| SHA-1 | `ad385165a153e25b87ba9ebb1745e20c088b4d9b` |
| SHA-256 | `76edebe707d788acf692af96e3276784d0501dd01eb272f08cbfb2e3a1c14d70` |
| SHA3-384 | `ab86bdfd087e5334232732eaeb840432df5e4ce854233b3dfb317ed8ce10c7f2cdf7f5678506818ba6f3cb11f83654f5` |
| TLSH | `T1F3529851FD36A634252DC0F5AACA2500F14B513B461C3909B1AFA254BF3CBAC51FD6FA` |
| SSDEEP | `192:eNs/MbhrlqTZgKZPVmhxZPKgjlhtVZDmh5RDKlE3O+SUmTx0P3V6tbG8zesvq32a:ezl6S1LBYRQEZb36tyUgNSA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_76edebe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76edebe707d788acf692af96e3276784d0501dd01eb272f08cbfb2e3a1c14d70"
    family = "unknown"
    file_name = "init.sh"
    file_type = "sh"
    first_seen = "2026-06-20 20:41:38"
  condition:
    hash.sha256(0, filesize) == "76edebe707d788acf692af96e3276784d0501dd01eb272f08cbfb2e3a1c14d70"
}
```

### Sample 35: `c9eadf5f3be0996c`

| Field | Value |
|---|---|
| SHA-256 | `c9eadf5f3be0996c41ad4c42f7bf530b74d8682ac630cea018dd0edefa07d4ea` |
| Family label | `AsyncRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 20:40:48` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, AsyncRAT, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b37fb289ad1e3da62510caf740de1ce` |
| SHA-1 | `0468dca0ebefd05537dfa9a770b7c9e332aa4093` |
| SHA-256 | `c9eadf5f3be0996c41ad4c42f7bf530b74d8682ac630cea018dd0edefa07d4ea` |
| SHA3-384 | `357143b44da3be89935247d6dc5a2256f8b6c0022b0fe37daa925f9b44c2c79927719b9ee9ff790dc0cd233f20c9b375` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18B233D003BF9C12BF27E4F7858F22145867AF2673603D54E2CC4469B5A13BC29A525FE` |
| SSDEEP | `768:kuSEa5TAYOTSWUkC+zmo2qLnrSBHYPrUmIPImXQIJXOBjr0bEDx/wreq0YlAm+dS:kuSEa5TAxv2qrSGrUamXLp2gbEDx+eqt` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_035_c9eadf5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9eadf5f3be0996c41ad4c42f7bf530b74d8682ac630cea018dd0edefa07d4ea"
    family = "AsyncRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 20:40:48"
  condition:
    hash.sha256(0, filesize) == "c9eadf5f3be0996c41ad4c42f7bf530b74d8682ac630cea018dd0edefa07d4ea"
}
```

### Sample 36: `23c8252953a84b97`

| Field | Value |
|---|---|
| SHA-256 | `23c8252953a84b9735a79946efcb1f2b46d565905e2f032380d7c0a5940667d0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 20:35:36` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff9bc56dc6dee34844e2d123d1b438a5` |
| SHA-1 | `db172edb113c479a8d383341994b7baecd710bb5` |
| SHA-256 | `23c8252953a84b9735a79946efcb1f2b46d565905e2f032380d7c0a5940667d0` |
| SHA3-384 | `fd89f93ffba495ff5677fb4dc15e809aa9cfb08d4739a9ab2affba99aaa8616c67d69eb77f33d7c3b65375d73831fdb2` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1131833206F948CD6F59231399A916244E3E3BB6417718F9E0BC06B252E275FFEC39361` |
| SSDEEP | `1572864:7AYyyxBU7rUFpYrHK8o8iLxMtQ6ZMo/STJ6ppJ2FNwW5wF:7fxgkTUc4R/U6pXoQF` |
| ICON-DHASH | `82908e8e8e8e39d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_23c82529
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23c8252953a84b9735a79946efcb1f2b46d565905e2f032380d7c0a5940667d0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 20:35:36"
  condition:
    hash.sha256(0, filesize) == "23c8252953a84b9735a79946efcb1f2b46d565905e2f032380d7c0a5940667d0"
}
```

### Sample 37: `97ab95191daea05b`

| Field | Value |
|---|---|
| SHA-256 | `97ab95191daea05b15024ff2a3a52081a30d4238ba4db4efad5e232f44ab97ab` |
| Family label | `unknown` |
| File name | `kworkerd-scsi` |
| File type | `elf` |
| First seen | `2026-06-20 20:31:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8929456ded01078a2f8d69dbb7beb275` |
| SHA-1 | `5639fe9dda5bd0df766625a88a0086ad0a42aa4f` |
| SHA-256 | `97ab95191daea05b15024ff2a3a52081a30d4238ba4db4efad5e232f44ab97ab` |
| SHA3-384 | `053f0244f75b0f23d5dcea5781d81ad5e7d4945d491a2042898f4636b04d9b1385bf194c7f6deb8c9385131a6c736a6b` |
| TLSH | `T13F344A81319C7EAEE2973E3EC141951A6C0CCF14B886DD2241F9FA472ABB5DB1F3A145` |
| TELFHASH | `t10dc02b60243bd0298c05a509054a25cb34c74adb4b4d320600ac880401007274120138` |
| SSDEEP | `6144:sLSDY0MD2dJT7mJcOKeAQM93/gvkiPrROJ3h:5DY0OcJd6kiP8Vh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_97ab9519
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97ab95191daea05b15024ff2a3a52081a30d4238ba4db4efad5e232f44ab97ab"
    family = "unknown"
    file_name = "kworkerd-scsi"
    file_type = "elf"
    first_seen = "2026-06-20 20:31:37"
  condition:
    hash.sha256(0, filesize) == "97ab95191daea05b15024ff2a3a52081a30d4238ba4db4efad5e232f44ab97ab"
}
```

### Sample 38: `a32e7b6c1bab3264`

| Field | Value |
|---|---|
| SHA-256 | `a32e7b6c1bab32642fa78f78d1891f8ba1ca8c4fa2bb382ea91350c9290a1107` |
| Family label | `unknown` |
| File name | `kworkerd-blkcg` |
| File type | `elf` |
| First seen | `2026-06-20 20:31:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e30a8647ea9499eca8937826ba68949` |
| SHA-1 | `374c01e99cb6771a0be332609c47f46b364bddbe` |
| SHA-256 | `a32e7b6c1bab32642fa78f78d1891f8ba1ca8c4fa2bb382ea91350c9290a1107` |
| SHA3-384 | `57c3f4034d89bf9f0e1090460bbc5b060638d36e51423acea45402cedb6c2ab7b0b31b1bf82ec45e05703d8395207f93` |
| TLSH | `T11D3419A9BC40DB62C6D427BABB5D829933130F74C3DE7506CC241F2976EB55F0A3A582` |
| SSDEEP | `6144:srLotycUVDE1UAeEssM8jaMK3771WChKHYOa:YLoUc3UAeETaMyBYa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_a32e7b6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a32e7b6c1bab32642fa78f78d1891f8ba1ca8c4fa2bb382ea91350c9290a1107"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-20 20:31:24"
  condition:
    hash.sha256(0, filesize) == "a32e7b6c1bab32642fa78f78d1891f8ba1ca8c4fa2bb382ea91350c9290a1107"
}
```

### Sample 39: `585b523ab776fe15`

| Field | Value |
|---|---|
| SHA-256 | `585b523ab776fe15acd2f5ad75c58dfec436a4311c7bbc96758c7968ccb9ace3` |
| Family label | `unknown` |
| File name | `kworkerd-blkcg` |
| File type | `elf` |
| First seen | `2026-06-20 20:29:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2844ddb0b662811e1e3f0b7f41f86d00` |
| SHA-1 | `eac71328c90c3c9d0eecd2fcd0b840d531283d53` |
| SHA-256 | `585b523ab776fe15acd2f5ad75c58dfec436a4311c7bbc96758c7968ccb9ace3` |
| SHA3-384 | `703fc1897f9b9995ad6a40279a560a54a50dbc97ff1148eba6d53cd22afc89cfb40d0e8c70150d0527f8ab89560225bf` |
| TLSH | `T157A3122181B8FE50D4FCAE7755CAD0C71F1FC3A0242A37721589AEF3694029A23DD9DA` |
| TELFHASH | `t1349004034d4140f01134dc045cc51310f34510171c5f1017dc5c1d1f4477d755d11540` |
| SSDEEP | `3072:kioGWpBo3D4Guv2xqPYt+qhSZNUcbLGFBzfB:1s84GuvOqPwha/bLGnB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_585b523a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "585b523ab776fe15acd2f5ad75c58dfec436a4311c7bbc96758c7968ccb9ace3"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-20 20:29:33"
  condition:
    hash.sha256(0, filesize) == "585b523ab776fe15acd2f5ad75c58dfec436a4311c7bbc96758c7968ccb9ace3"
}
```

### Sample 40: `c32470f4960e3267`

| Field | Value |
|---|---|
| SHA-256 | `c32470f4960e3267292b81005f792a1755d7b708aec15d083f205cc978f3a6e3` |
| Family label | `unknown` |
| File name | `kworkerd-writeback` |
| File type | `elf` |
| First seen | `2026-06-20 20:28:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d82d846802dd2b38d95e5438a84fe33` |
| SHA-1 | `8047e7d3932e066927fcc21e3f16290fb3533c48` |
| SHA-256 | `c32470f4960e3267292b81005f792a1755d7b708aec15d083f205cc978f3a6e3` |
| SHA3-384 | `bfe745d32494f8968eb49f0a123bdc30045e2328b9678292a4b58ae117e44543cecfe21b6cf2d2262efadf21df4aa5c8` |
| TLSH | `T1E4645C02FF841E53C5411FB15D7B07B6A3AD48816CA9E03D9E0ABF2506738B9A5DF389` |
| SSDEEP | `6144:Z0KiA/7+k33ZIZrqk3d6HtU0GdVGa4rTX1cCJGu72MWLQdufRYGJOJS:ZJywZa6vOJRjAJS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_c32470f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c32470f4960e3267292b81005f792a1755d7b708aec15d083f205cc978f3a6e3"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-20 20:28:37"
  condition:
    hash.sha256(0, filesize) == "c32470f4960e3267292b81005f792a1755d7b708aec15d083f205cc978f3a6e3"
}
```

### Sample 41: `4bb095a58fff5ed7`

| Field | Value |
|---|---|
| SHA-256 | `4bb095a58fff5ed716654429a5d3e85659f5e88fdb3d70991fe74ea5d86572cf` |
| Family label | `unknown` |
| File name | `kworkerd-writeback` |
| File type | `elf` |
| First seen | `2026-06-20 20:27:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df05c04910a565e6f158d8c430d096fc` |
| SHA-1 | `14d3c6ae2040d6c7ab5d498ecf59008fb1f20eed` |
| SHA-256 | `4bb095a58fff5ed716654429a5d3e85659f5e88fdb3d70991fe74ea5d86572cf` |
| SHA3-384 | `a87b1a986c76649c629d74112c97d3f1658f7906547caeda1be6f506b5ede348a1a231d0042ab0e64b0d25466999fc37` |
| TLSH | `T181B31228E1D70837FDFACDE6A464DD6EB342205FB3D22C611124FBEEB580D9A564070A` |
| SSDEEP | `3072:W5Vg0dAAH8/NasNzeCw+TFH5WuyXHPCia3SxD4hCuqmcNos4u+qgwp4D:WY0dr8/NxzVTWVHPCxSfHmcNoo2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_4bb095a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bb095a58fff5ed716654429a5d3e85659f5e88fdb3d70991fe74ea5d86572cf"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-20 20:27:37"
  condition:
    hash.sha256(0, filesize) == "4bb095a58fff5ed716654429a5d3e85659f5e88fdb3d70991fe74ea5d86572cf"
}
```

### Sample 42: `efc0aee14544530c`

| Field | Value |
|---|---|
| SHA-256 | `efc0aee14544530c3d1b1abcd349d5f5d13069c923ea2c45c3f5a002927f41ce` |
| Family label | `unknown` |
| File name | `kblockd0` |
| File type | `elf` |
| First seen | `2026-06-20 20:17:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17b8aa8e40b438b44cb9818e965583d6` |
| SHA-1 | `6db2746cb5303b0fbc240560235e423d45aa4b57` |
| SHA-256 | `efc0aee14544530c3d1b1abcd349d5f5d13069c923ea2c45c3f5a002927f41ce` |
| SHA3-384 | `a9d18a8ba60b5bcb444928941a88dc1f2ae62412f23642b17e965cfc06bfb4afc8eb09b31a5ddd2cb283d93c3aa2eafc` |
| TLSH | `T178560857B8924943C4E83677B8BE81C432631EBA9B8752566D05FE3C3EBE5D90E38314` |
| TELFHASH | `t168e022a2df0c23cc5be00251868912698ee83abc0380bb998e2d268b1aa34ca7046019` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:sJdK4CeyQgV9c+JsNb+huYzSRsAhi/TQNCqDlPdSzg5E7w:CdKncGADGulPdJEc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_efc0aee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc0aee14544530c3d1b1abcd349d5f5d13069c923ea2c45c3f5a002927f41ce"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:17:30"
  condition:
    hash.sha256(0, filesize) == "efc0aee14544530c3d1b1abcd349d5f5d13069c923ea2c45c3f5a002927f41ce"
}
```

### Sample 43: `0bc4d1eff24c7152`

| Field | Value |
|---|---|
| SHA-256 | `0bc4d1eff24c715260b70eaf0abe32655e99a675a6edd47532aa43f843e6a815` |
| Family label | `unknown` |
| File name | `jbd2_sda1d` |
| File type | `elf` |
| First seen | `2026-06-20 20:17:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdec0ce02002bb8eaae5a2e590b62929` |
| SHA-1 | `db6425c2e9a94986f2cb6eee8b8863255c3596a9` |
| SHA-256 | `0bc4d1eff24c715260b70eaf0abe32655e99a675a6edd47532aa43f843e6a815` |
| SHA3-384 | `a223480b9c0ac76bf0825df766510b4cea21c66515084e520de288002a235d5022230c3cf14ae0f8cce08a5ec48d6544` |
| TLSH | `T1D8560857B9924943C4E83677B8BE81C432631EBA9B8752566D04FE3C3EBE5D90E39304` |
| TELFHASH | `t188e068305f2e334c37d0e08c160b0a1ac9d83bb80350bf8cdf19271f06524cb309942a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:mgC9pHUZDfoCmPzCLqKwI31tWGjE53D+ld1nLUg6y+06g5EQO:mgumfft03D+l3ZEf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_0bc4d1ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc4d1eff24c715260b70eaf0abe32655e99a675a6edd47532aa43f843e6a815"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-06-20 20:17:08"
  condition:
    hash.sha256(0, filesize) == "0bc4d1eff24c715260b70eaf0abe32655e99a675a6edd47532aa43f843e6a815"
}
```

### Sample 44: `33dcdaafec603a3b`

| Field | Value |
|---|---|
| SHA-256 | `33dcdaafec603a3b65796c06235130d6141cdfd45752235bf66b8b17f2f2ecee` |
| Family label | `unknown` |
| File name | `ecryptfsd` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a475439e67975995dbd493b3683aaeb8` |
| SHA-1 | `db506c6f7b4ddcea3ee3afb76c8a910535eebb27` |
| SHA-256 | `33dcdaafec603a3b65796c06235130d6141cdfd45752235bf66b8b17f2f2ecee` |
| SHA3-384 | `2aa6e0744a9a19745378f1b85b9dc50f915ff2691160e32053395ab820fab7adc23c0e597456cf92b342e1cfc01b0b3e` |
| TLSH | `T16C66F809AD843BFAC02C4B7454EACA5622B05D144AF1467626A5FFEDFC762787F0788C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:HrT4rs502bEe2Tl34J6FTs8vsW/ALIqtG7MdHg5Er:H2TlIJ6NUa48Er` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_33dcdaaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33dcdaafec603a3b65796c06235130d6141cdfd45752235bf66b8b17f2f2ecee"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:59"
  condition:
    hash.sha256(0, filesize) == "33dcdaafec603a3b65796c06235130d6141cdfd45752235bf66b8b17f2f2ecee"
}
```

### Sample 45: `e7d800b02d760d90`

| Field | Value |
|---|---|
| SHA-256 | `e7d800b02d760d904093d0490348d225c45fce9e74192278f7ed6ba240f1daf1` |
| Family label | `unknown` |
| File name | `devfreq_wq` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32d32d166fe24c9fc193c34a4dc498ee` |
| SHA-1 | `857ca1663e605404a6c821cf4841869262d0b263` |
| SHA-256 | `e7d800b02d760d904093d0490348d225c45fce9e74192278f7ed6ba240f1daf1` |
| SHA3-384 | `c006e33ecea8157fcbb81b49d70dad14dc8d7cad1bd1d9335e541fda4d7ef19976621aa75fa49efbda536b7b2c772504` |
| TLSH | `T1FF564981FB48A12AD94A0A324CB30B70B3916D85C1F48D6F5709F72F45B26F6A94FED4` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:k29ZrWykQ/HSuiKQgS0VmXn88LjdW0InEjEo:tWN+BSHXdgnfo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_e7d800b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7d800b02d760d904093d0490348d225c45fce9e74192278f7ed6ba240f1daf1"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:54"
  condition:
    hash.sha256(0, filesize) == "e7d800b02d760d904093d0490348d225c45fce9e74192278f7ed6ba240f1daf1"
}
```

### Sample 46: `7b85b11424041c21`

| Field | Value |
|---|---|
| SHA-256 | `7b85b11424041c217a86cb3a197ce0646210592b2f068057b4b883c939634f42` |
| Family label | `unknown` |
| File name | `xfsaild_sda` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:33` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c556ba6251cffa23040ca139c5e686d` |
| SHA-1 | `e946a79dc37a5407c892701d64604be7f2479732` |
| SHA-256 | `7b85b11424041c217a86cb3a197ce0646210592b2f068057b4b883c939634f42` |
| SHA3-384 | `111d9c6c6f9208b99c347a0ad22f2e3931535a9eaa76227ad8dbc748cf9647c5a8daa4ed0fb13b74399265d143f47765` |
| TLSH | `T1BD661712BF89DE5BD2A820358EB7C23833D53D04C1B060369656F71D1EBE2A49D6BDD8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:lZu8QabCQ5930+5XgQNOYyL+6bKv1VHHEt5Ea:eQ3ItGv1VnEjEa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_7b85b114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b85b11424041c217a86cb3a197ce0646210592b2f068057b4b883c939634f42"
    family = "unknown"
    file_name = "xfsaild_sda"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:33"
  condition:
    hash.sha256(0, filesize) == "7b85b11424041c217a86cb3a197ce0646210592b2f068057b4b883c939634f42"
}
```

### Sample 47: `64e27acb5c452aed`

| Field | Value |
|---|---|
| SHA-256 | `64e27acb5c452aed9f67c35e59bf503835d0f7197b70fdd56c4773751380275f` |
| Family label | `unknown` |
| File name | `scsi_tmf_0` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:30` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63e635830daf068b0b34643868c73d70` |
| SHA-1 | `dd41562cc9e1ea4861aa871b239ad638fae31e10` |
| SHA-256 | `64e27acb5c452aed9f67c35e59bf503835d0f7197b70fdd56c4773751380275f` |
| SHA3-384 | `c073f6467debe5a3901a8a9a0ec015f80869ec5bbd3257b0eb1954aff1cb57564f9e14edf436dc5f9853bcc4ee89b219` |
| TLSH | `T16C66F855BDC22B66C1DC03B444FE626662643E454BA5072323E4F7E83A7773CAF5A88C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:zK6sjnZaQPYleWjEeyy1PKmrZZiucOYS4+LbJJg5Ej:ztSZa5ecyyde0yEj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_64e27acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e27acb5c452aed9f67c35e59bf503835d0f7197b70fdd56c4773751380275f"
    family = "unknown"
    file_name = "scsi_tmf_0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:30"
  condition:
    hash.sha256(0, filesize) == "64e27acb5c452aed9f67c35e59bf503835d0f7197b70fdd56c4773751380275f"
}
```

### Sample 48: `2c380252e543a887`

| Field | Value |
|---|---|
| SHA-256 | `2c380252e543a88730da5e5473b0234e0aa7ff2e99f1b0698141a980d08a73b9` |
| Family label | `unknown` |
| File name | `edac_polld` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:29` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `657955600cce799d537fd71ee94840fe` |
| SHA-1 | `8b554c85635a18e7a94174f73dab8bb565ea2a71` |
| SHA-256 | `2c380252e543a88730da5e5473b0234e0aa7ff2e99f1b0698141a980d08a73b9` |
| SHA3-384 | `b075eb5cb9ed2076bbfc7917a1abde2400e50d11cea3efc177717d89f28b06c74495aefa49d9671474d088517cea25db` |
| TLSH | `T18D66F6C1E991D24AC63D6D31EFE6EFD8E26B2F315C885A4AC9C8F73E18B314580B5560` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:SM4wa8PbfpHZ7hTbpkQtn1xBXG57H/xEYApbkakW3bE+8ddgIc4wNRRcRLp6RmHh:SM4wa8PbfD51PzYIMRtamnDjEU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_2c380252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c380252e543a88730da5e5473b0234e0aa7ff2e99f1b0698141a980d08a73b9"
    family = "unknown"
    file_name = "edac_polld"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:29"
  condition:
    hash.sha256(0, filesize) == "2c380252e543a88730da5e5473b0234e0aa7ff2e99f1b0698141a980d08a73b9"
}
```

### Sample 49: `d431302d1890dbe5`

| Field | Value |
|---|---|
| SHA-256 | `d431302d1890dbe576dd8a30fdd3a8aa4de1ec53f692b64553644c4a18470d99` |
| Family label | `unknown` |
| File name | `zswap_shrinkd` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:29` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdb48c6fc6312c8f270f0aaddae2f0b2` |
| SHA-1 | `278d7d0a37e3c0e8596cee86ed1ce43c7fc8156c` |
| SHA-256 | `d431302d1890dbe576dd8a30fdd3a8aa4de1ec53f692b64553644c4a18470d99` |
| SHA3-384 | `cd207ea57b031a812451c68c826ee4500c39cf52077193df0068aa94ffd1cecee9544cdccbf050d139577d80d98733c9` |
| TLSH | `T1DF8533D3A2E034A5FD620D31D3F314360A2B9AB94C1F5A0C6EA5C91A55560FAFE37CC6` |
| SSDEEP | `49152:v4RmuD6VxtJRzGF7MVEpYkjknttMs+8FuGCL+kGolS/m+qcgAa:PP2JYkytMF80GCLVl+qz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_d431302d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d431302d1890dbe576dd8a30fdd3a8aa4de1ec53f692b64553644c4a18470d99"
    family = "unknown"
    file_name = "zswap_shrinkd"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:29"
  condition:
    hash.sha256(0, filesize) == "d431302d1890dbe576dd8a30fdd3a8aa4de1ec53f692b64553644c4a18470d99"
}
```

### Sample 50: `000575e07e3657a7`

| Field | Value |
|---|---|
| SHA-256 | `000575e07e3657a767778a53587fd81b492fe02ea361e98de439e6345653071e` |
| Family label | `unknown` |
| File name | `rcuop_0` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:27` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c06878b4c3ede63b93dc4286003f69a` |
| SHA-1 | `d67bcf43de93f8ef31e307ffea81b0760d5a5171` |
| SHA-256 | `000575e07e3657a767778a53587fd81b492fe02ea361e98de439e6345653071e` |
| SHA3-384 | `21cafd24cc3477c362a057b73e8e4545191097c3093bdf1122c28bc6162355574079d5013505ee9645a9f4938457f6f0` |
| TLSH | `T1188533B0FD769B692B760838F2570825F9CD9FCD347FBE813A4E610A6614D46FA1E008` |
| SSDEEP | `24576:sYU+GC/q/fACb6FFeGC9l+0KW6uFMmyrn1hwQ9srxjsZuSKHksycXLTZs:snzCS/YFel+1jLrn1a2srxe4HkyLTZs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_000575e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "000575e07e3657a767778a53587fd81b492fe02ea361e98de439e6345653071e"
    family = "unknown"
    file_name = "rcuop_0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:27"
  condition:
    hash.sha256(0, filesize) == "000575e07e3657a767778a53587fd81b492fe02ea361e98de439e6345653071e"
}
```

### Sample 51: `602fd1e0a2ff3d5a`

| Field | Value |
|---|---|
| SHA-256 | `602fd1e0a2ff3d5a0ce13f4301e93894c8f30ceeac4f344d371f1641baf08265` |
| Family label | `unknown` |
| File name | `kswapd0` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:26` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa57bd988a40a6183b998d8dc59df81c` |
| SHA-1 | `0ffa78ed21975eaaf45582506245ac3676a4e761` |
| SHA-256 | `602fd1e0a2ff3d5a0ce13f4301e93894c8f30ceeac4f344d371f1641baf08265` |
| SHA3-384 | `3f536564861453f37a069de2418483063665ac37f54b7c8b374cdf84875b448ed402b382ee99455bb50edd5593f54b96` |
| TLSH | `T12A75335E1EF6AA2BC79ECDE1E0212B488AAC7D77C95DBC05C075619385ED68E0F40BC4` |
| SSDEEP | `49152:4hlZLt/OIkRt+VQa5cJeuFttbFt3g74GFMkPK4:YBKRtB1Jbb58XFMWK4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_602fd1e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602fd1e0a2ff3d5a0ce13f4301e93894c8f30ceeac4f344d371f1641baf08265"
    family = "unknown"
    file_name = "kswapd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:26"
  condition:
    hash.sha256(0, filesize) == "602fd1e0a2ff3d5a0ce13f4301e93894c8f30ceeac4f344d371f1641baf08265"
}
```

### Sample 52: `d2676ac0a5290da1`

| Field | Value |
|---|---|
| SHA-256 | `d2676ac0a5290da1be5f312e7aaf992849c1a2c9e5bccb80b59a655de68f655b` |
| Family label | `unknown` |
| File name | `kworker_u8` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:25` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f782ccd05744d323c7bbedee70ba478` |
| SHA-1 | `42a2cf2d1b2ca43d887290849bb8d95ef7b72dfc` |
| SHA-256 | `d2676ac0a5290da1be5f312e7aaf992849c1a2c9e5bccb80b59a655de68f655b` |
| SHA3-384 | `a08fc24d167dd8a08e4d632f3e0448e0c98fa2423fc82262eafe5d40fec476625581bc86938227ea2efc3f3885669344` |
| TLSH | `T1FD9533BD426856C5F34FD492E4490B8ED0F8271520AF0C7B3A74541963FEDA5CAA8AFC` |
| SSDEEP | `24576:mZqkdFbKSeVSuJtJZufCEoawL6d/5OGDGWSQha+Yf8DO1ERiBfp0y/Tj1lERRl0W:IqWsaaQwL6dBlaWSQ36hh1lERReA6rOt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_d2676ac0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2676ac0a5290da1be5f312e7aaf992849c1a2c9e5bccb80b59a655de68f655b"
    family = "unknown"
    file_name = "kworker_u8"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:25"
  condition:
    hash.sha256(0, filesize) == "d2676ac0a5290da1be5f312e7aaf992849c1a2c9e5bccb80b59a655de68f655b"
}
```

### Sample 53: `7cc605b5fffa1478`

| Field | Value |
|---|---|
| SHA-256 | `7cc605b5fffa1478a286c2479f7c6f947fbf1ddf44bbf72f3028b4d62bb08dcb` |
| Family label | `unknown` |
| File name | `ksoftirqd0` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:24` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6132000f7c4750ffff67cb08be88a119` |
| SHA-1 | `3600f4818a91f82a78ecd12122a266ef73039a0e` |
| SHA-256 | `7cc605b5fffa1478a286c2479f7c6f947fbf1ddf44bbf72f3028b4d62bb08dcb` |
| SHA3-384 | `bd9ba966e7e580872ea4da6ea34c7cb0bd7d3cb3c06f1549210a9485825cad37dde2db1edf956ca60e967850fd7da143` |
| TLSH | `T12885330681A43749C6F36C5BA51B4AB6ABDF42037C48305F67D98D5BF8F708AE1904BB` |
| TELFHASH | `t199b001264083b5e5128cae9b4986ae6942626e396192345c380ad39691572ab29111d2` |
| SSDEEP | `49152:zaQ4vaApkIKQkOLAba4KvkLp1IzDMnBTOyvcyDBEezZH//Uy:zwFKQkHbJKFagAJBvzZH//N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_7cc605b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cc605b5fffa1478a286c2479f7c6f947fbf1ddf44bbf72f3028b4d62bb08dcb"
    family = "unknown"
    file_name = "ksoftirqd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:24"
  condition:
    hash.sha256(0, filesize) == "7cc605b5fffa1478a286c2479f7c6f947fbf1ddf44bbf72f3028b4d62bb08dcb"
}
```

### Sample 54: `ed655d6bbc931506`

| Field | Value |
|---|---|
| SHA-256 | `ed655d6bbc9315067360982455b4d14d5ef0c5fdf7ead51550bac30e25414afa` |
| Family label | `unknown` |
| File name | `kblockd0` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:24` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dea7147a32a1c00225289db907a0c3c9` |
| SHA-1 | `468501f0e7faadc812dfecc7aad2d76552daf2a1` |
| SHA-256 | `ed655d6bbc9315067360982455b4d14d5ef0c5fdf7ead51550bac30e25414afa` |
| SHA3-384 | `aa5dc47a397bee39069193d8d4123a42009633389ce994fcba56ec21be1d5ea49eb9490ffcff42346b438a979084bf5d` |
| TLSH | `T1308533D0AA9E0C5F6B1B13353EE64F4F1BE8B57812313DACB6A6742A24F971D2C51708` |
| TELFHASH | `t14990027601345094322d464e2206d33a1660248d3b1410111750158493d458017ac482` |
| SSDEEP | `24576:sDkzFkb2pjkvsYxvtP3Xj3XRTffGBCyEs7IYeBWRP60P8HxCznUJR:PzFG4MDtr9fGB3ILBMEUznq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_ed655d6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed655d6bbc9315067360982455b4d14d5ef0c5fdf7ead51550bac30e25414afa"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:24"
  condition:
    hash.sha256(0, filesize) == "ed655d6bbc9315067360982455b4d14d5ef0c5fdf7ead51550bac30e25414afa"
}
```

### Sample 55: `97c458bad070c330`

| Field | Value |
|---|---|
| SHA-256 | `97c458bad070c33011bd4e1500c208e72ee5c376e6f92dc42e81b676fef6dac8` |
| Family label | `unknown` |
| File name | `jbd2_sda1d` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:23` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c0db6cde9e15c8d19ee2ae0bf26ac29` |
| SHA-1 | `51572c99fab069b9472334e3e029ea6b37f9786e` |
| SHA-256 | `97c458bad070c33011bd4e1500c208e72ee5c376e6f92dc42e81b676fef6dac8` |
| SHA3-384 | `fb11f93aaf48db96b33d393ada7f980086631472870ee4609d1943bdb54a2a9b5562302ab169a5d99980d3f9d959bc2d` |
| TLSH | `T17785338746CDCBB7642A7DD8D384BA2409554AFD330A54D61731426FFAAD28330F6AF2` |
| SSDEEP | `24576:agVKVekxuNpsGz9eGXn46SWhx+l38iORFF3P5zCA1dMX21xJ/xKwG+lmq0:agYbYNpzz9H9x+lsNPVCoP1xJjG+lmq0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_97c458ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c458bad070c33011bd4e1500c208e72ee5c376e6f92dc42e81b676fef6dac8"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:23"
  condition:
    hash.sha256(0, filesize) == "97c458bad070c33011bd4e1500c208e72ee5c376e6f92dc42e81b676fef6dac8"
}
```

### Sample 56: `39f268023db21296`

| Field | Value |
|---|---|
| SHA-256 | `39f268023db21296dfa4a259791d3d5bd559e29dfa588469ff5fa170b7c05f19` |
| Family label | `unknown` |
| File name | `ecryptfsd` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:22` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51a919ca6bffcff7c963b3e020fcd728` |
| SHA-1 | `a56d202bf241639adc20c1e2d26955476f5c980d` |
| SHA-256 | `39f268023db21296dfa4a259791d3d5bd559e29dfa588469ff5fa170b7c05f19` |
| SHA3-384 | `2a8411b06ed84241d0ccdbfd54b51f4d1e6f3f82bce5cf078b280c9987e57080aba8872005e3adbf16982cae8dc5d7f2` |
| TLSH | `T1B38533CDE77A22BADD76DF3EA756EEC003CE2190D220254A1C5B5BCA49573F2361192C` |
| SSDEEP | `49152:YqbaBYWj/LFWqFZMGYctibhcRINleOs+Dwj:YqyAHGYcc0INUP/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_39f26802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39f268023db21296dfa4a259791d3d5bd559e29dfa588469ff5fa170b7c05f19"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:22"
  condition:
    hash.sha256(0, filesize) == "39f268023db21296dfa4a259791d3d5bd559e29dfa588469ff5fa170b7c05f19"
}
```

### Sample 57: `5cf721b03d29a2e4`

| Field | Value |
|---|---|
| SHA-256 | `5cf721b03d29a2e45a8d9a917d86e89dc8ecd6000fd6d3a0398949421d20618a` |
| Family label | `unknown` |
| File name | `devfreq_wq` |
| File type | `elf` |
| First seen | `2026-06-20 20:16:22` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `110828e98e76a39270bd967795901e4b` |
| SHA-1 | `60b16474942b2eaf9adbd433e5fa01f2461cec12` |
| SHA-256 | `5cf721b03d29a2e45a8d9a917d86e89dc8ecd6000fd6d3a0398949421d20618a` |
| SHA3-384 | `49503f9dd98b0ab0386540392f0bcce3a75a0d3d3e01a0ca87c623c2a7a4fe7dd5b312625e510bfb62d384364a478bde` |
| TLSH | `T1147533BF73478D938F7209FD1ADE75615A1B940F35F6E99344ADF24C08632029AA07CA` |
| SSDEEP | `49152:kRcQHufzqak1OFrswhfEz3ruyIU2xK7uc374pkLc96:k2cchnBXEHLni6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_5cf721b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cf721b03d29a2e45a8d9a917d86e89dc8ecd6000fd6d3a0398949421d20618a"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:22"
  condition:
    hash.sha256(0, filesize) == "5cf721b03d29a2e45a8d9a917d86e89dc8ecd6000fd6d3a0398949421d20618a"
}
```

### Sample 58: `ccc32204d9b5248e`

| Field | Value |
|---|---|
| SHA-256 | `ccc32204d9b5248ee3971fad33c3becdc5c5d77fda668517203fed473ba8c748` |
| Family label | `unknown` |
| File name | `Setup.zip` |
| File type | `zip` |
| First seen | `2026-06-20 20:12:42` |
| Reporter | `Kejult` |
| Tags | `exe, stealc, stealer, vidar, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `056a9958447a0a43f5ebe86bdecf8bc9` |
| SHA-1 | `e78843eb25897f013927c20dfeaf0303d5e12d10` |
| SHA-256 | `ccc32204d9b5248ee3971fad33c3becdc5c5d77fda668517203fed473ba8c748` |
| SHA3-384 | `1dacc252e1d132f434f99a14f85fae76adaff64aba587dc30bd6522932817f82dd8e5b588ccc1eb3246e6cde37bee305` |
| TLSH | `T175C52218978BE5FAC19D4170621F8BAF7AB1458E16A1830BD3268C7E2C93FC57F61E11` |
| SSDEEP | `49152:rsScfTA1dcPnwEV6uy/hW0otqBApg9ZGJ1KnUBIdKSMMNjxCmnI:wu1CPmpWlqBcg90J8nQI6MM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_ccc32204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccc32204d9b5248ee3971fad33c3becdc5c5d77fda668517203fed473ba8c748"
    family = "unknown"
    file_name = "Setup.zip"
    file_type = "zip"
    first_seen = "2026-06-20 20:12:42"
  condition:
    hash.sha256(0, filesize) == "ccc32204d9b5248ee3971fad33c3becdc5c5d77fda668517203fed473ba8c748"
}
```

### Sample 59: `977d720443bbac54`

| Field | Value |
|---|---|
| SHA-256 | `977d720443bbac5473d10ca314861eec8a6bf050b2be56485bc8d9c4766a4c7c` |
| Family label | `unknown` |
| File name | `obfusticate me captian.zip` |
| File type | `zip` |
| First seen | `2026-06-20 20:11:11` |
| Reporter | `smica83` |
| Tags | `tirepatch, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81b56755404f0b833b433f578ce5c681` |
| SHA-1 | `9a5d131593d4e1ebfcc0cd47687d14ebda831866` |
| SHA-256 | `977d720443bbac5473d10ca314861eec8a6bf050b2be56485bc8d9c4766a4c7c` |
| SHA3-384 | `01c6015091181e7a257c0e22243e33f6b3e2259f4c66e8ce5502a3e62011be4ee31cbdcf94477af85658f09fd59f2926` |
| TLSH | `T101C312E0E487BB0BCCA6DB3576634F61A431793864462BA55ECFF296E091120C46F22D` |
| SSDEEP | `3072:lXHTxcBi+gSxQ2eeO6H6v739k37sSBz+yW+:lXtcB7xQKav7tsoSN+Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_977d7204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "977d720443bbac5473d10ca314861eec8a6bf050b2be56485bc8d9c4766a4c7c"
    family = "unknown"
    file_name = "obfusticate me captian.zip"
    file_type = "zip"
    first_seen = "2026-06-20 20:11:11"
  condition:
    hash.sha256(0, filesize) == "977d720443bbac5473d10ca314861eec8a6bf050b2be56485bc8d9c4766a4c7c"
}
```

### Sample 60: `7931ba55069255c1`

| Field | Value |
|---|---|
| SHA-256 | `7931ba55069255c1392a01a20633d0d4cff9afb6b029096ef421d2798ca61e5f` |
| Family label | `unknown` |
| File name | `bioset0` |
| File type | `elf` |
| First seen | `2026-06-20 20:10:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `305f4065a8522f1e16574501507a2c1b` |
| SHA-1 | `49410bc117c18a538504b063d91f590cdf7eec92` |
| SHA-256 | `7931ba55069255c1392a01a20633d0d4cff9afb6b029096ef421d2798ca61e5f` |
| SHA3-384 | `97af43c6fbec6f8f1411a4f9a023bc4cb81bd7d5880e9a840c9c55806ae45dae45b0b660459089ab8c0db5ac9f256054` |
| TLSH | `T1DD560857B8D24992C4E83637B8BE80C433635EFA9B8656566D05FE383EBE1D90E34314` |
| TELFHASH | `t117e092556e0e23cd6fe04665468c42a88de93afc03506b988e3e6a5a09928c67086c15` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:TmRgv/hgXC1xZyGMIJYm0GEcBBj7CD4aK2OZ23g5EE:iQ3PPByK2OZjEE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_7931ba55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7931ba55069255c1392a01a20633d0d4cff9afb6b029096ef421d2798ca61e5f"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-06-20 20:10:57"
  condition:
    hash.sha256(0, filesize) == "7931ba55069255c1392a01a20633d0d4cff9afb6b029096ef421d2798ca61e5f"
}
```

### Sample 61: `531518f1b8c7d743`

| Field | Value |
|---|---|
| SHA-256 | `531518f1b8c7d743defda272598e38d65f902f89eb152b0881add72aaf5c2e08` |
| Family label | `unknown` |
| File name | `cfg80211d` |
| File type | `elf` |
| First seen | `2026-06-20 20:10:43` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c73ef7a2810a8c499b1ef4f6ead5b26d` |
| SHA-1 | `5e736f5b8069d650ac7c61c02888dc0200007b86` |
| SHA-256 | `531518f1b8c7d743defda272598e38d65f902f89eb152b0881add72aaf5c2e08` |
| SHA3-384 | `2449f935f4ffa5b0b0951b2d1c9d35aff80fc5efacc74fe0ee0caef7e27d0bc68027143660e0171b47ab2077f5f6fd32` |
| TLSH | `T194567C0EFD24CFB5C6A003B649B812981371AD026FC74B03A239F77CBDB6694DE46695` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:IjF2jHDAjjzBTcU3bwZuxxYYupigw+8p15uwQAg5Ev:tjmjzBTcrXBJEv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_531518f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "531518f1b8c7d743defda272598e38d65f902f89eb152b0881add72aaf5c2e08"
    family = "unknown"
    file_name = "cfg80211d"
    file_type = "elf"
    first_seen = "2026-06-20 20:10:43"
  condition:
    hash.sha256(0, filesize) == "531518f1b8c7d743defda272598e38d65f902f89eb152b0881add72aaf5c2e08"
}
```

### Sample 62: `41541d2b0efad921`

| Field | Value |
|---|---|
| SHA-256 | `41541d2b0efad921142ff74dae952e803c0cca19e8cc1df0b673b1ffb92162e6` |
| Family label | `unknown` |
| File name | `bioset0` |
| File type | `elf` |
| First seen | `2026-06-20 20:10:40` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2df13bae0b18d7701b686d4ed6be3d93` |
| SHA-1 | `1ec1db742f3fcee4bec4b8540342ea35c4e6e7d2` |
| SHA-256 | `41541d2b0efad921142ff74dae952e803c0cca19e8cc1df0b673b1ffb92162e6` |
| SHA3-384 | `1e2f2ed6c400c9c365ca3fe2bee68a849d7541fe030440c5520d691609b3bc168ec8c129ec4a311211015c310d802e2b` |
| TLSH | `T16B8533A342B7CAA86A5770373945ED853EBBC045DD990738C7F8222588E381F6B7174B` |
| SSDEEP | `24576:mrVJhAb1GBBqGVyOndoN5gWniUktR/73dH+0qZexILfh4lsyOxcrAm9HnVTwcwwM:mhYb1GxV1ndwFktRT3dejkxvhVRuUDs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_41541d2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41541d2b0efad921142ff74dae952e803c0cca19e8cc1df0b673b1ffb92162e6"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-06-20 20:10:40"
  condition:
    hash.sha256(0, filesize) == "41541d2b0efad921142ff74dae952e803c0cca19e8cc1df0b673b1ffb92162e6"
}
```

### Sample 63: `d0b4aa152d85c274`

| Field | Value |
|---|---|
| SHA-256 | `d0b4aa152d85c274ef213eedde09eaf75dcdcf4d4ef026a889d846f357d4c6d6` |
| Family label | `unknown` |
| File name | `Axel.exe` |
| File type | `exe` |
| First seen | `2026-06-20 20:10:32` |
| Reporter | `Kejult` |
| Tags | `exe, malicious, VMProtect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f57de1990fcbef3023edcf79897c14d` |
| SHA-256 | `d0b4aa152d85c274ef213eedde09eaf75dcdcf4d4ef026a889d846f357d4c6d6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_d0b4aa15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0b4aa152d85c274ef213eedde09eaf75dcdcf4d4ef026a889d846f357d4c6d6"
    family = "unknown"
    file_name = "Axel.exe"
    file_type = "exe"
    first_seen = "2026-06-20 20:10:32"
  condition:
    hash.sha256(0, filesize) == "d0b4aa152d85c274ef213eedde09eaf75dcdcf4d4ef026a889d846f357d4c6d6"
}
```

### Sample 64: `ad20b5dd23ef403b`

| Field | Value |
|---|---|
| SHA-256 | `ad20b5dd23ef403b0f39c81ad354aa283409a43587ce90107ca8b6a0800bebc6` |
| Family label | `unknown` |
| File name | `obfusticate me captian 2.txt` |
| File type | `unknown` |
| First seen | `2026-06-20 20:09:07` |
| Reporter | `smica83` |
| Tags | `tirepatch` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8693695a2c3227deeb72e52daff795f1` |
| SHA-256 | `ad20b5dd23ef403b0f39c81ad354aa283409a43587ce90107ca8b6a0800bebc6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_ad20b5dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad20b5dd23ef403b0f39c81ad354aa283409a43587ce90107ca8b6a0800bebc6"
    family = "unknown"
    file_name = "obfusticate me captian 2.txt"
    file_type = "unknown"
    first_seen = "2026-06-20 20:09:07"
  condition:
    hash.sha256(0, filesize) == "ad20b5dd23ef403b0f39c81ad354aa283409a43587ce90107ca8b6a0800bebc6"
}
```

### Sample 65: `dabdb9d1e9ef6ea0`

| Field | Value |
|---|---|
| SHA-256 | `dabdb9d1e9ef6ea07d8dd631461d4074d99030a59ae9b6746b750a51ddb9cdd3` |
| Family label | `unknown` |
| File name | `obfusticate me captian.txt` |
| File type | `unknown` |
| First seen | `2026-06-20 20:08:50` |
| Reporter | `smica83` |
| Tags | `tirepatch` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ebb687751000f685513045dbcce2717` |
| SHA-256 | `dabdb9d1e9ef6ea07d8dd631461d4074d99030a59ae9b6746b750a51ddb9cdd3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_dabdb9d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dabdb9d1e9ef6ea07d8dd631461d4074d99030a59ae9b6746b750a51ddb9cdd3"
    family = "unknown"
    file_name = "obfusticate me captian.txt"
    file_type = "unknown"
    first_seen = "2026-06-20 20:08:50"
  condition:
    hash.sha256(0, filesize) == "dabdb9d1e9ef6ea07d8dd631461d4074d99030a59ae9b6746b750a51ddb9cdd3"
}
```

### Sample 66: `1a16a08151ad1e69`

| Field | Value |
|---|---|
| SHA-256 | `1a16a08151ad1e698f53d70d36c0e5dafd9c2bbc3bd2710e5904f54b91aae128` |
| Family label | `unknown` |
| File name | `grok.txt.lnk` |
| File type | `lnk` |
| First seen | `2026-06-20 20:04:20` |
| Reporter | `smica83` |
| Tags | `lnk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc2b214604bbb67b930e86de641d50fa` |
| SHA-1 | `43c4811b6c97191f358de49f2b639fcb547b145e` |
| SHA-256 | `1a16a08151ad1e698f53d70d36c0e5dafd9c2bbc3bd2710e5904f54b91aae128` |
| SHA3-384 | `f434f4306b8f71dab4211320dc8964e977f5c462d2b61d1d8db09e1281622bfdcaffe08ce5c52359293378db783923e8` |
| TLSH | `T1F511C0041E6A0328E3F2CD3B849BA32187327806FA328F1A01D186CC6858641FC25F2F` |
| SSDEEP | `24:87WJd67orApx+/FqH3hWkzZpS+/WrabS8c:8OS5QqxW+pSja2v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_1a16a081
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a16a08151ad1e698f53d70d36c0e5dafd9c2bbc3bd2710e5904f54b91aae128"
    family = "unknown"
    file_name = "grok.txt.lnk"
    file_type = "lnk"
    first_seen = "2026-06-20 20:04:20"
  condition:
    hash.sha256(0, filesize) == "1a16a08151ad1e698f53d70d36c0e5dafd9c2bbc3bd2710e5904f54b91aae128"
}
```

### Sample 67: `06de9c0bc74686e8`

| Field | Value |
|---|---|
| SHA-256 | `06de9c0bc74686e8c244213d37cc4c7463a73ec3d86219e671b543fe3d8b2f97` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-20 20:03:49` |
| Reporter | `Kejult` |
| Tags | `exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `404e02760d2368b109f7da83afa25e3c` |
| SHA-256 | `06de9c0bc74686e8c244213d37cc4c7463a73ec3d86219e671b543fe3d8b2f97` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_06de9c0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06de9c0bc74686e8c244213d37cc4c7463a73ec3d86219e671b543fe3d8b2f97"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-20 20:03:49"
  condition:
    hash.sha256(0, filesize) == "06de9c0bc74686e8c244213d37cc4c7463a73ec3d86219e671b543fe3d8b2f97"
}
```

### Sample 68: `027531689ffd282c`

| Field | Value |
|---|---|
| SHA-256 | `027531689ffd282ce3e8b3dd6c68acfe8ec2466ed7e1354907b1983f0678c9d6` |
| Family label | `unknown` |
| File name | `WeTransfer_Setup.msi` |
| File type | `unknown` |
| First seen | `2026-06-20 20:02:37` |
| Reporter | `smica83` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f86010491e50012afbd67a1d0dcff996` |
| SHA-1 | `e061c2e95b92a6ea44f215b5f8c5e45af8b66d98` |
| SHA-256 | `027531689ffd282ce3e8b3dd6c68acfe8ec2466ed7e1354907b1983f0678c9d6` |
| SHA3-384 | `e30030651036cbb12d787468838fc1d618a8cd1a37f93b08ebe8eef1db8285c72c2a1b9c31847db3d430b06e29217d31` |
| TLSH | `T16893D04E3B04D321C9011335862FD7D49F67CD1D5EA662AFA2DEB24C5DB28C497A39E0` |
| SSDEEP | `1536:DyWCZSaGlYccV6Pd4lE9laI0uFdj+O/bl0gdh/F3WUJ0:mWg2YccV6l2EaIxt+2blphEh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_02753168
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "027531689ffd282ce3e8b3dd6c68acfe8ec2466ed7e1354907b1983f0678c9d6"
    family = "unknown"
    file_name = "WeTransfer_Setup.msi"
    file_type = "unknown"
    first_seen = "2026-06-20 20:02:37"
  condition:
    hash.sha256(0, filesize) == "027531689ffd282ce3e8b3dd6c68acfe8ec2466ed7e1354907b1983f0678c9d6"
}
```

### Sample 69: `a78dfed1650aef00`

| Field | Value |
|---|---|
| SHA-256 | `a78dfed1650aef00f19f9b86d529d42500cb2202923169692a789bb7f3bb402b` |
| Family label | `unknown` |
| File name | `Void-Loader.exe` |
| File type | `exe` |
| First seen | `2026-06-20 19:55:14` |
| Reporter | `Kejult` |
| Tags | `exe, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `062a5e59925595038bb7522dc3d16250` |
| SHA-256 | `a78dfed1650aef00f19f9b86d529d42500cb2202923169692a789bb7f3bb402b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_a78dfed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a78dfed1650aef00f19f9b86d529d42500cb2202923169692a789bb7f3bb402b"
    family = "unknown"
    file_name = "Void-Loader.exe"
    file_type = "exe"
    first_seen = "2026-06-20 19:55:14"
  condition:
    hash.sha256(0, filesize) == "a78dfed1650aef00f19f9b86d529d42500cb2202923169692a789bb7f3bb402b"
}
```

### Sample 70: `79f2856beb38aebc`

| Field | Value |
|---|---|
| SHA-256 | `79f2856beb38aebc676db11193bef2912299b4ebc21da484e80e36024c3b377e` |
| Family label | `unknown` |
| File name | `tftp.sh` |
| File type | `sh` |
| First seen | `2026-06-20 19:55:05` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e1429968a654fbffae2c19838d1b86` |
| SHA-1 | `ed55960eebafb7a768b84fb747a9436c1bb4b388` |
| SHA-256 | `79f2856beb38aebc676db11193bef2912299b4ebc21da484e80e36024c3b377e` |
| SHA3-384 | `ef452290cca42ae62c6fc7de0512e293fd4a7e878b3c0e014c7023abe2977941f1decfb9576dcf059864ca2c7c447fdf` |
| TLSH | `T1F42153D423A05BF20FD494456A138CFD799F4CFB2F1399E41D2804E2AB60686FC342BA` |
| SSDEEP | `24:xBFl8UMBQOBsV1B011XABOKasB6N6mBcTBwsBnmYB+V/BYWBykAWLBYdBM9AB7y:HFWUAQusVL0110OFgg62cNwgmsOJYGyc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_79f2856b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f2856beb38aebc676db11193bef2912299b4ebc21da484e80e36024c3b377e"
    family = "unknown"
    file_name = "tftp.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:55:05"
  condition:
    hash.sha256(0, filesize) == "79f2856beb38aebc676db11193bef2912299b4ebc21da484e80e36024c3b377e"
}
```

### Sample 71: `fa84bfb56f24194e`

| Field | Value |
|---|---|
| SHA-256 | `fa84bfb56f24194e953a3b800aafe918e99ce2d00d102049ab1f4b973a9f508d` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-06-20 19:55:05` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eae25426745a4910cf11a0de00caabf7` |
| SHA-1 | `c093fbf3e9d43143b2e8a68a2ef4078d6b410227` |
| SHA-256 | `fa84bfb56f24194e953a3b800aafe918e99ce2d00d102049ab1f4b973a9f508d` |
| SHA3-384 | `a2731ae1fc52ea8f5a1f389ad57b5580a950ab7de4973887f34ece4833212879aaf33292820f54cf3e853b591e4098d7` |
| TLSH | `T13F214BC912A067F38ED8C94039539CADB06D49D77A078AEC284C0AF36E52B96FC1CF55` |
| SSDEEP | `24:sB5gHBqV5vFBRqBC1RBgBKBdTTqBkBnIB+RBEf3BykIBUBM93BGSN:gGhqd7kC1nEadv6I8WEyfYOxRN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_fa84bfb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa84bfb56f24194e953a3b800aafe918e99ce2d00d102049ab1f4b973a9f508d"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:55:05"
  condition:
    hash.sha256(0, filesize) == "fa84bfb56f24194e953a3b800aafe918e99ce2d00d102049ab1f4b973a9f508d"
}
```

### Sample 72: `f9e57e757b896dea`

| Field | Value |
|---|---|
| SHA-256 | `f9e57e757b896deab77b71e725055453328fffb613b59c130ce90eb14e0befc7` |
| Family label | `unknown` |
| File name | `ftpget.sh` |
| File type | `sh` |
| First seen | `2026-06-20 19:54:59` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83849dc3972faa9fad3ec8451e06eba8` |
| SHA-1 | `fec747af46181cce7f221ef000bfa6b7b7156b1d` |
| SHA-256 | `f9e57e757b896deab77b71e725055453328fffb613b59c130ce90eb14e0befc7` |
| SHA3-384 | `13f63264224f5624c7917e1eccafd20c5a0507192dce79484011f0498f7f8ee38f38178c186a0fb2e9eacf5e3c4d9e3f` |
| TLSH | `T1B92146C432A077F25FDEF45A2A1B58EF21AD58D72F039CD8181C44E1AF50BC6EC246A6` |
| SSDEEP | `24:fsB58d8BqVdEFBUdNqBC11dmB0dvCBdTWd9qBydJ+BSdsOEBKdHEBCdkB4b/diBS:fgSdQydE7UdIC11d20dvCdCd96ydJ+Sj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_f9e57e75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9e57e757b896deab77b71e725055453328fffb613b59c130ce90eb14e0befc7"
    family = "unknown"
    file_name = "ftpget.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:54:59"
  condition:
    hash.sha256(0, filesize) == "f9e57e757b896deab77b71e725055453328fffb613b59c130ce90eb14e0befc7"
}
```

### Sample 73: `673337ea6fb0eba1`

| Field | Value |
|---|---|
| SHA-256 | `673337ea6fb0eba12c2e7abe1447878e7f9ee63dad296aa8ed47578bb0c1f039` |
| Family label | `unknown` |
| File name | `curl.sh` |
| File type | `sh` |
| First seen | `2026-06-20 19:54:58` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac8c364e24688a56497b491c4d7a1f95` |
| SHA-1 | `975a57af4de7634a6fa149b651603865b356e97d` |
| SHA-256 | `673337ea6fb0eba12c2e7abe1447878e7f9ee63dad296aa8ed47578bb0c1f039` |
| SHA3-384 | `6f561f9cf05c699e67f6d27430fc5fe97581b982d5a1aeb501aff7ef3d66091429b324cba71f34324d5abfa99a282fe4` |
| TLSH | `T1F5213AC812A067F38BD8D940B96399EDB06D04D77E1798E4A4084AE36E563C6FC1C366` |
| SSDEEP | `24:VB59HBqg5vFByqBC1IBdBnBdTcqBVBNB4bGBvf3ByClBNBMW3BpuBW:rThzd7jC18DBdo6rTNxyCT3x8g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_673337ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "673337ea6fb0eba12c2e7abe1447878e7f9ee63dad296aa8ed47578bb0c1f039"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:54:58"
  condition:
    hash.sha256(0, filesize) == "673337ea6fb0eba12c2e7abe1447878e7f9ee63dad296aa8ed47578bb0c1f039"
}
```

### Sample 74: `2e1369bc8343db24`

| Field | Value |
|---|---|
| SHA-256 | `2e1369bc8343db24f34e4a309ba1a0efbd181150f0e2d7ddb153e179e2659773` |
| Family label | `unknown` |
| File name | `ProfitInvext_CRM_API_Documentation.zip` |
| File type | `zip` |
| First seen | `2026-06-20 19:52:50` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fde565a60909c6ae667ab6301c8893ff` |
| SHA-1 | `fbcbcdecc8eb86ce4f9a0242e6deb52e8f252475` |
| SHA-256 | `2e1369bc8343db24f34e4a309ba1a0efbd181150f0e2d7ddb153e179e2659773` |
| SHA3-384 | `e3b63f8ac8308e7fa6c12bcf3692f2f466c93b4022ef293a81b18ec0944fc46ed495280c480080bc459d12b32fb9ad5d` |
| TLSH | `T15F41D90054FB2B42C27FE237B90EA4CEF1464D41612B74927E18857E6ED84D16599F0E` |
| SSDEEP | `48:9EYfItwdYU+nwZ0rDbJqZN7bQMEAzcrnmNASmREV5cnk6:SOIRjw6z0XbQMEAIrmNAHEVenk6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_2e1369bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e1369bc8343db24f34e4a309ba1a0efbd181150f0e2d7ddb153e179e2659773"
    family = "unknown"
    file_name = "ProfitInvext_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-06-20 19:52:50"
  condition:
    hash.sha256(0, filesize) == "2e1369bc8343db24f34e4a309ba1a0efbd181150f0e2d7ddb153e179e2659773"
}
```

### Sample 75: `7ccbda568ff313b5`

| Field | Value |
|---|---|
| SHA-256 | `7ccbda568ff313b5e75d20b3bad6b9191a5f5b53eb867d05150c732f5cb039c2` |
| Family label | `unknown` |
| File name | `إعداد_القادة.pdf.zip` |
| File type | `zip` |
| First seen | `2026-06-20 19:47:22` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7754077ee9191839a971e99d38e9dc1a` |
| SHA-1 | `2eb2d5c3aa11524e031ae6dd6f1715b5c877cbd5` |
| SHA-256 | `7ccbda568ff313b5e75d20b3bad6b9191a5f5b53eb867d05150c732f5cb039c2` |
| SHA3-384 | `7ccc7bb15094542a073f548e35fdbf005f74b7b11b4749b7523cd1446c2acbb113cee711a0d5b7542b0b731bf62d6ab3` |
| TLSH | `T1F683AC9476E80304F1B5FE36CE7677864436BA80EE318B6C0AA4CC6C6951A01DC71F33` |
| SSDEEP | `24:foGX/ALDR5yW2RiqTeKT6CwD8Bx51WEn9+JkMRgRrT7UL3LXU5oG6V:f5vIRUVQqTelCUk51WU+KHhkLI56V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_7ccbda56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ccbda568ff313b5e75d20b3bad6b9191a5f5b53eb867d05150c732f5cb039c2"
    family = "unknown"
    file_name = "إعداد_القادة.pdf.zip"
    file_type = "zip"
    first_seen = "2026-06-20 19:47:22"
  condition:
    hash.sha256(0, filesize) == "7ccbda568ff313b5e75d20b3bad6b9191a5f5b53eb867d05150c732f5cb039c2"
}
```

### Sample 76: `ec2c3ddffdc0ff40`

| Field | Value |
|---|---|
| SHA-256 | `ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c` |
| Family label | `Prometei` |
| File name | `ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c` |
| File type | `elf` |
| First seen | `2026-06-20 19:45:42` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2496f7592fec3c0abba8b6cbec2765ca` |
| SHA-1 | `f32c9b396b378f5d524d732c42bdd3b0df08e332` |
| SHA-256 | `ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c` |
| SHA3-384 | `7e93065cc1ccc729d69ce865e5a07b48dc703b3b42a1056fd4f860f3d73505c014d1274db576517efaa19ddbd128dd61` |
| TLSH | `T1B1A423B4F9219E9F6DD76DB91B24831DE181C172689D4C2313AE94A34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsd8:Fs6pyCC/Ya2hpi6T6N4C` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_076_ec2c3ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c"
    family = "Prometei"
    file_name = "ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c"
    file_type = "elf"
    first_seen = "2026-06-20 19:45:42"
  condition:
    hash.sha256(0, filesize) == "ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c"
}
```

### Sample 77: `d9115ff47fa95067`

| Field | Value |
|---|---|
| SHA-256 | `d9115ff47fa9506711bc9c734e8b96125f18f48a5217ccbc1f057b2ce51a465e` |
| Family label | `unknown` |
| File name | `Radiology_MRI_Brain_Final_Report_Signed.lnk` |
| File type | `lnk` |
| First seen | `2026-06-20 19:43:07` |
| Reporter | `smica83` |
| Tags | `lnk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `659458bde3b89e413d5ba954dcbf3775` |
| SHA-1 | `b30d8b3425f6c03659d9d7a7c13154595298b812` |
| SHA-256 | `d9115ff47fa9506711bc9c734e8b96125f18f48a5217ccbc1f057b2ce51a465e` |
| SHA3-384 | `64698b0a98e48becfa3865b268ebad53d04521097515d17a1d9e9a1de528f9238ebb654da1384ca30a08004ce0486b18` |
| TLSH | `T1818163A559D98F30E77B45B304BE8A19893FF1848B1EDA8942C4DD8C305AAE0F434AE1` |
| SSDEEP | `48:8w/mDJn3U0Fbc6PeY8XuHrAmo4L+5Mzkt8ta8NM:8wuVn3NbXeuLAXp6A8tacM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_d9115ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9115ff47fa9506711bc9c734e8b96125f18f48a5217ccbc1f057b2ce51a465e"
    family = "unknown"
    file_name = "Radiology_MRI_Brain_Final_Report_Signed.lnk"
    file_type = "lnk"
    first_seen = "2026-06-20 19:43:07"
  condition:
    hash.sha256(0, filesize) == "d9115ff47fa9506711bc9c734e8b96125f18f48a5217ccbc1f057b2ce51a465e"
}
```

### Sample 78: `c06c3002302f4720`

| Field | Value |
|---|---|
| SHA-256 | `c06c3002302f47202884762c57982d86718ba4500699e9ef37d5cd513c6e8bf8` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 19:32:49` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0541c8b7fd74b0f5dfeae5efa574216` |
| SHA-1 | `006e2982a742a5085e87985e22dcff59fa5d9647` |
| SHA-256 | `c06c3002302f47202884762c57982d86718ba4500699e9ef37d5cd513c6e8bf8` |
| SHA3-384 | `a716a771216944a185bcada36c7913d29ec5e746cb3dcaaa5af6d09a2ead30384a82aabee3494bc6a7fe0053df2594bf` |
| IMPHASH | `a30c78a48c548a65b4846cfd9d8c7138` |
| TLSH | `T17E264B03E2A541E8C09DC179C30BD637AB76B88A4631B29F1BE81F612F69F506F1D749` |
| SSDEEP | `49152:riHDazMZq/LXnxsCCGByl9Ah/uN0D8dfOBVgcjKoeW7Zi5u4KW7r+Da3dtUxnkdY:2HSGrQFpgIKscOi91Ehys` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_078_c06c3002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c06c3002302f47202884762c57982d86718ba4500699e9ef37d5cd513c6e8bf8"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:32:49"
  condition:
    hash.sha256(0, filesize) == "c06c3002302f47202884762c57982d86718ba4500699e9ef37d5cd513c6e8bf8"
}
```

### Sample 79: `dacf7be18ad926cb`

| Field | Value |
|---|---|
| SHA-256 | `dacf7be18ad926cb2008f1a139439add5917bbded18e1b303bc7dd5c63cf4402` |
| Family label | `unknown` |
| File name | `dxon-atualizador-acesso.zip` |
| File type | `zip` |
| First seen | `2026-06-20 19:30:32` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0c1afa44161437d62201bed17ebb2de` |
| SHA-1 | `146a9827cc8da8ae7879ffe987bd5878d4c3bc17` |
| SHA-256 | `dacf7be18ad926cb2008f1a139439add5917bbded18e1b303bc7dd5c63cf4402` |
| SHA3-384 | `28f3f8843b22ecf9b2af823bc2279534a03a8c5b9f313bd9a4464a07cd60626e79e1f5348b675cbe5ae4cc20c5fbc3da` |
| TLSH | `T1E2F0D463D3C44921D19875788548EDC76582D28D1E389EBF57582F241C5B7560EDEC05` |
| SSDEEP | `12:5jiriL/v2eYNTZTgCHn/YPfFk7ftuhcN8aFJAfbXrwJaO:9iriLHFeTZ9n/YPf+L0u8wOLrw5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_dacf7be1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dacf7be18ad926cb2008f1a139439add5917bbded18e1b303bc7dd5c63cf4402"
    family = "unknown"
    file_name = "dxon-atualizador-acesso.zip"
    file_type = "zip"
    first_seen = "2026-06-20 19:30:32"
  condition:
    hash.sha256(0, filesize) == "dacf7be18ad926cb2008f1a139439add5917bbded18e1b303bc7dd5c63cf4402"
}
```

### Sample 80: `e462eb417f3ebe66`

| Field | Value |
|---|---|
| SHA-256 | `e462eb417f3ebe66041226a9d05174353889f1d189d71be1fa0559b0b40f8c79` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.BackDoor.Armada.1.30483.9391` |
| File type | `elf` |
| First seen | `2026-06-20 19:21:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89ccc31bbe39fa4f782c4331cf91be3d` |
| SHA-1 | `0d11712f2ff681fa7c120688e8f5839a77e91e38` |
| SHA-256 | `e462eb417f3ebe66041226a9d05174353889f1d189d71be1fa0559b0b40f8c79` |
| SHA3-384 | `ce998d606a9e3a7ac268bf14924943af0b1597fe959f886b6ad00bb36309a461f7841e12eaac8b0850180ebe9644cbdc` |
| TLSH | `T132342999BC40DB62C6D427BAFB5D829933130F74C3DE7506CC241F2966EB55F0A3A682` |
| SSDEEP | `6144:scLotBc52LE+U4rEssM8jaMK3771WChKHgOZ:HLo7cMU4rETaMyB4Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_e462eb41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e462eb417f3ebe66041226a9d05174353889f1d189d71be1fa0559b0b40f8c79"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30483.9391"
    file_type = "elf"
    first_seen = "2026-06-20 19:21:48"
  condition:
    hash.sha256(0, filesize) == "e462eb417f3ebe66041226a9d05174353889f1d189d71be1fa0559b0b40f8c79"
}
```

### Sample 81: `ed6b9a8c2e638fc9`

| Field | Value |
|---|---|
| SHA-256 | `ed6b9a8c2e638fc92a10cc88a0228e0c1dc088d5a28bb790f322137680b123f0` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.BackDoor.Armada.1.30872.16543` |
| File type | `elf` |
| First seen | `2026-06-20 19:21:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bda8d378206d1d427113ebd1d0f93056` |
| SHA-1 | `ff325456a382cc6746bb575868debd77d6ce66eb` |
| SHA-256 | `ed6b9a8c2e638fc92a10cc88a0228e0c1dc088d5a28bb790f322137680b123f0` |
| SHA3-384 | `4cc8ab4767195235028c24565f2bcfbb7528014991b91a1211a37cdc613f64a43d9676c1acb50da73555ab270a627e23` |
| TLSH | `T168342A99BC40DB66C6E427BAFB4C429933134F78C3DD3506CD245F2976EB54B0A3A682` |
| SSDEEP | `6144:f1u8u9eP0oKkYF8krBt9zJfahXW9WIWeswUfCVzQOZ:nu9ecXkYF8krBt8XQLbRZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_ed6b9a8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed6b9a8c2e638fc92a10cc88a0228e0c1dc088d5a28bb790f322137680b123f0"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30872.16543"
    file_type = "elf"
    first_seen = "2026-06-20 19:21:45"
  condition:
    hash.sha256(0, filesize) == "ed6b9a8c2e638fc92a10cc88a0228e0c1dc088d5a28bb790f322137680b123f0"
}
```

### Sample 82: `0e6902640affe9ac`

| Field | Value |
|---|---|
| SHA-256 | `0e6902640affe9ac58c39d52046a073741b8e77a6ad29137bdeb6f8cf8222964` |
| Family label | `RemusStealer` |
| File name | `SecuriteInfo.com.Win32.Dh-A.39239491` |
| File type | `exe` |
| First seen | `2026-06-20 19:20:50` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71682679387d5f8e8d1540e77b1b8d61` |
| SHA-1 | `55168d5f90679d56f58e5f581a064cd0045012fd` |
| SHA-256 | `0e6902640affe9ac58c39d52046a073741b8e77a6ad29137bdeb6f8cf8222964` |
| SHA3-384 | `ea4429b760eb6c09443015ffb7089aa21d5a923437d1ee805702fe7fd740f2273d961dcdb3edc7600b9651f53835ee39` |
| IMPHASH | `47274177192650375984b2b645ebe61c` |
| TLSH | `T10D136C62E1E223D7F8EB8376E9603333E5B1F44BA154564F8324DB092F3A1716568F92` |
| SSDEEP | `768:UA8J5nZI5t6rNlslBGFbqsx4x7ONBezr+l5lfoDZPdvenF2MwLB9tB8tA2K9V37W:UfeCNlslB0xE7+4r+rlwD1dvgDwV9gtB` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_082_0e690264
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6902640affe9ac58c39d52046a073741b8e77a6ad29137bdeb6f8cf8222964"
    family = "RemusStealer"
    file_name = "SecuriteInfo.com.Win32.Dh-A.39239491"
    file_type = "exe"
    first_seen = "2026-06-20 19:20:50"
  condition:
    hash.sha256(0, filesize) == "0e6902640affe9ac58c39d52046a073741b8e77a6ad29137bdeb6f8cf8222964"
}
```

### Sample 83: `ea6bdcebcb553f50`

| Field | Value |
|---|---|
| SHA-256 | `ea6bdcebcb553f5089383938412f2e4010ea74ae1e6543b923cad89563c7a6cf` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.BackDoor.Armada.1.13139.19924` |
| File type | `elf` |
| First seen | `2026-06-20 19:20:48` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `406176149f73ce4f39534ade2b529670` |
| SHA-1 | `900503637a462e57abe3cddd5a2b72cdfdb3f106` |
| SHA-256 | `ea6bdcebcb553f5089383938412f2e4010ea74ae1e6543b923cad89563c7a6cf` |
| SHA3-384 | `3dcd5f1768bcc4502fd7ec1a6a884d904964de9007d314239ab3014bb6612073ebda1b8d86e0dd2fe9725acb392e1d82` |
| TLSH | `T1E4A3121378D9FEBCDE189B31FDB553A0E7AD4EB916A83B05250A75A213C7002461F2BD` |
| SSDEEP | `1536:x2hmmFimREATtbqWoU4awpw6UjuQlLH3M3OJXxQEW0lbKcUWgmQLiTGUhaisaJzX:0EgjRosoKlj3tJ2wluuQL4hXLRwu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_ea6bdceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea6bdcebcb553f5089383938412f2e4010ea74ae1e6543b923cad89563c7a6cf"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.13139.19924"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:48"
  condition:
    hash.sha256(0, filesize) == "ea6bdcebcb553f5089383938412f2e4010ea74ae1e6543b923cad89563c7a6cf"
}
```

### Sample 84: `915d8baa66a420bd`

| Field | Value |
|---|---|
| SHA-256 | `915d8baa66a420bd67b75a9d6152ab99036c16d29f1b73b2ad4d8e3dbae382e2` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.BackDoor.Armada.1.30483.9391` |
| File type | `elf` |
| First seen | `2026-06-20 19:20:45` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7560006cd7ec668652484999aae4dba3` |
| SHA-1 | `4ef4a5c697705a2dbc6dd918ba32980621f51185` |
| SHA-256 | `915d8baa66a420bd67b75a9d6152ab99036c16d29f1b73b2ad4d8e3dbae382e2` |
| SHA3-384 | `a54cc50dfc2392c878d0ae9d9a5777e671bfe1edab18f5da3e3e73d26a66adcc33b6a796afe72c511f019c30015c3d52` |
| TLSH | `T14CA31258F08E9422C796017A8DD5DF1B0E9ED399F77BF5AB0540D3F0C76358212AAE24` |
| SSDEEP | `3072:XIdadX7BdsrJJG+jHlv5Gbldm/JOwbKoGL:Madldsn9jHlRq8c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_915d8baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "915d8baa66a420bd67b75a9d6152ab99036c16d29f1b73b2ad4d8e3dbae382e2"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30483.9391"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:45"
  condition:
    hash.sha256(0, filesize) == "915d8baa66a420bd67b75a9d6152ab99036c16d29f1b73b2ad4d8e3dbae382e2"
}
```

### Sample 85: `d3d74f36518d6bb5`

| Field | Value |
|---|---|
| SHA-256 | `d3d74f36518d6bb59929f9f1601b90520e6228877ab30787e97acd857e38cf2e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Linux.BackDoor.Armada.1.30872.16543` |
| File type | `elf` |
| First seen | `2026-06-20 19:20:43` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9517c01a112bca917727a7ca42c1018` |
| SHA-1 | `cc4fc4ec4f11a0da6bf70bc2a3cdb46378c34315` |
| SHA-256 | `d3d74f36518d6bb59929f9f1601b90520e6228877ab30787e97acd857e38cf2e` |
| SHA3-384 | `a79ff8940d95df7503df95898c2f3662291729ee2b9c5256d531bdb8522ca4f01c28e31418d0b9a25d7fa13d39a089bf` |
| TLSH | `T194A3121378D9FEBCDE189B31FDB553A0E7AD4EB916A83705250A75A223C7002461F2BD` |
| SSDEEP | `1536:x2hmmFimREATtbqWoU4awpw6UjuQlLH3M3OJXxQEW0lbKcUWgmQLiTGUhaisaJz6:0EgjRosoKlj3tJ2wluuQL4hXLRw8e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_d3d74f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3d74f36518d6bb59929f9f1601b90520e6228877ab30787e97acd857e38cf2e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30872.16543"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:43"
  condition:
    hash.sha256(0, filesize) == "d3d74f36518d6bb59929f9f1601b90520e6228877ab30787e97acd857e38cf2e"
}
```

### Sample 86: `7165ccfa91053dd6`

| Field | Value |
|---|---|
| SHA-256 | `7165ccfa91053dd6c0141ff42a6d92eeb8d19d582b0f57188ae305ec43235d32` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.BitCoinMiner-HF.67986673` |
| File type | `elf` |
| First seen | `2026-06-20 19:20:41` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f45d7d2e578f3497a9dec4e712ce795a` |
| SHA-1 | `515aee01b29de96cf4104609520d82ae13e9159e` |
| SHA-256 | `7165ccfa91053dd6c0141ff42a6d92eeb8d19d582b0f57188ae305ec43235d32` |
| SHA3-384 | `8489652bd563e093216088ff55875a21de0f8e924e7e5532088614898359c162501449c4ee12a6310c09e21e51a30093` |
| TLSH | `T120F65B47F9A614E8C1AEC430866BD653BA717C48072177E72B94B6302F77FE05A79B20` |
| TELFHASH | `t1445257314abc35b5b6a6da10b3a274b496772c6162f434b55063ed85ffc1e801ceac3b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:ddGnqlnsf8nl4lcmDi1WIPFCBNcJ7oEkLsQXE:dRlnsUlOqUqFCIkLsQXE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_7165ccfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7165ccfa91053dd6c0141ff42a6d92eeb8d19d582b0f57188ae305ec43235d32"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.BitCoinMiner-HF.67986673"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:41"
  condition:
    hash.sha256(0, filesize) == "7165ccfa91053dd6c0141ff42a6d92eeb8d19d582b0f57188ae305ec43235d32"
}
```

### Sample 87: `8b0ef90a42476f8d`

| Field | Value |
|---|---|
| SHA-256 | `8b0ef90a42476f8df2eae4c3e271fbb558a5d136d22e4e6f87e138b6d3281a08` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 19:15:12` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1df1670262960591ffcd70179d1521fc` |
| SHA-1 | `c372b46ea7163d98c63f75c242801e6cc7c266ee` |
| SHA-256 | `8b0ef90a42476f8df2eae4c3e271fbb558a5d136d22e4e6f87e138b6d3281a08` |
| SHA3-384 | `bdf211930777828a102c60741776d3cc2b04820d5d4e801a2c82cde028784cf23f712d1c80b81768bc883d495d658380` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T14A373377A28A653EE06A5B354A72D110953B6E50AD238D0ADFF4346CCF3D1B03D3EA46` |
| SSDEEP | `393216:27YD1NCULP0Uqqca8XjyJvwK4N581I4ES9F+qN:AYD1gULMBqca8XjyJoK4HNnk+q` |
| ICON-DHASH | `e1c2d2e3a392b233` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_8b0ef90a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0ef90a42476f8df2eae4c3e271fbb558a5d136d22e4e6f87e138b6d3281a08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:15:12"
  condition:
    hash.sha256(0, filesize) == "8b0ef90a42476f8df2eae4c3e271fbb558a5d136d22e4e6f87e138b6d3281a08"
}
```

### Sample 88: `526ae427fececcdf`

| Field | Value |
|---|---|
| SHA-256 | `526ae427fececcdfb7d231d95a3a4f3ffa83c130ed5d58192daad06510f4ee69` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 19:07:30` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX4.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d45dad3c505e89ac54acb6dbc86ec41e` |
| SHA-1 | `d9e22066987e02a6bd6e50fe3882109a1ad2567e` |
| SHA-256 | `526ae427fececcdfb7d231d95a3a4f3ffa83c130ed5d58192daad06510f4ee69` |
| SHA3-384 | `5ab62a6c347473d4ad9d375a44d0149255060a28f636de0779f9f5fc379f4b6ba2d59382a150343b1be23cc689edaa1f` |
| IMPHASH | `d9c0bfb4053066384ee7484b4c2917f9` |
| TLSH | `T18DF522223F94D902D8AA1E718A70CBF81720FC1D8945DB9734E7AE1F7D9E6C75E02588` |
| SSDEEP | `49152:ih+DpOIjw1yXYpexFaNpGHrZEf2m04Mfqn4epjK7i2/vx39lA5IxN4S:iADMI8kvxGKbm7AkEx7Cw5` |
| ICON-DHASH | `0028696969692800` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_088_526ae427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "526ae427fececcdfb7d231d95a3a4f3ffa83c130ed5d58192daad06510f4ee69"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:07:30"
  condition:
    hash.sha256(0, filesize) == "526ae427fececcdfb7d231d95a3a4f3ffa83c130ed5d58192daad06510f4ee69"
}
```

### Sample 89: `5390c32de7ad5886`

| Field | Value |
|---|---|
| SHA-256 | `5390c32de7ad5886330c7e66667b41ed652e1e0e9411591c4d9be1d40e2fdb01` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-20 19:04:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6fa8219cfc0270e5cae4d252a78add8` |
| SHA-1 | `d73ef6a79c134589c55489c1723059b035ca4562` |
| SHA-256 | `5390c32de7ad5886330c7e66667b41ed652e1e0e9411591c4d9be1d40e2fdb01` |
| SHA3-384 | `0af7e2c0d36f1f1a0a948654f6ed2a25a9eebc9bb6bfe4ee9acaf908a2ca3dbb2927f6fc9533d947707a60bdb18b5126` |
| TLSH | `T15D01AFC64640E9109069CA5D77A79590B461C3CF074A0B6C7FDD1D2DFB8C914F127F88` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaSX0dr+0a1etPZXb7LN7:e9Qp+MsSKr+0a1et97N7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_5390c32d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5390c32de7ad5886330c7e66667b41ed652e1e0e9411591c4d9be1d40e2fdb01"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-20 19:04:38"
  condition:
    hash.sha256(0, filesize) == "5390c32de7ad5886330c7e66667b41ed652e1e0e9411591c4d9be1d40e2fdb01"
}
```

### Sample 90: `1ce931d621b70d14`

| Field | Value |
|---|---|
| SHA-256 | `1ce931d621b70d14bdc90b5dcb8dc8cfce60e027f60eb2ff895c60efeb8ffbe7` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-20 19:02:00` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dea9bcf5ed297e9803b91e6b75fd3f3` |
| SHA-1 | `4c219a04109734d4a50f591c720fa15c2e951912` |
| SHA-256 | `1ce931d621b70d14bdc90b5dcb8dc8cfce60e027f60eb2ff895c60efeb8ffbe7` |
| SHA3-384 | `69cf29bb9764cc59a8d36ea4e6b3a7a0cabd4b9f6c29569aa3462c88cca6e8b53894f1e6a8edf23ae14e342f6c8e1bba` |
| IMPHASH | `a30c78a48c548a65b4846cfd9d8c7138` |
| TLSH | `T10E264B03E2A541E8C09DC179C30BD637AB76B88A4631B29F1BE81F612F69F506F1D749` |
| SSDEEP | `49152:LiHDazMZq/LXnxsCCGByl9Ah/uN0D8dfOBVgcjKoeW7Zi5u4KW7r+Da3dtUxnkdE:WHSGrQFpgIKscOi91Ehyo` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_090_1ce931d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ce931d621b70d14bdc90b5dcb8dc8cfce60e027f60eb2ff895c60efeb8ffbe7"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:02:00"
  condition:
    hash.sha256(0, filesize) == "1ce931d621b70d14bdc90b5dcb8dc8cfce60e027f60eb2ff895c60efeb8ffbe7"
}
```

### Sample 91: `b187869c3dc6e0f1`

| Field | Value |
|---|---|
| SHA-256 | `b187869c3dc6e0f1c3b6666867c26be9d5e728ac8b0aa88554078ad3feee2003` |
| Family label | `Mirai` |
| File name | `bin.m68k` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59c21ad2fd35dbfc4c75d660f1f2b184` |
| SHA-1 | `3ecf048d32c19c46f3b076e9104db52bea8ff1d4` |
| SHA-256 | `b187869c3dc6e0f1c3b6666867c26be9d5e728ac8b0aa88554078ad3feee2003` |
| SHA3-384 | `f3d3b4f78d536e21571c1e4c9f2eedc02282bfb82abbd37496b7353a5c0904a9977b025a8460adfa7ce9681e036b53a9` |
| TLSH | `T189342B87F900DF7EFC0BE37244674915B130BF6A18620677F122BDE6AE290D5192BE85` |
| SSDEEP | `3072:wqgVIOAS+iztekrinjxXFvr/pJTMy/ERp6mX6CT0TOiGk6Ex4VdjbiTL/iBglpG9:wqgVIOboTdOy/gp6mpTKGZExdLagGKA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b187869c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b187869c3dc6e0f1c3b6666867c26be9d5e728ac8b0aa88554078ad3feee2003"
    family = "Mirai"
    file_name = "bin.m68k"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:53"
  condition:
    hash.sha256(0, filesize) == "b187869c3dc6e0f1c3b6666867c26be9d5e728ac8b0aa88554078ad3feee2003"
}
```

### Sample 92: `4d4e52f75a6ed80e`

| Field | Value |
|---|---|
| SHA-256 | `4d4e52f75a6ed80e486a147d377c308ac5cd111cae7b775d7a4f33bd38248c1b` |
| Family label | `Mirai` |
| File name | `bin.armv4eb` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3143b75465461f8d41b299fc5fb6ac31` |
| SHA-1 | `08fb322909c4491b8f57666396d5a4748a4be9c0` |
| SHA-256 | `4d4e52f75a6ed80e486a147d377c308ac5cd111cae7b775d7a4f33bd38248c1b` |
| SHA3-384 | `f7df7f9aed7d57ec4f2b8b64990ca65fbb5a148f106e52bedf72c9fd5552ab46c8fc6ade954132c969935e77fc8404ba` |
| TLSH | `T193241990BA59EC32C05E1D3667FBDB593B0369D14EA39104C460EBCCBB875C0AB6857B` |
| SSDEEP | `3072:fDbXY3kGL71D5oItsE4meiPuBzdWdIAV547OtEmj77nGGL72+:fX1G3HoISE5PuNkV54svjpL72+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_4d4e52f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d4e52f75a6ed80e486a147d377c308ac5cd111cae7b775d7a4f33bd38248c1b"
    family = "Mirai"
    file_name = "bin.armv4eb"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:51"
  condition:
    hash.sha256(0, filesize) == "4d4e52f75a6ed80e486a147d377c308ac5cd111cae7b775d7a4f33bd38248c1b"
}
```

### Sample 93: `7d8a76a128030322`

| Field | Value |
|---|---|
| SHA-256 | `7d8a76a128030322c8c2a6a8a618a318f65bb4f90dc9438999e23c99f3dc6760` |
| Family label | `Mirai` |
| File name | `bin.i586` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7c81a476e919549fd3e4149d23d76d8` |
| SHA-1 | `e998a4d0dc3ea38ed6e406f766b03e35106bb577` |
| SHA-256 | `7d8a76a128030322c8c2a6a8a618a318f65bb4f90dc9438999e23c99f3dc6760` |
| SHA3-384 | `6e0b4aa44adb7f30c4269524794e3a896ec01024a0f154c1cd3cc8041bf9facb52b5b1cfbf3bc1df8af9e6967fb84cb8` |
| TLSH | `T17704F842EA43DFB3E55310F202B787310E71E97A6C66D542E3BCBCB4A9615D1A60A37C` |
| TELFHASH | `t1ec9148b5bfb209dcb7d0d902d24d5721dd1cd53b745079ba0af2269837b2b026276c39` |
| SSDEEP | `3072:nfmM6+Sg5eOESSvk4sOmdc6AIFX3PElOxi32KpzyPN7GE/MlpGe:nxx5eOBLgIFhA32OuFT/iGe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_7d8a76a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d8a76a128030322c8c2a6a8a618a318f65bb4f90dc9438999e23c99f3dc6760"
    family = "Mirai"
    file_name = "bin.i586"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:50"
  condition:
    hash.sha256(0, filesize) == "7d8a76a128030322c8c2a6a8a618a318f65bb4f90dc9438999e23c99f3dc6760"
}
```

### Sample 94: `7d25396b6d7fb9ce`

| Field | Value |
|---|---|
| SHA-256 | `7d25396b6d7fb9cef476ea318eae9a8c89fdffed92616b7792af5298214d5b91` |
| Family label | `Mirai` |
| File name | `bin.armv6l` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91f909420470fc7c9129f6a01d924e53` |
| SHA-1 | `6a8b4d76f50917c2b7f5284c99939756a9950676` |
| SHA-256 | `7d25396b6d7fb9cef476ea318eae9a8c89fdffed92616b7792af5298214d5b91` |
| SHA3-384 | `38ef8c390844d978a5becef51d736a0333535ccef4f8f22a4e0060695dba1d583ead62c110b556005c362fd8c1882661` |
| TLSH | `T1B924E947B991CF12C1C111FEFE5E418D37136FB8D2DA72029D24AFA477868EA0E7A116` |
| SSDEEP | `6144:xoMWDAzSf4sXLCloq+RaPiVv5L5FWe9bmhSjzr2:x6Dd4sXGlgRaP8bWetmIjz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_7d25396b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d25396b6d7fb9cef476ea318eae9a8c89fdffed92616b7792af5298214d5b91"
    family = "Mirai"
    file_name = "bin.armv6l"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:48"
  condition:
    hash.sha256(0, filesize) == "7d25396b6d7fb9cef476ea318eae9a8c89fdffed92616b7792af5298214d5b91"
}
```

### Sample 95: `1d99ff30758e4872`

| Field | Value |
|---|---|
| SHA-256 | `1d99ff30758e487264c3550c2b0c3c37646e772266882809898a2ed0c5f74c4b` |
| Family label | `Mirai` |
| File name | `bin.mips` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1c92d6f641044432575ee8255ac880f` |
| SHA-1 | `be4fb9ffe1bd1cb8680d0b6b5f1a3615158853f1` |
| SHA-256 | `1d99ff30758e487264c3550c2b0c3c37646e772266882809898a2ed0c5f74c4b` |
| SHA3-384 | `88bd73982394136bf9f59d5eae57f8d971b4969399116b6d96eba25a51d388c5a5e5363644a8ec05587d616343664ce0` |
| TLSH | `T1FB548A1A2E22DF7FF66D867047F389305A9876D62AE1D544F16CE60C1F2028E641F7E8` |
| TELFHASH | `t1825190180d7817f4a6655c9d49acff36d6a330df7e161c378e50e86eab6aa435d00c0d` |
| SSDEEP | `6144:kRR/4cIFzpz7L+gjX25sCwDrSalSqZD/TZ+jukK:Npz7TT2wDrojuN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_1d99ff30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d99ff30758e487264c3550c2b0c3c37646e772266882809898a2ed0c5f74c4b"
    family = "Mirai"
    file_name = "bin.mips"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:46"
  condition:
    hash.sha256(0, filesize) == "1d99ff30758e487264c3550c2b0c3c37646e772266882809898a2ed0c5f74c4b"
}
```

### Sample 96: `08566baf2de3d75a`

| Field | Value |
|---|---|
| SHA-256 | `08566baf2de3d75a6161ffce3611c07b15029faa32c3225dfa8409e6b2b7828a` |
| Family label | `Mirai` |
| File name | `bin.i486` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63cfcc8d1c9a15b078b7cb0c5efdd1d8` |
| SHA-1 | `109a86facc2c826f53c6465c53f8b13478aa259a` |
| SHA-256 | `08566baf2de3d75a6161ffce3611c07b15029faa32c3225dfa8409e6b2b7828a` |
| SHA3-384 | `5871510d4eed497e1fbafb436b99c9af7e4a52b54f138226e97c111cd117387f8f88361a1ac9c8ca37988125776ea7a1` |
| TLSH | `T104043802E603C9B2C41301B112F7CB765E31F9B7AE25D452D3FCEEA0ADA56D165093AE` |
| TELFHASH | `t18b912b75fef509dcb7d0c801d24e5361de19e53b34503aba0af2269837b2a42527ac7a` |
| SSDEEP | `3072:6pvxSRDkCQZzYsjRV58c5aiJE7/CNDh7mU83Dlpy8X:yv5dRqc5aomu7J8Ly8X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_08566baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08566baf2de3d75a6161ffce3611c07b15029faa32c3225dfa8409e6b2b7828a"
    family = "Mirai"
    file_name = "bin.i486"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:45"
  condition:
    hash.sha256(0, filesize) == "08566baf2de3d75a6161ffce3611c07b15029faa32c3225dfa8409e6b2b7828a"
}
```

### Sample 97: `8797ddcc01829135`

| Field | Value |
|---|---|
| SHA-256 | `8797ddcc018291354d75d56ba44b6dcdef8d8e4b593dd92a859d63200248bb76` |
| Family label | `Mirai` |
| File name | `bin.armv7l` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a735f5eeba5ceab07967966861332698` |
| SHA-1 | `b77c8c2856b8cd1969e26f2982402eb1ad019a93` |
| SHA-256 | `8797ddcc018291354d75d56ba44b6dcdef8d8e4b593dd92a859d63200248bb76` |
| SHA3-384 | `27a6fb71e6d1112f5c72497ac5c3476862a6e3c100414af5798023f5058f62b24524118b041c0572b964ba3f54066e84` |
| TLSH | `T12B14F74AB9919F11D5D231FEFA9F419833136BA8D7FA7101DD206F6033C699B0B7A212` |
| SSDEEP | `6144:1YL5UvebhOc88zc/vCcSaU/MvNL1QH0hP14iWXj06i:1YLWedONqc/vCZaUcNL1QHGeiWXj0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_8797ddcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8797ddcc018291354d75d56ba44b6dcdef8d8e4b593dd92a859d63200248bb76"
    family = "Mirai"
    file_name = "bin.armv7l"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:43"
  condition:
    hash.sha256(0, filesize) == "8797ddcc018291354d75d56ba44b6dcdef8d8e4b593dd92a859d63200248bb76"
}
```

### Sample 98: `a6ec23370de4e184`

| Field | Value |
|---|---|
| SHA-256 | `a6ec23370de4e1849d6e91f60494fd39c6069f25b963110cb13cb60c371e8512` |
| Family label | `Mirai` |
| File name | `bin.powerpc` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9c1c21931e143a671494eb2e89fe5b9` |
| SHA-1 | `f3ae306c4a7bf200c2194846fd0017d36cbba614` |
| SHA-256 | `a6ec23370de4e1849d6e91f60494fd39c6069f25b963110cb13cb60c371e8512` |
| SHA3-384 | `91b01b5714c1dc40db1045bedeaaec3c110f752b8e71fee5e747dc5f322757e2b1f59a669eaf72cd9bde62daf5a58360` |
| TLSH | `T1612439027B0D0E03D1532DF0273B1BE14BEFFDA128B5E680755EBEC59271DB22489A99` |
| SSDEEP | `3072:AaQzEan+B5RL6tiseuDTc5AIxseNkAbZn9HvVFS8Q1jHMnGIC:W+B58xesQ5rxRkAbZn9zSvjgC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_a6ec2337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6ec23370de4e1849d6e91f60494fd39c6069f25b963110cb13cb60c371e8512"
    family = "Mirai"
    file_name = "bin.powerpc"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:42"
  condition:
    hash.sha256(0, filesize) == "a6ec23370de4e1849d6e91f60494fd39c6069f25b963110cb13cb60c371e8512"
}
```

### Sample 99: `731aa53e556fe38c`

| Field | Value |
|---|---|
| SHA-256 | `731aa53e556fe38caf0f74bd6cbb249e35648643c295cadfdf902afd392f3b41` |
| Family label | `Mirai` |
| File name | `bin.powerpc-440fp` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `078eb04a07c053c331d43ce7e7f23358` |
| SHA-1 | `30d321b1dc2b7a774ed5721045b0df70b7e7a38f` |
| SHA-256 | `731aa53e556fe38caf0f74bd6cbb249e35648643c295cadfdf902afd392f3b41` |
| SHA3-384 | `27ca369a1fd64d0fd0dea388fe6620e9ae1329f81566af279e33101ddb025b3e934ff1f8a019edf30765c2f9acfe5eac` |
| TLSH | `T1EB242A027B0D0E07D1432DF4267B0BF14B9BAD6138FAE681750AFEC957B1DB1644AA8D` |
| SSDEEP | `3072:ZUEdJWfJNUaqrJVqNWZMxxN99iRFDYJrMhgfNjZgnGuA:ZwJWacJJZMxf99iTDY1MhAj0A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_731aa53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731aa53e556fe38caf0f74bd6cbb249e35648643c295cadfdf902afd392f3b41"
    family = "Mirai"
    file_name = "bin.powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:40"
  condition:
    hash.sha256(0, filesize) == "731aa53e556fe38caf0f74bd6cbb249e35648643c295cadfdf902afd392f3b41"
}
```

### Sample 100: `2ae7795781a76b07`

| Field | Value |
|---|---|
| SHA-256 | `2ae7795781a76b073d3aa3533a6bfc647114cc1462e701bfff289f6d7ce55d4e` |
| Family label | `Mirai` |
| File name | `bin.armv5l` |
| File type | `elf` |
| First seen | `2026-06-20 18:58:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e426d97a89f62452655d00be8e0aa2c` |
| SHA-1 | `36dbf95b73d1964a372c35db425fe3ab01828c3e` |
| SHA-256 | `2ae7795781a76b073d3aa3533a6bfc647114cc1462e701bfff289f6d7ce55d4e` |
| SHA3-384 | `02c0b33f149be31b11b7cd4a02d79b995911bcc23b7f8504dfa4a2c494e6a698aab85e0ce9bcb85ca0a8042326b0b1a7` |
| TLSH | `T10414E946BD518F23C6C311FAFB9F429C37266BA8D6EB3102DD157FA437864DA093A211` |
| TELFHASH | `t159110002aeb419befad1c0be42dd60172704304aad6438f8dcbdfa6d6353d98703680b` |
| SSDEEP | `6144:FNx7P6kO+mQpTKl375GL2fnLjMq4j4LL:FNxT6kOypTKl39vfLjMq4j4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_2ae77957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae7795781a76b073d3aa3533a6bfc647114cc1462e701bfff289f6d7ce55d4e"
    family = "Mirai"
    file_name = "bin.armv5l"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:39"
  condition:
    hash.sha256(0, filesize) == "2ae7795781a76b073d3aa3533a6bfc647114cc1462e701bfff289f6d7ce55d4e"
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
 * Generated: 2026-06-20T22:04:32.023703+00:00
 */

rule MalwareBazaar_unknown_001_a9303e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9303e3948a212476179499bf5e7aaf5df89fc490bf28c8ec15005bf8b023ee5"
    family = "unknown"
    file_name = "Client.exe"
    file_type = "exe"
    first_seen = "2026-06-20 21:59:08"
  condition:
    hash.sha256(0, filesize) == "a9303e3948a212476179499bf5e7aaf5df89fc490bf28c8ec15005bf8b023ee5"
}

rule MalwareBazaar_unknown_002_b1d863f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1d863f55530e9f30b6d80d9930a638581e6c00674d5e25cb38b88911cc0ccba"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:56:32"
  condition:
    hash.sha256(0, filesize) == "b1d863f55530e9f30b6d80d9930a638581e6c00674d5e25cb38b88911cc0ccba"
}

rule MalwareBazaar_CoinMiner_003_eb2cca23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb2cca230b99d059355c3d4d2c35e9585aedd030c7477535b86bbc950d7ea2a9"
    family = "CoinMiner"
    file_name = "client.exe"
    file_type = "exe"
    first_seen = "2026-06-20 21:55:32"
  condition:
    hash.sha256(0, filesize) == "eb2cca230b99d059355c3d4d2c35e9585aedd030c7477535b86bbc950d7ea2a9"
}

rule MalwareBazaar_unknown_004_a9b58569
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9b58569a98930ebe0b68bddd9fb13e4ddc9e75530b283d07b853c97b6c13d8a"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-20 21:47:43"
  condition:
    hash.sha256(0, filesize) == "a9b58569a98930ebe0b68bddd9fb13e4ddc9e75530b283d07b853c97b6c13d8a"
}

rule MalwareBazaar_unknown_005_ec77a80a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec77a80a984c029be6242314bce682b5234783801f4dbe449b250e0198bcbf26"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:45:55"
  condition:
    hash.sha256(0, filesize) == "ec77a80a984c029be6242314bce682b5234783801f4dbe449b250e0198bcbf26"
}

rule MalwareBazaar_CoinMiner_006_5122b2cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5122b2cc1fc99c60330b863c94e09e82553eff28cbfba8496f30bea88465b77d"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:45:29"
  condition:
    hash.sha256(0, filesize) == "5122b2cc1fc99c60330b863c94e09e82553eff28cbfba8496f30bea88465b77d"
}

rule MalwareBazaar_CoinMiner_007_40345a35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40345a358400cb771088c33a9cf194946da95c2bb2d979e7be5e1c8c37facf33"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:45:09"
  condition:
    hash.sha256(0, filesize) == "40345a358400cb771088c33a9cf194946da95c2bb2d979e7be5e1c8c37facf33"
}

rule MalwareBazaar_CoinMiner_008_52764c8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52764c8c74bc2ec19138f7bbaaeb30fc24f5384709409e756f3edb03848c67bb"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:44:49"
  condition:
    hash.sha256(0, filesize) == "52764c8c74bc2ec19138f7bbaaeb30fc24f5384709409e756f3edb03848c67bb"
}

rule MalwareBazaar_unknown_009_afac9708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afac970888a621eb5a408c1820d941839c28ce4fbc351dfa0d23402f04fcd3bc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 21:44:29"
  condition:
    hash.sha256(0, filesize) == "afac970888a621eb5a408c1820d941839c28ce4fbc351dfa0d23402f04fcd3bc"
}

rule MalwareBazaar_unknown_010_3660074f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3660074f4a92b21ddababd36837c86db20ccd883866bc1dbeed11ed081a1df3e"
    family = "unknown"
    file_name = "kworkerd-netns"
    file_type = "elf"
    first_seen = "2026-06-20 21:37:39"
  condition:
    hash.sha256(0, filesize) == "3660074f4a92b21ddababd36837c86db20ccd883866bc1dbeed11ed081a1df3e"
}

rule MalwareBazaar_unknown_011_61dda033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61dda033ee6a52ace288049c4d5be53959a5dcd0467dcd4286f3c8203ff984a4"
    family = "unknown"
    file_name = "kworkerd-irq"
    file_type = "elf"
    first_seen = "2026-06-20 21:27:43"
  condition:
    hash.sha256(0, filesize) == "61dda033ee6a52ace288049c4d5be53959a5dcd0467dcd4286f3c8203ff984a4"
}

rule MalwareBazaar_unknown_012_e6e09041
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6e09041ef99c529827b12f93d988dc29320fffdb604fbebbfc7403cffae6baf"
    family = "unknown"
    file_name = "kworkerd-cgroup"
    file_type = "elf"
    first_seen = "2026-06-20 21:23:40"
  condition:
    hash.sha256(0, filesize) == "e6e09041ef99c529827b12f93d988dc29320fffdb604fbebbfc7403cffae6baf"
}

rule MalwareBazaar_unknown_013_c1e97858
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e97858d11f97a0157f31aeb413c76ecd9cd96062929e2e659ae9e3c0dc78c4"
    family = "unknown"
    file_name = "kworkerd"
    file_type = "elf"
    first_seen = "2026-06-20 21:15:40"
  condition:
    hash.sha256(0, filesize) == "c1e97858d11f97a0157f31aeb413c76ecd9cd96062929e2e659ae9e3c0dc78c4"
}

rule MalwareBazaar_unknown_014_691c25e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "691c25e6addecd537d5948e809346235694f18621322f847299f464c35613615"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-20 21:12:37"
  condition:
    hash.sha256(0, filesize) == "691c25e6addecd537d5948e809346235694f18621322f847299f464c35613615"
}

rule MalwareBazaar_unknown_015_c1ddca85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ddca8512611169717a8f9dec04cf8a5e5636d49fbbe33f6e80c7cfa8891023"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-06-20 21:12:35"
  condition:
    hash.sha256(0, filesize) == "c1ddca8512611169717a8f9dec04cf8a5e5636d49fbbe33f6e80c7cfa8891023"
}

rule MalwareBazaar_unknown_016_c9ede383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9ede3834a7beceb195f105766eed01c3cfbf146d7982bf659d3ff75ef7bafa0"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-20 21:11:43"
  condition:
    hash.sha256(0, filesize) == "c9ede3834a7beceb195f105766eed01c3cfbf146d7982bf659d3ff75ef7bafa0"
}

rule MalwareBazaar_unknown_017_ae5db9eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae5db9eb1406557f12e2d9b474b2519beba3b6fc6afdb8ded74f41d258ae82cd"
    family = "unknown"
    file_name = "kworkerd-rcu"
    file_type = "elf"
    first_seen = "2026-06-20 21:11:41"
  condition:
    hash.sha256(0, filesize) == "ae5db9eb1406557f12e2d9b474b2519beba3b6fc6afdb8ded74f41d258ae82cd"
}

rule MalwareBazaar_unknown_018_c9b09ab0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9b09ab0ba66f76f8f4cfb00e34a941672dd84c4b535c3f328cf806d6a45cd9c"
    family = "unknown"
    file_name = "kworkerd-netns-rt"
    file_type = "elf"
    first_seen = "2026-06-20 21:11:40"
  condition:
    hash.sha256(0, filesize) == "c9b09ab0ba66f76f8f4cfb00e34a941672dd84c4b535c3f328cf806d6a45cd9c"
}

rule MalwareBazaar_Mirai_019_b67542eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b67542ebf7ea604cd661298d3e8dfb0e49592ea342267a4c1320363cd0afed50"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-20 21:09:36"
  condition:
    hash.sha256(0, filesize) == "b67542ebf7ea604cd661298d3e8dfb0e49592ea342267a4c1320363cd0afed50"
}

rule MalwareBazaar_unknown_020_d41fd901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d41fd9018d83a1275535f8cbe0ee0b8cbfe440eeb0d9a29bc24a75643cf0a102"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-20 20:51:04"
  condition:
    hash.sha256(0, filesize) == "d41fd9018d83a1275535f8cbe0ee0b8cbfe440eeb0d9a29bc24a75643cf0a102"
}

rule MalwareBazaar_Mirai_021_33e1522d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33e1522d870d0d929ac0a1733f746c58ba7abc8dcb1e9efc28d4393d4eb5d749"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:45"
  condition:
    hash.sha256(0, filesize) == "33e1522d870d0d929ac0a1733f746c58ba7abc8dcb1e9efc28d4393d4eb5d749"
}

rule MalwareBazaar_Mirai_022_d991f08e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d991f08e6d422bca943238a276b01aceff5d3f674c33531d6038a59a08c1a9e8"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:45"
  condition:
    hash.sha256(0, filesize) == "d991f08e6d422bca943238a276b01aceff5d3f674c33531d6038a59a08c1a9e8"
}

rule MalwareBazaar_Mirai_023_7f5f2aaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f5f2aaa392cd5770e6c2dff7d390e15c3e6c774886408e4cfb8b0b65cb31c32"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:43"
  condition:
    hash.sha256(0, filesize) == "7f5f2aaa392cd5770e6c2dff7d390e15c3e6c774886408e4cfb8b0b65cb31c32"
}

rule MalwareBazaar_Mirai_024_81ae285a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ae285ab750dfbd504bea7e8f44e10b7e44dc634ace7dda017bb2de7ff2bd2a"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:43"
  condition:
    hash.sha256(0, filesize) == "81ae285ab750dfbd504bea7e8f44e10b7e44dc634ace7dda017bb2de7ff2bd2a"
}

rule MalwareBazaar_Mirai_025_74394ecc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74394ecce3f159b8a2ba94104976e18d32e8077c1df0b9f4b471128d96521b1d"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:42"
  condition:
    hash.sha256(0, filesize) == "74394ecce3f159b8a2ba94104976e18d32e8077c1df0b9f4b471128d96521b1d"
}

rule MalwareBazaar_Mirai_026_b090e5a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b090e5a3b3c104c446018af559c074adf42dc10a8c4e34270fa2228a1f2f82c5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-20 20:50:42"
  condition:
    hash.sha256(0, filesize) == "b090e5a3b3c104c446018af559c074adf42dc10a8c4e34270fa2228a1f2f82c5"
}

rule MalwareBazaar_unknown_027_666abe7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "666abe7af5c43351abba61abe9eda5f99f6b84d7702ee36faefc345eddc54384"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-06-20 20:50:41"
  condition:
    hash.sha256(0, filesize) == "666abe7af5c43351abba61abe9eda5f99f6b84d7702ee36faefc345eddc54384"
}

rule MalwareBazaar_unknown_028_f9f8567a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9f8567aaa807983097deb4b7fb130cc2374ace1fb08a6a825324d892f11c140"
    family = "unknown"
    file_name = "kworkerd-irq-bal"
    file_type = "elf"
    first_seen = "2026-06-20 20:49:34"
  condition:
    hash.sha256(0, filesize) == "f9f8567aaa807983097deb4b7fb130cc2374ace1fb08a6a825324d892f11c140"
}

rule MalwareBazaar_unknown_029_5c2d1ffb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c2d1ffb8d00e3e93d60dc3294b08ce9afa08962d2658a67694b8f9c477e87d3"
    family = "unknown"
    file_name = "kworkerd-softirq"
    file_type = "elf"
    first_seen = "2026-06-20 20:47:37"
  condition:
    hash.sha256(0, filesize) == "5c2d1ffb8d00e3e93d60dc3294b08ce9afa08962d2658a67694b8f9c477e87d3"
}

rule MalwareBazaar_Mirai_030_5401b74c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5401b74c9a0d32febbf9ecbaa6665ab839d66f53a54c06fb4f0ac14207a2c4a5"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-20 20:46:43"
  condition:
    hash.sha256(0, filesize) == "5401b74c9a0d32febbf9ecbaa6665ab839d66f53a54c06fb4f0ac14207a2c4a5"
}

rule MalwareBazaar_Mirai_031_4b45fc7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b45fc7bd3f81203fb9ff383f45b39dc9bc291437a141610b76cd9f3620ec308"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-06-20 20:45:36"
  condition:
    hash.sha256(0, filesize) == "4b45fc7bd3f81203fb9ff383f45b39dc9bc291437a141610b76cd9f3620ec308"
}

rule MalwareBazaar_Mirai_032_637cc40d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "637cc40d3f134ef600020e513709b4389fe3c169206dcbbe34171b51528a0024"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-20 20:45:35"
  condition:
    hash.sha256(0, filesize) == "637cc40d3f134ef600020e513709b4389fe3c169206dcbbe34171b51528a0024"
}

rule MalwareBazaar_ConnectWise_033_4c6c3fb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6c3fb40ded613933d00a87000b065649322eec736018493bc607ce72c76017"
    family = "ConnectWise"
    file_name = "Adobe_Acrobat_Reader_DC_Updater_Windows_installer_Win11_x86_x64_Win10-Win11_x64.vbs"
    file_type = "vbs"
    first_seen = "2026-06-20 20:41:55"
  condition:
    hash.sha256(0, filesize) == "4c6c3fb40ded613933d00a87000b065649322eec736018493bc607ce72c76017"
}

rule MalwareBazaar_unknown_034_76edebe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76edebe707d788acf692af96e3276784d0501dd01eb272f08cbfb2e3a1c14d70"
    family = "unknown"
    file_name = "init.sh"
    file_type = "sh"
    first_seen = "2026-06-20 20:41:38"
  condition:
    hash.sha256(0, filesize) == "76edebe707d788acf692af96e3276784d0501dd01eb272f08cbfb2e3a1c14d70"
}

rule MalwareBazaar_AsyncRAT_035_c9eadf5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9eadf5f3be0996c41ad4c42f7bf530b74d8682ac630cea018dd0edefa07d4ea"
    family = "AsyncRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 20:40:48"
  condition:
    hash.sha256(0, filesize) == "c9eadf5f3be0996c41ad4c42f7bf530b74d8682ac630cea018dd0edefa07d4ea"
}

rule MalwareBazaar_unknown_036_23c82529
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23c8252953a84b9735a79946efcb1f2b46d565905e2f032380d7c0a5940667d0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 20:35:36"
  condition:
    hash.sha256(0, filesize) == "23c8252953a84b9735a79946efcb1f2b46d565905e2f032380d7c0a5940667d0"
}

rule MalwareBazaar_unknown_037_97ab9519
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97ab95191daea05b15024ff2a3a52081a30d4238ba4db4efad5e232f44ab97ab"
    family = "unknown"
    file_name = "kworkerd-scsi"
    file_type = "elf"
    first_seen = "2026-06-20 20:31:37"
  condition:
    hash.sha256(0, filesize) == "97ab95191daea05b15024ff2a3a52081a30d4238ba4db4efad5e232f44ab97ab"
}

rule MalwareBazaar_unknown_038_a32e7b6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a32e7b6c1bab32642fa78f78d1891f8ba1ca8c4fa2bb382ea91350c9290a1107"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-20 20:31:24"
  condition:
    hash.sha256(0, filesize) == "a32e7b6c1bab32642fa78f78d1891f8ba1ca8c4fa2bb382ea91350c9290a1107"
}

rule MalwareBazaar_unknown_039_585b523a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "585b523ab776fe15acd2f5ad75c58dfec436a4311c7bbc96758c7968ccb9ace3"
    family = "unknown"
    file_name = "kworkerd-blkcg"
    file_type = "elf"
    first_seen = "2026-06-20 20:29:33"
  condition:
    hash.sha256(0, filesize) == "585b523ab776fe15acd2f5ad75c58dfec436a4311c7bbc96758c7968ccb9ace3"
}

rule MalwareBazaar_unknown_040_c32470f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c32470f4960e3267292b81005f792a1755d7b708aec15d083f205cc978f3a6e3"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-20 20:28:37"
  condition:
    hash.sha256(0, filesize) == "c32470f4960e3267292b81005f792a1755d7b708aec15d083f205cc978f3a6e3"
}

rule MalwareBazaar_unknown_041_4bb095a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bb095a58fff5ed716654429a5d3e85659f5e88fdb3d70991fe74ea5d86572cf"
    family = "unknown"
    file_name = "kworkerd-writeback"
    file_type = "elf"
    first_seen = "2026-06-20 20:27:37"
  condition:
    hash.sha256(0, filesize) == "4bb095a58fff5ed716654429a5d3e85659f5e88fdb3d70991fe74ea5d86572cf"
}

rule MalwareBazaar_unknown_042_efc0aee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc0aee14544530c3d1b1abcd349d5f5d13069c923ea2c45c3f5a002927f41ce"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:17:30"
  condition:
    hash.sha256(0, filesize) == "efc0aee14544530c3d1b1abcd349d5f5d13069c923ea2c45c3f5a002927f41ce"
}

rule MalwareBazaar_unknown_043_0bc4d1ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc4d1eff24c715260b70eaf0abe32655e99a675a6edd47532aa43f843e6a815"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-06-20 20:17:08"
  condition:
    hash.sha256(0, filesize) == "0bc4d1eff24c715260b70eaf0abe32655e99a675a6edd47532aa43f843e6a815"
}

rule MalwareBazaar_unknown_044_33dcdaaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33dcdaafec603a3b65796c06235130d6141cdfd45752235bf66b8b17f2f2ecee"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:59"
  condition:
    hash.sha256(0, filesize) == "33dcdaafec603a3b65796c06235130d6141cdfd45752235bf66b8b17f2f2ecee"
}

rule MalwareBazaar_unknown_045_e7d800b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7d800b02d760d904093d0490348d225c45fce9e74192278f7ed6ba240f1daf1"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:54"
  condition:
    hash.sha256(0, filesize) == "e7d800b02d760d904093d0490348d225c45fce9e74192278f7ed6ba240f1daf1"
}

rule MalwareBazaar_unknown_046_7b85b114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b85b11424041c217a86cb3a197ce0646210592b2f068057b4b883c939634f42"
    family = "unknown"
    file_name = "xfsaild_sda"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:33"
  condition:
    hash.sha256(0, filesize) == "7b85b11424041c217a86cb3a197ce0646210592b2f068057b4b883c939634f42"
}

rule MalwareBazaar_unknown_047_64e27acb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e27acb5c452aed9f67c35e59bf503835d0f7197b70fdd56c4773751380275f"
    family = "unknown"
    file_name = "scsi_tmf_0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:30"
  condition:
    hash.sha256(0, filesize) == "64e27acb5c452aed9f67c35e59bf503835d0f7197b70fdd56c4773751380275f"
}

rule MalwareBazaar_unknown_048_2c380252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c380252e543a88730da5e5473b0234e0aa7ff2e99f1b0698141a980d08a73b9"
    family = "unknown"
    file_name = "edac_polld"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:29"
  condition:
    hash.sha256(0, filesize) == "2c380252e543a88730da5e5473b0234e0aa7ff2e99f1b0698141a980d08a73b9"
}

rule MalwareBazaar_unknown_049_d431302d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d431302d1890dbe576dd8a30fdd3a8aa4de1ec53f692b64553644c4a18470d99"
    family = "unknown"
    file_name = "zswap_shrinkd"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:29"
  condition:
    hash.sha256(0, filesize) == "d431302d1890dbe576dd8a30fdd3a8aa4de1ec53f692b64553644c4a18470d99"
}

rule MalwareBazaar_unknown_050_000575e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "000575e07e3657a767778a53587fd81b492fe02ea361e98de439e6345653071e"
    family = "unknown"
    file_name = "rcuop_0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:27"
  condition:
    hash.sha256(0, filesize) == "000575e07e3657a767778a53587fd81b492fe02ea361e98de439e6345653071e"
}

rule MalwareBazaar_unknown_051_602fd1e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602fd1e0a2ff3d5a0ce13f4301e93894c8f30ceeac4f344d371f1641baf08265"
    family = "unknown"
    file_name = "kswapd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:26"
  condition:
    hash.sha256(0, filesize) == "602fd1e0a2ff3d5a0ce13f4301e93894c8f30ceeac4f344d371f1641baf08265"
}

rule MalwareBazaar_unknown_052_d2676ac0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2676ac0a5290da1be5f312e7aaf992849c1a2c9e5bccb80b59a655de68f655b"
    family = "unknown"
    file_name = "kworker_u8"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:25"
  condition:
    hash.sha256(0, filesize) == "d2676ac0a5290da1be5f312e7aaf992849c1a2c9e5bccb80b59a655de68f655b"
}

rule MalwareBazaar_unknown_053_7cc605b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cc605b5fffa1478a286c2479f7c6f947fbf1ddf44bbf72f3028b4d62bb08dcb"
    family = "unknown"
    file_name = "ksoftirqd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:24"
  condition:
    hash.sha256(0, filesize) == "7cc605b5fffa1478a286c2479f7c6f947fbf1ddf44bbf72f3028b4d62bb08dcb"
}

rule MalwareBazaar_unknown_054_ed655d6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed655d6bbc9315067360982455b4d14d5ef0c5fdf7ead51550bac30e25414afa"
    family = "unknown"
    file_name = "kblockd0"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:24"
  condition:
    hash.sha256(0, filesize) == "ed655d6bbc9315067360982455b4d14d5ef0c5fdf7ead51550bac30e25414afa"
}

rule MalwareBazaar_unknown_055_97c458ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c458bad070c33011bd4e1500c208e72ee5c376e6f92dc42e81b676fef6dac8"
    family = "unknown"
    file_name = "jbd2_sda1d"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:23"
  condition:
    hash.sha256(0, filesize) == "97c458bad070c33011bd4e1500c208e72ee5c376e6f92dc42e81b676fef6dac8"
}

rule MalwareBazaar_unknown_056_39f26802
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39f268023db21296dfa4a259791d3d5bd559e29dfa588469ff5fa170b7c05f19"
    family = "unknown"
    file_name = "ecryptfsd"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:22"
  condition:
    hash.sha256(0, filesize) == "39f268023db21296dfa4a259791d3d5bd559e29dfa588469ff5fa170b7c05f19"
}

rule MalwareBazaar_unknown_057_5cf721b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cf721b03d29a2e45a8d9a917d86e89dc8ecd6000fd6d3a0398949421d20618a"
    family = "unknown"
    file_name = "devfreq_wq"
    file_type = "elf"
    first_seen = "2026-06-20 20:16:22"
  condition:
    hash.sha256(0, filesize) == "5cf721b03d29a2e45a8d9a917d86e89dc8ecd6000fd6d3a0398949421d20618a"
}

rule MalwareBazaar_unknown_058_ccc32204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccc32204d9b5248ee3971fad33c3becdc5c5d77fda668517203fed473ba8c748"
    family = "unknown"
    file_name = "Setup.zip"
    file_type = "zip"
    first_seen = "2026-06-20 20:12:42"
  condition:
    hash.sha256(0, filesize) == "ccc32204d9b5248ee3971fad33c3becdc5c5d77fda668517203fed473ba8c748"
}

rule MalwareBazaar_unknown_059_977d7204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "977d720443bbac5473d10ca314861eec8a6bf050b2be56485bc8d9c4766a4c7c"
    family = "unknown"
    file_name = "obfusticate me captian.zip"
    file_type = "zip"
    first_seen = "2026-06-20 20:11:11"
  condition:
    hash.sha256(0, filesize) == "977d720443bbac5473d10ca314861eec8a6bf050b2be56485bc8d9c4766a4c7c"
}

rule MalwareBazaar_unknown_060_7931ba55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7931ba55069255c1392a01a20633d0d4cff9afb6b029096ef421d2798ca61e5f"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-06-20 20:10:57"
  condition:
    hash.sha256(0, filesize) == "7931ba55069255c1392a01a20633d0d4cff9afb6b029096ef421d2798ca61e5f"
}

rule MalwareBazaar_unknown_061_531518f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "531518f1b8c7d743defda272598e38d65f902f89eb152b0881add72aaf5c2e08"
    family = "unknown"
    file_name = "cfg80211d"
    file_type = "elf"
    first_seen = "2026-06-20 20:10:43"
  condition:
    hash.sha256(0, filesize) == "531518f1b8c7d743defda272598e38d65f902f89eb152b0881add72aaf5c2e08"
}

rule MalwareBazaar_unknown_062_41541d2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41541d2b0efad921142ff74dae952e803c0cca19e8cc1df0b673b1ffb92162e6"
    family = "unknown"
    file_name = "bioset0"
    file_type = "elf"
    first_seen = "2026-06-20 20:10:40"
  condition:
    hash.sha256(0, filesize) == "41541d2b0efad921142ff74dae952e803c0cca19e8cc1df0b673b1ffb92162e6"
}

rule MalwareBazaar_unknown_063_d0b4aa15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0b4aa152d85c274ef213eedde09eaf75dcdcf4d4ef026a889d846f357d4c6d6"
    family = "unknown"
    file_name = "Axel.exe"
    file_type = "exe"
    first_seen = "2026-06-20 20:10:32"
  condition:
    hash.sha256(0, filesize) == "d0b4aa152d85c274ef213eedde09eaf75dcdcf4d4ef026a889d846f357d4c6d6"
}

rule MalwareBazaar_unknown_064_ad20b5dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad20b5dd23ef403b0f39c81ad354aa283409a43587ce90107ca8b6a0800bebc6"
    family = "unknown"
    file_name = "obfusticate me captian 2.txt"
    file_type = "unknown"
    first_seen = "2026-06-20 20:09:07"
  condition:
    hash.sha256(0, filesize) == "ad20b5dd23ef403b0f39c81ad354aa283409a43587ce90107ca8b6a0800bebc6"
}

rule MalwareBazaar_unknown_065_dabdb9d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dabdb9d1e9ef6ea07d8dd631461d4074d99030a59ae9b6746b750a51ddb9cdd3"
    family = "unknown"
    file_name = "obfusticate me captian.txt"
    file_type = "unknown"
    first_seen = "2026-06-20 20:08:50"
  condition:
    hash.sha256(0, filesize) == "dabdb9d1e9ef6ea07d8dd631461d4074d99030a59ae9b6746b750a51ddb9cdd3"
}

rule MalwareBazaar_unknown_066_1a16a081
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a16a08151ad1e698f53d70d36c0e5dafd9c2bbc3bd2710e5904f54b91aae128"
    family = "unknown"
    file_name = "grok.txt.lnk"
    file_type = "lnk"
    first_seen = "2026-06-20 20:04:20"
  condition:
    hash.sha256(0, filesize) == "1a16a08151ad1e698f53d70d36c0e5dafd9c2bbc3bd2710e5904f54b91aae128"
}

rule MalwareBazaar_unknown_067_06de9c0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06de9c0bc74686e8c244213d37cc4c7463a73ec3d86219e671b543fe3d8b2f97"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-20 20:03:49"
  condition:
    hash.sha256(0, filesize) == "06de9c0bc74686e8c244213d37cc4c7463a73ec3d86219e671b543fe3d8b2f97"
}

rule MalwareBazaar_unknown_068_02753168
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "027531689ffd282ce3e8b3dd6c68acfe8ec2466ed7e1354907b1983f0678c9d6"
    family = "unknown"
    file_name = "WeTransfer_Setup.msi"
    file_type = "unknown"
    first_seen = "2026-06-20 20:02:37"
  condition:
    hash.sha256(0, filesize) == "027531689ffd282ce3e8b3dd6c68acfe8ec2466ed7e1354907b1983f0678c9d6"
}

rule MalwareBazaar_unknown_069_a78dfed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a78dfed1650aef00f19f9b86d529d42500cb2202923169692a789bb7f3bb402b"
    family = "unknown"
    file_name = "Void-Loader.exe"
    file_type = "exe"
    first_seen = "2026-06-20 19:55:14"
  condition:
    hash.sha256(0, filesize) == "a78dfed1650aef00f19f9b86d529d42500cb2202923169692a789bb7f3bb402b"
}

rule MalwareBazaar_unknown_070_79f2856b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79f2856beb38aebc676db11193bef2912299b4ebc21da484e80e36024c3b377e"
    family = "unknown"
    file_name = "tftp.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:55:05"
  condition:
    hash.sha256(0, filesize) == "79f2856beb38aebc676db11193bef2912299b4ebc21da484e80e36024c3b377e"
}

rule MalwareBazaar_unknown_071_fa84bfb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa84bfb56f24194e953a3b800aafe918e99ce2d00d102049ab1f4b973a9f508d"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:55:05"
  condition:
    hash.sha256(0, filesize) == "fa84bfb56f24194e953a3b800aafe918e99ce2d00d102049ab1f4b973a9f508d"
}

rule MalwareBazaar_unknown_072_f9e57e75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9e57e757b896deab77b71e725055453328fffb613b59c130ce90eb14e0befc7"
    family = "unknown"
    file_name = "ftpget.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:54:59"
  condition:
    hash.sha256(0, filesize) == "f9e57e757b896deab77b71e725055453328fffb613b59c130ce90eb14e0befc7"
}

rule MalwareBazaar_unknown_073_673337ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "673337ea6fb0eba12c2e7abe1447878e7f9ee63dad296aa8ed47578bb0c1f039"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-06-20 19:54:58"
  condition:
    hash.sha256(0, filesize) == "673337ea6fb0eba12c2e7abe1447878e7f9ee63dad296aa8ed47578bb0c1f039"
}

rule MalwareBazaar_unknown_074_2e1369bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e1369bc8343db24f34e4a309ba1a0efbd181150f0e2d7ddb153e179e2659773"
    family = "unknown"
    file_name = "ProfitInvext_CRM_API_Documentation.zip"
    file_type = "zip"
    first_seen = "2026-06-20 19:52:50"
  condition:
    hash.sha256(0, filesize) == "2e1369bc8343db24f34e4a309ba1a0efbd181150f0e2d7ddb153e179e2659773"
}

rule MalwareBazaar_unknown_075_7ccbda56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ccbda568ff313b5e75d20b3bad6b9191a5f5b53eb867d05150c732f5cb039c2"
    family = "unknown"
    file_name = "إعداد_القادة.pdf.zip"
    file_type = "zip"
    first_seen = "2026-06-20 19:47:22"
  condition:
    hash.sha256(0, filesize) == "7ccbda568ff313b5e75d20b3bad6b9191a5f5b53eb867d05150c732f5cb039c2"
}

rule MalwareBazaar_Prometei_076_ec2c3ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c"
    family = "Prometei"
    file_name = "ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c"
    file_type = "elf"
    first_seen = "2026-06-20 19:45:42"
  condition:
    hash.sha256(0, filesize) == "ec2c3ddffdc0ff40a4d9c59c03221733b80fe36bb706bcbb9aa4650e05e96a5c"
}

rule MalwareBazaar_unknown_077_d9115ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9115ff47fa9506711bc9c734e8b96125f18f48a5217ccbc1f057b2ce51a465e"
    family = "unknown"
    file_name = "Radiology_MRI_Brain_Final_Report_Signed.lnk"
    file_type = "lnk"
    first_seen = "2026-06-20 19:43:07"
  condition:
    hash.sha256(0, filesize) == "d9115ff47fa9506711bc9c734e8b96125f18f48a5217ccbc1f057b2ce51a465e"
}

rule MalwareBazaar_RustyStealer_078_c06c3002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c06c3002302f47202884762c57982d86718ba4500699e9ef37d5cd513c6e8bf8"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:32:49"
  condition:
    hash.sha256(0, filesize) == "c06c3002302f47202884762c57982d86718ba4500699e9ef37d5cd513c6e8bf8"
}

rule MalwareBazaar_unknown_079_dacf7be1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dacf7be18ad926cb2008f1a139439add5917bbded18e1b303bc7dd5c63cf4402"
    family = "unknown"
    file_name = "dxon-atualizador-acesso.zip"
    file_type = "zip"
    first_seen = "2026-06-20 19:30:32"
  condition:
    hash.sha256(0, filesize) == "dacf7be18ad926cb2008f1a139439add5917bbded18e1b303bc7dd5c63cf4402"
}

rule MalwareBazaar_unknown_080_e462eb41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e462eb417f3ebe66041226a9d05174353889f1d189d71be1fa0559b0b40f8c79"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30483.9391"
    file_type = "elf"
    first_seen = "2026-06-20 19:21:48"
  condition:
    hash.sha256(0, filesize) == "e462eb417f3ebe66041226a9d05174353889f1d189d71be1fa0559b0b40f8c79"
}

rule MalwareBazaar_unknown_081_ed6b9a8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed6b9a8c2e638fc92a10cc88a0228e0c1dc088d5a28bb790f322137680b123f0"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30872.16543"
    file_type = "elf"
    first_seen = "2026-06-20 19:21:45"
  condition:
    hash.sha256(0, filesize) == "ed6b9a8c2e638fc92a10cc88a0228e0c1dc088d5a28bb790f322137680b123f0"
}

rule MalwareBazaar_RemusStealer_082_0e690264
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6902640affe9ac58c39d52046a073741b8e77a6ad29137bdeb6f8cf8222964"
    family = "RemusStealer"
    file_name = "SecuriteInfo.com.Win32.Dh-A.39239491"
    file_type = "exe"
    first_seen = "2026-06-20 19:20:50"
  condition:
    hash.sha256(0, filesize) == "0e6902640affe9ac58c39d52046a073741b8e77a6ad29137bdeb6f8cf8222964"
}

rule MalwareBazaar_unknown_083_ea6bdceb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea6bdcebcb553f5089383938412f2e4010ea74ae1e6543b923cad89563c7a6cf"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.13139.19924"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:48"
  condition:
    hash.sha256(0, filesize) == "ea6bdcebcb553f5089383938412f2e4010ea74ae1e6543b923cad89563c7a6cf"
}

rule MalwareBazaar_unknown_084_915d8baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "915d8baa66a420bd67b75a9d6152ab99036c16d29f1b73b2ad4d8e3dbae382e2"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30483.9391"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:45"
  condition:
    hash.sha256(0, filesize) == "915d8baa66a420bd67b75a9d6152ab99036c16d29f1b73b2ad4d8e3dbae382e2"
}

rule MalwareBazaar_unknown_085_d3d74f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3d74f36518d6bb59929f9f1601b90520e6228877ab30787e97acd857e38cf2e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Linux.BackDoor.Armada.1.30872.16543"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:43"
  condition:
    hash.sha256(0, filesize) == "d3d74f36518d6bb59929f9f1601b90520e6228877ab30787e97acd857e38cf2e"
}

rule MalwareBazaar_Mirai_086_7165ccfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7165ccfa91053dd6c0141ff42a6d92eeb8d19d582b0f57188ae305ec43235d32"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.BitCoinMiner-HF.67986673"
    file_type = "elf"
    first_seen = "2026-06-20 19:20:41"
  condition:
    hash.sha256(0, filesize) == "7165ccfa91053dd6c0141ff42a6d92eeb8d19d582b0f57188ae305ec43235d32"
}

rule MalwareBazaar_unknown_087_8b0ef90a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0ef90a42476f8df2eae4c3e271fbb558a5d136d22e4e6f87e138b6d3281a08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:15:12"
  condition:
    hash.sha256(0, filesize) == "8b0ef90a42476f8df2eae4c3e271fbb558a5d136d22e4e6f87e138b6d3281a08"
}

rule MalwareBazaar_RemusStealer_088_526ae427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "526ae427fececcdfb7d231d95a3a4f3ffa83c130ed5d58192daad06510f4ee69"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:07:30"
  condition:
    hash.sha256(0, filesize) == "526ae427fececcdfb7d231d95a3a4f3ffa83c130ed5d58192daad06510f4ee69"
}

rule MalwareBazaar_unknown_089_5390c32d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5390c32de7ad5886330c7e66667b41ed652e1e0e9411591c4d9be1d40e2fdb01"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-20 19:04:38"
  condition:
    hash.sha256(0, filesize) == "5390c32de7ad5886330c7e66667b41ed652e1e0e9411591c4d9be1d40e2fdb01"
}

rule MalwareBazaar_RustyStealer_090_1ce931d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ce931d621b70d14bdc90b5dcb8dc8cfce60e027f60eb2ff895c60efeb8ffbe7"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-20 19:02:00"
  condition:
    hash.sha256(0, filesize) == "1ce931d621b70d14bdc90b5dcb8dc8cfce60e027f60eb2ff895c60efeb8ffbe7"
}

rule MalwareBazaar_Mirai_091_b187869c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b187869c3dc6e0f1c3b6666867c26be9d5e728ac8b0aa88554078ad3feee2003"
    family = "Mirai"
    file_name = "bin.m68k"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:53"
  condition:
    hash.sha256(0, filesize) == "b187869c3dc6e0f1c3b6666867c26be9d5e728ac8b0aa88554078ad3feee2003"
}

rule MalwareBazaar_Mirai_092_4d4e52f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d4e52f75a6ed80e486a147d377c308ac5cd111cae7b775d7a4f33bd38248c1b"
    family = "Mirai"
    file_name = "bin.armv4eb"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:51"
  condition:
    hash.sha256(0, filesize) == "4d4e52f75a6ed80e486a147d377c308ac5cd111cae7b775d7a4f33bd38248c1b"
}

rule MalwareBazaar_Mirai_093_7d8a76a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d8a76a128030322c8c2a6a8a618a318f65bb4f90dc9438999e23c99f3dc6760"
    family = "Mirai"
    file_name = "bin.i586"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:50"
  condition:
    hash.sha256(0, filesize) == "7d8a76a128030322c8c2a6a8a618a318f65bb4f90dc9438999e23c99f3dc6760"
}

rule MalwareBazaar_Mirai_094_7d25396b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d25396b6d7fb9cef476ea318eae9a8c89fdffed92616b7792af5298214d5b91"
    family = "Mirai"
    file_name = "bin.armv6l"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:48"
  condition:
    hash.sha256(0, filesize) == "7d25396b6d7fb9cef476ea318eae9a8c89fdffed92616b7792af5298214d5b91"
}

rule MalwareBazaar_Mirai_095_1d99ff30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d99ff30758e487264c3550c2b0c3c37646e772266882809898a2ed0c5f74c4b"
    family = "Mirai"
    file_name = "bin.mips"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:46"
  condition:
    hash.sha256(0, filesize) == "1d99ff30758e487264c3550c2b0c3c37646e772266882809898a2ed0c5f74c4b"
}

rule MalwareBazaar_Mirai_096_08566baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08566baf2de3d75a6161ffce3611c07b15029faa32c3225dfa8409e6b2b7828a"
    family = "Mirai"
    file_name = "bin.i486"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:45"
  condition:
    hash.sha256(0, filesize) == "08566baf2de3d75a6161ffce3611c07b15029faa32c3225dfa8409e6b2b7828a"
}

rule MalwareBazaar_Mirai_097_8797ddcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8797ddcc018291354d75d56ba44b6dcdef8d8e4b593dd92a859d63200248bb76"
    family = "Mirai"
    file_name = "bin.armv7l"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:43"
  condition:
    hash.sha256(0, filesize) == "8797ddcc018291354d75d56ba44b6dcdef8d8e4b593dd92a859d63200248bb76"
}

rule MalwareBazaar_Mirai_098_a6ec2337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6ec23370de4e1849d6e91f60494fd39c6069f25b963110cb13cb60c371e8512"
    family = "Mirai"
    file_name = "bin.powerpc"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:42"
  condition:
    hash.sha256(0, filesize) == "a6ec23370de4e1849d6e91f60494fd39c6069f25b963110cb13cb60c371e8512"
}

rule MalwareBazaar_Mirai_099_731aa53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731aa53e556fe38caf0f74bd6cbb249e35648643c295cadfdf902afd392f3b41"
    family = "Mirai"
    file_name = "bin.powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:40"
  condition:
    hash.sha256(0, filesize) == "731aa53e556fe38caf0f74bd6cbb249e35648643c295cadfdf902afd392f3b41"
}

rule MalwareBazaar_Mirai_100_2ae77957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae7795781a76b073d3aa3533a6bfc647114cc1462e701bfff289f6d7ce55d4e"
    family = "Mirai"
    file_name = "bin.armv5l"
    file_type = "elf"
    first_seen = "2026-06-20 18:58:39"
  condition:
    hash.sha256(0, filesize) == "2ae7795781a76b073d3aa3533a6bfc647114cc1462e701bfff289f6d7ce55d4e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

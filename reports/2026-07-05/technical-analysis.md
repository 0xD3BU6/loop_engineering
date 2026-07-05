# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-05

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 692 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 692 |
| Unique family labels | 10 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 35 |
| Vidar | 32 |
| Mirai | 22 |
| MaskGramStealer | 3 |
| SalatStealer | 3 |
| NanoCore | 1 |
| Gafgyt | 1 |
| Stealc | 1 |
| CoinMiner | 1 |
| RemusStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 64 |
| elf | 25 |
| zip | 3 |
| 7z | 2 |
| sh | 2 |
| msi | 2 |
| dll | 1 |
| unknown | 1 |

## Per-Sample Analysis

### Sample 1: `551aa018350fcf2b`

| Field | Value |
|---|---|
| SHA-256 | `551aa018350fcf2b435b4d361dd4f117349a5136851f84ac10c02da1526e4e67` |
| Family label | `NanoCore` |
| File name | `sales-tracker.io.exe` |
| File type | `exe` |
| First seen | `2026-07-05 04:05:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e3bb978d68490c99faac7f590933832` |
| SHA-1 | `c9970f57910e5e2bb746d838ab0f248bdfa1e15b` |
| SHA-256 | `551aa018350fcf2b435b4d361dd4f117349a5136851f84ac10c02da1526e4e67` |
| SHA3-384 | `e52530c2813f2e728c999d3afe7384591889ced31b3fb0704a8b149f8a543d8f7648110cff58e4e57b00ae664cbfe6ce` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14414CF2A77A84A2FE2DE85B9611211538378C2E3DCC3F3EE18D855B35B663E50A071D7` |
| SSDEEP | `3072:MzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HI2asvu1SEImfAF8V7m8CJvflRa:MLV6Bta6dtJmakIM5JuvImfVqflRj0vR` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_001_551aa018
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "551aa018350fcf2b435b4d361dd4f117349a5136851f84ac10c02da1526e4e67"
    family = "NanoCore"
    file_name = "sales-tracker.io.exe"
    file_type = "exe"
    first_seen = "2026-07-05 04:05:05"
  condition:
    hash.sha256(0, filesize) == "551aa018350fcf2b435b4d361dd4f117349a5136851f84ac10c02da1526e4e67"
}
```

### Sample 2: `d9f15a43821328bf`

| Field | Value |
|---|---|
| SHA-256 | `d9f15a43821328bf482e2945ff9da40fa05f382777819d8e9fa3aaae8704862d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-05 03:51:59` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba3544437b369bbd4687a2ce30077a3f` |
| SHA-1 | `612fb6725b2c4b8f2c0edf6a2de5b1e53c8b8a76` |
| SHA-256 | `d9f15a43821328bf482e2945ff9da40fa05f382777819d8e9fa3aaae8704862d` |
| SHA3-384 | `0189377bf0332b59c8df2d905916b49acb3063368ea8d6ba09fafb6780dcfefffcf76aea463436860b87fdf9af67aef3` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T10FE63318ABE001FEE9B7813C9DE19652D1B0B8651B61CEDF2798D7716E532E08C38B17` |
| SSDEEP | `393216:IPHX1Bpawu+ifaDgNDXMCHWUjXFcuI3/PGTAI:I/lBzbpDYDXMb8XyH/O7` |
| ICON-DHASH | `b2f1e8cccce871b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_d9f15a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9f15a43821328bf482e2945ff9da40fa05f382777819d8e9fa3aaae8704862d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 03:51:59"
  condition:
    hash.sha256(0, filesize) == "d9f15a43821328bf482e2945ff9da40fa05f382777819d8e9fa3aaae8704862d"
}
```

### Sample 3: `f193b47f2739aaa3`

| Field | Value |
|---|---|
| SHA-256 | `f193b47f2739aaa35c0ecec5d2731dc7d343c200340015e4a2bff663c3041512` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-05 03:12:53` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4be39027f6e94c46bf4307f6762d8b98` |
| SHA-1 | `def05ff2de5bf7d550e6230c19480bae253d8043` |
| SHA-256 | `f193b47f2739aaa35c0ecec5d2731dc7d343c200340015e4a2bff663c3041512` |
| SHA3-384 | `38c3c1e8373f8bd2b80f47f8102be068f05c45ce550aa878b7b379b136fd8442dd3daebb6d9005487b48ede88746dc54` |
| IMPHASH | `20f35ed688f00eacb2c7ea603d9f248e` |
| TLSH | `T10E24292BD25375FCE552C03852667232BB32BA3D47309EF70392D7359D21AC0AE79A25` |
| SSDEEP | `3072:9SziFM0L3isiMJbXeEyqAbAMym8D68pnqWrrorGkM54Yqn:cilJjOvB8DHAWH8HYq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_f193b47f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f193b47f2739aaa35c0ecec5d2731dc7d343c200340015e4a2bff663c3041512"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-05 03:12:53"
  condition:
    hash.sha256(0, filesize) == "f193b47f2739aaa35c0ecec5d2731dc7d343c200340015e4a2bff663c3041512"
}
```

### Sample 4: `11936fb09c6770b6`

| Field | Value |
|---|---|
| SHA-256 | `11936fb09c6770b658ce5335e704bdba76722e1282eb53630beca2e007bb0850` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-05 02:55:13` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, push-telemetryportal-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a4c99ebd4cc814064ef6b209e8aa874` |
| SHA-1 | `51c6fa57c0590d67f12565dbf43a8b35e9935ebf` |
| SHA-256 | `11936fb09c6770b658ce5335e704bdba76722e1282eb53630beca2e007bb0850` |
| SHA3-384 | `91819d9e62fc9beafe435ded412f03e399c826e0b2a5ca2dd328eef9e0a27e0924b52cec5f04867a98f075791242efaf` |
| TLSH | `T10EF63386A4B21FD6D89C013D81AF8B47639ABB074043936B5764E36B3FF37F19929940` |
| SSDEEP | `393216:2UPTC40OSoynIC24FYlry7NTnhA+Trw6NXC8eFBT:+40O1yt24HhTh5TrnXC8ej` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_11936fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11936fb09c6770b658ce5335e704bdba76722e1282eb53630beca2e007bb0850"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-05 02:55:13"
  condition:
    hash.sha256(0, filesize) == "11936fb09c6770b658ce5335e704bdba76722e1282eb53630beca2e007bb0850"
}
```

### Sample 5: `c016fd7194859f51`

| Field | Value |
|---|---|
| SHA-256 | `c016fd7194859f518e61b204e9df51a683959a28399bd88ec0f7b7f30858f133` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-05 02:53:21` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, push-telemetryportal-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1824c5e2e9ade06e617a7e061fc8633` |
| SHA-1 | `b0f7017a9b3ddbd3c9caaecfb19a18c18f628465` |
| SHA-256 | `c016fd7194859f518e61b204e9df51a683959a28399bd88ec0f7b7f30858f133` |
| SHA3-384 | `49e928c04ae8349e7100ac34a022c3ccbd0704a8961508ae7020518a22acd4eee207e7933d2d32a0656a24fa6113f89d` |
| TLSH | `T1F57723697A2D340BF9D18BFD94E539CC2167258849912E2F9F2F4471F673319BC3A822` |
| SSDEEP | `786432:eak7U8EBheCm/Pk+fDInMSnAZolgT9Tlltn2Fk8jB:eaQEBheCm/8eMhnAWlghLtn2F1B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_c016fd71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c016fd7194859f518e61b204e9df51a683959a28399bd88ec0f7b7f30858f133"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-05 02:53:21"
  condition:
    hash.sha256(0, filesize) == "c016fd7194859f518e61b204e9df51a683959a28399bd88ec0f7b7f30858f133"
}
```

### Sample 6: `422c55e0219b09d0`

| Field | Value |
|---|---|
| SHA-256 | `422c55e0219b09d0262782b25420c601304f5d1b46a325f2b4859ef77244ff42` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-05 02:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99755cc0b98e663e73aac9be9aa33c13` |
| SHA-1 | `116af423f975819cd0668484d7e0fb7c83460fb8` |
| SHA-256 | `422c55e0219b09d0262782b25420c601304f5d1b46a325f2b4859ef77244ff42` |
| SHA3-384 | `1e68754c7a75f002e349aaf2deffe72df03e71a049307d0b8aac8602a99f3456e5c6a2f8cfd1870aec4b853d6f23c7d3` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F4E63359A0D001EED533843CFE6185F2D56934A95BB2CA8F1BD4D3E1BC5B2E04E3A64B` |
| SSDEEP | `393216:WcPtPJhURu1YY0WpZYmPxz48ITXMCHWUjXWcuI3/PGTAI:Wclf9R5z4zTXMb8XrH/O7` |
| ICON-DHASH | `f0f8cc8682c6f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_422c55e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "422c55e0219b09d0262782b25420c601304f5d1b46a325f2b4859ef77244ff42"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 02:52:11"
  condition:
    hash.sha256(0, filesize) == "422c55e0219b09d0262782b25420c601304f5d1b46a325f2b4859ef77244ff42"
}
```

### Sample 7: `720035e8c6cfb6cd`

| Field | Value |
|---|---|
| SHA-256 | `720035e8c6cfb6cdc35041b7f6fd3883d2dc4821aad56e39f3ca0f2947e2dc8e` |
| Family label | `unknown` |
| File name | `recuva_professional__technician_(2026)_full_español_[mega].7z` |
| File type | `7z` |
| First seen | `2026-07-05 02:52:10` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-2699, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f344e4d3d76ac6712ddc17a7ac284da3` |
| SHA-1 | `a73bfde9e33db85ab272a2e3b883879fd4c20824` |
| SHA-256 | `720035e8c6cfb6cdc35041b7f6fd3883d2dc4821aad56e39f3ca0f2947e2dc8e` |
| SHA3-384 | `ec393ad46be06563649806bc65adc6184eb63d7fe8163cb0684bac53c75974999e77da162157a34c9a1277d5a6b4ea5e` |
| TLSH | `T161073387B71B2C0FC7264D819618BBC2E7FE2B726604DEB1456CDC31B88D598A1F598C` |
| SSDEEP | `393216:aFCt9xmBrjQ5+4X0w1H5E98jVH8/UB0+3xM0DnR/hj0yUBM6/xSX:aWDrXbN5EgH2CRBzJYyEM+s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_720035e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "720035e8c6cfb6cdc35041b7f6fd3883d2dc4821aad56e39f3ca0f2947e2dc8e"
    family = "unknown"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-07-05 02:52:10"
  condition:
    hash.sha256(0, filesize) == "720035e8c6cfb6cdc35041b7f6fd3883d2dc4821aad56e39f3ca0f2947e2dc8e"
}
```

### Sample 8: `134385f37bc37813`

| Field | Value |
|---|---|
| SHA-256 | `134385f37bc37813bd7b811a628b700d0791c31c2ea0f2cf037d2463e02976f3` |
| Family label | `unknown` |
| File name | `cx-programmer 9.1 free download full.7z` |
| File type | `7z` |
| First seen | `2026-07-05 02:50:57` |
| Reporter | `iamaachum` |
| Tags | `7z, file-pumped, pw-3179, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fafe52bd2c298f8b7a88ecc8778fd098` |
| SHA-1 | `659251f9149677fb5515b3ce45078fba2dd7f2c2` |
| SHA-256 | `134385f37bc37813bd7b811a628b700d0791c31c2ea0f2cf037d2463e02976f3` |
| SHA3-384 | `a46a39c239f128fcc9f2954442c4bd1cd07e45ec4b3654f6cf16ac807064ff1d503abb515a58eaf3faabdb06820a4b1b` |
| TLSH | `T12107337180058ACA3A332CB87B35621A1D75C6197A2CE0DD3E6F91AC0BDE65D4B4DBD3` |
| SSDEEP | `393216:73nIZmav9nMUy7xTt/hqsGeQOuR47lOpPRA/65VFPoTq/NrSC:73YmalnI7x+sxQ9yYRZGG/lSC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_134385f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "134385f37bc37813bd7b811a628b700d0791c31c2ea0f2cf037d2463e02976f3"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-07-05 02:50:57"
  condition:
    hash.sha256(0, filesize) == "134385f37bc37813bd7b811a628b700d0791c31c2ea0f2cf037d2463e02976f3"
}
```

### Sample 9: `6cb7fd54f66b99cc`

| Field | Value |
|---|---|
| SHA-256 | `6cb7fd54f66b99cc623bfc38f8aed37b87e36a59882ea770ce30c825bbbe754b` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-05 02:49:26` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, releases-cloudgateway-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62fbcb5eed035d28a3cd95bce4c81bdc` |
| SHA-1 | `4485ba9c695d1d711f5c4fa8d9f255582c5969a9` |
| SHA-256 | `6cb7fd54f66b99cc623bfc38f8aed37b87e36a59882ea770ce30c825bbbe754b` |
| SHA3-384 | `a1432f08141c22d9b1cbc9f1ac8840028fabc14404a3ea1945a30c3be1630053d1c07a891ecc7bef7dab43fd74bd6b27` |
| TLSH | `T17C573328F8963A61EC4DC5B406B02DA403F06D76037B5BC42374746FA667FAE9B34A35` |
| SSDEEP | `786432:SnPIL9OBHBS1Rz9t0EZOWUietXPaVr0VYze8n5jZtzI:rAST4ie+0cei5ltI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_6cb7fd54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cb7fd54f66b99cc623bfc38f8aed37b87e36a59882ea770ce30c825bbbe754b"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-05 02:49:26"
  condition:
    hash.sha256(0, filesize) == "6cb7fd54f66b99cc623bfc38f8aed37b87e36a59882ea770ce30c825bbbe754b"
}
```

### Sample 10: `befaa63b031753c4`

| Field | Value |
|---|---|
| SHA-256 | `befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec` |
| Family label | `Gafgyt` |
| File name | `befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec` |
| File type | `elf` |
| First seen | `2026-07-05 02:09:45` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46505a7f012438e9cd7cb8af114530ec` |
| SHA-1 | `0afdd25eea1c82c4fd134a5c914769d20f86b5b6` |
| SHA-256 | `befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec` |
| SHA3-384 | `22e2ce5564c1fd51fc4f84b29d2a089b7ae009d07aa59825a2059a764df6cd079ca392ceb87579c07365ad2433c56760` |
| TLSH | `T1C744C71A3A11DFBFF56D863107B38A3047D9769626E1934AF25CD71C1E2028E681FBE4` |
| TELFHASH | `t144713158d43d09e9eea35d19a8692bf34993e12926f46b18ff66cdc0081f42df224d0f` |
| SSDEEP | `3072:dNFNVpJHJ4vqUagT10PJCRZUSlY9E+YlyrbT+Zy7KwmtwAL4OObI:FXGEgCPJaZdd+nbT+Zy7KwmtwAL4OObI` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_010_befaa63b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec"
    family = "Gafgyt"
    file_name = "befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec"
    file_type = "elf"
    first_seen = "2026-07-05 02:09:45"
  condition:
    hash.sha256(0, filesize) == "befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec"
}
```

### Sample 11: `8e8580be4c0807a0`

| Field | Value |
|---|---|
| SHA-256 | `8e8580be4c0807a0141da1e7cddf1763fea514408897d1bf2f7e298198525437` |
| Family label | `Mirai` |
| File name | `Mozi.m` |
| File type | `elf` |
| First seen | `2026-07-05 02:04:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9e1d4cc3a9a9d3bdc54baf112077bd1` |
| SHA-1 | `051ee2689c553541c235bdfdc7be8d1802876c6d` |
| SHA-256 | `8e8580be4c0807a0141da1e7cddf1763fea514408897d1bf2f7e298198525437` |
| SHA3-384 | `bdc838dd6093d247e35f1d4bf626bc8b898a554ee681ad32df74ae34a812cdfcb30a24b38f6af0d791b07d34c4189fe6` |
| TLSH | `T10244398AFD81AF25D5C5227BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_8e8580be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e8580be4c0807a0141da1e7cddf1763fea514408897d1bf2f7e298198525437"
    family = "Mirai"
    file_name = "Mozi.m"
    file_type = "elf"
    first_seen = "2026-07-05 02:04:13"
  condition:
    hash.sha256(0, filesize) == "8e8580be4c0807a0141da1e7cddf1763fea514408897d1bf2f7e298198525437"
}
```

### Sample 12: `ccbf818a36523c19`

| Field | Value |
|---|---|
| SHA-256 | `ccbf818a36523c19051d066f8e5edad655a478516afc916cd915aacca80dbcd2` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-05 01:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69ac856f989a3dc0d8bff532c6f7f331` |
| SHA-1 | `a6b87c3a216ef6e26d483fa69151174b27a7c6f8` |
| SHA-256 | `ccbf818a36523c19051d066f8e5edad655a478516afc916cd915aacca80dbcd2` |
| SHA3-384 | `4ca9e45a79b540a544f44c92096fa5cf077122ca2948cc3eb191af546914302fd36e0fb790ad65d65d7da7097fae6067` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E0E633545AC001FEECB7513CBEE14695D5A8F4BA4733C5AB439CA3622D271F08E3A762` |
| SSDEEP | `393216:5PT923iF69GT0Y+XSDOhSXMCHWUjX+cuI3/PGTAI:5LkSg9GkaXMb8XzH/O7` |
| ICON-DHASH | `71f0f0d8f8e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_ccbf818a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccbf818a36523c19051d066f8e5edad655a478516afc916cd915aacca80dbcd2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 01:52:10"
  condition:
    hash.sha256(0, filesize) == "ccbf818a36523c19051d066f8e5edad655a478516afc916cd915aacca80dbcd2"
}
```

### Sample 13: `5c8dcfaf72d826e5`

| Field | Value |
|---|---|
| SHA-256 | `5c8dcfaf72d826e5e944b2b3c5a5f19c52f5d254e4f7de5a0a385354e778e955` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-05 01:28:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b5e9ea4ed0ba0fd94033b766b6eb1b5` |
| SHA-1 | `68d325d7b2c6b63cba75ce6113c32890b007ca26` |
| SHA-256 | `5c8dcfaf72d826e5e944b2b3c5a5f19c52f5d254e4f7de5a0a385354e778e955` |
| SHA3-384 | `d6054942b0b4aa3ed6555598c09809947ede1159556d88f113685720363e2f0eeb4a15be30166b806366e3871762d5e0` |
| TLSH | `T1BC144AC3F900DDBEF80AE73784134915B130B7A214925B37B257797BAC3A19A1467F8A` |
| SSDEEP | `3072:29/k/QZzZKBITD6KATgmgM91XAD6MYmTQ1ci1wVejbiUL/4RzyqC0niS:mM/QZOICHgM91QDXlNi1jL/gyqcS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_5c8dcfaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8dcfaf72d826e5e944b2b3c5a5f19c52f5d254e4f7de5a0a385354e778e955"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-05 01:28:13"
  condition:
    hash.sha256(0, filesize) == "5c8dcfaf72d826e5e944b2b3c5a5f19c52f5d254e4f7de5a0a385354e778e955"
}
```

### Sample 14: `848b460096ecaeaf`

| Field | Value |
|---|---|
| SHA-256 | `848b460096ecaeaf40ed9399c67650a0914967cd8ba35a3e59fbd372ddc2a7ee` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-05 01:28:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fecfd4c8d58252abb469f6cc26414701` |
| SHA-1 | `837578bac7e060af6ba7337b174f0a88a0a70875` |
| SHA-256 | `848b460096ecaeaf40ed9399c67650a0914967cd8ba35a3e59fbd372ddc2a7ee` |
| SHA3-384 | `4575dde256588066da97ac57f14ad701e99c5bd9005d07a47ae8761e1066f8650c80a7cf3c13b2acdf5c11183625d755` |
| TLSH | `T16A236C6516853C24AE99C4375C7F2F0CB9A983E6314491DDBFCA3CF28C4AA9CE21875D` |
| SSDEEP | `768:Yr9NyXsZztCx9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:GHusZ7cB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_848b4600
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "848b460096ecaeaf40ed9399c67650a0914967cd8ba35a3e59fbd372ddc2a7ee"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-05 01:28:12"
  condition:
    hash.sha256(0, filesize) == "848b460096ecaeaf40ed9399c67650a0914967cd8ba35a3e59fbd372ddc2a7ee"
}
```

### Sample 15: `d1bc8967a413300d`

| Field | Value |
|---|---|
| SHA-256 | `d1bc8967a413300d080ab7720d597511c1885912f35f6b11e4462dc12eb314ef` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-05 01:15:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7feb34857e0f3ad6c939c0e9e7d4f65b` |
| SHA-1 | `f2bea48e8eec792f90bba98e5f8e1852ed8fae77` |
| SHA-256 | `d1bc8967a413300d080ab7720d597511c1885912f35f6b11e4462dc12eb314ef` |
| SHA3-384 | `222afa436d8a797f5004c261a4e33992728caa62b3cb192ed8357cda0e0df11156ea9476ab5871c7404c4e3b82b70927` |
| TLSH | `T1F734C61F6F228F6EF269CB7447B74E35975C23D622E1D684D2ACD2101E6028E541FBB8` |
| TELFHASH | `t13641a4180d7813b0a6656c5d089def27d6a731db7e1b6c238e50e86eeb69f838d14d0c` |
| SSDEEP | `3072:jXzW5U6H5df8GyIzXBOud7stJMxJtnbCl6NGU47loJ2:jXSSG5dWIrI8xHbCl6IHloJ2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_d1bc8967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1bc8967a413300d080ab7720d597511c1885912f35f6b11e4462dc12eb314ef"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-05 01:15:08"
  condition:
    hash.sha256(0, filesize) == "d1bc8967a413300d080ab7720d597511c1885912f35f6b11e4462dc12eb314ef"
}
```

### Sample 16: `dc3f3a497e0c23bb`

| Field | Value |
|---|---|
| SHA-256 | `dc3f3a497e0c23bb74713d90a4a4da901c4ad3f2062af803af03179c78726df2` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-05 01:11:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7350c957c8fca2cfca4b7807efa9c43` |
| SHA-1 | `1839a62746ef12f775b5be1ecf99df0cff9a2a05` |
| SHA-256 | `dc3f3a497e0c23bb74713d90a4a4da901c4ad3f2062af803af03179c78726df2` |
| SHA3-384 | `c54f3d0e8ccd8b5c2162f3fdff44704660774ed8730d8d8a816cf1e154ec786fc6d199e0231835b9bfad9858e9f7976c` |
| TLSH | `T1B6042945F9819A17C6C612BBFB5E428D372A13A8D3EE3103DD255F2137DB96B0A3B241` |
| TELFHASH | `t1c1a00219cfb816eb710258c6ccc3406fe1b72499134164098f359646bdc20b8b1679b2` |
| SSDEEP | `3072:acqDKVGmkvM9wPexJOMcU4OjIarfJDNCEm886:3Vl9/DZcU4OMar9NrT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_dc3f3a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc3f3a497e0c23bb74713d90a4a4da901c4ad3f2062af803af03179c78726df2"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-05 01:11:05"
  condition:
    hash.sha256(0, filesize) == "dc3f3a497e0c23bb74713d90a4a4da901c4ad3f2062af803af03179c78726df2"
}
```

### Sample 17: `46880af4b7bbb74d`

| Field | Value |
|---|---|
| SHA-256 | `46880af4b7bbb74def06569aecda2d96702de4b8b7723b05af927674928ce327` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-05 00:52:25` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43e647b9d685e1e5be276026df86d7e4` |
| SHA-1 | `3acbcfe403d42d59ce337403a39201cad1107ad4` |
| SHA-256 | `46880af4b7bbb74def06569aecda2d96702de4b8b7723b05af927674928ce327` |
| SHA3-384 | `e631b45e685fae733c81b10dbdd79916704e1291ca99819b1d30929d1f226d13db645fe48be66a106b3126ad5cce6b29` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1FDE6332CEBE006FFD6730035EA66A199E56578221BB1C58F279897C66D833E08C3D753` |
| SSDEEP | `393216:ybO0JfWO7BcqDFCa3ETsCuIxH3XMCHWUjXMcuI3/PGTAI:ybJetqDFCF3RXMb8XZH/O7` |
| ICON-DHASH | `5479d0f0e0e870b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_46880af4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46880af4b7bbb74def06569aecda2d96702de4b8b7723b05af927674928ce327"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 00:52:25"
  condition:
    hash.sha256(0, filesize) == "46880af4b7bbb74def06569aecda2d96702de4b8b7723b05af927674928ce327"
}
```

### Sample 18: `b74f6ba6f0a2fd99`

| Field | Value |
|---|---|
| SHA-256 | `b74f6ba6f0a2fd9969cea27d371567823fd7b9a6ffe14aa5347adc63d70fc1e3` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-05 00:51:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4ea7c23112be168a7783fa48934ec03` |
| SHA-1 | `6fbb277168511b63056d2b813e50aca018a24e5b` |
| SHA-256 | `b74f6ba6f0a2fd9969cea27d371567823fd7b9a6ffe14aa5347adc63d70fc1e3` |
| SHA3-384 | `2c2ccb82b72aabc877ffd22078c10258e6e983f4f35e561b13be8f12996811950e5b77f669ead88850f6d0c72f35952a` |
| TLSH | `T11634F80AAB610EFBECAFCD3701E90B0524CC645622A53F367674D918F94A54F4AE3D78` |
| SSDEEP | `3072:O/k9Epohhkm43gXAy6XboWgXGXzgR9foPGAfHBr:Hr4XwROoWXwW+AB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_b74f6ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b74f6ba6f0a2fd9969cea27d371567823fd7b9a6ffe14aa5347adc63d70fc1e3"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-05 00:51:26"
  condition:
    hash.sha256(0, filesize) == "b74f6ba6f0a2fd9969cea27d371567823fd7b9a6ffe14aa5347adc63d70fc1e3"
}
```

### Sample 19: `12db9c40d7315b02`

| Field | Value |
|---|---|
| SHA-256 | `12db9c40d7315b02d5231d11e04854b0c1ea3574219a97a32e6cd6a6cf8e8f60` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-05 00:49:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f2d3180b697c8b138e2f3a1cd0936c4` |
| SHA-1 | `c409dccd86fcc0cee4294c188070ceb2e80dce40` |
| SHA-256 | `12db9c40d7315b02d5231d11e04854b0c1ea3574219a97a32e6cd6a6cf8e8f60` |
| SHA3-384 | `ea88a899ff07cf757cf0f5b10656e73170f0a03bd95d53b9854eb19d75efe1ce630cbde00dd7fcf29eba3d129ad6b28d` |
| TLSH | `T1FE442946FB414A13C4D617B9EA9F42453333E768D3EB7306D928AFB03B8779A0E62505` |
| TELFHASH | `t18a41ea758b64112a5aa1dd14d9ea97b2251eda1b1344fa73de35c48c280948fe927c0f` |
| SSDEEP | `6144:lRv2k9DAMk5WIs/H1ByajPl0qv0MtuclBii8hE1V/Gpr2mC2qC5s:ll/9DAMCWlH1ByajPl0qv0SxPuE/I6mi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_12db9c40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12db9c40d7315b02d5231d11e04854b0c1ea3574219a97a32e6cd6a6cf8e8f60"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-05 00:49:23"
  condition:
    hash.sha256(0, filesize) == "12db9c40d7315b02d5231d11e04854b0c1ea3574219a97a32e6cd6a6cf8e8f60"
}
```

### Sample 20: `f37cc14d7aba3e5a`

| Field | Value |
|---|---|
| SHA-256 | `f37cc14d7aba3e5acb68885336ccf3882c61d4220c50618d0344aa874b4f0fb6` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-05 00:46:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7144e9deb23ea76b159f8640766d1155` |
| SHA-1 | `e52659901d465800df1706a00071f75ace1f190f` |
| SHA-256 | `f37cc14d7aba3e5acb68885336ccf3882c61d4220c50618d0344aa874b4f0fb6` |
| SHA3-384 | `df7507f5b48d808cefedc0372e5f19240089e65af2dfb8da6d85bd2082883ad9efbf542057c0351bc61c5caca739c417` |
| TLSH | `T1AE141956F8819B15D5D112BEFE0E128D33232BBCE2DE72129D246F30778B96B0A7B505` |
| TELFHASH | `t130a00216db825056f09b83e9a189a59bc3793090e28661e1675453a93d139d93411496` |
| SSDEEP | `3072:5yopnl2EQiEV+UZsFgp1tyhUS1EArXG9soYaav2psJxDdhAC3Vd3R5Kf:dnl2EQiEAqc0byht1rXcsZa5gxDQ+Vd+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_f37cc14d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f37cc14d7aba3e5acb68885336ccf3882c61d4220c50618d0344aa874b4f0fb6"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-05 00:46:15"
  condition:
    hash.sha256(0, filesize) == "f37cc14d7aba3e5acb68885336ccf3882c61d4220c50618d0344aa874b4f0fb6"
}
```

### Sample 21: `0f2bd4b70f03a3f5`

| Field | Value |
|---|---|
| SHA-256 | `0f2bd4b70f03a3f5eba2121af97e5afb3c5969e4887c960c00d4c5b02c5c785f` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-05 00:45:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e7e1b36f954d5c9e04525f2fbf8015b` |
| SHA-1 | `e076646dcc964ef6e4f78966bd8f387f6a0b77c3` |
| SHA-256 | `0f2bd4b70f03a3f5eba2121af97e5afb3c5969e4887c960c00d4c5b02c5c785f` |
| SHA3-384 | `a3325a5fe8541e0c14e2f8105381b738ad72a20e3503e9c846a7bf6e3d7235fd7bd9c4c50f2f90f8127b3e56eb3f99b5` |
| TLSH | `T143832A91B981966EC2E063BFF95E928D333563E8C2DE3523DD118B1137CA61F0977A90` |
| TELFHASH | `t1edf08b04fe7a8f1948f29a70dcac17a0d407512791b21b20ef52cad1cc3e468f308d1d` |
| SSDEEP | `1536:GT3qwGZbgDoB7bx4gJy+b4pu4N793L3L72mWf4Iyd2FEd:4UZbn7bx4gJyfJ3r/ew9d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_0f2bd4b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2bd4b70f03a3f5eba2121af97e5afb3c5969e4887c960c00d4c5b02c5c785f"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-05 00:45:11"
  condition:
    hash.sha256(0, filesize) == "0f2bd4b70f03a3f5eba2121af97e5afb3c5969e4887c960c00d4c5b02c5c785f"
}
```

### Sample 22: `028c7bb4023c6678`

| Field | Value |
|---|---|
| SHA-256 | `028c7bb4023c66785328a078fb9ba3787418c45aace2b31395b9e06443224f71` |
| Family label | `unknown` |
| File name | `chrome_elf.dll` |
| File type | `dll` |
| First seen | `2026-07-05 00:21:34` |
| Reporter | `johnk3r` |
| Tags | `31-44-7-3, banker, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0413cbb5394de60195f92eb34775d9e4` |
| SHA-1 | `0ddd32dc4b3b4a6c339d14546759d4c1f94d4f98` |
| SHA-256 | `028c7bb4023c66785328a078fb9ba3787418c45aace2b31395b9e06443224f71` |
| SHA3-384 | `5ea6cc01a0131589be4d30bbb4762e4916338e3869c42d8055f9661d3569012b269ccbf4551d07c3078ed9fc7518b9d3` |
| IMPHASH | `055f03c0930ee8e112600d2d9eea4c04` |
| TLSH | `T14FC7335B39C7C4FBD4C509B0971777E713B7A2534ACA8C7A5AC42449D9E2FB2203E982` |
| SSDEEP | `1572864:+0N92y60WTub4IHvSytoHPeeEaytZVix8ULgZy9cZqN6rQe97PgS:+OLWTu0IKyc7EaytZpty9cZqkXPT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_028c7bb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "028c7bb4023c66785328a078fb9ba3787418c45aace2b31395b9e06443224f71"
    family = "unknown"
    file_name = "chrome_elf.dll"
    file_type = "dll"
    first_seen = "2026-07-05 00:21:34"
  condition:
    hash.sha256(0, filesize) == "028c7bb4023c66785328a078fb9ba3787418c45aace2b31395b9e06443224f71"
}
```

### Sample 23: `716608d7e9a26e98`

| Field | Value |
|---|---|
| SHA-256 | `716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-05 00:13:14` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc903b2967c0c943084a0d5c0d131cf1` |
| SHA-1 | `1dd66d9ee5902947bda7eb381fa256877a646879` |
| SHA-256 | `716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078` |
| SHA3-384 | `d8b5c2ab6568d99f05d1581efed6f86138438c1a6c78e3757317101400f95a95599b7f2b846edb77e8c6f63cdc63fd9c` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T14EA5330012E409D1E02AA7B05CE74E6B4534F8B24B7116BF35E8967C9F267C5A53BB2F` |
| SSDEEP | `49152:Au8yU6VTiz0JmAM/UaDjOlgrXcoJA5OZxwvt:VFs0JcJDjOsO5OHw` |
| ICON-DHASH | `1fbc72cec2e3e3a8` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_023_716608d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-05 00:13:14"
  condition:
    hash.sha256(0, filesize) == "716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078"
}
```

### Sample 24: `f23e6b705868c3d3`

| Field | Value |
|---|---|
| SHA-256 | `f23e6b705868c3d3a6615be240bfa23620b0b873fd17b12a9481f7580a18ec75` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.45211965` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:38` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f765f2396c7f2df4753ef0b02b20f3a` |
| SHA-1 | `64c1b72294206007c43834fc70b3fa299ed6c3d9` |
| SHA-256 | `f23e6b705868c3d3a6615be240bfa23620b0b873fd17b12a9481f7580a18ec75` |
| SHA3-384 | `6aa608cef388b7cdb1991566c78cc66f7e4a4c643d2ae8fa6c4f91e221e4bc2afcd4f1a42597b320ea998782f415e1a7` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14AD5AD0B7CD545E9C4AAA3318DBA42967B35BC494F3227D72E9077782E727E08D36B40` |
| SSDEEP | `49152:V50BJeqTR9up7t8eoqvBkoA/+h7r0hri4Hw95gZ:V50dGN5kh/Of6rDQ95m` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_024_f23e6b70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f23e6b705868c3d3a6615be240bfa23620b0b873fd17b12a9481f7580a18ec75"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.45211965"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:38"
  condition:
    hash.sha256(0, filesize) == "f23e6b705868c3d3a6615be240bfa23620b0b873fd17b12a9481f7580a18ec75"
}
```

### Sample 25: `9462805f80c946c4`

| Field | Value |
|---|---|
| SHA-256 | `9462805f80c946c49bf44a3d567a682b666d1d0bd74e3819050339e6f3e93451` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.11482139` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:36` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f80fb7d02e567f3c92aed65acd83565` |
| SHA-1 | `a2229b5da50d9f4c9fba066a7af5c23efbe22675` |
| SHA-256 | `9462805f80c946c49bf44a3d567a682b666d1d0bd74e3819050339e6f3e93451` |
| SHA3-384 | `612f114fe92a4518c210abd55a871e630dc289515d5c876f6ec7a40134f07100fed05d50d0fa1562d823687571b33b14` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C1E59E47BCD009E5D5AAA6328DB792927B30BC454F3623D72E8072782F767D19C3A784` |
| SSDEEP | `49152:Hznf00G7buw5Zs0CVmQTqseuqnmHz18cFMIarEftsI4P:Hzs9odscFMdEsIs` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_025_9462805f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9462805f80c946c49bf44a3d567a682b666d1d0bd74e3819050339e6f3e93451"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.11482139"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:36"
  condition:
    hash.sha256(0, filesize) == "9462805f80c946c49bf44a3d567a682b666d1d0bd74e3819050339e6f3e93451"
}
```

### Sample 26: `8e3cf3dc6e5d8fdf`

| Field | Value |
|---|---|
| SHA-256 | `8e3cf3dc6e5d8fdfbcc8575e9e97003f7f919c6ba2ea5889ec3ac658ceacc8a9` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61852.17703.28157` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:34` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1c7abb7d3e27a5a13788863449b0678` |
| SHA-1 | `05842daee782946e80621abe836f235fcb919e76` |
| SHA-256 | `8e3cf3dc6e5d8fdfbcc8575e9e97003f7f919c6ba2ea5889ec3ac658ceacc8a9` |
| SHA3-384 | `8df29bc158a7ac61dd437a8413e00f0c824d5f737a3cbbc556b710e20295874aed2fba1aab42072af0df711177c26b78` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A8F57C47ACE108FAC09AA23185B75696BB74BC090F3227D32E91B7382F72BE05D75754` |
| SSDEEP | `49152:GDapaeJv7Dz45PGoIk9DdDQ97F+tKSAbB+2avZSFWnLOgCsDpDg:GWhXo2FoAbB+2avZxLe` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_026_8e3cf3dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e3cf3dc6e5d8fdfbcc8575e9e97003f7f919c6ba2ea5889ec3ac658ceacc8a9"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61852.17703.28157"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:34"
  condition:
    hash.sha256(0, filesize) == "8e3cf3dc6e5d8fdfbcc8575e9e97003f7f919c6ba2ea5889ec3ac658ceacc8a9"
}
```

### Sample 27: `e74cf40d9df39097`

| Field | Value |
|---|---|
| SHA-256 | `e74cf40d9df390976e11bad98f81df248c14b6e5a45c889b05095fb66117a83b` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.79583238` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:32` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14849cd2fbd1dc33147101bb7d028b61` |
| SHA-1 | `b8fa979c5b97fcdd3012fd6399a1bc75f22add36` |
| SHA-256 | `e74cf40d9df390976e11bad98f81df248c14b6e5a45c889b05095fb66117a83b` |
| SHA3-384 | `f0805ea5a24e1c9fc743a1a26e9ac2afc189b003d3f7682844e54ee1622759e3d4c5ea10c9459cf27f1c653800dd171f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17AE5AE0B7CE044E9D8AA92358CB751967B71BC490F3267D32E80B2782FB27D09D76B54` |
| SSDEEP | `49152:mJi9PRkDTG8WYrYN1DUTs9xFUU74xLu+FJbN1nrUJIPVgaGD:mJikK7LMi+GIPVVGD` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_027_e74cf40d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e74cf40d9df390976e11bad98f81df248c14b6e5a45c889b05095fb66117a83b"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.79583238"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:32"
  condition:
    hash.sha256(0, filesize) == "e74cf40d9df390976e11bad98f81df248c14b6e5a45c889b05095fb66117a83b"
}
```

### Sample 28: `d9d6fc3085dd822f`

| Field | Value |
|---|---|
| SHA-256 | `d9d6fc3085dd822f258601164ecb21f318822a63ca0360aead9201bcee49ed04` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.PWS.StealerNET.203.19366.4374` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:30` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b3c6ee4490da28af2ec40637384c400` |
| SHA-1 | `96f4bf9096686fcb2cd171034b9ea22cd4da2280` |
| SHA-256 | `d9d6fc3085dd822f258601164ecb21f318822a63ca0360aead9201bcee49ed04` |
| SHA3-384 | `e3325dd76e832e3dec5026332ef3715af650cde56455942e071317e8bf83433ca27773e873885dfbc432e50f29b104dc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F134086E9E97A641C5160836B87353814B799E7964CFB5628EE33FFE4BF3C9810070A1` |
| SSDEEP | `3072:4/sQH9nTmUMzavkcHrU2DYgdbIX5US94NpVq8BxFRzaqF+o2GQJ7/JzqVfGv1:49TsgYUbcdgVqwlL` |
| ICON-DHASH | `f0d0c8cdcd88c0e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_d9d6fc30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d6fc3085dd822f258601164ecb21f318822a63ca0360aead9201bcee49ed04"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.PWS.StealerNET.203.19366.4374"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:30"
  condition:
    hash.sha256(0, filesize) == "d9d6fc3085dd822f258601164ecb21f318822a63ca0360aead9201bcee49ed04"
}
```

### Sample 29: `360e3c6d428da649`

| Field | Value |
|---|---|
| SHA-256 | `360e3c6d428da649c77a426d3f0379a3a1eced35f0d7a68f5a925d4b300ccaf7` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.57237154` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:28` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eaf137a95d93a9093efc6280adaf9326` |
| SHA-1 | `4119957c3a2100afdc5eda40c89cdb2f426abf7f` |
| SHA-256 | `360e3c6d428da649c77a426d3f0379a3a1eced35f0d7a68f5a925d4b300ccaf7` |
| SHA3-384 | `71f5a602ca6c5f53fae004ddc73ed5753186411ca8e6b54144529f132bb43477b8c133e6f0ce4479df7bcc7f8a594098` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16DD59D076DE119E9D4EA963189B642A67B70BC090F3633D32E94B3782F727E14D35B90` |
| SSDEEP | `49152:JQVuTmstSRhlmMA5kEg8QdlL1/oOxMFnH9/n4wEoszogn7WXlBgUt7:JQu6s/g8QdlL1/oCMFnHVn4wEoszognG` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_029_360e3c6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "360e3c6d428da649c77a426d3f0379a3a1eced35f0d7a68f5a925d4b300ccaf7"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.57237154"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:28"
  condition:
    hash.sha256(0, filesize) == "360e3c6d428da649c77a426d3f0379a3a1eced35f0d7a68f5a925d4b300ccaf7"
}
```

### Sample 30: `31da18115d031c33`

| Field | Value |
|---|---|
| SHA-256 | `31da18115d031c335b2b4f2b2d3a1277ace95a139e7293e469ee2f55d084d3a3` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.38397872` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:26` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9af17b2049b920cdc6729948eb7e625f` |
| SHA-1 | `911ea308dddb874b517885a9909f029126a54aba` |
| SHA-256 | `31da18115d031c335b2b4f2b2d3a1277ace95a139e7293e469ee2f55d084d3a3` |
| SHA3-384 | `dcefffc562f67af74a980a10fe16dec476cb0f71a425b30c158f3c6924e030edf3b6e3ae76564512cece49b095539242` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T182E59D0B6CD249EAC4AA673289B615927A75FC154F3233D72E90B6783F727E48C39740` |
| SSDEEP | `49152:Md20uoiCzddk8L215lj5D9dhupmLAvy+BiMQoNrPyVovkkrgwv:MdkoL2hdmisoiPyGvkkrt` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_030_31da1811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31da18115d031c335b2b4f2b2d3a1277ace95a139e7293e469ee2f55d084d3a3"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.38397872"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:26"
  condition:
    hash.sha256(0, filesize) == "31da18115d031c335b2b4f2b2d3a1277ace95a139e7293e469ee2f55d084d3a3"
}
```

### Sample 31: `eded86eb5c664d71`

| Field | Value |
|---|---|
| SHA-256 | `eded86eb5c664d712b1393001d997338d122e53b15885adc4c89d2421a412f64` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.87659349` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:23` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1a2c6e811791ad672f8f600257c5fe8` |
| SHA-1 | `fe459ec940c0a2fecfa72ced9003c6be44af8865` |
| SHA-256 | `eded86eb5c664d712b1393001d997338d122e53b15885adc4c89d2421a412f64` |
| SHA3-384 | `c711c3d2982ed5708b97d00d03072797e701e0dd679a36c83b7a3b5cfa02f4253de19f0fe7c43aef15cfb307574477c6` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CFD59C4A6CE049EAD49A973289B612867B74BC490F3273D72E9073783F72BD15C36784` |
| SSDEEP | `49152:u5I1RmV9Et/vSi9X5XYzeZXlWrcwRZGuX9vlmNK5ktm5w+gclC:u5SAUIzeZwrpRZGuX9vlmNK51K` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_031_eded86eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eded86eb5c664d712b1393001d997338d122e53b15885adc4c89d2421a412f64"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.87659349"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:23"
  condition:
    hash.sha256(0, filesize) == "eded86eb5c664d712b1393001d997338d122e53b15885adc4c89d2421a412f64"
}
```

### Sample 32: `16d67fa1f9e77c46`

| Field | Value |
|---|---|
| SHA-256 | `16d67fa1f9e77c465e62a6a37f0c5bd54b8385215a5f40b1e5644dd3d84e0dad` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.65488933` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:22` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fdb32623242973019d8eb9dfc1c96af` |
| SHA-1 | `499850d03ccc25102d17584956bb01e53fd5aa6f` |
| SHA-256 | `16d67fa1f9e77c465e62a6a37f0c5bd54b8385215a5f40b1e5644dd3d84e0dad` |
| SHA3-384 | `b7016ec28647feee737fa86f90d09741a91dd37aa17bbffc1b8627fd3b513bf8df48f515f9862295b3576bf1f693a6b1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T186D58C577DD009E9C49AA23688B65186BB71BC090F3223D72E90B3783F72BD19D7A744` |
| SSDEEP | `49152:CM38XcF9NPOjKL9a+Kn1ap4If2DmRF1yhWJBVgPGjJI:CM3RPLw78XfDRryWJBVsGjS` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_032_16d67fa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16d67fa1f9e77c465e62a6a37f0c5bd54b8385215a5f40b1e5644dd3d84e0dad"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.65488933"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:22"
  condition:
    hash.sha256(0, filesize) == "16d67fa1f9e77c465e62a6a37f0c5bd54b8385215a5f40b1e5644dd3d84e0dad"
}
```

### Sample 33: `5525784bfcc0c334`

| Field | Value |
|---|---|
| SHA-256 | `5525784bfcc0c3340da0289ab8a5aed5565e73dc7246366b246ff000f7757ac5` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.49523153` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:20` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9a904c03fe2967cbb32211c28ef2da6` |
| SHA-1 | `8ec145ca3051276ef9698916841d785067ecfccd` |
| SHA-256 | `5525784bfcc0c3340da0289ab8a5aed5565e73dc7246366b246ff000f7757ac5` |
| SHA3-384 | `e6f3e3044ddd993dbceb600d6cb3bda791b99c961299e293ff96ff9f5c65b7b2ddac2681e6a50fc120d33657624f3fbb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T101D5AD0BACE209E9D49AA7759DB342567B38FC494F3227D76E8076782E723E18C35740` |
| SSDEEP | `49152:csEmnyDjTfZ+tR78mDAa+Rr6wThpfLgKBZOtgO:cs5fj8L0UAl` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_033_5525784b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5525784bfcc0c3340da0289ab8a5aed5565e73dc7246366b246ff000f7757ac5"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.49523153"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:20"
  condition:
    hash.sha256(0, filesize) == "5525784bfcc0c3340da0289ab8a5aed5565e73dc7246366b246ff000f7757ac5"
}
```

### Sample 34: `08510ddd7019a2fb`

| Field | Value |
|---|---|
| SHA-256 | `08510ddd7019a2fb09d4893c35ddbb3356cd8ce3fe6e43fa68f9f13e95287d46` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.25595179` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:18` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b703aacd3e943ffe9083c14779cd7cbb` |
| SHA-1 | `aa5e4452366f883dbb8a551b97a25e2739ca58a1` |
| SHA-256 | `08510ddd7019a2fb09d4893c35ddbb3356cd8ce3fe6e43fa68f9f13e95287d46` |
| SHA3-384 | `33396073f86db3f766c9a4456fa410a22dd54fa5ba6a5773a7f171eff343d918513420dbb8530de0140416eed04583ae` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F3E59D0B7CD145EAD8AA92768CBA91927B71BC090F3623D32E90B77C2E727D44D36750` |
| SSDEEP | `49152:D2HjesePiRBf3QcZrfbp//6mhcZ6sqeoHe3go:D2q+n5/6acZ6qTT` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_034_08510ddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08510ddd7019a2fb09d4893c35ddbb3356cd8ce3fe6e43fa68f9f13e95287d46"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.25595179"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:18"
  condition:
    hash.sha256(0, filesize) == "08510ddd7019a2fb09d4893c35ddbb3356cd8ce3fe6e43fa68f9f13e95287d46"
}
```

### Sample 35: `33b317b7ffc3ea44`

| Field | Value |
|---|---|
| SHA-256 | `33b317b7ffc3ea442add1da7aa7a7c444b670c62943e684c2ec2c5d6fa97904c` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.49954333` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:16` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe8e6273c6c4ce33dc5506a497c60a16` |
| SHA-1 | `47ecc87cb6b4effe354e194e6338886769157795` |
| SHA-256 | `33b317b7ffc3ea442add1da7aa7a7c444b670c62943e684c2ec2c5d6fa97904c` |
| SHA3-384 | `c6d2ea0413608f25d441a2c5d107f0e99c96a6e456bbb8766ad4899f2cf4c8e7ec0d91ca277a293f2fd483a8beefd182` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T136D59D4BBCD148E9D8AAA3328CB611867B74BC094F3623D72E50B6782F727D1AC35754` |
| SSDEEP | `49152:EjO+4rvfjF7d1wAv65itXoG4WD5e7UlRHGOD9GCg9:Ej6jUItXo7WkkhGOJGCi` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_035_33b317b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33b317b7ffc3ea442add1da7aa7a7c444b670c62943e684c2ec2c5d6fa97904c"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.49954333"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:16"
  condition:
    hash.sha256(0, filesize) == "33b317b7ffc3ea442add1da7aa7a7c444b670c62943e684c2ec2c5d6fa97904c"
}
```

### Sample 36: `62f16a144816655a`

| Field | Value |
|---|---|
| SHA-256 | `62f16a144816655addc35fa23adb766203296c38b75452e6d30aa4a3a13df6b5` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.62131.22581.20107` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:13` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `776abc34a4ac6c2e3a93c809a39e1974` |
| SHA-1 | `2fa9cf5acea1246a6bf71fffcbc7b3d823f3d9e2` |
| SHA-256 | `62f16a144816655addc35fa23adb766203296c38b75452e6d30aa4a3a13df6b5` |
| SHA3-384 | `38fd2eb2fa5cef7a30e043a960c080d27277d0f85d7a1a178c649131d23e0e58be189d1598302e874d01556e52046e07` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T110D59D0B7CD048E9C86A6B3189B242967B34FC160F3623D72E5076792F727E09D7A785` |
| SSDEEP | `24576:KUu5LYwzrN8FoP+kAytRHFoQbsZSRIEMUNTCB+Qoxcp98qScc2wHxcfAdrBRtxzl:KUuVY28YZAy3H2FU9iycf2BLgq` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_036_62f16a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62f16a144816655addc35fa23adb766203296c38b75452e6d30aa4a3a13df6b5"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62131.22581.20107"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:13"
  condition:
    hash.sha256(0, filesize) == "62f16a144816655addc35fa23adb766203296c38b75452e6d30aa4a3a13df6b5"
}
```

### Sample 37: `b19e9f8b8b5cefd7`

| Field | Value |
|---|---|
| SHA-256 | `b19e9f8b8b5cefd798ffd7a3b428aa842798d697a049f32cf80c720ccb5602f0` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61915.1296.13418` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:10` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ae339b769bb7b5ec637d243e07a349e` |
| SHA-1 | `51c82d82b7e8e89521e4f3259524fbc2a4b8e595` |
| SHA-256 | `b19e9f8b8b5cefd798ffd7a3b428aa842798d697a049f32cf80c720ccb5602f0` |
| SHA3-384 | `fc3573569d80e5dc17834481c83dc9d27342ca3af62fc78ea988b85c1f2a9d0ad0015b246bdbde73631a74bd50f5b241` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T137D5AE0BBCD508E9C4AA673588B201967B35BC4A0F3263C72E90B7782F727E19D79754` |
| SSDEEP | `49152:OIWQYezEREEbDncQtLiwhjsVhzPqsBbcUVgwN:OIKeBQtmojsbzPqsBbTV9N` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_037_b19e9f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19e9f8b8b5cefd798ffd7a3b428aa842798d697a049f32cf80c720ccb5602f0"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61915.1296.13418"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:10"
  condition:
    hash.sha256(0, filesize) == "b19e9f8b8b5cefd798ffd7a3b428aa842798d697a049f32cf80c720ccb5602f0"
}
```

### Sample 38: `ec59758993501d25`

| Field | Value |
|---|---|
| SHA-256 | `ec59758993501d25047672e4c46d33d7489012bf3936832af18896fb1bbef109` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.62620.2012.11636` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:08` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f853d193d83029352212ae5135589816` |
| SHA-1 | `af7c9e5a99e1d7de22f316eb0ccd9c694ed26f90` |
| SHA-256 | `ec59758993501d25047672e4c46d33d7489012bf3936832af18896fb1bbef109` |
| SHA3-384 | `50430775191d5390cd40af005c46afd6014fee413183beec246b7f4e9a1774f0434230a99e939c2ccb820da7e9fe90c3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T159D5AF0B7CE408E9C46A573688B252927B30BC564F3263D72E90B67C2F76BE09C79754` |
| SSDEEP | `49152:o124yaD0luCrOifPzJTy+6tqi4iYW5nwngA:o1kPXz5y+6155nIF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_038_ec597589
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec59758993501d25047672e4c46d33d7489012bf3936832af18896fb1bbef109"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62620.2012.11636"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:08"
  condition:
    hash.sha256(0, filesize) == "ec59758993501d25047672e4c46d33d7489012bf3936832af18896fb1bbef109"
}
```

### Sample 39: `9cd9c0a79450290b`

| Field | Value |
|---|---|
| SHA-256 | `9cd9c0a79450290b1ac0ea3235df6cd68332cc5a426991fa1d53eb7f19ec5a09` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61904.18316.7310` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:05` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb4da97b8dbf3dd30c9d32d2879c67a2` |
| SHA-1 | `fb2d549228df09be55ebc41b0d8d77f0c1d1a77b` |
| SHA-256 | `9cd9c0a79450290b1ac0ea3235df6cd68332cc5a426991fa1d53eb7f19ec5a09` |
| SHA3-384 | `fcda11c506e788af5e567a47319317764fe9405684a4711a6af538756b18d09d794933790fad1fd5d1df8acf17ca5368` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1CFD59D0B7C9148EED469A2368DB611567B74BC190F3663D72E90B7383E32BE19C39784` |
| SSDEEP | `49152:p8d+qC4D+FuDYoLQlfwZqVuFm4s5jlWOojvpDIcR4gE:p8w9qQlfPVuFmNjBorpkV9` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_039_9cd9c0a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cd9c0a79450290b1ac0ea3235df6cd68332cc5a426991fa1d53eb7f19ec5a09"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61904.18316.7310"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:05"
  condition:
    hash.sha256(0, filesize) == "9cd9c0a79450290b1ac0ea3235df6cd68332cc5a426991fa1d53eb7f19ec5a09"
}
```

### Sample 40: `c2cfd3d5cc6db523`

| Field | Value |
|---|---|
| SHA-256 | `c2cfd3d5cc6db52356661d50b0374c494c96af73cb0fea33babb9616d4453098` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.88959866` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:01` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb6189c15ec116abb50005041e178d74` |
| SHA-1 | `6995d6a1f44b8ba4f5c9971514e082816a8f0eae` |
| SHA-256 | `c2cfd3d5cc6db52356661d50b0374c494c96af73cb0fea33babb9616d4453098` |
| SHA3-384 | `98a491131663641a81e125d5ef8d15635b9c93e16e6ce212fa7b9c485d7d117e2cdc6ae8958e77b5f944169715588823` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T169D59C0B6CD049EAC4AAA63689B751927B30BC054F3263D72E40B7783FB2BD09D75B54` |
| SSDEEP | `49152:nwIjnR4toOc+w1uxYOl+FGVrNPflR16x+g2:nwu7syFGVrNVR16kp` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_040_c2cfd3d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2cfd3d5cc6db52356661d50b0374c494c96af73cb0fea33babb9616d4453098"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.88959866"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:01"
  condition:
    hash.sha256(0, filesize) == "c2cfd3d5cc6db52356661d50b0374c494c96af73cb0fea33babb9616d4453098"
}
```

### Sample 41: `337463ea7d1ef14b`

| Field | Value |
|---|---|
| SHA-256 | `337463ea7d1ef14be117bf0461be4dd342794f5919c820173651b9d7a7269ae3` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61853.5418.11599` |
| File type | `exe` |
| First seen | `2026-07-05 00:00:00` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2344b27221e13bd6fdae3cbf1d71dbd2` |
| SHA-1 | `a87f3e023cff230f8b4bdfa7945e4e43dcc2c0c9` |
| SHA-256 | `337463ea7d1ef14be117bf0461be4dd342794f5919c820173651b9d7a7269ae3` |
| SHA3-384 | `1f02ff9f92dc7ed83d7f056f402c4b251a44806badba555a105c359f8689d6ce8912779c1146d2be20a536e8dd662398` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T156F56B47BCD148E5C09AA33289B79296BB75BC090B3123D32E90B7382F76BD05D75B58` |
| SSDEEP | `49152:WH26pOTjiRIAYE4RsCnm9TAVMamygFn0ggCsDpYpPHi:WRjNVjyk0KPHi` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_041_337463ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "337463ea7d1ef14be117bf0461be4dd342794f5919c820173651b9d7a7269ae3"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61853.5418.11599"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:00"
  condition:
    hash.sha256(0, filesize) == "337463ea7d1ef14be117bf0461be4dd342794f5919c820173651b9d7a7269ae3"
}
```

### Sample 42: `b6fba18b6641eac4`

| Field | Value |
|---|---|
| SHA-256 | `b6fba18b6641eac47499735a0c872814b20bdc65ed491c04769d0e556d2ec40b` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61937.4405.20783` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:58` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834ee0b48222d8b99475dfd38d5283b9` |
| SHA-1 | `2a6b75235df4ce03bc213a72cecfca0579998d69` |
| SHA-256 | `b6fba18b6641eac47499735a0c872814b20bdc65ed491c04769d0e556d2ec40b` |
| SHA3-384 | `cb4974526fd6cd1cab7be656cd076cfbd043716ed2d928369a21dda5d03f525d43e331084b9f967fabc6001ea23ade3f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1BFD59D0BBCD109E9D45A673688B251923B34BC094F3663D72E90B3782F72BE09D39795` |
| SSDEEP | `49152:bqSuDzh8cabt5v6Iyhs6UHSXNrhMdDPOij2gx:bqvQv6IyhsBHAM5Gij2Q` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_042_b6fba18b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6fba18b6641eac47499735a0c872814b20bdc65ed491c04769d0e556d2ec40b"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61937.4405.20783"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:58"
  condition:
    hash.sha256(0, filesize) == "b6fba18b6641eac47499735a0c872814b20bdc65ed491c04769d0e556d2ec40b"
}
```

### Sample 43: `0f1bcecd61092de0`

| Field | Value |
|---|---|
| SHA-256 | `0f1bcecd61092de0735dba542259b31c6566a1df62069a0a3287a0a12dcfa4f2` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.62060.9877.21148` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:57` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76095c93b9c8ec3655df1c6345f9437a` |
| SHA-1 | `733cdd58fa430b86a2daeca2e1b795cdbb3511c0` |
| SHA-256 | `0f1bcecd61092de0735dba542259b31c6566a1df62069a0a3287a0a12dcfa4f2` |
| SHA3-384 | `de1dbea3f9eadc4531667fb8bdd888b3a0c2a5133693d7bc5f5bda57951e2b9695fc1cdfb8939688c48a77fe9a3b9aa3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A5D59E0B6CD008E9D8AA573648B611857B35BC1A4F3163DB2EA4B3783F76BE09C35794` |
| SSDEEP | `49152:C3evFzicIonEtQfaTGLt/tylCm+P31U4GhIlolD+hO7jAgL:C3mmbGLtdz35GhIlolDCO78i` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_043_0f1bcecd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f1bcecd61092de0735dba542259b31c6566a1df62069a0a3287a0a12dcfa4f2"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62060.9877.21148"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:57"
  condition:
    hash.sha256(0, filesize) == "0f1bcecd61092de0735dba542259b31c6566a1df62069a0a3287a0a12dcfa4f2"
}
```

### Sample 44: `3d776e8445933dee`

| Field | Value |
|---|---|
| SHA-256 | `3d776e8445933dee504ffe673a96480d5313c1e71979faebb74c3c9734b96b31` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.44919756` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:56` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0007e1a20d9443cb815780c52ea1cdfb` |
| SHA-1 | `5e949d52b9c2d4a35a70d800985818c9b2135d69` |
| SHA-256 | `3d776e8445933dee504ffe673a96480d5313c1e71979faebb74c3c9734b96b31` |
| SHA3-384 | `405e00753f3ce665efd555dacc0fe6aab896260a1d28af152267f0bd9a900489b538fef635937c5712acfb6842cd63f2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A1D59D0BBDD048EAD4AAA33189B612967B30BC094F3227D72E90B77C2E727D19D35751` |
| SSDEEP | `49152:JQVuTmstSaF+M/xBb3clmBpWu9xMUQAoAEgZG09:JQuAIxWlmBpWjgE6G09` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_044_3d776e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d776e8445933dee504ffe673a96480d5313c1e71979faebb74c3c9734b96b31"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.44919756"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:56"
  condition:
    hash.sha256(0, filesize) == "3d776e8445933dee504ffe673a96480d5313c1e71979faebb74c3c9734b96b31"
}
```

### Sample 45: `08be0ddd6e5d0004`

| Field | Value |
|---|---|
| SHA-256 | `08be0ddd6e5d000404d4c5f27b7a1acf98c12ac4e4e715ae750f4d80f8e830e5` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.62619.15404.14512` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:54` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b77d29650850f76aa139cbbf7453a206` |
| SHA-1 | `4cd613e3b2d94d777d30ecfcf62cd0befe0b4842` |
| SHA-256 | `08be0ddd6e5d000404d4c5f27b7a1acf98c12ac4e4e715ae750f4d80f8e830e5` |
| SHA3-384 | `ffcd4b34c48754aa8c615ea8fb6331943308ca153eda3eca0a713e281929fc114e11561c576cd04dadfe730eb7e559f1` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F8D59D0B7C9109F6C49A677588B251917B34BC1A4F3627D32E90B7382F727E1AC36B94` |
| SSDEEP | `24576:wXc5uz9iGvhKEpekLKMywVb4wt3K880pX/jTolVzCWdlYF3JuWkEmKYxnuMmVqkA:wXc8zZhNEc5zjryCFF0mmN4F+jHp1PgS` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_045_08be0ddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08be0ddd6e5d000404d4c5f27b7a1acf98c12ac4e4e715ae750f4d80f8e830e5"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62619.15404.14512"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:54"
  condition:
    hash.sha256(0, filesize) == "08be0ddd6e5d000404d4c5f27b7a1acf98c12ac4e4e715ae750f4d80f8e830e5"
}
```

### Sample 46: `ebdd2ac5c447807f`

| Field | Value |
|---|---|
| SHA-256 | `ebdd2ac5c447807ff3218ae4fe747a681dc1097b64025452acbf7faa1fb17ca4` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.65646623` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:53` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8c5e570415b946b7a157a91377ad6ad` |
| SHA-1 | `d9c7eaaf67ce48be524c2ef9cb3f78fd19bf5b46` |
| SHA-256 | `ebdd2ac5c447807ff3218ae4fe747a681dc1097b64025452acbf7faa1fb17ca4` |
| SHA3-384 | `80ebd9f0e6cdacee7483c6f1fd877e48b68d6885957f97b872f81a62d4a963d939130000c3e9fa420e4c861fbe8ef608` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C8D58C076CD105F9D4AAA63298BA11D63B75BC094F3263D32E90B3792FB2BE18D35750` |
| SSDEEP | `49152:1WbQnVKTdTsQA4l7AIzKwuP+FEfU1IBgfazNtHgIN8:1WgS9AIRsU1CgwH1N8` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_046_ebdd2ac5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebdd2ac5c447807ff3218ae4fe747a681dc1097b64025452acbf7faa1fb17ca4"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.65646623"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:53"
  condition:
    hash.sha256(0, filesize) == "ebdd2ac5c447807ff3218ae4fe747a681dc1097b64025452acbf7faa1fb17ca4"
}
```

### Sample 47: `4521f532bf22c315`

| Field | Value |
|---|---|
| SHA-256 | `4521f532bf22c3155a95a71c4797253680dc60618c74c18522506a603ef43a03` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.62148.2993.29667` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:51` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb0da5f19b4395355e77c8da57d7266a` |
| SHA-1 | `ae22f19ee1036f18f42a9fb9cfd203d0f15d6766` |
| SHA-256 | `4521f532bf22c3155a95a71c4797253680dc60618c74c18522506a603ef43a03` |
| SHA3-384 | `0ead8f1f63f6d46331c630ed8d0a31c5de163ceebd60dedc00f54d1e685be0c26945a8ed0558d7ac9c0f254b9b814807` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T111D59D0B7C9109E9D8AA633688B251927B79BC450F3623D33E90B6783F727E19D39741` |
| SSDEEP | `49152:mv8RCDoF8Zt/ZTqYH26qbumU/FphRlMWcazv70CSg:mvFDJKumUtLRqWcabw` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_047_4521f532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4521f532bf22c3155a95a71c4797253680dc60618c74c18522506a603ef43a03"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62148.2993.29667"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:51"
  condition:
    hash.sha256(0, filesize) == "4521f532bf22c3155a95a71c4797253680dc60618c74c18522506a603ef43a03"
}
```

### Sample 48: `9eb3e292b091c691`

| Field | Value |
|---|---|
| SHA-256 | `9eb3e292b091c691943b70fc0e9d6d2c5e5c55727518e40018ba72b27d71e0a3` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61959.9199.15630` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:50` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0f29b04fcb7ca3303e900e189eb5549` |
| SHA-1 | `3170e2e9076e6e7f27dafea941febfc1b994ce51` |
| SHA-256 | `9eb3e292b091c691943b70fc0e9d6d2c5e5c55727518e40018ba72b27d71e0a3` |
| SHA3-384 | `f26c9ad0541f88ba9b6a2d73c296c9d7b26ef0b74b6d6069529a2655e2dd887770cd7501d05c2367ebe5f9a2caa8b36c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17ED5AD0B7CD049E9C8AA963648B251967B30BC160F7623D32E90B7783F76BE19C79750` |
| SSDEEP | `49152:btmlPoQc65tjwricZ7vCZKZt6a+aRLeCAZw8F+usKp5WkepaIl5t8XuRgN:bt1PricZlZQa+ah/30DaaIlX8G4` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_048_9eb3e292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb3e292b091c691943b70fc0e9d6d2c5e5c55727518e40018ba72b27d71e0a3"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61959.9199.15630"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:50"
  condition:
    hash.sha256(0, filesize) == "9eb3e292b091c691943b70fc0e9d6d2c5e5c55727518e40018ba72b27d71e0a3"
}
```

### Sample 49: `c11aeec42a7f3c4e`

| Field | Value |
|---|---|
| SHA-256 | `c11aeec42a7f3c4e7895d37cf403b6900793226444dfc83ad2b85aab152e457c` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.61860.23656.11656` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:48` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d197145d9ca63ded215154bb64c9dc40` |
| SHA-1 | `9c76c024469b7605f9ff575d7b5a9c68ebdfe57e` |
| SHA-256 | `c11aeec42a7f3c4e7895d37cf403b6900793226444dfc83ad2b85aab152e457c` |
| SHA3-384 | `968c7f308080b37bdf60bee5289838d4f272d95c416eaf463e28604ab9603eb4b8af86b9bec6ab08a2ae4e19aa6f9697` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T162F58B47BC9048FAC06AA331CAB69196BB75BC080F3223D72E90B7392E767E45D75714` |
| SSDEEP | `49152:LKpjlRkiShIGxewjFi2chBDj5do7J+/RLpE3RIgo34KH0NlY7OI+RiTtHtnlOgCc:LI6eL5l5ci+gHtlj` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_049_c11aeec4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c11aeec42a7f3c4e7895d37cf403b6900793226444dfc83ad2b85aab152e457c"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61860.23656.11656"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:48"
  condition:
    hash.sha256(0, filesize) == "c11aeec42a7f3c4e7895d37cf403b6900793226444dfc83ad2b85aab152e457c"
}
```

### Sample 50: `0c4ad7ea7fd1d241`

| Field | Value |
|---|---|
| SHA-256 | `0c4ad7ea7fd1d24186efc73657dd5feed3f7c7243089e4d9eae0b1f63abeb69d` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.99646532` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:47` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcc568c8a51881d74be42b270ee0e38d` |
| SHA-1 | `c8781fb94d3f26d813bb5a55a703dca02121ae3d` |
| SHA-256 | `0c4ad7ea7fd1d24186efc73657dd5feed3f7c7243089e4d9eae0b1f63abeb69d` |
| SHA3-384 | `b4de6fa6b13f70203701f692e6fc6da87d98885ecab2902226242a0c14609d7c3df5aeb635c8a95ed452d78b47bd69e4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T185D59D4B7CD004E9C4AAA6328CB651977B79BC594F3263D72E40B3382E727D09D7AB50` |
| SSDEEP | `49152:WvpaOLeM7aEMKUF2X+F3ZtcX+3ecr72VnV3noIfhZq/csPJgGzL/:Wvp3JOgXY3Ztcqecn2VV3noIfhZ5OJt/` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_050_0c4ad7ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c4ad7ea7fd1d24186efc73657dd5feed3f7c7243089e4d9eae0b1f63abeb69d"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.99646532"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:47"
  condition:
    hash.sha256(0, filesize) == "0c4ad7ea7fd1d24186efc73657dd5feed3f7c7243089e4d9eae0b1f63abeb69d"
}
```

### Sample 51: `741eea6f598af241`

| Field | Value |
|---|---|
| SHA-256 | `741eea6f598af241e1337ad567b7c6d52e601309a381f934ab6ce245c7906469` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.78866488` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:46` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb0451aa69db2baa8973078965893b08` |
| SHA-1 | `9477e8ca9c28b45f506dd6c50f98c7d15e861afa` |
| SHA-256 | `741eea6f598af241e1337ad567b7c6d52e601309a381f934ab6ce245c7906469` |
| SHA3-384 | `10bba906443dc9cc40ee7bab44779c88902bf0fc5559f1da0934d463214e01635ec40b79f8a650ef6bba8a09660b901a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D3E58C4B7CE005E9D4AB633689B652867B75BC590F3223D72E90B6382F727D08D3A750` |
| SSDEEP | `24576:Dh6CplZo/PP5D1OaMdU9mnA7AzdSD08NF8ZHJCXEqMaBRuL5igvn8zMqnqLRrVtw:Dh6yb0HGaCPEWdSIJB5igvnwAgnmJM` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_051_741eea6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "741eea6f598af241e1337ad567b7c6d52e601309a381f934ab6ce245c7906469"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.78866488"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:46"
  condition:
    hash.sha256(0, filesize) == "741eea6f598af241e1337ad567b7c6d52e601309a381f934ab6ce245c7906469"
}
```

### Sample 52: `fcd8643dff51723d`

| Field | Value |
|---|---|
| SHA-256 | `fcd8643dff51723d1250496b2a8e10d69fb6e2eb4c01c30cbad32bbf54c9ce51` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.61776561` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:44` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `871c3d3bc610e885318af5669948a07d` |
| SHA-1 | `7c7e735265f2b25be141acac89f91f424387e093` |
| SHA-256 | `fcd8643dff51723d1250496b2a8e10d69fb6e2eb4c01c30cbad32bbf54c9ce51` |
| SHA3-384 | `9e175063bcf0f0fe0f7d3f2e4ed404d61495075835ea38f91a7e320b65e3f9685757c3c3949098adb2d5c409fbf029f0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16CE5AE4B7CD405E9C8AAA33588B691967B74BC194F3133D32E84B7782E327E49D76780` |
| SSDEEP | `49152:s/008dWagNzTrif4krU2DWQCxI7fJTkDAEbseX4:s/se4ZpDWQC+7tkcS` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_052_fcd8643d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcd8643dff51723d1250496b2a8e10d69fb6e2eb4c01c30cbad32bbf54c9ce51"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.61776561"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:44"
  condition:
    hash.sha256(0, filesize) == "fcd8643dff51723d1250496b2a8e10d69fb6e2eb4c01c30cbad32bbf54c9ce51"
}
```

### Sample 53: `5bcd63edfe855697`

| Field | Value |
|---|---|
| SHA-256 | `5bcd63edfe85569733cd75e76cb89fa3e9b3628694fa66e23e953a6724cb3ed9` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.43331428` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:43` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5f708b13d4b70dc6aac1d0a491780a7` |
| SHA-1 | `e8f545c21e8429c7f33158e1cbd25a665cf48916` |
| SHA-256 | `5bcd63edfe85569733cd75e76cb89fa3e9b3628694fa66e23e953a6724cb3ed9` |
| SHA3-384 | `b7a20d174064c0cb2716429db926db24238b16eb16de0be4819f09d48f955a1f4cc0e1fa5304a16d005bd4232c274d49` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T116D59D0BACD114F9C4AA673288B651827B35FC454F3623DB2E80B6382F727E1AC79754` |
| SSDEEP | `49152:S/fztsvObm6d9ZZHkzxTqOGO6ekB7RmaUWrJig2:S/JVzEaekB7IYr8B` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_053_5bcd63ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bcd63edfe85569733cd75e76cb89fa3e9b3628694fa66e23e953a6724cb3ed9"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.43331428"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:43"
  condition:
    hash.sha256(0, filesize) == "5bcd63edfe85569733cd75e76cb89fa3e9b3628694fa66e23e953a6724cb3ed9"
}
```

### Sample 54: `bacb8e6d037adfe4`

| Field | Value |
|---|---|
| SHA-256 | `bacb8e6d037adfe4e4643c6d8b64d47c0b7eb5a2716733871e6efde97130bd62` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.48744784` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:41` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57e8309eca711cc64df9b9abbdc05db8` |
| SHA-1 | `80e032644134d3a3bd943c238ec5e5b5c10f09bb` |
| SHA-256 | `bacb8e6d037adfe4e4643c6d8b64d47c0b7eb5a2716733871e6efde97130bd62` |
| SHA3-384 | `c2cce19ea8a83c0f6fdd53ac17c1515e07334b0cf6c8fd776fff5e799928d8046dd9a6054f1ee991ced8eb4d070af6b5` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E7D59D0B7C9149F9C86AA33289B641927B74BC094F3263D72E90B7782F767E19C35394` |
| SSDEEP | `49152:4jiVKsOPT5Bt+AFnZ0Q97JeuPhMTpct0UZL4iAPZg:4jWKz2gN0d` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_054_bacb8e6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bacb8e6d037adfe4e4643c6d8b64d47c0b7eb5a2716733871e6efde97130bd62"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.48744784"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:41"
  condition:
    hash.sha256(0, filesize) == "bacb8e6d037adfe4e4643c6d8b64d47c0b7eb5a2716733871e6efde97130bd62"
}
```

### Sample 55: `e4d6f88789bab6b4`

| Field | Value |
|---|---|
| SHA-256 | `e4d6f88789bab6b4646c872227ee03a81bed1532bb1b9953ef98b8535678886b` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.52541319` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:40` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1830bb589ad77073fe8ad97d4a8de0ff` |
| SHA-1 | `205f5a4da0e5655edaca72bcb7a3181430345959` |
| SHA-256 | `e4d6f88789bab6b4646c872227ee03a81bed1532bb1b9953ef98b8535678886b` |
| SHA3-384 | `05d0e1710f8207ba3d50532b2a99f1c29c3b25e09a6176a52cbc55547f76d588f8076e54e810d659cd712f52e888af9c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T138E58B0B7C9149EAD49AA33688B342967A75FC090F7223E32E90B6783F767E15D35740` |
| SSDEEP | `49152:gctDA/k9HWl/OH1Hxe307gU9/YFV1vTEaYEYOsewISnnghLz68mgk:gcyYTeEMU9GV1Honm6/` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_055_e4d6f887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4d6f88789bab6b4646c872227ee03a81bed1532bb1b9953ef98b8535678886b"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.52541319"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:40"
  condition:
    hash.sha256(0, filesize) == "e4d6f88789bab6b4646c872227ee03a81bed1532bb1b9953ef98b8535678886b"
}
```

### Sample 56: `316ac119eef39b92`

| Field | Value |
|---|---|
| SHA-256 | `316ac119eef39b921d33f69cde46351f2caafc7cae17fe4f2dcbd6a38284da0a` |
| Family label | `Vidar` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.62135.7466.13646` |
| File type | `exe` |
| First seen | `2026-07-04 23:59:39` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c35ad8b1ad825c4a2f5b39921b8dc44` |
| SHA-1 | `d67b8c7dff0a7be3ca8ef848593494abc8cabcd5` |
| SHA-256 | `316ac119eef39b921d33f69cde46351f2caafc7cae17fe4f2dcbd6a38284da0a` |
| SHA3-384 | `1d6163fd898be66580699d7780d3810652bbac21bd8f917aab7b896e19586405ad8117e3b49e14d64f52216c3efc3a5d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T199D59E0B7CD109E9C4A6A73648B651967B34BC1A0F7623D72ED073382E32BE19D79790` |
| SSDEEP | `49152:ntmlPoQc65tjwID3ev23xeDqVL2JhCBlbIagq:nt1Pgoa0yb7L` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_056_316ac119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "316ac119eef39b921d33f69cde46351f2caafc7cae17fe4f2dcbd6a38284da0a"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62135.7466.13646"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:39"
  condition:
    hash.sha256(0, filesize) == "316ac119eef39b921d33f69cde46351f2caafc7cae17fe4f2dcbd6a38284da0a"
}
```

### Sample 57: `b39f87a3671b4b2b`

| Field | Value |
|---|---|
| SHA-256 | `b39f87a3671b4b2be40c8431c8901fb4c57d58506a8d73356a40f2c94b45007f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 23:52:06` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79cf7a509c9b0ced4aa049f4aa1a8d4d` |
| SHA-1 | `1299af036f5b66ea843a282355d52c51630950de` |
| SHA-256 | `b39f87a3671b4b2be40c8431c8901fb4c57d58506a8d73356a40f2c94b45007f` |
| SHA3-384 | `d166e5ac51e546170b506fffcb29e965ab876d3680d035c3dc87cad9b9c60f1318adbfd8fe38ea7c0ae8150f0933ae90` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1AAE6335866D812BDFEA34038EEF39AE0E57578761772CEDB076442D4AD231E45C38A23` |
| SSDEEP | `393216:YnaVtonx2g0x/eBAENXMCHWUjXccuI3/PGTAI:YafG0xmBAoXMb8XJH/O7` |
| ICON-DHASH | `30f8d0f0e0e8f0b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_b39f87a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b39f87a3671b4b2be40c8431c8901fb4c57d58506a8d73356a40f2c94b45007f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 23:52:06"
  condition:
    hash.sha256(0, filesize) == "b39f87a3671b4b2be40c8431c8901fb4c57d58506a8d73356a40f2c94b45007f"
}
```

### Sample 58: `3aa36f96be626122`

| Field | Value |
|---|---|
| SHA-256 | `3aa36f96be62612268c0359e169fe6a8dac0cd2e628b3638e22a8173d7f8e789` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 23:47:52` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ab3f68ee647f193da0fc680ce93a5a7` |
| SHA-1 | `ca6d41e615c5d758e64b114a1efaac849ac45ac8` |
| SHA-256 | `3aa36f96be62612268c0359e169fe6a8dac0cd2e628b3638e22a8173d7f8e789` |
| SHA3-384 | `523f1c48034715913ebd21e105d62f394dd00c7bf8f8d6012e15a2edce90a868d6ff3fdc1b1ce29d6c8a31c684ef7130` |
| IMPHASH | `570a23107981914bfa2e50b080fd55c0` |
| TLSH | `T1FA15CB70F720F275C912DBF04018D7E5DA729C9CD7984017CA7A285BEBDA8DD0B1EA62` |
| SSDEEP | `6144:IFHNltn9P1mxKyy3hZq96PGCIdLZ+TO+o:En98xKyyRZc6uzZd+o` |
| ICON-DHASH | `30e8cccccccce830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_3aa36f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aa36f96be62612268c0359e169fe6a8dac0cd2e628b3638e22a8173d7f8e789"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 23:47:52"
  condition:
    hash.sha256(0, filesize) == "3aa36f96be62612268c0359e169fe6a8dac0cd2e628b3638e22a8173d7f8e789"
}
```

### Sample 59: `317e6d0cde0de866`

| Field | Value |
|---|---|
| SHA-256 | `317e6d0cde0de8664db8f5c1d6c316d61ca91ef64e59a37a522df1b7425acc0c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 23:04:59` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93bd07cf950f573d0ae03115f7db5dd3` |
| SHA-1 | `a5653be4df7f7dc8143e3d27ccf3afbfa7533431` |
| SHA-256 | `317e6d0cde0de8664db8f5c1d6c316d61ca91ef64e59a37a522df1b7425acc0c` |
| SHA3-384 | `e3919a5203d33da4bcb2514a123a76ed356e22709bd7a67c39f1b491146db6905a83aa3d8d084c12d5d888297a4db990` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T14C825C0FB9424726C0E110B49676873BDA786872338854DBFB944AED0B686D2FC3365F` |
| SSDEEP | `192:taISCngTBvqQ1jV6lXwIXZ5qF4le6qo/fKUSiu9zw+gj5tBOgbOBqmEdEFWEo/GC:FIqQlV6lOF40uu9JgFtfUhav8U9cCF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_317e6d0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "317e6d0cde0de8664db8f5c1d6c316d61ca91ef64e59a37a522df1b7425acc0c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 23:04:59"
  condition:
    hash.sha256(0, filesize) == "317e6d0cde0de8664db8f5c1d6c316d61ca91ef64e59a37a522df1b7425acc0c"
}
```

### Sample 60: `58d5ed5b67253c36`

| Field | Value |
|---|---|
| SHA-256 | `58d5ed5b67253c3644d233e721a8180ffd0b9267588c5605d98fbc049b446a01` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 23:04:02` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc09cdd2ebc0089f147e8362fa57dc0f` |
| SHA-1 | `f6ca41be2d90d4640a07bfb7586e481820cf12e3` |
| SHA-256 | `58d5ed5b67253c3644d233e721a8180ffd0b9267588c5605d98fbc049b446a01` |
| SHA3-384 | `2f6823e54c3a2f0dd0f4f5fcf32e4c78f348aaa9fc5a6d4bf9f31e17600459ca8935b3b928ef1012398e69fc73fbbc89` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T15632911E2E4B0321DE5009B4E575424A517C2EE37387EBDBE633D6DB4AD6E4580C0AAF` |
| SSDEEP | `192:jojWccS5BQcxSHO8S59jtPFJxTEZmFhquc:joBocsu3fjtPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_060_58d5ed5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58d5ed5b67253c3644d233e721a8180ffd0b9267588c5605d98fbc049b446a01"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 23:04:02"
  condition:
    hash.sha256(0, filesize) == "58d5ed5b67253c3644d233e721a8180ffd0b9267588c5605d98fbc049b446a01"
}
```

### Sample 61: `1900573180c4f539`

| Field | Value |
|---|---|
| SHA-256 | `1900573180c4f5395fcf45b79fdc1ee14fe2067dd3579970d670c9faffcbd22d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 22:52:25` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a15260c2ddd2f1f03ef5af6405d2bf9e` |
| SHA-1 | `18c3e66191fcd6d8980caaa950cc34c55958961e` |
| SHA-256 | `1900573180c4f5395fcf45b79fdc1ee14fe2067dd3579970d670c9faffcbd22d` |
| SHA3-384 | `73b080f82b67eee883e2cd1c723195d3f03e4101b2d535c9f51f611a4df7881b527751eebeab97b554505905daebbc4d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T184E6339C1AC412BEFA67903DEB62969DD6B8B0310F21C98F5B7587D0AE272D00E3C557` |
| SSDEEP | `393216:n7SmyCFCwUJkFLoTQs1XMCHWUjXhcuI3/PGTAI:nU3JJGQdXMb8X2H/O7` |
| ICON-DHASH | `71f0e4d4e4e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_19005731
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1900573180c4f5395fcf45b79fdc1ee14fe2067dd3579970d670c9faffcbd22d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 22:52:25"
  condition:
    hash.sha256(0, filesize) == "1900573180c4f5395fcf45b79fdc1ee14fe2067dd3579970d670c9faffcbd22d"
}
```

### Sample 62: `dcc3893f89bdc55d`

| Field | Value |
|---|---|
| SHA-256 | `dcc3893f89bdc55dc2f56bfccd426a7652e37b5a4e8790de99afc47bec3ecef4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `msi` |
| First seen | `2026-07-04 22:51:49` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bf5f842603e1048d1d41b6ecec8797c` |
| SHA-1 | `63f715c8309dfe0489da8e9a2908833c1eea3774` |
| SHA-256 | `dcc3893f89bdc55dc2f56bfccd426a7652e37b5a4e8790de99afc47bec3ecef4` |
| SHA3-384 | `416fb4d5a46260c7ed53a2b33942bcfa77e1da21b08b125725e6a9f8bd04229149bcd5e8f87534aa6c4559941399e095` |
| TLSH | `T1032723E6AE222D83CE6525BB23521342AF314DB23B2287113D75F90D1C7D1FA5AD9387` |
| SSDEEP | `393216:LDc8lw/6S3glvyv87upy4GCAKUdCCu3et11G0DlWziY:Liipa06RA7d9IeqGY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_dcc3893f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcc3893f89bdc55dc2f56bfccd426a7652e37b5a4e8790de99afc47bec3ecef4"
    family = "unknown"
    file_name = "file"
    file_type = "msi"
    first_seen = "2026-07-04 22:51:49"
  condition:
    hash.sha256(0, filesize) == "dcc3893f89bdc55dc2f56bfccd426a7652e37b5a4e8790de99afc47bec3ecef4"
}
```

### Sample 63: `698bc8bcff623634`

| Field | Value |
|---|---|
| SHA-256 | `698bc8bcff6236341a6ad1d222e65c1b3771ca2a7042f3bd9cc5e1c40c4f392e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 22:47:50` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d33f742030f90c706adeaf4a634e2b11` |
| SHA-1 | `ec200fb39c72d1041a91fa9713354ff8dd22da40` |
| SHA-256 | `698bc8bcff6236341a6ad1d222e65c1b3771ca2a7042f3bd9cc5e1c40c4f392e` |
| SHA3-384 | `c46cff1b1a69598d26042340b117dc72c31261d66ac8755a805c13cd582614ccc4416dcb6edd334b084c4fe44adc39be` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1F7825B0FB941472AC0E110B49676877BDAB86871338414DBFB948AED0A686D2FC3365F` |
| SSDEEP | `384:l6IqQ1VaFuxoSZuu9JgFtfURav8U9cFF:lQRUD9ba0U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_698bc8bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "698bc8bcff6236341a6ad1d222e65c1b3771ca2a7042f3bd9cc5e1c40c4f392e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 22:47:50"
  condition:
    hash.sha256(0, filesize) == "698bc8bcff6236341a6ad1d222e65c1b3771ca2a7042f3bd9cc5e1c40c4f392e"
}
```

### Sample 64: `7fd7a0a3703782d6`

| Field | Value |
|---|---|
| SHA-256 | `7fd7a0a3703782d6eee97a8bfbd82e77ab65ebb7c5af3407bfc21c4ec1dd2ac9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 22:46:28` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e05db546225b635b3722764e3c73a461` |
| SHA-1 | `61acdd8d51cdb9db741739411fe9cfc89fe50728` |
| SHA-256 | `7fd7a0a3703782d6eee97a8bfbd82e77ab65ebb7c5af3407bfc21c4ec1dd2ac9` |
| SHA3-384 | `091d6d21b14f9b686129cdc70d422d71e29aadc9d90904573d97a0907f4ad18838cd04bdf858a2127a2f69c42d170f69` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T143825B0FB9424726C0E110B49676863BDA78687233C854DBFB944AED0B686D2FC3365F` |
| SSDEEP | `192:0aISCngTBvqQ1jV6lXwIXZ5qh4le6qo/fKUSiu9zw+gj5tBOgbOBqmEdEFWEo/GN:0IqQlV6lOh40uu9JgFtfUhav8U9cBF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_7fd7a0a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fd7a0a3703782d6eee97a8bfbd82e77ab65ebb7c5af3407bfc21c4ec1dd2ac9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 22:46:28"
  condition:
    hash.sha256(0, filesize) == "7fd7a0a3703782d6eee97a8bfbd82e77ab65ebb7c5af3407bfc21c4ec1dd2ac9"
}
```

### Sample 65: `7084792a0c28fb37`

| Field | Value |
|---|---|
| SHA-256 | `7084792a0c28fb37ec207c2b0a12dae8e6d43996e6b56cfe6f78970d72886121` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 22:38:10` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f59a897ace537928af73ac6442a9ad66` |
| SHA-1 | `5a1ed24cba996376ebf3bb1c236adb0b309babcb` |
| SHA-256 | `7084792a0c28fb37ec207c2b0a12dae8e6d43996e6b56cfe6f78970d72886121` |
| SHA3-384 | `45f0e0da381744059cf2538e1c7c4cbef917b5e5fd9d88801ef2df7f128d2e5a95a348eca3619e9b5395232a9384e75b` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T158825C0FB9424726C0E110B49676873BDA786871338854DBF7948AED0B686D2FC3365F` |
| SSDEEP | `192:N2aISCngTBvqQ1jV6lXwIXZ5qh4le6qo/fKUSiu9zw+gj5tBOgbOBqmEdEFWEo/p:NyIqQlV6lOh40uu9JgFtfUhav8U9cuF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_7084792a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7084792a0c28fb37ec207c2b0a12dae8e6d43996e6b56cfe6f78970d72886121"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 22:38:10"
  condition:
    hash.sha256(0, filesize) == "7084792a0c28fb37ec207c2b0a12dae8e6d43996e6b56cfe6f78970d72886121"
}
```

### Sample 66: `d7e334967a876168`

| Field | Value |
|---|---|
| SHA-256 | `d7e334967a876168a3437f68020fd181e7e2320ea2742fc3583d3015025b1f6b` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 21:52:25` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a5775b4ebfb602d389f32f276fa27a6` |
| SHA-1 | `194aa965f6f0ca3777e8e74015531ec9a1f6edb1` |
| SHA-256 | `d7e334967a876168a3437f68020fd181e7e2320ea2742fc3583d3015025b1f6b` |
| SHA3-384 | `b86aeee7611cad40b4180ea4cbe29acfee2df0e97e85a2bddfc7bcf26f26beee744aa0b20c30a0f2edd65ff0ff66f2ff` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T109E6332C67D012FFE573413C9AB19991D469B87A5773CAEF07D09BA25E832E08C39643` |
| SSDEEP | `393216:YEHvucHaq9Vb7bMMV/6o6UDAo7XMCHWUjX1cuI3/PGTAI:YEHVXMMVyHU8o7XMb8XCH/O7` |
| ICON-DHASH | `d4f070e8e8617138` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_d7e33496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7e334967a876168a3437f68020fd181e7e2320ea2742fc3583d3015025b1f6b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 21:52:25"
  condition:
    hash.sha256(0, filesize) == "d7e334967a876168a3437f68020fd181e7e2320ea2742fc3583d3015025b1f6b"
}
```

### Sample 67: `10424631b904e849`

| Field | Value |
|---|---|
| SHA-256 | `10424631b904e8498cb388966b92f850d9ddaed105188e73010533b66717829d` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-04 21:52:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fa9c44f2937f40a5d70a55c31e1b43b` |
| SHA-1 | `8dd378fd4e6ed1444de39ed5b1f5087045695b56` |
| SHA-256 | `10424631b904e8498cb388966b92f850d9ddaed105188e73010533b66717829d` |
| SHA3-384 | `a440c8b18c6377ae3e2bb4ed4168a883a033310c29fa0ece3c494a660e0184d2d5da1d46f6974fcc22a0dd537336259d` |
| TLSH | `T1AA44F607BBA18EB3C89FDD3706FA870120CEF4572564672B7274DA5CBA0A54F49D38A4` |
| TELFHASH | `t144713158d43d09e9eea35d19a8692bf34993e12926f46b18ff66cdc0081f42df224d0f` |
| SSDEEP | `6144:TKAyh+9hIUcwUkRMtbzfbT+Zy7KwmtwAL4OObI:TK54vIFkRMtPbT+Zy7KwmtwAL4OObI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_10424631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10424631b904e8498cb388966b92f850d9ddaed105188e73010533b66717829d"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-04 21:52:14"
  condition:
    hash.sha256(0, filesize) == "10424631b904e8498cb388966b92f850d9ddaed105188e73010533b66717829d"
}
```

### Sample 68: `4b98c014977ad113`

| Field | Value |
|---|---|
| SHA-256 | `4b98c014977ad113c22aaf5f794c567c41f8b7e6b77a3cab964116a1d8b0a542` |
| Family label | `unknown` |
| File name | `aintall.6638250006.msi` |
| File type | `msi` |
| First seen | `2026-07-04 21:32:34` |
| Reporter | `CNGaoLing` |
| Tags | `Gh0st, Gh0stRAT, msi, SilverFox` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12455676af0b269860b383ed870d4cc2` |
| SHA-1 | `e473c0ec54ad78a11ed23cafa635497e46d0066c` |
| SHA-256 | `4b98c014977ad113c22aaf5f794c567c41f8b7e6b77a3cab964116a1d8b0a542` |
| SHA3-384 | `71e5f018fbe8aaca869acb60fd347eef4d95eaee920ca28159fc342cd26e2f9d320451bb8edbe25c9dce3c7a53e88cde` |
| TLSH | `T19B5633C4BAA55171C0ABCB744503A66EB12C3FC4BAA59C077ADDF7244F33B1A24B6781` |
| SSDEEP | `98304:gO76GUkZKFpFOBHM9yqjshiRj+0b36o1mXAxSJOszHs29Wc/ld/NubjwIlyDmUN0:f6GUkoFOBHMMqjiiN+0H1moY/JpWbsFg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_4b98c014
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b98c014977ad113c22aaf5f794c567c41f8b7e6b77a3cab964116a1d8b0a542"
    family = "unknown"
    file_name = "aintall.6638250006.msi"
    file_type = "msi"
    first_seen = "2026-07-04 21:32:34"
  condition:
    hash.sha256(0, filesize) == "4b98c014977ad113c22aaf5f794c567c41f8b7e6b77a3cab964116a1d8b0a542"
}
```

### Sample 69: `0ea72062143e9dd4`

| Field | Value |
|---|---|
| SHA-256 | `0ea72062143e9dd49fecfccfa6dd2594d3f6f831e5ff9b0b5aa91631afdd8724` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 20:53:50` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, E, exe, signed, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a67dc70cd397d23aca3cff0fcfeb72f` |
| SHA-1 | `c344482878852e01cd7986e8ae1ac541e7a6f049` |
| SHA-256 | `0ea72062143e9dd49fecfccfa6dd2594d3f6f831e5ff9b0b5aa91631afdd8724` |
| SHA3-384 | `69318e918338a960dbad6d71bac58e737d6b61d60c65ba0009c55c4b0f2e454ac44d257f7c2ee1fbd9c280367c6ae969` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T138F58C07ECA148E5C0A9A332C9B7959A7736BC091B3227D72E60A7783F727C06D35B15` |
| SSDEEP | `49152:Jy+9ZTMEEzDKGK9BsfnRFFZoFjkZLN6zgN7n9Cye:JP2K9mFrZ6zgN796` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_0ea72062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ea72062143e9dd49fecfccfa6dd2594d3f6f831e5ff9b0b5aa91631afdd8724"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 20:53:50"
  condition:
    hash.sha256(0, filesize) == "0ea72062143e9dd49fecfccfa6dd2594d3f6f831e5ff9b0b5aa91631afdd8724"
}
```

### Sample 70: `61c398e690795f37`

| Field | Value |
|---|---|
| SHA-256 | `61c398e690795f37e111ecf8050f371c7e31bc99b7eacd92c8cf356649c72c0d` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 20:52:05` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd6dc486c4a0de0b9460a709cb92b085` |
| SHA-1 | `6933770c4661da278d66912b595016f08822f928` |
| SHA-256 | `61c398e690795f37e111ecf8050f371c7e31bc99b7eacd92c8cf356649c72c0d` |
| SHA3-384 | `2d6ea5f4b343c7af912211f09bb5f9db0fa1be2700abf6b9e9a969cebb8a0459231bc5c5bee46a5972a115cccc7032fc` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T166E6330C6AD101FEE6B3807C9DE15255E57870960772C98F4BA487B12DA72F2CE39B4B` |
| SSDEEP | `393216:hqc6J4CnXLzAdg4IWfXMCHWUjXQcuI3/PGTAI:h7Mn/Ai4I2XMb8XFH/O7` |
| ICON-DHASH | `f0f0dc8682c4f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_61c398e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61c398e690795f37e111ecf8050f371c7e31bc99b7eacd92c8cf356649c72c0d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 20:52:05"
  condition:
    hash.sha256(0, filesize) == "61c398e690795f37e111ecf8050f371c7e31bc99b7eacd92c8cf356649c72c0d"
}
```

### Sample 71: `36e70b9c5271aefe`

| Field | Value |
|---|---|
| SHA-256 | `36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179` |
| Family label | `unknown` |
| File name | `36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179` |
| File type | `elf` |
| First seen | `2026-07-04 20:43:15` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `584a173a7a32756b26c4a5dfe0356b25` |
| SHA-1 | `1b6fa52c604ef081e5c1358ede5a182d7e3a4adf` |
| SHA-256 | `36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179` |
| SHA3-384 | `8ee6684f1808a4922358c71d4f671dff66fa30b522f399e26b09ee3e6490d58384f0d02f3d0d6b0a3c4ddd0e8ee94725` |
| TLSH | `T17D85F757F89590F4C0EEE174C726A213BAA13499473437E36FA18AF11B26FE466BC314` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzd:cqYUQuVDp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_36e70b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179"
    family = "unknown"
    file_name = "36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179"
    file_type = "elf"
    first_seen = "2026-07-04 20:43:15"
  condition:
    hash.sha256(0, filesize) == "36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179"
}
```

### Sample 72: `1412ef99e1bdbc0e`

| Field | Value |
|---|---|
| SHA-256 | `1412ef99e1bdbc0ef34df0b25f9455cdee4a40984c4caec099a8e9f08b21301a` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 20:35:40` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc32cc4b61f03675e3aafe72543b0d5e` |
| SHA-1 | `9c7ff829477cd46e84a2e74501f79d46c874c0ba` |
| SHA-256 | `1412ef99e1bdbc0ef34df0b25f9455cdee4a40984c4caec099a8e9f08b21301a` |
| SHA3-384 | `dd395daf6016302fa880763b20da257437d60cb2197a4d1bce1a551544d7a035d31dfbddf979d5ec63c8c47fb6b8c48e` |
| IMPHASH | `d1c35276ff2b8e9d448afb940bccb1f0` |
| TLSH | `T1D0043A5BD5D540E9EC1AC6348A99E237A4B3F8562936BA4F2BA0DF051F90B30B71DF04` |
| SSDEEP | `3072:nftXePELBxpwWAkcv3CQAEALqmECASmTiAG625g2F87Ak0ght:VO2p2ki3CQlAuBAmTGdg2SMght` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_072_1412ef99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1412ef99e1bdbc0ef34df0b25f9455cdee4a40984c4caec099a8e9f08b21301a"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 20:35:40"
  condition:
    hash.sha256(0, filesize) == "1412ef99e1bdbc0ef34df0b25f9455cdee4a40984c4caec099a8e9f08b21301a"
}
```

### Sample 73: `444ae54b9603d446`

| Field | Value |
|---|---|
| SHA-256 | `444ae54b9603d446ca3497bf3a8647f16a43786798631f88a1de1db48ebba09a` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-07-04 20:16:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38bdd5fb79d09e9ad03acdaabd85d9e5` |
| SHA-1 | `ca8bc0ab1006d234a7e5816408d6b87c894f4c4d` |
| SHA-256 | `444ae54b9603d446ca3497bf3a8647f16a43786798631f88a1de1db48ebba09a` |
| SHA3-384 | `0b3575557cc86f6a952084c291bb24502a269a432dc8c5238a35b3903377c2454cd092e3f18326e9bbc35df0e8672bc1` |
| TLSH | `T1A5B35BB3DC26AF98C655D074B0B08FB92F53A59482471FBE19B6C2B44443D8DFA05BB8` |
| SSDEEP | `1536:WTW/VCxsHZusj2Li62C8vqKTR5/PPVGAto2WszrW+TNe7Z:WytCxsjx62NFT7VG92WcrbwN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_444ae54b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "444ae54b9603d446ca3497bf3a8647f16a43786798631f88a1de1db48ebba09a"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-07-04 20:16:09"
  condition:
    hash.sha256(0, filesize) == "444ae54b9603d446ca3497bf3a8647f16a43786798631f88a1de1db48ebba09a"
}
```

### Sample 74: `53faf93d2f0a5cac`

| Field | Value |
|---|---|
| SHA-256 | `53faf93d2f0a5caccf8a99a797602c07aa0d19a26249feb705570cb2fbd9483f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-04 20:12:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b6e19ccce188151d67eec2c397d14c6` |
| SHA-1 | `93eb5e19dd2a0c69479151f6de9fb75b75b9326e` |
| SHA-256 | `53faf93d2f0a5caccf8a99a797602c07aa0d19a26249feb705570cb2fbd9483f` |
| SHA3-384 | `799f0dc8816dff0a334c9b6ae8480a2cff8ec34a399358eb5bf73323a1c2ca69e478e35f7ae321b266b6bcb4105498b9` |
| TLSH | `T1C4236C6516857C24AA99C4375C7F2F0CBDA983E6314491DDBFCA3CF28C4AA9CE21871D` |
| SSDEEP | `768:PDr9NyXsZztCd9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:/HusZbcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_53faf93d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53faf93d2f0a5caccf8a99a797602c07aa0d19a26249feb705570cb2fbd9483f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-04 20:12:04"
  condition:
    hash.sha256(0, filesize) == "53faf93d2f0a5caccf8a99a797602c07aa0d19a26249feb705570cb2fbd9483f"
}
```

### Sample 75: `38809fbd8e2c55db`

| Field | Value |
|---|---|
| SHA-256 | `38809fbd8e2c55db79df0c71984ec5be8988f27f423674e5f6f58f572c2118c3` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-07-04 19:53:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `badc57a353888f262c3358be1b117081` |
| SHA-1 | `7571745b5119a5e6a83ee133ef1070c8e83b85f8` |
| SHA-256 | `38809fbd8e2c55db79df0c71984ec5be8988f27f423674e5f6f58f572c2118c3` |
| SHA3-384 | `a1f7566b2bb9ee71e625b5e227bdec518a0186bf684a8909ab581b1bfe7bac6051ceb000b8cbaa79d284e0cccaa99ff2` |
| TLSH | `T1A304C719AB510FBBDCAFDD3702E90B0139CC955B22A93B363674D528F54E50B4AE3C68` |
| SSDEEP | `3072:nKpzGZeNkSfcQqmav8SqaRVlnYz6521t:nKYZeNYQqmeqavlg652` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_38809fbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38809fbd8e2c55db79df0c71984ec5be8988f27f423674e5f6f58f572c2118c3"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-07-04 19:53:01"
  condition:
    hash.sha256(0, filesize) == "38809fbd8e2c55db79df0c71984ec5be8988f27f423674e5f6f58f572c2118c3"
}
```

### Sample 76: `c6048c44535ab5fe`

| Field | Value |
|---|---|
| SHA-256 | `c6048c44535ab5fe1f7af9047eacf7225d88fc7b0c9324c1595a8b45d2d9588e` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 19:52:25` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33f8017e45465207aa2aac600e0b1fa1` |
| SHA-1 | `834d8b30b5544b1d568e654011463fbc02a6d323` |
| SHA-256 | `c6048c44535ab5fe1f7af9047eacf7225d88fc7b0c9324c1595a8b45d2d9588e` |
| SHA3-384 | `883ba50cf6ba02808c7a5dea0bef1727997ae5af1c6bf2a96250d4266cdf51b358bbb42ee51048eb9ab6e3bcf7c916b8` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E7E6335465E522FEEEA3413EE8E195C9C939787A1B33C5AF03A007656F270F0DD7920A` |
| SSDEEP | `393216:x3Mtni0QB+bQjubnLBtsQw8YXMCHWUjXRcuI3/PGTAI:x3qnc+bQjALBty8YXMb8XGH/O7` |
| ICON-DHASH | `71f8d0f0f0e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_c6048c44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6048c44535ab5fe1f7af9047eacf7225d88fc7b0c9324c1595a8b45d2d9588e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 19:52:25"
  condition:
    hash.sha256(0, filesize) == "c6048c44535ab5fe1f7af9047eacf7225d88fc7b0c9324c1595a8b45d2d9588e"
}
```

### Sample 77: `adf43c66f5394bc1`

| Field | Value |
|---|---|
| SHA-256 | `adf43c66f5394bc13aaaf3df3adaa6debeb69aa7bb126b665f1b2522607b8225` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 19:42:54` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `650e5e901ef003b85999cdeaa80de3ab` |
| SHA-1 | `1c9788a4749b807e12d03af17ecf45f16e725bc1` |
| SHA-256 | `adf43c66f5394bc13aaaf3df3adaa6debeb69aa7bb126b665f1b2522607b8225` |
| SHA3-384 | `6a588874a985de6a5ac7b366d60705365fa7faa01552b915867b7481081b44f195fa8b7e95d6562e4ca4515cc1bf2866` |
| IMPHASH | `d1c35276ff2b8e9d448afb940bccb1f0` |
| TLSH | `T155044A5BD8D540E9EC1AC638899AE237A4B2FC561936BA4F6BA0DF051F90B30771DF04` |
| SSDEEP | `3072:II4i4F/omV25ANhQHRtL7H87shCVybLDVVBhPliai7Ak0ght:AVNWxtL7ceKyL5hPliaOMght` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_077_adf43c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adf43c66f5394bc13aaaf3df3adaa6debeb69aa7bb126b665f1b2522607b8225"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:42:54"
  condition:
    hash.sha256(0, filesize) == "adf43c66f5394bc13aaaf3df3adaa6debeb69aa7bb126b665f1b2522607b8225"
}
```

### Sample 78: `0d4e9e01ec989627`

| Field | Value |
|---|---|
| SHA-256 | `0d4e9e01ec989627f77a09f744574f2bbd733f53b1736a2cc857c28bb4d820b3` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-07-04 19:41:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6eabba2e577e3a074ad125e07a0192a4` |
| SHA-1 | `7075ed45ba61c554e43d1352fd65eb6d5ab84761` |
| SHA-256 | `0d4e9e01ec989627f77a09f744574f2bbd733f53b1736a2cc857c28bb4d820b3` |
| SHA3-384 | `da16b896334222a60a77416de0e627cda9baef3fa660c44c4ed7b4ce79a446113db96b4243984a5c31202b73d41af962` |
| TLSH | `T100E30A46F8814B12D5D111BAFE1E128E37131BB8E2DE73029D246F647B8A97F0E3B915` |
| TELFHASH | `t1a1d0a781de182c54d6f49069c1ee6266679171d13f4460875eea1c5706310e7707030f` |
| SSDEEP | `3072:aTe9DGwUMhyTxXMbSrjWa223+t+T8PSpLC:ueBGw3wxXGSrCanP8PSpLC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_0d4e9e01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4e9e01ec989627f77a09f744574f2bbd733f53b1736a2cc857c28bb4d820b3"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-07-04 19:41:59"
  condition:
    hash.sha256(0, filesize) == "0d4e9e01ec989627f77a09f744574f2bbd733f53b1736a2cc857c28bb4d820b3"
}
```

### Sample 79: `5139f93689b44649`

| Field | Value |
|---|---|
| SHA-256 | `5139f93689b446491172f9d157d563a91ba5e1da1403591eebbbb9d66d15549c` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 19:34:03` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX3.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6395ec00b00be5437122936e25d83f3` |
| SHA-1 | `2ebc0c7c1d0d08ba31b23d7b066cd3532f427456` |
| SHA-256 | `5139f93689b446491172f9d157d563a91ba5e1da1403591eebbbb9d66d15549c` |
| SHA3-384 | `797d5c59fe69c08bbe9daa4a0c33a2bb4b2bed609a393e22db423c6408fea2b6653bd00de2231a5e769cb6bde1a6771b` |
| IMPHASH | `67f6728bb9c2c56c262f6da70935d9d5` |
| TLSH | `T108548E5AF7A508FAEE77817CC9524601EA727C564760D6CF03A04AA72F237E09E3E711` |
| SSDEEP | `3072:QsZJwWBXV+WISOMphc7/25Y4jcZSmh0WFS05e5HVmFYt1zDye0KGnX5/j25HzX9U:hZfmQY4oYmh5sJ/KGrT9G1zE8RLM0` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_079_5139f936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5139f93689b446491172f9d157d563a91ba5e1da1403591eebbbb9d66d15549c"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:34:03"
  condition:
    hash.sha256(0, filesize) == "5139f93689b446491172f9d157d563a91ba5e1da1403591eebbbb9d66d15549c"
}
```

### Sample 80: `aff2feb0de45aa7c`

| Field | Value |
|---|---|
| SHA-256 | `aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e` |
| Family label | `unknown` |
| File name | `aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e` |
| File type | `elf` |
| First seen | `2026-07-04 19:31:25` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cfeb986d73f28d362bc3e00c04e21af` |
| SHA-1 | `d4c6846c48ced43c924c863866b051a6fcab1b2b` |
| SHA-256 | `aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e` |
| SHA3-384 | `795633f10b4d6e3ac7eaae759273b360c0185cc2683f65010f6aa87b9698fd6a664ce8d75c6a46786fbd532e5e3c8c0e` |
| TLSH | `T15647DF77814238E9E5B98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ3:cqYUQuVDt0TZEg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_aff2feb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e"
    family = "unknown"
    file_name = "aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e"
    file_type = "elf"
    first_seen = "2026-07-04 19:31:25"
  condition:
    hash.sha256(0, filesize) == "aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e"
}
```

### Sample 81: `10346d6fe66d5f29`

| Field | Value |
|---|---|
| SHA-256 | `10346d6fe66d5f29516bc9479de6c47392b0537a9c00389d1d3871243dcc0854` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-04 19:29:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b86220403f57735f1ae154dec9c3b226` |
| SHA-1 | `231e71c502b60401960c29aedce1e9bee3c281dc` |
| SHA-256 | `10346d6fe66d5f29516bc9479de6c47392b0537a9c00389d1d3871243dcc0854` |
| SHA3-384 | `4631d3443b5521336c41f0c05db9f3c31981b75dfc7691dd41911f6f652786d5f996b424c9f925e92d31cab513c3b9e8` |
| TLSH | `T1D7243A05EB408B53C49627B9FA9F43113323D758E7A773059A28ABB03F8779E4F62506` |
| TELFHASH | `t137313f85d43d88696ef26c2cec2927f2455397211b705a20dfaac4c42c2f00af932c2b` |
| SSDEEP | `6144:HYkaY+1Y4ECaHKLrg70mT4JTIrqWFYqYV/GJVRk6IE:HYvY++4ECaHKLrgpEyrQ7/GHIE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_10346d6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10346d6fe66d5f29516bc9479de6c47392b0537a9c00389d1d3871243dcc0854"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-04 19:29:08"
  condition:
    hash.sha256(0, filesize) == "10346d6fe66d5f29516bc9479de6c47392b0537a9c00389d1d3871243dcc0854"
}
```

### Sample 82: `01d80b720d55ed10`

| Field | Value |
|---|---|
| SHA-256 | `01d80b720d55ed1098ccabe709a582e1322ee2afd357981a8190531915af5ad4` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-07-04 19:27:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f857ce63168999a9d52fedadfad80e22` |
| SHA-1 | `f9b097910cd7f67cf6c8d78818b48f59e5193d49` |
| SHA-256 | `01d80b720d55ed1098ccabe709a582e1322ee2afd357981a8190531915af5ad4` |
| SHA3-384 | `f7b8e21b7f37b5aea4822e12f97e019d144a6fa8c288aee7b89c28c9d0344aa21ae2e790cd95049cc613cd472892782b` |
| TLSH | `T14A042945EA404B13C4D627B9F6DF42453333AB9493EB73069528AFB43F8679E4F22A05` |
| TELFHASH | `t178310071567851269aa1ec64d9ed97b2652ac7171340ff32df26c0cc281a449f62ac0f` |
| SSDEEP | `3072:8Le6vh5G1QIruCee+asuTuRebU7IVILTZQe38YhTfYo+M/RzApthLn:0e6vfRIr1r+asuTuReAvLT/38+x+M/R+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_01d80b72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01d80b720d55ed1098ccabe709a582e1322ee2afd357981a8190531915af5ad4"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-07-04 19:27:11"
  condition:
    hash.sha256(0, filesize) == "01d80b720d55ed1098ccabe709a582e1322ee2afd357981a8190531915af5ad4"
}
```

### Sample 83: `1ef81db33375ce7f`

| Field | Value |
|---|---|
| SHA-256 | `1ef81db33375ce7fb1a6e22cc88f7711d7cce2845e4c5f8bb4e4a0aa11917e86` |
| Family label | `Mirai` |
| File name | `dg.mips` |
| File type | `elf` |
| First seen | `2026-07-04 19:23:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1b68a8243ea51726d1476fa4a52d096` |
| SHA-1 | `8ce67fd4b776bbab694646295a68ba969e8b7757` |
| SHA-256 | `1ef81db33375ce7fb1a6e22cc88f7711d7cce2845e4c5f8bb4e4a0aa11917e86` |
| SHA3-384 | `af9f2d7aadc75e400baba5b6d5abc7f9834c767da3af292c3a8f4117ce84cb8424a103b5dee598d3550ba0b6b4138d82` |
| TLSH | `T1ED24B61E6E328F7DF268C73447F74A34A75923D626E1D684D1ACD1142F2039E681FBA8` |
| TELFHASH | `t1fe41955c0d7817b0b2655c9d05ddff76d6a330da7e262c238f51e86aab78a835d10c1c` |
| SSDEEP | `3072:itFiiwqTH9cEDJGMqbtiEdppbDdBUewcggWr6O1VsbzjI7KOH:itFiin9cEDotikbB22NWR1KbzjdOH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_1ef81db3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ef81db33375ce7fb1a6e22cc88f7711d7cce2845e4c5f8bb4e4a0aa11917e86"
    family = "Mirai"
    file_name = "dg.mips"
    file_type = "elf"
    first_seen = "2026-07-04 19:23:45"
  condition:
    hash.sha256(0, filesize) == "1ef81db33375ce7fb1a6e22cc88f7711d7cce2845e4c5f8bb4e4a0aa11917e86"
}
```

### Sample 84: `6ed2f848536d84e6`

| Field | Value |
|---|---|
| SHA-256 | `6ed2f848536d84e6fd14eb4258f1f5ac95a1c3ad87dbc42c5b7fc5af812d06d7` |
| Family label | `Mirai` |
| File name | `dg.mips` |
| File type | `elf` |
| First seen | `2026-07-04 19:22:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8588e5933af154289c26ab43dcd2ad0` |
| SHA-1 | `1d79c74c62087d9fd19d530875589a3fe71625d0` |
| SHA-256 | `6ed2f848536d84e6fd14eb4258f1f5ac95a1c3ad87dbc42c5b7fc5af812d06d7` |
| SHA3-384 | `d42854755f3d94d59b484fbbd4269a1f3d4dc539fb3db39135dd190d222eab1a3faa2b555e6874c684e354f805a00c56` |
| TLSH | `T19C6302FF97A1E358E677E03146C903B01BE11D58C6A7EECC9902278591334A5B784F6E` |
| SSDEEP | `1536:RljtNfVwI1hQZbnxkL97b0Vk18az19D1FvNiCKlPi0oVEW1:RtttduZDWB7gk18M9oC0K5VEe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_6ed2f848
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ed2f848536d84e6fd14eb4258f1f5ac95a1c3ad87dbc42c5b7fc5af812d06d7"
    family = "Mirai"
    file_name = "dg.mips"
    file_type = "elf"
    first_seen = "2026-07-04 19:22:02"
  condition:
    hash.sha256(0, filesize) == "6ed2f848536d84e6fd14eb4258f1f5ac95a1c3ad87dbc42c5b7fc5af812d06d7"
}
```

### Sample 85: `f504852cbbb545c4`

| Field | Value |
|---|---|
| SHA-256 | `f504852cbbb545c41c227f85171632c919503e44c1aa9d52253e750bdf1b995c` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-07-04 19:15:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `153457e99671346e813fb84496972693` |
| SHA-1 | `f89dd1a76c3d7f9c3e1e40bdaf8b22c02f8177a8` |
| SHA-256 | `f504852cbbb545c41c227f85171632c919503e44c1aa9d52253e750bdf1b995c` |
| SHA3-384 | `9d5e00bfe4ba79da87c8eff2f6525fab32e8e70145b199a2538a78263223a1d2f2285417e0bc3c9f1a6a3488ba3ba632` |
| TLSH | `T183C31B45FC404B23C6D612BBFB5E428D3B2A17D9D3EE720399215F60378686B0E3B646` |
| TELFHASH | `t1e1114416cf5c01de3fe04208956ab50b9c64359d1bb775434c757a0fe382ce3306e821` |
| SSDEEP | `1536:pnK20FG5NCjNoCDMQkYOqcW2AcRX4VRo6TDjJtCyMLYRCCaXYv4BPQlnKwywDROn:BK23kPRPOfW2R446rJtCZLYpQYAHbN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_f504852c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f504852cbbb545c41c227f85171632c919503e44c1aa9d52253e750bdf1b995c"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-07-04 19:15:24"
  condition:
    hash.sha256(0, filesize) == "f504852cbbb545c41c227f85171632c919503e44c1aa9d52253e750bdf1b995c"
}
```

### Sample 86: `ec6af7f9aeb339a3`

| Field | Value |
|---|---|
| SHA-256 | `ec6af7f9aeb339a3ca03f50be96d8b7063dec7f7f3bd53f9a3ab6fb81b89afba` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 19:13:14` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e1b503f9cc84c0de371e827d5e1fea4` |
| SHA-1 | `2f3bf18f551f3bc20affb9798def24fde11f63ff` |
| SHA-256 | `ec6af7f9aeb339a3ca03f50be96d8b7063dec7f7f3bd53f9a3ab6fb81b89afba` |
| SHA3-384 | `1ca9e2b4da7770ee1ebe60ffb81155d3e21ed051f1c5f49d24a3f74f8032a6811cdca7ca7e6bf9f5fe678450dd1a7f69` |
| IMPHASH | `ca30fe585f3c506bf603153bca46c40e` |
| TLSH | `T14A259B61EB64F2B6E815D772940CCAF1DF737C5AC7B4002F5A1D601BE3D3A8653A8A24` |
| SSDEEP | `6144:aqUuTMYA5V52htQYvla8xoIb3wDrkAf7LPHoSjmGMjEi:YuTMp5qUao8Tw3kAf7UAmGOB` |
| ICON-DHASH | `f09682aaaa8296f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_ec6af7f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec6af7f9aeb339a3ca03f50be96d8b7063dec7f7f3bd53f9a3ab6fb81b89afba"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:13:14"
  condition:
    hash.sha256(0, filesize) == "ec6af7f9aeb339a3ca03f50be96d8b7063dec7f7f3bd53f9a3ab6fb81b89afba"
}
```

### Sample 87: `ae6e2ee1f562285f`

| Field | Value |
|---|---|
| SHA-256 | `ae6e2ee1f562285f3a357e26ec7543854a41e829b75257e6fd5d6ee6d7d10693` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-07-04 19:10:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ad89509522c77d773928aaa7cbbb1ba` |
| SHA-1 | `1a3677fe72edd22824de091aa610a0f42500b626` |
| SHA-256 | `ae6e2ee1f562285f3a357e26ec7543854a41e829b75257e6fd5d6ee6d7d10693` |
| SHA3-384 | `b2ebc3f5dbbc59f5722cd7180328c1e3368af0ca5d2b255465949d4e5fc54cc15bf0f0a3109f83baa0a984ce51da5598` |
| TLSH | `T1D3E329C7F800DEFAF80AE33748570905B630BBE115921B372257797BED3A1991963E86` |
| SSDEEP | `3072:qmzTDH86JK78FO7xtjA7s2idk6w9YwVvjbiXL+noy+WYPr:q2TDH86JO3jA7sHda9YPLry+pPr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_ae6e2ee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae6e2ee1f562285f3a357e26ec7543854a41e829b75257e6fd5d6ee6d7d10693"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-07-04 19:10:18"
  condition:
    hash.sha256(0, filesize) == "ae6e2ee1f562285f3a357e26ec7543854a41e829b75257e6fd5d6ee6d7d10693"
}
```

### Sample 88: `4af306ca60a93680`

| Field | Value |
|---|---|
| SHA-256 | `4af306ca60a936809d8f33ecc20d9135fe130b8034fe2db174e91d54716614a7` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-07-04 19:08:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63e98a1468129141405bb90451b04b48` |
| SHA-1 | `e30f192801aac9f60018a7c5e9a4e0ac49c8a085` |
| SHA-256 | `4af306ca60a936809d8f33ecc20d9135fe130b8034fe2db174e91d54716614a7` |
| SHA3-384 | `a2e9802ff141dc064889ec557b75562f05a17ac3cf4d638f0a0f5a5bf3585b49f053f920540389cba0b8f1870ba75068` |
| TLSH | `T14CD30945F8505B23C6C612BBFB5E428D3B2A17E9D3EF720399216F20378695B0E37946` |
| TELFHASH | `t1a41150c58b946a5d9ff0100dc69fb10360b070496b0b34a38e2e762b92132d1b81cc13` |
| SSDEEP | `1536:kKdnEPmm8uKrRZWjp7F8PAZYg4V9z6mTQfoAO0fF5wpr8VBipAFly+wywnRl2JI3:kKtV8Nh8P24PvsoAOwFMo+pC6+KN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_4af306ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4af306ca60a936809d8f33ecc20d9135fe130b8034fe2db174e91d54716614a7"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-07-04 19:08:15"
  condition:
    hash.sha256(0, filesize) == "4af306ca60a936809d8f33ecc20d9135fe130b8034fe2db174e91d54716614a7"
}
```

### Sample 89: `f644411026620ae3`

| Field | Value |
|---|---|
| SHA-256 | `f644411026620ae3f8d2c7cca2067d594b6ced57429a2291f90bac663d06d40c` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 19:08:00` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6b3b5a699a8cd55456e0d6f1b5b6ad3` |
| SHA-1 | `f7e7d813b5cf876d0c4d5179b3897c63e1a4be3c` |
| SHA-256 | `f644411026620ae3f8d2c7cca2067d594b6ced57429a2291f90bac663d06d40c` |
| SHA3-384 | `54f657ffaaf0584c65d600b0fdaf1bf4c2c39e5c84f5196a362d6a93942d70d88403a203d28e43cc2e380b5a88da9e24` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1B8C60233A24B613DE02E06392E7AD122553B6E717D624E0F96E434ACCF3D1607DBA647` |
| SSDEEP | `98304:EoJJqDrBRi7+FyPit+oGd88jPRpt1UksRrgvGa+1hwE3gmpRgrYVNljQ:HuFRi70y4+BjPRp6REvOhorYVN` |
| ICON-DHASH | `14cbc4d2d2c4cb14` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_089_f6444110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f644411026620ae3f8d2c7cca2067d594b6ced57429a2291f90bac663d06d40c"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:08:00"
  condition:
    hash.sha256(0, filesize) == "f644411026620ae3f8d2c7cca2067d594b6ced57429a2291f90bac663d06d40c"
}
```

### Sample 90: `184d0b251392babb`

| Field | Value |
|---|---|
| SHA-256 | `184d0b251392babb683b1b7e48ed5a64714655504244f00a02d9cc7c7d483ce1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-04 19:00:37` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, signed, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7c258e259322672128afb6d8d628b04` |
| SHA-1 | `bed1fd71b919a610ab9ba1e17b0e022cf48150d1` |
| SHA-256 | `184d0b251392babb683b1b7e48ed5a64714655504244f00a02d9cc7c7d483ce1` |
| SHA3-384 | `16d7b246470e4f54e7f44caed0118f784e18dc9dd83fc3fa530283a5a6d7ca0b28395ff99d35203451d819dcaa69ba3f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T140069D07BDE108EAC0AE923289B7569A7B74BC490F3227D72E50B6782F767C05C35B54` |
| SSDEEP | `49152:bbUZ2GxH9nhcZBSI4c38GaY/LWA02lTTUA4EKAfZLVzrVYMeyKVX/FCq2HK4HYDR:blPDaR6X1hLFVYMiFCq6BMuYRr` |
| ICON-DHASH | `aae8e8e8e8e8e8aa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_184d0b25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "184d0b251392babb683b1b7e48ed5a64714655504244f00a02d9cc7c7d483ce1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:00:37"
  condition:
    hash.sha256(0, filesize) == "184d0b251392babb683b1b7e48ed5a64714655504244f00a02d9cc7c7d483ce1"
}
```

### Sample 91: `94dc994f1fe99fd4`

| Field | Value |
|---|---|
| SHA-256 | `94dc994f1fe99fd402f2aed5a681a0d46ddc8417519d72f8a72071261368bb4f` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-07-04 18:55:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32dc37835fad591c9f00e8d963744739` |
| SHA-1 | `c787d6d91e641d9536514a932e6bfa58d83b2099` |
| SHA-256 | `94dc994f1fe99fd402f2aed5a681a0d46ddc8417519d72f8a72071261368bb4f` |
| SHA3-384 | `00b644c9bc25c055b7b4b10b758e7b030029c5697951f5c862fd57cf2acf63c75f4c13e6b647d322d6ee4aab47ef2473` |
| TLSH | `T1FD937CC0F683C4F6E84305B1507BE7379B32F1B9101AFA43D3699A72DC91951EA1AB9C` |
| TELFHASH | `t10751b1fa6dba08ecfbd0a804c75e5bd33669ca7b153025b0406398b532f79954475c3a` |
| SSDEEP | `1536:W/QCZaxGdvts3i5JPholIxPu++ALtgUIKqI4FrS4LSz:WYCZa8dvm3oJPhAIxP5htSKfUmDz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_94dc994f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94dc994f1fe99fd402f2aed5a681a0d46ddc8417519d72f8a72071261368bb4f"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-07-04 18:55:01"
  condition:
    hash.sha256(0, filesize) == "94dc994f1fe99fd402f2aed5a681a0d46ddc8417519d72f8a72071261368bb4f"
}
```

### Sample 92: `b9c89db879a1b922`

| Field | Value |
|---|---|
| SHA-256 | `b9c89db879a1b9223a6e5de8707bf5fb42e1e9118e28cb80360673997f0f80be` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-04 18:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4834e2a0c04942304cd22a3bd74b6fd` |
| SHA-1 | `55ff8bf9ee68fa22f05f3dfc4814230b824a33e5` |
| SHA-256 | `b9c89db879a1b9223a6e5de8707bf5fb42e1e9118e28cb80360673997f0f80be` |
| SHA3-384 | `401c55e3f692a7419409a52b3f268ef8d6986dc65a256d61ea251c805e89dc6ac949126f9b2be2d5c5adbcecaa34f3bf` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T16EE63308B2F011FBD8B7113CBCE042B5D59578B50732C69F87A4AAA5BE673D18D3E212` |
| SSDEEP | `393216:s+8YeZOgZWuW0aEUtsh1fCWrYNxXMCHWUjX/cuI3/PGTAI:s+cggMP0dU8fHrYNxXMb8XUH/O7` |
| ICON-DHASH | `71f0d4d8e8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_b9c89db8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c89db879a1b9223a6e5de8707bf5fb42e1e9118e28cb80360673997f0f80be"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 18:52:10"
  condition:
    hash.sha256(0, filesize) == "b9c89db879a1b9223a6e5de8707bf5fb42e1e9118e28cb80360673997f0f80be"
}
```

### Sample 93: `1c7dc921cf45fb25`

| Field | Value |
|---|---|
| SHA-256 | `1c7dc921cf45fb255a9e7a0e0aec6ea30bfc5f2a3fe110c72ee00de7817f5913` |
| Family label | `unknown` |
| File name | `o.xml` |
| File type | `unknown` |
| First seen | `2026-07-04 18:50:00` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f706766dfec19de9a341724554e0eaf` |
| SHA-256 | `1c7dc921cf45fb255a9e7a0e0aec6ea30bfc5f2a3fe110c72ee00de7817f5913` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_1c7dc921
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c7dc921cf45fb255a9e7a0e0aec6ea30bfc5f2a3fe110c72ee00de7817f5913"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-07-04 18:50:00"
  condition:
    hash.sha256(0, filesize) == "1c7dc921cf45fb255a9e7a0e0aec6ea30bfc5f2a3fe110c72ee00de7817f5913"
}
```

### Sample 94: `b5bc53ee395db78c`

| Field | Value |
|---|---|
| SHA-256 | `b5bc53ee395db78c5922a5556ad50bc6fc6f9ab0524194fe5be8e1d4d9f3b859` |
| Family label | `Mirai` |
| File name | `i` |
| File type | `elf` |
| First seen | `2026-07-04 18:46:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31d7ab817a5259df5b90f8cf9b807ac4` |
| SHA-1 | `24958b46b9d8aeb062a6b6536e259c2a9810f4d0` |
| SHA-256 | `b5bc53ee395db78c5922a5556ad50bc6fc6f9ab0524194fe5be8e1d4d9f3b859` |
| SHA3-384 | `3394521dbf4041bfc29a0cf70ba0e850d916236d3f374d0b36045b2a6015d1b6b5373aed85700d0ef8946ba50fbf409a` |
| TLSH | `T11B53F686BC82865689D423BFB97D81CE331373B8D2DF7102CD155F18B6CA94F0E6A952` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4ifP:T2s/ITo7WCkybotgsJ913DhrbW4UP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_b5bc53ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5bc53ee395db78c5922a5556ad50bc6fc6f9ab0524194fe5be8e1d4d9f3b859"
    family = "Mirai"
    file_name = "i"
    file_type = "elf"
    first_seen = "2026-07-04 18:46:03"
  condition:
    hash.sha256(0, filesize) == "b5bc53ee395db78c5922a5556ad50bc6fc6f9ab0524194fe5be8e1d4d9f3b859"
}
```

### Sample 95: `11897f1af9fd7814`

| Field | Value |
|---|---|
| SHA-256 | `11897f1af9fd7814c1c8e03148cafc4a18ba4978ddaa9c31f64ae5a6fff92635` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-07-04 18:44:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc4c7baf666099d98f5af426d815f998` |
| SHA-1 | `bd69ff29c59f3b7476a1dcdc1bc38d6e0ae4485c` |
| SHA-256 | `11897f1af9fd7814c1c8e03148cafc4a18ba4978ddaa9c31f64ae5a6fff92635` |
| SHA3-384 | `e8acbf03dea7b6e31a4d68b6ad8c3ee3bbd7a4268ec4e09e0c6beac224384fb5f1aa148f256ce649b99395baf235233d` |
| TLSH | `T1DAD33A06730C0A47D2632EB03A3F67D193AFDAC121E4FA41355F9B8A95B1E325586ECD` |
| SSDEEP | `1536:xnlQp4Goyx6BxIBUiuxfytKte4c/tzabw0M7lrkJvAhhDrp+p3jqkXD7wO:ouHKUiuxhtyuwh7l7hG0O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_11897f1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11897f1af9fd7814c1c8e03148cafc4a18ba4978ddaa9c31f64ae5a6fff92635"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-07-04 18:44:59"
  condition:
    hash.sha256(0, filesize) == "11897f1af9fd7814c1c8e03148cafc4a18ba4978ddaa9c31f64ae5a6fff92635"
}
```

### Sample 96: `78f05b9d029f0226`

| Field | Value |
|---|---|
| SHA-256 | `78f05b9d029f0226c68730c45c2d3ed59a617c4d2115f3669eb75869f5d0099b` |
| Family label | `SalatStealer` |
| File name | `RKNByPass.exe` |
| File type | `exe` |
| First seen | `2026-07-04 18:34:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53d66227529f0067cdbf4abfdbbb8d67` |
| SHA-1 | `0dc0cb45ab74c0a11e2b0a351ffb46287775a563` |
| SHA-256 | `78f05b9d029f0226c68730c45c2d3ed59a617c4d2115f3669eb75869f5d0099b` |
| SHA3-384 | `6f321e201b07ebc03f7938841e0b439719bc38fc0dbea44648c35d9034bbe85a326e4a838fa07ef0e315d728ed16c463` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T183C66B11FADB95F1E903583101ABB37F23315D048B28DB9BEB547B2AF87B6A10D66305` |
| SSDEEP | `98304:7ZalwwiNclCzAmeNTk+7d3qg74SG2Z1rEU2:swUAAPq+7d6A/Sz` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_096_78f05b9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78f05b9d029f0226c68730c45c2d3ed59a617c4d2115f3669eb75869f5d0099b"
    family = "SalatStealer"
    file_name = "RKNByPass.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:34:12"
  condition:
    hash.sha256(0, filesize) == "78f05b9d029f0226c68730c45c2d3ed59a617c4d2115f3669eb75869f5d0099b"
}
```

### Sample 97: `fd315aaf3b4e34f2`

| Field | Value |
|---|---|
| SHA-256 | `fd315aaf3b4e34f2b210a39d04a08b60e8b0484241c0a953ef7ec740bdf405f8` |
| Family label | `SalatStealer` |
| File name | `RKNByPass.exe` |
| File type | `exe` |
| First seen | `2026-07-04 18:31:28` |
| Reporter | `Alex_sev` |
| Tags | `exe, infostealer, salat, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01810d0da014221225e410b9888780de` |
| SHA-1 | `c96539cb92c1f3f8e17ba8ac494aa8a95eea0412` |
| SHA-256 | `fd315aaf3b4e34f2b210a39d04a08b60e8b0484241c0a953ef7ec740bdf405f8` |
| SHA3-384 | `fa37b776870fbcd0686cb6c4aee0ff4d55385af819a463d853a9326a2468a86705ac96619713433158dca736dd494043` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T152F53386D197D87BE19C2EF0B83964A17299DE0BCC754ECB893044C646AF406DFE6F21` |
| SSDEEP | `98304:FcausFpgqhuw19kxHzbnia/CqmHz7INkmIQP53KlMc2yh0:eausXhST7qqmHz7I1IQP53Uhh0` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_097_fd315aaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd315aaf3b4e34f2b210a39d04a08b60e8b0484241c0a953ef7ec740bdf405f8"
    family = "SalatStealer"
    file_name = "RKNByPass.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:31:28"
  condition:
    hash.sha256(0, filesize) == "fd315aaf3b4e34f2b210a39d04a08b60e8b0484241c0a953ef7ec740bdf405f8"
}
```

### Sample 98: `f44aa3193bdb9b79`

| Field | Value |
|---|---|
| SHA-256 | `f44aa3193bdb9b79598542f1421d2da02e92f74565f277728f847b7933974e35` |
| Family label | `unknown` |
| File name | `zapret v1.9.9b.exe` |
| File type | `exe` |
| First seen | `2026-07-04 18:28:10` |
| Reporter | `Alex_sev` |
| Tags | `Agent, exe, Generic, Loader, Yogi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf058ed0b039b5c801e4f5da188bccd0` |
| SHA-1 | `fa0c141338eb27408b23df24d3496fd0cf5ba2e6` |
| SHA-256 | `f44aa3193bdb9b79598542f1421d2da02e92f74565f277728f847b7933974e35` |
| SHA3-384 | `bbb10b3490966ddfb92eb60f74afc68ee109c0bfc84feed53a121570f4a92c7c111efbf4b8737f3efc1049f1f8519657` |
| IMPHASH | `d54f4ce7166adf987d04345af91ff939` |
| TLSH | `T14EB63302425B60DAC2D5A973EE3FE9E09735B329A61E32C9452D62373F462D26F3C153` |
| SSDEEP | `196608:85GltmLZgJWlxy/sQXLIhpEQfRWee63IZKD9h7vs38KjdaxqeDB9I:vvYgUls/sQMk2RWePE05s3TaFDBm` |
| ICON-DHASH | `b070b088d8c8d8a4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_f44aa319
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f44aa3193bdb9b79598542f1421d2da02e92f74565f277728f847b7933974e35"
    family = "unknown"
    file_name = "zapret v1.9.9b.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:28:10"
  condition:
    hash.sha256(0, filesize) == "f44aa3193bdb9b79598542f1421d2da02e92f74565f277728f847b7933974e35"
}
```

### Sample 99: `0e2ad9912cc24574`

| Field | Value |
|---|---|
| SHA-256 | `0e2ad9912cc24574917d46e8d99c75348987cc8272dafea87c35df142ee121c1` |
| Family label | `unknown` |
| File name | `Zapret.exe` |
| File type | `exe` |
| First seen | `2026-07-04 18:22:45` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ecb6d38c9bb3af5fddaed18347affba` |
| SHA-1 | `93aa0a6674147661c84687284b325e77a5d2f4c3` |
| SHA-256 | `0e2ad9912cc24574917d46e8d99c75348987cc8272dafea87c35df142ee121c1` |
| SHA3-384 | `2d59c0b5aac0651d4abc9fe73c1ccc5e0ac1dd855bf5eca5643e1913f7754123d45a3b80cd6f013e54a653167bbefa77` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T168C66B11FADB95F1E903583101ABB37F23315D048B28DB9BEB547B2AF87B6A10D66305` |
| SSDEEP | `98304:dY/LGM+lgLCYj8bzPliE9bQg4SG2Z1rEPi:UGw5j45iE9Mg/S6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_0e2ad991
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e2ad9912cc24574917d46e8d99c75348987cc8272dafea87c35df142ee121c1"
    family = "unknown"
    file_name = "Zapret.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:22:45"
  condition:
    hash.sha256(0, filesize) == "0e2ad9912cc24574917d46e8d99c75348987cc8272dafea87c35df142ee121c1"
}
```

### Sample 100: `8bc30eb67e864fc8`

| Field | Value |
|---|---|
| SHA-256 | `8bc30eb67e864fc80ad80cd3fc52a4c74613af1c60ba1975b788a26cc277d8a7` |
| Family label | `SalatStealer` |
| File name | `Zapret.exe` |
| File type | `exe` |
| First seen | `2026-07-04 18:19:43` |
| Reporter | `Alex_sev` |
| Tags | `exe, infostealer, salat, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b16b61877a7d7c2a9f99529ea32ddd44` |
| SHA-1 | `3927d0e0a3804afe41215c0f2237e408c2c377e4` |
| SHA-256 | `8bc30eb67e864fc80ad80cd3fc52a4c74613af1c60ba1975b788a26cc277d8a7` |
| SHA3-384 | `1cdb88f37f8ce0ed6fc5dc285cf94cf636ae0e024f7075d9cd24b2d62520fc19acb47b1bfc9ef24ffae88c3fcb8e8fa7` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T156F5330ACEED3F22CFA7A2766E25D56862D880CF19454B9251582311B2D8D3DFF31BE4` |
| SSDEEP | `98304:IosBuIpH7zSoT11WP7MPhRA8WwFgPIDbCoO2:6PbzN54eRA8xFgPIfCoV` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_100_8bc30eb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bc30eb67e864fc80ad80cd3fc52a4c74613af1c60ba1975b788a26cc277d8a7"
    family = "SalatStealer"
    file_name = "Zapret.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:19:43"
  condition:
    hash.sha256(0, filesize) == "8bc30eb67e864fc80ad80cd3fc52a4c74613af1c60ba1975b788a26cc277d8a7"
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
 * Generated: 2026-07-05T04:34:26.137510+00:00
 */

rule MalwareBazaar_NanoCore_001_551aa018
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "551aa018350fcf2b435b4d361dd4f117349a5136851f84ac10c02da1526e4e67"
    family = "NanoCore"
    file_name = "sales-tracker.io.exe"
    file_type = "exe"
    first_seen = "2026-07-05 04:05:05"
  condition:
    hash.sha256(0, filesize) == "551aa018350fcf2b435b4d361dd4f117349a5136851f84ac10c02da1526e4e67"
}

rule MalwareBazaar_unknown_002_d9f15a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9f15a43821328bf482e2945ff9da40fa05f382777819d8e9fa3aaae8704862d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 03:51:59"
  condition:
    hash.sha256(0, filesize) == "d9f15a43821328bf482e2945ff9da40fa05f382777819d8e9fa3aaae8704862d"
}

rule MalwareBazaar_unknown_003_f193b47f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f193b47f2739aaa35c0ecec5d2731dc7d343c200340015e4a2bff663c3041512"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-05 03:12:53"
  condition:
    hash.sha256(0, filesize) == "f193b47f2739aaa35c0ecec5d2731dc7d343c200340015e4a2bff663c3041512"
}

rule MalwareBazaar_unknown_004_11936fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11936fb09c6770b658ce5335e704bdba76722e1282eb53630beca2e007bb0850"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-05 02:55:13"
  condition:
    hash.sha256(0, filesize) == "11936fb09c6770b658ce5335e704bdba76722e1282eb53630beca2e007bb0850"
}

rule MalwareBazaar_unknown_005_c016fd71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c016fd7194859f518e61b204e9df51a683959a28399bd88ec0f7b7f30858f133"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-05 02:53:21"
  condition:
    hash.sha256(0, filesize) == "c016fd7194859f518e61b204e9df51a683959a28399bd88ec0f7b7f30858f133"
}

rule MalwareBazaar_unknown_006_422c55e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "422c55e0219b09d0262782b25420c601304f5d1b46a325f2b4859ef77244ff42"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 02:52:11"
  condition:
    hash.sha256(0, filesize) == "422c55e0219b09d0262782b25420c601304f5d1b46a325f2b4859ef77244ff42"
}

rule MalwareBazaar_unknown_007_720035e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "720035e8c6cfb6cdc35041b7f6fd3883d2dc4821aad56e39f3ca0f2947e2dc8e"
    family = "unknown"
    file_name = "recuva_professional__technician_(2026)_full_español_[mega].7z"
    file_type = "7z"
    first_seen = "2026-07-05 02:52:10"
  condition:
    hash.sha256(0, filesize) == "720035e8c6cfb6cdc35041b7f6fd3883d2dc4821aad56e39f3ca0f2947e2dc8e"
}

rule MalwareBazaar_unknown_008_134385f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "134385f37bc37813bd7b811a628b700d0791c31c2ea0f2cf037d2463e02976f3"
    family = "unknown"
    file_name = "cx-programmer 9.1 free download full.7z"
    file_type = "7z"
    first_seen = "2026-07-05 02:50:57"
  condition:
    hash.sha256(0, filesize) == "134385f37bc37813bd7b811a628b700d0791c31c2ea0f2cf037d2463e02976f3"
}

rule MalwareBazaar_unknown_009_6cb7fd54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cb7fd54f66b99cc623bfc38f8aed37b87e36a59882ea770ce30c825bbbe754b"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-05 02:49:26"
  condition:
    hash.sha256(0, filesize) == "6cb7fd54f66b99cc623bfc38f8aed37b87e36a59882ea770ce30c825bbbe754b"
}

rule MalwareBazaar_Gafgyt_010_befaa63b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec"
    family = "Gafgyt"
    file_name = "befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec"
    file_type = "elf"
    first_seen = "2026-07-05 02:09:45"
  condition:
    hash.sha256(0, filesize) == "befaa63b031753c4e811f7f24b68c6107c8a6b1720e027aee673efde3c9f13ec"
}

rule MalwareBazaar_Mirai_011_8e8580be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e8580be4c0807a0141da1e7cddf1763fea514408897d1bf2f7e298198525437"
    family = "Mirai"
    file_name = "Mozi.m"
    file_type = "elf"
    first_seen = "2026-07-05 02:04:13"
  condition:
    hash.sha256(0, filesize) == "8e8580be4c0807a0141da1e7cddf1763fea514408897d1bf2f7e298198525437"
}

rule MalwareBazaar_unknown_012_ccbf818a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ccbf818a36523c19051d066f8e5edad655a478516afc916cd915aacca80dbcd2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 01:52:10"
  condition:
    hash.sha256(0, filesize) == "ccbf818a36523c19051d066f8e5edad655a478516afc916cd915aacca80dbcd2"
}

rule MalwareBazaar_Mirai_013_5c8dcfaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8dcfaf72d826e5e944b2b3c5a5f19c52f5d254e4f7de5a0a385354e778e955"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-05 01:28:13"
  condition:
    hash.sha256(0, filesize) == "5c8dcfaf72d826e5e944b2b3c5a5f19c52f5d254e4f7de5a0a385354e778e955"
}

rule MalwareBazaar_unknown_014_848b4600
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "848b460096ecaeaf40ed9399c67650a0914967cd8ba35a3e59fbd372ddc2a7ee"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-05 01:28:12"
  condition:
    hash.sha256(0, filesize) == "848b460096ecaeaf40ed9399c67650a0914967cd8ba35a3e59fbd372ddc2a7ee"
}

rule MalwareBazaar_Mirai_015_d1bc8967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1bc8967a413300d080ab7720d597511c1885912f35f6b11e4462dc12eb314ef"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-05 01:15:08"
  condition:
    hash.sha256(0, filesize) == "d1bc8967a413300d080ab7720d597511c1885912f35f6b11e4462dc12eb314ef"
}

rule MalwareBazaar_Mirai_016_dc3f3a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc3f3a497e0c23bb74713d90a4a4da901c4ad3f2062af803af03179c78726df2"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-05 01:11:05"
  condition:
    hash.sha256(0, filesize) == "dc3f3a497e0c23bb74713d90a4a4da901c4ad3f2062af803af03179c78726df2"
}

rule MalwareBazaar_unknown_017_46880af4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46880af4b7bbb74def06569aecda2d96702de4b8b7723b05af927674928ce327"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-05 00:52:25"
  condition:
    hash.sha256(0, filesize) == "46880af4b7bbb74def06569aecda2d96702de4b8b7723b05af927674928ce327"
}

rule MalwareBazaar_Mirai_018_b74f6ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b74f6ba6f0a2fd9969cea27d371567823fd7b9a6ffe14aa5347adc63d70fc1e3"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-05 00:51:26"
  condition:
    hash.sha256(0, filesize) == "b74f6ba6f0a2fd9969cea27d371567823fd7b9a6ffe14aa5347adc63d70fc1e3"
}

rule MalwareBazaar_Mirai_019_12db9c40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12db9c40d7315b02d5231d11e04854b0c1ea3574219a97a32e6cd6a6cf8e8f60"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-05 00:49:23"
  condition:
    hash.sha256(0, filesize) == "12db9c40d7315b02d5231d11e04854b0c1ea3574219a97a32e6cd6a6cf8e8f60"
}

rule MalwareBazaar_Mirai_020_f37cc14d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f37cc14d7aba3e5acb68885336ccf3882c61d4220c50618d0344aa874b4f0fb6"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-05 00:46:15"
  condition:
    hash.sha256(0, filesize) == "f37cc14d7aba3e5acb68885336ccf3882c61d4220c50618d0344aa874b4f0fb6"
}

rule MalwareBazaar_Mirai_021_0f2bd4b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2bd4b70f03a3f5eba2121af97e5afb3c5969e4887c960c00d4c5b02c5c785f"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-05 00:45:11"
  condition:
    hash.sha256(0, filesize) == "0f2bd4b70f03a3f5eba2121af97e5afb3c5969e4887c960c00d4c5b02c5c785f"
}

rule MalwareBazaar_unknown_022_028c7bb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "028c7bb4023c66785328a078fb9ba3787418c45aace2b31395b9e06443224f71"
    family = "unknown"
    file_name = "chrome_elf.dll"
    file_type = "dll"
    first_seen = "2026-07-05 00:21:34"
  condition:
    hash.sha256(0, filesize) == "028c7bb4023c66785328a078fb9ba3787418c45aace2b31395b9e06443224f71"
}

rule MalwareBazaar_Stealc_023_716608d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-05 00:13:14"
  condition:
    hash.sha256(0, filesize) == "716608d7e9a26e980f916e73792abcb86bbb21fb949436b7f359afcaf730b078"
}

rule MalwareBazaar_Vidar_024_f23e6b70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f23e6b705868c3d3a6615be240bfa23620b0b873fd17b12a9481f7580a18ec75"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.45211965"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:38"
  condition:
    hash.sha256(0, filesize) == "f23e6b705868c3d3a6615be240bfa23620b0b873fd17b12a9481f7580a18ec75"
}

rule MalwareBazaar_Vidar_025_9462805f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9462805f80c946c49bf44a3d567a682b666d1d0bd74e3819050339e6f3e93451"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.11482139"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:36"
  condition:
    hash.sha256(0, filesize) == "9462805f80c946c49bf44a3d567a682b666d1d0bd74e3819050339e6f3e93451"
}

rule MalwareBazaar_Vidar_026_8e3cf3dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e3cf3dc6e5d8fdfbcc8575e9e97003f7f919c6ba2ea5889ec3ac658ceacc8a9"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61852.17703.28157"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:34"
  condition:
    hash.sha256(0, filesize) == "8e3cf3dc6e5d8fdfbcc8575e9e97003f7f919c6ba2ea5889ec3ac658ceacc8a9"
}

rule MalwareBazaar_Vidar_027_e74cf40d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e74cf40d9df390976e11bad98f81df248c14b6e5a45c889b05095fb66117a83b"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.79583238"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:32"
  condition:
    hash.sha256(0, filesize) == "e74cf40d9df390976e11bad98f81df248c14b6e5a45c889b05095fb66117a83b"
}

rule MalwareBazaar_unknown_028_d9d6fc30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9d6fc3085dd822f258601164ecb21f318822a63ca0360aead9201bcee49ed04"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.PWS.StealerNET.203.19366.4374"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:30"
  condition:
    hash.sha256(0, filesize) == "d9d6fc3085dd822f258601164ecb21f318822a63ca0360aead9201bcee49ed04"
}

rule MalwareBazaar_Vidar_029_360e3c6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "360e3c6d428da649c77a426d3f0379a3a1eced35f0d7a68f5a925d4b300ccaf7"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.57237154"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:28"
  condition:
    hash.sha256(0, filesize) == "360e3c6d428da649c77a426d3f0379a3a1eced35f0d7a68f5a925d4b300ccaf7"
}

rule MalwareBazaar_Vidar_030_31da1811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31da18115d031c335b2b4f2b2d3a1277ace95a139e7293e469ee2f55d084d3a3"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.38397872"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:26"
  condition:
    hash.sha256(0, filesize) == "31da18115d031c335b2b4f2b2d3a1277ace95a139e7293e469ee2f55d084d3a3"
}

rule MalwareBazaar_Vidar_031_eded86eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eded86eb5c664d712b1393001d997338d122e53b15885adc4c89d2421a412f64"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.87659349"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:23"
  condition:
    hash.sha256(0, filesize) == "eded86eb5c664d712b1393001d997338d122e53b15885adc4c89d2421a412f64"
}

rule MalwareBazaar_Vidar_032_16d67fa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16d67fa1f9e77c465e62a6a37f0c5bd54b8385215a5f40b1e5644dd3d84e0dad"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.65488933"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:22"
  condition:
    hash.sha256(0, filesize) == "16d67fa1f9e77c465e62a6a37f0c5bd54b8385215a5f40b1e5644dd3d84e0dad"
}

rule MalwareBazaar_Vidar_033_5525784b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5525784bfcc0c3340da0289ab8a5aed5565e73dc7246366b246ff000f7757ac5"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.49523153"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:20"
  condition:
    hash.sha256(0, filesize) == "5525784bfcc0c3340da0289ab8a5aed5565e73dc7246366b246ff000f7757ac5"
}

rule MalwareBazaar_Vidar_034_08510ddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08510ddd7019a2fb09d4893c35ddbb3356cd8ce3fe6e43fa68f9f13e95287d46"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.25595179"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:18"
  condition:
    hash.sha256(0, filesize) == "08510ddd7019a2fb09d4893c35ddbb3356cd8ce3fe6e43fa68f9f13e95287d46"
}

rule MalwareBazaar_Vidar_035_33b317b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33b317b7ffc3ea442add1da7aa7a7c444b670c62943e684c2ec2c5d6fa97904c"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.49954333"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:16"
  condition:
    hash.sha256(0, filesize) == "33b317b7ffc3ea442add1da7aa7a7c444b670c62943e684c2ec2c5d6fa97904c"
}

rule MalwareBazaar_Vidar_036_62f16a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62f16a144816655addc35fa23adb766203296c38b75452e6d30aa4a3a13df6b5"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62131.22581.20107"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:13"
  condition:
    hash.sha256(0, filesize) == "62f16a144816655addc35fa23adb766203296c38b75452e6d30aa4a3a13df6b5"
}

rule MalwareBazaar_Vidar_037_b19e9f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19e9f8b8b5cefd798ffd7a3b428aa842798d697a049f32cf80c720ccb5602f0"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61915.1296.13418"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:10"
  condition:
    hash.sha256(0, filesize) == "b19e9f8b8b5cefd798ffd7a3b428aa842798d697a049f32cf80c720ccb5602f0"
}

rule MalwareBazaar_Vidar_038_ec597589
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec59758993501d25047672e4c46d33d7489012bf3936832af18896fb1bbef109"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62620.2012.11636"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:08"
  condition:
    hash.sha256(0, filesize) == "ec59758993501d25047672e4c46d33d7489012bf3936832af18896fb1bbef109"
}

rule MalwareBazaar_Vidar_039_9cd9c0a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cd9c0a79450290b1ac0ea3235df6cd68332cc5a426991fa1d53eb7f19ec5a09"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61904.18316.7310"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:05"
  condition:
    hash.sha256(0, filesize) == "9cd9c0a79450290b1ac0ea3235df6cd68332cc5a426991fa1d53eb7f19ec5a09"
}

rule MalwareBazaar_Vidar_040_c2cfd3d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2cfd3d5cc6db52356661d50b0374c494c96af73cb0fea33babb9616d4453098"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.88959866"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:01"
  condition:
    hash.sha256(0, filesize) == "c2cfd3d5cc6db52356661d50b0374c494c96af73cb0fea33babb9616d4453098"
}

rule MalwareBazaar_Vidar_041_337463ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "337463ea7d1ef14be117bf0461be4dd342794f5919c820173651b9d7a7269ae3"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61853.5418.11599"
    file_type = "exe"
    first_seen = "2026-07-05 00:00:00"
  condition:
    hash.sha256(0, filesize) == "337463ea7d1ef14be117bf0461be4dd342794f5919c820173651b9d7a7269ae3"
}

rule MalwareBazaar_Vidar_042_b6fba18b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6fba18b6641eac47499735a0c872814b20bdc65ed491c04769d0e556d2ec40b"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61937.4405.20783"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:58"
  condition:
    hash.sha256(0, filesize) == "b6fba18b6641eac47499735a0c872814b20bdc65ed491c04769d0e556d2ec40b"
}

rule MalwareBazaar_Vidar_043_0f1bcecd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f1bcecd61092de0735dba542259b31c6566a1df62069a0a3287a0a12dcfa4f2"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62060.9877.21148"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:57"
  condition:
    hash.sha256(0, filesize) == "0f1bcecd61092de0735dba542259b31c6566a1df62069a0a3287a0a12dcfa4f2"
}

rule MalwareBazaar_Vidar_044_3d776e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d776e8445933dee504ffe673a96480d5313c1e71979faebb74c3c9734b96b31"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.44919756"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:56"
  condition:
    hash.sha256(0, filesize) == "3d776e8445933dee504ffe673a96480d5313c1e71979faebb74c3c9734b96b31"
}

rule MalwareBazaar_Vidar_045_08be0ddd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08be0ddd6e5d000404d4c5f27b7a1acf98c12ac4e4e715ae750f4d80f8e830e5"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62619.15404.14512"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:54"
  condition:
    hash.sha256(0, filesize) == "08be0ddd6e5d000404d4c5f27b7a1acf98c12ac4e4e715ae750f4d80f8e830e5"
}

rule MalwareBazaar_Vidar_046_ebdd2ac5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebdd2ac5c447807ff3218ae4fe747a681dc1097b64025452acbf7faa1fb17ca4"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.65646623"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:53"
  condition:
    hash.sha256(0, filesize) == "ebdd2ac5c447807ff3218ae4fe747a681dc1097b64025452acbf7faa1fb17ca4"
}

rule MalwareBazaar_Vidar_047_4521f532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4521f532bf22c3155a95a71c4797253680dc60618c74c18522506a603ef43a03"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62148.2993.29667"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:51"
  condition:
    hash.sha256(0, filesize) == "4521f532bf22c3155a95a71c4797253680dc60618c74c18522506a603ef43a03"
}

rule MalwareBazaar_Vidar_048_9eb3e292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb3e292b091c691943b70fc0e9d6d2c5e5c55727518e40018ba72b27d71e0a3"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61959.9199.15630"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:50"
  condition:
    hash.sha256(0, filesize) == "9eb3e292b091c691943b70fc0e9d6d2c5e5c55727518e40018ba72b27d71e0a3"
}

rule MalwareBazaar_Vidar_049_c11aeec4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c11aeec42a7f3c4e7895d37cf403b6900793226444dfc83ad2b85aab152e457c"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.61860.23656.11656"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:48"
  condition:
    hash.sha256(0, filesize) == "c11aeec42a7f3c4e7895d37cf403b6900793226444dfc83ad2b85aab152e457c"
}

rule MalwareBazaar_Vidar_050_0c4ad7ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c4ad7ea7fd1d24186efc73657dd5feed3f7c7243089e4d9eae0b1f63abeb69d"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.99646532"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:47"
  condition:
    hash.sha256(0, filesize) == "0c4ad7ea7fd1d24186efc73657dd5feed3f7c7243089e4d9eae0b1f63abeb69d"
}

rule MalwareBazaar_Vidar_051_741eea6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "741eea6f598af241e1337ad567b7c6d52e601309a381f934ab6ce245c7906469"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.78866488"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:46"
  condition:
    hash.sha256(0, filesize) == "741eea6f598af241e1337ad567b7c6d52e601309a381f934ab6ce245c7906469"
}

rule MalwareBazaar_Vidar_052_fcd8643d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fcd8643dff51723d1250496b2a8e10d69fb6e2eb4c01c30cbad32bbf54c9ce51"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.61776561"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:44"
  condition:
    hash.sha256(0, filesize) == "fcd8643dff51723d1250496b2a8e10d69fb6e2eb4c01c30cbad32bbf54c9ce51"
}

rule MalwareBazaar_Vidar_053_5bcd63ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bcd63edfe85569733cd75e76cb89fa3e9b3628694fa66e23e953a6724cb3ed9"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.43331428"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:43"
  condition:
    hash.sha256(0, filesize) == "5bcd63edfe85569733cd75e76cb89fa3e9b3628694fa66e23e953a6724cb3ed9"
}

rule MalwareBazaar_Vidar_054_bacb8e6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bacb8e6d037adfe4e4643c6d8b64d47c0b7eb5a2716733871e6efde97130bd62"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.48744784"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:41"
  condition:
    hash.sha256(0, filesize) == "bacb8e6d037adfe4e4643c6d8b64d47c0b7eb5a2716733871e6efde97130bd62"
}

rule MalwareBazaar_Vidar_055_e4d6f887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4d6f88789bab6b4646c872227ee03a81bed1532bb1b9953ef98b8535678886b"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.52541319"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:40"
  condition:
    hash.sha256(0, filesize) == "e4d6f88789bab6b4646c872227ee03a81bed1532bb1b9953ef98b8535678886b"
}

rule MalwareBazaar_Vidar_056_316ac119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "316ac119eef39b921d33f69cde46351f2caafc7cae17fe4f2dcbd6a38284da0a"
    family = "Vidar"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.62135.7466.13646"
    file_type = "exe"
    first_seen = "2026-07-04 23:59:39"
  condition:
    hash.sha256(0, filesize) == "316ac119eef39b921d33f69cde46351f2caafc7cae17fe4f2dcbd6a38284da0a"
}

rule MalwareBazaar_unknown_057_b39f87a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b39f87a3671b4b2be40c8431c8901fb4c57d58506a8d73356a40f2c94b45007f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 23:52:06"
  condition:
    hash.sha256(0, filesize) == "b39f87a3671b4b2be40c8431c8901fb4c57d58506a8d73356a40f2c94b45007f"
}

rule MalwareBazaar_unknown_058_3aa36f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3aa36f96be62612268c0359e169fe6a8dac0cd2e628b3638e22a8173d7f8e789"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 23:47:52"
  condition:
    hash.sha256(0, filesize) == "3aa36f96be62612268c0359e169fe6a8dac0cd2e628b3638e22a8173d7f8e789"
}

rule MalwareBazaar_unknown_059_317e6d0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "317e6d0cde0de8664db8f5c1d6c316d61ca91ef64e59a37a522df1b7425acc0c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 23:04:59"
  condition:
    hash.sha256(0, filesize) == "317e6d0cde0de8664db8f5c1d6c316d61ca91ef64e59a37a522df1b7425acc0c"
}

rule MalwareBazaar_CoinMiner_060_58d5ed5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58d5ed5b67253c3644d233e721a8180ffd0b9267588c5605d98fbc049b446a01"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 23:04:02"
  condition:
    hash.sha256(0, filesize) == "58d5ed5b67253c3644d233e721a8180ffd0b9267588c5605d98fbc049b446a01"
}

rule MalwareBazaar_unknown_061_19005731
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1900573180c4f5395fcf45b79fdc1ee14fe2067dd3579970d670c9faffcbd22d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 22:52:25"
  condition:
    hash.sha256(0, filesize) == "1900573180c4f5395fcf45b79fdc1ee14fe2067dd3579970d670c9faffcbd22d"
}

rule MalwareBazaar_unknown_062_dcc3893f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcc3893f89bdc55dc2f56bfccd426a7652e37b5a4e8790de99afc47bec3ecef4"
    family = "unknown"
    file_name = "file"
    file_type = "msi"
    first_seen = "2026-07-04 22:51:49"
  condition:
    hash.sha256(0, filesize) == "dcc3893f89bdc55dc2f56bfccd426a7652e37b5a4e8790de99afc47bec3ecef4"
}

rule MalwareBazaar_unknown_063_698bc8bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "698bc8bcff6236341a6ad1d222e65c1b3771ca2a7042f3bd9cc5e1c40c4f392e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 22:47:50"
  condition:
    hash.sha256(0, filesize) == "698bc8bcff6236341a6ad1d222e65c1b3771ca2a7042f3bd9cc5e1c40c4f392e"
}

rule MalwareBazaar_unknown_064_7fd7a0a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fd7a0a3703782d6eee97a8bfbd82e77ab65ebb7c5af3407bfc21c4ec1dd2ac9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 22:46:28"
  condition:
    hash.sha256(0, filesize) == "7fd7a0a3703782d6eee97a8bfbd82e77ab65ebb7c5af3407bfc21c4ec1dd2ac9"
}

rule MalwareBazaar_unknown_065_7084792a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7084792a0c28fb37ec207c2b0a12dae8e6d43996e6b56cfe6f78970d72886121"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 22:38:10"
  condition:
    hash.sha256(0, filesize) == "7084792a0c28fb37ec207c2b0a12dae8e6d43996e6b56cfe6f78970d72886121"
}

rule MalwareBazaar_unknown_066_d7e33496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7e334967a876168a3437f68020fd181e7e2320ea2742fc3583d3015025b1f6b"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 21:52:25"
  condition:
    hash.sha256(0, filesize) == "d7e334967a876168a3437f68020fd181e7e2320ea2742fc3583d3015025b1f6b"
}

rule MalwareBazaar_Mirai_067_10424631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10424631b904e8498cb388966b92f850d9ddaed105188e73010533b66717829d"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-04 21:52:14"
  condition:
    hash.sha256(0, filesize) == "10424631b904e8498cb388966b92f850d9ddaed105188e73010533b66717829d"
}

rule MalwareBazaar_unknown_068_4b98c014
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b98c014977ad113c22aaf5f794c567c41f8b7e6b77a3cab964116a1d8b0a542"
    family = "unknown"
    file_name = "aintall.6638250006.msi"
    file_type = "msi"
    first_seen = "2026-07-04 21:32:34"
  condition:
    hash.sha256(0, filesize) == "4b98c014977ad113c22aaf5f794c567c41f8b7e6b77a3cab964116a1d8b0a542"
}

rule MalwareBazaar_unknown_069_0ea72062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ea72062143e9dd49fecfccfa6dd2594d3f6f831e5ff9b0b5aa91631afdd8724"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 20:53:50"
  condition:
    hash.sha256(0, filesize) == "0ea72062143e9dd49fecfccfa6dd2594d3f6f831e5ff9b0b5aa91631afdd8724"
}

rule MalwareBazaar_unknown_070_61c398e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61c398e690795f37e111ecf8050f371c7e31bc99b7eacd92c8cf356649c72c0d"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 20:52:05"
  condition:
    hash.sha256(0, filesize) == "61c398e690795f37e111ecf8050f371c7e31bc99b7eacd92c8cf356649c72c0d"
}

rule MalwareBazaar_unknown_071_36e70b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179"
    family = "unknown"
    file_name = "36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179"
    file_type = "elf"
    first_seen = "2026-07-04 20:43:15"
  condition:
    hash.sha256(0, filesize) == "36e70b9c5271aefeb3e4b4bc0eff8e81683f0ddfea4deed55dbc4cc0567ca179"
}

rule MalwareBazaar_MaskGramStealer_072_1412ef99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1412ef99e1bdbc0ef34df0b25f9455cdee4a40984c4caec099a8e9f08b21301a"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 20:35:40"
  condition:
    hash.sha256(0, filesize) == "1412ef99e1bdbc0ef34df0b25f9455cdee4a40984c4caec099a8e9f08b21301a"
}

rule MalwareBazaar_Mirai_073_444ae54b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "444ae54b9603d446ca3497bf3a8647f16a43786798631f88a1de1db48ebba09a"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-07-04 20:16:09"
  condition:
    hash.sha256(0, filesize) == "444ae54b9603d446ca3497bf3a8647f16a43786798631f88a1de1db48ebba09a"
}

rule MalwareBazaar_unknown_074_53faf93d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53faf93d2f0a5caccf8a99a797602c07aa0d19a26249feb705570cb2fbd9483f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-04 20:12:04"
  condition:
    hash.sha256(0, filesize) == "53faf93d2f0a5caccf8a99a797602c07aa0d19a26249feb705570cb2fbd9483f"
}

rule MalwareBazaar_Mirai_075_38809fbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38809fbd8e2c55db79df0c71984ec5be8988f27f423674e5f6f58f572c2118c3"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-07-04 19:53:01"
  condition:
    hash.sha256(0, filesize) == "38809fbd8e2c55db79df0c71984ec5be8988f27f423674e5f6f58f572c2118c3"
}

rule MalwareBazaar_unknown_076_c6048c44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6048c44535ab5fe1f7af9047eacf7225d88fc7b0c9324c1595a8b45d2d9588e"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 19:52:25"
  condition:
    hash.sha256(0, filesize) == "c6048c44535ab5fe1f7af9047eacf7225d88fc7b0c9324c1595a8b45d2d9588e"
}

rule MalwareBazaar_MaskGramStealer_077_adf43c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adf43c66f5394bc13aaaf3df3adaa6debeb69aa7bb126b665f1b2522607b8225"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:42:54"
  condition:
    hash.sha256(0, filesize) == "adf43c66f5394bc13aaaf3df3adaa6debeb69aa7bb126b665f1b2522607b8225"
}

rule MalwareBazaar_Mirai_078_0d4e9e01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4e9e01ec989627f77a09f744574f2bbd733f53b1736a2cc857c28bb4d820b3"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-07-04 19:41:59"
  condition:
    hash.sha256(0, filesize) == "0d4e9e01ec989627f77a09f744574f2bbd733f53b1736a2cc857c28bb4d820b3"
}

rule MalwareBazaar_RemusStealer_079_5139f936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5139f93689b446491172f9d157d563a91ba5e1da1403591eebbbb9d66d15549c"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:34:03"
  condition:
    hash.sha256(0, filesize) == "5139f93689b446491172f9d157d563a91ba5e1da1403591eebbbb9d66d15549c"
}

rule MalwareBazaar_unknown_080_aff2feb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e"
    family = "unknown"
    file_name = "aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e"
    file_type = "elf"
    first_seen = "2026-07-04 19:31:25"
  condition:
    hash.sha256(0, filesize) == "aff2feb0de45aa7c0e62cf110a637e10b6bb6acb93deaa6e33aaa6b920715b9e"
}

rule MalwareBazaar_Mirai_081_10346d6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10346d6fe66d5f29516bc9479de6c47392b0537a9c00389d1d3871243dcc0854"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-04 19:29:08"
  condition:
    hash.sha256(0, filesize) == "10346d6fe66d5f29516bc9479de6c47392b0537a9c00389d1d3871243dcc0854"
}

rule MalwareBazaar_Mirai_082_01d80b72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01d80b720d55ed1098ccabe709a582e1322ee2afd357981a8190531915af5ad4"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-07-04 19:27:11"
  condition:
    hash.sha256(0, filesize) == "01d80b720d55ed1098ccabe709a582e1322ee2afd357981a8190531915af5ad4"
}

rule MalwareBazaar_Mirai_083_1ef81db3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ef81db33375ce7fb1a6e22cc88f7711d7cce2845e4c5f8bb4e4a0aa11917e86"
    family = "Mirai"
    file_name = "dg.mips"
    file_type = "elf"
    first_seen = "2026-07-04 19:23:45"
  condition:
    hash.sha256(0, filesize) == "1ef81db33375ce7fb1a6e22cc88f7711d7cce2845e4c5f8bb4e4a0aa11917e86"
}

rule MalwareBazaar_Mirai_084_6ed2f848
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ed2f848536d84e6fd14eb4258f1f5ac95a1c3ad87dbc42c5b7fc5af812d06d7"
    family = "Mirai"
    file_name = "dg.mips"
    file_type = "elf"
    first_seen = "2026-07-04 19:22:02"
  condition:
    hash.sha256(0, filesize) == "6ed2f848536d84e6fd14eb4258f1f5ac95a1c3ad87dbc42c5b7fc5af812d06d7"
}

rule MalwareBazaar_Mirai_085_f504852c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f504852cbbb545c41c227f85171632c919503e44c1aa9d52253e750bdf1b995c"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-07-04 19:15:24"
  condition:
    hash.sha256(0, filesize) == "f504852cbbb545c41c227f85171632c919503e44c1aa9d52253e750bdf1b995c"
}

rule MalwareBazaar_unknown_086_ec6af7f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec6af7f9aeb339a3ca03f50be96d8b7063dec7f7f3bd53f9a3ab6fb81b89afba"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:13:14"
  condition:
    hash.sha256(0, filesize) == "ec6af7f9aeb339a3ca03f50be96d8b7063dec7f7f3bd53f9a3ab6fb81b89afba"
}

rule MalwareBazaar_Mirai_087_ae6e2ee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae6e2ee1f562285f3a357e26ec7543854a41e829b75257e6fd5d6ee6d7d10693"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-07-04 19:10:18"
  condition:
    hash.sha256(0, filesize) == "ae6e2ee1f562285f3a357e26ec7543854a41e829b75257e6fd5d6ee6d7d10693"
}

rule MalwareBazaar_Mirai_088_4af306ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4af306ca60a936809d8f33ecc20d9135fe130b8034fe2db174e91d54716614a7"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-07-04 19:08:15"
  condition:
    hash.sha256(0, filesize) == "4af306ca60a936809d8f33ecc20d9135fe130b8034fe2db174e91d54716614a7"
}

rule MalwareBazaar_MaskGramStealer_089_f6444110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f644411026620ae3f8d2c7cca2067d594b6ced57429a2291f90bac663d06d40c"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:08:00"
  condition:
    hash.sha256(0, filesize) == "f644411026620ae3f8d2c7cca2067d594b6ced57429a2291f90bac663d06d40c"
}

rule MalwareBazaar_unknown_090_184d0b25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "184d0b251392babb683b1b7e48ed5a64714655504244f00a02d9cc7c7d483ce1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-04 19:00:37"
  condition:
    hash.sha256(0, filesize) == "184d0b251392babb683b1b7e48ed5a64714655504244f00a02d9cc7c7d483ce1"
}

rule MalwareBazaar_Mirai_091_94dc994f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94dc994f1fe99fd402f2aed5a681a0d46ddc8417519d72f8a72071261368bb4f"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-07-04 18:55:01"
  condition:
    hash.sha256(0, filesize) == "94dc994f1fe99fd402f2aed5a681a0d46ddc8417519d72f8a72071261368bb4f"
}

rule MalwareBazaar_unknown_092_b9c89db8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c89db879a1b9223a6e5de8707bf5fb42e1e9118e28cb80360673997f0f80be"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-04 18:52:10"
  condition:
    hash.sha256(0, filesize) == "b9c89db879a1b9223a6e5de8707bf5fb42e1e9118e28cb80360673997f0f80be"
}

rule MalwareBazaar_unknown_093_1c7dc921
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c7dc921cf45fb255a9e7a0e0aec6ea30bfc5f2a3fe110c72ee00de7817f5913"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-07-04 18:50:00"
  condition:
    hash.sha256(0, filesize) == "1c7dc921cf45fb255a9e7a0e0aec6ea30bfc5f2a3fe110c72ee00de7817f5913"
}

rule MalwareBazaar_Mirai_094_b5bc53ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5bc53ee395db78c5922a5556ad50bc6fc6f9ab0524194fe5be8e1d4d9f3b859"
    family = "Mirai"
    file_name = "i"
    file_type = "elf"
    first_seen = "2026-07-04 18:46:03"
  condition:
    hash.sha256(0, filesize) == "b5bc53ee395db78c5922a5556ad50bc6fc6f9ab0524194fe5be8e1d4d9f3b859"
}

rule MalwareBazaar_Mirai_095_11897f1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11897f1af9fd7814c1c8e03148cafc4a18ba4978ddaa9c31f64ae5a6fff92635"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-07-04 18:44:59"
  condition:
    hash.sha256(0, filesize) == "11897f1af9fd7814c1c8e03148cafc4a18ba4978ddaa9c31f64ae5a6fff92635"
}

rule MalwareBazaar_SalatStealer_096_78f05b9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78f05b9d029f0226c68730c45c2d3ed59a617c4d2115f3669eb75869f5d0099b"
    family = "SalatStealer"
    file_name = "RKNByPass.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:34:12"
  condition:
    hash.sha256(0, filesize) == "78f05b9d029f0226c68730c45c2d3ed59a617c4d2115f3669eb75869f5d0099b"
}

rule MalwareBazaar_SalatStealer_097_fd315aaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd315aaf3b4e34f2b210a39d04a08b60e8b0484241c0a953ef7ec740bdf405f8"
    family = "SalatStealer"
    file_name = "RKNByPass.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:31:28"
  condition:
    hash.sha256(0, filesize) == "fd315aaf3b4e34f2b210a39d04a08b60e8b0484241c0a953ef7ec740bdf405f8"
}

rule MalwareBazaar_unknown_098_f44aa319
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f44aa3193bdb9b79598542f1421d2da02e92f74565f277728f847b7933974e35"
    family = "unknown"
    file_name = "zapret v1.9.9b.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:28:10"
  condition:
    hash.sha256(0, filesize) == "f44aa3193bdb9b79598542f1421d2da02e92f74565f277728f847b7933974e35"
}

rule MalwareBazaar_unknown_099_0e2ad991
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e2ad9912cc24574917d46e8d99c75348987cc8272dafea87c35df142ee121c1"
    family = "unknown"
    file_name = "Zapret.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:22:45"
  condition:
    hash.sha256(0, filesize) == "0e2ad9912cc24574917d46e8d99c75348987cc8272dafea87c35df142ee121c1"
}

rule MalwareBazaar_SalatStealer_100_8bc30eb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bc30eb67e864fc80ad80cd3fc52a4c74613af1c60ba1975b788a26cc277d8a7"
    family = "SalatStealer"
    file_name = "Zapret.exe"
    file_type = "exe"
    first_seen = "2026-07-04 18:19:43"
  condition:
    hash.sha256(0, filesize) == "8bc30eb67e864fc80ad80cd3fc52a4c74613af1c60ba1975b788a26cc277d8a7"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

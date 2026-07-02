# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-02

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 561 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 561 |
| Unique family labels | 8 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 79 |
| Mirai | 15 |
| AsyncRAT | 1 |
| Gafgyt | 1 |
| Prometei | 1 |
| SilentNet | 1 |
| ValleyRAT | 1 |
| Formbook | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 26 |
| apk | 26 |
| sh | 16 |
| unknown | 15 |
| exe | 10 |
| js | 3 |
| jar | 2 |
| dll | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `e6c5297e36310026`

| Field | Value |
|---|---|
| SHA-256 | `e6c5297e3631002646b7aca0aeaf880309e6d9213312ca63ac611554abe4f0bd` |
| Family label | `unknown` |
| File name | `libtcmalloc_minimal.dll` |
| File type | `dll` |
| First seen | `2026-07-02 04:33:02` |
| Reporter | `GDHJDSYDH1` |
| Tags | `backdoor, dll, DLLHijack, downloader, dropper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a779910d43dd427d257c2ab12ea04f6` |
| SHA-256 | `e6c5297e3631002646b7aca0aeaf880309e6d9213312ca63ac611554abe4f0bd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_e6c5297e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6c5297e3631002646b7aca0aeaf880309e6d9213312ca63ac611554abe4f0bd"
    family = "unknown"
    file_name = "libtcmalloc_minimal.dll"
    file_type = "dll"
    first_seen = "2026-07-02 04:33:02"
  condition:
    hash.sha256(0, filesize) == "e6c5297e3631002646b7aca0aeaf880309e6d9213312ca63ac611554abe4f0bd"
}
```

### Sample 2: `54166148dad00288`

| Field | Value |
|---|---|
| SHA-256 | `54166148dad002881957d42c2b793285bf6534a60c1c6becc1da218b1e5d31ac` |
| Family label | `Mirai` |
| File name | `vcimanagement.ppc` |
| File type | `elf` |
| First seen | `2026-07-02 04:31:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20d9b6cc89e7516f252a9aab8d6d8794` |
| SHA-1 | `62ec2bc83d9d91350cafa2106e0db245b1f56618` |
| SHA-256 | `54166148dad002881957d42c2b793285bf6534a60c1c6becc1da218b1e5d31ac` |
| SHA3-384 | `168e1f962b73f0fc3448fde5a7ab7df9e20a54ef2fb40c3d9d3dcbcb665abd6a6517755a51df17f7a6cf7f001df99797` |
| TLSH | `T1E9633C4372280F47E5A249B4253F1BE093BFED5024F4BA88694FDB5A4639E761086FCD` |
| SSDEEP | `768:rtbRcTIqx+TV7Rn0/qPhTS1qBeaqPfH7MZff9rwhOm7SG26sMxH5R+h2xMBS62Og:4g7q0TS1qBp2DM2OPMx36EZIJuN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_54166148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54166148dad002881957d42c2b793285bf6534a60c1c6becc1da218b1e5d31ac"
    family = "Mirai"
    file_name = "vcimanagement.ppc"
    file_type = "elf"
    first_seen = "2026-07-02 04:31:11"
  condition:
    hash.sha256(0, filesize) == "54166148dad002881957d42c2b793285bf6534a60c1c6becc1da218b1e5d31ac"
}
```

### Sample 3: `19fcb0877dd3375c`

| Field | Value |
|---|---|
| SHA-256 | `19fcb0877dd3375c036c5f3093bf1960d75710de97958cff8ad8a14f63ab9369` |
| Family label | `unknown` |
| File name | `vcimanagement.arm5` |
| File type | `elf` |
| First seen | `2026-07-02 04:31:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72b056d9eaa945fe5b8814103bda1640` |
| SHA-1 | `a4b745efc5d28ea873e4866fcf77b92354c7c81f` |
| SHA-256 | `19fcb0877dd3375c036c5f3093bf1960d75710de97958cff8ad8a14f63ab9369` |
| SHA3-384 | `3c3ac008c8f2c791e9b58ebda30bf23939c1e8909664e5c005ce6ba90378b1b2f96512fdce20e8d7531bfc0a33111359` |
| TLSH | `T1E133E8527DC26A2AC2E0537AF9AE81CE332067E8D1DF7257CC211B0476DA55F0DA3B52` |
| TELFHASH | `t156e02600ac759a5888d76ab49c9c06b49901221250664b10cf10d6e4883f454e308e4a` |
| SSDEEP | `1536:hCqZI1iDUguHppKKOxgPg6osAvH3Y09WZoh+fgh8l:XZeAPD9WmhA3l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_19fcb087
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fcb0877dd3375c036c5f3093bf1960d75710de97958cff8ad8a14f63ab9369"
    family = "unknown"
    file_name = "vcimanagement.arm5"
    file_type = "elf"
    first_seen = "2026-07-02 04:31:09"
  condition:
    hash.sha256(0, filesize) == "19fcb0877dd3375c036c5f3093bf1960d75710de97958cff8ad8a14f63ab9369"
}
```

### Sample 4: `c80a916d945db5fc`

| Field | Value |
|---|---|
| SHA-256 | `c80a916d945db5fc67e2b566eeb1910c1be2ececd0434cd6dedcf1da9a17f921` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm7` |
| File type | `elf` |
| First seen | `2026-07-02 04:31:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eedb4d4ffbfeb95cf5644074038e3262` |
| SHA-1 | `17d732acb7f37cee6bc81ee7336dbd321dfb79ff` |
| SHA-256 | `c80a916d945db5fc67e2b566eeb1910c1be2ececd0434cd6dedcf1da9a17f921` |
| SHA3-384 | `ab69fcfe241f32078d829467ea93fb786ff6bbc48cc351a0e40fde3e1192cacf6901e60f2ee51212a51c6b62b2dd4feb` |
| TLSH | `T143E34C46EA818F13C4D5177ABAAF01893332A75493DB730699186FB43FC6B6F0E63605` |
| TELFHASH | `t1fd311ef00b2ba1281a64cf9c88dcb3b9022c93165246df33ef2484bca01449ef939d4f` |
| SSDEEP | `3072:qJs9NARj5/Icu+NGtKfS6XH9gM33kigvNO6bl7XgwxQK3MSLOfM/9JJLxh:qJs9NARj5/IctGtK66Xh0O6bl7XNQLSh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_c80a916d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c80a916d945db5fc67e2b566eeb1910c1be2ececd0434cd6dedcf1da9a17f921"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-07-02 04:31:07"
  condition:
    hash.sha256(0, filesize) == "c80a916d945db5fc67e2b566eeb1910c1be2ececd0434cd6dedcf1da9a17f921"
}
```

### Sample 5: `01467634dee8365d`

| Field | Value |
|---|---|
| SHA-256 | `01467634dee8365d372e015ba94b8998d9ea0aceb2831092ca55bbbe5796cb39` |
| Family label | `Mirai` |
| File name | `vcimanagement.mips` |
| File type | `elf` |
| First seen | `2026-07-02 04:30:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8940b6a615ea873829a737b1b40122d` |
| SHA-1 | `d3cca9bef6fdabe08ce4955af91528c6704e50b2` |
| SHA-256 | `01467634dee8365d372e015ba94b8998d9ea0aceb2831092ca55bbbe5796cb39` |
| SHA3-384 | `e1636560fc9f915c8a0a98554bfd34169565be948698d461b62872228cddd08a14c3999ab6f5dbc570c29ae1d2edf8ee` |
| TLSH | `T12293B61E3E258FBCF79D823547B78E229648378A26E1C545E15CEA011EB034E741FBAD` |
| TELFHASH | `t17b014f58853807f0d7950decabedff7ad49151cf06165e338e00f9aeda65a428d01c2c` |
| SSDEEP | `1536:bK/QR35eT0Ata6s8QpTy4OVDZZUHWm5XSWYkhoh9m:ke3sTPutO4OVNZXm5XSWXhaY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_01467634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01467634dee8365d372e015ba94b8998d9ea0aceb2831092ca55bbbe5796cb39"
    family = "Mirai"
    file_name = "vcimanagement.mips"
    file_type = "elf"
    first_seen = "2026-07-02 04:30:05"
  condition:
    hash.sha256(0, filesize) == "01467634dee8365d372e015ba94b8998d9ea0aceb2831092ca55bbbe5796cb39"
}
```

### Sample 6: `96bbe280b9b8bcac`

| Field | Value |
|---|---|
| SHA-256 | `96bbe280b9b8bcace06dacb11ecc83f9f94c6e74d301d2e02e00ccf33179fb76` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-02 04:30:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a192c62b5efe6d5ed51e7754dabb8696` |
| SHA-1 | `13e5f3c585c81f76241c031a2121a72ec3dc144c` |
| SHA-256 | `96bbe280b9b8bcace06dacb11ecc83f9f94c6e74d301d2e02e00ccf33179fb76` |
| SHA3-384 | `f75f6c07e2323be3fb1d55ad4e8e6f9a0ec3a16fa20812733ec37a7a60cce4440a93ff65e153784cadc3495e5d87affe` |
| TLSH | `T1F8213E8D23ACB1311DCEC916731EC2EA39E295D2A4E40934B274DC34C6BBA8A3113F61` |
| SSDEEP | `24:3J3T5iHlwibV5Plwjy51NIplwi55xlw3KCk5Qlwcj5hlwVU5j8lwcj5llwJQ5plf:F4F7RrPqjFQ+IvRLZafR/d7D0ZypDzx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_96bbe280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96bbe280b9b8bcace06dacb11ecc83f9f94c6e74d301d2e02e00ccf33179fb76"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-02 04:30:03"
  condition:
    hash.sha256(0, filesize) == "96bbe280b9b8bcace06dacb11ecc83f9f94c6e74d301d2e02e00ccf33179fb76"
}
```

### Sample 7: `ba1b8d49b09ae263`

| Field | Value |
|---|---|
| SHA-256 | `ba1b8d49b09ae2635326a9995e5dbaf10cef2dfed2c53de0ecc271c5a1089581` |
| Family label | `Mirai` |
| File name | `vcimanagement.mpsl` |
| File type | `elf` |
| First seen | `2026-07-02 04:30:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cef226ab6a74dd714abc2e79a5db2d5f` |
| SHA-1 | `aa3f7e9f8edd771d77068b6a0c9eac8130a6905a` |
| SHA-256 | `ba1b8d49b09ae2635326a9995e5dbaf10cef2dfed2c53de0ecc271c5a1089581` |
| SHA3-384 | `5fda8be1e73c2879f996cb1385aa29069b744f8fa7c31404a4d3bb5a446fe4ac99951e6370a0ddeefb154da2588ede96` |
| TLSH | `T14093B30ABF740FF7E86FDD3749A92709158C550A22E97B357930D818F64B26F19E3860` |
| SSDEEP | `1536:zahaNVXM/WLJR1jzYvXI2I3Lk/0B/BXsZiaBLTe:zahGVEWj1/Mp2TXs/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_ba1b8d49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba1b8d49b09ae2635326a9995e5dbaf10cef2dfed2c53de0ecc271c5a1089581"
    family = "Mirai"
    file_name = "vcimanagement.mpsl"
    file_type = "elf"
    first_seen = "2026-07-02 04:30:02"
  condition:
    hash.sha256(0, filesize) == "ba1b8d49b09ae2635326a9995e5dbaf10cef2dfed2c53de0ecc271c5a1089581"
}
```

### Sample 8: `5a4f83d9146cf4af`

| Field | Value |
|---|---|
| SHA-256 | `5a4f83d9146cf4afc6eccab55e67b464d76ec6ec5343df55a5f98e59b57b8503` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm` |
| File type | `elf` |
| First seen | `2026-07-02 04:30:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65faae5d09d1ca53736a0e51c6f964c7` |
| SHA-1 | `83bc77a755feceb51d1a572b782acd5ac489c67b` |
| SHA-256 | `5a4f83d9146cf4afc6eccab55e67b464d76ec6ec5343df55a5f98e59b57b8503` |
| SHA3-384 | `9d23dcd4e8a80c48d7502c3a6b3c3ddc4b688581f05247fbf808b8421f53f74d10229ff2a87abe066d1a736e28080219` |
| TLSH | `T10C63079678C19A12C6E423BBF96E41CD332563A8D2DF320B9D212F5477CA82F0D67652` |
| TELFHASH | `t1f841a3e7db340aee67d6554492cea13559dd729a0f4118a3c60c2b0fd9c3692f41e833` |
| SSDEEP | `1536:U69Uvb15Wu1S7+hIVt5f6pxCCpRTYDdOcahWMUOH4g5b9/e35uEfh:U6ex9RgdOvhTqgm3nf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_5a4f83d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a4f83d9146cf4afc6eccab55e67b464d76ec6ec5343df55a5f98e59b57b8503"
    family = "Mirai"
    file_name = "vcimanagement.arm"
    file_type = "elf"
    first_seen = "2026-07-02 04:30:00"
  condition:
    hash.sha256(0, filesize) == "5a4f83d9146cf4afc6eccab55e67b464d76ec6ec5343df55a5f98e59b57b8503"
}
```

### Sample 9: `9938142110657a6e`

| Field | Value |
|---|---|
| SHA-256 | `9938142110657a6e02605d6da7466d06fa28767c20fd237b92b1e04c003a0380` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-02 04:29:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b13553b5c5df72062399709376d2eea0` |
| SHA-1 | `74e4efedd4ee3a0f05c8e611ff6d4f1828e9756d` |
| SHA-256 | `9938142110657a6e02605d6da7466d06fa28767c20fd237b92b1e04c003a0380` |
| SHA3-384 | `8697437076b5f53b4d2ee47db49f1b9383c6b2147deb0675ae67ab1bdd1789ece89c14f2328e09ac9387a9a3c7398a1a` |
| TLSH | `T19921378D236CB13408CEC912331EC7E239E396D294E40E3866A4DC36CA77D867117F46` |
| SSDEEP | `24:y5iHlwibB5Plwjc51NIplwi15xlw3KCi5Qlwcj5hlwVy5j8lwcj5llwJ+5plwdoZ:y4F79rPqjFQYIvR7Za/Rfd7D0VyFDzx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_99381421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9938142110657a6e02605d6da7466d06fa28767c20fd237b92b1e04c003a0380"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-02 04:29:59"
  condition:
    hash.sha256(0, filesize) == "9938142110657a6e02605d6da7466d06fa28767c20fd237b92b1e04c003a0380"
}
```

### Sample 10: `f5344149c1197d65`

| Field | Value |
|---|---|
| SHA-256 | `f5344149c1197d65c74f5594fd9e569b34605cd10e7e3cd5bc5ee17f003c2e66` |
| Family label | `Mirai` |
| File name | `vcimanagement.spc` |
| File type | `elf` |
| First seen | `2026-07-02 04:29:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ee8b9bee6ae8223636b6ed3cc0adbcf` |
| SHA-1 | `b125da0d822b0c439c6b58a4601764210f7a6521` |
| SHA-256 | `f5344149c1197d65c74f5594fd9e569b34605cd10e7e3cd5bc5ee17f003c2e66` |
| SHA3-384 | `48cf758b380f456fb2e7740263d68ea952ea7e8ac88dd620c11647f1d50f57d8af71f0da475fcbc2891803bdb9fa5bbc` |
| TLSH | `T190635A356D7A2E27C1C0A53E22F74764B2E1178E3AE8CA1E7D720E0EFF50A5460176B5` |
| SSDEEP | `1536:xBzNxnVCvXUB5HtSxZ8ChBKBPgvYLZGGTTJj:fzMx1vWIaGG5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_f5344149
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5344149c1197d65c74f5594fd9e569b34605cd10e7e3cd5bc5ee17f003c2e66"
    family = "Mirai"
    file_name = "vcimanagement.spc"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:58"
  condition:
    hash.sha256(0, filesize) == "f5344149c1197d65c74f5594fd9e569b34605cd10e7e3cd5bc5ee17f003c2e66"
}
```

### Sample 11: `9f04177030da8125`

| Field | Value |
|---|---|
| SHA-256 | `9f04177030da8125b2a23b471e5027c4ad48bded9f7ff64733051a8ad7f2a6e3` |
| Family label | `Mirai` |
| File name | `vcimanagement.m68k` |
| File type | `elf` |
| First seen | `2026-07-02 04:29:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a1a34c2d232097bc7e1d58e295c2279` |
| SHA-1 | `95c07efb6888d1a33c4e2019c181dcdf75452c28` |
| SHA-256 | `9f04177030da8125b2a23b471e5027c4ad48bded9f7ff64733051a8ad7f2a6e3` |
| SHA3-384 | `45e0bdb2386dbbfc97ff09ced3b66af7bc7a1aa0f8db87ea7d9ac399bcbbd1704a9de156c14c3480412c9bcef4f5efef` |
| TLSH | `T183635BD5E4029E3CF94BE6BE90170B08B92163545A930F2BD6AAFCD77CB306C9E46D41` |
| SSDEEP | `1536:JPoL/1vtkFW8s3ldF3GDrJ6VxsHZa2oUIM8ZG:OL/DgGVe4D4orq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_9f041770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f04177030da8125b2a23b471e5027c4ad48bded9f7ff64733051a8ad7f2a6e3"
    family = "Mirai"
    file_name = "vcimanagement.m68k"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:57"
  condition:
    hash.sha256(0, filesize) == "9f04177030da8125b2a23b471e5027c4ad48bded9f7ff64733051a8ad7f2a6e3"
}
```

### Sample 12: `1214d108e59c54c3`

| Field | Value |
|---|---|
| SHA-256 | `1214d108e59c54c3f6f548ccdeab6be49ffbf71b68957834878282686e745e96` |
| Family label | `Mirai` |
| File name | `vcimanagement.sh4` |
| File type | `elf` |
| First seen | `2026-07-02 04:29:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `178cea07746133dfe4f72fe0fc49ef68` |
| SHA-1 | `eee557fc4244f058106063a48d1fb8786e566f1b` |
| SHA-256 | `1214d108e59c54c3f6f548ccdeab6be49ffbf71b68957834878282686e745e96` |
| SHA3-384 | `1a6804b9e464f486ed71a502656cb10ae2ccc038133c4e4a4871fc4b3636e69b37cf5dad7f4b14fb58743285176e5bff` |
| TLSH | `T1F8539EA6C819BD94C4008334B422DEB42B63F40596671EB98E8789955487EFCF61F3FB` |
| SSDEEP | `1536:Oa8tF/MUQ75ifwt1ARSAmJF/Naz/TlHmrmCwM:OXttMUQ75QQbOTlmrm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_1214d108
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1214d108e59c54c3f6f548ccdeab6be49ffbf71b68957834878282686e745e96"
    family = "Mirai"
    file_name = "vcimanagement.sh4"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:56"
  condition:
    hash.sha256(0, filesize) == "1214d108e59c54c3f6f548ccdeab6be49ffbf71b68957834878282686e745e96"
}
```

### Sample 13: `f2fb50c771143507`

| Field | Value |
|---|---|
| SHA-256 | `f2fb50c771143507eeb3a5753bab53a8c87c4dbefe35adfa65dfb1a98e1c7639` |
| Family label | `Mirai` |
| File name | `vcimanagement.x86` |
| File type | `elf` |
| First seen | `2026-07-02 04:29:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9dee161da5d155d3d9d9dd5682169fb` |
| SHA-1 | `99d59703ba0b14876283af2357a044ec47f08262` |
| SHA-256 | `f2fb50c771143507eeb3a5753bab53a8c87c4dbefe35adfa65dfb1a98e1c7639` |
| SHA3-384 | `8a5c5980dadaa4fe9e3e1b1244fba6cad94c694124a545dc177fe7ea2560f47779549329bd9ca8bedea3521eb8c93b89` |
| TLSH | `T18A533AC1A983DCF2DD1146B83177FF328636F436212AE9E7D7D9A923AC81E41910729D` |
| TELFHASH | `t1c21138f95e7b1ce8f7e49440930e0b22666ae97b296033914633dcb421fdd8204b8c78` |
| SSDEEP | `1536:VMzVhePhrkmetvEuckIzN/hkfgiu5Bs88oUqpY8+3UoBiAGpTLE:VMzVhePlkmetvBcxJhyu5B1QqpE1oAGf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_f2fb50c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2fb50c771143507eeb3a5753bab53a8c87c4dbefe35adfa65dfb1a98e1c7639"
    family = "Mirai"
    file_name = "vcimanagement.x86"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:54"
  condition:
    hash.sha256(0, filesize) == "f2fb50c771143507eeb3a5753bab53a8c87c4dbefe35adfa65dfb1a98e1c7639"
}
```

### Sample 14: `60cbc151ef10a9e7`

| Field | Value |
|---|---|
| SHA-256 | `60cbc151ef10a9e7309638ea2d90c7da8a72af4c590308bca61f08243b64715f` |
| Family label | `Mirai` |
| File name | `vcimanagement.arm6` |
| File type | `elf` |
| First seen | `2026-07-02 04:29:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a5fd113040c60ccd081bb5607c33350` |
| SHA-1 | `ea3dc6d7f447b8ad0b4ab68e0f944449f5844765` |
| SHA-256 | `60cbc151ef10a9e7309638ea2d90c7da8a72af4c590308bca61f08243b64715f` |
| SHA3-384 | `1409e07b1ecdaffb03ae3100a48ed1e045f147c8aa240e9d41f15f3a708ca0671088e6aa2667f9c015936da7e042fb77` |
| TLSH | `T13483E895B8C18E11C5D413BBF92E018D331267A8E2DFB2179D206F147BCA92F0E7BA55` |
| TELFHASH | `t13321dce3df140edcb7f4939486cb624b06f935ae2b4974a78a4da74e81a39c0745e032` |
| SSDEEP | `1536:uRnabgUZLKq/zB8dAm5UhNTzeRGq1SM2b/cQ7dTMi6N1vGKYw5e5e995nZ4cuIfN:VgYLp/t815YNPeUqoMS/cod4pNFNL0aN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_60cbc151
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60cbc151ef10a9e7309638ea2d90c7da8a72af4c590308bca61f08243b64715f"
    family = "Mirai"
    file_name = "vcimanagement.arm6"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:53"
  condition:
    hash.sha256(0, filesize) == "60cbc151ef10a9e7309638ea2d90c7da8a72af4c590308bca61f08243b64715f"
}
```

### Sample 15: `998c6056363bdd5a`

| Field | Value |
|---|---|
| SHA-256 | `998c6056363bdd5ae5f299f06ec37d7a2e4a3807366a48fbc84de821cd6ba52b` |
| Family label | `unknown` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-07-02 04:29:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8beef39733a2cda45fdc9330e4eb024e` |
| SHA-1 | `3786ce0ab7c68ba06c2e67a60e96d28b2ea1e537` |
| SHA-256 | `998c6056363bdd5ae5f299f06ec37d7a2e4a3807366a48fbc84de821cd6ba52b` |
| SHA3-384 | `60b4536e4f70f8dcca7f6bb9437e6bd6cf39f162bf20a7963de95dec5370c38cecf37606e9d5ea7a074cc953fd8e0509` |
| TLSH | `T104210ECE23ACB1300CCEC952331EC6F639E696E254D40A3866A8DC75967BD9A7113F44` |
| SSDEEP | `24:E5iHlwibXk5Plwjak51NIplwijk5xlw3KCMk5QlwcFk5hlwV8k5j8lwcFk5llwJi:E4F7rkrpkqFkFQOkIJkRdkZa5kRZkd7O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_998c6056
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998c6056363bdd5ae5f299f06ec37d7a2e4a3807366a48fbc84de821cd6ba52b"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-02 04:29:52"
  condition:
    hash.sha256(0, filesize) == "998c6056363bdd5ae5f299f06ec37d7a2e4a3807366a48fbc84de821cd6ba52b"
}
```

### Sample 16: `614b2ac37b407b9a`

| Field | Value |
|---|---|
| SHA-256 | `614b2ac37b407b9a136255fa9709ed1fcfa8aa0b82b5a6065753a8eeddd111da` |
| Family label | `unknown` |
| File name | `樱桃播放器.zip` |
| File type | `zip` |
| First seen | `2026-07-02 04:26:32` |
| Reporter | `GDHJDSYDH1` |
| Tags | `backdoor, DLLHijack, downloader, dropper, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e26666a681a09df3a6b80e475ec3fbf` |
| SHA-1 | `9e0f1ff4b4b4a8189ea6827dfbf6b7ebe9f891b1` |
| SHA-256 | `614b2ac37b407b9a136255fa9709ed1fcfa8aa0b82b5a6065753a8eeddd111da` |
| SHA3-384 | `96dabc49f1041f1a899cb510069a2de4c69c62b8db45463db9b36f890887238208c2b58e47c281c7367e25953c533151` |
| TLSH | `T19C873340552D8986DA61C6739FBB7C7238F61D40E1833EC75AB03DDCAE7A087AF5121A` |
| SSDEEP | `786432:GDY6c47RFH8WEwnszZh1SC/JOEHW01ApgKQp4mDW/LyBGMhy4nBFh1V:+nc47RFcWEwszZh1SAUgJ1Apg2mD4uBZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_614b2ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "614b2ac37b407b9a136255fa9709ed1fcfa8aa0b82b5a6065753a8eeddd111da"
    family = "unknown"
    file_name = "樱桃播放器.zip"
    file_type = "zip"
    first_seen = "2026-07-02 04:26:32"
  condition:
    hash.sha256(0, filesize) == "614b2ac37b407b9a136255fa9709ed1fcfa8aa0b82b5a6065753a8eeddd111da"
}
```

### Sample 17: `14dbfd961231b155`

| Field | Value |
|---|---|
| SHA-256 | `14dbfd961231b155965c48b3ab75c1ad551bca63ae686ec4a903e30249fa578f` |
| Family label | `unknown` |
| File name | `ipmiv2.xml` |
| File type | `unknown` |
| First seen | `2026-07-02 03:51:51` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1142da1d33094179e5af4ef84ef0e3cb` |
| SHA-256 | `14dbfd961231b155965c48b3ab75c1ad551bca63ae686ec4a903e30249fa578f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_14dbfd96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14dbfd961231b155965c48b3ab75c1ad551bca63ae686ec4a903e30249fa578f"
    family = "unknown"
    file_name = "ipmiv2.xml"
    file_type = "unknown"
    first_seen = "2026-07-02 03:51:51"
  condition:
    hash.sha256(0, filesize) == "14dbfd961231b155965c48b3ab75c1ad551bca63ae686ec4a903e30249fa578f"
}
```

### Sample 18: `48f8f9303da8baab`

| Field | Value |
|---|---|
| SHA-256 | `48f8f9303da8baab31e347d8f5686fe4b13a3a34af9e34395a2b61f27fd0c2bd` |
| Family label | `unknown` |
| File name | `PB 2400.JS` |
| File type | `js` |
| First seen | `2026-07-02 02:47:24` |
| Reporter | `nat` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c850951bd418c58a5ae4523065c1c922` |
| SHA-1 | `7f760b124c5b36acd963560ff95898ae3e3cb5db` |
| SHA-256 | `48f8f9303da8baab31e347d8f5686fe4b13a3a34af9e34395a2b61f27fd0c2bd` |
| SHA3-384 | `9e611c679e6c46880713b80d92529e8fa6104c1b71f4590015d5fa328d7949671d4839856f9666af20d689d8ca2415b8` |
| TLSH | `T17E667D4065A4A2C339389B3A941D7EDB3D4E54F3AD74CF4936EECABA944CF022974253` |
| SSDEEP | `196608:2tX1MlLCb0hDgOo9DzG2HIbWUH1ymxv4VD9cJ11zITJSV3ssmZutX1MlLCz:kX16uhG551yEyg118TJSOsmeX17` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_48f8f930
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f8f9303da8baab31e347d8f5686fe4b13a3a34af9e34395a2b61f27fd0c2bd"
    family = "unknown"
    file_name = "PB 2400.JS"
    file_type = "js"
    first_seen = "2026-07-02 02:47:24"
  condition:
    hash.sha256(0, filesize) == "48f8f9303da8baab31e347d8f5686fe4b13a3a34af9e34395a2b61f27fd0c2bd"
}
```

### Sample 19: `40f84ae721a13a38`

| Field | Value |
|---|---|
| SHA-256 | `40f84ae721a13a383e13d18ba0d4cd120db5fe61fae4eefc117347fa6d1a4352` |
| Family label | `AsyncRAT` |
| File name | `SGH09876545678XW.js` |
| File type | `js` |
| First seen | `2026-07-02 02:47:06` |
| Reporter | `nat` |
| Tags | `AsyncRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc5eef48d8137eef70410515ae974aea` |
| SHA-1 | `9a297bdf2e2014743cc76739b71af175e27a9a66` |
| SHA-256 | `40f84ae721a13a383e13d18ba0d4cd120db5fe61fae4eefc117347fa6d1a4352` |
| SHA3-384 | `f3d486061eb63c525ff20ea074dd69e6fdf370899f1f92cc4c7d08caca5abb7d9baf3ded26f771a7ffec055df0d41a9c` |
| TLSH | `T10464D0082BC1B9728BD9943F247F926EEE3D4C869644D0C8F757F884FDB53069627288` |
| SSDEEP | `6144:ZrObwammarKkMF6Lm6X0SbVbMVkksSS4iaV3KY:ZrObkmog+/VwV3vVF` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_019_40f84ae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f84ae721a13a383e13d18ba0d4cd120db5fe61fae4eefc117347fa6d1a4352"
    family = "AsyncRAT"
    file_name = "SGH09876545678XW.js"
    file_type = "js"
    first_seen = "2026-07-02 02:47:06"
  condition:
    hash.sha256(0, filesize) == "40f84ae721a13a383e13d18ba0d4cd120db5fe61fae4eefc117347fa6d1a4352"
}
```

### Sample 20: `ebe4bd445397393f`

| Field | Value |
|---|---|
| SHA-256 | `ebe4bd445397393fb554db6554fb37afd31d0a30d309df8194901104027c52cd` |
| Family label | `unknown` |
| File name | `Order_Specification.js` |
| File type | `js` |
| First seen | `2026-07-02 02:46:47` |
| Reporter | `nat` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e0aea2832cf3aa3e160438902aee0bb` |
| SHA-1 | `2436bd33c86ce7827f8c540f36871fbff8767ec1` |
| SHA-256 | `ebe4bd445397393fb554db6554fb37afd31d0a30d309df8194901104027c52cd` |
| SHA3-384 | `59f570db62d57fa5c443fe002bd627393366c09323ed805b450cd22ae064383dcedab3fc6c2d2263601f251d30af096d` |
| TLSH | `T1330341D345D6F84BC5984655E74E04F92ED383D1F920AFAE1E0568FD8858A3F42E88F8` |
| SSDEEP | `192:1HaDDrHRHgSfbCFhfxC6rEyoyzEOzs8wRyqOD+LC4ze7Upzttnwls6:1CH5GFFxCyiOusqs7+e8u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_ebe4bd44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebe4bd445397393fb554db6554fb37afd31d0a30d309df8194901104027c52cd"
    family = "unknown"
    file_name = "Order_Specification.js"
    file_type = "js"
    first_seen = "2026-07-02 02:46:47"
  condition:
    hash.sha256(0, filesize) == "ebe4bd445397393fb554db6554fb37afd31d0a30d309df8194901104027c52cd"
}
```

### Sample 21: `8c51a2cf33720cd5`

| Field | Value |
|---|---|
| SHA-256 | `8c51a2cf33720cd5afa5739816bd52b0dd2ce2a2f27601ea6b3672da0de5c98d` |
| Family label | `unknown` |
| File name | `f` |
| File type | `unknown` |
| First seen | `2026-07-02 02:30:57` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdf49c199d004f0df236984852106d71` |
| SHA-256 | `8c51a2cf33720cd5afa5739816bd52b0dd2ce2a2f27601ea6b3672da0de5c98d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_8c51a2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c51a2cf33720cd5afa5739816bd52b0dd2ce2a2f27601ea6b3672da0de5c98d"
    family = "unknown"
    file_name = "f"
    file_type = "unknown"
    first_seen = "2026-07-02 02:30:57"
  condition:
    hash.sha256(0, filesize) == "8c51a2cf33720cd5afa5739816bd52b0dd2ce2a2f27601ea6b3672da0de5c98d"
}
```

### Sample 22: `67eaa2a0b90bec27`

| Field | Value |
|---|---|
| SHA-256 | `67eaa2a0b90bec27372402195301867fae5fcb063dc006b13cc654ea2b74dbd5` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-02 02:10:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e28002ea23f9d94b7b437cbe1fa36ce3` |
| SHA-1 | `f1c12d5b7fc1ac930e1b01751d7085e0f7fdfdbc` |
| SHA-256 | `67eaa2a0b90bec27372402195301867fae5fcb063dc006b13cc654ea2b74dbd5` |
| SHA3-384 | `f9d10c6a0c4803a6fb8c8f730de17c9a9c5fd42e0af7d1ea8633897fda68f380e35818ff7a18f0efdcbd7a3a115555ed` |
| TLSH | `T1A1016FC681446D1050EAEA1D22E75594F810C3CE1A5A4F7AFFADAD3DEB84D14F026F84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaiX41F3/M4EMtWZLXZOX:e9Qp+MsiXiEfMtWZjZOX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_67eaa2a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67eaa2a0b90bec27372402195301867fae5fcb063dc006b13cc654ea2b74dbd5"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-02 02:10:51"
  condition:
    hash.sha256(0, filesize) == "67eaa2a0b90bec27372402195301867fae5fcb063dc006b13cc654ea2b74dbd5"
}
```

### Sample 23: `6d08e6b1345dad62`

| Field | Value |
|---|---|
| SHA-256 | `6d08e6b1345dad62816b4612f92b0689eb937339ef04480ffe02bf58a28e8a70` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-02 01:52:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abad6c53cf28349353f381cea68dca1b` |
| SHA-1 | `e830f446367f8a105e44626530eab77eceaa27f6` |
| SHA-256 | `6d08e6b1345dad62816b4612f92b0689eb937339ef04480ffe02bf58a28e8a70` |
| SHA3-384 | `ed9a34b0cf632fa675549e44f2669d210518b9f48c1bfb75451b929cbddbf8829108b93b5f18143ff3d47beabd4c69e0` |
| TLSH | `T1F3D097A3622302B060316858F0CFAA80B2081B3E8D80C62D7833743B3F46309F0E0B91` |
| SSDEEP | `6:hTNxy9MLWi/LpQ87x0DGQAulNXYq4HvXDG+NjVsNXYrkJ:VNxy9M9X1QPiq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_6d08e6b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d08e6b1345dad62816b4612f92b0689eb937339ef04480ffe02bf58a28e8a70"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-02 01:52:50"
  condition:
    hash.sha256(0, filesize) == "6d08e6b1345dad62816b4612f92b0689eb937339ef04480ffe02bf58a28e8a70"
}
```

### Sample 24: `fdaac01917b26411`

| Field | Value |
|---|---|
| SHA-256 | `fdaac01917b2641163f593fccb03f51db0aa368e4acb1d955d8747c5a93faadc` |
| Family label | `unknown` |
| File name | `iran.powerpc` |
| File type | `elf` |
| First seen | `2026-07-02 01:51:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1fdf726c0df8d71948b08853fada56f` |
| SHA-1 | `b3299c16c1d4d01a9464fa3292d4831a4e8a12d3` |
| SHA-256 | `fdaac01917b2641163f593fccb03f51db0aa368e4acb1d955d8747c5a93faadc` |
| SHA3-384 | `d7c20dfe98189047f8b81d3791ff3eae8d15a8019b46ba4818fd46e1a5dfba17f4ca9c22e7a5b4387c8a6d9b409d75d1` |
| TLSH | `T118D33A06B70D0947D2632EF43B3B27E193DFDA8124E4E744651FBA8AA171D32458AECD` |
| SSDEEP | `1536:RZFVXjZxlrfRWU9F6H+Mf+U7uyUaQ7VpY1TANEuXgfSBvAnkiigCoFNGvWCHDt5/:fFVzZxdfRWUbfCT5uDOnjg0G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_fdaac019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdaac01917b2641163f593fccb03f51db0aa368e4acb1d955d8747c5a93faadc"
    family = "unknown"
    file_name = "iran.powerpc"
    file_type = "elf"
    first_seen = "2026-07-02 01:51:48"
  condition:
    hash.sha256(0, filesize) == "fdaac01917b2641163f593fccb03f51db0aa368e4acb1d955d8747c5a93faadc"
}
```

### Sample 25: `3d68bc2eccba098b`

| Field | Value |
|---|---|
| SHA-256 | `3d68bc2eccba098b2a5d8c641a14c50a15663e0fc268d4f98141f617d68f143f` |
| Family label | `Gafgyt` |
| File name | `a-r.m-6.Sakura` |
| File type | `elf` |
| First seen | `2026-07-02 01:48:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceb298c9837f57b89dfde7401724cd38` |
| SHA-1 | `bb63cc29f0bfa659a60a6ea025ecaced0ae3b925` |
| SHA-256 | `3d68bc2eccba098b2a5d8c641a14c50a15663e0fc268d4f98141f617d68f143f` |
| SHA3-384 | `da3c04a86200ef03df5c5d2b4559e88645392e53b1abbef92406eefe8fe5c1ad04915e9ad59e21c9b1ebe10c420467f5` |
| TLSH | `T169D31A04E551876BC2D2137AF79E469D37331BA493DB33215A34ABB82FC179D2E39821` |
| TELFHASH | `t1b8211d03a1eaca292bb79a34acb847f102556a2373927e717f0ec5c444370437978edb` |
| SSDEEP | `3072:NQe3TQbfKa/XMVky8hGGfvPW986SLgmFQwYvQX8T7:p3TQbCafVBvPdLgmFQwYvG8T7` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_025_3d68bc2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d68bc2eccba098b2a5d8c641a14c50a15663e0fc268d4f98141f617d68f143f"
    family = "Gafgyt"
    file_name = "a-r.m-6.Sakura"
    file_type = "elf"
    first_seen = "2026-07-02 01:48:12"
  condition:
    hash.sha256(0, filesize) == "3d68bc2eccba098b2a5d8c641a14c50a15663e0fc268d4f98141f617d68f143f"
}
```

### Sample 26: `c99b5c82486be6bf`

| Field | Value |
|---|---|
| SHA-256 | `c99b5c82486be6bf6e9e018e5f2bdcbdfd922c075c1fac3923bbcdf8e4bec9c8` |
| Family label | `unknown` |
| File name | `iran.sh4` |
| File type | `elf` |
| First seen | `2026-07-02 01:29:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd3716ee99f08c2b3082cc59c0288f7e` |
| SHA-1 | `3286e17fd8fe0250f3766f3e7ef11c8a441a11b4` |
| SHA-256 | `c99b5c82486be6bf6e9e018e5f2bdcbdfd922c075c1fac3923bbcdf8e4bec9c8` |
| SHA3-384 | `ffcac14052f939869ca083f1729d4278b2e4bdc2b98cec98b3a241cc80b1b1a14284b50ea50e227d1f2f89806ee1f6f0` |
| TLSH | `T12FC35BA3CD2A6F5CC624D9B4F0709F791BA3992181471FBA457BC2748093D8DFA463B8` |
| SSDEEP | `1536:6flhkIxi4ImruzLCHKjtMv7GZ8obpVKsdWcWZFXPtVyNWER/FYR:6daIx59QLPjkAbpVrAcW/XSNHR/+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_c99b5c82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c99b5c82486be6bf6e9e018e5f2bdcbdfd922c075c1fac3923bbcdf8e4bec9c8"
    family = "unknown"
    file_name = "iran.sh4"
    file_type = "elf"
    first_seen = "2026-07-02 01:29:47"
  condition:
    hash.sha256(0, filesize) == "c99b5c82486be6bf6e9e018e5f2bdcbdfd922c075c1fac3923bbcdf8e4bec9c8"
}
```

### Sample 27: `d53dd27e40da9a3c`

| Field | Value |
|---|---|
| SHA-256 | `d53dd27e40da9a3c793da32c0bdde83c54e5da81dc9c6cf2d4f1886b93a25560` |
| Family label | `unknown` |
| File name | `smp.jar` |
| File type | `jar` |
| First seen | `2026-07-02 01:22:10` |
| Reporter | `lucibee` |
| Tags | `IRAHook, jar, payload` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe6cb411f86018613413b7b2f6753983` |
| SHA-1 | `38a253fcba67a4badcd06036e70ea2eac4684cfb` |
| SHA-256 | `d53dd27e40da9a3c793da32c0bdde83c54e5da81dc9c6cf2d4f1886b93a25560` |
| SHA3-384 | `d4f00f230f4d34321370bf447de9b5d3fe88fe7a0a9680e6743252c9b6fa24b4da82f143cfa0584752587f30450738e8` |
| TLSH | `T152672326BDF6C82BD96780B311C3C35360291AD9A807D07F47A08D859DB1DAA2356FFD` |
| SSDEEP | `786432:wWvTUDadwK+pNzN3a9pcDpe7v0eZIsXNYGxZ:B4mGBpNzw9zv0eXy8Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_d53dd27e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d53dd27e40da9a3c793da32c0bdde83c54e5da81dc9c6cf2d4f1886b93a25560"
    family = "unknown"
    file_name = "smp.jar"
    file_type = "jar"
    first_seen = "2026-07-02 01:22:10"
  condition:
    hash.sha256(0, filesize) == "d53dd27e40da9a3c793da32c0bdde83c54e5da81dc9c6cf2d4f1886b93a25560"
}
```

### Sample 28: `5af8303a76db5fea`

| Field | Value |
|---|---|
| SHA-256 | `5af8303a76db5feaac150cc350392fb8e2582c27adbdf59566528b741c14e3f3` |
| Family label | `unknown` |
| File name | `bbc` |
| File type | `sh` |
| First seen | `2026-07-02 01:20:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `720cac7fa7554f1b8fcc8b725ad76ca0` |
| SHA-1 | `18e6f5c001feac288fa34dc3e68d33523b1ada02` |
| SHA-256 | `5af8303a76db5feaac150cc350392fb8e2582c27adbdf59566528b741c14e3f3` |
| SHA3-384 | `fe7d1193ddfe4cecb6220529240b9490cb295a974f7d8a6efc9ddb6f9755d2b0bfaf157ab635e136c2058ad024dba23f` |
| TLSH | `T1C8F08203B487F032804439A89765F75AFC247C476262CD4CB8407A50DED24247861140` |
| SSDEEP | `12:lSjhh1OL9ephRjk4Y4bou7Co1VOq2xddNizdI/HXqNB:lk1gYpTr8i3fOq2bf8IY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5af8303a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5af8303a76db5feaac150cc350392fb8e2582c27adbdf59566528b741c14e3f3"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-07-02 01:20:51"
  condition:
    hash.sha256(0, filesize) == "5af8303a76db5feaac150cc350392fb8e2582c27adbdf59566528b741c14e3f3"
}
```

### Sample 29: `15b04c03fae4a70b`

| Field | Value |
|---|---|
| SHA-256 | `15b04c03fae4a70bb8b9b14d91c156c76d163d5198fff67bab554e6f15b7385a` |
| Family label | `Mirai` |
| File name | `iran.armv4l` |
| File type | `elf` |
| First seen | `2026-07-02 01:06:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d97e7fc39534a3ff786b0f6abfedb8cf` |
| SHA-1 | `f8d8cc30e53f699d9ebeb62337d902c783bb890e` |
| SHA-256 | `15b04c03fae4a70bb8b9b14d91c156c76d163d5198fff67bab554e6f15b7385a` |
| SHA3-384 | `c4f084a85d2a70f0020b1c3d1578994df4f9fb085e9c724f750343b60fe976b47b2cb49d69f821304310620a859c5fe4` |
| TLSH | `T17DD31A45FD419F17CAC256BBFF4E428D7B2A176CD2EE720399256F20378B85A0E3A141` |
| TELFHASH | `t1df110e9198100d9cb6d0430951ee716759e938f92a313276ffafed1e43529e1961c02e` |
| SSDEEP | `1536:CBhFErfLW09qK6s3JUnhM2uduwfoeTtwYQR96ZAOY43yYrCAuMQUNlIMwyw3+jix:YhFELLTR6s3JUSwwhJw563RmJhSxSD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_15b04c03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15b04c03fae4a70bb8b9b14d91c156c76d163d5198fff67bab554e6f15b7385a"
    family = "Mirai"
    file_name = "iran.armv4l"
    file_type = "elf"
    first_seen = "2026-07-02 01:06:51"
  condition:
    hash.sha256(0, filesize) == "15b04c03fae4a70bb8b9b14d91c156c76d163d5198fff67bab554e6f15b7385a"
}
```

### Sample 30: `a97f44445fd3a18c`

| Field | Value |
|---|---|
| SHA-256 | `a97f44445fd3a18c35cc268d6e4f89673d460714406a9776f7c39060b2827f02` |
| Family label | `unknown` |
| File name | `iran.x86_64` |
| File type | `elf` |
| First seen | `2026-07-02 01:02:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7673b3d39d0fa353cdf717120badf2b6` |
| SHA-1 | `f06813fdbdbaa2189c85d141dfe5f901dcd2e5cc` |
| SHA-256 | `a97f44445fd3a18c35cc268d6e4f89673d460714406a9776f7c39060b2827f02` |
| SHA3-384 | `547b244a5f24da6cca4d5b30e9d37f28af561d7c6abb9abc7eced7f3bca4d14ee8e7d2fd8a7a799a5dc1feeed1b5b6c4` |
| TLSH | `T120D35D17B5C1D0FDC8D6C1B88BAAE126DA32B42D5234B15F27C46F262E5DE206F6DB10` |
| TELFHASH | `t16351dcb135aa38e471e7b256730ada64c8350a5104d030e3dbb7b9face11b840d76437` |
| SSDEEP | `3072:MkFIef3bwwGil1P/Wpb1EAdqXxHMc/OH1P9SmJsscA88:yE2R7hxHGh8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_a97f4444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a97f44445fd3a18c35cc268d6e4f89673d460714406a9776f7c39060b2827f02"
    family = "unknown"
    file_name = "iran.x86_64"
    file_type = "elf"
    first_seen = "2026-07-02 01:02:40"
  condition:
    hash.sha256(0, filesize) == "a97f44445fd3a18c35cc268d6e4f89673d460714406a9776f7c39060b2827f02"
}
```

### Sample 31: `d61cab6815d2c502`

| Field | Value |
|---|---|
| SHA-256 | `d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183` |
| Family label | `unknown` |
| File name | `d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183` |
| File type | `elf` |
| First seen | `2026-07-02 01:01:58` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c00675d73f4978553a782b0d73a94eb` |
| SHA-1 | `ff0656576077e3c51cf1807c7e8b22c2695cf064` |
| SHA-256 | `d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183` |
| SHA3-384 | `be2ed113447f171f7adc51850842a4cb63c1b108d624375cc0c688a181c7409b87293f3437f76469270d68668ceea5e3` |
| TLSH | `T1D657CF7792067CEDE9B94DB4C41015816DA878874778E3C7BAC8B0E666EB6D08D3E730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQI:cqYUQuVDt0TZEAk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_d61cab68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183"
    family = "unknown"
    file_name = "d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183"
    file_type = "elf"
    first_seen = "2026-07-02 01:01:58"
  condition:
    hash.sha256(0, filesize) == "d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183"
}
```

### Sample 32: `45ddea6f511d08f7`

| Field | Value |
|---|---|
| SHA-256 | `45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31` |
| Family label | `unknown` |
| File name | `45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31` |
| File type | `elf` |
| First seen | `2026-07-02 01:01:51` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fae500faf8a32e64cd02345ce1247b6e` |
| SHA-1 | `2240c991a90c559223847a08b81bb1cc95fdefc0` |
| SHA-256 | `45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31` |
| SHA3-384 | `83649120f8501e3b41c60184d80800ae8238a5b52ec1e9d4086b2331f85c2fe9d2584d247e4738aab9d27ae7ac236934` |
| TLSH | `T131D3F75B5CA450E5D4EEE078CA3BF217BEB27014073837E72EA15A610F67EE161B8B14` |
| SSDEEP | `1536:oqZxxZV29yl9anqCLrhC3SiajSusE19/aFXUOF/lQB8foyRLZ8/1fu:om2ACLE5ajZJKXUo/KBP/2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_45ddea6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31"
    family = "unknown"
    file_name = "45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31"
    file_type = "elf"
    first_seen = "2026-07-02 01:01:51"
  condition:
    hash.sha256(0, filesize) == "45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31"
}
```

### Sample 33: `2dd2d2e4b0caad0e`

| Field | Value |
|---|---|
| SHA-256 | `2dd2d2e4b0caad0ee13ce14277b88ac1d1585b7ba1ed627d853f05ca9b171c66` |
| Family label | `unknown` |
| File name | `iran.x86_64` |
| File type | `elf` |
| First seen | `2026-07-02 01:01:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a13675f9eff0a5cb808931df5eb73554` |
| SHA-1 | `304be64d088455bfcc58e52b10ed805259bda512` |
| SHA-256 | `2dd2d2e4b0caad0ee13ce14277b88ac1d1585b7ba1ed627d853f05ca9b171c66` |
| SHA3-384 | `8a0037b884bf2a1ef2a9e32da0099f4a8e595485aafcd75062f8687d51ca2c4074f1c28b84d25f841cd17fa8cc156900` |
| TLSH | `T1494302E76F9AF024CFBA8E31052D06C0DD6DFD43212B1763D5E806A5A9167EB7C90922` |
| SSDEEP | `1536:llrrNBi1pgNEJ1JxvE8c/8Ap0aYOv7BljYN:l9y0NUMNp0aYOzBK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_2dd2d2e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd2d2e4b0caad0ee13ce14277b88ac1d1585b7ba1ed627d853f05ca9b171c66"
    family = "unknown"
    file_name = "iran.x86_64"
    file_type = "elf"
    first_seen = "2026-07-02 01:01:49"
  condition:
    hash.sha256(0, filesize) == "2dd2d2e4b0caad0ee13ce14277b88ac1d1585b7ba1ed627d853f05ca9b171c66"
}
```

### Sample 34: `1a0342c1c562ff15`

| Field | Value |
|---|---|
| SHA-256 | `1a0342c1c562ff1527627192d8ea3be9aedde4b47c5436d5f2bcb924d9725397` |
| Family label | `Mirai` |
| File name | `iran.armv7l` |
| File type | `elf` |
| First seen | `2026-07-02 00:49:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77fccd17a8c1695fc2ae89a0c10b1807` |
| SHA-1 | `dba2daf4ef806d2603da22ea895d659052ddac93` |
| SHA-256 | `1a0342c1c562ff1527627192d8ea3be9aedde4b47c5436d5f2bcb924d9725397` |
| SHA3-384 | `92988685ce261b503b73d195e47d56268a12a409f99d97824a39bed0028a27a04286257e54ba68c39641268ecd40533d` |
| TLSH | `T182C30649ED416F01D9D636FEFE4E028973534B6CE3FE7101AA245B2127CAA6B0F7A105` |
| TELFHASH | `t1e41123b39b408acd63c3c08068dd3565698c367a3b1c1409b2adff0b81d3560f428434` |
| SSDEEP | `3072:eoEBSBlUvKO3Qhx+nv8Sta4cYC/2OA2J+McDHRrnvIwueN:ZEUBlUiy6x+vRta4PC/2OAc+jHtvIwuY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_1a0342c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a0342c1c562ff1527627192d8ea3be9aedde4b47c5436d5f2bcb924d9725397"
    family = "Mirai"
    file_name = "iran.armv7l"
    file_type = "elf"
    first_seen = "2026-07-02 00:49:47"
  condition:
    hash.sha256(0, filesize) == "1a0342c1c562ff1527627192d8ea3be9aedde4b47c5436d5f2bcb924d9725397"
}
```

### Sample 35: `463c8c98e977e279`

| Field | Value |
|---|---|
| SHA-256 | `463c8c98e977e279732093f73ded0f41d292a83d08c35609d544b90bcc195a8b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-02 00:42:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fd378bc943cf7742174a3bdccff1651` |
| SHA-1 | `5fe6a3332ff4aa20a5f28a779aab0780627f9d46` |
| SHA-256 | `463c8c98e977e279732093f73ded0f41d292a83d08c35609d544b90bcc195a8b` |
| SHA3-384 | `db6ef9959a0f7f76d77faaa1dd1396b6a252aa22576e73da6415bd5271d99c33a7274812494c7677d305635aaece4261` |
| TLSH | `T1A0236C6516817C24AA99D4371D7F2F0CBDA983E6320492DDBFCA3CF28C59A9CD11872D` |
| SSDEEP | `768:zXRWNGxVH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:NlxCcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_463c8c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "463c8c98e977e279732093f73ded0f41d292a83d08c35609d544b90bcc195a8b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-02 00:42:48"
  condition:
    hash.sha256(0, filesize) == "463c8c98e977e279732093f73ded0f41d292a83d08c35609d544b90bcc195a8b"
}
```

### Sample 36: `e36fb6c05e513695`

| Field | Value |
|---|---|
| SHA-256 | `e36fb6c05e5136959ba0a1feb19185da2b242f808d4d1fd26d9b6664a1eaf65f` |
| Family label | `Mirai` |
| File name | `iran.armv6l` |
| File type | `elf` |
| First seen | `2026-07-02 00:38:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d386e0d0b503aa88ef9d83069b7eb8bb` |
| SHA-1 | `b1fdff935ae93c694400c48ff9d80ba4e44452ab` |
| SHA-256 | `e36fb6c05e5136959ba0a1feb19185da2b242f808d4d1fd26d9b6664a1eaf65f` |
| SHA3-384 | `49135fcf632ef65949cdbcbce647c07122b467636b4c90f2da1dff1ce88b9e199f9e9ff9ec80dc5719fcbc070cf0263b` |
| TLSH | `T180E31A46F8819F12D5D151BEFE0E128E73131B3CE2DE72129D246B747B8A8BB0E3A515` |
| TELFHASH | `t18e11c03aca4914de72f1850491cf212e179cbc6a2f5674157bf7ef1f82534e1712842a` |
| SSDEEP | `3072:DNYO7m3RQb+G6dtiazQjWp6Ka7XnDpeox6c6LF8hEC:DqO7AM+PtiazQy6KgpNx6ZF8GC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_e36fb6c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e36fb6c05e5136959ba0a1feb19185da2b242f808d4d1fd26d9b6664a1eaf65f"
    family = "Mirai"
    file_name = "iran.armv6l"
    file_type = "elf"
    first_seen = "2026-07-02 00:38:46"
  condition:
    hash.sha256(0, filesize) == "e36fb6c05e5136959ba0a1feb19185da2b242f808d4d1fd26d9b6664a1eaf65f"
}
```

### Sample 37: `23dbb81b2e100442`

| Field | Value |
|---|---|
| SHA-256 | `23dbb81b2e1004427f908dca6fced8e08115fb42f6928c4a639144636387dde5` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-02 00:33:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f0c7ef579ab8e74cab7e5d3aa88c816` |
| SHA-1 | `cf9857cdebb27ce842dd223031aa5ee5190f1901` |
| SHA-256 | `23dbb81b2e1004427f908dca6fced8e08115fb42f6928c4a639144636387dde5` |
| SHA3-384 | `97c53ddabe9759205aa9cd4433a97b139766dab104fb30694744da313980651d3d1e334bc978ff5c16fad490c1b8059c` |
| TLSH | `T13F0148C68240AD10506AEA1E62E756D0B410C3CE0A5A0F78BFDDAD3DEB98D14F126F88` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaiX4bF3/MSEMHWZBXZ67:e9Qp+MsiXGEpMHWZ9Z67` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_23dbb81b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23dbb81b2e1004427f908dca6fced8e08115fb42f6928c4a639144636387dde5"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-02 00:33:46"
  condition:
    hash.sha256(0, filesize) == "23dbb81b2e1004427f908dca6fced8e08115fb42f6928c4a639144636387dde5"
}
```

### Sample 38: `ad0a8700ca705ec2`

| Field | Value |
|---|---|
| SHA-256 | `ad0a8700ca705ec2d71c7951a3e4cad8b84b0a03b361d8f05dfed7b77ffce8ea` |
| Family label | `unknown` |
| File name | `iran.mipsel` |
| File type | `elf` |
| First seen | `2026-07-02 00:29:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9ed874a9fc5510a22348d0e10d1eae1` |
| SHA-1 | `407ff2d45d86ad42071c49619774815c00c0dba2` |
| SHA-256 | `ad0a8700ca705ec2d71c7951a3e4cad8b84b0a03b361d8f05dfed7b77ffce8ea` |
| SHA3-384 | `2f569ea19056e4784d9a4588a348bdfb6ef1c947386507de7e86c4f3504342bd4a6c865500ec0f2618b5083ae62beafe` |
| TLSH | `T15904C71A9F920FFBDC6FDD3702A90B0635CC555722A43B363674D928F54AA0B49E3C68` |
| SSDEEP | `3072:JaRhGQd6fzirBrwkQk4jNWYy1oma49zCQZpF:JEhB6fXkQk9Y9xszd7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_ad0a8700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad0a8700ca705ec2d71c7951a3e4cad8b84b0a03b361d8f05dfed7b77ffce8ea"
    family = "unknown"
    file_name = "iran.mipsel"
    file_type = "elf"
    first_seen = "2026-07-02 00:29:46"
  condition:
    hash.sha256(0, filesize) == "ad0a8700ca705ec2d71c7951a3e4cad8b84b0a03b361d8f05dfed7b77ffce8ea"
}
```

### Sample 39: `c359082d3c646c95`

| Field | Value |
|---|---|
| SHA-256 | `c359082d3c646c95de08998999807e3d21cf9f8b8d5a67f871836b45845232b7` |
| Family label | `Mirai` |
| File name | `iran.aarch64` |
| File type | `elf` |
| First seen | `2026-07-02 00:28:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37ecb93c583c5ce391005e9cff09180c` |
| SHA-1 | `3440bbfef3e1a724a2175c28a9955ed39a665a39` |
| SHA-256 | `c359082d3c646c95de08998999807e3d21cf9f8b8d5a67f871836b45845232b7` |
| SHA3-384 | `416142e5b437fac8e9f158399a01f24335aa8662bfd5a83da75e6b2b4420574f73612771c18bdf53789033fcc8effacb` |
| TLSH | `T139145AA9BA0F6C41F2C2D3F8DE8C83E13E1735E3C7768971791212EDDAA39D95990502` |
| SSDEEP | `3072:G+yfyYlw8+NyNX47JhGr7qMW7v2AIZaJ+eMLsnoq:G+yfyYe8yyNXoJAXqB7vth+ehnoq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_c359082d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c359082d3c646c95de08998999807e3d21cf9f8b8d5a67f871836b45845232b7"
    family = "Mirai"
    file_name = "iran.aarch64"
    file_type = "elf"
    first_seen = "2026-07-02 00:28:47"
  condition:
    hash.sha256(0, filesize) == "c359082d3c646c95de08998999807e3d21cf9f8b8d5a67f871836b45845232b7"
}
```

### Sample 40: `d463b63b43f0e7ee`

| Field | Value |
|---|---|
| SHA-256 | `d463b63b43f0e7ee43373c74490c11877a925084bac04240e2ae4305b16cfe3e` |
| Family label | `unknown` |
| File name | `iran.m68k` |
| File type | `elf` |
| First seen | `2026-07-02 00:27:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bad6f964d8446321883f2530b2e3624f` |
| SHA-1 | `ab2395040c7c2b9dea8e20ff3c45e9b5ca5df2df` |
| SHA-256 | `d463b63b43f0e7ee43373c74490c11877a925084bac04240e2ae4305b16cfe3e` |
| SHA3-384 | `634c111520574f2d8de83b400f61e871814d1ccd364b65dd13e92a3419fa7eb3a99a6358c5ef1bae4d356072a79aec75` |
| TLSH | `T144F308C7F900DAF6F809E3374853080AB130B7A144926A777257357EED3E199197BE8A` |
| SSDEEP | `3072:7rxau8y+M564bybl5J6dwOI5fb+ny0ypfV8jbibLTMfOusiOc:7rAK57ybvJ6dwV5+1ypfLQTOc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_d463b63b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d463b63b43f0e7ee43373c74490c11877a925084bac04240e2ae4305b16cfe3e"
    family = "unknown"
    file_name = "iran.m68k"
    file_type = "elf"
    first_seen = "2026-07-02 00:27:46"
  condition:
    hash.sha256(0, filesize) == "d463b63b43f0e7ee43373c74490c11877a925084bac04240e2ae4305b16cfe3e"
}
```

### Sample 41: `871e5390aa140633`

| Field | Value |
|---|---|
| SHA-256 | `871e5390aa140633638e9a377ed9c3bb38adbe51152bd363d809716aa581cd47` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-02 00:25:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `862a7b8d1c157196f69bb509e08cc890` |
| SHA-1 | `24c4ca7105ec28e0112807c72e3a79f295021e08` |
| SHA-256 | `871e5390aa140633638e9a377ed9c3bb38adbe51152bd363d809716aa581cd47` |
| SHA3-384 | `c63ba1c00a914128ca042223cea6a6222a1605f1910603facb15c0cea40e4aec4548d1c8ab8bf84e5d17477d93cf7031` |
| TLSH | `T18CD097B391B302B01821C814FACBB400BBA4AF7E8C92C91DFA0310B61E1B30BF4C12D5` |
| SSDEEP | `6:hTamI2Z4XpcK2ZTWwF190ZpAulNXYq9DG+NjVsNXYrkJ:VahN5IZTWw1ePiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_871e5390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "871e5390aa140633638e9a377ed9c3bb38adbe51152bd363d809716aa581cd47"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-02 00:25:50"
  condition:
    hash.sha256(0, filesize) == "871e5390aa140633638e9a377ed9c3bb38adbe51152bd363d809716aa581cd47"
}
```

### Sample 42: `90ff88acf5009481`

| Field | Value |
|---|---|
| SHA-256 | `90ff88acf500948127dd71befff24024fa531f59154f788b4640e2b396e5cb30` |
| Family label | `unknown` |
| File name | `bbc` |
| File type | `sh` |
| First seen | `2026-07-02 00:10:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `169efceeb1c6bdb76fd3b6a871ffb211` |
| SHA-1 | `5300aa649c6e1d5f66c606780ba5dcc559973b06` |
| SHA-256 | `90ff88acf500948127dd71befff24024fa531f59154f788b4640e2b396e5cb30` |
| SHA3-384 | `02f85ad371dfb4b09bdd15450f1974ba46380342239c779abc0d818141728cc14ad3552752eecbca2b13bed41aad0dc1` |
| TLSH | `T1A7F0A007B48BF036808439E8DB66F75AFC74BC476262DE4CB840BBA0DFD24347861240` |
| SSDEEP | `12:lSjhh1OL9ephRjk4Y4bou7Co1VOq2xddNizdI/HXLS9r:lk1gYpTr8i3fOq2bf8Ijer` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_90ff88ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90ff88acf500948127dd71befff24024fa531f59154f788b4640e2b396e5cb30"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-07-02 00:10:48"
  condition:
    hash.sha256(0, filesize) == "90ff88acf500948127dd71befff24024fa531f59154f788b4640e2b396e5cb30"
}
```

### Sample 43: `3155a4b8a3f92e29`

| Field | Value |
|---|---|
| SHA-256 | `3155a4b8a3f92e2947f88970a4d9f6a0c47fa66c93a1f5c7c8b8cabe93f6acf6` |
| Family label | `unknown` |
| File name | `sweetclient.jar` |
| File type | `jar` |
| First seen | `2026-07-01 23:58:23` |
| Reporter | `lucibee` |
| Tags | `IRAHook, jar, minecraft, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c907a31feade35ecb5e5fd689b9b12fa` |
| SHA-1 | `90acdb930108393031d86e7bed93bb9dfdc6f57e` |
| SHA-256 | `3155a4b8a3f92e2947f88970a4d9f6a0c47fa66c93a1f5c7c8b8cabe93f6acf6` |
| SHA3-384 | `36f46a483447164e1a44363f3414482e4e1d87f3c51ec46711d1c5083e1c6b82afb7a88751153255f97cd0aacc4134d9` |
| TLSH | `T1E12533AAB5A69EB0F127B13D3183461EFE35224525CD9DA17E9018C87D23832C367DDE` |
| SSDEEP | `24576:MkBGe4KzcwAd7dR2cvBuUnppKtCSckQt/USzPMfOcMbGWOWvc:MPRKgw49vEQKtwhU+MmBlc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_3155a4b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3155a4b8a3f92e2947f88970a4d9f6a0c47fa66c93a1f5c7c8b8cabe93f6acf6"
    family = "unknown"
    file_name = "sweetclient.jar"
    file_type = "jar"
    first_seen = "2026-07-01 23:58:23"
  condition:
    hash.sha256(0, filesize) == "3155a4b8a3f92e2947f88970a4d9f6a0c47fa66c93a1f5c7c8b8cabe93f6acf6"
}
```

### Sample 44: `b982d3035533c2fb`

| Field | Value |
|---|---|
| SHA-256 | `b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb` |
| Family label | `unknown` |
| File name | `b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb` |
| File type | `elf` |
| First seen | `2026-07-01 23:22:48` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58202d53b803b62ecb9bc89a0d4d40bc` |
| SHA-1 | `6be67874ada031b4330df74d7759a990c672154d` |
| SHA-256 | `b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb` |
| SHA3-384 | `e6793f27c3b74140b0796349685f476e170694537b7abf60e53f97442d22a68d17189863f7ddb40f6f438f91bec09d82` |
| TLSH | `T19757CF7792067CEDE9B94DB4C41015816DA878874778E3C7BAC870E6A6EB6D08D3E730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQh:cqYUQuVDt0TZE2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_b982d303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb"
    family = "unknown"
    file_name = "b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb"
    file_type = "elf"
    first_seen = "2026-07-01 23:22:48"
  condition:
    hash.sha256(0, filesize) == "b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb"
}
```

### Sample 45: `c6ba287f87ac3550`

| Field | Value |
|---|---|
| SHA-256 | `c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4` |
| Family label | `Prometei` |
| File name | `c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4` |
| File type | `elf` |
| First seen | `2026-07-01 23:00:39` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b20450b0c5fc73e221d31962e07468c5` |
| SHA-1 | `23d1550557fe097ba95a2d71e0be8d9108b6cb80` |
| SHA-256 | `c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4` |
| SHA3-384 | `1d2e9724153803112e3b856d42c79f1ba22845cecf71fe80f9962bd245d7c9219ad8f5eb4d78f43890fd61aaa5b4dc9c` |
| TLSH | `T1F8A423B4F9219E9F6DD769B91B24C31DE182C172589D4C2313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdO:Fs6pyCC/Ya2hpi6T6N4g` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_045_c6ba287f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4"
    family = "Prometei"
    file_name = "c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4"
    file_type = "elf"
    first_seen = "2026-07-01 23:00:39"
  condition:
    hash.sha256(0, filesize) == "c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4"
}
```

### Sample 46: `d1f8cfd9d854f859`

| Field | Value |
|---|---|
| SHA-256 | `d1f8cfd9d854f8594341197ba9e1bba84948824441133c22e2e83ba914f47e59` |
| Family label | `unknown` |
| File name | `4433-1.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 22:55:02` |
| Reporter | `BastianHein_` |
| Tags | `Dex, moqhao` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `443fdfa81a953620e4f4fd82673c56cc` |
| SHA-256 | `d1f8cfd9d854f8594341197ba9e1bba84948824441133c22e2e83ba914f47e59` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_d1f8cfd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1f8cfd9d854f8594341197ba9e1bba84948824441133c22e2e83ba914f47e59"
    family = "unknown"
    file_name = "4433-1.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 22:55:02"
  condition:
    hash.sha256(0, filesize) == "d1f8cfd9d854f8594341197ba9e1bba84948824441133c22e2e83ba914f47e59"
}
```

### Sample 47: `759a471d829cf0bc`

| Field | Value |
|---|---|
| SHA-256 | `759a471d829cf0bcd6c0481e0bf63b7030fb9abdb6e974c385f1bf4dcf188211` |
| Family label | `unknown` |
| File name | `dogandcat(1).apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:44:20` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cdee9278cc3325a8169ce898c1b7c25` |
| SHA-1 | `5455df55693fbc13245caca1314bfa2fa0c91a29` |
| SHA-256 | `759a471d829cf0bcd6c0481e0bf63b7030fb9abdb6e974c385f1bf4dcf188211` |
| SHA3-384 | `138a8452408d9892563f18dbbd6dbc7f4ecb9f7a67017fdd97da767d024cc82c94bbdaaaaf4159277b435dc75658e850` |
| TLSH | `T136A45D06EA904E33C4AF127D45A31780373AA949AB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:Oodf9exi7x2lV5RMFs53cogD53Mpd39RCjBH6l1q:OoT7xsvMs5Mzmp+H6m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_759a471d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "759a471d829cf0bcd6c0481e0bf63b7030fb9abdb6e974c385f1bf4dcf188211"
    family = "unknown"
    file_name = "dogandcat(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:20"
  condition:
    hash.sha256(0, filesize) == "759a471d829cf0bcd6c0481e0bf63b7030fb9abdb6e974c385f1bf4dcf188211"
}
```

### Sample 48: `c72d1f2b115b7b08`

| Field | Value |
|---|---|
| SHA-256 | `c72d1f2b115b7b08b92549589d2f628df42cfa3bd398333cde88ac0f7da18c7c` |
| Family label | `unknown` |
| File name | `dogandcat.apk.signed.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:44:14` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96b84b0fb56abf0d1dbdb2dfadfb117e` |
| SHA-1 | `28b4b30375524abb9e2d3b2533d0f0984b3eb69e` |
| SHA-256 | `c72d1f2b115b7b08b92549589d2f628df42cfa3bd398333cde88ac0f7da18c7c` |
| SHA3-384 | `6ba8ee5afd68cee5ba018aa87bff5c1079955a397d42126a9b4f296401001daf4cf6f3224893423a17f13489f58674a3` |
| TLSH | `T109B45D06EA904E33C4AF127D45A31780373AA949AB43834B360DEA787FB33D65B875D5` |
| SSDEEP | `6144:qodf9exi7x2lV5RMFs53cogD53Mpd39RCjB3a5jn74:qoT7xsvMs5Mzmp+3aJ74` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_c72d1f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c72d1f2b115b7b08b92549589d2f628df42cfa3bd398333cde88ac0f7da18c7c"
    family = "unknown"
    file_name = "dogandcat.apk.signed.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:14"
  condition:
    hash.sha256(0, filesize) == "c72d1f2b115b7b08b92549589d2f628df42cfa3bd398333cde88ac0f7da18c7c"
}
```

### Sample 49: `481aeb107b7e44c1`

| Field | Value |
|---|---|
| SHA-256 | `481aeb107b7e44c109ab0aa25ae8f75a41658736f7a6be61f928596da7bdec4a` |
| Family label | `unknown` |
| File name | `dogandcat.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:44:07` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16d83376f88f9c020e59636b0fddc536` |
| SHA-1 | `6085910bafe57e7a1e9532abbb86be2e35dd26c6` |
| SHA-256 | `481aeb107b7e44c109ab0aa25ae8f75a41658736f7a6be61f928596da7bdec4a` |
| SHA3-384 | `2c50e90b8af1f0071ec0d2cfa7d8e27d4753866a8bdc6eb168f640511af3f4be284f44938a13cff5cc860cd7334c8d9b` |
| TLSH | `T1EAA46C06DE904D33C8AE227D45A30390373AA689A743834B260DD6B57F933EB5F876D5` |
| SSDEEP | `6144:modf9exi7x2lV5RMFs53cogD53Mpd39RCjBcMpcq3H:moT7xsvMs5Mzmp+cMpT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_481aeb10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "481aeb107b7e44c109ab0aa25ae8f75a41658736f7a6be61f928596da7bdec4a"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:07"
  condition:
    hash.sha256(0, filesize) == "481aeb107b7e44c109ab0aa25ae8f75a41658736f7a6be61f928596da7bdec4a"
}
```

### Sample 50: `d0ac31d3d1554f8f`

| Field | Value |
|---|---|
| SHA-256 | `d0ac31d3d1554f8f6563df056b83cd23cb7ceb6d1dfd88b40f6001be9c665c49` |
| Family label | `unknown` |
| File name | `dog_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:44:00` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62e5c62d0439f6657f8eb14dbdbba342` |
| SHA-1 | `df19404de1e51a00198dad61f65b1f4b91032e22` |
| SHA-256 | `d0ac31d3d1554f8f6563df056b83cd23cb7ceb6d1dfd88b40f6001be9c665c49` |
| SHA3-384 | `80ee9be6052418661ce4d8c60d50f5bba8915b9528df4eb9a9af835857fcfa944c10caaa5792bb44d81e766e9f1dec5c` |
| TLSH | `T1EEA45C06EA904E33C4AF127D45A31780373AA949AB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:Zodf9exi7x2lV5RMFs53cogD53Mpd39RCjBbxmOg:ZoT7xsvMs5Mzmp+bx6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_d0ac31d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0ac31d3d1554f8f6563df056b83cd23cb7ceb6d1dfd88b40f6001be9c665c49"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:00"
  condition:
    hash.sha256(0, filesize) == "d0ac31d3d1554f8f6563df056b83cd23cb7ceb6d1dfd88b40f6001be9c665c49"
}
```

### Sample 51: `1c6e2a4049892710`

| Field | Value |
|---|---|
| SHA-256 | `1c6e2a40498927104042e739da3c7d0f6de2497376ce01bf39d94173fb368a36` |
| Family label | `unknown` |
| File name | `chiken(1).apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:43:54` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73faf2df92e88c03f4a79ef42a9de36b` |
| SHA-1 | `50238ce23dbba44b8a5f0a4ed94abbef83994d85` |
| SHA-256 | `1c6e2a40498927104042e739da3c7d0f6de2497376ce01bf39d94173fb368a36` |
| SHA3-384 | `fbd3ec930a6e4d14d03a3da6796f3bb139b23f7d4c6ada627a9ca9d97ec06dbaa6e7cb3342d6d9e364eb442920a536c4` |
| TLSH | `T1DC862385E728043FC5B9097249F707312B678E1A49D2B7572988362C9C7B24C5FAEFC9` |
| SSDEEP | `196608:9MgRVhFNpXMy1P+TgHe8uz8GOTeo9JIKStunA1X1L9IUj/+D:9MgnhF38y1PQ87z9JIsMX1L5/s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_1c6e2a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c6e2a40498927104042e739da3c7d0f6de2497376ce01bf39d94173fb368a36"
    family = "unknown"
    file_name = "chiken(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:54"
  condition:
    hash.sha256(0, filesize) == "1c6e2a40498927104042e739da3c7d0f6de2497376ce01bf39d94173fb368a36"
}
```

### Sample 52: `fabb76c9d0df6d71`

| Field | Value |
|---|---|
| SHA-256 | `fabb76c9d0df6d712745755c162e5b533b0a898afed44a2cf10d39822d5d4106` |
| Family label | `unknown` |
| File name | `chiken.apk.signed.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:43:48` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd7232b35a77b9710cb19395547bdf0f` |
| SHA-1 | `e3f2f755335617cd9786110f44f202cee4d641a9` |
| SHA-256 | `fabb76c9d0df6d712745755c162e5b533b0a898afed44a2cf10d39822d5d4106` |
| SHA3-384 | `c738c0cfaad23496969d94c813fc6818eafa4a8ae1c1b73a74bf1a0f139e09e0269e78f93063db628a320cd7a2891ce9` |
| TLSH | `T15D078C06E3069867C5DC973819B647C2F335AE4A6B8783171349F16CEEB3AE6DF54280` |
| SSDEEP | `98304:vxd0yY0X5tR2p/wNrVoodQukgZBW6Di/5vfERSzEYmmmYu9RTqF/UgOdhfaEWyuU:pdZY0JtR2Yo3upvW6G/uRcBUgQ4yu3mJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_fabb76c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fabb76c9d0df6d712745755c162e5b533b0a898afed44a2cf10d39822d5d4106"
    family = "unknown"
    file_name = "chiken.apk.signed.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:48"
  condition:
    hash.sha256(0, filesize) == "fabb76c9d0df6d712745755c162e5b533b0a898afed44a2cf10d39822d5d4106"
}
```

### Sample 53: `c7fa36defaa3be8f`

| Field | Value |
|---|---|
| SHA-256 | `c7fa36defaa3be8ffc4c2a9341fe66a22435a6d6f0f664a9fdfd1d8c217d0525` |
| Family label | `unknown` |
| File name | `chiken.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:43:40` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cf443632492a67d44a7662c435dbcd3` |
| SHA-1 | `c63eb30f0ae3dc50f6dc1fbfd1f17d0b82ce2d7f` |
| SHA-256 | `c7fa36defaa3be8ffc4c2a9341fe66a22435a6d6f0f664a9fdfd1d8c217d0525` |
| SHA3-384 | `3715e497362eaab20d7b0836179e4e1874b346e6adeec669729eb2721068c43d0ce3a58e98b23b917722cad5a06b6ae1` |
| TLSH | `T11E077C06E3069867C5DC973819B647C2F335AE4A6B8783171349F16CEEB3AE6DF54280` |
| SSDEEP | `98304:Rxd0yY0X5tR2p/wNrVuoZQukgZBW6Di/5vrERSzEYmmmYu93Tej/UokDhfSEIkW9:7dZY0JtR2YuhupvW6G/6RcLUok6kW1a6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_c7fa36de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7fa36defaa3be8ffc4c2a9341fe66a22435a6d6f0f664a9fdfd1d8c217d0525"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:40"
  condition:
    hash.sha256(0, filesize) == "c7fa36defaa3be8ffc4c2a9341fe66a22435a6d6f0f664a9fdfd1d8c217d0525"
}
```

### Sample 54: `55426492f381b775`

| Field | Value |
|---|---|
| SHA-256 | `55426492f381b775c3fa0c592435bbe47b26febe27c9988d91ef2c026ecd4927` |
| Family label | `unknown` |
| File name | `chiken_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:43:33` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf7573127e54db3ca93a5706050ad2bf` |
| SHA-1 | `efadbceed5d27a1f29099a15f34d32c5ae95b25a` |
| SHA-256 | `55426492f381b775c3fa0c592435bbe47b26febe27c9988d91ef2c026ecd4927` |
| SHA3-384 | `280a8cf5940668eb13d25eb4fc40ec91c7c54b398d798baee2c0473447a6f6d7b3a4a1080f5152f9319bd05dc3bf0257` |
| TLSH | `T155077C06E3069867C5DC973819B647C2F335AE4A6B8783171349F16CEEB3AE6DF54280` |
| SSDEEP | `98304:Gxd0yY0X5tR2p/wNrVHoZQukgZBW6Di/5vrERSzEYmmmYu93Tej/UokDhfSEIkWV:2dZY0JtR2YHhupvW6G/6RcLUok6kW1aq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_55426492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55426492f381b775c3fa0c592435bbe47b26febe27c9988d91ef2c026ecd4927"
    family = "unknown"
    file_name = "chiken_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:33"
  condition:
    hash.sha256(0, filesize) == "55426492f381b775c3fa0c592435bbe47b26febe27c9988d91ef2c026ecd4927"
}
```

### Sample 55: `2624bcb312523b0a`

| Field | Value |
|---|---|
| SHA-256 | `2624bcb312523b0a47ecf86e0997103e7106c7619878c52a5ea8507b9f8734a4` |
| Family label | `SilentNet` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-01 22:30:33` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d10f4cb2e646ba8757f471fe1fa1b65a` |
| SHA-1 | `6d801aaa85fd6b11b74ff704229e7b43d4967abd` |
| SHA-256 | `2624bcb312523b0a47ecf86e0997103e7106c7619878c52a5ea8507b9f8734a4` |
| SHA3-384 | `f1ead6c7fff009094285fa5f3657e9985db74cb031a11df5c320dd1de7fa725acd6314b4552175d1b3e0ac4bff1261f8` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T13C357C83EBE385D8C156C8B5534BF137F9627C8E4A157196ABC41E633E67B64E22CB00` |
| SSDEEP | `12288:tZ+OE4MmD6/Oyspc5EEBBBHGBgzGerwGEvPqItNquB:tcb4M06WpoPrwfvP3f5` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_055_2624bcb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2624bcb312523b0a47ecf86e0997103e7106c7619878c52a5ea8507b9f8734a4"
    family = "SilentNet"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 22:30:33"
  condition:
    hash.sha256(0, filesize) == "2624bcb312523b0a47ecf86e0997103e7106c7619878c52a5ea8507b9f8734a4"
}
```

### Sample 56: `ad6a776395907df9`

| Field | Value |
|---|---|
| SHA-256 | `ad6a776395907df97ff5214c97220c5a6f11d7e038d9e28180500b14820a771f` |
| Family label | `unknown` |
| File name | `dogandcat.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:18:03` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39ea6b277bf13663fd0c2738b81e599c` |
| SHA-1 | `0c6ebfa14a3f106cc494087b5f32f23e3da23953` |
| SHA-256 | `ad6a776395907df97ff5214c97220c5a6f11d7e038d9e28180500b14820a771f` |
| SHA3-384 | `4dd47a5301bc1995af3e952254960e559307fe18059682094230d4621b30277102e4eab5cf1697490f5a3ea8417c9ebb` |
| TLSH | `T126B45C06EA904E33C4AF127D45A31780373AA949AB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:oodf9exi7x2lV5RMFs53cogD53Mpd39RCjBBR0kb0C:ooT7xsvMs5Mzmp+BRz0C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_ad6a7763
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad6a776395907df97ff5214c97220c5a6f11d7e038d9e28180500b14820a771f"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:18:03"
  condition:
    hash.sha256(0, filesize) == "ad6a776395907df97ff5214c97220c5a6f11d7e038d9e28180500b14820a771f"
}
```

### Sample 57: `cc30bf9361b728c8`

| Field | Value |
|---|---|
| SHA-256 | `cc30bf9361b728c8dfa1ec1810d584b3501bfc100c606976abab77443b1fb216` |
| Family label | `unknown` |
| File name | `dog_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:17:58` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `529b2cd819673e34194411dfd4935090` |
| SHA-1 | `6ef41e9279ff30dbcba237cf7dba3b343c0f4cc1` |
| SHA-256 | `cc30bf9361b728c8dfa1ec1810d584b3501bfc100c606976abab77443b1fb216` |
| SHA3-384 | `59389eb1be0d4a4aa29f881e994d77b5e8f29124762c79daf8d03810d70795d9603ccb4a0cfea07259285d86c703cc96` |
| TLSH | `T1A2A45C06EA904E33C4AE127D45A31780373AA949AB43834B320DEA787FB33D65F975D5` |
| SSDEEP | `6144:fodf9exi7x2lV5RMFs53cogD53Mpd39RCjBDgbPn:foT7xsvMs5Mzmp+DgT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_cc30bf93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc30bf9361b728c8dfa1ec1810d584b3501bfc100c606976abab77443b1fb216"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:17:58"
  condition:
    hash.sha256(0, filesize) == "cc30bf9361b728c8dfa1ec1810d584b3501bfc100c606976abab77443b1fb216"
}
```

### Sample 58: `b0105ccfdc0b7ecd`

| Field | Value |
|---|---|
| SHA-256 | `b0105ccfdc0b7ecd83bce3be22221b3a867b9ec4c6ad06fde568e2f165beb9dc` |
| Family label | `unknown` |
| File name | `chiken.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:17:52` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3960946a4d8e73d1ece6a1556b4e8a48` |
| SHA-1 | `3b84213694f9d2dd2f18b6bfb07028ca90be9385` |
| SHA-256 | `b0105ccfdc0b7ecd83bce3be22221b3a867b9ec4c6ad06fde568e2f165beb9dc` |
| SHA3-384 | `0b06b07635c8422362743ae9a8ad4c928e2ebdeb40c28fe48f88fc78e755a219cbf00e01bc17caf518c7aac6f25a9750` |
| TLSH | `T18EF68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:FptSYw5jF8zChrH/VxcrUoe6D4YVQBQukgZBW6Di/5vYERSzEYmmmYu9XKuP5k51:Fpt4jF8eNYU0tupvW6G/tRc1NJlB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_b0105ccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0105ccfdc0b7ecd83bce3be22221b3a867b9ec4c6ad06fde568e2f165beb9dc"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:17:52"
  condition:
    hash.sha256(0, filesize) == "b0105ccfdc0b7ecd83bce3be22221b3a867b9ec4c6ad06fde568e2f165beb9dc"
}
```

### Sample 59: `2a42612f7974cbeb`

| Field | Value |
|---|---|
| SHA-256 | `2a42612f7974cbeb0d0278a554b94eed6dcecd499d1c36a3362b4439552fb357` |
| Family label | `unknown` |
| File name | `chiken_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:17:39` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d6b7e3f97223a5732d7a27f289dcfa8` |
| SHA-1 | `4af00bdee035181e3c65d493ed978c9f8fc73c6a` |
| SHA-256 | `2a42612f7974cbeb0d0278a554b94eed6dcecd499d1c36a3362b4439552fb357` |
| SHA3-384 | `cd3d46f1fec77f1c2beacf3cae8c7a994b088a795032db8e89b738fc798a2822553393a806a5f757bf67139339461906` |
| TLSH | `T1CBF68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:iptSYw5jF8zChrH/VxcrUoh6D4YVQbQukgZBW6Di/5vEERSzEYmmmYu99muPbwDj:ipt4jF8eNYUfdupvW6G/pRc9XRv5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_2a42612f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a42612f7974cbeb0d0278a554b94eed6dcecd499d1c36a3362b4439552fb357"
    family = "unknown"
    file_name = "chiken_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:17:39"
  condition:
    hash.sha256(0, filesize) == "2a42612f7974cbeb0d0278a554b94eed6dcecd499d1c36a3362b4439552fb357"
}
```

### Sample 60: `9a1f416d44a48db4`

| Field | Value |
|---|---|
| SHA-256 | `9a1f416d44a48db4c4f58ec4743c95d7f8a331b1613f46fba966b41ff688b858` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-01 22:16:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `691917fba1160706c673c8c6ed48426b` |
| SHA-1 | `e0c71b5d6d8d247ae48a746241fa8f5d114cbbac` |
| SHA-256 | `9a1f416d44a48db4c4f58ec4743c95d7f8a331b1613f46fba966b41ff688b858` |
| SHA3-384 | `a9635e7e715f4d64bde94873ab75d87dacc26ee0f9603616ab79f4297040499dfc61e530fe4a795980fb174546214bed` |
| TLSH | `T1F6236C6516857C24AE99C8361C7E2F0CB9AD83E5310452EDBFCB3CF28C4AA9DD11971D` |
| SSDEEP | `768:e+w9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:e+NcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_9a1f416d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a1f416d44a48db4c4f58ec4743c95d7f8a331b1613f46fba966b41ff688b858"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-01 22:16:48"
  condition:
    hash.sha256(0, filesize) == "9a1f416d44a48db4c4f58ec4743c95d7f8a331b1613f46fba966b41ff688b858"
}
```

### Sample 61: `70d9c4b9c40e523e`

| Field | Value |
|---|---|
| SHA-256 | `70d9c4b9c40e523eed7907eda95f7bf997c3979c1111fdd34c2ed998f3f05fa8` |
| Family label | `unknown` |
| File name | `dogandcat.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:11:00` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a387c985d61fd5220087e004627930f7` |
| SHA-1 | `e1d20dd9f7cbf078187c46d1ebfb92e0fd1675b8` |
| SHA-256 | `70d9c4b9c40e523eed7907eda95f7bf997c3979c1111fdd34c2ed998f3f05fa8` |
| SHA3-384 | `fe10ee6df8b75c537fd8f3a2813b7b1d8fdddc27dc268e4f5c205a242729e57109032ccc09f8009161b48e3c7df29cce` |
| TLSH | `T1C6B45D06EA904E33C4AE127D45A31780373AA949EB43834B360DEA787FB33D65B875D5` |
| SSDEEP | `6144:lodf9exi7x2lV5RMFs53cogD53Mpd39RCjBNNUkDX:loT7xsvMs5Mzmp+NNb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_70d9c4b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d9c4b9c40e523eed7907eda95f7bf997c3979c1111fdd34c2ed998f3f05fa8"
    family = "unknown"
    file_name = "dogandcat.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:11:00"
  condition:
    hash.sha256(0, filesize) == "70d9c4b9c40e523eed7907eda95f7bf997c3979c1111fdd34c2ed998f3f05fa8"
}
```

### Sample 62: `9532979ac61ad44b`

| Field | Value |
|---|---|
| SHA-256 | `9532979ac61ad44b90bf0885b1634b685809df93bca37d018e523823095c9e57` |
| Family label | `unknown` |
| File name | `dogandcat.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:10:55` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69cf5499fa3959f092ecd4f1183a7d28` |
| SHA-1 | `b3a897c814cc4179099e3980fa3be110da76c17e` |
| SHA-256 | `9532979ac61ad44b90bf0885b1634b685809df93bca37d018e523823095c9e57` |
| SHA3-384 | `fa28142d0600ca2eb62913b290e29d7c4c796a4d155a054db6bc866ac9ce6c83e21706a74349dfe05edd9f0dc29eb4ea` |
| TLSH | `T189A45C06EA904E33C4AE127D45A31780373AA949EB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:Hodf9exi7x2lV5RMFs53cogD53Mpd39RCjBDvcSH:HoT7xsvMs5Mzmp+Dv7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_9532979a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9532979ac61ad44b90bf0885b1634b685809df93bca37d018e523823095c9e57"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:55"
  condition:
    hash.sha256(0, filesize) == "9532979ac61ad44b90bf0885b1634b685809df93bca37d018e523823095c9e57"
}
```

### Sample 63: `fc7b4423cdd2e36b`

| Field | Value |
|---|---|
| SHA-256 | `fc7b4423cdd2e36ba713e650987336ff5d92268ad130b30384d024337cb86c73` |
| Family label | `unknown` |
| File name | `dog_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:10:49` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bce95b0c58b0938ac56a8e884d91f3ed` |
| SHA-1 | `b1bd10352f2267112a4feb3d70fd784711aa0656` |
| SHA-256 | `fc7b4423cdd2e36ba713e650987336ff5d92268ad130b30384d024337cb86c73` |
| SHA3-384 | `14a176915d5d510800293c4277906a8359e6a043e8b355077584414496f808ffe915c72cc8310481da9865aafe3b45be` |
| TLSH | `T11CA45C06EA904E33C4AE127D45A31780373AA949EB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:wodf9exi7x2lV5RMFs53cogD53Mpd39RCjBnUTxV:woT7xsvMs5Mzmp+nUX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_fc7b4423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc7b4423cdd2e36ba713e650987336ff5d92268ad130b30384d024337cb86c73"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:49"
  condition:
    hash.sha256(0, filesize) == "fc7b4423cdd2e36ba713e650987336ff5d92268ad130b30384d024337cb86c73"
}
```

### Sample 64: `eda53d81661e2dca`

| Field | Value |
|---|---|
| SHA-256 | `eda53d81661e2dcad1a4cc200dece0c4d8b2732b23c9e109317a06e4a752141c` |
| Family label | `unknown` |
| File name | `chiken(1).apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:10:42` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fa0685719b1836a080e773bd99fb4a0` |
| SHA-1 | `e5872efe54b6cdab2ff3ec19ca26873a93ebb08a` |
| SHA-256 | `eda53d81661e2dcad1a4cc200dece0c4d8b2732b23c9e109317a06e4a752141c` |
| SHA3-384 | `8bac9d38f2fcb67b546f780f38372090d62ba0be0d9df6af80e10ac8fe091d984e15e5990a95429705188f75a695a770` |
| TLSH | `T141F68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:5ptSYw5jF8zChrH/VxcrUoe6D4YVQBQukgZBW6Di/5vEERSzEYmmmYu9HumPZExb:5pt4jF8eNYUgdupvW6G/9RcR9plv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_eda53d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda53d81661e2dcad1a4cc200dece0c4d8b2732b23c9e109317a06e4a752141c"
    family = "unknown"
    file_name = "chiken(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:42"
  condition:
    hash.sha256(0, filesize) == "eda53d81661e2dcad1a4cc200dece0c4d8b2732b23c9e109317a06e4a752141c"
}
```

### Sample 65: `d8c0defc4f57bbbf`

| Field | Value |
|---|---|
| SHA-256 | `d8c0defc4f57bbbf9867012b2da45c5e2e8f7358e951889315415d9068a72cb1` |
| Family label | `unknown` |
| File name | `chiken.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:10:28` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4dee8175db73e4641989cf5fe06f97d9` |
| SHA-1 | `1cb3e6f32ae17330dae7072f523103f82c10f62a` |
| SHA-256 | `d8c0defc4f57bbbf9867012b2da45c5e2e8f7358e951889315415d9068a72cb1` |
| SHA3-384 | `609ba3f966b1d14bbc2b415079da252c6804ee8139f7b2d68fa7abba9c784b2d8b812a14cb733c461dbcc0c57ee7a066` |
| TLSH | `T1D6F68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:DptSYw5jF8zChrH/VxcrUoM6D4YVQbQukgZBW6Di/5vEERSzEYmmmYu9ROWP/8Ll:Dpt4jF8eNYUatupvW6G/NRclrV1d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_d8c0defc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8c0defc4f57bbbf9867012b2da45c5e2e8f7358e951889315415d9068a72cb1"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:28"
  condition:
    hash.sha256(0, filesize) == "d8c0defc4f57bbbf9867012b2da45c5e2e8f7358e951889315415d9068a72cb1"
}
```

### Sample 66: `16a11191fa0c9db9`

| Field | Value |
|---|---|
| SHA-256 | `16a11191fa0c9db957c9163d3e6a1dbb3c63dc9edcd5badb92e59d44a64e53c8` |
| Family label | `unknown` |
| File name | `chiken_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-01 22:10:16` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a438b27bba79b288239396b42a85eb1e` |
| SHA-1 | `2db3b3d43f665b3bc0182e800ce4de5b23fa9c00` |
| SHA-256 | `16a11191fa0c9db957c9163d3e6a1dbb3c63dc9edcd5badb92e59d44a64e53c8` |
| SHA3-384 | `7dbbb02f62a92c63d7170a49d112251b9df7582a354c0a3da960dcb110bb3a49b1a2b75471ca6dc43044b2b6e6cf4699` |
| TLSH | `T146F68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:eptSYw5jF8zChrH/VxcrUox6D4YVQbQukgZBW6Di/5vEERSzEYmmmYu9ROWP/8Lp:ept4jF8eNYU7tupvW6G/NRclrV1B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_16a11191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16a11191fa0c9db957c9163d3e6a1dbb3c63dc9edcd5badb92e59d44a64e53c8"
    family = "unknown"
    file_name = "chiken_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:16"
  condition:
    hash.sha256(0, filesize) == "16a11191fa0c9db957c9163d3e6a1dbb3c63dc9edcd5badb92e59d44a64e53c8"
}
```

### Sample 67: `778922930cf94d91`

| Field | Value |
|---|---|
| SHA-256 | `778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273` |
| Family label | `Mirai` |
| File name | `778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273` |
| File type | `sh` |
| First seen | `2026-07-01 22:08:50` |
| Reporter | `Hassan_Pouladi` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78bbe61b2893044ee12b08b204a178fb` |
| SHA-1 | `e62056780e1d6e8ce3d5d36b0fa31e05d99d12a8` |
| SHA-256 | `778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273` |
| SHA3-384 | `3098ba91f08dda83176d5b36adfb031db4e217696c60aa486c9256bd3e5e94e85ed2c06c9f2bf71b077c70b82321b9af` |
| TLSH | `T10F11A58C1091F2D10DD9A6326F81EF391493B6ABFD95692CBB8E036CE6F8DC1301069D` |
| SSDEEP | `12:oIJtCIzJxSJqLviffz5JGA7Lui6Ud4JALhihB9YQJ0HoLziW4D72J0HoLd8iW4Dg:on2sJd8vUinFXOyUOa65O7MM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_77892293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273"
    family = "Mirai"
    file_name = "778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273"
    file_type = "sh"
    first_seen = "2026-07-01 22:08:50"
  condition:
    hash.sha256(0, filesize) == "778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273"
}
```

### Sample 68: `b6c42dd2f522b242`

| Field | Value |
|---|---|
| SHA-256 | `b6c42dd2f522b2424e77443472d6ad4a0710d738ef664d69a0141bb71b1424c3` |
| Family label | `unknown` |
| File name | `dogandcat.apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:55:46` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3b7ea263e6198c2821c0d3be77a83bc` |
| SHA-1 | `f434b1528b307cf1609507beeeec221bff91a0f9` |
| SHA-256 | `b6c42dd2f522b2424e77443472d6ad4a0710d738ef664d69a0141bb71b1424c3` |
| SHA3-384 | `46f9b686c36ee2d73153ab8b80e4cead6fd55b9608cae59461e2c114fdccbf595ec7bdbae742f50b0fc5149a1a0e13c4` |
| TLSH | `T159A46C06DE904D33C8AE227D05A31390373AA689A743834B260DD6B57F933EB5F876D5` |
| SSDEEP | `6144:hodf9exi7x2lV5RMFs53cogD53Mpd39RCjBcMpzq3F:hoT7xsvMs5Mzmp+cMpm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_b6c42dd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6c42dd2f522b2424e77443472d6ad4a0710d738ef664d69a0141bb71b1424c3"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:55:46"
  condition:
    hash.sha256(0, filesize) == "b6c42dd2f522b2424e77443472d6ad4a0710d738ef664d69a0141bb71b1424c3"
}
```

### Sample 69: `88124fa447b804b2`

| Field | Value |
|---|---|
| SHA-256 | `88124fa447b804b2b10358a99f5f08d8450e0893106c99aada7f1fd845cec25f` |
| Family label | `unknown` |
| File name | `chiken(2).apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:55:39` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c184c4d3a7c5632ef26a403d88459d9` |
| SHA-1 | `1f38d836b2ecefc377df25709d6efd3472e8539c` |
| SHA-256 | `88124fa447b804b2b10358a99f5f08d8450e0893106c99aada7f1fd845cec25f` |
| SHA3-384 | `262950442ec7c01b3fcc02bb15d16bd93cbc6ce01d7acb19feb86796e42d95dc19afd9ef7249fe4067b488aeefa589c7` |
| TLSH | `T164F68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:kptSYw5jF8zChrH/VxcrUod6D4YVQsQukgZBW6Di/5vRERSzEYmmmYu9ZswPZbo6:kpt4jF8eNYUnwupvW6G/YRcn1ZmN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_88124fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88124fa447b804b2b10358a99f5f08d8450e0893106c99aada7f1fd845cec25f"
    family = "unknown"
    file_name = "chiken(2).apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:55:39"
  condition:
    hash.sha256(0, filesize) == "88124fa447b804b2b10358a99f5f08d8450e0893106c99aada7f1fd845cec25f"
}
```

### Sample 70: `3a90670af15275d0`

| Field | Value |
|---|---|
| SHA-256 | `3a90670af15275d048191fe41bfcbe63939961364a16de93178eff69ff810834` |
| Family label | `unknown` |
| File name | `chiken.apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:55:23` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1351afbe7586db0c3a455d044531cf02` |
| SHA-1 | `467c300b592546b2b373f1559be6b6e525510ac7` |
| SHA-256 | `3a90670af15275d048191fe41bfcbe63939961364a16de93178eff69ff810834` |
| SHA3-384 | `c525e0d8ec5e8b4bb6f386fbc1911b717c9cef8346fd0fc661c68c920a3f7e82c4ccf9faa5e57dfc04816d02454813e3` |
| TLSH | `T117762386F728013FC5B644724AA6033167678D2A4ED7AB4B2988772C9D7760C0F6EFC5` |
| SSDEEP | `196608:FAQlEJfbk00qJwQk6FWE9JIKXFtunVhDNbf:FAAUkNtQkhE9JIo8V/bf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_3a90670a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a90670af15275d048191fe41bfcbe63939961364a16de93178eff69ff810834"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:55:23"
  condition:
    hash.sha256(0, filesize) == "3a90670af15275d048191fe41bfcbe63939961364a16de93178eff69ff810834"
}
```

### Sample 71: `4427a7140286f25d`

| Field | Value |
|---|---|
| SHA-256 | `4427a7140286f25d16069b06e650a4e904f2e290eed2cf6f647a2d50284f9f20` |
| Family label | `unknown` |
| File name | `4392-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 21:47:45` |
| Reporter | `BastianHein_` |
| Tags | `Dex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df246a68d17e080f000d8d743255ba8e` |
| SHA-256 | `4427a7140286f25d16069b06e650a4e904f2e290eed2cf6f647a2d50284f9f20` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_4427a714
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4427a7140286f25d16069b06e650a4e904f2e290eed2cf6f647a2d50284f9f20"
    family = "unknown"
    file_name = "4392-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 21:47:45"
  condition:
    hash.sha256(0, filesize) == "4427a7140286f25d16069b06e650a4e904f2e290eed2cf6f647a2d50284f9f20"
}
```

### Sample 72: `0ed25bcfc5703d01`

| Field | Value |
|---|---|
| SHA-256 | `0ed25bcfc5703d016338dfe5579a16451fcf28cc3f2ce6f70f06daa77c63a4c6` |
| Family label | `unknown` |
| File name | `payload.apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:43:50` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01ba4eb8f9effd30c8e13c6f8244b285` |
| SHA-1 | `8556f954a57edc8a26e6a369c2901f02ca656c58` |
| SHA-256 | `0ed25bcfc5703d016338dfe5579a16451fcf28cc3f2ce6f70f06daa77c63a4c6` |
| SHA3-384 | `0e7e43eb960ad70a6acbbcd4fd729a8e07f893bc013ea7ad01d19879c0dc4bd7aa76f7d6b98096cd8d0528cdc95c6283` |
| TLSH | `T17586F0C6FBD95C2FD8732475C65A22B1A6125C158B92DFC75A04B218787B2E88F3DBC0` |
| SSDEEP | `196608:bae8uhy4Z05CQ11F3fcBwbCE8BOM3O86QOz/OzXtOJ0:DKQQ93CwASL9z1J0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_0ed25bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ed25bcfc5703d016338dfe5579a16451fcf28cc3f2ce6f70f06daa77c63a4c6"
    family = "unknown"
    file_name = "payload.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:50"
  condition:
    hash.sha256(0, filesize) == "0ed25bcfc5703d016338dfe5579a16451fcf28cc3f2ce6f70f06daa77c63a4c6"
}
```

### Sample 73: `5b5417ce2b0fe3a5`

| Field | Value |
|---|---|
| SHA-256 | `5b5417ce2b0fe3a576b079eae4c43d22f4c4bf2cd907f6f1c47f955eb8eb6aa4` |
| Family label | `unknown` |
| File name | `dogandcat(1).apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:43:35` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a70a6dbf85c9236b503e42f566d4cf7f` |
| SHA-1 | `d9d973ec3cda31bdb6b512389676327f1fd90fe5` |
| SHA-256 | `5b5417ce2b0fe3a576b079eae4c43d22f4c4bf2cd907f6f1c47f955eb8eb6aa4` |
| SHA3-384 | `ff3355ed7e83a1661fc70f1756679f9f26985b9f3da72725ffe352045539b2042d4b667dd0e985bbc70a9ff8f3719519` |
| TLSH | `T1EBA45C06EA904E33C4AF127D45A31780373AA949AB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:codf9exi7x2lV5RMFs53cogD53Mpd39RCjBnoH81:coT7xsvMs5Mzmp+no4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_5b5417ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5417ce2b0fe3a576b079eae4c43d22f4c4bf2cd907f6f1c47f955eb8eb6aa4"
    family = "unknown"
    file_name = "dogandcat(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:35"
  condition:
    hash.sha256(0, filesize) == "5b5417ce2b0fe3a576b079eae4c43d22f4c4bf2cd907f6f1c47f955eb8eb6aa4"
}
```

### Sample 74: `cf9dea7dc62717e4`

| Field | Value |
|---|---|
| SHA-256 | `cf9dea7dc62717e4b239f0595594ec4211252e3d8fad46b1b59061f698801993` |
| Family label | `unknown` |
| File name | `dogandcat.apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:43:29` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42a73d34ac66b8df192973a9edf9cfce` |
| SHA-1 | `c2e1ab09d343fd13d1757087d17596e781b12504` |
| SHA-256 | `cf9dea7dc62717e4b239f0595594ec4211252e3d8fad46b1b59061f698801993` |
| SHA3-384 | `a63a0543ed9f3fbd3d01ba547db481a141bb1e0dca9a8e6418435dbc5c8a7247abece9ef5be3dbae3bda0789e50b7283` |
| TLSH | `T1C5A46C06DE904D33C8AE227D05A31390373AA689A743834B260DD6B57F933EB5F876D5` |
| SSDEEP | `6144:modf9exi7x2lV5RMFs53cogD53Mpd39RCjBcMpcq3n:moT7xsvMs5Mzmp+cMpr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_cf9dea7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf9dea7dc62717e4b239f0595594ec4211252e3d8fad46b1b59061f698801993"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:29"
  condition:
    hash.sha256(0, filesize) == "cf9dea7dc62717e4b239f0595594ec4211252e3d8fad46b1b59061f698801993"
}
```

### Sample 75: `8705c9b738bac607`

| Field | Value |
|---|---|
| SHA-256 | `8705c9b738bac60713fbb93b31f02fff061fcaf42ec26ec62400438fb844bb32` |
| Family label | `unknown` |
| File name | `chiken(1).apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:43:22` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d5b295f47fb79bfebb3a490b3079e4d` |
| SHA-1 | `628dea0a6d6a4f3128a22b4867392c16ef759a5c` |
| SHA-256 | `8705c9b738bac60713fbb93b31f02fff061fcaf42ec26ec62400438fb844bb32` |
| SHA3-384 | `ce3386ffb11f48cccb5ac9a9fad6818e7a9f8ea1c8b0ef6bd6230bd4cb51a804f43204fafd760b5ee771187bf4ec8663` |
| TLSH | `T119F68D0BE302DA26C8DC7B3C29B657C637316E4E9F8343635058FD6D9E726E59B24290` |
| SSDEEP | `98304:kptSYw5jF8zChrH/VxcrUod6D4YVQsQukgZBW6Di/5vRERSzEYmmmYu9Zs5PnAP9:kpt4jF8eNYUnwupvW6G/YRcn41bL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_8705c9b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8705c9b738bac60713fbb93b31f02fff061fcaf42ec26ec62400438fb844bb32"
    family = "unknown"
    file_name = "chiken(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:22"
  condition:
    hash.sha256(0, filesize) == "8705c9b738bac60713fbb93b31f02fff061fcaf42ec26ec62400438fb844bb32"
}
```

### Sample 76: `15cd5bbbdb9e5f98`

| Field | Value |
|---|---|
| SHA-256 | `15cd5bbbdb9e5f980043bcc849a66c8fb77ba4af44dacfdc653e2488622b2408` |
| Family label | `unknown` |
| File name | `chiken.apk` |
| File type | `apk` |
| First seen | `2026-07-01 21:43:05` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2b8c31f78596501d1c08e2088ff0429` |
| SHA-1 | `7337390ec0f9295188b447e405a28f6cf9604036` |
| SHA-256 | `15cd5bbbdb9e5f980043bcc849a66c8fb77ba4af44dacfdc653e2488622b2408` |
| SHA3-384 | `8227076e28de98d6446c536b13bed092242610cb43ffcf6576573f8a5a0283c5648527153c41fb4d29bc4839394d8f54` |
| TLSH | `T127762386F728013FC5B644724AA6033167678D2A4ED7AB4B2988772C9D7760C0F6EFC5` |
| SSDEEP | `196608:UAQlEJfbk00qJNQk6FWE9JIKXFtunVhDNGC:UAAUkNQQkhE9JIo8V/GC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_15cd5bbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15cd5bbbdb9e5f980043bcc849a66c8fb77ba4af44dacfdc653e2488622b2408"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:05"
  condition:
    hash.sha256(0, filesize) == "15cd5bbbdb9e5f980043bcc849a66c8fb77ba4af44dacfdc653e2488622b2408"
}
```

### Sample 77: `5281e44fdd82e2c7`

| Field | Value |
|---|---|
| SHA-256 | `5281e44fdd82e2c79a54b145517bc7295dd14adc10ca69ec6986dcc242394ae9` |
| Family label | `unknown` |
| File name | `4407-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 21:24:16` |
| Reporter | `BastianHein_` |
| Tags | `Dex, herodotus` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d58abed33e3610e8a1aa6ff1c8d379f` |
| SHA-256 | `5281e44fdd82e2c79a54b145517bc7295dd14adc10ca69ec6986dcc242394ae9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_5281e44f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5281e44fdd82e2c79a54b145517bc7295dd14adc10ca69ec6986dcc242394ae9"
    family = "unknown"
    file_name = "4407-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 21:24:16"
  condition:
    hash.sha256(0, filesize) == "5281e44fdd82e2c79a54b145517bc7295dd14adc10ca69ec6986dcc242394ae9"
}
```

### Sample 78: `de4ca2d0a042ca83`

| Field | Value |
|---|---|
| SHA-256 | `de4ca2d0a042ca8338017d349818bcd4263eab9b83490cf9c45a44495c542660` |
| Family label | `ValleyRAT` |
| File name | `点击切换简体中文语言包.exe` |
| File type | `exe` |
| First seen | `2026-07-01 21:22:47` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c24d5ab1277f88518ef769aa4f595d1` |
| SHA-1 | `2d9499306298de7ab631dfa600cc3597685f8068` |
| SHA-256 | `de4ca2d0a042ca8338017d349818bcd4263eab9b83490cf9c45a44495c542660` |
| SHA3-384 | `594ad6176384fce569042fe10fa3d14d23286dd517a16ee344766fed0cfd40cf7706d7dcb7251d5a58cded2b6593177a` |
| IMPHASH | `49ea913537e8846d169d32fce7302ec5` |
| TLSH | `T156958C06B66541FCC09BD278C61A5657E7B17C86172097CF1290BAA62F73BE21F7E320` |
| SSDEEP | `49152:0/7E4O8OBQOH7D1dCKAJg6PwcVPPbL7MyTkX:0AJ9Sgcs` |
| ICON-DHASH | `cca6337171331acc` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_078_de4ca2d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de4ca2d0a042ca8338017d349818bcd4263eab9b83490cf9c45a44495c542660"
    family = "ValleyRAT"
    file_name = "点击切换简体中文语言包.exe"
    file_type = "exe"
    first_seen = "2026-07-01 21:22:47"
  condition:
    hash.sha256(0, filesize) == "de4ca2d0a042ca8338017d349818bcd4263eab9b83490cf9c45a44495c542660"
}
```

### Sample 79: `0e071173b997fd6f`

| Field | Value |
|---|---|
| SHA-256 | `0e071173b997fd6ff92a74b770f133978587d9e3540e114ec9e680b1fe749a0b` |
| Family label | `unknown` |
| File name | `点击此处安装简体中文'.exe` |
| File type | `exe` |
| First seen | `2026-07-01 21:22:16` |
| Reporter | `CNGaoLing` |
| Tags | `exe, KeyLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bff0d401bfb634df88b9e0a534435b43` |
| SHA-1 | `1530ab1f4b0b4f635e2d709b52093cb2a14347bf` |
| SHA-256 | `0e071173b997fd6ff92a74b770f133978587d9e3540e114ec9e680b1fe749a0b` |
| SHA3-384 | `01d9aca0b79ea94046e226f8ca95b996f72dd2c0d6239b890cf1fd125e4a9f4c46854a692b16b55654ea7c0d36aea5ec` |
| IMPHASH | `ec9810074d13d45ed1fc9c6179bc2a2c` |
| TLSH | `T1C4647C1277E080BAE6A207310FF64779A7BEF9945E358A4B73C4DA1D9D32541CB3A321` |
| SSDEEP | `6144:/2lZBsFrLf0ZwhxR23tT8kN57WVyyG54rEWzAPQ0dGJ:/+ZaFrLf0ZwTM3tTHN57AyydrEVo` |
| ICON-DHASH | `71b119dcce576333` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_0e071173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e071173b997fd6ff92a74b770f133978587d9e3540e114ec9e680b1fe749a0b"
    family = "unknown"
    file_name = "点击此处安装简体中文'.exe"
    file_type = "exe"
    first_seen = "2026-07-01 21:22:16"
  condition:
    hash.sha256(0, filesize) == "0e071173b997fd6ff92a74b770f133978587d9e3540e114ec9e680b1fe749a0b"
}
```

### Sample 80: `69525610bf4cd62d`

| Field | Value |
|---|---|
| SHA-256 | `69525610bf4cd62d90ca4e184de6107ac647db5b7d61f534bf48ba7b3a1a877e` |
| Family label | `unknown` |
| File name | `【【点击安装简体中文语言包zh_cn】】.exe` |
| File type | `exe` |
| First seen | `2026-07-01 21:21:46` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gamarue` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `796dddd0386d5813cc9a95b4dc8fc328` |
| SHA-1 | `7590dcf335911cb4253064259d658e0b6eae9003` |
| SHA-256 | `69525610bf4cd62d90ca4e184de6107ac647db5b7d61f534bf48ba7b3a1a877e` |
| SHA3-384 | `3b9522b977b7b296cfb02ab8edbe6aad44a32e973bac6c6aa31ee6671f9c2237c2ab09cb2abe6350b929fbbdde5a3a67` |
| IMPHASH | `a165f62f913e63193e3d31c9bc7f7652` |
| TLSH | `T18715E005AA9182ABF031883455774B42DF7ABC4C67204A937F9C71BB6F3B7506E2D722` |
| SSDEEP | `24576:PCVIntxNI7s5doLPJc/OzDsQAs9qripzwPtfeU:5xNI7s5doLPMfs9qripiGU` |
| ICON-DHASH | `b269cc8e8ecc69b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_69525610
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69525610bf4cd62d90ca4e184de6107ac647db5b7d61f534bf48ba7b3a1a877e"
    family = "unknown"
    file_name = "【【点击安装简体中文语言包zh_cn】】.exe"
    file_type = "exe"
    first_seen = "2026-07-01 21:21:46"
  condition:
    hash.sha256(0, filesize) == "69525610bf4cd62d90ca4e184de6107ac647db5b7d61f534bf48ba7b3a1a877e"
}
```

### Sample 81: `64bb3ef49a6f0d11`

| Field | Value |
|---|---|
| SHA-256 | `64bb3ef49a6f0d11aa926b5af1cd93796af2137e529068859fc15f691c034510` |
| Family label | `Formbook` |
| File name | `Quotation Request.exe` |
| File type | `exe` |
| First seen | `2026-07-01 20:59:30` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e3dd45aaf15c4bc163554aec1f0f287` |
| SHA-1 | `52bbcf346aadd9fb197b07192df37aa59af53452` |
| SHA-256 | `64bb3ef49a6f0d11aa926b5af1cd93796af2137e529068859fc15f691c034510` |
| SHA3-384 | `bd5659c9cc29ae16a0ceece4e365d71abfad0a64f210e3d5f087b96d05e89d79b98294640cfbef59614583d21756e41d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16F25F11A17D85BA4F8BEAB788174095183F1F927E732E71E3DAC50ED5E31B818612723` |
| SSDEEP | `12288:jZHebB5kODVKaZuCgHebdfSWdeGRpQ6s7Ewaz4RH6IspnAzzi:tHefksxDZs5iKMzyn7O` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_081_64bb3ef4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bb3ef49a6f0d11aa926b5af1cd93796af2137e529068859fc15f691c034510"
    family = "Formbook"
    file_name = "Quotation Request.exe"
    file_type = "exe"
    first_seen = "2026-07-01 20:59:30"
  condition:
    hash.sha256(0, filesize) == "64bb3ef49a6f0d11aa926b5af1cd93796af2137e529068859fc15f691c034510"
}
```

### Sample 82: `4b58c020d155e5c3`

| Field | Value |
|---|---|
| SHA-256 | `4b58c020d155e5c31a1a3a48065ce3c4217ffd8352487f87147a605f2488d907` |
| Family label | `unknown` |
| File name | `Game_win1.1.exe` |
| File type | `exe` |
| First seen | `2026-07-01 20:59:06` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0a6537d177ce0349704a5b7cbcb198d` |
| SHA-1 | `87dec6992258fbc174900f10d36701495704bfcb` |
| SHA-256 | `4b58c020d155e5c31a1a3a48065ce3c4217ffd8352487f87147a605f2488d907` |
| SHA3-384 | `229b66d6325da9c6033ed87fd6441c917f04e14619985b6c79a143189fced66ba731418a3e51a382416b39b45cce48f2` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T10008334A019ED2ABDDDD9DFC135598324258C023EDB16C8E2AC7746433E1BC771FAA86` |
| SSDEEP | `1572864:bt9IKPFVDrDPAeU0Vry+p2kMUYzNgFs9FB/z6LR91UlK4jdDmCLEuo7:bUK9V3TDJy+p1MUEgFuB/z6zmU6dDmSs` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_4b58c020
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b58c020d155e5c31a1a3a48065ce3c4217ffd8352487f87147a605f2488d907"
    family = "unknown"
    file_name = "Game_win1.1.exe"
    file_type = "exe"
    first_seen = "2026-07-01 20:59:06"
  condition:
    hash.sha256(0, filesize) == "4b58c020d155e5c31a1a3a48065ce3c4217ffd8352487f87147a605f2488d907"
}
```

### Sample 83: `d5208ee9717fd73b`

| Field | Value |
|---|---|
| SHA-256 | `d5208ee9717fd73b8cbb395805ff2886b34ca7a2cb14c544da8e70ddb6a8ab2e` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-01 20:29:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41087c0d3999acb99135e983d1323173` |
| SHA-1 | `bd9beaa921a716894afae06b2c72a33240794293` |
| SHA-256 | `d5208ee9717fd73b8cbb395805ff2886b34ca7a2cb14c544da8e70ddb6a8ab2e` |
| SHA3-384 | `4165accac1e8e6595c9b3d022cbc99766d3d36a3f327a7533c0b343c82f16c733e70b9e3e50170cf6d1e9295dee46540` |
| TLSH | `T196016FD79601AD10505ADA5D22975190F461C3DF094A4B6C7F9C5E2DFB88918F07AF84` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkalCjF11CXIFCQd9CFVFC4Y0auD:kXCKysE2hi0ziQvZohalILR/Sz97` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_d5208ee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5208ee9717fd73b8cbb395805ff2886b34ca7a2cb14c544da8e70ddb6a8ab2e"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-01 20:29:44"
  condition:
    hash.sha256(0, filesize) == "d5208ee9717fd73b8cbb395805ff2886b34ca7a2cb14c544da8e70ddb6a8ab2e"
}
```

### Sample 84: `be790bd961586ed3`

| Field | Value |
|---|---|
| SHA-256 | `be790bd961586ed3f8461a0fda3e1ea065234e3d927c7fdda24a905813283d7b` |
| Family label | `unknown` |
| File name | `5156-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:21:10` |
| Reporter | `BastianHein_` |
| Tags | `dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `957bc6879c9cc8ff2536417de5289351` |
| SHA-256 | `be790bd961586ed3f8461a0fda3e1ea065234e3d927c7fdda24a905813283d7b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_be790bd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be790bd961586ed3f8461a0fda3e1ea065234e3d927c7fdda24a905813283d7b"
    family = "unknown"
    file_name = "5156-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:21:10"
  condition:
    hash.sha256(0, filesize) == "be790bd961586ed3f8461a0fda3e1ea065234e3d927c7fdda24a905813283d7b"
}
```

### Sample 85: `1c7b037c1a5439d4`

| Field | Value |
|---|---|
| SHA-256 | `1c7b037c1a5439d4ab8ae9b79643a5a12c384491e2aa05dd5ca0a909ee302102` |
| Family label | `unknown` |
| File name | `4256-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:20:59` |
| Reporter | `BastianHein_` |
| Tags | `dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `623838cfe83e1567658742850e49e59e` |
| SHA-256 | `1c7b037c1a5439d4ab8ae9b79643a5a12c384491e2aa05dd5ca0a909ee302102` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_1c7b037c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c7b037c1a5439d4ab8ae9b79643a5a12c384491e2aa05dd5ca0a909ee302102"
    family = "unknown"
    file_name = "4256-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:59"
  condition:
    hash.sha256(0, filesize) == "1c7b037c1a5439d4ab8ae9b79643a5a12c384491e2aa05dd5ca0a909ee302102"
}
```

### Sample 86: `8729d419ca1dc5d2`

| Field | Value |
|---|---|
| SHA-256 | `8729d419ca1dc5d2694da626a91b47fdfba682b57d98e5d1f21c62c99c9ff84d` |
| Family label | `unknown` |
| File name | `4253-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:20:47` |
| Reporter | `BastianHein_` |
| Tags | `dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce0d80ce914e1cfa55ff22c61f1da01f` |
| SHA-256 | `8729d419ca1dc5d2694da626a91b47fdfba682b57d98e5d1f21c62c99c9ff84d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_8729d419
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8729d419ca1dc5d2694da626a91b47fdfba682b57d98e5d1f21c62c99c9ff84d"
    family = "unknown"
    file_name = "4253-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:47"
  condition:
    hash.sha256(0, filesize) == "8729d419ca1dc5d2694da626a91b47fdfba682b57d98e5d1f21c62c99c9ff84d"
}
```

### Sample 87: `7c73095e6b642b64`

| Field | Value |
|---|---|
| SHA-256 | `7c73095e6b642b642efe29aeef1e5de509185937f336fa18a2e291cd06fcfbe7` |
| Family label | `unknown` |
| File name | `4252-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:20:36` |
| Reporter | `BastianHein_` |
| Tags | `dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7dc8e3266b7ef27ce39f890735d2524` |
| SHA-256 | `7c73095e6b642b642efe29aeef1e5de509185937f336fa18a2e291cd06fcfbe7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_7c73095e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c73095e6b642b642efe29aeef1e5de509185937f336fa18a2e291cd06fcfbe7"
    family = "unknown"
    file_name = "4252-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:36"
  condition:
    hash.sha256(0, filesize) == "7c73095e6b642b642efe29aeef1e5de509185937f336fa18a2e291cd06fcfbe7"
}
```

### Sample 88: `26250690ff4335ad`

| Field | Value |
|---|---|
| SHA-256 | `26250690ff4335ad646319c5311b3878d2ba7bb30ff6538dd1ebdc2660f77c01` |
| Family label | `unknown` |
| File name | `4246-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:20:25` |
| Reporter | `BastianHein_` |
| Tags | `dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a4733670bd938b49601a87615d29eb0` |
| SHA-256 | `26250690ff4335ad646319c5311b3878d2ba7bb30ff6538dd1ebdc2660f77c01` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_26250690
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26250690ff4335ad646319c5311b3878d2ba7bb30ff6538dd1ebdc2660f77c01"
    family = "unknown"
    file_name = "4246-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:25"
  condition:
    hash.sha256(0, filesize) == "26250690ff4335ad646319c5311b3878d2ba7bb30ff6538dd1ebdc2660f77c01"
}
```

### Sample 89: `b79dd5b1942cd20a`

| Field | Value |
|---|---|
| SHA-256 | `b79dd5b1942cd20af76e42d6fb8dd093b4711dfd7b10845fc831dd7fa62870cb` |
| Family label | `unknown` |
| File name | `4240-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:20:14` |
| Reporter | `BastianHein_` |
| Tags | `dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75c814ba5d5c3de2138a2bf9b842535c` |
| SHA-256 | `b79dd5b1942cd20af76e42d6fb8dd093b4711dfd7b10845fc831dd7fa62870cb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_b79dd5b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b79dd5b1942cd20af76e42d6fb8dd093b4711dfd7b10845fc831dd7fa62870cb"
    family = "unknown"
    file_name = "4240-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:14"
  condition:
    hash.sha256(0, filesize) == "b79dd5b1942cd20af76e42d6fb8dd093b4711dfd7b10845fc831dd7fa62870cb"
}
```

### Sample 90: `81c8208418452c3b`

| Field | Value |
|---|---|
| SHA-256 | `81c8208418452c3b853578feefd0d1bf5bdef557fc6a007bbfdc52ade20d177e` |
| Family label | `unknown` |
| File name | `4315-1.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 20:02:34` |
| Reporter | `BastianHein_` |
| Tags | `Dex, mirax` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79c1677ed6de6216211b8d4bcd47b0bb` |
| SHA-256 | `81c8208418452c3b853578feefd0d1bf5bdef557fc6a007bbfdc52ade20d177e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_81c82084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81c8208418452c3b853578feefd0d1bf5bdef557fc6a007bbfdc52ade20d177e"
    family = "unknown"
    file_name = "4315-1.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:02:34"
  condition:
    hash.sha256(0, filesize) == "81c8208418452c3b853578feefd0d1bf5bdef557fc6a007bbfdc52ade20d177e"
}
```

### Sample 91: `69f79d97ab5d02af`

| Field | Value |
|---|---|
| SHA-256 | `69f79d97ab5d02af88b2669985d9b7cb26e176081ba0dde4a1c0ea78cf6bdac5` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-01 19:51:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a40ec0412516339256f04e0e174ba2b` |
| SHA-1 | `a6a659e1a321ab78ac85b5197d7e43b56da1d9fc` |
| SHA-256 | `69f79d97ab5d02af88b2669985d9b7cb26e176081ba0dde4a1c0ea78cf6bdac5` |
| SHA3-384 | `60bb50ca0c23355eb78815e3f91784346643516a72f90926d4c43742edd81c02ff1fa01e6599c8f2a564aeb3280c1cc8` |
| TLSH | `T1F6236D6516857C24AE99C8361C7E2F0CB9AD83E5320451EDBFCB3CF68C4AA9CE11971D` |
| SSDEEP | `768:D+W9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:D+TcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_69f79d97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69f79d97ab5d02af88b2669985d9b7cb26e176081ba0dde4a1c0ea78cf6bdac5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-01 19:51:44"
  condition:
    hash.sha256(0, filesize) == "69f79d97ab5d02af88b2669985d9b7cb26e176081ba0dde4a1c0ea78cf6bdac5"
}
```

### Sample 92: `08030523df4e3fbb`

| Field | Value |
|---|---|
| SHA-256 | `08030523df4e3fbb7e9cc42455673d574975d0fb5bc10c551e407354e17716f4` |
| Family label | `unknown` |
| File name | `4563-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 19:50:04` |
| Reporter | `BastianHein_` |
| Tags | `dex, Konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3de6ab7c9017e1c08fae6219a10845c0` |
| SHA-256 | `08030523df4e3fbb7e9cc42455673d574975d0fb5bc10c551e407354e17716f4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_08030523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08030523df4e3fbb7e9cc42455673d574975d0fb5bc10c551e407354e17716f4"
    family = "unknown"
    file_name = "4563-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 19:50:04"
  condition:
    hash.sha256(0, filesize) == "08030523df4e3fbb7e9cc42455673d574975d0fb5bc10c551e407354e17716f4"
}
```

### Sample 93: `44d1d36e93844f0c`

| Field | Value |
|---|---|
| SHA-256 | `44d1d36e93844f0c93e1ebb3232f6130bcf90e2de7b85078bc0f5e0c17016eac` |
| Family label | `unknown` |
| File name | `4373-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 19:49:51` |
| Reporter | `BastianHein_` |
| Tags | `Dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbc7fc7dca22a58acc75694070e2b537` |
| SHA-256 | `44d1d36e93844f0c93e1ebb3232f6130bcf90e2de7b85078bc0f5e0c17016eac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_44d1d36e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44d1d36e93844f0c93e1ebb3232f6130bcf90e2de7b85078bc0f5e0c17016eac"
    family = "unknown"
    file_name = "4373-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 19:49:51"
  condition:
    hash.sha256(0, filesize) == "44d1d36e93844f0c93e1ebb3232f6130bcf90e2de7b85078bc0f5e0c17016eac"
}
```

### Sample 94: `efbf94416ae8cc4b`

| Field | Value |
|---|---|
| SHA-256 | `efbf94416ae8cc4b7569679c9d5f3af3cc9e270e9010702dc798fba216ce61dc` |
| Family label | `unknown` |
| File name | `4320-0.dex` |
| File type | `unknown` |
| First seen | `2026-07-01 19:49:36` |
| Reporter | `BastianHein_` |
| Tags | `Dex, konfety` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67c3fbde092e8669e10581c549242530` |
| SHA-256 | `efbf94416ae8cc4b7569679c9d5f3af3cc9e270e9010702dc798fba216ce61dc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_efbf9441
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efbf94416ae8cc4b7569679c9d5f3af3cc9e270e9010702dc798fba216ce61dc"
    family = "unknown"
    file_name = "4320-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 19:49:36"
  condition:
    hash.sha256(0, filesize) == "efbf94416ae8cc4b7569679c9d5f3af3cc9e270e9010702dc798fba216ce61dc"
}
```

### Sample 95: `d85e8b60d7fdb801`

| Field | Value |
|---|---|
| SHA-256 | `d85e8b60d7fdb80139ec7551f85ec86d31889407a8ded9e161d12a6499f8fc89` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-01 19:47:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1419c230060428c72ea4b6a3bf8c3627` |
| SHA-1 | `9b345dcd4d73c561ce22fed4b4813f3d75176406` |
| SHA-256 | `d85e8b60d7fdb80139ec7551f85ec86d31889407a8ded9e161d12a6499f8fc89` |
| SHA3-384 | `f688b81cbe493a14afe1fa8d728efff94cbd484ef666e22b6351972bd785bbd3b1d6388a5147a8206fdc8f821b8576c8` |
| TLSH | `T1810148D98414AD0084AAE66D22DB5594F410D3CF154A8B65FF6C6D2DEB84914F07AFC8` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaNlgTJiKFC8vjcf3X:e9Qp+MsNOTjFC8Yf3X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_d85e8b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d85e8b60d7fdb80139ec7551f85ec86d31889407a8ded9e161d12a6499f8fc89"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-01 19:47:43"
  condition:
    hash.sha256(0, filesize) == "d85e8b60d7fdb80139ec7551f85ec86d31889407a8ded9e161d12a6499f8fc89"
}
```

### Sample 96: `101cca11ddad5036`

| Field | Value |
|---|---|
| SHA-256 | `101cca11ddad5036ce8675a024e763f1123fda5ebcc063145c2bff4cda990ef9` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-07-01 19:20:00` |
| Reporter | `Kejult` |
| Tags | `dll, exe, remus, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88d452b8f9bd13c2a37f19f9ee0f64db` |
| SHA-1 | `4e22c94fe8331af19ca98f7ecaccd5d678f751da` |
| SHA-256 | `101cca11ddad5036ce8675a024e763f1123fda5ebcc063145c2bff4cda990ef9` |
| SHA3-384 | `75148922f0ab951a94ede70067721494ab9e8996f649ad5c5200a2abe3864bce744045319f5d78749f1aee321c202c41` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T1D7D56B07AD9249B5D495A33288AB53513B3CFC444B7237C71ED0B63A2FB2BD29936B44` |
| SSDEEP | `49152:ERiWgoImYoPgeACPOkd97naupeqkaN1J+px2PmqMkx8/K/4ZxrB:ERwmPL97akeqkaN1J+pxdNkx8PZxrB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_101cca11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "101cca11ddad5036ce8675a024e763f1123fda5ebcc063145c2bff4cda990ef9"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-01 19:20:00"
  condition:
    hash.sha256(0, filesize) == "101cca11ddad5036ce8675a024e763f1123fda5ebcc063145c2bff4cda990ef9"
}
```

### Sample 97: `b9505282931ce703`

| Field | Value |
|---|---|
| SHA-256 | `b9505282931ce70307a14689daf7767ba1124113c24c7e174499bb5331351a5e` |
| Family label | `unknown` |
| File name | `install-1.5.exe` |
| File type | `exe` |
| First seen | `2026-07-01 19:13:02` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5e2e6b8c0000408bac3946589ec5562` |
| SHA-1 | `e242f6507a82d5d089064e52f17cac1180b0d67c` |
| SHA-256 | `b9505282931ce70307a14689daf7767ba1124113c24c7e174499bb5331351a5e` |
| SHA3-384 | `37f61ad3a55f7fe03eab06e7d63d109206d6439974d9ae22c901a5a55708200321a7e04661d4826f0478d12ecfe3d125` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T145D58C0B6C9149E9C89A673289B652527B34FC410F3223E72E80B7783FB2BE15D76754` |
| SSDEEP | `49152:T/FY3mazHS52iV2o2Pu1Rn/JD8Ydy025i:T/oUf2PuzJD8qyDY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_b9505282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9505282931ce70307a14689daf7767ba1124113c24c7e174499bb5331351a5e"
    family = "unknown"
    file_name = "install-1.5.exe"
    file_type = "exe"
    first_seen = "2026-07-01 19:13:02"
  condition:
    hash.sha256(0, filesize) == "b9505282931ce70307a14689daf7767ba1124113c24c7e174499bb5331351a5e"
}
```

### Sample 98: `cb7d113f74a978a4`

| Field | Value |
|---|---|
| SHA-256 | `cb7d113f74a978a48ae16a41abc11697436ac6f0f858138eaa94fea4b25e9f4d` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-07-01 19:08:35` |
| Reporter | `Kejult` |
| Tags | `dll, exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46f0ea14d4abc27eabd05e48f14cb2cd` |
| SHA-1 | `e938b03b39a314bc1f7b44bd62ddc0e0ef3e1966` |
| SHA-256 | `cb7d113f74a978a48ae16a41abc11697436ac6f0f858138eaa94fea4b25e9f4d` |
| SHA3-384 | `970ab9e92d5194a0bc32b283153cfdab338a0939fb3a3db2efb7347dd6e2ae4b1ddb199bdbb2268dcdf54af931047101` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T16906AE07BCE044B6C8A9633648B741507B39B84B4B363BE72E50B2792F7A7D09E79744` |
| SSDEEP | `49152:KLoYNNd3XyuPcufx/VHZaJARJOLpyP3+BTsf5n0YO5smx/s:KLxHUgt5qwPFJPO59xE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_cb7d113f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb7d113f74a978a48ae16a41abc11697436ac6f0f858138eaa94fea4b25e9f4d"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-01 19:08:35"
  condition:
    hash.sha256(0, filesize) == "cb7d113f74a978a48ae16a41abc11697436ac6f0f858138eaa94fea4b25e9f4d"
}
```

### Sample 99: `bf17415182653889`

| Field | Value |
|---|---|
| SHA-256 | `bf1741518265388933600614e165d73237c44dcd6b2d9dcde7cd2bb3ea177b42` |
| Family label | `unknown` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-07-01 19:06:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f619f2a1852861cce566d6539d49907` |
| SHA-1 | `e52460032d082b5b99270ec7d7aff98d88e3b814` |
| SHA-256 | `bf1741518265388933600614e165d73237c44dcd6b2d9dcde7cd2bb3ea177b42` |
| SHA3-384 | `896084e7f592af83dfd30d9586a57424f30d48cc80650bf0d4e0a688047a2c92d5b201dfe6fa7b0714d7f121bca064ac` |
| TLSH | `T193D02240F1503F387BF40905848AE8D0FA070FF4CE1D13B0308A84A3B0E910CE0B6E10` |
| SSDEEP | `6:H6s9USMA63xQ2BWuar1HylKNh2w5afaD0v0O+:as9LB6BFUClYE8AM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_bf174151
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf1741518265388933600614e165d73237c44dcd6b2d9dcde7cd2bb3ea177b42"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-01 19:06:44"
  condition:
    hash.sha256(0, filesize) == "bf1741518265388933600614e165d73237c44dcd6b2d9dcde7cd2bb3ea177b42"
}
```

### Sample 100: `15bd2334d11f0058`

| Field | Value |
|---|---|
| SHA-256 | `15bd2334d11f0058a578ea871b87637a8f918a39755b43976ba2d14c2fdb79c7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-01 18:59:24` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26a6effd566f47815c6900b6aae2ca22` |
| SHA-1 | `e618398fde004ece90f65697c0e8ad7032fbca7d` |
| SHA-256 | `15bd2334d11f0058a578ea871b87637a8f918a39755b43976ba2d14c2fdb79c7` |
| SHA3-384 | `251d403e50aad2f364cda0f26dc0229024bbb63c9deb4f6340391175876304991e9fc44755bb7940dbdc398465233583` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E6D58C0B6CD048EAE45AA73689B751827B74BC054F3263E72E80B3783E727D25D36B54` |
| SSDEEP | `49152:XNtle7iyqlOBuCb+iN555FN6UORrMjZxdK5A:XNOyEn76U338m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_15bd2334
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15bd2334d11f0058a578ea871b87637a8f918a39755b43976ba2d14c2fdb79c7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 18:59:24"
  condition:
    hash.sha256(0, filesize) == "15bd2334d11f0058a578ea871b87637a8f918a39755b43976ba2d14c2fdb79c7"
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
 * Generated: 2026-07-02T04:33:29.022497+00:00
 */

rule MalwareBazaar_unknown_001_e6c5297e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6c5297e3631002646b7aca0aeaf880309e6d9213312ca63ac611554abe4f0bd"
    family = "unknown"
    file_name = "libtcmalloc_minimal.dll"
    file_type = "dll"
    first_seen = "2026-07-02 04:33:02"
  condition:
    hash.sha256(0, filesize) == "e6c5297e3631002646b7aca0aeaf880309e6d9213312ca63ac611554abe4f0bd"
}

rule MalwareBazaar_Mirai_002_54166148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54166148dad002881957d42c2b793285bf6534a60c1c6becc1da218b1e5d31ac"
    family = "Mirai"
    file_name = "vcimanagement.ppc"
    file_type = "elf"
    first_seen = "2026-07-02 04:31:11"
  condition:
    hash.sha256(0, filesize) == "54166148dad002881957d42c2b793285bf6534a60c1c6becc1da218b1e5d31ac"
}

rule MalwareBazaar_unknown_003_19fcb087
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fcb0877dd3375c036c5f3093bf1960d75710de97958cff8ad8a14f63ab9369"
    family = "unknown"
    file_name = "vcimanagement.arm5"
    file_type = "elf"
    first_seen = "2026-07-02 04:31:09"
  condition:
    hash.sha256(0, filesize) == "19fcb0877dd3375c036c5f3093bf1960d75710de97958cff8ad8a14f63ab9369"
}

rule MalwareBazaar_Mirai_004_c80a916d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c80a916d945db5fc67e2b566eeb1910c1be2ececd0434cd6dedcf1da9a17f921"
    family = "Mirai"
    file_name = "vcimanagement.arm7"
    file_type = "elf"
    first_seen = "2026-07-02 04:31:07"
  condition:
    hash.sha256(0, filesize) == "c80a916d945db5fc67e2b566eeb1910c1be2ececd0434cd6dedcf1da9a17f921"
}

rule MalwareBazaar_Mirai_005_01467634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01467634dee8365d372e015ba94b8998d9ea0aceb2831092ca55bbbe5796cb39"
    family = "Mirai"
    file_name = "vcimanagement.mips"
    file_type = "elf"
    first_seen = "2026-07-02 04:30:05"
  condition:
    hash.sha256(0, filesize) == "01467634dee8365d372e015ba94b8998d9ea0aceb2831092ca55bbbe5796cb39"
}

rule MalwareBazaar_unknown_006_96bbe280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96bbe280b9b8bcace06dacb11ecc83f9f94c6e74d301d2e02e00ccf33179fb76"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-02 04:30:03"
  condition:
    hash.sha256(0, filesize) == "96bbe280b9b8bcace06dacb11ecc83f9f94c6e74d301d2e02e00ccf33179fb76"
}

rule MalwareBazaar_Mirai_007_ba1b8d49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba1b8d49b09ae2635326a9995e5dbaf10cef2dfed2c53de0ecc271c5a1089581"
    family = "Mirai"
    file_name = "vcimanagement.mpsl"
    file_type = "elf"
    first_seen = "2026-07-02 04:30:02"
  condition:
    hash.sha256(0, filesize) == "ba1b8d49b09ae2635326a9995e5dbaf10cef2dfed2c53de0ecc271c5a1089581"
}

rule MalwareBazaar_Mirai_008_5a4f83d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a4f83d9146cf4afc6eccab55e67b464d76ec6ec5343df55a5f98e59b57b8503"
    family = "Mirai"
    file_name = "vcimanagement.arm"
    file_type = "elf"
    first_seen = "2026-07-02 04:30:00"
  condition:
    hash.sha256(0, filesize) == "5a4f83d9146cf4afc6eccab55e67b464d76ec6ec5343df55a5f98e59b57b8503"
}

rule MalwareBazaar_unknown_009_99381421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9938142110657a6e02605d6da7466d06fa28767c20fd237b92b1e04c003a0380"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-02 04:29:59"
  condition:
    hash.sha256(0, filesize) == "9938142110657a6e02605d6da7466d06fa28767c20fd237b92b1e04c003a0380"
}

rule MalwareBazaar_Mirai_010_f5344149
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5344149c1197d65c74f5594fd9e569b34605cd10e7e3cd5bc5ee17f003c2e66"
    family = "Mirai"
    file_name = "vcimanagement.spc"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:58"
  condition:
    hash.sha256(0, filesize) == "f5344149c1197d65c74f5594fd9e569b34605cd10e7e3cd5bc5ee17f003c2e66"
}

rule MalwareBazaar_Mirai_011_9f041770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f04177030da8125b2a23b471e5027c4ad48bded9f7ff64733051a8ad7f2a6e3"
    family = "Mirai"
    file_name = "vcimanagement.m68k"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:57"
  condition:
    hash.sha256(0, filesize) == "9f04177030da8125b2a23b471e5027c4ad48bded9f7ff64733051a8ad7f2a6e3"
}

rule MalwareBazaar_Mirai_012_1214d108
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1214d108e59c54c3f6f548ccdeab6be49ffbf71b68957834878282686e745e96"
    family = "Mirai"
    file_name = "vcimanagement.sh4"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:56"
  condition:
    hash.sha256(0, filesize) == "1214d108e59c54c3f6f548ccdeab6be49ffbf71b68957834878282686e745e96"
}

rule MalwareBazaar_Mirai_013_f2fb50c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2fb50c771143507eeb3a5753bab53a8c87c4dbefe35adfa65dfb1a98e1c7639"
    family = "Mirai"
    file_name = "vcimanagement.x86"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:54"
  condition:
    hash.sha256(0, filesize) == "f2fb50c771143507eeb3a5753bab53a8c87c4dbefe35adfa65dfb1a98e1c7639"
}

rule MalwareBazaar_Mirai_014_60cbc151
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60cbc151ef10a9e7309638ea2d90c7da8a72af4c590308bca61f08243b64715f"
    family = "Mirai"
    file_name = "vcimanagement.arm6"
    file_type = "elf"
    first_seen = "2026-07-02 04:29:53"
  condition:
    hash.sha256(0, filesize) == "60cbc151ef10a9e7309638ea2d90c7da8a72af4c590308bca61f08243b64715f"
}

rule MalwareBazaar_unknown_015_998c6056
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998c6056363bdd5ae5f299f06ec37d7a2e4a3807366a48fbc84de821cd6ba52b"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-02 04:29:52"
  condition:
    hash.sha256(0, filesize) == "998c6056363bdd5ae5f299f06ec37d7a2e4a3807366a48fbc84de821cd6ba52b"
}

rule MalwareBazaar_unknown_016_614b2ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "614b2ac37b407b9a136255fa9709ed1fcfa8aa0b82b5a6065753a8eeddd111da"
    family = "unknown"
    file_name = "樱桃播放器.zip"
    file_type = "zip"
    first_seen = "2026-07-02 04:26:32"
  condition:
    hash.sha256(0, filesize) == "614b2ac37b407b9a136255fa9709ed1fcfa8aa0b82b5a6065753a8eeddd111da"
}

rule MalwareBazaar_unknown_017_14dbfd96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14dbfd961231b155965c48b3ab75c1ad551bca63ae686ec4a903e30249fa578f"
    family = "unknown"
    file_name = "ipmiv2.xml"
    file_type = "unknown"
    first_seen = "2026-07-02 03:51:51"
  condition:
    hash.sha256(0, filesize) == "14dbfd961231b155965c48b3ab75c1ad551bca63ae686ec4a903e30249fa578f"
}

rule MalwareBazaar_unknown_018_48f8f930
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f8f9303da8baab31e347d8f5686fe4b13a3a34af9e34395a2b61f27fd0c2bd"
    family = "unknown"
    file_name = "PB 2400.JS"
    file_type = "js"
    first_seen = "2026-07-02 02:47:24"
  condition:
    hash.sha256(0, filesize) == "48f8f9303da8baab31e347d8f5686fe4b13a3a34af9e34395a2b61f27fd0c2bd"
}

rule MalwareBazaar_AsyncRAT_019_40f84ae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f84ae721a13a383e13d18ba0d4cd120db5fe61fae4eefc117347fa6d1a4352"
    family = "AsyncRAT"
    file_name = "SGH09876545678XW.js"
    file_type = "js"
    first_seen = "2026-07-02 02:47:06"
  condition:
    hash.sha256(0, filesize) == "40f84ae721a13a383e13d18ba0d4cd120db5fe61fae4eefc117347fa6d1a4352"
}

rule MalwareBazaar_unknown_020_ebe4bd44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebe4bd445397393fb554db6554fb37afd31d0a30d309df8194901104027c52cd"
    family = "unknown"
    file_name = "Order_Specification.js"
    file_type = "js"
    first_seen = "2026-07-02 02:46:47"
  condition:
    hash.sha256(0, filesize) == "ebe4bd445397393fb554db6554fb37afd31d0a30d309df8194901104027c52cd"
}

rule MalwareBazaar_unknown_021_8c51a2cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c51a2cf33720cd5afa5739816bd52b0dd2ce2a2f27601ea6b3672da0de5c98d"
    family = "unknown"
    file_name = "f"
    file_type = "unknown"
    first_seen = "2026-07-02 02:30:57"
  condition:
    hash.sha256(0, filesize) == "8c51a2cf33720cd5afa5739816bd52b0dd2ce2a2f27601ea6b3672da0de5c98d"
}

rule MalwareBazaar_unknown_022_67eaa2a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67eaa2a0b90bec27372402195301867fae5fcb063dc006b13cc654ea2b74dbd5"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-02 02:10:51"
  condition:
    hash.sha256(0, filesize) == "67eaa2a0b90bec27372402195301867fae5fcb063dc006b13cc654ea2b74dbd5"
}

rule MalwareBazaar_unknown_023_6d08e6b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d08e6b1345dad62816b4612f92b0689eb937339ef04480ffe02bf58a28e8a70"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-02 01:52:50"
  condition:
    hash.sha256(0, filesize) == "6d08e6b1345dad62816b4612f92b0689eb937339ef04480ffe02bf58a28e8a70"
}

rule MalwareBazaar_unknown_024_fdaac019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdaac01917b2641163f593fccb03f51db0aa368e4acb1d955d8747c5a93faadc"
    family = "unknown"
    file_name = "iran.powerpc"
    file_type = "elf"
    first_seen = "2026-07-02 01:51:48"
  condition:
    hash.sha256(0, filesize) == "fdaac01917b2641163f593fccb03f51db0aa368e4acb1d955d8747c5a93faadc"
}

rule MalwareBazaar_Gafgyt_025_3d68bc2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d68bc2eccba098b2a5d8c641a14c50a15663e0fc268d4f98141f617d68f143f"
    family = "Gafgyt"
    file_name = "a-r.m-6.Sakura"
    file_type = "elf"
    first_seen = "2026-07-02 01:48:12"
  condition:
    hash.sha256(0, filesize) == "3d68bc2eccba098b2a5d8c641a14c50a15663e0fc268d4f98141f617d68f143f"
}

rule MalwareBazaar_unknown_026_c99b5c82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c99b5c82486be6bf6e9e018e5f2bdcbdfd922c075c1fac3923bbcdf8e4bec9c8"
    family = "unknown"
    file_name = "iran.sh4"
    file_type = "elf"
    first_seen = "2026-07-02 01:29:47"
  condition:
    hash.sha256(0, filesize) == "c99b5c82486be6bf6e9e018e5f2bdcbdfd922c075c1fac3923bbcdf8e4bec9c8"
}

rule MalwareBazaar_unknown_027_d53dd27e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d53dd27e40da9a3c793da32c0bdde83c54e5da81dc9c6cf2d4f1886b93a25560"
    family = "unknown"
    file_name = "smp.jar"
    file_type = "jar"
    first_seen = "2026-07-02 01:22:10"
  condition:
    hash.sha256(0, filesize) == "d53dd27e40da9a3c793da32c0bdde83c54e5da81dc9c6cf2d4f1886b93a25560"
}

rule MalwareBazaar_unknown_028_5af8303a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5af8303a76db5feaac150cc350392fb8e2582c27adbdf59566528b741c14e3f3"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-07-02 01:20:51"
  condition:
    hash.sha256(0, filesize) == "5af8303a76db5feaac150cc350392fb8e2582c27adbdf59566528b741c14e3f3"
}

rule MalwareBazaar_Mirai_029_15b04c03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15b04c03fae4a70bb8b9b14d91c156c76d163d5198fff67bab554e6f15b7385a"
    family = "Mirai"
    file_name = "iran.armv4l"
    file_type = "elf"
    first_seen = "2026-07-02 01:06:51"
  condition:
    hash.sha256(0, filesize) == "15b04c03fae4a70bb8b9b14d91c156c76d163d5198fff67bab554e6f15b7385a"
}

rule MalwareBazaar_unknown_030_a97f4444
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a97f44445fd3a18c35cc268d6e4f89673d460714406a9776f7c39060b2827f02"
    family = "unknown"
    file_name = "iran.x86_64"
    file_type = "elf"
    first_seen = "2026-07-02 01:02:40"
  condition:
    hash.sha256(0, filesize) == "a97f44445fd3a18c35cc268d6e4f89673d460714406a9776f7c39060b2827f02"
}

rule MalwareBazaar_unknown_031_d61cab68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183"
    family = "unknown"
    file_name = "d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183"
    file_type = "elf"
    first_seen = "2026-07-02 01:01:58"
  condition:
    hash.sha256(0, filesize) == "d61cab6815d2c50228abc96e326158089f485b8a393994dbc97ca9040e1b2183"
}

rule MalwareBazaar_unknown_032_45ddea6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31"
    family = "unknown"
    file_name = "45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31"
    file_type = "elf"
    first_seen = "2026-07-02 01:01:51"
  condition:
    hash.sha256(0, filesize) == "45ddea6f511d08f73e89d515052378cab0099a5a327468f40d6f1da7ffd03c31"
}

rule MalwareBazaar_unknown_033_2dd2d2e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd2d2e4b0caad0ee13ce14277b88ac1d1585b7ba1ed627d853f05ca9b171c66"
    family = "unknown"
    file_name = "iran.x86_64"
    file_type = "elf"
    first_seen = "2026-07-02 01:01:49"
  condition:
    hash.sha256(0, filesize) == "2dd2d2e4b0caad0ee13ce14277b88ac1d1585b7ba1ed627d853f05ca9b171c66"
}

rule MalwareBazaar_Mirai_034_1a0342c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a0342c1c562ff1527627192d8ea3be9aedde4b47c5436d5f2bcb924d9725397"
    family = "Mirai"
    file_name = "iran.armv7l"
    file_type = "elf"
    first_seen = "2026-07-02 00:49:47"
  condition:
    hash.sha256(0, filesize) == "1a0342c1c562ff1527627192d8ea3be9aedde4b47c5436d5f2bcb924d9725397"
}

rule MalwareBazaar_unknown_035_463c8c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "463c8c98e977e279732093f73ded0f41d292a83d08c35609d544b90bcc195a8b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-02 00:42:48"
  condition:
    hash.sha256(0, filesize) == "463c8c98e977e279732093f73ded0f41d292a83d08c35609d544b90bcc195a8b"
}

rule MalwareBazaar_Mirai_036_e36fb6c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e36fb6c05e5136959ba0a1feb19185da2b242f808d4d1fd26d9b6664a1eaf65f"
    family = "Mirai"
    file_name = "iran.armv6l"
    file_type = "elf"
    first_seen = "2026-07-02 00:38:46"
  condition:
    hash.sha256(0, filesize) == "e36fb6c05e5136959ba0a1feb19185da2b242f808d4d1fd26d9b6664a1eaf65f"
}

rule MalwareBazaar_unknown_037_23dbb81b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23dbb81b2e1004427f908dca6fced8e08115fb42f6928c4a639144636387dde5"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-02 00:33:46"
  condition:
    hash.sha256(0, filesize) == "23dbb81b2e1004427f908dca6fced8e08115fb42f6928c4a639144636387dde5"
}

rule MalwareBazaar_unknown_038_ad0a8700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad0a8700ca705ec2d71c7951a3e4cad8b84b0a03b361d8f05dfed7b77ffce8ea"
    family = "unknown"
    file_name = "iran.mipsel"
    file_type = "elf"
    first_seen = "2026-07-02 00:29:46"
  condition:
    hash.sha256(0, filesize) == "ad0a8700ca705ec2d71c7951a3e4cad8b84b0a03b361d8f05dfed7b77ffce8ea"
}

rule MalwareBazaar_Mirai_039_c359082d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c359082d3c646c95de08998999807e3d21cf9f8b8d5a67f871836b45845232b7"
    family = "Mirai"
    file_name = "iran.aarch64"
    file_type = "elf"
    first_seen = "2026-07-02 00:28:47"
  condition:
    hash.sha256(0, filesize) == "c359082d3c646c95de08998999807e3d21cf9f8b8d5a67f871836b45845232b7"
}

rule MalwareBazaar_unknown_040_d463b63b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d463b63b43f0e7ee43373c74490c11877a925084bac04240e2ae4305b16cfe3e"
    family = "unknown"
    file_name = "iran.m68k"
    file_type = "elf"
    first_seen = "2026-07-02 00:27:46"
  condition:
    hash.sha256(0, filesize) == "d463b63b43f0e7ee43373c74490c11877a925084bac04240e2ae4305b16cfe3e"
}

rule MalwareBazaar_unknown_041_871e5390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "871e5390aa140633638e9a377ed9c3bb38adbe51152bd363d809716aa581cd47"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-02 00:25:50"
  condition:
    hash.sha256(0, filesize) == "871e5390aa140633638e9a377ed9c3bb38adbe51152bd363d809716aa581cd47"
}

rule MalwareBazaar_unknown_042_90ff88ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90ff88acf500948127dd71befff24024fa531f59154f788b4640e2b396e5cb30"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-07-02 00:10:48"
  condition:
    hash.sha256(0, filesize) == "90ff88acf500948127dd71befff24024fa531f59154f788b4640e2b396e5cb30"
}

rule MalwareBazaar_unknown_043_3155a4b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3155a4b8a3f92e2947f88970a4d9f6a0c47fa66c93a1f5c7c8b8cabe93f6acf6"
    family = "unknown"
    file_name = "sweetclient.jar"
    file_type = "jar"
    first_seen = "2026-07-01 23:58:23"
  condition:
    hash.sha256(0, filesize) == "3155a4b8a3f92e2947f88970a4d9f6a0c47fa66c93a1f5c7c8b8cabe93f6acf6"
}

rule MalwareBazaar_unknown_044_b982d303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb"
    family = "unknown"
    file_name = "b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb"
    file_type = "elf"
    first_seen = "2026-07-01 23:22:48"
  condition:
    hash.sha256(0, filesize) == "b982d3035533c2fbfb1e4fda2e45fc5f40c3274d5132dd52f5d414bfa3f170eb"
}

rule MalwareBazaar_Prometei_045_c6ba287f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4"
    family = "Prometei"
    file_name = "c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4"
    file_type = "elf"
    first_seen = "2026-07-01 23:00:39"
  condition:
    hash.sha256(0, filesize) == "c6ba287f87ac35501b8e3f73a8c139309a2a0843508c979549c2519caf10f3d4"
}

rule MalwareBazaar_unknown_046_d1f8cfd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1f8cfd9d854f8594341197ba9e1bba84948824441133c22e2e83ba914f47e59"
    family = "unknown"
    file_name = "4433-1.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 22:55:02"
  condition:
    hash.sha256(0, filesize) == "d1f8cfd9d854f8594341197ba9e1bba84948824441133c22e2e83ba914f47e59"
}

rule MalwareBazaar_unknown_047_759a471d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "759a471d829cf0bcd6c0481e0bf63b7030fb9abdb6e974c385f1bf4dcf188211"
    family = "unknown"
    file_name = "dogandcat(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:20"
  condition:
    hash.sha256(0, filesize) == "759a471d829cf0bcd6c0481e0bf63b7030fb9abdb6e974c385f1bf4dcf188211"
}

rule MalwareBazaar_unknown_048_c72d1f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c72d1f2b115b7b08b92549589d2f628df42cfa3bd398333cde88ac0f7da18c7c"
    family = "unknown"
    file_name = "dogandcat.apk.signed.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:14"
  condition:
    hash.sha256(0, filesize) == "c72d1f2b115b7b08b92549589d2f628df42cfa3bd398333cde88ac0f7da18c7c"
}

rule MalwareBazaar_unknown_049_481aeb10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "481aeb107b7e44c109ab0aa25ae8f75a41658736f7a6be61f928596da7bdec4a"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:07"
  condition:
    hash.sha256(0, filesize) == "481aeb107b7e44c109ab0aa25ae8f75a41658736f7a6be61f928596da7bdec4a"
}

rule MalwareBazaar_unknown_050_d0ac31d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0ac31d3d1554f8f6563df056b83cd23cb7ceb6d1dfd88b40f6001be9c665c49"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:44:00"
  condition:
    hash.sha256(0, filesize) == "d0ac31d3d1554f8f6563df056b83cd23cb7ceb6d1dfd88b40f6001be9c665c49"
}

rule MalwareBazaar_unknown_051_1c6e2a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c6e2a40498927104042e739da3c7d0f6de2497376ce01bf39d94173fb368a36"
    family = "unknown"
    file_name = "chiken(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:54"
  condition:
    hash.sha256(0, filesize) == "1c6e2a40498927104042e739da3c7d0f6de2497376ce01bf39d94173fb368a36"
}

rule MalwareBazaar_unknown_052_fabb76c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fabb76c9d0df6d712745755c162e5b533b0a898afed44a2cf10d39822d5d4106"
    family = "unknown"
    file_name = "chiken.apk.signed.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:48"
  condition:
    hash.sha256(0, filesize) == "fabb76c9d0df6d712745755c162e5b533b0a898afed44a2cf10d39822d5d4106"
}

rule MalwareBazaar_unknown_053_c7fa36de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7fa36defaa3be8ffc4c2a9341fe66a22435a6d6f0f664a9fdfd1d8c217d0525"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:40"
  condition:
    hash.sha256(0, filesize) == "c7fa36defaa3be8ffc4c2a9341fe66a22435a6d6f0f664a9fdfd1d8c217d0525"
}

rule MalwareBazaar_unknown_054_55426492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55426492f381b775c3fa0c592435bbe47b26febe27c9988d91ef2c026ecd4927"
    family = "unknown"
    file_name = "chiken_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:43:33"
  condition:
    hash.sha256(0, filesize) == "55426492f381b775c3fa0c592435bbe47b26febe27c9988d91ef2c026ecd4927"
}

rule MalwareBazaar_SilentNet_055_2624bcb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2624bcb312523b0a47ecf86e0997103e7106c7619878c52a5ea8507b9f8734a4"
    family = "SilentNet"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 22:30:33"
  condition:
    hash.sha256(0, filesize) == "2624bcb312523b0a47ecf86e0997103e7106c7619878c52a5ea8507b9f8734a4"
}

rule MalwareBazaar_unknown_056_ad6a7763
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad6a776395907df97ff5214c97220c5a6f11d7e038d9e28180500b14820a771f"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:18:03"
  condition:
    hash.sha256(0, filesize) == "ad6a776395907df97ff5214c97220c5a6f11d7e038d9e28180500b14820a771f"
}

rule MalwareBazaar_unknown_057_cc30bf93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc30bf9361b728c8dfa1ec1810d584b3501bfc100c606976abab77443b1fb216"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:17:58"
  condition:
    hash.sha256(0, filesize) == "cc30bf9361b728c8dfa1ec1810d584b3501bfc100c606976abab77443b1fb216"
}

rule MalwareBazaar_unknown_058_b0105ccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0105ccfdc0b7ecd83bce3be22221b3a867b9ec4c6ad06fde568e2f165beb9dc"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:17:52"
  condition:
    hash.sha256(0, filesize) == "b0105ccfdc0b7ecd83bce3be22221b3a867b9ec4c6ad06fde568e2f165beb9dc"
}

rule MalwareBazaar_unknown_059_2a42612f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a42612f7974cbeb0d0278a554b94eed6dcecd499d1c36a3362b4439552fb357"
    family = "unknown"
    file_name = "chiken_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:17:39"
  condition:
    hash.sha256(0, filesize) == "2a42612f7974cbeb0d0278a554b94eed6dcecd499d1c36a3362b4439552fb357"
}

rule MalwareBazaar_unknown_060_9a1f416d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a1f416d44a48db4c4f58ec4743c95d7f8a331b1613f46fba966b41ff688b858"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-01 22:16:48"
  condition:
    hash.sha256(0, filesize) == "9a1f416d44a48db4c4f58ec4743c95d7f8a331b1613f46fba966b41ff688b858"
}

rule MalwareBazaar_unknown_061_70d9c4b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70d9c4b9c40e523eed7907eda95f7bf997c3979c1111fdd34c2ed998f3f05fa8"
    family = "unknown"
    file_name = "dogandcat.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:11:00"
  condition:
    hash.sha256(0, filesize) == "70d9c4b9c40e523eed7907eda95f7bf997c3979c1111fdd34c2ed998f3f05fa8"
}

rule MalwareBazaar_unknown_062_9532979a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9532979ac61ad44b90bf0885b1634b685809df93bca37d018e523823095c9e57"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:55"
  condition:
    hash.sha256(0, filesize) == "9532979ac61ad44b90bf0885b1634b685809df93bca37d018e523823095c9e57"
}

rule MalwareBazaar_unknown_063_fc7b4423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc7b4423cdd2e36ba713e650987336ff5d92268ad130b30384d024337cb86c73"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:49"
  condition:
    hash.sha256(0, filesize) == "fc7b4423cdd2e36ba713e650987336ff5d92268ad130b30384d024337cb86c73"
}

rule MalwareBazaar_unknown_064_eda53d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda53d81661e2dcad1a4cc200dece0c4d8b2732b23c9e109317a06e4a752141c"
    family = "unknown"
    file_name = "chiken(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:42"
  condition:
    hash.sha256(0, filesize) == "eda53d81661e2dcad1a4cc200dece0c4d8b2732b23c9e109317a06e4a752141c"
}

rule MalwareBazaar_unknown_065_d8c0defc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8c0defc4f57bbbf9867012b2da45c5e2e8f7358e951889315415d9068a72cb1"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:28"
  condition:
    hash.sha256(0, filesize) == "d8c0defc4f57bbbf9867012b2da45c5e2e8f7358e951889315415d9068a72cb1"
}

rule MalwareBazaar_unknown_066_16a11191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16a11191fa0c9db957c9163d3e6a1dbb3c63dc9edcd5badb92e59d44a64e53c8"
    family = "unknown"
    file_name = "chiken_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-01 22:10:16"
  condition:
    hash.sha256(0, filesize) == "16a11191fa0c9db957c9163d3e6a1dbb3c63dc9edcd5badb92e59d44a64e53c8"
}

rule MalwareBazaar_Mirai_067_77892293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273"
    family = "Mirai"
    file_name = "778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273"
    file_type = "sh"
    first_seen = "2026-07-01 22:08:50"
  condition:
    hash.sha256(0, filesize) == "778922930cf94d91671d3ad83fca3b3b8c50f24eb3f42b4c9f84022bb3902273"
}

rule MalwareBazaar_unknown_068_b6c42dd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6c42dd2f522b2424e77443472d6ad4a0710d738ef664d69a0141bb71b1424c3"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:55:46"
  condition:
    hash.sha256(0, filesize) == "b6c42dd2f522b2424e77443472d6ad4a0710d738ef664d69a0141bb71b1424c3"
}

rule MalwareBazaar_unknown_069_88124fa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88124fa447b804b2b10358a99f5f08d8450e0893106c99aada7f1fd845cec25f"
    family = "unknown"
    file_name = "chiken(2).apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:55:39"
  condition:
    hash.sha256(0, filesize) == "88124fa447b804b2b10358a99f5f08d8450e0893106c99aada7f1fd845cec25f"
}

rule MalwareBazaar_unknown_070_3a90670a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a90670af15275d048191fe41bfcbe63939961364a16de93178eff69ff810834"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:55:23"
  condition:
    hash.sha256(0, filesize) == "3a90670af15275d048191fe41bfcbe63939961364a16de93178eff69ff810834"
}

rule MalwareBazaar_unknown_071_4427a714
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4427a7140286f25d16069b06e650a4e904f2e290eed2cf6f647a2d50284f9f20"
    family = "unknown"
    file_name = "4392-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 21:47:45"
  condition:
    hash.sha256(0, filesize) == "4427a7140286f25d16069b06e650a4e904f2e290eed2cf6f647a2d50284f9f20"
}

rule MalwareBazaar_unknown_072_0ed25bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ed25bcfc5703d016338dfe5579a16451fcf28cc3f2ce6f70f06daa77c63a4c6"
    family = "unknown"
    file_name = "payload.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:50"
  condition:
    hash.sha256(0, filesize) == "0ed25bcfc5703d016338dfe5579a16451fcf28cc3f2ce6f70f06daa77c63a4c6"
}

rule MalwareBazaar_unknown_073_5b5417ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5417ce2b0fe3a576b079eae4c43d22f4c4bf2cd907f6f1c47f955eb8eb6aa4"
    family = "unknown"
    file_name = "dogandcat(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:35"
  condition:
    hash.sha256(0, filesize) == "5b5417ce2b0fe3a576b079eae4c43d22f4c4bf2cd907f6f1c47f955eb8eb6aa4"
}

rule MalwareBazaar_unknown_074_cf9dea7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf9dea7dc62717e4b239f0595594ec4211252e3d8fad46b1b59061f698801993"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:29"
  condition:
    hash.sha256(0, filesize) == "cf9dea7dc62717e4b239f0595594ec4211252e3d8fad46b1b59061f698801993"
}

rule MalwareBazaar_unknown_075_8705c9b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8705c9b738bac60713fbb93b31f02fff061fcaf42ec26ec62400438fb844bb32"
    family = "unknown"
    file_name = "chiken(1).apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:22"
  condition:
    hash.sha256(0, filesize) == "8705c9b738bac60713fbb93b31f02fff061fcaf42ec26ec62400438fb844bb32"
}

rule MalwareBazaar_unknown_076_15cd5bbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15cd5bbbdb9e5f980043bcc849a66c8fb77ba4af44dacfdc653e2488622b2408"
    family = "unknown"
    file_name = "chiken.apk"
    file_type = "apk"
    first_seen = "2026-07-01 21:43:05"
  condition:
    hash.sha256(0, filesize) == "15cd5bbbdb9e5f980043bcc849a66c8fb77ba4af44dacfdc653e2488622b2408"
}

rule MalwareBazaar_unknown_077_5281e44f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5281e44fdd82e2c79a54b145517bc7295dd14adc10ca69ec6986dcc242394ae9"
    family = "unknown"
    file_name = "4407-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 21:24:16"
  condition:
    hash.sha256(0, filesize) == "5281e44fdd82e2c79a54b145517bc7295dd14adc10ca69ec6986dcc242394ae9"
}

rule MalwareBazaar_ValleyRAT_078_de4ca2d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de4ca2d0a042ca8338017d349818bcd4263eab9b83490cf9c45a44495c542660"
    family = "ValleyRAT"
    file_name = "点击切换简体中文语言包.exe"
    file_type = "exe"
    first_seen = "2026-07-01 21:22:47"
  condition:
    hash.sha256(0, filesize) == "de4ca2d0a042ca8338017d349818bcd4263eab9b83490cf9c45a44495c542660"
}

rule MalwareBazaar_unknown_079_0e071173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e071173b997fd6ff92a74b770f133978587d9e3540e114ec9e680b1fe749a0b"
    family = "unknown"
    file_name = "点击此处安装简体中文'.exe"
    file_type = "exe"
    first_seen = "2026-07-01 21:22:16"
  condition:
    hash.sha256(0, filesize) == "0e071173b997fd6ff92a74b770f133978587d9e3540e114ec9e680b1fe749a0b"
}

rule MalwareBazaar_unknown_080_69525610
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69525610bf4cd62d90ca4e184de6107ac647db5b7d61f534bf48ba7b3a1a877e"
    family = "unknown"
    file_name = "【【点击安装简体中文语言包zh_cn】】.exe"
    file_type = "exe"
    first_seen = "2026-07-01 21:21:46"
  condition:
    hash.sha256(0, filesize) == "69525610bf4cd62d90ca4e184de6107ac647db5b7d61f534bf48ba7b3a1a877e"
}

rule MalwareBazaar_Formbook_081_64bb3ef4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bb3ef49a6f0d11aa926b5af1cd93796af2137e529068859fc15f691c034510"
    family = "Formbook"
    file_name = "Quotation Request.exe"
    file_type = "exe"
    first_seen = "2026-07-01 20:59:30"
  condition:
    hash.sha256(0, filesize) == "64bb3ef49a6f0d11aa926b5af1cd93796af2137e529068859fc15f691c034510"
}

rule MalwareBazaar_unknown_082_4b58c020
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b58c020d155e5c31a1a3a48065ce3c4217ffd8352487f87147a605f2488d907"
    family = "unknown"
    file_name = "Game_win1.1.exe"
    file_type = "exe"
    first_seen = "2026-07-01 20:59:06"
  condition:
    hash.sha256(0, filesize) == "4b58c020d155e5c31a1a3a48065ce3c4217ffd8352487f87147a605f2488d907"
}

rule MalwareBazaar_unknown_083_d5208ee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5208ee9717fd73b8cbb395805ff2886b34ca7a2cb14c544da8e70ddb6a8ab2e"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-01 20:29:44"
  condition:
    hash.sha256(0, filesize) == "d5208ee9717fd73b8cbb395805ff2886b34ca7a2cb14c544da8e70ddb6a8ab2e"
}

rule MalwareBazaar_unknown_084_be790bd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be790bd961586ed3f8461a0fda3e1ea065234e3d927c7fdda24a905813283d7b"
    family = "unknown"
    file_name = "5156-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:21:10"
  condition:
    hash.sha256(0, filesize) == "be790bd961586ed3f8461a0fda3e1ea065234e3d927c7fdda24a905813283d7b"
}

rule MalwareBazaar_unknown_085_1c7b037c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c7b037c1a5439d4ab8ae9b79643a5a12c384491e2aa05dd5ca0a909ee302102"
    family = "unknown"
    file_name = "4256-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:59"
  condition:
    hash.sha256(0, filesize) == "1c7b037c1a5439d4ab8ae9b79643a5a12c384491e2aa05dd5ca0a909ee302102"
}

rule MalwareBazaar_unknown_086_8729d419
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8729d419ca1dc5d2694da626a91b47fdfba682b57d98e5d1f21c62c99c9ff84d"
    family = "unknown"
    file_name = "4253-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:47"
  condition:
    hash.sha256(0, filesize) == "8729d419ca1dc5d2694da626a91b47fdfba682b57d98e5d1f21c62c99c9ff84d"
}

rule MalwareBazaar_unknown_087_7c73095e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c73095e6b642b642efe29aeef1e5de509185937f336fa18a2e291cd06fcfbe7"
    family = "unknown"
    file_name = "4252-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:36"
  condition:
    hash.sha256(0, filesize) == "7c73095e6b642b642efe29aeef1e5de509185937f336fa18a2e291cd06fcfbe7"
}

rule MalwareBazaar_unknown_088_26250690
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26250690ff4335ad646319c5311b3878d2ba7bb30ff6538dd1ebdc2660f77c01"
    family = "unknown"
    file_name = "4246-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:25"
  condition:
    hash.sha256(0, filesize) == "26250690ff4335ad646319c5311b3878d2ba7bb30ff6538dd1ebdc2660f77c01"
}

rule MalwareBazaar_unknown_089_b79dd5b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b79dd5b1942cd20af76e42d6fb8dd093b4711dfd7b10845fc831dd7fa62870cb"
    family = "unknown"
    file_name = "4240-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:20:14"
  condition:
    hash.sha256(0, filesize) == "b79dd5b1942cd20af76e42d6fb8dd093b4711dfd7b10845fc831dd7fa62870cb"
}

rule MalwareBazaar_unknown_090_81c82084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81c8208418452c3b853578feefd0d1bf5bdef557fc6a007bbfdc52ade20d177e"
    family = "unknown"
    file_name = "4315-1.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 20:02:34"
  condition:
    hash.sha256(0, filesize) == "81c8208418452c3b853578feefd0d1bf5bdef557fc6a007bbfdc52ade20d177e"
}

rule MalwareBazaar_unknown_091_69f79d97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69f79d97ab5d02af88b2669985d9b7cb26e176081ba0dde4a1c0ea78cf6bdac5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-01 19:51:44"
  condition:
    hash.sha256(0, filesize) == "69f79d97ab5d02af88b2669985d9b7cb26e176081ba0dde4a1c0ea78cf6bdac5"
}

rule MalwareBazaar_unknown_092_08030523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08030523df4e3fbb7e9cc42455673d574975d0fb5bc10c551e407354e17716f4"
    family = "unknown"
    file_name = "4563-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 19:50:04"
  condition:
    hash.sha256(0, filesize) == "08030523df4e3fbb7e9cc42455673d574975d0fb5bc10c551e407354e17716f4"
}

rule MalwareBazaar_unknown_093_44d1d36e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44d1d36e93844f0c93e1ebb3232f6130bcf90e2de7b85078bc0f5e0c17016eac"
    family = "unknown"
    file_name = "4373-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 19:49:51"
  condition:
    hash.sha256(0, filesize) == "44d1d36e93844f0c93e1ebb3232f6130bcf90e2de7b85078bc0f5e0c17016eac"
}

rule MalwareBazaar_unknown_094_efbf9441
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efbf94416ae8cc4b7569679c9d5f3af3cc9e270e9010702dc798fba216ce61dc"
    family = "unknown"
    file_name = "4320-0.dex"
    file_type = "unknown"
    first_seen = "2026-07-01 19:49:36"
  condition:
    hash.sha256(0, filesize) == "efbf94416ae8cc4b7569679c9d5f3af3cc9e270e9010702dc798fba216ce61dc"
}

rule MalwareBazaar_unknown_095_d85e8b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d85e8b60d7fdb80139ec7551f85ec86d31889407a8ded9e161d12a6499f8fc89"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-01 19:47:43"
  condition:
    hash.sha256(0, filesize) == "d85e8b60d7fdb80139ec7551f85ec86d31889407a8ded9e161d12a6499f8fc89"
}

rule MalwareBazaar_unknown_096_101cca11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "101cca11ddad5036ce8675a024e763f1123fda5ebcc063145c2bff4cda990ef9"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-01 19:20:00"
  condition:
    hash.sha256(0, filesize) == "101cca11ddad5036ce8675a024e763f1123fda5ebcc063145c2bff4cda990ef9"
}

rule MalwareBazaar_unknown_097_b9505282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9505282931ce70307a14689daf7767ba1124113c24c7e174499bb5331351a5e"
    family = "unknown"
    file_name = "install-1.5.exe"
    file_type = "exe"
    first_seen = "2026-07-01 19:13:02"
  condition:
    hash.sha256(0, filesize) == "b9505282931ce70307a14689daf7767ba1124113c24c7e174499bb5331351a5e"
}

rule MalwareBazaar_unknown_098_cb7d113f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb7d113f74a978a48ae16a41abc11697436ac6f0f858138eaa94fea4b25e9f4d"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-07-01 19:08:35"
  condition:
    hash.sha256(0, filesize) == "cb7d113f74a978a48ae16a41abc11697436ac6f0f858138eaa94fea4b25e9f4d"
}

rule MalwareBazaar_unknown_099_bf174151
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf1741518265388933600614e165d73237c44dcd6b2d9dcde7cd2bb3ea177b42"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-01 19:06:44"
  condition:
    hash.sha256(0, filesize) == "bf1741518265388933600614e165d73237c44dcd6b2d9dcde7cd2bb3ea177b42"
}

rule MalwareBazaar_unknown_100_15bd2334
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15bd2334d11f0058a578ea871b87637a8f918a39755b43976ba2d14c2fdb79c7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-01 18:59:24"
  condition:
    hash.sha256(0, filesize) == "15bd2334d11f0058a578ea871b87637a8f918a39755b43976ba2d14c2fdb79c7"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

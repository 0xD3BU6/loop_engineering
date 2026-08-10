# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-10

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 620 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 620 |
| Unique family labels | 5 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 57 |
| Mirai | 36 |
| Prometei | 5 |
| Loda | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 54 |
| exe | 24 |
| sh | 13 |
| unknown | 6 |
| js | 3 |

## Per-Sample Analysis

### Sample 1: `7bf7e6decac47c1d`

| Field | Value |
|---|---|
| SHA-256 | `7bf7e6decac47c1d1e315a8ef07a83ac148467fda3d6e284870c22c4d500314c` |
| Family label | `unknown` |
| File name | `main.e300c3` |
| File type | `elf` |
| First seen | `2026-08-10 02:33:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ead0e809fab3827f5228618a15710e2a` |
| SHA-1 | `f519656a07d56cb8e2edd157a259e24ffaebd243` |
| SHA-256 | `7bf7e6decac47c1d1e315a8ef07a83ac148467fda3d6e284870c22c4d500314c` |
| SHA3-384 | `6bb1b563ba661e4684fe2394b0ccdccfa52b91cb111c58bfcf1a207a0304cc0d0aeaf1417ee8a54695b08d25c4979e4e` |
| TLSH | `T147530A23FB0C0452D8D36EB80E7F0BE68315AD5120FE9115750D6F9A1B36F315687BAA` |
| SSDEEP | `1536:CmaT0Yvmt3uyanB+gRy58YB1RrSMH/2H1Aqft18IoME:CXT0YvWehB+we1RjHeH1AK8fME` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_7bf7e6de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bf7e6decac47c1d1e315a8ef07a83ac148467fda3d6e284870c22c4d500314c"
    family = "unknown"
    file_name = "main.e300c3"
    file_type = "elf"
    first_seen = "2026-08-10 02:33:43"
  condition:
    hash.sha256(0, filesize) == "7bf7e6decac47c1d1e315a8ef07a83ac148467fda3d6e284870c22c4d500314c"
}
```

### Sample 2: `98196b4050ff4ef4`

| Field | Value |
|---|---|
| SHA-256 | `98196b4050ff4ef422082b82e54b63570955e0fdb2fcb8ec5a0783d6d97e2264` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-10 02:28:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dff17bf4f87aad1f1fde602d1bddd1a1` |
| SHA-1 | `d15ceee338fd9f91fef30d48499fc3eb984c5e01` |
| SHA-256 | `98196b4050ff4ef422082b82e54b63570955e0fdb2fcb8ec5a0783d6d97e2264` |
| SHA3-384 | `23a86b8ce4f6228abb8e11981988b43504778e09bf3470720826dc2fdcb188435b13ddebf7c33c52a5765120918834c0` |
| TLSH | `T10883D506EF550FFBDC6FDD3706A9070225CC665B22A93B3A3534D928B55B24B0AE3C64` |
| SSDEEP | `1536:D3qYhpgNaGTdS3hYY4Z20uc8c3/aZ0U214Vl93yrY3Y82Iz0Q:D39hpgvTdSJTc8ia/XGb82q0Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_98196b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98196b4050ff4ef422082b82e54b63570955e0fdb2fcb8ec5a0783d6d97e2264"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-10 02:28:41"
  condition:
    hash.sha256(0, filesize) == "98196b4050ff4ef422082b82e54b63570955e0fdb2fcb8ec5a0783d6d97e2264"
}
```

### Sample 3: `605108764fe03fc9`

| Field | Value |
|---|---|
| SHA-256 | `605108764fe03fc94d3d631ba09abc815cdbaacf2d4414a7aafc06934a83f163` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-10 02:27:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `529427dd9a950d6233d9bb4a1c3b2e93` |
| SHA-1 | `363baa9c661d95936d17c9d97454c331d790091f` |
| SHA-256 | `605108764fe03fc94d3d631ba09abc815cdbaacf2d4414a7aafc06934a83f163` |
| SHA3-384 | `d9b6518c09185c92f339b42d01dd8be6a26913b271c6979013d54f77c168713d2da842c8be0bcb96ea893af5b476f1b6` |
| TLSH | `T1ADF2E16E70D4789EEFEC4C79420CE7216E55F0C0B28397DEEFE05AD95A35A17D44900A` |
| SSDEEP | `768:lGwiPffsTuFG2qcheO7GQUOLz6hPxv03XijEWM3j:1iPfiuFGANGQUX8nij6j` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_60510876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "605108764fe03fc94d3d631ba09abc815cdbaacf2d4414a7aafc06934a83f163"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-10 02:27:49"
  condition:
    hash.sha256(0, filesize) == "605108764fe03fc94d3d631ba09abc815cdbaacf2d4414a7aafc06934a83f163"
}
```

### Sample 4: `28453e3796ae864a`

| Field | Value |
|---|---|
| SHA-256 | `28453e3796ae864a07efceb26f881c2d3d05bcdb95012b817e8dfe9fdc5eee34` |
| Family label | `unknown` |
| File name | `main.mips32` |
| File type | `elf` |
| First seen | `2026-08-10 02:27:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a080c35fae733726bd422c55f81e7e9` |
| SHA-1 | `63ef4fa804d8920c01e2588bb26bd765e648ea69` |
| SHA-256 | `28453e3796ae864a07efceb26f881c2d3d05bcdb95012b817e8dfe9fdc5eee34` |
| SHA3-384 | `69f12d6b1245bb9c9be093469b89827a44e399b4c6f8bd260e944b363dfb69b0a8922bf21bb4a6671831080843b63c84` |
| TLSH | `T11E631A7A7711AFA9C26CD53009F28BE58AF21A6325E280817374DB0CAE7151C2C9FDF5` |
| SSDEEP | `1536:pidZZug3zU+xUBMZraMGqK5QiXEzEnkApGz2cs85eWNfFKEV+jOPf:MkAz2x85eWNTVi6f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_28453e37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28453e3796ae864a07efceb26f881c2d3d05bcdb95012b817e8dfe9fdc5eee34"
    family = "unknown"
    file_name = "main.mips32"
    file_type = "elf"
    first_seen = "2026-08-10 02:27:48"
  condition:
    hash.sha256(0, filesize) == "28453e3796ae864a07efceb26f881c2d3d05bcdb95012b817e8dfe9fdc5eee34"
}
```

### Sample 5: `62f058d6f04af72a`

| Field | Value |
|---|---|
| SHA-256 | `62f058d6f04af72a0dca6cb973fb9b7b6b75aa6162d769abf9bca946fcaedeb2` |
| Family label | `unknown` |
| File name | `main.aarch64be` |
| File type | `elf` |
| First seen | `2026-08-10 02:27:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d62a8a38ae1d5023c0f7647784a1df1` |
| SHA-1 | `87075f7aedda63b6d6974ecb14cf8536688ff208` |
| SHA-256 | `62f058d6f04af72a0dca6cb973fb9b7b6b75aa6162d769abf9bca946fcaedeb2` |
| SHA3-384 | `bf40410fc15bcd8eea5e4384cb7ec25550414598e0a7aac3072247675eda3321d4cbda0f85235f4d3de15ec461447fd0` |
| TLSH | `T135133BBEDF0E3941E3D4E338EB550BE1603F7924D39680B67E42718DC4E99DD89A2246` |
| SSDEEP | `768:QVE3rvrM5WPmE9CTjPavELfT/MVir4FyGZFLawW0KrT3C2hiWW:WEbzM5ZRPP7YYs3ZEb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_62f058d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62f058d6f04af72a0dca6cb973fb9b7b6b75aa6162d769abf9bca946fcaedeb2"
    family = "unknown"
    file_name = "main.aarch64be"
    file_type = "elf"
    first_seen = "2026-08-10 02:27:46"
  condition:
    hash.sha256(0, filesize) == "62f058d6f04af72a0dca6cb973fb9b7b6b75aa6162d769abf9bca946fcaedeb2"
}
```

### Sample 6: `844aba4ec75e4f22`

| Field | Value |
|---|---|
| SHA-256 | `844aba4ec75e4f229d096f01a2582c66c9bbea1416077cf479fa07d237dc1103` |
| Family label | `unknown` |
| File name | `ORDER_202606001pdf.js` |
| File type | `js` |
| First seen | `2026-08-10 02:25:37` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f77fd04907846cd52c41ed987ca960af` |
| SHA-1 | `23a1e7f3913f83495744bf7d5aee793800e01164` |
| SHA-256 | `844aba4ec75e4f229d096f01a2582c66c9bbea1416077cf479fa07d237dc1103` |
| SHA3-384 | `a72ccaf222fade12671730a02d68ad1d9743b2f40cb5e4df6d239154e54b3c1dc7b5fa872d10b4426d9d7a296241cb9b` |
| TLSH | `T194E5C7B232DF658A991C3705A44C14A90F6F845A2BC229EDF4CF51951F1F84A7A80EFF` |
| SSDEEP | `12288:tZxRDNkbgIgVycoThv/TQS4c7glxSsOJRYkWK4Iq7mczvvl3Hjse5AVoB52bDhxP:RlNXShkZc7JnYI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_844aba4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "844aba4ec75e4f229d096f01a2582c66c9bbea1416077cf479fa07d237dc1103"
    family = "unknown"
    file_name = "ORDER_202606001pdf.js"
    file_type = "js"
    first_seen = "2026-08-10 02:25:37"
  condition:
    hash.sha256(0, filesize) == "844aba4ec75e4f229d096f01a2582c66c9bbea1416077cf479fa07d237dc1103"
}
```

### Sample 7: `04cb291caba794af`

| Field | Value |
|---|---|
| SHA-256 | `04cb291caba794af54a271778636d58817a9056e6cfa6e28ae7389e3cefcfcb9` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-10 02:24:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ead39e75bf397aed5a6dc076662d2014` |
| SHA-1 | `faf3b4e4bdea36c6c7d04a74dbfab3492158df8d` |
| SHA-256 | `04cb291caba794af54a271778636d58817a9056e6cfa6e28ae7389e3cefcfcb9` |
| SHA3-384 | `39de9ba5d54e01bbc1736374af2fba808b1524543ce780bb9ec8f25ebda190a6930f28c7bc31ebb6a480e8234d1f1836` |
| TLSH | `T1AD532A55FC819712C6D122BBFB6E428D372A5368D2EF32079E256F1037C796B0E6B601` |
| TELFHASH | `t1d1f0dc1184881decd6b5465b9e0e11afc76e34853ae608c2a3c8ff5e9433df13435a7a` |
| SSDEEP | `1536:ltc29GVTKL+IdnbqsUY9uufcQiHWBCt3LEe43uE:ltcxG11utUuufLAtYruE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_04cb291c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04cb291caba794af54a271778636d58817a9056e6cfa6e28ae7389e3cefcfcb9"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-10 02:24:42"
  condition:
    hash.sha256(0, filesize) == "04cb291caba794af54a271778636d58817a9056e6cfa6e28ae7389e3cefcfcb9"
}
```

### Sample 8: `a85a4f1cb0212692`

| Field | Value |
|---|---|
| SHA-256 | `a85a4f1cb021269231f526880c990dc93db657e3173075fa12744b4f9ea4e9ea` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-10 02:23:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e4ba8e2cd5baeff395d6c45992b26e8` |
| SHA-1 | `bbca5011b7755a7748876f2354d9438c5757915e` |
| SHA-256 | `a85a4f1cb021269231f526880c990dc93db657e3173075fa12744b4f9ea4e9ea` |
| SHA3-384 | `5f23c2f1e14a22bbf0c0e3978dac8de4d4c80addc084f79c5aabf63deceea6182d20c4afbba52cccd3ddf421157b00f8` |
| TLSH | `T19CE2E1B067C2FE71C1F01C36E97AC9C6E3251B74818762E261FCD23EB2D610556B934A` |
| SSDEEP | `384:0JWpYc6x6cv4bkusuu81mm/fDQS07qI79jLKCFpy/IH9ILn9TVC9oONTjzvKHzCJ:aAYLpv4bhLGm10P9jhq/IHWRfONX3UQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_a85a4f1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85a4f1cb021269231f526880c990dc93db657e3173075fa12744b4f9ea4e9ea"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-10 02:23:41"
  condition:
    hash.sha256(0, filesize) == "a85a4f1cb021269231f526880c990dc93db657e3173075fa12744b4f9ea4e9ea"
}
```

### Sample 9: `3976eda2ae8a095f`

| Field | Value |
|---|---|
| SHA-256 | `3976eda2ae8a095f3868ad94d8b28e8bf3019298a73097a3a124a6f56b687b80` |
| Family label | `unknown` |
| File name | `main.aarch64` |
| File type | `elf` |
| First seen | `2026-08-10 02:19:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b4bc1b21eaab2a3b0fb94dd0d8013ac` |
| SHA-1 | `4d371305c419a7639c7524e5ef51bf8b426e92b8` |
| SHA-256 | `3976eda2ae8a095f3868ad94d8b28e8bf3019298a73097a3a124a6f56b687b80` |
| SHA3-384 | `cbdce36ce8881ca6f32b1e21e4951a5b00e6ce68ba04890dd75f2ca14f168fba2cb7eaefcc0d95e5e041bf89c13bf5d2` |
| TLSH | `T1C5131BABDE0E3941E3D4E338E7590BE1A02F7934D29680B77E42718DC4ED9DD8D92252` |
| SSDEEP | `768:Zv/i2+QPNW5cKy47DaLs9ykjiA+PfcZplFxLiYBZoCT8la6J:ZvMQVFtKDDyk1+nch+s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_3976eda2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3976eda2ae8a095f3868ad94d8b28e8bf3019298a73097a3a124a6f56b687b80"
    family = "unknown"
    file_name = "main.aarch64"
    file_type = "elf"
    first_seen = "2026-08-10 02:19:42"
  condition:
    hash.sha256(0, filesize) == "3976eda2ae8a095f3868ad94d8b28e8bf3019298a73097a3a124a6f56b687b80"
}
```

### Sample 10: `8c95dfa95220071f`

| Field | Value |
|---|---|
| SHA-256 | `8c95dfa95220071f3984c3158ee101597f53b6a1d1c092d07ba852f3ff37089a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-10 02:18:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e0bd3a985bc9e0937b35c99e92173fc` |
| SHA-1 | `bfabb344588f43940ace42df3416eece7d1d2e4d` |
| SHA-256 | `8c95dfa95220071f3984c3158ee101597f53b6a1d1c092d07ba852f3ff37089a` |
| SHA3-384 | `ec3d8027b05e44059ca4a3edd3591ffede9e05fd31447f56edacd8527d0ec0dfb31a7768aaed5a6f916169138dafb4d0` |
| TLSH | `T14C83A61E6E219FBDFA68C23047B78A21979C33D627E1D685D29CD6001E7034E641FFA8` |
| TELFHASH | `t1e7115b488d3823e587325d992badff76e1a130de4b255d378e10edadaa6dd424e01c1c` |
| SSDEEP | `1536:rYM+VffRbU4YnVviHdy9BeBcwCcTgee8ns5RSld641Ri:rD+fpbU4YVedEeawz2zEd64y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_8c95dfa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c95dfa95220071f3984c3158ee101597f53b6a1d1c092d07ba852f3ff37089a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-10 02:18:35"
  condition:
    hash.sha256(0, filesize) == "8c95dfa95220071f3984c3158ee101597f53b6a1d1c092d07ba852f3ff37089a"
}
```

### Sample 11: `853971052934e04c`

| Field | Value |
|---|---|
| SHA-256 | `853971052934e04c4063d7613fcdbb20c54ab4ee44bcfa184861b021663abf02` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-10 02:17:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4846a98e33bf324302a57e6269620816` |
| SHA-1 | `9542054c8b7f61ca8d420d786ed3d2e3d908884c` |
| SHA-256 | `853971052934e04c4063d7613fcdbb20c54ab4ee44bcfa184861b021663abf02` |
| SHA3-384 | `312ff1c2df431d6b67192dd0e5e7d3f16571de5163f5001da2c63412a68e9c33ea4aa634a2fad361423cad00d6a5c5d9` |
| TLSH | `T16CF2F1AF829798B3C837C77625E75BD04A6E07A6B465FC871101F25BE9470A9F4E42C0` |
| SSDEEP | `768:5wmhVBt5CxVrsvR3l/aReqdzInM3VC3yTSj5af4qJgGlzDpUYso:6QbGVrsj/FuIMFCv5awOVqYD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_85397105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "853971052934e04c4063d7613fcdbb20c54ab4ee44bcfa184861b021663abf02"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-10 02:17:43"
  condition:
    hash.sha256(0, filesize) == "853971052934e04c4063d7613fcdbb20c54ab4ee44bcfa184861b021663abf02"
}
```

### Sample 12: `22804a77a4bfbc5f`

| Field | Value |
|---|---|
| SHA-256 | `22804a77a4bfbc5f5df66ee61f8cdd422b0ea2a589fdfc6667b3ea58fc2c0ab3` |
| Family label | `unknown` |
| File name | `main.x86-64-i7` |
| File type | `elf` |
| First seen | `2026-08-10 02:13:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e618014ef07e84bb9f1528837eae666e` |
| SHA-1 | `74fc15de4c8e4d852b989f9d6f328ed8a70751e7` |
| SHA-256 | `22804a77a4bfbc5f5df66ee61f8cdd422b0ea2a589fdfc6667b3ea58fc2c0ab3` |
| SHA3-384 | `2522df6a34b3fa527065f16c77249b00cffd809116b077f22ba4b11d308b105375adc24e92ea3c16c9c3342b6952647f` |
| TLSH | `T10253D71BB6A3B0BCC247C0B45A9AD5B1B9317CB002213D7FA7C8FA312935E416659F72` |
| TELFHASH | `t18521f2214a6d38b1b1c7aa117350f1358d32289221e032f0a6b679fadb01f421f71c37` |
| SSDEEP | `1536:FSW6tN+bRAIxS2J7D0yWwwXuvZCi4IVRuGW2EUr:FtbRA8RJ7Dsat` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_22804a77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22804a77a4bfbc5f5df66ee61f8cdd422b0ea2a589fdfc6667b3ea58fc2c0ab3"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-10 02:13:39"
  condition:
    hash.sha256(0, filesize) == "22804a77a4bfbc5f5df66ee61f8cdd422b0ea2a589fdfc6667b3ea58fc2c0ab3"
}
```

### Sample 13: `5417acf48dbfb047`

| Field | Value |
|---|---|
| SHA-256 | `5417acf48dbfb04701be9fa60902059982e5f9febaebfeab1c9f51166b6fd144` |
| Family label | `unknown` |
| File name | `main.mips` |
| File type | `elf` |
| First seen | `2026-08-10 02:11:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a440af32d4f66eb14aba1cbf90eaeb83` |
| SHA-1 | `df230e3521762d165f89b489173d506adc5d49b8` |
| SHA-256 | `5417acf48dbfb04701be9fa60902059982e5f9febaebfeab1c9f51166b6fd144` |
| SHA3-384 | `7bebbd029009478e272cd7f74a88043d52f8b97cf1855fc337eb6c3286dc99dcbd06eae5393717297b5666ae971697f8` |
| TLSH | `T1FE63452A1A21FFFEE16E823047F39E7097556AD636E1C280E26CD7085F7028D185F7A5` |
| TELFHASH | `t17d118458453423f0d7855c9d67edff76e46140ef8a666e37ce10ecaaab21a425d00d2c` |
| SSDEEP | `1536:Jib+5AnryiihUgSgYpYvtc48d2hzTvawmJy77V2twXE:nKbn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_5417acf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5417acf48dbfb04701be9fa60902059982e5f9febaebfeab1c9f51166b6fd144"
    family = "unknown"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-10 02:11:44"
  condition:
    hash.sha256(0, filesize) == "5417acf48dbfb04701be9fa60902059982e5f9febaebfeab1c9f51166b6fd144"
}
```

### Sample 14: `cd24f0432e249235`

| Field | Value |
|---|---|
| SHA-256 | `cd24f0432e2492359dd91d611a2117b949dc991e03cf8e940875cc30c8c95b1e` |
| Family label | `unknown` |
| File name | `8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe` |
| File type | `exe` |
| First seen | `2026-08-10 02:09:44` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f1a5bed49a72973b26ead70df742e56` |
| SHA-1 | `5892f26b63dfc2b404a8311b8db36ce1a1581529` |
| SHA-256 | `cd24f0432e2492359dd91d611a2117b949dc991e03cf8e940875cc30c8c95b1e` |
| SHA3-384 | `87014a3b3b54cc6e94ee10c3d9b0c3a648c5890c46c5dbe7ccc95b2cd0411f3c8fd3d71def78f20694d084f695a93f1f` |
| IMPHASH | `75f85177e42aca4607666d9186f1316a` |
| TLSH | `T16D74DF6376B8F05EE8D157324F47C74287A93F949892E09E39B4230F2C656549F38BB2` |
| SSDEEP | `6144:4zNIwwaJjEpW95NCdlfGW3lYl5Z7LS5u/ZqaUbki42u6n9FM7C4bz3:4zNIwwOjJ95NCdl7YRPjqo2uIFMzbj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_cd24f043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd24f0432e2492359dd91d611a2117b949dc991e03cf8e940875cc30c8c95b1e"
    family = "unknown"
    file_name = "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
    file_type = "exe"
    first_seen = "2026-08-10 02:09:44"
  condition:
    hash.sha256(0, filesize) == "cd24f0432e2492359dd91d611a2117b949dc991e03cf8e940875cc30c8c95b1e"
}
```

### Sample 15: `5c5575b228ce5c6f`

| Field | Value |
|---|---|
| SHA-256 | `5c5575b228ce5c6f5cbe7dcdcde823a6ca926665f345adc585c8cd6df4f89ac0` |
| Family label | `Prometei` |
| File name | `0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750` |
| File type | `elf` |
| First seen | `2026-08-10 02:09:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a19d933d23e188f44f87e6cfbc79754b` |
| SHA-1 | `22469e8745c819600b8d0fcdc88b3d9fc22c2528` |
| SHA-256 | `5c5575b228ce5c6f5cbe7dcdcde823a6ca926665f345adc585c8cd6df4f89ac0` |
| SHA3-384 | `99676e0f19d660b4f6b184a016dc84885a25cfe326298c9284719a2b2500ee864cf11ab2db6b83a764ef675e9937a5d0` |
| TLSH | `T124167D2BB2A354FCC15BD030979FD673A835B4F801317D7B26809A352E72E605B69F62` |
| TELFHASH | `t1170273780bf2b87036c7c914b343d4f829772d2a66f534f1295228a8eec5ac44db7863` |
| SSDEEP | `98304:rOMUTZs37lmhsUoj+o/mcITAVyDBTz3NehBwMBvZgV:OsFSTz3NehnBx` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_015_5c5575b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5575b228ce5c6f5cbe7dcdcde823a6ca926665f345adc585c8cd6df4f89ac0"
    family = "Prometei"
    file_name = "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
    file_type = "elf"
    first_seen = "2026-08-10 02:09:41"
  condition:
    hash.sha256(0, filesize) == "5c5575b228ce5c6f5cbe7dcdcde823a6ca926665f345adc585c8cd6df4f89ac0"
}
```

### Sample 16: `47c89331a453ce7d`

| Field | Value |
|---|---|
| SHA-256 | `47c89331a453ce7d3a340dbedd22963e97926991ad405272ebc9bfc0df410e3c` |
| Family label | `unknown` |
| File name | `main.armv5-eabi` |
| File type | `elf` |
| First seen | `2026-08-10 02:09:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49d67a68860e618990b70a8bed6c160e` |
| SHA-1 | `95b3334112d9d5bd29afb5167d54ecf674fb5619` |
| SHA-256 | `47c89331a453ce7d3a340dbedd22963e97926991ad405272ebc9bfc0df410e3c` |
| SHA3-384 | `348c1c66a1b14d8367bcd21525fc5e4947b7dfd1df6f7329f31791d1932167b9f3483673b252ca24339e8a694e84033c` |
| TLSH | `T1AC630A95F840DA35C7C075BAFA5E02DD33130FA8E2EA31158D21AB353BF7A594A3B542` |
| SSDEEP | `1536:tYSAHU6DnejFhsX4XMwb4nFxj5ITgqDMtAnDndzlnUHY0zlpcwhNOkC0r:tkq/ineHzdzlnUrcADX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_47c89331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c89331a453ce7d3a340dbedd22963e97926991ad405272ebc9bfc0df410e3c"
    family = "unknown"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-08-10 02:09:39"
  condition:
    hash.sha256(0, filesize) == "47c89331a453ce7d3a340dbedd22963e97926991ad405272ebc9bfc0df410e3c"
}
```

### Sample 17: `58f68179c5c95efb`

| Field | Value |
|---|---|
| SHA-256 | `58f68179c5c95efbe4aa2d3943a7257ae58a580d71ca3a467d01372f9336e678` |
| Family label | `unknown` |
| File name | `main.x86-64-v4` |
| File type | `elf` |
| First seen | `2026-08-10 02:09:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d5ceaba43fa5bb9229fa8dbeb3597c5` |
| SHA-1 | `72fa4236753f7affd290f98ffba3d936edb41d3d` |
| SHA-256 | `58f68179c5c95efbe4aa2d3943a7257ae58a580d71ca3a467d01372f9336e678` |
| SHA3-384 | `eed04d3a97c12d76717e9c497e6dc2fffd097e3e7703cf618bfd176eb89ebd7477a7989cc759625afa44791861fe0fdb` |
| TLSH | `T1FC53081BB6E3B0BCC297D0745A5A99F2B9317CA002213E7F97C8FA312E35D112759A71` |
| TELFHASH | `t1df21a4b14dae39a1a19be7216311a07088312d5651e032e199b6b9e6df21f820ff5c33` |
| SSDEEP | `1536:5cgDdE1lbUjiSNkvEo5untFqXby0Rr6h6z3Ur:5cHfUjiSCmq+3L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_58f68179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58f68179c5c95efbe4aa2d3943a7257ae58a580d71ca3a467d01372f9336e678"
    family = "unknown"
    file_name = "main.x86-64-v4"
    file_type = "elf"
    first_seen = "2026-08-10 02:09:38"
  condition:
    hash.sha256(0, filesize) == "58f68179c5c95efbe4aa2d3943a7257ae58a580d71ca3a467d01372f9336e678"
}
```

### Sample 18: `37889641ac36cf08`

| Field | Value |
|---|---|
| SHA-256 | `37889641ac36cf081c187dc147939e329add2f571bd41363c8d4e5639bdb13b4` |
| Family label | `Prometei` |
| File name | `f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39` |
| File type | `exe` |
| First seen | `2026-08-10 02:09:37` |
| Reporter | `abuse_ch` |
| Tags | `exe, Prometei, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2970a8a61e6614818fec183b2e98b614` |
| SHA-1 | `3ffad3dde380a4c2782d0d4e7177bc8aa841d78c` |
| SHA-256 | `37889641ac36cf081c187dc147939e329add2f571bd41363c8d4e5639bdb13b4` |
| SHA3-384 | `c8504c6d6fbb9c8259a750f78886c73f712efd9c171be1257eb69820ef1e57c37fe8743e31649ae59471e77ec0a03e17` |
| IMPHASH | `497ec0ba56520a465b1c189de65cd68b` |
| TLSH | `T141445A13B201DC39D75206B1AD9F9B52097A7C391F3316DB73B01AACD6F01D2AE25B1A` |
| SSDEEP | `6144:7rAvsdc+iejBwJsyamsyo2iI0RnemvRGo0AsfZQ:7rAUdc4jEsyamsyo2i6mJGo0AsR` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_018_37889641
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37889641ac36cf081c187dc147939e329add2f571bd41363c8d4e5639bdb13b4"
    family = "Prometei"
    file_name = "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
    file_type = "exe"
    first_seen = "2026-08-10 02:09:37"
  condition:
    hash.sha256(0, filesize) == "37889641ac36cf081c187dc147939e329add2f571bd41363c8d4e5639bdb13b4"
}
```

### Sample 19: `dff3fe8edc2b6c29`

| Field | Value |
|---|---|
| SHA-256 | `dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a` |
| Family label | `Prometei` |
| File name | `dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a` |
| File type | `elf` |
| First seen | `2026-08-10 02:08:35` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fd7f470101385e2e2f3a35fc62e6d6c` |
| SHA-1 | `265ff1b6217cd0060595aea61221c9f58f55ff16` |
| SHA-256 | `dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a` |
| SHA3-384 | `19be25e2b9d0bd2422567e843cd45ed05e0ed906a7368373affa075adab7d2b0275cf3f5d0672ae1b61db8309df03276` |
| TLSH | `T1E99423FA1A8EF3FB49127F7027A0980081A47470F99D775986CBFDDA0FA52679CC8108` |
| SSDEEP | `12288:Ka6aYYIX2dWVxeJAaLYxAOfUhjXb44UfhlBeSE:T+2WejYxUxsI` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_019_dff3fe8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a"
    family = "Prometei"
    file_name = "dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a"
    file_type = "elf"
    first_seen = "2026-08-10 02:08:35"
  condition:
    hash.sha256(0, filesize) == "dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a"
}
```

### Sample 20: `608b2c8220a595a9`

| Field | Value |
|---|---|
| SHA-256 | `608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652` |
| Family label | `unknown` |
| File name | `608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652` |
| File type | `unknown` |
| First seen | `2026-08-10 02:08:32` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fea49f9d167e3becfeabe1735001855` |
| SHA-256 | `608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_608b2c82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652"
    family = "unknown"
    file_name = "608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652"
    file_type = "unknown"
    first_seen = "2026-08-10 02:08:32"
  condition:
    hash.sha256(0, filesize) == "608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652"
}
```

### Sample 21: `8a0aa04876b1221d`

| Field | Value |
|---|---|
| SHA-256 | `8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe` |
| Family label | `unknown` |
| File name | `8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe` |
| File type | `exe` |
| First seen | `2026-08-10 02:08:31` |
| Reporter | `c2hunter` |
| Tags | `exe, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc23dcfdbba5bb8f7987ae709e3559a9` |
| SHA-1 | `6ece81ae575977eb112f31e3877b5225dcbd102f` |
| SHA-256 | `8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe` |
| SHA3-384 | `1c69cc87f0e116128f800cff548868c75caa372aa6c1c106435fdc02481dc74ccbea13d0005a3084d1ec933154cfb169` |
| IMPHASH | `f418afe0379776397753ae40798cc2e3` |
| TLSH | `T1BA34F13668B83F14D423B679720B1F3281F5571F3A3B156CFAFE4BB2B1646110A6358A` |
| SSDEEP | `3072:FjYKz0b1fne3uapce5iUOIHJRsoIWl2oPlO72vGvW246N6aPGjgpdSVife12u7XR:Cre3NpGUOcnsoP9AjUOxvSVey7Oo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_8a0aa048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
    family = "unknown"
    file_name = "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
    file_type = "exe"
    first_seen = "2026-08-10 02:08:31"
  condition:
    hash.sha256(0, filesize) == "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
}
```

### Sample 22: `0ca3a4c2800f9454`

| Field | Value |
|---|---|
| SHA-256 | `0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750` |
| Family label | `Prometei` |
| File name | `0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750` |
| File type | `elf` |
| First seen | `2026-08-10 02:08:30` |
| Reporter | `c2hunter` |
| Tags | `elf, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60afd5c2a771fd8fc1746717e39bcdbc` |
| SHA-1 | `96bb1c2a720716a05f876ef280b8d904c53396aa` |
| SHA-256 | `0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750` |
| SHA3-384 | `c5ebb126ddd97097589d1dc8c9bf6b0490c73effe53a3e321a616ffc97ae8b1e535320c1814f39f70f543fe0c50fb6d5` |
| TLSH | `T1968533FA241A6056C502F8A737BA36E2960D6CB52DDCE09FD4CED4A61A3D5EE4F103C1` |
| SSDEEP | `24576:U5EPwlAml7uAKqU0zhb20eH5YEdA85xYsP3zRqU9MNvYbvNspKu5Xfuwd3vjMxmS:kxOmVyn0k5YEdA852Ez0WKgNsJmwlumS` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_022_0ca3a4c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
    family = "Prometei"
    file_name = "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
    file_type = "elf"
    first_seen = "2026-08-10 02:08:30"
  condition:
    hash.sha256(0, filesize) == "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
}
```

### Sample 23: `f4ac4f735b9ff260`

| Field | Value |
|---|---|
| SHA-256 | `f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39` |
| Family label | `Prometei` |
| File name | `f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39` |
| File type | `exe` |
| First seen | `2026-08-10 02:08:27` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcbb75d7701abc0b8264f885895ad0b0` |
| SHA-1 | `9c952494cea92443debfb5f1951e3bb7daf9c57e` |
| SHA-256 | `f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39` |
| SHA3-384 | `4bedc327312ee0164b005d540445eff1e6ec02596e9ed3357bb4119dbd079a67238962ce9f974b0cc765be1a190398c8` |
| IMPHASH | `973785c0920d1d10bba6df76714adc36` |
| TLSH | `T148B3F157F5C62D00C3E8AA3DB00FB7B2E045CA3698A980049FAF9F67DB76F1021559C9` |
| SSDEEP | `1536:daDsof88ljf7UCEGBsklNLA7stO6g9BHHKp5TwvmH7gwT0Nm7mS5ZuX+cguhZxeh:d5ojfYc9dA7HX9kDEmH7gBSvcF9sH1H` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_023_f4ac4f73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
    family = "Prometei"
    file_name = "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
    file_type = "exe"
    first_seen = "2026-08-10 02:08:27"
  condition:
    hash.sha256(0, filesize) == "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
}
```

### Sample 24: `63c7c59b2959a3de`

| Field | Value |
|---|---|
| SHA-256 | `63c7c59b2959a3de5a5456dc53aaa41362bb7a610e8a872f15dc2b5d163902a5` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-10 02:01:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03429a781f706020cc1897d2ce9d17b8` |
| SHA-1 | `97e0e91f907ad4d7eb1756756d348184caab0710` |
| SHA-256 | `63c7c59b2959a3de5a5456dc53aaa41362bb7a610e8a872f15dc2b5d163902a5` |
| SHA3-384 | `8288c43492ddc1568914da1d94e8e6acd74b41b253271fb4639a7e96ab06c994aa0581ab1fa4bf862456f15d3ca90577` |
| TLSH | `T16B731A5AB8819B11D5C116BEFA1E518E3313077CE3DE73229E24AF20778796B0E7B506` |
| TELFHASH | `t1a1d022a34a5819cccaa0c126c2b307313982bb3d26841182eb82af2d60370762549a32` |
| SSDEEP | `1536:SDnd7oMCDO+qrwFLtdoaTv8LQ3Mxi/1eoxZ61AJ7NG5FYNz:27hCDBDtdoaTN1eoxZ61AJxGnuz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_63c7c59b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c7c59b2959a3de5a5456dc53aaa41362bb7a610e8a872f15dc2b5d163902a5"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-10 02:01:49"
  condition:
    hash.sha256(0, filesize) == "63c7c59b2959a3de5a5456dc53aaa41362bb7a610e8a872f15dc2b5d163902a5"
}
```

### Sample 25: `98497bc74a1bb5ff`

| Field | Value |
|---|---|
| SHA-256 | `98497bc74a1bb5ff9750cbeb785bc245ccec38d570b3ccbdc88861dee6b2a498` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-10 01:59:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6df0f866bfc65e4701dc50a3888c4ca6` |
| SHA-1 | `8024164bf7336e2b2ae0996445eb45eac3de2fc2` |
| SHA-256 | `98497bc74a1bb5ff9750cbeb785bc245ccec38d570b3ccbdc88861dee6b2a498` |
| SHA3-384 | `09a930b1a11f9059b3e53f3eb8f28f230492721656b29f19491c7f18730e4ae21e6513ce8d8779b93ea6884105f0b371` |
| TLSH | `T1FEF2E17BEDC9A269E750183CE838C203B321186484877F703195CA6039C6B67FB796E7` |
| SSDEEP | `768:zDcN8in1nNDvuT7k52wmyVeSnQKLOKcfOHaCuk1BwUq3UI2VY:z4+y1nNDo4sw8KLOKqCuk1yCY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_98497bc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98497bc74a1bb5ff9750cbeb785bc245ccec38d570b3ccbdc88861dee6b2a498"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-10 01:59:35"
  condition:
    hash.sha256(0, filesize) == "98497bc74a1bb5ff9750cbeb785bc245ccec38d570b3ccbdc88861dee6b2a498"
}
```

### Sample 26: `e81d62a221ae112e`

| Field | Value |
|---|---|
| SHA-256 | `e81d62a221ae112e6184c3eb152082ab5ceefd9ba3ce15aa38968dcefdb47a81` |
| Family label | `unknown` |
| File name | `uuyc.4.1.0.exe` |
| File type | `exe` |
| First seen | `2026-08-10 01:56:30` |
| Reporter | `CNGaoLing` |
| Tags | `Backdoor, Dapato, exe, RAT, SilverFox` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a639e66dabc9503ff477d27ba6492e06` |
| SHA-1 | `3381cd94d24c3e318bcf16a4f88740c18e7a1ee6` |
| SHA-256 | `e81d62a221ae112e6184c3eb152082ab5ceefd9ba3ce15aa38968dcefdb47a81` |
| SHA3-384 | `b67b12dd46ab4a74b5c59fa5bff9d7472414a097e88b23c92a18028c3e290d049fc1c8c6632da7298dd8c2716ef6be18` |
| IMPHASH | `50da9c66b00fd68bbfb8d54a47418acd` |
| TLSH | `T1EE28335726A880E8E266D034C4578AE7D7F1BC910B79C79F10A07A2F1F776A20D6B353` |
| SSDEEP | `1572864:BlcFQzO0I4nP/baeAq5/0T1QsB5WJKeAYA//8pHYP0XKECgVt7BZb+NXa3daJ5:0FnEnPjcB/YC/8hYP0XxZJB3ta7` |
| ICON-DHASH | `fadadac2a2b8c4e4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_e81d62a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e81d62a221ae112e6184c3eb152082ab5ceefd9ba3ce15aa38968dcefdb47a81"
    family = "unknown"
    file_name = "uuyc.4.1.0.exe"
    file_type = "exe"
    first_seen = "2026-08-10 01:56:30"
  condition:
    hash.sha256(0, filesize) == "e81d62a221ae112e6184c3eb152082ab5ceefd9ba3ce15aa38968dcefdb47a81"
}
```

### Sample 27: `5252a88bf7cdf432`

| Field | Value |
|---|---|
| SHA-256 | `5252a88bf7cdf43210cbf1f9e7d377b28c8f7f1393e653c03b7e6393dc6e376b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-10 01:51:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12cd6a23db52223662a5a098ceaf0f02` |
| SHA-1 | `848b3ff0d3d7db733f7f21a36a2012024ccd53fc` |
| SHA-256 | `5252a88bf7cdf43210cbf1f9e7d377b28c8f7f1393e653c03b7e6393dc6e376b` |
| SHA3-384 | `b9059fadbd28fd2e7b31fe40bde16eccc2c1cc25aea25ab161d17c470c27c984da765658ff514c5e2c4074af912a5aa5` |
| TLSH | `T1BFC27C966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:Cs8vCB+25j6es8R49FYpMSUpi+20qUpi+20YQX:98l25JOd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_5252a88b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5252a88bf7cdf43210cbf1f9e7d377b28c8f7f1393e653c03b7e6393dc6e376b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:51:42"
  condition:
    hash.sha256(0, filesize) == "5252a88bf7cdf43210cbf1f9e7d377b28c8f7f1393e653c03b7e6393dc6e376b"
}
```

### Sample 28: `dd6350bd0ecef9c4`

| Field | Value |
|---|---|
| SHA-256 | `dd6350bd0ecef9c4803c039c581253cc95adf5efd5347097457e4f99318abc6f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-10 01:49:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88a520dcd5cfd12657629f627386da49` |
| SHA-1 | `fd269813a1a4355d3bbe666de392c13cc981d096` |
| SHA-256 | `dd6350bd0ecef9c4803c039c581253cc95adf5efd5347097457e4f99318abc6f` |
| SHA3-384 | `952c37267bfe9a133a850a483631ffb9f7d6b14bc4ca2c63dee118c7802ee8840456e2bddc809c6362bece4dbcd0eb64` |
| TLSH | `T108C27D966A967C44BDC98A3E4CBD2B0D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:C/E8vCB+25j6es8Rrej9FYpMSUpi+20qUpi+20YQX:qE8l25JrWd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_dd6350bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd6350bd0ecef9c4803c039c581253cc95adf5efd5347097457e4f99318abc6f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:49:41"
  condition:
    hash.sha256(0, filesize) == "dd6350bd0ecef9c4803c039c581253cc95adf5efd5347097457e4f99318abc6f"
}
```

### Sample 29: `10fd2c56ff14202d`

| Field | Value |
|---|---|
| SHA-256 | `10fd2c56ff14202d44aeb6ecab9ff5cf36c148bba9abaaa641496de2319979dd` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-10 01:49:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7619b80e26d31581355aefc1ff867bbf` |
| SHA-1 | `6450a575c9c838659cd2af50aa928f7e5f1ba22d` |
| SHA-256 | `10fd2c56ff14202d44aeb6ecab9ff5cf36c148bba9abaaa641496de2319979dd` |
| SHA3-384 | `ec2cc7ffa32685d13b7007024e631eb40a6ea6aba4db2a9be8f4093a6f6ae446c8bebf96bb595c688f4f83228e22c2c0` |
| TLSH | `T1C7316EDE06202A311512CE5EB3A3319CB6CDA1E72D9FD7D4ED481EA942897CCF261B0D` |
| SSDEEP | `24:zi0tWL9LHH7dDhGfRbbsi56ZJLac8c6uzXto3T9zXZ7Z8X/:zi0tWL9LnpE+ApduzXtq9zk/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_10fd2c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10fd2c56ff14202d44aeb6ecab9ff5cf36c148bba9abaaa641496de2319979dd"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-10 01:49:39"
  condition:
    hash.sha256(0, filesize) == "10fd2c56ff14202d44aeb6ecab9ff5cf36c148bba9abaaa641496de2319979dd"
}
```

### Sample 30: `d7367a850acb0ee7`

| Field | Value |
|---|---|
| SHA-256 | `d7367a850acb0ee789a09dd4ac407163905856935d955bae53e9554055899ceb` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-10 01:49:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d37e62a4cfd3c0c807a559b92d26b85d` |
| SHA-1 | `c6cc31058e9939642c777c8b98465b629213f529` |
| SHA-256 | `d7367a850acb0ee789a09dd4ac407163905856935d955bae53e9554055899ceb` |
| SHA3-384 | `6ea81f968da3c5c1b721cc0f14a02155e803d4cece7811d57905797bafd890cb5d918ad7c1b6abebabf33d97cb39533c` |
| TLSH | `T1B0236C551A957C14AA98C4371D7E2F0CBDA943E6320452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:SVEJVIhtML9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:oEJ2M8cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_d7367a85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7367a850acb0ee789a09dd4ac407163905856935d955bae53e9554055899ceb"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:49:38"
  condition:
    hash.sha256(0, filesize) == "d7367a850acb0ee789a09dd4ac407163905856935d955bae53e9554055899ceb"
}
```

### Sample 31: `27dc9bdb577cc603`

| Field | Value |
|---|---|
| SHA-256 | `27dc9bdb577cc60327ab3560ed452941a5c53a938a8ecaecde098641487be501` |
| Family label | `unknown` |
| File name | `package.json` |
| File type | `unknown` |
| First seen | `2026-08-10 01:42:02` |
| Reporter | `a3n` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a6c8d088b2287c840a8f3cd7dd84857` |
| SHA-256 | `27dc9bdb577cc60327ab3560ed452941a5c53a938a8ecaecde098641487be501` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_27dc9bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27dc9bdb577cc60327ab3560ed452941a5c53a938a8ecaecde098641487be501"
    family = "unknown"
    file_name = "package.json"
    file_type = "unknown"
    first_seen = "2026-08-10 01:42:02"
  condition:
    hash.sha256(0, filesize) == "27dc9bdb577cc60327ab3560ed452941a5c53a938a8ecaecde098641487be501"
}
```

### Sample 32: `f76da38b39db5068`

| Field | Value |
|---|---|
| SHA-256 | `f76da38b39db5068b1dc5411b4f2d40706a8e34ce5258ec68c88fda5af3754bf` |
| Family label | `unknown` |
| File name | `stage2-beavertail.js` |
| File type | `js` |
| First seen | `2026-08-10 01:42:00` |
| Reporter | `a3n` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9313c101b17b7ff97755b5680af14401` |
| SHA-1 | `e1a8ec971c3b84b396b1247fbd21ad1fec15820f` |
| SHA-256 | `f76da38b39db5068b1dc5411b4f2d40706a8e34ce5258ec68c88fda5af3754bf` |
| SHA3-384 | `811cc188973d9662f16c0fe133668208d1db29266fc32dabae53840997b67a6cfbe9891d9ea83c3791f47fe7d90f49aa` |
| TLSH | `T1CD167384D184E03397DD6B93BE857AA9F23669E284C8BA4F85747D4C29B8507D7B0CCC` |
| SSDEEP | `49152:l+N39cATn2HuYtfx3aO6GKknt0Ni2DRG4gUvC8tKGIDCTWuLy1ZZWH9pEJu9XtxS:B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_f76da38b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f76da38b39db5068b1dc5411b4f2d40706a8e34ce5258ec68c88fda5af3754bf"
    family = "unknown"
    file_name = "stage2-beavertail.js"
    file_type = "js"
    first_seen = "2026-08-10 01:42:00"
  condition:
    hash.sha256(0, filesize) == "f76da38b39db5068b1dc5411b4f2d40706a8e34ce5258ec68c88fda5af3754bf"
}
```

### Sample 33: `19e8655cf0664ca6`

| Field | Value |
|---|---|
| SHA-256 | `19e8655cf0664ca6cd413580483d1dedab2a0d871422ccc270f026b1f3951261` |
| Family label | `unknown` |
| File name | `vscode-bootstrap.sh` |
| File type | `sh` |
| First seen | `2026-08-10 01:41:56` |
| Reporter | `a3n` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14825aa3874632c9e8712795f88df834` |
| SHA-256 | `19e8655cf0664ca6cd413580483d1dedab2a0d871422ccc270f026b1f3951261` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_19e8655c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19e8655cf0664ca6cd413580483d1dedab2a0d871422ccc270f026b1f3951261"
    family = "unknown"
    file_name = "vscode-bootstrap.sh"
    file_type = "sh"
    first_seen = "2026-08-10 01:41:56"
  condition:
    hash.sha256(0, filesize) == "19e8655cf0664ca6cd413580483d1dedab2a0d871422ccc270f026b1f3951261"
}
```

### Sample 34: `75ef2f55a8631224`

| Field | Value |
|---|---|
| SHA-256 | `75ef2f55a86312240f0316468a693500efe97cf097cc7d22bcd9ffe237f473dc` |
| Family label | `unknown` |
| File name | `stage1-env-setup.js` |
| File type | `js` |
| First seen | `2026-08-10 01:41:33` |
| Reporter | `a3n` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `547fdc31fdc781db74774fd790e14360` |
| SHA-256 | `75ef2f55a86312240f0316468a693500efe97cf097cc7d22bcd9ffe237f473dc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_75ef2f55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75ef2f55a86312240f0316468a693500efe97cf097cc7d22bcd9ffe237f473dc"
    family = "unknown"
    file_name = "stage1-env-setup.js"
    file_type = "js"
    first_seen = "2026-08-10 01:41:33"
  condition:
    hash.sha256(0, filesize) == "75ef2f55a86312240f0316468a693500efe97cf097cc7d22bcd9ffe237f473dc"
}
```

### Sample 35: `a0006e9a7a2dbf8e`

| Field | Value |
|---|---|
| SHA-256 | `a0006e9a7a2dbf8e1245a3d6e0847130b337a463ec60b0f0c7ccac3a244303f1` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-10 01:23:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7eb1253e53ed997951f541680b445ee4` |
| SHA-1 | `c7b819f3aa965fb890dadb1b1a80280ba66a666b` |
| SHA-256 | `a0006e9a7a2dbf8e1245a3d6e0847130b337a463ec60b0f0c7ccac3a244303f1` |
| SHA3-384 | `0139514a564ee97dd4d8f12f1b41935eaa2a3c38c42b09f3112b890dc8c123ebd8cbe24351d8bde3c0d0fe58b8e47b4e` |
| TLSH | `T108235C2516857C24AE98C4361C7E2F0CB9AD43E6324452EEBFCB3CF68C4A69D910971D` |
| SSDEEP | `768:9+IG9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:9+Ijcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_a0006e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0006e9a7a2dbf8e1245a3d6e0847130b337a463ec60b0f0c7ccac3a244303f1"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:23:44"
  condition:
    hash.sha256(0, filesize) == "a0006e9a7a2dbf8e1245a3d6e0847130b337a463ec60b0f0c7ccac3a244303f1"
}
```

### Sample 36: `c0c587eff2689362`

| Field | Value |
|---|---|
| SHA-256 | `c0c587eff26893624f4fa504208ed33fe03589228406431549cfead5c44f17e3` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-08-10 00:51:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6176ecd1410b3909ef4f3005a9b1ed5d` |
| SHA-1 | `93d3e322ee46891da3de9c07a58885bf764906d2` |
| SHA-256 | `c0c587eff26893624f4fa504208ed33fe03589228406431549cfead5c44f17e3` |
| SHA3-384 | `372eb6e05cd54f631bca93c27fedc4d130293bfcb4dac312c7110ab2a3fcbdb52a039cb9cc0af3a8524edd620fdbb8fa` |
| TLSH | `T1D9A47D0339760D26E4C5A57551EB03A2FAF693CB20BC4B1AFD940CDABF167A070522F9` |
| SSDEEP | `6144:c8l0Cp/ryidXvpIFFIgtORZA/Y72s8UJUjp7GuI5vImxgI:c8l0EmidvpIFbQruM2s8Ua6hheI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_c0c587ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0c587eff26893624f4fa504208ed33fe03589228406431549cfead5c44f17e3"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-10 00:51:47"
  condition:
    hash.sha256(0, filesize) == "c0c587eff26893624f4fa504208ed33fe03589228406431549cfead5c44f17e3"
}
```

### Sample 37: `c414e83794ecb9ed`

| Field | Value |
|---|---|
| SHA-256 | `c414e83794ecb9ed7fc4f39b2b69ac84473721d622fa09c6d565852e777b0e02` |
| Family label | `unknown` |
| File name | `XBDTGO.464.dec` |
| File type | `exe` |
| First seen | `2026-08-10 00:27:28` |
| Reporter | `johnk3r` |
| Tags | `exe, latam, mosquito, ssl-fic20-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3895165fffb52ebe47b0b5a7755821af` |
| SHA-1 | `be9a6c29e0bd8643f535fd5fea761309b3f2a1b3` |
| SHA-256 | `c414e83794ecb9ed7fc4f39b2b69ac84473721d622fa09c6d565852e777b0e02` |
| SHA3-384 | `3cfce36da737ed5ec21a4676f48f7a566292c154412c0c1863c40a9a3927791b5f8f766422278739ef7e4b38c68691a4` |
| IMPHASH | `62cc1d574bca5325a51f5b7373f96626` |
| TLSH | `T1F6947C26FB640076E167D538CDA34901EB727C8E43209BCB23A94A965F63FE05E3E751` |
| SSDEEP | `6144:wDDlrvrSNMzVo7RGIESJAJzkePxyOr1xdtp2TlMPpQs4:KxvM7MIESi57r1LWTlMPpv4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_c414e837
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c414e83794ecb9ed7fc4f39b2b69ac84473721d622fa09c6d565852e777b0e02"
    family = "unknown"
    file_name = "XBDTGO.464.dec"
    file_type = "exe"
    first_seen = "2026-08-10 00:27:28"
  condition:
    hash.sha256(0, filesize) == "c414e83794ecb9ed7fc4f39b2b69ac84473721d622fa09c6d565852e777b0e02"
}
```

### Sample 38: `6eba72e816768b1c`

| Field | Value |
|---|---|
| SHA-256 | `6eba72e816768b1c383487af637ddc3d64e5feacaed1bd7312b983bf28478ecd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-10 00:26:52` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf5be826908833f55e850ea0ba85d3e6` |
| SHA-1 | `d67a15dd0a498dce033bb588377485aa038e545f` |
| SHA-256 | `6eba72e816768b1c383487af637ddc3d64e5feacaed1bd7312b983bf28478ecd` |
| SHA3-384 | `956e21c8d2f6d21211739a6abd2bfec43224cc07c9cc1c4d49b6569d4616d796d90e46077029060b07eda7c278d407c6` |
| TLSH | `T1C6C5F1383CFB501DE173FF716EE8799ADD9FBA33260A645A204503478B12A81EE5253D` |
| SSDEEP | `24576:evzqEiCYdfvuxgDnn3/MAj351zcU/xj/irv7HthfzT6CM3:J2YdfWC/vcUVijv2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_6eba72e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eba72e816768b1c383487af637ddc3d64e5feacaed1bd7312b983bf28478ecd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-10 00:26:52"
  condition:
    hash.sha256(0, filesize) == "6eba72e816768b1c383487af637ddc3d64e5feacaed1bd7312b983bf28478ecd"
}
```

### Sample 39: `dc5422ec75cbe6a1`

| Field | Value |
|---|---|
| SHA-256 | `dc5422ec75cbe6a12f2788a310f2f487e1be22768ca7b0db5aae3f17b90b19e0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-10 00:21:18` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b3adecca1b94e59e4c37ed240f5ef6e` |
| SHA-1 | `9f724cbd9e6a661d0ac1a389c137d520ec0fcc31` |
| SHA-256 | `dc5422ec75cbe6a12f2788a310f2f487e1be22768ca7b0db5aae3f17b90b19e0` |
| SHA3-384 | `f68f3895cf7af1cab30c19d4acc67fb981e6097cc74e240f8f67f9bc06e68326381007f8287f5ae92a35867c19743698` |
| TLSH | `T1F0D501383CFB502DE173FF716EE879DADD9FBA322606645A204503478B12A81EE5253D` |
| SSDEEP | `24576:5AylvdqEiCYbk4BueslzpixhdustgNf/H8vp12odD3dXEh6EO:582YJ+IxbC38vr2odKs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_dc5422ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5422ec75cbe6a12f2788a310f2f487e1be22768ca7b0db5aae3f17b90b19e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-10 00:21:18"
  condition:
    hash.sha256(0, filesize) == "dc5422ec75cbe6a12f2788a310f2f487e1be22768ca7b0db5aae3f17b90b19e0"
}
```

### Sample 40: `6a207057c4750722`

| Field | Value |
|---|---|
| SHA-256 | `6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649` |
| Family label | `unknown` |
| File name | `6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649` |
| File type | `elf` |
| First seen | `2026-08-10 00:20:39` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ebf523f65ced692e45eb1f6367d4e95` |
| SHA-1 | `6ccd1ea583ac5571dbec293710b92c7acd8b49b3` |
| SHA-256 | `6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649` |
| SHA3-384 | `64e500b64c58233ce6bce9a39206f1c17b269da1503f23c21932939b46c7e1130b870dfa13b3ba52bbc27e2658b8fea7` |
| TLSH | `T16325337DAF1C9AEC433A971835B1D24B8EC1F8967B27540624BD82F853EEDD36C12468` |
| SSDEEP | `24576:lertoMkebO9ErP4/kuxwn4ZCKBAvck/X3Sh5GrMOZrwUUkya8:YrtUegEsxwWb+vck/XialwAya8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_6a207057
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649"
    family = "unknown"
    file_name = "6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649"
    file_type = "elf"
    first_seen = "2026-08-10 00:20:39"
  condition:
    hash.sha256(0, filesize) == "6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649"
}
```

### Sample 41: `0a3e9686877a670b`

| Field | Value |
|---|---|
| SHA-256 | `0a3e9686877a670b85b55c614b53decbdc97988605ac1c2fdcf2b56e25e080c6` |
| Family label | `unknown` |
| File name | `PFTZZN.478.dec` |
| File type | `exe` |
| First seen | `2026-08-10 00:05:53` |
| Reporter | `johnk3r` |
| Tags | `exe, latam, mosquito, ssl-fic20-com, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9380b0cef1b1af5e53f4bae55392404e` |
| SHA-1 | `f2a34ff72fa8f13ca322cadc9a1f2e36dfb5de54` |
| SHA-256 | `0a3e9686877a670b85b55c614b53decbdc97988605ac1c2fdcf2b56e25e080c6` |
| SHA3-384 | `214b531525893575463e6c5a3e293b4685d29a37b9d68a3151bb6181c9f50e0f43fd3e8a2a0dbbedcdcf5a11015d40ff` |
| IMPHASH | `bcb151cdaa5a26bccf82eb41d5b5df24` |
| TLSH | `T19F857E57F2B400B9D4A7C17989471907EBB278061774E7DF17A08AAA6F23FE1167E320` |
| SSDEEP | `24576:p1nCWu7ciCJKB0YETD3nUKbewsTqC6Yu4RZUmDXQ6Gex7gYbdgNgIaH7h+skNIBO:p1Hu8RYEf3nUzu/a1DXMgIaR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_0a3e9686
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a3e9686877a670b85b55c614b53decbdc97988605ac1c2fdcf2b56e25e080c6"
    family = "unknown"
    file_name = "PFTZZN.478.dec"
    file_type = "exe"
    first_seen = "2026-08-10 00:05:53"
  condition:
    hash.sha256(0, filesize) == "0a3e9686877a670b85b55c614b53decbdc97988605ac1c2fdcf2b56e25e080c6"
}
```

### Sample 42: `43b7219764a030a1`

| Field | Value |
|---|---|
| SHA-256 | `43b7219764a030a1b3f8466421890f8433928152aee42a497d0d2e4ed1284a98` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 23:58:10` |
| Reporter | `Bitsight` |
| Tags | `37412fcd9a39df7667b49f4bab671219, dropped-by-Vidar, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bee1f8ccea4644eb6996d611ec5c0daf` |
| SHA-1 | `cc6a9016d61353a03de40295824df5b92e76381d` |
| SHA-256 | `43b7219764a030a1b3f8466421890f8433928152aee42a497d0d2e4ed1284a98` |
| SHA3-384 | `9620378fc168f4f027f2755ad10a2ef5504052fb0c51de13cc4e27d15c71d484169539c06244f4d98b5b3ecb79a5292d` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T11254CE85B6A290FCE1B7847888721E12FB363D5507109BBF2350867ABF535A0BD19F26` |
| SSDEEP | `6144:4sRVrlS/S4uIBdW5sHZWYW88qeLNt2A0m94RKVUJDh:dVrlS/SNIXXHvW80H2LUVUJDh` |
| ICON-DHASH | `e4e8d49494b4d4cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_43b72197
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43b7219764a030a1b3f8466421890f8433928152aee42a497d0d2e4ed1284a98"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 23:58:10"
  condition:
    hash.sha256(0, filesize) == "43b7219764a030a1b3f8466421890f8433928152aee42a497d0d2e4ed1284a98"
}
```

### Sample 43: `1486367f2721ec26`

| Field | Value |
|---|---|
| SHA-256 | `1486367f2721ec266fc2df924c9f240572a01af6564a7ea8091550c552e93cce` |
| Family label | `unknown` |
| File name | `E0D1751CC03E266E5C44CA729DB16D6E.exe` |
| File type | `exe` |
| First seen | `2026-08-09 23:55:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b55b633c2633fa7eb4d8747cb223b7a4` |
| SHA-1 | `add72fffd804af3bb62fc609fbbd48156fd935e3` |
| SHA-256 | `1486367f2721ec266fc2df924c9f240572a01af6564a7ea8091550c552e93cce` |
| SHA3-384 | `8d60c3cb64ed188e83d4206a38b98604e949e9ce89a9ef81afbfe8ef4db8b0ae3aac0f6a3e2d801b966efb2e35d62791` |
| IMPHASH | `f2da2e4c1b5a39d16c40d60cec2608d7` |
| TLSH | `T17875E083B3DD82A1C6715133BA66BB416E7B7C2505B0F4AB2FC9153DAD70162423EA73` |
| SSDEEP | `24576:54lavt0LkLL9IMixoEFNYjxjx1SUuUS8IWW5sPZy14JwK4xuQ86E80Vq9MmCS:Ikwkn9IMSNYjxVkiwWXqRilaPCS` |
| ICON-DHASH | `3480e8e8c0c7f2e1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_1486367f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1486367f2721ec266fc2df924c9f240572a01af6564a7ea8091550c552e93cce"
    family = "unknown"
    file_name = "E0D1751CC03E266E5C44CA729DB16D6E.exe"
    file_type = "exe"
    first_seen = "2026-08-09 23:55:34"
  condition:
    hash.sha256(0, filesize) == "1486367f2721ec266fc2df924c9f240572a01af6564a7ea8091550c552e93cce"
}
```

### Sample 44: `f5c235bf56a9c15a`

| Field | Value |
|---|---|
| SHA-256 | `f5c235bf56a9c15afb65f83f437678cd6fac7e23b9a850b7806d395f4b778948` |
| Family label | `unknown` |
| File name | `geometrydash.apk` |
| File type | `elf` |
| First seen | `2026-08-09 23:55:16` |
| Reporter | `emmanualopsecgo` |
| Tags | `dongfeng-skidrip, elf, linfeng` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dec6d3df7a65c976807fe9d9aac6798` |
| SHA-256 | `f5c235bf56a9c15afb65f83f437678cd6fac7e23b9a850b7806d395f4b778948` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_f5c235bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c235bf56a9c15afb65f83f437678cd6fac7e23b9a850b7806d395f4b778948"
    family = "unknown"
    file_name = "geometrydash.apk"
    file_type = "elf"
    first_seen = "2026-08-09 23:55:16"
  condition:
    hash.sha256(0, filesize) == "f5c235bf56a9c15afb65f83f437678cd6fac7e23b9a850b7806d395f4b778948"
}
```

### Sample 45: `1cd822b584795da0`

| Field | Value |
|---|---|
| SHA-256 | `1cd822b584795da0981798fd11958635deaccc72b50ba2a6c3e9981fa4f94c29` |
| Family label | `Loda` |
| File name | `E0D1751CC03E266E5C44CA729DB16D6E.exe` |
| File type | `exe` |
| First seen | `2026-08-09 23:55:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, Loda, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0d1751cc03e266e5c44ca729db16d6e` |
| SHA-1 | `dcfd9cda93ffe7744830b39c89c06a42ed9e02ab` |
| SHA-256 | `1cd822b584795da0981798fd11958635deaccc72b50ba2a6c3e9981fa4f94c29` |
| SHA3-384 | `113bc101536c242726498ee738ad33b07a9fdd024d3646b6e5c4ad927d70c1a9419184ebc47f8f3bd7f0c8f4432040a6` |
| IMPHASH | `ef471c0edf1877cd5a881a6a8bf647b9` |
| TLSH | `T1424512C2EA1594C2F839907461BB5E961A667C7B8CB426B9324EF2342DF131314B7D2F` |
| SSDEEP | `24576:/hloDX0XOf4wvjGmSUuo8IWW5sPZy14JwK4xuQ86E8m:/hloJf9vyP0WXqRi` |
| ICON-DHASH | `3480e8e8c0c7f2e1` |

#### Technical Assessment

- The sample is tracked as `Loda` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Loda_045_1cd822b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cd822b584795da0981798fd11958635deaccc72b50ba2a6c3e9981fa4f94c29"
    family = "Loda"
    file_name = "E0D1751CC03E266E5C44CA729DB16D6E.exe"
    file_type = "exe"
    first_seen = "2026-08-09 23:55:04"
  condition:
    hash.sha256(0, filesize) == "1cd822b584795da0981798fd11958635deaccc72b50ba2a6c3e9981fa4f94c29"
}
```

### Sample 46: `f116c0400a9cd5d5`

| Field | Value |
|---|---|
| SHA-256 | `f116c0400a9cd5d5629bdf6453cabaa4f1715a042d4efd6e5882f30f6642c1aa` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 23:19:10` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84723ecd740f5600c7d53eb17af748fe` |
| SHA-1 | `4a580fc0decf1c7e3496f86ca9f31794c6f18e6e` |
| SHA-256 | `f116c0400a9cd5d5629bdf6453cabaa4f1715a042d4efd6e5882f30f6642c1aa` |
| SHA3-384 | `ce4914a3ceced842b29388c04b68d3df8f8eb08935400b418fa93d7e2cb6a5ef8a0029a6061dbe4e72e0151639d3b017` |
| IMPHASH | `2b1576a7a1f4aa6570bb1a33aca4c56e` |
| TLSH | `T1A4933A01F590A07FF9EA81FAD2F24A69582CFF74134984E39290755B97206EEFC7502B` |
| SSDEEP | `1536:iBHfP6Fmav8214fM5HKBRe/hKM82BqjhqRDh4pGreXA:A/pOyfUHKy/Y32QjU4pGreXA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_f116c040
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f116c0400a9cd5d5629bdf6453cabaa4f1715a042d4efd6e5882f30f6642c1aa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 23:19:10"
  condition:
    hash.sha256(0, filesize) == "f116c0400a9cd5d5629bdf6453cabaa4f1715a042d4efd6e5882f30f6642c1aa"
}
```

### Sample 47: `8c78a55c8bf545e0`

| Field | Value |
|---|---|
| SHA-256 | `8c78a55c8bf545e0d21b8757eaa0b709b4af47b13d34a38df81045e67026bd96` |
| Family label | `unknown` |
| File name | `sostener2.vbs` |
| File type | `unknown` |
| First seen | `2026-08-09 23:06:15` |
| Reporter | `skocherhan` |
| Tags | `asegurar2026-duckdns-org` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc4096d29c2e1ac9c95f739693069730` |
| SHA-256 | `8c78a55c8bf545e0d21b8757eaa0b709b4af47b13d34a38df81045e67026bd96` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_8c78a55c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c78a55c8bf545e0d21b8757eaa0b709b4af47b13d34a38df81045e67026bd96"
    family = "unknown"
    file_name = "sostener2.vbs"
    file_type = "unknown"
    first_seen = "2026-08-09 23:06:15"
  condition:
    hash.sha256(0, filesize) == "8c78a55c8bf545e0d21b8757eaa0b709b4af47b13d34a38df81045e67026bd96"
}
```

### Sample 48: `e2a6e93cf04fdeaf`

| Field | Value |
|---|---|
| SHA-256 | `e2a6e93cf04fdeafa93bb6e541107f5bfcf78ab79d92f1bf51c69de1d4f55433` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-09 22:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46a756241e8102202f1b88f2c0e7f3ad` |
| SHA-1 | `0ac690713b39aaff48f6ec5f7fc359ab107898ee` |
| SHA-256 | `e2a6e93cf04fdeafa93bb6e541107f5bfcf78ab79d92f1bf51c69de1d4f55433` |
| SHA3-384 | `8972cda8b91a07f51c580087c5d14f761405159870dfba884b300950f46a24ae6912849ff6dd739384dd440d70e48038` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T13DE6338877E11AFEC9B7D03DEDE02210F5B5B8265B71C9E74B6497A62C231D04938B63` |
| SSDEEP | `393216:OGmToWNkwTEQ8asYJzU8FezXMCHWUjCLcuI3/PGTAI:OG8Au78u+oezXMb8CoH/O7` |
| ICON-DHASH | `40b960c0dc797204` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_e2a6e93c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2a6e93cf04fdeafa93bb6e541107f5bfcf78ab79d92f1bf51c69de1d4f55433"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 22:52:30"
  condition:
    hash.sha256(0, filesize) == "e2a6e93cf04fdeafa93bb6e541107f5bfcf78ab79d92f1bf51c69de1d4f55433"
}
```

### Sample 49: `c7cf596bfb34b831`

| Field | Value |
|---|---|
| SHA-256 | `c7cf596bfb34b83148bfc5d0bc17cc559fcda297d8308da9a3a71a82d5cba5e0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 22:47:03` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4b278286395369f441922b191b4ebe0` |
| SHA-1 | `196e91da9ec9088b1538c152a74d0a8d76af27b8` |
| SHA-256 | `c7cf596bfb34b83148bfc5d0bc17cc559fcda297d8308da9a3a71a82d5cba5e0` |
| SHA3-384 | `6764300ef39684de63cd66a9d95be7f24396c149d388b17d682b2ef7940dd05207925e43ba26ed270e1ab38a3a70fef8` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T139D61237B28AE53EE16E4A3619B3D154583B7AA1AC134D0AD6F4445CCF2A1A03E3F747` |
| SSDEEP | `98304:YAX7lKPmXywDKLC85LEsromuyBhY+LIizApRx5KUNG7jC2sRtb4TGCNkDfpY6JL1:nlzyaKLP/omRCGIi0pEU0jaHb4Za8` |
| ICON-DHASH | `20585860e0e064b4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_c7cf596b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7cf596bfb34b83148bfc5d0bc17cc559fcda297d8308da9a3a71a82d5cba5e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 22:47:03"
  condition:
    hash.sha256(0, filesize) == "c7cf596bfb34b83148bfc5d0bc17cc559fcda297d8308da9a3a71a82d5cba5e0"
}
```

### Sample 50: `c353b5ebbf55e2cd`

| Field | Value |
|---|---|
| SHA-256 | `c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869` |
| Family label | `unknown` |
| File name | `c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869.bin` |
| File type | `unknown` |
| First seen | `2026-08-09 22:19:46` |
| Reporter | `Tuxxin` |
| Tags | `ClickFix, jpg, stego, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11ee77249be69c3a6e401474ce2776af` |
| SHA-256 | `c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_c353b5eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869"
    family = "unknown"
    file_name = "c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869.bin"
    file_type = "unknown"
    first_seen = "2026-08-09 22:19:46"
  condition:
    hash.sha256(0, filesize) == "c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869"
}
```

### Sample 51: `3341d939b43c52d0`

| Field | Value |
|---|---|
| SHA-256 | `3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87` |
| Family label | `unknown` |
| File name | `3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87.bin` |
| File type | `unknown` |
| First seen | `2026-08-09 22:19:32` |
| Reporter | `Tuxxin` |
| Tags | `loader, NetSupport, png, RAT, stego, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbca97335b2ed4e992610e5662a14b46` |
| SHA-256 | `3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_3341d939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87"
    family = "unknown"
    file_name = "3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87.bin"
    file_type = "unknown"
    first_seen = "2026-08-09 22:19:32"
  condition:
    hash.sha256(0, filesize) == "3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87"
}
```

### Sample 52: `80feaa2945c81e75`

| Field | Value |
|---|---|
| SHA-256 | `80feaa2945c81e75c5045e9e403bff5e8914f4691e525eee5064c04d3ab421a6` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-09 21:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cef8b2ae86398ea943b0d8ba59ccf36c` |
| SHA-1 | `1e7bab3893d9a9e4402f18a80e64ee1fc0a38e9a` |
| SHA-256 | `80feaa2945c81e75c5045e9e403bff5e8914f4691e525eee5064c04d3ab421a6` |
| SHA3-384 | `6e345538b27022843fcb619759f828599f96e303b19ebb91ee41d85bc2aede40e94155010181f90c60a32d0faa951f45` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DCE6330826C002EFD6F3833CACB217A1E6B5B45A5775C99B47E447652D932E24E3DB32` |
| SSDEEP | `393216:PGmiEw154IJ9Zmiw/cppL386I0TXMCHWUjfcuI3/PGTAI:PG3BzfZX0CpM6IcXMb80H/O7` |
| ICON-DHASH | `e8e865e0d9e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_80feaa29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80feaa2945c81e75c5045e9e403bff5e8914f4691e525eee5064c04d3ab421a6"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 21:52:28"
  condition:
    hash.sha256(0, filesize) == "80feaa2945c81e75c5045e9e403bff5e8914f4691e525eee5064c04d3ab421a6"
}
```

### Sample 53: `629cfb8d9fcb99aa`

| Field | Value |
|---|---|
| SHA-256 | `629cfb8d9fcb99aa0083415da49692ce4c94ecf01ed173e628a8ea8a9d4a5cf9` |
| Family label | `unknown` |
| File name | `WatchForParty Setup 1.2.0.exe` |
| File type | `exe` |
| First seen | `2026-08-09 21:46:49` |
| Reporter | `JaffaCakes118` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9777f980cd8762d7253e4cc776dda7c0` |
| SHA-1 | `7820a8f3ce9ca53b0cb30e0aca27ef407de0608e` |
| SHA-256 | `629cfb8d9fcb99aa0083415da49692ce4c94ecf01ed173e628a8ea8a9d4a5cf9` |
| SHA3-384 | `9c075b58d2411d445b40589848a57707bfbe84ee3cfe7b8a95e9a206bfb2c09420210911b3ed53b932054764cefd5f53` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1B9083336AAF13470C7C58E321A1555A3009DE18F51977E78B379B27FA21A281C2C6FED` |
| SSDEEP | `1572864:eb2um4Ndc2Vq4ujn8KOY8ZwK1JIr+c3O7qYzhdhPtGwaK2Q+EdPpXt:ebTm4PHq4uj8A8ZwewNgqYtT0FKN/Xt` |
| ICON-DHASH | `f8f0c6e8b886ccf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_629cfb8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629cfb8d9fcb99aa0083415da49692ce4c94ecf01ed173e628a8ea8a9d4a5cf9"
    family = "unknown"
    file_name = "WatchForParty Setup 1.2.0.exe"
    file_type = "exe"
    first_seen = "2026-08-09 21:46:49"
  condition:
    hash.sha256(0, filesize) == "629cfb8d9fcb99aa0083415da49692ce4c94ecf01ed173e628a8ea8a9d4a5cf9"
}
```

### Sample 54: `aeede7ef5532b1a2`

| Field | Value |
|---|---|
| SHA-256 | `aeede7ef5532b1a261640e1b8becabb87619adb893cb7a5a7c9e45e1397b7214` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-08-09 21:38:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1f1de771b0d12ce5aa85deab8fbc87d` |
| SHA-1 | `19b259e28ecc6e5287af92525592e463367fa9fc` |
| SHA-256 | `aeede7ef5532b1a261640e1b8becabb87619adb893cb7a5a7c9e45e1397b7214` |
| SHA3-384 | `1bbc3d93c5d76c0820cba56745ed57f59d6b24be5c13185082e4535be6ccb5f5c31527cba7ccc5adedfd13e90e120049` |
| TLSH | `T148F32B46E7418A13C0D2177ABADF424533239B64D3DB33069928BFB43F8679E4E67606` |
| TELFHASH | `t13931ff325721411a6e51cc64dcee57f1251d86172744ee33ef36c8cc651a49af62bc4f` |
| SSDEEP | `3072:D2lRn0/VCaaQ5QSyQNDE0k2Rv6VpuQbCexM/9DT80:D2laNCaaQ5QSymEaRiVcQbCEM/9DT80` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_aeede7ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeede7ef5532b1a261640e1b8becabb87619adb893cb7a5a7c9e45e1397b7214"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:45"
  condition:
    hash.sha256(0, filesize) == "aeede7ef5532b1a261640e1b8becabb87619adb893cb7a5a7c9e45e1397b7214"
}
```

### Sample 55: `f9fc8919461bc8a4`

| Field | Value |
|---|---|
| SHA-256 | `f9fc8919461bc8a4e023fd4e155edb29cefe60d5ff60ec4d9dee34dbe608b7de` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-09 21:38:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50bb34c9d0bcbbff9d07d86301e1b19d` |
| SHA-1 | `3aa20116fa903b500d13364eb81f1866ede8c026` |
| SHA-256 | `f9fc8919461bc8a4e023fd4e155edb29cefe60d5ff60ec4d9dee34dbe608b7de` |
| SHA3-384 | `ae6ab4eda98b8b065a40fd309e192e9400e957f8ba9ef380606c43f48e5d9e1c59642a27e01b50cd0701a8c5ecc33a7f` |
| TLSH | `T135535AC8AA43D8F6FD5241712133EB378636F139112DEA87C7A9DD36AC52900EA5739C` |
| TELFHASH | `t1ba31c2f72eae09ecb7d5a808c30a1fd32935d6bb1a6072b145b1285123f3d81507ad75` |
| SSDEEP | `1536:KhberOEn3VfK+naUZGxt9V82YdQs3EFTwVfudVFUHWdI1wubjariXY:KhELn3VfKpJVW3qsudVKHWYwX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_f9fc8919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9fc8919461bc8a4e023fd4e155edb29cefe60d5ff60ec4d9dee34dbe608b7de"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:42"
  condition:
    hash.sha256(0, filesize) == "f9fc8919461bc8a4e023fd4e155edb29cefe60d5ff60ec4d9dee34dbe608b7de"
}
```

### Sample 56: `228d7fb728de73c7`

| Field | Value |
|---|---|
| SHA-256 | `228d7fb728de73c767ce29a875a51166c20e1337bca94a95df59472fe8129d3a` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-08-09 21:38:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f424a3d603c8bb20582b09b368f1b027` |
| SHA-1 | `0d06e3a5d7bbf878d62c0ce4673ed73edc9e8cdf` |
| SHA-256 | `228d7fb728de73c767ce29a875a51166c20e1337bca94a95df59472fe8129d3a` |
| SHA3-384 | `1f7a9b8ae7a53f15b3774602768dfa17632f6adf0d6e53abdc2dbd103137d795663f4ce0664f4bfb22cff5850c8ac13c` |
| TLSH | `T161732981BC815713C6D012BBFB5E428E372653A8D2EF72179D226F21378786B0E77652` |
| TELFHASH | `t19e51e0b69ba90adc8bd0c648c18e613e2fed365d9710292ac34daf4f86836c1b51d437` |
| SSDEEP | `1536:mqloqjP80Oe95dXwmIDcl+T20aPdhEjvzs/h3:mqlHpXwmvw2T42` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_228d7fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "228d7fb728de73c767ce29a875a51166c20e1337bca94a95df59472fe8129d3a"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:40"
  condition:
    hash.sha256(0, filesize) == "228d7fb728de73c767ce29a875a51166c20e1337bca94a95df59472fe8129d3a"
}
```

### Sample 57: `859c7ea1bd8957ab`

| Field | Value |
|---|---|
| SHA-256 | `859c7ea1bd8957aba1507f9b63c8717fb8cfe39632c05d00b47edece313fd775` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-09 21:38:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74bf0d3fa579c0514b1ac9e7b2575431` |
| SHA-1 | `de6e2cbbfe1217878bce751a60de85ec1e18720f` |
| SHA-256 | `859c7ea1bd8957aba1507f9b63c8717fb8cfe39632c05d00b47edece313fd775` |
| SHA3-384 | `a48cbebb151b28a6a5132629ea5aabd0302d0a6b045d47dd617bf8031516021678fc43f621a1fdacdde9e97b0f98571b` |
| TLSH | `T11E83F856B8814B12D5D512BEFA1E118E3323177CE3DE73129E206F20778B96B0E7B916` |
| TELFHASH | `t1771190700a8999d87e20ce8887ceb1a579433872ab6519464f6b7d4b43922d2772581f` |
| SSDEEP | `1536:OjniCdB6iAA67Fm7X+ZlI959EaO9vVQnMTioSpfsnZcO7Se54YSs/hG:eP6iOA+Zm959EaOqpfsnZcOWe+H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_859c7ea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "859c7ea1bd8957aba1507f9b63c8717fb8cfe39632c05d00b47edece313fd775"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:35"
  condition:
    hash.sha256(0, filesize) == "859c7ea1bd8957aba1507f9b63c8717fb8cfe39632c05d00b47edece313fd775"
}
```

### Sample 58: `a610644ce6bd9531`

| Field | Value |
|---|---|
| SHA-256 | `a610644ce6bd9531062134b5a017f5339edcb79bdd247cb7c4acf32c2d147b6f` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `370adbcaf76e11d71a84bd4084a3edf3` |
| SHA-1 | `7da06bf70ef5715d5b2bc1ce452a29a5060b2cc4` |
| SHA-256 | `a610644ce6bd9531062134b5a017f5339edcb79bdd247cb7c4acf32c2d147b6f` |
| SHA3-384 | `42c76cfffde4b04cb96f47ce02e2798f0ca84d2572cdf434b6b3f8b42d3d1e711fd9024fefc6ecda7b07cac50d466686` |
| TLSH | `T11E539E73C63E2E54C19582B4B8709E751BA3F54082975FFA1A96C2B99083DECF6093F4` |
| SSDEEP | `1536:3LwtVRCFOcpD5o/KloeemSyiCSY5T+8zs/nz:3LQCQcptoillSyiuNDM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_a610644c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a610644ce6bd9531062134b5a017f5339edcb79bdd247cb7c4acf32c2d147b6f"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:53"
  condition:
    hash.sha256(0, filesize) == "a610644ce6bd9531062134b5a017f5339edcb79bdd247cb7c4acf32c2d147b6f"
}
```

### Sample 59: `0f731dea0d5ade4a`

| Field | Value |
|---|---|
| SHA-256 | `0f731dea0d5ade4a346204d58d650eb8833a2d5958078320e4035e4d06bf4045` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71e144411742f910c7a22ffaf29c4bfc` |
| SHA-1 | `c1e247955017df8c1fada3573fc7097879404546` |
| SHA-256 | `0f731dea0d5ade4a346204d58d650eb8833a2d5958078320e4035e4d06bf4045` |
| SHA3-384 | `c75db5d4c8d8899925a69b767b84b1e91b3023e23da9f2c9d40ca7e8c0ceb7675ab7dc71800e3b0d0c8b5a357b57cede` |
| TLSH | `T19C734B22BA751D2BC4D4E87A61F30321F2F2478A25ACCA1A7D720D4DBF65A4032577F9` |
| SSDEEP | `1536:nJxSUCuRy82KFEFfkhsxQ+tBPznN95YYsP08tu8/1e:JIwaFchUDDNPVSe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_0f731dea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f731dea0d5ade4a346204d58d650eb8833a2d5958078320e4035e4d06bf4045"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:51"
  condition:
    hash.sha256(0, filesize) == "0f731dea0d5ade4a346204d58d650eb8833a2d5958078320e4035e4d06bf4045"
}
```

### Sample 60: `3dcf0133640f73c2`

| Field | Value |
|---|---|
| SHA-256 | `3dcf0133640f73c2a0e0ae748b927aec4d698036bdb213b16306da558499e1c9` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dffdf78211a5f119438bedb4ea05569` |
| SHA-1 | `358b854f0c93b9649b7f801d98b7b5ce95266e10` |
| SHA-256 | `3dcf0133640f73c2a0e0ae748b927aec4d698036bdb213b16306da558499e1c9` |
| SHA3-384 | `f623169cbfaae651fdce6d00bb03fcff5583f617b700e5c4b9459957db71d8722d880a551fbfed191c0f86f699d93091` |
| TLSH | `T19E4301C94191ED77C3B55CF1BAAE4806639B9FB4A12F2588C024158DACECF92B45DC83` |
| SSDEEP | `1536:m9CyU2qRwBCOBnEJn7ml+HC+yAgjkLFeSaS8SBlJm:m9tlB9Bg7xi+yAykLFRNHDm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_3dcf0133
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dcf0133640f73c2a0e0ae748b927aec4d698036bdb213b16306da558499e1c9"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:50"
  condition:
    hash.sha256(0, filesize) == "3dcf0133640f73c2a0e0ae748b927aec4d698036bdb213b16306da558499e1c9"
}
```

### Sample 61: `a09a3ac37a49a36a`

| Field | Value |
|---|---|
| SHA-256 | `a09a3ac37a49a36a0ae56159890f44be2b98d2539a0083eeaac9ef06df293b11` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79ade8a56d83d346b024affa0469086f` |
| SHA-1 | `12fddf7f280158f30730c9b5a5ad5e9290830cd8` |
| SHA-256 | `a09a3ac37a49a36a0ae56159890f44be2b98d2539a0083eeaac9ef06df293b11` |
| SHA3-384 | `d863c63d5302f8f38978f29e7762b3a1255d15de162010eb013cbf30859aef8c6640e46493625fdccaca0cb3afa84c20` |
| TLSH | `T1D7E2E16891DD0121F7FE537BE5EAD886F43098E2079BC90134D15B7538BB230DB5A942` |
| SSDEEP | `768:iIPBQe76Dx/Ah2ZAGaozPZgdcPuWYFSUXOCt9UHfw0pdbS/u/q:iIPBb6Dxogn8aPRAXOCt9UHo0nbty` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_a09a3ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a09a3ac37a49a36a0ae56159890f44be2b98d2539a0083eeaac9ef06df293b11"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:49"
  condition:
    hash.sha256(0, filesize) == "a09a3ac37a49a36a0ae56159890f44be2b98d2539a0083eeaac9ef06df293b11"
}
```

### Sample 62: `225180eedf6fa953`

| Field | Value |
|---|---|
| SHA-256 | `225180eedf6fa9533eb28c6e060e40c71a04c0a12cb1fb6a5d67a917855c3287` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fc4e264db846275b962ad445d3beaa0` |
| SHA-1 | `2164e36d90af5fc5db2ad011c5b36b0571faca83` |
| SHA-256 | `225180eedf6fa9533eb28c6e060e40c71a04c0a12cb1fb6a5d67a917855c3287` |
| SHA3-384 | `c3662d8923ac74dbdf6e7f83fff04949f96b53e58440a03d8472de89dde63f9a07c0914340b88e32cd4539c3feef691e` |
| TLSH | `T175F2E1F0054726A0C2946077C5788D8A177A4B79E4F9B64D340417D7BEE244FBAFC19E` |
| SSDEEP | `768:59QZbkBAGhUkqA697hcYgAYsPbW3iIJs3Uoz/:fQZWWkqA69VxgAYsPbpPz/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_225180ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "225180eedf6fa9533eb28c6e060e40c71a04c0a12cb1fb6a5d67a917855c3287"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:47"
  condition:
    hash.sha256(0, filesize) == "225180eedf6fa9533eb28c6e060e40c71a04c0a12cb1fb6a5d67a917855c3287"
}
```

### Sample 63: `db536bc1e79bfdfa`

| Field | Value |
|---|---|
| SHA-256 | `db536bc1e79bfdfaf454199e1eec59c34e8168028c30f24f4f1962314b150cd0` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e5dea3581b8c9967f9e1d16e034ec64` |
| SHA-1 | `88471b5fef6b70c7162d8dea478c6ea3e8eb874f` |
| SHA-256 | `db536bc1e79bfdfaf454199e1eec59c34e8168028c30f24f4f1962314b150cd0` |
| SHA3-384 | `4c02f557a09ba53638446520a459d71b5c593f4603480352f84d66e5ee56ce2dc1082381c5be791a0f97f3e883c17d3c` |
| TLSH | `T1CB03F2DDD8E87C90CD9E0F79520C1B350D59F0C1719D872FAB860DCEE1B9982FA86164` |
| SSDEEP | `768:BBoq+Ugdom7WdflNgBXo0uWSXxKTGGcXEBDXveuuAoAI/PbFK6NtuW0dcWlA:EdHom7cvgBwWS0yG6Et2XAoAI/xKs1O4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_db536bc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db536bc1e79bfdfaf454199e1eec59c34e8168028c30f24f4f1962314b150cd0"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:46"
  condition:
    hash.sha256(0, filesize) == "db536bc1e79bfdfaf454199e1eec59c34e8168028c30f24f4f1962314b150cd0"
}
```

### Sample 64: `cb28ac52b01aae74`

| Field | Value |
|---|---|
| SHA-256 | `cb28ac52b01aae74781bfd0e606238d6a6d0d86565f29402f5578d64aafcfadf` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba80fd0a6b3ee93fc188f15c6570a195` |
| SHA-1 | `0fa554b5c8a7b8f1783aeb37be5d04e9b3218858` |
| SHA-256 | `cb28ac52b01aae74781bfd0e606238d6a6d0d86565f29402f5578d64aafcfadf` |
| SHA3-384 | `7255f7aded8c766958dde5e44a5a31364608742ce420dea9adf9cb442ea55252e0769c5721653ef5fcc90349e9c4071e` |
| TLSH | `T12103E16DE54259B1CB3198B9FB2802C73EB40DFE806EB56E3258918935C1B45139E7C2` |
| SSDEEP | `768:VtGPdEKjRtShV3SfCvZeQpo/FiLUyG9O6LWNNFx9q3UELUFe:LK+4yNo9iLlGxWN0Ld` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_cb28ac52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb28ac52b01aae74781bfd0e606238d6a6d0d86565f29402f5578d64aafcfadf"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:45"
  condition:
    hash.sha256(0, filesize) == "cb28ac52b01aae74781bfd0e606238d6a6d0d86565f29402f5578d64aafcfadf"
}
```

### Sample 65: `057b81202f6505c2`

| Field | Value |
|---|---|
| SHA-256 | `057b81202f6505c2024a273f065ec606994ab42d6326be506676d88ec03320a9` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-08-09 21:37:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a06cac3db099561b11397a214b344860` |
| SHA-1 | `d773fb16e59f51f1f9667e64840d7d639c2ef25d` |
| SHA-256 | `057b81202f6505c2024a273f065ec606994ab42d6326be506676d88ec03320a9` |
| SHA3-384 | `3230237e642ba24151b282a12f57c555a2ba472839f49d293c1f81c0451e4bb690e71a21b050ae46a279dfef1adbad90` |
| TLSH | `T1EE833AD7F801DDBDF80ED77B4453490AB231A3910A830F3A6757BA67ED321A45826EC2` |
| SSDEEP | `1536:ZjJGU386qYvQtGuNM6W8FwGXAyy/QKYVZJfC4IpehmFVbVXHtA:pJG8HYtGuNM66X9QNVzDhmFBZtA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_057b8120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057b81202f6505c2024a273f065ec606994ab42d6326be506676d88ec03320a9"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:43"
  condition:
    hash.sha256(0, filesize) == "057b81202f6505c2024a273f065ec606994ab42d6326be506676d88ec03320a9"
}
```

### Sample 66: `336b0f9c3a253185`

| Field | Value |
|---|---|
| SHA-256 | `336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9` |
| Family label | `CoinMiner` |
| File name | `336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9.exe` |
| File type | `exe` |
| First seen | `2026-08-09 21:28:45` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e46e4adb3748dcd996ca6cabafe2183` |
| SHA-1 | `cc420ef7024b2e119234e10a0b1be10c8149c067` |
| SHA-256 | `336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9` |
| SHA3-384 | `5c0daeeca0c6e817312ac367c7952c4d975ddd2498946cdc60044db271f578f387a80b12889404653f918e08ae92a37e` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T11A3633CB29DA2070E156C3B45253747FB27A7F719625BDCB36C929888D23E2C283E745` |
| SSDEEP | `98304:bzdYv9YhVTZrqFZcAaYURY4uqZBcvrmE9Mg3Rydytt/:bpiqh9ZOLcTnflOZt` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_066_336b0f9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9"
    family = "CoinMiner"
    file_name = "336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9.exe"
    file_type = "exe"
    first_seen = "2026-08-09 21:28:45"
  condition:
    hash.sha256(0, filesize) == "336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9"
}
```

### Sample 67: `aed1c085d62d724c`

| Field | Value |
|---|---|
| SHA-256 | `aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81` |
| Family label | `unknown` |
| File name | `aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81.bin` |
| File type | `unknown` |
| First seen | `2026-08-09 21:20:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9ba742cb679b2e33f14d1659bc16c6b` |
| SHA-256 | `aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_aed1c085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81"
    family = "unknown"
    file_name = "aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81.bin"
    file_type = "unknown"
    first_seen = "2026-08-09 21:20:14"
  condition:
    hash.sha256(0, filesize) == "aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81"
}
```

### Sample 68: `2c216e25c7b4fcde`

| Field | Value |
|---|---|
| SHA-256 | `2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc` |
| Family label | `unknown` |
| File name | `2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc.exe` |
| File type | `exe` |
| First seen | `2026-08-09 21:20:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37d294a2800b2becec9e5d08e5e91311` |
| SHA-1 | `23d563c1d4e9a1d03e0bc65f62c1ac96a09e554c` |
| SHA-256 | `2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc` |
| SHA3-384 | `a23b583ef56c86d6dfca0b291dee9bb90f370890a631e723b6d1884f657f30ab1737dc5044e669c21c07f77357d19229` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T17DD52385B1B6493AD836C3B28F93F56DB1B4B7848AB48D07BACC39014D53255993F3B2` |
| SSDEEP | `49152:/Voy0DYYmEsZWFY1sduPrPW0gDsZKKKxYAXT09bWbLM8ieR4STXp:RnX1skPbWhsZPKxNj0hWbQqRV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_2c216e25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc"
    family = "unknown"
    file_name = "2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc.exe"
    file_type = "exe"
    first_seen = "2026-08-09 21:20:10"
  condition:
    hash.sha256(0, filesize) == "2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc"
}
```

### Sample 69: `3c38434b6ab45e0f`

| Field | Value |
|---|---|
| SHA-256 | `3c38434b6ab45e0f4a2409cabd4bebfbbd1fbb3cc1b2d454180b4ea44b192a7d` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-08-09 21:03:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00ab717a1cce708ebcaccc4e4e903ff1` |
| SHA-1 | `963dd1b7917214586ab9a024654cd923ca6eb7a5` |
| SHA-256 | `3c38434b6ab45e0f4a2409cabd4bebfbbd1fbb3cc1b2d454180b4ea44b192a7d` |
| SHA3-384 | `a0df6ba68ebc26df9b2dcb3c8b1ea5f055074a5b62ee7a022e3f5c5d9c54ba7a9be359899429cbbc800a6c959a95045f` |
| TLSH | `T1FAC3122AC2E3F65A97F42E37D208D20EB62F41B5A15D21E1FB854E45FAC32191D3D1B8` |
| SSDEEP | `3072:zgwt10J52q0lK1XRF0VPv9brotdhluguLc05hOuaQXuI8ygz0vIxAXgpnZ:htkZ0jPVnIlm40rne1z0xX2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_3c38434b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c38434b6ab45e0f4a2409cabd4bebfbbd1fbb3cc1b2d454180b4ea44b192a7d"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-09 21:03:57"
  condition:
    hash.sha256(0, filesize) == "3c38434b6ab45e0f4a2409cabd4bebfbbd1fbb3cc1b2d454180b4ea44b192a7d"
}
```

### Sample 70: `c68b3590f893ae0a`

| Field | Value |
|---|---|
| SHA-256 | `c68b3590f893ae0a6155db05e88119cc958a76c2cf3f7168f12c7ccf5861ee45` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-08-09 20:57:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93c5600a0e20689939dd059820b34a10` |
| SHA-1 | `67c043084ab3774a79fc1e691db669d973a92826` |
| SHA-256 | `c68b3590f893ae0a6155db05e88119cc958a76c2cf3f7168f12c7ccf5861ee45` |
| SHA3-384 | `0ddc7c5f616a8f846a081849eac2dfcbc3b1693566999e4ca49c127e4587579785c52e3aecf7cc8acf4f5b0499c864a6` |
| TLSH | `T1D9436CD4E643D9F5E80B19B1113AF7375E31E0F82228EA93D7A4AA32BC53741E5469CC` |
| TELFHASH | `t17e2149e72e7255fdb7e0a408c72f7ae32676d963013065b841b31d8423f29c2853ac35` |
| SSDEEP | `1536:e5IzW32sRUqVZgwohemCS5Qb+ZTYgal5TTSFaz:YIq3FRUqVZgnsmCSGb+ZTNOT0e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_c68b3590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c68b3590f893ae0a6155db05e88119cc958a76c2cf3f7168f12c7ccf5861ee45"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-09 20:57:41"
  condition:
    hash.sha256(0, filesize) == "c68b3590f893ae0a6155db05e88119cc958a76c2cf3f7168f12c7ccf5861ee45"
}
```

### Sample 71: `ffbdd6701bc06df3`

| Field | Value |
|---|---|
| SHA-256 | `ffbdd6701bc06df37076a057f34a50ef286ff3c735e5c3fc1f9ca984e6c82871` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-09 20:52:27` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `294e18037789f83c17fb8b94f7251589` |
| SHA-1 | `9e0e759c9e82e18f7b6cf73160e6e998b969779b` |
| SHA-256 | `ffbdd6701bc06df37076a057f34a50ef286ff3c735e5c3fc1f9ca984e6c82871` |
| SHA3-384 | `efc7c2ee6dee294bc80e438bb53614e9d681b4c40e6ba614f2bd1039fe85da4ec17a8e193caf820fcc9f9b459ac20611` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T140E633486ED121EBD6B3823D9FD51250F57EB0B56731C7C74BB856B24E232E1093EA22` |
| SSDEEP | `393216:nfGmnOzLl0qEn+bq86GprMwwXMCHWUjscuI3/PGTAI:fGnN0Ln+3pQTXMb85H/O7` |
| ICON-DHASH | `54f8d0f0e0e8f0b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_ffbdd670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffbdd6701bc06df37076a057f34a50ef286ff3c735e5c3fc1f9ca984e6c82871"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 20:52:27"
  condition:
    hash.sha256(0, filesize) == "ffbdd6701bc06df37076a057f34a50ef286ff3c735e5c3fc1f9ca984e6c82871"
}
```

### Sample 72: `54d2f14a4e9e61de`

| Field | Value |
|---|---|
| SHA-256 | `54d2f14a4e9e61dec0954a2efe866753e2bf304b02313d468b273b32b84b2047` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-09 20:51:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c90fb8df78f0ebfd8624580b949018a3` |
| SHA-1 | `e47273bdddf55f0996ee2088c43b0353a20e8f97` |
| SHA-256 | `54d2f14a4e9e61dec0954a2efe866753e2bf304b02313d468b273b32b84b2047` |
| SHA3-384 | `2db100c1d3013e7e5f2f542f9715b85df0c9e75be407b9ccac2573b72f81279b7cb8815ee6042205565bc157b58dcdbe` |
| TLSH | `T109137D7BE46E5E54D0460230B4649F341F13F6C493536EBB1EAA82A15487AECF905FF8` |
| SSDEEP | `768:OaRH4ge4hYyFDinQT3yMILr7vade+7Cvo9az18C/Aw:OaRYghh/FmnQyMi/ad77X9W8C/h` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_54d2f14a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54d2f14a4e9e61dec0954a2efe866753e2bf304b02313d468b273b32b84b2047"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-09 20:51:43"
  condition:
    hash.sha256(0, filesize) == "54d2f14a4e9e61dec0954a2efe866753e2bf304b02313d468b273b32b84b2047"
}
```

### Sample 73: `5df7f62378cb073f`

| Field | Value |
|---|---|
| SHA-256 | `5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7` |
| Family label | `unknown` |
| File name | `5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7.exe` |
| File type | `exe` |
| First seen | `2026-08-09 20:50:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `144cc03241cc99db6779e5d9f7c09fc3` |
| SHA-1 | `d0a43ae2e268f8e8899e6a9625bcbfb9c425a3a0` |
| SHA-256 | `5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7` |
| SHA3-384 | `9b0560aeae8b0c3caa4ca0cecec31e17d178865c7162687b66305834376376b61cc109a263ca4aece18448c8356756eb` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1FDA5D03FB28B753EE06A5A3A7AB6E210543B7E61A4134C1696E4E44CCF350B01D3E797` |
| SSDEEP | `24576:AXNrSLScusMmOvjjhzvLJz236cLR9DC+UmvcnYTn0eaR+rE4mUzJFZhYJLchafH5:/uI2hQpLR91jUnc0r143zZ+vFOoljH` |
| ICON-DHASH | `f0d0b2b27286c460` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_5df7f623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7"
    family = "unknown"
    file_name = "5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7.exe"
    file_type = "exe"
    first_seen = "2026-08-09 20:50:01"
  condition:
    hash.sha256(0, filesize) == "5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7"
}
```

### Sample 74: `607e69311a7cd5f6`

| Field | Value |
|---|---|
| SHA-256 | `607e69311a7cd5f6becb65334193965b9c5436b8ea8b86bcc04ace0b391754a1` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-09 20:49:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b27a4709b82511aa18e27ff068bfb3d8` |
| SHA-1 | `74845c097a52be6264a15e500e6f6ff61ae0c0fc` |
| SHA-256 | `607e69311a7cd5f6becb65334193965b9c5436b8ea8b86bcc04ace0b391754a1` |
| SHA3-384 | `a16a8985de2abcaad3e3e06f90fb7eac0ac64f478c19dde2f6326237b9f7893f36f8c8f48d265553a896ec621dc7105d` |
| TLSH | `T1A353A519BF610FB7EC6BCD3709A81B0538CC644A22A87B367934D468F64B25B59F3C64` |
| SSDEEP | `768:aAVWeuUsAYGMmcoKw5BheiTebiQ2ZFVyXiSA7mWzkCw:aAVWVxHNwxjTIitZFVbmao` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_607e6931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "607e69311a7cd5f6becb65334193965b9c5436b8ea8b86bcc04ace0b391754a1"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-09 20:49:41"
  condition:
    hash.sha256(0, filesize) == "607e69311a7cd5f6becb65334193965b9c5436b8ea8b86bcc04ace0b391754a1"
}
```

### Sample 75: `3f52c9d217c625a8`

| Field | Value |
|---|---|
| SHA-256 | `3f52c9d217c625a8e8b12be29c828d27dbec62bf021d5f0d481dcced080043e8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 20:42:56` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3e9e0d1c119505e4b067a293d0884cd` |
| SHA-1 | `edacf8dfc7e8314cdfb7e02429e28f5983bde9a4` |
| SHA-256 | `3f52c9d217c625a8e8b12be29c828d27dbec62bf021d5f0d481dcced080043e8` |
| SHA3-384 | `95dc9f27a50414cd1f2bb23b469c8f7b18b2b053a06fd78ed90115c496e29e7c95a331853f0b9396e8db9c8b4af73877` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T126164903BE9548F9C1A5E73589774252BA74BC4C4B3133D32EA0AAB82F763D06E74B54` |
| SSDEEP | `49152:sgeZyDmXUfkWSsI6MuJ2kJwOizezjATKv:s5wI6MK2/7ezjd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_3f52c9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f52c9d217c625a8e8b12be29c828d27dbec62bf021d5f0d481dcced080043e8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 20:42:56"
  condition:
    hash.sha256(0, filesize) == "3f52c9d217c625a8e8b12be29c828d27dbec62bf021d5f0d481dcced080043e8"
}
```

### Sample 76: `f1712480cba485a3`

| Field | Value |
|---|---|
| SHA-256 | `f1712480cba485a3a146af70a45ba896419fa83b8e3dd846f2c27a4772aabfdd` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-09 20:39:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d99cf5697df9c5ac8a4fbcb413f9df4` |
| SHA-1 | `c1867c80a5176cda86ab46c7a0ce5e98db8afc69` |
| SHA-256 | `f1712480cba485a3a146af70a45ba896419fa83b8e3dd846f2c27a4772aabfdd` |
| SHA3-384 | `ed781af2ab71f8bd85e91b1c87aab51e3cad20d93461b5acefd7d94dc0e17a7e42de1f0cf7322fa74ee83bd20fd89514` |
| TLSH | `T1F6531C06F2525AFDC0C7C4308A5FE52A693170E95230A23F7E9473B62EE3F75192AD85` |
| TELFHASH | `t10ce07200fcb88b2c9cdaaab4adcd07b4aa00220260178b10cf10daf0c83f448e30ce5e` |
| SSDEEP | `1536:t6oC2ELeBT+jmV/FjTQipMuCFEBTXZIc4m:koC2ELeBT+q3TQR7yBTXZIc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f1712480
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1712480cba485a3a146af70a45ba896419fa83b8e3dd846f2c27a4772aabfdd"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-09 20:39:43"
  condition:
    hash.sha256(0, filesize) == "f1712480cba485a3a146af70a45ba896419fa83b8e3dd846f2c27a4772aabfdd"
}
```

### Sample 77: `28c5cccd904a42f5`

| Field | Value |
|---|---|
| SHA-256 | `28c5cccd904a42f5393074833568646c27b33aec0513e1c5a4b83e92d9bc8a57` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-09 20:33:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0e51f30e117070ecf63c727598b0f14` |
| SHA-1 | `03c22e63a5a67d26015c464e15a02aa1e23fee88` |
| SHA-256 | `28c5cccd904a42f5393074833568646c27b33aec0513e1c5a4b83e92d9bc8a57` |
| SHA3-384 | `abc8b5166d66f26d664463f756b8cb14623a786758a804d4b15dc1dd13aa887807759353e0d8acaa79d742e569b00489` |
| TLSH | `T12C31419A01105A311103CA4F33B63288B35DF1FB685FD7E1DD890E9A968839CF225F5E` |
| SSDEEP | `24:MpD9pJQuGDLUOHdb3k4q650bylElVkOZpJkqkdZU2/2:MpD9pyLdHdR+PnkOZpJkqkov` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_28c5cccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c5cccd904a42f5393074833568646c27b33aec0513e1c5a4b83e92d9bc8a57"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-09 20:33:49"
  condition:
    hash.sha256(0, filesize) == "28c5cccd904a42f5393074833568646c27b33aec0513e1c5a4b83e92d9bc8a57"
}
```

### Sample 78: `109a968976cf3c6a`

| Field | Value |
|---|---|
| SHA-256 | `109a968976cf3c6a950e5956963c3ba5b3206d261d16b025df21059974c72971` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-09 20:25:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df2b678f797e6d15543d4052c440d203` |
| SHA-1 | `122c01a74add77ff1b09197b943188cf461bede4` |
| SHA-256 | `109a968976cf3c6a950e5956963c3ba5b3206d261d16b025df21059974c72971` |
| SHA3-384 | `eb52ae1e306255c3be187e18b8bd4811989d32918e7e9d4ff78a1bd7c9e121dbf151732adc1ecdf35ad3ac4651d09ec5` |
| TLSH | `T169C27D966A867C44BDC94A3E4CBE2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:++T8vCB+25j6es8Ro79FYpMSUpi+20qUpi+20YQX:38l25Jad2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_109a9689
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "109a968976cf3c6a950e5956963c3ba5b3206d261d16b025df21059974c72971"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-09 20:25:46"
  condition:
    hash.sha256(0, filesize) == "109a968976cf3c6a950e5956963c3ba5b3206d261d16b025df21059974c72971"
}
```

### Sample 79: `6da56af87f9d4848`

| Field | Value |
|---|---|
| SHA-256 | `6da56af87f9d4848a02fc392b74f38f0ab165d8d97d014acd96362210dc144b5` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-09 20:19:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24222908acaf4457d89d9667574c8cc4` |
| SHA-1 | `0756b6ee0d532fc5c206abc73a50789b6f0c32db` |
| SHA-256 | `6da56af87f9d4848a02fc392b74f38f0ab165d8d97d014acd96362210dc144b5` |
| SHA3-384 | `b994a92d344ca46b8ed1ed59888e903ab4d990c3a6896b6e7294dc0e655f4bd162ee5b118062da1a65b4da5b4213e0f9` |
| TLSH | `T1CF235C6516857C24AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69D910871D` |
| SSDEEP | `768:fXRWNGxVzV9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ZlxJGcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_6da56af8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da56af87f9d4848a02fc392b74f38f0ab165d8d97d014acd96362210dc144b5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 20:19:42"
  condition:
    hash.sha256(0, filesize) == "6da56af87f9d4848a02fc392b74f38f0ab165d8d97d014acd96362210dc144b5"
}
```

### Sample 80: `f6a89afd80bcfccc`

| Field | Value |
|---|---|
| SHA-256 | `f6a89afd80bcfccc8ade155c0ef92a770de44610efdcac2b6a21650dc136dca5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 20:18:32` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dbf46f03bc6b37117f299969c88e608` |
| SHA-1 | `9b43384cf59598e7a2304986180990b8c0e91890` |
| SHA-256 | `f6a89afd80bcfccc8ade155c0ef92a770de44610efdcac2b6a21650dc136dca5` |
| SHA3-384 | `2fbbbf9dd49869a3c3c6da57608587ae3e9938a2d0595fd9b1bfffdb68690fc7b31d5b4c5b8419a62ea5e45fc750591b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F704AE62706BA81CC55653B01837E4EDA093FF872D138786325DB1AB2F7236176E4EC9` |
| SSDEEP | `3072:ZbImplGmplumplGmplcZGjXpoGoByXPQs2UTXQ8yb7aFcHiSIvF68fJ:ZbImpsmpUmpsmpaZGbpYByPT7lyvIcCP` |
| ICON-DHASH | `a2a9d8f88a88c9c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_f6a89afd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6a89afd80bcfccc8ade155c0ef92a770de44610efdcac2b6a21650dc136dca5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 20:18:32"
  condition:
    hash.sha256(0, filesize) == "f6a89afd80bcfccc8ade155c0ef92a770de44610efdcac2b6a21650dc136dca5"
}
```

### Sample 81: `907e8720528ff4a4`

| Field | Value |
|---|---|
| SHA-256 | `907e8720528ff4a45168679e5b6865f527089d2f0ce0e3594e947a5b07ae5d00` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-09 20:07:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb82e983154a1c690c5ea1ae2faca9b9` |
| SHA-1 | `5484823b2b0ff9b106e66ae0582a1537514d7872` |
| SHA-256 | `907e8720528ff4a45168679e5b6865f527089d2f0ce0e3594e947a5b07ae5d00` |
| SHA3-384 | `640e8dc37f5a9f7655cfe921e6bd1a28b535adf83ba8e2dcb51de68baba51e7c9f92058983dc1afb52417aa31680e20e` |
| TLSH | `T15E43751E6D168FBCFB59863447B78E219A5833D627D1D642E16CDA002EA034E741FFAC` |
| TELFHASH | `t16a014f18543813f4d7854ddd7bedff31e01150df5e561e338d10e99aab21a468c00c2c` |
| SSDEEP | `768:DvaLxUxyQpPT5rhmuTSFtqmSnoh2Lt3ug+u1QZi0e4fyMnup//dujgtywwr:DvJFP1gtsF+u1l0lk16gtLM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_907e8720
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "907e8720528ff4a45168679e5b6865f527089d2f0ce0e3594e947a5b07ae5d00"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-09 20:07:43"
  condition:
    hash.sha256(0, filesize) == "907e8720528ff4a45168679e5b6865f527089d2f0ce0e3594e947a5b07ae5d00"
}
```

### Sample 82: `014f5068274dc499`

| Field | Value |
|---|---|
| SHA-256 | `014f5068274dc499a77cac8ec4e0168ed142cdfd29a772a721ca65b35cd467f9` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-09 20:07:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5eb866b15c92f98ecdf5d3e590705267` |
| SHA-1 | `c92a8b3638c4cc8288c5023a7709abb1838b3d82` |
| SHA-256 | `014f5068274dc499a77cac8ec4e0168ed142cdfd29a772a721ca65b35cd467f9` |
| SHA3-384 | `e5564b18691a3e48e2f5c4ea75e71d51f6e601728511707aa3e5efccf3f009abcc97e710afdac37a6cc281f850e5db38` |
| TLSH | `T18401ABC6D2146A1040EAD99D22976494F832C3C7154B4F79BF6CA43F9F98E04B02AF98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaqCouEgtC9Wz+CxFDCVKnzbRaC1YX:kXCKysE2hi0ziQvZohaq+EynSMDSEw9X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_014f5068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "014f5068274dc499a77cac8ec4e0168ed142cdfd29a772a721ca65b35cd467f9"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-09 20:07:42"
  condition:
    hash.sha256(0, filesize) == "014f5068274dc499a77cac8ec4e0168ed142cdfd29a772a721ca65b35cd467f9"
}
```

### Sample 83: `d9e85bf2a14b2ee5`

| Field | Value |
|---|---|
| SHA-256 | `d9e85bf2a14b2ee550e5b5132550a6efe74e3289e72d30e5c3220a723e1990e7` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-09 20:07:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d613f1c5f8e2475cf208a8053c3dcbf9` |
| SHA-1 | `702063f0829b69bc148f7eef3b270da6269f1518` |
| SHA-256 | `d9e85bf2a14b2ee550e5b5132550a6efe74e3289e72d30e5c3220a723e1990e7` |
| SHA3-384 | `9a36a8ea523b1a56a25ee1ae69474fea2546540c5200cf39fa1b68a32b5a08b23ce9efb072eea108cc9ec9376cd6ddf5` |
| TLSH | `T150C33B56E6818B13C4D61775B6EF42453323A794A3DB73069924AFF43F827AF0E23906` |
| TELFHASH | `t1f321fd355760a5195ea1cd5488ee57b2262c8b172744ef33de35c48c64050dae63bc4f` |
| SSDEEP | `3072:hQC3iWQgKKME7mnmYzBuiiEF+EuNM/9RE:hQC3jDME7mnTFucF+E4M/9RE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_d9e85bf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9e85bf2a14b2ee550e5b5132550a6efe74e3289e72d30e5c3220a723e1990e7"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-09 20:07:41"
  condition:
    hash.sha256(0, filesize) == "d9e85bf2a14b2ee550e5b5132550a6efe74e3289e72d30e5c3220a723e1990e7"
}
```

### Sample 84: `56c43ff49fda9a95`

| Field | Value |
|---|---|
| SHA-256 | `56c43ff49fda9a95111adbcc0076919244c7962ce22f5d2c41b18fb01fdf090f` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-09 20:05:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcb76071e2caac82fb10589ac0675ffc` |
| SHA-1 | `b2d0ec8f88a43d60d4d78a310aff9f1110c58abc` |
| SHA-256 | `56c43ff49fda9a95111adbcc0076919244c7962ce22f5d2c41b18fb01fdf090f` |
| SHA3-384 | `7e57067db68550bb9133bc08e82c0297e104d1c4c6aa316701124233059fb4dc89304dbc297c32562d9dc8ffbf14781b` |
| TLSH | `T16F1318C4F553D8F0EC5A06703076EB365F35F1FA222DE553D3A5DA72BC82602AA0699C` |
| TELFHASH | `t1941182b62fb248ecf2d0b808c75e5ae31b39d2776ab15cf644b929553bf210180b7536` |
| SSDEEP | `768:xMlB2zs8ssGfrRI6aQ2CEenzvq8uDOycN95VlVs:YYzs8ssGfrRI6aVCEe7WOrNrVla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_56c43ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c43ff49fda9a95111adbcc0076919244c7962ce22f5d2c41b18fb01fdf090f"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-09 20:05:42"
  condition:
    hash.sha256(0, filesize) == "56c43ff49fda9a95111adbcc0076919244c7962ce22f5d2c41b18fb01fdf090f"
}
```

### Sample 85: `f6c878d6f2c1b4e2`

| Field | Value |
|---|---|
| SHA-256 | `f6c878d6f2c1b4e2bb12fc3a1bc555cdc8d1fd4679728e2f58b4df0429cd9efe` |
| Family label | `unknown` |
| File name | `f` |
| File type | `elf` |
| First seen | `2026-08-09 19:59:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bf89625d2cba6e182b979b2a5a43925` |
| SHA-1 | `273b3420ce3c8fde5938716c86f1e0446436a02a` |
| SHA-256 | `f6c878d6f2c1b4e2bb12fc3a1bc555cdc8d1fd4679728e2f58b4df0429cd9efe` |
| SHA3-384 | `963aed398f177aa796ec5fa5917a1fa3420eb4d6dbbe6192dd3c1d2d92f4c205a132fa8dec74918839d3962ac8d444ac` |
| TLSH | `T1B5D30907ED816EF7C01FCD70456DC24A15D658AA92E9A22F71FCC98CBBBD30646D7888` |
| SSDEEP | `1536:W3P/49rAGgDXrNk+5N71eRMgm9OKiF9+Z+G1u6veHk0WLOJusRf2cXLAErJ:WH4krz5N159OIP30WSV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_f6c878d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6c878d6f2c1b4e2bb12fc3a1bc555cdc8d1fd4679728e2f58b4df0429cd9efe"
    family = "unknown"
    file_name = "f"
    file_type = "elf"
    first_seen = "2026-08-09 19:59:36"
  condition:
    hash.sha256(0, filesize) == "f6c878d6f2c1b4e2bb12fc3a1bc555cdc8d1fd4679728e2f58b4df0429cd9efe"
}
```

### Sample 86: `50fa9aa29ed55faf`

| Field | Value |
|---|---|
| SHA-256 | `50fa9aa29ed55faf83cfe718097bb66a104a83cfddbd0fed4db702dfe6b84e83` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-09 19:57:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d4e8376a0331cc17540911f87ca4479` |
| SHA-1 | `7db6fe102502f93798d0eb7c249397644a4a7d40` |
| SHA-256 | `50fa9aa29ed55faf83cfe718097bb66a104a83cfddbd0fed4db702dfe6b84e83` |
| SHA3-384 | `67e3f98f6111fb74dcaa6593c9f3413566eda23720badce8f6dbc11d37baa3e7a198f7158b388bb78d2d88a19d1e641f` |
| TLSH | `T133D312EBE62DC099CBD4997279A9DC44335AF09740849BCF897E3D6B08B3B61FC50660` |
| SSDEEP | `3072:ODFgjSMAYDMEBiJTIaO+SQF0mKOv63TaQuueW8iCUBWVAVGlbD:OQNiJTS+j+TOv2TaQuueW8PUBWQIbD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_50fa9aa2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50fa9aa29ed55faf83cfe718097bb66a104a83cfddbd0fed4db702dfe6b84e83"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-09 19:57:37"
  condition:
    hash.sha256(0, filesize) == "50fa9aa29ed55faf83cfe718097bb66a104a83cfddbd0fed4db702dfe6b84e83"
}
```

### Sample 87: `c962067f11b2f516`

| Field | Value |
|---|---|
| SHA-256 | `c962067f11b2f516f0686d4c659b2717aaff65ca529bf0e03d51f9ce70f9537f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-09 19:53:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a71f604c8279e7a612cc0136f5f5c0b` |
| SHA-1 | `5e62656f1fe109aa011ad02dfecc6d190d3affa4` |
| SHA-256 | `c962067f11b2f516f0686d4c659b2717aaff65ca529bf0e03d51f9ce70f9537f` |
| SHA3-384 | `41df8c7b7731fadae7ba8b005918190234cb20267733f3831766b96ce7e6fd8674b5e2a8346da9e1f5777412f656af37` |
| TLSH | `T1EC236C6516857C14AE99C4365C7E2F0CBDAD43E6314492EE7FCE3CF28C4A6ADA20871D` |
| SSDEEP | `768:qr9NyXsZztCo9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:UHusZQcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_c962067f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c962067f11b2f516f0686d4c659b2717aaff65ca529bf0e03d51f9ce70f9537f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 19:53:39"
  condition:
    hash.sha256(0, filesize) == "c962067f11b2f516f0686d4c659b2717aaff65ca529bf0e03d51f9ce70f9537f"
}
```

### Sample 88: `e3380c141107fec4`

| Field | Value |
|---|---|
| SHA-256 | `e3380c141107fec48efb61170278e0cc74bdc793d669fc660483d929fa22871e` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-09 19:53:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d908b351fcaf92938420e4a08dbc22fe` |
| SHA-1 | `0b1c9ab71cb2c5d071e45584a353290de26db202` |
| SHA-256 | `e3380c141107fec48efb61170278e0cc74bdc793d669fc660483d929fa22871e` |
| SHA3-384 | `a98debc68cb5c912fc02de6e313b502152efd1f6e0e1eb8786bdd39ee1e51303ad7d88e259f100884eaee9d2acdad417` |
| TLSH | `T172231841B8818613C6E4137AB66E46CE372563E8E2DFB21B9D321F503B9682F0D67F45` |
| TELFHASH | `t16a31de544ecd16dc86f08a85954d633b3aa134b19f122d1a4f977f8f8753cd17029436` |
| SSDEEP | `768:5pT3sFvRsOvMZM3RKvqKt1n9iy/8q2E/PoVtX/N+WrH3S3y9mvLsw:P3sFvGOvAccdQO/kXfXS3ycZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_e3380c14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3380c141107fec48efb61170278e0cc74bdc793d669fc660483d929fa22871e"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-09 19:53:38"
  condition:
    hash.sha256(0, filesize) == "e3380c141107fec48efb61170278e0cc74bdc793d669fc660483d929fa22871e"
}
```

### Sample 89: `633af775e71f8752`

| Field | Value |
|---|---|
| SHA-256 | `633af775e71f8752dc4ea4ec64bbbb79ded0004cc4ef13b074a54f1d7321096f` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-09 19:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e6a691bbddfeea898e3bc37c16a07df` |
| SHA-1 | `d75f639193f2b09a131366b58bc7215a8055de9d` |
| SHA-256 | `633af775e71f8752dc4ea4ec64bbbb79ded0004cc4ef13b074a54f1d7321096f` |
| SHA3-384 | `4640097b8ef33b4539075a8b1a72e60cfa46cfd5908fd22ae342206d45c42a34ad387a8dfb92bfa806cb97fe3b3433bd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T187E63348A6D001EEEAB3503CFFF142A5E46A78764735CDEF47A896519E031F1883A727` |
| SSDEEP | `393216:xGm/HyQe3tP9QeZZLjIfRpXMCHWUj8cuI3/PGTAI:xGqHbitPrIpXMb8pH/O7` |
| ICON-DHASH | `f0f89ca29ac6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_633af775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "633af775e71f8752dc4ea4ec64bbbb79ded0004cc4ef13b074a54f1d7321096f"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 19:52:30"
  condition:
    hash.sha256(0, filesize) == "633af775e71f8752dc4ea4ec64bbbb79ded0004cc4ef13b074a54f1d7321096f"
}
```

### Sample 90: `866569b33ab608b5`

| Field | Value |
|---|---|
| SHA-256 | `866569b33ab608b5bebbd4796b12e605d826cde7fb335409e332c08d02aae132` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-09 19:51:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d04340d717d509875cac0e105abe009` |
| SHA-1 | `231b70e56ffe686c4461215262aad7c5a6a76c29` |
| SHA-256 | `866569b33ab608b5bebbd4796b12e605d826cde7fb335409e332c08d02aae132` |
| SHA3-384 | `1fba1cf1487e90f6009a9a3c050346505965658270ff61e54d464b40dbdd07bbace0daf722d33a8066a193b56358cf29` |
| TLSH | `T1DF03D651F8829A27C6E1127AB6BE468E333073E982CFB617D9214B103BD551F0D63F92` |
| TELFHASH | `t10ce07200fcb88b2c9cdaaab4adcd07b4aa00220260178b10cf10daf0c83f448e30ce5e` |
| SSDEEP | `768:0s5xPh9deftcG5dm80LyFBWEu/tOr4MkKvlw9QSo8qMaIE1JomMm/NkwTkkkkkkn:0sz+f2G5dmSBWjV8kZbJql1smD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_866569b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866569b33ab608b5bebbd4796b12e605d826cde7fb335409e332c08d02aae132"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-09 19:51:43"
  condition:
    hash.sha256(0, filesize) == "866569b33ab608b5bebbd4796b12e605d826cde7fb335409e332c08d02aae132"
}
```

### Sample 91: `a6d87ca41c596e3f`

| Field | Value |
|---|---|
| SHA-256 | `a6d87ca41c596e3f8a06ce4cc6105cc2e5a133fca49da4d78d16116f298dd931` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-09 19:47:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `182d3a073ea8eb042ed39ad83029fd7c` |
| SHA-1 | `2a8c9ac171adc7b489e77373aac45606f54cd0c6` |
| SHA-256 | `a6d87ca41c596e3f8a06ce4cc6105cc2e5a133fca49da4d78d16116f298dd931` |
| SHA3-384 | `1cedbb4bc1ed1f5b1e2314ddbc1cdaa9fb5301f0218c402d2432895dc0f1210e4515725adb7f50f2c8cf5d260e31fb8a` |
| TLSH | `T1DD016BD69250AA104069D95E62D666D0F431C3C6454B0FB8BF9C942FAB9CE04B026F98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaqCouPtC9W/+CCsFDCVKnvbRaC1rYauD:kXCKysE2hi0ziQvZohaq+VnWSDSPn7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_a6d87ca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6d87ca41c596e3f8a06ce4cc6105cc2e5a133fca49da4d78d16116f298dd931"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-09 19:47:44"
  condition:
    hash.sha256(0, filesize) == "a6d87ca41c596e3f8a06ce4cc6105cc2e5a133fca49da4d78d16116f298dd931"
}
```

### Sample 92: `cca318919263231e`

| Field | Value |
|---|---|
| SHA-256 | `cca318919263231e18be956046e4d74c295c12e091a31c4ecc593775fa34e198` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-09 19:45:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f16b1c37a79824e217badc8fa08fb2c` |
| SHA-1 | `0a3f424bad0f897e57271313ce99961d625ef0e2` |
| SHA-256 | `cca318919263231e18be956046e4d74c295c12e091a31c4ecc593775fa34e198` |
| SHA3-384 | `86128311c4a07f6c7f4018c61685480d3d748ae30a2b3ce42947d3e9bf74a443480f69d0f12049097dac9be959c34a36` |
| TLSH | `T11823289AF8429D7DF94BE77E14164A09B93173D052831B2A13B7FEA37C331591D12E81` |
| SSDEEP | `768:mFPewtBdxjcJw2ZXnI1VaSxu+Jkxf8MYqEI8q8DfpGv:APJjcJzsVaSg+yf8MFEI/8D0v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_cca31891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cca318919263231e18be956046e4d74c295c12e091a31c4ecc593775fa34e198"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-09 19:45:39"
  condition:
    hash.sha256(0, filesize) == "cca318919263231e18be956046e4d74c295c12e091a31c4ecc593775fa34e198"
}
```

### Sample 93: `c2235ce06b77fd6b`

| Field | Value |
|---|---|
| SHA-256 | `c2235ce06b77fd6b73cdf3e825d2200308aff3a48aba90044ecc6eba2b4b951c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-09 19:45:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fbaa9ce80a1ebb0f20950c701ba3874` |
| SHA-1 | `32aef126395d984495f72d6a4511474ccec0b10f` |
| SHA-256 | `c2235ce06b77fd6b73cdf3e825d2200308aff3a48aba90044ecc6eba2b4b951c` |
| SHA3-384 | `8a5f73ad619626ff899b7894fdb5bcc6f2ef5ce94f61ea41a9c3168f3874d47f035d659da0b330a8d46524621453ff6f` |
| TLSH | `T1E9236C551A857C149E99C4371D7E2F0CB9AD43E6320452EE7FCB3CF28C8AA9DA20971D` |
| SSDEEP | `768:dVEJVIhtMA9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:zEJ2M9cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_c2235ce0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2235ce06b77fd6b73cdf3e825d2200308aff3a48aba90044ecc6eba2b4b951c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 19:45:38"
  condition:
    hash.sha256(0, filesize) == "c2235ce06b77fd6b73cdf3e825d2200308aff3a48aba90044ecc6eba2b4b951c"
}
```

### Sample 94: `5127a4b2e74ed750`

| Field | Value |
|---|---|
| SHA-256 | `5127a4b2e74ed750fe8d18bd196c5d6ea926979b35910443a4087329ce98b781` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-09 19:37:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db61652ac2f72a461770083971ecfe94` |
| SHA-1 | `ebb6f23b1ffd042b1bdd8f99eaf30ce8bbb8c2bd` |
| SHA-256 | `5127a4b2e74ed750fe8d18bd196c5d6ea926979b35910443a4087329ce98b781` |
| SHA3-384 | `ee5c7798af58375ef06a53f5d45f66a9798d09145958a367b9a446e4c6fc2794278ff0bd36da71ef5463f9f70cc3541f` |
| TLSH | `T19E233A25BA761F17C0D168B521FB4B6876F106CE26A8CA4E3DB20D9EFF618406503AF4` |
| SSDEEP | `768:/BoBCKHvxxNDs+trBy1ZBpUm7X8slf4AQjqO+23WuVuwc:/B8zHvxnjrBy1/pUmT8sSAQj42mKc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_5127a4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5127a4b2e74ed750fe8d18bd196c5d6ea926979b35910443a4087329ce98b781"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-09 19:37:36"
  condition:
    hash.sha256(0, filesize) == "5127a4b2e74ed750fe8d18bd196c5d6ea926979b35910443a4087329ce98b781"
}
```

### Sample 95: `8c7f926e3ee6c278`

| Field | Value |
|---|---|
| SHA-256 | `8c7f926e3ee6c27892f4bc2d93d915586c41d2eee94a2721b11c9d769046111a` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.ELF.Mirai.APD.tr.27914.20887` |
| File type | `elf` |
| First seen | `2026-08-09 19:35:36` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fc23a5fa28a6b1bc44f800930a82c0d` |
| SHA-1 | `287b9bf3cbe51028a6e5db680395a490b1534b70` |
| SHA-256 | `8c7f926e3ee6c27892f4bc2d93d915586c41d2eee94a2721b11c9d769046111a` |
| SHA3-384 | `fc5a9cd8e5c924266c2fefe6a92a6b96d0882a2375f64d167e40ca25c2b388c6b4b42c4afa688b911294073661fb1c0a` |
| TLSH | `T17D822AD1942BE5E0CD050630313AFB372A74E43D0137EEA3DB92DAE79AC6683D4A125D` |
| SSDEEP | `384:fj6QzwczNIVdKpDP3bsOdnAuhhDXf3KPJb4ve:+Q36zKp4g7b3Kh4ve` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_8c7f926e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7f926e3ee6c27892f4bc2d93d915586c41d2eee94a2721b11c9d769046111a"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai.APD.tr.27914.20887"
    file_type = "elf"
    first_seen = "2026-08-09 19:35:36"
  condition:
    hash.sha256(0, filesize) == "8c7f926e3ee6c27892f4bc2d93d915586c41d2eee94a2721b11c9d769046111a"
}
```

### Sample 96: `931e34552fae7cd9`

| Field | Value |
|---|---|
| SHA-256 | `931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df` |
| Family label | `unknown` |
| File name | `931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df.elf` |
| File type | `elf` |
| First seen | `2026-08-09 19:30:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdeef45dabe3c82333eee042cb97b98d` |
| SHA-1 | `f9ba69cd3deeb3e1db802d6fb96563e53df09319` |
| SHA-256 | `931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df` |
| SHA3-384 | `12f658d68ff8cf6cb3c98640d127693628716f7718ead8464326ea20a38d9d7d7e6b06f1907c2edd921c5ac9d67c9ef0` |
| TLSH | `T135461711FECB14F6E9031E3144BBA26F23315D058B25EB87EB44BF29F977A951932209` |
| TELFHASH | `t1dbd2dfb7159da4ec67f0850786af7120cef5e03726e0387119e6b8c15b73d93a6268b8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:xsqiwQQTceXBKvarlUPKDIp5pdtdNyYy7jETeZbsG+ahPgI+5EE:xsqJcyZDcXdNyJ7jEA+8UEE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_931e3455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df"
    family = "unknown"
    file_name = "931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:30:01"
  condition:
    hash.sha256(0, filesize) == "931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df"
}
```

### Sample 97: `2e0cf5af50240dbb`

| Field | Value |
|---|---|
| SHA-256 | `2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5` |
| Family label | `Mirai` |
| File name | `2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5.elf` |
| File type | `elf` |
| First seen | `2026-08-09 19:24:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc125288c02af6aff21922df8bd49336` |
| SHA-1 | `9b72fa2f55a018d837bebfec336c718c2d794541` |
| SHA-256 | `2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5` |
| SHA3-384 | `35189dc714e5c595d22f3b597c7a943c6bca347b2fa3dcfeec9e4c1d2188ec935f9f86b6b490110b0817baacdcc4aff5` |
| TLSH | `T1FDD3120660D8405E8A5E1D7ED0CF21EBDF4C84C7DDBD8E889AAC4E019FF74292465ABD` |
| SSDEEP | `3072:RdhlN00HSnb0SAvmAGzmc2I9XBKg49+N3XZ36O:RdV1H8brKc2I9xv536O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_2e0cf5af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5"
    family = "Mirai"
    file_name = "2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:24:53"
  condition:
    hash.sha256(0, filesize) == "2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5"
}
```

### Sample 98: `6cae7a11941d4b59`

| Field | Value |
|---|---|
| SHA-256 | `6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986` |
| Family label | `unknown` |
| File name | `6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986.elf` |
| File type | `elf` |
| First seen | `2026-08-09 19:19:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56f854836477c41b673882c518b95c7d` |
| SHA-1 | `28adf90aadbdee80d61b98e4d5cf3624784ebee4` |
| SHA-256 | `6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986` |
| SHA3-384 | `5a041892a31874b209f9b50a2e26163e40b5a2a50cde36f23d90cfe35e3be5fe80b1f27ca23aeec54a5625d6d468744c` |
| TLSH | `T1E6465B02FA182FA6C9205D3388B30E9127626E552B319747E744F27FA9F73460F56F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:TvYErg8Obs9MKF1kyquTmJD1S497ayesNEPQIPPi2V5EW:rYErg8OYeKrkyGNEZ1EW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_6cae7a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986"
    family = "unknown"
    file_name = "6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:19:57"
  condition:
    hash.sha256(0, filesize) == "6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986"
}
```

### Sample 99: `bf807da85ac1b940`

| Field | Value |
|---|---|
| SHA-256 | `bf807da85ac1b940cad9795a33f101467c72674d7f98ae6b61c3a5e3695a17a5` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-09 19:19:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f169207482a00a276375eb08a16f3be` |
| SHA-1 | `cf9405e3b9b91e2b987072b6d888e1c7b327f6e8` |
| SHA-256 | `bf807da85ac1b940cad9795a33f101467c72674d7f98ae6b61c3a5e3695a17a5` |
| SHA3-384 | `53717319fba2570b335b5d1028aef8dbd731d7b7b13665bf0d420c64628c645b6d7d35ea0986a773089da3309a24edb0` |
| TLSH | `T18A133B02721C0F17C4A35A70253E5BD187BEEAD032E4F289655F9BA68A75E371482FCD` |
| SSDEEP | `768:04UB4TLiotRfYRW0CRG48XWHysxClF32MusczFWM1dWYlL1Tvwq:PUBeqmTHkRjzM1dNLmq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_bf807da8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf807da85ac1b940cad9795a33f101467c72674d7f98ae6b61c3a5e3695a17a5"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-09 19:19:42"
  condition:
    hash.sha256(0, filesize) == "bf807da85ac1b940cad9795a33f101467c72674d7f98ae6b61c3a5e3695a17a5"
}
```

### Sample 100: `f4bdbd0603010c13`

| Field | Value |
|---|---|
| SHA-256 | `f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e` |
| Family label | `unknown` |
| File name | `f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e.elf` |
| File type | `elf` |
| First seen | `2026-08-09 19:15:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2bb6e403d066aba5d261f6694d89c43` |
| SHA-1 | `b4badb2aa675a19a2a7531de6e744d295b61dc34` |
| SHA-256 | `f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e` |
| SHA3-384 | `50b27245d7cb5f7359c5618eda18aa381be37a67940cb7cb75d75fa91903a8f14c56f2e2e6d894cfb6ed327ff07c2f16` |
| TLSH | `T1ED660852BF88DE1FE69821359AF2C23473D53D0081E0A4368756F7191EBF2A49D1BED8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vzL67nqaOMIFR5UPZmTSLZ3wrMHH4t5El:vlpMTcGVwrMn4jEl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_f4bdbd06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e"
    family = "unknown"
    file_name = "f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:15:07"
  condition:
    hash.sha256(0, filesize) == "f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e"
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
 * Generated: 2026-08-10T02:37:37.708671+00:00
 */

rule MalwareBazaar_unknown_001_7bf7e6de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bf7e6decac47c1d1e315a8ef07a83ac148467fda3d6e284870c22c4d500314c"
    family = "unknown"
    file_name = "main.e300c3"
    file_type = "elf"
    first_seen = "2026-08-10 02:33:43"
  condition:
    hash.sha256(0, filesize) == "7bf7e6decac47c1d1e315a8ef07a83ac148467fda3d6e284870c22c4d500314c"
}

rule MalwareBazaar_Mirai_002_98196b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98196b4050ff4ef422082b82e54b63570955e0fdb2fcb8ec5a0783d6d97e2264"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-10 02:28:41"
  condition:
    hash.sha256(0, filesize) == "98196b4050ff4ef422082b82e54b63570955e0fdb2fcb8ec5a0783d6d97e2264"
}

rule MalwareBazaar_Mirai_003_60510876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "605108764fe03fc94d3d631ba09abc815cdbaacf2d4414a7aafc06934a83f163"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-10 02:27:49"
  condition:
    hash.sha256(0, filesize) == "605108764fe03fc94d3d631ba09abc815cdbaacf2d4414a7aafc06934a83f163"
}

rule MalwareBazaar_unknown_004_28453e37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28453e3796ae864a07efceb26f881c2d3d05bcdb95012b817e8dfe9fdc5eee34"
    family = "unknown"
    file_name = "main.mips32"
    file_type = "elf"
    first_seen = "2026-08-10 02:27:48"
  condition:
    hash.sha256(0, filesize) == "28453e3796ae864a07efceb26f881c2d3d05bcdb95012b817e8dfe9fdc5eee34"
}

rule MalwareBazaar_unknown_005_62f058d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62f058d6f04af72a0dca6cb973fb9b7b6b75aa6162d769abf9bca946fcaedeb2"
    family = "unknown"
    file_name = "main.aarch64be"
    file_type = "elf"
    first_seen = "2026-08-10 02:27:46"
  condition:
    hash.sha256(0, filesize) == "62f058d6f04af72a0dca6cb973fb9b7b6b75aa6162d769abf9bca946fcaedeb2"
}

rule MalwareBazaar_unknown_006_844aba4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "844aba4ec75e4f229d096f01a2582c66c9bbea1416077cf479fa07d237dc1103"
    family = "unknown"
    file_name = "ORDER_202606001pdf.js"
    file_type = "js"
    first_seen = "2026-08-10 02:25:37"
  condition:
    hash.sha256(0, filesize) == "844aba4ec75e4f229d096f01a2582c66c9bbea1416077cf479fa07d237dc1103"
}

rule MalwareBazaar_Mirai_007_04cb291c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04cb291caba794af54a271778636d58817a9056e6cfa6e28ae7389e3cefcfcb9"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-10 02:24:42"
  condition:
    hash.sha256(0, filesize) == "04cb291caba794af54a271778636d58817a9056e6cfa6e28ae7389e3cefcfcb9"
}

rule MalwareBazaar_Mirai_008_a85a4f1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85a4f1cb021269231f526880c990dc93db657e3173075fa12744b4f9ea4e9ea"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-10 02:23:41"
  condition:
    hash.sha256(0, filesize) == "a85a4f1cb021269231f526880c990dc93db657e3173075fa12744b4f9ea4e9ea"
}

rule MalwareBazaar_unknown_009_3976eda2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3976eda2ae8a095f3868ad94d8b28e8bf3019298a73097a3a124a6f56b687b80"
    family = "unknown"
    file_name = "main.aarch64"
    file_type = "elf"
    first_seen = "2026-08-10 02:19:42"
  condition:
    hash.sha256(0, filesize) == "3976eda2ae8a095f3868ad94d8b28e8bf3019298a73097a3a124a6f56b687b80"
}

rule MalwareBazaar_Mirai_010_8c95dfa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c95dfa95220071f3984c3158ee101597f53b6a1d1c092d07ba852f3ff37089a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-10 02:18:35"
  condition:
    hash.sha256(0, filesize) == "8c95dfa95220071f3984c3158ee101597f53b6a1d1c092d07ba852f3ff37089a"
}

rule MalwareBazaar_Mirai_011_85397105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "853971052934e04c4063d7613fcdbb20c54ab4ee44bcfa184861b021663abf02"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-10 02:17:43"
  condition:
    hash.sha256(0, filesize) == "853971052934e04c4063d7613fcdbb20c54ab4ee44bcfa184861b021663abf02"
}

rule MalwareBazaar_unknown_012_22804a77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22804a77a4bfbc5f5df66ee61f8cdd422b0ea2a589fdfc6667b3ea58fc2c0ab3"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-10 02:13:39"
  condition:
    hash.sha256(0, filesize) == "22804a77a4bfbc5f5df66ee61f8cdd422b0ea2a589fdfc6667b3ea58fc2c0ab3"
}

rule MalwareBazaar_unknown_013_5417acf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5417acf48dbfb04701be9fa60902059982e5f9febaebfeab1c9f51166b6fd144"
    family = "unknown"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-10 02:11:44"
  condition:
    hash.sha256(0, filesize) == "5417acf48dbfb04701be9fa60902059982e5f9febaebfeab1c9f51166b6fd144"
}

rule MalwareBazaar_unknown_014_cd24f043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd24f0432e2492359dd91d611a2117b949dc991e03cf8e940875cc30c8c95b1e"
    family = "unknown"
    file_name = "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
    file_type = "exe"
    first_seen = "2026-08-10 02:09:44"
  condition:
    hash.sha256(0, filesize) == "cd24f0432e2492359dd91d611a2117b949dc991e03cf8e940875cc30c8c95b1e"
}

rule MalwareBazaar_Prometei_015_5c5575b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5575b228ce5c6f5cbe7dcdcde823a6ca926665f345adc585c8cd6df4f89ac0"
    family = "Prometei"
    file_name = "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
    file_type = "elf"
    first_seen = "2026-08-10 02:09:41"
  condition:
    hash.sha256(0, filesize) == "5c5575b228ce5c6f5cbe7dcdcde823a6ca926665f345adc585c8cd6df4f89ac0"
}

rule MalwareBazaar_unknown_016_47c89331
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c89331a453ce7d3a340dbedd22963e97926991ad405272ebc9bfc0df410e3c"
    family = "unknown"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-08-10 02:09:39"
  condition:
    hash.sha256(0, filesize) == "47c89331a453ce7d3a340dbedd22963e97926991ad405272ebc9bfc0df410e3c"
}

rule MalwareBazaar_unknown_017_58f68179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58f68179c5c95efbe4aa2d3943a7257ae58a580d71ca3a467d01372f9336e678"
    family = "unknown"
    file_name = "main.x86-64-v4"
    file_type = "elf"
    first_seen = "2026-08-10 02:09:38"
  condition:
    hash.sha256(0, filesize) == "58f68179c5c95efbe4aa2d3943a7257ae58a580d71ca3a467d01372f9336e678"
}

rule MalwareBazaar_Prometei_018_37889641
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37889641ac36cf081c187dc147939e329add2f571bd41363c8d4e5639bdb13b4"
    family = "Prometei"
    file_name = "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
    file_type = "exe"
    first_seen = "2026-08-10 02:09:37"
  condition:
    hash.sha256(0, filesize) == "37889641ac36cf081c187dc147939e329add2f571bd41363c8d4e5639bdb13b4"
}

rule MalwareBazaar_Prometei_019_dff3fe8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a"
    family = "Prometei"
    file_name = "dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a"
    file_type = "elf"
    first_seen = "2026-08-10 02:08:35"
  condition:
    hash.sha256(0, filesize) == "dff3fe8edc2b6c29114940240e91e236df49a395ae7a6424928c0bd77259ae0a"
}

rule MalwareBazaar_unknown_020_608b2c82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652"
    family = "unknown"
    file_name = "608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652"
    file_type = "unknown"
    first_seen = "2026-08-10 02:08:32"
  condition:
    hash.sha256(0, filesize) == "608b2c8220a595a9766e2fdc5c91899dda635f97bc505e1a41e523aaddb11652"
}

rule MalwareBazaar_unknown_021_8a0aa048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
    family = "unknown"
    file_name = "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
    file_type = "exe"
    first_seen = "2026-08-10 02:08:31"
  condition:
    hash.sha256(0, filesize) == "8a0aa04876b1221d0330ddfb7a4153c80e9eec24dab9c1fc2801fa5a14076ffe"
}

rule MalwareBazaar_Prometei_022_0ca3a4c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
    family = "Prometei"
    file_name = "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
    file_type = "elf"
    first_seen = "2026-08-10 02:08:30"
  condition:
    hash.sha256(0, filesize) == "0ca3a4c2800f9454cdcbb8398a7ec97b00f90f4234c7c5e48e206a8352d86750"
}

rule MalwareBazaar_Prometei_023_f4ac4f73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
    family = "Prometei"
    file_name = "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
    file_type = "exe"
    first_seen = "2026-08-10 02:08:27"
  condition:
    hash.sha256(0, filesize) == "f4ac4f735b9ff260a275734d86610dccb8558d1a54c6d6a78a94c33b6aaf6e39"
}

rule MalwareBazaar_Mirai_024_63c7c59b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c7c59b2959a3de5a5456dc53aaa41362bb7a610e8a872f15dc2b5d163902a5"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-10 02:01:49"
  condition:
    hash.sha256(0, filesize) == "63c7c59b2959a3de5a5456dc53aaa41362bb7a610e8a872f15dc2b5d163902a5"
}

rule MalwareBazaar_Mirai_025_98497bc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98497bc74a1bb5ff9750cbeb785bc245ccec38d570b3ccbdc88861dee6b2a498"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-10 01:59:35"
  condition:
    hash.sha256(0, filesize) == "98497bc74a1bb5ff9750cbeb785bc245ccec38d570b3ccbdc88861dee6b2a498"
}

rule MalwareBazaar_unknown_026_e81d62a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e81d62a221ae112e6184c3eb152082ab5ceefd9ba3ce15aa38968dcefdb47a81"
    family = "unknown"
    file_name = "uuyc.4.1.0.exe"
    file_type = "exe"
    first_seen = "2026-08-10 01:56:30"
  condition:
    hash.sha256(0, filesize) == "e81d62a221ae112e6184c3eb152082ab5ceefd9ba3ce15aa38968dcefdb47a81"
}

rule MalwareBazaar_unknown_027_5252a88b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5252a88bf7cdf43210cbf1f9e7d377b28c8f7f1393e653c03b7e6393dc6e376b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:51:42"
  condition:
    hash.sha256(0, filesize) == "5252a88bf7cdf43210cbf1f9e7d377b28c8f7f1393e653c03b7e6393dc6e376b"
}

rule MalwareBazaar_unknown_028_dd6350bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd6350bd0ecef9c4803c039c581253cc95adf5efd5347097457e4f99318abc6f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:49:41"
  condition:
    hash.sha256(0, filesize) == "dd6350bd0ecef9c4803c039c581253cc95adf5efd5347097457e4f99318abc6f"
}

rule MalwareBazaar_unknown_029_10fd2c56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10fd2c56ff14202d44aeb6ecab9ff5cf36c148bba9abaaa641496de2319979dd"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-10 01:49:39"
  condition:
    hash.sha256(0, filesize) == "10fd2c56ff14202d44aeb6ecab9ff5cf36c148bba9abaaa641496de2319979dd"
}

rule MalwareBazaar_unknown_030_d7367a85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7367a850acb0ee789a09dd4ac407163905856935d955bae53e9554055899ceb"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:49:38"
  condition:
    hash.sha256(0, filesize) == "d7367a850acb0ee789a09dd4ac407163905856935d955bae53e9554055899ceb"
}

rule MalwareBazaar_unknown_031_27dc9bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27dc9bdb577cc60327ab3560ed452941a5c53a938a8ecaecde098641487be501"
    family = "unknown"
    file_name = "package.json"
    file_type = "unknown"
    first_seen = "2026-08-10 01:42:02"
  condition:
    hash.sha256(0, filesize) == "27dc9bdb577cc60327ab3560ed452941a5c53a938a8ecaecde098641487be501"
}

rule MalwareBazaar_unknown_032_f76da38b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f76da38b39db5068b1dc5411b4f2d40706a8e34ce5258ec68c88fda5af3754bf"
    family = "unknown"
    file_name = "stage2-beavertail.js"
    file_type = "js"
    first_seen = "2026-08-10 01:42:00"
  condition:
    hash.sha256(0, filesize) == "f76da38b39db5068b1dc5411b4f2d40706a8e34ce5258ec68c88fda5af3754bf"
}

rule MalwareBazaar_unknown_033_19e8655c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19e8655cf0664ca6cd413580483d1dedab2a0d871422ccc270f026b1f3951261"
    family = "unknown"
    file_name = "vscode-bootstrap.sh"
    file_type = "sh"
    first_seen = "2026-08-10 01:41:56"
  condition:
    hash.sha256(0, filesize) == "19e8655cf0664ca6cd413580483d1dedab2a0d871422ccc270f026b1f3951261"
}

rule MalwareBazaar_unknown_034_75ef2f55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75ef2f55a86312240f0316468a693500efe97cf097cc7d22bcd9ffe237f473dc"
    family = "unknown"
    file_name = "stage1-env-setup.js"
    file_type = "js"
    first_seen = "2026-08-10 01:41:33"
  condition:
    hash.sha256(0, filesize) == "75ef2f55a86312240f0316468a693500efe97cf097cc7d22bcd9ffe237f473dc"
}

rule MalwareBazaar_unknown_035_a0006e9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0006e9a7a2dbf8e1245a3d6e0847130b337a463ec60b0f0c7ccac3a244303f1"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-10 01:23:44"
  condition:
    hash.sha256(0, filesize) == "a0006e9a7a2dbf8e1245a3d6e0847130b337a463ec60b0f0c7ccac3a244303f1"
}

rule MalwareBazaar_Mirai_036_c0c587ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0c587eff26893624f4fa504208ed33fe03589228406431549cfead5c44f17e3"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-10 00:51:47"
  condition:
    hash.sha256(0, filesize) == "c0c587eff26893624f4fa504208ed33fe03589228406431549cfead5c44f17e3"
}

rule MalwareBazaar_unknown_037_c414e837
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c414e83794ecb9ed7fc4f39b2b69ac84473721d622fa09c6d565852e777b0e02"
    family = "unknown"
    file_name = "XBDTGO.464.dec"
    file_type = "exe"
    first_seen = "2026-08-10 00:27:28"
  condition:
    hash.sha256(0, filesize) == "c414e83794ecb9ed7fc4f39b2b69ac84473721d622fa09c6d565852e777b0e02"
}

rule MalwareBazaar_unknown_038_6eba72e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eba72e816768b1c383487af637ddc3d64e5feacaed1bd7312b983bf28478ecd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-10 00:26:52"
  condition:
    hash.sha256(0, filesize) == "6eba72e816768b1c383487af637ddc3d64e5feacaed1bd7312b983bf28478ecd"
}

rule MalwareBazaar_unknown_039_dc5422ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc5422ec75cbe6a12f2788a310f2f487e1be22768ca7b0db5aae3f17b90b19e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-10 00:21:18"
  condition:
    hash.sha256(0, filesize) == "dc5422ec75cbe6a12f2788a310f2f487e1be22768ca7b0db5aae3f17b90b19e0"
}

rule MalwareBazaar_unknown_040_6a207057
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649"
    family = "unknown"
    file_name = "6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649"
    file_type = "elf"
    first_seen = "2026-08-10 00:20:39"
  condition:
    hash.sha256(0, filesize) == "6a207057c4750722c439c989b3270a6ccb60129a2d61b86286a3edef1f31e649"
}

rule MalwareBazaar_unknown_041_0a3e9686
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a3e9686877a670b85b55c614b53decbdc97988605ac1c2fdcf2b56e25e080c6"
    family = "unknown"
    file_name = "PFTZZN.478.dec"
    file_type = "exe"
    first_seen = "2026-08-10 00:05:53"
  condition:
    hash.sha256(0, filesize) == "0a3e9686877a670b85b55c614b53decbdc97988605ac1c2fdcf2b56e25e080c6"
}

rule MalwareBazaar_unknown_042_43b72197
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43b7219764a030a1b3f8466421890f8433928152aee42a497d0d2e4ed1284a98"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 23:58:10"
  condition:
    hash.sha256(0, filesize) == "43b7219764a030a1b3f8466421890f8433928152aee42a497d0d2e4ed1284a98"
}

rule MalwareBazaar_unknown_043_1486367f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1486367f2721ec266fc2df924c9f240572a01af6564a7ea8091550c552e93cce"
    family = "unknown"
    file_name = "E0D1751CC03E266E5C44CA729DB16D6E.exe"
    file_type = "exe"
    first_seen = "2026-08-09 23:55:34"
  condition:
    hash.sha256(0, filesize) == "1486367f2721ec266fc2df924c9f240572a01af6564a7ea8091550c552e93cce"
}

rule MalwareBazaar_unknown_044_f5c235bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c235bf56a9c15afb65f83f437678cd6fac7e23b9a850b7806d395f4b778948"
    family = "unknown"
    file_name = "geometrydash.apk"
    file_type = "elf"
    first_seen = "2026-08-09 23:55:16"
  condition:
    hash.sha256(0, filesize) == "f5c235bf56a9c15afb65f83f437678cd6fac7e23b9a850b7806d395f4b778948"
}

rule MalwareBazaar_Loda_045_1cd822b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cd822b584795da0981798fd11958635deaccc72b50ba2a6c3e9981fa4f94c29"
    family = "Loda"
    file_name = "E0D1751CC03E266E5C44CA729DB16D6E.exe"
    file_type = "exe"
    first_seen = "2026-08-09 23:55:04"
  condition:
    hash.sha256(0, filesize) == "1cd822b584795da0981798fd11958635deaccc72b50ba2a6c3e9981fa4f94c29"
}

rule MalwareBazaar_unknown_046_f116c040
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f116c0400a9cd5d5629bdf6453cabaa4f1715a042d4efd6e5882f30f6642c1aa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 23:19:10"
  condition:
    hash.sha256(0, filesize) == "f116c0400a9cd5d5629bdf6453cabaa4f1715a042d4efd6e5882f30f6642c1aa"
}

rule MalwareBazaar_unknown_047_8c78a55c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c78a55c8bf545e0d21b8757eaa0b709b4af47b13d34a38df81045e67026bd96"
    family = "unknown"
    file_name = "sostener2.vbs"
    file_type = "unknown"
    first_seen = "2026-08-09 23:06:15"
  condition:
    hash.sha256(0, filesize) == "8c78a55c8bf545e0d21b8757eaa0b709b4af47b13d34a38df81045e67026bd96"
}

rule MalwareBazaar_unknown_048_e2a6e93c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2a6e93cf04fdeafa93bb6e541107f5bfcf78ab79d92f1bf51c69de1d4f55433"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 22:52:30"
  condition:
    hash.sha256(0, filesize) == "e2a6e93cf04fdeafa93bb6e541107f5bfcf78ab79d92f1bf51c69de1d4f55433"
}

rule MalwareBazaar_unknown_049_c7cf596b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7cf596bfb34b83148bfc5d0bc17cc559fcda297d8308da9a3a71a82d5cba5e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 22:47:03"
  condition:
    hash.sha256(0, filesize) == "c7cf596bfb34b83148bfc5d0bc17cc559fcda297d8308da9a3a71a82d5cba5e0"
}

rule MalwareBazaar_unknown_050_c353b5eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869"
    family = "unknown"
    file_name = "c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869.bin"
    file_type = "unknown"
    first_seen = "2026-08-09 22:19:46"
  condition:
    hash.sha256(0, filesize) == "c353b5ebbf55e2cd1d6b50a04707b364f746e8ea3b5a17896bdc5c80a7e78869"
}

rule MalwareBazaar_unknown_051_3341d939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87"
    family = "unknown"
    file_name = "3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87.bin"
    file_type = "unknown"
    first_seen = "2026-08-09 22:19:32"
  condition:
    hash.sha256(0, filesize) == "3341d939b43c52d0f254b3020bd396f05cd874fa1873dffad839a0d927edee87"
}

rule MalwareBazaar_unknown_052_80feaa29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80feaa2945c81e75c5045e9e403bff5e8914f4691e525eee5064c04d3ab421a6"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 21:52:28"
  condition:
    hash.sha256(0, filesize) == "80feaa2945c81e75c5045e9e403bff5e8914f4691e525eee5064c04d3ab421a6"
}

rule MalwareBazaar_unknown_053_629cfb8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629cfb8d9fcb99aa0083415da49692ce4c94ecf01ed173e628a8ea8a9d4a5cf9"
    family = "unknown"
    file_name = "WatchForParty Setup 1.2.0.exe"
    file_type = "exe"
    first_seen = "2026-08-09 21:46:49"
  condition:
    hash.sha256(0, filesize) == "629cfb8d9fcb99aa0083415da49692ce4c94ecf01ed173e628a8ea8a9d4a5cf9"
}

rule MalwareBazaar_Mirai_054_aeede7ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeede7ef5532b1a261640e1b8becabb87619adb893cb7a5a7c9e45e1397b7214"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:45"
  condition:
    hash.sha256(0, filesize) == "aeede7ef5532b1a261640e1b8becabb87619adb893cb7a5a7c9e45e1397b7214"
}

rule MalwareBazaar_Mirai_055_f9fc8919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9fc8919461bc8a4e023fd4e155edb29cefe60d5ff60ec4d9dee34dbe608b7de"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:42"
  condition:
    hash.sha256(0, filesize) == "f9fc8919461bc8a4e023fd4e155edb29cefe60d5ff60ec4d9dee34dbe608b7de"
}

rule MalwareBazaar_Mirai_056_228d7fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "228d7fb728de73c767ce29a875a51166c20e1337bca94a95df59472fe8129d3a"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:40"
  condition:
    hash.sha256(0, filesize) == "228d7fb728de73c767ce29a875a51166c20e1337bca94a95df59472fe8129d3a"
}

rule MalwareBazaar_Mirai_057_859c7ea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "859c7ea1bd8957aba1507f9b63c8717fb8cfe39632c05d00b47edece313fd775"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-09 21:38:35"
  condition:
    hash.sha256(0, filesize) == "859c7ea1bd8957aba1507f9b63c8717fb8cfe39632c05d00b47edece313fd775"
}

rule MalwareBazaar_Mirai_058_a610644c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a610644ce6bd9531062134b5a017f5339edcb79bdd247cb7c4acf32c2d147b6f"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:53"
  condition:
    hash.sha256(0, filesize) == "a610644ce6bd9531062134b5a017f5339edcb79bdd247cb7c4acf32c2d147b6f"
}

rule MalwareBazaar_Mirai_059_0f731dea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f731dea0d5ade4a346204d58d650eb8833a2d5958078320e4035e4d06bf4045"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:51"
  condition:
    hash.sha256(0, filesize) == "0f731dea0d5ade4a346204d58d650eb8833a2d5958078320e4035e4d06bf4045"
}

rule MalwareBazaar_Mirai_060_3dcf0133
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dcf0133640f73c2a0e0ae748b927aec4d698036bdb213b16306da558499e1c9"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:50"
  condition:
    hash.sha256(0, filesize) == "3dcf0133640f73c2a0e0ae748b927aec4d698036bdb213b16306da558499e1c9"
}

rule MalwareBazaar_Mirai_061_a09a3ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a09a3ac37a49a36a0ae56159890f44be2b98d2539a0083eeaac9ef06df293b11"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:49"
  condition:
    hash.sha256(0, filesize) == "a09a3ac37a49a36a0ae56159890f44be2b98d2539a0083eeaac9ef06df293b11"
}

rule MalwareBazaar_Mirai_062_225180ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "225180eedf6fa9533eb28c6e060e40c71a04c0a12cb1fb6a5d67a917855c3287"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:47"
  condition:
    hash.sha256(0, filesize) == "225180eedf6fa9533eb28c6e060e40c71a04c0a12cb1fb6a5d67a917855c3287"
}

rule MalwareBazaar_Mirai_063_db536bc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db536bc1e79bfdfaf454199e1eec59c34e8168028c30f24f4f1962314b150cd0"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:46"
  condition:
    hash.sha256(0, filesize) == "db536bc1e79bfdfaf454199e1eec59c34e8168028c30f24f4f1962314b150cd0"
}

rule MalwareBazaar_Mirai_064_cb28ac52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb28ac52b01aae74781bfd0e606238d6a6d0d86565f29402f5578d64aafcfadf"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:45"
  condition:
    hash.sha256(0, filesize) == "cb28ac52b01aae74781bfd0e606238d6a6d0d86565f29402f5578d64aafcfadf"
}

rule MalwareBazaar_Mirai_065_057b8120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057b81202f6505c2024a273f065ec606994ab42d6326be506676d88ec03320a9"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-08-09 21:37:43"
  condition:
    hash.sha256(0, filesize) == "057b81202f6505c2024a273f065ec606994ab42d6326be506676d88ec03320a9"
}

rule MalwareBazaar_CoinMiner_066_336b0f9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9"
    family = "CoinMiner"
    file_name = "336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9.exe"
    file_type = "exe"
    first_seen = "2026-08-09 21:28:45"
  condition:
    hash.sha256(0, filesize) == "336b0f9c3a253185c700bf3516dad58725a7e442cf83d07fee9e50911470e5c9"
}

rule MalwareBazaar_unknown_067_aed1c085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81"
    family = "unknown"
    file_name = "aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81.bin"
    file_type = "unknown"
    first_seen = "2026-08-09 21:20:14"
  condition:
    hash.sha256(0, filesize) == "aed1c085d62d724ca8b74b588eec3b923acd8a6d29dc63f84047f206c853ad81"
}

rule MalwareBazaar_unknown_068_2c216e25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc"
    family = "unknown"
    file_name = "2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc.exe"
    file_type = "exe"
    first_seen = "2026-08-09 21:20:10"
  condition:
    hash.sha256(0, filesize) == "2c216e25c7b4fcde4393264c822e718044f93e657c14253983136bbda06bd9bc"
}

rule MalwareBazaar_Mirai_069_3c38434b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c38434b6ab45e0f4a2409cabd4bebfbbd1fbb3cc1b2d454180b4ea44b192a7d"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-09 21:03:57"
  condition:
    hash.sha256(0, filesize) == "3c38434b6ab45e0f4a2409cabd4bebfbbd1fbb3cc1b2d454180b4ea44b192a7d"
}

rule MalwareBazaar_Mirai_070_c68b3590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c68b3590f893ae0a6155db05e88119cc958a76c2cf3f7168f12c7ccf5861ee45"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-09 20:57:41"
  condition:
    hash.sha256(0, filesize) == "c68b3590f893ae0a6155db05e88119cc958a76c2cf3f7168f12c7ccf5861ee45"
}

rule MalwareBazaar_unknown_071_ffbdd670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffbdd6701bc06df37076a057f34a50ef286ff3c735e5c3fc1f9ca984e6c82871"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 20:52:27"
  condition:
    hash.sha256(0, filesize) == "ffbdd6701bc06df37076a057f34a50ef286ff3c735e5c3fc1f9ca984e6c82871"
}

rule MalwareBazaar_Mirai_072_54d2f14a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54d2f14a4e9e61dec0954a2efe866753e2bf304b02313d468b273b32b84b2047"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-09 20:51:43"
  condition:
    hash.sha256(0, filesize) == "54d2f14a4e9e61dec0954a2efe866753e2bf304b02313d468b273b32b84b2047"
}

rule MalwareBazaar_unknown_073_5df7f623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7"
    family = "unknown"
    file_name = "5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7.exe"
    file_type = "exe"
    first_seen = "2026-08-09 20:50:01"
  condition:
    hash.sha256(0, filesize) == "5df7f62378cb073fa04a10740bfb378ff1ea0953e4e0d560ccdb8ba044f187c7"
}

rule MalwareBazaar_Mirai_074_607e6931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "607e69311a7cd5f6becb65334193965b9c5436b8ea8b86bcc04ace0b391754a1"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-09 20:49:41"
  condition:
    hash.sha256(0, filesize) == "607e69311a7cd5f6becb65334193965b9c5436b8ea8b86bcc04ace0b391754a1"
}

rule MalwareBazaar_unknown_075_3f52c9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f52c9d217c625a8e8b12be29c828d27dbec62bf021d5f0d481dcced080043e8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 20:42:56"
  condition:
    hash.sha256(0, filesize) == "3f52c9d217c625a8e8b12be29c828d27dbec62bf021d5f0d481dcced080043e8"
}

rule MalwareBazaar_Mirai_076_f1712480
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1712480cba485a3a146af70a45ba896419fa83b8e3dd846f2c27a4772aabfdd"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-09 20:39:43"
  condition:
    hash.sha256(0, filesize) == "f1712480cba485a3a146af70a45ba896419fa83b8e3dd846f2c27a4772aabfdd"
}

rule MalwareBazaar_unknown_077_28c5cccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c5cccd904a42f5393074833568646c27b33aec0513e1c5a4b83e92d9bc8a57"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-09 20:33:49"
  condition:
    hash.sha256(0, filesize) == "28c5cccd904a42f5393074833568646c27b33aec0513e1c5a4b83e92d9bc8a57"
}

rule MalwareBazaar_unknown_078_109a9689
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "109a968976cf3c6a950e5956963c3ba5b3206d261d16b025df21059974c72971"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-09 20:25:46"
  condition:
    hash.sha256(0, filesize) == "109a968976cf3c6a950e5956963c3ba5b3206d261d16b025df21059974c72971"
}

rule MalwareBazaar_unknown_079_6da56af8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da56af87f9d4848a02fc392b74f38f0ab165d8d97d014acd96362210dc144b5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 20:19:42"
  condition:
    hash.sha256(0, filesize) == "6da56af87f9d4848a02fc392b74f38f0ab165d8d97d014acd96362210dc144b5"
}

rule MalwareBazaar_unknown_080_f6a89afd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6a89afd80bcfccc8ade155c0ef92a770de44610efdcac2b6a21650dc136dca5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 20:18:32"
  condition:
    hash.sha256(0, filesize) == "f6a89afd80bcfccc8ade155c0ef92a770de44610efdcac2b6a21650dc136dca5"
}

rule MalwareBazaar_Mirai_081_907e8720
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "907e8720528ff4a45168679e5b6865f527089d2f0ce0e3594e947a5b07ae5d00"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-09 20:07:43"
  condition:
    hash.sha256(0, filesize) == "907e8720528ff4a45168679e5b6865f527089d2f0ce0e3594e947a5b07ae5d00"
}

rule MalwareBazaar_unknown_082_014f5068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "014f5068274dc499a77cac8ec4e0168ed142cdfd29a772a721ca65b35cd467f9"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-09 20:07:42"
  condition:
    hash.sha256(0, filesize) == "014f5068274dc499a77cac8ec4e0168ed142cdfd29a772a721ca65b35cd467f9"
}

rule MalwareBazaar_Mirai_083_d9e85bf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9e85bf2a14b2ee550e5b5132550a6efe74e3289e72d30e5c3220a723e1990e7"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-09 20:07:41"
  condition:
    hash.sha256(0, filesize) == "d9e85bf2a14b2ee550e5b5132550a6efe74e3289e72d30e5c3220a723e1990e7"
}

rule MalwareBazaar_Mirai_084_56c43ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c43ff49fda9a95111adbcc0076919244c7962ce22f5d2c41b18fb01fdf090f"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-09 20:05:42"
  condition:
    hash.sha256(0, filesize) == "56c43ff49fda9a95111adbcc0076919244c7962ce22f5d2c41b18fb01fdf090f"
}

rule MalwareBazaar_unknown_085_f6c878d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6c878d6f2c1b4e2bb12fc3a1bc555cdc8d1fd4679728e2f58b4df0429cd9efe"
    family = "unknown"
    file_name = "f"
    file_type = "elf"
    first_seen = "2026-08-09 19:59:36"
  condition:
    hash.sha256(0, filesize) == "f6c878d6f2c1b4e2bb12fc3a1bc555cdc8d1fd4679728e2f58b4df0429cd9efe"
}

rule MalwareBazaar_unknown_086_50fa9aa2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50fa9aa29ed55faf83cfe718097bb66a104a83cfddbd0fed4db702dfe6b84e83"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-09 19:57:37"
  condition:
    hash.sha256(0, filesize) == "50fa9aa29ed55faf83cfe718097bb66a104a83cfddbd0fed4db702dfe6b84e83"
}

rule MalwareBazaar_unknown_087_c962067f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c962067f11b2f516f0686d4c659b2717aaff65ca529bf0e03d51f9ce70f9537f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 19:53:39"
  condition:
    hash.sha256(0, filesize) == "c962067f11b2f516f0686d4c659b2717aaff65ca529bf0e03d51f9ce70f9537f"
}

rule MalwareBazaar_Mirai_088_e3380c14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3380c141107fec48efb61170278e0cc74bdc793d669fc660483d929fa22871e"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-09 19:53:38"
  condition:
    hash.sha256(0, filesize) == "e3380c141107fec48efb61170278e0cc74bdc793d669fc660483d929fa22871e"
}

rule MalwareBazaar_unknown_089_633af775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "633af775e71f8752dc4ea4ec64bbbb79ded0004cc4ef13b074a54f1d7321096f"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-09 19:52:30"
  condition:
    hash.sha256(0, filesize) == "633af775e71f8752dc4ea4ec64bbbb79ded0004cc4ef13b074a54f1d7321096f"
}

rule MalwareBazaar_Mirai_090_866569b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866569b33ab608b5bebbd4796b12e605d826cde7fb335409e332c08d02aae132"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-09 19:51:43"
  condition:
    hash.sha256(0, filesize) == "866569b33ab608b5bebbd4796b12e605d826cde7fb335409e332c08d02aae132"
}

rule MalwareBazaar_unknown_091_a6d87ca4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6d87ca41c596e3f8a06ce4cc6105cc2e5a133fca49da4d78d16116f298dd931"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-09 19:47:44"
  condition:
    hash.sha256(0, filesize) == "a6d87ca41c596e3f8a06ce4cc6105cc2e5a133fca49da4d78d16116f298dd931"
}

rule MalwareBazaar_Mirai_092_cca31891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cca318919263231e18be956046e4d74c295c12e091a31c4ecc593775fa34e198"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-09 19:45:39"
  condition:
    hash.sha256(0, filesize) == "cca318919263231e18be956046e4d74c295c12e091a31c4ecc593775fa34e198"
}

rule MalwareBazaar_unknown_093_c2235ce0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2235ce06b77fd6b73cdf3e825d2200308aff3a48aba90044ecc6eba2b4b951c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 19:45:38"
  condition:
    hash.sha256(0, filesize) == "c2235ce06b77fd6b73cdf3e825d2200308aff3a48aba90044ecc6eba2b4b951c"
}

rule MalwareBazaar_Mirai_094_5127a4b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5127a4b2e74ed750fe8d18bd196c5d6ea926979b35910443a4087329ce98b781"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-09 19:37:36"
  condition:
    hash.sha256(0, filesize) == "5127a4b2e74ed750fe8d18bd196c5d6ea926979b35910443a4087329ce98b781"
}

rule MalwareBazaar_Mirai_095_8c7f926e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c7f926e3ee6c27892f4bc2d93d915586c41d2eee94a2721b11c9d769046111a"
    family = "Mirai"
    file_name = "SecuriteInfo.com.ELF.Mirai.APD.tr.27914.20887"
    file_type = "elf"
    first_seen = "2026-08-09 19:35:36"
  condition:
    hash.sha256(0, filesize) == "8c7f926e3ee6c27892f4bc2d93d915586c41d2eee94a2721b11c9d769046111a"
}

rule MalwareBazaar_unknown_096_931e3455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df"
    family = "unknown"
    file_name = "931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:30:01"
  condition:
    hash.sha256(0, filesize) == "931e34552fae7cd90bea3f68ad247b8602cb2daa1734e8fe28a1c863fb8796df"
}

rule MalwareBazaar_Mirai_097_2e0cf5af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5"
    family = "Mirai"
    file_name = "2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:24:53"
  condition:
    hash.sha256(0, filesize) == "2e0cf5af50240dbbd1105637e53d2ffff73379ffdc13bc8483d47d39c44775c5"
}

rule MalwareBazaar_unknown_098_6cae7a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986"
    family = "unknown"
    file_name = "6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:19:57"
  condition:
    hash.sha256(0, filesize) == "6cae7a11941d4b5993a30bccf786ee39d0051736443df539b7c8cf551d8d4986"
}

rule MalwareBazaar_Mirai_099_bf807da8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf807da85ac1b940cad9795a33f101467c72674d7f98ae6b61c3a5e3695a17a5"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-09 19:19:42"
  condition:
    hash.sha256(0, filesize) == "bf807da85ac1b940cad9795a33f101467c72674d7f98ae6b61c3a5e3695a17a5"
}

rule MalwareBazaar_unknown_100_f4bdbd06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e"
    family = "unknown"
    file_name = "f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e.elf"
    file_type = "elf"
    first_seen = "2026-08-09 19:15:07"
  condition:
    hash.sha256(0, filesize) == "f4bdbd0603010c136ee9582e391ea5546a5f8c1fe541c92425a6d046a38c648e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

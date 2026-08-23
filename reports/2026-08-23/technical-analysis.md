# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-23

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 625 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 625 |
| Unique family labels | 9 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 48 |
| Mirai | 36 |
| RemusStealer | 7 |
| Vidar | 4 |
| WannaCry | 1 |
| SnappyClient | 1 |
| AsyncRAT | 1 |
| CoinMiner | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 40 |
| elf | 39 |
| unknown | 10 |
| sh | 8 |
| iso | 1 |
| msi | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `2f579dc80d3ba5d6`

| Field | Value |
|---|---|
| SHA-256 | `2f579dc80d3ba5d6bb786464049281528c326497f3bba3fc7689767a51987034` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-23 01:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79028fa0dc95eceebb99ad66f4aede67` |
| SHA-256 | `2f579dc80d3ba5d6bb786464049281528c326497f3bba3fc7689767a51987034` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_2f579dc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f579dc80d3ba5d6bb786464049281528c326497f3bba3fc7689767a51987034"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 01:52:10"
  condition:
    hash.sha256(0, filesize) == "2f579dc80d3ba5d6bb786464049281528c326497f3bba3fc7689767a51987034"
}
```

### Sample 2: `22b80878a53e54dd`

| Field | Value |
|---|---|
| SHA-256 | `22b80878a53e54dda7d026318cb5a080cf34b12296cbf6ec885ebe55c330f446` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-23 01:34:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73c4db07d57fc6a77ee05592ce76dc48` |
| SHA-1 | `9dd5c91ed3ff57d00519c70c7c825d158b9e8a8a` |
| SHA-256 | `22b80878a53e54dda7d026318cb5a080cf34b12296cbf6ec885ebe55c330f446` |
| SHA3-384 | `d89037f8d0be8393d5549cf16295037ef77656a9c61c88a8304d6c68fe12fe91f56f6839a2b3f58bf5170f26ece1a1e3` |
| TLSH | `T1B4040755FC418A13CAC366BBFF4D428D37271768D3EE320399256F21279A86B0E7B146` |
| TELFHASH | `t1e73131148f981d9cb3e04978909e522b65ec35f8b9282861be5ecfce0d134d2b438c2f` |
| SSDEEP | `3072:FMaLwN1OxSJ74FX8ouh3o4zVwO1Iw8URRj9IvS5ntOXSEkUw7XH5ekzbTpH4p10P:FMYU1OwJcFX8oQo4zyQIwjRR+wMXSEk7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_22b80878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22b80878a53e54dda7d026318cb5a080cf34b12296cbf6ec885ebe55c330f446"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-23 01:34:13"
  condition:
    hash.sha256(0, filesize) == "22b80878a53e54dda7d026318cb5a080cf34b12296cbf6ec885ebe55c330f446"
}
```

### Sample 3: `3fb7b63a67396bec`

| Field | Value |
|---|---|
| SHA-256 | `3fb7b63a67396bec9b30a424e1136a3283e44bdbbabc47b1063fa44cbcaedb4c` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-23 01:33:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f24e1604ef1d57f205926500a29af9ef` |
| SHA-1 | `37f303c3442f40bc210ac4625157496ce75cb28e` |
| SHA-256 | `3fb7b63a67396bec9b30a424e1136a3283e44bdbbabc47b1063fa44cbcaedb4c` |
| SHA3-384 | `de699fee29c3125ab8ec7ddcc71568b5c8310a8a34fc68a6cfa5f82b164fc7e38bdd866a945afdcdb821d8e3de104782` |
| TLSH | `T1386302A03E927411DA521537E51F8942F81B22E8E9F6F3743D19245BF0EBD9BC8B04DA` |
| SSDEEP | `1536:AxVXXArRNOn/uWFsBRnB4F+7Yi0tVUqMzh:ADHAMuWaRnxOVUJt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_3fb7b63a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb7b63a67396bec9b30a424e1136a3283e44bdbbabc47b1063fa44cbcaedb4c"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-23 01:33:16"
  condition:
    hash.sha256(0, filesize) == "3fb7b63a67396bec9b30a424e1136a3283e44bdbbabc47b1063fa44cbcaedb4c"
}
```

### Sample 4: `73e99a29a8b4c4f1`

| Field | Value |
|---|---|
| SHA-256 | `73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232` |
| Family label | `unknown` |
| File name | `73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232` |
| File type | `elf` |
| First seen | `2026-08-23 01:25:45` |
| Reporter | `cybersecproject` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a21885ecca118db2dc403b702d9a0f9e` |
| SHA-1 | `2fed1feac60d17bca65548a454cca958b63585b9` |
| SHA-256 | `73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232` |
| SHA3-384 | `619069414d1c75fe5f6a4b726e792e3471a3de86a5fbedc96302bdf5616d360c0b2ed697d0d524ee2ed43a6563dc95d3` |
| TLSH | `T1B1163349EC9D3A73CB1A32782A783AA18BECBC598D25C1689D130F51FD0D731316E9D9` |
| SSDEEP | `98304:RqDLvFvuP3Ecd+bR+oTyW2wiIMA5qJSGUXB5NGK:RO7FvS3EcSVkBkqAt5NL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_73e99a29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232"
    family = "unknown"
    file_name = "73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232"
    file_type = "elf"
    first_seen = "2026-08-23 01:25:45"
  condition:
    hash.sha256(0, filesize) == "73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232"
}
```

### Sample 5: `a6fbbdec757b0fe9`

| Field | Value |
|---|---|
| SHA-256 | `a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049` |
| Family label | `unknown` |
| File name | `a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049` |
| File type | `elf` |
| First seen | `2026-08-23 01:16:54` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f954494173b99bff50efd3899e4425d` |
| SHA-1 | `0e46e722243dd52eeb701883f79f786a92fe47ba` |
| SHA-256 | `a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049` |
| SHA3-384 | `fa9107460ce44e0fea2dbded43a31783dfd44ab1e36f10936474a70a764bb51d679a2f4a07829d3cf918d2c27683ae63` |
| TLSH | `T1E895F857F49590E4C0EEE174C726A213BEA13499473837E36FA186F11B26FE4A6BC314` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzs:cqYUQuVDI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_a6fbbdec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049"
    family = "unknown"
    file_name = "a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049"
    file_type = "elf"
    first_seen = "2026-08-23 01:16:54"
  condition:
    hash.sha256(0, filesize) == "a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049"
}
```

### Sample 6: `7ab43ecf8d7bb6cd`

| Field | Value |
|---|---|
| SHA-256 | `7ab43ecf8d7bb6cdc9caa10ae48317d550a2f586ee5bcbc21065d3e9f629b03b` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-23 00:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `465c80b3bc30a1e1e7d3cb1795192c7a` |
| SHA-256 | `7ab43ecf8d7bb6cdc9caa10ae48317d550a2f586ee5bcbc21065d3e9f629b03b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_7ab43ecf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ab43ecf8d7bb6cdc9caa10ae48317d550a2f586ee5bcbc21065d3e9f629b03b"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 00:52:11"
  condition:
    hash.sha256(0, filesize) == "7ab43ecf8d7bb6cdc9caa10ae48317d550a2f586ee5bcbc21065d3e9f629b03b"
}
```

### Sample 7: `d63e71109ca0a304`

| Field | Value |
|---|---|
| SHA-256 | `d63e71109ca0a304312ddc21def555dc9f73c71ddae8d7bcd6f94a189a2d8f0b` |
| Family label | `RemusStealer` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:39:44` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31ac5ef2dc666ab821818fc716d66bf5` |
| SHA-1 | `931d023a2bb0eaf34847d43fe65cc870ca4fb06d` |
| SHA-256 | `d63e71109ca0a304312ddc21def555dc9f73c71ddae8d7bcd6f94a189a2d8f0b` |
| SHA3-384 | `77c20921afb7334388c972d596aaf0c3780e189c961d8356c5511cca24c6a7f0a0646fb177acf8ebde1dc3acf20d6d04` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1BDC57D076D9542B5C49AAF3589768252B631FC0CD73273E32E90BA782F357C19E76B08` |
| SSDEEP | `49152:V9+7jezHDmWINFnEJOrzJTog2z/7UA3TYYVDoJ04rn/7UqURihs5WuQ3IWVg6RGG:HcKHDry+JOPJUg2z/4YVDoJ04rn/7UqF` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_007_d63e7110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d63e71109ca0a304312ddc21def555dc9f73c71ddae8d7bcd6f94a189a2d8f0b"
    family = "RemusStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:39:44"
  condition:
    hash.sha256(0, filesize) == "d63e71109ca0a304312ddc21def555dc9f73c71ddae8d7bcd6f94a189a2d8f0b"
}
```

### Sample 8: `aa5045411ba7da09`

| Field | Value |
|---|---|
| SHA-256 | `aa5045411ba7da09339ea56b718435ed4db6970b77a2495750427c3e0983f4b5` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:38:57` |
| Reporter | `iamaachum` |
| Tags | `exe, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe04a8e07af1dbc71f42f5426f8ea8f2` |
| SHA-1 | `30a88e1ba76824e2ce56e8bbdc771e87f7b0a791` |
| SHA-256 | `aa5045411ba7da09339ea56b718435ed4db6970b77a2495750427c3e0983f4b5` |
| SHA3-384 | `1baff2e3ec931228eb3fa81450492879e2096cef4ff95fafc310ca63910b717feb0c465b4446e8169a8073ec727a6286` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1390733053F62A8F6D2AA80369E0EE3555835E2AA52C8CF17A3FC5E4E1ED3D7543430D9` |
| SSDEEP | `393216:+pbs7d4Hda49iujQ/sqA/3GwsdCWIqpkEsc+1aId9rrl+vNLm/jP:e84HdJ9xjxnBitmEsxYIPrl6CLP` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_aa504541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa5045411ba7da09339ea56b718435ed4db6970b77a2495750427c3e0983f4b5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:38:57"
  condition:
    hash.sha256(0, filesize) == "aa5045411ba7da09339ea56b718435ed4db6970b77a2495750427c3e0983f4b5"
}
```

### Sample 9: `506461eb9cdf0a48`

| Field | Value |
|---|---|
| SHA-256 | `506461eb9cdf0a488c4955188e47b317481932c7427c2994f83192b5f0c0bfd8` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:38:02` |
| Reporter | `iamaachum` |
| Tags | `exe, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7014aa28e0aceb8c34e6d1e3c6ef986` |
| SHA-1 | `f3b9ed878d15af93f42e801aa1533a8fa8f1a79b` |
| SHA-256 | `506461eb9cdf0a488c4955188e47b317481932c7427c2994f83192b5f0c0bfd8` |
| SHA3-384 | `98c362cdcfe43d95596a6bb65c33504272fd284b035e4c7a009d18eea2470b89c46839448e3b7fdbcb5b033f0aebd299` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T11B073381F7E9F4E1E2A1D073590ECB2549B6F36CA3824F5A19A9BF050F528D1DE830D9` |
| SSDEEP | `393216:+pbs7d4HdaCn7xbKN+6LYMG2nJ+11iFuXE7wAbOphzUvoQ/enDWX2:e84HdB74N+6LYlPiwAwAiLU7GCm` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_506461eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "506461eb9cdf0a488c4955188e47b317481932c7427c2994f83192b5f0c0bfd8"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:38:02"
  condition:
    hash.sha256(0, filesize) == "506461eb9cdf0a488c4955188e47b317481932c7427c2994f83192b5f0c0bfd8"
}
```

### Sample 10: `7a3d2c381a1f2400`

| Field | Value |
|---|---|
| SHA-256 | `7a3d2c381a1f24002794f1bf5e7c7a2c73507a04a3741c40f6b7790983892e53` |
| Family label | `unknown` |
| File name | `InstallerV29171x64_.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:35:50` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c035d3a590ef1300c25a4069d634a45` |
| SHA-1 | `ccc3a222db885e363cd9c719d796380642f3afbe` |
| SHA-256 | `7a3d2c381a1f24002794f1bf5e7c7a2c73507a04a3741c40f6b7790983892e53` |
| SHA3-384 | `2bca2d2c18ac12735ac1a5fe9774a034cae4f4db05bd6e38e855eb08205c5ca9b363d224bcb708b680adda195c93d0e9` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T140F633B03E2008A1DD7C18B6C09F57BA17BDC79D628162120F5E713C967E43E9AE7B64` |
| SSDEEP | `393216:UzkEpVEVnmLlUj3QffMwvkqhE2fZXi/LLlUdSK5Eci8i3j:UzhQVnmLCjA8cthE2fZXi/E5vi8i` |
| ICON-DHASH | `0ccecec4d4a2e2a2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_7a3d2c38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a3d2c381a1f24002794f1bf5e7c7a2c73507a04a3741c40f6b7790983892e53"
    family = "unknown"
    file_name = "InstallerV29171x64_.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:35:50"
  condition:
    hash.sha256(0, filesize) == "7a3d2c381a1f24002794f1bf5e7c7a2c73507a04a3741c40f6b7790983892e53"
}
```

### Sample 11: `98dc1ee834d16639`

| Field | Value |
|---|---|
| SHA-256 | `98dc1ee834d166396ed8c20ec28f8defd7e8b127b5da6787dba6cba1abfb6f06` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-08-23 00:35:23` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96f77ac6a1428e4166309756565fdc38` |
| SHA-1 | `ea19cdf910111d22d00a2c63f08f86d21e8ba680` |
| SHA-256 | `98dc1ee834d166396ed8c20ec28f8defd7e8b127b5da6787dba6cba1abfb6f06` |
| SHA3-384 | `a6bcdf423469b574f78268a53d5b869fe2680b05e1fff0e9123d7ff79193fc5f59d444011af2421d678a1291138efaa8` |
| TLSH | `T133F633B03E2008A1DD7C18B6C09F57B617BEC79D628162121F5E313C967E43E9AE7B64` |
| SSDEEP | `393216:DzkEpVEVnmLlUj3QffMwvkqhE2fZXi/LLlUdSK5Eci8i3j:DzhQVnmLCjA8cthE2fZXi/E5vi8i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_98dc1ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98dc1ee834d166396ed8c20ec28f8defd7e8b127b5da6787dba6cba1abfb6f06"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-23 00:35:23"
  condition:
    hash.sha256(0, filesize) == "98dc1ee834d166396ed8c20ec28f8defd7e8b127b5da6787dba6cba1abfb6f06"
}
```

### Sample 12: `85c671370fdca987`

| Field | Value |
|---|---|
| SHA-256 | `85c671370fdca9874db8f56081d8069be21ac0195af2267fc1bbea2d5739c3e6` |
| Family label | `unknown` |
| File name | `dll` |
| File type | `exe` |
| First seen | `2026-08-23 00:35:01` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `565d28c1cda1031ba967eaaced566f24` |
| SHA-1 | `eebe1b1d6f3d419b88c1778c208529d9aff8e38a` |
| SHA-256 | `85c671370fdca9874db8f56081d8069be21ac0195af2267fc1bbea2d5739c3e6` |
| SHA3-384 | `1dbfbadac348402f91eec51d87a7f396248276937df7294d83a35219514baeac27854e021c7cde7fe17510655e2547de` |
| IMPHASH | `00dd128d087d2d10c39a58611ccf6407` |
| TLSH | `T12577336563B6C0F6E8F305314A8B45D4B727BC545B60D9CF4AA42A332E731A06A3CDF2` |
| SSDEEP | `786432:+5vzd21nbhVEHCYFqSSjkLZIHLOSuXMb8O2PBD+gEwLKbuLz5HMLyRtDUW:+9zM1CuHKpcF+BDO0mufl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_85c67137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85c671370fdca9874db8f56081d8069be21ac0195af2267fc1bbea2d5739c3e6"
    family = "unknown"
    file_name = "dll"
    file_type = "exe"
    first_seen = "2026-08-23 00:35:01"
  condition:
    hash.sha256(0, filesize) == "85c671370fdca9874db8f56081d8069be21ac0195af2267fc1bbea2d5739c3e6"
}
```

### Sample 13: `0bb70961853f4ce3`

| Field | Value |
|---|---|
| SHA-256 | `0bb70961853f4ce36650d296b7e945e0dda5a9ac2964e7a217cc35bbfbb1f253` |
| Family label | `RemusStealer` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:33:55` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43a2fd70c618f59ef00e86529a3bbfcd` |
| SHA-1 | `806cd14faeca43740542fd66aa3c27ce787a8a3d` |
| SHA-256 | `0bb70961853f4ce36650d296b7e945e0dda5a9ac2964e7a217cc35bbfbb1f253` |
| SHA3-384 | `9048442dca2aa287e02a7454782fdde72ef2675148de7056c9b5909d86a96a3fb327c07fc054a266ff0b719d9aa30207` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1F5F539072D9540E0C5969F35D63B8692BE34BC48D73537A32E90A9702F25BD26EFDB20` |
| SSDEEP | `49152:NoYY1KRN41s21RzRz8DClm3TWkUiRp0MEd6:iYeuukWbyW6` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_013_0bb70961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bb70961853f4ce36650d296b7e945e0dda5a9ac2964e7a217cc35bbfbb1f253"
    family = "RemusStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:33:55"
  condition:
    hash.sha256(0, filesize) == "0bb70961853f4ce36650d296b7e945e0dda5a9ac2964e7a217cc35bbfbb1f253"
}
```

### Sample 14: `fc0553851d495ff5`

| Field | Value |
|---|---|
| SHA-256 | `fc0553851d495ff5b6aba8c8d472f210f5c5d7ac05dcb56c27c61941eaa3b7ea` |
| Family label | `RemusStealer` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:33:24` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15045b47099b04256ec19beef96fcb30` |
| SHA-1 | `74575f67904870eb80f3abd2bd44d33aa271bc0e` |
| SHA-256 | `fc0553851d495ff5b6aba8c8d472f210f5c5d7ac05dcb56c27c61941eaa3b7ea` |
| SHA3-384 | `7ee8502a9a75c321250ca55e0a2a93237e494f7f750a9d0d1f8ed0c60a48f0bebe661c212440845c064d4769d5826be5` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1B1C57D47AC9140A9D4A6A732896B8153F671BC48CB3633D73F84B6742F727C1AE79B04` |
| SSDEEP | `49152:jKt8CzaVnKAg1AGAOF+YxFbWkQhL0qqPgX:VCWhvg1T+rr` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_014_fc055385
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc0553851d495ff5b6aba8c8d472f210f5c5d7ac05dcb56c27c61941eaa3b7ea"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:33:24"
  condition:
    hash.sha256(0, filesize) == "fc0553851d495ff5b6aba8c8d472f210f5c5d7ac05dcb56c27c61941eaa3b7ea"
}
```

### Sample 15: `0325bda37ee3ae51`

| Field | Value |
|---|---|
| SHA-256 | `0325bda37ee3ae51de29b706986ee9345d9e110b14cdcbde615dd11f959c085a` |
| Family label | `RemusStealer` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:32:38` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fa7935cb39e9dc9bbd93886c82bdae7` |
| SHA-1 | `01f3f92aaec8ac1a6295075cf684e73924b204e5` |
| SHA-256 | `0325bda37ee3ae51de29b706986ee9345d9e110b14cdcbde615dd11f959c085a` |
| SHA3-384 | `9acfe35bc882f12c3b033455656a1a5d6fb676fa92f64d36db17ffef7d836a6d121b8da5b1c3ad271ba0ba8eda8ffab0` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1D3768C17789541E4C4AADF34C47782137A64F8CDDB3523A39E21AA342F757C2ADBAB04` |
| SSDEEP | `49152:QaG9M8050bulX2JswtXbr2dxN/Z1btDEbPMfja0qgcvgxdmIcEwpJ:0tuqrV+xFSbSjGgxdTcE6` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_015_0325bda3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0325bda37ee3ae51de29b706986ee9345d9e110b14cdcbde615dd11f959c085a"
    family = "RemusStealer"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:32:38"
  condition:
    hash.sha256(0, filesize) == "0325bda37ee3ae51de29b706986ee9345d9e110b14cdcbde615dd11f959c085a"
}
```

### Sample 16: `803af293617ebe93`

| Field | Value |
|---|---|
| SHA-256 | `803af293617ebe93de009614e1b029fa7bd07616e9c1dda0019fd6c69fe409e6` |
| Family label | `RemusStealer` |
| File name | `517824218.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:31:04` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-RenPyLoader, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2db3fa70d6f6dad930e9239281444f18` |
| SHA-1 | `7d394bf5a6b5bdcefe7e1d7dbd6aca1050e19086` |
| SHA-256 | `803af293617ebe93de009614e1b029fa7bd07616e9c1dda0019fd6c69fe409e6` |
| SHA3-384 | `e6ac2f788e5e144dab77c86f9bcc7673cbc654ecffcb81a5c8d675e21bb9bb57e42ea37ceffcbf3bc5409dcfbc3ebb06` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1F3563913799541E4C4AADE34C47782137A64F88D9B3437936E21AE342FB97C29DBBB04` |
| SSDEEP | `24576:suWTHMPE01xGG27PCIaVYfB9zW44oGD+HdW5ykhSZ4OLkfimECUTLR6mqlKcVmi7:1WAPEklki4Ki91CskqmELLRl32Hl+K` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_016_803af293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "803af293617ebe93de009614e1b029fa7bd07616e9c1dda0019fd6c69fe409e6"
    family = "RemusStealer"
    file_name = "517824218.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:31:04"
  condition:
    hash.sha256(0, filesize) == "803af293617ebe93de009614e1b029fa7bd07616e9c1dda0019fd6c69fe409e6"
}
```

### Sample 17: `bfa315c6c37f5bac`

| Field | Value |
|---|---|
| SHA-256 | `bfa315c6c37f5bac2c5959d4e606d11ca1ae1a46e09b107e16983709e08538b3` |
| Family label | `unknown` |
| File name | `UTODYIBG.msi` |
| File type | `msi` |
| First seen | `2026-08-23 00:29:44` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, HijackLoader, msi, SnappyClient, softwareinformsdk-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfca53ca1e4f8d8138093a35dff51cd1` |
| SHA-1 | `7291c516ff7cb309ff4db7636f1a0b575a03354e` |
| SHA-256 | `bfa315c6c37f5bac2c5959d4e606d11ca1ae1a46e09b107e16983709e08538b3` |
| SHA3-384 | `a632597be467efb27d90c67aeb66417fe31732502d131cf3603a924f4e21665811d7a108958eedb5717f781d9ae57a62` |
| TLSH | `T12E66338CF53AAA53D1C9FB399DCD46906FF99E439FA1181E3580B6E409F81E1318E4C6` |
| SSDEEP | `196608:1XpOfy4WUFUqXtW0wKm1TqxkIQ70t0aIoHH:1X2fq+E9Km1Tqxkf0tJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_bfa315c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfa315c6c37f5bac2c5959d4e606d11ca1ae1a46e09b107e16983709e08538b3"
    family = "unknown"
    file_name = "UTODYIBG.msi"
    file_type = "msi"
    first_seen = "2026-08-23 00:29:44"
  condition:
    hash.sha256(0, filesize) == "bfa315c6c37f5bac2c5959d4e606d11ca1ae1a46e09b107e16983709e08538b3"
}
```

### Sample 18: `c23360a782643838`

| Field | Value |
|---|---|
| SHA-256 | `c23360a78264383810f154246cc656e556bc89b3e1765ccc8970f016a53a1e05` |
| Family label | `unknown` |
| File name | `b1.ps1` |
| File type | `ps1` |
| First seen | `2026-08-23 00:29:02` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, HijackLoader, ps1, SnappyClient, softwareinformsdk-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c4df7d860e754906eb8abe8ebcf2ebf` |
| SHA-1 | `51e58cde4d13f2fcf61172ec06d76e2ededd7e5c` |
| SHA-256 | `c23360a78264383810f154246cc656e556bc89b3e1765ccc8970f016a53a1e05` |
| SHA3-384 | `41747a6d30697b244e47e5a39441e87df413b811058b5180ebaa0135be3c0460b1789bef8a5e3d54d51c5fa747c8d38f` |
| TLSH | `T1D7548F489E44A5FD2253007A24D224EDA638573988F83575364BC68EF14CF3DE9B9EF2` |
| SSDEEP | `3072:maHkMycSDrDztOnmGJR6FvDPA41EAmVCP39zzlHy8oi0vzSmYnSy0xLFiTBnNjbg:zHkpDLw81KAm0P3NZHz99nd0yVVbG9J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_c23360a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23360a78264383810f154246cc656e556bc89b3e1765ccc8970f016a53a1e05"
    family = "unknown"
    file_name = "b1.ps1"
    file_type = "ps1"
    first_seen = "2026-08-23 00:29:02"
  condition:
    hash.sha256(0, filesize) == "c23360a78264383810f154246cc656e556bc89b3e1765ccc8970f016a53a1e05"
}
```

### Sample 19: `4772fcead4cf5168`

| Field | Value |
|---|---|
| SHA-256 | `4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58` |
| Family label | `WannaCry` |
| File name | `4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58` |
| File type | `exe` |
| First seen | `2026-08-23 00:15:27` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e1aad1fe43fca159fb616a2c2d72c42` |
| SHA-1 | `b28a34e7e9defee41c70b578fcd5b9318905797e` |
| SHA-256 | `4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58` |
| SHA3-384 | `b82f8b6e89fb99cf865a1b6a6c626174cdbca6c0082c72b6944e46e3131ade9811c6d7616da50e780ba9c3abeee5b9fc` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1D4363398626CA1FCF0450EB444B38E1AF7B37C5567BA4B0F8780866B0D53B9BAF94741` |
| SSDEEP | `98304:D8DqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2H:D8DqPe1Cxcxk3ZAEUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_019_4772fcea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58"
    family = "WannaCry"
    file_name = "4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58"
    file_type = "exe"
    first_seen = "2026-08-23 00:15:27"
  condition:
    hash.sha256(0, filesize) == "4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58"
}
```

### Sample 20: `6f295f2aa87bdc8c`

| Field | Value |
|---|---|
| SHA-256 | `6f295f2aa87bdc8c3d44d7c71d642bfa3bf647293e0f72295b2a09100ad686df` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-23 00:09:49` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4448ff3acf0bb078c5233b6cc0f977ca` |
| SHA-1 | `8d778fb4d32b91d39000e1581a868ecd9cd13194` |
| SHA-256 | `6f295f2aa87bdc8c3d44d7c71d642bfa3bf647293e0f72295b2a09100ad686df` |
| SHA3-384 | `a23a51c065d5f2b08ab14babab692051fa2a825642d46c7b61b2898cadb00f2540335ef15c253f53beb54fd348c8c05a` |
| IMPHASH | `17d93a499a2e9751b971a60a1c081ad2` |
| TLSH | `T12F0612527B869971C01ADF70C465E3BD7324FF458A518B2736C87E0F7E9A292ED26380` |
| SSDEEP | `98304:oJjGK5fX1dtTlLBeQ9tYAktWjy4/BN5t4qpC:oJjGkfzVztYAktHezt4KC` |
| ICON-DHASH | `30f0f0f0f069b254` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_6f295f2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f295f2aa87bdc8c3d44d7c71d642bfa3bf647293e0f72295b2a09100ad686df"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-23 00:09:49"
  condition:
    hash.sha256(0, filesize) == "6f295f2aa87bdc8c3d44d7c71d642bfa3bf647293e0f72295b2a09100ad686df"
}
```

### Sample 21: `5693516606e45930`

| Field | Value |
|---|---|
| SHA-256 | `5693516606e4593095480afa2d0d2f8f7740a73f2789bf0d549fece3dada9d1c` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.W64.Agent.ECKA.tr.25116.31718` |
| File type | `exe` |
| First seen | `2026-08-23 00:07:00` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5801382ae3ce2e897245e9698f641ca8` |
| SHA-1 | `554251df76b0f387e8c288ba01433be7d3ccc896` |
| SHA-256 | `5693516606e4593095480afa2d0d2f8f7740a73f2789bf0d549fece3dada9d1c` |
| SHA3-384 | `eaf7aecb93cb0f315958d3d1143308ddeb1ae286363946f307f9f1f38af0ab8d20ed828e66f60ecaa4a9b1620fe2e31d` |
| IMPHASH | `7c75a83e117d2bdfb2814c53e840c172` |
| TLSH | `T1FBF5231DD7A844FDE0B7A574CA924C12E73ABC4A4771E78B07D4B8521F732909A3AB12` |
| SSDEEP | `98304:cvOityjtyH3BfOv62zgotKjYofINcMN0vfgpreyP:zit+tSfG62zgbEVNc5faSC` |
| ICON-DHASH | `f0cc968a8a86c4c8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_56935166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5693516606e4593095480afa2d0d2f8f7740a73f2789bf0d549fece3dada9d1c"
    family = "unknown"
    file_name = "SecuriteInfo.com.W64.Agent.ECKA.tr.25116.31718"
    file_type = "exe"
    first_seen = "2026-08-23 00:07:00"
  condition:
    hash.sha256(0, filesize) == "5693516606e4593095480afa2d0d2f8f7740a73f2789bf0d549fece3dada9d1c"
}
```

### Sample 22: `8df8bd5daa09bae7`

| Field | Value |
|---|---|
| SHA-256 | `8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b` |
| Family label | `unknown` |
| File name | `8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b.exe` |
| File type | `exe` |
| First seen | `2026-08-23 00:06:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59e58138f6fb0bef9bfa107089e84aca` |
| SHA-1 | `176358a53994871e5c060962efd6d924ec874c0b` |
| SHA-256 | `8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b` |
| SHA3-384 | `4f285cb5926e49fed603ed2415cc8aaa29da793d01f5245b8fee67d1fa5b6d88f5d1c799838f1a19113ec8eb88741007` |
| IMPHASH | `b8048b8957358587b4fda264349e8f60` |
| TLSH | `T1EBD5239ABDF31AB5C433C7F69D83E06EB319BB904A614D473ACC5A118D53948AC39339` |
| SSDEEP | `49152:C03+hj44mvsFI5Z5jBjpVZmJbiBD2TMTUnGnk/UHNw5IGyBnhQCxjW74y1jb:T044T8vBjpVU2Np7IiNUIlNxSsQj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_8df8bd5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b"
    family = "unknown"
    file_name = "8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:06:38"
  condition:
    hash.sha256(0, filesize) == "8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b"
}
```

### Sample 23: `6ded9017cd432164`

| Field | Value |
|---|---|
| SHA-256 | `6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135` |
| Family label | `Vidar` |
| File name | `6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135.bin` |
| File type | `exe` |
| First seen | `2026-08-22 23:57:01` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02746f7f86387506be7c67fe1725b4f4` |
| SHA-1 | `f4c62294aacf410dcb308a16868d3cdd6343f44b` |
| SHA-256 | `6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135` |
| SHA3-384 | `dafeff15b4a9f22319652be26dd72498d805d822deec0c7e340cc9fca866e5461a6e61387f9c43bdefc8d4c72c79388e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T116565B17AE9148FAC0A9D735C4B74616BA70B84D4B3233D31E52BE786E317C16E35BA0` |
| SSDEEP | `49152:snYqrY0uVVSnnd5N6CWDo9IDCwRcGvpFOAwa9ZaLJSzAsgh:s9l7cRc4QczA7` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_023_6ded9017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135"
    family = "Vidar"
    file_name = "6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135.bin"
    file_type = "exe"
    first_seen = "2026-08-22 23:57:01"
  condition:
    hash.sha256(0, filesize) == "6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135"
}
```

### Sample 24: `7f97963c60595faf`

| Field | Value |
|---|---|
| SHA-256 | `7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0` |
| Family label | `unknown` |
| File name | `7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0.exe` |
| File type | `exe` |
| First seen | `2026-08-22 23:56:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84034335e9d6e730c343e48977f01235` |
| SHA-1 | `9cedcf9dc4a683f265367294c2128d9ff3d95e76` |
| SHA-256 | `7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0` |
| SHA3-384 | `abd04878a56540a89c387309a51e5d118d1b0dddb18e001aa82fce7ed85884e53e92868f669a935e23739c6e463ca545` |
| IMPHASH | `24e8765fd838d429e6f908cdeb96c2d6` |
| TLSH | `T1FED522D6FEF346B4F432C3778293201EB1297B58076A4D473ADD6F002E529682D3967A` |
| SSDEEP | `49152:1DyIDa0kqwhznyt2U57aLoPCXH3LvjDZyDKQ9gk6dAwBFALzE1emtYhV3dx0weg:BmPqwhzyzjaXH3Lvn4GQV6dAHLaetPx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_7f97963c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0"
    family = "unknown"
    file_name = "7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0.exe"
    file_type = "exe"
    first_seen = "2026-08-22 23:56:49"
  condition:
    hash.sha256(0, filesize) == "7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0"
}
```

### Sample 25: `65c7e0f7c75a121f`

| Field | Value |
|---|---|
| SHA-256 | `65c7e0f7c75a121f75e4232cfd8d2f1245f7efb70a903e7aaf4c556de5d34e7f` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 23:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ed0f8fb9f3e95c10d5172f79869b8df` |
| SHA-256 | `65c7e0f7c75a121f75e4232cfd8d2f1245f7efb70a903e7aaf4c556de5d34e7f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_65c7e0f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65c7e0f7c75a121f75e4232cfd8d2f1245f7efb70a903e7aaf4c556de5d34e7f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 23:52:11"
  condition:
    hash.sha256(0, filesize) == "65c7e0f7c75a121f75e4232cfd8d2f1245f7efb70a903e7aaf4c556de5d34e7f"
}
```

### Sample 26: `ece0710b08cd1364`

| Field | Value |
|---|---|
| SHA-256 | `ece0710b08cd1364f8b700bb3a1535a9ad9f132ce4c0ddc5c428a2a26207013d` |
| Family label | `Mirai` |
| File name | `daredevil.powerpc` |
| File type | `elf` |
| First seen | `2026-08-22 23:28:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c41ab9b33e5a654fca1bf99cb661c43b` |
| SHA-1 | `38495bfb53fce71282df6ac6fb0b99db9762daff` |
| SHA-256 | `ece0710b08cd1364f8b700bb3a1535a9ad9f132ce4c0ddc5c428a2a26207013d` |
| SHA3-384 | `0141aac20d709538c65278eb18d3edf9971287fa26607be8364e8acc847433a539092b10226666195161028f1fa7725c` |
| TLSH | `T1E2E31905730D0547D2A72EF03A3F6BE197AFDAD131E4E640295EA78E8172D321986ECD` |
| SSDEEP | `1536:uRAdBz2FmaGnO1I+5a516MEnUTxfPJaqAOqzydPyWPDxGqGvAYremCWEZ0HhORTE:rz2ZGnO1VsNEnUTxEqgGymDNY2NE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_ece0710b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece0710b08cd1364f8b700bb3a1535a9ad9f132ce4c0ddc5c428a2a26207013d"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-22 23:28:16"
  condition:
    hash.sha256(0, filesize) == "ece0710b08cd1364f8b700bb3a1535a9ad9f132ce4c0ddc5c428a2a26207013d"
}
```

### Sample 27: `697a9e37941c73e9`

| Field | Value |
|---|---|
| SHA-256 | `697a9e37941c73e9116a3532ad6dd5627b7c0f4580ecd30960346a72f9d0f646` |
| Family label | `Mirai` |
| File name | `daredevil.powerpc` |
| File type | `elf` |
| First seen | `2026-08-22 23:27:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dd42b85971197c30f57c09dd7814505` |
| SHA-1 | `9e8a07de4e7af2d525dde0ba6c7e4344cbcd05ca` |
| SHA-256 | `697a9e37941c73e9116a3532ad6dd5627b7c0f4580ecd30960346a72f9d0f646` |
| SHA3-384 | `7bd963d10169be8e9d9eedb5a24a31ae71c3b16bf13f33a5e1abeec43215ba073f8d414452864b6ebed60628b902900b` |
| TLSH | `T1F23302B6D811B0E9FE7827E94C56D8CCFE861F6D20F0C862E985BE831636414B5587C4` |
| SSDEEP | `1536:vGiRD5go2aUE59JCE1gLWDtjpozJ34u+qgw09U:vmoH59JCE1gL2CzJ4u+qgw9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_697a9e37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "697a9e37941c73e9116a3532ad6dd5627b7c0f4580ecd30960346a72f9d0f646"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-22 23:27:18"
  condition:
    hash.sha256(0, filesize) == "697a9e37941c73e9116a3532ad6dd5627b7c0f4580ecd30960346a72f9d0f646"
}
```

### Sample 28: `9c2e3246eb0507cd`

| Field | Value |
|---|---|
| SHA-256 | `9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350` |
| Family label | `unknown` |
| File name | `9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350.bin` |
| File type | `exe` |
| First seen | `2026-08-22 23:26:22` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `964f6e5512cdd7ebd3a68e51f1620f03` |
| SHA-1 | `7b376ecf50e1925e0cbdf1ab74e59fe37c8e8759` |
| SHA-256 | `9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350` |
| SHA3-384 | `3a21e1fc2834785b1ec74c36bb07d6305dc66613cdc61ec9d5e8c10f99c35f4fae44edf9a8318240933a8403fb036648` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T16E069D03BE8545A5E8865B3648B68252B731FC4CD73277E32E90B2782F757C19E7AB04` |
| SSDEEP | `98304:bCkd3jgJESXdJ+EZqxBgY5dk3mekco9+uH1SWediKyR81Hx0qsbizs5A2/3EHrjl:ekd3jgJESXdJb8Ha` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_9c2e3246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350"
    family = "unknown"
    file_name = "9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350.bin"
    file_type = "exe"
    first_seen = "2026-08-22 23:26:22"
  condition:
    hash.sha256(0, filesize) == "9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350"
}
```

### Sample 29: `11f3beea1d73e129`

| Field | Value |
|---|---|
| SHA-256 | `11f3beea1d73e12968f999281374286c16fa7649407ed5cbc068195142a631f4` |
| Family label | `SnappyClient` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-22 23:15:55` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, SnappyClient, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84e38378eaee827ee86bd112d3a7bc49` |
| SHA-1 | `2ced32f96f17ebe0e16b029eb5ae7206a4a87a47` |
| SHA-256 | `11f3beea1d73e12968f999281374286c16fa7649407ed5cbc068195142a631f4` |
| SHA3-384 | `ac623c2040296ce032f900aba31db898ca90ed3d8790b3b2c8e78214760db04c0e2c1ed9c6a7f028172ab6d97a3edefe` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T18656339362930072F8A15F32A4908591AE5778BD20F170457C76E60F3A79BD7AF733A2` |
| SSDEEP | `98304:bDs2vy9wfmBkY6MG73lE66nnAcCOSx/kH6DSZoeqOPu2DYenL1dNIYqAl+Z4d:bHv6bKpcoROPtvL1zc2d` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_029_11f3beea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f3beea1d73e12968f999281374286c16fa7649407ed5cbc068195142a631f4"
    family = "SnappyClient"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 23:15:55"
  condition:
    hash.sha256(0, filesize) == "11f3beea1d73e12968f999281374286c16fa7649407ed5cbc068195142a631f4"
}
```

### Sample 30: `98bd4791d07de85c`

| Field | Value |
|---|---|
| SHA-256 | `98bd4791d07de85c51338cd82bd68855631a1e3c17a9384195b2caddce5d4e51` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 22:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5451d59602447fc4e9f26de777d4cb7` |
| SHA-256 | `98bd4791d07de85c51338cd82bd68855631a1e3c17a9384195b2caddce5d4e51` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_98bd4791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98bd4791d07de85c51338cd82bd68855631a1e3c17a9384195b2caddce5d4e51"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 22:52:10"
  condition:
    hash.sha256(0, filesize) == "98bd4791d07de85c51338cd82bd68855631a1e3c17a9384195b2caddce5d4e51"
}
```

### Sample 31: `7c1e63840584f07b`

| Field | Value |
|---|---|
| SHA-256 | `7c1e63840584f07bd1e1436a02c7b65375fbf6c80ab289aaf2a5d16d63804737` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-22 22:30:54` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6df2a62bd8dbcfa4561a5eec4bf3f643` |
| SHA-1 | `d973120cb5d1f8e47bcd4b3a10a278e4494ab028` |
| SHA-256 | `7c1e63840584f07bd1e1436a02c7b65375fbf6c80ab289aaf2a5d16d63804737` |
| SHA3-384 | `1a9ec0c336327ae543b93f4d8987903476a92d59343c3544757e5b9247a875091586c145dd01a2b9afa3f431b499e27c` |
| IMPHASH | `d9adf3d4668feb6438044eaa36a0f13d` |
| TLSH | `T1B63622A27F05D801D4960E74CA76C3E9A720FD08DE85935B31EAAF2FFDE62D25D02185` |
| SSDEEP | `98304:Kk3eRUmxjssDukD2jhS+UhaMNaO1dR0W6pq0Ny:KHxxjssuHhf/caO1Kg0Ny` |
| ICON-DHASH | `20e0d8d4ccd8f838` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_7c1e6384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c1e63840584f07bd1e1436a02c7b65375fbf6c80ab289aaf2a5d16d63804737"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 22:30:54"
  condition:
    hash.sha256(0, filesize) == "7c1e63840584f07bd1e1436a02c7b65375fbf6c80ab289aaf2a5d16d63804737"
}
```

### Sample 32: `62ee3a4c45d77d8f`

| Field | Value |
|---|---|
| SHA-256 | `62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0` |
| Family label | `unknown` |
| File name | `62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0.exe` |
| File type | `exe` |
| First seen | `2026-08-22 22:26:33` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5c21fa655f0bc9ffd03f3a683f57f6c` |
| SHA-1 | `8d0bf1f65b772584503e21f1f441c724c0d31705` |
| SHA-256 | `62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0` |
| SHA3-384 | `25dec9d533994f5b7b300616cd4ece15cac233c240527b4d63a9e04e52b057c306e0c7dbe6d39b278136e33ad51c2438` |
| IMPHASH | `cc678ea372003a91fefb68ce6b422039` |
| TLSH | `T131D5238A7DF71970D836CBB18F82F46D716E7B8057B25DA7358D29408E029689C3B339` |
| SSDEEP | `49152:RZlAwRoFWR/Kj2Sg60NE+40HaQ9yui/Qvr1KKkXQVA/qdsrpJ9N0E:2wRoEujgTEd5QTEKkXQd2N0E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_62ee3a4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0"
    family = "unknown"
    file_name = "62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0.exe"
    file_type = "exe"
    first_seen = "2026-08-22 22:26:33"
  condition:
    hash.sha256(0, filesize) == "62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0"
}
```

### Sample 33: `633980cfc11ed6ed`

| Field | Value |
|---|---|
| SHA-256 | `633980cfc11ed6eddfb30571ecf45392073707f382cc24967fd91472498922aa` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 21:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `056ccc5feaa9b325aeb423f239880151` |
| SHA-256 | `633980cfc11ed6eddfb30571ecf45392073707f382cc24967fd91472498922aa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_633980cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "633980cfc11ed6eddfb30571ecf45392073707f382cc24967fd91472498922aa"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 21:52:09"
  condition:
    hash.sha256(0, filesize) == "633980cfc11ed6eddfb30571ecf45392073707f382cc24967fd91472498922aa"
}
```

### Sample 34: `4cc6621aa8311d15`

| Field | Value |
|---|---|
| SHA-256 | `4cc6621aa8311d15b172c95edeb7da76a7d3ab35f6ef0a74f3a0a5b85384865c` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-22 21:50:30` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51d911a61d677a12eb54cb5dc9740331` |
| SHA-1 | `12530308fe66def597ad667b0d25f63a3e1e5ef6` |
| SHA-256 | `4cc6621aa8311d15b172c95edeb7da76a7d3ab35f6ef0a74f3a0a5b85384865c` |
| SHA3-384 | `7d7eb31e4354a7c9dfb7a76681f081dbc57295a7a9efcdb5bbc56633bc44ecc1713fc9942c530d8e8d1caab4e982b818` |
| TLSH | `T1853190DA05518B311403CA5E73F2714CA68EA3FB2D4FD7E0C91D0EAA428978CF261B49` |
| SSDEEP | `24:u2Lwnm4VGs9pSeWo171AocMBiNKXEoOmCWGhdEN:km4VGESenTBiNCEoeWJN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_4cc6621a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc6621aa8311d15b172c95edeb7da76a7d3ab35f6ef0a74f3a0a5b85384865c"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-22 21:50:30"
  condition:
    hash.sha256(0, filesize) == "4cc6621aa8311d15b172c95edeb7da76a7d3ab35f6ef0a74f3a0a5b85384865c"
}
```

### Sample 35: `1d7c06f35efeffe0`

| Field | Value |
|---|---|
| SHA-256 | `1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45` |
| Family label | `Vidar` |
| File name | `1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45.bin` |
| File type | `exe` |
| First seen | `2026-08-22 21:48:02` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45c12638098dfeef4df009e59765ea6c` |
| SHA-1 | `5184fd1dcf6d5d4a36549476af6bb2cec5946ce9` |
| SHA-256 | `1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45` |
| SHA3-384 | `2a4daa6abae36cf0ff3baf226ae4138caffbe47907b80a09197c2192b199dccf8327932bb4d53d255e2250d814fcc530` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T138666B03BDA545A9D4AA9738C9B78652BB75BC48873133D72E10B6343F32BD0AE75780` |
| SSDEEP | `49152:PrMYuVRfVdaYrtQBKFvzeJvEgCixe6p6gqIxBJaR5HeqNSoPEmH99GLryrTmwuu:1KTTi5OIU5HeqNSoPnH9pHHuu` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_035_1d7c06f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45"
    family = "Vidar"
    file_name = "1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45.bin"
    file_type = "exe"
    first_seen = "2026-08-22 21:48:02"
  condition:
    hash.sha256(0, filesize) == "1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45"
}
```

### Sample 36: `a3cd0bf6fdcb213d`

| Field | Value |
|---|---|
| SHA-256 | `a3cd0bf6fdcb213d1bfef9252a7b8dca39841a31cd104cd5c1b5a4cc8fca7484` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-22 21:28:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62ee742192a95cc94bbabeabbf9bad67` |
| SHA-1 | `eca5e260ea8a7a4827d85ef6c4893055fe3495d3` |
| SHA-256 | `a3cd0bf6fdcb213d1bfef9252a7b8dca39841a31cd104cd5c1b5a4cc8fca7484` |
| SHA3-384 | `fe0aa553a5a72812286985bdd74c36e8264cc37a33c902397e3eff78d986c98fc65b35689234d846b50c039968d3e74d` |
| TLSH | `T1ADC28D966A867C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:L8vCB+25j6es8RD9FYpMSUpi+20qUpi+20YQX:L8l25JFd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_a3cd0bf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3cd0bf6fdcb213d1bfef9252a7b8dca39841a31cd104cd5c1b5a4cc8fca7484"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-22 21:28:19"
  condition:
    hash.sha256(0, filesize) == "a3cd0bf6fdcb213d1bfef9252a7b8dca39841a31cd104cd5c1b5a4cc8fca7484"
}
```

### Sample 37: `2e2d2824dfb7ed20`

| Field | Value |
|---|---|
| SHA-256 | `2e2d2824dfb7ed201e1e8e87ee43579738bbd53392cab6fcf603b8bad4e752d9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-22 21:28:13` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `154576d32027d092a5414e1c57327d1a` |
| SHA-1 | `0bb1154898a0041fad9d6255da7822c0006b4e9b` |
| SHA-256 | `2e2d2824dfb7ed201e1e8e87ee43579738bbd53392cab6fcf603b8bad4e752d9` |
| SHA3-384 | `a0e1f1943b19a8b6d6e7f2d541c18ac354f7697ad94df8de9d1f906f4610f06ab80c044c1f312108080345f41f5cf1ce` |
| IMPHASH | `4cfe725a19934c4ba4009472955c9c5b` |
| TLSH | `T1630601A23F85D930D0478B70C965E7FD7329FF49C9618B4731D56E0BBDAA6C64E22280` |
| SSDEEP | `98304:GNcXNIO4HnGRWR+MdgdSNHWaPIAcqq2KPB:GcXSRGRWR+MqdmtIAFLAB` |
| ICON-DHASH | `9271e8f0f0f0f000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_2e2d2824
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e2d2824dfb7ed201e1e8e87ee43579738bbd53392cab6fcf603b8bad4e752d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 21:28:13"
  condition:
    hash.sha256(0, filesize) == "2e2d2824dfb7ed201e1e8e87ee43579738bbd53392cab6fcf603b8bad4e752d9"
}
```

### Sample 38: `1175a66971e9c4b2`

| Field | Value |
|---|---|
| SHA-256 | `1175a66971e9c4b23053162f29788b8f2bfc585a442474d75e72edd2c962b465` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-08-22 21:13:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b343bdd417f0677d44df68f7dbeb9a93` |
| SHA-1 | `97c70bce3ee007abb112bea8bb385e6447b931b7` |
| SHA-256 | `1175a66971e9c4b23053162f29788b8f2bfc585a442474d75e72edd2c962b465` |
| SHA3-384 | `820afec1c00b6b19ed0a5dfb7bd224126e9d59d085d0ab51203022f6bf404c5906e891e1e3fc9b9da80819d73384c255` |
| TLSH | `T116259F8CE96FBDC6F3CAF3789B0D9AA1A52B7170E25361A33547534E81D61D4CAF0920` |
| SSDEEP | `12288:/O9CNDAgs7TuisazwZvpXoM+9WuJPK/6+WNbIuUkBuuZ8Xk04a9xw57PKEU:m9ClSCdacQMl8S/uZxUoH0hj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_1175a669
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1175a66971e9c4b23053162f29788b8f2bfc585a442474d75e72edd2c962b465"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-08-22 21:13:18"
  condition:
    hash.sha256(0, filesize) == "1175a66971e9c4b23053162f29788b8f2bfc585a442474d75e72edd2c962b465"
}
```

### Sample 39: `277b3e1711cb5b02`

| Field | Value |
|---|---|
| SHA-256 | `277b3e1711cb5b0287933b2d83f65129bf7168dc188a90cade77ff62dc08eb40` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-22 21:01:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5e040cfdac02dd10b1472c0bdb338f5` |
| SHA-1 | `67dbc14cf2dc76755a0e550c2e2fb8a3b52bb3a3` |
| SHA-256 | `277b3e1711cb5b0287933b2d83f65129bf7168dc188a90cade77ff62dc08eb40` |
| SHA3-384 | `2de179b44994f809781c721ab7a1c0bcbdeb53200a5f6350f2f9b0f613795266ac02458df2281aa65b55c5e430501621` |
| TLSH | `T160235C6516867C24AE99C4361C7E2F0CB9AD43E6324452EE7FCB3CF28C4A69DD109B1D` |
| SSDEEP | `768:1+g9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:1+dcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_277b3e17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "277b3e1711cb5b0287933b2d83f65129bf7168dc188a90cade77ff62dc08eb40"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-22 21:01:30"
  condition:
    hash.sha256(0, filesize) == "277b3e1711cb5b0287933b2d83f65129bf7168dc188a90cade77ff62dc08eb40"
}
```

### Sample 40: `1d8db801829975be`

| Field | Value |
|---|---|
| SHA-256 | `1d8db801829975be3241657b4b270f9006dff5a1ebfa5fe2227a17febdd292b5` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 20:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `510fe140f0ac21eaa6c73f370a5d7524` |
| SHA-256 | `1d8db801829975be3241657b4b270f9006dff5a1ebfa5fe2227a17febdd292b5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_1d8db801
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8db801829975be3241657b4b270f9006dff5a1ebfa5fe2227a17febdd292b5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 20:52:11"
  condition:
    hash.sha256(0, filesize) == "1d8db801829975be3241657b4b270f9006dff5a1ebfa5fe2227a17febdd292b5"
}
```

### Sample 41: `39291bc66505cbf6`

| Field | Value |
|---|---|
| SHA-256 | `39291bc66505cbf67c93116709b2e84ef3b5559d01ce461f37214e05bac09918` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-22 20:50:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6e9de70020b58efd9898608fc51015f` |
| SHA-1 | `bcbeb62b711c33e6ca2c5c48dfc66648d541a958` |
| SHA-256 | `39291bc66505cbf67c93116709b2e84ef3b5559d01ce461f37214e05bac09918` |
| SHA3-384 | `63f23d2848b960ec57bd38049993f86e73fbd5f116022511de0ebc138433b0855e94d255cc768d7af0375da43672c06a` |
| TLSH | `T17E236C651A857C24AA98C4371D7E1F0CBDAD43E6324492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:RXRWNGxVk9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:rlxHcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_39291bc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39291bc66505cbf67c93116709b2e84ef3b5559d01ce461f37214e05bac09918"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-22 20:50:30"
  condition:
    hash.sha256(0, filesize) == "39291bc66505cbf67c93116709b2e84ef3b5559d01ce461f37214e05bac09918"
}
```

### Sample 42: `a16a75072235626b`

| Field | Value |
|---|---|
| SHA-256 | `a16a75072235626bbae7449183964366f32b3e33bf8514aa83c9cedc4f5cafbe` |
| Family label | `Mirai` |
| File name | `daredevil.armv6l` |
| File type | `elf` |
| First seen | `2026-08-22 20:27:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0028a83a1f46b3d828e77df6ff3aa4c` |
| SHA-1 | `2ea95f2612a1e9763dc64dc6e258f8218d5e3a29` |
| SHA-256 | `a16a75072235626bbae7449183964366f32b3e33bf8514aa83c9cedc4f5cafbe` |
| SHA3-384 | `4c63b8ea32543868c5d51acad2db60a7a8275baa994ab73122118499e6f0601fbe7df6e8ab946b641d0d65229945e7ac` |
| TLSH | `T148E30A96F8818B11D5C211BAFE1E124E37131BB8E3DE72039D146B69778BC7B0A3B915` |
| SSDEEP | `3072:/+D5eBAHtCs5UtAhz3XLeYILbQaIScq2GJZIFge:/GeC95eo3XKNL0aCG7IFge` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_a16a7507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a16a75072235626bbae7449183964366f32b3e33bf8514aa83c9cedc4f5cafbe"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-22 20:27:28"
  condition:
    hash.sha256(0, filesize) == "a16a75072235626bbae7449183964366f32b3e33bf8514aa83c9cedc4f5cafbe"
}
```

### Sample 43: `966ddd385a30176a`

| Field | Value |
|---|---|
| SHA-256 | `966ddd385a30176ae00f0b7a33d0a6d7b9c9527c613e6effe963573b3bb0b742` |
| Family label | `Mirai` |
| File name | `daredevil.armv6l` |
| File type | `elf` |
| First seen | `2026-08-22 20:26:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58de241c9af85b5adef91c416afad99e` |
| SHA-1 | `6b9cb1aa45fff0b609d54e371566115fbe24b377` |
| SHA-256 | `966ddd385a30176ae00f0b7a33d0a6d7b9c9527c613e6effe963573b3bb0b742` |
| SHA3-384 | `7c1afa0bc7ca7f90cdfb8cf9167faca1200bc085763632aa9455a14be9825cd066e630c8c456111601403e81b3118924` |
| TLSH | `T14143F142C11F8C12DD755C36DE4E8408AF729B76A19DF2F5830AAB7C10D22E5EEE9C85` |
| SSDEEP | `768:/KSPBv5i6mw+8pU7hIy/T33DSYoAcBThNeJ1kATj3u0+K4c2bq1PrFWuX9q3UELu:TPBM6YKuTHDSSYhELkoj3u0G/GZrFoLu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_966ddd38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "966ddd385a30176ae00f0b7a33d0a6d7b9c9527c613e6effe963573b3bb0b742"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-22 20:26:45"
  condition:
    hash.sha256(0, filesize) == "966ddd385a30176ae00f0b7a33d0a6d7b9c9527c613e6effe963573b3bb0b742"
}
```

### Sample 44: `27619f3ff4786a56`

| Field | Value |
|---|---|
| SHA-256 | `27619f3ff4786a56cd58697dbd6f7d58ee842aa13990afb0dfebb5ef376d359f` |
| Family label | `Mirai` |
| File name | `db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:22:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b3bbb66e393719379732870d8c5e394` |
| SHA-1 | `22810e25c9fd5472061d8fca0887dcd5373c7015` |
| SHA-256 | `27619f3ff4786a56cd58697dbd6f7d58ee842aa13990afb0dfebb5ef376d359f` |
| SHA3-384 | `9402a123a1eec9742a408b9a8e556001eb67e4ceb0172115c098528390587872afde14cf71dae704218f93fdb281ef99` |
| TLSH | `T112B3F799FC414B01D9D636FAFE0F128933534BB8E3F9B1029E145B2A27CA95B0B77905` |
| TELFHASH | `t1a3e07d16e5341a0927d6e450c07ff8550fbcb08c3a2314b1c44c86c60a41989391e727` |
| SSDEEP | `3072:QkBwJYHSSxahmhsO3JyaEK29nnmbTdniy3:r6RSxGmh75yaEK29nmJ3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_27619f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27619f3ff4786a56cd58697dbd6f7d58ee842aa13990afb0dfebb5ef376d359f"
    family = "Mirai"
    file_name = "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:30"
  condition:
    hash.sha256(0, filesize) == "27619f3ff4786a56cd58697dbd6f7d58ee842aa13990afb0dfebb5ef376d359f"
}
```

### Sample 45: `868b7eb4ff5b6a29`

| Field | Value |
|---|---|
| SHA-256 | `868b7eb4ff5b6a298035439f718dd871dc747b10dd60e92de10b1ec8bae602b0` |
| Family label | `Mirai` |
| File name | `1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:22:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e0abaab9faf59720f2decdaf5256983` |
| SHA-1 | `3a08fea5bda7350af45a473c1322232e55c547c0` |
| SHA-256 | `868b7eb4ff5b6a298035439f718dd871dc747b10dd60e92de10b1ec8bae602b0` |
| SHA3-384 | `8e725dec5a45b5dc0507c052bd6de60857620b43e3555c2071f5e8d8460764942000c006f245095dcc1b1c76abaf5d61` |
| TLSH | `T19304B81E6E228F7DF27887744BB34E25975D33D627E0D684E2ACC5105E2029E581FFA8` |
| TELFHASH | `t1604171180e7817e4a3356d8e059dff76969330db3f166d678e11e86aa769d834e10c0c` |
| SSDEEP | `1536:Ou9bf5AGaW5Nrcq4JKEFUONWywuYs79qE4+Rer9QNFnXT0QTiRtS1wHXQLFg:zbRk25rONWywuZ79L4+YQNJoztSqHqe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_868b7eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "868b7eb4ff5b6a298035439f718dd871dc747b10dd60e92de10b1ec8bae602b0"
    family = "Mirai"
    file_name = "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:28"
  condition:
    hash.sha256(0, filesize) == "868b7eb4ff5b6a298035439f718dd871dc747b10dd60e92de10b1ec8bae602b0"
}
```

### Sample 46: `96ca231cc6d653b8`

| Field | Value |
|---|---|
| SHA-256 | `96ca231cc6d653b82f60d7403c09898b404d99e9178150d935c74653f44deeef` |
| Family label | `Mirai` |
| File name | `d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:22:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a71353a80d2ceae22fb54e38df3f5464` |
| SHA-1 | `0f3af5f5cf46e01ee44ea8ce7c4adc3bc04e9dd9` |
| SHA-256 | `96ca231cc6d653b82f60d7403c09898b404d99e9178150d935c74653f44deeef` |
| SHA3-384 | `e4f40245827c89cb147f66721ab7c1556ef5fea700f6a4874a95580dd0ad35d3837351384d92ffb6792d18520640cf05` |
| TLSH | `T148633D58F343E4F0DA8205F020AFFB3B6931D9D11260DDABEBF4BAE56E616426415E1C` |
| TELFHASH | `t1bf31d5ba1dba1cd8fbd19800c24a1fe24d5ae73f15607af34721a41923abf41503bc35` |
| SSDEEP | `1536:xwwNpJMdU5rT4obxrb4Vrt0uILQ0Jtl35Um31gOGgZeJ+r:+wNpJMm5rT4o54f76bKOBgW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_96ca231c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96ca231cc6d653b82f60d7403c09898b404d99e9178150d935c74653f44deeef"
    family = "Mirai"
    file_name = "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:26"
  condition:
    hash.sha256(0, filesize) == "96ca231cc6d653b82f60d7403c09898b404d99e9178150d935c74653f44deeef"
}
```

### Sample 47: `b3a7a8115e041717`

| Field | Value |
|---|---|
| SHA-256 | `b3a7a8115e04171760623daf10d46891ca3e68b7a0627ff2ac2d23d42825537c` |
| Family label | `Mirai` |
| File name | `d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:22:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcb3924e4ed96fa0a5f5b5d8ed994aef` |
| SHA-1 | `6c3e0ea6e553ec0e9d30a3141e7d04300202b48b` |
| SHA-256 | `b3a7a8115e04171760623daf10d46891ca3e68b7a0627ff2ac2d23d42825537c` |
| SHA3-384 | `0ed5971ac7ce84b3b41a4d7f1b741b3c36c91f6090b54128ba63111b6cfec06b37dc2a5d08e4f0272646e3a26890bc9f` |
| TLSH | `T111E33A06B8C054FEC49AC2744ADEB536DD32B4AD5138B66F27D06E323E8DE217E5CA50` |
| TELFHASH | `t10b5189b02d552d64a2e3a779734eeae5bc310d2128e271e8dd27a9e2ce137c00c724b5` |
| SSDEEP | `1536:1bsygPAqTE4L9R/3ob+Q7jqTGMuO6eRI9ATRC+C5HTdFj8MBjSzFmL3Mog:v4pRfobLjqi0I9AnC5HTb8M9SJEMog` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_b3a7a811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3a7a8115e04171760623daf10d46891ca3e68b7a0627ff2ac2d23d42825537c"
    family = "Mirai"
    file_name = "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:22"
  condition:
    hash.sha256(0, filesize) == "b3a7a8115e04171760623daf10d46891ca3e68b7a0627ff2ac2d23d42825537c"
}
```

### Sample 48: `e89c58757fe39524`

| Field | Value |
|---|---|
| SHA-256 | `e89c58757fe395241043e948f135ba8056d5151c654cef1b64715d9993b67311` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-22 20:22:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d654f1a9db4cff7a4e94145d861abef` |
| SHA-1 | `0cc68fb7b11aa4a5d16173d786befe4218c808e7` |
| SHA-256 | `e89c58757fe395241043e948f135ba8056d5151c654cef1b64715d9993b67311` |
| SHA3-384 | `de7304ddce119aee6976acee52747ada3d31840c1e56defd5c28836b664766f7423e7f99bdc5241aeb3897786cd0512c` |
| TLSH | `T10DC28D966A867C44BEC94A3E4CBE2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:O28vCB+25j6es8R29FYpMSUpi+20qUpi+20YQX:O28l25Jgd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_e89c5875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e89c58757fe395241043e948f135ba8056d5151c654cef1b64715d9993b67311"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-22 20:22:21"
  condition:
    hash.sha256(0, filesize) == "e89c58757fe395241043e948f135ba8056d5151c654cef1b64715d9993b67311"
}
```

### Sample 49: `db90a56bc8875d23`

| Field | Value |
|---|---|
| SHA-256 | `db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586` |
| Family label | `Mirai` |
| File name | `db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:22:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `151d7770ea5762d136a8c0f2ba904539` |
| SHA-1 | `bf42ddfc398a8ab6009e72d8fdf5e797d9eb5852` |
| SHA-256 | `db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586` |
| SHA3-384 | `31c0c9a290963df09e3b3befbea218655279584af9585a079f4003bfa98ef46c50ac385ebab01dc69ff15d47d567e4c7` |
| TLSH | `T1CC23F117DA22E475C65C7D36D11A19CA622F9BB0C0FC77F93328F714368362999EE4A0` |
| SSDEEP | `768:DkvI3X4MzocSHz7zch+E7yTTiiOuCh6D8JiJr5GB0a0+6wHugmkwX29q3UELN:Dvo/fEOq1uCoD8JiLGS+bufLN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_db90a56b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586"
    family = "Mirai"
    file_name = "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:04"
  condition:
    hash.sha256(0, filesize) == "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586"
}
```

### Sample 50: `1b9d05b3a4bfdad2`

| Field | Value |
|---|---|
| SHA-256 | `1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5` |
| Family label | `Mirai` |
| File name | `1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:21:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb6ef919784ac5d0750d1bb303433a96` |
| SHA-1 | `e00e888cbc94288177e4377c144f2a6ded8da41d` |
| SHA-256 | `1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5` |
| SHA3-384 | `29df5d5da8e104583bf328e38fd5d970ff516c31e4c8ab3b3299be7b2c0a93a027f8944dd94f0d2b093cc2efba993ef9` |
| TLSH | `T15843025802C1C89DEB4CC9F887D24371BD2D1A375016B756AEE9A2D7EC52211F8736E1` |
| SSDEEP | `1536:lVo9ffE+KIF/wNe5gQspMGEpue6LPxWgk6FAyVJuh:fis+nF/wA6QshEp36LpVT2yVQh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_1b9d05b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5"
    family = "Mirai"
    file_name = "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:59"
  condition:
    hash.sha256(0, filesize) == "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5"
}
```

### Sample 51: `d5ddf0ea7ce42430`

| Field | Value |
|---|---|
| SHA-256 | `d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f` |
| Family label | `Mirai` |
| File name | `d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:21:54` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb0d704fb5a4cd48a0ef07021e943c81` |
| SHA-1 | `6765a96a029fde984357c2cf19c07833c622d283` |
| SHA-256 | `d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f` |
| SHA3-384 | `ddab15d947ce7aef1021c601b7673445dce94789bf4c37daa08bb2acee7370d4ee3f67afc6391f9acb9e80f4270b13b4` |
| TLSH | `T154F2D1A6E4ACD4D59A09CB7B08CBBB216959CE899741E6B3EEC41132EF97F403964007` |
| SSDEEP | `768:djb/XVMyunxAM6Vpopaa/VcnEEyYJxMFexGnbcuyD7UkWykkA7:dfXu3xAMYKp//TRedGnouy8kzkku` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_d5ddf0ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f"
    family = "Mirai"
    file_name = "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:54"
  condition:
    hash.sha256(0, filesize) == "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f"
}
```

### Sample 52: `749738fc07e21c74`

| Field | Value |
|---|---|
| SHA-256 | `749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4` |
| Family label | `Mirai` |
| File name | `749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:21:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e59ab1eabc3c7ded1071ba7da55e9d8` |
| SHA-1 | `3951956bdf4f0d596f7da46b051ece8345d257df` |
| SHA-256 | `749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4` |
| SHA3-384 | `dd482d1d58febaa821a9332caa54276f6a98781d9b38383883fbc958506ead2db16b065bbc976eb76ca368b88f1abe19` |
| TLSH | `T11AF32997F800DEBAF80BE33644570905B130B7E115926B377257787BED3E1A91827E86` |
| SSDEEP | `3072:oUb5vQTYg1xwfmI4OykOV70cVsjbioLSDQyDUuL:ohBHweIJyb70RLDyDTL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_749738fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4"
    family = "Mirai"
    file_name = "749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:50"
  condition:
    hash.sha256(0, filesize) == "749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4"
}
```

### Sample 53: `39ce8676c5aac257`

| Field | Value |
|---|---|
| SHA-256 | `39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db` |
| Family label | `Mirai` |
| File name | `39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:21:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cba8ae652d04c25777aa3a3e18793a13` |
| SHA-1 | `38deac9a9e7d1214af32c082fe7fdab07bd227ab` |
| SHA-256 | `39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db` |
| SHA3-384 | `eac9dba3b488dbcf65c4454596fddf397c932bab53eecf0022f3813996361368c2a7014b397bb6881ef4456ce52be6fa` |
| TLSH | `T11CC36B72CC256F68E126E974B078CFBA1B139481918B5FBE2863C3714097D8DF546BB8` |
| SSDEEP | `3072:BvHM6ZeHqL+8bBSbpwTm50JKZeWimD8GM:xHFnL9opwTSvLiC8GM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_39ce8676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db"
    family = "Mirai"
    file_name = "39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:44"
  condition:
    hash.sha256(0, filesize) == "39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db"
}
```

### Sample 54: `d4e955b6b22af7d6`

| Field | Value |
|---|---|
| SHA-256 | `d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4` |
| Family label | `Mirai` |
| File name | `d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:21:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9073c9de486f3b4f1346d0c6141cb227` |
| SHA-1 | `0f3a69b3017681cdb3c7011819147535d62e13e1` |
| SHA-256 | `d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4` |
| SHA3-384 | `85ea8defb77efa65ef3e279be6a4f6f31ec02a9602033ac60385a326188724e0bdbe503244036167d0135ee767f2938f` |
| TLSH | `T1BA4302E3267188BECC406934587993EAFC53A00332359F4F59C834FB9A8B9A45C5ABC5` |
| SSDEEP | `1536:WBpjJNBViS4EuM242Y/BZIZfsC/wF1kVuF:aDB2Elf2YEv/wDkVY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_d4e955b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4"
    family = "Mirai"
    file_name = "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:35"
  condition:
    hash.sha256(0, filesize) == "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4"
}
```

### Sample 55: `ce8e33a1d4a4b707`

| Field | Value |
|---|---|
| SHA-256 | `ce8e33a1d4a4b707f2b9e53cd061ef30ea5d719b81dee31f4248434cd033c1c0` |
| Family label | `Mirai` |
| File name | `daredevil.armv4l` |
| File type | `elf` |
| First seen | `2026-08-22 20:18:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d468da8f86a2b23d5aa21ebf68215f1` |
| SHA-1 | `d874207c00bc60a96f83e2f6acc1e10a13024699` |
| SHA-256 | `ce8e33a1d4a4b707f2b9e53cd061ef30ea5d719b81dee31f4248434cd033c1c0` |
| SHA3-384 | `e4cb8dc90ac53371fb34909bc3a7951775787a11e49d4cda67029c70c2cf0f53fcd84ed415e0b5e1845381fbea42a773` |
| TLSH | `T1F5E30989BC818B13C6E261B7FB5E428D3B2707E8D3EA71039D296B25375B4570E37542` |
| TELFHASH | `t1de316514cf6c0bcc6be44429d06d362479f430fd69133a06df66ab4f4a42cd2b02d827` |
| SSDEEP | `3072:ftyT2gJSjV7oDAg8epZ46XMWKT8e5a7GaJU:lyKgJSjponB3468WK4sqGaJU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_ce8e33a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce8e33a1d4a4b707f2b9e53cd061ef30ea5d719b81dee31f4248434cd033c1c0"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-22 20:18:26"
  condition:
    hash.sha256(0, filesize) == "ce8e33a1d4a4b707f2b9e53cd061ef30ea5d719b81dee31f4248434cd033c1c0"
}
```

### Sample 56: `381abe223780261b`

| Field | Value |
|---|---|
| SHA-256 | `381abe223780261b0c5316f43396b3bae7ce3f8030e287fc2558796a74762b34` |
| Family label | `Mirai` |
| File name | `daredevil.armv4l` |
| File type | `elf` |
| First seen | `2026-08-22 20:17:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46fcd5f3c3cacdf46b7ede549072f8ac` |
| SHA-1 | `f59c84a36e58ac21db6ed91a766b431ce67387b7` |
| SHA-256 | `381abe223780261b0c5316f43396b3bae7ce3f8030e287fc2558796a74762b34` |
| SHA3-384 | `d4f73450f153aaa08b0aede3eea4e5ca188a04912a2f0c8973ce1adac58287940ad92e77c05f26e5c959dd70a083f5e2` |
| TLSH | `T14333F17998A85DE1C434DE74DCFD89927897BF29D6F935B24228617CA06708F02F4BC4` |
| SSDEEP | `768:U58c+Dzc56EU86oLZuYLuLSz4GMMVp0nE3bkSGLEknn6mKl3pyUh7ZQzXGqPiR6F:U58cjAEUKNuk0nE3AJlkNQzXGWiLHz2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_381abe22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "381abe223780261b0c5316f43396b3bae7ce3f8030e287fc2558796a74762b34"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-22 20:17:48"
  condition:
    hash.sha256(0, filesize) == "381abe223780261b0c5316f43396b3bae7ce3f8030e287fc2558796a74762b34"
}
```

### Sample 57: `29efe86a4d5fd6a5`

| Field | Value |
|---|---|
| SHA-256 | `29efe86a4d5fd6a5d9b58ce5b766f98218900352d1ea70029b12afeb831888f9` |
| Family label | `Mirai` |
| File name | `9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:17:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c66a209b6afb28ed5a675200b147f298` |
| SHA-1 | `3b0d3a6b99f564e9ee8620a59547b3990ba7d2d8` |
| SHA-256 | `29efe86a4d5fd6a5d9b58ce5b766f98218900352d1ea70029b12afeb831888f9` |
| SHA3-384 | `5095ba404384cfad98e68c9791ef5c91a85ab09abfe2130b84120ba423b92c725f4ce09ec8d8e983dd11cbfb0fe7f80e` |
| TLSH | `T1F0D30B45FC818B13C6E261B7FB5E428D3B2A07E8D3EA71039D296B25379B4570E3B542` |
| SSDEEP | `1536:MIOMNy2mga0rsHVeM64cHyWBAcDd4VjkLTBtzYCtxW5mXYpnY6J3luhwywox1zRh:5U2mgadAMmSWB14GL1tzYoxTonL3s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_29efe86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29efe86a4d5fd6a5d9b58ce5b766f98218900352d1ea70029b12afeb831888f9"
    family = "Mirai"
    file_name = "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:17:22"
  condition:
    hash.sha256(0, filesize) == "29efe86a4d5fd6a5d9b58ce5b766f98218900352d1ea70029b12afeb831888f9"
}
```

### Sample 58: `ad58f0683617d904`

| Field | Value |
|---|---|
| SHA-256 | `ad58f0683617d9046fa5d5e499073acf813b647d6ae56a2a031449068d95d39c` |
| Family label | `Mirai` |
| File name | `8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:17:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3ee25fd5ac8cd975d6cad7b4ad033ea` |
| SHA-1 | `ab766304a56e4f0afd315121be216b7eaf3fba49` |
| SHA-256 | `ad58f0683617d9046fa5d5e499073acf813b647d6ae56a2a031449068d95d39c` |
| SHA3-384 | `e90e1193379dd06c878537313c28f895e3fc86756c652f80260a7ef288c0b178ec58e558f3636f41b1967cac4870516d` |
| TLSH | `T166E32A05730C0547D2A72EF03A3F6BE1A7EFDAD131E4E640255EA78A9171D322986ECD` |
| SSDEEP | `1536:IniqkzYkS7dD5x5hY0XBlxfxfckyKgsNe2IzJWrS5sNNPOjhGqwvA4/7mSWc5cmC:IKzYZ7ZHU8lxfxaK1+SS4Oj34O9Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_ad58f068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad58f0683617d9046fa5d5e499073acf813b647d6ae56a2a031449068d95d39c"
    family = "Mirai"
    file_name = "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:17:19"
  condition:
    hash.sha256(0, filesize) == "ad58f0683617d9046fa5d5e499073acf813b647d6ae56a2a031449068d95d39c"
}
```

### Sample 59: `9f02fa45ccce7347`

| Field | Value |
|---|---|
| SHA-256 | `9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303` |
| Family label | `Mirai` |
| File name | `9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:16:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfe28486776aed4e2929f11cce0acd74` |
| SHA-1 | `7a6674de46740bfc3dfb077b1be8a223c89a87df` |
| SHA-256 | `9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303` |
| SHA3-384 | `4ab7fa062b69033e028b4fae684a92cf896fd4dc67ff251101602f63eb263e23bd1fb135825a74905dfcc84ae6ee9516` |
| TLSH | `T18133F17279EECDD68B740BB6F890424D46FA2B79D6E921D008B983E0F79CC4651F1542` |
| SSDEEP | `768:oDJr7IOsro9MlX6GZwAuuAmdW4EZYHs3EA4GZSbMTOFAh2nOYlN9cXNtoli0ls3b:XOsroE5zXW4EbFlZS4z2n99i4li0ozZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_9f02fa45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303"
    family = "Mirai"
    file_name = "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:53"
  condition:
    hash.sha256(0, filesize) == "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303"
}
```

### Sample 60: `eb2f8dce5497c725`

| Field | Value |
|---|---|
| SHA-256 | `eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104` |
| Family label | `Mirai` |
| File name | `eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:16:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb2c5836b60df7a0534c340bdd4ad6cb` |
| SHA-1 | `c4a6b203336ae1ed2f79691121523b021c43b551` |
| SHA-256 | `eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104` |
| SHA3-384 | `2db282a7ec0e71300efebaf0bd53d02cd5c784f6aa1aa08ed623cf53f33a39cb7015f1abf1515fa58f0619d8a8f03fc1` |
| TLSH | `T17C254B88F4D0EB96C2C4AA76F71C655C33130735E2EB710699299B3137EB46B0F7AA11` |
| TELFHASH | `t179f0ac12728c69f4a2f2c2a0e3c4599d64b934f003a231aa47641d1ecae9fc325cf832` |
| SSDEEP | `12288:5p8G8R9/b474wFrLShrVEk38BN9qCENV0EvbtNP2+o1kWaIhFyvLdXa9BgptA0n:5pIzE48rLShCP9W1TP2dCWaIhUvJKK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_eb2f8dce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104"
    family = "Mirai"
    file_name = "eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:48"
  condition:
    hash.sha256(0, filesize) == "eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104"
}
```

### Sample 61: `66d8f18742afa0b9`

| Field | Value |
|---|---|
| SHA-256 | `66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709` |
| Family label | `Mirai` |
| File name | `66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:16:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d38c138d409e2cd36a6922605109408d` |
| SHA-1 | `e1ab058caa21f55b316b4d972f5a79190cb2bf97` |
| SHA-256 | `66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709` |
| SHA3-384 | `7e447d6d827317a602bb3ef8506cb45fe7abc341914f0891d1cf36ac5d7f24e7c17c0c4cac916ca5274d1dc9e25f6f99` |
| TLSH | `T17B456D19A2F2F1FCD14BC034539BD9625931B47635333D7B32C9AA322A76DA113ADB21` |
| TELFHASH | `t1f7f1de744ff939b0b2d7d9117362f0b19932187aa6f836f41612add4df95ec04c6282b` |
| SSDEEP | `24576:CaZhlNgZicIvNkV3rizpVW2r+hYT0zdfX1H:1zlNgrI43rizpVkhsKlH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_66d8f187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709"
    family = "Mirai"
    file_name = "66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:45"
  condition:
    hash.sha256(0, filesize) == "66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709"
}
```

### Sample 62: `8239a5b14056d6bc`

| Field | Value |
|---|---|
| SHA-256 | `8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba` |
| Family label | `Mirai` |
| File name | `8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:16:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ac6079f46da7bb7517f55074dc5b5c3` |
| SHA-1 | `38d76c42dcff91b700bdeb62a78ccd530b9a8443` |
| SHA-256 | `8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba` |
| SHA3-384 | `b8daf3b4251de0c156d1b1bc862dee909f02f642f4df66e6cdc24d53002400b2e0d857ed3a61c58d59c0f0d8d34910cd` |
| TLSH | `T1F4330211D2D6198CFD699D2AD933A2C066720B96BBE4F4E02981BF350C9F714DB9DEC0` |
| SSDEEP | `1536:jdAoICAsdhgdtDxF47K4yUbirfaCzx4BtkF4u+qgw09J:51Ildpx+KJii7aSGtkF4u+qgwc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_8239a5b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba"
    family = "Mirai"
    file_name = "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:41"
  condition:
    hash.sha256(0, filesize) == "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba"
}
```

### Sample 63: `5a35d2623dc83cc6`

| Field | Value |
|---|---|
| SHA-256 | `5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54` |
| Family label | `Mirai` |
| File name | `5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54.elf` |
| File type | `elf` |
| First seen | `2026-08-22 20:16:37` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c06839ef5a6b66bdaf5d41861080a68` |
| SHA-1 | `123f7793afd0984d0801fba22524debe206a5eed` |
| SHA-256 | `5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54` |
| SHA3-384 | `4951bf3049c2eb4526babf6cadcec0e298990ce457dffc03a185cde1a0cde26dae97d981694b9008df77cdc54bca85ca` |
| TLSH | `T108456D466371CF8CF354E67002B39A165EA611B326E361C6A2BDE620376125D1CAFFF4` |
| TELFHASH | `t194619e98097813f4b3655c9d4aedff36d5a320ef3a161d239e10e85da726e839c10c1d` |
| SSDEEP | `24576:FtRxQDdX9Mape4SYfKfLf4a3GYMwJaZE1mDj/gAA:bwXPetYu4aHMwQf3c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_5a35d262
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54"
    family = "Mirai"
    file_name = "5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:37"
  condition:
    hash.sha256(0, filesize) == "5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54"
}
```

### Sample 64: `3f36db0edd3ef78b`

| Field | Value |
|---|---|
| SHA-256 | `3f36db0edd3ef78b7c0b5025463e26fb7d7924fab5df47ef8c12839c71d061a0` |
| Family label | `Mirai` |
| File name | `daredevil.sparc` |
| File type | `elf` |
| First seen | `2026-08-22 20:11:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1ef1ff80d9eec3407bff0e01fdf7215` |
| SHA-1 | `c0d99e5275f4db88bf4555f2fe78e043fd05c9af` |
| SHA-256 | `3f36db0edd3ef78b7c0b5025463e26fb7d7924fab5df47ef8c12839c71d061a0` |
| SHA3-384 | `feef65132895224ff85d939773f7ffc3addd310006002a11bc80e31b3e946e7d2583f45f5728d959a76ac257f23c53eb` |
| TLSH | `T1F823F716EE786A27C1D0323614E78A21E97663D917A8D64F7EB31C49DD58320303EEDE` |
| TELFHASH | `t14be02240fdb84a1889e79ab0dc8c46a0a4036223a2660b21cf11eae08c3f854f70cd6a` |
| SSDEEP | `768:Iqbs8kMAWRiFMVoG+LgoOqsJbHzXa6bNMI6mAdHrpOj1P:Bbs4FtR+cxqsVja6b76m4MP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_3f36db0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f36db0edd3ef78b7c0b5025463e26fb7d7924fab5df47ef8c12839c71d061a0"
    family = "Mirai"
    file_name = "daredevil.sparc"
    file_type = "elf"
    first_seen = "2026-08-22 20:11:47"
  condition:
    hash.sha256(0, filesize) == "3f36db0edd3ef78b7c0b5025463e26fb7d7924fab5df47ef8c12839c71d061a0"
}
```

### Sample 65: `9fc5141ce0a056a7`

| Field | Value |
|---|---|
| SHA-256 | `9fc5141ce0a056a769af034dbd3559f0f6ad0d09e1a71638bae19a5fadce4f63` |
| Family label | `Mirai` |
| File name | `bot.i686` |
| File type | `elf` |
| First seen | `2026-08-22 20:08:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e91dc29307b1833b50188966e7ccb8d7` |
| SHA-1 | `7e71ba1d4b2e2e2ab7db33b81386b659e5f9217a` |
| SHA-256 | `9fc5141ce0a056a769af034dbd3559f0f6ad0d09e1a71638bae19a5fadce4f63` |
| SHA3-384 | `9484445a6b37daf5f4cd01a6800ad9ae3f52d42ad7462771c5002ba2b81cce9eff3f992ba1c5fed0948e5243c5e82d9b` |
| TLSH | `T168456BC8E3E3D1F9F25395B0034FABA71D3052266053F6E6E78D6A6371733521A5A238` |
| TELFHASH | `t1eb22bbb325ae68ec3bf088158a5b7210ce96e03719f039b20df354d1a773e539a76578` |
| SSDEEP | `24576:uFfOZbQ4hpihDZ3DLVZ0UfDomYnWzPH3P0umlvcUp+Ht:uYnhpihVgb9nev3OkHt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_9fc5141c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fc5141ce0a056a769af034dbd3559f0f6ad0d09e1a71638bae19a5fadce4f63"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-22 20:08:48"
  condition:
    hash.sha256(0, filesize) == "9fc5141ce0a056a769af034dbd3559f0f6ad0d09e1a71638bae19a5fadce4f63"
}
```

### Sample 66: `0c866ff3e572339e`

| Field | Value |
|---|---|
| SHA-256 | `0c866ff3e572339e40d5e53cbff06238ba8433f1d8a972cda512a39a7f450d37` |
| Family label | `Mirai` |
| File name | `daredevil.mipsel` |
| File type | `elf` |
| First seen | `2026-08-22 20:08:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26144b57fb35c536b62e8481f222a321` |
| SHA-1 | `9008474e82f7a6eb7067fc407659dc47b46e01fa` |
| SHA-256 | `0c866ff3e572339e40d5e53cbff06238ba8433f1d8a972cda512a39a7f450d37` |
| SHA3-384 | `c0e6dd1c0796ec127573d2628535a062dac7f4d91b124a6e501670681bae3e13e31e2d85160eb7339c534c4f9e73a69f` |
| TLSH | `T1DE04D90AAF610FBBD8BFDD3305E90B0639DC644722A93B753674D528F50A64B4AD3C68` |
| SSDEEP | `3072:KmYMfW/J3hz0NhwN9lNV40iMVLmdk+z6:KmYMfW/H0NsU0VVYv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_0c866ff3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c866ff3e572339e40d5e53cbff06238ba8433f1d8a972cda512a39a7f450d37"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-22 20:08:10"
  condition:
    hash.sha256(0, filesize) == "0c866ff3e572339e40d5e53cbff06238ba8433f1d8a972cda512a39a7f450d37"
}
```

### Sample 67: `0fea0febf7bea085`

| Field | Value |
|---|---|
| SHA-256 | `0fea0febf7bea085c21d58d55387a63d4f3f329c698d8642e21d510bb6828962` |
| Family label | `Mirai` |
| File name | `daredevil.mipsel` |
| File type | `elf` |
| First seen | `2026-08-22 20:07:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6aa6ea944f0a4776dabe63e072f95b9` |
| SHA-1 | `bafb31e165c7441a841532a9c7889af487a62935` |
| SHA-256 | `0fea0febf7bea085c21d58d55387a63d4f3f329c698d8642e21d510bb6828962` |
| SHA3-384 | `11b5c8371d88575ca0ae106caa1e40f857d17ee1112c9cd5b4b2da1abf6d3de6d0cfa309531977f14ef707e18b64c663` |
| TLSH | `T1BD43F1F885B198EDC81D957E67AD1688C860D452734B4BDCDB02DCCAEA8B063F89817C` |
| SSDEEP | `1536:BRr3fKuN4UOw3IEAP56x7tqsTtUaOqs8hq:z3F4i3IEguxqsmhqs1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_0fea0feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fea0febf7bea085c21d58d55387a63d4f3f329c698d8642e21d510bb6828962"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-22 20:07:24"
  condition:
    hash.sha256(0, filesize) == "0fea0febf7bea085c21d58d55387a63d4f3f329c698d8642e21d510bb6828962"
}
```

### Sample 68: `66cd0fd624d086ab`

| Field | Value |
|---|---|
| SHA-256 | `66cd0fd624d086ab2e383eae1f97c14565e16de3d184a7e7555fe35b1d9c5d1b` |
| Family label | `Mirai` |
| File name | `daredevil.arc` |
| File type | `elf` |
| First seen | `2026-08-22 20:04:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66695899f677bbe293922ae9432d1af9` |
| SHA-1 | `bc02ad69043b98697f1c3f0937d81307f1ec2022` |
| SHA-256 | `66cd0fd624d086ab2e383eae1f97c14565e16de3d184a7e7555fe35b1d9c5d1b` |
| SHA3-384 | `09916e2c2e4b852e22c824d3f9224e9d40cee7da5c299b20691e4bd1db59a1675ba0b744aa602babc82dccd5818cac79` |
| TLSH | `T18CD3AE63B24F0450C46606F45BCB9BAD2E3366C04E6F59E77C7E723E9A724CA1811BE1` |
| SSDEEP | `3072:ysKddFgVAsL6ipV0589XZA7qevBRgcCJBheNznZsq:dKdUP6H5EKOeJTCJbgz2q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_66cd0fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66cd0fd624d086ab2e383eae1f97c14565e16de3d184a7e7555fe35b1d9c5d1b"
    family = "Mirai"
    file_name = "daredevil.arc"
    file_type = "elf"
    first_seen = "2026-08-22 20:04:24"
  condition:
    hash.sha256(0, filesize) == "66cd0fd624d086ab2e383eae1f97c14565e16de3d184a7e7555fe35b1d9c5d1b"
}
```

### Sample 69: `f48debf0e99b1613`

| Field | Value |
|---|---|
| SHA-256 | `f48debf0e99b16130594458c82205af33785a97f7d3df4cfed7cd30acd266b2d` |
| Family label | `RemusStealer` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-08-22 19:52:15` |
| Reporter | `iamaachum` |
| Tags | `AsgardProtector, dropped-by-OffLoader, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f9d90923d2d9bba0de4e375d8f3cd11` |
| SHA-1 | `56a11de9764cb29c2821441b10bf68f2b9d1a40b` |
| SHA-256 | `f48debf0e99b16130594458c82205af33785a97f7d3df4cfed7cd30acd266b2d` |
| SHA3-384 | `222994d84053d31e0f9fa2009bc84e57949aeaa5d305865d3650099935d14825065f46d585e8a1f9e9dc6378dd3f8bc0` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T16A65230361E84846F5BD473689F7859B9234FC826B398ACF62A9490D1FB3ED0E13571B` |
| SSDEEP | `24576:UWSwy7GSBhKMijatSk5pOryr1agRRRxC3M8g2tX/OEH+GS/:XEBhKNjatSkey5agRDc3M8g2tPb+GS` |
| ICON-DHASH | `dae8eadafae2aed8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_069_f48debf0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48debf0e99b16130594458c82205af33785a97f7d3df4cfed7cd30acd266b2d"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-22 19:52:15"
  condition:
    hash.sha256(0, filesize) == "f48debf0e99b16130594458c82205af33785a97f7d3df4cfed7cd30acd266b2d"
}
```

### Sample 70: `c6f6ae0ce1a2a2e8`

| Field | Value |
|---|---|
| SHA-256 | `c6f6ae0ce1a2a2e8e5066b8a78edc06b8cc3586d5fd5716c257ca388d1d79655` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 19:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c269ecc209a1cdec64d8496b0e4b06fa` |
| SHA-256 | `c6f6ae0ce1a2a2e8e5066b8a78edc06b8cc3586d5fd5716c257ca388d1d79655` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_c6f6ae0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6f6ae0ce1a2a2e8e5066b8a78edc06b8cc3586d5fd5716c257ca388d1d79655"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 19:52:09"
  condition:
    hash.sha256(0, filesize) == "c6f6ae0ce1a2a2e8e5066b8a78edc06b8cc3586d5fd5716c257ca388d1d79655"
}
```

### Sample 71: `782a55c97a9a4605`

| Field | Value |
|---|---|
| SHA-256 | `782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374` |
| Family label | `Mirai` |
| File name | `782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374.elf` |
| File type | `elf` |
| First seen | `2026-08-22 19:46:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe9e4f0e77128c093284402d15c3aeee` |
| SHA-1 | `957dccf079113b4e8f99b632a23a67232bd76613` |
| SHA-256 | `782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374` |
| SHA3-384 | `deb0a6b6f7a39c1a0bf3e75b3ee9d5b6061278ccb35a379dcb45eb7fa2105e11694b6650daf6a7baba7ac6608e703012` |
| TLSH | `T18F457C059F901FDFD0AFCD30462E960B08ED4DA722C6B7B5A0BCCC59B39A2494ED7958` |
| SSDEEP | `12288:+2JybSpmiEccTL0BrSuMzRPiv7et8hOgXVse1UZ1ajGPdOHJ/jWJQPFP0uUADIOS:KynU7kcwO2fohbQUOAy/pbpEAgpnmqv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_782a55c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374"
    family = "Mirai"
    file_name = "782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:46:38"
  condition:
    hash.sha256(0, filesize) == "782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374"
}
```

### Sample 72: `882386fb50324ab5`

| Field | Value |
|---|---|
| SHA-256 | `882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2` |
| Family label | `Mirai` |
| File name | `882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2.elf` |
| File type | `elf` |
| First seen | `2026-08-22 19:46:34` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9570f3f612da61224929b862ed3787a1` |
| SHA-1 | `d7cc5a0157ae1cebe7f92ef722901190889ee8b9` |
| SHA-256 | `882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2` |
| SHA3-384 | `8dfdfba3f70e82b97c0bdd606af92ae9da9e98a1a62f54d616948a4714916f94810aae6d8ed403ed738df91b87dfafa9` |
| TLSH | `T1F5458E05F72886A3D5425DF0173F57C6F7256A1310FAA22A330FAB232372A3A95C7795` |
| SSDEEP | `24576:F72Hh7O3lifZtQulxrJ6uxqPaXlNxlsF55z6n66ur723i:YHh7O3liEulxMu0MlNxWF55Iar72S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_882386fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2"
    family = "Mirai"
    file_name = "882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:46:34"
  condition:
    hash.sha256(0, filesize) == "882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2"
}
```

### Sample 73: `0e3f4c846181031a`

| Field | Value |
|---|---|
| SHA-256 | `0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa` |
| Family label | `Mirai` |
| File name | `0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa.elf` |
| File type | `elf` |
| First seen | `2026-08-22 19:41:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aff70b20490c83103b4776a95e44fb6d` |
| SHA-1 | `2cc81379afc39eddfd444885a22b0c45525604b0` |
| SHA-256 | `0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa` |
| SHA3-384 | `19c729975e3ae98495bdaec8efd70bf9294f9e52f15b6fa388788aecef25c2ee0ed4af8bcb17f28b2b34823ca5892e04` |
| TLSH | `T1B5F49FC8E3F2EBCEE199E9355201BC064D66853730E37385725FA5B3327A1704BE9A61` |
| SSDEEP | `12288:eX8GzvwPwgu1yVbwscmTPBW2G2MGszvWBneiQa9ggpPLpVHg:Rvxu1yVdcmN2zGpRVH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_0e3f4c84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa"
    family = "Mirai"
    file_name = "0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:41:42"
  condition:
    hash.sha256(0, filesize) == "0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa"
}
```

### Sample 74: `dfcfa81660a11bcc`

| Field | Value |
|---|---|
| SHA-256 | `dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc` |
| Family label | `Mirai` |
| File name | `dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc.elf` |
| File type | `elf` |
| First seen | `2026-08-22 19:41:36` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d46b88dab56227fe9d86a53016723d19` |
| SHA-1 | `95e0b1c0e435c5069f31870ffd2839b987fc6d53` |
| SHA-256 | `dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc` |
| SHA3-384 | `807a27959b1d56efe96b457410dc793d8e458df7a54c4a234604cdbdfd5bf105be5de8e1f28fcca4f338da441dcdc8c7` |
| TLSH | `T15315AF91E2B0E7DDD118CA746179F9384F52B23332837182B2BF855312AB29579EDB70` |
| SSDEEP | `12288:gqdwdQ7sp4IjMY/Z/E6J8pcsFd4f5ITrqF/nZUgMS3DaOQtxW4FfG9xADfQp9yJM:qeIIY/DsFd4x8OnLm3FvkDV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_dfcfa816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc"
    family = "Mirai"
    file_name = "dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:41:36"
  condition:
    hash.sha256(0, filesize) == "dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc"
}
```

### Sample 75: `a88aa9d6b0dc066a`

| Field | Value |
|---|---|
| SHA-256 | `a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710` |
| Family label | `unknown` |
| File name | `a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710` |
| File type | `sh` |
| First seen | `2026-08-22 19:30:20` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb1a55950cc19379d7c1d912097dfa6d` |
| SHA-1 | `d96f64e62aeaac259e02ab1e8a2f6ed3dd1c2e68` |
| SHA-256 | `a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710` |
| SHA3-384 | `d5ccbf453913bb330f45506b68ac16dc7da4c6867ce96b4af8b71da46d14c248bb9b9aa33a5a7d270729198ce7deda04` |
| TLSH | `T184316F9F51201A320402CE4EB7B7750CB68DE1FB2D5FCBD0D8498EAA86586CCF221B59` |
| SSDEEP | `24:+bCsb1yJopps3TTE/e6e1qtpe7KLcJ2yAt4bbHIj:+bXbsopaUYJ2yRbbHIj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_a88aa9d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710"
    family = "unknown"
    file_name = "a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710"
    file_type = "sh"
    first_seen = "2026-08-22 19:30:20"
  condition:
    hash.sha256(0, filesize) == "a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710"
}
```

### Sample 76: `123c42921a703926`

| Field | Value |
|---|---|
| SHA-256 | `123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331` |
| Family label | `unknown` |
| File name | `123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331` |
| File type | `sh` |
| First seen | `2026-08-22 19:30:16` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73b14cfb712a9a1778873bc548ed699e` |
| SHA-1 | `a40b88d964ce70984dcde40004fa66113165e5e7` |
| SHA-256 | `123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331` |
| SHA3-384 | `b517357b414d8621b4bdf444d5e1839d353086f3aa674ac9dcff2fc7566b727a1bd5904771d3d71ae7c2192e1508d762` |
| TLSH | `T1483104CA14542A725142CADE33B2214D628EE1F7386FDBD4DC590DA962487CCF2E5F49` |
| SSDEEP | `24:bctL12LjQqXZwdt2FhwwZHbV7RgHtHSyT5H:+L12LjRRFvZHbVSHtV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_123c4292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331"
    family = "unknown"
    file_name = "123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331"
    file_type = "sh"
    first_seen = "2026-08-22 19:30:16"
  condition:
    hash.sha256(0, filesize) == "123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331"
}
```

### Sample 77: `3c667f6229ea2acb`

| Field | Value |
|---|---|
| SHA-256 | `3c667f6229ea2acb192d3ee6982ff5f3a7638fdb33563ad7224d64afd95dd01a` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 18:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc49e422487c134b6b5eaad51ffc5ad3` |
| SHA-256 | `3c667f6229ea2acb192d3ee6982ff5f3a7638fdb33563ad7224d64afd95dd01a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_3c667f62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c667f6229ea2acb192d3ee6982ff5f3a7638fdb33563ad7224d64afd95dd01a"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 18:52:09"
  condition:
    hash.sha256(0, filesize) == "3c667f6229ea2acb192d3ee6982ff5f3a7638fdb33563ad7224d64afd95dd01a"
}
```

### Sample 78: `20082d2052d2d406`

| Field | Value |
|---|---|
| SHA-256 | `20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-22 18:49:21` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, dropped-by-GCleaner, exe, F, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8adc5c25b4fe2bfe0fd5d623ade01b76` |
| SHA-1 | `3088cd77ee02faf163202631d247c53fcb1185e5` |
| SHA-256 | `20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e` |
| SHA3-384 | `cf2cb1d610ebe4846f68cd846d089898265ba25842e5da451f8f139c5f1fe8fbb04fbaa7a45d7a0c16429283a566a187` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F1952F603BEA61D9F077BE26C7EA7692D62FB3737A07965B1600030F0622542DF53939` |
| SSDEEP | `24576:XF8/OcAblxAAkKGR/xgDTC6JKKWOtY9/6dGXRsXsvVf:q/Oc6lxALKM/uS0/gJXqXs9` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_078_20082d20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 18:49:21"
  condition:
    hash.sha256(0, filesize) == "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e"
}
```

### Sample 79: `c0909c4463983aff`

| Field | Value |
|---|---|
| SHA-256 | `c0909c4463983aff4ea390f9da2c1428a1a05bddb4f6d3293c04af36fc0831a9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-22 18:45:11` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX4.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63494842a00fe1ba1cdcae532670baf5` |
| SHA-1 | `11147c84001378223abd7bb4175c7382b2ec46d2` |
| SHA-256 | `c0909c4463983aff4ea390f9da2c1428a1a05bddb4f6d3293c04af36fc0831a9` |
| SHA3-384 | `b324978b10c49a23ae36010ed38ad04d75ba5a4c99683ad9f4173d872630275ef7870003cdf7692e201d843e79002c33` |
| IMPHASH | `2c89d36313c9c017a0b9cc90cdb0923b` |
| TLSH | `T13726331B6B88A408E90FAAFC153F2B81357FF752B552323D85E3497D5C40261ABEE46C` |
| SSDEEP | `98304:i/oqjB1tbTbMuFeI1JbpRMFYiIn7/EryK8Kgl:iAqRXgOdoYiI7/BKEl` |
| ICON-DHASH | `c4f071b2b271f0cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_c0909c44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0909c4463983aff4ea390f9da2c1428a1a05bddb4f6d3293c04af36fc0831a9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 18:45:11"
  condition:
    hash.sha256(0, filesize) == "c0909c4463983aff4ea390f9da2c1428a1a05bddb4f6d3293c04af36fc0831a9"
}
```

### Sample 80: `5958756858b724c4`

| Field | Value |
|---|---|
| SHA-256 | `5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6` |
| Family label | `unknown` |
| File name | `5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6.exe` |
| File type | `exe` |
| First seen | `2026-08-22 18:01:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `798eb4def3d8afc28eb5bd737c82e79a` |
| SHA-1 | `b0b4cbb227d5a10116cb06981892969e66b9768c` |
| SHA-256 | `5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6` |
| SHA3-384 | `f58d063550e63c15b2bc80a98d995c77286ad131b77991097fa382324be7d14feb878c06cabcc7b353afc428c6c6b14e` |
| IMPHASH | `b8048b8957358587b4fda264349e8f60` |
| TLSH | `T16DD523AA7DF61A79D432C3F58D82F46E72393B8157348E93368806014E739989C3977E` |
| SSDEEP | `49152:ssBQn4COLLpnAosYM+gzDJJfygDG4R3Y3Og5uKJkOgJRLtVy92QgTnEq2RJ+cxpz:XBQ4ConAoslvDnC4RgOUpaRLLm29URAh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_59587568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6"
    family = "unknown"
    file_name = "5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6.exe"
    file_type = "exe"
    first_seen = "2026-08-22 18:01:32"
  condition:
    hash.sha256(0, filesize) == "5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6"
}
```

### Sample 81: `4ad1af0f9bec58fb`

| Field | Value |
|---|---|
| SHA-256 | `4ad1af0f9bec58fbbca457c4279e70b89cbe2084c75969107de09ef34e0df3f5` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 17:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `158c90ef0b14b487de350b1ae290cbaf` |
| SHA-256 | `4ad1af0f9bec58fbbca457c4279e70b89cbe2084c75969107de09ef34e0df3f5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_4ad1af0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ad1af0f9bec58fbbca457c4279e70b89cbe2084c75969107de09ef34e0df3f5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 17:52:11"
  condition:
    hash.sha256(0, filesize) == "4ad1af0f9bec58fbbca457c4279e70b89cbe2084c75969107de09ef34e0df3f5"
}
```

### Sample 82: `478a5d81892f27b5`

| Field | Value |
|---|---|
| SHA-256 | `478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e` |
| Family label | `unknown` |
| File name | `478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e.exe` |
| File type | `exe` |
| First seen | `2026-08-22 17:51:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1680963d810d9d89c1c81bd311d0f1b` |
| SHA-1 | `475c5e64323e808944a361fe3a7590a183749ff9` |
| SHA-256 | `478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e` |
| SHA3-384 | `f74c459f820022dcc26c3ad0fd71fd567be0b6e851c18585d5fc4cc06eebfa1b4b91ffc1971a40e93e4e67a5e803c68b` |
| IMPHASH | `24e8765fd838d429e6f908cdeb96c2d6` |
| TLSH | `T155D5239EFC862070E433C7BB87D3206EB17937554B258C9EB2C8AB445E239186CB7765` |
| SSDEEP | `49152:aOt6jm1cytVlmgubFdkpuk3ZSrWcTVOo7suzw3lGAJ+bIPGI+IR52N1agaJu7q:aOWm1nlmgubFkSicB5su8fw6GF02N1oL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_478a5d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e"
    family = "unknown"
    file_name = "478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e.exe"
    file_type = "exe"
    first_seen = "2026-08-22 17:51:35"
  condition:
    hash.sha256(0, filesize) == "478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e"
}
```

### Sample 83: `1cbad26e560805b3`

| Field | Value |
|---|---|
| SHA-256 | `1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead` |
| Family label | `unknown` |
| File name | `1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead.exe` |
| File type | `exe` |
| First seen | `2026-08-22 17:36:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4c8da8391131faafbc1622050df06d6` |
| SHA-1 | `e67a542b01dec3265263b2d2b87d8c1381403d00` |
| SHA-256 | `1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead` |
| SHA3-384 | `fff8e6143919d7682cbcc7dc39bb3568b5b7a770298d830807d44c8526343fccd59552fa9485266e9abeec2c5109b62b` |
| IMPHASH | `e5e480df311e1f1fb84816415c6d8594` |
| TLSH | `T1F7248D6BB4E41BB4F46FE235C5456B26C1F2344A5B31D29F51B48EE62F13332A22D386` |
| SSDEEP | `6144:S3GvcwEi6j2eE1dwp9FKoN0zzeqhxE4Zf:QGvtwpiS0zzeeBd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_1cbad26e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead"
    family = "unknown"
    file_name = "1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead.exe"
    file_type = "exe"
    first_seen = "2026-08-22 17:36:34"
  condition:
    hash.sha256(0, filesize) == "1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead"
}
```

### Sample 84: `650a4cd183179db8`

| Field | Value |
|---|---|
| SHA-256 | `650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273` |
| Family label | `unknown` |
| File name | `650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273.bin` |
| File type | `exe` |
| First seen | `2026-08-22 17:14:15` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f3871298a1d12a1bd32cccddce86ee0` |
| SHA-1 | `392c59924103a45553b1e4bd1f5845e42d4f1c9b` |
| SHA-256 | `650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273` |
| SHA3-384 | `f6c6027c05b3121412ba33795a8822d2c226983643024c6ef2ce22fb4b54b2739672ca0938965d8212618290172d99e1` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T102366C072D9141E4E5A18F388237D692AA74BC48C73673A36EA0A1703F75BD17EF9B11` |
| SSDEEP | `49152:gbHBZzsTcceNx8ud9wpQSnotNSOL7PE16ZldbUeLC7fN4uTwqOgmburdUKGKNbxH:GhZvnY8P5s6DW7VbSwNbxH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_650a4cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273"
    family = "unknown"
    file_name = "650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273.bin"
    file_type = "exe"
    first_seen = "2026-08-22 17:14:15"
  condition:
    hash.sha256(0, filesize) == "650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273"
}
```

### Sample 85: `9cfd1645a9ce5896`

| Field | Value |
|---|---|
| SHA-256 | `9cfd1645a9ce589649c7821e75f72723a5e13d6dd3aab8a6bada7aa8d8651233` |
| Family label | `AsyncRAT` |
| File name | `VIN88APP.exe` |
| File type | `exe` |
| First seen | `2026-08-22 17:02:21` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fbeea9f24c9314ef0fdc36245f22054` |
| SHA-1 | `7ea8329364111610c7f029a4640c3de87afa6d14` |
| SHA-256 | `9cfd1645a9ce589649c7821e75f72723a5e13d6dd3aab8a6bada7aa8d8651233` |
| SHA3-384 | `21f9f046546dde7ad06b60ed6dfe2fb32eee6f9f5aba475dae342745538fb0ec8b0eb6cc49d08d9b34169d8d0438220e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11AC23B0833E4C571E2FD4ABA9833E5008B75E55B9913D76A6FC890AD2E237CD8A14FD4` |
| SSDEEP | `384:sAZguIKgpDW8LLHtZARPn9jXH9qbuUshybQxnCJfJBndnjJrKr++:sAZgHdt+bIbIBiBnSr++` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_085_9cfd1645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cfd1645a9ce589649c7821e75f72723a5e13d6dd3aab8a6bada7aa8d8651233"
    family = "AsyncRAT"
    file_name = "VIN88APP.exe"
    file_type = "exe"
    first_seen = "2026-08-22 17:02:21"
  condition:
    hash.sha256(0, filesize) == "9cfd1645a9ce589649c7821e75f72723a5e13d6dd3aab8a6bada7aa8d8651233"
}
```

### Sample 86: `4b3414176f27060a`

| Field | Value |
|---|---|
| SHA-256 | `4b3414176f27060a6730d09121dfad6f39fca4f9c5a9875b7ba597318af11dcf` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-22 16:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce4fc27110c792b4c4b80180d2b7db9f` |
| SHA-256 | `4b3414176f27060a6730d09121dfad6f39fca4f9c5a9875b7ba597318af11dcf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_4b341417
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b3414176f27060a6730d09121dfad6f39fca4f9c5a9875b7ba597318af11dcf"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 16:52:10"
  condition:
    hash.sha256(0, filesize) == "4b3414176f27060a6730d09121dfad6f39fca4f9c5a9875b7ba597318af11dcf"
}
```

### Sample 87: `d8a25c8e3928fe21`

| Field | Value |
|---|---|
| SHA-256 | `d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687` |
| Family label | `Vidar` |
| File name | `d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687.bin` |
| File type | `exe` |
| First seen | `2026-08-22 16:35:25` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1316d93667bb04d22ddc89f99adb14a3` |
| SHA-1 | `d20c5c4746634435f52252aa2852e5d4082319cc` |
| SHA-256 | `d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687` |
| SHA3-384 | `c92a8df3e9184a4703ea86b59959876cc4972713615185765470a1722a49ce0fdff6974deb47b97546ccb366cea8877f` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T10F168C43FF90586AD456A23284B7A251773DBC095B2227E76F9073762F327C0A93B724` |
| SSDEEP | `49152:SKc8kVW/2vRkRqhbHFcmUYVddpFhavtEaRactq1YMh+el:S5W4jiqddpFhavtEaRacwCMgel` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_087_d8a25c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687"
    family = "Vidar"
    file_name = "d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687.bin"
    file_type = "exe"
    first_seen = "2026-08-22 16:35:25"
  condition:
    hash.sha256(0, filesize) == "d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687"
}
```

### Sample 88: `a5593326022f9fa6`

| Field | Value |
|---|---|
| SHA-256 | `a5593326022f9fa6306b62bc81e7833a719543510ba60bb0727cf5c0fba84181` |
| Family label | `unknown` |
| File name | `Frostix.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:34:05` |
| Reporter | `Alex_sev` |
| Tags | `exe, generic, malpack, packed, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6325fc4d958c95a85b57b08995dc2f06` |
| SHA-1 | `05c174d5f8db8f7cb7f3c5753e9472cb3fb698d5` |
| SHA-256 | `a5593326022f9fa6306b62bc81e7833a719543510ba60bb0727cf5c0fba84181` |
| SHA3-384 | `f448787de40492ccb71b923e6329fedc688ffe5e7e29d41bfbc76554d594866003ef84ad0fea557bbb46f19b7ec3647d` |
| IMPHASH | `d795714239f5a4576175cf1aa5d349a0` |
| TLSH | `T101F523F0B9872A75D017FB70451AF6BDF06E378A8AA5CC077BE8AE111E6350C1635B84` |
| SSDEEP | `98304:3icb7kdwgdR+89RuAtf+1O1RTsG3g7KnNAPK:rb4dwIRVb+1O1RTpQ7K/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_a5593326
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5593326022f9fa6306b62bc81e7833a719543510ba60bb0727cf5c0fba84181"
    family = "unknown"
    file_name = "Frostix.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:34:05"
  condition:
    hash.sha256(0, filesize) == "a5593326022f9fa6306b62bc81e7833a719543510ba60bb0727cf5c0fba84181"
}
```

### Sample 89: `ea6336072689dc80`

| Field | Value |
|---|---|
| SHA-256 | `ea6336072689dc80c1031970337cd1d33bc29c924d65ad2c4088f624adaaee5f` |
| Family label | `unknown` |
| File name | `libcurl.dll` |
| File type | `exe` |
| First seen | `2026-08-22 16:32:13` |
| Reporter | `Alex_sev` |
| Tags | `agent, dllhijack, exe, generic, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15d80588b736fc27547d84631239f40b` |
| SHA-1 | `7d6b6fc017d15d248915e57637cdccb7f8d6d8a5` |
| SHA-256 | `ea6336072689dc80c1031970337cd1d33bc29c924d65ad2c4088f624adaaee5f` |
| SHA3-384 | `3c05185aacce38ca6a5ddc0c2b59e85ea8852d92681d7f66446f6f950c1411e14478c8a3a06d134f6ea71eced05b54a4` |
| IMPHASH | `37c732262d2c12a3a554bb4982f2541d` |
| TLSH | `T16165C01BB3A412B9E17BD27CC5571A1AFAB2780A132097CB13E547AA1F637E0463F351` |
| SSDEEP | `24576:yhrc6JZvf9fYE2PONVKoYzbPiKys/PyqVbagpqvX+YaVvHRIcSc+A:yhJZvf9gE2PONVKlriKyz2Q2IcShA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_ea633607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea6336072689dc80c1031970337cd1d33bc29c924d65ad2c4088f624adaaee5f"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-08-22 16:32:13"
  condition:
    hash.sha256(0, filesize) == "ea6336072689dc80c1031970337cd1d33bc29c924d65ad2c4088f624adaaee5f"
}
```

### Sample 90: `57e2a8f9bd8e32dd`

| Field | Value |
|---|---|
| SHA-256 | `57e2a8f9bd8e32dd98032761993df0bca2054343ff24bd6a6570fce93d0eccf0` |
| Family label | `unknown` |
| File name | `setup_app_V8.15.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:24:46` |
| Reporter | `Alex_sev` |
| Tags | `dropper, exe, packed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc7265252458baecbbc766f8357c1ac3` |
| SHA-1 | `2b1d309c25aacf5e8c37f10e778c7c7a5db8ca8b` |
| SHA-256 | `57e2a8f9bd8e32dd98032761993df0bca2054343ff24bd6a6570fce93d0eccf0` |
| SHA3-384 | `042090c1d8c6ed0fb743995ec4bd4bae3ccae4861ef632b2201839da1b55091b16b2ab6bb281b27c180449371db983ec` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T18AE62237B28B653EF06E5A3559B2E210583B76616D138D4BD6F0486CCF292A03E3F647` |
| SSDEEP | `196608:HHimrNxlDVlRPZI+YV34zaBmTwb6EP4T0m0u:HHimZxdVLPu+Yxn68F4T0mF` |
| ICON-DHASH | `f0c8ce9696ccf030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_57e2a8f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57e2a8f9bd8e32dd98032761993df0bca2054343ff24bd6a6570fce93d0eccf0"
    family = "unknown"
    file_name = "setup_app_V8.15.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:24:46"
  condition:
    hash.sha256(0, filesize) == "57e2a8f9bd8e32dd98032761993df0bca2054343ff24bd6a6570fce93d0eccf0"
}
```

### Sample 91: `084aa5657fae525d`

| Field | Value |
|---|---|
| SHA-256 | `084aa5657fae525db8ec6a96d9953033529cdf4c3f3183663599190046110144` |
| Family label | `unknown` |
| File name | `core-release.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:23:35` |
| Reporter | `Alex_sev` |
| Tags | `exe, nsis, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcbecc849171189eb6aea1355f4187a2` |
| SHA-1 | `ec8529bf996356a5e277f7ddd551d11864fc4389` |
| SHA-256 | `084aa5657fae525db8ec6a96d9953033529cdf4c3f3183663599190046110144` |
| SHA3-384 | `85d334f3a1ace7f78d8c912f9b08ba3ed61e9b6a4f5cda8a9d75b3ad8a8fd6d20d2c0868e6a09e80a38dc2ccb9bce3ce` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1362833FBF925B305CA5BA4B368C30AF81014B3D4A22721BB743E6CCAE91E55257C7935` |
| SSDEEP | `1572864:pLdkmGB4tTO9Dt3Twsc/m+FQj9J+47h3uSSyXz9pPa/zrYpGoopO0dMUp7:p2mWX9t3Us3uQjq0hFSsz9BMrRCSp7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_084aa565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "084aa5657fae525db8ec6a96d9953033529cdf4c3f3183663599190046110144"
    family = "unknown"
    file_name = "core-release.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:23:35"
  condition:
    hash.sha256(0, filesize) == "084aa5657fae525db8ec6a96d9953033529cdf4c3f3183663599190046110144"
}
```

### Sample 92: `db576e0cfabd6fad`

| Field | Value |
|---|---|
| SHA-256 | `db576e0cfabd6fadfff0534e764a29d73e288939baad993cc07cc7a9cc67a633` |
| Family label | `Vidar` |
| File name | `Installer.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:22:11` |
| Reporter | `Alex_sev` |
| Tags | `agent, dropper, exe, injector, js, script, stealerc, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c58fb6eeaf990e39e2f04558125fda2` |
| SHA-1 | `8c7fc4e236cb8be0d0cce55b47189bd8b5c53f6d` |
| SHA-256 | `db576e0cfabd6fadfff0534e764a29d73e288939baad993cc07cc7a9cc67a633` |
| SHA3-384 | `58f47749582fee66298fc3462195d0cfda554933d5b0022b99917542076c0bb55d1c61a75bc7d6d4c3f760ff3afe63a2` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T15E083340469A4211D18BAFF8A23F1EF7BF270EE0732EA49F16528571F58586BC59C24F` |
| SSDEEP | `1572864:2LdkLwcWwNVR8FFIABZI48z2Fi/S8JKBUmy+N5Xe6EfB7Q7:22MczVRgaABZVPArg/bXeB7Q7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_092_db576e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db576e0cfabd6fadfff0534e764a29d73e288939baad993cc07cc7a9cc67a633"
    family = "Vidar"
    file_name = "Installer.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:22:11"
  condition:
    hash.sha256(0, filesize) == "db576e0cfabd6fadfff0534e764a29d73e288939baad993cc07cc7a9cc67a633"
}
```

### Sample 93: `7dc2493b4e868083`

| Field | Value |
|---|---|
| SHA-256 | `7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08` |
| Family label | `CoinMiner` |
| File name | `7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:21:18` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20b5814bb246b612cce7d1f4d13669bd` |
| SHA-1 | `3ec6ff5df1c41fa320a8f1642896d5ef4ba95bb4` |
| SHA-256 | `7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08` |
| SHA3-384 | `d02441eb9cf1ecf731ed9357117f44f8ea8ae4ac28754fff98fda15f8fce99f80ef2cd210125a2c4501a7fb590729751` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1A13623AB6EC61074D042C7A8A627B03E717F3B948B753D1EB5DC6C095EAE908543E7C2` |
| SSDEEP | `98304:S6wpuZY8J31RXMc6AjFuT87/2f81yn1LnFE0GGMN7TX2d3gFuduT/IpTr:S6wkY8x/8cDf6fqyn1LnS0GGcT43gFet` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_093_7dc2493b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08"
    family = "CoinMiner"
    file_name = "7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:21:18"
  condition:
    hash.sha256(0, filesize) == "7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08"
}
```

### Sample 94: `edfd37d6b17c72ba`

| Field | Value |
|---|---|
| SHA-256 | `edfd37d6b17c72badfd6b1a42b9b2254ba799ae62274d1e944986a249e71a76d` |
| Family label | `RustyStealer` |
| File name | `ProjectFiles.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:19:46` |
| Reporter | `Alex_sev` |
| Tags | `coins, exe, loader, psw, rust, RustyStealer, stealer, tedy` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `569d640788db16fad0c52f294c079c0e` |
| SHA-1 | `89dc53c55864ab884af6571ecd5126d784a2fa3f` |
| SHA-256 | `edfd37d6b17c72badfd6b1a42b9b2254ba799ae62274d1e944986a249e71a76d` |
| SHA3-384 | `b304f0a685aed663563ccc7b9956e04a30f2f635f5e17eca689447b834f9bd41d5af1feea31a4f06764de87949360ae4` |
| IMPHASH | `dc23f35f4425f2ffdf21ac62a948976a` |
| TLSH | `T19EB6C0B876047DE6E66F437BDA96ACEC137626639A87A4CD4064B7C305A3371FF02805` |
| SSDEEP | `24576:Jfh7MBcHaOAl/Z90MBNrTLwuxKaleMs4CJ1OOqIlaZhsdBrTO2GV1bzt/VmCUiOL:ZhYBcHFKZ9dBNQ8fjjFM` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_094_edfd37d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edfd37d6b17c72badfd6b1a42b9b2254ba799ae62274d1e944986a249e71a76d"
    family = "RustyStealer"
    file_name = "ProjectFiles.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:19:46"
  condition:
    hash.sha256(0, filesize) == "edfd37d6b17c72badfd6b1a42b9b2254ba799ae62274d1e944986a249e71a76d"
}
```

### Sample 95: `b79826d8513bde75`

| Field | Value |
|---|---|
| SHA-256 | `b79826d8513bde7512e66836bc800366e0954d4514440369d711b2c857acefa9` |
| Family label | `unknown` |
| File name | `blpxart.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:17:38` |
| Reporter | `Alex_sev` |
| Tags | `antosandbox, dropper, exe, generic, kryptik, python, sysn` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `378228949e28ca52318c01149ff55a1a` |
| SHA-1 | `a00d6647019bd9fece907c47f3de0cd77b5c4349` |
| SHA-256 | `b79826d8513bde7512e66836bc800366e0954d4514440369d711b2c857acefa9` |
| SHA3-384 | `22d0af258a3c719b6aca104542c9d0ebcbca6e2fd3fba15e81d7d17deb384f529900619fba168322e2d1475b693aca1c` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1EBE63318BBA051FAE5B7403E58A3D812A2E372661712E6DB27D105A53F371F08E787F1` |
| SSDEEP | `393216:DI/YXEAphVtk510MjWSoiHVBSC7VzCIysvUYD:DI/YRphW10MiziHVB/ZzdbvUYD` |
| ICON-DHASH | `072961edb8f89a84` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_b79826d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b79826d8513bde7512e66836bc800366e0954d4514440369d711b2c857acefa9"
    family = "unknown"
    file_name = "blpxart.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:17:38"
  condition:
    hash.sha256(0, filesize) == "b79826d8513bde7512e66836bc800366e0954d4514440369d711b2c857acefa9"
}
```

### Sample 96: `01c6226686c808cb`

| Field | Value |
|---|---|
| SHA-256 | `01c6226686c808cb5f80bd35c3787ea9e783275a4476e35ddfee426ef48bd5c8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-22 16:16:50` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af9ce44135ea431fa7706fa9f66068ca` |
| SHA-1 | `2932019cda4e8fb56abde71f6769947b8ff1f4a8` |
| SHA-256 | `01c6226686c808cb5f80bd35c3787ea9e783275a4476e35ddfee426ef48bd5c8` |
| SHA3-384 | `a157e360b6650e2c95b9929e720481a5514c04e7531c185bb7c783f3bba0d939a8b2a053639a2a008ca226f2f6ab2df9` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T12A36ADA3FB6E8ADBE85A2436910118033BA43E566C7157577FA4A37E2F7DE40DD80B01` |
| SSDEEP | `24576:BF1eF2UYMcnyNWWa0G+KlAcqnQZQJ94ydPp24Mf7+mJhPkDA3XgTQGR7j75+f60l:BF122UYMcnyYsSADlJCfF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_01c62266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c6226686c808cb5f80bd35c3787ea9e783275a4476e35ddfee426ef48bd5c8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 16:16:50"
  condition:
    hash.sha256(0, filesize) == "01c6226686c808cb5f80bd35c3787ea9e783275a4476e35ddfee426ef48bd5c8"
}
```

### Sample 97: `82f756e01aca66ee`

| Field | Value |
|---|---|
| SHA-256 | `82f756e01aca66ee3ab70f2830dd8ae1d9b0702ffac240b7791206b07d9603ed` |
| Family label | `unknown` |
| File name | `Unutma.exe` |
| File type | `exe` |
| First seen | `2026-08-22 16:14:58` |
| Reporter | `Alex_sev` |
| Tags | `exe, generic, msil, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eb6cd8df064e204284fb9673a3251ce` |
| SHA-1 | `68aec22b03045d4d70e767a4d127af323a3baf29` |
| SHA-256 | `82f756e01aca66ee3ab70f2830dd8ae1d9b0702ffac240b7791206b07d9603ed` |
| SHA3-384 | `87e3f744a7654e46a0325d8d1a9d4aac3c05d8db0cea8276860114c1448baf55e65cc34c58d85c2e9e331b84990f94e7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T164E4AE153AF9C07AD2A60531CA6E57F1C1F693250F2385C72BC09E2C1E35AD5CA36E7A` |
| SSDEEP | `12288:NyyKdVnyNhXCV4EkP7AIfzNXZ0b5NrnkcAqIV0A1caRIqgH:NKvyNhXCV4E8BXAfrnkcAqU0AeH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_82f756e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82f756e01aca66ee3ab70f2830dd8ae1d9b0702ffac240b7791206b07d9603ed"
    family = "unknown"
    file_name = "Unutma.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:14:58"
  condition:
    hash.sha256(0, filesize) == "82f756e01aca66ee3ab70f2830dd8ae1d9b0702ffac240b7791206b07d9603ed"
}
```

### Sample 98: `d122152125d5a9bd`

| Field | Value |
|---|---|
| SHA-256 | `d122152125d5a9bd67d3ed73b7e5ef41ffbf6126d83831b0f44256156ab67d1a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-22 16:13:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff8f84c9d8618b4083d5808a9cb19c4a` |
| SHA-1 | `798c4829b110af0d4ac000ac40ecb3a5f62df39a` |
| SHA-256 | `d122152125d5a9bd67d3ed73b7e5ef41ffbf6126d83831b0f44256156ab67d1a` |
| SHA3-384 | `746c049a1221a43ea307794e1b2e2e28d1ac77fa6a832c24ddb56b12f586944ef3a350f8960b31fdcba86bd9cf57d046` |
| TLSH | `T127C28E966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:v8vCB+25j6es8Rp9FYpMSUpi+20qUpi+20YQX:v8l25JPd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_d1221521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d122152125d5a9bd67d3ed73b7e5ef41ffbf6126d83831b0f44256156ab67d1a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-22 16:13:32"
  condition:
    hash.sha256(0, filesize) == "d122152125d5a9bd67d3ed73b7e5ef41ffbf6126d83831b0f44256156ab67d1a"
}
```

### Sample 99: `6910ce0e2d85fdee`

| Field | Value |
|---|---|
| SHA-256 | `6910ce0e2d85fdeecf0789191ca1cb84e396854879d338de91630172379575dc` |
| Family label | `unknown` |
| File name | `main.mips64-n32` |
| File type | `elf` |
| First seen | `2026-08-22 15:56:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `507f932e0098143e065394c26b8e5c09` |
| SHA-1 | `c9b950407ab0f19a26d2868440be0fad295afa49` |
| SHA-256 | `6910ce0e2d85fdeecf0789191ca1cb84e396854879d338de91630172379575dc` |
| SHA3-384 | `72ff1e3e44e509b84c00bc1fb9a2f4e2ae818ed4af113973777eaeb67179e2a1b1a5a0768ee26084951275d102de3635` |
| TLSH | `T197D34C33B709AF63C67D52B40EF2CA39D6E1264109E39095A312DF1C7E352696C2EDE4` |
| SSDEEP | `1536:0Tz8/X+Rh5IFHvd32uUhOx8nyQ39csveooJF5PjEX2WmyRFZ3dArro:0AAmHl32NMx8pNcPJF5QmWp3+fo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_6910ce0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6910ce0e2d85fdeecf0789191ca1cb84e396854879d338de91630172379575dc"
    family = "unknown"
    file_name = "main.mips64-n32"
    file_type = "elf"
    first_seen = "2026-08-22 15:56:29"
  condition:
    hash.sha256(0, filesize) == "6910ce0e2d85fdeecf0789191ca1cb84e396854879d338de91630172379575dc"
}
```

### Sample 100: `e38069b9890b8c1e`

| Field | Value |
|---|---|
| SHA-256 | `e38069b9890b8c1e1763b5cb4c43981b98095f225779e16c83aad28c31ab5da5` |
| Family label | `unknown` |
| File name | `main.armv6-eabihf` |
| File type | `elf` |
| First seen | `2026-08-22 15:51:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e0c6b345c1259ca6b2c6a6f8affcdcb` |
| SHA-1 | `8e6d79e6f774de381385264cddc3c8e873494ccd` |
| SHA-256 | `e38069b9890b8c1e1763b5cb4c43981b98095f225779e16c83aad28c31ab5da5` |
| SHA3-384 | `04ea2b95d8fd47bc4372858fc1f96965c8dc710c84feb46e967a9bc07d29a72f141d1057d48e5dbdc2c7714cb3a19b24` |
| TLSH | `T1BC531998F844D675CBD031BAF61E02DD73130FA8D2EA31158E21AA3577FB9194E3B942` |
| SSDEEP | `1536:LSpo/On4Zq5MdlyLfmxXoJigEft3SOIO3d8q4EoYO8nveJM54QLJJRWUk0r:LS0SCoOJSHad84oXI4wWUR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_e38069b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e38069b9890b8c1e1763b5cb4c43981b98095f225779e16c83aad28c31ab5da5"
    family = "unknown"
    file_name = "main.armv6-eabihf"
    file_type = "elf"
    first_seen = "2026-08-22 15:51:56"
  condition:
    hash.sha256(0, filesize) == "e38069b9890b8c1e1763b5cb4c43981b98095f225779e16c83aad28c31ab5da5"
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
 * Generated: 2026-08-23T02:02:20.969838+00:00
 */

rule MalwareBazaar_unknown_001_2f579dc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f579dc80d3ba5d6bb786464049281528c326497f3bba3fc7689767a51987034"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 01:52:10"
  condition:
    hash.sha256(0, filesize) == "2f579dc80d3ba5d6bb786464049281528c326497f3bba3fc7689767a51987034"
}

rule MalwareBazaar_Mirai_002_22b80878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22b80878a53e54dda7d026318cb5a080cf34b12296cbf6ec885ebe55c330f446"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-23 01:34:13"
  condition:
    hash.sha256(0, filesize) == "22b80878a53e54dda7d026318cb5a080cf34b12296cbf6ec885ebe55c330f446"
}

rule MalwareBazaar_Mirai_003_3fb7b63a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb7b63a67396bec9b30a424e1136a3283e44bdbbabc47b1063fa44cbcaedb4c"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-23 01:33:16"
  condition:
    hash.sha256(0, filesize) == "3fb7b63a67396bec9b30a424e1136a3283e44bdbbabc47b1063fa44cbcaedb4c"
}

rule MalwareBazaar_unknown_004_73e99a29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232"
    family = "unknown"
    file_name = "73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232"
    file_type = "elf"
    first_seen = "2026-08-23 01:25:45"
  condition:
    hash.sha256(0, filesize) == "73e99a29a8b4c4f148937765e141f0db6359e75d4f401fd4b6c3836927937232"
}

rule MalwareBazaar_unknown_005_a6fbbdec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049"
    family = "unknown"
    file_name = "a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049"
    file_type = "elf"
    first_seen = "2026-08-23 01:16:54"
  condition:
    hash.sha256(0, filesize) == "a6fbbdec757b0fe91ea18dc3d9f7b379c18ca49eeef63afaea8da3c9385b1049"
}

rule MalwareBazaar_unknown_006_7ab43ecf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ab43ecf8d7bb6cdc9caa10ae48317d550a2f586ee5bcbc21065d3e9f629b03b"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 00:52:11"
  condition:
    hash.sha256(0, filesize) == "7ab43ecf8d7bb6cdc9caa10ae48317d550a2f586ee5bcbc21065d3e9f629b03b"
}

rule MalwareBazaar_RemusStealer_007_d63e7110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d63e71109ca0a304312ddc21def555dc9f73c71ddae8d7bcd6f94a189a2d8f0b"
    family = "RemusStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:39:44"
  condition:
    hash.sha256(0, filesize) == "d63e71109ca0a304312ddc21def555dc9f73c71ddae8d7bcd6f94a189a2d8f0b"
}

rule MalwareBazaar_unknown_008_aa504541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa5045411ba7da09339ea56b718435ed4db6970b77a2495750427c3e0983f4b5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:38:57"
  condition:
    hash.sha256(0, filesize) == "aa5045411ba7da09339ea56b718435ed4db6970b77a2495750427c3e0983f4b5"
}

rule MalwareBazaar_unknown_009_506461eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "506461eb9cdf0a488c4955188e47b317481932c7427c2994f83192b5f0c0bfd8"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:38:02"
  condition:
    hash.sha256(0, filesize) == "506461eb9cdf0a488c4955188e47b317481932c7427c2994f83192b5f0c0bfd8"
}

rule MalwareBazaar_unknown_010_7a3d2c38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a3d2c381a1f24002794f1bf5e7c7a2c73507a04a3741c40f6b7790983892e53"
    family = "unknown"
    file_name = "InstallerV29171x64_.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:35:50"
  condition:
    hash.sha256(0, filesize) == "7a3d2c381a1f24002794f1bf5e7c7a2c73507a04a3741c40f6b7790983892e53"
}

rule MalwareBazaar_unknown_011_98dc1ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98dc1ee834d166396ed8c20ec28f8defd7e8b127b5da6787dba6cba1abfb6f06"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-23 00:35:23"
  condition:
    hash.sha256(0, filesize) == "98dc1ee834d166396ed8c20ec28f8defd7e8b127b5da6787dba6cba1abfb6f06"
}

rule MalwareBazaar_unknown_012_85c67137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85c671370fdca9874db8f56081d8069be21ac0195af2267fc1bbea2d5739c3e6"
    family = "unknown"
    file_name = "dll"
    file_type = "exe"
    first_seen = "2026-08-23 00:35:01"
  condition:
    hash.sha256(0, filesize) == "85c671370fdca9874db8f56081d8069be21ac0195af2267fc1bbea2d5739c3e6"
}

rule MalwareBazaar_RemusStealer_013_0bb70961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bb70961853f4ce36650d296b7e945e0dda5a9ac2964e7a217cc35bbfbb1f253"
    family = "RemusStealer"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:33:55"
  condition:
    hash.sha256(0, filesize) == "0bb70961853f4ce36650d296b7e945e0dda5a9ac2964e7a217cc35bbfbb1f253"
}

rule MalwareBazaar_RemusStealer_014_fc055385
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc0553851d495ff5b6aba8c8d472f210f5c5d7ac05dcb56c27c61941eaa3b7ea"
    family = "RemusStealer"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:33:24"
  condition:
    hash.sha256(0, filesize) == "fc0553851d495ff5b6aba8c8d472f210f5c5d7ac05dcb56c27c61941eaa3b7ea"
}

rule MalwareBazaar_RemusStealer_015_0325bda3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0325bda37ee3ae51de29b706986ee9345d9e110b14cdcbde615dd11f959c085a"
    family = "RemusStealer"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:32:38"
  condition:
    hash.sha256(0, filesize) == "0325bda37ee3ae51de29b706986ee9345d9e110b14cdcbde615dd11f959c085a"
}

rule MalwareBazaar_RemusStealer_016_803af293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "803af293617ebe93de009614e1b029fa7bd07616e9c1dda0019fd6c69fe409e6"
    family = "RemusStealer"
    file_name = "517824218.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:31:04"
  condition:
    hash.sha256(0, filesize) == "803af293617ebe93de009614e1b029fa7bd07616e9c1dda0019fd6c69fe409e6"
}

rule MalwareBazaar_unknown_017_bfa315c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfa315c6c37f5bac2c5959d4e606d11ca1ae1a46e09b107e16983709e08538b3"
    family = "unknown"
    file_name = "UTODYIBG.msi"
    file_type = "msi"
    first_seen = "2026-08-23 00:29:44"
  condition:
    hash.sha256(0, filesize) == "bfa315c6c37f5bac2c5959d4e606d11ca1ae1a46e09b107e16983709e08538b3"
}

rule MalwareBazaar_unknown_018_c23360a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23360a78264383810f154246cc656e556bc89b3e1765ccc8970f016a53a1e05"
    family = "unknown"
    file_name = "b1.ps1"
    file_type = "ps1"
    first_seen = "2026-08-23 00:29:02"
  condition:
    hash.sha256(0, filesize) == "c23360a78264383810f154246cc656e556bc89b3e1765ccc8970f016a53a1e05"
}

rule MalwareBazaar_WannaCry_019_4772fcea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58"
    family = "WannaCry"
    file_name = "4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58"
    file_type = "exe"
    first_seen = "2026-08-23 00:15:27"
  condition:
    hash.sha256(0, filesize) == "4772fcead4cf5168b4e26bebfc94df0f0bef08ba80871c13f23dc30ba788fa58"
}

rule MalwareBazaar_unknown_020_6f295f2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f295f2aa87bdc8c3d44d7c71d642bfa3bf647293e0f72295b2a09100ad686df"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-23 00:09:49"
  condition:
    hash.sha256(0, filesize) == "6f295f2aa87bdc8c3d44d7c71d642bfa3bf647293e0f72295b2a09100ad686df"
}

rule MalwareBazaar_unknown_021_56935166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5693516606e4593095480afa2d0d2f8f7740a73f2789bf0d549fece3dada9d1c"
    family = "unknown"
    file_name = "SecuriteInfo.com.W64.Agent.ECKA.tr.25116.31718"
    file_type = "exe"
    first_seen = "2026-08-23 00:07:00"
  condition:
    hash.sha256(0, filesize) == "5693516606e4593095480afa2d0d2f8f7740a73f2789bf0d549fece3dada9d1c"
}

rule MalwareBazaar_unknown_022_8df8bd5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b"
    family = "unknown"
    file_name = "8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b.exe"
    file_type = "exe"
    first_seen = "2026-08-23 00:06:38"
  condition:
    hash.sha256(0, filesize) == "8df8bd5daa09bae7a780dec61921b14c83fd32709a68dc2b4c6480d138ebc07b"
}

rule MalwareBazaar_Vidar_023_6ded9017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135"
    family = "Vidar"
    file_name = "6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135.bin"
    file_type = "exe"
    first_seen = "2026-08-22 23:57:01"
  condition:
    hash.sha256(0, filesize) == "6ded9017cd432164a43b918aad495ca55bba80a5c0785db7f416276fbf85a135"
}

rule MalwareBazaar_unknown_024_7f97963c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0"
    family = "unknown"
    file_name = "7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0.exe"
    file_type = "exe"
    first_seen = "2026-08-22 23:56:49"
  condition:
    hash.sha256(0, filesize) == "7f97963c60595faf7dab56bfc0035a27a211296e86abad7f41563715312c11f0"
}

rule MalwareBazaar_unknown_025_65c7e0f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65c7e0f7c75a121f75e4232cfd8d2f1245f7efb70a903e7aaf4c556de5d34e7f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 23:52:11"
  condition:
    hash.sha256(0, filesize) == "65c7e0f7c75a121f75e4232cfd8d2f1245f7efb70a903e7aaf4c556de5d34e7f"
}

rule MalwareBazaar_Mirai_026_ece0710b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece0710b08cd1364f8b700bb3a1535a9ad9f132ce4c0ddc5c428a2a26207013d"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-22 23:28:16"
  condition:
    hash.sha256(0, filesize) == "ece0710b08cd1364f8b700bb3a1535a9ad9f132ce4c0ddc5c428a2a26207013d"
}

rule MalwareBazaar_Mirai_027_697a9e37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "697a9e37941c73e9116a3532ad6dd5627b7c0f4580ecd30960346a72f9d0f646"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-22 23:27:18"
  condition:
    hash.sha256(0, filesize) == "697a9e37941c73e9116a3532ad6dd5627b7c0f4580ecd30960346a72f9d0f646"
}

rule MalwareBazaar_unknown_028_9c2e3246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350"
    family = "unknown"
    file_name = "9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350.bin"
    file_type = "exe"
    first_seen = "2026-08-22 23:26:22"
  condition:
    hash.sha256(0, filesize) == "9c2e3246eb0507cdde787eec351cd822312bac1562c23afbdba299702d43d350"
}

rule MalwareBazaar_SnappyClient_029_11f3beea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f3beea1d73e12968f999281374286c16fa7649407ed5cbc068195142a631f4"
    family = "SnappyClient"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 23:15:55"
  condition:
    hash.sha256(0, filesize) == "11f3beea1d73e12968f999281374286c16fa7649407ed5cbc068195142a631f4"
}

rule MalwareBazaar_unknown_030_98bd4791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98bd4791d07de85c51338cd82bd68855631a1e3c17a9384195b2caddce5d4e51"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 22:52:10"
  condition:
    hash.sha256(0, filesize) == "98bd4791d07de85c51338cd82bd68855631a1e3c17a9384195b2caddce5d4e51"
}

rule MalwareBazaar_unknown_031_7c1e6384
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c1e63840584f07bd1e1436a02c7b65375fbf6c80ab289aaf2a5d16d63804737"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 22:30:54"
  condition:
    hash.sha256(0, filesize) == "7c1e63840584f07bd1e1436a02c7b65375fbf6c80ab289aaf2a5d16d63804737"
}

rule MalwareBazaar_unknown_032_62ee3a4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0"
    family = "unknown"
    file_name = "62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0.exe"
    file_type = "exe"
    first_seen = "2026-08-22 22:26:33"
  condition:
    hash.sha256(0, filesize) == "62ee3a4c45d77d8f65685307846669a9dfae14703d17a1f0a3d139d6354ea9a0"
}

rule MalwareBazaar_unknown_033_633980cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "633980cfc11ed6eddfb30571ecf45392073707f382cc24967fd91472498922aa"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 21:52:09"
  condition:
    hash.sha256(0, filesize) == "633980cfc11ed6eddfb30571ecf45392073707f382cc24967fd91472498922aa"
}

rule MalwareBazaar_Mirai_034_4cc6621a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc6621aa8311d15b172c95edeb7da76a7d3ab35f6ef0a74f3a0a5b85384865c"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-22 21:50:30"
  condition:
    hash.sha256(0, filesize) == "4cc6621aa8311d15b172c95edeb7da76a7d3ab35f6ef0a74f3a0a5b85384865c"
}

rule MalwareBazaar_Vidar_035_1d7c06f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45"
    family = "Vidar"
    file_name = "1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45.bin"
    file_type = "exe"
    first_seen = "2026-08-22 21:48:02"
  condition:
    hash.sha256(0, filesize) == "1d7c06f35efeffe0a9e614e88a0a718c82f64cdfb65f7598104cec612ce24a45"
}

rule MalwareBazaar_unknown_036_a3cd0bf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3cd0bf6fdcb213d1bfef9252a7b8dca39841a31cd104cd5c1b5a4cc8fca7484"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-22 21:28:19"
  condition:
    hash.sha256(0, filesize) == "a3cd0bf6fdcb213d1bfef9252a7b8dca39841a31cd104cd5c1b5a4cc8fca7484"
}

rule MalwareBazaar_unknown_037_2e2d2824
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e2d2824dfb7ed201e1e8e87ee43579738bbd53392cab6fcf603b8bad4e752d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 21:28:13"
  condition:
    hash.sha256(0, filesize) == "2e2d2824dfb7ed201e1e8e87ee43579738bbd53392cab6fcf603b8bad4e752d9"
}

rule MalwareBazaar_Mirai_038_1175a669
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1175a66971e9c4b23053162f29788b8f2bfc585a442474d75e72edd2c962b465"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-08-22 21:13:18"
  condition:
    hash.sha256(0, filesize) == "1175a66971e9c4b23053162f29788b8f2bfc585a442474d75e72edd2c962b465"
}

rule MalwareBazaar_unknown_039_277b3e17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "277b3e1711cb5b0287933b2d83f65129bf7168dc188a90cade77ff62dc08eb40"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-22 21:01:30"
  condition:
    hash.sha256(0, filesize) == "277b3e1711cb5b0287933b2d83f65129bf7168dc188a90cade77ff62dc08eb40"
}

rule MalwareBazaar_unknown_040_1d8db801
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8db801829975be3241657b4b270f9006dff5a1ebfa5fe2227a17febdd292b5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 20:52:11"
  condition:
    hash.sha256(0, filesize) == "1d8db801829975be3241657b4b270f9006dff5a1ebfa5fe2227a17febdd292b5"
}

rule MalwareBazaar_unknown_041_39291bc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39291bc66505cbf67c93116709b2e84ef3b5559d01ce461f37214e05bac09918"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-22 20:50:30"
  condition:
    hash.sha256(0, filesize) == "39291bc66505cbf67c93116709b2e84ef3b5559d01ce461f37214e05bac09918"
}

rule MalwareBazaar_Mirai_042_a16a7507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a16a75072235626bbae7449183964366f32b3e33bf8514aa83c9cedc4f5cafbe"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-22 20:27:28"
  condition:
    hash.sha256(0, filesize) == "a16a75072235626bbae7449183964366f32b3e33bf8514aa83c9cedc4f5cafbe"
}

rule MalwareBazaar_Mirai_043_966ddd38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "966ddd385a30176ae00f0b7a33d0a6d7b9c9527c613e6effe963573b3bb0b742"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-22 20:26:45"
  condition:
    hash.sha256(0, filesize) == "966ddd385a30176ae00f0b7a33d0a6d7b9c9527c613e6effe963573b3bb0b742"
}

rule MalwareBazaar_Mirai_044_27619f3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27619f3ff4786a56cd58697dbd6f7d58ee842aa13990afb0dfebb5ef376d359f"
    family = "Mirai"
    file_name = "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:30"
  condition:
    hash.sha256(0, filesize) == "27619f3ff4786a56cd58697dbd6f7d58ee842aa13990afb0dfebb5ef376d359f"
}

rule MalwareBazaar_Mirai_045_868b7eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "868b7eb4ff5b6a298035439f718dd871dc747b10dd60e92de10b1ec8bae602b0"
    family = "Mirai"
    file_name = "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:28"
  condition:
    hash.sha256(0, filesize) == "868b7eb4ff5b6a298035439f718dd871dc747b10dd60e92de10b1ec8bae602b0"
}

rule MalwareBazaar_Mirai_046_96ca231c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96ca231cc6d653b82f60d7403c09898b404d99e9178150d935c74653f44deeef"
    family = "Mirai"
    file_name = "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:26"
  condition:
    hash.sha256(0, filesize) == "96ca231cc6d653b82f60d7403c09898b404d99e9178150d935c74653f44deeef"
}

rule MalwareBazaar_Mirai_047_b3a7a811
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3a7a8115e04171760623daf10d46891ca3e68b7a0627ff2ac2d23d42825537c"
    family = "Mirai"
    file_name = "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:22"
  condition:
    hash.sha256(0, filesize) == "b3a7a8115e04171760623daf10d46891ca3e68b7a0627ff2ac2d23d42825537c"
}

rule MalwareBazaar_unknown_048_e89c5875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e89c58757fe395241043e948f135ba8056d5151c654cef1b64715d9993b67311"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-22 20:22:21"
  condition:
    hash.sha256(0, filesize) == "e89c58757fe395241043e948f135ba8056d5151c654cef1b64715d9993b67311"
}

rule MalwareBazaar_Mirai_049_db90a56b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586"
    family = "Mirai"
    file_name = "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:22:04"
  condition:
    hash.sha256(0, filesize) == "db90a56bc8875d2383214276d016185c31024bd47096763d06f503d008d7c586"
}

rule MalwareBazaar_Mirai_050_1b9d05b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5"
    family = "Mirai"
    file_name = "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:59"
  condition:
    hash.sha256(0, filesize) == "1b9d05b3a4bfdad200304586dfe842663ad30352460b6c27fa85f7763ac197c5"
}

rule MalwareBazaar_Mirai_051_d5ddf0ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f"
    family = "Mirai"
    file_name = "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:54"
  condition:
    hash.sha256(0, filesize) == "d5ddf0ea7ce424309816359ce32f90bb6b28780c7cfdab2c321570f3e4d15a9f"
}

rule MalwareBazaar_Mirai_052_749738fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4"
    family = "Mirai"
    file_name = "749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:50"
  condition:
    hash.sha256(0, filesize) == "749738fc07e21c7433a3524bdf2631342d1f8e7d9d0e3b264099e3cab7f686d4"
}

rule MalwareBazaar_Mirai_053_39ce8676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db"
    family = "Mirai"
    file_name = "39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:44"
  condition:
    hash.sha256(0, filesize) == "39ce8676c5aac2579fc8c329f02ac4a8ae00a2ecb9f8fd0b7102c8db1746e9db"
}

rule MalwareBazaar_Mirai_054_d4e955b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4"
    family = "Mirai"
    file_name = "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:21:35"
  condition:
    hash.sha256(0, filesize) == "d4e955b6b22af7d62d9102d5db1940a0ede1328fa8b73970a2f46d5f3236c9d4"
}

rule MalwareBazaar_Mirai_055_ce8e33a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce8e33a1d4a4b707f2b9e53cd061ef30ea5d719b81dee31f4248434cd033c1c0"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-22 20:18:26"
  condition:
    hash.sha256(0, filesize) == "ce8e33a1d4a4b707f2b9e53cd061ef30ea5d719b81dee31f4248434cd033c1c0"
}

rule MalwareBazaar_Mirai_056_381abe22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "381abe223780261b0c5316f43396b3bae7ce3f8030e287fc2558796a74762b34"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-22 20:17:48"
  condition:
    hash.sha256(0, filesize) == "381abe223780261b0c5316f43396b3bae7ce3f8030e287fc2558796a74762b34"
}

rule MalwareBazaar_Mirai_057_29efe86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29efe86a4d5fd6a5d9b58ce5b766f98218900352d1ea70029b12afeb831888f9"
    family = "Mirai"
    file_name = "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:17:22"
  condition:
    hash.sha256(0, filesize) == "29efe86a4d5fd6a5d9b58ce5b766f98218900352d1ea70029b12afeb831888f9"
}

rule MalwareBazaar_Mirai_058_ad58f068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad58f0683617d9046fa5d5e499073acf813b647d6ae56a2a031449068d95d39c"
    family = "Mirai"
    file_name = "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:17:19"
  condition:
    hash.sha256(0, filesize) == "ad58f0683617d9046fa5d5e499073acf813b647d6ae56a2a031449068d95d39c"
}

rule MalwareBazaar_Mirai_059_9f02fa45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303"
    family = "Mirai"
    file_name = "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:53"
  condition:
    hash.sha256(0, filesize) == "9f02fa45ccce73477cec37ddb8393412af225c51f415f472fe73ac22e10c9303"
}

rule MalwareBazaar_Mirai_060_eb2f8dce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104"
    family = "Mirai"
    file_name = "eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:48"
  condition:
    hash.sha256(0, filesize) == "eb2f8dce5497c7254c3af535926f5db8b59dfaa2731e93726d3e768cc57fb104"
}

rule MalwareBazaar_Mirai_061_66d8f187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709"
    family = "Mirai"
    file_name = "66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:45"
  condition:
    hash.sha256(0, filesize) == "66d8f18742afa0b917fef01c9e0a8ddfb768529e571051387ca3f227746ea709"
}

rule MalwareBazaar_Mirai_062_8239a5b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba"
    family = "Mirai"
    file_name = "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:41"
  condition:
    hash.sha256(0, filesize) == "8239a5b14056d6bced947074cf866dc3ffd14689c4bc47d7a80eb448bffde0ba"
}

rule MalwareBazaar_Mirai_063_5a35d262
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54"
    family = "Mirai"
    file_name = "5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54.elf"
    file_type = "elf"
    first_seen = "2026-08-22 20:16:37"
  condition:
    hash.sha256(0, filesize) == "5a35d2623dc83cc634c0b556274c2aebaa05ddda02a9bdf9e3824bd45b623a54"
}

rule MalwareBazaar_Mirai_064_3f36db0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f36db0edd3ef78b7c0b5025463e26fb7d7924fab5df47ef8c12839c71d061a0"
    family = "Mirai"
    file_name = "daredevil.sparc"
    file_type = "elf"
    first_seen = "2026-08-22 20:11:47"
  condition:
    hash.sha256(0, filesize) == "3f36db0edd3ef78b7c0b5025463e26fb7d7924fab5df47ef8c12839c71d061a0"
}

rule MalwareBazaar_Mirai_065_9fc5141c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fc5141ce0a056a769af034dbd3559f0f6ad0d09e1a71638bae19a5fadce4f63"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-22 20:08:48"
  condition:
    hash.sha256(0, filesize) == "9fc5141ce0a056a769af034dbd3559f0f6ad0d09e1a71638bae19a5fadce4f63"
}

rule MalwareBazaar_Mirai_066_0c866ff3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c866ff3e572339e40d5e53cbff06238ba8433f1d8a972cda512a39a7f450d37"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-22 20:08:10"
  condition:
    hash.sha256(0, filesize) == "0c866ff3e572339e40d5e53cbff06238ba8433f1d8a972cda512a39a7f450d37"
}

rule MalwareBazaar_Mirai_067_0fea0feb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fea0febf7bea085c21d58d55387a63d4f3f329c698d8642e21d510bb6828962"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-22 20:07:24"
  condition:
    hash.sha256(0, filesize) == "0fea0febf7bea085c21d58d55387a63d4f3f329c698d8642e21d510bb6828962"
}

rule MalwareBazaar_Mirai_068_66cd0fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66cd0fd624d086ab2e383eae1f97c14565e16de3d184a7e7555fe35b1d9c5d1b"
    family = "Mirai"
    file_name = "daredevil.arc"
    file_type = "elf"
    first_seen = "2026-08-22 20:04:24"
  condition:
    hash.sha256(0, filesize) == "66cd0fd624d086ab2e383eae1f97c14565e16de3d184a7e7555fe35b1d9c5d1b"
}

rule MalwareBazaar_RemusStealer_069_f48debf0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48debf0e99b16130594458c82205af33785a97f7d3df4cfed7cd30acd266b2d"
    family = "RemusStealer"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-22 19:52:15"
  condition:
    hash.sha256(0, filesize) == "f48debf0e99b16130594458c82205af33785a97f7d3df4cfed7cd30acd266b2d"
}

rule MalwareBazaar_unknown_070_c6f6ae0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6f6ae0ce1a2a2e8e5066b8a78edc06b8cc3586d5fd5716c257ca388d1d79655"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 19:52:09"
  condition:
    hash.sha256(0, filesize) == "c6f6ae0ce1a2a2e8e5066b8a78edc06b8cc3586d5fd5716c257ca388d1d79655"
}

rule MalwareBazaar_Mirai_071_782a55c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374"
    family = "Mirai"
    file_name = "782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:46:38"
  condition:
    hash.sha256(0, filesize) == "782a55c97a9a460550fa4f80b806cabca251990fd5b9aafd82bc6b4739ff3374"
}

rule MalwareBazaar_Mirai_072_882386fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2"
    family = "Mirai"
    file_name = "882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:46:34"
  condition:
    hash.sha256(0, filesize) == "882386fb50324ab5f35f2327c1cfdf4f9cc28189eab66727820d17f544ddb0e2"
}

rule MalwareBazaar_Mirai_073_0e3f4c84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa"
    family = "Mirai"
    file_name = "0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:41:42"
  condition:
    hash.sha256(0, filesize) == "0e3f4c846181031a64b8d820e8b163d2b5acc982ab6290f062baa2a955ddeaaa"
}

rule MalwareBazaar_Mirai_074_dfcfa816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc"
    family = "Mirai"
    file_name = "dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc.elf"
    file_type = "elf"
    first_seen = "2026-08-22 19:41:36"
  condition:
    hash.sha256(0, filesize) == "dfcfa81660a11bccc54d1c53adf025795e7473d51df00f38d42a635d04a29cfc"
}

rule MalwareBazaar_unknown_075_a88aa9d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710"
    family = "unknown"
    file_name = "a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710"
    file_type = "sh"
    first_seen = "2026-08-22 19:30:20"
  condition:
    hash.sha256(0, filesize) == "a88aa9d6b0dc066a618ee48e4b488a13a007e4e95512b8caa138c85b7d26b710"
}

rule MalwareBazaar_unknown_076_123c4292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331"
    family = "unknown"
    file_name = "123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331"
    file_type = "sh"
    first_seen = "2026-08-22 19:30:16"
  condition:
    hash.sha256(0, filesize) == "123c42921a7039265420ceb19517f0385c523a05f097d8191acd1aa8151d0331"
}

rule MalwareBazaar_unknown_077_3c667f62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c667f6229ea2acb192d3ee6982ff5f3a7638fdb33563ad7224d64afd95dd01a"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 18:52:09"
  condition:
    hash.sha256(0, filesize) == "3c667f6229ea2acb192d3ee6982ff5f3a7638fdb33563ad7224d64afd95dd01a"
}

rule MalwareBazaar_RemusStealer_078_20082d20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 18:49:21"
  condition:
    hash.sha256(0, filesize) == "20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e"
}

rule MalwareBazaar_unknown_079_c0909c44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0909c4463983aff4ea390f9da2c1428a1a05bddb4f6d3293c04af36fc0831a9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 18:45:11"
  condition:
    hash.sha256(0, filesize) == "c0909c4463983aff4ea390f9da2c1428a1a05bddb4f6d3293c04af36fc0831a9"
}

rule MalwareBazaar_unknown_080_59587568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6"
    family = "unknown"
    file_name = "5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6.exe"
    file_type = "exe"
    first_seen = "2026-08-22 18:01:32"
  condition:
    hash.sha256(0, filesize) == "5958756858b724c4759f8ba0dace15a9618f9b6b48e0ce5b7a5ad87e20c0c6f6"
}

rule MalwareBazaar_unknown_081_4ad1af0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ad1af0f9bec58fbbca457c4279e70b89cbe2084c75969107de09ef34e0df3f5"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 17:52:11"
  condition:
    hash.sha256(0, filesize) == "4ad1af0f9bec58fbbca457c4279e70b89cbe2084c75969107de09ef34e0df3f5"
}

rule MalwareBazaar_unknown_082_478a5d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e"
    family = "unknown"
    file_name = "478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e.exe"
    file_type = "exe"
    first_seen = "2026-08-22 17:51:35"
  condition:
    hash.sha256(0, filesize) == "478a5d81892f27b5d5fb05e4667d16d86ee2c8dee5882c52e4377123cd88526e"
}

rule MalwareBazaar_unknown_083_1cbad26e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead"
    family = "unknown"
    file_name = "1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead.exe"
    file_type = "exe"
    first_seen = "2026-08-22 17:36:34"
  condition:
    hash.sha256(0, filesize) == "1cbad26e560805b31cdd674e17de876d2791a2534e25c6b6c87547d762b92ead"
}

rule MalwareBazaar_unknown_084_650a4cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273"
    family = "unknown"
    file_name = "650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273.bin"
    file_type = "exe"
    first_seen = "2026-08-22 17:14:15"
  condition:
    hash.sha256(0, filesize) == "650a4cd183179db8538cd162826b1192177683eb94863b98791348e19c035273"
}

rule MalwareBazaar_AsyncRAT_085_9cfd1645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cfd1645a9ce589649c7821e75f72723a5e13d6dd3aab8a6bada7aa8d8651233"
    family = "AsyncRAT"
    file_name = "VIN88APP.exe"
    file_type = "exe"
    first_seen = "2026-08-22 17:02:21"
  condition:
    hash.sha256(0, filesize) == "9cfd1645a9ce589649c7821e75f72723a5e13d6dd3aab8a6bada7aa8d8651233"
}

rule MalwareBazaar_unknown_086_4b341417
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b3414176f27060a6730d09121dfad6f39fca4f9c5a9875b7ba597318af11dcf"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-22 16:52:10"
  condition:
    hash.sha256(0, filesize) == "4b3414176f27060a6730d09121dfad6f39fca4f9c5a9875b7ba597318af11dcf"
}

rule MalwareBazaar_Vidar_087_d8a25c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687"
    family = "Vidar"
    file_name = "d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687.bin"
    file_type = "exe"
    first_seen = "2026-08-22 16:35:25"
  condition:
    hash.sha256(0, filesize) == "d8a25c8e3928fe213f3d40f80f6bb75c3dc17da4d50655fd15bb1160c3f7e687"
}

rule MalwareBazaar_unknown_088_a5593326
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5593326022f9fa6306b62bc81e7833a719543510ba60bb0727cf5c0fba84181"
    family = "unknown"
    file_name = "Frostix.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:34:05"
  condition:
    hash.sha256(0, filesize) == "a5593326022f9fa6306b62bc81e7833a719543510ba60bb0727cf5c0fba84181"
}

rule MalwareBazaar_unknown_089_ea633607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea6336072689dc80c1031970337cd1d33bc29c924d65ad2c4088f624adaaee5f"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-08-22 16:32:13"
  condition:
    hash.sha256(0, filesize) == "ea6336072689dc80c1031970337cd1d33bc29c924d65ad2c4088f624adaaee5f"
}

rule MalwareBazaar_unknown_090_57e2a8f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57e2a8f9bd8e32dd98032761993df0bca2054343ff24bd6a6570fce93d0eccf0"
    family = "unknown"
    file_name = "setup_app_V8.15.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:24:46"
  condition:
    hash.sha256(0, filesize) == "57e2a8f9bd8e32dd98032761993df0bca2054343ff24bd6a6570fce93d0eccf0"
}

rule MalwareBazaar_unknown_091_084aa565
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "084aa5657fae525db8ec6a96d9953033529cdf4c3f3183663599190046110144"
    family = "unknown"
    file_name = "core-release.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:23:35"
  condition:
    hash.sha256(0, filesize) == "084aa5657fae525db8ec6a96d9953033529cdf4c3f3183663599190046110144"
}

rule MalwareBazaar_Vidar_092_db576e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db576e0cfabd6fadfff0534e764a29d73e288939baad993cc07cc7a9cc67a633"
    family = "Vidar"
    file_name = "Installer.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:22:11"
  condition:
    hash.sha256(0, filesize) == "db576e0cfabd6fadfff0534e764a29d73e288939baad993cc07cc7a9cc67a633"
}

rule MalwareBazaar_CoinMiner_093_7dc2493b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08"
    family = "CoinMiner"
    file_name = "7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:21:18"
  condition:
    hash.sha256(0, filesize) == "7dc2493b4e8680833bda7f854a2caf64743b8cf975fbd55b393636eef1867f08"
}

rule MalwareBazaar_RustyStealer_094_edfd37d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edfd37d6b17c72badfd6b1a42b9b2254ba799ae62274d1e944986a249e71a76d"
    family = "RustyStealer"
    file_name = "ProjectFiles.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:19:46"
  condition:
    hash.sha256(0, filesize) == "edfd37d6b17c72badfd6b1a42b9b2254ba799ae62274d1e944986a249e71a76d"
}

rule MalwareBazaar_unknown_095_b79826d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b79826d8513bde7512e66836bc800366e0954d4514440369d711b2c857acefa9"
    family = "unknown"
    file_name = "blpxart.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:17:38"
  condition:
    hash.sha256(0, filesize) == "b79826d8513bde7512e66836bc800366e0954d4514440369d711b2c857acefa9"
}

rule MalwareBazaar_unknown_096_01c62266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01c6226686c808cb5f80bd35c3787ea9e783275a4476e35ddfee426ef48bd5c8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-22 16:16:50"
  condition:
    hash.sha256(0, filesize) == "01c6226686c808cb5f80bd35c3787ea9e783275a4476e35ddfee426ef48bd5c8"
}

rule MalwareBazaar_unknown_097_82f756e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82f756e01aca66ee3ab70f2830dd8ae1d9b0702ffac240b7791206b07d9603ed"
    family = "unknown"
    file_name = "Unutma.exe"
    file_type = "exe"
    first_seen = "2026-08-22 16:14:58"
  condition:
    hash.sha256(0, filesize) == "82f756e01aca66ee3ab70f2830dd8ae1d9b0702ffac240b7791206b07d9603ed"
}

rule MalwareBazaar_unknown_098_d1221521
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d122152125d5a9bd67d3ed73b7e5ef41ffbf6126d83831b0f44256156ab67d1a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-22 16:13:32"
  condition:
    hash.sha256(0, filesize) == "d122152125d5a9bd67d3ed73b7e5ef41ffbf6126d83831b0f44256156ab67d1a"
}

rule MalwareBazaar_unknown_099_6910ce0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6910ce0e2d85fdeecf0789191ca1cb84e396854879d338de91630172379575dc"
    family = "unknown"
    file_name = "main.mips64-n32"
    file_type = "elf"
    first_seen = "2026-08-22 15:56:29"
  condition:
    hash.sha256(0, filesize) == "6910ce0e2d85fdeecf0789191ca1cb84e396854879d338de91630172379575dc"
}

rule MalwareBazaar_unknown_100_e38069b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e38069b9890b8c1e1763b5cb4c43981b98095f225779e16c83aad28c31ab5da5"
    family = "unknown"
    file_name = "main.armv6-eabihf"
    file_type = "elf"
    first_seen = "2026-08-22 15:51:56"
  condition:
    hash.sha256(0, filesize) == "e38069b9890b8c1e1763b5cb4c43981b98095f225779e16c83aad28c31ab5da5"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

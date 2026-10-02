# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-02

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 405 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 405 |
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 86 |
| Mirai | 8 |
| ConnectWise | 2 |
| RemoteManipulator | 1 |
| ValleyRAT | 1 |
| BlankGrabber | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| dll | 45 |
| elf | 24 |
| sh | 11 |
| exe | 10 |
| unknown | 4 |
| zip | 3 |
| msi | 2 |
| py | 1 |

## Per-Sample Analysis

### Sample 1: `6ed042d86dac44f7`

| Field | Value |
|---|---|
| SHA-256 | `6ed042d86dac44f704212ef9c846f7f65b8cec9988addac9f6edd17250be1fc5` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-02 05:41:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dbf499dbf379c5eb18d158ea1785a0e` |
| SHA-1 | `db673df33c5cbeb7109e4cf1e0caaa8f6d98f694` |
| SHA-256 | `6ed042d86dac44f704212ef9c846f7f65b8cec9988addac9f6edd17250be1fc5` |
| SHA3-384 | `f32e1ac8652e7f17f7bf968bd41126d3304cab16065401841a41ba358cc41ef453af67f4788802e9f9a9378642d4dd87` |
| TLSH | `T1B6345B42F5B2D6F0F35342B401AEA72F8F215915A0B7DF53EBD42D22E423964222B779` |
| TELFHASH | `t1b7416629dfb2be18b3b1e4921292c011397a3c2a92d57cb095d0577fac846c4049e91e` |
| SSDEEP | `6144:NgywE69ZM0A5YKEFu0FtvOb2U3eKupzq:vwE64mku9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_6ed042d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ed042d86dac44f704212ef9c846f7f65b8cec9988addac9f6edd17250be1fc5"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-02 05:41:48"
  condition:
    hash.sha256(0, filesize) == "6ed042d86dac44f704212ef9c846f7f65b8cec9988addac9f6edd17250be1fc5"
}
```

### Sample 2: `457ff62cb3e95fad`

| Field | Value |
|---|---|
| SHA-256 | `457ff62cb3e95fad075c1310859ef7d7c960ec35308c7e9b8b76dc3e1bc84c91` |
| Family label | `unknown` |
| File name | `457ff62cb3e95fad.bin` |
| File type | `unknown` |
| First seen | `2026-10-02 05:25:18` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8763bd034cdffc549c02ea9f95ad8055` |
| SHA-256 | `457ff62cb3e95fad075c1310859ef7d7c960ec35308c7e9b8b76dc3e1bc84c91` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_457ff62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "457ff62cb3e95fad075c1310859ef7d7c960ec35308c7e9b8b76dc3e1bc84c91"
    family = "unknown"
    file_name = "457ff62cb3e95fad.bin"
    file_type = "unknown"
    first_seen = "2026-10-02 05:25:18"
  condition:
    hash.sha256(0, filesize) == "457ff62cb3e95fad075c1310859ef7d7c960ec35308c7e9b8b76dc3e1bc84c91"
}
```

### Sample 3: `4bd1e37982b854d4`

| Field | Value |
|---|---|
| SHA-256 | `4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848` |
| Family label | `Mirai` |
| File name | `4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848` |
| File type | `elf` |
| First seen | `2026-10-02 05:17:48` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aeb0e0ac1430056182d3f26e5b1538a0` |
| SHA-1 | `c3672e3d09e45bc09a8ce6b0b6e856fb0814920b` |
| SHA-256 | `4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848` |
| SHA3-384 | `a38daaf32e0e4b911f83ca33adbb830077e17307384cf7d2d99dc246bc5a122645b6213d4d69ddc6e541a4351135b2d0` |
| TLSH | `T1A3C3188BFC81DE6946C0277BFE2E418A330327B4D1DF71539D141F28B68A94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJ4:T2s/gAWuboqsJ9xcJxspJBqQgTuaJ4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_4bd1e379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848"
    family = "Mirai"
    file_name = "4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848"
    file_type = "elf"
    first_seen = "2026-10-02 05:17:48"
  condition:
    hash.sha256(0, filesize) == "4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848"
}
```

### Sample 4: `043ebed69763576c`

| Field | Value |
|---|---|
| SHA-256 | `043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee` |
| Family label | `unknown` |
| File name | `043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee.bin` |
| File type | `unknown` |
| First seen | `2026-10-02 05:13:34` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3d5b68627f1126ea24df4e6754f26b2` |
| SHA-256 | `043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_043ebed6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee"
    family = "unknown"
    file_name = "043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee.bin"
    file_type = "unknown"
    first_seen = "2026-10-02 05:13:34"
  condition:
    hash.sha256(0, filesize) == "043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee"
}
```

### Sample 5: `f3016f7e967ace80`

| Field | Value |
|---|---|
| SHA-256 | `f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3` |
| Family label | `unknown` |
| File name | `f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3.exe` |
| File type | `exe` |
| First seen | `2026-10-02 05:13:29` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05c79741f371b3db9412f3d4652747ae` |
| SHA-1 | `1596171868a2d9fb34c818c6eedaa20dec4ac4b1` |
| SHA-256 | `f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3` |
| SHA3-384 | `07b7cced8536ffcfaa5bc32a477a360a7ff75ea38effe1a8a69a5d799005a2f6e654d30625e5d19730ab698ded114f67` |
| IMPHASH | `31255cad033271b7d1d8d38eb82eb60e` |
| TLSH | `T1CB148E19B7AA10FBE1779938C9514906FA737C524760AADF43900BB68F237E09E3E711` |
| SSDEEP | `3072:tKT3EcOkjUT3SJrKCqIFzkhEfIkQC1LfEtyHo6hEq0XKCmJjquVF3tO:tKT3EcOMGCx6hAI4l8mBquVZg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_f3016f7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3"
    family = "unknown"
    file_name = "f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3.exe"
    file_type = "exe"
    first_seen = "2026-10-02 05:13:29"
  condition:
    hash.sha256(0, filesize) == "f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3"
}
```

### Sample 6: `08809c9882e4e113`

| Field | Value |
|---|---|
| SHA-256 | `08809c9882e4e1137b2827a7431aaad833278fa186687ab737f8575b14c5d5b5` |
| Family label | `unknown` |
| File name | `eclipse.armv7l` |
| File type | `elf` |
| First seen | `2026-10-02 05:11:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfeb5e703db2cd87ed54d0ea31a806c5` |
| SHA-1 | `f088ffc728b48d3726434ccf92b6539ee01c0c30` |
| SHA-256 | `08809c9882e4e1137b2827a7431aaad833278fa186687ab737f8575b14c5d5b5` |
| SHA3-384 | `04b2c75ad364b18e3e0f8ed41eeadb1cb14396b617e3a11ec194c94058717b4e70cde8628948e9b529d1828a8b69c5e7` |
| TLSH | `T17FA42966E8419B51D5D12ABFFF6E824973131B78F3EE72119D195F3063CB88A0E3A502` |
| SSDEEP | `12288:VnSZINd2N8Lfs6vApWaSvNYU6NejfsauLymuFwmc4rYU:MZINjfBVm3d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_08809c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08809c9882e4e1137b2827a7431aaad833278fa186687ab737f8575b14c5d5b5"
    family = "unknown"
    file_name = "eclipse.armv7l"
    file_type = "elf"
    first_seen = "2026-10-02 05:11:52"
  condition:
    hash.sha256(0, filesize) == "08809c9882e4e1137b2827a7431aaad833278fa186687ab737f8575b14c5d5b5"
}
```

### Sample 7: `e7aeac7b5834cc74`

| Field | Value |
|---|---|
| SHA-256 | `e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-02 05:02:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac2d54c21f5d29e7c8c5f6185c5610f2` |
| SHA-1 | `2357b5aea297e14ae6e6ae5fabda6df6cba6a4df` |
| SHA-256 | `e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72` |
| SHA3-384 | `f94a1d41a5cb238561b3e6f11f94e2f863e9dd90f915ab7cf379d230305f45e7ce52f0cbdc4731ce8ba91d958995c20a` |
| TLSH | `T12EE36C03F5C19CFDC489D174875EC2A3EA71F89922256A9B27946E323F3EF61270D681` |
| TELFHASH | `t12f51dcb02e497588729b6716b30ade3ee877056200f575e8dc73adf4cd226810e524e2` |
| SSDEEP | `3072:dUNABeNS6UApzPXcQgGFrDK0Wsznva9izFSalbtl289dIb9g2Ipm6:dBeNSipT/DlWmvQqXlbW8PIb9g2aF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_e7aeac7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-02 05:02:56"
  condition:
    hash.sha256(0, filesize) == "e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72"
}
```

### Sample 8: `6713eedc768899e0`

| Field | Value |
|---|---|
| SHA-256 | `6713eedc768899e0e3a1ad096e242f17ad94b51760462459edf559c589a625db` |
| Family label | `Mirai` |
| File name | `eclipse.armv5l` |
| File type | `elf` |
| First seen | `2026-10-02 04:56:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d865fa8b0992b1b17da82b0efb919588` |
| SHA-1 | `3b4c60077fcf53b91b0b7188fdfb22a47e7d27ed` |
| SHA-256 | `6713eedc768899e0e3a1ad096e242f17ad94b51760462459edf559c589a625db` |
| SHA3-384 | `0cd958ffacca692ccedc9c5430a413da14ecf065b185018c24d11bcd7f2692ed626b6a5149a6a51542ac6d85e661e0f7` |
| TLSH | `T175A43A62F9419F56C6D12ABBFF5E824833135B78E2EE711299199F3033DB8960E3B141` |
| TELFHASH | `t1fdd02205801121e1979002f2c1ca23b32a29f2ba89ec380f1092af498fd3e08b22f412` |
| SSDEEP | `12288:Pgnbkijwgd8EnzH4nyT6G9LE6YHN7m041kth7PgOF:+xBXXZiNd5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_6713eedc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6713eedc768899e0e3a1ad096e242f17ad94b51760462459edf559c589a625db"
    family = "Mirai"
    file_name = "eclipse.armv5l"
    file_type = "elf"
    first_seen = "2026-10-02 04:56:49"
  condition:
    hash.sha256(0, filesize) == "6713eedc768899e0e3a1ad096e242f17ad94b51760462459edf559c589a625db"
}
```

### Sample 9: `06fffeea93435328`

| Field | Value |
|---|---|
| SHA-256 | `06fffeea93435328949a102e15496f92e4dddb66cdb8a351d7efb31e0a0b5049` |
| Family label | `unknown` |
| File name | `new.txt` |
| File type | `elf` |
| First seen | `2026-10-02 04:56:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c26ef04b89f6917b9067f69c95f71e1c` |
| SHA-1 | `462e3a547c5ba2605f7d967923a6eb652d677ae9` |
| SHA-256 | `06fffeea93435328949a102e15496f92e4dddb66cdb8a351d7efb31e0a0b5049` |
| SHA3-384 | `f1c2ca4d9ac9e463fb6b3be86332ae21773cade94e2535e6ef3e39fc1ded0ce3f89014eec699353e81461004c2c4be1d` |
| TLSH | `T1FEB32801F742EBB8E68308F5087ADB64FF354D1B023088EBF7D166B4B8A1A9154E755E` |
| TELFHASH | `t1a411c293c22179bbe1f094b9c1faf5b196774398aba89911d13efe321d46d80561a013` |
| SSDEEP | `1536:AVrNxG8giUnvzkgJaWdOFkRCfni290e7vmrAcWA+WdObWrzxe/T7vqfFzLRrl+3p:Ap68giUws+knSlGldL8/T7vqfvAzt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_06fffeea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06fffeea93435328949a102e15496f92e4dddb66cdb8a351d7efb31e0a0b5049"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-02 04:56:47"
  condition:
    hash.sha256(0, filesize) == "06fffeea93435328949a102e15496f92e4dddb66cdb8a351d7efb31e0a0b5049"
}
```

### Sample 10: `2dda0c1d9f63287c`

| Field | Value |
|---|---|
| SHA-256 | `2dda0c1d9f63287c19663780ba88e731b4530568a65d5886cfc6a416d805926e` |
| Family label | `unknown` |
| File name | `newisbest.exe` |
| File type | `exe` |
| First seen | `2026-10-02 04:53:33` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e1e3e81669617907fc3880c1b908af1` |
| SHA-1 | `cdc67f09c4d4695f553b9c58c4f2fb5677d94f64` |
| SHA-256 | `2dda0c1d9f63287c19663780ba88e731b4530568a65d5886cfc6a416d805926e` |
| SHA3-384 | `d2de76e48a15e58734a76f60c7bea87a6c0818bffec40b8fc67c39d61a5a445484bc9f401ea710d0ac6b25578a4bd3e6` |
| IMPHASH | `4b49920f3d33b96050c7242a43e673a7` |
| TLSH | `T19425188606B662B0F8DCAA7EDBE7A574F16C4C8804A31D3FD79E14D968701D064EFB09` |
| SSDEEP | `24576:RnTsL2Lw8BF/r55OLG+kiX5kbkeySj4A0p68e:RTyu/CpkimbxjaQ` |
| ICON-DHASH | `241a647551542a14` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_2dda0c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dda0c1d9f63287c19663780ba88e731b4530568a65d5886cfc6a416d805926e"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-10-02 04:53:33"
  condition:
    hash.sha256(0, filesize) == "2dda0c1d9f63287c19663780ba88e731b4530568a65d5886cfc6a416d805926e"
}
```

### Sample 11: `0cffc29fc64c22f9`

| Field | Value |
|---|---|
| SHA-256 | `0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443` |
| Family label | `ConnectWise` |
| File name | `0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443.exe` |
| File type | `exe` |
| First seen | `2026-10-02 04:52:45` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cae84627dbbeb527dd8e670a127a0cd` |
| SHA-1 | `c13b03e3d428b6f7f361db15a1d9559ca7ceb770` |
| SHA-256 | `0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443` |
| SHA3-384 | `ceded9e2c9b5d6a4a5d10bacdf7a7f5f784cd81ff8ddb3171ec4609f6aa936edb90dc9f75ff3191d70e9f5f035b26750` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T134D61211B3D6A5B6D0BF0639D87982A55675BC058B62C6EF53D4B92C2D32BC08E32373` |
| SSDEEP | `393216:p2xiFxbwpa7C02xiFxbwpaD2xiFxbwpag2xiFxbwpaE:4UFxMpaCfUFxMpxUFxMpmUFxMpz` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_011_0cffc29f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443"
    family = "ConnectWise"
    file_name = "0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443.exe"
    file_type = "exe"
    first_seen = "2026-10-02 04:52:45"
  condition:
    hash.sha256(0, filesize) == "0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443"
}
```

### Sample 12: `fff5c971e185d83a`

| Field | Value |
|---|---|
| SHA-256 | `fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee` |
| Family label | `unknown` |
| File name | `fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee` |
| File type | `dll` |
| First seen | `2026-10-02 04:44:10` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df2361e4cdff7d562d8f338d291ec6f2` |
| SHA-256 | `fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_fff5c971
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee"
    family = "unknown"
    file_name = "fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee"
    file_type = "dll"
    first_seen = "2026-10-02 04:44:10"
  condition:
    hash.sha256(0, filesize) == "fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee"
}
```

### Sample 13: `e55cbd5263a4b365`

| Field | Value |
|---|---|
| SHA-256 | `e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19` |
| Family label | `unknown` |
| File name | `e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19` |
| File type | `dll` |
| First seen | `2026-10-02 04:44:01` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `917622dd22d73f7c36f3af6a0eeb9a2b` |
| SHA-256 | `e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_e55cbd52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19"
    family = "unknown"
    file_name = "e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19"
    file_type = "dll"
    first_seen = "2026-10-02 04:44:01"
  condition:
    hash.sha256(0, filesize) == "e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19"
}
```

### Sample 14: `bd6ced0e07e43dd4`

| Field | Value |
|---|---|
| SHA-256 | `bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88` |
| Family label | `unknown` |
| File name | `bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:52` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8541e25bfbbad5844049581b6ccbb08e` |
| SHA-1 | `f0dbe865bc129b3a91be41460c253c1a5a913cf8` |
| SHA-256 | `bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88` |
| SHA3-384 | `47c0c18ae8d03357b81ab0a517e349d73011013505c80838291853589398a726d59b3e3811f965a0c4d42c24c0576ae0` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T18336602199C8E7C0D713A1B7477E46785A514094F3057B92B3B1AEE3E66B08F4EB02DE` |
| SSDEEP | `49152:SnjQqMSPbcBVQeRkRiwt/Zx+TDmg27RnWGj:+8qPoBhRkkGZxID527BWG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_bd6ced0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88"
    family = "unknown"
    file_name = "bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:52"
  condition:
    hash.sha256(0, filesize) == "bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88"
}
```

### Sample 15: `7f0789ce97f44dc4`

| Field | Value |
|---|---|
| SHA-256 | `7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd` |
| Family label | `unknown` |
| File name | `7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:43` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8512d1ed376d05cb59c1a60ca4fd84ea` |
| SHA-256 | `7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_7f0789ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd"
    family = "unknown"
    file_name = "7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:43"
  condition:
    hash.sha256(0, filesize) == "7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd"
}
```

### Sample 16: `7440d8eaa7a1eb49`

| Field | Value |
|---|---|
| SHA-256 | `7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce` |
| Family label | `unknown` |
| File name | `7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:35` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8809a6b7a2921ac5b91cfc9bf3f25935` |
| SHA-256 | `7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_7440d8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce"
    family = "unknown"
    file_name = "7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:35"
  condition:
    hash.sha256(0, filesize) == "7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce"
}
```

### Sample 17: `24b581123f36d8ae`

| Field | Value |
|---|---|
| SHA-256 | `24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f` |
| Family label | `unknown` |
| File name | `24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:27` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3cc8632dfd77026d7bb67f8013bc275` |
| SHA-256 | `24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_24b58112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f"
    family = "unknown"
    file_name = "24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:27"
  condition:
    hash.sha256(0, filesize) == "24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f"
}
```

### Sample 18: `5494465aae2857ce`

| Field | Value |
|---|---|
| SHA-256 | `5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b` |
| Family label | `unknown` |
| File name | `5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:19` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23e72b10beff2819141ea47ae9184870` |
| SHA-1 | `bca235139e6243492d6f5a0c0620cd89c6a6f72f` |
| SHA-256 | `5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b` |
| SHA3-384 | `753049328f3fb456db94b0622a450eee920f27af2950dce555bf42262a8a31fe70b30d6733f0541fa7709b1f916ec785` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T161360126F28194F5C46712B0401B1BFEAB78A4210F5F62DF7B408B5D2EA27D2D736A53` |
| SSDEEP | `49152:RnpELPbcBV6fI6dHRTzF1Pd+TSqTdX1xzJAqMujA7tv:1pAoBs1PdcSUxJAqMuk7l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_5494465a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b"
    family = "unknown"
    file_name = "5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:19"
  condition:
    hash.sha256(0, filesize) == "5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b"
}
```

### Sample 19: `93094569048b9cda`

| Field | Value |
|---|---|
| SHA-256 | `93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d` |
| Family label | `unknown` |
| File name | `93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:11` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01a82bdb67286d271f2d4f20d4d30eab` |
| SHA-256 | `93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_93094569
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d"
    family = "unknown"
    file_name = "93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:11"
  condition:
    hash.sha256(0, filesize) == "93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d"
}
```

### Sample 20: `b9ae285be3643a84`

| Field | Value |
|---|---|
| SHA-256 | `b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad` |
| Family label | `unknown` |
| File name | `b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad` |
| File type | `dll` |
| First seen | `2026-10-02 04:43:02` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `823849841596f10dc964340e58cfcc33` |
| SHA-256 | `b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_b9ae285b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad"
    family = "unknown"
    file_name = "b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:02"
  condition:
    hash.sha256(0, filesize) == "b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad"
}
```

### Sample 21: `82754b7e96e5e509`

| Field | Value |
|---|---|
| SHA-256 | `82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126` |
| Family label | `unknown` |
| File name | `82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:54` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d31d25eedd79f744b8a3d58888fd668b` |
| SHA-1 | `826f5143b089779c5917af9250ae75ef641d793f` |
| SHA-256 | `82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126` |
| SHA3-384 | `1cac776c43fcb265e6f70b3364b57d79eb1d7c831b4dc5b4c46711ee477b5ebd5bc0bb3c1b75d0904e8ba7f86cb80fa6` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1B0363364962DB1BCF0050EB04492859BABFB3C57B7BA5A1FCF8045660D83B5F9BC0E61` |
| SSDEEP | `98304:+DqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2x3:+DqPe1Cxcxk3ZAEUadzR8yc4x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_82754b7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126"
    family = "unknown"
    file_name = "82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:54"
  condition:
    hash.sha256(0, filesize) == "82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126"
}
```

### Sample 22: `2225462661583a82`

| Field | Value |
|---|---|
| SHA-256 | `2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795` |
| Family label | `unknown` |
| File name | `2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:45` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d8bd329ab433bbfe2f41fc7a0bc60d5` |
| SHA-256 | `2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_22254626
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795"
    family = "unknown"
    file_name = "2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:45"
  condition:
    hash.sha256(0, filesize) == "2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795"
}
```

### Sample 23: `88f6f20e3d2851ad`

| Field | Value |
|---|---|
| SHA-256 | `88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5` |
| Family label | `unknown` |
| File name | `88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:38` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43d1b7c9d0a2ad17457ef6199c16a6c6` |
| SHA-1 | `cc4fd6364fca15d642b12c6dc53aa823e4dca699` |
| SHA-256 | `88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5` |
| SHA3-384 | `8c641899f90f6f406306a5906db76f460a987cf4d55d371dc2c73dc02ba9b7893ebacc9c29ac57c6bf86ff71c586b68a` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T19136235531A8C0B4D103157044ABCB62F6B6BC2917BA694FBF904E3E3E63BA1E715B43` |
| SSDEEP | `49152:RnpEKUv9wC7+VQej/1INRx+TSqTdX1HkQo6SAARdhnv:1pyv+Fhz1aRxcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_88f6f20e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5"
    family = "unknown"
    file_name = "88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:38"
  condition:
    hash.sha256(0, filesize) == "88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5"
}
```

### Sample 24: `50d82407b6f0d36a`

| Field | Value |
|---|---|
| SHA-256 | `50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de` |
| Family label | `unknown` |
| File name | `50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:30` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b7fafd30a24fe05fb3c7a47a71e68ce` |
| SHA-256 | `50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_50d82407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de"
    family = "unknown"
    file_name = "50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:30"
  condition:
    hash.sha256(0, filesize) == "50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de"
}
```

### Sample 25: `749be61425d402c1`

| Field | Value |
|---|---|
| SHA-256 | `749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8` |
| Family label | `unknown` |
| File name | `749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:22` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9baf8ffbe84fdb05ad355f75d4ac73e4` |
| SHA-256 | `749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_749be614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8"
    family = "unknown"
    file_name = "749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:22"
  condition:
    hash.sha256(0, filesize) == "749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8"
}
```

### Sample 26: `3c5592c53301f894`

| Field | Value |
|---|---|
| SHA-256 | `3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f` |
| Family label | `unknown` |
| File name | `3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:14` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `494753ed4a622aab1b3ec4ea1c9615a7` |
| SHA-256 | `3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_3c5592c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f"
    family = "unknown"
    file_name = "3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:14"
  condition:
    hash.sha256(0, filesize) == "3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f"
}
```

### Sample 27: `6fb2331acaa1539c`

| Field | Value |
|---|---|
| SHA-256 | `6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c` |
| Family label | `unknown` |
| File name | `6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c` |
| File type | `dll` |
| First seen | `2026-10-02 04:42:05` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcf648f9ae3c25f2fa777d62944cc450` |
| SHA-256 | `6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_6fb2331a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c"
    family = "unknown"
    file_name = "6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:05"
  condition:
    hash.sha256(0, filesize) == "6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c"
}
```

### Sample 28: `54d4b7ac7bafcf65`

| Field | Value |
|---|---|
| SHA-256 | `54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e` |
| Family label | `unknown` |
| File name | `54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e` |
| File type | `dll` |
| First seen | `2026-10-02 04:41:57` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `106e21fb736cb4e7a18a1746ef18e03f` |
| SHA-256 | `54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_54d4b7ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e"
    family = "unknown"
    file_name = "54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e"
    file_type = "dll"
    first_seen = "2026-10-02 04:41:57"
  condition:
    hash.sha256(0, filesize) == "54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e"
}
```

### Sample 29: `c8a451d25d8e85fe`

| Field | Value |
|---|---|
| SHA-256 | `c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf` |
| Family label | `unknown` |
| File name | `c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf` |
| File type | `dll` |
| First seen | `2026-10-02 04:41:50` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5884415c71c9edba3761d502772ed017` |
| SHA-1 | `3c3e123e5ced58529742c2d25d2c823c86ea0218` |
| SHA-256 | `c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf` |
| SHA3-384 | `09699dd93cfca6a5178245f073e9fbd52baee3048c8a4b79f57f5276c9371275a5d998120021adbbbb5d89f9c348dd69` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T16F36122A366CD1BCC11A523160634A76EAB77CAA627D970F8B54CB560D13350BFB4F07` |
| SSDEEP | `12288:yvbLgPlu+QhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw:SbLgddQhfdmMSirYbcMNgef` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_c8a451d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf"
    family = "unknown"
    file_name = "c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf"
    file_type = "dll"
    first_seen = "2026-10-02 04:41:50"
  condition:
    hash.sha256(0, filesize) == "c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf"
}
```

### Sample 30: `05b644f9c8f87057`

| Field | Value |
|---|---|
| SHA-256 | `05b644f9c8f87057aeb24a64776600fe37547a65f052886e285222bdc5f0d90b` |
| Family label | `unknown` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-02 04:41:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `febf956d6246cf773f3c549856076882` |
| SHA-1 | `dd7b4404c35f2df3952a8ba983757172d525b668` |
| SHA-256 | `05b644f9c8f87057aeb24a64776600fe37547a65f052886e285222bdc5f0d90b` |
| SHA3-384 | `3ec0dacf3646f9f7cef19ccb5da67caf0faf653977d6111842ce02a18c5affb0220b6af311957829b894105238be8f78` |
| TLSH | `T1DE4429A6BC82E486C5D026BAFB6ED3C8334763F8D3DE3012DC06872565CE5990F3A655` |
| TELFHASH | `t10df0e5e4698de159f1c3a8d0f27ebd15877a634bff0a39460610b42d2c8b6d10512e17` |
| SSDEEP | `6144:2g/wpTU5bewmcVVKIh8KZqZ2vIKZBjJlu0kwYfB9+JyOwou+M:0U1ccVsIhtwDMBjJU5PJ9+lO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_05b644f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05b644f9c8f87057aeb24a64776600fe37547a65f052886e285222bdc5f0d90b"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-02 04:41:49"
  condition:
    hash.sha256(0, filesize) == "05b644f9c8f87057aeb24a64776600fe37547a65f052886e285222bdc5f0d90b"
}
```

### Sample 31: `0b8ef4e7cd3f29de`

| Field | Value |
|---|---|
| SHA-256 | `0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15` |
| Family label | `unknown` |
| File name | `0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15` |
| File type | `dll` |
| First seen | `2026-10-02 04:41:19` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad3affe36d36cc6b92dce9040232aa60` |
| SHA-256 | `0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_0b8ef4e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15"
    family = "unknown"
    file_name = "0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15"
    file_type = "dll"
    first_seen = "2026-10-02 04:41:19"
  condition:
    hash.sha256(0, filesize) == "0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15"
}
```

### Sample 32: `b60b5a142cbd64b6`

| Field | Value |
|---|---|
| SHA-256 | `b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae` |
| Family label | `unknown` |
| File name | `b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae` |
| File type | `elf` |
| First seen | `2026-10-02 04:35:42` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdd807f7b15ed561aad1cbbf33bc47b1` |
| SHA-256 | `b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_b60b5a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae"
    family = "unknown"
    file_name = "b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:42"
  condition:
    hash.sha256(0, filesize) == "b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae"
}
```

### Sample 33: `1a8cfff75c4f4b4b`

| Field | Value |
|---|---|
| SHA-256 | `1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a` |
| Family label | `unknown` |
| File name | `1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a` |
| File type | `elf` |
| First seen | `2026-10-02 04:35:32` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, Mirai, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bea53265b101132421d07be86274bcd` |
| SHA-256 | `1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_1a8cfff7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a"
    family = "unknown"
    file_name = "1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:32"
  condition:
    hash.sha256(0, filesize) == "1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a"
}
```

### Sample 34: `898080cee26a3c93`

| Field | Value |
|---|---|
| SHA-256 | `898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0` |
| Family label | `unknown` |
| File name | `898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0` |
| File type | `elf` |
| First seen | `2026-10-02 04:35:20` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfc9287594ded9e29b115a0fdf0be9f5` |
| SHA-256 | `898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_898080ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0"
    family = "unknown"
    file_name = "898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:20"
  condition:
    hash.sha256(0, filesize) == "898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0"
}
```

### Sample 35: `43820d92efd2b7c6`

| Field | Value |
|---|---|
| SHA-256 | `43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976` |
| Family label | `unknown` |
| File name | `43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976` |
| File type | `elf` |
| First seen | `2026-10-02 04:35:12` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b48cf7ac5130c6fe2cb75981ab4192e8` |
| SHA-256 | `43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_43820d92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976"
    family = "unknown"
    file_name = "43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:12"
  condition:
    hash.sha256(0, filesize) == "43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976"
}
```

### Sample 36: `e9813d6185b3ed64`

| Field | Value |
|---|---|
| SHA-256 | `e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0` |
| Family label | `unknown` |
| File name | `e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0` |
| File type | `elf` |
| First seen | `2026-10-02 04:34:50` |
| Reporter | `asandov` |
| Tags | `adbhoney, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5306217e13e624c5e065182c47df77f` |
| SHA-256 | `e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_e9813d61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0"
    family = "unknown"
    file_name = "e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0"
    file_type = "elf"
    first_seen = "2026-10-02 04:34:50"
  condition:
    hash.sha256(0, filesize) == "e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0"
}
```

### Sample 37: `4898d1f8e5e60450`

| Field | Value |
|---|---|
| SHA-256 | `4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70` |
| Family label | `unknown` |
| File name | `4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70` |
| File type | `unknown` |
| First seen | `2026-10-02 04:34:46` |
| Reporter | `asandov` |
| Tags | `adbhoney, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59396cd454fed65fe26c9bddbf3cd497` |
| SHA-256 | `4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_4898d1f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70"
    family = "unknown"
    file_name = "4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70"
    file_type = "unknown"
    first_seen = "2026-10-02 04:34:46"
  condition:
    hash.sha256(0, filesize) == "4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70"
}
```

### Sample 38: `729a2102bb790a12`

| Field | Value |
|---|---|
| SHA-256 | `729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c` |
| Family label | `unknown` |
| File name | `729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c` |
| File type | `sh` |
| First seen | `2026-10-02 04:34:43` |
| Reporter | `asandov` |
| Tags | `adbhoney, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1151fa1d2dc317ef6c18bd34e7404368` |
| SHA-256 | `729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_729a2102
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c"
    family = "unknown"
    file_name = "729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c"
    file_type = "sh"
    first_seen = "2026-10-02 04:34:43"
  condition:
    hash.sha256(0, filesize) == "729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c"
}
```

### Sample 39: `42f302e579fe04a9`

| Field | Value |
|---|---|
| SHA-256 | `42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9` |
| Family label | `unknown` |
| File name | `42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:40` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b16b3de85effd3d757cd5271a245c16` |
| SHA-1 | `d2127563784400eaaba89a8a501ed13cab3b8a6c` |
| SHA-256 | `42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9` |
| SHA3-384 | `d7a5a5a253d8ddc5ffce37600e2de96ba35d52acfe2a504a70a9f6a37572de9cf89245355d0a0195a3c6179ae6d77ce8` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1C3366B01D1E51AA0DAF25FF6266BDB10533A6E45C95BA66E1221A00F0C77F1CDDE2F2C` |
| SSDEEP | `49152:znAQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAA4AMEc:TDqPoBhz1aRxcSUDk36SAH5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_42f302e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9"
    family = "unknown"
    file_name = "42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:40"
  condition:
    hash.sha256(0, filesize) == "42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9"
}
```

### Sample 40: `545a5362e94dc1f0`

| Field | Value |
|---|---|
| SHA-256 | `545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739` |
| Family label | `unknown` |
| File name | `545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:33` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d4b50187712f75b7b6077044a88b1c8` |
| SHA-256 | `545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_545a5362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739"
    family = "unknown"
    file_name = "545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:33"
  condition:
    hash.sha256(0, filesize) == "545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739"
}
```

### Sample 41: `97bfa8beb89ba541`

| Field | Value |
|---|---|
| SHA-256 | `97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081` |
| Family label | `unknown` |
| File name | `97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:27` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8a3c54d399514110fa0fcc33db735ce` |
| SHA-256 | `97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_97bfa8be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081"
    family = "unknown"
    file_name = "97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:27"
  condition:
    hash.sha256(0, filesize) == "97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081"
}
```

### Sample 42: `c0902a637fa3edc7`

| Field | Value |
|---|---|
| SHA-256 | `c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55` |
| Family label | `unknown` |
| File name | `c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:20` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b48beaef654a5469c6521505e5decbd` |
| SHA-256 | `c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_c0902a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55"
    family = "unknown"
    file_name = "c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:20"
  condition:
    hash.sha256(0, filesize) == "c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55"
}
```

### Sample 43: `7f32fd534b1acbb4`

| Field | Value |
|---|---|
| SHA-256 | `7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78` |
| Family label | `unknown` |
| File name | `7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:14` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d5dcf131686627de70dc6afb0e9b5ff` |
| SHA-256 | `7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_7f32fd53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78"
    family = "unknown"
    file_name = "7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:14"
  condition:
    hash.sha256(0, filesize) == "7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78"
}
```

### Sample 44: `21d52f970117819d`

| Field | Value |
|---|---|
| SHA-256 | `21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0` |
| Family label | `unknown` |
| File name | `21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:08` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffe9ccaad1190c36b7df3b8bdcb45875` |
| SHA-256 | `21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_21d52f97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0"
    family = "unknown"
    file_name = "21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:08"
  condition:
    hash.sha256(0, filesize) == "21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0"
}
```

### Sample 45: `489d62f69e4336fd`

| Field | Value |
|---|---|
| SHA-256 | `489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71` |
| Family label | `unknown` |
| File name | `489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71` |
| File type | `dll` |
| First seen | `2026-10-02 04:34:01` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `095d83ee1494554d00b726cfddee494c` |
| SHA-256 | `489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_489d62f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71"
    family = "unknown"
    file_name = "489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:01"
  condition:
    hash.sha256(0, filesize) == "489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71"
}
```

### Sample 46: `4c99f251878a8712`

| Field | Value |
|---|---|
| SHA-256 | `4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a` |
| Family label | `unknown` |
| File name | `4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a` |
| File type | `dll` |
| First seen | `2026-10-02 04:33:55` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb1b335a3ec5809f0f5b9de43dfdf617` |
| SHA-256 | `4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_4c99f251
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a"
    family = "unknown"
    file_name = "4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:55"
  condition:
    hash.sha256(0, filesize) == "4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a"
}
```

### Sample 47: `c3f082d1dbd1b82a`

| Field | Value |
|---|---|
| SHA-256 | `c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e` |
| Family label | `unknown` |
| File name | `c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e` |
| File type | `dll` |
| First seen | `2026-10-02 04:33:49` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa369255b98dd1e7e6d686d891c3e481` |
| SHA-256 | `c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_c3f082d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e"
    family = "unknown"
    file_name = "c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:49"
  condition:
    hash.sha256(0, filesize) == "c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e"
}
```

### Sample 48: `f9f0e48a96f2ce21`

| Field | Value |
|---|---|
| SHA-256 | `f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1` |
| Family label | `unknown` |
| File name | `f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1` |
| File type | `dll` |
| First seen | `2026-10-02 04:33:43` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd28ee6b81646ca2aec9ed82a3d8ae8f` |
| SHA-256 | `f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_f9f0e48a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1"
    family = "unknown"
    file_name = "f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:43"
  condition:
    hash.sha256(0, filesize) == "f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1"
}
```

### Sample 49: `ec64f5d5ca51fa22`

| Field | Value |
|---|---|
| SHA-256 | `ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10` |
| Family label | `unknown` |
| File name | `ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10` |
| File type | `dll` |
| First seen | `2026-10-02 04:33:36` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `711a166b88ac297cc530b8140119841d` |
| SHA-1 | `f69522943dffe86f45f69af072e626a8dda42bd4` |
| SHA-256 | `ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10` |
| SHA3-384 | `d567eeb464e0756bec5ec2ec94abac14a210cb488b6fbb487a3efe5c3e668d217dbd1aec229a61fc86acefe182faff8c` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1FF363380656C61F8E0980BF4A4734A69B3B77C6C61BB4F5FE7C083651C43BC3AB98A55` |
| SSDEEP | `49152:unsEMSPbcBVQejJAARdhnv9AMEcaEau3R8yAH1plAH:afPoBh1AEdhv9593R8yAVp2H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_ec64f5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10"
    family = "unknown"
    file_name = "ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:36"
  condition:
    hash.sha256(0, filesize) == "ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10"
}
```

### Sample 50: `cfe1829b62a2bc42`

| Field | Value |
|---|---|
| SHA-256 | `cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838` |
| Family label | `unknown` |
| File name | `cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838` |
| File type | `dll` |
| First seen | `2026-10-02 04:33:30` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e3903e7bd8af72a61bc542d30cfa96a` |
| SHA-256 | `cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_cfe1829b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838"
    family = "unknown"
    file_name = "cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:30"
  condition:
    hash.sha256(0, filesize) == "cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838"
}
```

### Sample 51: `40c655fb966dcb8e`

| Field | Value |
|---|---|
| SHA-256 | `40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1` |
| Family label | `unknown` |
| File name | `40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1` |
| File type | `dll` |
| First seen | `2026-10-02 04:33:23` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45d3d09e4095a1b59a69051a4db3940c` |
| SHA-256 | `40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_40c655fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1"
    family = "unknown"
    file_name = "40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:23"
  condition:
    hash.sha256(0, filesize) == "40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1"
}
```

### Sample 52: `887cee8882a211aa`

| Field | Value |
|---|---|
| SHA-256 | `887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef` |
| Family label | `unknown` |
| File name | `887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef` |
| File type | `sh` |
| First seen | `2026-10-02 04:33:15` |
| Reporter | `asandov` |
| Tags | `cowrie, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b3245f758c57123dcff30875e6b7d0e` |
| SHA-256 | `887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_887cee88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef"
    family = "unknown"
    file_name = "887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef"
    file_type = "sh"
    first_seen = "2026-10-02 04:33:15"
  condition:
    hash.sha256(0, filesize) == "887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef"
}
```

### Sample 53: `704462fa073a2fb7`

| Field | Value |
|---|---|
| SHA-256 | `704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9` |
| Family label | `unknown` |
| File name | `704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9` |
| File type | `sh` |
| First seen | `2026-10-02 04:33:11` |
| Reporter | `asandov` |
| Tags | `cowrie, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92f49ec745b4fc49b3ac19240103be40` |
| SHA-256 | `704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_704462fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9"
    family = "unknown"
    file_name = "704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9"
    file_type = "sh"
    first_seen = "2026-10-02 04:33:11"
  condition:
    hash.sha256(0, filesize) == "704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9"
}
```

### Sample 54: `340a71927feeac94`

| Field | Value |
|---|---|
| SHA-256 | `340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972` |
| Family label | `unknown` |
| File name | `340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972` |
| File type | `dll` |
| First seen | `2026-10-02 04:32:53` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f48699de2a8ce87ea614449a2b42914d` |
| SHA-256 | `340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_340a7192
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972"
    family = "unknown"
    file_name = "340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972"
    file_type = "dll"
    first_seen = "2026-10-02 04:32:53"
  condition:
    hash.sha256(0, filesize) == "340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972"
}
```

### Sample 55: `a71878d240325a79`

| Field | Value |
|---|---|
| SHA-256 | `a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654` |
| Family label | `unknown` |
| File name | `a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654` |
| File type | `dll` |
| First seen | `2026-10-02 04:32:48` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d5e6896dab8ab1abb3f6141bb917d90` |
| SHA-256 | `a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_a71878d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654"
    family = "unknown"
    file_name = "a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654"
    file_type = "dll"
    first_seen = "2026-10-02 04:32:48"
  condition:
    hash.sha256(0, filesize) == "a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654"
}
```

### Sample 56: `abb34def49390567`

| Field | Value |
|---|---|
| SHA-256 | `abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023` |
| Family label | `unknown` |
| File name | `abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023` |
| File type | `elf` |
| First seen | `2026-10-02 04:32:39` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, Mirai, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3c870f82072f8ea86f8badd88d701e9` |
| SHA-256 | `abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_abb34def
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023"
    family = "unknown"
    file_name = "abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023"
    file_type = "elf"
    first_seen = "2026-10-02 04:32:39"
  condition:
    hash.sha256(0, filesize) == "abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023"
}
```

### Sample 57: `9b3fde5cad3037c0`

| Field | Value |
|---|---|
| SHA-256 | `9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3` |
| Family label | `unknown` |
| File name | `9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3` |
| File type | `elf` |
| First seen | `2026-10-02 04:32:29` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54d3ee022e7bb98fcb724c37ef5dd744` |
| SHA-256 | `9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_9b3fde5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3"
    family = "unknown"
    file_name = "9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3"
    file_type = "elf"
    first_seen = "2026-10-02 04:32:29"
  condition:
    hash.sha256(0, filesize) == "9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3"
}
```

### Sample 58: `0577adf4a25ca1c3`

| Field | Value |
|---|---|
| SHA-256 | `0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d` |
| Family label | `unknown` |
| File name | `0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d` |
| File type | `dll` |
| First seen | `2026-10-02 04:32:04` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00c9e54f5c2c31cf4bc2bb0a178712ec` |
| SHA-256 | `0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_0577adf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d"
    family = "unknown"
    file_name = "0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d"
    file_type = "dll"
    first_seen = "2026-10-02 04:32:04"
  condition:
    hash.sha256(0, filesize) == "0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d"
}
```

### Sample 59: `f64df3e33e654e73`

| Field | Value |
|---|---|
| SHA-256 | `f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309` |
| Family label | `unknown` |
| File name | `f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309` |
| File type | `unknown` |
| First seen | `2026-10-02 04:32:00` |
| Reporter | `asandov` |
| Tags | `dionaea, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2b2b97a2fde8ed2aeb53fdbe0bc870f` |
| SHA-256 | `f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_f64df3e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309"
    family = "unknown"
    file_name = "f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309"
    file_type = "unknown"
    first_seen = "2026-10-02 04:32:00"
  condition:
    hash.sha256(0, filesize) == "f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309"
}
```

### Sample 60: `2d3d59eb67ef2c95`

| Field | Value |
|---|---|
| SHA-256 | `2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318` |
| Family label | `unknown` |
| File name | `2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318` |
| File type | `dll` |
| First seen | `2026-10-02 04:31:58` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5521420b9ac552be0918796bb0b8273` |
| SHA-256 | `2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_2d3d59eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318"
    family = "unknown"
    file_name = "2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:58"
  condition:
    hash.sha256(0, filesize) == "2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318"
}
```

### Sample 61: `6b4882e140503454`

| Field | Value |
|---|---|
| SHA-256 | `6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94` |
| Family label | `unknown` |
| File name | `6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94` |
| File type | `dll` |
| First seen | `2026-10-02 04:31:55` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ba726799e89af42d8da35c502fb2d5d` |
| SHA-256 | `6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_6b4882e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94"
    family = "unknown"
    file_name = "6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:55"
  condition:
    hash.sha256(0, filesize) == "6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94"
}
```

### Sample 62: `dbcd1e680a9516f4`

| Field | Value |
|---|---|
| SHA-256 | `dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b` |
| Family label | `unknown` |
| File name | `dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b` |
| File type | `dll` |
| First seen | `2026-10-02 04:31:51` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a5652d603a9692907c95b45a0ecc104` |
| SHA-256 | `dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_dbcd1e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b"
    family = "unknown"
    file_name = "dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:51"
  condition:
    hash.sha256(0, filesize) == "dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b"
}
```

### Sample 63: `fa18d676b7bdba39`

| Field | Value |
|---|---|
| SHA-256 | `fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd` |
| Family label | `unknown` |
| File name | `fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd` |
| File type | `dll` |
| First seen | `2026-10-02 04:31:48` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fe956cf672bea58f5c447b769e1981c` |
| SHA-256 | `fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_fa18d676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd"
    family = "unknown"
    file_name = "fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:48"
  condition:
    hash.sha256(0, filesize) == "fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd"
}
```

### Sample 64: `318a05e0e97d6b49`

| Field | Value |
|---|---|
| SHA-256 | `318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03` |
| Family label | `unknown` |
| File name | `318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03` |
| File type | `dll` |
| First seen | `2026-10-02 04:31:44` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fffbb6074b52ce8d0bae47ac5a6a3b38` |
| SHA-256 | `318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_318a05e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03"
    family = "unknown"
    file_name = "318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:44"
  condition:
    hash.sha256(0, filesize) == "318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03"
}
```

### Sample 65: `6ffa1d6c99875db8`

| Field | Value |
|---|---|
| SHA-256 | `6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629` |
| Family label | `unknown` |
| File name | `6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629` |
| File type | `dll` |
| First seen | `2026-10-02 04:31:40` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b70c2b67b124c8ce26d2c8a37c07d01` |
| SHA-256 | `6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_6ffa1d6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629"
    family = "unknown"
    file_name = "6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:40"
  condition:
    hash.sha256(0, filesize) == "6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629"
}
```

### Sample 66: `8238a342a0f30e6a`

| Field | Value |
|---|---|
| SHA-256 | `8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6` |
| Family label | `unknown` |
| File name | `8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6` |
| File type | `elf` |
| First seen | `2026-10-02 04:31:36` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, Gafgyt, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6377ea756caf51efea65df7b5caf9ca2` |
| SHA-256 | `8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_8238a342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6"
    family = "unknown"
    file_name = "8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6"
    file_type = "elf"
    first_seen = "2026-10-02 04:31:36"
  condition:
    hash.sha256(0, filesize) == "8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6"
}
```

### Sample 67: `9f628b3fd279bbf6`

| Field | Value |
|---|---|
| SHA-256 | `9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6` |
| Family label | `unknown` |
| File name | `9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6` |
| File type | `elf` |
| First seen | `2026-10-02 04:31:31` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, Mirai, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb37334ba37f8840812f92da9ebfeee7` |
| SHA-256 | `9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9f628b3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6"
    family = "unknown"
    file_name = "9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6"
    file_type = "elf"
    first_seen = "2026-10-02 04:31:31"
  condition:
    hash.sha256(0, filesize) == "9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6"
}
```

### Sample 68: `f1d41d03b3376c40`

| Field | Value |
|---|---|
| SHA-256 | `f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd` |
| Family label | `unknown` |
| File name | `f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd` |
| File type | `dll` |
| First seen | `2026-10-02 04:30:50` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5840a9753ed8f90fbd7264c8db27c4b` |
| SHA-256 | `f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_f1d41d03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd"
    family = "unknown"
    file_name = "f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:50"
  condition:
    hash.sha256(0, filesize) == "f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd"
}
```

### Sample 69: `665cddac04e345ea`

| Field | Value |
|---|---|
| SHA-256 | `665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9` |
| Family label | `unknown` |
| File name | `665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9` |
| File type | `dll` |
| First seen | `2026-10-02 04:30:43` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ecca08445521f486fe9bff458817b2f` |
| SHA-256 | `665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_665cddac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9"
    family = "unknown"
    file_name = "665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:43"
  condition:
    hash.sha256(0, filesize) == "665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9"
}
```

### Sample 70: `ec9cbd6f5375401b`

| Field | Value |
|---|---|
| SHA-256 | `ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7` |
| Family label | `unknown` |
| File name | `ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7` |
| File type | `dll` |
| First seen | `2026-10-02 04:30:36` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf8133a2e32fec790224859d729f0b14` |
| SHA-256 | `ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_ec9cbd6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7"
    family = "unknown"
    file_name = "ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:36"
  condition:
    hash.sha256(0, filesize) == "ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7"
}
```

### Sample 71: `7331826168a261cb`

| Field | Value |
|---|---|
| SHA-256 | `7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e` |
| Family label | `unknown` |
| File name | `7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e` |
| File type | `dll` |
| First seen | `2026-10-02 04:30:31` |
| Reporter | `asandov` |
| Tags | `dionaea, dll, exe, honeypot, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c7ed12db0a175975f87191637e2f4c7` |
| SHA-256 | `7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_73318261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e"
    family = "unknown"
    file_name = "7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:31"
  condition:
    hash.sha256(0, filesize) == "7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e"
}
```

### Sample 72: `29a723d93e9541ea`

| Field | Value |
|---|---|
| SHA-256 | `29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2` |
| Family label | `unknown` |
| File name | `29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2` |
| File type | `elf` |
| First seen | `2026-10-02 04:30:22` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5aa9c5347d483cad60b5030eb1a7ebe7` |
| SHA-256 | `29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_29a723d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2"
    family = "unknown"
    file_name = "29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2"
    file_type = "elf"
    first_seen = "2026-10-02 04:30:22"
  condition:
    hash.sha256(0, filesize) == "29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2"
}
```

### Sample 73: `037440f3874a99bc`

| Field | Value |
|---|---|
| SHA-256 | `037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434` |
| Family label | `unknown` |
| File name | `037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434` |
| File type | `elf` |
| First seen | `2026-10-02 04:30:13` |
| Reporter | `asandov` |
| Tags | `cowrie, elf, honeypot, Mirai, xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a8b962897a6d5fb6e8ae8e83f508eb8` |
| SHA-256 | `037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_037440f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434"
    family = "unknown"
    file_name = "037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434"
    file_type = "elf"
    first_seen = "2026-10-02 04:30:13"
  condition:
    hash.sha256(0, filesize) == "037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434"
}
```

### Sample 74: `c80debfcc13b6b9d`

| Field | Value |
|---|---|
| SHA-256 | `c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a` |
| Family label | `unknown` |
| File name | `c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a.bin` |
| File type | `zip` |
| First seen | `2026-10-02 04:28:33` |
| Reporter | `Tuxxin` |
| Tags | `signed, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7440cf3223d8aed1cea5c179d0c1574` |
| SHA-1 | `520c344d36f7cf67f45c5f1449de15d333601e31` |
| SHA-256 | `c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a` |
| SHA3-384 | `fb6f2565186313c5c15bbf396d2a0922511b5eaa9d16c38c9092c1fb78985c7c92e4fdfac329ce555539659ae513c361` |
| TLSH | `T11666334BBEC1370CF43DC9B4B8FF61E8E05592539111E7AA0792AA4421757C8DB2AFC9` |
| SSDEEP | `196608:mvHtFqY0gQpmoZvQQntcZLUWo3Q2j6ZH8wJ2mtRDAO721:6HtbLHQntc+ZQ22l8m2mzBK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_c80debfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a"
    family = "unknown"
    file_name = "c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a.bin"
    file_type = "zip"
    first_seen = "2026-10-02 04:28:33"
  condition:
    hash.sha256(0, filesize) == "c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a"
}
```

### Sample 75: `7bac68e19b279f76`

| Field | Value |
|---|---|
| SHA-256 | `7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d` |
| Family label | `Mirai` |
| File name | `7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d` |
| File type | `elf` |
| First seen | `2026-10-02 04:17:15` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9272afdf76d96abde48bde8e522bcf4` |
| SHA-1 | `edc5da6acbe1ded52892e72a50c193bef20b7380` |
| SHA-256 | `7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d` |
| SHA3-384 | `8e96c522eec1b2563bc4dd310bbf3d1efa5178626a398b74b936ca7e77e0ea1d846e8e3be35eb4ae5db4f1788278c855` |
| TLSH | `T107543A8AFD81AE25D5C122BBFE2F428A331317B8D2EB71129D145F2476CA94F0F7A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_7bac68e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d"
    family = "Mirai"
    file_name = "7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d"
    file_type = "elf"
    first_seen = "2026-10-02 04:17:15"
  condition:
    hash.sha256(0, filesize) == "7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d"
}
```

### Sample 76: `ebe315f58648a2d4`

| Field | Value |
|---|---|
| SHA-256 | `ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7` |
| Family label | `RemoteManipulator` |
| File name | `ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7.msi` |
| File type | `msi` |
| First seen | `2026-10-02 04:12:58` |
| Reporter | `Tuxxin` |
| Tags | `msi, RemoteManipulator` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c980150b7c49ed01fef8cefcfb2ae752` |
| SHA-1 | `6ae2018c4cc315347ed23a918783d1371dcc7f5c` |
| SHA-256 | `ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7` |
| SHA3-384 | `98773b919b65a437834b8840f982cf809a101eae1c684f744b14d9dabe8067d44301bdad2a64db23757554fff7978fbf` |
| TLSH | `T1953723C2F751042AFD9F077296FB4E1C493AEDBD9B60234B69E0730925B3D92096B493` |
| SSDEEP | `393216:6LfK/LS1/Lgntpvw2D3r4qg8RvPNJrHS7i9CPq7E0YIpUx9gZjpWQma9BKyIo9Xb:yIQy+qRvPn2+CP+EUE9vFo9L` |

#### Technical Assessment

- The sample is tracked as `RemoteManipulator` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemoteManipulator_076_ebe315f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7"
    family = "RemoteManipulator"
    file_name = "ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7.msi"
    file_type = "msi"
    first_seen = "2026-10-02 04:12:58"
  condition:
    hash.sha256(0, filesize) == "ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7"
}
```

### Sample 77: `bfad966f4b09e89b`

| Field | Value |
|---|---|
| SHA-256 | `bfad966f4b09e89b20d72d2fa16d2bc0a305297621d2eb88f4d8768d7ed92633` |
| Family label | `unknown` |
| File name | `Nx_5936.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:10:20` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19786b7d81f8733ee430c1654b401622` |
| SHA-1 | `5f99e974e58b4f53771b28f75c256ae7279919da` |
| SHA-256 | `bfad966f4b09e89b20d72d2fa16d2bc0a305297621d2eb88f4d8768d7ed92633` |
| SHA3-384 | `1c70a1c8067184e989576169c3d2df249f6ae7b7b8c03f40834329ca51244737b6b2368be4393a03bf7d1baefe474694` |
| TLSH | `T1E161FE9C9457DEE83EEA4E39F12E41001847DF6FB4753CA48643BDBF80A92C48424BA9` |
| SSDEEP | `96:tuVlrqP7wjufeurNXaiTso/Lsr1rHNCDS810Ohh0r5rl6:d7EweF6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_bfad966f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfad966f4b09e89b20d72d2fa16d2bc0a305297621d2eb88f4d8768d7ed92633"
    family = "unknown"
    file_name = "Nx_5936.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:10:20"
  condition:
    hash.sha256(0, filesize) == "bfad966f4b09e89b20d72d2fa16d2bc0a305297621d2eb88f4d8768d7ed92633"
}
```

### Sample 78: `c69576b1daa12465`

| Field | Value |
|---|---|
| SHA-256 | `c69576b1daa1246563e2391f84ad603c6fba454adc363146712a2e77f7b09510` |
| Family label | `unknown` |
| File name | `Nx_zD.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:10:03` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b1e905016222d7707b1945b34b3f789` |
| SHA-1 | `af4c767de5325d0af577c18f77be9e77ecba8092` |
| SHA-256 | `c69576b1daa1246563e2391f84ad603c6fba454adc363146712a2e77f7b09510` |
| SHA3-384 | `19c5175e3aebce601a08a7a0649022c860fc72ef1d4d66aaee9f80f25ed4ccad9686c8f3c55673023f477224b46bd4b1` |
| TLSH | `T12E61019C9457DDD8BEEA8FB5F12A41001E5BFEBBE4753CA48643F8BD80592C40424FA1` |
| SSDEEP | `96:tuVlrqPuwWuKburkdal0s7Y/sr2r0E9/S1q07ej0rAr+6:dutRbI6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_c69576b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c69576b1daa1246563e2391f84ad603c6fba454adc363146712a2e77f7b09510"
    family = "unknown"
    file_name = "Nx_zD.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:10:03"
  condition:
    hash.sha256(0, filesize) == "c69576b1daa1246563e2391f84ad603c6fba454adc363146712a2e77f7b09510"
}
```

### Sample 79: `6ce6b4ebd1a25b97`

| Field | Value |
|---|---|
| SHA-256 | `6ce6b4ebd1a25b971fcc9e1b8ef8ff00d2aed3b5117b3799bd1943c4400f9fbd` |
| Family label | `unknown` |
| File name | `Nx_7508.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:09:56` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04a17846ab2e9305ad06095dc9586540` |
| SHA-1 | `7f5ce872fc798b1c46ce72125f40c75d60297c21` |
| SHA-256 | `6ce6b4ebd1a25b971fcc9e1b8ef8ff00d2aed3b5117b3799bd1943c4400f9fbd` |
| SHA3-384 | `8e3eda3c7e3fd336215d9d55e9e58c3fc0681103c5c97a097f9aba15bb51ab2595a121faf4f2c61f63cf3ae03e2d8fd3` |
| TLSH | `T12271DFACA4979DD93EEA4E36F12EC0102C87DE9B64797EE04643B4FD805D2C62464AA1` |
| SSDEEP | `96:tuVxr4t7fMNoNrjwNynyIaxBxIs1r1Isr8rr8IQ/Is0r0iSHk0pg0r6r1T0yU6:R7Ei5wCyL/dJIUT/8AN6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_6ce6b4eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ce6b4ebd1a25b971fcc9e1b8ef8ff00d2aed3b5117b3799bd1943c4400f9fbd"
    family = "unknown"
    file_name = "Nx_7508.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:56"
  condition:
    hash.sha256(0, filesize) == "6ce6b4ebd1a25b971fcc9e1b8ef8ff00d2aed3b5117b3799bd1943c4400f9fbd"
}
```

### Sample 80: `223edab12979b91a`

| Field | Value |
|---|---|
| SHA-256 | `223edab12979b91a01a53519fbfb52a97f772ac50ae6cc34bfde7a784306da30` |
| Family label | `unknown` |
| File name | `Nx_5100.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:09:50` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f1d7acc69b20961376e401ec224d7d5` |
| SHA-1 | `1050cc0d60d121a17bbf56a3cead8450ceeb0090` |
| SHA-256 | `223edab12979b91a01a53519fbfb52a97f772ac50ae6cc34bfde7a784306da30` |
| SHA3-384 | `c4015cc1303f30d0f5f75cf1a0ed6bdfbbf786ad92b4d1200a3e01edf7b54375a95deaac43bf5621fadbe313428f4719` |
| TLSH | `T18761CCACA457DDD47FFD8E36F12A41011A47DF5B64BA3CE44783B8AE805D2C41424BA9` |
| SSDEEP | `96:tuVlrqPWwOuSnurEpaNcsjwLsrWrUI5LSNC0TGD0rgre6:dWNhnw6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_223edab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "223edab12979b91a01a53519fbfb52a97f772ac50ae6cc34bfde7a784306da30"
    family = "unknown"
    file_name = "Nx_5100.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:50"
  condition:
    hash.sha256(0, filesize) == "223edab12979b91a01a53519fbfb52a97f772ac50ae6cc34bfde7a784306da30"
}
```

### Sample 81: `7f0c6678d94bed94`

| Field | Value |
|---|---|
| SHA-256 | `7f0c6678d94bed94ddd2369bb5d59ead44fb2777dbb1ca27d86143f3cf73e1b8` |
| Family label | `unknown` |
| File name | `Nx_8507.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:09:44` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `073cef07cce6c05352b4ff4ab66dfd40` |
| SHA-1 | `aaa21ed14f41c2fc9981c92f7e32cf6d2dca92cb` |
| SHA-256 | `7f0c6678d94bed94ddd2369bb5d59ead44fb2777dbb1ca27d86143f3cf73e1b8` |
| SHA3-384 | `17481438717b8932a5fcf58807939b7af788ef96028a442750d9b8a2461cce0fc0bc30dc3d59628f63a07e53e2b0d4b0` |
| TLSH | `T15B612EACA067EDD93EFA4E39F32E40001847DE5F64B53EA4564BF8BD806C2C40624BE1` |
| SSDEEP | `96:tuVlrqPWweuaXurwJa9MsrI3srarwYpDS9S0rur0r0ri6:dWBNXs6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_7f0c6678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f0c6678d94bed94ddd2369bb5d59ead44fb2777dbb1ca27d86143f3cf73e1b8"
    family = "unknown"
    file_name = "Nx_8507.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:44"
  condition:
    hash.sha256(0, filesize) == "7f0c6678d94bed94ddd2369bb5d59ead44fb2777dbb1ca27d86143f3cf73e1b8"
}
```

### Sample 82: `f878eccf4b300f80`

| Field | Value |
|---|---|
| SHA-256 | `f878eccf4b300f8085ceb866a2f71aed10428109e2cb89079a685699c6ef0941` |
| Family label | `unknown` |
| File name | `nx_verify-iteration-3.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:09:39` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ac325d6bc66ee68d2bf5804462a339b` |
| SHA-1 | `91879d05b5d15dfb81c7dfb2a5d5dc8cb3aaf7f0` |
| SHA-256 | `f878eccf4b300f8085ceb866a2f71aed10428109e2cb89079a685699c6ef0941` |
| SHA3-384 | `a46c74384e731379db8ebcafaf3bf8e0ac50975aa833e7301ed389b01b9f92889376121cd8db5c9426af6067bfb57729` |
| TLSH | `T12B11659DA0835DCB2EFE0EB9322BD5102146C32F591B2DD68B4371EE10992CC6298AF1` |
| SSDEEP | `24:tu61823AMxm+JAMxu90p5AMxT8J18Il9lUpWflV838rlzkaFl:tuU8qGqOup5z8D8IXGpWfX838rB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_f878eccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f878eccf4b300f8085ceb866a2f71aed10428109e2cb89079a685699c6ef0941"
    family = "unknown"
    file_name = "nx_verify-iteration-3.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:39"
  condition:
    hash.sha256(0, filesize) == "f878eccf4b300f8085ceb866a2f71aed10428109e2cb89079a685699c6ef0941"
}
```

### Sample 83: `7bfdc8b959ef92ef`

| Field | Value |
|---|---|
| SHA-256 | `7bfdc8b959ef92ef35cb9eb74f9641096e74508061be37effe74abdb5435408e` |
| Family label | `unknown` |
| File name | `nx_verify-iteration-2.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:09:33` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e11605454f471dc41edab986a3a1e69` |
| SHA-1 | `b3070a063ab7d99a53ad6b5f7bfed181f3770530` |
| SHA-256 | `7bfdc8b959ef92ef35cb9eb74f9641096e74508061be37effe74abdb5435408e` |
| SHA3-384 | `4648050e5dd7b1b7d5890f04ebaee85815f01a55e113b4b01922bb8ef00c6e5ae54f53e8e735178cdc1c4d3fad34c248` |
| TLSH | `T11FF05C9D50839EC71EFA0EFA12B7D6107141D29BD54B6CDB4B0331AD20181CC32649BD` |
| SSDEEP | `12:thp4P6xL8WTzwId4sBOw0w8EBOwIi8WTHBDlR+d9a9ef7HsV+GLH:tu6181C0py18IlQknLH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_7bfdc8b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bfdc8b959ef92ef35cb9eb74f9641096e74508061be37effe74abdb5435408e"
    family = "unknown"
    file_name = "nx_verify-iteration-2.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:33"
  condition:
    hash.sha256(0, filesize) == "7bfdc8b959ef92ef35cb9eb74f9641096e74508061be37effe74abdb5435408e"
}
```

### Sample 84: `accc5d1c6a5affdf`

| Field | Value |
|---|---|
| SHA-256 | `accc5d1c6a5affdfce6e316f7ac7745a93598c568723d5b69189b86ee1b8b58f` |
| Family label | `unknown` |
| File name | `nx_verify-iteration-1.sh` |
| File type | `sh` |
| First seen | `2026-10-02 04:09:09` |
| Reporter | `boredchilada2` |
| Tags | `citrix-netscaler, cve-2026-88771, sh, shell-script, webshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2a11bffbc76e55f403944d3d6bed545` |
| SHA-1 | `a53eb3ebf5d0982612caeae0d84f0baedaad3b30` |
| SHA-256 | `accc5d1c6a5affdfce6e316f7ac7745a93598c568723d5b69189b86ee1b8b58f` |
| SHA3-384 | `2c391a34be98faee96d7dad27a7432ed3abbb9ef46ad2f69743d3b11ccc90e2c3814e85e3ac0176472c5bd86e435d414` |
| TLSH | `T141E0868D94C31ED71EFA48FA127BCB1426C5F747069A5DEB974236AE70143C43268AB2` |
| SSDEEP | `6:thOAqXiojQ1qKL8WTo/dqX9GaKpTw8QqGaKp/i8WTkGaKDZE1od9p05N9pV:thp4P6xL8WTo/d4sBpTw8EBp/i8WTHBw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_accc5d1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "accc5d1c6a5affdfce6e316f7ac7745a93598c568723d5b69189b86ee1b8b58f"
    family = "unknown"
    file_name = "nx_verify-iteration-1.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:09"
  condition:
    hash.sha256(0, filesize) == "accc5d1c6a5affdfce6e316f7ac7745a93598c568723d5b69189b86ee1b8b58f"
}
```

### Sample 85: `8fd5f4249f5cc9d7`

| Field | Value |
|---|---|
| SHA-256 | `8fd5f4249f5cc9d7d33ed7679c0b78a5b269d82d2bc7bf3014f19fbff8d4d660` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-02 04:07:42` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b190a0d5b6c8fa1861b9a853db666e49` |
| SHA-1 | `98fbbbf606626fa4933441609f889c1c30bfda5b` |
| SHA-256 | `8fd5f4249f5cc9d7d33ed7679c0b78a5b269d82d2bc7bf3014f19fbff8d4d660` |
| SHA3-384 | `fb8df72facc581d7c25b96697b5f248671239736bdd1b4ef006a91f4202d6bbfed516df1eb63bcb4cd3e87c08aa404da` |
| IMPHASH | `30460a99eb4cf142ef950fe91489aa59` |
| TLSH | `T1E5253A6017863EFCF12A803C2A360595E13764FE83FF17DE067B727A68451C27AE5A58` |
| SSDEEP | `12288:CoINnBCgYOYvJqpjUDwDU3j9YFolzs4VFhM4hUeQHJ2tUKzfGz2Ah8JDqYDY5fos:CVNo8eH3xY26ADUzotHqaZDqPos` |
| ICON-DHASH | `fcd7a96d6da9573d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_8fd5f424
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd5f4249f5cc9d7d33ed7679c0b78a5b269d82d2bc7bf3014f19fbff8d4d660"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 04:07:42"
  condition:
    hash.sha256(0, filesize) == "8fd5f4249f5cc9d7d33ed7679c0b78a5b269d82d2bc7bf3014f19fbff8d4d660"
}
```

### Sample 86: `ab2d265ebc26207a`

| Field | Value |
|---|---|
| SHA-256 | `ab2d265ebc26207ab8dbd7341d11e314b371665b742b7fbee0c29a0b2d0da112` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-02 03:41:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e783d24260a856a057b93f6e4f0fcdc` |
| SHA-1 | `4c7e5aeed2b3a4970e8646a5da9a58860885578f` |
| SHA-256 | `ab2d265ebc26207ab8dbd7341d11e314b371665b742b7fbee0c29a0b2d0da112` |
| SHA3-384 | `9d53ce9cb35473b4bcb1144e0a5a85614d4a497239f44588e019050badd2eaed8e4c38eef8e17464ac8e3a7c9d7e536b` |
| TLSH | `T1C2632951F8819623C6D5127AFAAE028D3B2513E8E2DF72139E225F2137D682F0D77E45` |
| TELFHASH | `t11441e0a68e981fdc53e0834843cf6239bed834f8a71016a5cf7eab5f02435c2712a532` |
| SSDEEP | `1536:cbzeZ9y75ctpvkIK8rGLIxQfkmNZScfnJ4S1zY5Y:cbHwfGLIxQfkmNruS1QY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_ab2d265e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab2d265ebc26207ab8dbd7341d11e314b371665b742b7fbee0c29a0b2d0da112"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-02 03:41:45"
  condition:
    hash.sha256(0, filesize) == "ab2d265ebc26207ab8dbd7341d11e314b371665b742b7fbee0c29a0b2d0da112"
}
```

### Sample 87: `70a787b2b0d59b8a`

| Field | Value |
|---|---|
| SHA-256 | `70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e` |
| Family label | `ValleyRAT` |
| File name | `70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e.bin` |
| File type | `zip` |
| First seen | `2026-10-02 03:17:48` |
| Reporter | `Tuxxin` |
| Tags | `ValleyRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd444162648f1cc04e666fd25b7f498c` |
| SHA-1 | `e8b5a7083057ac9f52db7bc5e02e877b06cb951f` |
| SHA-256 | `70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e` |
| SHA3-384 | `6e27646d5f5fab978ccb2bd9237e2c31cd43e7ed41950db662717dd7fa32b0bdeba8ca079c97517a680dffa44d6820c6` |
| TLSH | `T17AB2E181EFF1EBB1CDEEDBF81E5288256C0459A0AE74C21D974A490230BDF54612FE48` |
| SSDEEP | `384:eKnyVVNQTGO4z+ICskTCsPF3HuvH+IxpBP6qtnAGOCLd6EyzrniLpG1mUhYpR:e1VYKnkTBieQxvzrLd/yaLpG1mUhYT` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_087_70a787b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e"
    family = "ValleyRAT"
    file_name = "70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e.bin"
    file_type = "zip"
    first_seen = "2026-10-02 03:17:48"
  condition:
    hash.sha256(0, filesize) == "70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e"
}
```

### Sample 88: `9aca0c8c2c56573b`

| Field | Value |
|---|---|
| SHA-256 | `9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676` |
| Family label | `unknown` |
| File name | `9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676.exe` |
| File type | `exe` |
| First seen | `2026-10-02 03:17:44` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f11340965330e413bf44cb98a3a5ec66` |
| SHA-1 | `91fce4786efd5eb7cd3c9c6d03e676616804e090` |
| SHA-256 | `9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676` |
| SHA3-384 | `cdd318fdbba3807ae08ad61d01488875e8f7191f66ef2d6399895c1dcbca97f3f23c30618447a461b48381d514cadb6c` |
| IMPHASH | `5be828fd20a09a875ae7745043b7e4cb` |
| TLSH | `T147E67B6BB2A4DD19C66AC53E82578F0495337DB6C7B3B3E7C68132646A328C06D3F251` |
| SSDEEP | `196608:jlLlMrKMlUdSyaQxudhRWU6kXkq++2q3Gb:jlLl8VlU0yaQYd8ecaG` |
| ICON-DHASH | `b2ecc4ececb8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_9aca0c8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676"
    family = "unknown"
    file_name = "9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676.exe"
    file_type = "exe"
    first_seen = "2026-10-02 03:17:44"
  condition:
    hash.sha256(0, filesize) == "9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676"
}
```

### Sample 89: `c95b623dfb6bdb6b`

| Field | Value |
|---|---|
| SHA-256 | `c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0` |
| Family label | `Mirai` |
| File name | `c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0` |
| File type | `elf` |
| First seen | `2026-10-02 03:17:42` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `366185a7e24af289a71bd6192cc88697` |
| SHA-1 | `54748d6c54e1f05e518db4a9dc261cb532b4150e` |
| SHA-256 | `c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0` |
| SHA3-384 | `cf44285a2c4dcb61e2d3b820851702546623695b39a14ca0ec18657fe17597785d7f32aab962d751747007fc3b0ca9eb` |
| TLSH | `T171B3079BBC919E5945D413BBBE2E418E331327B8D1DF7103DD141F18B6CA94F0E6AA82` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQgv:T2s/gAWuboqsJ9xcJxspJBqQgv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_c95b623d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0"
    family = "Mirai"
    file_name = "c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0"
    file_type = "elf"
    first_seen = "2026-10-02 03:17:42"
  condition:
    hash.sha256(0, filesize) == "c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0"
}
```

### Sample 90: `6eb96335adda1760`

| Field | Value |
|---|---|
| SHA-256 | `6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce` |
| Family label | `Mirai` |
| File name | `6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce` |
| File type | `elf` |
| First seen | `2026-10-02 02:17:58` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `064a59e06bed6d35937d85d5a9dab71d` |
| SHA-1 | `1dba78b5a21ac1f83f88ffc0abb58e6b9933198f` |
| SHA-256 | `6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce` |
| SHA3-384 | `be2494c037c1c97a3d0557373d0106ee3d9a81ea015b31c65d35b2d3f37f8687d89a26a7af846756bef5d6e10e01650e` |
| TLSH | `T1A334298AFC81AF65D5D422BBFE2E428A331317B8D2EA71129D145F2477CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqq:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_6eb96335
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce"
    family = "Mirai"
    file_name = "6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce"
    file_type = "elf"
    first_seen = "2026-10-02 02:17:58"
  condition:
    hash.sha256(0, filesize) == "6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce"
}
```

### Sample 91: `7bcb16d0c7d42109`

| Field | Value |
|---|---|
| SHA-256 | `7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d` |
| Family label | `unknown` |
| File name | `7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d.bin` |
| File type | `zip` |
| First seen | `2026-10-02 02:13:21` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b3bccdb3bcbd48162aa77270d910276` |
| SHA-1 | `77d04e2a6f8f9f5fce9c180c72a7f8cfefe5c63a` |
| SHA-256 | `7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d` |
| SHA3-384 | `705a2ceb21ce4e21dfeda699c39c1b95f8757b1f36410a4536abda597401fbf8c63bf087b45318567c5a8a62a904e397` |
| TLSH | `T1EDD19F5CF2608D73F101F1B51F0F30116C7696221BA775AA1D27362DB2A2B828B8EF1D` |
| SSDEEP | `192:EWdPS6B3Oo/i2oIPPaoQ5nGn7CMXcA3ERGQqiJ:EWa2vPunGnmHzkQ9J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_7bcb16d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d"
    family = "unknown"
    file_name = "7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d.bin"
    file_type = "zip"
    first_seen = "2026-10-02 02:13:21"
  condition:
    hash.sha256(0, filesize) == "7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d"
}
```

### Sample 92: `bd5f576f639aabe3`

| Field | Value |
|---|---|
| SHA-256 | `bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2` |
| Family label | `unknown` |
| File name | `bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2.exe` |
| File type | `exe` |
| First seen | `2026-10-02 02:13:10` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90bf77712d94d6e59bc0c62a0890eee2` |
| SHA-1 | `f9801f69b885b1545f139261f46bdb30b6bed911` |
| SHA-256 | `bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2` |
| SHA3-384 | `72ff3249555b258621b5d44c08a25f94f06ab2a587582408424c5b093412b29a26a0329bdb96f8c385c9ca89899b83e8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15564128D67D8A35ADB7F9B3A2B7A238091317D499D5AD78D8F40017D28A0F80DC71B1B` |
| SSDEEP | `6144:Cr+6o7M9npIrpreL4jGr5a/1LX/4Ub5Tix3pVQcs6O:zXQ9pIrpo4jMqXwzf2D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_bd5f576f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2"
    family = "unknown"
    file_name = "bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:13:10"
  condition:
    hash.sha256(0, filesize) == "bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2"
}
```

### Sample 93: `9923c026e550d023`

| Field | Value |
|---|---|
| SHA-256 | `9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a` |
| Family label | `unknown` |
| File name | `9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a.exe` |
| File type | `exe` |
| First seen | `2026-10-02 02:13:06` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fcc0abb1e2f9ec9572952f04ebbf88d` |
| SHA-1 | `6683f3d5df2dff7eced3c2feb4d9c3b71a4e2d4c` |
| SHA-256 | `9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a` |
| SHA3-384 | `a8b3dd507ece0c5dacb516ba26018a4ae45f10c04b6c3a1efb0ead81a194272b42168252c72969b59f4bdcb82527039e` |
| IMPHASH | `6f9fd465750a0db68adce98869da7d3c` |
| TLSH | `T13605231DFB0389F5DA6348305187FABF8A7C9D12956E870ADB5612368E76FB1613E300` |
| SSDEEP | `12288:z6kHneV/cx1pZRsnypcoe3/e0KTakAhHAlhXZq/MIHutoSREEGutEG4PEwiQh23:P+VW1WLPvKODAlPq/LHieSKiy23` |
| ICON-DHASH | `0026002f3f002600` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_9923c026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a"
    family = "unknown"
    file_name = "9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:13:06"
  condition:
    hash.sha256(0, filesize) == "9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a"
}
```

### Sample 94: `8f990f1e541560df`

| Field | Value |
|---|---|
| SHA-256 | `8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8` |
| Family label | `BlankGrabber` |
| File name | `8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8.exe` |
| File type | `exe` |
| First seen | `2026-10-02 02:13:02` |
| Reporter | `Tuxxin` |
| Tags | `BlankGrabber, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `637cc9753d5346601f33f08fda899c23` |
| SHA-1 | `a60d0d71bd2a6c1f614f6d1e4357f28ae7e65cf2` |
| SHA-256 | `8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8` |
| SHA3-384 | `46a6747364c4e488cf3235b18b22df687ea9f531af41cd8c3dc735e5fa5f4927f3acd6ea9fa2a3a0cea399853e1f05c1` |
| IMPHASH | `965e162fe6366ee377aa9bc80bdd5c65` |
| TLSH | `T1DC763329B3F008F6F9B369B9C492D5499371BC050B24CEDB43585AA91F276908D3FF68` |
| SSDEEP | `98304:jRDjWM8JEmwaK7amaHl3Ne4i3Tf2PkOpfW9hZMMoVmkzhxIdfXeRuYRJJcGhEIF7:jR0DjHeNTfm/pf+xk4dWRumrbW3jmzT` |
| ICON-DHASH | `100c623239310608` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_094_8f990f1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8"
    family = "BlankGrabber"
    file_name = "8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:13:02"
  condition:
    hash.sha256(0, filesize) == "8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8"
}
```

### Sample 95: `029b962730399375`

| Field | Value |
|---|---|
| SHA-256 | `029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae` |
| Family label | `RustyStealer` |
| File name | `029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae.exe` |
| File type | `exe` |
| First seen | `2026-10-02 02:12:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `262055815d9dd49b9898503e74162fc3` |
| SHA-1 | `d23fdea30c6171dadbddd1fc4b5f857ef40aa074` |
| SHA-256 | `029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae` |
| SHA3-384 | `e04c5cafbc95efe4424a8b882b6b1ce423fe1d2cf0b6bec1e07befd81abd81a8561bd266ed02b58e424cb3bad0ec82a3` |
| IMPHASH | `0fe6732025f09a1670eddeb6d5129b22` |
| TLSH | `T15E669D43F36291ECC12AC0749356A233FA62B849073566FB67D44B313E66FD05A3DB4A` |
| SSDEEP | `98304:BpGvA2WI/D1dPHULRBk2bVwgb327p/NbfrH+wJV:27dvIBkaPmt5` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_095_029b9627
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae"
    family = "RustyStealer"
    file_name = "029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:12:45"
  condition:
    hash.sha256(0, filesize) == "029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae"
}
```

### Sample 96: `323a0ad213a0154b`

| Field | Value |
|---|---|
| SHA-256 | `323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464` |
| Family label | `unknown` |
| File name | `323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464.exe` |
| File type | `exe` |
| First seen | `2026-10-02 02:12:40` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da6049ec17fd01ff99433bdd7753889b` |
| SHA-1 | `ef24074cd2d8a8643c32c200045f67c5d1de2931` |
| SHA-256 | `323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464` |
| SHA3-384 | `a3bfd734893b06778520e03cffc2e5a870a84522de8f7dca59c8168c376020ae8ac2149d43a9aebdfbe18bd1485cbd2a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C5B66B43ED9145E4C8AD91308A6792A3BF717C495B3123C72B60F7686FBABE05E79340` |
| SSDEEP | `98304:W1JSi4VlXnGXx2MoP2e8pSWGzhdhup8Jg6EEv:WvuGXx2hOe4SWGFr9G69v` |
| ICON-DHASH | `13ac65f8b4d5300f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_323a0ad2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464"
    family = "unknown"
    file_name = "323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:12:40"
  condition:
    hash.sha256(0, filesize) == "323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464"
}
```

### Sample 97: `3e1ca09e40ec98f4`

| Field | Value |
|---|---|
| SHA-256 | `3e1ca09e40ec98f4f7853108f28ec2d46607031a0803a90bbb8035b375f20c0f` |
| Family label | `unknown` |
| File name | `eclipse.armv7l` |
| File type | `elf` |
| First seen | `2026-10-02 01:35:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af4feb2bd0a800b9e21ac07bd5999a66` |
| SHA-1 | `0e12ff82c655f2fde12b383a6799805b2bd6dab6` |
| SHA-256 | `3e1ca09e40ec98f4f7853108f28ec2d46607031a0803a90bbb8035b375f20c0f` |
| SHA3-384 | `2f97975445fa816798f1180b8144d2a036eccc6b13fb82a522e5f1453384a910bd85f6ff4af233a53c92570d99ec12fe` |
| TLSH | `T138A42966E8419B51D5D12ABFFF6E824973131B78F3EE72119D195F3063CB88A0E3A502` |
| SSDEEP | `12288:sHEZINdm116WVfsCfApWaSUu4JWF+jina+IyGOtJZcYbYU:PZINWTfJ5FH6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_3e1ca09e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1ca09e40ec98f4f7853108f28ec2d46607031a0803a90bbb8035b375f20c0f"
    family = "unknown"
    file_name = "eclipse.armv7l"
    file_type = "elf"
    first_seen = "2026-10-02 01:35:46"
  condition:
    hash.sha256(0, filesize) == "3e1ca09e40ec98f4f7853108f28ec2d46607031a0803a90bbb8035b375f20c0f"
}
```

### Sample 98: `53b9d801349be358`

| Field | Value |
|---|---|
| SHA-256 | `53b9d801349be358960d5be9c3b5d153e44bbd155bccb7e5fa3318647b6b8b51` |
| Family label | `unknown` |
| File name | `shellcode.py` |
| File type | `py` |
| First seen | `2026-10-02 01:25:49` |
| Reporter | `johnk3r` |
| Tags | `fa-lkmqd-com, py` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f2abee5293bfaee414c89944a6fb80e` |
| SHA-1 | `0fe3afbd61ae9e196463fc1617d89cfb473de9c7` |
| SHA-256 | `53b9d801349be358960d5be9c3b5d153e44bbd155bccb7e5fa3318647b6b8b51` |
| SHA3-384 | `1f45407f2f04b98ec389008539a407b57d5a459da00213fee1b86239d8529a6927bba8a8760347d221958a4633b12c4a` |
| TLSH | `T10832EBC74613C16F568EC8165E7A7ACC3C69D06FC4C9A702F0D9AA0F57A8E2B8194FC1` |
| SSDEEP | `192:PkpWBjIPC42T5hELqPgSbFblWp8gsZ1JBzd3uKJiqHVzDA+yD3FHjyB:PBBjUerPBFXrJzs2ARZHjI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `py`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_53b9d801
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53b9d801349be358960d5be9c3b5d153e44bbd155bccb7e5fa3318647b6b8b51"
    family = "unknown"
    file_name = "shellcode.py"
    file_type = "py"
    first_seen = "2026-10-02 01:25:49"
  condition:
    hash.sha256(0, filesize) == "53b9d801349be358960d5be9c3b5d153e44bbd155bccb7e5fa3318647b6b8b51"
}
```

### Sample 99: `a018b9018d5f50d6`

| Field | Value |
|---|---|
| SHA-256 | `a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d` |
| Family label | `ConnectWise` |
| File name | `a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d.msi` |
| File type | `msi` |
| First seen | `2026-10-02 01:17:39` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e0a491224b14580d04e8cae8ee9466f` |
| SHA-1 | `eb61314899230575a9a5e307b344a89ae31539f9` |
| SHA-256 | `a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d` |
| SHA3-384 | `b58bcfde46cc3914bc5521f888634f4f9b508a54881e2d44b72185aaf7c6add74e49cac3ebd668ab5e55217866bbcfa9` |
| TLSH | `T130D623116BF89678F0F22A35E876A0B1A5377D125E22D12E2324791E2C75EC0C9B3777` |
| SSDEEP | `196608:zHxcp9ym3nltDUJV6Hxcp9ym3mHxcp9ym3+Hxcp9ym3UHxcp9ym3EHxcp9ym3LHH:dGplpZGp0GpMGpyGpiGpVGpM` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_099_a018b901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d"
    family = "ConnectWise"
    file_name = "a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d.msi"
    file_type = "msi"
    first_seen = "2026-10-02 01:17:39"
  condition:
    hash.sha256(0, filesize) == "a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d"
}
```

### Sample 100: `d610c87652eacd91`

| Field | Value |
|---|---|
| SHA-256 | `d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9` |
| Family label | `Mirai` |
| File name | `d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9` |
| File type | `elf` |
| First seen | `2026-10-02 01:17:38` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66f33fcce43ab5461f9de21c5171a62e` |
| SHA-1 | `1a74b898ba5c56668317c3af2d4d962d8b4dfd00` |
| SHA-256 | `d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9` |
| SHA3-384 | `d025f220e2022e90d4806e1a7bf790816d86f1a8198688ba2479f8b84728108b4d1e34407bbef6c6a13d93beb31cf6c5` |
| TLSH | `T1FB342A8AFC81AF2595C526BBFE2E428A331317B8D2EB71129D145F2477CA94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqq:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_d610c876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9"
    family = "Mirai"
    file_name = "d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9"
    file_type = "elf"
    first_seen = "2026-10-02 01:17:38"
  condition:
    hash.sha256(0, filesize) == "d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9"
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
 * Generated: 2026-10-02T05:50:03.369948+00:00
 */

rule MalwareBazaar_unknown_001_6ed042d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ed042d86dac44f704212ef9c846f7f65b8cec9988addac9f6edd17250be1fc5"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-02 05:41:48"
  condition:
    hash.sha256(0, filesize) == "6ed042d86dac44f704212ef9c846f7f65b8cec9988addac9f6edd17250be1fc5"
}

rule MalwareBazaar_unknown_002_457ff62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "457ff62cb3e95fad075c1310859ef7d7c960ec35308c7e9b8b76dc3e1bc84c91"
    family = "unknown"
    file_name = "457ff62cb3e95fad.bin"
    file_type = "unknown"
    first_seen = "2026-10-02 05:25:18"
  condition:
    hash.sha256(0, filesize) == "457ff62cb3e95fad075c1310859ef7d7c960ec35308c7e9b8b76dc3e1bc84c91"
}

rule MalwareBazaar_Mirai_003_4bd1e379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848"
    family = "Mirai"
    file_name = "4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848"
    file_type = "elf"
    first_seen = "2026-10-02 05:17:48"
  condition:
    hash.sha256(0, filesize) == "4bd1e37982b854d4ad4801ab68496b02ff29050d800373d9601ca4b792720848"
}

rule MalwareBazaar_unknown_004_043ebed6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee"
    family = "unknown"
    file_name = "043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee.bin"
    file_type = "unknown"
    first_seen = "2026-10-02 05:13:34"
  condition:
    hash.sha256(0, filesize) == "043ebed69763576c9e01c71afe80e1d60184ccd1c92e33d30da5e067f22d2bee"
}

rule MalwareBazaar_unknown_005_f3016f7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3"
    family = "unknown"
    file_name = "f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3.exe"
    file_type = "exe"
    first_seen = "2026-10-02 05:13:29"
  condition:
    hash.sha256(0, filesize) == "f3016f7e967ace800d9aa1c66535dbd698f51182628fa7c415e2f1c4699e4ab3"
}

rule MalwareBazaar_unknown_006_08809c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08809c9882e4e1137b2827a7431aaad833278fa186687ab737f8575b14c5d5b5"
    family = "unknown"
    file_name = "eclipse.armv7l"
    file_type = "elf"
    first_seen = "2026-10-02 05:11:52"
  condition:
    hash.sha256(0, filesize) == "08809c9882e4e1137b2827a7431aaad833278fa186687ab737f8575b14c5d5b5"
}

rule MalwareBazaar_Mirai_007_e7aeac7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-02 05:02:56"
  condition:
    hash.sha256(0, filesize) == "e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72"
}

rule MalwareBazaar_Mirai_008_6713eedc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6713eedc768899e0e3a1ad096e242f17ad94b51760462459edf559c589a625db"
    family = "Mirai"
    file_name = "eclipse.armv5l"
    file_type = "elf"
    first_seen = "2026-10-02 04:56:49"
  condition:
    hash.sha256(0, filesize) == "6713eedc768899e0e3a1ad096e242f17ad94b51760462459edf559c589a625db"
}

rule MalwareBazaar_unknown_009_06fffeea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06fffeea93435328949a102e15496f92e4dddb66cdb8a351d7efb31e0a0b5049"
    family = "unknown"
    file_name = "new.txt"
    file_type = "elf"
    first_seen = "2026-10-02 04:56:47"
  condition:
    hash.sha256(0, filesize) == "06fffeea93435328949a102e15496f92e4dddb66cdb8a351d7efb31e0a0b5049"
}

rule MalwareBazaar_unknown_010_2dda0c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dda0c1d9f63287c19663780ba88e731b4530568a65d5886cfc6a416d805926e"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-10-02 04:53:33"
  condition:
    hash.sha256(0, filesize) == "2dda0c1d9f63287c19663780ba88e731b4530568a65d5886cfc6a416d805926e"
}

rule MalwareBazaar_ConnectWise_011_0cffc29f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443"
    family = "ConnectWise"
    file_name = "0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443.exe"
    file_type = "exe"
    first_seen = "2026-10-02 04:52:45"
  condition:
    hash.sha256(0, filesize) == "0cffc29fc64c22f94a22321404301c936b0ac85ae5fe77ad23bf921a7ecaa443"
}

rule MalwareBazaar_unknown_012_fff5c971
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee"
    family = "unknown"
    file_name = "fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee"
    file_type = "dll"
    first_seen = "2026-10-02 04:44:10"
  condition:
    hash.sha256(0, filesize) == "fff5c971e185d83acd635dfb4a5ce9fd917d6de26783ba5e930f790d7e57fdee"
}

rule MalwareBazaar_unknown_013_e55cbd52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19"
    family = "unknown"
    file_name = "e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19"
    file_type = "dll"
    first_seen = "2026-10-02 04:44:01"
  condition:
    hash.sha256(0, filesize) == "e55cbd5263a4b36537a24165c56b51d24118655947e4d64061a3141f7960de19"
}

rule MalwareBazaar_unknown_014_bd6ced0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88"
    family = "unknown"
    file_name = "bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:52"
  condition:
    hash.sha256(0, filesize) == "bd6ced0e07e43dd444d32cdbb91cdca95cba576f91550cb6cf02093599fbfa88"
}

rule MalwareBazaar_unknown_015_7f0789ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd"
    family = "unknown"
    file_name = "7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:43"
  condition:
    hash.sha256(0, filesize) == "7f0789ce97f44dc4e049ca86580d1ad3e3ff74ce06e179ad5c2c3c7872235dfd"
}

rule MalwareBazaar_unknown_016_7440d8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce"
    family = "unknown"
    file_name = "7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:35"
  condition:
    hash.sha256(0, filesize) == "7440d8eaa7a1eb499a0a838f3af936cbb5616a67944412fa9f40f609e1fd32ce"
}

rule MalwareBazaar_unknown_017_24b58112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f"
    family = "unknown"
    file_name = "24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:27"
  condition:
    hash.sha256(0, filesize) == "24b581123f36d8aed3f6dbd289e6bee933f7586db0281d9e5a232f706e18d23f"
}

rule MalwareBazaar_unknown_018_5494465a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b"
    family = "unknown"
    file_name = "5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:19"
  condition:
    hash.sha256(0, filesize) == "5494465aae2857ce53b6a45bfbf7d8a539a86c0778214e67e5bf09637efd3a7b"
}

rule MalwareBazaar_unknown_019_93094569
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d"
    family = "unknown"
    file_name = "93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:11"
  condition:
    hash.sha256(0, filesize) == "93094569048b9cda7f573e6c3b7aa22dd1a44fe301f3fbf0b2e61e6fcdb6cd9d"
}

rule MalwareBazaar_unknown_020_b9ae285b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad"
    family = "unknown"
    file_name = "b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad"
    file_type = "dll"
    first_seen = "2026-10-02 04:43:02"
  condition:
    hash.sha256(0, filesize) == "b9ae285be3643a84b1590a75151a5c97b11a2b4f7f2c32e18abe4568fc0261ad"
}

rule MalwareBazaar_unknown_021_82754b7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126"
    family = "unknown"
    file_name = "82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:54"
  condition:
    hash.sha256(0, filesize) == "82754b7e96e5e509a82be696b3c96f0f164abab855407a6279ed5143233d9126"
}

rule MalwareBazaar_unknown_022_22254626
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795"
    family = "unknown"
    file_name = "2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:45"
  condition:
    hash.sha256(0, filesize) == "2225462661583a82237c6a78755623b47f32fc41a2467da7c5988ce2bd8a8795"
}

rule MalwareBazaar_unknown_023_88f6f20e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5"
    family = "unknown"
    file_name = "88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:38"
  condition:
    hash.sha256(0, filesize) == "88f6f20e3d2851adc879f033466ff3bdfa50e6975a1dc3a51da1bb55266994b5"
}

rule MalwareBazaar_unknown_024_50d82407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de"
    family = "unknown"
    file_name = "50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:30"
  condition:
    hash.sha256(0, filesize) == "50d82407b6f0d36ae9dda7fd81e250d4b3699f4d02a10138131756d2abc132de"
}

rule MalwareBazaar_unknown_025_749be614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8"
    family = "unknown"
    file_name = "749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:22"
  condition:
    hash.sha256(0, filesize) == "749be61425d402c132c5200eb437456a6e54585d7e255e5f8f212315821536e8"
}

rule MalwareBazaar_unknown_026_3c5592c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f"
    family = "unknown"
    file_name = "3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:14"
  condition:
    hash.sha256(0, filesize) == "3c5592c53301f894a58c7c0c3363449fed56b68c4e9be778d4da7665edba528f"
}

rule MalwareBazaar_unknown_027_6fb2331a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c"
    family = "unknown"
    file_name = "6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c"
    file_type = "dll"
    first_seen = "2026-10-02 04:42:05"
  condition:
    hash.sha256(0, filesize) == "6fb2331acaa1539ca4daa70de38bce19b8f31335d81fc9a23a7743a54562b16c"
}

rule MalwareBazaar_unknown_028_54d4b7ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e"
    family = "unknown"
    file_name = "54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e"
    file_type = "dll"
    first_seen = "2026-10-02 04:41:57"
  condition:
    hash.sha256(0, filesize) == "54d4b7ac7bafcf657cceb0ba8231d287065a1da82f9cc8dbf4077be950bf3d8e"
}

rule MalwareBazaar_unknown_029_c8a451d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf"
    family = "unknown"
    file_name = "c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf"
    file_type = "dll"
    first_seen = "2026-10-02 04:41:50"
  condition:
    hash.sha256(0, filesize) == "c8a451d25d8e85fe85651e8b9dc686bc5666b25d060c6f6354542ebdcd422fbf"
}

rule MalwareBazaar_unknown_030_05b644f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05b644f9c8f87057aeb24a64776600fe37547a65f052886e285222bdc5f0d90b"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-02 04:41:49"
  condition:
    hash.sha256(0, filesize) == "05b644f9c8f87057aeb24a64776600fe37547a65f052886e285222bdc5f0d90b"
}

rule MalwareBazaar_unknown_031_0b8ef4e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15"
    family = "unknown"
    file_name = "0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15"
    file_type = "dll"
    first_seen = "2026-10-02 04:41:19"
  condition:
    hash.sha256(0, filesize) == "0b8ef4e7cd3f29de53c595575b322a0d008f904d1eb582619a32d0e29dabbe15"
}

rule MalwareBazaar_unknown_032_b60b5a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae"
    family = "unknown"
    file_name = "b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:42"
  condition:
    hash.sha256(0, filesize) == "b60b5a142cbd64b6a74aab73b48c4c1476cf26ba65fb1cf8ca13780ec41ad1ae"
}

rule MalwareBazaar_unknown_033_1a8cfff7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a"
    family = "unknown"
    file_name = "1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:32"
  condition:
    hash.sha256(0, filesize) == "1a8cfff75c4f4b4b6cdb982d60647c413cd306b561de716e1b76efea98c68c2a"
}

rule MalwareBazaar_unknown_034_898080ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0"
    family = "unknown"
    file_name = "898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:20"
  condition:
    hash.sha256(0, filesize) == "898080cee26a3c93c634f0ab9cb3454417a050cc9a1321592e47abab9c417bf0"
}

rule MalwareBazaar_unknown_035_43820d92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976"
    family = "unknown"
    file_name = "43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976"
    file_type = "elf"
    first_seen = "2026-10-02 04:35:12"
  condition:
    hash.sha256(0, filesize) == "43820d92efd2b7c619970523b830a8709afb96d02bb89fba8e772a1a63c15976"
}

rule MalwareBazaar_unknown_036_e9813d61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0"
    family = "unknown"
    file_name = "e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0"
    file_type = "elf"
    first_seen = "2026-10-02 04:34:50"
  condition:
    hash.sha256(0, filesize) == "e9813d6185b3ed64abefb13df06ca13c29e95b06f948071add75f4bb6a0b11b0"
}

rule MalwareBazaar_unknown_037_4898d1f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70"
    family = "unknown"
    file_name = "4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70"
    file_type = "unknown"
    first_seen = "2026-10-02 04:34:46"
  condition:
    hash.sha256(0, filesize) == "4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70"
}

rule MalwareBazaar_unknown_038_729a2102
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c"
    family = "unknown"
    file_name = "729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c"
    file_type = "sh"
    first_seen = "2026-10-02 04:34:43"
  condition:
    hash.sha256(0, filesize) == "729a2102bb790a128fbd8df95caf3aeb28cb0e2a855ffafafc14637f162f866c"
}

rule MalwareBazaar_unknown_039_42f302e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9"
    family = "unknown"
    file_name = "42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:40"
  condition:
    hash.sha256(0, filesize) == "42f302e579fe04a91cf03f115ea5eac0686102e5faf7abff92e0f56e3058f6f9"
}

rule MalwareBazaar_unknown_040_545a5362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739"
    family = "unknown"
    file_name = "545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:33"
  condition:
    hash.sha256(0, filesize) == "545a5362e94dc1f062ddb6e3ffb2efc625acff46a345e9273658de5989d8c739"
}

rule MalwareBazaar_unknown_041_97bfa8be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081"
    family = "unknown"
    file_name = "97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:27"
  condition:
    hash.sha256(0, filesize) == "97bfa8beb89ba5411680b0b503e4fbaed5e0d01675cce0d7c3a73a731adc1081"
}

rule MalwareBazaar_unknown_042_c0902a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55"
    family = "unknown"
    file_name = "c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:20"
  condition:
    hash.sha256(0, filesize) == "c0902a637fa3edc7dc90ece1cfb9d63648b76969caec60ff39ab2563c0b1ea55"
}

rule MalwareBazaar_unknown_043_7f32fd53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78"
    family = "unknown"
    file_name = "7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:14"
  condition:
    hash.sha256(0, filesize) == "7f32fd534b1acbb43fb8001872cabd9f0a70a5ae5d10d87505b422fddd4a6a78"
}

rule MalwareBazaar_unknown_044_21d52f97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0"
    family = "unknown"
    file_name = "21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:08"
  condition:
    hash.sha256(0, filesize) == "21d52f970117819dab150b9d71d64d2afb3794ca7c6de574321d27b1849b71b0"
}

rule MalwareBazaar_unknown_045_489d62f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71"
    family = "unknown"
    file_name = "489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71"
    file_type = "dll"
    first_seen = "2026-10-02 04:34:01"
  condition:
    hash.sha256(0, filesize) == "489d62f69e4336fd750156567c618ca4bd553c51a2ded2262bc81b44edc67e71"
}

rule MalwareBazaar_unknown_046_4c99f251
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a"
    family = "unknown"
    file_name = "4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:55"
  condition:
    hash.sha256(0, filesize) == "4c99f251878a8712c1dcf8606c8f85b75648ff0a6d263ed7e8e50427059f473a"
}

rule MalwareBazaar_unknown_047_c3f082d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e"
    family = "unknown"
    file_name = "c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:49"
  condition:
    hash.sha256(0, filesize) == "c3f082d1dbd1b82a9fdf07a844211c68a4f2bec3b81f0822ca10ec1ddf1ce30e"
}

rule MalwareBazaar_unknown_048_f9f0e48a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1"
    family = "unknown"
    file_name = "f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:43"
  condition:
    hash.sha256(0, filesize) == "f9f0e48a96f2ce21a77471c45a32491729f9c203fec25b176ebfbb0ed2f0f4b1"
}

rule MalwareBazaar_unknown_049_ec64f5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10"
    family = "unknown"
    file_name = "ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:36"
  condition:
    hash.sha256(0, filesize) == "ec64f5d5ca51fa22055c9b313c4e94c376065f4bea0f27f15adc4c0f3678de10"
}

rule MalwareBazaar_unknown_050_cfe1829b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838"
    family = "unknown"
    file_name = "cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:30"
  condition:
    hash.sha256(0, filesize) == "cfe1829b62a2bc4291f3ca74a7f1e8646fd00be34451f340275a77b566ea5838"
}

rule MalwareBazaar_unknown_051_40c655fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1"
    family = "unknown"
    file_name = "40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1"
    file_type = "dll"
    first_seen = "2026-10-02 04:33:23"
  condition:
    hash.sha256(0, filesize) == "40c655fb966dcb8e039bf1dcd66f2ba2aee68c072006c9ea1aab92d036bb2cb1"
}

rule MalwareBazaar_unknown_052_887cee88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef"
    family = "unknown"
    file_name = "887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef"
    file_type = "sh"
    first_seen = "2026-10-02 04:33:15"
  condition:
    hash.sha256(0, filesize) == "887cee8882a211aa262f950214ae561cbce8f400ef63a9d46d7583c6cfbeafef"
}

rule MalwareBazaar_unknown_053_704462fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9"
    family = "unknown"
    file_name = "704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9"
    file_type = "sh"
    first_seen = "2026-10-02 04:33:11"
  condition:
    hash.sha256(0, filesize) == "704462fa073a2fb72ea73f543e844427a67890276908b7eb3277c3913e64e0c9"
}

rule MalwareBazaar_unknown_054_340a7192
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972"
    family = "unknown"
    file_name = "340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972"
    file_type = "dll"
    first_seen = "2026-10-02 04:32:53"
  condition:
    hash.sha256(0, filesize) == "340a71927feeac945750661685cfa8ff61cbf2a6cb27cfcc5e8a3da7c0b66972"
}

rule MalwareBazaar_unknown_055_a71878d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654"
    family = "unknown"
    file_name = "a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654"
    file_type = "dll"
    first_seen = "2026-10-02 04:32:48"
  condition:
    hash.sha256(0, filesize) == "a71878d240325a795d54079ca7ff360575c184de8510c90e1f2e95d458e93654"
}

rule MalwareBazaar_unknown_056_abb34def
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023"
    family = "unknown"
    file_name = "abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023"
    file_type = "elf"
    first_seen = "2026-10-02 04:32:39"
  condition:
    hash.sha256(0, filesize) == "abb34def493905670e26e7b55929d73308ab768ab83cdda3aedac2c647cde023"
}

rule MalwareBazaar_unknown_057_9b3fde5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3"
    family = "unknown"
    file_name = "9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3"
    file_type = "elf"
    first_seen = "2026-10-02 04:32:29"
  condition:
    hash.sha256(0, filesize) == "9b3fde5cad3037c0ed14a74c1d9b339081b7eb53dbcb2057573834a9d37a4db3"
}

rule MalwareBazaar_unknown_058_0577adf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d"
    family = "unknown"
    file_name = "0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d"
    file_type = "dll"
    first_seen = "2026-10-02 04:32:04"
  condition:
    hash.sha256(0, filesize) == "0577adf4a25ca1c3a36e867fb6f268ff8235636a72f308cdd60985c2cc89512d"
}

rule MalwareBazaar_unknown_059_f64df3e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309"
    family = "unknown"
    file_name = "f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309"
    file_type = "unknown"
    first_seen = "2026-10-02 04:32:00"
  condition:
    hash.sha256(0, filesize) == "f64df3e33e654e7330d07d7e568c26e0370822dd67e9f9e19071324a32787309"
}

rule MalwareBazaar_unknown_060_2d3d59eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318"
    family = "unknown"
    file_name = "2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:58"
  condition:
    hash.sha256(0, filesize) == "2d3d59eb67ef2c9547f976b97c284a726e71f3b02f5d08844d6dcb9918ce5318"
}

rule MalwareBazaar_unknown_061_6b4882e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94"
    family = "unknown"
    file_name = "6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:55"
  condition:
    hash.sha256(0, filesize) == "6b4882e1405034545e256f7f063b33a98c4d15734a0c976acad5bbcbf8630f94"
}

rule MalwareBazaar_unknown_062_dbcd1e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b"
    family = "unknown"
    file_name = "dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:51"
  condition:
    hash.sha256(0, filesize) == "dbcd1e680a9516f4c07688ebf8fdf55ea4e150b0602b81d533b4e1f25a1d8d2b"
}

rule MalwareBazaar_unknown_063_fa18d676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd"
    family = "unknown"
    file_name = "fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:48"
  condition:
    hash.sha256(0, filesize) == "fa18d676b7bdba3940fbc3eaff4b3227643b8a2beae1c83b605743f0fe1486dd"
}

rule MalwareBazaar_unknown_064_318a05e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03"
    family = "unknown"
    file_name = "318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:44"
  condition:
    hash.sha256(0, filesize) == "318a05e0e97d6b4977b90e9da5247e34c2dc13fd714ec104ae1918325d46de03"
}

rule MalwareBazaar_unknown_065_6ffa1d6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629"
    family = "unknown"
    file_name = "6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629"
    file_type = "dll"
    first_seen = "2026-10-02 04:31:40"
  condition:
    hash.sha256(0, filesize) == "6ffa1d6c99875db8f4565f214a24cc85a3c51f24937c63fc126f589ff4fed629"
}

rule MalwareBazaar_unknown_066_8238a342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6"
    family = "unknown"
    file_name = "8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6"
    file_type = "elf"
    first_seen = "2026-10-02 04:31:36"
  condition:
    hash.sha256(0, filesize) == "8238a342a0f30e6ac2973bfaa978e8bace3e1287c0db0889dd5738f9ec6083a6"
}

rule MalwareBazaar_unknown_067_9f628b3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6"
    family = "unknown"
    file_name = "9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6"
    file_type = "elf"
    first_seen = "2026-10-02 04:31:31"
  condition:
    hash.sha256(0, filesize) == "9f628b3fd279bbf6c9bdb70814c802dd0091bf42240a21b5b88dd6c24e1a69d6"
}

rule MalwareBazaar_unknown_068_f1d41d03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd"
    family = "unknown"
    file_name = "f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:50"
  condition:
    hash.sha256(0, filesize) == "f1d41d03b3376c404cad4725fd62e9c15157074ddf7617e8d3ad05712208a4fd"
}

rule MalwareBazaar_unknown_069_665cddac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9"
    family = "unknown"
    file_name = "665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:43"
  condition:
    hash.sha256(0, filesize) == "665cddac04e345ea11a45e1235960d98baaee4b745b8117496efefc474c044b9"
}

rule MalwareBazaar_unknown_070_ec9cbd6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7"
    family = "unknown"
    file_name = "ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:36"
  condition:
    hash.sha256(0, filesize) == "ec9cbd6f5375401b9224fe7d19f446ba50bb27cbedee27f189fb218fcfa6e0f7"
}

rule MalwareBazaar_unknown_071_73318261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e"
    family = "unknown"
    file_name = "7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e"
    file_type = "dll"
    first_seen = "2026-10-02 04:30:31"
  condition:
    hash.sha256(0, filesize) == "7331826168a261cb730dcf8922d7e3f8dabe0456d1a274ff8f5489a7dd2b110e"
}

rule MalwareBazaar_unknown_072_29a723d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2"
    family = "unknown"
    file_name = "29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2"
    file_type = "elf"
    first_seen = "2026-10-02 04:30:22"
  condition:
    hash.sha256(0, filesize) == "29a723d93e9541ea1d17feea6637828111bf06f99c52d84b3aae143c42407ed2"
}

rule MalwareBazaar_unknown_073_037440f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434"
    family = "unknown"
    file_name = "037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434"
    file_type = "elf"
    first_seen = "2026-10-02 04:30:13"
  condition:
    hash.sha256(0, filesize) == "037440f3874a99bcc706561a0833e5db8bc9cb3b2cbe5c73bdb465cc14dba434"
}

rule MalwareBazaar_unknown_074_c80debfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a"
    family = "unknown"
    file_name = "c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a.bin"
    file_type = "zip"
    first_seen = "2026-10-02 04:28:33"
  condition:
    hash.sha256(0, filesize) == "c80debfcc13b6b9dc675b48154f331cfa9aba5af149d3899a9f23a1e09cdc64a"
}

rule MalwareBazaar_Mirai_075_7bac68e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d"
    family = "Mirai"
    file_name = "7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d"
    file_type = "elf"
    first_seen = "2026-10-02 04:17:15"
  condition:
    hash.sha256(0, filesize) == "7bac68e19b279f768e36b194f39de21f17dcdb6dacdcf27fa6f14d851fe9733d"
}

rule MalwareBazaar_RemoteManipulator_076_ebe315f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7"
    family = "RemoteManipulator"
    file_name = "ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7.msi"
    file_type = "msi"
    first_seen = "2026-10-02 04:12:58"
  condition:
    hash.sha256(0, filesize) == "ebe315f58648a2d4a30e607230fd07cebd6251a054d4b7fe3e1078e8991857d7"
}

rule MalwareBazaar_unknown_077_bfad966f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfad966f4b09e89b20d72d2fa16d2bc0a305297621d2eb88f4d8768d7ed92633"
    family = "unknown"
    file_name = "Nx_5936.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:10:20"
  condition:
    hash.sha256(0, filesize) == "bfad966f4b09e89b20d72d2fa16d2bc0a305297621d2eb88f4d8768d7ed92633"
}

rule MalwareBazaar_unknown_078_c69576b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c69576b1daa1246563e2391f84ad603c6fba454adc363146712a2e77f7b09510"
    family = "unknown"
    file_name = "Nx_zD.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:10:03"
  condition:
    hash.sha256(0, filesize) == "c69576b1daa1246563e2391f84ad603c6fba454adc363146712a2e77f7b09510"
}

rule MalwareBazaar_unknown_079_6ce6b4eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ce6b4ebd1a25b971fcc9e1b8ef8ff00d2aed3b5117b3799bd1943c4400f9fbd"
    family = "unknown"
    file_name = "Nx_7508.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:56"
  condition:
    hash.sha256(0, filesize) == "6ce6b4ebd1a25b971fcc9e1b8ef8ff00d2aed3b5117b3799bd1943c4400f9fbd"
}

rule MalwareBazaar_unknown_080_223edab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "223edab12979b91a01a53519fbfb52a97f772ac50ae6cc34bfde7a784306da30"
    family = "unknown"
    file_name = "Nx_5100.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:50"
  condition:
    hash.sha256(0, filesize) == "223edab12979b91a01a53519fbfb52a97f772ac50ae6cc34bfde7a784306da30"
}

rule MalwareBazaar_unknown_081_7f0c6678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f0c6678d94bed94ddd2369bb5d59ead44fb2777dbb1ca27d86143f3cf73e1b8"
    family = "unknown"
    file_name = "Nx_8507.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:44"
  condition:
    hash.sha256(0, filesize) == "7f0c6678d94bed94ddd2369bb5d59ead44fb2777dbb1ca27d86143f3cf73e1b8"
}

rule MalwareBazaar_unknown_082_f878eccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f878eccf4b300f8085ceb866a2f71aed10428109e2cb89079a685699c6ef0941"
    family = "unknown"
    file_name = "nx_verify-iteration-3.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:39"
  condition:
    hash.sha256(0, filesize) == "f878eccf4b300f8085ceb866a2f71aed10428109e2cb89079a685699c6ef0941"
}

rule MalwareBazaar_unknown_083_7bfdc8b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bfdc8b959ef92ef35cb9eb74f9641096e74508061be37effe74abdb5435408e"
    family = "unknown"
    file_name = "nx_verify-iteration-2.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:33"
  condition:
    hash.sha256(0, filesize) == "7bfdc8b959ef92ef35cb9eb74f9641096e74508061be37effe74abdb5435408e"
}

rule MalwareBazaar_unknown_084_accc5d1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "accc5d1c6a5affdfce6e316f7ac7745a93598c568723d5b69189b86ee1b8b58f"
    family = "unknown"
    file_name = "nx_verify-iteration-1.sh"
    file_type = "sh"
    first_seen = "2026-10-02 04:09:09"
  condition:
    hash.sha256(0, filesize) == "accc5d1c6a5affdfce6e316f7ac7745a93598c568723d5b69189b86ee1b8b58f"
}

rule MalwareBazaar_unknown_085_8fd5f424
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd5f4249f5cc9d7d33ed7679c0b78a5b269d82d2bc7bf3014f19fbff8d4d660"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-02 04:07:42"
  condition:
    hash.sha256(0, filesize) == "8fd5f4249f5cc9d7d33ed7679c0b78a5b269d82d2bc7bf3014f19fbff8d4d660"
}

rule MalwareBazaar_Mirai_086_ab2d265e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab2d265ebc26207ab8dbd7341d11e314b371665b742b7fbee0c29a0b2d0da112"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-02 03:41:45"
  condition:
    hash.sha256(0, filesize) == "ab2d265ebc26207ab8dbd7341d11e314b371665b742b7fbee0c29a0b2d0da112"
}

rule MalwareBazaar_ValleyRAT_087_70a787b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e"
    family = "ValleyRAT"
    file_name = "70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e.bin"
    file_type = "zip"
    first_seen = "2026-10-02 03:17:48"
  condition:
    hash.sha256(0, filesize) == "70a787b2b0d59b8abf14019f674fbc70e9e2d01b6ed844821d9708ebd3c3ce4e"
}

rule MalwareBazaar_unknown_088_9aca0c8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676"
    family = "unknown"
    file_name = "9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676.exe"
    file_type = "exe"
    first_seen = "2026-10-02 03:17:44"
  condition:
    hash.sha256(0, filesize) == "9aca0c8c2c56573b634344275aa590358a857f4f2b0d21657880056f75d46676"
}

rule MalwareBazaar_Mirai_089_c95b623d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0"
    family = "Mirai"
    file_name = "c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0"
    file_type = "elf"
    first_seen = "2026-10-02 03:17:42"
  condition:
    hash.sha256(0, filesize) == "c95b623dfb6bdb6b6fe25ce9a839bbbb01a950cd747a5593c27bc3ea346dd5e0"
}

rule MalwareBazaar_Mirai_090_6eb96335
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce"
    family = "Mirai"
    file_name = "6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce"
    file_type = "elf"
    first_seen = "2026-10-02 02:17:58"
  condition:
    hash.sha256(0, filesize) == "6eb96335adda176094942bbccf04c86d0e0005a93841753413fba49be22b1bce"
}

rule MalwareBazaar_unknown_091_7bcb16d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d"
    family = "unknown"
    file_name = "7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d.bin"
    file_type = "zip"
    first_seen = "2026-10-02 02:13:21"
  condition:
    hash.sha256(0, filesize) == "7bcb16d0c7d421091b04fcd6f9405cc2440eafe0b3cdf9c48f026eec8802a31d"
}

rule MalwareBazaar_unknown_092_bd5f576f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2"
    family = "unknown"
    file_name = "bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:13:10"
  condition:
    hash.sha256(0, filesize) == "bd5f576f639aabe3c6ce5e8e0146aa176e81128bdce7c09304006673db9c95a2"
}

rule MalwareBazaar_unknown_093_9923c026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a"
    family = "unknown"
    file_name = "9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:13:06"
  condition:
    hash.sha256(0, filesize) == "9923c026e550d0231d52308f9dfde33b22d515580fe0e958020aa02ca81c702a"
}

rule MalwareBazaar_BlankGrabber_094_8f990f1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8"
    family = "BlankGrabber"
    file_name = "8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:13:02"
  condition:
    hash.sha256(0, filesize) == "8f990f1e541560dfd73f07bd44965c7855e62ef7b5631962a36ee211945b8ef8"
}

rule MalwareBazaar_RustyStealer_095_029b9627
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae"
    family = "RustyStealer"
    file_name = "029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:12:45"
  condition:
    hash.sha256(0, filesize) == "029b9627303993756e3a7006c0ef7420a18fac1f43b11cf1e5b293a3197e94ae"
}

rule MalwareBazaar_unknown_096_323a0ad2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464"
    family = "unknown"
    file_name = "323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464.exe"
    file_type = "exe"
    first_seen = "2026-10-02 02:12:40"
  condition:
    hash.sha256(0, filesize) == "323a0ad213a0154b60ad7e7300b40f389ef7ff2dc922e1235a418a46addda464"
}

rule MalwareBazaar_unknown_097_3e1ca09e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1ca09e40ec98f4f7853108f28ec2d46607031a0803a90bbb8035b375f20c0f"
    family = "unknown"
    file_name = "eclipse.armv7l"
    file_type = "elf"
    first_seen = "2026-10-02 01:35:46"
  condition:
    hash.sha256(0, filesize) == "3e1ca09e40ec98f4f7853108f28ec2d46607031a0803a90bbb8035b375f20c0f"
}

rule MalwareBazaar_unknown_098_53b9d801
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53b9d801349be358960d5be9c3b5d153e44bbd155bccb7e5fa3318647b6b8b51"
    family = "unknown"
    file_name = "shellcode.py"
    file_type = "py"
    first_seen = "2026-10-02 01:25:49"
  condition:
    hash.sha256(0, filesize) == "53b9d801349be358960d5be9c3b5d153e44bbd155bccb7e5fa3318647b6b8b51"
}

rule MalwareBazaar_ConnectWise_099_a018b901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d"
    family = "ConnectWise"
    file_name = "a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d.msi"
    file_type = "msi"
    first_seen = "2026-10-02 01:17:39"
  condition:
    hash.sha256(0, filesize) == "a018b9018d5f50d67da3e7c455bc3e3886b41be0b362b6709f012ee35a2a6b2d"
}

rule MalwareBazaar_Mirai_100_d610c876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9"
    family = "Mirai"
    file_name = "d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9"
    file_type = "elf"
    first_seen = "2026-10-02 01:17:38"
  condition:
    hash.sha256(0, filesize) == "d610c87652eacd912bd98808a6ac8f0ff588c43c9348ea2f9ce1a4d44ce885b9"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-25

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 568 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 568 |
| Unique family labels | 8 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 64 |
| Mirai | 28 |
| Vidar | 3 |
| RemusStealer | 1 |
| AsyncRAT | 1 |
| RemcosRAT | 1 |
| CoinMiner | 1 |
| Phorphiex | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 39 |
| exe | 22 |
| unknown | 18 |
| sh | 11 |
| zip | 2 |
| 7z | 1 |
| rar | 1 |
| pdf | 1 |
| ps1 | 1 |
| lnk | 1 |

## Per-Sample Analysis

### Sample 1: `24e7ae95c625a50f`

| Field | Value |
|---|---|
| SHA-256 | `24e7ae95c625a50f9426ab5f32e7710ccb97e6d19d39b94bc8bd461c49f99c67` |
| Family label | `unknown` |
| File name | `System Applications 001.7z` |
| File type | `7z` |
| First seen | `2026-08-25 01:53:43` |
| Reporter | `anonymous` |
| Tags | `7z, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1539be3909923de14486d4b7aaa319c7` |
| SHA-1 | `348dc4203ff4033ace6eaca023f51504ef6951b0` |
| SHA-256 | `24e7ae95c625a50f9426ab5f32e7710ccb97e6d19d39b94bc8bd461c49f99c67` |
| SHA3-384 | `e534a649971594199b1c24dc63a0fc4227015defd7df97c047781f70877a5c368fd5ff48604102fcc3903f0b47cd7eb8` |
| TLSH | `T1C7B73323B7E4CCB010AE7ECEDFC66E218DA48CE3A4238846667546DF92B74DF4919C51` |
| SSDEEP | `1572864:mdutTcBJxLwswdV2zIoGpBwfPuqsoOYzaC8:gSTcr1ws42zXFPuonzaC8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_24e7ae95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24e7ae95c625a50f9426ab5f32e7710ccb97e6d19d39b94bc8bd461c49f99c67"
    family = "unknown"
    file_name = "System Applications 001.7z"
    file_type = "7z"
    first_seen = "2026-08-25 01:53:43"
  condition:
    hash.sha256(0, filesize) == "24e7ae95c625a50f9426ab5f32e7710ccb97e6d19d39b94bc8bd461c49f99c67"
}
```

### Sample 2: `5e5590a064f53a7a`

| Field | Value |
|---|---|
| SHA-256 | `5e5590a064f53a7a2e2d0e9144d1d86b03f45b491902a3b8119dc9fd0f9a4b78` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-25 01:52:14` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `049a3065ce23f60c4a845d0d27e92a22` |
| SHA-256 | `5e5590a064f53a7a2e2d0e9144d1d86b03f45b491902a3b8119dc9fd0f9a4b78` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_5e5590a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e5590a064f53a7a2e2d0e9144d1d86b03f45b491902a3b8119dc9fd0f9a4b78"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-25 01:52:14"
  condition:
    hash.sha256(0, filesize) == "5e5590a064f53a7a2e2d0e9144d1d86b03f45b491902a3b8119dc9fd0f9a4b78"
}
```

### Sample 3: `ab282de6689911c7`

| Field | Value |
|---|---|
| SHA-256 | `ab282de6689911c7a81ecccb272f1f9f4e1e3705f8d81950f9e791edf79647a2` |
| Family label | `unknown` |
| File name | `DOC-J1674 + 674-1 + 1674-2.rar` |
| File type | `rar` |
| First seen | `2026-08-25 01:02:09` |
| Reporter | `anonymous` |
| Tags | `FormBook, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f9f9335f66a3c4e43662b0998f25e3b` |
| SHA-1 | `832e66d7bf4ffb69e4d26253198578c15114f641` |
| SHA-256 | `ab282de6689911c7a81ecccb272f1f9f4e1e3705f8d81950f9e791edf79647a2` |
| SHA3-384 | `0b72d6c761c0eb892dd2794f79428910936128ab09f7fd56292c15d5addda69078fc2decb3651004d90079515c6099a6` |
| TLSH | `T1EE15233A58EE632445E78704462C9F3B9F6F0927253BB673ACE70174E41C21799F836A` |
| SSDEEP | `12288:TEvX3XVsLtHqU1lKOp8OPgh9iCNTPnuXykiAEzHJMKfmej2XkcxAeLMOE5YHWYUr:TKlWK+b8lFxk7KT6xAgXCY2ou2H7DS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_ab282de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab282de6689911c7a81ecccb272f1f9f4e1e3705f8d81950f9e791edf79647a2"
    family = "unknown"
    file_name = "DOC-J1674 + 674-1 + 1674-2.rar"
    file_type = "rar"
    first_seen = "2026-08-25 01:02:09"
  condition:
    hash.sha256(0, filesize) == "ab282de6689911c7a81ecccb272f1f9f4e1e3705f8d81950f9e791edf79647a2"
}
```

### Sample 4: `ee981b6035362e01`

| Field | Value |
|---|---|
| SHA-256 | `ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328` |
| Family label | `unknown` |
| File name | `ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328.exe` |
| File type | `exe` |
| First seen | `2026-08-25 01:02:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aad294780651aa303040f3225e7aba3b` |
| SHA-1 | `a852e84e13481d98baf97449272e2b081a6d3984` |
| SHA-256 | `ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328` |
| SHA3-384 | `488fcdf356b41d88762c6e83f7922e0e4773c562a7767ee1fbe0276d469e8b2ada62bb98aa3d7b1997ba7029d2c6e7d8` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T126D5226AFC823EBAD436C3F71693A56DB1597F858A609C4E76C82B005D1292D3C3B335` |
| SSDEEP | `49152:zVnSkiQ7XttncTtWcWg/TJBiOImUIMxF09dNH5FgPBR4SchjsoIaNLg7:zz3rDcK6BXiQd55FgPBSBXIo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_ee981b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328"
    family = "unknown"
    file_name = "ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328.exe"
    file_type = "exe"
    first_seen = "2026-08-25 01:02:06"
  condition:
    hash.sha256(0, filesize) == "ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328"
}
```

### Sample 5: `015f9cc2efae6b07`

| Field | Value |
|---|---|
| SHA-256 | `015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451` |
| Family label | `unknown` |
| File name | `015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451` |
| File type | `elf` |
| First seen | `2026-08-25 01:01:16` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2384ad217fd89a5bdfd2e893cb4b2e74` |
| SHA-1 | `1924154c07ab4c48307427850f17857067582614` |
| SHA-256 | `015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451` |
| SHA3-384 | `dd13f1c5853b328a5c24dda6a70802d9acd039efb71e4736042dbab0d7e01094ec74c8c9b1897ef3ffd3a3e26763ac86` |
| TLSH | `T1E827CE77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQn:cqYUQuVDt0TZEU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_015f9cc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451"
    family = "unknown"
    file_name = "015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451"
    file_type = "elf"
    first_seen = "2026-08-25 01:01:16"
  condition:
    hash.sha256(0, filesize) == "015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451"
}
```

### Sample 6: `e6d0f0b93c126288`

| Field | Value |
|---|---|
| SHA-256 | `e6d0f0b93c12628872622c103b6fdd5227fc94b432ffe431df6e77cb4676830c` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-25 00:52:14` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e750308224f7dd39507dfc403a7da7c0` |
| SHA-256 | `e6d0f0b93c12628872622c103b6fdd5227fc94b432ffe431df6e77cb4676830c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_e6d0f0b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6d0f0b93c12628872622c103b6fdd5227fc94b432ffe431df6e77cb4676830c"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-25 00:52:14"
  condition:
    hash.sha256(0, filesize) == "e6d0f0b93c12628872622c103b6fdd5227fc94b432ffe431df6e77cb4676830c"
}
```

### Sample 7: `696101c117b86e7f`

| Field | Value |
|---|---|
| SHA-256 | `696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4` |
| Family label | `unknown` |
| File name | `696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4` |
| File type | `elf` |
| First seen | `2026-08-25 00:02:00` |
| Reporter | `APT6pack` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8c2a884ae2250d5e52d13194b073209` |
| SHA-1 | `fe6daade67a3ddf3a6f86ad4f76d6aea973d8dc9` |
| SHA-256 | `696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4` |
| SHA3-384 | `7605f9e3be4bc33b2f3aa2f606b69bacc044423f60f4cc81bf84ec12a5612196bbeec6bd31a4c3c9f3d0bb865d56f96b` |
| TLSH | `T12347DF77814338E9E5B98DB4D41025426DAC388B5738A3C7BAC471E667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQP:cqYUQuVDt0TZE8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_696101c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4"
    family = "unknown"
    file_name = "696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4"
    file_type = "elf"
    first_seen = "2026-08-25 00:02:00"
  condition:
    hash.sha256(0, filesize) == "696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4"
}
```

### Sample 8: `fba00f02ac5abe5b`

| Field | Value |
|---|---|
| SHA-256 | `fba00f02ac5abe5b9f7185d74ba753aa12984517fd79ce70a17ffd0ab3fa9adb` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-24 23:55:02` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX1.file, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1a774ce1a8b5aa8ccf6b7c4b1cfd0ee` |
| SHA-1 | `8a57b2a9cbad582ca6211f7ee7686e6450782853` |
| SHA-256 | `fba00f02ac5abe5b9f7185d74ba753aa12984517fd79ce70a17ffd0ab3fa9adb` |
| SHA3-384 | `22a742ddf48928376004d25e82a403d29cefa56fb90aba0eab857b6103d3f7e2933a05b0bc0188473f0837bdd011b06e` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T163C57C43BC8161B0E999E336C4750251B730B84C1B3573D76E56BBB82E32BD50E7ABA4` |
| SSDEEP | `49152:1WGktsilU5fOTaZY4lb3FDMdQnSgvcUzyuD1EC:rfJmqMtk` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_008_fba00f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba00f02ac5abe5b9f7185d74ba753aa12984517fd79ce70a17ffd0ab3fa9adb"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 23:55:02"
  condition:
    hash.sha256(0, filesize) == "fba00f02ac5abe5b9f7185d74ba753aa12984517fd79ce70a17ffd0ab3fa9adb"
}
```

### Sample 9: `091f4580316498af`

| Field | Value |
|---|---|
| SHA-256 | `091f4580316498af0b96de415bc0f418e61f31e6defb57a54e4084382e51de63` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.ELF.Svirtu-AA.71646998` |
| File type | `elf` |
| First seen | `2026-08-24 23:52:15` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a569d38fa137ce89f70831b0473fe5ca` |
| SHA-1 | `717f39a49c05716190c6cdc8a38ed623e55c3086` |
| SHA-256 | `091f4580316498af0b96de415bc0f418e61f31e6defb57a54e4084382e51de63` |
| SHA3-384 | `a233ad25d45fe729873b1397ed735e38b2dc1b9abb768233574284a51e4f0f4c90896b542ccbe0ca1028567cbecbd7c4` |
| TLSH | `T12C029E6AF21CFDCDCC39C9F664F39F4E725AEA4EB1DBA285800094A9C85724274713D6` |
| SSDEEP | `192:kR9/5NlBRDGHeYT4jZKCK6MfRZX6YdHuLk74o4y31i:6Jn6v4jZKCXGTX2jyFi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_091f4580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "091f4580316498af0b96de415bc0f418e61f31e6defb57a54e4084382e51de63"
    family = "unknown"
    file_name = "SecuriteInfo.com.ELF.Svirtu-AA.71646998"
    file_type = "elf"
    first_seen = "2026-08-24 23:52:15"
  condition:
    hash.sha256(0, filesize) == "091f4580316498af0b96de415bc0f418e61f31e6defb57a54e4084382e51de63"
}
```

### Sample 10: `aa06c6b9f0676b66`

| Field | Value |
|---|---|
| SHA-256 | `aa06c6b9f0676b66664593106f88cb8ce719f40be1a0372156f64f4dbed84c8b` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 23:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99ea0ba43286edf00b192f5a8364b26c` |
| SHA-256 | `aa06c6b9f0676b66664593106f88cb8ce719f40be1a0372156f64f4dbed84c8b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_aa06c6b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa06c6b9f0676b66664593106f88cb8ce719f40be1a0372156f64f4dbed84c8b"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 23:52:11"
  condition:
    hash.sha256(0, filesize) == "aa06c6b9f0676b66664593106f88cb8ce719f40be1a0372156f64f4dbed84c8b"
}
```

### Sample 11: `b8128e8b60602523`

| Field | Value |
|---|---|
| SHA-256 | `b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3` |
| Family label | `unknown` |
| File name | `b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3` |
| File type | `sh` |
| First seen | `2026-08-24 23:30:12` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22fc0bb170ee22e071dd0773cd30adb2` |
| SHA-1 | `617a3d61068732141d7840602491795656686d1d` |
| SHA-256 | `b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3` |
| SHA3-384 | `ca77a7eed405cc1d827445b394fe3aa45b52df289601b68fcf029832862e3f318cfbde102e3969655d611032f894f13c` |
| TLSH | `T121314F9F51241B311102DD8E73A27159618ED6EB289FD7E0DE090FA982886CCF222B5E` |
| SSDEEP | `24:s0r4ziFLxczxSWSjEgG/xf38JMB0qMwdgEwflcb:Pr4zYVV2/x0GBbMwdefl6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_b8128e8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3"
    family = "unknown"
    file_name = "b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3"
    file_type = "sh"
    first_seen = "2026-08-24 23:30:12"
  condition:
    hash.sha256(0, filesize) == "b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3"
}
```

### Sample 12: `866f6652ceff5218`

| Field | Value |
|---|---|
| SHA-256 | `866f6652ceff521896811a1666fbe0fd17fd879e31953b47cb3cfab1619067eb` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnm68kxnxn` |
| File type | `elf` |
| First seen | `2026-08-24 23:24:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcfd4b9b9bbf487f495a83769cc82f75` |
| SHA-1 | `a2254c4ac1eab68eaf1090685dd603fba0c44b06` |
| SHA-256 | `866f6652ceff521896811a1666fbe0fd17fd879e31953b47cb3cfab1619067eb` |
| SHA3-384 | `68e0412d4d18b3331f42f36dc15ded07915768f81382ccfd41b3f30cc141b566764c7c3285b44b371eefd6f4e788da2c` |
| TLSH | `T143B3BF87B1907ABEF0A45E3FC4135E26E6259F705583173D71BDF9906E3A3903292E42` |
| SSDEEP | `1536:NoOxCg+uUGWkCqYUqwaJ1XqfXg5AcS5blaZeCtjHXNLdCS2T15OvhSkz+8rSx:N1xKlGWnqTUcXgZS5gZ7CSXhSLUSx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_866f6652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866f6652ceff521896811a1666fbe0fd17fd879e31953b47cb3cfab1619067eb"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnm68kxnxn"
    file_type = "elf"
    first_seen = "2026-08-24 23:24:36"
  condition:
    hash.sha256(0, filesize) == "866f6652ceff521896811a1666fbe0fd17fd879e31953b47cb3cfab1619067eb"
}
```

### Sample 13: `53160a2c0530340f`

| Field | Value |
|---|---|
| SHA-256 | `53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88` |
| Family label | `unknown` |
| File name | `53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88.exe` |
| File type | `exe` |
| First seen | `2026-08-24 23:12:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c34229a38381e4ef1cdac65d57509247` |
| SHA-1 | `c3035ff9ee3fb9d222f7725fed7f7825adefc32e` |
| SHA-256 | `53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88` |
| SHA3-384 | `796679ebcdccf9ca83106835211c400b0d4d1eaaf24f83fc4310b0a8704808afd137df89c54c07194cf8b7bcf235bfe4` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T157D52359AAF20474D437C7B18F92E07DB06A37858BA08E5BB39C3E105C635996D3B3B1` |
| SSDEEP | `49152:Qp7/1Zpv+vI4xt097SgWDiZA6Jc3yXgJxHRvyBiFJ+oWBRIRczI+OSiE5JXGHlq:QpL1ZgRxt05SEt6CXqxHEzIlQGHl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_53160a2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88"
    family = "unknown"
    file_name = "53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88.exe"
    file_type = "exe"
    first_seen = "2026-08-24 23:12:15"
  condition:
    hash.sha256(0, filesize) == "53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88"
}
```

### Sample 14: `c51e5bedcf9d7753`

| Field | Value |
|---|---|
| SHA-256 | `c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162` |
| Family label | `unknown` |
| File name | `c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162` |
| File type | `sh` |
| First seen | `2026-08-24 23:00:15` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db9ce65907781e8d85f3c6507701ab0c` |
| SHA-1 | `9414e02d14731f2142d13bea2601eb712126dbaf` |
| SHA-256 | `c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162` |
| SHA3-384 | `50f34b1546412fae7e6deaa86161c26780bd3cd18aae7664293f8c769d11d4dda237de00370039dcbfe7a0be6282135d` |
| TLSH | `T10931869F442019311502CAAE7767358D628EA1E72CAFC7E098594EE9829C78CF352B5A` |
| SSDEEP | `24:G2mO+UGSGPN4PZEtgQgaRtlBk85RhaYCo9y3dm:iJ94Bzhap285REYtGdm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_c51e5bed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162"
    family = "unknown"
    file_name = "c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162"
    file_type = "sh"
    first_seen = "2026-08-24 23:00:15"
  condition:
    hash.sha256(0, filesize) == "c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162"
}
```

### Sample 15: `f4cad3370b0c1889`

| Field | Value |
|---|---|
| SHA-256 | `f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36` |
| Family label | `unknown` |
| File name | `f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36` |
| File type | `unknown` |
| First seen | `2026-08-24 22:53:32` |
| Reporter | `moldy` |
| Tags | `honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57eb6b7a8c994d2e14976b29884fa493` |
| SHA-256 | `f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_f4cad337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36"
    family = "unknown"
    file_name = "f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36"
    file_type = "unknown"
    first_seen = "2026-08-24 22:53:32"
  condition:
    hash.sha256(0, filesize) == "f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36"
}
```

### Sample 16: `06d9d9f415792963`

| Field | Value |
|---|---|
| SHA-256 | `06d9d9f4157929638f122ca4dfb2f6afa4822d5279332afed91faba006c49cd0` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 22:52:17` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e20fc488ce869b32d3117663a92005c` |
| SHA-256 | `06d9d9f4157929638f122ca4dfb2f6afa4822d5279332afed91faba006c49cd0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_06d9d9f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06d9d9f4157929638f122ca4dfb2f6afa4822d5279332afed91faba006c49cd0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 22:52:17"
  condition:
    hash.sha256(0, filesize) == "06d9d9f4157929638f122ca4dfb2f6afa4822d5279332afed91faba006c49cd0"
}
```

### Sample 17: `701921b96f6934bf`

| Field | Value |
|---|---|
| SHA-256 | `701921b96f6934bffa01eff0ddfe42037de70d7cf96ef859480057d9200b0562` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-24 22:46:48` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09870a81bbbf27786349298943a3fde7` |
| SHA-256 | `701921b96f6934bffa01eff0ddfe42037de70d7cf96ef859480057d9200b0562` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_701921b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "701921b96f6934bffa01eff0ddfe42037de70d7cf96ef859480057d9200b0562"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-24 22:46:48"
  condition:
    hash.sha256(0, filesize) == "701921b96f6934bffa01eff0ddfe42037de70d7cf96ef859480057d9200b0562"
}
```

### Sample 18: `82608a590fa29af4`

| Field | Value |
|---|---|
| SHA-256 | `82608a590fa29af44c5b77830074b7e0b9d27174d042c6a8ed6f7119b6d54bb9` |
| Family label | `unknown` |
| File name | `23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b.exe` |
| File type | `exe` |
| First seen | `2026-08-24 22:03:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7e8f4b1136567a630d7e82465780042` |
| SHA-1 | `e1b69a52333fbcd25335739d30378f15ef2a3341` |
| SHA-256 | `82608a590fa29af44c5b77830074b7e0b9d27174d042c6a8ed6f7119b6d54bb9` |
| SHA3-384 | `288de9fcf10c56ab958b1b6e0642ac98e52891b39a4c11db7f766e1a4885798669c1fc4641370fd715790b7f6d52cdaa` |
| TLSH | `T1A4551E8ED8919BF8B3A6F773521AD6225CF6344780328631CF457E395F02F24A524EDA` |
| SSDEEP | `12288:DKnr3gPi2qT/Q6hGT692vl9Iem6m9gEBi:DKr3gCTY6sUeBE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_82608a59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82608a590fa29af44c5b77830074b7e0b9d27174d042c6a8ed6f7119b6d54bb9"
    family = "unknown"
    file_name = "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 22:03:18"
  condition:
    hash.sha256(0, filesize) == "82608a590fa29af44c5b77830074b7e0b9d27174d042c6a8ed6f7119b6d54bb9"
}
```

### Sample 19: `23b3344bfa7fab78`

| Field | Value |
|---|---|
| SHA-256 | `23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b` |
| Family label | `unknown` |
| File name | `23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b.exe` |
| File type | `exe` |
| First seen | `2026-08-24 22:02:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71d75b8cd84cb874b92ed8cc0efa8042` |
| SHA-1 | `017e9abda7a2c6412f824782dba680400860d07e` |
| SHA-256 | `23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b` |
| SHA3-384 | `6342f74940bacefdefce152a3ddfe0846f975bb04c22a495ab3df2f38e3894ecf75030788e06e81be10c0398fc0c3c72` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12F74234662D7678CDCDE9834039931C3AE0F777CB985E77A90BED9AE33609348E45848` |
| SSDEEP | `6144:6i17fe5lQvi+WglLT7SfvujsJOYasCbKY0qEluDeVplyomdL0L09yXRy3oy2UVIv:6m7fekvi+WgLT7Sej6OYHCbK3qguU+dw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_23b3344b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b"
    family = "unknown"
    file_name = "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 22:02:13"
  condition:
    hash.sha256(0, filesize) == "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b"
}
```

### Sample 20: `49f6d68d8020ab4b`

| Field | Value |
|---|---|
| SHA-256 | `49f6d68d8020ab4b83e52ccc80a6fb53605097c264ef46a3de694a48ad520f21` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-24 21:54:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e527da4b713ccebdfb8b46fe17b67e8` |
| SHA-1 | `326aa56468c5ff775f622cebc99deef8a33cfef8` |
| SHA-256 | `49f6d68d8020ab4b83e52ccc80a6fb53605097c264ef46a3de694a48ad520f21` |
| SHA3-384 | `e325ed2e877b2b08748bf34fcfdf67a1500d2d05d15d66d76524a7e8f580684cab8b79072aed264fabdd2d52d820d459` |
| TLSH | `T18E34D75E2E628F3EF269873487B74E25975862C722D1D640F16CD1102F2029EA56FFEC` |
| TELFHASH | `t1f4417f280d7817f0a7755c9d459dff77d6a330db3e222c278e11e46aab69a839d10c0c` |
| SSDEEP | `6144:wH6jum7s0+1bx9KeepotZFGj8FLKEssMOgh5oHd+M:mxoCgEssMOgh5oHJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_49f6d68d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49f6d68d8020ab4b83e52ccc80a6fb53605097c264ef46a3de694a48ad520f21"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-24 21:54:44"
  condition:
    hash.sha256(0, filesize) == "49f6d68d8020ab4b83e52ccc80a6fb53605097c264ef46a3de694a48ad520f21"
}
```

### Sample 21: `caec10a5adfdec9e`

| Field | Value |
|---|---|
| SHA-256 | `caec10a5adfdec9ec202c091306a7af005e38f5b8cd0f59d0dfa5e3b41b343c4` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-24 21:54:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13f0de5691a918dfd6713fbfb2bd32c7` |
| SHA-1 | `bcc34d14b3680a1ed2d9007e1069a0a5684091a4` |
| SHA-256 | `caec10a5adfdec9ec202c091306a7af005e38f5b8cd0f59d0dfa5e3b41b343c4` |
| SHA3-384 | `46e9c9e607754a874fae557848c59ec8eeb3ab36a5e76333d5aa4221e91a26474219679112f313b59720d7e7b280f0eb` |
| TLSH | `T1C234E9096FB20EFBD86BDD3B06E91A06248C641722947B35763CD528BF0A54F4AE3D74` |
| SSDEEP | `3072:O1M4HYHWgMKp22mWuDM6+UThTdvDvmdiICSHPLBu1EssMZc/T03ImIys61X1h5on:2ncuDM9kBVjmM6vLKEssMOgh5oeT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_caec10a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caec10a5adfdec9ec202c091306a7af005e38f5b8cd0f59d0dfa5e3b41b343c4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-24 21:54:43"
  condition:
    hash.sha256(0, filesize) == "caec10a5adfdec9ec202c091306a7af005e38f5b8cd0f59d0dfa5e3b41b343c4"
}
```

### Sample 22: `62868f70c9145d6b`

| Field | Value |
|---|---|
| SHA-256 | `62868f70c9145d6b67edd9d595fbf10d05d51442c3b7e2d4e459e7da1df1e8e2` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-24 21:53:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f2efd82c43f00c4400aad0f22f9cfb3` |
| SHA-1 | `0b925ff390792ef9344437c04b37d61d1c021655` |
| SHA-256 | `62868f70c9145d6b67edd9d595fbf10d05d51442c3b7e2d4e459e7da1df1e8e2` |
| SHA3-384 | `ad6dddf5c15c861a2a6610f034270f5ef86ca4c1eecf83d5daaab1ad29de862e73bde8c2fd568c97eeaaaff53d976a13` |
| TLSH | `T1ACD36CC56DE3E0F1E953857A4A6F931A4B36E4370119D911FB2E28386F42110E7BB7AC` |
| TELFHASH | `t1c351eafb2b7b0ce9a754ac45d30e6b511e49e77b196032e34563c421235aec1857bc39` |
| SSDEEP | `3072:UCaVHDLv6BLSXBgv3c6ebYPzMUPMhK2iu1EssMZc/T03ImIys61X1h5oV:gHfv6BKB+wrTK2vEssMOgh5oV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_62868f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62868f70c9145d6b67edd9d595fbf10d05d51442c3b7e2d4e459e7da1df1e8e2"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-24 21:53:06"
  condition:
    hash.sha256(0, filesize) == "62868f70c9145d6b67edd9d595fbf10d05d51442c3b7e2d4e459e7da1df1e8e2"
}
```

### Sample 23: `38f50dc222dfcfce`

| Field | Value |
|---|---|
| SHA-256 | `38f50dc222dfcfce713055db0c5270a086ea6bc31353d586119b2b86bc81f557` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 21:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47c41112f2b6d05d6b3a47eea7fbc986` |
| SHA-256 | `38f50dc222dfcfce713055db0c5270a086ea6bc31353d586119b2b86bc81f557` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_38f50dc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38f50dc222dfcfce713055db0c5270a086ea6bc31353d586119b2b86bc81f557"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 21:52:11"
  condition:
    hash.sha256(0, filesize) == "38f50dc222dfcfce713055db0c5270a086ea6bc31353d586119b2b86bc81f557"
}
```

### Sample 24: `df4997d19239b1ad`

| Field | Value |
|---|---|
| SHA-256 | `df4997d19239b1adb12274e20a09dbd9ddd903bb171afea96a469878377fe525` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-24 21:46:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48f7394edb387960e90fca6be8a43fe6` |
| SHA-1 | `cfc632d1738df9b4c997d7fadbd37f1ac8042400` |
| SHA-256 | `df4997d19239b1adb12274e20a09dbd9ddd903bb171afea96a469878377fe525` |
| SHA3-384 | `d1dfc568cf03b65c3b85208d2fc8487134b5f6cc7f0766561d7b51102ada1323f220c1142c610dbded806710d0caeac5` |
| TLSH | `T16C93F8917CF3A156C6C3863FEB4F92093322619782CE7522FD1D5B602FCA11A87B7991` |
| TELFHASH | `t1fef09e45fd388b198de27a74ac8803a584035217612387248f98dae4cc3e01aa748d5d` |
| SSDEEP | `1536:rZ/hoCc4V3bHxxW452pxu3e2P5AIKHqkI/TnejM3nTu1EssMZcywT03ImIys61Xu:Vhc4VRWpxu3e2P5AIKHJITnS0Tu1Essf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_df4997d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df4997d19239b1adb12274e20a09dbd9ddd903bb171afea96a469878377fe525"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-24 21:46:01"
  condition:
    hash.sha256(0, filesize) == "df4997d19239b1adb12274e20a09dbd9ddd903bb171afea96a469878377fe525"
}
```

### Sample 25: `ba15814980b4e622`

| Field | Value |
|---|---|
| SHA-256 | `ba15814980b4e622b00a3d4fc739681edea7549b3ae0c99de79d2365da590264` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-24 21:44:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `894ede3740869d35162555f974f0b9e7` |
| SHA-1 | `0cb7f67a42d45518ad926b8d0d0fcc4a55b76bf8` |
| SHA-256 | `ba15814980b4e622b00a3d4fc739681edea7549b3ae0c99de79d2365da590264` |
| SHA3-384 | `69f65142d58063667988839dd2a5fdc6cc1b2bc2958e5fdf29362e43ec56c14ea9b67d0317d7e21425e0ad29b2b499cd` |
| TLSH | `T1C2235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD109B1D` |
| SSDEEP | `768:9+iJ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:9+/cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_ba158149
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba15814980b4e622b00a3d4fc739681edea7549b3ae0c99de79d2365da590264"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-24 21:44:20"
  condition:
    hash.sha256(0, filesize) == "ba15814980b4e622b00a3d4fc739681edea7549b3ae0c99de79d2365da590264"
}
```

### Sample 26: `1e4e68d5e61e9c31`

| Field | Value |
|---|---|
| SHA-256 | `1e4e68d5e61e9c3159621f6e7dfe07d2cb7a42d5d60e5b0949d9a257f4cd9fc3` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-24 21:36:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00a731db18285a8191edabef63504dba` |
| SHA-1 | `92108da12e227d0f3adb91d41acd99694575315d` |
| SHA-256 | `1e4e68d5e61e9c3159621f6e7dfe07d2cb7a42d5d60e5b0949d9a257f4cd9fc3` |
| SHA3-384 | `1a81be821b223827415463e4e40f861d876f142b4ad788e06e0e6892999bdf02158e8d4b6e58e4c9c8e80b0933c95e22` |
| TLSH | `T195145AD3BC12D9BAF84BE73B89470405B130B66310815A33721F747BAF7A0A556B7E86` |
| SSDEEP | `3072:x+RuBteH31wEjVM4t1qwBAHSGHVzjbieLx+IycIfgSu1EssMZc/T03ImIys61X1L:x+FjC4twwqSGPLxycEgfEssMOgh5ojE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_1e4e68d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e4e68d5e61e9c3159621f6e7dfe07d2cb7a42d5d60e5b0949d9a257f4cd9fc3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-24 21:36:47"
  condition:
    hash.sha256(0, filesize) == "1e4e68d5e61e9c3159621f6e7dfe07d2cb7a42d5d60e5b0949d9a257f4cd9fc3"
}
```

### Sample 27: `7c33aadf2aaf9322`

| Field | Value |
|---|---|
| SHA-256 | `7c33aadf2aaf932241116217b5cc7a96575217a8f93ca131e4bf3def72b4b8db` |
| Family label | `unknown` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-24 21:28:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b38a8990c0d4359973374c7c182da69` |
| SHA-1 | `25c9b8821a3f9dca0d58949af4aa91ef0a0a099e` |
| SHA-256 | `7c33aadf2aaf932241116217b5cc7a96575217a8f93ca131e4bf3def72b4b8db` |
| SHA3-384 | `780b2c8649bd1adaa33dfcf300720d5fdd476ebbcadeaddb4e338d37ca0b9e0b2ec9ddbb4bb476d126baee216adc8daa` |
| TLSH | `T19D143951BCA29A12C6C3467BFB4F418D372A635AD2DD7102FC1D6F603F8A46B4A7B181` |
| SSDEEP | `3072:LoWWVznh2W4dBf/4YHKeU5K4ALmhDyfEvxZWTySfu1EssMZc/T03ImIys61X1h52:LJcznh2W4dBfwY/aK4AyhDnATyS8EssH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_7c33aadf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c33aadf2aaf932241116217b5cc7a96575217a8f93ca131e4bf3def72b4b8db"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-24 21:28:34"
  condition:
    hash.sha256(0, filesize) == "7c33aadf2aaf932241116217b5cc7a96575217a8f93ca131e4bf3def72b4b8db"
}
```

### Sample 28: `ddd4725b035f19eb`

| Field | Value |
|---|---|
| SHA-256 | `ddd4725b035f19eb316e983c1e91fb02865fe9878d3b7ca57b1de9000bbd1cc3` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-24 21:16:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cc44396e372fe8c6e35a4424d6ef39a` |
| SHA-1 | `f542b5b4752a3942f0e7350b5485ce109dfeab8c` |
| SHA-256 | `ddd4725b035f19eb316e983c1e91fb02865fe9878d3b7ca57b1de9000bbd1cc3` |
| SHA3-384 | `d9e46ef5fff05fad8f538cc5ff4cfc7322a79de0103c1101d76ab63a96f5fa74cbd37175313d688c2ac65dec8ebf5ef5` |
| TLSH | `T15B140952ACD29B12C6C2457EFB0E514E7313676AD2CE7212FD2C6B703F8A47B0A7A445` |
| TELFHASH | `t148e0c283d92986acbbc22385a1e0e214a9b1f10e08462c84c0d49b0ba723ca1b46a82d` |
| SSDEEP | `6144:7+mOvUk0NhCCTl+6V3FjfXRsIa7FS4sAZAzEssMOgh5ov:HOvUk0NhCCTl+6V3FXaIa7o4KEssMOg+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_ddd4725b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddd4725b035f19eb316e983c1e91fb02865fe9878d3b7ca57b1de9000bbd1cc3"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-24 21:16:42"
  condition:
    hash.sha256(0, filesize) == "ddd4725b035f19eb316e983c1e91fb02865fe9878d3b7ca57b1de9000bbd1cc3"
}
```

### Sample 29: `e87e97d3604ac46b`

| Field | Value |
|---|---|
| SHA-256 | `e87e97d3604ac46b46af03541af99968f268d9cd338d498318d878cb465d8610` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-24 20:56:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1445b5c477b8eb42afac59ece7d00f83` |
| SHA-1 | `9fd877893633f65f28742c1518adc0fbf1d5246b` |
| SHA-256 | `e87e97d3604ac46b46af03541af99968f268d9cd338d498318d878cb465d8610` |
| SHA3-384 | `c168472bb65709ef1b1126381d5c718754aeca1cfe31bd024a14c4f15ba32198f35dacb01b1270db0f3c813c5fff8632` |
| TLSH | `T15DC27D966A867C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15FACD618B1A` |
| SSDEEP | `768:s8vCB+25j6es8Rp9FYpMSUpi+20qUpi+20YQX:s8l25JPd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_e87e97d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e87e97d3604ac46b46af03541af99968f268d9cd338d498318d878cb465d8610"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 20:56:48"
  condition:
    hash.sha256(0, filesize) == "e87e97d3604ac46b46af03541af99968f268d9cd338d498318d878cb465d8610"
}
```

### Sample 30: `4379770bf5e7d2ab`

| Field | Value |
|---|---|
| SHA-256 | `4379770bf5e7d2ab7ff966e7d8cd4a59a3182bac56e1b76bec3255d5278ea703` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-24 20:54:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90637eaa50cc04552dc4126298869f3d` |
| SHA-1 | `b64428eec6616ff93b18c5115937db297f5f428e` |
| SHA-256 | `4379770bf5e7d2ab7ff966e7d8cd4a59a3182bac56e1b76bec3255d5278ea703` |
| SHA3-384 | `07820cca2e42591b09f56a7eab7795557ebb805de290833f384731fe3fb12a08f39ee627f5613ce1814aba0a269e36d1` |
| TLSH | `T1CB047DA38CB36D54D2568479F2268A3D1B13E413424B5E64B8BFC2B40F43D99F2667F4` |
| SSDEEP | `3072:oZKr1U4dttPwtygvdp/Er+34DE+N5YCjWWA6ZR/wu1EssMZc/T03ImIys61X1h5z:oZKr1U4x4tyg/sr+3kE+9yW5ZR/REssW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_4379770b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4379770bf5e7d2ab7ff966e7d8cd4a59a3182bac56e1b76bec3255d5278ea703"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-24 20:54:46"
  condition:
    hash.sha256(0, filesize) == "4379770bf5e7d2ab7ff966e7d8cd4a59a3182bac56e1b76bec3255d5278ea703"
}
```

### Sample 31: `d9970bf3b3d62d91`

| Field | Value |
|---|---|
| SHA-256 | `d9970bf3b3d62d914572bc4dc73d3b71f919411a448e020fc16dc674a19c62ee` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 20:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `765be220a4a7ad7b5ef7385797081616` |
| SHA-256 | `d9970bf3b3d62d914572bc4dc73d3b71f919411a448e020fc16dc674a19c62ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_d9970bf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9970bf3b3d62d914572bc4dc73d3b71f919411a448e020fc16dc674a19c62ee"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 20:52:11"
  condition:
    hash.sha256(0, filesize) == "d9970bf3b3d62d914572bc4dc73d3b71f919411a448e020fc16dc674a19c62ee"
}
```

### Sample 32: `9f125d9a22595089`

| Field | Value |
|---|---|
| SHA-256 | `9f125d9a2259508929f3d321a1db86d7ee381d404ec34be44c096ebbc736b6eb` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-24 20:42:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c027dc77ba6fbc27104f6d185fa45b0` |
| SHA-1 | `ba022b75133742449e75284df7180592df98aa3c` |
| SHA-256 | `9f125d9a2259508929f3d321a1db86d7ee381d404ec34be44c096ebbc736b6eb` |
| SHA3-384 | `762c55351dd8d6da9bb6d617d548bf3ddb748632dfcbf603461b65bdc36907b36a2e591b39ed25167ac27fdc4bf7dcd1` |
| TLSH | `T11B31709E04142A716402C99E7363354C669DE2FB2D9FD7D0EC4E4EA983897CCF1A1F49` |
| SSDEEP | `12:UBMV76BMJ7vk6H7ZsgUg6KL6KPt8uNt6TAxicn6Iix6Ii29s7X76lBuwM6q1576J:+MVsMJ7ZRpYk29kjUXXXPQkUv7m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_9f125d9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f125d9a2259508929f3d321a1db86d7ee381d404ec34be44c096ebbc736b6eb"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-24 20:42:52"
  condition:
    hash.sha256(0, filesize) == "9f125d9a2259508929f3d321a1db86d7ee381d404ec34be44c096ebbc736b6eb"
}
```

### Sample 33: `4ac8325d485cdd1b`

| Field | Value |
|---|---|
| SHA-256 | `4ac8325d485cdd1b00d808223b9e60a6bc7dd62fe409703f3112009f6d737139` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxni386xnxn` |
| File type | `elf` |
| First seen | `2026-08-24 20:37:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9361ae6fd746ffa3863cd7f686286a2e` |
| SHA-1 | `a19374ef1d57f5de3bd58d2b12dcb91fa0001ed5` |
| SHA-256 | `4ac8325d485cdd1b00d808223b9e60a6bc7dd62fe409703f3112009f6d737139` |
| SHA3-384 | `fe77da1862ef1bd4b44b5ae4de37e658e911fc1091bf9953f665d6d5d2e6b93f8f01af31a7113042add74baae6a17c5f` |
| TLSH | `T154C35B82E6A2D0F1E68701B00557E3E68935EA305416CEC6FFA93D71EC717829D9BB1C` |
| TELFHASH | `t1dd4107fa5ea60ce873d49c05d35e1730b909da3b687036aa40f31e7536fad9212b5c35` |
| SSDEEP | `3072:X6tJsoRNjmj1VGCLUZMIV9Sr+QVrxZNio9w:1oRNjmj1VGc3rRioi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_4ac8325d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ac8325d485cdd1b00d808223b9e60a6bc7dd62fe409703f3112009f6d737139"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-08-24 20:37:14"
  condition:
    hash.sha256(0, filesize) == "4ac8325d485cdd1b00d808223b9e60a6bc7dd62fe409703f3112009f6d737139"
}
```

### Sample 34: `2cfab543fa110359`

| Field | Value |
|---|---|
| SHA-256 | `2cfab543fa110359af5b5b1c525091c0dffd77dee1be7b034c3e9194be675a6a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-24 20:37:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e78d104a52b103650df89351edd09729` |
| SHA-1 | `60b0526295e7bdda6c12fcf3d4d547733a10b2f1` |
| SHA-256 | `2cfab543fa110359af5b5b1c525091c0dffd77dee1be7b034c3e9194be675a6a` |
| SHA3-384 | `92ae7687b2ac6ad9783e8c3af0aa38f3b407195debe4ea3853193ebfeb9339328b680b48e782cd37c77aa829b4ebcb91` |
| TLSH | `T1DEC28D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324D42AC3D8A3C719C11F9CD618B1A` |
| SSDEEP | `768:88vCB+25j6es8Rd9FYpMSUpi+20qUpi+20YQX:88l25JLd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_2cfab543
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cfab543fa110359af5b5b1c525091c0dffd77dee1be7b034c3e9194be675a6a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 20:37:00"
  condition:
    hash.sha256(0, filesize) == "2cfab543fa110359af5b5b1c525091c0dffd77dee1be7b034c3e9194be675a6a"
}
```

### Sample 35: `1c31596586ddf65d`

| Field | Value |
|---|---|
| SHA-256 | `1c31596586ddf65d16aec86ddf43df1ca67cfaa43815b9170f031a9efcb0e8dc` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-24 20:36:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0368c69db18cc4bc37485f4b839f85c2` |
| SHA-1 | `1e589e260cd9a95ee8765958f6dfdb931ea7486b` |
| SHA-256 | `1c31596586ddf65d16aec86ddf43df1ca67cfaa43815b9170f031a9efcb0e8dc` |
| SHA3-384 | `a2e41fbaacd4142748ebf011c8c08bd71fd7590688db3d057783e5cc52bb7e93b583ba99ffb9d57937b726e4c50dfeb6` |
| TLSH | `T166934B2129F3A112D6D3A43F879F121AF16279070188C61BBD3E9D6E7F4229077B76E4` |
| TELFHASH | `t1fef09e45fd388b198de27a74ac8803a584035217612387248f98dae4cc3e01aa748d5d` |
| SSDEEP | `1536:MmvvlvH7qN8lGtRrdRJuMA+mdrYQFId9Tu1EssMZcywT03ImIys61XKNAh5ot:MGlyrDJDm7IdBu1EssMZc/T03ImIys6K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_1c315965
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c31596586ddf65d16aec86ddf43df1ca67cfaa43815b9170f031a9efcb0e8dc"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-24 20:36:59"
  condition:
    hash.sha256(0, filesize) == "1c31596586ddf65d16aec86ddf43df1ca67cfaa43815b9170f031a9efcb0e8dc"
}
```

### Sample 36: `eeb0b68d4dd52077`

| Field | Value |
|---|---|
| SHA-256 | `eeb0b68d4dd520776f44644d2da00b3ed3dc55edce73b663b4d4748619065823` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxni386xnxn` |
| File type | `elf` |
| First seen | `2026-08-24 20:36:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75918dcbff1d082be00828a0d6e74b41` |
| SHA-1 | `72b5df02b425432be1679bd256dede393ec86a3e` |
| SHA-256 | `eeb0b68d4dd520776f44644d2da00b3ed3dc55edce73b663b4d4748619065823` |
| SHA3-384 | `cd003cc12916504b1f149c6e01cc1266e944ecd22c298d92fd471e77bb2c6e7e63338f0c009a8ff86f5a01bc389e98a5` |
| TLSH | `T1E6530230A1B3E987C563EB34FE1ED99D9000CF485A123B761BB98159AE71295F71CE23` |
| TELFHASH | `t1ffb01102ccca2c820020802cce0a00afa280ea382c0f322380f82c2aa028e0b2028202` |
| SSDEEP | `1536:xNMwRj1W6DZg6NjH3bvskfQOGpw3Nup6P4Lkg4azH4:/JzW6DZg6NjLvlQbuoo4LGazH4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_eeb0b68d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb0b68d4dd520776f44644d2da00b3ed3dc55edce73b663b4d4748619065823"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-08-24 20:36:58"
  condition:
    hash.sha256(0, filesize) == "eeb0b68d4dd520776f44644d2da00b3ed3dc55edce73b663b4d4748619065823"
}
```

### Sample 37: `fa87d394aeef4050`

| Field | Value |
|---|---|
| SHA-256 | `fa87d394aeef40501a545ec76bc1599c5e4959e9f4b69f1c0f455fbdfbb2b10a` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-24 20:30:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f1c64d723539fd67bc63aa6c6469094` |
| SHA-1 | `327f496d139e0943305c601db81edb96f5335727` |
| SHA-256 | `fa87d394aeef40501a545ec76bc1599c5e4959e9f4b69f1c0f455fbdfbb2b10a` |
| SHA3-384 | `a3ccb5733be594c5aaf2b1cca100fb516d76c9fa123772af2680dede518be0aad889e65a71edae6f774335a3b06075b1` |
| TLSH | `T1FF243B52AAD24A13C5D3177AFBDF41063323A65693CB7302F92CABB43F8625A4E73541` |
| TELFHASH | `t177311f3117359612aeb0da589ce953a7152e82262285ef73de25c5dc540a0abe633c4f` |
| SSDEEP | `6144:sprhAZI1tG8zEYyPJkMfFDPgaPhA+1CLhZ6pEssMOgh5oz+bSpM/9L5:qhAZI1tG8zEYyPJkMNDPgaPhA+1PEss+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_fa87d394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa87d394aeef40501a545ec76bc1599c5e4959e9f4b69f1c0f455fbdfbb2b10a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-24 20:30:58"
  condition:
    hash.sha256(0, filesize) == "fa87d394aeef40501a545ec76bc1599c5e4959e9f4b69f1c0f455fbdfbb2b10a"
}
```

### Sample 38: `c94f29dbdb37f18f`

| Field | Value |
|---|---|
| SHA-256 | `c94f29dbdb37f18fd314fe38571ab19194e35dd4eac957c8710e5ca1e4d50ab0` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-24 20:30:56` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de50b441f5a2a98ce4719cfab17ed110` |
| SHA-256 | `c94f29dbdb37f18fd314fe38571ab19194e35dd4eac957c8710e5ca1e4d50ab0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_c94f29db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c94f29dbdb37f18fd314fe38571ab19194e35dd4eac957c8710e5ca1e4d50ab0"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-24 20:30:56"
  condition:
    hash.sha256(0, filesize) == "c94f29dbdb37f18fd314fe38571ab19194e35dd4eac957c8710e5ca1e4d50ab0"
}
```

### Sample 39: `19646fbbd930cecd`

| Field | Value |
|---|---|
| SHA-256 | `19646fbbd930cecd76c64022dccf8b2a6c3c0d76d577d4ff00f92fa215113ad4` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-24 20:26:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b68cffbba31b52267f154004ec2f080a` |
| SHA-1 | `574985d0d743f1171c2b2b8d5d5aff8ba89d82cd` |
| SHA-256 | `19646fbbd930cecd76c64022dccf8b2a6c3c0d76d577d4ff00f92fa215113ad4` |
| SHA3-384 | `c3fa3fcbb19f6147ebdd26f1cdb4155abdeef52e3481e864df659040df80124a54a21ddbaa547fe794b572131da04ce1` |
| TLSH | `T171235C552A857C14AA98C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AADDA10961D` |
| SSDEEP | `768:5JFWzZx5F9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:DkzIcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_19646fbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19646fbbd930cecd76c64022dccf8b2a6c3c0d76d577d4ff00f92fa215113ad4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-24 20:26:58"
  condition:
    hash.sha256(0, filesize) == "19646fbbd930cecd76c64022dccf8b2a6c3c0d76d577d4ff00f92fa215113ad4"
}
```

### Sample 40: `6ff8c9cabc23696b`

| Field | Value |
|---|---|
| SHA-256 | `6ff8c9cabc23696ba9120a1125520c8928cff24d687cf944b1c3bbe92a00b135` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-08-24 20:25:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b7673a4586fa65d2c12565a79e9e42c` |
| SHA-1 | `9b25e2e51b195ab425a4ad700f6fe90516153266` |
| SHA-256 | `6ff8c9cabc23696ba9120a1125520c8928cff24d687cf944b1c3bbe92a00b135` |
| SHA3-384 | `b6fbc77717e1cd215c4f899d12471e87e0866d9e3140f57daba829187e6601994b0233307c28b3058e07578ea9cc2813` |
| TLSH | `T11AE36BC169A3E0B2EA53897A473B931A5B32D4370219DA11F72E68347F43151E7BB78C` |
| TELFHASH | `t11f5139f52a7e0cdcf750a805e20e6f226d4e577b256037b205b3d83932abd45457b839` |
| SSDEEP | `3072:udKCJfxD7iWRlTw363hnSF7QVzbUjGsu1EssMZc/T03ImIys61X1h5om:1CJfR7r2iOjGVEssMOgh5om` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_6ff8c9ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff8c9cabc23696ba9120a1125520c8928cff24d687cf944b1c3bbe92a00b135"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-24 20:25:00"
  condition:
    hash.sha256(0, filesize) == "6ff8c9cabc23696ba9120a1125520c8928cff24d687cf944b1c3bbe92a00b135"
}
```

### Sample 41: `9a9c5c666ef38446`

| Field | Value |
|---|---|
| SHA-256 | `9a9c5c666ef384460c68200de9badf75910be4dc2101b8eb62448ccd52cf2e81` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-24 20:24:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1430d331e5f28684b7cf8214f9abf6c5` |
| SHA-1 | `7b62bf03a450639986c9b9c6aa8dce64d2bec4e8` |
| SHA-256 | `9a9c5c666ef384460c68200de9badf75910be4dc2101b8eb62448ccd52cf2e81` |
| SHA3-384 | `0d19a67dae5509d2358bc3e2cf55e8835fcfa225026507afbe6533478f5308080f11a2c3be93e14d7b0dd69a45bbcf31` |
| TLSH | `T1CC144B02776D0403D3632DB43B3B13D1939FE4A321A4E604790FAA996FB2D31A696DDD` |
| SSDEEP | `3072:sekY2fVanUgtQNRxidVCsneTsSxn0u1EssMZc/T03ImIys61X1h5oxuy:sD1VaUgtQbxEVFneQWndEssMOgh5oxuy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_9a9c5c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a9c5c666ef384460c68200de9badf75910be4dc2101b8eb62448ccd52cf2e81"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-24 20:24:59"
  condition:
    hash.sha256(0, filesize) == "9a9c5c666ef384460c68200de9badf75910be4dc2101b8eb62448ccd52cf2e81"
}
```

### Sample 42: `a458d1a2770a455c`

| Field | Value |
|---|---|
| SHA-256 | `a458d1a2770a455c1360388fd13bcffd69989835c3c0993917d863a996566b5a` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-24 20:16:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1aa080ee9caaf7ae28aed2d161ee743` |
| SHA-1 | `826da7078016bdee42a0b1119d2cfdeac4690a7a` |
| SHA-256 | `a458d1a2770a455c1360388fd13bcffd69989835c3c0993917d863a996566b5a` |
| SHA3-384 | `8f52f79516b22811790d0db82e88de288fff9d66891df4b941a81157b5fc8ef9cdb7123542a7990c4ed74fea93344a84` |
| TLSH | `T130146D1378E190FDC9D7C1398B9FA01AD632F41B1128B21A774D7E652F4EE306BAD684` |
| TELFHASH | `t1bf51cc753e593884b2d7f763730ec659f835191008e574e6ae7758e28a123c80db3463` |
| SSDEEP | `3072:jtb5AbwCqMg8lKTouDZ1Q2M/vz7Re/6RAGRznlu1EssMZc/T03ImIys61X1h5oy:jt6ERJo+C5e/i5n2EssMOgh5oy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_a458d1a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a458d1a2770a455c1360388fd13bcffd69989835c3c0993917d863a996566b5a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-24 20:16:55"
  condition:
    hash.sha256(0, filesize) == "a458d1a2770a455c1360388fd13bcffd69989835c3c0993917d863a996566b5a"
}
```

### Sample 43: `f077cc7061c6c9f0`

| Field | Value |
|---|---|
| SHA-256 | `f077cc7061c6c9f0c280ec6507a74b00887f1ebe1047d58ddd0160f7de4fc70c` |
| Family label | `unknown` |
| File name | `Payroll_statement.pdf.pdf` |
| File type | `pdf` |
| First seen | `2026-08-24 19:55:17` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5321dfbea00de03d28e2d9754fd8f7bd` |
| SHA-1 | `feb433d92db8d76e17413194bc2703359cd2e83f` |
| SHA-256 | `f077cc7061c6c9f0c280ec6507a74b00887f1ebe1047d58ddd0160f7de4fc70c` |
| SHA3-384 | `457a7c503d0658771ffb8e77e303170f78d9227813390d4b880147522ee4f959899251ded84a15ad51ee32e9ba569054` |
| TLSH | `T1D833E11D507619CDE4508EA65A2BF3388AC674A2E7D43D490C78535C148FF20AAFBCDE` |
| SSDEEP | `1536:g2YoK911CATL9YjVzdsHmwelqnGJ273bH53:g2u95TYqqq627d3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `pdf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_f077cc70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f077cc7061c6c9f0c280ec6507a74b00887f1ebe1047d58ddd0160f7de4fc70c"
    family = "unknown"
    file_name = "Payroll_statement.pdf.pdf"
    file_type = "pdf"
    first_seen = "2026-08-24 19:55:17"
  condition:
    hash.sha256(0, filesize) == "f077cc7061c6c9f0c280ec6507a74b00887f1ebe1047d58ddd0160f7de4fc70c"
}
```

### Sample 44: `6234c22a90248540`

| Field | Value |
|---|---|
| SHA-256 | `6234c22a90248540b7e12261de5ffb94426d85b08694e9e06d72a644ce215e0e` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 19:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6a693d352c813fc2d8e7121de125ecf` |
| SHA-256 | `6234c22a90248540b7e12261de5ffb94426d85b08694e9e06d72a644ce215e0e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_6234c22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6234c22a90248540b7e12261de5ffb94426d85b08694e9e06d72a644ce215e0e"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 19:52:11"
  condition:
    hash.sha256(0, filesize) == "6234c22a90248540b7e12261de5ffb94426d85b08694e9e06d72a644ce215e0e"
}
```

### Sample 45: `a4e921a7afacd5c9`

| Field | Value |
|---|---|
| SHA-256 | `a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684` |
| Family label | `AsyncRAT` |
| File name | `FLY88APP.exe` |
| File type | `exe` |
| First seen | `2026-08-24 19:51:59` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc02159ff52160379afd976481ab54d9` |
| SHA-1 | `f406685a84605b12d907a3571f68619d8bb74ada` |
| SHA-256 | `a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684` |
| SHA3-384 | `1ecf8ddacd48f2b58e2106f4929a577d97d70d95f2ff99fbacb8ac117091190624a379b53b46858054de1b7bf3d3c8cd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T123C22B0833E4C572E2FD4ABE8C33E5108B79A55B9A23D75A5FC490AD29237CD8A14FD4` |
| SSDEEP | `384:kgSVEEMiNPWmvHtZARPn9jLH9qbuUsQbQxnCJfJBndnjJVKA:kgSVXFdt+vIbgBiBncA` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_045_a4e921a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684"
    family = "AsyncRAT"
    file_name = "FLY88APP.exe"
    file_type = "exe"
    first_seen = "2026-08-24 19:51:59"
  condition:
    hash.sha256(0, filesize) == "a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684"
}
```

### Sample 46: `74f92110966d46b4`

| Field | Value |
|---|---|
| SHA-256 | `74f92110966d46b49dab95189364618795e12e8895f0246e37e7e7b8f67346cf` |
| Family label | `unknown` |
| File name | `Invoice.ps1` |
| File type | `ps1` |
| First seen | `2026-08-24 19:49:00` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16dc08fefecd9065e8cd1a010fcd7ed6` |
| SHA-1 | `ec700c7ccbadd4a19d1feff0450692a075123085` |
| SHA-256 | `74f92110966d46b49dab95189364618795e12e8895f0246e37e7e7b8f67346cf` |
| SHA3-384 | `2d451fbd4d20cd44ce80411764010d6ec99b0f36fd4160238208c669e5f6248d42bee5433bb15dbd966a603cb4f06476` |
| TLSH | `T19D4733219F6AADBE4AAC933C30BF5F1D2BA00FC59458E5EB07D460C7025EF41456BC6A` |
| SSDEEP | `49152:v14dAhVqR14DQmXuiS5vp93QwGSLFohsuJ2d/NiR3Jl4tb0R3CeIgpzDN9ZaIJ+l:G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_74f92110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f92110966d46b49dab95189364618795e12e8895f0246e37e7e7b8f67346cf"
    family = "unknown"
    file_name = "Invoice.ps1"
    file_type = "ps1"
    first_seen = "2026-08-24 19:49:00"
  condition:
    hash.sha256(0, filesize) == "74f92110966d46b49dab95189364618795e12e8895f0246e37e7e7b8f67346cf"
}
```

### Sample 47: `d4d2b7e99fdc2ce7`

| Field | Value |
|---|---|
| SHA-256 | `d4d2b7e99fdc2ce7eca14986a189d974bb24e42fea69b4bf6424301146d869bd` |
| Family label | `unknown` |
| File name | `Invoice.zip` |
| File type | `zip` |
| First seen | `2026-08-24 19:48:47` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ca5a606709ffe95c5e826d176f5dc59` |
| SHA-1 | `24f0cc1e3394cb1058fa6e9589246f3d3be42d41` |
| SHA-256 | `d4d2b7e99fdc2ce7eca14986a189d974bb24e42fea69b4bf6424301146d869bd` |
| SHA3-384 | `87b41aa61ad9cbfb52b88ce494e487c4251708c8b0bec08769e34f285d9486d51d0221fc111fe8f1211d05eabe6edeeb` |
| TLSH | `T1A701863683643139CA7270302C118701402F45835314A37351F729952E5AB92132D0A0` |
| SSDEEP | `12:5jO4Nr5Yim1Mgj3HOw0a0lUwV55lycpd90vUMEsP77ZF/g7rJPdNQuaz:9DNaMaXOwCUu8cz90vUMEK/ZKZPdip` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_d4d2b7e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4d2b7e99fdc2ce7eca14986a189d974bb24e42fea69b4bf6424301146d869bd"
    family = "unknown"
    file_name = "Invoice.zip"
    file_type = "zip"
    first_seen = "2026-08-24 19:48:47"
  condition:
    hash.sha256(0, filesize) == "d4d2b7e99fdc2ce7eca14986a189d974bb24e42fea69b4bf6424301146d869bd"
}
```

### Sample 48: `3e9ca509f6c5bdaa`

| Field | Value |
|---|---|
| SHA-256 | `3e9ca509f6c5bdaaac14abdb6ab28f3cce3fd4efee65f5e0ddbeb4e8d7833cf6` |
| Family label | `unknown` |
| File name | `main.py` |
| File type | `unknown` |
| First seen | `2026-08-24 19:47:57` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `315867ca3852b12a03b8d0f5b2efff7d` |
| SHA-256 | `3e9ca509f6c5bdaaac14abdb6ab28f3cce3fd4efee65f5e0ddbeb4e8d7833cf6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_3e9ca509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e9ca509f6c5bdaaac14abdb6ab28f3cce3fd4efee65f5e0ddbeb4e8d7833cf6"
    family = "unknown"
    file_name = "main.py"
    file_type = "unknown"
    first_seen = "2026-08-24 19:47:57"
  condition:
    hash.sha256(0, filesize) == "3e9ca509f6c5bdaaac14abdb6ab28f3cce3fd4efee65f5e0ddbeb4e8d7833cf6"
}
```

### Sample 49: `cee5f4234344c497`

| Field | Value |
|---|---|
| SHA-256 | `cee5f4234344c49796812e11c5b14c68089c09ee1c772e71ff1cc296a26925ca` |
| Family label | `unknown` |
| File name | `Invoice.lnk` |
| File type | `lnk` |
| First seen | `2026-08-24 19:46:47` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5fc0547a1a8802d3196abd82c35ff6c` |
| SHA-1 | `59828c00d5f8cd488184d85c4ef17aaca0830c3f` |
| SHA-256 | `cee5f4234344c49796812e11c5b14c68089c09ee1c772e71ff1cc296a26925ca` |
| SHA3-384 | `ab0deaf6df8a3df97227aafcb2cbb0b09c262b55841329c9bd47d3ae0a8d2017652eb9e9c9f240f4f43940daebfc05b6` |
| TLSH | `T177410A146AE60714E2B3CB3D6CBAF21189767C46EE51CFDD019191885424614F975F3F` |
| SSDEEP | `24:8E/BHYVKVWf+/CW55irVueUMkW+wlRgUoIbPOF3+/QT4I02YhX:8A5acoueHGwlRgBIbPOF3fMI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_cee5f423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee5f4234344c49796812e11c5b14c68089c09ee1c772e71ff1cc296a26925ca"
    family = "unknown"
    file_name = "Invoice.lnk"
    file_type = "lnk"
    first_seen = "2026-08-24 19:46:47"
  condition:
    hash.sha256(0, filesize) == "cee5f4234344c49796812e11c5b14c68089c09ee1c772e71ff1cc296a26925ca"
}
```

### Sample 50: `ab4c9f360c6d5f3e`

| Field | Value |
|---|---|
| SHA-256 | `ab4c9f360c6d5f3e0d9a90c713d4ccfb2780ef52da41a028d6516cf9ea5e9238` |
| Family label | `unknown` |
| File name | `totolink.sh` |
| File type | `sh` |
| First seen | `2026-08-24 19:39:44` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a84400795f3aee784c2b348d6b7fec9` |
| SHA-1 | `37972ddd9e93ad2399c871253753cf12ffc94009` |
| SHA-256 | `ab4c9f360c6d5f3e0d9a90c713d4ccfb2780ef52da41a028d6516cf9ea5e9238` |
| SHA3-384 | `43eea951b9ba37329e3d7d002870ab35f62203c95d10db0cf71a53630ca735763299541b0093d8e91751fff7857bad91` |
| TLSH | `T17941FAFE7052B762DFA68E05F260F674B217E1D571CF3A8CF98C6993CC46840726AA01` |
| SSDEEP | `48:4CCpOCmhpi0p2BpaUGzp2V22G9TezXqD90ooW6urVr4xz4jpyVdhmh:yQFcAf36urVr4xz4jpyVdhmh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_ab4c9f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4c9f360c6d5f3e0d9a90c713d4ccfb2780ef52da41a028d6516cf9ea5e9238"
    family = "unknown"
    file_name = "totolink.sh"
    file_type = "sh"
    first_seen = "2026-08-24 19:39:44"
  condition:
    hash.sha256(0, filesize) == "ab4c9f360c6d5f3e0d9a90c713d4ccfb2780ef52da41a028d6516cf9ea5e9238"
}
```

### Sample 51: `3426e4a772946d9a`

| Field | Value |
|---|---|
| SHA-256 | `3426e4a772946d9aa423cc2332a28ea755e91c8b445c50e29c465c72562d9c30` |
| Family label | `unknown` |
| File name | `tplinkrouter.sh` |
| File type | `sh` |
| First seen | `2026-08-24 19:39:25` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfbfc61595a3b2eae1d9601cefb24da5` |
| SHA-1 | `3166a5aa98591576193fcb06b2dc6ac0663b4df3` |
| SHA-256 | `3426e4a772946d9aa423cc2332a28ea755e91c8b445c50e29c465c72562d9c30` |
| SHA3-384 | `86b05465bc9b0aea3afc86d20d38dc64519953de8560ec7b168f76e5125ca8329c62e0bc17899781cf3615facac014f5` |
| TLSH | `T18641FBFD7052B703DFB68E05F260E674B21BE1D571CF268CF88C6853CC4694076AAA01` |
| SSDEEP | `48:4CCpOCmhpi0p2BpaUGzp2V22G9TezXqD90ooWt0ui0I0rH000zH0a0M0F0I0Q0kp:yQFcAf3uu/JrUNzUXFmJx9SN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_3426e4a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3426e4a772946d9aa423cc2332a28ea755e91c8b445c50e29c465c72562d9c30"
    family = "unknown"
    file_name = "tplinkrouter.sh"
    file_type = "sh"
    first_seen = "2026-08-24 19:39:25"
  condition:
    hash.sha256(0, filesize) == "3426e4a772946d9aa423cc2332a28ea755e91c8b445c50e29c465c72562d9c30"
}
```

### Sample 52: `7b331a01b8e0e31e`

| Field | Value |
|---|---|
| SHA-256 | `7b331a01b8e0e31ed406f358502711b619b618e5e2dd02d48f1b54e8a6030580` |
| Family label | `unknown` |
| File name | `log` |
| File type | `unknown` |
| First seen | `2026-08-24 19:31:15` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03aead7083c7d32544ae568591750c78` |
| SHA-256 | `7b331a01b8e0e31ed406f358502711b619b618e5e2dd02d48f1b54e8a6030580` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_7b331a01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b331a01b8e0e31ed406f358502711b619b618e5e2dd02d48f1b54e8a6030580"
    family = "unknown"
    file_name = "log"
    file_type = "unknown"
    first_seen = "2026-08-24 19:31:15"
  condition:
    hash.sha256(0, filesize) == "7b331a01b8e0e31ed406f358502711b619b618e5e2dd02d48f1b54e8a6030580"
}
```

### Sample 53: `057d3ea58a5f5bc5`

| Field | Value |
|---|---|
| SHA-256 | `057d3ea58a5f5bc53d47386869544f8fd692403bc029a24db9ed26c587366b58` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-24 19:13:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `046241c30c2b7c189dcdf919ea26a271` |
| SHA-1 | `d8a882abe7e3b92c05966fe8e3d06ecb8417bb6a` |
| SHA-256 | `057d3ea58a5f5bc53d47386869544f8fd692403bc029a24db9ed26c587366b58` |
| SHA3-384 | `0bb2ced1f127d83376676d3028c971302a2dffbfff552b411c8db151f8a5e786ee57daaadea250d8af0ab3600fa860dd` |
| TLSH | `T1E5733B56FC814A23C6C1127BF76E468D3B2653E8E2DA72039E259F3133C751B0D6B895` |
| TELFHASH | `t1bf4143b1e7b40bdc67c0c704c24a9265aeb4316d771034a38b2d978b92d3bc1b11e42b` |
| SSDEEP | `1536:uB/VU93ilj19ZBpCO72Rbu1U+qhxp8f8vNT:uB/VBBpCO72RDRZNT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_057d3ea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057d3ea58a5f5bc53d47386869544f8fd692403bc029a24db9ed26c587366b58"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-24 19:13:24"
  condition:
    hash.sha256(0, filesize) == "057d3ea58a5f5bc53d47386869544f8fd692403bc029a24db9ed26c587366b58"
}
```

### Sample 54: `b20f09da61ed52f5`

| Field | Value |
|---|---|
| SHA-256 | `b20f09da61ed52f5603e0c549a5b3880e32e4d34ccaf3f4b1628c76a939e799b` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-24 19:13:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f014db52e5bbb144e4be521bf278176` |
| SHA-1 | `7f9a412bdb37af235c4c9b40e38649b849a7a716` |
| SHA-256 | `b20f09da61ed52f5603e0c549a5b3880e32e4d34ccaf3f4b1628c76a939e799b` |
| SHA3-384 | `a848cfcd4392d8256bc5af8cdd85737b5f433bdf846feb409222844bcd9105643aaec0d5a623d7ad76a20b857ee66cb9` |
| TLSH | `T141132986FCC24A3FC2C013B9A66E5A4E3761E3E4D2CB76079E54577236C620F1D6AD84` |
| TELFHASH | `t1e4e06840fc755e1854e76570dcdc47b095012223606a4b20cf55dae0883f110e30ce4d` |
| SSDEEP | `768:XG2/l2Q2SsD3pDi9ZbyE2hk4G+6ZQ+QVgOJUCmJdtBNCw3oOM:X3+SsDUJn2hPq8VgOdGP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_b20f09da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20f09da61ed52f5603e0c549a5b3880e32e4d34ccaf3f4b1628c76a939e799b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-24 19:13:22"
  condition:
    hash.sha256(0, filesize) == "b20f09da61ed52f5603e0c549a5b3880e32e4d34ccaf3f4b1628c76a939e799b"
}
```

### Sample 55: `0fcb8cddfed9c70b`

| Field | Value |
|---|---|
| SHA-256 | `0fcb8cddfed9c70b99e202646ca6dc82745685c5ab12db933a93f17ac6471a5b` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-24 19:12:58` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87e936e45862b3025c7d0b9059beb6e1` |
| SHA-1 | `4684bf196eef91778e9e8430cd70f6fd6620007a` |
| SHA-256 | `0fcb8cddfed9c70b99e202646ca6dc82745685c5ab12db933a93f17ac6471a5b` |
| SHA3-384 | `617c54c2369736cbe8f992f9471c19aa16fb078f81d261009bc5db305a7686ae8b78a49d8ef18939cff4ba92c8e3748d` |
| TLSH | `T134F2E1603709BCB6CD6095B2EEF1CF46F36A93B9D1FA312915000A54ECE661298F53CA` |
| SSDEEP | `768:6JTKmOVP3WWkPgb7lPBIqxwQEECBah3zGK0weMs3Uoz9:6AmO4POPN5Evo3F0XJz9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_0fcb8cdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fcb8cddfed9c70b99e202646ca6dc82745685c5ab12db933a93f17ac6471a5b"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-24 19:12:58"
  condition:
    hash.sha256(0, filesize) == "0fcb8cddfed9c70b99e202646ca6dc82745685c5ab12db933a93f17ac6471a5b"
}
```

### Sample 56: `9bc48e9fbc56e1b9`

| Field | Value |
|---|---|
| SHA-256 | `9bc48e9fbc56e1b9c9643f1221d518b85498be7ced8dd40301194e7a63a1fbb1` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-24 19:12:58` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75296fbb05aa05c98e386a7c7edd048c` |
| SHA-1 | `ef30b2d6a97478bbb4de9893d84c5ed10aad6835` |
| SHA-256 | `9bc48e9fbc56e1b9c9643f1221d518b85498be7ced8dd40301194e7a63a1fbb1` |
| SHA3-384 | `353e9f5b2bc34f5b820c89d347c23cf4796dee9cff1208388ec9ccc7c8d74e28aa1f2f5c172fc7f765366826e349990d` |
| TLSH | `T18492D16F9454A0C4D6614837E6ECDACBA2B60BFDE3F4307517A85A2CF26624023B605F` |
| SSDEEP | `384:y3CFDQy54M7zLnmZFiPThj6r8CKozfdchYC+Gyx2QSHWOCrjchymdGUop5htm:qCmyqM7zLnmZQLh+IWfdzFG/QPOCHcsk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_9bc48e9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bc48e9fbc56e1b9c9643f1221d518b85498be7ced8dd40301194e7a63a1fbb1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-24 19:12:58"
  condition:
    hash.sha256(0, filesize) == "9bc48e9fbc56e1b9c9643f1221d518b85498be7ced8dd40301194e7a63a1fbb1"
}
```

### Sample 57: `880a9ea4c0bfcff6`

| Field | Value |
|---|---|
| SHA-256 | `880a9ea4c0bfcff656613559449a906f3da211c977fb8e29927b33322ccdd6dc` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-08-24 19:12:57` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c60fa779002232fde58108a99a918e6f` |
| SHA-1 | `5657b5726a71593deb1ac243ef625a98be33c26a` |
| SHA-256 | `880a9ea4c0bfcff656613559449a906f3da211c977fb8e29927b33322ccdd6dc` |
| SHA3-384 | `a16587ee00bd8b3f29893053bc59402cc0804fb0fef71883dceb1f1388e6f9ee35c3dd1dc71c10b495175dcefffaf8a0` |
| TLSH | `T1C5B3AEEBF64715A2C85243F013C79F8E3E2323909E57A4E76D1E267B15760DB1D0AB81` |
| SSDEEP | `1536:pkA9afIgfNMW3zC8aRGGTtJM/qrlpmxJ6nDgJe/LWW:6fIw3e8ZE3MYlphDgJeq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_880a9ea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "880a9ea4c0bfcff656613559449a906f3da211c977fb8e29927b33322ccdd6dc"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-24 19:12:57"
  condition:
    hash.sha256(0, filesize) == "880a9ea4c0bfcff656613559449a906f3da211c977fb8e29927b33322ccdd6dc"
}
```

### Sample 58: `c722abf3b2b1c116`

| Field | Value |
|---|---|
| SHA-256 | `c722abf3b2b1c1167babcee38fb6ae40369e3e4bf5f16c3940647234a89a2987` |
| Family label | `unknown` |
| File name | `t.sh` |
| File type | `sh` |
| First seen | `2026-08-24 19:12:56` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd7c06f2de324054ca0b86042539e86b` |
| SHA-1 | `e3a4b04eade0f53eeb6abdf778006932a84ea9df` |
| SHA-256 | `c722abf3b2b1c1167babcee38fb6ae40369e3e4bf5f16c3940647234a89a2987` |
| SHA3-384 | `5aee90c0ece0af58a43ad196554e4e1eda58cd086f84ef4e23bd04956e8debb615548087ef4c8fe4ed64d18b3e3590a7` |
| TLSH | `T16941D1E8A460F6A3F1ADEE25722D92944442989F608D3E0DDD82BD31C8CC814F1ECF16` |
| SSDEEP | `48:QJCyv7vsM7cHzV1HzTtLHYaH0KCrj1XkCqxCUP9PGw9PRftyGY/GsnlBYAB5mfZz:QuhkIdLdpvjsPVM84` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_c722abf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c722abf3b2b1c1167babcee38fb6ae40369e3e4bf5f16c3940647234a89a2987"
    family = "unknown"
    file_name = "t.sh"
    file_type = "sh"
    first_seen = "2026-08-24 19:12:56"
  condition:
    hash.sha256(0, filesize) == "c722abf3b2b1c1167babcee38fb6ae40369e3e4bf5f16c3940647234a89a2987"
}
```

### Sample 59: `60c471550e9b223e`

| Field | Value |
|---|---|
| SHA-256 | `60c471550e9b223efbf44106125c6e97c9132f62d6383f13c63d5a5d15962c9c` |
| Family label | `unknown` |
| File name | `pure.dat` |
| File type | `unknown` |
| First seen | `2026-08-24 19:10:48` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5606d1d4f7f3a3bbb0cb0a3d21423f96` |
| SHA-256 | `60c471550e9b223efbf44106125c6e97c9132f62d6383f13c63d5a5d15962c9c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_60c47155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60c471550e9b223efbf44106125c6e97c9132f62d6383f13c63d5a5d15962c9c"
    family = "unknown"
    file_name = "pure.dat"
    file_type = "unknown"
    first_seen = "2026-08-24 19:10:48"
  condition:
    hash.sha256(0, filesize) == "60c471550e9b223efbf44106125c6e97c9132f62d6383f13c63d5a5d15962c9c"
}
```

### Sample 60: `c1353b26a025f7cb`

| Field | Value |
|---|---|
| SHA-256 | `c1353b26a025f7cb9c5b232f87e9d1f40ae92f87ceca592e6326f1296f419ca1` |
| Family label | `unknown` |
| File name | `boss.bat` |
| File type | `bat` |
| First seen | `2026-08-24 19:10:48` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d6bf691e97bc84b9e8336a71999300c` |
| SHA-1 | `25aa2de8cc67542647812e4b6d057064e985a92b` |
| SHA-256 | `c1353b26a025f7cb9c5b232f87e9d1f40ae92f87ceca592e6326f1296f419ca1` |
| SHA3-384 | `d0ec34e7aa4ce780e5c5093354bb37c06b22058f2af4acabc59c80a1cb78eac3a6a909af250cf0fd25cb16aa0e2cb831` |
| TLSH | `T10FF0F46A041A35378B23CD28CB484646B22BEA8098D2374BF2A00D1AA801E8273952E3` |
| SSDEEP | `12:381kUM8YFEqROpdzh3g9ivFU1AwTh3lHFU1Alh3QHFU1AyGh323FU1A2wh34r0Ae:3D8Y+M4dzxg9mS1A+xBS1AlxQS1ABxgH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_c1353b26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1353b26a025f7cb9c5b232f87e9d1f40ae92f87ceca592e6326f1296f419ca1"
    family = "unknown"
    file_name = "boss.bat"
    file_type = "bat"
    first_seen = "2026-08-24 19:10:48"
  condition:
    hash.sha256(0, filesize) == "c1353b26a025f7cb9c5b232f87e9d1f40ae92f87ceca592e6326f1296f419ca1"
}
```

### Sample 61: `582988ffe1334f23`

| Field | Value |
|---|---|
| SHA-256 | `582988ffe1334f235fc20667fe67538e50f2a918994126c0fa284bfa45e62c44` |
| Family label | `unknown` |
| File name | `bot_arm` |
| File type | `elf` |
| First seen | `2026-08-24 19:05:07` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0aa3079bd91ef7080e5340584995f705` |
| SHA-1 | `bf5526aaa0ac3e7a9bb21633f5050fb129d4b0e3` |
| SHA-256 | `582988ffe1334f235fc20667fe67538e50f2a918994126c0fa284bfa45e62c44` |
| SHA3-384 | `7d2b2a3d700e6c85e7a6ad45800417a0b14953f0455d9a99bd5ba2e889ccb789b3469d8f61c00d58e80e285a51449a69` |
| TLSH | `T140C44A55F880DFA1C6C129B6F64D86AC33174779D2E772068A258B343BE786B0F3B641` |
| TELFHASH | `t1dbd0a7556cac1ae4f2c0631844354b3f5bf724cc07506629472eb9ef0651dc27515077` |
| SSDEEP | `12288:GLmSyud7z3GZdqEvee14fX7coB6r+Ar6pO/cg:pHGXWJv714fX7cr+Ag` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_582988ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "582988ffe1334f235fc20667fe67538e50f2a918994126c0fa284bfa45e62c44"
    family = "unknown"
    file_name = "bot_arm"
    file_type = "elf"
    first_seen = "2026-08-24 19:05:07"
  condition:
    hash.sha256(0, filesize) == "582988ffe1334f235fc20667fe67538e50f2a918994126c0fa284bfa45e62c44"
}
```

### Sample 62: `9bd6b5300b97ab25`

| Field | Value |
|---|---|
| SHA-256 | `9bd6b5300b97ab253ea6f3377176f5658f9f78bea5d534fdbe71a24ce96831f9` |
| Family label | `unknown` |
| File name | `z28scan_copy_20260824085.vbs` |
| File type | `vbs` |
| First seen | `2026-08-24 19:01:23` |
| Reporter | `fabiodemartin` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0bf5139aa5276a5e0c232c148302bb3` |
| SHA-1 | `87239d0c2b9aa328963ae635608519af23458a5d` |
| SHA-256 | `9bd6b5300b97ab253ea6f3377176f5658f9f78bea5d534fdbe71a24ce96831f9` |
| SHA3-384 | `58b98f9d617031433e9e24b1937fb8476a5b763faae2d0dda368f02afbd36e4aa8b5f1fe42a134fd8c356689c677e764` |
| TLSH | `T181554BBCCAA672FA5BEC07821D3126CE4086985721259F7B21CFDF1DEEA5B4C0C93915` |
| SSDEEP | `768:YShJ6vYSLFJZKrdCPwjrXUdvvODXpISo6rNxMVHbMjTT+hoShGucCzFdLyJ5Pk6K:wX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_9bd6b530
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd6b5300b97ab253ea6f3377176f5658f9f78bea5d534fdbe71a24ce96831f9"
    family = "unknown"
    file_name = "z28scan_copy_20260824085.vbs"
    file_type = "vbs"
    first_seen = "2026-08-24 19:01:23"
  condition:
    hash.sha256(0, filesize) == "9bd6b5300b97ab253ea6f3377176f5658f9f78bea5d534fdbe71a24ce96831f9"
}
```

### Sample 63: `d28dc0f5aed61ada`

| Field | Value |
|---|---|
| SHA-256 | `d28dc0f5aed61adab3547ea9ffba04b4280460a80ed1181b27de4836c4ca655a` |
| Family label | `RemcosRAT` |
| File name | `rNo0998006967505633.vbe` |
| File type | `vbe` |
| First seen | `2026-08-24 19:01:11` |
| Reporter | `fabiodemartin` |
| Tags | `RemcosRAT, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `450cf39e41e6a5073255ad52311fa404` |
| SHA-1 | `35da7e4697286dcf6ad1bb2dbb96bbf449129bfb` |
| SHA-256 | `d28dc0f5aed61adab3547ea9ffba04b4280460a80ed1181b27de4836c4ca655a` |
| SHA3-384 | `0cb32c38db612f2b5ceecd954d5996fb3ce83581fb9b370b0f271e85425bdd813b210b13e1c789de4b5968d168b63eb0` |
| TLSH | `T127538FA21F28C0E32D5DB05860C1DFEE86767127B9B94D0717649BA2CEBD1CB3E855C2` |
| SSDEEP | `768:NF0vBjjL4Z2zYUR9/4X2MJx/ptFzvBa6gZkabcSxgObucgSKTonmYN3Jw6bYcZEV:ojM9Kms8gTOP` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_063_d28dc0f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d28dc0f5aed61adab3547ea9ffba04b4280460a80ed1181b27de4836c4ca655a"
    family = "RemcosRAT"
    file_name = "rNo0998006967505633.vbe"
    file_type = "vbe"
    first_seen = "2026-08-24 19:01:11"
  condition:
    hash.sha256(0, filesize) == "d28dc0f5aed61adab3547ea9ffba04b4280460a80ed1181b27de4836c4ca655a"
}
```

### Sample 64: `f5b850be90148056`

| Field | Value |
|---|---|
| SHA-256 | `f5b850be90148056aa4dcc36802479a73a2966a07e7e66562feeee013ed70de5` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-08-24 18:52:16` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48b2c96b2b5c92e1d7792a60af223b53` |
| SHA-1 | `21b797c7852b64c2da9554290ef4c3a0f406d7d2` |
| SHA-256 | `f5b850be90148056aa4dcc36802479a73a2966a07e7e66562feeee013ed70de5` |
| SHA3-384 | `57c5cd60df840d1ad2d8643097e930ba765ba2439e41acbdbaabe28787fccc653f3cc1286239940c0c985a3291aaa958` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1DAC57B43BC8161B0D999E336D4750251F730B8481B3573D72E46BBB82E32BE51E7AB98` |
| SSDEEP | `49152:3qrhItLA47PFxS1JAdcq6ORxranSgvcU8HnuD1Ac:aU7jIAdcq6gx5jW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_f5b850be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b850be90148056aa4dcc36802479a73a2966a07e7e66562feeee013ed70de5"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:52:16"
  condition:
    hash.sha256(0, filesize) == "f5b850be90148056aa4dcc36802479a73a2966a07e7e66562feeee013ed70de5"
}
```

### Sample 65: `d48258e2d336c986`

| Field | Value |
|---|---|
| SHA-256 | `d48258e2d336c98631c4f0936bdbd4c1aeb850f1da2c5a097a38a6ba908910af` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 18:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `598e337e9731b849c7ddc813c33d29cd` |
| SHA-256 | `d48258e2d336c98631c4f0936bdbd4c1aeb850f1da2c5a097a38a6ba908910af` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_d48258e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d48258e2d336c98631c4f0936bdbd4c1aeb850f1da2c5a097a38a6ba908910af"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 18:52:11"
  condition:
    hash.sha256(0, filesize) == "d48258e2d336c98631c4f0936bdbd4c1aeb850f1da2c5a097a38a6ba908910af"
}
```

### Sample 66: `a10cfa5f8b511c28`

| Field | Value |
|---|---|
| SHA-256 | `a10cfa5f8b511c281adebc60c0c34b62f37dd589c4cb136ca578d82c0067a9d2` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-24 18:51:09` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dabee65d0f22b4bf8f10342b72714e20` |
| SHA-1 | `2285312da4e0508f043bc590ff5b0c31478d55ee` |
| SHA-256 | `a10cfa5f8b511c281adebc60c0c34b62f37dd589c4cb136ca578d82c0067a9d2` |
| SHA3-384 | `f59d3baedd016e5702f60ff30a2c10ab45b563d3ff9882a45ed38cf81a056c51ad985caefce88a9a901948d33f7fb31d` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T11EB63389B3A604FCE89E913F92E9825767A270B7436883CB67E00D514F272D5EF35B11` |
| SSDEEP | `196608:wOE0W8/LaeA1HeT39IigQTauDXURuA3dSYEQVdlCE7:wOjW8o1+TtIiL2uARuA3dS9QVrCE7` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_a10cfa5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a10cfa5f8b511c281adebc60c0c34b62f37dd589c4cb136ca578d82c0067a9d2"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:51:09"
  condition:
    hash.sha256(0, filesize) == "a10cfa5f8b511c281adebc60c0c34b62f37dd589c4cb136ca578d82c0067a9d2"
}
```

### Sample 67: `5bb97826cac1543d`

| Field | Value |
|---|---|
| SHA-256 | `5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135` |
| Family label | `unknown` |
| File name | `5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135.exe` |
| File type | `exe` |
| First seen | `2026-08-24 18:43:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2645519c94b369f0a36c7fbda5adac54` |
| SHA-1 | `f1c434bd1c556e5f10d047704a597719817b0643` |
| SHA-256 | `5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135` |
| SHA3-384 | `43edcc656e665284ecf732a7f188e7860c7f2cf3975f46cea5d12ac682decbb543bd9c58dea438c739ad958fbb81af5f` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1CCD52299B8BA15B9E432C3F18FD2F0BDF0693B824EB18D5B7ACC5A004D125552C7A376` |
| SSDEEP | `49152:nMyl82KFZn1LN0WCE5yM+X2QEODikv1rxomDVXfuhmvHMDy38sOItEG/mBh+gg5r:nV4n1J0EI2OD91xloeHDnmb+gen` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_5bb97826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135"
    family = "unknown"
    file_name = "5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:43:01"
  condition:
    hash.sha256(0, filesize) == "5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135"
}
```

### Sample 68: `3675be6c9d4f5be9`

| Field | Value |
|---|---|
| SHA-256 | `3675be6c9d4f5be9d5404784c438b75baac1b4dda9886fa88ea5459b97ee4b7d` |
| Family label | `unknown` |
| File name | `kworker` |
| File type | `elf` |
| First seen | `2026-08-24 18:35:47` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f05c749e517bbfa9c76647f94d93ee4` |
| SHA-1 | `1cbfdbd5e48eb008bd3a179d123cfd5423734250` |
| SHA-256 | `3675be6c9d4f5be9d5404784c438b75baac1b4dda9886fa88ea5459b97ee4b7d` |
| SHA3-384 | `22f581fd2ba3df7a43d4decf39483e6c0d919c3f97302cb35565efd8bdea3bb31cf09b6875fa1b8e09299d27b39d2957` |
| TLSH | `T14C774B43E8E61A94C4EAC1B0D166815BBBB23C5D1B7823EB1B90F3701F36BD05AB6751` |
| TELFHASH | `t16fc250b09ab874f4b6a6c965f3f67474d63324f227d838f04436b892efa0e851855c27` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:1KVBkorBGqtl8EEgcb/xxq/n+R6Pup/FIjrnoLccqRUjrwWDFMFb7els:1Ksolb8EwZ4Q+rnGtqRMwWpMb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_3675be6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3675be6c9d4f5be9d5404784c438b75baac1b4dda9886fa88ea5459b97ee4b7d"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-08-24 18:35:47"
  condition:
    hash.sha256(0, filesize) == "3675be6c9d4f5be9d5404784c438b75baac1b4dda9886fa88ea5459b97ee4b7d"
}
```

### Sample 69: `2199808b5669b6d4`

| Field | Value |
|---|---|
| SHA-256 | `2199808b5669b6d4d316ad5f0f2ec8a29c796f178ee43ce2c1166d2d468cecea` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-24 18:29:34` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93f21ed26c833208d70dc98b33918bf6` |
| SHA-1 | `169efd994b894301bfa003cd782dd2af8bff305e` |
| SHA-256 | `2199808b5669b6d4d316ad5f0f2ec8a29c796f178ee43ce2c1166d2d468cecea` |
| SHA3-384 | `831e9d8a6f1a11ef7b98b48ccf004a17251e2f635042983499c496312abe6afdf261a3fa898b79a1c16a77a65147cbef` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T10E22D51E2E860331EE6008B0E675864A113D5EE37386FBEBE733D6870AD5D4584C06AF` |
| SSDEEP | `192:bcolWLwziNBQ5tsxeugRPFJxTEZmFhEorccGFGp:4oBiHAvPFwZsMFG` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_069_2199808b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2199808b5669b6d4d316ad5f0f2ec8a29c796f178ee43ce2c1166d2d468cecea"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 18:29:34"
  condition:
    hash.sha256(0, filesize) == "2199808b5669b6d4d316ad5f0f2ec8a29c796f178ee43ce2c1166d2d468cecea"
}
```

### Sample 70: `82a7c6208b7b98fd`

| Field | Value |
|---|---|
| SHA-256 | `82a7c6208b7b98fda014dbe12d7afd6101941920b4ea87124e19eb6c9cb9f4b2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-24 18:28:34` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf6067531d65ee6f95cfae3a5455f894` |
| SHA-1 | `d4923e8a3a04c85448855b87d68d1605849feb43` |
| SHA-256 | `82a7c6208b7b98fda014dbe12d7afd6101941920b4ea87124e19eb6c9cb9f4b2` |
| SHA3-384 | `f497af205c345e3dc6d6e1572a1bc590caff2ff7a634191caba379bd7c346ef93e074a10c15089e64e6f2263d2648957` |
| IMPHASH | `ab4deb034aa730f55aea72b8fd02202e` |
| TLSH | `T102B62357E2A344F8C95BC1B497A7C772B930F8690234BD2E1E94D7212F26E604F1EB64` |
| SSDEEP | `196608:Kqr7mJGlZSlp7vaXFE045/ifTJYXoLViHqlCY9soAlHcR431du3PX:h/Sp7vACpIVyqA6HAIE18fX` |
| ICON-DHASH | `70f0d4d4d4cce870` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_82a7c620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a7c6208b7b98fda014dbe12d7afd6101941920b4ea87124e19eb6c9cb9f4b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 18:28:34"
  condition:
    hash.sha256(0, filesize) == "82a7c6208b7b98fda014dbe12d7afd6101941920b4ea87124e19eb6c9cb9f4b2"
}
```

### Sample 71: `49b40f07663805da`

| Field | Value |
|---|---|
| SHA-256 | `49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68` |
| Family label | `unknown` |
| File name | `49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68.exe` |
| File type | `exe` |
| First seen | `2026-08-24 18:27:25` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e5f0065da7d4a6403dd07c7d93d20c7` |
| SHA-1 | `544765739aaf40e8f0900666555c38581f3ea854` |
| SHA-256 | `49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68` |
| SHA3-384 | `94a9776c3c4e0fa5c8e496e5eb68af7134efa19227a11fe641b9f5035de8f2ba978bd0ca090dfb6fbfcefaf0448228d7` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T1F6E523E4BED23976F426CBB76793B8BE71293B4189608C0D36CD1B052D215187DBB389` |
| SSDEEP | `49152:ycrobH5TWOEE22KrQtoADzs9wSDjeKKvwA80AA84thHBn14K2GLdcfG:JS5TWFprADzs9Lf/KvwAHThthH114K7J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_49b40f07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68"
    family = "unknown"
    file_name = "49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:27:25"
  condition:
    hash.sha256(0, filesize) == "49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68"
}
```

### Sample 72: `e9af23e5212e3860`

| Field | Value |
|---|---|
| SHA-256 | `e9af23e5212e38604fd00de454c5dca0f192d976a24e7f7d8480140c9fe8fa38` |
| Family label | `unknown` |
| File name | `DiscordZapret.zip` |
| File type | `zip` |
| First seen | `2026-08-24 18:20:49` |
| Reporter | `Alex_sev` |
| Tags | `stealer, zapret, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb5c77ae93629961ece951bc6def3d57` |
| SHA-1 | `b04342e1333a759cd8cfe4bce5973d07226438d3` |
| SHA-256 | `e9af23e5212e38604fd00de454c5dca0f192d976a24e7f7d8480140c9fe8fa38` |
| SHA3-384 | `50b9173e4b75952d1f9657b33861884404022ca7fc6f84029c15228f091ed6739b47b6dd7c050d94d0fde7ce53107d75` |
| TLSH | `T1BE7733AC75B5BA6AF1D4437BC6852CB6DF2CA540E39C3DAB8E2041477D8310E5F2AC61` |
| SSDEEP | `786432:KQPqp4OySCU7DFrckpCtXnP0Fg6fSlO0e4NXbCAC9i:KJpD6KDFrIXP0fSdXz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_e9af23e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9af23e5212e38604fd00de454c5dca0f192d976a24e7f7d8480140c9fe8fa38"
    family = "unknown"
    file_name = "DiscordZapret.zip"
    file_type = "zip"
    first_seen = "2026-08-24 18:20:49"
  condition:
    hash.sha256(0, filesize) == "e9af23e5212e38604fd00de454c5dca0f192d976a24e7f7d8480140c9fe8fa38"
}
```

### Sample 73: `4f5fb39c58955bca`

| Field | Value |
|---|---|
| SHA-256 | `4f5fb39c58955bcab166d2ff557fe6064cd7f7628f16527d32455784d6c7e0ac` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 17:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfac413f947b3fca5d8221b8ad097c0d` |
| SHA-256 | `4f5fb39c58955bcab166d2ff557fe6064cd7f7628f16527d32455784d6c7e0ac` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_4f5fb39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f5fb39c58955bcab166d2ff557fe6064cd7f7628f16527d32455784d6c7e0ac"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 17:52:11"
  condition:
    hash.sha256(0, filesize) == "4f5fb39c58955bcab166d2ff557fe6064cd7f7628f16527d32455784d6c7e0ac"
}
```

### Sample 74: `69daa1a225ee2c46`

| Field | Value |
|---|---|
| SHA-256 | `69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6` |
| Family label | `Vidar` |
| File name | `69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6.bin` |
| File type | `exe` |
| First seen | `2026-08-24 17:34:50` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85c89eabf109e53c5fa5f7d9bb03f80b` |
| SHA-1 | `afc44263beaf8a5c391ca5e4592153c8cae012f7` |
| SHA-256 | `69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6` |
| SHA3-384 | `985a46f4ee22e97911d64d0921b20907f62c16b7c7bc511a623fe8e11b82dd65051ce0d08c29fbc503cdb4c59391dd18` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T10C069C07FCE108A5D59CA3318AAA42427B7DBC851B3263E32E54B77A2FB7BD05935305` |
| SSDEEP | `49152:0PwPHwPDSU88IoyiW0QqqeitYnb1uxvDghFEWP1CU8v3CTxvj:0GRrKmtYnb1Wb6Efoxvj` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_074_69daa1a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6"
    family = "Vidar"
    file_name = "69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:34:50"
  condition:
    hash.sha256(0, filesize) == "69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6"
}
```

### Sample 75: `5e6d524040203629`

| Field | Value |
|---|---|
| SHA-256 | `5e6d5240402036291aff059a205ae94c60b72e45b6faae2f3567d7e7368f5d16` |
| Family label | `Phorphiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-24 17:14:36` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorphiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed7f7dbeed08ef3446c29432ee50861a` |
| SHA-1 | `20676bec6038ab33b21d264864f4854d6022044a` |
| SHA-256 | `5e6d5240402036291aff059a205ae94c60b72e45b6faae2f3567d7e7368f5d16` |
| SHA3-384 | `ee254aa3a3e8be2695ed407cb60a05086c2b804b89c5c53cd1307fd18ff6b0d96b206ad3445749442a920b4b83daf658` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T1CD824B0FB9424326D0E11070A676867BDA79A8B633C414DBF7E48AED0A686D1FC3315F` |
| SSDEEP | `384:ak6I8vVaF6OSYUQQlmLu94gXTczlmxav8U9crl:akPTUQQt9U8a0U` |

#### Technical Assessment

- The sample is tracked as `Phorphiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorphiex_075_5e6d5240
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e6d5240402036291aff059a205ae94c60b72e45b6faae2f3567d7e7368f5d16"
    family = "Phorphiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 17:14:36"
  condition:
    hash.sha256(0, filesize) == "5e6d5240402036291aff059a205ae94c60b72e45b6faae2f3567d7e7368f5d16"
}
```

### Sample 76: `670b6d281f391863`

| Field | Value |
|---|---|
| SHA-256 | `670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c` |
| Family label | `Vidar` |
| File name | `670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c.bin` |
| File type | `exe` |
| First seen | `2026-08-24 17:02:47` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d1082265e6707d1cfebff97cc9764a4` |
| SHA-1 | `949c39d12430a13f1029226b5459724a8b43308e` |
| SHA-256 | `670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c` |
| SHA3-384 | `a40bf445640ee31ae2197a8d9a2fa492f00cde5c3e4fd3cbf051b596d2759e7918b725c710b9ac1c8490a1fc8ff8ae4c` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T16E183303FA9440A5D45A8B3695BA8213FB35BC8D973A33D72E54B6382E7A3D03E75305` |
| SSDEEP | `1572864:uUAmSmr7imhgSjla2u6fa8Z847Ff73ygKTSpdWzYvA1PM2aRn3ZvOMi:PtS22KtQ25i8X7J3PYSpEzj1PM2kvOf` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_076_670b6d28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c"
    family = "Vidar"
    file_name = "670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:47"
  condition:
    hash.sha256(0, filesize) == "670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c"
}
```

### Sample 77: `b9c86f9be2c5c297`

| Field | Value |
|---|---|
| SHA-256 | `b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d` |
| Family label | `Vidar` |
| File name | `b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d.bin` |
| File type | `exe` |
| First seen | `2026-08-24 17:02:39` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72e83993135fefb794e68bf3f051bfa8` |
| SHA-1 | `ee043791c94bea70054e147b5f8ed80ea1c9ff0e` |
| SHA-256 | `b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d` |
| SHA3-384 | `39944bc22ac6741751792f5ee812e8577dc30d0eb05ac77257a8ed7ce6c01a02ed5edaa6fb14ef0cc4cd61b93686d35c` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T192183303FD9580E5D8568B35C9BA8553BB32BC8D9B3A33D32E5066382F793D06AB4315` |
| SSDEEP | `1572864:uWP0oyyek/qPkhT8kqaMLJnqR/nVMtuhEQc8K5AuFwZTluS96vlWQxMTEJ1Ln9S:VRyvk58krqnqR9MqEB8K6uB6oTu0Ln0` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_077_b9c86f9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d"
    family = "Vidar"
    file_name = "b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:39"
  condition:
    hash.sha256(0, filesize) == "b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d"
}
```

### Sample 78: `4980c099052a595c`

| Field | Value |
|---|---|
| SHA-256 | `4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9` |
| Family label | `unknown` |
| File name | `4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9.bin` |
| File type | `exe` |
| First seen | `2026-08-24 17:02:32` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5341495aa3c5d1b56ade1ef353ab28a7` |
| SHA-1 | `e1e8eed4824cf6d56771b6b040aba0beb53d1167` |
| SHA-256 | `4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9` |
| SHA3-384 | `fc1dde0fb147e87b4cb53d0bf4fbb189dc99e7c9b4dee0993c7494b89281e1b9c89c9fa7f9c3c4a9d718d109be8c73fe` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T138283307F98580E5C45A9B31C6BAC613BB32BC8D573673D72E10B6382E7A7D069B5306` |
| SSDEEP | `1572864:uA+wv83pf4VcPJK+nN6DqJpEtFkot1O/UdRObYzUSLcT8CMgtiBQpgpNOjin:CFOOJFnNKqJStV1O/UdQkgd4yg3f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_4980c099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9"
    family = "unknown"
    file_name = "4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:32"
  condition:
    hash.sha256(0, filesize) == "4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9"
}
```

### Sample 79: `97f5bd9347bb5798`

| Field | Value |
|---|---|
| SHA-256 | `97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26` |
| Family label | `unknown` |
| File name | `97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26.exe` |
| File type | `exe` |
| First seen | `2026-08-24 17:02:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `822d9758adbd2401eb16b7c0f13acfc1` |
| SHA-1 | `337f3655e80e1071bdcb9985e8838cca39f3c280` |
| SHA-256 | `97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26` |
| SHA3-384 | `6fc2f60dbfca05580fa7a389a72bfa249c1bb89c3e904737b081b62f2b5d90f851cc375a3703b97e54c59250105eb15f` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T187D52394B8F614B4D432CBB28FD3E56DB06A7799CBA04DA77BCD69000C53994AC3A371` |
| SSDEEP | `49152:4DXHyo3M7/KHRDOWcxlFfRin12KXQZpcnUiqA7ZnFjhSo95lpea6p:iio3MTUB0Rc15Upg7ZnFjh95Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_97f5bd93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26"
    family = "unknown"
    file_name = "97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26.exe"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:06"
  condition:
    hash.sha256(0, filesize) == "97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26"
}
```

### Sample 80: `998b905cff24fa1e`

| Field | Value |
|---|---|
| SHA-256 | `998b905cff24fa1e98c4b59de79b5fee66a68faf59a9c1b8e4e42a77b40f46a7` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 16:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f87638b4c2a65b301842c74e2a0dfd3` |
| SHA-256 | `998b905cff24fa1e98c4b59de79b5fee66a68faf59a9c1b8e4e42a77b40f46a7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_998b905c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998b905cff24fa1e98c4b59de79b5fee66a68faf59a9c1b8e4e42a77b40f46a7"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 16:52:11"
  condition:
    hash.sha256(0, filesize) == "998b905cff24fa1e98c4b59de79b5fee66a68faf59a9c1b8e4e42a77b40f46a7"
}
```

### Sample 81: `2df2599e1f1e5555`

| Field | Value |
|---|---|
| SHA-256 | `2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382` |
| Family label | `unknown` |
| File name | `2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382.bin` |
| File type | `exe` |
| First seen | `2026-08-24 16:48:16` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb06a8f0af94c96f430132a02e8f4910` |
| SHA-1 | `f4d2d04ca3b422f10806cd83ce0ebc27ae0e80c3` |
| SHA-256 | `2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382` |
| SHA3-384 | `b6bd49167ef5b136fec2f36f04bdfd6b88196f87a5b584b7028163af53de3a91d78f930d53aa761552afacdff82370e2` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T1CC283303B99441A4D4669B31C5BA9353BB35B88E9B3673C33F44A2381F367D06EB9316` |
| SSDEEP | `1572864:wxkUCeVV5U2nMJtbNf6pSNIeQfcLU4SevDjoHqiVLgYqqqkTEYWZ74:/9Qg2Mb5SsL3N/baVLgYqqqoXx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_2df2599e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382"
    family = "unknown"
    file_name = "2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382.bin"
    file_type = "exe"
    first_seen = "2026-08-24 16:48:16"
  condition:
    hash.sha256(0, filesize) == "2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382"
}
```

### Sample 82: `b949007bb4e1adcd`

| Field | Value |
|---|---|
| SHA-256 | `b949007bb4e1adcd2026c61f79d379dc349bfec86fdad8baddeea64356159ca5` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-24 16:02:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bab483411938183916160326ce17e69` |
| SHA-1 | `94d00b47c201a94e77fa43ca456b6e8c8a5a16c6` |
| SHA-256 | `b949007bb4e1adcd2026c61f79d379dc349bfec86fdad8baddeea64356159ca5` |
| SHA3-384 | `d1aa091feebd388eee7080b6f0dade61b66ba28107df49e141fba7c3ba3720fb4ddd5842b8e0ce950d1ad4d58f14494d` |
| TLSH | `T1E1C27D966A867C44BEC94A3E4CBD1B1D6DF5C3D1324942AC3D8A3C719C11F9CD618B1A` |
| SSDEEP | `768:r8vCB+25j6es8RoH9FYpMSUpi+20qUpi+20YQX:r8l25Johd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_b949007b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b949007bb4e1adcd2026c61f79d379dc349bfec86fdad8baddeea64356159ca5"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 16:02:39"
  condition:
    hash.sha256(0, filesize) == "b949007bb4e1adcd2026c61f79d379dc349bfec86fdad8baddeea64356159ca5"
}
```

### Sample 83: `c20e18f5a2efcdb5`

| Field | Value |
|---|---|
| SHA-256 | `c20e18f5a2efcdb5a128991570c50bb57236d9b09667cc5cfece1f9ada6e2129` |
| Family label | `unknown` |
| File name | `ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b.exe` |
| File type | `exe` |
| First seen | `2026-08-24 15:57:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ee900d9853699e17b5872db14d15df9` |
| SHA-1 | `96ef7491e05edc24a64797e65569f32a31e0ee4c` |
| SHA-256 | `c20e18f5a2efcdb5a128991570c50bb57236d9b09667cc5cfece1f9ada6e2129` |
| SHA3-384 | `bb05a942aa3c70a388e7f5450ae3b1c9d3950fad825aab6b3396b35029d1fe1b82c4f40bb9182c266ba7d77787d94eef` |
| TLSH | `T160551E8ED8919BF8B3A6F773521AD6225CF6344780328631CF457E395F02F24A524EDA` |
| SSDEEP | `12288:DKnr3gPi2qT/Q6hGT692vl9Iem6m9gEBi:DKr3gCTY6sUeBE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_c20e18f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c20e18f5a2efcdb5a128991570c50bb57236d9b09667cc5cfece1f9ada6e2129"
    family = "unknown"
    file_name = "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 15:57:17"
  condition:
    hash.sha256(0, filesize) == "c20e18f5a2efcdb5a128991570c50bb57236d9b09667cc5cfece1f9ada6e2129"
}
```

### Sample 84: `ea5b61bc8d140124`

| Field | Value |
|---|---|
| SHA-256 | `ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b` |
| Family label | `unknown` |
| File name | `ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b.exe` |
| File type | `exe` |
| First seen | `2026-08-24 15:57:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e7afaa8ae07d25002358c8a453a12ad` |
| SHA-1 | `ddb4822820a3e1c5d21d6f82eec557c0b7ef7e72` |
| SHA-256 | `ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b` |
| SHA3-384 | `e1c065dd3bfabddf011fef17357aea8ef09a04a186fbae95b95cf62efda887010951cab2941a9fcf7b7b2317eab2ba07` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T18974234662D7678CDCDE9834039931C3AE0F777CB985E77A90AED9AE33609348E45848` |
| SSDEEP | `6144:Ni17fe5lQvi+WglLT7SfvujsJOYasCbKY0qEluDeVplyomdL0L09yXRy3oy2UVIv:Nm7fekvi+WgLT7Sej6OYHCbK3qguU+dw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_ea5b61bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b"
    family = "unknown"
    file_name = "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 15:57:05"
  condition:
    hash.sha256(0, filesize) == "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b"
}
```

### Sample 85: `840d6303cf94d4dd`

| Field | Value |
|---|---|
| SHA-256 | `840d6303cf94d4dd8d2bc8d4718535efaee87be41a36b8278f4460efd0e4b912` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-24 15:52:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f463f69f6c375019af283bc28eb7c85a` |
| SHA-1 | `667155b8b5f81b211ffec170e88f86c1dcdfa833` |
| SHA-256 | `840d6303cf94d4dd8d2bc8d4718535efaee87be41a36b8278f4460efd0e4b912` |
| SHA3-384 | `1b790571f1a4ba56b99b1455b3101d4915377a2c1c0c6506634d8b777f7d4bf89ae1f87bd92865f401f11824fb5a3d51` |
| TLSH | `T117143A95F890DE52C6D5267AF96E518C331313B8D2DAB106CD244F38B7EB85E0F3A942` |
| SSDEEP | `6144:sRlx8s/kMmKTUQ4g8O592I0zMp0No9MpM1J5km:2lF/kMTTUQ4g8O78UNMi15` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_840d6303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "840d6303cf94d4dd8d2bc8d4718535efaee87be41a36b8278f4460efd0e4b912"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 15:52:20"
  condition:
    hash.sha256(0, filesize) == "840d6303cf94d4dd8d2bc8d4718535efaee87be41a36b8278f4460efd0e4b912"
}
```

### Sample 86: `2464a77c5296a3d3`

| Field | Value |
|---|---|
| SHA-256 | `2464a77c5296a3d37905cd37c52a43e7bc15e7ced8f403d86b7aea7a7082d50f` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 15:52:13` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5739d6f35f36ee5df8e6be79ca13c1e5` |
| SHA-256 | `2464a77c5296a3d37905cd37c52a43e7bc15e7ced8f403d86b7aea7a7082d50f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_2464a77c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2464a77c5296a3d37905cd37c52a43e7bc15e7ced8f403d86b7aea7a7082d50f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 15:52:13"
  condition:
    hash.sha256(0, filesize) == "2464a77c5296a3d37905cd37c52a43e7bc15e7ced8f403d86b7aea7a7082d50f"
}
```

### Sample 87: `f7e1104b45cc7ee1`

| Field | Value |
|---|---|
| SHA-256 | `f7e1104b45cc7ee10120174be0218abc628e780b2c598d796cd4c50f647f6322` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-24 15:51:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3efdc00ed0d2a9777a33b92b29daca66` |
| SHA-1 | `f606745e9081d12bdca0cb18965012623a5e1e32` |
| SHA-256 | `f7e1104b45cc7ee10120174be0218abc628e780b2c598d796cd4c50f647f6322` |
| SHA3-384 | `881ef5100dbfffc4ac1b52ca67c26b0b8f11cc5c8e468fac4108ab17cd3d10c887b0e2e9f041b51a4b8a931e19c4df58` |
| TLSH | `T1A48312C215405592C2B2343BD2285BE1EEA06B74BBA130B4DC17799D7DE3D2A1EBD1CE` |
| SSDEEP | `1536:R7JFmTfIsEgFyOOKpbUZxaD+9WhAV1sp8kcEz69QHRbIrHI0vTk6UcjrrSSD4uXk:R77kIs7EKpQie3V1saBi27I046jj58Kk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_f7e1104b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7e1104b45cc7ee10120174be0218abc628e780b2c598d796cd4c50f647f6322"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 15:51:31"
  condition:
    hash.sha256(0, filesize) == "f7e1104b45cc7ee10120174be0218abc628e780b2c598d796cd4c50f647f6322"
}
```

### Sample 88: `755f57158a93bf4f`

| Field | Value |
|---|---|
| SHA-256 | `755f57158a93bf4f884fa819f854f1db27341970c6a2d16824a5f2ff9d66deff` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-24 15:49:17` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `428bbf9e73b06d1c4a648c82ada669f8` |
| SHA-256 | `755f57158a93bf4f884fa819f854f1db27341970c6a2d16824a5f2ff9d66deff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_755f5715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "755f57158a93bf4f884fa819f854f1db27341970c6a2d16824a5f2ff9d66deff"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-24 15:49:17"
  condition:
    hash.sha256(0, filesize) == "755f57158a93bf4f884fa819f854f1db27341970c6a2d16824a5f2ff9d66deff"
}
```

### Sample 89: `435ba2f17112114a`

| Field | Value |
|---|---|
| SHA-256 | `435ba2f17112114a9a0b3356b4657e5fbd35c7cf311f143d2fb939a1d8a8fc2a` |
| Family label | `unknown` |
| File name | `main.sparc64` |
| File type | `elf` |
| First seen | `2026-08-24 15:49:16` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1625c5a83a58c8426a9a57f59177795` |
| SHA-1 | `cf18f7f1a2495778d9045dfae4cb5312a4fe0861` |
| SHA-256 | `435ba2f17112114a9a0b3356b4657e5fbd35c7cf311f143d2fb939a1d8a8fc2a` |
| SHA3-384 | `8d33226ec32e57db64637f189972f89bd0820f8f8af71318df277a7cd138a39af7c21bb7a1fbb5c146ec34d4fcc3d10b` |
| TLSH | `T1C725AE523BF61461D64046358FE2D321720ADBE874D54A8B9F908EEFDF032651E82CFA` |
| SSDEEP | `12288:oAhx87OJdu5Ch+Lwtejq05oSY1o4mra5dCYy79:dx3dYABSYRvW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_435ba2f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "435ba2f17112114a9a0b3356b4657e5fbd35c7cf311f143d2fb939a1d8a8fc2a"
    family = "unknown"
    file_name = "main.sparc64"
    file_type = "elf"
    first_seen = "2026-08-24 15:49:16"
  condition:
    hash.sha256(0, filesize) == "435ba2f17112114a9a0b3356b4657e5fbd35c7cf311f143d2fb939a1d8a8fc2a"
}
```

### Sample 90: `202c64b8adf00206`

| Field | Value |
|---|---|
| SHA-256 | `202c64b8adf002065f9f272d9ee2949bc1b71411ab0f332ca3daf1d36cfbcd7e` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-24 15:45:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cff650168c633999c80884d2bf5e069d` |
| SHA-1 | `07f603e79bcf904d4558f13b61c0c9630e3a5bc2` |
| SHA-256 | `202c64b8adf002065f9f272d9ee2949bc1b71411ab0f332ca3daf1d36cfbcd7e` |
| SHA3-384 | `79c76f2f313c61afc6eae9212a4cbe4e1edcea034392aa11c8ca747a8f5ce93416fa33e3cdb5034f09431a375f16ebf6` |
| TLSH | `T199144A95F890DE52C6D0267AFA7D518C330317B8D3DA7116CE108B35B7EB95A0F3A982` |
| SSDEEP | `6144:roAr/Tah1if9UVcYEEUYDckzjR482pwzihN2B6OTEkm:7rGhsfucYEEUSnR48Bc2gf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_202c64b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202c64b8adf002065f9f272d9ee2949bc1b71411ab0f332ca3daf1d36cfbcd7e"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-24 15:45:32"
  condition:
    hash.sha256(0, filesize) == "202c64b8adf002065f9f272d9ee2949bc1b71411ab0f332ca3daf1d36cfbcd7e"
}
```

### Sample 91: `4ea8e41bc05d6f5a`

| Field | Value |
|---|---|
| SHA-256 | `4ea8e41bc05d6f5a11aec94578a2af51a0cf5f25040890a2a714fa6bc46fa965` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-24 15:44:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00766876dbc4efb14549f722a68794c0` |
| SHA-1 | `423e18e2f29bbe0b55aea61fc4a1cc976c3c6c43` |
| SHA-256 | `4ea8e41bc05d6f5a11aec94578a2af51a0cf5f25040890a2a714fa6bc46fa965` |
| SHA3-384 | `a08fa152a17affce0e1efb5232b3315643e1b523f5906c6549870e100f16052bcdb5c8a70efb7b4751bb0c64f6844273` |
| TLSH | `T16F830260D8AE73CDC5259838C40AD622BDA1E850B6F6F34670892725EDF12CB1F7D34A` |
| SSDEEP | `1536:0Sb722VO7LBcrtiZcubVMou336LyfjkhFIWbtv7fUKlsafF:0E722VsButiZFUjLkhaWb5lsat` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_4ea8e41b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ea8e41bc05d6f5a11aec94578a2af51a0cf5f25040890a2a714fa6bc46fa965"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-24 15:44:23"
  condition:
    hash.sha256(0, filesize) == "4ea8e41bc05d6f5a11aec94578a2af51a0cf5f25040890a2a714fa6bc46fa965"
}
```

### Sample 92: `e01e53f0eff39e22`

| Field | Value |
|---|---|
| SHA-256 | `e01e53f0eff39e22fdfbd50fd17bdc39f5db20eddf4c7f6d1b61271f6f63c8a1` |
| Family label | `Mirai` |
| File name | `main.mips` |
| File type | `elf` |
| First seen | `2026-08-24 15:41:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bc8d2ea5bfdeb8da6b1fb5908bdbcd9` |
| SHA-1 | `225b5b234cdbcbad3e031a65633d905924145b7c` |
| SHA-256 | `e01e53f0eff39e22fdfbd50fd17bdc39f5db20eddf4c7f6d1b61271f6f63c8a1` |
| SHA3-384 | `005109f0d76f24de12d4407c6387078388188280e3c889f4b9fe617a5830961c00055a8bc820470ef2e6a9dbdcfdfed0` |
| TLSH | `T17E6364292A21EFFDE16E823047F39E70935926D637F1C680E26CC7485E7029D189F7A5` |
| TELFHASH | `t185115e18453823f0c7825cad6bddff76d5a044ef5a226e37ce40fca99a21a865e00c2c` |
| SSDEEP | `1536:KHPHixpBuQ0aChFaLhtBrRZV/Pr1lZGnbPWDrBg0P2h8eBVn:/T65` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_e01e53f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e01e53f0eff39e22fdfbd50fd17bdc39f5db20eddf4c7f6d1b61271f6f63c8a1"
    family = "Mirai"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-24 15:41:42"
  condition:
    hash.sha256(0, filesize) == "e01e53f0eff39e22fdfbd50fd17bdc39f5db20eddf4c7f6d1b61271f6f63c8a1"
}
```

### Sample 93: `75b6135f464b51aa`

| Field | Value |
|---|---|
| SHA-256 | `75b6135f464b51aa7d8d0547c979027c0bf3379ec00d6e334b4e5d0e15404a7d` |
| Family label | `unknown` |
| File name | `main.microblazeel` |
| File type | `elf` |
| First seen | `2026-08-24 15:39:27` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2eb34170f955e2cc7cde2c755ba702e` |
| SHA-1 | `85a3be59433758b2cca3a54fb9d119fe4b9ec8eb` |
| SHA-256 | `75b6135f464b51aa7d8d0547c979027c0bf3379ec00d6e334b4e5d0e15404a7d` |
| SHA3-384 | `36770e988afe07936bc90ef96a2337b28f425ff07e3c7d9c3480e3bd73efeef5e6ad70772070d2a7727fb2f3c5bd950e` |
| TLSH | `T1D4A3E60FBC5ADAB2C9929A34C27F00512315874158BBAF7369BBC21DD76213BD7279C8` |
| SSDEEP | `3072:+cbDlsnn90xJXPcbUkG6kKdeAK657JYoXEo5AyWVXH:+ctsnuxJfcgkG6kKde2YN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_75b6135f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75b6135f464b51aa7d8d0547c979027c0bf3379ec00d6e334b4e5d0e15404a7d"
    family = "unknown"
    file_name = "main.microblazeel"
    file_type = "elf"
    first_seen = "2026-08-24 15:39:27"
  condition:
    hash.sha256(0, filesize) == "75b6135f464b51aa7d8d0547c979027c0bf3379ec00d6e334b4e5d0e15404a7d"
}
```

### Sample 94: `6e134b0a2d2247ca`

| Field | Value |
|---|---|
| SHA-256 | `6e134b0a2d2247cab988db2b0bfc7a511b1e7c79c0d3699536558352abb47b40` |
| Family label | `unknown` |
| File name | `main.mips32r6el` |
| File type | `elf` |
| First seen | `2026-08-24 15:39:26` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5f5f906b21b4e3f8ed4ba1b1a37b28d` |
| SHA-1 | `e1abe49a6ca79c4d1adeb91a237c8b9584338295` |
| SHA-256 | `6e134b0a2d2247cab988db2b0bfc7a511b1e7c79c0d3699536558352abb47b40` |
| SHA3-384 | `c900b38983aba99a75d284fc8b5e52c79f6f0565981cec1538e93bd2660cd9e7c9e12419d75b0eda2d322a94ecd4a697` |
| TLSH | `T197D3E913EE807EB7C51ADC74426FC25214EB5CFAA2E5A33A71F8469DBE7C20611C7588` |
| SSDEEP | `1536:zC7FdOBUZAT09VvoRs4O8f8ZjARSBPkD82xwMEr59a:u7FoBUZBjwRRO8f8ZzE8ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_6e134b0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e134b0a2d2247cab988db2b0bfc7a511b1e7c79c0d3699536558352abb47b40"
    family = "unknown"
    file_name = "main.mips32r6el"
    file_type = "elf"
    first_seen = "2026-08-24 15:39:26"
  condition:
    hash.sha256(0, filesize) == "6e134b0a2d2247cab988db2b0bfc7a511b1e7c79c0d3699536558352abb47b40"
}
```

### Sample 95: `1a4d9b7355fc76aa`

| Field | Value |
|---|---|
| SHA-256 | `1a4d9b7355fc76aa8eaf91c67b9ace2cc3fbf70b13d88d4ce565ed9aa15f0b5f` |
| Family label | `unknown` |
| File name | `main.archs38` |
| File type | `elf` |
| First seen | `2026-08-24 15:37:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc87fd641dbf28d96c3981c3d7d40ef3` |
| SHA-1 | `09b8584dc861457398235e916769adc0f07d3f5e` |
| SHA-256 | `1a4d9b7355fc76aa8eaf91c67b9ace2cc3fbf70b13d88d4ce565ed9aa15f0b5f` |
| SHA3-384 | `3a3ef136fd96664e963968061e0671840d35352e6c0837ee1ce3f0664ebc21f256d266dd2b634add45c5742b4c45d89f` |
| TLSH | `T1F4A36C4B760B2880F82102F0A7DE93E03F1551DBAF361EB7586A62F76F7319D1D06662` |
| SSDEEP | `1536:+LUGHVr6HCyno/ZdJROL+Tanf50Qcr+J34jgLZCUn5p5M/LW:gHB6HCynibROLjcXgUhq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_1a4d9b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a4d9b7355fc76aa8eaf91c67b9ace2cc3fbf70b13d88d4ce565ed9aa15f0b5f"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-24 15:37:15"
  condition:
    hash.sha256(0, filesize) == "1a4d9b7355fc76aa8eaf91c67b9ace2cc3fbf70b13d88d4ce565ed9aa15f0b5f"
}
```

### Sample 96: `55e231d9583fbd2e`

| Field | Value |
|---|---|
| SHA-256 | `55e231d9583fbd2e372ac0f8ef6f5fa97cee1ecd30a934c8d8811328f3601585` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-24 15:35:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7f2b92638f02873880f9783157ac98a` |
| SHA-1 | `d90b0965a0af34afd1eb30db9b6d9d8053b0bca0` |
| SHA-256 | `55e231d9583fbd2e372ac0f8ef6f5fa97cee1ecd30a934c8d8811328f3601585` |
| SHA3-384 | `80d958aab24f32b8ff5398a07b75b854557ebb4f24fc9e9aef262c4e7432dc49521fc671b37cef4717f637cdb9adf890` |
| TLSH | `T18A545B5F7B10CF61E229C53149B38B5667E5266327E2C559E21CEE087E6038C682FFE4` |
| TELFHASH | `t1cc4100a04e3bda06db89caec86fdab2e790e91061259cf33ee30417d40510f9e259d4f` |
| SSDEEP | `6144:gM5XD4YODabLHG4kq79xu6h+l2rVXxEeJDh:r5XUXWzUR2rVbF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_55e231d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e231d9583fbd2e372ac0f8ef6f5fa97cee1ecd30a934c8d8811328f3601585"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-24 15:35:19"
  condition:
    hash.sha256(0, filesize) == "55e231d9583fbd2e372ac0f8ef6f5fa97cee1ecd30a934c8d8811328f3601585"
}
```

### Sample 97: `a2901d935af19fc7`

| Field | Value |
|---|---|
| SHA-256 | `a2901d935af19fc75533750e8948dc291b57fa4dbbc62ee7917823320ac927e2` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-24 15:34:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af3bd30bf8e41ab18024d8b217363773` |
| SHA-1 | `ad20adf0430d5bc928ad7aaac243adffe4d59ec1` |
| SHA-256 | `a2901d935af19fc75533750e8948dc291b57fa4dbbc62ee7917823320ac927e2` |
| SHA3-384 | `f71ec9f9a4ab8b8ef0eb341586c69853149b84634cd2f031caeffcd9e0cef3a05a314250a589e2d1728cf40cd148cc74` |
| TLSH | `T17DB312AD37478C66FF5C4672A5104BC01A71CF6BB20392FB283AD592A773B81252F046` |
| SSDEEP | `3072:HE0S2EhExtdWNOuuQ8vNnrc+5OeEM6fTkhpFHnFAqAUV1sq:k0S2EhExtdWNcQiNnrc+Pv6b6RFZl1sq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_a2901d93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2901d935af19fc75533750e8948dc291b57fa4dbbc62ee7917823320ac927e2"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-24 15:34:40"
  condition:
    hash.sha256(0, filesize) == "a2901d935af19fc75533750e8948dc291b57fa4dbbc62ee7917823320ac927e2"
}
```

### Sample 98: `89f87c3a7c6aaa5c`

| Field | Value |
|---|---|
| SHA-256 | `89f87c3a7c6aaa5c2d9c9bfee5aa08cee02072776631d39be4b9f0207dcb3e4e` |
| Family label | `unknown` |
| File name | `main.mips32r5el` |
| File type | `elf` |
| First seen | `2026-08-24 15:34:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bba76f16dbb167a6d434b6617fa94683` |
| SHA-1 | `2638d382933b574ec77bf3e899db6988b5300126` |
| SHA-256 | `89f87c3a7c6aaa5c2d9c9bfee5aa08cee02072776631d39be4b9f0207dcb3e4e` |
| SHA3-384 | `264b380e65b7eb732b30c3ced3f40a259f1e040f21108b25654c91ae3633c559717b508c36235cc741fd353950716eec` |
| TLSH | `T14FD30A03ED816EF7C45EDD70852DC24A15DA5CBA92E9922F71F8C98CBBBD20546D38C8` |
| SSDEEP | `1536:F7VYdcBu0hiPij2DFmXvSwE5sn33w09rxowsWwgpFDVCK7iGsEre:F7YcBuXPy2Zh5s33wgsWwgHoo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_89f87c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89f87c3a7c6aaa5c2d9c9bfee5aa08cee02072776631d39be4b9f0207dcb3e4e"
    family = "unknown"
    file_name = "main.mips32r5el"
    file_type = "elf"
    first_seen = "2026-08-24 15:34:39"
  condition:
    hash.sha256(0, filesize) == "89f87c3a7c6aaa5c2d9c9bfee5aa08cee02072776631d39be4b9f0207dcb3e4e"
}
```

### Sample 99: `2847a02ead80a60c`

| Field | Value |
|---|---|
| SHA-256 | `2847a02ead80a60c25245bca169655b89fb2c724cb7bd7ec184860d94336b9c1` |
| Family label | `unknown` |
| File name | `stage2.bin` |
| File type | `exe` |
| First seen | `2026-08-24 15:34:11` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0b251cf7d41f433d99da067dc27058` |
| SHA-1 | `017ec058de8f55b34d3bfb6826c5f88a1703efe0` |
| SHA-256 | `2847a02ead80a60c25245bca169655b89fb2c724cb7bd7ec184860d94336b9c1` |
| SHA3-384 | `dc645474e89d33a07f0489e46d7b3b00141e1a5ac893ca26d1425cbd031291c36a11e216eefe2cf997cd1fc71d58b800` |
| IMPHASH | `d3a615b1875384c0ec55dd8588433cef` |
| TLSH | `T1B1656C17E3A345ECC56FC13483579776BA70B8290634792E1A94DB322F21E909F6EB24` |
| SSDEEP | `24576:fRRrN/cdW0DUX4Pt+ZbdQJslUJ9zif9PEuBgfb9/zJhVxfcjUq:7rN/cdW0DUX4V+ZblUJ9ziPRBgf` |
| ICON-DHASH | `c4b2e8f0f0aab2cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_2847a02e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2847a02ead80a60c25245bca169655b89fb2c724cb7bd7ec184860d94336b9c1"
    family = "unknown"
    file_name = "stage2.bin"
    file_type = "exe"
    first_seen = "2026-08-24 15:34:11"
  condition:
    hash.sha256(0, filesize) == "2847a02ead80a60c25245bca169655b89fb2c724cb7bd7ec184860d94336b9c1"
}
```

### Sample 100: `13967a1f8467a05a`

| Field | Value |
|---|---|
| SHA-256 | `13967a1f8467a05a8a162856547c123359029fccf00c8c2bb1988daa1a451d86` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-08-24 15:33:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b2ba46afccaa061822913813be116d2` |
| SHA-1 | `1872b08139c6e0ed1d64380b04b6ff729224272f` |
| SHA-256 | `13967a1f8467a05a8a162856547c123359029fccf00c8c2bb1988daa1a451d86` |
| SHA3-384 | `1029ab0af3f76ab21637cfd5507606de5b080609f4c8c1da1bdbb2e2b244c0badb26ca7abda64dc22bb613ed8015d94f` |
| TLSH | `T180347D49FE47D0F0EA9309F0211AE76FBA356A325136F5E2FF893A22F4B1701594925C` |
| SSDEEP | `6144:uCg31iOqF4Snyg+ZTD3LsE8oWXCg+ei4ddtkcus:uCg31iOq+SNGnz8Xh5i4dlu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_13967a1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13967a1f8467a05a8a162856547c123359029fccf00c8c2bb1988daa1a451d86"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-24 15:33:19"
  condition:
    hash.sha256(0, filesize) == "13967a1f8467a05a8a162856547c123359029fccf00c8c2bb1988daa1a451d86"
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
 * Generated: 2026-08-25T01:55:45.187560+00:00
 */

rule MalwareBazaar_unknown_001_24e7ae95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24e7ae95c625a50f9426ab5f32e7710ccb97e6d19d39b94bc8bd461c49f99c67"
    family = "unknown"
    file_name = "System Applications 001.7z"
    file_type = "7z"
    first_seen = "2026-08-25 01:53:43"
  condition:
    hash.sha256(0, filesize) == "24e7ae95c625a50f9426ab5f32e7710ccb97e6d19d39b94bc8bd461c49f99c67"
}

rule MalwareBazaar_unknown_002_5e5590a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e5590a064f53a7a2e2d0e9144d1d86b03f45b491902a3b8119dc9fd0f9a4b78"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-25 01:52:14"
  condition:
    hash.sha256(0, filesize) == "5e5590a064f53a7a2e2d0e9144d1d86b03f45b491902a3b8119dc9fd0f9a4b78"
}

rule MalwareBazaar_unknown_003_ab282de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab282de6689911c7a81ecccb272f1f9f4e1e3705f8d81950f9e791edf79647a2"
    family = "unknown"
    file_name = "DOC-J1674 + 674-1 + 1674-2.rar"
    file_type = "rar"
    first_seen = "2026-08-25 01:02:09"
  condition:
    hash.sha256(0, filesize) == "ab282de6689911c7a81ecccb272f1f9f4e1e3705f8d81950f9e791edf79647a2"
}

rule MalwareBazaar_unknown_004_ee981b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328"
    family = "unknown"
    file_name = "ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328.exe"
    file_type = "exe"
    first_seen = "2026-08-25 01:02:06"
  condition:
    hash.sha256(0, filesize) == "ee981b6035362e01d50684b36e9db1e4a5cc97abe6414adecc866ffb93313328"
}

rule MalwareBazaar_unknown_005_015f9cc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451"
    family = "unknown"
    file_name = "015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451"
    file_type = "elf"
    first_seen = "2026-08-25 01:01:16"
  condition:
    hash.sha256(0, filesize) == "015f9cc2efae6b070bb3834b9550f89d617af9541de326dbd5f4f261eb46d451"
}

rule MalwareBazaar_unknown_006_e6d0f0b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6d0f0b93c12628872622c103b6fdd5227fc94b432ffe431df6e77cb4676830c"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-25 00:52:14"
  condition:
    hash.sha256(0, filesize) == "e6d0f0b93c12628872622c103b6fdd5227fc94b432ffe431df6e77cb4676830c"
}

rule MalwareBazaar_unknown_007_696101c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4"
    family = "unknown"
    file_name = "696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4"
    file_type = "elf"
    first_seen = "2026-08-25 00:02:00"
  condition:
    hash.sha256(0, filesize) == "696101c117b86e7f0983705b532e870dbf108953c670f4a8545b9366ba857aa4"
}

rule MalwareBazaar_RemusStealer_008_fba00f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba00f02ac5abe5b9f7185d74ba753aa12984517fd79ce70a17ffd0ab3fa9adb"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 23:55:02"
  condition:
    hash.sha256(0, filesize) == "fba00f02ac5abe5b9f7185d74ba753aa12984517fd79ce70a17ffd0ab3fa9adb"
}

rule MalwareBazaar_unknown_009_091f4580
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "091f4580316498af0b96de415bc0f418e61f31e6defb57a54e4084382e51de63"
    family = "unknown"
    file_name = "SecuriteInfo.com.ELF.Svirtu-AA.71646998"
    file_type = "elf"
    first_seen = "2026-08-24 23:52:15"
  condition:
    hash.sha256(0, filesize) == "091f4580316498af0b96de415bc0f418e61f31e6defb57a54e4084382e51de63"
}

rule MalwareBazaar_unknown_010_aa06c6b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa06c6b9f0676b66664593106f88cb8ce719f40be1a0372156f64f4dbed84c8b"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 23:52:11"
  condition:
    hash.sha256(0, filesize) == "aa06c6b9f0676b66664593106f88cb8ce719f40be1a0372156f64f4dbed84c8b"
}

rule MalwareBazaar_unknown_011_b8128e8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3"
    family = "unknown"
    file_name = "b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3"
    file_type = "sh"
    first_seen = "2026-08-24 23:30:12"
  condition:
    hash.sha256(0, filesize) == "b8128e8b6060252381314a8d3033d4ec51ab09f72e591897a63d85d4040534c3"
}

rule MalwareBazaar_Mirai_012_866f6652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866f6652ceff521896811a1666fbe0fd17fd879e31953b47cb3cfab1619067eb"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnm68kxnxn"
    file_type = "elf"
    first_seen = "2026-08-24 23:24:36"
  condition:
    hash.sha256(0, filesize) == "866f6652ceff521896811a1666fbe0fd17fd879e31953b47cb3cfab1619067eb"
}

rule MalwareBazaar_unknown_013_53160a2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88"
    family = "unknown"
    file_name = "53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88.exe"
    file_type = "exe"
    first_seen = "2026-08-24 23:12:15"
  condition:
    hash.sha256(0, filesize) == "53160a2c0530340faa7d622f4e145ea8bba75af2f50e5d85eff8393a3bf34d88"
}

rule MalwareBazaar_unknown_014_c51e5bed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162"
    family = "unknown"
    file_name = "c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162"
    file_type = "sh"
    first_seen = "2026-08-24 23:00:15"
  condition:
    hash.sha256(0, filesize) == "c51e5bedcf9d77535405e0a93b9c38d956a07a66f0f99462033e6069f01aa162"
}

rule MalwareBazaar_unknown_015_f4cad337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36"
    family = "unknown"
    file_name = "f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36"
    file_type = "unknown"
    first_seen = "2026-08-24 22:53:32"
  condition:
    hash.sha256(0, filesize) == "f4cad3370b0c1889d4b5b6dd466f2103d458224c4b274a87486a35b5f1803b36"
}

rule MalwareBazaar_unknown_016_06d9d9f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06d9d9f4157929638f122ca4dfb2f6afa4822d5279332afed91faba006c49cd0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 22:52:17"
  condition:
    hash.sha256(0, filesize) == "06d9d9f4157929638f122ca4dfb2f6afa4822d5279332afed91faba006c49cd0"
}

rule MalwareBazaar_unknown_017_701921b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "701921b96f6934bffa01eff0ddfe42037de70d7cf96ef859480057d9200b0562"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-24 22:46:48"
  condition:
    hash.sha256(0, filesize) == "701921b96f6934bffa01eff0ddfe42037de70d7cf96ef859480057d9200b0562"
}

rule MalwareBazaar_unknown_018_82608a59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82608a590fa29af44c5b77830074b7e0b9d27174d042c6a8ed6f7119b6d54bb9"
    family = "unknown"
    file_name = "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 22:03:18"
  condition:
    hash.sha256(0, filesize) == "82608a590fa29af44c5b77830074b7e0b9d27174d042c6a8ed6f7119b6d54bb9"
}

rule MalwareBazaar_unknown_019_23b3344b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b"
    family = "unknown"
    file_name = "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 22:02:13"
  condition:
    hash.sha256(0, filesize) == "23b3344bfa7fab78adec1754aba67f57b468a3ea052d56522770ef99497e499b"
}

rule MalwareBazaar_Mirai_020_49f6d68d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49f6d68d8020ab4b83e52ccc80a6fb53605097c264ef46a3de694a48ad520f21"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-24 21:54:44"
  condition:
    hash.sha256(0, filesize) == "49f6d68d8020ab4b83e52ccc80a6fb53605097c264ef46a3de694a48ad520f21"
}

rule MalwareBazaar_Mirai_021_caec10a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caec10a5adfdec9ec202c091306a7af005e38f5b8cd0f59d0dfa5e3b41b343c4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-24 21:54:43"
  condition:
    hash.sha256(0, filesize) == "caec10a5adfdec9ec202c091306a7af005e38f5b8cd0f59d0dfa5e3b41b343c4"
}

rule MalwareBazaar_Mirai_022_62868f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62868f70c9145d6b67edd9d595fbf10d05d51442c3b7e2d4e459e7da1df1e8e2"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-24 21:53:06"
  condition:
    hash.sha256(0, filesize) == "62868f70c9145d6b67edd9d595fbf10d05d51442c3b7e2d4e459e7da1df1e8e2"
}

rule MalwareBazaar_unknown_023_38f50dc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38f50dc222dfcfce713055db0c5270a086ea6bc31353d586119b2b86bc81f557"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 21:52:11"
  condition:
    hash.sha256(0, filesize) == "38f50dc222dfcfce713055db0c5270a086ea6bc31353d586119b2b86bc81f557"
}

rule MalwareBazaar_Mirai_024_df4997d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df4997d19239b1adb12274e20a09dbd9ddd903bb171afea96a469878377fe525"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-24 21:46:01"
  condition:
    hash.sha256(0, filesize) == "df4997d19239b1adb12274e20a09dbd9ddd903bb171afea96a469878377fe525"
}

rule MalwareBazaar_unknown_025_ba158149
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba15814980b4e622b00a3d4fc739681edea7549b3ae0c99de79d2365da590264"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-24 21:44:20"
  condition:
    hash.sha256(0, filesize) == "ba15814980b4e622b00a3d4fc739681edea7549b3ae0c99de79d2365da590264"
}

rule MalwareBazaar_Mirai_026_1e4e68d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e4e68d5e61e9c3159621f6e7dfe07d2cb7a42d5d60e5b0949d9a257f4cd9fc3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-24 21:36:47"
  condition:
    hash.sha256(0, filesize) == "1e4e68d5e61e9c3159621f6e7dfe07d2cb7a42d5d60e5b0949d9a257f4cd9fc3"
}

rule MalwareBazaar_unknown_027_7c33aadf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c33aadf2aaf932241116217b5cc7a96575217a8f93ca131e4bf3def72b4b8db"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-24 21:28:34"
  condition:
    hash.sha256(0, filesize) == "7c33aadf2aaf932241116217b5cc7a96575217a8f93ca131e4bf3def72b4b8db"
}

rule MalwareBazaar_Mirai_028_ddd4725b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddd4725b035f19eb316e983c1e91fb02865fe9878d3b7ca57b1de9000bbd1cc3"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-24 21:16:42"
  condition:
    hash.sha256(0, filesize) == "ddd4725b035f19eb316e983c1e91fb02865fe9878d3b7ca57b1de9000bbd1cc3"
}

rule MalwareBazaar_unknown_029_e87e97d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e87e97d3604ac46b46af03541af99968f268d9cd338d498318d878cb465d8610"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 20:56:48"
  condition:
    hash.sha256(0, filesize) == "e87e97d3604ac46b46af03541af99968f268d9cd338d498318d878cb465d8610"
}

rule MalwareBazaar_Mirai_030_4379770b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4379770bf5e7d2ab7ff966e7d8cd4a59a3182bac56e1b76bec3255d5278ea703"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-24 20:54:46"
  condition:
    hash.sha256(0, filesize) == "4379770bf5e7d2ab7ff966e7d8cd4a59a3182bac56e1b76bec3255d5278ea703"
}

rule MalwareBazaar_unknown_031_d9970bf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9970bf3b3d62d914572bc4dc73d3b71f919411a448e020fc16dc674a19c62ee"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 20:52:11"
  condition:
    hash.sha256(0, filesize) == "d9970bf3b3d62d914572bc4dc73d3b71f919411a448e020fc16dc674a19c62ee"
}

rule MalwareBazaar_unknown_032_9f125d9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f125d9a2259508929f3d321a1db86d7ee381d404ec34be44c096ebbc736b6eb"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-24 20:42:52"
  condition:
    hash.sha256(0, filesize) == "9f125d9a2259508929f3d321a1db86d7ee381d404ec34be44c096ebbc736b6eb"
}

rule MalwareBazaar_Mirai_033_4ac8325d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ac8325d485cdd1b00d808223b9e60a6bc7dd62fe409703f3112009f6d737139"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-08-24 20:37:14"
  condition:
    hash.sha256(0, filesize) == "4ac8325d485cdd1b00d808223b9e60a6bc7dd62fe409703f3112009f6d737139"
}

rule MalwareBazaar_unknown_034_2cfab543
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cfab543fa110359af5b5b1c525091c0dffd77dee1be7b034c3e9194be675a6a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 20:37:00"
  condition:
    hash.sha256(0, filesize) == "2cfab543fa110359af5b5b1c525091c0dffd77dee1be7b034c3e9194be675a6a"
}

rule MalwareBazaar_Mirai_035_1c315965
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c31596586ddf65d16aec86ddf43df1ca67cfaa43815b9170f031a9efcb0e8dc"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-24 20:36:59"
  condition:
    hash.sha256(0, filesize) == "1c31596586ddf65d16aec86ddf43df1ca67cfaa43815b9170f031a9efcb0e8dc"
}

rule MalwareBazaar_Mirai_036_eeb0b68d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb0b68d4dd520776f44644d2da00b3ed3dc55edce73b663b4d4748619065823"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-08-24 20:36:58"
  condition:
    hash.sha256(0, filesize) == "eeb0b68d4dd520776f44644d2da00b3ed3dc55edce73b663b4d4748619065823"
}

rule MalwareBazaar_Mirai_037_fa87d394
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa87d394aeef40501a545ec76bc1599c5e4959e9f4b69f1c0f455fbdfbb2b10a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-24 20:30:58"
  condition:
    hash.sha256(0, filesize) == "fa87d394aeef40501a545ec76bc1599c5e4959e9f4b69f1c0f455fbdfbb2b10a"
}

rule MalwareBazaar_unknown_038_c94f29db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c94f29dbdb37f18fd314fe38571ab19194e35dd4eac957c8710e5ca1e4d50ab0"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-24 20:30:56"
  condition:
    hash.sha256(0, filesize) == "c94f29dbdb37f18fd314fe38571ab19194e35dd4eac957c8710e5ca1e4d50ab0"
}

rule MalwareBazaar_unknown_039_19646fbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19646fbbd930cecd76c64022dccf8b2a6c3c0d76d577d4ff00f92fa215113ad4"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-24 20:26:58"
  condition:
    hash.sha256(0, filesize) == "19646fbbd930cecd76c64022dccf8b2a6c3c0d76d577d4ff00f92fa215113ad4"
}

rule MalwareBazaar_Mirai_040_6ff8c9ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff8c9cabc23696ba9120a1125520c8928cff24d687cf944b1c3bbe92a00b135"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-24 20:25:00"
  condition:
    hash.sha256(0, filesize) == "6ff8c9cabc23696ba9120a1125520c8928cff24d687cf944b1c3bbe92a00b135"
}

rule MalwareBazaar_Mirai_041_9a9c5c66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a9c5c666ef384460c68200de9badf75910be4dc2101b8eb62448ccd52cf2e81"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-24 20:24:59"
  condition:
    hash.sha256(0, filesize) == "9a9c5c666ef384460c68200de9badf75910be4dc2101b8eb62448ccd52cf2e81"
}

rule MalwareBazaar_Mirai_042_a458d1a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a458d1a2770a455c1360388fd13bcffd69989835c3c0993917d863a996566b5a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-24 20:16:55"
  condition:
    hash.sha256(0, filesize) == "a458d1a2770a455c1360388fd13bcffd69989835c3c0993917d863a996566b5a"
}

rule MalwareBazaar_unknown_043_f077cc70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f077cc7061c6c9f0c280ec6507a74b00887f1ebe1047d58ddd0160f7de4fc70c"
    family = "unknown"
    file_name = "Payroll_statement.pdf.pdf"
    file_type = "pdf"
    first_seen = "2026-08-24 19:55:17"
  condition:
    hash.sha256(0, filesize) == "f077cc7061c6c9f0c280ec6507a74b00887f1ebe1047d58ddd0160f7de4fc70c"
}

rule MalwareBazaar_unknown_044_6234c22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6234c22a90248540b7e12261de5ffb94426d85b08694e9e06d72a644ce215e0e"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 19:52:11"
  condition:
    hash.sha256(0, filesize) == "6234c22a90248540b7e12261de5ffb94426d85b08694e9e06d72a644ce215e0e"
}

rule MalwareBazaar_AsyncRAT_045_a4e921a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684"
    family = "AsyncRAT"
    file_name = "FLY88APP.exe"
    file_type = "exe"
    first_seen = "2026-08-24 19:51:59"
  condition:
    hash.sha256(0, filesize) == "a4e921a7afacd5c9d8037425088e87847b0171e8985adc659cdb32d265db2684"
}

rule MalwareBazaar_unknown_046_74f92110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74f92110966d46b49dab95189364618795e12e8895f0246e37e7e7b8f67346cf"
    family = "unknown"
    file_name = "Invoice.ps1"
    file_type = "ps1"
    first_seen = "2026-08-24 19:49:00"
  condition:
    hash.sha256(0, filesize) == "74f92110966d46b49dab95189364618795e12e8895f0246e37e7e7b8f67346cf"
}

rule MalwareBazaar_unknown_047_d4d2b7e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4d2b7e99fdc2ce7eca14986a189d974bb24e42fea69b4bf6424301146d869bd"
    family = "unknown"
    file_name = "Invoice.zip"
    file_type = "zip"
    first_seen = "2026-08-24 19:48:47"
  condition:
    hash.sha256(0, filesize) == "d4d2b7e99fdc2ce7eca14986a189d974bb24e42fea69b4bf6424301146d869bd"
}

rule MalwareBazaar_unknown_048_3e9ca509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e9ca509f6c5bdaaac14abdb6ab28f3cce3fd4efee65f5e0ddbeb4e8d7833cf6"
    family = "unknown"
    file_name = "main.py"
    file_type = "unknown"
    first_seen = "2026-08-24 19:47:57"
  condition:
    hash.sha256(0, filesize) == "3e9ca509f6c5bdaaac14abdb6ab28f3cce3fd4efee65f5e0ddbeb4e8d7833cf6"
}

rule MalwareBazaar_unknown_049_cee5f423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee5f4234344c49796812e11c5b14c68089c09ee1c772e71ff1cc296a26925ca"
    family = "unknown"
    file_name = "Invoice.lnk"
    file_type = "lnk"
    first_seen = "2026-08-24 19:46:47"
  condition:
    hash.sha256(0, filesize) == "cee5f4234344c49796812e11c5b14c68089c09ee1c772e71ff1cc296a26925ca"
}

rule MalwareBazaar_unknown_050_ab4c9f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4c9f360c6d5f3e0d9a90c713d4ccfb2780ef52da41a028d6516cf9ea5e9238"
    family = "unknown"
    file_name = "totolink.sh"
    file_type = "sh"
    first_seen = "2026-08-24 19:39:44"
  condition:
    hash.sha256(0, filesize) == "ab4c9f360c6d5f3e0d9a90c713d4ccfb2780ef52da41a028d6516cf9ea5e9238"
}

rule MalwareBazaar_unknown_051_3426e4a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3426e4a772946d9aa423cc2332a28ea755e91c8b445c50e29c465c72562d9c30"
    family = "unknown"
    file_name = "tplinkrouter.sh"
    file_type = "sh"
    first_seen = "2026-08-24 19:39:25"
  condition:
    hash.sha256(0, filesize) == "3426e4a772946d9aa423cc2332a28ea755e91c8b445c50e29c465c72562d9c30"
}

rule MalwareBazaar_unknown_052_7b331a01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b331a01b8e0e31ed406f358502711b619b618e5e2dd02d48f1b54e8a6030580"
    family = "unknown"
    file_name = "log"
    file_type = "unknown"
    first_seen = "2026-08-24 19:31:15"
  condition:
    hash.sha256(0, filesize) == "7b331a01b8e0e31ed406f358502711b619b618e5e2dd02d48f1b54e8a6030580"
}

rule MalwareBazaar_Mirai_053_057d3ea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057d3ea58a5f5bc53d47386869544f8fd692403bc029a24db9ed26c587366b58"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-24 19:13:24"
  condition:
    hash.sha256(0, filesize) == "057d3ea58a5f5bc53d47386869544f8fd692403bc029a24db9ed26c587366b58"
}

rule MalwareBazaar_Mirai_054_b20f09da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b20f09da61ed52f5603e0c549a5b3880e32e4d34ccaf3f4b1628c76a939e799b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-24 19:13:22"
  condition:
    hash.sha256(0, filesize) == "b20f09da61ed52f5603e0c549a5b3880e32e4d34ccaf3f4b1628c76a939e799b"
}

rule MalwareBazaar_Mirai_055_0fcb8cdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fcb8cddfed9c70b99e202646ca6dc82745685c5ab12db933a93f17ac6471a5b"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-24 19:12:58"
  condition:
    hash.sha256(0, filesize) == "0fcb8cddfed9c70b99e202646ca6dc82745685c5ab12db933a93f17ac6471a5b"
}

rule MalwareBazaar_Mirai_056_9bc48e9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bc48e9fbc56e1b9c9643f1221d518b85498be7ced8dd40301194e7a63a1fbb1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-24 19:12:58"
  condition:
    hash.sha256(0, filesize) == "9bc48e9fbc56e1b9c9643f1221d518b85498be7ced8dd40301194e7a63a1fbb1"
}

rule MalwareBazaar_Mirai_057_880a9ea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "880a9ea4c0bfcff656613559449a906f3da211c977fb8e29927b33322ccdd6dc"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-24 19:12:57"
  condition:
    hash.sha256(0, filesize) == "880a9ea4c0bfcff656613559449a906f3da211c977fb8e29927b33322ccdd6dc"
}

rule MalwareBazaar_unknown_058_c722abf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c722abf3b2b1c1167babcee38fb6ae40369e3e4bf5f16c3940647234a89a2987"
    family = "unknown"
    file_name = "t.sh"
    file_type = "sh"
    first_seen = "2026-08-24 19:12:56"
  condition:
    hash.sha256(0, filesize) == "c722abf3b2b1c1167babcee38fb6ae40369e3e4bf5f16c3940647234a89a2987"
}

rule MalwareBazaar_unknown_059_60c47155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60c471550e9b223efbf44106125c6e97c9132f62d6383f13c63d5a5d15962c9c"
    family = "unknown"
    file_name = "pure.dat"
    file_type = "unknown"
    first_seen = "2026-08-24 19:10:48"
  condition:
    hash.sha256(0, filesize) == "60c471550e9b223efbf44106125c6e97c9132f62d6383f13c63d5a5d15962c9c"
}

rule MalwareBazaar_unknown_060_c1353b26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1353b26a025f7cb9c5b232f87e9d1f40ae92f87ceca592e6326f1296f419ca1"
    family = "unknown"
    file_name = "boss.bat"
    file_type = "bat"
    first_seen = "2026-08-24 19:10:48"
  condition:
    hash.sha256(0, filesize) == "c1353b26a025f7cb9c5b232f87e9d1f40ae92f87ceca592e6326f1296f419ca1"
}

rule MalwareBazaar_unknown_061_582988ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "582988ffe1334f235fc20667fe67538e50f2a918994126c0fa284bfa45e62c44"
    family = "unknown"
    file_name = "bot_arm"
    file_type = "elf"
    first_seen = "2026-08-24 19:05:07"
  condition:
    hash.sha256(0, filesize) == "582988ffe1334f235fc20667fe67538e50f2a918994126c0fa284bfa45e62c44"
}

rule MalwareBazaar_unknown_062_9bd6b530
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd6b5300b97ab253ea6f3377176f5658f9f78bea5d534fdbe71a24ce96831f9"
    family = "unknown"
    file_name = "z28scan_copy_20260824085.vbs"
    file_type = "vbs"
    first_seen = "2026-08-24 19:01:23"
  condition:
    hash.sha256(0, filesize) == "9bd6b5300b97ab253ea6f3377176f5658f9f78bea5d534fdbe71a24ce96831f9"
}

rule MalwareBazaar_RemcosRAT_063_d28dc0f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d28dc0f5aed61adab3547ea9ffba04b4280460a80ed1181b27de4836c4ca655a"
    family = "RemcosRAT"
    file_name = "rNo0998006967505633.vbe"
    file_type = "vbe"
    first_seen = "2026-08-24 19:01:11"
  condition:
    hash.sha256(0, filesize) == "d28dc0f5aed61adab3547ea9ffba04b4280460a80ed1181b27de4836c4ca655a"
}

rule MalwareBazaar_unknown_064_f5b850be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b850be90148056aa4dcc36802479a73a2966a07e7e66562feeee013ed70de5"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:52:16"
  condition:
    hash.sha256(0, filesize) == "f5b850be90148056aa4dcc36802479a73a2966a07e7e66562feeee013ed70de5"
}

rule MalwareBazaar_unknown_065_d48258e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d48258e2d336c98631c4f0936bdbd4c1aeb850f1da2c5a097a38a6ba908910af"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 18:52:11"
  condition:
    hash.sha256(0, filesize) == "d48258e2d336c98631c4f0936bdbd4c1aeb850f1da2c5a097a38a6ba908910af"
}

rule MalwareBazaar_unknown_066_a10cfa5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a10cfa5f8b511c281adebc60c0c34b62f37dd589c4cb136ca578d82c0067a9d2"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:51:09"
  condition:
    hash.sha256(0, filesize) == "a10cfa5f8b511c281adebc60c0c34b62f37dd589c4cb136ca578d82c0067a9d2"
}

rule MalwareBazaar_unknown_067_5bb97826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135"
    family = "unknown"
    file_name = "5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:43:01"
  condition:
    hash.sha256(0, filesize) == "5bb97826cac1543d4699ef3448b66bc9a8b0675d0a71de7626dc7e82b33b5135"
}

rule MalwareBazaar_unknown_068_3675be6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3675be6c9d4f5be9d5404784c438b75baac1b4dda9886fa88ea5459b97ee4b7d"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-08-24 18:35:47"
  condition:
    hash.sha256(0, filesize) == "3675be6c9d4f5be9d5404784c438b75baac1b4dda9886fa88ea5459b97ee4b7d"
}

rule MalwareBazaar_CoinMiner_069_2199808b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2199808b5669b6d4d316ad5f0f2ec8a29c796f178ee43ce2c1166d2d468cecea"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 18:29:34"
  condition:
    hash.sha256(0, filesize) == "2199808b5669b6d4d316ad5f0f2ec8a29c796f178ee43ce2c1166d2d468cecea"
}

rule MalwareBazaar_unknown_070_82a7c620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a7c6208b7b98fda014dbe12d7afd6101941920b4ea87124e19eb6c9cb9f4b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 18:28:34"
  condition:
    hash.sha256(0, filesize) == "82a7c6208b7b98fda014dbe12d7afd6101941920b4ea87124e19eb6c9cb9f4b2"
}

rule MalwareBazaar_unknown_071_49b40f07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68"
    family = "unknown"
    file_name = "49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68.exe"
    file_type = "exe"
    first_seen = "2026-08-24 18:27:25"
  condition:
    hash.sha256(0, filesize) == "49b40f07663805daa576a72d301b7670972430af82c92145b9702feab1bb1c68"
}

rule MalwareBazaar_unknown_072_e9af23e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9af23e5212e38604fd00de454c5dca0f192d976a24e7f7d8480140c9fe8fa38"
    family = "unknown"
    file_name = "DiscordZapret.zip"
    file_type = "zip"
    first_seen = "2026-08-24 18:20:49"
  condition:
    hash.sha256(0, filesize) == "e9af23e5212e38604fd00de454c5dca0f192d976a24e7f7d8480140c9fe8fa38"
}

rule MalwareBazaar_unknown_073_4f5fb39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f5fb39c58955bcab166d2ff557fe6064cd7f7628f16527d32455784d6c7e0ac"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 17:52:11"
  condition:
    hash.sha256(0, filesize) == "4f5fb39c58955bcab166d2ff557fe6064cd7f7628f16527d32455784d6c7e0ac"
}

rule MalwareBazaar_Vidar_074_69daa1a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6"
    family = "Vidar"
    file_name = "69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:34:50"
  condition:
    hash.sha256(0, filesize) == "69daa1a225ee2c4680838016d6ad87e391834c441a9e96f56701e1722dbf7ab6"
}

rule MalwareBazaar_Phorphiex_075_5e6d5240
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e6d5240402036291aff059a205ae94c60b72e45b6faae2f3567d7e7368f5d16"
    family = "Phorphiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-24 17:14:36"
  condition:
    hash.sha256(0, filesize) == "5e6d5240402036291aff059a205ae94c60b72e45b6faae2f3567d7e7368f5d16"
}

rule MalwareBazaar_Vidar_076_670b6d28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c"
    family = "Vidar"
    file_name = "670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:47"
  condition:
    hash.sha256(0, filesize) == "670b6d281f3918638255fd6592f80bfa9d77fcbd78f62071e237978fa329cd2c"
}

rule MalwareBazaar_Vidar_077_b9c86f9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d"
    family = "Vidar"
    file_name = "b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:39"
  condition:
    hash.sha256(0, filesize) == "b9c86f9be2c5c29796f1ffbe53636400add4e4329350d2d839928542cc05786d"
}

rule MalwareBazaar_unknown_078_4980c099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9"
    family = "unknown"
    file_name = "4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9.bin"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:32"
  condition:
    hash.sha256(0, filesize) == "4980c099052a595c008011d0f5a7983d86650a77519f15dc72f21b3b40a021b9"
}

rule MalwareBazaar_unknown_079_97f5bd93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26"
    family = "unknown"
    file_name = "97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26.exe"
    file_type = "exe"
    first_seen = "2026-08-24 17:02:06"
  condition:
    hash.sha256(0, filesize) == "97f5bd9347bb579899de04cd24947af7ea65f9c69fa91cf24435e71205c76a26"
}

rule MalwareBazaar_unknown_080_998b905c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "998b905cff24fa1e98c4b59de79b5fee66a68faf59a9c1b8e4e42a77b40f46a7"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 16:52:11"
  condition:
    hash.sha256(0, filesize) == "998b905cff24fa1e98c4b59de79b5fee66a68faf59a9c1b8e4e42a77b40f46a7"
}

rule MalwareBazaar_unknown_081_2df2599e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382"
    family = "unknown"
    file_name = "2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382.bin"
    file_type = "exe"
    first_seen = "2026-08-24 16:48:16"
  condition:
    hash.sha256(0, filesize) == "2df2599e1f1e5555723ebf783deed130702a1f3484f82d7fa2a4963507b57382"
}

rule MalwareBazaar_unknown_082_b949007b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b949007bb4e1adcd2026c61f79d379dc349bfec86fdad8baddeea64356159ca5"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 16:02:39"
  condition:
    hash.sha256(0, filesize) == "b949007bb4e1adcd2026c61f79d379dc349bfec86fdad8baddeea64356159ca5"
}

rule MalwareBazaar_unknown_083_c20e18f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c20e18f5a2efcdb5a128991570c50bb57236d9b09667cc5cfece1f9ada6e2129"
    family = "unknown"
    file_name = "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 15:57:17"
  condition:
    hash.sha256(0, filesize) == "c20e18f5a2efcdb5a128991570c50bb57236d9b09667cc5cfece1f9ada6e2129"
}

rule MalwareBazaar_unknown_084_ea5b61bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b"
    family = "unknown"
    file_name = "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b.exe"
    file_type = "exe"
    first_seen = "2026-08-24 15:57:05"
  condition:
    hash.sha256(0, filesize) == "ea5b61bc8d140124753c3ec265b5542e0dc5323bfc613e365339a4819808360b"
}

rule MalwareBazaar_Mirai_085_840d6303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "840d6303cf94d4dd8d2bc8d4718535efaee87be41a36b8278f4460efd0e4b912"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 15:52:20"
  condition:
    hash.sha256(0, filesize) == "840d6303cf94d4dd8d2bc8d4718535efaee87be41a36b8278f4460efd0e4b912"
}

rule MalwareBazaar_unknown_086_2464a77c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2464a77c5296a3d37905cd37c52a43e7bc15e7ced8f403d86b7aea7a7082d50f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 15:52:13"
  condition:
    hash.sha256(0, filesize) == "2464a77c5296a3d37905cd37c52a43e7bc15e7ced8f403d86b7aea7a7082d50f"
}

rule MalwareBazaar_Mirai_087_f7e1104b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7e1104b45cc7ee10120174be0218abc628e780b2c598d796cd4c50f647f6322"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 15:51:31"
  condition:
    hash.sha256(0, filesize) == "f7e1104b45cc7ee10120174be0218abc628e780b2c598d796cd4c50f647f6322"
}

rule MalwareBazaar_unknown_088_755f5715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "755f57158a93bf4f884fa819f854f1db27341970c6a2d16824a5f2ff9d66deff"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-24 15:49:17"
  condition:
    hash.sha256(0, filesize) == "755f57158a93bf4f884fa819f854f1db27341970c6a2d16824a5f2ff9d66deff"
}

rule MalwareBazaar_unknown_089_435ba2f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "435ba2f17112114a9a0b3356b4657e5fbd35c7cf311f143d2fb939a1d8a8fc2a"
    family = "unknown"
    file_name = "main.sparc64"
    file_type = "elf"
    first_seen = "2026-08-24 15:49:16"
  condition:
    hash.sha256(0, filesize) == "435ba2f17112114a9a0b3356b4657e5fbd35c7cf311f143d2fb939a1d8a8fc2a"
}

rule MalwareBazaar_Mirai_090_202c64b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202c64b8adf002065f9f272d9ee2949bc1b71411ab0f332ca3daf1d36cfbcd7e"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-24 15:45:32"
  condition:
    hash.sha256(0, filesize) == "202c64b8adf002065f9f272d9ee2949bc1b71411ab0f332ca3daf1d36cfbcd7e"
}

rule MalwareBazaar_Mirai_091_4ea8e41b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ea8e41bc05d6f5a11aec94578a2af51a0cf5f25040890a2a714fa6bc46fa965"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-24 15:44:23"
  condition:
    hash.sha256(0, filesize) == "4ea8e41bc05d6f5a11aec94578a2af51a0cf5f25040890a2a714fa6bc46fa965"
}

rule MalwareBazaar_Mirai_092_e01e53f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e01e53f0eff39e22fdfbd50fd17bdc39f5db20eddf4c7f6d1b61271f6f63c8a1"
    family = "Mirai"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-24 15:41:42"
  condition:
    hash.sha256(0, filesize) == "e01e53f0eff39e22fdfbd50fd17bdc39f5db20eddf4c7f6d1b61271f6f63c8a1"
}

rule MalwareBazaar_unknown_093_75b6135f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75b6135f464b51aa7d8d0547c979027c0bf3379ec00d6e334b4e5d0e15404a7d"
    family = "unknown"
    file_name = "main.microblazeel"
    file_type = "elf"
    first_seen = "2026-08-24 15:39:27"
  condition:
    hash.sha256(0, filesize) == "75b6135f464b51aa7d8d0547c979027c0bf3379ec00d6e334b4e5d0e15404a7d"
}

rule MalwareBazaar_unknown_094_6e134b0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e134b0a2d2247cab988db2b0bfc7a511b1e7c79c0d3699536558352abb47b40"
    family = "unknown"
    file_name = "main.mips32r6el"
    file_type = "elf"
    first_seen = "2026-08-24 15:39:26"
  condition:
    hash.sha256(0, filesize) == "6e134b0a2d2247cab988db2b0bfc7a511b1e7c79c0d3699536558352abb47b40"
}

rule MalwareBazaar_unknown_095_1a4d9b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a4d9b7355fc76aa8eaf91c67b9ace2cc3fbf70b13d88d4ce565ed9aa15f0b5f"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-24 15:37:15"
  condition:
    hash.sha256(0, filesize) == "1a4d9b7355fc76aa8eaf91c67b9ace2cc3fbf70b13d88d4ce565ed9aa15f0b5f"
}

rule MalwareBazaar_Mirai_096_55e231d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e231d9583fbd2e372ac0f8ef6f5fa97cee1ecd30a934c8d8811328f3601585"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-24 15:35:19"
  condition:
    hash.sha256(0, filesize) == "55e231d9583fbd2e372ac0f8ef6f5fa97cee1ecd30a934c8d8811328f3601585"
}

rule MalwareBazaar_Mirai_097_a2901d93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2901d935af19fc75533750e8948dc291b57fa4dbbc62ee7917823320ac927e2"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-24 15:34:40"
  condition:
    hash.sha256(0, filesize) == "a2901d935af19fc75533750e8948dc291b57fa4dbbc62ee7917823320ac927e2"
}

rule MalwareBazaar_unknown_098_89f87c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89f87c3a7c6aaa5c2d9c9bfee5aa08cee02072776631d39be4b9f0207dcb3e4e"
    family = "unknown"
    file_name = "main.mips32r5el"
    file_type = "elf"
    first_seen = "2026-08-24 15:34:39"
  condition:
    hash.sha256(0, filesize) == "89f87c3a7c6aaa5c2d9c9bfee5aa08cee02072776631d39be4b9f0207dcb3e4e"
}

rule MalwareBazaar_unknown_099_2847a02e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2847a02ead80a60c25245bca169655b89fb2c724cb7bd7ec184860d94336b9c1"
    family = "unknown"
    file_name = "stage2.bin"
    file_type = "exe"
    first_seen = "2026-08-24 15:34:11"
  condition:
    hash.sha256(0, filesize) == "2847a02ead80a60c25245bca169655b89fb2c724cb7bd7ec184860d94336b9c1"
}

rule MalwareBazaar_Mirai_100_13967a1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13967a1f8467a05a8a162856547c123359029fccf00c8c2bb1988daa1a451d86"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-24 15:33:19"
  condition:
    hash.sha256(0, filesize) == "13967a1f8467a05a8a162856547c123359029fccf00c8c2bb1988daa1a451d86"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

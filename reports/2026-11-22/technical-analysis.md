# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-22

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 671 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 671 |
| Unique family labels | 8 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 61 |
| Mirai | 17 |
| Snowlight | 9 |
| Prometei | 6 |
| njrat | 3 |
| AsyncRAT | 2 |
| WARDENStealer | 1 |
| VShell | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 68 |
| macho | 15 |
| exe | 11 |
| dll | 5 |
| zsh | 1 |

## Per-Sample Analysis

### Sample 1: `b83222b68af47625`

| Field | Value |
|---|---|
| SHA-256 | `b83222b68af47625da71b332e68969894dcaf4de7f026d995e9b9562432963b0` |
| Family label | `unknown` |
| File name | `stage3_payload.dll` |
| File type | `dll` |
| First seen | `2026-11-22 06:43:27` |
| Reporter | `Daydream` |
| Tags | `dll, dotnet, il-virtualized, PavinLoader, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dbaa32f86e7bd8c7a897b8538e22960` |
| SHA-1 | `5d1968465de021edae34cd0af5f6e2076deed6ee` |
| SHA-256 | `b83222b68af47625da71b332e68969894dcaf4de7f026d995e9b9562432963b0` |
| SHA3-384 | `27e9a70afc76946f421a39514e29c03e503d53a6f123b310525e82be4ba75201b7685cfaf1596e66466a7e817bbe0211` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T18786B5436B04CB01C878353A42FA6D3D6361F9CB1BB2890FDF427BAB5DD65A59D4C20A` |
| SSDEEP | `196608:LseUgmYypLWh31H7KJm2oXir63EusMUC:LseUgmYypLW/bKJm2oXiOQMU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_b83222b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83222b68af47625da71b332e68969894dcaf4de7f026d995e9b9562432963b0"
    family = "unknown"
    file_name = "stage3_payload.dll"
    file_type = "dll"
    first_seen = "2026-11-22 06:43:27"
  condition:
    hash.sha256(0, filesize) == "b83222b68af47625da71b332e68969894dcaf4de7f026d995e9b9562432963b0"
}
```

### Sample 2: `d5b6c533464791de`

| Field | Value |
|---|---|
| SHA-256 | `d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9` |
| Family label | `unknown` |
| File name | `stage2_GeoAPI.dll` |
| File type | `dll` |
| First seen | `2026-11-22 06:43:20` |
| Reporter | `Daydream` |
| Tags | `custom-vm, dll, dotnet, MSBuild, PavinLoader, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e97bddc10ae0c5724c80bd5cca023f1e` |
| SHA-1 | `123e2e660e6a2fe2d63cb4bfbcbd50741d8587b5` |
| SHA-256 | `d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9` |
| SHA3-384 | `a54b66fa3849384a9345aa264035d5bb3358de8375552631903e6e9418514a4573bc9cdd4ca402a351ac630acf5a6ea5` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T189B33B08579CF556F6EE0539A4F211585378F26B26C3EB4F0C8858B699833CA58C8EF7` |
| SSDEEP | `1536:hO30OxNIBZG1IpY1wUb6SeDA/UKMIEHx1cd8H75qUzJoJLBU:KXxmPY1wUADY2IEHXcKb5qjJL2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_d5b6c533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9"
    family = "unknown"
    file_name = "stage2_GeoAPI.dll"
    file_type = "dll"
    first_seen = "2026-11-22 06:43:20"
  condition:
    hash.sha256(0, filesize) == "d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9"
}
```

### Sample 3: `6625aea96db13a28`

| Field | Value |
|---|---|
| SHA-256 | `6625aea96db13a283507c36ab57d6f5d9b40a1d8d282a99c2f90204fc93db10e` |
| Family label | `unknown` |
| File name | `macho_6625aea96db1.bin` |
| File type | `macho` |
| First seen | `2026-11-22 06:27:18` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3a28788fa0cc47a3306fcc00bf815ca` |
| SHA-1 | `e79a4336fa3b5b195146b4837303e2ce59f0e42a` |
| SHA-256 | `6625aea96db13a283507c36ab57d6f5d9b40a1d8d282a99c2f90204fc93db10e` |
| SHA3-384 | `00607cebcf08d50073030bc51cb4a391f57737eaa33127413d73d8239b051b309fa46411f163e1f3a90fe892e91073dc` |
| TLSH | `T1E2362320DA350477E1099A326E242F5E58DC97C0EA44BAFC13729B727E367537AF7122` |
| SSDEEP | `49152:ZIc2ZnC2GbIrNB1Zx5HM+ist6ZRp8QMkeDI9P8LOlmDQKJ16I/wFNprZD3nMiisE:heDEHmVr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_6625aea9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6625aea96db13a283507c36ab57d6f5d9b40a1d8d282a99c2f90204fc93db10e"
    family = "unknown"
    file_name = "macho_6625aea96db1.bin"
    file_type = "macho"
    first_seen = "2026-11-22 06:27:18"
  condition:
    hash.sha256(0, filesize) == "6625aea96db13a283507c36ab57d6f5d9b40a1d8d282a99c2f90204fc93db10e"
}
```

### Sample 4: `db3781a0d5193d2d`

| Field | Value |
|---|---|
| SHA-256 | `db3781a0d5193d2dafb6c332844dccaa613ea2954f9cafc4a1ac2316a3febf74` |
| Family label | `unknown` |
| File name | `stage1_db3781a0d519.zsh` |
| File type | `zsh` |
| First seen | `2026-11-22 06:27:10` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, macOS, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bc13cb2929da8713dfeab3c1d0bd6d4` |
| SHA-1 | `cc81813ed21f115200d8046e19c2d664651b4224` |
| SHA-256 | `db3781a0d5193d2dafb6c332844dccaa613ea2954f9cafc4a1ac2316a3febf74` |
| SHA3-384 | `7e7505902ed723146efcc9fc4b5dd559e192d847483bf7ba490c456bba98fd72595abc79352e0887a94869524b410c2b` |
| TLSH | `T188613B74D521A170D664153AAA973D281BEE36F94FD8F628B0B79F80185FE41E10310A` |
| SSDEEP | `96:c8iuEbWj+AHituFMR4SWuM7QDCmOWXTYlL4l1wsJ7Uv52CcxTfxR:cCFjJHitvqD6Cm8U/J7Cotj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zsh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_db3781a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3781a0d5193d2dafb6c332844dccaa613ea2954f9cafc4a1ac2316a3febf74"
    family = "unknown"
    file_name = "stage1_db3781a0d519.zsh"
    file_type = "zsh"
    first_seen = "2026-11-22 06:27:10"
  condition:
    hash.sha256(0, filesize) == "db3781a0d5193d2dafb6c332844dccaa613ea2954f9cafc4a1ac2316a3febf74"
}
```

### Sample 5: `79bd50b55be8f108`

| Field | Value |
|---|---|
| SHA-256 | `79bd50b55be8f1084fcb6c6e101efd3e301377357a9026b43ac2d7fb101c4132` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-22 06:08:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4497d16e926721b23888c6a0a267598a` |
| SHA-1 | `227d1d949bc2a75237da5bf352bc1692a2dbf29b` |
| SHA-256 | `79bd50b55be8f1084fcb6c6e101efd3e301377357a9026b43ac2d7fb101c4132` |
| SHA3-384 | `1f752546d6e884124890e8719f83f7796d833b01a65ced203eb2047fd3822f12ef3cb8bdafad650034fc6054fe65cb93` |
| TLSH | `T161556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSY:SDjxB4m5n8XlaPWi+d+a4TjxQP46` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_005_79bd50b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79bd50b55be8f1084fcb6c6e101efd3e301377357a9026b43ac2d7fb101c4132"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 06:08:05"
  condition:
    hash.sha256(0, filesize) == "79bd50b55be8f1084fcb6c6e101efd3e301377357a9026b43ac2d7fb101c4132"
}
```

### Sample 6: `51168eace244c00e`

| Field | Value |
|---|---|
| SHA-256 | `51168eace244c00e97e0bf25045cee749fa000d5e82ecbf7820f9b3ad285bef9` |
| Family label | `unknown` |
| File name | `easyshell-l64-51168eace244c00e.bin` |
| File type | `elf` |
| First seen | `2026-11-22 06:06:24` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `684f108169e00995f3a5a819cd0e2026` |
| SHA-1 | `c100385cc76198f9380c6a753c3284809de5a5ed` |
| SHA-256 | `51168eace244c00e97e0bf25045cee749fa000d5e82ecbf7820f9b3ad285bef9` |
| SHA3-384 | `ae733a8a1df3933d1284c135537314b77c42eedfa6b95de6409b33b19f8e550e7db05869352173df07ac77172fb9dd9c` |
| TLSH | `T143267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxi3H8hIU6iKHh:OYjiiKgib9qRGcEul3cW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_51168eac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51168eace244c00e97e0bf25045cee749fa000d5e82ecbf7820f9b3ad285bef9"
    family = "unknown"
    file_name = "easyshell-l64-51168eace244c00e.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:06:24"
  condition:
    hash.sha256(0, filesize) == "51168eace244c00e97e0bf25045cee749fa000d5e82ecbf7820f9b3ad285bef9"
}
```

### Sample 7: `b4e1ff8d3bf8835b`

| Field | Value |
|---|---|
| SHA-256 | `b4e1ff8d3bf8835bce05f991c48b5d7151a73fbc4865737e919973ebd2b17517` |
| Family label | `unknown` |
| File name | `easyshell-l32-b4e1ff8d3bf8835b.bin` |
| File type | `elf` |
| First seen | `2026-11-22 06:06:12` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c1fb1831fd2d482cdb1292bc6c1a3e0` |
| SHA-1 | `2523cbc6eb1ea4bc2686055b21fb702ba4153d02` |
| SHA-256 | `b4e1ff8d3bf8835bce05f991c48b5d7151a73fbc4865737e919973ebd2b17517` |
| SHA3-384 | `ad4643f7a7baae76e3c3392be73753bf4e96f4810fbeba7d8c794c3f7ce9a755ba41f70f5c13c75ce9a64ee44a2998fb` |
| TLSH | `T138068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1dF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1ddb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_b4e1ff8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4e1ff8d3bf8835bce05f991c48b5d7151a73fbc4865737e919973ebd2b17517"
    family = "unknown"
    file_name = "easyshell-l32-b4e1ff8d3bf8835b.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:06:12"
  condition:
    hash.sha256(0, filesize) == "b4e1ff8d3bf8835bce05f991c48b5d7151a73fbc4865737e919973ebd2b17517"
}
```

### Sample 8: `8c860d4f5a0bc5a5`

| Field | Value |
|---|---|
| SHA-256 | `8c860d4f5a0bc5a521cf9e2d2fcefd204bb937640e67c0fc0e939caeb626cec1` |
| Family label | `unknown` |
| File name | `easyshell-l128-8c860d4f5a0bc5a5.bin` |
| File type | `elf` |
| First seen | `2026-11-22 06:06:04` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c685ecd28956f2b966d6dec49302a717` |
| SHA-1 | `b19abc15ef8282f6cc1f1718d61868073479dd20` |
| SHA-256 | `8c860d4f5a0bc5a521cf9e2d2fcefd204bb937640e67c0fc0e939caeb626cec1` |
| SHA3-384 | `e3e29d0e528c30a7f5e149f0f7975b8ccd6e1ea21b9ecfa606e38bba2b4bfcb53b06e3a8c70c9844d358d8cd2faa271c` |
| TLSH | `T14B067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CI:FUkCxwUGnaPdX8PhAS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_8c860d4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c860d4f5a0bc5a521cf9e2d2fcefd204bb937640e67c0fc0e939caeb626cec1"
    family = "unknown"
    file_name = "easyshell-l128-8c860d4f5a0bc5a5.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:06:04"
  condition:
    hash.sha256(0, filesize) == "8c860d4f5a0bc5a521cf9e2d2fcefd204bb937640e67c0fc0e939caeb626cec1"
}
```

### Sample 9: `d3b80a7d6395872a`

| Field | Value |
|---|---|
| SHA-256 | `d3b80a7d6395872ad3f0f3da938d6f9de10a37c92f1d633f268a452eb983bf93` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-d3b80a7d6395872a.bin` |
| File type | `macho` |
| First seen | `2026-11-22 06:05:56` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae812dda40377d1cececdab7a6217081` |
| SHA-1 | `09ffe2289537d9fc8737c2821edc34786c89102f` |
| SHA-256 | `d3b80a7d6395872ad3f0f3da938d6f9de10a37c92f1d633f268a452eb983bf93` |
| SHA3-384 | `cf29c4f778551d339b17d788c1120da953082ea3bf3a7d5824e2ce3217d4641485ddf6a23ce7c2ea8438791eba657d48` |
| TLSH | `T158F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgQsj5g5FIU6icBV8GQU5NZm+lzg:8SeI1gkkvTgQt5C+OGU5NZm+lzg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_d3b80a7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3b80a7d6395872ad3f0f3da938d6f9de10a37c92f1d633f268a452eb983bf93"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-d3b80a7d6395872a.bin"
    file_type = "macho"
    first_seen = "2026-11-22 06:05:56"
  condition:
    hash.sha256(0, filesize) == "d3b80a7d6395872ad3f0f3da938d6f9de10a37c92f1d633f268a452eb983bf93"
}
```

### Sample 10: `5d323e7e0a47d099`

| Field | Value |
|---|---|
| SHA-256 | `5d323e7e0a47d099f1f8d883919abfbcc50dbb537f8f711c57bd1ff6ac6cad58` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-5d323e7e0a47d099.bin` |
| File type | `macho` |
| First seen | `2026-11-22 06:05:49` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a72cae792773f8eefbf30bed1d1e2422` |
| SHA-1 | `8720f61581e55c2576076c590fe82c5eeaf9a59f` |
| SHA-256 | `5d323e7e0a47d099f1f8d883919abfbcc50dbb537f8f711c57bd1ff6ac6cad58` |
| SHA3-384 | `6b1cd3fdf05fdd5349ef5fd86d1436ca1c62b3934e44b009c59cd8f964a554e08c65a03a401234b622d36fdaf77545dd` |
| TLSH | `T143168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6fKhx+wgbZmBlz4X:kyLbLNomEr6fKjm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_5d323e7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d323e7e0a47d099f1f8d883919abfbcc50dbb537f8f711c57bd1ff6ac6cad58"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-5d323e7e0a47d099.bin"
    file_type = "macho"
    first_seen = "2026-11-22 06:05:49"
  condition:
    hash.sha256(0, filesize) == "5d323e7e0a47d099f1f8d883919abfbcc50dbb537f8f711c57bd1ff6ac6cad58"
}
```

### Sample 11: `5fee32ba6b1747a1`

| Field | Value |
|---|---|
| SHA-256 | `5fee32ba6b1747a1246930e49096f224e0cdf4f9d82386e92ec3fb1b36f99527` |
| Family label | `unknown` |
| File name | `easyshell-a64-5fee32ba6b1747a1.bin` |
| File type | `elf` |
| First seen | `2026-11-22 06:05:39` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25b91087ab429ac8c88c5fb672414bca` |
| SHA-1 | `9573e465d1adbded53349a46ee95a069948b7634` |
| SHA-256 | `5fee32ba6b1747a1246930e49096f224e0cdf4f9d82386e92ec3fb1b36f99527` |
| SHA3-384 | `f8f9c463da2bb9a51b692539e390a54cceea101ace200df2f3d1c261bb307b33f332537a9ab58bb674f7c5d30d886ca4` |
| TLSH | `T11106B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WdGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WdLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_5fee32ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fee32ba6b1747a1246930e49096f224e0cdf4f9d82386e92ec3fb1b36f99527"
    family = "unknown"
    file_name = "easyshell-a64-5fee32ba6b1747a1.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:05:39"
  condition:
    hash.sha256(0, filesize) == "5fee32ba6b1747a1246930e49096f224e0cdf4f9d82386e92ec3fb1b36f99527"
}
```

### Sample 12: `6e237da8c748e4af`

| Field | Value |
|---|---|
| SHA-256 | `6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6` |
| Family label | `unknown` |
| File name | `easyshell-a32-6e237da8c748e4af.bin` |
| File type | `elf` |
| First seen | `2026-11-22 06:05:31` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e8e06b3571bbe8168494ffc89d7b2b5` |
| SHA-1 | `3b89a8f25a8639c9aff7e6174cdba4ea1629b47e` |
| SHA-256 | `6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6` |
| SHA3-384 | `ee0cdbb3fb0964a92542a4d53bb9b2112e8bfd2c65c84daf54e871f6f2adc13af8edd59ddb3c3b248c34adae2fd10a0c` |
| TLSH | `T1B2F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBL:FhvZpiEGUx+pVdq62laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_6e237da8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6"
    family = "unknown"
    file_name = "easyshell-a32-6e237da8c748e4af.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:05:31"
  condition:
    hash.sha256(0, filesize) == "6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6"
}
```

### Sample 13: `ef91275146f14b58`

| Field | Value |
|---|---|
| SHA-256 | `ef91275146f14b583e829410df052ae84bb770f5d50295d068d9a0e3e98ca887` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-22 06:02:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de44b8bb766c4821ae00842a927b7af8` |
| SHA-1 | `fc93bb85121d78498f2f26e92a6ed41350438769` |
| SHA-256 | `ef91275146f14b583e829410df052ae84bb770f5d50295d068d9a0e3e98ca887` |
| SHA3-384 | `192fdcb7519639cbc8c79c84d26cc5ae412e67bca000bc52139a41b5eaa03b7cb5e556a9543ec6b0b887ce84aae6f52a` |
| TLSH | `T1AA556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSH:SDjxB4m5n8XlaPWi+d+a4TjxQP4F` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_013_ef912751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef91275146f14b583e829410df052ae84bb770f5d50295d068d9a0e3e98ca887"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 06:02:05"
  condition:
    hash.sha256(0, filesize) == "ef91275146f14b583e829410df052ae84bb770f5d50295d068d9a0e3e98ca887"
}
```

### Sample 14: `4d2cf54f047be072`

| Field | Value |
|---|---|
| SHA-256 | `4d2cf54f047be0726d8f4c32a177c6620729457745ed24c63cdbcde1f091e35c` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-22 05:48:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6eca8714f29db923d861465b1f317cf` |
| SHA-1 | `cb1ab39498235c1e06a6799fab23863b8dcf03ca` |
| SHA-256 | `4d2cf54f047be0726d8f4c32a177c6620729457745ed24c63cdbcde1f091e35c` |
| SHA3-384 | `c744b4d17f6145b840e30d6788ff53a94e48f583acd600b200263e8e38ad56b131f7ea2ca7a1a71878152fac1eb066fc` |
| TLSH | `T189556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSG:SDjxB4m5n8XlaPWi+d+a4TjxQP44` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_014_4d2cf54f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d2cf54f047be0726d8f4c32a177c6620729457745ed24c63cdbcde1f091e35c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:48:08"
  condition:
    hash.sha256(0, filesize) == "4d2cf54f047be0726d8f4c32a177c6620729457745ed24c63cdbcde1f091e35c"
}
```

### Sample 15: `b2a6bec11bc9297a`

| Field | Value |
|---|---|
| SHA-256 | `b2a6bec11bc9297a16f8516a34bf513c34f4e8cd7f3015ac223ed0b0bdd8e473` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-22 05:48:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac20d4ea7ab12c384feeec7aecfe54d6` |
| SHA-1 | `f17787012f6b03a220bedb580ad77518d142d5b8` |
| SHA-256 | `b2a6bec11bc9297a16f8516a34bf513c34f4e8cd7f3015ac223ed0b0bdd8e473` |
| SHA3-384 | `5292cbbd317d6e8423608fde33afb77884b4ff110a8e8b21b0335987f97263618d2d67588f039df535ade3389763588c` |
| TLSH | `T113556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSv:SDjxB4m5n8XlaPWi+d+a4TjxQP49` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_015_b2a6bec1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a6bec11bc9297a16f8516a34bf513c34f4e8cd7f3015ac223ed0b0bdd8e473"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:48:05"
  condition:
    hash.sha256(0, filesize) == "b2a6bec11bc9297a16f8516a34bf513c34f4e8cd7f3015ac223ed0b0bdd8e473"
}
```

### Sample 16: `324d121016696bb6`

| Field | Value |
|---|---|
| SHA-256 | `324d121016696bb62b0cda3c7dee7e8f931acea7cf7231890cd772accb666e0e` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-22 05:43:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89587dd982fc9229232bc02e4d80a6a5` |
| SHA-1 | `f97c25406319df46f547ba6e9aa1e78815c49bea` |
| SHA-256 | `324d121016696bb62b0cda3c7dee7e8f931acea7cf7231890cd772accb666e0e` |
| SHA3-384 | `a807bad324157a4aeb77f330c291c8565e8e233fdfff6f2f69323044ecd215c9315b0e2ff5842d1eb0ce0c83f8bc89fa` |
| TLSH | `T130556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS/:SDjxB4m5n8XlaPWi+d+a4TjxQP49` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_016_324d1210
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "324d121016696bb62b0cda3c7dee7e8f931acea7cf7231890cd772accb666e0e"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:43:06"
  condition:
    hash.sha256(0, filesize) == "324d121016696bb62b0cda3c7dee7e8f931acea7cf7231890cd772accb666e0e"
}
```

### Sample 17: `97b11141a91af93a`

| Field | Value |
|---|---|
| SHA-256 | `97b11141a91af93a778afb3ccc68100fac980c1daa41df6ac65cd7034382b287` |
| Family label | `Mirai` |
| File name | `splm68k` |
| File type | `elf` |
| First seen | `2026-11-22 05:41:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bfda50dcb29fffd934c2499121f3fad` |
| SHA-1 | `2458608f305a6ef43b2d96807ce6c4e63a093534` |
| SHA-256 | `97b11141a91af93a778afb3ccc68100fac980c1daa41df6ac65cd7034382b287` |
| SHA3-384 | `f56cd0e2268f275a936a510df0c3c03e35a8ae3025c3998af6a21955fff4bd87bac582c49081315db53864eda44ef632` |
| TLSH | `T112D35CD2F400DE7DFC0EE73785574A0AB271F3A261920776B257A527ED350A50A2EF82` |
| SSDEEP | `3072:Iy4uebthLxkjWW7AfZSnlCC777777777EFx1ojBmy97Va3/o8cdozH0HTc:IMebtXkjWW7AfZ2lCW0y9ha3/ncy0HTc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_97b11141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b11141a91af93a778afb3ccc68100fac980c1daa41df6ac65cd7034382b287"
    family = "Mirai"
    file_name = "splm68k"
    file_type = "elf"
    first_seen = "2026-11-22 05:41:05"
  condition:
    hash.sha256(0, filesize) == "97b11141a91af93a778afb3ccc68100fac980c1daa41df6ac65cd7034382b287"
}
```

### Sample 18: `77ee1ac0e1cebe54`

| Field | Value |
|---|---|
| SHA-256 | `77ee1ac0e1cebe542621f7696c594b3d19f32d5f1784a8e9b9fbe879c68fbc1e` |
| Family label | `Mirai` |
| File name | `nklsh4` |
| File type | `elf` |
| First seen | `2026-11-22 05:35:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a44316441c517c6b0f4bf1566a0aa19` |
| SHA-1 | `82c60423099be55295afc4989eae2f1b6cd748c3` |
| SHA-256 | `77ee1ac0e1cebe542621f7696c594b3d19f32d5f1784a8e9b9fbe879c68fbc1e` |
| SHA3-384 | `348fba9d0733bc8277a63cd431ceabc6d267114b5a4b401289e04a460fabcb3d337a3082cd247568167c3addea34f86e` |
| TLSH | `T129C3BF61D9E9ADA0D16D11F0B0709F7947339490558B0EF75AA8C66890C3FC8F68ABBC` |
| SSDEEP | `3072:dl7Cagcv8Co6p0t5ln3oJ92tlAQbquGfGV:dkalECoJXlnO+PKeV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_77ee1ac0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77ee1ac0e1cebe542621f7696c594b3d19f32d5f1784a8e9b9fbe879c68fbc1e"
    family = "Mirai"
    file_name = "nklsh4"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:13"
  condition:
    hash.sha256(0, filesize) == "77ee1ac0e1cebe542621f7696c594b3d19f32d5f1784a8e9b9fbe879c68fbc1e"
}
```

### Sample 19: `ea3ba48d47911939`

| Field | Value |
|---|---|
| SHA-256 | `ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1` |
| Family label | `Mirai` |
| File name | `splarm7` |
| File type | `elf` |
| First seen | `2026-11-22 05:35:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15dcfd6acceefce4e504988e4e8343da` |
| SHA-1 | `0fef469e92ef8ad1af24d9b529fc45369a491557` |
| SHA-256 | `ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1` |
| SHA3-384 | `00c249353cbcd6d32a0bd8bc97b62d9f8498ef207201694ec8430437d30a338ce6be1e48d713f5b03463009203876966` |
| TLSH | `T14DF32A95F8819B11D5D635BAFE2F52CD33130BBCE3FA31129E249B24638A95B0E3B505` |
| TELFHASH | `t1fcf0c96291d88af839d0c3a6c2f9121f53f9b7b2a304122c062dc6db5e41ac93131803` |
| SSDEEP | `3072:Im3Za1C4pNHPeG8IjoCRDydP4/zEfNok0Ba2FayQxMEWiTEjEVOIGA:Im3Za1/NH2ykCE94/gVuBa2FayQxxWDs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_ea3ba48d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1"
    family = "Mirai"
    file_name = "splarm7"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:11"
  condition:
    hash.sha256(0, filesize) == "ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1"
}
```

### Sample 20: `be758e9e5ced1c67`

| Field | Value |
|---|---|
| SHA-256 | `be758e9e5ced1c67dddd360c20bd28ff0feb8a0e18272cbb615ca2b48a1ae2d8` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-22 05:35:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df3dbcac8d821ad9ae42fea11729b186` |
| SHA-1 | `8a6d98c30c36cb60e437e255222cec549dabb864` |
| SHA-256 | `be758e9e5ced1c67dddd360c20bd28ff0feb8a0e18272cbb615ca2b48a1ae2d8` |
| SHA3-384 | `b315830b4466bdac676cbfe739d55de109ab98f84a35238abf68bfcbd7b3564a3062a9245076ad645280db8d19615d84` |
| TLSH | `T1D5556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSZ:SDjxB4m5n8XlaPWi+d+a4TjxQP4/` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_020_be758e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be758e9e5ced1c67dddd360c20bd28ff0feb8a0e18272cbb615ca2b48a1ae2d8"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:08"
  condition:
    hash.sha256(0, filesize) == "be758e9e5ced1c67dddd360c20bd28ff0feb8a0e18272cbb615ca2b48a1ae2d8"
}
```

### Sample 21: `e1adcb6d7f294e4c`

| Field | Value |
|---|---|
| SHA-256 | `e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0` |
| Family label | `Mirai` |
| File name | `splspc` |
| File type | `elf` |
| First seen | `2026-11-22 05:35:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8d21e55201afd9b80b6feda2b7a4f30` |
| SHA-1 | `9d0786bfd3baa76e2e8b586aa7974a0217772fb3` |
| SHA-256 | `e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0` |
| SHA3-384 | `4a78b0b5da607cd306906bed84babf70c94863b64ea7da6281344272e4edd648ce93b3eeda8b6d1af53ee8ea4b9cc26b` |
| TLSH | `T193E36D26BD791D2BC1D4657711E74332F1F3138631BC9A197EE20E8CAF18B503257AAA` |
| SSDEEP | `1536:6/zlglxUPZ8Ny8U9ynhDgNhwUl1Kcss3Sf7ng/aMU81RtQNGgN+55hBPjJw+/stO:6/uS6s8MyncJiERCvNIhxVpMhWLGWZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_e1adcb6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0"
    family = "Mirai"
    file_name = "splspc"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:05"
  condition:
    hash.sha256(0, filesize) == "e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0"
}
```

### Sample 22: `cedf9be0a3bd2b9d`

| Field | Value |
|---|---|
| SHA-256 | `cedf9be0a3bd2b9d9bc756ff8168422eb9e0318169ce8caf85f6a3f25370aaf8` |
| Family label | `Mirai` |
| File name | `nklarm6` |
| File type | `elf` |
| First seen | `2026-11-22 05:32:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc86ec090a96784e2f22f1d309d463e1` |
| SHA-1 | `e9ee2657a09d4c5c1c5bf9ee9ddcb6b8b59f627e` |
| SHA-256 | `cedf9be0a3bd2b9d9bc756ff8168422eb9e0318169ce8caf85f6a3f25370aaf8` |
| SHA3-384 | `88aeac5a908430151e1da9020414de3ddeb16f3dd40ae7481d3c0079ed8b86fbc0edf450ac6a33d010e23c8b1df076b5` |
| TLSH | `T1DAE33C56F8819B11C5C261BAFE2F51CD331317BCE3EB72169E149B24678B86B0E3B905` |
| TELFHASH | `t182f02e23ea5d6acc27f9419ac65a5039d7d971963b012048c955d34f4f471e1a819c03` |
| SSDEEP | `3072:TSwcDeJdv0b9eGwf4t7C777kDWIMu1uZn3WParsls2qUTCC4xGrGc:TSwbJkwBE7C777sMln3ga4q29CCTSc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_cedf9be0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cedf9be0a3bd2b9d9bc756ff8168422eb9e0318169ce8caf85f6a3f25370aaf8"
    family = "Mirai"
    file_name = "nklarm6"
    file_type = "elf"
    first_seen = "2026-11-22 05:32:09"
  condition:
    hash.sha256(0, filesize) == "cedf9be0a3bd2b9d9bc756ff8168422eb9e0318169ce8caf85f6a3f25370aaf8"
}
```

### Sample 23: `0b8e14f2818069a9`

| Field | Value |
|---|---|
| SHA-256 | `0b8e14f2818069a955f9f5d6678491873c070da5910050c0f3b5fdde8af22657` |
| Family label | `Mirai` |
| File name | `nklx86` |
| File type | `elf` |
| First seen | `2026-11-22 05:32:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95bb058f7ce7673a194f516a3e552db2` |
| SHA-1 | `514384299942444f9e18bdf764a343279c0d1faf` |
| SHA-256 | `0b8e14f2818069a955f9f5d6678491873c070da5910050c0f3b5fdde8af22657` |
| SHA3-384 | `ea6022a4129b87be4ede11802300f2c28289ae2bae0012e61a2c31203666285e1c36e54286148b0e18838ead08cf7060` |
| TLSH | `T1EBC37EC9E387D4F2F84A057120B7BB775231E9794038DE87E7B8AE36EC11701A50A66D` |
| TELFHASH | `t1f5417c77bd725cecb7e0c817c79f9712ce2ae87b291026b90af6249032f195110b5c39` |
| SSDEEP | `3072:EanO5kQw6YD1a4e3mxgDciKl37gQDz9lfQaY:IkQCTe3+gDciKdTpqaY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_0b8e14f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8e14f2818069a955f9f5d6678491873c070da5910050c0f3b5fdde8af22657"
    family = "Mirai"
    file_name = "nklx86"
    file_type = "elf"
    first_seen = "2026-11-22 05:32:06"
  condition:
    hash.sha256(0, filesize) == "0b8e14f2818069a955f9f5d6678491873c070da5910050c0f3b5fdde8af22657"
}
```

### Sample 24: `761502391a5a5768`

| Field | Value |
|---|---|
| SHA-256 | `761502391a5a576872b57a799cdc55b089ced5fd5a850ab433bfae173f7eb915` |
| Family label | `Mirai` |
| File name | `nklarm5` |
| File type | `elf` |
| First seen | `2026-11-22 05:31:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9304e02bb9fdee1bd9c97d6bde358f1a` |
| SHA-1 | `770d9edfd7904cd651eea6e3a1fe1b52771fab7f` |
| SHA-256 | `761502391a5a576872b57a799cdc55b089ced5fd5a850ab433bfae173f7eb915` |
| SHA3-384 | `0b11347338524d9793ad78f7fc10b1bb8031fe55a2e119b4691fe258a331591c1eab0d8b637dc76c43305c995e7c621a` |
| TLSH | `T105D31A85FD819A12C6D36177FB6E92CD371703B8D3EA32079D155B25678A82A0F3FA40` |
| TELFHASH | `t156f05922a6a417c8fbd0438812ee1216db94f0ed031110f98e1c870f8e935d6f569823` |
| SSDEEP | `3072:oGs9zIVY8UI4Yg7Vxi78XA4rdBS29wYUtm1+kRmGg:oGs9zInk7xK8XAwdYAwYUo1fRxg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_76150239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "761502391a5a576872b57a799cdc55b089ced5fd5a850ab433bfae173f7eb915"
    family = "Mirai"
    file_name = "nklarm5"
    file_type = "elf"
    first_seen = "2026-11-22 05:31:05"
  condition:
    hash.sha256(0, filesize) == "761502391a5a576872b57a799cdc55b089ced5fd5a850ab433bfae173f7eb915"
}
```

### Sample 25: `c15f379dfdecb483`

| Field | Value |
|---|---|
| SHA-256 | `c15f379dfdecb483eeef9ec025df9e5b0d78f00dd58b6adbedee163faaf6e2d3` |
| Family label | `Mirai` |
| File name | `nabsh4` |
| File type | `elf` |
| First seen | `2026-11-22 05:27:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82fd34bb3f5b7c133a40dd402d31c936` |
| SHA-1 | `a562556decbd91d5140c22b3aa181a6b2510c48d` |
| SHA-256 | `c15f379dfdecb483eeef9ec025df9e5b0d78f00dd58b6adbedee163faaf6e2d3` |
| SHA3-384 | `a6d45a36ba782d086e2b0250cf40ec2cb865ffcde0cee2feee232c7c753684682e64b861b338676651aa35a0dd90cd82` |
| TLSH | `T1E8D3CF61D9A5AEC1C05D51F1B070EFB84B23A59051871EFB35A8C6A99083ECCF68D7BC` |
| SSDEEP | `3072:htGxeRomXu7L5DKRwOw23vH8gkyY4NddeiGMZ:hie7+7t4lw2vyAWFMZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_c15f379d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c15f379dfdecb483eeef9ec025df9e5b0d78f00dd58b6adbedee163faaf6e2d3"
    family = "Mirai"
    file_name = "nabsh4"
    file_type = "elf"
    first_seen = "2026-11-22 05:27:07"
  condition:
    hash.sha256(0, filesize) == "c15f379dfdecb483eeef9ec025df9e5b0d78f00dd58b6adbedee163faaf6e2d3"
}
```

### Sample 26: `f5bc707ddd5e3ab0`

| Field | Value |
|---|---|
| SHA-256 | `f5bc707ddd5e3ab0a20d925b9fe153bab05c66e39be8c87f67e028a4bca95610` |
| Family label | `Mirai` |
| File name | `splppc` |
| File type | `elf` |
| First seen | `2026-11-22 05:27:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0ec9e3b4c5856bb2b624dfb37070d29` |
| SHA-1 | `4cd2aaffcf8c96a81d590dfcd457a6f98881087f` |
| SHA-256 | `f5bc707ddd5e3ab0a20d925b9fe153bab05c66e39be8c87f67e028a4bca95610` |
| SHA3-384 | `fa6c20438f9c4369be16c10217845a08a9db022ed18f19d6b5b463b9464168770d74991e01999ba8941d98ce55296a85` |
| TLSH | `T1E8E38C44F71C0943E1671CB02A3F3BE5A3AED9E011F4A649650EFB4E5272E315686ECD` |
| SSDEEP | `3072:NEIEDpvINAPfRKko2rufaVmL45ghyZdIGbt/j:NEIwC12EaMLgghCpbV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_f5bc707d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5bc707ddd5e3ab0a20d925b9fe153bab05c66e39be8c87f67e028a4bca95610"
    family = "Mirai"
    file_name = "splppc"
    file_type = "elf"
    first_seen = "2026-11-22 05:27:04"
  condition:
    hash.sha256(0, filesize) == "f5bc707ddd5e3ab0a20d925b9fe153bab05c66e39be8c87f67e028a4bca95610"
}
```

### Sample 27: `98a5e3003d095984`

| Field | Value |
|---|---|
| SHA-256 | `98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92` |
| Family label | `WARDENStealer` |
| File name | `p?t=0636274d194685e698b7f6bc558eec14_d5bcce35aaf5dafe9c99bbe0105909d2d90d1456` |
| File type | `exe` |
| First seen | `2026-11-22 05:24:07` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7f64c74be9e778392c129d322a24ba1` |
| SHA-1 | `95247f7024f7ced564c50af4b9dd3797b1680ed6` |
| SHA-256 | `98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92` |
| SHA3-384 | `1c5406a03b09526399b1575428fa81e803b71b2b48635aa04bdf167af6cfd06e0652dc0c4182cdbcde00b80d885ebe0f` |
| IMPHASH | `85e6a385899147db799c17ac460ad5e9` |
| TLSH | `T1CAF40112FAD943E8D52AC239C6555622EA717C060B61AAFF1398476F1F336D08F3EB50` |
| SSDEEP | `12288:PCv4UNs4c6uCMB+8KXvAUfPHdQ/deqLplmug9D2PPinXWlvc:PCAgy+/ACHdseElmug+Ekc` |
| ICON-DHASH | `1468969e0e461804` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_027_98a5e300
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92"
    family = "WARDENStealer"
    file_name = "p?t=0636274d194685e698b7f6bc558eec14_d5bcce35aaf5dafe9c99bbe0105909d2d90d1456"
    file_type = "exe"
    first_seen = "2026-11-22 05:24:07"
  condition:
    hash.sha256(0, filesize) == "98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92"
}
```

### Sample 28: `7425b7a56dc97422`

| Field | Value |
|---|---|
| SHA-256 | `7425b7a56dc9742208fed2d4604f0a3e186e58192b48f4c6a96592ce1d56e49d` |
| Family label | `unknown` |
| File name | `stage2_plugx.dll` |
| File type | `dll` |
| First seen | `2026-11-22 05:16:11` |
| Reporter | `Daydream` |
| Tags | `APT, dll, Korplug, MustangPanda, PlugX, unpacked` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77878f9f18dfe1e0e3cdb62cc6e7eac1` |
| SHA-1 | `13ff0e548f8b5a57a3c0ea1cca0a2b77199bceeb` |
| SHA-256 | `7425b7a56dc9742208fed2d4604f0a3e186e58192b48f4c6a96592ce1d56e49d` |
| SHA3-384 | `834aead1aa1aa48601090ab8d10c28582b43dcdefcfde8a2ba247cb2adbae0f7187c4eebdc23362d3b9190e91eb8e790` |
| IMPHASH | `2426463889e8c3d7e29431c9ce193e20` |
| TLSH | `T139449DC3A14191B7FAED54388210EA3F877D3E0087B0CE7FAB859DE99A177409665339` |
| SSDEEP | `6144:0s39zsnOWgEQ394sQBeYv/GgMTDKwj2NpLpsPsq+jWM+9T3R0GRzJ640ymLz/llY:0m2tgBN4sQBeYv/GgMTDKwj2NpLpsPs4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_7425b7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7425b7a56dc9742208fed2d4604f0a3e186e58192b48f4c6a96592ce1d56e49d"
    family = "unknown"
    file_name = "stage2_plugx.dll"
    file_type = "dll"
    first_seen = "2026-11-22 05:16:11"
  condition:
    hash.sha256(0, filesize) == "7425b7a56dc9742208fed2d4604f0a3e186e58192b48f4c6a96592ce1d56e49d"
}
```

### Sample 29: `42e9e779b677a744`

| Field | Value |
|---|---|
| SHA-256 | `42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957` |
| Family label | `unknown` |
| File name | `easyshell-l64-42e9e779b677a744.bin` |
| File type | `elf` |
| First seen | `2026-11-22 05:07:07` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6056c2c202bfcd9226c9ad048e4e0126` |
| SHA-1 | `552a9440dcd379191e46574c855564bef05eaaff` |
| SHA-256 | `42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957` |
| SHA3-384 | `e547eb53075461f41f653f9af80c3fd782e5be6a80ed47819c95f2b93b486ceb988d811069ad76fd44581265cf7a88e3` |
| TLSH | `T1DC267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYximH8hIU6iKHh:OYjiiKgib9qRGcEulmcW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_42e9e779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957"
    family = "unknown"
    file_name = "easyshell-l64-42e9e779b677a744.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:07:07"
  condition:
    hash.sha256(0, filesize) == "42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957"
}
```

### Sample 30: `dba9625fec97eb3b`

| Field | Value |
|---|---|
| SHA-256 | `dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb` |
| Family label | `unknown` |
| File name | `easyshell-l32-dba9625fec97eb3b.bin` |
| File type | `elf` |
| First seen | `2026-11-22 05:06:53` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ac0926ae09e7fb62186d06e95abcf86` |
| SHA-1 | `5e14f3e44bbf3497c346c99cab79ae9ca75895fd` |
| SHA-256 | `dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb` |
| SHA3-384 | `1dbed73751a37d5eaf20dac61d7130f41bdcc5e5ccf03f5a36df9de6c2ac6bf20efd72fc0a4b0f5068061631cb26b3d3` |
| TLSH | `T1AC068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1oF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1odb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_dba9625f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb"
    family = "unknown"
    file_name = "easyshell-l32-dba9625fec97eb3b.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:06:53"
  condition:
    hash.sha256(0, filesize) == "dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb"
}
```

### Sample 31: `4b0f0e6823776624`

| Field | Value |
|---|---|
| SHA-256 | `4b0f0e682377662425e8c94754be35f0adb263589bc26dcc49faba7c038ffca1` |
| Family label | `unknown` |
| File name | `easyshell-l128-4b0f0e6823776624.bin` |
| File type | `elf` |
| First seen | `2026-11-22 05:06:41` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fff158d561bdcd7c46ff75e2505419ce` |
| SHA-1 | `cc2c2da7b91bd9e37e7cdda4be618764d98ab828` |
| SHA-256 | `4b0f0e682377662425e8c94754be35f0adb263589bc26dcc49faba7c038ffca1` |
| SHA3-384 | `a6b06c51761ff025355b7b4f3cf56e4d6cce1c696074e3659c4ac24c317dd9f13a6457e63b71dc158f9bb3271f3e256e` |
| TLSH | `T151067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1C9:FUkCxwUGnaPdX8PuAS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_4b0f0e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b0f0e682377662425e8c94754be35f0adb263589bc26dcc49faba7c038ffca1"
    family = "unknown"
    file_name = "easyshell-l128-4b0f0e6823776624.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:06:41"
  condition:
    hash.sha256(0, filesize) == "4b0f0e682377662425e8c94754be35f0adb263589bc26dcc49faba7c038ffca1"
}
```

### Sample 32: `72577de6fb4313e2`

| Field | Value |
|---|---|
| SHA-256 | `72577de6fb4313e23d46c5c4b713bb5c458427e353c562060da4175b3e77cad4` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-72577de6fb4313e2.bin` |
| File type | `macho` |
| First seen | `2026-11-22 05:06:27` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7d87d6a889a0137d15c7bbc5bc3616e` |
| SHA-1 | `352ba6c2caf9ae431308391609378685a6fcf9bd` |
| SHA-256 | `72577de6fb4313e23d46c5c4b713bb5c458427e353c562060da4175b3e77cad4` |
| SHA3-384 | `d134433e8a04a4a5d6dab62003107473c4c6d1290d3f73c43f9c86853979f46dda73ca51ee489e5bfafa333dabb77a07` |
| TLSH | `T164F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tgusj5g5FIU6icBV8GQU5NZm+lz7:8SeI1gkkvTgut5C+OGU5NZm+lz7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_72577de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72577de6fb4313e23d46c5c4b713bb5c458427e353c562060da4175b3e77cad4"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-72577de6fb4313e2.bin"
    file_type = "macho"
    first_seen = "2026-11-22 05:06:27"
  condition:
    hash.sha256(0, filesize) == "72577de6fb4313e23d46c5c4b713bb5c458427e353c562060da4175b3e77cad4"
}
```

### Sample 33: `e25839ef096b3910`

| Field | Value |
|---|---|
| SHA-256 | `e25839ef096b39109333cb92d8baa5880402a3841057e6133833135d8e4ca78c` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-e25839ef096b3910.bin` |
| File type | `macho` |
| First seen | `2026-11-22 05:06:12` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b482ad81bfe6dc3f7e26833b4c5284fb` |
| SHA-1 | `bf06c87d6e6fed1cdfa4fe066677958ab050f537` |
| SHA-256 | `e25839ef096b39109333cb92d8baa5880402a3841057e6133833135d8e4ca78c` |
| SHA3-384 | `0730c0bee457b197fb21d379c71a624671bfa0f9c59d0a8b2a0a3aaa16c0eac6d9873c6cc8b532b2f657d1aaea2c155b` |
| TLSH | `T1F3168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO65Khx+wgbZmBlzlX:kyLbLNomEr65KjB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_e25839ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e25839ef096b39109333cb92d8baa5880402a3841057e6133833135d8e4ca78c"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-e25839ef096b3910.bin"
    file_type = "macho"
    first_seen = "2026-11-22 05:06:12"
  condition:
    hash.sha256(0, filesize) == "e25839ef096b39109333cb92d8baa5880402a3841057e6133833135d8e4ca78c"
}
```

### Sample 34: `7be5b6eef6df0540`

| Field | Value |
|---|---|
| SHA-256 | `7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223` |
| Family label | `unknown` |
| File name | `easyshell-a64-7be5b6eef6df0540.bin` |
| File type | `elf` |
| First seen | `2026-11-22 05:05:56` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a999dd758cccead7081376fae3e8e685` |
| SHA-1 | `51150bfd3cfb7f8ce668b543cdbdd821ca6036d6` |
| SHA-256 | `7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223` |
| SHA3-384 | `98ca5479d696750ff1c56f333ec56c0fe8f07c14fb1554e76cffad5eca9b1bfbc6645eefff58bc50b7714f69bc4fa2da` |
| TLSH | `T1B706B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WyGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WyLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_7be5b6ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223"
    family = "unknown"
    file_name = "easyshell-a64-7be5b6eef6df0540.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:05:56"
  condition:
    hash.sha256(0, filesize) == "7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223"
}
```

### Sample 35: `e8e60fbba93bc587`

| Field | Value |
|---|---|
| SHA-256 | `e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2` |
| Family label | `unknown` |
| File name | `easyshell-a32-e8e60fbba93bc587.bin` |
| File type | `elf` |
| First seen | `2026-11-22 05:05:40` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0c7d7623f4e7f42d25ba60c1251d5e` |
| SHA-1 | `d572065c9f927ff44c2a3a20ea7db3ba1e50bb63` |
| SHA-256 | `e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2` |
| SHA3-384 | `077471a81cf23c60c1e0a18265297dfa86d20c587f4fc78a0c130b2df62d7c7f0380ddcaaaa44abe103e0ad8b9a2d04c` |
| TLSH | `T11AF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBk:FhvZpiEGUx+pVdqz2laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_e8e60fbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2"
    family = "unknown"
    file_name = "easyshell-a32-e8e60fbba93bc587.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:05:40"
  condition:
    hash.sha256(0, filesize) == "e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2"
}
```

### Sample 36: `2ae7c72ba12d5235`

| Field | Value |
|---|---|
| SHA-256 | `2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56` |
| Family label | `unknown` |
| File name | `486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31` |
| File type | `elf` |
| First seen | `2026-11-22 05:00:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c2b3b636d22040a68600a8a898692eb` |
| SHA-1 | `9e53a54230bb923e96d73799f63f82b9fcda9e91` |
| SHA-256 | `2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56` |
| SHA3-384 | `a82329debf6b45efce3a2ab98b39ee838ffe367b5cf4a769a7040aa764c7609e610095075e1f5f6598a60ca72c96216f` |
| TLSH | `T10D171243B8E60CA4D4FAD271952A8222FA71780D0B7963DF57A0B7741F337E18976B84` |
| TELFHASH | `t19362e0754a7c74b5b2a7c921f362b4b4e6331cb163f874b05027b891efe1e811c9a867` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `393216:PeDOuKsnbulZR0V7kuE3VVmmuKibA0P8XxZINQ2lHyh4zIRY6V:21Ksn0ZR0V7kuE3VjVRuWIS2lHyh+IRV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_2ae7c72b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56"
    family = "unknown"
    file_name = "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
    file_type = "elf"
    first_seen = "2026-11-22 05:00:36"
  condition:
    hash.sha256(0, filesize) == "2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56"
}
```

### Sample 37: `486d258731b76f09`

| Field | Value |
|---|---|
| SHA-256 | `486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31` |
| Family label | `unknown` |
| File name | `486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31` |
| File type | `elf` |
| First seen | `2026-11-22 05:00:02` |
| Reporter | `Portfwd` |
| Tags | `elf, upx, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2eeb205754c206e7ec7c3431ddeb56a` |
| SHA-1 | `cf02279fdd7fe2473b11d4e1356ebb3e3c3e933d` |
| SHA-256 | `486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31` |
| SHA3-384 | `56165367199a4c573ef58b9fa4d0050d577c841f216afbf716afe2ea00303d963788033471b421de03ff215aa4c31430` |
| TLSH | `T18B073343D25BF639E029C6783A42C6C167B9B127E205E357EED473AE8F699704DC2231` |
| SSDEEP | `393216:I7FDOuKsnbulZR0V7kuE3VVmmuKibA0P8XxZINQ2lHyh4zIRY67:I7Z1Ksn0ZR0V7kuE3VjVRuWIS2lHyh+o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_486d2587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
    family = "unknown"
    file_name = "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
    file_type = "elf"
    first_seen = "2026-11-22 05:00:02"
  condition:
    hash.sha256(0, filesize) == "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
}
```

### Sample 38: `d396f3c20883a3b7`

| Field | Value |
|---|---|
| SHA-256 | `d396f3c20883a3b71244c87c537595108010239e4e17e6c09bca83ea5a475677` |
| Family label | `unknown` |
| File name | `SendFile.dll` |
| File type | `dll` |
| First seen | `2026-11-22 04:45:47` |
| Reporter | `Daydream` |
| Tags | `dll, dotnet, RAT, SendFile, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75ef0d23e82fe64a3ac7980a57149aa2` |
| SHA-1 | `2e1505803f415c2f2c033a2b8996df0ed916f8a6` |
| SHA-256 | `d396f3c20883a3b71244c87c537595108010239e4e17e6c09bca83ea5a475677` |
| SHA3-384 | `d6af82195dacbf4224229c44243a010f137d8706048562158364cb4a6f8a5b3eec40c943544282d0a9170864f75e0873` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T19F922B0DABE886A6D5EE4D762CB2861047B0FB175E03CB4F5CE990DD1E633C192507DA` |
| SSDEEP | `384:YJFOHOsOdVOB4jRKkACgdRngHPkHiMjWR+bSh0XSW9Ot575MZ919pCBmvec:Yi49g3FHiM1biF5wrMX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_d396f3c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d396f3c20883a3b71244c87c537595108010239e4e17e6c09bca83ea5a475677"
    family = "unknown"
    file_name = "SendFile.dll"
    file_type = "dll"
    first_seen = "2026-11-22 04:45:47"
  condition:
    hash.sha256(0, filesize) == "d396f3c20883a3b71244c87c537595108010239e4e17e6c09bca83ea5a475677"
}
```

### Sample 39: `f7a83c1455e0e0b4`

| Field | Value |
|---|---|
| SHA-256 | `f7a83c1455e0e0b41dbe6e69daa346356fbfc076f3edb12b99b9d0f76ec4068e` |
| Family label | `unknown` |
| File name | `RemoteDesktop.dll` |
| File type | `dll` |
| First seen | `2026-11-22 04:45:41` |
| Reporter | `Daydream` |
| Tags | `dll, dotnet, RAT, RemoteDesktop, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8aef2a46829420080682c1233dd0e15` |
| SHA-1 | `b75cde7ad84f187a2ceaac0f32749a34539c342e` |
| SHA-256 | `f7a83c1455e0e0b41dbe6e69daa346356fbfc076f3edb12b99b9d0f76ec4068e` |
| SHA3-384 | `23da8eff4e02b32165833d3488a32cf7cf0d0edde0aa89deb58bbe2fb80fd4b522a5018913b40ae1eb7466df66d8b5ef` |
| IMPHASH | `dae02f32a21e03ce65412f6e56942daa` |
| TLSH | `T1AB555B51FFE06EA6C08F36BEF4A159130AB0B0411276E78B4B46216D9FC73849D1ABD7` |
| SSDEEP | `24576:h2vONVAx+95vf8ROmqdWEI8s3FFFFFFFFGTt+xt:hlNVAxU5vf8RnqdUFFFFFFFFy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_f7a83c14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a83c1455e0e0b41dbe6e69daa346356fbfc076f3edb12b99b9d0f76ec4068e"
    family = "unknown"
    file_name = "RemoteDesktop.dll"
    file_type = "dll"
    first_seen = "2026-11-22 04:45:41"
  condition:
    hash.sha256(0, filesize) == "f7a83c1455e0e0b41dbe6e69daa346356fbfc076f3edb12b99b9d0f76ec4068e"
}
```

### Sample 40: `65278002c1474ae3`

| Field | Value |
|---|---|
| SHA-256 | `65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5` |
| Family label | `njrat` |
| File name | `0393931eeb8f945c58c40b438ba310d5.exe` |
| File type | `exe` |
| First seen | `2026-11-22 04:35:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0393931eeb8f945c58c40b438ba310d5` |
| SHA-1 | `126b8dd66f91b5ca3fe6b032fcd3668f6e567bad` |
| SHA-256 | `65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5` |
| SHA3-384 | `154b729b962223beca85d4fc9cb43084e9ea79475ce67256f64bae08a31740a14566db294018b165244d4848adb7fe43` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T144A2194DB7688619C3AD1AB409F3232487F1F68B8951DF4B1CDA10DA6F236D06642AFD` |
| SSDEEP | `384:lW6JwUSlWXMpv7MQTmKB4Xf5hsbNmH5aOWQ+dcs//34LAZSTjQNg:k6JwUqWXsv7MQTmKQhOMZWQuHq2+` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_040_65278002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5"
    family = "njrat"
    file_name = "0393931eeb8f945c58c40b438ba310d5.exe"
    file_type = "exe"
    first_seen = "2026-11-22 04:35:18"
  condition:
    hash.sha256(0, filesize) == "65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5"
}
```

### Sample 41: `c7b88a4348f92215`

| Field | Value |
|---|---|
| SHA-256 | `c7b88a4348f9221566d2146fc892ea3a1fb0db642344fcbeddc9bb3721ea4a5b` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-c7b88a4348f92215.bin` |
| File type | `macho` |
| First seen | `2026-11-22 04:35:15` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f6356505a9e2cd6877182f32ec6ee67` |
| SHA-1 | `62b84255d300ab372dff378eaaf80a0b810079b2` |
| SHA-256 | `c7b88a4348f9221566d2146fc892ea3a1fb0db642344fcbeddc9bb3721ea4a5b` |
| SHA3-384 | `cd4718439ebd2e63ede79e6c6aeb8cd1196557d4473eb7939d9d5e313241f932fad6b822394430f506a45dd30aea4718` |
| TLSH | `T1ADF5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgCsj5g5FIU6icBV8GQU5NZm+lzQ:8SeI1gkkvTgCt5C+OGU5NZm+lzQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_c7b88a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7b88a4348f9221566d2146fc892ea3a1fb0db642344fcbeddc9bb3721ea4a5b"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-c7b88a4348f92215.bin"
    file_type = "macho"
    first_seen = "2026-11-22 04:35:15"
  condition:
    hash.sha256(0, filesize) == "c7b88a4348f9221566d2146fc892ea3a1fb0db642344fcbeddc9bb3721ea4a5b"
}
```

### Sample 42: `e96cfcc9e7675236`

| Field | Value |
|---|---|
| SHA-256 | `e96cfcc9e76752365f8f73ce50e8c73e7400c2d0bf5b652ed1274f7f673b3655` |
| Family label | `njrat` |
| File name | `041036279a76a6991e5e8f961a2fdb6a.exe` |
| File type | `exe` |
| First seen | `2026-11-22 04:35:13` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `041036279a76a6991e5e8f961a2fdb6a` |
| SHA-1 | `c6841aa2f9e5841b14472b856ec3ce883e6dda66` |
| SHA-256 | `e96cfcc9e76752365f8f73ce50e8c73e7400c2d0bf5b652ed1274f7f673b3655` |
| SHA3-384 | `c9aa705b614f48f5053f4884b75a6d9d40c52420c96ce12cf1ea196f60ae234e616da1172fbcd7cd0aea92bf24cd7b25` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T146A2098D77688618D3AE1AB84CF3631487B1F68B8941DF4B1CDA10DA2F236D05652AFD` |
| SSDEEP | `384:6W6J/USlvpJkBXMGvgMQTmKByzWnqhwYmHGaOWQ+dcs//34LAZSTTi2:r6JUqvpJkBXXvgMQTmKKirKWQuHqc2` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_042_e96cfcc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96cfcc9e76752365f8f73ce50e8c73e7400c2d0bf5b652ed1274f7f673b3655"
    family = "njrat"
    file_name = "041036279a76a6991e5e8f961a2fdb6a.exe"
    file_type = "exe"
    first_seen = "2026-11-22 04:35:13"
  condition:
    hash.sha256(0, filesize) == "e96cfcc9e76752365f8f73ce50e8c73e7400c2d0bf5b652ed1274f7f673b3655"
}
```

### Sample 43: `6917a5ed510690eb`

| Field | Value |
|---|---|
| SHA-256 | `6917a5ed510690eb3fd89690acc09f5fa8e106efd986002afef4e3f6b5654288` |
| Family label | `njrat` |
| File name | `85D7BFF793FE83CE92BCD656C89A53C9.exe` |
| File type | `exe` |
| First seen | `2026-11-22 04:35:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85d7bff793fe83ce92bcd656c89a53c9` |
| SHA-1 | `9064f5017d5fe88b92c2daf3411ad1c3270dd3d9` |
| SHA-256 | `6917a5ed510690eb3fd89690acc09f5fa8e106efd986002afef4e3f6b5654288` |
| SHA3-384 | `9db4e4acf328228ea97fc36674458e4a23b8bc84d7f9e9a51c0552d175b419dc1b3ae84673c6b5875e83f5197a0caee8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D635E039F600EBE2C13E5537D6FB19A80F376C379089C21269D9B2DEA813767542718E` |
| SSDEEP | `24576:830V/rv30V/rv30V/rx1t30V/rdH+kkzefpC:83K/L3K/L3K/dn3K/nkz` |
| ICON-DHASH | `71f0cc8e8ea4e071` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_043_6917a5ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6917a5ed510690eb3fd89690acc09f5fa8e106efd986002afef4e3f6b5654288"
    family = "njrat"
    file_name = "85D7BFF793FE83CE92BCD656C89A53C9.exe"
    file_type = "exe"
    first_seen = "2026-11-22 04:35:08"
  condition:
    hash.sha256(0, filesize) == "6917a5ed510690eb3fd89690acc09f5fa8e106efd986002afef4e3f6b5654288"
}
```

### Sample 44: `d4bf63eabcb4b7d9`

| Field | Value |
|---|---|
| SHA-256 | `d4bf63eabcb4b7d9af2eb7421fe0072bf9c6f634fc6d55cb2001ea1831a141f1` |
| Family label | `unknown` |
| File name | `easyshell-l64-d4bf63eabcb4b7d9.bin` |
| File type | `elf` |
| First seen | `2026-11-22 04:06:34` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `152cc09a59db07eead8a9b202e60d3e4` |
| SHA-1 | `0ec33409f6adb9772f3e58299ac0524fc9d09347` |
| SHA-256 | `d4bf63eabcb4b7d9af2eb7421fe0072bf9c6f634fc6d55cb2001ea1831a141f1` |
| SHA3-384 | `013fe69cebe536e21c7044babc7ebfc53839e77dd833e25bb23f94d67b61cd34ef166fc35b0788500ef26a456b68645f` |
| TLSH | `T10A267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxioH8hIU6iKHh:OYjiiKgib9qRGcEulocW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_d4bf63ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4bf63eabcb4b7d9af2eb7421fe0072bf9c6f634fc6d55cb2001ea1831a141f1"
    family = "unknown"
    file_name = "easyshell-l64-d4bf63eabcb4b7d9.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:06:34"
  condition:
    hash.sha256(0, filesize) == "d4bf63eabcb4b7d9af2eb7421fe0072bf9c6f634fc6d55cb2001ea1831a141f1"
}
```

### Sample 45: `f4d89fdb46433b82`

| Field | Value |
|---|---|
| SHA-256 | `f4d89fdb46433b8265ed4f6ffc00eab5e983ffd70835e912256d9e8c978a7cce` |
| Family label | `unknown` |
| File name | `easyshell-l32-f4d89fdb46433b82.bin` |
| File type | `elf` |
| First seen | `2026-11-22 04:06:25` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e140e49973a8743bc2db780d6615b60` |
| SHA-1 | `fe4fd066e5c7ace1ae614418e73758f8b112efc1` |
| SHA-256 | `f4d89fdb46433b8265ed4f6ffc00eab5e983ffd70835e912256d9e8c978a7cce` |
| SHA3-384 | `243a5529d2090a6a59d73e51f1db2c732ac74b33c89ccd908e723c1a9765ec8d017110627b015f93fb79403b858681c5` |
| TLSH | `T15D068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL14F3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm14db` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_f4d89fdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d89fdb46433b8265ed4f6ffc00eab5e983ffd70835e912256d9e8c978a7cce"
    family = "unknown"
    file_name = "easyshell-l32-f4d89fdb46433b82.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:06:25"
  condition:
    hash.sha256(0, filesize) == "f4d89fdb46433b8265ed4f6ffc00eab5e983ffd70835e912256d9e8c978a7cce"
}
```

### Sample 46: `5687dc250beeb631`

| Field | Value |
|---|---|
| SHA-256 | `5687dc250beeb631c44478c7101e1d40751b3ce9cfb3c2654f67d5ce8fd5700b` |
| Family label | `unknown` |
| File name | `easyshell-l128-5687dc250beeb631.bin` |
| File type | `elf` |
| First seen | `2026-11-22 04:06:16` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cbd6ac6c49bf09652e47fdc6b15c85c` |
| SHA-1 | `a9f187d162709bd18d8015e8303c1738e852c6f2` |
| SHA-256 | `5687dc250beeb631c44478c7101e1d40751b3ce9cfb3c2654f67d5ce8fd5700b` |
| SHA3-384 | `8874e1179619b3a52c7ba01b8c00f2f2675483746581c012d60f8b74141b45d9d1b7f8c89691249572c5110ccdfa2b4d` |
| TLSH | `T103067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Ci:FUkCxwUGnaPdX8P3AS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_5687dc25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5687dc250beeb631c44478c7101e1d40751b3ce9cfb3c2654f67d5ce8fd5700b"
    family = "unknown"
    file_name = "easyshell-l128-5687dc250beeb631.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:06:16"
  condition:
    hash.sha256(0, filesize) == "5687dc250beeb631c44478c7101e1d40751b3ce9cfb3c2654f67d5ce8fd5700b"
}
```

### Sample 47: `52c0e084a024b59f`

| Field | Value |
|---|---|
| SHA-256 | `52c0e084a024b59f442937763818d5bab2f7ca03a78f28257d84855cf28cee4c` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-52c0e084a024b59f.bin` |
| File type | `macho` |
| First seen | `2026-11-22 04:06:05` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08428b9df0e725caa58771d74de79e27` |
| SHA-1 | `3ae99e033d6c7ce2aa54125c1076ed62da28a1e4` |
| SHA-256 | `52c0e084a024b59f442937763818d5bab2f7ca03a78f28257d84855cf28cee4c` |
| SHA3-384 | `8aa21dfded498e288767a613a48316472eeeab876b665e6d294cf24208a055bdf2cd927647f6c9e1f5162e73809d713f` |
| TLSH | `T1B2168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6SKhx+wgbZmBlzrX:kyLbLNomEr6SKjf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_52c0e084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52c0e084a024b59f442937763818d5bab2f7ca03a78f28257d84855cf28cee4c"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-52c0e084a024b59f.bin"
    file_type = "macho"
    first_seen = "2026-11-22 04:06:05"
  condition:
    hash.sha256(0, filesize) == "52c0e084a024b59f442937763818d5bab2f7ca03a78f28257d84855cf28cee4c"
}
```

### Sample 48: `ecb7249f17a35a37`

| Field | Value |
|---|---|
| SHA-256 | `ecb7249f17a35a37bb3d6c07cbf595e7e072194f0a73d860619ccd1eca929d3e` |
| Family label | `unknown` |
| File name | `easyshell-a64-ecb7249f17a35a37.bin` |
| File type | `elf` |
| First seen | `2026-11-22 04:05:56` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5838f1ad8a90bd720fb399631e9bca8` |
| SHA-1 | `0f4fc39fb7bb9b09dc89d780e236a6531bfb42c1` |
| SHA-256 | `ecb7249f17a35a37bb3d6c07cbf595e7e072194f0a73d860619ccd1eca929d3e` |
| SHA3-384 | `bd8856947aec0d91cf966302ca474da437d529ee9caf8a5e3f0f473a99270bbf6c8c5439316cac2b04363da669060b09` |
| TLSH | `T15906B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WIGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WILd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ecb7249f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecb7249f17a35a37bb3d6c07cbf595e7e072194f0a73d860619ccd1eca929d3e"
    family = "unknown"
    file_name = "easyshell-a64-ecb7249f17a35a37.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:05:56"
  condition:
    hash.sha256(0, filesize) == "ecb7249f17a35a37bb3d6c07cbf595e7e072194f0a73d860619ccd1eca929d3e"
}
```

### Sample 49: `81eef296f3a76368`

| Field | Value |
|---|---|
| SHA-256 | `81eef296f3a763689e27d7a6c6649ca1652595e792e66a5e9b5fcbebbe7bab13` |
| Family label | `unknown` |
| File name | `easyshell-a32-81eef296f3a76368.bin` |
| File type | `elf` |
| First seen | `2026-11-22 04:05:46` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa667e52663e8a0653585a28f9db4934` |
| SHA-1 | `67294832e5725d7342142303d40b98b7d8d9fdc0` |
| SHA-256 | `81eef296f3a763689e27d7a6c6649ca1652595e792e66a5e9b5fcbebbe7bab13` |
| SHA3-384 | `ab18f69b2368f89129d191e4ad236b36efc85e099a2108cb51016e0ae042b363c75138efc3f821fd401ed54f25b7009d` |
| TLSH | `T18DF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRB4:FhvZpiEGUx+pVdqj2laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_81eef296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81eef296f3a763689e27d7a6c6649ca1652595e792e66a5e9b5fcbebbe7bab13"
    family = "unknown"
    file_name = "easyshell-a32-81eef296f3a76368.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:05:46"
  condition:
    hash.sha256(0, filesize) == "81eef296f3a763689e27d7a6c6649ca1652595e792e66a5e9b5fcbebbe7bab13"
}
```

### Sample 50: `110c07247027bb54`

| Field | Value |
|---|---|
| SHA-256 | `110c07247027bb547d5c49ac1075c66009f0fe8758f4372a5919760f4257f3ae` |
| Family label | `unknown` |
| File name | `bld_TlrF2SwGuBe_C-7pcu0IIdZx.exe` |
| File type | `exe` |
| First seen | `2026-11-22 03:37:17` |
| Reporter | `Daydream` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00a29b07caa081c42089cf79f8065690` |
| SHA-1 | `1e87789bb25aa63ae13d284cd22d951d169f4016` |
| SHA-256 | `110c07247027bb547d5c49ac1075c66009f0fe8758f4372a5919760f4257f3ae` |
| SHA3-384 | `9e749be99d6c6ce7ad0b0b667c84d798a2781f490a11386c6db5979e22e374b0ac9fdf533700405c70c72d336fd03d9b` |
| IMPHASH | `71eb0f18e577947f062d0811f3a37327` |
| TLSH | `T1C3054B157A4908BDD9CAD479978B6923452834CF0E71BCFF83C5A2323EAA0B59F36345` |
| SSDEEP | `12288:97tcNWRdeUTXAWIZHvKFHB63NuOlbYmg8GLYmDX0/gKxVk5k0O1u5V86L:rcox7ATKj8+YmDXzKFiBL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_110c0724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "110c07247027bb547d5c49ac1075c66009f0fe8758f4372a5919760f4257f3ae"
    family = "unknown"
    file_name = "bld_TlrF2SwGuBe_C-7pcu0IIdZx.exe"
    file_type = "exe"
    first_seen = "2026-11-22 03:37:17"
  condition:
    hash.sha256(0, filesize) == "110c07247027bb547d5c49ac1075c66009f0fe8758f4372a5919760f4257f3ae"
}
```

### Sample 51: `ea4331274b2e9453`

| Field | Value |
|---|---|
| SHA-256 | `ea4331274b2e94537380aae9c28ff5565d218bf12f7f6917297d672d91b5f03b` |
| Family label | `unknown` |
| File name | `easyshell-l64-ea4331274b2e9453.bin` |
| File type | `elf` |
| First seen | `2026-11-22 03:36:44` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c39e3e2f8026c61c4857fadf0465aa43` |
| SHA-1 | `fe853c0c8f6dccbc7c4e6f4ede7378d727c1db43` |
| SHA-256 | `ea4331274b2e94537380aae9c28ff5565d218bf12f7f6917297d672d91b5f03b` |
| SHA3-384 | `463c635e57df96ea47e84b74b032ec6e42371e8afab0154ee43ec7ae2ca8ee5ab5f13f99f1161a34ec060ba480a64820` |
| TLSH | `T1F7267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiPH8hIU6iKHh:OYjiiKgib9qRGcEulPcW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_ea433127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea4331274b2e94537380aae9c28ff5565d218bf12f7f6917297d672d91b5f03b"
    family = "unknown"
    file_name = "easyshell-l64-ea4331274b2e9453.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:36:44"
  condition:
    hash.sha256(0, filesize) == "ea4331274b2e94537380aae9c28ff5565d218bf12f7f6917297d672d91b5f03b"
}
```

### Sample 52: `f10c69f82a06e92d`

| Field | Value |
|---|---|
| SHA-256 | `f10c69f82a06e92d3804ee19afecfa60b586864afb0c218cb15116ad3d8211a7` |
| Family label | `unknown` |
| File name | `easyshell-l32-f10c69f82a06e92d.bin` |
| File type | `elf` |
| First seen | `2026-11-22 03:36:34` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98d9aa3c59fc554dfe3fa65337fa4c3b` |
| SHA-1 | `b674ce9a7d5b668b6502fcbd00afa4368393bd59` |
| SHA-256 | `f10c69f82a06e92d3804ee19afecfa60b586864afb0c218cb15116ad3d8211a7` |
| SHA3-384 | `dc7498b0699765454e3d2244c3397ea0e26f43a4ff641797c8c51bda305f7d99dcbfd747a7031547ea3323e555901fc9` |
| TLSH | `T174068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL16F3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm16db` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_f10c69f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f10c69f82a06e92d3804ee19afecfa60b586864afb0c218cb15116ad3d8211a7"
    family = "unknown"
    file_name = "easyshell-l32-f10c69f82a06e92d.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:36:34"
  condition:
    hash.sha256(0, filesize) == "f10c69f82a06e92d3804ee19afecfa60b586864afb0c218cb15116ad3d8211a7"
}
```

### Sample 53: `de62dbf8a6973867`

| Field | Value |
|---|---|
| SHA-256 | `de62dbf8a697386736ad743301527cfbb265ddb311dfd7e8c4c17a87604f2660` |
| Family label | `unknown` |
| File name | `easyshell-l128-de62dbf8a6973867.bin` |
| File type | `elf` |
| First seen | `2026-11-22 03:36:23` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9108a749608608f56dc1f3ceeaa6d53` |
| SHA-1 | `8a284e131514dc7d17c91eac77f52805bc60fbc3` |
| SHA-256 | `de62dbf8a697386736ad743301527cfbb265ddb311dfd7e8c4c17a87604f2660` |
| SHA3-384 | `c1a5944c7009742ef87c63c9cced91d0d1f57d1c03176517569a20f4a05c31b32fc0a8d40df409363ff20d5b7eab766e` |
| TLSH | `T1EF067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CM:FUkCxwUGnaPdX8PdAS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_de62dbf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de62dbf8a697386736ad743301527cfbb265ddb311dfd7e8c4c17a87604f2660"
    family = "unknown"
    file_name = "easyshell-l128-de62dbf8a6973867.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:36:23"
  condition:
    hash.sha256(0, filesize) == "de62dbf8a697386736ad743301527cfbb265ddb311dfd7e8c4c17a87604f2660"
}
```

### Sample 54: `ba6cf8268569277e`

| Field | Value |
|---|---|
| SHA-256 | `ba6cf8268569277e0829e6520fcb909b53afee1c9ff77c2f4fa84b7352f45ef8` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-ba6cf8268569277e.bin` |
| File type | `macho` |
| First seen | `2026-11-22 03:36:11` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2ec2a6371b70830044eaa4955d5f2d4` |
| SHA-1 | `8c54ba66d2b1a9d0abeee0d71f2a2ece43722069` |
| SHA-256 | `ba6cf8268569277e0829e6520fcb909b53afee1c9ff77c2f4fa84b7352f45ef8` |
| SHA3-384 | `4b8d661510f869a72bab25308a1d0e7eb8eef184fde91a0ca5096db67935f1b07a809fcf2c0968e0d57455620f142704` |
| TLSH | `T126F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tgzsj5g5FIU6icBV8GQU5NZm+lz4:8SeI1gkkvTgzt5C+OGU5NZm+lz4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_ba6cf826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba6cf8268569277e0829e6520fcb909b53afee1c9ff77c2f4fa84b7352f45ef8"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-ba6cf8268569277e.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:36:11"
  condition:
    hash.sha256(0, filesize) == "ba6cf8268569277e0829e6520fcb909b53afee1c9ff77c2f4fa84b7352f45ef8"
}
```

### Sample 55: `2fff613eec82f689`

| Field | Value |
|---|---|
| SHA-256 | `2fff613eec82f689fbe881a72021da2c9113356edde66b338d23c561f4279533` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-2fff613eec82f689.bin` |
| File type | `macho` |
| First seen | `2026-11-22 03:36:01` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bee24a610efaaa990841536d34922ea2` |
| SHA-1 | `a3600fd5e7b571f86beeddbfcac5889f95a627bb` |
| SHA-256 | `2fff613eec82f689fbe881a72021da2c9113356edde66b338d23c561f4279533` |
| SHA3-384 | `9e599a359e5d3274af0f8a6a4bbec749751c038c5f23f883b37484708e0cf66c244f57c094c3f0a2da3ad421283b9a26` |
| TLSH | `T1F5168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6QKhx+wgbZmBlzcX:kyLbLNomEr6QKja` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_2fff613e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fff613eec82f689fbe881a72021da2c9113356edde66b338d23c561f4279533"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-2fff613eec82f689.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:36:01"
  condition:
    hash.sha256(0, filesize) == "2fff613eec82f689fbe881a72021da2c9113356edde66b338d23c561f4279533"
}
```

### Sample 56: `e19b17b0785986bb`

| Field | Value |
|---|---|
| SHA-256 | `e19b17b0785986bbc90e15f73acfbf3ac685595a3d747caafe8cf12c5e219b82` |
| Family label | `unknown` |
| File name | `easyshell-a64-e19b17b0785986bb.bin` |
| File type | `elf` |
| First seen | `2026-11-22 03:35:50` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `900df60af3660ff96520b01d63531065` |
| SHA-1 | `aae3b45f4873b122540b11e1d8bf3900468566de` |
| SHA-256 | `e19b17b0785986bbc90e15f73acfbf3ac685595a3d747caafe8cf12c5e219b82` |
| SHA3-384 | `9f2a52682cb925b2a02840b5f16d7a14dfd694ae5e2c7ea584b651e29dc1e273e931bf996ef4791504379505a7c3a3ed` |
| TLSH | `T1AD06B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WvGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WvLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e19b17b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e19b17b0785986bbc90e15f73acfbf3ac685595a3d747caafe8cf12c5e219b82"
    family = "unknown"
    file_name = "easyshell-a64-e19b17b0785986bb.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:35:50"
  condition:
    hash.sha256(0, filesize) == "e19b17b0785986bbc90e15f73acfbf3ac685595a3d747caafe8cf12c5e219b82"
}
```

### Sample 57: `40cbace90c418c18`

| Field | Value |
|---|---|
| SHA-256 | `40cbace90c418c186538fe01c61affbd2dc5bbbe2d617314ac97f4f764eabb3e` |
| Family label | `unknown` |
| File name | `easyshell-a32-40cbace90c418c18.bin` |
| File type | `elf` |
| First seen | `2026-11-22 03:35:35` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d20f5c3a01ba7de010666bbd6f99cf1` |
| SHA-1 | `d441195b8d376c2624191d1ef47d83932f6e6c1b` |
| SHA-256 | `40cbace90c418c186538fe01c61affbd2dc5bbbe2d617314ac97f4f764eabb3e` |
| SHA3-384 | `fa1ba8bd2f22aab71bfaa23b92db98e495ecc161f8bdffde4f1855bdc709eda78ab29cb719c02fd27f433f47af202da2` |
| TLSH | `T1EAF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBx:FhvZpiEGUx+pVdqE2laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_40cbace9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40cbace90c418c186538fe01c61affbd2dc5bbbe2d617314ac97f4f764eabb3e"
    family = "unknown"
    file_name = "easyshell-a32-40cbace90c418c18.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:35:35"
  condition:
    hash.sha256(0, filesize) == "40cbace90c418c186538fe01c61affbd2dc5bbbe2d617314ac97f4f764eabb3e"
}
```

### Sample 58: `9488a73e7044759c`

| Field | Value |
|---|---|
| SHA-256 | `9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76` |
| Family label | `Mirai` |
| File name | `9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76.elf` |
| File type | `elf` |
| First seen | `2026-11-22 03:23:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f84bbbdf4fa60c5bed3dc5951904db8b` |
| SHA-1 | `23ad050bf00423102fa862bfb2cb16d96751cbae` |
| SHA-256 | `9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76` |
| SHA3-384 | `6ec0d77632f4bebd68fba428306b349f05507148f2b8df4c2065f7701cbb7498d56d6f8e917167dc234ba6402f392e5c` |
| TLSH | `T12C126147A2D1CE7FC8E813384457122472BBD47ADFA29713064C64766E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5klTTej6TNJ9VSNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTITTfTpV+dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_9488a73e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76"
    family = "Mirai"
    file_name = "9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:23:33"
  condition:
    hash.sha256(0, filesize) == "9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76"
}
```

### Sample 59: `29d9fa86c2910e09`

| Field | Value |
|---|---|
| SHA-256 | `29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f` |
| Family label | `unknown` |
| File name | `29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f.elf` |
| File type | `elf` |
| First seen | `2026-11-22 03:23:29` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3daf69aa98e0e7abdd9c7885c7d8bad5` |
| SHA-1 | `63e18b22c89f1630ec929883225cb09487ca5837` |
| SHA-256 | `29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f` |
| SHA3-384 | `2eab32c5efbff610f07bd17d055ba5d73cd30a20af48bf70b71036546748dc719eb2dcf1b4f95d638d577187d8b08e53` |
| TLSH | `T15C22ED17F3E5DDFFC8AA577409A713703223C836DB428783680C46547FAB29E6EA5644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOvtsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxvtsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_29d9fa86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f"
    family = "unknown"
    file_name = "29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:23:29"
  condition:
    hash.sha256(0, filesize) == "29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f"
}
```

### Sample 60: `e4b3979b686f4f86`

| Field | Value |
|---|---|
| SHA-256 | `e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e` |
| Family label | `unknown` |
| File name | `e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e.elf` |
| File type | `elf` |
| First seen | `2026-11-22 03:19:30` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3f22920f5b68ab86d4d124b6db4830f` |
| SHA-1 | `0bbdd7dd50b86d190b9dda0941b095084caf7f06` |
| SHA-256 | `e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e` |
| SHA3-384 | `adcd18c30f4fef72c5c5261d8e0339d758339e5cfce21b1c6433fb04da0064331acbfc47d182fe214ca3115eb9e6bca2` |
| TLSH | `T1E822ED17F3D5DDFFC8AA577409A312703223C836DB428783680C46543FAB29E6EA5744` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMODtsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxDtsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_e4b3979b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e"
    family = "unknown"
    file_name = "e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:19:30"
  condition:
    hash.sha256(0, filesize) == "e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e"
}
```

### Sample 61: `16de8964fc6f30eb`

| Field | Value |
|---|---|
| SHA-256 | `16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4` |
| Family label | `unknown` |
| File name | `16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4.elf` |
| File type | `elf` |
| First seen | `2026-11-22 03:14:28` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93e800c7a415b702ca63d706a44cf1d4` |
| SHA-1 | `4d0e631417d50649699ad6f11a75cdbe576925a7` |
| SHA-256 | `16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4` |
| SHA3-384 | `f43eb8ca359c3affa9236f0753b7d88063c6b3a20d1beaf56a7c0ff827b05415ff6ccb63d57d0657a02401d2ed2bb3f6` |
| TLSH | `T19022EC17F3E5DDFFC8AA577409A312703223C836DB428783680C46553FAB29E6EA6644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOftsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxftsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_16de8964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4"
    family = "unknown"
    file_name = "16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:14:28"
  condition:
    hash.sha256(0, filesize) == "16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4"
}
```

### Sample 62: `426c59c7f7d4dc97`

| Field | Value |
|---|---|
| SHA-256 | `426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc` |
| Family label | `unknown` |
| File name | `426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc.elf` |
| File type | `elf` |
| First seen | `2026-11-22 03:10:28` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f242966737974068af6d4df2da080d0` |
| SHA-1 | `50280b27e5b36c481612b4bef06caa5c1f09fb0c` |
| SHA-256 | `426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc` |
| SHA3-384 | `759ce4b69eb5d75b8cdf8b73a22bbc5f4bdebb20c090153caab24bdda42d1f9caf884c7b104f3c1ebf822b3211fe4ea5` |
| TLSH | `T10CE13382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsYLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvlg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_426c59c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc"
    family = "unknown"
    file_name = "426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:10:28"
  condition:
    hash.sha256(0, filesize) == "426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc"
}
```

### Sample 63: `e0f9211e0e7dfc2b`

| Field | Value |
|---|---|
| SHA-256 | `e0f9211e0e7dfc2b76c4b4b158611cc0d2b32b93b5f47a8e5f30921a648b1bd3` |
| Family label | `unknown` |
| File name | `easyshell-l128-e0f9211e0e7dfc2b.bin` |
| File type | `elf` |
| First seen | `2026-11-22 03:05:40` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef4d12a15a0544e35a46c2a4c26cacd8` |
| SHA-1 | `b79107a5d58e1aacff2ab4038cbb41cde72b53a4` |
| SHA-256 | `e0f9211e0e7dfc2b76c4b4b158611cc0d2b32b93b5f47a8e5f30921a648b1bd3` |
| SHA3-384 | `abb35289aa8c55187ad5e1de2a354f7a4b4e5ff1a287061209d73adaf66b791c614825d5d4116874ec104887f93533bd` |
| TLSH | `T11C067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CW:FUkCxwUGnaPdX8PTAS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_e0f9211e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0f9211e0e7dfc2b76c4b4b158611cc0d2b32b93b5f47a8e5f30921a648b1bd3"
    family = "unknown"
    file_name = "easyshell-l128-e0f9211e0e7dfc2b.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:05:40"
  condition:
    hash.sha256(0, filesize) == "e0f9211e0e7dfc2b76c4b4b158611cc0d2b32b93b5f47a8e5f30921a648b1bd3"
}
```

### Sample 64: `4f0fa59e83ecdcb1`

| Field | Value |
|---|---|
| SHA-256 | `4f0fa59e83ecdcb19b3decea839d6efb0a493bcc7cbc6441bea2f678a761f593` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-4f0fa59e83ecdcb1.bin` |
| File type | `macho` |
| First seen | `2026-11-22 03:05:31` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b784736e0befdfc7264657150a2a3f6e` |
| SHA-1 | `c7a7df0408c1d16b335be792c72b9c96bbeb9240` |
| SHA-256 | `4f0fa59e83ecdcb19b3decea839d6efb0a493bcc7cbc6441bea2f678a761f593` |
| SHA3-384 | `7cba4ef661fcfe52a4ac99befaae85b192c5b1247c2c6fbe7b46aaff00245fc82565b0397c8543d6fa69df12ff1b6b01` |
| TLSH | `T1D4F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tg0sj5g5FIU6icBV8GQU5NZm+lza:8SeI1gkkvTg0t5C+OGU5NZm+lza` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_4f0fa59e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f0fa59e83ecdcb19b3decea839d6efb0a493bcc7cbc6441bea2f678a761f593"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-4f0fa59e83ecdcb1.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:05:31"
  condition:
    hash.sha256(0, filesize) == "4f0fa59e83ecdcb19b3decea839d6efb0a493bcc7cbc6441bea2f678a761f593"
}
```

### Sample 65: `127cdc08898474e2`

| Field | Value |
|---|---|
| SHA-256 | `127cdc08898474e2f203fd99adb0b7f9594316416b148c3f7271149b0aa9f3bb` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-127cdc08898474e2.bin` |
| File type | `macho` |
| First seen | `2026-11-22 03:05:23` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e25387363b06066d429c39b6cd3c8ea4` |
| SHA-1 | `174d564dcc70460eb9bee3a5bd0c557f6448269f` |
| SHA-256 | `127cdc08898474e2f203fd99adb0b7f9594316416b148c3f7271149b0aa9f3bb` |
| SHA3-384 | `0ca3b88ad8273c57f2d10c4870267bc62d8c2aff4bff934cfaed21ed6c1e6088d7c85d05a1087c7e54404327ae6a516b` |
| TLSH | `T16B168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO66Khx+wgbZmBlzlX:kyLbLNomEr66KjB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_127cdc08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "127cdc08898474e2f203fd99adb0b7f9594316416b148c3f7271149b0aa9f3bb"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-127cdc08898474e2.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:05:23"
  condition:
    hash.sha256(0, filesize) == "127cdc08898474e2f203fd99adb0b7f9594316416b148c3f7271149b0aa9f3bb"
}
```

### Sample 66: `f4d8b02fb88d38ba`

| Field | Value |
|---|---|
| SHA-256 | `f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927` |
| Family label | `Mirai` |
| File name | `f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:49:15` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a739ef587976bf069fd73d1128a7f5e` |
| SHA-1 | `4d3fab4de9a631dabb95a65d8ea93f001740c76d` |
| SHA-256 | `f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927` |
| SHA3-384 | `085bedbd14ffaeb9f89dad4160b1221e909f8a81acd0b681478f87ba3b392971a4edd71433eb4b7380d7c09661d75982` |
| TLSH | `T17DE15207E2D5CD72D8CD133846935749213AC86EAB83AF03650C5999EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFz146Owz7cSym4S2ofahbpZiQ:fsue7c+JpFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_f4d8b02f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927"
    family = "Mirai"
    file_name = "f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:49:15"
  condition:
    hash.sha256(0, filesize) == "f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927"
}
```

### Sample 67: `2a9de0c67c4c9949`

| Field | Value |
|---|---|
| SHA-256 | `2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf` |
| Family label | `Snowlight` |
| File name | `2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:45:23` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bdb4937aeab16b0df0e19b72d218c4c` |
| SHA-1 | `24b25c15f5bb74eae4b9e515efe3c4ead971d017` |
| SHA-256 | `2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf` |
| SHA3-384 | `030d7c203d89906a842e4fddfbd4fad22f0c7d669310966355f55986633db85a448e05056454b0966f8db3deef895b84` |
| TLSH | `T1D4124047A2D0CE3FC8D953384467122472B794BEDF629713064815B63F427E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6YkH5ML09V1J9G8Ymd+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHCZMWT1YmQhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_067_2a9de0c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf"
    family = "Snowlight"
    file_name = "2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:45:23"
  condition:
    hash.sha256(0, filesize) == "2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf"
}
```

### Sample 68: `e51390434f9b9f75`

| Field | Value |
|---|---|
| SHA-256 | `e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4` |
| Family label | `Snowlight` |
| File name | `e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:45:18` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9e26dd678b6db3fe3144e22d480688a` |
| SHA-1 | `fffb5f0a5e655834f65a3caf616e1ef181b27460` |
| SHA-256 | `e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4` |
| SHA3-384 | `877896219100fd8253b3673336a59cfd6b27e13ad28a80c9b4be09d33e9f070488811708de4e2051b111190d64e21694` |
| TLSH | `T1AB123047A2D0CE3FC8D953384467122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6hH5ML09V1J9G8YmD+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWH+ZMWT1YmyhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_068_e5139043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4"
    family = "Snowlight"
    file_name = "e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:45:18"
  condition:
    hash.sha256(0, filesize) == "e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4"
}
```

### Sample 69: `c7cba2982069fcbd`

| Field | Value |
|---|---|
| SHA-256 | `c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2` |
| Family label | `unknown` |
| File name | `c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:45:12` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55fa36c26c8bc53116f45a8b37140c3b` |
| SHA-1 | `0043787f35d5ece43b9af259e66438f9fbed5242` |
| SHA-256 | `c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2` |
| SHA3-384 | `882bae48646f6619ffff99ac4f82c1e8876c06a2f530eb55db9cdd1c6a7b781280450c47b36366b72197b58512215448` |
| TLSH | `T146E13382B9D6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsGLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvbg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_c7cba298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2"
    family = "unknown"
    file_name = "c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:45:12"
  condition:
    hash.sha256(0, filesize) == "c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2"
}
```

### Sample 70: `ae2ffa6371d991fa`

| Field | Value |
|---|---|
| SHA-256 | `ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1` |
| Family label | `Snowlight` |
| File name | `ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:44:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f318153de5521ded0af89c0b5ade1e09` |
| SHA-1 | `54f5964b019e46b4f6a240fa2fe5b1abbd7852a5` |
| SHA-256 | `ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1` |
| SHA3-384 | `a434b22f9ba672b43cd086abd39b0b7e0567282f6fa68d63aeb9600c6a50ea6b5e412c376502c5b05e00889f3159a5ec` |
| TLSH | `T13FE18117E2E2CD32D8D0137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3+JheuhiD5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbuJhA1Zz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_070_ae2ffa63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1"
    family = "Snowlight"
    file_name = "ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:44:09"
  condition:
    hash.sha256(0, filesize) == "ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1"
}
```

### Sample 71: `3a6eb545f67b05d7`

| Field | Value |
|---|---|
| SHA-256 | `3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e` |
| Family label | `Snowlight` |
| File name | `3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:43:18` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c72fa3e9be24b7b6bf27970c6c3a08e7` |
| SHA-1 | `8c3ac0a69c6c02e568da7f779d6bd28e1990c128` |
| SHA-256 | `3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e` |
| SHA3-384 | `84bd0b9d1c2dc84f29614e879b23a5a6d50667003ad937b32ec2476469e041820add47e2b740691dab982c29419a3b8c` |
| TLSH | `T1A8123F47A2D0CE3FC8D9533844A7122472B794BEDF629713064815B63F423E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8YmC+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmvhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_071_3a6eb545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e"
    family = "Snowlight"
    file_name = "3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:43:18"
  condition:
    hash.sha256(0, filesize) == "3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e"
}
```

### Sample 72: `a9b284bd0d02f949`

| Field | Value |
|---|---|
| SHA-256 | `a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73` |
| Family label | `unknown` |
| File name | `a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:43:15` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e858a009f27109c20c66917aa22fd6c` |
| SHA-1 | `e4f00f617301a0d5d9b9ed2798b6b96c733246b5` |
| SHA-256 | `a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73` |
| SHA3-384 | `64945e110e42d60045d5928a7503183626f1a2e02552109a29a557c329e3bf6d9fd3bf8578763fd55e32649bd8ef5b01` |
| TLSH | `T10AE13482BDD6CE3BCCA9627A1673C6203372C951AB439B17210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsDLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvmg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_a9b284bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73"
    family = "unknown"
    file_name = "a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:43:15"
  condition:
    hash.sha256(0, filesize) == "a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73"
}
```

### Sample 73: `421fe03e7fe7dc0a`

| Field | Value |
|---|---|
| SHA-256 | `421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b` |
| Family label | `Snowlight` |
| File name | `421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:43:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96a8c04ec6d49608b372f2e0f25836f7` |
| SHA-1 | `87ca4e0c9331748e1224ea53562fd254e72d54eb` |
| SHA-256 | `421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b` |
| SHA3-384 | `05c847abb9b1bfd81e3efacf584938fb51fa2d66090962eadd13da544996792c69f6e38b34e1753998ae4203ca08129c` |
| TLSH | `T168E16117E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3DJheuhilk5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbTJhAEZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_073_421fe03e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b"
    family = "Snowlight"
    file_name = "421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:43:11"
  condition:
    hash.sha256(0, filesize) == "421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b"
}
```

### Sample 74: `a5824717d76d9574`

| Field | Value |
|---|---|
| SHA-256 | `a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc` |
| Family label | `unknown` |
| File name | `a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc.bin` |
| File type | `macho` |
| First seen | `2026-11-22 02:43:07` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `822c85583928fc86a403acb77ebd97fb` |
| SHA-1 | `8a90dd2b8eca2b34524a46efdbb4fff15649a55c` |
| SHA-256 | `a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc` |
| SHA3-384 | `696bbb51004731790f1b8ccf3bae61ebe6efe500935d7862dee42e2d0f0c9720a413c69d78410018f9f56b905a157777` |
| TLSH | `T1F2E22D43AB4C8965C26D82301AF71BC6A616F5B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUCVZqDDt0TOTLZ0BbFw24HKk6XrMclSibFqAMcl:z4ZZXvv7VZMt0TO2bVI/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_a5824717
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc"
    family = "unknown"
    file_name = "a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:43:07"
  condition:
    hash.sha256(0, filesize) == "a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc"
}
```

### Sample 75: `df75fb0af714ebb1`

| Field | Value |
|---|---|
| SHA-256 | `df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1` |
| Family label | `Snowlight` |
| File name | `df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:41:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `546e7e6f77531adc31f45844fb650c17` |
| SHA-1 | `6b000ebc26eb32a6803c6a16581ebb7dee552bed` |
| SHA-256 | `df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1` |
| SHA3-384 | `dd9cdeaf987bdd5b09a05bfe5edb187a82aecfbb45e4bfaa0331abac5f50903895e528c8fa269fef983b7d24e86ece30` |
| TLSH | `T15CE16207E2D5CD72D8CD133846935749213AC86EAB83EF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccF9146Cwz7cSym4S2ofahbpZiQ:fsue7c8JtFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_075_df75fb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1"
    family = "Snowlight"
    file_name = "df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:41:13"
  condition:
    hash.sha256(0, filesize) == "df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1"
}
```

### Sample 76: `b88ce61119ffd4d6`

| Field | Value |
|---|---|
| SHA-256 | `b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51` |
| Family label | `VShell` |
| File name | `b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51.exe` |
| File type | `exe` |
| First seen | `2026-11-22 02:41:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58046ae1d5ff666d6b72e0013755fc43` |
| SHA-1 | `96871bbded0d54204743a066a2b3ad4c460dfd62` |
| SHA-256 | `b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51` |
| SHA3-384 | `8fe350361721e88fbb00144fd1783afc45b280ae2c753e72bd912ead7249729960cd203eba549d213582351436c165bf` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T18C716198F3136AF1E43C8BF840D3A664D0599BB8C250BF8D5F60381D3C210BA265EF96` |
| SSDEEP | `48:6Icwm0D8t2WdJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jc8t/SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_076_b88ce611
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51"
    family = "VShell"
    file_name = "b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:41:08"
  condition:
    hash.sha256(0, filesize) == "b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51"
}
```

### Sample 77: `8d8f265501b697fb`

| Field | Value |
|---|---|
| SHA-256 | `8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3` |
| Family label | `Mirai` |
| File name | `8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:41:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb2cd11aa53118d9074f80fd9b16cc33` |
| SHA-1 | `4e3e0fc68012a00f66bb1aefe303aee256a7d717` |
| SHA-256 | `8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3` |
| SHA3-384 | `78d21426fe9f277cf6f96b27eb6b460a6cdbe961950f53b2227280a2f0f23c77764041743deb5c1a95dfc09c74043de9` |
| TLSH | `T19DF14256BAEBDD73CCAD233A07678714337588D2AB43AB13610C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtzWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7b4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_8d8f2655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3"
    family = "Mirai"
    file_name = "8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:41:04"
  condition:
    hash.sha256(0, filesize) == "8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3"
}
```

### Sample 78: `0d09731b806d5b29`

| Field | Value |
|---|---|
| SHA-256 | `0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9` |
| Family label | `Mirai` |
| File name | `0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:40:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23925bcf41949f82968f5661f90ab232` |
| SHA-1 | `490b16ade701e1879cd76e2769d1d10a9116fcd7` |
| SHA-256 | `0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9` |
| SHA3-384 | `4fc1bd738d4a334263525c519efad90902758cef21b79a8888421aee03209d336c175fd6742be37cd4e035c0dca706d8` |
| TLSH | `T1A6F14256BAEBCD73CCAD233A07678714337588D2AF42AB13610C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtSWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7G4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_0d09731b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9"
    family = "Mirai"
    file_name = "0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:40:06"
  condition:
    hash.sha256(0, filesize) == "0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9"
}
```

### Sample 79: `3670d581ce49907e`

| Field | Value |
|---|---|
| SHA-256 | `3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38` |
| Family label | `Snowlight` |
| File name | `3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:40:00` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b8ee97f4263999ba54bbb4d9fb092c0` |
| SHA-1 | `a3306dc9542297e389e127a17b37fd90db6e3e75` |
| SHA-256 | `3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38` |
| SHA3-384 | `d000da145a10bbb3fe15ba6138f2c11735ee95a3e040fe31c1339c41609ba3d54d8f8ea52a945a6d37353bd7648512d8` |
| TLSH | `T153123047A2D0CE3FC8D9533844A7122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS67H5ML09V1J9G8Ym2+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHMZMWT1YmrhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_079_3670d581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38"
    family = "Snowlight"
    file_name = "3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:40:00"
  condition:
    hash.sha256(0, filesize) == "3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38"
}
```

### Sample 80: `52f2f47ab83bd438`

| Field | Value |
|---|---|
| SHA-256 | `52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a` |
| Family label | `Mirai` |
| File name | `52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:39:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8be7349d6a40e069d0ad55e911487211` |
| SHA-1 | `de3903b9b9e96454372e761c9d719da49404277e` |
| SHA-256 | `52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a` |
| SHA3-384 | `30663353813c4a5f15b084976f80b26670d04b1296bfc0267efd4aa2e3777cf80ab1978ac97208b57cbeafe3400bcd61` |
| TLSH | `T15AF13256BAEBCD73CCAD233A07678714337588D2AB42AB13610C08752D835ECAD76BD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtoBWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7u74OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_52f2f47a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a"
    family = "Mirai"
    file_name = "52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:13"
  condition:
    hash.sha256(0, filesize) == "52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a"
}
```

### Sample 81: `d14168ef3873196a`

| Field | Value |
|---|---|
| SHA-256 | `d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6` |
| Family label | `Mirai` |
| File name | `d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:39:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3d9ce0e20ae106841a3b5701eaefb2a` |
| SHA-1 | `5a633b5d65a0b455b2c4ae15b56302090488b8f1` |
| SHA-256 | `d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6` |
| SHA3-384 | `e1468a322819f6e4a684b882d312e7baa2c50a243d07e3b0fbde500e026b1624b62b28b9ea50faa0a2b1c585e3e06a4b` |
| TLSH | `T1ADE15207E2D5CD72D8CD133847935749223AC86EAB83AF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFF146gwz7cSym4S2ofahbpZiQ:fsue7cYJLFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_d14168ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6"
    family = "Mirai"
    file_name = "d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:10"
  condition:
    hash.sha256(0, filesize) == "d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6"
}
```

### Sample 82: `b5b2396cb8487d4d`

| Field | Value |
|---|---|
| SHA-256 | `b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503` |
| Family label | `unknown` |
| File name | `b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:39:06` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fbd4ae54438814f607d31a8c1961d2b` |
| SHA-1 | `78eeacd5394c663b7e8417ab012174d8b207309f` |
| SHA-256 | `b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503` |
| SHA3-384 | `8a5c54a88342ff4821e911bdfd05c5d6f426bb972116c9e2a22c71785e48a047c482784cc5a4199037a56b83878b1652` |
| TLSH | `T146E13382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsd0Lmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvdhg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_b5b2396c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503"
    family = "unknown"
    file_name = "b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:06"
  condition:
    hash.sha256(0, filesize) == "b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503"
}
```

### Sample 83: `1989c77490600455`

| Field | Value |
|---|---|
| SHA-256 | `1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27` |
| Family label | `unknown` |
| File name | `1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:39:02` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b6299804b3964dfbf62e9ac045d30dd` |
| SHA-1 | `6cc6ee8d1d673932fa075b75ddebd6af862702b4` |
| SHA-256 | `1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27` |
| SHA3-384 | `3963d51c424920917c5225729f0ee6043ca1344ef3cc8fd032255b3ea9f1a6584ca57d1ffdb9b5bd60ab289be704754e` |
| TLSH | `T14722EC17F3E5DDFFC8AA577809A713703223C836DB428783680C46547FAB29E6EA5644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMO6tsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dx6tsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_1989c774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27"
    family = "unknown"
    file_name = "1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:02"
  condition:
    hash.sha256(0, filesize) == "1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27"
}
```

### Sample 84: `148360b9b30da352`

| Field | Value |
|---|---|
| SHA-256 | `148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec` |
| Family label | `unknown` |
| File name | `148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec.bin` |
| File type | `macho` |
| First seen | `2026-11-22 02:38:58` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd48fb7a55f8b1852c10104b09946427` |
| SHA-1 | `e56ac4562271d0207a89f40301db9fe4e357bef4` |
| SHA-256 | `148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec` |
| SHA3-384 | `6e9331391caded90c6d6f65d840e44ca7c2cd6aa008796b34f1b552f3b622e45643348a6b27c8da9ff14d350d77c4a74` |
| TLSH | `T108E24F43675C5929D05D83BA62FB1B976609F8B009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEc5DbDP67li97WsCawYjqclS06W1YbqclSl:GI2c5DbDyIwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_148360b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec"
    family = "unknown"
    file_name = "148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:38:58"
  condition:
    hash.sha256(0, filesize) == "148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec"
}
```

### Sample 85: `c6d6956c6dbd8e59`

| Field | Value |
|---|---|
| SHA-256 | `c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15` |
| Family label | `Snowlight` |
| File name | `c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:37:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2c0fd9f1b3bfcd725020c7a84c781ce` |
| SHA-1 | `6e837adcc7f961f04e0865e7eefad5e7567a533b` |
| SHA-256 | `c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15` |
| SHA3-384 | `f53f114bdcf01117d2d4090328b227eafa9c9461ce50faab240709f2ddc4726b2bf2bc3d024065e7d29a103893c31923` |
| TLSH | `T17FE16217E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3SJheuhilL5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbiJhAnZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_085_c6d6956c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15"
    family = "Snowlight"
    file_name = "c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:37:46"
  condition:
    hash.sha256(0, filesize) == "c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15"
}
```

### Sample 86: `5767546a3455f16e`

| Field | Value |
|---|---|
| SHA-256 | `5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e` |
| Family label | `Mirai` |
| File name | `5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:37:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38019d45ba1e67b520c8f6b3acc2db7f` |
| SHA-1 | `134fa5b3f1605686dbe776fdcb5b23413c110914` |
| SHA-256 | `5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e` |
| SHA3-384 | `fc7f3a46cb5c1d2025f783975dcb95d1dc6cdcea84a4fe44d23f6e7fe0f03d67dd785fa31ce1b15ea06852d9b5ad3b13` |
| TLSH | `T1B1220D27F3D4DDFFC8AA5335899307713223C83ADB828383691C56593F9B29D1E65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOXx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeB+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_5767546a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e"
    family = "Mirai"
    file_name = "5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:37:42"
  condition:
    hash.sha256(0, filesize) == "5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e"
}
```

### Sample 87: `44594b0af658242d`

| Field | Value |
|---|---|
| SHA-256 | `44594b0af658242d61fcae9cacf5d1f520635b014908903524d0499c35dcf68e` |
| Family label | `unknown` |
| File name | `easyshell-l64-44594b0af658242d.bin` |
| File type | `elf` |
| First seen | `2026-11-22 02:36:57` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6f8dd2abd75dbde8b140c674f510c02` |
| SHA-1 | `11eae94ceb1014cc5ef82a39639c96aeacf1cc3d` |
| SHA-256 | `44594b0af658242d61fcae9cacf5d1f520635b014908903524d0499c35dcf68e` |
| SHA3-384 | `bfe28cd25b61630f9721091e35396cc83d56188d11ff839519e9d9d535f9a1d5d0616b540b13d83576199dc26e6045ac` |
| TLSH | `T19E267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxie0H8hIU6iKB:OYjiiKgib9qRGcEule0cW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_44594b0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44594b0af658242d61fcae9cacf5d1f520635b014908903524d0499c35dcf68e"
    family = "unknown"
    file_name = "easyshell-l64-44594b0af658242d.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:36:57"
  condition:
    hash.sha256(0, filesize) == "44594b0af658242d61fcae9cacf5d1f520635b014908903524d0499c35dcf68e"
}
```

### Sample 88: `57709d9d152792f0`

| Field | Value |
|---|---|
| SHA-256 | `57709d9d152792f0faa249455a20ae0d24655a32cf17d8f1f7b97875ec495569` |
| Family label | `unknown` |
| File name | `easyshell-l32-57709d9d152792f0.bin` |
| File type | `elf` |
| First seen | `2026-11-22 02:36:38` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30126d710257cd6d55a8aa9e1345569a` |
| SHA-1 | `5e48b357949afd0bf27733490949be09b8315e52` |
| SHA-256 | `57709d9d152792f0faa249455a20ae0d24655a32cf17d8f1f7b97875ec495569` |
| SHA3-384 | `e0336b9c234e2b430e242703e90c57499e91ff85666cbd8a6589ab8e0b40398933727614143d1844978e3008a2371221` |
| TLSH | `T1C1068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1xF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1xdb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_57709d9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57709d9d152792f0faa249455a20ae0d24655a32cf17d8f1f7b97875ec495569"
    family = "unknown"
    file_name = "easyshell-l32-57709d9d152792f0.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:36:38"
  condition:
    hash.sha256(0, filesize) == "57709d9d152792f0faa249455a20ae0d24655a32cf17d8f1f7b97875ec495569"
}
```

### Sample 89: `ad3ea695f5b6889f`

| Field | Value |
|---|---|
| SHA-256 | `ad3ea695f5b6889f149df3598898ec7f0ea5dfc1abf1d6245b794ccdc86b7cb2` |
| Family label | `unknown` |
| File name | `easyshell-l128-ad3ea695f5b6889f.bin` |
| File type | `elf` |
| First seen | `2026-11-22 02:36:21` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `187e349bb23edb4279f6978aeb86e382` |
| SHA-1 | `d63f6bdd7aa7979853310d8b618333e3d9582167` |
| SHA-256 | `ad3ea695f5b6889f149df3598898ec7f0ea5dfc1abf1d6245b794ccdc86b7cb2` |
| SHA3-384 | `45afcc9af9df1e0407366209d94ad46e0a24e120a9f45b372365f1ece63497fc2b31b6fbb0bed0589337bde8c486113e` |
| TLSH | `T12D067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CY:FUkCxwUGnaPdX8PRAS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_ad3ea695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad3ea695f5b6889f149df3598898ec7f0ea5dfc1abf1d6245b794ccdc86b7cb2"
    family = "unknown"
    file_name = "easyshell-l128-ad3ea695f5b6889f.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:36:21"
  condition:
    hash.sha256(0, filesize) == "ad3ea695f5b6889f149df3598898ec7f0ea5dfc1abf1d6245b794ccdc86b7cb2"
}
```

### Sample 90: `560e477d9fd6e8f4`

| Field | Value |
|---|---|
| SHA-256 | `560e477d9fd6e8f4033d4f207fa44aae3c095d0a8dbad4339a4906edc7352e77` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-560e477d9fd6e8f4.bin` |
| File type | `macho` |
| First seen | `2026-11-22 02:36:10` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab0deb266d896416dae462c7fa005f61` |
| SHA-1 | `ba4cc029e4fdf8d36fddb09c52163cf0f2c1928d` |
| SHA-256 | `560e477d9fd6e8f4033d4f207fa44aae3c095d0a8dbad4339a4906edc7352e77` |
| SHA3-384 | `8c4818266ff52f254e7da780fd95a2f1bc7a3f0c32ca59bad4839a3112893e2c2c74dbd126f0fe53a29117dd25cd7182` |
| TLSH | `T188F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tg6sj5g5FIU6icBV8GQU5NZm+lzP:8SeI1gkkvTg6t5C+OGU5NZm+lzP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_560e477d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "560e477d9fd6e8f4033d4f207fa44aae3c095d0a8dbad4339a4906edc7352e77"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-560e477d9fd6e8f4.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:36:10"
  condition:
    hash.sha256(0, filesize) == "560e477d9fd6e8f4033d4f207fa44aae3c095d0a8dbad4339a4906edc7352e77"
}
```

### Sample 91: `4b1e8c92b53a8054`

| Field | Value |
|---|---|
| SHA-256 | `4b1e8c92b53a8054fa76f1c22345bde3368e657a0001c2eaf3389d176a83967a` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-4b1e8c92b53a8054.bin` |
| File type | `macho` |
| First seen | `2026-11-22 02:36:01` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `560aafdd77f268ff3d54cce55847a43e` |
| SHA-1 | `4db377530349f1f1df41add5973c07510335d2b0` |
| SHA-256 | `4b1e8c92b53a8054fa76f1c22345bde3368e657a0001c2eaf3389d176a83967a` |
| SHA3-384 | `329198afdef6fbbc2b375bed48a6eba1c423bfa5ec931bb3282f83a3911b529b6552e01bf31d2766cfd6f01649cfc084` |
| TLSH | `T154168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6IKhx+wgbZmBlzsX:kyLbLNomEr6IKjy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_4b1e8c92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1e8c92b53a8054fa76f1c22345bde3368e657a0001c2eaf3389d176a83967a"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-4b1e8c92b53a8054.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:36:01"
  condition:
    hash.sha256(0, filesize) == "4b1e8c92b53a8054fa76f1c22345bde3368e657a0001c2eaf3389d176a83967a"
}
```

### Sample 92: `94c5458e5ec40830`

| Field | Value |
|---|---|
| SHA-256 | `94c5458e5ec408307d61b6b7a28e977e0835a207429c8471daebca2dc4f13e73` |
| Family label | `unknown` |
| File name | `easyshell-a64-94c5458e5ec40830.bin` |
| File type | `elf` |
| First seen | `2026-11-22 02:35:51` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8884651a53c93efa0598a82405b1a09` |
| SHA-1 | `9c658f272e82f7835d162545ffc20a1530a0dafc` |
| SHA-256 | `94c5458e5ec408307d61b6b7a28e977e0835a207429c8471daebca2dc4f13e73` |
| SHA3-384 | `0939cb9ebf74cfc7bf9062f6fc7bb215618f760c99e7f7f3c3a580f0b36683aef740f0ea34ea920323e214374b86b1ec` |
| TLSH | `T1F606B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712W3GYKIU6iKx4YzjJHz2b3:EWBWoO2OC712W3Ld+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_94c5458e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94c5458e5ec408307d61b6b7a28e977e0835a207429c8471daebca2dc4f13e73"
    family = "unknown"
    file_name = "easyshell-a64-94c5458e5ec40830.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:51"
  condition:
    hash.sha256(0, filesize) == "94c5458e5ec408307d61b6b7a28e977e0835a207429c8471daebca2dc4f13e73"
}
```

### Sample 93: `420b398543f6eaf7`

| Field | Value |
|---|---|
| SHA-256 | `420b398543f6eaf762970ea87709b013eaa1f55d731db395eecedeeb241a24f6` |
| Family label | `unknown` |
| File name | `easyshell-a32-420b398543f6eaf7.bin` |
| File type | `elf` |
| First seen | `2026-11-22 02:35:42` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e462383c97c3eb11dd4ae7de8d4475b` |
| SHA-1 | `fc60cf536f8a41536a60a00a365bf82f6ca4c3d6` |
| SHA-256 | `420b398543f6eaf762970ea87709b013eaa1f55d731db395eecedeeb241a24f6` |
| SHA3-384 | `a643db3eaff05f8b001ce2d1551a7f3bf9455b9117173717fa02ea281566ab1443831254e12d2e2d7c321a23ebf7985a` |
| TLSH | `T1EFF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBI:FhvZpiEGUx+pVdqj2laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_420b3985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420b398543f6eaf762970ea87709b013eaa1f55d731db395eecedeeb241a24f6"
    family = "unknown"
    file_name = "easyshell-a32-420b398543f6eaf7.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:42"
  condition:
    hash.sha256(0, filesize) == "420b398543f6eaf762970ea87709b013eaa1f55d731db395eecedeeb241a24f6"
}
```

### Sample 94: `fd65edfa48b0f1de`

| Field | Value |
|---|---|
| SHA-256 | `fd65edfa48b0f1debb87048d0642aa11330787c5ecc6c6a6dd3a7bdbe94899e3` |
| Family label | `unknown` |
| File name | `bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461.exe` |
| File type | `exe` |
| First seen | `2026-11-22 02:35:36` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09568034d4fea53ec55b025bff0ec67e` |
| SHA-1 | `eb4ab5de1ea76678de856303036390dab35dd4dd` |
| SHA-256 | `fd65edfa48b0f1debb87048d0642aa11330787c5ecc6c6a6dd3a7bdbe94899e3` |
| SHA3-384 | `997e9f6d87ffc37bc7b6fbdfc434e533ad894f72d8014dde8e976a7d11d3d4afad3ef2ae610b97b6cd0aab77f78593c2` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1707749A3F9A21DE4C4ACE439C16294523B71BC59473053D77A99FB206F3ABD06E7A700` |
| SSDEEP | `196608:nOT4YI1cf0wwVPlipUpnGBunUf8hk3kxCb/DzZAAwnqsuy:84dtwgPlipm3Uf8hkVbZD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_fd65edfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd65edfa48b0f1debb87048d0642aa11330787c5ecc6c6a6dd3a7bdbe94899e3"
    family = "unknown"
    file_name = "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:35:36"
  condition:
    hash.sha256(0, filesize) == "fd65edfa48b0f1debb87048d0642aa11330787c5ecc6c6a6dd3a7bdbe94899e3"
}
```

### Sample 95: `782f7659e7ded305`

| Field | Value |
|---|---|
| SHA-256 | `782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe` |
| Family label | `Snowlight` |
| File name | `782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:35:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ae05ffb5ac7ef8417267a3ee8f6d29c` |
| SHA-1 | `ec61094aaef4811ca3116229f55b21c71ddc09aa` |
| SHA-256 | `782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe` |
| SHA3-384 | `2e38118fc281b19d67be87fecd66be8c4b343a6bc2468b7d654a33c6dd542937d27c1ae0f653d2c5095282c7f1620375` |
| TLSH | `T192124047A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9VFNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpVVdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_095_782f7659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe"
    family = "Snowlight"
    file_name = "782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:10"
  condition:
    hash.sha256(0, filesize) == "782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe"
}
```

### Sample 96: `80f39ac61300ef0a`

| Field | Value |
|---|---|
| SHA-256 | `80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde` |
| Family label | `Mirai` |
| File name | `80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde.elf` |
| File type | `elf` |
| First seen | `2026-11-22 02:35:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc6084c5b15ec3a67949c10f79631168` |
| SHA-1 | `b637c2091744a83f7df1489f195dce195af519d5` |
| SHA-256 | `80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde` |
| SHA3-384 | `e0254fbe667c9013752c42c6c4743fb66686bd7adbdc125eba924a33b8943581c7123464bf685db42d7c6282be02a2e4` |
| TLSH | `T127F13356BAEBCD73CCAD233A07678714337588D2AB42AB13611C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8Dt+QWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7w+4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_80f39ac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde"
    family = "Mirai"
    file_name = "80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:05"
  condition:
    hash.sha256(0, filesize) == "80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde"
}
```

### Sample 97: `4b40529b516789fd`

| Field | Value |
|---|---|
| SHA-256 | `4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef` |
| Family label | `unknown` |
| File name | `4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef.exe` |
| File type | `exe` |
| First seen | `2026-11-22 02:34:19` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae1a57bdf44d3bc87c0f500ce8c615d4` |
| SHA-1 | `76af99116c0a9c9feb595ed7786e15428a1a316b` |
| SHA-256 | `4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef` |
| SHA3-384 | `f1a721087edfe1ee46a79507fc0929f5905f360c9fc4e814d10a4cb6dae842a891dcea86c28c3a5553025b5715d0f2a7` |
| IMPHASH | `61480822252d0ba4def6189894f99a0a` |
| TLSH | `T15626331851D3F8B4C5D9413F6A336752B70A07E23EB442B74DFAAA8D3739A60FE44461` |
| SSDEEP | `98304:yYETGkztP4NEj1C+R5xuxHdlqtwkQnE0gDsLQ4t7MsBtcEbqr2eKYlQxr:y7G6uNy4+R5Ix9Uw7pQ4t1/C2ho4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_4b40529b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef"
    family = "unknown"
    file_name = "4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:19"
  condition:
    hash.sha256(0, filesize) == "4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef"
}
```

### Sample 98: `bfdc4f1d759cfed6`

| Field | Value |
|---|---|
| SHA-256 | `bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461` |
| Family label | `unknown` |
| File name | `bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461.exe` |
| File type | `exe` |
| First seen | `2026-11-22 02:34:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afe16c9ef090cbb3d093bdc9a8b49216` |
| SHA-1 | `6d61b80e2bb113ea9911a0022f71ee9170df23f6` |
| SHA-256 | `bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461` |
| SHA3-384 | `1211e036cd46d7ff1fc691a8599d8c8492d2e3bdb84212752fb7744ad13fe0ead4ee39af6b0b7100e1b88f7db581c25a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1778633F3D4159DC9D12AA833DC7E634A34D298ABB78719923E8164E2731170F7E092DE` |
| SSDEEP | `196608:r44HxYFIhYx48Xu2TlcIwkOLqotTYjerGXs0I5QkP0Verj+1+sHeZHf:3Hx4cYx4WuGwkO2o+jeK+u0r2JeZH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_bfdc4f1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461"
    family = "unknown"
    file_name = "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:14"
  condition:
    hash.sha256(0, filesize) == "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461"
}
```

### Sample 99: `a0b5d7303653d5fa`

| Field | Value |
|---|---|
| SHA-256 | `a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd` |
| Family label | `AsyncRAT` |
| File name | `a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd.exe` |
| File type | `exe` |
| First seen | `2026-11-22 02:34:08` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af57bb9c431b18c527f7a189a1ad440a` |
| SHA-1 | `585ddd1011e2fb6749f3dab1835bc9c479f2859e` |
| SHA-256 | `a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd` |
| SHA3-384 | `89ee49415b1b86f3c90d9504c4c5f8a64c2df5b028c65c227caa2b3b85522e80a2aab6b91780e9bae2aa5c97046cf1d7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T156232B003BE9812BF1BE4F78ACF26145867AF6633602D54D2CC451DB5613BC69A42AFE` |
| SSDEEP | `768:xuQHNTvEEaBrWUXFd5mo2qmiAv5U9GJAoqEzPIizjbcgX3im8nfD/Al1BDZex:xuQHNT8572xXvMhpi3bzXSvfD/Abdex` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_099_a0b5d730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd"
    family = "AsyncRAT"
    file_name = "a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:08"
  condition:
    hash.sha256(0, filesize) == "a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd"
}
```

### Sample 100: `aaf507608bebae4f`

| Field | Value |
|---|---|
| SHA-256 | `aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060` |
| Family label | `AsyncRAT` |
| File name | `aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060.exe` |
| File type | `exe` |
| First seen | `2026-11-22 02:34:04` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1100d6abb454b068c1f0647e4277c9f` |
| SHA-1 | `6a28183e84c7e8a1f873255cdb33c93b41c4820d` |
| SHA-256 | `aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060` |
| SHA3-384 | `28fdf337a63dcf2cd11aa7dbb93b73a89bd1e290ace1e82b7fbb204c821e52f8ea05678dad12e3f21cf1af981dfe943e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T118233A0037E9812BF2BE5F7899F26145867AF2637603D98D2CC411DB4613FC69642AFE` |
| SSDEEP | `768:muISdTYEXlTWU/+qhmo2qbWROGJAYGIHPIXzjbCgX3iJZXHve9BFzuq44BDZfx:muISdTYUN2pQ9pX3blXSrm563+dfx` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_100_aaf50760
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060"
    family = "AsyncRAT"
    file_name = "aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:04"
  condition:
    hash.sha256(0, filesize) == "aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060"
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
 * Generated: 2026-11-22T07:03:28.995719+00:00
 */

rule MalwareBazaar_unknown_001_b83222b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83222b68af47625da71b332e68969894dcaf4de7f026d995e9b9562432963b0"
    family = "unknown"
    file_name = "stage3_payload.dll"
    file_type = "dll"
    first_seen = "2026-11-22 06:43:27"
  condition:
    hash.sha256(0, filesize) == "b83222b68af47625da71b332e68969894dcaf4de7f026d995e9b9562432963b0"
}

rule MalwareBazaar_unknown_002_d5b6c533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9"
    family = "unknown"
    file_name = "stage2_GeoAPI.dll"
    file_type = "dll"
    first_seen = "2026-11-22 06:43:20"
  condition:
    hash.sha256(0, filesize) == "d5b6c533464791de05d018fe3c1b35dafc52c5def01b3d88e592f30889459bc9"
}

rule MalwareBazaar_unknown_003_6625aea9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6625aea96db13a283507c36ab57d6f5d9b40a1d8d282a99c2f90204fc93db10e"
    family = "unknown"
    file_name = "macho_6625aea96db1.bin"
    file_type = "macho"
    first_seen = "2026-11-22 06:27:18"
  condition:
    hash.sha256(0, filesize) == "6625aea96db13a283507c36ab57d6f5d9b40a1d8d282a99c2f90204fc93db10e"
}

rule MalwareBazaar_unknown_004_db3781a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3781a0d5193d2dafb6c332844dccaa613ea2954f9cafc4a1ac2316a3febf74"
    family = "unknown"
    file_name = "stage1_db3781a0d519.zsh"
    file_type = "zsh"
    first_seen = "2026-11-22 06:27:10"
  condition:
    hash.sha256(0, filesize) == "db3781a0d5193d2dafb6c332844dccaa613ea2954f9cafc4a1ac2316a3febf74"
}

rule MalwareBazaar_Prometei_005_79bd50b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79bd50b55be8f1084fcb6c6e101efd3e301377357a9026b43ac2d7fb101c4132"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 06:08:05"
  condition:
    hash.sha256(0, filesize) == "79bd50b55be8f1084fcb6c6e101efd3e301377357a9026b43ac2d7fb101c4132"
}

rule MalwareBazaar_unknown_006_51168eac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51168eace244c00e97e0bf25045cee749fa000d5e82ecbf7820f9b3ad285bef9"
    family = "unknown"
    file_name = "easyshell-l64-51168eace244c00e.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:06:24"
  condition:
    hash.sha256(0, filesize) == "51168eace244c00e97e0bf25045cee749fa000d5e82ecbf7820f9b3ad285bef9"
}

rule MalwareBazaar_unknown_007_b4e1ff8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4e1ff8d3bf8835bce05f991c48b5d7151a73fbc4865737e919973ebd2b17517"
    family = "unknown"
    file_name = "easyshell-l32-b4e1ff8d3bf8835b.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:06:12"
  condition:
    hash.sha256(0, filesize) == "b4e1ff8d3bf8835bce05f991c48b5d7151a73fbc4865737e919973ebd2b17517"
}

rule MalwareBazaar_unknown_008_8c860d4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c860d4f5a0bc5a521cf9e2d2fcefd204bb937640e67c0fc0e939caeb626cec1"
    family = "unknown"
    file_name = "easyshell-l128-8c860d4f5a0bc5a5.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:06:04"
  condition:
    hash.sha256(0, filesize) == "8c860d4f5a0bc5a521cf9e2d2fcefd204bb937640e67c0fc0e939caeb626cec1"
}

rule MalwareBazaar_unknown_009_d3b80a7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3b80a7d6395872ad3f0f3da938d6f9de10a37c92f1d633f268a452eb983bf93"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-d3b80a7d6395872a.bin"
    file_type = "macho"
    first_seen = "2026-11-22 06:05:56"
  condition:
    hash.sha256(0, filesize) == "d3b80a7d6395872ad3f0f3da938d6f9de10a37c92f1d633f268a452eb983bf93"
}

rule MalwareBazaar_unknown_010_5d323e7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d323e7e0a47d099f1f8d883919abfbcc50dbb537f8f711c57bd1ff6ac6cad58"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-5d323e7e0a47d099.bin"
    file_type = "macho"
    first_seen = "2026-11-22 06:05:49"
  condition:
    hash.sha256(0, filesize) == "5d323e7e0a47d099f1f8d883919abfbcc50dbb537f8f711c57bd1ff6ac6cad58"
}

rule MalwareBazaar_unknown_011_5fee32ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fee32ba6b1747a1246930e49096f224e0cdf4f9d82386e92ec3fb1b36f99527"
    family = "unknown"
    file_name = "easyshell-a64-5fee32ba6b1747a1.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:05:39"
  condition:
    hash.sha256(0, filesize) == "5fee32ba6b1747a1246930e49096f224e0cdf4f9d82386e92ec3fb1b36f99527"
}

rule MalwareBazaar_unknown_012_6e237da8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6"
    family = "unknown"
    file_name = "easyshell-a32-6e237da8c748e4af.bin"
    file_type = "elf"
    first_seen = "2026-11-22 06:05:31"
  condition:
    hash.sha256(0, filesize) == "6e237da8c748e4afc14fccae83533eb03f8ac2a1c4958379fc1d623bfc28bfa6"
}

rule MalwareBazaar_Prometei_013_ef912751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef91275146f14b583e829410df052ae84bb770f5d50295d068d9a0e3e98ca887"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 06:02:05"
  condition:
    hash.sha256(0, filesize) == "ef91275146f14b583e829410df052ae84bb770f5d50295d068d9a0e3e98ca887"
}

rule MalwareBazaar_Prometei_014_4d2cf54f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d2cf54f047be0726d8f4c32a177c6620729457745ed24c63cdbcde1f091e35c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:48:08"
  condition:
    hash.sha256(0, filesize) == "4d2cf54f047be0726d8f4c32a177c6620729457745ed24c63cdbcde1f091e35c"
}

rule MalwareBazaar_Prometei_015_b2a6bec1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a6bec11bc9297a16f8516a34bf513c34f4e8cd7f3015ac223ed0b0bdd8e473"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:48:05"
  condition:
    hash.sha256(0, filesize) == "b2a6bec11bc9297a16f8516a34bf513c34f4e8cd7f3015ac223ed0b0bdd8e473"
}

rule MalwareBazaar_Prometei_016_324d1210
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "324d121016696bb62b0cda3c7dee7e8f931acea7cf7231890cd772accb666e0e"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:43:06"
  condition:
    hash.sha256(0, filesize) == "324d121016696bb62b0cda3c7dee7e8f931acea7cf7231890cd772accb666e0e"
}

rule MalwareBazaar_Mirai_017_97b11141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b11141a91af93a778afb3ccc68100fac980c1daa41df6ac65cd7034382b287"
    family = "Mirai"
    file_name = "splm68k"
    file_type = "elf"
    first_seen = "2026-11-22 05:41:05"
  condition:
    hash.sha256(0, filesize) == "97b11141a91af93a778afb3ccc68100fac980c1daa41df6ac65cd7034382b287"
}

rule MalwareBazaar_Mirai_018_77ee1ac0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77ee1ac0e1cebe542621f7696c594b3d19f32d5f1784a8e9b9fbe879c68fbc1e"
    family = "Mirai"
    file_name = "nklsh4"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:13"
  condition:
    hash.sha256(0, filesize) == "77ee1ac0e1cebe542621f7696c594b3d19f32d5f1784a8e9b9fbe879c68fbc1e"
}

rule MalwareBazaar_Mirai_019_ea3ba48d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1"
    family = "Mirai"
    file_name = "splarm7"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:11"
  condition:
    hash.sha256(0, filesize) == "ea3ba48d47911939b516dabb21ed302bb3a66a61916d86a9f60d8a0df7975ed1"
}

rule MalwareBazaar_Prometei_020_be758e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be758e9e5ced1c67dddd360c20bd28ff0feb8a0e18272cbb615ca2b48a1ae2d8"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:08"
  condition:
    hash.sha256(0, filesize) == "be758e9e5ced1c67dddd360c20bd28ff0feb8a0e18272cbb615ca2b48a1ae2d8"
}

rule MalwareBazaar_Mirai_021_e1adcb6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0"
    family = "Mirai"
    file_name = "splspc"
    file_type = "elf"
    first_seen = "2026-11-22 05:35:05"
  condition:
    hash.sha256(0, filesize) == "e1adcb6d7f294e4c50c6507350f0e705b027482b3c84de02146c6c52ab6fd6f0"
}

rule MalwareBazaar_Mirai_022_cedf9be0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cedf9be0a3bd2b9d9bc756ff8168422eb9e0318169ce8caf85f6a3f25370aaf8"
    family = "Mirai"
    file_name = "nklarm6"
    file_type = "elf"
    first_seen = "2026-11-22 05:32:09"
  condition:
    hash.sha256(0, filesize) == "cedf9be0a3bd2b9d9bc756ff8168422eb9e0318169ce8caf85f6a3f25370aaf8"
}

rule MalwareBazaar_Mirai_023_0b8e14f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8e14f2818069a955f9f5d6678491873c070da5910050c0f3b5fdde8af22657"
    family = "Mirai"
    file_name = "nklx86"
    file_type = "elf"
    first_seen = "2026-11-22 05:32:06"
  condition:
    hash.sha256(0, filesize) == "0b8e14f2818069a955f9f5d6678491873c070da5910050c0f3b5fdde8af22657"
}

rule MalwareBazaar_Mirai_024_76150239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "761502391a5a576872b57a799cdc55b089ced5fd5a850ab433bfae173f7eb915"
    family = "Mirai"
    file_name = "nklarm5"
    file_type = "elf"
    first_seen = "2026-11-22 05:31:05"
  condition:
    hash.sha256(0, filesize) == "761502391a5a576872b57a799cdc55b089ced5fd5a850ab433bfae173f7eb915"
}

rule MalwareBazaar_Mirai_025_c15f379d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c15f379dfdecb483eeef9ec025df9e5b0d78f00dd58b6adbedee163faaf6e2d3"
    family = "Mirai"
    file_name = "nabsh4"
    file_type = "elf"
    first_seen = "2026-11-22 05:27:07"
  condition:
    hash.sha256(0, filesize) == "c15f379dfdecb483eeef9ec025df9e5b0d78f00dd58b6adbedee163faaf6e2d3"
}

rule MalwareBazaar_Mirai_026_f5bc707d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5bc707ddd5e3ab0a20d925b9fe153bab05c66e39be8c87f67e028a4bca95610"
    family = "Mirai"
    file_name = "splppc"
    file_type = "elf"
    first_seen = "2026-11-22 05:27:04"
  condition:
    hash.sha256(0, filesize) == "f5bc707ddd5e3ab0a20d925b9fe153bab05c66e39be8c87f67e028a4bca95610"
}

rule MalwareBazaar_WARDENStealer_027_98a5e300
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92"
    family = "WARDENStealer"
    file_name = "p?t=0636274d194685e698b7f6bc558eec14_d5bcce35aaf5dafe9c99bbe0105909d2d90d1456"
    file_type = "exe"
    first_seen = "2026-11-22 05:24:07"
  condition:
    hash.sha256(0, filesize) == "98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92"
}

rule MalwareBazaar_unknown_028_7425b7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7425b7a56dc9742208fed2d4604f0a3e186e58192b48f4c6a96592ce1d56e49d"
    family = "unknown"
    file_name = "stage2_plugx.dll"
    file_type = "dll"
    first_seen = "2026-11-22 05:16:11"
  condition:
    hash.sha256(0, filesize) == "7425b7a56dc9742208fed2d4604f0a3e186e58192b48f4c6a96592ce1d56e49d"
}

rule MalwareBazaar_unknown_029_42e9e779
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957"
    family = "unknown"
    file_name = "easyshell-l64-42e9e779b677a744.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:07:07"
  condition:
    hash.sha256(0, filesize) == "42e9e779b677a744028b1276672d6ec010a96773cd143dd38cf32fdf104a4957"
}

rule MalwareBazaar_unknown_030_dba9625f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb"
    family = "unknown"
    file_name = "easyshell-l32-dba9625fec97eb3b.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:06:53"
  condition:
    hash.sha256(0, filesize) == "dba9625fec97eb3bac3ffdd2c3036ab2dd5a0b66ee8761cd07e9325cf663bfeb"
}

rule MalwareBazaar_unknown_031_4b0f0e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b0f0e682377662425e8c94754be35f0adb263589bc26dcc49faba7c038ffca1"
    family = "unknown"
    file_name = "easyshell-l128-4b0f0e6823776624.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:06:41"
  condition:
    hash.sha256(0, filesize) == "4b0f0e682377662425e8c94754be35f0adb263589bc26dcc49faba7c038ffca1"
}

rule MalwareBazaar_unknown_032_72577de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72577de6fb4313e23d46c5c4b713bb5c458427e353c562060da4175b3e77cad4"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-72577de6fb4313e2.bin"
    file_type = "macho"
    first_seen = "2026-11-22 05:06:27"
  condition:
    hash.sha256(0, filesize) == "72577de6fb4313e23d46c5c4b713bb5c458427e353c562060da4175b3e77cad4"
}

rule MalwareBazaar_unknown_033_e25839ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e25839ef096b39109333cb92d8baa5880402a3841057e6133833135d8e4ca78c"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-e25839ef096b3910.bin"
    file_type = "macho"
    first_seen = "2026-11-22 05:06:12"
  condition:
    hash.sha256(0, filesize) == "e25839ef096b39109333cb92d8baa5880402a3841057e6133833135d8e4ca78c"
}

rule MalwareBazaar_unknown_034_7be5b6ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223"
    family = "unknown"
    file_name = "easyshell-a64-7be5b6eef6df0540.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:05:56"
  condition:
    hash.sha256(0, filesize) == "7be5b6eef6df0540a745b8e725a5fdc4ff4ce95c878afcf6f0b4f88a36bdd223"
}

rule MalwareBazaar_unknown_035_e8e60fbb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2"
    family = "unknown"
    file_name = "easyshell-a32-e8e60fbba93bc587.bin"
    file_type = "elf"
    first_seen = "2026-11-22 05:05:40"
  condition:
    hash.sha256(0, filesize) == "e8e60fbba93bc587135a5a474bc52dec8dd6ec0d051d38554d71ecf9f6f463e2"
}

rule MalwareBazaar_unknown_036_2ae7c72b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56"
    family = "unknown"
    file_name = "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
    file_type = "elf"
    first_seen = "2026-11-22 05:00:36"
  condition:
    hash.sha256(0, filesize) == "2ae7c72ba12d52355551550aa6c2147549a40260524bbb2c8bbb359b0474bc56"
}

rule MalwareBazaar_unknown_037_486d2587
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
    family = "unknown"
    file_name = "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
    file_type = "elf"
    first_seen = "2026-11-22 05:00:02"
  condition:
    hash.sha256(0, filesize) == "486d258731b76f0922d79542593cc97880100f589028743a0a79b7380c19ee31"
}

rule MalwareBazaar_unknown_038_d396f3c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d396f3c20883a3b71244c87c537595108010239e4e17e6c09bca83ea5a475677"
    family = "unknown"
    file_name = "SendFile.dll"
    file_type = "dll"
    first_seen = "2026-11-22 04:45:47"
  condition:
    hash.sha256(0, filesize) == "d396f3c20883a3b71244c87c537595108010239e4e17e6c09bca83ea5a475677"
}

rule MalwareBazaar_unknown_039_f7a83c14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7a83c1455e0e0b41dbe6e69daa346356fbfc076f3edb12b99b9d0f76ec4068e"
    family = "unknown"
    file_name = "RemoteDesktop.dll"
    file_type = "dll"
    first_seen = "2026-11-22 04:45:41"
  condition:
    hash.sha256(0, filesize) == "f7a83c1455e0e0b41dbe6e69daa346356fbfc076f3edb12b99b9d0f76ec4068e"
}

rule MalwareBazaar_njrat_040_65278002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5"
    family = "njrat"
    file_name = "0393931eeb8f945c58c40b438ba310d5.exe"
    file_type = "exe"
    first_seen = "2026-11-22 04:35:18"
  condition:
    hash.sha256(0, filesize) == "65278002c1474ae35c8abafd51ae524d9d4a18cabea22597cd505fbcd780c1a5"
}

rule MalwareBazaar_unknown_041_c7b88a43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7b88a4348f9221566d2146fc892ea3a1fb0db642344fcbeddc9bb3721ea4a5b"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-c7b88a4348f92215.bin"
    file_type = "macho"
    first_seen = "2026-11-22 04:35:15"
  condition:
    hash.sha256(0, filesize) == "c7b88a4348f9221566d2146fc892ea3a1fb0db642344fcbeddc9bb3721ea4a5b"
}

rule MalwareBazaar_njrat_042_e96cfcc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96cfcc9e76752365f8f73ce50e8c73e7400c2d0bf5b652ed1274f7f673b3655"
    family = "njrat"
    file_name = "041036279a76a6991e5e8f961a2fdb6a.exe"
    file_type = "exe"
    first_seen = "2026-11-22 04:35:13"
  condition:
    hash.sha256(0, filesize) == "e96cfcc9e76752365f8f73ce50e8c73e7400c2d0bf5b652ed1274f7f673b3655"
}

rule MalwareBazaar_njrat_043_6917a5ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6917a5ed510690eb3fd89690acc09f5fa8e106efd986002afef4e3f6b5654288"
    family = "njrat"
    file_name = "85D7BFF793FE83CE92BCD656C89A53C9.exe"
    file_type = "exe"
    first_seen = "2026-11-22 04:35:08"
  condition:
    hash.sha256(0, filesize) == "6917a5ed510690eb3fd89690acc09f5fa8e106efd986002afef4e3f6b5654288"
}

rule MalwareBazaar_unknown_044_d4bf63ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4bf63eabcb4b7d9af2eb7421fe0072bf9c6f634fc6d55cb2001ea1831a141f1"
    family = "unknown"
    file_name = "easyshell-l64-d4bf63eabcb4b7d9.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:06:34"
  condition:
    hash.sha256(0, filesize) == "d4bf63eabcb4b7d9af2eb7421fe0072bf9c6f634fc6d55cb2001ea1831a141f1"
}

rule MalwareBazaar_unknown_045_f4d89fdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d89fdb46433b8265ed4f6ffc00eab5e983ffd70835e912256d9e8c978a7cce"
    family = "unknown"
    file_name = "easyshell-l32-f4d89fdb46433b82.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:06:25"
  condition:
    hash.sha256(0, filesize) == "f4d89fdb46433b8265ed4f6ffc00eab5e983ffd70835e912256d9e8c978a7cce"
}

rule MalwareBazaar_unknown_046_5687dc25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5687dc250beeb631c44478c7101e1d40751b3ce9cfb3c2654f67d5ce8fd5700b"
    family = "unknown"
    file_name = "easyshell-l128-5687dc250beeb631.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:06:16"
  condition:
    hash.sha256(0, filesize) == "5687dc250beeb631c44478c7101e1d40751b3ce9cfb3c2654f67d5ce8fd5700b"
}

rule MalwareBazaar_unknown_047_52c0e084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52c0e084a024b59f442937763818d5bab2f7ca03a78f28257d84855cf28cee4c"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-52c0e084a024b59f.bin"
    file_type = "macho"
    first_seen = "2026-11-22 04:06:05"
  condition:
    hash.sha256(0, filesize) == "52c0e084a024b59f442937763818d5bab2f7ca03a78f28257d84855cf28cee4c"
}

rule MalwareBazaar_unknown_048_ecb7249f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecb7249f17a35a37bb3d6c07cbf595e7e072194f0a73d860619ccd1eca929d3e"
    family = "unknown"
    file_name = "easyshell-a64-ecb7249f17a35a37.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:05:56"
  condition:
    hash.sha256(0, filesize) == "ecb7249f17a35a37bb3d6c07cbf595e7e072194f0a73d860619ccd1eca929d3e"
}

rule MalwareBazaar_unknown_049_81eef296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81eef296f3a763689e27d7a6c6649ca1652595e792e66a5e9b5fcbebbe7bab13"
    family = "unknown"
    file_name = "easyshell-a32-81eef296f3a76368.bin"
    file_type = "elf"
    first_seen = "2026-11-22 04:05:46"
  condition:
    hash.sha256(0, filesize) == "81eef296f3a763689e27d7a6c6649ca1652595e792e66a5e9b5fcbebbe7bab13"
}

rule MalwareBazaar_unknown_050_110c0724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "110c07247027bb547d5c49ac1075c66009f0fe8758f4372a5919760f4257f3ae"
    family = "unknown"
    file_name = "bld_TlrF2SwGuBe_C-7pcu0IIdZx.exe"
    file_type = "exe"
    first_seen = "2026-11-22 03:37:17"
  condition:
    hash.sha256(0, filesize) == "110c07247027bb547d5c49ac1075c66009f0fe8758f4372a5919760f4257f3ae"
}

rule MalwareBazaar_unknown_051_ea433127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea4331274b2e94537380aae9c28ff5565d218bf12f7f6917297d672d91b5f03b"
    family = "unknown"
    file_name = "easyshell-l64-ea4331274b2e9453.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:36:44"
  condition:
    hash.sha256(0, filesize) == "ea4331274b2e94537380aae9c28ff5565d218bf12f7f6917297d672d91b5f03b"
}

rule MalwareBazaar_unknown_052_f10c69f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f10c69f82a06e92d3804ee19afecfa60b586864afb0c218cb15116ad3d8211a7"
    family = "unknown"
    file_name = "easyshell-l32-f10c69f82a06e92d.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:36:34"
  condition:
    hash.sha256(0, filesize) == "f10c69f82a06e92d3804ee19afecfa60b586864afb0c218cb15116ad3d8211a7"
}

rule MalwareBazaar_unknown_053_de62dbf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de62dbf8a697386736ad743301527cfbb265ddb311dfd7e8c4c17a87604f2660"
    family = "unknown"
    file_name = "easyshell-l128-de62dbf8a6973867.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:36:23"
  condition:
    hash.sha256(0, filesize) == "de62dbf8a697386736ad743301527cfbb265ddb311dfd7e8c4c17a87604f2660"
}

rule MalwareBazaar_unknown_054_ba6cf826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba6cf8268569277e0829e6520fcb909b53afee1c9ff77c2f4fa84b7352f45ef8"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-ba6cf8268569277e.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:36:11"
  condition:
    hash.sha256(0, filesize) == "ba6cf8268569277e0829e6520fcb909b53afee1c9ff77c2f4fa84b7352f45ef8"
}

rule MalwareBazaar_unknown_055_2fff613e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fff613eec82f689fbe881a72021da2c9113356edde66b338d23c561f4279533"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-2fff613eec82f689.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:36:01"
  condition:
    hash.sha256(0, filesize) == "2fff613eec82f689fbe881a72021da2c9113356edde66b338d23c561f4279533"
}

rule MalwareBazaar_unknown_056_e19b17b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e19b17b0785986bbc90e15f73acfbf3ac685595a3d747caafe8cf12c5e219b82"
    family = "unknown"
    file_name = "easyshell-a64-e19b17b0785986bb.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:35:50"
  condition:
    hash.sha256(0, filesize) == "e19b17b0785986bbc90e15f73acfbf3ac685595a3d747caafe8cf12c5e219b82"
}

rule MalwareBazaar_unknown_057_40cbace9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40cbace90c418c186538fe01c61affbd2dc5bbbe2d617314ac97f4f764eabb3e"
    family = "unknown"
    file_name = "easyshell-a32-40cbace90c418c18.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:35:35"
  condition:
    hash.sha256(0, filesize) == "40cbace90c418c186538fe01c61affbd2dc5bbbe2d617314ac97f4f764eabb3e"
}

rule MalwareBazaar_Mirai_058_9488a73e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76"
    family = "Mirai"
    file_name = "9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:23:33"
  condition:
    hash.sha256(0, filesize) == "9488a73e7044759c6956f038efce32560ef2976ed49820fa5a87f0ed84f2bb76"
}

rule MalwareBazaar_unknown_059_29d9fa86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f"
    family = "unknown"
    file_name = "29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:23:29"
  condition:
    hash.sha256(0, filesize) == "29d9fa86c2910e09df9e75d9c08c8e969d05fcaa5816da755465170a0fa5847f"
}

rule MalwareBazaar_unknown_060_e4b3979b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e"
    family = "unknown"
    file_name = "e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:19:30"
  condition:
    hash.sha256(0, filesize) == "e4b3979b686f4f86522d826721d582c38bbdf8ec9e3bef07788c4f3f1e970d3e"
}

rule MalwareBazaar_unknown_061_16de8964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4"
    family = "unknown"
    file_name = "16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:14:28"
  condition:
    hash.sha256(0, filesize) == "16de8964fc6f30eb5ed80978c2e6bea878160f889b3ba9b08b76f771498606f4"
}

rule MalwareBazaar_unknown_062_426c59c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc"
    family = "unknown"
    file_name = "426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc.elf"
    file_type = "elf"
    first_seen = "2026-11-22 03:10:28"
  condition:
    hash.sha256(0, filesize) == "426c59c7f7d4dc97d7ca4ac32c9a0227cd9b25ab598d63594e640b3855db35fc"
}

rule MalwareBazaar_unknown_063_e0f9211e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0f9211e0e7dfc2b76c4b4b158611cc0d2b32b93b5f47a8e5f30921a648b1bd3"
    family = "unknown"
    file_name = "easyshell-l128-e0f9211e0e7dfc2b.bin"
    file_type = "elf"
    first_seen = "2026-11-22 03:05:40"
  condition:
    hash.sha256(0, filesize) == "e0f9211e0e7dfc2b76c4b4b158611cc0d2b32b93b5f47a8e5f30921a648b1bd3"
}

rule MalwareBazaar_unknown_064_4f0fa59e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f0fa59e83ecdcb19b3decea839d6efb0a493bcc7cbc6441bea2f678a761f593"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-4f0fa59e83ecdcb1.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:05:31"
  condition:
    hash.sha256(0, filesize) == "4f0fa59e83ecdcb19b3decea839d6efb0a493bcc7cbc6441bea2f678a761f593"
}

rule MalwareBazaar_unknown_065_127cdc08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "127cdc08898474e2f203fd99adb0b7f9594316416b148c3f7271149b0aa9f3bb"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-127cdc08898474e2.bin"
    file_type = "macho"
    first_seen = "2026-11-22 03:05:23"
  condition:
    hash.sha256(0, filesize) == "127cdc08898474e2f203fd99adb0b7f9594316416b148c3f7271149b0aa9f3bb"
}

rule MalwareBazaar_Mirai_066_f4d8b02f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927"
    family = "Mirai"
    file_name = "f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:49:15"
  condition:
    hash.sha256(0, filesize) == "f4d8b02fb88d38ba31e04772130cbf0e62c0363482c96f435bd873282cf19927"
}

rule MalwareBazaar_Snowlight_067_2a9de0c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf"
    family = "Snowlight"
    file_name = "2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:45:23"
  condition:
    hash.sha256(0, filesize) == "2a9de0c67c4c9949ebddc0fa1b261e9d71d6cd5a3f94266540ec335c09ee7fdf"
}

rule MalwareBazaar_Snowlight_068_e5139043
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4"
    family = "Snowlight"
    file_name = "e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:45:18"
  condition:
    hash.sha256(0, filesize) == "e51390434f9b9f757c4777058fc76548dad77d747ca935ebc1cf8745aa6ef4e4"
}

rule MalwareBazaar_unknown_069_c7cba298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2"
    family = "unknown"
    file_name = "c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:45:12"
  condition:
    hash.sha256(0, filesize) == "c7cba2982069fcbd2a6c62b75bda25ad73f04908e8fca409e2b5400c99807de2"
}

rule MalwareBazaar_Snowlight_070_ae2ffa63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1"
    family = "Snowlight"
    file_name = "ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:44:09"
  condition:
    hash.sha256(0, filesize) == "ae2ffa6371d991fa68715cb68fbf330e99a3cb212b368c4b1a9adf42275657c1"
}

rule MalwareBazaar_Snowlight_071_3a6eb545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e"
    family = "Snowlight"
    file_name = "3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:43:18"
  condition:
    hash.sha256(0, filesize) == "3a6eb545f67b05d720c8ddcd56ad54c06ea499a26ade554dc80efe8e5acd0b6e"
}

rule MalwareBazaar_unknown_072_a9b284bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73"
    family = "unknown"
    file_name = "a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:43:15"
  condition:
    hash.sha256(0, filesize) == "a9b284bd0d02f949da7b0b2b585c63b0c13d19c09ec69a4b9c9d56d9c8788c73"
}

rule MalwareBazaar_Snowlight_073_421fe03e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b"
    family = "Snowlight"
    file_name = "421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:43:11"
  condition:
    hash.sha256(0, filesize) == "421fe03e7fe7dc0acc6d7a235e410caffdf0bba1879e6db9b98bb37d686f9a7b"
}

rule MalwareBazaar_unknown_074_a5824717
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc"
    family = "unknown"
    file_name = "a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:43:07"
  condition:
    hash.sha256(0, filesize) == "a5824717d76d9574e61674fcb8f9ece65e5d9d17e1a0378855071c39b95139cc"
}

rule MalwareBazaar_Snowlight_075_df75fb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1"
    family = "Snowlight"
    file_name = "df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:41:13"
  condition:
    hash.sha256(0, filesize) == "df75fb0af714ebb11a671b7969373514e05ed8712189e14348ecc425e31fc1b1"
}

rule MalwareBazaar_VShell_076_b88ce611
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51"
    family = "VShell"
    file_name = "b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:41:08"
  condition:
    hash.sha256(0, filesize) == "b88ce61119ffd4d676b42900455a62ba1c822d62ac3dd03672a1982959917b51"
}

rule MalwareBazaar_Mirai_077_8d8f2655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3"
    family = "Mirai"
    file_name = "8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:41:04"
  condition:
    hash.sha256(0, filesize) == "8d8f265501b697fb3d8617a97422d006ba40e7f2c28c433f24dc2104d070d0c3"
}

rule MalwareBazaar_Mirai_078_0d09731b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9"
    family = "Mirai"
    file_name = "0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:40:06"
  condition:
    hash.sha256(0, filesize) == "0d09731b806d5b292cd0fc8d86bd6f1cf49ae417b678e386bc68c9c9403fe3f9"
}

rule MalwareBazaar_Snowlight_079_3670d581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38"
    family = "Snowlight"
    file_name = "3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:40:00"
  condition:
    hash.sha256(0, filesize) == "3670d581ce49907e22eb922c31aa361db24baf897b1c16438fb3f84ac7b42e38"
}

rule MalwareBazaar_Mirai_080_52f2f47a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a"
    family = "Mirai"
    file_name = "52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:13"
  condition:
    hash.sha256(0, filesize) == "52f2f47ab83bd438292b358f2cb2a3e1364c776bf32cd26c0521538e146aab2a"
}

rule MalwareBazaar_Mirai_081_d14168ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6"
    family = "Mirai"
    file_name = "d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:10"
  condition:
    hash.sha256(0, filesize) == "d14168ef3873196a1a7a2ac241a84139b12744a15ecc344117e8db7c1945c0c6"
}

rule MalwareBazaar_unknown_082_b5b2396c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503"
    family = "unknown"
    file_name = "b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:06"
  condition:
    hash.sha256(0, filesize) == "b5b2396cb8487d4d248e33dd89ac937ba82933d6d1f4f53d3dc5df9b839a7503"
}

rule MalwareBazaar_unknown_083_1989c774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27"
    family = "unknown"
    file_name = "1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:39:02"
  condition:
    hash.sha256(0, filesize) == "1989c7749060045535e6b529a31fd2aa4359d6b014c7608dccd69e7fc80edb27"
}

rule MalwareBazaar_unknown_084_148360b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec"
    family = "unknown"
    file_name = "148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:38:58"
  condition:
    hash.sha256(0, filesize) == "148360b9b30da35291ae5a328d2be28b6f3ab69d9e176772bb0c323a8a4750ec"
}

rule MalwareBazaar_Snowlight_085_c6d6956c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15"
    family = "Snowlight"
    file_name = "c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:37:46"
  condition:
    hash.sha256(0, filesize) == "c6d6956c6dbd8e591e09f2255b084e6329c81f8e0ebe7ad33888bbcf5986ec15"
}

rule MalwareBazaar_Mirai_086_5767546a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e"
    family = "Mirai"
    file_name = "5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:37:42"
  condition:
    hash.sha256(0, filesize) == "5767546a3455f16eb4866f37caa775d74c6cd0d839c72023978d9d43b50a3d3e"
}

rule MalwareBazaar_unknown_087_44594b0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44594b0af658242d61fcae9cacf5d1f520635b014908903524d0499c35dcf68e"
    family = "unknown"
    file_name = "easyshell-l64-44594b0af658242d.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:36:57"
  condition:
    hash.sha256(0, filesize) == "44594b0af658242d61fcae9cacf5d1f520635b014908903524d0499c35dcf68e"
}

rule MalwareBazaar_unknown_088_57709d9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57709d9d152792f0faa249455a20ae0d24655a32cf17d8f1f7b97875ec495569"
    family = "unknown"
    file_name = "easyshell-l32-57709d9d152792f0.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:36:38"
  condition:
    hash.sha256(0, filesize) == "57709d9d152792f0faa249455a20ae0d24655a32cf17d8f1f7b97875ec495569"
}

rule MalwareBazaar_unknown_089_ad3ea695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad3ea695f5b6889f149df3598898ec7f0ea5dfc1abf1d6245b794ccdc86b7cb2"
    family = "unknown"
    file_name = "easyshell-l128-ad3ea695f5b6889f.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:36:21"
  condition:
    hash.sha256(0, filesize) == "ad3ea695f5b6889f149df3598898ec7f0ea5dfc1abf1d6245b794ccdc86b7cb2"
}

rule MalwareBazaar_unknown_090_560e477d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "560e477d9fd6e8f4033d4f207fa44aae3c095d0a8dbad4339a4906edc7352e77"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-560e477d9fd6e8f4.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:36:10"
  condition:
    hash.sha256(0, filesize) == "560e477d9fd6e8f4033d4f207fa44aae3c095d0a8dbad4339a4906edc7352e77"
}

rule MalwareBazaar_unknown_091_4b1e8c92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1e8c92b53a8054fa76f1c22345bde3368e657a0001c2eaf3389d176a83967a"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-4b1e8c92b53a8054.bin"
    file_type = "macho"
    first_seen = "2026-11-22 02:36:01"
  condition:
    hash.sha256(0, filesize) == "4b1e8c92b53a8054fa76f1c22345bde3368e657a0001c2eaf3389d176a83967a"
}

rule MalwareBazaar_unknown_092_94c5458e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94c5458e5ec408307d61b6b7a28e977e0835a207429c8471daebca2dc4f13e73"
    family = "unknown"
    file_name = "easyshell-a64-94c5458e5ec40830.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:51"
  condition:
    hash.sha256(0, filesize) == "94c5458e5ec408307d61b6b7a28e977e0835a207429c8471daebca2dc4f13e73"
}

rule MalwareBazaar_unknown_093_420b3985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420b398543f6eaf762970ea87709b013eaa1f55d731db395eecedeeb241a24f6"
    family = "unknown"
    file_name = "easyshell-a32-420b398543f6eaf7.bin"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:42"
  condition:
    hash.sha256(0, filesize) == "420b398543f6eaf762970ea87709b013eaa1f55d731db395eecedeeb241a24f6"
}

rule MalwareBazaar_unknown_094_fd65edfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd65edfa48b0f1debb87048d0642aa11330787c5ecc6c6a6dd3a7bdbe94899e3"
    family = "unknown"
    file_name = "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:35:36"
  condition:
    hash.sha256(0, filesize) == "fd65edfa48b0f1debb87048d0642aa11330787c5ecc6c6a6dd3a7bdbe94899e3"
}

rule MalwareBazaar_Snowlight_095_782f7659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe"
    family = "Snowlight"
    file_name = "782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:10"
  condition:
    hash.sha256(0, filesize) == "782f7659e7ded3054142a6e14cf187e5fddd04a629f0fee5a57f7db1726cfdfe"
}

rule MalwareBazaar_Mirai_096_80f39ac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde"
    family = "Mirai"
    file_name = "80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde.elf"
    file_type = "elf"
    first_seen = "2026-11-22 02:35:05"
  condition:
    hash.sha256(0, filesize) == "80f39ac61300ef0a9012279c360f4b454471646febaf47f9396466a5fffb2fde"
}

rule MalwareBazaar_unknown_097_4b40529b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef"
    family = "unknown"
    file_name = "4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:19"
  condition:
    hash.sha256(0, filesize) == "4b40529b516789fdb4472658b31a92d3ead5ff304eaa18b4e82df5c16ea44fef"
}

rule MalwareBazaar_unknown_098_bfdc4f1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461"
    family = "unknown"
    file_name = "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:14"
  condition:
    hash.sha256(0, filesize) == "bfdc4f1d759cfed6a234791a254e6233cf1622298f2ec323e8d56525ccc88461"
}

rule MalwareBazaar_AsyncRAT_099_a0b5d730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd"
    family = "AsyncRAT"
    file_name = "a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:08"
  condition:
    hash.sha256(0, filesize) == "a0b5d7303653d5faa11bd8a59a269429c3213a03e696322c87dd27af260cfffd"
}

rule MalwareBazaar_AsyncRAT_100_aaf50760
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060"
    family = "AsyncRAT"
    file_name = "aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060.exe"
    file_type = "exe"
    first_seen = "2026-11-22 02:34:04"
  condition:
    hash.sha256(0, filesize) == "aaf507608bebae4ff5c736e194bea67b72235347eb4bdbae3eda0861cfd6e060"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

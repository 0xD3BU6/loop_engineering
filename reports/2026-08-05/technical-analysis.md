# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-05

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 651 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 651 |
| Unique family labels | 12 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 51 |
| unknown | 32 |
| ValleyRAT | 4 |
| Prometei | 3 |
| CoinMiner | 2 |
| Pony | 2 |
| Gh0stRAT | 1 |
| Formbook | 1 |
| DCRat | 1 |
| RemcosRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 57 |
| exe | 21 |
| sh | 14 |
| unknown | 2 |
| js | 2 |
| zip | 2 |
| dll | 2 |

## Per-Sample Analysis

### Sample 1: `e0be3f6600d16a77`

| Field | Value |
|---|---|
| SHA-256 | `e0be3f6600d16a77b705cc780dde976839e605c8c44b7205af301f0bab4287ef` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-05 03:22:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b2de39726907ebb133bbb630c55536a` |
| SHA-1 | `db57a3ab74d95d9aac6c48c910ce15978f5507f4` |
| SHA-256 | `e0be3f6600d16a77b705cc780dde976839e605c8c44b7205af301f0bab4287ef` |
| SHA3-384 | `e342806c76e9fe152ac23931bb1f5eb6ad062fd992dd4fa43eb17230f79ff9c7ecd99d79cc512ff12562797a8aa20ef3` |
| TLSH | `T190C319A9F890DE52C6D526B6FB4E418C33231778C3DE7106CE149E3467FB95A0A3E942` |
| SSDEEP | `3072:ZT5VBa0Zv5medpH+mMJ1uIYrcYEEUIvXMWmNwhGolYMqPbN3F+RDuS5mf1Dl:ZVDZniruBrcYEEUIvXMWAwP6MqHmiomf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_e0be3f66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0be3f6600d16a77b705cc780dde976839e605c8c44b7205af301f0bab4287ef"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-05 03:22:34"
  condition:
    hash.sha256(0, filesize) == "e0be3f6600d16a77b705cc780dde976839e605c8c44b7205af301f0bab4287ef"
}
```

### Sample 2: `8beb744ad418cf03`

| Field | Value |
|---|---|
| SHA-256 | `8beb744ad418cf0304095aead056fde47dcb889ed917b78559c8c0c68dffe581` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-05 03:21:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef1c39c21ac6ea4c7bb99d379f0d85f0` |
| SHA-1 | `12f04e1ae2873a32a5fe1df0d6e1fe5840ac573c` |
| SHA-256 | `8beb744ad418cf0304095aead056fde47dcb889ed917b78559c8c0c68dffe581` |
| SHA3-384 | `978ff1ad8193c4d25ee6f766fdc6ef2982e0ba28336c51d166c325f837eb3167ef54586218bed7319c57ef7b5e2f4a78` |
| TLSH | `T13A430262220A7FD1C5932C7BD37EF188B194A97C52B836B1433902D9D165C5B3BFB542` |
| SSDEEP | `1536:5vL3NHASE8G6gmaSZX/NAdPJW1bsg5MDT3l5fZl:5vDNdEcgAZXlQh2sw+v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_8beb744a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8beb744ad418cf0304095aead056fde47dcb889ed917b78559c8c0c68dffe581"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-05 03:21:47"
  condition:
    hash.sha256(0, filesize) == "8beb744ad418cf0304095aead056fde47dcb889ed917b78559c8c0c68dffe581"
}
```

### Sample 3: `0a9c86f0f73ef504`

| Field | Value |
|---|---|
| SHA-256 | `0a9c86f0f73ef504afc9215b8032b4f10e356cc6d8bb20eff97413ae517faafc` |
| Family label | `Mirai` |
| File name | `renzo.sh` |
| File type | `sh` |
| First seen | `2026-08-05 03:11:32` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6865f288f369477f5b51466d1c2f3e6a` |
| SHA-1 | `1208a1b612e279f45563c907afbad6330c44aa24` |
| SHA-256 | `0a9c86f0f73ef504afc9215b8032b4f10e356cc6d8bb20eff97413ae517faafc` |
| SHA3-384 | `374679e1c2f01e570fc14fded8246a383d5723694d17fe7500bf45cf03213776d63ed114a27913403643d75caa16ac67` |
| TLSH | `T191019EED946644313F0E943B32291C507641082F24B95EDD128EDD638E0CFA9235EA33` |
| SSDEEP | `12:liXI0aDNjWr5jWijW2HjN/OpG5rNaQFTERE5YEmYXmY6uYYiH:4MNjWr5jWijW2HjN/OqsGBYDYXmYRYr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_0a9c86f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a9c86f0f73ef504afc9215b8032b4f10e356cc6d8bb20eff97413ae517faafc"
    family = "Mirai"
    file_name = "renzo.sh"
    file_type = "sh"
    first_seen = "2026-08-05 03:11:32"
  condition:
    hash.sha256(0, filesize) == "0a9c86f0f73ef504afc9215b8032b4f10e356cc6d8bb20eff97413ae517faafc"
}
```

### Sample 4: `e9e1ff9629e53ed0`

| Field | Value |
|---|---|
| SHA-256 | `e9e1ff9629e53ed07c4cb758a310d894d88c049f497bd189a058a85c8bff2a61` |
| Family label | `unknown` |
| File name | `sensi_totolink.sh` |
| File type | `sh` |
| First seen | `2026-08-05 03:09:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b26ebec73708719f7b4de88beda7538c` |
| SHA-1 | `1603351affedee2afaa42fae3b5fa83d282bf32c` |
| SHA-256 | `e9e1ff9629e53ed07c4cb758a310d894d88c049f497bd189a058a85c8bff2a61` |
| SHA3-384 | `4335874fa4d17a3268270b225054b76fcc8088749bacc4c7e72e16bb284b302a89d16103eea1d0a8d58694d793ee53b6` |
| TLSH | `T12DF09EE5955284323F3D4A36F7041895F642181714E16689714DD9315E3C9786265F33` |
| SSDEEP | `12:Am6MJGvFHV7KCkpQm9jWT9jWg5jWJFFl7j6NiCYRNaNN7sfYOfqd0Y1IYTv:AmlJGi8m9jWT9jWg5jWJFr7je7YRsvYC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_e9e1ff96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9e1ff9629e53ed07c4cb758a310d894d88c049f497bd189a058a85c8bff2a61"
    family = "unknown"
    file_name = "sensi_totolink.sh"
    file_type = "sh"
    first_seen = "2026-08-05 03:09:17"
  condition:
    hash.sha256(0, filesize) == "e9e1ff9629e53ed07c4cb758a310d894d88c049f497bd189a058a85c8bff2a61"
}
```

### Sample 5: `834e241f797dc0f4`

| Field | Value |
|---|---|
| SHA-256 | `834e241f797dc0f4886cfdd0b2ef6e6fbbb510d2ab5d481fbe55fedb63fd7b21` |
| Family label | `unknown` |
| File name | `netgear` |
| File type | `sh` |
| First seen | `2026-08-05 03:09:16` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab7ef4f6f862458c6343e0d25553b5e1` |
| SHA-1 | `1f59e8587afe235e5b84f80e074b486352638700` |
| SHA-256 | `834e241f797dc0f4886cfdd0b2ef6e6fbbb510d2ab5d481fbe55fedb63fd7b21` |
| SHA3-384 | `747ee9647613d59ed3d6018a8ec875dce00041d312adfb2cbe841947d781f788b78abb318abb9c496f987c50aae506a4` |
| TLSH | `T15901AFF5A49289353F29CB37B6095985F901142B18B52689B10C9A715F3C9742259F33` |
| SSDEEP | `24:uem9jWhjWg5jWJFr7jS/Y7YLaWcfXsvofYOfHY1IYpYsYlRv:uT9j8jZ5jsnjS/IWcfXffnPl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_834e241f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "834e241f797dc0f4886cfdd0b2ef6e6fbbb510d2ab5d481fbe55fedb63fd7b21"
    family = "unknown"
    file_name = "netgear"
    file_type = "sh"
    first_seen = "2026-08-05 03:09:16"
  condition:
    hash.sha256(0, filesize) == "834e241f797dc0f4886cfdd0b2ef6e6fbbb510d2ab5d481fbe55fedb63fd7b21"
}
```

### Sample 6: `f0a9123f4a672c76`

| Field | Value |
|---|---|
| SHA-256 | `f0a9123f4a672c76a6c61a47b8ef4d991b398526c0b072f909ccc2630e0eb2de` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-05 02:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c7970a95086dc63e2c9262e7c195eff` |
| SHA-1 | `f6739b4ad55b2377afa8a6299e81a94a03bfa71f` |
| SHA-256 | `f0a9123f4a672c76a6c61a47b8ef4d991b398526c0b072f909ccc2630e0eb2de` |
| SHA3-384 | `f0528b00cb954df4ecb16ef1e3c8de5660f5b518ce3275bb9080a01737211bf9bbe1afb4523df4901deede48dfa6ed8e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T113E6334869D423EEDAF3857C8DC208AAE179B4764732CAEB1BB867971D531E08D3D701` |
| SSDEEP | `393216:cGmnP3gEQTMzhP56AXMCHWUjfcuI3/PGTAI:cGNEQTMNPdXMb80H/O7` |
| ICON-DHASH | `e8e864e0d8e8ec48` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_f0a9123f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0a9123f4a672c76a6c61a47b8ef4d991b398526c0b072f909ccc2630e0eb2de"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-05 02:52:29"
  condition:
    hash.sha256(0, filesize) == "f0a9123f4a672c76a6c61a47b8ef4d991b398526c0b072f909ccc2630e0eb2de"
}
```

### Sample 7: `135cefead339d5e0`

| Field | Value |
|---|---|
| SHA-256 | `135cefead339d5e0813e38049da8666efefef7c7b64c6ed22f5fec62b676ced1` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-08-05 02:50:28` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cc953fc3fd9bd40ff0a4fd6dd21b41b` |
| SHA-1 | `b4bc5e859101507ec3af8b556def0aa817246179` |
| SHA-256 | `135cefead339d5e0813e38049da8666efefef7c7b64c6ed22f5fec62b676ced1` |
| SHA3-384 | `6f2ae1270e513774624184ed91098318a26cc6a650703a2c490f76ee52ebd65eca0f49eb1175d001c0da6aaeabd25b2d` |
| TLSH | `T1BD0429C7FD00DDBAF809E33748130809B130BBA254925A777257356FED3A295197BE8A` |
| SSDEEP | `3072:T1ThsmVqwyJ3XjRcirf200yvcKd34FSkGD52RVRf4grVpjbiNLEy5cKNKB:Uwgx4yvjd34F7GD8V4g2LLvNKB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_135cefea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135cefead339d5e0813e38049da8666efefef7c7b64c6ed22f5fec62b676ced1"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:28"
  condition:
    hash.sha256(0, filesize) == "135cefead339d5e0813e38049da8666efefef7c7b64c6ed22f5fec62b676ced1"
}
```

### Sample 8: `5f3709aa1823bc15`

| Field | Value |
|---|---|
| SHA-256 | `5f3709aa1823bc153c63dc5d0bccab9fbf9e252a910a08a639e857bd9f8f0149` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-08-05 02:50:28` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7bc67139a7d7ed94654c4e0de1aa334` |
| SHA-1 | `2668cd67e8df3c5e91df5fc339ad3c110cdc57f6` |
| SHA-256 | `5f3709aa1823bc153c63dc5d0bccab9fbf9e252a910a08a639e857bd9f8f0149` |
| SHA3-384 | `54c0dfa121afb147381b59e84611bada03077b86263768dd63daa8e6798125a672b41d840415b8f004307f91ed799a5e` |
| TLSH | `T17E24955E6A328F7DF368873447B74A35975D22D627E1DA84E2ACC1041F2434E681FFA8` |
| TELFHASH | `t15741811c097813b0a7796c5e499dff76d6a330de7f262c238e50e86aa769b835d11c0c` |
| SSDEEP | `3072:sPvQ0inW06qBVrDuQ5SPkCekMcJXs9op/rzibKom:sw0inW06I1DA81qJQ2/r4Kom` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_5f3709aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f3709aa1823bc153c63dc5d0bccab9fbf9e252a910a08a639e857bd9f8f0149"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:28"
  condition:
    hash.sha256(0, filesize) == "5f3709aa1823bc153c63dc5d0bccab9fbf9e252a910a08a639e857bd9f8f0149"
}
```

### Sample 9: `bebd8062fba5ab71`

| Field | Value |
|---|---|
| SHA-256 | `bebd8062fba5ab7163333480655f9027995ace5d4eee2bebab499d4c549923f3` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-08-05 02:50:28` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61505dbce5b8c81b8b3cd542e9547925` |
| SHA-1 | `8c039bf4a743b27477d07c2eb47dea2fa2b851ab` |
| SHA-256 | `bebd8062fba5ab7163333480655f9027995ace5d4eee2bebab499d4c549923f3` |
| SHA3-384 | `6b4cf8cc48f53948ebf2cc7f36b0e72bfc81d199b51e66f69b5e56c9b06906459b38595f353fef94bd4d07f872626fb6` |
| TLSH | `T1DE24C60AAF610FFBD8AFDD3746E90B0635CC650722A83B3A3674D924F54A54B49D3C68` |
| SSDEEP | `3072:P9/6gT7DbU28Mn0NawZ5aMBjv+7GYNRPO1:P9ND1f08wZ5Fj6GY3PO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_bebd8062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bebd8062fba5ab7163333480655f9027995ace5d4eee2bebab499d4c549923f3"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:28"
  condition:
    hash.sha256(0, filesize) == "bebd8062fba5ab7163333480655f9027995ace5d4eee2bebab499d4c549923f3"
}
```

### Sample 10: `41973e5dc419ef5d`

| Field | Value |
|---|---|
| SHA-256 | `41973e5dc419ef5d31ba3c0b984ae22d80dddd15d3bf65696e7e0c919134430f` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-08-05 02:50:27` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5edd133760ff0b66524654958b0f3614` |
| SHA-1 | `13ad2076c05702a776053ee9dbff2cca014ef1a9` |
| SHA-256 | `41973e5dc419ef5d31ba3c0b984ae22d80dddd15d3bf65696e7e0c919134430f` |
| SHA3-384 | `03f62bae331537fc14074cbb86ecbe34a4087370414f703e86c9d94e73f0723594acf2a59890702e00fd36291718d907` |
| TLSH | `T1E0F35B0274D0D4FEC8E5C2B84BEFE136DA32B4595274761F23C8AE262E5DF212B6D650` |
| TELFHASH | `t1f951de703ca63a5c61ebe726b30ae95dad750d600ce371f5dd7368eace023844da3062` |
| SSDEEP | `3072:wQUWH4VklB1Amd10qb8ODAhv4y1jFg+SVqKE:wZWfYOB25dfKE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_41973e5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41973e5dc419ef5d31ba3c0b984ae22d80dddd15d3bf65696e7e0c919134430f"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:27"
  condition:
    hash.sha256(0, filesize) == "41973e5dc419ef5d31ba3c0b984ae22d80dddd15d3bf65696e7e0c919134430f"
}
```

### Sample 11: `ca2af697388746b2`

| Field | Value |
|---|---|
| SHA-256 | `ca2af697388746b2381dc7c4e857ffcec86223ea4618de4583437380050d7770` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-08-05 02:50:27` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9243523b2111579b333d6741517e4069` |
| SHA-1 | `e8fbe93a2a71f28abbd5fab68d97a05e656ea172` |
| SHA-256 | `ca2af697388746b2381dc7c4e857ffcec86223ea4618de4583437380050d7770` |
| SHA3-384 | `e84a639bf39ef0a25ddbfbda3d8f429fdbc325af9b5ca1e21fefdbd9ed026a1494d7c0afa0bbcae0d9d7d33e1f792f55` |
| TLSH | `T155246BA8BA0F6C01F2C3D3F8DE8C87E13A1735E3C7768971791212EDDAA39D95990512` |
| SSDEEP | `3072:wwS1OScpwRz0maXCvz9P+HyC37HbKG9P9nKMhazboqN3y:LuOScKRz0mayvhPIyu7HWwnKbzboq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_ca2af697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca2af697388746b2381dc7c4e857ffcec86223ea4618de4583437380050d7770"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:27"
  condition:
    hash.sha256(0, filesize) == "ca2af697388746b2381dc7c4e857ffcec86223ea4618de4583437380050d7770"
}
```

### Sample 12: `563bcacf84a7c6e9`

| Field | Value |
|---|---|
| SHA-256 | `563bcacf84a7c6e900023f7970caaace95bf49c91f63f76c295d32a8f9cc55bf` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-05 02:43:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2964fa0f630463150faa4313bca1966f` |
| SHA-1 | `d45a66ddcc42faa5463f6f2b83e78397012a3d78` |
| SHA-256 | `563bcacf84a7c6e900023f7970caaace95bf49c91f63f76c295d32a8f9cc55bf` |
| SHA3-384 | `f83814de6605f442538b699dcbbd1038f430a0714efd337e074731ce7a270b5d49e89101b3bfb9cf77bf684fead25fa1` |
| TLSH | `T16DC27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:Y8vCB+25j6es8RY9FYpMSUpi+20qUpi+20YQX:Y8l25Jud2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_563bcacf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "563bcacf84a7c6e900023f7970caaace95bf49c91f63f76c295d32a8f9cc55bf"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-05 02:43:35"
  condition:
    hash.sha256(0, filesize) == "563bcacf84a7c6e900023f7970caaace95bf49c91f63f76c295d32a8f9cc55bf"
}
```

### Sample 13: `3b3bc398e71b2dad`

| Field | Value |
|---|---|
| SHA-256 | `3b3bc398e71b2dad7e7af96b0607b264e405f3af2ed453b251f3575a6e513fba` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-05 02:31:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38e1fd82d7e08a915a910ce78186f073` |
| SHA-1 | `1a8b0b7e6324279fbf409aecbf9a8d6950f12624` |
| SHA-256 | `3b3bc398e71b2dad7e7af96b0607b264e405f3af2ed453b251f3575a6e513fba` |
| SHA3-384 | `1b7d846dbdc32459800cf7997b7a317aa2ddc0cd9b7eba60d0ca96a2492953781febf8afdcee0c24fb781f4b8b695dc4` |
| TLSH | `T14FC27C966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:m8vCB+25j6es8RF9FYpMSUpi+20qUpi+20YQX:m8l25Jjd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_3b3bc398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b3bc398e71b2dad7e7af96b0607b264e405f3af2ed453b251f3575a6e513fba"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-05 02:31:50"
  condition:
    hash.sha256(0, filesize) == "3b3bc398e71b2dad7e7af96b0607b264e405f3af2ed453b251f3575a6e513fba"
}
```

### Sample 14: `2272cf84ed710394`

| Field | Value |
|---|---|
| SHA-256 | `2272cf84ed710394a08d70054cf2f54e96fd65af399e5addfcfdffe284266a56` |
| Family label | `unknown` |
| File name | `lterouter` |
| File type | `unknown` |
| First seen | `2026-08-05 02:19:44` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1bd9b2e7d6c48633c6dc7d211f768c9` |
| SHA-256 | `2272cf84ed710394a08d70054cf2f54e96fd65af399e5addfcfdffe284266a56` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_2272cf84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2272cf84ed710394a08d70054cf2f54e96fd65af399e5addfcfdffe284266a56"
    family = "unknown"
    file_name = "lterouter"
    file_type = "unknown"
    first_seen = "2026-08-05 02:19:44"
  condition:
    hash.sha256(0, filesize) == "2272cf84ed710394a08d70054cf2f54e96fd65af399e5addfcfdffe284266a56"
}
```

### Sample 15: `8c0495b2595aff42`

| Field | Value |
|---|---|
| SHA-256 | `8c0495b2595aff4244c1c157a3f2594f12275d776509a6b49224f357b88f4270` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-05 02:08:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0c4e39a002352b4a6344126a3f44ce0` |
| SHA-1 | `0d0311c204f5471f5ed5293116d6d4e4f3842044` |
| SHA-256 | `8c0495b2595aff4244c1c157a3f2594f12275d776509a6b49224f357b88f4270` |
| SHA3-384 | `43e21ace9df188b6d200cbbd85a44a8ade5cd7e48f275e3c4b62be2c0a608a78bb45da01724bad161b390129b6280e6d` |
| TLSH | `T146C3123A938CE892045AD9BF61AEBB18045FF8CCD098D6E6EF4D097ECD0032455ED791` |
| SSDEEP | `3072:3PjvN0zkW4C6ZjJAIXOfCUlYKlFyugtAtoutDN:3jN+kLPJdXS6Kf/LoSDN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_8c0495b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0495b2595aff4244c1c157a3f2594f12275d776509a6b49224f357b88f4270"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:20"
  condition:
    hash.sha256(0, filesize) == "8c0495b2595aff4244c1c157a3f2594f12275d776509a6b49224f357b88f4270"
}
```

### Sample 16: `9b1c0cb8ac770445`

| Field | Value |
|---|---|
| SHA-256 | `9b1c0cb8ac7704452f06292398a65ffe9b3c901329f93ac716d7486ed8798d94` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-05 02:08:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44d564b267fa8a53297a937a89309315` |
| SHA-1 | `1ab9d5072f8c6a1fae5163519a359614fd2447d9` |
| SHA-256 | `9b1c0cb8ac7704452f06292398a65ffe9b3c901329f93ac716d7486ed8798d94` |
| SHA3-384 | `93be48c039c52e13507191d5ab40b699e4bf14879536e37110ceeb0650bc6585c052f8a3e8d15d23f616a4a53eccbeb9` |
| TLSH | `T1F5D3125D6C333B59E865393678EE072ACE9110EE4B21877E8BFD494A206FD873906473` |
| SSDEEP | `3072:2lbKL83FTLLrdzvfO4+U6V7ya1viLBWITLWaV1LDMypzSAj:2BKm1zvf8V7D18BJTFTL3B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_9b1c0cb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1c0cb8ac7704452f06292398a65ffe9b3c901329f93ac716d7486ed8798d94"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:19"
  condition:
    hash.sha256(0, filesize) == "9b1c0cb8ac7704452f06292398a65ffe9b3c901329f93ac716d7486ed8798d94"
}
```

### Sample 17: `ab1b6934bc586d44`

| Field | Value |
|---|---|
| SHA-256 | `ab1b6934bc586d442ec14067cb8075b94f66e0981c41fb308758ba7949eaa437` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-05 02:08:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db7eede4f6d1c21472c98bf96cc58502` |
| SHA-1 | `6e7fddff494ca0be5191d02548b7aa771fd9bd97` |
| SHA-256 | `ab1b6934bc586d442ec14067cb8075b94f66e0981c41fb308758ba7949eaa437` |
| SHA3-384 | `a5f89ae63610d403451692e35f3b2ea060332ffa78ebf2d2fb137544c8c8683d848dcbdaa30d5224afeca8a80ba33845` |
| TLSH | `T172D3127FDA79083BD5399074A99A23A56E7D69F7B003F4562E4AC3224C70F2933532C6` |
| SSDEEP | `3072:R+kzsw8M5Ppwa3YT8htu9s4N3Bj5jVD869V0yJIjVM:RLzswL7Iutb4N3Bjh98TyJIRM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_ab1b6934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab1b6934bc586d442ec14067cb8075b94f66e0981c41fb308758ba7949eaa437"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:17"
  condition:
    hash.sha256(0, filesize) == "ab1b6934bc586d442ec14067cb8075b94f66e0981c41fb308758ba7949eaa437"
}
```

### Sample 18: `28b4e8084fd3eb35`

| Field | Value |
|---|---|
| SHA-256 | `28b4e8084fd3eb35aa0fcf362c87c43b7b380379643c209b40015e744f5df425` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-05 02:08:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0489fc28cfb85f9d9c91dadd6fc2ca2` |
| SHA-1 | `d4db10357add1bd38a8ac0a7491946c8a3b4fa57` |
| SHA-256 | `28b4e8084fd3eb35aa0fcf362c87c43b7b380379643c209b40015e744f5df425` |
| SHA3-384 | `e01c8925eb655506fb52f3c5bedc97fa13a1ad6bf03345f21071aa74b222882c6fe17385e616fa1d1b9dabe7e368f119` |
| TLSH | `T1D8B31263B9C01F9366B3AB65E801A00B53627D9490072F3DC669FF2D5193E9C09EE4D7` |
| SSDEEP | `3072:jGhGc30ZXifdC0e4ZJ+SZKeiIZZuKzDxWcxV7Z:K4c8XifdCB4D+UFJZZLDVZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_28b4e808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28b4e8084fd3eb35aa0fcf362c87c43b7b380379643c209b40015e744f5df425"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:15"
  condition:
    hash.sha256(0, filesize) == "28b4e8084fd3eb35aa0fcf362c87c43b7b380379643c209b40015e744f5df425"
}
```

### Sample 19: `5c72400083008275`

| Field | Value |
|---|---|
| SHA-256 | `5c724000830082753cdb5c57ae528b92350d9ff94bb0e935d17c04b9b41253ba` |
| Family label | `unknown` |
| File name | `tbk` |
| File type | `unknown` |
| First seen | `2026-08-05 02:08:13` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24cef98575e7a54fd5ec53671d0c715d` |
| SHA-256 | `5c724000830082753cdb5c57ae528b92350d9ff94bb0e935d17c04b9b41253ba` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_5c724000
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c724000830082753cdb5c57ae528b92350d9ff94bb0e935d17c04b9b41253ba"
    family = "unknown"
    file_name = "tbk"
    file_type = "unknown"
    first_seen = "2026-08-05 02:08:13"
  condition:
    hash.sha256(0, filesize) == "5c724000830082753cdb5c57ae528b92350d9ff94bb0e935d17c04b9b41253ba"
}
```

### Sample 20: `6db4914bfa06a112`

| Field | Value |
|---|---|
| SHA-256 | `6db4914bfa06a112892250974b42abde5c7a096050c970a1dcbb23172ff863f6` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-05 02:01:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ab45d0e17f3bece44ab60a1659104c5` |
| SHA-1 | `b78ae090d9f24269327d5f4dc50b46fe33d964f3` |
| SHA-256 | `6db4914bfa06a112892250974b42abde5c7a096050c970a1dcbb23172ff863f6` |
| SHA3-384 | `444f1d00cd9963085ac2fbdf3d0ebe2e46960ba4fed132e2af7ae0039375bf87aca20cb5ab3f12b1f6513944eb18807b` |
| TLSH | `T1763184EF13429A211554CE4BB271224D9700C1DF2E6BE7E8EE4C2D29B68E54C329DE4B` |
| SSDEEP | `24:i8919UWC7uut75OeHGtsHQuCBP7+yqT5BH:i8dwua75RGtsHQuCBP7tqbH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_6db4914b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db4914bfa06a112892250974b42abde5c7a096050c970a1dcbb23172ff863f6"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-05 02:01:52"
  condition:
    hash.sha256(0, filesize) == "6db4914bfa06a112892250974b42abde5c7a096050c970a1dcbb23172ff863f6"
}
```

### Sample 21: `a374f3ebc886eda1`

| Field | Value |
|---|---|
| SHA-256 | `a374f3ebc886eda122ca1229138b8a31ce0758addb60c0dd38052e5a95b3d37d` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-05 01:58:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bffbfc243a228af9ea95ccceb3e578c6` |
| SHA-1 | `6f7e5aa9716ac19035cb2a42edae24b6de44307d` |
| SHA-256 | `a374f3ebc886eda122ca1229138b8a31ce0758addb60c0dd38052e5a95b3d37d` |
| SHA3-384 | `c79f02b46013680236de09ac6d94ef29afda0562d5ba4c83a6a1c627302075b4161003d35e6eda4de85eae63a7f8595f` |
| TLSH | `T1EB01AFC9C400AC0090AA9E5D26E75554F810C3CF1A9A4FB9BF9C6D3EFB88D14B066F84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha1M1prF1fbnte53X:e9Qp+Mse1dF1fbnA53X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_a374f3eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a374f3ebc886eda122ca1229138b8a31ce0758addb60c0dd38052e5a95b3d37d"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-05 01:58:33"
  condition:
    hash.sha256(0, filesize) == "a374f3ebc886eda122ca1229138b8a31ce0758addb60c0dd38052e5a95b3d37d"
}
```

### Sample 22: `919e2a1a6d175590`

| Field | Value |
|---|---|
| SHA-256 | `919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769` |
| Family label | `Prometei` |
| File name | `919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769` |
| File type | `elf` |
| First seen | `2026-08-05 01:56:19` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `144bb5b02b3b6c4462c7468ac7740fa6` |
| SHA-1 | `c73a9de3ae9f0be76f04d6c3f88f62c4429866e6` |
| SHA-256 | `919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769` |
| SHA3-384 | `b095748126b085b0043e84aca6bf7dec28fc3d105459a124bcb7be9761b4619cfc11ab92cfd9eb6479c06d4d2299db5d` |
| TLSH | `T127A423B4F9219E9F6DD769B91B24831DE182C172689D4C1313AE94A34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdk:Fs6pyCC/Ya2hpi6T6N4a` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_022_919e2a1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769"
    family = "Prometei"
    file_name = "919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769"
    file_type = "elf"
    first_seen = "2026-08-05 01:56:19"
  condition:
    hash.sha256(0, filesize) == "919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769"
}
```

### Sample 23: `b6fcb33c4d6193b0`

| Field | Value |
|---|---|
| SHA-256 | `b6fcb33c4d6193b07bcb7c595ab6209e6a935f853ba73c07212b4a4c9eff5518` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-05 01:50:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0afc11d0fc849f09583286d35a9c5166` |
| SHA-1 | `6e8718f35839de1bdd1385495d3a4c217a614efd` |
| SHA-256 | `b6fcb33c4d6193b07bcb7c595ab6209e6a935f853ba73c07212b4a4c9eff5518` |
| SHA3-384 | `9f1d792f392df00ac4b86b53103a1e42f39f3e289216605d8d26e64fae49022ee6471153ede2fc512ad69392c4bca0d8` |
| TLSH | `T1D2D32B17B64148BDC4E1E0708B7BA962D738B0BD5231271F2B95AB721C92B691F1BBC1` |
| TELFHASH | `t16611ec0e7b2647ab7d9109a86fe147e68407409fd01d4bd5dfd4db96c039164fd008de` |
| SSDEEP | `1536:G1JUOHzadQU4WUrlHUCrX1T+f7ZD+FnzwMI1yPIlJT1Te7OkK3GnRdVgdZM3Nq:0JUMFBhZXhcQhTkxc0GnRdmPM3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_b6fcb33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6fcb33c4d6193b07bcb7c595ab6209e6a935f853ba73c07212b4a4c9eff5518"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-05 01:50:32"
  condition:
    hash.sha256(0, filesize) == "b6fcb33c4d6193b07bcb7c595ab6209e6a935f853ba73c07212b4a4c9eff5518"
}
```

### Sample 24: `3a6e532493b6e27a`

| Field | Value |
|---|---|
| SHA-256 | `3a6e532493b6e27a65591644109e2d2021d1ef4d7abae9e5f5c36244ed653d4d` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-05 01:36:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cb849c9254f28ad3a10fd3211a77217` |
| SHA-1 | `80ace9b8fd7fd44149d50c51e20379440c2cf56e` |
| SHA-256 | `3a6e532493b6e27a65591644109e2d2021d1ef4d7abae9e5f5c36244ed653d4d` |
| SHA3-384 | `dced079a9a5c258ae3dfb8797ed00828dba3be040da90710c1514b62c89e7e888241a6ef06177b629bc3db6760186344` |
| TLSH | `T1BB01ABCAD4609800909DD55C22EB2155FC31C3C7165B8F79BFACA93E9B94D05B067FD4` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaVjCoX2C3VbjCmXCeTIChzMBX:kXCKysE2hi0ziQvZohaVjxG0Z1h8U4X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_3a6e5324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a6e532493b6e27a65591644109e2d2021d1ef4d7abae9e5f5c36244ed653d4d"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-05 01:36:32"
  condition:
    hash.sha256(0, filesize) == "3a6e532493b6e27a65591644109e2d2021d1ef4d7abae9e5f5c36244ed653d4d"
}
```

### Sample 25: `367ea7e4e3abd64b`

| Field | Value |
|---|---|
| SHA-256 | `367ea7e4e3abd64b1d89c6d4ebc82bd42b9f2b56897b093c1f0f411303c28945` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-05 01:27:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f52e334be54ae6f28fb9f19fdf5f00fe` |
| SHA-1 | `5cadb5c016687aab7b39e42b91361feec5c5283c` |
| SHA-256 | `367ea7e4e3abd64b1d89c6d4ebc82bd42b9f2b56897b093c1f0f411303c28945` |
| SHA3-384 | `7e0a38d1274bce214d7606b564dc642ef4d17630062b76e0bd4eafe10c68db3961973a4bac72f7985de4eadc2a5f99ce` |
| TLSH | `T100236C6516857C14AE99C4365C7E2F0CB9AD43E6314492EE7FCE3CF28C4A6AD920871D` |
| SSDEEP | `768:w9r9NyXsZztCt9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:wFHusZTcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_367ea7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "367ea7e4e3abd64b1d89c6d4ebc82bd42b9f2b56897b093c1f0f411303c28945"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-05 01:27:46"
  condition:
    hash.sha256(0, filesize) == "367ea7e4e3abd64b1d89c6d4ebc82bd42b9f2b56897b093c1f0f411303c28945"
}
```

### Sample 26: `fc04a6d3555001a8`

| Field | Value |
|---|---|
| SHA-256 | `fc04a6d3555001a8f04cf75dcdc1cb2de12f530d78603c31aadea81fb26312a3` |
| Family label | `unknown` |
| File name | `MV ANNA SCHULTE VESSEL Q88 PARTICULARS.js` |
| File type | `js` |
| First seen | `2026-08-05 01:26:34` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84890ef65a2a0ec62b1115809928c71c` |
| SHA-1 | `2872bf0290f44efed82943bead3cd16eecd8ebe5` |
| SHA-256 | `fc04a6d3555001a8f04cf75dcdc1cb2de12f530d78603c31aadea81fb26312a3` |
| SHA3-384 | `9508e4adaeeffcf5aae6b7d7dc51ec83b0396a9560eb371b55e215837cb971e531d54429379f7d4ea6a720dc8408678d` |
| TLSH | `T1FEE50AD323CD798B5D59B7B6A64CF6040BBFE2620B8235D1A9CE0949872F0D7A5D08DC` |
| SSDEEP | `12288:krJDc94BmkFRIqvf2r5MaA6SVYvuQlhAyGkruQ2t5J9DDWh4dtU5VvbuNApECKNb:OJo+kPgCMVddkoux5c2oVt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_fc04a6d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc04a6d3555001a8f04cf75dcdc1cb2de12f530d78603c31aadea81fb26312a3"
    family = "unknown"
    file_name = "MV ANNA SCHULTE VESSEL Q88 PARTICULARS.js"
    file_type = "js"
    first_seen = "2026-08-05 01:26:34"
  condition:
    hash.sha256(0, filesize) == "fc04a6d3555001a8f04cf75dcdc1cb2de12f530d78603c31aadea81fb26312a3"
}
```

### Sample 27: `ba584221459b0f1a`

| Field | Value |
|---|---|
| SHA-256 | `ba584221459b0f1a6359864f3addeca070259f707eb402f26e945565eb25852d` |
| Family label | `Mirai` |
| File name | `main.mipsel` |
| File type | `elf` |
| First seen | `2026-08-05 01:12:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91ae10d8443e8f48845bb727384b86ea` |
| SHA-1 | `64e5595ca9f9ac33dcdc4875ea49b742dc2a0068` |
| SHA-256 | `ba584221459b0f1a6359864f3addeca070259f707eb402f26e945565eb25852d` |
| SHA3-384 | `0a3c3d43b5b1731b0ab86f5edab0a16d4fb84920f9fc17eb79f5baef9e533f4108ba9904fe62bd009afd3f40f42551e4` |
| TLSH | `T1AB43641AAF629E77D81FDD7301E8850120CDB49762AA2B2F7170CA6CF75B98B05D3C94` |
| SSDEEP | `1536:ug0e5e+NsG6JEFClpbGUoK88Jzny4Dy1rtrZg61VsVfDA:uze5eosG6quNGUoRrZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_ba584221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba584221459b0f1a6359864f3addeca070259f707eb402f26e945565eb25852d"
    family = "Mirai"
    file_name = "main.mipsel"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:51"
  condition:
    hash.sha256(0, filesize) == "ba584221459b0f1a6359864f3addeca070259f707eb402f26e945565eb25852d"
}
```

### Sample 28: `0eda0c619807b5d9`

| Field | Value |
|---|---|
| SHA-256 | `0eda0c619807b5d9f641b253338fbc9574a31d7573b979d4dc63dec16bc29399` |
| Family label | `Mirai` |
| File name | `main.x86_64` |
| File type | `elf` |
| First seen | `2026-08-05 01:12:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48554c3a4f4c2d0d88f1edfe848fab18` |
| SHA-1 | `5eb24958eb9b79442a2e09eafa64347c5c7937cd` |
| SHA-256 | `0eda0c619807b5d9f641b253338fbc9574a31d7573b979d4dc63dec16bc29399` |
| SHA3-384 | `57a5fd13b378eb913b701300d41050d09655eab49042fa34c9778a018406a1512e29764ff73612bb89482e435ab03876` |
| TLSH | `T1CA03E827F6618C2FC44BD2B19BDFA6219623B8792331600F9394FF615E4D5C4EE9A243` |
| TELFHASH | `t14311b2b07a493dd172cbf826b35af1b6cd390c3612a236e6c9b1b5f5c720fd06942861` |
| SSDEEP | `768:BgE/rbqhuPDSH9+7ZI1KgBolcb6mVKuLbfwOSsau7:i0rbq2+d+211oAVnTwOSsau` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_0eda0c61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eda0c619807b5d9f641b253338fbc9574a31d7573b979d4dc63dec16bc29399"
    family = "Mirai"
    file_name = "main.x86_64"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:49"
  condition:
    hash.sha256(0, filesize) == "0eda0c619807b5d9f641b253338fbc9574a31d7573b979d4dc63dec16bc29399"
}
```

### Sample 29: `c8f50aebfc5cf950`

| Field | Value |
|---|---|
| SHA-256 | `c8f50aebfc5cf9506e58593afcee45d98aa2a1e142644aabf316e46c61374f95` |
| Family label | `unknown` |
| File name | `main.mips` |
| File type | `elf` |
| First seen | `2026-08-05 01:12:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44bc46927e58e76510e5664a8388169b` |
| SHA-1 | `e2a8359373366989656754cc4931cdf859ff60bf` |
| SHA-256 | `c8f50aebfc5cf9506e58593afcee45d98aa2a1e142644aabf316e46c61374f95` |
| SHA3-384 | `dab74383a4c34cc2e092ee9c58e697f4bc09dfaa84f9f7301969129e3b236ae66a4487da093308503c0fed62d6e1adfc` |
| TLSH | `T15343442A2A21AFFEF56E823047F39E70D75535E226E0C284E26CCB185F7028D585F795` |
| TELFHASH | `t1be017c58583417f193894dde77edff34e4a140df89262f3b8d50ecea9621a468c00c2c` |
| SSDEEP | `1536:bYRYD6yh6HEMrBp5r5gEZNe19q057gxsE+BHcTT:l5Ck0T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_c8f50aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8f50aebfc5cf9506e58593afcee45d98aa2a1e142644aabf316e46c61374f95"
    family = "unknown"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:48"
  condition:
    hash.sha256(0, filesize) == "c8f50aebfc5cf9506e58593afcee45d98aa2a1e142644aabf316e46c61374f95"
}
```

### Sample 30: `93fd29a33fb0d14b`

| Field | Value |
|---|---|
| SHA-256 | `93fd29a33fb0d14b9b55b6b8cbbfab61bae8dcc14745d03ec7138207cc84b9ad` |
| Family label | `unknown` |
| File name | `run.sh` |
| File type | `sh` |
| First seen | `2026-08-05 01:12:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b40c59005833724c2010b8965a13362` |
| SHA-1 | `1bfea71935971131204f626dd3ea92e34b65244c` |
| SHA-256 | `93fd29a33fb0d14b9b55b6b8cbbfab61bae8dcc14745d03ec7138207cc84b9ad` |
| SHA3-384 | `1b0ca13333af9efa7f2ec470da71cfb9660d35df7291892fee0e0f6772968f988f412aa74b71910fe0c13a46a0414bf6` |
| TLSH | `T17D212BB090905449DD24E44938FA040872259AA261717F05BC9C2EFBEEDB9A4F53F7BE` |
| SSDEEP | `24:h0XZH9SJBCPi9NWxuWctYJl8YJltuLoGE:ENfi9N0uWctYX8YXwLov` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_93fd29a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93fd29a33fb0d14b9b55b6b8cbbfab61bae8dcc14745d03ec7138207cc84b9ad"
    family = "unknown"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-08-05 01:12:46"
  condition:
    hash.sha256(0, filesize) == "93fd29a33fb0d14b9b55b6b8cbbfab61bae8dcc14745d03ec7138207cc84b9ad"
}
```

### Sample 31: `ae2a66ca651b5741`

| Field | Value |
|---|---|
| SHA-256 | `ae2a66ca651b574132c6d29b0bcb714bc2b2855d52f139fcd4d03e1e5d3c12ea` |
| Family label | `unknown` |
| File name | `main.armv4` |
| File type | `elf` |
| First seen | `2026-08-05 01:12:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca759b42d58ca63e704a66d6ab213bfe` |
| SHA-1 | `ac3b2442d0b52192a9bbc6cbc6212d6157023de9` |
| SHA-256 | `ae2a66ca651b574132c6d29b0bcb714bc2b2855d52f139fcd4d03e1e5d3c12ea` |
| SHA3-384 | `bbc345b59ea4470671abe02b20846244085c125c14b1083a38b1b266c06abca1e70322786db2c7d458f373b860b5a669` |
| TLSH | `T1DF03E943FA5D8B07C19271B7F75E429E3A2E6D79A3F932119830AFD023C65F11939226` |
| TELFHASH | `t1d70189200d58dccc7298901de9ef85268b2870fa36bf245139bbe88d9e53cf190308ad` |
| SSDEEP | `768:IcI1ft8nn69IO8edPqUsoIUJFL3dqIQNTKEUOfB27:7I1ftey8eVlso1FrdqTn527` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_ae2a66ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2a66ca651b574132c6d29b0bcb714bc2b2855d52f139fcd4d03e1e5d3c12ea"
    family = "unknown"
    file_name = "main.armv4"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:44"
  condition:
    hash.sha256(0, filesize) == "ae2a66ca651b574132c6d29b0bcb714bc2b2855d52f139fcd4d03e1e5d3c12ea"
}
```

### Sample 32: `808c6fdb337af1c2`

| Field | Value |
|---|---|
| SHA-256 | `808c6fdb337af1c24a141b3a2a1006041575d0bfe260b055a70d003c3806eac6` |
| Family label | `Mirai` |
| File name | `main.armv6` |
| File type | `elf` |
| First seen | `2026-08-05 01:12:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f659ddc4c4aae7b0fc6fb8428e1063b` |
| SHA-1 | `df2c71afb9d7e020888a551497f8a6dab453bcdc` |
| SHA-256 | `808c6fdb337af1c24a141b3a2a1006041575d0bfe260b055a70d003c3806eac6` |
| SHA3-384 | `207c82edc84ece1c9eca51d871e10468b63df30ef46687f50a1501462aa7e3d244349bd3bec54366a281219f80b455e0` |
| TLSH | `T17B030A42E651DB06C59272BAFB8E014E37176F68F7EE32359E306FE013825E70939925` |
| SSDEEP | `768:x5nOr0lyUZ0AbzaFj2cR9D7mRQ4MSiPiyyvFyj7YrTfaKVE/2/:x5nOr0lz0AbzySc72tM9iyyvgnYrK2/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_808c6fdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "808c6fdb337af1c24a141b3a2a1006041575d0bfe260b055a70d003c3806eac6"
    family = "Mirai"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:43"
  condition:
    hash.sha256(0, filesize) == "808c6fdb337af1c24a141b3a2a1006041575d0bfe260b055a70d003c3806eac6"
}
```

### Sample 33: `2fa9fb858fac4b50`

| Field | Value |
|---|---|
| SHA-256 | `2fa9fb858fac4b501006e2f787e0af1ebd591be08ad08f86eb97348329bca3c7` |
| Family label | `Mirai` |
| File name | `main.armv5` |
| File type | `elf` |
| First seen | `2026-08-05 01:12:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fb74a718a3b9ae9e97b5ef8bec2a587` |
| SHA-1 | `7b07e674b9651e6a98181fb3135405629c2ac7b0` |
| SHA-256 | `2fa9fb858fac4b501006e2f787e0af1ebd591be08ad08f86eb97348329bca3c7` |
| SHA3-384 | `5ac3956296663b2fc8a5463c663d649668120bafbe8bee16c51b22aae37340d7837c14f6efe0d999d82c2830135eece9` |
| TLSH | `T142031A42E651DB06C59272BAFB8E014E37176F68F7EE32359E306FE013825E70939925` |
| SSDEEP | `768:x5nOr0lyUZ0AbzaFj2cR9D7mRQ4MSiPiyyvFyj7YrTfaKVE/T/:x5nOr0lz0AbzySc72tM9iyyvgnYrKT/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_2fa9fb85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fa9fb858fac4b501006e2f787e0af1ebd591be08ad08f86eb97348329bca3c7"
    family = "Mirai"
    file_name = "main.armv5"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:41"
  condition:
    hash.sha256(0, filesize) == "2fa9fb858fac4b501006e2f787e0af1ebd591be08ad08f86eb97348329bca3c7"
}
```

### Sample 34: `a1364a57e9114843`

| Field | Value |
|---|---|
| SHA-256 | `a1364a57e9114843e6a6707b196d5b824d48737abb66d6f3621215b6b0ebfecc` |
| Family label | `Mirai` |
| File name | `d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6` |
| File type | `elf` |
| First seen | `2026-08-05 01:01:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a5a3a3e3b119acc87697c4d482d7fd5` |
| SHA-1 | `5bc9caa11427abb1a0e04b709075c397ec666f5e` |
| SHA-256 | `a1364a57e9114843e6a6707b196d5b824d48737abb66d6f3621215b6b0ebfecc` |
| SHA3-384 | `2bb08bf76fae66060787d8f14769914cb30f19f3d4e6bec3a30432f945aeca92530f9ef91200bdba901e9716bc3807a5` |
| TLSH | `T145935BD4E643D8F5EC63053621B7FB3B9E72F5BD2128DA43C3A49676A823541C40AA7C` |
| TELFHASH | `t15b31d5f9177a0ced6bc06942b21e2f31bc0d6a7b417066e601f35978266fe4152bad3c` |
| SSDEEP | `1536:WzF5mW9HVGK8nO3x3gXJP7TIbzGdHFvqZQcxrrwxFy/vZyt:s51VL3g5TTIvG1FWQeYFHt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_a1364a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1364a57e9114843e6a6707b196d5b824d48737abb66d6f3621215b6b0ebfecc"
    family = "Mirai"
    file_name = "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
    file_type = "elf"
    first_seen = "2026-08-05 01:01:49"
  condition:
    hash.sha256(0, filesize) == "a1364a57e9114843e6a6707b196d5b824d48737abb66d6f3621215b6b0ebfecc"
}
```

### Sample 35: `053076456278fcab`

| Field | Value |
|---|---|
| SHA-256 | `053076456278fcab8a1820126d590986170a08754eb301dbaff9b8184bedc2fb` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-05 01:00:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50ddff0b1f7eeb59e02d8529abef038a` |
| SHA-1 | `140aea5ae9b428f585992d9d7eec25cfaea620f8` |
| SHA-256 | `053076456278fcab8a1820126d590986170a08754eb301dbaff9b8184bedc2fb` |
| SHA3-384 | `db7b41a1db2a7276bf16aef7c8f413d3ce5d46f40caf29f1c7660cfb96e5665a358d914294b35a244c4ec511ce3ded09` |
| TLSH | `T12C014CD98550AD1090699A5966E75290F410C3CF0A9A0BB87FDC593DFB88914B026F94` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha1M1pN6gP1ffntk57N7:e9Qp+Mse16gP1ffnO57N7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_05307645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "053076456278fcab8a1820126d590986170a08754eb301dbaff9b8184bedc2fb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-05 01:00:43"
  condition:
    hash.sha256(0, filesize) == "053076456278fcab8a1820126d590986170a08754eb301dbaff9b8184bedc2fb"
}
```

### Sample 36: `d8602f06298cba1a`

| Field | Value |
|---|---|
| SHA-256 | `d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6` |
| Family label | `Mirai` |
| File name | `d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6` |
| File type | `elf` |
| First seen | `2026-08-05 01:00:26` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a05f5ffbe4f0d7ef69a0aaea19444e0` |
| SHA-1 | `0e7f3696f835455a0e849763983ede60127e0509` |
| SHA-256 | `d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6` |
| SHA3-384 | `6166525a74282969d6916607c72646fc6c30475200a6d12161f9aa915319e7fdc9dcb0a4854a312619fff193404f2533` |
| TLSH | `T1EF1302D222DC8DA0C61D15FE128D776E116CE6EAECD2D8ED49C001659CA0F593D60BF6` |
| SSDEEP | `768:Pp9i4h0726dzuhnvpaaJ/dXNs5VINsio7Fd/N1H/zwnbcuyD7UHQRjqg:Pvi4h07shnhjJ/dB+ioRdFynouy8HyR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_d8602f06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
    family = "Mirai"
    file_name = "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
    file_type = "elf"
    first_seen = "2026-08-05 01:00:26"
  condition:
    hash.sha256(0, filesize) == "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
}
```

### Sample 37: `3a09f7e85184a22d`

| Field | Value |
|---|---|
| SHA-256 | `3a09f7e85184a22da474d5fba72c2bed3afb2423e139b7973897067264f7bdc6` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-05 00:57:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6df6013b68ad0921b72c4480d4ede5bf` |
| SHA-1 | `566ba581c73e8684ba66b59f218a1ea2a2cbebf7` |
| SHA-256 | `3a09f7e85184a22da474d5fba72c2bed3afb2423e139b7973897067264f7bdc6` |
| SHA3-384 | `055246ae748f380f6d8c3883d3665e5773f2692ab4dd7ed089d88c3eba993788fe837b69537862c7f5db43c809d21b44` |
| TLSH | `T140235C512A857C14AA99C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AA9DA10971D` |
| SSDEEP | `768:HJFWzZx569GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:pkzZcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_3a09f7e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a09f7e85184a22da474d5fba72c2bed3afb2423e139b7973897067264f7bdc6"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-05 00:57:37"
  condition:
    hash.sha256(0, filesize) == "3a09f7e85184a22da474d5fba72c2bed3afb2423e139b7973897067264f7bdc6"
}
```

### Sample 38: `c1dfc650c67b98f8`

| Field | Value |
|---|---|
| SHA-256 | `c1dfc650c67b98f8f51ca35bc8583fe4454f6f3c4e6263f1dbead0e969ea463a` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-08-05 00:57:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0812e42b716d16ab61212f9d0314c6c` |
| SHA-1 | `3c46b6d6aa8db2eecc2eda0101bff342d00ef0e4` |
| SHA-256 | `c1dfc650c67b98f8f51ca35bc8583fe4454f6f3c4e6263f1dbead0e969ea463a` |
| SHA3-384 | `be148f959ec5ee8cb3d52f95f4dd7d06e03c6c0f246943fc001baf3b14adcc98db46e4da57b4dbc85daf23696a4e5be6` |
| TLSH | `T1DEC3180BB55249BCC1F1C1309B7BE225DB30709DA631375F6B946B362C56FA81F29B90` |
| TELFHASH | `t1c8110a0e7b2a47abbd9149a86fe447e68807415f904d8bd5dfd4cb96c039164fe008de` |
| SSDEEP | `1536:ElCfgX8NVZIMaauGKzKJhtzrRcgHmz9f/UQxv/sQ57O8nxheSgwgd:ElCFNw1stztN+XUajRCSKd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_c1dfc650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1dfc650c67b98f8f51ca35bc8583fe4454f6f3c4e6263f1dbead0e969ea463a"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-05 00:57:36"
  condition:
    hash.sha256(0, filesize) == "c1dfc650c67b98f8f51ca35bc8583fe4454f6f3c4e6263f1dbead0e969ea463a"
}
```

### Sample 39: `5c5e89bf5b0ecf61`

| Field | Value |
|---|---|
| SHA-256 | `5c5e89bf5b0ecf61e19bcd0f50f4edcba6b256c8862b4ee8f5efa1c416956c00` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-05 00:54:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec6f8d8d8cb60fd3e8e91c9a744f4214` |
| SHA-1 | `b5b335233d8531386148b0ff25f0f26d5c94e154` |
| SHA-256 | `5c5e89bf5b0ecf61e19bcd0f50f4edcba6b256c8862b4ee8f5efa1c416956c00` |
| SHA3-384 | `e269f6824d711a205b21d541b28f9c3d1d3fdba0ee6e8823e85842c6a744555a5e7d284fc01793360bd76e20246ac61c` |
| TLSH | `T1CB01ABC6D560A500905DD91E62EB52A0B821C3C7465B0F787FDC993DAB98D05B0A7FD8` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaVjCoT2C3+sbjC4XCefIChzMbauD:kXCKysE2hi0ziQvZohaVjxC0+s5hgUU7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_5c5e89bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5e89bf5b0ecf61e19bcd0f50f4edcba6b256c8862b4ee8f5efa1c416956c00"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-05 00:54:35"
  condition:
    hash.sha256(0, filesize) == "5c5e89bf5b0ecf61e19bcd0f50f4edcba6b256c8862b4ee8f5efa1c416956c00"
}
```

### Sample 40: `8bf367564afbbc28`

| Field | Value |
|---|---|
| SHA-256 | `8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b` |
| Family label | `Gh0stRAT` |
| File name | `rLobO7.exe` |
| File type | `exe` |
| First seen | `2026-08-05 00:48:47` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0st, Gh0stRAT, SilverFox` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3c9d1993a05188c4bce23a34aa1d549` |
| SHA-1 | `e71485853edf523fe5a5fb1d6e3b543b65feb652` |
| SHA-256 | `8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b` |
| SHA3-384 | `eb7b890bf52fc07d687f989a928242b677f59a373ce613b7396f56c328f03aeb27529ab98a7a0f3a77f90d28eedec4be` |
| IMPHASH | `d9022e87b984803cdab2208819b430c2` |
| TLSH | `T110271223F38D653FD05B3E3D663792A4987B76602D128C57A6FC2A8C4F391801E2A757` |
| SSDEEP | `393216:mCyLpUDY1B6aZsxSzbNbgbRi1mrZeaACA8Mf0SiNJzgbWA:MGD4NIoA414enP40iA` |
| ICON-DHASH | `4c0f2bcccc692317` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_040_8bf36756
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b"
    family = "Gh0stRAT"
    file_name = "rLobO7.exe"
    file_type = "exe"
    first_seen = "2026-08-05 00:48:47"
  condition:
    hash.sha256(0, filesize) == "8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b"
}
```

### Sample 41: `951c35be1ee761f7`

| Field | Value |
|---|---|
| SHA-256 | `951c35be1ee761f7ba5c95ac29d4bd5b623b62d947276133bca63871844dbf63` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.GenericKD.81024962.25068.1356` |
| File type | `exe` |
| First seen | `2026-08-05 00:34:56` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `004a9b30d096ea79f8350e4013fd0e38` |
| SHA-1 | `8e1bdae4753611c5ccab2a3e6e0d9f51ab9eaf15` |
| SHA-256 | `951c35be1ee761f7ba5c95ac29d4bd5b623b62d947276133bca63871844dbf63` |
| SHA3-384 | `0146aab9865e70b3702aad8bf1e5af53de330c6a79bf3a9c8edb4db9cefb08a4d6607640a480dd4c1bd69b2da8b735bf` |
| IMPHASH | `de85a398477c39117ee5fd3f2278b959` |
| TLSH | `T18FA5C0C3EAF289DCC1638C3C5AADA113E136390D865C477BFB9D29503F2578AB464B19` |
| SSDEEP | `49152:HXAbqCrvUt2o428iiUv+vQSsy18RNajVEtAtReHO+geiHieXD7d:vnTDJFCl` |
| ICON-DHASH | `f0f06969697196cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_951c35be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "951c35be1ee761f7ba5c95ac29d4bd5b623b62d947276133bca63871844dbf63"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.GenericKD.81024962.25068.1356"
    file_type = "exe"
    first_seen = "2026-08-05 00:34:56"
  condition:
    hash.sha256(0, filesize) == "951c35be1ee761f7ba5c95ac29d4bd5b623b62d947276133bca63871844dbf63"
}
```

### Sample 42: `c6d4209d7086ece3`

| Field | Value |
|---|---|
| SHA-256 | `c6d4209d7086ece3833d2c655e1fa281881515c487733205ace2fc9452b91a1f` |
| Family label | `unknown` |
| File name | `voxfix.exe` |
| File type | `exe` |
| First seen | `2026-08-05 00:16:13` |
| Reporter | `Flechaa` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b48594fa63f56bf074801dac09d57275` |
| SHA-1 | `c5ea7df65dfccb856b51e8a3827bb325bc965b4e` |
| SHA-256 | `c6d4209d7086ece3833d2c655e1fa281881515c487733205ace2fc9452b91a1f` |
| SHA3-384 | `59f2106e91084f859bc6fe68c9649c1625112455db59e1824bca21db759fceb1c8ee14a521477a24bbce1302c85e6ce5` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1D3E733000B0FC1B1D145E2F6DB8BAD4A982EFBCB92D8571A1BDE54B26256CF59C73231` |
| SSDEEP | `1572864:BzFaNokS5i00u3mCgBjcxceYcyr8U57IoMTXnIjj7:BzFuS5i8kjc6eQjM7E7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_c6d4209d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6d4209d7086ece3833d2c655e1fa281881515c487733205ace2fc9452b91a1f"
    family = "unknown"
    file_name = "voxfix.exe"
    file_type = "exe"
    first_seen = "2026-08-05 00:16:13"
  condition:
    hash.sha256(0, filesize) == "c6d4209d7086ece3833d2c655e1fa281881515c487733205ace2fc9452b91a1f"
}
```

### Sample 43: `ff7556135cf2beee`

| Field | Value |
|---|---|
| SHA-256 | `ff7556135cf2beee8e4b110a3563ea6deb5d86a92580eaa38398dc092e0b98dd` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-08-04 23:53:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ef55ba50a6cd390e5b49aa4c0db58bf` |
| SHA-1 | `6322fe64294971dda3aaa047b63bc457293c472a` |
| SHA-256 | `ff7556135cf2beee8e4b110a3563ea6deb5d86a92580eaa38398dc092e0b98dd` |
| SHA3-384 | `ec6998ae08dd1ed70c7f15e609681311a910de730f6c66c5738d5d93d4d9bee514240af7cb591e2e7373f17d5e50c348` |
| TLSH | `T17F632A91BC819B13C6D512BBFB6E028D372613A8D2EF72039D266F21378785B0E77651` |
| TELFHASH | `t10231dcb58e4c0fc87bb0db5487ce723ab1d836b9ab112135ce1b6f5b0613680761e836` |
| SSDEEP | `1536:tLk15ADO50HaK9sFNsSF6GInq9LRq89qLvQa:tLkwDSNso6GbREn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_ff755613
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff7556135cf2beee8e4b110a3563ea6deb5d86a92580eaa38398dc092e0b98dd"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-04 23:53:14"
  condition:
    hash.sha256(0, filesize) == "ff7556135cf2beee8e4b110a3563ea6deb5d86a92580eaa38398dc092e0b98dd"
}
```

### Sample 44: `e1bcd3ef29771dcc`

| Field | Value |
|---|---|
| SHA-256 | `e1bcd3ef29771dcce576f910c9dd9fabed482ed5a03a11aa1617bb2a029daa72` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-04 23:53:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8474af411a1a61b4fa91f2c79172bc3` |
| SHA-1 | `55e640994c53312388c1fb6ea8960b2dd93af1e6` |
| SHA-256 | `e1bcd3ef29771dcce576f910c9dd9fabed482ed5a03a11aa1617bb2a029daa72` |
| SHA3-384 | `a4f42d43dc90650e768d4f6143a6da5b37c1d9a878f07b2dd2f0f07eeba67ce5ac8b4b7cff0718fa3d3fdac98532167c` |
| TLSH | `T163731995B8818B22C5D512BEFE1E118E3313177CE3DE73229D206F24778696B0E7B916` |
| TELFHASH | `t1d301f1241acd4eac5fe0c52e876f4313391831b54c236a658d7f259f23129d23495039` |
| SSDEEP | `1536:DAnQq6+9bDfANnVfmw39hVUZJacs+kQLMGiA09k3Uw7+75gYsP:oZDfaVPjVUZJac509k3UwC7Op` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_e1bcd3ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1bcd3ef29771dcce576f910c9dd9fabed482ed5a03a11aa1617bb2a029daa72"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-04 23:53:08"
  condition:
    hash.sha256(0, filesize) == "e1bcd3ef29771dcce576f910c9dd9fabed482ed5a03a11aa1617bb2a029daa72"
}
```

### Sample 45: `331e955b58409993`

| Field | Value |
|---|---|
| SHA-256 | `331e955b58409993cb50593b0314666dcd35afd38edf4ebc9dbdd272fc595137` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d7aba9d21e3793a6f8b9c94b0367577` |
| SHA-1 | `0e0c614909aba3cf85899de4dcd35ebf5eb03d58` |
| SHA-256 | `331e955b58409993cb50593b0314666dcd35afd38edf4ebc9dbdd272fc595137` |
| SHA3-384 | `97993d89e7d9b5bd74edf3481aa17d9582c2936287d9228c40c32f433daf33e777e9fe469b12103a1d68cedc99c048ce` |
| TLSH | `T1D8435BC1A68BD4F4EE6605F41177E3734732F839112DCAC7D3299932B952610EA9B39C` |
| TELFHASH | `t11d3124eb5eaa09fcb7d07d08c31b2b571976d573057072b840b29ca422f2dd19136c3a` |
| SSDEEP | `1536:RcYAsMflv2PNc79uESIcE5LHzTn1EF9/p9tAI+lv/uF+:Rcx9flv2PQDtconO9B9KTlf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_331e955b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "331e955b58409993cb50593b0314666dcd35afd38edf4ebc9dbdd272fc595137"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:59"
  condition:
    hash.sha256(0, filesize) == "331e955b58409993cb50593b0314666dcd35afd38edf4ebc9dbdd272fc595137"
}
```

### Sample 46: `3b89db05cd1e6283`

| Field | Value |
|---|---|
| SHA-256 | `3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `029ca0976c75731261cd1fe5b696ddf6` |
| SHA-1 | `936be0cc7707ad40d4950f058d0bc04a73cc74cb` |
| SHA-256 | `3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5` |
| SHA3-384 | `6e300bdfeb0665083aa1186f469862c59358114007d03ccc24becf5f1973224677c0d11d0857391278c77509f81d9d16` |
| TLSH | `T10A93C81E6E218FBDF768873147B78A21A39C33D627E1D685E25CD6001F6124E641FFA8` |
| TELFHASH | `t1dc115b4c4a3813e49b711d9d2badef73e19130ef0a256d338e10b99daa6d9825e00c1c` |
| SSDEEP | `1536:8vaRljjJToLe2iiMLOke/1vkeCOiuWcu1c:FRljFToiCMLpe/hVW31c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_3b89db05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:56"
  condition:
    hash.sha256(0, filesize) == "3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5"
}
```

### Sample 47: `a6d7e53827923e4e`

| Field | Value |
|---|---|
| SHA-256 | `a6d7e53827923e4ef5ad75738d9f972d070436669e3f8898041d11dad4311d64` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba786fcc12a5defaffc96001e3310c51` |
| SHA-1 | `2630533673431c290d945c973a0c5d0b3bd55145` |
| SHA-256 | `a6d7e53827923e4ef5ad75738d9f972d070436669e3f8898041d11dad4311d64` |
| SHA3-384 | `dab62afdb8d1d604eea105ff0b0f9da207fd60b39d3a0c20e190c47b0d86737cac56846d0e71e24e338018ca31635967` |
| TLSH | `T1F2F20881B9925A27C1E423BAAA7F618E333173A8D2DF7757D8111F10BB8981F4D63B41` |
| TELFHASH | `t1e4e05504be668e0998e79ab0ccbd07a4e802121391a65b20cf12cbe0883f448e308d2e` |
| SSDEEP | `768:ty/DUyXeYUqiAzF68zF2rL+8T8SEG3mX39IZnM07:tCXBUrAmL+fG4WZD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_a6d7e538
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6d7e53827923e4ef5ad75738d9f972d070436669e3f8898041d11dad4311d64"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:54"
  condition:
    hash.sha256(0, filesize) == "a6d7e53827923e4ef5ad75738d9f972d070436669e3f8898041d11dad4311d64"
}
```

### Sample 48: `573f7e484d4c9657`

| Field | Value |
|---|---|
| SHA-256 | `573f7e484d4c9657434581cce579a623a1cf3e65acb910d908a87d3d6681dcea` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1da6fff71eb28185fe6b09a436227661` |
| SHA-1 | `2c0073291a2f828fa3cdf3792c1ce134f18f8f88` |
| SHA-256 | `573f7e484d4c9657434581cce579a623a1cf3e65acb910d908a87d3d6681dcea` |
| SHA3-384 | `6a0eceff82e7e0ae01ea75860197ae9d996131e04891af0a51c9cebc169d15531b4cd00c027915b3d9ae388a14679604` |
| TLSH | `T15293E706BB650FFBDCAFCD3706A9170525CC551A52B93B3A3634C928F64B21B4AE3C64` |
| SSDEEP | `1536:Fi9M4jBIagVLZzdGBFSoITdb5UCYlBMxAZmjyXs9BGhYLqO0K:FWMoSagVNpUY3YlBIAUiLO7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_573f7e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "573f7e484d4c9657434581cce579a623a1cf3e65acb910d908a87d3d6681dcea"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:52"
  condition:
    hash.sha256(0, filesize) == "573f7e484d4c9657434581cce579a623a1cf3e65acb910d908a87d3d6681dcea"
}
```

### Sample 49: `ceef74efa11e4416`

| Field | Value |
|---|---|
| SHA-256 | `ceef74efa11e441698207a000466abc3048d4144feb2be779e44a498a8dfc54a` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d57234d2ec566f15a20c88780977b38` |
| SHA-1 | `7a1e0e7ef3eaa16460a66186e26e376f7863b1c0` |
| SHA-256 | `ceef74efa11e441698207a000466abc3048d4144feb2be779e44a498a8dfc54a` |
| SHA3-384 | `5c8d4f46c1f972b61d3218e17b4fe06342ad5dfb0645a4fce1611a0d975196340fe7022ab244345f63d6bdffb90fe192` |
| TLSH | `T1C0E33B46E7414A13C4D61779BAEF42453323AB64D3EB73059928BFB43F867AE0E23605` |
| TELFHASH | `t1c421fe31572141196a52cc60dcee47f1252c8b172744ef33cf36c4cc641a09ae62bc4f` |
| SSDEEP | `3072:RYj3Oxbj4Bafybkeb2fwU7l4/NvModnk3JpxM/9bo7:RYj3O+BafybkebQwY4/ZMmk3J3M/9bo7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_ceef74ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceef74efa11e441698207a000466abc3048d4144feb2be779e44a498a8dfc54a"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:49"
  condition:
    hash.sha256(0, filesize) == "ceef74efa11e441698207a000466abc3048d4144feb2be779e44a498a8dfc54a"
}
```

### Sample 50: `f76f596286a2b1e0`

| Field | Value |
|---|---|
| SHA-256 | `f76f596286a2b1e0686b9b7e7ca1eb18ab462ccf3b4c5dbef6c09f7ddc593272` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c957533603cfcc1f559bc3a3199ddb12` |
| SHA-1 | `a2af92a0b43f4d308453cd64bec0db586a1c6743` |
| SHA-256 | `f76f596286a2b1e0686b9b7e7ca1eb18ab462ccf3b4c5dbef6c09f7ddc593272` |
| SHA3-384 | `42fb4605bbfc6b5baaf443eace99d8769c3ffe120ee97ce7a6770bf66509cf1f46be7a06ccefd2dea02a56e850e08b00` |
| TLSH | `T190E2E07298839A52D3E0083CDA689EC6B59D39B5E2F87B8154504BF0EA55008D3773C7` |
| SSDEEP | `768:FMSAfmfnkGVXSa1c2pb0oEj7DHVfr9+TPa5SJ2khAIc0hXs3Uoz1:JAoXCAtVGj7jJiPaMJ20Wz1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_f76f5962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f76f596286a2b1e0686b9b7e7ca1eb18ab462ccf3b4c5dbef6c09f7ddc593272"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:06"
  condition:
    hash.sha256(0, filesize) == "f76f596286a2b1e0686b9b7e7ca1eb18ab462ccf3b4c5dbef6c09f7ddc593272"
}
```

### Sample 51: `5a433a64567fce8e`

| Field | Value |
|---|---|
| SHA-256 | `5a433a64567fce8e9ccf41dc6ce2d3536b2382d116b9737912a4709926cd283c` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32daeb58e93a99c67f95b353b7be69b0` |
| SHA-1 | `c805c9565ae16a6603db288c6928a6c6854366fe` |
| SHA-256 | `5a433a64567fce8e9ccf41dc6ce2d3536b2382d116b9737912a4709926cd283c` |
| SHA3-384 | `950df92766cbb74732383ac7c0aa8e4160848b2d8defdba3f13b66a0e653be83c58ced4a09c051605a090563dd7a794e` |
| TLSH | `T137F2F13031727675CD810E76DBA542837EB109B5C65C35BAAA7F3D6C8CC62830B7D8A2` |
| SSDEEP | `768:AMFxIpp61ohh5VNYYrZPJqeUUzo92x4681BBxbT67IcdTv+2VdOkwl9q3UELeW:AMIp6+hh5VNYeZUeDzo92xT87B9kTCud` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_5a433a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a433a64567fce8e9ccf41dc6ce2d3536b2382d116b9737912a4709926cd283c"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:04"
  condition:
    hash.sha256(0, filesize) == "5a433a64567fce8e9ccf41dc6ce2d3536b2382d116b9737912a4709926cd283c"
}
```

### Sample 52: `1f2bc04401a73357`

| Field | Value |
|---|---|
| SHA-256 | `1f2bc04401a73357813d145ea66ec6ad168c21e44dd9a47ff840102d301fbc51` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e2a507a225425d0ca41ffff9e949f4e` |
| SHA-1 | `ad00b0fe0ccbc5cd769b2f37440eb70e10ba7c27` |
| SHA-256 | `1f2bc04401a73357813d145ea66ec6ad168c21e44dd9a47ff840102d301fbc51` |
| SHA3-384 | `8605d757828b31a32b5e37cffcd652cf213c349188d7cc05e7645d190717b580d541494d2d4f4882476a0a5e62f073c8` |
| TLSH | `T139735C32B9761D27C4D0A87A61F34724F2F2479A25ACCA1A3DB10D8EBF3564032577B6` |
| SSDEEP | `1536:y1WSpkB5DQ4YPmxjnk3QwtwceNM5Z8ggRE8uLtf8u:2HsemeaLN8egYHu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_1f2bc044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f2bc04401a73357813d145ea66ec6ad168c21e44dd9a47ff840102d301fbc51"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:03"
  condition:
    hash.sha256(0, filesize) == "1f2bc04401a73357813d145ea66ec6ad168c21e44dd9a47ff840102d301fbc51"
}
```

### Sample 53: `1f71e800d6147c59`

| Field | Value |
|---|---|
| SHA-256 | `1f71e800d6147c5932c6a85eaa3dc8f9e79ed8eed5493821a562f5609585fb5d` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-08-04 23:52:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `039b190c7cf4994e67cb1c545a88162e` |
| SHA-1 | `ac29f6746b11662fc1ba2d31feef8c3c18d8727f` |
| SHA-256 | `1f71e800d6147c5932c6a85eaa3dc8f9e79ed8eed5493821a562f5609585fb5d` |
| SHA3-384 | `8f35ad42baee8ac840551bb2f717437983160b6783cdf787561af07743584a30f072298831867a440d64e690a5fa7381` |
| TLSH | `T1FA7328D7B400DDBDF80ED77B44534A0AB231A79155830F3A6397BA67FD321A84866F82` |
| SSDEEP | `1536:+hI/ss2F7AyB4wXx8IJPsG+0VjnJFtbTCbolHuJ/9tYyqX:+hI0HrB4wXtCFajnntvqJ/9WyqX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_1f71e800
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f71e800d6147c5932c6a85eaa3dc8f9e79ed8eed5493821a562f5609585fb5d"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:02"
  condition:
    hash.sha256(0, filesize) == "1f71e800d6147c5932c6a85eaa3dc8f9e79ed8eed5493821a562f5609585fb5d"
}
```

### Sample 54: `b2f27f60ab93a86f`

| Field | Value |
|---|---|
| SHA-256 | `b2f27f60ab93a86fce986b7137986fabbe7952ad38e6a9d6c0d458c019baeeb0` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-08-04 23:51:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b36431acc22b468ccaa622a82c9ae595` |
| SHA-1 | `064e2bd4642a10b466d647f8a6a02af0c1d168e4` |
| SHA-256 | `b2f27f60ab93a86fce986b7137986fabbe7952ad38e6a9d6c0d458c019baeeb0` |
| SHA3-384 | `bc5c2e9bc1f1c590323e2e90b5d61b0a6070a7cf013ebc4a866eb17e7245e7c86ea757eabcd6dd460beee5235a504b6f` |
| TLSH | `T1E3E2E1B86BA8270FEF19613753E18CEDA7BA1D650E94D5612B14CBE311061AEC32D731` |
| SSDEEP | `768:D/Afcl9QI38cDxXGFbzVvgi0dHBOM6oZMxwd4:DY0l9QI3VwhVvgiWhooZq1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_b2f27f60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2f27f60ab93a86fce986b7137986fabbe7952ad38e6a9d6c0d458c019baeeb0"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:59"
  condition:
    hash.sha256(0, filesize) == "b2f27f60ab93a86fce986b7137986fabbe7952ad38e6a9d6c0d458c019baeeb0"
}
```

### Sample 55: `d2726a8326104f79`

| Field | Value |
|---|---|
| SHA-256 | `d2726a8326104f79becf68c4e806a6f9ddfde07344baf592e0a783a9e4ac58cd` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-08-04 23:51:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e40c858cd52a9381428bf2fe385c58f4` |
| SHA-1 | `1c49d4a009165808bc65a832a982f443fa77442d` |
| SHA-256 | `d2726a8326104f79becf68c4e806a6f9ddfde07344baf592e0a783a9e4ac58cd` |
| SHA3-384 | `2e12052fe47c509158e8a37ae06e6705a542d16264df98d16c90ed68f50108843d169a7286d431eaeba24c0514282e96` |
| TLSH | `T15DF2E16836010DF5EE23D83E12B903E9AC69837054D7DC56392EE687E96A1BB74C7CD0` |
| SSDEEP | `768:psneKrC019npifNuNxUjgZZddiFTPBSx+fJgGlzDpbuR1Jt:psnvC013i19jgZ7688dVJuj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_d2726a83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2726a8326104f79becf68c4e806a6f9ddfde07344baf592e0a783a9e4ac58cd"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:58"
  condition:
    hash.sha256(0, filesize) == "d2726a8326104f79becf68c4e806a6f9ddfde07344baf592e0a783a9e4ac58cd"
}
```

### Sample 56: `f3eed21ca3a8d078`

| Field | Value |
|---|---|
| SHA-256 | `f3eed21ca3a8d07883868fc0245a17acf954336675cfe2bd042d4bb29a35e0f9` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-08-04 23:51:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3add6151f29a2724898e49c264ac1a1b` |
| SHA-1 | `3213240f571c622af54b58c0b1b38a6cdfcd5a49` |
| SHA-256 | `f3eed21ca3a8d07883868fc0245a17acf954336675cfe2bd042d4bb29a35e0f9` |
| SHA3-384 | `2ee2ae1b44eb3c5a87ecd45cdba430ac1024008780c2f68425a64f405582d08a44f0df3804cc94119df33b58b50c98cf` |
| TLSH | `T11D82C02701E75CB0D6B16A32DD3C8985B1FB9F78D27A72B0291E064CA9C41099A3C94E` |
| SSDEEP | `384:Gelrb97x8fEJ4G+5KZjcUSMKdEWjhymdGUop5h4wx:Bbj8nKZ4UiW8s3Uozlx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_f3eed21c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3eed21ca3a8d07883868fc0245a17acf954336675cfe2bd042d4bb29a35e0f9"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:57"
  condition:
    hash.sha256(0, filesize) == "f3eed21ca3a8d07883868fc0245a17acf954336675cfe2bd042d4bb29a35e0f9"
}
```

### Sample 57: `ac787255b109b455`

| Field | Value |
|---|---|
| SHA-256 | `ac787255b109b4558b0bffe85f5b4f158bd260f993b9aedb6cbf1d0b227ca5ad` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-08-04 23:51:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `166e8c2a90bf76c09185f3e7b168a6fc` |
| SHA-1 | `fd18e9f07128584d2c119a81c698a0fa9346039e` |
| SHA-256 | `ac787255b109b4558b0bffe85f5b4f158bd260f993b9aedb6cbf1d0b227ca5ad` |
| SHA3-384 | `3f12457cc356d771fa27aa5baed76893e9250d2e52c091db4e8565242e6001c1e3f752923b0fa964bdf9078a29402aef` |
| TLSH | `T1D9F2E17EF8183146CCACE67C009E6BEB65D5F96533E75BEC630044D9EE0811E35AD268` |
| SSDEEP | `768:Tg4k7NaZ6I+n6hFZZOfODnjrSFgPFAZNxdpO5UhF17qbWda:T1k7A0VmZZOwjrSFgNAV3mUhjGIa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_ac787255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac787255b109b4558b0bffe85f5b4f158bd260f993b9aedb6cbf1d0b227ca5ad"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:56"
  condition:
    hash.sha256(0, filesize) == "ac787255b109b4558b0bffe85f5b4f158bd260f993b9aedb6cbf1d0b227ca5ad"
}
```

### Sample 58: `7258dc0bef74fe98`

| Field | Value |
|---|---|
| SHA-256 | `7258dc0bef74fe98f77dc6a29c513063cba7131a68974e2e1f21412f199d366c` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-08-04 23:51:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b152ca15c412328cf22b65b0e209e59` |
| SHA-1 | `ebb19c6cdeafb0b3c8e49ba55364cc06c5c60bb4` |
| SHA-256 | `7258dc0bef74fe98f77dc6a29c513063cba7131a68974e2e1f21412f199d366c` |
| SHA3-384 | `5783dc6da9e2ecf337e48581d0cb944bec16cd498b41e0dfc28b9cf21f6324b207c192a3e6167d47dbe9ca1e06647c67` |
| TLSH | `T1CE43023A4C8F591107A83DF4C56C17CB4D4D6FB4E19931B246BE1EAAF12984296FC2D3` |
| SSDEEP | `768:QvB5QwePT9S85H666sJn1ds+SIsZ43QyyBZSXqPyyuzx39ZJHi8QnNrC9q3UELYP:iPe7IgHRpK4IZS6B639ZJHM3LgNeGd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_7258dc0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7258dc0bef74fe98f77dc6a29c513063cba7131a68974e2e1f21412f199d366c"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:55"
  condition:
    hash.sha256(0, filesize) == "7258dc0bef74fe98f77dc6a29c513063cba7131a68974e2e1f21412f199d366c"
}
```

### Sample 59: `dd9d754896001df7`

| Field | Value |
|---|---|
| SHA-256 | `dd9d754896001df78f96486b10729650e5957a08e4931d6b6a1a154753a26c63` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 23:48:30` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3f1a63acf8c12e1994da70dcc1b9508` |
| SHA-1 | `8b5a5b2eafac846e3995f2e80fa2e801df585519` |
| SHA-256 | `dd9d754896001df78f96486b10729650e5957a08e4931d6b6a1a154753a26c63` |
| SHA3-384 | `ca38f8ac43c5a17a6689d516b756bd549a111f26a0e730555a09c96c8ba1727c37d7c71bfd6f90a678a2e0215c5c6d3a` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T1F7771256E2FD00E8D57AC0BCC6575517EBB2345917309BEB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:+uML4PXoeOvHiwB3sn+h1hW25F+wX0ff6yajCs6+4S3Nftl:+5soeeCwDrhWG+tf6fj4ull` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_dd9d7548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd9d754896001df78f96486b10729650e5957a08e4931d6b6a1a154753a26c63"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:48:30"
  condition:
    hash.sha256(0, filesize) == "dd9d754896001df78f96486b10729650e5957a08e4931d6b6a1a154753a26c63"
}
```

### Sample 60: `96b09d3c8deac6e7`

| Field | Value |
|---|---|
| SHA-256 | `96b09d3c8deac6e7694c8a37ce45b5359fb7345f13e824c808831321eefd5f01` |
| Family label | `unknown` |
| File name | `java-qEKUrj.exe` |
| File type | `exe` |
| First seen | `2026-08-04 23:45:52` |
| Reporter | `Flechaa` |
| Tags | `electron, exe, infostealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eaa14a38f0f9d65a9db6f0cceee1a914` |
| SHA-1 | `52574c16aa7af67ea08be9ed4fde7b0e74602cf2` |
| SHA-256 | `96b09d3c8deac6e7694c8a37ce45b5359fb7345f13e824c808831321eefd5f01` |
| SHA3-384 | `3c3e5019afc98ad8dc3e02b0aacea7c4e4514bf292cb840e8ad65deb3265142a4ed06ce98e85c1fe5adfe21d599fe270` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T10CE733C919DEA47ED6686BFD03312876207CBFDA7FA5C91468C580C7680976E8C32D72` |
| SSDEEP | `1572864:UzXH/d3YYrS9SXDmcoOoz0Q4RysehXQKapNFHuPBdgoEEAd07:UzX1IYrvmcoFzyIIp+/7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_96b09d3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96b09d3c8deac6e7694c8a37ce45b5359fb7345f13e824c808831321eefd5f01"
    family = "unknown"
    file_name = "java-qEKUrj.exe"
    file_type = "exe"
    first_seen = "2026-08-04 23:45:52"
  condition:
    hash.sha256(0, filesize) == "96b09d3c8deac6e7694c8a37ce45b5359fb7345f13e824c808831321eefd5f01"
}
```

### Sample 61: `b4647c8851c31698`

| Field | Value |
|---|---|
| SHA-256 | `b4647c8851c316988984a6c6d534f103a0cd65e5f165f8aaaa9da8b0a7f28854` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 23:41:30` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a537502a50dc17582ca318676f5e7f0` |
| SHA-1 | `3fe31d67c6c22ae20abc32237697fcb6f9bf122e` |
| SHA-256 | `b4647c8851c316988984a6c6d534f103a0cd65e5f165f8aaaa9da8b0a7f28854` |
| SHA3-384 | `027cd0e8ceace1ec95d3698be20afd8b11d696454179738e0cdda4aefe5805759a252e142a34a9a9124ac0492660e5a4` |
| IMPHASH | `e2bf3ea500ed6add4b896d96c842dc0a` |
| TLSH | `T189875C93F8922A90D4EEC274C272816BB7613C590B3823E75690F7601F3ABD4DAB7751` |
| SSDEEP | `196608:158HKYeP2mwIsj2ZIj2AaMEtOiP7M6ODCVzGlOPRM/wMK/zKthg32RQkaGiCdNUz:174j2+j23/OgRrMK/ehg32RDaG9dfui` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_b4647c88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4647c8851c316988984a6c6d534f103a0cd65e5f165f8aaaa9da8b0a7f28854"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:41:30"
  condition:
    hash.sha256(0, filesize) == "b4647c8851c316988984a6c6d534f103a0cd65e5f165f8aaaa9da8b0a7f28854"
}
```

### Sample 62: `757060d1a348f54c`

| Field | Value |
|---|---|
| SHA-256 | `757060d1a348f54c2fceeb3337e0e8b8a984d3f3001ffc27771dd49f559254e7` |
| Family label | `unknown` |
| File name | `msedge.exe` |
| File type | `exe` |
| First seen | `2026-08-04 23:22:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa361a2c34222dd96b9cb8a6ac38d7de` |
| SHA-1 | `001b194569773929260830ccdd0ecf4177709e1a` |
| SHA-256 | `757060d1a348f54c2fceeb3337e0e8b8a984d3f3001ffc27771dd49f559254e7` |
| SHA3-384 | `64b86fec13bd317e41fa9f73a8f825bcac05ccf5c361f8c7d29b28cbf5d39722c87c876edbabb6f199740aa13996f8a0` |
| IMPHASH | `f2da2e4c1b5a39d16c40d60cec2608d7` |
| TLSH | `T18E75E01367DE92A5C2725173BA55BB426E7FBD2805B1F09B2FD4093DEA20131821EB73` |
| SSDEEP | `49152:Qkwkn9IMSNYJEwXUHLpDoBqsTi2lwaPCS:rdnsQE9L9ZsTllvPC` |
| ICON-DHASH | `f0d4820ccecef4f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_757060d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "757060d1a348f54c2fceeb3337e0e8b8a984d3f3001ffc27771dd49f559254e7"
    family = "unknown"
    file_name = "msedge.exe"
    file_type = "exe"
    first_seen = "2026-08-04 23:22:34"
  condition:
    hash.sha256(0, filesize) == "757060d1a348f54c2fceeb3337e0e8b8a984d3f3001ffc27771dd49f559254e7"
}
```

### Sample 63: `2b2cf3626f4d79fa`

| Field | Value |
|---|---|
| SHA-256 | `2b2cf3626f4d79fa2b10001f024b86677c63e2381f0923331924d26b1ee676ba` |
| Family label | `unknown` |
| File name | `msedge.exe` |
| File type | `exe` |
| First seen | `2026-08-04 23:21:30` |
| Reporter | `TannerFilip` |
| Tags | `exe, lodarat, rat, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61e7b67b3ca5412726f99a469d54c545` |
| SHA-1 | `8b78edc4466399b0a4158f018f614dcf01f255c4` |
| SHA-256 | `2b2cf3626f4d79fa2b10001f024b86677c63e2381f0923331924d26b1ee676ba` |
| SHA3-384 | `f9dbd29739060a03ea40d63f9c7f971d67ac373d6cd40bf5ef5294ca0680fea2e5bf838b07b06a2e7e17b919d10be9a1` |
| IMPHASH | `ef471c0edf1877cd5a881a6a8bf647b9` |
| TLSH | `T19435132A4E8BBCDFE41459B45496DBD6066CDFA5B4E506EC30E4EF3DA3A24748600FB0` |
| SSDEEP | `24576:3hloDX0XOf4btEJNO5HjXp/LI6oVjbBqsTg92lz:3hloJfsEvUHLpDoBqsTi2l` |
| ICON-DHASH | `f0d4820ccecef4f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_2b2cf362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b2cf3626f4d79fa2b10001f024b86677c63e2381f0923331924d26b1ee676ba"
    family = "unknown"
    file_name = "msedge.exe"
    file_type = "exe"
    first_seen = "2026-08-04 23:21:30"
  condition:
    hash.sha256(0, filesize) == "2b2cf3626f4d79fa2b10001f024b86677c63e2381f0923331924d26b1ee676ba"
}
```

### Sample 64: `ae12961097868ed2`

| Field | Value |
|---|---|
| SHA-256 | `ae12961097868ed2394644d506dfd40d175d30ef159def7d68a845ac23f7a9b3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 23:14:21` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0702fad301d4fe09a98c878d74b1b5ea` |
| SHA-1 | `1081734150ecc7e0125f9da6b4f1dd58bbb17a24` |
| SHA-256 | `ae12961097868ed2394644d506dfd40d175d30ef159def7d68a845ac23f7a9b3` |
| SHA3-384 | `c7bd32a69c927b7a30ee8dff29979771f0fbbf3ecad17de417f9b0d17e4ad99201c817f35c4e2b4c776058a4628f397d` |
| IMPHASH | `83fa772670ac674cd68ff73f3ef04802` |
| TLSH | `T10243B69167F9151AF6F38E783C7465568C7BBE726D61E08E8280204F0875B95CE78B33` |
| SSDEEP | `768:spM+/0vaXDiTLlGCI0App3rWSph6koM3R+qsq:uCEiTLXA3bfp4koUR+v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_ae129610
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae12961097868ed2394644d506dfd40d175d30ef159def7d68a845ac23f7a9b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:14:21"
  condition:
    hash.sha256(0, filesize) == "ae12961097868ed2394644d506dfd40d175d30ef159def7d68a845ac23f7a9b3"
}
```

### Sample 65: `0aae3c635faa512b`

| Field | Value |
|---|---|
| SHA-256 | `0aae3c635faa512b497fd34dce58b7b5fcaafcbe0a67e4c154cf7659ba334b81` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 23:13:14` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cd5cfd593b9708f8a72fdea8bbcaec5` |
| SHA-1 | `d6973c358e3997dbaf694f0db6693635bd780664` |
| SHA-256 | `0aae3c635faa512b497fd34dce58b7b5fcaafcbe0a67e4c154cf7659ba334b81` |
| SHA3-384 | `fae18b862b689dd312afc1503fdcc6d0354467119f4fcbc7dfe310f068cb60081c3aaa5e8d21e56184471fb0e89c60fd` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1A122D61E2E460330EE5048B0E2755A4A553D5DE37386FBDBE333D5970AD5D8584C0AAF` |
| SSDEEP | `192:xcolWai9BQ5tMxeuwq5C2PFJxTEZmFhEorccGF:OoJi3Ak3PFwZsMF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_065_0aae3c63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aae3c635faa512b497fd34dce58b7b5fcaafcbe0a67e4c154cf7659ba334b81"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:13:14"
  condition:
    hash.sha256(0, filesize) == "0aae3c635faa512b497fd34dce58b7b5fcaafcbe0a67e4c154cf7659ba334b81"
}
```

### Sample 66: `2c6790b4141e5bbd`

| Field | Value |
|---|---|
| SHA-256 | `2c6790b4141e5bbd9684c129acb2a7aeb1b8b3c167dfdfd6b3e9df7013bd1f4d` |
| Family label | `unknown` |
| File name | `java-rjZsjZ.exe` |
| File type | `exe` |
| First seen | `2026-08-04 22:52:46` |
| Reporter | `Flechaa` |
| Tags | `electron, exe, infostealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26f2b6e4a15be9822ca4299612b41fce` |
| SHA-1 | `62bafae99f3d06ab32435d61e9b8b0226fbd3473` |
| SHA-256 | `2c6790b4141e5bbd9684c129acb2a7aeb1b8b3c167dfdfd6b3e9df7013bd1f4d` |
| SHA3-384 | `182c59990be2a500bed2319ba72984b93411ca720c42dec798b2aad876b91fdbff978718c9f083ef763931a668979310` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T167E733B160FA4495D29C33F44F329D7E10E7AEBDEDE44A0C92CD349299B3AC6046199F` |
| SSDEEP | `1572864:GzjzJT1M7S9SXDmcoOoz0Q4RysehXQKapNFHuPBdgoEEAdG7:GzpRM7vmcoFzyIIp+H7` |
| ICON-DHASH | `524a4d4f260f0b1e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_2c6790b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6790b4141e5bbd9684c129acb2a7aeb1b8b3c167dfdfd6b3e9df7013bd1f4d"
    family = "unknown"
    file_name = "java-rjZsjZ.exe"
    file_type = "exe"
    first_seen = "2026-08-04 22:52:46"
  condition:
    hash.sha256(0, filesize) == "2c6790b4141e5bbd9684c129acb2a7aeb1b8b3c167dfdfd6b3e9df7013bd1f4d"
}
```

### Sample 67: `fe8277705549324d`

| Field | Value |
|---|---|
| SHA-256 | `fe8277705549324d8fdb94cc7d9a9083190f3e93e8e5dfec582b5afa5d42c97d` |
| Family label | `unknown` |
| File name | `photo_287742060718.zip` |
| File type | `zip` |
| First seen | `2026-08-04 22:18:55` |
| Reporter | `k3dg3` |
| Tags | `PureRAT, zgRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faa2e02a0bfc9a94117cb4cd5f281829` |
| SHA-1 | `b4e650340077519842773626b4b1c3760964eb28` |
| SHA-256 | `fe8277705549324d8fdb94cc7d9a9083190f3e93e8e5dfec582b5afa5d42c97d` |
| SHA3-384 | `c929349db1ef16ea54396cb2ae4bb699edd6bbc314592cc69170bd0eb1985c4bad2fdc440a166ae200f84d37d6c9dad0` |
| TLSH | `T1D2219650DAE40A20DEC6977D267D1FA011646528BC0FDBDBB8060247A76374D1BC3D16` |
| SSDEEP | `24:9EBVgbtW/x6/7eco5ILyuIhzyAG7ouxj9VkvhSqXhubSuRzSrf1C0pQ/FiV+oLel:9dJWk/7Ro5KN7ouxjcjxuJzSrf1CpFQ6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_fe827770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe8277705549324d8fdb94cc7d9a9083190f3e93e8e5dfec582b5afa5d42c97d"
    family = "unknown"
    file_name = "photo_287742060718.zip"
    file_type = "zip"
    first_seen = "2026-08-04 22:18:55"
  condition:
    hash.sha256(0, filesize) == "fe8277705549324d8fdb94cc7d9a9083190f3e93e8e5dfec582b5afa5d42c97d"
}
```

### Sample 68: `6941fbafdf1c7e5d`

| Field | Value |
|---|---|
| SHA-256 | `6941fbafdf1c7e5ddd12b9050c27501aba8b0ab05e1916afffd21ba30257ebf8` |
| Family label | `unknown` |
| File name | `pfbofa.zip` |
| File type | `zip` |
| First seen | `2026-08-04 22:16:48` |
| Reporter | `k3dg3` |
| Tags | `PureRAT, zgRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3206acc6fc88ef09cf845f65e9965484` |
| SHA-1 | `0c4891b76bc605a064b84e1ae37c25c3f1bfb82e` |
| SHA-256 | `6941fbafdf1c7e5ddd12b9050c27501aba8b0ab05e1916afffd21ba30257ebf8` |
| SHA3-384 | `3bc8fc3b6d97f078e576170231607d0b2790575fd3021e2d33c50d0073cc81587d2b6439a5d057688d0788009a06c372` |
| TLSH | `T1DF530123FB189E2C837F21116BD93983DE184A5D0D8DF458A4CAB44BE4E0756EB4FE46` |
| SSDEEP | `1536:+6NiG3ckfq/6P10YTm/slmRjufzPUm5ww+gBy0XQ4R:pNzMxUDT5luj2PxwJgByiR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_6941fbaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6941fbafdf1c7e5ddd12b9050c27501aba8b0ab05e1916afffd21ba30257ebf8"
    family = "unknown"
    file_name = "pfbofa.zip"
    file_type = "zip"
    first_seen = "2026-08-04 22:16:48"
  condition:
    hash.sha256(0, filesize) == "6941fbafdf1c7e5ddd12b9050c27501aba8b0ab05e1916afffd21ba30257ebf8"
}
```

### Sample 69: `151b01ecbb7aca8b`

| Field | Value |
|---|---|
| SHA-256 | `151b01ecbb7aca8b8a3e82f2e74c4f496e95046b89601a2482e6dcb3d570d78c` |
| Family label | `Formbook` |
| File name | `Q88 with vessel's particulars.exe` |
| File type | `exe` |
| First seen | `2026-08-04 22:14:41` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da90fd74d3033e19b43c7bf0c9a9eec0` |
| SHA-1 | `dd5b0cb474bef398e49423fe6b83713834232439` |
| SHA-256 | `151b01ecbb7aca8b8a3e82f2e74c4f496e95046b89601a2482e6dcb3d570d78c` |
| SHA3-384 | `92218cb8a8c816820c6965782af3015ca15866015d0167b5132d4f4a82e911e498006650ac44589edb121e94b22657c1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1772501262E83BB40D7780F3DC162149853F4D21B5222F7AA1EFE02F44E57F6D9A2745A` |
| SSDEEP | `24576:S+4S39HMJU3YORunWhm60XybH350qIno0GYb:S+b3eJUDYnWY60K5Mj` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_069_151b01ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "151b01ecbb7aca8b8a3e82f2e74c4f496e95046b89601a2482e6dcb3d570d78c"
    family = "Formbook"
    file_name = "Q88 with vessel's particulars.exe"
    file_type = "exe"
    first_seen = "2026-08-04 22:14:41"
  condition:
    hash.sha256(0, filesize) == "151b01ecbb7aca8b8a3e82f2e74c4f496e95046b89601a2482e6dcb3d570d78c"
}
```

### Sample 70: `4cc5af32dfe739b1`

| Field | Value |
|---|---|
| SHA-256 | `4cc5af32dfe739b1d73d1291dd178e4b8b76cb5b5cb4096b03d060c9236a5896` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-04 22:09:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbfc482fd1420ffc9f918f064a20c59c` |
| SHA-1 | `825d925b5e2f90d7d5160c9fb07a465f7f7219d5` |
| SHA-256 | `4cc5af32dfe739b1d73d1291dd178e4b8b76cb5b5cb4096b03d060c9236a5896` |
| SHA3-384 | `b4acf004664b4ab165fa3a74e3c8dd80ad7e27fb6e0ea1e80fdaff2896ad31a4316bb3e657bc880f449402a6ee22b991` |
| TLSH | `T13F3190FF0316DB128904CA4BB3A1154D5205C2AF2F6BE7F8EF4C2D3A638A5583259B47` |
| SSDEEP | `24:q3pGyj6b6BYKEVpPo0dHXwg+jeYsFYmoCcgl7J7NE:Io1dpw0dAg+6YsFN7J7NE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_4cc5af32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc5af32dfe739b1d73d1291dd178e4b8b76cb5b5cb4096b03d060c9236a5896"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-04 22:09:48"
  condition:
    hash.sha256(0, filesize) == "4cc5af32dfe739b1d73d1291dd178e4b8b76cb5b5cb4096b03d060c9236a5896"
}
```

### Sample 71: `0e6518062d007026`

| Field | Value |
|---|---|
| SHA-256 | `0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e` |
| Family label | `Prometei` |
| File name | `0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e` |
| File type | `elf` |
| First seen | `2026-08-04 22:08:04` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd8d47b19e413e031d9c8b40d49f136d` |
| SHA-1 | `0c7df2950889474de81430d89c0c1776686a267d` |
| SHA-256 | `0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e` |
| SHA3-384 | `736d6788963a54affd9ddee33636fd5b7ccacfa635786ef9ae70bb4a987b69e281abf800425953d939b3dc03220f63e9` |
| TLSH | `T1EFA423B4F9219E8F6DD769B91B24C31DE182D172589D4C2313AE94A34F3D732AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdt:Fs6pyCC/Ya2hpi6T6N4b` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_071_0e651806
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e"
    family = "Prometei"
    file_name = "0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e"
    file_type = "elf"
    first_seen = "2026-08-04 22:08:04"
  condition:
    hash.sha256(0, filesize) == "0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e"
}
```

### Sample 72: `a5073027d44c6ce3`

| Field | Value |
|---|---|
| SHA-256 | `a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836` |
| Family label | `Prometei` |
| File name | `a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836` |
| File type | `elf` |
| First seen | `2026-08-04 22:07:07` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c480e63ebeb2bd7dc3846b216d34886` |
| SHA-1 | `2cfc74c230d1c370d157e651ea3066f341b0206f` |
| SHA-256 | `a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836` |
| SHA3-384 | `c67626039485d8a293cd940c94ab85fd7c57c21a4fa7ba38efaa68e70656ce883c5e00f039366c470611826d895618a3` |
| TLSH | `T177A423B4F9219E8F6DD769B91B24831DE182C172589D4C2313AE95E34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdk:Fs6pyCC/Ya2hpi6T6N4m` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_072_a5073027
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836"
    family = "Prometei"
    file_name = "a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836"
    file_type = "elf"
    first_seen = "2026-08-04 22:07:07"
  condition:
    hash.sha256(0, filesize) == "a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836"
}
```

### Sample 73: `918a0a4cde273e28`

| Field | Value |
|---|---|
| SHA-256 | `918a0a4cde273e289a846a5e21e160c2caf84372cc13c717d707458c7fd561a8` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-08-04 21:57:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03a2ee34e4320374b76fac09f265159c` |
| SHA-1 | `527c5666a6757860e7f1ee9ec8e36e9af10de154` |
| SHA-256 | `918a0a4cde273e289a846a5e21e160c2caf84372cc13c717d707458c7fd561a8` |
| SHA3-384 | `828cfe5c8de1dd8c6638f90ff5ab0b48873df0b42a9f2ac77a8d02e7d6a072d17370ee680a1787460a25e7f91fde0f40` |
| TLSH | `T1D5E3074AA9519F12D5C321FAFB9F814933136FB8E3F93102DD246F60278B99B0E76512` |
| TELFHASH | `t15e21f15dcd9c0fac7bd48388c0ee990f86f5356b1f102066da5d9e6f4292cc67035927` |
| SSDEEP | `3072:7L1lAQfl3poFSyQLShdGx5w0VaAX9ug9B5Syzr9GSuOXgSneAQPcFcq:7HllpoFSyQfxJVaKV9B5Syv9GSvgC1Qe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_918a0a4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "918a0a4cde273e289a846a5e21e160c2caf84372cc13c717d707458c7fd561a8"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-04 21:57:40"
  condition:
    hash.sha256(0, filesize) == "918a0a4cde273e289a846a5e21e160c2caf84372cc13c717d707458c7fd561a8"
}
```

### Sample 74: `a8ae2492cac79019`

| Field | Value |
|---|---|
| SHA-256 | `a8ae2492cac7901938e1e12b81d858b96f9b10609bda4678dfb63a0be56473e7` |
| Family label | `Mirai` |
| File name | `data_powerpc` |
| File type | `elf` |
| First seen | `2026-08-04 21:57:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6090d84f3ccccd3d3902921f640dfc9` |
| SHA-1 | `2ffb8b05eb6f599abf3dae5e6eb5e6f07289aeca` |
| SHA-256 | `a8ae2492cac7901938e1e12b81d858b96f9b10609bda4678dfb63a0be56473e7` |
| SHA3-384 | `f60f2fc33d5d0fc688b330b233b4d57e7a9c10331162c89ca0cfff07ab37fa9eeabd5b3316631d9aefaba80338a9ddd1` |
| TLSH | `T1C9C33902770D0F43E1232CF03B7B1BE0879ABEA619F5A584751EBEC65275EB12142ED9` |
| SSDEEP | `3072:V//0H5Iu/M2Fo4zMot5CRMw/KbIX+6atnE6:V//6H//e4A8gRMBbCItnE6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_a8ae2492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ae2492cac7901938e1e12b81d858b96f9b10609bda4678dfb63a0be56473e7"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-04 21:57:39"
  condition:
    hash.sha256(0, filesize) == "a8ae2492cac7901938e1e12b81d858b96f9b10609bda4678dfb63a0be56473e7"
}
```

### Sample 75: `26d365cb80c309e4`

| Field | Value |
|---|---|
| SHA-256 | `26d365cb80c309e42a88e0091f15a3c5de80409d18d141c83c8802e82abab22f` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-08-04 21:57:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbf0833f9bc206c1ca56376c5b47119e` |
| SHA-1 | `7e78e4592d01c78b6d39ce50587c0ce3ddeb6665` |
| SHA-256 | `26d365cb80c309e42a88e0091f15a3c5de80409d18d141c83c8802e82abab22f` |
| SHA3-384 | `595be80a93ab454b2652d41b35337fdb6a1a27f3a761fae1943ade79e8f5d6f425a6fa4abde060fa7d5b2be31bc89281` |
| TLSH | `T1EDC31A427E528F13C6C321F6FBAE42583B136B7CD7EA7202A9247F50274B8DA0E76551` |
| TELFHASH | `t1a321e222df9905ac67f0c555819be02547ed34ee175a24294e1a7b2f8c4b580b83d825` |
| SSDEEP | `3072:79M51agDjr3WrKkU9ZamTl1hGWVauXkS6O4X:6Vr3WrKk4aM1hGqa/S6O4X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_26d365cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26d365cb80c309e42a88e0091f15a3c5de80409d18d141c83c8802e82abab22f"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-04 21:57:37"
  condition:
    hash.sha256(0, filesize) == "26d365cb80c309e42a88e0091f15a3c5de80409d18d141c83c8802e82abab22f"
}
```

### Sample 76: `47db897ff8ee59a7`

| Field | Value |
|---|---|
| SHA-256 | `47db897ff8ee59a7caa16b8b06e8bf45a376be9e3f581587d8fcaeda6d7d75d0` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-08-04 21:54:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20d8300b6ac1237261d0b08bb2369f14` |
| SHA-1 | `e4d2799428e03c671dba52cf5b01f50cf8e1892e` |
| SHA-256 | `47db897ff8ee59a7caa16b8b06e8bf45a376be9e3f581587d8fcaeda6d7d75d0` |
| SHA3-384 | `9c7094d9bce32dda188c8418d045e42174168f73c0099c770afdc176dcf092be0e3012573890f11553cb6acd8e7bf200` |
| TLSH | `T11BD31A56A952CB12C1C325BAFB9F514D33132FB8E3ED72029D14AF60678B8DB0E76512` |
| TELFHASH | `t1d221ac66ffd10a6c5bf443ed92a988391aad358e0b2138578b08f72fc2529d4f029422` |
| SSDEEP | `3072:rM2RyKsGadJ7x8Wtulk+PdcEbLzav0yS7R6N5mhfjoLxXO:rtxs5dJ7x8WtkP6EbfatS8N5AoLxXO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_47db897f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47db897ff8ee59a7caa16b8b06e8bf45a376be9e3f581587d8fcaeda6d7d75d0"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-04 21:54:34"
  condition:
    hash.sha256(0, filesize) == "47db897ff8ee59a7caa16b8b06e8bf45a376be9e3f581587d8fcaeda6d7d75d0"
}
```

### Sample 77: `b038d9b928a355c5`

| Field | Value |
|---|---|
| SHA-256 | `b038d9b928a355c583d0c64f5f32990e557a40117d9fa7b9c231022f540f40be` |
| Family label | `Mirai` |
| File name | `data_arm5` |
| File type | `elf` |
| First seen | `2026-08-04 21:54:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca5fef9a891acf04dddfb9680ca652ae` |
| SHA-1 | `dd00c1e11fd2dc34a78cff078e34639892bdf239` |
| SHA-256 | `b038d9b928a355c583d0c64f5f32990e557a40117d9fa7b9c231022f540f40be` |
| SHA3-384 | `6697c8a3a9b1cfe04bb9c42bbed098e1b5d73ab5bd94a126dfeaa8ffad4b8b4f89c7659ec1c6ad2c95cfd4667c08673f` |
| TLSH | `T1F4C31A527E429F13C6C321F6FBAE46583B176B7DD7EA3102E9247F50234B8DA0E26611` |
| TELFHASH | `t18021e051ea90169c6bf182ac91bde1564bd930b85b133119af3ba35f9acad81300c466` |
| SSDEEP | `3072:LXTRoumQZXAGtermlOin5DoMCU1vAQaX:BoumQxAFKOintpCqvAQaX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_b038d9b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b038d9b928a355c583d0c64f5f32990e557a40117d9fa7b9c231022f540f40be"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-04 21:54:33"
  condition:
    hash.sha256(0, filesize) == "b038d9b928a355c583d0c64f5f32990e557a40117d9fa7b9c231022f540f40be"
}
```

### Sample 78: `8de2d51797f11389`

| Field | Value |
|---|---|
| SHA-256 | `8de2d51797f113896007d6ed8c634d99f5cee4c34c2bf55b1e4c19432afcbab3` |
| Family label | `ValleyRAT` |
| File name | `C5940ABAE3FB2C368F0841417C9B0454.exe` |
| File type | `exe` |
| First seen | `2026-08-04 21:45:32` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5940abae3fb2c368f0841417c9b0454` |
| SHA-1 | `4a7d250aa077b7e3a2923cf7451058ae07a69b77` |
| SHA-256 | `8de2d51797f113896007d6ed8c634d99f5cee4c34c2bf55b1e4c19432afcbab3` |
| SHA3-384 | `5a8b7b1ef8d7dad7cdd8e168caed8097e94c3f959f81082cf24d8abb3367825dee6d49f2a669339587f92b2273ac438d` |
| IMPHASH | `d61098bb34ea41207b7b575f9f5f033b` |
| TLSH | `T1CB866B21B54ACC26D1AD06B85D2C9F9AD23C6D261B2184DB72FE7F5E16364C23236F13` |
| SSDEEP | `196608:dOt5LgwyaVFZ5AejK9Z6aHm+ByHXDmKuemuUIBqYSqSbhK:dOt5LgwyaPEejK9Z6aPcCKuemuTBHDSU` |
| ICON-DHASH | `6d6de9c7b1b0a2c0` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_078_8de2d517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de2d51797f113896007d6ed8c634d99f5cee4c34c2bf55b1e4c19432afcbab3"
    family = "ValleyRAT"
    file_name = "C5940ABAE3FB2C368F0841417C9B0454.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:32"
  condition:
    hash.sha256(0, filesize) == "8de2d51797f113896007d6ed8c634d99f5cee4c34c2bf55b1e4c19432afcbab3"
}
```

### Sample 79: `1d0b8f081975cc9d`

| Field | Value |
|---|---|
| SHA-256 | `1d0b8f081975cc9dfb542c8da5d173c3a68a23531e83f07e86ccc706e56d76f3` |
| Family label | `ValleyRAT` |
| File name | `B33A668328313F6843B1B8094BFAFFE3.exe` |
| File type | `exe` |
| First seen | `2026-08-04 21:45:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b33a668328313f6843b1b8094bfaffe3` |
| SHA-1 | `9681a8e07a3f673e5fad0cd3fd844ed67422ee0d` |
| SHA-256 | `1d0b8f081975cc9dfb542c8da5d173c3a68a23531e83f07e86ccc706e56d76f3` |
| SHA3-384 | `b007d69d6441dd366bd034ec50dd55846c9a029fb7f19c1c7c537ac5bd25b2f42c1ee5784790ce0d01ff1cb230e8f7b8` |
| IMPHASH | `40ab50289f7ef5fae60801f88d4541fc` |
| TLSH | `T16A160213B28BE43EE05E0B370572A26494FBB7656127ED1697E0889CCF661502E3FB47` |
| SSDEEP | `98304:3rYNP16C0RSAqUcfQCS1bNmVnLLa4OHb5fO36rojDTg:bYF4CLAtp7pNmVnOO33jng` |
| ICON-DHASH | `b292849696969e8e` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_079_1d0b8f08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d0b8f081975cc9dfb542c8da5d173c3a68a23531e83f07e86ccc706e56d76f3"
    family = "ValleyRAT"
    file_name = "B33A668328313F6843B1B8094BFAFFE3.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:28"
  condition:
    hash.sha256(0, filesize) == "1d0b8f081975cc9dfb542c8da5d173c3a68a23531e83f07e86ccc706e56d76f3"
}
```

### Sample 80: `931ce3beac7484c2`

| Field | Value |
|---|---|
| SHA-256 | `931ce3beac7484c2bab59eb90ee0b8230823a2f7b0dbfd6ffd4296767b0640b8` |
| Family label | `ValleyRAT` |
| File name | `47A4F35908F85C4A3FBE536341989D7A.dll` |
| File type | `dll` |
| First seen | `2026-08-04 21:45:24` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47a4f35908f85c4a3fbe536341989d7a` |
| SHA-1 | `6c05f1d4a1d5ab6414f2df877978cf253c2f2d30` |
| SHA-256 | `931ce3beac7484c2bab59eb90ee0b8230823a2f7b0dbfd6ffd4296767b0640b8` |
| SHA3-384 | `5879018a51e69e4b133dbf03c88d87b354e76a4b4dfb06bc9a929cba8ebeb298f6aff54651775699786139359516a9ff` |
| IMPHASH | `3d78bbe1faa6a6dae6c4cb9020627809` |
| TLSH | `T1EF746C21B291C236D5AE1130A679DB7B0D7D78310BE5D0CBA3D04E6E1E217E2EE3475A` |
| SSDEEP | `6144:8n+06yirywPV6q6KRIb1qkNMJ5A8S0+z2oQ9UeFMr:Ah6yiBP3DkK5A8S0+2ouU` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_080_931ce3be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "931ce3beac7484c2bab59eb90ee0b8230823a2f7b0dbfd6ffd4296767b0640b8"
    family = "ValleyRAT"
    file_name = "47A4F35908F85C4A3FBE536341989D7A.dll"
    file_type = "dll"
    first_seen = "2026-08-04 21:45:24"
  condition:
    hash.sha256(0, filesize) == "931ce3beac7484c2bab59eb90ee0b8230823a2f7b0dbfd6ffd4296767b0640b8"
}
```

### Sample 81: `3e6b5327d9d19cdc`

| Field | Value |
|---|---|
| SHA-256 | `3e6b5327d9d19cdcd8adf389b991cba090c49bd9f11d4909da89e19420c16b42` |
| Family label | `ValleyRAT` |
| File name | `83A191C82A700BD83128F7AD8576A1CD.dll` |
| File type | `dll` |
| First seen | `2026-08-04 21:45:21` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83a191c82a700bd83128f7ad8576a1cd` |
| SHA-1 | `5cdbcbbd73e6c239fd73ee8597e0e57d7c4182f5` |
| SHA-256 | `3e6b5327d9d19cdcd8adf389b991cba090c49bd9f11d4909da89e19420c16b42` |
| SHA3-384 | `1c346217998c399a5a6cf8d58e7f555ed1dfa12e23a7409043bb749a2d6ab88961afec9aad4794c0568e88682e376f99` |
| IMPHASH | `3d78bbe1faa6a6dae6c4cb9020627809` |
| TLSH | `T119747C21B291C236D5AE1134A679DB7B0D7D78310BE5D0CBA3D04A6E1E213E2EF3475A` |
| SSDEEP | `6144:Wn+06yirywPV6q6KRIb1qkNMJ5A8S0+z2oQHUeFMr:mh6yiBP3DkK5A8S0+2oIU` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_081_3e6b5327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e6b5327d9d19cdcd8adf389b991cba090c49bd9f11d4909da89e19420c16b42"
    family = "ValleyRAT"
    file_name = "83A191C82A700BD83128F7AD8576A1CD.dll"
    file_type = "dll"
    first_seen = "2026-08-04 21:45:21"
  condition:
    hash.sha256(0, filesize) == "3e6b5327d9d19cdcd8adf389b991cba090c49bd9f11d4909da89e19420c16b42"
}
```

### Sample 82: `a85a685e87533194`

| Field | Value |
|---|---|
| SHA-256 | `a85a685e8753319479922d6098726906804dca6a518205ed70fd555c5289d743` |
| Family label | `DCRat` |
| File name | `0a3e2c2bd38771605cb2eeae9c8cbc62.exe` |
| File type | `exe` |
| First seen | `2026-08-04 21:45:17` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a3e2c2bd38771605cb2eeae9c8cbc62` |
| SHA-1 | `9a271677e5d66df8d0b7d0677893d69ce9ab72f1` |
| SHA-256 | `a85a685e8753319479922d6098726906804dca6a518205ed70fd555c5289d743` |
| SHA3-384 | `ef5f9b6bf70d8bdf2814efa969e449570f1bfacb427dc0569a2eaa877ed3d019267b60316b88b5b75161ec3471a5f618` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E4E5D0017E45CE01F0091273C2EF494847B9A95166A6E31FBDBA37AE65523E73C0DACB` |
| SSDEEP | `49152:0iLfjgg4P/r0AXH3gyMaElS0a+yqQKrvVkOPR3QdE0QynCsAJWVPT7djEPt:bfjgrLJgyelE43/0LnCbYVrBjEPt` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_082_a85a685e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85a685e8753319479922d6098726906804dca6a518205ed70fd555c5289d743"
    family = "DCRat"
    file_name = "0a3e2c2bd38771605cb2eeae9c8cbc62.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:17"
  condition:
    hash.sha256(0, filesize) == "a85a685e8753319479922d6098726906804dca6a518205ed70fd555c5289d743"
}
```

### Sample 83: `5d8b365ca864c693`

| Field | Value |
|---|---|
| SHA-256 | `5d8b365ca864c693f967e2b087db0838dea3cb639325ae9be1df085b771f8796` |
| Family label | `RemcosRAT` |
| File name | `Order Specicifications-request for AYB64537.J.js` |
| File type | `js` |
| First seen | `2026-08-04 21:45:14` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa401024b25cfc7e0a62134ff7ff71e3` |
| SHA-1 | `d5b0fe65a71d1493c87bb3205a55504209868b9a` |
| SHA-256 | `5d8b365ca864c693f967e2b087db0838dea3cb639325ae9be1df085b771f8796` |
| SHA3-384 | `281f8713ba7ba8864400df5caed6f3f924d5a3598b1eddddaee0d084d4927a90a67fb025df971ab6724992ea56c08ded` |
| TLSH | `T1361629D2279591727721BBAD923ECD319A0EA15318C2CF1471ADE608376CD4FA358EE3` |
| SSDEEP | `98304:pkpKh34Cmue98+14wNtzeIuarxW/ZGITowutjREG/Fy35K5TRfRxKzO+OiQfa94I:+A6CW6EzeIuarxW/AjptjuG/A52KTwa/` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_083_5d8b365c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8b365ca864c693f967e2b087db0838dea3cb639325ae9be1df085b771f8796"
    family = "RemcosRAT"
    file_name = "Order Specicifications-request for AYB64537.J.js"
    file_type = "js"
    first_seen = "2026-08-04 21:45:14"
  condition:
    hash.sha256(0, filesize) == "5d8b365ca864c693f967e2b087db0838dea3cb639325ae9be1df085b771f8796"
}
```

### Sample 84: `1f0ed64ac1128b10`

| Field | Value |
|---|---|
| SHA-256 | `1f0ed64ac1128b10a54ad87cf10d1145bf56e7046b1eb7da1ff5162a0661dc8a` |
| Family label | `Pony` |
| File name | `FEE9A1FF4882BA692E235A8CE1E525B1.exe` |
| File type | `exe` |
| First seen | `2026-08-04 21:45:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, Pony` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fee9a1ff4882ba692e235a8ce1e525b1` |
| SHA-1 | `3da11f13d831adda99b81fd43583c57ccb0474ab` |
| SHA-256 | `1f0ed64ac1128b10a54ad87cf10d1145bf56e7046b1eb7da1ff5162a0661dc8a` |
| SHA3-384 | `2eb172c312aeacccf8e10ceb761ac29e3425b3f8c240cd94a83656373066951064dd9820f658b14d0840f2e63374bccc` |
| IMPHASH | `6d809cf712ffd89f86be8f79e3bcd47d` |
| TLSH | `T15783F803F4C1E0F2C1A216712BC11770F7FDAEA9BC764D5FEF8C5585ADA2296AB12052` |
| SSDEEP | `1536:vIGto2wQwgqTt/vV07lBfbmcTD9OemOU/TvekzbQTl2/C:A67kwBfbmVOAY4/C` |

#### Technical Assessment

- The sample is tracked as `Pony` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Pony_084_1f0ed64a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f0ed64ac1128b10a54ad87cf10d1145bf56e7046b1eb7da1ff5162a0661dc8a"
    family = "Pony"
    file_name = "FEE9A1FF4882BA692E235A8CE1E525B1.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:09"
  condition:
    hash.sha256(0, filesize) == "1f0ed64ac1128b10a54ad87cf10d1145bf56e7046b1eb7da1ff5162a0661dc8a"
}
```

### Sample 85: `93cfcf58ba02b670`

| Field | Value |
|---|---|
| SHA-256 | `93cfcf58ba02b6704041d8e036b4230a4ba9561723c5e7e8fdce681684864870` |
| Family label | `Pony` |
| File name | `A06194A36273470E5BEDEBE9D313B951.exe` |
| File type | `exe` |
| First seen | `2026-08-04 21:45:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, Pony` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a06194a36273470e5bedebe9d313b951` |
| SHA-1 | `a21226a0e754f7f27579c17e4f1f35ed7a1d978e` |
| SHA-256 | `93cfcf58ba02b6704041d8e036b4230a4ba9561723c5e7e8fdce681684864870` |
| SHA3-384 | `58b355a4af39e181a633016e115257bad262aea08333b188e5e29785cf42aed2b25614f0f6d95999fd98d9f1f84adc0a` |
| IMPHASH | `6d809cf712ffd89f86be8f79e3bcd47d` |
| TLSH | `T10883F803F4C1E0F2C1A216712BC11770F7FDAEA9BC764D5FEF8C5585ADA2296AB12052` |
| SSDEEP | `1536:9IGto2wQwgqTt/vV07lBfbmcTD9OemOU/TvekzbQTl2/C:667kwBfbmVOAY4/C` |

#### Technical Assessment

- The sample is tracked as `Pony` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Pony_085_93cfcf58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93cfcf58ba02b6704041d8e036b4230a4ba9561723c5e7e8fdce681684864870"
    family = "Pony"
    file_name = "A06194A36273470E5BEDEBE9D313B951.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:06"
  condition:
    hash.sha256(0, filesize) == "93cfcf58ba02b6704041d8e036b4230a4ba9561723c5e7e8fdce681684864870"
}
```

### Sample 86: `97b2a7b78f98521a`

| Field | Value |
|---|---|
| SHA-256 | `97b2a7b78f98521a1436c44adb0f717b84364f67f4444b22d544caa2eba8811b` |
| Family label | `NanoCore` |
| File name | `23d82b604133932ba4391ae7fb344dd0.exe` |
| File type | `exe` |
| First seen | `2026-08-04 21:40:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23d82b604133932ba4391ae7fb344dd0` |
| SHA-1 | `9b75143b3e4e331a0de2796dc06ac888c55b0dca` |
| SHA-256 | `97b2a7b78f98521a1436c44adb0f717b84364f67f4444b22d544caa2eba8811b` |
| SHA3-384 | `696abc47e96765277d2f4961ad4586ea58a0c93751bc113081e84e4b1da5d193caef01ad3cecd9e124c7d69abf8253e5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CE14CF1637A84A2FD2DE86BD611202139379C2E3A8C3F7DE28D455B79F667E50A070D3` |
| SSDEEP | `6144:gLV6Bta6dtJmakIM5kEcNr2JvU639Wn2a2:gLV6BtpmkmcNr6lNc0` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_086_97b2a7b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b2a7b78f98521a1436c44adb0f717b84364f67f4444b22d544caa2eba8811b"
    family = "NanoCore"
    file_name = "23d82b604133932ba4391ae7fb344dd0.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:40:05"
  condition:
    hash.sha256(0, filesize) == "97b2a7b78f98521a1436c44adb0f717b84364f67f4444b22d544caa2eba8811b"
}
```

### Sample 87: `b481cc2e88ab19b6`

| Field | Value |
|---|---|
| SHA-256 | `b481cc2e88ab19b63fca837aef5d80b961659621db8650ee307305062b4eeb41` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 21:33:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b59686479528d4aabc65f98ab2ee479b` |
| SHA-1 | `21308bc38b389ed859040ca70c776995a75a2642` |
| SHA-256 | `b481cc2e88ab19b63fca837aef5d80b961659621db8650ee307305062b4eeb41` |
| SHA3-384 | `462820349ccfccbe0f69aa27eb564a27f27b0e729e227c4abbcd6da708544f5155320bbc03eff437227a45a283459f3a` |
| TLSH | `T1E1845B93F6A228FCD952C930825D6513E638744943126AFB27C8EB753E16ED06F3EB50` |
| TELFHASH | `t19fa159b0418b65f8d592e5d5cfb2b72296b203e567546930813dfc70ee02fe4b965c03` |
| SSDEEP | `6144:HAVAAOAggqG0NFGN9rh5IZcF5zoJgha/phZNg8LOUuNC1rq5DF7OpQ:Hi1CBLnGPh5ImPsN/9bLOUWCotO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_b481cc2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b481cc2e88ab19b63fca837aef5d80b961659621db8650ee307305062b4eeb41"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 21:33:45"
  condition:
    hash.sha256(0, filesize) == "b481cc2e88ab19b63fca837aef5d80b961659621db8650ee307305062b4eeb41"
}
```

### Sample 88: `844b854d590e9ebe`

| Field | Value |
|---|---|
| SHA-256 | `844b854d590e9ebe4ae09a7233125f473ce3b05312bce3374b5f05c7d50d123a` |
| Family label | `Mirai` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-08-04 21:33:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbac2ea950c7313c7ad5ab041fa1eae8` |
| SHA-1 | `8e466d1addc4e1e31b4cc5109c7818bf2ff1e678` |
| SHA-256 | `844b854d590e9ebe4ae09a7233125f473ce3b05312bce3374b5f05c7d50d123a` |
| SHA3-384 | `2272ca06ccd42ebb00e592f56ad0ad9e193e20c1b6b8d50d01c53c998c243e2e9c8d308fc711c3de70a88027ba548556` |
| TLSH | `T15DF3E60ABB600FF7D8ABDD7702EA0B1129CCA95725B43B797534E818B50B58B4AD3C74` |
| SSDEEP | `1536:KRL+5d2HrbdPsoCNbhWaZ/m1L5qe0N8TDMLbtUwG/H4BBoZWPlZ4Dph7PCdu+V3X:cJL5PsApjrYBBtliphEvJR2EV2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_844b854d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "844b854d590e9ebe4ae09a7233125f473ce3b05312bce3374b5f05c7d50d123a"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 21:33:42"
  condition:
    hash.sha256(0, filesize) == "844b854d590e9ebe4ae09a7233125f473ce3b05312bce3374b5f05c7d50d123a"
}
```

### Sample 89: `6c65afb1eb421e19`

| Field | Value |
|---|---|
| SHA-256 | `6c65afb1eb421e192dd0b6ab9fa187b0973d43f10763279dd7f60098ec1acd69` |
| Family label | `Mirai` |
| File name | `data_mips` |
| File type | `elf` |
| First seen | `2026-08-04 21:33:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e0d48babde7905f11ff1935b9b3a44` |
| SHA-1 | `97e7dbc7907fbe703e3144234779a8b1067037db` |
| SHA-256 | `6c65afb1eb421e192dd0b6ab9fa187b0973d43f10763279dd7f60098ec1acd69` |
| SHA3-384 | `b3d0009b817ac4dfc54c70953797b4dc874a246e667c55631c1852f53f49e24b872b44bcd9e553d5b6362ec0c8f27e01` |
| TLSH | `T16DF3975A6E228F7EF369877147B78E20975977D616E1C680E2ACD5001F202CE641FFB8` |
| TELFHASH | `t17c4192080db817e0b6396c59045dfb67d6a330de7e266c238f21e86aa769b435d14c1d` |
| SSDEEP | `3072:UMVklUaZLaRzRbIj4AAD+C3pnt8JoFT2E2VAY9W:5VklUIGRzR0j4QynXV2E2CKW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_6c65afb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c65afb1eb421e192dd0b6ab9fa187b0973d43f10763279dd7f60098ec1acd69"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-04 21:33:40"
  condition:
    hash.sha256(0, filesize) == "6c65afb1eb421e192dd0b6ab9fa187b0973d43f10763279dd7f60098ec1acd69"
}
```

### Sample 90: `b19eb2605a969acd`

| Field | Value |
|---|---|
| SHA-256 | `b19eb2605a969acda3bd284d2376acc657c3a556d4c81ce17eaaabe39d48b990` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 21:25:07` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `994bceb67f526c2ad2a4d4d304bf0cb8` |
| SHA-1 | `712ab4371b1979c2104280e21e57842a70ab9f63` |
| SHA-256 | `b19eb2605a969acda3bd284d2376acc657c3a556d4c81ce17eaaabe39d48b990` |
| SHA3-384 | `d9e0b477261e7fb0f19ab1b6dd083eca2f47de48d4fa614d023bbd71253f4678972702d47ba38fe714b1d9317074e4a4` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1E932D51E2E460331DE5008B4E575864A513C1EE37393EBDBE633E5DB0AD6E4584C1AAF` |
| SSDEEP | `192:YhIo2WbtBwLxeuqMaugPFJxTEZmFhEucS:po5oAJzugPFwZ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_090_b19eb260
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19eb2605a969acda3bd284d2376acc657c3a556d4c81ce17eaaabe39d48b990"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 21:25:07"
  condition:
    hash.sha256(0, filesize) == "b19eb2605a969acda3bd284d2376acc657c3a556d4c81ce17eaaabe39d48b990"
}
```

### Sample 91: `0d298a65db890328`

| Field | Value |
|---|---|
| SHA-256 | `0d298a65db890328d0357b2fb39ea7352645a994a601f430c38450769635f957` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-04 21:22:42` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX7.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4264991601686145d9e14f36c1e7b3d9` |
| SHA-1 | `feb272114aba399e891d551603b195c4bce264c7` |
| SHA-256 | `0d298a65db890328d0357b2fb39ea7352645a994a601f430c38450769635f957` |
| SHA3-384 | `86a23024faed29ba7bb9199b77e4b95f3eb68c45c4499530923806ec699b14f45aceadce86832b277d60ce373a755d12` |
| IMPHASH | `d9c0bfb4053066384ee7484b4c2917f9` |
| TLSH | `T143A533800BC87843DC9E83F7EC9526A25768557157A96C03827752092EB773BF3B02AF` |
| SSDEEP | `49152:bO+wxA1pzE9o3xJPMwSjlRyauLF1n7dgG75JUTe8dkXioeLS7/tugRs98Lb2az34:yJqzz0Cx1MNKfnh/lXLZUrCbVz3Dc` |
| ICON-DHASH | `30f8cc8e8eccf030` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_091_0d298a65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d298a65db890328d0357b2fb39ea7352645a994a601f430c38450769635f957"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 21:22:42"
  condition:
    hash.sha256(0, filesize) == "0d298a65db890328d0357b2fb39ea7352645a994a601f430c38450769635f957"
}
```

### Sample 92: `b7db32e16aa207e3`

| Field | Value |
|---|---|
| SHA-256 | `b7db32e16aa207e3643f6f9a1b076e7b8ffdb8166ff5e76fe966ae0c94638ac0` |
| Family label | `Mirai` |
| File name | `boatnet.mips` |
| File type | `elf` |
| First seen | `2026-08-04 21:17:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5a368edff2c23f939ba18141a640044` |
| SHA-1 | `3915a69048bc216d004a70ad163929a0ef43d293` |
| SHA-256 | `b7db32e16aa207e3643f6f9a1b076e7b8ffdb8166ff5e76fe966ae0c94638ac0` |
| SHA3-384 | `7d1905838b2252d4cbb18224dca1cf5300901450dfe7acca09be1a68a49d665a96223cd035eaccab02c40e01fed4edbb` |
| TLSH | `T130A3D61FAE058FBDF759C63407FB8E21969833C72AA1D581E17CD2105E6028E641FFA8` |
| TELFHASH | `t1d611a14c8a7413e4a7365ce9186eeb77e16131dd67326c234f01aca8ebadd814e10c0c` |
| SSDEEP | `1536:wb9iiB0QEn3XxThWXZp+3xd0gVaFqfm8eoN/D8WsD:piIXxUZp+70gVVfmmwWsD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_b7db32e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7db32e16aa207e3643f6f9a1b076e7b8ffdb8166ff5e76fe966ae0c94638ac0"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-04 21:17:02"
  condition:
    hash.sha256(0, filesize) == "b7db32e16aa207e3643f6f9a1b076e7b8ffdb8166ff5e76fe966ae0c94638ac0"
}
```

### Sample 93: `6e7d98f590da5a91`

| Field | Value |
|---|---|
| SHA-256 | `6e7d98f590da5a91bf0285d31002b80fb373a88aa1c355e63da5f6a4bd8f46c1` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-08-04 21:16:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4afa66fb709cfb1bd01ecc5d93cd2ac1` |
| SHA-1 | `f83615174d6e2cfe488fbf076310baf2b131cdbb` |
| SHA-256 | `6e7d98f590da5a91bf0285d31002b80fb373a88aa1c355e63da5f6a4bd8f46c1` |
| SHA3-384 | `2b05258920846afaa690039186c9618dc776fbf4ae14e49d8d2f627f81cb95dfcba2fe8f69d32fa4b80ad8e0386c9e98` |
| TLSH | `T1A5F34D46EB418A13C4D61776BAEF42453323A7A493DB330699287FF43F8279E0D63A45` |
| TELFHASH | `t137310eb5133691055aa1cd9889fda7b5112cc2131782ff73ef15c8dc141a04ee62ac4f` |
| SSDEEP | `3072:cIflfpp10ZmOcaTelZHYJtDOW+D2zQDq89DM/9iHLvB:cglfppyZzcaTelZHY3DOUQDq8JM/94vB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_6e7d98f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e7d98f590da5a91bf0285d31002b80fb373a88aa1c355e63da5f6a4bd8f46c1"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:59"
  condition:
    hash.sha256(0, filesize) == "6e7d98f590da5a91bf0285d31002b80fb373a88aa1c355e63da5f6a4bd8f46c1"
}
```

### Sample 94: `668ecef78b39f2b1`

| Field | Value |
|---|---|
| SHA-256 | `668ecef78b39f2b1b602b54d4701546dfb5c6b0701449bb3d8282fc845b4e029` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-08-04 21:16:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d985376e3c8b5df1b01fb9f8c1ae8a7` |
| SHA-1 | `2ed049fc280487e590f144ff98aa2cda82992b11` |
| SHA-256 | `668ecef78b39f2b1b602b54d4701546dfb5c6b0701449bb3d8282fc845b4e029` |
| SHA3-384 | `d9a33b3c9ebdf1041268d569616f253c2b47dfe973620736507114f490b13f22cf12bb58e3fb72f5ef51135b74eabe5a` |
| TLSH | `T148833A95FC829613C5D512BBFA6E428D3B3A13E8E2DB3207DD215F207B8681B0D77A45` |
| TELFHASH | `t124b0924a4fb819beb664434e818e11395898b81a6f26a03c95f05f42c8e5898f065981` |
| SSDEEP | `1536:sYenZos47kNsK8/NZ44jHrTdu7CnkylOrP3wRPFl2vk04:PenZos49NzHdqFH44V4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_668ecef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668ecef78b39f2b1b602b54d4701546dfb5c6b0701449bb3d8282fc845b4e029"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:56"
  condition:
    hash.sha256(0, filesize) == "668ecef78b39f2b1b602b54d4701546dfb5c6b0701449bb3d8282fc845b4e029"
}
```

### Sample 95: `111c0e6222dfb48f`

| Field | Value |
|---|---|
| SHA-256 | `111c0e6222dfb48fa9cb3e4b9f89f7ca8d610c5ef8dd337e6f810d06a1217b77` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-08-04 21:16:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8306b3a2d18320a7db5e465b497d5bd2` |
| SHA-1 | `64645824ddeb2b7df0d6325037502e35343a8a99` |
| SHA-256 | `111c0e6222dfb48fa9cb3e4b9f89f7ca8d610c5ef8dd337e6f810d06a1217b77` |
| SHA3-384 | `f0d486dc46c61df358ed1360ae4c85ad1dcf1961d6b6bfaa1eb8f8dbc936f085da267fd2be2969edc67c694dc84d399c` |
| TLSH | `T1EA836C02B31C0A47D1A31DB02B3F5BD093FAA5E121E4B689791EAB969671D331586FCC` |
| SSDEEP | `1536:SS9vDk4NJAS09ZR3+fKXqD6i5Ip22FXT/Kcd6NNlDdyubhZ2v:hkmcZR+MqD2bFjyNBy02v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_111c0e62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "111c0e6222dfb48fa9cb3e4b9f89f7ca8d610c5ef8dd337e6f810d06a1217b77"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:52"
  condition:
    hash.sha256(0, filesize) == "111c0e6222dfb48fa9cb3e4b9f89f7ca8d610c5ef8dd337e6f810d06a1217b77"
}
```

### Sample 96: `45d4f75e7486a914`

| Field | Value |
|---|---|
| SHA-256 | `45d4f75e7486a914b9f9125b87e427dd62eb4c9c8acb1b2f8cfb5ffbb7577ed1` |
| Family label | `Mirai` |
| File name | `boatnet.x86_64` |
| File type | `elf` |
| First seen | `2026-08-04 21:16:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b172779c8fd392625e46ece2dfd41bd5` |
| SHA-1 | `b74c638a5a5b5daa4692e9c2b5a922e201a37da1` |
| SHA-256 | `45d4f75e7486a914b9f9125b87e427dd62eb4c9c8acb1b2f8cfb5ffbb7577ed1` |
| SHA3-384 | `908a638e1da1d48eba25c840ff4715eb5b3c508a8232461ff7c5f00acb666e7edb1a61cf011864ffdd9fce57708ab13f` |
| TLSH | `T1D4634BC1E243D0F5D817017121B7F7379E36E2F9111AD64BF7A88E72AE62602A516BCC` |
| TELFHASH | `t15721c2ff5a7a1df4a7e4b900c30e2b21384aeb7b187076a15663d934216edc194adc39` |
| SSDEEP | `1536:J+sa6jFk5ssXrFZ8Fyc9VG42Ptd+g3j3JwZh5PRZBSU0uV:Asa6j6Os7FuweG3PP+g3j541bau` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_45d4f75e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45d4f75e7486a914b9f9125b87e427dd62eb4c9c8acb1b2f8cfb5ffbb7577ed1"
    family = "Mirai"
    file_name = "boatnet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:41"
  condition:
    hash.sha256(0, filesize) == "45d4f75e7486a914b9f9125b87e427dd62eb4c9c8acb1b2f8cfb5ffbb7577ed1"
}
```

### Sample 97: `3252b9d9d5761506`

| Field | Value |
|---|---|
| SHA-256 | `3252b9d9d57615060976d4b3bed8684dd59539a0d0cc5616564f132859cb2b5e` |
| Family label | `Mirai` |
| File name | `boatnet.arm5` |
| File type | `elf` |
| First seen | `2026-08-04 21:16:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d622310f67b0815898a50cf729f5bae` |
| SHA-1 | `b7a824dd070e2f8a5c591bb527bf4bc26fba6a17` |
| SHA-256 | `3252b9d9d57615060976d4b3bed8684dd59539a0d0cc5616564f132859cb2b5e` |
| SHA3-384 | `fedf56c1ffa47aa16c3450f6a0312cbf333c5dafb21c91f5edb58b86df2e24f3b9dfebab815aaa8610f5834e0d2602d7` |
| TLSH | `T1C4432995BD824627C1D062BABAAE5A8C373523F8D2CB7227D8314B117B8550F1D77F84` |
| TELFHASH | `t1ebe0ab00fdb88b285ad38970dcac12e492406627612207219f14cae0c83f051d30d91b` |
| SSDEEP | `768:x5rRT2Uv5NzZAaLAYJd/hNduSneNTUbKUl8kNx+MUvh/CN9EHcMUNA5oecEw/:x+C51ZlLAU/ZAUlxNxqCMc9SEl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_3252b9d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3252b9d9d57615060976d4b3bed8684dd59539a0d0cc5616564f132859cb2b5e"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:37"
  condition:
    hash.sha256(0, filesize) == "3252b9d9d57615060976d4b3bed8684dd59539a0d0cc5616564f132859cb2b5e"
}
```

### Sample 98: `ae4525d81a9b2b1b`

| Field | Value |
|---|---|
| SHA-256 | `ae4525d81a9b2b1ba4e53b778344f1e412c1ead8ddc3eec317bbf41c18514680` |
| Family label | `Mirai` |
| File name | `boatnet.mips` |
| File type | `elf` |
| First seen | `2026-08-04 21:15:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05a6d1afa2050cf52059528cd18b725f` |
| SHA-1 | `724830b72ba24be3ccd21aab4c6dee38e7f8dbcc` |
| SHA-256 | `ae4525d81a9b2b1ba4e53b778344f1e412c1ead8ddc3eec317bbf41c18514680` |
| SHA3-384 | `c333f58607a9695328341e3ef40a1ec36760f2b59085d8be5507597b6f0357f081e5cd404382c0453a384e90495a9a48` |
| TLSH | `T13103F11876075364DF8AC83FFBB4037229970AEB4083EC459681D9564EDAB2678CF98D` |
| SSDEEP | `768:b27nSfHBV3z50vrABZsPM9/zmYutjC8Hb3zdVldxa0QXwDc6WxcgboAKyX4JgGlP:b27AHTukAPMBzgCsvgCgpx0yX4VJuG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_ae4525d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae4525d81a9b2b1ba4e53b778344f1e412c1ead8ddc3eec317bbf41c18514680"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-04 21:15:58"
  condition:
    hash.sha256(0, filesize) == "ae4525d81a9b2b1ba4e53b778344f1e412c1ead8ddc3eec317bbf41c18514680"
}
```

### Sample 99: `5a9589968d81f208`

| Field | Value |
|---|---|
| SHA-256 | `5a9589968d81f208848a2bbf9d701f99b27ae151876be0fa79fa1809cf5a538b` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-08-04 21:15:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a46d3b467c60c86ad901fb56e44cae63` |
| SHA-1 | `e6f177e152789f55aacc421863132dca8180cfac` |
| SHA-256 | `5a9589968d81f208848a2bbf9d701f99b27ae151876be0fa79fa1809cf5a538b` |
| SHA3-384 | `0b327c0b3544c89bb80022fb36146cf483a36d6608d5f2c459ca2ba8c655cb72f4ae6e7a443bbc7c2fc504ee989e3e4a` |
| TLSH | `T18F53021D9777C970C3301C7AC9E61D94435B7EF692EB3D3B9298E608B5024067F69A83` |
| SSDEEP | `1536:wXTIVuTttjYJ7tWhmgOH3LcKyHQmXYww+zVp2:wXTcIKchmRLcjDXBwip2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_5a958996
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a9589968d81f208848a2bbf9d701f99b27ae151876be0fa79fa1809cf5a538b"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-04 21:15:57"
  condition:
    hash.sha256(0, filesize) == "5a9589968d81f208848a2bbf9d701f99b27ae151876be0fa79fa1809cf5a538b"
}
```

### Sample 100: `aabfd94ac3d68386`

| Field | Value |
|---|---|
| SHA-256 | `aabfd94ac3d68386aa56acff0742e2578bc5f39a2f0a75691c5123afc188765c` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-08-04 21:15:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4be389b7d8c729f87c54324f3138d11c` |
| SHA-1 | `84365ef35bad186ddf2428b6ae51be9eff9e1a3c` |
| SHA-256 | `aabfd94ac3d68386aa56acff0742e2578bc5f39a2f0a75691c5123afc188765c` |
| SHA3-384 | `97afe3665fd56734a61fcbeb7788e9ab30b9a665afa712c39486f6dcabe566aac56123be229789c58972887f36e09c26` |
| TLSH | `T18403F1B92CE295E0DD34547E6E698160AFA786F852D072BE3A080F37D1C1627837C2D7` |
| SSDEEP | `768:PE8Ng0W5sKpNWdVh9FXPOOLWrqe+tT3urY8QEfIcNNuEs3UozU:cUxW5XYPVLWrqQY8Q7kuhzU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_aabfd94a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aabfd94ac3d68386aa56acff0742e2578bc5f39a2f0a75691c5123afc188765c"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-04 21:15:56"
  condition:
    hash.sha256(0, filesize) == "aabfd94ac3d68386aa56acff0742e2578bc5f39a2f0a75691c5123afc188765c"
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
 * Generated: 2026-08-05T03:39:15.852148+00:00
 */

rule MalwareBazaar_Mirai_001_e0be3f66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0be3f6600d16a77b705cc780dde976839e605c8c44b7205af301f0bab4287ef"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-05 03:22:34"
  condition:
    hash.sha256(0, filesize) == "e0be3f6600d16a77b705cc780dde976839e605c8c44b7205af301f0bab4287ef"
}

rule MalwareBazaar_Mirai_002_8beb744a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8beb744ad418cf0304095aead056fde47dcb889ed917b78559c8c0c68dffe581"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-05 03:21:47"
  condition:
    hash.sha256(0, filesize) == "8beb744ad418cf0304095aead056fde47dcb889ed917b78559c8c0c68dffe581"
}

rule MalwareBazaar_Mirai_003_0a9c86f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a9c86f0f73ef504afc9215b8032b4f10e356cc6d8bb20eff97413ae517faafc"
    family = "Mirai"
    file_name = "renzo.sh"
    file_type = "sh"
    first_seen = "2026-08-05 03:11:32"
  condition:
    hash.sha256(0, filesize) == "0a9c86f0f73ef504afc9215b8032b4f10e356cc6d8bb20eff97413ae517faafc"
}

rule MalwareBazaar_unknown_004_e9e1ff96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9e1ff9629e53ed07c4cb758a310d894d88c049f497bd189a058a85c8bff2a61"
    family = "unknown"
    file_name = "sensi_totolink.sh"
    file_type = "sh"
    first_seen = "2026-08-05 03:09:17"
  condition:
    hash.sha256(0, filesize) == "e9e1ff9629e53ed07c4cb758a310d894d88c049f497bd189a058a85c8bff2a61"
}

rule MalwareBazaar_unknown_005_834e241f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "834e241f797dc0f4886cfdd0b2ef6e6fbbb510d2ab5d481fbe55fedb63fd7b21"
    family = "unknown"
    file_name = "netgear"
    file_type = "sh"
    first_seen = "2026-08-05 03:09:16"
  condition:
    hash.sha256(0, filesize) == "834e241f797dc0f4886cfdd0b2ef6e6fbbb510d2ab5d481fbe55fedb63fd7b21"
}

rule MalwareBazaar_unknown_006_f0a9123f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0a9123f4a672c76a6c61a47b8ef4d991b398526c0b072f909ccc2630e0eb2de"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-05 02:52:29"
  condition:
    hash.sha256(0, filesize) == "f0a9123f4a672c76a6c61a47b8ef4d991b398526c0b072f909ccc2630e0eb2de"
}

rule MalwareBazaar_Mirai_007_135cefea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "135cefead339d5e0813e38049da8666efefef7c7b64c6ed22f5fec62b676ced1"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:28"
  condition:
    hash.sha256(0, filesize) == "135cefead339d5e0813e38049da8666efefef7c7b64c6ed22f5fec62b676ced1"
}

rule MalwareBazaar_Mirai_008_5f3709aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f3709aa1823bc153c63dc5d0bccab9fbf9e252a910a08a639e857bd9f8f0149"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:28"
  condition:
    hash.sha256(0, filesize) == "5f3709aa1823bc153c63dc5d0bccab9fbf9e252a910a08a639e857bd9f8f0149"
}

rule MalwareBazaar_Mirai_009_bebd8062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bebd8062fba5ab7163333480655f9027995ace5d4eee2bebab499d4c549923f3"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:28"
  condition:
    hash.sha256(0, filesize) == "bebd8062fba5ab7163333480655f9027995ace5d4eee2bebab499d4c549923f3"
}

rule MalwareBazaar_Mirai_010_41973e5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41973e5dc419ef5d31ba3c0b984ae22d80dddd15d3bf65696e7e0c919134430f"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:27"
  condition:
    hash.sha256(0, filesize) == "41973e5dc419ef5d31ba3c0b984ae22d80dddd15d3bf65696e7e0c919134430f"
}

rule MalwareBazaar_Mirai_011_ca2af697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca2af697388746b2381dc7c4e857ffcec86223ea4618de4583437380050d7770"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-05 02:50:27"
  condition:
    hash.sha256(0, filesize) == "ca2af697388746b2381dc7c4e857ffcec86223ea4618de4583437380050d7770"
}

rule MalwareBazaar_unknown_012_563bcacf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "563bcacf84a7c6e900023f7970caaace95bf49c91f63f76c295d32a8f9cc55bf"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-05 02:43:35"
  condition:
    hash.sha256(0, filesize) == "563bcacf84a7c6e900023f7970caaace95bf49c91f63f76c295d32a8f9cc55bf"
}

rule MalwareBazaar_unknown_013_3b3bc398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b3bc398e71b2dad7e7af96b0607b264e405f3af2ed453b251f3575a6e513fba"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-05 02:31:50"
  condition:
    hash.sha256(0, filesize) == "3b3bc398e71b2dad7e7af96b0607b264e405f3af2ed453b251f3575a6e513fba"
}

rule MalwareBazaar_unknown_014_2272cf84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2272cf84ed710394a08d70054cf2f54e96fd65af399e5addfcfdffe284266a56"
    family = "unknown"
    file_name = "lterouter"
    file_type = "unknown"
    first_seen = "2026-08-05 02:19:44"
  condition:
    hash.sha256(0, filesize) == "2272cf84ed710394a08d70054cf2f54e96fd65af399e5addfcfdffe284266a56"
}

rule MalwareBazaar_unknown_015_8c0495b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0495b2595aff4244c1c157a3f2594f12275d776509a6b49224f357b88f4270"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:20"
  condition:
    hash.sha256(0, filesize) == "8c0495b2595aff4244c1c157a3f2594f12275d776509a6b49224f357b88f4270"
}

rule MalwareBazaar_Mirai_016_9b1c0cb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1c0cb8ac7704452f06292398a65ffe9b3c901329f93ac716d7486ed8798d94"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:19"
  condition:
    hash.sha256(0, filesize) == "9b1c0cb8ac7704452f06292398a65ffe9b3c901329f93ac716d7486ed8798d94"
}

rule MalwareBazaar_Mirai_017_ab1b6934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab1b6934bc586d442ec14067cb8075b94f66e0981c41fb308758ba7949eaa437"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:17"
  condition:
    hash.sha256(0, filesize) == "ab1b6934bc586d442ec14067cb8075b94f66e0981c41fb308758ba7949eaa437"
}

rule MalwareBazaar_unknown_018_28b4e808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28b4e8084fd3eb35aa0fcf362c87c43b7b380379643c209b40015e744f5df425"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-05 02:08:15"
  condition:
    hash.sha256(0, filesize) == "28b4e8084fd3eb35aa0fcf362c87c43b7b380379643c209b40015e744f5df425"
}

rule MalwareBazaar_unknown_019_5c724000
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c724000830082753cdb5c57ae528b92350d9ff94bb0e935d17c04b9b41253ba"
    family = "unknown"
    file_name = "tbk"
    file_type = "unknown"
    first_seen = "2026-08-05 02:08:13"
  condition:
    hash.sha256(0, filesize) == "5c724000830082753cdb5c57ae528b92350d9ff94bb0e935d17c04b9b41253ba"
}

rule MalwareBazaar_unknown_020_6db4914b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db4914bfa06a112892250974b42abde5c7a096050c970a1dcbb23172ff863f6"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-05 02:01:52"
  condition:
    hash.sha256(0, filesize) == "6db4914bfa06a112892250974b42abde5c7a096050c970a1dcbb23172ff863f6"
}

rule MalwareBazaar_unknown_021_a374f3eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a374f3ebc886eda122ca1229138b8a31ce0758addb60c0dd38052e5a95b3d37d"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-05 01:58:33"
  condition:
    hash.sha256(0, filesize) == "a374f3ebc886eda122ca1229138b8a31ce0758addb60c0dd38052e5a95b3d37d"
}

rule MalwareBazaar_Prometei_022_919e2a1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769"
    family = "Prometei"
    file_name = "919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769"
    file_type = "elf"
    first_seen = "2026-08-05 01:56:19"
  condition:
    hash.sha256(0, filesize) == "919e2a1a6d1755902e4def4456e6220e9c069efc34d8bfc850f4490a5f88c769"
}

rule MalwareBazaar_Mirai_023_b6fcb33c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6fcb33c4d6193b07bcb7c595ab6209e6a935f853ba73c07212b4a4c9eff5518"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-05 01:50:32"
  condition:
    hash.sha256(0, filesize) == "b6fcb33c4d6193b07bcb7c595ab6209e6a935f853ba73c07212b4a4c9eff5518"
}

rule MalwareBazaar_unknown_024_3a6e5324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a6e532493b6e27a65591644109e2d2021d1ef4d7abae9e5f5c36244ed653d4d"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-05 01:36:32"
  condition:
    hash.sha256(0, filesize) == "3a6e532493b6e27a65591644109e2d2021d1ef4d7abae9e5f5c36244ed653d4d"
}

rule MalwareBazaar_unknown_025_367ea7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "367ea7e4e3abd64b1d89c6d4ebc82bd42b9f2b56897b093c1f0f411303c28945"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-05 01:27:46"
  condition:
    hash.sha256(0, filesize) == "367ea7e4e3abd64b1d89c6d4ebc82bd42b9f2b56897b093c1f0f411303c28945"
}

rule MalwareBazaar_unknown_026_fc04a6d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc04a6d3555001a8f04cf75dcdc1cb2de12f530d78603c31aadea81fb26312a3"
    family = "unknown"
    file_name = "MV ANNA SCHULTE VESSEL Q88 PARTICULARS.js"
    file_type = "js"
    first_seen = "2026-08-05 01:26:34"
  condition:
    hash.sha256(0, filesize) == "fc04a6d3555001a8f04cf75dcdc1cb2de12f530d78603c31aadea81fb26312a3"
}

rule MalwareBazaar_Mirai_027_ba584221
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba584221459b0f1a6359864f3addeca070259f707eb402f26e945565eb25852d"
    family = "Mirai"
    file_name = "main.mipsel"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:51"
  condition:
    hash.sha256(0, filesize) == "ba584221459b0f1a6359864f3addeca070259f707eb402f26e945565eb25852d"
}

rule MalwareBazaar_Mirai_028_0eda0c61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eda0c619807b5d9f641b253338fbc9574a31d7573b979d4dc63dec16bc29399"
    family = "Mirai"
    file_name = "main.x86_64"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:49"
  condition:
    hash.sha256(0, filesize) == "0eda0c619807b5d9f641b253338fbc9574a31d7573b979d4dc63dec16bc29399"
}

rule MalwareBazaar_unknown_029_c8f50aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8f50aebfc5cf9506e58593afcee45d98aa2a1e142644aabf316e46c61374f95"
    family = "unknown"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:48"
  condition:
    hash.sha256(0, filesize) == "c8f50aebfc5cf9506e58593afcee45d98aa2a1e142644aabf316e46c61374f95"
}

rule MalwareBazaar_unknown_030_93fd29a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93fd29a33fb0d14b9b55b6b8cbbfab61bae8dcc14745d03ec7138207cc84b9ad"
    family = "unknown"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-08-05 01:12:46"
  condition:
    hash.sha256(0, filesize) == "93fd29a33fb0d14b9b55b6b8cbbfab61bae8dcc14745d03ec7138207cc84b9ad"
}

rule MalwareBazaar_unknown_031_ae2a66ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2a66ca651b574132c6d29b0bcb714bc2b2855d52f139fcd4d03e1e5d3c12ea"
    family = "unknown"
    file_name = "main.armv4"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:44"
  condition:
    hash.sha256(0, filesize) == "ae2a66ca651b574132c6d29b0bcb714bc2b2855d52f139fcd4d03e1e5d3c12ea"
}

rule MalwareBazaar_Mirai_032_808c6fdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "808c6fdb337af1c24a141b3a2a1006041575d0bfe260b055a70d003c3806eac6"
    family = "Mirai"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:43"
  condition:
    hash.sha256(0, filesize) == "808c6fdb337af1c24a141b3a2a1006041575d0bfe260b055a70d003c3806eac6"
}

rule MalwareBazaar_Mirai_033_2fa9fb85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fa9fb858fac4b501006e2f787e0af1ebd591be08ad08f86eb97348329bca3c7"
    family = "Mirai"
    file_name = "main.armv5"
    file_type = "elf"
    first_seen = "2026-08-05 01:12:41"
  condition:
    hash.sha256(0, filesize) == "2fa9fb858fac4b501006e2f787e0af1ebd591be08ad08f86eb97348329bca3c7"
}

rule MalwareBazaar_Mirai_034_a1364a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1364a57e9114843e6a6707b196d5b824d48737abb66d6f3621215b6b0ebfecc"
    family = "Mirai"
    file_name = "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
    file_type = "elf"
    first_seen = "2026-08-05 01:01:49"
  condition:
    hash.sha256(0, filesize) == "a1364a57e9114843e6a6707b196d5b824d48737abb66d6f3621215b6b0ebfecc"
}

rule MalwareBazaar_unknown_035_05307645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "053076456278fcab8a1820126d590986170a08754eb301dbaff9b8184bedc2fb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-05 01:00:43"
  condition:
    hash.sha256(0, filesize) == "053076456278fcab8a1820126d590986170a08754eb301dbaff9b8184bedc2fb"
}

rule MalwareBazaar_Mirai_036_d8602f06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
    family = "Mirai"
    file_name = "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
    file_type = "elf"
    first_seen = "2026-08-05 01:00:26"
  condition:
    hash.sha256(0, filesize) == "d8602f06298cba1a8fbd4c3a2ef8f68cb3e5b07f7d933bfd0e6184b4e683a1c6"
}

rule MalwareBazaar_unknown_037_3a09f7e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a09f7e85184a22da474d5fba72c2bed3afb2423e139b7973897067264f7bdc6"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-05 00:57:37"
  condition:
    hash.sha256(0, filesize) == "3a09f7e85184a22da474d5fba72c2bed3afb2423e139b7973897067264f7bdc6"
}

rule MalwareBazaar_Mirai_038_c1dfc650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1dfc650c67b98f8f51ca35bc8583fe4454f6f3c4e6263f1dbead0e969ea463a"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-05 00:57:36"
  condition:
    hash.sha256(0, filesize) == "c1dfc650c67b98f8f51ca35bc8583fe4454f6f3c4e6263f1dbead0e969ea463a"
}

rule MalwareBazaar_unknown_039_5c5e89bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5e89bf5b0ecf61e19bcd0f50f4edcba6b256c8862b4ee8f5efa1c416956c00"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-05 00:54:35"
  condition:
    hash.sha256(0, filesize) == "5c5e89bf5b0ecf61e19bcd0f50f4edcba6b256c8862b4ee8f5efa1c416956c00"
}

rule MalwareBazaar_Gh0stRAT_040_8bf36756
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b"
    family = "Gh0stRAT"
    file_name = "rLobO7.exe"
    file_type = "exe"
    first_seen = "2026-08-05 00:48:47"
  condition:
    hash.sha256(0, filesize) == "8bf367564afbbc28d3101d21124b5bfc3ec006fb32d4a2ba3fb9ccf1414fad8b"
}

rule MalwareBazaar_unknown_041_951c35be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "951c35be1ee761f7ba5c95ac29d4bd5b623b62d947276133bca63871844dbf63"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.GenericKD.81024962.25068.1356"
    file_type = "exe"
    first_seen = "2026-08-05 00:34:56"
  condition:
    hash.sha256(0, filesize) == "951c35be1ee761f7ba5c95ac29d4bd5b623b62d947276133bca63871844dbf63"
}

rule MalwareBazaar_unknown_042_c6d4209d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6d4209d7086ece3833d2c655e1fa281881515c487733205ace2fc9452b91a1f"
    family = "unknown"
    file_name = "voxfix.exe"
    file_type = "exe"
    first_seen = "2026-08-05 00:16:13"
  condition:
    hash.sha256(0, filesize) == "c6d4209d7086ece3833d2c655e1fa281881515c487733205ace2fc9452b91a1f"
}

rule MalwareBazaar_Mirai_043_ff755613
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff7556135cf2beee8e4b110a3563ea6deb5d86a92580eaa38398dc092e0b98dd"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-04 23:53:14"
  condition:
    hash.sha256(0, filesize) == "ff7556135cf2beee8e4b110a3563ea6deb5d86a92580eaa38398dc092e0b98dd"
}

rule MalwareBazaar_Mirai_044_e1bcd3ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1bcd3ef29771dcce576f910c9dd9fabed482ed5a03a11aa1617bb2a029daa72"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-04 23:53:08"
  condition:
    hash.sha256(0, filesize) == "e1bcd3ef29771dcce576f910c9dd9fabed482ed5a03a11aa1617bb2a029daa72"
}

rule MalwareBazaar_Mirai_045_331e955b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "331e955b58409993cb50593b0314666dcd35afd38edf4ebc9dbdd272fc595137"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:59"
  condition:
    hash.sha256(0, filesize) == "331e955b58409993cb50593b0314666dcd35afd38edf4ebc9dbdd272fc595137"
}

rule MalwareBazaar_Mirai_046_3b89db05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:56"
  condition:
    hash.sha256(0, filesize) == "3b89db05cd1e6283a5d23e32eb6a6c17d92953c80c93befa194a0c93a633c1b5"
}

rule MalwareBazaar_Mirai_047_a6d7e538
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6d7e53827923e4ef5ad75738d9f972d070436669e3f8898041d11dad4311d64"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:54"
  condition:
    hash.sha256(0, filesize) == "a6d7e53827923e4ef5ad75738d9f972d070436669e3f8898041d11dad4311d64"
}

rule MalwareBazaar_Mirai_048_573f7e48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "573f7e484d4c9657434581cce579a623a1cf3e65acb910d908a87d3d6681dcea"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:52"
  condition:
    hash.sha256(0, filesize) == "573f7e484d4c9657434581cce579a623a1cf3e65acb910d908a87d3d6681dcea"
}

rule MalwareBazaar_Mirai_049_ceef74ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceef74efa11e441698207a000466abc3048d4144feb2be779e44a498a8dfc54a"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:49"
  condition:
    hash.sha256(0, filesize) == "ceef74efa11e441698207a000466abc3048d4144feb2be779e44a498a8dfc54a"
}

rule MalwareBazaar_Mirai_050_f76f5962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f76f596286a2b1e0686b9b7e7ca1eb18ab462ccf3b4c5dbef6c09f7ddc593272"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:06"
  condition:
    hash.sha256(0, filesize) == "f76f596286a2b1e0686b9b7e7ca1eb18ab462ccf3b4c5dbef6c09f7ddc593272"
}

rule MalwareBazaar_Mirai_051_5a433a64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a433a64567fce8e9ccf41dc6ce2d3536b2382d116b9737912a4709926cd283c"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:04"
  condition:
    hash.sha256(0, filesize) == "5a433a64567fce8e9ccf41dc6ce2d3536b2382d116b9737912a4709926cd283c"
}

rule MalwareBazaar_Mirai_052_1f2bc044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f2bc04401a73357813d145ea66ec6ad168c21e44dd9a47ff840102d301fbc51"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:03"
  condition:
    hash.sha256(0, filesize) == "1f2bc04401a73357813d145ea66ec6ad168c21e44dd9a47ff840102d301fbc51"
}

rule MalwareBazaar_Mirai_053_1f71e800
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f71e800d6147c5932c6a85eaa3dc8f9e79ed8eed5493821a562f5609585fb5d"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-08-04 23:52:02"
  condition:
    hash.sha256(0, filesize) == "1f71e800d6147c5932c6a85eaa3dc8f9e79ed8eed5493821a562f5609585fb5d"
}

rule MalwareBazaar_Mirai_054_b2f27f60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2f27f60ab93a86fce986b7137986fabbe7952ad38e6a9d6c0d458c019baeeb0"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:59"
  condition:
    hash.sha256(0, filesize) == "b2f27f60ab93a86fce986b7137986fabbe7952ad38e6a9d6c0d458c019baeeb0"
}

rule MalwareBazaar_Mirai_055_d2726a83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2726a8326104f79becf68c4e806a6f9ddfde07344baf592e0a783a9e4ac58cd"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:58"
  condition:
    hash.sha256(0, filesize) == "d2726a8326104f79becf68c4e806a6f9ddfde07344baf592e0a783a9e4ac58cd"
}

rule MalwareBazaar_Mirai_056_f3eed21c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3eed21ca3a8d07883868fc0245a17acf954336675cfe2bd042d4bb29a35e0f9"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:57"
  condition:
    hash.sha256(0, filesize) == "f3eed21ca3a8d07883868fc0245a17acf954336675cfe2bd042d4bb29a35e0f9"
}

rule MalwareBazaar_Mirai_057_ac787255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac787255b109b4558b0bffe85f5b4f158bd260f993b9aedb6cbf1d0b227ca5ad"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:56"
  condition:
    hash.sha256(0, filesize) == "ac787255b109b4558b0bffe85f5b4f158bd260f993b9aedb6cbf1d0b227ca5ad"
}

rule MalwareBazaar_Mirai_058_7258dc0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7258dc0bef74fe98f77dc6a29c513063cba7131a68974e2e1f21412f199d366c"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-08-04 23:51:55"
  condition:
    hash.sha256(0, filesize) == "7258dc0bef74fe98f77dc6a29c513063cba7131a68974e2e1f21412f199d366c"
}

rule MalwareBazaar_unknown_059_dd9d7548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd9d754896001df78f96486b10729650e5957a08e4931d6b6a1a154753a26c63"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:48:30"
  condition:
    hash.sha256(0, filesize) == "dd9d754896001df78f96486b10729650e5957a08e4931d6b6a1a154753a26c63"
}

rule MalwareBazaar_unknown_060_96b09d3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96b09d3c8deac6e7694c8a37ce45b5359fb7345f13e824c808831321eefd5f01"
    family = "unknown"
    file_name = "java-qEKUrj.exe"
    file_type = "exe"
    first_seen = "2026-08-04 23:45:52"
  condition:
    hash.sha256(0, filesize) == "96b09d3c8deac6e7694c8a37ce45b5359fb7345f13e824c808831321eefd5f01"
}

rule MalwareBazaar_unknown_061_b4647c88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4647c8851c316988984a6c6d534f103a0cd65e5f165f8aaaa9da8b0a7f28854"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:41:30"
  condition:
    hash.sha256(0, filesize) == "b4647c8851c316988984a6c6d534f103a0cd65e5f165f8aaaa9da8b0a7f28854"
}

rule MalwareBazaar_unknown_062_757060d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "757060d1a348f54c2fceeb3337e0e8b8a984d3f3001ffc27771dd49f559254e7"
    family = "unknown"
    file_name = "msedge.exe"
    file_type = "exe"
    first_seen = "2026-08-04 23:22:34"
  condition:
    hash.sha256(0, filesize) == "757060d1a348f54c2fceeb3337e0e8b8a984d3f3001ffc27771dd49f559254e7"
}

rule MalwareBazaar_unknown_063_2b2cf362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b2cf3626f4d79fa2b10001f024b86677c63e2381f0923331924d26b1ee676ba"
    family = "unknown"
    file_name = "msedge.exe"
    file_type = "exe"
    first_seen = "2026-08-04 23:21:30"
  condition:
    hash.sha256(0, filesize) == "2b2cf3626f4d79fa2b10001f024b86677c63e2381f0923331924d26b1ee676ba"
}

rule MalwareBazaar_unknown_064_ae129610
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae12961097868ed2394644d506dfd40d175d30ef159def7d68a845ac23f7a9b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:14:21"
  condition:
    hash.sha256(0, filesize) == "ae12961097868ed2394644d506dfd40d175d30ef159def7d68a845ac23f7a9b3"
}

rule MalwareBazaar_CoinMiner_065_0aae3c63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0aae3c635faa512b497fd34dce58b7b5fcaafcbe0a67e4c154cf7659ba334b81"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 23:13:14"
  condition:
    hash.sha256(0, filesize) == "0aae3c635faa512b497fd34dce58b7b5fcaafcbe0a67e4c154cf7659ba334b81"
}

rule MalwareBazaar_unknown_066_2c6790b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6790b4141e5bbd9684c129acb2a7aeb1b8b3c167dfdfd6b3e9df7013bd1f4d"
    family = "unknown"
    file_name = "java-rjZsjZ.exe"
    file_type = "exe"
    first_seen = "2026-08-04 22:52:46"
  condition:
    hash.sha256(0, filesize) == "2c6790b4141e5bbd9684c129acb2a7aeb1b8b3c167dfdfd6b3e9df7013bd1f4d"
}

rule MalwareBazaar_unknown_067_fe827770
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe8277705549324d8fdb94cc7d9a9083190f3e93e8e5dfec582b5afa5d42c97d"
    family = "unknown"
    file_name = "photo_287742060718.zip"
    file_type = "zip"
    first_seen = "2026-08-04 22:18:55"
  condition:
    hash.sha256(0, filesize) == "fe8277705549324d8fdb94cc7d9a9083190f3e93e8e5dfec582b5afa5d42c97d"
}

rule MalwareBazaar_unknown_068_6941fbaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6941fbafdf1c7e5ddd12b9050c27501aba8b0ab05e1916afffd21ba30257ebf8"
    family = "unknown"
    file_name = "pfbofa.zip"
    file_type = "zip"
    first_seen = "2026-08-04 22:16:48"
  condition:
    hash.sha256(0, filesize) == "6941fbafdf1c7e5ddd12b9050c27501aba8b0ab05e1916afffd21ba30257ebf8"
}

rule MalwareBazaar_Formbook_069_151b01ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "151b01ecbb7aca8b8a3e82f2e74c4f496e95046b89601a2482e6dcb3d570d78c"
    family = "Formbook"
    file_name = "Q88 with vessel's particulars.exe"
    file_type = "exe"
    first_seen = "2026-08-04 22:14:41"
  condition:
    hash.sha256(0, filesize) == "151b01ecbb7aca8b8a3e82f2e74c4f496e95046b89601a2482e6dcb3d570d78c"
}

rule MalwareBazaar_unknown_070_4cc5af32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc5af32dfe739b1d73d1291dd178e4b8b76cb5b5cb4096b03d060c9236a5896"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-04 22:09:48"
  condition:
    hash.sha256(0, filesize) == "4cc5af32dfe739b1d73d1291dd178e4b8b76cb5b5cb4096b03d060c9236a5896"
}

rule MalwareBazaar_Prometei_071_0e651806
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e"
    family = "Prometei"
    file_name = "0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e"
    file_type = "elf"
    first_seen = "2026-08-04 22:08:04"
  condition:
    hash.sha256(0, filesize) == "0e6518062d007026012e15e87f993f51b5338a6317c69330db4671887817a26e"
}

rule MalwareBazaar_Prometei_072_a5073027
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836"
    family = "Prometei"
    file_name = "a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836"
    file_type = "elf"
    first_seen = "2026-08-04 22:07:07"
  condition:
    hash.sha256(0, filesize) == "a5073027d44c6ce3d7b0b8b29e4cfefb509665c4c25848e75522ebd7eb17c836"
}

rule MalwareBazaar_Mirai_073_918a0a4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "918a0a4cde273e289a846a5e21e160c2caf84372cc13c717d707458c7fd561a8"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-08-04 21:57:40"
  condition:
    hash.sha256(0, filesize) == "918a0a4cde273e289a846a5e21e160c2caf84372cc13c717d707458c7fd561a8"
}

rule MalwareBazaar_Mirai_074_a8ae2492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ae2492cac7901938e1e12b81d858b96f9b10609bda4678dfb63a0be56473e7"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-08-04 21:57:39"
  condition:
    hash.sha256(0, filesize) == "a8ae2492cac7901938e1e12b81d858b96f9b10609bda4678dfb63a0be56473e7"
}

rule MalwareBazaar_Mirai_075_26d365cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26d365cb80c309e42a88e0091f15a3c5de80409d18d141c83c8802e82abab22f"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-08-04 21:57:37"
  condition:
    hash.sha256(0, filesize) == "26d365cb80c309e42a88e0091f15a3c5de80409d18d141c83c8802e82abab22f"
}

rule MalwareBazaar_Mirai_076_47db897f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47db897ff8ee59a7caa16b8b06e8bf45a376be9e3f581587d8fcaeda6d7d75d0"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-08-04 21:54:34"
  condition:
    hash.sha256(0, filesize) == "47db897ff8ee59a7caa16b8b06e8bf45a376be9e3f581587d8fcaeda6d7d75d0"
}

rule MalwareBazaar_Mirai_077_b038d9b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b038d9b928a355c583d0c64f5f32990e557a40117d9fa7b9c231022f540f40be"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-08-04 21:54:33"
  condition:
    hash.sha256(0, filesize) == "b038d9b928a355c583d0c64f5f32990e557a40117d9fa7b9c231022f540f40be"
}

rule MalwareBazaar_ValleyRAT_078_8de2d517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de2d51797f113896007d6ed8c634d99f5cee4c34c2bf55b1e4c19432afcbab3"
    family = "ValleyRAT"
    file_name = "C5940ABAE3FB2C368F0841417C9B0454.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:32"
  condition:
    hash.sha256(0, filesize) == "8de2d51797f113896007d6ed8c634d99f5cee4c34c2bf55b1e4c19432afcbab3"
}

rule MalwareBazaar_ValleyRAT_079_1d0b8f08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d0b8f081975cc9dfb542c8da5d173c3a68a23531e83f07e86ccc706e56d76f3"
    family = "ValleyRAT"
    file_name = "B33A668328313F6843B1B8094BFAFFE3.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:28"
  condition:
    hash.sha256(0, filesize) == "1d0b8f081975cc9dfb542c8da5d173c3a68a23531e83f07e86ccc706e56d76f3"
}

rule MalwareBazaar_ValleyRAT_080_931ce3be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "931ce3beac7484c2bab59eb90ee0b8230823a2f7b0dbfd6ffd4296767b0640b8"
    family = "ValleyRAT"
    file_name = "47A4F35908F85C4A3FBE536341989D7A.dll"
    file_type = "dll"
    first_seen = "2026-08-04 21:45:24"
  condition:
    hash.sha256(0, filesize) == "931ce3beac7484c2bab59eb90ee0b8230823a2f7b0dbfd6ffd4296767b0640b8"
}

rule MalwareBazaar_ValleyRAT_081_3e6b5327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e6b5327d9d19cdcd8adf389b991cba090c49bd9f11d4909da89e19420c16b42"
    family = "ValleyRAT"
    file_name = "83A191C82A700BD83128F7AD8576A1CD.dll"
    file_type = "dll"
    first_seen = "2026-08-04 21:45:21"
  condition:
    hash.sha256(0, filesize) == "3e6b5327d9d19cdcd8adf389b991cba090c49bd9f11d4909da89e19420c16b42"
}

rule MalwareBazaar_DCRat_082_a85a685e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a85a685e8753319479922d6098726906804dca6a518205ed70fd555c5289d743"
    family = "DCRat"
    file_name = "0a3e2c2bd38771605cb2eeae9c8cbc62.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:17"
  condition:
    hash.sha256(0, filesize) == "a85a685e8753319479922d6098726906804dca6a518205ed70fd555c5289d743"
}

rule MalwareBazaar_RemcosRAT_083_5d8b365c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8b365ca864c693f967e2b087db0838dea3cb639325ae9be1df085b771f8796"
    family = "RemcosRAT"
    file_name = "Order Specicifications-request for AYB64537.J.js"
    file_type = "js"
    first_seen = "2026-08-04 21:45:14"
  condition:
    hash.sha256(0, filesize) == "5d8b365ca864c693f967e2b087db0838dea3cb639325ae9be1df085b771f8796"
}

rule MalwareBazaar_Pony_084_1f0ed64a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f0ed64ac1128b10a54ad87cf10d1145bf56e7046b1eb7da1ff5162a0661dc8a"
    family = "Pony"
    file_name = "FEE9A1FF4882BA692E235A8CE1E525B1.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:09"
  condition:
    hash.sha256(0, filesize) == "1f0ed64ac1128b10a54ad87cf10d1145bf56e7046b1eb7da1ff5162a0661dc8a"
}

rule MalwareBazaar_Pony_085_93cfcf58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93cfcf58ba02b6704041d8e036b4230a4ba9561723c5e7e8fdce681684864870"
    family = "Pony"
    file_name = "A06194A36273470E5BEDEBE9D313B951.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:45:06"
  condition:
    hash.sha256(0, filesize) == "93cfcf58ba02b6704041d8e036b4230a4ba9561723c5e7e8fdce681684864870"
}

rule MalwareBazaar_NanoCore_086_97b2a7b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b2a7b78f98521a1436c44adb0f717b84364f67f4444b22d544caa2eba8811b"
    family = "NanoCore"
    file_name = "23d82b604133932ba4391ae7fb344dd0.exe"
    file_type = "exe"
    first_seen = "2026-08-04 21:40:05"
  condition:
    hash.sha256(0, filesize) == "97b2a7b78f98521a1436c44adb0f717b84364f67f4444b22d544caa2eba8811b"
}

rule MalwareBazaar_Mirai_087_b481cc2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b481cc2e88ab19b63fca837aef5d80b961659621db8650ee307305062b4eeb41"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 21:33:45"
  condition:
    hash.sha256(0, filesize) == "b481cc2e88ab19b63fca837aef5d80b961659621db8650ee307305062b4eeb41"
}

rule MalwareBazaar_Mirai_088_844b854d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "844b854d590e9ebe4ae09a7233125f473ce3b05312bce3374b5f05c7d50d123a"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-08-04 21:33:42"
  condition:
    hash.sha256(0, filesize) == "844b854d590e9ebe4ae09a7233125f473ce3b05312bce3374b5f05c7d50d123a"
}

rule MalwareBazaar_Mirai_089_6c65afb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c65afb1eb421e192dd0b6ab9fa187b0973d43f10763279dd7f60098ec1acd69"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-08-04 21:33:40"
  condition:
    hash.sha256(0, filesize) == "6c65afb1eb421e192dd0b6ab9fa187b0973d43f10763279dd7f60098ec1acd69"
}

rule MalwareBazaar_CoinMiner_090_b19eb260
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19eb2605a969acda3bd284d2376acc657c3a556d4c81ce17eaaabe39d48b990"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 21:25:07"
  condition:
    hash.sha256(0, filesize) == "b19eb2605a969acda3bd284d2376acc657c3a556d4c81ce17eaaabe39d48b990"
}

rule MalwareBazaar_RemusStealer_091_0d298a65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d298a65db890328d0357b2fb39ea7352645a994a601f430c38450769635f957"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-04 21:22:42"
  condition:
    hash.sha256(0, filesize) == "0d298a65db890328d0357b2fb39ea7352645a994a601f430c38450769635f957"
}

rule MalwareBazaar_Mirai_092_b7db32e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7db32e16aa207e3643f6f9a1b076e7b8ffdb8166ff5e76fe966ae0c94638ac0"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-04 21:17:02"
  condition:
    hash.sha256(0, filesize) == "b7db32e16aa207e3643f6f9a1b076e7b8ffdb8166ff5e76fe966ae0c94638ac0"
}

rule MalwareBazaar_Mirai_093_6e7d98f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e7d98f590da5a91bf0285d31002b80fb373a88aa1c355e63da5f6a4bd8f46c1"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:59"
  condition:
    hash.sha256(0, filesize) == "6e7d98f590da5a91bf0285d31002b80fb373a88aa1c355e63da5f6a4bd8f46c1"
}

rule MalwareBazaar_Mirai_094_668ecef7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668ecef78b39f2b1b602b54d4701546dfb5c6b0701449bb3d8282fc845b4e029"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:56"
  condition:
    hash.sha256(0, filesize) == "668ecef78b39f2b1b602b54d4701546dfb5c6b0701449bb3d8282fc845b4e029"
}

rule MalwareBazaar_Mirai_095_111c0e62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "111c0e6222dfb48fa9cb3e4b9f89f7ca8d610c5ef8dd337e6f810d06a1217b77"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:52"
  condition:
    hash.sha256(0, filesize) == "111c0e6222dfb48fa9cb3e4b9f89f7ca8d610c5ef8dd337e6f810d06a1217b77"
}

rule MalwareBazaar_Mirai_096_45d4f75e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45d4f75e7486a914b9f9125b87e427dd62eb4c9c8acb1b2f8cfb5ffbb7577ed1"
    family = "Mirai"
    file_name = "boatnet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:41"
  condition:
    hash.sha256(0, filesize) == "45d4f75e7486a914b9f9125b87e427dd62eb4c9c8acb1b2f8cfb5ffbb7577ed1"
}

rule MalwareBazaar_Mirai_097_3252b9d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3252b9d9d57615060976d4b3bed8684dd59539a0d0cc5616564f132859cb2b5e"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-04 21:16:37"
  condition:
    hash.sha256(0, filesize) == "3252b9d9d57615060976d4b3bed8684dd59539a0d0cc5616564f132859cb2b5e"
}

rule MalwareBazaar_Mirai_098_ae4525d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae4525d81a9b2b1ba4e53b778344f1e412c1ead8ddc3eec317bbf41c18514680"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-04 21:15:58"
  condition:
    hash.sha256(0, filesize) == "ae4525d81a9b2b1ba4e53b778344f1e412c1ead8ddc3eec317bbf41c18514680"
}

rule MalwareBazaar_Mirai_099_5a958996
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a9589968d81f208848a2bbf9d701f99b27ae151876be0fa79fa1809cf5a538b"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-04 21:15:57"
  condition:
    hash.sha256(0, filesize) == "5a9589968d81f208848a2bbf9d701f99b27ae151876be0fa79fa1809cf5a538b"
}

rule MalwareBazaar_Mirai_100_aabfd94a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aabfd94ac3d68386aa56acff0742e2578bc5f39a2f0a75691c5123afc188765c"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-04 21:15:56"
  condition:
    hash.sha256(0, filesize) == "aabfd94ac3d68386aa56acff0742e2578bc5f39a2f0a75691c5123afc188765c"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

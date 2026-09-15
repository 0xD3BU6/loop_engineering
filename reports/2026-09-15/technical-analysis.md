# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-15

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 563 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 563 |
| Unique family labels | 5 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 64 |
| Mirai | 26 |
| DDoSAgent | 8 |
| CoinMiner | 1 |
| Vidar | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 47 |
| unknown | 21 |
| exe | 11 |
| jar | 10 |
| sh | 7 |
| zip | 2 |
| js | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `0277ef3cbf8986b7`

| Field | Value |
|---|---|
| SHA-256 | `0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37` |
| Family label | `unknown` |
| File name | `0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37.bin` |
| File type | `exe` |
| First seen | `2026-09-15 04:50:23` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7ed9c2e411e56baa5679673c54889b8` |
| SHA-1 | `6c5072be26c926bd3587599db4e7d1b6ccfe3dc1` |
| SHA-256 | `0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37` |
| SHA3-384 | `5a7c1e72f47bd11747ed482f0c1776084f18c2b8fc82bd332636cce260f5a3921304d6b41b02ca25cb86465a775f1b0d` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T1CE38330BEA0564F8C46DD631C5B7896BAB35B88C433133931E69AD306F72BE25C79724` |
| SSDEEP | `3145728:LzsoLQlBEOYgSOHFBRX8Nyz/nYl/pphNSqS:L48QIXgRDrrUxo3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_0277ef3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37"
    family = "unknown"
    file_name = "0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37.bin"
    file_type = "exe"
    first_seen = "2026-09-15 04:50:23"
  condition:
    hash.sha256(0, filesize) == "0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37"
}
```

### Sample 2: `b41906309049e719`

| Field | Value |
|---|---|
| SHA-256 | `b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c` |
| Family label | `unknown` |
| File name | `b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c.bin` |
| File type | `exe` |
| First seen | `2026-09-15 04:50:11` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c22a859720b45480d9fb2b76bfd3874e` |
| SHA-1 | `6ee21cf46449a99ec915dc991135a635c0af04b6` |
| SHA-256 | `b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c` |
| SHA3-384 | `c4cc0f1af1ec892d0d853bcde5566bd6aa43380d5e5a74f673e871ed3d0ef01480c67c4083c28981913c1a98d0004128` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T10D28230BEA5124F4C4AEE631C5B7855AAB35BC8C433133932E59AD70AF727E21C79724` |
| SSDEEP | `1572864:9elxmwEzrZKfehAsyH4CSxSVckqkrB3h142YuC3Vfsss2X/8Maurmnl2SKA+8CgE:4xREXZK2hyHtOS9qkrBg9fXDagml2NM6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_b4190630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c"
    family = "unknown"
    file_name = "b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c.bin"
    file_type = "exe"
    first_seen = "2026-09-15 04:50:11"
  condition:
    hash.sha256(0, filesize) == "b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c"
}
```

### Sample 3: `15c866b13c057059`

| Field | Value |
|---|---|
| SHA-256 | `15c866b13c0570599bf7ab1124de239afa107296f2740ef40e19295408518367` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-15 04:27:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31a01a487b1053deb1c7e71271f19e47` |
| SHA-1 | `6f07c4374479efd6ec044bac7b0f9fcfb4934a4a` |
| SHA-256 | `15c866b13c0570599bf7ab1124de239afa107296f2740ef40e19295408518367` |
| SHA3-384 | `633ec0663b83670393ec5d11b47c3abab95b2531400485c1412a0ce3b9f77846be11b47be61021999ac501c5f56de7c3` |
| TLSH | `T1D9236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:iCXRWNGxVQ9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ZlxXcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_15c866b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15c866b13c0570599bf7ab1124de239afa107296f2740ef40e19295408518367"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-15 04:27:48"
  condition:
    hash.sha256(0, filesize) == "15c866b13c0570599bf7ab1124de239afa107296f2740ef40e19295408518367"
}
```

### Sample 4: `b0c1c46317a49973`

| Field | Value |
|---|---|
| SHA-256 | `b0c1c46317a49973e100bac37ef92c39c81680e53635826fedb9979d04aba027` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 04:27:44` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b583148fbc95676008b473b0dc29700f` |
| SHA-256 | `b0c1c46317a49973e100bac37ef92c39c81680e53635826fedb9979d04aba027` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_b0c1c463
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0c1c46317a49973e100bac37ef92c39c81680e53635826fedb9979d04aba027"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 04:27:44"
  condition:
    hash.sha256(0, filesize) == "b0c1c46317a49973e100bac37ef92c39c81680e53635826fedb9979d04aba027"
}
```

### Sample 5: `fdb78eea518d6c63`

| Field | Value |
|---|---|
| SHA-256 | `fdb78eea518d6c632fb05206989403d4c2c5fd6143e7f9ecb3007552b0040ee1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 04:27:37` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d5b88fa3783339876f260081068c829` |
| SHA-256 | `fdb78eea518d6c632fb05206989403d4c2c5fd6143e7f9ecb3007552b0040ee1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_fdb78eea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdb78eea518d6c632fb05206989403d4c2c5fd6143e7f9ecb3007552b0040ee1"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 04:27:37"
  condition:
    hash.sha256(0, filesize) == "fdb78eea518d6c632fb05206989403d4c2c5fd6143e7f9ecb3007552b0040ee1"
}
```

### Sample 6: `f79830fcc9e617d4`

| Field | Value |
|---|---|
| SHA-256 | `f79830fcc9e617d4497668f8cd0b3718cc0c606d2a52ae6d45566af6986f3caa` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-15 04:18:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d44565dc83a1b7d7e8aab794ebe3a01` |
| SHA-1 | `9fb904b9fc315c2f3546044ebe69224837a8b83c` |
| SHA-256 | `f79830fcc9e617d4497668f8cd0b3718cc0c606d2a52ae6d45566af6986f3caa` |
| SHA3-384 | `b0b7a4f84afe4ab397a61850781d72ef02b2d16b78b1fd719d25ab1b8c5987aa4b5c30f3799712b5fb88a63de1f27f46` |
| TLSH | `T1FFC28D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:d48vCB+25j6es8R69FYpMSUpi+20qUpi+20YQX:C8l25Jsd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_f79830fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f79830fcc9e617d4497668f8cd0b3718cc0c606d2a52ae6d45566af6986f3caa"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-15 04:18:51"
  condition:
    hash.sha256(0, filesize) == "f79830fcc9e617d4497668f8cd0b3718cc0c606d2a52ae6d45566af6986f3caa"
}
```

### Sample 7: `3fe634abe12ecaaa`

| Field | Value |
|---|---|
| SHA-256 | `3fe634abe12ecaaaa52597bed14bd61e3d58908e55c803ab20b09043f80da76f` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-15 04:15:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dc0a3e0c352e09f2d60516d0acfd369` |
| SHA-1 | `88374b78d6714e6852d52fd01e6c003220220238` |
| SHA-256 | `3fe634abe12ecaaaa52597bed14bd61e3d58908e55c803ab20b09043f80da76f` |
| SHA3-384 | `3c32f7438de1e71a28bd4f58c521b2728b5b8a78400f15130bc376ec2c4be7efb87875eb4f84454f79b20a8b21ca712a` |
| TLSH | `T155D56C11EDC704F6E8061A3209BB66AF23319C054F64EBD7E9447F3CFA7B6991932249` |
| TELFHASH | `t14a638401acf30e6b5ac51727acf409c1236ad00f0666b6f95e68c77839db08d593e76e` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:pcjhnaZdkRsnG22+0MSCB9C0JbltBm1JM/ZD:Ohnan5GFtEJbXgJQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_3fe634ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fe634abe12ecaaaa52597bed14bd61e3d58908e55c803ab20b09043f80da76f"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-15 04:15:50"
  condition:
    hash.sha256(0, filesize) == "3fe634abe12ecaaaa52597bed14bd61e3d58908e55c803ab20b09043f80da76f"
}
```

### Sample 8: `6759c72365d0c690`

| Field | Value |
|---|---|
| SHA-256 | `6759c72365d0c690db613ff30635970668f5699b65c3842ecdc4f1b695ed13a7` |
| Family label | `unknown` |
| File name | `fail` |
| File type | `unknown` |
| First seen | `2026-09-15 03:54:31` |
| Reporter | `Tuxxin` |
| Tags | `clickfix, mshta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90208ff558df6a5662cc988b58f7a9e5` |
| SHA-256 | `6759c72365d0c690db613ff30635970668f5699b65c3842ecdc4f1b695ed13a7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_6759c723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6759c72365d0c690db613ff30635970668f5699b65c3842ecdc4f1b695ed13a7"
    family = "unknown"
    file_name = "fail"
    file_type = "unknown"
    first_seen = "2026-09-15 03:54:31"
  condition:
    hash.sha256(0, filesize) == "6759c72365d0c690db613ff30635970668f5699b65c3842ecdc4f1b695ed13a7"
}
```

### Sample 9: `f8d09bb7ef380153`

| Field | Value |
|---|---|
| SHA-256 | `f8d09bb7ef38015342fb8ae11c489fc1a3f01e743123e4222e9291cb474fb75e` |
| Family label | `unknown` |
| File name | `app.zip` |
| File type | `zip` |
| First seen | `2026-09-15 03:54:28` |
| Reporter | `Tuxxin` |
| Tags | `clickfix, macos, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a79a20c46cbda66cbc93eae7f1e9173e` |
| SHA-1 | `8874c7052a2e675f4b6fa5d66804ea764fb32eb4` |
| SHA-256 | `f8d09bb7ef38015342fb8ae11c489fc1a3f01e743123e4222e9291cb474fb75e` |
| SHA3-384 | `4722f1259ce9e50603d5f1b9f1eda35a1d5012cb79268d2a4e1f013330bd4cbff004c0a6151ceb441c36eaf20955fe87` |
| TLSH | `T123363361ACC689C4EC5F367C604E5419E98ECE9BD1DFCA1D8E643B1C9AC6672B1B04C3` |
| SSDEEP | `98304:xSZMX8Xam2k0Tt4RPxgaTZv63PsuU+xdUOcetndr1HvRt59aC/2O7MPsEgDfMPtc:+M89zRPrx630u33UmRXHvj5kCb7mggPi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_f8d09bb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8d09bb7ef38015342fb8ae11c489fc1a3f01e743123e4222e9291cb474fb75e"
    family = "unknown"
    file_name = "app.zip"
    file_type = "zip"
    first_seen = "2026-09-15 03:54:28"
  condition:
    hash.sha256(0, filesize) == "f8d09bb7ef38015342fb8ae11c489fc1a3f01e743123e4222e9291cb474fb75e"
}
```

### Sample 10: `df6d5478ddb0af04`

| Field | Value |
|---|---|
| SHA-256 | `df6d5478ddb0af048dd9090b304cadb5077170785d542b95236749f1e6f72651` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-15 03:27:26` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6234f1a17ce1937b4f1efbd9afc90c97` |
| SHA-1 | `4dddecf55f764778a843c5c7054d41149031af55` |
| SHA-256 | `df6d5478ddb0af048dd9090b304cadb5077170785d542b95236749f1e6f72651` |
| SHA3-384 | `29e579d48f654a0167c4bcbbae42a75019c0931752b574d6593b1eeaa8e98d9bdff050ac6e8997543646f55e724e6c97` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T161788D11A3E81A15E27B8679977382A1E6B1BC535711C1CF0094FD4A2F73BC2BA36376` |
| SSDEEP | `786432:qUhNORRcy/AtCWV5OtsFgtah1PTYrNajgSL0suRz0jokK5Z:NhN0CHcWeiTyaESL/k5f` |
| ICON-DHASH | `800c7079697004a0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_df6d5478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df6d5478ddb0af048dd9090b304cadb5077170785d542b95236749f1e6f72651"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-15 03:27:26"
  condition:
    hash.sha256(0, filesize) == "df6d5478ddb0af048dd9090b304cadb5077170785d542b95236749f1e6f72651"
}
```

### Sample 11: `7bcc255efa1b2810`

| Field | Value |
|---|---|
| SHA-256 | `7bcc255efa1b2810ce3daba713ab1b89403bbdc96d39fa88c8015d937dd75acd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 03:26:55` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb380498df595678218350f36f686161` |
| SHA-256 | `7bcc255efa1b2810ce3daba713ab1b89403bbdc96d39fa88c8015d937dd75acd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_7bcc255e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bcc255efa1b2810ce3daba713ab1b89403bbdc96d39fa88c8015d937dd75acd"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 03:26:55"
  condition:
    hash.sha256(0, filesize) == "7bcc255efa1b2810ce3daba713ab1b89403bbdc96d39fa88c8015d937dd75acd"
}
```

### Sample 12: `b94f3f723573c551`

| Field | Value |
|---|---|
| SHA-256 | `b94f3f723573c5513ee3f1d0ef52a25ce40ff251bfd0b9c2e584565c564e07e3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 03:26:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6d984f5d607793de63ef8704df7c90f` |
| SHA-256 | `b94f3f723573c5513ee3f1d0ef52a25ce40ff251bfd0b9c2e584565c564e07e3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_b94f3f72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94f3f723573c5513ee3f1d0ef52a25ce40ff251bfd0b9c2e584565c564e07e3"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 03:26:45"
  condition:
    hash.sha256(0, filesize) == "b94f3f723573c5513ee3f1d0ef52a25ce40ff251bfd0b9c2e584565c564e07e3"
}
```

### Sample 13: `b74680f5b86f229f`

| Field | Value |
|---|---|
| SHA-256 | `b74680f5b86f229f3df6e0b1e7f4384a0f330b3e7108ab048df5a90a09d4946d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 03:04:42` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `803eb0d9ac9b4a02c06ed7700502451e` |
| SHA-256 | `b74680f5b86f229f3df6e0b1e7f4384a0f330b3e7108ab048df5a90a09d4946d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_b74680f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b74680f5b86f229f3df6e0b1e7f4384a0f330b3e7108ab048df5a90a09d4946d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 03:04:42"
  condition:
    hash.sha256(0, filesize) == "b74680f5b86f229f3df6e0b1e7f4384a0f330b3e7108ab048df5a90a09d4946d"
}
```

### Sample 14: `948ec40af3fd4ed8`

| Field | Value |
|---|---|
| SHA-256 | `948ec40af3fd4ed80929c53e08733bd7ecf2598ee9f93e203bd0ad88bab52ed5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 02:26:09` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `503273c83f2141008e3067e3275ebe26` |
| SHA-256 | `948ec40af3fd4ed80929c53e08733bd7ecf2598ee9f93e203bd0ad88bab52ed5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_948ec40a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "948ec40af3fd4ed80929c53e08733bd7ecf2598ee9f93e203bd0ad88bab52ed5"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 02:26:09"
  condition:
    hash.sha256(0, filesize) == "948ec40af3fd4ed80929c53e08733bd7ecf2598ee9f93e203bd0ad88bab52ed5"
}
```

### Sample 15: `24429840c4558d54`

| Field | Value |
|---|---|
| SHA-256 | `24429840c4558d541a70878ad980e8e51e4acac371f28344ce2455391bf23b05` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 02:26:02` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34a189e1bdfb08acb18d5349561d394b` |
| SHA-256 | `24429840c4558d541a70878ad980e8e51e4acac371f28344ce2455391bf23b05` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_24429840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24429840c4558d541a70878ad980e8e51e4acac371f28344ce2455391bf23b05"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 02:26:02"
  condition:
    hash.sha256(0, filesize) == "24429840c4558d541a70878ad980e8e51e4acac371f28344ce2455391bf23b05"
}
```

### Sample 16: `a47f99ee1afb916c`

| Field | Value |
|---|---|
| SHA-256 | `a47f99ee1afb916c204d48410e385afe772895c1f2d40570eb63f22f5ee5bf99` |
| Family label | `unknown` |
| File name | `MV GREAT AMITY QUOTATION FORM.js` |
| File type | `js` |
| First seen | `2026-09-15 02:25:37` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e5ec35c5adbedac3e830e8c3ae58644` |
| SHA-1 | `4bced983e94b8cf5b4bdfd2139fc99f0b36f7720` |
| SHA-256 | `a47f99ee1afb916c204d48410e385afe772895c1f2d40570eb63f22f5ee5bf99` |
| SHA3-384 | `b4ea99ccac8d853b94fe878f53fa2f14c4531858940fe17df7d904eaa9410724b61e83db25bd0020fa47e90af95fd673` |
| TLSH | `T123E5A6A73AEE7ACFAA453309A54EBC514F1EC0209ED14FC498CF57E8854B10E68649DF` |
| SSDEEP | `49152:xhdDctGslOQ6o5DhzOhXcBfDQGUGM9PcymxsSHOvyr/r7zrZqYS/T:h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_a47f99ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a47f99ee1afb916c204d48410e385afe772895c1f2d40570eb63f22f5ee5bf99"
    family = "unknown"
    file_name = "MV GREAT AMITY QUOTATION FORM.js"
    file_type = "js"
    first_seen = "2026-09-15 02:25:37"
  condition:
    hash.sha256(0, filesize) == "a47f99ee1afb916c204d48410e385afe772895c1f2d40570eb63f22f5ee5bf99"
}
```

### Sample 17: `b84d080e5839eaf4`

| Field | Value |
|---|---|
| SHA-256 | `b84d080e5839eaf4ff997066dd152e1454bc71238c192ee2fbd1946a15214046` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-15 02:05:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66503930c37bd3beaac61c651c91973e` |
| SHA-1 | `554bc13c0ac670000b5f0d932358c69490fa8100` |
| SHA-256 | `b84d080e5839eaf4ff997066dd152e1454bc71238c192ee2fbd1946a15214046` |
| SHA3-384 | `c56e546de340f72cd7b96814ec894650d1b9d732b0a9f91f26c6aaad9d784076639aeca7f01648b48adde706dd07008f` |
| TLSH | `T1DC236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10971D` |
| SSDEEP | `768:UMXRWNGxVH9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Uglx+cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_b84d080e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b84d080e5839eaf4ff997066dd152e1454bc71238c192ee2fbd1946a15214046"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-15 02:05:52"
  condition:
    hash.sha256(0, filesize) == "b84d080e5839eaf4ff997066dd152e1454bc71238c192ee2fbd1946a15214046"
}
```

### Sample 18: `2d6a529713ed9e28`

| Field | Value |
|---|---|
| SHA-256 | `2d6a529713ed9e2871b7553f253818c078d342b8e3475be140c8fb47bedcf125` |
| Family label | `unknown` |
| File name | `bypass.ps1` |
| File type | `ps1` |
| First seen | `2026-09-15 01:45:39` |
| Reporter | `ave9858` |
| Tags | `fakemas, OverlordRAT, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ea817d7912b66dd8db4541ba908b1c2` |
| SHA-1 | `1cfe073ece2c53d7447778350817df119f2697d4` |
| SHA-256 | `2d6a529713ed9e2871b7553f253818c078d342b8e3475be140c8fb47bedcf125` |
| SHA3-384 | `ed2e860605c170a5068b1fff70922cca94048b0cb33f67a8ec009703f5116c0961c3dc4c8b4c64821a4670b98e76e34d` |
| TLSH | `T18F5199566AF992A9C3C350E61494E348A226D247401F5B11BEFC8DC4BF945EDC7FC2C9` |
| SSDEEP | `48:BKH1vFmFROR/PVEfdilwVZzCFZNQi8BXG9COOmkKkdbOSMp8Bn1Gp7pttD+VkLbx:B0mFEofkEzCFZNr85yMZtGHzxzJbVh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_2d6a5297
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6a529713ed9e2871b7553f253818c078d342b8e3475be140c8fb47bedcf125"
    family = "unknown"
    file_name = "bypass.ps1"
    file_type = "ps1"
    first_seen = "2026-09-15 01:45:39"
  condition:
    hash.sha256(0, filesize) == "2d6a529713ed9e2871b7553f253818c078d342b8e3475be140c8fb47bedcf125"
}
```

### Sample 19: `616e28750cba299b`

| Field | Value |
|---|---|
| SHA-256 | `616e28750cba299b1d0d055be7889176533eb473c73cca40888a46f29a885cc8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 01:25:43` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce4c91064eb7eb8c05fce63274667896` |
| SHA-256 | `616e28750cba299b1d0d055be7889176533eb473c73cca40888a46f29a885cc8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_616e2875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "616e28750cba299b1d0d055be7889176533eb473c73cca40888a46f29a885cc8"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 01:25:43"
  condition:
    hash.sha256(0, filesize) == "616e28750cba299b1d0d055be7889176533eb473c73cca40888a46f29a885cc8"
}
```

### Sample 20: `67531c07cc3224ff`

| Field | Value |
|---|---|
| SHA-256 | `67531c07cc3224ff2b8756a057164fe64b21a3cc9190218438365c183e0591db` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 01:25:34` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2d1e8e4ef9a60224723830088f96e32` |
| SHA-256 | `67531c07cc3224ff2b8756a057164fe64b21a3cc9190218438365c183e0591db` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_67531c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67531c07cc3224ff2b8756a057164fe64b21a3cc9190218438365c183e0591db"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 01:25:34"
  condition:
    hash.sha256(0, filesize) == "67531c07cc3224ff2b8756a057164fe64b21a3cc9190218438365c183e0591db"
}
```

### Sample 21: `4c0a1be9b84d1c73`

| Field | Value |
|---|---|
| SHA-256 | `4c0a1be9b84d1c7332f90ad6600b6a40585448a67bedb714417c4cbdfbe27f92` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 01:25:05` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `278492f16c32b1a07585effab2d26675` |
| SHA-256 | `4c0a1be9b84d1c7332f90ad6600b6a40585448a67bedb714417c4cbdfbe27f92` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_4c0a1be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c0a1be9b84d1c7332f90ad6600b6a40585448a67bedb714417c4cbdfbe27f92"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 01:25:05"
  condition:
    hash.sha256(0, filesize) == "4c0a1be9b84d1c7332f90ad6600b6a40585448a67bedb714417c4cbdfbe27f92"
}
```

### Sample 22: `0e8870f48e3971b4`

| Field | Value |
|---|---|
| SHA-256 | `0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85` |
| Family label | `unknown` |
| File name | `0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85` |
| File type | `elf` |
| First seen | `2026-09-15 00:58:16` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64040ef908e9964de135772ca9cba11e` |
| SHA-1 | `3c3a83ef9b67e4cba0cd30bafdc9f8f9d4a214b9` |
| SHA-256 | `0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85` |
| SHA3-384 | `b28280e48c5869663c731ff2f5ef834612e3a9938f37d9cd5d986780ec8aa38b4773cecb52fb7013c0fb9e474cfd8374` |
| TLSH | `T188346A17F99150B8D188C6308BAFE133E772F45D5130BA4B27E62E227D23B90BB1A755` |
| SSDEEP | `3072:5XDgEITLGJvQkuMIrTbg+BrlOETqjAYEshoo2Ri1pM6i08lfCM6qIY2Y38:5zgrLgvfudNVlHTqFQRiIdlfCM6qIk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_0e8870f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85"
    family = "unknown"
    file_name = "0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85"
    file_type = "elf"
    first_seen = "2026-09-15 00:58:16"
  condition:
    hash.sha256(0, filesize) == "0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85"
}
```

### Sample 23: `2899b8a2d4d7c47f`

| Field | Value |
|---|---|
| SHA-256 | `2899b8a2d4d7c47fff7e1c6cf63d8dbfb6c440a037ab399514f508164e2b0894` |
| Family label | `CoinMiner` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.27176296` |
| File type | `exe` |
| First seen | `2026-09-15 00:43:52` |
| Reporter | `SecuriteInfoCom` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32eaf1bdb7f07ce331690ed88e18b1f1` |
| SHA-1 | `5a9f5a9ce30246ce565a31c87f6227b762db8a35` |
| SHA-256 | `2899b8a2d4d7c47fff7e1c6cf63d8dbfb6c440a037ab399514f508164e2b0894` |
| SHA3-384 | `efff19e26bb83f43908a85b63d9d62b729bd00e4f5c4aae5f873b3b28bce19f510a592706dec0290a9e376c0d1e1d10a` |
| IMPHASH | `15596bcc7e7948f19395f593298f677a` |
| TLSH | `T1255633776F57099AF8CA64B19540FAED23C9AE4CE1221D7D1C1A2F21CC210C8F65BE9D` |
| SSDEEP | `98304:XR14kvu094O8omLnuzrclexxcZCbD7mUk+mch+NCAvLbWcFoBOBJ:wk20GszrWeGC37mImhCwtocj` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_023_2899b8a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2899b8a2d4d7c47fff7e1c6cf63d8dbfb6c440a037ab399514f508164e2b0894"
    family = "CoinMiner"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.27176296"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:52"
  condition:
    hash.sha256(0, filesize) == "2899b8a2d4d7c47fff7e1c6cf63d8dbfb6c440a037ab399514f508164e2b0894"
}
```

### Sample 24: `70f775cdcbd1dc33`

| Field | Value |
|---|---|
| SHA-256 | `70f775cdcbd1dc33a8fe195c3d9edd702b3b6d2f226a049d7cefc8e7cee3163b` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.22653435` |
| File type | `exe` |
| First seen | `2026-09-15 00:43:51` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3aac95680a2b0552caddcb46303c7087` |
| SHA-1 | `bae0c6968e3ee104a59ec10875685db81cecc385` |
| SHA-256 | `70f775cdcbd1dc33a8fe195c3d9edd702b3b6d2f226a049d7cefc8e7cee3163b` |
| SHA3-384 | `77d8b56ad78a65705c7ab4f2b92e20ef059e18c3b3290d6eaecd4011f5b1d25553764a35dfa0278049e02c560ea7a359` |
| IMPHASH | `988a8244c72195b4bb8a0139a4adfc0a` |
| TLSH | `T1B016337D4CC8598DC89FA7B7C9EAB697A5A8365AC2FC68CCD063FD81D8117234300D69` |
| SSDEEP | `98304:OHoDw4/8ZTRcua/Y41kdDuHtIK5hECn6O2+DJXfJ:vxkXcpODuHtIKTEmTJD9x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_70f775cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70f775cdcbd1dc33a8fe195c3d9edd702b3b6d2f226a049d7cefc8e7cee3163b"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.22653435"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:51"
  condition:
    hash.sha256(0, filesize) == "70f775cdcbd1dc33a8fe195c3d9edd702b3b6d2f226a049d7cefc8e7cee3163b"
}
```

### Sample 25: `11d5ae7c90cb88ff`

| Field | Value |
|---|---|
| SHA-256 | `11d5ae7c90cb88ff232dc6556ad9ed2185d981f23206defbce7eb88c19c0e090` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Variant.Midie.189066.22482136` |
| File type | `exe` |
| First seen | `2026-09-15 00:43:49` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8c590a1a079434720c9960af3683265` |
| SHA-1 | `489917a8f0fa00a82af62604d170e5e7d6dbd2a3` |
| SHA-256 | `11d5ae7c90cb88ff232dc6556ad9ed2185d981f23206defbce7eb88c19c0e090` |
| SHA3-384 | `1e543ad6f0d1c0dfb86de5dfd6fd8c3f0988cc6c7c6a2788ea0b60fe5dc2fd93b13c196097485a39c4d42a503eca4449` |
| IMPHASH | `740b08f4ff3b69c9c5adb9182d224363` |
| TLSH | `T18B16330C8A5C3AD9D9D32EFA16B21C79CB044B4046FBA295C825F5F1F05F7A6B711A0E` |
| SSDEEP | `98304:lnwePgEp/tDc8LZKcLU6Tt69fLK9mZapJ2:lpp/lc8o/P9fLKC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_11d5ae7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d5ae7c90cb88ff232dc6556ad9ed2185d981f23206defbce7eb88c19c0e090"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Midie.189066.22482136"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:49"
  condition:
    hash.sha256(0, filesize) == "11d5ae7c90cb88ff232dc6556ad9ed2185d981f23206defbce7eb88c19c0e090"
}
```

### Sample 26: `0880c280f51a7c22`

| Field | Value |
|---|---|
| SHA-256 | `0880c280f51a7c22fdbc5d15a4d13e1137d27003cb2775430023370082afcc58` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Variant.Midie.189100.48315442` |
| File type | `exe` |
| First seen | `2026-09-15 00:43:47` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52936c347d2e2d7dcbe047f2adcd9037` |
| SHA-1 | `95838470e9fb9a2048054f3a9827bbe2027ca2a5` |
| SHA-256 | `0880c280f51a7c22fdbc5d15a4d13e1137d27003cb2775430023370082afcc58` |
| SHA3-384 | `0e1ed2be8804ee44bbbdabe4843ee4dc2eb9ab7cd346c44fec77a303cf14a0eef4facc5ef0b1c6857d25945418582302` |
| IMPHASH | `a333184d381e7a8056423277306244fc` |
| TLSH | `T1701633288F4366AEF4BD06F9417D18898311DF0A9434EDBB67099E0A4BFCB1FC17A645` |
| SSDEEP | `98304:6rfVR/FIGCuEcWwrezdd/FOfAYHmBRFnQufZ39uO3EmC:6Dn/6GP9foHLYH23fZ34IC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_0880c280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0880c280f51a7c22fdbc5d15a4d13e1137d27003cb2775430023370082afcc58"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Midie.189100.48315442"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:47"
  condition:
    hash.sha256(0, filesize) == "0880c280f51a7c22fdbc5d15a4d13e1137d27003cb2775430023370082afcc58"
}
```

### Sample 27: `3557949447ce7bd6`

| Field | Value |
|---|---|
| SHA-256 | `3557949447ce7bd6b6b1c66bc49ca4b421ec28640757a1e18c6fed9732889fdb` |
| Family label | `unknown` |
| File name | `WizzyAddonFree.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:34:12` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e13ad037b88fb043c4fd0920d8ed5ae` |
| SHA-1 | `92fe00f1ee698003b2ad05cd55325931135a87b4` |
| SHA-256 | `3557949447ce7bd6b6b1c66bc49ca4b421ec28640757a1e18c6fed9732889fdb` |
| SHA3-384 | `fd44b7ce1f47fbdbac4be32d5499f42dc17cba85a34d2ed8d01a1609f1df5657b6e8e53b20b340d736a713d2a40218a9` |
| TLSH | `T16A7302391E91F165DF85A93D2233A41E1E5EA2D8CD0EBE7E00F6ED918841DA5B365CC0` |
| SSDEEP | `1536:B10BWs22GZuPydQ1yiHb1KafwbcqWgtECCmz:T0Bf22vKdSKaIb5WgtECD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_35579494
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3557949447ce7bd6b6b1c66bc49ca4b421ec28640757a1e18c6fed9732889fdb"
    family = "unknown"
    file_name = "WizzyAddonFree.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:34:12"
  condition:
    hash.sha256(0, filesize) == "3557949447ce7bd6b6b1c66bc49ca4b421ec28640757a1e18c6fed9732889fdb"
}
```

### Sample 28: `d59f3052ca0a0f0f`

| Field | Value |
|---|---|
| SHA-256 | `d59f3052ca0a0f0fec3e4d2fe78f5f531a074ec4b6fd1f0bcf1a04f28ca14a02` |
| Family label | `unknown` |
| File name | `Wizzy_Addon_1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:34:08` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91c75a1a889b488ae48d8af835f37190` |
| SHA-1 | `adc1ee0e033db050945d9a5a858b3dbf56de5935` |
| SHA-256 | `d59f3052ca0a0f0fec3e4d2fe78f5f531a074ec4b6fd1f0bcf1a04f28ca14a02` |
| SHA3-384 | `4c9363a9a55baad98558df385e8166923dd4071af12ac41e39d9895746def2121e3cbff751d2ac72686cf0c159f75012` |
| TLSH | `T10EE302031B3CD299E90B27F4A4499B4EF47845E0D48B990B29B94BF70C4216F6FA4B6C` |
| SSDEEP | `3072:kKqHMx5I+0w4d3mLFXmgbC2DSy/ia5JSPgYdcWGUVdRred600CmodG/vgRufCqt6:kTsvxMYLFBGS/iaYB5ad6ZC1MgRu/tCP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_d59f3052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d59f3052ca0a0f0fec3e4d2fe78f5f531a074ec4b6fd1f0bcf1a04f28ca14a02"
    family = "unknown"
    file_name = "Wizzy_Addon_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:34:08"
  condition:
    hash.sha256(0, filesize) == "d59f3052ca0a0f0fec3e4d2fe78f5f531a074ec4b6fd1f0bcf1a04f28ca14a02"
}
```

### Sample 29: `155acb35cece5a4d`

| Field | Value |
|---|---|
| SHA-256 | `155acb35cece5a4df8255853905e6136c5af5ae8725110c8cfe37786126dd994` |
| Family label | `unknown` |
| File name | `Sped_Debug_V4.3.1.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:34:03` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55a2845290901bc99f9a756adeae314a` |
| SHA-1 | `d40933d1ac87fbe8726f9a20008a5004d382eb11` |
| SHA-256 | `155acb35cece5a4df8255853905e6136c5af5ae8725110c8cfe37786126dd994` |
| SHA3-384 | `1c3b254d542a66150e317c1188fec67edc2d6dc3a85eb0fe55926c51cf82c52efe0abea888f91491029a8ba374fc427f` |
| TLSH | `T12D63F1A8BE92EBEDD61FC4786060959B7D1488ADE1C4F71364F05D4244D8F492623F8E` |
| SSDEEP | `1536:KV+SCJ9DcYSrLoHC4FAyT13FBkcc8+y6vYTcNOMxpsxpX:8+Xjc9rLqCC7BkR3y6vYoOMxpQX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_155acb35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "155acb35cece5a4df8255853905e6136c5af5ae8725110c8cfe37786126dd994"
    family = "unknown"
    file_name = "Sped_Debug_V4.3.1.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:34:03"
  condition:
    hash.sha256(0, filesize) == "155acb35cece5a4df8255853905e6136c5af5ae8725110c8cfe37786126dd994"
}
```

### Sample 30: `6bec04011ad77b53`

| Field | Value |
|---|---|
| SHA-256 | `6bec04011ad77b53986ddb64707fc9cd86a4ee5903ad79a95b5d55c1df525c50` |
| Family label | `unknown` |
| File name | `Sped_Debug_1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:54` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dd14fdd887869f43ecf99086782e850` |
| SHA-1 | `41bf135c770b5894a4abf30700a70be3e8e41b0e` |
| SHA-256 | `6bec04011ad77b53986ddb64707fc9cd86a4ee5903ad79a95b5d55c1df525c50` |
| SHA3-384 | `862524327456fcdc5a11ccdcc47c37f2470804446baab36628cf89ff178213a3a4f2d22f5a0bd7280046ecfcb50c9f07` |
| TLSH | `T1D07302B83C85C62FED3B8B75C641D28BAF654B25671B7243B02246EF4C6840C9D59CBD` |
| SSDEEP | `1536:9M4XD+1JfdpGVoLZ6LlekX7NkShpyDU2jmono5Myp1z:9XD+XFjdYUkX7/p92jmoapJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_6bec0401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bec04011ad77b53986ddb64707fc9cd86a4ee5903ad79a95b5d55c1df525c50"
    family = "unknown"
    file_name = "Sped_Debug_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:54"
  condition:
    hash.sha256(0, filesize) == "6bec04011ad77b53986ddb64707fc9cd86a4ee5903ad79a95b5d55c1df525c50"
}
```

### Sample 31: `e0c17b87590f5c34`

| Field | Value |
|---|---|
| SHA-256 | `e0c17b87590f5c34c9ac68fe89a780b147c40754d757e53c3394ec47fa09b41d` |
| Family label | `unknown` |
| File name | `Sped_debug_1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:49` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `656b4295d919cf4ea5df2494304ca73e` |
| SHA-1 | `dd89d5e162aa5ed44ce89f0c2ed5c532705aefc8` |
| SHA-256 | `e0c17b87590f5c34c9ac68fe89a780b147c40754d757e53c3394ec47fa09b41d` |
| SHA3-384 | `c24a5a05029cd6cfff4fb2df41a56c675a8de801dea0c119c414d9982c6f2bd1b0e70ae9be59bda3000a068a73d3d9bd` |
| TLSH | `T145A312B60E65703AC7874537D016C5B51BF4A53906E748BB2E082ED85DA74BE3F81B28` |
| SSDEEP | `1536:ECeHJbzFwp9WWuwDVsK7LK1kyFEvDQuUPJHFTYW+WkBLWh3nyrJv/:ECeFDWuwDVsKKsIhHGWaq0rR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_e0c17b87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0c17b87590f5c34c9ac68fe89a780b147c40754d757e53c3394ec47fa09b41d"
    family = "unknown"
    file_name = "Sped_debug_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:49"
  condition:
    hash.sha256(0, filesize) == "e0c17b87590f5c34c9ac68fe89a780b147c40754d757e53c3394ec47fa09b41d"
}
```

### Sample 32: `ca01c2bd0132c7ee`

| Field | Value |
|---|---|
| SHA-256 | `ca01c2bd0132c7ee9af1734ff9473bdf5d3ebc31b632e24c387b1cc79f667d2d` |
| Family label | `unknown` |
| File name | `MeteorClient_Plus_1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:44` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `196d37fd6795fc5ad3371b921516decc` |
| SHA-1 | `303c625799250eb29cc98fed5a072b50f1b7879f` |
| SHA-256 | `ca01c2bd0132c7ee9af1734ff9473bdf5d3ebc31b632e24c387b1cc79f667d2d` |
| SHA3-384 | `738554fa1cb75b9bf2cab705af6cb99e0335e6054f47538756c42353ba0370997be2283268c90060687146098cc5af56` |
| TLSH | `T14973022B1D80DCCDD56BD8387C37C6E42C2A5C26EA867B7CC586085D5AB18BB6383D5C` |
| SSDEEP | `1536:oZy5n8qoBIN2i+T5BQCubMkO01x28rPY5QPmrvV9ErEV8iIH+wNuF:gBIQlWCYNO+28VSrErEVN4+LF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_ca01c2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca01c2bd0132c7ee9af1734ff9473bdf5d3ebc31b632e24c387b1cc79f667d2d"
    family = "unknown"
    file_name = "MeteorClient_Plus_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:44"
  condition:
    hash.sha256(0, filesize) == "ca01c2bd0132c7ee9af1734ff9473bdf5d3ebc31b632e24c387b1cc79f667d2d"
}
```

### Sample 33: `50700097a2318d4e`

| Field | Value |
|---|---|
| SHA-256 | `50700097a2318d4e716ad4f0e1bbf6d3159dee5526a579fb4e365a1287de8fec` |
| Family label | `unknown` |
| File name | `Argon_Addon_1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:39` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3f5845e9a73edb58b4faf31fecab156` |
| SHA-1 | `fd343fdffa2c374841cbe26b0417a476218e5a29` |
| SHA-256 | `50700097a2318d4e716ad4f0e1bbf6d3159dee5526a579fb4e365a1287de8fec` |
| SHA3-384 | `03e8400a9767b5084fac446d42b60081f77408a58cac2cf64206bcad3e718f1583d9777eea9f0b04efed58634b9e56ae` |
| TLSH | `T1327302652DF0E950E76B61B200CCBFECB399142A53435DCDA23504D90DE69CA8FE6DAC` |
| SSDEEP | `1536:F5GADSa7qa5nK6l7VQh4IdM9zg7ZxTzEUq0jgvpzQ/ahVfbVDJk:3DDvqmnJl7yho9sTzHqAgvpzQozVFk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_50700097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50700097a2318d4e716ad4f0e1bbf6d3159dee5526a579fb4e365a1287de8fec"
    family = "unknown"
    file_name = "Argon_Addon_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:39"
  condition:
    hash.sha256(0, filesize) == "50700097a2318d4e716ad4f0e1bbf6d3159dee5526a579fb4e365a1287de8fec"
}
```

### Sample 34: `f912cf350ba42c1a`

| Field | Value |
|---|---|
| SHA-256 | `f912cf350ba42c1a74107a1afe1c863410872544595846d72f7f7197cd7a7d8f` |
| Family label | `unknown` |
| File name | `Argon_1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:34` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcc9a3074901334d57720b16de1ba0a1` |
| SHA-1 | `40b297d16ec9fc05ad5a9dad2cbe8a2cb9a3fe17` |
| SHA-256 | `f912cf350ba42c1a74107a1afe1c863410872544595846d72f7f7197cd7a7d8f` |
| SHA3-384 | `3d82b9d681c568d0a4bd3f35fbc38d7ae43e7fd123e13b8577fd2426ba3af306b3f84db2d7cd5b29d5341c4efe2f3455` |
| TLSH | `T193953309BB4E54B9DA4F93F13F0CA9E71A3D0C91D8A5210F29C865880D638DA7F5EB5C` |
| SSDEEP | `49152:jVYxegl78kbphCykyBawmuWSVt5Qi5kX3We:j8egtDp+yB+utD5oGe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_f912cf35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f912cf350ba42c1a74107a1afe1c863410872544595846d72f7f7197cd7a7d8f"
    family = "unknown"
    file_name = "Argon_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:34"
  condition:
    hash.sha256(0, filesize) == "f912cf350ba42c1a74107a1afe1c863410872544595846d72f7f7197cd7a7d8f"
}
```

### Sample 35: `f81b15882d9395e5`

| Field | Value |
|---|---|
| SHA-256 | `f81b15882d9395e53488d4c13cba1e4f4257976172bd6f12a3d26c3a61dc15ac` |
| Family label | `unknown` |
| File name | `2trouser-streak-1.6.1-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:29` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34952d5f0b9242b136208032ef0ccc93` |
| SHA-1 | `129038605bf7cb8abebb97ef40049756b30fbecd` |
| SHA-256 | `f81b15882d9395e53488d4c13cba1e4f4257976172bd6f12a3d26c3a61dc15ac` |
| SHA3-384 | `d491a616b5fe35d7804ae2c6d0960d05106a31b68376b1e6b4ceb96995d6fbfb982cae8def640afc4f8b0c9a6effa02e` |
| TLSH | `T1907312A1FD6FDEA7D71FCC7162887E36847A09973658AD63408801BA5BC3DE40D43D85` |
| SSDEEP | `1536:n59niibnSX9adYwfcq+3Ebf+O2sJ96h48ty8njKn:nn2XU7p+3Eb2OJQhg8jKn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_f81b1588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f81b15882d9395e53488d4c13cba1e4f4257976172bd6f12a3d26c3a61dc15ac"
    family = "unknown"
    file_name = "2trouser-streak-1.6.1-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:29"
  condition:
    hash.sha256(0, filesize) == "f81b15882d9395e53488d4c13cba1e4f4257976172bd6f12a3d26c3a61dc15ac"
}
```

### Sample 36: `144da0aeaea5caf8`

| Field | Value |
|---|---|
| SHA-256 | `144da0aeaea5caf8b2ea86d0158fa7c43326d88b98654c32afd6d68f5e1a8cad` |
| Family label | `unknown` |
| File name | `1trouser-streak-1.6.1-26.1.2.jar` |
| File type | `jar` |
| First seen | `2026-09-15 00:33:24` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `918e3efcd3d150cb76c212cf723d93bd` |
| SHA-1 | `fa5c3a38d9a48b24fd6c9743b72d625f0d31c8d0` |
| SHA-256 | `144da0aeaea5caf8b2ea86d0158fa7c43326d88b98654c32afd6d68f5e1a8cad` |
| SHA3-384 | `4f4c5ffcd2641e5139e37d8fc30c5f766efa2b20b98fa7298a3d508e80c99c7481270e14fce60239d40ff62411ea3018` |
| TLSH | `T196150241BF2B9527C12FA37C786A4921EEE890DCA92D218504FBD368CDD2CAD11B5F5C` |
| SSDEEP | `24576:cA09OPpo1AQM4nfsOlMcLODgdiiOMDJLIoPniy:41AOnUQxSI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_144da0ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "144da0aeaea5caf8b2ea86d0158fa7c43326d88b98654c32afd6d68f5e1a8cad"
    family = "unknown"
    file_name = "1trouser-streak-1.6.1-26.1.2.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:24"
  condition:
    hash.sha256(0, filesize) == "144da0aeaea5caf8b2ea86d0158fa7c43326d88b98654c32afd6d68f5e1a8cad"
}
```

### Sample 37: `1c65f6d3a349fbe7`

| Field | Value |
|---|---|
| SHA-256 | `1c65f6d3a349fbe7ebb6ebfc3cccd204372c6cbae98a540991a9f0dcf0090fb7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-15 00:31:10` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2e0cf5c2665a517e2bba6aeb1ebf028` |
| SHA-1 | `41202175d5b585cb7c8c749d13dedee502c2edd0` |
| SHA-256 | `1c65f6d3a349fbe7ebb6ebfc3cccd204372c6cbae98a540991a9f0dcf0090fb7` |
| SHA3-384 | `a2c4b46c80770790dfc96a8d70bb66a4378c946dd8803f880579a45283b48b84b54eeece95cef01576d6f8cfcd306f39` |
| TLSH | `T111E5E7F41CBA63B4CED34BB2E672A90BD5A7782C4A713093CE5603D354231AA7CD1B59` |
| SSDEEP | `49152:FzS4ps1rksprpo2TYFwSPvRoWfKCSZ/mvmwD/:A4pWLrRTFwvRoWfKCSZ/mvmwD/` |
| ICON-DHASH | `6c30e0cc69494d00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_1c65f6d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c65f6d3a349fbe7ebb6ebfc3cccd204372c6cbae98a540991a9f0dcf0090fb7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-15 00:31:10"
  condition:
    hash.sha256(0, filesize) == "1c65f6d3a349fbe7ebb6ebfc3cccd204372c6cbae98a540991a9f0dcf0090fb7"
}
```

### Sample 38: `53d3709927bdc75c`

| Field | Value |
|---|---|
| SHA-256 | `53d3709927bdc75c04c9f1174575513620b9f1a348caad5f055f79042fe3502f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 00:24:49` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `941bcddd53964912b40fea2a9703efb9` |
| SHA-256 | `53d3709927bdc75c04c9f1174575513620b9f1a348caad5f055f79042fe3502f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_53d37099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53d3709927bdc75c04c9f1174575513620b9f1a348caad5f055f79042fe3502f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 00:24:49"
  condition:
    hash.sha256(0, filesize) == "53d3709927bdc75c04c9f1174575513620b9f1a348caad5f055f79042fe3502f"
}
```

### Sample 39: `055dcf09917e321b`

| Field | Value |
|---|---|
| SHA-256 | `055dcf09917e321b63d38c3ab9f233bd43346c236a93d47e70e8639a6565056f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 00:24:32` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `854ef92588ad2819681c75dec1621925` |
| SHA-256 | `055dcf09917e321b63d38c3ab9f233bd43346c236a93d47e70e8639a6565056f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_055dcf09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "055dcf09917e321b63d38c3ab9f233bd43346c236a93d47e70e8639a6565056f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 00:24:32"
  condition:
    hash.sha256(0, filesize) == "055dcf09917e321b63d38c3ab9f233bd43346c236a93d47e70e8639a6565056f"
}
```

### Sample 40: `e147e9ee523c496a`

| Field | Value |
|---|---|
| SHA-256 | `e147e9ee523c496ad1c6abcfea75e2df8cac2a55601504b8d832ffd5fa637216` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-15 00:24:26` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4470a7be0279481fe276c4661cbd4340` |
| SHA-256 | `e147e9ee523c496ad1c6abcfea75e2df8cac2a55601504b8d832ffd5fa637216` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_e147e9ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e147e9ee523c496ad1c6abcfea75e2df8cac2a55601504b8d832ffd5fa637216"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 00:24:26"
  condition:
    hash.sha256(0, filesize) == "e147e9ee523c496ad1c6abcfea75e2df8cac2a55601504b8d832ffd5fa637216"
}
```

### Sample 41: `984c917a26534874`

| Field | Value |
|---|---|
| SHA-256 | `984c917a265348743e1612194129c08182d4a3b87dca676ca2957bcfcfb7ba9e` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d00fb2ad6ae29d07923974a39c1f3324` |
| SHA-1 | `c5edec6e8e17e65dd0ef8882b02debe9f6100db9` |
| SHA-256 | `984c917a265348743e1612194129c08182d4a3b87dca676ca2957bcfcfb7ba9e` |
| SHA3-384 | `d9a2ac561e2137cdfef00b05c87cbcecc47968f8d681b2cda609777d3171c26af3056e6649719fe462fb47a1abe9b7e3` |
| TLSH | `T1AED31986BB83DEB3E45310F102F79B315B31FD3A5822DA82E3B5BDB559654D0A60632C` |
| TELFHASH | `t16c7155b2afe90ddc7bd16801834e6361891df63f245076a606b2d84527baf82617bc38` |
| SSDEEP | `1536:l1mZ8lSTZw8IIzmuyrCQxBhWDxECJ/tLf/p8/sSPsW6eAUJ0Gohx9P+JgDzBJ4An:lGfVw8zvyaKC7Ty0SPPHhJMvLWAn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_984c917a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "984c917a265348743e1612194129c08182d4a3b87dca676ca2957bcfcfb7ba9e"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:55"
  condition:
    hash.sha256(0, filesize) == "984c917a265348743e1612194129c08182d4a3b87dca676ca2957bcfcfb7ba9e"
}
```

### Sample 42: `11ddeecddc36fdc6`

| Field | Value |
|---|---|
| SHA-256 | `11ddeecddc36fdc6e7c1ef548f7a058c4562181dced791a809f0f3cbdd98f1f4` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea89a8dbe0d018f6bc831c7dbe739aac` |
| SHA-1 | `83d4fafdffcf082c01f1bf1a42c908d6ae084ed8` |
| SHA-256 | `11ddeecddc36fdc6e7c1ef548f7a058c4562181dced791a809f0f3cbdd98f1f4` |
| SHA3-384 | `fbcf1fb34b4206c7d34e920a01264ec51239d123df1521dac316fad878e0c69f4ebe18feca8fd96ac40ec1a211da4521` |
| TLSH | `T11EE3F946BD418F13C6C721F6FB9E429C3B166F6DD6FA310399257FA0238A4D70A3A251` |
| SSDEEP | `3072:s/+zeJuzgrr2sHEy7dT4BFfbpHpaJMgL8u:s/eeJuohkMdT4BFbpJAMgL8u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_11ddeecd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11ddeecddc36fdc6e7c1ef548f7a058c4562181dced791a809f0f3cbdd98f1f4"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:49"
  condition:
    hash.sha256(0, filesize) == "11ddeecddc36fdc6e7c1ef548f7a058c4562181dced791a809f0f3cbdd98f1f4"
}
```

### Sample 43: `ed5111198033af68`

| Field | Value |
|---|---|
| SHA-256 | `ed5111198033af68921829ce367b3d0e2d7afb72dafcc20fc404911595dad8df` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33a1e9baf28b39650e28f91f5b717f65` |
| SHA-1 | `6531872d37c033cd2029e67a9e0dd079b2c35ad7` |
| SHA-256 | `ed5111198033af68921829ce367b3d0e2d7afb72dafcc20fc404911595dad8df` |
| SHA3-384 | `e3aa1593ae3200e38ee3b703c54a80c1fdc153557994f2c2478c952d55b32c47a50ed712d8ae1f963cefb4f614e1dfad` |
| TLSH | `T1A5D30809BA429F11D59731FAFB8F415933536FA8E3FA7101D9206F6123CA9DB0B76212` |
| SSDEEP | `3072:fEk73NgOlnw/GJzBUx16azmSC8u1c/VppVsLzjcXL:f5bNBuONBU36a6SC8u1kxVozjcXL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_ed511119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed5111198033af68921829ce367b3d0e2d7afb72dafcc20fc404911595dad8df"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:43"
  condition:
    hash.sha256(0, filesize) == "ed5111198033af68921829ce367b3d0e2d7afb72dafcc20fc404911595dad8df"
}
```

### Sample 44: `ba6ac641e7d4d686`

| Field | Value |
|---|---|
| SHA-256 | `ba6ac641e7d4d68625562b2c1068519b01b2dc046ca375b8290905e7c779c700` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2de1992df623ce00275b511fd8b176e1` |
| SHA-1 | `cc286efe097b3f2f2cf99aee1704d4dab2f8835d` |
| SHA-256 | `ba6ac641e7d4d68625562b2c1068519b01b2dc046ca375b8290905e7c779c700` |
| SHA3-384 | `b458d48346e4275bfdc21318c82157bf02bdc02c5c15f72c3da326afacf9b6d1ec211d23e831419a13c22a590645efb1` |
| TLSH | `T129F31C06B952CF12D1C311B9FF5E414D37136F78E3EA72029D24AFA067868EB0E7A516` |
| SSDEEP | `3072:3MfMPfdS7Rs1QYHRCqXKjd0hdazxicpMw2sbqCSsJ0DtT1G:3MU3dJ7xTXqdeawpw21CSsGDtJG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_ba6ac641
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba6ac641e7d4d68625562b2c1068519b01b2dc046ca375b8290905e7c779c700"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:36"
  condition:
    hash.sha256(0, filesize) == "ba6ac641e7d4d68625562b2c1068519b01b2dc046ca375b8290905e7c779c700"
}
```

### Sample 45: `48ed5f360461fb61`

| Field | Value |
|---|---|
| SHA-256 | `48ed5f360461fb6115d7508c2ddd57ee4526268e21685e30c771eee0172b0518` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4743cd8e0ad0f0a11fbb8d974d24fd30` |
| SHA-1 | `3da4d275354b0f13841499dac19fc4bc00a61b68` |
| SHA-256 | `48ed5f360461fb6115d7508c2ddd57ee4526268e21685e30c771eee0172b0518` |
| SHA3-384 | `7a09e9a8cf5d4dbed4f694e081ea9a611ede4b629f7b65df995b3e920e8bd3243809931edb5677603fc1a340ecdfee10` |
| TLSH | `T1DD24641A3E22DF7FF66D827047F38920579836962AE1D585F26CD70C1E2028E641FBE4` |
| TELFHASH | `t117419018097813f0a3695c5d05edff7ad6a331db7e162c338e51e86ae769a834d10c1c` |
| SSDEEP | `3072:WycpTz5Xu3udHQBwfLS4EBgF2sQnNX6Y6gCHNk:WycdzpskH5em2rNXrPCHNk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_48ed5f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48ed5f360461fb6115d7508c2ddd57ee4526268e21685e30c771eee0172b0518"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:34"
  condition:
    hash.sha256(0, filesize) == "48ed5f360461fb6115d7508c2ddd57ee4526268e21685e30c771eee0172b0518"
}
```

### Sample 46: `eb629e5c6971bdf2`

| Field | Value |
|---|---|
| SHA-256 | `eb629e5c6971bdf2f15ab5908c3374c8b518c5950a7e992b5cc690c5d93645df` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e065f2c1223b648fc44219ac1af4efc` |
| SHA-1 | `0c7ad4dc7270accd816b32d976214973d04396ca` |
| SHA-256 | `eb629e5c6971bdf2f15ab5908c3374c8b518c5950a7e992b5cc690c5d93645df` |
| SHA3-384 | `e30f3f3686095c160e108a188ae74a55846b1b0dfe974ba128569ee9bbced961004198ae5edd9e0ada1fbaefacc0b4db` |
| TLSH | `T1C0A35BC1F683F1FAFC1251B51027E3379733E439502ADA93C3ADEA26EC527518A1A61C` |
| TELFHASH | `t1a95128fb1e7a0df877d0a840c31eaba11d2dda7b1460369705b39824329bdc281bdd38` |
| SSDEEP | `1536:q37GK4AzAlUaVkUHzPnW8mHz39XqdcBNzSP8Ef1vw:+GpAz04UT+8IzZqYe5w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_eb629e5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb629e5c6971bdf2f15ab5908c3374c8b518c5950a7e992b5cc690c5d93645df"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:14"
  condition:
    hash.sha256(0, filesize) == "eb629e5c6971bdf2f15ab5908c3374c8b518c5950a7e992b5cc690c5d93645df"
}
```

### Sample 47: `b4d610165fad608a`

| Field | Value |
|---|---|
| SHA-256 | `b4d610165fad608a3f1fea5829703130e2750b8b0673b22191c2ac8398d86245` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de11e48f6f9c9661f7536d0270d359d6` |
| SHA-1 | `3ffcf1d5a871ef4de3b642c492831c332679e256` |
| SHA-256 | `b4d610165fad608a3f1fea5829703130e2750b8b0673b22191c2ac8398d86245` |
| SHA3-384 | `89c6e2562caa08fd3db5484f857f4696927e661b6ca5f5b267056be0823274222b6e2131714cfc96ca7da8028b39ce0b` |
| TLSH | `T11023074AFD805F00D9E525BAFE1E424D33934B7CE3FE7111AE215B2523C6A2B0B7A911` |
| TELFHASH | `t18cf09e104a856cedf3d2190ad38e76439912aaea3f746c8633ebbc075337f82053029d` |
| SSDEEP | `1536:5lnESiKbuDyyyyyyyyoPo0/IOWNFXiK2lnkivAt+JHC4D:vikr/IOWNFA1At+Ji+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_b4d61016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4d610165fad608a3f1fea5829703130e2750b8b0673b22191c2ac8398d86245"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:13"
  condition:
    hash.sha256(0, filesize) == "b4d610165fad608a3f1fea5829703130e2750b8b0673b22191c2ac8398d86245"
}
```

### Sample 48: `bd988816939ebc8d`

| Field | Value |
|---|---|
| SHA-256 | `bd988816939ebc8dc8dc7e0252ed5ad13c56426e4bbe0a695b6141fb37d0460c` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35c8c6efab7eb4fc2700596ebd8ca020` |
| SHA-1 | `5c1d9e2788a025eb4ab59f01b4a8ef511a1a8710` |
| SHA-256 | `bd988816939ebc8dc8dc7e0252ed5ad13c56426e4bbe0a695b6141fb37d0460c` |
| SHA3-384 | `55320accbf257533f86bd9eb689afbd12d964aa09e340895426e50177dcbb6f03d1537a1b16520d5f07ac467f91291a5` |
| TLSH | `T1B843F11BE2BFAB0CF68E2234084F5E8D0476DE40DA5499F59591BE386963ECA7104F87` |
| SSDEEP | `1536:hmy/9J+ILM+QIi44zRnX6kGqiEp7J+nh25pt1mq27GKnouy8Hy1:hmGgQiq3fm7Jw25piaSoutm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_bd988816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd988816939ebc8dc8dc7e0252ed5ad13c56426e4bbe0a695b6141fb37d0460c"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:11"
  condition:
    hash.sha256(0, filesize) == "bd988816939ebc8dc8dc7e0252ed5ad13c56426e4bbe0a695b6141fb37d0460c"
}
```

### Sample 49: `986a4a5b1e03c96e`

| Field | Value |
|---|---|
| SHA-256 | `986a4a5b1e03c96e04184c29c83897baa86ec0897da248f02cf66b75daefe7bc` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:10` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48a7cbc678746deec353c099c8f75c53` |
| SHA-1 | `e69021b2cceca2427fce8b97ec9d549453a319f5` |
| SHA-256 | `986a4a5b1e03c96e04184c29c83897baa86ec0897da248f02cf66b75daefe7bc` |
| SHA3-384 | `c1c72e8e829bebf32cac172b386c3e182e190239dde26102ac240ffd9b545c258b985841724c5f46bb3faa09360d8ea5` |
| TLSH | `T1AEB2080677580E5BD1AFBAB03A3F1BD493EBFF9112A4D681160EA7CAC1B5E371141C89` |
| SSDEEP | `384:rRT9osofADj7cIxakDJTDx/7NwgAVjTdAkA/bttVLV3OZi:rbom7cIB1VzAZAp/5tr3F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_986a4a5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "986a4a5b1e03c96e04184c29c83897baa86ec0897da248f02cf66b75daefe7bc"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:10"
  condition:
    hash.sha256(0, filesize) == "986a4a5b1e03c96e04184c29c83897baa86ec0897da248f02cf66b75daefe7bc"
}
```

### Sample 50: `9ff88017519fb71b`

| Field | Value |
|---|---|
| SHA-256 | `9ff88017519fb71b389b56d318192ac6e5127ce3addb1527fd29cbe44823b3a5` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d4c2f19014a31c83b43ecd485fc0ef2` |
| SHA-1 | `7cdbdb0c665bd2a4287ec8622195ddfbae6771c2` |
| SHA-256 | `9ff88017519fb71b389b56d318192ac6e5127ce3addb1527fd29cbe44823b3a5` |
| SHA3-384 | `2e8d6a3302c23ab99f52b91198c1e5e0b59cb444aa961bf1b9bfa4a68e9414ce4d74ef92253e03cc56130e0de1b06b49` |
| TLSH | `T1BED35B83B0037F2DF4D24136457E5BD53FA591C39B321CA78321EAE66B632B07A99871` |
| SSDEEP | `3072:FD7b7gqZ/Icmmm7i3x3aGlmHfQjoY3pGob:FDDgmAmqQtwfQjoYz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_9ff88017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ff88017519fb71b389b56d318192ac6e5127ce3addb1527fd29cbe44823b3a5"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:09"
  condition:
    hash.sha256(0, filesize) == "9ff88017519fb71b389b56d318192ac6e5127ce3addb1527fd29cbe44823b3a5"
}
```

### Sample 51: `2979a730fd65b8ad`

| Field | Value |
|---|---|
| SHA-256 | `2979a730fd65b8ad89c03aa64667b3265a320e4c375e2364dfbc775fb43ff5bf` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d606f4cecfa1134ca789dac1355f604` |
| SHA-1 | `0f13e7bea37eb5e07debf418d391d0495251f386` |
| SHA-256 | `2979a730fd65b8ad89c03aa64667b3265a320e4c375e2364dfbc775fb43ff5bf` |
| SHA3-384 | `901a7c5c202fb569a4e1b3a2c259c1942075fb27819ba2909501bf9fcb17f7f66fafb933a1abf871a986f7ac65461172` |
| TLSH | `T197E2944F6E328FDDF669C7344AF34E30A799238226E1C686D36CD1501E6024E985FBE5` |
| TELFHASH | `t184e0e51c1ab413a436348859485def57d1e030df77263c178b1314f977fc8425d29d04` |
| SSDEEP | `768:HFPuV73QkBfPgmj2/S3zLMiXoQ0eTK3yPn/:HVuVd8SDLLYIBn/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_2979a730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2979a730fd65b8ad89c03aa64667b3265a320e4c375e2364dfbc775fb43ff5bf"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:08"
  condition:
    hash.sha256(0, filesize) == "2979a730fd65b8ad89c03aa64667b3265a320e4c375e2364dfbc775fb43ff5bf"
}
```

### Sample 52: `9c4094d36da65b65`

| Field | Value |
|---|---|
| SHA-256 | `9c4094d36da65b655a0a05f129ba328b6852c81496e266a671035406a111ac03` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21739b3cb8b4d738960caeee0c49e346` |
| SHA-1 | `cd13e41b1e546f39d5a299324f716df6731b92f1` |
| SHA-256 | `9c4094d36da65b655a0a05f129ba328b6852c81496e266a671035406a111ac03` |
| SHA3-384 | `5d421a826e7de440fdbd224630be8272ff3fead62974d9006fed777fa471d03419354a02e60cfbd1c4dc799a363b6338` |
| TLSH | `T185B25C86FD814517CEE51176FA2E928C37665BB4E2FF3303AA221F642742A1F0F3A405` |
| TELFHASH | `t158115711864c8d9eb240856ce1ad46031626e1ba3c7e3a62bdfb981f810bcf39471926` |
| SSDEEP | `384:dG2m2FfIQp9Mgj6JwqQ87+2eZvaBcjQOF9hM4tXV5aceBy6jdmFx4eG:dfyRVg87+zvaOPFLM6qy6jF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_9c4094d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4094d36da65b655a0a05f129ba328b6852c81496e266a671035406a111ac03"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:06"
  condition:
    hash.sha256(0, filesize) == "9c4094d36da65b655a0a05f129ba328b6852c81496e266a671035406a111ac03"
}
```

### Sample 53: `51ffa5550b4d7d54`

| Field | Value |
|---|---|
| SHA-256 | `51ffa5550b4d7d549f3b1bc78af7f279e7e124224a08815df6bd9880f3700949` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74b1407b148b656f2c885b23c0816352` |
| SHA-1 | `245b62d2377a32e28753fd5d99e52569184f0386` |
| SHA-256 | `51ffa5550b4d7d549f3b1bc78af7f279e7e124224a08815df6bd9880f3700949` |
| SHA3-384 | `25751b880522f6946de98167918010eb3f81bc6308f4447971dc6db547dcb758d2cdd8b3a89e1cdd268baccf344c8e10` |
| TLSH | `T123B22B81E487E0F2E41B46B98092A77EDB30D61A2515D91BFF7097BDEE13911830F31A` |
| TELFHASH | `t149f0c8a1bd6204f9fbc7bd4ceb1e2643db365db20b1164fd58f6610179d1641d0b2001` |
| SSDEEP | `384:fCXJdg5g3tI4cjfaxWapnTUIsc83SFG1bhs7yURpOLja0pqKEtkzw:y7tIffgWkYIsnvdeGURpwa0pqK+Ow` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_51ffa555
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51ffa5550b4d7d549f3b1bc78af7f279e7e124224a08815df6bd9880f3700949"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:05"
  condition:
    hash.sha256(0, filesize) == "51ffa5550b4d7d549f3b1bc78af7f279e7e124224a08815df6bd9880f3700949"
}
```

### Sample 54: `661659a33ec77035`

| Field | Value |
|---|---|
| SHA-256 | `661659a33ec770358bd42c3c86d2301c81ab8277acda696b6e9640b85f36e7b4` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c9026a356d22e7d0435d9e69db24cc7` |
| SHA-1 | `8cca4e47f0ab747a84a7373800d14ed5dbd3095f` |
| SHA-256 | `661659a33ec770358bd42c3c86d2301c81ab8277acda696b6e9640b85f36e7b4` |
| SHA3-384 | `6f42b088044eebf11085dd56ecda5b1268dbf9f7b0527f0f846ca0f87f5cd8eae483ea3b92650facf6f4e16eab24eb70` |
| TLSH | `T15DE32A0EE14798A4F16281F1129D93F17D3065FB923BBC67DF4A17F1BB23282AD0525A` |
| TELFHASH | `t1103103f8357a0ce597d09853b28d0b212d0ea77b28a472f345b35524327fc8252bbc39` |
| SSDEEP | `3072:QoiQN/ylBUFh8+hM2xTPU+hNY1QAxKxqtI:/iQN/CmM+I+h21QAxKxqtI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_661659a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "661659a33ec770358bd42c3c86d2301c81ab8277acda696b6e9640b85f36e7b4"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:04"
  condition:
    hash.sha256(0, filesize) == "661659a33ec770358bd42c3c86d2301c81ab8277acda696b6e9640b85f36e7b4"
}
```

### Sample 55: `4381db9471d1286e`

| Field | Value |
|---|---|
| SHA-256 | `4381db9471d1286e4a633036dcb8d0daaa3b776e6c7291cb77f6c055968b7e4c` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cde5e808b340cd2abd47df45495ff4da` |
| SHA-1 | `0259cb1cb7f8b5885fc3564c17f660160bf2cbf1` |
| SHA-256 | `4381db9471d1286e4a633036dcb8d0daaa3b776e6c7291cb77f6c055968b7e4c` |
| SHA3-384 | `2306398633d787b81fd4c3e8e9ebf2e8f0c7e490f0233180623e17250a526d1902a879e0401205d1b038dfeb909a74f9` |
| TLSH | `T10D147B27A1539D81F04501F4166DC7F03F22A9CB27372D62ACAF82FA5B135E9BC59392` |
| SSDEEP | `1536:ijy6gh8gJnoZEVAV26Zj/Mtcl22rrL/scHMeEcUbI1f7ltpcrjZ0d8Snkn5p5M/7:X6gagJoZECHVD/scHXOIY/Z0+SnRqI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_4381db94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4381db9471d1286e4a633036dcb8d0daaa3b776e6c7291cb77f6c055968b7e4c"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:02"
  condition:
    hash.sha256(0, filesize) == "4381db9471d1286e4a633036dcb8d0daaa3b776e6c7291cb77f6c055968b7e4c"
}
```

### Sample 56: `d2d57498b71a7087`

| Field | Value |
|---|---|
| SHA-256 | `d2d57498b71a7087b94f25c0d661dd815378e6fb8a29ef804ba35c1369e5c4e7` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fd97068074b354a6f8d1266d57c7e0d` |
| SHA-1 | `ab3fdeb562ed2f51db24a407812bedabeba05977` |
| SHA-256 | `d2d57498b71a7087b94f25c0d661dd815378e6fb8a29ef804ba35c1369e5c4e7` |
| SHA3-384 | `b2fa5ad421c5354c440a533118fb058eacd04549fd9f3a35a0c1c825ae16b082ceecd9e91384efdd9b68f11560fb6ceb` |
| TLSH | `T1C2D32973ED269F4AC21BA1F0A1B14E751B53BD6649170EF9A476EAE48143CCCF2047B8` |
| SSDEEP | `3072:Pmy55ktgwMHC8Q55VAV1P+iNWfdOhk1A:7ktWHC8Q5T1i4f+k1A` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_d2d57498
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d57498b71a7087b94f25c0d661dd815378e6fb8a29ef804ba35c1369e5c4e7"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:01"
  condition:
    hash.sha256(0, filesize) == "d2d57498b71a7087b94f25c0d661dd815378e6fb8a29ef804ba35c1369e5c4e7"
}
```

### Sample 57: `a0be732007098c52`

| Field | Value |
|---|---|
| SHA-256 | `a0be732007098c52ceae1984b0c4a40a7fd5fcb41af813589c99d866094b6dfe` |
| Family label | `unknown` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-15 00:05:00` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e41a666d2da6848579370e8b128f777` |
| SHA-1 | `26f75f5f4b172a023986c96bb64b0df3eaa02f26` |
| SHA-256 | `a0be732007098c52ceae1984b0c4a40a7fd5fcb41af813589c99d866094b6dfe` |
| SHA3-384 | `45c5cfb94083fad977962aed81f2574a1124e99b70841ce36287f09cf90481a3ea5bd408278e9b546300366b564f883d` |
| TLSH | `T194D21A3AEA724913C4D499B895F3832CB9F9425F647D4B163C6B0EC4EB91AC06113FE8` |
| SSDEEP | `384:6ysT8AllDko1OxoUmdKzN57tSezXasmFFU+pph1K7R2w:6ysTZ3OxoHqBNeO+3K7Ew` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_a0be7320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0be732007098c52ceae1984b0c4a40a7fd5fcb41af813589c99d866094b6dfe"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:00"
  condition:
    hash.sha256(0, filesize) == "a0be732007098c52ceae1984b0c4a40a7fd5fcb41af813589c99d866094b6dfe"
}
```

### Sample 58: `a2c56d2c1461dcd6`

| Field | Value |
|---|---|
| SHA-256 | `a2c56d2c1461dcd696cfa53263457b547583397e49d83002d4ce38db5247b745` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb71de7ad99ba64a6b3729f593f2d3e9` |
| SHA-1 | `149b1f679806fde37c9d5892609406a5aebb092b` |
| SHA-256 | `a2c56d2c1461dcd696cfa53263457b547583397e49d83002d4ce38db5247b745` |
| SHA3-384 | `1b2b721f2d0168702d21effd46bbb74d801bae62640d4e5dd2dccd10ebd2ae22245bb8aef82a15b79792f9ba543dbfd4` |
| TLSH | `T13933027AC394917B4335203D7F16A73E6F328739A7D7548ACAB8616878C508B33B3915` |
| SSDEEP | `768:SwxvMs0fQjgitHHJiN205EYgrIPfPWIeZxNfkR9NleCIM6t3AH1rC9oTCPVis3Uj:f3BxHHkN2I5gkXO3Zxqm3A1Etfz8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_a2c56d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2c56d2c1461dcd696cfa53263457b547583397e49d83002d4ce38db5247b745"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:59"
  condition:
    hash.sha256(0, filesize) == "a2c56d2c1461dcd696cfa53263457b547583397e49d83002d4ce38db5247b745"
}
```

### Sample 59: `67b54624d9328a2d`

| Field | Value |
|---|---|
| SHA-256 | `67b54624d9328a2d31395aa5f8c02ddf4d56ee61ff23171aab889f344802ac71` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d747b2176594302c03f30628e63872d3` |
| SHA-1 | `a495134d113628005145dab8b72d10006af49a86` |
| SHA-256 | `67b54624d9328a2d31395aa5f8c02ddf4d56ee61ff23171aab889f344802ac71` |
| SHA3-384 | `971ebf054d77ca988e6f0bd4e03caab8c5abcc5cc26d6317686582f75235f8bfa3a5501d09a8c1b941af37283d8532f7` |
| TLSH | `T1C9143B47DE891EDBF00BC9B4866D43D23EA255DB51F6AE32857CCCDC7B4B2494AA3084` |
| SSDEEP | `1536:LCq7gl0vT2mr9gN/n3xNmfbogBux91wmkHlc3igLEEIQz6S1ljcXzisjVMFmfnKI:LCX0uNjgAql68jE4Xzism+zafT/1Pq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_67b54624
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b54624d9328a2d31395aa5f8c02ddf4d56ee61ff23171aab889f344802ac71"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:57"
  condition:
    hash.sha256(0, filesize) == "67b54624d9328a2d31395aa5f8c02ddf4d56ee61ff23171aab889f344802ac71"
}
```

### Sample 60: `eb71e1cd1e4fc87c`

| Field | Value |
|---|---|
| SHA-256 | `eb71e1cd1e4fc87c773d6bec1bb2319140ef9d6fa6c5ff6d17ae903a148ae454` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4835b452a9bc44abd1037a66435c7692` |
| SHA-1 | `c8784ffaa9b78451d9ca5d1eb86356e9c5603c24` |
| SHA-256 | `eb71e1cd1e4fc87c773d6bec1bb2319140ef9d6fa6c5ff6d17ae903a148ae454` |
| SHA3-384 | `7db0b83fc91e2e9a02c2e14f198531e1af75ddf248933c1eb6cfa706af5d9aa807975124b67277e62f58048136941bb1` |
| TLSH | `T1E9F32A8BF812CE52F5C016F9BA4D42C83F1213FBD2FA75129D154BB47B9754A0E3AA42` |
| TELFHASH | `t109e0d811be9c3d6c66da50cd542b412deaa232ca07403004cf0ab6871ee6da0b559c22` |
| SSDEEP | `3072:JJgnD+CCfEGLVQ1fDs2+NFJXdXP9yepuVxq:Je+B8fDs2+v9yiuVxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_eb71e1cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb71e1cd1e4fc87c773d6bec1bb2319140ef9d6fa6c5ff6d17ae903a148ae454"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:56"
  condition:
    hash.sha256(0, filesize) == "eb71e1cd1e4fc87c773d6bec1bb2319140ef9d6fa6c5ff6d17ae903a148ae454"
}
```

### Sample 61: `d8f0fc2dde29a06e`

| Field | Value |
|---|---|
| SHA-256 | `d8f0fc2dde29a06ef28695fb2da741843636ecf3b3b8e20c200db7bda957ea38` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89b18adde0bd2198131a4d46a7236cd3` |
| SHA-1 | `30a1c1aee5f9ba327bff2516fb76f32f27a241a4` |
| SHA-256 | `d8f0fc2dde29a06ef28695fb2da741843636ecf3b3b8e20c200db7bda957ea38` |
| SHA3-384 | `4a0693235c912c868d20b39375fe0ac2ead589981aedcac6634c04a6d1f532bd1c4cdc268414158cb499f6fe10fe7dbb` |
| TLSH | `T164E3294BF8428E52F5D116F5B79D42C83F1203FBC3FE7512AD045BB52B9785A0E2AA42` |
| TELFHASH | `t120e0c290f5bc264c5fc4407c9015810ba9e538e8633938009faed28fe8414947c29437` |
| SSDEEP | `3072:kC67IK70MNSklXOveh5XCUL7LwnvLVt/94TVxq4:ktLlZOveh5Z4LVtMVxq4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_d8f0fc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8f0fc2dde29a06ef28695fb2da741843636ecf3b3b8e20c200db7bda957ea38"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:55"
  condition:
    hash.sha256(0, filesize) == "d8f0fc2dde29a06ef28695fb2da741843636ecf3b3b8e20c200db7bda957ea38"
}
```

### Sample 62: `c37a868283f9deb5`

| Field | Value |
|---|---|
| SHA-256 | `c37a868283f9deb5e57a6f5853acea54137fe1582ded9c1a33026ae642f5a470` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c975b6618fdd042db2b3d6b65998756f` |
| SHA-1 | `162648a27c3f626d1f7c8da6f419881484bbfce9` |
| SHA-256 | `c37a868283f9deb5e57a6f5853acea54137fe1582ded9c1a33026ae642f5a470` |
| SHA3-384 | `9c319189bbe623add11862648bcd00d3dbaf965e2cc6638d8a795d9e7ca073bcdcbfc843262aef162c9a3c90d6346f24` |
| TLSH | `T1F6B23C91E7C3E0F7E88401FD1152D7516336F438216AFD4BEB2026BBB812921E757BA9` |
| TELFHASH | `t1d4f046c23daa01e8fa80fe4dd31f2a43db2a6ab8173570ef4cf5b20632c111481a141a` |
| SSDEEP | `384:fORoHGlOvCRVvpnzR3sGzBWl7uRI9BcwQZU8c1j9v4IFWkS+UGuyI:kYGlOvCRVvpnV3NAH9YU8cL4IFNStZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_c37a8682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c37a868283f9deb5e57a6f5853acea54137fe1582ded9c1a33026ae642f5a470"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:54"
  condition:
    hash.sha256(0, filesize) == "c37a868283f9deb5e57a6f5853acea54137fe1582ded9c1a33026ae642f5a470"
}
```

### Sample 63: `ff41a85b9b561bb4`

| Field | Value |
|---|---|
| SHA-256 | `ff41a85b9b561bb4626716f14d8155efda987fbbd2d21dd8fd16e63c2313e76c` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e973c023cf6dc7bd843f5e06b732d8e5` |
| SHA-1 | `85e90829bede78ab8898962bd322e9b9345026cf` |
| SHA-256 | `ff41a85b9b561bb4626716f14d8155efda987fbbd2d21dd8fd16e63c2313e76c` |
| SHA3-384 | `1b6505fa76ba4b5ebcf54e00086c96f481b68b4910acd44c8c2bfde256dd5717257a56456bb7091bac0ca54fd18e2c13` |
| TLSH | `T1AD330230D124BC4575A217B9E3F9814A04B7C8FC57BDBC63996948BA0D802A646F4CEF` |
| SSDEEP | `1536:Cq5ht3hCQ1nm7sjbetYKsh+nrDdGtBQI6hmHL9W:Cq5hTXmaCgh+nNGXj6hmHLk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_ff41a85b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff41a85b9b561bb4626716f14d8155efda987fbbd2d21dd8fd16e63c2313e76c"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:53"
  condition:
    hash.sha256(0, filesize) == "ff41a85b9b561bb4626716f14d8155efda987fbbd2d21dd8fd16e63c2313e76c"
}
```

### Sample 64: `af15a7b17b0a90a7`

| Field | Value |
|---|---|
| SHA-256 | `af15a7b17b0a90a7094f5b2d701452a69ede9b8fa1917c99eac23a25f848bc1c` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed1004f0fb469dd4ddf7d1e4039a770a` |
| SHA-1 | `e2b2002490b8ab7254eaca3a452dc902f485b7cc` |
| SHA-256 | `af15a7b17b0a90a7094f5b2d701452a69ede9b8fa1917c99eac23a25f848bc1c` |
| SHA3-384 | `0327f8307b387ae78737870e9cdf53bab7dd8103367ce8b72328caa27544a4a0d60ba254d7ab249fd78689fc00e3de10` |
| TLSH | `T1E8C20853A9C7F0FDC86982794187B034A273B039127ABD463BE5E72F6E7AE124F49401` |
| TELFHASH | `t1cff082b1b36638f0b6eb7d17a349d461c97c19f5046039e586b29cfdaf04fd04c05812` |
| SSDEEP | `384:DGBwSak2nTZD+zagYIpTtr5WXv+zXiL3zh8YyMm:DmU1DEYsIHzzhj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_af15a7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af15a7b17b0a90a7094f5b2d701452a69ede9b8fa1917c99eac23a25f848bc1c"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:52"
  condition:
    hash.sha256(0, filesize) == "af15a7b17b0a90a7094f5b2d701452a69ede9b8fa1917c99eac23a25f848bc1c"
}
```

### Sample 65: `d1012a4aebc3437c`

| Field | Value |
|---|---|
| SHA-256 | `d1012a4aebc3437c1e163736158e05411710b4ddd3d08b12e71b0999f4b57241` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ade40ee3b359aa84d8f342ac637a244` |
| SHA-1 | `a2ca9470b71494ef645a89dbef53def03440bc07` |
| SHA-256 | `d1012a4aebc3437c1e163736158e05411710b4ddd3d08b12e71b0999f4b57241` |
| SHA3-384 | `d9f0f5d16f9d8f5c8152c099e8621e264695a5d587c43ac04c34162965c2867dc8c2061f82c9376fadc0ac9ec139b101` |
| TLSH | `T165935B07B98154BEC0C7C73A935BD222E533B47017122A2B278CAE763E25F252F5D769` |
| TELFHASH | `t1b711dc4d9e7c0a1d6f837974edec67b1640ac4269b7a4f119f149380503e296910ed3f` |
| SSDEEP | `1536:CMotscmFip20OMJX8tyEp5kQv9c+hFPN7viEsNrahIyHD:jfw00aQQvDNeaKyHD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_d1012a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1012a4aebc3437c1e163736158e05411710b4ddd3d08b12e71b0999f4b57241"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:50"
  condition:
    hash.sha256(0, filesize) == "d1012a4aebc3437c1e163736158e05411710b4ddd3d08b12e71b0999f4b57241"
}
```

### Sample 66: `369ba5bed5a6fbd6`

| Field | Value |
|---|---|
| SHA-256 | `369ba5bed5a6fbd6b41dd5ec0b55823809c2286f16797972b6ece6b13f20e956` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16e4f688fb5fb92f581b8e6df33fe21f` |
| SHA-1 | `e54b5793a97b834776fbe08378721ad94592a57a` |
| SHA-256 | `369ba5bed5a6fbd6b41dd5ec0b55823809c2286f16797972b6ece6b13f20e956` |
| SHA3-384 | `72a57218672f18012f95cfd7022b109b56714b20fadadf99baa46a25fe07024841d2dfcb53230ed807d74eb37d209e6c` |
| TLSH | `T1F2635AC5F643D4F5E96705344137EB7BAA32F2B90229EB87E77482327C92642D90678C` |
| TELFHASH | `t14d31f0f71dbe0cd9b7d56810c31e5f922a59e23b2a5132a0056398b133a7fc150b9c3a` |
| SSDEEP | `1536:RaZsGDExpTGAtV+/C8eQBW2OnEGcfz3WyL35IUfA5PGFjfnP+:zGYxpTGASC4XTfyyLpIoYPsP+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_369ba5be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "369ba5bed5a6fbd6b41dd5ec0b55823809c2286f16797972b6ece6b13f20e956"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:49"
  condition:
    hash.sha256(0, filesize) == "369ba5bed5a6fbd6b41dd5ec0b55823809c2286f16797972b6ece6b13f20e956"
}
```

### Sample 67: `f3a0dabfa3647245`

| Field | Value |
|---|---|
| SHA-256 | `f3a0dabfa3647245c974f607f4dbb88accb74f8bdbe3e72ffd8ebdfa0c81b5fd` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ad42bdf16db219d99ea9cd7c4ec2388` |
| SHA-1 | `4775261c3bfe08891edaf71423969cd3d138ebd6` |
| SHA-256 | `f3a0dabfa3647245c974f607f4dbb88accb74f8bdbe3e72ffd8ebdfa0c81b5fd` |
| SHA3-384 | `edc5639fe1b348ffe1afa86f5de909e7ebf711ec75a7b466cb88f6a6c7e0656b48013ddfbaf53f1fba61fb009bd57160` |
| TLSH | `T1F0E2E815EF504EBBD8A7CD3344B84B4230CD6C2723F52B2B2D71E929B11A54A9BD39E4` |
| SSDEEP | `768:LXnUWeCvISc5UBHlwef7eNusXOXiq6OeXE3:LkagDyBCu70W6OW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_f3a0dabf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3a0dabfa3647245c974f607f4dbb88accb74f8bdbe3e72ffd8ebdfa0c81b5fd"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:48"
  condition:
    hash.sha256(0, filesize) == "f3a0dabfa3647245c974f607f4dbb88accb74f8bdbe3e72ffd8ebdfa0c81b5fd"
}
```

### Sample 68: `3843a11d8d205c61`

| Field | Value |
|---|---|
| SHA-256 | `3843a11d8d205c614c23a0905fb9d06a2822170c815d5be1aa87ca9540840fd4` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a6d9a93faf15e60ff7800eb1acdb2e6` |
| SHA-1 | `91e248fcdb89796f177c32997fb6732e350172b3` |
| SHA-256 | `3843a11d8d205c614c23a0905fb9d06a2822170c815d5be1aa87ca9540840fd4` |
| SHA3-384 | `0a69e65561bf9fd8e3efbb34bafc5f212cd37da5d9400cc12b95432669efd85dcec76f4969ec4265ba8eb426c7ea81dc` |
| TLSH | `T1FAC2E7FDF512A9ADF84EFB3E8401410D7A70A72550411A7537AAA937DC333A8193AE93` |
| SSDEEP | `384:KPda6gfFNg0fPL7WAlJFLMhOmJpcFuoZ8HAp3KV7Khb26oNwIkfabiQcfS:KVavfFfLW8FuK8E3Kkx26kwIkf+idfS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_3843a11d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3843a11d8d205c614c23a0905fb9d06a2822170c815d5be1aa87ca9540840fd4"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:47"
  condition:
    hash.sha256(0, filesize) == "3843a11d8d205c614c23a0905fb9d06a2822170c815d5be1aa87ca9540840fd4"
}
```

### Sample 69: `6ac13ba61c4aca04`

| Field | Value |
|---|---|
| SHA-256 | `6ac13ba61c4aca04b471adf9c6955c4e5bc5607499e7d735ecc5a246ef9cb870` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `578992212f50eac1c44d61c12920b0e1` |
| SHA-1 | `dc8007cc173ca70cd559e4817c89c15f8c5df599` |
| SHA-256 | `6ac13ba61c4aca04b471adf9c6955c4e5bc5607499e7d735ecc5a246ef9cb870` |
| SHA3-384 | `f7cd37c6831a5e5a295becc4b12f4fe106ee3519a72f6fe3889413865507e62595b19d349a2d1333b4ffba173c0a9232` |
| TLSH | `T100144B03F7054A62F45209705A7F07E2AFE180C325749C496A0FA7D61B33ABAD5D3FA9` |
| SSDEEP | `3072:7BqXK1HdSCxB0BL5nkrjKl9j8SnRs0piQ:dqXKnSCxB0BLVkyl91Rs2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_6ac13ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ac13ba61c4aca04b471adf9c6955c4e5bc5607499e7d735ecc5a246ef9cb870"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:45"
  condition:
    hash.sha256(0, filesize) == "6ac13ba61c4aca04b471adf9c6955c4e5bc5607499e7d735ecc5a246ef9cb870"
}
```

### Sample 70: `91b1e063ea4fefaa`

| Field | Value |
|---|---|
| SHA-256 | `91b1e063ea4fefaabbde9e9b71b4ff9024e28afc99174e6963043882f33e5213` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6e05b8a428984038a6c0a7364c18b0e` |
| SHA-1 | `8b74313bbab44fa65dc82c3b1e580e2b71b05090` |
| SHA-256 | `91b1e063ea4fefaabbde9e9b71b4ff9024e28afc99174e6963043882f33e5213` |
| SHA3-384 | `8cd7c50b112e92a56e8a8135658d749e419fdfef381f1063a64972ea99fb2664565845ea4fc33366c6aaca303fe2208d` |
| TLSH | `T16343026540EE8BF381A05E7A4C2D644CF8517F3882573881B4A9DA1D0A77EBE27F5087` |
| SSDEEP | `1536:ahWtDH36TFRiCQNi3iE/GLRF6cVb9gcLL:OWtb36TFRiP0iEE5VJgcLL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_91b1e063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91b1e063ea4fefaabbde9e9b71b4ff9024e28afc99174e6963043882f33e5213"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:44"
  condition:
    hash.sha256(0, filesize) == "91b1e063ea4fefaabbde9e9b71b4ff9024e28afc99174e6963043882f33e5213"
}
```

### Sample 71: `bb13f9dd26f736b7`

| Field | Value |
|---|---|
| SHA-256 | `bb13f9dd26f736b78dfe2cb4636c37f25e17ebe4394a7f8a8ed23568359d68ec` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76d2f89c084d0d8e39a2a39696914f19` |
| SHA-1 | `1ee5cdd5a084f70a07bb93e188ff0dcfe8d478d7` |
| SHA-256 | `bb13f9dd26f736b78dfe2cb4636c37f25e17ebe4394a7f8a8ed23568359d68ec` |
| SHA3-384 | `8e9b0aa2d7644a6344e263c708c0b0ea3b4a5adc8ce76bda6139a44782f720b599e80873fc8eda6a167802b1b8f777a6` |
| TLSH | `T18253F1BC0F1E0186DB9D96B01DB982C25FF50FD28A92CC43665EC5674642AE37892DEC` |
| SSDEEP | `1536:Ty1pRZlXrszwOh8eIkf7esRfQCccEjfuA6uevPMvE5Z4VJu3B:e1pBdlkjes9ccEqAuvPMvEX4VQx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_bb13f9dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb13f9dd26f736b78dfe2cb4636c37f25e17ebe4394a7f8a8ed23568359d68ec"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:43"
  condition:
    hash.sha256(0, filesize) == "bb13f9dd26f736b78dfe2cb4636c37f25e17ebe4394a7f8a8ed23568359d68ec"
}
```

### Sample 72: `45449a9cbd6e700e`

| Field | Value |
|---|---|
| SHA-256 | `45449a9cbd6e700e2e8fe87bfb0ac930e11a32b2441c0e1a652911c25878ecc7` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-15 00:04:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0f08e515e2d24c377ad2f4cce18228e` |
| SHA-1 | `3be226aebfeae048e5c09830bac8edc40ea330df` |
| SHA-256 | `45449a9cbd6e700e2e8fe87bfb0ac930e11a32b2441c0e1a652911c25878ecc7` |
| SHA3-384 | `110a505072a379259a4d5bb32e1d2c72fdee9dd8bd3bddba119406845869fe02399ad18c14d8f34df389f9cadd89e264` |
| TLSH | `T1DBB26CA18F3A1F94E26443B4642187384B53E41AB74F0EBE162FA3618443D8DF1967B8` |
| SSDEEP | `384:KG1lMaIPgfe4QFlCgg+Xzf38FmfIfRXomENGNXevVLZhdr75zoZ/ynTqBg7xpY:KG1KaIWe4QbCT+emfI5XV2LDoJuvzY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_45449a9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45449a9cbd6e700e2e8fe87bfb0ac930e11a32b2441c0e1a652911c25878ecc7"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:42"
  condition:
    hash.sha256(0, filesize) == "45449a9cbd6e700e2e8fe87bfb0ac930e11a32b2441c0e1a652911c25878ecc7"
}
```

### Sample 73: `a2172f40e99b78fd`

| Field | Value |
|---|---|
| SHA-256 | `a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff` |
| Family label | `unknown` |
| File name | `a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff.bin` |
| File type | `unknown` |
| First seen | `2026-09-15 00:04:19` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfb0c79b1ca5f52d78f19793d47052cd` |
| SHA-256 | `a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_a2172f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff"
    family = "unknown"
    file_name = "a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff.bin"
    file_type = "unknown"
    first_seen = "2026-09-15 00:04:19"
  condition:
    hash.sha256(0, filesize) == "a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff"
}
```

### Sample 74: `ad14ac5387ca612b`

| Field | Value |
|---|---|
| SHA-256 | `ad14ac5387ca612b118e65562fe6c5846755c635b89362f4e616c987ecf83ec8` |
| Family label | `unknown` |
| File name | `libcurl.dll` |
| File type | `exe` |
| First seen | `2026-09-14 23:47:44` |
| Reporter | `Kejult` |
| Tags | `dll, dropper, exe, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87addbde2d9772673afcd345876d56e9` |
| SHA-1 | `2f06d8ce3152f958e06ec8da4eeea3fa643f8176` |
| SHA-256 | `ad14ac5387ca612b118e65562fe6c5846755c635b89362f4e616c987ecf83ec8` |
| SHA3-384 | `dbe73161f4dd60749033046561c74ab453d7eb46eb58e8900b0407b8213f8f2f2e65f226b1a03f4d9b670530c9b6323b` |
| IMPHASH | `1e6a4142ad6a521fe1a5012997804f01` |
| TLSH | `T1B305120F57A809B7C4949239D8B71E09D772B9530662EB6F079452C63FA33A01E2BF35` |
| SSDEEP | `12288:/bLTaHMbPfD5ncSN7Kf2n3xJuxVErt3oZCP4+qRqZZfjhk3HRZ71nMXLLaDr5XoW:zLvbH9W2iER4pwThk3xZOXiDho1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_ad14ac53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad14ac5387ca612b118e65562fe6c5846755c635b89362f4e616c987ecf83ec8"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-09-14 23:47:44"
  condition:
    hash.sha256(0, filesize) == "ad14ac5387ca612b118e65562fe6c5846755c635b89362f4e616c987ecf83ec8"
}
```

### Sample 75: `5188e2aa998cb1c1`

| Field | Value |
|---|---|
| SHA-256 | `5188e2aa998cb1c1bb47ef6d1e4a88ca040cbf6323b28932e1fd5a8867a6c9ec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-14 23:23:30` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b6dcb7865fa21c057c9e1c515e0a93a` |
| SHA-256 | `5188e2aa998cb1c1bb47ef6d1e4a88ca040cbf6323b28932e1fd5a8867a6c9ec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_5188e2aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5188e2aa998cb1c1bb47ef6d1e4a88ca040cbf6323b28932e1fd5a8867a6c9ec"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 23:23:30"
  condition:
    hash.sha256(0, filesize) == "5188e2aa998cb1c1bb47ef6d1e4a88ca040cbf6323b28932e1fd5a8867a6c9ec"
}
```

### Sample 76: `27b80f1fc1dfbddd`

| Field | Value |
|---|---|
| SHA-256 | `27b80f1fc1dfbddd60b1a3993fe4f3995ef605036f05880eba39058fba428788` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-14 23:23:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `567827393a7605e986e3c5e00e3315ca` |
| SHA-256 | `27b80f1fc1dfbddd60b1a3993fe4f3995ef605036f05880eba39058fba428788` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_27b80f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b80f1fc1dfbddd60b1a3993fe4f3995ef605036f05880eba39058fba428788"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 23:23:23"
  condition:
    hash.sha256(0, filesize) == "27b80f1fc1dfbddd60b1a3993fe4f3995ef605036f05880eba39058fba428788"
}
```

### Sample 77: `74dd17083294d2a8`

| Field | Value |
|---|---|
| SHA-256 | `74dd17083294d2a8452debd0debf322b7d83c6eaa035333805128233976338a2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-14 23:04:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `074e6f4cada312cc90547d95cbd998fd` |
| SHA-1 | `ec20a82ef928ca1528364c90e5297811b8b04a0b` |
| SHA-256 | `74dd17083294d2a8452debd0debf322b7d83c6eaa035333805128233976338a2` |
| SHA3-384 | `c9adf1ce2102136522e4be98fa8d1b194736a80536a5626ed301eb1b19739a898d22ddfc8dea84dc487f15b87d87384c` |
| TLSH | `T118D31945FD409B23CAD226BBFB4E428D772A1768D3EE7203D9255F20378A9570E37642` |
| TELFHASH | `t1eae06155cc791dcc7dd40b8542de31716bd4312c7f0c9015e9789f5b4551594b43e81e` |
| SSDEEP | `1536:U2VMHvHrv7CBUIQW+cklUGFfPA02lMAD/ggTtZ5dyfrOn/6oWQHQwWBIlalwywm3:Uxvj74/OfP8MAcgP5E26oWCQjXwZepu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_74dd1708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74dd17083294d2a8452debd0debf322b7d83c6eaa035333805128233976338a2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-14 23:04:41"
  condition:
    hash.sha256(0, filesize) == "74dd17083294d2a8452debd0debf322b7d83c6eaa035333805128233976338a2"
}
```

### Sample 78: `5c8a0e5bd968d5ec`

| Field | Value |
|---|---|
| SHA-256 | `5c8a0e5bd968d5ec48414a31564cde204d45e1ce52abe09f23e5b16640f5afdf` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-14 22:29:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5871275c28294365475ed101110bcf4` |
| SHA-1 | `53c0ff51fb1ecc66f42de079cfbfa193fde620b3` |
| SHA-256 | `5c8a0e5bd968d5ec48414a31564cde204d45e1ce52abe09f23e5b16640f5afdf` |
| SHA3-384 | `c62589fbf6a513590a3c1875cd893a6f2e89086c942094f678dbe48cf657e700633577222e6d297ff658667488531b6c` |
| TLSH | `T190237D552A857C14AA98C4371D7E2F0CB9AD43E6320492ED7FCF3CF68C4A69D921871D` |
| SSDEEP | `768:2XOGVvOV9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:YLWGcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_5c8a0e5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8a0e5bd968d5ec48414a31564cde204d45e1ce52abe09f23e5b16640f5afdf"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 22:29:42"
  condition:
    hash.sha256(0, filesize) == "5c8a0e5bd968d5ec48414a31564cde204d45e1ce52abe09f23e5b16640f5afdf"
}
```

### Sample 79: `85b7f8b94b73b375`

| Field | Value |
|---|---|
| SHA-256 | `85b7f8b94b73b3751d7979c0bcb890af50fb31094d0c93130fa6f86068799c7e` |
| Family label | `DDoSAgent` |
| File name | `ppc64le` |
| File type | `elf` |
| First seen | `2026-09-14 22:25:45` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec58a9460004c2519c491a4b0143c1fb` |
| SHA-1 | `27bcf40f3a762eb5616a1029707435fcec4a657a` |
| SHA-256 | `85b7f8b94b73b3751d7979c0bcb890af50fb31094d0c93130fa6f86068799c7e` |
| SHA3-384 | `777dc3b69dd56f64220ecbd960f55d6c4fd8cfa86e9fb8caae1c0a7de512a9f5e06a6b1fd4cdda789ace95020b592284` |
| TLSH | `T1E2763A42F6496FE5C924493389E34E6123B3AD542B319B52E704F3BEACB63410F56F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:vpl66AtWwhylGD36RqRlXh7Fq+wZPOIfzu7ThSLr/Up5P5Es:Rl66AtHhylk36RSHCPFucLr8prEs` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_079_85b7f8b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85b7f8b94b73b3751d7979c0bcb890af50fb31094d0c93130fa6f86068799c7e"
    family = "DDoSAgent"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-09-14 22:25:45"
  condition:
    hash.sha256(0, filesize) == "85b7f8b94b73b3751d7979c0bcb890af50fb31094d0c93130fa6f86068799c7e"
}
```

### Sample 80: `bd7303f2214000df`

| Field | Value |
|---|---|
| SHA-256 | `bd7303f2214000dfe435d4c9d309895214db2c36a38c458a8028fccf1cca018d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-14 22:22:38` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ca88429c0e70fa565157171350eb0bc` |
| SHA-256 | `bd7303f2214000dfe435d4c9d309895214db2c36a38c458a8028fccf1cca018d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_bd7303f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd7303f2214000dfe435d4c9d309895214db2c36a38c458a8028fccf1cca018d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 22:22:38"
  condition:
    hash.sha256(0, filesize) == "bd7303f2214000dfe435d4c9d309895214db2c36a38c458a8028fccf1cca018d"
}
```

### Sample 81: `3ab3257610bad25f`

| Field | Value |
|---|---|
| SHA-256 | `3ab3257610bad25f96b03ed985940af3dab3fae69856d0264a52eff1e8d55184` |
| Family label | `DDoSAgent` |
| File name | `mips64le` |
| File type | `elf` |
| First seen | `2026-09-14 22:18:44` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bafd52290c38094c795782c5047820b4` |
| SHA-1 | `f6fb8866cdb19d05df48c3632bd3a755dda3fe31` |
| SHA-256 | `3ab3257610bad25f96b03ed985940af3dab3fae69856d0264a52eff1e8d55184` |
| SHA3-384 | `e13fda3f69180c62852cabad4ac7f3d87705d816fe938952aae49e479aa8b315d2321c3f6290bf521a132a3476ab469a` |
| TLSH | `T1CE862B51FEC22B66C58C037485EE626662607E454B92032337E4EBE83E7B73DDF56848` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:JPl+KXWWEA66v4m84aPI1i/23OuYXmj9U00d6vNgCoyY5EW:JdVjEN6v4x4anGqcyLEW` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_081_3ab32576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab3257610bad25f96b03ed985940af3dab3fae69856d0264a52eff1e8d55184"
    family = "DDoSAgent"
    file_name = "mips64le"
    file_type = "elf"
    first_seen = "2026-09-14 22:18:44"
  condition:
    hash.sha256(0, filesize) == "3ab3257610bad25f96b03ed985940af3dab3fae69856d0264a52eff1e8d55184"
}
```

### Sample 82: `3b77c5b788cf0ab7`

| Field | Value |
|---|---|
| SHA-256 | `3b77c5b788cf0ab705c5ad8589bf4abfcab4f3c021e4444072b04b839ea0f11d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-14 22:16:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f892286f0a6f926b32b6297a8e559146` |
| SHA-1 | `4868ecc19a92dbf3615743cad97e884301a9011e` |
| SHA-256 | `3b77c5b788cf0ab705c5ad8589bf4abfcab4f3c021e4444072b04b839ea0f11d` |
| SHA3-384 | `29f36f51c7705f11cad62a0b105369a466348346637fab2ea5e3b3e19b1168d4c8b599253ebd31cd09a3a3cc8ecbaab4` |
| TLSH | `T1E2236C661A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10971D` |
| SSDEEP | `768:PXRWNGxVE9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:plxHcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_3b77c5b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b77c5b788cf0ab705c5ad8589bf4abfcab4f3c021e4444072b04b839ea0f11d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 22:16:42"
  condition:
    hash.sha256(0, filesize) == "3b77c5b788cf0ab705c5ad8589bf4abfcab4f3c021e4444072b04b839ea0f11d"
}
```

### Sample 83: `d78530edbd145e6a`

| Field | Value |
|---|---|
| SHA-256 | `d78530edbd145e6ab5daf2b68f5260dc51b279d0552a8092da0b018eeeb2fe64` |
| Family label | `unknown` |
| File name | `KerRansom.exe` |
| File type | `exe` |
| First seen | `2026-09-14 22:09:35` |
| Reporter | `AmadeyHunter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60fa63a3620e71e6b7512cab6e9a9b54` |
| SHA-1 | `c9168a65e3e9bc8e12d36417bbef97b559c78b31` |
| SHA-256 | `d78530edbd145e6ab5daf2b68f5260dc51b279d0552a8092da0b018eeeb2fe64` |
| SHA3-384 | `78a64c59e3a897135a34e61cc2d3bd7bbd1a324b2dd8b5699a720e04e347d85cb8b0028bf5777e80491c85881eec3855` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15F824D4177F54728F1BB0B796AB746201B37B862DC36C38E09CC558D1FB37488866B66` |
| SSDEEP | `192:IDuXiXeD394/uapXPUygZ3Wsb815GO9URdJyS9QMW7joSTJtYNDgeNqgtgUHo/40:/iOZ25PvgVfcf9URd7QngjheB4sG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_d78530ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d78530edbd145e6ab5daf2b68f5260dc51b279d0552a8092da0b018eeeb2fe64"
    family = "unknown"
    file_name = "KerRansom.exe"
    file_type = "exe"
    first_seen = "2026-09-14 22:09:35"
  condition:
    hash.sha256(0, filesize) == "d78530edbd145e6ab5daf2b68f5260dc51b279d0552a8092da0b018eeeb2fe64"
}
```

### Sample 84: `923efaa33499532b`

| Field | Value |
|---|---|
| SHA-256 | `923efaa33499532bf5e2bc911375a184f1310f8e13032c6ad5cecbcba466eaab` |
| Family label | `DDoSAgent` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-09-14 22:04:44` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1aa1cee984bcff6ea8f8b25c9726e984` |
| SHA-1 | `c7991fb10b7d9dded3f32954d6806af7c49db0d1` |
| SHA-256 | `923efaa33499532bf5e2bc911375a184f1310f8e13032c6ad5cecbcba466eaab` |
| SHA3-384 | `eec067309ccd1c8b1b28d252a4bae95d2904a8cadfeb4971dfa46981ebbdbf645b211b5ed4a8af338384c5ad845e3d7a` |
| TLSH | `T148862851BF98EE1FD69521348AA7C27473E53D0181F420369A62FB0D1EBF2B0991BDD8` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:KvKWwdKi+wH80zlJPYAt1Y/mjF8k8zXwbHHUt5Ee:Ksc0zPBSXwbnUjEe` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_084_923efaa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "923efaa33499532bf5e2bc911375a184f1310f8e13032c6ad5cecbcba466eaab"
    family = "DDoSAgent"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-14 22:04:44"
  condition:
    hash.sha256(0, filesize) == "923efaa33499532bf5e2bc911375a184f1310f8e13032c6ad5cecbcba466eaab"
}
```

### Sample 85: `cc149bcff87af9e9`

| Field | Value |
|---|---|
| SHA-256 | `cc149bcff87af9e93a32087711b2f974f8236e90e9a89f8727f29b8b520cce15` |
| Family label | `DDoSAgent` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-09-14 22:02:43` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b09d1ed70620312fae4f5d4f2aa7fee1` |
| SHA-1 | `810a4c5452c023bf8b48b94be29cf15e233abbc0` |
| SHA-256 | `cc149bcff87af9e93a32087711b2f974f8236e90e9a89f8727f29b8b520cce15` |
| SHA3-384 | `5fe01768f01b46ba3de7e7b24c9745a31aa464019cc848de23d3513a4e9fe04366a79d548ced7f8b59942a57bed739aa` |
| TLSH | `T187766B91F788A135D94A0B328CA30B70B3612D82C1E4C96F5709F76F59B26F6694FED0` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Jxf61fKxKz116ZRJp++InEXZ9MBsTP1aSgWLoQfsLFYhKt8qm2yht1UwHHUt5ERy:Iz11mgBsoSgWJWSG8q+5nUjEs` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_085_cc149bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc149bcff87af9e93a32087711b2f974f8236e90e9a89f8727f29b8b520cce15"
    family = "DDoSAgent"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-09-14 22:02:43"
  condition:
    hash.sha256(0, filesize) == "cc149bcff87af9e93a32087711b2f974f8236e90e9a89f8727f29b8b520cce15"
}
```

### Sample 86: `65967cdfe6d7afaa`

| Field | Value |
|---|---|
| SHA-256 | `65967cdfe6d7afaab4022101e177b315d773dfd1ddec609a2a08d751f7a9f7f2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-14 21:56:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7a451032a230cb91dbc052573b42551` |
| SHA-1 | `8baa0309b505c5a0ff55888338e97cad25c77e31` |
| SHA-256 | `65967cdfe6d7afaab4022101e177b315d773dfd1ddec609a2a08d751f7a9f7f2` |
| SHA3-384 | `86a8e84325723eaf9c42565743c6edf8de214e7716e6ca945d71a7aa8fcf82762bad42351e91e8cfde2f570965fad901` |
| TLSH | `T168C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:28vCB+25j6es8RR9FYpMSUpi+20qUpi+20YQX:28l25JHd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_65967cdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65967cdfe6d7afaab4022101e177b315d773dfd1ddec609a2a08d751f7a9f7f2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 21:56:41"
  condition:
    hash.sha256(0, filesize) == "65967cdfe6d7afaab4022101e177b315d773dfd1ddec609a2a08d751f7a9f7f2"
}
```

### Sample 87: `2c7a07e88d6166e1`

| Field | Value |
|---|---|
| SHA-256 | `2c7a07e88d6166e1b73e637ece612a8d2b4745f137889186f36f7f54b99e6843` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-09-14 21:46:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8381627f0537223e821462f2ba10633` |
| SHA-1 | `429c7dfa39a684c9ba72790a307ab2c2664180be` |
| SHA-256 | `2c7a07e88d6166e1b73e637ece612a8d2b4745f137889186f36f7f54b99e6843` |
| SHA3-384 | `6c145c7daf7ca9db53b5820bf0de12c1485346e3b2bc3467fbd018a062c8f55f518ac82a0917db252221554183ff98ff` |
| TLSH | `T1CB762997B9D24952C4E83637BCBE81C433631EB99B87525A6D05FE383ABE1D90E35304` |
| TELFHASH | `t140d05e6d9e4d6accdfbac0c0464e11494dd870f4261493b94f29771b0042061b54f052` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:IUn42YavOZkpldPOOMmnT8+jn80UXzuVZiGZrtCdBNk9b5QIon45Ec:IUPvbOOMmnT8+jn805iJNk92KEc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_2c7a07e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c7a07e88d6166e1b73e637ece612a8d2b4745f137889186f36f7f54b99e6843"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-14 21:46:46"
  condition:
    hash.sha256(0, filesize) == "2c7a07e88d6166e1b73e637ece612a8d2b4745f137889186f36f7f54b99e6843"
}
```

### Sample 88: `8209f6d4cf183d4e`

| Field | Value |
|---|---|
| SHA-256 | `8209f6d4cf183d4ebe5bb60c3a1ebee96cb734cba4a7f65569993c3626ed5dfb` |
| Family label | `DDoSAgent` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-14 21:46:44` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c210c859171b45d0fabc96a032181eb` |
| SHA-1 | `b2f2186047ef8b573d7c7324116b0c8f4bf3eee4` |
| SHA-256 | `8209f6d4cf183d4ebe5bb60c3a1ebee96cb734cba4a7f65569993c3626ed5dfb` |
| SHA3-384 | `d72f4b8624d7f66c718ba34eae7bd3d310f29a55fbcbcabf159c63152a0e7df7588f2da4ae95432977a0805a70b7de6d` |
| TLSH | `T1F5763903FCA515A8C0AAD534CA769223BB727C895B3123D72F90F7682F72BD06979750` |
| TELFHASH | `t1874289754ebd38b4b39ad910b3a2b4b4953728a572f438b15023e994ffc1e801ce6877` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Je9lMJNz1flr8VHjvgf7KiPr6zf2Ieq+VD7TX1cOM1U65RLrIv8PAa1y8v+2PVeD:JeULpMojmz+M+VD3lOK8veu25sTyMEx` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_088_8209f6d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8209f6d4cf183d4ebe5bb60c3a1ebee96cb734cba4a7f65569993c3626ed5dfb"
    family = "DDoSAgent"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-14 21:46:44"
  condition:
    hash.sha256(0, filesize) == "8209f6d4cf183d4ebe5bb60c3a1ebee96cb734cba4a7f65569993c3626ed5dfb"
}
```

### Sample 89: `ac6d9d241447c7e7`

| Field | Value |
|---|---|
| SHA-256 | `ac6d9d241447c7e75cbd103af057ff1f1361972b26de93f7885a15a44946a5f0` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-09-14 21:45:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa64c4002f9848762ea0fc14e74ef66f` |
| SHA-1 | `7ade3cb2510da05e59255cd2805b1cc4d45499af` |
| SHA-256 | `ac6d9d241447c7e75cbd103af057ff1f1361972b26de93f7885a15a44946a5f0` |
| SHA3-384 | `1637d8293294f3e97d9cfecb59367bda707152ad60daed12817fde0ae2ca5ac8b8ad745b2747c280671e586addfdbb78` |
| TLSH | `T13176199BB9D24952C4E43A37BCBD80C432631EB99B87525A6D05FE383EBE5D90E34314` |
| TELFHASH | `t180d0a76a5e0f2a8cc7bad0c00f1e10488de83df81b1593b86f09776f5143091395e010` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:y1myh2/lqmnjLpIrJ00TElcX5cZ5IiXGZfaz5x4hLFs6gxpag45EX:GmhqopIrJ00TElcX5cSc4hLFsNbaREX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_ac6d9d24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac6d9d241447c7e75cbd103af057ff1f1361972b26de93f7885a15a44946a5f0"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-14 21:45:49"
  condition:
    hash.sha256(0, filesize) == "ac6d9d241447c7e75cbd103af057ff1f1361972b26de93f7885a15a44946a5f0"
}
```

### Sample 90: `9859c5629611b8b3`

| Field | Value |
|---|---|
| SHA-256 | `9859c5629611b8b3c40f4827bf0e92cb09894df39f98b9690ca8ff949c33a6f6` |
| Family label | `unknown` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-09-14 21:45:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `152e4a912a90ba0c78abd4f4b1b3e0dc` |
| SHA-1 | `a8c5a6125cf429ba6953217b9a2d04cc33d02a57` |
| SHA-256 | `9859c5629611b8b3c40f4827bf0e92cb09894df39f98b9690ca8ff949c33a6f6` |
| SHA3-384 | `e52b367a66dccbb2a2588fb3e5f07a3759fa0e37ce275819a815a96604d7e4b0c5b9206c5999a8e281e26d3aca61adc8` |
| TLSH | `T1C0761997B9924952C4E83A37BCBD80C433634EB98B87525A6D15FE383EBE1D90E34354` |
| TELFHASH | `t113d05e6a5f6d2b4c8ff2c650060e20194ee82078032193644e4e673b9283895364e051` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:23hoLjXUI3y6XLDHw3y5ghh3YxeVwWM3VH3jiPrlE78khwQoPw45Ee:U2PUyy67DHw3y5ghhd3rlE788wQYBEe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_9859c562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9859c5629611b8b3c40f4827bf0e92cb09894df39f98b9690ca8ff949c33a6f6"
    family = "unknown"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-14 21:45:47"
  condition:
    hash.sha256(0, filesize) == "9859c5629611b8b3c40f4827bf0e92cb09894df39f98b9690ca8ff949c33a6f6"
}
```

### Sample 91: `6a18b61cba5b5517`

| Field | Value |
|---|---|
| SHA-256 | `6a18b61cba5b5517594dbb37fe581b937196b987d74b41025279e942bdeb6312` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-14 21:44:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c8937aaf44299585dbcf3f900a7083c` |
| SHA-1 | `3cfcb079a65e2d70ad3b42051e0ef9b0f45d2af8` |
| SHA-256 | `6a18b61cba5b5517594dbb37fe581b937196b987d74b41025279e942bdeb6312` |
| SHA3-384 | `e8c5e68df2912fd3c4f2e426003d66c4ae3166c48b143b20b738fb29192b7808c9777fae770b280ae0eca940743f4b8f` |
| TLSH | `T1F9C27C956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:i8vCB+25j6es8RI9FYpMSUpi+20qUpi+20YQX:i8l25Jed2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_6a18b61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a18b61cba5b5517594dbb37fe581b937196b987d74b41025279e942bdeb6312"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 21:44:42"
  condition:
    hash.sha256(0, filesize) == "6a18b61cba5b5517594dbb37fe581b937196b987d74b41025279e942bdeb6312"
}
```

### Sample 92: `d5db35dfa6dc550a`

| Field | Value |
|---|---|
| SHA-256 | `d5db35dfa6dc550a9cf6b53586672410a2a08df31979d2141933b59cbf5116da` |
| Family label | `unknown` |
| File name | `EXE A ANALIZAR.zip` |
| File type | `zip` |
| First seen | `2026-09-14 21:44:13` |
| Reporter | `cypherpunk472` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1adb634b0b498a770a19f53788ca4039` |
| SHA-1 | `b1342ca30f841542b67d238ee7cf473e12d0b54d` |
| SHA-256 | `d5db35dfa6dc550a9cf6b53586672410a2a08df31979d2141933b59cbf5116da` |
| SHA3-384 | `b0db9887e8608d677affa6a4eca0a5f8046ebf7bddbe53b66b65b17be95b6cff00604241a7d528a089932c48c325afaf` |
| TLSH | `T19FD633AD546058E4E3E1E47AD3AF9D1B901D80C7B2FA26C31EFE6D94E85F80EE5C5090` |
| SSDEEP | `393216:GZbZYPz4gd3mH0TPS1+oU0Ao130QNSEw3OM3oboJhEFR:YbePzvPS1nmoN04SN3OWJhEj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_d5db35df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5db35dfa6dc550a9cf6b53586672410a2a08df31979d2141933b59cbf5116da"
    family = "unknown"
    file_name = "EXE A ANALIZAR.zip"
    file_type = "zip"
    first_seen = "2026-09-14 21:44:13"
  condition:
    hash.sha256(0, filesize) == "d5db35dfa6dc550a9cf6b53586672410a2a08df31979d2141933b59cbf5116da"
}
```

### Sample 93: `165192a853ab1a3e`

| Field | Value |
|---|---|
| SHA-256 | `165192a853ab1a3ee6dee068afb67c551be4c60e8d8fef23a1b63eeadde9efec` |
| Family label | `DDoSAgent` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-14 21:41:43` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54c20f11b1daceb046f5e0b40d94e7cf` |
| SHA-1 | `96db0f8a7342bde4be0a072f09b15b3ba35d665b` |
| SHA-256 | `165192a853ab1a3ee6dee068afb67c551be4c60e8d8fef23a1b63eeadde9efec` |
| SHA3-384 | `30a5ed87e6550cff6f2265a7ce83154dfffc8e9f057abecb841131f1ac9a00d700eca1f53b5b317179d01916ba643084` |
| TLSH | `T1828618177A69EB0EC76921341CB2CE9427291C8506D7A527B381F30CE9F21BD4A6ECF5` |
| TELFHASH | `t1729002500885550c256408785d3df60161e0a82350350418bb445f92905c41a234c465` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:+3zavDfaY2zCynHkV+9B9WxJRcV7uXywE52LmtMfMb7T3ZsXdzn+uD+BpYNTzseB:F5RvFSuDWYbyPi5ydKt7fLynUjEa` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_093_165192a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "165192a853ab1a3ee6dee068afb67c551be4c60e8d8fef23a1b63eeadde9efec"
    family = "DDoSAgent"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-14 21:41:43"
  condition:
    hash.sha256(0, filesize) == "165192a853ab1a3ee6dee068afb67c551be4c60e8d8fef23a1b63eeadde9efec"
}
```

### Sample 94: `94f86588275cf31d`

| Field | Value |
|---|---|
| SHA-256 | `94f86588275cf31d3b0569a6dcbc534bbcb0adddc02f1c7f0d2ffa2a172930cc` |
| Family label | `DDoSAgent` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-14 21:40:47` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34e31818fafc00afa24951dc13cf1902` |
| SHA-1 | `40598cb7e5f5755de3600618af7401a71f7239d7` |
| SHA-256 | `94f86588275cf31d3b0569a6dcbc534bbcb0adddc02f1c7f0d2ffa2a172930cc` |
| SHA3-384 | `b621b5f249bec2e0fcb8e3d3292c4d39e6ee9c361dfd279e39166a1dd724004e7fc6da8c46fd4b5918c68e3fcd405c85` |
| TLSH | `T159762751FECB50F6E9031D3144ABA23F23325D058F28DB97EA507F29F97BA911936209` |
| TELFHASH | `t1bee2beb3159d64e877f0880787af7524cef6e0f726f078f159e6b8c09672c829626874` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:APOuZqGyquErK4DDODpqGGAsvvf+phwE1:AR8BbGV4hJ1` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_094_94f86588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94f86588275cf31d3b0569a6dcbc534bbcb0adddc02f1c7f0d2ffa2a172930cc"
    family = "DDoSAgent"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-14 21:40:47"
  condition:
    hash.sha256(0, filesize) == "94f86588275cf31d3b0569a6dcbc534bbcb0adddc02f1c7f0d2ffa2a172930cc"
}
```

### Sample 95: `2148a8f11eb5ecc6`

| Field | Value |
|---|---|
| SHA-256 | `2148a8f11eb5ecc6568a2a9535786a3809bd2331b993ace8a9d6c8e01c50451a` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-09-14 21:39:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7e3999b3a682e3138086d3dad69280e` |
| SHA-1 | `b869066434b5e268c538a81ba62578be9b15d92a` |
| SHA-256 | `2148a8f11eb5ecc6568a2a9535786a3809bd2331b993ace8a9d6c8e01c50451a` |
| SHA3-384 | `4425f7680f5bb0e5515487d979969acbf0b9697a4a196a99d671afa3341480e5a36f09858a0071aa1533e4e4b3542731` |
| TLSH | `T1F9667B46BC5D6463D9C9B6351FA712943339BC089F82C7276A14BB7CE9F23588F132A1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:+if6N4pwjVg3gZfxLatZzpH15lVZ+6RJKsMkSWWJ3NmojP5E3:+us4pgg3gZfstZzpHjd+6Ru9TE3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_2148a8f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2148a8f11eb5ecc6568a2a9535786a3809bd2331b993ace8a9d6c8e01c50451a"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-09-14 21:39:43"
  condition:
    hash.sha256(0, filesize) == "2148a8f11eb5ecc6568a2a9535786a3809bd2331b993ace8a9d6c8e01c50451a"
}
```

### Sample 96: `4ef2b2638d876707`

| Field | Value |
|---|---|
| SHA-256 | `4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a` |
| Family label | `Vidar` |
| File name | `4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a.bin` |
| File type | `exe` |
| First seen | `2026-09-14 21:38:51` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2662d8ddaa38e648c7b331e2568ebec` |
| SHA-1 | `a1e7bb38f43baf8a6c7300a4cc73d34133ba18e9` |
| SHA-256 | `4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a` |
| SHA3-384 | `fe75994fcd7fe12d359ec291f3bbb3ceb1795e3c66a269028ad295a47d1042f78dd4e8593fdb04b8181681d112d72cc2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B5567B17FD9108E9C0DAA23189A79252BB71BC494B3223D72FA0B7782F727D06D78754` |
| SSDEEP | `49152:WFklDT/uQkck/7Tgr5jAt5mzP68YR66qUMAM+iM5FOZ30TMqcuzrBexKcK9KJERV:WCYeAizybJqxM5Fk0TMv4rCE+s` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_096_4ef2b263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a"
    family = "Vidar"
    file_name = "4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a.bin"
    file_type = "exe"
    first_seen = "2026-09-14 21:38:51"
  condition:
    hash.sha256(0, filesize) == "4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a"
}
```

### Sample 97: `aee47183a08adfd0`

| Field | Value |
|---|---|
| SHA-256 | `aee47183a08adfd0ccfcc3d319ceb32fffebd99c1f843c92efb8a4027fd43b3d` |
| Family label | `DDoSAgent` |
| File name | `ppc64le` |
| File type | `elf` |
| First seen | `2026-09-14 21:38:44` |
| Reporter | `abuse_ch` |
| Tags | `DDoSAgent, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d2b29ac5f85af4cea6bd344175e02ac` |
| SHA-1 | `1a678a927212407d2ddafac2907e546165865a6d` |
| SHA-256 | `aee47183a08adfd0ccfcc3d319ceb32fffebd99c1f843c92efb8a4027fd43b3d` |
| SHA3-384 | `8cd4235a157a34db73038cfdc276eee07d3b054bf6d75f0b5b392258da82b1147f24246bde29bef83ad43e590e259bf5` |
| TLSH | `T15B763942F6496FE5C924493385E34E612373AD542B319B52EB44F2BEADB73020F16F98` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Nhm/bX8L4Yn4QmQ1oZ+LCmtCQPZIItzu7T3M1vRNwP5EE:Dm/bX8UYnpmQ10gxPPuHEvRIEE` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_097_aee47183
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aee47183a08adfd0ccfcc3d319ceb32fffebd99c1f843c92efb8a4027fd43b3d"
    family = "DDoSAgent"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-09-14 21:38:44"
  condition:
    hash.sha256(0, filesize) == "aee47183a08adfd0ccfcc3d319ceb32fffebd99c1f843c92efb8a4027fd43b3d"
}
```

### Sample 98: `7b2716ab74fcdd19`

| Field | Value |
|---|---|
| SHA-256 | `7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399` |
| Family label | `unknown` |
| File name | `7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399` |
| File type | `unknown` |
| First seen | `2026-09-14 21:30:17` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bb737a05a57a0faad9cab3e7b10fadf` |
| SHA-256 | `7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_7b2716ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399"
    family = "unknown"
    file_name = "7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399"
    file_type = "unknown"
    first_seen = "2026-09-14 21:30:17"
  condition:
    hash.sha256(0, filesize) == "7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399"
}
```

### Sample 99: `b6419e147a22be9c`

| Field | Value |
|---|---|
| SHA-256 | `b6419e147a22be9c254afdd69253ebb648e27725d26c5072a849d0fcb9886932` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-14 21:21:51` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, loader_proxy_v1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bf9e59f784b8828ba3be8029705417c` |
| SHA-256 | `b6419e147a22be9c254afdd69253ebb648e27725d26c5072a849d0fcb9886932` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_b6419e14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6419e147a22be9c254afdd69253ebb648e27725d26c5072a849d0fcb9886932"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 21:21:51"
  condition:
    hash.sha256(0, filesize) == "b6419e147a22be9c254afdd69253ebb648e27725d26c5072a849d0fcb9886932"
}
```

### Sample 100: `7652f213a448eacb`

| Field | Value |
|---|---|
| SHA-256 | `7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81` |
| Family label | `unknown` |
| File name | `7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81` |
| File type | `unknown` |
| First seen | `2026-09-14 21:15:25` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72242dfddd5d7bb2586420407823214d` |
| SHA-256 | `7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_7652f213
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81"
    family = "unknown"
    file_name = "7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81"
    file_type = "unknown"
    first_seen = "2026-09-14 21:15:25"
  condition:
    hash.sha256(0, filesize) == "7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81"
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
 * Generated: 2026-09-15T05:01:19.482441+00:00
 */

rule MalwareBazaar_unknown_001_0277ef3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37"
    family = "unknown"
    file_name = "0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37.bin"
    file_type = "exe"
    first_seen = "2026-09-15 04:50:23"
  condition:
    hash.sha256(0, filesize) == "0277ef3cbf8986b7ffeefb5c8e4d2dc9af7c79c01e920438fe4ad11c2510aa37"
}

rule MalwareBazaar_unknown_002_b4190630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c"
    family = "unknown"
    file_name = "b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c.bin"
    file_type = "exe"
    first_seen = "2026-09-15 04:50:11"
  condition:
    hash.sha256(0, filesize) == "b41906309049e71902ad617f8c83abd325f633de595311f9666272551d56b75c"
}

rule MalwareBazaar_unknown_003_15c866b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15c866b13c0570599bf7ab1124de239afa107296f2740ef40e19295408518367"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-15 04:27:48"
  condition:
    hash.sha256(0, filesize) == "15c866b13c0570599bf7ab1124de239afa107296f2740ef40e19295408518367"
}

rule MalwareBazaar_unknown_004_b0c1c463
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0c1c46317a49973e100bac37ef92c39c81680e53635826fedb9979d04aba027"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 04:27:44"
  condition:
    hash.sha256(0, filesize) == "b0c1c46317a49973e100bac37ef92c39c81680e53635826fedb9979d04aba027"
}

rule MalwareBazaar_unknown_005_fdb78eea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdb78eea518d6c632fb05206989403d4c2c5fd6143e7f9ecb3007552b0040ee1"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 04:27:37"
  condition:
    hash.sha256(0, filesize) == "fdb78eea518d6c632fb05206989403d4c2c5fd6143e7f9ecb3007552b0040ee1"
}

rule MalwareBazaar_unknown_006_f79830fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f79830fcc9e617d4497668f8cd0b3718cc0c606d2a52ae6d45566af6986f3caa"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-15 04:18:51"
  condition:
    hash.sha256(0, filesize) == "f79830fcc9e617d4497668f8cd0b3718cc0c606d2a52ae6d45566af6986f3caa"
}

rule MalwareBazaar_unknown_007_3fe634ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fe634abe12ecaaaa52597bed14bd61e3d58908e55c803ab20b09043f80da76f"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-15 04:15:50"
  condition:
    hash.sha256(0, filesize) == "3fe634abe12ecaaaa52597bed14bd61e3d58908e55c803ab20b09043f80da76f"
}

rule MalwareBazaar_unknown_008_6759c723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6759c72365d0c690db613ff30635970668f5699b65c3842ecdc4f1b695ed13a7"
    family = "unknown"
    file_name = "fail"
    file_type = "unknown"
    first_seen = "2026-09-15 03:54:31"
  condition:
    hash.sha256(0, filesize) == "6759c72365d0c690db613ff30635970668f5699b65c3842ecdc4f1b695ed13a7"
}

rule MalwareBazaar_unknown_009_f8d09bb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8d09bb7ef38015342fb8ae11c489fc1a3f01e743123e4222e9291cb474fb75e"
    family = "unknown"
    file_name = "app.zip"
    file_type = "zip"
    first_seen = "2026-09-15 03:54:28"
  condition:
    hash.sha256(0, filesize) == "f8d09bb7ef38015342fb8ae11c489fc1a3f01e743123e4222e9291cb474fb75e"
}

rule MalwareBazaar_unknown_010_df6d5478
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df6d5478ddb0af048dd9090b304cadb5077170785d542b95236749f1e6f72651"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-15 03:27:26"
  condition:
    hash.sha256(0, filesize) == "df6d5478ddb0af048dd9090b304cadb5077170785d542b95236749f1e6f72651"
}

rule MalwareBazaar_unknown_011_7bcc255e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bcc255efa1b2810ce3daba713ab1b89403bbdc96d39fa88c8015d937dd75acd"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 03:26:55"
  condition:
    hash.sha256(0, filesize) == "7bcc255efa1b2810ce3daba713ab1b89403bbdc96d39fa88c8015d937dd75acd"
}

rule MalwareBazaar_unknown_012_b94f3f72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94f3f723573c5513ee3f1d0ef52a25ce40ff251bfd0b9c2e584565c564e07e3"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 03:26:45"
  condition:
    hash.sha256(0, filesize) == "b94f3f723573c5513ee3f1d0ef52a25ce40ff251bfd0b9c2e584565c564e07e3"
}

rule MalwareBazaar_unknown_013_b74680f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b74680f5b86f229f3df6e0b1e7f4384a0f330b3e7108ab048df5a90a09d4946d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 03:04:42"
  condition:
    hash.sha256(0, filesize) == "b74680f5b86f229f3df6e0b1e7f4384a0f330b3e7108ab048df5a90a09d4946d"
}

rule MalwareBazaar_unknown_014_948ec40a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "948ec40af3fd4ed80929c53e08733bd7ecf2598ee9f93e203bd0ad88bab52ed5"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 02:26:09"
  condition:
    hash.sha256(0, filesize) == "948ec40af3fd4ed80929c53e08733bd7ecf2598ee9f93e203bd0ad88bab52ed5"
}

rule MalwareBazaar_unknown_015_24429840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24429840c4558d541a70878ad980e8e51e4acac371f28344ce2455391bf23b05"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 02:26:02"
  condition:
    hash.sha256(0, filesize) == "24429840c4558d541a70878ad980e8e51e4acac371f28344ce2455391bf23b05"
}

rule MalwareBazaar_unknown_016_a47f99ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a47f99ee1afb916c204d48410e385afe772895c1f2d40570eb63f22f5ee5bf99"
    family = "unknown"
    file_name = "MV GREAT AMITY QUOTATION FORM.js"
    file_type = "js"
    first_seen = "2026-09-15 02:25:37"
  condition:
    hash.sha256(0, filesize) == "a47f99ee1afb916c204d48410e385afe772895c1f2d40570eb63f22f5ee5bf99"
}

rule MalwareBazaar_unknown_017_b84d080e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b84d080e5839eaf4ff997066dd152e1454bc71238c192ee2fbd1946a15214046"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-15 02:05:52"
  condition:
    hash.sha256(0, filesize) == "b84d080e5839eaf4ff997066dd152e1454bc71238c192ee2fbd1946a15214046"
}

rule MalwareBazaar_unknown_018_2d6a5297
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6a529713ed9e2871b7553f253818c078d342b8e3475be140c8fb47bedcf125"
    family = "unknown"
    file_name = "bypass.ps1"
    file_type = "ps1"
    first_seen = "2026-09-15 01:45:39"
  condition:
    hash.sha256(0, filesize) == "2d6a529713ed9e2871b7553f253818c078d342b8e3475be140c8fb47bedcf125"
}

rule MalwareBazaar_unknown_019_616e2875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "616e28750cba299b1d0d055be7889176533eb473c73cca40888a46f29a885cc8"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 01:25:43"
  condition:
    hash.sha256(0, filesize) == "616e28750cba299b1d0d055be7889176533eb473c73cca40888a46f29a885cc8"
}

rule MalwareBazaar_unknown_020_67531c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67531c07cc3224ff2b8756a057164fe64b21a3cc9190218438365c183e0591db"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 01:25:34"
  condition:
    hash.sha256(0, filesize) == "67531c07cc3224ff2b8756a057164fe64b21a3cc9190218438365c183e0591db"
}

rule MalwareBazaar_unknown_021_4c0a1be9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c0a1be9b84d1c7332f90ad6600b6a40585448a67bedb714417c4cbdfbe27f92"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 01:25:05"
  condition:
    hash.sha256(0, filesize) == "4c0a1be9b84d1c7332f90ad6600b6a40585448a67bedb714417c4cbdfbe27f92"
}

rule MalwareBazaar_unknown_022_0e8870f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85"
    family = "unknown"
    file_name = "0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85"
    file_type = "elf"
    first_seen = "2026-09-15 00:58:16"
  condition:
    hash.sha256(0, filesize) == "0e8870f48e3971b4f1586129a25be97ba15ff6fcca0b7abb303b7c02f1f94b85"
}

rule MalwareBazaar_CoinMiner_023_2899b8a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2899b8a2d4d7c47fff7e1c6cf63d8dbfb6c440a037ab399514f508164e2b0894"
    family = "CoinMiner"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.27176296"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:52"
  condition:
    hash.sha256(0, filesize) == "2899b8a2d4d7c47fff7e1c6cf63d8dbfb6c440a037ab399514f508164e2b0894"
}

rule MalwareBazaar_unknown_024_70f775cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70f775cdcbd1dc33a8fe195c3d9edd702b3b6d2f226a049d7cefc8e7cee3163b"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.22653435"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:51"
  condition:
    hash.sha256(0, filesize) == "70f775cdcbd1dc33a8fe195c3d9edd702b3b6d2f226a049d7cefc8e7cee3163b"
}

rule MalwareBazaar_unknown_025_11d5ae7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d5ae7c90cb88ff232dc6556ad9ed2185d981f23206defbce7eb88c19c0e090"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Midie.189066.22482136"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:49"
  condition:
    hash.sha256(0, filesize) == "11d5ae7c90cb88ff232dc6556ad9ed2185d981f23206defbce7eb88c19c0e090"
}

rule MalwareBazaar_unknown_026_0880c280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0880c280f51a7c22fdbc5d15a4d13e1137d27003cb2775430023370082afcc58"
    family = "unknown"
    file_name = "SecuriteInfo.com.Variant.Midie.189100.48315442"
    file_type = "exe"
    first_seen = "2026-09-15 00:43:47"
  condition:
    hash.sha256(0, filesize) == "0880c280f51a7c22fdbc5d15a4d13e1137d27003cb2775430023370082afcc58"
}

rule MalwareBazaar_unknown_027_35579494
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3557949447ce7bd6b6b1c66bc49ca4b421ec28640757a1e18c6fed9732889fdb"
    family = "unknown"
    file_name = "WizzyAddonFree.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:34:12"
  condition:
    hash.sha256(0, filesize) == "3557949447ce7bd6b6b1c66bc49ca4b421ec28640757a1e18c6fed9732889fdb"
}

rule MalwareBazaar_unknown_028_d59f3052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d59f3052ca0a0f0fec3e4d2fe78f5f531a074ec4b6fd1f0bcf1a04f28ca14a02"
    family = "unknown"
    file_name = "Wizzy_Addon_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:34:08"
  condition:
    hash.sha256(0, filesize) == "d59f3052ca0a0f0fec3e4d2fe78f5f531a074ec4b6fd1f0bcf1a04f28ca14a02"
}

rule MalwareBazaar_unknown_029_155acb35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "155acb35cece5a4df8255853905e6136c5af5ae8725110c8cfe37786126dd994"
    family = "unknown"
    file_name = "Sped_Debug_V4.3.1.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:34:03"
  condition:
    hash.sha256(0, filesize) == "155acb35cece5a4df8255853905e6136c5af5ae8725110c8cfe37786126dd994"
}

rule MalwareBazaar_unknown_030_6bec0401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bec04011ad77b53986ddb64707fc9cd86a4ee5903ad79a95b5d55c1df525c50"
    family = "unknown"
    file_name = "Sped_Debug_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:54"
  condition:
    hash.sha256(0, filesize) == "6bec04011ad77b53986ddb64707fc9cd86a4ee5903ad79a95b5d55c1df525c50"
}

rule MalwareBazaar_unknown_031_e0c17b87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0c17b87590f5c34c9ac68fe89a780b147c40754d757e53c3394ec47fa09b41d"
    family = "unknown"
    file_name = "Sped_debug_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:49"
  condition:
    hash.sha256(0, filesize) == "e0c17b87590f5c34c9ac68fe89a780b147c40754d757e53c3394ec47fa09b41d"
}

rule MalwareBazaar_unknown_032_ca01c2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca01c2bd0132c7ee9af1734ff9473bdf5d3ebc31b632e24c387b1cc79f667d2d"
    family = "unknown"
    file_name = "MeteorClient_Plus_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:44"
  condition:
    hash.sha256(0, filesize) == "ca01c2bd0132c7ee9af1734ff9473bdf5d3ebc31b632e24c387b1cc79f667d2d"
}

rule MalwareBazaar_unknown_033_50700097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50700097a2318d4e716ad4f0e1bbf6d3159dee5526a579fb4e365a1287de8fec"
    family = "unknown"
    file_name = "Argon_Addon_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:39"
  condition:
    hash.sha256(0, filesize) == "50700097a2318d4e716ad4f0e1bbf6d3159dee5526a579fb4e365a1287de8fec"
}

rule MalwareBazaar_unknown_034_f912cf35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f912cf350ba42c1a74107a1afe1c863410872544595846d72f7f7197cd7a7d8f"
    family = "unknown"
    file_name = "Argon_1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:34"
  condition:
    hash.sha256(0, filesize) == "f912cf350ba42c1a74107a1afe1c863410872544595846d72f7f7197cd7a7d8f"
}

rule MalwareBazaar_unknown_035_f81b1588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f81b15882d9395e53488d4c13cba1e4f4257976172bd6f12a3d26c3a61dc15ac"
    family = "unknown"
    file_name = "2trouser-streak-1.6.1-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:29"
  condition:
    hash.sha256(0, filesize) == "f81b15882d9395e53488d4c13cba1e4f4257976172bd6f12a3d26c3a61dc15ac"
}

rule MalwareBazaar_unknown_036_144da0ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "144da0aeaea5caf8b2ea86d0158fa7c43326d88b98654c32afd6d68f5e1a8cad"
    family = "unknown"
    file_name = "1trouser-streak-1.6.1-26.1.2.jar"
    file_type = "jar"
    first_seen = "2026-09-15 00:33:24"
  condition:
    hash.sha256(0, filesize) == "144da0aeaea5caf8b2ea86d0158fa7c43326d88b98654c32afd6d68f5e1a8cad"
}

rule MalwareBazaar_unknown_037_1c65f6d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c65f6d3a349fbe7ebb6ebfc3cccd204372c6cbae98a540991a9f0dcf0090fb7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-15 00:31:10"
  condition:
    hash.sha256(0, filesize) == "1c65f6d3a349fbe7ebb6ebfc3cccd204372c6cbae98a540991a9f0dcf0090fb7"
}

rule MalwareBazaar_unknown_038_53d37099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53d3709927bdc75c04c9f1174575513620b9f1a348caad5f055f79042fe3502f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 00:24:49"
  condition:
    hash.sha256(0, filesize) == "53d3709927bdc75c04c9f1174575513620b9f1a348caad5f055f79042fe3502f"
}

rule MalwareBazaar_unknown_039_055dcf09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "055dcf09917e321b63d38c3ab9f233bd43346c236a93d47e70e8639a6565056f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 00:24:32"
  condition:
    hash.sha256(0, filesize) == "055dcf09917e321b63d38c3ab9f233bd43346c236a93d47e70e8639a6565056f"
}

rule MalwareBazaar_unknown_040_e147e9ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e147e9ee523c496ad1c6abcfea75e2df8cac2a55601504b8d832ffd5fa637216"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-15 00:24:26"
  condition:
    hash.sha256(0, filesize) == "e147e9ee523c496ad1c6abcfea75e2df8cac2a55601504b8d832ffd5fa637216"
}

rule MalwareBazaar_Mirai_041_984c917a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "984c917a265348743e1612194129c08182d4a3b87dca676ca2957bcfcfb7ba9e"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:55"
  condition:
    hash.sha256(0, filesize) == "984c917a265348743e1612194129c08182d4a3b87dca676ca2957bcfcfb7ba9e"
}

rule MalwareBazaar_Mirai_042_11ddeecd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11ddeecddc36fdc6e7c1ef548f7a058c4562181dced791a809f0f3cbdd98f1f4"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:49"
  condition:
    hash.sha256(0, filesize) == "11ddeecddc36fdc6e7c1ef548f7a058c4562181dced791a809f0f3cbdd98f1f4"
}

rule MalwareBazaar_Mirai_043_ed511119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed5111198033af68921829ce367b3d0e2d7afb72dafcc20fc404911595dad8df"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:43"
  condition:
    hash.sha256(0, filesize) == "ed5111198033af68921829ce367b3d0e2d7afb72dafcc20fc404911595dad8df"
}

rule MalwareBazaar_Mirai_044_ba6ac641
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba6ac641e7d4d68625562b2c1068519b01b2dc046ca375b8290905e7c779c700"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:36"
  condition:
    hash.sha256(0, filesize) == "ba6ac641e7d4d68625562b2c1068519b01b2dc046ca375b8290905e7c779c700"
}

rule MalwareBazaar_Mirai_045_48ed5f36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48ed5f360461fb6115d7508c2ddd57ee4526268e21685e30c771eee0172b0518"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:34"
  condition:
    hash.sha256(0, filesize) == "48ed5f360461fb6115d7508c2ddd57ee4526268e21685e30c771eee0172b0518"
}

rule MalwareBazaar_Mirai_046_eb629e5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb629e5c6971bdf2f15ab5908c3374c8b518c5950a7e992b5cc690c5d93645df"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:14"
  condition:
    hash.sha256(0, filesize) == "eb629e5c6971bdf2f15ab5908c3374c8b518c5950a7e992b5cc690c5d93645df"
}

rule MalwareBazaar_Mirai_047_b4d61016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4d610165fad608a3f1fea5829703130e2750b8b0673b22191c2ac8398d86245"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:13"
  condition:
    hash.sha256(0, filesize) == "b4d610165fad608a3f1fea5829703130e2750b8b0673b22191c2ac8398d86245"
}

rule MalwareBazaar_Mirai_048_bd988816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd988816939ebc8dc8dc7e0252ed5ad13c56426e4bbe0a695b6141fb37d0460c"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:11"
  condition:
    hash.sha256(0, filesize) == "bd988816939ebc8dc8dc7e0252ed5ad13c56426e4bbe0a695b6141fb37d0460c"
}

rule MalwareBazaar_unknown_049_986a4a5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "986a4a5b1e03c96e04184c29c83897baa86ec0897da248f02cf66b75daefe7bc"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:10"
  condition:
    hash.sha256(0, filesize) == "986a4a5b1e03c96e04184c29c83897baa86ec0897da248f02cf66b75daefe7bc"
}

rule MalwareBazaar_Mirai_050_9ff88017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ff88017519fb71b389b56d318192ac6e5127ce3addb1527fd29cbe44823b3a5"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:09"
  condition:
    hash.sha256(0, filesize) == "9ff88017519fb71b389b56d318192ac6e5127ce3addb1527fd29cbe44823b3a5"
}

rule MalwareBazaar_unknown_051_2979a730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2979a730fd65b8ad89c03aa64667b3265a320e4c375e2364dfbc775fb43ff5bf"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:08"
  condition:
    hash.sha256(0, filesize) == "2979a730fd65b8ad89c03aa64667b3265a320e4c375e2364dfbc775fb43ff5bf"
}

rule MalwareBazaar_Mirai_052_9c4094d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c4094d36da65b655a0a05f129ba328b6852c81496e266a671035406a111ac03"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:06"
  condition:
    hash.sha256(0, filesize) == "9c4094d36da65b655a0a05f129ba328b6852c81496e266a671035406a111ac03"
}

rule MalwareBazaar_unknown_053_51ffa555
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51ffa5550b4d7d549f3b1bc78af7f279e7e124224a08815df6bd9880f3700949"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:05"
  condition:
    hash.sha256(0, filesize) == "51ffa5550b4d7d549f3b1bc78af7f279e7e124224a08815df6bd9880f3700949"
}

rule MalwareBazaar_Mirai_054_661659a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "661659a33ec770358bd42c3c86d2301c81ab8277acda696b6e9640b85f36e7b4"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:04"
  condition:
    hash.sha256(0, filesize) == "661659a33ec770358bd42c3c86d2301c81ab8277acda696b6e9640b85f36e7b4"
}

rule MalwareBazaar_Mirai_055_4381db94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4381db9471d1286e4a633036dcb8d0daaa3b776e6c7291cb77f6c055968b7e4c"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:02"
  condition:
    hash.sha256(0, filesize) == "4381db9471d1286e4a633036dcb8d0daaa3b776e6c7291cb77f6c055968b7e4c"
}

rule MalwareBazaar_Mirai_056_d2d57498
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d57498b71a7087b94f25c0d661dd815378e6fb8a29ef804ba35c1369e5c4e7"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:01"
  condition:
    hash.sha256(0, filesize) == "d2d57498b71a7087b94f25c0d661dd815378e6fb8a29ef804ba35c1369e5c4e7"
}

rule MalwareBazaar_unknown_057_a0be7320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0be732007098c52ceae1984b0c4a40a7fd5fcb41af813589c99d866094b6dfe"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-15 00:05:00"
  condition:
    hash.sha256(0, filesize) == "a0be732007098c52ceae1984b0c4a40a7fd5fcb41af813589c99d866094b6dfe"
}

rule MalwareBazaar_Mirai_058_a2c56d2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2c56d2c1461dcd696cfa53263457b547583397e49d83002d4ce38db5247b745"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:59"
  condition:
    hash.sha256(0, filesize) == "a2c56d2c1461dcd696cfa53263457b547583397e49d83002d4ce38db5247b745"
}

rule MalwareBazaar_Mirai_059_67b54624
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b54624d9328a2d31395aa5f8c02ddf4d56ee61ff23171aab889f344802ac71"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:57"
  condition:
    hash.sha256(0, filesize) == "67b54624d9328a2d31395aa5f8c02ddf4d56ee61ff23171aab889f344802ac71"
}

rule MalwareBazaar_Mirai_060_eb71e1cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb71e1cd1e4fc87c773d6bec1bb2319140ef9d6fa6c5ff6d17ae903a148ae454"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:56"
  condition:
    hash.sha256(0, filesize) == "eb71e1cd1e4fc87c773d6bec1bb2319140ef9d6fa6c5ff6d17ae903a148ae454"
}

rule MalwareBazaar_Mirai_061_d8f0fc2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8f0fc2dde29a06ef28695fb2da741843636ecf3b3b8e20c200db7bda957ea38"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:55"
  condition:
    hash.sha256(0, filesize) == "d8f0fc2dde29a06ef28695fb2da741843636ecf3b3b8e20c200db7bda957ea38"
}

rule MalwareBazaar_unknown_062_c37a8682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c37a868283f9deb5e57a6f5853acea54137fe1582ded9c1a33026ae642f5a470"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:54"
  condition:
    hash.sha256(0, filesize) == "c37a868283f9deb5e57a6f5853acea54137fe1582ded9c1a33026ae642f5a470"
}

rule MalwareBazaar_Mirai_063_ff41a85b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff41a85b9b561bb4626716f14d8155efda987fbbd2d21dd8fd16e63c2313e76c"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:53"
  condition:
    hash.sha256(0, filesize) == "ff41a85b9b561bb4626716f14d8155efda987fbbd2d21dd8fd16e63c2313e76c"
}

rule MalwareBazaar_unknown_064_af15a7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af15a7b17b0a90a7094f5b2d701452a69ede9b8fa1917c99eac23a25f848bc1c"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:52"
  condition:
    hash.sha256(0, filesize) == "af15a7b17b0a90a7094f5b2d701452a69ede9b8fa1917c99eac23a25f848bc1c"
}

rule MalwareBazaar_Mirai_065_d1012a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1012a4aebc3437c1e163736158e05411710b4ddd3d08b12e71b0999f4b57241"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:50"
  condition:
    hash.sha256(0, filesize) == "d1012a4aebc3437c1e163736158e05411710b4ddd3d08b12e71b0999f4b57241"
}

rule MalwareBazaar_Mirai_066_369ba5be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "369ba5bed5a6fbd6b41dd5ec0b55823809c2286f16797972b6ece6b13f20e956"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:49"
  condition:
    hash.sha256(0, filesize) == "369ba5bed5a6fbd6b41dd5ec0b55823809c2286f16797972b6ece6b13f20e956"
}

rule MalwareBazaar_unknown_067_f3a0dabf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3a0dabfa3647245c974f607f4dbb88accb74f8bdbe3e72ffd8ebdfa0c81b5fd"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:48"
  condition:
    hash.sha256(0, filesize) == "f3a0dabfa3647245c974f607f4dbb88accb74f8bdbe3e72ffd8ebdfa0c81b5fd"
}

rule MalwareBazaar_Mirai_068_3843a11d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3843a11d8d205c614c23a0905fb9d06a2822170c815d5be1aa87ca9540840fd4"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:47"
  condition:
    hash.sha256(0, filesize) == "3843a11d8d205c614c23a0905fb9d06a2822170c815d5be1aa87ca9540840fd4"
}

rule MalwareBazaar_Mirai_069_6ac13ba6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ac13ba61c4aca04b471adf9c6955c4e5bc5607499e7d735ecc5a246ef9cb870"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:45"
  condition:
    hash.sha256(0, filesize) == "6ac13ba61c4aca04b471adf9c6955c4e5bc5607499e7d735ecc5a246ef9cb870"
}

rule MalwareBazaar_Mirai_070_91b1e063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91b1e063ea4fefaabbde9e9b71b4ff9024e28afc99174e6963043882f33e5213"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:44"
  condition:
    hash.sha256(0, filesize) == "91b1e063ea4fefaabbde9e9b71b4ff9024e28afc99174e6963043882f33e5213"
}

rule MalwareBazaar_Mirai_071_bb13f9dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb13f9dd26f736b78dfe2cb4636c37f25e17ebe4394a7f8a8ed23568359d68ec"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:43"
  condition:
    hash.sha256(0, filesize) == "bb13f9dd26f736b78dfe2cb4636c37f25e17ebe4394a7f8a8ed23568359d68ec"
}

rule MalwareBazaar_Mirai_072_45449a9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45449a9cbd6e700e2e8fe87bfb0ac930e11a32b2441c0e1a652911c25878ecc7"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-15 00:04:42"
  condition:
    hash.sha256(0, filesize) == "45449a9cbd6e700e2e8fe87bfb0ac930e11a32b2441c0e1a652911c25878ecc7"
}

rule MalwareBazaar_unknown_073_a2172f40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff"
    family = "unknown"
    file_name = "a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff.bin"
    file_type = "unknown"
    first_seen = "2026-09-15 00:04:19"
  condition:
    hash.sha256(0, filesize) == "a2172f40e99b78fde9980848b5eaa7d223f31c58eecbf6acca85939c9a3465ff"
}

rule MalwareBazaar_unknown_074_ad14ac53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad14ac5387ca612b118e65562fe6c5846755c635b89362f4e616c987ecf83ec8"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-09-14 23:47:44"
  condition:
    hash.sha256(0, filesize) == "ad14ac5387ca612b118e65562fe6c5846755c635b89362f4e616c987ecf83ec8"
}

rule MalwareBazaar_unknown_075_5188e2aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5188e2aa998cb1c1bb47ef6d1e4a88ca040cbf6323b28932e1fd5a8867a6c9ec"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 23:23:30"
  condition:
    hash.sha256(0, filesize) == "5188e2aa998cb1c1bb47ef6d1e4a88ca040cbf6323b28932e1fd5a8867a6c9ec"
}

rule MalwareBazaar_unknown_076_27b80f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b80f1fc1dfbddd60b1a3993fe4f3995ef605036f05880eba39058fba428788"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 23:23:23"
  condition:
    hash.sha256(0, filesize) == "27b80f1fc1dfbddd60b1a3993fe4f3995ef605036f05880eba39058fba428788"
}

rule MalwareBazaar_Mirai_077_74dd1708
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74dd17083294d2a8452debd0debf322b7d83c6eaa035333805128233976338a2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-14 23:04:41"
  condition:
    hash.sha256(0, filesize) == "74dd17083294d2a8452debd0debf322b7d83c6eaa035333805128233976338a2"
}

rule MalwareBazaar_unknown_078_5c8a0e5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8a0e5bd968d5ec48414a31564cde204d45e1ce52abe09f23e5b16640f5afdf"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 22:29:42"
  condition:
    hash.sha256(0, filesize) == "5c8a0e5bd968d5ec48414a31564cde204d45e1ce52abe09f23e5b16640f5afdf"
}

rule MalwareBazaar_DDoSAgent_079_85b7f8b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85b7f8b94b73b3751d7979c0bcb890af50fb31094d0c93130fa6f86068799c7e"
    family = "DDoSAgent"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-09-14 22:25:45"
  condition:
    hash.sha256(0, filesize) == "85b7f8b94b73b3751d7979c0bcb890af50fb31094d0c93130fa6f86068799c7e"
}

rule MalwareBazaar_unknown_080_bd7303f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd7303f2214000dfe435d4c9d309895214db2c36a38c458a8028fccf1cca018d"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 22:22:38"
  condition:
    hash.sha256(0, filesize) == "bd7303f2214000dfe435d4c9d309895214db2c36a38c458a8028fccf1cca018d"
}

rule MalwareBazaar_DDoSAgent_081_3ab32576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab3257610bad25f96b03ed985940af3dab3fae69856d0264a52eff1e8d55184"
    family = "DDoSAgent"
    file_name = "mips64le"
    file_type = "elf"
    first_seen = "2026-09-14 22:18:44"
  condition:
    hash.sha256(0, filesize) == "3ab3257610bad25f96b03ed985940af3dab3fae69856d0264a52eff1e8d55184"
}

rule MalwareBazaar_unknown_082_3b77c5b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b77c5b788cf0ab705c5ad8589bf4abfcab4f3c021e4444072b04b839ea0f11d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-14 22:16:42"
  condition:
    hash.sha256(0, filesize) == "3b77c5b788cf0ab705c5ad8589bf4abfcab4f3c021e4444072b04b839ea0f11d"
}

rule MalwareBazaar_unknown_083_d78530ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d78530edbd145e6ab5daf2b68f5260dc51b279d0552a8092da0b018eeeb2fe64"
    family = "unknown"
    file_name = "KerRansom.exe"
    file_type = "exe"
    first_seen = "2026-09-14 22:09:35"
  condition:
    hash.sha256(0, filesize) == "d78530edbd145e6ab5daf2b68f5260dc51b279d0552a8092da0b018eeeb2fe64"
}

rule MalwareBazaar_DDoSAgent_084_923efaa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "923efaa33499532bf5e2bc911375a184f1310f8e13032c6ad5cecbcba466eaab"
    family = "DDoSAgent"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-14 22:04:44"
  condition:
    hash.sha256(0, filesize) == "923efaa33499532bf5e2bc911375a184f1310f8e13032c6ad5cecbcba466eaab"
}

rule MalwareBazaar_DDoSAgent_085_cc149bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc149bcff87af9e93a32087711b2f974f8236e90e9a89f8727f29b8b520cce15"
    family = "DDoSAgent"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-09-14 22:02:43"
  condition:
    hash.sha256(0, filesize) == "cc149bcff87af9e93a32087711b2f974f8236e90e9a89f8727f29b8b520cce15"
}

rule MalwareBazaar_unknown_086_65967cdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65967cdfe6d7afaab4022101e177b315d773dfd1ddec609a2a08d751f7a9f7f2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 21:56:41"
  condition:
    hash.sha256(0, filesize) == "65967cdfe6d7afaab4022101e177b315d773dfd1ddec609a2a08d751f7a9f7f2"
}

rule MalwareBazaar_unknown_087_2c7a07e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c7a07e88d6166e1b73e637ece612a8d2b4745f137889186f36f7f54b99e6843"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-14 21:46:46"
  condition:
    hash.sha256(0, filesize) == "2c7a07e88d6166e1b73e637ece612a8d2b4745f137889186f36f7f54b99e6843"
}

rule MalwareBazaar_DDoSAgent_088_8209f6d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8209f6d4cf183d4ebe5bb60c3a1ebee96cb734cba4a7f65569993c3626ed5dfb"
    family = "DDoSAgent"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-14 21:46:44"
  condition:
    hash.sha256(0, filesize) == "8209f6d4cf183d4ebe5bb60c3a1ebee96cb734cba4a7f65569993c3626ed5dfb"
}

rule MalwareBazaar_unknown_089_ac6d9d24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac6d9d241447c7e75cbd103af057ff1f1361972b26de93f7885a15a44946a5f0"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-14 21:45:49"
  condition:
    hash.sha256(0, filesize) == "ac6d9d241447c7e75cbd103af057ff1f1361972b26de93f7885a15a44946a5f0"
}

rule MalwareBazaar_unknown_090_9859c562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9859c5629611b8b3c40f4827bf0e92cb09894df39f98b9690ca8ff949c33a6f6"
    family = "unknown"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-09-14 21:45:47"
  condition:
    hash.sha256(0, filesize) == "9859c5629611b8b3c40f4827bf0e92cb09894df39f98b9690ca8ff949c33a6f6"
}

rule MalwareBazaar_unknown_091_6a18b61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a18b61cba5b5517594dbb37fe581b937196b987d74b41025279e942bdeb6312"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-14 21:44:42"
  condition:
    hash.sha256(0, filesize) == "6a18b61cba5b5517594dbb37fe581b937196b987d74b41025279e942bdeb6312"
}

rule MalwareBazaar_unknown_092_d5db35df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5db35dfa6dc550a9cf6b53586672410a2a08df31979d2141933b59cbf5116da"
    family = "unknown"
    file_name = "EXE A ANALIZAR.zip"
    file_type = "zip"
    first_seen = "2026-09-14 21:44:13"
  condition:
    hash.sha256(0, filesize) == "d5db35dfa6dc550a9cf6b53586672410a2a08df31979d2141933b59cbf5116da"
}

rule MalwareBazaar_DDoSAgent_093_165192a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "165192a853ab1a3ee6dee068afb67c551be4c60e8d8fef23a1b63eeadde9efec"
    family = "DDoSAgent"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-14 21:41:43"
  condition:
    hash.sha256(0, filesize) == "165192a853ab1a3ee6dee068afb67c551be4c60e8d8fef23a1b63eeadde9efec"
}

rule MalwareBazaar_DDoSAgent_094_94f86588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94f86588275cf31d3b0569a6dcbc534bbcb0adddc02f1c7f0d2ffa2a172930cc"
    family = "DDoSAgent"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-14 21:40:47"
  condition:
    hash.sha256(0, filesize) == "94f86588275cf31d3b0569a6dcbc534bbcb0adddc02f1c7f0d2ffa2a172930cc"
}

rule MalwareBazaar_unknown_095_2148a8f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2148a8f11eb5ecc6568a2a9535786a3809bd2331b993ace8a9d6c8e01c50451a"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-09-14 21:39:43"
  condition:
    hash.sha256(0, filesize) == "2148a8f11eb5ecc6568a2a9535786a3809bd2331b993ace8a9d6c8e01c50451a"
}

rule MalwareBazaar_Vidar_096_4ef2b263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a"
    family = "Vidar"
    file_name = "4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a.bin"
    file_type = "exe"
    first_seen = "2026-09-14 21:38:51"
  condition:
    hash.sha256(0, filesize) == "4ef2b2638d87670790c999a61136c25449b4e0a3ab83929f88054c499e85619a"
}

rule MalwareBazaar_DDoSAgent_097_aee47183
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aee47183a08adfd0ccfcc3d319ceb32fffebd99c1f843c92efb8a4027fd43b3d"
    family = "DDoSAgent"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-09-14 21:38:44"
  condition:
    hash.sha256(0, filesize) == "aee47183a08adfd0ccfcc3d319ceb32fffebd99c1f843c92efb8a4027fd43b3d"
}

rule MalwareBazaar_unknown_098_7b2716ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399"
    family = "unknown"
    file_name = "7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399"
    file_type = "unknown"
    first_seen = "2026-09-14 21:30:17"
  condition:
    hash.sha256(0, filesize) == "7b2716ab74fcdd193cac92ad906d661751e2b48a1d095ca016b29839f5860399"
}

rule MalwareBazaar_unknown_099_b6419e14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6419e147a22be9c254afdd69253ebb648e27725d26c5072a849d0fcb9886932"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-14 21:21:51"
  condition:
    hash.sha256(0, filesize) == "b6419e147a22be9c254afdd69253ebb648e27725d26c5072a849d0fcb9886932"
}

rule MalwareBazaar_unknown_100_7652f213
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81"
    family = "unknown"
    file_name = "7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81"
    file_type = "unknown"
    first_seen = "2026-09-14 21:15:25"
  condition:
    hash.sha256(0, filesize) == "7652f213a448eacbe2a75594ecd99aa497284f27bb603ba38fdf5dad30746c81"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

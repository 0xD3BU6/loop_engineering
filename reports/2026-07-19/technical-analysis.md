# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-19

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 623 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 623 |
| Unique family labels | 12 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 50 |
| Mirai | 37 |
| RemusStealer | 3 |
| Stealc | 2 |
| MaskGramStealer | 1 |
| WannaCry | 1 |
| Arechclient2 | 1 |
| Vidar | 1 |
| ValleyRAT | 1 |
| NanoCore | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 41 |
| exe | 37 |
| sh | 11 |
| unknown | 6 |
| zip | 5 |

## Per-Sample Analysis

### Sample 1: `71d5fabdd8b47808`

| Field | Value |
|---|---|
| SHA-256 | `71d5fabdd8b478089e543ab6a6e92fa1bcf822ca095ee9ace7789e665c495dec` |
| Family label | `unknown` |
| File name | `DeltaExecutor.exe` |
| File type | `exe` |
| First seen | `2026-07-19 03:52:30` |
| Reporter | `hexinglarps` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93cc155253429c5d55a4d35c41f11a33` |
| SHA-1 | `001e146ce340e22096824e3428aaafd95fce6528` |
| SHA-256 | `71d5fabdd8b478089e543ab6a6e92fa1bcf822ca095ee9ace7789e665c495dec` |
| SHA3-384 | `62484331438c490272fb3ba715aafd93643f031b7cdc58652d2800bcee6f577b41c1bba8e41c357511f9ddb0f655aa3a` |
| IMPHASH | `f469ac0906218570f79c54d1b58dc057` |
| TLSH | `T1C1577C07AFDC07FCD567C7FC89AB9B32C6F1B86A8622C24B0554C7151E729B14E6A321` |
| SSDEEP | `49152:ToAnT5THZp2mLlODnSiGLGqna/x5qIj5yPgFjs913k/BRHGfoN0IrR/ZDlGIBLOH:TdK1qna/x5qIji3WjHHNPO100c+R6M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_71d5fabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71d5fabdd8b478089e543ab6a6e92fa1bcf822ca095ee9ace7789e665c495dec"
    family = "unknown"
    file_name = "DeltaExecutor.exe"
    file_type = "exe"
    first_seen = "2026-07-19 03:52:30"
  condition:
    hash.sha256(0, filesize) == "71d5fabdd8b478089e543ab6a6e92fa1bcf822ca095ee9ace7789e665c495dec"
}
```

### Sample 2: `38452489fd072aa7`

| Field | Value |
|---|---|
| SHA-256 | `38452489fd072aa7fedd7a3e61ea37ed2b41efca30bc589b268f6525cf3019c2` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-19 03:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3006f98990508fe14cfa94aefeb18bda` |
| SHA-1 | `0ed0c0384f173c6bca24884b9f6714d881e8ad41` |
| SHA-256 | `38452489fd072aa7fedd7a3e61ea37ed2b41efca30bc589b268f6525cf3019c2` |
| SHA3-384 | `d01b20a15531d504842ab4e4e652a1bcf54e79cc6f5eaf30649717bc05f9d03c6afd2fe6502818e711d504f5e5b0fdda` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C2E6334865E055FEE5938138E9B2D6E5F5A9B8B24B32CBDF0B5487992E130D08D3C173` |
| SSDEEP | `393216:wMRgaBv5z6wUdOJn9GXMCHWUjXkcuI3/PGTAI:w7IGOxAXMb8XxH/O7` |
| ICON-DHASH | `f8f8f8f8f8f8e0e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_38452489
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38452489fd072aa7fedd7a3e61ea37ed2b41efca30bc589b268f6525cf3019c2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 03:52:09"
  condition:
    hash.sha256(0, filesize) == "38452489fd072aa7fedd7a3e61ea37ed2b41efca30bc589b268f6525cf3019c2"
}
```

### Sample 3: `19ee106f5490826e`

| Field | Value |
|---|---|
| SHA-256 | `19ee106f5490826e09271022d24b27a0586a48c5c9db4a55a63320bafcbb8342` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-19 03:44:56` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dd58790c78d382d696cdfbca55f832d` |
| SHA-1 | `67d86cf4d4c8a064647dc468c18344541affdaea` |
| SHA-256 | `19ee106f5490826e09271022d24b27a0586a48c5c9db4a55a63320bafcbb8342` |
| SHA3-384 | `3dc17b4413a78ee8fc693c9be9fe6f717367fe6c93be9b96fa09bfa73938bfc345ba564f8112a16ebdbc8378499263fa` |
| IMPHASH | `d1c35276ff2b8e9d448afb940bccb1f0` |
| TLSH | `T171144A1BD5D540EDEC19C6388A9AE237A4B3F85A1936B64F6BA0DF111F90B30B719F04` |
| SSDEEP | `3072:sVwyAZJRnwkyq/ekljAOFELjwfC/AJ9LKhM9XAyS6CHDd7tNVkR7ykugct:3y4VKOyLsK/i/9Qjz7tNu8gct` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_003_19ee106f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19ee106f5490826e09271022d24b27a0586a48c5c9db4a55a63320bafcbb8342"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 03:44:56"
  condition:
    hash.sha256(0, filesize) == "19ee106f5490826e09271022d24b27a0586a48c5c9db4a55a63320bafcbb8342"
}
```

### Sample 4: `ee5b4f0f96155f0e`

| Field | Value |
|---|---|
| SHA-256 | `ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81` |
| Family label | `unknown` |
| File name | `ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81` |
| File type | `elf` |
| First seen | `2026-07-19 03:30:32` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0da34bd922eaac9f48c05fa9d31cc9d2` |
| SHA-1 | `be7ff7c7e85a7b807a939f4404343ccaf624b63f` |
| SHA-256 | `ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81` |
| SHA3-384 | `64785b1a28c5b3a9f15ae384658f167327b17f68024f036169438cf9deea4a8c020d3e833c7d801d21a276fa02c1cdbb` |
| TLSH | `T128F69D77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQQ:cqYUQuVDt0TZEf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_ee5b4f0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81"
    family = "unknown"
    file_name = "ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81"
    file_type = "elf"
    first_seen = "2026-07-19 03:30:32"
  condition:
    hash.sha256(0, filesize) == "ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81"
}
```

### Sample 5: `cc2ba5d5272e640a`

| Field | Value |
|---|---|
| SHA-256 | `cc2ba5d5272e640a2ec9caeca2f92cb4606c84bd5c0b9a394b960879b28a7e9a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-19 02:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fb9a6424d7eef704700dd64ed2e7f42` |
| SHA-1 | `2264cd64033ee93b15f5d6edecdb47cda8dcb55b` |
| SHA-256 | `cc2ba5d5272e640a2ec9caeca2f92cb4606c84bd5c0b9a394b960879b28a7e9a` |
| SHA3-384 | `ae77a7526e0addd179ea2780902b3e39c059046c558a7e904802a8bdf6e9736d26e31292c8503c1a68c57718c8d3dfe8` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DFE6331819E403EEFAB3407DED91A981D1A5FC690376CAEB0B9C4661AC771908D7CB37` |
| SSDEEP | `393216:SrOEG66I57C4CPVvAblm7r0ZpXMCHWUjXbcuI3/PGTAI:SP3C4CpARmv0nXMb8XYH/O7` |
| ICON-DHASH | `9878e0c0d8f8f022` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_cc2ba5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc2ba5d5272e640a2ec9caeca2f92cb4606c84bd5c0b9a394b960879b28a7e9a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 02:52:09"
  condition:
    hash.sha256(0, filesize) == "cc2ba5d5272e640a2ec9caeca2f92cb4606c84bd5c0b9a394b960879b28a7e9a"
}
```

### Sample 6: `8c582d4d3d953bdc`

| Field | Value |
|---|---|
| SHA-256 | `8c582d4d3d953bdcd6a9956a2d928bc3af0889b73b19b8e573743840f92e35e0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-19 02:06:28` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `883f15985088fae4dc40a742a8f5eec0` |
| SHA-1 | `315d75cd79288a91bc89055d7402b725c7bc8257` |
| SHA-256 | `8c582d4d3d953bdcd6a9956a2d928bc3af0889b73b19b8e573743840f92e35e0` |
| SHA3-384 | `b863cc95588e2468b7a4539669def785dbe77f28df6a82751191deab9d2c2a8c289593116582bd40951d6c2cee6eb8f6` |
| IMPHASH | `94e1c85e15805e1e413bdf491fdaa09c` |
| TLSH | `T1C975B016A3A801FCD077C2B4CE57960BEBB2B44A1334A6DF57D09D962F23A715A3E311` |
| SSDEEP | `49152:13bWFJs0UztTKmUDr9J0bxIjGKB0RhbF7J:UFy0U8YxGeRX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_8c582d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c582d4d3d953bdcd6a9956a2d928bc3af0889b73b19b8e573743840f92e35e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 02:06:28"
  condition:
    hash.sha256(0, filesize) == "8c582d4d3d953bdcd6a9956a2d928bc3af0889b73b19b8e573743840f92e35e0"
}
```

### Sample 7: `a3adc3ba9fb49339`

| Field | Value |
|---|---|
| SHA-256 | `a3adc3ba9fb493396d33ad6b5c49aabc27c3d95d42451636c501b5f6b1a431a3` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-19 02:00:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55b8ff7fc8ab06df6d4fb5109ed76d36` |
| SHA-1 | `c7d77f41b65aa440577377716f6cb85929615f36` |
| SHA-256 | `a3adc3ba9fb493396d33ad6b5c49aabc27c3d95d42451636c501b5f6b1a431a3` |
| SHA3-384 | `a24a9aaf46e826c6adf55e7f43cc053090bbf8e27231cca371106c8b517fc4a567bf3e19b9881b6eeffe120113e18fb3` |
| TLSH | `T10D01CECAE150991040DEC51D33975458F871C3C7164B8BB4BF6CA43E9B98E14F066F88` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHka9Ccn1Cu1BCIBFC9gwXC//6X:kXCKysE2hi0ziQvZoha9NV/TFeXm/6X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_a3adc3ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3adc3ba9fb493396d33ad6b5c49aabc27c3d95d42451636c501b5f6b1a431a3"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-19 02:00:10"
  condition:
    hash.sha256(0, filesize) == "a3adc3ba9fb493396d33ad6b5c49aabc27c3d95d42451636c501b5f6b1a431a3"
}
```

### Sample 8: `205fec0325df0ef4`

| Field | Value |
|---|---|
| SHA-256 | `205fec0325df0ef40fdccdffd525cd3a27f26c8a37eff09ab4e1341f32963f56` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-19 01:54:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e956959f8969e2cf24aee7da08cc24a5` |
| SHA-1 | `363cc0344d9bc18cd8d96a120da06ba0505508a2` |
| SHA-256 | `205fec0325df0ef40fdccdffd525cd3a27f26c8a37eff09ab4e1341f32963f56` |
| SHA3-384 | `063ad3e073d3c8609ea15682c8742668423032cc87b9c5c7aa50263bddfd537796467f9b7f1631baeb6bb1476f929d9e` |
| TLSH | `T1290633C5B718C1D284134DBBC8E4BDFF4A04BBC9943041E96068AF796A3C6296DF8ED5` |
| SSDEEP | `98304:lNmXygLrhylpVSo+QPlSQbCYRylv4GNKI0c7Ooyz:lwpXo+8DbNRyl3KIh/yz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_205fec03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205fec0325df0ef40fdccdffd525cd3a27f26c8a37eff09ab4e1341f32963f56"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-19 01:54:09"
  condition:
    hash.sha256(0, filesize) == "205fec0325df0ef40fdccdffd525cd3a27f26c8a37eff09ab4e1341f32963f56"
}
```

### Sample 9: `23e44f9545eccc2f`

| Field | Value |
|---|---|
| SHA-256 | `23e44f9545eccc2fa95f563995118008826e64ead3844a6ecc6b50592a55dd37` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-19 01:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5ea5bca915287fad3ee08c00a789b0a` |
| SHA-1 | `e44b851814bc7466d2b6b450a0d3596baa67e6d1` |
| SHA-256 | `23e44f9545eccc2fa95f563995118008826e64ead3844a6ecc6b50592a55dd37` |
| SHA3-384 | `d084d7a3f89e38ffc07a4e9e0cbdc9b2f0cbe4f6031cf5c9222dbc18552baaf399fabd399fa32ad94a9c36df24df061f` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C5E6338476E111FEE667513CEAE141B5E5A6B8A24733CAC70BB8C362AE433D4483D747` |
| SSDEEP | `393216:LZmChaz1kjPcBbJp+It4lrXMCHWUjXXcuI3/PGTAI:LlazDeIt4lrXMb8XsH/O7` |
| ICON-DHASH | `40b960c0dc797204` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_23e44f95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23e44f9545eccc2fa95f563995118008826e64ead3844a6ecc6b50592a55dd37"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 01:52:08"
  condition:
    hash.sha256(0, filesize) == "23e44f9545eccc2fa95f563995118008826e64ead3844a6ecc6b50592a55dd37"
}
```

### Sample 10: `50f055e3b6662ff9`

| Field | Value |
|---|---|
| SHA-256 | `50f055e3b6662ff9f81a04eef52092b644f1617b9d0d9e6bc3f1f1deca01e3a9` |
| Family label | `unknown` |
| File name | `riscv` |
| File type | `elf` |
| First seen | `2026-07-19 01:45:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98cf266493a57fd79a02943aff61e614` |
| SHA-1 | `22506172fe7f135b83d228110f485986722f2c6f` |
| SHA-256 | `50f055e3b6662ff9f81a04eef52092b644f1617b9d0d9e6bc3f1f1deca01e3a9` |
| SHA3-384 | `8734de1e3cac57cc813c9ae3fcd13464002bae143c3f852e4b5c03e52b65d35b5812907b11fcfdf86a4e042bb557b4f0` |
| TLSH | `T12B8533C09E17CE6A9FC7BCF4E7A7D2780555F325036CA72AAB7E103D202805CD475AA9` |
| SSDEEP | `49152:t7c6QJOue2Sltv2i66hVtMPzEOp5BHGUf6zZ:t7T2SlJn66h6zE2gZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_50f055e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50f055e3b6662ff9f81a04eef52092b644f1617b9d0d9e6bc3f1f1deca01e3a9"
    family = "unknown"
    file_name = "riscv"
    file_type = "elf"
    first_seen = "2026-07-19 01:45:23"
  condition:
    hash.sha256(0, filesize) == "50f055e3b6662ff9f81a04eef52092b644f1617b9d0d9e6bc3f1f1deca01e3a9"
}
```

### Sample 11: `64f2828e5e89e4bc`

| Field | Value |
|---|---|
| SHA-256 | `64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715` |
| Family label | `unknown` |
| File name | `64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715` |
| File type | `exe` |
| First seen | `2026-07-19 01:15:30` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c5a2cc6f282ad609aa6f3a9f6a7950c` |
| SHA-1 | `38f0bbdf2d2414339505f527b369e591ba7eb33f` |
| SHA-256 | `64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715` |
| SHA3-384 | `84bc1979e3a379e341747fb588fbbdb0c75489871cb6bfcdc82e4e8a94bab46e84c902c26bbe018c9b729b567f731658` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1BE363358726CA1BCF0450AB444B38E1AF7B33C5967BA4B0F97C0867B0D53B9BAB94741` |
| SSDEEP | `98304:DqDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2H:DqDqPe1Cxcxk3ZAEUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_64f2828e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715"
    family = "unknown"
    file_name = "64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715"
    file_type = "exe"
    first_seen = "2026-07-19 01:15:30"
  condition:
    hash.sha256(0, filesize) == "64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715"
}
```

### Sample 12: `fbfa869a9d6e624a`

| Field | Value |
|---|---|
| SHA-256 | `fbfa869a9d6e624a4134e6c44baef0987d0c09f4b9be3ec95295f77599e4f566` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-19 00:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a77aa4a0070fad1d7448c6f5f100c592` |
| SHA-1 | `53074580821f3ee3226bbd4dafb837657b40306e` |
| SHA-256 | `fbfa869a9d6e624a4134e6c44baef0987d0c09f4b9be3ec95295f77599e4f566` |
| SHA3-384 | `578524952de9d727840d8930979cb3a37e27f52cf212c5b1a0585e1e7634bee84cd1ed54fa7a03a5e1c01ffa3a784b2f` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T184E63348BAD402FEF5B2403DBAF0A6A5D876B4660375C59B0BA057B5BC072E04E3D397` |
| SSDEEP | `393216:96pKTPfb4NIwxA7CRDaXIXMCHWUjXNcuI3/PGTAI:96nIwxWCRDaXIXMb8X6H/O7` |
| ICON-DHASH | `70f0f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_fbfa869a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbfa869a9d6e624a4134e6c44baef0987d0c09f4b9be3ec95295f77599e4f566"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 00:52:09"
  condition:
    hash.sha256(0, filesize) == "fbfa869a9d6e624a4134e6c44baef0987d0c09f4b9be3ec95295f77599e4f566"
}
```

### Sample 13: `c60861d98b3aa236`

| Field | Value |
|---|---|
| SHA-256 | `c60861d98b3aa236c215d5ce2a4ec571c2ec8a8503dfb57472eb2d3cbc6e6c04` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-19 00:30:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2862898599775e54c61c8beb8c505fc5` |
| SHA-1 | `73cbf954fdb64e76f8125e00ad4e52a76a9a2290` |
| SHA-256 | `c60861d98b3aa236c215d5ce2a4ec571c2ec8a8503dfb57472eb2d3cbc6e6c04` |
| SHA3-384 | `d64c734a45a79a523a240c1154ce22f5549d7d2b0f59cc0f82bdae492a5edd0e8a8f73eef67add5c1a9d591153683e51` |
| TLSH | `T162C27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:Y8vCB+25j6es8RGr9FYpMSUpi+20qUpi+20YQX:Y8l25JG9d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_c60861d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60861d98b3aa236c215d5ce2a4ec571c2ec8a8503dfb57472eb2d3cbc6e6c04"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:30:38"
  condition:
    hash.sha256(0, filesize) == "c60861d98b3aa236c215d5ce2a4ec571c2ec8a8503dfb57472eb2d3cbc6e6c04"
}
```

### Sample 14: `92a629ea255b2def`

| Field | Value |
|---|---|
| SHA-256 | `92a629ea255b2deff884e40577915f56665508defdfe78cfb85c6a12dfe1fdc0` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-19 00:20:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bfe8025aaaf2415a90f3dfd88fbcb52` |
| SHA-1 | `d83c747211a3b639fbb42e66dd5d2b7fe441edb1` |
| SHA-256 | `92a629ea255b2deff884e40577915f56665508defdfe78cfb85c6a12dfe1fdc0` |
| SHA3-384 | `58d27eadf8a48c46bfcd82567ae157cf4faff67cd3f0b61ba1879af8f24f92374c86bb72559bf0e6740412b2349c4bb4` |
| TLSH | `T13DC27D956A867C44BEC98A3E4CBD2B0D6DF5C3D1224942AC3D8B3C71DC15FACD618B1A` |
| SSDEEP | `768:u8vCB+25j6es8RL9FYpMSUpi+20qUpi+20YQX:u8l25Jdd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_92a629ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a629ea255b2deff884e40577915f56665508defdfe78cfb85c6a12dfe1fdc0"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:20:40"
  condition:
    hash.sha256(0, filesize) == "92a629ea255b2deff884e40577915f56665508defdfe78cfb85c6a12dfe1fdc0"
}
```

### Sample 15: `5fc07750ace241e2`

| Field | Value |
|---|---|
| SHA-256 | `5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df` |
| Family label | `WannaCry` |
| File name | `5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df` |
| File type | `exe` |
| First seen | `2026-07-19 00:15:31` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `174ad172303b51111727aea63e9bdc0a` |
| SHA-1 | `94cec0c0823f19023c283e73a4b7486113e02f22` |
| SHA-256 | `5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df` |
| SHA3-384 | `858a895ce036880cc42066354015cb7ff716c75257992f4f0c1b760b9529730297e30c0c5c820adbe52f76465b2d652b` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1BF363358726CA1BCF0460AB444B38D2AF7B37C59677A8B0F8784827B0E53B979F94711` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUg6SAEdhvxWa9P593R8yAVp2H:DXDqPe1CxcuZAEUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_015_5fc07750
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df"
    family = "WannaCry"
    file_name = "5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df"
    file_type = "exe"
    first_seen = "2026-07-19 00:15:31"
  condition:
    hash.sha256(0, filesize) == "5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df"
}
```

### Sample 16: `342a2753d8a86364`

| Field | Value |
|---|---|
| SHA-256 | `342a2753d8a86364f26b67552bea963470412d8342ed6e71560fabc07b32999f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-19 00:06:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `275a03e7a0ec53e69c7da13c0bd6348a` |
| SHA-1 | `d59726cedf47553aa1151020dcd0d38e7f7eeb82` |
| SHA-256 | `342a2753d8a86364f26b67552bea963470412d8342ed6e71560fabc07b32999f` |
| SHA3-384 | `05e5be545c4bf7fee484a70b44dfa09c8dbc5ecc5d9d5400af973d54bba88361665d989e4a03423cf0ac3ac73e02bb26` |
| TLSH | `T1C0235C651A857C14AE99C4361D7E2F0CB9AD43E6320452DE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:0ZlVEJVIhtMU9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:0ZrEJ2MZcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_342a2753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "342a2753d8a86364f26b67552bea963470412d8342ed6e71560fabc07b32999f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:06:51"
  condition:
    hash.sha256(0, filesize) == "342a2753d8a86364f26b67552bea963470412d8342ed6e71560fabc07b32999f"
}
```

### Sample 17: `650cbbc9cce1761c`

| Field | Value |
|---|---|
| SHA-256 | `650cbbc9cce1761c658b98dd7e2d7aff2532e9d04e1056a1c44a61652406b104` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-19 00:04:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0498c52d419bb229ca7947fed6bdb26` |
| SHA-1 | `5fdbd0e3915b9b9e5f5bec50b224b4f319bdac28` |
| SHA-256 | `650cbbc9cce1761c658b98dd7e2d7aff2532e9d04e1056a1c44a61652406b104` |
| SHA3-384 | `2a2a402d1cd9c489a527a46df07b0a7df23c12cc1860d0c245085cfd503e33452e458dae6e0b0bb7ae680a328ff8a8da` |
| TLSH | `T1FE236C6516857C14AE99C4375C7E2F0CBDAD43E6314492EE7FCA3CF28C4A6AD920871D` |
| SSDEEP | `768:Ur9NyXsZztCs9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:SHusZgcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_650cbbc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "650cbbc9cce1761c658b98dd7e2d7aff2532e9d04e1056a1c44a61652406b104"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:04:52"
  condition:
    hash.sha256(0, filesize) == "650cbbc9cce1761c658b98dd7e2d7aff2532e9d04e1056a1c44a61652406b104"
}
```

### Sample 18: `0df61c7d4a7b90b9`

| Field | Value |
|---|---|
| SHA-256 | `0df61c7d4a7b90b9e859c8ade8abbdf2bafd395b5d05ad7d8807284ccedb82f8` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-19 00:04:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e22ca5abd32db9b7561ef1b158efbbbd` |
| SHA-1 | `b9871cc2ba0684e50ef7a3c7ece4875a23804eb3` |
| SHA-256 | `0df61c7d4a7b90b9e859c8ade8abbdf2bafd395b5d05ad7d8807284ccedb82f8` |
| SHA3-384 | `0f344543ecdbf2ea6cc6c7cdf74e797402172cbcb638ba2467c618d3f6a02c327ed14a9baadef9a71efa3db2a9d15104` |
| TLSH | `T15201CECAE250DA10405EC91D33965594B871C3C7064B0BB87F9C943DAB9CE10F066F88` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHka9Cmn1CGBC8hBFCEwXC//ENauD:kXCKysE2hi0ziQvZoha9h9rjFKXm/G7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_0df61c7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0df61c7d4a7b90b9e859c8ade8abbdf2bafd395b5d05ad7d8807284ccedb82f8"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-19 00:04:50"
  condition:
    hash.sha256(0, filesize) == "0df61c7d4a7b90b9e859c8ade8abbdf2bafd395b5d05ad7d8807284ccedb82f8"
}
```

### Sample 19: `896ae0ba6b9686c9`

| Field | Value |
|---|---|
| SHA-256 | `896ae0ba6b9686c9ff56a7455f72be69289ee55ab0e2aae9168cb7f5baa01817` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-19 00:02:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39576cc0fa308c776d4c5376fcc8ec29` |
| SHA-1 | `249a07e3a0b3d780f3b5f0f8267812512441e06a` |
| SHA-256 | `896ae0ba6b9686c9ff56a7455f72be69289ee55ab0e2aae9168cb7f5baa01817` |
| SHA3-384 | `da5b97c0c7b71c34c514ab4d5b14ae36badbf8b5c61b79168923b63b8eb0b1f330fb67e4fc41d87f6340702f4b2b3342` |
| TLSH | `T1CAC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACC618B1A` |
| SSDEEP | `768:g8vCB+25j6es8Rs99FYpMSUpi+20qUpi+20YQX:g8l25JWd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_896ae0ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896ae0ba6b9686c9ff56a7455f72be69289ee55ab0e2aae9168cb7f5baa01817"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:02:51"
  condition:
    hash.sha256(0, filesize) == "896ae0ba6b9686c9ff56a7455f72be69289ee55ab0e2aae9168cb7f5baa01817"
}
```

### Sample 20: `2c4f1c37a25f687d`

| Field | Value |
|---|---|
| SHA-256 | `2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59` |
| Family label | `unknown` |
| File name | `2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59` |
| File type | `exe` |
| First seen | `2026-07-19 00:02:33` |
| Reporter | `johnk3r` |
| Tags | `BasicRMM, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c196ea62e13d7ef3cdb233cdb848a61f` |
| SHA-1 | `8db179834ff28f7d3c10c7a7923c6cfa5875d589` |
| SHA-256 | `2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59` |
| SHA3-384 | `339c831c5af747dfa755f0fb93c81ab8054218e2c57b1801864f0849a8f91989fe6ce4af2898f486f74eb987567263f9` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T188C67D03E8A145E9C1B9E235C9669263BB717C491B3223D72B60F7342F76BD06EB9350` |
| SSDEEP | `196608:ToJCfNjW5ccrpY+fOk8ZDQNZKqr9yz1zVr:TXfNjkccrpYzk8JQNhw1zVr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_2c4f1c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59"
    family = "unknown"
    file_name = "2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59"
    file_type = "exe"
    first_seen = "2026-07-19 00:02:33"
  condition:
    hash.sha256(0, filesize) == "2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59"
}
```

### Sample 21: `fec4f7679f9ab5ec`

| Field | Value |
|---|---|
| SHA-256 | `fec4f7679f9ab5ec9f5cf4f3702e52fd085a4ac9306acd9a62b7c088b6605208` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 23:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41731d594158148252af0689c2d8497e` |
| SHA-1 | `c1a19b0e4ecb6ea66a8bea5ae44fe85a95a3822c` |
| SHA-256 | `fec4f7679f9ab5ec9f5cf4f3702e52fd085a4ac9306acd9a62b7c088b6605208` |
| SHA3-384 | `9733b344a9e26f84aeed52ce8b871480f69e2039ab69319ae257e7a2688c5cd337caa6236a15eb7a8a2bb1fd8e98bb4b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E7E63308AAE581EEE673403C6DE195C9A1B5F0750372CAD72B642315FE2B2F48D78397` |
| SSDEEP | `393216:LWY/Un8F9aW622DiOXftHSTRIXMCHWUjXjcuI3/PGTAI:LWbia+25tHStIXMb8XAH/O7` |
| ICON-DHASH | `30f0d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_fec4f767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fec4f7679f9ab5ec9f5cf4f3702e52fd085a4ac9306acd9a62b7c088b6605208"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 23:52:09"
  condition:
    hash.sha256(0, filesize) == "fec4f7679f9ab5ec9f5cf4f3702e52fd085a4ac9306acd9a62b7c088b6605208"
}
```

### Sample 22: `fd4a088e691cf191`

| Field | Value |
|---|---|
| SHA-256 | `fd4a088e691cf191050f9551aaf616ea04ba60d1cbbbd71022731aa5db3ef2e6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 22:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81a28cc52f4847eea66ba842a97b4f33` |
| SHA-1 | `a4a351591567e6350eac41affc1aef2986a512f0` |
| SHA-256 | `fd4a088e691cf191050f9551aaf616ea04ba60d1cbbbd71022731aa5db3ef2e6` |
| SHA3-384 | `f0f62c122b7e57d774f25c44b580db9b2a96850fb107e88fac9f245f0579b8d2654b466a6cfe8f7e8a2c138ca5473ae9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T135E63308A9E211EEE967803CED715066E8A870750772C59B57BC43A54C633E2EF3E367` |
| SSDEEP | `393216:VZb6fsKErHkfDUIUAH4KuGSXMCHWUjXLcuI3/PGTAI:VIfsKEYfDUIj4HXMb8XoH/O7` |
| ICON-DHASH | `71f0e8c8e8e8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_fd4a088e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4a088e691cf191050f9551aaf616ea04ba60d1cbbbd71022731aa5db3ef2e6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 22:52:08"
  condition:
    hash.sha256(0, filesize) == "fd4a088e691cf191050f9551aaf616ea04ba60d1cbbbd71022731aa5db3ef2e6"
}
```

### Sample 23: `4a96a4b4cece7a57`

| Field | Value |
|---|---|
| SHA-256 | `4a96a4b4cece7a576ec22780a49294c8ebbec0b1f546ac48b50708690a7250c9` |
| Family label | `Arechclient2` |
| File name | `jquery.uo.js.zip` |
| File type | `zip` |
| First seen | `2026-07-18 21:19:12` |
| Reporter | `iamaachum` |
| Tags | `45-140-14-113, Arechclient2, dropped-by-ACRStealer, SectopRAT, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9268aa87efb18f309a3a3f9a27d8988a` |
| SHA-1 | `79f3b6a6b055f37b592b498a550466f10f395943` |
| SHA-256 | `4a96a4b4cece7a576ec22780a49294c8ebbec0b1f546ac48b50708690a7250c9` |
| SHA3-384 | `1c24aab25ace13dc21bd16b74ca3f90f1cc671aa000dc8332115a5486303b406fbcd57a2e23465d918add4b7282a123e` |
| TLSH | `T1F5869F21A2F901A8E0BBD6788A768633DBB178155734D7CF0294C5192F27FE09A7F721` |
| SSDEEP | `196608:5q8FAzrKAXW8CdR2E8Z/Wo1jZppolk19ztoTr2fymH:Y5zGAXW822wo1jZppolk19ztoTr2fymH` |

#### Technical Assessment

- The sample is tracked as `Arechclient2` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Arechclient2_023_4a96a4b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a96a4b4cece7a576ec22780a49294c8ebbec0b1f546ac48b50708690a7250c9"
    family = "Arechclient2"
    file_name = "jquery.uo.js.zip"
    file_type = "zip"
    first_seen = "2026-07-18 21:19:12"
  condition:
    hash.sha256(0, filesize) == "4a96a4b4cece7a576ec22780a49294c8ebbec0b1f546ac48b50708690a7250c9"
}
```

### Sample 24: `254fff0fabd0b47a`

| Field | Value |
|---|---|
| SHA-256 | `254fff0fabd0b47ae67cc9e45539e2c7de33bee70e5e2e951d4db215f74af676` |
| Family label | `unknown` |
| File name | `jquery.min.js.zip` |
| File type | `zip` |
| First seen | `2026-07-18 21:17:59` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, static-quorashift-cc, ZigClipper, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dac2a970cec91ea985ea1f79d50c06d` |
| SHA-1 | `8c85328ba0501ffe9284e957843361328222bd31` |
| SHA-256 | `254fff0fabd0b47ae67cc9e45539e2c7de33bee70e5e2e951d4db215f74af676` |
| SHA3-384 | `94c6f463bf0370dd4baa4d786262be826f407b3b561b6433f65ee17f200fc81772c33fd2846bab815bb9a3f467df57a2` |
| TLSH | `T12516BE16A3AD01E4D16BE278C6969732D6B17C064331E6CB03E9D6292F37BE05B7B311` |
| SSDEEP | `49152:tLlepsLJEjLLvtL393OGiLkacvukXNzw1L43EZ/Yu5p1F/Iiq9KpUmTfFqSgdDPC:tAstxQvhmZ/Yu524p/8lu5dZD6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_254fff0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254fff0fabd0b47ae67cc9e45539e2c7de33bee70e5e2e951d4db215f74af676"
    family = "unknown"
    file_name = "jquery.min.js.zip"
    file_type = "zip"
    first_seen = "2026-07-18 21:17:59"
  condition:
    hash.sha256(0, filesize) == "254fff0fabd0b47ae67cc9e45539e2c7de33bee70e5e2e951d4db215f74af676"
}
```

### Sample 25: `68444caba536c785`

| Field | Value |
|---|---|
| SHA-256 | `68444caba536c78572538d6c7886b69820f22319e7616532d20069da6ac2775b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-18 21:10:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c219cb0907dcc247775c73054bcb4b99` |
| SHA-1 | `7306ee913f9dcb0af8033e53c2c1b39e0016b94e` |
| SHA-256 | `68444caba536c78572538d6c7886b69820f22319e7616532d20069da6ac2775b` |
| SHA3-384 | `91aee6cca559deea908e4080603453ae07a1b237b9b9cfbe3c36abe41a7c8167b279864f4dd096f21d1296440c9a2e79` |
| TLSH | `T179235C552A857C14AA98C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AADD920961D` |
| SSDEEP | `768:XJFWzZx5m9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Zkzhcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_68444cab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68444caba536c78572538d6c7886b69820f22319e7616532d20069da6ac2775b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 21:10:58"
  condition:
    hash.sha256(0, filesize) == "68444caba536c78572538d6c7886b69820f22319e7616532d20069da6ac2775b"
}
```

### Sample 26: `b7f7d8aa57f70f60`

| Field | Value |
|---|---|
| SHA-256 | `b7f7d8aa57f70f6042b6b52fedef3eac4ee3d401e4d1f706aabd2af122b8eed6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 20:53:06` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31bd181806e2ecb8de8c3df4eec16f7e` |
| SHA-1 | `8473553d907c867dda5223f15d913c9f141aa04f` |
| SHA-256 | `b7f7d8aa57f70f6042b6b52fedef3eac4ee3d401e4d1f706aabd2af122b8eed6` |
| SHA3-384 | `2bef93b6303f1d11171934e062640d16469b5cda0e98a8ee42a523e48b46c01e570ea23678a436ea743adbf4caf7cd9c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T150E63318BBC002EBE6724178FAF26286F57AB4760732CA5F476847612D272E15C3C767` |
| SSDEEP | `393216:io4Q11ABs7cIWBmyp2XMCHWUjXVcuI3/PGTAI:iBO73KmbXMb8XiH/O7` |
| ICON-DHASH | `d4f8d1f0e0e971b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_b7f7d8aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f7d8aa57f70f6042b6b52fedef3eac4ee3d401e4d1f706aabd2af122b8eed6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 20:53:06"
  condition:
    hash.sha256(0, filesize) == "b7f7d8aa57f70f6042b6b52fedef3eac4ee3d401e4d1f706aabd2af122b8eed6"
}
```

### Sample 27: `cb336a6e3fc0e9aa`

| Field | Value |
|---|---|
| SHA-256 | `cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06` |
| Family label | `unknown` |
| File name | `setup_patched.exe` |
| File type | `exe` |
| First seen | `2026-07-18 20:46:32` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, AsgardProtector, de-pumped, exe, res-explicittweak-cc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb8c32e7142b83eb891d2be7f20352cf` |
| SHA-1 | `501b5c01a55474d8fc07cff23b8c14108a690e71` |
| SHA-256 | `cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06` |
| SHA3-384 | `b2ebbb28390d587f4b34d12c750ca870eff0e4ee2aa7299e0d172c2da5da9ae5db7b856274fb48aa1e1a6d4aa2c21556` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T15CA5331319ED0AE4FA795730A8F207139730FE562B7A878F1348D09F4F16AE1997934A` |
| SSDEEP | `49152:09CUaz8YKb+hU58oulzMThQJ/z3ChDOgYYcRcfCD:0YFKiyKoAzWQpsOnyfCD` |
| ICON-DHASH | `0f4ddcd8a02d3324` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_cb336a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06"
    family = "unknown"
    file_name = "setup_patched.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:46:32"
  condition:
    hash.sha256(0, filesize) == "cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06"
}
```

### Sample 28: `5fbed74e14ac6672`

| Field | Value |
|---|---|
| SHA-256 | `5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-18 20:45:55` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, AsgardProtector, file-pumped, res-explicittweak-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc702c37cbff921c378b62a270ec3568` |
| SHA-1 | `a26239e234bcfda7fbc794927c06ba4a4beb627e` |
| SHA-256 | `5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165` |
| SHA3-384 | `6a821ecffb7fe07b143db1dcd61b45db183ab1bfb120e20b04995a2348372db5dafc5a35855119e679de4ef4e0121d62` |
| TLSH | `T1CCE5F01624AA0F94DD9C027890DB0F46679DFF0A620AD71F4362F26FBFF67B09928441` |
| SSDEEP | `49152:6Xng9gC8zwsqF+/U5i6SbJMbbQ33d32hDOgKCCRefVI:6Xgm5qEsA6wJEQn2OlQfVI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5fbed74e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-18 20:45:55"
  condition:
    hash.sha256(0, filesize) == "5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165"
}
```

### Sample 29: `7c9a76145f39a052`

| Field | Value |
|---|---|
| SHA-256 | `7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8` |
| Family label | `unknown` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-07-18 20:43:59` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, logs-workflowengine-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f4e7a8e3266a147353d47a6c6f95fb9` |
| SHA-1 | `80caad03cd2b385f911982b806eae1906b2a2d2d` |
| SHA-256 | `7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8` |
| SHA3-384 | `ebbfff4dee7243ed59946bc129beb6a082b6f66fc69acd04668a6b7a7b8f61631e778b8759c31036a2fe64b636d1a237` |
| TLSH | `T1C5773325F8293261F88DC6B405B01AA813E4BD71037F27D42274756FCA67F6C9F69A38` |
| SSDEEP | `786432:EMrRVxNmoiMPv1tboni7vfbAM/4jm0ZtEnLkHSiZHMswlbyUoRYFmIC+:EERJbJzHbom0XUL8SiZHMb3oRiJC+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_7c9a7614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-18 20:43:59"
  condition:
    hash.sha256(0, filesize) == "7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8"
}
```

### Sample 30: `5679dcddde61ea4e`

| Field | Value |
|---|---|
| SHA-256 | `5679dcddde61ea4ea8ee5199339ba059940b1257211fcf95c80d1d5b4063e85a` |
| Family label | `Stealc` |
| File name | `FLStudio2025 Crack_patched.exe` |
| File type | `exe` |
| First seen | `2026-07-18 20:42:03` |
| Reporter | `iamaachum` |
| Tags | `de-pumped, exe, Stealc, windows-update-local-rest` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dbf1dd9fa7ca2165077c1289ba0acf9` |
| SHA-1 | `724cf38a0d0ae333834841937ac646306fbd09b2` |
| SHA-256 | `5679dcddde61ea4ea8ee5199339ba059940b1257211fcf95c80d1d5b4063e85a` |
| SHA3-384 | `ed9e45f47b26d870dcb72754706c41aeb2fee408fca8913f40c8884f14b557eba39921955160c4faf2744c33c2ede8e0` |
| TLSH | `T117E523E8E39DCF1AC7954FB00555D27523F02D8AD410D7029EEAACDFB426F2191983A7` |
| SSDEEP | `49152:bOPxMJrnMoYj1662IGEmNa3nXuigV3tBPXep:aPSBnKj166PFmNanIVPXe` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_030_5679dcdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5679dcddde61ea4ea8ee5199339ba059940b1257211fcf95c80d1d5b4063e85a"
    family = "Stealc"
    file_name = "FLStudio2025 Crack_patched.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:42:03"
  condition:
    hash.sha256(0, filesize) == "5679dcddde61ea4ea8ee5199339ba059940b1257211fcf95c80d1d5b4063e85a"
}
```

### Sample 31: `4e97683e5e793591`

| Field | Value |
|---|---|
| SHA-256 | `4e97683e5e7935915b26a1e5b036ea1d6ae2b1a9b5f1830a4e2acb68275589a1` |
| Family label | `Stealc` |
| File name | `FLStudio2025.zip` |
| File type | `zip` |
| First seen | `2026-07-18 20:41:06` |
| Reporter | `iamaachum` |
| Tags | `file-pumped, pw-2026, Stealc, windows-update-local-rest, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e16aeb032273a90e927640c57c27cfac` |
| SHA-1 | `eb339aed1349674928b46398cdeded4f6fd385d4` |
| SHA-256 | `4e97683e5e7935915b26a1e5b036ea1d6ae2b1a9b5f1830a4e2acb68275589a1` |
| SHA3-384 | `72bb4823635906f0f411c7bab835dc63e77087317c7d20c1ec57dafef5494d6bfdd07cfe406ab9a867a3c7613939dcbd` |
| TLSH | `T111B5332DADA53D05B734C8B39904F58DAD0CE3FA791BB4117674A308C9B869F86C3B19` |
| SSDEEP | `49152:hxgfcXQ7hPafPEdW8WYqDoSbQzydrE8ejoPe6O/ql+3T8KoBkTau:huUXQpW8qpb+8ejYn+4Kpau` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_031_4e97683e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e97683e5e7935915b26a1e5b036ea1d6ae2b1a9b5f1830a4e2acb68275589a1"
    family = "Stealc"
    file_name = "FLStudio2025.zip"
    file_type = "zip"
    first_seen = "2026-07-18 20:41:06"
  condition:
    hash.sha256(0, filesize) == "4e97683e5e7935915b26a1e5b036ea1d6ae2b1a9b5f1830a4e2acb68275589a1"
}
```

### Sample 32: `3769b472782adfa0`

| Field | Value |
|---|---|
| SHA-256 | `3769b472782adfa0897d722918ad7c43dd8e9f19734b87bed9f3768866b7f119` |
| Family label | `Vidar` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-07-18 20:39:40` |
| Reporter | `iamaachum` |
| Tags | `exe, micronsoftwares-com, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bdc639558c2f9ec7142aff3a4ad742b` |
| SHA-1 | `ea7dea1f949a0dc839ad492da1c708d327a6a4b6` |
| SHA-256 | `3769b472782adfa0897d722918ad7c43dd8e9f19734b87bed9f3768866b7f119` |
| SHA3-384 | `0eabfebbdc9ec456d7fca7a05154c947a0488104d8e98eeeb32a5ec88e1b54887fc887a3794f331576c627d6277d2afc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15F267C07FCA108EAD0D9A23589A792527B757C091B3233D32EA0B7782F72BD05E79754` |
| SSDEEP | `49152:omkYtynmotcvBzQUwTnWm0Vfbhm9aaTHgQry5aLsUAbGyWkHYjxcdqjY:oHAFfr1m9aru1iW0` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_032_3769b472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3769b472782adfa0897d722918ad7c43dd8e9f19734b87bed9f3768866b7f119"
    family = "Vidar"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:39:40"
  condition:
    hash.sha256(0, filesize) == "3769b472782adfa0897d722918ad7c43dd8e9f19734b87bed9f3768866b7f119"
}
```

### Sample 33: `87436ab32d87fd80`

| Field | Value |
|---|---|
| SHA-256 | `87436ab32d87fd80d2dfed7232b9f75cd06d771de11e2623d0ae5d350c4dbc3f` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-07-18 20:39:03` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b820988618a6b1fd3a5c7369785ed779` |
| SHA-1 | `35dde9b0f57c44a9e47afa0e2c0191df8cae13c8` |
| SHA-256 | `87436ab32d87fd80d2dfed7232b9f75cd06d771de11e2623d0ae5d350c4dbc3f` |
| SHA3-384 | `68b9e6362e9a07bcfe9dc0543f334bf0fa001abe25e534736acb9e953b0e4532e9c99a3744329610f3d31f59c6c928cb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15DD54947BC9108F6C0A9A335C9A79646BB75BC091B3623D72EA0BB782F727D05D39710` |
| SSDEEP | `49152:JpApmJkctbkkSSaLYdhrvb3oa+b/ZkqIGcq0:JKErdh3AbRW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_87436ab3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87436ab32d87fd80d2dfed7232b9f75cd06d771de11e2623d0ae5d350c4dbc3f"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:39:03"
  condition:
    hash.sha256(0, filesize) == "87436ab32d87fd80d2dfed7232b9f75cd06d771de11e2623d0ae5d350c4dbc3f"
}
```

### Sample 34: `7502ed3956c621d9`

| Field | Value |
|---|---|
| SHA-256 | `7502ed3956c621d9442e51343a9d9fd22fb080d1a9edcffc1386901ebb4da9ec` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-07-18 20:38:11` |
| Reporter | `iamaachum` |
| Tags | `cucumber-oslo-cc, exe, NWHStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daf4f3b835566a9356346df55aec2827` |
| SHA-1 | `77491b71e3ee8b5909347e82d91da197f2434408` |
| SHA-256 | `7502ed3956c621d9442e51343a9d9fd22fb080d1a9edcffc1386901ebb4da9ec` |
| SHA3-384 | `7269bc0ad558cfa3ea24187e08a9d84b240f9895b63435a8edc852ac9ee1d1e4f33bf7293c24ffc80cadf0f7c7fad785` |
| IMPHASH | `fd6f6d07cc33ee9a2b65bda58a07bb94` |
| TLSH | `T170286C43A2E751D8F0BBD17497E65323E932BC490B3469EF12944B312F72AE0A779B11` |
| SSDEEP | `1572864:GZa7hmguP2nG0/Vyv7UhgxIabc/x7Awby:GZa7hmguP2nUOnAwby` |
| ICON-DHASH | `9170cc9296cc7001` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_7502ed39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7502ed3956c621d9442e51343a9d9fd22fb080d1a9edcffc1386901ebb4da9ec"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:38:11"
  condition:
    hash.sha256(0, filesize) == "7502ed3956c621d9442e51343a9d9fd22fb080d1a9edcffc1386901ebb4da9ec"
}
```

### Sample 35: `a2ca31441dec4d9a`

| Field | Value |
|---|---|
| SHA-256 | `a2ca31441dec4d9a0d5895c0b2cc3fa9fb77928e91d4b8b0e14d189de62a977e` |
| Family label | `RemusStealer` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-07-18 20:36:16` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a2e2d854e6590012c7d506556fe0a1e` |
| SHA-1 | `5506d8c3809f67bbfd103861644a92d98f261790` |
| SHA-256 | `a2ca31441dec4d9a0d5895c0b2cc3fa9fb77928e91d4b8b0e14d189de62a977e` |
| SHA3-384 | `136407f3007f8f2ac5150e8b91341d0289ee418414ee0b2acadfb547c0211ef4dc12c90d9476ccb551b2210589aaf434` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15AE55B47FCA108F6C099A335C9A79642BB75BC081B3623D72EA0BB782E727D05D79714` |
| SSDEEP | `49152:HxE9G262Gj7Qcew8A81Og2TN75h5kqb2cJUd:H+8D8gT3h52` |
| ICON-DHASH | `f2f967b4f03443b0` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_035_a2ca3144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2ca31441dec4d9a0d5895c0b2cc3fa9fb77928e91d4b8b0e14d189de62a977e"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:36:16"
  condition:
    hash.sha256(0, filesize) == "a2ca31441dec4d9a0d5895c0b2cc3fa9fb77928e91d4b8b0e14d189de62a977e"
}
```

### Sample 36: `d0ff931a90185451`

| Field | Value |
|---|---|
| SHA-256 | `d0ff931a901854514c8afb8305293deee95a33627615cbf727f500f89531fd6e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-18 20:13:22` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6d73d6f992a64fec85bc2dcc3bc0ba7` |
| SHA-1 | `40e5290d17486b81dcaa1dbf5ec1cf559af35434` |
| SHA-256 | `d0ff931a901854514c8afb8305293deee95a33627615cbf727f500f89531fd6e` |
| SHA3-384 | `727fc80e61364519b1340d5e3b9f0a39c6a6e3d98185b0df08008efb4e763a51a7d19616fb8c9e9ab15bbb9be5b5ee1f` |
| IMPHASH | `3e6bb8ffd12689b22caf2a451c63973e` |
| TLSH | `T1AAF523037F41E116C04A2975CEA4DBF91329FC0C865A979B36D66E5FBEDE1CB2C24290` |
| SSDEEP | `98304:0eMb3Q5T4JauHvxOEKxbHdzGHSgk+BKgz/rm:rM7Qtz24E6bgHSgk6Kgbrm` |
| ICON-DHASH | `d4e869b2b269e8d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_d0ff931a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0ff931a901854514c8afb8305293deee95a33627615cbf727f500f89531fd6e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 20:13:22"
  condition:
    hash.sha256(0, filesize) == "d0ff931a901854514c8afb8305293deee95a33627615cbf727f500f89531fd6e"
}
```

### Sample 37: `1ad7dfd90e4928dc`

| Field | Value |
|---|---|
| SHA-256 | `1ad7dfd90e4928dcf285956e5fa3af23f14d7166d8deca9b82ab26532e734894` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-18 20:07:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1ecce9cdb0247a76a5f1d5a038fa7b8` |
| SHA-1 | `257832db3c3e8d94eefe3124a880c483d04455a9` |
| SHA-256 | `1ad7dfd90e4928dcf285956e5fa3af23f14d7166d8deca9b82ab26532e734894` |
| SHA3-384 | `e3a885de6b7404f71f45836ab67a1dd35f9143a6891233f1ab837890efca15e9ca6f6f640653aec9348a30d5f7e3721c` |
| TLSH | `T1E1D32999F880DE52C6D12676FB5E118C33231778C3DE710ACE245E346BEBD5A0A7E942` |
| SSDEEP | `3072:ZBz7cJm0Jg6lcc14ns/5vVh5cYEEUO7QZ2m/HW2+lp7Plub+Zff1Dl5:ZB/E7quX5cYEEUO7QZ2SHj+lzo2f955` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_1ad7dfd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ad7dfd90e4928dcf285956e5fa3af23f14d7166d8deca9b82ab26532e734894"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-18 20:07:58"
  condition:
    hash.sha256(0, filesize) == "1ad7dfd90e4928dcf285956e5fa3af23f14d7166d8deca9b82ab26532e734894"
}
```

### Sample 38: `44c18a7290c4e03d`

| Field | Value |
|---|---|
| SHA-256 | `44c18a7290c4e03daa4e22478bfb946c68bf49696394c0b587af76645fbae6b2` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-18 20:07:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db43e871868c51eb13607bccdd3e8161` |
| SHA-1 | `ff3c1a3390d974f38973209e48ae8b62e0e4d146` |
| SHA-256 | `44c18a7290c4e03daa4e22478bfb946c68bf49696394c0b587af76645fbae6b2` |
| SHA3-384 | `cf920d07645d8fd74d89cf9e9899f4483619660696f0e8d9aee729757e7457dcd5e1918cfc01f9b94b771fdb98a7f564` |
| TLSH | `T10643F2F093188E69EB111C31C1659E42875283BD5A5D27B04A15878C7E96C8FF3DBE8F` |
| SSDEEP | `1536:OY2StSuO8ksOgNdlK/MuESAxs9CU9DuL9XZ4aArfv:O1ExfksO+lCMuELs9CtLxZy3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_44c18a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44c18a7290c4e03daa4e22478bfb946c68bf49696394c0b587af76645fbae6b2"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-18 20:07:38"
  condition:
    hash.sha256(0, filesize) == "44c18a7290c4e03daa4e22478bfb946c68bf49696394c0b587af76645fbae6b2"
}
```

### Sample 39: `12f403c241fe472d`

| Field | Value |
|---|---|
| SHA-256 | `12f403c241fe472d840be10776e24d78613401efa752e523e9892253f18eb73f` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 19:57:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25984b39e6cd25cbafd85d920cfd8453` |
| SHA-1 | `4498bdacb86d46cd29525cb42c4db1f378b63250` |
| SHA-256 | `12f403c241fe472d840be10776e24d78613401efa752e523e9892253f18eb73f` |
| SHA3-384 | `22cc53044897f14c2f635d49bdb05b55efa659ad342866f95c571979e377e4a9449f6fea52c0aebad360a02596b75ce7` |
| TLSH | `T1BF143B49BE652BE7D05FCE30152A930B25DE644FA3F1B73AE278CD4C399A20859F3854` |
| TELFHASH | `t1c131cef08b3b55215a89cbec89edb75e491e8115460bdf33fe2180bc50160ede225d4f` |
| SSDEEP | `3072:jax87Edk8XOb6C1SGwheOE1gIpGeoudYF1DZ:je87Edk8Xc6C1SGwheOypGeonzt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_12f403c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f403c241fe472d840be10776e24d78613401efa752e523e9892253f18eb73f"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 19:57:39"
  condition:
    hash.sha256(0, filesize) == "12f403c241fe472d840be10776e24d78613401efa752e523e9892253f18eb73f"
}
```

### Sample 40: `a4d9ff95947ec0ae`

| Field | Value |
|---|---|
| SHA-256 | `a4d9ff95947ec0aee0aa0344cc7c41076b1474a613ed8eb995c5ce52cc4dc77a` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 19:57:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07cc02f404cc980b784e0cf4b9f7a6fc` |
| SHA-1 | `221340bab80f2917a360f5e788b38070970a545c` |
| SHA-256 | `a4d9ff95947ec0aee0aa0344cc7c41076b1474a613ed8eb995c5ce52cc4dc77a` |
| SHA3-384 | `47efd81e02625ada186ae908bfeca6419de92aef61efc4285e6efaea23e2fc103ae0f46d1875ac37e39e20ccda9b85b8` |
| TLSH | `T1448312D22B9BF5D6D533DE729242440705B0E7F0BCA82AA542C107656BB8DCC336A87E` |
| SSDEEP | `1536:GoTYWfxHQGSCNJanvUWaMWs88DvLrTSHgl6bnEQlYyLIUJwpDfd0M:VfxHQG7qnvUWaJs8eibEQ+SzOp50M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_a4d9ff95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4d9ff95947ec0aee0aa0344cc7c41076b1474a613ed8eb995c5ce52cc4dc77a"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 19:57:12"
  condition:
    hash.sha256(0, filesize) == "a4d9ff95947ec0aee0aa0344cc7c41076b1474a613ed8eb995c5ce52cc4dc77a"
}
```

### Sample 41: `0cc4b3d85067560d`

| Field | Value |
|---|---|
| SHA-256 | `0cc4b3d85067560d977bd3db51484d2073dc07eab3115b0d606214e6666e86e9` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-18 19:57:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9d60659ffadbb54ee72c62322040a07` |
| SHA-1 | `2d68daba693b9dd55356329c94417a79c2be1b99` |
| SHA-256 | `0cc4b3d85067560d977bd3db51484d2073dc07eab3115b0d606214e6666e86e9` |
| SHA3-384 | `ac51b7b13f849fa323b99b83412fe76d42179a49d7ef05b0657dc1a9839f35db2a6c2d040cab657f6602aae2bceedd49` |
| TLSH | `T1A8C28C966A867C44BEC94A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:X8vCB+25j6es8R7R9FYpMSUpi+20qUpi+20YQX:X8l25J7Hd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_0cc4b3d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cc4b3d85067560d977bd3db51484d2073dc07eab3115b0d606214e6666e86e9"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-18 19:57:11"
  condition:
    hash.sha256(0, filesize) == "0cc4b3d85067560d977bd3db51484d2073dc07eab3115b0d606214e6666e86e9"
}
```

### Sample 42: `d6bb2dc0431405c4`

| Field | Value |
|---|---|
| SHA-256 | `d6bb2dc0431405c4158cc15ed0171fd3a53986bc79149ada27dec7b1edcf5b14` |
| Family label | `Mirai` |
| File name | `tmips` |
| File type | `elf` |
| First seen | `2026-07-18 19:57:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `feef25ff082e96ecd128d8328235861c` |
| SHA-1 | `51ae8b83f4b13d8bee68a509e1d813bd2d2c25df` |
| SHA-256 | `d6bb2dc0431405c4158cc15ed0171fd3a53986bc79149ada27dec7b1edcf5b14` |
| SHA3-384 | `9cc47af9e4110e7d75270879f01f89ab1e5a21bce78ee52eb7c2f0fcf37408b77ea50d42ab9f0671251c4f9c081865c6` |
| TLSH | `T1BFB3C61A2E219F7EF35C827547B78E25935C27C627F1D585D29CD9001E7038EA81FBA8` |
| TELFHASH | `t1de11e808893863f4d7b21cd967edff76e49170db46215e778e00e9ad9a2ed425e01c2c` |
| SSDEEP | `3072:ESHa6vAaUu29Ip5t7t7pboxe0CEaONQIzogc7wa1y:ESHa6vvUu29Ip5t78QEaON/c51y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_d6bb2dc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6bb2dc0431405c4158cc15ed0171fd3a53986bc79149ada27dec7b1edcf5b14"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-18 19:57:10"
  condition:
    hash.sha256(0, filesize) == "d6bb2dc0431405c4158cc15ed0171fd3a53986bc79149ada27dec7b1edcf5b14"
}
```

### Sample 43: `de2242d7b25c7129`

| Field | Value |
|---|---|
| SHA-256 | `de2242d7b25c7129db2db9d37c4d3b10388769a9d69c02ed24df4d9375ae9bfd` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:52:19` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78c53be6706481e18028c3dc4ca76fd3` |
| SHA-1 | `627ccf37459337970951341cb17c26df1ccda4fb` |
| SHA-256 | `de2242d7b25c7129db2db9d37c4d3b10388769a9d69c02ed24df4d9375ae9bfd` |
| SHA3-384 | `effad1905e118ce1cf25cb6f2e64512ad6e37c5dff14013dc2cd0d813e887e28ed7d2fd9f9c288b2c25dee09c3240275` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10CD54A07FC9109F6C09AA335C9A79642BB75BC091B3223D72EA0BB782E727D15D39710` |
| SSDEEP | `49152:wgcTVlrKegQUWeSNe4iGrbiRvSnngkqouc:wb744tsvog` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_de2242d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de2242d7b25c7129db2db9d37c4d3b10388769a9d69c02ed24df4d9375ae9bfd"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:52:19"
  condition:
    hash.sha256(0, filesize) == "de2242d7b25c7129db2db9d37c4d3b10388769a9d69c02ed24df4d9375ae9bfd"
}
```

### Sample 44: `c481200a9404e919`

| Field | Value |
|---|---|
| SHA-256 | `c481200a9404e919fd2510f78ca1a119ce563dcaccd96329eef495eb664af2f3` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 19:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bab958e7900384f1c018d7e33e651e85` |
| SHA-1 | `6fc7df641b9aa5aa37dd8a2604ff4a1de1d1c9c8` |
| SHA-256 | `c481200a9404e919fd2510f78ca1a119ce563dcaccd96329eef495eb664af2f3` |
| SHA3-384 | `399589200d69bc95a5e66e49e89ca69221e99c4549d3b1fcaaa3d72d09ebbe84c1de11c292c8263d50dc984a69c20fda` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T177E63358EAC425EDDA23003CEED386D5E6A978A50B31C8DB178887B96F971D04D3D363` |
| SSDEEP | `393216:X5Gs2zlmIPkxM8Rpl05VhqLSYXMCHWUjX5cuI3/PGTAI:XP2zlmIPkWI0PIL9XMb8XOH/O7` |
| ICON-DHASH | `19dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_c481200a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c481200a9404e919fd2510f78ca1a119ce563dcaccd96329eef495eb664af2f3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 19:52:11"
  condition:
    hash.sha256(0, filesize) == "c481200a9404e919fd2510f78ca1a119ce563dcaccd96329eef495eb664af2f3"
}
```

### Sample 45: `7f9abea59adaab02`

| Field | Value |
|---|---|
| SHA-256 | `7f9abea59adaab023f9c023f315d41e2599246d660569a72d12fd7298facd30d` |
| Family label | `RemusStealer` |
| File name | `setup_euone.bin` |
| File type | `exe` |
| First seen | `2026-07-18 19:52:07` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, GCleaner, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faf46bcad3054d8b66eb21155cca966d` |
| SHA-1 | `deac2c858aff1490bbd6c4a56dc75d38bfc985d7` |
| SHA-256 | `7f9abea59adaab023f9c023f315d41e2599246d660569a72d12fd7298facd30d` |
| SHA3-384 | `68a70a1d59a84560875cefd3b5af58b7ad0b82c014ebf1b0ebb776bbf33df093ca903b97d8de2f4456921342afbf14bf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F8657E2027E91199F57BAE36D7E6B186D67FF3626A069F4F1144834B0623702CE83D39` |
| SSDEEP | `12288:BkrkenekJ6R859c4qGhrwQNFmbKVbNPwGO8MDkjtnsJturxkbbNxjmVE0VvlBGCD:BCPMyPPhr7NPXH4osJeMgTc6vmBSvGQ` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_045_7f9abea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9abea59adaab023f9c023f315d41e2599246d660569a72d12fd7298facd30d"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-18 19:52:07"
  condition:
    hash.sha256(0, filesize) == "7f9abea59adaab023f9c023f315d41e2599246d660569a72d12fd7298facd30d"
}
```

### Sample 46: `82b541e29a8413e1`

| Field | Value |
|---|---|
| SHA-256 | `82b541e29a8413e1453ebc9323ce37fd86d02bc108b7c9fbe877c49ffe19ae4a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-18 19:42:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `776cf05d4dc937085e65847c92e56357` |
| SHA-1 | `b22598132453960c2ba2b7b56da37fcb405e2ff9` |
| SHA-256 | `82b541e29a8413e1453ebc9323ce37fd86d02bc108b7c9fbe877c49ffe19ae4a` |
| SHA3-384 | `66c02c5a9f92ef74b814960d4715a546dae84d60c514e12d124efa6f67411d9f64a3c240db0dca1cb6484209f31d0465` |
| TLSH | `T1E0237D6526857C14AA99C8371D7E2F0CBDAD43E6320452EE7FCB3CF68C4A69CA10971D` |
| SSDEEP | `768:A6rDTPjHh9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:3r3ucr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_82b541e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82b541e29a8413e1453ebc9323ce37fd86d02bc108b7c9fbe877c49ffe19ae4a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 19:42:38"
  condition:
    hash.sha256(0, filesize) == "82b541e29a8413e1453ebc9323ce37fd86d02bc108b7c9fbe877c49ffe19ae4a"
}
```

### Sample 47: `cc794f7ab2405917`

| Field | Value |
|---|---|
| SHA-256 | `cc794f7ab2405917722c4f093695bfc9a4b5f0c43e83b807e11078f235c0f20d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-18 19:37:50` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cc72530600bc81570e41d83c4fc723d` |
| SHA-1 | `1a0e6ae5bf273f096aa9665b5e2a75c86d32f639` |
| SHA-256 | `cc794f7ab2405917722c4f093695bfc9a4b5f0c43e83b807e11078f235c0f20d` |
| SHA3-384 | `7aceed6dd7aeaeecd3cd95f590f102bdb8cfe0116193b3dbafca5e6824782a64b1382ae31e207fc6d29492cd842ca436` |
| IMPHASH | `64a45e547ff6ac4f0ce5439179290d74` |
| TLSH | `T186E52306BB90E550C90A6DBACE60E3FDA325FD4CCA61934374C17F6BBDA91C26F06059` |
| SSDEEP | `98304:lMIikU1/vbIw2rxdJxKCW6inTzmnwA0XsnXH:lMNAdJxKCW62TynVj3` |
| ICON-DHASH | `10b2b269e9f0f400` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_cc794f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc794f7ab2405917722c4f093695bfc9a4b5f0c43e83b807e11078f235c0f20d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 19:37:50"
  condition:
    hash.sha256(0, filesize) == "cc794f7ab2405917722c4f093695bfc9a4b5f0c43e83b807e11078f235c0f20d"
}
```

### Sample 48: `8fde35bc9d65dbe2`

| Field | Value |
|---|---|
| SHA-256 | `8fde35bc9d65dbe298daaa2cf8d720b452bc3f1d0596d58a6380819a704ccfe6` |
| Family label | `unknown` |
| File name | `_up.bin` |
| File type | `unknown` |
| First seen | `2026-07-18 19:34:02` |
| Reporter | `nullblue67` |
| Tags | `aws, cryptostealer, exfiltration, infostealer, python, stealer, wallet-stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9d2118382b03576769a3a039492ac01` |
| SHA-256 | `8fde35bc9d65dbe298daaa2cf8d720b452bc3f1d0596d58a6380819a704ccfe6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_8fde35bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fde35bc9d65dbe298daaa2cf8d720b452bc3f1d0596d58a6380819a704ccfe6"
    family = "unknown"
    file_name = "_up.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:34:02"
  condition:
    hash.sha256(0, filesize) == "8fde35bc9d65dbe298daaa2cf8d720b452bc3f1d0596d58a6380819a704ccfe6"
}
```

### Sample 49: `0a3061ce09d7e3cb`

| Field | Value |
|---|---|
| SHA-256 | `0a3061ce09d7e3cb2b3d3453432da69ee83b59b782853d1f6462fd177db75a7a` |
| Family label | `ValleyRAT` |
| File name | `WindowsUpdate.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:30:05` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.sa, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `342921124f76e174afe304378f83b131` |
| SHA-1 | `41992224badfd69a5c54c81745872ac29abc91cd` |
| SHA-256 | `0a3061ce09d7e3cb2b3d3453432da69ee83b59b782853d1f6462fd177db75a7a` |
| SHA3-384 | `5589db6c8f0384c9dc85ee0bee5fa2a3b1f50e59fcda922332b8fe272165a2e807a2fb876cc2bf7dd138f3b10a425610` |
| IMPHASH | `9a5ce9cc0ff609d5b4e33d5c57eaa35a` |
| TLSH | `T1F514274BAA6A20E0E1758134477307E29B6D3D355692DB9F43D03B169E3E2D0FD29B32` |
| SSDEEP | `3072:90DxAbBeJSzeMm8NmuQ2s6J8J22buAs0FNmhMn+IhNrY:u9A5zeMmkrM8Yl` |
| ICON-DHASH | `011d45253929e1c6` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_049_0a3061ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a3061ce09d7e3cb2b3d3453432da69ee83b59b782853d1f6462fd177db75a7a"
    family = "ValleyRAT"
    file_name = "WindowsUpdate.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:30:05"
  condition:
    hash.sha256(0, filesize) == "0a3061ce09d7e3cb2b3d3453432da69ee83b59b782853d1f6462fd177db75a7a"
}
```

### Sample 50: `b81541b461d90fd8`

| Field | Value |
|---|---|
| SHA-256 | `b81541b461d90fd82a6f15db387b00d4562556c6880be44daae581ad8857696b` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-18 19:28:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `901e476e87da6d323d36fedc2f953bcf` |
| SHA-1 | `d182aa9c76d4d7a73b2531976059b875b796a968` |
| SHA-256 | `b81541b461d90fd82a6f15db387b00d4562556c6880be44daae581ad8857696b` |
| SHA3-384 | `125d4067c9dccb857a3570f1466abb2da49f35475aef64d94ae64c7bdd25cabebced5c45d8d05b3c04d296cede7e43a9` |
| TLSH | `T10CD32999F880DE52C6D12676FB5E118C33231778C3DE710ACE245E346BEBD5A0A7E942` |
| SSDEEP | `3072:ZBz7cJm0Jg6lcc14ns/5vVh5cYEEUO7QZ2m/HW2+lp7Plub+Zof1Dl5:ZB/E7quX5cYEEUO7QZ2SHj+lzo2o955` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_b81541b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81541b461d90fd82a6f15db387b00d4562556c6880be44daae581ad8857696b"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-18 19:28:43"
  condition:
    hash.sha256(0, filesize) == "b81541b461d90fd82a6f15db387b00d4562556c6880be44daae581ad8857696b"
}
```

### Sample 51: `807ff5f5f8287af5`

| Field | Value |
|---|---|
| SHA-256 | `807ff5f5f8287af5e32bc184dffff438f87e856b207d5860f7d2d6fc95a8b5bb` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-18 19:28:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e55bd83cd00769bedd63fcdac6ce8bf` |
| SHA-1 | `19b33fe59ab717dd787c7b13ece0e12ee59a962d` |
| SHA-256 | `807ff5f5f8287af5e32bc184dffff438f87e856b207d5860f7d2d6fc95a8b5bb` |
| SHA3-384 | `c6761c21109286e9dded7c40558d63063fe58d41c2d5a26512f9c954915106ece40af77169ebf1602e13f5e81c91feed` |
| TLSH | `T16843F1F05315895AEB211D32C1B5CF428B52C37E6A5C23B44916868C7A9588EA3DAF8F` |
| SSDEEP | `1536:OY2StSuO8ksOgNdlK/MuESAxs9CU9DuL9XXObzfb:O1ExfksO+lCMuELs9CtLx+PT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_807ff5f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "807ff5f5f8287af5e32bc184dffff438f87e856b207d5860f7d2d6fc95a8b5bb"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-18 19:28:12"
  condition:
    hash.sha256(0, filesize) == "807ff5f5f8287af5e32bc184dffff438f87e856b207d5860f7d2d6fc95a8b5bb"
}
```

### Sample 52: `5d8b4b815ac2ebb4`

| Field | Value |
|---|---|
| SHA-256 | `5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b` |
| Family label | `unknown` |
| File name | `5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b.bin` |
| File type | `unknown` |
| First seen | `2026-07-18 19:28:05` |
| Reporter | `whack` |
| Tags | `script, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05ad654b1d3706635d3dd56a08729beb` |
| SHA-256 | `5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_5d8b4b81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b"
    family = "unknown"
    file_name = "5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:28:05"
  condition:
    hash.sha256(0, filesize) == "5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b"
}
```

### Sample 53: `d5558cd419c8d46b`

| Field | Value |
|---|---|
| SHA-256 | `d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed` |
| Family label | `unknown` |
| File name | `d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed.bin` |
| File type | `unknown` |
| First seen | `2026-07-18 19:27:41` |
| Reporter | `whack` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3be7b8b182ccd96e48989b4e57311193` |
| SHA-256 | `d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_d5558cd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"
    family = "unknown"
    file_name = "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:27:41"
  condition:
    hash.sha256(0, filesize) == "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"
}
```

### Sample 54: `5ca42befc2a4171b`

| Field | Value |
|---|---|
| SHA-256 | `5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590` |
| Family label | `unknown` |
| File name | `5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:27:04` |
| Reporter | `whack` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `098efe3ae2e32aa84af702428710065e` |
| SHA-256 | `5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_5ca42bef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590"
    family = "unknown"
    file_name = "5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:27:04"
  condition:
    hash.sha256(0, filesize) == "5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590"
}
```

### Sample 55: `acff38c20f19afa1`

| Field | Value |
|---|---|
| SHA-256 | `acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd` |
| Family label | `unknown` |
| File name | `acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:26:56` |
| Reporter | `whack` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73873e23248337990f71a178c6080717` |
| SHA-256 | `acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_acff38c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd"
    family = "unknown"
    file_name = "acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:56"
  condition:
    hash.sha256(0, filesize) == "acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd"
}
```

### Sample 56: `e9639e3c4681ce85`

| Field | Value |
|---|---|
| SHA-256 | `e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80` |
| Family label | `unknown` |
| File name | `e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80.bin` |
| File type | `unknown` |
| First seen | `2026-07-18 19:26:53` |
| Reporter | `whack` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e46c4e5e1fbc64b1bae9ebd9bcef7fcf` |
| SHA-256 | `e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e9639e3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80"
    family = "unknown"
    file_name = "e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:26:53"
  condition:
    hash.sha256(0, filesize) == "e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80"
}
```

### Sample 57: `28484ae186b36505`

| Field | Value |
|---|---|
| SHA-256 | `28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a` |
| Family label | `unknown` |
| File name | `28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a.bin` |
| File type | `unknown` |
| First seen | `2026-07-18 19:26:50` |
| Reporter | `whack` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dd1551c05b87cf0486418c593b37fd3` |
| SHA-256 | `28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_28484ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a"
    family = "unknown"
    file_name = "28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:26:50"
  condition:
    hash.sha256(0, filesize) == "28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a"
}
```

### Sample 58: `3c285c3fd881cc3b`

| Field | Value |
|---|---|
| SHA-256 | `3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360` |
| Family label | `unknown` |
| File name | `3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:26:42` |
| Reporter | `whack` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2252f024521dfee2ccf057282cc16caf` |
| SHA-256 | `3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_3c285c3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360"
    family = "unknown"
    file_name = "3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:42"
  condition:
    hash.sha256(0, filesize) == "3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360"
}
```

### Sample 59: `c767bb6b6dd0b149`

| Field | Value |
|---|---|
| SHA-256 | `c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861` |
| Family label | `unknown` |
| File name | `c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:26:38` |
| Reporter | `whack` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e7f18f1e50a222a17888d3de9e63730` |
| SHA-256 | `c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_c767bb6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861"
    family = "unknown"
    file_name = "c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:38"
  condition:
    hash.sha256(0, filesize) == "c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861"
}
```

### Sample 60: `1066003052bf79de`

| Field | Value |
|---|---|
| SHA-256 | `1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7` |
| Family label | `unknown` |
| File name | `1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:26:22` |
| Reporter | `whack` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47faf7750cf003e0f64ea3fea9c44b39` |
| SHA-256 | `1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_10660030
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7"
    family = "unknown"
    file_name = "1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:22"
  condition:
    hash.sha256(0, filesize) == "1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7"
}
```

### Sample 61: `c1d7ce9290ee9a14`

| Field | Value |
|---|---|
| SHA-256 | `c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07` |
| Family label | `NanoCore` |
| File name | `036227aa4ccacd6153de68143e02f001.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:25:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `036227aa4ccacd6153de68143e02f001` |
| SHA-1 | `746b7fc0665654244961885933decb7c3f7dc3a4` |
| SHA-256 | `c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07` |
| SHA3-384 | `88059047349c28852a94bff1fc24201167243f6a6041e2492bd7599f44e2815b4d026d09bf985bc276a3890c922a95f8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14614CF267BF98A2FE2DE86B9611212028379C2E399C3F3DE18D455B74F267E506071D3` |
| SSDEEP | `3072:MzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HIC9P+1Nda82N+xdkv9iRLGeQL8:MLV6Bta6dtJmakIM5pkAgNpx` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_061_c1d7ce92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07"
    family = "NanoCore"
    file_name = "036227aa4ccacd6153de68143e02f001.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:25:06"
  condition:
    hash.sha256(0, filesize) == "c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07"
}
```

### Sample 62: `2e0cc1e150d44c19`

| Field | Value |
|---|---|
| SHA-256 | `2e0cc1e150d44c19a28246ad632d71efeae39ce1a71ff32be4707b2fb8303360` |
| Family label | `unknown` |
| File name | `KL-2026.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:24:46` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaed2057837383f973ea9f681c533da5` |
| SHA-1 | `8752896c85760629c8520c88eaa8e1464a3d05f8` |
| SHA-256 | `2e0cc1e150d44c19a28246ad632d71efeae39ce1a71ff32be4707b2fb8303360` |
| SHA3-384 | `6c5456be2d305432f6be80656a6e47519215871fe9dda45c13761213883b3f268cb1f09bce1d4b1c9043ebe556a2833a` |
| IMPHASH | `f4d1e4cd7416ef83f79f7c6a038875b3` |
| TLSH | `T146183305C6E3FD67FF08863E318A76EE8BEDD18688CA9902461F15F59175A4C12C327B` |
| SSDEEP | `1572864:otxRftUgOPzx6HsZFVAuK24cQgbWF0ZK/DZGbQRiVgIZvm9oqSPPWt:KftUgox643P/ZKIkRCPZe9xSWt` |
| ICON-DHASH | `d0e0f86cf4dcdccc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_2e0cc1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e0cc1e150d44c19a28246ad632d71efeae39ce1a71ff32be4707b2fb8303360"
    family = "unknown"
    file_name = "KL-2026.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:24:46"
  condition:
    hash.sha256(0, filesize) == "2e0cc1e150d44c19a28246ad632d71efeae39ce1a71ff32be4707b2fb8303360"
}
```

### Sample 63: `6aa982f7c6167752`

| Field | Value |
|---|---|
| SHA-256 | `6aa982f7c6167752e8f58083dc5f1c11ff0aa63b3c3d2e192009cce2cef84ee0` |
| Family label | `Gh0stRAT` |
| File name | `3DQQey.exe` |
| File type | `exe` |
| First seen | `2026-07-18 19:23:53` |
| Reporter | `CNGaoLing` |
| Tags | `exe, Gh0st, Gh0stRAT, SilverFox` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d9fa801432654ebfe456974bb355bd2` |
| SHA-1 | `875108112d2fdfbdb04d75bbbe993b1ce8aea140` |
| SHA-256 | `6aa982f7c6167752e8f58083dc5f1c11ff0aa63b3c3d2e192009cce2cef84ee0` |
| SHA3-384 | `8f67c1ccec91f04d00c7b79b1cfb8c643f31b1f7eac2bf42e2f86854639c526ee5bedf0e81da46b1672bd152f0a1307f` |
| IMPHASH | `5a594319a0d69dbc452e748bcf05892e` |
| TLSH | `T18A17333FF26C663FC96A063248B386500CBBB915AA1E8C1B17F44C1DDF6A4611E3BB55` |
| SSDEEP | `393216:KwFpnUUq4rTJSxbrBcD6np1JJwg3ClC2/5QkLXGqdoadbqGvCH6F:KVT4JYmD6p1JuCqGqB/F` |
| ICON-DHASH | `d4dcdcfab4a4ea0e` |

#### Technical Assessment

- The sample is tracked as `Gh0stRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gh0stRAT_063_6aa982f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa982f7c6167752e8f58083dc5f1c11ff0aa63b3c3d2e192009cce2cef84ee0"
    family = "Gh0stRAT"
    file_name = "3DQQey.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:23:53"
  condition:
    hash.sha256(0, filesize) == "6aa982f7c6167752e8f58083dc5f1c11ff0aa63b3c3d2e192009cce2cef84ee0"
}
```

### Sample 64: `ae017c8e2745db9d`

| Field | Value |
|---|---|
| SHA-256 | `ae017c8e2745db9dbc72190fa6ef481fcaee17624ef75aa3dee317e1774783d3` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-18 19:21:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a4300401f3ca8f89e98d945d0f3600a` |
| SHA-1 | `0103316dfe505831beaf6a67718013e32c9fd806` |
| SHA-256 | `ae017c8e2745db9dbc72190fa6ef481fcaee17624ef75aa3dee317e1774783d3` |
| SHA3-384 | `5b9b67f5595ff9cda0e988984002de1d2566f167aa97f9218cacbd7da10cef8971b54ee38536377df30b5271e86845ad` |
| TLSH | `T114148D01FB140953D1931EB45B3F07B6D379988358FAE009290BBB561733EBA96C7B89` |
| SSDEEP | `6144:fMfyxWEG1Y0b9cf+zWmAk/Opxco8N3OFQCHGa:U6jIcbQeoCx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_ae017c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae017c8e2745db9dbc72190fa6ef481fcaee17624ef75aa3dee317e1774783d3"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-18 19:21:19"
  condition:
    hash.sha256(0, filesize) == "ae017c8e2745db9dbc72190fa6ef481fcaee17624ef75aa3dee317e1774783d3"
}
```

### Sample 65: `67a84e063171340d`

| Field | Value |
|---|---|
| SHA-256 | `67a84e063171340de0b552334aa72b1760bbcc699acda2251d8c89cc5bdb6019` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-18 19:20:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb7161df20cdad35979418eeaa69da23` |
| SHA-1 | `0f2a7e4a4cbd4a760d433c109ead624fa7a7c3ba` |
| SHA-256 | `67a84e063171340de0b552334aa72b1760bbcc699acda2251d8c89cc5bdb6019` |
| SHA3-384 | `07c24de88653fd0bf029e57ed69fe6614409bd99fb2418194b7b78fe3f0211e16d359633dad4492d030e75c3f51c9222` |
| TLSH | `T1996302ED82643E0FDECE37B1694FF5D8D6941BC136B28BD24B804D7A4121E94E94072A` |
| SSDEEP | `1536:UlmGEt9ccBIbfv84d5lcxM7RoSxbVOc+mBw/24DlGoCemW2dT4u+qgw0r3:Ur5bc4Bcx4Bw+i/vTCZT4u+qgws` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_67a84e06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67a84e063171340de0b552334aa72b1760bbcc699acda2251d8c89cc5bdb6019"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-18 19:20:28"
  condition:
    hash.sha256(0, filesize) == "67a84e063171340de0b552334aa72b1760bbcc699acda2251d8c89cc5bdb6019"
}
```

### Sample 66: `e3fbfb7116690c98`

| Field | Value |
|---|---|
| SHA-256 | `e3fbfb7116690c986c33431e4609270793a4ad77e231bf69a804c276cc6b3de8` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-18 19:14:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08013559ceb333d76180b6312fb665cb` |
| SHA-1 | `33d3b227600b3d8d39c0edee675deb99060c9cb6` |
| SHA-256 | `e3fbfb7116690c986c33431e4609270793a4ad77e231bf69a804c276cc6b3de8` |
| SHA3-384 | `bcf820f6a0ab3a8ab2813ee1acadc4a2f10400fd45bae9e91cf93e4fa1880a661066b58e539f577c2f72f8b844ea32b5` |
| TLSH | `T174D33A06759154FCC15BC434C76FA537EA31B86D13343AAF6B84AA312E23E711F0AB92` |
| SSDEEP | `1536:xf5yMjx/K7FKgTcuxVm10Tiwns2rGPZrxPKjzC1SEG2l4ra8ykDC/3Z1MczZ/G46:WEpKk0cuxVTxGxFK2HqiZ1ZZ/G4tAy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_e3fbfb71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fbfb7116690c986c33431e4609270793a4ad77e231bf69a804c276cc6b3de8"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 19:14:39"
  condition:
    hash.sha256(0, filesize) == "e3fbfb7116690c986c33431e4609270793a4ad77e231bf69a804c276cc6b3de8"
}
```

### Sample 67: `74647c51a6559b61`

| Field | Value |
|---|---|
| SHA-256 | `74647c51a6559b61360585913586b1631a09a262112a132c2b094bbbdbf58393` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-18 19:13:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbb9b8956b806b1f95bf90bd0bcba987` |
| SHA-1 | `b280055fe2ebe53b8c0bb37171676d081184c05f` |
| SHA-256 | `74647c51a6559b61360585913586b1631a09a262112a132c2b094bbbdbf58393` |
| SHA3-384 | `6cb5c52724c9fc290bf6f094c09f7d3ae1785ddc5c35eb5ad32a3365bca638e3a298507a2b873e9151d050ee7e4ba7e1` |
| TLSH | `T11953F2B7211DA176D2A2B0BD514452E4E82A984F2A23961D11EB3F7EDCF22267C53F13` |
| SSDEEP | `1536:/R1UkIGMYR0HD2T5FlD6Sc18Pvsnz5ABFdU/yjm:/wkIG/0HD2lWSc8Pvq52kyC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_74647c51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74647c51a6559b61360585913586b1631a09a262112a132c2b094bbbdbf58393"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 19:13:09"
  condition:
    hash.sha256(0, filesize) == "74647c51a6559b61360585913586b1631a09a262112a132c2b094bbbdbf58393"
}
```

### Sample 68: `a450ac18a22635a9`

| Field | Value |
|---|---|
| SHA-256 | `a450ac18a22635a97910c4ac7e1320d091429a94838d21560a41e134748bc3a7` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-18 19:12:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcb287f25da63c942da7d2e0baa81df0` |
| SHA-1 | `ae74e2fd07f6f677d8053a56d483f49f8e77cc93` |
| SHA-256 | `a450ac18a22635a97910c4ac7e1320d091429a94838d21560a41e134748bc3a7` |
| SHA3-384 | `675c0ee798ff789dc8ca08846bb7cdba69a1893372ad570357245332d5cffb3ebd14ef329b3b61bcd6dccd85d8ca5feb` |
| TLSH | `T1EBD32A99FC80DE52C6D12675FA5E118C332357B8C3DA7206CD209E3477EBD9A0A7E942` |
| SSDEEP | `3072:m54NUsnyFlldoniF9qUQ4g8OYCbiLnAwIR1qp3lef1Dl:mmUsyFliUQ4g8ONbiLo1qp1e95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_a450ac18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a450ac18a22635a97910c4ac7e1320d091429a94838d21560a41e134748bc3a7"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-18 19:12:43"
  condition:
    hash.sha256(0, filesize) == "a450ac18a22635a97910c4ac7e1320d091429a94838d21560a41e134748bc3a7"
}
```

### Sample 69: `849980ecdf9d5d0e`

| Field | Value |
|---|---|
| SHA-256 | `849980ecdf9d5d0ea16f373c017f5aea16de2f91a0f56bcaf618c4fa4570dfb6` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-18 19:10:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8ab5da6f31c62622fe40ea20871ac3c` |
| SHA-1 | `fce809d76b956cc47a86c4ba08c0599e766487a7` |
| SHA-256 | `849980ecdf9d5d0ea16f373c017f5aea16de2f91a0f56bcaf618c4fa4570dfb6` |
| SHA3-384 | `6106b6ec5dcb63c11210d7b7c907f863d5df575c8fc15fc83dcf415a2bfa9bee304decec15dcf3114847f3a9cc7bfd7f` |
| TLSH | `T10643F2D1918B77A8E7170C72582542B3B0137B7C35FE31EA322C9A68B3E51C27174AE5` |
| SSDEEP | `1536:knAwBW7dMp/wGEB68ulZGrrnq/15EijE3jbtAfU:k9BWatLkUji5Ac` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_849980ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849980ecdf9d5d0ea16f373c017f5aea16de2f91a0f56bcaf618c4fa4570dfb6"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-18 19:10:17"
  condition:
    hash.sha256(0, filesize) == "849980ecdf9d5d0ea16f373c017f5aea16de2f91a0f56bcaf618c4fa4570dfb6"
}
```

### Sample 70: `531ee66757ef12a3`

| Field | Value |
|---|---|
| SHA-256 | `531ee66757ef12a35e430ca9bc723e1076a7242968f16925028bae0786505f5b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-18 19:06:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7c5c351504b5432c67887a639c47149` |
| SHA-1 | `b6ad3e9527099490d25ce8c10e7bc07acbca2593` |
| SHA-256 | `531ee66757ef12a35e430ca9bc723e1076a7242968f16925028bae0786505f5b` |
| SHA3-384 | `25aa013516ff98933b6fd503f9ccb713d83e8810c5fe89353b8b0b7e54fa613a25715a6ec8fa0209bb7da483206e0552` |
| TLSH | `T107236D651A857C24AA98C4371D7E1F0CBDAD43E6324492DE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:RXRWNGxVd09GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:rlx1cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_531ee667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "531ee66757ef12a35e430ca9bc723e1076a7242968f16925028bae0786505f5b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 19:06:54"
  condition:
    hash.sha256(0, filesize) == "531ee66757ef12a35e430ca9bc723e1076a7242968f16925028bae0786505f5b"
}
```

### Sample 71: `ec4d064aad177bbd`

| Field | Value |
|---|---|
| SHA-256 | `ec4d064aad177bbdbe3eddbc4b884732f66ee9233737888822423521ad0a19d2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-18 19:02:15` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87bb7dcef84c6d43cb1aa24ca53a6f9c` |
| SHA-1 | `a94f7a09f83bb397db620883b5632ef544531119` |
| SHA-256 | `ec4d064aad177bbdbe3eddbc4b884732f66ee9233737888822423521ad0a19d2` |
| SHA3-384 | `3bc651f7622bd2c49856592407d8a5727c081e343fda1572ecfcde04f3eefa9a54741ab91989ef9399bf504c8ce388c5` |
| IMPHASH | `3053b4f010e487673d7cd87a67262ddf` |
| TLSH | `T1A3E512033F10D942D06A1A359935CBF99321FC49EBA2439774C9BE4BBDEDAC25E026C5` |
| SSDEEP | `49152:6ANAZXZGyFBsaP7098V3dO4MXTXNGkzWXOOnrfKctSvBkisjT6UNKKyJWWgw:KXDF6aj/BMrNG6WXOOnrfKc8vBSjmUEP` |
| ICON-DHASH | `30f8ccd4d469b254` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_ec4d064a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec4d064aad177bbdbe3eddbc4b884732f66ee9233737888822423521ad0a19d2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 19:02:15"
  condition:
    hash.sha256(0, filesize) == "ec4d064aad177bbdbe3eddbc4b884732f66ee9233737888822423521ad0a19d2"
}
```

### Sample 72: `de9f7cef593d14d9`

| Field | Value |
|---|---|
| SHA-256 | `de9f7cef593d14d92502e907a7a4db73ffc2e5304c81183a853bc2e400ee5852` |
| Family label | `Mirai` |
| File name | `volar.sh4` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9ca030ae8e871d2fbe9ea6d590d4803` |
| SHA-1 | `77ff223a3296c57248958bcd706d096dae63216e` |
| SHA-256 | `de9f7cef593d14d92502e907a7a4db73ffc2e5304c81183a853bc2e400ee5852` |
| SHA3-384 | `d64bce361e1eb0a5dee14fb6ada052311103d2777e02a8d6874df0ca7b9056741fc01e471f0a12e18f122cfcc8ae2c0b` |
| TLSH | `T118B30963ED26AF1AD166E0F0B1F18E781B63BD2649471F9DA432EAE44147CCCB5053B8` |
| SSDEEP | `1536:dDYaZVJ+aCLKoxZv7KI7T+3XLwbWi56o6SBA49rQm:dDBVJ+a7o7NT+nMbW4GSq49F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_de9f7cef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de9f7cef593d14d92502e907a7a4db73ffc2e5304c81183a853bc2e400ee5852"
    family = "Mirai"
    file_name = "volar.sh4"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:58"
  condition:
    hash.sha256(0, filesize) == "de9f7cef593d14d92502e907a7a4db73ffc2e5304c81183a853bc2e400ee5852"
}
```

### Sample 73: `fbf8926b091c0eb3`

| Field | Value |
|---|---|
| SHA-256 | `fbf8926b091c0eb3f58e6ad7a483f44c14ba27aed05e9bdfe779d2bae490c39f` |
| Family label | `Mirai` |
| File name | `volar.i686` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19c71d88a3a2d23e208fdc07ff3364cc` |
| SHA-1 | `1088f1c0cdaa01f97de5108b1d22ed476164d83f` |
| SHA-256 | `fbf8926b091c0eb3f58e6ad7a483f44c14ba27aed05e9bdfe779d2bae490c39f` |
| SHA3-384 | `6162a8afdc471dcf6e973ffc9d4ff1e96a2ff7a183facb8ae8c000d4bd06df7efb151a0ede5ccb82ca66b9cb1eb04f04` |
| TLSH | `T1E7A31786BF43DFB3E85310F101F74B254B32FD3A5826DA95E3297EA59A061C1A616338` |
| TELFHASH | `t1636135b22eea08f8f7c05819d74e67e35e29da3b151075aa06f2694133f3b91c176c38` |
| SSDEEP | `1536:Helasa/vIJX7W2Grh8qLKMaHp9RrPTbTavZdq9x:HO5a/vCCrrh8qLyTidEx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_fbf8926b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbf8926b091c0eb3f58e6ad7a483f44c14ba27aed05e9bdfe779d2bae490c39f"
    family = "Mirai"
    file_name = "volar.i686"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:57"
  condition:
    hash.sha256(0, filesize) == "fbf8926b091c0eb3f58e6ad7a483f44c14ba27aed05e9bdfe779d2bae490c39f"
}
```

### Sample 74: `7e68a50b160e0bff`

| Field | Value |
|---|---|
| SHA-256 | `7e68a50b160e0bff70caaeb40beed073420d49e7544deed275f5f935e64342db` |
| Family label | `Mirai` |
| File name | `volar.mips` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf0815f041901a138ad2cefc1d92d1b1` |
| SHA-1 | `037a14b3052baf0f503381c606eee0be6be28f32` |
| SHA-256 | `7e68a50b160e0bff70caaeb40beed073420d49e7544deed275f5f935e64342db` |
| SHA3-384 | `8ee30766109d5309fbb54c491900d081688bd67a9ebd40ecec5159bebdf07d468e5555515a443c6dcd1af20427ef4654` |
| TLSH | `T14104551A3E22DFBBF56D827047F38920579876D636E19685F26CD70C1E2028E641F7E8` |
| TELFHASH | `t1054150180e7413f4a3756c8d1addff3a96a330db7a166d378e11e8aaa7699834d10c1c` |
| SSDEEP | `1536:uCuOizigcbnKw+rkKBcoesJy5QGY2Qu8TaSdoXYOGFvrbdHOjHR1:uCuzCbnKLr1Bcz5QywdjOGFvHdHOLR1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_7e68a50b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e68a50b160e0bff70caaeb40beed073420d49e7544deed275f5f935e64342db"
    family = "Mirai"
    file_name = "volar.mips"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:55"
  condition:
    hash.sha256(0, filesize) == "7e68a50b160e0bff70caaeb40beed073420d49e7544deed275f5f935e64342db"
}
```

### Sample 75: `a100f345ef9144f0`

| Field | Value |
|---|---|
| SHA-256 | `a100f345ef9144f03b9beb8341d47f4eaaf8a3fd7090c2414b4096ced17fb712` |
| Family label | `Mirai` |
| File name | `volar.m68k` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee71b10cbeab6604443252a31fed2925` |
| SHA-1 | `6573d9d93b3c977714934aa78affdcbd634ff27d` |
| SHA-256 | `a100f345ef9144f03b9beb8341d47f4eaaf8a3fd7090c2414b4096ced17fb712` |
| SHA3-384 | `61d68519fc7b1dfb1c7e3d00dde5b5fe789ef386d19f78c346f08b7c05aa5ef92581df839f110816b9932e0944df4d63` |
| TLSH | `T19FE3E6C7FD01DEB7F40AE37648A348157130FFA60D621A73722379AAEA390D51467E86` |
| SSDEEP | `3072:InVA2bFnorO66R/bLRa7SAOUpw0VxjbigLsFDXyu3En1E:yoy66RTLNZUG6L6Dyu4E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_a100f345
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a100f345ef9144f03b9beb8341d47f4eaaf8a3fd7090c2414b4096ced17fb712"
    family = "Mirai"
    file_name = "volar.m68k"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:54"
  condition:
    hash.sha256(0, filesize) == "a100f345ef9144f03b9beb8341d47f4eaaf8a3fd7090c2414b4096ced17fb712"
}
```

### Sample 76: `f014432085dddfca`

| Field | Value |
|---|---|
| SHA-256 | `f014432085dddfca9b50bb643db12d3d0d491209f7ebb50205247a3b4ae8ecb5` |
| Family label | `Mirai` |
| File name | `volar.armv5l` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ac87989f76ede9ae83d1bb376805d21` |
| SHA-1 | `760ab2a05db6897cc094cdef064853a98ee14d65` |
| SHA-256 | `f014432085dddfca9b50bb643db12d3d0d491209f7ebb50205247a3b4ae8ecb5` |
| SHA3-384 | `bd0616ffacef976eb546e45c4a5dcc4cabf23dfc85201cf5bfb05e555e7b8ea37f4ecbc3140f9766e61b9fb799a0015a` |
| TLSH | `T13BC3D846BD418F13C5C321F7FBDE42987E166B6DD6FA3202A9257FA037474D60A3A212` |
| TELFHASH | `t15bf07d688f8829fcf7d18504d5fe7349914460b58a510ca0f9de0b9f497349ea264115` |
| SSDEEP | `1536:l7p+fg7am28+zsn4V7Vm7lxIEBVsYYEGsv/R7WuloCwywlKaDyh2nUgmw1OY1squ:RYQam26n4TmpxIV+/ldZazwD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f0144320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f014432085dddfca9b50bb643db12d3d0d491209f7ebb50205247a3b4ae8ecb5"
    family = "Mirai"
    file_name = "volar.armv5l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:52"
  condition:
    hash.sha256(0, filesize) == "f014432085dddfca9b50bb643db12d3d0d491209f7ebb50205247a3b4ae8ecb5"
}
```

### Sample 77: `047b8f53b5e26d13`

| Field | Value |
|---|---|
| SHA-256 | `047b8f53b5e26d13f8656ef360642637cb19a51bc082933a5babc314c884e497` |
| Family label | `Mirai` |
| File name | `volar.x86_64` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca0f70d123b5c45764ff4f0b3377137a` |
| SHA-1 | `0bd43ebb9b03d540914e28ba48b758c2fd03c397` |
| SHA-256 | `047b8f53b5e26d13f8656ef360642637cb19a51bc082933a5babc314c884e497` |
| SHA3-384 | `12894af8b55d4c5614b51a82bacf36714fb77a1c02d0d57e64e05f99c66c2b6995a142e2053c89f9afb315220dc038c1` |
| TLSH | `T18A256C5BB2B370FCD467C13083ABCB626C36B42511212E7B65C4DA352E66D701B29FA7` |
| TELFHASH | `t1f2c18e745aea74b0a7dbd621b322f5759973153923dd36f05a32ad90ef00f804ca6c2b` |
| SSDEEP | `12288:9ybcN7uIyGXdkpy4G7/AR0Jx6R7z/k9DeYJY17QyW9rqIpaU:4bcN7uIyGXdkpy4G7/nxGv/28FI1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_047b8f53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "047b8f53b5e26d13f8656ef360642637cb19a51bc082933a5babc314c884e497"
    family = "Mirai"
    file_name = "volar.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:50"
  condition:
    hash.sha256(0, filesize) == "047b8f53b5e26d13f8656ef360642637cb19a51bc082933a5babc314c884e497"
}
```

### Sample 78: `4db94890194b749a`

| Field | Value |
|---|---|
| SHA-256 | `4db94890194b749a6c1a6cb77a102543cda3f5fbe488425835f3d197a8e3467d` |
| Family label | `Mirai` |
| File name | `volar.armv7l` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7207157b6f080be7379d88d3ead03ef9` |
| SHA-1 | `b12ae4f5dbff7d0f1c9ba3202efdc21a93121e9c` |
| SHA-256 | `4db94890194b749a6c1a6cb77a102543cda3f5fbe488425835f3d197a8e3467d` |
| SHA3-384 | `d602b283885969880ae166524bc61e59e299fca4198478f56d8482951f8b3da52907ce4fe6caacba3892370f3cb0b572` |
| TLSH | `T108B3E645A9419F11E4D731FAFB9F425833536FACE3F97101EA206F6123CAA9B0F66112` |
| SSDEEP | `3072:QRdvRInvptNtH+altG7Uud/ndz257DhmnKDW:QRdqvTNtH+altGZxdy57Dh+KDW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_4db94890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4db94890194b749a6c1a6cb77a102543cda3f5fbe488425835f3d197a8e3467d"
    family = "Mirai"
    file_name = "volar.armv7l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:48"
  condition:
    hash.sha256(0, filesize) == "4db94890194b749a6c1a6cb77a102543cda3f5fbe488425835f3d197a8e3467d"
}
```

### Sample 79: `f1ca4dfdb08bfe7f`

| Field | Value |
|---|---|
| SHA-256 | `f1ca4dfdb08bfe7f4ebb4c710098042713caf579ca47614fda6cf24ab82d582d` |
| Family label | `Mirai` |
| File name | `volar.armv6l` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce7ff8d7627c738ae018ace77a3b920e` |
| SHA-1 | `bcbb0a9cd79d596bc4d3c6640fba228b64422a21` |
| SHA-256 | `f1ca4dfdb08bfe7f4ebb4c710098042713caf579ca47614fda6cf24ab82d582d` |
| SHA3-384 | `231c8c91120da424e9c414ffcc9a6b5d53317f3d6cf41e8005f5ea64c61cc409f1c592efd37170d430190857629a7cfe` |
| TLSH | `T14FD3F906A941DF12D1C311B9FF5E42593B136F7CD3EE72029D24AFA0674A8EB0E7A116` |
| SSDEEP | `3072:xkYsLZ6Xj6XWYadnYqp3POEMLL0p0PVMETJG:xkf0XGX3adY0P/00p0PVjdG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_f1ca4dfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1ca4dfdb08bfe7f4ebb4c710098042713caf579ca47614fda6cf24ab82d582d"
    family = "Mirai"
    file_name = "volar.armv6l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:47"
  condition:
    hash.sha256(0, filesize) == "f1ca4dfdb08bfe7f4ebb4c710098042713caf579ca47614fda6cf24ab82d582d"
}
```

### Sample 80: `4e20ecc7c2c6cad3`

| Field | Value |
|---|---|
| SHA-256 | `4e20ecc7c2c6cad3af874398379b1c48026c4ecd3601fbeec48e15ca7e7dcd88` |
| Family label | `Mirai` |
| File name | `volar.powerpc-440fp` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `346f5d63f2e801ff944d6222845cee38` |
| SHA-1 | `5e807022545a833c99e521d74227451bf8b34e33` |
| SHA-256 | `4e20ecc7c2c6cad3af874398379b1c48026c4ecd3601fbeec48e15ca7e7dcd88` |
| SHA3-384 | `f65d9d3fd4dc47363673343774bca5d32a774e22e52aa5d042ff289fad92ccb6963bb419d2aca2f9a7f5a5018270c1c5` |
| TLSH | `T160C307027B0D4F03E1532DF4377B4BE1839BBD5628A9E680711AFEC993719B29506E8D` |
| SSDEEP | `1536:3IZ7Oi88s/uZxoqfN0rl9T+SQa00zmClrpRLrbvAMSnKPhzJtGrTqSYr/4:4Zrs/uZxzNolbQa0+lrDcMw2L4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_4e20ecc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e20ecc7c2c6cad3af874398379b1c48026c4ecd3601fbeec48e15ca7e7dcd88"
    family = "Mirai"
    file_name = "volar.powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:45"
  condition:
    hash.sha256(0, filesize) == "4e20ecc7c2c6cad3af874398379b1c48026c4ecd3601fbeec48e15ca7e7dcd88"
}
```

### Sample 81: `d9bc4a1cdc65f4da`

| Field | Value |
|---|---|
| SHA-256 | `d9bc4a1cdc65f4dabbdb00ce3583600093ec2a804b8cfd3276905523207346e8` |
| Family label | `Mirai` |
| File name | `volar.powerpc` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcbb4f100bb6dcb5b80d461668456cce` |
| SHA-1 | `65a908abc36e2a37fff383aa72ca99ca2fa2e522` |
| SHA-256 | `d9bc4a1cdc65f4dabbdb00ce3583600093ec2a804b8cfd3276905523207346e8` |
| SHA3-384 | `2d423298af098e234e72ccb2780a7968b94f6d67567b6ca614519e3656b45d98447aaea0216c8a49802545ae9534989c` |
| TLSH | `T188C30702770D4F43D1233EF03B7B1BE0979BFD5629A4A680742EBEC992719B21145EA9` |
| SSDEEP | `1536:A2fbC+aHFwCx0ODBbeLZZ9IP8KtXz8kGvAoSP8uBohvKOz0Bq321rZD:A2cHKCx/BadIHtxvoUX1dD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_d9bc4a1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9bc4a1cdc65f4dabbdb00ce3583600093ec2a804b8cfd3276905523207346e8"
    family = "Mirai"
    file_name = "volar.powerpc"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:43"
  condition:
    hash.sha256(0, filesize) == "d9bc4a1cdc65f4dabbdb00ce3583600093ec2a804b8cfd3276905523207346e8"
}
```

### Sample 82: `af49d43403a24c6d`

| Field | Value |
|---|---|
| SHA-256 | `af49d43403a24c6d6877ba376707960991f06c4f8836d2b3e0962fd4363b8e8b` |
| Family label | `Mirai` |
| File name | `volar.armv4l` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d0f9f6942c9f3e21c5f0d13091c1025` |
| SHA-1 | `0ee63d9ac0eabb217e1e9350382856ab418fc987` |
| SHA-256 | `af49d43403a24c6d6877ba376707960991f06c4f8836d2b3e0962fd4363b8e8b` |
| SHA3-384 | `2ace74f9700c394bace8c46b8e3381505acd1213a5ce649eaa69fdb1dda9d5a5802716b434232c94159e6d0ee63553a1` |
| TLSH | `T1F7C3E946BD418F13C5C321FBFBDE42987A166F6DD6FA3202A925BFA037474D6093A112` |
| TELFHASH | `t106f07d748f482afcf7d64884d6feb348461470b546410c70face1f5e4a6395aa25411a` |
| SSDEEP | `1536:yov7rQ78DQpG4V7VT7/XJII93IlPHs+35wDlx9wywL5TBznHR048O7z0MvzrQfR9:hvnQ75G4TTzXJefJCCzgRpD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_af49d434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af49d43403a24c6d6877ba376707960991f06c4f8836d2b3e0962fd4363b8e8b"
    family = "Mirai"
    file_name = "volar.armv4l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:42"
  condition:
    hash.sha256(0, filesize) == "af49d43403a24c6d6877ba376707960991f06c4f8836d2b3e0962fd4363b8e8b"
}
```

### Sample 83: `d87fa47e317a71d7`

| Field | Value |
|---|---|
| SHA-256 | `d87fa47e317a71d7780731282b6342917c04cff6c369f5e44caccab77b2c954d` |
| Family label | `Mirai` |
| File name | `volar.i586` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3af54771d00e0134a1ee18aaf66f8f0f` |
| SHA-1 | `17039de0cdf974c7e67fe322876d8330cab6423c` |
| SHA-256 | `d87fa47e317a71d7780731282b6342917c04cff6c369f5e44caccab77b2c954d` |
| SHA3-384 | `cbe5f89d69d74749bfa096994cc8b89e2c578b4729aa0b48a40a67c215b3db53fe273b87fafeb454df5419e9eec6e0ba` |
| TLSH | `T133A30686BB93DFB3E55310F501F74B324A32FD3A5826DA81E339BDA199551C0A61B338` |
| TELFHASH | `t1b06135e66ef508e8f3c05849d34e57a35b19da7b162171ab41f2394533e3b918272c39` |
| SSDEEP | `1536:K6HQFTcNQtKlOaMKvL3FXP8KAdfaWEXefHfJfT5tu0OqnX:K/2utK0lKvL3R8KgCO5j6S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_d87fa47e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d87fa47e317a71d7780731282b6342917c04cff6c369f5e44caccab77b2c954d"
    family = "Mirai"
    file_name = "volar.i586"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:40"
  condition:
    hash.sha256(0, filesize) == "d87fa47e317a71d7780731282b6342917c04cff6c369f5e44caccab77b2c954d"
}
```

### Sample 84: `c37be238d47d871d`

| Field | Value |
|---|---|
| SHA-256 | `c37be238d47d871db84c482f94f9a8859afe4b32b8d4a272387285cf9fc8ae3b` |
| Family label | `Mirai` |
| File name | `volar.mipsel` |
| File type | `elf` |
| First seen | `2026-07-18 19:00:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39f7500727580a537791ba184d7e72f1` |
| SHA-1 | `ae4e03c9088ca9ee20b533ba8e913091cedf6dba` |
| SHA-256 | `c37be238d47d871db84c482f94f9a8859afe4b32b8d4a272387285cf9fc8ae3b` |
| SHA3-384 | `072610b90b69bd3afb077e0f783980b4249cb63f5295f8b72cdbc8c254490e6d197e64afb889ed2f5c9415fb0fd31566` |
| TLSH | `T11804C6066F519EB7C86FDD7306F98A0128CCB45725643B7A3270DB6CB91A58B09E3CB4` |
| SSDEEP | `1536:ohbw/kSGOkDhXaWYQvxMs682kU3iC5a9NHiTUYZ+fIh9Xwoi7OnFaCTrnCMpczOz:oikS0DhqRQZMshiTXJtHFa+CUczOxJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_c37be238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c37be238d47d871db84c482f94f9a8859afe4b32b8d4a272387285cf9fc8ae3b"
    family = "Mirai"
    file_name = "volar.mipsel"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:38"
  condition:
    hash.sha256(0, filesize) == "c37be238d47d871db84c482f94f9a8859afe4b32b8d4a272387285cf9fc8ae3b"
}
```

### Sample 85: `67cd0abe451f8c0c`

| Field | Value |
|---|---|
| SHA-256 | `67cd0abe451f8c0c224f8bdb6a62355f926db7a7aa500ab95b2bb8bfe52408a9` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-18 18:58:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49f9810356fdfd73dc779ffa4b6eab0e` |
| SHA-1 | `4584d3e676857cc7ffb04ac7750dd1e91f48bcf7` |
| SHA-256 | `67cd0abe451f8c0c224f8bdb6a62355f926db7a7aa500ab95b2bb8bfe52408a9` |
| SHA3-384 | `d7b04c9d5e701e3776e3ac8da5265d2960f43e2c80e8cdb33cc7996ba801c4d0f38daadda27dce2648ac4c9226ab8229` |
| TLSH | `T17373085AFD40AF11E5D625BAFE4E414933534B6CE3EE7212AE209B2527CA91B0F3B405` |
| TELFHASH | `t163b012b183c61455b1d32643411c3611172c34ad7e9120a1171aa7d541830810100070` |
| SSDEEP | `1536:MdnqqleLClqjB2NDafp4E9AXy87llXHiGM6iLKSdtiZ1YHLprRP:K4CTNDafp4E9AXNPM6MKSbin8DP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_67cd0abe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67cd0abe451f8c0c224f8bdb6a62355f926db7a7aa500ab95b2bb8bfe52408a9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-18 18:58:15"
  condition:
    hash.sha256(0, filesize) == "67cd0abe451f8c0c224f8bdb6a62355f926db7a7aa500ab95b2bb8bfe52408a9"
}
```

### Sample 86: `72c4c6cbabad1ce3`

| Field | Value |
|---|---|
| SHA-256 | `72c4c6cbabad1ce385845dc85a9c602400b70378a8f75b0b564e6ea10491b4fe` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-18 18:58:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e68e85db632917b938dca7d9033c6c79` |
| SHA-1 | `ea03bf58a6f8cb8dfdbccb7cd8c333f6b6f88ca0` |
| SHA-256 | `72c4c6cbabad1ce385845dc85a9c602400b70378a8f75b0b564e6ea10491b4fe` |
| SHA3-384 | `01f4214f54dd2f09a43ecdbd8b927530a8e5e28488f4edb3fa38b929b4a9ddcddb51e4f92c54ef9b1d7ab4ab73b9f4b7` |
| TLSH | `T143331995FD41A602C6C155B7FF0F838D7726435CE2EE3303AA296B21378B86A0E3B541` |
| TELFHASH | `t19ab01230c2c45c3c3cf50063d9ab8133112d0c040ddc2221204f285e13c1ca581b3148` |
| SSDEEP | `768:J0ILfa667qlQH9GEqEwBQADNUTjOS+3MwIGEwVlknOgW/jPBIGh1vMeH6PQdljsA:xfUCQ7SSAmmITG9knOgIBbhi5QLgrRN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_72c4c6cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72c4c6cbabad1ce385845dc85a9c602400b70378a8f75b0b564e6ea10491b4fe"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-18 18:58:13"
  condition:
    hash.sha256(0, filesize) == "72c4c6cbabad1ce385845dc85a9c602400b70378a8f75b0b564e6ea10491b4fe"
}
```

### Sample 87: `dcf9ff0064a9aa01`

| Field | Value |
|---|---|
| SHA-256 | `dcf9ff0064a9aa018d389bf96c776e10a968abec34d3ff8f161441c13c6a0326` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-18 18:58:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26009797db8b54a6b68fdbdde6a1762e` |
| SHA-1 | `82793dfc1af79aaa1ef7847e668a87f86c3c1e68` |
| SHA-256 | `dcf9ff0064a9aa018d389bf96c776e10a968abec34d3ff8f161441c13c6a0326` |
| SHA3-384 | `d8c5dcbbb24955ca58917ed7dce154a182a1b63d5001f480f6c6131d566ae4fd68aead8ca947d3da1e235bba8fe4cf2f` |
| TLSH | `T162432955BD42A612C6C155BBFF0E438D7B27439CE2EA3303AE256F21378B46A0E3B551` |
| TELFHASH | `t19ab01230c2c45c3c3cf50063d9ab8133112d0c040ddc2221204f285e13c1ca581b3148` |
| SSDEEP | `1536:6fU2Q3ydHmQ2usFknOU5iThUiwNvhrRx:6DGQ2uynTSLx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_dcf9ff00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcf9ff0064a9aa018d389bf96c776e10a968abec34d3ff8f161441c13c6a0326"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 18:58:12"
  condition:
    hash.sha256(0, filesize) == "dcf9ff0064a9aa018d389bf96c776e10a968abec34d3ff8f161441c13c6a0326"
}
```

### Sample 88: `50ba9982d25df879`

| Field | Value |
|---|---|
| SHA-256 | `50ba9982d25df8797332c35d0c01a0df36a2057f41d3b18f3c553ecce715617e` |
| Family label | `Mirai` |
| File name | `manji.arm7` |
| File type | `elf` |
| First seen | `2026-07-18 18:55:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb67dd37123412fe0dde18630e667244` |
| SHA-1 | `bdeb80435cf921363e71160b5009387de5eaed06` |
| SHA-256 | `50ba9982d25df8797332c35d0c01a0df36a2057f41d3b18f3c553ecce715617e` |
| SHA3-384 | `1061a9dce6e2a082b03a9a9edb99401b3e821de098a6c226aaf64880e8adc9da5e74900775d2f6d5fc2b96aaa745873b` |
| TLSH | `T14EB30946A9429B11D5C631FAFBAF414933136FB8E3FA7111D9206F6023C69DB0E77612` |
| TELFHASH | `t14de0c002d71c18ec63c9801812fab228fc62f2a01c3426913f95ec9d9157995712dc35` |
| SSDEEP | `3072:pqiy9qVvpOFnQfG/7/0VZYPY9On5NaBF7h1uzagz8fBZI0cMbugf:pqiJKdQe/7/0VZYPCK5NaBF7h17gz8go` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_50ba9982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50ba9982d25df8797332c35d0c01a0df36a2057f41d3b18f3c553ecce715617e"
    family = "Mirai"
    file_name = "manji.arm7"
    file_type = "elf"
    first_seen = "2026-07-18 18:55:33"
  condition:
    hash.sha256(0, filesize) == "50ba9982d25df8797332c35d0c01a0df36a2057f41d3b18f3c553ecce715617e"
}
```

### Sample 89: `cd9ce9b42d1457bd`

| Field | Value |
|---|---|
| SHA-256 | `cd9ce9b42d1457bd6d15ca0f9c9c8590359cc321ff551a8ce6b04a0547c77625` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-18 18:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e42d183df6aae410eb878712965c2ed` |
| SHA-1 | `6d5f7dfc382eaf4dc532c95293f8909126d602f4` |
| SHA-256 | `cd9ce9b42d1457bd6d15ca0f9c9c8590359cc321ff551a8ce6b04a0547c77625` |
| SHA3-384 | `0d97fbaabd5c99ae54304736f6cd0b167bb4af432420f356bd21c7973ae74a28c8158ea2308380d2e03a0ef228ea857c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T13CE6331825E002FAE7B7403CADA250E8E564B4B40FB2CACF4794C6566D672F14E3D67B` |
| SSDEEP | `393216:JbsTAQNlCwceFafizpEWCgrjn97XMCHWUjXHcuI3/PGTAI:xsTAATFKePjn97XMb8X8H/O7` |
| ICON-DHASH | `70f0f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_cd9ce9b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd9ce9b42d1457bd6d15ca0f9c9c8590359cc321ff551a8ce6b04a0547c77625"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 18:52:10"
  condition:
    hash.sha256(0, filesize) == "cd9ce9b42d1457bd6d15ca0f9c9c8590359cc321ff551a8ce6b04a0547c77625"
}
```

### Sample 90: `ed6f6f2144998175`

| Field | Value |
|---|---|
| SHA-256 | `ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8` |
| Family label | `unknown` |
| File name | `ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8.bin` |
| File type | `unknown` |
| First seen | `2026-07-18 18:47:23` |
| Reporter | `whack` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54d14e2aba479693f9fd361a56d5f525` |
| SHA-256 | `ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_ed6f6f21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8"
    family = "unknown"
    file_name = "ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 18:47:23"
  condition:
    hash.sha256(0, filesize) == "ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8"
}
```

### Sample 91: `40df3e55e5962c49`

| Field | Value |
|---|---|
| SHA-256 | `40df3e55e5962c490ccfb5e2a245f6d5d78d4fdff3fdde2459eb1f81aeb786f2` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-18 18:46:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30b12818b8694b5271853c408e94ee48` |
| SHA-1 | `251c522cf26fa72e552aaac42dfe54e6d737d6ef` |
| SHA-256 | `40df3e55e5962c490ccfb5e2a245f6d5d78d4fdff3fdde2459eb1f81aeb786f2` |
| SHA3-384 | `f7a2f717791b928c7b3e6483c536c28e959ed147c878baa822e2302b5714b02404ce24c398ba083daa96521150201727` |
| TLSH | `T13FD32999F880DE52C6D12676FB5E118C33231778C3DE710ACE245E346BEBD5A0A7E942` |
| SSDEEP | `3072:ZBz7cJm0Jg6lcc14ns/5vVh5cYEEUO7QZ2m/HW2+lp7Plub+Zlf1Dl5:ZB/E7quX5cYEEUO7QZ2SHj+lzo2l955` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_40df3e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40df3e55e5962c490ccfb5e2a245f6d5d78d4fdff3fdde2459eb1f81aeb786f2"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-18 18:46:23"
  condition:
    hash.sha256(0, filesize) == "40df3e55e5962c490ccfb5e2a245f6d5d78d4fdff3fdde2459eb1f81aeb786f2"
}
```

### Sample 92: `aa6d7499fa9716e2`

| Field | Value |
|---|---|
| SHA-256 | `aa6d7499fa9716e23e6300969321e9ff97614249a39de6697554bf9d94103567` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-18 18:45:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1234ad68afb3d8c0ffd4960d53f952d7` |
| SHA-1 | `5c8ada5fa4ca0a483562215c607165cc62bfabe9` |
| SHA-256 | `aa6d7499fa9716e23e6300969321e9ff97614249a39de6697554bf9d94103567` |
| SHA3-384 | `9594f2e8448d6fa65311325859d247c63ea0f6196ec0dc04897da3892fd6912eabe62b4e99802f58b5bcddeb5b6d6c48` |
| TLSH | `T10343F1B053148E5DEB221C31C5F99E028B51937D594C22F50A16874DBB95C8EE3DBF8E` |
| SSDEEP | `1536:OY2StSuO8ksOgNdlK/MuESAxs9CU9DuL9XhEWbfM:O1ExfksO+lCMuELs9CtLxOe0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_aa6d7499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa6d7499fa9716e23e6300969321e9ff97614249a39de6697554bf9d94103567"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-18 18:45:41"
  condition:
    hash.sha256(0, filesize) == "aa6d7499fa9716e23e6300969321e9ff97614249a39de6697554bf9d94103567"
}
```

### Sample 93: `98253ed6c9bfb2f6`

| Field | Value |
|---|---|
| SHA-256 | `98253ed6c9bfb2f61fe97d17952f2b07c01bd64802d385fcd1c09a6384b06b30` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-07-18 18:40:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d4f3a84e36806c0036a41b6c6bdce17` |
| SHA-1 | `7a27aa6bca1682881eb02dd6e56afeeb2f2a1602` |
| SHA-256 | `98253ed6c9bfb2f61fe97d17952f2b07c01bd64802d385fcd1c09a6384b06b30` |
| SHA3-384 | `d13cc7f841aa8eef2186f80f0d0c1f45f3e114a41abc8ad7096bec91e5fbc5ce3ed457926312b7fa2040b83b726504d9` |
| TLSH | `T1D2B3198AB8816B25D2C326BBFE5F014E33574BA8D3EA72129D144F7077CA95B0E37605` |
| TELFHASH | `t14be06fa2e60f28ec0be8602780ca401e92fd70c83b192040dac96fabe846960f44c836` |
| SSDEEP | `3072:TMppCy1CKodLVCitmUeOV+JIG1/aXUj9f6hHx4u3n4Cw0:TM/3odYisUbMIc/aXUj9f6xxlp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_98253ed6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98253ed6c9bfb2f61fe97d17952f2b07c01bd64802d385fcd1c09a6384b06b30"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-18 18:40:55"
  condition:
    hash.sha256(0, filesize) == "98253ed6c9bfb2f61fe97d17952f2b07c01bd64802d385fcd1c09a6384b06b30"
}
```

### Sample 94: `9a3937779254885e`

| Field | Value |
|---|---|
| SHA-256 | `9a3937779254885ea9e033003615445122558e7b3c4d18b638f60e6e4686466a` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-18 18:36:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03e3679e761222def61af0dccf32fb97` |
| SHA-1 | `472b25abda0c798463f5fc66732fab0e84372c19` |
| SHA-256 | `9a3937779254885ea9e033003615445122558e7b3c4d18b638f60e6e4686466a` |
| SHA3-384 | `a1e6cf663a9a289191c76770345a34151e63c80151e0ac5bd939a30c64e102de06b479a3cfd72155b42a52f0f35893a4` |
| TLSH | `T1D863D60AEF510EFBC86FDE3705A90B0631CC955722B83B3A3574D928F55A54B4AE3C68` |
| SSDEEP | `1536:11ygeSrDBmgmwdb5ysNv6qPtPPhQaIxrzfrRCb:11ygSkb5ylwJAVCb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_9a393777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a3937779254885ea9e033003615445122558e7b3c4d18b638f60e6e4686466a"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 18:36:23"
  condition:
    hash.sha256(0, filesize) == "9a3937779254885ea9e033003615445122558e7b3c4d18b638f60e6e4686466a"
}
```

### Sample 95: `9264d342f207b8a9`

| Field | Value |
|---|---|
| SHA-256 | `9264d342f207b8a9233c393b864c26617385071283b030ec6b6976069d91a587` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-18 18:30:57` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX1.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ab0732a85899cb205f645e969d0b4b8` |
| SHA-1 | `50cba914311bba28c423bbc11d499b429b1b64ff` |
| SHA-256 | `9264d342f207b8a9233c393b864c26617385071283b030ec6b6976069d91a587` |
| SHA3-384 | `631782ef40438ee2478cda12df6f42944984f251f11f438d0c73372cbe480a6dff707381b80aea020826235f775813bc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T10DD54A47FCA148F6C099A335C9A79642BB75BC081B3623D72EA0BB782E727D05D79710` |
| SSDEEP | `49152:spiUixi6ZrYNc8RpkJuodLn6gc8RNsFkqKAc:sp7vUF7c8RNG` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_095_9264d342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9264d342f207b8a9233c393b864c26617385071283b030ec6b6976069d91a587"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 18:30:57"
  condition:
    hash.sha256(0, filesize) == "9264d342f207b8a9233c393b864c26617385071283b030ec6b6976069d91a587"
}
```

### Sample 96: `72344facd02bea90`

| Field | Value |
|---|---|
| SHA-256 | `72344facd02bea9007c59c2a67bd96d521838b566298caf0f80c6ceecf93520f` |
| Family label | `HijackLoader` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-18 18:30:05` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, HijackLoader, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f238406f5cd53942450f145e1c977476` |
| SHA-1 | `fb7cd49f47060a8514fe5c358bb2a9f74eb215f4` |
| SHA-256 | `72344facd02bea9007c59c2a67bd96d521838b566298caf0f80c6ceecf93520f` |
| SHA3-384 | `4c31d4b50282df0fac92b6ec48ccdf64f53fcb9121557edddcece31c9895b157a2833174248300da306ce38658763fd7` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T19F663303B7875071E47295BA48A7C0516E3778BC2FE8D04D3D75C24CAC7AA05ADBA7A3` |
| SSDEEP | `98304:lFdWd/ry9xZ5zd+5p52hlTo5x3uS2HaSqCGK82mE/G2tIG4hcDzGTkvIs04Lx34d:lj9xl+Emxk/TlmE/BSSzGT+9od` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `HijackLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_HijackLoader_096_72344fac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72344facd02bea9007c59c2a67bd96d521838b566298caf0f80c6ceecf93520f"
    family = "HijackLoader"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 18:30:05"
  condition:
    hash.sha256(0, filesize) == "72344facd02bea9007c59c2a67bd96d521838b566298caf0f80c6ceecf93520f"
}
```

### Sample 97: `c16f7856cae36b5c`

| Field | Value |
|---|---|
| SHA-256 | `c16f7856cae36b5c59f80368c1132b7f45564368671ca58a6da40846f18d3848` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-18 18:29:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b56f0f1828e54cb0cb6ece90a735b697` |
| SHA-1 | `fc5064692858e133bda71fd9795f5022c2294692` |
| SHA-256 | `c16f7856cae36b5c59f80368c1132b7f45564368671ca58a6da40846f18d3848` |
| SHA3-384 | `455502bfda834126a6c767000a83c105445d607296f565c9c246e2827d4103642caae371bceae86b1e4295591624efce` |
| TLSH | `T193236C46BB43E0B6F95712B610BBA7164732F93500B9EB46CF256D31ED13601A72B3AC` |
| TELFHASH | `t19131c3e13e6108fcf392ac4ec71e56939f1995735661a4be04f92b823bf21758160921` |
| SSDEEP | `768:0hrJo/gSS8PeKUjgT8vtjssMiAuPoS4Z18dJoyaYfH+WJcSpaIMp:0Y13GKUIEtDPp4ZeJDRcSpa7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_c16f7856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c16f7856cae36b5c59f80368c1132b7f45564368671ca58a6da40846f18d3848"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-18 18:29:23"
  condition:
    hash.sha256(0, filesize) == "c16f7856cae36b5c59f80368c1132b7f45564368671ca58a6da40846f18d3848"
}
```

### Sample 98: `1324d15db1d78343`

| Field | Value |
|---|---|
| SHA-256 | `1324d15db1d78343bf88928fade641a0ae022d1a6d3464645d35b7cc1058c3aa` |
| Family label | `Mirai` |
| File name | `tarm` |
| File type | `elf` |
| First seen | `2026-07-18 18:18:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53c76d3bfc39477ac013fe34e1e4e152` |
| SHA-1 | `fd9d3a170e6eb92043ca7d30658e94d677f24632` |
| SHA-256 | `1324d15db1d78343bf88928fade641a0ae022d1a6d3464645d35b7cc1058c3aa` |
| SHA3-384 | `9e71dcb8b40d25d3aa29d0122dfef4253ff01785b5bf984d6116d1ff7ec048502e126ee0d238d244ec476281d93565f2` |
| TLSH | `T1FA9329C4B841A622C6D2127BFE5F018D376657E8D2EA3307CD291FA1738A96B0D37716` |
| TELFHASH | `t1e4519eaafb601f9d2bda016591cf70165ffc359d1f1538a28a2dab4fc446641702d827` |
| SSDEEP | `1536:KmgEgdUa6uyULJYLaQQq0716ba2dSAVfIkGGHtYov9oy8DoMvEgwBD:KmgEgdUa6uyULJY7Qq056cIf5GyGoez+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_1324d15d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1324d15db1d78343bf88928fade641a0ae022d1a6d3464645d35b7cc1058c3aa"
    family = "Mirai"
    file_name = "tarm"
    file_type = "elf"
    first_seen = "2026-07-18 18:18:23"
  condition:
    hash.sha256(0, filesize) == "1324d15db1d78343bf88928fade641a0ae022d1a6d3464645d35b7cc1058c3aa"
}
```

### Sample 99: `28c333433d226048`

| Field | Value |
|---|---|
| SHA-256 | `28c333433d22604881ac9c0c7521f7e673988dbe056d97d3d0597e0abb80d819` |
| Family label | `Mirai` |
| File name | `gIP` |
| File type | `elf` |
| First seen | `2026-07-18 18:13:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `293f9cb946b1540a74312033f9af3e28` |
| SHA-1 | `30b2574f7305ef274f86d634758adf4c5b532f0d` |
| SHA-256 | `28c333433d22604881ac9c0c7521f7e673988dbe056d97d3d0597e0abb80d819` |
| SHA3-384 | `6cab7a746fe56591ab31510a6827a49aaf037139d9d3b32da3309273ce0d689e08c1cd338fc1bedf1095c6c308f0e799` |
| TLSH | `T13E63F86BB9418F19C5C1267AFE1D934E331327BCE3DEB213DE142B65278B56B0E2A405` |
| TELFHASH | `t19801ce304a8659dc9bd0c10b12ef1246551cf2f133201d6db7e9dadb95c3469f31642d` |
| SSDEEP | `1536:FWnNRuxGj4uKKnrCj80gnIWlexzDq3VqHsJZA2LIiw9XyrHcYdaF:ARuxGjLxrg8t2/QqHsvLy9XyrHp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_28c33343
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c333433d22604881ac9c0c7521f7e673988dbe056d97d3d0597e0abb80d819"
    family = "Mirai"
    file_name = "gIP"
    file_type = "elf"
    first_seen = "2026-07-18 18:13:57"
  condition:
    hash.sha256(0, filesize) == "28c333433d22604881ac9c0c7521f7e673988dbe056d97d3d0597e0abb80d819"
}
```

### Sample 100: `19242a87d17e1a5b`

| Field | Value |
|---|---|
| SHA-256 | `19242a87d17e1a5bc37d00762371e72b9dfdff2cf338cdf13e39ecd142e5e17e` |
| Family label | `unknown` |
| File name | `LXZk` |
| File type | `elf` |
| First seen | `2026-07-18 18:13:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49f6ec7e6063a24b392718dec110d0c9` |
| SHA-1 | `aad7411548995691e057ba5302356a23710c905c` |
| SHA-256 | `19242a87d17e1a5bc37d00762371e72b9dfdff2cf338cdf13e39ecd142e5e17e` |
| SHA3-384 | `f1b4d4a463d655e5cd49029777326319fe9aa290c10dea5c905a824f5d27f40f419e4fa285e715194fb11efe4ce38f51` |
| TLSH | `T1A2A3B60E2E61DF6CF369823497B78B34A65C63D12BD1D684D1ACD6012E7034E681F7BA` |
| TELFHASH | `t12e31e919493813f4d3b11e8c6aeefb72e09174df6a261e378f11e9aade1e9419d10c1c` |
| SSDEEP | `1536:+k5CrLNfBctuWrEe2JBT6lPQfyNFdOckLoZjZ/Ep5Plg4fyqHx4ONNaW6y6MG:QLKEe2JBT6l8jctZjZCdg2R+9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_19242a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19242a87d17e1a5bc37d00762371e72b9dfdff2cf338cdf13e39ecd142e5e17e"
    family = "unknown"
    file_name = "LXZk"
    file_type = "elf"
    first_seen = "2026-07-18 18:13:56"
  condition:
    hash.sha256(0, filesize) == "19242a87d17e1a5bc37d00762371e72b9dfdff2cf338cdf13e39ecd142e5e17e"
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
 * Generated: 2026-07-19T03:59:43.101466+00:00
 */

rule MalwareBazaar_unknown_001_71d5fabd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71d5fabdd8b478089e543ab6a6e92fa1bcf822ca095ee9ace7789e665c495dec"
    family = "unknown"
    file_name = "DeltaExecutor.exe"
    file_type = "exe"
    first_seen = "2026-07-19 03:52:30"
  condition:
    hash.sha256(0, filesize) == "71d5fabdd8b478089e543ab6a6e92fa1bcf822ca095ee9ace7789e665c495dec"
}

rule MalwareBazaar_unknown_002_38452489
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38452489fd072aa7fedd7a3e61ea37ed2b41efca30bc589b268f6525cf3019c2"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 03:52:09"
  condition:
    hash.sha256(0, filesize) == "38452489fd072aa7fedd7a3e61ea37ed2b41efca30bc589b268f6525cf3019c2"
}

rule MalwareBazaar_MaskGramStealer_003_19ee106f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19ee106f5490826e09271022d24b27a0586a48c5c9db4a55a63320bafcbb8342"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 03:44:56"
  condition:
    hash.sha256(0, filesize) == "19ee106f5490826e09271022d24b27a0586a48c5c9db4a55a63320bafcbb8342"
}

rule MalwareBazaar_unknown_004_ee5b4f0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81"
    family = "unknown"
    file_name = "ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81"
    file_type = "elf"
    first_seen = "2026-07-19 03:30:32"
  condition:
    hash.sha256(0, filesize) == "ee5b4f0f96155f0e6d93d7816e26c54b64c230d8af0397eecb99039cff844b81"
}

rule MalwareBazaar_unknown_005_cc2ba5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc2ba5d5272e640a2ec9caeca2f92cb4606c84bd5c0b9a394b960879b28a7e9a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 02:52:09"
  condition:
    hash.sha256(0, filesize) == "cc2ba5d5272e640a2ec9caeca2f92cb4606c84bd5c0b9a394b960879b28a7e9a"
}

rule MalwareBazaar_unknown_006_8c582d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c582d4d3d953bdcd6a9956a2d928bc3af0889b73b19b8e573743840f92e35e0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-19 02:06:28"
  condition:
    hash.sha256(0, filesize) == "8c582d4d3d953bdcd6a9956a2d928bc3af0889b73b19b8e573743840f92e35e0"
}

rule MalwareBazaar_unknown_007_a3adc3ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3adc3ba9fb493396d33ad6b5c49aabc27c3d95d42451636c501b5f6b1a431a3"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-19 02:00:10"
  condition:
    hash.sha256(0, filesize) == "a3adc3ba9fb493396d33ad6b5c49aabc27c3d95d42451636c501b5f6b1a431a3"
}

rule MalwareBazaar_unknown_008_205fec03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205fec0325df0ef40fdccdffd525cd3a27f26c8a37eff09ab4e1341f32963f56"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-19 01:54:09"
  condition:
    hash.sha256(0, filesize) == "205fec0325df0ef40fdccdffd525cd3a27f26c8a37eff09ab4e1341f32963f56"
}

rule MalwareBazaar_unknown_009_23e44f95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23e44f9545eccc2fa95f563995118008826e64ead3844a6ecc6b50592a55dd37"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 01:52:08"
  condition:
    hash.sha256(0, filesize) == "23e44f9545eccc2fa95f563995118008826e64ead3844a6ecc6b50592a55dd37"
}

rule MalwareBazaar_unknown_010_50f055e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50f055e3b6662ff9f81a04eef52092b644f1617b9d0d9e6bc3f1f1deca01e3a9"
    family = "unknown"
    file_name = "riscv"
    file_type = "elf"
    first_seen = "2026-07-19 01:45:23"
  condition:
    hash.sha256(0, filesize) == "50f055e3b6662ff9f81a04eef52092b644f1617b9d0d9e6bc3f1f1deca01e3a9"
}

rule MalwareBazaar_unknown_011_64f2828e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715"
    family = "unknown"
    file_name = "64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715"
    file_type = "exe"
    first_seen = "2026-07-19 01:15:30"
  condition:
    hash.sha256(0, filesize) == "64f2828e5e89e4bc6ca46d799d6140f2fae9a0db324caecf74d39d785cdf8715"
}

rule MalwareBazaar_unknown_012_fbfa869a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbfa869a9d6e624a4134e6c44baef0987d0c09f4b9be3ec95295f77599e4f566"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-19 00:52:09"
  condition:
    hash.sha256(0, filesize) == "fbfa869a9d6e624a4134e6c44baef0987d0c09f4b9be3ec95295f77599e4f566"
}

rule MalwareBazaar_unknown_013_c60861d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60861d98b3aa236c215d5ce2a4ec571c2ec8a8503dfb57472eb2d3cbc6e6c04"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:30:38"
  condition:
    hash.sha256(0, filesize) == "c60861d98b3aa236c215d5ce2a4ec571c2ec8a8503dfb57472eb2d3cbc6e6c04"
}

rule MalwareBazaar_unknown_014_92a629ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a629ea255b2deff884e40577915f56665508defdfe78cfb85c6a12dfe1fdc0"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:20:40"
  condition:
    hash.sha256(0, filesize) == "92a629ea255b2deff884e40577915f56665508defdfe78cfb85c6a12dfe1fdc0"
}

rule MalwareBazaar_WannaCry_015_5fc07750
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df"
    family = "WannaCry"
    file_name = "5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df"
    file_type = "exe"
    first_seen = "2026-07-19 00:15:31"
  condition:
    hash.sha256(0, filesize) == "5fc07750ace241e22a7d63a5d5aff50815e975aa0084c285ccc7c514c58c09df"
}

rule MalwareBazaar_unknown_016_342a2753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "342a2753d8a86364f26b67552bea963470412d8342ed6e71560fabc07b32999f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:06:51"
  condition:
    hash.sha256(0, filesize) == "342a2753d8a86364f26b67552bea963470412d8342ed6e71560fabc07b32999f"
}

rule MalwareBazaar_unknown_017_650cbbc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "650cbbc9cce1761c658b98dd7e2d7aff2532e9d04e1056a1c44a61652406b104"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:04:52"
  condition:
    hash.sha256(0, filesize) == "650cbbc9cce1761c658b98dd7e2d7aff2532e9d04e1056a1c44a61652406b104"
}

rule MalwareBazaar_unknown_018_0df61c7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0df61c7d4a7b90b9e859c8ade8abbdf2bafd395b5d05ad7d8807284ccedb82f8"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-19 00:04:50"
  condition:
    hash.sha256(0, filesize) == "0df61c7d4a7b90b9e859c8ade8abbdf2bafd395b5d05ad7d8807284ccedb82f8"
}

rule MalwareBazaar_unknown_019_896ae0ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896ae0ba6b9686c9ff56a7455f72be69289ee55ab0e2aae9168cb7f5baa01817"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-19 00:02:51"
  condition:
    hash.sha256(0, filesize) == "896ae0ba6b9686c9ff56a7455f72be69289ee55ab0e2aae9168cb7f5baa01817"
}

rule MalwareBazaar_unknown_020_2c4f1c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59"
    family = "unknown"
    file_name = "2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59"
    file_type = "exe"
    first_seen = "2026-07-19 00:02:33"
  condition:
    hash.sha256(0, filesize) == "2c4f1c37a25f687ddeca3bae95ab1449da75c5612ec820977f695bf072909d59"
}

rule MalwareBazaar_unknown_021_fec4f767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fec4f7679f9ab5ec9f5cf4f3702e52fd085a4ac9306acd9a62b7c088b6605208"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 23:52:09"
  condition:
    hash.sha256(0, filesize) == "fec4f7679f9ab5ec9f5cf4f3702e52fd085a4ac9306acd9a62b7c088b6605208"
}

rule MalwareBazaar_unknown_022_fd4a088e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4a088e691cf191050f9551aaf616ea04ba60d1cbbbd71022731aa5db3ef2e6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 22:52:08"
  condition:
    hash.sha256(0, filesize) == "fd4a088e691cf191050f9551aaf616ea04ba60d1cbbbd71022731aa5db3ef2e6"
}

rule MalwareBazaar_Arechclient2_023_4a96a4b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a96a4b4cece7a576ec22780a49294c8ebbec0b1f546ac48b50708690a7250c9"
    family = "Arechclient2"
    file_name = "jquery.uo.js.zip"
    file_type = "zip"
    first_seen = "2026-07-18 21:19:12"
  condition:
    hash.sha256(0, filesize) == "4a96a4b4cece7a576ec22780a49294c8ebbec0b1f546ac48b50708690a7250c9"
}

rule MalwareBazaar_unknown_024_254fff0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254fff0fabd0b47ae67cc9e45539e2c7de33bee70e5e2e951d4db215f74af676"
    family = "unknown"
    file_name = "jquery.min.js.zip"
    file_type = "zip"
    first_seen = "2026-07-18 21:17:59"
  condition:
    hash.sha256(0, filesize) == "254fff0fabd0b47ae67cc9e45539e2c7de33bee70e5e2e951d4db215f74af676"
}

rule MalwareBazaar_unknown_025_68444cab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68444caba536c78572538d6c7886b69820f22319e7616532d20069da6ac2775b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 21:10:58"
  condition:
    hash.sha256(0, filesize) == "68444caba536c78572538d6c7886b69820f22319e7616532d20069da6ac2775b"
}

rule MalwareBazaar_unknown_026_b7f7d8aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f7d8aa57f70f6042b6b52fedef3eac4ee3d401e4d1f706aabd2af122b8eed6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 20:53:06"
  condition:
    hash.sha256(0, filesize) == "b7f7d8aa57f70f6042b6b52fedef3eac4ee3d401e4d1f706aabd2af122b8eed6"
}

rule MalwareBazaar_unknown_027_cb336a6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06"
    family = "unknown"
    file_name = "setup_patched.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:46:32"
  condition:
    hash.sha256(0, filesize) == "cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06"
}

rule MalwareBazaar_unknown_028_5fbed74e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-18 20:45:55"
  condition:
    hash.sha256(0, filesize) == "5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165"
}

rule MalwareBazaar_unknown_029_7c9a7614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8"
    family = "unknown"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-07-18 20:43:59"
  condition:
    hash.sha256(0, filesize) == "7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8"
}

rule MalwareBazaar_Stealc_030_5679dcdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5679dcddde61ea4ea8ee5199339ba059940b1257211fcf95c80d1d5b4063e85a"
    family = "Stealc"
    file_name = "FLStudio2025 Crack_patched.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:42:03"
  condition:
    hash.sha256(0, filesize) == "5679dcddde61ea4ea8ee5199339ba059940b1257211fcf95c80d1d5b4063e85a"
}

rule MalwareBazaar_Stealc_031_4e97683e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e97683e5e7935915b26a1e5b036ea1d6ae2b1a9b5f1830a4e2acb68275589a1"
    family = "Stealc"
    file_name = "FLStudio2025.zip"
    file_type = "zip"
    first_seen = "2026-07-18 20:41:06"
  condition:
    hash.sha256(0, filesize) == "4e97683e5e7935915b26a1e5b036ea1d6ae2b1a9b5f1830a4e2acb68275589a1"
}

rule MalwareBazaar_Vidar_032_3769b472
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3769b472782adfa0897d722918ad7c43dd8e9f19734b87bed9f3768866b7f119"
    family = "Vidar"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:39:40"
  condition:
    hash.sha256(0, filesize) == "3769b472782adfa0897d722918ad7c43dd8e9f19734b87bed9f3768866b7f119"
}

rule MalwareBazaar_unknown_033_87436ab3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87436ab32d87fd80d2dfed7232b9f75cd06d771de11e2623d0ae5d350c4dbc3f"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:39:03"
  condition:
    hash.sha256(0, filesize) == "87436ab32d87fd80d2dfed7232b9f75cd06d771de11e2623d0ae5d350c4dbc3f"
}

rule MalwareBazaar_unknown_034_7502ed39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7502ed3956c621d9442e51343a9d9fd22fb080d1a9edcffc1386901ebb4da9ec"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:38:11"
  condition:
    hash.sha256(0, filesize) == "7502ed3956c621d9442e51343a9d9fd22fb080d1a9edcffc1386901ebb4da9ec"
}

rule MalwareBazaar_RemusStealer_035_a2ca3144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2ca31441dec4d9a0d5895c0b2cc3fa9fb77928e91d4b8b0e14d189de62a977e"
    family = "RemusStealer"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-07-18 20:36:16"
  condition:
    hash.sha256(0, filesize) == "a2ca31441dec4d9a0d5895c0b2cc3fa9fb77928e91d4b8b0e14d189de62a977e"
}

rule MalwareBazaar_unknown_036_d0ff931a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0ff931a901854514c8afb8305293deee95a33627615cbf727f500f89531fd6e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 20:13:22"
  condition:
    hash.sha256(0, filesize) == "d0ff931a901854514c8afb8305293deee95a33627615cbf727f500f89531fd6e"
}

rule MalwareBazaar_Mirai_037_1ad7dfd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ad7dfd90e4928dcf285956e5fa3af23f14d7166d8deca9b82ab26532e734894"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-18 20:07:58"
  condition:
    hash.sha256(0, filesize) == "1ad7dfd90e4928dcf285956e5fa3af23f14d7166d8deca9b82ab26532e734894"
}

rule MalwareBazaar_Mirai_038_44c18a72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44c18a7290c4e03daa4e22478bfb946c68bf49696394c0b587af76645fbae6b2"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-18 20:07:38"
  condition:
    hash.sha256(0, filesize) == "44c18a7290c4e03daa4e22478bfb946c68bf49696394c0b587af76645fbae6b2"
}

rule MalwareBazaar_Mirai_039_12f403c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12f403c241fe472d840be10776e24d78613401efa752e523e9892253f18eb73f"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 19:57:39"
  condition:
    hash.sha256(0, filesize) == "12f403c241fe472d840be10776e24d78613401efa752e523e9892253f18eb73f"
}

rule MalwareBazaar_Mirai_040_a4d9ff95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4d9ff95947ec0aee0aa0344cc7c41076b1474a613ed8eb995c5ce52cc4dc77a"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 19:57:12"
  condition:
    hash.sha256(0, filesize) == "a4d9ff95947ec0aee0aa0344cc7c41076b1474a613ed8eb995c5ce52cc4dc77a"
}

rule MalwareBazaar_unknown_041_0cc4b3d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cc4b3d85067560d977bd3db51484d2073dc07eab3115b0d606214e6666e86e9"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-18 19:57:11"
  condition:
    hash.sha256(0, filesize) == "0cc4b3d85067560d977bd3db51484d2073dc07eab3115b0d606214e6666e86e9"
}

rule MalwareBazaar_Mirai_042_d6bb2dc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6bb2dc0431405c4158cc15ed0171fd3a53986bc79149ada27dec7b1edcf5b14"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-18 19:57:10"
  condition:
    hash.sha256(0, filesize) == "d6bb2dc0431405c4158cc15ed0171fd3a53986bc79149ada27dec7b1edcf5b14"
}

rule MalwareBazaar_unknown_043_de2242d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de2242d7b25c7129db2db9d37c4d3b10388769a9d69c02ed24df4d9375ae9bfd"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:52:19"
  condition:
    hash.sha256(0, filesize) == "de2242d7b25c7129db2db9d37c4d3b10388769a9d69c02ed24df4d9375ae9bfd"
}

rule MalwareBazaar_unknown_044_c481200a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c481200a9404e919fd2510f78ca1a119ce563dcaccd96329eef495eb664af2f3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 19:52:11"
  condition:
    hash.sha256(0, filesize) == "c481200a9404e919fd2510f78ca1a119ce563dcaccd96329eef495eb664af2f3"
}

rule MalwareBazaar_RemusStealer_045_7f9abea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9abea59adaab023f9c023f315d41e2599246d660569a72d12fd7298facd30d"
    family = "RemusStealer"
    file_name = "setup_euone.bin"
    file_type = "exe"
    first_seen = "2026-07-18 19:52:07"
  condition:
    hash.sha256(0, filesize) == "7f9abea59adaab023f9c023f315d41e2599246d660569a72d12fd7298facd30d"
}

rule MalwareBazaar_unknown_046_82b541e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82b541e29a8413e1453ebc9323ce37fd86d02bc108b7c9fbe877c49ffe19ae4a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 19:42:38"
  condition:
    hash.sha256(0, filesize) == "82b541e29a8413e1453ebc9323ce37fd86d02bc108b7c9fbe877c49ffe19ae4a"
}

rule MalwareBazaar_unknown_047_cc794f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc794f7ab2405917722c4f093695bfc9a4b5f0c43e83b807e11078f235c0f20d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 19:37:50"
  condition:
    hash.sha256(0, filesize) == "cc794f7ab2405917722c4f093695bfc9a4b5f0c43e83b807e11078f235c0f20d"
}

rule MalwareBazaar_unknown_048_8fde35bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fde35bc9d65dbe298daaa2cf8d720b452bc3f1d0596d58a6380819a704ccfe6"
    family = "unknown"
    file_name = "_up.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:34:02"
  condition:
    hash.sha256(0, filesize) == "8fde35bc9d65dbe298daaa2cf8d720b452bc3f1d0596d58a6380819a704ccfe6"
}

rule MalwareBazaar_ValleyRAT_049_0a3061ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a3061ce09d7e3cb2b3d3453432da69ee83b59b782853d1f6462fd177db75a7a"
    family = "ValleyRAT"
    file_name = "WindowsUpdate.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:30:05"
  condition:
    hash.sha256(0, filesize) == "0a3061ce09d7e3cb2b3d3453432da69ee83b59b782853d1f6462fd177db75a7a"
}

rule MalwareBazaar_Mirai_050_b81541b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81541b461d90fd82a6f15db387b00d4562556c6880be44daae581ad8857696b"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-18 19:28:43"
  condition:
    hash.sha256(0, filesize) == "b81541b461d90fd82a6f15db387b00d4562556c6880be44daae581ad8857696b"
}

rule MalwareBazaar_Mirai_051_807ff5f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "807ff5f5f8287af5e32bc184dffff438f87e856b207d5860f7d2d6fc95a8b5bb"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-18 19:28:12"
  condition:
    hash.sha256(0, filesize) == "807ff5f5f8287af5e32bc184dffff438f87e856b207d5860f7d2d6fc95a8b5bb"
}

rule MalwareBazaar_unknown_052_5d8b4b81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b"
    family = "unknown"
    file_name = "5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:28:05"
  condition:
    hash.sha256(0, filesize) == "5d8b4b815ac2ebb4a9bedeee389ed591daf60a7105556cf3c1fd585b18b0456b"
}

rule MalwareBazaar_unknown_053_d5558cd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"
    family = "unknown"
    file_name = "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:27:41"
  condition:
    hash.sha256(0, filesize) == "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"
}

rule MalwareBazaar_unknown_054_5ca42bef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590"
    family = "unknown"
    file_name = "5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:27:04"
  condition:
    hash.sha256(0, filesize) == "5ca42befc2a4171bdb0936c1d4153e6da8fd527a42b83b2eef78c3366f6e9590"
}

rule MalwareBazaar_unknown_055_acff38c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd"
    family = "unknown"
    file_name = "acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:56"
  condition:
    hash.sha256(0, filesize) == "acff38c20f19afa1c3318528dc1ba6d262f10870f95e053a4908c2a66889d8fd"
}

rule MalwareBazaar_unknown_056_e9639e3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80"
    family = "unknown"
    file_name = "e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:26:53"
  condition:
    hash.sha256(0, filesize) == "e9639e3c4681ce85f852fbac48e2eeee5ba51296dbfec57c200d59b76237ab80"
}

rule MalwareBazaar_unknown_057_28484ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a"
    family = "unknown"
    file_name = "28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 19:26:50"
  condition:
    hash.sha256(0, filesize) == "28484ae186b36505be08ca8d04e35b3662a63ffe9e74a929e62711ecdde5b95a"
}

rule MalwareBazaar_unknown_058_3c285c3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360"
    family = "unknown"
    file_name = "3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:42"
  condition:
    hash.sha256(0, filesize) == "3c285c3fd881cc3bfa5796593310c80844ce3c85cb4b8c033b8d4c033a0a7360"
}

rule MalwareBazaar_unknown_059_c767bb6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861"
    family = "unknown"
    file_name = "c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:38"
  condition:
    hash.sha256(0, filesize) == "c767bb6b6dd0b149e46b7066269b6d9fac1f9eb2dcafcec59475fd78a8af7861"
}

rule MalwareBazaar_unknown_060_10660030
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7"
    family = "unknown"
    file_name = "1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:26:22"
  condition:
    hash.sha256(0, filesize) == "1066003052bf79de8ab4f07bb7ff3dc980a8622b9175ef714a6df5dd01d517b7"
}

rule MalwareBazaar_NanoCore_061_c1d7ce92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07"
    family = "NanoCore"
    file_name = "036227aa4ccacd6153de68143e02f001.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:25:06"
  condition:
    hash.sha256(0, filesize) == "c1d7ce9290ee9a148ea430871f900a44511b8db374dedcb4d417072b54e48d07"
}

rule MalwareBazaar_unknown_062_2e0cc1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e0cc1e150d44c19a28246ad632d71efeae39ce1a71ff32be4707b2fb8303360"
    family = "unknown"
    file_name = "KL-2026.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:24:46"
  condition:
    hash.sha256(0, filesize) == "2e0cc1e150d44c19a28246ad632d71efeae39ce1a71ff32be4707b2fb8303360"
}

rule MalwareBazaar_Gh0stRAT_063_6aa982f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aa982f7c6167752e8f58083dc5f1c11ff0aa63b3c3d2e192009cce2cef84ee0"
    family = "Gh0stRAT"
    file_name = "3DQQey.exe"
    file_type = "exe"
    first_seen = "2026-07-18 19:23:53"
  condition:
    hash.sha256(0, filesize) == "6aa982f7c6167752e8f58083dc5f1c11ff0aa63b3c3d2e192009cce2cef84ee0"
}

rule MalwareBazaar_Mirai_064_ae017c8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae017c8e2745db9dbc72190fa6ef481fcaee17624ef75aa3dee317e1774783d3"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-18 19:21:19"
  condition:
    hash.sha256(0, filesize) == "ae017c8e2745db9dbc72190fa6ef481fcaee17624ef75aa3dee317e1774783d3"
}

rule MalwareBazaar_Mirai_065_67a84e06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67a84e063171340de0b552334aa72b1760bbcc699acda2251d8c89cc5bdb6019"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-18 19:20:28"
  condition:
    hash.sha256(0, filesize) == "67a84e063171340de0b552334aa72b1760bbcc699acda2251d8c89cc5bdb6019"
}

rule MalwareBazaar_Mirai_066_e3fbfb71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fbfb7116690c986c33431e4609270793a4ad77e231bf69a804c276cc6b3de8"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 19:14:39"
  condition:
    hash.sha256(0, filesize) == "e3fbfb7116690c986c33431e4609270793a4ad77e231bf69a804c276cc6b3de8"
}

rule MalwareBazaar_Mirai_067_74647c51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74647c51a6559b61360585913586b1631a09a262112a132c2b094bbbdbf58393"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 19:13:09"
  condition:
    hash.sha256(0, filesize) == "74647c51a6559b61360585913586b1631a09a262112a132c2b094bbbdbf58393"
}

rule MalwareBazaar_Mirai_068_a450ac18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a450ac18a22635a97910c4ac7e1320d091429a94838d21560a41e134748bc3a7"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-18 19:12:43"
  condition:
    hash.sha256(0, filesize) == "a450ac18a22635a97910c4ac7e1320d091429a94838d21560a41e134748bc3a7"
}

rule MalwareBazaar_Mirai_069_849980ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849980ecdf9d5d0ea16f373c017f5aea16de2f91a0f56bcaf618c4fa4570dfb6"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-18 19:10:17"
  condition:
    hash.sha256(0, filesize) == "849980ecdf9d5d0ea16f373c017f5aea16de2f91a0f56bcaf618c4fa4570dfb6"
}

rule MalwareBazaar_unknown_070_531ee667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "531ee66757ef12a35e430ca9bc723e1076a7242968f16925028bae0786505f5b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-18 19:06:54"
  condition:
    hash.sha256(0, filesize) == "531ee66757ef12a35e430ca9bc723e1076a7242968f16925028bae0786505f5b"
}

rule MalwareBazaar_unknown_071_ec4d064a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec4d064aad177bbdbe3eddbc4b884732f66ee9233737888822423521ad0a19d2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 19:02:15"
  condition:
    hash.sha256(0, filesize) == "ec4d064aad177bbdbe3eddbc4b884732f66ee9233737888822423521ad0a19d2"
}

rule MalwareBazaar_Mirai_072_de9f7cef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de9f7cef593d14d92502e907a7a4db73ffc2e5304c81183a853bc2e400ee5852"
    family = "Mirai"
    file_name = "volar.sh4"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:58"
  condition:
    hash.sha256(0, filesize) == "de9f7cef593d14d92502e907a7a4db73ffc2e5304c81183a853bc2e400ee5852"
}

rule MalwareBazaar_Mirai_073_fbf8926b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbf8926b091c0eb3f58e6ad7a483f44c14ba27aed05e9bdfe779d2bae490c39f"
    family = "Mirai"
    file_name = "volar.i686"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:57"
  condition:
    hash.sha256(0, filesize) == "fbf8926b091c0eb3f58e6ad7a483f44c14ba27aed05e9bdfe779d2bae490c39f"
}

rule MalwareBazaar_Mirai_074_7e68a50b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e68a50b160e0bff70caaeb40beed073420d49e7544deed275f5f935e64342db"
    family = "Mirai"
    file_name = "volar.mips"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:55"
  condition:
    hash.sha256(0, filesize) == "7e68a50b160e0bff70caaeb40beed073420d49e7544deed275f5f935e64342db"
}

rule MalwareBazaar_Mirai_075_a100f345
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a100f345ef9144f03b9beb8341d47f4eaaf8a3fd7090c2414b4096ced17fb712"
    family = "Mirai"
    file_name = "volar.m68k"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:54"
  condition:
    hash.sha256(0, filesize) == "a100f345ef9144f03b9beb8341d47f4eaaf8a3fd7090c2414b4096ced17fb712"
}

rule MalwareBazaar_Mirai_076_f0144320
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f014432085dddfca9b50bb643db12d3d0d491209f7ebb50205247a3b4ae8ecb5"
    family = "Mirai"
    file_name = "volar.armv5l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:52"
  condition:
    hash.sha256(0, filesize) == "f014432085dddfca9b50bb643db12d3d0d491209f7ebb50205247a3b4ae8ecb5"
}

rule MalwareBazaar_Mirai_077_047b8f53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "047b8f53b5e26d13f8656ef360642637cb19a51bc082933a5babc314c884e497"
    family = "Mirai"
    file_name = "volar.x86_64"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:50"
  condition:
    hash.sha256(0, filesize) == "047b8f53b5e26d13f8656ef360642637cb19a51bc082933a5babc314c884e497"
}

rule MalwareBazaar_Mirai_078_4db94890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4db94890194b749a6c1a6cb77a102543cda3f5fbe488425835f3d197a8e3467d"
    family = "Mirai"
    file_name = "volar.armv7l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:48"
  condition:
    hash.sha256(0, filesize) == "4db94890194b749a6c1a6cb77a102543cda3f5fbe488425835f3d197a8e3467d"
}

rule MalwareBazaar_Mirai_079_f1ca4dfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1ca4dfdb08bfe7f4ebb4c710098042713caf579ca47614fda6cf24ab82d582d"
    family = "Mirai"
    file_name = "volar.armv6l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:47"
  condition:
    hash.sha256(0, filesize) == "f1ca4dfdb08bfe7f4ebb4c710098042713caf579ca47614fda6cf24ab82d582d"
}

rule MalwareBazaar_Mirai_080_4e20ecc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e20ecc7c2c6cad3af874398379b1c48026c4ecd3601fbeec48e15ca7e7dcd88"
    family = "Mirai"
    file_name = "volar.powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:45"
  condition:
    hash.sha256(0, filesize) == "4e20ecc7c2c6cad3af874398379b1c48026c4ecd3601fbeec48e15ca7e7dcd88"
}

rule MalwareBazaar_Mirai_081_d9bc4a1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9bc4a1cdc65f4dabbdb00ce3583600093ec2a804b8cfd3276905523207346e8"
    family = "Mirai"
    file_name = "volar.powerpc"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:43"
  condition:
    hash.sha256(0, filesize) == "d9bc4a1cdc65f4dabbdb00ce3583600093ec2a804b8cfd3276905523207346e8"
}

rule MalwareBazaar_Mirai_082_af49d434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af49d43403a24c6d6877ba376707960991f06c4f8836d2b3e0962fd4363b8e8b"
    family = "Mirai"
    file_name = "volar.armv4l"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:42"
  condition:
    hash.sha256(0, filesize) == "af49d43403a24c6d6877ba376707960991f06c4f8836d2b3e0962fd4363b8e8b"
}

rule MalwareBazaar_Mirai_083_d87fa47e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d87fa47e317a71d7780731282b6342917c04cff6c369f5e44caccab77b2c954d"
    family = "Mirai"
    file_name = "volar.i586"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:40"
  condition:
    hash.sha256(0, filesize) == "d87fa47e317a71d7780731282b6342917c04cff6c369f5e44caccab77b2c954d"
}

rule MalwareBazaar_Mirai_084_c37be238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c37be238d47d871db84c482f94f9a8859afe4b32b8d4a272387285cf9fc8ae3b"
    family = "Mirai"
    file_name = "volar.mipsel"
    file_type = "elf"
    first_seen = "2026-07-18 19:00:38"
  condition:
    hash.sha256(0, filesize) == "c37be238d47d871db84c482f94f9a8859afe4b32b8d4a272387285cf9fc8ae3b"
}

rule MalwareBazaar_Mirai_085_67cd0abe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67cd0abe451f8c0c224f8bdb6a62355f926db7a7aa500ab95b2bb8bfe52408a9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-18 18:58:15"
  condition:
    hash.sha256(0, filesize) == "67cd0abe451f8c0c224f8bdb6a62355f926db7a7aa500ab95b2bb8bfe52408a9"
}

rule MalwareBazaar_Mirai_086_72c4c6cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72c4c6cbabad1ce385845dc85a9c602400b70378a8f75b0b564e6ea10491b4fe"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-18 18:58:13"
  condition:
    hash.sha256(0, filesize) == "72c4c6cbabad1ce385845dc85a9c602400b70378a8f75b0b564e6ea10491b4fe"
}

rule MalwareBazaar_Mirai_087_dcf9ff00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcf9ff0064a9aa018d389bf96c776e10a968abec34d3ff8f161441c13c6a0326"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-18 18:58:12"
  condition:
    hash.sha256(0, filesize) == "dcf9ff0064a9aa018d389bf96c776e10a968abec34d3ff8f161441c13c6a0326"
}

rule MalwareBazaar_Mirai_088_50ba9982
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50ba9982d25df8797332c35d0c01a0df36a2057f41d3b18f3c553ecce715617e"
    family = "Mirai"
    file_name = "manji.arm7"
    file_type = "elf"
    first_seen = "2026-07-18 18:55:33"
  condition:
    hash.sha256(0, filesize) == "50ba9982d25df8797332c35d0c01a0df36a2057f41d3b18f3c553ecce715617e"
}

rule MalwareBazaar_unknown_089_cd9ce9b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd9ce9b42d1457bd6d15ca0f9c9c8590359cc321ff551a8ce6b04a0547c77625"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-18 18:52:10"
  condition:
    hash.sha256(0, filesize) == "cd9ce9b42d1457bd6d15ca0f9c9c8590359cc321ff551a8ce6b04a0547c77625"
}

rule MalwareBazaar_unknown_090_ed6f6f21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8"
    family = "unknown"
    file_name = "ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8.bin"
    file_type = "unknown"
    first_seen = "2026-07-18 18:47:23"
  condition:
    hash.sha256(0, filesize) == "ed6f6f2144998175c846a99d2a0faab5bf7b6ace318f0fe2dc4bfeaf4700c1d8"
}

rule MalwareBazaar_Mirai_091_40df3e55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40df3e55e5962c490ccfb5e2a245f6d5d78d4fdff3fdde2459eb1f81aeb786f2"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-18 18:46:23"
  condition:
    hash.sha256(0, filesize) == "40df3e55e5962c490ccfb5e2a245f6d5d78d4fdff3fdde2459eb1f81aeb786f2"
}

rule MalwareBazaar_Mirai_092_aa6d7499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa6d7499fa9716e23e6300969321e9ff97614249a39de6697554bf9d94103567"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-18 18:45:41"
  condition:
    hash.sha256(0, filesize) == "aa6d7499fa9716e23e6300969321e9ff97614249a39de6697554bf9d94103567"
}

rule MalwareBazaar_Mirai_093_98253ed6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98253ed6c9bfb2f61fe97d17952f2b07c01bd64802d385fcd1c09a6384b06b30"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-07-18 18:40:55"
  condition:
    hash.sha256(0, filesize) == "98253ed6c9bfb2f61fe97d17952f2b07c01bd64802d385fcd1c09a6384b06b30"
}

rule MalwareBazaar_Mirai_094_9a393777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a3937779254885ea9e033003615445122558e7b3c4d18b638f60e6e4686466a"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-18 18:36:23"
  condition:
    hash.sha256(0, filesize) == "9a3937779254885ea9e033003615445122558e7b3c4d18b638f60e6e4686466a"
}

rule MalwareBazaar_RemusStealer_095_9264d342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9264d342f207b8a9233c393b864c26617385071283b030ec6b6976069d91a587"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 18:30:57"
  condition:
    hash.sha256(0, filesize) == "9264d342f207b8a9233c393b864c26617385071283b030ec6b6976069d91a587"
}

rule MalwareBazaar_HijackLoader_096_72344fac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72344facd02bea9007c59c2a67bd96d521838b566298caf0f80c6ceecf93520f"
    family = "HijackLoader"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-18 18:30:05"
  condition:
    hash.sha256(0, filesize) == "72344facd02bea9007c59c2a67bd96d521838b566298caf0f80c6ceecf93520f"
}

rule MalwareBazaar_Mirai_097_c16f7856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c16f7856cae36b5c59f80368c1132b7f45564368671ca58a6da40846f18d3848"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-18 18:29:23"
  condition:
    hash.sha256(0, filesize) == "c16f7856cae36b5c59f80368c1132b7f45564368671ca58a6da40846f18d3848"
}

rule MalwareBazaar_Mirai_098_1324d15d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1324d15db1d78343bf88928fade641a0ae022d1a6d3464645d35b7cc1058c3aa"
    family = "Mirai"
    file_name = "tarm"
    file_type = "elf"
    first_seen = "2026-07-18 18:18:23"
  condition:
    hash.sha256(0, filesize) == "1324d15db1d78343bf88928fade641a0ae022d1a6d3464645d35b7cc1058c3aa"
}

rule MalwareBazaar_Mirai_099_28c33343
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c333433d22604881ac9c0c7521f7e673988dbe056d97d3d0597e0abb80d819"
    family = "Mirai"
    file_name = "gIP"
    file_type = "elf"
    first_seen = "2026-07-18 18:13:57"
  condition:
    hash.sha256(0, filesize) == "28c333433d22604881ac9c0c7521f7e673988dbe056d97d3d0597e0abb80d819"
}

rule MalwareBazaar_unknown_100_19242a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19242a87d17e1a5bc37d00762371e72b9dfdff2cf338cdf13e39ecd142e5e17e"
    family = "unknown"
    file_name = "LXZk"
    file_type = "elf"
    first_seen = "2026-07-18 18:13:56"
  condition:
    hash.sha256(0, filesize) == "19242a87d17e1a5bc37d00762371e72b9dfdff2cf338cdf13e39ecd142e5e17e"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

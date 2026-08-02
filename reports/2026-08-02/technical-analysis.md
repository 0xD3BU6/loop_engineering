# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-02

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 507 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 507 |
| Unique family labels | 7 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 48 |
| Mirai | 47 |
| njrat | 1 |
| WannaCry | 1 |
| CoinMiner | 1 |
| NanoCore | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 47 |
| exe | 43 |
| sh | 8 |
| xapk | 1 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `dc87cc13bad5c4cc`

| Field | Value |
|---|---|
| SHA-256 | `dc87cc13bad5c4cc715ace4737ac6f303994a68ec8a772067da9765d642e1b28` |
| Family label | `unknown` |
| File name | `Launcher.exe` |
| File type | `exe` |
| First seen | `2026-08-02 03:19:48` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91912c07e3b6893dc8113e77b0923309` |
| SHA-1 | `eed9618dd94b86fe10990521889cabbedc6ea329` |
| SHA-256 | `dc87cc13bad5c4cc715ace4737ac6f303994a68ec8a772067da9765d642e1b28` |
| SHA3-384 | `5ed381da74e122514795370bb20e1d7cbe721866c79852b330e743f65d99f4d9fd307a15b9cf8af4716971b75ff74d8d` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T17308339403D69A9AC28BAFFD127F0FD3AD5A6EA0725D90BF03168432F1D546BC58D04B` |
| SSDEEP | `1572864:ALdkgowUngb6LtGKXpIMFIABZI48z2Fi/S8JKBUmy+N5Xe6EfB777:A29ng6LQK5BaABZVPArg/bXeB777` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_dc87cc13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc87cc13bad5c4cc715ace4737ac6f303994a68ec8a772067da9765d642e1b28"
    family = "unknown"
    file_name = "Launcher.exe"
    file_type = "exe"
    first_seen = "2026-08-02 03:19:48"
  condition:
    hash.sha256(0, filesize) == "dc87cc13bad5c4cc715ace4737ac6f303994a68ec8a772067da9765d642e1b28"
}
```

### Sample 2: `068fa74e4843dd0a`

| Field | Value |
|---|---|
| SHA-256 | `068fa74e4843dd0a7fd1488f262281e9b6b0e19d67eb8d52b20d63fda158fd3e` |
| Family label | `unknown` |
| File name | `Loader 9.0.11.exe` |
| File type | `exe` |
| First seen | `2026-08-02 02:45:17` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b81cbcc057d46aa660722301d59efb5` |
| SHA-1 | `96ff9e92dc4d60b8f00d743e0d2614fbff612788` |
| SHA-256 | `068fa74e4843dd0a7fd1488f262281e9b6b0e19d67eb8d52b20d63fda158fd3e` |
| SHA3-384 | `12f1216902b7d62d86f82a7e8fbac24b98c6ea3e974e1fd62aa846ef58a933a07235d2c4855eab0954cc5d8054cc3e39` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16BC6CF03ECA105E9C0A9E23589669653BB717C484B3527D73BA0F7382F76BD0AE79740` |
| SSDEEP | `196608:KID6ZjzrBZgrXnbxnV6mrRBVXeVTZy+YYs5V6:KID6ZDBirrtV6mFBVXeVly+Zs5V6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_068fa74e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "068fa74e4843dd0a7fd1488f262281e9b6b0e19d67eb8d52b20d63fda158fd3e"
    family = "unknown"
    file_name = "Loader 9.0.11.exe"
    file_type = "exe"
    first_seen = "2026-08-02 02:45:17"
  condition:
    hash.sha256(0, filesize) == "068fa74e4843dd0a7fd1488f262281e9b6b0e19d67eb8d52b20d63fda158fd3e"
}
```

### Sample 3: `4d70c592117d8714`

| Field | Value |
|---|---|
| SHA-256 | `4d70c592117d87144a826f81b53227f2756fa93015ea251050418b7f28bfa449` |
| Family label | `Mirai` |
| File name | `morte.x86_64` |
| File type | `elf` |
| First seen | `2026-08-02 02:18:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed08687f974a1a19e3b8f76d1a7340d3` |
| SHA-1 | `6fd1a3d6e9b4f0b7c90f88371abf3049ff8d5e21` |
| SHA-256 | `4d70c592117d87144a826f81b53227f2756fa93015ea251050418b7f28bfa449` |
| SHA3-384 | `b9e6f96ca02850f3860b641dce151ce8a8c2b1ad1fd916d26a169f83a26fc6b13345114004fefe2a0ca0fcf5d1086122` |
| TLSH | `T185B34B03B9C28DFDC046C034437FBA36D925F0EE1639B29B27F5EE266D0EE610A19955` |
| TELFHASH | `t1342168703cce39e820d79738b25eeea5e57104210dd17da99d6b6ea9df0ab444c82085` |
| SSDEEP | `3072:vEWK3B33zFmdUXAeJ+4gJeXzAt+lLnuJTjtOEV/YGkYGR:vEWK3R3hm2XAeJ+4gJeXZuxjpQO8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_4d70c592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d70c592117d87144a826f81b53227f2756fa93015ea251050418b7f28bfa449"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 02:18:29"
  condition:
    hash.sha256(0, filesize) == "4d70c592117d87144a826f81b53227f2756fa93015ea251050418b7f28bfa449"
}
```

### Sample 4: `ab901b2408ef3910`

| Field | Value |
|---|---|
| SHA-256 | `ab901b2408ef39103a2b44eccb0dd49a6fe3ba895a2f00e0fb0cc9e71890739c` |
| Family label | `Mirai` |
| File name | `morte.x86_64` |
| File type | `elf` |
| First seen | `2026-08-02 02:17:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69967cb243a863a0c8071189186dc969` |
| SHA-1 | `c8cfb8796fc0dbf34c3a151ad1961aeeab458fc8` |
| SHA-256 | `ab901b2408ef39103a2b44eccb0dd49a6fe3ba895a2f00e0fb0cc9e71890739c` |
| SHA3-384 | `ad476d511c624b562b41639574f617d64eaf645623987080700d6d24e0d01b96e5096bc530553bbed3634945d339c3a9` |
| TLSH | `T12723F1B1C97FEFB0D439B8F18C486B8478ED655F5713875D249422A81EBBE205C12EE2` |
| SSDEEP | `768:3DbdXXjWo86KJKMIw1tV+qWts83xxLFUGlkQNzEi/dyq49ld8N0sLFx05u:3DbdUbR5VAtt3349ldm5Au` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_ab901b24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab901b2408ef39103a2b44eccb0dd49a6fe3ba895a2f00e0fb0cc9e71890739c"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 02:17:48"
  condition:
    hash.sha256(0, filesize) == "ab901b2408ef39103a2b44eccb0dd49a6fe3ba895a2f00e0fb0cc9e71890739c"
}
```

### Sample 5: `21d8e211fab58567`

| Field | Value |
|---|---|
| SHA-256 | `21d8e211fab585677e0cf843c6ec41f0718b8f5ef32aae102d57b2a5e078b0ab` |
| Family label | `Mirai` |
| File name | `zero.mipsel` |
| File type | `elf` |
| First seen | `2026-08-02 02:15:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28868fd3d425b25c984f22855e311c1e` |
| SHA-1 | `663c38062e1f08fd1b6c924b095d59abf2b79d07` |
| SHA-256 | `21d8e211fab585677e0cf843c6ec41f0718b8f5ef32aae102d57b2a5e078b0ab` |
| SHA3-384 | `241e9c5514526d0ffcb8c4ef75ac8af8c46856ee5fec631b045a239fccc7b5e38b2c012944b1a3b2ea7eb861929812e6` |
| TLSH | `T1B624EA0AAFA21EBBD8BFDE3305D9070538CC544722A57B397674C928F50EA4B5AD3C64` |
| SSDEEP | `3072:ARz+86yRSMqPAnpGl4SpWhVClJH/4Y3WYC:ARz+hiSMqPAElLpWnCX/40WY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_21d8e211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d8e211fab585677e0cf843c6ec41f0718b8f5ef32aae102d57b2a5e078b0ab"
    family = "Mirai"
    file_name = "zero.mipsel"
    file_type = "elf"
    first_seen = "2026-08-02 02:15:48"
  condition:
    hash.sha256(0, filesize) == "21d8e211fab585677e0cf843c6ec41f0718b8f5ef32aae102d57b2a5e078b0ab"
}
```

### Sample 6: `5ce18989a7bdc921`

| Field | Value |
|---|---|
| SHA-256 | `5ce18989a7bdc92129e04ccee765ff3b1edcc3f0f7f08dc5f6755958b5a70d87` |
| Family label | `Mirai` |
| File name | `zero.mipsel` |
| File type | `elf` |
| First seen | `2026-08-02 02:15:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dae117de34af609ce1c10aa6aa762632` |
| SHA-1 | `e03bf38c520709fe59aea4ca7068ecf7557a4de0` |
| SHA-256 | `5ce18989a7bdc92129e04ccee765ff3b1edcc3f0f7f08dc5f6755958b5a70d87` |
| SHA3-384 | `679f74a69cc3881853e1a61ff7af00b0b2c7db870035a0bf350b8a22bdc3bc5772e85c79c8c0585d048d7a202ad16756` |
| TLSH | `T15353F1D9DDEBFC2BC92E6DF981B86F28785840597CC6DBDFA3104A48D528B0DB029065` |
| SSDEEP | `1536:11daLQpNtfDuePWu5dw9Jfz1+m5i+1cflqJAzdw:MQpN5oSk+P+y8ezi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_5ce18989
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce18989a7bdc92129e04ccee765ff3b1edcc3f0f7f08dc5f6755958b5a70d87"
    family = "Mirai"
    file_name = "zero.mipsel"
    file_type = "elf"
    first_seen = "2026-08-02 02:15:15"
  condition:
    hash.sha256(0, filesize) == "5ce18989a7bdc92129e04ccee765ff3b1edcc3f0f7f08dc5f6755958b5a70d87"
}
```

### Sample 7: `a51580aade05f548`

| Field | Value |
|---|---|
| SHA-256 | `a51580aade05f548b87eaf1dd98e4004330dbdcd8822a6405588944c57a8d33a` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-02 02:15:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bf1b48138aecfd39dd241f7f515578a` |
| SHA-1 | `418469b90afbade1081e050b10a0a23ad90f3302` |
| SHA-256 | `a51580aade05f548b87eaf1dd98e4004330dbdcd8822a6405588944c57a8d33a` |
| SHA3-384 | `c95a49c1de8692d14d95cdebb23738d357062f5d32ee652923356a2d1120dfbd1be509ea51cf01c8ee947d34b78e8efe` |
| TLSH | `T19B016BC693649910801A995E22E651E1FC31C3C7254E4F787F9C682DABDCE14F16BF98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaxMmF2AFuN1i0Xsj7d/tTlGN7:e9Qp+MsxvF2AIwPjhtTlM7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_a51580aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a51580aade05f548b87eaf1dd98e4004330dbdcd8822a6405588944c57a8d33a"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-02 02:15:14"
  condition:
    hash.sha256(0, filesize) == "a51580aade05f548b87eaf1dd98e4004330dbdcd8822a6405588944c57a8d33a"
}
```

### Sample 8: `736e09c587ec9320`

| Field | Value |
|---|---|
| SHA-256 | `736e09c587ec9320b96517f32378c1e8770ad15490d72a5113a8a62040a82166` |
| Family label | `Mirai` |
| File name | `zero.sparc` |
| File type | `elf` |
| First seen | `2026-08-02 02:12:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0aa6b428b61c90d4295fa729ff95baea` |
| SHA-1 | `bfda8a99beadc4704f768604c08be7f7f4226422` |
| SHA-256 | `736e09c587ec9320b96517f32378c1e8770ad15490d72a5113a8a62040a82166` |
| SHA3-384 | `decea1797975b142eaa070f660c9abbfdc0fa528fbd6dc88ba058f4ab9b6fddd0311559c1a288e41f06aac3e0136828c` |
| TLSH | `T16963B61AEE786A26C5D0217604E34911E97263ED1BBCA68F7EA72C0DDD15360303DEDE` |
| TELFHASH | `t133e06801ecbd475c89e79a74cc9c06a0d402222290670f20df00d9e4c83f450f308d9a` |
| SSDEEP | `1536:ULDN+d8b7oiAENci0npZ1PsJY2hEEeFCu0cRlDd:ULxOENcX1PsJYQc1d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_736e09c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "736e09c587ec9320b96517f32378c1e8770ad15490d72a5113a8a62040a82166"
    family = "Mirai"
    file_name = "zero.sparc"
    file_type = "elf"
    first_seen = "2026-08-02 02:12:30"
  condition:
    hash.sha256(0, filesize) == "736e09c587ec9320b96517f32378c1e8770ad15490d72a5113a8a62040a82166"
}
```

### Sample 9: `420dc609a9852388`

| Field | Value |
|---|---|
| SHA-256 | `420dc609a9852388f9bf158e1fb7aa73032fbd7090e8217df1af504d613af30c` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-08-02 02:11:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4b8aabe7d0636beb834053f87aecfd9` |
| SHA-1 | `98caab35ee49bd4e459cdbaaa4b4863e6915ef15` |
| SHA-256 | `420dc609a9852388f9bf158e1fb7aa73032fbd7090e8217df1af504d613af30c` |
| SHA3-384 | `a8c1c52d84b135bf203448cd7ec431c1dec9e5a55b50bd265f38f6a70170f49d444977ac079d684327292b7c656c389a` |
| TLSH | `T13DD02EA2A06341B010928810F6D69800B184D36F4C55C619FA9354302F10284F0C93B8` |
| SSDEEP | `6:hTNpF5S7x1cnN3FIvCFpAulNXYq9DG+NjVsNXYrkJ:VNrM7xobIOpPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_420dc609
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420dc609a9852388f9bf158e1fb7aa73032fbd7090e8217df1af504d613af30c"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-08-02 02:11:17"
  condition:
    hash.sha256(0, filesize) == "420dc609a9852388f9bf158e1fb7aa73032fbd7090e8217df1af504d613af30c"
}
```

### Sample 10: `7f49a17645cd8394`

| Field | Value |
|---|---|
| SHA-256 | `7f49a17645cd8394dca58c67cb6c5ee810291f51111c632d67fb5d9c82bd1820` |
| Family label | `Mirai` |
| File name | `morte.m68k` |
| File type | `elf` |
| First seen | `2026-08-02 02:05:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8e85cd9815e053b13ad568a6b479db0` |
| SHA-1 | `4229b4f1c749e030bbf7f5cb847c82a2a19d1ad9` |
| SHA-256 | `7f49a17645cd8394dca58c67cb6c5ee810291f51111c632d67fb5d9c82bd1820` |
| SHA3-384 | `49d4ffc72cc5af20766e9f2ee93ec4e1612e5d1874130c90df2e9a05b966334276071b264186728f23545893594fd04c` |
| TLSH | `T100C33CCAB802CE7DF90FD5B644630D0AB935A3A156C31F26625BFDD3AD321A4BC12D85` |
| SSDEEP | `3072:WNU2AOGhTyN2r1YUgBUqzh3H1NWxM/R/bw:wUTOGhTyN2VUFV3VNlR/bw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_7f49a176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f49a17645cd8394dca58c67cb6c5ee810291f51111c632d67fb5d9c82bd1820"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-08-02 02:05:26"
  condition:
    hash.sha256(0, filesize) == "7f49a17645cd8394dca58c67cb6c5ee810291f51111c632d67fb5d9c82bd1820"
}
```

### Sample 11: `c7bfdeeffd0c9c3b`

| Field | Value |
|---|---|
| SHA-256 | `c7bfdeeffd0c9c3bbcb017caa8c57ef83ddfb9743209c33099c08a1389f66698` |
| Family label | `Mirai` |
| File name | `zero.powerpc` |
| File type | `elf` |
| First seen | `2026-08-02 02:04:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d32dffccefccfe6742a66f732a53257` |
| SHA-1 | `969d1d266ff273742106f90583c6b689a999f7f8` |
| SHA-256 | `c7bfdeeffd0c9c3bbcb017caa8c57ef83ddfb9743209c33099c08a1389f66698` |
| SHA3-384 | `34976cac0eb2177d489d61e24ac2cf9e3061f8dc0fbc0b7ba88a53d68abec504b1ec87e937f61a21860832681db2b316` |
| TLSH | `T1ECF33B05734C004BE2A71EF03A3F6BE597EFDA9131F4A541295F9B4A8171A322986FCD` |
| SSDEEP | `1536:DRXrhoUlsUXqdbDGLXw9+K5TZLqxRRPvWn4lvpH/Vf1eqAvAAO0VA/6z0dTpfMzc:DRX3ad3EXw9+OLqx6wH9f7A0dAvE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_c7bfdeef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7bfdeeffd0c9c3bbcb017caa8c57ef83ddfb9743209c33099c08a1389f66698"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-08-02 02:04:30"
  condition:
    hash.sha256(0, filesize) == "c7bfdeeffd0c9c3bbcb017caa8c57ef83ddfb9743209c33099c08a1389f66698"
}
```

### Sample 12: `fe95a35a549a6e17`

| Field | Value |
|---|---|
| SHA-256 | `fe95a35a549a6e1783f30a0727ad1b7823f7607775a34865336752a266ed304a` |
| Family label | `Mirai` |
| File name | `zero.powerpc` |
| File type | `elf` |
| First seen | `2026-08-02 02:03:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `876a2bcddcc21ac6a66ceffc437a77bd` |
| SHA-1 | `2620989e757f48c39f8cb49facc0a8836b7c9cd4` |
| SHA-256 | `fe95a35a549a6e1783f30a0727ad1b7823f7607775a34865336752a266ed304a` |
| SHA3-384 | `ca1c87fdfe064e6466f46b16bed3b0f5239222d60fae896b4ca90eb9eba4c67f85cd51492ad990464c7a4498bcc68a9c` |
| TLSH | `T13443F2DD78C90DD9FFA79BBECD43C9C13B65C5ED17C59AD83390B2409507A889A02CA8` |
| SSDEEP | `1536:oB9+SWw8JddOQNtrXEMgiQIytRdbeyJZt4u+qgw09P:oTkw8L9EMyIKRdbeKZt4u+qgwi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_fe95a35a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe95a35a549a6e1783f30a0727ad1b7823f7607775a34865336752a266ed304a"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-08-02 02:03:33"
  condition:
    hash.sha256(0, filesize) == "fe95a35a549a6e1783f30a0727ad1b7823f7607775a34865336752a266ed304a"
}
```

### Sample 13: `78238dfbb4da6c6d`

| Field | Value |
|---|---|
| SHA-256 | `78238dfbb4da6c6d8c04ba930deea29807c11d25e30bfd07e73d363603e57648` |
| Family label | `Mirai` |
| File name | `morte.mips` |
| File type | `elf` |
| First seen | `2026-08-02 02:01:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2850bed410f3ef5bdd143567666c867e` |
| SHA-1 | `e1dcdb4a96cb80bb4f5c18a5a252698130a9c0d2` |
| SHA-256 | `78238dfbb4da6c6d8c04ba930deea29807c11d25e30bfd07e73d363603e57648` |
| SHA3-384 | `d635a25583ed68dd238be20ecb897aa4e199b1b3c6d8bd6e729f742838a86865f663a88b79319d37f97dec8774247a1d` |
| TLSH | `T1DBE3E71E7E618F3DFBA9C23447B78E26965933C637E1C585D1ACDA001E6024E641FFA8` |
| TELFHASH | `t1b7115e1c493822f097725c9d5aeeff72e5a030df46365e378e10e8a9ab6dd429d00c2c` |
| SSDEEP | `3072:6F+6uk9hckUGXZy9q/uleW0AJsPQDLHFwLH6EDq0Rp6+P+po5C5DB1NjHm1X8AfV:6F+6uk9hckUGXZy9q/uleW0AJsPQDMH7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_78238dfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78238dfbb4da6c6d8c04ba930deea29807c11d25e30bfd07e73d363603e57648"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-08-02 02:01:16"
  condition:
    hash.sha256(0, filesize) == "78238dfbb4da6c6d8c04ba930deea29807c11d25e30bfd07e73d363603e57648"
}
```

### Sample 14: `2df589b5d6f301f2`

| Field | Value |
|---|---|
| SHA-256 | `2df589b5d6f301f24a0102c34655d145a203c1281034394be4f6f9dbafd750de` |
| Family label | `Mirai` |
| File name | `morte.mips` |
| File type | `elf` |
| First seen | `2026-08-02 02:00:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe7fc79a4f76b7315e045113eb0c8ed6` |
| SHA-1 | `8e9ce0f04dfb8ccc7e466136e70a63fde4a63d4e` |
| SHA-256 | `2df589b5d6f301f24a0102c34655d145a203c1281034394be4f6f9dbafd750de` |
| SHA3-384 | `e16bb91bb9b22ccfb7d3e121f9fc9b24852cdd22c859295faf6154337da5238ddd6386d5d4ba75691ee88d3d169491d1` |
| TLSH | `T15423F1EE1F85C4FBC876E8F14A27A73805661EB19801DC9E75B0D9176AB75E4338D2C0` |
| SSDEEP | `768:TufLsKvA6hQ4H29CmJj7PSuWMMqkq9ZO3RwrK4T9M/ApmJg/s0s9iKuRiKJgGlz5:Kf7Wa29CafSRokq9I3RwrK45M/AE2/sg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_2df589b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2df589b5d6f301f24a0102c34655d145a203c1281034394be4f6f9dbafd750de"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-08-02 02:00:16"
  condition:
    hash.sha256(0, filesize) == "2df589b5d6f301f24a0102c34655d145a203c1281034394be4f6f9dbafd750de"
}
```

### Sample 15: `897a5c4077216fd9`

| Field | Value |
|---|---|
| SHA-256 | `897a5c4077216fd9bb766b6a0b8fbd1c8af9c6a7550fabc74643363bdb477ef1` |
| Family label | `unknown` |
| File name | `AI+File+Cleaner_1.0.5.xapk` |
| File type | `xapk` |
| First seen | `2026-08-02 01:57:32` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d69b7cb1d24db0b23de76539a2265037` |
| SHA-256 | `897a5c4077216fd9bb766b6a0b8fbd1c8af9c6a7550fabc74643363bdb477ef1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_897a5c40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "897a5c4077216fd9bb766b6a0b8fbd1c8af9c6a7550fabc74643363bdb477ef1"
    family = "unknown"
    file_name = "AI+File+Cleaner_1.0.5.xapk"
    file_type = "xapk"
    first_seen = "2026-08-02 01:57:32"
  condition:
    hash.sha256(0, filesize) == "897a5c4077216fd9bb766b6a0b8fbd1c8af9c6a7550fabc74643363bdb477ef1"
}
```

### Sample 16: `6364e72f4838a6e1`

| Field | Value |
|---|---|
| SHA-256 | `6364e72f4838a6e1c487a15f8b373a950d0830fa94a275cebf247dd4820da676` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-08-02 01:53:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `005f779a9116d7c06b92e4dcda352136` |
| SHA-1 | `5610a0d1f77309fe1c46b295a82466ad652bdd73` |
| SHA-256 | `6364e72f4838a6e1c487a15f8b373a950d0830fa94a275cebf247dd4820da676` |
| SHA3-384 | `dfb19ea7103dd8e9934c04516b170629afd2c9a4b7ca134716eda2ec9d9e0b5700c2188ba8ff8325f961303f967536bb` |
| TLSH | `T18A145C46EA414E13C0D7137AB6AF424A333297A4D3DB73069D286FB43BC279E0E67645` |
| TELFHASH | `t101311072933152266a61d914dcec97b2162dc7071288fe33df35849c141a49ee53bc1f` |
| SSDEEP | `6144:fyL4oAzWZvkRlqaHjp7VcKBTLCMBkL93JgM/9Auug:fy89zWZ8RlqaHjp7VcKBPBIfZ/auR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_6364e72f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6364e72f4838a6e1c487a15f8b373a950d0830fa94a275cebf247dd4820da676"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-08-02 01:53:34"
  condition:
    hash.sha256(0, filesize) == "6364e72f4838a6e1c487a15f8b373a950d0830fa94a275cebf247dd4820da676"
}
```

### Sample 17: `85938a1944c69e21`

| Field | Value |
|---|---|
| SHA-256 | `85938a1944c69e21ae3034e69ae7e6bee123204d15ccbf4bfdd9e90ea2ea2730` |
| Family label | `Mirai` |
| File name | `morte.arm7` |
| File type | `elf` |
| First seen | `2026-08-02 01:53:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3adc827f1ef0aac9d6f1e8d8bb0a14e7` |
| SHA-1 | `4f0ebb49b8d64a083f71ae33051334ab72b8e33f` |
| SHA-256 | `85938a1944c69e21ae3034e69ae7e6bee123204d15ccbf4bfdd9e90ea2ea2730` |
| SHA3-384 | `c9092fd687263bd64afe07097b4f1fc929a94b9ac372afe3245ee294087b77f1fc239d8f159a7ca13f8cfb61e34afd4f` |
| TLSH | `T1A7630259EB4634DBE9206AB2C47CD8A65B798B4C72571F930F4C87A8C978E132D1D80F` |
| SSDEEP | `1536:ptMg4w5mHHtAP5DKEQZMbZyJC5OJKPcRq2/LUQrOr68ON1z:7fF5mHHtiM2bZWC5yKPcRqqLUYY69Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_85938a19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85938a1944c69e21ae3034e69ae7e6bee123204d15ccbf4bfdd9e90ea2ea2730"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-08-02 01:53:16"
  condition:
    hash.sha256(0, filesize) == "85938a1944c69e21ae3034e69ae7e6bee123204d15ccbf4bfdd9e90ea2ea2730"
}
```

### Sample 18: `01ee4d3f8cd10497`

| Field | Value |
|---|---|
| SHA-256 | `01ee4d3f8cd104975fadd5282d27524e8c7f08335c01200434bb217a3be62917` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-02 01:53:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f91925b4a115c7c91fa23d8d194f44e5` |
| SHA-1 | `dd7b4b54a1e56581c227a1f6f0cc531bb9b936db` |
| SHA-256 | `01ee4d3f8cd104975fadd5282d27524e8c7f08335c01200434bb217a3be62917` |
| SHA3-384 | `e36e1a3ec6300944395a17896efe403e4e8a230998eb0fe83234491dd0c7a0b06335f96adfaba0dd9249b817e6662934` |
| TLSH | `T1CA01ABCEE164881040DAD91D329B5594FC71C3CB164A4FB9BF6CA43ADB84E14B036FD8` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaCEX3NUyJp58yeE/F/uX:e9Qp+MsCEX3NXJkqN/uX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_01ee4d3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ee4d3f8cd104975fadd5282d27524e8c7f08335c01200434bb217a3be62917"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-02 01:53:14"
  condition:
    hash.sha256(0, filesize) == "01ee4d3f8cd104975fadd5282d27524e8c7f08335c01200434bb217a3be62917"
}
```

### Sample 19: `4744701e8d7db089`

| Field | Value |
|---|---|
| SHA-256 | `4744701e8d7db089167a1709509f1f07c46323d85bdb48ba1d96921386507e1e` |
| Family label | `Mirai` |
| File name | `morte.spc` |
| File type | `elf` |
| First seen | `2026-08-02 01:50:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `306993c1b784ba238ab3bf35df4dc737` |
| SHA-1 | `cf6c65203bf30c33277f64d7fa43b1480db01c95` |
| SHA-256 | `4744701e8d7db089167a1709509f1f07c46323d85bdb48ba1d96921386507e1e` |
| SHA3-384 | `42da4145b9db531359ce0d53b53f721e161412bd846858d5b7f4027125793e2aa7caa6c5cc604e9b9a86f174032993bf` |
| TLSH | `T1CDB36D22B8391E27C4E0987B22F74766F1F657D914A8CA0E7E710E8EFF255503607AB4` |
| SSDEEP | `1536:/B9LXhde/3t3H7XL3Tj0IfSLeNaNYfwr8vpdzvKtnnnW+r4eCHtCJmYm5XY8RJBL:JFahbe8v2nW+jIQJmYOoFc3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_4744701e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4744701e8d7db089167a1709509f1f07c46323d85bdb48ba1d96921386507e1e"
    family = "Mirai"
    file_name = "morte.spc"
    file_type = "elf"
    first_seen = "2026-08-02 01:50:28"
  condition:
    hash.sha256(0, filesize) == "4744701e8d7db089167a1709509f1f07c46323d85bdb48ba1d96921386507e1e"
}
```

### Sample 20: `7861050378c2366c`

| Field | Value |
|---|---|
| SHA-256 | `7861050378c2366c6ce197e14d464dfec5ad7e7a15aed97fba99e2a9bb870e91` |
| Family label | `Mirai` |
| File name | `zero.m68k` |
| File type | `elf` |
| First seen | `2026-08-02 01:49:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89d6c46a455a89547ad989f25018ee2f` |
| SHA-1 | `a39f9b2e5ace6b871a40e2b2ab215172b1a9d68e` |
| SHA-256 | `7861050378c2366c6ce197e14d464dfec5ad7e7a15aed97fba99e2a9bb870e91` |
| SHA3-384 | `3065968dde1bd9ffc492d7da168c16724e06c019c05e5d559097ee2895d73481d603d6aff34c344120348825c2960103` |
| TLSH | `T195041797FC00CEBEF41BE37644570A057130B7E145926B376663796BDD3E0A92823E8A` |
| SSDEEP | `3072:YNvHE8TimUgvkth2a8iHU6luxOg8AooVsjbioLSqRty4NODVp2:Mhimk2a8iHU6ox+AoxLly4CVp2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_78610503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7861050378c2366c6ce197e14d464dfec5ad7e7a15aed97fba99e2a9bb870e91"
    family = "Mirai"
    file_name = "zero.m68k"
    file_type = "elf"
    first_seen = "2026-08-02 01:49:15"
  condition:
    hash.sha256(0, filesize) == "7861050378c2366c6ce197e14d464dfec5ad7e7a15aed97fba99e2a9bb870e91"
}
```

### Sample 21: `9c5d705f07e17a4b`

| Field | Value |
|---|---|
| SHA-256 | `9c5d705f07e17a4bf809d384c67630ec197ac11335747e068424067fde56a9d0` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-02 01:48:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d936fab5bf40ac4d251814d723c8fa9` |
| SHA-1 | `d40e19637020b972b09a7fec9acc4beff2e8e364` |
| SHA-256 | `9c5d705f07e17a4bf809d384c67630ec197ac11335747e068424067fde56a9d0` |
| SHA3-384 | `33c225bdbefe362704f43f3cb83193f61a2495b7570c91296572c0a9b5fdaad4ec499dd4da9f45af5d74ef732748a0d0` |
| TLSH | `T143B36DC9F647D0F5EC5705302176FB37AE72E4BA2328DA83D3A89A327C21641D456B9C` |
| TELFHASH | `t1bb31c5fab77608d857c0a903e68eab31bd4d27bb25503aa306f76874351714190bbc79` |
| SSDEEP | `3072:7EqQwKemz+S5OCXUBta7ecz2mRsfJCmBD:4qQwKepSM5n3fJCmBD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_9c5d705f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c5d705f07e17a4bf809d384c67630ec197ac11335747e068424067fde56a9d0"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-02 01:48:32"
  condition:
    hash.sha256(0, filesize) == "9c5d705f07e17a4bf809d384c67630ec197ac11335747e068424067fde56a9d0"
}
```

### Sample 22: `09a0d0b2a3b5f7af`

| Field | Value |
|---|---|
| SHA-256 | `09a0d0b2a3b5f7af9990075bb8ddf974b9233d8b94883f63f9660642753bd667` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-02 01:47:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd30b15425790cf19291d8f703c49d28` |
| SHA-1 | `eccc162ea9f37cc00d03bc31901e9f3c02cc4c8e` |
| SHA-256 | `09a0d0b2a3b5f7af9990075bb8ddf974b9233d8b94883f63f9660642753bd667` |
| SHA3-384 | `cd8246efca720287f30edb52941b63672ac14d0af7df9e564920befb70b34bd4f879dfc866ab7b4074eb39ebbe19c8b2` |
| TLSH | `T1002302778EB60362D0275138DE7DF28F0455118A60E2D4A7F29C723D499B7D522B0EE0` |
| SSDEEP | `768:LHcV4XqzbovGBNotOenQOuMX7tNy3wASxWIFnLsjkvCz2/jHE1X1X8YM+/SqovMn:0qqzbovGBN6bQ87tNZfxWIdpqzqjk1XD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_09a0d0b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09a0d0b2a3b5f7af9990075bb8ddf974b9233d8b94883f63f9660642753bd667"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-02 01:47:32"
  condition:
    hash.sha256(0, filesize) == "09a0d0b2a3b5f7af9990075bb8ddf974b9233d8b94883f63f9660642753bd667"
}
```

### Sample 23: `d86694d1cbdf7af6`

| Field | Value |
|---|---|
| SHA-256 | `d86694d1cbdf7af6d65e8c362ab68b3bd18a6d6a5d882416704c2409e87e1b1e` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-08-02 01:46:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1d9c26eaf3d22b3c80ae8fd92e1b469` |
| SHA-1 | `74da7f7adb87cac8fb5a93adee5536b29689f1b3` |
| SHA-256 | `d86694d1cbdf7af6d65e8c362ab68b3bd18a6d6a5d882416704c2409e87e1b1e` |
| SHA3-384 | `1eedfd83a591bb049970159e8d72fde1ecd07edb910c0460d46bc728137acf3e4a295366091d4d79419fe245b92348a7` |
| TLSH | `T174B34BC0F98B81F5C40B8C306166F63FCE31D5A95271DAADFF9A9F32DA776019502249` |
| TELFHASH | `t1b13103b8f2750d9c9bc09503aa4e5730ad0ebe7b356036b909f73525357314262bcc39` |
| SSDEEP | `3072:08iN7p8KcnM5NcN4IV6OZzrjU7GDCCgptWsRCGq:Yt8VnMvcN1Rdnq6PGq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_d86694d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86694d1cbdf7af6d65e8c362ab68b3bd18a6d6a5d882416704c2409e87e1b1e"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-08-02 01:46:28"
  condition:
    hash.sha256(0, filesize) == "d86694d1cbdf7af6d65e8c362ab68b3bd18a6d6a5d882416704c2409e87e1b1e"
}
```

### Sample 24: `c0362bd243e87ca8`

| Field | Value |
|---|---|
| SHA-256 | `c0362bd243e87ca8fa0a5ec6eb3674ed57f30baf797b21043c2662f6f6d1db1e` |
| Family label | `Mirai` |
| File name | `morte.i686` |
| File type | `elf` |
| First seen | `2026-08-02 01:45:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cd5995ce10b309abf5f56e135dedb30` |
| SHA-1 | `455b468e3ddcbf3f6342a4b1f0d924cc5dafc60d` |
| SHA-256 | `c0362bd243e87ca8fa0a5ec6eb3674ed57f30baf797b21043c2662f6f6d1db1e` |
| SHA3-384 | `0e871a7ec4f4e5cd0dc3e57a43622e32bd41538d1ce286ce889c7af87032f41d4823096097c98f761ded15ef18893f83` |
| TLSH | `T1E523F25262FDDA15DA2E067422DED4CA395CEC656B0C82F9CA88712F4434F353F298DE` |
| SSDEEP | `768:zwbDYZ0ofy7ghK2QQdhSCXglDrm7zc59vnrDVDWMgan2JiRSsUmkjUJQzxov/+nL:z2YZ0Cy7ghMQPSSiDrm7459/11gaAXsc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_c0362bd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0362bd243e87ca8fa0a5ec6eb3674ed57f30baf797b21043c2662f6f6d1db1e"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-08-02 01:45:40"
  condition:
    hash.sha256(0, filesize) == "c0362bd243e87ca8fa0a5ec6eb3674ed57f30baf797b21043c2662f6f6d1db1e"
}
```

### Sample 25: `8aaf628e5e59c226`

| Field | Value |
|---|---|
| SHA-256 | `8aaf628e5e59c2260fc05f3528fe0c2699f739db14a0e6264f45dca4001a8377` |
| Family label | `Mirai` |
| File name | `zero.aarch64` |
| File type | `elf` |
| First seen | `2026-08-02 01:42:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02fa135a4e092d843554640629e09e42` |
| SHA-1 | `c6a63fcff6ef48282ae94704bac7480409effcd1` |
| SHA-256 | `8aaf628e5e59c2260fc05f3528fe0c2699f739db14a0e6264f45dca4001a8377` |
| SHA3-384 | `6e916196432a960b0fa410fbd7588edcec09f1b4a4426c25d2bb1e5b0e2aecdc879da5df8d7c7c59b2b53f693b10a524` |
| TLSH | `T152144A99FA0F6D42F1C7D2FCDE4D8BD13A1730E3D7368A656D0203EDDAA39995980902` |
| SSDEEP | `3072:aM7gUMBfJfSQSf06/bzxNczlG7xhOuUKoA0zW7BymxZd6tPMxR+Rjq:S1ZE2zl47OKoA0zW7B78tPu+Rjq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_8aaf628e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8aaf628e5e59c2260fc05f3528fe0c2699f739db14a0e6264f45dca4001a8377"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-08-02 01:42:32"
  condition:
    hash.sha256(0, filesize) == "8aaf628e5e59c2260fc05f3528fe0c2699f739db14a0e6264f45dca4001a8377"
}
```

### Sample 26: `8f847d78922ffdcf`

| Field | Value |
|---|---|
| SHA-256 | `8f847d78922ffdcfe6e7373d8a0227d9d74544c55472d1dcde203ba845bbd896` |
| Family label | `Mirai` |
| File name | `zero.aarch64` |
| File type | `elf` |
| First seen | `2026-08-02 01:41:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4440f18cc9fc01560eea0c0c1adb6acf` |
| SHA-1 | `bb5f51e126ee96abc010b922c0bb5ea7940029fd` |
| SHA-256 | `8f847d78922ffdcfe6e7373d8a0227d9d74544c55472d1dcde203ba845bbd896` |
| SHA3-384 | `a6da4abc42ddd60b9b0b9bcf59826f7257e2ede63c244d84b143419ba6bc841c775aeb792915f45a31e1aec6b2100f5e` |
| TLSH | `T19C830214A7BE9D0AEB6EA3787C69500FA448AA6A1FEDE733EC4277C3D0408571334536` |
| SSDEEP | `1536:2WNkuzbxERZqg254Y7D9gMQQWTtmuQKKOH5v4K1FdD0OJsSQrL:7kkxhfbSTTl5l13D0OJSv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_8f847d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f847d78922ffdcfe6e7373d8a0227d9d74544c55472d1dcde203ba845bbd896"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-08-02 01:41:39"
  condition:
    hash.sha256(0, filesize) == "8f847d78922ffdcfe6e7373d8a0227d9d74544c55472d1dcde203ba845bbd896"
}
```

### Sample 27: `ac795868b63b04cc`

| Field | Value |
|---|---|
| SHA-256 | `ac795868b63b04ccd18e4070a5e021870ab81c2eb307f8bb04543220f6b0c371` |
| Family label | `Mirai` |
| File name | `zero.armv6l` |
| File type | `elf` |
| First seen | `2026-08-02 01:40:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2108a89ab1e70982dbbfa89cff3de81` |
| SHA-1 | `99100e243802d2265bd54074fb2d8699d122d25f` |
| SHA-256 | `ac795868b63b04ccd18e4070a5e021870ab81c2eb307f8bb04543220f6b0c371` |
| SHA3-384 | `50d72fb28a9747cf7f700308293252b44883b5fd6089c3adf6695aeb7618b5f55d90e8433e6be0fbb58e28ace29ec00e` |
| TLSH | `T1A4F31B86BC814B01D1C215B6FE1D124E37135B78E3E972139E186B3D7B8ACBB0A3B955` |
| TELFHASH | `t1dbc08051fef0125c56c491950101a058f25031eb1e3136e74245c70b0eb1e457435503` |
| SSDEEP | `3072:RpjfE0nZ+B0+d2UVonPxBX9yFTaSMBWag1uKRpwAnmv3i:AU7+opBX0FTabBW9wAnmv3i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_ac795868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac795868b63b04ccd18e4070a5e021870ab81c2eb307f8bb04543220f6b0c371"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-08-02 01:40:43"
  condition:
    hash.sha256(0, filesize) == "ac795868b63b04ccd18e4070a5e021870ab81c2eb307f8bb04543220f6b0c371"
}
```

### Sample 28: `2ffbc8a866d557a4`

| Field | Value |
|---|---|
| SHA-256 | `2ffbc8a866d557a4c5bc38138385f53f76495fdfc2e816c3c03a136fd4766132` |
| Family label | `Mirai` |
| File name | `zero.armv6l` |
| File type | `elf` |
| First seen | `2026-08-02 01:40:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4eb81e7d911e9c08dea7d16ba35d997` |
| SHA-1 | `80c83732233e3cf9a68e61b3ed41d17ccb4f7572` |
| SHA-256 | `2ffbc8a866d557a4c5bc38138385f53f76495fdfc2e816c3c03a136fd4766132` |
| SHA3-384 | `544f5aecb3b83d2b9a3bee3e3c91119b0def2a4b3a231c3ea3c7b4466ff3ab5e270976efd53a51e7f2476fcf294d6659` |
| TLSH | `T1654302A325822533C420887EFE1A00D31E5686B945CD75B75211BB88F6C7F8B9EFB197` |
| SSDEEP | `1536:xjsyC2yFBgrpbucuWSpTuXS6qf9MXM+XjciN6iLQ:xjfFT8EqfSMZY5LQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_2ffbc8a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ffbc8a866d557a4c5bc38138385f53f76495fdfc2e816c3c03a136fd4766132"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-08-02 01:40:26"
  condition:
    hash.sha256(0, filesize) == "2ffbc8a866d557a4c5bc38138385f53f76495fdfc2e816c3c03a136fd4766132"
}
```

### Sample 29: `2b84a52a2d4d954b`

| Field | Value |
|---|---|
| SHA-256 | `2b84a52a2d4d954bbe37342a8575d735808d520972662de903edeb8e62ea0076` |
| Family label | `Mirai` |
| File name | `morte.arc` |
| File type | `elf` |
| First seen | `2026-08-02 01:40:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9bae4c61ed64c58ff5081ceb63db469` |
| SHA-1 | `a3583127a1ad497010a02dd16d58e949f29ab760` |
| SHA-256 | `2b84a52a2d4d954bbe37342a8575d735808d520972662de903edeb8e62ea0076` |
| SHA3-384 | `6114f5bc89230d1bfb4ba9ef77f3d3e3f3c50aadcccdb0fad21cfd05f22db7a47055b20eb95a3a0bdc791a039321300f` |
| TLSH | `T188D3AEA7F74721D1C86306F407CB4BDD2E6322829F6B98E7BC5F653B197A0DA0502B91` |
| SSDEEP | `3072:UsyHPBOg+J6eBAR9cWutBXBduCugbBbq:Upj+fLf/zxbq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_2b84a52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b84a52a2d4d954bbe37342a8575d735808d520972662de903edeb8e62ea0076"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-08-02 01:40:25"
  condition:
    hash.sha256(0, filesize) == "2b84a52a2d4d954bbe37342a8575d735808d520972662de903edeb8e62ea0076"
}
```

### Sample 30: `bde905ff9a0748dc`

| Field | Value |
|---|---|
| SHA-256 | `bde905ff9a0748dc6f31b52b99b712c5b410b49843729e4932b647c15707fea1` |
| Family label | `unknown` |
| File name | `a.sh` |
| File type | `sh` |
| First seen | `2026-08-02 01:40:23` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `528e36d1010cf423310230fb686725b4` |
| SHA-1 | `a137876efda162b1a42342db0a71e4f81f3c0ef3` |
| SHA-256 | `bde905ff9a0748dc6f31b52b99b712c5b410b49843729e4932b647c15707fea1` |
| SHA3-384 | `0e7ba1f7b01f2a45445559d0e29075d8d3db916cb0159557f0c9e18a89e55360afc348aa014a49b0adcb1928b90f702a` |
| TLSH | `T1C411DAAF045429AED6138903F274E33EF31B7FAD7EBA3B08C7856653A448440317298D` |
| SSDEEP | `24:5XQ9EteE+pTUVUTBTfVFTYpEXcEwpES/E9pKojEEJDEiurRwFRXCdRXnRwqqRwGz:emL+5aUxdNYyDwyh9kticw7XCTXRwq0P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_bde905ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde905ff9a0748dc6f31b52b99b712c5b410b49843729e4932b647c15707fea1"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-08-02 01:40:23"
  condition:
    hash.sha256(0, filesize) == "bde905ff9a0748dc6f31b52b99b712c5b410b49843729e4932b647c15707fea1"
}
```

### Sample 31: `50a42309a5fb81a0`

| Field | Value |
|---|---|
| SHA-256 | `50a42309a5fb81a08d92811ef90568d4ae67101690f430a1208feba3ca67ef40` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-02 01:33:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66f17e49bbe51c35f29da2c1d53a4bce` |
| SHA-1 | `6824b380ed0abdb3c41446b43b0924b07dd7170f` |
| SHA-256 | `50a42309a5fb81a08d92811ef90568d4ae67101690f430a1208feba3ca67ef40` |
| SHA3-384 | `261aae2ead8358d9bf5e9cbaa726c8a6918e931a68756af4f7b2ff66af7229ab3b3a58935af646ed02ee8de9a58456fe` |
| TLSH | `T135236C6516857C14AE98C4375C7E2F0CB9AD43E6314492EE7FCA3CF28C4A6ADA20875D` |
| SSDEEP | `768:ATr9NyXsZztCI9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:AnHusZQcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_50a42309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50a42309a5fb81a08d92811ef90568d4ae67101690f430a1208feba3ca67ef40"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:33:39"
  condition:
    hash.sha256(0, filesize) == "50a42309a5fb81a08d92811ef90568d4ae67101690f430a1208feba3ca67ef40"
}
```

### Sample 32: `0976602bea0da481`

| Field | Value |
|---|---|
| SHA-256 | `0976602bea0da4814b69d1985b4fb488ecca41574d037dd64a6f55ba65c0b69b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-02 01:31:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0867673d1f227dee386a8078edfcab04` |
| SHA-1 | `a6308d725c0f4c10a6614cd2b6b20b83e4494c5a` |
| SHA-256 | `0976602bea0da4814b69d1985b4fb488ecca41574d037dd64a6f55ba65c0b69b` |
| SHA3-384 | `9b644a076cc9fccfd72e6ba956c7b6781533f39b6839471a0ecee66bfd6c507228deca6c0be766411908f15f31e5be25` |
| TLSH | `T1CC237D552A857C14AA98C4371D7E2F0CB9AD43E6320452ED7FCF3CF68C4A69DA11871D` |
| SSDEEP | `768:XXOGVv59GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:nLKcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_0976602b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0976602bea0da4814b69d1985b4fb488ecca41574d037dd64a6f55ba65c0b69b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:31:17"
  condition:
    hash.sha256(0, filesize) == "0976602bea0da4814b69d1985b4fb488ecca41574d037dd64a6f55ba65c0b69b"
}
```

### Sample 33: `d67edc48b43fc48a`

| Field | Value |
|---|---|
| SHA-256 | `d67edc48b43fc48a0b399d5144bb5d3d0862e77065117fe10f7822a70daa1d96` |
| Family label | `Mirai` |
| File name | `zero.x86_64` |
| File type | `elf` |
| First seen | `2026-08-02 01:29:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ffe3f1d758e5f29323b1e7e978c3ab2` |
| SHA-1 | `89a6132d864b4b1c3b2ea677f3b13dff83d59d27` |
| SHA-256 | `d67edc48b43fc48a0b399d5144bb5d3d0862e77065117fe10f7822a70daa1d96` |
| SHA3-384 | `41bd89bfb2277eafe54af7b65cfa48c4c78540b645fdde3c88c22b4f8b47ee1d611de6ff949d2344fdc0c8a017bce26d` |
| TLSH | `T1A1F33A0ABCC054FEC489C2748AADB532ED32B45E5134B6AB27C06E323D8DE61BE5D751` |
| TELFHASH | `t1c451be302c46398c62e7ab55724feeaee87309100de1b4e4ee2b7ae4ce477c84d43091` |
| SSDEEP | `3072:M6iSdcPSM+K2hwDAbHbDtYbBIeEW+9i9rYK6brE+BSF73:viSdcPSLASY+9BPCV3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_d67edc48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d67edc48b43fc48a0b399d5144bb5d3d0862e77065117fe10f7822a70daa1d96"
    family = "Mirai"
    file_name = "zero.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 01:29:24"
  condition:
    hash.sha256(0, filesize) == "d67edc48b43fc48a0b399d5144bb5d3d0862e77065117fe10f7822a70daa1d96"
}
```

### Sample 34: `1bf6ad02a9a94174`

| Field | Value |
|---|---|
| SHA-256 | `1bf6ad02a9a9417479c27e67072b6aa54571709e7ef0b9304dfb92bddd1f109f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-02 01:28:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b43751c96113fdf46282a1bf5b758467` |
| SHA-1 | `fd93f755b2a458feb0410a913f83958123c46370` |
| SHA-256 | `1bf6ad02a9a9417479c27e67072b6aa54571709e7ef0b9304dfb92bddd1f109f` |
| SHA3-384 | `e1bb4d3b7a5b894464da28a280bc7f519bd05a67351e8236c2eab164898375cd4a5e02a018a3e64c2bef1abc99c3b980` |
| TLSH | `T139C28D956A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC12FACD618B1A` |
| SSDEEP | `768:O8vCB+25j6es8RDZ9FYpMSUpi+20qUpi+20YQX:O8l25JD/d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_1bf6ad02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bf6ad02a9a9417479c27e67072b6aa54571709e7ef0b9304dfb92bddd1f109f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:28:31"
  condition:
    hash.sha256(0, filesize) == "1bf6ad02a9a9417479c27e67072b6aa54571709e7ef0b9304dfb92bddd1f109f"
}
```

### Sample 35: `28a16751269feab6`

| Field | Value |
|---|---|
| SHA-256 | `28a16751269feab605a0df2ace7b0023cfc439947ce9b23ebda0675b88bd4dbd` |
| Family label | `Mirai` |
| File name | `zero.x86_64` |
| File type | `elf` |
| First seen | `2026-08-02 01:28:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd4e47f7394893dcf0f9c759e05a0b8d` |
| SHA-1 | `e1e5588d55a9e47e80ee36280315f04ba093dc38` |
| SHA-256 | `28a16751269feab605a0df2ace7b0023cfc439947ce9b23ebda0675b88bd4dbd` |
| SHA3-384 | `2f56b8384dc110c649c62d39dae1667d64ff19839c130ab8bf131a597a51364c1631bffb0ccccba67f17b8a44d35c3db` |
| TLSH | `T13D43F2722466EBBCF72B6B7E5648B240C8371A32A51B2EEE54511167067FFE11C0CAD2` |
| SSDEEP | `1536:G10HkpCfuso6bUkL+hSSsVaKCUrB864dxW:GN4Ho6TKZKNVtUW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_28a16751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28a16751269feab605a0df2ace7b0023cfc439947ce9b23ebda0675b88bd4dbd"
    family = "Mirai"
    file_name = "zero.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 01:28:30"
  condition:
    hash.sha256(0, filesize) == "28a16751269feab605a0df2ace7b0023cfc439947ce9b23ebda0675b88bd4dbd"
}
```

### Sample 36: `9651658cdd06bf43`

| Field | Value |
|---|---|
| SHA-256 | `9651658cdd06bf43195524fe79ba39488d96c971bc5c3ac822f2a6abd9f33855` |
| Family label | `Mirai` |
| File name | `zero.sh4` |
| File type | `elf` |
| First seen | `2026-08-02 01:27:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7e9661e0b26e3494d3b61dc74e68887` |
| SHA-1 | `8292bb3bf68f3c8fbe166db729717c0c8765d4de` |
| SHA-256 | `9651658cdd06bf43195524fe79ba39488d96c971bc5c3ac822f2a6abd9f33855` |
| SHA3-384 | `ca0938815686b2ff62037878aac4d5a5c69434c37fa550e14dc0c32b66cb46724e606e8b5e3fa5c967edd5cf18c40878` |
| TLSH | `T1C2E36D22CC356E9CE036ED31603C8ABA172394E4540B9EBA3967C3714057DD9F996BF8` |
| SSDEEP | `3072:9HdzG5SM8ZpZq1YgDMkiiCaykjMWiuU5RWoyo40Y7:9p8SM8ZLq1YgDMkShkjM5P8oF40Y7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_9651658c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9651658cdd06bf43195524fe79ba39488d96c971bc5c3ac822f2a6abd9f33855"
    family = "Mirai"
    file_name = "zero.sh4"
    file_type = "elf"
    first_seen = "2026-08-02 01:27:17"
  condition:
    hash.sha256(0, filesize) == "9651658cdd06bf43195524fe79ba39488d96c971bc5c3ac822f2a6abd9f33855"
}
```

### Sample 37: `6baeb67d22fa275b`

| Field | Value |
|---|---|
| SHA-256 | `6baeb67d22fa275bd2426180e5fe051ac1831c050db47d8fb89640813d4f4afa` |
| Family label | `Mirai` |
| File name | `morte.arm5` |
| File type | `elf` |
| First seen | `2026-08-02 01:22:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5fa023db639e70cbdfa68149fc7416c` |
| SHA-1 | `8b59412e0b6d3c11e488a503971ea173493d66b9` |
| SHA-256 | `6baeb67d22fa275bd2426180e5fe051ac1831c050db47d8fb89640813d4f4afa` |
| SHA3-384 | `7c7762fa1198d8f43e284b95d8f3811e71d6995f2c95b5eb3f3ac8d76b2d87ad9002cb238df4be56c59bd10afb40cc03` |
| TLSH | `T16283F682F8828A2AC2D4237AE66F658E3761B3E5D2DF7517CD204B123B8511F0D67E91` |
| TELFHASH | `t10fe06140fe764b1884e75a34ecdd47b495116217a1664710cf54daf0883f15ca71cd5e` |
| SSDEEP | `1536:z3MBXt7eC/zU+8Ij35OiKgjwMn7E/mEvsBrSlLUuwB:z3MBd7e4zUI/wqSRAB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_6baeb67d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6baeb67d22fa275bd2426180e5fe051ac1831c050db47d8fb89640813d4f4afa"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 01:22:29"
  condition:
    hash.sha256(0, filesize) == "6baeb67d22fa275bd2426180e5fe051ac1831c050db47d8fb89640813d4f4afa"
}
```

### Sample 38: `7218d0523a4d05c5`

| Field | Value |
|---|---|
| SHA-256 | `7218d0523a4d05c52557f93febc58b45b67fa65a91e62656a74724d3ad87772d` |
| Family label | `Mirai` |
| File name | `morte.arm5` |
| File type | `elf` |
| First seen | `2026-08-02 01:21:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `deef52143396eea1d61cfffc2e152961` |
| SHA-1 | `863d2f2e873886a1e6ad173ce48c3ae7461faf9b` |
| SHA-256 | `7218d0523a4d05c52557f93febc58b45b67fa65a91e62656a74724d3ad87772d` |
| SHA3-384 | `4a82ae6ca79a759e0ab46c79c47c036e0b582aba40887778f412f590b750f7a8d021deef84245ea892488566b1c7e31c` |
| TLSH | `T1B4D2DF500442E9B695306475ABEC85C3738F56ACE4BA78672A800FA0FF61587ED7D7C3` |
| SSDEEP | `768:GPaCwwwmXkzedefht4oCydLRzc0s3Uoz7od:2cpmXkwyCFyd5izsd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_7218d052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7218d0523a4d05c52557f93febc58b45b67fa65a91e62656a74724d3ad87772d"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 01:21:39"
  condition:
    hash.sha256(0, filesize) == "7218d0523a4d05c52557f93febc58b45b67fa65a91e62656a74724d3ad87772d"
}
```

### Sample 39: `52e0c4974427db87`

| Field | Value |
|---|---|
| SHA-256 | `52e0c4974427db87b915d5b81785e6a9a014f5626e7adefee0c4a9710edd626d` |
| Family label | `Mirai` |
| File name | `morte.x86` |
| File type | `elf` |
| First seen | `2026-08-02 01:17:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd87c85a06a65791729a8238a8f7a268` |
| SHA-1 | `86953bc702ec75bd0c8d0ea32dd21911015155e9` |
| SHA-256 | `52e0c4974427db87b915d5b81785e6a9a014f5626e7adefee0c4a9710edd626d` |
| SHA3-384 | `5b5cbb84856089e8618f0426cf1ce32c075d02fa7a46b683f07e12cb18b5cfbf59096fb9866126eaa7057196f9996984` |
| TLSH | `T190A36CD6E283D4F5EC2241303176FF379E72E5BA2128DD83D7A49663BC62A42D406E5C` |
| TELFHASH | `t104312ff972bb0ce897c06903f60a6b30bd5c67bb105036b604f7283a365250152bbd39` |
| SSDEEP | `1536:rMmRqozBnO115B3k7myNqhwN+bYTMIqWBtlgALf5SZ+ZwLjh:wmDg3U7myNq+N+biL5tXD5+Ljh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_52e0c497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e0c4974427db87b915d5b81785e6a9a014f5626e7adefee0c4a9710edd626d"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-08-02 01:17:29"
  condition:
    hash.sha256(0, filesize) == "52e0c4974427db87b915d5b81785e6a9a014f5626e7adefee0c4a9710edd626d"
}
```

### Sample 40: `e9a42640b2832e6b`

| Field | Value |
|---|---|
| SHA-256 | `e9a42640b2832e6b4fab461e57d07f99cfb0f8428d64862e887206ba3a9e0b4f` |
| Family label | `Mirai` |
| File name | `morte.x86` |
| File type | `elf` |
| First seen | `2026-08-02 01:16:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1553b2eca1d147515a25763f0c3a17fe` |
| SHA-1 | `ade95c873c4e8613895ccc5cde5ca0740858d870` |
| SHA-256 | `e9a42640b2832e6b4fab461e57d07f99cfb0f8428d64862e887206ba3a9e0b4f` |
| SHA3-384 | `c7200acfe51313c0c10549241babc07c7336496af953fff6977b7239f844a204469d3f47e7772b98542350573e1adfd1` |
| TLSH | `T1BE13F122EAAA8444828E01FD84373D5D4109F84E65548FCFABE023E7D90EB7354BD9F6` |
| SSDEEP | `768:2gDoFSJjBGqGPCcnFpAKGB4Dl0sMy/hqGX99tm7BndWnbcuyD7UoQRjg:WGVDGPXnEB4GsMy/h/XfuB0nouy8oyc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_e9a42640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9a42640b2832e6b4fab461e57d07f99cfb0f8428d64862e887206ba3a9e0b4f"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-08-02 01:16:18"
  condition:
    hash.sha256(0, filesize) == "e9a42640b2832e6b4fab461e57d07f99cfb0f8428d64862e887206ba3a9e0b4f"
}
```

### Sample 41: `a10994395ee8391e`

| Field | Value |
|---|---|
| SHA-256 | `a10994395ee8391edb37a4472ce34744946598a30b8d656285d09fa57faf480b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-02 01:09:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b53d3736a5a8de6518193b8b712d13ed` |
| SHA-1 | `0a35464cf5c308b05b39d73a47549771f33ee786` |
| SHA-256 | `a10994395ee8391edb37a4472ce34744946598a30b8d656285d09fa57faf480b` |
| SHA3-384 | `aec5e1f413d88cf4419549ccb5a1af86508daecbe542001e2c04271f1c142fefee442ccd65c4b9593f2e5af59f9fca4e` |
| TLSH | `T18CC27D966A867C44BEC94A3E4CBD2B0D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:AQM8vCB+25j6es8RX9FYpMSUpi+20qUpi+20YQX:3M8l25Jxd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_a1099439
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a10994395ee8391edb37a4472ce34744946598a30b8d656285d09fa57faf480b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:09:29"
  condition:
    hash.sha256(0, filesize) == "a10994395ee8391edb37a4472ce34744946598a30b8d656285d09fa57faf480b"
}
```

### Sample 42: `585d6ed50abdf150`

| Field | Value |
|---|---|
| SHA-256 | `585d6ed50abdf1500cad819da63dc78d2d8afbecb791e5a5d2407817ef083ffb` |
| Family label | `Mirai` |
| File name | `zero.armv5l` |
| File type | `elf` |
| First seen | `2026-08-02 01:08:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9199b6e117e9bf63cdd0f76973bf22c1` |
| SHA-1 | `d912bea025038058a40b8889f0c9bae82d518c83` |
| SHA-256 | `585d6ed50abdf1500cad819da63dc78d2d8afbecb791e5a5d2407817ef083ffb` |
| SHA3-384 | `bf4a561576fc7e1f22acb986e74716cae10100c73f21452385843003ed1f82383839bbd95b8e66cd92cef575bde5a86f` |
| TLSH | `T101F31B8ABC818B13C6E161B7FB1E428D372643ACD3EA71179D186B29375B8970E37741` |
| TELFHASH | `t1f2313052d9980bdc17d0c70091af622b6eac34fc677620486f6dab5f4317ac53428871` |
| SSDEEP | `3072:1hxcCGw9iOqcN+o0RbUf4SD1aZFbdkf28/tq/:1hrj9izQiJUf4SDoZHk+81q/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_585d6ed5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "585d6ed50abdf1500cad819da63dc78d2d8afbecb791e5a5d2407817ef083ffb"
    family = "Mirai"
    file_name = "zero.armv5l"
    file_type = "elf"
    first_seen = "2026-08-02 01:08:27"
  condition:
    hash.sha256(0, filesize) == "585d6ed50abdf1500cad819da63dc78d2d8afbecb791e5a5d2407817ef083ffb"
}
```

### Sample 43: `fd8afd2e0d2d6b33`

| Field | Value |
|---|---|
| SHA-256 | `fd8afd2e0d2d6b33739270e33d0343efaaf9856e0ad26f98cb2cfdb3f72360cb` |
| Family label | `Mirai` |
| File name | `zero.armv5l` |
| File type | `elf` |
| First seen | `2026-08-02 01:08:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d54cf40b605a0d28a458a080f7d0e613` |
| SHA-1 | `e0dc844159a874d2ccc9d4a6b3647bfdd3e93959` |
| SHA-256 | `fd8afd2e0d2d6b33739270e33d0343efaaf9856e0ad26f98cb2cfdb3f72360cb` |
| SHA3-384 | `0a464b8931161159fbb6830e5d0086e5884c98c7b9025a6c1aa0b1d39273a58862edd1ff407028d7791e19e624fe9536` |
| TLSH | `T1AF33F27E51553C30EAB0333EA1D18C9722A58A7582DFF9F30A144E296B7268360F3E57` |
| SSDEEP | `1536:NRcE/LRFZAIF6M9v9G2NTppUZQCjFYNi3vGRzz0:NeWLRQsLv9GMp2SEFQweRzY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_fd8afd2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd8afd2e0d2d6b33739270e33d0343efaaf9856e0ad26f98cb2cfdb3f72360cb"
    family = "Mirai"
    file_name = "zero.armv5l"
    file_type = "elf"
    first_seen = "2026-08-02 01:08:15"
  condition:
    hash.sha256(0, filesize) == "fd8afd2e0d2d6b33739270e33d0343efaaf9856e0ad26f98cb2cfdb3f72360cb"
}
```

### Sample 44: `e7a21d0bb71be754`

| Field | Value |
|---|---|
| SHA-256 | `e7a21d0bb71be7547e411b75de1ea32a40966965543172d8e6693da5ac9a5f7b` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-08-02 01:06:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3531dbb844fa5ae9090ed92018e1eefe` |
| SHA-1 | `e5f822ca06e8026b8fb36babf8fa834202fd9562` |
| SHA-256 | `e7a21d0bb71be7547e411b75de1ea32a40966965543172d8e6693da5ac9a5f7b` |
| SHA3-384 | `c341f8ddb2ab61efc14eb43a3e9bd4887d1fec0d9af2851b909ee2b307d6281529ca49313c48b2922c43d2aedf1c2341` |
| TLSH | `T11BC33A85F8828A62D6D7237AFA6E128E372163E8D3DE7103CD216F2137C651F0D67991` |
| TELFHASH | `t1e411a263df920dac17f0821445beb25eedbd71ed2b0665958b5d6f4e44035d0b22d132` |
| SSDEEP | `1536:m57SbTR8mhSHxP0Pizl0+doQ/v3y6x8jdYkC2DyFwm3pB2P8xvoL:m57WT1hwau3yW0Yr2DxUBoL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_e7a21d0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7a21d0bb71be7547e411b75de1ea32a40966965543172d8e6693da5ac9a5f7b"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-08-02 01:06:28"
  condition:
    hash.sha256(0, filesize) == "e7a21d0bb71be7547e411b75de1ea32a40966965543172d8e6693da5ac9a5f7b"
}
```

### Sample 45: `409629d29129fcd7`

| Field | Value |
|---|---|
| SHA-256 | `409629d29129fcd72a0d48d11773a1c20e81a721c8346427b3c1a1a7da135892` |
| Family label | `Mirai` |
| File name | `morte.arm` |
| File type | `elf` |
| First seen | `2026-08-02 01:05:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee6960c4bbccbc8a409319dc7a628b6e` |
| SHA-1 | `c91f387e9b40854bd3d4e8c1650a320f5f08ea33` |
| SHA-256 | `409629d29129fcd72a0d48d11773a1c20e81a721c8346427b3c1a1a7da135892` |
| SHA3-384 | `9fd1722ac81ce05b69c7399501065494145bfb1bab5e3e4081af65acf4252d0c3db8ce625ce771c9a9f59ba0325ddbd4` |
| TLSH | `T166230211015C75A09A704473BDED8249218B4AD5E6FF76A81A172E20F8CD3CABF7338B` |
| SSDEEP | `768:011vnkyvkY1Ok/1wHEQ2Ctdx9ZoPUaaIuzJPvotDunA+LGgj8u5gSYT5vBUapGs9:YNkyM6O2CkBklZubanztMuAQjQpBUap/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_409629d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "409629d29129fcd72a0d48d11773a1c20e81a721c8346427b3c1a1a7da135892"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-08-02 01:05:30"
  condition:
    hash.sha256(0, filesize) == "409629d29129fcd72a0d48d11773a1c20e81a721c8346427b3c1a1a7da135892"
}
```

### Sample 46: `fd4746bedadaf4df`

| Field | Value |
|---|---|
| SHA-256 | `fd4746bedadaf4dfc3c9b6e062f0488e9c866e79455079ad8790e9a37c95cc03` |
| Family label | `Mirai` |
| File name | `zero.armv4l` |
| File type | `elf` |
| First seen | `2026-08-02 00:52:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c679ca7fcd82f32680166b57fd6ad14d` |
| SHA-1 | `e4f77f8274e70020cd02c37c34ea8ae61bc8b8a8` |
| SHA-256 | `fd4746bedadaf4dfc3c9b6e062f0488e9c866e79455079ad8790e9a37c95cc03` |
| SHA3-384 | `c716e86a89c2a8581e881721bd2e8a7ae99881aaa0d5a6a5a5f200d18f1d050b5634792f48414290930d163d144e74ec` |
| TLSH | `T1BEF31B8ABC818B03C5E261B3FB0E428D372647E8D3EA71179D196F29375B8970E37651` |
| TELFHASH | `t1e7311060154c0f9cdbc08a5c92ae113beda930e527122545ef1d639f8a53de1f137a3b` |
| SSDEEP | `3072:SNy0UQiOiPTe+oiBmb4JZ1l3NdmOyahSB:SgQi7aMEb4JvldcpahSB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_fd4746be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4746bedadaf4dfc3c9b6e062f0488e9c866e79455079ad8790e9a37c95cc03"
    family = "Mirai"
    file_name = "zero.armv4l"
    file_type = "elf"
    first_seen = "2026-08-02 00:52:31"
  condition:
    hash.sha256(0, filesize) == "fd4746bedadaf4dfc3c9b6e062f0488e9c866e79455079ad8790e9a37c95cc03"
}
```

### Sample 47: `61bc9a3758c56d8c`

| Field | Value |
|---|---|
| SHA-256 | `61bc9a3758c56d8cb261853b8b9feb686d5da08402f83564089c09610d3c6cef` |
| Family label | `Mirai` |
| File name | `zero.armv4l` |
| File type | `elf` |
| First seen | `2026-08-02 00:51:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbc3cc5020fddf990ef1f20dcd2b052b` |
| SHA-1 | `de036af9da7029dafe9ff29717335afde6e4be72` |
| SHA-256 | `61bc9a3758c56d8cb261853b8b9feb686d5da08402f83564089c09610d3c6cef` |
| SHA3-384 | `f506ac1c66be77f506819efd4b04d641b3cb07eee4ab19a7e25e072508c2521ee7cd37b50ce1a4f6c1aacd61bbcfbb12` |
| TLSH | `T10543E11814B8583AD6710439E53C1B4976FB83B485CF231B325A0964A5CB7E9A6BF983` |
| SSDEEP | `1536:NkdFpMP267Fhi9pZBIqCZHprpSAqVxo/FvBzx:N8f8B7amqCwAIxYFvB9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_61bc9a37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61bc9a3758c56d8cb261853b8b9feb686d5da08402f83564089c09610d3c6cef"
    family = "Mirai"
    file_name = "zero.armv4l"
    file_type = "elf"
    first_seen = "2026-08-02 00:51:39"
  condition:
    hash.sha256(0, filesize) == "61bc9a3758c56d8cb261853b8b9feb686d5da08402f83564089c09610d3c6cef"
}
```

### Sample 48: `b4eb673cc44d251e`

| Field | Value |
|---|---|
| SHA-256 | `b4eb673cc44d251ecc21afc9e19240ad69ef9f99ea5a319ef57ea261ee15b452` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-08-02 00:43:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `375254c03f390301e5b641111c1f0c40` |
| SHA-1 | `7143b9573c4f36f16f1f301c9afbfdc59956d0cf` |
| SHA-256 | `b4eb673cc44d251ecc21afc9e19240ad69ef9f99ea5a319ef57ea261ee15b452` |
| SHA3-384 | `058e91d6fac50ffb3378abe916c5da5f193da19b2a8307307540e9a1227b2cf18e2b3a4b62a7f9ae41876d2a34eb9d83` |
| TLSH | `T1D3E3F709BF610FF7E89FCC3709E91B0528CD556732A93B36B534D918B64B24B26E3864` |
| SSDEEP | `3072:zwV6WWosd4Bi3u7KGzJtcMaeeGeVlJSnKW2oyJi6ts1uYKu:zwIWWosd4Bi3u7KGzJtcMae10lJiKDbo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_b4eb673c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4eb673cc44d251ecc21afc9e19240ad69ef9f99ea5a319ef57ea261ee15b452"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:34"
  condition:
    hash.sha256(0, filesize) == "b4eb673cc44d251ecc21afc9e19240ad69ef9f99ea5a319ef57ea261ee15b452"
}
```

### Sample 49: `f38943d7da545cbb`

| Field | Value |
|---|---|
| SHA-256 | `f38943d7da545cbb1771b7934a42e2ee9677986d671d12896b18235ebb894394` |
| Family label | `Mirai` |
| File name | `zero.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-02 00:43:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4f0e91461b5bee890b1fa320346ffa9` |
| SHA-1 | `d6183438b6546a676742b4c0761dc6398d529105` |
| SHA-256 | `f38943d7da545cbb1771b7934a42e2ee9677986d671d12896b18235ebb894394` |
| SHA3-384 | `59719253ebd60b94de3fd63950ded96e2b6754b60bbe5ed2a7ea3c87d6186c10ef4f721b22a69a77df658a9766f328ce` |
| TLSH | `T16724B84F6E239F7DF67887344BB35E25675923D623E0D684E1ACC2105E2029E581FFA8` |
| TELFHASH | `t1614193180e7813f0a339ad4e059dff7ad6a330db7e166d238e11e85ea769a435e10d0c` |
| SSDEEP | `3072:eq0AsDTvciQzHFBtcS/tfFu7y9cEwDIklS:J6TeH3tdqy9JwDIUS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_f38943d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f38943d7da545cbb1771b7934a42e2ee9677986d671d12896b18235ebb894394"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:31"
  condition:
    hash.sha256(0, filesize) == "f38943d7da545cbb1771b7934a42e2ee9677986d671d12896b18235ebb894394"
}
```

### Sample 50: `dec424fc8ec0ec7f`

| Field | Value |
|---|---|
| SHA-256 | `dec424fc8ec0ec7f4e234f2ed759fd0ad672d8090e62dcf2a2fd3d4d8c90ac92` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-08-02 00:43:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ad4565a180db6beaf5355d806dcb755` |
| SHA-1 | `be2c263d543eb69d6d74556d314876e43b8d2178` |
| SHA-256 | `dec424fc8ec0ec7f4e234f2ed759fd0ad672d8090e62dcf2a2fd3d4d8c90ac92` |
| SHA3-384 | `f6b16982a9d4d6af7dfe069e28f55067e8397635e0ff2b2e3b78236ab6e30f972363bb7de18d1f6e669fdcd1dfba6eb1` |
| TLSH | `T135B35C4273180F57C1930AB02E3F1BF687BBE5D021E4BA89650F9B1A8675E77154AFC8` |
| SSDEEP | `1536:3Vbxi0VY3+TmlGzmRRuNfvyJpkw8piKlglnw59KDp93+JuM1+463tLdME:Fbk0VkR8mkMp9Xtd9Cuk2+E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_dec424fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dec424fc8ec0ec7f4e234f2ed759fd0ad672d8090e62dcf2a2fd3d4d8c90ac92"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:29"
  condition:
    hash.sha256(0, filesize) == "dec424fc8ec0ec7f4e234f2ed759fd0ad672d8090e62dcf2a2fd3d4d8c90ac92"
}
```

### Sample 51: `c29f04f3bf672aa6`

| Field | Value |
|---|---|
| SHA-256 | `c29f04f3bf672aa6e91a47b810bab140b7b21b0925fa10b3fc676c5c43057b90` |
| Family label | `Mirai` |
| File name | `morte.mpsl` |
| File type | `elf` |
| First seen | `2026-08-02 00:43:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b76289767913796c0547e2381f1f564f` |
| SHA-1 | `9017a160276a9760c3075f0a0135ed76088b5192` |
| SHA-256 | `c29f04f3bf672aa6e91a47b810bab140b7b21b0925fa10b3fc676c5c43057b90` |
| SHA3-384 | `a404dc1b154f44841c0db445d5195d37d73f2048c5d3f1d06fd411c41474a1dc0b92545738ded36e3e00e591326a58d5` |
| TLSH | `T14F33F1DD926F2449EBEC4D3EB76F07E69A02F488321E6FCA13165C5192AC44F32C506C` |
| SSDEEP | `768:FF6WiBf9i4tROBwZ3OPhgD6GhB9K0Ul1yh43h8f1R/YNrtrohdBEE9aP+ZIWU5:T6DG4tB+ZgDh5Jh43h8/YFmS5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_c29f04f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29f04f3bf672aa6e91a47b810bab140b7b21b0925fa10b3fc676c5c43057b90"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:19"
  condition:
    hash.sha256(0, filesize) == "c29f04f3bf672aa6e91a47b810bab140b7b21b0925fa10b3fc676c5c43057b90"
}
```

### Sample 52: `f47c9c3d3efc9891`

| Field | Value |
|---|---|
| SHA-256 | `f47c9c3d3efc98916fb74aa908075ffadf39b219dbdd7fa17d3da24ea77322cb` |
| Family label | `Mirai` |
| File name | `zero.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-02 00:43:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b5f3e31b64463bc4e5cf572363c3f2a` |
| SHA-1 | `7de31467c01f7d659bf16898c7bd8653421d2113` |
| SHA-256 | `f47c9c3d3efc98916fb74aa908075ffadf39b219dbdd7fa17d3da24ea77322cb` |
| SHA3-384 | `8c5daa2adfe0d8c74bba977e5e09bdad992fa30ca755c07ef4fce4c616a74bd17f1443b3b5fb315e3f47441ac5f437a3` |
| TLSH | `T16253025438065BECFE05C27C91E107A829A79A765272D42B28C8CEA3DF5498C3D5BFE0` |
| SSDEEP | `1536:KxwOGojcwOACygI8XgHe0L/JhWklXKxyXc2baVJu7:KfGouy76gxzHWCXMYfOVQ7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_f47c9c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47c9c3d3efc98916fb74aa908075ffadf39b219dbdd7fa17d3da24ea77322cb"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:18"
  condition:
    hash.sha256(0, filesize) == "f47c9c3d3efc98916fb74aa908075ffadf39b219dbdd7fa17d3da24ea77322cb"
}
```

### Sample 53: `7948a099bfa5e5ff`

| Field | Value |
|---|---|
| SHA-256 | `7948a099bfa5e5ffb60a1c94a64cbbae5b2f359a0a61159f39b54973b8f9bcff` |
| Family label | `Mirai` |
| File name | `morte.ppc` |
| File type | `elf` |
| First seen | `2026-08-02 00:43:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d39891972c4aae814411b4e56cd284d7` |
| SHA-1 | `743cb34ae6af3ee2db8d46a819df6494e66986a4` |
| SHA-256 | `7948a099bfa5e5ffb60a1c94a64cbbae5b2f359a0a61159f39b54973b8f9bcff` |
| SHA3-384 | `099cd2756b4de51bf97212a904b15f5b241888b2a2f2af8572053429826c1ccdd1bcf269e80ee2dcc5e972589251518d` |
| TLSH | `T1A813F191F0501CFBD2BFCA202741DADA37B98F962B6E65F27580FF54C60152A26482F8` |
| SSDEEP | `768:e6tQngu7T7t9yzKJjSiUI8e3H3nSj5Zkc4e5VFEiYsJie8urJJorlAdLqV0n04ux:rtjuR8aS/2H3IR35VrXJie8ufYlnV0na` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_7948a099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7948a099bfa5e5ffb60a1c94a64cbbae5b2f359a0a61159f39b54973b8f9bcff"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:16"
  condition:
    hash.sha256(0, filesize) == "7948a099bfa5e5ffb60a1c94a64cbbae5b2f359a0a61159f39b54973b8f9bcff"
}
```

### Sample 54: `9699025026d72bc7`

| Field | Value |
|---|---|
| SHA-256 | `9699025026d72bc780f108afe1749ef36fc109b91d90a9225bbd0e6e90102fcd` |
| Family label | `Mirai` |
| File name | `morte.arm6` |
| File type | `elf` |
| First seen | `2026-08-02 00:42:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c168971c0cc3517ff3cc94c9ebc324f6` |
| SHA-1 | `3ad0e98c99fb77abb96a97c4a5ac909ab6952334` |
| SHA-256 | `9699025026d72bc780f108afe1749ef36fc109b91d90a9225bbd0e6e90102fcd` |
| SHA3-384 | `17bd8f5e350e309cd61280192a29ef814445714b75ff1ed47453cd914515b9fbccb885644bbb3974267ee48e924802a5` |
| TLSH | `T11FC31946F9824A22C5D713BEFA2E118E331217B8F3DE72229E205F2537C651B0EB7955` |
| TELFHASH | `t1fb21df65ff74166c17e4824945d5d80a4fe930ed0a522c53df197b17cd4a247f12e921` |
| SSDEEP | `3072:PpHd8lUqfrzzpFZ3TOzCajrROPzfIDETq9Z:Pp9QNfrzd3TO+a3kLID19Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_96990250
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9699025026d72bc780f108afe1749ef36fc109b91d90a9225bbd0e6e90102fcd"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-08-02 00:42:28"
  condition:
    hash.sha256(0, filesize) == "9699025026d72bc780f108afe1749ef36fc109b91d90a9225bbd0e6e90102fcd"
}
```

### Sample 55: `69e9c7d448f0171c`

| Field | Value |
|---|---|
| SHA-256 | `69e9c7d448f0171c34feb8af04e09d576ab33b105b4c57efbd72aada686401a0` |
| Family label | `Mirai` |
| File name | `zero.i486` |
| File type | `elf` |
| First seen | `2026-08-02 00:42:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `649defd344c72648a14a3c062e673927` |
| SHA-1 | `86fa96ff0c97efc2f96872d0af29623b074c6403` |
| SHA-256 | `69e9c7d448f0171c34feb8af04e09d576ab33b105b4c57efbd72aada686401a0` |
| SHA3-384 | `2f30063c7bbc9c621ddf0bbd13cc8510a4a8c2976bf6473e71bce72b1b7cd4d584e4860ffb980cd5d4a2366fc41838e9` |
| TLSH | `T1D8A32B1DD783E9F0C9420AB0115FBB379931C8E12230ADFBE7E47ED6A961781A456E1C` |
| TELFHASH | `t10031c5b556b908d8abc06502f14f6b709d5db67f3110b6934bf3a0113767a8263abc3d` |
| SSDEEP | `3072:Uw5rY9IfnpLUuZY7rrrG4YHLJnlAcDeBbyKDOhdP:Uw5rY9IfnpLXY7rrr3YtBDNrP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_69e9c7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69e9c7d448f0171c34feb8af04e09d576ab33b105b4c57efbd72aada686401a0"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-08-02 00:42:25"
  condition:
    hash.sha256(0, filesize) == "69e9c7d448f0171c34feb8af04e09d576ab33b105b4c57efbd72aada686401a0"
}
```

### Sample 56: `6d987d86a194619f`

| Field | Value |
|---|---|
| SHA-256 | `6d987d86a194619f432a0e317c0bc4490fc3d25113ab3880018a4da7cdb5f3de` |
| Family label | `Mirai` |
| File name | `morte.arm6` |
| File type | `elf` |
| First seen | `2026-08-02 00:41:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08287f0ca3af805842739aa50af9b8f3` |
| SHA-1 | `06284449156bb67999acf067f47dd0048a68519d` |
| SHA-256 | `6d987d86a194619f432a0e317c0bc4490fc3d25113ab3880018a4da7cdb5f3de` |
| SHA3-384 | `ee112fc1054f0ef841bbaa50f81ca487fcf769611690f7b4ba302824d27da02f6d5a0859958d5400b345a6e97f99ed12` |
| TLSH | `T1F223F1E4801294E38DF11D3DEDA805C22E94B3F19A1F707527BBE151ADA209F7AD6892` |
| SSDEEP | `1536:rkjf1IqoN8F9rahm7QstqeRS++LzD53IPXDdLV:rYt9oNA17LQek+Kf534DdLV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_6d987d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d987d86a194619f432a0e317c0bc4490fc3d25113ab3880018a4da7cdb5f3de"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-08-02 00:41:42"
  condition:
    hash.sha256(0, filesize) == "6d987d86a194619f432a0e317c0bc4490fc3d25113ab3880018a4da7cdb5f3de"
}
```

### Sample 57: `631edb65012fe8df`

| Field | Value |
|---|---|
| SHA-256 | `631edb65012fe8dff1eb511edc1660fc8cede0bafe531f507cc491654e47fd6f` |
| Family label | `Mirai` |
| File name | `zero.i486` |
| File type | `elf` |
| First seen | `2026-08-02 00:41:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7e79791d415c7a7f2968dce6c6bf48f` |
| SHA-1 | `0d250e3b3ddda504c8c68c638937bc7a1e19e4e9` |
| SHA-256 | `631edb65012fe8dff1eb511edc1660fc8cede0bafe531f507cc491654e47fd6f` |
| SHA3-384 | `2ce8897482b44e688b75e61a4f492f35c7ae94329509fb795da3f401fa6baa9bb211c9f1edeeb3bc596d3484359c2f22` |
| TLSH | `T1B313E0A3D6FD6E81C56102731E3E1A26AC2AD50E91419CEB7BE0247B20D7B1C7E0598B` |
| SSDEEP | `768:XCkO5tOKfhaFFTnUqVcLJCLUD5KG0HOdrLG9FUfAnd4YCbEnbcuyD7UkWykkAe:XRO5tOK0ZnUqCgif0HELG9FUoOJbEnoV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_631edb65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "631edb65012fe8dff1eb511edc1660fc8cede0bafe531f507cc491654e47fd6f"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-08-02 00:41:41"
  condition:
    hash.sha256(0, filesize) == "631edb65012fe8dff1eb511edc1660fc8cede0bafe531f507cc491654e47fd6f"
}
```

### Sample 58: `3178e838e991d587`

| Field | Value |
|---|---|
| SHA-256 | `3178e838e991d58717ede5115f146b7ff6882aeaada063e0243d50f5c5d85122` |
| Family label | `Mirai` |
| File name | `zero.arc` |
| File type | `elf` |
| First seen | `2026-08-02 00:40:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69cd092182dcdb51abd81a7d88478569` |
| SHA-1 | `45bc1a0f54e590b865325934f610a8b4f5c3d0fb` |
| SHA-256 | `3178e838e991d58717ede5115f146b7ff6882aeaada063e0243d50f5c5d85122` |
| SHA3-384 | `b511e6156e29110962feb16c1caac517cb43b9bcaa1217fa4392917f49d5cd4af082acb14ebf0327e2edb15f48d8bd9d` |
| TLSH | `T195F3BF27724F1450C8A505F496EB9B6E3B2316404EAF5AEBBC7E233E9E730CA15407E0` |
| SSDEEP | `3072:CMgoEc8PCvuE8orM9JzHziRjiPq5qwg3Cth3TJXUZ/qq:tgoEc8Pu/gJzTPCUFCtTX8qq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_3178e838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3178e838e991d58717ede5115f146b7ff6882aeaada063e0243d50f5c5d85122"
    family = "Mirai"
    file_name = "zero.arc"
    file_type = "elf"
    first_seen = "2026-08-02 00:40:26"
  condition:
    hash.sha256(0, filesize) == "3178e838e991d58717ede5115f146b7ff6882aeaada063e0243d50f5c5d85122"
}
```

### Sample 59: `06185d74edbdc06f`

| Field | Value |
|---|---|
| SHA-256 | `06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e` |
| Family label | `njrat` |
| File name | `06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e.exe` |
| File type | `exe` |
| First seen | `2026-08-02 00:11:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, njrat, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9fbf6f35099d3dd0f984ffb7e027b35` |
| SHA-1 | `2f6e93b860cef097c863668b1f38a6f7088bcb77` |
| SHA-256 | `06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e` |
| SHA3-384 | `f63fe852aa052ee4e500c0f4ecb2b42822b9649a104c7842a6dd114742abac5db06b6e4fa78d1224e9949ee86b3980c0` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T141E4F119F6A650E8E15E4431C7488662FA773D1283D1DA2F42D0F67E6F32650BDE8B23` |
| SSDEEP | `12288:uVrlrnZXcHfoFJ3QTQyLEs6cbVDsNh9qzw87/T/xxPEyhLy4ZxUtx8VCpVf688B:inZMHfJTfLL6cZsj9qzw87/Txx/LBktM` |
| ICON-DHASH | `455d455551655945` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_059_06185d74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e"
    family = "njrat"
    file_name = "06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e.exe"
    file_type = "exe"
    first_seen = "2026-08-02 00:11:31"
  condition:
    hash.sha256(0, filesize) == "06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e"
}
```

### Sample 60: `6b465dc7cc21ba92`

| Field | Value |
|---|---|
| SHA-256 | `6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b` |
| Family label | `WannaCry` |
| File name | `92d7549c8cf73bc0f29cea5ba8991560` |
| File type | `dll` |
| First seen | `2026-08-02 00:07:23` |
| Reporter | `Xoreyo` |
| Tags | `dll, honeypot, honeypot-xore, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92d7549c8cf73bc0f29cea5ba8991560` |
| SHA-1 | `84385c351cdf4cef52b816d5864431f29c615db3` |
| SHA-256 | `6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b` |
| SHA3-384 | `335f90d8d935b14cf76a5f562518be235fe7fd5d4ffa8230b2daf10a7fdfa26f4f402dcd3c54c810edff75cb49968673` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1B636235A757CA1FCC10A6375B4778A2692B73C5A22BD9B0F9B548B220C03760FF64B53` |
| SSDEEP | `24576:RbLguEQhfdmMSirYbcMNgef0QeQjG/D8kI:RnUQqMSPbcBVQej/` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_060_6b465dc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
    family = "WannaCry"
    file_name = "92d7549c8cf73bc0f29cea5ba8991560"
    file_type = "dll"
    first_seen = "2026-08-02 00:07:23"
  condition:
    hash.sha256(0, filesize) == "6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
}
```

### Sample 61: `6bcd0a97bb8c444b`

| Field | Value |
|---|---|
| SHA-256 | `6bcd0a97bb8c444b66e686e2bceb32cccf4090f13b6b5ed778c0341e31fe9d8a` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.36984827` |
| File type | `exe` |
| First seen | `2026-08-01 23:53:16` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eef744fd80a3520d1c67e6eb98f091bc` |
| SHA-1 | `548a5108fef4d712e6e8ca26223be5aade0bf89d` |
| SHA-256 | `6bcd0a97bb8c444b66e686e2bceb32cccf4090f13b6b5ed778c0341e31fe9d8a` |
| SHA3-384 | `14629934939e3c9f51c2c64f78aa50057377eb8ae6667a810444d47ffb610fbf9a2761820d42534b10a7f12806d0d2f5` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T1A6E52398BE9A7671E033C3F783A728FD711A37908B648D5E35896B106D13428BCBB355` |
| SSDEEP | `49152:xAOZA9sAXMRPEGt60S+6lCUiGj40257NyyDhl5KrDZADcTZ:uOZAERdj6NgJheBHF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_6bcd0a97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bcd0a97bb8c444b66e686e2bceb32cccf4090f13b6b5ed778c0341e31fe9d8a"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.36984827"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:16"
  condition:
    hash.sha256(0, filesize) == "6bcd0a97bb8c444b66e686e2bceb32cccf4090f13b6b5ed778c0341e31fe9d8a"
}
```

### Sample 62: `a94e9aca1aca0c7e`

| Field | Value |
|---|---|
| SHA-256 | `a94e9aca1aca0c7e006a0d8684c5423b1a3bd7e48734eee4f12f0caa3b5d901a` |
| Family label | `CoinMiner` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.64356642` |
| File type | `exe` |
| First seen | `2026-08-01 23:53:15` |
| Reporter | `SecuriteInfoCom` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be2f08950440b3bb987fc5d0999b3f1f` |
| SHA-1 | `689a96b72e20cc501fa145637d1cdc3f76d68a3c` |
| SHA-256 | `a94e9aca1aca0c7e006a0d8684c5423b1a3bd7e48734eee4f12f0caa3b5d901a` |
| SHA3-384 | `78acc2157bcf628fc6a7983819c54b58b15f2eb9122e470f72bfe0b535f14647b4965f6b6129605f7c6cee8e1e74245e` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1AF36338A78CF6074C48BC7A5853A306DB075BBE55B647C0A7FCD54548EAAF18A43C3CA` |
| SSDEEP | `98304:4cOQTlHoQK8lS9TvPcBI2jJZcTkGZ2NRT+2lqGWl0bzcncr/YQBv:4JQTKXyS9rPyPrHT+2sVWHcbQB` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_062_a94e9aca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a94e9aca1aca0c7e006a0d8684c5423b1a3bd7e48734eee4f12f0caa3b5d901a"
    family = "CoinMiner"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.64356642"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:15"
  condition:
    hash.sha256(0, filesize) == "a94e9aca1aca0c7e006a0d8684c5423b1a3bd7e48734eee4f12f0caa3b5d901a"
}
```

### Sample 63: `c1fd57d1c2fa32e5`

| Field | Value |
|---|---|
| SHA-256 | `c1fd57d1c2fa32e530ce16b95a306e98cd098e44e4599e9daa5d700d0a437814` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.37843656` |
| File type | `exe` |
| First seen | `2026-08-01 23:53:14` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a339cb67c78539655af90e4ff14de0e` |
| SHA-1 | `b539e3a90222b09bedcd2cf7484e4f63a5bf7f4d` |
| SHA-256 | `c1fd57d1c2fa32e530ce16b95a306e98cd098e44e4599e9daa5d700d0a437814` |
| SHA3-384 | `f83163e8ae798a0f627a346a17152473f40912edf2901db76882b0b6ac0c61e28371f7452243125247fd483c2ff41178` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T183D523D264F65974D07BC3B28F92E87CB059BB818A608E0BF6CE7540DD23689A537770` |
| SSDEEP | `49152:ypvDoNFFOpa9cEn5JTS4i1KIRyuEy9LqGQZB/pAgVLB4IM:yp7UOoD5JS4Y17Jqb/s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_c1fd57d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1fd57d1c2fa32e530ce16b95a306e98cd098e44e4599e9daa5d700d0a437814"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.37843656"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:14"
  condition:
    hash.sha256(0, filesize) == "c1fd57d1c2fa32e530ce16b95a306e98cd098e44e4599e9daa5d700d0a437814"
}
```

### Sample 64: `b193be680eff393e`

| Field | Value |
|---|---|
| SHA-256 | `b193be680eff393e70bd8dba2b8b1d84249b729191aa8a5014ab884360cdc9c3` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Evo-gen.79735182` |
| File type | `exe` |
| First seen | `2026-08-01 23:53:12` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c5a4089bafd03e67e7afdad3985523f` |
| SHA-1 | `c16f7496e4cf87e816b98f0bb134ac77e577e1c1` |
| SHA-256 | `b193be680eff393e70bd8dba2b8b1d84249b729191aa8a5014ab884360cdc9c3` |
| SHA3-384 | `f6c3ec6dafea2fcf9851466d1b8b7a6a7a137cd8aaddc8fef1d3db70b74b1ed229708f33b31d3d20c5b504dc7225ebd7` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T192D5239A79FA0930C877C3B29F03F07DB01ABB5A8B618D47F6D865109E136986437772` |
| SSDEEP | `49152:8KtbOOWSuMJSPPDfV3uiW+BQg2iUO9xvBSOjO/YD8IGMpIzYzeFaIh9:1bjAXdVW+CkBLBSEOqQUI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_b193be68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b193be680eff393e70bd8dba2b8b1d84249b729191aa8a5014ab884360cdc9c3"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.79735182"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:12"
  condition:
    hash.sha256(0, filesize) == "b193be680eff393e70bd8dba2b8b1d84249b729191aa8a5014ab884360cdc9c3"
}
```

### Sample 65: `0ec1ed0daf72e7f3`

| Field | Value |
|---|---|
| SHA-256 | `0ec1ed0daf72e7f3b2a9afb44d8e2de77b97b126788e54e0cb948cc176de91ba` |
| Family label | `NanoCore` |
| File name | `1a5e935a2545bde844f7aa04d6bce296.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:45:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a5e935a2545bde844f7aa04d6bce296` |
| SHA-1 | `31943eb5d52b7f2af3f21db0a2d078899274033b` |
| SHA-256 | `0ec1ed0daf72e7f3b2a9afb44d8e2de77b97b126788e54e0cb948cc176de91ba` |
| SHA3-384 | `ee8a5a2659f9e907265e8387263e401fa38b7d836fa37eec76d75b271596ef89cf3b2a2519460411a38d134afa38c2a7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E614CF6677A8492FE2DE867D601212529379C2E39CC3F3EE58D854B38F227E44A071D3` |
| SSDEEP | `3072:MzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HIAHwKNdlIhtRSE8KaDtyvLGVQd:MLV6Bta6dtJmakIM5zTw37ax4L24` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_065_0ec1ed0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ec1ed0daf72e7f3b2a9afb44d8e2de77b97b126788e54e0cb948cc176de91ba"
    family = "NanoCore"
    file_name = "1a5e935a2545bde844f7aa04d6bce296.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:45:05"
  condition:
    hash.sha256(0, filesize) == "0ec1ed0daf72e7f3b2a9afb44d8e2de77b97b126788e54e0cb948cc176de91ba"
}
```

### Sample 66: `0f0fd4870160fab8`

| Field | Value |
|---|---|
| SHA-256 | `0f0fd4870160fab8ca35512ecef8425e8c0e733f7a771109598e8efa36fc42e3` |
| Family label | `RustyStealer` |
| File name | `nvidia-runtimer.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:33:16` |
| Reporter | `cxiao` |
| Tags | `exe, LabubaRAT, rust, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b37fec109ca8e946266eb1bdf8ac1cd` |
| SHA-1 | `0c1e615682656ef0567acd7a9dc4a1336cd67831` |
| SHA-256 | `0f0fd4870160fab8ca35512ecef8425e8c0e733f7a771109598e8efa36fc42e3` |
| SHA3-384 | `ed2dd0147e95d433e6f8ae77322392b45ae310b5af1ec5af0091c5385a3b6e0276bf346ce525bacc42c79c5e2280168f` |
| IMPHASH | `246a347f07eeee769d4ff08b3997a170` |
| TLSH | `T17CA65B43F6A291ECC16AC074835A6233FB72B84907217AEB57D486313F52FE06A7D719` |
| SSDEEP | `98304:YHKJElk0e+uXuzE9/c3m9u9CNJ4H3Fdyr0g3FMzCFoDC2rA/95Bn+:USMcNI42zCCDCWA/B` |
| ICON-DHASH | `9cf0c096b0c2bec0` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_066_0f0fd487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f0fd4870160fab8ca35512ecef8425e8c0e733f7a771109598e8efa36fc42e3"
    family = "RustyStealer"
    file_name = "nvidia-runtimer.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:33:16"
  condition:
    hash.sha256(0, filesize) == "0f0fd4870160fab8ca35512ecef8425e8c0e733f7a771109598e8efa36fc42e3"
}
```

### Sample 67: `43520016f45b231d`

| Field | Value |
|---|---|
| SHA-256 | `43520016f45b231de67e5797be498a3fe9a473952db29de40c6223291149a86c` |
| Family label | `unknown` |
| File name | `ipxroute.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:25:25` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0290e0528b1394e8346ee34023e98575` |
| SHA-256 | `43520016f45b231de67e5797be498a3fe9a473952db29de40c6223291149a86c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_43520016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43520016f45b231de67e5797be498a3fe9a473952db29de40c6223291149a86c"
    family = "unknown"
    file_name = "ipxroute.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:25"
  condition:
    hash.sha256(0, filesize) == "43520016f45b231de67e5797be498a3fe9a473952db29de40c6223291149a86c"
}
```

### Sample 68: `400fc5b426841f1f`

| Field | Value |
|---|---|
| SHA-256 | `400fc5b426841f1fa22ed8c3293638186754caea8d8d4ec7d3bab45c51cef08a` |
| Family label | `unknown` |
| File name | `searchindexer.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:25:17` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3f915597152c11f877fd3dff8c4ad97` |
| SHA-256 | `400fc5b426841f1fa22ed8c3293638186754caea8d8d4ec7d3bab45c51cef08a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_400fc5b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "400fc5b426841f1fa22ed8c3293638186754caea8d8d4ec7d3bab45c51cef08a"
    family = "unknown"
    file_name = "searchindexer.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:17"
  condition:
    hash.sha256(0, filesize) == "400fc5b426841f1fa22ed8c3293638186754caea8d8d4ec7d3bab45c51cef08a"
}
```

### Sample 69: `bfdb1d343244c126`

| Field | Value |
|---|---|
| SHA-256 | `bfdb1d343244c126b015fb25d6fcf60433969318f137bac6f489a56b6035d619` |
| Family label | `unknown` |
| File name | `mblctr.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:25:12` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e6915867800e87047a23fd0b3b6a86a` |
| SHA-256 | `bfdb1d343244c126b015fb25d6fcf60433969318f137bac6f489a56b6035d619` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_bfdb1d34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfdb1d343244c126b015fb25d6fcf60433969318f137bac6f489a56b6035d619"
    family = "unknown"
    file_name = "mblctr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:12"
  condition:
    hash.sha256(0, filesize) == "bfdb1d343244c126b015fb25d6fcf60433969318f137bac6f489a56b6035d619"
}
```

### Sample 70: `2f68440b8f04e649`

| Field | Value |
|---|---|
| SHA-256 | `2f68440b8f04e649f3b24d562459e7a63d04ca41ca643f6b8075b8f0851e0ab8` |
| Family label | `unknown` |
| File name | `expand.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:25:11` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c1a50a443d4ef189f0be5d5a7b25014` |
| SHA-1 | `a88696a78e93360aa75ad99b8627b979195d7ff6` |
| SHA-256 | `2f68440b8f04e649f3b24d562459e7a63d04ca41ca643f6b8075b8f0851e0ab8` |
| SHA3-384 | `0f4e1f7b6a0826dc91f8246910da526f6267bad95a3617e85f0739f121539fadcd53b6c3f85b7d95a559b99966577a32` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T194463308B3E809E2E9B3D039C5565621D573B5254BB0D1CF03AC9A762F676E0AF3BB50` |
| SSDEEP | `98304:bugt2RLICDtPfeE/jowqK5LN1KQ0oTh2M9QrABlolllbHSZMPM66J:PEICteErownP0oTcMsABqlBn6` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_2f68440b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f68440b8f04e649f3b24d562459e7a63d04ca41ca643f6b8075b8f0851e0ab8"
    family = "unknown"
    file_name = "expand.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:11"
  condition:
    hash.sha256(0, filesize) == "2f68440b8f04e649f3b24d562459e7a63d04ca41ca643f6b8075b8f0851e0ab8"
}
```

### Sample 71: `c8afe6e024d71b3c`

| Field | Value |
|---|---|
| SHA-256 | `c8afe6e024d71b3c6fc185f73f5a676cfd2e06feff560ed77d5b048d489a5397` |
| Family label | `unknown` |
| File name | `w32tm.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:25:05` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7aa3c4fb8fad3005c8542b88080a3eaf` |
| SHA-256 | `c8afe6e024d71b3c6fc185f73f5a676cfd2e06feff560ed77d5b048d489a5397` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_c8afe6e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8afe6e024d71b3c6fc185f73f5a676cfd2e06feff560ed77d5b048d489a5397"
    family = "unknown"
    file_name = "w32tm.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:05"
  condition:
    hash.sha256(0, filesize) == "c8afe6e024d71b3c6fc185f73f5a676cfd2e06feff560ed77d5b048d489a5397"
}
```

### Sample 72: `d441c338d7af4ac5`

| Field | Value |
|---|---|
| SHA-256 | `d441c338d7af4ac5301081e9a91723fd1ab303ff59162a4e09b31b48c6f87267` |
| Family label | `unknown` |
| File name | `msdt.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:25:02` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f370beeec713cac0029e11714d5a116d` |
| SHA-256 | `d441c338d7af4ac5301081e9a91723fd1ab303ff59162a4e09b31b48c6f87267` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_d441c338
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d441c338d7af4ac5301081e9a91723fd1ab303ff59162a4e09b31b48c6f87267"
    family = "unknown"
    file_name = "msdt.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:02"
  condition:
    hash.sha256(0, filesize) == "d441c338d7af4ac5301081e9a91723fd1ab303ff59162a4e09b31b48c6f87267"
}
```

### Sample 73: `373ca0a0e89006ec`

| Field | Value |
|---|---|
| SHA-256 | `373ca0a0e89006ec968611fb0c15a569e3c12f338292df69fbeba45d0db37828` |
| Family label | `unknown` |
| File name | `qwinsta.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:59` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `509c1d22c8531ad79ee67d83d042c193` |
| SHA-256 | `373ca0a0e89006ec968611fb0c15a569e3c12f338292df69fbeba45d0db37828` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_373ca0a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "373ca0a0e89006ec968611fb0c15a569e3c12f338292df69fbeba45d0db37828"
    family = "unknown"
    file_name = "qwinsta.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:59"
  condition:
    hash.sha256(0, filesize) == "373ca0a0e89006ec968611fb0c15a569e3c12f338292df69fbeba45d0db37828"
}
```

### Sample 74: `9d88e9dd9f5fab20`

| Field | Value |
|---|---|
| SHA-256 | `9d88e9dd9f5fab20b1ec58533231e33c5307057cd8dd98046fff7e2c19442a9c` |
| Family label | `unknown` |
| File name | `wuauclt.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:56` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae9a9e316d414401b633f70de7d23c35` |
| SHA-256 | `9d88e9dd9f5fab20b1ec58533231e33c5307057cd8dd98046fff7e2c19442a9c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_9d88e9dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d88e9dd9f5fab20b1ec58533231e33c5307057cd8dd98046fff7e2c19442a9c"
    family = "unknown"
    file_name = "wuauclt.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:56"
  condition:
    hash.sha256(0, filesize) == "9d88e9dd9f5fab20b1ec58533231e33c5307057cd8dd98046fff7e2c19442a9c"
}
```

### Sample 75: `38e3500020a3b0e9`

| Field | Value |
|---|---|
| SHA-256 | `38e3500020a3b0e9747fca7a7c85cf51e4e1c29c0fcce2da19b1376e5ebc9f0a` |
| Family label | `unknown` |
| File name | `ipconfig.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:45` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db5184df2e9d747376554a4877983cb6` |
| SHA-256 | `38e3500020a3b0e9747fca7a7c85cf51e4e1c29c0fcce2da19b1376e5ebc9f0a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_38e35000
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38e3500020a3b0e9747fca7a7c85cf51e4e1c29c0fcce2da19b1376e5ebc9f0a"
    family = "unknown"
    file_name = "ipconfig.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:45"
  condition:
    hash.sha256(0, filesize) == "38e3500020a3b0e9747fca7a7c85cf51e4e1c29c0fcce2da19b1376e5ebc9f0a"
}
```

### Sample 76: `fd1c66931da5e031`

| Field | Value |
|---|---|
| SHA-256 | `fd1c66931da5e03116d24e861246d8d8c5f398cd6e73e47b06f04afcf372ec20` |
| Family label | `unknown` |
| File name | `winver.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:33` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `704ea1143d7aea6bc5e7476889ecaf1e` |
| SHA-256 | `fd1c66931da5e03116d24e861246d8d8c5f398cd6e73e47b06f04afcf372ec20` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_fd1c6693
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd1c66931da5e03116d24e861246d8d8c5f398cd6e73e47b06f04afcf372ec20"
    family = "unknown"
    file_name = "winver.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:33"
  condition:
    hash.sha256(0, filesize) == "fd1c66931da5e03116d24e861246d8d8c5f398cd6e73e47b06f04afcf372ec20"
}
```

### Sample 77: `872cf388fa9db1f2`

| Field | Value |
|---|---|
| SHA-256 | `872cf388fa9db1f2045d9cb6b70d46f6b0d582ae434d86417956f45220620ca7` |
| Family label | `unknown` |
| File name | `cmd.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:18` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f793880330f0b3b35dac75dd97727ea9` |
| SHA-256 | `872cf388fa9db1f2045d9cb6b70d46f6b0d582ae434d86417956f45220620ca7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_872cf388
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872cf388fa9db1f2045d9cb6b70d46f6b0d582ae434d86417956f45220620ca7"
    family = "unknown"
    file_name = "cmd.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:18"
  condition:
    hash.sha256(0, filesize) == "872cf388fa9db1f2045d9cb6b70d46f6b0d582ae434d86417956f45220620ca7"
}
```

### Sample 78: `523d5347de7d2a9f`

| Field | Value |
|---|---|
| SHA-256 | `523d5347de7d2a9f4de3f66e5c108c0ab268b11ff251cef94457a0907da0b048` |
| Family label | `unknown` |
| File name | `spoolsv.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:11` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e00535389e02712fcf6d2e1458c84be3` |
| SHA-256 | `523d5347de7d2a9f4de3f66e5c108c0ab268b11ff251cef94457a0907da0b048` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_523d5347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "523d5347de7d2a9f4de3f66e5c108c0ab268b11ff251cef94457a0907da0b048"
    family = "unknown"
    file_name = "spoolsv.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:11"
  condition:
    hash.sha256(0, filesize) == "523d5347de7d2a9f4de3f66e5c108c0ab268b11ff251cef94457a0907da0b048"
}
```

### Sample 79: `fd1063e2d8af2eed`

| Field | Value |
|---|---|
| SHA-256 | `fd1063e2d8af2eedaf59f388ac4534f27d3933ca3e6e244f7be056044e685c13` |
| Family label | `unknown` |
| File name | `icacls.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:11` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17e26e05477009fa87f9bc4ca4baa374` |
| SHA-256 | `fd1063e2d8af2eedaf59f388ac4534f27d3933ca3e6e244f7be056044e685c13` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_fd1063e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd1063e2d8af2eedaf59f388ac4534f27d3933ca3e6e244f7be056044e685c13"
    family = "unknown"
    file_name = "icacls.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:11"
  condition:
    hash.sha256(0, filesize) == "fd1063e2d8af2eedaf59f388ac4534f27d3933ca3e6e244f7be056044e685c13"
}
```

### Sample 80: `5630f2a1acdc2142`

| Field | Value |
|---|---|
| SHA-256 | `5630f2a1acdc21427d6259e9040bfb9f6959640b5a8f58576f36cca7c25bc99a` |
| Family label | `unknown` |
| File name | `mmc.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:24:01` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b68a6b6b97930d21bd7078985ee380c9` |
| SHA-256 | `5630f2a1acdc21427d6259e9040bfb9f6959640b5a8f58576f36cca7c25bc99a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5630f2a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5630f2a1acdc21427d6259e9040bfb9f6959640b5a8f58576f36cca7c25bc99a"
    family = "unknown"
    file_name = "mmc.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:01"
  condition:
    hash.sha256(0, filesize) == "5630f2a1acdc21427d6259e9040bfb9f6959640b5a8f58576f36cca7c25bc99a"
}
```

### Sample 81: `bd9bc8659065964c`

| Field | Value |
|---|---|
| SHA-256 | `bd9bc8659065964c42e3eb062e79d46d4f368e802dc68d9232d86e01b0ee5342` |
| Family label | `unknown` |
| File name | `eventvwr.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:56` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7ad0fa61443bde12b789ba02f8786c0` |
| SHA-1 | `3c41d0e8a3b71a8e042d6c4a1e125f8a448dc47a` |
| SHA-256 | `bd9bc8659065964c42e3eb062e79d46d4f368e802dc68d9232d86e01b0ee5342` |
| SHA3-384 | `c5ac13f9ec04209ad4c9c0b58ed8db1df36386828d931a95907dde55463301af8de0ec6cd4a29f4b446c7929475f6ad6` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1A8463308B3A809D6E6B3D53D81565211D872B4264BB0D2CF43AC9B662F777D0AE3FB50` |
| SSDEEP | `98304:6CgtvzICDtPfeE/jowqK5LN1KQ0oTh2M9QrABlolllXHhM3wh6zrq:k7ICteErownP0oTcMsABqlkgcze` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_bd9bc865
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd9bc8659065964c42e3eb062e79d46d4f368e802dc68d9232d86e01b0ee5342"
    family = "unknown"
    file_name = "eventvwr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:56"
  condition:
    hash.sha256(0, filesize) == "bd9bc8659065964c42e3eb062e79d46d4f368e802dc68d9232d86e01b0ee5342"
}
```

### Sample 82: `209794740e72dc14`

| Field | Value |
|---|---|
| SHA-256 | `209794740e72dc14164fcb4c9cc8329e036dfe3e786c3f17c64eddd749f6f071` |
| Family label | `unknown` |
| File name | `chkdsk.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:55` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afac74635e2cc6fb371c51c6a905f310` |
| SHA-256 | `209794740e72dc14164fcb4c9cc8329e036dfe3e786c3f17c64eddd749f6f071` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_20979474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "209794740e72dc14164fcb4c9cc8329e036dfe3e786c3f17c64eddd749f6f071"
    family = "unknown"
    file_name = "chkdsk.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:55"
  condition:
    hash.sha256(0, filesize) == "209794740e72dc14164fcb4c9cc8329e036dfe3e786c3f17c64eddd749f6f071"
}
```

### Sample 83: `600b2f3979aa534b`

| Field | Value |
|---|---|
| SHA-256 | `600b2f3979aa534bcfac6faea5da715d48b14c1a081ffaebdf7732b354797a79` |
| Family label | `unknown` |
| File name | `vssadmin.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:47` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61844ba5da6717cd7e52902c3ccde171` |
| SHA-256 | `600b2f3979aa534bcfac6faea5da715d48b14c1a081ffaebdf7732b354797a79` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_600b2f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "600b2f3979aa534bcfac6faea5da715d48b14c1a081ffaebdf7732b354797a79"
    family = "unknown"
    file_name = "vssadmin.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:47"
  condition:
    hash.sha256(0, filesize) == "600b2f3979aa534bcfac6faea5da715d48b14c1a081ffaebdf7732b354797a79"
}
```

### Sample 84: `0ac2dd4e7b97149c`

| Field | Value |
|---|---|
| SHA-256 | `0ac2dd4e7b97149caba8e0e2af7c41f3d98023873ebdea1122c8a28b7a2ac198` |
| Family label | `unknown` |
| File name | `lpq.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:42` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `518dc6f4c1c867ee5e96682523201209` |
| SHA-256 | `0ac2dd4e7b97149caba8e0e2af7c41f3d98023873ebdea1122c8a28b7a2ac198` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_0ac2dd4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ac2dd4e7b97149caba8e0e2af7c41f3d98023873ebdea1122c8a28b7a2ac198"
    family = "unknown"
    file_name = "lpq.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:42"
  condition:
    hash.sha256(0, filesize) == "0ac2dd4e7b97149caba8e0e2af7c41f3d98023873ebdea1122c8a28b7a2ac198"
}
```

### Sample 85: `9115a6e66a79b24a`

| Field | Value |
|---|---|
| SHA-256 | `9115a6e66a79b24af7a2596f82fe39013d67e6bd14009d52c8f377c4cc5fc6b7` |
| Family label | `unknown` |
| File name | `telnet.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:42` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c65edd48805362e830d91bb1d0f9ae07` |
| SHA-256 | `9115a6e66a79b24af7a2596f82fe39013d67e6bd14009d52c8f377c4cc5fc6b7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_9115a6e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9115a6e66a79b24af7a2596f82fe39013d67e6bd14009d52c8f377c4cc5fc6b7"
    family = "unknown"
    file_name = "telnet.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:42"
  condition:
    hash.sha256(0, filesize) == "9115a6e66a79b24af7a2596f82fe39013d67e6bd14009d52c8f377c4cc5fc6b7"
}
```

### Sample 86: `aeed1f8809aeecf2`

| Field | Value |
|---|---|
| SHA-256 | `aeed1f8809aeecf255a9409743d560b94bdee20a37b2670f9c37b755b2422a99` |
| Family label | `unknown` |
| File name | `regsvr32.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:32` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed706ea71fc22ff750877f7b34ca59b5` |
| SHA-256 | `aeed1f8809aeecf255a9409743d560b94bdee20a37b2670f9c37b755b2422a99` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_aeed1f88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeed1f8809aeecf255a9409743d560b94bdee20a37b2670f9c37b755b2422a99"
    family = "unknown"
    file_name = "regsvr32.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:32"
  condition:
    hash.sha256(0, filesize) == "aeed1f8809aeecf255a9409743d560b94bdee20a37b2670f9c37b755b2422a99"
}
```

### Sample 87: `50d79d022c8f149e`

| Field | Value |
|---|---|
| SHA-256 | `50d79d022c8f149e3d28f645b32925377df42f8ccd71905a8a73862172d4c893` |
| Family label | `unknown` |
| File name | `forfiles.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:13` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae7c58f615880e907772ef9c5673354a` |
| SHA-256 | `50d79d022c8f149e3d28f645b32925377df42f8ccd71905a8a73862172d4c893` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_50d79d02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d79d022c8f149e3d28f645b32925377df42f8ccd71905a8a73862172d4c893"
    family = "unknown"
    file_name = "forfiles.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:13"
  condition:
    hash.sha256(0, filesize) == "50d79d022c8f149e3d28f645b32925377df42f8ccd71905a8a73862172d4c893"
}
```

### Sample 88: `5a756182c6ed8a91`

| Field | Value |
|---|---|
| SHA-256 | `5a756182c6ed8a913fe6ee79892d07b1e71cd8e20ca8096927c3cd150d4a8ba2` |
| Family label | `unknown` |
| File name | `bcdedit.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:09` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9831260de4e5c2e2c620b1a92e5e9a32` |
| SHA-256 | `5a756182c6ed8a913fe6ee79892d07b1e71cd8e20ca8096927c3cd150d4a8ba2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_5a756182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a756182c6ed8a913fe6ee79892d07b1e71cd8e20ca8096927c3cd150d4a8ba2"
    family = "unknown"
    file_name = "bcdedit.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:09"
  condition:
    hash.sha256(0, filesize) == "5a756182c6ed8a913fe6ee79892d07b1e71cd8e20ca8096927c3cd150d4a8ba2"
}
```

### Sample 89: `60192de00b87c968`

| Field | Value |
|---|---|
| SHA-256 | `60192de00b87c9684aa653ea15ea60640d0b6497bc855efd5fc66272f0d17d35` |
| Family label | `unknown` |
| File name | `sysprep.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:23:01` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c6471fb9507d46b98088d789eb0a8fe` |
| SHA-256 | `60192de00b87c9684aa653ea15ea60640d0b6497bc855efd5fc66272f0d17d35` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_60192de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60192de00b87c9684aa653ea15ea60640d0b6497bc855efd5fc66272f0d17d35"
    family = "unknown"
    file_name = "sysprep.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:01"
  condition:
    hash.sha256(0, filesize) == "60192de00b87c9684aa653ea15ea60640d0b6497bc855efd5fc66272f0d17d35"
}
```

### Sample 90: `a3c6726b13bf4a79`

| Field | Value |
|---|---|
| SHA-256 | `a3c6726b13bf4a7904ab8bd91f6d2d7596ab005cba246b2a59ee318ba727fff8` |
| Family label | `unknown` |
| File name | `vds.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:58` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a33faf605da382fb0003356b167d5e74` |
| SHA-256 | `a3c6726b13bf4a7904ab8bd91f6d2d7596ab005cba246b2a59ee318ba727fff8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_a3c6726b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c6726b13bf4a7904ab8bd91f6d2d7596ab005cba246b2a59ee318ba727fff8"
    family = "unknown"
    file_name = "vds.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:58"
  condition:
    hash.sha256(0, filesize) == "a3c6726b13bf4a7904ab8bd91f6d2d7596ab005cba246b2a59ee318ba727fff8"
}
```

### Sample 91: `fabfa7b111d9105d`

| Field | Value |
|---|---|
| SHA-256 | `fabfa7b111d9105d9d40091ae62151c5b882e7115eb5e3d27e18e0228600a515` |
| Family label | `unknown` |
| File name | `sfc.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:53` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58a01ebace0949d14a73b077be98013a` |
| SHA-256 | `fabfa7b111d9105d9d40091ae62151c5b882e7115eb5e3d27e18e0228600a515` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_fabfa7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fabfa7b111d9105d9d40091ae62151c5b882e7115eb5e3d27e18e0228600a515"
    family = "unknown"
    file_name = "sfc.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:53"
  condition:
    hash.sha256(0, filesize) == "fabfa7b111d9105d9d40091ae62151c5b882e7115eb5e3d27e18e0228600a515"
}
```

### Sample 92: `fa1115eb9670ae43`

| Field | Value |
|---|---|
| SHA-256 | `fa1115eb9670ae43ecba6f995c78ce6ffa7ff101fea1373d082b66d531c5c288` |
| Family label | `unknown` |
| File name | `tscon.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:44` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06aede3c96e3f0951339fc71c2521ba9` |
| SHA-256 | `fa1115eb9670ae43ecba6f995c78ce6ffa7ff101fea1373d082b66d531c5c288` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_fa1115eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa1115eb9670ae43ecba6f995c78ce6ffa7ff101fea1373d082b66d531c5c288"
    family = "unknown"
    file_name = "tscon.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:44"
  condition:
    hash.sha256(0, filesize) == "fa1115eb9670ae43ecba6f995c78ce6ffa7ff101fea1373d082b66d531c5c288"
}
```

### Sample 93: `03e37a82cf86dab6`

| Field | Value |
|---|---|
| SHA-256 | `03e37a82cf86dab6c21f370985eb86698ee8aadd1910cab7e3a17cce5a385248` |
| Family label | `unknown` |
| File name | `msiexec.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:37` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbccad4eb9b77c1bd99442da8417f0cb` |
| SHA-256 | `03e37a82cf86dab6c21f370985eb86698ee8aadd1910cab7e3a17cce5a385248` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_03e37a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03e37a82cf86dab6c21f370985eb86698ee8aadd1910cab7e3a17cce5a385248"
    family = "unknown"
    file_name = "msiexec.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:37"
  condition:
    hash.sha256(0, filesize) == "03e37a82cf86dab6c21f370985eb86698ee8aadd1910cab7e3a17cce5a385248"
}
```

### Sample 94: `8fd8ed7459c026a5`

| Field | Value |
|---|---|
| SHA-256 | `8fd8ed7459c026a542e961e2d3f4f4f9d5378ac3ba587d885e94270314837cf1` |
| Family label | `unknown` |
| File name | `diskpart.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:33` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e71a0e198e0eb52a961502c408a90f25` |
| SHA-256 | `8fd8ed7459c026a542e961e2d3f4f4f9d5378ac3ba587d885e94270314837cf1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_8fd8ed74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd8ed7459c026a542e961e2d3f4f4f9d5378ac3ba587d885e94270314837cf1"
    family = "unknown"
    file_name = "diskpart.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:33"
  condition:
    hash.sha256(0, filesize) == "8fd8ed7459c026a542e961e2d3f4f4f9d5378ac3ba587d885e94270314837cf1"
}
```

### Sample 95: `cd9f53a2acc32016`

| Field | Value |
|---|---|
| SHA-256 | `cd9f53a2acc32016d8976a0d501e0a63d25c3cc04a07a7cb89ee2bd992b78e91` |
| Family label | `unknown` |
| File name | `ntmsmgr.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:28` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad2d720ff9c77eb3a2ccddb16439924d` |
| SHA-256 | `cd9f53a2acc32016d8976a0d501e0a63d25c3cc04a07a7cb89ee2bd992b78e91` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_cd9f53a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd9f53a2acc32016d8976a0d501e0a63d25c3cc04a07a7cb89ee2bd992b78e91"
    family = "unknown"
    file_name = "ntmsmgr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:28"
  condition:
    hash.sha256(0, filesize) == "cd9f53a2acc32016d8976a0d501e0a63d25c3cc04a07a7cb89ee2bd992b78e91"
}
```

### Sample 96: `895c874d5391cb3f`

| Field | Value |
|---|---|
| SHA-256 | `895c874d5391cb3f363e9257252598ee62c3346f4cfa54270fa049f5cd09cd88` |
| Family label | `unknown` |
| File name | `imapi.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:23` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96b6238262e8c0dcab3fee65217fab63` |
| SHA-256 | `895c874d5391cb3f363e9257252598ee62c3346f4cfa54270fa049f5cd09cd88` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_895c874d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "895c874d5391cb3f363e9257252598ee62c3346f4cfa54270fa049f5cd09cd88"
    family = "unknown"
    file_name = "imapi.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:23"
  condition:
    hash.sha256(0, filesize) == "895c874d5391cb3f363e9257252598ee62c3346f4cfa54270fa049f5cd09cd88"
}
```

### Sample 97: `a1a8db5386e8c36c`

| Field | Value |
|---|---|
| SHA-256 | `a1a8db5386e8c36ce4592ab20113b2988e8fa17f36889654f525589a6d382568` |
| Family label | `unknown` |
| File name | `mblctr.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:23` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47b6873a6d3bf039c9f12ecfd9e3773d` |
| SHA-1 | `b5fd44120fd04bb945c8f78d3ad6075aa71a38e9` |
| SHA-256 | `a1a8db5386e8c36ce4592ab20113b2988e8fa17f36889654f525589a6d382568` |
| SHA3-384 | `6ce34a3e21f1bdf9634536c379c69ee76e877dea149d00bee9741b0e48af111dab4c6b6549c0196d4ee43a69227bc5ce` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T170463308B3A808E1FAB3D13985565221D873B4254BF0D5CB43AC9B762F677E0AE3B754` |
| SSDEEP | `98304:ZkgtzTTICDtPfeE/jowqK5LN1KQ0oTh2M9QrABlolllVHlMz2i6zm:rPTICteErownP0oTcMsABqlSKtz` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_a1a8db53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1a8db5386e8c36ce4592ab20113b2988e8fa17f36889654f525589a6d382568"
    family = "unknown"
    file_name = "mblctr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:23"
  condition:
    hash.sha256(0, filesize) == "a1a8db5386e8c36ce4592ab20113b2988e8fa17f36889654f525589a6d382568"
}
```

### Sample 98: `1a382dd04ce22d5d`

| Field | Value |
|---|---|
| SHA-256 | `1a382dd04ce22d5d7ef9dacb37bb59277eff58462a27ef282a86d013a0bfb9ad` |
| Family label | `unknown` |
| File name | `wevtutil.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:19` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `659f233dfb806ecb59c7d4edc69e4c5a` |
| SHA-256 | `1a382dd04ce22d5d7ef9dacb37bb59277eff58462a27ef282a86d013a0bfb9ad` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_1a382dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a382dd04ce22d5d7ef9dacb37bb59277eff58462a27ef282a86d013a0bfb9ad"
    family = "unknown"
    file_name = "wevtutil.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:19"
  condition:
    hash.sha256(0, filesize) == "1a382dd04ce22d5d7ef9dacb37bb59277eff58462a27ef282a86d013a0bfb9ad"
}
```

### Sample 99: `dbd47856ff60b311`

| Field | Value |
|---|---|
| SHA-256 | `dbd47856ff60b3116575b28a7f385ee530e40d7048a8bffce22283ea9dee8629` |
| Family label | `unknown` |
| File name | `powershell_ise.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:15` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `532c8a1a050bf208d35148b66c301825` |
| SHA-256 | `dbd47856ff60b3116575b28a7f385ee530e40d7048a8bffce22283ea9dee8629` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_dbd47856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbd47856ff60b3116575b28a7f385ee530e40d7048a8bffce22283ea9dee8629"
    family = "unknown"
    file_name = "powershell_ise.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:15"
  condition:
    hash.sha256(0, filesize) == "dbd47856ff60b3116575b28a7f385ee530e40d7048a8bffce22283ea9dee8629"
}
```

### Sample 100: `c690250a8818a268`

| Field | Value |
|---|---|
| SHA-256 | `c690250a8818a2685c5dd6d3a89b8f00588ee2c593440ee6c0a232425af0f7c9` |
| Family label | `unknown` |
| File name | `xwizard.exe` |
| File type | `exe` |
| First seen | `2026-08-01 23:22:11` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a147cdbef2746bc96441df2231a56e45` |
| SHA-256 | `c690250a8818a2685c5dd6d3a89b8f00588ee2c593440ee6c0a232425af0f7c9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_c690250a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c690250a8818a2685c5dd6d3a89b8f00588ee2c593440ee6c0a232425af0f7c9"
    family = "unknown"
    file_name = "xwizard.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:11"
  condition:
    hash.sha256(0, filesize) == "c690250a8818a2685c5dd6d3a89b8f00588ee2c593440ee6c0a232425af0f7c9"
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
 * Generated: 2026-08-02T03:58:12.776226+00:00
 */

rule MalwareBazaar_unknown_001_dc87cc13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc87cc13bad5c4cc715ace4737ac6f303994a68ec8a772067da9765d642e1b28"
    family = "unknown"
    file_name = "Launcher.exe"
    file_type = "exe"
    first_seen = "2026-08-02 03:19:48"
  condition:
    hash.sha256(0, filesize) == "dc87cc13bad5c4cc715ace4737ac6f303994a68ec8a772067da9765d642e1b28"
}

rule MalwareBazaar_unknown_002_068fa74e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "068fa74e4843dd0a7fd1488f262281e9b6b0e19d67eb8d52b20d63fda158fd3e"
    family = "unknown"
    file_name = "Loader 9.0.11.exe"
    file_type = "exe"
    first_seen = "2026-08-02 02:45:17"
  condition:
    hash.sha256(0, filesize) == "068fa74e4843dd0a7fd1488f262281e9b6b0e19d67eb8d52b20d63fda158fd3e"
}

rule MalwareBazaar_Mirai_003_4d70c592
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d70c592117d87144a826f81b53227f2756fa93015ea251050418b7f28bfa449"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 02:18:29"
  condition:
    hash.sha256(0, filesize) == "4d70c592117d87144a826f81b53227f2756fa93015ea251050418b7f28bfa449"
}

rule MalwareBazaar_Mirai_004_ab901b24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab901b2408ef39103a2b44eccb0dd49a6fe3ba895a2f00e0fb0cc9e71890739c"
    family = "Mirai"
    file_name = "morte.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 02:17:48"
  condition:
    hash.sha256(0, filesize) == "ab901b2408ef39103a2b44eccb0dd49a6fe3ba895a2f00e0fb0cc9e71890739c"
}

rule MalwareBazaar_Mirai_005_21d8e211
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d8e211fab585677e0cf843c6ec41f0718b8f5ef32aae102d57b2a5e078b0ab"
    family = "Mirai"
    file_name = "zero.mipsel"
    file_type = "elf"
    first_seen = "2026-08-02 02:15:48"
  condition:
    hash.sha256(0, filesize) == "21d8e211fab585677e0cf843c6ec41f0718b8f5ef32aae102d57b2a5e078b0ab"
}

rule MalwareBazaar_Mirai_006_5ce18989
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce18989a7bdc92129e04ccee765ff3b1edcc3f0f7f08dc5f6755958b5a70d87"
    family = "Mirai"
    file_name = "zero.mipsel"
    file_type = "elf"
    first_seen = "2026-08-02 02:15:15"
  condition:
    hash.sha256(0, filesize) == "5ce18989a7bdc92129e04ccee765ff3b1edcc3f0f7f08dc5f6755958b5a70d87"
}

rule MalwareBazaar_unknown_007_a51580aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a51580aade05f548b87eaf1dd98e4004330dbdcd8822a6405588944c57a8d33a"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-02 02:15:14"
  condition:
    hash.sha256(0, filesize) == "a51580aade05f548b87eaf1dd98e4004330dbdcd8822a6405588944c57a8d33a"
}

rule MalwareBazaar_Mirai_008_736e09c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "736e09c587ec9320b96517f32378c1e8770ad15490d72a5113a8a62040a82166"
    family = "Mirai"
    file_name = "zero.sparc"
    file_type = "elf"
    first_seen = "2026-08-02 02:12:30"
  condition:
    hash.sha256(0, filesize) == "736e09c587ec9320b96517f32378c1e8770ad15490d72a5113a8a62040a82166"
}

rule MalwareBazaar_unknown_009_420dc609
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420dc609a9852388f9bf158e1fb7aa73032fbd7090e8217df1af504d613af30c"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-08-02 02:11:17"
  condition:
    hash.sha256(0, filesize) == "420dc609a9852388f9bf158e1fb7aa73032fbd7090e8217df1af504d613af30c"
}

rule MalwareBazaar_Mirai_010_7f49a176
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f49a17645cd8394dca58c67cb6c5ee810291f51111c632d67fb5d9c82bd1820"
    family = "Mirai"
    file_name = "morte.m68k"
    file_type = "elf"
    first_seen = "2026-08-02 02:05:26"
  condition:
    hash.sha256(0, filesize) == "7f49a17645cd8394dca58c67cb6c5ee810291f51111c632d67fb5d9c82bd1820"
}

rule MalwareBazaar_Mirai_011_c7bfdeef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7bfdeeffd0c9c3bbcb017caa8c57ef83ddfb9743209c33099c08a1389f66698"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-08-02 02:04:30"
  condition:
    hash.sha256(0, filesize) == "c7bfdeeffd0c9c3bbcb017caa8c57ef83ddfb9743209c33099c08a1389f66698"
}

rule MalwareBazaar_Mirai_012_fe95a35a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe95a35a549a6e1783f30a0727ad1b7823f7607775a34865336752a266ed304a"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-08-02 02:03:33"
  condition:
    hash.sha256(0, filesize) == "fe95a35a549a6e1783f30a0727ad1b7823f7607775a34865336752a266ed304a"
}

rule MalwareBazaar_Mirai_013_78238dfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78238dfbb4da6c6d8c04ba930deea29807c11d25e30bfd07e73d363603e57648"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-08-02 02:01:16"
  condition:
    hash.sha256(0, filesize) == "78238dfbb4da6c6d8c04ba930deea29807c11d25e30bfd07e73d363603e57648"
}

rule MalwareBazaar_Mirai_014_2df589b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2df589b5d6f301f24a0102c34655d145a203c1281034394be4f6f9dbafd750de"
    family = "Mirai"
    file_name = "morte.mips"
    file_type = "elf"
    first_seen = "2026-08-02 02:00:16"
  condition:
    hash.sha256(0, filesize) == "2df589b5d6f301f24a0102c34655d145a203c1281034394be4f6f9dbafd750de"
}

rule MalwareBazaar_unknown_015_897a5c40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "897a5c4077216fd9bb766b6a0b8fbd1c8af9c6a7550fabc74643363bdb477ef1"
    family = "unknown"
    file_name = "AI+File+Cleaner_1.0.5.xapk"
    file_type = "xapk"
    first_seen = "2026-08-02 01:57:32"
  condition:
    hash.sha256(0, filesize) == "897a5c4077216fd9bb766b6a0b8fbd1c8af9c6a7550fabc74643363bdb477ef1"
}

rule MalwareBazaar_Mirai_016_6364e72f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6364e72f4838a6e1c487a15f8b373a950d0830fa94a275cebf247dd4820da676"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-08-02 01:53:34"
  condition:
    hash.sha256(0, filesize) == "6364e72f4838a6e1c487a15f8b373a950d0830fa94a275cebf247dd4820da676"
}

rule MalwareBazaar_Mirai_017_85938a19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85938a1944c69e21ae3034e69ae7e6bee123204d15ccbf4bfdd9e90ea2ea2730"
    family = "Mirai"
    file_name = "morte.arm7"
    file_type = "elf"
    first_seen = "2026-08-02 01:53:16"
  condition:
    hash.sha256(0, filesize) == "85938a1944c69e21ae3034e69ae7e6bee123204d15ccbf4bfdd9e90ea2ea2730"
}

rule MalwareBazaar_unknown_018_01ee4d3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ee4d3f8cd104975fadd5282d27524e8c7f08335c01200434bb217a3be62917"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-02 01:53:14"
  condition:
    hash.sha256(0, filesize) == "01ee4d3f8cd104975fadd5282d27524e8c7f08335c01200434bb217a3be62917"
}

rule MalwareBazaar_Mirai_019_4744701e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4744701e8d7db089167a1709509f1f07c46323d85bdb48ba1d96921386507e1e"
    family = "Mirai"
    file_name = "morte.spc"
    file_type = "elf"
    first_seen = "2026-08-02 01:50:28"
  condition:
    hash.sha256(0, filesize) == "4744701e8d7db089167a1709509f1f07c46323d85bdb48ba1d96921386507e1e"
}

rule MalwareBazaar_Mirai_020_78610503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7861050378c2366c6ce197e14d464dfec5ad7e7a15aed97fba99e2a9bb870e91"
    family = "Mirai"
    file_name = "zero.m68k"
    file_type = "elf"
    first_seen = "2026-08-02 01:49:15"
  condition:
    hash.sha256(0, filesize) == "7861050378c2366c6ce197e14d464dfec5ad7e7a15aed97fba99e2a9bb870e91"
}

rule MalwareBazaar_Mirai_021_9c5d705f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c5d705f07e17a4bf809d384c67630ec197ac11335747e068424067fde56a9d0"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-02 01:48:32"
  condition:
    hash.sha256(0, filesize) == "9c5d705f07e17a4bf809d384c67630ec197ac11335747e068424067fde56a9d0"
}

rule MalwareBazaar_Mirai_022_09a0d0b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09a0d0b2a3b5f7af9990075bb8ddf974b9233d8b94883f63f9660642753bd667"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-02 01:47:32"
  condition:
    hash.sha256(0, filesize) == "09a0d0b2a3b5f7af9990075bb8ddf974b9233d8b94883f63f9660642753bd667"
}

rule MalwareBazaar_Mirai_023_d86694d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86694d1cbdf7af6d65e8c362ab68b3bd18a6d6a5d882416704c2409e87e1b1e"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-08-02 01:46:28"
  condition:
    hash.sha256(0, filesize) == "d86694d1cbdf7af6d65e8c362ab68b3bd18a6d6a5d882416704c2409e87e1b1e"
}

rule MalwareBazaar_Mirai_024_c0362bd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0362bd243e87ca8fa0a5ec6eb3674ed57f30baf797b21043c2662f6f6d1db1e"
    family = "Mirai"
    file_name = "morte.i686"
    file_type = "elf"
    first_seen = "2026-08-02 01:45:40"
  condition:
    hash.sha256(0, filesize) == "c0362bd243e87ca8fa0a5ec6eb3674ed57f30baf797b21043c2662f6f6d1db1e"
}

rule MalwareBazaar_Mirai_025_8aaf628e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8aaf628e5e59c2260fc05f3528fe0c2699f739db14a0e6264f45dca4001a8377"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-08-02 01:42:32"
  condition:
    hash.sha256(0, filesize) == "8aaf628e5e59c2260fc05f3528fe0c2699f739db14a0e6264f45dca4001a8377"
}

rule MalwareBazaar_Mirai_026_8f847d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f847d78922ffdcfe6e7373d8a0227d9d74544c55472d1dcde203ba845bbd896"
    family = "Mirai"
    file_name = "zero.aarch64"
    file_type = "elf"
    first_seen = "2026-08-02 01:41:39"
  condition:
    hash.sha256(0, filesize) == "8f847d78922ffdcfe6e7373d8a0227d9d74544c55472d1dcde203ba845bbd896"
}

rule MalwareBazaar_Mirai_027_ac795868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac795868b63b04ccd18e4070a5e021870ab81c2eb307f8bb04543220f6b0c371"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-08-02 01:40:43"
  condition:
    hash.sha256(0, filesize) == "ac795868b63b04ccd18e4070a5e021870ab81c2eb307f8bb04543220f6b0c371"
}

rule MalwareBazaar_Mirai_028_2ffbc8a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ffbc8a866d557a4c5bc38138385f53f76495fdfc2e816c3c03a136fd4766132"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-08-02 01:40:26"
  condition:
    hash.sha256(0, filesize) == "2ffbc8a866d557a4c5bc38138385f53f76495fdfc2e816c3c03a136fd4766132"
}

rule MalwareBazaar_Mirai_029_2b84a52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b84a52a2d4d954bbe37342a8575d735808d520972662de903edeb8e62ea0076"
    family = "Mirai"
    file_name = "morte.arc"
    file_type = "elf"
    first_seen = "2026-08-02 01:40:25"
  condition:
    hash.sha256(0, filesize) == "2b84a52a2d4d954bbe37342a8575d735808d520972662de903edeb8e62ea0076"
}

rule MalwareBazaar_unknown_030_bde905ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde905ff9a0748dc6f31b52b99b712c5b410b49843729e4932b647c15707fea1"
    family = "unknown"
    file_name = "a.sh"
    file_type = "sh"
    first_seen = "2026-08-02 01:40:23"
  condition:
    hash.sha256(0, filesize) == "bde905ff9a0748dc6f31b52b99b712c5b410b49843729e4932b647c15707fea1"
}

rule MalwareBazaar_unknown_031_50a42309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50a42309a5fb81a08d92811ef90568d4ae67101690f430a1208feba3ca67ef40"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:33:39"
  condition:
    hash.sha256(0, filesize) == "50a42309a5fb81a08d92811ef90568d4ae67101690f430a1208feba3ca67ef40"
}

rule MalwareBazaar_unknown_032_0976602b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0976602bea0da4814b69d1985b4fb488ecca41574d037dd64a6f55ba65c0b69b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:31:17"
  condition:
    hash.sha256(0, filesize) == "0976602bea0da4814b69d1985b4fb488ecca41574d037dd64a6f55ba65c0b69b"
}

rule MalwareBazaar_Mirai_033_d67edc48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d67edc48b43fc48a0b399d5144bb5d3d0862e77065117fe10f7822a70daa1d96"
    family = "Mirai"
    file_name = "zero.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 01:29:24"
  condition:
    hash.sha256(0, filesize) == "d67edc48b43fc48a0b399d5144bb5d3d0862e77065117fe10f7822a70daa1d96"
}

rule MalwareBazaar_unknown_034_1bf6ad02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bf6ad02a9a9417479c27e67072b6aa54571709e7ef0b9304dfb92bddd1f109f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:28:31"
  condition:
    hash.sha256(0, filesize) == "1bf6ad02a9a9417479c27e67072b6aa54571709e7ef0b9304dfb92bddd1f109f"
}

rule MalwareBazaar_Mirai_035_28a16751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28a16751269feab605a0df2ace7b0023cfc439947ce9b23ebda0675b88bd4dbd"
    family = "Mirai"
    file_name = "zero.x86_64"
    file_type = "elf"
    first_seen = "2026-08-02 01:28:30"
  condition:
    hash.sha256(0, filesize) == "28a16751269feab605a0df2ace7b0023cfc439947ce9b23ebda0675b88bd4dbd"
}

rule MalwareBazaar_Mirai_036_9651658c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9651658cdd06bf43195524fe79ba39488d96c971bc5c3ac822f2a6abd9f33855"
    family = "Mirai"
    file_name = "zero.sh4"
    file_type = "elf"
    first_seen = "2026-08-02 01:27:17"
  condition:
    hash.sha256(0, filesize) == "9651658cdd06bf43195524fe79ba39488d96c971bc5c3ac822f2a6abd9f33855"
}

rule MalwareBazaar_Mirai_037_6baeb67d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6baeb67d22fa275bd2426180e5fe051ac1831c050db47d8fb89640813d4f4afa"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 01:22:29"
  condition:
    hash.sha256(0, filesize) == "6baeb67d22fa275bd2426180e5fe051ac1831c050db47d8fb89640813d4f4afa"
}

rule MalwareBazaar_Mirai_038_7218d052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7218d0523a4d05c52557f93febc58b45b67fa65a91e62656a74724d3ad87772d"
    family = "Mirai"
    file_name = "morte.arm5"
    file_type = "elf"
    first_seen = "2026-08-02 01:21:39"
  condition:
    hash.sha256(0, filesize) == "7218d0523a4d05c52557f93febc58b45b67fa65a91e62656a74724d3ad87772d"
}

rule MalwareBazaar_Mirai_039_52e0c497
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e0c4974427db87b915d5b81785e6a9a014f5626e7adefee0c4a9710edd626d"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-08-02 01:17:29"
  condition:
    hash.sha256(0, filesize) == "52e0c4974427db87b915d5b81785e6a9a014f5626e7adefee0c4a9710edd626d"
}

rule MalwareBazaar_Mirai_040_e9a42640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9a42640b2832e6b4fab461e57d07f99cfb0f8428d64862e887206ba3a9e0b4f"
    family = "Mirai"
    file_name = "morte.x86"
    file_type = "elf"
    first_seen = "2026-08-02 01:16:18"
  condition:
    hash.sha256(0, filesize) == "e9a42640b2832e6b4fab461e57d07f99cfb0f8428d64862e887206ba3a9e0b4f"
}

rule MalwareBazaar_unknown_041_a1099439
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a10994395ee8391edb37a4472ce34744946598a30b8d656285d09fa57faf480b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-02 01:09:29"
  condition:
    hash.sha256(0, filesize) == "a10994395ee8391edb37a4472ce34744946598a30b8d656285d09fa57faf480b"
}

rule MalwareBazaar_Mirai_042_585d6ed5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "585d6ed50abdf1500cad819da63dc78d2d8afbecb791e5a5d2407817ef083ffb"
    family = "Mirai"
    file_name = "zero.armv5l"
    file_type = "elf"
    first_seen = "2026-08-02 01:08:27"
  condition:
    hash.sha256(0, filesize) == "585d6ed50abdf1500cad819da63dc78d2d8afbecb791e5a5d2407817ef083ffb"
}

rule MalwareBazaar_Mirai_043_fd8afd2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd8afd2e0d2d6b33739270e33d0343efaaf9856e0ad26f98cb2cfdb3f72360cb"
    family = "Mirai"
    file_name = "zero.armv5l"
    file_type = "elf"
    first_seen = "2026-08-02 01:08:15"
  condition:
    hash.sha256(0, filesize) == "fd8afd2e0d2d6b33739270e33d0343efaaf9856e0ad26f98cb2cfdb3f72360cb"
}

rule MalwareBazaar_Mirai_044_e7a21d0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7a21d0bb71be7547e411b75de1ea32a40966965543172d8e6693da5ac9a5f7b"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-08-02 01:06:28"
  condition:
    hash.sha256(0, filesize) == "e7a21d0bb71be7547e411b75de1ea32a40966965543172d8e6693da5ac9a5f7b"
}

rule MalwareBazaar_Mirai_045_409629d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "409629d29129fcd72a0d48d11773a1c20e81a721c8346427b3c1a1a7da135892"
    family = "Mirai"
    file_name = "morte.arm"
    file_type = "elf"
    first_seen = "2026-08-02 01:05:30"
  condition:
    hash.sha256(0, filesize) == "409629d29129fcd72a0d48d11773a1c20e81a721c8346427b3c1a1a7da135892"
}

rule MalwareBazaar_Mirai_046_fd4746be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd4746bedadaf4dfc3c9b6e062f0488e9c866e79455079ad8790e9a37c95cc03"
    family = "Mirai"
    file_name = "zero.armv4l"
    file_type = "elf"
    first_seen = "2026-08-02 00:52:31"
  condition:
    hash.sha256(0, filesize) == "fd4746bedadaf4dfc3c9b6e062f0488e9c866e79455079ad8790e9a37c95cc03"
}

rule MalwareBazaar_Mirai_047_61bc9a37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61bc9a3758c56d8cb261853b8b9feb686d5da08402f83564089c09610d3c6cef"
    family = "Mirai"
    file_name = "zero.armv4l"
    file_type = "elf"
    first_seen = "2026-08-02 00:51:39"
  condition:
    hash.sha256(0, filesize) == "61bc9a3758c56d8cb261853b8b9feb686d5da08402f83564089c09610d3c6cef"
}

rule MalwareBazaar_Mirai_048_b4eb673c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4eb673cc44d251ecc21afc9e19240ad69ef9f99ea5a319ef57ea261ee15b452"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:34"
  condition:
    hash.sha256(0, filesize) == "b4eb673cc44d251ecc21afc9e19240ad69ef9f99ea5a319ef57ea261ee15b452"
}

rule MalwareBazaar_Mirai_049_f38943d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f38943d7da545cbb1771b7934a42e2ee9677986d671d12896b18235ebb894394"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:31"
  condition:
    hash.sha256(0, filesize) == "f38943d7da545cbb1771b7934a42e2ee9677986d671d12896b18235ebb894394"
}

rule MalwareBazaar_Mirai_050_dec424fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dec424fc8ec0ec7f4e234f2ed759fd0ad672d8090e62dcf2a2fd3d4d8c90ac92"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:29"
  condition:
    hash.sha256(0, filesize) == "dec424fc8ec0ec7f4e234f2ed759fd0ad672d8090e62dcf2a2fd3d4d8c90ac92"
}

rule MalwareBazaar_Mirai_051_c29f04f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29f04f3bf672aa6e91a47b810bab140b7b21b0925fa10b3fc676c5c43057b90"
    family = "Mirai"
    file_name = "morte.mpsl"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:19"
  condition:
    hash.sha256(0, filesize) == "c29f04f3bf672aa6e91a47b810bab140b7b21b0925fa10b3fc676c5c43057b90"
}

rule MalwareBazaar_Mirai_052_f47c9c3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47c9c3d3efc98916fb74aa908075ffadf39b219dbdd7fa17d3da24ea77322cb"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:18"
  condition:
    hash.sha256(0, filesize) == "f47c9c3d3efc98916fb74aa908075ffadf39b219dbdd7fa17d3da24ea77322cb"
}

rule MalwareBazaar_Mirai_053_7948a099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7948a099bfa5e5ffb60a1c94a64cbbae5b2f359a0a61159f39b54973b8f9bcff"
    family = "Mirai"
    file_name = "morte.ppc"
    file_type = "elf"
    first_seen = "2026-08-02 00:43:16"
  condition:
    hash.sha256(0, filesize) == "7948a099bfa5e5ffb60a1c94a64cbbae5b2f359a0a61159f39b54973b8f9bcff"
}

rule MalwareBazaar_Mirai_054_96990250
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9699025026d72bc780f108afe1749ef36fc109b91d90a9225bbd0e6e90102fcd"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-08-02 00:42:28"
  condition:
    hash.sha256(0, filesize) == "9699025026d72bc780f108afe1749ef36fc109b91d90a9225bbd0e6e90102fcd"
}

rule MalwareBazaar_Mirai_055_69e9c7d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69e9c7d448f0171c34feb8af04e09d576ab33b105b4c57efbd72aada686401a0"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-08-02 00:42:25"
  condition:
    hash.sha256(0, filesize) == "69e9c7d448f0171c34feb8af04e09d576ab33b105b4c57efbd72aada686401a0"
}

rule MalwareBazaar_Mirai_056_6d987d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d987d86a194619f432a0e317c0bc4490fc3d25113ab3880018a4da7cdb5f3de"
    family = "Mirai"
    file_name = "morte.arm6"
    file_type = "elf"
    first_seen = "2026-08-02 00:41:42"
  condition:
    hash.sha256(0, filesize) == "6d987d86a194619f432a0e317c0bc4490fc3d25113ab3880018a4da7cdb5f3de"
}

rule MalwareBazaar_Mirai_057_631edb65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "631edb65012fe8dff1eb511edc1660fc8cede0bafe531f507cc491654e47fd6f"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-08-02 00:41:41"
  condition:
    hash.sha256(0, filesize) == "631edb65012fe8dff1eb511edc1660fc8cede0bafe531f507cc491654e47fd6f"
}

rule MalwareBazaar_Mirai_058_3178e838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3178e838e991d58717ede5115f146b7ff6882aeaada063e0243d50f5c5d85122"
    family = "Mirai"
    file_name = "zero.arc"
    file_type = "elf"
    first_seen = "2026-08-02 00:40:26"
  condition:
    hash.sha256(0, filesize) == "3178e838e991d58717ede5115f146b7ff6882aeaada063e0243d50f5c5d85122"
}

rule MalwareBazaar_njrat_059_06185d74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e"
    family = "njrat"
    file_name = "06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e.exe"
    file_type = "exe"
    first_seen = "2026-08-02 00:11:31"
  condition:
    hash.sha256(0, filesize) == "06185d74edbdc06f99095e96f74aa2e49a1cda2d02a294c11a9ac35a0231075e"
}

rule MalwareBazaar_WannaCry_060_6b465dc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
    family = "WannaCry"
    file_name = "92d7549c8cf73bc0f29cea5ba8991560"
    file_type = "dll"
    first_seen = "2026-08-02 00:07:23"
  condition:
    hash.sha256(0, filesize) == "6b465dc7cc21ba92d848425f8eabae3dc9f72d873d92a7b18639fd79814c7b1b"
}

rule MalwareBazaar_unknown_061_6bcd0a97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bcd0a97bb8c444b66e686e2bceb32cccf4090f13b6b5ed778c0341e31fe9d8a"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.36984827"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:16"
  condition:
    hash.sha256(0, filesize) == "6bcd0a97bb8c444b66e686e2bceb32cccf4090f13b6b5ed778c0341e31fe9d8a"
}

rule MalwareBazaar_CoinMiner_062_a94e9aca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a94e9aca1aca0c7e006a0d8684c5423b1a3bd7e48734eee4f12f0caa3b5d901a"
    family = "CoinMiner"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.64356642"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:15"
  condition:
    hash.sha256(0, filesize) == "a94e9aca1aca0c7e006a0d8684c5423b1a3bd7e48734eee4f12f0caa3b5d901a"
}

rule MalwareBazaar_unknown_063_c1fd57d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1fd57d1c2fa32e530ce16b95a306e98cd098e44e4599e9daa5d700d0a437814"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.37843656"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:14"
  condition:
    hash.sha256(0, filesize) == "c1fd57d1c2fa32e530ce16b95a306e98cd098e44e4599e9daa5d700d0a437814"
}

rule MalwareBazaar_unknown_064_b193be68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b193be680eff393e70bd8dba2b8b1d84249b729191aa8a5014ab884360cdc9c3"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Evo-gen.79735182"
    file_type = "exe"
    first_seen = "2026-08-01 23:53:12"
  condition:
    hash.sha256(0, filesize) == "b193be680eff393e70bd8dba2b8b1d84249b729191aa8a5014ab884360cdc9c3"
}

rule MalwareBazaar_NanoCore_065_0ec1ed0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ec1ed0daf72e7f3b2a9afb44d8e2de77b97b126788e54e0cb948cc176de91ba"
    family = "NanoCore"
    file_name = "1a5e935a2545bde844f7aa04d6bce296.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:45:05"
  condition:
    hash.sha256(0, filesize) == "0ec1ed0daf72e7f3b2a9afb44d8e2de77b97b126788e54e0cb948cc176de91ba"
}

rule MalwareBazaar_RustyStealer_066_0f0fd487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f0fd4870160fab8ca35512ecef8425e8c0e733f7a771109598e8efa36fc42e3"
    family = "RustyStealer"
    file_name = "nvidia-runtimer.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:33:16"
  condition:
    hash.sha256(0, filesize) == "0f0fd4870160fab8ca35512ecef8425e8c0e733f7a771109598e8efa36fc42e3"
}

rule MalwareBazaar_unknown_067_43520016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43520016f45b231de67e5797be498a3fe9a473952db29de40c6223291149a86c"
    family = "unknown"
    file_name = "ipxroute.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:25"
  condition:
    hash.sha256(0, filesize) == "43520016f45b231de67e5797be498a3fe9a473952db29de40c6223291149a86c"
}

rule MalwareBazaar_unknown_068_400fc5b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "400fc5b426841f1fa22ed8c3293638186754caea8d8d4ec7d3bab45c51cef08a"
    family = "unknown"
    file_name = "searchindexer.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:17"
  condition:
    hash.sha256(0, filesize) == "400fc5b426841f1fa22ed8c3293638186754caea8d8d4ec7d3bab45c51cef08a"
}

rule MalwareBazaar_unknown_069_bfdb1d34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfdb1d343244c126b015fb25d6fcf60433969318f137bac6f489a56b6035d619"
    family = "unknown"
    file_name = "mblctr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:12"
  condition:
    hash.sha256(0, filesize) == "bfdb1d343244c126b015fb25d6fcf60433969318f137bac6f489a56b6035d619"
}

rule MalwareBazaar_unknown_070_2f68440b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f68440b8f04e649f3b24d562459e7a63d04ca41ca643f6b8075b8f0851e0ab8"
    family = "unknown"
    file_name = "expand.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:11"
  condition:
    hash.sha256(0, filesize) == "2f68440b8f04e649f3b24d562459e7a63d04ca41ca643f6b8075b8f0851e0ab8"
}

rule MalwareBazaar_unknown_071_c8afe6e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8afe6e024d71b3c6fc185f73f5a676cfd2e06feff560ed77d5b048d489a5397"
    family = "unknown"
    file_name = "w32tm.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:05"
  condition:
    hash.sha256(0, filesize) == "c8afe6e024d71b3c6fc185f73f5a676cfd2e06feff560ed77d5b048d489a5397"
}

rule MalwareBazaar_unknown_072_d441c338
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d441c338d7af4ac5301081e9a91723fd1ab303ff59162a4e09b31b48c6f87267"
    family = "unknown"
    file_name = "msdt.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:25:02"
  condition:
    hash.sha256(0, filesize) == "d441c338d7af4ac5301081e9a91723fd1ab303ff59162a4e09b31b48c6f87267"
}

rule MalwareBazaar_unknown_073_373ca0a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "373ca0a0e89006ec968611fb0c15a569e3c12f338292df69fbeba45d0db37828"
    family = "unknown"
    file_name = "qwinsta.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:59"
  condition:
    hash.sha256(0, filesize) == "373ca0a0e89006ec968611fb0c15a569e3c12f338292df69fbeba45d0db37828"
}

rule MalwareBazaar_unknown_074_9d88e9dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d88e9dd9f5fab20b1ec58533231e33c5307057cd8dd98046fff7e2c19442a9c"
    family = "unknown"
    file_name = "wuauclt.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:56"
  condition:
    hash.sha256(0, filesize) == "9d88e9dd9f5fab20b1ec58533231e33c5307057cd8dd98046fff7e2c19442a9c"
}

rule MalwareBazaar_unknown_075_38e35000
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38e3500020a3b0e9747fca7a7c85cf51e4e1c29c0fcce2da19b1376e5ebc9f0a"
    family = "unknown"
    file_name = "ipconfig.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:45"
  condition:
    hash.sha256(0, filesize) == "38e3500020a3b0e9747fca7a7c85cf51e4e1c29c0fcce2da19b1376e5ebc9f0a"
}

rule MalwareBazaar_unknown_076_fd1c6693
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd1c66931da5e03116d24e861246d8d8c5f398cd6e73e47b06f04afcf372ec20"
    family = "unknown"
    file_name = "winver.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:33"
  condition:
    hash.sha256(0, filesize) == "fd1c66931da5e03116d24e861246d8d8c5f398cd6e73e47b06f04afcf372ec20"
}

rule MalwareBazaar_unknown_077_872cf388
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "872cf388fa9db1f2045d9cb6b70d46f6b0d582ae434d86417956f45220620ca7"
    family = "unknown"
    file_name = "cmd.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:18"
  condition:
    hash.sha256(0, filesize) == "872cf388fa9db1f2045d9cb6b70d46f6b0d582ae434d86417956f45220620ca7"
}

rule MalwareBazaar_unknown_078_523d5347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "523d5347de7d2a9f4de3f66e5c108c0ab268b11ff251cef94457a0907da0b048"
    family = "unknown"
    file_name = "spoolsv.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:11"
  condition:
    hash.sha256(0, filesize) == "523d5347de7d2a9f4de3f66e5c108c0ab268b11ff251cef94457a0907da0b048"
}

rule MalwareBazaar_unknown_079_fd1063e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd1063e2d8af2eedaf59f388ac4534f27d3933ca3e6e244f7be056044e685c13"
    family = "unknown"
    file_name = "icacls.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:11"
  condition:
    hash.sha256(0, filesize) == "fd1063e2d8af2eedaf59f388ac4534f27d3933ca3e6e244f7be056044e685c13"
}

rule MalwareBazaar_unknown_080_5630f2a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5630f2a1acdc21427d6259e9040bfb9f6959640b5a8f58576f36cca7c25bc99a"
    family = "unknown"
    file_name = "mmc.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:24:01"
  condition:
    hash.sha256(0, filesize) == "5630f2a1acdc21427d6259e9040bfb9f6959640b5a8f58576f36cca7c25bc99a"
}

rule MalwareBazaar_unknown_081_bd9bc865
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd9bc8659065964c42e3eb062e79d46d4f368e802dc68d9232d86e01b0ee5342"
    family = "unknown"
    file_name = "eventvwr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:56"
  condition:
    hash.sha256(0, filesize) == "bd9bc8659065964c42e3eb062e79d46d4f368e802dc68d9232d86e01b0ee5342"
}

rule MalwareBazaar_unknown_082_20979474
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "209794740e72dc14164fcb4c9cc8329e036dfe3e786c3f17c64eddd749f6f071"
    family = "unknown"
    file_name = "chkdsk.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:55"
  condition:
    hash.sha256(0, filesize) == "209794740e72dc14164fcb4c9cc8329e036dfe3e786c3f17c64eddd749f6f071"
}

rule MalwareBazaar_unknown_083_600b2f39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "600b2f3979aa534bcfac6faea5da715d48b14c1a081ffaebdf7732b354797a79"
    family = "unknown"
    file_name = "vssadmin.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:47"
  condition:
    hash.sha256(0, filesize) == "600b2f3979aa534bcfac6faea5da715d48b14c1a081ffaebdf7732b354797a79"
}

rule MalwareBazaar_unknown_084_0ac2dd4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ac2dd4e7b97149caba8e0e2af7c41f3d98023873ebdea1122c8a28b7a2ac198"
    family = "unknown"
    file_name = "lpq.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:42"
  condition:
    hash.sha256(0, filesize) == "0ac2dd4e7b97149caba8e0e2af7c41f3d98023873ebdea1122c8a28b7a2ac198"
}

rule MalwareBazaar_unknown_085_9115a6e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9115a6e66a79b24af7a2596f82fe39013d67e6bd14009d52c8f377c4cc5fc6b7"
    family = "unknown"
    file_name = "telnet.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:42"
  condition:
    hash.sha256(0, filesize) == "9115a6e66a79b24af7a2596f82fe39013d67e6bd14009d52c8f377c4cc5fc6b7"
}

rule MalwareBazaar_unknown_086_aeed1f88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeed1f8809aeecf255a9409743d560b94bdee20a37b2670f9c37b755b2422a99"
    family = "unknown"
    file_name = "regsvr32.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:32"
  condition:
    hash.sha256(0, filesize) == "aeed1f8809aeecf255a9409743d560b94bdee20a37b2670f9c37b755b2422a99"
}

rule MalwareBazaar_unknown_087_50d79d02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d79d022c8f149e3d28f645b32925377df42f8ccd71905a8a73862172d4c893"
    family = "unknown"
    file_name = "forfiles.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:13"
  condition:
    hash.sha256(0, filesize) == "50d79d022c8f149e3d28f645b32925377df42f8ccd71905a8a73862172d4c893"
}

rule MalwareBazaar_unknown_088_5a756182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a756182c6ed8a913fe6ee79892d07b1e71cd8e20ca8096927c3cd150d4a8ba2"
    family = "unknown"
    file_name = "bcdedit.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:09"
  condition:
    hash.sha256(0, filesize) == "5a756182c6ed8a913fe6ee79892d07b1e71cd8e20ca8096927c3cd150d4a8ba2"
}

rule MalwareBazaar_unknown_089_60192de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60192de00b87c9684aa653ea15ea60640d0b6497bc855efd5fc66272f0d17d35"
    family = "unknown"
    file_name = "sysprep.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:23:01"
  condition:
    hash.sha256(0, filesize) == "60192de00b87c9684aa653ea15ea60640d0b6497bc855efd5fc66272f0d17d35"
}

rule MalwareBazaar_unknown_090_a3c6726b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c6726b13bf4a7904ab8bd91f6d2d7596ab005cba246b2a59ee318ba727fff8"
    family = "unknown"
    file_name = "vds.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:58"
  condition:
    hash.sha256(0, filesize) == "a3c6726b13bf4a7904ab8bd91f6d2d7596ab005cba246b2a59ee318ba727fff8"
}

rule MalwareBazaar_unknown_091_fabfa7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fabfa7b111d9105d9d40091ae62151c5b882e7115eb5e3d27e18e0228600a515"
    family = "unknown"
    file_name = "sfc.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:53"
  condition:
    hash.sha256(0, filesize) == "fabfa7b111d9105d9d40091ae62151c5b882e7115eb5e3d27e18e0228600a515"
}

rule MalwareBazaar_unknown_092_fa1115eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa1115eb9670ae43ecba6f995c78ce6ffa7ff101fea1373d082b66d531c5c288"
    family = "unknown"
    file_name = "tscon.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:44"
  condition:
    hash.sha256(0, filesize) == "fa1115eb9670ae43ecba6f995c78ce6ffa7ff101fea1373d082b66d531c5c288"
}

rule MalwareBazaar_unknown_093_03e37a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03e37a82cf86dab6c21f370985eb86698ee8aadd1910cab7e3a17cce5a385248"
    family = "unknown"
    file_name = "msiexec.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:37"
  condition:
    hash.sha256(0, filesize) == "03e37a82cf86dab6c21f370985eb86698ee8aadd1910cab7e3a17cce5a385248"
}

rule MalwareBazaar_unknown_094_8fd8ed74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fd8ed7459c026a542e961e2d3f4f4f9d5378ac3ba587d885e94270314837cf1"
    family = "unknown"
    file_name = "diskpart.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:33"
  condition:
    hash.sha256(0, filesize) == "8fd8ed7459c026a542e961e2d3f4f4f9d5378ac3ba587d885e94270314837cf1"
}

rule MalwareBazaar_unknown_095_cd9f53a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd9f53a2acc32016d8976a0d501e0a63d25c3cc04a07a7cb89ee2bd992b78e91"
    family = "unknown"
    file_name = "ntmsmgr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:28"
  condition:
    hash.sha256(0, filesize) == "cd9f53a2acc32016d8976a0d501e0a63d25c3cc04a07a7cb89ee2bd992b78e91"
}

rule MalwareBazaar_unknown_096_895c874d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "895c874d5391cb3f363e9257252598ee62c3346f4cfa54270fa049f5cd09cd88"
    family = "unknown"
    file_name = "imapi.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:23"
  condition:
    hash.sha256(0, filesize) == "895c874d5391cb3f363e9257252598ee62c3346f4cfa54270fa049f5cd09cd88"
}

rule MalwareBazaar_unknown_097_a1a8db53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1a8db5386e8c36ce4592ab20113b2988e8fa17f36889654f525589a6d382568"
    family = "unknown"
    file_name = "mblctr.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:23"
  condition:
    hash.sha256(0, filesize) == "a1a8db5386e8c36ce4592ab20113b2988e8fa17f36889654f525589a6d382568"
}

rule MalwareBazaar_unknown_098_1a382dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a382dd04ce22d5d7ef9dacb37bb59277eff58462a27ef282a86d013a0bfb9ad"
    family = "unknown"
    file_name = "wevtutil.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:19"
  condition:
    hash.sha256(0, filesize) == "1a382dd04ce22d5d7ef9dacb37bb59277eff58462a27ef282a86d013a0bfb9ad"
}

rule MalwareBazaar_unknown_099_dbd47856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbd47856ff60b3116575b28a7f385ee530e40d7048a8bffce22283ea9dee8629"
    family = "unknown"
    file_name = "powershell_ise.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:15"
  condition:
    hash.sha256(0, filesize) == "dbd47856ff60b3116575b28a7f385ee530e40d7048a8bffce22283ea9dee8629"
}

rule MalwareBazaar_unknown_100_c690250a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c690250a8818a2685c5dd6d3a89b8f00588ee2c593440ee6c0a232425af0f7c9"
    family = "unknown"
    file_name = "xwizard.exe"
    file_type = "exe"
    first_seen = "2026-08-01 23:22:11"
  condition:
    hash.sha256(0, filesize) == "c690250a8818a2685c5dd6d3a89b8f00588ee2c593440ee6c0a232425af0f7c9"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

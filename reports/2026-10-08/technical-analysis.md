# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-08

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 670 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 670 |
| Unique family labels | 7 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 57 |
| unknown | 36 |
| RemusStealer | 2 |
| Vidar | 2 |
| RevStealer | 1 |
| ValleyRAT | 1 |
| VShell | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 64 |
| exe | 19 |
| sh | 4 |
| msi | 3 |
| zip | 3 |
| js | 1 |
| dll | 1 |
| rar | 1 |
| macho | 1 |
| au3 | 1 |

## Per-Sample Analysis

### Sample 1: `4b9c63f38bd6a44a`

| Field | Value |
|---|---|
| SHA-256 | `4b9c63f38bd6a44a571be9ad89abdb15753762848d79994368b6a9df487adf91` |
| Family label | `Mirai` |
| File name | `eclipse.mips` |
| File type | `elf` |
| First seen | `2026-10-08 06:11:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66995d042cd70d37b2b90f17fd48736f` |
| SHA-1 | `3830e62e218a01b364eba89ca266f0119895133d` |
| SHA-256 | `4b9c63f38bd6a44a571be9ad89abdb15753762848d79994368b6a9df487adf91` |
| SHA3-384 | `17786ebe2f74a86edebb85fbeb3417fcb3ff759ff58df8da7aa7e8065e0869592bc210219e9fad4eefc1aa05e4aa32a1` |
| TLSH | `T19BE4B81A7E22DF7EF578873047F78A64969932D62BE18594B19CC20C1F3018E591FBE8` |
| TELFHASH | `t17bb126a8193813e4bb559d8c45ddef36d8a238df3a161c239e50e85ee72ba835e10c1d` |
| SSDEEP | `6144:f4CKiiV4ev6PBAHgDl5lkWzBtwJJXy4O3xqTQ9mOhTNVFZxYp4gaLwW0YmIzhott:fbB7jzD4swWoznv1DKqnoo2e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_4b9c63f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b9c63f38bd6a44a571be9ad89abdb15753762848d79994368b6a9df487adf91"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-10-08 06:11:54"
  condition:
    hash.sha256(0, filesize) == "4b9c63f38bd6a44a571be9ad89abdb15753762848d79994368b6a9df487adf91"
}
```

### Sample 2: `123d63412a11ac17`

| Field | Value |
|---|---|
| SHA-256 | `123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a` |
| Family label | `unknown` |
| File name | `123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a` |
| File type | `exe` |
| First seen | `2026-10-08 06:01:40` |
| Reporter | `c2hunter` |
| Tags | `exe, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd23d19979fe5b09f28e494706c48e80` |
| SHA-1 | `9519f2ca86673eca1d3deea89562af3597361e60` |
| SHA-256 | `123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a` |
| SHA3-384 | `4af33a8dbbaf6a9fe13c20abf9e5161fe2903b14bd90f173c57c0a2b85c03bce2388393e04260f438cd488967ba20d74` |
| IMPHASH | `4776e99a40d8b72668e173a43de71810` |
| TLSH | `T14234BFA36038BE9FCDE91F379C8E891753A52FD5C880107E1D94750EFE672082E3A566` |
| SSDEEP | `6144:VftXfOMEuiqMwSBxWj/Fh36jsrQqarDXmdeyYKNip:VfB6wSM4gEodfYx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_123d6341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a"
    family = "unknown"
    file_name = "123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a"
    file_type = "exe"
    first_seen = "2026-10-08 06:01:40"
  condition:
    hash.sha256(0, filesize) == "123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a"
}
```

### Sample 3: `0ee51420bf76c957`

| Field | Value |
|---|---|
| SHA-256 | `0ee51420bf76c95707151e64efb94636103299413bc67e99ea2fbb9f6da86e9d` |
| Family label | `Mirai` |
| File name | `eclipse.sh4` |
| File type | `elf` |
| First seen | `2026-10-08 06:00:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9b8f2d6f61e7c39296fa71c82d32e2a` |
| SHA-1 | `c30ad488b362198beae4eeb02d13bbbba460e34b` |
| SHA-256 | `0ee51420bf76c95707151e64efb94636103299413bc67e99ea2fbb9f6da86e9d` |
| SHA3-384 | `1ef176515fe146da13b18fb1e0969f05dc6f34340ff74aa00e5c8d6b5449563c5a291faf8c485f35671fe74e6ff6acb0` |
| TLSH | `T1C3948C62D8265F4AC122E5F4F8B2CE781F426D6164472FADE5A3CEB48083DC9F619374` |
| SSDEEP | `12288:QyaHWJPG0gMX15Iw5jRLKLujL2WiuwzoCCRC1v/vt:wH2G0lDXKmL2r6If` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_0ee51420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ee51420bf76c95707151e64efb94636103299413bc67e99ea2fbb9f6da86e9d"
    family = "Mirai"
    file_name = "eclipse.sh4"
    file_type = "elf"
    first_seen = "2026-10-08 06:00:35"
  condition:
    hash.sha256(0, filesize) == "0ee51420bf76c95707151e64efb94636103299413bc67e99ea2fbb9f6da86e9d"
}
```

### Sample 4: `b965f772177c2e79`

| Field | Value |
|---|---|
| SHA-256 | `b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65` |
| Family label | `Mirai` |
| File name | `curl.sh` |
| File type | `sh` |
| First seen | `2026-10-08 06:00:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33d779ab46d96aed066ec2e2ca364258` |
| SHA-1 | `9e2798bd3b5009f7b5ddb970273a34a30a6a388a` |
| SHA-256 | `b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65` |
| SHA3-384 | `96248a398ca9342b526c9438af7da362e2c703a82c81b68fa3c832c5cb7481ffd0b8d9af1e7293c48518e9ef358f02b3` |
| TLSH | `T1DE314DC008D17B7FDDD8D9197762A06D502868CA3E6B3EC4D4DB38D8A6942C2F520E0D` |
| SSDEEP | `24:e+EBvi1yFBFBvK9hZhYTtqBvTm7Twr1BvWP9PBvsbEByTvDp8wXMtqBVSjRwZBjC:e+oviwFB7v8hZicvIErLvA95vT07pb0B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_b965f772
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65"
    family = "Mirai"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-10-08 06:00:33"
  condition:
    hash.sha256(0, filesize) == "b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65"
}
```

### Sample 5: `efc37e171e6a133d`

| Field | Value |
|---|---|
| SHA-256 | `efc37e171e6a133d0fb0e9197da76227f1794fda5a93ebab0d718f8111768176` |
| Family label | `Mirai` |
| File name | `jklarm5` |
| File type | `elf` |
| First seen | `2026-10-08 06:00:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25cf08a89c79b9b08b9bcda67134b3b9` |
| SHA-1 | `c966b1338dde5eeeebab77e387a07b2e13c9610d` |
| SHA-256 | `efc37e171e6a133d0fb0e9197da76227f1794fda5a93ebab0d718f8111768176` |
| SHA3-384 | `a7f579ee93caf070f1ce96c94cee9e701123ff278c6eef659c4e91f7c8290f819c2be5acd0d6b1903df8c78be5104da8` |
| TLSH | `T158B31A8ABC85C602C5E161B7FB1F52CD376643A8D3E671139D18AF29374B86B0E3B641` |
| TELFHASH | `t13a112f21dec05d9cfbe404a852eb132b500c36ab6db2190325fe98af47315d7b030458` |
| SSDEEP | `1536:thKDKoPniEd43RoL4xqmEp3+vP39nJlseh8C768lczxw1nmfx8xRE:PKOMiEu3mw/EN+v/nmeh8Cjc1kmfxV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_efc37e17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc37e171e6a133d0fb0e9197da76227f1794fda5a93ebab0d718f8111768176"
    family = "Mirai"
    file_name = "jklarm5"
    file_type = "elf"
    first_seen = "2026-10-08 06:00:31"
  condition:
    hash.sha256(0, filesize) == "efc37e171e6a133d0fb0e9197da76227f1794fda5a93ebab0d718f8111768176"
}
```

### Sample 6: `4c475abc830a8a1c`

| Field | Value |
|---|---|
| SHA-256 | `4c475abc830a8a1cf460927c26daea7dd156b641b66ebf72835e74dc38ef1577` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-08 05:56:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2da213fc7dd8ad76b4f50d40922d86bc` |
| SHA-1 | `ecff5e1ebac4d6e35e8a85d2954827c97a6162b2` |
| SHA-256 | `4c475abc830a8a1cf460927c26daea7dd156b641b66ebf72835e74dc38ef1577` |
| SHA3-384 | `700c47a9bd193dc24280ce8818d67f7a86c9e1b3423ebad5eb946bf77f27db0be7b422dfa02f86ac81d3613f2185d447` |
| TLSH | `T1FA157C89E7C7D4E1F25304F10A4FC7F21528A2265063F6F2EB8C1A9778B6B525E1632D` |
| TELFHASH | `t1dbc106b3696558dcb7f08902829b7124df36e02725f035721df35481bbb2e436f6a978` |
| SSDEEP | `24576:yLvmhXBhwqZq7sYzEcLpf1A3PAZ1mZQ52QWy:y6hXBhdq9wip2MT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_4c475abc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c475abc830a8a1cf460927c26daea7dd156b641b66ebf72835e74dc38ef1577"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 05:56:40"
  condition:
    hash.sha256(0, filesize) == "4c475abc830a8a1cf460927c26daea7dd156b641b66ebf72835e74dc38ef1577"
}
```

### Sample 7: `f80220d22e396186`

| Field | Value |
|---|---|
| SHA-256 | `f80220d22e396186175a3e8f61e8175a3cb25b4a18d7e31937cf4925ca7e3b82` |
| Family label | `Mirai` |
| File name | `jklarm6` |
| File type | `elf` |
| First seen | `2026-10-08 05:56:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23229b41493745453e913b931c3cbf9b` |
| SHA-1 | `65b88c68a2149d3d31949ff0553deef39af2d3ef` |
| SHA-256 | `f80220d22e396186175a3e8f61e8175a3cb25b4a18d7e31937cf4925ca7e3b82` |
| SHA3-384 | `9d935b1a095089e54310fc1cfa0d64d6003ba9522fcd8cd6b6f13a0943c169ca6f8e549aafc18d546184db9df8d6a975` |
| TLSH | `T198B31BC6BC80CB11D6C615BAFE1E518D33134BB8D3EE72139E149B2D678B86B0A3B515` |
| TELFHASH | `t136f09734af84154cdec680a1c0e6a31066eab0ea7d3e181a4e366f0f8c151d47639817` |
| SSDEEP | `3072:nsRRAmwzKfwGxIuEN7MxrI06y7w0Lj7oamnmXBPJpME+e0GCA5VQ:VKvIz4xeAw0Lvoa0mX7iEFg3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_f80220d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80220d22e396186175a3e8f61e8175a3cb25b4a18d7e31937cf4925ca7e3b82"
    family = "Mirai"
    file_name = "jklarm6"
    file_type = "elf"
    first_seen = "2026-10-08 05:56:38"
  condition:
    hash.sha256(0, filesize) == "f80220d22e396186175a3e8f61e8175a3cb25b4a18d7e31937cf4925ca7e3b82"
}
```

### Sample 8: `7b8cd695424f9b00`

| Field | Value |
|---|---|
| SHA-256 | `7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417` |
| Family label | `Mirai` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-10-08 05:56:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2032f2294942f776a127af3f8f900c77` |
| SHA-1 | `054db30935ad054e6a6f44649808054ee43a45b0` |
| SHA-256 | `7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417` |
| SHA3-384 | `b0b57deb12395b90fda628c6afba27a3edc3e6670d29f6ad447569e094fd738e34448946bd30f746674fb23e6f9ce641` |
| TLSH | `T1573154C114C17B7ECDD8D5157752A43D902868C52E6B2FDCD8DF38D8A681AD2F510E4C` |
| SSDEEP | `24:FeEBvi1pieBFBvK9hOh4TtqBvTm7T3L1BvWPivB8s7EByTvDp83XrQtqBVSjR35Q:Feovi3lB7v8hOCcvIbLLvAiZ8z07po7Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_7b8cd695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417"
    family = "Mirai"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-10-08 05:56:36"
  condition:
    hash.sha256(0, filesize) == "7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417"
}
```

### Sample 9: `9ea109cdf6b5c41f`

| Field | Value |
|---|---|
| SHA-256 | `9ea109cdf6b5c41f63737d6ec31d6f8c75d826a2d6939d8aeb675d7134b318d9` |
| Family label | `Mirai` |
| File name | `eclipse.armv7l` |
| File type | `elf` |
| First seen | `2026-10-08 05:56:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdf7d7dc91f97185ad85e520e7060722` |
| SHA-1 | `7382749ff15ce8f75eba8b1be929ab05da8506d3` |
| SHA-256 | `9ea109cdf6b5c41f63737d6ec31d6f8c75d826a2d6939d8aeb675d7134b318d9` |
| SHA3-384 | `2719af2eb6c5b1a58dd040177dbb58d3dd89bcfe821222621cd2d2483c3f8fd56ac04e38f3c2b819deb13d2b03bbc441` |
| TLSH | `T1D0A42966ED419B51D5D22ABEFF5E824933131B78F2EE72119D195F3073CB88A0E3A502` |
| SSDEEP | `12288:EzWK4BSuqCaykB/LeyJ4kbETJ/4XbVdmUdSa53i8XrebxFo9n:+77JF9ApCs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_9ea109cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea109cdf6b5c41f63737d6ec31d6f8c75d826a2d6939d8aeb675d7134b318d9"
    family = "Mirai"
    file_name = "eclipse.armv7l"
    file_type = "elf"
    first_seen = "2026-10-08 05:56:34"
  condition:
    hash.sha256(0, filesize) == "9ea109cdf6b5c41f63737d6ec31d6f8c75d826a2d6939d8aeb675d7134b318d9"
}
```

### Sample 10: `1298d6b525ff9313`

| Field | Value |
|---|---|
| SHA-256 | `1298d6b525ff93135ba5328dd5ec97cf71870fe9f869b5e6e4a23de23bc99e96` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-10-08 05:52:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9345f4b76a51ad6fc43cb210073a0918` |
| SHA-1 | `eaa16019316dde7d3e283760063751f0dd761741` |
| SHA-256 | `1298d6b525ff93135ba5328dd5ec97cf71870fe9f869b5e6e4a23de23bc99e96` |
| SHA3-384 | `1a484af2d6db02f6c6c748745e2aed1466022bc0e8c1126ab5d7192b8b6104045ca98dbb9108056a53414c53479f5c96` |
| TLSH | `T16DD33A2275791E2BC4E0A87E22F74761F1F157DA25A8C90E7EB20D4FFF212206507AB4` |
| SSDEEP | `3072:nZUlV+Fawd99IVWFjKc7RgyhOFe30Hi09lshKwNh:ZUH+FD99IVWFt5OgEmhPNh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_1298d6b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1298d6b525ff93135ba5328dd5ec97cf71870fe9f869b5e6e4a23de23bc99e96"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-08 05:52:43"
  condition:
    hash.sha256(0, filesize) == "1298d6b525ff93135ba5328dd5ec97cf71870fe9f869b5e6e4a23de23bc99e96"
}
```

### Sample 11: `c11ab3d584a5f56b`

| Field | Value |
|---|---|
| SHA-256 | `c11ab3d584a5f56b443061f8e02b7d5d7257ecf16a5148682a80eefcbf4e21dc` |
| Family label | `Mirai` |
| File name | `eclipse.m68k` |
| File type | `elf` |
| First seen | `2026-10-08 05:40:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4e880858e38a1985b69aeacd32f3a53` |
| SHA-1 | `6c2f6a93448bc696411994e98854098b78ae1369` |
| SHA-256 | `c11ab3d584a5f56b443061f8e02b7d5d7257ecf16a5148682a80eefcbf4e21dc` |
| SHA3-384 | `155b63bcd03b73e7872845feed570b891e0b7a3a8c6af9d53136fe9eb7282877b96db8b9c180644afb2af2e5359eb93a` |
| TLSH | `T1F3944C87FA01C9BBF44BA332455349157120FB7298826F37703778A9EA3E2A55533BC9` |
| SSDEEP | `6144:dR+TQ3MynaF+LdoWdtEBxlDy8tTd9WkPhTrf2SJm/zpuWenLXlym+qqDL0Wmu5:dWQ3dnqxJBrapIzqnTm+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_c11ab3d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c11ab3d584a5f56b443061f8e02b7d5d7257ecf16a5148682a80eefcbf4e21dc"
    family = "Mirai"
    file_name = "eclipse.m68k"
    file_type = "elf"
    first_seen = "2026-10-08 05:40:56"
  condition:
    hash.sha256(0, filesize) == "c11ab3d584a5f56b443061f8e02b7d5d7257ecf16a5148682a80eefcbf4e21dc"
}
```

### Sample 12: `f190679b3691ab8a`

| Field | Value |
|---|---|
| SHA-256 | `f190679b3691ab8ad2ad74df3ddfccff7933bc163186eba88a68ef82cfeb404c` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-08 05:37:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f3adf70b31d6ad01cd6c8d104d09fe4` |
| SHA-1 | `5a3e622b23048d6f770d02281d53d6dbaa99df9a` |
| SHA-256 | `f190679b3691ab8ad2ad74df3ddfccff7933bc163186eba88a68ef82cfeb404c` |
| SHA3-384 | `64a7338a1863ee7dba819eef285ab7dc2b5a5627e9c23752a00bd25bbdb10ee83f490c54c07b4205fc43544a0a671b6a` |
| TLSH | `T1B8C33A06F58184FCC08AC2341B6FB63AA935F1DD1238F6E76BD0AF127D4AE614E1DA54` |
| TELFHASH | `t11b318bb42d6239aca0d7c705778dea2ab9b100120ee5f2c69f07bd888c42a8c0d7a456` |
| SSDEEP | `3072:pxv986gurREnQI8ysmTn645T1c4n2pPCZzFr0PGvVS3/2zQAPUAackTzIj0:DPgurREnQI8ysmT64J1c4n2pPaFsez5n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_f190679b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f190679b3691ab8ad2ad74df3ddfccff7933bc163186eba88a68ef82cfeb404c"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 05:37:25"
  condition:
    hash.sha256(0, filesize) == "f190679b3691ab8ad2ad74df3ddfccff7933bc163186eba88a68ef82cfeb404c"
}
```

### Sample 13: `db20893cd7e78894`

| Field | Value |
|---|---|
| SHA-256 | `db20893cd7e7889473e6bc0f7392b7b0a52c5fc7d11e2ba1fb3325da2e7664b4` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-08 05:30:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8049a6d0a193d015835ecb0a4aa7c00c` |
| SHA-1 | `2374fe3be4584be158a13fcf6e99439edae86f28` |
| SHA-256 | `db20893cd7e7889473e6bc0f7392b7b0a52c5fc7d11e2ba1fb3325da2e7664b4` |
| SHA3-384 | `4eec960eec24d743e052c89b21e69a6889880af3601aa9d0a9f954ea6246a4971da6edc59903ad55ae9a3a03bca98a15` |
| TLSH | `T180B339C0EA47D4F5DD1642302277F73B9A32F17A1139DA83E3A89F327C52A41D90A29D` |
| TELFHASH | `t13d31a4bcf6360cdcabc19502b28ea361ad0d7b6b642137fa1ef22465327204157b6c39` |
| SSDEEP | `3072:XFmzGpEWmXBLFkpzjYS3Z/5+JcDEhaohHw0pJbLb:XFmzY5mXBypzjYYZ/5+JnlHLb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_db20893c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db20893cd7e7889473e6bc0f7392b7b0a52c5fc7d11e2ba1fb3325da2e7664b4"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-08 05:30:19"
  condition:
    hash.sha256(0, filesize) == "db20893cd7e7889473e6bc0f7392b7b0a52c5fc7d11e2ba1fb3325da2e7664b4"
}
```

### Sample 14: `21492d4240365a15`

| Field | Value |
|---|---|
| SHA-256 | `21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150` |
| Family label | `Mirai` |
| File name | `21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150` |
| File type | `elf` |
| First seen | `2026-10-08 05:28:48` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f854815e01280f5699eb63693656941f` |
| SHA-1 | `276a268b2fe3b2735f5f2aeea2ac4e15c9824970` |
| SHA-256 | `21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150` |
| SHA3-384 | `9bdc82339d7a25971176778a1b734c04ee5fecdbd89016eee882206a79ca461752bd57d23c78428161035bf0c23859a1` |
| TLSH | `T15EA31946B9819F11D4D621BAFAAE408C33136BBCD3EE7111DC20AF5527CA99B0F77612` |
| TELFHASH | `t13e11dc01db841eccbbc1874ca3ca223b29fe335866122818a32e970f4656cc2b418c37` |
| SSDEEP | `3072:4upmsG1DUtcZaI5kGGwPxw5jeTWHog4wJu:JpmsGp/ZaI5kGGex8eCHRJu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_21492d42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150"
    family = "Mirai"
    file_name = "21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150"
    file_type = "elf"
    first_seen = "2026-10-08 05:28:48"
  condition:
    hash.sha256(0, filesize) == "21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150"
}
```

### Sample 15: `a1387b7ec0e7488b`

| Field | Value |
|---|---|
| SHA-256 | `a1387b7ec0e7488b84b1ddab1c3927b0657918256cf8c25ca252080da5a49e83` |
| Family label | `Mirai` |
| File name | `eclipse.powerpc` |
| File type | `elf` |
| First seen | `2026-10-08 05:19:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eeeb63004ce3cdcba615d48b05775dcf` |
| SHA-1 | `1f2cca20add3a9cf50ec18fbd259320d73d98f24` |
| SHA-256 | `a1387b7ec0e7488b84b1ddab1c3927b0657918256cf8c25ca252080da5a49e83` |
| SHA3-384 | `f0b500f2565287772b805ad9ae46028e0339885f3eb246f1dc217ff80a78aef7ee687b4b9ecdb68deaf1b29678f50763` |
| TLSH | `T1BFA43C02A71D0F43F2931DF0373B1BF1D3AF999134A59594790FAA8A92F2D31055AACE` |
| SSDEEP | `6144:ZzxPtNvvYJsjX7ACs4hGQ584uCWWEOJyxgac4e4/bg+r5qqDL7dbj:ZZvvvYJUXuW24nTbahNbF0qnBbj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_a1387b7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1387b7ec0e7488b84b1ddab1c3927b0657918256cf8c25ca252080da5a49e83"
    family = "Mirai"
    file_name = "eclipse.powerpc"
    file_type = "elf"
    first_seen = "2026-10-08 05:19:52"
  condition:
    hash.sha256(0, filesize) == "a1387b7ec0e7488b84b1ddab1c3927b0657918256cf8c25ca252080da5a49e83"
}
```

### Sample 16: `cab39b72d61381b9`

| Field | Value |
|---|---|
| SHA-256 | `cab39b72d61381b9f379acc62cad4b5fabee0e38cd167ff2ceb7b55dcb6509c6` |
| Family label | `unknown` |
| File name | `eclipse.armv5l` |
| File type | `elf` |
| First seen | `2026-10-08 05:19:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b29233ae5d215c86ecf9b05d1518ee6` |
| SHA-1 | `96e3ada4a140996b2443660364e794bec56076cf` |
| SHA-256 | `cab39b72d61381b9f379acc62cad4b5fabee0e38cd167ff2ceb7b55dcb6509c6` |
| SHA3-384 | `d61b0d208e58c930b514e84e0e1d94ad9dac86f28b8721943e4d07345a8db046f9024b375be4c70b519e9c5355c872a6` |
| TLSH | `T10DA42A52BC419B53C6D12ABBFF5E834833175B78E2EE71129919AB3073DB8960E3B141` |
| TELFHASH | `t17fe0cd60024679e1959007e5f6bde32928e56dafc480d8b25bf08cda809154ed14b840` |
| SSDEEP | `12288:qjp5MIrBYhLtQZDfWix3WnJgcdQvsZN4mOrAIBbu5hHT:al8Ltazx+ZN4mP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_cab39b72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab39b72d61381b9f379acc62cad4b5fabee0e38cd167ff2ceb7b55dcb6509c6"
    family = "unknown"
    file_name = "eclipse.armv5l"
    file_type = "elf"
    first_seen = "2026-10-08 05:19:50"
  condition:
    hash.sha256(0, filesize) == "cab39b72d61381b9f379acc62cad4b5fabee0e38cd167ff2ceb7b55dcb6509c6"
}
```

### Sample 17: `7d72264319c996b8`

| Field | Value |
|---|---|
| SHA-256 | `7d72264319c996b8c3dabfb3ae01961f7c124471207bae849e85cea32c82c79a` |
| Family label | `RemusStealer` |
| File name | `89d4bf8726440c1e25623d10bf36c52de91113130b058bc4fcb4c637758c2070.exe` |
| File type | `exe` |
| First seen | `2026-10-08 05:17:54` |
| Reporter | `abuse_ch` |
| Tags | `de-pumped, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bf180fb81eaded9afa930e69af74b81` |
| SHA-1 | `b69d5b01a2ff6e2d058e16977677b5e586f93c83` |
| SHA-256 | `7d72264319c996b8c3dabfb3ae01961f7c124471207bae849e85cea32c82c79a` |
| SHA3-384 | `050e63e29d0887d6d3191e787df819135a0fd2b361db4978784a7a5a7a22d319e978b690121ffb356840e3024fed3637` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T121A60703775804D8C867EE74C075562A65B07C8C96357B8F4E99AEA41F2A789AFFCF00` |
| SSDEEP | `49152:+rmiugZ/ER1t+FypOhJw/C8k9zsJtx3jpd22HRaqOpA+0NxfNWlPvHL4XOACgjkJ:Fid/4GVqGvMx` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_017_7d722643
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d72264319c996b8c3dabfb3ae01961f7c124471207bae849e85cea32c82c79a"
    family = "RemusStealer"
    file_name = "89d4bf8726440c1e25623d10bf36c52de91113130b058bc4fcb4c637758c2070.exe"
    file_type = "exe"
    first_seen = "2026-10-08 05:17:54"
  condition:
    hash.sha256(0, filesize) == "7d72264319c996b8c3dabfb3ae01961f7c124471207bae849e85cea32c82c79a"
}
```

### Sample 18: `26b837f91d2341ea`

| Field | Value |
|---|---|
| SHA-256 | `26b837f91d2341ea1e817c4654a53e0ff75feb6c6f7e341ae61158ae24fa6f67` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-10-08 04:52:18` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `056af6e243e697da008000123fc257ce` |
| SHA-1 | `37af7cdf53f6b3f46283ced38ed00dd0ded00774` |
| SHA-256 | `26b837f91d2341ea1e817c4654a53e0ff75feb6c6f7e341ae61158ae24fa6f67` |
| SHA3-384 | `9d2dd02dd48d7dc7c1d16a6bea7ac9cb16403aa196f797f0bbcbc501f244b54e1b3dbaff5b6da2b5ee293182a14a232f` |
| TLSH | `T196137D22B28182F8C02BD1B8CAEA105BD2F2F0859535566F67F2DE815F63720DC35B23` |
| SSDEEP | `768:2GXJIoDBxCTgL3n+ww0T7lHtkymEnfaTsXSLKcHKdpBO5l/Fc9jmNC/u6c1iJGlG:ZXaoD3C4cdDH4k4Skzc4G7Gf7yLwDY5w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_26b837f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26b837f91d2341ea1e817c4654a53e0ff75feb6c6f7e341ae61158ae24fa6f67"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-10-08 04:52:18"
  condition:
    hash.sha256(0, filesize) == "26b837f91d2341ea1e817c4654a53e0ff75feb6c6f7e341ae61158ae24fa6f67"
}
```

### Sample 19: `bb85ba27f3091b70`

| Field | Value |
|---|---|
| SHA-256 | `bb85ba27f3091b70021fcd35e9be354fd8506078b7d4714991f9df061b80613a` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-10-08 04:48:18` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c40b2fa960b679bf23d62ca9aa73cb0` |
| SHA-1 | `bc8a695e9bddd6e505f0487f93994a9db471006e` |
| SHA-256 | `bb85ba27f3091b70021fcd35e9be354fd8506078b7d4714991f9df061b80613a` |
| SHA3-384 | `166b333b900185b1cc2385f4edb35feca28739cd97183c02f67cd965a4a1e444caf4f157ff8c926c50fececeb9594e94` |
| IMPHASH | `2fcc06b594242d89481f8a1318d76760` |
| TLSH | `T11DD3091FB79358F8C50B8138C2DAB375E735FC650324AB2F0A59E73B2D209644F59AA4` |
| SSDEEP | `3072:e6moyxFtLwixfpIobA8ETKfDbmrzhpSO5WY/JBRAAAAAAAAAAAAAAr+AAAA0AAbE:C7yPTKfDbmrzhp55WY/SUNRn48u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_bb85ba27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb85ba27f3091b70021fcd35e9be354fd8506078b7d4714991f9df061b80613a"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-10-08 04:48:18"
  condition:
    hash.sha256(0, filesize) == "bb85ba27f3091b70021fcd35e9be354fd8506078b7d4714991f9df061b80613a"
}
```

### Sample 20: `69dafc3b40a5b0e5`

| Field | Value |
|---|---|
| SHA-256 | `69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0` |
| Family label | `RevStealer` |
| File name | `69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0.exe` |
| File type | `exe` |
| First seen | `2026-10-08 03:50:59` |
| Reporter | `Kejult` |
| Tags | `exe, packed, RevStealer, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ad85d51df8c276818ef4c45cad6cf63` |
| SHA-1 | `3ae41014b7ff7675d13a1197ab40f05d1dc48a45` |
| SHA-256 | `69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0` |
| SHA3-384 | `ab55dc7b84fbd20c360b9fbbfa5a6f256f11c67058da36119744d79103eb0d075a3f32bdb1a544cc48a57cd20c09f8a0` |
| IMPHASH | `001b63852a413bf6eef528d920bb10b4` |
| TLSH | `T1E7D52389BDB24671D0B3C7B69283747EB12937514BB58C67378D6B10AC12A197C3B3B8` |
| SSDEEP | `49152:YiRG18fGrWPwFaCn+tHx39C9sq6+HVfz5jx4UDC16ea6nxpXYp6zkXPD:NnPwMCn+tH7C9ISpu75nxpIp9D` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_020_69dafc3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0"
    family = "RevStealer"
    file_name = "69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0.exe"
    file_type = "exe"
    first_seen = "2026-10-08 03:50:59"
  condition:
    hash.sha256(0, filesize) == "69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0"
}
```

### Sample 21: `0f37ed17ba77ce94`

| Field | Value |
|---|---|
| SHA-256 | `0f37ed17ba77ce94b880e16f1e38464ebaf5cd907666cf75075df16d9a166092` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-08 03:35:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62b999539aa9527c40af688337d128f9` |
| SHA-1 | `7a111b2437d904a3d77e6068e0435283e4666648` |
| SHA-256 | `0f37ed17ba77ce94b880e16f1e38464ebaf5cd907666cf75075df16d9a166092` |
| SHA3-384 | `071b2c74d837bf406d1edb9fd8c3a7aa71e2d44d31c8b493d08efe67aee8620de49c060f9b891fc26bc7bc097e9ecb23` |
| TLSH | `T1E655FA8FD48213B5B393FBA3825AD6366DF6350980728731CF557D358F42E24A228ED9` |
| SSDEEP | `6144:Jo8RHjTHWUkiQU7zqeQHOe2vEu/NwvaX8fmSDh9sN/+umFDTTxIs+9Z9v6MIRL/a:Jo8RDFelovMh4ctN7P+YEplD8R` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_021_0f37ed17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f37ed17ba77ce94b880e16f1e38464ebaf5cd907666cf75075df16d9a166092"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 03:35:24"
  condition:
    hash.sha256(0, filesize) == "0f37ed17ba77ce94b880e16f1e38464ebaf5cd907666cf75075df16d9a166092"
}
```

### Sample 22: `63d5297ab9ccc40d`

| Field | Value |
|---|---|
| SHA-256 | `63d5297ab9ccc40d45877940e18d5403e26914f1d71b59fb973f667d9095df54` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-08 03:35:09` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12d814fd207528a5a717d5165935234d` |
| SHA-1 | `b86377694a68f49df4848d2e97e7ba1a877a5a41` |
| SHA-256 | `63d5297ab9ccc40d45877940e18d5403e26914f1d71b59fb973f667d9095df54` |
| SHA3-384 | `b8459ef4b07a8770b16415571b045c83a6fed5ab2d901c595d5e80d3d29656fd7630884fd3fccc80bdc60faf6c043343` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T13674126AE11B4E40CAE7E5B247E097F2A71CB23D364DE331A21DCD09778CE91EE91458` |
| SSDEEP | `6144:XEIAdMUSno7i1QzYn2UyyOURnYqbihmaqgTQ/EllEOrE5nTtA2B8I/zfv704novX:Nui1JpXnUHlqlnTtMI/D704n+wmUNr8t` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_022_63d5297a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63d5297ab9ccc40d45877940e18d5403e26914f1d71b59fb973f667d9095df54"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 03:35:09"
  condition:
    hash.sha256(0, filesize) == "63d5297ab9ccc40d45877940e18d5403e26914f1d71b59fb973f667d9095df54"
}
```

### Sample 23: `f0157306c1872b74`

| Field | Value |
|---|---|
| SHA-256 | `f0157306c1872b748e2a1c4edc12b516e0786fa01c61e9903f67d120c6ae3a90` |
| Family label | `unknown` |
| File name | `z1PO3294.msi` |
| File type | `msi` |
| First seen | `2026-10-08 03:00:06` |
| Reporter | `fabiodemartin` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2871da407c3748ba990af302059898c5` |
| SHA-1 | `b7564019bb3251b2f8567f02eb2163ead00418e9` |
| SHA-256 | `f0157306c1872b748e2a1c4edc12b516e0786fa01c61e9903f67d120c6ae3a90` |
| SHA3-384 | `22b7a3531909184ef7a3b98faa5165bcbd05542e55dac55297dea37a07f2d7f22bc2e092a19205233e99f8c088632674` |
| TLSH | `T1DD0523D7B2A07132C732563243BF42B11636AE1CE770B63725AD32C92F7609079A9BD4` |
| SSDEEP | `24576:lJgw+nDC+YhXsDM/rFLBOzU+tamaTL6nOPdLfLN6:lJgwGC+YZsIDdBOztahTwCLzk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_f0157306
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0157306c1872b748e2a1c4edc12b516e0786fa01c61e9903f67d120c6ae3a90"
    family = "unknown"
    file_name = "z1PO3294.msi"
    file_type = "msi"
    first_seen = "2026-10-08 03:00:06"
  condition:
    hash.sha256(0, filesize) == "f0157306c1872b748e2a1c4edc12b516e0786fa01c61e9903f67d120c6ae3a90"
}
```

### Sample 24: `d6db1449d533d851`

| Field | Value |
|---|---|
| SHA-256 | `d6db1449d533d851dd6bd2030a03ac857deb4eecf2067038d4dafb85ab14c320` |
| Family label | `Mirai` |
| File name | `eclipse.armv6l` |
| File type | `elf` |
| First seen | `2026-10-08 02:52:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0add9770c84a23cbe2b349d13af56da2` |
| SHA-1 | `45905717ebd572cb92a6b1e709984791d9b87683` |
| SHA-256 | `d6db1449d533d851dd6bd2030a03ac857deb4eecf2067038d4dafb85ab14c320` |
| SHA3-384 | `c0b0a686d9fc33b30366fad357e12f7a95fc67dcbfab42992e8bc2738db7041408e5da9c398e8172a2259c6f95000f13` |
| TLSH | `T1E2A42966E9419B52C5C12ABEFF5E824933131F78F2DE72119D189F7067CB89A0E3E502` |
| SSDEEP | `12288:6g4g1yG+Uj3KPzqqQm5D9HkOiGAwZZf1K6Kahsd2al/p+:CCq7bqUp0Gunhlh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_d6db1449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6db1449d533d851dd6bd2030a03ac857deb4eecf2067038d4dafb85ab14c320"
    family = "Mirai"
    file_name = "eclipse.armv6l"
    file_type = "elf"
    first_seen = "2026-10-08 02:52:45"
  condition:
    hash.sha256(0, filesize) == "d6db1449d533d851dd6bd2030a03ac857deb4eecf2067038d4dafb85ab14c320"
}
```

### Sample 25: `64506ae267aed8af`

| Field | Value |
|---|---|
| SHA-256 | `64506ae267aed8afa5cfbb41ca8f5677600747f02fe27b8d8d926d12e3ad99f2` |
| Family label | `unknown` |
| File name | `NEW_FLF7997_SHIPMENT_DETAILpdf.com` |
| File type | `exe` |
| First seen | `2026-10-08 02:51:21` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `596dc288e8914898b0be9d57a0e3d277` |
| SHA-1 | `06aebc4b151876e8c1c9e118f90e14aba11b284d` |
| SHA-256 | `64506ae267aed8afa5cfbb41ca8f5677600747f02fe27b8d8d926d12e3ad99f2` |
| SHA3-384 | `03ac26707287d6e8f46743264cf8216fe9715100826ccfaf0d3027acde552c077d9841f7259ec20e1c6470d52f8618e7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12D05F114331ADC13E56257F00970E37197785ED4A461E3E3CEFBADEBB9A67806809683` |
| SSDEEP | `24576:bvCKX8jRLCOo0fQyrQVPwynhO0QE0Bfwh2y:bvCfjg30f9rQVBWto2y` |
| ICON-DHASH | `f0e8e8e0f0b2e8e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_64506ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64506ae267aed8afa5cfbb41ca8f5677600747f02fe27b8d8d926d12e3ad99f2"
    family = "unknown"
    file_name = "NEW_FLF7997_SHIPMENT_DETAILpdf.com"
    file_type = "exe"
    first_seen = "2026-10-08 02:51:21"
  condition:
    hash.sha256(0, filesize) == "64506ae267aed8afa5cfbb41ca8f5677600747f02fe27b8d8d926d12e3ad99f2"
}
```

### Sample 26: `2e965ae359bcc693`

| Field | Value |
|---|---|
| SHA-256 | `2e965ae359bcc693148128a48232f8c4e8a8beb84b2af822eb9abe4b0fa5a8da` |
| Family label | `unknown` |
| File name | `RFQ ORDER LIST.js` |
| File type | `js` |
| First seen | `2026-10-08 02:15:47` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74f4754a43478fc6198acf7475f65313` |
| SHA-1 | `420e458f7cab3c6b668c7a698ddce11f1a776e75` |
| SHA-256 | `2e965ae359bcc693148128a48232f8c4e8a8beb84b2af822eb9abe4b0fa5a8da` |
| SHA3-384 | `75ad113da7fdcf98d8d4b761b162d5a982716c1e35546dc61ab5da032e973bac4c054052581974b1573ecf17a1f06554` |
| TLSH | `T1C2C5126BEC065B4FC89F5E843255885A1826EF27567875D23CCE1A2DE3A8F703365338` |
| SSDEEP | `24576:B1+5FldPR7/DHZYFl388ZVjZ9DQIKu5rmaGYYf9EE9a6VtFnsQ7YTOvwWI9642NX:TCqJZ95KB7SYxKOMUJkY3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_2e965ae3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e965ae359bcc693148128a48232f8c4e8a8beb84b2af822eb9abe4b0fa5a8da"
    family = "unknown"
    file_name = "RFQ ORDER LIST.js"
    file_type = "js"
    first_seen = "2026-10-08 02:15:47"
  condition:
    hash.sha256(0, filesize) == "2e965ae359bcc693148128a48232f8c4e8a8beb84b2af822eb9abe4b0fa5a8da"
}
```

### Sample 27: `4b8ff07916069c2e`

| Field | Value |
|---|---|
| SHA-256 | `4b8ff07916069c2e4249264e3f328ff20bba73f853058603797d514658c6cbf6` |
| Family label | `ValleyRAT` |
| File name | `76D096206F9FC7ACD8399789E603BF1C.dll` |
| File type | `dll` |
| First seen | `2026-10-08 02:05:10` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76d096206f9fc7acd8399789e603bf1c` |
| SHA-1 | `896ceb9ecf94c822857974e6af00535de2606d04` |
| SHA-256 | `4b8ff07916069c2e4249264e3f328ff20bba73f853058603797d514658c6cbf6` |
| SHA3-384 | `d524aefbccdc1499f27c69866a882137769d4fc4fcb66ddec966fe33856aabdbc75a29b59f4220fac64a79ded6c69202` |
| IMPHASH | `ed719d06b435e943e2137e8d090ae910` |
| TLSH | `T1CD847D01B5818131E9AE0934B835DBA75A7DB8710BE4D4DFA3C44DAE9E207D1EB3871B` |
| SSDEEP | `6144:AcZZ+x7m+cWCDq7ZNIFTRhUE1Tk6++a3/z3mDAa/SnkuVNzEAYEQHWpo:JQc8nIFTRp1TkhhGWVt01` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_027_4b8ff079
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8ff07916069c2e4249264e3f328ff20bba73f853058603797d514658c6cbf6"
    family = "ValleyRAT"
    file_name = "76D096206F9FC7ACD8399789E603BF1C.dll"
    file_type = "dll"
    first_seen = "2026-10-08 02:05:10"
  condition:
    hash.sha256(0, filesize) == "4b8ff07916069c2e4249264e3f328ff20bba73f853058603797d514658c6cbf6"
}
```

### Sample 28: `f5de41608cef6956`

| Field | Value |
|---|---|
| SHA-256 | `f5de41608cef69564120fe3d3641595e00c6b79d43a5a4a21e966dc971e0470a` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-08 01:41:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4ab8767fc891a314576ae5469989bd3` |
| SHA-1 | `95cb610353bd062d7886609467de7229215e7b03` |
| SHA-256 | `f5de41608cef69564120fe3d3641595e00c6b79d43a5a4a21e966dc971e0470a` |
| SHA3-384 | `d7b2479426cb58992fbc9b794dc5ca5af5f06d26bb81ccd59aa2a896a57765dd040ffa31e01d55dc7e25a4777ac1ad30` |
| TLSH | `T1BD465B55FC1D68A3D6C976752F7612D43639BC485F82C3232A24BB3DAAF23588F12271` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:DXPnC21/mQIJ0o8WDGk8Mo7TZIF+S0e9Gp5E6:DXPCE/vI8WDGQB+i9G/E6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_f5de4160
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5de41608cef69564120fe3d3641595e00c6b79d43a5a4a21e966dc971e0470a"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-08 01:41:36"
  condition:
    hash.sha256(0, filesize) == "f5de41608cef69564120fe3d3641595e00c6b79d43a5a4a21e966dc971e0470a"
}
```

### Sample 29: `eee4ac11b0d5d301`

| Field | Value |
|---|---|
| SHA-256 | `eee4ac11b0d5d301b3e42cfd8ae1eeb91e13eb4283d2e1cba1dbbdcaf263c480` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-08 01:41:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98eac7a7c6c69dd1e519b696632f7598` |
| SHA-1 | `f9e5ee236e7c6718ec6fcd5e84562c0655053e6b` |
| SHA-256 | `eee4ac11b0d5d301b3e42cfd8ae1eeb91e13eb4283d2e1cba1dbbdcaf263c480` |
| SHA3-384 | `6543bc38b3bd265ba258992c8979d9655367138c45abdf0d9dc7674c70c324a23728a517b77fceb29ec54359cf164f61` |
| TLSH | `T12FF52A167F049FFBC41CCF704EBDC706C06CAD92D5F555267668878DB9AA3022B13AA8` |
| SSDEEP | `49152:sd+gDlvZUeFxbFJ3T3+/I2pN6u1nejRS:s/DlvZUeXFJMI2xny` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_eee4ac11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eee4ac11b0d5d301b3e42cfd8ae1eeb91e13eb4283d2e1cba1dbbdcaf263c480"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-08 01:41:34"
  condition:
    hash.sha256(0, filesize) == "eee4ac11b0d5d301b3e42cfd8ae1eeb91e13eb4283d2e1cba1dbbdcaf263c480"
}
```

### Sample 30: `bc2c00af55c952dd`

| Field | Value |
|---|---|
| SHA-256 | `bc2c00af55c952dd304f074322ff8766bc00b851fb75c076d7da503f33edfb62` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-10-08 01:37:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22fb6a673f56a254039c4f0db0ae147f` |
| SHA-1 | `605b2b7f1989e656a59370b008ae51f92ca19273` |
| SHA-256 | `bc2c00af55c952dd304f074322ff8766bc00b851fb75c076d7da503f33edfb62` |
| SHA3-384 | `85bceb9e56def2589c3e278d30154215f903201321b4f1a7b5696d8bab1539f93f5d32e0f3ef088c3d698a56ff4c245b` |
| TLSH | `T1C644C60B6F228F2EF26A87B047F34D359B5876D71AE1D681D1ACD5141F202CE641FBA8` |
| TELFHASH | `t1ba4182580d7913a4a2256c5d449dff2bd6a331dfbe166c238e11e86eeb69f834d10c0d` |
| SSDEEP | `3072:6EXVBeOVBCEQcJW78e1MjPmc4tKxEhhQgSzgpibL9Ef3x9lv:6EXTVsPcJte4urD2DgkJEPpv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_bc2c00af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2c00af55c952dd304f074322ff8766bc00b851fb75c076d7da503f33edfb62"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-10-08 01:37:39"
  condition:
    hash.sha256(0, filesize) == "bc2c00af55c952dd304f074322ff8766bc00b851fb75c076d7da503f33edfb62"
}
```

### Sample 31: `7c0eca069425de62`

| Field | Value |
|---|---|
| SHA-256 | `7c0eca069425de62a1e39073e62206e8c7b2082aa6163daea602c16c869f3846` |
| Family label | `unknown` |
| File name | `purchase order.rar` |
| File type | `rar` |
| First seen | `2026-10-08 01:36:20` |
| Reporter | `anonymous` |
| Tags | `rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e9e6b6f5644dcd1b2aec422e7dc6b4a` |
| SHA-1 | `415da79fcac69145b0abea0e12fee04ade701ecc` |
| SHA-256 | `7c0eca069425de62a1e39073e62206e8c7b2082aa6163daea602c16c869f3846` |
| SHA3-384 | `857c7f73a67a2fdb3db70d02cef3cee250a401fd71feb926ccc08934e7c83e35a030f510aa037ce08e5dee0a0dee7496` |
| TLSH | `T13F16333BF4F1622C96D3E112C4755C1AB66D40E99B19F0A2BCBCB1C144EA57E297ACF0` |
| SSDEEP | `98304:ixVcpzd15fjRnRJBbdzutd1+N780H7Mbz2Mho+P30:ixqz15fNnRfhzgI780Hgbz2YP30` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_7c0eca06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c0eca069425de62a1e39073e62206e8c7b2082aa6163daea602c16c869f3846"
    family = "unknown"
    file_name = "purchase order.rar"
    file_type = "rar"
    first_seen = "2026-10-08 01:36:20"
  condition:
    hash.sha256(0, filesize) == "7c0eca069425de62a1e39073e62206e8c7b2082aa6163daea602c16c869f3846"
}
```

### Sample 32: `a20fd13bc48d9d09`

| Field | Value |
|---|---|
| SHA-256 | `a20fd13bc48d9d092746ca0ae0493a7b4280ac81e7eb6731151761ac8cc91dba` |
| Family label | `unknown` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-10-08 01:33:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb2ff68f56a18098c2a6486195ce6407` |
| SHA-1 | `5faeee92cb5ef9ae4abfdb760dca89bc03dcff39` |
| SHA-256 | `a20fd13bc48d9d092746ca0ae0493a7b4280ac81e7eb6731151761ac8cc91dba` |
| SHA3-384 | `a6cd84fd3a0d8d9d050379e0591924c464e29bc9655144debb9d4a16c79048f275d4901413e6211f8c9299b4084270f4` |
| TLSH | `T11C565C81FB4CA125EA4A0B3288730F7473605D85D1E4996F170AF72F06B26F6698FED4` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:+hmpEWcA2SOol/dU+rfiLmnwI8s6Q9Vmn4jEL:yCT9nwIJvunjL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_a20fd13b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20fd13bc48d9d092746ca0ae0493a7b4280ac81e7eb6731151761ac8cc91dba"
    family = "unknown"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-08 01:33:56"
  condition:
    hash.sha256(0, filesize) == "a20fd13bc48d9d092746ca0ae0493a7b4280ac81e7eb6731151761ac8cc91dba"
}
```

### Sample 33: `f5cd52e208bef630`

| Field | Value |
|---|---|
| SHA-256 | `f5cd52e208bef630b6a6431e0e435e085e9e10106be9bb4c72e6147f1362a789` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-08 01:33:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0a55f7f047705ae869933bc01d5b0da` |
| SHA-1 | `d8fed21a7267bd0e489c3a5b21d7cdb5a3d8445a` |
| SHA-256 | `f5cd52e208bef630b6a6431e0e435e085e9e10106be9bb4c72e6147f1362a789` |
| SHA3-384 | `dc6e16c0a77957e04088be4f333fa61e96fa4be432b0e27bd9f23aedc44844586763c32019a16d72d20805c3edd9a4fe` |
| TLSH | `T14B93E551BC82562BC5E023BAA67E668D336477E4C2CF722BC8214B257BC561F0C63F95` |
| TELFHASH | `t1d9e06800fd699a1ca9d39670ed5902b6a2022233b61b0b11cfe4cbd0843b004b60de9e` |
| SSDEEP | `1536:Cd+t0rbCuNhS7CVha4m2WiLMBZO+WC27nVDuw8GSr8zn:8+tsCurVDN+ouw8Lin` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_f5cd52e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5cd52e208bef630b6a6431e0e435e085e9e10106be9bb4c72e6147f1362a789"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-08 01:33:53"
  condition:
    hash.sha256(0, filesize) == "f5cd52e208bef630b6a6431e0e435e085e9e10106be9bb4c72e6147f1362a789"
}
```

### Sample 34: `199694033b66e4b8`

| Field | Value |
|---|---|
| SHA-256 | `199694033b66e4b868e19e1b17c10e7e402ffb58bf3c989e91ff45e6d65c7956` |
| Family label | `unknown` |
| File name | `macho_199694033b66.bin` |
| File type | `macho` |
| First seen | `2026-10-08 01:26:18` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1fd3dc435a78a730894fef17952b2b7` |
| SHA-1 | `0454789e9ff0221da9c3cbaf7d11a14e9edfa801` |
| SHA-256 | `199694033b66e4b868e19e1b17c10e7e402ffb58bf3c989e91ff45e6d65c7956` |
| SHA3-384 | `c571a13039b3334ec4b4a8703b722768f2f142b5f737f822ab0d4e98be58bc1c068390b0198c86519defae2b72c6cab2` |
| TLSH | `T1D445F142CF6250D6F6CCCB342B3B9E239F656535858921DB63911E988E313D3F16B32A` |
| SSDEEP | `24576:nCe37owodwmUjpZym+/u4SdY1kfSmwHpX+K:nv7owmbt/u/iIdS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_19969403
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "199694033b66e4b868e19e1b17c10e7e402ffb58bf3c989e91ff45e6d65c7956"
    family = "unknown"
    file_name = "macho_199694033b66.bin"
    file_type = "macho"
    first_seen = "2026-10-08 01:26:18"
  condition:
    hash.sha256(0, filesize) == "199694033b66e4b868e19e1b17c10e7e402ffb58bf3c989e91ff45e6d65c7956"
}
```

### Sample 35: `a527b6aee124dba9`

| Field | Value |
|---|---|
| SHA-256 | `a527b6aee124dba9df0ece29610bc141bf532075189e0d62a7e26f343844f867` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-08 01:23:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `842f69c1f2bc009571d4e7565afaaf09` |
| SHA-1 | `9db94f5fafb3c2ed905a1431973a08851e88c3b1` |
| SHA-256 | `a527b6aee124dba9df0ece29610bc141bf532075189e0d62a7e26f343844f867` |
| SHA3-384 | `8e6cbec8307b8a7dc293b24f3d8436ffd8e68f04aa72fe0f206b5cb1cb01b3d9b5408bfc6bf96ec6c51f5699e8641a4a` |
| TLSH | `T153B59E44AA8D683AEAC6F0FCCD4C08A0731F35E41514C3BA7C25915DED86BE58B79B72` |
| SSDEEP | `24576:6Oy7brzZM+d1OMR3tkqWfEoR73L4vK7XKIVraV7q1nLWOmeEKHkWV/pH67CnjXCc:63/WtMR3tmR7nGenLNdEJMHd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_a527b6ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a527b6aee124dba9df0ece29610bc141bf532075189e0d62a7e26f343844f867"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-08 01:23:20"
  condition:
    hash.sha256(0, filesize) == "a527b6aee124dba9df0ece29610bc141bf532075189e0d62a7e26f343844f867"
}
```

### Sample 36: `7ec4e71a172d2112`

| Field | Value |
|---|---|
| SHA-256 | `7ec4e71a172d211208be0bc17434f0812a49d74674f406a1666c46a984757a93` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-10-08 01:19:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af14c4c5d5429f3d825132d347bdc926` |
| SHA-1 | `8ef2bc8ba61b8abc12eae1584e5482ac9ea99c29` |
| SHA-256 | `7ec4e71a172d211208be0bc17434f0812a49d74674f406a1666c46a984757a93` |
| SHA3-384 | `a656c74ab06a37e3461ff30b3b01aa35927bc5574dc8ed937e9ee9208ff4694b3ab142501dd4629db0addec548e16c52` |
| TLSH | `T1B9F37D53EC266F5AD217A4F0B2F29F381B13FD6689931E95A462EEF04047DC9B4053B8` |
| SSDEEP | `3072:cu+dkK6U+2wDMo3+InUNf8eRF3dRYWbC8wrSVu:cuR2YZ3+InUNf5lBburx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_7ec4e71a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec4e71a172d211208be0bc17434f0812a49d74674f406a1666c46a984757a93"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-10-08 01:19:41"
  condition:
    hash.sha256(0, filesize) == "7ec4e71a172d211208be0bc17434f0812a49d74674f406a1666c46a984757a93"
}
```

### Sample 37: `fe1d7aedc8ebd297`

| Field | Value |
|---|---|
| SHA-256 | `fe1d7aedc8ebd2976e1c7041a6982635698cc77e93eeea12a844f4ce06e620b1` |
| Family label | `Mirai` |
| File name | `bot` |
| File type | `elf` |
| First seen | `2026-10-08 01:19:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `404325eb5c8ba507b682e6938cece066` |
| SHA-1 | `1b1391defdd8a32e0303c343dd98f49e59268a7d` |
| SHA-256 | `fe1d7aedc8ebd2976e1c7041a6982635698cc77e93eeea12a844f4ce06e620b1` |
| SHA3-384 | `be486c2c162ea8da8dcd1839dcca35542b231519aa3c9dcc97e481d8ba3c772df26d0284f5a464f38ede4597f4881cef` |
| TLSH | `T1ABC55B02FA6240A9D969C834835DA523F734B84E47103BEB2BD4AB103F29FE15F79B55` |
| TELFHASH | `t15182c1b7e3d43aac4bd4c31442a5695d8afb09a503666caac73a7bd3cf16f114b0c871` |
| SSDEEP | `49152:n6Zh3apS01vYZYGYEY4YGlDx4xiun7DtCOH5pzjYBQAde9cQqFfpuaa9VF0f+ffm:CDCEOH5zBqDALl3m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_fe1d7aed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1d7aedc8ebd2976e1c7041a6982635698cc77e93eeea12a844f4ce06e620b1"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-10-08 01:19:39"
  condition:
    hash.sha256(0, filesize) == "fe1d7aedc8ebd2976e1c7041a6982635698cc77e93eeea12a844f4ce06e620b1"
}
```

### Sample 38: `9d984c4c21b2c708`

| Field | Value |
|---|---|
| SHA-256 | `9d984c4c21b2c708cc1df1d8ad8687472390ba6c08c4ff95dbc63facc9dcef7a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-08 01:15:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5342289731d87c0ea5847f658f716b6c` |
| SHA-1 | `99031205a2945e0c7f9e26801cd9c0f1fef7d6c1` |
| SHA-256 | `9d984c4c21b2c708cc1df1d8ad8687472390ba6c08c4ff95dbc63facc9dcef7a` |
| SHA3-384 | `40b15b436a7fba44bf5619dbb8760fa55a4f1607caba602d6053e6f5f60453767f1790428df5081b8835e6166178879c` |
| TLSH | `T13A04B50E6E198F7CF79987345BB79E31925833872AE1C582E1ACD7105E6024F641FFA8` |
| TELFHASH | `t1d12193584a7412e067325c8c5a9dff7bd67130ef6b161c378e11a8aabb6d8419e20c0c` |
| SSDEEP | `3072:1OATXjpCgqDJHDexBJKfjPV4kuMu8hJBQX/uw9EfszRpSP/QBrj4jTv3TcJ2tD2X:1OATXjpCgqDJHDexBJKfjPV4kuMu8hJ2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_9d984c4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d984c4c21b2c708cc1df1d8ad8687472390ba6c08c4ff95dbc63facc9dcef7a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-08 01:15:30"
  condition:
    hash.sha256(0, filesize) == "9d984c4c21b2c708cc1df1d8ad8687472390ba6c08c4ff95dbc63facc9dcef7a"
}
```

### Sample 39: `77d2fc48b9f21ea2`

| Field | Value |
|---|---|
| SHA-256 | `77d2fc48b9f21ea2a65a90f07f9544343e47d08edbeafe17c306c9cc143fda80` |
| Family label | `unknown` |
| File name | `ppc64le` |
| File type | `elf` |
| First seen | `2026-10-08 01:11:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0848937c53851a6e4cc112dd4940a156` |
| SHA-1 | `9665ebd1be04ef3d25a798b42735ab51c865801a` |
| SHA-256 | `77d2fc48b9f21ea2a65a90f07f9544343e47d08edbeafe17c306c9cc143fda80` |
| SHA3-384 | `6890a1f0dee69be48e9402cb173174e20502f7577d82a4daaf7f2237d074711e858952d325c02887357c33337908160a` |
| TLSH | `T1C5564A02FA0D2F95C920497385B74EA127A26E956B318B52DB04F27F7DF23161F16F88` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:lANwh9Oaul3397A3RaItgQj5ai1JqgQCLAQCoFk5EK:uNwh9Oauln9A3RxW1CfXgEK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_77d2fc48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77d2fc48b9f21ea2a65a90f07f9544343e47d08edbeafe17c306c9cc143fda80"
    family = "unknown"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-10-08 01:11:39"
  condition:
    hash.sha256(0, filesize) == "77d2fc48b9f21ea2a65a90f07f9544343e47d08edbeafe17c306c9cc143fda80"
}
```

### Sample 40: `f2df79291d08c29e`

| Field | Value |
|---|---|
| SHA-256 | `f2df79291d08c29e4dd851ac2d73d4440da32802585fed60418973cd1a7b0044` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-10-08 00:54:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d650293f70d0cd741a3e7104b5b0e1a` |
| SHA-1 | `a2c258fa22a6ba7a527190d8140a18f0b2d8febc` |
| SHA-256 | `f2df79291d08c29e4dd851ac2d73d4440da32802585fed60418973cd1a7b0044` |
| SHA3-384 | `8981daae8df4dee9fa80219c749827b4a1c66a8cbf19e9484376c7fe03145bbc76a4ccfea4549c63f97d1a10fe4597db` |
| TLSH | `T14D44E80AAF610FFBD86BDD3702EA0B0524CCA81726A53B757274D918F54A68F4AD3C74` |
| SSDEEP | `3072:MXCYDzUL2emMXiY7aWAobMqcFSTmGQtQIlxTkrTTeq:a9MOBFEmpjyDeq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_f2df7929
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2df79291d08c29e4dd851ac2d73d4440da32802585fed60418973cd1a7b0044"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-10-08 00:54:20"
  condition:
    hash.sha256(0, filesize) == "f2df79291d08c29e4dd851ac2d73d4440da32802585fed60418973cd1a7b0044"
}
```

### Sample 41: `52ac6da98c763673`

| Field | Value |
|---|---|
| SHA-256 | `52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002` |
| Family label | `unknown` |
| File name | `52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002.exe` |
| File type | `exe` |
| First seen | `2026-10-08 00:54:09` |
| Reporter | `Kejult` |
| Tags | `DefenderTamper, Dropper, exe, KillAV, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ef6f83e38f66810104568442ff3ed8b` |
| SHA-1 | `b7dc6da7d9e8dffba82b920401ff20dd448b2f19` |
| SHA-256 | `52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002` |
| SHA3-384 | `754fe3a9fffad3a2bd7f2f67fa4c108999b7cdbe9d2dd7a63bb3dd54ac8af0537a01189b9816fd27b86318df5e7a7bac` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T14C48F01663E111AAD577D178C7AB6203EB72B40713308BDB329C43652F73AE45E7AB60` |
| SSDEEP | `1572864:1Pp36F/iKRzAo0EL9uXpXFxAI/MZqNrGZVOc4XIoC3MnluZQrZP:1PpIlAheuXpX/z/5NivOcC7hlTrl` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_52ac6da9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002"
    family = "unknown"
    file_name = "52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002.exe"
    file_type = "exe"
    first_seen = "2026-10-08 00:54:09"
  condition:
    hash.sha256(0, filesize) == "52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002"
}
```

### Sample 42: `c871c21a1e5398ba`

| Field | Value |
|---|---|
| SHA-256 | `c871c21a1e5398bab70d1c5155e7c8a6675b07082faf9a158de552f12ed6d357` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-08 00:50:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a846eaca11314976ca4f61f6fb0ddb57` |
| SHA-1 | `7cf20660f393329d2c82f885e2201590eae0cc2c` |
| SHA-256 | `c871c21a1e5398bab70d1c5155e7c8a6675b07082faf9a158de552f12ed6d357` |
| SHA3-384 | `0333c7bae7715b7bcce3cb044dacac5487a4c007a3999d7a30ce9df7b3225b81fa6e44c8f1b4a3715f124af3cd1384f3` |
| TLSH | `T124561897B9D24982C5E43A77A9BE80C533630EBA9B8652575D04FE3C3EBE1D90E34314` |
| TELFHASH | `t1b7d097034f9c3bd86fd0800a0430016fcbed30f83a482b889f1d329f8f2282d40e1092` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:79NH8DvfZMkrW6lnq9KlTOu/V1QphzCWZ7JRzSkfX5ELy:CvfZMkrWonq8llPW9JRzjBEe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_c871c21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c871c21a1e5398bab70d1c5155e7c8a6675b07082faf9a158de552f12ed6d357"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-08 00:50:35"
  condition:
    hash.sha256(0, filesize) == "c871c21a1e5398bab70d1c5155e7c8a6675b07082faf9a158de552f12ed6d357"
}
```

### Sample 43: `76f091251ac65574`

| Field | Value |
|---|---|
| SHA-256 | `76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb` |
| Family label | `unknown` |
| File name | `76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb.exe` |
| File type | `exe` |
| First seen | `2026-10-08 00:46:53` |
| Reporter | `Kejult` |
| Tags | `BypassUAC, exe, injector, loader, trojan, UACbypass` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8d2983d35e3fece46e9298d341e824c` |
| SHA-1 | `00657996cb23603d23ea9e4315b892895dfed364` |
| SHA-256 | `76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb` |
| SHA3-384 | `c524e1b255cef78a260eeaaba31361064fd1437d5bbf7a3d59d0d4474182c06beb21b76fa43d382a7d336453e80a44fb` |
| IMPHASH | `694a10f92efdb5ba9c32ad08fff67a41` |
| TLSH | `T1BDE4E665F5637C90ED534BB5D84A0583A8BE3B40C806EEBE511A6D4D3B632678C9E30F` |
| SSDEEP | `6144:hgJikQ0HlfHI8ThuvGF85bXLprXFKG4GGGGGXGGGGGcGGVZ/GZGGVGGdGGGG7gGu:hgpQ6lfooug85LLpBSXNDo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_76f09125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb"
    family = "unknown"
    file_name = "76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb.exe"
    file_type = "exe"
    first_seen = "2026-10-08 00:46:53"
  condition:
    hash.sha256(0, filesize) == "76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb"
}
```

### Sample 44: `0a2d67c0390cb31c`

| Field | Value |
|---|---|
| SHA-256 | `0a2d67c0390cb31ce23d132d1e96c20385ae61d482c1627669ae3d9b7a7e77c4` |
| Family label | `Mirai` |
| File name | `mbupload-qudvn1jh.bin` |
| File type | `elf` |
| First seen | `2026-10-08 00:44:09` |
| Reporter | `wristhulk` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa5d68b55600b59ca4d757cdf51c8608` |
| SHA-1 | `aacd54930c9db300d6db9c1bf329363bf737abe4` |
| SHA-256 | `0a2d67c0390cb31ce23d132d1e96c20385ae61d482c1627669ae3d9b7a7e77c4` |
| SHA3-384 | `aeb23d8a357933a0629880743a32fff61616c422f27ac137c89ff54bed74ef79e8c9a685cd8dcad81518138b95c6cda2` |
| TLSH | `T16F157C89E7C3D4F1F65304F10A4FC7E21528A2165063F6F2EB8C1A9778B6B526E1632D` |
| TELFHASH | `t1bcc1f1b329609cecb7f05902865b7224de36e02726f029760df26451b7b2e436f36d78` |
| SSDEEP | `24576:BegOhPPhHINr+mxdzlbdVg32NNdmOwO20Qb:BChPPhoNhnpbgp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_0a2d67c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a2d67c0390cb31ce23d132d1e96c20385ae61d482c1627669ae3d9b7a7e77c4"
    family = "Mirai"
    file_name = "mbupload-qudvn1jh.bin"
    file_type = "elf"
    first_seen = "2026-10-08 00:44:09"
  condition:
    hash.sha256(0, filesize) == "0a2d67c0390cb31ce23d132d1e96c20385ae61d482c1627669ae3d9b7a7e77c4"
}
```

### Sample 45: `17fcb5d7d251b968`

| Field | Value |
|---|---|
| SHA-256 | `17fcb5d7d251b9684177a28843a4aaaee86539469ad20de3deb2063ee18ed63a` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-10-08 00:40:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `235eed6080b09debcdf28fc012892a9b` |
| SHA-1 | `d3851c1f3a7169f5c06ecddf90bad9370e48a1eb` |
| SHA-256 | `17fcb5d7d251b9684177a28843a4aaaee86539469ad20de3deb2063ee18ed63a` |
| SHA3-384 | `5e87af371374ec89d54a702e3282d432431eec3705fe71b25e4701ec810946e91fd39c27dca06a2a8e6fd5c5fd412309` |
| TLSH | `T1CC95F8A7BC428A42C4D425BBF97E90D4335717B8D3EB7216EC05CA356ACF4990E3AB11` |
| TELFHASH | `t144d0eb027f3a208e9fcaf035628a507331e83834ee1380a00a28ae0f920b9b4301f00c` |
| SSDEEP | `24576:39dzuNf9Phuka/T6bW2QUwXzW4k4cdK8sAavWxWtlaIaVJnEb:tQf9PoW+Xz2K8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_17fcb5d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17fcb5d7d251b9684177a28843a4aaaee86539469ad20de3deb2063ee18ed63a"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-08 00:40:19"
  condition:
    hash.sha256(0, filesize) == "17fcb5d7d251b9684177a28843a4aaaee86539469ad20de3deb2063ee18ed63a"
}
```

### Sample 46: `0bff11bb3bf1c344`

| Field | Value |
|---|---|
| SHA-256 | `0bff11bb3bf1c34493d7185fc47b738d302d63a1b740d751de2eabfc1bc173c7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-08 00:40:08` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, signed, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cef710a5c1c61c76cdc25d395f2415f` |
| SHA-1 | `ec789669830deafe6668e82e8019ed659ba8ff97` |
| SHA-256 | `0bff11bb3bf1c34493d7185fc47b738d302d63a1b740d751de2eabfc1bc173c7` |
| SHA3-384 | `2967472121d9a13fa59faa2ca2763bd111be622245ba6d35ffcbe23df47b88b7c236ce0983b96233fde1cee76d60b14c` |
| IMPHASH | `f4cff7283978573ad2393aebe54a0b80` |
| TLSH | `T1ACC3BF16B7D67C98C20B8470E459A23ABEB3F275A4DEA16856CCD11C6CE1AC00F1F57B` |
| SSDEEP | `3072:8XMnRDMcti2TPti2pTHnmUPW4xrvj1/dNZn7uJ:aMRwcti2TPtPdnplxrvj1/nZn7uJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_0bff11bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bff11bb3bf1c34493d7185fc47b738d302d63a1b740d751de2eabfc1bc173c7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 00:40:08"
  condition:
    hash.sha256(0, filesize) == "0bff11bb3bf1c34493d7185fc47b738d302d63a1b740d751de2eabfc1bc173c7"
}
```

### Sample 47: `4aff30bdeee80b3d`

| Field | Value |
|---|---|
| SHA-256 | `4aff30bdeee80b3d8c5357048f6a9c92f216a079569d11db9aacfc7f1e02fc9b` |
| Family label | `RemusStealer` |
| File name | `89d4bf8726440c1e25623d10bf36c52de91113130b058bc4fcb4c637758c2070.zip` |
| File type | `zip` |
| First seen | `2026-10-08 00:31:58` |
| Reporter | `Kejult` |
| Tags | `file-pumped, remus, RemusStealer, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `116cad2bf66115bdd321b04075cdbde1` |
| SHA-1 | `65b2d4d5e9b82a2bce88c5047c37f209272238fb` |
| SHA-256 | `4aff30bdeee80b3d8c5357048f6a9c92f216a079569d11db9aacfc7f1e02fc9b` |
| SHA3-384 | `de1f9b93fc091f7adf2b8c2085f960a85902f079e652470ca953670bcdf0249b5879a7164a83bbe28d2e90cf90491881` |
| TLSH | `T14EF56268978BF5FAC09D4170625F8BAF76B185DA0391930AC7668C6E2C97FC07F61E01` |
| SSDEEP | `49152:1chMmwXXp6rto4U1CEY2TqhEhxRuXtGmupoQa6SvgeLsjxbtEOnOIPg0FKSJ4j81:czwHgZo4U0EY22mxijybWISClaR6` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_047_4aff30bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aff30bdeee80b3d8c5357048f6a9c92f216a079569d11db9aacfc7f1e02fc9b"
    family = "RemusStealer"
    file_name = "89d4bf8726440c1e25623d10bf36c52de91113130b058bc4fcb4c637758c2070.zip"
    file_type = "zip"
    first_seen = "2026-10-08 00:31:58"
  condition:
    hash.sha256(0, filesize) == "4aff30bdeee80b3d8c5357048f6a9c92f216a079569d11db9aacfc7f1e02fc9b"
}
```

### Sample 48: `893b3638dccebe9c`

| Field | Value |
|---|---|
| SHA-256 | `893b3638dccebe9c646d2301632ba5210f41b777dffd69e6b6e41bcf400d7e3c` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-08 00:30:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71797e13c152a817a3b8a5b8054d7569` |
| SHA-1 | `738b2745494a86eae8cecaf0aa3a1d42c4e45947` |
| SHA-256 | `893b3638dccebe9c646d2301632ba5210f41b777dffd69e6b6e41bcf400d7e3c` |
| SHA3-384 | `1c4b982fa694d6ec997dd677da9fd566860a2c878a3fb1159b32cdc421b0d7ddc5303b820bbe798f43e833a0a7106872` |
| TLSH | `T17DE35D8AF4029E7DFD4FE5BE44670E09E931A39131831B2A53DBFDA3A9311990D17E81` |
| SSDEEP | `3072:noDlIyA+oy+ZGiTUrDQCcX7ZLgLq2e9FdlJcNNu:RDy+ZGFcll2e9rcNNu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_893b3638
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "893b3638dccebe9c646d2301632ba5210f41b777dffd69e6b6e41bcf400d7e3c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-08 00:30:06"
  condition:
    hash.sha256(0, filesize) == "893b3638dccebe9c646d2301632ba5210f41b777dffd69e6b6e41bcf400d7e3c"
}
```

### Sample 49: `d54e450bcf0392d6`

| Field | Value |
|---|---|
| SHA-256 | `d54e450bcf0392d61af498d83b11271208049ee7679ab2576b7874cbad6bd43f` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-08 00:30:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7614f2187738a9838afbe697e83e9ca` |
| SHA-1 | `6e1f1d1ebdef70da4788de93bf4247027cf9c3e9` |
| SHA-256 | `d54e450bcf0392d61af498d83b11271208049ee7679ab2576b7874cbad6bd43f` |
| SHA3-384 | `701133761669fe04f475b4d665b910dfa0fa29aa5c7a7ef96bcb059924c349b2f093d66a776a65dfc89c209c99f6c71c` |
| TLSH | `T1BD563812FACB14F6E5031E3154BBA26F23315D054B24EBD7EB40BB29FD7B6912932219` |
| TELFHASH | `t1e0e2ee73059da4ec67e0450787af7220cef6e07b26d038f159f3b8c19a72d539a26978` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:hmrXzo/cisO4LtseA9hRMLRjredsydV7wurWe1KNrqOSrLIyk2b5Eq:QXzo/cBpI9hRMRSdsy37MpWNEq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_d54e450b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d54e450bcf0392d61af498d83b11271208049ee7679ab2576b7874cbad6bd43f"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-08 00:30:04"
  condition:
    hash.sha256(0, filesize) == "d54e450bcf0392d61af498d83b11271208049ee7679ab2576b7874cbad6bd43f"
}
```

### Sample 50: `58a017f405835569`

| Field | Value |
|---|---|
| SHA-256 | `58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05` |
| Family label | `unknown` |
| File name | `58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05.exe` |
| File type | `exe` |
| First seen | `2026-10-08 00:21:11` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eda6f08155d2299772d9730ea6f9aef6` |
| SHA-1 | `19d0186a7e9efdb414d17f7e2124741512d914e0` |
| SHA-256 | `58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05` |
| SHA3-384 | `5277797b2b5d090c6a3e04e7fa62b1fe7fe3e4f14cf1ae80a5838f89f7ce9b781be073d31e6f336a69346bc80adb3516` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1EBE61A1772C810ECCA4BD3B588B05E7912B23DAE5532778E0F99BE901F067956F68F48` |
| SSDEEP | `49152:v2yCL3XLBZUA4i7NhN9drQH0EftL4RcdW1LcNAxs8dyhcK0svR:EnvLkDNNR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_58a017f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05"
    family = "unknown"
    file_name = "58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05.exe"
    file_type = "exe"
    first_seen = "2026-10-08 00:21:11"
  condition:
    hash.sha256(0, filesize) == "58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05"
}
```

### Sample 51: `f0cd29fff42a7dad`

| Field | Value |
|---|---|
| SHA-256 | `f0cd29fff42a7dad4b00c7b1c684a7e759a159baef96f57a285e1ff7f61bbab5` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-08 00:18:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df3a53646508997ed98a15ae1c2c87a6` |
| SHA-1 | `8bc16cb258df5232ccf6b09ea73c87d0dc8eebcb` |
| SHA-256 | `f0cd29fff42a7dad4b00c7b1c684a7e759a159baef96f57a285e1ff7f61bbab5` |
| SHA3-384 | `a4de6a0d73f5ef876d30f3cc3adf480fae1cdf6add361a57e5cc1210a4b9328cdcaee7b0981048246fcbb5b18ce15b29` |
| TLSH | `T105E33A56E7404B13C0D62775B6EF424533239BA493EB73069928AFF43F8279E4E23A05` |
| TELFHASH | `t1ac310e755b22a1166961dd64d9fe87b1a51983131784ff33df2688cc240904ee72bc5f` |
| SSDEEP | `3072:ueP4E/YaXCsqdYEgNGB4vZ7crGzRSM/9jlBvyZ:uetYaXCsqdYFNxNcrGzgM/9Tw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_f0cd29ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0cd29fff42a7dad4b00c7b1c684a7e759a159baef96f57a285e1ff7f61bbab5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-08 00:18:46"
  condition:
    hash.sha256(0, filesize) == "f0cd29fff42a7dad4b00c7b1c684a7e759a159baef96f57a285e1ff7f61bbab5"
}
```

### Sample 52: `9fac6abd1c35da9e`

| Field | Value |
|---|---|
| SHA-256 | `9fac6abd1c35da9e68fb4f00f33de82306adf96093ea806f3c42d4a153e39c9e` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-07 23:53:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d57e2ab1e93a3c4f49fabb96472bbd7a` |
| SHA-1 | `e5de4c6188d67924b17d5514d7e284c588ac2480` |
| SHA-256 | `9fac6abd1c35da9e68fb4f00f33de82306adf96093ea806f3c42d4a153e39c9e` |
| SHA3-384 | `5442042a83412328a7e7ffdeae05028d7d2b201a659f604554ca3726e9f241b1778b040dc4b0a50d9a12a9fbfcde819c` |
| TLSH | `T122E33B56EB404B13C0D61779B6EF424533239BA493EB730699246FF43F8679E4E23A05` |
| TELFHASH | `t1ac310e755b22a1166961dd64d9fe87b1a51983131784ff33df2688cc240904ee72bc5f` |
| SSDEEP | `3072:le+4w/HaAYe6Qxse54PO8tqd77c2GvyfV7Xqomyw:lesHaAYe6QxxOudc2GvyfV76VT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_9fac6abd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fac6abd1c35da9e68fb4f00f33de82306adf96093ea806f3c42d4a153e39c9e"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-07 23:53:20"
  condition:
    hash.sha256(0, filesize) == "9fac6abd1c35da9e68fb4f00f33de82306adf96093ea806f3c42d4a153e39c9e"
}
```

### Sample 53: `b83161e15983296d`

| Field | Value |
|---|---|
| SHA-256 | `b83161e15983296d02b14206f2a00f6ce7928d7f6c5b56c80aaa5c8e115fd7f7` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-10-07 23:49:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaa4a4fc52c011f0fe9b9d9fac032c38` |
| SHA-1 | `f954306e53c4959cf235112a2639f645b0432716` |
| SHA-256 | `b83161e15983296d02b14206f2a00f6ce7928d7f6c5b56c80aaa5c8e115fd7f7` |
| SHA3-384 | `0297361d93139d7f4fd0bed9cc432abc7acfc1aa91d53bcb941e99474eb3ec4a29d0ce5aa3e8b68b7ef6444cc27d5bf4` |
| TLSH | `T1D1143B02B71D0E43C1632EF0267B1BE097EBAE6224B5E240751FBEC98271DB61545EDE` |
| SSDEEP | `3072:vaxff5esizMypniTahxZUP73Ku7Z8gZIJ:8QJznmahxZUD3KkZyJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_b83161e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83161e15983296d02b14206f2a00f6ce7928d7f6c5b56c80aaa5c8e115fd7f7"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-10-07 23:49:42"
  condition:
    hash.sha256(0, filesize) == "b83161e15983296d02b14206f2a00f6ce7928d7f6c5b56c80aaa5c8e115fd7f7"
}
```

### Sample 54: `d441b9180182969f`

| Field | Value |
|---|---|
| SHA-256 | `d441b9180182969f844543b556a012a87b056b333f0a98da9b6abdaa7c791805` |
| Family label | `unknown` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-07 23:46:23` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85bbc628ccb0e66190e9553f3814aa65` |
| SHA-1 | `7b01660506af5bcfe883da6364a67b4cc0050d08` |
| SHA-256 | `d441b9180182969f844543b556a012a87b056b333f0a98da9b6abdaa7c791805` |
| SHA3-384 | `33fabb2eb40cbdfcdf78b3a75b9ec4e53c4712e41c529326fdb36a8dc16e149ae9cdb34a587f0116300a474ef3c22d14` |
| TLSH | `T1EF66F919EDC42FE6C82D5B3490EACA9613B45D104AF1463626A5FFA9BC772347F4388C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:cqSJ5WLZI4D9jwI+dor9SYKdnXE11/75EG8l:Nx5Ok1lEG8l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_d441b918
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d441b9180182969f844543b556a012a87b056b333f0a98da9b6abdaa7c791805"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-07 23:46:23"
  condition:
    hash.sha256(0, filesize) == "d441b9180182969f844543b556a012a87b056b333f0a98da9b6abdaa7c791805"
}
```

### Sample 55: `feaa5822f2af1ce3`

| Field | Value |
|---|---|
| SHA-256 | `feaa5822f2af1ce3686d527d14877332c69ea565e2afcff25ef437e3b915e300` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-07 23:44:09` |
| Reporter | `Bitsight` |
| Tags | `B, BB4.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d30ef63dae06d200e1cfdd643ba908a` |
| SHA-1 | `6f441fae059da36b3a46977dd5624c6e3c57ae07` |
| SHA-256 | `feaa5822f2af1ce3686d527d14877332c69ea565e2afcff25ef437e3b915e300` |
| SHA3-384 | `5547eba71570476f9ee954d662aa07a06179ec13b1609287491f753726224b966ddafd4d6a2e02caeb9e414ffea6d98f` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T120D6022B634B663DE01986753672E21F683F6D316DD18C0D96FCB478FBB2170192E682` |
| SSDEEP | `196608:hcZOQ1IA3RF+PlEwvR9TGiY3KA933VvtVHT:hmOKIGEDJ9y3Kep/HT` |
| ICON-DHASH | `36f1dcb49ccc7166` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_feaa5822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "feaa5822f2af1ce3686d527d14877332c69ea565e2afcff25ef437e3b915e300"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 23:44:09"
  condition:
    hash.sha256(0, filesize) == "feaa5822f2af1ce3686d527d14877332c69ea565e2afcff25ef437e3b915e300"
}
```

### Sample 56: `9080cd485a8b9474`

| Field | Value |
|---|---|
| SHA-256 | `9080cd485a8b94742cce721c63ffd0266ee9b3684e48165db8b6b12e0d181760` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-07 23:42:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f915468572db3de220f5ebeea7e69d5e` |
| SHA-1 | `ab76661eee11cc042a15ef40d6e383bac1f74b4d` |
| SHA-256 | `9080cd485a8b94742cce721c63ffd0266ee9b3684e48165db8b6b12e0d181760` |
| SHA3-384 | `abaf69dd21f9bcf9ef7fcc517e904301215258bb3e397643a29092115d50a4621f579eb80eab96d06a4f1fd5aeb737fd` |
| TLSH | `T13CF52B16B920CFBDF08CE13054F3DA9411E168E309E5016EF368DB1C6EB5A4E5A3B9D9` |
| SSDEEP | `24576:T92t3z+S3NBtL34U9z3eNeN8MT6QQsYe82a3lmE0VT7h4OJ3Qe8tbuXYaKV9jiRN:T9gBN3MUSOEV+W45f3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_9080cd48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9080cd485a8b94742cce721c63ffd0266ee9b3684e48165db8b6b12e0d181760"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-07 23:42:46"
  condition:
    hash.sha256(0, filesize) == "9080cd485a8b94742cce721c63ffd0266ee9b3684e48165db8b6b12e0d181760"
}
```

### Sample 57: `7a0efc7fd55dd9e6`

| Field | Value |
|---|---|
| SHA-256 | `7a0efc7fd55dd9e665342b788b092f5660597ba1e3526f1bec3be14399a06e53` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-10-07 23:36:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cff92fc9d5ae444829ca90a616f3c983` |
| SHA-1 | `16e861ebef4b15d7deca92ec450707174cdd55ce` |
| SHA-256 | `7a0efc7fd55dd9e665342b788b092f5660597ba1e3526f1bec3be14399a06e53` |
| SHA3-384 | `5868da8190f984414c3715a743f1b8d4a125cc19ebdcdaba809abaa4e29a526006fe66424cf0d386c6876a27af6feac3` |
| TLSH | `T10CC34B22363A0B27C0E6683540F7D736B3F65BC92A64920B7A615EDC7F56AE034437B4` |
| TELFHASH | `t1f431ec755b22a5166961ed64ddfe8bb1951a83121784ff33df2688cc290a04ee72fc0f` |
| SSDEEP | `1536:H6uyXyWHbCs4EA9Ry2lh3rcieMEltEuX7WNO60MPRtQx2Kv02E5+ydn/Ohb:afH9A9JLrDvElVX7U8MPox2402E5+q8b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_7a0efc7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0efc7fd55dd9e665342b788b092f5660597ba1e3526f1bec3be14399a06e53"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-07 23:36:15"
  condition:
    hash.sha256(0, filesize) == "7a0efc7fd55dd9e665342b788b092f5660597ba1e3526f1bec3be14399a06e53"
}
```

### Sample 58: `4dcfaccade604435`

| Field | Value |
|---|---|
| SHA-256 | `4dcfaccade6044355f8b933ad74c97085497d7e34762e5eab473dd2b5804b486` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-07 23:32:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aee95714ed27ffa4a1fa643b7420d5d7` |
| SHA-1 | `f4bc88434089dfe5dc8364e29985cc9368b2e5ab` |
| SHA-256 | `4dcfaccade6044355f8b933ad74c97085497d7e34762e5eab473dd2b5804b486` |
| SHA3-384 | `9cbb742ddcebc274877b836381d76e49bf299a3a0a7e19d9895855b9e19c93f8c54ff0f82109604c2ab09e6ec8bcb0fe` |
| TLSH | `T164D3E91A7A158FADF28EC63147F78E3156A427D12B92E141E16CDB102F2139D6C4FFA8` |
| TELFHASH | `t1f4311e755b22a1166960dd68ddfe87b1a51a83131784ff33ef2688cc240a04ee72bc4f` |
| SSDEEP | `1536:mfFTBUgJNcjHw9dv6XTf67X2cTD+98NmDsEpopl/Gw07UQ6PL1:mYgJNaH56r88msEWpl/Gw0bm1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_4dcfacca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dcfaccade6044355f8b933ad74c97085497d7e34762e5eab473dd2b5804b486"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-07 23:32:34"
  condition:
    hash.sha256(0, filesize) == "4dcfaccade6044355f8b933ad74c97085497d7e34762e5eab473dd2b5804b486"
}
```

### Sample 59: `0bfabbd22e5fd617`

| Field | Value |
|---|---|
| SHA-256 | `0bfabbd22e5fd6175f5701ebcb2c54aad28e5bb1106a0d98ee2a7dc1cc39bda1` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-07 23:32:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee1a5cf48b6bdc5f9fd10e585ba47aa3` |
| SHA-1 | `0f6c2c00ac7a8f4ffdbd4ef753626d242a8c5b68` |
| SHA-256 | `0bfabbd22e5fd6175f5701ebcb2c54aad28e5bb1106a0d98ee2a7dc1cc39bda1` |
| SHA3-384 | `0fac754813ac262afeb079587e3ea2d679019cf4fd388a8db55ac8809e851fa876456ddaff4830c9738060ed0a7983ea` |
| TLSH | `T1D5E32882BB03DAF3D45311F112B75B218A71FC3B5C3BE682E7647DA199526C0A61736C` |
| TELFHASH | `t1c2614cb96b760cdc5b90ac03e24e5b31bd0dab7b246077b305f359b4326a941517bc38` |
| SSDEEP | `1536:Y+nYEONaAssTCU8RwQ5jTu2yQ01LiDz1sxNE5hemFDEpZ8Fu3NEqw39VFSwfWToD:GXTCvwQ5jygSeDzANEzlIZoudE/Kf1K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_0bfabbd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bfabbd22e5fd6175f5701ebcb2c54aad28e5bb1106a0d98ee2a7dc1cc39bda1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-07 23:32:32"
  condition:
    hash.sha256(0, filesize) == "0bfabbd22e5fd6175f5701ebcb2c54aad28e5bb1106a0d98ee2a7dc1cc39bda1"
}
```

### Sample 60: `d6bac5a15715c7e1`

| Field | Value |
|---|---|
| SHA-256 | `d6bac5a15715c7e1f917c1e9bda5631e852f0e61388efbbace90b5a00b653ad3` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-07 23:29:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd03720a56866b3b1aa255c4aa7f6ca1` |
| SHA-1 | `50ce22aa61b4a66aee96ffb85a8e37edbfcefc8e` |
| SHA-256 | `d6bac5a15715c7e1f917c1e9bda5631e852f0e61388efbbace90b5a00b653ad3` |
| SHA3-384 | `56bd5fb54d37b2cc110912d8ef6d9cd9c19b41bcd657d15edc287fb7b02d1968c1770308e631aedda2068453402a9f38` |
| TLSH | `T1B6B33A12B3290957D09749B11AEF1BF183B6ECD026F2B244952EBFA40733BB51485F9B` |
| TELFHASH | `t10f3110755b22a1166960dd64ddfe87b1a51983231784ff33df2688cc240904ee72bc4f` |
| SSDEEP | `1536:0Jr5/y+gximXiUZyZ+zltTUtTe4JThvdpl4BYOhiptsQCK8:q5/y+gfiURzltgtTeelm5hUS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_d6bac5a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6bac5a15715c7e1f917c1e9bda5631e852f0e61388efbbace90b5a00b653ad3"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-07 23:29:14"
  condition:
    hash.sha256(0, filesize) == "d6bac5a15715c7e1f917c1e9bda5631e852f0e61388efbbace90b5a00b653ad3"
}
```

### Sample 61: `df00f0dd7e94d5b0`

| Field | Value |
|---|---|
| SHA-256 | `df00f0dd7e94d5b0fa9bab04f681f313e8f7de19b8af9eca5e862290e1f7d519` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-07 23:25:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb22635465e9adb0c86ef00890e4fda` |
| SHA-1 | `41545d8e45e03d9461e79fbd00cf9e3c4621d34b` |
| SHA-256 | `df00f0dd7e94d5b0fa9bab04f681f313e8f7de19b8af9eca5e862290e1f7d519` |
| SHA3-384 | `b1fbb6da57a2790c6b02c8da2ecbe289cdb7ab1ac7bc6c226bced2c83749de7f47b4492b03d06eebdfa4db38e4ada888` |
| TLSH | `T1CB934CCAF401DDBDF84AE6770C534E197671F2E00A830B36575BBA7BE9721982427D81` |
| SSDEEP | `1536:efWpNSGZ1fGedJoahEaF282qbVxQeuacWjcW0JcWcBCWeeNQx5k4L9DY4/KNgqDf:O+puedjEvqpxQeuacWjcW0JcWcBJBNgK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_df00f0dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df00f0dd7e94d5b0fa9bab04f681f313e8f7de19b8af9eca5e862290e1f7d519"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-07 23:25:34"
  condition:
    hash.sha256(0, filesize) == "df00f0dd7e94d5b0fa9bab04f681f313e8f7de19b8af9eca5e862290e1f7d519"
}
```

### Sample 62: `871313d5587ad784`

| Field | Value |
|---|---|
| SHA-256 | `871313d5587ad78426255e619f598f90044cf15909b6b4fcdb1cdc6962f57e6b` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-07 23:25:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b79653ebd664b56e3cd7ad639294b4a3` |
| SHA-1 | `58025d9714b398bc9e302c1aa97e786945f01f21` |
| SHA-256 | `871313d5587ad78426255e619f598f90044cf15909b6b4fcdb1cdc6962f57e6b` |
| SHA3-384 | `b2ed84b1f36aec5265fb223ebbd29f0fa61e247adf32824f59e449a5856128cef9f0c4eabc5f874502e81ac6f66556ee` |
| TLSH | `T193241A46F8819F16C1C211BAFE5E514D37136FB8E2DE7112DD20AFA0378A4EB0A7B516` |
| TELFHASH | `t1eca0023d74d80231b6b186e58985012d51297649b777756217a0943e2d315d070e3835` |
| SSDEEP | `6144:6byAHUDxJRVfh9hXgYOaIpQps+EZ2UiW7:6byAHUFJR9zhXNOagd+EM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_871313d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "871313d5587ad78426255e619f598f90044cf15909b6b4fcdb1cdc6962f57e6b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 23:25:31"
  condition:
    hash.sha256(0, filesize) == "871313d5587ad78426255e619f598f90044cf15909b6b4fcdb1cdc6962f57e6b"
}
```

### Sample 63: `ceb3064b2db79487`

| Field | Value |
|---|---|
| SHA-256 | `ceb3064b2db7948711964dbfaba861aee73ef415a4454929528b3f26a8dda263` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-07 23:22:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b13a1771c4f0765eda42ccdc00b2a625` |
| SHA-1 | `2d8e96da2529e33d73fd0e0aab015d2811570a65` |
| SHA-256 | `ceb3064b2db7948711964dbfaba861aee73ef415a4454929528b3f26a8dda263` |
| SHA3-384 | `3be37de1645baaa8dfd52334d4469f63912853d4af6fd8aae92d496d2c85c0e212d741601ae8b978d1a089b8aab2e061` |
| TLSH | `T136732999F8418723C6D1167BFA6E028D372657ECE2EA721399215F6137C782B0D37E42` |
| TELFHASH | `t1b831bee6cb4909dca7e1c745838a237dbed939b4a7002765ce3d7b4f47465c1ba2a031` |
| SSDEEP | `1536:EihXAQi0/7qk08ws1iC+0vvKYJZwjMM+FFNqV5ebzQoukv/N:dhFi0/y/s13+0vvjzcMDFFNqbebzQo/N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_ceb3064b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceb3064b2db7948711964dbfaba861aee73ef415a4454929528b3f26a8dda263"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-07 23:22:17"
  condition:
    hash.sha256(0, filesize) == "ceb3064b2db7948711964dbfaba861aee73ef415a4454929528b3f26a8dda263"
}
```

### Sample 64: `1e76392a5f25bd97`

| Field | Value |
|---|---|
| SHA-256 | `1e76392a5f25bd9700b38d164be21c42946d3ef5a6bdc906093d9ebf9da6574b` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-10-07 23:22:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44e9daf90837e9f25c16a7b388ba967b` |
| SHA-1 | `7977c5891f04b5b5d5d4a6287fcbdf929dee9927` |
| SHA-256 | `1e76392a5f25bd9700b38d164be21c42946d3ef5a6bdc906093d9ebf9da6574b` |
| SHA3-384 | `853b4657f0dad789f3a8d8966148cb70ad73078e969ba15ba64b51a99edeacdfde4f756f99e44ab0fdca32daaf550afe` |
| TLSH | `T136E53A6BBE264E52C5C026BFB8BD818C73531378E2DA7516DE089E352ECF5CA4D32644` |
| TELFHASH | `t109211449283d0ef7a8b246509c241aa2c247c42e78514704ff20cbd10bfa048b527f4f` |
| SSDEEP | `49152:T33ZyYLQBihE5C4L2t25W+cxXUSwPz2I5zr9lINh6Un399/Jpl5n:T33oMQBihEFS5n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_1e76392a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e76392a5f25bd9700b38d164be21c42946d3ef5a6bdc906093d9ebf9da6574b"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-07 23:22:15"
  condition:
    hash.sha256(0, filesize) == "1e76392a5f25bd9700b38d164be21c42946d3ef5a6bdc906093d9ebf9da6574b"
}
```

### Sample 65: `e3923ff4e583f286`

| Field | Value |
|---|---|
| SHA-256 | `e3923ff4e583f2860938954ae43f3abbd7b1f09b59528b1b53dafd1ad768cec8` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-10-07 23:18:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4940dbe39bdee217579c5e4247d3528f` |
| SHA-1 | `ee3cc25ae73d2e2bb91b668508500497e875121c` |
| SHA-256 | `e3923ff4e583f2860938954ae43f3abbd7b1f09b59528b1b53dafd1ad768cec8` |
| SHA3-384 | `ba2f294ca07a69f167deab5e16b7bbd26e13e715b8a59a2790ccfdaa11798c9b4c74bc0bb43eb64b6f6f1dbf9359f3e5` |
| TLSH | `T12DC55B02E910A568D63230F1214FA23498650532736389E7FF99AC7C663F6D35B7A63F` |
| TELFHASH | `t18423e926a79019fca7c687d4c6f27438dbf635e493421ca5822a7f77de02f82851e817` |
| SSDEEP | `49152:L18Yujv/if1v5zjguNmIOY2hEeklFKtjM18JMPvdAV8hawM6Hh+sSpn+:Z8Y6v/if1h/guNmLEeKce1Zc8Qb6Hh1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_e3923ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3923ff4e583f2860938954ae43f3abbd7b1f09b59528b1b53dafd1ad768cec8"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-07 23:18:39"
  condition:
    hash.sha256(0, filesize) == "e3923ff4e583f2860938954ae43f3abbd7b1f09b59528b1b53dafd1ad768cec8"
}
```

### Sample 66: `d542b8cd29eb7341`

| Field | Value |
|---|---|
| SHA-256 | `d542b8cd29eb734177669aa9251690b47c0537c7ebbd8167311615e2836b584e` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-07 23:15:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0d256884edc28e9e5fd6b7ce2a10b9` |
| SHA-1 | `48ef8caa7cde886bec3d809c0dd0513282767f31` |
| SHA-256 | `d542b8cd29eb734177669aa9251690b47c0537c7ebbd8167311615e2836b584e` |
| SHA3-384 | `070b47290dc5f421894ecf66a461ae3388ea68bf88e561bb86540f9fe482bb7e5ad6a00e6b599554d8078b082482a43e` |
| TLSH | `T1EC932A96B9929A1EC6D053BFFA5E578C332573F8C3DE3123D9108A51378B52F0636A90` |
| TELFHASH | `t180f0e100fd7a8e1948f29670dcbc07a0d403522360b21720ef56cad08c3e458f308d0d` |
| SSDEEP | `1536:M+3983c+GkkCsHeYpFSZs+dc3pqaCWE1lJwBcm6veNCr2mWf1OIydSIjEvD:M7cpkYpFSZs+MIl+K7veie1a7j4D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_d542b8cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d542b8cd29eb734177669aa9251690b47c0537c7ebbd8167311615e2836b584e"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-07 23:15:24"
  condition:
    hash.sha256(0, filesize) == "d542b8cd29eb734177669aa9251690b47c0537c7ebbd8167311615e2836b584e"
}
```

### Sample 67: `dbe8e30860c8fc4f`

| Field | Value |
|---|---|
| SHA-256 | `dbe8e30860c8fc4f1470138113f3ea1983129319938b3bb98f3616df0ac23f01` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-10-07 23:12:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de31509881c8104305b7517fd66c40a1` |
| SHA-1 | `0b8af5ac9188c8847596a3f23cd9f46f1ca62342` |
| SHA-256 | `dbe8e30860c8fc4f1470138113f3ea1983129319938b3bb98f3616df0ac23f01` |
| SHA3-384 | `bec4ef45c75787ff0bfe462bf711d70d9a359070d8301a6b2f4d7dd842be0b3abac526c750b34437e97ec8aa08051e1e` |
| TLSH | `T155D32A07BFA10FFBD85BCE3702EB0B21158DD95A23926B367138DD68B64728A16D3D50` |
| TELFHASH | `t1f4311e755b22a1166960dd68ddfe87b1a51a83131784ff33ef2688cc240a04ee72bc4f` |
| SSDEEP | `1536:XJQT5SdsKBSsooJZboeGhrF7wJ04lYPhvyKg86KuZmn+jre8PL1:XJQlusKBfoo3Ee0rWsPsKtXimnUrx1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_dbe8e308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbe8e30860c8fc4f1470138113f3ea1983129319938b3bb98f3616df0ac23f01"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-07 23:12:14"
  condition:
    hash.sha256(0, filesize) == "dbe8e30860c8fc4f1470138113f3ea1983129319938b3bb98f3616df0ac23f01"
}
```

### Sample 68: `ad4e18765c30d633`

| Field | Value |
|---|---|
| SHA-256 | `ad4e18765c30d633729411f72d3343a6e4cb1243eca3658025119eb2885820f0` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-07 23:12:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f74b026f26436f7590d1ceac3f2b93a` |
| SHA-1 | `03ee4b36095e378cde56ff67b21a39ad026e6623` |
| SHA-256 | `ad4e18765c30d633729411f72d3343a6e4cb1243eca3658025119eb2885820f0` |
| SHA3-384 | `42450f7d8d5908310c81f426b7413424ff5b3bd010e51cf3ae19c2cdbeb2fa03f7fd0016cdf76a08d921894e9856a3ef` |
| TLSH | `T10E143BC3F900DEBEF80BE3B6449309157430FB6618635A72B153BDBAA93A0D51527F86` |
| SSDEEP | `3072:8UPuWkPo09pjYAyKmCNRevap3gM0lWesAAmDOZnVTjbiLL/W1Py700jLc:BPeQ09i/E3gMOWjeOZCL/ey7Xc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_ad4e1876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad4e18765c30d633729411f72d3343a6e4cb1243eca3658025119eb2885820f0"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-07 23:12:12"
  condition:
    hash.sha256(0, filesize) == "ad4e18765c30d633729411f72d3343a6e4cb1243eca3658025119eb2885820f0"
}
```

### Sample 69: `79374890314b4d74`

| Field | Value |
|---|---|
| SHA-256 | `79374890314b4d74a2093200bd952229c2b4eba010b083f32e4097dd1487bf00` |
| Family label | `unknown` |
| File name | `run.sh` |
| File type | `sh` |
| First seen | `2026-10-07 23:12:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `344d897bee71ce10fafa8fc5d8ab4f5e` |
| SHA-1 | `09d9147f9e9f937abb2e383bac280a9a71434884` |
| SHA-256 | `79374890314b4d74a2093200bd952229c2b4eba010b083f32e4097dd1487bf00` |
| SHA3-384 | `52d309371a52febc607d5f5c9c3c19f050a287698346fe72fd9f10c9232ffb9799825d5c3746c62c8deb8dfb71ef0924` |
| TLSH | `T19CA1938A2078973DA46FDD6C3DE58A40588947E236F13F395EB009536C899B0B3C9F5E` |
| SSDEEP | `96:rlJ8fvBizLxn6CAd3voNP2jlyi6pnP4yQvdAKSvBgL6T2/NiVXNIdFJ4dxAf7cR1:rlJ8fvBizLxn6CAd3voNP2jlyi6pnP4w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_79374890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79374890314b4d74a2093200bd952229c2b4eba010b083f32e4097dd1487bf00"
    family = "unknown"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-10-07 23:12:10"
  condition:
    hash.sha256(0, filesize) == "79374890314b4d74a2093200bd952229c2b4eba010b083f32e4097dd1487bf00"
}
```

### Sample 70: `133401d9a9f9c803`

| Field | Value |
|---|---|
| SHA-256 | `133401d9a9f9c8036f0fa21d2fc221089e24830eb772f2761d7b4e8de691e94f` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-07 23:08:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96abd4f176fd955db0e6d7d3d164b699` |
| SHA-1 | `a55a1d63a2c64e3dc0054565f9e2eb29e7db9454` |
| SHA-256 | `133401d9a9f9c8036f0fa21d2fc221089e24830eb772f2761d7b4e8de691e94f` |
| SHA3-384 | `5567a84a0d6fb1d1f13b6ea23cbdfb66c5c7cf1dd05db5050d12c3a2c468ce0859559d155a20071e122262347810bac2` |
| TLSH | `T1B6664A537A38E70EE228213048B1CAC56B6D1C5641E6991BA391F71DF8F31AC4E6EDF1` |
| TELFHASH | `t16db0921788a00a48a0a248c15ec4715140e2ec23282965aebf750d934e0e806006d006` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:qsk4UV5cuIgSox20zXJP956Sbo5UOF7s1gHpzIbv5hQCh09fOIhrYGOdE1HH4t55:605UF5h0WC1n4jEa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_133401d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "133401d9a9f9c8036f0fa21d2fc221089e24830eb772f2761d7b4e8de691e94f"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-07 23:08:32"
  condition:
    hash.sha256(0, filesize) == "133401d9a9f9c8036f0fa21d2fc221089e24830eb772f2761d7b4e8de691e94f"
}
```

### Sample 71: `124cae6f4b5b82d3`

| Field | Value |
|---|---|
| SHA-256 | `124cae6f4b5b82d325519441c3f1ac7510ef9873944e200f512b67d7b749ecbd` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-10-07 23:06:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dd27e5c6c9bcdbe4d61d37ea03f902e` |
| SHA-1 | `95f890709d1f7bc7a3a3448679e4d20f44d2e753` |
| SHA-256 | `124cae6f4b5b82d325519441c3f1ac7510ef9873944e200f512b67d7b749ecbd` |
| SHA3-384 | `4cdd863efc538249812cf8e58aca6df60a545c390429e763961b2250a59870855ce88bd60291b6c8af6d2f3f7c5e4ffb` |
| TLSH | `T1C3431891B8819A23C5D4137AF56E56CD372023E8E2CF72179E214F613AC682F0C6AE95` |
| TELFHASH | `t19f3177758b981ecc27f8c385468a1269bee430f857109a7dde3f775b42534c1325e923` |
| SSDEEP | `768:raehM993TLSmRTIrL8Fvvhp9H0HrZQ8yoWXagcLVPWtuQ/C71mA2EDEy0eYjW9TF:/M99jmL8BZp9IFUoWKdYuvQ5KIqkypZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_124cae6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "124cae6f4b5b82d325519441c3f1ac7510ef9873944e200f512b67d7b749ecbd"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-10-07 23:06:28"
  condition:
    hash.sha256(0, filesize) == "124cae6f4b5b82d325519441c3f1ac7510ef9873944e200f512b67d7b749ecbd"
}
```

### Sample 72: `8c1fbd2ce69d88d5`

| Field | Value |
|---|---|
| SHA-256 | `8c1fbd2ce69d88d5ac8b577538d0a0b5a715f9f332a082e95e6cf1d0d69dbb95` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-10-07 23:05:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1bb0c1317240987b03a5e73e16ce086` |
| SHA-1 | `5a1a6e29b992353f82781bc78dc7fd8ef2810a18` |
| SHA-256 | `8c1fbd2ce69d88d5ac8b577538d0a0b5a715f9f332a082e95e6cf1d0d69dbb95` |
| SHA3-384 | `4fe176dcb61507ffa729249f818a2e4922f9419155ac1de24ef1f3ceac5f34428cff8f2a3032d78c368ca9b20845003b` |
| TLSH | `T193A2E01472633D56F3ED2C3DC8AA8357FD671BFC80F632766D011620C94D60A2E39A4A` |
| SSDEEP | `384:TvtIoZxrSniaXs+qx+bwqPX+VOcFd5fHq52lxjNFwhymdGUop5hS:TvQn4j+ZO5fKAlxZFws3Uozs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_8c1fbd2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c1fbd2ce69d88d5ac8b577538d0a0b5a715f9f332a082e95e6cf1d0d69dbb95"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-10-07 23:05:30"
  condition:
    hash.sha256(0, filesize) == "8c1fbd2ce69d88d5ac8b577538d0a0b5a715f9f332a082e95e6cf1d0d69dbb95"
}
```

### Sample 73: `bb85d7ed379fee30`

| Field | Value |
|---|---|
| SHA-256 | `bb85d7ed379fee306fa43fb0724720e5584bbcc6792780889408daf6f4024604` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-10-07 23:05:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aeae30dfda9cb4528f16c1d87439ded` |
| SHA-1 | `d6e8216ff3cfc7cd93d12df4d977375f4c8bd67b` |
| SHA-256 | `bb85d7ed379fee306fa43fb0724720e5584bbcc6792780889408daf6f4024604` |
| SHA3-384 | `e30746ec8035cf6155efa21136d51e0f34b784dfd561bdcc49b567b324e374cb3251ce4fd093112d4fd8ce292d6c6504` |
| TLSH | `T129A34B13D5614AA3C0835FB925F78E790B13A8A24B121F71562DCFF80A43DCDBC59BA6` |
| TELFHASH | `t178310c755b22a1166960dda4d9fe87b1a51a83131784ff33ef2688cc640a04ee72bc4f` |
| SSDEEP | `1536:BqRGA08V2PpDet4oTOvp8G+RkQnu5E4kA9lcCzIdC:BqRuFetnKRJsYEEEC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_bb85d7ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb85d7ed379fee306fa43fb0724720e5584bbcc6792780889408daf6f4024604"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-07 23:05:27"
  condition:
    hash.sha256(0, filesize) == "bb85d7ed379fee306fa43fb0724720e5584bbcc6792780889408daf6f4024604"
}
```

### Sample 74: `465356f33b322c3f`

| Field | Value |
|---|---|
| SHA-256 | `465356f33b322c3f0aa694c8db805ee97ae1f278191e215468f9c10ec5a60ae1` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-07 23:05:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45317ff0ebfb7c0f376b2676c81c57b4` |
| SHA-1 | `d6337373bde4a927aef6a7c58f667d0f39a87c43` |
| SHA-256 | `465356f33b322c3f0aa694c8db805ee97ae1f278191e215468f9c10ec5a60ae1` |
| SHA3-384 | `569890d708a31d64e7f2b8af7a85065d99e9e62a8b03f43fb1903da2addea712f76cad2bf6b542eac95c2dafc1a6717b` |
| TLSH | `T1B1A52AAFB8429E42C4D465FAF57D81D8334753B8C2EAB116EA11CB3539DF84A0E39B44` |
| TELFHASH | `t1e9a002e86b544c786bec3830c603597a609c22507660d0e952f5b7ede65dc95618b570` |
| SSDEEP | `24576:b7oIFzF34t5yhOg2RuJvmxRXUaS+zmnjjItkfmOqb1QeT9J64ve3oJ:bTQ6hsS+zmjjUkfmOM1QqIoJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_465356f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "465356f33b322c3f0aa694c8db805ee97ae1f278191e215468f9c10ec5a60ae1"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-07 23:05:25"
  condition:
    hash.sha256(0, filesize) == "465356f33b322c3f0aa694c8db805ee97ae1f278191e215468f9c10ec5a60ae1"
}
```

### Sample 75: `f55e5c839aa59fa2`

| Field | Value |
|---|---|
| SHA-256 | `f55e5c839aa59fa24da5417d6771690af1fc6402259b44de0b678c4c468cda07` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-10-07 22:59:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1683c6e67f6b9ccb4a7a845d7052a455` |
| SHA-1 | `2db1ad8a61b7cf6d7e8c0a09d7f1b44fc7ec6823` |
| SHA-256 | `f55e5c839aa59fa24da5417d6771690af1fc6402259b44de0b678c4c468cda07` |
| SHA3-384 | `520820915912de3d857e25f8ba89165988fe6fb351252165e0b7b70f0f5ca02bf28a112d08ce94def41c1ca211ee05b8` |
| TLSH | `T14E140A45F9419F17C6C322FBFB9E428C37256BACD6EE7102DD20AF61378A49B0936251` |
| TELFHASH | `t1bfa00275958d15b6355a91a2037bc61444f561e747481bf09709a1831dc53e9705292f` |
| SSDEEP | `3072:m3TvB3ykPjfJlAUU9ALWeTMADthX4G4f1DXGTXYyd31aAlC:c3zAITnJhX4Gu1DXG8K3XlC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_f55e5c83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f55e5c839aa59fa24da5417d6771690af1fc6402259b44de0b678c4c468cda07"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-10-07 22:59:16"
  condition:
    hash.sha256(0, filesize) == "f55e5c839aa59fa24da5417d6771690af1fc6402259b44de0b678c4c468cda07"
}
```

### Sample 76: `5015ec59389553a6`

| Field | Value |
|---|---|
| SHA-256 | `5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183` |
| Family label | `unknown` |
| File name | `5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183` |
| File type | `elf` |
| First seen | `2026-10-07 22:41:32` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5344555424c45d2a7ea565ba9cf8af3d` |
| SHA-1 | `7b5686a5b1fda6a3a24f6ad2cf3fb659e313969a` |
| SHA-256 | `5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183` |
| SHA3-384 | `e15c5ab31d83c47e5bc28019d1b2c99e275d48d9bcb7d9940df7956117f436f71131afcaa29a482f73ebd5ef552dd518` |
| TLSH | `T1CDF3129780938BF7F54676B3DD0CCDDF24103A91AA4CFE926D6B3297230AC96484B64D` |
| SSDEEP | `3072:n43QAiVsDn5P+h2D8j18H2iFgp1YhNpdiXpQuQi47IPkVb25Xy:4gMD5E2D8j1k28GmNTYC52kVb2dy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_5015ec59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183"
    family = "unknown"
    file_name = "5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183"
    file_type = "elf"
    first_seen = "2026-10-07 22:41:32"
  condition:
    hash.sha256(0, filesize) == "5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183"
}
```

### Sample 77: `7f20d4142b4b4d7b`

| Field | Value |
|---|---|
| SHA-256 | `7f20d4142b4b4d7b1664fe1c30def83ee5bac0eadbb24abf2b83136dabcee321` |
| Family label | `unknown` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-07 22:08:40` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c32f73c6db6f317772871f0e0704a4c` |
| SHA-1 | `2a6f9a09d7ca02c7318a83aceb86425d655077f3` |
| SHA-256 | `7f20d4142b4b4d7b1664fe1c30def83ee5bac0eadbb24abf2b83136dabcee321` |
| SHA3-384 | `e7e24fb4b8aad0a18002e6712e5622dc4eaea3844a83935e61d4e88f47898f86a3b9b3a7d0defa7d074b2feb4158b0e9` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1AE86E817618410ECCA4BC27648F45D7E17F23DAE5133B78A0A95BEA12F13BD66F60E48` |
| SSDEEP | `24576:QDOdKJtUBBjHqrv1IC1voTuGLS1HxpIWkxoXaCDQB2XRaHjOfusCPWdnc4H8WHoL:4JiBB7qxICbxF4B2X8HjOzCcZfx+SjW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_7f20d414
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f20d4142b4b4d7b1664fe1c30def83ee5bac0eadbb24abf2b83136dabcee321"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-07 22:08:40"
  condition:
    hash.sha256(0, filesize) == "7f20d4142b4b4d7b1664fe1c30def83ee5bac0eadbb24abf2b83136dabcee321"
}
```

### Sample 78: `2c9cee1590813b82`

| Field | Value |
|---|---|
| SHA-256 | `2c9cee1590813b8223d232761c8689ef0623a7d5ae442b3f0c89c76abc10755a` |
| Family label | `VShell` |
| File name | `18159a377f89efd15c0a9d436027ed35.exe` |
| File type | `exe` |
| First seen | `2026-10-07 21:55:13` |
| Reporter | `abuse_ch` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18159a377f89efd15c0a9d436027ed35` |
| SHA-1 | `bc48b6664e8a2ddaae9a8e35b3458298d14c72d5` |
| SHA-256 | `2c9cee1590813b8223d232761c8689ef0623a7d5ae442b3f0c89c76abc10755a` |
| SHA3-384 | `768df61bbddf5210f1bb4f0b0f24751c287f778ab3cb490e58ed7d44acbc62f132b7c4b4a7b505b8b24fb336af2a3683` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T103716188F3136EF5E42C46F800D3A664D0199BB8C250BF4D5E60381D3C220BA265AF97` |
| SSDEEP | `48:6Icwm0zAt2WecJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jWAtzSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_078_2c9cee15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c9cee1590813b8223d232761c8689ef0623a7d5ae442b3f0c89c76abc10755a"
    family = "VShell"
    file_name = "18159a377f89efd15c0a9d436027ed35.exe"
    file_type = "exe"
    first_seen = "2026-10-07 21:55:13"
  condition:
    hash.sha256(0, filesize) == "2c9cee1590813b8223d232761c8689ef0623a7d5ae442b3f0c89c76abc10755a"
}
```

### Sample 79: `27e1594334eabcf7`

| Field | Value |
|---|---|
| SHA-256 | `27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b` |
| Family label | `unknown` |
| File name | `rvtools4.8.1.msi` |
| File type | `msi` |
| First seen | `2026-10-07 21:53:12` |
| Reporter | `SquiblydooBlog` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3bb2c8db10dba1b77e733f6c123f837` |
| SHA-1 | `02a65f5e980c5a67128795c3ab08499c82432511` |
| SHA-256 | `27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b` |
| SHA3-384 | `168fff843df035d1174507b81a7e9e89c1409aac6ac5a8bd31820930236531e3102c8653c1cfd2db4d402fe9a500230f` |
| TLSH | `T1FEB633F724A15E2BF4E1B07F08F7841F42713F826406645ED239BE466AF6A81A4FD1C9` |
| SSDEEP | `196608:fJ0J36ikBL3FccXm2Hnzesf/2HB7wM+2EQREIFkLKmFkSAoKPIC6:fVljnzesf/Q7wQT2KmFkpBe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_27e15943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b"
    family = "unknown"
    file_name = "rvtools4.8.1.msi"
    file_type = "msi"
    first_seen = "2026-10-07 21:53:12"
  condition:
    hash.sha256(0, filesize) == "27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b"
}
```

### Sample 80: `c85aa1fdc991830b`

| Field | Value |
|---|---|
| SHA-256 | `c85aa1fdc991830badc9cade5a7737d056a5e6198c7ee5b566650893d21cc3b3` |
| Family label | `unknown` |
| File name | `ССLосitуХ64-v.6.978.exe` |
| File type | `exe` |
| First seen | `2026-10-07 21:51:36` |
| Reporter | `NyxIndius` |
| Tags | `172-233-152-197, DDR, exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00f6d4dd503ea7c402bdec2a96273634` |
| SHA-1 | `a4a998a07830e6362ed34880bd0dd7962ef53a70` |
| SHA-256 | `c85aa1fdc991830badc9cade5a7737d056a5e6198c7ee5b566650893d21cc3b3` |
| SHA3-384 | `1b780b73bbe39c413e245dfc6b7956e81f780f1ccda6d00fa5207e800b93afd4d86d01a1faeb5d20a7e7ec3b5ff1dbc9` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1C886E817618410ECCA8BC27644F45D7E17F23DAE5133B78A0A95BEA12F13BD66F60E48` |
| SSDEEP | `49152:BH5FpcAIAv081d6Ur+swAkI3diiGTgiXcZEgSy:jUA1vJTvUjs5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_c85aa1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c85aa1fdc991830badc9cade5a7737d056a5e6198c7ee5b566650893d21cc3b3"
    family = "unknown"
    file_name = "ССLосitуХ64-v.6.978.exe"
    file_type = "exe"
    first_seen = "2026-10-07 21:51:36"
  condition:
    hash.sha256(0, filesize) == "c85aa1fdc991830badc9cade5a7737d056a5e6198c7ee5b566650893d21cc3b3"
}
```

### Sample 81: `7050da3bd5b59468`

| Field | Value |
|---|---|
| SHA-256 | `7050da3bd5b59468f4ab8457cf5f11b1cd5f556e54e2e0b1d5b1556088b949d8` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-07 21:34:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4393bf2ae69dd24ac1ecd40ad5d60df2` |
| SHA-1 | `b4253449be1a28c2f259d393fb94e4f5c3bba028` |
| SHA-256 | `7050da3bd5b59468f4ab8457cf5f11b1cd5f556e54e2e0b1d5b1556088b949d8` |
| SHA3-384 | `17e8c86c0f425d7359e860c5085fd4dd4292cb93469d03630ab5c7e0c600d8c01ea3dd50fb5ed475dc61d447fd98a7bf` |
| TLSH | `T1F9732A13B54280FCC58AC1340B5ABA3EDD37B4FC2268F6A63BD0FA225D96D215D1ED45` |
| TELFHASH | `t1b62102b1353619a0a1fbf5a5a344e51019610a7120d638f2e4b278fadf65bc20e76c77` |
| SSDEEP | `1536:LEe85xmrO8q4tzVBVQi6dap3ux9VvGWkV4PTQx6IDQ/HwjJg:f85xmrtq4hVB+SuxTG/4Pkx6t/QjJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_7050da3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7050da3bd5b59468f4ab8457cf5f11b1cd5f556e54e2e0b1d5b1556088b949d8"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-07 21:34:27"
  condition:
    hash.sha256(0, filesize) == "7050da3bd5b59468f4ab8457cf5f11b1cd5f556e54e2e0b1d5b1556088b949d8"
}
```

### Sample 82: `c2e709c9d1de36e3`

| Field | Value |
|---|---|
| SHA-256 | `c2e709c9d1de36e3a228e71d6ae7920c9f2e84fa73691508f8b73ea35855d6f7` |
| Family label | `unknown` |
| File name | `stage2.zip` |
| File type | `zip` |
| First seen | `2026-10-07 21:19:16` |
| Reporter | `johnk3r` |
| Tags | `au3, banker, contabilidadeacportela-net, controedatoerpestanavidroslat.com, hggdconfeccoesgruponacional-click, saladeouroriopreto-shop, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3c43e72abeb73a08980812e149e2494` |
| SHA-1 | `5fb5cd27a8c121b2f22f9087c3b4196000359e98` |
| SHA-256 | `c2e709c9d1de36e3a228e71d6ae7920c9f2e84fa73691508f8b73ea35855d6f7` |
| SHA3-384 | `05afeea53b26d086f42c3489a91c1ed8ae1d4a44e530910c8e764f02bfcf68d914a1f5d1bf86149073489c09feca2f99` |
| TLSH | `T1A232B07FF2BF8F79C39F8E34C1CF1930E6ED588A51A256C5184520740EA1E920DD7499` |
| SSDEEP | `192:oomS6FLFef9s6VwKxGiMLh4JOuvuwQUgR4BHOGx+rykgcSpoPoVa/UCgynfH:BmosyYigh4JZvDQUgeuGgrykgcSpoPcA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_c2e709c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2e709c9d1de36e3a228e71d6ae7920c9f2e84fa73691508f8b73ea35855d6f7"
    family = "unknown"
    file_name = "stage2.zip"
    file_type = "zip"
    first_seen = "2026-10-07 21:19:16"
  condition:
    hash.sha256(0, filesize) == "c2e709c9d1de36e3a228e71d6ae7920c9f2e84fa73691508f8b73ea35855d6f7"
}
```

### Sample 83: `18d1351e3d1956e6`

| Field | Value |
|---|---|
| SHA-256 | `18d1351e3d1956e63fdd3ee80f709e0320f7d1329ccea64ab8731c110343feec` |
| Family label | `unknown` |
| File name | `stage2.au3` |
| File type | `au3` |
| First seen | `2026-10-07 21:18:32` |
| Reporter | `johnk3r` |
| Tags | `au3, banker, contabilidadeacportela-net, controedatoerpestanavidroslat.com, hggdconfeccoesgruponacional-click, saladeouroriopreto-shop` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2557dc2cca82fe4513fa253181434c07` |
| SHA-1 | `0d05dd385eb86f46fc8fdd050888fabd821f8ed9` |
| SHA-256 | `18d1351e3d1956e63fdd3ee80f709e0320f7d1329ccea64ab8731c110343feec` |
| SHA3-384 | `7db13ea768113bd0228825d0e8cf6f42561a55f12071df69a8f98241cf5779e89a75f19dfe4ef31609ca2a90147f22ed` |
| TLSH | `T19823809E7C0BA25035FF4318AE67C59B78505E1F922E4402BAADD3E42F5C7BCD196322` |
| SSDEEP | `768:izg5ahVuen30e/0P3knZJ/bryFcCyMNpj:hahVSUuj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `au3`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_18d1351e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18d1351e3d1956e63fdd3ee80f709e0320f7d1329ccea64ab8731c110343feec"
    family = "unknown"
    file_name = "stage2.au3"
    file_type = "au3"
    first_seen = "2026-10-07 21:18:32"
  condition:
    hash.sha256(0, filesize) == "18d1351e3d1956e63fdd3ee80f709e0320f7d1329ccea64ab8731c110343feec"
}
```

### Sample 84: `8b0b07aa426d0a1a`

| Field | Value |
|---|---|
| SHA-256 | `8b0b07aa426d0a1a2ce43412cd65d3541cda9ca38d2d8ba2ee6be09033f717da` |
| Family label | `Mirai` |
| File name | `payload-mips` |
| File type | `elf` |
| First seen | `2026-10-07 21:09:08` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af0efd05e35fc158cd00104edb6a0bc1` |
| SHA-1 | `d99acda821c765a13005664ed0d74bcfa5680145` |
| SHA-256 | `8b0b07aa426d0a1a2ce43412cd65d3541cda9ca38d2d8ba2ee6be09033f717da` |
| SHA3-384 | `8df3785dcc29eafbe9cf6f1b5398964a6f258b0c25fdcad5d44dce7898b2f9b7e7a2e22d191706199eb55d1eeaedef4d` |
| TLSH | `T15E056C223B52DF65D354D63009F3C6619AF521A21FE2408962BCC3287E61B2D6D5FEF8` |
| SSDEEP | `24576:Bd4oyuXKit/Ui4RWfws86IXe+H5nIzWiEAq7:Bd4opsipfwsDIXWvw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_8b0b07aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0b07aa426d0a1a2ce43412cd65d3541cda9ca38d2d8ba2ee6be09033f717da"
    family = "Mirai"
    file_name = "payload-mips"
    file_type = "elf"
    first_seen = "2026-10-07 21:09:08"
  condition:
    hash.sha256(0, filesize) == "8b0b07aa426d0a1a2ce43412cd65d3541cda9ca38d2d8ba2ee6be09033f717da"
}
```

### Sample 85: `2782f0971bbab496`

| Field | Value |
|---|---|
| SHA-256 | `2782f0971bbab49699fb228e8c68b71b116f508b14ec5eb2e5774653e152c2ba` |
| Family label | `Mirai` |
| File name | `payload-mipsel` |
| File type | `elf` |
| First seen | `2026-10-07 21:08:49` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3baeb9e19bbec54c7edb1cfa61d6a825` |
| SHA-1 | `042d39c7ff00026910d27d6e84c899f24a9cf32a` |
| SHA-256 | `2782f0971bbab49699fb228e8c68b71b116f508b14ec5eb2e5774653e152c2ba` |
| SHA3-384 | `beac1bd614bdc9a051bd0401df1af9c8dd3764620d92762f322637efa93c5205c07ab4a9da57b66e3b24efae70f53f69` |
| TLSH | `T1D6054C06FF405FEBC0AECD31492EC30615EDE8D69AC1662E71F84B8C7A9D74A4AD7448` |
| SSDEEP | `24576:KrqpGPzm5jWSRuT78esbCaOSAHoQK+6ZEAq:W6prg8lumQ8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_2782f097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2782f0971bbab49699fb228e8c68b71b116f508b14ec5eb2e5774653e152c2ba"
    family = "Mirai"
    file_name = "payload-mipsel"
    file_type = "elf"
    first_seen = "2026-10-07 21:08:49"
  condition:
    hash.sha256(0, filesize) == "2782f0971bbab49699fb228e8c68b71b116f508b14ec5eb2e5774653e152c2ba"
}
```

### Sample 86: `d082bed899d8f975`

| Field | Value |
|---|---|
| SHA-256 | `d082bed899d8f975f201975f3c0517debd094cf40630649283de097b0361b8fc` |
| Family label | `unknown` |
| File name | `solicitado52` |
| File type | `msi` |
| First seen | `2026-10-07 21:03:53` |
| Reporter | `johnk3r` |
| Tags | `astaroth, banker, contabilidadeacportela-net, controedatoerpestanavidroslat-com, guildma, hggdconfeccoesgruponacional-click, msi, saladeouroriopreto-shop, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9766a65884177f26090aeca0a6247865` |
| SHA-1 | `3bf922314f250b156b7a1fdf2e5a025e59160982` |
| SHA-256 | `d082bed899d8f975f201975f3c0517debd094cf40630649283de097b0361b8fc` |
| SHA3-384 | `d23c6c493c64691e67d8807b4cb990db01b098a5cf60f6625b434412bee42aca64c9578767e1847700216a1aee6ac325` |
| TLSH | `T17FC73326A19A8F7DDBC8A63CAC8A504C984B2F05CC141A15E19FFE788673143B1B7E95` |
| SSDEEP | `786432:NzMvQBrCCdpr2FziVoJaHsN0tz4G6dDbmWWQAzYpVmcRzySr196bHVa7/VVYka/5:KueLFzEoJyc0mDb7M8pkcRMbk7/VVSG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_d082bed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d082bed899d8f975f201975f3c0517debd094cf40630649283de097b0361b8fc"
    family = "unknown"
    file_name = "solicitado52"
    file_type = "msi"
    first_seen = "2026-10-07 21:03:53"
  condition:
    hash.sha256(0, filesize) == "d082bed899d8f975f201975f3c0517debd094cf40630649283de097b0361b8fc"
}
```

### Sample 87: `143bf4866461a98e`

| Field | Value |
|---|---|
| SHA-256 | `143bf4866461a98e05b0b0ea3d68dcbf070bf98f65e8627890d070591bb4b41f` |
| Family label | `unknown` |
| File name | `solicitado52.zip` |
| File type | `zip` |
| First seen | `2026-10-07 21:03:18` |
| Reporter | `johnk3r` |
| Tags | `astaroth, banker, contabilidadeacportela-net, controedatoerpestanavidroslat-com, guildma, hggdconfeccoesgruponacional-click, saladeouroriopreto-shop, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6035add513a58ba3cef324d0ebfb403` |
| SHA-1 | `9397fe0ce9dcd93bb970cbaad0eeaf63d5fb300b` |
| SHA-256 | `143bf4866461a98e05b0b0ea3d68dcbf070bf98f65e8627890d070591bb4b41f` |
| SHA3-384 | `e4a49804c6978fb5c31a4ee8aa4673ae2c5713d34ff29ef248d234fe80517fcdc9b26408b9071dc5138a8f45ad3c0981` |
| TLSH | `T142C7337662AB9ABC2FC837197C5B904CA88F6349CC541B05F0DE9E2C4B12587B177EE4` |
| SSDEEP | `1572864:jQTQ9IaQzqN6exP3/PJSqP1nGf1TxL/4p:kc9szEx3BSqPUf1TxL4p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_143bf486
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "143bf4866461a98e05b0b0ea3d68dcbf070bf98f65e8627890d070591bb4b41f"
    family = "unknown"
    file_name = "solicitado52.zip"
    file_type = "zip"
    first_seen = "2026-10-07 21:03:18"
  condition:
    hash.sha256(0, filesize) == "143bf4866461a98e05b0b0ea3d68dcbf070bf98f65e8627890d070591bb4b41f"
}
```

### Sample 88: `39060de52929785f`

| Field | Value |
|---|---|
| SHA-256 | `39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561` |
| Family label | `unknown` |
| File name | `mbupload-ul2x5ji5.bin` |
| File type | `sh` |
| First seen | `2026-10-07 20:55:44` |
| Reporter | `wristhulk` |
| Tags | `cowrie, downloader, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9ce091a6876e438f2a2e7e7e8b6d6f7` |
| SHA-1 | `eb680fb2cd2332ab1dc66a346c22e923ed500a07` |
| SHA-256 | `39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561` |
| SHA3-384 | `706efdacc356a74dd51bd352c16822adc132ac2c2d6920398382492cbc98a69e279fd274e21e79fcc15aa0a604645749` |
| TLSH | `T134317CE7FC2145B2759A903CAEEF608076875B2709683C1A744EB8593F38468B195717` |
| SSDEEP | `48:gCuYAEkgUz9Qkj6cqf9EsHsZDXkED/BzJEcv5:nCFq8JkWlV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_39060de5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561"
    family = "unknown"
    file_name = "mbupload-ul2x5ji5.bin"
    file_type = "sh"
    first_seen = "2026-10-07 20:55:44"
  condition:
    hash.sha256(0, filesize) == "39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561"
}
```

### Sample 89: `694379dcffba0c6a`

| Field | Value |
|---|---|
| SHA-256 | `694379dcffba0c6af665361a3accf113f8c879fffacd5532301f550e0bfd9600` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-07 20:54:58` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46e89b5d5733bc5ff903e014c3c4d728` |
| SHA-1 | `c11a9686deb2274a36596abae55da3caa9b998aa` |
| SHA-256 | `694379dcffba0c6af665361a3accf113f8c879fffacd5532301f550e0bfd9600` |
| SHA3-384 | `4ba06d1ea1c111e918b670a1338eb233560c974e57cda18b7842f0afaee4fe5c04501b6dbbc9554b28c60dc6379f12e4` |
| IMPHASH | `029a7149d02bfe860bbe3e5533ccab81` |
| TLSH | `T1C0D4AF58B69402F9E137C274CE578613F7B278491374A9EB03E099A72F236E09B3E751` |
| SSDEEP | `6144:g7wijBW/IbMAmU+xqYWFw/2IWLA1q1mhkySWi5BfCCXXZWAfgVCDFN7EaVytWdR4:SSAmUSqYWFweTmOySWu1ZrI0FNEOEPZ` |
| ICON-DHASH | `55dcb6e2a2966868` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_694379dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "694379dcffba0c6af665361a3accf113f8c879fffacd5532301f550e0bfd9600"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 20:54:58"
  condition:
    hash.sha256(0, filesize) == "694379dcffba0c6af665361a3accf113f8c879fffacd5532301f550e0bfd9600"
}
```

### Sample 90: `25f7148ab7b1fcff`

| Field | Value |
|---|---|
| SHA-256 | `25f7148ab7b1fcffaf0ba1ef6bce03b2342ed70089a6b7e582a88824c37ece3a` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-07 20:53:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6be865e6aef9a8fab91797bff3c6676` |
| SHA-1 | `ac33b5a181640b515db851012a82dc2941ff3dd6` |
| SHA-256 | `25f7148ab7b1fcffaf0ba1ef6bce03b2342ed70089a6b7e582a88824c37ece3a` |
| SHA3-384 | `dfce54c48c8793315a0bfca75a0e78daf75b18680ebf008de0da756717204bcbfe66f066aa7400895e71b9d06de4dbdc` |
| TLSH | `T10D565B13ECA925E9C0AE92308A729553BB717C891F3123D32B50B7386F77BD069B9744` |
| TELFHASH | `t1263248314dbd35b5b696da10b3a3b4f899371ca572f878b11463a884ffc5e801ca2877` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Ko6iG1kyyDUMnpJeQ5VtfD2nd4I7czKAtoFnOt5CVZfN+DIbAKlK1Kcxm/75E/:KoC1bH5K5Cvb+xm/tE/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_25f7148a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f7148ab7b1fcffaf0ba1ef6bce03b2342ed70089a6b7e582a88824c37ece3a"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-07 20:53:29"
  condition:
    hash.sha256(0, filesize) == "25f7148ab7b1fcffaf0ba1ef6bce03b2342ed70089a6b7e582a88824c37ece3a"
}
```

### Sample 91: `311d843746a0c174`

| Field | Value |
|---|---|
| SHA-256 | `311d843746a0c17469003556ee0fcce655f97ff20a304a3d6cf2c800dae44e50` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-07 20:53:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a89c776eac74d10d5d4efea2702fe43f` |
| SHA-1 | `38558f9167b32d330bf73c6b109eeab49f9d4cc7` |
| SHA-256 | `311d843746a0c17469003556ee0fcce655f97ff20a304a3d6cf2c800dae44e50` |
| SHA3-384 | `dee9fbb760c525af00a9e11392a3d179e0d904603dda8e25370a5b1be2d32d3ed4e106642753e061dc1909d51b4550d7` |
| TLSH | `T189E33B56EB404B13C0D61779B6EF424533239BA493EB73069924AFF43F8679E4E23A05` |
| TELFHASH | `t1ac310e755b22a1166961dd64d9fe87b1a51983131784ff33df2688cc240904ee72bc5f` |
| SSDEEP | `3072:le+4w/HaAYe6Qxse54PO8tqd77c2GWWJxVXqomyw:lesHaAYe6QxxOudc2GWWJxV6VT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_311d8437
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "311d843746a0c17469003556ee0fcce655f97ff20a304a3d6cf2c800dae44e50"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 20:53:26"
  condition:
    hash.sha256(0, filesize) == "311d843746a0c17469003556ee0fcce655f97ff20a304a3d6cf2c800dae44e50"
}
```

### Sample 92: `fed1d182cd722f3d`

| Field | Value |
|---|---|
| SHA-256 | `fed1d182cd722f3d67695d1c1787910f1699dce6db409da5bb9f3aa1453d43d2` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-07 20:50:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `018bbdd10da13685f667139e6bf3e838` |
| SHA-1 | `57fd16a0ed3fd35e669f90da5bdfd6c7daadb423` |
| SHA-256 | `fed1d182cd722f3d67695d1c1787910f1699dce6db409da5bb9f3aa1453d43d2` |
| SHA3-384 | `f46a6cb34694257815b09f7d53443eaf0924c1b8a604141f378dfdcab35380f7c4da4aaab339de0f23452d7c1500e8e0` |
| TLSH | `T11F041946F9829F05D4D721FAFA8E514933536BB8E3FE7002ED205F6123CA59B0B76612` |
| TELFHASH | `t11ca00264561c78b1b4e646161df705d4a18060aa47142334434278bcad46c976463907` |
| SSDEEP | `3072:DFOYy/kO6aHzUDgcOQV3V66USPlxYW3jaWt7ApaUV4wotH7U8TsueKMmX:5y/kONTspHVo619xY2jay7ApaUV4XI8B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_fed1d182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fed1d182cd722f3d67695d1c1787910f1699dce6db409da5bb9f3aa1453d43d2"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-07 20:50:11"
  condition:
    hash.sha256(0, filesize) == "fed1d182cd722f3d67695d1c1787910f1699dce6db409da5bb9f3aa1453d43d2"
}
```

### Sample 93: `4715c0f8a834793e`

| Field | Value |
|---|---|
| SHA-256 | `4715c0f8a834793e89c0be07ff44ddb11fe93aab5e098eddc30cec8b76c5865b` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-07 20:47:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd9bcf922425bb56b128e37aad73cb8b` |
| SHA-1 | `c873f034eeb78a00c96360d29d3c95c828f75ccb` |
| SHA-256 | `4715c0f8a834793e89c0be07ff44ddb11fe93aab5e098eddc30cec8b76c5865b` |
| SHA3-384 | `815e112b54b29c7d17bbfe1f244b289e2431fee2b63b3979cdf0b133c13fe83dcbf05dbb3c688886122756b33d9b9415` |
| TLSH | `T144D3F965F880DE61C6D2267AFB9D438933231B78C3DE7102DD14AF3436EA95B0B3A546` |
| TELFHASH | `t139e0c012cfc81bfcf3e29c61c7a0656c93f735e42b15e0b4893848735c64881312643b` |
| SSDEEP | `3072:kJ1ragyT4RjgTZuamOH4I2Huao8KZqwJpefBrzS7V8bTO4nCv:kJDhUZEI2Huao8KZqwrefUV8bxI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_4715c0f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4715c0f8a834793e89c0be07ff44ddb11fe93aab5e098eddc30cec8b76c5865b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 20:47:20"
  condition:
    hash.sha256(0, filesize) == "4715c0f8a834793e89c0be07ff44ddb11fe93aab5e098eddc30cec8b76c5865b"
}
```

### Sample 94: `08233336f9eb09a8`

| Field | Value |
|---|---|
| SHA-256 | `08233336f9eb09a8cfdcb3789291656eedc6633f664c96a88f4d4f17ffea96b0` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-07 20:46:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f489d73fcb0c91625b5509fbaf7d4d16` |
| SHA-1 | `cf2670e868bfda9e2de2fa8e0a2f79f768f2d4ca` |
| SHA-256 | `08233336f9eb09a8cfdcb3789291656eedc6633f664c96a88f4d4f17ffea96b0` |
| SHA3-384 | `674b61c0cfd49910e2680d5802a0dc387bea8d5981a536f6ad9308c46c1ac0fa561ae96ce9d2192da541f5208fa87b03` |
| TLSH | `T14053014296F8F4E1D21479F8E86A24443BB32371D1D4B2551B08978FE7D3286A7BE9C3` |
| SSDEEP | `1536:6N+leQbkTmb+58B9EkaouFPYxIUnn32jpTBaa:Fs8HOoIIcTBt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_08233336
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08233336f9eb09a8cfdcb3789291656eedc6633f664c96a88f4d4f17ffea96b0"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 20:46:40"
  condition:
    hash.sha256(0, filesize) == "08233336f9eb09a8cfdcb3789291656eedc6633f664c96a88f4d4f17ffea96b0"
}
```

### Sample 95: `cfe8205eaccab5cb`

| Field | Value |
|---|---|
| SHA-256 | `cfe8205eaccab5cb53c393b0b2fec04952344c78739e869d11bd433b7bb53c57` |
| Family label | `Mirai` |
| File name | `jklarm7` |
| File type | `elf` |
| First seen | `2026-10-07 20:37:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8de741b339cbabdb2fe99d9958bd2d2b` |
| SHA-1 | `9b3418af6313101bde37305402a62e53f27195fd` |
| SHA-256 | `cfe8205eaccab5cb53c393b0b2fec04952344c78739e869d11bd433b7bb53c57` |
| SHA3-384 | `43b97067197d0a612db86b16303b7b7fcb6c7567ccbdc1b732a4e2d0fd176588b84af61da99eee0fb8ac6bcbd7fcdd0e` |
| TLSH | `T1D5C30A89FC808B11D5D525BAFE1E518D33534BBCE3FA7113DE149B2A278A86B0E37601` |
| SSDEEP | `3072:jOaRAA+tfrMxASEqZjfRpIp7wGyjjBxIa7VsJ8UpufWy98zrYFz5VU:K6AMhfYtwGyRea7VsJ8UQf583YC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_cfe8205e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe8205eaccab5cb53c393b0b2fec04952344c78739e869d11bd433b7bb53c57"
    family = "Mirai"
    file_name = "jklarm7"
    file_type = "elf"
    first_seen = "2026-10-07 20:37:12"
  condition:
    hash.sha256(0, filesize) == "cfe8205eaccab5cb53c393b0b2fec04952344c78739e869d11bd433b7bb53c57"
}
```

### Sample 96: `189316f75c03ac1f`

| Field | Value |
|---|---|
| SHA-256 | `189316f75c03ac1f4abf2b5c2a512304ff0235629bdc9425a3ce600a5080dcc2` |
| Family label | `Mirai` |
| File name | `jklarm` |
| File type | `elf` |
| First seen | `2026-10-07 20:37:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `621deee1b9d1a52a16cbf1e904da0938` |
| SHA-1 | `85760c9a259c50b24943848ea8a0f82869a516a0` |
| SHA-256 | `189316f75c03ac1f4abf2b5c2a512304ff0235629bdc9425a3ce600a5080dcc2` |
| SHA3-384 | `918955028f2bb7cc39176526cea42b4d3d35130b2d58dcea79004ea88c16ea37041de68331f38cf70d7e71e9621bb238` |
| TLSH | `T1ACB30A8ABCC1C612C5E161B7FB1F52CD372643A8E3E67117CD19AB29374B8670A3B151` |
| TELFHASH | `t1f571f11beb841f9c37f1056442ee502ba6f934dd0b11349ade6dab5f9f42ec27029827` |
| SSDEEP | `1536:cySHLrOYFhyrtBxTNwWhTgISxJS94BK4xhofxu+2nJHv4v+fx8xRra:dWjFsrLx9SISJKkK4xhb+Ye+fxGa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_189316f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189316f75c03ac1f4abf2b5c2a512304ff0235629bdc9425a3ce600a5080dcc2"
    family = "Mirai"
    file_name = "jklarm"
    file_type = "elf"
    first_seen = "2026-10-07 20:37:10"
  condition:
    hash.sha256(0, filesize) == "189316f75c03ac1f4abf2b5c2a512304ff0235629bdc9425a3ce600a5080dcc2"
}
```

### Sample 97: `c7379839f369be77`

| Field | Value |
|---|---|
| SHA-256 | `c7379839f369be77459456639443959b1760b4f0dae42e197a4099254d69f69c` |
| Family label | `unknown` |
| File name | `WiresharkPortable64_4.6.9.exe` |
| File type | `exe` |
| First seen | `2026-10-07 20:36:20` |
| Reporter | `smica83` |
| Tags | `exe, HUN` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `102ca9733867a87f60ea7409cb399080` |
| SHA-1 | `c34ba7564e514b33ba403c89e504df79e0d1bd8c` |
| SHA-256 | `c7379839f369be77459456639443959b1760b4f0dae42e197a4099254d69f69c` |
| SHA3-384 | `fe2d5fce2d3c8fe83da20a9c096dacfaf2616adc2e1407a7a02717bcd304e7620630ebe56a0ccd2a9ac317341da69f1b` |
| IMPHASH | `0aa1d2c5009f05de38022bfe7b2bd062` |
| TLSH | `T12B24BF19A3A32CF8C66AC13657D797B3E873F8225521EEBF0394CE351E56C51632D224` |
| SSDEEP | `6144:rHxxArkxigJt8ChDm1PbSWOOh0bmDE3kEJuc:Tcrg58ChcGAh0bMEkUt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_c7379839
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7379839f369be77459456639443959b1760b4f0dae42e197a4099254d69f69c"
    family = "unknown"
    file_name = "WiresharkPortable64_4.6.9.exe"
    file_type = "exe"
    first_seen = "2026-10-07 20:36:20"
  condition:
    hash.sha256(0, filesize) == "c7379839f369be77459456639443959b1760b4f0dae42e197a4099254d69f69c"
}
```

### Sample 98: `4a249b9250d5b448`

| Field | Value |
|---|---|
| SHA-256 | `4a249b9250d5b448702ff2cb127cd9424aed9c0234a182af30385189d667f78a` |
| Family label | `unknown` |
| File name | `NFSe-convenio_3525cf89.vbs` |
| File type | `vbs` |
| First seen | `2026-10-07 20:34:29` |
| Reporter | `johnk3r` |
| Tags | `banker, contabilidadeacportela-net, controedatoerpestanavidroslat-com, downloader, hggdconfeccoesgruponacional-click, saladeouroriopreto-shop, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf440850df123311c07131468c9c382f` |
| SHA-1 | `a1f303da1a48401eb105ee9c37dea587b0a417b4` |
| SHA-256 | `4a249b9250d5b448702ff2cb127cd9424aed9c0234a182af30385189d667f78a` |
| SHA3-384 | `492ea039bc536946fedc58db960efeaf0144e932feaba9820d75a56bb6bedb1487f09d93308b4a8c2773cb93ba6815bb` |
| TLSH | `T1F3F2063D5D67033765B8D318D0880A9BF65A669BF4325F1D94CB8FAA262324378C0F2D` |
| SSDEEP | `384:LKNH91GxyUF/1gfHBMRLCTG3nh79Z3rlnR4D:g1wIiNvHOD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_4a249b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a249b9250d5b448702ff2cb127cd9424aed9c0234a182af30385189d667f78a"
    family = "unknown"
    file_name = "NFSe-convenio_3525cf89.vbs"
    file_type = "vbs"
    first_seen = "2026-10-07 20:34:29"
  condition:
    hash.sha256(0, filesize) == "4a249b9250d5b448702ff2cb127cd9424aed9c0234a182af30385189d667f78a"
}
```

### Sample 99: `b209260c366e07c2`

| Field | Value |
|---|---|
| SHA-256 | `b209260c366e07c2f33e03a37afba393b06f29e236b7735bf74cc36fe87dc086` |
| Family label | `unknown` |
| File name | `Neural DSP Archetype Tim Henson X WiN-MAC.exe` |
| File type | `exe` |
| First seen | `2026-10-07 20:33:49` |
| Reporter | `anonymous` |
| Tags | `exe, infostealer, token grab` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34507bf7c00c94401b56daf56cbff5c5` |
| SHA-1 | `add9975c8c70862dff2922d1316cfd42e1d01d22` |
| SHA-256 | `b209260c366e07c2f33e03a37afba393b06f29e236b7735bf74cc36fe87dc086` |
| SHA3-384 | `e0aaeb607b373294e5c5bddd6d080629d75d3e3bd929e34ba357f022901885a3809ed3dedcfa90070ec087af8ea22f7e` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T157A5C03BF28BA13EE06A1A367A72A210553BBA1165164C1697FCF84CCF355701E3F687` |
| SSDEEP | `24576:iXfPki0RBC19GXIVdIHsgJXpJehyxwKlvdXgKfpXrbEL10B+kM/PfcXmH1bmBXjp:wob1B2+TwKfpbR+/T1bmBXfqC` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_b209260c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b209260c366e07c2f33e03a37afba393b06f29e236b7735bf74cc36fe87dc086"
    family = "unknown"
    file_name = "Neural DSP Archetype Tim Henson X WiN-MAC.exe"
    file_type = "exe"
    first_seen = "2026-10-07 20:33:49"
  condition:
    hash.sha256(0, filesize) == "b209260c366e07c2f33e03a37afba393b06f29e236b7735bf74cc36fe87dc086"
}
```

### Sample 100: `e52d35b6be2ed20b`

| Field | Value |
|---|---|
| SHA-256 | `e52d35b6be2ed20b97c41e9ab067914368e0106dab128ce119d65f20fd1e64eb` |
| Family label | `unknown` |
| File name | `SOA20261007054.291E17.vhdx` |
| File type | `vhdx` |
| First seen | `2026-10-07 20:33:10` |
| Reporter | `smica83` |
| Tags | `vhdx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7fe3212411042ff726ab2c967b670e6` |
| SHA-1 | `bb60054daa15de2f2c3decb14ace5a6a772af61f` |
| SHA-256 | `e52d35b6be2ed20b97c41e9ab067914368e0106dab128ce119d65f20fd1e64eb` |
| SHA3-384 | `b069b2e88e32f40cf77729227b5c10473bfe039a9a55d7b4e8ff5bc29bd7f7231832b066ecbc4a486acd2000d8a0c36c` |
| TLSH | `T18487CF213981C03ED2AA13708D7DB7B963BDAD201F3581DF62C87A2D6F709D25936663` |
| SSDEEP | `98304:7WCPEp3NBOMoNxY9J4SwEi8qmlNvZxOs3gz5da2aUydgHGyB8qyzojcAnG:R5QCv8qmlNvPtgzzcGL2g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vhdx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_e52d35b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e52d35b6be2ed20b97c41e9ab067914368e0106dab128ce119d65f20fd1e64eb"
    family = "unknown"
    file_name = "SOA20261007054.291E17.vhdx"
    file_type = "vhdx"
    first_seen = "2026-10-07 20:33:10"
  condition:
    hash.sha256(0, filesize) == "e52d35b6be2ed20b97c41e9ab067914368e0106dab128ce119d65f20fd1e64eb"
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
 * Generated: 2026-10-08T06:16:39.257233+00:00
 */

rule MalwareBazaar_Mirai_001_4b9c63f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b9c63f38bd6a44a571be9ad89abdb15753762848d79994368b6a9df487adf91"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-10-08 06:11:54"
  condition:
    hash.sha256(0, filesize) == "4b9c63f38bd6a44a571be9ad89abdb15753762848d79994368b6a9df487adf91"
}

rule MalwareBazaar_unknown_002_123d6341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a"
    family = "unknown"
    file_name = "123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a"
    file_type = "exe"
    first_seen = "2026-10-08 06:01:40"
  condition:
    hash.sha256(0, filesize) == "123d63412a11ac17534ed29361125e0267650cb43eaa543fb4e0827c7c968a0a"
}

rule MalwareBazaar_Mirai_003_0ee51420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ee51420bf76c95707151e64efb94636103299413bc67e99ea2fbb9f6da86e9d"
    family = "Mirai"
    file_name = "eclipse.sh4"
    file_type = "elf"
    first_seen = "2026-10-08 06:00:35"
  condition:
    hash.sha256(0, filesize) == "0ee51420bf76c95707151e64efb94636103299413bc67e99ea2fbb9f6da86e9d"
}

rule MalwareBazaar_Mirai_004_b965f772
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65"
    family = "Mirai"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-10-08 06:00:33"
  condition:
    hash.sha256(0, filesize) == "b965f772177c2e79bff3739cdffa544d357e16441bdd833428aae067fe52dd65"
}

rule MalwareBazaar_Mirai_005_efc37e17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc37e171e6a133d0fb0e9197da76227f1794fda5a93ebab0d718f8111768176"
    family = "Mirai"
    file_name = "jklarm5"
    file_type = "elf"
    first_seen = "2026-10-08 06:00:31"
  condition:
    hash.sha256(0, filesize) == "efc37e171e6a133d0fb0e9197da76227f1794fda5a93ebab0d718f8111768176"
}

rule MalwareBazaar_Mirai_006_4c475abc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c475abc830a8a1cf460927c26daea7dd156b641b66ebf72835e74dc38ef1577"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 05:56:40"
  condition:
    hash.sha256(0, filesize) == "4c475abc830a8a1cf460927c26daea7dd156b641b66ebf72835e74dc38ef1577"
}

rule MalwareBazaar_Mirai_007_f80220d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f80220d22e396186175a3e8f61e8175a3cb25b4a18d7e31937cf4925ca7e3b82"
    family = "Mirai"
    file_name = "jklarm6"
    file_type = "elf"
    first_seen = "2026-10-08 05:56:38"
  condition:
    hash.sha256(0, filesize) == "f80220d22e396186175a3e8f61e8175a3cb25b4a18d7e31937cf4925ca7e3b82"
}

rule MalwareBazaar_Mirai_008_7b8cd695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417"
    family = "Mirai"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-10-08 05:56:36"
  condition:
    hash.sha256(0, filesize) == "7b8cd695424f9b004b459ce886d92e9a24f38957dc9071510ab669a7cb89c417"
}

rule MalwareBazaar_Mirai_009_9ea109cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea109cdf6b5c41f63737d6ec31d6f8c75d826a2d6939d8aeb675d7134b318d9"
    family = "Mirai"
    file_name = "eclipse.armv7l"
    file_type = "elf"
    first_seen = "2026-10-08 05:56:34"
  condition:
    hash.sha256(0, filesize) == "9ea109cdf6b5c41f63737d6ec31d6f8c75d826a2d6939d8aeb675d7134b318d9"
}

rule MalwareBazaar_Mirai_010_1298d6b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1298d6b525ff93135ba5328dd5ec97cf71870fe9f869b5e6e4a23de23bc99e96"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-08 05:52:43"
  condition:
    hash.sha256(0, filesize) == "1298d6b525ff93135ba5328dd5ec97cf71870fe9f869b5e6e4a23de23bc99e96"
}

rule MalwareBazaar_Mirai_011_c11ab3d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c11ab3d584a5f56b443061f8e02b7d5d7257ecf16a5148682a80eefcbf4e21dc"
    family = "Mirai"
    file_name = "eclipse.m68k"
    file_type = "elf"
    first_seen = "2026-10-08 05:40:56"
  condition:
    hash.sha256(0, filesize) == "c11ab3d584a5f56b443061f8e02b7d5d7257ecf16a5148682a80eefcbf4e21dc"
}

rule MalwareBazaar_Mirai_012_f190679b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f190679b3691ab8ad2ad74df3ddfccff7933bc163186eba88a68ef82cfeb404c"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-08 05:37:25"
  condition:
    hash.sha256(0, filesize) == "f190679b3691ab8ad2ad74df3ddfccff7933bc163186eba88a68ef82cfeb404c"
}

rule MalwareBazaar_Mirai_013_db20893c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db20893cd7e7889473e6bc0f7392b7b0a52c5fc7d11e2ba1fb3325da2e7664b4"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-08 05:30:19"
  condition:
    hash.sha256(0, filesize) == "db20893cd7e7889473e6bc0f7392b7b0a52c5fc7d11e2ba1fb3325da2e7664b4"
}

rule MalwareBazaar_Mirai_014_21492d42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150"
    family = "Mirai"
    file_name = "21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150"
    file_type = "elf"
    first_seen = "2026-10-08 05:28:48"
  condition:
    hash.sha256(0, filesize) == "21492d4240365a15d22cc2a3ac6514e0b79e99f98187424f280d191b3de3d150"
}

rule MalwareBazaar_Mirai_015_a1387b7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1387b7ec0e7488b84b1ddab1c3927b0657918256cf8c25ca252080da5a49e83"
    family = "Mirai"
    file_name = "eclipse.powerpc"
    file_type = "elf"
    first_seen = "2026-10-08 05:19:52"
  condition:
    hash.sha256(0, filesize) == "a1387b7ec0e7488b84b1ddab1c3927b0657918256cf8c25ca252080da5a49e83"
}

rule MalwareBazaar_unknown_016_cab39b72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab39b72d61381b9f379acc62cad4b5fabee0e38cd167ff2ceb7b55dcb6509c6"
    family = "unknown"
    file_name = "eclipse.armv5l"
    file_type = "elf"
    first_seen = "2026-10-08 05:19:50"
  condition:
    hash.sha256(0, filesize) == "cab39b72d61381b9f379acc62cad4b5fabee0e38cd167ff2ceb7b55dcb6509c6"
}

rule MalwareBazaar_RemusStealer_017_7d722643
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d72264319c996b8c3dabfb3ae01961f7c124471207bae849e85cea32c82c79a"
    family = "RemusStealer"
    file_name = "89d4bf8726440c1e25623d10bf36c52de91113130b058bc4fcb4c637758c2070.exe"
    file_type = "exe"
    first_seen = "2026-10-08 05:17:54"
  condition:
    hash.sha256(0, filesize) == "7d72264319c996b8c3dabfb3ae01961f7c124471207bae849e85cea32c82c79a"
}

rule MalwareBazaar_unknown_018_26b837f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26b837f91d2341ea1e817c4654a53e0ff75feb6c6f7e341ae61158ae24fa6f67"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-10-08 04:52:18"
  condition:
    hash.sha256(0, filesize) == "26b837f91d2341ea1e817c4654a53e0ff75feb6c6f7e341ae61158ae24fa6f67"
}

rule MalwareBazaar_unknown_019_bb85ba27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb85ba27f3091b70021fcd35e9be354fd8506078b7d4714991f9df061b80613a"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-10-08 04:48:18"
  condition:
    hash.sha256(0, filesize) == "bb85ba27f3091b70021fcd35e9be354fd8506078b7d4714991f9df061b80613a"
}

rule MalwareBazaar_RevStealer_020_69dafc3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0"
    family = "RevStealer"
    file_name = "69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0.exe"
    file_type = "exe"
    first_seen = "2026-10-08 03:50:59"
  condition:
    hash.sha256(0, filesize) == "69dafc3b40a5b0e5eddc7cba6ec32ca7316b7e5405d8c6d5adfbccc4c06620c0"
}

rule MalwareBazaar_Vidar_021_0f37ed17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f37ed17ba77ce94b880e16f1e38464ebaf5cd907666cf75075df16d9a166092"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 03:35:24"
  condition:
    hash.sha256(0, filesize) == "0f37ed17ba77ce94b880e16f1e38464ebaf5cd907666cf75075df16d9a166092"
}

rule MalwareBazaar_Vidar_022_63d5297a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63d5297ab9ccc40d45877940e18d5403e26914f1d71b59fb973f667d9095df54"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 03:35:09"
  condition:
    hash.sha256(0, filesize) == "63d5297ab9ccc40d45877940e18d5403e26914f1d71b59fb973f667d9095df54"
}

rule MalwareBazaar_unknown_023_f0157306
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0157306c1872b748e2a1c4edc12b516e0786fa01c61e9903f67d120c6ae3a90"
    family = "unknown"
    file_name = "z1PO3294.msi"
    file_type = "msi"
    first_seen = "2026-10-08 03:00:06"
  condition:
    hash.sha256(0, filesize) == "f0157306c1872b748e2a1c4edc12b516e0786fa01c61e9903f67d120c6ae3a90"
}

rule MalwareBazaar_Mirai_024_d6db1449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6db1449d533d851dd6bd2030a03ac857deb4eecf2067038d4dafb85ab14c320"
    family = "Mirai"
    file_name = "eclipse.armv6l"
    file_type = "elf"
    first_seen = "2026-10-08 02:52:45"
  condition:
    hash.sha256(0, filesize) == "d6db1449d533d851dd6bd2030a03ac857deb4eecf2067038d4dafb85ab14c320"
}

rule MalwareBazaar_unknown_025_64506ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64506ae267aed8afa5cfbb41ca8f5677600747f02fe27b8d8d926d12e3ad99f2"
    family = "unknown"
    file_name = "NEW_FLF7997_SHIPMENT_DETAILpdf.com"
    file_type = "exe"
    first_seen = "2026-10-08 02:51:21"
  condition:
    hash.sha256(0, filesize) == "64506ae267aed8afa5cfbb41ca8f5677600747f02fe27b8d8d926d12e3ad99f2"
}

rule MalwareBazaar_unknown_026_2e965ae3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e965ae359bcc693148128a48232f8c4e8a8beb84b2af822eb9abe4b0fa5a8da"
    family = "unknown"
    file_name = "RFQ ORDER LIST.js"
    file_type = "js"
    first_seen = "2026-10-08 02:15:47"
  condition:
    hash.sha256(0, filesize) == "2e965ae359bcc693148128a48232f8c4e8a8beb84b2af822eb9abe4b0fa5a8da"
}

rule MalwareBazaar_ValleyRAT_027_4b8ff079
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8ff07916069c2e4249264e3f328ff20bba73f853058603797d514658c6cbf6"
    family = "ValleyRAT"
    file_name = "76D096206F9FC7ACD8399789E603BF1C.dll"
    file_type = "dll"
    first_seen = "2026-10-08 02:05:10"
  condition:
    hash.sha256(0, filesize) == "4b8ff07916069c2e4249264e3f328ff20bba73f853058603797d514658c6cbf6"
}

rule MalwareBazaar_unknown_028_f5de4160
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5de41608cef69564120fe3d3641595e00c6b79d43a5a4a21e966dc971e0470a"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-08 01:41:36"
  condition:
    hash.sha256(0, filesize) == "f5de41608cef69564120fe3d3641595e00c6b79d43a5a4a21e966dc971e0470a"
}

rule MalwareBazaar_Mirai_029_eee4ac11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eee4ac11b0d5d301b3e42cfd8ae1eeb91e13eb4283d2e1cba1dbbdcaf263c480"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-08 01:41:34"
  condition:
    hash.sha256(0, filesize) == "eee4ac11b0d5d301b3e42cfd8ae1eeb91e13eb4283d2e1cba1dbbdcaf263c480"
}

rule MalwareBazaar_Mirai_030_bc2c00af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2c00af55c952dd304f074322ff8766bc00b851fb75c076d7da503f33edfb62"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-10-08 01:37:39"
  condition:
    hash.sha256(0, filesize) == "bc2c00af55c952dd304f074322ff8766bc00b851fb75c076d7da503f33edfb62"
}

rule MalwareBazaar_unknown_031_7c0eca06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c0eca069425de62a1e39073e62206e8c7b2082aa6163daea602c16c869f3846"
    family = "unknown"
    file_name = "purchase order.rar"
    file_type = "rar"
    first_seen = "2026-10-08 01:36:20"
  condition:
    hash.sha256(0, filesize) == "7c0eca069425de62a1e39073e62206e8c7b2082aa6163daea602c16c869f3846"
}

rule MalwareBazaar_unknown_032_a20fd13b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a20fd13bc48d9d092746ca0ae0493a7b4280ac81e7eb6731151761ac8cc91dba"
    family = "unknown"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-08 01:33:56"
  condition:
    hash.sha256(0, filesize) == "a20fd13bc48d9d092746ca0ae0493a7b4280ac81e7eb6731151761ac8cc91dba"
}

rule MalwareBazaar_Mirai_033_f5cd52e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5cd52e208bef630b6a6431e0e435e085e9e10106be9bb4c72e6147f1362a789"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-08 01:33:53"
  condition:
    hash.sha256(0, filesize) == "f5cd52e208bef630b6a6431e0e435e085e9e10106be9bb4c72e6147f1362a789"
}

rule MalwareBazaar_unknown_034_19969403
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "199694033b66e4b868e19e1b17c10e7e402ffb58bf3c989e91ff45e6d65c7956"
    family = "unknown"
    file_name = "macho_199694033b66.bin"
    file_type = "macho"
    first_seen = "2026-10-08 01:26:18"
  condition:
    hash.sha256(0, filesize) == "199694033b66e4b868e19e1b17c10e7e402ffb58bf3c989e91ff45e6d65c7956"
}

rule MalwareBazaar_Mirai_035_a527b6ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a527b6aee124dba9df0ece29610bc141bf532075189e0d62a7e26f343844f867"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-08 01:23:20"
  condition:
    hash.sha256(0, filesize) == "a527b6aee124dba9df0ece29610bc141bf532075189e0d62a7e26f343844f867"
}

rule MalwareBazaar_Mirai_036_7ec4e71a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ec4e71a172d211208be0bc17434f0812a49d74674f406a1666c46a984757a93"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-10-08 01:19:41"
  condition:
    hash.sha256(0, filesize) == "7ec4e71a172d211208be0bc17434f0812a49d74674f406a1666c46a984757a93"
}

rule MalwareBazaar_Mirai_037_fe1d7aed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe1d7aedc8ebd2976e1c7041a6982635698cc77e93eeea12a844f4ce06e620b1"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-10-08 01:19:39"
  condition:
    hash.sha256(0, filesize) == "fe1d7aedc8ebd2976e1c7041a6982635698cc77e93eeea12a844f4ce06e620b1"
}

rule MalwareBazaar_Mirai_038_9d984c4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d984c4c21b2c708cc1df1d8ad8687472390ba6c08c4ff95dbc63facc9dcef7a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-08 01:15:30"
  condition:
    hash.sha256(0, filesize) == "9d984c4c21b2c708cc1df1d8ad8687472390ba6c08c4ff95dbc63facc9dcef7a"
}

rule MalwareBazaar_unknown_039_77d2fc48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77d2fc48b9f21ea2a65a90f07f9544343e47d08edbeafe17c306c9cc143fda80"
    family = "unknown"
    file_name = "ppc64le"
    file_type = "elf"
    first_seen = "2026-10-08 01:11:39"
  condition:
    hash.sha256(0, filesize) == "77d2fc48b9f21ea2a65a90f07f9544343e47d08edbeafe17c306c9cc143fda80"
}

rule MalwareBazaar_Mirai_040_f2df7929
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2df79291d08c29e4dd851ac2d73d4440da32802585fed60418973cd1a7b0044"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-10-08 00:54:20"
  condition:
    hash.sha256(0, filesize) == "f2df79291d08c29e4dd851ac2d73d4440da32802585fed60418973cd1a7b0044"
}

rule MalwareBazaar_unknown_041_52ac6da9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002"
    family = "unknown"
    file_name = "52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002.exe"
    file_type = "exe"
    first_seen = "2026-10-08 00:54:09"
  condition:
    hash.sha256(0, filesize) == "52ac6da98c763673e7c2ffa13a1f893325fd33c7179f9ac06b7a7de54b2be002"
}

rule MalwareBazaar_unknown_042_c871c21a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c871c21a1e5398bab70d1c5155e7c8a6675b07082faf9a158de552f12ed6d357"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-08 00:50:35"
  condition:
    hash.sha256(0, filesize) == "c871c21a1e5398bab70d1c5155e7c8a6675b07082faf9a158de552f12ed6d357"
}

rule MalwareBazaar_unknown_043_76f09125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb"
    family = "unknown"
    file_name = "76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb.exe"
    file_type = "exe"
    first_seen = "2026-10-08 00:46:53"
  condition:
    hash.sha256(0, filesize) == "76f091251ac6557420e211729dd1c070149ed6e3a0bab0bef0e81b995705b2bb"
}

rule MalwareBazaar_Mirai_044_0a2d67c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a2d67c0390cb31ce23d132d1e96c20385ae61d482c1627669ae3d9b7a7e77c4"
    family = "Mirai"
    file_name = "mbupload-qudvn1jh.bin"
    file_type = "elf"
    first_seen = "2026-10-08 00:44:09"
  condition:
    hash.sha256(0, filesize) == "0a2d67c0390cb31ce23d132d1e96c20385ae61d482c1627669ae3d9b7a7e77c4"
}

rule MalwareBazaar_Mirai_045_17fcb5d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17fcb5d7d251b9684177a28843a4aaaee86539469ad20de3deb2063ee18ed63a"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-08 00:40:19"
  condition:
    hash.sha256(0, filesize) == "17fcb5d7d251b9684177a28843a4aaaee86539469ad20de3deb2063ee18ed63a"
}

rule MalwareBazaar_unknown_046_0bff11bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bff11bb3bf1c34493d7185fc47b738d302d63a1b740d751de2eabfc1bc173c7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-08 00:40:08"
  condition:
    hash.sha256(0, filesize) == "0bff11bb3bf1c34493d7185fc47b738d302d63a1b740d751de2eabfc1bc173c7"
}

rule MalwareBazaar_RemusStealer_047_4aff30bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aff30bdeee80b3d8c5357048f6a9c92f216a079569d11db9aacfc7f1e02fc9b"
    family = "RemusStealer"
    file_name = "89d4bf8726440c1e25623d10bf36c52de91113130b058bc4fcb4c637758c2070.zip"
    file_type = "zip"
    first_seen = "2026-10-08 00:31:58"
  condition:
    hash.sha256(0, filesize) == "4aff30bdeee80b3d8c5357048f6a9c92f216a079569d11db9aacfc7f1e02fc9b"
}

rule MalwareBazaar_Mirai_048_893b3638
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "893b3638dccebe9c646d2301632ba5210f41b777dffd69e6b6e41bcf400d7e3c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-08 00:30:06"
  condition:
    hash.sha256(0, filesize) == "893b3638dccebe9c646d2301632ba5210f41b777dffd69e6b6e41bcf400d7e3c"
}

rule MalwareBazaar_Mirai_049_d54e450b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d54e450bcf0392d61af498d83b11271208049ee7679ab2576b7874cbad6bd43f"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-08 00:30:04"
  condition:
    hash.sha256(0, filesize) == "d54e450bcf0392d61af498d83b11271208049ee7679ab2576b7874cbad6bd43f"
}

rule MalwareBazaar_unknown_050_58a017f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05"
    family = "unknown"
    file_name = "58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05.exe"
    file_type = "exe"
    first_seen = "2026-10-08 00:21:11"
  condition:
    hash.sha256(0, filesize) == "58a017f40583556918cf57b15adbc15d51382e00de4e04e5d14ed7a7811c5f05"
}

rule MalwareBazaar_Mirai_051_f0cd29ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0cd29fff42a7dad4b00c7b1c684a7e759a159baef96f57a285e1ff7f61bbab5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-08 00:18:46"
  condition:
    hash.sha256(0, filesize) == "f0cd29fff42a7dad4b00c7b1c684a7e759a159baef96f57a285e1ff7f61bbab5"
}

rule MalwareBazaar_Mirai_052_9fac6abd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fac6abd1c35da9e68fb4f00f33de82306adf96093ea806f3c42d4a153e39c9e"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-07 23:53:20"
  condition:
    hash.sha256(0, filesize) == "9fac6abd1c35da9e68fb4f00f33de82306adf96093ea806f3c42d4a153e39c9e"
}

rule MalwareBazaar_Mirai_053_b83161e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83161e15983296d02b14206f2a00f6ce7928d7f6c5b56c80aaa5c8e115fd7f7"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-10-07 23:49:42"
  condition:
    hash.sha256(0, filesize) == "b83161e15983296d02b14206f2a00f6ce7928d7f6c5b56c80aaa5c8e115fd7f7"
}

rule MalwareBazaar_unknown_054_d441b918
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d441b9180182969f844543b556a012a87b056b333f0a98da9b6abdaa7c791805"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-07 23:46:23"
  condition:
    hash.sha256(0, filesize) == "d441b9180182969f844543b556a012a87b056b333f0a98da9b6abdaa7c791805"
}

rule MalwareBazaar_unknown_055_feaa5822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "feaa5822f2af1ce3686d527d14877332c69ea565e2afcff25ef437e3b915e300"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 23:44:09"
  condition:
    hash.sha256(0, filesize) == "feaa5822f2af1ce3686d527d14877332c69ea565e2afcff25ef437e3b915e300"
}

rule MalwareBazaar_Mirai_056_9080cd48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9080cd485a8b94742cce721c63ffd0266ee9b3684e48165db8b6b12e0d181760"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-07 23:42:46"
  condition:
    hash.sha256(0, filesize) == "9080cd485a8b94742cce721c63ffd0266ee9b3684e48165db8b6b12e0d181760"
}

rule MalwareBazaar_Mirai_057_7a0efc7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a0efc7fd55dd9e665342b788b092f5660597ba1e3526f1bec3be14399a06e53"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-07 23:36:15"
  condition:
    hash.sha256(0, filesize) == "7a0efc7fd55dd9e665342b788b092f5660597ba1e3526f1bec3be14399a06e53"
}

rule MalwareBazaar_Mirai_058_4dcfacca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dcfaccade6044355f8b933ad74c97085497d7e34762e5eab473dd2b5804b486"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-07 23:32:34"
  condition:
    hash.sha256(0, filesize) == "4dcfaccade6044355f8b933ad74c97085497d7e34762e5eab473dd2b5804b486"
}

rule MalwareBazaar_Mirai_059_0bfabbd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bfabbd22e5fd6175f5701ebcb2c54aad28e5bb1106a0d98ee2a7dc1cc39bda1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-07 23:32:32"
  condition:
    hash.sha256(0, filesize) == "0bfabbd22e5fd6175f5701ebcb2c54aad28e5bb1106a0d98ee2a7dc1cc39bda1"
}

rule MalwareBazaar_Mirai_060_d6bac5a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6bac5a15715c7e1f917c1e9bda5631e852f0e61388efbbace90b5a00b653ad3"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-07 23:29:14"
  condition:
    hash.sha256(0, filesize) == "d6bac5a15715c7e1f917c1e9bda5631e852f0e61388efbbace90b5a00b653ad3"
}

rule MalwareBazaar_Mirai_061_df00f0dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df00f0dd7e94d5b0fa9bab04f681f313e8f7de19b8af9eca5e862290e1f7d519"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-07 23:25:34"
  condition:
    hash.sha256(0, filesize) == "df00f0dd7e94d5b0fa9bab04f681f313e8f7de19b8af9eca5e862290e1f7d519"
}

rule MalwareBazaar_Mirai_062_871313d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "871313d5587ad78426255e619f598f90044cf15909b6b4fcdb1cdc6962f57e6b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 23:25:31"
  condition:
    hash.sha256(0, filesize) == "871313d5587ad78426255e619f598f90044cf15909b6b4fcdb1cdc6962f57e6b"
}

rule MalwareBazaar_Mirai_063_ceb3064b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceb3064b2db7948711964dbfaba861aee73ef415a4454929528b3f26a8dda263"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-07 23:22:17"
  condition:
    hash.sha256(0, filesize) == "ceb3064b2db7948711964dbfaba861aee73ef415a4454929528b3f26a8dda263"
}

rule MalwareBazaar_Mirai_064_1e76392a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e76392a5f25bd9700b38d164be21c42946d3ef5a6bdc906093d9ebf9da6574b"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-07 23:22:15"
  condition:
    hash.sha256(0, filesize) == "1e76392a5f25bd9700b38d164be21c42946d3ef5a6bdc906093d9ebf9da6574b"
}

rule MalwareBazaar_Mirai_065_e3923ff4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3923ff4e583f2860938954ae43f3abbd7b1f09b59528b1b53dafd1ad768cec8"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-07 23:18:39"
  condition:
    hash.sha256(0, filesize) == "e3923ff4e583f2860938954ae43f3abbd7b1f09b59528b1b53dafd1ad768cec8"
}

rule MalwareBazaar_Mirai_066_d542b8cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d542b8cd29eb734177669aa9251690b47c0537c7ebbd8167311615e2836b584e"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-07 23:15:24"
  condition:
    hash.sha256(0, filesize) == "d542b8cd29eb734177669aa9251690b47c0537c7ebbd8167311615e2836b584e"
}

rule MalwareBazaar_Mirai_067_dbe8e308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbe8e30860c8fc4f1470138113f3ea1983129319938b3bb98f3616df0ac23f01"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-07 23:12:14"
  condition:
    hash.sha256(0, filesize) == "dbe8e30860c8fc4f1470138113f3ea1983129319938b3bb98f3616df0ac23f01"
}

rule MalwareBazaar_Mirai_068_ad4e1876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad4e18765c30d633729411f72d3343a6e4cb1243eca3658025119eb2885820f0"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-07 23:12:12"
  condition:
    hash.sha256(0, filesize) == "ad4e18765c30d633729411f72d3343a6e4cb1243eca3658025119eb2885820f0"
}

rule MalwareBazaar_unknown_069_79374890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79374890314b4d74a2093200bd952229c2b4eba010b083f32e4097dd1487bf00"
    family = "unknown"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-10-07 23:12:10"
  condition:
    hash.sha256(0, filesize) == "79374890314b4d74a2093200bd952229c2b4eba010b083f32e4097dd1487bf00"
}

rule MalwareBazaar_unknown_070_133401d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "133401d9a9f9c8036f0fa21d2fc221089e24830eb772f2761d7b4e8de691e94f"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-07 23:08:32"
  condition:
    hash.sha256(0, filesize) == "133401d9a9f9c8036f0fa21d2fc221089e24830eb772f2761d7b4e8de691e94f"
}

rule MalwareBazaar_Mirai_071_124cae6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "124cae6f4b5b82d325519441c3f1ac7510ef9873944e200f512b67d7b749ecbd"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-10-07 23:06:28"
  condition:
    hash.sha256(0, filesize) == "124cae6f4b5b82d325519441c3f1ac7510ef9873944e200f512b67d7b749ecbd"
}

rule MalwareBazaar_Mirai_072_8c1fbd2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c1fbd2ce69d88d5ac8b577538d0a0b5a715f9f332a082e95e6cf1d0d69dbb95"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-10-07 23:05:30"
  condition:
    hash.sha256(0, filesize) == "8c1fbd2ce69d88d5ac8b577538d0a0b5a715f9f332a082e95e6cf1d0d69dbb95"
}

rule MalwareBazaar_Mirai_073_bb85d7ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb85d7ed379fee306fa43fb0724720e5584bbcc6792780889408daf6f4024604"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-07 23:05:27"
  condition:
    hash.sha256(0, filesize) == "bb85d7ed379fee306fa43fb0724720e5584bbcc6792780889408daf6f4024604"
}

rule MalwareBazaar_Mirai_074_465356f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "465356f33b322c3f0aa694c8db805ee97ae1f278191e215468f9c10ec5a60ae1"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-07 23:05:25"
  condition:
    hash.sha256(0, filesize) == "465356f33b322c3f0aa694c8db805ee97ae1f278191e215468f9c10ec5a60ae1"
}

rule MalwareBazaar_Mirai_075_f55e5c83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f55e5c839aa59fa24da5417d6771690af1fc6402259b44de0b678c4c468cda07"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-10-07 22:59:16"
  condition:
    hash.sha256(0, filesize) == "f55e5c839aa59fa24da5417d6771690af1fc6402259b44de0b678c4c468cda07"
}

rule MalwareBazaar_unknown_076_5015ec59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183"
    family = "unknown"
    file_name = "5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183"
    file_type = "elf"
    first_seen = "2026-10-07 22:41:32"
  condition:
    hash.sha256(0, filesize) == "5015ec59389553a611aa43b8adbdbfa51b8e7e51d1afcb3193716714b131d183"
}

rule MalwareBazaar_unknown_077_7f20d414
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f20d4142b4b4d7b1664fe1c30def83ee5bac0eadbb24abf2b83136dabcee321"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-07 22:08:40"
  condition:
    hash.sha256(0, filesize) == "7f20d4142b4b4d7b1664fe1c30def83ee5bac0eadbb24abf2b83136dabcee321"
}

rule MalwareBazaar_VShell_078_2c9cee15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c9cee1590813b8223d232761c8689ef0623a7d5ae442b3f0c89c76abc10755a"
    family = "VShell"
    file_name = "18159a377f89efd15c0a9d436027ed35.exe"
    file_type = "exe"
    first_seen = "2026-10-07 21:55:13"
  condition:
    hash.sha256(0, filesize) == "2c9cee1590813b8223d232761c8689ef0623a7d5ae442b3f0c89c76abc10755a"
}

rule MalwareBazaar_unknown_079_27e15943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b"
    family = "unknown"
    file_name = "rvtools4.8.1.msi"
    file_type = "msi"
    first_seen = "2026-10-07 21:53:12"
  condition:
    hash.sha256(0, filesize) == "27e1594334eabcf7d927fb444dabc1f4221a36a8faf13b741ac65a9b1a23c87b"
}

rule MalwareBazaar_unknown_080_c85aa1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c85aa1fdc991830badc9cade5a7737d056a5e6198c7ee5b566650893d21cc3b3"
    family = "unknown"
    file_name = "ССLосitуХ64-v.6.978.exe"
    file_type = "exe"
    first_seen = "2026-10-07 21:51:36"
  condition:
    hash.sha256(0, filesize) == "c85aa1fdc991830badc9cade5a7737d056a5e6198c7ee5b566650893d21cc3b3"
}

rule MalwareBazaar_Mirai_081_7050da3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7050da3bd5b59468f4ab8457cf5f11b1cd5f556e54e2e0b1d5b1556088b949d8"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-07 21:34:27"
  condition:
    hash.sha256(0, filesize) == "7050da3bd5b59468f4ab8457cf5f11b1cd5f556e54e2e0b1d5b1556088b949d8"
}

rule MalwareBazaar_unknown_082_c2e709c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2e709c9d1de36e3a228e71d6ae7920c9f2e84fa73691508f8b73ea35855d6f7"
    family = "unknown"
    file_name = "stage2.zip"
    file_type = "zip"
    first_seen = "2026-10-07 21:19:16"
  condition:
    hash.sha256(0, filesize) == "c2e709c9d1de36e3a228e71d6ae7920c9f2e84fa73691508f8b73ea35855d6f7"
}

rule MalwareBazaar_unknown_083_18d1351e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18d1351e3d1956e63fdd3ee80f709e0320f7d1329ccea64ab8731c110343feec"
    family = "unknown"
    file_name = "stage2.au3"
    file_type = "au3"
    first_seen = "2026-10-07 21:18:32"
  condition:
    hash.sha256(0, filesize) == "18d1351e3d1956e63fdd3ee80f709e0320f7d1329ccea64ab8731c110343feec"
}

rule MalwareBazaar_Mirai_084_8b0b07aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0b07aa426d0a1a2ce43412cd65d3541cda9ca38d2d8ba2ee6be09033f717da"
    family = "Mirai"
    file_name = "payload-mips"
    file_type = "elf"
    first_seen = "2026-10-07 21:09:08"
  condition:
    hash.sha256(0, filesize) == "8b0b07aa426d0a1a2ce43412cd65d3541cda9ca38d2d8ba2ee6be09033f717da"
}

rule MalwareBazaar_Mirai_085_2782f097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2782f0971bbab49699fb228e8c68b71b116f508b14ec5eb2e5774653e152c2ba"
    family = "Mirai"
    file_name = "payload-mipsel"
    file_type = "elf"
    first_seen = "2026-10-07 21:08:49"
  condition:
    hash.sha256(0, filesize) == "2782f0971bbab49699fb228e8c68b71b116f508b14ec5eb2e5774653e152c2ba"
}

rule MalwareBazaar_unknown_086_d082bed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d082bed899d8f975f201975f3c0517debd094cf40630649283de097b0361b8fc"
    family = "unknown"
    file_name = "solicitado52"
    file_type = "msi"
    first_seen = "2026-10-07 21:03:53"
  condition:
    hash.sha256(0, filesize) == "d082bed899d8f975f201975f3c0517debd094cf40630649283de097b0361b8fc"
}

rule MalwareBazaar_unknown_087_143bf486
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "143bf4866461a98e05b0b0ea3d68dcbf070bf98f65e8627890d070591bb4b41f"
    family = "unknown"
    file_name = "solicitado52.zip"
    file_type = "zip"
    first_seen = "2026-10-07 21:03:18"
  condition:
    hash.sha256(0, filesize) == "143bf4866461a98e05b0b0ea3d68dcbf070bf98f65e8627890d070591bb4b41f"
}

rule MalwareBazaar_unknown_088_39060de5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561"
    family = "unknown"
    file_name = "mbupload-ul2x5ji5.bin"
    file_type = "sh"
    first_seen = "2026-10-07 20:55:44"
  condition:
    hash.sha256(0, filesize) == "39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561"
}

rule MalwareBazaar_unknown_089_694379dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "694379dcffba0c6af665361a3accf113f8c879fffacd5532301f550e0bfd9600"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-07 20:54:58"
  condition:
    hash.sha256(0, filesize) == "694379dcffba0c6af665361a3accf113f8c879fffacd5532301f550e0bfd9600"
}

rule MalwareBazaar_unknown_090_25f7148a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25f7148ab7b1fcffaf0ba1ef6bce03b2342ed70089a6b7e582a88824c37ece3a"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-07 20:53:29"
  condition:
    hash.sha256(0, filesize) == "25f7148ab7b1fcffaf0ba1ef6bce03b2342ed70089a6b7e582a88824c37ece3a"
}

rule MalwareBazaar_Mirai_091_311d8437
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "311d843746a0c17469003556ee0fcce655f97ff20a304a3d6cf2c800dae44e50"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 20:53:26"
  condition:
    hash.sha256(0, filesize) == "311d843746a0c17469003556ee0fcce655f97ff20a304a3d6cf2c800dae44e50"
}

rule MalwareBazaar_Mirai_092_fed1d182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fed1d182cd722f3d67695d1c1787910f1699dce6db409da5bb9f3aa1453d43d2"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-07 20:50:11"
  condition:
    hash.sha256(0, filesize) == "fed1d182cd722f3d67695d1c1787910f1699dce6db409da5bb9f3aa1453d43d2"
}

rule MalwareBazaar_Mirai_093_4715c0f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4715c0f8a834793e89c0be07ff44ddb11fe93aab5e098eddc30cec8b76c5865b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 20:47:20"
  condition:
    hash.sha256(0, filesize) == "4715c0f8a834793e89c0be07ff44ddb11fe93aab5e098eddc30cec8b76c5865b"
}

rule MalwareBazaar_Mirai_094_08233336
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08233336f9eb09a8cfdcb3789291656eedc6633f664c96a88f4d4f17ffea96b0"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-07 20:46:40"
  condition:
    hash.sha256(0, filesize) == "08233336f9eb09a8cfdcb3789291656eedc6633f664c96a88f4d4f17ffea96b0"
}

rule MalwareBazaar_Mirai_095_cfe8205e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe8205eaccab5cb53c393b0b2fec04952344c78739e869d11bd433b7bb53c57"
    family = "Mirai"
    file_name = "jklarm7"
    file_type = "elf"
    first_seen = "2026-10-07 20:37:12"
  condition:
    hash.sha256(0, filesize) == "cfe8205eaccab5cb53c393b0b2fec04952344c78739e869d11bd433b7bb53c57"
}

rule MalwareBazaar_Mirai_096_189316f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189316f75c03ac1f4abf2b5c2a512304ff0235629bdc9425a3ce600a5080dcc2"
    family = "Mirai"
    file_name = "jklarm"
    file_type = "elf"
    first_seen = "2026-10-07 20:37:10"
  condition:
    hash.sha256(0, filesize) == "189316f75c03ac1f4abf2b5c2a512304ff0235629bdc9425a3ce600a5080dcc2"
}

rule MalwareBazaar_unknown_097_c7379839
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7379839f369be77459456639443959b1760b4f0dae42e197a4099254d69f69c"
    family = "unknown"
    file_name = "WiresharkPortable64_4.6.9.exe"
    file_type = "exe"
    first_seen = "2026-10-07 20:36:20"
  condition:
    hash.sha256(0, filesize) == "c7379839f369be77459456639443959b1760b4f0dae42e197a4099254d69f69c"
}

rule MalwareBazaar_unknown_098_4a249b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a249b9250d5b448702ff2cb127cd9424aed9c0234a182af30385189d667f78a"
    family = "unknown"
    file_name = "NFSe-convenio_3525cf89.vbs"
    file_type = "vbs"
    first_seen = "2026-10-07 20:34:29"
  condition:
    hash.sha256(0, filesize) == "4a249b9250d5b448702ff2cb127cd9424aed9c0234a182af30385189d667f78a"
}

rule MalwareBazaar_unknown_099_b209260c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b209260c366e07c2f33e03a37afba393b06f29e236b7735bf74cc36fe87dc086"
    family = "unknown"
    file_name = "Neural DSP Archetype Tim Henson X WiN-MAC.exe"
    file_type = "exe"
    first_seen = "2026-10-07 20:33:49"
  condition:
    hash.sha256(0, filesize) == "b209260c366e07c2f33e03a37afba393b06f29e236b7735bf74cc36fe87dc086"
}

rule MalwareBazaar_unknown_100_e52d35b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e52d35b6be2ed20b97c41e9ab067914368e0106dab128ce119d65f20fd1e64eb"
    family = "unknown"
    file_name = "SOA20261007054.291E17.vhdx"
    file_type = "vhdx"
    first_seen = "2026-10-07 20:33:10"
  condition:
    hash.sha256(0, filesize) == "e52d35b6be2ed20b97c41e9ab067914368e0106dab128ce119d65f20fd1e64eb"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-19

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 650 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 650 |
| Unique family labels | 10 |
| Unique file types | 11 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 69 |
| Mirai | 10 |
| Prometei | 6 |
| Snowlight | 5 |
| njrat | 3 |
| SalatStealer | 3 |
| AgentTesla | 1 |
| QuasarRAT | 1 |
| AsyncRAT | 1 |
| ConnectWise | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| js | 36 |
| elf | 30 |
| exe | 18 |
| macho | 7 |
| ps1 | 3 |
| xlsx | 1 |
| hta | 1 |
| bat | 1 |
| php | 1 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `7cf99107e71b500b`

| Field | Value |
|---|---|
| SHA-256 | `7cf99107e71b500bf13f6795f0188af9e74aa8ac1a49de30ea4324c09db7ec25` |
| Family label | `unknown` |
| File name | `imp` |
| File type | `elf` |
| First seen | `2026-11-19 07:35:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f6875c8ed8fab2c278f479d8f33c98d` |
| SHA-1 | `708882cd0b0cfc6c7fbc17ec15e820f3ed02b4f7` |
| SHA-256 | `7cf99107e71b500bf13f6795f0188af9e74aa8ac1a49de30ea4324c09db7ec25` |
| SHA3-384 | `7fc1aa54d6c4ef120a05ff5a11b3bd2e6e273d5d10150e01cf49b800a8f1b14da223d2b216865b939fc2b468c2a0eef9` |
| TLSH | `T13FF63947ECA606A9C0EEC2318576A1677B327C4A4B7023D71B50F6742F73BD0AAB9354` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:B7WGLJT3OJadviLwtK2bcUBzrheHuYkgslqbi6kFDFvcHzmOUxgjwE0:MGMU/KXxHsh6kFDFDKjJ0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_7cf99107
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cf99107e71b500bf13f6795f0188af9e74aa8ac1a49de30ea4324c09db7ec25"
    family = "unknown"
    file_name = "imp"
    file_type = "elf"
    first_seen = "2026-11-19 07:35:09"
  condition:
    hash.sha256(0, filesize) == "7cf99107e71b500bf13f6795f0188af9e74aa8ac1a49de30ea4324c09db7ec25"
}
```

### Sample 2: `2b9ff957accb416c`

| Field | Value |
|---|---|
| SHA-256 | `2b9ff957accb416c7e02242beec810c49e0374c665e8ff313d220551ca49803b` |
| Family label | `Mirai` |
| File name | `bot_x86_64_c` |
| File type | `elf` |
| First seen | `2026-11-19 07:28:14` |
| Reporter | `RogueBoulder3285` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3838aefecc2d8d8e4539082ade27751` |
| SHA-1 | `659c93d1665fe11cbff3a02e7feb9ed4b0fa9635` |
| SHA-256 | `2b9ff957accb416c7e02242beec810c49e0374c665e8ff313d220551ca49803b` |
| SHA3-384 | `39d8e0eb18b2e93ac7a6d7a28197b8806f1be20a15cc5040157017df01e79a8772de3033460b1863c77faff590eec709` |
| TLSH | `T10B456B5AF2B3B1ACD107C03457DBCAB16531B07526322DBB67C4CA352EB6DE41369B22` |
| SSDEEP | `24576:QvZc8qDuieDq0ILs6VNW/fZNLztv5UvnobtMeJm8CtfOKuXp:Ps6VNW55thUvnQtMeJm8GfOK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_2b9ff957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b9ff957accb416c7e02242beec810c49e0374c665e8ff313d220551ca49803b"
    family = "Mirai"
    file_name = "bot_x86_64_c"
    file_type = "elf"
    first_seen = "2026-11-19 07:28:14"
  condition:
    hash.sha256(0, filesize) == "2b9ff957accb416c7e02242beec810c49e0374c665e8ff313d220551ca49803b"
}
```

### Sample 3: `4dc746b1e61b8f77`

| Field | Value |
|---|---|
| SHA-256 | `4dc746b1e61b8f7749500863736a95c938e49c9087a53ab6d5eaf4c7ede06fcc` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-19 07:07:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7130b6e2c35bef804c10c03cf245f101` |
| SHA-1 | `f125c30e2a4465be92ba1af436f99ebc08d66038` |
| SHA-256 | `4dc746b1e61b8f7749500863736a95c938e49c9087a53ab6d5eaf4c7ede06fcc` |
| SHA3-384 | `dd7f46c27b3a93db4a4b1ad13bf3b74dfbde0ccb42d71ac88972ee881cd921f0cedeaf04154c56bf10bed74d034d8ec3` |
| TLSH | `T1D4556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSt:SDjxB4m5n8XlaPWi+d+a4TjxQP4L` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_003_4dc746b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dc746b1e61b8f7749500863736a95c938e49c9087a53ab6d5eaf4c7ede06fcc"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 07:07:06"
  condition:
    hash.sha256(0, filesize) == "4dc746b1e61b8f7749500863736a95c938e49c9087a53ab6d5eaf4c7ede06fcc"
}
```

### Sample 4: `5be19a8baf8b0483`

| Field | Value |
|---|---|
| SHA-256 | `5be19a8baf8b04839546e12448049ee9320578edea8eecf381a4c537793af5ee` |
| Family label | `unknown` |
| File name | `ultima quotazione per il 2026.js` |
| File type | `js` |
| First seen | `2026-11-19 07:04:41` |
| Reporter | `JAMESWT_WT` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79d6b1ef40ab2a3ff9a16df30def8c6a` |
| SHA-1 | `aafd77fbdd456ca6864cffb12e1528f35a0f0b3b` |
| SHA-256 | `5be19a8baf8b04839546e12448049ee9320578edea8eecf381a4c537793af5ee` |
| SHA3-384 | `a740cf25a39b9520e4e527825370e998f08b3ff1ba7efe04195abd614310e3c950b3ed87f8906ad223b43a1886d54c47` |
| TLSH | `T176535B68DA4319B74F836B88ACDD4A11C9B88315C4264160F2DEC74DA505EECEBBC6DF` |
| SSDEEP | `1536:m442OQWmyqZjfiFbKIB6rl0feOyBkk9MgOYaOIPuD6d0wfb:moQm6bKIB6rl0feOskk9lO3sWdZfb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_5be19a8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5be19a8baf8b04839546e12448049ee9320578edea8eecf381a4c537793af5ee"
    family = "unknown"
    file_name = "ultima quotazione per il 2026.js"
    file_type = "js"
    first_seen = "2026-11-19 07:04:41"
  condition:
    hash.sha256(0, filesize) == "5be19a8baf8b04839546e12448049ee9320578edea8eecf381a4c537793af5ee"
}
```

### Sample 5: `c8727e4087a5bb4f`

| Field | Value |
|---|---|
| SHA-256 | `c8727e4087a5bb4f94fc9919aa03279d9ea14ca8fe1b236d4f1d962fcdee55d1` |
| Family label | `unknown` |
| File name | `agent` |
| File type | `elf` |
| First seen | `2026-11-19 07:04:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57bc4e6ad2e9665febb7a0288d5f3470` |
| SHA-1 | `231fd9080153122ea7b55452f85a68550ac44a6e` |
| SHA-256 | `c8727e4087a5bb4f94fc9919aa03279d9ea14ca8fe1b236d4f1d962fcdee55d1` |
| SHA3-384 | `57fe709ea70c42ff84d343e99854aa25b80243cc0d0a18ad3b2ea9f03fd85b4e8424885bbda0beb482da5e60f2007aec` |
| TLSH | `T1DF665A53EC9515E9C0AED1318A62A213BB727C495F3123D32F90F6293F72BD0A9B9750` |
| TELFHASH | `t1b93269754abc7574b696d910b3a2b4f496372ca572f838b15063e994ffc1e801ce283b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:rREK2pttT/DxLNAU/bqmBIr4yYLY50LvLjUffdRngyyDYFFTL97vhRMPOWXxlq6Q:rRQprTdlTRlyguRFjMPOWeh6i09EXEq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_c8727e40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8727e4087a5bb4f94fc9919aa03279d9ea14ca8fe1b236d4f1d962fcdee55d1"
    family = "unknown"
    file_name = "agent"
    file_type = "elf"
    first_seen = "2026-11-19 07:04:06"
  condition:
    hash.sha256(0, filesize) == "c8727e4087a5bb4f94fc9919aa03279d9ea14ca8fe1b236d4f1d962fcdee55d1"
}
```

### Sample 6: `cae07077d58b6f81`

| Field | Value |
|---|---|
| SHA-256 | `cae07077d58b6f810b5e4e711081b38dde12aa1438b4d4e26db975e96f100f29` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2040d4d22d42cc4c7dfe18ca90baa13d` |
| SHA-1 | `c295b1f20bf486afc560d652a3b2a34c2ecd616a` |
| SHA-256 | `cae07077d58b6f810b5e4e711081b38dde12aa1438b4d4e26db975e96f100f29` |
| SHA3-384 | `2d6f032b824cca5699505f4c3b91eb872b4236cfba21a30204ac7126a5a68749a6be8f864ef2b577937f081e299f5f90` |
| TLSH | `T105C3E91E7E218FEEF259C27007F38A31569477962AA2D685E26CE6501F213CD2C1FF64` |
| TELFHASH | `t1c331fe329731411a5e52cc64dcee57f1281d86172b48ee33ee36c9cc241a499e62bc4f` |
| SSDEEP | `1536:xk8NZJjWAa/PUcve4meOeuCyTPHvwIp/read7Q1Qs/Rd/ue+dhfLod0UvXP/:JZJjBa/czhHvlp/o1F/P+3LodTvXP/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_cae07077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae07077d58b6f810b5e4e711081b38dde12aa1438b4d4e26db975e96f100f29"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:24"
  condition:
    hash.sha256(0, filesize) == "cae07077d58b6f810b5e4e711081b38dde12aa1438b4d4e26db975e96f100f29"
}
```

### Sample 7: `ed1647c515ff06df`

| Field | Value |
|---|---|
| SHA-256 | `ed1647c515ff06dfb8fd08a292794cd327930a6d040c38e5d270240390e2dfc7` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1ef54df08eebb113bdbb4d5858712c2` |
| SHA-1 | `625b3a8a765da60ce4df931b50f075c3fc0bea8c` |
| SHA-256 | `ed1647c515ff06dfb8fd08a292794cd327930a6d040c38e5d270240390e2dfc7` |
| SHA3-384 | `586feb9d7c44cd5086de1e41065daa1bbdfa8da9ba18a86b4c486ae74cd2ede4e05a5f2e9a6482a23f9bf6ffb77619c6` |
| TLSH | `T1A4C31901A9528A53C0C2177ABA9F41593723BB78D3DB3311DA14BFB42F476DF0E2A652` |
| TELFHASH | `t1ea31ff325731411a6e52cc60dcee57f1251d86272744ee33ef36c9cc651a49ae627c4f` |
| SSDEEP | `3072:NwP0km+Urrar8+wG3if7zKeYw1Ljme3WwF:NwP++U3aDVc7zKu1LjCwF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_ed1647c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1647c515ff06dfb8fd08a292794cd327930a6d040c38e5d270240390e2dfc7"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:21"
  condition:
    hash.sha256(0, filesize) == "ed1647c515ff06dfb8fd08a292794cd327930a6d040c38e5d270240390e2dfc7"
}
```

### Sample 8: `c22fbb6b05ee296a`

| Field | Value |
|---|---|
| SHA-256 | `c22fbb6b05ee296a7546bfe5f1fcc682e54036dc1e2dc2d4905ab4dd58c4e922` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66f7252ce7c31b7e3b11bd51ca7c00db` |
| SHA-1 | `6b7a6b3e112dde04108ba4534825a6c088ea2f2b` |
| SHA-256 | `c22fbb6b05ee296a7546bfe5f1fcc682e54036dc1e2dc2d4905ab4dd58c4e922` |
| SHA3-384 | `ca9736bfad0ab7bfda7dba46d1a2edcbf99288ed49632035bd2c8a6c1de7a7c10e004a5050fa8385fc372dfa4ca19a3d` |
| TLSH | `T157A31901BD818B63C1C227BAB7DF46593B21B76487EB3302A9157FB42F4769E0E27611` |
| TELFHASH | `t1c331fe329731411a5e52cc64dcee57f1281d86172b48ee33ee36c9cc241a499e62bc4f` |
| SSDEEP | `3072:VGBBa5og1w+8kayA7LOTr+34meQkl7R2/:VGOP1wNHyA7Lj3neQkl7R2/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_c22fbb6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c22fbb6b05ee296a7546bfe5f1fcc682e54036dc1e2dc2d4905ab4dd58c4e922"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:18"
  condition:
    hash.sha256(0, filesize) == "c22fbb6b05ee296a7546bfe5f1fcc682e54036dc1e2dc2d4905ab4dd58c4e922"
}
```

### Sample 9: `c1ea954eb146a364`

| Field | Value |
|---|---|
| SHA-256 | `c1ea954eb146a3647c8146da35ea0d5e0eb6725f23c25d1455365b17e635e1b4` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ffcb38518f287b03404248ea1536e84` |
| SHA-1 | `a09ae65ebc060bbc6e44895d38a3ca8c498ac4ac` |
| SHA-256 | `c1ea954eb146a3647c8146da35ea0d5e0eb6725f23c25d1455365b17e635e1b4` |
| SHA3-384 | `73afffeb13a43f6b83f929439933ce7450792675fa4768b6506266f87eb1cf0ed2cd573994edda867cba1d00b7bcd3ac` |
| TLSH | `T13C833923A9659F57C1821BF826E38A740B53FC154F130FBAA76DE9F815039ECB909361` |
| TELFHASH | `t1a531fe329731411a5e52cc64dcee57f1341d86172708ee33ee36c9cc641a499e62bc4f` |
| SSDEEP | `1536:aaDwtqKcomlIFZCXaZMYfPkYPmgpK2mP5A/iabC0c/v38Bs/n8ah3wHTBLC3SJU/:awacomlITCXaZMYXkYegQ2mgiabgXMlu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_c1ea954e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ea954eb146a3647c8146da35ea0d5e0eb6725f23c25d1455365b17e635e1b4"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:16"
  condition:
    hash.sha256(0, filesize) == "c1ea954eb146a3647c8146da35ea0d5e0eb6725f23c25d1455365b17e635e1b4"
}
```

### Sample 10: `fdd78118194450b9`

| Field | Value |
|---|---|
| SHA-256 | `fdd78118194450b9080a12d5def51f3e83e89fd40514e1d2a720764566d801e4` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8b5234a181c48b502c8e0cfa188e745` |
| SHA-1 | `d4d4a32a195cfa40138d7ba2fa89230f89a56fed` |
| SHA-256 | `fdd78118194450b9080a12d5def51f3e83e89fd40514e1d2a720764566d801e4` |
| SHA3-384 | `b6c5af77c531fc013a3c566b3c4f5e51b4d442b7ea0b6c9f3595ec7c4897e1e58171d29ec506ce5dae215a993b871db3` |
| TLSH | `T151A33A93B405EE7EF40ED6B604D34B25B670F7614E530B25B31BBEA3AA322D43816B41` |
| TELFHASH | `t15931dc329731411a5e52cc64dcee57f5381d86172b48ee73ee3ac9cc241a499e62bc4f` |
| SSDEEP | `3072:e5GTHxYRyRqwazPQta6Q9VXXz4FmA7u7xzjmUCjL/:RVPQ9VHzKu7xjmUCjL/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_fdd78118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd78118194450b9080a12d5def51f3e83e89fd40514e1d2a720764566d801e4"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:13"
  condition:
    hash.sha256(0, filesize) == "fdd78118194450b9080a12d5def51f3e83e89fd40514e1d2a720764566d801e4"
}
```

### Sample 11: `ba7e96e1b87b4568`

| Field | Value |
|---|---|
| SHA-256 | `ba7e96e1b87b45681a1967db43ec70db0debb24830fa8c60d115ef3ab3e483bb` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1013de71ee609a208626c8e2ac232da6` |
| SHA-1 | `4dbab65ab364003be5fa2308838f1912560e0083` |
| SHA-256 | `ba7e96e1b87b45681a1967db43ec70db0debb24830fa8c60d115ef3ab3e483bb` |
| SHA3-384 | `d3bb493e2f03f7b0d8d5143dfccf0da7145e87e761f948ccb3e6697a5e262b8df48b02c53356fb2317ea787ad2322984` |
| TLSH | `T1F7E32C46E6814B13C0D2177ABADF42453323A764D3DB73059928BFB43F8679E0E63605` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:U+Ug1WIx0UEaK0U4560zSlzhXRzM9hO3+keLUM/9g2JCVF:U+UDIxLEaK0U456xl9RI9c3+ZgM/9d8T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_ba7e96e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba7e96e1b87b45681a1967db43ec70db0debb24830fa8c60d115ef3ab3e483bb"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:11"
  condition:
    hash.sha256(0, filesize) == "ba7e96e1b87b45681a1967db43ec70db0debb24830fa8c60d115ef3ab3e483bb"
}
```

### Sample 12: `a7b523609fe8cc5c`

| Field | Value |
|---|---|
| SHA-256 | `a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da3fad5f724ace7be770f5cd49bf85e1` |
| SHA-1 | `c4ed8ba686804e1f4b0b6af7c99f2cb094b932dd` |
| SHA-256 | `a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76` |
| SHA3-384 | `5877f43d77fbd8b02f28e16e420451e6765d1b8c48c70fb53dad99a045ba2e8b57f511f20cb095ec4fffdb2fe0b003cc` |
| TLSH | `T181B32B01BD418B53C1D217BAB7DF46993B21776487EB3302A9297FB02F8369E1E27251` |
| TELFHASH | `t1c331fe329731411a5e52cc64dcee57f1281d86172b48ee33ee36c9cc241a499e62bc4f` |
| SSDEEP | `3072:P6dS6E0grAMNb+AApL5iHtgg5AnHNQP4wo+/:P6cPrAWCAApLgAnHNQP4wo+/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_a7b52360
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:08"
  condition:
    hash.sha256(0, filesize) == "a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76"
}
```

### Sample 13: `ef8aef100bc59ae5`

| Field | Value |
|---|---|
| SHA-256 | `ef8aef100bc59ae54ad24034132851fb6e0ba3e176156836b3378e0bad609e14` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-11-19 05:57:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `251a5c65335fb732b9ad3a46e8033578` |
| SHA-1 | `51f15fb5dd10e2ec6a7aa9db224c7274164996cd` |
| SHA-256 | `ef8aef100bc59ae54ad24034132851fb6e0ba3e176156836b3378e0bad609e14` |
| SHA3-384 | `3268b8c9a02d7add1f36dd126d74397f6004d41eb05747750f5dc9bc43c9a59d40c5638855184faa860258806403597a` |
| TLSH | `T17CC3F907BB554FF7C85BCE770AEB0711248DA91B26B52B367534EC78B60B18E19E3920` |
| TELFHASH | `t1c331fe329731411a5e52cc64dcee57f1281d86172b48ee33ee36c9cc241a499e62bc4f` |
| SSDEEP | `1536:kvGefaZSdtmo4/xl4ExO29zyN0ZNhdZp54crFCZeLs/h5JcSod0UvXP/:kOefaZSdc59zm0Hr6eoJ3odTvXP/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_ef8aef10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef8aef100bc59ae54ad24034132851fb6e0ba3e176156836b3378e0bad609e14"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:05"
  condition:
    hash.sha256(0, filesize) == "ef8aef100bc59ae54ad24034132851fb6e0ba3e176156836b3378e0bad609e14"
}
```

### Sample 14: `b81a1219f96873b4`

| Field | Value |
|---|---|
| SHA-256 | `b81a1219f96873b46cdb16a555b6fd7f657826fd7b2bbd1f7de68ee1ed1100d7` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-19 05:50:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7434e67d8c6a2dc6d7d0dfe68a302b05` |
| SHA-1 | `9591ee5745e35f55f8387cb67a99a09b7d8d34f8` |
| SHA-256 | `b81a1219f96873b46cdb16a555b6fd7f657826fd7b2bbd1f7de68ee1ed1100d7` |
| SHA3-384 | `03c7df362bed4ecf63a2b287dd5d3f701aea341d6fcea3e9c27f26b21787f44a2949dc66d61beb2ffb9b7479495ab1f7` |
| TLSH | `T158556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSK:SDjxB4m5n8XlaPWi+d+a4TjxQP4M` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_014_b81a1219
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81a1219f96873b46cdb16a555b6fd7f657826fd7b2bbd1f7de68ee1ed1100d7"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:50:05"
  condition:
    hash.sha256(0, filesize) == "b81a1219f96873b46cdb16a555b6fd7f657826fd7b2bbd1f7de68ee1ed1100d7"
}
```

### Sample 15: `529d1019d1d9dec8`

| Field | Value |
|---|---|
| SHA-256 | `529d1019d1d9dec858bfd8916ccab9c69e706ae978c8cdb2f8dfa827fa710147` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-19 05:42:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70650e7445c44ace625cf534263a79f6` |
| SHA-1 | `d8bd697126472f287ab410065b4ea8512e7f19b7` |
| SHA-256 | `529d1019d1d9dec858bfd8916ccab9c69e706ae978c8cdb2f8dfa827fa710147` |
| SHA3-384 | `80d5b4b750b167547d5a333593e61b7422c7d453af699446a7a1e9e5e9a61e42fb673651beec2ee87cb1a3a20b0c239a` |
| TLSH | `T141556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSz:SDjxB4m5n8XlaPWi+d+a4TjxQP4R` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_015_529d1019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "529d1019d1d9dec858bfd8916ccab9c69e706ae978c8cdb2f8dfa827fa710147"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:42:06"
  condition:
    hash.sha256(0, filesize) == "529d1019d1d9dec858bfd8916ccab9c69e706ae978c8cdb2f8dfa827fa710147"
}
```

### Sample 16: `fb2ea3bb6714a538`

| Field | Value |
|---|---|
| SHA-256 | `fb2ea3bb6714a5383b792c66e331bf85232d59e3a123b310a68634a90383c361` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-19 05:29:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adc72e0db98ae45b1e3087ef6a0c0a82` |
| SHA-1 | `b7a20a9331e0839cfdf59eebc8f898a38727b003` |
| SHA-256 | `fb2ea3bb6714a5383b792c66e331bf85232d59e3a123b310a68634a90383c361` |
| SHA3-384 | `e05089723e636e23047cff4ac1ed77d94c78a9562259e7713c6e080629d976fc4f3d076de0633cfa8a407ccd8a77b7b8` |
| TLSH | `T193556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSH:SDjxB4m5n8XlaPWi+d+a4TjxQP49` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_016_fb2ea3bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb2ea3bb6714a5383b792c66e331bf85232d59e3a123b310a68634a90383c361"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:29:06"
  condition:
    hash.sha256(0, filesize) == "fb2ea3bb6714a5383b792c66e331bf85232d59e3a123b310a68634a90383c361"
}
```

### Sample 17: `55a8952055a69b2e`

| Field | Value |
|---|---|
| SHA-256 | `55a8952055a69b2e916a61182443b8398547df2870b1dbe4e8668bf89897aac4` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Exploit.CVE-2017-0199.04.Gen.95874282` |
| File type | `xlsx` |
| First seen | `2026-11-19 05:23:17` |
| Reporter | `SecuriteInfoCom` |
| Tags | `xlsx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f967ab76f5713233b9b0c4224320a88` |
| SHA-1 | `382a8f70ebc03452b45051ed335465fd662863eb` |
| SHA-256 | `55a8952055a69b2e916a61182443b8398547df2870b1dbe4e8668bf89897aac4` |
| SHA3-384 | `a58d9e1000b1fc6c4d5ec6e3c12a3902b503583583599e083570bcf5cf7066b4722391ec9d36d6838d3bcd408a460519` |
| TLSH | `T166A3DF1E7212D85FCA69C83ECDD8C6E31A167C609D12E60B3481B72E1E750D3AB1B76D` |
| SSDEEP | `1536:NIgIEZtQnFUQB3q43X6gqH6soQJgP1L+al+VIYxTZQpW0ShFgFOYo+:N7IEZtQn5B93XgVMlzYxKpW0SQFO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xlsx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_55a89520
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a8952055a69b2e916a61182443b8398547df2870b1dbe4e8668bf89897aac4"
    family = "unknown"
    file_name = "SecuriteInfo.com.Exploit.CVE-2017-0199.04.Gen.95874282"
    file_type = "xlsx"
    first_seen = "2026-11-19 05:23:17"
  condition:
    hash.sha256(0, filesize) == "55a8952055a69b2e916a61182443b8398547df2870b1dbe4e8668bf89897aac4"
}
```

### Sample 18: `5d55a50b777e1ef7`

| Field | Value |
|---|---|
| SHA-256 | `5d55a50b777e1ef766c5420c0f4681cdc9c32e4b232a0262feff34d7634b1196` |
| Family label | `unknown` |
| File name | `paymentcopynov.hta` |
| File type | `hta` |
| First seen | `2026-11-19 05:20:13` |
| Reporter | `ni_fi_70` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c0dcda6420bbe011093f862576a9d3d` |
| SHA-1 | `7ff9f5a3c8d0a401ce7d87138a0ca31086792ba6` |
| SHA-256 | `5d55a50b777e1ef766c5420c0f4681cdc9c32e4b232a0262feff34d7634b1196` |
| SHA3-384 | `6d7de6fb1634171012b8d6695a70babe120f87f40c95ce7dfc3d87862526049c2d616fcecf3897c72b3e41c5bc707905` |
| TLSH | `T17E8282C95288D7E44559348B2E703BA4F79E4E6DD2274AC0399CAACC3E6EE14793370C` |
| SSDEEP | `384:bwiQfO/4KS/iQfO/4KS/iQfO/4KSH6MMrC5KiQfO/4KS/iQfO/4KS/iQfO/4KSN:bw+/4N/+/4N/+/4N+9+/4N/+/4N/+/43` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_5d55a50b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d55a50b777e1ef766c5420c0f4681cdc9c32e4b232a0262feff34d7634b1196"
    family = "unknown"
    file_name = "paymentcopynov.hta"
    file_type = "hta"
    first_seen = "2026-11-19 05:20:13"
  condition:
    hash.sha256(0, filesize) == "5d55a50b777e1ef766c5420c0f4681cdc9c32e4b232a0262feff34d7634b1196"
}
```

### Sample 19: `8f911ed9e53cd961`

| Field | Value |
|---|---|
| SHA-256 | `8f911ed9e53cd9614328eff3e9193bb5b412ad2384828e3173b58917071f20d5` |
| Family label | `unknown` |
| File name | `RequestforQuotationUAEU56942026ClosingBudget.js` |
| File type | `js` |
| First seen | `2026-11-19 05:20:10` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `236e6064c8c0cd00d0fe1e9233888d14` |
| SHA-1 | `5cc1f6541cbfc90378a88caeeea56cf76842d565` |
| SHA-256 | `8f911ed9e53cd9614328eff3e9193bb5b412ad2384828e3173b58917071f20d5` |
| SHA3-384 | `e5a2af8154d4d4de923219afd1a7e5143b3cad11850ca80b02f9eb05619380092424789b0376e42389fc09d00b845d9d` |
| TLSH | `T135B4131ED2C007F6C972573CD46FF03A90A3EE9586468B1B907945EA78A88F58F1364F` |
| SSDEEP | `6144:X2KQ2i1xl949Mu31N481gsHX6wTWm2eCW6GogXk7D0Vfg:dQ2i1xly12CNKV5qxCwi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_8f911ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f911ed9e53cd9614328eff3e9193bb5b412ad2384828e3173b58917071f20d5"
    family = "unknown"
    file_name = "RequestforQuotationUAEU56942026ClosingBudget.js"
    file_type = "js"
    first_seen = "2026-11-19 05:20:10"
  condition:
    hash.sha256(0, filesize) == "8f911ed9e53cd9614328eff3e9193bb5b412ad2384828e3173b58917071f20d5"
}
```

### Sample 20: `fac84a16fb7dc254`

| Field | Value |
|---|---|
| SHA-256 | `fac84a16fb7dc254ea370cb0784d86fc126944114b2f759ca6d205ba52b4e175` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-19 05:18:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f15a0694e24a71a7ef82a6f2620c0f54` |
| SHA-1 | `97c03915f2a83e0c057165be0289ccd1f9b63832` |
| SHA-256 | `fac84a16fb7dc254ea370cb0784d86fc126944114b2f759ca6d205ba52b4e175` |
| SHA3-384 | `aced48dee7184eaffc8474ed7d7f5b0ef041312245cea1647c5f561c3d4092e95803e0d131124a2c3477f4649a160b50` |
| TLSH | `T10D556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSP:SDjxB4m5n8XlaPWi+d+a4TjxQP4d` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_020_fac84a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fac84a16fb7dc254ea370cb0784d86fc126944114b2f759ca6d205ba52b4e175"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:18:06"
  condition:
    hash.sha256(0, filesize) == "fac84a16fb7dc254ea370cb0784d86fc126944114b2f759ca6d205ba52b4e175"
}
```

### Sample 21: `125dcd78f6327589`

| Field | Value |
|---|---|
| SHA-256 | `125dcd78f6327589e6dc65956fc27972ba2878bddf682230e27b109eff709283` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-19 05:16:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55073309224a64d8e0cd93ed18b73dba` |
| SHA-1 | `ce2824fc98f4b8319a6124b85bdc1eb732eb5a5a` |
| SHA-256 | `125dcd78f6327589e6dc65956fc27972ba2878bddf682230e27b109eff709283` |
| SHA3-384 | `839cde176142d7d6eec9bcd9f7c6bef17e4518939678d7cdee3851c19611d4e6e3c0df1738514fac5401b5f73d85ffdf` |
| TLSH | `T1F2556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSg:SDjxB4m5n8XlaPWi+d+a4TjxQP4i` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_021_125dcd78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "125dcd78f6327589e6dc65956fc27972ba2878bddf682230e27b109eff709283"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:16:05"
  condition:
    hash.sha256(0, filesize) == "125dcd78f6327589e6dc65956fc27972ba2878bddf682230e27b109eff709283"
}
```

### Sample 22: `e820baa54b34439f`

| Field | Value |
|---|---|
| SHA-256 | `e820baa54b34439fcdf9a492fc081b528dd3124c0f2be4d3696256f26db64a23` |
| Family label | `njrat` |
| File name | `2f11fc190f26038a0f24a69b2625eafc.exe` |
| File type | `exe` |
| First seen | `2026-11-19 05:10:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f11fc190f26038a0f24a69b2625eafc` |
| SHA-1 | `305cd29fb555df14d7c6ccf66a004036749f270e` |
| SHA-256 | `e820baa54b34439fcdf9a492fc081b528dd3124c0f2be4d3696256f26db64a23` |
| SHA3-384 | `baac0c232f527e4ca24778f70ae6e21222b3b06ad06d7ff069afbad5f9289e03cb88ccc758bfea7ad017361e76c0fa2f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T179B2C449B7B58714D2AF4A7848A3230446B1F3C7E980DBA74DE6008A1F17BD56912FEE` |
| SSDEEP | `384:zW6RDShUSla9XMNzh4/ph8xmHlaOWQ+dcs//34LAZSThKM2eRmFWNzuC:S6RShUqa9XkzU+cNWQuHqjKNC` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_022_e820baa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e820baa54b34439fcdf9a492fc081b528dd3124c0f2be4d3696256f26db64a23"
    family = "njrat"
    file_name = "2f11fc190f26038a0f24a69b2625eafc.exe"
    file_type = "exe"
    first_seen = "2026-11-19 05:10:06"
  condition:
    hash.sha256(0, filesize) == "e820baa54b34439fcdf9a492fc081b528dd3124c0f2be4d3696256f26db64a23"
}
```

### Sample 23: `3dec8ea7364b2df6`

| Field | Value |
|---|---|
| SHA-256 | `3dec8ea7364b2df6cb3e36f020457e0c8343978942d039aa2182599d98d0ae95` |
| Family label | `unknown` |
| File name | `3dec8ea7364b2df6.bin` |
| File type | `bat` |
| First seen | `2026-11-19 04:24:06` |
| Reporter | `Tuxxin` |
| Tags | `bat, powershell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9bc37f5c2e63bd530ee141ee554f9ba` |
| SHA-1 | `7918aec94a9b8e52e01e903767380e397ef1d9dd` |
| SHA-256 | `3dec8ea7364b2df6cb3e36f020457e0c8343978942d039aa2182599d98d0ae95` |
| SHA3-384 | `66b2575d369dbccc6d3a9c4a84336847964b92451ab17895c78451d4626dd6d741c3a7f9a8b4b0a7661ebc40d205b462` |
| TLSH | `T168D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdz3:Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_3dec8ea7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dec8ea7364b2df6cb3e36f020457e0c8343978942d039aa2182599d98d0ae95"
    family = "unknown"
    file_name = "3dec8ea7364b2df6.bin"
    file_type = "bat"
    first_seen = "2026-11-19 04:24:06"
  condition:
    hash.sha256(0, filesize) == "3dec8ea7364b2df6cb3e36f020457e0c8343978942d039aa2182599d98d0ae95"
}
```

### Sample 24: `c8f1f293ecaa0e83`

| Field | Value |
|---|---|
| SHA-256 | `c8f1f293ecaa0e83dd1d6421291ef834b39ad3b6cabf857c6e0c1920592a0a7f` |
| Family label | `unknown` |
| File name | `c8f1f293ecaa0e83.js` |
| File type | `js` |
| First seen | `2026-11-19 04:23:21` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cea610197f0fcbfd2a6e867b3666d82` |
| SHA-1 | `dab7cf8f642ad57d4f71e2a024426849ccb54092` |
| SHA-256 | `c8f1f293ecaa0e83dd1d6421291ef834b39ad3b6cabf857c6e0c1920592a0a7f` |
| SHA3-384 | `f4f3aac1bd6220bc4c35b4d5d5434ee6d2da5bcfe978761b69959f758aae4e769eeb58fc98556c5e107f42b7f015051e` |
| TLSH | `T1C2722AF97765216A03633532203F9102E277EB114D4BA050A2D68A817DBDFABD677FC8` |
| SSDEEP | `384:D/NxweEliOgRPIayJqnTTg9PipOQ7AGnhzwWKQNcDM:jEeQiOQIaCqnTTgMpJ7AGnhzwdicDM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_c8f1f293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8f1f293ecaa0e83dd1d6421291ef834b39ad3b6cabf857c6e0c1920592a0a7f"
    family = "unknown"
    file_name = "c8f1f293ecaa0e83.js"
    file_type = "js"
    first_seen = "2026-11-19 04:23:21"
  condition:
    hash.sha256(0, filesize) == "c8f1f293ecaa0e83dd1d6421291ef834b39ad3b6cabf857c6e0c1920592a0a7f"
}
```

### Sample 25: `b3b53bfe99f03ec7`

| Field | Value |
|---|---|
| SHA-256 | `b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189` |
| Family label | `unknown` |
| File name | `b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189.bin` |
| File type | `php` |
| First seen | `2026-11-19 04:22:03` |
| Reporter | `Tuxxin` |
| Tags | `php` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2059ebe96b6ace3dcf5b08e6b36cef56` |
| SHA-1 | `5dd9f18d1bad7ee472efb8db7459037e7cf3c7b2` |
| SHA-256 | `b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189` |
| SHA3-384 | `08f6f21956b80de004aca58fdf7b6b4c49f93320524cbbeef8f929deda78649aa98c49f92cbdf07062f5165756992b2b` |
| TLSH | `T106E25DB130A950BA9017D3EA222F775D397310A3D351C1C5BEFD4BA09BC1D6B5E269C8` |
| SSDEEP | `768:reM0pv7jMmal2Ts1eM0p0d1MSmsmalW8m4:qZZwITtZWdfTI8m4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `php`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_b3b53bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189"
    family = "unknown"
    file_name = "b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189.bin"
    file_type = "php"
    first_seen = "2026-11-19 04:22:03"
  condition:
    hash.sha256(0, filesize) == "b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189"
}
```

### Sample 26: `c0bc825da4033991`

| Field | Value |
|---|---|
| SHA-256 | `c0bc825da4033991c16f320dffecf2f54ac2709123a02d5e983d40bb8908532f` |
| Family label | `unknown` |
| File name | `vlcplay1.exe` |
| File type | `exe` |
| First seen | `2026-11-19 04:08:04` |
| Reporter | `mboll_research` |
| Tags | `exe, Xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0266534dff122e3ec782ddb9036114dc` |
| SHA-1 | `d423e30c6af5388b9ea836d167fcf6d8444fb46a` |
| SHA-256 | `c0bc825da4033991c16f320dffecf2f54ac2709123a02d5e983d40bb8908532f` |
| SHA3-384 | `83d51ca52258a3137dc03c67714831e31af302db3577335f541f32c6fc8e6933326267a65a630c36cfcedce549f61a58` |
| IMPHASH | `76e8ce8cd61e94de1bd27451c661aa45` |
| TLSH | `T1FCA6E04AD8534AD3D4A6B23D417AD20576307C8CDB22CFE399647B3B0E7A2D49EB8744` |
| SSDEEP | `98304:QI548URzvyQM/Mmc/N7IIG7Vf6+TCqUjrcDXmS2f2ymaTGUp8:NemQMe/SLVfAqUQYqaTGUp8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_c0bc825d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0bc825da4033991c16f320dffecf2f54ac2709123a02d5e983d40bb8908532f"
    family = "unknown"
    file_name = "vlcplay1.exe"
    file_type = "exe"
    first_seen = "2026-11-19 04:08:04"
  condition:
    hash.sha256(0, filesize) == "c0bc825da4033991c16f320dffecf2f54ac2709123a02d5e983d40bb8908532f"
}
```

### Sample 27: `1aaeee024b71bf7f`

| Field | Value |
|---|---|
| SHA-256 | `1aaeee024b71bf7f93e50d5904aac4a50ba6f58972e8b8f6569b0b1637727e89` |
| Family label | `SalatStealer` |
| File name | `FortniteAssistant.exe` |
| File type | `exe` |
| First seen | `2026-11-19 03:58:12` |
| Reporter | `Alex_sev` |
| Tags | `exe, salat, salatstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17f92ae9db216e99b48ffbf15ef56583` |
| SHA-1 | `d0f233e6c416b9ef0d1173ef4b44d78fe22bc803` |
| SHA-256 | `1aaeee024b71bf7f93e50d5904aac4a50ba6f58972e8b8f6569b0b1637727e89` |
| SHA3-384 | `ba43c196904c9d927b62ea6a6c692539c1114f79371ab63cf1584926dc316f274018451167d8e9a9e6df1d62661bc4bd` |
| IMPHASH | `0e128fb4564e6ae226b4ff18f1d3dfb4` |
| TLSH | `T18F67E122BA53B374E40394354526907BE362E9183F35C6B3F98C766AB7737E809761C2` |
| SSDEEP | `98304:SAfp2iw3DkQX4xHB2Ny42lxX4IdUuI0CYpUHb4iu8yMq8hY0JxAJ:32OBB2NCxX4I+urCYp2bbGMj` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_027_1aaeee02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1aaeee024b71bf7f93e50d5904aac4a50ba6f58972e8b8f6569b0b1637727e89"
    family = "SalatStealer"
    file_name = "FortniteAssistant.exe"
    file_type = "exe"
    first_seen = "2026-11-19 03:58:12"
  condition:
    hash.sha256(0, filesize) == "1aaeee024b71bf7f93e50d5904aac4a50ba6f58972e8b8f6569b0b1637727e89"
}
```

### Sample 28: `bcff4d6f844904bf`

| Field | Value |
|---|---|
| SHA-256 | `bcff4d6f844904bfb791dec13aa62cae4be05ef0c4d49c693a9043ce63ce33b4` |
| Family label | `unknown` |
| File name | `Msi Utility v3.exe` |
| File type | `exe` |
| First seen | `2026-11-19 03:54:12` |
| Reporter | `Alex_sev` |
| Tags | `exe, salat, salatstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53b7829cbbc5bebe1aa5cf3d8761e728` |
| SHA-1 | `3a729b877a2e6939ce724d6dac236a0b2f202c6d` |
| SHA-256 | `bcff4d6f844904bfb791dec13aa62cae4be05ef0c4d49c693a9043ce63ce33b4` |
| SHA3-384 | `361d40aa6c2fe4b0f96b0a00f89e216da389c8fadcccc67a89e5a2ebb9ce1a9c71ad8f3b1fcbadbfd7afe0063679a215` |
| IMPHASH | `0e128fb4564e6ae226b4ff18f1d3dfb4` |
| TLSH | `T1DE76E122BA53B374E40394354526907BE362E9183F35C6B3F98C766AB7737E809761C2` |
| SSDEEP | `98304:SAfp2iw3DkQX4xHB2Ny42lxX4IdUuI0CYpUHb4iu8yMq8hY0JxAJ:32OBB2NCxX4I+urCYp2bbGMj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_bcff4d6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcff4d6f844904bfb791dec13aa62cae4be05ef0c4d49c693a9043ce63ce33b4"
    family = "unknown"
    file_name = "Msi Utility v3.exe"
    file_type = "exe"
    first_seen = "2026-11-19 03:54:12"
  condition:
    hash.sha256(0, filesize) == "bcff4d6f844904bfb791dec13aa62cae4be05ef0c4d49c693a9043ce63ce33b4"
}
```

### Sample 29: `9650cb8f47f20042`

| Field | Value |
|---|---|
| SHA-256 | `9650cb8f47f20042ba83f1e659c39bdc1b129220b37dab86f9e1b4bbc5bf0968` |
| Family label | `AgentTesla` |
| File name | `Copia para el remitente.JS` |
| File type | `js` |
| First seen | `2026-11-19 03:45:22` |
| Reporter | `nat` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f4481361378c9f0fcef1057ad853f5d` |
| SHA-1 | `0cd40080dd76e719b9744e5ad20f36a2dec567af` |
| SHA-256 | `9650cb8f47f20042ba83f1e659c39bdc1b129220b37dab86f9e1b4bbc5bf0968` |
| SHA3-384 | `ba0e0cd5450e04c5a3269dcfec8da8e29d31a4cee41b95908af1e055e3af39f0e7c110e152dc153a6b431023047f0ccd` |
| TLSH | `T16906B2B12784B132772EABAC45369930958A700329C6CB37317DF259B65CD1BA3DCAD3` |
| SSDEEP | `98304:BVXQsTTDKMfHJRmQbiwVyBPJw82PYzTNesZ/UIosY7ikCQN8jj5mL:BVXQsTTDKMfHJRmQbiquw82DsZ/UeY7Z` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_029_9650cb8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9650cb8f47f20042ba83f1e659c39bdc1b129220b37dab86f9e1b4bbc5bf0968"
    family = "AgentTesla"
    file_name = "Copia para el remitente.JS"
    file_type = "js"
    first_seen = "2026-11-19 03:45:22"
  condition:
    hash.sha256(0, filesize) == "9650cb8f47f20042ba83f1e659c39bdc1b129220b37dab86f9e1b4bbc5bf0968"
}
```

### Sample 30: `0a27062fa52737bf`

| Field | Value |
|---|---|
| SHA-256 | `0a27062fa52737bf62edbbb800793545a27f154f8f10d4a05251ad8365910251` |
| Family label | `njrat` |
| File name | `21b5998aa4e57bf9b9423948eda2a039.exe` |
| File type | `exe` |
| First seen | `2026-11-19 03:45:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21b5998aa4e57bf9b9423948eda2a039` |
| SHA-1 | `fa321e76a3c6be323c58bd5943619da02d4396ba` |
| SHA-256 | `0a27062fa52737bf62edbbb800793545a27f154f8f10d4a05251ad8365910251` |
| SHA3-384 | `65818de824a235a8c57969cee118426ef5528e182d5fd441170ac2159ace89ee133981047c1e7c55725fd244506e08f9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E4A2194EB7688619D3AD1A7409B3632487B1F68BC541DF4B0CDA10DE2F636D05642BFD` |
| SSDEEP | `384:rWW6yUSlSXMa/MQTmKBJYqhwYmHUaOWQ+dcs//34LAZST7BO:rn6yUqSXf/MQTmKzirkWQuHqDO` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_030_0a27062f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a27062fa52737bf62edbbb800793545a27f154f8f10d4a05251ad8365910251"
    family = "njrat"
    file_name = "21b5998aa4e57bf9b9423948eda2a039.exe"
    file_type = "exe"
    first_seen = "2026-11-19 03:45:06"
  condition:
    hash.sha256(0, filesize) == "0a27062fa52737bf62edbbb800793545a27f154f8f10d4a05251ad8365910251"
}
```

### Sample 31: `9d21cf8b5c3416a0`

| Field | Value |
|---|---|
| SHA-256 | `9d21cf8b5c3416a01bfcc7caab84b10f8de3eba88229e2fcd358d0970b6742b2` |
| Family label | `unknown` |
| File name | `9d21cf8b5c3416a0.ps1` |
| File type | `ps1` |
| First seen | `2026-11-19 03:43:03` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82bbca59295b01a0008f93f094e87d18` |
| SHA-1 | `85a2a040fe74ab121981d235453a8bc1b71e16be` |
| SHA-256 | `9d21cf8b5c3416a01bfcc7caab84b10f8de3eba88229e2fcd358d0970b6742b2` |
| SHA3-384 | `2084b3b6bda049b58deb7211762f44f40a403b764e1edbf6f3229ef1643ac667c8fd092573ef5a5151b98217e5447dbc` |
| TLSH | `T1E452DBB1666EEFC0087EC76B9319D24B736E1C2096DE09DC5E458CD32D93303E85E9A8` |
| SSDEEP | `384:cpOZZh7y0WSonMA7OwuI5m5dNmLycjh4MkQy:oO5qP7OzI50dQd+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_9d21cf8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d21cf8b5c3416a01bfcc7caab84b10f8de3eba88229e2fcd358d0970b6742b2"
    family = "unknown"
    file_name = "9d21cf8b5c3416a0.ps1"
    file_type = "ps1"
    first_seen = "2026-11-19 03:43:03"
  condition:
    hash.sha256(0, filesize) == "9d21cf8b5c3416a01bfcc7caab84b10f8de3eba88229e2fcd358d0970b6742b2"
}
```

### Sample 32: `ebd0a96a159bdd16`

| Field | Value |
|---|---|
| SHA-256 | `ebd0a96a159bdd1628373228f1c7f67645315ffd5374d1caf6f4f7a7ffed3b21` |
| Family label | `unknown` |
| File name | `ebd0a96a159bdd16.js` |
| File type | `js` |
| First seen | `2026-11-19 03:33:05` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acc8c220c24f6966b1d0d51e175dcacc` |
| SHA-1 | `9d5ce8f7bde95f2aa4d5589c64645920ef92e0d8` |
| SHA-256 | `ebd0a96a159bdd1628373228f1c7f67645315ffd5374d1caf6f4f7a7ffed3b21` |
| SHA3-384 | `3e8b7bf58024fa5af6d2ccfbbea9c32f33502931731d7f7a6ccf08dbeafbba35186c4dee36f122e02497681f14b18912` |
| TLSH | `T1262385185EB705868333B26F9F5FE408257AB513B088E8587E4CD7205FCA495E987F9C` |
| SSDEEP | `768:5gWDbsgrjB29ePPmdVyjPAvK42a5wgDzE6VUEDiAwom5FtnMDxWnT6qdzoH:dbsgr929ePP0VyzAvKm5RVUEDiAwom5s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_ebd0a96a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd0a96a159bdd1628373228f1c7f67645315ffd5374d1caf6f4f7a7ffed3b21"
    family = "unknown"
    file_name = "ebd0a96a159bdd16.js"
    file_type = "js"
    first_seen = "2026-11-19 03:33:05"
  condition:
    hash.sha256(0, filesize) == "ebd0a96a159bdd1628373228f1c7f67645315ffd5374d1caf6f4f7a7ffed3b21"
}
```

### Sample 33: `05e2208e78605e63`

| Field | Value |
|---|---|
| SHA-256 | `05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953` |
| Family label | `unknown` |
| File name | `05e2208e78605e63.ps1` |
| File type | `ps1` |
| First seen | `2026-11-19 03:23:01` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edacbf0bcb934145cb1793a0898bfa4e` |
| SHA-1 | `02df082e302114f240742aa5bda443f0b65fb17b` |
| SHA-256 | `05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953` |
| SHA3-384 | `a6eeea8351923492e044ee493f5291eb2cbb1517f8d2b4bcaba5205e5dfeeb4db795ad4fd0aa4b0aebc482610d6178da` |
| TLSH | `T11BC46D347A022DFF4BB820C244D6811C563C36B9DA682DF56ACF4CA3291D77627B79B4` |
| SSDEEP | `6144:51iapsPZcrnKK3yGLDAkzIteDsTvtxg54h4t2tfcLJy7ZWy3uL81X9V:51nsPZcrnKK37AkUuUtu5a/FcLJUum` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_05e2208e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953"
    family = "unknown"
    file_name = "05e2208e78605e63.ps1"
    file_type = "ps1"
    first_seen = "2026-11-19 03:23:01"
  condition:
    hash.sha256(0, filesize) == "05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953"
}
```

### Sample 34: `945a796f7d6353f0`

| Field | Value |
|---|---|
| SHA-256 | `945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb` |
| Family label | `unknown` |
| File name | `945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb.bin` |
| File type | `js` |
| First seen | `2026-11-19 03:09:16` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `248607c3739de6d32f49bb514a817a5f` |
| SHA-1 | `b3c7291864b0bb32a58d830496230f306057e6b5` |
| SHA-256 | `945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb` |
| SHA3-384 | `b43dc0b1a123cd72c9434fd9aaa45c888c8c641b44f85d6063fdf31005841d7e54079fc41346bf03799cc4b6164ab734` |
| TLSH | `T199920799CF9B6D5C4B3AE42336DD89D50AAF03CE50E115EE71AFC39827F8C0568C52A4` |
| SSDEEP | `384:B5z/TRMs5nKh7jZM1Zeb+3LEdBT/LU8MqVcY3XcU:BhTRMs5nKh7jZM1ZK+3LCJ/48fx3Xf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_945a796f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb"
    family = "unknown"
    file_name = "945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb.bin"
    file_type = "js"
    first_seen = "2026-11-19 03:09:16"
  condition:
    hash.sha256(0, filesize) == "945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb"
}
```

### Sample 35: `748c78602755a47e`

| Field | Value |
|---|---|
| SHA-256 | `748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9` |
| Family label | `unknown` |
| File name | `748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9.bin` |
| File type | `ps1` |
| First seen | `2026-11-19 03:07:03` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c9e464af2517a04084023f1484a0b2e` |
| SHA-1 | `74483942bf93113a6fda81133788e473608ce5a2` |
| SHA-256 | `748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9` |
| SHA3-384 | `a67f656926ae0137206c1f37d4ce78f9659da6c7ef74b2ad7b9316d3cc14846977e732334ddceb2abc3fd1e0827cb045` |
| TLSH | `T13C340924A8893471598392BE4DEDE004F572416F518C1DD07BEC8588DFC26BD86BAAFF` |
| SSDEEP | `3072:nPxxANotv9gU1AS5EktTTySeKlvcL4+IGhHwzRJ7ytaOEUe7U1C+VvUHKzoJoJeJ:XySeKlvcLy/ORetaM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_748c7860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9"
    family = "unknown"
    file_name = "748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9.bin"
    file_type = "ps1"
    first_seen = "2026-11-19 03:07:03"
  condition:
    hash.sha256(0, filesize) == "748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9"
}
```

### Sample 36: `59cb95a9315ca3ac`

| Field | Value |
|---|---|
| SHA-256 | `59cb95a9315ca3aca32667acb48aa21be0b88f552d9032cacb64129d64067c4a` |
| Family label | `unknown` |
| File name | `59cb95a9315ca3ac.js` |
| File type | `js` |
| First seen | `2026-11-19 03:03:09` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96d055d50447fc247652e8f4ca040379` |
| SHA-1 | `9eb674437fcef28f4861f57d123e5174d5656324` |
| SHA-256 | `59cb95a9315ca3aca32667acb48aa21be0b88f552d9032cacb64129d64067c4a` |
| SHA3-384 | `fba5aac6e39979f3dbebd9c48b6884ec07d570d6eb64604eb5da1d03ec2425c17dacf4382f44bbdbb4a5e2504e710c28` |
| TLSH | `T13EE5A603A1D138A605D35EB6792750CAEC2D8BAFA18CA7B5B44DF834B8F1154E6EC770` |
| SSDEEP | `49152:Vm6PtZsfWIHQc9GELR0mMeRAsTfI4Lftk/R5kqd+usYDGNcd:b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_59cb95a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59cb95a9315ca3aca32667acb48aa21be0b88f552d9032cacb64129d64067c4a"
    family = "unknown"
    file_name = "59cb95a9315ca3ac.js"
    file_type = "js"
    first_seen = "2026-11-19 03:03:09"
  condition:
    hash.sha256(0, filesize) == "59cb95a9315ca3aca32667acb48aa21be0b88f552d9032cacb64129d64067c4a"
}
```

### Sample 37: `7e748bc2fbdc4700`

| Field | Value |
|---|---|
| SHA-256 | `7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026` |
| Family label | `unknown` |
| File name | `7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:49:00` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a63aa0a43dcb8cf77d10baf70a79227b` |
| SHA-1 | `8f36f60a40fc36fa727fb048585818f34444b58a` |
| SHA-256 | `7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026` |
| SHA3-384 | `9fdfa9b06f2bf945f638737310d2c79e061e280b8c2dbf64330f9778a31c819b91cd62a34ba57771a5abc1de41909f43` |
| TLSH | `T15182E696CF973C5C8B6AD92724EE8DD51A8F07CDA0F210EE706F83D867B8C1158C9295` |
| SSDEEP | `384:i5zjPlaIATSOSrMfYLd8gibzjDTPJgEx7UPoGfBKeCcAL:iFFt+tg+UPvfBKeC7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_7e748bc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026"
    family = "unknown"
    file_name = "7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:49:00"
  condition:
    hash.sha256(0, filesize) == "7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026"
}
```

### Sample 38: `9fbb31129c04e8eb`

| Field | Value |
|---|---|
| SHA-256 | `9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6` |
| Family label | `unknown` |
| File name | `9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:47:40` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `742230bf301de0ca755307099c11a1ae` |
| SHA-1 | `40d5e4cfc185a44b68b6613feebf18a28f15c0a3` |
| SHA-256 | `9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6` |
| SHA3-384 | `8c70071948e5172c2407394a778ebeafbe053f14f9e2cae2b99e558578db1517bba601526e62e7474fb18d32817037e2` |
| TLSH | `T1CA120EA05379ADBA82315A44CC34BE0DE1B4DCA56D4BD02AF82F3C89DF7A1D0879166C` |
| SSDEEP | `192:DcKuFMN8pLgQI1QrUILWPur6vAFhTjz20iXBhRhyialyGZhXFyvFy2roTM79M5rv:D4YCWOPpixbC4mh1yNJrFSb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_9fbb3112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6"
    family = "unknown"
    file_name = "9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:40"
  condition:
    hash.sha256(0, filesize) == "9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6"
}
```

### Sample 39: `6250fc1ab5eab3cb`

| Field | Value |
|---|---|
| SHA-256 | `6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d` |
| Family label | `unknown` |
| File name | `6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:47:35` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbb3a4a30c2db814a35455dce40eee1e` |
| SHA-1 | `0093e4ba91777078ca3022e81741257ce7b6f1b3` |
| SHA-256 | `6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d` |
| SHA3-384 | `52c48c1da98ac3d10ff5fca94af424fc9eb94cf6db9b5c721a36966bfc2f2cbfb52f7ec9f2c74dcd28755ac936e19e46` |
| TLSH | `T19DE23284A7D0A440034B6ABBBB1BF4E5E96A0CAC75844ACBF11DBD84F766327E4F1531` |
| SSDEEP | `768:lS6fjj3KYLOtF3cWsw0hJXpnn6QKN9F/NP1sI3kDP2MyKZDTBbqRe4mBPFlNBGjv:c6rjHLQN6LgHGHj+V5qGW+Ja2x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_6250fc1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d"
    family = "unknown"
    file_name = "6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:35"
  condition:
    hash.sha256(0, filesize) == "6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d"
}
```

### Sample 40: `389f3b3a223bbf18`

| Field | Value |
|---|---|
| SHA-256 | `389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712` |
| Family label | `unknown` |
| File name | `389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:47:32` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `382514b2532dd8b314fd5465186f46c1` |
| SHA-1 | `cdef071a5031c3ad2533306c9f7ca0d9c7d6623b` |
| SHA-256 | `389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712` |
| SHA3-384 | `01b2494adb3001786e69395d10ac33319ba749f18d11a13ecafe68f0b11503d721d924842a5ed77f0a0c6b4808ba7318` |
| TLSH | `T1D60351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:dAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:gr/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_389f3b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712"
    family = "unknown"
    file_name = "389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:32"
  condition:
    hash.sha256(0, filesize) == "389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712"
}
```

### Sample 41: `9e286f7a54f071e5`

| Field | Value |
|---|---|
| SHA-256 | `9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba` |
| Family label | `unknown` |
| File name | `9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:47:28` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95f0e2bc99c27f6315a74836b62c2368` |
| SHA-1 | `3db0fb1726091fd534abd656a2c2c9f356984bf4` |
| SHA-256 | `9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba` |
| SHA3-384 | `3a6e76ef74f1b166fa2e0dbbfadaf095712c88f01e742554a3bbc34955dec141908cc9706dc80bb79fe79be7fb4e5391` |
| TLSH | `T19EE25382BFC4B59113475BBFB61B70C4D26B199A7584048FF21CB8A4F7E6226E5F1A30` |
| SSDEEP | `768:yTXp2DFSIDkGjmvq/U2JQYliSjR3fFmnhavg/7Ti5MpbI9EYojkZhpzQkMNZPYKn:+2D5fWYbuPfOgiE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_9e286f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba"
    family = "unknown"
    file_name = "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:28"
  condition:
    hash.sha256(0, filesize) == "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba"
}
```

### Sample 42: `0a472a13fd265f26`

| Field | Value |
|---|---|
| SHA-256 | `0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2` |
| Family label | `unknown` |
| File name | `0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:45:11` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c9549c58a88b5b8783adb3974307bb5` |
| SHA-1 | `6f7bf7641607a7835f50d23a414418456f274303` |
| SHA-256 | `0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2` |
| SHA3-384 | `bffc2caa22a4fe60b9673e676a17edfaf74f1b30c273bedb449333dd2bf1483bb128ca48164b930acd9fc86aa52bac2b` |
| TLSH | `T1F8E286813BC064666343AABBBA1BF1D4E65B0CB93A8D488BF614FC44F561627D7F1930` |
| SSDEEP | `768:KZv10pkjlkpKiBns126OxGIoQPIRWXNPP9D5MA1lsUrI6gqyleP1ure9fUIq08Pk:81ApDfeyzuqU2WNi3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_0a472a13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2"
    family = "unknown"
    file_name = "0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:45:11"
  condition:
    hash.sha256(0, filesize) == "0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2"
}
```

### Sample 43: `d8e36eb4d58085a8`

| Field | Value |
|---|---|
| SHA-256 | `d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11` |
| Family label | `unknown` |
| File name | `d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:45:04` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbf7e1988cc5488a5022c59eaba72857` |
| SHA-1 | `8f453cb21264e7f8ad3a25ca636888e4cfdff112` |
| SHA-256 | `d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11` |
| SHA3-384 | `4d6e6b7eb907c12ab79502c7ebbe5dd98eeb9f68ed287c7775fb7cf3c027edc959eafcb5fb92c2ea52b4f4a397b09ec7` |
| TLSH | `T11D82E6A5CFAB2C4C4B6AD42739DE8DC51A9F03CE60A210EFB05FC3D55BB48155DC92A4` |
| SSDEEP | `384:v5zdeMFunobV+GN2zCDrN5iKAfPw1U65TNe8:vXewuqV+W2zEJbWw195pe8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_d8e36eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11"
    family = "unknown"
    file_name = "d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:45:04"
  condition:
    hash.sha256(0, filesize) == "d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11"
}
```

### Sample 44: `584a2ce0aeb4bc50`

| Field | Value |
|---|---|
| SHA-256 | `584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486` |
| Family label | `unknown` |
| File name | `584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:44:58` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `620e6ee65c87a16de7b3a3005e4261ec` |
| SHA-1 | `f87e57bd6f16cc9789a4e6fe99c87473753785e8` |
| SHA-256 | `584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486` |
| SHA3-384 | `df0a8971c9bd31e857b44850501b426ff5427af12daa31081771bcc77b7980be77991bc4c32e84b9cb070b7cc759fe25` |
| TLSH | `T1DCA22AA6CE977C1C0B66E92725DD89E50E9F03CDA0E111EEB15FD3D867B8C0158C9368` |
| SSDEEP | `384:c25z/TRMs5nKh2bFhpUzfGqRU+FSv7y4ua7FCob4bNcz6eT5rK2:zhTRMs5nKh25U6tlTuobSczJT5l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_584a2ce0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486"
    family = "unknown"
    file_name = "584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:58"
  condition:
    hash.sha256(0, filesize) == "584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486"
}
```

### Sample 45: `e2d35f05df843340`

| Field | Value |
|---|---|
| SHA-256 | `e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b` |
| Family label | `unknown` |
| File name | `e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:44:10` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b6210a3a49a5a0c3fdf5a40a398ec9f` |
| SHA-1 | `554ff1e2e17f2fea34201ab1cc876655c771b16a` |
| SHA-256 | `e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b` |
| SHA3-384 | `868f59c6184781a44d484ec3e68d77143cbc7dd22c31f2636e9751acf331634b50ed304b7e5e5e55714cb1afa9bc64e6` |
| TLSH | `T188F1E7E071B263B883A553ECD42D0410D23AC57BBC0F4871F22C9D877D695666A73E6D` |
| SSDEEP | `192:CM1M55ca+n2cXf0UaRdEf8/yfM5/ef+JRbFjLBZSXZ3Ap4bX4hW+CErSjvItL3o9:CM1U7+n2mG8f8KfMVefgJjL3SBXIpCXL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_e2d35f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b"
    family = "unknown"
    file_name = "e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:10"
  condition:
    hash.sha256(0, filesize) == "e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b"
}
```

### Sample 46: `c71c96fcaa21d84e`

| Field | Value |
|---|---|
| SHA-256 | `c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be` |
| Family label | `unknown` |
| File name | `c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:44:06` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1e72380498573ba3d7c5b721d30ab1f` |
| SHA-1 | `4cf38d9b3ba1cc49554444eaa97aa8a780bc0d24` |
| SHA-256 | `c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be` |
| SHA3-384 | `d5c79d8aafe655015cb209d659aecba60ff83a557bd6928f25e35aac9ab821e1f27f7213d3c01ee8641a608b4c3c71d9` |
| TLSH | `T14EA22AA6CE977C1C0B66E92725DD89E50E9F03CDA0E111EEB15FD3D867B8C0158C9368` |
| SSDEEP | `384:M25z/TRMs5nKh2bFhpUzfGqRU+FSv7y4ua7FCob4bNcz6eT5rK2:jhTRMs5nKh25U6tlTuobSczJT5l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_c71c96fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be"
    family = "unknown"
    file_name = "c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:06"
  condition:
    hash.sha256(0, filesize) == "c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be"
}
```

### Sample 47: `bca8d45805ba486e`

| Field | Value |
|---|---|
| SHA-256 | `bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524` |
| Family label | `unknown` |
| File name | `bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:44:01` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b292df46ef4ea826c0d41114979dc195` |
| SHA-1 | `5f83ae94c95301572c8e6fcc656d083e690a9c7d` |
| SHA-256 | `bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524` |
| SHA3-384 | `abccd69b85b3e02a30cddd2caa6fefef45d11ec0cc99326d78c444c6ad0f7740562f693d0c0a2afee07384255d461ae7` |
| TLSH | `T1D60351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:EAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:br/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_bca8d458
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524"
    family = "unknown"
    file_name = "bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:01"
  condition:
    hash.sha256(0, filesize) == "bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524"
}
```

### Sample 48: `011f6842382c4d4f`

| Field | Value |
|---|---|
| SHA-256 | `011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5` |
| Family label | `unknown` |
| File name | `011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:43:57` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bf1cf2dcc31d65be7e68db4befa4898` |
| SHA-1 | `c1824d0f551e22930555980b8cd14d05ad5c879f` |
| SHA-256 | `011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5` |
| SHA3-384 | `0a90284638faf04533aba8707916efd99c4941d971806089be9e420624abc26b99b533aa2e5d86f248170a6ac40dd869` |
| TLSH | `T14AF1E7E071B263B883A553ECD42D0410D23AC57BBC0F4871F22C9D877D695666A73E6D` |
| SSDEEP | `192:QM1M55ca+n2cXf0UaRdEf8/yfM5/ef+JRbFjLBZSXZ3Ap4bX4hW+CErSjvItL3o9:QM1U7+n2mG8f8KfMVefgJjL3SBXIpCXL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_011f6842
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5"
    family = "unknown"
    file_name = "011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:43:57"
  condition:
    hash.sha256(0, filesize) == "011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5"
}
```

### Sample 49: `533e995069ae094d`

| Field | Value |
|---|---|
| SHA-256 | `533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380` |
| Family label | `unknown` |
| File name | `533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:43:52` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d18b8bc130a58eedd9dbf061958a46b5` |
| SHA-1 | `68d64c20053880bdccd1668fadd400d3a3a52e36` |
| SHA-256 | `533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380` |
| SHA3-384 | `63f80bd5af87c9233d812036fb1ef51b7e17e3b379289b45a782ebb10201982141bb885b4c84581b810963f78223eac7` |
| TLSH | `T15142DCD853C7D4576BCC2C93EE144983713681BB778572C3B31CBE492BAA0C7C5AA989` |
| SSDEEP | `384:O/yBfFPXgiSRwNxNbaNCh86g0CkjqACCDJdHzi/rYHP9ZlobTuA6onTzD5XLFdpY:O/yBfFPfSRwNxNbaNCokeACSJdMr+P9B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_533e9950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380"
    family = "unknown"
    file_name = "533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:43:52"
  condition:
    hash.sha256(0, filesize) == "533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380"
}
```

### Sample 50: `95affaf9b4bb187b`

| Field | Value |
|---|---|
| SHA-256 | `95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850` |
| Family label | `unknown` |
| File name | `95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:37:16` |
| Reporter | `Tuxxin` |
| Tags | `js, script` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d43d0a16164e65b9653ecf0a8976d301` |
| SHA-1 | `d2c228051549acd977736642952abe0d93beb4b6` |
| SHA-256 | `95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850` |
| SHA3-384 | `ace067010fe39f144ad9cdbb6e188aef86a4987b9319a82324e92617e807d931ab1ceb130fd90675ae548080ec41dfbf` |
| TLSH | `T16B9308DDB3D2B06257AB30BD006F540FB236195A280D8850F12DD8E6BD74A4DA277FAD` |
| SSDEEP | `1536:Z4mCgi8DyCuXXFiJ+L0kJQsJVPEKLQRZdC/RAfDknv+p0WzH/Io9Z7qABZnu0sFT:ZGsKXAI2p0WP9bDrstfaHs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_95affaf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850"
    family = "unknown"
    file_name = "95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:37:16"
  condition:
    hash.sha256(0, filesize) == "95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850"
}
```

### Sample 51: `e4980b40d5ee4e3c`

| Field | Value |
|---|---|
| SHA-256 | `e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043` |
| Family label | `unknown` |
| File name | `e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:37:10` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `297ddd523c3151afd741da224e87f468` |
| SHA-1 | `2c6315d7d4da642e7c7080146939b0c9f42aea92` |
| SHA-256 | `e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043` |
| SHA3-384 | `02b8850e13d8f9862d3df1d912edcc06088cd1ddb75875f48e6c0af8c0cbebd5b26da433522e36106fadfc87b7ee7ed4` |
| TLSH | `T1549319DD73D2B02257AB30BD106F540FF2361959280D8950F268D8F9BC78A4AA277F6D` |
| SSDEEP | `1536:dnu00HWWaRxkqJg09pYxoxDKcXJrg8hXXO4dK3kyfiLJBhdSZE+I+QQ7rbaN1RUj:ddkWgoBhcZRQQmW42qg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_e4980b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043"
    family = "unknown"
    file_name = "e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:37:10"
  condition:
    hash.sha256(0, filesize) == "e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043"
}
```

### Sample 52: `c2ef57bd9005e60d`

| Field | Value |
|---|---|
| SHA-256 | `c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b` |
| Family label | `unknown` |
| File name | `c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:33:50` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcf5ece2bb03dc6cda1d64ac183cec5b` |
| SHA-1 | `465fc496710698d3a3a197aeafda4f2430f68e16` |
| SHA-256 | `c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b` |
| SHA3-384 | `dfc6e184e040ca7d81516d9a76fdab4bb8783387f0089eb56436f1fcfea9467b4fc9d8f36ccae46506e17037a5af8fa9` |
| TLSH | `T1E90351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:SAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:tr/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_c2ef57bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b"
    family = "unknown"
    file_name = "c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:33:50"
  condition:
    hash.sha256(0, filesize) == "c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b"
}
```

### Sample 53: `3f469d9c8b974224`

| Field | Value |
|---|---|
| SHA-256 | `3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a` |
| Family label | `unknown` |
| File name | `3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:30:02` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa67f2103d7cc6c7d02205b5b54ecd38` |
| SHA-1 | `c559890182cdbec9e546630e735817b56716674c` |
| SHA-256 | `3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a` |
| SHA3-384 | `61a8e6e9f41dfd920b755e50a976a86fbaec7f12cc7c9da3a4feb840ecbd1c5c96c3e4fa4119ab10ab6518b57d0957a0` |
| TLSH | `T1ED0351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:PAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:2r/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_3f469d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a"
    family = "unknown"
    file_name = "3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:30:02"
  condition:
    hash.sha256(0, filesize) == "3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a"
}
```

### Sample 54: `2dbd5b55987e3a79`

| Field | Value |
|---|---|
| SHA-256 | `2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4` |
| Family label | `unknown` |
| File name | `2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:29:58` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20a63066b5ccc179614ecf1fea60fa7c` |
| SHA-1 | `4b0ce467183c390c4f2dc4086a91a57a26958456` |
| SHA-256 | `2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4` |
| SHA3-384 | `97431160fb0ce69ee90fe997b09f2802fba72ab926ac31638d8fe1a4bf31ee19eef1749a762c584addf2f0f996534b57` |
| TLSH | `T187A22AA6CE977C1C0B66E92725DD89E50E9F03CDA0E111EEB15FD3D867B8C0158C9368` |
| SSDEEP | `384:k25z/TRMs5nKh2bFhpUzfGqRU+FSv7y4ua7FCob4bNcz6eT5rK2:LhTRMs5nKh25U6tlTuobSczJT5l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_2dbd5b55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4"
    family = "unknown"
    file_name = "2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:29:58"
  condition:
    hash.sha256(0, filesize) == "2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4"
}
```

### Sample 55: `810bd7539ab96bce`

| Field | Value |
|---|---|
| SHA-256 | `810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1` |
| Family label | `unknown` |
| File name | `810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:29:54` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ee2b6fbf58eef374ec4c6e0ba0bc404` |
| SHA-1 | `be581023b71139844121028ec9c8dc06c580c1c2` |
| SHA-256 | `810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1` |
| SHA3-384 | `125e2aedae2dd50e94e8b94f18c35a117d446d31e2a686cfe94dbe3a7d8681eb162dca7dddd095612781c0f004e92de3` |
| TLSH | `T171A22AAACE977C1C0B66E92725DD89E50E9F03CDA0E111EEB15FD3D867B8C0158C9368` |
| SSDEEP | `384:u25z/TRMs5nKh2bFhpUzfGqRU+FSv7y4ua7FCob4bNcz6eT5rK2:thTRMs5nKh25U6tlTuobSczJT5l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_810bd753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1"
    family = "unknown"
    file_name = "810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:29:54"
  condition:
    hash.sha256(0, filesize) == "810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1"
}
```

### Sample 56: `e2a4f5c098fef325`

| Field | Value |
|---|---|
| SHA-256 | `e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1` |
| Family label | `unknown` |
| File name | `e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:29:50` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b99d4c1bd971ac889a5b2e5e5376b5c6` |
| SHA-1 | `cf05381475ae5e8016ebeafb86d07b4121d9a88e` |
| SHA-256 | `e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1` |
| SHA3-384 | `9b94d7035e4fc50a1d70aa9b2688afd33e5d8af4e1f870977414977dc63ef02b71e053a1baaf7f83f7d8081d53d105cf` |
| TLSH | `T19E0351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:IAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:nr/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e2a4f5c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1"
    family = "unknown"
    file_name = "e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:29:50"
  condition:
    hash.sha256(0, filesize) == "e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1"
}
```

### Sample 57: `434f488ac3e12208`

| Field | Value |
|---|---|
| SHA-256 | `434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8` |
| Family label | `unknown` |
| File name | `434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:28:49` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b55078efc0cc038c5d87bb67b0fa762` |
| SHA-1 | `b0916cba3a095271c2083c40c1c97d27fff1584c` |
| SHA-256 | `434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8` |
| SHA3-384 | `e98578986ef073437fd7738eff65c7c90ae38c8501e20c1e9ee6e502201d2a273fe9eed6af6cd03a36761ebac89c6509` |
| TLSH | `T182A22AA6CE977C1C0B66E92725DD8AE50E9F03CDA0E111EEB15FD3D867B8C0158C9368` |
| SSDEEP | `384:M25z/TRMs5nKh2bFhpUzfGqRU+FSv7y4ua7FCob4bNcz6eT5rK2:jhTRMs5nKh25U6tlTuobSczJT5l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_434f488a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8"
    family = "unknown"
    file_name = "434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:28:49"
  condition:
    hash.sha256(0, filesize) == "434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8"
}
```

### Sample 58: `35ebd2d99c786e28`

| Field | Value |
|---|---|
| SHA-256 | `35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff` |
| Family label | `unknown` |
| File name | `35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:27:11` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c0bb8b53383333c3802fe1e84dd4f5a` |
| SHA-1 | `fd4045ea215f0256ae0fe44ccfa907fd4b667788` |
| SHA-256 | `35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff` |
| SHA3-384 | `98082476ec6bbdee7904a8f435f53a8e761e8efd4de698ef4137f0d5f8a2e8550c946c5aef40fbf81ccce3b595bd4e02` |
| TLSH | `T1AE0351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:nAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:er/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_35ebd2d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff"
    family = "unknown"
    file_name = "35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:27:11"
  condition:
    hash.sha256(0, filesize) == "35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff"
}
```

### Sample 59: `b61b4cd5cd1d0cf3`

| Field | Value |
|---|---|
| SHA-256 | `b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43` |
| Family label | `unknown` |
| File name | `b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:22:15` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0178bfe6cf7e64bcf40e62cc70342a87` |
| SHA-1 | `7d2f68d0cb80c368ddd6697fdc0c066d1dd0dba5` |
| SHA-256 | `b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43` |
| SHA3-384 | `90293518495c9f666839f48169513c6e99d2961879800cad250a75fd07c379772b6d27ebd3341b3c500829dcd9ac5a0e` |
| TLSH | `T10EE23284A7D0A440034B6ABBBB1BF4E5E96A0CAC75844ACBF11DBD84F766327E4F1531` |
| SSDEEP | `768:ZS6fjj3KYLOtF3cWsw0hJXpnn6QKN9F/NP1sI3kDP2MyKZDTBbqRe4mBPFlNBGjv:o6rjHLQN6LgHGHj+V5qGW+Ja2x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_b61b4cd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43"
    family = "unknown"
    file_name = "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:22:15"
  condition:
    hash.sha256(0, filesize) == "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43"
}
```

### Sample 60: `88f68396661b1191`

| Field | Value |
|---|---|
| SHA-256 | `88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626` |
| Family label | `unknown` |
| File name | `88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:22:11` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d8249b595f7ccbb2a871fe688b7c786` |
| SHA-1 | `d4119aa10ce206bc85faa5b3d142f5953aa69c1e` |
| SHA-256 | `88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626` |
| SHA3-384 | `dcf4d521fe535e4643a6233584fa8520730524a0d34eea7890f67fe0b837df5ed568a414b554335b6fb0e992faa44b88` |
| TLSH | `T1AF0351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:lAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:Yr/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_88f68396
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626"
    family = "unknown"
    file_name = "88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:22:11"
  condition:
    hash.sha256(0, filesize) == "88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626"
}
```

### Sample 61: `a5b81a1a98754d0f`

| Field | Value |
|---|---|
| SHA-256 | `a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41` |
| Family label | `unknown` |
| File name | `a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:22:07` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41e629c60f45771b2428d831b80412c6` |
| SHA-1 | `b8e90023a0126524597b2a129c46ec98d899b60b` |
| SHA-256 | `a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41` |
| SHA3-384 | `d6932786873dccd4312f19d5e6e7d0aae5524a33b0bb40ff93a821416ced9b06fc8cc8fbefb889fc7a932f8bcfa87a48` |
| TLSH | `T1460351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:7AnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:ar/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_a5b81a1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41"
    family = "unknown"
    file_name = "a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:22:07"
  condition:
    hash.sha256(0, filesize) == "a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41"
}
```

### Sample 62: `1d8e5258366efc42`

| Field | Value |
|---|---|
| SHA-256 | `1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5` |
| Family label | `unknown` |
| File name | `1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5` |
| File type | `exe` |
| First seen | `2026-11-19 02:15:11` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `861670da0c568ba12832a911a2d31acc` |
| SHA-1 | `7c543e9e9e7b2df868e7189ce778a8dc5141bd69` |
| SHA-256 | `1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5` |
| SHA3-384 | `7232a429ee1713a1b6e768470e561a0dc3d141a6c39f4e4fc080f492fb9aae2bae32fd045dbbfa656daa76eb1fe2da63` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T12D363394726CD1BCE1060AB444B38D26E7737C5557BF5B0F875086AB0E13B9BBB90B12` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8:DXDqPe1Cxcxk3ZAEUadzR8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_1d8e5258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5"
    family = "unknown"
    file_name = "1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5"
    file_type = "exe"
    first_seen = "2026-11-19 02:15:11"
  condition:
    hash.sha256(0, filesize) == "1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5"
}
```

### Sample 63: `a2e8e14e33734803`

| Field | Value |
|---|---|
| SHA-256 | `a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025` |
| Family label | `unknown` |
| File name | `a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025.bin` |
| File type | `js` |
| First seen | `2026-11-19 02:14:43` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcdec51c3ce6d024b0e5f8d5d401827b` |
| SHA-1 | `d5ef40ad8a74fec4bbce2f58feec4a6a58f5e4d6` |
| SHA-256 | `a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025` |
| SHA3-384 | `f87358da64aeaca7ce5c12542d3daf455e29a696836076c290c0fb1dfb5c783353bf1259a1a2a6eb5a4c6c3da00fc1f9` |
| TLSH | `T14393F8DDB3D1B06257AB30BD006F540FB236195D280D9850F129E8EABC74A4DA277FAD` |
| SSDEEP | `1536:q4mCgi8DyCuXXFiJ+L0kJQsJVPEKLQRZdC/RlfDknv+p0WzH/IoSZ7qABZnu0sFY:qGsKXlI2p0WPSbDrstfaJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_a2e8e14e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025"
    family = "unknown"
    file_name = "a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:14:43"
  condition:
    hash.sha256(0, filesize) == "a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025"
}
```

### Sample 64: `ba38e7dd33543cde`

| Field | Value |
|---|---|
| SHA-256 | `ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1` |
| Family label | `unknown` |
| File name | `cosmoLoader.exe` |
| File type | `exe` |
| First seen | `2026-11-19 02:14:00` |
| Reporter | `josie` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a5b16d14d5f7f8f7e130e5688ab79fd` |
| SHA-1 | `2da5e7a3e3339811483772ceee4b16357c7f5047` |
| SHA-256 | `ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1` |
| SHA3-384 | `af5716fb3eda70130efb8ab91415f877c82796d0a731fcdaddb54025b453e31235c74d5066d8b7aa063405e7a8a3bae6` |
| IMPHASH | `b40f185fa09153d3d6a39b926a7d9f17` |
| TLSH | `T167050102FAE187E9D03BC6788611453AE56A7C454F60A6FF07981B5F1E336E48E3EB14` |
| SSDEEP | `12288:NnGMz3Cb9wFARSLq2DhCjW1/TeUMsRi471i3wfRIMAAosmRLYUYYdahk5diOgx:pGMxF0+qWhC6/RfJfRIMAAJFYMk5oT` |
| ICON-DHASH | `8e7168d4d468718e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_ba38e7dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1"
    family = "unknown"
    file_name = "cosmoLoader.exe"
    file_type = "exe"
    first_seen = "2026-11-19 02:14:00"
  condition:
    hash.sha256(0, filesize) == "ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1"
}
```

### Sample 65: `af1b818c2fd2a5f5`

| Field | Value |
|---|---|
| SHA-256 | `af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc` |
| Family label | `Mirai` |
| File name | `af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc` |
| File type | `elf` |
| First seen | `2026-11-19 02:00:08` |
| Reporter | `beachcamp` |
| Tags | `arm, elf, honeypot, Mirai, ssh, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d62ba08388a85be17e08fa077c235cc` |
| SHA-1 | `158920cb833d0147a1ea5039fd887d11a140aa12` |
| SHA-256 | `af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc` |
| SHA3-384 | `256a75c78c3f8ce9b99a3f116bf4b75221859f74c482358dd06cba724a9c389019f1191ecae59d5875b4ccfe9171c8a0` |
| TLSH | `T179652A62F8828F66C6C04ABAFB1DC28C37135BB9D2ED70065614973577EBA960E3F111` |
| SSDEEP | `24576:DrkqDWxcDuYZ+cnO7tEQCNMKOLPGICB5bFpd+qShvk:RD+c81Cpd+qShs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_af1b818c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc"
    family = "Mirai"
    file_name = "af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc"
    file_type = "elf"
    first_seen = "2026-11-19 02:00:08"
  condition:
    hash.sha256(0, filesize) == "af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc"
}
```

### Sample 66: `53abf37710d6f2e3`

| Field | Value |
|---|---|
| SHA-256 | `53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8` |
| Family label | `unknown` |
| File name | `53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8.bin` |
| File type | `js` |
| First seen | `2026-11-19 01:59:29` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1f4ab46009ed505da50d23dbec4802c` |
| SHA-1 | `5870fbd577174138ff9909dcf64aa787c66e2c3e` |
| SHA-256 | `53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8` |
| SHA3-384 | `08c13b9d90db462743413cc101bf6929203b403bbd8ca65a2017f8b4e9db441d198bc8673c8ce9872ba707c38ac63d27` |
| TLSH | `T164B18D9068461B12434D199BAE4FC94A20E5ACD46D4BD4D2B28EF53CCFC898B2E35E79` |
| SSDEEP | `96:eDNCVMF9UPpwWKTy8enQeEX9yZ/UCG4rE8uyrCSvwmkDvvjhYKAePMVhJ2DV:dBB9Yy8GQeEYZ/rG3hDDhYKEVax` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_53abf377
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8"
    family = "unknown"
    file_name = "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8.bin"
    file_type = "js"
    first_seen = "2026-11-19 01:59:29"
  condition:
    hash.sha256(0, filesize) == "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8"
}
```

### Sample 67: `c0a8d6c39df2b219`

| Field | Value |
|---|---|
| SHA-256 | `c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce` |
| Family label | `unknown` |
| File name | `c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce.bin` |
| File type | `js` |
| First seen | `2026-11-19 01:52:03` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc4f7616fed2fefc90d85344f693f54c` |
| SHA-1 | `876171ef6c0549bcab8a2b15879a188079c6cda0` |
| SHA-256 | `c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce` |
| SHA3-384 | `5eacc2745707c186acdfde141399d6f0eebf9cffd5d0ac6a21a53de40aeccb8eafe1679f96064f529a765384e3b89af6` |
| TLSH | `T14D0351506AC07285134B6BF7B61BB0E9E11628DC3484485AF31DBC95F7A632BEEF1931` |
| SSDEEP | `768:fAnsGd8Y4vnNe9yZEG2ARCDu8AHm3Gall04grMTW8nsZhL0OT9kdB0EyOeRBq0ll:Gr/A4sK42qcbNJb6F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_c0a8d6c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce"
    family = "unknown"
    file_name = "c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce.bin"
    file_type = "js"
    first_seen = "2026-11-19 01:52:03"
  condition:
    hash.sha256(0, filesize) == "c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce"
}
```

### Sample 68: `b1645d539553b586`

| Field | Value |
|---|---|
| SHA-256 | `b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453` |
| Family label | `unknown` |
| File name | `b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453.bin` |
| File type | `js` |
| First seen | `2026-11-19 01:49:30` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f093441bf51435636e20a0c1e3b64a0` |
| SHA-1 | `b72599e8b775f8ff6513a7fadc172a7110aa65d9` |
| SHA-256 | `b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453` |
| SHA3-384 | `66d1691931f1065f3d5e271553ff2d948c1701f7d2cfc43123050b1749b5e3af5095276640404426e8f9bf39cac8d38e` |
| TLSH | `T1CBE286813BC064666343AABBBA1BF1D4E65B0CB93A8D488BF614FC44F561627D7F1930` |
| SSDEEP | `768:BZv10pkjlkpKiBns126OxGIoQPIRWXNPP9D5MA1lsUrI6gqyleP1ure9fUIq08Pk:D1ApDfeyzuqU2WNi3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_b1645d53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453"
    family = "unknown"
    file_name = "b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453.bin"
    file_type = "js"
    first_seen = "2026-11-19 01:49:30"
  condition:
    hash.sha256(0, filesize) == "b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453"
}
```

### Sample 69: `e364a0a9125468be`

| Field | Value |
|---|---|
| SHA-256 | `e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a` |
| Family label | `unknown` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-11-19 01:41:40` |
| Reporter | `pickledrick` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f94534d13af79be9a68ea62b889ce55c` |
| SHA-1 | `48ab499c83e31860bcfda28ae376b6f56073fb3a` |
| SHA-256 | `e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a` |
| SHA3-384 | `3d201c5a047c5a0268bd830f78164aad2f797752d7d46ebf86897e909c8c3f1e98ee0f8ba2097309102063d0394c609e` |
| TLSH | `T1BC7733F7CAFCE4428E334835AADDD93716B22664CF8C692A241334A056157F643ACED7` |
| SSDEEP | `786432:be96gje3sSf6pTCOuHFGoILkQYluLFK5y4tMKialJ6ByVFnXi9GZ:beUWiCpWOkGoIA9uLdKwqFXiUZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_e364a0a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a"
    family = "unknown"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-11-19 01:41:40"
  condition:
    hash.sha256(0, filesize) == "e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a"
}
```

### Sample 70: `5975cc213128bdd9`

| Field | Value |
|---|---|
| SHA-256 | `5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20` |
| Family label | `njrat` |
| File name | `1bf0c7c5732e63f87c6b2b21ee774ce4.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:40:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bf0c7c5732e63f87c6b2b21ee774ce4` |
| SHA-1 | `bf340d6ad39c63b96a90560366a6ef0602f9f845` |
| SHA-256 | `5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20` |
| SHA3-384 | `6bcc36872e5b44f53aa35faee8e06e0dd833eccc96b44d1e958cab81fe32384175998bb09962b167286e34f4c6943a12` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T172A2074977648619C3AD1A7848E3A32447B1F2CBD941DF5B0CEA10CE2F23BD16652AFD` |
| SSDEEP | `384:NW6WUSljXM8NUZGUByhyQmH+OaOWQ+dcs//34LAZSTvIj:M6WUqjX5GusDeCWQuHqqj` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_070_5975cc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20"
    family = "njrat"
    file_name = "1bf0c7c5732e63f87c6b2b21ee774ce4.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:40:06"
  condition:
    hash.sha256(0, filesize) == "5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20"
}
```

### Sample 71: `fd7cdd39be318780`

| Field | Value |
|---|---|
| SHA-256 | `fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a` |
| Family label | `Snowlight` |
| File name | `fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:29:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0912f77d5eb891fe9285a371a3945607` |
| SHA-1 | `07790fc3a59680d7a58c4433d1a9cd17c6728d4b` |
| SHA-256 | `fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a` |
| SHA3-384 | `871b3242777bbdd698aae77adcc00a9e7507620c55179c9472520b5baada258bf17afe4a3ffaaba5f1817bf6c598d203` |
| TLSH | `T19EE16207E2D5CE72D8CD133846931749213AC86EAB83AF03650C599AEE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFFk146Pwz7cSym4S2ofahbpZiQ:fsue7cSwJIFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_071_fd7cdd39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a"
    family = "Snowlight"
    file_name = "fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:29:19"
  condition:
    hash.sha256(0, filesize) == "fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a"
}
```

### Sample 72: `572db981cf481bb0`

| Field | Value |
|---|---|
| SHA-256 | `572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e` |
| Family label | `QuasarRAT` |
| File name | `572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:29:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `657c9de17b3900035abc4e4caea42a6d` |
| SHA-1 | `df9a6a123d7a45fa0666cc1fd315cc72f0a0aa8a` |
| SHA-256 | `572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e` |
| SHA3-384 | `0c6e352ab95d4c96c66b1026a65a5ba9e4e84c117541ca9f68dccc6e7dec521971627d60397f9d6af16de7faa8da6510` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C0E54B1437F95E33E16BD672D9B0501667F0F82AF363EB1B614267BA1C53B408C42AA7` |
| SSDEEP | `49152:3vDlL26AaNeWgPhlmVqvMQ7XSK9+i2ea+ZoGdmTHHB72eh2NT:3v5L26AaNeWgPhlmVqkQ7XSK9n2eaa` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_072_572db981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e"
    family = "QuasarRAT"
    file_name = "572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:29:14"
  condition:
    hash.sha256(0, filesize) == "572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e"
}
```

### Sample 73: `817cccc82f116d10`

| Field | Value |
|---|---|
| SHA-256 | `817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524` |
| Family label | `AsyncRAT` |
| File name | `817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:28:40` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `576f6b9f2a18541d04e3909081b02186` |
| SHA-1 | `20eb8aa162ee6add53ee38768d1e64fb713d31a5` |
| SHA-256 | `817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524` |
| SHA3-384 | `671b8829975115cca7c8c2ff6cd6705f9e71c122a476272fb3295eefd9b2b75d3f76ea4b48528c2cd0bfe38865267a9e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DC232B003BE9812BF2BE4F789CF26145867AF6633603D68A1CC4519B5613FC695436FE` |
| SSDEEP | `768:NuYHKTsufqG9vSLjWUvlPRmo2qbHxQHJcOPIcUzjbDgi3ir+5JqNdO9IDU5AoxV8:NuYHKTsjMvSX2esW3cU3bciSr+6NdwIH` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_073_817cccc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524"
    family = "AsyncRAT"
    file_name = "817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:28:40"
  condition:
    hash.sha256(0, filesize) == "817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524"
}
```

### Sample 74: `43409817d8f82d14`

| Field | Value |
|---|---|
| SHA-256 | `43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa` |
| Family label | `unknown` |
| File name | `43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:28:34` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bef6de0963ed3affdc5dd159a71924f1` |
| SHA-1 | `3e27133c21e31a88ab987340f6747250814b3d1f` |
| SHA-256 | `43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa` |
| SHA3-384 | `a165b2348b7ec5e98a0e22b7ad2bfeef31084efacc7875d68283cf492ddfd0c8b19644c06baccad2099c0391739ff2b9` |
| TLSH | `T1C2E12382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsmeLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvmzg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_43409817
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa"
    family = "unknown"
    file_name = "43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:28:34"
  condition:
    hash.sha256(0, filesize) == "43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa"
}
```

### Sample 75: `45731834d6dd54d3`

| Field | Value |
|---|---|
| SHA-256 | `45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4` |
| Family label | `unknown` |
| File name | `45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:28:23` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa29c21e11d02fa321e3353215f7fcd6` |
| SHA-1 | `ff4194b64dec7344338d8b8327162c24967468aa` |
| SHA-256 | `45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4` |
| SHA3-384 | `dd33f483898bdc810ad82376fac62b9677ce3a05cb5bf8500006e97ec88618eada89400572e12eaca853a104522d3061` |
| TLSH | `T1FCF13256BAEBCD73CCAD233A07678714337588D2AB43AB13611C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtlWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7p4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_45731834
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4"
    family = "unknown"
    file_name = "45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:28:23"
  condition:
    hash.sha256(0, filesize) == "45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4"
}
```

### Sample 76: `8fed438ede573781`

| Field | Value |
|---|---|
| SHA-256 | `8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d` |
| Family label | `unknown` |
| File name | `8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:28:18` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3f3605a5d671093ccb11ff49cbd4a04` |
| SHA-1 | `2689d87364a43a23982e8e04ba1fc042ab108bcc` |
| SHA-256 | `8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d` |
| SHA3-384 | `2425ed2db0329a6ddf8570b3142333936af17787ea10aaf9ffc7e24047cd6b4ec05fbfae99346b28ab71e9fb77db1458` |
| TLSH | `T16DF263239B1C5922C49C623842BB6742A23BF1E145D677774B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7J6Hh4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7JGhMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_8fed438e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d"
    family = "unknown"
    file_name = "8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:28:18"
  condition:
    hash.sha256(0, filesize) == "8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d"
}
```

### Sample 77: `2a0d32fa97dec912`

| Field | Value |
|---|---|
| SHA-256 | `2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13` |
| Family label | `unknown` |
| File name | `2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:27:08` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03e4bdd87915309e265b892ca2b7ee70` |
| SHA-1 | `7fcd35ca93fa32e03f9b0dd2e22206357cc2fa41` |
| SHA-256 | `2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13` |
| SHA3-384 | `7059c3c2d7e5320a74870dc17a74eb06e6b9bd5bccf05eb6efb23a498e2103b4cb030bdf4d95be36ae867ade4ecdb860` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19622E84977D94626E19F0F7A0AB1C34053B1F9DB8A23DB4F1AD4C78A1E327441942EE2` |
| SSDEEP | `192:E0e/mCQQPJab5dgWZPwDo2DgLpZ0vugj:udPJkTXPwD7DgLpZq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_2a0d32fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13"
    family = "unknown"
    file_name = "2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:27:08"
  condition:
    hash.sha256(0, filesize) == "2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13"
}
```

### Sample 78: `8564763407064117`

| Field | Value |
|---|---|
| SHA-256 | `8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216` |
| Family label | `unknown` |
| File name | `8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216.exe` |
| File type | `dll` |
| First seen | `2026-11-19 01:23:15` |
| Reporter | `Tuxxin` |
| Tags | `dll, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10fb1122079b5ae8e4147253a937f40f` |
| SHA-1 | `7d4e31c8b11be7c970860c4fbc8fe85c70724cb1` |
| SHA-256 | `8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216` |
| SHA3-384 | `d544a275ce4c6f754d543a61d417adb4613bf824b38985fae7f85dc575a256ea0cee73ac925d6644f6d79bc35fce7f3a` |
| IMPHASH | `761f47bb7965b1a7e85bb274c9eb1a8c` |
| TLSH | `T1FEF43A11ABA19039F9FB06F689FE256E503DB99017B484CB82C495DF4A79BE07E30713` |
| SSDEEP | `12288:aRvSGegYwKUu56rpekBynohJ8Z6eRGVmvydR9IXy9wcFBynW:a895cDBPJCkmvydzhx0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_85647634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216"
    family = "unknown"
    file_name = "8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216.exe"
    file_type = "dll"
    first_seen = "2026-11-19 01:23:15"
  condition:
    hash.sha256(0, filesize) == "8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216"
}
```

### Sample 79: `138ab98ad3626717`

| Field | Value |
|---|---|
| SHA-256 | `138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6` |
| Family label | `unknown` |
| File name | `138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:17:12` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d5684d823c1da9c7d477f3a51a70fd0` |
| SHA-1 | `7f9432456e0f895dbf78c47a7cbcda3383cef975` |
| SHA-256 | `138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6` |
| SHA3-384 | `9c80376e1d4ed2e1ed9d9b54f673fc247e37ebc9ab2bbd85a9ef5680a0d3e8928d1b79aed2947a9ec83a266edd2362a1` |
| TLSH | `T114F25F139B1C0A61C09C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BEB9D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRvPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfalilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_138ab98a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6"
    family = "unknown"
    file_name = "138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:17:12"
  condition:
    hash.sha256(0, filesize) == "138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6"
}
```

### Sample 80: `28ffc8bb9fd83a0b`

| Field | Value |
|---|---|
| SHA-256 | `28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a` |
| Family label | `unknown` |
| File name | `28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:14:18` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a945697a19a100e50d751e792327bd38` |
| SHA-1 | `e95e06892eb15df4e801fb483a21096d2fec5e82` |
| SHA-256 | `28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a` |
| SHA3-384 | `4869852250e3053c457147c37b75555a0f2a02fd13cd20f961b37410cb170d363e7a624434efaa8773ec30a367771e9a` |
| TLSH | `T135E25043675C5929D05D83BA22FB1B976609F8B009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZES5DbDP67li97WsCJwYjqclS06W1YbqclSl:GI2S5DbDynwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_28ffc8bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a"
    family = "unknown"
    file_name = "28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:14:18"
  condition:
    hash.sha256(0, filesize) == "28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a"
}
```

### Sample 81: `a73c9a918cdac476`

| Field | Value |
|---|---|
| SHA-256 | `a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b` |
| Family label | `unknown` |
| File name | `a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:14:13` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40157d11d5409cf903186c10535d7ca1` |
| SHA-1 | `21401e60bccf758ccfebb093d4159b1c2bd37b0d` |
| SHA-256 | `a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b` |
| SHA3-384 | `fc6d04c206abc34288f65070159214161b9cb51b3e152b50d2dfa2498505092b0c25bcd51709eba7db74926b4666b210` |
| TLSH | `T163F13256BAEBCD73CCAD233A07678714337588D2AB42AB13611C08752D835ECAD77AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtGWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7K4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_a73c9a91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b"
    family = "unknown"
    file_name = "a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:14:13"
  condition:
    hash.sha256(0, filesize) == "a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b"
}
```

### Sample 82: `20503d03da5868c8`

| Field | Value |
|---|---|
| SHA-256 | `20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f` |
| Family label | `unknown` |
| File name | `20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:13:23` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0201620969ef7499a1b96b2e033f37b6` |
| SHA-1 | `d70086d1047cbf7d13824c0bcc08b2dc7314ada0` |
| SHA-256 | `20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f` |
| SHA3-384 | `b3f7ba21c5ddea75293a968d9a5d92896aa4100fc65fa798a7de26ddaafd1b27c78cbfc9c235a5f3a24abee4184ad11e` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1F791C64270B999E7E85D41BB4C0FB8A0B91D740A41C483A74338A5993E3967BF47CB0D` |
| SSDEEP | `48:6IIF9BlQaexSgZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMTA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_20503d03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f"
    family = "unknown"
    file_name = "20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:13:23"
  condition:
    hash.sha256(0, filesize) == "20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f"
}
```

### Sample 83: `728493ecc28c2db6`

| Field | Value |
|---|---|
| SHA-256 | `728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214` |
| Family label | `unknown` |
| File name | `728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:13:18` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5d493bb364eb025d13e6e3e67e67a99` |
| SHA-1 | `6cbe847bb0dbd3face1d86f860fa7563247e3b00` |
| SHA-256 | `728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214` |
| SHA3-384 | `81b4ce15c891dd1dff49c2ed48ea7634a0045afb6e3c59aa54de322d5da1632b5fb58a852438d6333eac4175cc9c57a6` |
| IMPHASH | `d0b3556cc6e3c96ee093ade9e9bbf66f` |
| TLSH | `T1F1E4F1C6F6A591F8D417C03886174226F6B67C900B60A6FF4798973E5E37AD28F39B10` |
| SSDEEP | `12288:Jzs2bJ6UP1lHVnQd0Nza5m/tCs3ev5yU4ysfzWPet+M5warjthm:Jzsio2HdJE5yU5sfzNt+ejS` |
| ICON-DHASH | `6816706969711628` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_728493ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214"
    family = "unknown"
    file_name = "728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:13:18"
  condition:
    hash.sha256(0, filesize) == "728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214"
}
```

### Sample 84: `d0cba2efbac1a320`

| Field | Value |
|---|---|
| SHA-256 | `d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be` |
| Family label | `Snowlight` |
| File name | `d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:13:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10a8d9fe0d4ea068200cb3dd387a394b` |
| SHA-1 | `b7ac6660056575b801b9c0e9166493276b63a518` |
| SHA-256 | `d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be` |
| SHA3-384 | `413be2883efb236b1c75f0f03d5fd6fa411414058351d94cdcd945601cada8137f134880a5bc6ceb358dbae89219ce0f` |
| TLSH | `T19DE16207E2D5CE72D8CD133846931749223AD86EAB83AF03650C1999EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFS146Uwz7cSym4S2ofahbpZiQ:fsue7c9JvFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_084_d0cba2ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be"
    family = "Snowlight"
    file_name = "d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:13:11"
  condition:
    hash.sha256(0, filesize) == "d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be"
}
```

### Sample 85: `8fde2dcf1e2758bb`

| Field | Value |
|---|---|
| SHA-256 | `8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965` |
| Family label | `Snowlight` |
| File name | `8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:12:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e2993f44751e01bbdf49cae1a5bfaeb` |
| SHA-1 | `3bdde3aff9dd0e7f9e5448391ae768f2d97b1922` |
| SHA-256 | `8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965` |
| SHA3-384 | `1fdaf56947cb30bed861fb20aecd7720a97cc5abc4982894ec6669d2036c978a2b0867edd8873dc84b389fce9051145d` |
| TLSH | `T16A124147A2D1CE7FC8E813384457122472BBD47ADFA29713060C65766E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5UlTTej6TNJ9VlNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WT4TTfTpV1dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_085_8fde2dcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965"
    family = "Snowlight"
    file_name = "8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:12:19"
  condition:
    hash.sha256(0, filesize) == "8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965"
}
```

### Sample 86: `caf5c1ac20c8088a`

| Field | Value |
|---|---|
| SHA-256 | `caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570` |
| Family label | `unknown` |
| File name | `caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:12:13` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3de479806dcefb3a784b572c1463171` |
| SHA-1 | `faa45e19c5a1401d49507274c08780c738b0ca79` |
| SHA-256 | `caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570` |
| SHA3-384 | `658940eef10b14955ea349b1feb760b8622f6abfb6c75c5a5845e5aa12d3b2c7c4e6e5c446ea4f6d2b90a4a960b2c0c2` |
| TLSH | `T13EE12382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AACAD76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsTLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvWg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_caf5c1ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570"
    family = "unknown"
    file_name = "caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:12:13"
  condition:
    hash.sha256(0, filesize) == "caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570"
}
```

### Sample 87: `037b1b5b7fb6a3cc`

| Field | Value |
|---|---|
| SHA-256 | `037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf` |
| Family label | `Snowlight` |
| File name | `037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:12:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ee386480cda9d69b0a67df4414628e4` |
| SHA-1 | `5ab53bad79f3fd450af148ab0c1ff8aac742e947` |
| SHA-256 | `037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf` |
| SHA3-384 | `50bf2da86722b7ae0b439d8522c89524e01bccc6a7fde129356592c24df8e4cb8ff684c6e27be6b5c484b322721cf068` |
| TLSH | `T15F123F47A2D0CE3FC8D953384467122472B794BEDF629723064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `192:GqnWWHJZMWT1Ym2bhrsnurfjTr8sbnsl:5WWB1YmI8Oe` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_087_037b1b5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf"
    family = "Snowlight"
    file_name = "037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:12:09"
  condition:
    hash.sha256(0, filesize) == "037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf"
}
```

### Sample 88: `c1ef1966d8557f51`

| Field | Value |
|---|---|
| SHA-256 | `c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d` |
| Family label | `unknown` |
| File name | `c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:09:21` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `add0ab06009f37c8d183830dd5aed60f` |
| SHA-1 | `44d42c4a6f4ccf7db689f92778499929ac9a11fd` |
| SHA-256 | `c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d` |
| SHA3-384 | `27e05d3febbc07030b4d8e7ed54f639ea9cd7ac56918b6d83a0679d9104bb2905b46b9a6f4c509ce51c7d336270cb6bb` |
| TLSH | `T1ECE23E43AB4C8965C26D82301AF71BC6A616F5B09EE16B875750C7217FE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUWVZqDDt0TOTLZ0BbFw2wHKk6XrMclSibFqAMcl:z4ZZXvvHVZMt0TO2bVg/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_c1ef1966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d"
    family = "unknown"
    file_name = "c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:09:21"
  condition:
    hash.sha256(0, filesize) == "c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d"
}
```

### Sample 89: `0483096fdaf43af1`

| Field | Value |
|---|---|
| SHA-256 | `0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9` |
| Family label | `Snowlight` |
| File name | `0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:09:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `728b83f9f676872c3075a59f5fefd3ac` |
| SHA-1 | `6f88b4c8c2eae42f77b295d7c631050b5d9b89ea` |
| SHA-256 | `0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9` |
| SHA3-384 | `1a35f48bf7173a7d1f5b262b6ead465078492bfbf9a0daf819bd712aafa876b3da56e7c81e7efc0a91a0ba29ebd59a3f` |
| TLSH | `T192123F47A2D0CE3FC8D9533844A7122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6iH5ML09V1J9G8Ymm+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWH1ZMWT1Ym7hrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_089_0483096f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9"
    family = "Snowlight"
    file_name = "0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:09:16"
  condition:
    hash.sha256(0, filesize) == "0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9"
}
```

### Sample 90: `2e987f7ca6c3f481`

| Field | Value |
|---|---|
| SHA-256 | `2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3` |
| Family label | `unknown` |
| File name | `2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:09:11` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9107049be7b63817bda06ce1a8b99dff` |
| SHA-1 | `128a4c5008da10a8948dd35cf445b28aef05edac` |
| SHA-256 | `2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3` |
| SHA3-384 | `c854aabf863e1ab1e7d5ba6f910a48400bcd67f0aeabce10f1efbdbf59a4a5fea057ed22cf0f369c29743932de13506b` |
| TLSH | `T1F8E23E43AB4C8965C26D42301AF71BC6A615F5B09EE16B8B5750C7217FE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUwVZqDDt0TOTLZ0BbFw2yHKk6XrMclSibFqAMcl:z4ZZXvvFVZMt0TO2bV+/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_2e987f7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3"
    family = "unknown"
    file_name = "2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:09:11"
  condition:
    hash.sha256(0, filesize) == "2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3"
}
```

### Sample 91: `3fc727a3b0e7a071`

| Field | Value |
|---|---|
| SHA-256 | `3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b` |
| Family label | `unknown` |
| File name | `3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:07:25` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49e194f9047f5628b86654e2d6f11e4a` |
| SHA-1 | `bd451517521f4f02bf11110c148f8d32cb1fc4a2` |
| SHA-256 | `3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b` |
| SHA3-384 | `66362a9bb37e146e45f885db25744185fdb816041018742a3f18ffa5444c1f1402a8833b3725e1f776dc27a7c2919f07` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T12C91A5C5F757E6B2EC1C17F500A3B9A4C4682E14827C9B564FE16F1C3C111AA3D3DA52` |
| SSDEEP | `48:6I7lwe70i08SwJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1Z096q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_3fc727a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b"
    family = "unknown"
    file_name = "3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:07:25"
  condition:
    hash.sha256(0, filesize) == "3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b"
}
```

### Sample 92: `703e375fe6e77e52`

| Field | Value |
|---|---|
| SHA-256 | `703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e` |
| Family label | `unknown` |
| File name | `703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:07:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77959e52538f92e9f34250344bfab176` |
| SHA-1 | `0e5f62eb7960d510151d1328876e02ae910ddd45` |
| SHA-256 | `703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e` |
| SHA3-384 | `14cbb2d7b18bea091c74b89ff461a369c9edd4e1d6fb37a4fc0f6971db349480a9e34eef1cdd6969b88d80d895132623` |
| IMPHASH | `9dda1a1d1f8a1d13ae0297b47046b26e` |
| TLSH | `T1DEE533CEBE258D4BC8B8E13129D596456A2E7D1E4CEAD2071388C845AC7C3ECF755BE0` |
| SSDEEP | `98304:pihPNnFfy9oiz+nXcaRUgXlzkI9x98nzSvTrQeTX:pi9NnFfy9oiUXcMHXHKETX` |
| ICON-DHASH | `dcd4a6a2a6a69ac4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_703e375f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e"
    family = "unknown"
    file_name = "703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:07:14"
  condition:
    hash.sha256(0, filesize) == "703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e"
}
```

### Sample 93: `88ba086844d48ef6`

| Field | Value |
|---|---|
| SHA-256 | `88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2` |
| Family label | `ConnectWise` |
| File name | `88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:07:08` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, rmm-abuse, ScreenConnect, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `199e4613b9589c0f0784ae5a1a4b5dc9` |
| SHA-1 | `088346c6aa1a7a9ebafe848ba060e74514dff873` |
| SHA-256 | `88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2` |
| SHA3-384 | `831f38e61e5eed48fb43d0336d1855e929d83845e3fc195a546183d68046461a84d5f3147ab65892a4b0e38801d9c4a4` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T15ED61211B3F59675D1FB0638E87AA3615A35BC014B12C7AF6794792A2D327C08E323B7` |
| SSDEEP | `393216:nFri04SOLbX1fFri04SOLmFri04SOLyFri04SOLD:nMrSOLr1MrSOLmMrSOLyMrSOLD` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_093_88ba0868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2"
    family = "ConnectWise"
    file_name = "88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:07:08"
  condition:
    hash.sha256(0, filesize) == "88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2"
}
```

### Sample 94: `3113ee1149360169`

| Field | Value |
|---|---|
| SHA-256 | `3113ee11493601692e16664295d4f64b1c8407be91085d904880ec350305a5b1` |
| Family label | `SalatStealer` |
| File name | `1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:05:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8eb765dd5afd436c72ae057a2f7c53e4` |
| SHA-1 | `67fd35f3696149213f7f63923a089f1e011af793` |
| SHA-256 | `3113ee11493601692e16664295d4f64b1c8407be91085d904880ec350305a5b1` |
| SHA3-384 | `5ddcecf294641502bc29181d3a68a8ac97619064313a293770bb94f9019b10a0653f2b3d84a4ea49d4f343e88be26d96` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1AEC65A11FACB54F6E9035831446BB27F23355D048B28CB9BEB583B2AF87B691187B345` |
| SSDEEP | `98304:9N4hzKr7q+ruEitTU1/LKvkO84d8MwEnSEM:MzKOETlc8A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_094_3113ee11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3113ee11493601692e16664295d4f64b1c8407be91085d904880ec350305a5b1"
    family = "SalatStealer"
    file_name = "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:05:30"
  condition:
    hash.sha256(0, filesize) == "3113ee11493601692e16664295d4f64b1c8407be91085d904880ec350305a5b1"
}
```

### Sample 95: `85bb4cb9fd9590ca`

| Field | Value |
|---|---|
| SHA-256 | `85bb4cb9fd9590ca3549a4897255c6f01ea0d9eff77b487d031381c86db6b3c3` |
| Family label | `unknown` |
| File name | `楽天 インサイト.apk` |
| File type | `apk` |
| First seen | `2026-11-19 01:05:06` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc026d3225e3b0a330d2fffd10dc7594` |
| SHA-1 | `0d8557e0c7e216c958f89679c4a6d4721b76a75f` |
| SHA-256 | `85bb4cb9fd9590ca3549a4897255c6f01ea0d9eff77b487d031381c86db6b3c3` |
| SHA3-384 | `670b9bef7e3f907ec1f6c6d755bbd47b7f6a020509ec27f72105a28056e194ccb5fe271f5a606ff9854455b1f0f4a764` |
| TLSH | `T1B237331576712484D036A33D651ED0ABA7B9F737C2FA4DA39763E08B506F3902B463B2` |
| SSDEEP | `393216:Agggyao9MgslYDVFkZWto+lor0FfrNYrjGmo4fiexJ94/hgRnTfC/597y0VNzs:AgggCsluYUo+Gr0Jr2rRo4/P9y/f7NBs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_85bb4cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85bb4cb9fd9590ca3549a4897255c6f01ea0d9eff77b487d031381c86db6b3c3"
    family = "unknown"
    file_name = "楽天 インサイト.apk"
    file_type = "apk"
    first_seen = "2026-11-19 01:05:06"
  condition:
    hash.sha256(0, filesize) == "85bb4cb9fd9590ca3549a4897255c6f01ea0d9eff77b487d031381c86db6b3c3"
}
```

### Sample 96: `066ab138c6022b7c`

| Field | Value |
|---|---|
| SHA-256 | `066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4` |
| Family label | `unknown` |
| File name | `066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:04:32` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bd8a059cd9a99f4c5bcaa4407443bef` |
| SHA-1 | `ba6e498198c9e6b993da6e842b8e93cfb9284ebb` |
| SHA-256 | `066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4` |
| SHA3-384 | `b63092619da880fa496a53d4d59d950a6e43b0c27952bc7774bd277df0e31a42ba941ddfa59a5800279e24afb6ca529e` |
| TLSH | `T1DBE24F43675C5929D05D83BA22FB1B576619F8A009D45B432F50DA282FE23C47CB0FDB` |
| SSDEEP | `96:xcIZEb5DbDP67li97WsCEZwYjqclS06W1YbqclSl:GI2b5DbDyCZwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_066ab138
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4"
    family = "unknown"
    file_name = "066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:04:32"
  condition:
    hash.sha256(0, filesize) == "066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4"
}
```

### Sample 97: `6c80bb36afc32fcb`

| Field | Value |
|---|---|
| SHA-256 | `6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5` |
| Family label | `unknown` |
| File name | `6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:04:26` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `827c7c9a26b65a141fe902209a03ee32` |
| SHA-1 | `7886de39441c0e6d0d2d65229a08cfd9ecfd4746` |
| SHA-256 | `6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5` |
| SHA3-384 | `00a588d55736ae466ff06a636e65ffae23160b665facac5c836e9ebbb6eed9eaaf38f2faf19dd30f5ae765b4de7632fe` |
| TLSH | `T1A2E14382BDD6CE3BCCA9627A1673C6203372C551AB439B07210C48753D83AECAD76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsoLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvVg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_6c80bb36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5"
    family = "unknown"
    file_name = "6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:04:26"
  condition:
    hash.sha256(0, filesize) == "6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5"
}
```

### Sample 98: `1504be43c17da268`

| Field | Value |
|---|---|
| SHA-256 | `1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a` |
| Family label | `SalatStealer` |
| File name | `1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a.exe` |
| File type | `exe` |
| First seen | `2026-11-19 01:04:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00b46db72fee0da4d2336074d2ef6a80` |
| SHA-1 | `483e9939931d518bae75b27c08f306f8e8bf9eb4` |
| SHA-256 | `1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a` |
| SHA3-384 | `56ac1adb5158ae51a5973478bf8bc33358970a83907a4859ceb8dfce924e168c61b5b3d296463d133e93a9655bf14df5` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14FF533F6628F8D8EFBB8B33D866CB98409D3E5EFA4643AE6D5579100105880CD5A354F` |
| SSDEEP | `98304:3SZqCw2WPj83B69YIrkbR991QXMZlS2VRBZmtjG6wM/hF0b:oqCw2qqRD1QYlSQBZfUpU` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_098_1504be43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a"
    family = "SalatStealer"
    file_name = "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:04:18"
  condition:
    hash.sha256(0, filesize) == "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a"
}
```

### Sample 99: `348b109f2232a328`

| Field | Value |
|---|---|
| SHA-256 | `348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c` |
| Family label | `unknown` |
| File name | `348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c.bin` |
| File type | `macho` |
| First seen | `2026-11-19 01:03:13` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a2055ae0020ab125e6c984b55531aae` |
| SHA-1 | `78c723152b746eda6a865ec7493ba24c0b92d7e3` |
| SHA-256 | `348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c` |
| SHA3-384 | `ab315f5e4175a70e12a266cac7017902c5a4852b53c87202b7c42b79160f401e06173615b5313e2469239df94c1600ae` |
| TLSH | `T1EDE25043675C5929D05D83B922FB5B576619F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCwwYjqclS06W1YbqclSl:GI2n5DbDy+wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_348b109f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c"
    family = "unknown"
    file_name = "348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:03:13"
  condition:
    hash.sha256(0, filesize) == "348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c"
}
```

### Sample 100: `341a382d6f9e5400`

| Field | Value |
|---|---|
| SHA-256 | `341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767` |
| Family label | `unknown` |
| File name | `341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767.elf` |
| File type | `elf` |
| First seen | `2026-11-19 01:02:17` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80bad4799bbd573c127ef3798ecc5e7a` |
| SHA-1 | `39f3d28d7293bd163df91a51eae1b5950c12b5c4` |
| SHA-256 | `341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767` |
| SHA3-384 | `3525b1ea889ff85d9026729e71189ced313ecaf32b930e604967347945bd86cbcd0005d5a07f43f27c6e95713995cfc6` |
| TLSH | `T143F13356BAEBCD73CCAD233A07678714337588D2AB42AB13511C08752D835ECAD76BD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtZWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7R4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_341a382d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767"
    family = "unknown"
    file_name = "341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:02:17"
  condition:
    hash.sha256(0, filesize) == "341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767"
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
 * Generated: 2026-11-19T07:37:14.948460+00:00
 */

rule MalwareBazaar_unknown_001_7cf99107
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7cf99107e71b500bf13f6795f0188af9e74aa8ac1a49de30ea4324c09db7ec25"
    family = "unknown"
    file_name = "imp"
    file_type = "elf"
    first_seen = "2026-11-19 07:35:09"
  condition:
    hash.sha256(0, filesize) == "7cf99107e71b500bf13f6795f0188af9e74aa8ac1a49de30ea4324c09db7ec25"
}

rule MalwareBazaar_Mirai_002_2b9ff957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b9ff957accb416c7e02242beec810c49e0374c665e8ff313d220551ca49803b"
    family = "Mirai"
    file_name = "bot_x86_64_c"
    file_type = "elf"
    first_seen = "2026-11-19 07:28:14"
  condition:
    hash.sha256(0, filesize) == "2b9ff957accb416c7e02242beec810c49e0374c665e8ff313d220551ca49803b"
}

rule MalwareBazaar_Prometei_003_4dc746b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dc746b1e61b8f7749500863736a95c938e49c9087a53ab6d5eaf4c7ede06fcc"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 07:07:06"
  condition:
    hash.sha256(0, filesize) == "4dc746b1e61b8f7749500863736a95c938e49c9087a53ab6d5eaf4c7ede06fcc"
}

rule MalwareBazaar_unknown_004_5be19a8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5be19a8baf8b04839546e12448049ee9320578edea8eecf381a4c537793af5ee"
    family = "unknown"
    file_name = "ultima quotazione per il 2026.js"
    file_type = "js"
    first_seen = "2026-11-19 07:04:41"
  condition:
    hash.sha256(0, filesize) == "5be19a8baf8b04839546e12448049ee9320578edea8eecf381a4c537793af5ee"
}

rule MalwareBazaar_unknown_005_c8727e40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8727e4087a5bb4f94fc9919aa03279d9ea14ca8fe1b236d4f1d962fcdee55d1"
    family = "unknown"
    file_name = "agent"
    file_type = "elf"
    first_seen = "2026-11-19 07:04:06"
  condition:
    hash.sha256(0, filesize) == "c8727e4087a5bb4f94fc9919aa03279d9ea14ca8fe1b236d4f1d962fcdee55d1"
}

rule MalwareBazaar_Mirai_006_cae07077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae07077d58b6f810b5e4e711081b38dde12aa1438b4d4e26db975e96f100f29"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:24"
  condition:
    hash.sha256(0, filesize) == "cae07077d58b6f810b5e4e711081b38dde12aa1438b4d4e26db975e96f100f29"
}

rule MalwareBazaar_Mirai_007_ed1647c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed1647c515ff06dfb8fd08a292794cd327930a6d040c38e5d270240390e2dfc7"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:21"
  condition:
    hash.sha256(0, filesize) == "ed1647c515ff06dfb8fd08a292794cd327930a6d040c38e5d270240390e2dfc7"
}

rule MalwareBazaar_Mirai_008_c22fbb6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c22fbb6b05ee296a7546bfe5f1fcc682e54036dc1e2dc2d4905ab4dd58c4e922"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:18"
  condition:
    hash.sha256(0, filesize) == "c22fbb6b05ee296a7546bfe5f1fcc682e54036dc1e2dc2d4905ab4dd58c4e922"
}

rule MalwareBazaar_Mirai_009_c1ea954e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ea954eb146a3647c8146da35ea0d5e0eb6725f23c25d1455365b17e635e1b4"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:16"
  condition:
    hash.sha256(0, filesize) == "c1ea954eb146a3647c8146da35ea0d5e0eb6725f23c25d1455365b17e635e1b4"
}

rule MalwareBazaar_Mirai_010_fdd78118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd78118194450b9080a12d5def51f3e83e89fd40514e1d2a720764566d801e4"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:13"
  condition:
    hash.sha256(0, filesize) == "fdd78118194450b9080a12d5def51f3e83e89fd40514e1d2a720764566d801e4"
}

rule MalwareBazaar_Mirai_011_ba7e96e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba7e96e1b87b45681a1967db43ec70db0debb24830fa8c60d115ef3ab3e483bb"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:11"
  condition:
    hash.sha256(0, filesize) == "ba7e96e1b87b45681a1967db43ec70db0debb24830fa8c60d115ef3ab3e483bb"
}

rule MalwareBazaar_Mirai_012_a7b52360
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:08"
  condition:
    hash.sha256(0, filesize) == "a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76"
}

rule MalwareBazaar_Mirai_013_ef8aef10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef8aef100bc59ae54ad24034132851fb6e0ba3e176156836b3378e0bad609e14"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-11-19 05:57:05"
  condition:
    hash.sha256(0, filesize) == "ef8aef100bc59ae54ad24034132851fb6e0ba3e176156836b3378e0bad609e14"
}

rule MalwareBazaar_Prometei_014_b81a1219
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81a1219f96873b46cdb16a555b6fd7f657826fd7b2bbd1f7de68ee1ed1100d7"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:50:05"
  condition:
    hash.sha256(0, filesize) == "b81a1219f96873b46cdb16a555b6fd7f657826fd7b2bbd1f7de68ee1ed1100d7"
}

rule MalwareBazaar_Prometei_015_529d1019
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "529d1019d1d9dec858bfd8916ccab9c69e706ae978c8cdb2f8dfa827fa710147"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:42:06"
  condition:
    hash.sha256(0, filesize) == "529d1019d1d9dec858bfd8916ccab9c69e706ae978c8cdb2f8dfa827fa710147"
}

rule MalwareBazaar_Prometei_016_fb2ea3bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb2ea3bb6714a5383b792c66e331bf85232d59e3a123b310a68634a90383c361"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:29:06"
  condition:
    hash.sha256(0, filesize) == "fb2ea3bb6714a5383b792c66e331bf85232d59e3a123b310a68634a90383c361"
}

rule MalwareBazaar_unknown_017_55a89520
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a8952055a69b2e916a61182443b8398547df2870b1dbe4e8668bf89897aac4"
    family = "unknown"
    file_name = "SecuriteInfo.com.Exploit.CVE-2017-0199.04.Gen.95874282"
    file_type = "xlsx"
    first_seen = "2026-11-19 05:23:17"
  condition:
    hash.sha256(0, filesize) == "55a8952055a69b2e916a61182443b8398547df2870b1dbe4e8668bf89897aac4"
}

rule MalwareBazaar_unknown_018_5d55a50b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d55a50b777e1ef766c5420c0f4681cdc9c32e4b232a0262feff34d7634b1196"
    family = "unknown"
    file_name = "paymentcopynov.hta"
    file_type = "hta"
    first_seen = "2026-11-19 05:20:13"
  condition:
    hash.sha256(0, filesize) == "5d55a50b777e1ef766c5420c0f4681cdc9c32e4b232a0262feff34d7634b1196"
}

rule MalwareBazaar_unknown_019_8f911ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f911ed9e53cd9614328eff3e9193bb5b412ad2384828e3173b58917071f20d5"
    family = "unknown"
    file_name = "RequestforQuotationUAEU56942026ClosingBudget.js"
    file_type = "js"
    first_seen = "2026-11-19 05:20:10"
  condition:
    hash.sha256(0, filesize) == "8f911ed9e53cd9614328eff3e9193bb5b412ad2384828e3173b58917071f20d5"
}

rule MalwareBazaar_Prometei_020_fac84a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fac84a16fb7dc254ea370cb0784d86fc126944114b2f759ca6d205ba52b4e175"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:18:06"
  condition:
    hash.sha256(0, filesize) == "fac84a16fb7dc254ea370cb0784d86fc126944114b2f759ca6d205ba52b4e175"
}

rule MalwareBazaar_Prometei_021_125dcd78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "125dcd78f6327589e6dc65956fc27972ba2878bddf682230e27b109eff709283"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-19 05:16:05"
  condition:
    hash.sha256(0, filesize) == "125dcd78f6327589e6dc65956fc27972ba2878bddf682230e27b109eff709283"
}

rule MalwareBazaar_njrat_022_e820baa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e820baa54b34439fcdf9a492fc081b528dd3124c0f2be4d3696256f26db64a23"
    family = "njrat"
    file_name = "2f11fc190f26038a0f24a69b2625eafc.exe"
    file_type = "exe"
    first_seen = "2026-11-19 05:10:06"
  condition:
    hash.sha256(0, filesize) == "e820baa54b34439fcdf9a492fc081b528dd3124c0f2be4d3696256f26db64a23"
}

rule MalwareBazaar_unknown_023_3dec8ea7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dec8ea7364b2df6cb3e36f020457e0c8343978942d039aa2182599d98d0ae95"
    family = "unknown"
    file_name = "3dec8ea7364b2df6.bin"
    file_type = "bat"
    first_seen = "2026-11-19 04:24:06"
  condition:
    hash.sha256(0, filesize) == "3dec8ea7364b2df6cb3e36f020457e0c8343978942d039aa2182599d98d0ae95"
}

rule MalwareBazaar_unknown_024_c8f1f293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8f1f293ecaa0e83dd1d6421291ef834b39ad3b6cabf857c6e0c1920592a0a7f"
    family = "unknown"
    file_name = "c8f1f293ecaa0e83.js"
    file_type = "js"
    first_seen = "2026-11-19 04:23:21"
  condition:
    hash.sha256(0, filesize) == "c8f1f293ecaa0e83dd1d6421291ef834b39ad3b6cabf857c6e0c1920592a0a7f"
}

rule MalwareBazaar_unknown_025_b3b53bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189"
    family = "unknown"
    file_name = "b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189.bin"
    file_type = "php"
    first_seen = "2026-11-19 04:22:03"
  condition:
    hash.sha256(0, filesize) == "b3b53bfe99f03ec722f0e9ebdb0bb6a47272582bdfb2a785e1a40777a455b189"
}

rule MalwareBazaar_unknown_026_c0bc825d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0bc825da4033991c16f320dffecf2f54ac2709123a02d5e983d40bb8908532f"
    family = "unknown"
    file_name = "vlcplay1.exe"
    file_type = "exe"
    first_seen = "2026-11-19 04:08:04"
  condition:
    hash.sha256(0, filesize) == "c0bc825da4033991c16f320dffecf2f54ac2709123a02d5e983d40bb8908532f"
}

rule MalwareBazaar_SalatStealer_027_1aaeee02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1aaeee024b71bf7f93e50d5904aac4a50ba6f58972e8b8f6569b0b1637727e89"
    family = "SalatStealer"
    file_name = "FortniteAssistant.exe"
    file_type = "exe"
    first_seen = "2026-11-19 03:58:12"
  condition:
    hash.sha256(0, filesize) == "1aaeee024b71bf7f93e50d5904aac4a50ba6f58972e8b8f6569b0b1637727e89"
}

rule MalwareBazaar_unknown_028_bcff4d6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcff4d6f844904bfb791dec13aa62cae4be05ef0c4d49c693a9043ce63ce33b4"
    family = "unknown"
    file_name = "Msi Utility v3.exe"
    file_type = "exe"
    first_seen = "2026-11-19 03:54:12"
  condition:
    hash.sha256(0, filesize) == "bcff4d6f844904bfb791dec13aa62cae4be05ef0c4d49c693a9043ce63ce33b4"
}

rule MalwareBazaar_AgentTesla_029_9650cb8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9650cb8f47f20042ba83f1e659c39bdc1b129220b37dab86f9e1b4bbc5bf0968"
    family = "AgentTesla"
    file_name = "Copia para el remitente.JS"
    file_type = "js"
    first_seen = "2026-11-19 03:45:22"
  condition:
    hash.sha256(0, filesize) == "9650cb8f47f20042ba83f1e659c39bdc1b129220b37dab86f9e1b4bbc5bf0968"
}

rule MalwareBazaar_njrat_030_0a27062f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a27062fa52737bf62edbbb800793545a27f154f8f10d4a05251ad8365910251"
    family = "njrat"
    file_name = "21b5998aa4e57bf9b9423948eda2a039.exe"
    file_type = "exe"
    first_seen = "2026-11-19 03:45:06"
  condition:
    hash.sha256(0, filesize) == "0a27062fa52737bf62edbbb800793545a27f154f8f10d4a05251ad8365910251"
}

rule MalwareBazaar_unknown_031_9d21cf8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d21cf8b5c3416a01bfcc7caab84b10f8de3eba88229e2fcd358d0970b6742b2"
    family = "unknown"
    file_name = "9d21cf8b5c3416a0.ps1"
    file_type = "ps1"
    first_seen = "2026-11-19 03:43:03"
  condition:
    hash.sha256(0, filesize) == "9d21cf8b5c3416a01bfcc7caab84b10f8de3eba88229e2fcd358d0970b6742b2"
}

rule MalwareBazaar_unknown_032_ebd0a96a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd0a96a159bdd1628373228f1c7f67645315ffd5374d1caf6f4f7a7ffed3b21"
    family = "unknown"
    file_name = "ebd0a96a159bdd16.js"
    file_type = "js"
    first_seen = "2026-11-19 03:33:05"
  condition:
    hash.sha256(0, filesize) == "ebd0a96a159bdd1628373228f1c7f67645315ffd5374d1caf6f4f7a7ffed3b21"
}

rule MalwareBazaar_unknown_033_05e2208e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953"
    family = "unknown"
    file_name = "05e2208e78605e63.ps1"
    file_type = "ps1"
    first_seen = "2026-11-19 03:23:01"
  condition:
    hash.sha256(0, filesize) == "05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953"
}

rule MalwareBazaar_unknown_034_945a796f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb"
    family = "unknown"
    file_name = "945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb.bin"
    file_type = "js"
    first_seen = "2026-11-19 03:09:16"
  condition:
    hash.sha256(0, filesize) == "945a796f7d6353f0f53d1465e7ff90ed7af6e1440ce5931f6c19224289937adb"
}

rule MalwareBazaar_unknown_035_748c7860
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9"
    family = "unknown"
    file_name = "748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9.bin"
    file_type = "ps1"
    first_seen = "2026-11-19 03:07:03"
  condition:
    hash.sha256(0, filesize) == "748c78602755a47ea992e8627ebcc468046610c3e1a8d0c230b3d39a28b418a9"
}

rule MalwareBazaar_unknown_036_59cb95a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59cb95a9315ca3aca32667acb48aa21be0b88f552d9032cacb64129d64067c4a"
    family = "unknown"
    file_name = "59cb95a9315ca3ac.js"
    file_type = "js"
    first_seen = "2026-11-19 03:03:09"
  condition:
    hash.sha256(0, filesize) == "59cb95a9315ca3aca32667acb48aa21be0b88f552d9032cacb64129d64067c4a"
}

rule MalwareBazaar_unknown_037_7e748bc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026"
    family = "unknown"
    file_name = "7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:49:00"
  condition:
    hash.sha256(0, filesize) == "7e748bc2fbdc47001c50077e8c2d400473c43b5c613f28e51cd04e708d944026"
}

rule MalwareBazaar_unknown_038_9fbb3112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6"
    family = "unknown"
    file_name = "9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:40"
  condition:
    hash.sha256(0, filesize) == "9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6"
}

rule MalwareBazaar_unknown_039_6250fc1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d"
    family = "unknown"
    file_name = "6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:35"
  condition:
    hash.sha256(0, filesize) == "6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d"
}

rule MalwareBazaar_unknown_040_389f3b3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712"
    family = "unknown"
    file_name = "389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:32"
  condition:
    hash.sha256(0, filesize) == "389f3b3a223bbf18761bc3c342433ad49edb8ff4e0d808d8892534a281763712"
}

rule MalwareBazaar_unknown_041_9e286f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba"
    family = "unknown"
    file_name = "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:47:28"
  condition:
    hash.sha256(0, filesize) == "9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba"
}

rule MalwareBazaar_unknown_042_0a472a13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2"
    family = "unknown"
    file_name = "0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:45:11"
  condition:
    hash.sha256(0, filesize) == "0a472a13fd265f26c71bbf526b80a5b530c186d166f0c4fb3cf52761466eccd2"
}

rule MalwareBazaar_unknown_043_d8e36eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11"
    family = "unknown"
    file_name = "d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:45:04"
  condition:
    hash.sha256(0, filesize) == "d8e36eb4d58085a85648f84f42c9237b34705ffe1c85a302860543c6287b0a11"
}

rule MalwareBazaar_unknown_044_584a2ce0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486"
    family = "unknown"
    file_name = "584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:58"
  condition:
    hash.sha256(0, filesize) == "584a2ce0aeb4bc5020c1223e3affd032445962f0becd8448beeb6d21c22eb486"
}

rule MalwareBazaar_unknown_045_e2d35f05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b"
    family = "unknown"
    file_name = "e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:10"
  condition:
    hash.sha256(0, filesize) == "e2d35f05df843340e12b68dbac1d071034542a2b2111ebaead355b4c67e5ce8b"
}

rule MalwareBazaar_unknown_046_c71c96fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be"
    family = "unknown"
    file_name = "c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:06"
  condition:
    hash.sha256(0, filesize) == "c71c96fcaa21d84ec2b21ea55f12a516dc2719b4df7541c6c32946fd4ace46be"
}

rule MalwareBazaar_unknown_047_bca8d458
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524"
    family = "unknown"
    file_name = "bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:44:01"
  condition:
    hash.sha256(0, filesize) == "bca8d45805ba486e4193ef64813800e79661c76c9720e353d4f4f12cf3ab5524"
}

rule MalwareBazaar_unknown_048_011f6842
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5"
    family = "unknown"
    file_name = "011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:43:57"
  condition:
    hash.sha256(0, filesize) == "011f6842382c4d4fd371f6db91ff5da65a6c038529dc19dbb65ef81942b102d5"
}

rule MalwareBazaar_unknown_049_533e9950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380"
    family = "unknown"
    file_name = "533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:43:52"
  condition:
    hash.sha256(0, filesize) == "533e995069ae094d2b8f5acdee575c7f1ecf0364d59d9ab96c7a9524fd231380"
}

rule MalwareBazaar_unknown_050_95affaf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850"
    family = "unknown"
    file_name = "95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:37:16"
  condition:
    hash.sha256(0, filesize) == "95affaf9b4bb187b89d0131bfbc3abb714f0df66219c5da02a591e2f8497b850"
}

rule MalwareBazaar_unknown_051_e4980b40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043"
    family = "unknown"
    file_name = "e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:37:10"
  condition:
    hash.sha256(0, filesize) == "e4980b40d5ee4e3c1e474c901d8470557fc6dd974759fe80eb1003fd144d8043"
}

rule MalwareBazaar_unknown_052_c2ef57bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b"
    family = "unknown"
    file_name = "c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:33:50"
  condition:
    hash.sha256(0, filesize) == "c2ef57bd9005e60daf24158857efa1441593c8db3487b156a9b71e763e723f5b"
}

rule MalwareBazaar_unknown_053_3f469d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a"
    family = "unknown"
    file_name = "3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:30:02"
  condition:
    hash.sha256(0, filesize) == "3f469d9c8b974224cd19d9e6916c936e8e5d3e334a041a1888e3f75edef9e16a"
}

rule MalwareBazaar_unknown_054_2dbd5b55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4"
    family = "unknown"
    file_name = "2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:29:58"
  condition:
    hash.sha256(0, filesize) == "2dbd5b55987e3a79399cf46b4e4ed09329041ccc9cbf1864eb77ac279266e9f4"
}

rule MalwareBazaar_unknown_055_810bd753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1"
    family = "unknown"
    file_name = "810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:29:54"
  condition:
    hash.sha256(0, filesize) == "810bd7539ab96bce9690d2d5eb1769b8a079a82028494adb2278a58264577ab1"
}

rule MalwareBazaar_unknown_056_e2a4f5c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1"
    family = "unknown"
    file_name = "e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:29:50"
  condition:
    hash.sha256(0, filesize) == "e2a4f5c098fef325875174eafc9102a3ea7e226e85a3d2eeb5b5b64d599237f1"
}

rule MalwareBazaar_unknown_057_434f488a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8"
    family = "unknown"
    file_name = "434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:28:49"
  condition:
    hash.sha256(0, filesize) == "434f488ac3e1220863009ab7826a78b6ec83cd4394f0639d6da59e153c7587c8"
}

rule MalwareBazaar_unknown_058_35ebd2d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff"
    family = "unknown"
    file_name = "35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:27:11"
  condition:
    hash.sha256(0, filesize) == "35ebd2d99c786e28a5ff870a8c71b297c1fd03eef7f6d46b173d450faef043ff"
}

rule MalwareBazaar_unknown_059_b61b4cd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43"
    family = "unknown"
    file_name = "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:22:15"
  condition:
    hash.sha256(0, filesize) == "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43"
}

rule MalwareBazaar_unknown_060_88f68396
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626"
    family = "unknown"
    file_name = "88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:22:11"
  condition:
    hash.sha256(0, filesize) == "88f68396661b11912e6e3330302d0dcefd24011f5c610d8d5009e8e3672f5626"
}

rule MalwareBazaar_unknown_061_a5b81a1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41"
    family = "unknown"
    file_name = "a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:22:07"
  condition:
    hash.sha256(0, filesize) == "a5b81a1a98754d0ffb79419b7ce81ace95dcf2f330927d1a9fd8e567f0718a41"
}

rule MalwareBazaar_unknown_062_1d8e5258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5"
    family = "unknown"
    file_name = "1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5"
    file_type = "exe"
    first_seen = "2026-11-19 02:15:11"
  condition:
    hash.sha256(0, filesize) == "1d8e5258366efc427664a57b143918f98511db5fa1dfb53b52e537a92ca7f9f5"
}

rule MalwareBazaar_unknown_063_a2e8e14e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025"
    family = "unknown"
    file_name = "a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025.bin"
    file_type = "js"
    first_seen = "2026-11-19 02:14:43"
  condition:
    hash.sha256(0, filesize) == "a2e8e14e33734803b07e0a1968fb20112fd61d33c8efe789db0907153ca29025"
}

rule MalwareBazaar_unknown_064_ba38e7dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1"
    family = "unknown"
    file_name = "cosmoLoader.exe"
    file_type = "exe"
    first_seen = "2026-11-19 02:14:00"
  condition:
    hash.sha256(0, filesize) == "ba38e7dd33543cde9568a8f191e7f144465390394b77edb8f12d4f0b519a78a1"
}

rule MalwareBazaar_Mirai_065_af1b818c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc"
    family = "Mirai"
    file_name = "af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc"
    file_type = "elf"
    first_seen = "2026-11-19 02:00:08"
  condition:
    hash.sha256(0, filesize) == "af1b818c2fd2a5f57b1621281bafc03b551280b14952213ae7f72881be43d2fc"
}

rule MalwareBazaar_unknown_066_53abf377
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8"
    family = "unknown"
    file_name = "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8.bin"
    file_type = "js"
    first_seen = "2026-11-19 01:59:29"
  condition:
    hash.sha256(0, filesize) == "53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8"
}

rule MalwareBazaar_unknown_067_c0a8d6c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce"
    family = "unknown"
    file_name = "c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce.bin"
    file_type = "js"
    first_seen = "2026-11-19 01:52:03"
  condition:
    hash.sha256(0, filesize) == "c0a8d6c39df2b2193ce48c091868d1a3804951a2c6eb7e721e7df7ceae30d6ce"
}

rule MalwareBazaar_unknown_068_b1645d53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453"
    family = "unknown"
    file_name = "b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453.bin"
    file_type = "js"
    first_seen = "2026-11-19 01:49:30"
  condition:
    hash.sha256(0, filesize) == "b1645d539553b5863577cf9a85b3bcc4a420b78ac83b7e4f05c4a573d3375453"
}

rule MalwareBazaar_unknown_069_e364a0a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a"
    family = "unknown"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-11-19 01:41:40"
  condition:
    hash.sha256(0, filesize) == "e364a0a9125468bed48a7df849ee1849934a9227703c77ed32cf04b76f672c7a"
}

rule MalwareBazaar_njrat_070_5975cc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20"
    family = "njrat"
    file_name = "1bf0c7c5732e63f87c6b2b21ee774ce4.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:40:06"
  condition:
    hash.sha256(0, filesize) == "5975cc213128bdd9ebb2e8cec61b76205931fad79a3f87e9b548db1ce9a62c20"
}

rule MalwareBazaar_Snowlight_071_fd7cdd39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a"
    family = "Snowlight"
    file_name = "fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:29:19"
  condition:
    hash.sha256(0, filesize) == "fd7cdd39be318780aff80621bc7588264f2da03552e4c08c4e1b18489df1d91a"
}

rule MalwareBazaar_QuasarRAT_072_572db981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e"
    family = "QuasarRAT"
    file_name = "572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:29:14"
  condition:
    hash.sha256(0, filesize) == "572db981cf481bb08238911632bd1c570bb8195ac73b30e7771821802ace8e7e"
}

rule MalwareBazaar_AsyncRAT_073_817cccc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524"
    family = "AsyncRAT"
    file_name = "817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:28:40"
  condition:
    hash.sha256(0, filesize) == "817cccc82f116d1050197c8c89e208badeb26fae112e96894061f3b7b6017524"
}

rule MalwareBazaar_unknown_074_43409817
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa"
    family = "unknown"
    file_name = "43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:28:34"
  condition:
    hash.sha256(0, filesize) == "43409817d8f82d1457973d7f6b8abddcb7abc70465cd36a2c4bed35ce83396fa"
}

rule MalwareBazaar_unknown_075_45731834
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4"
    family = "unknown"
    file_name = "45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:28:23"
  condition:
    hash.sha256(0, filesize) == "45731834d6dd54d3bb2a44acbe9a178efcc8261895f648a5ea54432522d368d4"
}

rule MalwareBazaar_unknown_076_8fed438e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d"
    family = "unknown"
    file_name = "8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:28:18"
  condition:
    hash.sha256(0, filesize) == "8fed438ede5737818674b61f3b4459d78db56f9cd76c977d454d3b40f1312d7d"
}

rule MalwareBazaar_unknown_077_2a0d32fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13"
    family = "unknown"
    file_name = "2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:27:08"
  condition:
    hash.sha256(0, filesize) == "2a0d32fa97dec912a50c9438789e99a2160ac9310ecf2cb98e97c1502b990d13"
}

rule MalwareBazaar_unknown_078_85647634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216"
    family = "unknown"
    file_name = "8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216.exe"
    file_type = "dll"
    first_seen = "2026-11-19 01:23:15"
  condition:
    hash.sha256(0, filesize) == "8564763407064117726211ff8f89555e5a3b2b70bc9667032abd69cbe53b5216"
}

rule MalwareBazaar_unknown_079_138ab98a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6"
    family = "unknown"
    file_name = "138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:17:12"
  condition:
    hash.sha256(0, filesize) == "138ab98ad36267170dfa9e50f0decc562c71087d18d82b19b317af46d7627fa6"
}

rule MalwareBazaar_unknown_080_28ffc8bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a"
    family = "unknown"
    file_name = "28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:14:18"
  condition:
    hash.sha256(0, filesize) == "28ffc8bb9fd83a0b82f4d7980d5e1b47fc401b35dc2d96ca61301000b2f4871a"
}

rule MalwareBazaar_unknown_081_a73c9a91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b"
    family = "unknown"
    file_name = "a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:14:13"
  condition:
    hash.sha256(0, filesize) == "a73c9a918cdac476eb3bf2457bc33e10a6dc0375f15f10e1a5e590b09725894b"
}

rule MalwareBazaar_unknown_082_20503d03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f"
    family = "unknown"
    file_name = "20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:13:23"
  condition:
    hash.sha256(0, filesize) == "20503d03da5868c8a576412c70e9ae1b0fc947a5917a3fb9765192cc6481003f"
}

rule MalwareBazaar_unknown_083_728493ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214"
    family = "unknown"
    file_name = "728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:13:18"
  condition:
    hash.sha256(0, filesize) == "728493ecc28c2db6b0158b6272b4e502de504eaaff13d3f3d64b22daa8b80214"
}

rule MalwareBazaar_Snowlight_084_d0cba2ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be"
    family = "Snowlight"
    file_name = "d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:13:11"
  condition:
    hash.sha256(0, filesize) == "d0cba2efbac1a3202ddc473cf121553b96b6650d88339acb022d5671ef8251be"
}

rule MalwareBazaar_Snowlight_085_8fde2dcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965"
    family = "Snowlight"
    file_name = "8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:12:19"
  condition:
    hash.sha256(0, filesize) == "8fde2dcf1e2758bbea8a42b604aefb6e6de8245972084ad9ae7fd94e2071a965"
}

rule MalwareBazaar_unknown_086_caf5c1ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570"
    family = "unknown"
    file_name = "caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:12:13"
  condition:
    hash.sha256(0, filesize) == "caf5c1ac20c8088ae42b8e11d3f2e0c14a342ae5cf7cef76f8dab7085b929570"
}

rule MalwareBazaar_Snowlight_087_037b1b5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf"
    family = "Snowlight"
    file_name = "037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:12:09"
  condition:
    hash.sha256(0, filesize) == "037b1b5b7fb6a3ccc76f0dc6c23c0bbfd93edd03c3237922a6532e2f17f873bf"
}

rule MalwareBazaar_unknown_088_c1ef1966
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d"
    family = "unknown"
    file_name = "c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:09:21"
  condition:
    hash.sha256(0, filesize) == "c1ef1966d8557f51e39d1403d6ff2478c15af5a0d99cff5438bd747a48412f1d"
}

rule MalwareBazaar_Snowlight_089_0483096f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9"
    family = "Snowlight"
    file_name = "0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:09:16"
  condition:
    hash.sha256(0, filesize) == "0483096fdaf43af168b243448dbb8cddfbea4529c3cd43e284d576b718311ef9"
}

rule MalwareBazaar_unknown_090_2e987f7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3"
    family = "unknown"
    file_name = "2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:09:11"
  condition:
    hash.sha256(0, filesize) == "2e987f7ca6c3f481e7235d13d712c7ea5042d8f01df397d951870c59843cdea3"
}

rule MalwareBazaar_unknown_091_3fc727a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b"
    family = "unknown"
    file_name = "3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:07:25"
  condition:
    hash.sha256(0, filesize) == "3fc727a3b0e7a071b27a1831511a6f0993eb40862c5e60bf45ec10301b13531b"
}

rule MalwareBazaar_unknown_092_703e375f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e"
    family = "unknown"
    file_name = "703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:07:14"
  condition:
    hash.sha256(0, filesize) == "703e375fe6e77e527f1f71880a4851015f25b88a11e4e6d156452bd7fe4e343e"
}

rule MalwareBazaar_ConnectWise_093_88ba0868
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2"
    family = "ConnectWise"
    file_name = "88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:07:08"
  condition:
    hash.sha256(0, filesize) == "88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2"
}

rule MalwareBazaar_SalatStealer_094_3113ee11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3113ee11493601692e16664295d4f64b1c8407be91085d904880ec350305a5b1"
    family = "SalatStealer"
    file_name = "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:05:30"
  condition:
    hash.sha256(0, filesize) == "3113ee11493601692e16664295d4f64b1c8407be91085d904880ec350305a5b1"
}

rule MalwareBazaar_unknown_095_85bb4cb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85bb4cb9fd9590ca3549a4897255c6f01ea0d9eff77b487d031381c86db6b3c3"
    family = "unknown"
    file_name = "楽天 インサイト.apk"
    file_type = "apk"
    first_seen = "2026-11-19 01:05:06"
  condition:
    hash.sha256(0, filesize) == "85bb4cb9fd9590ca3549a4897255c6f01ea0d9eff77b487d031381c86db6b3c3"
}

rule MalwareBazaar_unknown_096_066ab138
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4"
    family = "unknown"
    file_name = "066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:04:32"
  condition:
    hash.sha256(0, filesize) == "066ab138c6022b7c7b7c1e89eabf7cb6f052a3ac581f6e39db8c82f7387a2ef4"
}

rule MalwareBazaar_unknown_097_6c80bb36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5"
    family = "unknown"
    file_name = "6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:04:26"
  condition:
    hash.sha256(0, filesize) == "6c80bb36afc32fcb5558ff2942280fd812d9998a00e543ef3e34ffd129d3a5d5"
}

rule MalwareBazaar_SalatStealer_098_1504be43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a"
    family = "SalatStealer"
    file_name = "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a.exe"
    file_type = "exe"
    first_seen = "2026-11-19 01:04:18"
  condition:
    hash.sha256(0, filesize) == "1504be43c17da2682cd43e9a201b149a8f6862037739ac5e34df4b3acb33306a"
}

rule MalwareBazaar_unknown_099_348b109f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c"
    family = "unknown"
    file_name = "348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c.bin"
    file_type = "macho"
    first_seen = "2026-11-19 01:03:13"
  condition:
    hash.sha256(0, filesize) == "348b109f2232a3280f1593ac0722b1f4feb44563c9d80a0543ac06972ad32e6c"
}

rule MalwareBazaar_unknown_100_341a382d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767"
    family = "unknown"
    file_name = "341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767.elf"
    file_type = "elf"
    first_seen = "2026-11-19 01:02:17"
  condition:
    hash.sha256(0, filesize) == "341a382d6f9e54007b4254f88a169a1c6879ac6415cd8e55792afb11652d2767"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

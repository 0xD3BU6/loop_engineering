# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-22

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 656 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 656 |
| Unique family labels | 6 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 55 |
| unknown | 40 |
| Snowlight | 2 |
| Gafgyt | 1 |
| ConnectWise | 1 |
| AgentTesla | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 64 |
| exe | 20 |
| macho | 7 |
| apk | 3 |
| hta | 2 |
| sh | 1 |
| msi | 1 |
| zip | 1 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `9fb95a7aa0a78ef1`

| Field | Value |
|---|---|
| SHA-256 | `9fb95a7aa0a78ef144cf49b4c97bfd2478e835ea05acdb0f5311c0aa138ff145` |
| Family label | `unknown` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-22 05:07:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b60787b9063737e426ac44c4ed07400` |
| SHA-1 | `53f4d23622f548394821b237785454267c24d89c` |
| SHA-256 | `9fb95a7aa0a78ef144cf49b4c97bfd2478e835ea05acdb0f5311c0aa138ff145` |
| SHA3-384 | `da690e9e618a63a8a293a0e20d1fc5157849f99ca8985912390ac14813f217550567f8a8fd854a55fa1b994dd38cadbe` |
| TLSH | `T1A56339CAF401DE7DF85AEA7B0C130D58A272F3614A830F265B57FE6BE931158195BC82` |
| SSDEEP | `1536:aB+0eOneolzdEIP7jBH96aNQeuacWjcW0JcWcBvxyFpyJxbSW8ljVu:KzzdEIP7jTNQeuacWjcW0JcWcB58pySG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_9fb95a7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb95a7aa0a78ef144cf49b4c97bfd2478e835ea05acdb0f5311c0aa138ff145"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-22 05:07:50"
  condition:
    hash.sha256(0, filesize) == "9fb95a7aa0a78ef144cf49b4c97bfd2478e835ea05acdb0f5311c0aa138ff145"
}
```

### Sample 2: `2b028191a4e34a9d`

| Field | Value |
|---|---|
| SHA-256 | `2b028191a4e34a9d7e83e7a98e242541d377dcce3495437b3d3e4a2c80c6d4a8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 05:06:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b718b1ca12be85f10ad4ef64bdd74f61` |
| SHA-1 | `476707862fafc33b44d96acb4e24bc19aab94c5f` |
| SHA-256 | `2b028191a4e34a9d7e83e7a98e242541d377dcce3495437b3d3e4a2c80c6d4a8` |
| SHA3-384 | `8027a437e82e1389d5fe342d224171af505ad32f08a00549ba3a743a266f64e43d1dd3dfdf977d08736e58b46227dd3a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16462D786D8921F5DDE4EC0703A11F938BAB537D04A256AF3D7928C3159AB9D00028FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uc6EDD:fKOe2/7c9sN3zfZR1m+RGjDa6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_2b028191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b028191a4e34a9d7e83e7a98e242541d377dcce3495437b3d3e4a2c80c6d4a8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 05:06:50"
  condition:
    hash.sha256(0, filesize) == "2b028191a4e34a9d7e83e7a98e242541d377dcce3495437b3d3e4a2c80c6d4a8"
}
```

### Sample 3: `4824b25eb3946999`

| Field | Value |
|---|---|
| SHA-256 | `4824b25eb39469992af6ec1a4f86239fd457aaeea84efcae1e1c8c9f62c78ab6` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-22 05:00:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10d7e474fffafae5e49bc715e5e6cf72` |
| SHA-1 | `2ce17b752844f79aad43d64f207da66b35932ea0` |
| SHA-256 | `4824b25eb39469992af6ec1a4f86239fd457aaeea84efcae1e1c8c9f62c78ab6` |
| SHA3-384 | `f7e1ccaa2c688ae082d5baf312aa71a3f1ab9bccd4383f9c5e4a409f5b6f396f557e3a71ffb8ad155dd0822ca938d72f` |
| TLSH | `T12AE33946FC819F11D9D629BAFE6E424833531BB8D3FA71129E105F2423CA92B0F7B915` |
| TELFHASH | `t12031eee7eb540aec6bd69244924e706e9afa35cb2f14349b8a1ca75fd602cd0703d437` |
| SSDEEP | `3072:fc3rNRMcSXCsO5zlx84MxyaNqnvXpTt5SfqO+tClor4deH5+:aWXCsO/x842yaNqnvXJt5SSdCarg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_4824b25e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4824b25eb39469992af6ec1a4f86239fd457aaeea84efcae1e1c8c9f62c78ab6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-22 05:00:41"
  condition:
    hash.sha256(0, filesize) == "4824b25eb39469992af6ec1a4f86239fd457aaeea84efcae1e1c8c9f62c78ab6"
}
```

### Sample 4: `b55300d14b8e52cf`

| Field | Value |
|---|---|
| SHA-256 | `b55300d14b8e52cfc4acaba43eec15bc6058b860483f9132d9df0843b6838bd9` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-22 05:00:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd62055d8bae90bb657ee9a5fbd39cb1` |
| SHA-1 | `a02edbba8a938e66b3b5a9b48d142d1241dc1336` |
| SHA-256 | `b55300d14b8e52cfc4acaba43eec15bc6058b860483f9132d9df0843b6838bd9` |
| SHA3-384 | `9a8ded4cf756199dbf8b8d18911e0db4f8de0c6714d9a6b74a81b279208eb3232a5c43ae77f203710f776d64be504638` |
| TLSH | `T141530201A55046D3D2816B33FE150A8797E2B99357FFB872BD019BD8FE12412F9B4609` |
| SSDEEP | `1536:H1Hz97ErVmx4ZFVTQb33b92vy00oa4TZntJ:HCkuTG3L9ey00o1Tl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_b55300d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b55300d14b8e52cfc4acaba43eec15bc6058b860483f9132d9df0843b6838bd9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-22 05:00:24"
  condition:
    hash.sha256(0, filesize) == "b55300d14b8e52cfc4acaba43eec15bc6058b860483f9132d9df0843b6838bd9"
}
```

### Sample 5: `4e1be65b2bbbb73f`

| Field | Value |
|---|---|
| SHA-256 | `4e1be65b2bbbb73ff6fe6c1c9cfef0fa250b1ceaae02f89d3c3d028056ba601b` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-22 04:57:41` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d3089f13dec251924e053b35a7b09c2` |
| SHA-1 | `03f463869112428e4d79b212075b9ef0f3207ea9` |
| SHA-256 | `4e1be65b2bbbb73ff6fe6c1c9cfef0fa250b1ceaae02f89d3c3d028056ba601b` |
| SHA3-384 | `0f5fa7ad6be1953a10c16f9f6d2e3f942a4143abb772834f3aa6ebd1a4d80aaf77b2bd661da254b497fc27e5647d4ead` |
| TLSH | `T1754183C952700975682BD94DF2B9B888719EF1FB2E8B57E4CCCC1DA95108A46F041B4D` |
| SSDEEP | `24:EsgZ0fNIzAKYyfUJqKUSwp6RQiuMxWNT2dSTsysCGTsOsRs:EsgZlAgJKUSy6RQQgTWSTsysCysOsRs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_4e1be65b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e1be65b2bbbb73ff6fe6c1c9cfef0fa250b1ceaae02f89d3c3d028056ba601b"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-22 04:57:41"
  condition:
    hash.sha256(0, filesize) == "4e1be65b2bbbb73ff6fe6c1c9cfef0fa250b1ceaae02f89d3c3d028056ba601b"
}
```

### Sample 6: `88ff66c702150325`

| Field | Value |
|---|---|
| SHA-256 | `88ff66c7021503253a2523c5fd779a2643457cc3f5fb9cd6b3c81272f8efb20b` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-09-22 04:57:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0450ea2774a5e6b3b4137144e06df6b3` |
| SHA-1 | `a53567de3cc2f41f1ac8132c734aa6eb6904c16a` |
| SHA-256 | `88ff66c7021503253a2523c5fd779a2643457cc3f5fb9cd6b3c81272f8efb20b` |
| SHA3-384 | `7614cfb0ccc247d229c8437221f7ed8f5215804a40b735bb9d6bbc973b8a4ef39c297095121300fdfff0135e2b868e61` |
| TLSH | `T1F8437CC8A253DAF5DC490A7810B3F7776637F67B3118E983D3A96D23AD83B00A44529D` |
| TELFHASH | `t11f2125f71df908ecb3c48841c20a97e20a79e53f2641766543b1bcd023e2fa05025c3d` |
| SSDEEP | `1536:h5PkdnU2KNd/oKrqykuaFrAIPlZphpjeuBW:LPkdnU2KD/oKrqykuGlHCuB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_88ff66c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ff66c7021503253a2523c5fd779a2643457cc3f5fb9cd6b3c81272f8efb20b"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-09-22 04:57:40"
  condition:
    hash.sha256(0, filesize) == "88ff66c7021503253a2523c5fd779a2643457cc3f5fb9cd6b3c81272f8efb20b"
}
```

### Sample 7: `a1baca3a9b387aa4`

| Field | Value |
|---|---|
| SHA-256 | `a1baca3a9b387aa478edeed198bd6263fdc60c6850281c4da8836915cc4fc404` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-22 04:56:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d1ee8efd7be1348c31b5f3a0332c878` |
| SHA-1 | `6c8c93f77a2c8dd32a8c40b5be1e87fb820c4180` |
| SHA-256 | `a1baca3a9b387aa478edeed198bd6263fdc60c6850281c4da8836915cc4fc404` |
| SHA3-384 | `eb9902d651a78511699518953fe800f12859632e9f09c01239c897be7f960ec6a70c4a83246ce5df8ef0ff629e437dd6` |
| TLSH | `T10FB35B02B5C0E8FCCC86C238436F6635DA32F66A1278B65F27D4EF153D5DF212A29A54` |
| TELFHASH | `t16c41beb02d99699810e7a725b20fe4e8dc7119301ae135f0af2b6de3de02f880c86467` |
| SSDEEP | `3072:IPrwQea2Guc4lDs1jGejGnXDcsX81xpd8WfaAUTKn7Vh2l:YCaN4D+0ly3d8Wall` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_a1baca3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1baca3a9b387aa478edeed198bd6263fdc60c6850281c4da8836915cc4fc404"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:56:18"
  condition:
    hash.sha256(0, filesize) == "a1baca3a9b387aa478edeed198bd6263fdc60c6850281c4da8836915cc4fc404"
}
```

### Sample 8: `f28609e7a34618ad`

| Field | Value |
|---|---|
| SHA-256 | `f28609e7a34618adf7487d8b257637faa648982774fbc81f31bdc71efaa608c3` |
| Family label | `Gafgyt` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-22 04:55:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca9a5c1c8c5f4154a63760053e481703` |
| SHA-1 | `f2036a00a0a1daf96273b414ba774e7df5f333f1` |
| SHA-256 | `f28609e7a34618adf7487d8b257637faa648982774fbc81f31bdc71efaa608c3` |
| SHA3-384 | `d128db90fcaeff9e8a42240d938319f8dfa9f9e05f3687132dd7639dd53c36af57e5e77c67d039bff93cf239ec686e2c` |
| TLSH | `T1FA33F1BF156FE634D2A24EBDF9A14BDCB635F32184264B37454C68FABD094122B35E20` |
| SSDEEP | `768:AM8n/JyhSkyVI8YgUhQpqPd0MiZY1ywtX5kr2DSjigHRbkNesokvfcnTapc4n:Ajn/JaSfTmQk6MitwterbikoNekuS9` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_008_f28609e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f28609e7a34618adf7487d8b257637faa648982774fbc81f31bdc71efaa608c3"
    family = "Gafgyt"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:55:19"
  condition:
    hash.sha256(0, filesize) == "f28609e7a34618adf7487d8b257637faa648982774fbc81f31bdc71efaa608c3"
}
```

### Sample 9: `6d452b17f963cd2e`

| Field | Value |
|---|---|
| SHA-256 | `6d452b17f963cd2e1636d1c1e1baa8f5b6663f5bc4d55a90e95d1fb926c15139` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-22 04:50:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b78283fac8c12e020a16d160d62fa7f` |
| SHA-1 | `62be70258b8cebca2eec1e0628d613099c91b39b` |
| SHA-256 | `6d452b17f963cd2e1636d1c1e1baa8f5b6663f5bc4d55a90e95d1fb926c15139` |
| SHA3-384 | `6c08708029b86b9d57f6e08153e7a4f73d4fb745c90cfe65a2c0b32206cf9f7e8bc46f1054d5834893fb6c6792f340c8` |
| TLSH | `T137C36C32BA395D2BC5D0A57A22F34335F4F6438A20F8991E3DA10D9CEF656503267BE4` |
| SSDEEP | `3072:zHoxYFRbjRFmW5AWfpNX94H2Dr/G312SPU:zHoxYFAW5AuN9VvlL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_6d452b17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d452b17f963cd2e1636d1c1e1baa8f5b6663f5bc4d55a90e95d1fb926c15139"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-22 04:50:24"
  condition:
    hash.sha256(0, filesize) == "6d452b17f963cd2e1636d1c1e1baa8f5b6663f5bc4d55a90e95d1fb926c15139"
}
```

### Sample 10: `3280724b7856f29b`

| Field | Value |
|---|---|
| SHA-256 | `3280724b7856f29be56ecbabfdbd43018a488e95462dfce5d61fe582b044327a` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-09-22 04:47:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7017f8e7a34ce2bbb6edc9fa08b2cf7` |
| SHA-1 | `68ad3ac165872690abd7a746dfcfd4541e994c2a` |
| SHA-256 | `3280724b7856f29be56ecbabfdbd43018a488e95462dfce5d61fe582b044327a` |
| SHA3-384 | `811b448aa6860ce6a41456cb67985c23b13bec86e2881cfc773e76b283a126f0908bb1176467ac4f2bd439f6d48f8c04` |
| TLSH | `T155540809FB8DDE8BC15083B54DAB0B227335D8A83746D7936719A53EECAB34C9E4254C` |
| TELFHASH | `t19d21fe8c993d09596a933574dcac27b0e50a8872ae660f21cf14c781456e19a910ee3f` |
| SSDEEP | `3072:M4sLv5E/cgw5KqzY8vCB4MzII7ZNHQx71yP7VT1HqaKmks/ic1iWK:wb2WKmY8vCB7lHE4T1HQsaiiWK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_3280724b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3280724b7856f29be56ecbabfdbd43018a488e95462dfce5d61fe582b044327a"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-09-22 04:47:42"
  condition:
    hash.sha256(0, filesize) == "3280724b7856f29be56ecbabfdbd43018a488e95462dfce5d61fe582b044327a"
}
```

### Sample 11: `3b33bd887a1de3f0`

| Field | Value |
|---|---|
| SHA-256 | `3b33bd887a1de3f0935c10d159dca99e123dc251a3074c2caf5085ed21334ee2` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-22 04:46:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19f43793fc5cf588b032505d252ed4ba` |
| SHA-1 | `db57c2c6011a6a9eac2222c1febaa175f31aea1c` |
| SHA-256 | `3b33bd887a1de3f0935c10d159dca99e123dc251a3074c2caf5085ed21334ee2` |
| SHA3-384 | `b8f83fecaf61e10803b796b3cf3f33d8f5a4db16b1d46b5e3b26fbfc94d682b751490fec90ad9132af5decad8cb2d62b` |
| TLSH | `T1D7D35B56BC818A11C5C21ABAFE2E524D331317BCE3EE72179E105F34638B96B0E3B655` |
| SSDEEP | `3072:Bi3fie4WilcU5AlqTxeh00aJrgfbfGG4RfwHQhxqOHcpR:PeecU5uqTshNalgfbEfqQXiR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_3b33bd88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b33bd887a1de3f0935c10d159dca99e123dc251a3074c2caf5085ed21334ee2"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-22 04:46:19"
  condition:
    hash.sha256(0, filesize) == "3b33bd887a1de3f0935c10d159dca99e123dc251a3074c2caf5085ed21334ee2"
}
```

### Sample 12: `656e539abc54f262`

| Field | Value |
|---|---|
| SHA-256 | `656e539abc54f262eabb6d091df50f9bec71a55905421f0a3fc2eb451aa0409e` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-22 04:45:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8f98a7f520fdb3b95cab4f5645d4dd3` |
| SHA-1 | `73cb1bd86f6dd7e9912c5e3c6bd3462631b2d514` |
| SHA-256 | `656e539abc54f262eabb6d091df50f9bec71a55905421f0a3fc2eb451aa0409e` |
| SHA3-384 | `344cbef6ecdfc1da72509fe7bf2ec75d8f3e242452a1ed935fa9597eb2ef62c55c7cd8b2c121423f770fe671881f6663` |
| TLSH | `T14E43027A5BED8102C1A00639F852F79DA611DFB89D9CB2481F2B0E2D39530561F71BD7` |
| SSDEEP | `1536:49CjzLBrChWq7r/A9r8igk8sKUmRBI9mIbIx1BlY6Qs:dh8UzKUmRezbIx1Blt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_656e539a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "656e539abc54f262eabb6d091df50f9bec71a55905421f0a3fc2eb451aa0409e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-22 04:45:20"
  condition:
    hash.sha256(0, filesize) == "656e539abc54f262eabb6d091df50f9bec71a55905421f0a3fc2eb451aa0409e"
}
```

### Sample 13: `e6c0edd85dcef6c6`

| Field | Value |
|---|---|
| SHA-256 | `e6c0edd85dcef6c64d9afcc6503f31e2d9bf142a65c193191434db7f4a938c93` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-09-22 04:37:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f9b51d1192990e14d31cef33df11156` |
| SHA-1 | `65f497ff6ae2975e34cd56fabd0f275a3c05158e` |
| SHA-256 | `e6c0edd85dcef6c64d9afcc6503f31e2d9bf142a65c193191434db7f4a938c93` |
| SHA3-384 | `748ecdb68c03f6a9df43b3d9e784815e67a888f9bcab8e13a226daa4cbdba025cb7fa49b669c86e28bb7cc42967dcf76` |
| TLSH | `T1C4632A45B8829B26C6D9237EFA2D108E3313A768E3DF7222DD115F5173C656B0E7A902` |
| TELFHASH | `t1f7f0c9259b961edc6bf888ed640e120a06cd74fdab01305faf1e278fd6031c1f7a180a` |
| SSDEEP | `1536:F/nz5Zcu42kbCeB48DEUIDYiYzWIwMi1pyDKV:p5ebFbCeBIUWpyDKV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_e6c0edd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6c0edd85dcef6c64d9afcc6503f31e2d9bf142a65c193191434db7f4a938c93"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-22 04:37:48"
  condition:
    hash.sha256(0, filesize) == "e6c0edd85dcef6c64d9afcc6503f31e2d9bf142a65c193191434db7f4a938c93"
}
```

### Sample 14: `34c3403102077f7c`

| Field | Value |
|---|---|
| SHA-256 | `34c3403102077f7cb506794533d855a229f457e210fb0848e836805f61136738` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:36:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9327cc816ee48073bd8ee534629a895` |
| SHA-1 | `d9ded1ec9e37d181f091361eb56a66512a5103d8` |
| SHA-256 | `34c3403102077f7cb506794533d855a229f457e210fb0848e836805f61136738` |
| SHA3-384 | `c32c39414bfa27eb9643e59d2fd593f1529d40bb7ce2098e923c5e305c609b39ab339952596f6c2ffed43270153e0fc8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B062C786AAE16BACDE4EC0703B11F938ADB03691866559F3D7C28D348DA39D00524FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uqn+8e:fKOe2/7c9sN3zfZR1m+RGtn+86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_34c34031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34c3403102077f7cb506794533d855a229f457e210fb0848e836805f61136738"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:36:27"
  condition:
    hash.sha256(0, filesize) == "34c3403102077f7cb506794533d855a229f457e210fb0848e836805f61136738"
}
```

### Sample 15: `8ff4db8ba96b9f1f`

| Field | Value |
|---|---|
| SHA-256 | `8ff4db8ba96b9f1fc116320d24f6b3705b0f3d9b27dfe9c87795ba5bc21e6eac` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:35:21` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae4a5af7110878d5ebf2fc8adb70df34` |
| SHA-1 | `7e2b2e9cbae86dce40f83056f975bc4611d0593b` |
| SHA-256 | `8ff4db8ba96b9f1fc116320d24f6b3705b0f3d9b27dfe9c87795ba5bc21e6eac` |
| SHA3-384 | `39accad0a39402cb2cbc726e43ae9ec395e9760d8ea406e41c05029450fa06539345e5427c55f4fa55c0d0ce71fbed80` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18262B696D8E22FADCE4F80707A21FC786AB47690856599E3D7828C315EA39D10434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ues/BM:fKOe2/7c9sN3zfZR1m+RG86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_8ff4db8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ff4db8ba96b9f1fc116320d24f6b3705b0f3d9b27dfe9c87795ba5bc21e6eac"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:35:21"
  condition:
    hash.sha256(0, filesize) == "8ff4db8ba96b9f1fc116320d24f6b3705b0f3d9b27dfe9c87795ba5bc21e6eac"
}
```

### Sample 16: `0fa58edeec9dd4bb`

| Field | Value |
|---|---|
| SHA-256 | `0fa58edeec9dd4bb18b48f8bcdaad4b22067f8eae6b6845c4450fabce4e2de71` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:34:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a533408b2f88dc22aac65a0eed9f2d16` |
| SHA-1 | `83ba6427cee168b1a59477e8335b15fb4366197c` |
| SHA-256 | `0fa58edeec9dd4bb18b48f8bcdaad4b22067f8eae6b6845c4450fabce4e2de71` |
| SHA3-384 | `2f769e00f6f70956bfab91a378e33e88c76d0f71ba72f48a0a4304f5efe935d38b249a85523f5a71d1ef6e51da2c245d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15B62D686DDA29F6CCE4E94703A11F838BD757AD08A659DE3D7828C325DA78D00024EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U4BgCc:fKOe2/7c9sN3zfZR1m+RGz6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_0fa58ede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fa58edeec9dd4bb18b48f8bcdaad4b22067f8eae6b6845c4450fabce4e2de71"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:34:08"
  condition:
    hash.sha256(0, filesize) == "0fa58edeec9dd4bb18b48f8bcdaad4b22067f8eae6b6845c4450fabce4e2de71"
}
```

### Sample 17: `f881db27f82e58f7`

| Field | Value |
|---|---|
| SHA-256 | `f881db27f82e58f72bf6475130f23a3cf12dbec3688fcf7b15901fbb543d8c79` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-22 04:33:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd14ed67799f6bd9358b5083e09d9dff` |
| SHA-1 | `9e20ae268fb09db0a3440167a360834097e80b4a` |
| SHA-256 | `f881db27f82e58f72bf6475130f23a3cf12dbec3688fcf7b15901fbb543d8c79` |
| SHA3-384 | `a1fd8d971e87e0f5e31261a49ae176b1d1b9634c80b08a29b4aa6bc649a790669364b6bdf6ab86608fed85b4251d3e0e` |
| TLSH | `T15CC33B03B5D24CFAC0C7C639935B9221E537F87523126A272398AE763E2EF141F49769` |
| TELFHASH | `t19d21fe8c993d09596a933574dcac27b0e50a8872ae660f21cf14c781456e19a910ee3f` |
| SSDEEP | `1536:ehpHFQrfa7jGGFhwuEdx3UlmTZ98cyngOEK4Ybh3a/C/NqaPzgs7P+0UHregKjq:ox7hCJZWcyYO3aAJPjtULegKjq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_f881db27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f881db27f82e58f72bf6475130f23a3cf12dbec3688fcf7b15901fbb543d8c79"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:33:15"
  condition:
    hash.sha256(0, filesize) == "f881db27f82e58f72bf6475130f23a3cf12dbec3688fcf7b15901fbb543d8c79"
}
```

### Sample 18: `7ee4e76a81d8ad7c`

| Field | Value |
|---|---|
| SHA-256 | `7ee4e76a81d8ad7cfcd235dff014376972ab6af8de3fcbc59d6f85a7a84ae551` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:32:56` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `921128b77cb57eedbd91555c86f6d218` |
| SHA-1 | `4f9021dc563de2a53ca18ffa79d521ddd7d91c8c` |
| SHA-256 | `7ee4e76a81d8ad7cfcd235dff014376972ab6af8de3fcbc59d6f85a7a84ae551` |
| SHA3-384 | `436060b637682772bb04db0aac5212e79d720cd6847cb872468cb7ac12036b0d78ecd9b2a69a3000b83326d375a91ea2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14262C58AD8A22A5CDE4ED0703F51F878ED713AA1C6A599F3D7928C355DA39D00024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UaBgCc:fKOe2/7c9sN3zfZR1m+RGB6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_7ee4e76a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ee4e76a81d8ad7cfcd235dff014376972ab6af8de3fcbc59d6f85a7a84ae551"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:32:56"
  condition:
    hash.sha256(0, filesize) == "7ee4e76a81d8ad7cfcd235dff014376972ab6af8de3fcbc59d6f85a7a84ae551"
}
```

### Sample 19: `6ff24f7acce25788`

| Field | Value |
|---|---|
| SHA-256 | `6ff24f7acce257889f3475be2b0862c3cb9b2d3c6f6668d5883b970cec0f3aaa` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-09-22 04:30:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18e7fc43831157e19b1bb9277c38b032` |
| SHA-1 | `daf6c45821c9158db5b94a2060f291080d1b6f67` |
| SHA-256 | `6ff24f7acce257889f3475be2b0862c3cb9b2d3c6f6668d5883b970cec0f3aaa` |
| SHA3-384 | `91120ab6e2f1a3341915682e050af87d6ef0965845786b5a3491d8efada19ae1da8a1dd0fb6bad1f3bb5fc48942a5250` |
| TLSH | `T109634B94B8815627C6DD337FF72D118D33269768E2EF32029A291F6173C6A2B0E77542` |
| TELFHASH | `t1aa21cdfa9e86068c6bd4c340408e61598eec32bc1b416169cf0aab4f50934c0b72d43d` |
| SSDEEP | `1536:0VJlT5NhkKT7R1+MkVloK6c0FyZrxkAF6+eC59u:0d5I619X+MUdkAF6+eC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_6ff24f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff24f7acce257889f3475be2b0862c3cb9b2d3c6f6668d5883b970cec0f3aaa"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-09-22 04:30:31"
  condition:
    hash.sha256(0, filesize) == "6ff24f7acce257889f3475be2b0862c3cb9b2d3c6f6668d5883b970cec0f3aaa"
}
```

### Sample 20: `4cc356f289e07ab0`

| Field | Value |
|---|---|
| SHA-256 | `4cc356f289e07ab01e8cea91a99c484a71497674933e084eb571799e494875b3` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-22 04:30:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe4f06102e899e7defc5c34a25632305` |
| SHA-1 | `6d224941a1eb2a0888c21a7d483d5aeb7b0520b1` |
| SHA-256 | `4cc356f289e07ab01e8cea91a99c484a71497674933e084eb571799e494875b3` |
| SHA3-384 | `4472b12a3db1dd8c1de793889c4aa1d1a5f7410fbdcbe227c7192038f69c4bbb48abfa247b8e2ffc5be562b638216a57` |
| TLSH | `T1CD83C50A5E208FACFB9A833187F74E25965C33A627E1C285D25CD9041EB434E645FFAD` |
| TELFHASH | `t19e21b41ad53c03f4d7c05cac6bedfb32e46190ef5a266d378e14dd9b9a59981ae00c1c` |
| SSDEEP | `768:jNu1VaC5UFMeeZlxHRnCODiVM43WAgZZMy4atMZhkptnLE2E0VD4gzB2xkXt0QZz:hMksDHR2VZgZx4at5tnLKgzcyButRuyk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_4cc356f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc356f289e07ab01e8cea91a99c484a71497674933e084eb571799e494875b3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:30:30"
  condition:
    hash.sha256(0, filesize) == "4cc356f289e07ab01e8cea91a99c484a71497674933e084eb571799e494875b3"
}
```

### Sample 21: `e477d71b715cc76b`

| Field | Value |
|---|---|
| SHA-256 | `e477d71b715cc76bd775b3c1e533c0d58c617687ca9286f9b77e01fa1d7af1df` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-22 04:30:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa64c051729f48ccc7d5cbee3a725f3b` |
| SHA-1 | `e9a8def84444349813de7fd7c8d0552cc14a5f11` |
| SHA-256 | `e477d71b715cc76bd775b3c1e533c0d58c617687ca9286f9b77e01fa1d7af1df` |
| SHA3-384 | `7fc6be139c25f58af75519685cde03a4e5bf46ee5e5daae4c8319cdcc3de8d53910b0f10fc88d00acd2553d1408270d9` |
| TLSH | `T18DD36DDAF500EEBEF40AEB3B44570606B230E3611A825B32635BB573F9361E56C26F45` |
| SSDEEP | `3072:iRLPJ+caxCFyIAMyOWFcNe/WXH8f4c7Vew8Y:idhYOyI/ynFz/fwhY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_e477d71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e477d71b715cc76bd775b3c1e533c0d58c617687ca9286f9b77e01fa1d7af1df"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-22 04:30:29"
  condition:
    hash.sha256(0, filesize) == "e477d71b715cc76bd775b3c1e533c0d58c617687ca9286f9b77e01fa1d7af1df"
}
```

### Sample 22: `7708a9dad1e14af5`

| Field | Value |
|---|---|
| SHA-256 | `7708a9dad1e14af5ffff9fb8e3d9505005d8c70a184a3ece34e589697ae22241` |
| Family label | `unknown` |
| File name | `fuck_niggers_39.hta` |
| File type | `hta` |
| First seen | `2026-09-22 04:30:27` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84493a3b9d78d9d60165d2a02224ddac` |
| SHA-1 | `6232fa88303a3b2e41fc51805d15b5ba42f6048c` |
| SHA-256 | `7708a9dad1e14af5ffff9fb8e3d9505005d8c70a184a3ece34e589697ae22241` |
| SHA3-384 | `4d7df3527ad2e06d15b31fc090f4cd212ff5f58302b22c1f23f17aacdc5b99d75445aa800af91f1bc085013d9ffd95bc` |
| TLSH | `T1B842FA5C9EE1B2B4F25703EF7BBB292D136461C71408C884F64CADE46F0B78D8652B5A` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxz6IQBaK79wFhI3L:sXX+/DV7k/3bPKRoq3L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_7708a9da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7708a9dad1e14af5ffff9fb8e3d9505005d8c70a184a3ece34e589697ae22241"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-09-22 04:30:27"
  condition:
    hash.sha256(0, filesize) == "7708a9dad1e14af5ffff9fb8e3d9505005d8c70a184a3ece34e589697ae22241"
}
```

### Sample 23: `d905e0552d522984`

| Field | Value |
|---|---|
| SHA-256 | `d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8` |
| Family label | `unknown` |
| File name | `d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8.bin` |
| File type | `macho` |
| First seen | `2026-09-22 04:30:03` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9788a413134650e02ab01833edf1ef7f` |
| SHA-1 | `523adf27617fd0c47062836fcd166f59e0b2a88e` |
| SHA-256 | `d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8` |
| SHA3-384 | `56cd8c385d3742f22c9c9affe6ad27aed8680ef88efaf70818799efc5f8495962f5d530956a9cd919d4f6445b6500bfb` |
| TLSH | `T1BDF263239B1C5922C88C663842BB6742A23AF1E145D677774B00C72DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7QHD4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7ADMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_d905e055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8"
    family = "unknown"
    file_name = "d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:30:03"
  condition:
    hash.sha256(0, filesize) == "d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8"
}
```

### Sample 24: `5ee6fd37ac43946e`

| Field | Value |
|---|---|
| SHA-256 | `5ee6fd37ac43946e7bbd556bfd730c11d725ce0bc2b0dc734688f936f216ce2f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:27:04` |
| Reporter | `Bitsight` |
| Tags | `579cd0, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecef61f6f8abfd7a98f254ad9537ec66` |
| SHA-1 | `6dd407470563347e6df4f944e035e09be47b5cf9` |
| SHA-256 | `5ee6fd37ac43946e7bbd556bfd730c11d725ce0bc2b0dc734688f936f216ce2f` |
| SHA3-384 | `fbac7c01a4f092d2cd3d9edcc0879b0fd66660b9ef3f774550ae05b8a1feefe3c51167c073c3b51dc073e4808a270eba` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T111B61237B28A653EE06E1A365AB3E210543B7A61AC134D1ED7F4489CCF251A03E3F657` |
| SSDEEP | `98304:VAX7EZNJElKLdM2jAsqd+82B/VivzgTYp0oRPcr6DJKHl3NK:UGY8+2sBdAB/gbgTYpDI6DcHl3N` |
| ICON-DHASH | `94b4b5e4d060e4d8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_5ee6fd37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ee6fd37ac43946e7bbd556bfd730c11d725ce0bc2b0dc734688f936f216ce2f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:27:04"
  condition:
    hash.sha256(0, filesize) == "5ee6fd37ac43946e7bbd556bfd730c11d725ce0bc2b0dc734688f936f216ce2f"
}
```

### Sample 25: `2f6d1c289f18d782`

| Field | Value |
|---|---|
| SHA-256 | `2f6d1c289f18d78243840e5dad1f832e34a794e5b5f4b997fa4e95ae0b715527` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-22 04:25:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fad0dfc724297a86a0c41036d8bcda77` |
| SHA-1 | `5b976f46144b5952fd14ac03b5bcbe95b1180114` |
| SHA-256 | `2f6d1c289f18d78243840e5dad1f832e34a794e5b5f4b997fa4e95ae0b715527` |
| SHA3-384 | `3158d8e16dcd3ae6615a2c692535ddeaa687e0b9cc5111dc3be9677999b0e0e5515c8f87c4a722144a5699ffedba112f` |
| TLSH | `T15AC34C86BC819A12C6D316B6FF6E828C772753B8D3EE32039E155F24338B95A0E37545` |
| TELFHASH | `t1f5211190da5044de73f5c01891af120e0ae93899276b2d40db7e6e0f42ca4c5713cc33` |
| SSDEEP | `3072:PZfA3WQOqn+Y84Y7z7wqCKbyj7MLQ9wUUKYPMRHCT:Pp8OY84Y7z7I7MLowU2Pt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_2f6d1c28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6d1c289f18d78243840e5dad1f832e34a794e5b5f4b997fa4e95ae0b715527"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-22 04:25:40"
  condition:
    hash.sha256(0, filesize) == "2f6d1c289f18d78243840e5dad1f832e34a794e5b5f4b997fa4e95ae0b715527"
}
```

### Sample 26: `dfeea5e6642130bb`

| Field | Value |
|---|---|
| SHA-256 | `dfeea5e6642130bb2690f0d3928ae2b65e72b2f10ab38684468677ff0cc06b12` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-22 04:23:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6574b39a9c4ca0f8d5344592e131a6c5` |
| SHA-1 | `fe79991ca927a3cce38f6d0a28c076b0553423f1` |
| SHA-256 | `dfeea5e6642130bb2690f0d3928ae2b65e72b2f10ab38684468677ff0cc06b12` |
| SHA3-384 | `41ed66e0c05044722f81f7148b48cca1fa1d1cfbea6d4fc6e10bbb4a2e7621e158cc95c56cd11a9902a4787395db4072` |
| TLSH | `T11CE30A0ABF200DFBE8ABCD3786E91B45258C651322A87B767D74D928F54A24F19C3C74` |
| SSDEEP | `3072:MjVrGJy9oBVDzU35Ny/sV7c1UK+BgZ5HgBNR:MjcJqoBVk35nO1kh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_dfeea5e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfeea5e6642130bb2690f0d3928ae2b65e72b2f10ab38684468677ff0cc06b12"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:32"
  condition:
    hash.sha256(0, filesize) == "dfeea5e6642130bb2690f0d3928ae2b65e72b2f10ab38684468677ff0cc06b12"
}
```

### Sample 27: `0a36bf76fe54ed05`

| Field | Value |
|---|---|
| SHA-256 | `0a36bf76fe54ed05c2c000c8ed91e66c073b537e4559889d27db691bf94f2fa6` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-22 04:23:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dfe5f2b435f132d642f6bdb3e13fd7e` |
| SHA-1 | `e000bc86dcd9ac197d7ca437a60b254cb2fee49b` |
| SHA-256 | `0a36bf76fe54ed05c2c000c8ed91e66c073b537e4559889d27db691bf94f2fa6` |
| SHA3-384 | `80561b977db1e5eaecf183f379842cf2004404315a70c6fbf9297c5d34f14e46ea788d6d6609cf1b88f99a96ca6ed6f8` |
| TLSH | `T13A538C76E51C6FECD0442DF4A8348FBC1B23B044918B2EB16B9B8669048BDDDF5487B9` |
| SSDEEP | `768:+mIKpJi7LqGoEOhP82KVj2ADZer14emgoAbWvkH/EtzxTtECRK7MkBN:hhXzd82KVj20ZeBD+kH/EttTtECR5e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_0a36bf76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a36bf76fe54ed05c2c000c8ed91e66c073b537e4559889d27db691bf94f2fa6"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:18"
  condition:
    hash.sha256(0, filesize) == "0a36bf76fe54ed05c2c000c8ed91e66c073b537e4559889d27db691bf94f2fa6"
}
```

### Sample 28: `808a9695b9a67812`

| Field | Value |
|---|---|
| SHA-256 | `808a9695b9a6781293f766ce3b3d747884a8af143045f25b8727af445ff92509` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-09-22 04:23:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3576de22b507280678176e5c479b1741` |
| SHA-1 | `497d7e128c7c0ba29aa3947270d8d933d5c481c0` |
| SHA-256 | `808a9695b9a6781293f766ce3b3d747884a8af143045f25b8727af445ff92509` |
| SHA3-384 | `c2c693b320ead77ada723073f416bba807db68ca6aceb5c2a671345bc82d4c1fb121372f690e4a1dd37c24ddf3899be6` |
| TLSH | `T108C33B86BC419A12C6D31976FB6E428C772717B8D3EF3203CE255F24328B96A0E3B551` |
| TELFHASH | `t1f64100a7eba41fdd27da430492dea12b4bf8359e1b5d2456864c1b4f06c6ac2703dc37` |
| SSDEEP | `3072:Zw9Ui69dJi0BaF6x6y63U5Xhwqp9eHqs:ZwivJi0BaJ3U5xw6C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_808a9695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "808a9695b9a6781293f766ce3b3d747884a8af143045f25b8727af445ff92509"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:17"
  condition:
    hash.sha256(0, filesize) == "808a9695b9a6781293f766ce3b3d747884a8af143045f25b8727af445ff92509"
}
```

### Sample 29: `45742a7a1c3e6502`

| Field | Value |
|---|---|
| SHA-256 | `45742a7a1c3e6502161a70441a40d5a19d6abef81e9378eb988c9a0c8e0100c0` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-09-22 04:23:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cbd4c47f6fb0d50a0cc87b9cb5fb40f` |
| SHA-1 | `f45354e32c74bdf413a204e6f9e17a787b5d8015` |
| SHA-256 | `45742a7a1c3e6502161a70441a40d5a19d6abef81e9378eb988c9a0c8e0100c0` |
| SHA3-384 | `8a3fbb060fe4dc62f1b1f96a411e714cf5deedf499bdbc5be8b7bfac8be94916a4d8b38ee7214c37eaa12b360920a3aa` |
| TLSH | `T113735C21A6361E17C0E0A47E91F74766F2FD060E1468C64FBDA20EDEEF2857072576B8` |
| SSDEEP | `1536:XdJ0bb5Z3imMl/7Tvil2OqtG8K+EuvBWqbtYSBJ7:XdJ0bH3imKTul2fJEubfD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_45742a7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45742a7a1c3e6502161a70441a40d5a19d6abef81e9378eb988c9a0c8e0100c0"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:15"
  condition:
    hash.sha256(0, filesize) == "45742a7a1c3e6502161a70441a40d5a19d6abef81e9378eb988c9a0c8e0100c0"
}
```

### Sample 30: `ec65a69848c51546`

| Field | Value |
|---|---|
| SHA-256 | `ec65a69848c51546e38fdeea9ad5f1df8166a4fd5bf55b7410e491d6929b4539` |
| Family label | `unknown` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-09-22 04:23:14` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b68ad6c0fe14a5679bc74f253a683086` |
| SHA-1 | `5e6e1b52ca9dd26f7d64be946ecfd5cdc6d1ff9b` |
| SHA-256 | `ec65a69848c51546e38fdeea9ad5f1df8166a4fd5bf55b7410e491d6929b4539` |
| SHA3-384 | `52d42632bf56d672049fc3fd547b5ded5e722d0a48c8b504ff11af90a22e80c040d4aadaabdc523e80205820c505dc95` |
| TLSH | `T16D332AC8A683DEF0D91106B0B866F7326A36F43AB10DD8A7E7A8F5637D5378190451AC` |
| TELFHASH | `t1d52135ba5dfb4df8b7d05150c30aa7e6192bc6bb1a5077e540a25cc837d2ce190a4c3e` |
| SSDEEP | `768:QQXWc3I7qi0T3F+d4f+4wcWZuQHcNsaFAHG+g/KVkW0SARxCvUf:QQSN0TVg4fWcWoQHlaFAHG+t01xCvU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_ec65a698
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec65a69848c51546e38fdeea9ad5f1df8166a4fd5bf55b7410e491d6929b4539"
    family = "unknown"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:14"
  condition:
    hash.sha256(0, filesize) == "ec65a69848c51546e38fdeea9ad5f1df8166a4fd5bf55b7410e491d6929b4539"
}
```

### Sample 31: `9c390922b43100f2`

| Field | Value |
|---|---|
| SHA-256 | `9c390922b43100f26adef9a8324eab473803e4ccd51014fe1da460f25534b209` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-22 04:23:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05cdf95b80b4aff5f3b038f93ee70c71` |
| SHA-1 | `a53c1ff4eb7eb9339907ea0798426e42ab2682c1` |
| SHA-256 | `9c390922b43100f26adef9a8324eab473803e4ccd51014fe1da460f25534b209` |
| SHA3-384 | `1378e20d54c8e3e3d189c9f9a11c8fdfe031d11a6f2dc2839a321593084083be2008f6b1034386da5831035d5fd75901` |
| TLSH | `T12B4301BDED315C93EF694CBC50F51762984862C0B2FEB59B12D29C18C22F58C7A865F8` |
| SSDEEP | `1536:dOmI4358GPsEfv8IT7s05Iasa1vGd3emWt9MVdeKNj:98GE1ITYb8vSOrgVdZj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_9c390922
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c390922b43100f26adef9a8324eab473803e4ccd51014fe1da460f25534b209"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:13"
  condition:
    hash.sha256(0, filesize) == "9c390922b43100f26adef9a8324eab473803e4ccd51014fe1da460f25534b209"
}
```

### Sample 32: `868baedc6d4e5b10`

| Field | Value |
|---|---|
| SHA-256 | `868baedc6d4e5b1092e2dea434cc234263974e50d62755357785f6dd8a3de40e` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-22 04:21:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee4aad8cc9897abf5043304a2ec15807` |
| SHA-1 | `b9c254af4d2e0d52be4ec378b85a2850146f1429` |
| SHA-256 | `868baedc6d4e5b1092e2dea434cc234263974e50d62755357785f6dd8a3de40e` |
| SHA3-384 | `58b60b050b99886df6d17d7b1491a330739ede7c371635a8225be57c685629fdf52e1f6f559961ba60749a71673b88de` |
| TLSH | `T165E3C50E6E319F7DF669C73447B34B20D69923D727E1C685E2ACD1151E2034E642FBA8` |
| TELFHASH | `t1ce31d0184a7827e067315c991a9dff7bd5b031ef2b116c338e11a96e6b7dc825e20c0c` |
| SSDEEP | `3072:qAqdLueBpARCSaCNCG76GckXy4tjfQKEHMxq2+:EdxXzQhXPXq/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_868baedc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "868baedc6d4e5b1092e2dea434cc234263974e50d62755357785f6dd8a3de40e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:21:29"
  condition:
    hash.sha256(0, filesize) == "868baedc6d4e5b1092e2dea434cc234263974e50d62755357785f6dd8a3de40e"
}
```

### Sample 33: `337a809ff61b8c49`

| Field | Value |
|---|---|
| SHA-256 | `337a809ff61b8c49f6c0222c81b966ddf1d9ba7d55497ca81aa1680fcd1a3659` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-22 04:20:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d01e281a502439aa3a649a207f6a97f` |
| SHA-1 | `ead72493eda4414ef08594fbb1d8cf03dd886d14` |
| SHA-256 | `337a809ff61b8c49f6c0222c81b966ddf1d9ba7d55497ca81aa1680fcd1a3659` |
| SHA3-384 | `e4e706d14fc1317ede23c45ee9f2f0add1bfa5b773e418f211aac3dda832713ded7cb4c5cc1bc78954ba4b1502ac50c2` |
| TLSH | `T167430226700D1577EC0DADBFAF25064436310DFCA841E7893EB4EA2ED9D989E48479E3` |
| SSDEEP | `1536:F1pjD2s0InIREMJQtzmPOiF7TFwBFVEWL:F10nPE5obF7ZwXVE8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_337a809f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "337a809ff61b8c49f6c0222c81b966ddf1d9ba7d55497ca81aa1680fcd1a3659"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:20:44"
  condition:
    hash.sha256(0, filesize) == "337a809ff61b8c49f6c0222c81b966ddf1d9ba7d55497ca81aa1680fcd1a3659"
}
```

### Sample 34: `67a80d38322f97e9`

| Field | Value |
|---|---|
| SHA-256 | `67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84` |
| Family label | `unknown` |
| File name | `67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84.bin` |
| File type | `macho` |
| First seen | `2026-09-22 04:20:17` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `183e9a78e32034c4d2ce5afca25022b4` |
| SHA-1 | `d86cbbf91a45cf410489e390e3b1e0a688c7baff` |
| SHA-256 | `67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84` |
| SHA3-384 | `7bc354044370e1bf7fbaab743e15f41afa81596ddca259f3322fa6859676a36b34dce3ed692e6065653989450d4eca0c` |
| TLSH | `T154E25043675C5929D05D83B922FB1B576609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCEwYjqclS06W1YbqclSl:GI2n5DbDySwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_67a80d38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84"
    family = "unknown"
    file_name = "67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:20:17"
  condition:
    hash.sha256(0, filesize) == "67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84"
}
```

### Sample 35: `5a288187008c829a`

| Field | Value |
|---|---|
| SHA-256 | `5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7` |
| Family label | `Mirai` |
| File name | `5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7.bin` |
| File type | `elf` |
| First seen | `2026-09-22 04:20:13` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e7d948d945d7914b34aecb0f06c1190` |
| SHA-1 | `264b0f4ad5d204c80cfb3d5a2507cbb9269e1970` |
| SHA-256 | `5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7` |
| SHA3-384 | `fb32ab1536c357991f3880635c56034fd13d55526aebae40fddf0eacfc1d4e155b14a967a1c6b3d5418c2ff610edcdbd` |
| TLSH | `T199F14356BAEBCD73CCAD233907678714337588D2AB42AB13510C08752D835ECAD76BE1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8Dt8WC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7s4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_5a288187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7"
    family = "Mirai"
    file_name = "5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7.bin"
    file_type = "elf"
    first_seen = "2026-09-22 04:20:13"
  condition:
    hash.sha256(0, filesize) == "5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7"
}
```

### Sample 36: `0f5546ed97ada81c`

| Field | Value |
|---|---|
| SHA-256 | `0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74` |
| Family label | `unknown` |
| File name | `0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74.bin` |
| File type | `macho` |
| First seen | `2026-09-22 04:20:10` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7715023b46155c6ceddf35a70c1902d` |
| SHA-1 | `1495fabd42cb2b0de902aea9c825a88221090917` |
| SHA-256 | `0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74` |
| SHA3-384 | `f1831bed33bb1f130994b6a3e28f13b8b65dc8725503a1362e2f21a971a377368c3b2395d6d67819630ce664741fb8a1` |
| TLSH | `T121F25F139B1C1A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRUPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfblilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_0f5546ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74"
    family = "unknown"
    file_name = "0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:20:10"
  condition:
    hash.sha256(0, filesize) == "0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74"
}
```

### Sample 37: `ea12ecd7d5475e52`

| Field | Value |
|---|---|
| SHA-256 | `ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a` |
| Family label | `Snowlight` |
| File name | `ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a.bin` |
| File type | `elf` |
| First seen | `2026-09-22 04:20:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `140af4f9fd2dd5bc80d801be8bde111f` |
| SHA-1 | `0eb112d79c033ef731dbf55dd5921a3de0479d28` |
| SHA-256 | `ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a` |
| SHA3-384 | `1a96041d5c044ea0ecac50aa6176b16c8a5f96486bfdb7035619f2d0eae392e6b0c3e0050037307724e2d4f1f98514a4` |
| TLSH | `T149123047A2D0CE3FC8D953384467122472B794BEDF629713064815B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS68H5ML09V1J9G8YmL+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHPZMWT1YmahrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_037_ea12ecd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a"
    family = "Snowlight"
    file_name = "ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a.bin"
    file_type = "elf"
    first_seen = "2026-09-22 04:20:07"
  condition:
    hash.sha256(0, filesize) == "ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a"
}
```

### Sample 38: `9179d88e423d3552`

| Field | Value |
|---|---|
| SHA-256 | `9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb` |
| Family label | `unknown` |
| File name | `9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb.bin` |
| File type | `macho` |
| First seen | `2026-09-22 04:20:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `729714deb7166989fa3d1a2d3d3b35ef` |
| SHA-1 | `2320e04034a97f1dbc0d795d09333052b0245712` |
| SHA-256 | `9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb` |
| SHA3-384 | `4347041943f0ffb946f11b8732c9d827ac3ed410a6ca8ceaed015a55c54f2119f2cde78849c359276b7a09abfe709d53` |
| TLSH | `T139E25F43675C5929D45D83BA62FB1B976609F8B009D45B432F90DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZER5DbDP67li97WsCewYjqclS06W1YbqclSl:GI2R5DbDyQwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_9179d88e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb"
    family = "unknown"
    file_name = "9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:20:04"
  condition:
    hash.sha256(0, filesize) == "9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb"
}
```

### Sample 39: `49f56adacc76cb99`

| Field | Value |
|---|---|
| SHA-256 | `49f56adacc76cb9951cbd211080e6f432c2f4d4f67107ff4ca01ee9f37d204d5` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-22 04:19:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8eaadc272bec399b417bb623fea8ec87` |
| SHA-1 | `f2a224a06bc19156128bb7634fd62f94c4e6576d` |
| SHA-256 | `49f56adacc76cb9951cbd211080e6f432c2f4d4f67107ff4ca01ee9f37d204d5` |
| SHA3-384 | `eb85474661800c007f221b7411c9038d5a89965274b5d968f4d23592cdf00547e69b77254d5881677a13a6d1e1617c67` |
| TLSH | `T131C34B02B71D0F43D2A75DF02E3F27E1D3BAE6D161F4E6892A0D974981B59372186EC8` |
| SSDEEP | `1536:CVh37oZcVwZbCCBX/Tc3n2sdWlr7YJqlTHyDzZIPbtTnKTqHyfQB1WqpMH3S8p:CVZMZ2wTLcT8lr7ezZkIqMH3S8p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_49f56ada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49f56adacc76cb9951cbd211080e6f432c2f4d4f67107ff4ca01ee9f37d204d5"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-22 04:19:28"
  condition:
    hash.sha256(0, filesize) == "49f56adacc76cb9951cbd211080e6f432c2f4d4f67107ff4ca01ee9f37d204d5"
}
```

### Sample 40: `bc23937a2be3b9e5`

| Field | Value |
|---|---|
| SHA-256 | `bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac` |
| Family label | `unknown` |
| File name | `bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac` |
| File type | `elf` |
| First seen | `2026-09-22 04:18:46` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `424b4eb2f956a78e9f1ec5d874f1ba89` |
| SHA-1 | `38902b3404caae7098e3c4a4febe6d8475e75197` |
| SHA-256 | `bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac` |
| SHA3-384 | `b01dd41394eb988c89567f2c9c7f0c98ac776d7a49988b5117caf238e17b278143c4f47c0ba6c99fd2fb526cdc971f59` |
| TLSH | `T14EC3088BBC91EE6946C0277BFE2E418E331327B4D1DF71139D141F58B68A94F0E6A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEua7:T2s/gAWuboqsJ9xcJxspJBqQgTua7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_bc23937a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac"
    family = "unknown"
    file_name = "bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac"
    file_type = "elf"
    first_seen = "2026-09-22 04:18:46"
  condition:
    hash.sha256(0, filesize) == "bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac"
}
```

### Sample 41: `8117b2072c377ce5`

| Field | Value |
|---|---|
| SHA-256 | `8117b2072c377ce574fb9acc5f11020b74954c419460ce801144a867f5a28e2b` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-22 04:18:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3abcfe92cc93505309eccdcfc818e2e0` |
| SHA-1 | `92890f17fa7436f03b463271dc83b804e0fa9ce9` |
| SHA-256 | `8117b2072c377ce574fb9acc5f11020b74954c419460ce801144a867f5a28e2b` |
| SHA3-384 | `a3c666920a425d7ecaeac97a956b1eea53f85faba43d182961fc48839a6af09b30d9894b77a2eaa3b18502cf00bcb322` |
| TLSH | `T17233F116C045EFC2E5CA99F2A0AA97D557E08B4834978C2375E1DE30AD1EF58A3837DC` |
| SSDEEP | `1536:BS7pZLSXiYpkF7tNTFyWt/MwJRMLfnzMC4u+qgw09n:BSFHXZ3t/M6qLfzMC4u+qgw6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_8117b207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8117b2072c377ce574fb9acc5f11020b74954c419460ce801144a867f5a28e2b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-22 04:18:27"
  condition:
    hash.sha256(0, filesize) == "8117b2072c377ce574fb9acc5f11020b74954c419460ce801144a867f5a28e2b"
}
```

### Sample 42: `eb21e3bc8b67a94c`

| Field | Value |
|---|---|
| SHA-256 | `eb21e3bc8b67a94c43548776767d6ec03e27463b431eda424ee10b14d667909e` |
| Family label | `Mirai` |
| File name | `tpijtvcr.mips64` |
| File type | `elf` |
| First seen | `2026-09-22 04:18:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b9c869c62f93c74541624089f17f798` |
| SHA-1 | `ce50ad7a1fd7bb0d388f115af625056a30afa7db` |
| SHA-256 | `eb21e3bc8b67a94c43548776767d6ec03e27463b431eda424ee10b14d667909e` |
| SHA3-384 | `dabb35fcd32ab24df7db7a32eda635c4a65f57aafbfafbb2cfa76e27434bc3e47e45e4c3e0222d891521c3551e1e41e0` |
| TLSH | `T1D1356D07AF445FEBC4AFCE34852EC35714EDE8C752C1A62D71BC8A9CBA593494AC3588` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:x35aR0nffnvMjs7QRdJ4L3Sj8Ck27fSa7HqxwHnKDk:raRUvnoqW8CD7LzqxwHL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_eb21e3bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb21e3bc8b67a94c43548776767d6ec03e27463b431eda424ee10b14d667909e"
    family = "Mirai"
    file_name = "tpijtvcr.mips64"
    file_type = "elf"
    first_seen = "2026-09-22 04:18:26"
  condition:
    hash.sha256(0, filesize) == "eb21e3bc8b67a94c43548776767d6ec03e27463b431eda424ee10b14d667909e"
}
```

### Sample 43: `4ec01f8e51ae1922`

| Field | Value |
|---|---|
| SHA-256 | `4ec01f8e51ae1922b416474cfc4a7df444ec03751217cd3ba7476ea68e4b83b3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:16:23` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `712eb3ccc646732f2409a04b90944a84` |
| SHA-1 | `009dade2e27b390b1a16e0f47988143aded092a5` |
| SHA-256 | `4ec01f8e51ae1922b416474cfc4a7df444ec03751217cd3ba7476ea68e4b83b3` |
| SHA3-384 | `45402e4f51c4f90504bb80bac75891891f5b1babda7af7be7c36fd58145181177c519e7bb26e9a9d8ae31ccc68cdb545` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10962D686E8A22F6CDE4F80703A11F878BDB47694866599F3D7828C355DA39D10424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UPfqBM:fKOe2/7c9sN3zfZR1m+RGB6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_4ec01f8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec01f8e51ae1922b416474cfc4a7df444ec03751217cd3ba7476ea68e4b83b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:16:23"
  condition:
    hash.sha256(0, filesize) == "4ec01f8e51ae1922b416474cfc4a7df444ec03751217cd3ba7476ea68e4b83b3"
}
```

### Sample 44: `39c9e4b414573729`

| Field | Value |
|---|---|
| SHA-256 | `39c9e4b4145737291169c46a0c76b097437f02d14122e9c67cabc29e288c63b7` |
| Family label | `unknown` |
| File name | `don12089.hta` |
| File type | `hta` |
| First seen | `2026-09-22 04:14:08` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f27eedc869081d560712218db52f4642` |
| SHA-1 | `0c659438049f7a9b69170526e6721ce0594e691c` |
| SHA-256 | `39c9e4b4145737291169c46a0c76b097437f02d14122e9c67cabc29e288c63b7` |
| SHA3-384 | `96ed249612342dd56463959e1af2144bccd51f520cc605119402cd3b4ba7aaa18b8551b8f459ad745fddeb76e31d70af` |
| TLSH | `T1F342085C9EA1B2B4F25703EE3BBB696D137451C71408C884F64CADE46F0B78D8692B4A` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxzXIQBBK797I3L:sXX+/DV7k/34IKRs3L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_39c9e4b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39c9e4b4145737291169c46a0c76b097437f02d14122e9c67cabc29e288c63b7"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-09-22 04:14:08"
  condition:
    hash.sha256(0, filesize) == "39c9e4b4145737291169c46a0c76b097437f02d14122e9c67cabc29e288c63b7"
}
```

### Sample 45: `1ad0fd139090f30a`

| Field | Value |
|---|---|
| SHA-256 | `1ad0fd139090f30a5c270f77304e898ee4219b73b8afeb34f56ffb360b2615cd` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-09-22 04:14:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4b157c8953905f7037305a049e6cb60` |
| SHA-1 | `adb988417c397d4c9646209e76f1a152869f132d` |
| SHA-256 | `1ad0fd139090f30a5c270f77304e898ee4219b73b8afeb34f56ffb360b2615cd` |
| SHA3-384 | `b210eec226097ee6ae41c380dd31e4b545aac67320753903874c8abdde63d6841419a4300f95f205dfd229c0b1d8079a` |
| TLSH | `T1F9832CC1A783DD7EF86D8BB0CA768E7837D905AB21A5D1D7D3293E090730182991DEC9` |
| SSDEEP | `1536:N73fpXyhE3+NlllFY8Qt1jRpx9y1fe3IuR1RzpXKTpZzqVsDE/4xWx2Mrgjpe8oT:R3fhyNujRxSMrgka4R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_1ad0fd13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ad0fd139090f30a5c270f77304e898ee4219b73b8afeb34f56ffb360b2615cd"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-22 04:14:07"
  condition:
    hash.sha256(0, filesize) == "1ad0fd139090f30a5c270f77304e898ee4219b73b8afeb34f56ffb360b2615cd"
}
```

### Sample 46: `d0500c994f047097`

| Field | Value |
|---|---|
| SHA-256 | `d0500c994f047097cff60c37d5ee64e8fd15d2b030f66912bd732dcedb4fb950` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:13:50` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b1c5fdaf83eddfe8dadd6875c4bed79` |
| SHA-1 | `f0c4f3bc9782bcbb6532422151ac8c94fafa9191` |
| SHA-256 | `d0500c994f047097cff60c37d5ee64e8fd15d2b030f66912bd732dcedb4fb950` |
| SHA3-384 | `f3f2695be278383a90de16d2c430262c71c247dae14704193fd0f97c420231d26a67cefe5c4643006355900a968c54fd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18D62C586E9A22F5CCE4E80703A11F838BD7436D48A6699E3D7828C355EA39D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UMr6BM:fKOe2/7c9sN3zfZR1m+RGb66C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_d0500c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0500c994f047097cff60c37d5ee64e8fd15d2b030f66912bd732dcedb4fb950"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:13:50"
  condition:
    hash.sha256(0, filesize) == "d0500c994f047097cff60c37d5ee64e8fd15d2b030f66912bd732dcedb4fb950"
}
```

### Sample 47: `4e307c7135af75e5`

| Field | Value |
|---|---|
| SHA-256 | `4e307c7135af75e51e1143b4541fd20bbf5259d63fca15c139deb0486cea6255` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-09-22 04:12:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dc0f2e004edb7050f0695b8069fb58f` |
| SHA-1 | `18d14f9cb8ee8e956f4ed9c8936dd83b03ccac9b` |
| SHA-256 | `4e307c7135af75e51e1143b4541fd20bbf5259d63fca15c139deb0486cea6255` |
| SHA3-384 | `ad7c93fc4f4b20150982dec7c50b042fbc8d1cfdb628ebf5ab4702ee5484443e5160c826b5750ac924eb3be16b71d4a4` |
| TLSH | `T1F9E32C46E6814B13C0D2177ABADF42453323AB64D3DB73059928BFB43F8679E0E63605` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:U+Ug9WIx0UEaK0U4560zSlzhXRzM9hO3+keLUM/9g2JCVF:U+UzIxLEaK0U456xl9RI9c3+ZgM/9d8T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_4e307c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e307c7135af75e51e1143b4541fd20bbf5259d63fca15c139deb0486cea6255"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:32"
  condition:
    hash.sha256(0, filesize) == "4e307c7135af75e51e1143b4541fd20bbf5259d63fca15c139deb0486cea6255"
}
```

### Sample 48: `7c22c8ca4ad12a6f`

| Field | Value |
|---|---|
| SHA-256 | `7c22c8ca4ad12a6f83c4fce2c00e39140b618e1aab9c2c892c1ddf00038eac45` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-09-22 04:12:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d07aaf093255271b0c4f1a6dc9905f34` |
| SHA-1 | `21ba1a1e3e507c5d37ed6f371f57b25815e8375e` |
| SHA-256 | `7c22c8ca4ad12a6f83c4fce2c00e39140b618e1aab9c2c892c1ddf00038eac45` |
| SHA3-384 | `7a4a87e75c96d692b4c65977fdf4d81bf2650fbcc969f5a43606351bad260b66ada5b8a896bd74407daaf65929f687c1` |
| TLSH | `T10DA3E506BB650FF7DC6FCD3706A9070225CCA51B22B83B367674D928B50B65B4AE3874` |
| SSDEEP | `1536:LvGefaZSdtO44/xl4ExO29zyN0ZNhdZp54crFCZeLs/h5J:LOefaZSdc59zm0Hr6eoJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_7c22c8ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c22c8ca4ad12a6f83c4fce2c00e39140b618e1aab9c2c892c1ddf00038eac45"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:30"
  condition:
    hash.sha256(0, filesize) == "7c22c8ca4ad12a6f83c4fce2c00e39140b618e1aab9c2c892c1ddf00038eac45"
}
```

### Sample 49: `c43142af94ce1873`

| Field | Value |
|---|---|
| SHA-256 | `c43142af94ce18731580ca2d1b667152458c71fa1051e9e9376ea57be1990d43` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-09-22 04:12:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a4b4f8bb61e0e0f82d55d281168ca5a` |
| SHA-1 | `a26f9821bcf55a115b3a1436b6cc62e1fb126e37` |
| SHA-256 | `c43142af94ce18731580ca2d1b667152458c71fa1051e9e9376ea57be1990d43` |
| SHA3-384 | `147511744e355fb14dbb672b9f578f272ba35e4b2c7a96fd51064b6fee1352880a65b966f9ec66b8ea5ff68f94e6644c` |
| TLSH | `T199631A91BD819B13C6D0227BFB5E428E372653A8D2EE72079D226F21378785F0E77641` |
| TELFHASH | `t1b04140a457940bdd5fd4c755928f613ab8de38f9af10399a8e2e7b0f81435c2b118433` |
| SSDEEP | `1536:XGBQnw68oqNi5I3zS/GIw+D3ohyaRdWViEs/hX:XGBBa5ME1w+8kayA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_c43142af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c43142af94ce18731580ca2d1b667152458c71fa1051e9e9376ea57be1990d43"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:29"
  condition:
    hash.sha256(0, filesize) == "c43142af94ce18731580ca2d1b667152458c71fa1051e9e9376ea57be1990d43"
}
```

### Sample 50: `ed0d357c20350cc7`

| Field | Value |
|---|---|
| SHA-256 | `ed0d357c20350cc7bdb6f9f4a8c1a5f1083cd9dd5bb3955bdb6c5dad53dc3e08` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-09-22 04:12:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09392c77703f07693935fc9e4170d8b5` |
| SHA-1 | `57895f3fffb4870290e7f713e351bc35f66ecc85` |
| SHA-256 | `ed0d357c20350cc7bdb6f9f4a8c1a5f1083cd9dd5bb3955bdb6c5dad53dc3e08` |
| SHA3-384 | `dbaf767156d7d1ede41c792e534e8274a7a42dc354d6db000ffa57e93c8ae0e98d4bc18fccdcea7b477be343c9f9c4ef` |
| TLSH | `T1AE732A91BD815713C6D012BBFB5E028E372A53A8D2EE72179D226F2137C786B0E77641` |
| TELFHASH | `t1de5113b9cba50aec17e0c744c2c9a13cabea34ac5b00555acb5d3f2b85479c1b01d437` |
| SSDEEP | `1536:86dz9MTC0XU66EeRp05brAMjztPz+Sbjt+UvAs/hY:86dS6EAUrAMNb+AA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_ed0d357c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed0d357c20350cc7bdb6f9f4a8c1a5f1083cd9dd5bb3955bdb6c5dad53dc3e08"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:26"
  condition:
    hash.sha256(0, filesize) == "ed0d357c20350cc7bdb6f9f4a8c1a5f1083cd9dd5bb3955bdb6c5dad53dc3e08"
}
```

### Sample 51: `10ef901cc942e5c0`

| Field | Value |
|---|---|
| SHA-256 | `10ef901cc942e5c0885ea96c9350c934b0ea6cc3a530d0c35757c9043e263093` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-09-22 04:12:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bef2be955271ab3cba4fdfac0463b117` |
| SHA-1 | `d2ce5baea7cc4951753e45d5d738ede336f97dd2` |
| SHA-256 | `10ef901cc942e5c0885ea96c9350c934b0ea6cc3a530d0c35757c9043e263093` |
| SHA3-384 | `c2849d4093cbb23636b49a618a15143d0259d0b53943abc35d0f5b00fdbb73655ed2722abf20b32daa39dd7067b4b566` |
| TLSH | `T1E0535BC5AA47D8F6FD5602711173E7378632F13A1129DA87C7A9ED32BC52900EA1739C` |
| TELFHASH | `t11f31b0fa6dee09fcb3d4a808c75a6fd31a7ae177156139b044b5585027f388081b5c3a` |
| SSDEEP | `1536:ahZerRy3lVDKvfb9IZG4R9bdx6qQWP++CMq32UFSTGhk15uJnaroXf:ahqo3lVDKbd4bzP+zf2UMT2M5O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_10ef901c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ef901cc942e5c0885ea96c9350c934b0ea6cc3a530d0c35757c9043e263093"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:24"
  condition:
    hash.sha256(0, filesize) == "10ef901cc942e5c0885ea96c9350c934b0ea6cc3a530d0c35757c9043e263093"
}
```

### Sample 52: `6586ac367d483ff1`

| Field | Value |
|---|---|
| SHA-256 | `6586ac367d483ff1409ec55c206b7d3401f2947de1786a40e12158319f895fa3` |
| Family label | `Mirai` |
| File name | `tpijtvcr.mips` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0f0605cd18801950e661b517d43819a` |
| SHA-1 | `fb2ed3a64eb192ea661d4d9d3441a00d1a180d41` |
| SHA-256 | `6586ac367d483ff1409ec55c206b7d3401f2947de1786a40e12158319f895fa3` |
| SHA3-384 | `d5d62efadd566cdb7f803c6ac4e4cbe4c2b3c58d264c4bb7fc1f35ef1a170b51264089a3b43827985c79516145fdfe02` |
| TLSH | `T142356C633731DF69E314D27004F3CA617A9524A31AE24096B36CC3287E6166E6D6FFE4` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:prvlTNyN/4EFQ4ZM9CbzL/82ciNpcIKff3fffbffffoAvqqxwHnKDkk:prvlSu4ZM9Cbfppl35qxwHLk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_6586ac36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6586ac367d483ff1409ec55c206b7d3401f2947de1786a40e12158319f895fa3"
    family = "Mirai"
    file_name = "tpijtvcr.mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:37"
  condition:
    hash.sha256(0, filesize) == "6586ac367d483ff1409ec55c206b7d3401f2947de1786a40e12158319f895fa3"
}
```

### Sample 53: `7881a1c74eb82255`

| Field | Value |
|---|---|
| SHA-256 | `7881a1c74eb8225530086b97fbc61037d3f86f7338c5d48248d99d432f04bdab` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90074e2ad8290ae37304b8c7d860c157` |
| SHA-1 | `ab539b9d17367cadb3f43d0ff9e810b63e2c121e` |
| SHA-256 | `7881a1c74eb8225530086b97fbc61037d3f86f7338c5d48248d99d432f04bdab` |
| SHA3-384 | `f1e8d828f1723bd0f3690f4fbed84d0829667749a48d7ed885887a6e691785ce62c6e5b6af42e72e96b77e2f89c753eb` |
| TLSH | `T199245E567710DFA3C268C2308EF3C75167E525C237D1965AB35CDB283E212982DABEE4` |
| TELFHASH | `t13521018c593d09497a633574dc9c27b0e50ac862fd750f21cf58c781456e16a920ee3f` |
| SSDEEP | `3072:JW0yp0lvVOkkdTxnJVCrnKUpjMy1UpeqAKReJ4MPXi+8tuTuzeCM9J5MC:Ji0HOkaFsjvCMqtkzB8oTaMT5MC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_7881a1c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7881a1c74eb8225530086b97fbc61037d3f86f7338c5d48248d99d432f04bdab"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:36"
  condition:
    hash.sha256(0, filesize) == "7881a1c74eb8225530086b97fbc61037d3f86f7338c5d48248d99d432f04bdab"
}
```

### Sample 54: `767bc5e083d0e680`

| Field | Value |
|---|---|
| SHA-256 | `767bc5e083d0e68015493075233e3c938d73f3b9d7d186c4226bdae110cdf76c` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df1faf9f5bed2852b9226e95f5c84213` |
| SHA-1 | `fbaaf961f930bb7b74814e6f51de1881a853441c` |
| SHA-256 | `767bc5e083d0e68015493075233e3c938d73f3b9d7d186c4226bdae110cdf76c` |
| SHA3-384 | `b9a009bbad7a430ef639a2c8bd7f325358c75fdfa87a8ff1d9d2288557592e0bce17bb79bd2bbb746a527580da8fb42e` |
| TLSH | `T1FC735C32B9751D2BC4D0A87A61F30325F2F2478A25ACCA1A7D720D8EBF6565032477F9` |
| SSDEEP | `1536:jP+SbCGR18pspTH1yDQ2tXXUN95s0xwlWptCMR8/pW:zf4yV8pENP1x6MoW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_767bc5e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "767bc5e083d0e68015493075233e3c938d73f3b9d7d186c4226bdae110cdf76c"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:35"
  condition:
    hash.sha256(0, filesize) == "767bc5e083d0e68015493075233e3c938d73f3b9d7d186c4226bdae110cdf76c"
}
```

### Sample 55: `7b778454d0034781`

| Field | Value |
|---|---|
| SHA-256 | `7b778454d0034781ce9d544963ddfe9bc6062a3de49bcea7d3d32db3bf9d3ad4` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ad3268d93362cc8c00834788fbad8d` |
| SHA-1 | `b654e8787116c2ddc1e188b0c93ab142c10bdd28` |
| SHA-256 | `7b778454d0034781ce9d544963ddfe9bc6062a3de49bcea7d3d32db3bf9d3ad4` |
| SHA3-384 | `ecfef34b28eaa77be58e91fca77d9d1109282897c87884252c61f6bb5324adde188db7c9ce4354ff6e60ed0e3cf0ff02` |
| TLSH | `T11B43F115521B37D8CF3604B2F6312D522A534AF980BC663A1B3967E437CF91D60F8987` |
| SSDEEP | `768:BqRbqJBeRMsTS+u4fbrBkRJXLG9OQr7kSzyQwDn/WYpr9q3UELudA6tlVTukpUkf:Kbq+tTSK/20Vxz3wDnemKLuy6tlV1nLJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_7b778454
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b778454d0034781ce9d544963ddfe9bc6062a3de49bcea7d3d32db3bf9d3ad4"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:33"
  condition:
    hash.sha256(0, filesize) == "7b778454d0034781ce9d544963ddfe9bc6062a3de49bcea7d3d32db3bf9d3ad4"
}
```

### Sample 56: `55a16f04fddda7dc`

| Field | Value |
|---|---|
| SHA-256 | `55a16f04fddda7dcb0296f0496ba45eef9bc9b2d449d8c96bcb89b23a6ff2093` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d85ba5be273a1e43aec23b362d1dee82` |
| SHA-1 | `c36c3ccfe79221ef4a57bbde076de28fbda2b230` |
| SHA-256 | `55a16f04fddda7dcb0296f0496ba45eef9bc9b2d449d8c96bcb89b23a6ff2093` |
| SHA3-384 | `fc803030aff7e44650dec731cdb5aa3b897631f2281d0e36c748df1c462c1915e2212d3a29ec63c72ccc7ecc09f71523` |
| TLSH | `T16603E1CEBEE4BEDEC66DADFD15360AB04F8828903353CA4C5544DC67FE2A2B67045468` |
| SSDEEP | `768:jVyIwYjG0JFQTFY8x7O++YzrYw3yZpJvmhJT/Wy:jVyYjXJo5M++YX/yNm3n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_55a16f04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a16f04fddda7dcb0296f0496ba45eef9bc9b2d449d8c96bcb89b23a6ff2093"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:32"
  condition:
    hash.sha256(0, filesize) == "55a16f04fddda7dcb0296f0496ba45eef9bc9b2d449d8c96bcb89b23a6ff2093"
}
```

### Sample 57: `7bed3a2187eadf3b`

| Field | Value |
|---|---|
| SHA-256 | `7bed3a2187eadf3b02f0ec4f1277fe2921dc98716a4f8d29c321c8aaa11afdc7` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5360ed8a72189e69b23f821b22ac07b` |
| SHA-1 | `1ec87d2c4f3943a55a4218770ecdb88814e73e89` |
| SHA-256 | `7bed3a2187eadf3b02f0ec4f1277fe2921dc98716a4f8d29c321c8aaa11afdc7` |
| SHA3-384 | `1fa17555a50363e5c52ed60ca4f6898ae423553cce8fb00e6f147a111e4aec4e9870e57d1ac93613a3618979eb5276ba` |
| TLSH | `T19EE2E1B1450538F4E5F14476F73D838975A776B8FAAC70AA2C2406F031F29819A782D7` |
| SSDEEP | `768:2eBsVPxhgCF28KjwEKBzNSR/wzC6fa5luOooaXBs3Uozx:2eGVPxGCs82wrBzNQwOb8NoUszx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_7bed3a21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bed3a2187eadf3b02f0ec4f1277fe2921dc98716a4f8d29c321c8aaa11afdc7"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:31"
  condition:
    hash.sha256(0, filesize) == "7bed3a2187eadf3b02f0ec4f1277fe2921dc98716a4f8d29c321c8aaa11afdc7"
}
```

### Sample 58: `fd190f5878eb26d0`

| Field | Value |
|---|---|
| SHA-256 | `fd190f5878eb26d07cf60a4533c17400eef1aaa6a82a7730f33a3c0fdd5806ff` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16925b2163bca21dc26710a1cd8a124c` |
| SHA-1 | `0f8cadce8c3772b91751eec9c027ac50a9b3c2cd` |
| SHA-256 | `fd190f5878eb26d07cf60a4533c17400eef1aaa6a82a7730f33a3c0fdd5806ff` |
| SHA3-384 | `79a72915c489dba3fe0ed923a990215ac95ec66673e7c56e11ecde19bfa91b83240e2773dd8780769275b724cc861d60` |
| TLSH | `T136F2F121B45B6151D9D34C7482FC55C3BAEA4BA4879F723019048AF0E7C41AF72F899A` |
| SSDEEP | `768:/ZAb2jdTWDPtuRl/kb0Brt5CwSbv+YXXZdksx/aWBkqTojfN+ss3Uozv:/ZAKjBWDPtuTkGSyYXzxyg8N6zv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_fd190f58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd190f5878eb26d07cf60a4533c17400eef1aaa6a82a7730f33a3c0fdd5806ff"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:30"
  condition:
    hash.sha256(0, filesize) == "fd190f5878eb26d07cf60a4533c17400eef1aaa6a82a7730f33a3c0fdd5806ff"
}
```

### Sample 59: `2c3245b63e7e18bb`

| Field | Value |
|---|---|
| SHA-256 | `2c3245b63e7e18bb762f72d57f338f1c40e5032289c2714a81eeeb4c7d9821d4` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-09-22 04:11:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85b4fb52e6cf4609f3162d89bce9d698` |
| SHA-1 | `6d471e3218115fa62d0195bf19e46f3fb7b2252f` |
| SHA-256 | `2c3245b63e7e18bb762f72d57f338f1c40e5032289c2714a81eeeb4c7d9821d4` |
| SHA3-384 | `8a389ef4aa88e2e8697235eb4b0d6e7faeaca29e5f38c23ffcabea2288a0e153b7ceee2905bc651cee8be282ad0eb07a` |
| TLSH | `T188E2F26A51ECB12CE44E903BC32FA98E31E65D11BE1BC69424C475DADF611F910B6833` |
| SSDEEP | `768:g32bRAqg2lQzSPMjFY8AFOEPB6ZSq7xnwNQBUi:DbRAp2l4ECF+FvB6ZSonwN2F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_2c3245b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c3245b63e7e18bb762f72d57f338f1c40e5032289c2714a81eeeb4c7d9821d4"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:29"
  condition:
    hash.sha256(0, filesize) == "2c3245b63e7e18bb762f72d57f338f1c40e5032289c2714a81eeeb4c7d9821d4"
}
```

### Sample 60: `776c519ae7e093e0`

| Field | Value |
|---|---|
| SHA-256 | `776c519ae7e093e009447f7c3f4636331b307793409fb71d5fae9e6f5404d24d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 04:11:20` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b05edbc894ca977788e5788adc2cbb4f` |
| SHA-1 | `204f15afe59ee4e01036e1e935bd2b1d9257e21d` |
| SHA-256 | `776c519ae7e093e009447f7c3f4636331b307793409fb71d5fae9e6f5404d24d` |
| SHA3-384 | `c9f1f4cb9744ce6b01eb4d7f47b859084080598abbbb7ff1640b917aacbf1ee5d01f091a6398f00d19f8794ef8a7563d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F762D68AECA21F5CDE4E80703B11F938BD7476908665ADE3D7828C309DA39D00428FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ucevlm:fKOe2/7c9sN3zfZR1m+RGEvF6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_776c519a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "776c519ae7e093e009447f7c3f4636331b307793409fb71d5fae9e6f5404d24d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:11:20"
  condition:
    hash.sha256(0, filesize) == "776c519ae7e093e009447f7c3f4636331b307793409fb71d5fae9e6f5404d24d"
}
```

### Sample 61: `ec8dc99e36906cdf`

| Field | Value |
|---|---|
| SHA-256 | `ec8dc99e36906cdfd88d6bbf0ebe1b409a420fbb8051b30181225bf3e94cd362` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-09-22 04:10:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf7c11e353ed313c0bb4fdb2e80b0092` |
| SHA-1 | `8a730eccbca3ffa689d229fc000852c7bfb85cb3` |
| SHA-256 | `ec8dc99e36906cdfd88d6bbf0ebe1b409a420fbb8051b30181225bf3e94cd362` |
| SHA3-384 | `0e17c05b72b60fcec99ad6c4005f1e9180886a841afbb579cfe560fea102b7fe000ca2597cb111d5867c7113ff407e19` |
| TLSH | `T113A3C91E6E218FBDF369C33047B78E21A79837D626E1D685E26CD6011E6034E641FFA4` |
| TELFHASH | `t173217f5c4d7412e48b321d9e2baeff76e19030de0b326d378e11aaadba6d9425d00c1c` |
| SSDEEP | `1536:yk8NZJjWAanPscve4meOeuCyTPHvwIp/read7Q1Qs/Rd/uP:WZJjBan0zhHvlp/o1F/c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_ec8dc99e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec8dc99e36906cdfd88d6bbf0ebe1b409a420fbb8051b30181225bf3e94cd362"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-22 04:10:26"
  condition:
    hash.sha256(0, filesize) == "ec8dc99e36906cdfd88d6bbf0ebe1b409a420fbb8051b30181225bf3e94cd362"
}
```

### Sample 62: `e8fdb578177f8403`

| Field | Value |
|---|---|
| SHA-256 | `e8fdb578177f84033916427efad848f72d8fd43e1672744fc625b5165f2feca7` |
| Family label | `unknown` |
| File name | `macho_e8fdb578177f.bin` |
| File type | `macho` |
| First seen | `2026-09-22 04:10:18` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `676c8609fd585bf83b684711ded92e73` |
| SHA-1 | `0575d6f1ebb5fd2099ff38a7e49097c155423b39` |
| SHA-256 | `e8fdb578177f84033916427efad848f72d8fd43e1672744fc625b5165f2feca7` |
| SHA3-384 | `81657479cebdd5852a80bbe899808d3f2dda6e9105542de7e331ecc232b93b9b561ee323a5444785ece8a24448507adc` |
| TLSH | `T1C325E101CE7290D6F9CCD7342B3B8D379F216664894921DE32922E989D353E3F16B25E` |
| SSDEEP | `12288:LBHnYzWQkFspxYEt/mRt7lcakqhSlw6QNCSMvohNQBQ1ejl/SEodDoQ1whT/WP/6:xktJOplkciQYSaBJS1d0FlAJ1gukY8Ck` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_e8fdb578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8fdb578177f84033916427efad848f72d8fd43e1672744fc625b5165f2feca7"
    family = "unknown"
    file_name = "macho_e8fdb578177f.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:10:18"
  condition:
    hash.sha256(0, filesize) == "e8fdb578177f84033916427efad848f72d8fd43e1672744fc625b5165f2feca7"
}
```

### Sample 63: `311b06b21cba02b2`

| Field | Value |
|---|---|
| SHA-256 | `311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044` |
| Family label | `unknown` |
| File name | `311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044.exe` |
| File type | `exe` |
| First seen | `2026-09-22 04:09:32` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `551cab852dd5a71b69c8a1460e9e158e` |
| SHA-1 | `24e385fa40aae086b392a51f8a02cc06e7a8dec3` |
| SHA-256 | `311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044` |
| SHA3-384 | `5f3bda21860d199bb653dd1eafe5a3f1b2cd00c1315df18f1b2ca6f792fbe8412638de5b9e3c569ba24b8e663359b4d3` |
| IMPHASH | `d5b1104f7bf955d6b89a47291d5b603b` |
| TLSH | `T1A607339877454EB4F8FB423CA9C08A22A2F1B5642B95D7AF0BF10E1219673D4DF347A1` |
| SSDEEP | `393216:V0L1F2ugIfUKOc0XEAphVtnIwQSg+nFoIykzt8xvZ7X2:+psu58KP0RphDBo+FoIygt+vZ7` |
| ICON-DHASH | `aebc385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_311b06b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044"
    family = "unknown"
    file_name = "311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044.exe"
    file_type = "exe"
    first_seen = "2026-09-22 04:09:32"
  condition:
    hash.sha256(0, filesize) == "311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044"
}
```

### Sample 64: `b895922be26f5111`

| Field | Value |
|---|---|
| SHA-256 | `b895922be26f51110b67d15ac70b32415b4b3338052bd5d584e6018ec10b70ec` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-09-22 04:09:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfd11df823d5d25ec5773d94aaf9dd49` |
| SHA-1 | `3bb361acf082dbcf230020375758a0308736522f` |
| SHA-256 | `b895922be26f51110b67d15ac70b32415b4b3338052bd5d584e6018ec10b70ec` |
| SHA3-384 | `b16f7f20b3c8a47da88046db5c899663a34040281add0de2580d248a53c7b8ca849ea89401241fba6eb255c8b6c64196` |
| TLSH | `T1B7539C73C8296E54D19582B4B871CB781B63B48482471FFA5BD9C2BA9083DFCF6093B4` |
| SSDEEP | `1536:JaDwtqKcomlIFZCXaZMYfPkYPmgpK2mP5A/iabC0c/v38Bs/n8a:JwacomlITCXaZMYXkYegQ2mgiabgXMla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_b895922b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b895922be26f51110b67d15ac70b32415b4b3338052bd5d584e6018ec10b70ec"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:24"
  condition:
    hash.sha256(0, filesize) == "b895922be26f51110b67d15ac70b32415b4b3338052bd5d584e6018ec10b70ec"
}
```

### Sample 65: `e435cf674b59d13f`

| Field | Value |
|---|---|
| SHA-256 | `e435cf674b59d13f68e4c985ec71a10338c54f024077467bbd04447a9a500e43` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-09-22 04:09:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8e54c1ad407103f0186a2a27271182c` |
| SHA-1 | `6a109a05e3806a7e52ef92185039a767058a9431` |
| SHA-256 | `e435cf674b59d13f68e4c985ec71a10338c54f024077467bbd04447a9a500e43` |
| SHA3-384 | `796c6b16e9df105bebc2923d175dfb67d3bcfe7ea89d46011a5040de9a1c68aa4f961de5d08e242d38d331c244569f2b` |
| TLSH | `T11D832A97F400EDBDF80AD77B4453490AB270A3A105830F36A39BB963FD721A45967EC6` |
| SSDEEP | `1536:quKG91R4YgWxYRyRqwwrzPQtav8FjWtFUo/V6OXZJ7/aNSOFmA7ExtX1dT:q5GTPxYRyRqwazPQta6Q9VXXz4FmA7ux` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_e435cf67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e435cf674b59d13f68e4c985ec71a10338c54f024077467bbd04447a9a500e43"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:23"
  condition:
    hash.sha256(0, filesize) == "e435cf674b59d13f68e4c985ec71a10338c54f024077467bbd04447a9a500e43"
}
```

### Sample 66: `01afb7ab7ba3a2bb`

| Field | Value |
|---|---|
| SHA-256 | `01afb7ab7ba3a2bb1ee71d8b6d174f3f6951c6cb75b13e64687b99ea1dbea4fb` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-22 04:09:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dc093c35ff08c60aa9106bada9f6607` |
| SHA-1 | `95e613c8982fee42512f7b48b2a4d499c6e21590` |
| SHA-256 | `01afb7ab7ba3a2bb1ee71d8b6d174f3f6951c6cb75b13e64687b99ea1dbea4fb` |
| SHA3-384 | `2bd567f30bdb24a27688611634e1133627f0eaa73cae5cca33a0a1215ab9b334666b9fbe2c1f890e3cd25ce9eafe9619` |
| TLSH | `T1B8D35D01FB084963C4435EB05E7B07ABD3664D9118FAE10969097F4A2B33DB795C7BC6` |
| SSDEEP | `3072:8ODe81ANGJ/JCAXf6ylyaWmiguPAjS6BcQIpzoFC:1e2ANGJ/JCAXf6+deDoGgIOU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_01afb7ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01afb7ab7ba3a2bb1ee71d8b6d174f3f6951c6cb75b13e64687b99ea1dbea4fb"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:22"
  condition:
    hash.sha256(0, filesize) == "01afb7ab7ba3a2bb1ee71d8b6d174f3f6951c6cb75b13e64687b99ea1dbea4fb"
}
```

### Sample 67: `aad92045b93fc25e`

| Field | Value |
|---|---|
| SHA-256 | `aad92045b93fc25e3729fddcc6ab97e8d0932788e40369da15632ad5e4d60a74` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-09-22 04:09:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc149712ea96db221a12b48871a7a815` |
| SHA-1 | `b5c8131e6e65a6478c43ef4b75d3a0653c3d4a63` |
| SHA-256 | `aad92045b93fc25e3729fddcc6ab97e8d0932788e40369da15632ad5e4d60a74` |
| SHA3-384 | `e5f41c06cddb35cd024d40bd62e9d8b9b38e5401b9dac1cdea54881f563ad8e673c955cee2d0de653cd8832eeb4c8682` |
| TLSH | `T1EDF2E0BD1240988DDCA4E6FF8A7A473065115736E4518C8FBC4EEA83AD5BC6974237D0` |
| SSDEEP | `768:tNYKyukZoTMKerNKE88YNmOUEZldWsvKon+6buPTkSJh/s5+0o1Fk9JgGlzDpbuA:nYdWlerNq5NmODZld5FnSJhwouVJuA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_aad92045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aad92045b93fc25e3729fddcc6ab97e8d0932788e40369da15632ad5e4d60a74"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:20"
  condition:
    hash.sha256(0, filesize) == "aad92045b93fc25e3729fddcc6ab97e8d0932788e40369da15632ad5e4d60a74"
}
```

### Sample 68: `b145b5bb3cf01821`

| Field | Value |
|---|---|
| SHA-256 | `b145b5bb3cf0182180e926335f6cf62f00b0524a4d0bf0158ea6136d34d5fe89` |
| Family label | `Mirai` |
| File name | `bot.arm64` |
| File type | `elf` |
| First seen | `2026-09-22 04:09:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff3e70cd00a2ee654aa8e5fc495be69b` |
| SHA-1 | `0462758f5399935cd9a5d313262478b7e5f372e6` |
| SHA-256 | `b145b5bb3cf0182180e926335f6cf62f00b0524a4d0bf0158ea6136d34d5fe89` |
| SHA3-384 | `8bcf885ad7e3aa510a57c14fb300d7dc8e9ba1460914e4b66fe26f381534cf694ad13ed5db775fb6a4d36fc3f84aad75` |
| TLSH | `T134356B5DFE1F7D47C2C6E23DEB4982B57127B098C62310A325C2034DE6C9D998F6299A` |
| TELFHASH | `t149a012020880810c0177ab114c95034910414833e81a3d551e0cda400410008034886a` |
| SSDEEP | `12288:KXy0TQt6F25ff/dG+ND7zeM7wuxReOoF7UxLjALY2ga56i6vGrkSL6JwbMQe8qwi:lm+dRD7zjRqW0Y2JgGwK6JwbM8qwy4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_b145b5bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b145b5bb3cf0182180e926335f6cf62f00b0524a4d0bf0158ea6136d34d5fe89"
    family = "Mirai"
    file_name = "bot.arm64"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:19"
  condition:
    hash.sha256(0, filesize) == "b145b5bb3cf0182180e926335f6cf62f00b0524a4d0bf0158ea6136d34d5fe89"
}
```

### Sample 69: `20b78165243129d6`

| Field | Value |
|---|---|
| SHA-256 | `20b78165243129d67f509342c6d3f6f690fa480263946b2fe6b90569b804e68c` |
| Family label | `Mirai` |
| File name | `ooikocqj.x86_64` |
| File type | `elf` |
| First seen | `2026-09-22 04:09:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `650626277f24d72366557c05d3632126` |
| SHA-1 | `fdfb00d6bbd706558b550ead5ade06a31f8a84d1` |
| SHA-256 | `20b78165243129d67f509342c6d3f6f690fa480263946b2fe6b90569b804e68c` |
| SHA3-384 | `ce83fe7e552562b5362cb182c37abce841995f7c9ecc3d301d1b39379183dc9519e54f82d12abfc74a8d268abc187c22` |
| TLSH | `T121355C5BB2A374BCC157C430839BDA62BD35B46502226D7FA5C4DB702E26E701B29F72` |
| TELFHASH | `t1f4e17b744bf974b1a6d6e710f352f0f54a771c3626ec35f46622ad88ee84f804c7682a` |
| SSDEEP | `24576:LXnQF1f0CPH46Fl5Nq5EWnvs2QQGkqOIrQxIRygXaRJE:DqB1f46FQ1nE2GOhxIRZXY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_20b78165
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20b78165243129d67f509342c6d3f6f690fa480263946b2fe6b90569b804e68c"
    family = "Mirai"
    file_name = "ooikocqj.x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:17"
  condition:
    hash.sha256(0, filesize) == "20b78165243129d67f509342c6d3f6f690fa480263946b2fe6b90569b804e68c"
}
```

### Sample 70: `f0779a0d621726d0`

| Field | Value |
|---|---|
| SHA-256 | `f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7` |
| Family label | `unknown` |
| File name | `f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7.exe` |
| File type | `exe` |
| First seen | `2026-09-22 04:09:01` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02e2116752dbb348570f8551cb43cee6` |
| SHA-1 | `412f733905ed23e3db61828e192c34a369befe48` |
| SHA-256 | `f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7` |
| SHA3-384 | `d7bb9b852eda13500d1e013fcc43380c1fbe4eb7cc1f67a367e46ee9dab25ccbdcec4998a156c9df6d3e28e3f7334ed9` |
| IMPHASH | `ac4ded70f85ef621e5f8917b250855be` |
| TLSH | `T188A62323618637BFD86B2A3F45B59738A9376E30D40B8C5696E1B84CDF3D0501EBE642` |
| SSDEEP | `196608:a7VO4wriCip6fRgRLt1tgxu7xFuEc+pKS5RZAoxDEUSFmscbezISHVh5V1N0kkp:a7VO3ritp4+nU6xY+pKS5rTxWQBezzVW` |
| ICON-DHASH | `f0d4ccb2b2ccd4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_f0779a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7"
    family = "unknown"
    file_name = "f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7.exe"
    file_type = "exe"
    first_seen = "2026-09-22 04:09:01"
  condition:
    hash.sha256(0, filesize) == "f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7"
}
```

### Sample 71: `b7364d80258da883`

| Field | Value |
|---|---|
| SHA-256 | `b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692` |
| Family label | `ConnectWise` |
| File name | `b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692.msi` |
| File type | `msi` |
| First seen | `2026-09-22 04:08:55` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44babdb48b17400fdb40f9af6ea6a2eb` |
| SHA-1 | `573971844ae998e76ccd8667fcb7758aa96d45bb` |
| SHA-256 | `b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692` |
| SHA3-384 | `bc52f823053cd63aa2f2879424d8c891cfd58f13a663824e633ffae91f82d6c533f04344e2638e5b2ae6fa1ff1f87847` |
| TLSH | `T1ECD623116BF89678F0F22A35E876A0B1A5377D125E22D12E2324791E2C75EC0C9B3777` |
| SSDEEP | `196608:qHxcp9ym3nltDUJVWHxcp9ym3DHxcp9ym3HHxcp9ym3CHxcp9ym3gHxcp9ym3AHx:4GplpBGptGpxGpQGpOGpuGpa` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_071_b7364d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692"
    family = "ConnectWise"
    file_name = "b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692.msi"
    file_type = "msi"
    first_seen = "2026-09-22 04:08:55"
  condition:
    hash.sha256(0, filesize) == "b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692"
}
```

### Sample 72: `40a8e6f126c138da`

| Field | Value |
|---|---|
| SHA-256 | `40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16` |
| Family label | `unknown` |
| File name | `40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16.exe` |
| File type | `exe` |
| First seen | `2026-09-22 04:08:41` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e08ca77e5f0d1e9dade8f9fc449e2e32` |
| SHA-1 | `be5e43377e493dbfcca5c3f905ffbc947c63a8d4` |
| SHA-256 | `40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16` |
| SHA3-384 | `d00daa4ffc4e8d3f2d5306f4ffb310c0f9123fc7238069231a423e76460ee79f737b986fdef514aa1851d77de6248db3` |
| IMPHASH | `f4639a0b3116c2cfc71144b88a929cfd` |
| TLSH | `T18EB6334D33FC444AC322467BB673AD7A72EF7B7672C58B560226911C1C371AEE88844E` |
| SSDEEP | `196608:2ksGCZ1dnon1Od0Y3i9V0TLv+ZifSNePSYokl2Qe4y2bID026mGat0o:2kCZPcOd0V9s7+ZCSNWSYoiCp6mGK` |
| ICON-DHASH | `c4dadadad2f492c2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_40a8e6f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16"
    family = "unknown"
    file_name = "40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16.exe"
    file_type = "exe"
    first_seen = "2026-09-22 04:08:41"
  condition:
    hash.sha256(0, filesize) == "40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16"
}
```

### Sample 73: `5db673e2ce242436`

| Field | Value |
|---|---|
| SHA-256 | `5db673e2ce2424361324469b1c84bf800d73fea50d302004e0866b04729e86f5` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-22 04:07:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8143d8a7bc1ff25ab61a2045b281b1f` |
| SHA-1 | `0b21b29e7c3b9bf1bea1bd6d6f2d70592839d8bf` |
| SHA-256 | `5db673e2ce2424361324469b1c84bf800d73fea50d302004e0866b04729e86f5` |
| SHA3-384 | `141170fd966eb7f5b3bc8f3a57082a25e23675ef6c5343bb0d8d58bf78ce1f44f39eae560548b063434a136e7fcf4c0d` |
| TLSH | `T16583B816BF650FF7EC1EDD3745A82B0625CCA50622BA7B363538D91CF64B24B06D38A4` |
| SSDEEP | `1536:EAEH1FQih2w3WDsWK0Bqn2x5l/VlC4mLbRc+f/Rs6o3XZg1HMT:ED1BAMXWKqqnW5lNQoDT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_5db673e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db673e2ce2424361324469b1c84bf800d73fea50d302004e0866b04729e86f5"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-22 04:07:17"
  condition:
    hash.sha256(0, filesize) == "5db673e2ce2424361324469b1c84bf800d73fea50d302004e0866b04729e86f5"
}
```

### Sample 74: `448fcc12cbc34e67`

| Field | Value |
|---|---|
| SHA-256 | `448fcc12cbc34e670318dd07c64e61bf91784969e8153e696db58523f77bacad` |
| Family label | `unknown` |
| File name | `1` |
| File type | `elf` |
| First seen | `2026-09-22 04:07:16` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69221a6a22e3595d9c6c4029b0aabafe` |
| SHA-1 | `535db1cd675d175c53879c7ceb788e1b451622d5` |
| SHA-256 | `448fcc12cbc34e670318dd07c64e61bf91784969e8153e696db58523f77bacad` |
| SHA3-384 | `7db13d41fb5b416ae1113c5314672710eb3e1eb163c9bd771a5b5b50d22285018feac949a960c72b79f392daf6d816be` |
| TLSH | `T1C2742353DB2BE2F3E0D739FD675816F2DE509DB8B0C04A0BA517316A261D77E2224B42` |
| SSDEEP | `6144:ygW658LkWZZgsqWNWhTDgZsYGywaDAOxg85dWzgHz7P70dLrKMK+G7g2bGYML58x:yH62L/ZC7/hIZGOg8XWzy7j0MJ+Xy4Lu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_448fcc12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448fcc12cbc34e670318dd07c64e61bf91784969e8153e696db58523f77bacad"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-22 04:07:16"
  condition:
    hash.sha256(0, filesize) == "448fcc12cbc34e670318dd07c64e61bf91784969e8153e696db58523f77bacad"
}
```

### Sample 75: `7ac457531bf03557`

| Field | Value |
|---|---|
| SHA-256 | `7ac457531bf03557031d6630798a75ce59b1fa98a390f076c5f2d1b5b1b16343` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-09-22 04:05:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0036cca5e973f3ba0c3c371adcedef45` |
| SHA-1 | `5463d054dc527952a2859998c1b0e01402c26b11` |
| SHA-256 | `7ac457531bf03557031d6630798a75ce59b1fa98a390f076c5f2d1b5b1b16343` |
| SHA3-384 | `a86076ef1ce02df73935970f539ad8bd591925dce1b4c365456a7f67fc59757c52bc27bc4aa51b441c2cf4301ed1402d` |
| TLSH | `T17CB3AD8BF70B65A0C8604BF447CB4BDD3B2332129E9B99E7AC1E293E5D750CE4906791` |
| SSDEEP | `1536:abLblROTyOFGPROkekT4Wj3GwYIN7+a6B0uA8/gX5yXg6/LW:asyOFLkekX407r6c84JyXg6q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_7ac45753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac457531bf03557031d6630798a75ce59b1fa98a390f076c5f2d1b5b1b16343"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-09-22 04:05:13"
  condition:
    hash.sha256(0, filesize) == "7ac457531bf03557031d6630798a75ce59b1fa98a390f076c5f2d1b5b1b16343"
}
```

### Sample 76: `aaf45dcc5c1fa53c`

| Field | Value |
|---|---|
| SHA-256 | `aaf45dcc5c1fa53c3f9fb482e9d5ac941b5ea30740779358726100b8ae9d44bf` |
| Family label | `Mirai` |
| File name | `ypezhbfg.armv6` |
| File type | `elf` |
| First seen | `2026-09-22 04:05:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f080a7f76959b6d33b8868f8665bd984` |
| SHA-1 | `4d62e707e91638abe92bf00adaffceb1c77411e6` |
| SHA-256 | `aaf45dcc5c1fa53c3f9fb482e9d5ac941b5ea30740779358726100b8ae9d44bf` |
| SHA3-384 | `34753d98fcff017a5805f9164fbffd73fdd0069bd35fb63e819793970d21fe34c17c3ec8fae25563cd0749bc9a4ea70f` |
| TLSH | `T172F4D059F55AEF03C4F7E536E4BB82D07262EC4F57928305650AE9BD380B3398B1A385` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `12288:yx2FM2YM/+M8t47cvwOg7xRKJOMz6XjfafVCYRd6pgPxIGNHq6kyB5cl1bTMg:yAYLHt44r27KJqfa1R7+6Hq6kyBCl1bw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_aaf45dcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaf45dcc5c1fa53c3f9fb482e9d5ac941b5ea30740779358726100b8ae9d44bf"
    family = "Mirai"
    file_name = "ypezhbfg.armv6"
    file_type = "elf"
    first_seen = "2026-09-22 04:05:11"
  condition:
    hash.sha256(0, filesize) == "aaf45dcc5c1fa53c3f9fb482e9d5ac941b5ea30740779358726100b8ae9d44bf"
}
```

### Sample 77: `df1a7b868293d9bf`

| Field | Value |
|---|---|
| SHA-256 | `df1a7b868293d9bfbad876349f87bc59520286ac7468c3ddfee421ff75572a26` |
| Family label | `unknown` |
| File name | `update.apk` |
| File type | `apk` |
| First seen | `2026-09-22 04:02:17` |
| Reporter | `anonymous` |
| Tags | `accessibility, android-banking-trojan, apk, hvnc, mediaprojection, StreamRat, zincapp` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebd79f6ce86c08bcdbfd15bb3c0e1ebf` |
| SHA-1 | `81bd694a6bf629c3decd9e5a04daa6b23a6fbd5d` |
| SHA-256 | `df1a7b868293d9bfbad876349f87bc59520286ac7468c3ddfee421ff75572a26` |
| SHA3-384 | `32f7072d8e9ba4d6cafadbae0acef25cd33c7e7f557c6e9eee78099599ed9d32097da37b3c1853af6c5fa6be2e49c393` |
| TLSH | `T1D006F125FF88BA38CEF34535997E8A954C448F4482C7D847E5F9701C2CBB9E0A7269D8` |
| SSDEEP | `49152:jn1gLpbbdvUG+B4JKY/44qKuXRfHFd12V1MVflXFYUvBntaznCEaY/XCndZo:4PdcG9KY/HF+tuMVfZFlYLVaY/l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_df1a7b86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df1a7b868293d9bfbad876349f87bc59520286ac7468c3ddfee421ff75572a26"
    family = "unknown"
    file_name = "update.apk"
    file_type = "apk"
    first_seen = "2026-09-22 04:02:17"
  condition:
    hash.sha256(0, filesize) == "df1a7b868293d9bfbad876349f87bc59520286ac7468c3ddfee421ff75572a26"
}
```

### Sample 78: `0dc6fa96d4ccd761`

| Field | Value |
|---|---|
| SHA-256 | `0dc6fa96d4ccd761d916d119d842fe191c9dd24bb0d97936f5fb168e898431f0` |
| Family label | `unknown` |
| File name | `Medicare.apk` |
| File type | `apk` |
| First seen | `2026-09-22 04:02:11` |
| Reporter | `anonymous` |
| Tags | `Android, apk, dashapp, dropper, Services-Australia-impersonation, StreamRat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c6589310667b707c4ecaecaa726981a` |
| SHA-1 | `20e558a9b624e1d783acf09417a844f135e41b22` |
| SHA-256 | `0dc6fa96d4ccd761d916d119d842fe191c9dd24bb0d97936f5fb168e898431f0` |
| SHA3-384 | `71d7a4e0f3e03cbe1549991f8eb1e331e8f92f0eb6e8c73db3525394a17ea55327e0cb727d0cb91dafd210f377b753d6` |
| TLSH | `T1B9660225FF48B63AC5F3453A993AC9258C408D4447C3D847A5E9753C2CBBBE4A73A9C8` |
| SSDEEP | `98304:rbEa0vWFRldAEoaDx0eRNiHz59dIKO1aNSpzFJFQnWILARlQMP0ftFiH9:PRrdAIiHzdIR10uzxQn3ARlQMP0VO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_0dc6fa96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc6fa96d4ccd761d916d119d842fe191c9dd24bb0d97936f5fb168e898431f0"
    family = "unknown"
    file_name = "Medicare.apk"
    file_type = "apk"
    first_seen = "2026-09-22 04:02:11"
  condition:
    hash.sha256(0, filesize) == "0dc6fa96d4ccd761d916d119d842fe191c9dd24bb0d97936f5fb168e898431f0"
}
```

### Sample 79: `31652883c0c168a0`

| Field | Value |
|---|---|
| SHA-256 | `31652883c0c168a09ec00d78a61c581b4125b3dc379452e18ba7873c03b99952` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 03:48:34` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3e4d91509afbe2f3a546ef62808e2cc` |
| SHA-1 | `fea06bafaacae4e581cc5d2a22117bde194b09c6` |
| SHA-256 | `31652883c0c168a09ec00d78a61c581b4125b3dc379452e18ba7873c03b99952` |
| SHA3-384 | `b8c7db41ed20b15542f44f2b8a5256405c3e800e159365f5b81547970aac58d5abec092242bd3aa8201cfbda198c709a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EF62C78ADCA25E6CDE4E80703B11FDA879B43692866659F3E7828C305DA39D04534FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ue4bBe:fKOe2/7c9sN3zfZR1m+RGKbB6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_31652883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31652883c0c168a09ec00d78a61c581b4125b3dc379452e18ba7873c03b99952"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:48:34"
  condition:
    hash.sha256(0, filesize) == "31652883c0c168a09ec00d78a61c581b4125b3dc379452e18ba7873c03b99952"
}
```

### Sample 80: `ed4c17e7f94a2832`

| Field | Value |
|---|---|
| SHA-256 | `ed4c17e7f94a2832fbecf8a258d4c6ac8edeb441e316a5e5895498e3b6e15fe0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 03:45:21` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `924614f38a3c9c9d15966c9eee329a82` |
| SHA-1 | `9d62aeefeae80f25eece69519f13d63fd74b1bee` |
| SHA-256 | `ed4c17e7f94a2832fbecf8a258d4c6ac8edeb441e316a5e5895498e3b6e15fe0` |
| SHA3-384 | `b36d0605aeb9cfdf3887000d8ab2402967ab341d25cdf00c2c39131925071e4562b62f22cf0e6e52ef6ffea142adc574` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CD62E786E8A22F6CCE4F80703A11F978BD7476918A6599E7D7828C345DA39D00434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UyaII5:fKOe2/7c9sN3zfZR1m+RGhL96C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_ed4c17e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed4c17e7f94a2832fbecf8a258d4c6ac8edeb441e316a5e5895498e3b6e15fe0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:45:21"
  condition:
    hash.sha256(0, filesize) == "ed4c17e7f94a2832fbecf8a258d4c6ac8edeb441e316a5e5895498e3b6e15fe0"
}
```

### Sample 81: `e745c9e5efe20a8a`

| Field | Value |
|---|---|
| SHA-256 | `e745c9e5efe20a8a8698c7810872daa88e2693d46bec47c76dd164d675f2b569` |
| Family label | `Mirai` |
| File name | `m.armv5l` |
| File type | `elf` |
| First seen | `2026-09-22 03:42:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d36668e4de17a1874ad4c74d39be919` |
| SHA-1 | `674c5fc7781160ed53b0c8d085cd1dc16ab40aef` |
| SHA-256 | `e745c9e5efe20a8a8698c7810872daa88e2693d46bec47c76dd164d675f2b569` |
| SHA3-384 | `9d5c9cc6d8363eb510500600a0d99670a87b39b2e6b0b67cc01101d2c387476bb7d4960a05e64fccd0a56fc1b15eb7b6` |
| TLSH | `T1C3152A95F880DF61C6C025BAF75D86AC331347B9C2E771069D159B343BEB86E0E3AA41` |
| TELFHASH | `t17ed0a70265cc02a5b1d046e79ef55b2c1051142417c1b1625b64781badc1fc61416977` |
| SSDEEP | `24576:ZOesTvXUbK1i0YPM9EZ2qBblVmfpd7hP4qTSD:ZOG0brTS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_e745c9e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e745c9e5efe20a8a8698c7810872daa88e2693d46bec47c76dd164d675f2b569"
    family = "Mirai"
    file_name = "m.armv5l"
    file_type = "elf"
    first_seen = "2026-09-22 03:42:59"
  condition:
    hash.sha256(0, filesize) == "e745c9e5efe20a8a8698c7810872daa88e2693d46bec47c76dd164d675f2b569"
}
```

### Sample 82: `0eb0e29ca00b7405`

| Field | Value |
|---|---|
| SHA-256 | `0eb0e29ca00b7405a80dcd803a40187dd96e5dbeec25390f117a9f966762440e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 03:42:52` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d381031882fde18272f635697c0d2f9f` |
| SHA-1 | `7758aa467a571d4ca24b4b83490b0af6ecf591db` |
| SHA-256 | `0eb0e29ca00b7405a80dcd803a40187dd96e5dbeec25390f117a9f966762440e` |
| SHA3-384 | `4aa37ebdb8e7213bbcf1245f596f4a56734d00fe4df52dcbdc0ac6391360d39f51a55d6815ac7c396fe5aa3dc67dcd5b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FC62D68AE8A26F6CCE4F90703A11FC78BD74369086659DE3D7868C345DA39D04424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UMRBgn:fKOe2/7c9sN3zfZR1m+RGdR6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_0eb0e29c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eb0e29ca00b7405a80dcd803a40187dd96e5dbeec25390f117a9f966762440e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:42:52"
  condition:
    hash.sha256(0, filesize) == "0eb0e29ca00b7405a80dcd803a40187dd96e5dbeec25390f117a9f966762440e"
}
```

### Sample 83: `5ec97f8bb694f488`

| Field | Value |
|---|---|
| SHA-256 | `5ec97f8bb694f488a7d4aefe3cc5f10b192a9300aa9300c4d1441e9b1823f089` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 03:40:26` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a81082e8d0e39211228951588994f17` |
| SHA-1 | `9ee846a220c2ed0f3875fad1809f3e3926cba69e` |
| SHA-256 | `5ec97f8bb694f488a7d4aefe3cc5f10b192a9300aa9300c4d1441e9b1823f089` |
| SHA3-384 | `8e17f894f10a4a7b1ffa0abb78d28c2fdffc6621b6622cf1a2c007bfea42bb847a71dddf3e84490d65ef05c7f44e066b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13A62D686E8A26F6CDE4F90703A11F878B97536A08A6599E7D7828C305DA3DD00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UEmnuR:fKOe2/7c9sN3zfZR1m+RGPZe6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_5ec97f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec97f8bb694f488a7d4aefe3cc5f10b192a9300aa9300c4d1441e9b1823f089"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:40:26"
  condition:
    hash.sha256(0, filesize) == "5ec97f8bb694f488a7d4aefe3cc5f10b192a9300aa9300c4d1441e9b1823f089"
}
```

### Sample 84: `0ce6c33423a25435`

| Field | Value |
|---|---|
| SHA-256 | `0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e` |
| Family label | `unknown` |
| File name | `0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e.bin` |
| File type | `zip` |
| First seen | `2026-09-22 03:40:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe7187156431787428fb54a76b1a432c` |
| SHA-1 | `ce0747fab9a293e5c6259486adeee62371673eab` |
| SHA-256 | `0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e` |
| SHA3-384 | `a0ea5750d840c55f351d5f098bd80f8265bb0da982a15c8cd9c9144a20893d4ec2ed34028baeb1d6f39f52358289bc61` |
| TLSH | `T1066533035EF80484D1D72B3094EF4B9A2A3D9E6B7E69A057DB76FD2EC8139608C1C749` |
| SSDEEP | `24576:q1IxZdhbUvHYu3q3hl9cqgL1l5cGje++Wk1hCe4F/wFNNi0SrM:VHgfYkfqgLBDeZWk/34F/mMprM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_0ce6c334
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e"
    family = "unknown"
    file_name = "0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e.bin"
    file_type = "zip"
    first_seen = "2026-09-22 03:40:04"
  condition:
    hash.sha256(0, filesize) == "0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e"
}
```

### Sample 85: `e73af00b82dc6519`

| Field | Value |
|---|---|
| SHA-256 | `e73af00b82dc65195ae47159967583d483fbe60bd2b838c52c5a5e269892b556` |
| Family label | `AgentTesla` |
| File name | `Shipment Documents.JS` |
| File type | `js` |
| First seen | `2026-09-22 03:38:22` |
| Reporter | `nat` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9c7018858d991b1966135851f41e0a6` |
| SHA-1 | `98e89a3dec33ff9497448516e137b3d695464388` |
| SHA-256 | `e73af00b82dc65195ae47159967583d483fbe60bd2b838c52c5a5e269892b556` |
| SHA3-384 | `7fb70757d2dbaaa9ac6202aa5bb30ef81b10630758d9c64d76a0b3d6668307191dfd5248fc49699f9a239d1433644812` |
| TLSH | `T1FF16924A1D47F621F97A12744C8E9B94CA6C7DF78648E803363E9C93FF647C29944E28` |
| SSDEEP | `98304:yYrP7lLoB8hyrXS4JzBa9G+QLIY2QSG37AnQipHJMFlIszMl:lPB2WyrCoHcdQtDI5` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_085_e73af00b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e73af00b82dc65195ae47159967583d483fbe60bd2b838c52c5a5e269892b556"
    family = "AgentTesla"
    file_name = "Shipment Documents.JS"
    file_type = "js"
    first_seen = "2026-09-22 03:38:22"
  condition:
    hash.sha256(0, filesize) == "e73af00b82dc65195ae47159967583d483fbe60bd2b838c52c5a5e269892b556"
}
```

### Sample 86: `5c2549ee09b8ab41`

| Field | Value |
|---|---|
| SHA-256 | `5c2549ee09b8ab41e83350656d656cbb1ace751f6dedda7f22b631c3bb238512` |
| Family label | `unknown` |
| File name | `u346d5539.exe` |
| File type | `exe` |
| First seen | `2026-09-22 03:38:15` |
| Reporter | `Parper` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8e081e7d81dc1425f1ffc5388ef6cb7` |
| SHA-1 | `d235168badd3899eb2c6fb5b9b1bc860c4dfccb6` |
| SHA-256 | `5c2549ee09b8ab41e83350656d656cbb1ace751f6dedda7f22b631c3bb238512` |
| SHA3-384 | `7f681acb364c027c6591e23855bdacad01367e40c57f8ddd353f5e708c0e402cdd00a8cf8e58280af716b4531ba5603d` |
| IMPHASH | `8db69de8fe1bb18dc96df49e477e193c` |
| TLSH | `T11C76F123A9516778C056D1354A22D022F662FC583F2593F77A8CB2783B737E45AB8BC1` |
| SSDEEP | `98304:qbQkS6QV7l87cgAp8RF0G1zpq5bFpr2AiQalwF02c0dqZs+U/fKXrWuO:U7F0G1zpqJFM/jlwFjc99W+CV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_5c2549ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c2549ee09b8ab41e83350656d656cbb1ace751f6dedda7f22b631c3bb238512"
    family = "unknown"
    file_name = "u346d5539.exe"
    file_type = "exe"
    first_seen = "2026-09-22 03:38:15"
  condition:
    hash.sha256(0, filesize) == "5c2549ee09b8ab41e83350656d656cbb1ace751f6dedda7f22b631c3bb238512"
}
```

### Sample 87: `0a71a7bc60ccea3a`

| Field | Value |
|---|---|
| SHA-256 | `0a71a7bc60ccea3ab59938a724508536b5186352f00ab3df857c8f83fb5502d6` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-22 03:31:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a32150e47fe9b351aa166de3a26a70f` |
| SHA-1 | `37bac09fb34f539950ee000cfe7df582373b12fe` |
| SHA-256 | `0a71a7bc60ccea3ab59938a724508536b5186352f00ab3df857c8f83fb5502d6` |
| SHA3-384 | `5fb303a734eb93755187c03741ec729cd7a82abd66802dda342a0100c2b18dd3d46c3542cf8ddd1f73b31041032a55dd` |
| TLSH | `T167B3AD73C9391EACC2549974B0A1EF7C4B93E441458B1EF969A9C77AC087ECCB14A3B4` |
| SSDEEP | `1536:gN0/LgkYvw0l7R7X4cnsb7zCQR9/JoyK1aKs4nzgC2kjgZTvFp11qpBHsP:G0/8kAwsO/RFw1znzgGj+6BHsP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_0a71a7bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a71a7bc60ccea3ab59938a724508536b5186352f00ab3df857c8f83fb5502d6"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-22 03:31:04"
  condition:
    hash.sha256(0, filesize) == "0a71a7bc60ccea3ab59938a724508536b5186352f00ab3df857c8f83fb5502d6"
}
```

### Sample 88: `1da1708bf4c4768f`

| Field | Value |
|---|---|
| SHA-256 | `1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9` |
| Family label | `Snowlight` |
| File name | `1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9.bin` |
| File type | `elf` |
| First seen | `2026-09-22 03:30:18` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5d6d6c4df6332fb944b654fe49420a9` |
| SHA-1 | `f117e488ae775e5313699cac1bdecf147a4069a8` |
| SHA-256 | `1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9` |
| SHA3-384 | `df3448f5ece3891f928fb4767157b3038e4d21b8251c44428be6046cfeebc100829825fc77535e47d7bc66a22457e72d` |
| TLSH | `T19A123F47A2D0CE3FC8D957384867122472B394BADF629713064815B63F427E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6ZH5ML09V1J9G8Yme+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHaZMWT1YmzhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_088_1da1708b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9"
    family = "Snowlight"
    file_name = "1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:18"
  condition:
    hash.sha256(0, filesize) == "1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9"
}
```

### Sample 89: `ca3235df8fcdcd0b`

| Field | Value |
|---|---|
| SHA-256 | `ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397` |
| Family label | `unknown` |
| File name | `ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397.bin` |
| File type | `elf` |
| First seen | `2026-09-22 03:30:17` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ea3510d260a3f37c4a9d2407c56c100` |
| SHA-1 | `ef169588fb8dd5e9cacaeb21ec73a09e2a7e3b50` |
| SHA-256 | `ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397` |
| SHA3-384 | `d5514dd163184f23abbc87b960503952d0e9dfd13d2db7bdf5bc42680dfe05222e40b7e3b30cf947015e1abec10d8136` |
| TLSH | `T133E13482BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsLLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvug/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_ca3235df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397"
    family = "unknown"
    file_name = "ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:17"
  condition:
    hash.sha256(0, filesize) == "ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397"
}
```

### Sample 90: `8cf51cb2140fc6ac`

| Field | Value |
|---|---|
| SHA-256 | `8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d` |
| Family label | `Mirai` |
| File name | `8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d.bin` |
| File type | `elf` |
| First seen | `2026-09-22 03:30:15` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c166eb5965aa1cfd5f4f934586ecde8` |
| SHA-1 | `415703a80415a8149717721eddd3ff48e1f1f889` |
| SHA-256 | `8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d` |
| SHA3-384 | `f0dc2e0362877e32cadd197df94b3591813b9016db52b5453588bc0ce4f7001a8c006c1f3bcaf200cbe6959279d33000` |
| TLSH | `T1D2F14256BAEBCD73CCAD233A07678714337588D2AF42AB13610C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtmWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7K4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_8cf51cb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d"
    family = "Mirai"
    file_name = "8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:15"
  condition:
    hash.sha256(0, filesize) == "8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d"
}
```

### Sample 91: `9c1afc0aab073c33`

| Field | Value |
|---|---|
| SHA-256 | `9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04` |
| Family label | `unknown` |
| File name | `9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04.bin` |
| File type | `macho` |
| First seen | `2026-09-22 03:30:13` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a89da96da22c1d7f787f149c092b1eb4` |
| SHA-1 | `1c5d4ae85df0c09bdc565e2c07deb457fe7bd8d7` |
| SHA-256 | `9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04` |
| SHA3-384 | `d040d14cbcfe532ff757ce5c67bb73b18889be099f9dd4f5e3077eee1e0c874ca52e34a91474d0761fc215fee59805d9` |
| TLSH | `T172F24E139B1C1A61C55C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRdPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfAlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_9c1afc0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04"
    family = "unknown"
    file_name = "9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04.bin"
    file_type = "macho"
    first_seen = "2026-09-22 03:30:13"
  condition:
    hash.sha256(0, filesize) == "9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04"
}
```

### Sample 92: `43fb2f8baa1c6148`

| Field | Value |
|---|---|
| SHA-256 | `43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e` |
| Family label | `Mirai` |
| File name | `43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e.bin` |
| File type | `elf` |
| First seen | `2026-09-22 03:30:09` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d677323b731d0b0fe4c038d15bbaa9d` |
| SHA-1 | `f6192f8cf91e10eb5c6cb3e8618bf81537a92dd3` |
| SHA-256 | `43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e` |
| SHA3-384 | `363c90ba5fc82767b5cebf04531f6a6bf832c0abcc5374fb92bf65aea765c9ef81e627461cad74ffabdb29c53a0d87fc` |
| TLSH | `T1ABF14356BAEBCD73CCAD233907678714337588D2AB42AB13511C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DteWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7a4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_43fb2f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e"
    family = "Mirai"
    file_name = "43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:09"
  condition:
    hash.sha256(0, filesize) == "43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e"
}
```

### Sample 93: `00073b735ce5801a`

| Field | Value |
|---|---|
| SHA-256 | `00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce` |
| Family label | `Mirai` |
| File name | `00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce.bin` |
| File type | `elf` |
| First seen | `2026-09-22 03:30:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83c72b41e9fbdb7195d96b3921dc135a` |
| SHA-1 | `89f04189bd39ab08e335e1bc3ad3938b16da7ebf` |
| SHA-256 | `00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce` |
| SHA3-384 | `1e53586409957014dad57762998a7662fbc885f4f2ac17633e9005350f70ffbeee1c144b232085b9c62ad302d8b45c1f` |
| TLSH | `T1DC125047A2D1CE7FC8E813384467122472BBD47ADFA29713050C64B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf53lTTej6TNJ9VNNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTHTTfTpV9dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_00073b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce"
    family = "Mirai"
    file_name = "00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:06"
  condition:
    hash.sha256(0, filesize) == "00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce"
}
```

### Sample 94: `d5813da58c59b237`

| Field | Value |
|---|---|
| SHA-256 | `d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24` |
| Family label | `unknown` |
| File name | `d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24.bin` |
| File type | `elf` |
| First seen | `2026-09-22 03:30:03` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1948b625b180f39419d3f6c76993b3f3` |
| SHA-1 | `8c5de92fdfb5d18c4fc5ff1e9950ab4aae584451` |
| SHA-256 | `d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24` |
| SHA3-384 | `8445d069feecf113eccacf0d2d441733c0b1fe552f2ad923fa974ed3deaf3bd5d3b26607c540c7ef039b7753d0174a01` |
| TLSH | `T19B22EC17F3E5DDFFC8AA577409A312703223C836DB428783680C46543FAB29E6EA5644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOftsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxftsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_d5813da5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24"
    family = "unknown"
    file_name = "d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:03"
  condition:
    hash.sha256(0, filesize) == "d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24"
}
```

### Sample 95: `ededcfc04224f39c`

| Field | Value |
|---|---|
| SHA-256 | `ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6` |
| Family label | `unknown` |
| File name | `ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6` |
| File type | `elf` |
| First seen | `2026-09-22 03:18:31` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03b8b980f2c357633e195ec595844edf` |
| SHA-1 | `d8707b3e2868960972d8d1f3e25f1bb916da5385` |
| SHA-256 | `ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6` |
| SHA3-384 | `c5e6f171bf3b70f5508d7c498556d729f326182bbcc7d3a41a306cb063bd65f80cdf8f76668dcae588510536b292aa6d` |
| TLSH | `T182C3089BBC81DE6946C0277BFE2E418E330327B4D1DF71139D141F68B68A94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuan:T2s/gAWuboqsJ9xcJxspJBqQgTuan` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_ededcfc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6"
    family = "unknown"
    file_name = "ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6"
    file_type = "elf"
    first_seen = "2026-09-22 03:18:31"
  condition:
    hash.sha256(0, filesize) == "ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6"
}
```

### Sample 96: `f6a2a23979851cab`

| Field | Value |
|---|---|
| SHA-256 | `f6a2a23979851cabf9f815eb88e1e08d027efb2b2383366605e30531c68982cb` |
| Family label | `unknown` |
| File name | `NordVPN_Бесплатный.vpn (2).apk` |
| File type | `apk` |
| First seen | `2026-09-22 03:05:10` |
| Reporter | `Parper` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f0c01c2287d5bd0017217a14d426b91` |
| SHA-1 | `546be924d719c5982fe0ece47ff096cff9fca1d1` |
| SHA-256 | `f6a2a23979851cabf9f815eb88e1e08d027efb2b2383366605e30531c68982cb` |
| SHA3-384 | `e19f9aafcdad915d1f66c71d0547f0110490251bab94e22b2da6a92013a07df7f401b96329e376d99a391676134415bb` |
| TLSH | `T10BA612318D082D33C425577B55A24663677B9B8827A2D33F4BB829287CF7F828B1D875` |
| SSDEEP | `196608:CAF/TkjXYzTS7UvP74YqqVNPl3N198y+fPwsRcJvkaUC:CWyXsoKNVT3Njx+f4laC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_f6a2a239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6a2a23979851cabf9f815eb88e1e08d027efb2b2383366605e30531c68982cb"
    family = "unknown"
    file_name = "NordVPN_Бесплатный.vpn (2).apk"
    file_type = "apk"
    first_seen = "2026-09-22 03:05:10"
  condition:
    hash.sha256(0, filesize) == "f6a2a23979851cabf9f815eb88e1e08d027efb2b2383366605e30531c68982cb"
}
```

### Sample 97: `0f20bfa5bb9dc9a4`

| Field | Value |
|---|---|
| SHA-256 | `0f20bfa5bb9dc9a475e79f7ead3e713ad93f53ddcdc078a63fb589787f5372e4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 03:04:38` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `160cf7e773b44b243ee7732a193805f1` |
| SHA-1 | `12bca8bc3ffb55c5f92cfd90845d99f7765085fc` |
| SHA-256 | `0f20bfa5bb9dc9a475e79f7ead3e713ad93f53ddcdc078a63fb589787f5372e4` |
| SHA3-384 | `3e3578b32d761cef2ebf6306e7c2993cfa66bb2e0c9c6b7c8f4182305dc9ea166482b2f516d15fef48084f3447cd21bc` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16C62E79AD8A26E6CCE4E80703E11F938BD713691962669E3D7818C315DA39D00534FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UNiBgn:fKOe2/7c9sN3zfZR1m+RGv6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_0f20bfa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f20bfa5bb9dc9a475e79f7ead3e713ad93f53ddcdc078a63fb589787f5372e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:04:38"
  condition:
    hash.sha256(0, filesize) == "0f20bfa5bb9dc9a475e79f7ead3e713ad93f53ddcdc078a63fb589787f5372e4"
}
```

### Sample 98: `e47c8eecb0f5b1ee`

| Field | Value |
|---|---|
| SHA-256 | `e47c8eecb0f5b1ee6024d9c12f70bb465a555bfedb5ba949dba493c75ff59a01` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-22 03:01:51` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55c9590f49bbe0a45e2083a5e54439ac` |
| SHA-1 | `cbdebd8db7b6e0486531d0a8672dbf6e4825fde7` |
| SHA-256 | `e47c8eecb0f5b1ee6024d9c12f70bb465a555bfedb5ba949dba493c75ff59a01` |
| SHA3-384 | `008fadfd887d49bc83bce5ae951e8ab2438f7a9b867b274448ab8b4cd4ba6e6404b8ff18c0079aa43936bba101b39e4a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19E62B687D8E26E5CDF4E90B03A11FC7A797076E146659AE3DB828C3199A39D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U+bBgn:fKOe2/7c9sN3zfZR1m+RGFb6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_e47c8eec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e47c8eecb0f5b1ee6024d9c12f70bb465a555bfedb5ba949dba493c75ff59a01"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:01:51"
  condition:
    hash.sha256(0, filesize) == "e47c8eecb0f5b1ee6024d9c12f70bb465a555bfedb5ba949dba493c75ff59a01"
}
```

### Sample 99: `0356cc5dbb826085`

| Field | Value |
|---|---|
| SHA-256 | `0356cc5dbb826085c0de5ca038d5888bf29cd4c80b26da987a2b9dc2eee727be` |
| Family label | `unknown` |
| File name | `macho_0356cc5dbb82.bin` |
| File type | `macho` |
| First seen | `2026-09-22 02:45:14` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28f6727a40ee1c2f1d61cafcfdb3ca7a` |
| SHA-1 | `ae4d59acce80bdce81a199eed1b58533ebd135c9` |
| SHA-256 | `0356cc5dbb826085c0de5ca038d5888bf29cd4c80b26da987a2b9dc2eee727be` |
| SHA3-384 | `c9460ae7274e55bcec2df2a2bcbe757d69e31b3fba3cf01e004e6d6f2d857d07560bdc19925fb28447d0c7543fd2938c` |
| TLSH | `T11D0502019F719866F5CCD3342F3A9A338B21A6614C8456DE67532F488E353E3F66B31A` |
| SSDEEP | `12288:niQHNA1KfEtqlXHfMoXc8zNg44NZHaI3I8J:nLJfT/AGg4KVQ2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_0356cc5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0356cc5dbb826085c0de5ca038d5888bf29cd4c80b26da987a2b9dc2eee727be"
    family = "unknown"
    file_name = "macho_0356cc5dbb82.bin"
    file_type = "macho"
    first_seen = "2026-09-22 02:45:14"
  condition:
    hash.sha256(0, filesize) == "0356cc5dbb826085c0de5ca038d5888bf29cd4c80b26da987a2b9dc2eee727be"
}
```

### Sample 100: `20b6b35078935b2e`

| Field | Value |
|---|---|
| SHA-256 | `20b6b35078935b2e905de50bbe0c8daeedad2e9d7683174407df1cc0d5185023` |
| Family label | `unknown` |
| File name | `libcurl.dll` |
| File type | `exe` |
| First seen | `2026-09-22 02:33:57` |
| Reporter | `Parper` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c83d32a904be8877665690ebc573f024` |
| SHA-1 | `1117a891852bae887c8f4040fcb5bf7c65f5f2ad` |
| SHA-256 | `20b6b35078935b2e905de50bbe0c8daeedad2e9d7683174407df1cc0d5185023` |
| SHA3-384 | `089f000a729ad3e99517eb0de0f75da5561a105838bef2a947ad5d8e88298d1bf72214265e847198f160e8faee2966f5` |
| IMPHASH | `1e6a4142ad6a521fe1a5012997804f01` |
| TLSH | `T10F452357ABD01C7AC6B9C23CC4232E05EB32785289A59BBF47F401964F67B510DBBE21` |
| SSDEEP | `24576:2319HHaGb4Cmuwmbhsci+j4DBrMDYRY6O0eIKe1B5vJc:2HaGP6chN6/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_20b6b350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20b6b35078935b2e905de50bbe0c8daeedad2e9d7683174407df1cc0d5185023"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-09-22 02:33:57"
  condition:
    hash.sha256(0, filesize) == "20b6b35078935b2e905de50bbe0c8daeedad2e9d7683174407df1cc0d5185023"
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
 * Generated: 2026-09-22T05:07:59.421667+00:00
 */

rule MalwareBazaar_unknown_001_9fb95a7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb95a7aa0a78ef144cf49b4c97bfd2478e835ea05acdb0f5311c0aa138ff145"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-22 05:07:50"
  condition:
    hash.sha256(0, filesize) == "9fb95a7aa0a78ef144cf49b4c97bfd2478e835ea05acdb0f5311c0aa138ff145"
}

rule MalwareBazaar_unknown_002_2b028191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b028191a4e34a9d7e83e7a98e242541d377dcce3495437b3d3e4a2c80c6d4a8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 05:06:50"
  condition:
    hash.sha256(0, filesize) == "2b028191a4e34a9d7e83e7a98e242541d377dcce3495437b3d3e4a2c80c6d4a8"
}

rule MalwareBazaar_Mirai_003_4824b25e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4824b25eb39469992af6ec1a4f86239fd457aaeea84efcae1e1c8c9f62c78ab6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-22 05:00:41"
  condition:
    hash.sha256(0, filesize) == "4824b25eb39469992af6ec1a4f86239fd457aaeea84efcae1e1c8c9f62c78ab6"
}

rule MalwareBazaar_Mirai_004_b55300d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b55300d14b8e52cfc4acaba43eec15bc6058b860483f9132d9df0843b6838bd9"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-22 05:00:24"
  condition:
    hash.sha256(0, filesize) == "b55300d14b8e52cfc4acaba43eec15bc6058b860483f9132d9df0843b6838bd9"
}

rule MalwareBazaar_Mirai_005_4e1be65b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e1be65b2bbbb73ff6fe6c1c9cfef0fa250b1ceaae02f89d3c3d028056ba601b"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-22 04:57:41"
  condition:
    hash.sha256(0, filesize) == "4e1be65b2bbbb73ff6fe6c1c9cfef0fa250b1ceaae02f89d3c3d028056ba601b"
}

rule MalwareBazaar_Mirai_006_88ff66c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88ff66c7021503253a2523c5fd779a2643457cc3f5fb9cd6b3c81272f8efb20b"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-09-22 04:57:40"
  condition:
    hash.sha256(0, filesize) == "88ff66c7021503253a2523c5fd779a2643457cc3f5fb9cd6b3c81272f8efb20b"
}

rule MalwareBazaar_Mirai_007_a1baca3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1baca3a9b387aa478edeed198bd6263fdc60c6850281c4da8836915cc4fc404"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:56:18"
  condition:
    hash.sha256(0, filesize) == "a1baca3a9b387aa478edeed198bd6263fdc60c6850281c4da8836915cc4fc404"
}

rule MalwareBazaar_Gafgyt_008_f28609e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f28609e7a34618adf7487d8b257637faa648982774fbc81f31bdc71efaa608c3"
    family = "Gafgyt"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:55:19"
  condition:
    hash.sha256(0, filesize) == "f28609e7a34618adf7487d8b257637faa648982774fbc81f31bdc71efaa608c3"
}

rule MalwareBazaar_Mirai_009_6d452b17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d452b17f963cd2e1636d1c1e1baa8f5b6663f5bc4d55a90e95d1fb926c15139"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-22 04:50:24"
  condition:
    hash.sha256(0, filesize) == "6d452b17f963cd2e1636d1c1e1baa8f5b6663f5bc4d55a90e95d1fb926c15139"
}

rule MalwareBazaar_Mirai_010_3280724b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3280724b7856f29be56ecbabfdbd43018a488e95462dfce5d61fe582b044327a"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-09-22 04:47:42"
  condition:
    hash.sha256(0, filesize) == "3280724b7856f29be56ecbabfdbd43018a488e95462dfce5d61fe582b044327a"
}

rule MalwareBazaar_Mirai_011_3b33bd88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b33bd887a1de3f0935c10d159dca99e123dc251a3074c2caf5085ed21334ee2"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-22 04:46:19"
  condition:
    hash.sha256(0, filesize) == "3b33bd887a1de3f0935c10d159dca99e123dc251a3074c2caf5085ed21334ee2"
}

rule MalwareBazaar_Mirai_012_656e539a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "656e539abc54f262eabb6d091df50f9bec71a55905421f0a3fc2eb451aa0409e"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-22 04:45:20"
  condition:
    hash.sha256(0, filesize) == "656e539abc54f262eabb6d091df50f9bec71a55905421f0a3fc2eb451aa0409e"
}

rule MalwareBazaar_Mirai_013_e6c0edd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6c0edd85dcef6c64d9afcc6503f31e2d9bf142a65c193191434db7f4a938c93"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-22 04:37:48"
  condition:
    hash.sha256(0, filesize) == "e6c0edd85dcef6c64d9afcc6503f31e2d9bf142a65c193191434db7f4a938c93"
}

rule MalwareBazaar_unknown_014_34c34031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34c3403102077f7cb506794533d855a229f457e210fb0848e836805f61136738"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:36:27"
  condition:
    hash.sha256(0, filesize) == "34c3403102077f7cb506794533d855a229f457e210fb0848e836805f61136738"
}

rule MalwareBazaar_unknown_015_8ff4db8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ff4db8ba96b9f1fc116320d24f6b3705b0f3d9b27dfe9c87795ba5bc21e6eac"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:35:21"
  condition:
    hash.sha256(0, filesize) == "8ff4db8ba96b9f1fc116320d24f6b3705b0f3d9b27dfe9c87795ba5bc21e6eac"
}

rule MalwareBazaar_unknown_016_0fa58ede
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fa58edeec9dd4bb18b48f8bcdaad4b22067f8eae6b6845c4450fabce4e2de71"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:34:08"
  condition:
    hash.sha256(0, filesize) == "0fa58edeec9dd4bb18b48f8bcdaad4b22067f8eae6b6845c4450fabce4e2de71"
}

rule MalwareBazaar_Mirai_017_f881db27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f881db27f82e58f72bf6475130f23a3cf12dbec3688fcf7b15901fbb543d8c79"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:33:15"
  condition:
    hash.sha256(0, filesize) == "f881db27f82e58f72bf6475130f23a3cf12dbec3688fcf7b15901fbb543d8c79"
}

rule MalwareBazaar_unknown_018_7ee4e76a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ee4e76a81d8ad7cfcd235dff014376972ab6af8de3fcbc59d6f85a7a84ae551"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:32:56"
  condition:
    hash.sha256(0, filesize) == "7ee4e76a81d8ad7cfcd235dff014376972ab6af8de3fcbc59d6f85a7a84ae551"
}

rule MalwareBazaar_Mirai_019_6ff24f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff24f7acce257889f3475be2b0862c3cb9b2d3c6f6668d5883b970cec0f3aaa"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-09-22 04:30:31"
  condition:
    hash.sha256(0, filesize) == "6ff24f7acce257889f3475be2b0862c3cb9b2d3c6f6668d5883b970cec0f3aaa"
}

rule MalwareBazaar_Mirai_020_4cc356f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cc356f289e07ab01e8cea91a99c484a71497674933e084eb571799e494875b3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:30:30"
  condition:
    hash.sha256(0, filesize) == "4cc356f289e07ab01e8cea91a99c484a71497674933e084eb571799e494875b3"
}

rule MalwareBazaar_Mirai_021_e477d71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e477d71b715cc76bd775b3c1e533c0d58c617687ca9286f9b77e01fa1d7af1df"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-22 04:30:29"
  condition:
    hash.sha256(0, filesize) == "e477d71b715cc76bd775b3c1e533c0d58c617687ca9286f9b77e01fa1d7af1df"
}

rule MalwareBazaar_unknown_022_7708a9da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7708a9dad1e14af5ffff9fb8e3d9505005d8c70a184a3ece34e589697ae22241"
    family = "unknown"
    file_name = "fuck_niggers_39.hta"
    file_type = "hta"
    first_seen = "2026-09-22 04:30:27"
  condition:
    hash.sha256(0, filesize) == "7708a9dad1e14af5ffff9fb8e3d9505005d8c70a184a3ece34e589697ae22241"
}

rule MalwareBazaar_unknown_023_d905e055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8"
    family = "unknown"
    file_name = "d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:30:03"
  condition:
    hash.sha256(0, filesize) == "d905e0552d522984f7442edb7cdb454843977c0ba7006c86f3d12e5058ff77d8"
}

rule MalwareBazaar_unknown_024_5ee6fd37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ee6fd37ac43946e7bbd556bfd730c11d725ce0bc2b0dc734688f936f216ce2f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:27:04"
  condition:
    hash.sha256(0, filesize) == "5ee6fd37ac43946e7bbd556bfd730c11d725ce0bc2b0dc734688f936f216ce2f"
}

rule MalwareBazaar_Mirai_025_2f6d1c28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6d1c289f18d78243840e5dad1f832e34a794e5b5f4b997fa4e95ae0b715527"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-22 04:25:40"
  condition:
    hash.sha256(0, filesize) == "2f6d1c289f18d78243840e5dad1f832e34a794e5b5f4b997fa4e95ae0b715527"
}

rule MalwareBazaar_Mirai_026_dfeea5e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfeea5e6642130bb2690f0d3928ae2b65e72b2f10ab38684468677ff0cc06b12"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:32"
  condition:
    hash.sha256(0, filesize) == "dfeea5e6642130bb2690f0d3928ae2b65e72b2f10ab38684468677ff0cc06b12"
}

rule MalwareBazaar_Mirai_027_0a36bf76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a36bf76fe54ed05c2c000c8ed91e66c073b537e4559889d27db691bf94f2fa6"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:18"
  condition:
    hash.sha256(0, filesize) == "0a36bf76fe54ed05c2c000c8ed91e66c073b537e4559889d27db691bf94f2fa6"
}

rule MalwareBazaar_Mirai_028_808a9695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "808a9695b9a6781293f766ce3b3d747884a8af143045f25b8727af445ff92509"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:17"
  condition:
    hash.sha256(0, filesize) == "808a9695b9a6781293f766ce3b3d747884a8af143045f25b8727af445ff92509"
}

rule MalwareBazaar_Mirai_029_45742a7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45742a7a1c3e6502161a70441a40d5a19d6abef81e9378eb988c9a0c8e0100c0"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:15"
  condition:
    hash.sha256(0, filesize) == "45742a7a1c3e6502161a70441a40d5a19d6abef81e9378eb988c9a0c8e0100c0"
}

rule MalwareBazaar_unknown_030_ec65a698
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec65a69848c51546e38fdeea9ad5f1df8166a4fd5bf55b7410e491d6929b4539"
    family = "unknown"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:14"
  condition:
    hash.sha256(0, filesize) == "ec65a69848c51546e38fdeea9ad5f1df8166a4fd5bf55b7410e491d6929b4539"
}

rule MalwareBazaar_Mirai_031_9c390922
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c390922b43100f26adef9a8324eab473803e4ccd51014fe1da460f25534b209"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:23:13"
  condition:
    hash.sha256(0, filesize) == "9c390922b43100f26adef9a8324eab473803e4ccd51014fe1da460f25534b209"
}

rule MalwareBazaar_Mirai_032_868baedc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "868baedc6d4e5b1092e2dea434cc234263974e50d62755357785f6dd8a3de40e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:21:29"
  condition:
    hash.sha256(0, filesize) == "868baedc6d4e5b1092e2dea434cc234263974e50d62755357785f6dd8a3de40e"
}

rule MalwareBazaar_Mirai_033_337a809f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "337a809ff61b8c49f6c0222c81b966ddf1d9ba7d55497ca81aa1680fcd1a3659"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:20:44"
  condition:
    hash.sha256(0, filesize) == "337a809ff61b8c49f6c0222c81b966ddf1d9ba7d55497ca81aa1680fcd1a3659"
}

rule MalwareBazaar_unknown_034_67a80d38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84"
    family = "unknown"
    file_name = "67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:20:17"
  condition:
    hash.sha256(0, filesize) == "67a80d38322f97e9df0c48060f9a89bdf5923dd416d1ee4add83ded2b028ab84"
}

rule MalwareBazaar_Mirai_035_5a288187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7"
    family = "Mirai"
    file_name = "5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7.bin"
    file_type = "elf"
    first_seen = "2026-09-22 04:20:13"
  condition:
    hash.sha256(0, filesize) == "5a288187008c829aad47cfdb716601f89b4a5b638f53acf1c5a51adb419019c7"
}

rule MalwareBazaar_unknown_036_0f5546ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74"
    family = "unknown"
    file_name = "0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:20:10"
  condition:
    hash.sha256(0, filesize) == "0f5546ed97ada81c095f38c2e9fa6766865f608ca3baff975bf82a81730b0b74"
}

rule MalwareBazaar_Snowlight_037_ea12ecd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a"
    family = "Snowlight"
    file_name = "ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a.bin"
    file_type = "elf"
    first_seen = "2026-09-22 04:20:07"
  condition:
    hash.sha256(0, filesize) == "ea12ecd7d5475e52ec6ba688a19d997730283ee22a7974b0af9da0633c96714a"
}

rule MalwareBazaar_unknown_038_9179d88e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb"
    family = "unknown"
    file_name = "9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:20:04"
  condition:
    hash.sha256(0, filesize) == "9179d88e423d35521801d98b1c697cbf78b27a55188a3e7844e0a444998c9adb"
}

rule MalwareBazaar_Mirai_039_49f56ada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49f56adacc76cb9951cbd211080e6f432c2f4d4f67107ff4ca01ee9f37d204d5"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-22 04:19:28"
  condition:
    hash.sha256(0, filesize) == "49f56adacc76cb9951cbd211080e6f432c2f4d4f67107ff4ca01ee9f37d204d5"
}

rule MalwareBazaar_unknown_040_bc23937a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac"
    family = "unknown"
    file_name = "bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac"
    file_type = "elf"
    first_seen = "2026-09-22 04:18:46"
  condition:
    hash.sha256(0, filesize) == "bc23937a2be3b9e5843f5337589b22f1a2448b9965db1b6ba395b6440c10fbac"
}

rule MalwareBazaar_Mirai_041_8117b207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8117b2072c377ce574fb9acc5f11020b74954c419460ce801144a867f5a28e2b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-22 04:18:27"
  condition:
    hash.sha256(0, filesize) == "8117b2072c377ce574fb9acc5f11020b74954c419460ce801144a867f5a28e2b"
}

rule MalwareBazaar_Mirai_042_eb21e3bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb21e3bc8b67a94c43548776767d6ec03e27463b431eda424ee10b14d667909e"
    family = "Mirai"
    file_name = "tpijtvcr.mips64"
    file_type = "elf"
    first_seen = "2026-09-22 04:18:26"
  condition:
    hash.sha256(0, filesize) == "eb21e3bc8b67a94c43548776767d6ec03e27463b431eda424ee10b14d667909e"
}

rule MalwareBazaar_unknown_043_4ec01f8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec01f8e51ae1922b416474cfc4a7df444ec03751217cd3ba7476ea68e4b83b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:16:23"
  condition:
    hash.sha256(0, filesize) == "4ec01f8e51ae1922b416474cfc4a7df444ec03751217cd3ba7476ea68e4b83b3"
}

rule MalwareBazaar_unknown_044_39c9e4b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39c9e4b4145737291169c46a0c76b097437f02d14122e9c67cabc29e288c63b7"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-09-22 04:14:08"
  condition:
    hash.sha256(0, filesize) == "39c9e4b4145737291169c46a0c76b097437f02d14122e9c67cabc29e288c63b7"
}

rule MalwareBazaar_Mirai_045_1ad0fd13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ad0fd139090f30a5c270f77304e898ee4219b73b8afeb34f56ffb360b2615cd"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-09-22 04:14:07"
  condition:
    hash.sha256(0, filesize) == "1ad0fd139090f30a5c270f77304e898ee4219b73b8afeb34f56ffb360b2615cd"
}

rule MalwareBazaar_unknown_046_d0500c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0500c994f047097cff60c37d5ee64e8fd15d2b030f66912bd732dcedb4fb950"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:13:50"
  condition:
    hash.sha256(0, filesize) == "d0500c994f047097cff60c37d5ee64e8fd15d2b030f66912bd732dcedb4fb950"
}

rule MalwareBazaar_Mirai_047_4e307c71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e307c7135af75e51e1143b4541fd20bbf5259d63fca15c139deb0486cea6255"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:32"
  condition:
    hash.sha256(0, filesize) == "4e307c7135af75e51e1143b4541fd20bbf5259d63fca15c139deb0486cea6255"
}

rule MalwareBazaar_Mirai_048_7c22c8ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c22c8ca4ad12a6f83c4fce2c00e39140b618e1aab9c2c892c1ddf00038eac45"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:30"
  condition:
    hash.sha256(0, filesize) == "7c22c8ca4ad12a6f83c4fce2c00e39140b618e1aab9c2c892c1ddf00038eac45"
}

rule MalwareBazaar_Mirai_049_c43142af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c43142af94ce18731580ca2d1b667152458c71fa1051e9e9376ea57be1990d43"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:29"
  condition:
    hash.sha256(0, filesize) == "c43142af94ce18731580ca2d1b667152458c71fa1051e9e9376ea57be1990d43"
}

rule MalwareBazaar_Mirai_050_ed0d357c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed0d357c20350cc7bdb6f9f4a8c1a5f1083cd9dd5bb3955bdb6c5dad53dc3e08"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:26"
  condition:
    hash.sha256(0, filesize) == "ed0d357c20350cc7bdb6f9f4a8c1a5f1083cd9dd5bb3955bdb6c5dad53dc3e08"
}

rule MalwareBazaar_Mirai_051_10ef901c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ef901cc942e5c0885ea96c9350c934b0ea6cc3a530d0c35757c9043e263093"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-22 04:12:24"
  condition:
    hash.sha256(0, filesize) == "10ef901cc942e5c0885ea96c9350c934b0ea6cc3a530d0c35757c9043e263093"
}

rule MalwareBazaar_Mirai_052_6586ac36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6586ac367d483ff1409ec55c206b7d3401f2947de1786a40e12158319f895fa3"
    family = "Mirai"
    file_name = "tpijtvcr.mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:37"
  condition:
    hash.sha256(0, filesize) == "6586ac367d483ff1409ec55c206b7d3401f2947de1786a40e12158319f895fa3"
}

rule MalwareBazaar_Mirai_053_7881a1c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7881a1c74eb8225530086b97fbc61037d3f86f7338c5d48248d99d432f04bdab"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:36"
  condition:
    hash.sha256(0, filesize) == "7881a1c74eb8225530086b97fbc61037d3f86f7338c5d48248d99d432f04bdab"
}

rule MalwareBazaar_Mirai_054_767bc5e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "767bc5e083d0e68015493075233e3c938d73f3b9d7d186c4226bdae110cdf76c"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:35"
  condition:
    hash.sha256(0, filesize) == "767bc5e083d0e68015493075233e3c938d73f3b9d7d186c4226bdae110cdf76c"
}

rule MalwareBazaar_Mirai_055_7b778454
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b778454d0034781ce9d544963ddfe9bc6062a3de49bcea7d3d32db3bf9d3ad4"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:33"
  condition:
    hash.sha256(0, filesize) == "7b778454d0034781ce9d544963ddfe9bc6062a3de49bcea7d3d32db3bf9d3ad4"
}

rule MalwareBazaar_Mirai_056_55a16f04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a16f04fddda7dcb0296f0496ba45eef9bc9b2d449d8c96bcb89b23a6ff2093"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:32"
  condition:
    hash.sha256(0, filesize) == "55a16f04fddda7dcb0296f0496ba45eef9bc9b2d449d8c96bcb89b23a6ff2093"
}

rule MalwareBazaar_Mirai_057_7bed3a21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bed3a2187eadf3b02f0ec4f1277fe2921dc98716a4f8d29c321c8aaa11afdc7"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:31"
  condition:
    hash.sha256(0, filesize) == "7bed3a2187eadf3b02f0ec4f1277fe2921dc98716a4f8d29c321c8aaa11afdc7"
}

rule MalwareBazaar_Mirai_058_fd190f58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd190f5878eb26d07cf60a4533c17400eef1aaa6a82a7730f33a3c0fdd5806ff"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:30"
  condition:
    hash.sha256(0, filesize) == "fd190f5878eb26d07cf60a4533c17400eef1aaa6a82a7730f33a3c0fdd5806ff"
}

rule MalwareBazaar_Mirai_059_2c3245b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c3245b63e7e18bb762f72d57f338f1c40e5032289c2714a81eeeb4c7d9821d4"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-09-22 04:11:29"
  condition:
    hash.sha256(0, filesize) == "2c3245b63e7e18bb762f72d57f338f1c40e5032289c2714a81eeeb4c7d9821d4"
}

rule MalwareBazaar_unknown_060_776c519a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "776c519ae7e093e009447f7c3f4636331b307793409fb71d5fae9e6f5404d24d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 04:11:20"
  condition:
    hash.sha256(0, filesize) == "776c519ae7e093e009447f7c3f4636331b307793409fb71d5fae9e6f5404d24d"
}

rule MalwareBazaar_Mirai_061_ec8dc99e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec8dc99e36906cdfd88d6bbf0ebe1b409a420fbb8051b30181225bf3e94cd362"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-22 04:10:26"
  condition:
    hash.sha256(0, filesize) == "ec8dc99e36906cdfd88d6bbf0ebe1b409a420fbb8051b30181225bf3e94cd362"
}

rule MalwareBazaar_unknown_062_e8fdb578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8fdb578177f84033916427efad848f72d8fd43e1672744fc625b5165f2feca7"
    family = "unknown"
    file_name = "macho_e8fdb578177f.bin"
    file_type = "macho"
    first_seen = "2026-09-22 04:10:18"
  condition:
    hash.sha256(0, filesize) == "e8fdb578177f84033916427efad848f72d8fd43e1672744fc625b5165f2feca7"
}

rule MalwareBazaar_unknown_063_311b06b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044"
    family = "unknown"
    file_name = "311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044.exe"
    file_type = "exe"
    first_seen = "2026-09-22 04:09:32"
  condition:
    hash.sha256(0, filesize) == "311b06b21cba02b2c7f1a2e822a2bb86f2a8d691b801326e6dde7aec86bf0044"
}

rule MalwareBazaar_Mirai_064_b895922b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b895922be26f51110b67d15ac70b32415b4b3338052bd5d584e6018ec10b70ec"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:24"
  condition:
    hash.sha256(0, filesize) == "b895922be26f51110b67d15ac70b32415b4b3338052bd5d584e6018ec10b70ec"
}

rule MalwareBazaar_Mirai_065_e435cf67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e435cf674b59d13f68e4c985ec71a10338c54f024077467bbd04447a9a500e43"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:23"
  condition:
    hash.sha256(0, filesize) == "e435cf674b59d13f68e4c985ec71a10338c54f024077467bbd04447a9a500e43"
}

rule MalwareBazaar_Mirai_066_01afb7ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01afb7ab7ba3a2bb1ee71d8b6d174f3f6951c6cb75b13e64687b99ea1dbea4fb"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:22"
  condition:
    hash.sha256(0, filesize) == "01afb7ab7ba3a2bb1ee71d8b6d174f3f6951c6cb75b13e64687b99ea1dbea4fb"
}

rule MalwareBazaar_Mirai_067_aad92045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aad92045b93fc25e3729fddcc6ab97e8d0932788e40369da15632ad5e4d60a74"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:20"
  condition:
    hash.sha256(0, filesize) == "aad92045b93fc25e3729fddcc6ab97e8d0932788e40369da15632ad5e4d60a74"
}

rule MalwareBazaar_Mirai_068_b145b5bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b145b5bb3cf0182180e926335f6cf62f00b0524a4d0bf0158ea6136d34d5fe89"
    family = "Mirai"
    file_name = "bot.arm64"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:19"
  condition:
    hash.sha256(0, filesize) == "b145b5bb3cf0182180e926335f6cf62f00b0524a4d0bf0158ea6136d34d5fe89"
}

rule MalwareBazaar_Mirai_069_20b78165
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20b78165243129d67f509342c6d3f6f690fa480263946b2fe6b90569b804e68c"
    family = "Mirai"
    file_name = "ooikocqj.x86_64"
    file_type = "elf"
    first_seen = "2026-09-22 04:09:17"
  condition:
    hash.sha256(0, filesize) == "20b78165243129d67f509342c6d3f6f690fa480263946b2fe6b90569b804e68c"
}

rule MalwareBazaar_unknown_070_f0779a0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7"
    family = "unknown"
    file_name = "f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7.exe"
    file_type = "exe"
    first_seen = "2026-09-22 04:09:01"
  condition:
    hash.sha256(0, filesize) == "f0779a0d621726d0553c12e28c24955b40035dc7fe287bf4f1e7cb9e5cb96ab7"
}

rule MalwareBazaar_ConnectWise_071_b7364d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692"
    family = "ConnectWise"
    file_name = "b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692.msi"
    file_type = "msi"
    first_seen = "2026-09-22 04:08:55"
  condition:
    hash.sha256(0, filesize) == "b7364d80258da883201641ec32b6682e862f266de9436fb73de51931dce80692"
}

rule MalwareBazaar_unknown_072_40a8e6f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16"
    family = "unknown"
    file_name = "40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16.exe"
    file_type = "exe"
    first_seen = "2026-09-22 04:08:41"
  condition:
    hash.sha256(0, filesize) == "40a8e6f126c138dadecc661355e5214459ea7c63d3ed64c0b0224a810baaed16"
}

rule MalwareBazaar_Mirai_073_5db673e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5db673e2ce2424361324469b1c84bf800d73fea50d302004e0866b04729e86f5"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-22 04:07:17"
  condition:
    hash.sha256(0, filesize) == "5db673e2ce2424361324469b1c84bf800d73fea50d302004e0866b04729e86f5"
}

rule MalwareBazaar_unknown_074_448fcc12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448fcc12cbc34e670318dd07c64e61bf91784969e8153e696db58523f77bacad"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-22 04:07:16"
  condition:
    hash.sha256(0, filesize) == "448fcc12cbc34e670318dd07c64e61bf91784969e8153e696db58523f77bacad"
}

rule MalwareBazaar_Mirai_075_7ac45753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac457531bf03557031d6630798a75ce59b1fa98a390f076c5f2d1b5b1b16343"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-09-22 04:05:13"
  condition:
    hash.sha256(0, filesize) == "7ac457531bf03557031d6630798a75ce59b1fa98a390f076c5f2d1b5b1b16343"
}

rule MalwareBazaar_Mirai_076_aaf45dcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaf45dcc5c1fa53c3f9fb482e9d5ac941b5ea30740779358726100b8ae9d44bf"
    family = "Mirai"
    file_name = "ypezhbfg.armv6"
    file_type = "elf"
    first_seen = "2026-09-22 04:05:11"
  condition:
    hash.sha256(0, filesize) == "aaf45dcc5c1fa53c3f9fb482e9d5ac941b5ea30740779358726100b8ae9d44bf"
}

rule MalwareBazaar_unknown_077_df1a7b86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df1a7b868293d9bfbad876349f87bc59520286ac7468c3ddfee421ff75572a26"
    family = "unknown"
    file_name = "update.apk"
    file_type = "apk"
    first_seen = "2026-09-22 04:02:17"
  condition:
    hash.sha256(0, filesize) == "df1a7b868293d9bfbad876349f87bc59520286ac7468c3ddfee421ff75572a26"
}

rule MalwareBazaar_unknown_078_0dc6fa96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc6fa96d4ccd761d916d119d842fe191c9dd24bb0d97936f5fb168e898431f0"
    family = "unknown"
    file_name = "Medicare.apk"
    file_type = "apk"
    first_seen = "2026-09-22 04:02:11"
  condition:
    hash.sha256(0, filesize) == "0dc6fa96d4ccd761d916d119d842fe191c9dd24bb0d97936f5fb168e898431f0"
}

rule MalwareBazaar_unknown_079_31652883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31652883c0c168a09ec00d78a61c581b4125b3dc379452e18ba7873c03b99952"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:48:34"
  condition:
    hash.sha256(0, filesize) == "31652883c0c168a09ec00d78a61c581b4125b3dc379452e18ba7873c03b99952"
}

rule MalwareBazaar_unknown_080_ed4c17e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed4c17e7f94a2832fbecf8a258d4c6ac8edeb441e316a5e5895498e3b6e15fe0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:45:21"
  condition:
    hash.sha256(0, filesize) == "ed4c17e7f94a2832fbecf8a258d4c6ac8edeb441e316a5e5895498e3b6e15fe0"
}

rule MalwareBazaar_Mirai_081_e745c9e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e745c9e5efe20a8a8698c7810872daa88e2693d46bec47c76dd164d675f2b569"
    family = "Mirai"
    file_name = "m.armv5l"
    file_type = "elf"
    first_seen = "2026-09-22 03:42:59"
  condition:
    hash.sha256(0, filesize) == "e745c9e5efe20a8a8698c7810872daa88e2693d46bec47c76dd164d675f2b569"
}

rule MalwareBazaar_unknown_082_0eb0e29c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0eb0e29ca00b7405a80dcd803a40187dd96e5dbeec25390f117a9f966762440e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:42:52"
  condition:
    hash.sha256(0, filesize) == "0eb0e29ca00b7405a80dcd803a40187dd96e5dbeec25390f117a9f966762440e"
}

rule MalwareBazaar_unknown_083_5ec97f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ec97f8bb694f488a7d4aefe3cc5f10b192a9300aa9300c4d1441e9b1823f089"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:40:26"
  condition:
    hash.sha256(0, filesize) == "5ec97f8bb694f488a7d4aefe3cc5f10b192a9300aa9300c4d1441e9b1823f089"
}

rule MalwareBazaar_unknown_084_0ce6c334
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e"
    family = "unknown"
    file_name = "0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e.bin"
    file_type = "zip"
    first_seen = "2026-09-22 03:40:04"
  condition:
    hash.sha256(0, filesize) == "0ce6c33423a25435aa0c6ee5e35d5cedcd2aff636bc5a9518a9c3127e3789d3e"
}

rule MalwareBazaar_AgentTesla_085_e73af00b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e73af00b82dc65195ae47159967583d483fbe60bd2b838c52c5a5e269892b556"
    family = "AgentTesla"
    file_name = "Shipment Documents.JS"
    file_type = "js"
    first_seen = "2026-09-22 03:38:22"
  condition:
    hash.sha256(0, filesize) == "e73af00b82dc65195ae47159967583d483fbe60bd2b838c52c5a5e269892b556"
}

rule MalwareBazaar_unknown_086_5c2549ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c2549ee09b8ab41e83350656d656cbb1ace751f6dedda7f22b631c3bb238512"
    family = "unknown"
    file_name = "u346d5539.exe"
    file_type = "exe"
    first_seen = "2026-09-22 03:38:15"
  condition:
    hash.sha256(0, filesize) == "5c2549ee09b8ab41e83350656d656cbb1ace751f6dedda7f22b631c3bb238512"
}

rule MalwareBazaar_Mirai_087_0a71a7bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a71a7bc60ccea3ab59938a724508536b5186352f00ab3df857c8f83fb5502d6"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-22 03:31:04"
  condition:
    hash.sha256(0, filesize) == "0a71a7bc60ccea3ab59938a724508536b5186352f00ab3df857c8f83fb5502d6"
}

rule MalwareBazaar_Snowlight_088_1da1708b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9"
    family = "Snowlight"
    file_name = "1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:18"
  condition:
    hash.sha256(0, filesize) == "1da1708bf4c4768f33b23c932505876dd59cf1a2b85034b3691397592c64ecc9"
}

rule MalwareBazaar_unknown_089_ca3235df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397"
    family = "unknown"
    file_name = "ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:17"
  condition:
    hash.sha256(0, filesize) == "ca3235df8fcdcd0b00a14eb0b87e494dd4e5b2229ae415be2a9ce40c41d87397"
}

rule MalwareBazaar_Mirai_090_8cf51cb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d"
    family = "Mirai"
    file_name = "8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:15"
  condition:
    hash.sha256(0, filesize) == "8cf51cb2140fc6ac7165be219eea70b9ca92796d128e226b0988d709152a8e5d"
}

rule MalwareBazaar_unknown_091_9c1afc0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04"
    family = "unknown"
    file_name = "9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04.bin"
    file_type = "macho"
    first_seen = "2026-09-22 03:30:13"
  condition:
    hash.sha256(0, filesize) == "9c1afc0aab073c3394d004ab0ff4154e2b46216da64f43f4288c79ead5fd8f04"
}

rule MalwareBazaar_Mirai_092_43fb2f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e"
    family = "Mirai"
    file_name = "43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:09"
  condition:
    hash.sha256(0, filesize) == "43fb2f8baa1c61488b01538bc0ff9be5b7f1a5e3d09a33684b914ecda726558e"
}

rule MalwareBazaar_Mirai_093_00073b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce"
    family = "Mirai"
    file_name = "00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:06"
  condition:
    hash.sha256(0, filesize) == "00073b735ce5801aebe65a018284cd954f5d5a527eb7fbf0eb672da0eda5e6ce"
}

rule MalwareBazaar_unknown_094_d5813da5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24"
    family = "unknown"
    file_name = "d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24.bin"
    file_type = "elf"
    first_seen = "2026-09-22 03:30:03"
  condition:
    hash.sha256(0, filesize) == "d5813da58c59b23785e76adddbcf89cd1ab56f977d8a56353ea1fcba60d97a24"
}

rule MalwareBazaar_unknown_095_ededcfc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6"
    family = "unknown"
    file_name = "ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6"
    file_type = "elf"
    first_seen = "2026-09-22 03:18:31"
  condition:
    hash.sha256(0, filesize) == "ededcfc04224f39c27933343a8a7b3351580606ca529f26c1c8d0165457115d6"
}

rule MalwareBazaar_unknown_096_f6a2a239
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6a2a23979851cabf9f815eb88e1e08d027efb2b2383366605e30531c68982cb"
    family = "unknown"
    file_name = "NordVPN_Бесплатный.vpn (2).apk"
    file_type = "apk"
    first_seen = "2026-09-22 03:05:10"
  condition:
    hash.sha256(0, filesize) == "f6a2a23979851cabf9f815eb88e1e08d027efb2b2383366605e30531c68982cb"
}

rule MalwareBazaar_unknown_097_0f20bfa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f20bfa5bb9dc9a475e79f7ead3e713ad93f53ddcdc078a63fb589787f5372e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:04:38"
  condition:
    hash.sha256(0, filesize) == "0f20bfa5bb9dc9a475e79f7ead3e713ad93f53ddcdc078a63fb589787f5372e4"
}

rule MalwareBazaar_unknown_098_e47c8eec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e47c8eecb0f5b1ee6024d9c12f70bb465a555bfedb5ba949dba493c75ff59a01"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-22 03:01:51"
  condition:
    hash.sha256(0, filesize) == "e47c8eecb0f5b1ee6024d9c12f70bb465a555bfedb5ba949dba493c75ff59a01"
}

rule MalwareBazaar_unknown_099_0356cc5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0356cc5dbb826085c0de5ca038d5888bf29cd4c80b26da987a2b9dc2eee727be"
    family = "unknown"
    file_name = "macho_0356cc5dbb82.bin"
    file_type = "macho"
    first_seen = "2026-09-22 02:45:14"
  condition:
    hash.sha256(0, filesize) == "0356cc5dbb826085c0de5ca038d5888bf29cd4c80b26da987a2b9dc2eee727be"
}

rule MalwareBazaar_unknown_100_20b6b350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20b6b35078935b2e905de50bbe0c8daeedad2e9d7683174407df1cc0d5185023"
    family = "unknown"
    file_name = "libcurl.dll"
    file_type = "exe"
    first_seen = "2026-09-22 02:33:57"
  condition:
    hash.sha256(0, filesize) == "20b6b35078935b2e905de50bbe0c8daeedad2e9d7683174407df1cc0d5185023"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-31

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 634 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 634 |
| Unique family labels | 12 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 45 |
| Mirai | 39 |
| AsyncRAT | 3 |
| Prometei | 2 |
| Vidar | 2 |
| VenomRAT | 2 |
| ConnectWise | 2 |
| AgentTesla | 1 |
| RemcosRAT | 1 |
| ValleyRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 51 |
| exe | 27 |
| sh | 14 |
| unknown | 4 |
| zip | 2 |
| bat | 1 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `f0d8b637f964d937`

| Field | Value |
|---|---|
| SHA-256 | `f0d8b637f964d937fb1d843226272938bdd34cda8ba957a01c029bde06505955` |
| Family label | `unknown` |
| File name | `setup_z8.0.05.exe` |
| File type | `exe` |
| First seen | `2026-08-31 05:45:22` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b662ab416709cc8d7a5fb5a89de7e665` |
| SHA-256 | `f0d8b637f964d937fb1d843226272938bdd34cda8ba957a01c029bde06505955` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_f0d8b637
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d8b637f964d937fb1d843226272938bdd34cda8ba957a01c029bde06505955"
    family = "unknown"
    file_name = "setup_z8.0.05.exe"
    file_type = "exe"
    first_seen = "2026-08-31 05:45:22"
  condition:
    hash.sha256(0, filesize) == "f0d8b637f964d937fb1d843226272938bdd34cda8ba957a01c029bde06505955"
}
```

### Sample 2: `4851063cf8c55d16`

| Field | Value |
|---|---|
| SHA-256 | `4851063cf8c55d16c4c77d107653c3edb5c35a0517a6558c769a594e4cf85e0c` |
| Family label | `AgentTesla` |
| File name | `cotización#especificaciones.exe` |
| File type | `exe` |
| First seen | `2026-08-31 04:17:04` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b0017627c81c861575b736797133601` |
| SHA-1 | `d1b5529fa67a48d049180383d9c22927d9689746` |
| SHA-256 | `4851063cf8c55d16c4c77d107653c3edb5c35a0517a6558c769a594e4cf85e0c` |
| SHA3-384 | `d362367b02e1c660c706bf905943bf034ec6103650898382514d5a97a2bf4316d09595f88b77d1076c775975ef455ca9` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T121A49E1057FC4729D5FF17799478624806B6FA4AA435E78E4A00F8EE2D13F8A7C22727` |
| SSDEEP | `12288:eVdfy9KY3yoZUKy7OgOdYj0UdmSFIUGKEjYy:md6IHoUBigOSj0UdmSFIUGKEjYy` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_002_4851063c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4851063cf8c55d16c4c77d107653c3edb5c35a0517a6558c769a594e4cf85e0c"
    family = "AgentTesla"
    file_name = "cotización#especificaciones.exe"
    file_type = "exe"
    first_seen = "2026-08-31 04:17:04"
  condition:
    hash.sha256(0, filesize) == "4851063cf8c55d16c4c77d107653c3edb5c35a0517a6558c769a594e4cf85e0c"
}
```

### Sample 3: `a8ff87ec07958c46`

| Field | Value |
|---|---|
| SHA-256 | `a8ff87ec07958c46ce45c043befab7efb6bc340868e8431d1b8e0295a103f462` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-31 04:15:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d2d38ea220f0d0dbb3e9e25190d45a3` |
| SHA-1 | `2514394670d501225e814fd8ea09e3aa812a8ba9` |
| SHA-256 | `a8ff87ec07958c46ce45c043befab7efb6bc340868e8431d1b8e0295a103f462` |
| SHA3-384 | `dfee9b6097edac3a4bf851de55623f0877a7434d09aab2cc3c46651cde505864dfc926f08e0a029e7669fd9c6d58873c` |
| TLSH | `T14E236C2516857C24AE98C4361C7E2F0CB9AD83E6324452EE7FCF3CF68C4A6AD910971D` |
| SSDEEP | `768:j+p9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:j+icr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_a8ff87ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ff87ec07958c46ce45c043befab7efb6bc340868e8431d1b8e0295a103f462"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 04:15:55"
  condition:
    hash.sha256(0, filesize) == "a8ff87ec07958c46ce45c043befab7efb6bc340868e8431d1b8e0295a103f462"
}
```

### Sample 4: `6f518952f4f49099`

| Field | Value |
|---|---|
| SHA-256 | `6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-31 04:15:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdd6efe3c9f740a94beea806eef5cc4a` |
| SHA-1 | `57b1115416eb0308dfd006e242aff8dc9482569d` |
| SHA-256 | `6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4` |
| SHA3-384 | `ae959e8db3f1c561ab0db27c838b249f10744c8610ee67512b02359d14cbb9f7cda3d739e48632c2a32814e7daf7edff` |
| TLSH | `T104144C1278E190FDC9D7C139CB9F9016D532F41B1128B22A775DBE662F4EE3067AE680` |
| TELFHASH | `t11a61ff713a52386c32e3b729730ec5d5f83609240ae270eaad73ade4ce9a7c40d62452` |
| SSDEEP | `3072:42zcq3WzUskHUNJFsF2BR0NAaHHpokp98AxvIUmzRTXu1EssMZc/T03ImIys61X+:42zcxk1Fca7pLyT0EssMOgh5ol` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_6f518952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-31 04:15:53"
  condition:
    hash.sha256(0, filesize) == "6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4"
}
```

### Sample 5: `27d5eba8a5c023a6`

| Field | Value |
|---|---|
| SHA-256 | `27d5eba8a5c023a6fecaeb6ec905c99fc0f0a305c52e2f977cf04127c2a09d71` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-31 04:01:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cced5437373fd11eb072a31df390a21` |
| SHA-1 | `ec4c81fda2e832e434bc825725776e2d2fb68d31` |
| SHA-256 | `27d5eba8a5c023a6fecaeb6ec905c99fc0f0a305c52e2f977cf04127c2a09d71` |
| SHA3-384 | `c217ab3bc71e260a7de8bc941a89a9617f0c447f128a79ef4cc8a67208706c191a05ca33c5702e1f2689d5af06481624` |
| TLSH | `T143936D2158FB7116D6C3943F939F421AF16635070188C61BBC2E5D6EBF422A0B3BB6E4` |
| TELFHASH | `t1fbf09e45fd384b198de27674ac8c03a184135317612387248f98d9e0cc3e11ab74cd5d` |
| SSDEEP | `1536:93Lm7pkcg/iSt/9g6cnKLKifMzXbTNgticeQb9BQkLCVhTu1EssMZcywT03ImIyC:9UTQt/26cn/hENBLCVtu1EssMZc/T03C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_27d5eba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27d5eba8a5c023a6fecaeb6ec905c99fc0f0a305c52e2f977cf04127c2a09d71"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-31 04:01:55"
  condition:
    hash.sha256(0, filesize) == "27d5eba8a5c023a6fecaeb6ec905c99fc0f0a305c52e2f977cf04127c2a09d71"
}
```

### Sample 6: `7c6fb00ee9f06f43`

| Field | Value |
|---|---|
| SHA-256 | `7c6fb00ee9f06f43dc1ae36c1cfe3b6d69155aa346272a153a43ad626a883302` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-31 04:01:53` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3d14d871f06c0183aa92f899cc6660d` |
| SHA-256 | `7c6fb00ee9f06f43dc1ae36c1cfe3b6d69155aa346272a153a43ad626a883302` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_7c6fb00e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c6fb00ee9f06f43dc1ae36c1cfe3b6d69155aa346272a153a43ad626a883302"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 04:01:53"
  condition:
    hash.sha256(0, filesize) == "7c6fb00ee9f06f43dc1ae36c1cfe3b6d69155aa346272a153a43ad626a883302"
}
```

### Sample 7: `a2e5983090f76e96`

| Field | Value |
|---|---|
| SHA-256 | `a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-31 03:53:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a14c7df10efc2c2b4ac4e5d2963fbe80` |
| SHA-1 | `c60470756d796db7ca88f7c0a5f430950e0861e5` |
| SHA-256 | `a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142` |
| SHA3-384 | `697411f5ce0ec861371ee0639b12006c7ed73c9e493bcb62958211a2481e6f4ab63b6416e60253c5a40f871f9d2dcd15` |
| TLSH | `T148244AC3FC51E9BAF84BE73B88474409B130B66311415A33721F757BAF2A09856B7E86` |
| SSDEEP | `6144:PSSjeORBEXmqBHnghLIdyxr/GEssMOgh5oDA:PSSj9qBHDEssMOgh5oDA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_a2e59830
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-31 03:53:52"
  condition:
    hash.sha256(0, filesize) == "a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142"
}
```

### Sample 8: `eb55e38de8ed4cd7`

| Field | Value |
|---|---|
| SHA-256 | `eb55e38de8ed4cd753ae895d232f9a0d6967eeafc726518e1c33b1b2acb18b82` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-31 03:53:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1b9e3eb79d1ae46b48f0e0a78054229` |
| SHA-1 | `38d741ca47868045f7504a948193d5ac1325ea98` |
| SHA-256 | `eb55e38de8ed4cd753ae895d232f9a0d6967eeafc726518e1c33b1b2acb18b82` |
| SHA3-384 | `c7b0f39fe687b4569cf3e277fd9176eace72f33a12235bc363262354c9679a5c5aac69ed76e01013ae194e0060900663` |
| TLSH | `T1DE44D809AFA20EF7D86BDD3746E9160625CC641722A83B35753CD928FF0A54F4AE3C64` |
| SSDEEP | `3072:X3+tHkHLY6vFKjDr/e6mnWBZeqw+21Tr5FXqu1EssMZc/T03ImIys61X1h5oDT:H9Kjn/Pp/e+G1FXXEssMOgh5oD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_eb55e38d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb55e38de8ed4cd753ae895d232f9a0d6967eeafc726518e1c33b1b2acb18b82"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-31 03:53:51"
  condition:
    hash.sha256(0, filesize) == "eb55e38de8ed4cd753ae895d232f9a0d6967eeafc726518e1c33b1b2acb18b82"
}
```

### Sample 9: `eef5d0dea6356bf0`

| Field | Value |
|---|---|
| SHA-256 | `eef5d0dea6356bf0b05852eca3cefd3fdb87b06ebff7578496a2824f966ca4e8` |
| Family label | `Mirai` |
| File name | `persist.arm7` |
| File type | `elf` |
| First seen | `2026-08-31 03:51:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca95a4d136d0c00c438fa39bd348f71e` |
| SHA-1 | `8e52be39f544f6a00c66b49eb4f4bc90f86a234b` |
| SHA-256 | `eef5d0dea6356bf0b05852eca3cefd3fdb87b06ebff7578496a2824f966ca4e8` |
| SHA3-384 | `1abba6053fcae6d5f4be75b058e866d5a019e6506b48f12eccab31f913683029b065c3009c8b42f769c36b25f689c73e` |
| TLSH | `T1D2F33B56F7418A13C4D2177AB6DF420533239BA4D3EB73069928AFF43F8279A0E67905` |
| TELFHASH | `t16b210f71623781296d61ce98ddeca7b2052d83132286ff33ef2ac4dc1805096ea29c0f` |
| SSDEEP | `3072:1+OKgzqe9lTaQbYE3quWDP5wEG/VYjrJQyXcdM/93Pf4E:1++TraQbYE3qugPzGtYPJQyXqM/9YE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_eef5d0de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eef5d0dea6356bf0b05852eca3cefd3fdb87b06ebff7578496a2824f966ca4e8"
    family = "Mirai"
    file_name = "persist.arm7"
    file_type = "elf"
    first_seen = "2026-08-31 03:51:43"
  condition:
    hash.sha256(0, filesize) == "eef5d0dea6356bf0b05852eca3cefd3fdb87b06ebff7578496a2824f966ca4e8"
}
```

### Sample 10: `d945cf407650717f`

| Field | Value |
|---|---|
| SHA-256 | `d945cf407650717fb6a880b8fda9f5daa623c33a5efb08cbed5ea01c9346131d` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-31 03:49:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c6efa2ccc274daa131984c1d0315c8f` |
| SHA-1 | `db336f74a6403d8486f5ba257295b0479bcb7397` |
| SHA-256 | `d945cf407650717fb6a880b8fda9f5daa623c33a5efb08cbed5ea01c9346131d` |
| SHA3-384 | `869f43c72e917b409664df1765f020cd16c50012b007c5302dc830e2da531c252d5028f74946cf0fc1f22f36a0849390` |
| TLSH | `T19E44D61E6E628F3EF2A9873487B74A25D75862D722D1D640F16CD1102F2025EA46FFE8` |
| TELFHASH | `t10141831c0e7413f0a2295d9d459dff7ad6a330eb7e166c378e11e86aa769a834d10c0c` |
| SSDEEP | `6144:LX/mjW0zJkWq1AC3cn1m36hsW4L2Q+0XXEssMOgh5ouM/:6q1Ls1QHMyEssMOgh5oui` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_d945cf40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d945cf407650717fb6a880b8fda9f5daa623c33a5efb08cbed5ea01c9346131d"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-31 03:49:42"
  condition:
    hash.sha256(0, filesize) == "d945cf407650717fb6a880b8fda9f5daa623c33a5efb08cbed5ea01c9346131d"
}
```

### Sample 11: `5c7357a1261582b7`

| Field | Value |
|---|---|
| SHA-256 | `5c7357a1261582b7a2d796dd7b5d2ff76a9dc0c70995edf91c06433701d20d1e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-31 03:45:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54744f1f983b0f834640d1d411248588` |
| SHA-1 | `6b500e4e3fe0fc6c57d878784effd189def94ed0` |
| SHA-256 | `5c7357a1261582b7a2d796dd7b5d2ff76a9dc0c70995edf91c06433701d20d1e` |
| SHA3-384 | `eb65b5fd4524fd2064d0004cef46dd70f55a85ecb23ded4331b8a4e1581faa7132f922c4504b14341e03840d62f38470` |
| TLSH | `T156C27C966A867C44BDC94A3E4CBD2B1D6DF5C3D1224942AC3D8A3C71DC12FACD618B1A` |
| SSDEEP | `768:A8vCB+25j6es8RC9FYpMSUpi+20qUpi+20YQX:A8l25Jkd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_5c7357a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c7357a1261582b7a2d796dd7b5d2ff76a9dc0c70995edf91c06433701d20d1e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 03:45:50"
  condition:
    hash.sha256(0, filesize) == "5c7357a1261582b7a2d796dd7b5d2ff76a9dc0c70995edf91c06433701d20d1e"
}
```

### Sample 12: `00be60c5d656295d`

| Field | Value |
|---|---|
| SHA-256 | `00be60c5d656295d0f3ab32d1f07967dd9c3294cb64fb57a9dc93c97f5224f59` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-08-31 03:43:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85ab72a0405c876ed70650a7e1d787e4` |
| SHA-1 | `eac83d32e12e88ec31d77f339426f4d785a38351` |
| SHA-256 | `00be60c5d656295d0f3ab32d1f07967dd9c3294cb64fb57a9dc93c97f5224f59` |
| SHA3-384 | `3f81cfa04bd9d756bb5a0a727532ac15d14818aa8f0e0c578f43e58e77bf70f33601b02e7df04855e5ea240e48dc9dc9` |
| TLSH | `T1A3F36BC57DE3E0B1E963497A466F931A5A32D0370219DA41FB2E69387F02050E7BB79C` |
| TELFHASH | `t18c6119f96e7e0de8b7409c05e28e1f216a0e677b146033b644b3982522bfd4141bbc39` |
| SSDEEP | `3072:e51PUFXU+0CNzuVgFSvi84QZjgT0lRLTqoG0u1EssMZc/T03ImIys61X1h5oF:WGFXUvCNzui9Ql12oGdEssMOgh5oF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_00be60c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00be60c5d656295d0f3ab32d1f07967dd9c3294cb64fb57a9dc93c97f5224f59"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-31 03:43:42"
  condition:
    hash.sha256(0, filesize) == "00be60c5d656295d0f3ab32d1f07967dd9c3294cb64fb57a9dc93c97f5224f59"
}
```

### Sample 13: `e46d5e3237a7b339`

| Field | Value |
|---|---|
| SHA-256 | `e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0` |
| Family label | `unknown` |
| File name | `e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0.raw` |
| File type | `zip` |
| First seen | `2026-08-31 03:42:42` |
| Reporter | `ApiValex73693` |
| Tags | `cowrie, dionaea, honeypot, signed, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b68a1627a100bbfa82dc1fa53cda9874` |
| SHA-1 | `7773122eaba614465e4581de8867b8de36e4d751` |
| SHA-256 | `e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0` |
| SHA3-384 | `70056dbd03a6cba1674f722f7f6ab3ee0de644f66c1d5c79a007054b0c63b7da4c7606cd05728af51c42aacbd320627e` |
| TLSH | `T1E5A423A77A5C226BF37F973215DFDB39058D8D9B8A005A1F14A2CA29E9C713A0331DC5` |
| SSDEEP | `6144:xI7NTOZ2/iqKpbsLG8YiPk+BeHsvdrvkRGOohjmjR4Rs6rnAbDpAwL7yKMZmIT:xUNLKpkG8dPkrIb4VjRwDA1TM4IT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_e46d5e32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0"
    family = "unknown"
    file_name = "e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0.raw"
    file_type = "zip"
    first_seen = "2026-08-31 03:42:42"
  condition:
    hash.sha256(0, filesize) == "e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0"
}
```

### Sample 14: `f8208c93d9bfc718`

| Field | Value |
|---|---|
| SHA-256 | `f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf` |
| Family label | `Mirai` |
| File name | `f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf.elf` |
| File type | `elf` |
| First seen | `2026-08-31 03:36:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05842ca991996f14346babf39f4c5c3b` |
| SHA-1 | `c17440c4c4f1f913f8f56d214926b38699715fe7` |
| SHA-256 | `f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf` |
| SHA3-384 | `d5f0029003fba8c503831f0a13c84d658b883bd2cc2a834183b1341b8bc116d3e068374a5ccff2c90dde1e4b842f56ea` |
| TLSH | `T16B142991BCA29622C6C3467BFB4E428D371A535AD3DE7102FD1D6F603F8A42B4A77481` |
| TELFHASH | `t1a0d0a74fcd3427e973cd8193208eb1042bd8f7462b07282726dd3fd96aa3e26f009014` |
| SSDEEP | `6144:Plkn0jo+df/Eq0BSmF48S4QssGUpuCGjEssMOgh5ov:tI0jo+df/Eq0TF4vVf4EssMOgh5ov` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_f8208c93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf"
    family = "Mirai"
    file_name = "f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf.elf"
    file_type = "elf"
    first_seen = "2026-08-31 03:36:44"
  condition:
    hash.sha256(0, filesize) == "f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf"
}
```

### Sample 15: `511fe46150f3e39b`

| Field | Value |
|---|---|
| SHA-256 | `511fe46150f3e39ba1bcb08cfc09d27da85f61805e08a17e84f356c4a107a903` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-31 03:35:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d01463375f7fdaccba2fd934eed81e7d` |
| SHA-1 | `68e0a8d5ee83dc05e1a7027861e290e72b531989` |
| SHA-256 | `511fe46150f3e39ba1bcb08cfc09d27da85f61805e08a17e84f356c4a107a903` |
| SHA3-384 | `5b48d81932f34b8a94152dbaa5859ee7c42818db3f50be4142cc107e973ea4bbf713b18800eb4feba91ec736d4b52e62` |
| TLSH | `T146144A02776D0403D3632DB43B3B27D1939FE49321A4F644790FAA995FB2931A296DCE` |
| SSDEEP | `6144:z0ShpQN1Z0xTnCgIGvQozNqzEssMOgh5owA:sv+7QVEssMOgh5owA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_511fe461
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "511fe46150f3e39ba1bcb08cfc09d27da85f61805e08a17e84f356c4a107a903"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-31 03:35:50"
  condition:
    hash.sha256(0, filesize) == "511fe46150f3e39ba1bcb08cfc09d27da85f61805e08a17e84f356c4a107a903"
}
```

### Sample 16: `e2982ce93a162c03`

| Field | Value |
|---|---|
| SHA-256 | `e2982ce93a162c03f9e826b13cb98a4b62410d931dd0312881d8f5579da7c8f9` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-31 03:27:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `431d59f641bd3728ec09f871917be51a` |
| SHA-1 | `9d293b6b5259afa7a3f8373bb7514d9d611530de` |
| SHA-256 | `e2982ce93a162c03f9e826b13cb98a4b62410d931dd0312881d8f5579da7c8f9` |
| SHA3-384 | `9a8f92335c9d8e12b6d38d491bacdd111f87f3afac07a6ee0a6290bede03ac58f2fd212b627c36387544f8d38d0cd012` |
| TLSH | `T19DC27C95AA867C44BEC94A3E4CBD2B1D6DF5C3D1224D42AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:X8vCB+25j6es8Rc9FYpMSUpi+20qUpi+20YQX:X8l25Jqd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_e2982ce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2982ce93a162c03f9e826b13cb98a4b62410d931dd0312881d8f5579da7c8f9"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 03:27:49"
  condition:
    hash.sha256(0, filesize) == "e2982ce93a162c03f9e826b13cb98a4b62410d931dd0312881d8f5579da7c8f9"
}
```

### Sample 17: `985a0ccc6ee392a1`

| Field | Value |
|---|---|
| SHA-256 | `985a0ccc6ee392a1ec2cbe1f00d4f467636a80ce9e6bc1f9343efdcee2150b66` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-31 03:21:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `498d7d2c581d6a7b1be2650495cd4d02` |
| SHA-1 | `e90cedac15198b2f92af6e995faca5aefa9c00fd` |
| SHA-256 | `985a0ccc6ee392a1ec2cbe1f00d4f467636a80ce9e6bc1f9343efdcee2150b66` |
| SHA3-384 | `1869a8d96a221dbbe9605261a781c4f4cd308fd54f9a9e22db399006bbe84a6e7f6ac6f3cf52e09949f4d39026072e74` |
| TLSH | `T1CF047CA3CCB37D10D6669836B2268A3D1B13E013424B6E64B86FD2741F43D9DF2A57B4` |
| SSDEEP | `3072:dq/3paidOnEfkMI+NGOvwtNCxgWaxlssM/3Au1EssMZc/T03ImIys61X1h5oe:I/3psvMfNGOKYpSBM/3hEssMOgh5oe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_985a0ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "985a0ccc6ee392a1ec2cbe1f00d4f467636a80ce9e6bc1f9343efdcee2150b66"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-31 03:21:47"
  condition:
    hash.sha256(0, filesize) == "985a0ccc6ee392a1ec2cbe1f00d4f467636a80ce9e6bc1f9343efdcee2150b66"
}
```

### Sample 18: `844553c171f4a953`

| Field | Value |
|---|---|
| SHA-256 | `844553c171f4a953bed4ce34c94bc373b5a41a0dfbec71e137534c827573f34b` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-31 03:19:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13a381d1276aa9bb0241daa915a40d1d` |
| SHA-1 | `4151eeaac2d702bc8a1ce6813f3b40e071f9d7c1` |
| SHA-256 | `844553c171f4a953bed4ce34c94bc373b5a41a0dfbec71e137534c827573f34b` |
| SHA3-384 | `5bcfd2d5e58ebe7dc88ba2257fde05d57b3b2ff3d3507d167f37154f25d5440d2f6d197c2a9e5c2532f7ba058b122737` |
| TLSH | `T1B9240752BCD29B11C6C2467EFB0E514E3313676AD2CE7212FD2C6B703F8A46B0A7A455` |
| SSDEEP | `6144:M7RmFU+caUs3Vfy+xWDXjMZwaoIu6lNuyCj9EssMOgh5oW:cmq+caUAVfy+x8Xj4wa5LlNOEssMOghF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_844553c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "844553c171f4a953bed4ce34c94bc373b5a41a0dfbec71e137534c827573f34b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-31 03:19:57"
  condition:
    hash.sha256(0, filesize) == "844553c171f4a953bed4ce34c94bc373b5a41a0dfbec71e137534c827573f34b"
}
```

### Sample 19: `3213024808835892`

| Field | Value |
|---|---|
| SHA-256 | `321302480883589241e6a4df24e3df3455a769c1f032a51ea1ff59a3cba858c1` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-31 03:03:14` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5b0c076a0a845cbe275ae628c715d27` |
| SHA-256 | `321302480883589241e6a4df24e3df3455a769c1f032a51ea1ff59a3cba858c1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_32130248
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "321302480883589241e6a4df24e3df3455a769c1f032a51ea1ff59a3cba858c1"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 03:03:14"
  condition:
    hash.sha256(0, filesize) == "321302480883589241e6a4df24e3df3455a769c1f032a51ea1ff59a3cba858c1"
}
```

### Sample 20: `5c81b3827e80082d`

| Field | Value |
|---|---|
| SHA-256 | `5c81b3827e80082d7fbbd9e82831a0ae31eb2ee4b97cb1b6730a95e6aa68c122` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-31 03:00:54` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48b5e5f5b844070510a1840fdc9a8dcd` |
| SHA-1 | `efd746255483a8fb56892e8d3bfcff8fabf3c954` |
| SHA-256 | `5c81b3827e80082d7fbbd9e82831a0ae31eb2ee4b97cb1b6730a95e6aa68c122` |
| SHA3-384 | `4b3679ca8561729b1108897d1b961b1c998e1e81e4fdc7eb90631d4b1540662cf3930d50b35ae141c73e6ea18f551e3a` |
| TLSH | `T14A317EDE11106E311013CEAEF7B6395C628EA1FB2C9FC7D499094EA942886DCF162F5D` |
| SSDEEP | `24:+kshgtOH6xzvCXjl+ao83VCmzU8zU8pHmM5aGJj:+ksyO6BvCJ+zEHmK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_5c81b382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c81b3827e80082d7fbbd9e82831a0ae31eb2ee4b97cb1b6730a95e6aa68c122"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-31 03:00:54"
  condition:
    hash.sha256(0, filesize) == "5c81b3827e80082d7fbbd9e82831a0ae31eb2ee4b97cb1b6730a95e6aa68c122"
}
```

### Sample 21: `85dbd88525d79406`

| Field | Value |
|---|---|
| SHA-256 | `85dbd88525d794060217730b5f22475de4b2eb18d45642bed42104945166a00e` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-31 02:54:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90e91e6a220ab386dd2634e1fadb35dd` |
| SHA-1 | `441d908ab30681f51f985d22dca18c4be0a7bbce` |
| SHA-256 | `85dbd88525d794060217730b5f22475de4b2eb18d45642bed42104945166a00e` |
| SHA3-384 | `d6025e0fc1ae7e0e6b3804d6d3c5022074cef8cea1281f11b219c71eb8886b47090cbfd99ac93494fab84e1df000e02c` |
| TLSH | `T13C236C6516857C15AA99C4371C7E2F0CBDAD43E6320452DE7FCE3CF28C4AA9DA20971D` |
| SSDEEP | `768:mcsr0a1ldC9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:4hHcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_85dbd885
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85dbd88525d794060217730b5f22475de4b2eb18d45642bed42104945166a00e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 02:54:49"
  condition:
    hash.sha256(0, filesize) == "85dbd88525d794060217730b5f22475de4b2eb18d45642bed42104945166a00e"
}
```

### Sample 22: `59e4426161024da7`

| Field | Value |
|---|---|
| SHA-256 | `59e4426161024da7af4b9755f2bf861bb8850b4469e9f00c8f7c15f4f18e9eb7` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-31 02:50:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `772ebd7fe19890c6599ea3bdebb4be4a` |
| SHA-1 | `6b964359f085dcf20259a4f612eda07d6eeeb78e` |
| SHA-256 | `59e4426161024da7af4b9755f2bf861bb8850b4469e9f00c8f7c15f4f18e9eb7` |
| SHA3-384 | `a4cb983ac27c1964ba6915fc5709a53035ac0876dcd1effdd210a3b2df19b1f50de8ef4df4dcf40ddd6b141a9d646db0` |
| TLSH | `T1F7A318A17CF3A156C7C3963AFB4F92093312A29783CD7512FD0D5A642FCA11B86B7981` |
| TELFHASH | `t1fbf09e45fd384b198de27674ac8c03a184135317612387248f98d9e0cc3e11ab74cd5d` |
| SSDEEP | `3072:ldsrxLN2KP7ZyU4m8iau2Vr5FvOu1EssMZc/T03ImIys61X1h5o:ldgxLN2KP7Zy5m8B1VXvTEssMOgh5o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_59e44261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e4426161024da7af4b9755f2bf861bb8850b4469e9f00c8f7c15f4f18e9eb7"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-31 02:50:59"
  condition:
    hash.sha256(0, filesize) == "59e4426161024da7af4b9755f2bf861bb8850b4469e9f00c8f7c15f4f18e9eb7"
}
```

### Sample 23: `41792492f0115944`

| Field | Value |
|---|---|
| SHA-256 | `41792492f011594491d180b1bfbed002f07a60e9697558b1a13e00176f9f4611` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-31 02:44:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a75c97843e40473d55798faa5555779` |
| SHA-1 | `977dbdeb51a1805eeba13fd2c96c5b55be7435b2` |
| SHA-256 | `41792492f011594491d180b1bfbed002f07a60e9697558b1a13e00176f9f4611` |
| SHA3-384 | `b73e5f22253bfbb7f8a59cf7ce981426f376548440d038e14b15b1926af1810f4a233e36f754991e9892771fc5f745c7` |
| TLSH | `T199343B52AAD24A13C5D31B7AF79F41063323A66693DB7302F91CAFB43F8625E4E63501` |
| TELFHASH | `t1f731fd3107315512aeb1da589ce953b3152e82266285ef33de25c4dc940a0abe637c4f` |
| SSDEEP | `6144:bxBQFEqUi9tk3jMm6yw/UaugPZiFGYmvRCziEssMOgh5o5MnmEM/9TO:7QFEqUi9tk3jMmRw/UaugPZirivEssMX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_41792492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41792492f011594491d180b1bfbed002f07a60e9697558b1a13e00176f9f4611"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-31 02:44:57"
  condition:
    hash.sha256(0, filesize) == "41792492f011594491d180b1bfbed002f07a60e9697558b1a13e00176f9f4611"
}
```

### Sample 24: `76520a25a234a651`

| Field | Value |
|---|---|
| SHA-256 | `76520a25a234a651c1f60c4ed7e0c2840e41e50604f7ceb80fed3079a003e97b` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-31 02:38:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32dd75cd2b5281fd311359b99b7fa386` |
| SHA-1 | `5560ceab3836a96b0571cbfc0a88142fa86ac38f` |
| SHA-256 | `76520a25a234a651c1f60c4ed7e0c2840e41e50604f7ceb80fed3079a003e97b` |
| SHA3-384 | `6513f5343b4ebb4ca8c847a50546077707e7c89f1c20ea206ed80b39bf8205a13b1b197033c3b0371bae9454d093475d` |
| TLSH | `T1FEE36BC179E3E0F1E6A34579426F431A8A36E4370229DA11F72E68797F02450E7BB79C` |
| TELFHASH | `t1785115f97abf0ce9a7549844530d1f22790debbb14a072f045f3a83532a7e8141b6c39` |
| SSDEEP | `3072:9tvVF4XiW2yAiZUQTnmnGtALNuqOzEeghfO09y6u1EssMZc/T03ImIys61X1h5oC:jH4yW2yAKUQ74ZgFgxl9ynEssMOgh5o4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_76520a25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76520a25a234a651c1f60c4ed7e0c2840e41e50604f7ceb80fed3079a003e97b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-31 02:38:49"
  condition:
    hash.sha256(0, filesize) == "76520a25a234a651c1f60c4ed7e0c2840e41e50604f7ceb80fed3079a003e97b"
}
```

### Sample 25: `011622e016f8dd26`

| Field | Value |
|---|---|
| SHA-256 | `011622e016f8dd26ea72849f3181882cc1bab3d72cc43e847936703fcd436bba` |
| Family label | `RemcosRAT` |
| File name | `Maxima_International_Sourcing.bat` |
| File type | `bat` |
| First seen | `2026-08-31 02:31:30` |
| Reporter | `nat` |
| Tags | `bat, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `367068e6c5501d4b8cf5abeb4c642876` |
| SHA-1 | `3ec658f8ad59cb4f56e9b9bb58f5397d2efd5f83` |
| SHA-256 | `011622e016f8dd26ea72849f3181882cc1bab3d72cc43e847936703fcd436bba` |
| SHA3-384 | `b4b23d241d8b31f38d0e1aee828989f25397eaed3576ed932f20034745ae65fab75284c45223136801b52bf3290f786b` |
| TLSH | `T1973523205C9818E902AFC21671798F6A67BEAFCACB48D2FD320E71D56C4D707ED59920` |
| SSDEEP | `24576:KgirHWMwCwDw3IbMXpymP8itMqxNvEcEVhGJyztnQPPL:SDEvbMZTZFxSC3L` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_025_011622e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011622e016f8dd26ea72849f3181882cc1bab3d72cc43e847936703fcd436bba"
    family = "RemcosRAT"
    file_name = "Maxima_International_Sourcing.bat"
    file_type = "bat"
    first_seen = "2026-08-31 02:31:30"
  condition:
    hash.sha256(0, filesize) == "011622e016f8dd26ea72849f3181882cc1bab3d72cc43e847936703fcd436bba"
}
```

### Sample 26: `319810073cff23bf`

| Field | Value |
|---|---|
| SHA-256 | `319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51` |
| Family label | `Prometei` |
| File name | `319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51` |
| File type | `elf` |
| First seen | `2026-08-31 01:40:33` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `518dc27c7177c1c2f15537c3886f94da` |
| SHA-1 | `ce0801fe70397a7b93f55407f6ddf5bfd7813528` |
| SHA-256 | `319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51` |
| SHA3-384 | `cdaf86291efd01fc53d19e987de9a66235bc526d48c8b27985c4dda3e7746e60fdea1c648e379ebd48a803b023fade92` |
| TLSH | `T1179423F8C83D2E30D8169B3CBB5A826CF0A15772D9562F6AB51AF5732179F1FAC60101` |
| SSDEEP | `6144:ZcfxS1fHETSACF2Gzm5DVvSHrKKRH4SCra+HWMiFbcAOXmw4Dsi6wwcitgI:a5WOSACZSV6eKRH5EPiamw4DsDwwcY` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_026_31981007
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51"
    family = "Prometei"
    file_name = "319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51"
    file_type = "elf"
    first_seen = "2026-08-31 01:40:33"
  condition:
    hash.sha256(0, filesize) == "319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51"
}
```

### Sample 27: `4d28296e8ff7f961`

| Field | Value |
|---|---|
| SHA-256 | `4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7` |
| Family label | `Prometei` |
| File name | `4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7` |
| File type | `exe` |
| First seen | `2026-08-31 01:39:38` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `211394f81556f64e9823cbd2a5fc1969` |
| SHA-1 | `7303ac5250721efe1d4de6118f467d04001a2be8` |
| SHA-256 | `4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7` |
| SHA3-384 | `4c2800ae2853c67fbcb68742f204ee9fa741f44c627997ca3a392ecb3324eaf2c2ab23517de303d6266d2027968756aa` |
| IMPHASH | `551920a564f0da077e7c568c1940defb` |
| TLSH | `T1B674CF3331B8F25EC84517728F62C7C263A97F55C992805F3EB4630F2A278595A36B36` |
| SSDEEP | `6144:axFm8jr8dmxZc+92bOiRRFsuNfgKk5H4RlANeKmFDhkMt:axY8H8dmxWWBivFBNGH4cNQR1t` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_027_4d28296e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7"
    family = "Prometei"
    file_name = "4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7"
    file_type = "exe"
    first_seen = "2026-08-31 01:39:38"
  condition:
    hash.sha256(0, filesize) == "4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7"
}
```

### Sample 28: `1b19bd93bc95ba90`

| Field | Value |
|---|---|
| SHA-256 | `1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd` |
| Family label | `unknown` |
| File name | `1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd.bin` |
| File type | `exe` |
| First seen | `2026-08-31 01:12:40` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee76666614adaeff2af23ff32f4091a5` |
| SHA-1 | `b120f30af14a37733bc8b0af292b496092d5f693` |
| SHA-256 | `1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd` |
| SHA3-384 | `f384ead3951c3575ea7b2dbdc0177e9437bb3e5ec37adce94c3e7fa303a161a312ceb0ca8db449d1e7b9bdfd5b53a1cb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C1568D077B8184B0D056EA7A84B6429477B07C5C833533AB2EA6F9303F663D1B67AF54` |
| SSDEEP | `49152:R5SExxGrhzt5HXIxtSMaoyP4Ena3wSh+2lRLJH1QCD+iX6KUqj9gx5fBlVgwu9wu:RvukxtclW5hrfCUjkQqEPF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_1b19bd93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd"
    family = "unknown"
    file_name = "1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd.bin"
    file_type = "exe"
    first_seen = "2026-08-31 01:12:40"
  condition:
    hash.sha256(0, filesize) == "1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd"
}
```

### Sample 29: `9fe7400eb8323751`

| Field | Value |
|---|---|
| SHA-256 | `9fe7400eb83237517f23e172d4e708b6744bf4b68ab1d1f0d21473581575a96c` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-31 00:58:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6a474d61dd07a39ffeb21692db714ef` |
| SHA-1 | `6a42846cc6e75eddbeebcf004046c2dd24e5dbce` |
| SHA-256 | `9fe7400eb83237517f23e172d4e708b6744bf4b68ab1d1f0d21473581575a96c` |
| SHA3-384 | `959e267ccd99cab5904dc19e0d3870f58e4ad741a2637c61a25f8412b0b02e2e73121f79b7faa75f6c278818e1e6e99c` |
| TLSH | `T152A319917CE3A156C6D3863EFB4F920933226297C3CD7522FD1D5A642F8A11B87B69C0` |
| TELFHASH | `t1b0f0c041fd388a144ae27a70ec6803a585134613612287248f58c9d0cc3e00ab248d1d` |
| SSDEEP | `3072:OFopxYuwLRefb+lKfzcDppoB5u1EssMZc/T03ImIys61X1h5o:OAxYuwLRefb+lKLqkBiEssMOgh5o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_9fe7400e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fe7400eb83237517f23e172d4e708b6744bf4b68ab1d1f0d21473581575a96c"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-31 00:58:57"
  condition:
    hash.sha256(0, filesize) == "9fe7400eb83237517f23e172d4e708b6744bf4b68ab1d1f0d21473581575a96c"
}
```

### Sample 30: `6c34734992fedeae`

| Field | Value |
|---|---|
| SHA-256 | `6c34734992fedeae18ca6796175a7d5e366db61b096afb2a40a51a500ac3e39f` |
| Family label | `ValleyRAT` |
| File name | `52C6A290E9CE70AC61B7F924CA5775AF.dll` |
| File type | `dll` |
| First seen | `2026-08-31 00:55:08` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c6a290e9ce70ac61b7f924ca5775af` |
| SHA-1 | `a8f7a063831d894b0b856ac2b4f0af92ff29a849` |
| SHA-256 | `6c34734992fedeae18ca6796175a7d5e366db61b096afb2a40a51a500ac3e39f` |
| SHA3-384 | `2d27295240ee32f116286e5addd41dd5d691b1982bce1d7a83bcc6f16cf870fc06a5d82ccde0e9c81322c806f187c6b8` |
| IMPHASH | `d5822bbb610a74c0ffb83554d889e5a4` |
| TLSH | `T191868D1377D0D8AAE2668374C581E6BD862D5D200FD882C376CF3E3739738916E646E6` |
| SSDEEP | `98304:zD+JUmYkINt0mvSVyX6LiJMQ40sCJjMl084eOMBBuBBI0/z0XqhS3tvpF80sEE:3+82iJMQ4sM14eOMPkBI2aqhctn` |
| ICON-DHASH | `8660a2b2b5d861a4` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_030_6c347349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c34734992fedeae18ca6796175a7d5e366db61b096afb2a40a51a500ac3e39f"
    family = "ValleyRAT"
    file_name = "52C6A290E9CE70AC61B7F924CA5775AF.dll"
    file_type = "dll"
    first_seen = "2026-08-31 00:55:08"
  condition:
    hash.sha256(0, filesize) == "6c34734992fedeae18ca6796175a7d5e366db61b096afb2a40a51a500ac3e39f"
}
```

### Sample 31: `ec2bc48545806557`

| Field | Value |
|---|---|
| SHA-256 | `ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa` |
| Family label | `unknown` |
| File name | `ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa.bin` |
| File type | `exe` |
| First seen | `2026-08-31 00:41:00` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36bf44cb244bc6d950a021c9a225d7b5` |
| SHA-1 | `f09c0e213099b8f58130d4a86ea586ee765c2181` |
| SHA-256 | `ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa` |
| SHA3-384 | `1746c73e52df678ec4e772f3ae681aef87224b21ad052f8702ebfa0916f5e5e9cc9acedbc7e79b295d2ddf2bc3d776b8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T137665B07AE5441A5C96BA73CC6BB0225A6B8BC4CEF753ADB1E8174307FB67D06976300` |
| SSDEEP | `98304:gtJndFRPOCbDjyoG0qzKaW2wsTRukz3x0N:gtlYCPjyoG6aXTEke` |
| ICON-DHASH | `4c126ce4d4680200` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_ec2bc485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa"
    family = "unknown"
    file_name = "ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa.bin"
    file_type = "exe"
    first_seen = "2026-08-31 00:41:00"
  condition:
    hash.sha256(0, filesize) == "ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa"
}
```

### Sample 32: `d7934bfa4e1d52ff`

| Field | Value |
|---|---|
| SHA-256 | `d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336` |
| Family label | `unknown` |
| File name | `d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336.bin` |
| File type | `exe` |
| First seen | `2026-08-31 00:19:53` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd2654e2244bcf9a6a2252a13755a3ee` |
| SHA-1 | `22827a2d38727640bef9a5bb4147984d7f8c081b` |
| SHA-256 | `d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336` |
| SHA3-384 | `8251116a1c4f138bd6165120bd5e31865aac8b293ab1a8fec018128a2ba1c235382831f82bc2899aa8a7ce478e5e59db` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T137366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaa+:uc3XND1aJrCOk+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_d7934bfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336"
    family = "unknown"
    file_name = "d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336.bin"
    file_type = "exe"
    first_seen = "2026-08-31 00:19:53"
  condition:
    hash.sha256(0, filesize) == "d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336"
}
```

### Sample 33: `8724ae953b9d69c4`

| Field | Value |
|---|---|
| SHA-256 | `8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac` |
| Family label | `unknown` |
| File name | `8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac.bin` |
| File type | `exe` |
| First seen | `2026-08-31 00:19:50` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96ff67bb540557c2b26c0f24e090de16` |
| SHA-1 | `329d1ecc0b6198a346030eb0f3a060f3e0bd3204` |
| SHA-256 | `8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac` |
| SHA3-384 | `728736dcf7a0ce899085687bc291d40b6dd58e94e80f43010deff89fdf2cd7f1dfbd8894a7bfa584428f267ab867eb97` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B3366A03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaP:uc3XND1aJrCOkP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_8724ae95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac"
    family = "unknown"
    file_name = "8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac.bin"
    file_type = "exe"
    first_seen = "2026-08-31 00:19:50"
  condition:
    hash.sha256(0, filesize) == "8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac"
}
```

### Sample 34: `9109d9bd117f540a`

| Field | Value |
|---|---|
| SHA-256 | `9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d` |
| Family label | `AsyncRAT` |
| File name | `132.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:43:01` |
| Reporter | `BlinkzSec` |
| Tags | `AsyncRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c97653e9ca2411da555ff27871e6f06f` |
| SHA-1 | `70eea44815946dec239d4a4f374107f6bc72b7fa` |
| SHA-256 | `9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d` |
| SHA3-384 | `1dbbb1b78868d50fecd209de2d0e680806c8d1398892c72b9258bdfa773402dda4baddbad8498e25a82ec041c5ddd74f` |
| IMPHASH | `8ce498296c9b800696487944f8873d0c` |
| TLSH | `T1BA04D00AE107DC51DD3A52B350DAC57A6590B918C731AF0FA609C624730BE32BB76B7E` |
| SSDEEP | `1536:uFML87TRk+XhtIrQtkaofCCB8BkVbvKmYGkEohAwWtBUySJ6zWtjI6/YHv:2kehtKQZWCBBkV+mYGdK8z40fP` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_034_9109d9bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d"
    family = "AsyncRAT"
    file_name = "132.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:43:01"
  condition:
    hash.sha256(0, filesize) == "9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d"
}
```

### Sample 35: `bf8c5ad334c9b4a8`

| Field | Value |
|---|---|
| SHA-256 | `bf8c5ad334c9b4a8dfb7eab8e33e4869e275ababc2f042efa74fe4514ba9eb26` |
| Family label | `unknown` |
| File name | `13.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:43:01` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3b1bff7013b59d643e9deeb474fa8b6` |
| SHA-1 | `8cf9eed03fca846c31543474c84df32c82399cbf` |
| SHA-256 | `bf8c5ad334c9b4a8dfb7eab8e33e4869e275ababc2f042efa74fe4514ba9eb26` |
| SHA3-384 | `65f9132ba49f9e8c9e83139f15ac2423dbcd45fbe997f459bd777ad4f573173516ed71af858aed0fb26647eda84d59d3` |
| IMPHASH | `56dfb8ceed6bebea3ee9cc31c63b4773` |
| TLSH | `T16B057D07B69195BCD15AC07883569673FB33B88B0630B9BF13E09B303E56EA5AB1C715` |
| SSDEEP | `12288:IMeeAHMaIrG1W+1BK1KRa7XAwc/LdyiJjGGx7gYVXR3sdULOjHxX:leRHMaR110xQwcByyR7ggepX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_bf8c5ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf8c5ad334c9b4a8dfb7eab8e33e4869e275ababc2f042efa74fe4514ba9eb26"
    family = "unknown"
    file_name = "13.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:43:01"
  condition:
    hash.sha256(0, filesize) == "bf8c5ad334c9b4a8dfb7eab8e33e4869e275ababc2f042efa74fe4514ba9eb26"
}
```

### Sample 36: `f6f7dbd6561e7ee6`

| Field | Value |
|---|---|
| SHA-256 | `f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f` |
| Family label | `AsyncRAT` |
| File name | `cs2.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:43:01` |
| Reporter | `BlinkzSec` |
| Tags | `AsyncRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a654205ddda5187ea3bf4b03074e4d2` |
| SHA-1 | `172a7bfb9eedb8b7c18ea7186309f013944caa75` |
| SHA-256 | `f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f` |
| SHA3-384 | `2a8ac7610469b88608568ca5666ff19042765add36626a8e714d5f181766c5cbe8dccc1b1e7294f78cf0cfd2282e6496` |
| IMPHASH | `2ed2f81f89a1bf1f161dc30df28cef9a` |
| TLSH | `T1CDB3F107F30A0652DD2AA272D089C4F3F770CFC912215D7D992B99242667B926B3A35F` |
| SSDEEP | `1536:078EQgoMNcjwGzlAbBbqfSpApMjY9WgWWlfSqyTX56+UzAP3vaqtVY7PJhMpPcv:cQT3lAbBbRpA+TgWqd69Uz8vTtViJh06` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_036_f6f7dbd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f"
    family = "AsyncRAT"
    file_name = "cs2.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:43:01"
  condition:
    hash.sha256(0, filesize) == "f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f"
}
```

### Sample 37: `76de6f8ba8cd0a78`

| Field | Value |
|---|---|
| SHA-256 | `76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd` |
| Family label | `unknown` |
| File name | `76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd.bin` |
| File type | `exe` |
| First seen | `2026-08-30 23:40:46` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0a691a2c38a39ac592e23be54bc33b2` |
| SHA-1 | `fd96fe13f35d02172f95757a6a26e6358e45ce40` |
| SHA-256 | `76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd` |
| SHA3-384 | `c0f9cc2cae63a3e2bbd66e9788c20d43a712d174de657191739d0f45a7819c760d45981b58fabef82e25e53975c9abbc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T104D67D07AA6002F4C896DB70C5BB52536A79B88CDB3273A36D1036746F7A7D0B9F9704` |
| SSDEEP | `98304:JJqVMz+4u2W0U5M8VOufrUqw8goATn200UDkZIAM:JJq70cMMjVmxB0k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_76de6f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd"
    family = "unknown"
    file_name = "76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd.bin"
    file_type = "exe"
    first_seen = "2026-08-30 23:40:46"
  condition:
    hash.sha256(0, filesize) == "76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd"
}
```

### Sample 38: `648e823a9408a715`

| Field | Value |
|---|---|
| SHA-256 | `648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa` |
| Family label | `Vidar` |
| File name | `648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa.bin` |
| File type | `exe` |
| First seen | `2026-08-30 23:40:43` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7a14b56edbc65dd1a1a5502c471dfb0` |
| SHA-1 | `84e0e1bdcdd81f7967ec6465990a7403985bb358` |
| SHA-256 | `648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa` |
| SHA3-384 | `cd10777c72a9f2d32d5d92a1ba5a81bdad78842ef342cf999569d8087d15dcc920b870cfbfef3d705b501e0a320cd808` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T197568D037F8181B0C056EA7A84F642617B787C1D833433AB6EA6A9703F663D1B675F64` |
| SSDEEP | `49152:w5tX7HzAKsVqkTeqNjWIreE6tzctMYi7vzPDd5OF5V7QVBtNffqVgGNGeflWsuwC:w/naldreIuY47d6T7QVNf1GFN39C` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_038_648e823a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa"
    family = "Vidar"
    file_name = "648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa.bin"
    file_type = "exe"
    first_seen = "2026-08-30 23:40:43"
  condition:
    hash.sha256(0, filesize) == "648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa"
}
```

### Sample 39: `aebe2aad890a1ac7`

| Field | Value |
|---|---|
| SHA-256 | `aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245` |
| Family label | `unknown` |
| File name | `aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245.bin` |
| File type | `exe` |
| First seen | `2026-08-30 23:40:41` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33b4136748d3840ffa86b44a7234a218` |
| SHA-1 | `8b79419c57ec5dbe52e79b822bdc041e283e95b9` |
| SHA-256 | `aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245` |
| SHA3-384 | `c7610e8c71f19b91d9b08902051dfc7f9f2f24f3fdc6363c310a4dc3b19385b6dc08d784a813bf4f7c89f0ab9a32d528` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T132366C07B5C45660C49AC639E2BD2722A770B88CCB3373E75E58ABB11E253D49F35788` |
| GIMPHASH | `3d9dc1e8ed6d43bcb262346513de26a24dbefbb99f9f7b2e92946bbad5666673` |
| SSDEEP | `98304:rVloT7SROyLnCDjaZFBvYjfI604fFjW5ESl7VViUTdz:rVlV8fI6Jjmjp5Tx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_aebe2aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245"
    family = "unknown"
    file_name = "aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245.bin"
    file_type = "exe"
    first_seen = "2026-08-30 23:40:41"
  condition:
    hash.sha256(0, filesize) == "aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245"
}
```

### Sample 40: `21bfcedfb79ec842`

| Field | Value |
|---|---|
| SHA-256 | `21bfcedfb79ec8427ad3d766b66997983a2910d05164773159263b52a5cd6317` |
| Family label | `unknown` |
| File name | `192.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:36:39` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7419e5d74c16467b624831100693684` |
| SHA-1 | `08824d14c9428e047645c9baa822964d7e8657b9` |
| SHA-256 | `21bfcedfb79ec8427ad3d766b66997983a2910d05164773159263b52a5cd6317` |
| SHA3-384 | `f49777932ecc69d580e07ba2fe04cb354c6ffeaee58ad96dcf79a6a1d7c30093ee8153b4957e3164385f5c698e7325c4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F0563A47EC9659E9C1AAE23489679253BB717C881B3123D32B50F7382F76BD06E79340` |
| SSDEEP | `49152:NiOKtTM3Xg9vcz6Xi6idfnM4ie1DWFRMZyumMkuAUa7GuQftfV4ZvkK/pafKiK96:NkZJdiBbWRomMjAD/RAUuIc6EF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_21bfcedf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21bfcedfb79ec8427ad3d766b66997983a2910d05164773159263b52a5cd6317"
    family = "unknown"
    file_name = "192.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:36:39"
  condition:
    hash.sha256(0, filesize) == "21bfcedfb79ec8427ad3d766b66997983a2910d05164773159263b52a5cd6317"
}
```

### Sample 41: `3610fcc54a204281`

| Field | Value |
|---|---|
| SHA-256 | `3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1` |
| Family label | `AsyncRAT` |
| File name | `118.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:30:37` |
| Reporter | `BlinkzSec` |
| Tags | `AsyncRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7c16c14713811db3f7bfca8cd7786cc` |
| SHA-1 | `3fad3a38e2a91a878558959ab5729c29e376f679` |
| SHA-256 | `3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1` |
| SHA3-384 | `a293506e84c7e2ece12df40dfeb28aea2f28e9fc4a00e86051d57427a2bcd391780d6848a3287f1e22646b842ec7b0ef` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T151942357EF32CE23D6D106721CBB34265EF3A567A6349B4343904A433A6BDC1A22F352` |
| SSDEEP | `12288:DyWZp1VcYJM0/VsmT+MSI5Y0UGvkXAUqYk9nhDXvZ:DyWZpM0CmTZY0jMX6nBhDXvZ` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_041_3610fcc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1"
    family = "AsyncRAT"
    file_name = "118.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:30:37"
  condition:
    hash.sha256(0, filesize) == "3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1"
}
```

### Sample 42: `9b1d38cd728ec1a4`

| Field | Value |
|---|---|
| SHA-256 | `9b1d38cd728ec1a478db668e86f7445ab5f0335b388feefc15502931cdcad704` |
| Family label | `VenomRAT` |
| File name | `103.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:30:36` |
| Reporter | `BlinkzSec` |
| Tags | `VenomRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `677fac716f816e337cf9b661a21c7df5` |
| SHA-1 | `2609219dbb074cfbbfe3265d96adf3e818d817f8` |
| SHA-256 | `9b1d38cd728ec1a478db668e86f7445ab5f0335b388feefc15502931cdcad704` |
| SHA3-384 | `66ffced2479b0fd1b400ca8ad1f7e68b973004a7f253bc7447b398b7c745fbb365eda96d31cceeb2d92c8ea1e9c1bdfc` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T18C942395EF22CE63EBA241B218FA361A9F63E522573CCA4303A04E473956DD1D61F3D1` |
| SSDEEP | `12288:DyWZp3VcYJM0/VsmT+MSI5Y0UGvkiTnfNZXv8:DyWZpS0CmTZY0jMiTf7Xv8` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `VenomRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VenomRAT_042_9b1d38cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1d38cd728ec1a478db668e86f7445ab5f0335b388feefc15502931cdcad704"
    family = "VenomRAT"
    file_name = "103.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:30:36"
  condition:
    hash.sha256(0, filesize) == "9b1d38cd728ec1a478db668e86f7445ab5f0335b388feefc15502931cdcad704"
}
```

### Sample 43: `f959a8494f2a1c4e`

| Field | Value |
|---|---|
| SHA-256 | `f959a8494f2a1c4e11f346ae8e3099593f156be2a5c8010d1747e4466a11316a` |
| Family label | `VenomRAT` |
| File name | `192.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:30:36` |
| Reporter | `BlinkzSec` |
| Tags | `VenomRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0487e6bad31fdd3652040fc52eef9ce6` |
| SHA-1 | `0a3bd5fc27c223f96061df53fad025f3dd4653bb` |
| SHA-256 | `f959a8494f2a1c4e11f346ae8e3099593f156be2a5c8010d1747e4466a11316a` |
| SHA3-384 | `fdd4b098fefdc1136737e2b936528a44786e30d280534309f97da9f5821b1da79812560105a53d8b95b0072632e6ea51` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T1B0942387EF36CD63D6F141B628F6356E1E7A842BA625934353504E023B47EE1D62F3A0` |
| SSDEEP | `12288:DyWZpR0VcYJM0/VsmT+MSI5Y0UGvkigsFBhZKA08Xvd:DyWZph0CmTZY0jMigsdZKP8Xvd` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `VenomRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VenomRAT_043_f959a849
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f959a8494f2a1c4e11f346ae8e3099593f156be2a5c8010d1747e4466a11316a"
    family = "VenomRAT"
    file_name = "192.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:30:36"
  condition:
    hash.sha256(0, filesize) == "f959a8494f2a1c4e11f346ae8e3099593f156be2a5c8010d1747e4466a11316a"
}
```

### Sample 44: `bfd241497d87b72e`

| Field | Value |
|---|---|
| SHA-256 | `bfd241497d87b72e6ca63d3c51f904c66890684cef0e14c11680eb5d0633f260` |
| Family label | `unknown` |
| File name | `s.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:23:44` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3895c7d1ea111540f3ecb490ad1c773` |
| SHA-1 | `ff6b036f7f7d5de285e6e74e30094a4a9d78c70f` |
| SHA-256 | `bfd241497d87b72e6ca63d3c51f904c66890684cef0e14c11680eb5d0633f260` |
| SHA3-384 | `b9ed97483f4c6eb169c5c0273e28f801086553f76e362585ae6721b0322aa48d5a8bd60956408f3c54b6d92c5f278055` |
| IMPHASH | `70841d0777dc2169e0bd4138268fa27c` |
| TLSH | `T1C382F885695634E9EE11853E8221873BFA20F6920B3286EF57D293351E78FD42F3C6C5` |
| SSDEEP | `192:XMLjGqHxpBLpSwSVdzO1ollCq91ktrQ3fZX/MkJdRMhlTET0X3DTZow:cmOx0wSV5O11q91kc3N/MudR0T63` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_bfd24149
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfd241497d87b72e6ca63d3c51f904c66890684cef0e14c11680eb5d0633f260"
    family = "unknown"
    file_name = "s.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:23:44"
  condition:
    hash.sha256(0, filesize) == "bfd241497d87b72e6ca63d3c51f904c66890684cef0e14c11680eb5d0633f260"
}
```

### Sample 45: `1dc1f5d8863e2f4d`

| Field | Value |
|---|---|
| SHA-256 | `1dc1f5d8863e2f4d6105a47e6aa11428668c9c604b3c55247e2bce376bdd5724` |
| Family label | `AdaptixC2` |
| File name | `agent.x64.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:22:39` |
| Reporter | `BlinkzSec` |
| Tags | `AdaptixC2` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f183b0cb31895a54a2b69c24991d8a70` |
| SHA-1 | `99fbd15de0026075188bbe6bee35622a1979496d` |
| SHA-256 | `1dc1f5d8863e2f4d6105a47e6aa11428668c9c604b3c55247e2bce376bdd5724` |
| SHA3-384 | `422db3b854084e0ede58835f985e47715f6f696d5c13dbcc8d8f28004f7f7dd33e24aed9b25bea3d349d57273b226ace` |
| TLSH | `T108F39737D6B3C0ADC06FD534AF839063A8B07C5C8534661A4BC56A527F2BD746FBA284` |
| SSDEEP | `3072:EtCrY75RVzRmOKZjss5igeCkDgwnzDI0EEn:EtCcz0vjss5KCkDgwnzDuEn` |

#### Technical Assessment

- The sample is tracked as `AdaptixC2` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AdaptixC2_045_1dc1f5d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dc1f5d8863e2f4d6105a47e6aa11428668c9c604b3c55247e2bce376bdd5724"
    family = "AdaptixC2"
    file_name = "agent.x64.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:22:39"
  condition:
    hash.sha256(0, filesize) == "1dc1f5d8863e2f4d6105a47e6aa11428668c9c604b3c55247e2bce376bdd5724"
}
```

### Sample 46: `71cdf126636c50a3`

| Field | Value |
|---|---|
| SHA-256 | `71cdf126636c50a3a2b71fa730ddc3f3ab03791a35a70aa774de8652ca96a174` |
| Family label | `RemusStealer` |
| File name | `main.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:20:34` |
| Reporter | `BlinkzSec` |
| Tags | `RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2473849b2a8e46e10627df3acc2591b3` |
| SHA-1 | `1a3893699c93f4bd8e3210f3c64a9de5319d9efe` |
| SHA-256 | `71cdf126636c50a3a2b71fa730ddc3f3ab03791a35a70aa774de8652ca96a174` |
| SHA3-384 | `dfd9bb2049f584b78a15030849c2a294151449d6b0de75233ddc1722c0df5d91b760c0d4525aabcfcf57ca1c227630ed` |
| IMPHASH | `5fd05bfc99e1c75c03df6a36d2365b57` |
| TLSH | `T1BFA47CD65A11FF83C166DFFD4476CA113C76AE5B1A06A20722487A8EC536ACF9337C81` |
| SSDEEP | `6144:cnU8OAGfYdTa1azm+M8O7p83IAsRTQh+YFL5z7Tsaw8sm7EWCcG0DHtcB4O:XymjiIAQKp5zsaom7EWCcG0DHtcB4O` |
| ICON-DHASH | `e8aa69d4d4cc8ee8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_046_71cdf126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71cdf126636c50a3a2b71fa730ddc3f3ab03791a35a70aa774de8652ca96a174"
    family = "RemusStealer"
    file_name = "main.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:20:34"
  condition:
    hash.sha256(0, filesize) == "71cdf126636c50a3a2b71fa730ddc3f3ab03791a35a70aa774de8652ca96a174"
}
```

### Sample 47: `3bc5b2464c55aab2`

| Field | Value |
|---|---|
| SHA-256 | `3bc5b2464c55aab2b5b9d7e6c646130dea5d863f8d6631b5d5fe2f23c6f73b61` |
| Family label | `unknown` |
| File name | `kworker` |
| File type | `elf` |
| First seen | `2026-08-30 23:18:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c14b747a195532d7f570e915c09013b` |
| SHA-1 | `cc659cae04edcd09ccf3c6752d052c31c7bbe416` |
| SHA-256 | `3bc5b2464c55aab2b5b9d7e6c646130dea5d863f8d6631b5d5fe2f23c6f73b61` |
| SHA3-384 | `d1450396d5e8bd8fd89a3ed52faab9221f1bd244afbc8672d556ebcd7659f60325fc220d16cac5fbb60b87025ac3740f` |
| TLSH | `T1ECC62B03E8D61199C4E9D1B489614262FA707C5C0B7923DB3BA1F7B82B327F09E76791` |
| TELFHASH | `t18d629b7549bd34b5b2aada11f3a374b4953318b576f834f01037ad91efd0e802c9a86b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:s/x5i4yMB7WZGflZ7ZuMaQ+Y5+w2d7sawC+9LjCKzAcUbSIyFPXChmpmfzbDM0Qf:SCmdcMUdizALbSGO0q7eEyNy6Y22H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_3bc5b246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bc5b2464c55aab2b5b9d7e6c646130dea5d863f8d6631b5d5fe2f23c6f73b61"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-08-30 23:18:24"
  condition:
    hash.sha256(0, filesize) == "3bc5b2464c55aab2b5b9d7e6c646130dea5d863f8d6631b5d5fe2f23c6f73b61"
}
```

### Sample 48: `d931dd41445159d9`

| Field | Value |
|---|---|
| SHA-256 | `d931dd41445159d939376b4ee6c6023bf49ba6599d9191006fdb8d99c71c410a` |
| Family label | `unknown` |
| File name | `kworker` |
| File type | `elf` |
| First seen | `2026-08-30 23:17:44` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `197530912cfb2036a9099bd7fd2dbe1f` |
| SHA-1 | `84af69c14d8ca62ad2ddfdc2396b903062f49c6a` |
| SHA-256 | `d931dd41445159d939376b4ee6c6023bf49ba6599d9191006fdb8d99c71c410a` |
| SHA3-384 | `643dd894595a0406c8daf549f7ec333d713f6eb905c43c2669e51bdf585ee04890749a80ca7bc97f784581e9eb65ae52` |
| TLSH | `T14C26332047253B37B4CD2B64BF7A2E98D961B21D75A08078BF35E6D9E378FD28512132` |
| SSDEEP | `98304:fjlFLOqcya5sAOnZAPNX8clwqyOAK7AJ7Km:fjvSqcyoOnqPNnhyfNl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_d931dd41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d931dd41445159d939376b4ee6c6023bf49ba6599d9191006fdb8d99c71c410a"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-08-30 23:17:44"
  condition:
    hash.sha256(0, filesize) == "d931dd41445159d939376b4ee6c6023bf49ba6599d9191006fdb8d99c71c410a"
}
```

### Sample 49: `eb409a50a259b298`

| Field | Value |
|---|---|
| SHA-256 | `eb409a50a259b298dc166799c99e51d59a253a7377a354e5a7c3d1cfb5ebcaaa` |
| Family label | `unknown` |
| File name | `payload.sh` |
| File type | `sh` |
| First seen | `2026-08-30 23:15:26` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a07c6fa3044f3275384106e368fd40ca` |
| SHA-1 | `4a93bf8973970fbb8e0eaebd634a5153c72378b2` |
| SHA-256 | `eb409a50a259b298dc166799c99e51d59a253a7377a354e5a7c3d1cfb5ebcaaa` |
| SHA3-384 | `f6b926947c839dcda8c8bfb34b1e455dd0411d41f44ad11374aabfab1adca3e11a114a1b083a9abe71615f806a286043` |
| TLSH | `T12D210717325134B1B38F48AD172E625610A202370034AE58B3EE17324FBA57538BB71A` |
| SSDEEP | `24:C4vaay+aqLCLCmTOLCS0Ml8R6T6W4vXb+LZFup1OPOk2eD:CIaay+aSmC+GCS1l8sT2vXbOXup18Z2w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_eb409a50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb409a50a259b298dc166799c99e51d59a253a7377a354e5a7c3d1cfb5ebcaaa"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-08-30 23:15:26"
  condition:
    hash.sha256(0, filesize) == "eb409a50a259b298dc166799c99e51d59a253a7377a354e5a7c3d1cfb5ebcaaa"
}
```

### Sample 50: `d9b69fe371aa57cb`

| Field | Value |
|---|---|
| SHA-256 | `d9b69fe371aa57cbe7b0e4b9221902cb207f7150693976a97beb8e59115c365a` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:13:41` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0dbe11439000d830f5b343b1b682bdd` |
| SHA-1 | `9a1ca28e2af96434f4d124871e2cc95808eeb233` |
| SHA-256 | `d9b69fe371aa57cbe7b0e4b9221902cb207f7150693976a97beb8e59115c365a` |
| SHA3-384 | `936517390344a575efce7d83df46408996594a29c21b8df480188cee8f73af8582e0c4a00a605a1c779735623ef3d768` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T19446E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:KzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:KhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_050_d9b69fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9b69fe371aa57cbe7b0e4b9221902cb207f7150693976a97beb8e59115c365a"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:13:41"
  condition:
    hash.sha256(0, filesize) == "d9b69fe371aa57cbe7b0e4b9221902cb207f7150693976a97beb8e59115c365a"
}
```

### Sample 51: `51f18fc444ca9660`

| Field | Value |
|---|---|
| SHA-256 | `51f18fc444ca9660bfdb73fe2f59007f932e743283f590e174308bfe4c34f55f` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-30 23:13:39` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0797a4c5b0dcfaf0e96155c0e04e31a3` |
| SHA-1 | `16c66beebc4aee9999888a10352f7659aa96d515` |
| SHA-256 | `51f18fc444ca9660bfdb73fe2f59007f932e743283f590e174308bfe4c34f55f` |
| SHA3-384 | `4b2bb3ba16ab3053b88dbe880da2c6ce2a91b4d790db77135295ba36381690610d6a717fc640ba56d37d8bae64a27fbc` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T11D646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:ymlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:R1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_051_51f18fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51f18fc444ca9660bfdb73fe2f59007f932e743283f590e174308bfe4c34f55f"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:13:39"
  condition:
    hash.sha256(0, filesize) == "51f18fc444ca9660bfdb73fe2f59007f932e743283f590e174308bfe4c34f55f"
}
```

### Sample 52: `e7dd64dbda89025a`

| Field | Value |
|---|---|
| SHA-256 | `e7dd64dbda89025ae8f155705b437c6a41fcc7e8616b11f5ebc955bb48c2acaa` |
| Family label | `Mirai` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-08-30 23:13:28` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e20a13ee80d79b74a038d44ee636b6aa` |
| SHA-1 | `5295a3ec55346517f4bbc353257b3e0fe367cb8b` |
| SHA-256 | `e7dd64dbda89025ae8f155705b437c6a41fcc7e8616b11f5ebc955bb48c2acaa` |
| SHA3-384 | `94f5654ee7e187e0b69325b934fefd365e44ddfac39add5bc8d311865faff7729e2774cd85245734deaca1160d20bc81` |
| TLSH | `T11CE02B9A10110E58CE9B4F28B7693BC03045DC5DE7201C2ED2AB45534DBCF01B706D77` |
| SSDEEP | `6:hOeGzIWEMdYzBqlQXZTDlfaIRtL57TN40yp:wtldYzYloDlCETPOX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_e7dd64db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7dd64dbda89025ae8f155705b437c6a41fcc7e8616b11f5ebc955bb48c2acaa"
    family = "Mirai"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-08-30 23:13:28"
  condition:
    hash.sha256(0, filesize) == "e7dd64dbda89025ae8f155705b437c6a41fcc7e8616b11f5ebc955bb48c2acaa"
}
```

### Sample 53: `13ef56abdc373ffa`

| Field | Value |
|---|---|
| SHA-256 | `13ef56abdc373ffa0761004b7c2d680f6d06b15d761642cc5538bafd8560d826` |
| Family label | `Mirai` |
| File name | `mirai.sh4` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:23` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `189c6b692f3d38644b2cc751036a9959` |
| SHA-1 | `89edd2c1768d9cf2aa73673ccdcc818f66fa8c95` |
| SHA-256 | `13ef56abdc373ffa0761004b7c2d680f6d06b15d761642cc5538bafd8560d826` |
| SHA3-384 | `23209f4e2a8164da71ac16cd75ffad4fb8f0b5bbd59c12579c62495c32e357c0a076a01c0c640d0e8b50d2db4cc9fff1` |
| TLSH | `T14D537CA2C02C6FE4D1489EF075788ABC1763F90494173EB2A757CAA91487E9CF184BF5` |
| SSDEEP | `768:gc2dPW+XDWIGrHLTfX1LS1YR/uyeGNAw/yjdvF4HAQLCVRJn7EWE:gc2djXCIGDvX1WC2zGShF4HAECVRm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_13ef56ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13ef56abdc373ffa0761004b7c2d680f6d06b15d761642cc5538bafd8560d826"
    family = "Mirai"
    file_name = "mirai.sh4"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:23"
  condition:
    hash.sha256(0, filesize) == "13ef56abdc373ffa0761004b7c2d680f6d06b15d761642cc5538bafd8560d826"
}
```

### Sample 54: `9b8f75b3758536e5`

| Field | Value |
|---|---|
| SHA-256 | `9b8f75b3758536e5b79092411b979e5a9617e8f04f1c60f000cb99d603b46134` |
| Family label | `Mirai` |
| File name | `mirai.spc` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:22` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `308bea5365bd9cd852e477210daafbdf` |
| SHA-1 | `4e99540f4a950b6d125a890287e68d411a80d164` |
| SHA-256 | `9b8f75b3758536e5b79092411b979e5a9617e8f04f1c60f000cb99d603b46134` |
| SHA3-384 | `3fae7cdf9d8f33503d500b1aaf013d1dbc345f7cfd700adf49fa041164b91794f213c512f20cf1a62c18ae9615d168ba` |
| TLSH | `T1CF735C21BA792F17C0E4F17E51F78726B2F9174E14A4CA5E3E220E8DAF1953032176B9` |
| SSDEEP | `1536:Rsxw/k2qQZXPEikT+W2z+mp+Sk6etsGSNw:RUu9si0Pm3exQw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_9b8f75b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b8f75b3758536e5b79092411b979e5a9617e8f04f1c60f000cb99d603b46134"
    family = "Mirai"
    file_name = "mirai.spc"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:22"
  condition:
    hash.sha256(0, filesize) == "9b8f75b3758536e5b79092411b979e5a9617e8f04f1c60f000cb99d603b46134"
}
```

### Sample 55: `1b647683b7fc5ee5`

| Field | Value |
|---|---|
| SHA-256 | `1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01` |
| Family label | `Mirai` |
| File name | `mirai.mips` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:21` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9cb4d7eda28f275a45e25aed202fba4` |
| SHA-1 | `e3a294318e7ef12c3457a05cc44f5fa5dbfcd9b8` |
| SHA-256 | `1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01` |
| SHA3-384 | `84f166076cabf6a4e59c9de154029d8f056ec3ffd5c227079120b9cc95eaa2801fa57bdd432f3b8ffdb7ef56e9252d10` |
| TLSH | `T1FA93A54A2E618FACFBD9823447F75B319258379527E1C584D29CED001EB074FA41FBAA` |
| TELFHASH | `t14221c516993803f8d7805ddd6becfb32d0b1a0cf29152d27cf64ee9a8a69d816e00c1c` |
| SSDEEP | `1536:EL/owQCoLlOQyGd5gJ19k9wkN3m/DhoRq5W6rG+hpzOplaC1Ryf3:EbHvoLEMEJQ13mrhoRErG+hww` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_1b647683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:21"
  condition:
    hash.sha256(0, filesize) == "1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01"
}
```

### Sample 56: `9b717d713836c386`

| Field | Value |
|---|---|
| SHA-256 | `9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01` |
| Family label | `Mirai` |
| File name | `mirai.ppc` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:21` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcbcc877b827b9e3ebdfc71c1cf49b0b` |
| SHA-1 | `b157927574c3a8c1b4bfadb7f0a7be6b198a49cf` |
| SHA-256 | `9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01` |
| SHA3-384 | `fac265fe5be7ee0efdfc7a09126cd5128ad102903580667fcc011d3de96b176b9100145503ea85b1429c5a11780a5e25` |
| TLSH | `T1EB633A0272284993E4621EF1393F1BE193FEED6111F0B6492A0FFB465175E32158AF9D` |
| SSDEEP | `1536:AIevJ3ORwXUxgVw1ZMNlY88gHOv55aZ4r0Q:NevJHwg0WNlYOHSr9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_9b717d71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01"
    family = "Mirai"
    file_name = "mirai.ppc"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:21"
  condition:
    hash.sha256(0, filesize) == "9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01"
}
```

### Sample 57: `0781d164ad718340`

| Field | Value |
|---|---|
| SHA-256 | `0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a` |
| Family label | `Mirai` |
| File name | `mirai.mpsl` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:20` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4ab6c11a310e22158ff9e74cfe8dda4` |
| SHA-1 | `73a4170a53cd03efaa7f43fd7283451473bf424a` |
| SHA-256 | `0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a` |
| SHA3-384 | `2ccb04c209a40b32ad7bb722cfae66434d1a98dbba24c681979a98cc9f65d92670e84454815108b638ca46a5ede06a79` |
| TLSH | `T17A93D61AAF661FF7E89FCC3744A9170520CCA50A22A93F75B538D828F68F14B55D38B4` |
| SSDEEP | `1536:OVHsf1ocnptO0lmb05O3ihMvYb2+WbrFP2LxA3F9VNcdbwVNll5YQWGBpkxS6cWD:Og1ocptO04owKElQ5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_0781d164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a"
    family = "Mirai"
    file_name = "mirai.mpsl"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:20"
  condition:
    hash.sha256(0, filesize) == "0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a"
}
```

### Sample 58: `d3326ec9bb37c8bc`

| Field | Value |
|---|---|
| SHA-256 | `d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d` |
| Family label | `Mirai` |
| File name | `mirai.arm7` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:20` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5521a6f577c8736988db4d481719531c` |
| SHA-1 | `0d8befbd63940271f4b59852425fa0d7d2d1143f` |
| SHA-256 | `d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d` |
| SHA3-384 | `bea10ce3add17c65d8884cfbc380134cc1bfae1860e3a553a6019ded53c6264acf559765f42865affaf03dc7c434df7d` |
| TLSH | `T1D863F856B8918A01C5C513BAFE2E118E331753B8D2DFB213DE106F60778A96F0E7B952` |
| TELFHASH | `t194218b728ee909ecab81c389d1cb70299ddc31b86f25105eda5e3b4a52b35c67526024` |
| SSDEEP | `1536:eRnmgeJ4li805QAzDmSGPp3p7nxczK6CY6VyhqfGEMr6h1aL8IOi11hbZWn:RgXxA/m5Vp1czKhVbfGEs6q1hbZWn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_d3326ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d"
    family = "Mirai"
    file_name = "mirai.arm7"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:20"
  condition:
    hash.sha256(0, filesize) == "d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d"
}
```

### Sample 59: `6492bc2bfaa40a1a`

| Field | Value |
|---|---|
| SHA-256 | `6492bc2bfaa40a1a4c783fde77be26cd0381038f13deacce833ae84a6dbc5712` |
| Family label | `Mirai` |
| File name | `mirai.arm` |
| File type | `elf` |
| First seen | `2026-08-30 23:13:19` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ada0a750a02cab4834d97bd05de91a9` |
| SHA-1 | `9ad55ee919605231dfd9329d07d735ea53605076` |
| SHA-256 | `6492bc2bfaa40a1a4c783fde77be26cd0381038f13deacce833ae84a6dbc5712` |
| SHA3-384 | `1f15dea093f5d7a9e3ce06adbdd43eadeb114683d87202b3181bc50addca79751ab519dd9bbeaba6359407599174a3ee` |
| TLSH | `T183631845F8918F02C6D412BBFA6E018D332663ACD2EB32139E116F2577CA92F0D7B556` |
| TELFHASH | `t1a43158f75e990adc3be0c74486ca622ec9a938ed17405ab9ce2d9757414b8c1343f526` |
| SSDEEP | `1536:/uVt53Ck2DyIQb2K2yIuKRctJPbLYp3TbyeU2Z41siFDpfZU2:/uVP2DyNbzSuKRmJPwpjbyv4mTFDpfZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_6492bc2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6492bc2bfaa40a1a4c783fde77be26cd0381038f13deacce833ae84a6dbc5712"
    family = "Mirai"
    file_name = "mirai.arm"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:19"
  condition:
    hash.sha256(0, filesize) == "6492bc2bfaa40a1a4c783fde77be26cd0381038f13deacce833ae84a6dbc5712"
}
```

### Sample 60: `4b6c5c2d773b5d4b`

| Field | Value |
|---|---|
| SHA-256 | `4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea` |
| Family label | `unknown` |
| File name | `4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea` |
| File type | `sh` |
| First seen | `2026-08-30 23:00:12` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc3bbc8437e1acf9c301e2238df2f48f` |
| SHA-1 | `9e4220ccff0d30388e9ced109a0b050903cd3bba` |
| SHA-256 | `4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea` |
| SHA3-384 | `0cf47e8478c51580140424ac0a17f1bb4fe77b4778bb60908a19af9f54abf3ac1a550c1585ac20ef791ffc8bcfa28a93` |
| TLSH | `T1ED31CF9F05010EB11047ED4E73B37548738DA2EB2C5FC7E9A8490EA9828878CF160F9E` |
| SSDEEP | `12:UV6zRDQqlrex6rec+MEHlk6lpwTNqU76NqY9RKkdY6d5Dul06Dn7CvNV6NiEbX70:Xlb3EhpAOKk9wuxE4JBNoUoC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_4b6c5c2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea"
    family = "unknown"
    file_name = "4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea"
    file_type = "sh"
    first_seen = "2026-08-30 23:00:12"
  condition:
    hash.sha256(0, filesize) == "4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea"
}
```

### Sample 61: `580f311847643ec2`

| Field | Value |
|---|---|
| SHA-256 | `580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8` |
| Family label | `unknown` |
| File name | `580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8` |
| File type | `sh` |
| First seen | `2026-08-30 22:30:20` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `579f571e732bfce7eda9adce6ed76acc` |
| SHA-1 | `bfc2d9fd100c5d7bc15daa39298d9ef4c7fdf237` |
| SHA-256 | `580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8` |
| SHA3-384 | `15571f9db0b66873f077925dd84510ca76c90fb40c656cff74139cb60df3f1bb0acdc9b569ecb499f9bccf0eafa53583` |
| TLSH | `T17D316E9A10105B301103CE9E77B7348D6A8DA2EB299FD3D9E8590EA982597CCF1A1F4D` |
| SSDEEP | `12:UBwP6BwDdNr6d/uwS7wcK6cktOL6OhA+IcIMlb6Y14EGNWs6NWGpGi6pGLtxZeFe:+NkNW1S7dcGAxNuGscGskKSxvE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_580f3118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8"
    family = "unknown"
    file_name = "580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8"
    file_type = "sh"
    first_seen = "2026-08-30 22:30:20"
  condition:
    hash.sha256(0, filesize) == "580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8"
}
```

### Sample 62: `cae1cce3f601c297`

| Field | Value |
|---|---|
| SHA-256 | `cae1cce3f601c297e9eb531df55a9d864605e383fafe3509fee0f2a99b25348e` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-30 22:27:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49d85b323477b2bfc819f740b307cec5` |
| SHA-1 | `1c22c04ed7b2ce25f95a7d6801d7ffaf1e8d8b7c` |
| SHA-256 | `cae1cce3f601c297e9eb531df55a9d864605e383fafe3509fee0f2a99b25348e` |
| SHA3-384 | `c298f436c05762b49ba24ddbcbd4f55b43cefbca6c6c3ff417a452a63ddedef8d29d335ac33465303a598f70528369f5` |
| TLSH | `T1E9344B52AA924A13C1D31B7AFB9F41463323A76693DB7306F91C6BB43F8225E4E73501` |
| TELFHASH | `t178311f3117359612aea0da589ced53b7152ec3262285ef73de25c4dc940a0abe633c4f` |
| SSDEEP | `6144:ncIBtw1SypwC6vOEWXuhYLamxdTgcLgmTH5IKEssMOgh5ofvyPBM/9gq3t:jBtw1SypwC6mEW+hYLamxdTgdW3EssMA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_cae1cce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae1cce3f601c297e9eb531df55a9d864605e383fafe3509fee0f2a99b25348e"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-30 22:27:50"
  condition:
    hash.sha256(0, filesize) == "cae1cce3f601c297e9eb531df55a9d864605e383fafe3509fee0f2a99b25348e"
}
```

### Sample 63: `f6f310bb98d67181`

| Field | Value |
|---|---|
| SHA-256 | `f6f310bb98d6718154b3962c89bc779a28d2b7f6afe4170e89229ed4aaff88ca` |
| Family label | `unknown` |
| File name | `.X0-lock_x86_64` |
| File type | `elf` |
| First seen | `2026-08-30 22:27:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `683ae9228415b7f265011029bc5acd18` |
| SHA-1 | `cd523930459547910f653518d79c89051c6c40f5` |
| SHA-256 | `f6f310bb98d6718154b3962c89bc779a28d2b7f6afe4170e89229ed4aaff88ca` |
| SHA3-384 | `3035c07f68524f0c1f8a48215113a501310b7bd4fcf8fbd454166574c5c282b3704e74d15cb4a9df2704b274ad5ba2d8` |
| TLSH | `T19C654C07B6A344BEC1F5C830874BC5B3AD3578546225397F7685AB202E77E204B6EBB1` |
| SSDEEP | `24576:j0vvDpbKIuRguqvXOT9seV7SJKZ4lFLXd6UvdbBRPTW+JxvMRk:gvLpb4Evg9s+7TKLXdrvdrmR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_f6f310bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6f310bb98d6718154b3962c89bc779a28d2b7f6afe4170e89229ed4aaff88ca"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-08-30 22:27:48"
  condition:
    hash.sha256(0, filesize) == "f6f310bb98d6718154b3962c89bc779a28d2b7f6afe4170e89229ed4aaff88ca"
}
```

### Sample 64: `c2d2b1e3e9c82a7a`

| Field | Value |
|---|---|
| SHA-256 | `c2d2b1e3e9c82a7a2cf99e1484fbc8c2b25f06a49efb7e3e3c7c63dbf347d9ca` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-30 22:27:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0c91a6ca11c2d551ff464d463150c05` |
| SHA-1 | `0a6c473e4ee664ea46c154876ab06b3e80f12f2b` |
| SHA-256 | `c2d2b1e3e9c82a7a2cf99e1484fbc8c2b25f06a49efb7e3e3c7c63dbf347d9ca` |
| SHA3-384 | `48caa975b2f1642f7164a66bea8275734365ab7c3236058b261c4aed8cd1a2b76ac85a153f6680ef41d02fb8cfaa1ca5` |
| TLSH | `T1D3935A2219F76116D6D3D83F839F0216F16635070188C61AFC2E5DAEBF42260B3BB6E5` |
| TELFHASH | `t1b0f0c041fd388a144ae27a70ec6803a585134613612287248f58c9d0cc3e00ab248d1d` |
| SSDEEP | `1536:FgNMEtB1bzGk/vlJaUQJSlUJ3t5V1XaAaz4B7b5OQuEpZVTu1EssMZcywT03ImIC:sFvlcUQSI11XZqEpZ5u1EssMZc/T03I2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_c2d2b1e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d2b1e3e9c82a7a2cf99e1484fbc8c2b25f06a49efb7e3e3c7c63dbf347d9ca"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-30 22:27:46"
  condition:
    hash.sha256(0, filesize) == "c2d2b1e3e9c82a7a2cf99e1484fbc8c2b25f06a49efb7e3e3c7c63dbf347d9ca"
}
```

### Sample 65: `ec5c7ff617a8f532`

| Field | Value |
|---|---|
| SHA-256 | `ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a` |
| Family label | `unknown` |
| File name | `ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a.exe` |
| File type | `exe` |
| First seen | `2026-08-30 22:26:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93bbe4c2af7f7e12489886ca86295d37` |
| SHA-1 | `c4451d3e217440db4d5586a24ed6444e54bafe17` |
| SHA-256 | `ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a` |
| SHA3-384 | `a0ed8ea16d35805c6d10f90ccb1fe27bda4ac85885bce7bcaab52e5bb9cabbb6e7b2ccd1e33a28dc42dce8bf60efb1ac` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T12CD52399BCC73E72F432C37B46D3A0AEB0293B9556208C5E76C85B509E538247C7B369` |
| SSDEEP | `49152:c/SowrZ+YnXyUt/ZUTBa01gLehTvfuIIoB/GLhcJT7G7APMqMH5FY9VC7rqxrxMy:cMwYnXyUZsJB5rIosLhUkAW5eSOO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_ec5c7ff6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a"
    family = "unknown"
    file_name = "ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a.exe"
    file_type = "exe"
    first_seen = "2026-08-30 22:26:48"
  condition:
    hash.sha256(0, filesize) == "ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a"
}
```

### Sample 66: `b82adccfc4f2c3e4`

| Field | Value |
|---|---|
| SHA-256 | `b82adccfc4f2c3e4c4bf6b14e2c080435e6578bf6449aeefa16a66698f736a3f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-30 22:14:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7c3a00d469b80a21ee4d45c4237578d` |
| SHA-1 | `717541e844c263a4cd6bd718a73179eb838665d4` |
| SHA-256 | `b82adccfc4f2c3e4c4bf6b14e2c080435e6578bf6449aeefa16a66698f736a3f` |
| SHA3-384 | `11abcdbf3b86dbe059f8cfe692277978b45ab41bdfde6c8a639efdd4449264e2f277e8d07434169f15441f212dabd05e` |
| TLSH | `T149236C6516857C14AA98C4375C7E2F0CBDAD43E6314492EE7FCB3CF28C4AAAD920875D` |
| SSDEEP | `768:i9NyXsZztCD9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:iHusZxcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_b82adccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b82adccfc4f2c3e4c4bf6b14e2c080435e6578bf6449aeefa16a66698f736a3f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-30 22:14:59"
  condition:
    hash.sha256(0, filesize) == "b82adccfc4f2c3e4c4bf6b14e2c080435e6578bf6449aeefa16a66698f736a3f"
}
```

### Sample 67: `d683b763682b0812`

| Field | Value |
|---|---|
| SHA-256 | `d683b763682b08127a52d049509ac0e861fe21bc54fb73eeb1841b854e6bf2a7` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-30 22:03:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3275de1df91c00b9ff709afb36d318c` |
| SHA-1 | `8e82881795729527f2a5fa606db8698cb7053b33` |
| SHA-256 | `d683b763682b08127a52d049509ac0e861fe21bc54fb73eeb1841b854e6bf2a7` |
| SHA3-384 | `e2106153d9188ab7cccc25ee9c03ca10af00848ca9bf00b7b9c68a85f0ea23fb2b309fda028f5ed62cd183a8d32afbeb` |
| TLSH | `T13C047CA2CCB27D60D3668475F2678A3D1B139413024B5E68B86FC2B42F43D98F2E57B4` |
| SSDEEP | `3072:o/z+jrN6qlTK5Xwowme7zHWUVP0QrzI/tu1EssMZc/T03ImIys61X1h5oZ:2YjO5XwA22U2QXI/eEssMOgh5oZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_d683b763
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d683b763682b08127a52d049509ac0e861fe21bc54fb73eeb1841b854e6bf2a7"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-30 22:03:18"
  condition:
    hash.sha256(0, filesize) == "d683b763682b08127a52d049509ac0e861fe21bc54fb73eeb1841b854e6bf2a7"
}
```

### Sample 68: `713cfb58fc152e53`

| Field | Value |
|---|---|
| SHA-256 | `713cfb58fc152e5369f7e51d177223b69dfca974e0ee2064a9f8a794393d31ff` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-30 22:00:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42bcfca83a783f2f81863f2fb2220549` |
| SHA-1 | `40d2a71d9ec8fc96e4f9e079e5de219714fab725` |
| SHA-256 | `713cfb58fc152e5369f7e51d177223b69dfca974e0ee2064a9f8a794393d31ff` |
| SHA3-384 | `fab2657aede6d668c7db191e124797b682ba07d106562a32d06b613b57574e92b0af9869ff98217c679a2288de55b6fa` |
| TLSH | `T11544D809AFB21EF7E86BDD3706E9160625CCA41722983B35763CD524FF4A50B4AE3C64` |
| SSDEEP | `3072:OoaTHfH8qwvzgS9vYtzzUQ9kvWcuxnCWSp4XvsBtPu1EssMZc/T03ImIys61X1hB:LfkS9v6z46SZgCCwtsEssMOgh5of` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_713cfb58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "713cfb58fc152e5369f7e51d177223b69dfca974e0ee2064a9f8a794393d31ff"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-30 22:00:52"
  condition:
    hash.sha256(0, filesize) == "713cfb58fc152e5369f7e51d177223b69dfca974e0ee2064a9f8a794393d31ff"
}
```

### Sample 69: `378663855be020f0`

| Field | Value |
|---|---|
| SHA-256 | `378663855be020f0c4bdf6e45c802ad721e6516c0b59fbfef8e5feaff4f42d9b` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-30 21:56:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3f839d5dfcfd8e5511fdfca13c02aa1` |
| SHA-1 | `7b60deb61a43c649b4f703b3702d045d3b5e4185` |
| SHA-256 | `378663855be020f0c4bdf6e45c802ad721e6516c0b59fbfef8e5feaff4f42d9b` |
| SHA3-384 | `d79ef78f3c30eb4c59fdbf56c12f0fe38ea7a2ab4c61410d58a1e946e2489dc1dbd2f3006a748363207826198487fa8f` |
| TLSH | `T1ECE36BC169E3E0F1EA5344B9426F931A4B36E4370119EA51FB2E68396F42050E7BB79C` |
| TELFHASH | `t10a5114fa7a6e0ce9b7949c45830d2f22794eeb7b246472e145f3983532a3e4184b5c3d` |
| SSDEEP | `3072:NzDrOzeMSfw5LryqHlxJde0nHF+QVwMOr/U3Bu1EssMZc/T03ImIys61X1h5oo:hOyMSfwt5P/VwZTU3KEssMOgh5oo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_37866385
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "378663855be020f0c4bdf6e45c802ad721e6516c0b59fbfef8e5feaff4f42d9b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-30 21:56:56"
  condition:
    hash.sha256(0, filesize) == "378663855be020f0c4bdf6e45c802ad721e6516c0b59fbfef8e5feaff4f42d9b"
}
```

### Sample 70: `348fb16af9b19174`

| Field | Value |
|---|---|
| SHA-256 | `348fb16af9b191747359553b9b995b82fff2dda2f4d3ecaff280080f3d6177e6` |
| Family label | `unknown` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-30 21:56:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f63d215ff3ef94537c1bb4c3af20ea93` |
| SHA-1 | `a485de1f17afc748f0648bc71fc00f0f2b246c27` |
| SHA-256 | `348fb16af9b191747359553b9b995b82fff2dda2f4d3ecaff280080f3d6177e6` |
| SHA3-384 | `88dae067e0ae9bc3c9d58c70a6630f086c36b8fac2b8c3139d15e7b0b2116add14993e8f15a7118f32ca53312513e450` |
| TLSH | `T1CBF3F100FF20F651D4506670C87B06192E5F69A205B2A58BA812B78FE424F7AF71BE7D` |
| SSDEEP | `1536:oV2QEHtBygXPf+Jv4Yidw+aOy3zN/bdOHDwyirEp+IO2D+sP0oLpE6TRgUwch889:S2Qq3+ZqwrlbkHEoMIO2DNJ6Zvcu6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_348fb16a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "348fb16af9b191747359553b9b995b82fff2dda2f4d3ecaff280080f3d6177e6"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-30 21:56:54"
  condition:
    hash.sha256(0, filesize) == "348fb16af9b191747359553b9b995b82fff2dda2f4d3ecaff280080f3d6177e6"
}
```

### Sample 71: `b3caa2e3d0c88a38`

| Field | Value |
|---|---|
| SHA-256 | `b3caa2e3d0c88a3872e1102f356fc665678b150e05a511412dc613ae04a118a9` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-30 21:56:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66509f3a50366f2b3ac52f3d7fc8a154` |
| SHA-1 | `3492041dc2b022d94e11e6bb5b80f748cfab384b` |
| SHA-256 | `b3caa2e3d0c88a3872e1102f356fc665678b150e05a511412dc613ae04a118a9` |
| SHA3-384 | `c3d4fe4364da67d0509a94fb842b84aad881f125d966fcf43e40db38fd499bd1f5fd2959041fe9ad4c9e4d76148f9446` |
| TLSH | `T182240852BCD29B11C6C2427EFB0E514E33136B7AD2CE7212BD1C6B703F8A46B0A7A555` |
| TELFHASH | `t149e07d63e64458dda2d0818562e1f1047875f02e0e05288448c8b75f4f17c23340ed01` |
| SSDEEP | `6144:8+ZpEiLp6ZZd7UR2+vXAroaavr4tYpRzw50aEssMOgh5ot4:zpEiLp6ZZd7UR2oXSoas0tYHcEssMOgP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_b3caa2e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3caa2e3d0c88a3872e1102f356fc665678b150e05a511412dc613ae04a118a9"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-30 21:56:53"
  condition:
    hash.sha256(0, filesize) == "b3caa2e3d0c88a3872e1102f356fc665678b150e05a511412dc613ae04a118a9"
}
```

### Sample 72: `c2a669ab6504a18b`

| Field | Value |
|---|---|
| SHA-256 | `c2a669ab6504a18b47c6f493efc899e47f29a9605a6b1df0b21cbf78ef1eb73b` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-30 21:50:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1fa3e0eb7b6755bfbdae529a75f2b53` |
| SHA-1 | `acd43f5607de72c4112c6b770b028242d57a6098` |
| SHA-256 | `c2a669ab6504a18b47c6f493efc899e47f29a9605a6b1df0b21cbf78ef1eb73b` |
| SHA3-384 | `88c5481f0c39dd60d51ea044bcd2f587a23b538c91e8ad4cd7c69170606164df02be26b3c5bc7edcf0578fb04757317e` |
| TLSH | `T1EE3183DA05152E311143CA4E37B2399C628EA1F71DAFD7E59D484FE9928868CF252F0D` |
| SSDEEP | `12:UUPR6UPZhJDKUma6mpHG967Dc4pm6LP0LXnr6zDN8d7685pFHr6pFxIFOd61Fgcf:Zx9KFYlDc4Uj229nmMUdGBM4Cl5vkqS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_c2a669ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2a669ab6504a18b47c6f493efc899e47f29a9605a6b1df0b21cbf78ef1eb73b"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-30 21:50:56"
  condition:
    hash.sha256(0, filesize) == "c2a669ab6504a18b47c6f493efc899e47f29a9605a6b1df0b21cbf78ef1eb73b"
}
```

### Sample 73: `b33121f5f6866196`

| Field | Value |
|---|---|
| SHA-256 | `b33121f5f6866196079651fcabc4fcf1998944578846eb83e557f3128ed4c867` |
| Family label | `unknown` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-30 21:50:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a7213af274942c523c6e3e0ddc82ddca` |
| SHA-1 | `a3f40357cd61b1722cd6f720c8e0976f0a645364` |
| SHA-256 | `b33121f5f6866196079651fcabc4fcf1998944578846eb83e557f3128ed4c867` |
| SHA3-384 | `7538f8819096668c2fd938a745dfb971331b74dd8e76b33f977a9a23ff6fec7d584dae2e1232bc87a8c6d7f34a6bac70` |
| TLSH | `T1E6C302C1E6268F64D747CA779AAF87876BC1AD47874B0B300E6FF229558C348B319E14` |
| SSDEEP | `3072:dP/grpM6wKKG6JwrZpn2JT46IMATx0Uh/3UyqnFvv+szqI2qS:dAd65G6JwrZUJ0lMATxlvIvWsvG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_b33121f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b33121f5f6866196079651fcabc4fcf1998944578846eb83e557f3128ed4c867"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-30 21:50:54"
  condition:
    hash.sha256(0, filesize) == "b33121f5f6866196079651fcabc4fcf1998944578846eb83e557f3128ed4c867"
}
```

### Sample 74: `f2bbb1db345b0b4a`

| Field | Value |
|---|---|
| SHA-256 | `f2bbb1db345b0b4a70ac285c77d6368d3e6294cf79418a10c47749711c7b93af` |
| Family label | `unknown` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-08-30 21:41:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d865d4555dc04692f7eb526c74c9147` |
| SHA-1 | `837c4d5afcb43b1afb85a5ae45d67a888374e1ff` |
| SHA-256 | `f2bbb1db345b0b4a70ac285c77d6368d3e6294cf79418a10c47749711c7b93af` |
| SHA3-384 | `ff05002b8e0bbfa72424d7ae1d10e993b1b973a358177179fd5cf7d314efe3790cd4abbcc6a3ee10a4e52ed2b80ce615` |
| TLSH | `T1ADA3F23BD596F04DE4955B3702CB53903903631A888B1C27F2AF97BD2B3A1D1B6AD1B4` |
| SSDEEP | `1536:uf1aGwvbsTwJKk07m4fM2F1rfGggmuMUq6IccOJaWXe4yE4pU/ok2:s4bsUJgHUORfnFLIJJTuFE4pOok2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_f2bbb1db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2bbb1db345b0b4a70ac285c77d6368d3e6294cf79418a10c47749711c7b93af"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-30 21:41:59"
  condition:
    hash.sha256(0, filesize) == "f2bbb1db345b0b4a70ac285c77d6368d3e6294cf79418a10c47749711c7b93af"
}
```

### Sample 75: `0afe53066fa70037`

| Field | Value |
|---|---|
| SHA-256 | `0afe53066fa700377a69d22c264f76761b8fb289308abfde8bf4fac7b0182111` |
| Family label | `unknown` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-30 21:39:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c9432c8f74693001fdfdc1b501ee6c2` |
| SHA-1 | `443db464fbde168c1f625eb9a7ab003a89dbcb42` |
| SHA-256 | `0afe53066fa700377a69d22c264f76761b8fb289308abfde8bf4fac7b0182111` |
| SHA3-384 | `57f856e5bc6d38ec1aa5a865bf8d28f4f56de2469bbc035cf6cacfb1446b9531f2c638a34cbc2feb6691f5e9ea29aa50` |
| TLSH | `T14D93124EB7E14E8ACC87133456F3D38AA9C59C0CFC95FF0A1115995AA8DC0EA4EA6CC5` |
| SSDEEP | `1536:8pGihCwJDWgGWrzWeZXGT1kzh034/ayC6e9Xkebx1NVYY6RtEFRN9TiTJEh:8pGiUwBWiKqo1uaoSyCJBkKVYmT9TWJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_0afe5306
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0afe53066fa700377a69d22c264f76761b8fb289308abfde8bf4fac7b0182111"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-30 21:39:55"
  condition:
    hash.sha256(0, filesize) == "0afe53066fa700377a69d22c264f76761b8fb289308abfde8bf4fac7b0182111"
}
```

### Sample 76: `38fe0a93c3da4369`

| Field | Value |
|---|---|
| SHA-256 | `38fe0a93c3da436976dd0e96f70e228107508fc26bd612c90ad643238e72fe56` |
| Family label | `unknown` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-30 21:37:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8942a01f619e3461108b8d31a0d43f07` |
| SHA-1 | `9df77d17d2764c70139c1edb50474d6640b73c4b` |
| SHA-256 | `38fe0a93c3da436976dd0e96f70e228107508fc26bd612c90ad643238e72fe56` |
| SHA3-384 | `531b9a0ec8edf0b01c4728680d7114d9bba868f031def987c4d5c541cd41a61febc594cc50bb5a1c62a1ca1bf063785f` |
| TLSH | `T14D930206F1C31BA9DC5D01FA9623DB0928C86404F58993077BFCD42DA8EB9F34F8A5A5` |
| SSDEEP | `1536:vWEDfnF/yQZFBoWclomQxHdApcRNZ/lCS+eK8ZjiHSZUvTpnHguzfZonSDC17AYF:vWEDPF/y4+Jel9r9i4K80AuthDMv6f+v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_38fe0a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38fe0a93c3da436976dd0e96f70e228107508fc26bd612c90ad643238e72fe56"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-30 21:37:56"
  condition:
    hash.sha256(0, filesize) == "38fe0a93c3da436976dd0e96f70e228107508fc26bd612c90ad643238e72fe56"
}
```

### Sample 77: `040fe79af10373a4`

| Field | Value |
|---|---|
| SHA-256 | `040fe79af10373a4a2680b5fbfd439dc7afca68c0bf9bc12144a4e9e33430292` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-30 21:37:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f210f6f6531ebd8e51a2ee76efd0471` |
| SHA-1 | `b84bd0d0e0ea22345994d6826465f1e1f151a45a` |
| SHA-256 | `040fe79af10373a4a2680b5fbfd439dc7afca68c0bf9bc12144a4e9e33430292` |
| SHA3-384 | `efa73a2ba11192eb760ecf5b0c726e0a402bdcbdb73984647afda81f17780854b3e33a27aa8d615670b4cd9cd59ee79a` |
| TLSH | `T163145C1378E190FDC9D7C1398B9F901AD932F41B1224B11A779DBE612F4EE30A7AD684` |
| TELFHASH | `t19861ed313a962d5832e7973a734bdad5f836092509e270ea9e739cf1ce4a7c84c63452` |
| SSDEEP | `3072:YeNvKdc1t0UXaIV56PS+Jo1JEmSZkN7XP1pBdV3Un5Xlu1EssMZc/T03ImIys612:vJ11t9buJK7P1Y5X2EssMOgh5oF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_040fe79a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040fe79af10373a4a2680b5fbfd439dc7afca68c0bf9bc12144a4e9e33430292"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-30 21:37:55"
  condition:
    hash.sha256(0, filesize) == "040fe79af10373a4a2680b5fbfd439dc7afca68c0bf9bc12144a4e9e33430292"
}
```

### Sample 78: `7209e154bd93a9cd`

| Field | Value |
|---|---|
| SHA-256 | `7209e154bd93a9cdd455902b3c3e412f2024e9f0ddb83fc0b180c4af2d8adf67` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-30 21:35:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6faa8019df7dd970257233f395185652` |
| SHA-1 | `accbdc41171327a8a5009e7ad034976e8eefdb72` |
| SHA-256 | `7209e154bd93a9cdd455902b3c3e412f2024e9f0ddb83fc0b180c4af2d8adf67` |
| SHA3-384 | `b9431d2bd5369385a5568d6d5faeae0de03d8b130f61322ddcbbd73d700ba146d1f13324f53166fa2d2139a6aedb5926` |
| TLSH | `T1C944C75E2E628F3EF3A98B3487B74A25975C62D713D1D640F16CD1101F2025EA46FFA8` |
| TELFHASH | `t10a41721c0d7813a0a7695c59599dff36e6a330db7f262c278e11e86ae769b435d10c0c` |
| SSDEEP | `6144:CbabObfmNx4/nlWw0wHojzCQ20OpaF4tsEssMOgh5odLD2:8fPpotTEssMOgh5odLD2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_7209e154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7209e154bd93a9cdd455902b3c3e412f2024e9f0ddb83fc0b180c4af2d8adf67"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-30 21:35:54"
  condition:
    hash.sha256(0, filesize) == "7209e154bd93a9cdd455902b3c3e412f2024e9f0ddb83fc0b180c4af2d8adf67"
}
```

### Sample 79: `cd8a4747ca552e4c`

| Field | Value |
|---|---|
| SHA-256 | `cd8a4747ca552e4ce1b1bd86249a068f33c3e512a8337dae20ebdd5237134988` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-30 21:31:01` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `770f9b5a333cc04a0a06720de6892d17` |
| SHA-1 | `5413d82088fed238e8aaecaa16758d5b33e7d5eb` |
| SHA-256 | `cd8a4747ca552e4ce1b1bd86249a068f33c3e512a8337dae20ebdd5237134988` |
| SHA3-384 | `f4cd13346492f22348d322033ec9e4a78669ee2c6894d94bd27339aded7f470e2e5c5accb3b173ab241526b798499777` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A9364A037B8981B0C055EA7A84B242517BB47C1D833433EB6EA6EA703F663D1B679F54` |
| SSDEEP | `49152:vCH76HHcMXNfd7ZNjEpinbaK7fUlu65w+AnSwgwnC:vB8K5xQwl3jC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_cd8a4747
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd8a4747ca552e4ce1b1bd86249a068f33c3e512a8337dae20ebdd5237134988"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-30 21:31:01"
  condition:
    hash.sha256(0, filesize) == "cd8a4747ca552e4ce1b1bd86249a068f33c3e512a8337dae20ebdd5237134988"
}
```

### Sample 80: `8727a17e67980f4d`

| Field | Value |
|---|---|
| SHA-256 | `8727a17e67980f4db297653f1bbdcf3a788f6241259427163de792b8f1e291b8` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-30 21:29:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d9e24f0c077de3a4b7b4df525df8f71` |
| SHA-1 | `2d128fe9af5f1fc7bbf8ec644fad3c8bb22bdce9` |
| SHA-256 | `8727a17e67980f4db297653f1bbdcf3a788f6241259427163de792b8f1e291b8` |
| SHA3-384 | `b73c88687dd378bd0d241ec9b8804fa84284dfc4048498c3de5338d5a64d39a195cb34860461dc7683c588f1bf6d1d80` |
| TLSH | `T1E42449D3FC11E9BAF84BE73B88470809B130B66311515A33721F757BAF2A09546B7E86` |
| SSDEEP | `6144:GWPdTPYlb1UqnBfwF2LhwJyZ+pMEssMOgh5oSg:GsdTPKnB5wsEssMOgh5oSg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_8727a17e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8727a17e67980f4db297653f1bbdcf3a788f6241259427163de792b8f1e291b8"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-30 21:29:51"
  condition:
    hash.sha256(0, filesize) == "8727a17e67980f4db297653f1bbdcf3a788f6241259427163de792b8f1e291b8"
}
```

### Sample 81: `4b8c22660c29b277`

| Field | Value |
|---|---|
| SHA-256 | `4b8c22660c29b27700e6b7cd0e990f9e2f08f2a581354a09a4cf9ae08d443a51` |
| Family label | `unknown` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-08-30 21:29:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2ba83a3004963b991f755a222d7e49c` |
| SHA-1 | `fa8920dd5e38016177facd2ae68053608748707e` |
| SHA-256 | `4b8c22660c29b27700e6b7cd0e990f9e2f08f2a581354a09a4cf9ae08d443a51` |
| SHA3-384 | `3f3ba91ee9e54196aa284369358cc17591ba9962d96dc735fc2b3b6618ccbf386e34c9e52c66410438c17af2a13fc053` |
| TLSH | `T121A30113DF21E463D6457335218D5637C0A7B83A3BCF8A6E23A09B399E786C4437A427` |
| SSDEEP | `1536:G3WgTD30vP2lNEa6uZTDd/HR2sosZ5oQhReTQejqOaG/Vb/eW1/p5qt1:77Ha6uZT1xT5jhinVKGzw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_4b8c2266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8c22660c29b27700e6b7cd0e990f9e2f08f2a581354a09a4cf9ae08d443a51"
    family = "unknown"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-30 21:29:50"
  condition:
    hash.sha256(0, filesize) == "4b8c22660c29b27700e6b7cd0e990f9e2f08f2a581354a09a4cf9ae08d443a51"
}
```

### Sample 82: `a78278e9b95b9eb1`

| Field | Value |
|---|---|
| SHA-256 | `a78278e9b95b9eb162331dfd052b98752b6757a8991012f44a84efc25e9f49d1` |
| Family label | `unknown` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-30 21:27:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e76b184e1fdeee0d4bd51bf76800574` |
| SHA-1 | `4982145bf44236a16f2613d875e42d00413e7f27` |
| SHA-256 | `a78278e9b95b9eb162331dfd052b98752b6757a8991012f44a84efc25e9f49d1` |
| SHA3-384 | `7e1ea33b22ed8969f24f22fab71691e8f4fd65107e533fce15f7056e623d3d6b4f91f3a3e379253eda899e9f31ba086c` |
| TLSH | `T1C7C302133B745E83C1499DB82C9B16B670BE45834AA7FB33932C6B50D2634C19B93D6B` |
| SSDEEP | `3072:CW9ATwxm7sVKKV/Hi/8kboAuvI94MtOkG:1HKK9HiEkbopwSKOj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_a78278e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a78278e9b95b9eb162331dfd052b98752b6757a8991012f44a84efc25e9f49d1"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-30 21:27:51"
  condition:
    hash.sha256(0, filesize) == "a78278e9b95b9eb162331dfd052b98752b6757a8991012f44a84efc25e9f49d1"
}
```

### Sample 83: `db59dfafcc05be92`

| Field | Value |
|---|---|
| SHA-256 | `db59dfafcc05be928df94d060ffb1655613a412d4d292983b204b90d4b4cda60` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-30 21:24:02` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5120f1ed43a69f9c949ecf38f8d238ea` |
| SHA-1 | `7d618516975f3b3923f8702f486c47e6b8068270` |
| SHA-256 | `db59dfafcc05be928df94d060ffb1655613a412d4d292983b204b90d4b4cda60` |
| SHA3-384 | `da502e444e862aeba8146d31832114d70d5541ba9e160a4c7f7058261c459c5ce159f7970bbc88495d56051a6026967a` |
| TLSH | `T16F236C6516857C14AE98C4365C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:er9NyXsZztC99GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:oHusZXcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_db59dfaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db59dfafcc05be928df94d060ffb1655613a412d4d292983b204b90d4b4cda60"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-30 21:24:02"
  condition:
    hash.sha256(0, filesize) == "db59dfafcc05be928df94d060ffb1655613a412d4d292983b204b90d4b4cda60"
}
```

### Sample 84: `11738a5b45dfdddb`

| Field | Value |
|---|---|
| SHA-256 | `11738a5b45dfdddb7511c815bfb61ceb2841468846d0d6386429373b856e3d19` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-30 21:22:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `613d24ccb308f0a278793fb625087666` |
| SHA-1 | `1bae775778f93328558e170e22358049df022051` |
| SHA-256 | `11738a5b45dfdddb7511c815bfb61ceb2841468846d0d6386429373b856e3d19` |
| SHA3-384 | `20d763989c98ff7cca18348e325b48dd6e8fab1262df73886ba58af657599e568d20102dff2e5bfff78c305bf1feed64` |
| TLSH | `T193C27D956A867C44BDC98A3E4CBD2B0D6DF5C3D1324952AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:x8vCB+25j6es8R29FYpMSUpi+20qUpi+20YQX:x8l25Jgd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_11738a5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11738a5b45dfdddb7511c815bfb61ceb2841468846d0d6386429373b856e3d19"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-30 21:22:15"
  condition:
    hash.sha256(0, filesize) == "11738a5b45dfdddb7511c815bfb61ceb2841468846d0d6386429373b856e3d19"
}
```

### Sample 85: `37ead5a16a9a8630`

| Field | Value |
|---|---|
| SHA-256 | `37ead5a16a9a8630b74a38a740b71789a3c6d1a3205c4e21675cadd2af90b472` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-30 21:22:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7b9e4734c1f38d66e8668864412ee17` |
| SHA-1 | `fbb4b4b0143a6d6b8bd15af7b6c6bc606080fa95` |
| SHA-256 | `37ead5a16a9a8630b74a38a740b71789a3c6d1a3205c4e21675cadd2af90b472` |
| SHA3-384 | `5f35e1be52696252b1e212d8e26db1c3d6b0a02de2f1749df26056ad394a1116da83c23a8395d0f5bcf973af095897e1` |
| TLSH | `T13C143945BCA29A12C6C3427BFB4E428D771A635AD3DD3102FD2D6F203F8A46B4A77581` |
| TELFHASH | `t151e07d2ade350bc82f94d14380edd214ef66f4cf56080c5683dc3ed509d6ed6b00d002` |
| SSDEEP | `6144:rAvd4YoqXWFgL2KR4gObi6ZQD0fnHEssMOgh5oB:8vd4YoqXWSLlR4rG6VEssMOgh5oB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_37ead5a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37ead5a16a9a8630b74a38a740b71789a3c6d1a3205c4e21675cadd2af90b472"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-30 21:22:13"
  condition:
    hash.sha256(0, filesize) == "37ead5a16a9a8630b74a38a740b71789a3c6d1a3205c4e21675cadd2af90b472"
}
```

### Sample 86: `ed4337ee1b5174a6`

| Field | Value |
|---|---|
| SHA-256 | `ed4337ee1b5174a6f113dfbf60faaf9ca17e531422da5001baeaab0878ac54f6` |
| Family label | `unknown` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-30 21:18:09` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02768a302c685da2af72d1d788647fa9` |
| SHA-1 | `4ffe5588afc607e71d12b49ffe9d7f02154735c1` |
| SHA-256 | `ed4337ee1b5174a6f113dfbf60faaf9ca17e531422da5001baeaab0878ac54f6` |
| SHA3-384 | `2dc10f011e291ec8910383f483921d528538fdf3b53c129ea7e4e5a68369fc9c0e241dea4b603cd9be638f555c96cd0b` |
| TLSH | `T1B393021DD2D26BE5F9AC1637D13347982948CC4D70A8BF86652D7CBDA89C1F1DEA0E04` |
| SSDEEP | `1536:8phhJCO4urJKyn9Jx9a7v3FWBA/8CNLczxMnYj8P0HN2tu/pYlNCNb:8phLb4urJxnPx9a3v/3lnP0HN2tu/6XC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_ed4337ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed4337ee1b5174a6f113dfbf60faaf9ca17e531422da5001baeaab0878ac54f6"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-30 21:18:09"
  condition:
    hash.sha256(0, filesize) == "ed4337ee1b5174a6f113dfbf60faaf9ca17e531422da5001baeaab0878ac54f6"
}
```

### Sample 87: `2041194a6bb541b4`

| Field | Value |
|---|---|
| SHA-256 | `2041194a6bb541b47ebc24cef891b00eb19c21708188310c61e87c5ef11dde31` |
| Family label | `unknown` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-30 21:15:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58d79516430ce8c8cbfbbde9afd655c6` |
| SHA-1 | `30a8c3157609a2193fa501539f30044ef8970b9c` |
| SHA-256 | `2041194a6bb541b47ebc24cef891b00eb19c21708188310c61e87c5ef11dde31` |
| SHA3-384 | `4b22aa5dd4ccc3e466cf9afc4cac647543ade6ff2eca47fd9330e227bdae8696ca8ca8a43d623c41de43f555b59dc246` |
| TLSH | `T113C302C23253CF64C9A2C3784273179ACEE79F12DED2EB64CFDEA04C564D15934A9A12` |
| SSDEEP | `3072:BPAYiMotZqP5HbND7JfyuIDmnEDIU3CmSM8Dg:BxiJtodbND7JfJEDGmf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_2041194a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2041194a6bb541b47ebc24cef891b00eb19c21708188310c61e87c5ef11dde31"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-30 21:15:53"
  condition:
    hash.sha256(0, filesize) == "2041194a6bb541b47ebc24cef891b00eb19c21708188310c61e87c5ef11dde31"
}
```

### Sample 88: `d251f7a30d6b797b`

| Field | Value |
|---|---|
| SHA-256 | `d251f7a30d6b797b0e2edf2fd9d7c5e42272dcfc9495bb6a9ee9b62e97a6bf51` |
| Family label | `unknown` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-30 21:13:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfb0d7ad0bc697eac95ce58b987d7f2f` |
| SHA-1 | `c2f11d6d918f82e5d8188212fd26e97a16e9a61d` |
| SHA-256 | `d251f7a30d6b797b0e2edf2fd9d7c5e42272dcfc9495bb6a9ee9b62e97a6bf51` |
| SHA3-384 | `0f77af07bf8ed6f41af9748c051b574949b1a1c34a80d882ebd9c3fb8391dff372fd09a1e4a3e169e8f94b88af8d1b66` |
| TLSH | `T16893021AF3D38A84DC604636D8C3D704660FCD08B9A77B572590EC34BDA83FD892A94A` |
| SSDEEP | `1536:8pGuh4YhtOnxj7JyA4BNT4l+n+XiCwKUUtfS+zzMhSsajQ6lJYs8IgWb4h9:8pGueYfOnF7oh75JvItWQQ6Tf8Usn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_d251f7a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d251f7a30d6b797b0e2edf2fd9d7c5e42272dcfc9495bb6a9ee9b62e97a6bf51"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-30 21:13:51"
  condition:
    hash.sha256(0, filesize) == "d251f7a30d6b797b0e2edf2fd9d7c5e42272dcfc9495bb6a9ee9b62e97a6bf51"
}
```

### Sample 89: `f6fd816e3249cc67`

| Field | Value |
|---|---|
| SHA-256 | `f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f` |
| Family label | `Vidar` |
| File name | `f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f.bin` |
| File type | `exe` |
| First seen | `2026-08-30 21:10:34` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2090fc3b3823d9e5a00f2c825edced3` |
| SHA-1 | `3068607735aedf1dd0c020991765f3d5176f5873` |
| SHA-256 | `f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f` |
| SHA3-384 | `62cddfaa2674f48bd8421456ca16e3ab7beab02534d782190720917433bf369388f984899574d4035df3493758bfd904` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T156667C07B9A505E8C89AC634C87B6243B6B8BC8D4B3573D72E10B6343F7A7D89976704` |
| SSDEEP | `49152:xQRQDEAs+c9yhakwV5jXO79FZIWo/ECtlmOVr8gqnfrttOy6h5+8mlzwirpWWmRw:xq4iVrEnzt+jPWwir3cw` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_089_f6fd816e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f"
    family = "Vidar"
    file_name = "f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f.bin"
    file_type = "exe"
    first_seen = "2026-08-30 21:10:34"
  condition:
    hash.sha256(0, filesize) == "f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f"
}
```

### Sample 90: `1ec76c4d3be7c42c`

| Field | Value |
|---|---|
| SHA-256 | `1ec76c4d3be7c42c78a5b9358c49219035ec638b129b497dcb78bd7a983e6d46` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-30 21:09:48` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5982230a6fbe95212791b237c8fcb6a1` |
| SHA-256 | `1ec76c4d3be7c42c78a5b9358c49219035ec638b129b497dcb78bd7a983e6d46` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_1ec76c4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec76c4d3be7c42c78a5b9358c49219035ec638b129b497dcb78bd7a983e6d46"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-30 21:09:48"
  condition:
    hash.sha256(0, filesize) == "1ec76c4d3be7c42c78a5b9358c49219035ec638b129b497dcb78bd7a983e6d46"
}
```

### Sample 91: `ddd09fd60251050e`

| Field | Value |
|---|---|
| SHA-256 | `ddd09fd60251050ebb2fed85ead524c234f830301b85476da997249726e9a60e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-30 20:59:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2750f7078de11a56e20699892380a0a0` |
| SHA-1 | `811940bd950c2ca655d719c40bcb92ce66ae4bdb` |
| SHA-256 | `ddd09fd60251050ebb2fed85ead524c234f830301b85476da997249726e9a60e` |
| SHA3-384 | `b0054d7524e8560a7064577aab9955839e158035e8a99850bc79d9f808843c5d8e1054c1c0d0cc8924b7aa45950600d3` |
| TLSH | `T17CC26C966A867C44BEC94A3E4CBD2B0D6DF5C3D1324942AC3D9B3C719C11FACD618B1A` |
| SSDEEP | `768:U8vCB+25j6es8RD9FYpMSUpi+20qUpi+20YQX:U8l25JFd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_ddd09fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddd09fd60251050ebb2fed85ead524c234f830301b85476da997249726e9a60e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-30 20:59:42"
  condition:
    hash.sha256(0, filesize) == "ddd09fd60251050ebb2fed85ead524c234f830301b85476da997249726e9a60e"
}
```

### Sample 92: `0fe9ee5552f17321`

| Field | Value |
|---|---|
| SHA-256 | `0fe9ee5552f17321c41c44ac8196ecaf4fe0d8e97207545f70906c636dab033a` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-30 20:57:43` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7494195b09a7609d15bd6a2a262dc27` |
| SHA-256 | `0fe9ee5552f17321c41c44ac8196ecaf4fe0d8e97207545f70906c636dab033a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_0fe9ee55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fe9ee5552f17321c41c44ac8196ecaf4fe0d8e97207545f70906c636dab033a"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-30 20:57:43"
  condition:
    hash.sha256(0, filesize) == "0fe9ee5552f17321c41c44ac8196ecaf4fe0d8e97207545f70906c636dab033a"
}
```

### Sample 93: `d5c876aed3c43d53`

| Field | Value |
|---|---|
| SHA-256 | `d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765` |
| Family label | `Mirai` |
| File name | `d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765.elf` |
| File type | `elf` |
| First seen | `2026-08-30 20:57:15` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5076094a04a64e4da17ea09fc1c31896` |
| SHA-1 | `7c93576d3bdfb305c7f72e0aacda9431c11b6359` |
| SHA-256 | `d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765` |
| SHA3-384 | `cfe5b140518b14f1971802066429f025f9bfac8c8a5af94a15131abe96d32d26d8feb223fdf73b403047390d06e249a9` |
| TLSH | `T18094194853B5D3CFE264EEB023367ED68BA7463234E7B285314FBA6313B212445D9DA4` |
| SSDEEP | `6144:DozLsI3fJ0ea37cuD3rvO0Hxygm+2UXJaTmbZ:8z1vJ0Hg007M5smbZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_d5c876ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765"
    family = "Mirai"
    file_name = "d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765.elf"
    file_type = "elf"
    first_seen = "2026-08-30 20:57:15"
  condition:
    hash.sha256(0, filesize) == "d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765"
}
```

### Sample 94: `990079676b581861`

| Field | Value |
|---|---|
| SHA-256 | `990079676b58186129270525cc8661e3f512d72acc60f82ee86509433dd85038` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-08-30 20:52:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b869708f7b9d805d5c3f896cc1a90c5` |
| SHA-1 | `e28b50db5d20e7b7ab6763960dd2d4dcf5a6a1a9` |
| SHA-256 | `990079676b58186129270525cc8661e3f512d72acc60f82ee86509433dd85038` |
| SHA3-384 | `1b2be140269a7f2958502ce7d268507bc72a25b5e88138bb43942c7f84231ec1ecc558b7d3b90e700330fbb255c550d9` |
| TLSH | `T12AF35BC1A9A3E0F1E963497A437F931A9A32D4370219D911F72E68387F42150E7BB79C` |
| TELFHASH | `t1f8613af96e7e09e8b7909c02e64e1f226d0d677b106032f605b2843532bfd8645bbc38` |
| SSDEEP | `3072:kBDKQrWzHEgIoa91oy/WIrn2wPtvbu1EssMZc/T03ImIys61X1h5ohek:6KQrAHprIr2AtvgEssMOgh5ohek` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_99007967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "990079676b58186129270525cc8661e3f512d72acc60f82ee86509433dd85038"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-30 20:52:04"
  condition:
    hash.sha256(0, filesize) == "990079676b58186129270525cc8661e3f512d72acc60f82ee86509433dd85038"
}
```

### Sample 95: `151ac96b0cd25d55`

| Field | Value |
|---|---|
| SHA-256 | `151ac96b0cd25d554866cfa5f4c8b2a7eb6c7dee85874c0966388ab3cd11ed22` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-30 20:48:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2415f3d1bc9fe8a1d55f2171cd57826d` |
| SHA-1 | `e22992523438bfbe81fefb10fdf7afbf3a867747` |
| SHA-256 | `151ac96b0cd25d554866cfa5f4c8b2a7eb6c7dee85874c0966388ab3cd11ed22` |
| SHA3-384 | `d0b0e51543323d0b0828199830c3496493c654b390f620c093c7752ebcb0216dd44c4dba22b40a5eb18365590208b24b` |
| TLSH | `T168A329917CE3A256C6D3463FFB8F920933126297C3CD7522FC0D5A642F8A11B86B69D1` |
| TELFHASH | `t1b0f0c041fd388a144ae27a70ec6803a585134613612287248f58c9d0cc3e00ab248d1d` |
| SSDEEP | `3072:UbHm9S+CRULh9mKpgFabzYIFu1EssMZc/T03ImIys61X1h5o:8r+CRULh9mVFagIWEssMOgh5o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_151ac96b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "151ac96b0cd25d554866cfa5f4c8b2a7eb6c7dee85874c0966388ab3cd11ed22"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-30 20:48:29"
  condition:
    hash.sha256(0, filesize) == "151ac96b0cd25d554866cfa5f4c8b2a7eb6c7dee85874c0966388ab3cd11ed22"
}
```

### Sample 96: `c327c09546c35128`

| Field | Value |
|---|---|
| SHA-256 | `c327c09546c35128f7fa873955bf6df7b3ecd45f308db8895f7f256a1aaec7ec` |
| Family label | `unknown` |
| File name | `ano70jf_pw_infected.zip` |
| File type | `zip` |
| First seen | `2026-08-30 20:42:42` |
| Reporter | `01EG` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab1c390ffd452108d807f6d79ef702c6` |
| SHA-256 | `c327c09546c35128f7fa873955bf6df7b3ecd45f308db8895f7f256a1aaec7ec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_c327c095
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c327c09546c35128f7fa873955bf6df7b3ecd45f308db8895f7f256a1aaec7ec"
    family = "unknown"
    file_name = "ano70jf_pw_infected.zip"
    file_type = "zip"
    first_seen = "2026-08-30 20:42:42"
  condition:
    hash.sha256(0, filesize) == "c327c09546c35128f7fa873955bf6df7b3ecd45f308db8895f7f256a1aaec7ec"
}
```

### Sample 97: `b95e693c051c1c73`

| Field | Value |
|---|---|
| SHA-256 | `b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-30 20:42:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39b6f697bcff4a61074c970c9fffb650` |
| SHA-1 | `e23c893be9c3cd27cc8edbae1b5982af3acb759a` |
| SHA-256 | `b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa` |
| SHA3-384 | `607aa37d25d51070f2c33b46d545aa7743bff8c54957db9b850f07bfdf61dab387700b55c959e515b779a3752a7bc591` |
| TLSH | `T14E144A02776D0403D3632DF43B3B53D1939BE49321A4F604790FAA995FB2832A696DDE` |
| SSDEEP | `3072:n/4c5So3SxcLP65tEADrrcTrlu1EssMZc/T03ImIys61X1h5oOH:n/p5SoCxsP65tlDXcTr2EssMOgh5oOH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_b95e693c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-30 20:42:04"
  condition:
    hash.sha256(0, filesize) == "b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa"
}
```

### Sample 98: `ba5b5e1cedf641a8`

| Field | Value |
|---|---|
| SHA-256 | `ba5b5e1cedf641a8c3281e631a2034b5e4ab4f0153dafead21d76164ed717d5b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-30 20:41:46` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `839665340cf40011310ec433d660a415` |
| SHA-1 | `12b19cdc956d4defb4566bc1d053e988542d94f8` |
| SHA-256 | `ba5b5e1cedf641a8c3281e631a2034b5e4ab4f0153dafead21d76164ed717d5b` |
| SHA3-384 | `6812b8209fdd3d43d0e88d037557e3a846938f5ba44b76dfa97f5fe5bc830f451e5cfe477ed4dd1be431a9391e86d5fb` |
| IMPHASH | `acb06808db35753dd3fb41d8c2e2f63b` |
| TLSH | `T1A6E423F24659E671C50DC8F9B39B0ACAF631E960C5644987F17134B917A0FE2D3862CE` |
| SSDEEP | `12288:4R95HDpfcNpg5Tz/buAsrzOoKuWtcQhx5avWPLBTXggy:QWg5Tz/b4yhcvWDBTXg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_ba5b5e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba5b5e1cedf641a8c3281e631a2034b5e4ab4f0153dafead21d76164ed717d5b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-30 20:41:46"
  condition:
    hash.sha256(0, filesize) == "ba5b5e1cedf641a8c3281e631a2034b5e4ab4f0153dafead21d76164ed717d5b"
}
```

### Sample 99: `e240ed6f9c39ce9f`

| Field | Value |
|---|---|
| SHA-256 | `e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512` |
| Family label | `unknown` |
| File name | `e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512.bin` |
| File type | `exe` |
| First seen | `2026-08-30 20:40:25` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33160626867482534091e219b1e22d62` |
| SHA-1 | `f9a18724c92ef1ec6b98e743806fec7364300261` |
| SHA-256 | `e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512` |
| SHA3-384 | `6f9662355ab1e32a748c049f9e3f3ade7a0504ec5be4965d3e03a7409bbab9c6cb7300ff0305a807f11ad5c6610fffe1` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T135283307B9C455A0C49AD135D2792722FA74BC8CCB32B7D71E58AAB11E363D8AF31748` |
| GIMPHASH | `32c6a2d884e480483c28cd54720853348165c67cabb74a425d39b5c3fc53fb72` |
| SSDEEP | `1572864:5QRUkrdsm9DQlcuZLp12Au+6gp/TFaFsop65nWj9I0IQay0UFZWD9+6q:qRUG2+uu+6i/AsoAxG1ay0Uj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_e240ed6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512"
    family = "unknown"
    file_name = "e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512.bin"
    file_type = "exe"
    first_seen = "2026-08-30 20:40:25"
  condition:
    hash.sha256(0, filesize) == "e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512"
}
```

### Sample 100: `d0d1bbcd8900f190`

| Field | Value |
|---|---|
| SHA-256 | `d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f` |
| Family label | `Mirai` |
| File name | `d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f.elf` |
| File type | `elf` |
| First seen | `2026-08-30 20:37:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9551b568b04946d9154e1f0fe5cb9555` |
| SHA-1 | `d436cea984ec1dde402e5a118ba8ff2ffa683552` |
| SHA-256 | `d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f` |
| SHA3-384 | `8510ab03754b67c7199eb5fdd9dce98708d496b753c9c5be06c62cdfdd181fb088d279b32ed95f1e644a51b8fdd8163c` |
| TLSH | `T1F5B4F84CA7F19FEFE09ADE3712642E07289D512731973B66717DEA22725B14A09E3C30` |
| SSDEEP | `6144:5DElNuO9MXg83sIQVcx7c9NmB0oGSOj2a9u61D:5DElNuO9MXg83I+Bc9mY2a9uSD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_d0d1bbcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f"
    family = "Mirai"
    file_name = "d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f.elf"
    file_type = "elf"
    first_seen = "2026-08-30 20:37:14"
  condition:
    hash.sha256(0, filesize) == "d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f"
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
 * Generated: 2026-08-31T05:45:32.700995+00:00
 */

rule MalwareBazaar_unknown_001_f0d8b637
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d8b637f964d937fb1d843226272938bdd34cda8ba957a01c029bde06505955"
    family = "unknown"
    file_name = "setup_z8.0.05.exe"
    file_type = "exe"
    first_seen = "2026-08-31 05:45:22"
  condition:
    hash.sha256(0, filesize) == "f0d8b637f964d937fb1d843226272938bdd34cda8ba957a01c029bde06505955"
}

rule MalwareBazaar_AgentTesla_002_4851063c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4851063cf8c55d16c4c77d107653c3edb5c35a0517a6558c769a594e4cf85e0c"
    family = "AgentTesla"
    file_name = "cotización#especificaciones.exe"
    file_type = "exe"
    first_seen = "2026-08-31 04:17:04"
  condition:
    hash.sha256(0, filesize) == "4851063cf8c55d16c4c77d107653c3edb5c35a0517a6558c769a594e4cf85e0c"
}

rule MalwareBazaar_unknown_003_a8ff87ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8ff87ec07958c46ce45c043befab7efb6bc340868e8431d1b8e0295a103f462"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 04:15:55"
  condition:
    hash.sha256(0, filesize) == "a8ff87ec07958c46ce45c043befab7efb6bc340868e8431d1b8e0295a103f462"
}

rule MalwareBazaar_Mirai_004_6f518952
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-31 04:15:53"
  condition:
    hash.sha256(0, filesize) == "6f518952f4f490993c223f25892dc70f35467c20aaffead61113de95161a78d4"
}

rule MalwareBazaar_Mirai_005_27d5eba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27d5eba8a5c023a6fecaeb6ec905c99fc0f0a305c52e2f977cf04127c2a09d71"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-31 04:01:55"
  condition:
    hash.sha256(0, filesize) == "27d5eba8a5c023a6fecaeb6ec905c99fc0f0a305c52e2f977cf04127c2a09d71"
}

rule MalwareBazaar_unknown_006_7c6fb00e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c6fb00ee9f06f43dc1ae36c1cfe3b6d69155aa346272a153a43ad626a883302"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 04:01:53"
  condition:
    hash.sha256(0, filesize) == "7c6fb00ee9f06f43dc1ae36c1cfe3b6d69155aa346272a153a43ad626a883302"
}

rule MalwareBazaar_Mirai_007_a2e59830
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-31 03:53:52"
  condition:
    hash.sha256(0, filesize) == "a2e5983090f76e9686379b266af0aa237973d0f4705dcb09806356da4b6ae142"
}

rule MalwareBazaar_Mirai_008_eb55e38d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb55e38de8ed4cd753ae895d232f9a0d6967eeafc726518e1c33b1b2acb18b82"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-31 03:53:51"
  condition:
    hash.sha256(0, filesize) == "eb55e38de8ed4cd753ae895d232f9a0d6967eeafc726518e1c33b1b2acb18b82"
}

rule MalwareBazaar_Mirai_009_eef5d0de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eef5d0dea6356bf0b05852eca3cefd3fdb87b06ebff7578496a2824f966ca4e8"
    family = "Mirai"
    file_name = "persist.arm7"
    file_type = "elf"
    first_seen = "2026-08-31 03:51:43"
  condition:
    hash.sha256(0, filesize) == "eef5d0dea6356bf0b05852eca3cefd3fdb87b06ebff7578496a2824f966ca4e8"
}

rule MalwareBazaar_Mirai_010_d945cf40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d945cf407650717fb6a880b8fda9f5daa623c33a5efb08cbed5ea01c9346131d"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-31 03:49:42"
  condition:
    hash.sha256(0, filesize) == "d945cf407650717fb6a880b8fda9f5daa623c33a5efb08cbed5ea01c9346131d"
}

rule MalwareBazaar_unknown_011_5c7357a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c7357a1261582b7a2d796dd7b5d2ff76a9dc0c70995edf91c06433701d20d1e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 03:45:50"
  condition:
    hash.sha256(0, filesize) == "5c7357a1261582b7a2d796dd7b5d2ff76a9dc0c70995edf91c06433701d20d1e"
}

rule MalwareBazaar_Mirai_012_00be60c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00be60c5d656295d0f3ab32d1f07967dd9c3294cb64fb57a9dc93c97f5224f59"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-31 03:43:42"
  condition:
    hash.sha256(0, filesize) == "00be60c5d656295d0f3ab32d1f07967dd9c3294cb64fb57a9dc93c97f5224f59"
}

rule MalwareBazaar_unknown_013_e46d5e32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0"
    family = "unknown"
    file_name = "e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0.raw"
    file_type = "zip"
    first_seen = "2026-08-31 03:42:42"
  condition:
    hash.sha256(0, filesize) == "e46d5e3237a7b339440dd7f005be4b77be4584749816bf64b0b3485e00862fd0"
}

rule MalwareBazaar_Mirai_014_f8208c93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf"
    family = "Mirai"
    file_name = "f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf.elf"
    file_type = "elf"
    first_seen = "2026-08-31 03:36:44"
  condition:
    hash.sha256(0, filesize) == "f8208c93d9bfc7186b29f86c3aa70056a33e0e8b8e0e4163f4bf6872fdac28cf"
}

rule MalwareBazaar_Mirai_015_511fe461
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "511fe46150f3e39ba1bcb08cfc09d27da85f61805e08a17e84f356c4a107a903"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-31 03:35:50"
  condition:
    hash.sha256(0, filesize) == "511fe46150f3e39ba1bcb08cfc09d27da85f61805e08a17e84f356c4a107a903"
}

rule MalwareBazaar_unknown_016_e2982ce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2982ce93a162c03f9e826b13cb98a4b62410d931dd0312881d8f5579da7c8f9"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-31 03:27:49"
  condition:
    hash.sha256(0, filesize) == "e2982ce93a162c03f9e826b13cb98a4b62410d931dd0312881d8f5579da7c8f9"
}

rule MalwareBazaar_Mirai_017_985a0ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "985a0ccc6ee392a1ec2cbe1f00d4f467636a80ce9e6bc1f9343efdcee2150b66"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-31 03:21:47"
  condition:
    hash.sha256(0, filesize) == "985a0ccc6ee392a1ec2cbe1f00d4f467636a80ce9e6bc1f9343efdcee2150b66"
}

rule MalwareBazaar_Mirai_018_844553c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "844553c171f4a953bed4ce34c94bc373b5a41a0dfbec71e137534c827573f34b"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-31 03:19:57"
  condition:
    hash.sha256(0, filesize) == "844553c171f4a953bed4ce34c94bc373b5a41a0dfbec71e137534c827573f34b"
}

rule MalwareBazaar_unknown_019_32130248
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "321302480883589241e6a4df24e3df3455a769c1f032a51ea1ff59a3cba858c1"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-31 03:03:14"
  condition:
    hash.sha256(0, filesize) == "321302480883589241e6a4df24e3df3455a769c1f032a51ea1ff59a3cba858c1"
}

rule MalwareBazaar_Mirai_020_5c81b382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c81b3827e80082d7fbbd9e82831a0ae31eb2ee4b97cb1b6730a95e6aa68c122"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-31 03:00:54"
  condition:
    hash.sha256(0, filesize) == "5c81b3827e80082d7fbbd9e82831a0ae31eb2ee4b97cb1b6730a95e6aa68c122"
}

rule MalwareBazaar_unknown_021_85dbd885
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85dbd88525d794060217730b5f22475de4b2eb18d45642bed42104945166a00e"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-31 02:54:49"
  condition:
    hash.sha256(0, filesize) == "85dbd88525d794060217730b5f22475de4b2eb18d45642bed42104945166a00e"
}

rule MalwareBazaar_Mirai_022_59e44261
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e4426161024da7af4b9755f2bf861bb8850b4469e9f00c8f7c15f4f18e9eb7"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-31 02:50:59"
  condition:
    hash.sha256(0, filesize) == "59e4426161024da7af4b9755f2bf861bb8850b4469e9f00c8f7c15f4f18e9eb7"
}

rule MalwareBazaar_Mirai_023_41792492
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41792492f011594491d180b1bfbed002f07a60e9697558b1a13e00176f9f4611"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-31 02:44:57"
  condition:
    hash.sha256(0, filesize) == "41792492f011594491d180b1bfbed002f07a60e9697558b1a13e00176f9f4611"
}

rule MalwareBazaar_Mirai_024_76520a25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76520a25a234a651c1f60c4ed7e0c2840e41e50604f7ceb80fed3079a003e97b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-31 02:38:49"
  condition:
    hash.sha256(0, filesize) == "76520a25a234a651c1f60c4ed7e0c2840e41e50604f7ceb80fed3079a003e97b"
}

rule MalwareBazaar_RemcosRAT_025_011622e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011622e016f8dd26ea72849f3181882cc1bab3d72cc43e847936703fcd436bba"
    family = "RemcosRAT"
    file_name = "Maxima_International_Sourcing.bat"
    file_type = "bat"
    first_seen = "2026-08-31 02:31:30"
  condition:
    hash.sha256(0, filesize) == "011622e016f8dd26ea72849f3181882cc1bab3d72cc43e847936703fcd436bba"
}

rule MalwareBazaar_Prometei_026_31981007
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51"
    family = "Prometei"
    file_name = "319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51"
    file_type = "elf"
    first_seen = "2026-08-31 01:40:33"
  condition:
    hash.sha256(0, filesize) == "319810073cff23bf40e305a5ba17c7c82b01488f901a6457f6f600d94c65bc51"
}

rule MalwareBazaar_Prometei_027_4d28296e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7"
    family = "Prometei"
    file_name = "4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7"
    file_type = "exe"
    first_seen = "2026-08-31 01:39:38"
  condition:
    hash.sha256(0, filesize) == "4d28296e8ff7f9616997a465ac85b13399bf398fb561431e0ff5a740cb7fd3c7"
}

rule MalwareBazaar_unknown_028_1b19bd93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd"
    family = "unknown"
    file_name = "1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd.bin"
    file_type = "exe"
    first_seen = "2026-08-31 01:12:40"
  condition:
    hash.sha256(0, filesize) == "1b19bd93bc95ba908f8d13cf9e7e69776d2d82722f325d9290550aed155e56bd"
}

rule MalwareBazaar_Mirai_029_9fe7400e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fe7400eb83237517f23e172d4e708b6744bf4b68ab1d1f0d21473581575a96c"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-31 00:58:57"
  condition:
    hash.sha256(0, filesize) == "9fe7400eb83237517f23e172d4e708b6744bf4b68ab1d1f0d21473581575a96c"
}

rule MalwareBazaar_ValleyRAT_030_6c347349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c34734992fedeae18ca6796175a7d5e366db61b096afb2a40a51a500ac3e39f"
    family = "ValleyRAT"
    file_name = "52C6A290E9CE70AC61B7F924CA5775AF.dll"
    file_type = "dll"
    first_seen = "2026-08-31 00:55:08"
  condition:
    hash.sha256(0, filesize) == "6c34734992fedeae18ca6796175a7d5e366db61b096afb2a40a51a500ac3e39f"
}

rule MalwareBazaar_unknown_031_ec2bc485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa"
    family = "unknown"
    file_name = "ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa.bin"
    file_type = "exe"
    first_seen = "2026-08-31 00:41:00"
  condition:
    hash.sha256(0, filesize) == "ec2bc48545806557a546855b94bafa55138ab603771290268e0fcbc5f72de6aa"
}

rule MalwareBazaar_unknown_032_d7934bfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336"
    family = "unknown"
    file_name = "d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336.bin"
    file_type = "exe"
    first_seen = "2026-08-31 00:19:53"
  condition:
    hash.sha256(0, filesize) == "d7934bfa4e1d52ff336ddc7ee231f206a1eb1ac286e5dd74e5d13ea12f824336"
}

rule MalwareBazaar_unknown_033_8724ae95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac"
    family = "unknown"
    file_name = "8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac.bin"
    file_type = "exe"
    first_seen = "2026-08-31 00:19:50"
  condition:
    hash.sha256(0, filesize) == "8724ae953b9d69c4d5dc13713f842a7c22257e97ada5df87e8409f1433e57dac"
}

rule MalwareBazaar_AsyncRAT_034_9109d9bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d"
    family = "AsyncRAT"
    file_name = "132.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:43:01"
  condition:
    hash.sha256(0, filesize) == "9109d9bd117f540aed9afa6f293c1396cc18ed979056eadca97c69e3f957c14d"
}

rule MalwareBazaar_unknown_035_bf8c5ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf8c5ad334c9b4a8dfb7eab8e33e4869e275ababc2f042efa74fe4514ba9eb26"
    family = "unknown"
    file_name = "13.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:43:01"
  condition:
    hash.sha256(0, filesize) == "bf8c5ad334c9b4a8dfb7eab8e33e4869e275ababc2f042efa74fe4514ba9eb26"
}

rule MalwareBazaar_AsyncRAT_036_f6f7dbd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f"
    family = "AsyncRAT"
    file_name = "cs2.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:43:01"
  condition:
    hash.sha256(0, filesize) == "f6f7dbd6561e7ee6ba7e6abffdb1e5de01bf511318aade34825d888e99db645f"
}

rule MalwareBazaar_unknown_037_76de6f8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd"
    family = "unknown"
    file_name = "76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd.bin"
    file_type = "exe"
    first_seen = "2026-08-30 23:40:46"
  condition:
    hash.sha256(0, filesize) == "76de6f8ba8cd0a7812d65b7810c799f152012671ed4e4118faa660c07a9662cd"
}

rule MalwareBazaar_Vidar_038_648e823a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa"
    family = "Vidar"
    file_name = "648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa.bin"
    file_type = "exe"
    first_seen = "2026-08-30 23:40:43"
  condition:
    hash.sha256(0, filesize) == "648e823a9408a715f9fe83bdd467efc4c3382c4d299fd8db380e5f00f88c9eaa"
}

rule MalwareBazaar_unknown_039_aebe2aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245"
    family = "unknown"
    file_name = "aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245.bin"
    file_type = "exe"
    first_seen = "2026-08-30 23:40:41"
  condition:
    hash.sha256(0, filesize) == "aebe2aad890a1ac75492bf2d698269870de3f775813ca806b9b8324343919245"
}

rule MalwareBazaar_unknown_040_21bfcedf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21bfcedfb79ec8427ad3d766b66997983a2910d05164773159263b52a5cd6317"
    family = "unknown"
    file_name = "192.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:36:39"
  condition:
    hash.sha256(0, filesize) == "21bfcedfb79ec8427ad3d766b66997983a2910d05164773159263b52a5cd6317"
}

rule MalwareBazaar_AsyncRAT_041_3610fcc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1"
    family = "AsyncRAT"
    file_name = "118.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:30:37"
  condition:
    hash.sha256(0, filesize) == "3610fcc54a204281b09095004f02b674cd75bdd83996a1428fdef85645eff3e1"
}

rule MalwareBazaar_VenomRAT_042_9b1d38cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1d38cd728ec1a478db668e86f7445ab5f0335b388feefc15502931cdcad704"
    family = "VenomRAT"
    file_name = "103.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:30:36"
  condition:
    hash.sha256(0, filesize) == "9b1d38cd728ec1a478db668e86f7445ab5f0335b388feefc15502931cdcad704"
}

rule MalwareBazaar_VenomRAT_043_f959a849
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f959a8494f2a1c4e11f346ae8e3099593f156be2a5c8010d1747e4466a11316a"
    family = "VenomRAT"
    file_name = "192.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:30:36"
  condition:
    hash.sha256(0, filesize) == "f959a8494f2a1c4e11f346ae8e3099593f156be2a5c8010d1747e4466a11316a"
}

rule MalwareBazaar_unknown_044_bfd24149
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfd241497d87b72e6ca63d3c51f904c66890684cef0e14c11680eb5d0633f260"
    family = "unknown"
    file_name = "s.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:23:44"
  condition:
    hash.sha256(0, filesize) == "bfd241497d87b72e6ca63d3c51f904c66890684cef0e14c11680eb5d0633f260"
}

rule MalwareBazaar_AdaptixC2_045_1dc1f5d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dc1f5d8863e2f4d6105a47e6aa11428668c9c604b3c55247e2bce376bdd5724"
    family = "AdaptixC2"
    file_name = "agent.x64.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:22:39"
  condition:
    hash.sha256(0, filesize) == "1dc1f5d8863e2f4d6105a47e6aa11428668c9c604b3c55247e2bce376bdd5724"
}

rule MalwareBazaar_RemusStealer_046_71cdf126
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71cdf126636c50a3a2b71fa730ddc3f3ab03791a35a70aa774de8652ca96a174"
    family = "RemusStealer"
    file_name = "main.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:20:34"
  condition:
    hash.sha256(0, filesize) == "71cdf126636c50a3a2b71fa730ddc3f3ab03791a35a70aa774de8652ca96a174"
}

rule MalwareBazaar_unknown_047_3bc5b246
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bc5b2464c55aab2b5b9d7e6c646130dea5d863f8d6631b5d5fe2f23c6f73b61"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-08-30 23:18:24"
  condition:
    hash.sha256(0, filesize) == "3bc5b2464c55aab2b5b9d7e6c646130dea5d863f8d6631b5d5fe2f23c6f73b61"
}

rule MalwareBazaar_unknown_048_d931dd41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d931dd41445159d939376b4ee6c6023bf49ba6599d9191006fdb8d99c71c410a"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-08-30 23:17:44"
  condition:
    hash.sha256(0, filesize) == "d931dd41445159d939376b4ee6c6023bf49ba6599d9191006fdb8d99c71c410a"
}

rule MalwareBazaar_unknown_049_eb409a50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb409a50a259b298dc166799c99e51d59a253a7377a354e5a7c3d1cfb5ebcaaa"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-08-30 23:15:26"
  condition:
    hash.sha256(0, filesize) == "eb409a50a259b298dc166799c99e51d59a253a7377a354e5a7c3d1cfb5ebcaaa"
}

rule MalwareBazaar_ConnectWise_050_d9b69fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9b69fe371aa57cbe7b0e4b9221902cb207f7150693976a97beb8e59115c365a"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:13:41"
  condition:
    hash.sha256(0, filesize) == "d9b69fe371aa57cbe7b0e4b9221902cb207f7150693976a97beb8e59115c365a"
}

rule MalwareBazaar_ConnectWise_051_51f18fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51f18fc444ca9660bfdb73fe2f59007f932e743283f590e174308bfe4c34f55f"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-30 23:13:39"
  condition:
    hash.sha256(0, filesize) == "51f18fc444ca9660bfdb73fe2f59007f932e743283f590e174308bfe4c34f55f"
}

rule MalwareBazaar_Mirai_052_e7dd64db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7dd64dbda89025ae8f155705b437c6a41fcc7e8616b11f5ebc955bb48c2acaa"
    family = "Mirai"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-08-30 23:13:28"
  condition:
    hash.sha256(0, filesize) == "e7dd64dbda89025ae8f155705b437c6a41fcc7e8616b11f5ebc955bb48c2acaa"
}

rule MalwareBazaar_Mirai_053_13ef56ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13ef56abdc373ffa0761004b7c2d680f6d06b15d761642cc5538bafd8560d826"
    family = "Mirai"
    file_name = "mirai.sh4"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:23"
  condition:
    hash.sha256(0, filesize) == "13ef56abdc373ffa0761004b7c2d680f6d06b15d761642cc5538bafd8560d826"
}

rule MalwareBazaar_Mirai_054_9b8f75b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b8f75b3758536e5b79092411b979e5a9617e8f04f1c60f000cb99d603b46134"
    family = "Mirai"
    file_name = "mirai.spc"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:22"
  condition:
    hash.sha256(0, filesize) == "9b8f75b3758536e5b79092411b979e5a9617e8f04f1c60f000cb99d603b46134"
}

rule MalwareBazaar_Mirai_055_1b647683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:21"
  condition:
    hash.sha256(0, filesize) == "1b647683b7fc5ee58b643bea788b28f03b236791e5737ab41896f6c15c32cc01"
}

rule MalwareBazaar_Mirai_056_9b717d71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01"
    family = "Mirai"
    file_name = "mirai.ppc"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:21"
  condition:
    hash.sha256(0, filesize) == "9b717d713836c386fd57e786ff5ea94b51216d1f588452a1866d6f66f7e9ba01"
}

rule MalwareBazaar_Mirai_057_0781d164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a"
    family = "Mirai"
    file_name = "mirai.mpsl"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:20"
  condition:
    hash.sha256(0, filesize) == "0781d164ad718340e5a359c13527d75f55c8d01150f514cb0a7c05cff35f766a"
}

rule MalwareBazaar_Mirai_058_d3326ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d"
    family = "Mirai"
    file_name = "mirai.arm7"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:20"
  condition:
    hash.sha256(0, filesize) == "d3326ec9bb37c8bcb65ffcf639d51ffdc0628804eb974b86bc9f14c1dd2a2c4d"
}

rule MalwareBazaar_Mirai_059_6492bc2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6492bc2bfaa40a1a4c783fde77be26cd0381038f13deacce833ae84a6dbc5712"
    family = "Mirai"
    file_name = "mirai.arm"
    file_type = "elf"
    first_seen = "2026-08-30 23:13:19"
  condition:
    hash.sha256(0, filesize) == "6492bc2bfaa40a1a4c783fde77be26cd0381038f13deacce833ae84a6dbc5712"
}

rule MalwareBazaar_unknown_060_4b6c5c2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea"
    family = "unknown"
    file_name = "4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea"
    file_type = "sh"
    first_seen = "2026-08-30 23:00:12"
  condition:
    hash.sha256(0, filesize) == "4b6c5c2d773b5d4b9483a20098faf68cbbc552ab477fbb7d5734409dd78f52ea"
}

rule MalwareBazaar_unknown_061_580f3118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8"
    family = "unknown"
    file_name = "580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8"
    file_type = "sh"
    first_seen = "2026-08-30 22:30:20"
  condition:
    hash.sha256(0, filesize) == "580f311847643ec21215c3a29d54dc4b3e35656c13ab066b79666e6561e5b0c8"
}

rule MalwareBazaar_Mirai_062_cae1cce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae1cce3f601c297e9eb531df55a9d864605e383fafe3509fee0f2a99b25348e"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-30 22:27:50"
  condition:
    hash.sha256(0, filesize) == "cae1cce3f601c297e9eb531df55a9d864605e383fafe3509fee0f2a99b25348e"
}

rule MalwareBazaar_unknown_063_f6f310bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6f310bb98d6718154b3962c89bc779a28d2b7f6afe4170e89229ed4aaff88ca"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-08-30 22:27:48"
  condition:
    hash.sha256(0, filesize) == "f6f310bb98d6718154b3962c89bc779a28d2b7f6afe4170e89229ed4aaff88ca"
}

rule MalwareBazaar_Mirai_064_c2d2b1e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d2b1e3e9c82a7a2cf99e1484fbc8c2b25f06a49efb7e3e3c7c63dbf347d9ca"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-30 22:27:46"
  condition:
    hash.sha256(0, filesize) == "c2d2b1e3e9c82a7a2cf99e1484fbc8c2b25f06a49efb7e3e3c7c63dbf347d9ca"
}

rule MalwareBazaar_unknown_065_ec5c7ff6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a"
    family = "unknown"
    file_name = "ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a.exe"
    file_type = "exe"
    first_seen = "2026-08-30 22:26:48"
  condition:
    hash.sha256(0, filesize) == "ec5c7ff617a8f5325aaee45688d9a8c8a564f28ef900a2f564909ff1f5395a9a"
}

rule MalwareBazaar_unknown_066_b82adccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b82adccfc4f2c3e4c4bf6b14e2c080435e6578bf6449aeefa16a66698f736a3f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-30 22:14:59"
  condition:
    hash.sha256(0, filesize) == "b82adccfc4f2c3e4c4bf6b14e2c080435e6578bf6449aeefa16a66698f736a3f"
}

rule MalwareBazaar_Mirai_067_d683b763
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d683b763682b08127a52d049509ac0e861fe21bc54fb73eeb1841b854e6bf2a7"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-30 22:03:18"
  condition:
    hash.sha256(0, filesize) == "d683b763682b08127a52d049509ac0e861fe21bc54fb73eeb1841b854e6bf2a7"
}

rule MalwareBazaar_Mirai_068_713cfb58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "713cfb58fc152e5369f7e51d177223b69dfca974e0ee2064a9f8a794393d31ff"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-30 22:00:52"
  condition:
    hash.sha256(0, filesize) == "713cfb58fc152e5369f7e51d177223b69dfca974e0ee2064a9f8a794393d31ff"
}

rule MalwareBazaar_Mirai_069_37866385
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "378663855be020f0c4bdf6e45c802ad721e6516c0b59fbfef8e5feaff4f42d9b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-30 21:56:56"
  condition:
    hash.sha256(0, filesize) == "378663855be020f0c4bdf6e45c802ad721e6516c0b59fbfef8e5feaff4f42d9b"
}

rule MalwareBazaar_unknown_070_348fb16a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "348fb16af9b191747359553b9b995b82fff2dda2f4d3ecaff280080f3d6177e6"
    family = "unknown"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-30 21:56:54"
  condition:
    hash.sha256(0, filesize) == "348fb16af9b191747359553b9b995b82fff2dda2f4d3ecaff280080f3d6177e6"
}

rule MalwareBazaar_Mirai_071_b3caa2e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3caa2e3d0c88a3872e1102f356fc665678b150e05a511412dc613ae04a118a9"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-30 21:56:53"
  condition:
    hash.sha256(0, filesize) == "b3caa2e3d0c88a3872e1102f356fc665678b150e05a511412dc613ae04a118a9"
}

rule MalwareBazaar_unknown_072_c2a669ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2a669ab6504a18b47c6f493efc899e47f29a9605a6b1df0b21cbf78ef1eb73b"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-30 21:50:56"
  condition:
    hash.sha256(0, filesize) == "c2a669ab6504a18b47c6f493efc899e47f29a9605a6b1df0b21cbf78ef1eb73b"
}

rule MalwareBazaar_unknown_073_b33121f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b33121f5f6866196079651fcabc4fcf1998944578846eb83e557f3128ed4c867"
    family = "unknown"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-30 21:50:54"
  condition:
    hash.sha256(0, filesize) == "b33121f5f6866196079651fcabc4fcf1998944578846eb83e557f3128ed4c867"
}

rule MalwareBazaar_unknown_074_f2bbb1db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2bbb1db345b0b4a70ac285c77d6368d3e6294cf79418a10c47749711c7b93af"
    family = "unknown"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-30 21:41:59"
  condition:
    hash.sha256(0, filesize) == "f2bbb1db345b0b4a70ac285c77d6368d3e6294cf79418a10c47749711c7b93af"
}

rule MalwareBazaar_unknown_075_0afe5306
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0afe53066fa700377a69d22c264f76761b8fb289308abfde8bf4fac7b0182111"
    family = "unknown"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-30 21:39:55"
  condition:
    hash.sha256(0, filesize) == "0afe53066fa700377a69d22c264f76761b8fb289308abfde8bf4fac7b0182111"
}

rule MalwareBazaar_unknown_076_38fe0a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38fe0a93c3da436976dd0e96f70e228107508fc26bd612c90ad643238e72fe56"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-30 21:37:56"
  condition:
    hash.sha256(0, filesize) == "38fe0a93c3da436976dd0e96f70e228107508fc26bd612c90ad643238e72fe56"
}

rule MalwareBazaar_Mirai_077_040fe79a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "040fe79af10373a4a2680b5fbfd439dc7afca68c0bf9bc12144a4e9e33430292"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-30 21:37:55"
  condition:
    hash.sha256(0, filesize) == "040fe79af10373a4a2680b5fbfd439dc7afca68c0bf9bc12144a4e9e33430292"
}

rule MalwareBazaar_Mirai_078_7209e154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7209e154bd93a9cdd455902b3c3e412f2024e9f0ddb83fc0b180c4af2d8adf67"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-30 21:35:54"
  condition:
    hash.sha256(0, filesize) == "7209e154bd93a9cdd455902b3c3e412f2024e9f0ddb83fc0b180c4af2d8adf67"
}

rule MalwareBazaar_unknown_079_cd8a4747
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd8a4747ca552e4ce1b1bd86249a068f33c3e512a8337dae20ebdd5237134988"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-30 21:31:01"
  condition:
    hash.sha256(0, filesize) == "cd8a4747ca552e4ce1b1bd86249a068f33c3e512a8337dae20ebdd5237134988"
}

rule MalwareBazaar_Mirai_080_8727a17e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8727a17e67980f4db297653f1bbdcf3a788f6241259427163de792b8f1e291b8"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-30 21:29:51"
  condition:
    hash.sha256(0, filesize) == "8727a17e67980f4db297653f1bbdcf3a788f6241259427163de792b8f1e291b8"
}

rule MalwareBazaar_unknown_081_4b8c2266
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b8c22660c29b27700e6b7cd0e990f9e2f08f2a581354a09a4cf9ae08d443a51"
    family = "unknown"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-30 21:29:50"
  condition:
    hash.sha256(0, filesize) == "4b8c22660c29b27700e6b7cd0e990f9e2f08f2a581354a09a4cf9ae08d443a51"
}

rule MalwareBazaar_unknown_082_a78278e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a78278e9b95b9eb162331dfd052b98752b6757a8991012f44a84efc25e9f49d1"
    family = "unknown"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-30 21:27:51"
  condition:
    hash.sha256(0, filesize) == "a78278e9b95b9eb162331dfd052b98752b6757a8991012f44a84efc25e9f49d1"
}

rule MalwareBazaar_unknown_083_db59dfaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db59dfafcc05be928df94d060ffb1655613a412d4d292983b204b90d4b4cda60"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-30 21:24:02"
  condition:
    hash.sha256(0, filesize) == "db59dfafcc05be928df94d060ffb1655613a412d4d292983b204b90d4b4cda60"
}

rule MalwareBazaar_unknown_084_11738a5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11738a5b45dfdddb7511c815bfb61ceb2841468846d0d6386429373b856e3d19"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-30 21:22:15"
  condition:
    hash.sha256(0, filesize) == "11738a5b45dfdddb7511c815bfb61ceb2841468846d0d6386429373b856e3d19"
}

rule MalwareBazaar_Mirai_085_37ead5a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37ead5a16a9a8630b74a38a740b71789a3c6d1a3205c4e21675cadd2af90b472"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-30 21:22:13"
  condition:
    hash.sha256(0, filesize) == "37ead5a16a9a8630b74a38a740b71789a3c6d1a3205c4e21675cadd2af90b472"
}

rule MalwareBazaar_unknown_086_ed4337ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed4337ee1b5174a6f113dfbf60faaf9ca17e531422da5001baeaab0878ac54f6"
    family = "unknown"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-30 21:18:09"
  condition:
    hash.sha256(0, filesize) == "ed4337ee1b5174a6f113dfbf60faaf9ca17e531422da5001baeaab0878ac54f6"
}

rule MalwareBazaar_unknown_087_2041194a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2041194a6bb541b47ebc24cef891b00eb19c21708188310c61e87c5ef11dde31"
    family = "unknown"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-30 21:15:53"
  condition:
    hash.sha256(0, filesize) == "2041194a6bb541b47ebc24cef891b00eb19c21708188310c61e87c5ef11dde31"
}

rule MalwareBazaar_unknown_088_d251f7a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d251f7a30d6b797b0e2edf2fd9d7c5e42272dcfc9495bb6a9ee9b62e97a6bf51"
    family = "unknown"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-30 21:13:51"
  condition:
    hash.sha256(0, filesize) == "d251f7a30d6b797b0e2edf2fd9d7c5e42272dcfc9495bb6a9ee9b62e97a6bf51"
}

rule MalwareBazaar_Vidar_089_f6fd816e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f"
    family = "Vidar"
    file_name = "f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f.bin"
    file_type = "exe"
    first_seen = "2026-08-30 21:10:34"
  condition:
    hash.sha256(0, filesize) == "f6fd816e3249cc679838c7936002b6a1e545f7a45d09893486f7f61f646bb21f"
}

rule MalwareBazaar_unknown_090_1ec76c4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ec76c4d3be7c42c78a5b9358c49219035ec638b129b497dcb78bd7a983e6d46"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-30 21:09:48"
  condition:
    hash.sha256(0, filesize) == "1ec76c4d3be7c42c78a5b9358c49219035ec638b129b497dcb78bd7a983e6d46"
}

rule MalwareBazaar_unknown_091_ddd09fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddd09fd60251050ebb2fed85ead524c234f830301b85476da997249726e9a60e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-30 20:59:42"
  condition:
    hash.sha256(0, filesize) == "ddd09fd60251050ebb2fed85ead524c234f830301b85476da997249726e9a60e"
}

rule MalwareBazaar_unknown_092_0fe9ee55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fe9ee5552f17321c41c44ac8196ecaf4fe0d8e97207545f70906c636dab033a"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-30 20:57:43"
  condition:
    hash.sha256(0, filesize) == "0fe9ee5552f17321c41c44ac8196ecaf4fe0d8e97207545f70906c636dab033a"
}

rule MalwareBazaar_Mirai_093_d5c876ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765"
    family = "Mirai"
    file_name = "d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765.elf"
    file_type = "elf"
    first_seen = "2026-08-30 20:57:15"
  condition:
    hash.sha256(0, filesize) == "d5c876aed3c43d53d1c37d5ea33a44e84fcd3af80a10c53b020fb8946bfd3765"
}

rule MalwareBazaar_Mirai_094_99007967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "990079676b58186129270525cc8661e3f512d72acc60f82ee86509433dd85038"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-08-30 20:52:04"
  condition:
    hash.sha256(0, filesize) == "990079676b58186129270525cc8661e3f512d72acc60f82ee86509433dd85038"
}

rule MalwareBazaar_Mirai_095_151ac96b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "151ac96b0cd25d554866cfa5f4c8b2a7eb6c7dee85874c0966388ab3cd11ed22"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-30 20:48:29"
  condition:
    hash.sha256(0, filesize) == "151ac96b0cd25d554866cfa5f4c8b2a7eb6c7dee85874c0966388ab3cd11ed22"
}

rule MalwareBazaar_unknown_096_c327c095
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c327c09546c35128f7fa873955bf6df7b3ecd45f308db8895f7f256a1aaec7ec"
    family = "unknown"
    file_name = "ano70jf_pw_infected.zip"
    file_type = "zip"
    first_seen = "2026-08-30 20:42:42"
  condition:
    hash.sha256(0, filesize) == "c327c09546c35128f7fa873955bf6df7b3ecd45f308db8895f7f256a1aaec7ec"
}

rule MalwareBazaar_Mirai_097_b95e693c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-30 20:42:04"
  condition:
    hash.sha256(0, filesize) == "b95e693c051c1c73a76d970e639ffde3bfa388dac2faccf57169c44c360100fa"
}

rule MalwareBazaar_unknown_098_ba5b5e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba5b5e1cedf641a8c3281e631a2034b5e4ab4f0153dafead21d76164ed717d5b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-30 20:41:46"
  condition:
    hash.sha256(0, filesize) == "ba5b5e1cedf641a8c3281e631a2034b5e4ab4f0153dafead21d76164ed717d5b"
}

rule MalwareBazaar_unknown_099_e240ed6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512"
    family = "unknown"
    file_name = "e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512.bin"
    file_type = "exe"
    first_seen = "2026-08-30 20:40:25"
  condition:
    hash.sha256(0, filesize) == "e240ed6f9c39ce9fa420af4164fbb976811bc49bce16ab2b3e2a98ebd1f40512"
}

rule MalwareBazaar_Mirai_100_d0d1bbcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f"
    family = "Mirai"
    file_name = "d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f.elf"
    file_type = "elf"
    first_seen = "2026-08-30 20:37:14"
  condition:
    hash.sha256(0, filesize) == "d0d1bbcd8900f190bc7b24e1b15e5558fbc917e5172712075207ee3e29c16a3f"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

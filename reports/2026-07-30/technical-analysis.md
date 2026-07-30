# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-30

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 652 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 652 |
| Unique family labels | 10 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 45 |
| Mirai | 45 |
| WannaCry | 2 |
| RemusStealer | 2 |
| RemcosRAT | 1 |
| njrat | 1 |
| RemoteX | 1 |
| Stealc | 1 |
| NanoCore | 1 |
| Phorpiex | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 47 |
| exe | 30 |
| sh | 12 |
| apk | 5 |
| unknown | 2 |
| js | 1 |
| vbs | 1 |
| 7z | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `a6eb7f69df025bf0`

| Field | Value |
|---|---|
| SHA-256 | `a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562` |
| Family label | `unknown` |
| File name | `tmp3A5.tmp.exe` |
| File type | `exe` |
| First seen | `2026-07-30 02:52:34` |
| Reporter | `Alex_sev` |
| Tags | `agent, backdoor, downloader, exe, msil` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eab119e1a445bdb9276dc76d572e20b` |
| SHA-1 | `74ee9a25dc26ec7d1d14cc5d6e10f15800b6c60e` |
| SHA-256 | `a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562` |
| SHA3-384 | `9b3b73cc3e14ba587a2f562fdadcc07f1f37bb63a1e01bd4d056511a1b19f4ed6378e5f273f6e3957430c8d7fc275bb8` |
| TLSH | `T1B2E438253B950D10E994147D867EAA00D732A0F26742B783370AF3A51E54EEDEF2E3D6` |
| SSDEEP | `12288:dXPhh1GbcsAmL+HPzF/ynLut8qZsX9zldx3hOA0P2y3zDIeIS:hVGom+H7dynLutrZw9zbm2KD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_a6eb7f69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562"
    family = "unknown"
    file_name = "tmp3A5.tmp.exe"
    file_type = "exe"
    first_seen = "2026-07-30 02:52:34"
  condition:
    hash.sha256(0, filesize) == "a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562"
}
```

### Sample 2: `31e86a063a1bdb8f`

| Field | Value |
|---|---|
| SHA-256 | `31e86a063a1bdb8f77d70a05c0b67ea7f962ccdd527a40311fe0debefb724375` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 02:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c88e46c406f6e91ac0175fc9f8efd240` |
| SHA-1 | `09b17c8374bfca50b7a634355a636f79af19e6a5` |
| SHA-256 | `31e86a063a1bdb8f77d70a05c0b67ea7f962ccdd527a40311fe0debefb724375` |
| SHA3-384 | `2559d50bbc37420277b0d20c77663c0a4077f3b5691d2b6ebd1dfbdef118a507ad8a8027c739dae7e47dba415bbdbe7b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T145E6339C76E425EDED67C03DADE20409E6B5B8751B72CADB47B407A26F631E00C3D21A` |
| SSDEEP | `393216:HUuse67YdpNXtK6FQpRQwibpPkXMCHWUjXvcuI3/PGTAI:HU0RXtKkQpRQGXMb8XkH/O7` |
| ICON-DHASH | `19dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_31e86a06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31e86a063a1bdb8f77d70a05c0b67ea7f962ccdd527a40311fe0debefb724375"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 02:52:31"
  condition:
    hash.sha256(0, filesize) == "31e86a063a1bdb8f77d70a05c0b67ea7f962ccdd527a40311fe0debefb724375"
}
```

### Sample 3: `a2da49f221ea054d`

| Field | Value |
|---|---|
| SHA-256 | `a2da49f221ea054d054ad6864fa443ffafd25a21ffc643a30257980963f36c7a` |
| Family label | `Mirai` |
| File name | `xd.ppc` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9744e0c192047aaa5c6939bdd2cfe7f1` |
| SHA-1 | `f01a7174b7aab32009a7f2cc4e9ad0e7670a87db` |
| SHA-256 | `a2da49f221ea054d054ad6864fa443ffafd25a21ffc643a30257980963f36c7a` |
| SHA3-384 | `7eb82c6f06ae10f3f2b3df8a530061ef4e45933102ef3cbb916ad56bb87df2cd03762c037e37dce39840e05c5862021b` |
| TLSH | `T119F45A82FF1D0563CA570DF0293F43E5F3217A9241B9D229330E5B572622E36AAC7796` |
| SSDEEP | `12288:SlxZmyYSEVXHE2ujGCKUka8Hha0pP9G2ccgMScE2QK1epoNS/dZ:SppEVXHEhqaSaqlgME2xST` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_a2da49f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2da49f221ea054d054ad6864fa443ffafd25a21ffc643a30257980963f36c7a"
    family = "Mirai"
    file_name = "xd.ppc"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:52"
  condition:
    hash.sha256(0, filesize) == "a2da49f221ea054d054ad6864fa443ffafd25a21ffc643a30257980963f36c7a"
}
```

### Sample 4: `537079272b0ccda6`

| Field | Value |
|---|---|
| SHA-256 | `537079272b0ccda68ba39a657e83549c91ba45d9eecefd29db322a200d08f354` |
| Family label | `Mirai` |
| File name | `xd.mpsl` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19b70058bc7440ba1e42725c3ade871e` |
| SHA-1 | `e66e448099f7662c836b17c7be7f5f29a680df6e` |
| SHA-256 | `537079272b0ccda68ba39a657e83549c91ba45d9eecefd29db322a200d08f354` |
| SHA3-384 | `031d4965c23f548466d4267d408895dd927aff0a93a01bfb252525834adabd0a80c0ff2b0495122086ec0e2df5d8641b` |
| TLSH | `T1A6E46B02EF441FEBC4AFCD30853E874B15DD998712D1A7B9A1FC894CBA8D65A4BD3488` |
| SSDEEP | `12288:MqrfCJGsLrfDEB+U6c6hJpqnRcpqS/cSzVd9sJ7hlOiOh0y+yrh2Zn/4o2mM2ItM:Ly2YgLxKx19T1D/fmh4RCJsfedCnd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_53707927
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "537079272b0ccda68ba39a657e83549c91ba45d9eecefd29db322a200d08f354"
    family = "Mirai"
    file_name = "xd.mpsl"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:51"
  condition:
    hash.sha256(0, filesize) == "537079272b0ccda68ba39a657e83549c91ba45d9eecefd29db322a200d08f354"
}
```

### Sample 5: `439b2f72b37b28a9`

| Field | Value |
|---|---|
| SHA-256 | `439b2f72b37b28a9114dec1bdc27e68b7b261f73a77d5408eab726e5ba096ecc` |
| Family label | `Mirai` |
| File name | `xd.spc` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87aa5d01e40874dedfd6a6b8d2129285` |
| SHA-1 | `992e57b27df18318a9ac6470ee7133fb61445c6a` |
| SHA-256 | `439b2f72b37b28a9114dec1bdc27e68b7b261f73a77d5408eab726e5ba096ecc` |
| SHA3-384 | `c3c621a7614958ab84e28a662a10ddafdd40f67de448c8b3549c66c8d0b751d4952630e8aee6439ea70f940e13deb7e2` |
| TLSH | `T10A259D02F7F61166D29083358662DB607A43ABA629E4420FDF604EDFEF572640E85CF7` |
| SSDEEP | `12288:eDs8FZawv8vM5fldLmrZ1SaSt80i/Fs50CyP+:jm5vldLeDSDt8Xg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_439b2f72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "439b2f72b37b28a9114dec1bdc27e68b7b261f73a77d5408eab726e5ba096ecc"
    family = "Mirai"
    file_name = "xd.spc"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:50"
  condition:
    hash.sha256(0, filesize) == "439b2f72b37b28a9114dec1bdc27e68b7b261f73a77d5408eab726e5ba096ecc"
}
```

### Sample 6: `c18b493bdf0403f0`

| Field | Value |
|---|---|
| SHA-256 | `c18b493bdf0403f015b58745c3ef3b18a7253437fcb567a1e5f63a2887eeaad1` |
| Family label | `Mirai` |
| File name | `xd.arm6` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3141c1b7a72029581fb390c542f722f` |
| SHA-1 | `369fd6ef014a551a1757d91ae81139f63f690a0c` |
| SHA-256 | `c18b493bdf0403f015b58745c3ef3b18a7253437fcb567a1e5f63a2887eeaad1` |
| SHA3-384 | `1030df203ea6c88780661c2bf161eb042dc9ed7fa20dc41308aa0b896d3ef38c8ab51a24ce5fcee195d31a72179bab49` |
| TLSH | `T103C44955F8809F61C6D539B6F64D42AC730747B9C3EB72069A244B343BDB8AB0B3A705` |
| TELFHASH | `t16ef09e25e5612b06e38316d4d037672656bd27a867127451cbea7e1d7f03ec015d0c77` |
| SSDEEP | `12288:OYdSUhlhAs+S0XfB+LtviNb0kd0iy8pLb/S:OTUhlhdGB+BwL9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_c18b493b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c18b493bdf0403f015b58745c3ef3b18a7253437fcb567a1e5f63a2887eeaad1"
    family = "Mirai"
    file_name = "xd.arm6"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:48"
  condition:
    hash.sha256(0, filesize) == "c18b493bdf0403f015b58745c3ef3b18a7253437fcb567a1e5f63a2887eeaad1"
}
```

### Sample 7: `44803559c71a805c`

| Field | Value |
|---|---|
| SHA-256 | `44803559c71a805c0400f3647ff6384dcdfe7a79254910b7fe514ee1e258c12d` |
| Family label | `Mirai` |
| File name | `xd.mips` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `300f4772fcc68e8fd6b04b79103f1312` |
| SHA-1 | `a34e722b0a1d6c6c5908eaf7f3b4201860ba7a41` |
| SHA-256 | `44803559c71a805c0400f3647ff6384dcdfe7a79254910b7fe514ee1e258c12d` |
| SHA3-384 | `13c9012e2526e30b303b2f1053e753efb6e6f228166866146733cf1e94d35700eda3b9c8c3958121416573eab50757e7` |
| TLSH | `T1C2E47D93B7228F94E361D27105F38B555AA921A307F350C2A37DC6207A50A6D6C2FFF9` |
| TELFHASH | `t19f418d48097813f0a6659c5d49ddff36d6a330eb3e162c278a11e89eeb69e839d14c1c` |
| SSDEEP | `12288:+NWlDM4bd+uuCBozDHoeca/QDTgKekrAGe/978p9pkkB8goG:hM4bIuuCyDoQ/QD9ek5e/ykkT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_44803559
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44803559c71a805c0400f3647ff6384dcdfe7a79254910b7fe514ee1e258c12d"
    family = "Mirai"
    file_name = "xd.mips"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:47"
  condition:
    hash.sha256(0, filesize) == "44803559c71a805c0400f3647ff6384dcdfe7a79254910b7fe514ee1e258c12d"
}
```

### Sample 8: `9fb440b26b054059`

| Field | Value |
|---|---|
| SHA-256 | `9fb440b26b054059cc167bdaacbb46e7821447d3b89359a40f6b9dd60163eaf8` |
| Family label | `Mirai` |
| File name | `xd.m68k` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73d90cd6d5262fde5252be5a23d58d6c` |
| SHA-1 | `62a5e790fe0b5165bd34b3bc88140907974cd69b` |
| SHA-256 | `9fb440b26b054059cc167bdaacbb46e7821447d3b89359a40f6b9dd60163eaf8` |
| SHA3-384 | `7a15a99b3eceeca79a7579558de3013a032785e8c223bb5a950c59a8b8abba9d593a1121017f63ed2561d9e603c6de01` |
| TLSH | `T1EAB4D0C673023E3EE0B3553A80A64F176735A3845083274B3175F9696A23AF92F75AC7` |
| SSDEEP | `12288:0+/Pqa1Y5o5fGTudkUTiRAB9wW9MNB5VLhVGWa:0ja25ERDkRJ3VGV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_9fb440b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb440b26b054059cc167bdaacbb46e7821447d3b89359a40f6b9dd60163eaf8"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:45"
  condition:
    hash.sha256(0, filesize) == "9fb440b26b054059cc167bdaacbb46e7821447d3b89359a40f6b9dd60163eaf8"
}
```

### Sample 9: `5f88be80111356aa`

| Field | Value |
|---|---|
| SHA-256 | `5f88be80111356aa32af22b72157c314dc65efd1cb36a41c25b00ee4b410f8fc` |
| Family label | `Mirai` |
| File name | `xd.sh4` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `015332f9226c6de62867d7a0bfa69482` |
| SHA-1 | `c127157f42174ad9222485c263deba643fdf8204` |
| SHA-256 | `5f88be80111356aa32af22b72157c314dc65efd1cb36a41c25b00ee4b410f8fc` |
| SHA3-384 | `206e879dbd3d860f57373cce46523359441d35335564b4aceee0558a845a03c2707aad5a44cb119872470782db177cbe` |
| TLSH | `T1DEB4C063F6B06EC5C4120A741CFAD3340758F39503E22661EBFAC9642C8B676B94DB76` |
| SSDEEP | `12288:MceMXzGweBSmcs++9YQrzctpzOg9bGjYLdWx8E8pPKor:qwzB7+9XzcPzhG8JK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_5f88be80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f88be80111356aa32af22b72157c314dc65efd1cb36a41c25b00ee4b410f8fc"
    family = "Mirai"
    file_name = "xd.sh4"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:44"
  condition:
    hash.sha256(0, filesize) == "5f88be80111356aa32af22b72157c314dc65efd1cb36a41c25b00ee4b410f8fc"
}
```

### Sample 10: `bbbab27acb546f3f`

| Field | Value |
|---|---|
| SHA-256 | `bbbab27acb546f3f3aa632bb5e084316f4af2fef4490262dfc33d4df624f96cc` |
| Family label | `Mirai` |
| File name | `xd.arm7` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5093df4d6566f583e604a641991ef6c9` |
| SHA-1 | `bbb62884faab4bc5d10e4b65a2bbf7d444944162` |
| SHA-256 | `bbbab27acb546f3f3aa632bb5e084316f4af2fef4490262dfc33d4df624f96cc` |
| SHA3-384 | `50d028be1c44fadb6a816f467b68fa439f73ff3f0164c69259574c6d83f8f4ab1539fc0f85aba30d0ec9244fd73877bc` |
| TLSH | `T1C994E096F79A3E45C8C7863519864245975DE59B33F383463B03ADBA382A3738F38385` |
| SSDEEP | `6144:zW8nGNjPCx7seU2hOVrbcrey6A6DOlDNrWeJUPGH8pLh/9:zLMPCxYeCc4A2OlDNrWeJ/H8pLh/9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_bbbab27a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbbab27acb546f3f3aa632bb5e084316f4af2fef4490262dfc33d4df624f96cc"
    family = "Mirai"
    file_name = "xd.arm7"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:43"
  condition:
    hash.sha256(0, filesize) == "bbbab27acb546f3f3aa632bb5e084316f4af2fef4490262dfc33d4df624f96cc"
}
```

### Sample 11: `bab2dee1fc862cd6`

| Field | Value |
|---|---|
| SHA-256 | `bab2dee1fc862cd6915bd9d70222c6be76103111d78c67dc498842a6c681ffed` |
| Family label | `Mirai` |
| File name | `xd.arm5` |
| File type | `elf` |
| First seen | `2026-07-30 02:40:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70af45cf0ca2bb6d98fb44febb71cef0` |
| SHA-1 | `dd30eadf337e35d820f2f78a03e41b6ad595d4cc` |
| SHA-256 | `bab2dee1fc862cd6915bd9d70222c6be76103111d78c67dc498842a6c681ffed` |
| SHA3-384 | `1924adb5b089e3c78f1b37c27b75a5998e0d8d2844357f84df4af48d31be245f68a12de3315ca1a4595f121d798c944d` |
| TLSH | `T1B8732B82F8D1FE53C6D82A76BA1E119D332253F8D2DA3303CE144A1577CD5994A3AB4E` |
| TELFHASH | `t1e9e02610ecb98f2c98d7aab4dc9c06a0a9012223504a4f10cf12daf0dc3f454e709d5a` |
| SSDEEP | `1536:ps1lKh2kqFeCDG0cF5NE4BpQnHmvqki9sefIF7ogDX:m1AhXMvU5G4BpQnHmJi6efoV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_bab2dee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bab2dee1fc862cd6915bd9d70222c6be76103111d78c67dc498842a6c681ffed"
    family = "Mirai"
    file_name = "xd.arm5"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:41"
  condition:
    hash.sha256(0, filesize) == "bab2dee1fc862cd6915bd9d70222c6be76103111d78c67dc498842a6c681ffed"
}
```

### Sample 12: `e54459c6e71f048b`

| Field | Value |
|---|---|
| SHA-256 | `e54459c6e71f048bcba8c3103982e2b9f4b5f9cd9b00d0b71a2d03a24ab84d12` |
| Family label | `unknown` |
| File name | `sensi.sh` |
| File type | `sh` |
| First seen | `2026-07-30 02:40:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c96a52caddc9817b1266a45332e8865b` |
| SHA-1 | `8ee5afd6f949af33adc7b112561a3c515126db07` |
| SHA-256 | `e54459c6e71f048bcba8c3103982e2b9f4b5f9cd9b00d0b71a2d03a24ab84d12` |
| SHA3-384 | `33b68bbd5bfdf10ae332b574f8213954c8e580ce4b63005a8496e609c6d96a2582fd5a3ab4c7b1acae22ebe7765f884c` |
| TLSH | `T17EF08BED94A640323F0D583771194C552602082F24B95BDD224E99635E0CFA8234EF33` |
| SSDEEP | `12:ZsU9jWijWr5jW2FFl7jN/OQrNaQoTERE5YXmY6uYCYEeyH:Zp9jWijWr5jW2Fr7jN/VsFBYXmYRYCYQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_e54459c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e54459c6e71f048bcba8c3103982e2b9f4b5f9cd9b00d0b71a2d03a24ab84d12"
    family = "unknown"
    file_name = "sensi.sh"
    file_type = "sh"
    first_seen = "2026-07-30 02:40:40"
  condition:
    hash.sha256(0, filesize) == "e54459c6e71f048bcba8c3103982e2b9f4b5f9cd9b00d0b71a2d03a24ab84d12"
}
```

### Sample 13: `bb87574dc35a257a`

| Field | Value |
|---|---|
| SHA-256 | `bb87574dc35a257a4e13e238f18d223709a49367e601e7acd43ed7730d35edbb` |
| Family label | `unknown` |
| File name | `AzureSet-NetAdapterPowerManagement.log` |
| File type | `unknown` |
| First seen | `2026-07-30 02:32:11` |
| Reporter | `anonymous` |
| Tags | `Trojan:Win32/Commando.A!ml` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6c1ab56667ad3eaaf53b1fcfffd3b83` |
| SHA-256 | `bb87574dc35a257a4e13e238f18d223709a49367e601e7acd43ed7730d35edbb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_bb87574d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb87574dc35a257a4e13e238f18d223709a49367e601e7acd43ed7730d35edbb"
    family = "unknown"
    file_name = "AzureSet-NetAdapterPowerManagement.log"
    file_type = "unknown"
    first_seen = "2026-07-30 02:32:11"
  condition:
    hash.sha256(0, filesize) == "bb87574dc35a257a4e13e238f18d223709a49367e601e7acd43ed7730d35edbb"
}
```

### Sample 14: `55f0132ba99eaf39`

| Field | Value |
|---|---|
| SHA-256 | `55f0132ba99eaf397afb997f26900c6ae6c9c797f2dd99da5423c33f549b5afe` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-30 02:16:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7a1cea97c38ea97117b62c110a6dd31` |
| SHA-1 | `44acb93271ac94d05b45df54fdee94155f310caf` |
| SHA-256 | `55f0132ba99eaf397afb997f26900c6ae6c9c797f2dd99da5423c33f549b5afe` |
| SHA3-384 | `94e8f2e7d8e748b47742b58f9b0d40cef93ad01ec9e58c1dea2ccc98d300ba5e2cdec7ba7ec77a3137101a565ac33ddd` |
| TLSH | `T140C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:EV8vCB+25j6es8RCB9FYpMSUpi+20qUpi+20YQX:EV8l25J0d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_55f0132b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55f0132ba99eaf397afb997f26900c6ae6c9c797f2dd99da5423c33f549b5afe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-30 02:16:44"
  condition:
    hash.sha256(0, filesize) == "55f0132ba99eaf397afb997f26900c6ae6c9c797f2dd99da5423c33f549b5afe"
}
```

### Sample 15: `edd25cef88fe2c1b`

| Field | Value |
|---|---|
| SHA-256 | `edd25cef88fe2c1bd562e33f9403c1644f09f80ce10690f1337e7b295357d751` |
| Family label | `RemcosRAT` |
| File name | `NEW ORDER REQUEST.js` |
| File type | `js` |
| First seen | `2026-07-30 02:08:55` |
| Reporter | `threatcat_ch` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7af916042594863f89341a58d0af1c3` |
| SHA-1 | `096d5d58cb60fe2f81d90e7d7f7131e970bc498c` |
| SHA-256 | `edd25cef88fe2c1bd562e33f9403c1644f09f80ce10690f1337e7b295357d751` |
| SHA3-384 | `b92e5d721d458522288dcc4bad97debec2477d4a54b2fa752a22e4ec09bcd41efcb1ecc4ff3c05c423d326030a5b7cbc` |
| TLSH | `T16D63EBB7B6AFAD0960084A01D66CDD1F2C2CBE539A2DC534F0F9A3FFA4429D13606975` |
| SSDEEP | `192:SQmFiX4IUX9ixG/7LFbYTMFbJgc4bd9FR4jCOPvp8jij212tW:XGgbd9VO2F` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_015_edd25cef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edd25cef88fe2c1bd562e33f9403c1644f09f80ce10690f1337e7b295357d751"
    family = "RemcosRAT"
    file_name = "NEW ORDER REQUEST.js"
    file_type = "js"
    first_seen = "2026-07-30 02:08:55"
  condition:
    hash.sha256(0, filesize) == "edd25cef88fe2c1bd562e33f9403c1644f09f80ce10690f1337e7b295357d751"
}
```

### Sample 16: `22eec70bf4412de6`

| Field | Value |
|---|---|
| SHA-256 | `22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-30 02:06:50` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb6e7e9a50c63be76b593d320b543d5c` |
| SHA-1 | `b92a001a0e3fba6eb0debff08bab9ce59a851754` |
| SHA-256 | `22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85` |
| SHA3-384 | `bd3a7eaafef2567ca6185b6ae2ea211533115ba23e8285fa0c504635fbd456de8054af0c90358f3f3fbee0c2654ad390` |
| IMPHASH | `83fa772670ac674cd68ff73f3ef04802` |
| TLSH | `T1AA43B69167F9151AF6F38E783C7465568C7BBE726D61E08E8280204F0875B95CE78B33` |
| SSDEEP | `768:mpM+/0vaXDiTLlGCI0App3vWSph6koM3R+qsq:sCEiTLXA3/fp4koUR+v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_22eec70b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 02:06:50"
  condition:
    hash.sha256(0, filesize) == "22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85"
}
```

### Sample 17: `1bef2e01e1f4aad8`

| Field | Value |
|---|---|
| SHA-256 | `1bef2e01e1f4aad8becdec1dc5f525dedd83567f9fecfe51f6c8ac9efdfc0b8e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-30 02:02:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eb2415d67e7323be8ccf9c1d24cef1f` |
| SHA-1 | `ec1b9bc58305b85817fc400a8fbf094e8240488e` |
| SHA-256 | `1bef2e01e1f4aad8becdec1dc5f525dedd83567f9fecfe51f6c8ac9efdfc0b8e` |
| SHA3-384 | `c2d4d3bf9dbefccc9089117b0f83f0f1807b1773613bd5fd58f0f99e00cced1d15d7a8a0852df8650b4600130dedb5d9` |
| TLSH | `T180C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:y8vCB+25j6es8RY9FYpMSUpi+20qUpi+20YQX:y8l25Jud2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_1bef2e01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bef2e01e1f4aad8becdec1dc5f525dedd83567f9fecfe51f6c8ac9efdfc0b8e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-30 02:02:58"
  condition:
    hash.sha256(0, filesize) == "1bef2e01e1f4aad8becdec1dc5f525dedd83567f9fecfe51f6c8ac9efdfc0b8e"
}
```

### Sample 18: `2a01a22a5d823b57`

| Field | Value |
|---|---|
| SHA-256 | `2a01a22a5d823b5705dad1f7de5d15ebf9068347099726b95878aeaf9de9b625` |
| Family label | `njrat` |
| File name | `ORDER 29TH.vbs` |
| File type | `vbs` |
| First seen | `2026-07-30 01:59:30` |
| Reporter | `threatcat_ch` |
| Tags | `njrat, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `395c72857511f2fa5a36caf83d5004db` |
| SHA-1 | `656de2be0895a3b9f7a2d4880b90c0f4f7f64aff` |
| SHA-256 | `2a01a22a5d823b5705dad1f7de5d15ebf9068347099726b95878aeaf9de9b625` |
| SHA3-384 | `6685e8bf1170fb2259485e66ca39aeb2e161a1ca63d0752f78fcd4196f072b83e881b498ca7bb3112634a6e92fbc9aa1` |
| TLSH | `T10AC56D0C8906F8EAEA10B6EF6C4D3B475941746759F718A96F5FE33E0BB39241F4108A` |
| SSDEEP | `192:8QAVtOtYZOMLK0KZIuTfzXz42996bslbowjZD:wpEHVZNbXzfjR` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_018_2a01a22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a01a22a5d823b5705dad1f7de5d15ebf9068347099726b95878aeaf9de9b625"
    family = "njrat"
    file_name = "ORDER 29TH.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 01:59:30"
  condition:
    hash.sha256(0, filesize) == "2a01a22a5d823b5705dad1f7de5d15ebf9068347099726b95878aeaf9de9b625"
}
```

### Sample 19: `4bc1bc072949437c`

| Field | Value |
|---|---|
| SHA-256 | `4bc1bc072949437c41adf9203ba98595ebaeb1ee47d231fc9e59a16e697e336c` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 01:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03009c13a8a4188a14bc879b6ba40416` |
| SHA-1 | `cc455511e8fc282f3bf819d0f87616c77f99164a` |
| SHA-256 | `4bc1bc072949437c41adf9203ba98595ebaeb1ee47d231fc9e59a16e697e336c` |
| SHA3-384 | `60219aa0eda4a90367aed6bc9522964113b21b4a6d30c32bd3011f3267114fca7f1533cca7a4be25c73e80aa531b3e91` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T152E633189BD407EEE5B351399FA1A882F13AF8B94372C5CFA7A847956D132D10C38763` |
| SSDEEP | `393216:03nnMxSjRaLLom41XMCHWUjXocuI3/PGTAI:6nzRaomuXMb8XdH/O7` |
| ICON-DHASH | `71f0f0e8e8e0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_4bc1bc07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bc1bc072949437c41adf9203ba98595ebaeb1ee47d231fc9e59a16e697e336c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 01:52:32"
  condition:
    hash.sha256(0, filesize) == "4bc1bc072949437c41adf9203ba98595ebaeb1ee47d231fc9e59a16e697e336c"
}
```

### Sample 20: `aa585df9ce9d53ee`

| Field | Value |
|---|---|
| SHA-256 | `aa585df9ce9d53ee758526dea601e4718bfd333ac594448574b7f6ac711f0fe8` |
| Family label | `Mirai` |
| File name | `zero.sh4` |
| File type | `elf` |
| First seen | `2026-07-30 01:48:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07ee3ab32e52dfa1f08e7b0ac0cf81ad` |
| SHA-1 | `537b3545145a2bf77a0c334eeb04017120055cc4` |
| SHA-256 | `aa585df9ce9d53ee758526dea601e4718bfd333ac594448574b7f6ac711f0fe8` |
| SHA3-384 | `c5cd9469c02487bdcd426c1f365e18783fa8a63303702689ce594aff1bf707139b1d3551e3b510933e503b5e36bf9415` |
| TLSH | `T130E36C22CCB56E9CE172E934A078CEBA1723D594450BAEBF286783715057DC8F486BF4` |
| SSDEEP | `3072:qrjnYWxyxyyyIye2S49w77RO7BW6ON94cEk:qrjnYWxyxyyyIyeH4W7YM60CcEk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_aa585df9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa585df9ce9d53ee758526dea601e4718bfd333ac594448574b7f6ac711f0fe8"
    family = "Mirai"
    file_name = "zero.sh4"
    file_type = "elf"
    first_seen = "2026-07-30 01:48:41"
  condition:
    hash.sha256(0, filesize) == "aa585df9ce9d53ee758526dea601e4718bfd333ac594448574b7f6ac711f0fe8"
}
```

### Sample 21: `a80f608476a3faac`

| Field | Value |
|---|---|
| SHA-256 | `a80f608476a3faacca1ef34361cc418a68661db2d87ccf0d9b14d307453e59f4` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-30 01:42:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a428d83303fd1f9930f9135a3d0fdea0` |
| SHA-1 | `4600206147b580d5408409ca9ab1c67664bdcfa6` |
| SHA-256 | `a80f608476a3faacca1ef34361cc418a68661db2d87ccf0d9b14d307453e59f4` |
| SHA3-384 | `d9fd0e88807608a0c8c181ff60e4ab51ec4b6d97d79f5235dc1876394bf542bc27d5fa08b7f84eef0ac699de96ff1981` |
| TLSH | `T1BBC27D966A867C44BDC94A3E4CBE2B0D6DF5C3D1324942AC3D4B3C719C11FACD618B1A` |
| SSDEEP | `768:B8vCB+25j6es8RKQn9FYpMSUpi+20qUpi+20YQX:B8l25JKQBd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_a80f6084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a80f608476a3faacca1ef34361cc418a68661db2d87ccf0d9b14d307453e59f4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-30 01:42:40"
  condition:
    hash.sha256(0, filesize) == "a80f608476a3faacca1ef34361cc418a68661db2d87ccf0d9b14d307453e59f4"
}
```

### Sample 22: `b67373fd6b4806d7`

| Field | Value |
|---|---|
| SHA-256 | `b67373fd6b4806d799d94fb1391e7e3c01354b1787fd2f879b6cff2f154f0c60` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-07-30 01:05:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5ee9a02e3239948de413d35762e88e5` |
| SHA-1 | `24d8b2b2860906b1b9e36a2e5d3728ad0f549088` |
| SHA-256 | `b67373fd6b4806d799d94fb1391e7e3c01354b1787fd2f879b6cff2f154f0c60` |
| SHA3-384 | `53a865a6e5714a72abc93a450364ba4cac6b130465e41fd11d7b000109b86546c778cd19651d21eafd185cdd4a27aa80` |
| TLSH | `T1DB24B61A3A22EFFFF168863007F38A7097E5259636A19745F26CD71C1F2028D681F7A4` |
| TELFHASH | `t1e7615359953c01d9de335c2964a96be30897e12a22e5fb19ff1acdc4084e43cf168e0f` |
| SSDEEP | `3072:xhFA0o20YPukHbCRfnRHRQIvTffSAmoz9nzBsNcPUTkFizT:p/PH0fn9r7fKAmoz9nzBsNcPUTkFizT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_b67373fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b67373fd6b4806d799d94fb1391e7e3c01354b1787fd2f879b6cff2f154f0c60"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-07-30 01:05:06"
  condition:
    hash.sha256(0, filesize) == "b67373fd6b4806d799d94fb1391e7e3c01354b1787fd2f879b6cff2f154f0c60"
}
```

### Sample 23: `243be638007185cd`

| Field | Value |
|---|---|
| SHA-256 | `243be638007185cdfd1b24a5d30f78c55bbb9e6fff241685e12a8a175728b9c1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-30 01:00:51` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4905e4aec4e45588d6fab8f138ba73ae` |
| SHA-1 | `47b46e94bb48c3bbd5adab3af998730d5cf75fc7` |
| SHA-256 | `243be638007185cdfd1b24a5d30f78c55bbb9e6fff241685e12a8a175728b9c1` |
| SHA3-384 | `84c67fe746f6ed26ab76c3ad22bd06177fa8242e2e291ca1568df9b5f746efd4d047ee9012f44c8ea633ee16a468e606` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T157F58C0B7CA109E6C499A33598B252517B71BC098B3633D72F91BB383E727D09D76B90` |
| SSDEEP | `49152:WfG+RoEZlGJbzvwKYejh4o+yL31taFo4waDN2+7Rtz:WlFIJMBN9Tz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_243be638
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243be638007185cdfd1b24a5d30f78c55bbb9e6fff241685e12a8a175728b9c1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 01:00:51"
  condition:
    hash.sha256(0, filesize) == "243be638007185cdfd1b24a5d30f78c55bbb9e6fff241685e12a8a175728b9c1"
}
```

### Sample 24: `a364fcd5ab8c0b31`

| Field | Value |
|---|---|
| SHA-256 | `a364fcd5ab8c0b3167f28db0e9729b552d29fbffa7a382561839fc4831c542c1` |
| Family label | `unknown` |
| File name | `exec_binary` |
| File type | `elf` |
| First seen | `2026-07-30 00:52:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `392c90f86248493fd122d8973bd6a374` |
| SHA-1 | `4a0b03e92bcbf940623d90dab5c28c2c23539bb3` |
| SHA-256 | `a364fcd5ab8c0b3167f28db0e9729b552d29fbffa7a382561839fc4831c542c1` |
| SHA3-384 | `c3e2ac9ec7077f8f423f7731ea427ed6ae1121aec7714790151fbe4f4c49a595b5b71e15f36ba70a58cdec1b7a137083` |
| TLSH | `T1281633C6490D4026952D4A74C02CE784F79F4F1A3BAE0BBDFAB613286D22FE56275D1C` |
| SSDEEP | `98304:tGCzApIVqguoftsKl9TNwVbrJQOssc6N1K0CQ9:eihuKs8yf2Fsr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_a364fcd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a364fcd5ab8c0b3167f28db0e9729b552d29fbffa7a382561839fc4831c542c1"
    family = "unknown"
    file_name = "exec_binary"
    file_type = "elf"
    first_seen = "2026-07-30 00:52:44"
  condition:
    hash.sha256(0, filesize) == "a364fcd5ab8c0b3167f28db0e9729b552d29fbffa7a382561839fc4831c542c1"
}
```

### Sample 25: `6d67be88230d11f5`

| Field | Value |
|---|---|
| SHA-256 | `6d67be88230d11f5751ab86094ccf4f704013e40c3172efee3bd08e772258f83` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-30 00:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6eeea1e0686edd419ffacf2097ee1cf5` |
| SHA-1 | `170657e1767a12f53a86078b2e116cd343b5b38e` |
| SHA-256 | `6d67be88230d11f5751ab86094ccf4f704013e40c3172efee3bd08e772258f83` |
| SHA3-384 | `e2dc6664f27f782da58f9b5fb48bb466d211b01d5d1e551c4b96d36aa6eb8d722195f9531ca35773700e118a51a4f6bf` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C1E63304FDD250EAF6B7C238AE92D265D079B4A20771CDEB23488767AD1B2E44C3D752` |
| SSDEEP | `393216:pcyjgkoUr4Ie3mT/izJluUdzy4VdzXMCHWUjXHcuI3/PGTAI:p7jgkmIe3UYJluUtfzXMb8X8H/O7` |
| ICON-DHASH | `71f0f0e8e8e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_6d67be88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d67be88230d11f5751ab86094ccf4f704013e40c3172efee3bd08e772258f83"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 00:52:33"
  condition:
    hash.sha256(0, filesize) == "6d67be88230d11f5751ab86094ccf4f704013e40c3172efee3bd08e772258f83"
}
```

### Sample 26: `679a5148066f3355`

| Field | Value |
|---|---|
| SHA-256 | `679a5148066f3355ed6f66f53a388f5b7c3a301d734311acda9804dd747385de` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-07-30 00:46:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c7746a96f9a2918b6afa71f5636c88b` |
| SHA-1 | `87fa5376511eb0856315bebd5b8cca8babba642f` |
| SHA-256 | `679a5148066f3355ed6f66f53a388f5b7c3a301d734311acda9804dd747385de` |
| SHA3-384 | `9ec09032e0f674aac7a9bcded3f5fe84a6a57093584edb6032c37708972fa0dbb4d70120f72d3bbb4dbfff1ecc76689c` |
| TLSH | `T172E34B42B32C0A43D2672EF43A3F27D1D3AFD95120F4E644255FAA899272E324547EDE` |
| SSDEEP | `3072:fagB9p5w7B9p52G6B9p5fDILdZcrBk0xp8kR8GwW66gMhb0nnJ:faz4ZrBk0x+kRSWJgMmnJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_679a5148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679a5148066f3355ed6f66f53a388f5b7c3a301d734311acda9804dd747385de"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-07-30 00:46:00"
  condition:
    hash.sha256(0, filesize) == "679a5148066f3355ed6f66f53a388f5b7c3a301d734311acda9804dd747385de"
}
```

### Sample 27: `fd7cdb47ad462dc0`

| Field | Value |
|---|---|
| SHA-256 | `fd7cdb47ad462dc080a987b66612784a1955d2b80d4bfec9031517fc0626a0eb` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-07-30 00:44:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb48bb5a6c94fd5489379f44227d71d6` |
| SHA-1 | `696d523509e4e05cf2e0665aae49907dcb561094` |
| SHA-256 | `fd7cdb47ad462dc080a987b66612784a1955d2b80d4bfec9031517fc0626a0eb` |
| SHA3-384 | `93ac1a24c0cf65882f28631003d72c93ce09ea4263dd2c31402ab96041b450dd22f1961195eb8e7c27b2f817ef106ae5` |
| TLSH | `T140430170043E6ED6BA591C3184BE8683B77D57CA26F4DD139699ABF3014E52332BC9E0` |
| SSDEEP | `1536:oPeiJoHjw77o90TLvr4p5bDX4u+qgw094:oPeCokUuT/o9X4u+qgwZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_fd7cdb47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7cdb47ad462dc080a987b66612784a1955d2b80d4bfec9031517fc0626a0eb"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-07-30 00:44:45"
  condition:
    hash.sha256(0, filesize) == "fd7cdb47ad462dc080a987b66612784a1955d2b80d4bfec9031517fc0626a0eb"
}
```

### Sample 28: `fafdcf2aa1011e57`

| Field | Value |
|---|---|
| SHA-256 | `fafdcf2aa1011e57905046c5e9d178f8c3812f311ee6c16c65a3f436511864b4` |
| Family label | `Mirai` |
| File name | `zero.sparc` |
| File type | `elf` |
| First seen | `2026-07-30 00:42:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98fa813fcd1d08de3e5a9a37876abbc6` |
| SHA-1 | `925d1c4c29a2be68ebf25bc072f2e0829ce6e245` |
| SHA-256 | `fafdcf2aa1011e57905046c5e9d178f8c3812f311ee6c16c65a3f436511864b4` |
| SHA3-384 | `a5a058bb3f8fae899c459b994e119b148d445591a88e0989b9752f66da8caf948b631dc5574b6acac09e6152813d4a96` |
| TLSH | `T102730915ED7C2B67C2E0213641E74A21F5B223DD1A78A68F7EA71D0DDD242A0313D9EE` |
| TELFHASH | `t1f8e0df10eda9865c88e7aa74dd9d07a4d9026222506a0b10df10dae4c83f458f309d5a` |
| SSDEEP | `1536:ppyxufRwReAXNYDanJ5qdFGnLocu7D7TxfFvi:vywfG8GJ5qdFGnLoci/zvi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_fafdcf2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fafdcf2aa1011e57905046c5e9d178f8c3812f311ee6c16c65a3f436511864b4"
    family = "Mirai"
    file_name = "zero.sparc"
    file_type = "elf"
    first_seen = "2026-07-30 00:42:43"
  condition:
    hash.sha256(0, filesize) == "fafdcf2aa1011e57905046c5e9d178f8c3812f311ee6c16c65a3f436511864b4"
}
```

### Sample 29: `b8fea3cc9b18b4b0`

| Field | Value |
|---|---|
| SHA-256 | `b8fea3cc9b18b4b09c94ed6645ad12d04274ddefa6ffd043576f00d2dea33d9b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-30 00:42:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07f32435e98fb5b53bb84357729f95e4` |
| SHA-1 | `02beb13d2569963cb91c17fee7ac134bc66540a4` |
| SHA-256 | `b8fea3cc9b18b4b09c94ed6645ad12d04274ddefa6ffd043576f00d2dea33d9b` |
| SHA3-384 | `f45b68ee170df1a629396c28d0d6599f6ebe513210e58a27f14ea252af2fb6b86df3eea64cc1e342ef2a5e670e687ccb` |
| TLSH | `T17D236D6516857C14AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10971D` |
| SSDEEP | `768:KXRWNGxVL9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:2lxmcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_b8fea3cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8fea3cc9b18b4b09c94ed6645ad12d04274ddefa6ffd043576f00d2dea33d9b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-30 00:42:41"
  condition:
    hash.sha256(0, filesize) == "b8fea3cc9b18b4b09c94ed6645ad12d04274ddefa6ffd043576f00d2dea33d9b"
}
```

### Sample 30: `38d8831322655204`

| Field | Value |
|---|---|
| SHA-256 | `38d883132265520493ca6b111191fb18ad691f13de2ada0c6598a92e880b2c7f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-30 00:36:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dc3d686908cbfab0328ee52cd385405` |
| SHA-1 | `4ebbe9e8540fa5458cd07dd6848eec61a30bf3c7` |
| SHA-256 | `38d883132265520493ca6b111191fb18ad691f13de2ada0c6598a92e880b2c7f` |
| SHA3-384 | `3cf3cd3f2fb053723d22c8ed3b0f013e4e3704240490725cf069f375c69152ac60e03cb9140f473d351abd2f2900cd56` |
| TLSH | `T19D235C6516857C24AE98C8361C7E2F0CB9AD43E6324452EEBFCB3CF68C4A69DD10971D` |
| SSDEEP | `768:3y+O9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:i+bcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_38d88313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38d883132265520493ca6b111191fb18ad691f13de2ada0c6598a92e880b2c7f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-30 00:36:50"
  condition:
    hash.sha256(0, filesize) == "38d883132265520493ca6b111191fb18ad691f13de2ada0c6598a92e880b2c7f"
}
```

### Sample 31: `bcf7bd7b46d57c05`

| Field | Value |
|---|---|
| SHA-256 | `bcf7bd7b46d57c055e8cde4588dae1aee094cc225074e0b5430640e90a8468ff` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 23:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d9fe4ce4cbb66bba8eeec6046d1e2b8` |
| SHA-1 | `03000941571e8c6142feab0aa699476be4711157` |
| SHA-256 | `bcf7bd7b46d57c055e8cde4588dae1aee094cc225074e0b5430640e90a8468ff` |
| SHA3-384 | `e3d81e70a67c01833b7999411ed648cf91db4e0b82a01a024191c4913c404e7644ff1aa947582b382f2b100195b86a5b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T140E6330485C002FED963523A9DE1E5A6E47AB87443B3C6DF8BB056367EA32E04E3D517` |
| SSDEEP | `393216:XgsueBHG4dwmMpS+fbOXMCHWUjXKcuI3/PGTAI:XgCBLdcJ6XMb8XnH/O7` |
| ICON-DHASH | `9878e0c0dcf8f022` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_bcf7bd7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcf7bd7b46d57c055e8cde4588dae1aee094cc225074e0b5430640e90a8468ff"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 23:52:31"
  condition:
    hash.sha256(0, filesize) == "bcf7bd7b46d57c055e8cde4588dae1aee094cc225074e0b5430640e90a8468ff"
}
```

### Sample 32: `26cba7929124eb13`

| Field | Value |
|---|---|
| SHA-256 | `26cba7929124eb13801a4e32c7071a2b3ab10896048bb25ca900e04edfa34795` |
| Family label | `RemoteX` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 23:26:02` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, RemoteX` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70167040a63143a7130cb17e6d3c50ec` |
| SHA-1 | `04225100608ee8c6edbc417ab3d5321a88f4ef9f` |
| SHA-256 | `26cba7929124eb13801a4e32c7071a2b3ab10896048bb25ca900e04edfa34795` |
| SHA3-384 | `eeb824a1952ceef53676d0ab04c907907de561c7761ea75053056a1d0c3272ba2a71f627b322633b2a117698e0f41bbd` |
| IMPHASH | `bf3d0d0ac28688e113006e8b183acf31` |
| TLSH | `T1DEF65A47E8A545E5C0AED175C6269212BB717C884F3063D72F90FB282F72BE0AE79744` |
| SSDEEP | `196608:upy44hK8zWJrtmM7oqUJB0HXZ97MU8J1Vq:uY44hK80rseoqSu7MU8o` |

#### Technical Assessment

- The sample is tracked as `RemoteX` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemoteX_032_26cba792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26cba7929124eb13801a4e32c7071a2b3ab10896048bb25ca900e04edfa34795"
    family = "RemoteX"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 23:26:02"
  condition:
    hash.sha256(0, filesize) == "26cba7929124eb13801a4e32c7071a2b3ab10896048bb25ca900e04edfa34795"
}
```

### Sample 33: `4b2bfcdbd2235a91`

| Field | Value |
|---|---|
| SHA-256 | `4b2bfcdbd2235a917786405381129da36922bbbb3f0342fbe44eaad3760afaa5` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 22:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa7a740a167d36f5ed71bb52478638d6` |
| SHA-1 | `6b58b9c15452ffe1a3178c79d77f0a93e8d0d0ad` |
| SHA-256 | `4b2bfcdbd2235a917786405381129da36922bbbb3f0342fbe44eaad3760afaa5` |
| SHA3-384 | `08eac6ce165a8068a7f9df7b2ba13f5b6355b3042e033a56401c49b09b8abeed979a6c39cd32cfe169c1edff9b92450c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1AEE633546BF122FEE4E3103C99A155E0E156B4690733C9FB07A0C6B96F5B2E09D3E326` |
| SSDEEP | `393216:b8FoPHL6mXElIC4xg/UmQXMCHWUjXFcuI3/PGTAI:bMoPHJX7C4xeDQXMb8XyH/O7` |
| ICON-DHASH | `e8e865e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_4b2bfcdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b2bfcdbd2235a917786405381129da36922bbbb3f0342fbe44eaad3760afaa5"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 22:52:31"
  condition:
    hash.sha256(0, filesize) == "4b2bfcdbd2235a917786405381129da36922bbbb3f0342fbe44eaad3760afaa5"
}
```

### Sample 34: `64d7a96e4307457c`

| Field | Value |
|---|---|
| SHA-256 | `64d7a96e4307457cf9c2efdd4990bcf4b5a215cb60fb8c36ebb46d1ac01f12d6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 22:50:32` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac8ce65b832f068c06f4dc4c7b0cc7ac` |
| SHA-1 | `f594cd58e9fc69721a93847c82205d09cba50b09` |
| SHA-256 | `64d7a96e4307457cf9c2efdd4990bcf4b5a215cb60fb8c36ebb46d1ac01f12d6` |
| SHA3-384 | `9bb22aab55e19c6268b783e1f1d379d57f694c1846e29dbcc017b5ed75e488dc9a8e4fda6baaf3c91f8476330dfb5145` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T144F55A077CA048E9D0AEA33189B652917B71BC094B3533D72FA0BA792F727D19D36B50` |
| SSDEEP | `24576:l17mSX1SO357SsP63HmVWAm5/ylxmimpuFNcsB5CbjnlfzBele5rKDm7j3c7iTLy:l179X1D35Wq63kWA5bm3puY2Cbf7xO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_64d7a96e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64d7a96e4307457cf9c2efdd4990bcf4b5a215cb60fb8c36ebb46d1ac01f12d6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 22:50:32"
  condition:
    hash.sha256(0, filesize) == "64d7a96e4307457cf9c2efdd4990bcf4b5a215cb60fb8c36ebb46d1ac01f12d6"
}
```

### Sample 35: `c0523063abe84c40`

| Field | Value |
|---|---|
| SHA-256 | `c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15` |
| Family label | `unknown` |
| File name | `c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15` |
| File type | `sh` |
| First seen | `2026-07-29 22:24:12` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fbdd4d76446e81cee9cdef60d64aff2` |
| SHA-1 | `7c7bd51937146a14b3c63d4165ff10fbaa3473bc` |
| SHA-256 | `c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15` |
| SHA3-384 | `5f230cccd79d30c8893223936ab94fc2e39bf9ab4e583fa2181fc1e4c6846e50a96ec4b5c5e1866ebebe28a2b65bddd1` |
| TLSH | `T16AE026A2B44280324A889447C55AC4A9709234032C55B22CA0337A718F8D168E23AFA9` |
| SSDEEP | `6:hZ+lfUzB+QFnTAJ3lqLeBsASA9QafpbA9Qe5plVyQJfRX50:SRpQFn8J3lfYA9QafpbA9QgpT1tk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_c0523063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15"
    family = "unknown"
    file_name = "c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15"
    file_type = "sh"
    first_seen = "2026-07-29 22:24:12"
  condition:
    hash.sha256(0, filesize) == "c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15"
}
```

### Sample 36: `a12938970191659c`

| Field | Value |
|---|---|
| SHA-256 | `a12938970191659c4b45d3aee886c6ef9b95f1e02e78eb85c71343f4a1e8cdd6` |
| Family label | `unknown` |
| File name | `662a80b0194fc616144c3a312a215faf4f78a5671ed978dc6796e581d9fe7d4a.7z` |
| File type | `7z` |
| First seen | `2026-07-29 22:05:34` |
| Reporter | `johnk3r` |
| Tags | `7z, banker, masgravr-shop` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e19a698ed7c3fb9664c52891973a242` |
| SHA-1 | `d2f083c9214fb0cf01466c06940ebc536beb4d0b` |
| SHA-256 | `a12938970191659c4b45d3aee886c6ef9b95f1e02e78eb85c71343f4a1e8cdd6` |
| SHA3-384 | `f060a11e006c3d3b47acbccbbdf0347b788345d5ca57444af07318332981eaf96e43fab979791e0f8a503c06e169ff1d` |
| TLSH | `T1668633CBC6E0E7DB2624BE4F63A01EDB655C5391A812E0AA324E7748DC05C5DB72F931` |
| SSDEEP | `196608:BfA2ypyPGru3zYF8sxiVUv7tYwWrxOtbZXJStVB6BRGZ1GKR7syDm:BfAZpyer6zu1xthJIV8O1GKJnS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `7z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_a1293897
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a12938970191659c4b45d3aee886c6ef9b95f1e02e78eb85c71343f4a1e8cdd6"
    family = "unknown"
    file_name = "662a80b0194fc616144c3a312a215faf4f78a5671ed978dc6796e581d9fe7d4a.7z"
    file_type = "7z"
    first_seen = "2026-07-29 22:05:34"
  condition:
    hash.sha256(0, filesize) == "a12938970191659c4b45d3aee886c6ef9b95f1e02e78eb85c71343f4a1e8cdd6"
}
```

### Sample 37: `86dac88668ac7f20`

| Field | Value |
|---|---|
| SHA-256 | `86dac88668ac7f20317d657ee7e95aea8a9df3530ff2713f8d62557e381bbec9` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 21:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07f8e0b9aed8eb0806104303d40aaca2` |
| SHA-1 | `36d174663ab2394e4533c6cea997e24380db8921` |
| SHA-256 | `86dac88668ac7f20317d657ee7e95aea8a9df3530ff2713f8d62557e381bbec9` |
| SHA3-384 | `74591fae966ae822df0e3583a87245e266b5c940d13d2ca1e8a6123d397e838ad929e8234f373a0a5ef1b9c03128f600` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1EBE63308AAD123FAF6738338EDE2549AC52DB86603B2C5CF5B8487915E171F18D7E253` |
| SSDEEP | `393216:k6PdOEu7yj5ZT92Xfl2zpXMCHWUjXscuI3/PGTAI:kcOE8yj53XMb8X5H/O7` |
| ICON-DHASH | `e86865e0d8e8ec58` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_86dac886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86dac88668ac7f20317d657ee7e95aea8a9df3530ff2713f8d62557e381bbec9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 21:52:31"
  condition:
    hash.sha256(0, filesize) == "86dac88668ac7f20317d657ee7e95aea8a9df3530ff2713f8d62557e381bbec9"
}
```

### Sample 38: `0ed2bdca1aba5f0a`

| Field | Value |
|---|---|
| SHA-256 | `0ed2bdca1aba5f0aa9b460314668ee74511d57e54adecb06a5595aa227db6a30` |
| Family label | `unknown` |
| File name | `RBL-Credit-Card-1.apk` |
| File type | `apk` |
| First seen | `2026-07-29 21:29:49` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Malware, RBL Bank, RBL Credit Card, signed, SpyAgent, Spyware, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `003637951e466ba67a0adad1615c942f` |
| SHA-1 | `e3bcc72e16c253902e597b5370642a4bd001f495` |
| SHA-256 | `0ed2bdca1aba5f0aa9b460314668ee74511d57e54adecb06a5595aa227db6a30` |
| SHA3-384 | `1575e913ed7cddd3276aaf984f0187a875cab8c3d2f310ea1ef3188aae45c8f81512fd750b8c757ef884d57bdb5c8506` |
| TLSH | `T1C306F1A47796A91ECC3B50320A255375124BEC228FE2E7576435339EEC379D84F4AEC8` |
| SSDEEP | `98304:YXmtO7OrdLQnsGU8YVENInPCPUF2/95AQCx3:YTKxcnsdvoIPD2/9g3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_0ed2bdca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ed2bdca1aba5f0aa9b460314668ee74511d57e54adecb06a5595aa227db6a30"
    family = "unknown"
    file_name = "RBL-Credit-Card-1.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:29:49"
  condition:
    hash.sha256(0, filesize) == "0ed2bdca1aba5f0aa9b460314668ee74511d57e54adecb06a5595aa227db6a30"
}
```

### Sample 39: `76bc2cfa58c82672`

| Field | Value |
|---|---|
| SHA-256 | `76bc2cfa58c82672d1cbe9112bcec4e8e7935a53b1db21b0f5731cf96fadcde6` |
| Family label | `unknown` |
| File name | `imobile.apk` |
| File type | `apk` |
| First seen | `2026-07-29 21:24:12` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, ICICI Bank, iMobile, Malware, Riskware, SpyAgent, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8d387c552c63596797ec59d17c5b08d` |
| SHA-1 | `860da3ef07eef55ffab4685574690343cb11ba9c` |
| SHA-256 | `76bc2cfa58c82672d1cbe9112bcec4e8e7935a53b1db21b0f5731cf96fadcde6` |
| SHA3-384 | `21872ef9732334fd2aa798d34c203f5ef7082c7db4addf45ae25ca7b66581d8ff56a2ccb0b0385ba9655a1df1825db87` |
| TLSH | `T17FE63306F92D4C6DD8B635783D14C34638327CA98B12C28B3561B37EBEF3AD1976A161` |
| SSDEEP | `393216:RzKkFcynFDsD/e0yUsoO9EwDb6wxLL9MQF:RzfFPnFQD/Hx53QLLN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_76bc2cfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76bc2cfa58c82672d1cbe9112bcec4e8e7935a53b1db21b0f5731cf96fadcde6"
    family = "unknown"
    file_name = "imobile.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:24:12"
  condition:
    hash.sha256(0, filesize) == "76bc2cfa58c82672d1cbe9112bcec4e8e7935a53b1db21b0f5731cf96fadcde6"
}
```

### Sample 40: `13bd0b75039576c6`

| Field | Value |
|---|---|
| SHA-256 | `13bd0b75039576c6b5f249e507cb5de04300c83b2971edd94686659848c504c7` |
| Family label | `unknown` |
| File name | `iMobile Lite.apk` |
| File type | `apk` |
| First seen | `2026-07-29 21:20:45` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, ICICI Bank, iMobile, Malware, Riskware, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f94f81384c09055ad220442654bd9119` |
| SHA-1 | `4a58bf3046d040dd03440280776b8c2d4f221637` |
| SHA-256 | `13bd0b75039576c6b5f249e507cb5de04300c83b2971edd94686659848c504c7` |
| SHA3-384 | `91f1fc1f76cb5f2293a2df800ebaeefd2a411e567ba22e6db5f24c0f4dd39bce8493e2f42667c7e1d5773ad4092e03a4` |
| TLSH | `T168C63302E71DB453C9F3A23A7F71472664275CA64712E2831A71F23C9DF7BC0EA59A90` |
| SSDEEP | `196608:rkV2mexLLi9wmRlVns6WXdFN5oYhfolHSedBy3BACbXApVn8kQwuNQ:dXFijnsPNFF2xdAxACbXQVn897NQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_13bd0b75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13bd0b75039576c6b5f249e507cb5de04300c83b2971edd94686659848c504c7"
    family = "unknown"
    file_name = "iMobile Lite.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:20:45"
  condition:
    hash.sha256(0, filesize) == "13bd0b75039576c6b5f249e507cb5de04300c83b2971edd94686659848c504c7"
}
```

### Sample 41: `6f65ac067cd914ac`

| Field | Value |
|---|---|
| SHA-256 | `6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337` |
| Family label | `WannaCry` |
| File name | `6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337` |
| File type | `exe` |
| First seen | `2026-07-29 21:15:27` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ac564e1f6b5b1fb1fa22cf419566ef0` |
| SHA-1 | `286e08273c64ff646c4de582bccbbf8861ea28a2` |
| SHA-256 | `6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337` |
| SHA3-384 | `180ca8b0442006beb793388429ec998c7d657ef0437090e8fc1ef6b6af912ea92e71a44fcce4372ae9d9915f3ab1db5a` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T18006239932AC81FCD1171670D0B78E25F273BC6E12BA470F97508A392E53B81BB64B57` |
| SSDEEP | `24576:jbLgBbLgurihdmMSirYbcMNgef0DHzoAdNLTSk+RdhAdmv:jnsnnMSPbcBVD3N3ARdhnv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_041_6f65ac06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337"
    family = "WannaCry"
    file_name = "6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337"
    file_type = "exe"
    first_seen = "2026-07-29 21:15:27"
  condition:
    hash.sha256(0, filesize) == "6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337"
}
```

### Sample 42: `5bee3cf919dc5bb9`

| Field | Value |
|---|---|
| SHA-256 | `5bee3cf919dc5bb90de4be716a5e035b05803c1618795382546a735629c79e2e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 21:14:09` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cae1190a9fea6022ed6c2bfa39cbd0f` |
| SHA-1 | `40d2fd45ad590390321bbead1ef8b89e23477e07` |
| SHA-256 | `5bee3cf919dc5bb90de4be716a5e035b05803c1618795382546a735629c79e2e` |
| SHA3-384 | `09896a4a8f3e4078ec931ad1639a3b5d9dd780eb0e07254f81d47dd1f2b6a832edfc70deec4476a0b11f9a8fc036d92a` |
| IMPHASH | `08fd62a9d05cc8111782017958ea975d` |
| TLSH | `T1BD25025AB1B580F5E16BC079CFD2925BE3B27445472093DF16A087BA1F177E0BD2A322` |
| SSDEEP | `12288:zNYl/0Val4vGewiuEhplWVzMu4I7x+I74TGP/jOXpwzNqVAIalcX9K8lWFcf6TGY:Il4vGd/IAt7b/yZwhXILf8NSk/v/hAwH` |
| ICON-DHASH | `f6b4a8ba6492985a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_5bee3cf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bee3cf919dc5bb90de4be716a5e035b05803c1618795382546a735629c79e2e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 21:14:09"
  condition:
    hash.sha256(0, filesize) == "5bee3cf919dc5bb90de4be716a5e035b05803c1618795382546a735629c79e2e"
}
```

### Sample 43: `04a7afdf922df7e6`

| Field | Value |
|---|---|
| SHA-256 | `04a7afdf922df7e62e68cdcdec70597bcb86d2831fb50665b6989ebe850a2a6f` |
| Family label | `Mirai` |
| File name | `zero.arc` |
| File type | `elf` |
| First seen | `2026-07-29 21:10:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a78335abd6297529ad5ca8dce43042fa` |
| SHA-1 | `8a872d379b294fe46d23bc42128b71f78dc91a90` |
| SHA-256 | `04a7afdf922df7e62e68cdcdec70597bcb86d2831fb50665b6989ebe850a2a6f` |
| SHA3-384 | `58942c7a3455830973341a6e37e599e9d12bdb2e1cc34af73f79516359a3b7890a0432e51d8f97a284378bc1e74cb2ae` |
| TLSH | `T155E3BF27724F1450C89641F54AEB9F5E3B3315809EAF59EBBCAE233BDA724CD1501BA0` |
| SSDEEP | `3072:zUGnMpA8mlhfcaj8me94y+3jZXtYs0qqfcnRDgJCTG5FMubCq:zUGnMpA8m/qWyIjBSAImUCTG5FbCq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_04a7afdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04a7afdf922df7e62e68cdcdec70597bcb86d2831fb50665b6989ebe850a2a6f"
    family = "Mirai"
    file_name = "zero.arc"
    file_type = "elf"
    first_seen = "2026-07-29 21:10:51"
  condition:
    hash.sha256(0, filesize) == "04a7afdf922df7e62e68cdcdec70597bcb86d2831fb50665b6989ebe850a2a6f"
}
```

### Sample 44: `dc923b4f2165fe6f`

| Field | Value |
|---|---|
| SHA-256 | `dc923b4f2165fe6f326f26f8739ceb3d3aea3e5b78bc8b091047fc677d0214ad` |
| Family label | `Mirai` |
| File name | `ya4` |
| File type | `elf` |
| First seen | `2026-07-29 21:00:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ad1f7c974926a2f1a78b56da3d2b49f` |
| SHA-1 | `ef5c8b05125cef8ed901f43f20838f6f638add82` |
| SHA-256 | `dc923b4f2165fe6f326f26f8739ceb3d3aea3e5b78bc8b091047fc677d0214ad` |
| SHA3-384 | `607ff034a072d21e2bad291c017b2604f87c7f62f06eb17850dfeb1ddb9c2326b80cc3b2e6aff362b83b09897c3b75f1` |
| TLSH | `T10AA3C71B2F619FACF3A9833497B74B30965C23D123E2C684D1ACD9012E7434E595F7AA` |
| TELFHASH | `t11631e519487812f4d3610d9d6eeefb31e0a170df29261e378f22ed5aee1d8428d10c1d` |
| SSDEEP | `1536:dQ8ZkBcaCn7FuLyEQEbJv/1iHGdgW8x7Q8puFs7dXav09TV3iDtR:b37FuWEQ+JX1VdgHbuFsBy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_dc923b4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc923b4f2165fe6f326f26f8739ceb3d3aea3e5b78bc8b091047fc677d0214ad"
    family = "Mirai"
    file_name = "ya4"
    file_type = "elf"
    first_seen = "2026-07-29 21:00:51"
  condition:
    hash.sha256(0, filesize) == "dc923b4f2165fe6f326f26f8739ceb3d3aea3e5b78bc8b091047fc677d0214ad"
}
```

### Sample 45: `ed2457fc9931b8af`

| Field | Value |
|---|---|
| SHA-256 | `ed2457fc9931b8af83ff1428339fd6acb8619b73cf0e82c2658180f8e718626d` |
| Family label | `Mirai` |
| File name | `y1V` |
| File type | `elf` |
| First seen | `2026-07-29 21:00:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38c9c210c20b01f91406d105b743f1da` |
| SHA-1 | `98f6d9d0625db76ace958f72879a23af49849555` |
| SHA-256 | `ed2457fc9931b8af83ff1428339fd6acb8619b73cf0e82c2658180f8e718626d` |
| SHA3-384 | `669db87b4227dc86d6152fcb1e2dc14b476a97c4a5a5c614456bc38c11790c809071bc3f1a4db573b32d735caab8e78f` |
| TLSH | `T13863196BB9918F15C1C1567AFE1D534D33132BB8E3DEB213EE042B652B8B46B0E2A405` |
| TELFHASH | `t135f08b29ce5c0add9be0c14188ff370455e0b1b27b006607eefc8f998111682729b41c` |
| SSDEEP | `1536:OxnPrZ5acdjPA7kBWv3pIcqAQKxV4iAwYieYWBJz4EWVMh:grBjI3IfAPxVREYWBJza` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_ed2457fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed2457fc9931b8af83ff1428339fd6acb8619b73cf0e82c2658180f8e718626d"
    family = "Mirai"
    file_name = "y1V"
    file_type = "elf"
    first_seen = "2026-07-29 21:00:50"
  condition:
    hash.sha256(0, filesize) == "ed2457fc9931b8af83ff1428339fd6acb8619b73cf0e82c2658180f8e718626d"
}
```

### Sample 46: `a1416a250bf7219f`

| Field | Value |
|---|---|
| SHA-256 | `a1416a250bf7219f95961f484421dda844b5013b5561c4a40591489dcfcdd384` |
| Family label | `unknown` |
| File name | `TikTok18.apk` |
| File type | `apk` |
| First seen | `2026-07-29 21:00:19` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, Malware, Spyware, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1ff75a46b2acb5a4355a3294d79e6e1` |
| SHA-1 | `12660cf55d5523314ce8d40e1407e4f6862597df` |
| SHA-256 | `a1416a250bf7219f95961f484421dda844b5013b5561c4a40591489dcfcdd384` |
| SHA3-384 | `b9443b7714a0aaaafa55dcdf5546123a60b33cc27d2df9a1d742cbffa6210ac247602795a05a805f9297bba564e438f5` |
| TLSH | `T10486225AFB48D85EC4B3133646765566410B1C66CF83E7839A90722C2EBB9C44E8BFCD` |
| SSDEEP | `196608:p1fK8qG7CRhh5m4fMQKGFbl2z4f3yxCnXzqTMo+mdR/:pH76hy4fM68zAmQHmdR/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_a1416a25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1416a250bf7219f95961f484421dda844b5013b5561c4a40591489dcfcdd384"
    family = "unknown"
    file_name = "TikTok18.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:00:19"
  condition:
    hash.sha256(0, filesize) == "a1416a250bf7219f95961f484421dda844b5013b5561c4a40591489dcfcdd384"
}
```

### Sample 47: `63898fa3645e69a3`

| Field | Value |
|---|---|
| SHA-256 | `63898fa3645e69a333f8ea158d0c4e7bb20a4265f0d4597f50ee2ffffc9df820` |
| Family label | `unknown` |
| File name | `SexySwipe.apk` |
| File type | `apk` |
| First seen | `2026-07-29 20:56:51` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Banker, Dropper, Malware, SpyAgent, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb9e804816df12760731d1a72089a1d9` |
| SHA-1 | `d7888df63014c0828ab8fc9bef4702990940a7aa` |
| SHA-256 | `63898fa3645e69a333f8ea158d0c4e7bb20a4265f0d4597f50ee2ffffc9df820` |
| SHA3-384 | `8a1fc033ecff32919d96cf1c46b4b67033c32577c28b2a6d359e6d3e02e0d1484dddee0b675f30b6fa95a6b6e537b886` |
| TLSH | `T1E815126BB308B8EBD6FF553FCDA398E802775E34C44B658B4850B6A401B33E6D709985` |
| SSDEEP | `24576:Dak8Dsilas9ZgaEjJGeAKXV93EqzOMMBIIIYee8MMBIIIYeeT:uke6sLgaEjjl93ES3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_63898fa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63898fa3645e69a333f8ea158d0c4e7bb20a4265f0d4597f50ee2ffffc9df820"
    family = "unknown"
    file_name = "SexySwipe.apk"
    file_type = "apk"
    first_seen = "2026-07-29 20:56:51"
  condition:
    hash.sha256(0, filesize) == "63898fa3645e69a333f8ea158d0c4e7bb20a4265f0d4597f50ee2ffffc9df820"
}
```

### Sample 48: `5d060c6fbf2dc9bc`

| Field | Value |
|---|---|
| SHA-256 | `5d060c6fbf2dc9bcb1131452aec575fc921e64c88828dc0faa78a9a09770e551` |
| Family label | `Mirai` |
| File name | `real_x86_64` |
| File type | `elf` |
| First seen | `2026-07-29 20:56:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bd7b0f48a59cc62986f4f4e48b40727` |
| SHA-1 | `d8adfcd6f82d766d6f7a9c9e117cf6a99063ae56` |
| SHA-256 | `5d060c6fbf2dc9bcb1131452aec575fc921e64c88828dc0faa78a9a09770e551` |
| SHA3-384 | `8792073765813bd4a8f16c002141865d36b1da8b34fab21d2642f750f4a148502bd94706670facdd4c2ae70043fa5932` |
| TLSH | `T13E058D1BB2B3B6BDC01BC03047DBC6714532F0756A322D7B27C49A383E9ADA5171AB65` |
| TELFHASH | `t1d4014e714b6065275752ce5498de6363252d896a9b0cfd7bd530850c21054fee637c8f` |
| SSDEEP | `12288:Nk5FWXrqxfxVetWTPR2aNgT59NnYdkH8Zqej2aL76b/HayUN0HXdqaBwhcq:NvXrqNxVeOPYaNgTz5aL7a4jaBw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_5d060c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d060c6fbf2dc9bcb1131452aec575fc921e64c88828dc0faa78a9a09770e551"
    family = "Mirai"
    file_name = "real_x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 20:56:44"
  condition:
    hash.sha256(0, filesize) == "5d060c6fbf2dc9bcb1131452aec575fc921e64c88828dc0faa78a9a09770e551"
}
```

### Sample 49: `b24e5a844ab93fe8`

| Field | Value |
|---|---|
| SHA-256 | `b24e5a844ab93fe8567b9f5937280cad8f3fdd4db0eeddd69079af1e8d7f31b2` |
| Family label | `unknown` |
| File name | `ssh_brute` |
| File type | `elf` |
| First seen | `2026-07-29 20:56:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9db07fd7c50faf86d61f44421c8a0501` |
| SHA-1 | `ced344ac6b9b8c28bfbd0d43c4bd1980aded86b5` |
| SHA-256 | `b24e5a844ab93fe8567b9f5937280cad8f3fdd4db0eeddd69079af1e8d7f31b2` |
| SHA3-384 | `1198fe1a687c75038bb08500c8479294f6a7de4c791a5c137b3d0fa3e2dcdb3f33be47655ff0007e7de1051a2781a5e1` |
| TLSH | `T133768D17FCA545A9C0EA9231897282527B71BC485B3123D73FA0F7382F76BD4AA79344` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:LdCmWRxMJBtyBoEJC+0ALz6f9sTe/ifpqXLBIHFZ3:LdCDxMJBMBBqfmSEELBIHFp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_b24e5a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b24e5a844ab93fe8567b9f5937280cad8f3fdd4db0eeddd69079af1e8d7f31b2"
    family = "unknown"
    file_name = "ssh_brute"
    file_type = "elf"
    first_seen = "2026-07-29 20:56:43"
  condition:
    hash.sha256(0, filesize) == "b24e5a844ab93fe8567b9f5937280cad8f3fdd4db0eeddd69079af1e8d7f31b2"
}
```

### Sample 50: `a58cdd282196a800`

| Field | Value |
|---|---|
| SHA-256 | `a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da` |
| Family label | `Stealc` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-07-29 20:52:42` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db05580a540923fc9018705a62224a36` |
| SHA-1 | `26cd2070839628f53add0f11f9352cd95bb134ef` |
| SHA-256 | `a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da` |
| SHA3-384 | `9c21364ef4ed726c6b04f9d5b0697bb5ccd7ed11321a085fe6f2ea27e89b9b0814b82780e720cf3b414082116eea6ebf` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T150952392A1D82269E4F6533305F143136F31BCA57BB60ADF15AC396E0F635E0E2B4B52` |
| SSDEEP | `49152:Z/hN1OaNOBOxcTTqZnK1MvMY8WOYXQCQEBy/wE:FzxcT2ZaMvf8IAClWw` |
| ICON-DHASH | `e8e8ececacf4d8e8` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_050_a58cdd28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-29 20:52:42"
  condition:
    hash.sha256(0, filesize) == "a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da"
}
```

### Sample 51: `d7676d0f24364b27`

| Field | Value |
|---|---|
| SHA-256 | `d7676d0f24364b278a6dd2b1c5fd34f688881cf3ff9e53e1e40f1b4048b7ce28` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 20:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b4e700f64175b020cf150e7e9586517` |
| SHA-1 | `a70da5f794a7c7775e0ee155ad07685da8114a09` |
| SHA-256 | `d7676d0f24364b278a6dd2b1c5fd34f688881cf3ff9e53e1e40f1b4048b7ce28` |
| SHA3-384 | `b6980231225408c311b003534978cce368ae1bda29b0eb8fee794146da93efb2caf40fe8cda02f8deeb3f36739fd048e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F7E633085AD093EFEAB7913CE9E255D6E669B0B36B31C4CF02D483151D271E0C93DA6B` |
| SSDEEP | `393216:vjRwlUDJrKxNSeYhBkFZKXMCHWUjX0cuI3/PGTAI:vmlUlr6SesBkFoXMb8XhH/O7` |
| ICON-DHASH | `e86864e0d8e8ec48` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_d7676d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7676d0f24364b278a6dd2b1c5fd34f688881cf3ff9e53e1e40f1b4048b7ce28"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 20:52:31"
  condition:
    hash.sha256(0, filesize) == "d7676d0f24364b278a6dd2b1c5fd34f688881cf3ff9e53e1e40f1b4048b7ce28"
}
```

### Sample 52: `66116ac63292be96`

| Field | Value |
|---|---|
| SHA-256 | `66116ac63292be96cc8a20fb991844fa378c19051a156f1c4dffb7db01b43dc2` |
| Family label | `Mirai` |
| File name | `HjEG` |
| File type | `elf` |
| First seen | `2026-07-29 20:32:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bfe958cf0059d28cca18c596506078d` |
| SHA-1 | `34d47f59fff7c7878bb9c1ace26a93bb7cf23bef` |
| SHA-256 | `66116ac63292be96cc8a20fb991844fa378c19051a156f1c4dffb7db01b43dc2` |
| SHA3-384 | `52ca93781f0fc813132f54df1a411668b22d202c317913540f1ccae674570cfc3ce42a6a39206eb285bb5fa9b09935bb` |
| TLSH | `T1B783175AB9419F05D0D526BAFF0E534A33536BB8E3EE7102EE142B2527CA91F0F3A401` |
| TELFHASH | `t166f081a0075d0dcd07f4c604c7ee57291c71b45e37004907bee9ef0745e21d3725921a` |
| SSDEEP | `1536:0FnF1YeTQ5SEnBGfBC46fvNWsD/Ry3dV2WqWNp02wdl1lieWVj57PI:a1YqrEBbvws7REdV2WqWNBYtWVjB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_66116ac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66116ac63292be96cc8a20fb991844fa378c19051a156f1c4dffb7db01b43dc2"
    family = "Mirai"
    file_name = "HjEG"
    file_type = "elf"
    first_seen = "2026-07-29 20:32:42"
  condition:
    hash.sha256(0, filesize) == "66116ac63292be96cc8a20fb991844fa378c19051a156f1c4dffb7db01b43dc2"
}
```

### Sample 53: `bd744729e85f0084`

| Field | Value |
|---|---|
| SHA-256 | `bd744729e85f0084857466fe1d3df9d5caacb8b1f7cb0ac2bac6067361907da9` |
| Family label | `Mirai` |
| File name | `RYb` |
| File type | `elf` |
| First seen | `2026-07-29 20:32:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c21376ca7a9fdb38c4a9cc2ae62cbc2` |
| SHA-1 | `479358d113de7a6f1d52147b65dcc5d58b52d9d9` |
| SHA-256 | `bd744729e85f0084857466fe1d3df9d5caacb8b1f7cb0ac2bac6067361907da9` |
| SHA3-384 | `dab40b9872e46c2a8bc4750b7e50de0a3bce85f298477332be735d414948fdfa2c353ae3ee1803ec33c4b0f21fc07eac` |
| TLSH | `T11CA3C84AAF611DBBD81BDD3705AD0B4235CCA60771683B723934D928FA4A54F8AD3CB4` |
| SSDEEP | `1536:TWAuojFRU1tftXcTBiA60g34SF83a6H5OQSJX4mMU4py70D5HPE9Sp:CAlqtftXciA6n83Ty` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_bd744729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd744729e85f0084857466fe1d3df9d5caacb8b1f7cb0ac2bac6067361907da9"
    family = "Mirai"
    file_name = "RYb"
    file_type = "elf"
    first_seen = "2026-07-29 20:32:41"
  condition:
    hash.sha256(0, filesize) == "bd744729e85f0084857466fe1d3df9d5caacb8b1f7cb0ac2bac6067361907da9"
}
```

### Sample 54: `36b19a238e94508c`

| Field | Value |
|---|---|
| SHA-256 | `36b19a238e94508cb66ee491f6c0f7c36ec07a938fd8cdf1ca292a864fba7f14` |
| Family label | `Mirai` |
| File name | `hix` |
| File type | `elf` |
| First seen | `2026-07-29 20:32:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b6cc90a605e5a2e65a67330b0d58ed9` |
| SHA-1 | `fa7c16641564df20ac2daed90fcacfa4f539747f` |
| SHA-256 | `36b19a238e94508cb66ee491f6c0f7c36ec07a938fd8cdf1ca292a864fba7f14` |
| SHA3-384 | `22c0c480c61e7ad995c303c7e1bdeca3e721c94609e9b884ffe0ba32d9da030cd450862120b040a37cce86e713b93ec5` |
| TLSH | `T123632A66B8419B16C2C16777FF1EC389332663E8E3DA7203DE152F5A338B41A0E3A555` |
| TELFHASH | `t1b8f0e135448b28dc79e8c144c2df43538d5432792200561c36ecde438493d53b22dc1d` |
| SSDEEP | `1536:i2UbdQCTvTGZc6QY4dKkhrUBvbJ/QU8Y8sZcM6lFHEoXnNNYG:i2UbeCTyUSkhUBzJ4UM+j0FHEAn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_36b19a23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36b19a238e94508cb66ee491f6c0f7c36ec07a938fd8cdf1ca292a864fba7f14"
    family = "Mirai"
    file_name = "hix"
    file_type = "elf"
    first_seen = "2026-07-29 20:32:39"
  condition:
    hash.sha256(0, filesize) == "36b19a238e94508cb66ee491f6c0f7c36ec07a938fd8cdf1ca292a864fba7f14"
}
```

### Sample 55: `2ec31f7f0ed881a6`

| Field | Value |
|---|---|
| SHA-256 | `2ec31f7f0ed881a6f33f44be53ddc89fff6f5f80390504093ddb4edccb46a830` |
| Family label | `RemusStealer` |
| File name | `MicrosoftEdge.exe` |
| File type | `exe` |
| First seen | `2026-07-29 20:30:20` |
| Reporter | `H3rm3s_` |
| Tags | `exe, Infostealer, REMUS, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f9f58a97a8fa8fdede17725cfd8d08d` |
| SHA-1 | `a46ce78b4c02141abd95cb3ea30453328fc01dba` |
| SHA-256 | `2ec31f7f0ed881a6f33f44be53ddc89fff6f5f80390504093ddb4edccb46a830` |
| SHA3-384 | `ed13622796e9839b86fedb85fa35b8f0ec540f95b745b1d2a79630bc3730257417b743826ea0b593554224e148606a6f` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1F2C55B47BCA119E5C0AEA2368932518ABB71BC441F3223D76E90B7782F73BD15C79709` |
| SSDEEP | `24576:0t00usaJ7iN3f1Z8pHeeEC9uESRLnJcR1hCVrjbUXMdPm2LQuGWsbAROL2OG:0t06aJ7ix1ZneEMu8krjYX+59OL2` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_055_2ec31f7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec31f7f0ed881a6f33f44be53ddc89fff6f5f80390504093ddb4edccb46a830"
    family = "RemusStealer"
    file_name = "MicrosoftEdge.exe"
    file_type = "exe"
    first_seen = "2026-07-29 20:30:20"
  condition:
    hash.sha256(0, filesize) == "2ec31f7f0ed881a6f33f44be53ddc89fff6f5f80390504093ddb4edccb46a830"
}
```

### Sample 56: `88536cf7df49585b`

| Field | Value |
|---|---|
| SHA-256 | `88536cf7df49585be4aa97e938b5ef5b5ccc46abbd2919010646a9a17281e3b5` |
| Family label | `NanoCore` |
| File name | `2c5a9aa5ca5b6d98a5551da0ec0be9af.exe` |
| File type | `exe` |
| First seen | `2026-07-29 20:20:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c5a9aa5ca5b6d98a5551da0ec0be9af` |
| SHA-1 | `b6a9ba6fdc95dcb5e78a5fa50a76f32f982b3125` |
| SHA-256 | `88536cf7df49585be4aa97e938b5ef5b5ccc46abbd2919010646a9a17281e3b5` |
| SHA3-384 | `1754fc1867575122b6f18cf99cc168ab848f54dc7d5f27e6693583e6ac2d834ef5c93e0c8bded2ae406dacfcf9f272dd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19914D0563BA84A2FE2DE8579712212139379C2E3E8C3F3DE28E451B64F567E50A071D3` |
| SSDEEP | `3072:szEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HI/1sC6wwBLsjAIZnB/nFgMbszD:sLV6Bta6dtJmakIM5O+LsjAcW/zhIRA` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_056_88536cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88536cf7df49585be4aa97e938b5ef5b5ccc46abbd2919010646a9a17281e3b5"
    family = "NanoCore"
    file_name = "2c5a9aa5ca5b6d98a5551da0ec0be9af.exe"
    file_type = "exe"
    first_seen = "2026-07-29 20:20:06"
  condition:
    hash.sha256(0, filesize) == "88536cf7df49585be4aa97e938b5ef5b5ccc46abbd2919010646a9a17281e3b5"
}
```

### Sample 57: `0c3424f930bd6ac0`

| Field | Value |
|---|---|
| SHA-256 | `0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434` |
| Family label | `Mirai` |
| File name | `0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434` |
| File type | `sh` |
| First seen | `2026-07-29 20:17:07` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdc88b642ec443885a8bdf5807e4f6e8` |
| SHA-1 | `610c426218084a4174a243434ec8c152ed1f6fc0` |
| SHA-256 | `0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434` |
| SHA3-384 | `105cd24e65eb3832aaf50155f13042d76ea683b2b49de71557ccc42cdca5a212a4206ca31623d6e292a9c32047da9a74` |
| TLSH | `T169316ACB00605A795303DADE7372361DB00C89FB289FDBA4DC080EAD96995CC72A5F95` |
| SSDEEP | `24:JNJ6i/h3EtjHYi+DSPQIPDjiQWiT1zNaN839hIE7L9:JNJ6i/h3EtjT+DSPL6c1zNaNGHtJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_0c3424f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434"
    family = "Mirai"
    file_name = "0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434"
    file_type = "sh"
    first_seen = "2026-07-29 20:17:07"
  condition:
    hash.sha256(0, filesize) == "0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434"
}
```

### Sample 58: `6a4d371a7e822157`

| Field | Value |
|---|---|
| SHA-256 | `6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2` |
| Family label | `WannaCry` |
| File name | `6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2` |
| File type | `exe` |
| First seen | `2026-07-29 20:15:29` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `609a433ec177c59a2667d9e29a15e17e` |
| SHA-1 | `a12df571520fe64a8847428e81d040176b8c6594` |
| SHA-256 | `6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2` |
| SHA3-384 | `1c687278732e64a2f9a9593c82ffd6b39e690d2ad6b71e82008f06a44d1c42fa9b669216865b6606e8843f12cbdb594d` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14A363398726C90FCE0450EB444B38D1AF7B37C5A67B64A1F4BC0877B0E53B9BAA94741` |
| SSDEEP | `98304:DI8cPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2H:DI8cPe1Cxcxk3ZAEUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_058_6a4d371a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2"
    family = "WannaCry"
    file_name = "6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2"
    file_type = "exe"
    first_seen = "2026-07-29 20:15:29"
  condition:
    hash.sha256(0, filesize) == "6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2"
}
```

### Sample 59: `d1b8110868977a69`

| Field | Value |
|---|---|
| SHA-256 | `d1b8110868977a697f191498c1bd2ff1ea7ca469d1a7632b07411236dd75002d` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-29 20:14:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34b7b98f441482c064c5265244cc9959` |
| SHA-1 | `2f775d263b7c7edb840185a5efaac8fc8caef3f5` |
| SHA-256 | `d1b8110868977a697f191498c1bd2ff1ea7ca469d1a7632b07411236dd75002d` |
| SHA3-384 | `21b19aeb76d5111be59b24c92134f2dff0a2824da0ccc151542f4650e2b44a416bb26cb4cd6a99f3c3e29070a866130c` |
| TLSH | `T197044A02772D0D03D1A32EB03B3B67E097EF999221A4B541345E6F9E9075E336946ECE` |
| SSDEEP | `3072:UcocDro3xdYKr7yKfIxHxN/G9Pfk2BcoC1J:1B3o3wKSxN/G9nVcoGJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_d1b81108
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b8110868977a697f191498c1bd2ff1ea7ca469d1a7632b07411236dd75002d"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-29 20:14:42"
  condition:
    hash.sha256(0, filesize) == "d1b8110868977a697f191498c1bd2ff1ea7ca469d1a7632b07411236dd75002d"
}
```

### Sample 60: `5d9ed51e8c68d43b`

| Field | Value |
|---|---|
| SHA-256 | `5d9ed51e8c68d43b9c2f8f6c9d18eef8f808a6f872115765a4cd2b43660cad8f` |
| Family label | `RemusStealer` |
| File name | `package.msi` |
| File type | `msi` |
| First seen | `2026-07-29 20:05:00` |
| Reporter | `H3rm3s_` |
| Tags | `dropper, msi, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d80e3c2a8ea8635e6337f6527b0bb4ad` |
| SHA-1 | `38afe2a4fdf706cb6f901e1cef624a673f6af165` |
| SHA-256 | `5d9ed51e8c68d43b9c2f8f6c9d18eef8f808a6f872115765a4cd2b43660cad8f` |
| SHA3-384 | `11ef4f75e0f43dac052b0cf89df364b43c130df6bd1071b670ef9f3ea836585cfe7586eaf6aa1acb751b103eb453deca` |
| TLSH | `T1194523D9374A5550DC215B3D0629C27627EEBCB74D92A409BBD5FA2C8F39AC01043AEF` |
| SSDEEP | `24576:Kh+7ToO+67FF/H+zSuHLk+6J/nXABk9dtwQnTKyiiRh7HdGM:YbOTBF/H2SurAXGIdtwWuyBh7H9` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_060_5d9ed51e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d9ed51e8c68d43b9c2f8f6c9d18eef8f808a6f872115765a4cd2b43660cad8f"
    family = "RemusStealer"
    file_name = "package.msi"
    file_type = "msi"
    first_seen = "2026-07-29 20:05:00"
  condition:
    hash.sha256(0, filesize) == "5d9ed51e8c68d43b9c2f8f6c9d18eef8f808a6f872115765a4cd2b43660cad8f"
}
```

### Sample 61: `eb8426a2c3842702`

| Field | Value |
|---|---|
| SHA-256 | `eb8426a2c384270297500f7ee836f38c6ba86eb981f8729304f0dc022e8e2754` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-29 20:02:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b98d443149c72fe624c2277d41d4b328` |
| SHA-1 | `f494a6d308cb6b9d4ffe5e7ebf29b06fc2f9730c` |
| SHA-256 | `eb8426a2c384270297500f7ee836f38c6ba86eb981f8729304f0dc022e8e2754` |
| SHA3-384 | `5db4476888c99fb50fc77565c02db3390ec8d9f071f4edc2c03345ebb9e40f807559ecd29be274d4e109bf27384c577d` |
| TLSH | `T1E5235C2516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF28C4A6ADD109B1D` |
| SSDEEP | `768:C+l9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:C+2cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_eb8426a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb8426a2c384270297500f7ee836f38c6ba86eb981f8729304f0dc022e8e2754"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-29 20:02:58"
  condition:
    hash.sha256(0, filesize) == "eb8426a2c384270297500f7ee836f38c6ba86eb981f8729304f0dc022e8e2754"
}
```

### Sample 62: `2fcaa054ede7ae26`

| Field | Value |
|---|---|
| SHA-256 | `2fcaa054ede7ae263d4479c83e122bc124b2c78b768ad653eb4511a95360fd3f` |
| Family label | `unknown` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-07-29 19:52:42` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `981ea5de867a785979783b1f13235d2a` |
| SHA-1 | `b06bc16b1b54ec93770ca8b47dc319f5f690dd9c` |
| SHA-256 | `2fcaa054ede7ae263d4479c83e122bc124b2c78b768ad653eb4511a95360fd3f` |
| SHA3-384 | `eab2f6cdabc214459b6541f09b42fc71daa3304151262f10ff917847f7be08396ed3711f217750e20c0f51498d48dae4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T118967B077CD108EAC0AE933189A65661BB74BC084B7573EB2F60B6392F727D19D36B50` |
| SSDEEP | `49152:OcUw5AgCHAlrZCUVV3BCJ51pwY5hJkzCUbEE7WmK:OCLTkwYjy2APo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_2fcaa054
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fcaa054ede7ae263d4479c83e122bc124b2c78b768ad653eb4511a95360fd3f"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-29 19:52:42"
  condition:
    hash.sha256(0, filesize) == "2fcaa054ede7ae263d4479c83e122bc124b2c78b768ad653eb4511a95360fd3f"
}
```

### Sample 63: `d0c0dc10447e81af`

| Field | Value |
|---|---|
| SHA-256 | `d0c0dc10447e81afa7b17ececeb7ad616a8a7b58fa9dbe70f03165fcea0a9f71` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-29 19:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e156047d9217122c15da13f2c8765a5` |
| SHA-1 | `69959abe409438a3f0a7b5a48c6ee0eba89e52f2` |
| SHA-256 | `d0c0dc10447e81afa7b17ececeb7ad616a8a7b58fa9dbe70f03165fcea0a9f71` |
| SHA3-384 | `c8ca297ae5839b7e94cfebd5a7d26e9f3baa30ccd119c725249239abea8d18adb1d4046a6f4e30b34576ab579e17aff9` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BCE6335467D021FEF6B2403DB8B21E97E9A578B60733C49F67A853526F032A44E38727` |
| SSDEEP | `393216:lgJyavLDOC3qMCYXMCHWUjXQcuI3/PGTAI:lgpLvnCYXMb8XFH/O7` |
| ICON-DHASH | `b271e8cccce8f0b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_d0c0dc10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0c0dc10447e81afa7b17ececeb7ad616a8a7b58fa9dbe70f03165fcea0a9f71"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 19:52:31"
  condition:
    hash.sha256(0, filesize) == "d0c0dc10447e81afa7b17ececeb7ad616a8a7b58fa9dbe70f03165fcea0a9f71"
}
```

### Sample 64: `3f661a590790cb90`

| Field | Value |
|---|---|
| SHA-256 | `3f661a590790cb90966dd89803bfa662abd8aa67bbf4d90e44888a48399597f9` |
| Family label | `Mirai` |
| File name | `bytetocrypt` |
| File type | `elf` |
| First seen | `2026-07-29 19:51:47` |
| Reporter | `smica83` |
| Tags | `ByteToBreach, elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a751ea8a6607d2922493d25509477157` |
| SHA-1 | `0a24f046d805011a692163372aae5524772ddc57` |
| SHA-256 | `3f661a590790cb90966dd89803bfa662abd8aa67bbf4d90e44888a48399597f9` |
| SHA3-384 | `f39ad1a4feb4a1c008e4ff0edbca3e560f7cb11e773a26ad824f00cca65e6eb5cdd92b3f7bdd23add65cb8250bb56364` |
| TLSH | `T1A316AE5AB5BC0877D88AC8B0C38ED3825E3474A805D1606B7E5526E53F69F705EBBF02` |
| SSDEEP | `49152:Id7Sm0loRyVMriA8OcEX+CfGziviONbA1PDijvszlQCKsCck7PbwA2ghE+YIB6TQ:ztjVtnHziaONyLyN37qghJkl9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_3f661a59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f661a590790cb90966dd89803bfa662abd8aa67bbf4d90e44888a48399597f9"
    family = "Mirai"
    file_name = "bytetocrypt"
    file_type = "elf"
    first_seen = "2026-07-29 19:51:47"
  condition:
    hash.sha256(0, filesize) == "3f661a590790cb90966dd89803bfa662abd8aa67bbf4d90e44888a48399597f9"
}
```

### Sample 65: `03cba07268c420c1`

| Field | Value |
|---|---|
| SHA-256 | `03cba07268c420c1e208547cbb7162fa0f34176c8949fc5cb279cef06e94e90d` |
| Family label | `Mirai` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-29 19:50:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eadd80203a866a7eb9525e228cc46a42` |
| SHA-1 | `8393c48b171ada1b49980d29146b20911e00f3d0` |
| SHA-256 | `03cba07268c420c1e208547cbb7162fa0f34176c8949fc5cb279cef06e94e90d` |
| SHA3-384 | `50495ae6c5569ce1ad655787af1e240c78224a197b053236f809224b8b4395763d80aec8ddeb6d98a66e3c439efa5bcc` |
| TLSH | `T12701ABCAE1609D00809A981D22EB9554F830C7C7254B4BA9FFACE43E9B98D14F076F84` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaxECwVgjCS5rF5FCrqhdCcyCJN8ZX:kXCKysE2hi0ziQvZohaxEBortdb6DX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_03cba072
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03cba07268c420c1e208547cbb7162fa0f34176c8949fc5cb279cef06e94e90d"
    family = "Mirai"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-29 19:50:42"
  condition:
    hash.sha256(0, filesize) == "03cba07268c420c1e208547cbb7162fa0f34176c8949fc5cb279cef06e94e90d"
}
```

### Sample 66: `97c77f02acfa0a62`

| Field | Value |
|---|---|
| SHA-256 | `97c77f02acfa0a62992da06101c5e07e713b68f58e59098a209030a06ff2aa2e` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-29 19:48:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa3dd10879cd98e1e3327b96c6f6a6f3` |
| SHA-1 | `12bd22be8975c4d169a74e5c0cec7f4883b01191` |
| SHA-256 | `97c77f02acfa0a62992da06101c5e07e713b68f58e59098a209030a06ff2aa2e` |
| SHA3-384 | `2ae949ee9572671c02b28389830a3264baa8777dee8a9ccbf6a6dbb3316fbef13f5528dd8d39c432bd85615951e60353` |
| TLSH | `T17DC34DC0F243E6F5D84605715037E732DB76D6E6211DEE43E398DA3AAC62842C91AE9C` |
| TELFHASH | `t1de51b6f90a7e0cf8abd49802e20e5f766d5da67b252076a144b3dc74336fd4650bac38` |
| SSDEEP | `1536:EX+Dp51T9e5sSyvaiR6xSEL0KjpURSCmPoQLSqcBLkb9EJD7p:Xl51T9e5oaiAIlspQSXPRGTp1F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_97c77f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c77f02acfa0a62992da06101c5e07e713b68f58e59098a209030a06ff2aa2e"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-29 19:48:45"
  condition:
    hash.sha256(0, filesize) == "97c77f02acfa0a62992da06101c5e07e713b68f58e59098a209030a06ff2aa2e"
}
```

### Sample 67: `6bdedd8343999e8e`

| Field | Value |
|---|---|
| SHA-256 | `6bdedd8343999e8e0fce00858ee8fe47c1e42e27db2a217d4cdb689e048b5522` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-29 19:48:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f493aac6f5c916ae211fa607e46d03e8` |
| SHA-1 | `f133283253256346357bb37bd9bd5dc8d9d4914c` |
| SHA-256 | `6bdedd8343999e8e0fce00858ee8fe47c1e42e27db2a217d4cdb689e048b5522` |
| SHA3-384 | `c81fb92860764c77304a674c591ed528045bf6b259575e199e3bbe20eb30044906a565d1e7cb02c318ea061761ebd804` |
| TLSH | `T1BA631885FC915B2AC2C117BAB5BE668D3724A3F493CE3113EC214B253BC951F4936E86` |
| TELFHASH | `t18ce02200bc699e2a69c79a70dced07a89501a12310768b108f14dbe4c83f118920ca4e` |
| SSDEEP | `1536:U+YC7svXl30oFPZWN6YNM+oZ0K1a10rb9EJ:U+YCwiE8N6YEM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_6bdedd83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bdedd8343999e8e0fce00858ee8fe47c1e42e27db2a217d4cdb689e048b5522"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-29 19:48:44"
  condition:
    hash.sha256(0, filesize) == "6bdedd8343999e8e0fce00858ee8fe47c1e42e27db2a217d4cdb689e048b5522"
}
```

### Sample 68: `f051f14146e69ffd`

| Field | Value |
|---|---|
| SHA-256 | `f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538` |
| Family label | `unknown` |
| File name | `f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538` |
| File type | `exe` |
| First seen | `2026-07-29 19:48:02` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e14169bf40da9dad9f5da6c6658366a` |
| SHA-1 | `daf8e4e1e763fb653b7f62f4f822716b3ac1444b` |
| SHA-256 | `f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538` |
| SHA3-384 | `85d4a8af8c54f14c84b62f37182f985795371ffd889803b8d7eebdd9f8402dfd1325fabff23947fc179e1b528356d5d3` |
| IMPHASH | `c556f65b0320cbea87f199fb45a6de9e` |
| TLSH | `T138047D46B3A500BBE5B7C639CD631646E772780207609BDF03A042767F6B7D09D3AB62` |
| SSDEEP | `3072:hPiLnXpwGEhFb7ihrSer2pz655YaLv0Ved7/lpCwX:ALXOBzbmdrYz62edbPX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_f051f141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538"
    family = "unknown"
    file_name = "f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538"
    file_type = "exe"
    first_seen = "2026-07-29 19:48:02"
  condition:
    hash.sha256(0, filesize) == "f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538"
}
```

### Sample 69: `bf38ae8c1b495b2a`

| Field | Value |
|---|---|
| SHA-256 | `bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8` |
| Family label | `unknown` |
| File name | `bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8` |
| File type | `exe` |
| First seen | `2026-07-29 19:47:54` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c79eae94b61b603d34ac50fadd2755aa` |
| SHA-1 | `807b6700644854b9b4f84c21dac86b384b50c2ef` |
| SHA-256 | `bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8` |
| SHA3-384 | `6fafca927cf0f8a0314a3a0720fc6ef0bc51c54dd0a40ab1b4922f98d9e0823a21cd788b6476971e5bdb97b64166a0b1` |
| IMPHASH | `bf949854a0fc6d2bcf5bacdd08688a0d` |
| TLSH | `T1C9749EA5BB5F4463FDE58035405288CCB37964ED89017AAE8AC6721E0D17EE40EFAF74` |
| SSDEEP | `6144:KWpPOSAUwgQesDdDtHLQUt/K6UCknPhcgrrdEmhxKZqdjmDTI:jlOgQesxVQUtC6+n5cJmhx92T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_bf38ae8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8"
    family = "unknown"
    file_name = "bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:54"
  condition:
    hash.sha256(0, filesize) == "bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8"
}
```

### Sample 70: `bc9c4e81bc9acd2a`

| Field | Value |
|---|---|
| SHA-256 | `bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e` |
| Family label | `unknown` |
| File name | `bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e` |
| File type | `exe` |
| First seen | `2026-07-29 19:47:45` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fe4d138aef4c2a91e0ccf17cac22abb` |
| SHA-1 | `91ceedd5aa38c5e79e0facc25303a5178b305f38` |
| SHA-256 | `bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e` |
| SHA3-384 | `ecae6b94a06a7c4bac21161d34c59acce79c9df8b2a21d978432ee67b3809a44b14b0b917607790b3d5966620477dbf3` |
| IMPHASH | `5c9da646790c3ac480cd4ddda3f760f4` |
| TLSH | `T173F38E1BB3A510BBE1B79739C9630645F776B81147209BEF03A443662F237D19E3AB21` |
| SSDEEP | `3072:UXXbVf4dfaWxXBsmquKeVfJGYz1CYvsZOM22bKR4:Uhwd5xXmchGYUZZ2ic4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_bc9c4e81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e"
    family = "unknown"
    file_name = "bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:45"
  condition:
    hash.sha256(0, filesize) == "bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e"
}
```

### Sample 71: `af5a2f1b7e388d4f`

| Field | Value |
|---|---|
| SHA-256 | `af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a` |
| Family label | `unknown` |
| File name | `af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a` |
| File type | `exe` |
| First seen | `2026-07-29 19:47:38` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1ed84cdb056b981f901ffa5f1c7b4d9` |
| SHA-1 | `c420aa7625a990af7b93b58ec24aa3ecd0a4a679` |
| SHA-256 | `af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a` |
| SHA3-384 | `be7298c0d6ca03fe78a8969cec0b9842f1d4c81985b6d2cfaf410a171f9a21f07d7a8712a0624233fc489335876dba64` |
| IMPHASH | `5c9da646790c3ac480cd4ddda3f760f4` |
| TLSH | `T124F38D5BB3A510FBE0779638C9630645E776B81107609BEF03A4427A2F237D19E3EB61` |
| SSDEEP | `3072:Z83TfPFAz6pK+u/euY5Zn1rjlHnvNj3FE71+nw+:ZufP86JQGZn/Xnw+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_af5a2f1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a"
    family = "unknown"
    file_name = "af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:38"
  condition:
    hash.sha256(0, filesize) == "af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a"
}
```

### Sample 72: `78906623ce30eba7`

| Field | Value |
|---|---|
| SHA-256 | `78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e` |
| Family label | `unknown` |
| File name | `78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e` |
| File type | `exe` |
| First seen | `2026-07-29 19:47:25` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `732ca97070f214e5622d78ab17e9f205` |
| SHA-1 | `b5e01bed601b42966fc7ae98826d9782b8cb486c` |
| SHA-256 | `78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e` |
| SHA3-384 | `dd7ac0c189cbfa0a2329ff31b18c01272ee02103fb0e7b3773c35d2e484fc9ba832ad493f7276e9005d075b12d75c00f` |
| IMPHASH | `bf949854a0fc6d2bcf5bacdd08688a0d` |
| TLSH | `T196747E1699A5B0C6E01B9A339233D517CF75BEB59A63E35FC269924B0E333804F26DD0` |
| SSDEEP | `6144:wWpPOSAUwgQesP9WfVntuOI3nItmG4soji:RlOgQeslEVtudI6E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_78906623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e"
    family = "unknown"
    file_name = "78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:25"
  condition:
    hash.sha256(0, filesize) == "78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e"
}
```

### Sample 73: `a01634a49545e05d`

| Field | Value |
|---|---|
| SHA-256 | `a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a` |
| Family label | `unknown` |
| File name | `a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a` |
| File type | `exe` |
| First seen | `2026-07-29 19:47:06` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01ca373cfe9d3ef889aa428177d045a7` |
| SHA-1 | `36ea122f42d68a773ea5be1a386eb203a309334a` |
| SHA-256 | `a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a` |
| SHA3-384 | `04ed06caa5ba3d4f8f66df41af3e4ae2452072dddc5b2ec999fc7bd20243e5c5b3bb24c7ca59661d152203ad9bbf0c86` |
| IMPHASH | `741f0bf68a28ce3a873985d135617016` |
| TLSH | `T1AED45B5238D5149AC13782F2CF93E1749713FC781DA4852FA2CD2E165F0AEA12D63AF6` |
| SSDEEP | `6144:IXfpmxRVpsvPF50xj8niAhoDsAiv5pTGBNN9hR5wKHqj6f3rdJhnt/eGWv4r4BMA:IXxmQvDiUXTsN9hMjsLeJMqj4zWY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_a01634a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a"
    family = "unknown"
    file_name = "a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:06"
  condition:
    hash.sha256(0, filesize) == "a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a"
}
```

### Sample 74: `f552f87811e0ac4c`

| Field | Value |
|---|---|
| SHA-256 | `f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a` |
| Family label | `unknown` |
| File name | `f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a` |
| File type | `exe` |
| First seen | `2026-07-29 19:46:55` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `982a04e87ee9784ae34a059f94e13c47` |
| SHA-1 | `143de44afc38923c93a7d3c312c12e98378ac7c5` |
| SHA-256 | `f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a` |
| SHA3-384 | `fde48d1911c7e7eafd8f321b8a39c8f8f19538027b13d2a14f6a9d01e85eb22deee918343bac0fbdfcf44bcf881c245a` |
| IMPHASH | `741f0bf68a28ce3a873985d135617016` |
| TLSH | `T1AAD46B5238D514DAC13682F2CF93E1749713FC781DA4852BA2CD2E165F0AEA12D63EF6` |
| SSDEEP | `6144:I+Dh1PrCbTsyit1xj8niAhoDsAiv5pTGBNN9hR5wKHqj6f3rdJhnt/eGWv4r4BMF:I+d1TrtAiUXTsN9hMjsLeJMqj4zWY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_f552f878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a"
    family = "unknown"
    file_name = "f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a"
    file_type = "exe"
    first_seen = "2026-07-29 19:46:55"
  condition:
    hash.sha256(0, filesize) == "f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a"
}
```

### Sample 75: `8d0c4a2565d38c92`

| Field | Value |
|---|---|
| SHA-256 | `8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55` |
| Family label | `unknown` |
| File name | `8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55` |
| File type | `exe` |
| First seen | `2026-07-29 19:46:43` |
| Reporter | `anonymous` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e03f4c8c1facef9dc3148bf534fb50be` |
| SHA-1 | `5d2192bba4949cb6a02ca08c59e282a60f5bd7c2` |
| SHA-256 | `8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55` |
| SHA3-384 | `f8776d75c960f980f720f0bd83b0818e5d9038ae6d3ac413bbf1fe724719dba05ca010e1d6368871b82d5457a702d709` |
| IMPHASH | `741f0bf68a28ce3a873985d135617016` |
| TLSH | `T13AD46C5239D5189AC13682F2CF93E1749713FC751DA0852FA2CD2E165F0AEA12D23EF6` |
| SSDEEP | `6144:r+txhFHnCbTsO6tTFjonCwxuFkQGvnT9yBbdJXtN+onVdz4QLr8WrnRmmW7IrjiI:r+tzFPfta+gT9udJX1S0mGij4/4DO8m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_8d0c4a25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55"
    family = "unknown"
    file_name = "8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55"
    file_type = "exe"
    first_seen = "2026-07-29 19:46:43"
  condition:
    hash.sha256(0, filesize) == "8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55"
}
```

### Sample 76: `816f1f4df1f3964c`

| Field | Value |
|---|---|
| SHA-256 | `816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6` |
| Family label | `unknown` |
| File name | `816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6` |
| File type | `exe` |
| First seen | `2026-07-29 19:46:33` |
| Reporter | `anonymous` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b73f3e8401225bb90f898d0aa41793e` |
| SHA-1 | `0322d5384822d076c5c0ddc16ed8a661dc5ee782` |
| SHA-256 | `816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6` |
| SHA3-384 | `a1e541bcb8046198f7f16dc947deed80098d89116553f9622db286eca45db62ff740bd229b10cf7e17e3a04ac7ada9e9` |
| IMPHASH | `39e02ffded34b5af420a331c1a5785d1` |
| TLSH | `T197D46B6234D518D9C136C2F2CF97E1749713FC751DA0852BA2CD2E166F0AEA12D23AF6` |
| SSDEEP | `6144:bGHmpYLsPpb38nw+6FBn83VZp9v34pR/xrYkVz9NRlzDJfLPcUz+AcAC+rNYjihb:iHGPK6rOjpl3C/x/Vpz16GjYjiF7cQ6g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_816f1f4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6"
    family = "unknown"
    file_name = "816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6"
    file_type = "exe"
    first_seen = "2026-07-29 19:46:33"
  condition:
    hash.sha256(0, filesize) == "816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6"
}
```

### Sample 77: `5ce2d378811c84c0`

| Field | Value |
|---|---|
| SHA-256 | `5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae` |
| Family label | `unknown` |
| File name | `5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae` |
| File type | `unknown` |
| First seen | `2026-07-29 19:46:15` |
| Reporter | `anonymous` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae8bfd798e2096f07e09df8e799312e5` |
| SHA-256 | `5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_5ce2d378
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae"
    family = "unknown"
    file_name = "5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae"
    file_type = "unknown"
    first_seen = "2026-07-29 19:46:15"
  condition:
    hash.sha256(0, filesize) == "5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae"
}
```

### Sample 78: `a2a67bc564e7dae8`

| Field | Value |
|---|---|
| SHA-256 | `a2a67bc564e7dae8ebb3bf87368df309c1a5cb80b007872adc294e5da76106e4` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-07-29 19:32:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce4846fef2fbeccd49e6c1fc35481276` |
| SHA-1 | `63fe070a14ba6d01ed9e49f4f9dce6fc2f2a7854` |
| SHA-256 | `a2a67bc564e7dae8ebb3bf87368df309c1a5cb80b007872adc294e5da76106e4` |
| SHA3-384 | `9d223a8cc29d8fa5feb7f6271427c061d9085fb1e0d4aeec6e72104ca2ac7a71b377a1076f08fd903ffb7f288fb85746` |
| TLSH | `T138730981BC80AA2AC7C01677EE6F509D3300A7D9D2DA3742DD581BB4BB8E81F0D57B56` |
| TELFHASH | `t17ae06840bc76862888d6aab4ad9d07b19601a21250178b20cf20d5e0d83f448e308e6a` |
| SSDEEP | `1536:x5onZdJ8XbE/V9qlMyEDqTUuSDzcjl8t4VEc3Xgx+:xGnZgXS8DGz484qiQY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_a2a67bc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2a67bc564e7dae8ebb3bf87368df309c1a5cb80b007872adc294e5da76106e4"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-07-29 19:32:41"
  condition:
    hash.sha256(0, filesize) == "a2a67bc564e7dae8ebb3bf87368df309c1a5cb80b007872adc294e5da76106e4"
}
```

### Sample 79: `d6a3c1e20b5ee7b1`

| Field | Value |
|---|---|
| SHA-256 | `d6a3c1e20b5ee7b111614d914b286bc1d0d4bfd5f6663893a4478ab28c6c2e58` |
| Family label | `unknown` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-07-29 19:32:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb54f4b533db5588503feccc7e917842` |
| SHA-1 | `bb60717d92493306ddd976b261c0dc4d0448019f` |
| SHA-256 | `d6a3c1e20b5ee7b111614d914b286bc1d0d4bfd5f6663893a4478ab28c6c2e58` |
| SHA3-384 | `b96b514f534c43db62f8a63d00a193a4371d353ae421e1d94366ea505292b0e9e9fa10ff5b3fe345b904f701bcc8a7f2` |
| TLSH | `T143E3AFA7F74F1450C82107F41BCB5BAD2A3325018E6B56E66C2E773E6A739DB18063D1` |
| SSDEEP | `3072:rmO09bfVP2weXXGABBx2n+vNn9njgYCSfZDIGdq:rmO0tdLeXTBT2S9nRCSBDZq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_d6a3c1e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6a3c1e20b5ee7b111614d914b286bc1d0d4bfd5f6663893a4478ab28c6c2e58"
    family = "unknown"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-29 19:32:40"
  condition:
    hash.sha256(0, filesize) == "d6a3c1e20b5ee7b111614d914b286bc1d0d4bfd5f6663893a4478ab28c6c2e58"
}
```

### Sample 80: `77580df28349934b`

| Field | Value |
|---|---|
| SHA-256 | `77580df28349934bc9b326713207109426c53962fa030405668004c2175d519b` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-07-29 19:22:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9017ea42eac2a02697bfcd5b7f14bcb` |
| SHA-1 | `621b75f72e90baff3174aab0a628a575297500e3` |
| SHA-256 | `77580df28349934bc9b326713207109426c53962fa030405668004c2175d519b` |
| SHA3-384 | `bb2feda7c81bf4e04d71f64208242ffe8853f0763a8601cdb08272758a59fd598f8c73a86a3ba9bac45761725262aa0f` |
| TLSH | `T1A0E31A56F9819F11D5C151BAFF0E128E33131B7CE2DE72129D24AB707B8A8BB0E3A515` |
| TELFHASH | `t165f081f1836605ecb7c5c74102dd271dc7cc742d0600241992dc675fc6625db751a43a` |
| SSDEEP | `3072:c7mAoCw7QsuWvDetOOTraSiG6FlYBY+NEgYDLgSi/tQj9Usg:c7/obvuuStOOfaHG6FW3NuDLg/teXg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_77580df2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77580df28349934bc9b326713207109426c53962fa030405668004c2175d519b"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-29 19:22:44"
  condition:
    hash.sha256(0, filesize) == "77580df28349934bc9b326713207109426c53962fa030405668004c2175d519b"
}
```

### Sample 81: `2ad53cce04d81baa`

| Field | Value |
|---|---|
| SHA-256 | `2ad53cce04d81baa4eb732c88d465743c45a5ef4349d71d18759f715848c8f9e` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-07-29 19:22:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d643aa6bb955919a965eeda5fb897faa` |
| SHA-1 | `4cf9d0feb89137944454e13eaadaf34ff8241d6f` |
| SHA-256 | `2ad53cce04d81baa4eb732c88d465743c45a5ef4349d71d18759f715848c8f9e` |
| SHA3-384 | `e5e198fd6167d7f5e416d6203f1bcadf891f4a7079f8aed895fdd803a7d0a32b9ed6fdc3a48ba8d47f4f56c986f34e52` |
| TLSH | `T194D30945FC445F57CAC225BBFF4E438C772A1768E2EE720399256B60378B85B0E3A241` |
| TELFHASH | `t19f21f1f24e482eec73c4c158d1bfa46b0eac34b8173121676d6abb4e87939d5f51442e` |
| SSDEEP | `3072:nsy+Achgd7xDbCxwx6ZzhSgNIitth+UFN:nO6F1bCxwcZzNIIX+UFN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_2ad53cce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad53cce04d81baa4eb732c88d465743c45a5ef4349d71d18759f715848c8f9e"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-29 19:22:42"
  condition:
    hash.sha256(0, filesize) == "2ad53cce04d81baa4eb732c88d465743c45a5ef4349d71d18759f715848c8f9e"
}
```

### Sample 82: `ddfc434ed42759bb`

| Field | Value |
|---|---|
| SHA-256 | `ddfc434ed42759bb027f8aa7ba857e1955a462000d7f128b8f2987995864e4eb` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-29 19:21:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `addddd198dd0a396b85c6cb91caf64a4` |
| SHA-1 | `5820f36c43394c42807045dce087fd68cd72ec75` |
| SHA-256 | `ddfc434ed42759bb027f8aa7ba857e1955a462000d7f128b8f2987995864e4eb` |
| SHA3-384 | `ce9ee6f1a3dc13eee5cea01dca6a52f60746273d060bf6f5618cf237076c12cd74998c15c7c0ce658a9e885ef1e618fd` |
| TLSH | `T1D0E35B17B5C190FEC8D9D1B88BEAF626DA33B4291134721E27C86F2B2E4DE205F5D650` |
| TELFHASH | `t1d851deb13ea92c4471e3b63ab306e9a55c760a1519e031d2deb3b8e5af137840e72437` |
| SSDEEP | `3072:qm73/ShoBu/N99181+A1vlzkYsmEq3jQELBKwlua4TEM:QiF1zrfJX4nTEM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_ddfc434e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddfc434ed42759bb027f8aa7ba857e1955a462000d7f128b8f2987995864e4eb"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 19:21:45"
  condition:
    hash.sha256(0, filesize) == "ddfc434ed42759bb027f8aa7ba857e1955a462000d7f128b8f2987995864e4eb"
}
```

### Sample 83: `9378b08d1f873cc7`

| Field | Value |
|---|---|
| SHA-256 | `9378b08d1f873cc78b3eae058a3f5533590d932a53a0f8ca1a9d7a3533398773` |
| Family label | `Mirai` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-29 19:20:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8cd4a24157de566ca3116fbc625e369` |
| SHA-1 | `df90031c5626504451c10a5f6c26cf927e0e7435` |
| SHA-256 | `9378b08d1f873cc78b3eae058a3f5533590d932a53a0f8ca1a9d7a3533398773` |
| SHA3-384 | `d637005671115b8c24af8575ee7446bbbecab0ebe3ab0f63e7c25b3f0e5f49020c8e587d9fae35985f5dc2ca31d5b7cb` |
| TLSH | `T149016BCAE2609D108019D81E22EA9690B430C7C7554B0FA8FFDC943EEB98D14F066F98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaxECwMjCS5rrF5FCrqzxdCmyCJN8TauD:kXCKysE2hi0ziQvZohaxEYr3JdHOF7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_9378b08d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9378b08d1f873cc78b3eae058a3f5533590d932a53a0f8ca1a9d7a3533398773"
    family = "Mirai"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-29 19:20:42"
  condition:
    hash.sha256(0, filesize) == "9378b08d1f873cc78b3eae058a3f5533590d932a53a0f8ca1a9d7a3533398773"
}
```

### Sample 84: `b14e42aa75e85d5e`

| Field | Value |
|---|---|
| SHA-256 | `b14e42aa75e85d5e0d14e831bf7988f0e235cb5e1d48255a637dac7548e4a4e6` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-29 19:20:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `387bee10cc8c313cda5c3d717319eb80` |
| SHA-1 | `dff89c9ec45147d4ddc371279fa1e56139fd806c` |
| SHA-256 | `b14e42aa75e85d5e0d14e831bf7988f0e235cb5e1d48255a637dac7548e4a4e6` |
| SHA3-384 | `72c999db592ef5464b6ccb2a2876d40a45fa997e8888182df170a59519d8a28fd1dbc2532a5c763d9ad7ade57059650a` |
| TLSH | `T1F543F1F3A277E370C61B1AB77E57FD41C62828858A099F1B6DC061B8F5612CCB9302A5` |
| SSDEEP | `768:5ygEx53yPGEQQWZoodBL75IKld+O8qJ+xEHNhnAugCgIbeBxmF9dYLTUd5lQ7Aku:5nq+n/hodJaad+QJdhnAuN5beGHRdwHu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_b14e42aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b14e42aa75e85d5e0d14e831bf7988f0e235cb5e1d48255a637dac7548e4a4e6"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 19:20:41"
  condition:
    hash.sha256(0, filesize) == "b14e42aa75e85d5e0d14e831bf7988f0e235cb5e1d48255a637dac7548e4a4e6"
}
```

### Sample 85: `67f3574076af6c92`

| Field | Value |
|---|---|
| SHA-256 | `67f3574076af6c924ace8cd5352e99b7d9c756e7ef72ee356acdae0250f22307` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-29 19:20:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9939d74c60037938ef085b7dba70269a` |
| SHA-1 | `ce23d55556723aa6db15796afc136ce659f2cd9e` |
| SHA-256 | `67f3574076af6c924ace8cd5352e99b7d9c756e7ef72ee356acdae0250f22307` |
| SHA3-384 | `5319ba98232f2681fa96dd5cd7ed1316e16eec893842fe4ee63625f8029701768d1062843ae3ac81fd28c8d2807f06db` |
| TLSH | `T1A504B81A6F228F7DF268C73047B74A35976D23D627E1D684E2ACC1142F6029E541FFA8` |
| TELFHASH | `t1e04186180e7817b067755c9e499dfb36d6a330db7f265c338e61e86aeb69a428d10c0c` |
| SSDEEP | `3072:Y1yIlu0jwI473wnTG28fa42MK98GAuuEbGXaxeVZizuJKlcF42D8:Y1yIlu0UATG2zMd7dmXePgwKlc+2D8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_67f35740
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67f3574076af6c924ace8cd5352e99b7d9c756e7ef72ee356acdae0250f22307"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-29 19:20:40"
  condition:
    hash.sha256(0, filesize) == "67f3574076af6c924ace8cd5352e99b7d9c756e7ef72ee356acdae0250f22307"
}
```

### Sample 86: `5a6a5d0a5fa64dd0`

| Field | Value |
|---|---|
| SHA-256 | `5a6a5d0a5fa64dd08476f2e9ed9dfacd92b4a142777fee5d37b5c05fbb972c2c` |
| Family label | `unknown` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-29 19:16:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16d0dfb8e6a93f5b3b409ff2c79f57a3` |
| SHA-1 | `dc6997c1785236b7711bfa11856b8fb6aefaf5a5` |
| SHA-256 | `5a6a5d0a5fa64dd08476f2e9ed9dfacd92b4a142777fee5d37b5c05fbb972c2c` |
| SHA3-384 | `64913647fd1288590c5bde9c7fc01a7a7e9b2323491068c0a8966e452c040fae6bc0ef5a415453c7930ebe258cb33015` |
| TLSH | `T1B1C35A73CC352F58C664E5B5B0B08F7A6B53A824814B5FBA5877C2788083D8DF6467B8` |
| SSDEEP | `3072:bMv475R9k360PCKScU2FOdWEWKJggtlog:bN75R9kq0KLboEWKVX7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_5a6a5d0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a6a5d0a5fa64dd08476f2e9ed9dfacd92b4a142777fee5d37b5c05fbb972c2c"
    family = "unknown"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-29 19:16:48"
  condition:
    hash.sha256(0, filesize) == "5a6a5d0a5fa64dd08476f2e9ed9dfacd92b4a142777fee5d37b5c05fbb972c2c"
}
```

### Sample 87: `ebd140217102e211`

| Field | Value |
|---|---|
| SHA-256 | `ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-29 19:16:37` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6edb9c07dccb6bbf836fb28a6560e921` |
| SHA-1 | `eecbc3e7c7477bf7be9540285f1858fd8f237e3c` |
| SHA-256 | `ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8` |
| SHA3-384 | `0e6d4087df82b2de29afb6acfa452525dba3f56436e12a249e7d0f35e516cbc8ea88b8c16d86632ae36ce55073f395be` |
| IMPHASH | `b8b034a37970476c0e8791d5941c31e3` |
| TLSH | `T10F622B0EAA818035EAD10076827F422745BD6C7223D4BDDBF7A068CA5EB47D1F43156F` |
| SSDEEP | `192:AX7wkiyXgzhDDAyxdq4lKQe33hg/FeaFResJKUSfTzwbkQaesmJxTmv8U9cthb9l:AZi3DAybqFBg/Uf9TmkQzFav8U9cxl` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_087_ebd14021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 19:16:37"
  condition:
    hash.sha256(0, filesize) == "ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8"
}
```

### Sample 88: `bfc864e08da7597e`

| Field | Value |
|---|---|
| SHA-256 | `bfc864e08da7597e73bc116169c20acab325ac0ed4efcfde5cbe751f7334416f` |
| Family label | `Mirai` |
| File name | `zero.powerpc` |
| File type | `elf` |
| First seen | `2026-07-29 19:16:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7edd0caae42aa2de506798b06fb62ca` |
| SHA-1 | `96a4931f518314777719745ba32003b8212d4f75` |
| SHA-256 | `bfc864e08da7597e73bc116169c20acab325ac0ed4efcfde5cbe751f7334416f` |
| SHA3-384 | `898bd5a4228d6f27dbd60a58c3a122d825dbc6169001d401592a8e2dc48bcb15b0807f9d28da90b5194be3e93c4989fb` |
| TLSH | `T11DF33B01735C0447E3A75EF0393F6BE597EFDAA021F4A245290F978A4171E32698AECD` |
| SSDEEP | `1536:c7B6HoZls8+6xGdUNn89A5w4xRRAbj9upuvAsHnkm1+fdGp/q6yQ0HprwC+rW8Bp:c7x+6xuUNnc4xGudsZsHh6W8f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_bfc864e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfc864e08da7597e73bc116169c20acab325ac0ed4efcfde5cbe751f7334416f"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-07-29 19:16:02"
  condition:
    hash.sha256(0, filesize) == "bfc864e08da7597e73bc116169c20acab325ac0ed4efcfde5cbe751f7334416f"
}
```

### Sample 89: `c51cd6ef8dda0858`

| Field | Value |
|---|---|
| SHA-256 | `c51cd6ef8dda0858ddcc67d4742b2ec0f9a3889d1ac3a3c7627f443e4ca68a79` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-29 19:15:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43d8804a4fd0a221fb0c222e332426fd` |
| SHA-1 | `cd15d495998a72e7519ef2ca4b372eca0d601a2f` |
| SHA-256 | `c51cd6ef8dda0858ddcc67d4742b2ec0f9a3889d1ac3a3c7627f443e4ca68a79` |
| SHA3-384 | `8e7bd9c6354f5a173f612dc76d43772272423f977ce38c0ad554382bad1384e8c1da88934ab8d077397833d6f994a6c7` |
| TLSH | `T1F5C32AA9F880DE62C6D5267AFB4E418C33231778D3DE7105CE149E3467EB95A0E3E942` |
| SSDEEP | `3072:CON9L2wOtnosmfncYEEU0084WnCwlDBteiMALe++pH5aA1Dz:COTAmvcYEEU0HnphBteipWZamn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_c51cd6ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51cd6ef8dda0858ddcc67d4742b2ec0f9a3889d1ac3a3c7627f443e4ca68a79"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-29 19:15:59"
  condition:
    hash.sha256(0, filesize) == "c51cd6ef8dda0858ddcc67d4742b2ec0f9a3889d1ac3a3c7627f443e4ca68a79"
}
```

### Sample 90: `adec57e91d17360a`

| Field | Value |
|---|---|
| SHA-256 | `adec57e91d17360a84d443ec280165e6c00aa95e7664e70d7332bf7a4b4e0e70` |
| Family label | `Mirai` |
| File name | `zero.powerpc` |
| File type | `elf` |
| First seen | `2026-07-29 19:14:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a00d7ad4013d1c2f4236732cbcdcfb8c` |
| SHA-1 | `ada830434ff17368af94c60be3de921f4b16bb49` |
| SHA-256 | `adec57e91d17360a84d443ec280165e6c00aa95e7664e70d7332bf7a4b4e0e70` |
| SHA3-384 | `e9088b56ded8d037be37d63202cf97945a0b23a40c98c96fe7870e269a9a10cef2aadbd01ecc72fcae7937254ad3a25f` |
| TLSH | `T15C43F11296B92F01DDDE993ABB80DDD463A08F09F7E18DC420FD0D857912A126EA7EC5` |
| SSDEEP | `1536:i+q/OvpV2Rn1e5aJZuyo623NJHGzrSLN//4u+qgw09H:L0OvpV2Rn1L58JkeX4u+qgw2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_adec57e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adec57e91d17360a84d443ec280165e6c00aa95e7664e70d7332bf7a4b4e0e70"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-07-29 19:14:41"
  condition:
    hash.sha256(0, filesize) == "adec57e91d17360a84d443ec280165e6c00aa95e7664e70d7332bf7a4b4e0e70"
}
```

### Sample 91: `05937148071e4dd0`

| Field | Value |
|---|---|
| SHA-256 | `05937148071e4dd0a4f0dfa9f37b0dc587fc0b16041e446673affdfe0109c98d` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-29 19:14:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1ccc2c65745e781ce2a543abee0ebb3` |
| SHA-1 | `3e3ba9950f0ef1eaaa1b42e7cfd73e284577a7a8` |
| SHA-256 | `05937148071e4dd0a4f0dfa9f37b0dc587fc0b16041e446673affdfe0109c98d` |
| SHA3-384 | `c386967d6fbb85202ea0490d1e511bd4697def68357b7ad46ff31d0d17769e40a439777f1031d6d1e53676f7d56d33e9` |
| TLSH | `T11B430182824C3F16D7F4157BF07F898677324974E4125A626504DB25FAA02F9BEB0ECB` |
| SSDEEP | `768:bufijwnGd9fo99PC9/2xrCqS3xtVOfr06aqM7z8KBUrfl8WQW8APon/bqakAOSq3:6tGLCgs3SBHOxpM7lUrumW3hqUtKGfY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_05937148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05937148071e4dd0a4f0dfa9f37b0dc587fc0b16041e446673affdfe0109c98d"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-29 19:14:40"
  condition:
    hash.sha256(0, filesize) == "05937148071e4dd0a4f0dfa9f37b0dc587fc0b16041e446673affdfe0109c98d"
}
```

### Sample 92: `08983ed95707cb36`

| Field | Value |
|---|---|
| SHA-256 | `08983ed95707cb36e6282d4eaa5146525d8878e9ddff22b984c8a4298607bdc8` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-29 19:14:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4c2e30e7fc93f5ea420536b9e64c66f` |
| SHA-1 | `8109f4fd5e8f499ad55e2e9572ce7e43e08918d2` |
| SHA-256 | `08983ed95707cb36e6282d4eaa5146525d8878e9ddff22b984c8a4298607bdc8` |
| SHA3-384 | `a26004e68ad85f7473df14a089b42336d4ef5beda5489b78f3ad1ec45242516d43474221ce7e7e49e262ae4f017f64bb` |
| TLSH | `T178145CA9BA0F6C41F1C2D3F9DE8C83E13E1731E3C77689B1781212EDDAA39D95990502` |
| SSDEEP | `3072:VxSsbgDFybl+jw2tFCNniMRq1GG7SKKKRyvppRM1rnoq:VxpbgDFoluw2tFgnhY1D7SKropRonoq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_08983ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08983ed95707cb36e6282d4eaa5146525d8878e9ddff22b984c8a4298607bdc8"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-29 19:14:39"
  condition:
    hash.sha256(0, filesize) == "08983ed95707cb36e6282d4eaa5146525d8878e9ddff22b984c8a4298607bdc8"
}
```

### Sample 93: `6f65c49d2057a600`

| Field | Value |
|---|---|
| SHA-256 | `6f65c49d2057a600e59c26b8ca003a17c2f312e3ecc269b8c69a6c0ad24dae19` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-29 19:12:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8318f43f7ed91d04a5359a5f96fa533d` |
| SHA-1 | `42ed356d5aeefc5c8a2beb8d3657e2600cff5ea9` |
| SHA-256 | `6f65c49d2057a600e59c26b8ca003a17c2f312e3ecc269b8c69a6c0ad24dae19` |
| SHA3-384 | `cd7ae035a93380bb10efc832174a4845211b45ebc28369dbec07be5de6d74aa7cabefc2c87f5e00b065b60c6d8e01937` |
| TLSH | `T1C0236C6516857C14AA99C4365C7E2F0CBDAD43E6314492EE7FCF3CF28C4A6ADA20871D` |
| SSDEEP | `768:4r9NyXsZztC79GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:mHusZdcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_6f65c49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f65c49d2057a600e59c26b8ca003a17c2f312e3ecc269b8c69a6c0ad24dae19"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-29 19:12:38"
  condition:
    hash.sha256(0, filesize) == "6f65c49d2057a600e59c26b8ca003a17c2f312e3ecc269b8c69a6c0ad24dae19"
}
```

### Sample 94: `d614e03ba9ec3b8b`

| Field | Value |
|---|---|
| SHA-256 | `d614e03ba9ec3b8bc6b942b8e2f4743eab4d43b6620267a73896a11f5387c315` |
| Family label | `Mirai` |
| File name | `zero.m68k` |
| File type | `elf` |
| First seen | `2026-07-29 19:08:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1dfcdb4231fc07e66db197e4f447500` |
| SHA-1 | `f7fc674a207b525dfe2ae735c7add5bf7220b2be` |
| SHA-256 | `d614e03ba9ec3b8bc6b942b8e2f4743eab4d43b6620267a73896a11f5387c315` |
| SHA3-384 | `501dcc85590bb97a7f9af3d9b45b079a41358431c6d326637aaabaa1c5b833e956989db6345516b92802949ae1e194da` |
| TLSH | `T1FC043AD7F800CDBEF06BD37684530A067530B7E144526B377253796BED3A1A92923E8A` |
| SSDEEP | `3072:jNaxp3o0IjzpZEX0D5hIQtp4SbVAjbiALmnI2N5qwrMxY7XyndmlX:pipNX0D5Gmp4SkLmIQQ8ynwlX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_d614e03b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d614e03ba9ec3b8bc6b942b8e2f4743eab4d43b6620267a73896a11f5387c315"
    family = "Mirai"
    file_name = "zero.m68k"
    file_type = "elf"
    first_seen = "2026-07-29 19:08:44"
  condition:
    hash.sha256(0, filesize) == "d614e03ba9ec3b8bc6b942b8e2f4743eab4d43b6620267a73896a11f5387c315"
}
```

### Sample 95: `ee951324005c874f`

| Field | Value |
|---|---|
| SHA-256 | `ee951324005c874fc6b65d8c0028d206a32c4d3efe1f719fca2e64f0542331ba` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-29 19:03:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `066e06846d74add594831b086bf6950b` |
| SHA-1 | `62efd19336908f42a1b38f96a23fe3305b1d6388` |
| SHA-256 | `ee951324005c874fc6b65d8c0028d206a32c4d3efe1f719fca2e64f0542331ba` |
| SHA3-384 | `877f1f139b72d0e6c0851d93ac74a27e2fdc78f931062b317e8d52aa5b7d12e3a21990e981a420273d5e0129325e9cd8` |
| TLSH | `T1C5041A4B7B11CF61D32DD9300AB3CF9656E926621AD28449F21CDE183E25349B92FFE4` |
| TELFHASH | `t14031deb08b7b65119ac5c7ec88edb75a491e8111470adf33ed3280bc90260ede32ad4f` |
| SSDEEP | `3072:ROBv/E5va7suz90UCmMGfWVOyEPLbXY69FM6yIvUVKlSws6cp+1Dqja:8vs5y7suz2opt9WwUVMiJp88a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_ee951324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee951324005c874fc6b65d8c0028d206a32c4d3efe1f719fca2e64f0542331ba"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-29 19:03:51"
  condition:
    hash.sha256(0, filesize) == "ee951324005c874fc6b65d8c0028d206a32c4d3efe1f719fca2e64f0542331ba"
}
```

### Sample 96: `870f422bb0b9dbcf`

| Field | Value |
|---|---|
| SHA-256 | `870f422bb0b9dbcf78765cd258372dc44268ee64d46e074f466c064ffe88f3b8` |
| Family label | `Mirai` |
| File name | `zero.armv6l` |
| File type | `elf` |
| First seen | `2026-07-29 19:03:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53489d293645cd5d5d15dd0cbf4443ae` |
| SHA-1 | `fe5c29cd24457c317492573bc6d3ad5aa7105b2a` |
| SHA-256 | `870f422bb0b9dbcf78765cd258372dc44268ee64d46e074f466c064ffe88f3b8` |
| SHA3-384 | `63f9d60925c7bb9bbf0b990c3e6143bb9eed7153959f2f8066b31e36ba14fdb645600778bb67b1ac275e5afc74d514ad` |
| TLSH | `T1FA041B86BC818B01D5C616B6FE1E164E37135B78E3E972039E146B393B8AC6F0E3B515` |
| TELFHASH | `t12221209697a40ffca7e8c7e081da70098be937ed2f0039198e0de7970565dc2762d432` |
| SSDEEP | `3072:iGZLg905FVPTBToLmpMguHcUWVUHalw7W5uH0AsfC95iPUnGYSWXGB3ER3sBKBgM:iGZL/hoLmpMguHcUWVUHalw7W5uH0Asw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_870f422b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870f422bb0b9dbcf78765cd258372dc44268ee64d46e074f466c064ffe88f3b8"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-29 19:03:49"
  condition:
    hash.sha256(0, filesize) == "870f422bb0b9dbcf78765cd258372dc44268ee64d46e074f466c064ffe88f3b8"
}
```

### Sample 97: `6ea50710c93686f0`

| Field | Value |
|---|---|
| SHA-256 | `6ea50710c93686f003af4b988504499a27ecd8355b47642c9737dce630950865` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-29 19:02:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb9827c99c6423d78393297cf5fca9f8` |
| SHA-1 | `eaa8fe3531cb5b1948ce61fc135d20a6736367c7` |
| SHA-256 | `6ea50710c93686f003af4b988504499a27ecd8355b47642c9737dce630950865` |
| SHA3-384 | `cf828e789ab7615f979c5384d477afc6717e6ecb298d0ce36700985c2f81feeb3eecba690c638b0db24c1bb61e6b003d` |
| TLSH | `T1088302E3A572466FF3D513B708A2084F2D76917A2C2CC559B0A70A1F443D4CF9AF9E94` |
| SSDEEP | `1536:aB/ccsAf+KnPnemRda2r5EuY5Bj8UV8er+XKjOahcSCvkpomKtAROjkeQF:ynsAf+cnJvaw5EuYqerPKYczSwAROju` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_6ea50710
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ea50710c93686f003af4b988504499a27ecd8355b47642c9737dce630950865"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-29 19:02:58"
  condition:
    hash.sha256(0, filesize) == "6ea50710c93686f003af4b988504499a27ecd8355b47642c9737dce630950865"
}
```

### Sample 98: `aac8a487f9297ee2`

| Field | Value |
|---|---|
| SHA-256 | `aac8a487f9297ee2fe85b2a96d70ca018c597df314657eaeb9701b730bc8c956` |
| Family label | `Mirai` |
| File name | `zero.armv6l` |
| File type | `elf` |
| First seen | `2026-07-29 19:02:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f731bb59964f62c08e00e9375855d2d9` |
| SHA-1 | `b39741be901fcfcdb18e86e6ae5ea5dd1f468382` |
| SHA-256 | `aac8a487f9297ee2fe85b2a96d70ca018c597df314657eaeb9701b730bc8c956` |
| SHA3-384 | `55e05a6ac56451e957098fa5259b72c439263425fec548617bb4c7f85e46aa8f0f8769b8b63e3b8386651528f6f8e00e` |
| TLSH | `T1C7430283D20A1C66F5645B32467D430AA39A6DBCE8FF606F9D0F909D5CC71E4837906B` |
| SSDEEP | `1536:kbawx9y6HetnW3I9/IU/k+XqE0pa6PYaDPL5:kbaMIK54pttqEWpPTPL5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_aac8a487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aac8a487f9297ee2fe85b2a96d70ca018c597df314657eaeb9701b730bc8c956"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-29 19:02:56"
  condition:
    hash.sha256(0, filesize) == "aac8a487f9297ee2fe85b2a96d70ca018c597df314657eaeb9701b730bc8c956"
}
```

### Sample 99: `c297678aeeca8dc5`

| Field | Value |
|---|---|
| SHA-256 | `c297678aeeca8dc51d1c9ba9b70505210dd8f43199daa00d4995e0a923336762` |
| Family label | `unknown` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-29 19:02:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ec294100e7b09b44c1f941784e0d133` |
| SHA-1 | `d9430d82e9e68ddfeb61a5bddf5fe69a8bb33bcf` |
| SHA-256 | `c297678aeeca8dc51d1c9ba9b70505210dd8f43199daa00d4995e0a923336762` |
| SHA3-384 | `dc33a1a6cfb7e7d5814040e57714479150bdba97894fa7bccf3233c3c483ace4a5267f4fe77696af59849365fb0b0032` |
| TLSH | `T1BD14D81A9F510EFBDCAFDD3702E90A0635CCA54722A43B353674D528F54BA4B4AE3C68` |
| SSDEEP | `3072:MijlUx4cPEJVC9qPLpAUBKKHkkDxCCtr9kNrS:MylUNPS0qPOKKKh1DrGN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_c297678a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c297678aeeca8dc51d1c9ba9b70505210dd8f43199daa00d4995e0a923336762"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-29 19:02:55"
  condition:
    hash.sha256(0, filesize) == "c297678aeeca8dc51d1c9ba9b70505210dd8f43199daa00d4995e0a923336762"
}
```

### Sample 100: `0f46b89689bf2d3c`

| Field | Value |
|---|---|
| SHA-256 | `0f46b89689bf2d3cbcebff2f1f6986d0591f91f2e06b710a2b2aba771d50f21d` |
| Family label | `Mirai` |
| File name | `zero.armv4l` |
| File type | `elf` |
| First seen | `2026-07-29 19:01:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6159f6402c855bbe524e1fd5b003de86` |
| SHA-1 | `4503a8eff0ac5b2d428888b80b015269639259f1` |
| SHA-256 | `0f46b89689bf2d3cbcebff2f1f6986d0591f91f2e06b710a2b2aba771d50f21d` |
| SHA3-384 | `06cc427c1499afb937855df9524a51fd6c285bf79dfb004a41777bb47bf234f1e46bf3fe996a647518d6ad68fa43f86e` |
| TLSH | `T199F32C86BC808B13C6E151B7FB4E528E372603E8D3EAB1079D196F25379B8970E37651` |
| TELFHASH | `t14e41005e9fa40fec6bc482e040ce4129aaa932afa31129538f5d578fc543fe2f515837` |
| SSDEEP | `3072:L5jfYfjX1W0J62Bl4nK4wRdZ3Sxmvi8qUtB:Ldft0JjX4K4wHZ3SxmSUtB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_0f46b896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f46b89689bf2d3cbcebff2f1f6986d0591f91f2e06b710a2b2aba771d50f21d"
    family = "Mirai"
    file_name = "zero.armv4l"
    file_type = "elf"
    first_seen = "2026-07-29 19:01:55"
  condition:
    hash.sha256(0, filesize) == "0f46b89689bf2d3cbcebff2f1f6986d0591f91f2e06b710a2b2aba771d50f21d"
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
 * Generated: 2026-07-30T03:35:24.324231+00:00
 */

rule MalwareBazaar_unknown_001_a6eb7f69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562"
    family = "unknown"
    file_name = "tmp3A5.tmp.exe"
    file_type = "exe"
    first_seen = "2026-07-30 02:52:34"
  condition:
    hash.sha256(0, filesize) == "a6eb7f69df025bf0229d9d3a9754cf687e8165978fd2fcf3accd30c6afa67562"
}

rule MalwareBazaar_unknown_002_31e86a06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31e86a063a1bdb8f77d70a05c0b67ea7f962ccdd527a40311fe0debefb724375"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 02:52:31"
  condition:
    hash.sha256(0, filesize) == "31e86a063a1bdb8f77d70a05c0b67ea7f962ccdd527a40311fe0debefb724375"
}

rule MalwareBazaar_Mirai_003_a2da49f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2da49f221ea054d054ad6864fa443ffafd25a21ffc643a30257980963f36c7a"
    family = "Mirai"
    file_name = "xd.ppc"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:52"
  condition:
    hash.sha256(0, filesize) == "a2da49f221ea054d054ad6864fa443ffafd25a21ffc643a30257980963f36c7a"
}

rule MalwareBazaar_Mirai_004_53707927
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "537079272b0ccda68ba39a657e83549c91ba45d9eecefd29db322a200d08f354"
    family = "Mirai"
    file_name = "xd.mpsl"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:51"
  condition:
    hash.sha256(0, filesize) == "537079272b0ccda68ba39a657e83549c91ba45d9eecefd29db322a200d08f354"
}

rule MalwareBazaar_Mirai_005_439b2f72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "439b2f72b37b28a9114dec1bdc27e68b7b261f73a77d5408eab726e5ba096ecc"
    family = "Mirai"
    file_name = "xd.spc"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:50"
  condition:
    hash.sha256(0, filesize) == "439b2f72b37b28a9114dec1bdc27e68b7b261f73a77d5408eab726e5ba096ecc"
}

rule MalwareBazaar_Mirai_006_c18b493b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c18b493bdf0403f015b58745c3ef3b18a7253437fcb567a1e5f63a2887eeaad1"
    family = "Mirai"
    file_name = "xd.arm6"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:48"
  condition:
    hash.sha256(0, filesize) == "c18b493bdf0403f015b58745c3ef3b18a7253437fcb567a1e5f63a2887eeaad1"
}

rule MalwareBazaar_Mirai_007_44803559
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44803559c71a805c0400f3647ff6384dcdfe7a79254910b7fe514ee1e258c12d"
    family = "Mirai"
    file_name = "xd.mips"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:47"
  condition:
    hash.sha256(0, filesize) == "44803559c71a805c0400f3647ff6384dcdfe7a79254910b7fe514ee1e258c12d"
}

rule MalwareBazaar_Mirai_008_9fb440b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb440b26b054059cc167bdaacbb46e7821447d3b89359a40f6b9dd60163eaf8"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:45"
  condition:
    hash.sha256(0, filesize) == "9fb440b26b054059cc167bdaacbb46e7821447d3b89359a40f6b9dd60163eaf8"
}

rule MalwareBazaar_Mirai_009_5f88be80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f88be80111356aa32af22b72157c314dc65efd1cb36a41c25b00ee4b410f8fc"
    family = "Mirai"
    file_name = "xd.sh4"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:44"
  condition:
    hash.sha256(0, filesize) == "5f88be80111356aa32af22b72157c314dc65efd1cb36a41c25b00ee4b410f8fc"
}

rule MalwareBazaar_Mirai_010_bbbab27a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbbab27acb546f3f3aa632bb5e084316f4af2fef4490262dfc33d4df624f96cc"
    family = "Mirai"
    file_name = "xd.arm7"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:43"
  condition:
    hash.sha256(0, filesize) == "bbbab27acb546f3f3aa632bb5e084316f4af2fef4490262dfc33d4df624f96cc"
}

rule MalwareBazaar_Mirai_011_bab2dee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bab2dee1fc862cd6915bd9d70222c6be76103111d78c67dc498842a6c681ffed"
    family = "Mirai"
    file_name = "xd.arm5"
    file_type = "elf"
    first_seen = "2026-07-30 02:40:41"
  condition:
    hash.sha256(0, filesize) == "bab2dee1fc862cd6915bd9d70222c6be76103111d78c67dc498842a6c681ffed"
}

rule MalwareBazaar_unknown_012_e54459c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e54459c6e71f048bcba8c3103982e2b9f4b5f9cd9b00d0b71a2d03a24ab84d12"
    family = "unknown"
    file_name = "sensi.sh"
    file_type = "sh"
    first_seen = "2026-07-30 02:40:40"
  condition:
    hash.sha256(0, filesize) == "e54459c6e71f048bcba8c3103982e2b9f4b5f9cd9b00d0b71a2d03a24ab84d12"
}

rule MalwareBazaar_unknown_013_bb87574d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb87574dc35a257a4e13e238f18d223709a49367e601e7acd43ed7730d35edbb"
    family = "unknown"
    file_name = "AzureSet-NetAdapterPowerManagement.log"
    file_type = "unknown"
    first_seen = "2026-07-30 02:32:11"
  condition:
    hash.sha256(0, filesize) == "bb87574dc35a257a4e13e238f18d223709a49367e601e7acd43ed7730d35edbb"
}

rule MalwareBazaar_unknown_014_55f0132b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55f0132ba99eaf397afb997f26900c6ae6c9c797f2dd99da5423c33f549b5afe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-30 02:16:44"
  condition:
    hash.sha256(0, filesize) == "55f0132ba99eaf397afb997f26900c6ae6c9c797f2dd99da5423c33f549b5afe"
}

rule MalwareBazaar_RemcosRAT_015_edd25cef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edd25cef88fe2c1bd562e33f9403c1644f09f80ce10690f1337e7b295357d751"
    family = "RemcosRAT"
    file_name = "NEW ORDER REQUEST.js"
    file_type = "js"
    first_seen = "2026-07-30 02:08:55"
  condition:
    hash.sha256(0, filesize) == "edd25cef88fe2c1bd562e33f9403c1644f09f80ce10690f1337e7b295357d751"
}

rule MalwareBazaar_unknown_016_22eec70b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 02:06:50"
  condition:
    hash.sha256(0, filesize) == "22eec70bf4412de64eb3ac2aaf1991a7e1ca197f8ec37339fa549e0037908e85"
}

rule MalwareBazaar_unknown_017_1bef2e01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bef2e01e1f4aad8becdec1dc5f525dedd83567f9fecfe51f6c8ac9efdfc0b8e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-30 02:02:58"
  condition:
    hash.sha256(0, filesize) == "1bef2e01e1f4aad8becdec1dc5f525dedd83567f9fecfe51f6c8ac9efdfc0b8e"
}

rule MalwareBazaar_njrat_018_2a01a22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a01a22a5d823b5705dad1f7de5d15ebf9068347099726b95878aeaf9de9b625"
    family = "njrat"
    file_name = "ORDER 29TH.vbs"
    file_type = "vbs"
    first_seen = "2026-07-30 01:59:30"
  condition:
    hash.sha256(0, filesize) == "2a01a22a5d823b5705dad1f7de5d15ebf9068347099726b95878aeaf9de9b625"
}

rule MalwareBazaar_unknown_019_4bc1bc07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bc1bc072949437c41adf9203ba98595ebaeb1ee47d231fc9e59a16e697e336c"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 01:52:32"
  condition:
    hash.sha256(0, filesize) == "4bc1bc072949437c41adf9203ba98595ebaeb1ee47d231fc9e59a16e697e336c"
}

rule MalwareBazaar_Mirai_020_aa585df9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa585df9ce9d53ee758526dea601e4718bfd333ac594448574b7f6ac711f0fe8"
    family = "Mirai"
    file_name = "zero.sh4"
    file_type = "elf"
    first_seen = "2026-07-30 01:48:41"
  condition:
    hash.sha256(0, filesize) == "aa585df9ce9d53ee758526dea601e4718bfd333ac594448574b7f6ac711f0fe8"
}

rule MalwareBazaar_unknown_021_a80f6084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a80f608476a3faacca1ef34361cc418a68661db2d87ccf0d9b14d307453e59f4"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-30 01:42:40"
  condition:
    hash.sha256(0, filesize) == "a80f608476a3faacca1ef34361cc418a68661db2d87ccf0d9b14d307453e59f4"
}

rule MalwareBazaar_Mirai_022_b67373fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b67373fd6b4806d799d94fb1391e7e3c01354b1787fd2f879b6cff2f154f0c60"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-07-30 01:05:06"
  condition:
    hash.sha256(0, filesize) == "b67373fd6b4806d799d94fb1391e7e3c01354b1787fd2f879b6cff2f154f0c60"
}

rule MalwareBazaar_unknown_023_243be638
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "243be638007185cdfd1b24a5d30f78c55bbb9e6fff241685e12a8a175728b9c1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-30 01:00:51"
  condition:
    hash.sha256(0, filesize) == "243be638007185cdfd1b24a5d30f78c55bbb9e6fff241685e12a8a175728b9c1"
}

rule MalwareBazaar_unknown_024_a364fcd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a364fcd5ab8c0b3167f28db0e9729b552d29fbffa7a382561839fc4831c542c1"
    family = "unknown"
    file_name = "exec_binary"
    file_type = "elf"
    first_seen = "2026-07-30 00:52:44"
  condition:
    hash.sha256(0, filesize) == "a364fcd5ab8c0b3167f28db0e9729b552d29fbffa7a382561839fc4831c542c1"
}

rule MalwareBazaar_unknown_025_6d67be88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d67be88230d11f5751ab86094ccf4f704013e40c3172efee3bd08e772258f83"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-30 00:52:33"
  condition:
    hash.sha256(0, filesize) == "6d67be88230d11f5751ab86094ccf4f704013e40c3172efee3bd08e772258f83"
}

rule MalwareBazaar_Mirai_026_679a5148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679a5148066f3355ed6f66f53a388f5b7c3a301d734311acda9804dd747385de"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-07-30 00:46:00"
  condition:
    hash.sha256(0, filesize) == "679a5148066f3355ed6f66f53a388f5b7c3a301d734311acda9804dd747385de"
}

rule MalwareBazaar_Mirai_027_fd7cdb47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7cdb47ad462dc080a987b66612784a1955d2b80d4bfec9031517fc0626a0eb"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-07-30 00:44:45"
  condition:
    hash.sha256(0, filesize) == "fd7cdb47ad462dc080a987b66612784a1955d2b80d4bfec9031517fc0626a0eb"
}

rule MalwareBazaar_Mirai_028_fafdcf2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fafdcf2aa1011e57905046c5e9d178f8c3812f311ee6c16c65a3f436511864b4"
    family = "Mirai"
    file_name = "zero.sparc"
    file_type = "elf"
    first_seen = "2026-07-30 00:42:43"
  condition:
    hash.sha256(0, filesize) == "fafdcf2aa1011e57905046c5e9d178f8c3812f311ee6c16c65a3f436511864b4"
}

rule MalwareBazaar_unknown_029_b8fea3cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8fea3cc9b18b4b09c94ed6645ad12d04274ddefa6ffd043576f00d2dea33d9b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-30 00:42:41"
  condition:
    hash.sha256(0, filesize) == "b8fea3cc9b18b4b09c94ed6645ad12d04274ddefa6ffd043576f00d2dea33d9b"
}

rule MalwareBazaar_unknown_030_38d88313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38d883132265520493ca6b111191fb18ad691f13de2ada0c6598a92e880b2c7f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-30 00:36:50"
  condition:
    hash.sha256(0, filesize) == "38d883132265520493ca6b111191fb18ad691f13de2ada0c6598a92e880b2c7f"
}

rule MalwareBazaar_unknown_031_bcf7bd7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcf7bd7b46d57c055e8cde4588dae1aee094cc225074e0b5430640e90a8468ff"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 23:52:31"
  condition:
    hash.sha256(0, filesize) == "bcf7bd7b46d57c055e8cde4588dae1aee094cc225074e0b5430640e90a8468ff"
}

rule MalwareBazaar_RemoteX_032_26cba792
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26cba7929124eb13801a4e32c7071a2b3ab10896048bb25ca900e04edfa34795"
    family = "RemoteX"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 23:26:02"
  condition:
    hash.sha256(0, filesize) == "26cba7929124eb13801a4e32c7071a2b3ab10896048bb25ca900e04edfa34795"
}

rule MalwareBazaar_unknown_033_4b2bfcdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b2bfcdbd2235a917786405381129da36922bbbb3f0342fbe44eaad3760afaa5"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 22:52:31"
  condition:
    hash.sha256(0, filesize) == "4b2bfcdbd2235a917786405381129da36922bbbb3f0342fbe44eaad3760afaa5"
}

rule MalwareBazaar_unknown_034_64d7a96e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64d7a96e4307457cf9c2efdd4990bcf4b5a215cb60fb8c36ebb46d1ac01f12d6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 22:50:32"
  condition:
    hash.sha256(0, filesize) == "64d7a96e4307457cf9c2efdd4990bcf4b5a215cb60fb8c36ebb46d1ac01f12d6"
}

rule MalwareBazaar_unknown_035_c0523063
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15"
    family = "unknown"
    file_name = "c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15"
    file_type = "sh"
    first_seen = "2026-07-29 22:24:12"
  condition:
    hash.sha256(0, filesize) == "c0523063abe84c4064e3fad4f5503f9a7ea500420ddf909ef4ae1979da45cc15"
}

rule MalwareBazaar_unknown_036_a1293897
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a12938970191659c4b45d3aee886c6ef9b95f1e02e78eb85c71343f4a1e8cdd6"
    family = "unknown"
    file_name = "662a80b0194fc616144c3a312a215faf4f78a5671ed978dc6796e581d9fe7d4a.7z"
    file_type = "7z"
    first_seen = "2026-07-29 22:05:34"
  condition:
    hash.sha256(0, filesize) == "a12938970191659c4b45d3aee886c6ef9b95f1e02e78eb85c71343f4a1e8cdd6"
}

rule MalwareBazaar_unknown_037_86dac886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86dac88668ac7f20317d657ee7e95aea8a9df3530ff2713f8d62557e381bbec9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 21:52:31"
  condition:
    hash.sha256(0, filesize) == "86dac88668ac7f20317d657ee7e95aea8a9df3530ff2713f8d62557e381bbec9"
}

rule MalwareBazaar_unknown_038_0ed2bdca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ed2bdca1aba5f0aa9b460314668ee74511d57e54adecb06a5595aa227db6a30"
    family = "unknown"
    file_name = "RBL-Credit-Card-1.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:29:49"
  condition:
    hash.sha256(0, filesize) == "0ed2bdca1aba5f0aa9b460314668ee74511d57e54adecb06a5595aa227db6a30"
}

rule MalwareBazaar_unknown_039_76bc2cfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76bc2cfa58c82672d1cbe9112bcec4e8e7935a53b1db21b0f5731cf96fadcde6"
    family = "unknown"
    file_name = "imobile.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:24:12"
  condition:
    hash.sha256(0, filesize) == "76bc2cfa58c82672d1cbe9112bcec4e8e7935a53b1db21b0f5731cf96fadcde6"
}

rule MalwareBazaar_unknown_040_13bd0b75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13bd0b75039576c6b5f249e507cb5de04300c83b2971edd94686659848c504c7"
    family = "unknown"
    file_name = "iMobile Lite.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:20:45"
  condition:
    hash.sha256(0, filesize) == "13bd0b75039576c6b5f249e507cb5de04300c83b2971edd94686659848c504c7"
}

rule MalwareBazaar_WannaCry_041_6f65ac06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337"
    family = "WannaCry"
    file_name = "6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337"
    file_type = "exe"
    first_seen = "2026-07-29 21:15:27"
  condition:
    hash.sha256(0, filesize) == "6f65ac067cd914ac0d3a04d801e0363cf615f867c0fe683340656387e48f9337"
}

rule MalwareBazaar_unknown_042_5bee3cf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bee3cf919dc5bb90de4be716a5e035b05803c1618795382546a735629c79e2e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 21:14:09"
  condition:
    hash.sha256(0, filesize) == "5bee3cf919dc5bb90de4be716a5e035b05803c1618795382546a735629c79e2e"
}

rule MalwareBazaar_Mirai_043_04a7afdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04a7afdf922df7e62e68cdcdec70597bcb86d2831fb50665b6989ebe850a2a6f"
    family = "Mirai"
    file_name = "zero.arc"
    file_type = "elf"
    first_seen = "2026-07-29 21:10:51"
  condition:
    hash.sha256(0, filesize) == "04a7afdf922df7e62e68cdcdec70597bcb86d2831fb50665b6989ebe850a2a6f"
}

rule MalwareBazaar_Mirai_044_dc923b4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc923b4f2165fe6f326f26f8739ceb3d3aea3e5b78bc8b091047fc677d0214ad"
    family = "Mirai"
    file_name = "ya4"
    file_type = "elf"
    first_seen = "2026-07-29 21:00:51"
  condition:
    hash.sha256(0, filesize) == "dc923b4f2165fe6f326f26f8739ceb3d3aea3e5b78bc8b091047fc677d0214ad"
}

rule MalwareBazaar_Mirai_045_ed2457fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed2457fc9931b8af83ff1428339fd6acb8619b73cf0e82c2658180f8e718626d"
    family = "Mirai"
    file_name = "y1V"
    file_type = "elf"
    first_seen = "2026-07-29 21:00:50"
  condition:
    hash.sha256(0, filesize) == "ed2457fc9931b8af83ff1428339fd6acb8619b73cf0e82c2658180f8e718626d"
}

rule MalwareBazaar_unknown_046_a1416a25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1416a250bf7219f95961f484421dda844b5013b5561c4a40591489dcfcdd384"
    family = "unknown"
    file_name = "TikTok18.apk"
    file_type = "apk"
    first_seen = "2026-07-29 21:00:19"
  condition:
    hash.sha256(0, filesize) == "a1416a250bf7219f95961f484421dda844b5013b5561c4a40591489dcfcdd384"
}

rule MalwareBazaar_unknown_047_63898fa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63898fa3645e69a333f8ea158d0c4e7bb20a4265f0d4597f50ee2ffffc9df820"
    family = "unknown"
    file_name = "SexySwipe.apk"
    file_type = "apk"
    first_seen = "2026-07-29 20:56:51"
  condition:
    hash.sha256(0, filesize) == "63898fa3645e69a333f8ea158d0c4e7bb20a4265f0d4597f50ee2ffffc9df820"
}

rule MalwareBazaar_Mirai_048_5d060c6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d060c6fbf2dc9bcb1131452aec575fc921e64c88828dc0faa78a9a09770e551"
    family = "Mirai"
    file_name = "real_x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 20:56:44"
  condition:
    hash.sha256(0, filesize) == "5d060c6fbf2dc9bcb1131452aec575fc921e64c88828dc0faa78a9a09770e551"
}

rule MalwareBazaar_unknown_049_b24e5a84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b24e5a844ab93fe8567b9f5937280cad8f3fdd4db0eeddd69079af1e8d7f31b2"
    family = "unknown"
    file_name = "ssh_brute"
    file_type = "elf"
    first_seen = "2026-07-29 20:56:43"
  condition:
    hash.sha256(0, filesize) == "b24e5a844ab93fe8567b9f5937280cad8f3fdd4db0eeddd69079af1e8d7f31b2"
}

rule MalwareBazaar_Stealc_050_a58cdd28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-29 20:52:42"
  condition:
    hash.sha256(0, filesize) == "a58cdd282196a800054eabccafbecbbf5a4eeb6a5a7a925353d7901dae0db9da"
}

rule MalwareBazaar_unknown_051_d7676d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7676d0f24364b278a6dd2b1c5fd34f688881cf3ff9e53e1e40f1b4048b7ce28"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 20:52:31"
  condition:
    hash.sha256(0, filesize) == "d7676d0f24364b278a6dd2b1c5fd34f688881cf3ff9e53e1e40f1b4048b7ce28"
}

rule MalwareBazaar_Mirai_052_66116ac6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66116ac63292be96cc8a20fb991844fa378c19051a156f1c4dffb7db01b43dc2"
    family = "Mirai"
    file_name = "HjEG"
    file_type = "elf"
    first_seen = "2026-07-29 20:32:42"
  condition:
    hash.sha256(0, filesize) == "66116ac63292be96cc8a20fb991844fa378c19051a156f1c4dffb7db01b43dc2"
}

rule MalwareBazaar_Mirai_053_bd744729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd744729e85f0084857466fe1d3df9d5caacb8b1f7cb0ac2bac6067361907da9"
    family = "Mirai"
    file_name = "RYb"
    file_type = "elf"
    first_seen = "2026-07-29 20:32:41"
  condition:
    hash.sha256(0, filesize) == "bd744729e85f0084857466fe1d3df9d5caacb8b1f7cb0ac2bac6067361907da9"
}

rule MalwareBazaar_Mirai_054_36b19a23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36b19a238e94508cb66ee491f6c0f7c36ec07a938fd8cdf1ca292a864fba7f14"
    family = "Mirai"
    file_name = "hix"
    file_type = "elf"
    first_seen = "2026-07-29 20:32:39"
  condition:
    hash.sha256(0, filesize) == "36b19a238e94508cb66ee491f6c0f7c36ec07a938fd8cdf1ca292a864fba7f14"
}

rule MalwareBazaar_RemusStealer_055_2ec31f7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec31f7f0ed881a6f33f44be53ddc89fff6f5f80390504093ddb4edccb46a830"
    family = "RemusStealer"
    file_name = "MicrosoftEdge.exe"
    file_type = "exe"
    first_seen = "2026-07-29 20:30:20"
  condition:
    hash.sha256(0, filesize) == "2ec31f7f0ed881a6f33f44be53ddc89fff6f5f80390504093ddb4edccb46a830"
}

rule MalwareBazaar_NanoCore_056_88536cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88536cf7df49585be4aa97e938b5ef5b5ccc46abbd2919010646a9a17281e3b5"
    family = "NanoCore"
    file_name = "2c5a9aa5ca5b6d98a5551da0ec0be9af.exe"
    file_type = "exe"
    first_seen = "2026-07-29 20:20:06"
  condition:
    hash.sha256(0, filesize) == "88536cf7df49585be4aa97e938b5ef5b5ccc46abbd2919010646a9a17281e3b5"
}

rule MalwareBazaar_Mirai_057_0c3424f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434"
    family = "Mirai"
    file_name = "0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434"
    file_type = "sh"
    first_seen = "2026-07-29 20:17:07"
  condition:
    hash.sha256(0, filesize) == "0c3424f930bd6ac00091ef6a6f96cf4f88f830c85b8937dd1776154202048434"
}

rule MalwareBazaar_WannaCry_058_6a4d371a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2"
    family = "WannaCry"
    file_name = "6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2"
    file_type = "exe"
    first_seen = "2026-07-29 20:15:29"
  condition:
    hash.sha256(0, filesize) == "6a4d371a7e82215799f79944204cf1ae4586a5a1cb6bdd5f6fb55e811e2154f2"
}

rule MalwareBazaar_Mirai_059_d1b81108
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1b8110868977a697f191498c1bd2ff1ea7ca469d1a7632b07411236dd75002d"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-29 20:14:42"
  condition:
    hash.sha256(0, filesize) == "d1b8110868977a697f191498c1bd2ff1ea7ca469d1a7632b07411236dd75002d"
}

rule MalwareBazaar_RemusStealer_060_5d9ed51e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d9ed51e8c68d43b9c2f8f6c9d18eef8f808a6f872115765a4cd2b43660cad8f"
    family = "RemusStealer"
    file_name = "package.msi"
    file_type = "msi"
    first_seen = "2026-07-29 20:05:00"
  condition:
    hash.sha256(0, filesize) == "5d9ed51e8c68d43b9c2f8f6c9d18eef8f808a6f872115765a4cd2b43660cad8f"
}

rule MalwareBazaar_unknown_061_eb8426a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb8426a2c384270297500f7ee836f38c6ba86eb981f8729304f0dc022e8e2754"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-29 20:02:58"
  condition:
    hash.sha256(0, filesize) == "eb8426a2c384270297500f7ee836f38c6ba86eb981f8729304f0dc022e8e2754"
}

rule MalwareBazaar_unknown_062_2fcaa054
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fcaa054ede7ae263d4479c83e122bc124b2c78b768ad653eb4511a95360fd3f"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-29 19:52:42"
  condition:
    hash.sha256(0, filesize) == "2fcaa054ede7ae263d4479c83e122bc124b2c78b768ad653eb4511a95360fd3f"
}

rule MalwareBazaar_unknown_063_d0c0dc10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0c0dc10447e81afa7b17ececeb7ad616a8a7b58fa9dbe70f03165fcea0a9f71"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-29 19:52:31"
  condition:
    hash.sha256(0, filesize) == "d0c0dc10447e81afa7b17ececeb7ad616a8a7b58fa9dbe70f03165fcea0a9f71"
}

rule MalwareBazaar_Mirai_064_3f661a59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f661a590790cb90966dd89803bfa662abd8aa67bbf4d90e44888a48399597f9"
    family = "Mirai"
    file_name = "bytetocrypt"
    file_type = "elf"
    first_seen = "2026-07-29 19:51:47"
  condition:
    hash.sha256(0, filesize) == "3f661a590790cb90966dd89803bfa662abd8aa67bbf4d90e44888a48399597f9"
}

rule MalwareBazaar_Mirai_065_03cba072
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03cba07268c420c1e208547cbb7162fa0f34176c8949fc5cb279cef06e94e90d"
    family = "Mirai"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-29 19:50:42"
  condition:
    hash.sha256(0, filesize) == "03cba07268c420c1e208547cbb7162fa0f34176c8949fc5cb279cef06e94e90d"
}

rule MalwareBazaar_Mirai_066_97c77f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97c77f02acfa0a62992da06101c5e07e713b68f58e59098a209030a06ff2aa2e"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-29 19:48:45"
  condition:
    hash.sha256(0, filesize) == "97c77f02acfa0a62992da06101c5e07e713b68f58e59098a209030a06ff2aa2e"
}

rule MalwareBazaar_Mirai_067_6bdedd83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bdedd8343999e8e0fce00858ee8fe47c1e42e27db2a217d4cdb689e048b5522"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-29 19:48:44"
  condition:
    hash.sha256(0, filesize) == "6bdedd8343999e8e0fce00858ee8fe47c1e42e27db2a217d4cdb689e048b5522"
}

rule MalwareBazaar_unknown_068_f051f141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538"
    family = "unknown"
    file_name = "f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538"
    file_type = "exe"
    first_seen = "2026-07-29 19:48:02"
  condition:
    hash.sha256(0, filesize) == "f051f14146e69ffd2f22c48c5126f53e8a94e2ce86b9adb46de0fb5230d46538"
}

rule MalwareBazaar_unknown_069_bf38ae8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8"
    family = "unknown"
    file_name = "bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:54"
  condition:
    hash.sha256(0, filesize) == "bf38ae8c1b495b2a547337759969967a8bf632f5adbbd9a9bb7c724007d684b8"
}

rule MalwareBazaar_unknown_070_bc9c4e81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e"
    family = "unknown"
    file_name = "bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:45"
  condition:
    hash.sha256(0, filesize) == "bc9c4e81bc9acd2a93de62ba696009084594161da3db5eddc4774a006d8bd07e"
}

rule MalwareBazaar_unknown_071_af5a2f1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a"
    family = "unknown"
    file_name = "af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:38"
  condition:
    hash.sha256(0, filesize) == "af5a2f1b7e388d4fb49d72e8f453fda673472ad603bf72aee4869a34b37f535a"
}

rule MalwareBazaar_unknown_072_78906623
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e"
    family = "unknown"
    file_name = "78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:25"
  condition:
    hash.sha256(0, filesize) == "78906623ce30eba7174e99d7f9d1df5fe69d1fdd7d5eb36329963e29b65bef2e"
}

rule MalwareBazaar_unknown_073_a01634a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a"
    family = "unknown"
    file_name = "a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a"
    file_type = "exe"
    first_seen = "2026-07-29 19:47:06"
  condition:
    hash.sha256(0, filesize) == "a01634a49545e05dcb1624aec62184f1f45c9224e4d356d191971914a4668a5a"
}

rule MalwareBazaar_unknown_074_f552f878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a"
    family = "unknown"
    file_name = "f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a"
    file_type = "exe"
    first_seen = "2026-07-29 19:46:55"
  condition:
    hash.sha256(0, filesize) == "f552f87811e0ac4c6757926e79bbf3a38fe6648634aaadb5a01f6e87e3a4951a"
}

rule MalwareBazaar_unknown_075_8d0c4a25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55"
    family = "unknown"
    file_name = "8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55"
    file_type = "exe"
    first_seen = "2026-07-29 19:46:43"
  condition:
    hash.sha256(0, filesize) == "8d0c4a2565d38c923a50bb5daf512a7b80633643c65b5464d665e5f71b8fbd55"
}

rule MalwareBazaar_unknown_076_816f1f4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6"
    family = "unknown"
    file_name = "816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6"
    file_type = "exe"
    first_seen = "2026-07-29 19:46:33"
  condition:
    hash.sha256(0, filesize) == "816f1f4df1f3964c807ea3606a6319a7872b6de54dd9286c1fed4982d6982af6"
}

rule MalwareBazaar_unknown_077_5ce2d378
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae"
    family = "unknown"
    file_name = "5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae"
    file_type = "unknown"
    first_seen = "2026-07-29 19:46:15"
  condition:
    hash.sha256(0, filesize) == "5ce2d378811c84c085f39d0ce264d03138cbdd46ae752adb1b8d2373f6873bae"
}

rule MalwareBazaar_Mirai_078_a2a67bc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2a67bc564e7dae8ebb3bf87368df309c1a5cb80b007872adc294e5da76106e4"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-07-29 19:32:41"
  condition:
    hash.sha256(0, filesize) == "a2a67bc564e7dae8ebb3bf87368df309c1a5cb80b007872adc294e5da76106e4"
}

rule MalwareBazaar_unknown_079_d6a3c1e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6a3c1e20b5ee7b111614d914b286bc1d0d4bfd5f6663893a4478ab28c6c2e58"
    family = "unknown"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-29 19:32:40"
  condition:
    hash.sha256(0, filesize) == "d6a3c1e20b5ee7b111614d914b286bc1d0d4bfd5f6663893a4478ab28c6c2e58"
}

rule MalwareBazaar_Mirai_080_77580df2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77580df28349934bc9b326713207109426c53962fa030405668004c2175d519b"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-07-29 19:22:44"
  condition:
    hash.sha256(0, filesize) == "77580df28349934bc9b326713207109426c53962fa030405668004c2175d519b"
}

rule MalwareBazaar_Mirai_081_2ad53cce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad53cce04d81baa4eb732c88d465743c45a5ef4349d71d18759f715848c8f9e"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-07-29 19:22:42"
  condition:
    hash.sha256(0, filesize) == "2ad53cce04d81baa4eb732c88d465743c45a5ef4349d71d18759f715848c8f9e"
}

rule MalwareBazaar_Mirai_082_ddfc434e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddfc434ed42759bb027f8aa7ba857e1955a462000d7f128b8f2987995864e4eb"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 19:21:45"
  condition:
    hash.sha256(0, filesize) == "ddfc434ed42759bb027f8aa7ba857e1955a462000d7f128b8f2987995864e4eb"
}

rule MalwareBazaar_Mirai_083_9378b08d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9378b08d1f873cc78b3eae058a3f5533590d932a53a0f8ca1a9d7a3533398773"
    family = "Mirai"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-29 19:20:42"
  condition:
    hash.sha256(0, filesize) == "9378b08d1f873cc78b3eae058a3f5533590d932a53a0f8ca1a9d7a3533398773"
}

rule MalwareBazaar_Mirai_084_b14e42aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b14e42aa75e85d5e0d14e831bf7988f0e235cb5e1d48255a637dac7548e4a4e6"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-29 19:20:41"
  condition:
    hash.sha256(0, filesize) == "b14e42aa75e85d5e0d14e831bf7988f0e235cb5e1d48255a637dac7548e4a4e6"
}

rule MalwareBazaar_Mirai_085_67f35740
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67f3574076af6c924ace8cd5352e99b7d9c756e7ef72ee356acdae0250f22307"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-29 19:20:40"
  condition:
    hash.sha256(0, filesize) == "67f3574076af6c924ace8cd5352e99b7d9c756e7ef72ee356acdae0250f22307"
}

rule MalwareBazaar_unknown_086_5a6a5d0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a6a5d0a5fa64dd08476f2e9ed9dfacd92b4a142777fee5d37b5c05fbb972c2c"
    family = "unknown"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-29 19:16:48"
  condition:
    hash.sha256(0, filesize) == "5a6a5d0a5fa64dd08476f2e9ed9dfacd92b4a142777fee5d37b5c05fbb972c2c"
}

rule MalwareBazaar_Phorpiex_087_ebd14021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-29 19:16:37"
  condition:
    hash.sha256(0, filesize) == "ebd140217102e211a74b341198292a392a0e25ecf5ec1a53fb411c14c3b7b6f8"
}

rule MalwareBazaar_Mirai_088_bfc864e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfc864e08da7597e73bc116169c20acab325ac0ed4efcfde5cbe751f7334416f"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-07-29 19:16:02"
  condition:
    hash.sha256(0, filesize) == "bfc864e08da7597e73bc116169c20acab325ac0ed4efcfde5cbe751f7334416f"
}

rule MalwareBazaar_Mirai_089_c51cd6ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c51cd6ef8dda0858ddcc67d4742b2ec0f9a3889d1ac3a3c7627f443e4ca68a79"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-29 19:15:59"
  condition:
    hash.sha256(0, filesize) == "c51cd6ef8dda0858ddcc67d4742b2ec0f9a3889d1ac3a3c7627f443e4ca68a79"
}

rule MalwareBazaar_Mirai_090_adec57e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adec57e91d17360a84d443ec280165e6c00aa95e7664e70d7332bf7a4b4e0e70"
    family = "Mirai"
    file_name = "zero.powerpc"
    file_type = "elf"
    first_seen = "2026-07-29 19:14:41"
  condition:
    hash.sha256(0, filesize) == "adec57e91d17360a84d443ec280165e6c00aa95e7664e70d7332bf7a4b4e0e70"
}

rule MalwareBazaar_Mirai_091_05937148
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05937148071e4dd0a4f0dfa9f37b0dc587fc0b16041e446673affdfe0109c98d"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-29 19:14:40"
  condition:
    hash.sha256(0, filesize) == "05937148071e4dd0a4f0dfa9f37b0dc587fc0b16041e446673affdfe0109c98d"
}

rule MalwareBazaar_Mirai_092_08983ed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08983ed95707cb36e6282d4eaa5146525d8878e9ddff22b984c8a4298607bdc8"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-29 19:14:39"
  condition:
    hash.sha256(0, filesize) == "08983ed95707cb36e6282d4eaa5146525d8878e9ddff22b984c8a4298607bdc8"
}

rule MalwareBazaar_unknown_093_6f65c49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f65c49d2057a600e59c26b8ca003a17c2f312e3ecc269b8c69a6c0ad24dae19"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-29 19:12:38"
  condition:
    hash.sha256(0, filesize) == "6f65c49d2057a600e59c26b8ca003a17c2f312e3ecc269b8c69a6c0ad24dae19"
}

rule MalwareBazaar_Mirai_094_d614e03b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d614e03ba9ec3b8bc6b942b8e2f4743eab4d43b6620267a73896a11f5387c315"
    family = "Mirai"
    file_name = "zero.m68k"
    file_type = "elf"
    first_seen = "2026-07-29 19:08:44"
  condition:
    hash.sha256(0, filesize) == "d614e03ba9ec3b8bc6b942b8e2f4743eab4d43b6620267a73896a11f5387c315"
}

rule MalwareBazaar_Mirai_095_ee951324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee951324005c874fc6b65d8c0028d206a32c4d3efe1f719fca2e64f0542331ba"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-29 19:03:51"
  condition:
    hash.sha256(0, filesize) == "ee951324005c874fc6b65d8c0028d206a32c4d3efe1f719fca2e64f0542331ba"
}

rule MalwareBazaar_Mirai_096_870f422b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "870f422bb0b9dbcf78765cd258372dc44268ee64d46e074f466c064ffe88f3b8"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-29 19:03:49"
  condition:
    hash.sha256(0, filesize) == "870f422bb0b9dbcf78765cd258372dc44268ee64d46e074f466c064ffe88f3b8"
}

rule MalwareBazaar_Mirai_097_6ea50710
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ea50710c93686f003af4b988504499a27ecd8355b47642c9737dce630950865"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-29 19:02:58"
  condition:
    hash.sha256(0, filesize) == "6ea50710c93686f003af4b988504499a27ecd8355b47642c9737dce630950865"
}

rule MalwareBazaar_Mirai_098_aac8a487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aac8a487f9297ee2fe85b2a96d70ca018c597df314657eaeb9701b730bc8c956"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-29 19:02:56"
  condition:
    hash.sha256(0, filesize) == "aac8a487f9297ee2fe85b2a96d70ca018c597df314657eaeb9701b730bc8c956"
}

rule MalwareBazaar_unknown_099_c297678a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c297678aeeca8dc51d1c9ba9b70505210dd8f43199daa00d4995e0a923336762"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-29 19:02:55"
  condition:
    hash.sha256(0, filesize) == "c297678aeeca8dc51d1c9ba9b70505210dd8f43199daa00d4995e0a923336762"
}

rule MalwareBazaar_Mirai_100_0f46b896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f46b89689bf2d3cbcebff2f1f6986d0591f91f2e06b710a2b2aba771d50f21d"
    family = "Mirai"
    file_name = "zero.armv4l"
    file_type = "elf"
    first_seen = "2026-07-29 19:01:55"
  condition:
    hash.sha256(0, filesize) == "0f46b89689bf2d3cbcebff2f1f6986d0591f91f2e06b710a2b2aba771d50f21d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

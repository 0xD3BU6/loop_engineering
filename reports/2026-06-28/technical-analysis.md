# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-28

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
| Unique family labels | 10 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 47 |
| unknown | 39 |
| Gafgyt | 3 |
| BlankGrabber | 3 |
| SpyNote | 3 |
| Amadey | 1 |
| njrat | 1 |
| Socks5Systemz | 1 |
| IRATA | 1 |
| Vidar | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 60 |
| exe | 19 |
| sh | 8 |
| apk | 6 |
| unknown | 3 |
| msi | 2 |
| js | 2 |

## Per-Sample Analysis

### Sample 1: `c942ecd62cc2de17`

| Field | Value |
|---|---|
| SHA-256 | `c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a` |
| Family label | `Amadey` |
| File name | `C1CDA5F5016B812993DD4858FA6FB949.exe` |
| File type | `exe` |
| First seen | `2026-06-28 04:45:07` |
| Reporter | `abuse_ch` |
| Tags | `Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1cda5f5016b812993dd4858fa6fb949` |
| SHA-1 | `75b70ffacf08e1d1cc7d77fbf3dc719c8711f150` |
| SHA-256 | `c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a` |
| SHA3-384 | `92473b63781faebe52daa31b17349e19253144268dfdc855f8418cfab03c9ec82ba42b25d7d3ffa2efbd59ff74f33f57` |
| IMPHASH | `5a282f0b621c44aabe5e9f6b1dc31d22` |
| TLSH | `T113946B307917D032DA6091711E6AFFF684AD6C259B3145DBBBC40E779E202D26A31F3A` |
| SSDEEP | `6144:2Og7rfAJJqbj5mCI+zmY0da01PhBQNYt8YV0hqX+IPcFzIOd+aTgLAOSbU7wxPt:2Og7rfAJJqb8lRhBQNK4MOd+2iEtxP` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_001_c942ecd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a"
    family = "Amadey"
    file_name = "C1CDA5F5016B812993DD4858FA6FB949.exe"
    file_type = "exe"
    first_seen = "2026-06-28 04:45:07"
  condition:
    hash.sha256(0, filesize) == "c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a"
}
```

### Sample 2: `ae6e5050df886ebe`

| Field | Value |
|---|---|
| SHA-256 | `ae6e5050df886ebe8d391f43c8b97dac2ca4e1b1de6e3021f573ca1dd3a62999` |
| Family label | `Mirai` |
| File name | `flutter.mipsel` |
| File type | `elf` |
| First seen | `2026-06-28 03:52:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f357387f06b80fcea1bfa9bc88afe289` |
| SHA-1 | `fe36c0e414b07e29a91adc8b343509fd574babd9` |
| SHA-256 | `ae6e5050df886ebe8d391f43c8b97dac2ca4e1b1de6e3021f573ca1dd3a62999` |
| SHA3-384 | `5e738db55103210ecfdf1df8e8725b261b8bba4a50522a140ed6277446cc111433b41991ad04b3cd5d23d65f62676e4b` |
| TLSH | `T115344A8A9EA01EDBC46FCD30062E871719ED599BA3F1773AC67CDC48358E24946E385C` |
| TELFHASH | `t198412e729b79a5239ec2c4509cfe9322b51ec11a0a55de27df24844c102e09eb22be9f` |
| SSDEEP | `6144:UX6gAOnXSgXg7kqzJq2ZhFIlkYahfP4TpCCHJlzK/a8L:P9KXSgXg7zJn8kiYC6CS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_ae6e5050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae6e5050df886ebe8d391f43c8b97dac2ca4e1b1de6e3021f573ca1dd3a62999"
    family = "Mirai"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:40"
  condition:
    hash.sha256(0, filesize) == "ae6e5050df886ebe8d391f43c8b97dac2ca4e1b1de6e3021f573ca1dd3a62999"
}
```

### Sample 3: `e8ddc81d5b7fbc35`

| Field | Value |
|---|---|
| SHA-256 | `e8ddc81d5b7fbc3585ae8bdfeb22d612eee224bc58a967eb7c40b9a2a9dccd85` |
| Family label | `Mirai` |
| File name | `flutter.x86_64` |
| File type | `elf` |
| First seen | `2026-06-28 03:52:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0193e5d6257988cb400290464f3a64d` |
| SHA-1 | `88fab23a40731876c79f21fd2fc9e0d3d9a8f0ea` |
| SHA-256 | `e8ddc81d5b7fbc3585ae8bdfeb22d612eee224bc58a967eb7c40b9a2a9dccd85` |
| SHA3-384 | `6e4ff519a1ff2b5233f50d7678952ca9aad3b9bcf2026b1e6974a6f0c550c050ef181399c6b819839a89f7176aacce5d` |
| TLSH | `T1D1044A03A5D294FEC19AC87087AFD536E931349902357A2F6BD8AF312E35E70272E751` |
| TELFHASH | `t1334190706dd938b86293db479312e929fe73095031ee7af85557acd1cd0abc01c66426` |
| SSDEEP | `3072:e7y8rls/UTOjWD/a6ZvXi/DZTGnxy7aed/k+frX9R9MvvpNj+Fm:n8ry/4mWDy6IFax6lk+rX9R94j+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_e8ddc81d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ddc81d5b7fbc3585ae8bdfeb22d612eee224bc58a967eb7c40b9a2a9dccd85"
    family = "Mirai"
    file_name = "flutter.x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:38"
  condition:
    hash.sha256(0, filesize) == "e8ddc81d5b7fbc3585ae8bdfeb22d612eee224bc58a967eb7c40b9a2a9dccd85"
}
```

### Sample 4: `e7cfc962d32487c6`

| Field | Value |
|---|---|
| SHA-256 | `e7cfc962d32487c62508734bdfa918dd7f7faa9d812f71b1ad56b6788dc4bb3b` |
| Family label | `Mirai` |
| File name | `flutter.mipsel` |
| File type | `elf` |
| First seen | `2026-06-28 03:52:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9eb797865a9218fa6c8560cacd827a75` |
| SHA-1 | `f25b70a2302e33432dd246bd09aff515efebc2db` |
| SHA-256 | `e7cfc962d32487c62508734bdfa918dd7f7faa9d812f71b1ad56b6788dc4bb3b` |
| SHA3-384 | `14d98a8081b07d57c203de9394012f89e1432bf23181c38982914f490414be52189251e222748e91e7cab9a70b360158` |
| TLSH | `T182C3127D4C779ABED0DD76B9337342EBE90F2808700064A181782ACA2677FE5D6345CA` |
| SSDEEP | `3072:BgeR+9Q1pi2amTm2rB8IjageDvTg3TRx2V+kS:BgeR+9Q1pirmCJIjnf3TD24` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_e7cfc962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7cfc962d32487c62508734bdfa918dd7f7faa9d812f71b1ad56b6788dc4bb3b"
    family = "Mirai"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:01"
  condition:
    hash.sha256(0, filesize) == "e7cfc962d32487c62508734bdfa918dd7f7faa9d812f71b1ad56b6788dc4bb3b"
}
```

### Sample 5: `05a2e838e3fcc27b`

| Field | Value |
|---|---|
| SHA-256 | `05a2e838e3fcc27b6dbd536d0c123d52e25b341464ed8b38f892f38d38fa6cfa` |
| Family label | `Mirai` |
| File name | `flutter.x86_64` |
| File type | `elf` |
| First seen | `2026-06-28 03:52:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff725b4b2cd1636274f515aac8f73a38` |
| SHA-1 | `119966b578d3135db54b6e158a2546e386d940a1` |
| SHA-256 | `05a2e838e3fcc27b6dbd536d0c123d52e25b341464ed8b38f892f38d38fa6cfa` |
| SHA3-384 | `00ffba77ef80a55027b012bbbb9246afc3dc34d61d3f40e5c5a0c361ead583df9fdda859581bcf2cb0ad5a1f662000c4` |
| TLSH | `T12493023C798A0A17F90A207FB100681F7CDD723967909D60EE792D17BC2FC2EA658647` |
| SSDEEP | `1536:uGKVOfkGoT1+e4lXaJniZWMmNTIGjDRp7KP42C6nKarClsi0XRaZ3F1O:6VOMGo5SlKJzN9/LS427TWlsi0Xcq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_05a2e838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a2e838e3fcc27b6dbd536d0c123d52e25b341464ed8b38f892f38d38fa6cfa"
    family = "Mirai"
    file_name = "flutter.x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:00"
  condition:
    hash.sha256(0, filesize) == "05a2e838e3fcc27b6dbd536d0c123d52e25b341464ed8b38f892f38d38fa6cfa"
}
```

### Sample 6: `7b2a71759e427400`

| Field | Value |
|---|---|
| SHA-256 | `7b2a71759e42740089ac9081f749d854b8d9132eab7e2edbef22279e0c2e8dcf` |
| Family label | `Mirai` |
| File name | `flutter.m68k` |
| File type | `elf` |
| First seen | `2026-06-28 03:51:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3479279d8791a9178ff6458e45b6471` |
| SHA-1 | `a8965e5388fe039dd0312b2b31a26ac6d3a36cd3` |
| SHA-256 | `7b2a71759e42740089ac9081f749d854b8d9132eab7e2edbef22279e0c2e8dcf` |
| SHA3-384 | `619badd8adece5aa3dc8ab63b71af58ebc64442680ef5abd667f8ee21e975e63f3a825da8a97bc0354ceb1ecaba4ed55` |
| TLSH | `T1EDF37CC5B2083D2FD5933F3EC51D16179D0C8F57A8838A1280AAFA875BB39971F3654A` |
| TELFHASH | `t1c2e08cb29fa07a231984c905c4f723b5b16ce48a0a4efd4be340082c40d911f721bd5f` |
| SSDEEP | `3072:OJd8cUINFTv8GcvIk8tddYoeL1TFv8ro3DvXn+iavv8oeM7:udzU4Fr8v0ddYHL1TV2uvX+TZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_7b2a7175
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b2a71759e42740089ac9081f749d854b8d9132eab7e2edbef22279e0c2e8dcf"
    family = "Mirai"
    file_name = "flutter.m68k"
    file_type = "elf"
    first_seen = "2026-06-28 03:51:59"
  condition:
    hash.sha256(0, filesize) == "7b2a71759e42740089ac9081f749d854b8d9132eab7e2edbef22279e0c2e8dcf"
}
```

### Sample 7: `5a9f6ea331964b80`

| Field | Value |
|---|---|
| SHA-256 | `5a9f6ea331964b80df719baa5b14a15ffd5a326cc32dd4849638443e76b8f65a` |
| Family label | `Mirai` |
| File name | `flutter.arm8` |
| File type | `elf` |
| First seen | `2026-06-28 03:51:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fd703d6f08ddd58369efd810a80a24b` |
| SHA-1 | `7643befe22cbc317363b4a509190a0a5d689cfd3` |
| SHA-256 | `5a9f6ea331964b80df719baa5b14a15ffd5a326cc32dd4849638443e76b8f65a` |
| SHA3-384 | `2be6f62cba32f368617541c70d4b695b7505ee192e11b6505d765fd4fe4e6cfac76d267bc47275b9e3112c78b3e157fa` |
| TLSH | `T1A1048E9CAD0EBD01C7DAE3BD8C098B62B03774B44365C1B37D0052AED9BBDA6D5E2521` |
| SSDEEP | `3072:bM44B913uRwRLgOuPucRfFJkniKljNlHayTbD/VUOpPMoilp69KiSvvc5:Q44BDf1RiKl/HaIbDKOp0HpmKK5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_5a9f6ea3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a9f6ea331964b80df719baa5b14a15ffd5a326cc32dd4849638443e76b8f65a"
    family = "Mirai"
    file_name = "flutter.arm8"
    file_type = "elf"
    first_seen = "2026-06-28 03:51:42"
  condition:
    hash.sha256(0, filesize) == "5a9f6ea331964b80df719baa5b14a15ffd5a326cc32dd4849638443e76b8f65a"
}
```

### Sample 8: `26a65e84c4ed6721`

| Field | Value |
|---|---|
| SHA-256 | `26a65e84c4ed6721d591f8c50676405bd240198185891773be2b7855e9f95133` |
| Family label | `Mirai` |
| File name | `flutter.arm8` |
| File type | `elf` |
| First seen | `2026-06-28 03:51:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47f2fc9ee1d3c734ba6d37846615fa61` |
| SHA-1 | `e7967e9b25ec85a6611e056e72c8d5d8713c0838` |
| SHA-256 | `26a65e84c4ed6721d591f8c50676405bd240198185891773be2b7855e9f95133` |
| SHA3-384 | `7cbd743db57da51d5804de0f4051ac7083e6a2e88d2ade1cf6886cdd59557a5e216516d2552c1db9ea68f41a4973b608` |
| TLSH | `T1899302D4345C85A8F11474FCE5401AC40F1EF4BD2E7669EB5206A4B41A6523EF62B3CF` |
| SSDEEP | `1536:ixzFVzpp7hQw+mkl6DsFz2P6Oj4GgnkbuFp7Np94kUnPqG6up08fLHw52EE:eVp7h3+mi662iBGgkbmxpqSG708DQfE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_26a65e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a65e84c4ed6721d591f8c50676405bd240198185891773be2b7855e9f95133"
    family = "Mirai"
    file_name = "flutter.arm8"
    file_type = "elf"
    first_seen = "2026-06-28 03:51:00"
  condition:
    hash.sha256(0, filesize) == "26a65e84c4ed6721d591f8c50676405bd240198185891773be2b7855e9f95133"
}
```

### Sample 9: `89a8132ebca5b6de`

| Field | Value |
|---|---|
| SHA-256 | `89a8132ebca5b6de89c9890a5e911883c2e0b58216161705eb6042a6ebb9b775` |
| Family label | `Mirai` |
| File name | `flutter.ppc` |
| File type | `elf` |
| First seen | `2026-06-28 03:50:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17be67fd28db0d7c79f2616775ba8665` |
| SHA-1 | `27638da0a37ce54debfa9dac8d1f37256cdcad95` |
| SHA-256 | `89a8132ebca5b6de89c9890a5e911883c2e0b58216161705eb6042a6ebb9b775` |
| SHA3-384 | `4cf29619b607bbbfb1523b8fc8960236c782e51e14962246edf17647ecbd9824f151b2a21746389cd55ff66081fab6d1` |
| TLSH | `T153147D01FB284653D5925FB44B3B0776D32D499308BAF00D1E0BBB1A1673EF6A19B789` |
| SSDEEP | `6144:W452Elr2kd1PD5yP/l9iG+N9sJsCR6meqq:WZkrP69YsGqq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_89a8132e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89a8132ebca5b6de89c9890a5e911883c2e0b58216161705eb6042a6ebb9b775"
    family = "Mirai"
    file_name = "flutter.ppc"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:51"
  condition:
    hash.sha256(0, filesize) == "89a8132ebca5b6de89c9890a5e911883c2e0b58216161705eb6042a6ebb9b775"
}
```

### Sample 10: `04e16f35916321da`

| Field | Value |
|---|---|
| SHA-256 | `04e16f35916321dab115dab2fd960623dc43e29f2c24f2094b492e5b48ffb8c8` |
| Family label | `Mirai` |
| File name | `flutter.mips` |
| File type | `elf` |
| First seen | `2026-06-28 03:50:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f30f578b47dda1aa1c7e5e202f2168c6` |
| SHA-1 | `fe9d748ac48fb5aac334f44c8e2557501acb6ffb` |
| SHA-256 | `04e16f35916321dab115dab2fd960623dc43e29f2c24f2094b492e5b48ffb8c8` |
| SHA3-384 | `ab2b95f29ab6d1405d85a86bed565aa65b34d51817ecd616e052db11601c96ddb5506de2d7b4ac9bb1df779c125662c6` |
| TLSH | `T142345C4B77A08F90E275D93006F34AA39AB9129317E39545E2BDDE113E6034C6C2FFA4` |
| TELFHASH | `t198412e729b79a5239ec2c4509cfe9322b51ec11a0a55de27df24844c102e09eb22be9f` |
| SSDEEP | `6144:Ic4e/ON6IYZhMY6GsMMZf0TsyfHJLXDX6/WM8+:IVedIYZ9mas6XDKOM7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_04e16f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04e16f35916321dab115dab2fd960623dc43e29f2c24f2094b492e5b48ffb8c8"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:48"
  condition:
    hash.sha256(0, filesize) == "04e16f35916321dab115dab2fd960623dc43e29f2c24f2094b492e5b48ffb8c8"
}
```

### Sample 11: `4229febbc3cd893a`

| Field | Value |
|---|---|
| SHA-256 | `4229febbc3cd893a2010b1d4a4174c9faac5a086973ffcc639d6f8ea9bee2c1b` |
| Family label | `Mirai` |
| File name | `flutter.x86` |
| File type | `elf` |
| First seen | `2026-06-28 03:50:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e320beb127e0ee7a49712913ec19577` |
| SHA-1 | `049f52e0f60f999a8a034229cc80663fa259961d` |
| SHA-256 | `4229febbc3cd893a2010b1d4a4174c9faac5a086973ffcc639d6f8ea9bee2c1b` |
| SHA3-384 | `b63ee46ad7f9597c89312d9908e558f3b73ab82d2b122c8f24abee72e64f904913ad01483b62e32181b35e65bfbaab83` |
| TLSH | `T16A046B1BEA43E170E0739031414ADBB78639A9344342C417FBA63E35EDB46C5E686B2E` |
| SSDEEP | `3072:zd0RVke0elWIB8fv20kaauytqInqOowFS5PRariTqWc0avvaMx9:zd0keHBO20kaauycIqwDWxMx9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_4229febb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4229febbc3cd893a2010b1d4a4174c9faac5a086973ffcc639d6f8ea9bee2c1b"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:45"
  condition:
    hash.sha256(0, filesize) == "4229febbc3cd893a2010b1d4a4174c9faac5a086973ffcc639d6f8ea9bee2c1b"
}
```

### Sample 12: `d6262ccd82f491d1`

| Field | Value |
|---|---|
| SHA-256 | `d6262ccd82f491d10bc9b8e5c6eb30f57c67c186b5cbc21766f1ad903f837b1d` |
| Family label | `Mirai` |
| File name | `flutter.ppc` |
| File type | `elf` |
| First seen | `2026-06-28 03:50:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `226e5f566267acfd8ce24786ba70427f` |
| SHA-1 | `b8ff8b1a1d0322fd62467722adadcf770da44eb0` |
| SHA-256 | `d6262ccd82f491d10bc9b8e5c6eb30f57c67c186b5cbc21766f1ad903f837b1d` |
| SHA3-384 | `1dc01bc47f0c60c1abd51b740bb4715e9da2494ed897c58f10dfcf0a75887014f20e5d198202e40a9d9d04757e75be8e` |
| TLSH | `T134A3128B0594ED89E165FEF81F36E6FD958148EC3002A5D152F94B9EC6233BC58B06F1` |
| SSDEEP | `3072:6BorFGfqnIV66575fyJPcHYAmw9wgrg71F:kQFIV6SkFgdnpg7T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_d6262ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6262ccd82f491d10bc9b8e5c6eb30f57c67c186b5cbc21766f1ad903f837b1d"
    family = "Mirai"
    file_name = "flutter.ppc"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:00"
  condition:
    hash.sha256(0, filesize) == "d6262ccd82f491d10bc9b8e5c6eb30f57c67c186b5cbc21766f1ad903f837b1d"
}
```

### Sample 13: `03dea2fdbbece0bb`

| Field | Value |
|---|---|
| SHA-256 | `03dea2fdbbece0bb95bcc7d1d0e46878d55f666efb087184a9a2bdde79cec5a2` |
| Family label | `Mirai` |
| File name | `flutter.mips` |
| File type | `elf` |
| First seen | `2026-06-28 03:49:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e22557694d8e0f071850e763d405986` |
| SHA-1 | `7e9a3d97710eff78b8a184523122b334fe2ed93f` |
| SHA-256 | `03dea2fdbbece0bb95bcc7d1d0e46878d55f666efb087184a9a2bdde79cec5a2` |
| SHA3-384 | `eaa0bed2bc8b09eb0059479bd26d765b86df224d32c766a2caa02629df12d8e7b69e0519ff69aa9c06420252c6532815` |
| TLSH | `T1F4C3127DD890F534901FB538C3E28FEAD8714C5D8FAF95AFC166A601C75A2F27125822` |
| SSDEEP | `3072:AuPh6tqntbVLhHWbo6s/Z+F57mFdyV2OU2WWp8E:X56tqnB32iZm4dyVxB8E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_03dea2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03dea2fdbbece0bb95bcc7d1d0e46878d55f666efb087184a9a2bdde79cec5a2"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-06-28 03:49:58"
  condition:
    hash.sha256(0, filesize) == "03dea2fdbbece0bb95bcc7d1d0e46878d55f666efb087184a9a2bdde79cec5a2"
}
```

### Sample 14: `eb413a5266524253`

| Field | Value |
|---|---|
| SHA-256 | `eb413a52665242534572609a704d17b990599e3ace305d2abaeda555c9762ace` |
| Family label | `Mirai` |
| File name | `flutter.x86` |
| File type | `elf` |
| First seen | `2026-06-28 03:49:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cf053295fabe3cd3616721530e7d881` |
| SHA-1 | `a44f820f655a538daf177aa62b2e899db5ca57ac` |
| SHA-256 | `eb413a52665242534572609a704d17b990599e3ace305d2abaeda555c9762ace` |
| SHA3-384 | `632340da789166cf1b640a10ca36a449b84212267b351f45fb029ef2d15833f08c8709ec1f9576716a6bcdcba79cf309` |
| TLSH | `T14393020B64A4A87BFA7B8C79322A1FF435E4A01C2DFEF59F121A6F11E14B940366D714` |
| SSDEEP | `1536:KfVkpSBnbs9C/GPD0/QfXe3qD9SmuXRBTFbIL0cw3Sw8mFIzVmT7VacVbB:KfV+SBnVG1exxDRIAcw3Iz0T7wcVbB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_eb413a52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb413a52665242534572609a704d17b990599e3ace305d2abaeda555c9762ace"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-06-28 03:49:57"
  condition:
    hash.sha256(0, filesize) == "eb413a52665242534572609a704d17b990599e3ace305d2abaeda555c9762ace"
}
```

### Sample 15: `e7730ccf5bfcb40d`

| Field | Value |
|---|---|
| SHA-256 | `e7730ccf5bfcb40df1c54f1600cdee4c0c56cb88fdcc6ae9c338d36a1a7f994d` |
| Family label | `Gafgyt` |
| File name | `m-6.8-k.Sakura` |
| File type | `elf` |
| First seen | `2026-06-28 03:29:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffc3f4db19d7755835d1b7773734d913` |
| SHA-1 | `3b00f0622a660d8daea4ef156057a756187a687a` |
| SHA-256 | `e7730ccf5bfcb40df1c54f1600cdee4c0c56cb88fdcc6ae9c338d36a1a7f994d` |
| SHA3-384 | `87f4f098d4d01685fa81bc2f7eb402a789262d836dd0cb9e129ad3ef24a57947da7041572431738e3cc125b095677a94` |
| TLSH | `T11E042A04E6404B57C2E227BAF7CB424D33339B94A3DB33159938ABB43FC27995E26525` |
| TELFHASH | `t172211d03a1eaca292bb79a34ac7847f102556a2363927e317f0ec5c444370437978edb` |
| SSDEEP | `3072:Z5adk1Iab0TLjD7E9J0IrvakiGYL/Ckh7sDFVTmiw5BniQlgA:Z5adiIab0TLj3ElukiGYL/Cvmiw5Bn5p` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_015_e7730ccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7730ccf5bfcb40df1c54f1600cdee4c0c56cb88fdcc6ae9c338d36a1a7f994d"
    family = "Gafgyt"
    file_name = "m-6.8-k.Sakura"
    file_type = "elf"
    first_seen = "2026-06-28 03:29:59"
  condition:
    hash.sha256(0, filesize) == "e7730ccf5bfcb40df1c54f1600cdee4c0c56cb88fdcc6ae9c338d36a1a7f994d"
}
```

### Sample 16: `239adbe22edee724`

| Field | Value |
|---|---|
| SHA-256 | `239adbe22edee724d96e4b5fe0f4a7213c8eba6dba33ff938340dd33aaa08ad6` |
| Family label | `Gafgyt` |
| File name | `m-i.p-s.Sakura` |
| File type | `elf` |
| First seen | `2026-06-28 03:29:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `544630271edf03986a412bbfa6dcf3c0` |
| SHA-1 | `f93bec6494b24956bbe9e3458cdf6d749e520f75` |
| SHA-256 | `239adbe22edee724d96e4b5fe0f4a7213c8eba6dba33ff938340dd33aaa08ad6` |
| SHA3-384 | `3d6b6e4953ced13f572d79cc9c41b5b1449afc93fc85c9196a2fdab91f68ae65d020702d41314bd6e6720b1806b02315` |
| TLSH | `T104E3843E7E22BFBEE26882310BF35F70979561D227919346E26CE6181E7128D1C5F760` |
| TELFHASH | `t1a9210d4371faca292bb356346cb842f112956a233391be71bf1dc5c494370027974ecb` |
| SSDEEP | `1536:LqAo2mV7PguPkn02rKCpSuSdS3So82rKCcS1LFfqFp3nem1nYose/d4RJJFOAmDP:lKGdrZWn71vORJ/mDOVcG1DJ01so` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_016_239adbe2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239adbe22edee724d96e4b5fe0f4a7213c8eba6dba33ff938340dd33aaa08ad6"
    family = "Gafgyt"
    file_name = "m-i.p-s.Sakura"
    file_type = "elf"
    first_seen = "2026-06-28 03:29:57"
  condition:
    hash.sha256(0, filesize) == "239adbe22edee724d96e4b5fe0f4a7213c8eba6dba33ff938340dd33aaa08ad6"
}
```

### Sample 17: `3bbcf6984724e025`

| Field | Value |
|---|---|
| SHA-256 | `3bbcf6984724e025180a86a790ff6e7fb442c4e66e0eb0518e2c553a2e698322` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-06-28 03:29:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `980251549a673b0f0803d2930cf4c64a` |
| SHA-1 | `b370790b4717c6066fc151ae17f98b69fd0d5bed` |
| SHA-256 | `3bbcf6984724e025180a86a790ff6e7fb442c4e66e0eb0518e2c553a2e698322` |
| SHA3-384 | `a063dca24781d4f3f10c8d37fecfbf479a610eeaa77d4944d4dccd9d73e6ec13f4b19913dd516df25d2e3425f772dfec` |
| TLSH | `T195637EC9E287D8F6FC1705702036E73BAE71E0AA211CE696C778D5B1FC86941A117ADC` |
| TELFHASH | `t16e31d7ff0ebe18a8b7c06980835e6e215819e537046036a44562a96866dfdc550bec3d` |
| SSDEEP | `1536:pnUQJZdRlDAXO6QyQUK6+QGpxUx97qJ7RvsuIr5bhd8s:pnUQJ7RlUXTQpUK6+QAxUn72+uWcs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_3bbcf698
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bbcf6984724e025180a86a790ff6e7fb442c4e66e0eb0518e2c553a2e698322"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-06-28 03:29:56"
  condition:
    hash.sha256(0, filesize) == "3bbcf6984724e025180a86a790ff6e7fb442c4e66e0eb0518e2c553a2e698322"
}
```

### Sample 18: `4b516f504ee1a53a`

| Field | Value |
|---|---|
| SHA-256 | `4b516f504ee1a53a1056067398e231cf2a0011152335e06d680cc0876ec30383` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-28 03:19:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `609c38599c8b98d761612b8124b65fe8` |
| SHA-1 | `518efd80f3f41107e02489a10c6cafdbd8be009b` |
| SHA-256 | `4b516f504ee1a53a1056067398e231cf2a0011152335e06d680cc0876ec30383` |
| SHA3-384 | `a27648fccc9ed6f842d64515a6115bb2c700abf3229e5edd368897503f564bc346f3ee471ae52347b49cfdd3fe1a8a34` |
| TLSH | `T1F56629137E1CE70EE12822345DB2CAC4A7291C9642D6A917A351F318F9F306D9E6EDF1` |
| TELFHASH | `t1ddb0921788a00a48a0a248c14ec4715141e2ed23182965aebf750dd64e0e806006d416` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:inaDeYojrY6ZL2Gkt6q3PoJ9+MK5gymK7J0mi6dhCylp/4UTTrv2uC9kheBCKuHW:s1KhhCyl7xn4jEi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_4b516f50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b516f504ee1a53a1056067398e231cf2a0011152335e06d680cc0876ec30383"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:08"
  condition:
    hash.sha256(0, filesize) == "4b516f504ee1a53a1056067398e231cf2a0011152335e06d680cc0876ec30383"
}
```

### Sample 19: `a0ac62b9a8c8f2bd`

| Field | Value |
|---|---|
| SHA-256 | `a0ac62b9a8c8f2bdebbeffa5ea6ba90c88d07f595fe1b39ff11d521ddb881a99` |
| Family label | `Mirai` |
| File name | `android_arm64` |
| File type | `elf` |
| First seen | `2026-06-28 03:19:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73702a508a923a0f3430e551e6ea9e11` |
| SHA-1 | `8ff6b2eea92fbc10703cbd08167521ce3b097aee` |
| SHA-256 | `a0ac62b9a8c8f2bdebbeffa5ea6ba90c88d07f595fe1b39ff11d521ddb881a99` |
| SHA3-384 | `47c1dd581841e798c837243c262540f443097a14ec380d10926ff99d9eb7bb9136bc49a74a0d99279364a62bbb7cff51` |
| TLSH | `T11F56286DF82EE5A2EDC976B15E6103877239BC085B81C312A714BA3DBAF73C48F12551` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:h0r14+M2hjg/G1mzGvENNLLuT5fq7iQ3jUc5E9:h0R4L2qEm6voSfWi2jUOE9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_a0ac62b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0ac62b9a8c8f2bdebbeffa5ea6ba90c88d07f595fe1b39ff11d521ddb881a99"
    family = "Mirai"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:06"
  condition:
    hash.sha256(0, filesize) == "a0ac62b9a8c8f2bdebbeffa5ea6ba90c88d07f595fe1b39ff11d521ddb881a99"
}
```

### Sample 20: `d4da359838c9d2f8`

| Field | Value |
|---|---|
| SHA-256 | `d4da359838c9d2f850f5b51266b5870ad82b7f1ebfea60baa81d7058dd4429da` |
| Family label | `Mirai` |
| File name | `mipsle` |
| File type | `elf` |
| First seen | `2026-06-28 03:19:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3711839a4369e09f26524bad44e61513` |
| SHA-1 | `fa8bf01945751afb4d2e0e57ce1884e36b77c72a` |
| SHA-256 | `d4da359838c9d2f850f5b51266b5870ad82b7f1ebfea60baa81d7058dd4429da` |
| SHA3-384 | `95a1a154af3397dfa7816dfcc9b43bbd72a5fb7172273bfca8e21193bec62437a6c664a765096e452d99b0eb7d54df45` |
| TLSH | `T1A966E809AD842BE6C85D4B3484EACA9613B05D144BF1463B56A4FBADBC772787F07C8C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:NkDVbeLAMajMtpzVXc88tNXjnoitIv88888X88888888i8N88888g1kp829IJg+v:C1SCBIEF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_d4da3598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4da359838c9d2f850f5b51266b5870ad82b7f1ebfea60baa81d7058dd4429da"
    family = "Mirai"
    file_name = "mipsle"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:04"
  condition:
    hash.sha256(0, filesize) == "d4da359838c9d2f850f5b51266b5870ad82b7f1ebfea60baa81d7058dd4429da"
}
```

### Sample 21: `1a7c957b107b4ecc`

| Field | Value |
|---|---|
| SHA-256 | `1a7c957b107b4eccfe3c079472b457fd3c13068bc6b65c69c1bdf536d353bf8a` |
| Family label | `Mirai` |
| File name | `arm64` |
| File type | `elf` |
| First seen | `2026-06-28 03:19:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e28fd12fd6f4cd301522c69854faad66` |
| SHA-1 | `73524232bed1b2ae880ec69506c261228a42f26c` |
| SHA-256 | `1a7c957b107b4eccfe3c079472b457fd3c13068bc6b65c69c1bdf536d353bf8a` |
| SHA3-384 | `15c031f11d6519f4fc06c97efb35ae0ff8172fc4d80ce1cc59f60f0bb3bbc421bbe64c0c02e0745f4c36e9258fc3a885` |
| TLSH | `T135466C45BC1D2862D6C97A752F7613D47239BC489F82D3232618F73DB9F27988F122A1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:VsshjbSTEB15vk/pKDdpp/ggS6dLegGVzT5Ei:VsmvNRvWp4/5ddElEi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_1a7c957b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a7c957b107b4eccfe3c079472b457fd3c13068bc6b65c69c1bdf536d353bf8a"
    family = "Mirai"
    file_name = "arm64"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:02"
  condition:
    hash.sha256(0, filesize) == "1a7c957b107b4eccfe3c079472b457fd3c13068bc6b65c69c1bdf536d353bf8a"
}
```

### Sample 22: `546c20af1d14d8f6`

| Field | Value |
|---|---|
| SHA-256 | `546c20af1d14d8f69618c0d3a1696b0815a1b0cec1a3c351f516a66cb781cfe1` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-28 03:19:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8832c06e718636543f9dc53351bf879e` |
| SHA-1 | `aeca31304360380b5080736cd3af5e45c924f720` |
| SHA-256 | `546c20af1d14d8f69618c0d3a1696b0815a1b0cec1a3c351f516a66cb781cfe1` |
| SHA3-384 | `77d966e88c12dffe257b118c592c24c16f125f14d3bcf8b6c8bd51bec9bf4b8bda13ebc85c5fc5170596c2d439ab39c8` |
| TLSH | `T12F461897B9D25983C4E43A7BA8BE80C433634EB99B8712565D14FE383EBE1D90E35344` |
| TELFHASH | `t118e0d8998e2d36ac29d44080151d119e4de031fc0b003b9c4f1e778f130362875c489b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:EoxUbdGOZ4v5FC5HTuDgDvGQO3qqnul5Ev:zxUbdz4v5f6GP3qWwEv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_546c20af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "546c20af1d14d8f69618c0d3a1696b0815a1b0cec1a3c351f516a66cb781cfe1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:01"
  condition:
    hash.sha256(0, filesize) == "546c20af1d14d8f69618c0d3a1696b0815a1b0cec1a3c351f516a66cb781cfe1"
}
```

### Sample 23: `db11e9ffefc70af6`

| Field | Value |
|---|---|
| SHA-256 | `db11e9ffefc70af6f51b4ffd4c0d127d0dd075667b62a48c095a211c4364c41d` |
| Family label | `Mirai` |
| File name | `i386` |
| File type | `elf` |
| First seen | `2026-06-28 03:18:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fadb789df82b02628d28583f149e9b5a` |
| SHA-1 | `3d0920ed4a294a1147903233bef23007d8201320` |
| SHA-256 | `db11e9ffefc70af6f51b4ffd4c0d127d0dd075667b62a48c095a211c4364c41d` |
| SHA3-384 | `b4fcd67549c81b22008d8b52ecd58bfad312bd98e91011a4c7a8e49db81fb052f6421fd52d51576e863479d36bf056a1` |
| TLSH | `T197461711FECB14F6E9031E3108BBA26F63355D058B24EBD7EB407E69F97B6911932209` |
| TELFHASH | `t1eed2ddb7059da4eca7e0840796af7120cff5e03726e0387129e7b8c15773d53aa26878` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:+m4AV7kST2vASSXumIYTtWXdVyi67JrcwxG2tahapP4WZDvFwfk8aCI5Ek:+qkST2fSAYTtIdVyz7u2jAW5Ek` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_db11e9ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db11e9ffefc70af6f51b4ffd4c0d127d0dd075667b62a48c095a211c4364c41d"
    family = "Mirai"
    file_name = "i386"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:59"
  condition:
    hash.sha256(0, filesize) == "db11e9ffefc70af6f51b4ffd4c0d127d0dd075667b62a48c095a211c4364c41d"
}
```

### Sample 24: `ddcb3ddec77d4780`

| Field | Value |
|---|---|
| SHA-256 | `ddcb3ddec77d47804ea560d2ac6459925d85236a52854fd7106653c41128e49f` |
| Family label | `Mirai` |
| File name | `amd64` |
| File type | `elf` |
| First seen | `2026-06-28 03:18:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00041b0fdcd7183256e416330bc817b7` |
| SHA-1 | `7ab01ed50c56fca004cdaf6ba0a3b700f2917249` |
| SHA-256 | `ddcb3ddec77d47804ea560d2ac6459925d85236a52854fd7106653c41128e49f` |
| SHA3-384 | `766e89f70f2fbad06616ecf31153e2210c4d52dbe46134edf4ee37732eb77cbe85c6d5c7155565d9609217a2d4cb15f5` |
| TLSH | `T139564A17ECA555E9C0AED2308A62A553BB71BC492B3163D32B50F3382F77BD06A79344` |
| TELFHASH | `t12752a73549bd35b5a6aada11f3a2b5f4a9371c6532f434f11023a984ffc1e801cea877` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:sRDGf29AEbeaAz1hlTAKVPnGC5Wl1sWpPWCtRL631FvECCviNNB/KlK1KcJJH5E7:sR1910cPWsePfJhJzE7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_ddcb3dde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddcb3ddec77d47804ea560d2ac6459925d85236a52854fd7106653c41128e49f"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:57"
  condition:
    hash.sha256(0, filesize) == "ddcb3ddec77d47804ea560d2ac6459925d85236a52854fd7106653c41128e49f"
}
```

### Sample 25: `e3e4bebafddb63fe`

| Field | Value |
|---|---|
| SHA-256 | `e3e4bebafddb63fee04a5e6dce99f4f2188115282794b6166865b38acd9cc7d2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-28 03:18:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de595161e1836427e8e5c2b765093548` |
| SHA-1 | `e7c6ef8de95734b39ceb8ca02a0d589a069dcfd1` |
| SHA-256 | `e3e4bebafddb63fee04a5e6dce99f4f2188115282794b6166865b38acd9cc7d2` |
| SHA3-384 | `85fb5e6bac7901bd78d2376972b5c2032ab395bba607b3f3ac0620de379e890f58a64239d0453a2ce4efc51785b09ac4` |
| TLSH | `T17A560897B9D24942C4E43A7BB8BD80C433631EB99BC612665D14FE383EBE1D90E39354` |
| TELFHASH | `t101e0488a8e5c2a9c55d0d2840996035eced435fc17507ba98f9f77db07829d570cb41e` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:kzNk2SO8nYoc0nsBPuRRsZjGPYtCXLjij5E2:gdKYN0sBPuTwtC7jCE2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_e3e4beba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3e4bebafddb63fee04a5e6dce99f4f2188115282794b6166865b38acd9cc7d2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:56"
  condition:
    hash.sha256(0, filesize) == "e3e4bebafddb63fee04a5e6dce99f4f2188115282794b6166865b38acd9cc7d2"
}
```

### Sample 26: `21d6961360c96072`

| Field | Value |
|---|---|
| SHA-256 | `21d6961360c9607230396b4458990f1816cfa4608bc2f1d943f2ddbcd003de70` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-06-28 03:18:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09b31cb7bf982dbfe7a0197eeca99d1f` |
| SHA-1 | `21cc1d366af8dc8b9d7e53df9f2aba980075febc` |
| SHA-256 | `21d6961360c9607230396b4458990f1816cfa4608bc2f1d943f2ddbcd003de70` |
| SHA3-384 | `74dac24568dd734811ea44c6d997842e0870ddef5a93ddf0a07ca0cbecde2659d81a1ce27808f97686990b5007b6804b` |
| TLSH | `T10E461897B9D25943C4E4367BB8BD80C833631EF9AB8652565D04FE383ABE1D90E35348` |
| TELFHASH | `t120e0d8968d6d369431d082455559079ecfe438fc130027ec8fab778f4745965b4cb41f` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:f+nR9440iRqOL/MHHqZnfLHYV8a7Nck/SI5lh5Ex:mR94FiRf/MH9J7Nt6GEx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_21d69613
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d6961360c9607230396b4458990f1816cfa4608bc2f1d943f2ddbcd003de70"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:54"
  condition:
    hash.sha256(0, filesize) == "21d6961360c9607230396b4458990f1816cfa4608bc2f1d943f2ddbcd003de70"
}
```

### Sample 27: `a5602dae7c1e2168`

| Field | Value |
|---|---|
| SHA-256 | `a5602dae7c1e216851e295865023239476ed76677abf46ec7626a17cd2ae29b4` |
| Family label | `unknown` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-06-28 03:18:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c01a85d1da1db0e10f0a896b801c575c` |
| SHA-1 | `6c82ad6b7fcada2ec49b37322a80766b2bab0833` |
| SHA-256 | `a5602dae7c1e216851e295865023239476ed76677abf46ec7626a17cd2ae29b4` |
| SHA3-384 | `5cda6f6efe341a565cbdef8fbb19d4a0ac2b8faaae47de5283932350b62ade50fa4c69845506cd10bdbf16aae529f24c` |
| TLSH | `T1E141E39B227080B3840FDE69FB5491D1E18A47E2B5A3CFF8B46D446B009D26CB5B2E30` |
| SSDEEP | `24:iuOJMRtVIZ3/2HToHZB79B7KscNI4ANIx9KP71KPsd2vfV2v4v5WSQH7As/J2:+QPwjOHKPZKPu2vd2vHHUg8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_a5602dae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5602dae7c1e216851e295865023239476ed76677abf46ec7626a17cd2ae29b4"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-06-28 03:18:52"
  condition:
    hash.sha256(0, filesize) == "a5602dae7c1e216851e295865023239476ed76677abf46ec7626a17cd2ae29b4"
}
```

### Sample 28: `33a7648c64588e85`

| Field | Value |
|---|---|
| SHA-256 | `33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb` |
| Family label | `unknown` |
| File name | `loader.ps1.bin` |
| File type | `unknown` |
| First seen | `2026-06-28 03:00:21` |
| Reporter | `anonymous` |
| Tags | `beacon, Cobalt Strike, hashed dll, loader, multi-stage, Powershell, Russia` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b15592bbe1cb0b82501c69b5c43d83c0` |
| SHA-256 | `33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_33a7648c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb"
    family = "unknown"
    file_name = "loader.ps1.bin"
    file_type = "unknown"
    first_seen = "2026-06-28 03:00:21"
  condition:
    hash.sha256(0, filesize) == "33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb"
}
```

### Sample 29: `b2687e641c114589`

| Field | Value |
|---|---|
| SHA-256 | `b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-28 02:30:56` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `011c4ffba12eb2a298ff83159177ca7a` |
| SHA-1 | `71f8c01b5819fe2d77519326317a1922cbd92a40` |
| SHA-256 | `b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7` |
| SHA3-384 | `dc4185575f1ccb0bcd6341c627b671823c05c997033afddbd1d59b4c0a6c62354bc707e76e97c0b0336b6cf787b53e33` |
| IMPHASH | `e387f9bdbdc891a56417c52c45ed0b91` |
| TLSH | `T16A75232107E864B6D45AA3B8C5F6035398B0BC615B3569DF3284BA7D5F73AC0E432B86` |
| SSDEEP | `24576:+fNfaTYDXNTwp8/TmSCOUC+L3KhXpHA88hVM3rgDzCXz6RE9EL2YwGFL9d:hYWpKTmSB8L3Kpg8OM3Ez9NL2YFT` |
| ICON-DHASH | `68f8da8edddc9c98` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_b2687e64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-28 02:30:56"
  condition:
    hash.sha256(0, filesize) == "b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7"
}
```

### Sample 30: `8d813de09c2124bf`

| Field | Value |
|---|---|
| SHA-256 | `8d813de09c2124bfd87ea963b031730e10bd646817cecdb5195c829c3c34d6a9` |
| Family label | `unknown` |
| File name | `a-software85659006.msi` |
| File type | `msi` |
| First seen | `2026-06-28 02:24:32` |
| Reporter | `GDHJDSYDH1` |
| Tags | `backdoor, dropper, Gh0stRat, msi, SilverFox, ValleyRat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f24de5e6db99994cf189a3df224a0037` |
| SHA-1 | `9c6f806fc474406403ec16c2161e41870c2b4798` |
| SHA-256 | `8d813de09c2124bfd87ea963b031730e10bd646817cecdb5195c829c3c34d6a9` |
| SHA3-384 | `19d2142e3ccfc9775500c10d3cdc2ecb92d4b93d7fffb0d2c18ed755d884d429afc2c1b7b65e5ed36c29f8be25536c55` |
| TLSH | `T1E4563397B5C218F8D00BDBB4025762AE713A7FD5CFA48D46B3EA790D0C7261964F2287` |
| SSDEEP | `98304:1gmNIbJGVDcbdpq4ZDBZiJNsTFUnai9orzolVyddWjUcAbgA6e5P4esDgw:FNIb2iq4ZFZsNsTKnRColVvjUc9Ad+fb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_8d813de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d813de09c2124bfd87ea963b031730e10bd646817cecdb5195c829c3c34d6a9"
    family = "unknown"
    file_name = "a-software85659006.msi"
    file_type = "msi"
    first_seen = "2026-06-28 02:24:32"
  condition:
    hash.sha256(0, filesize) == "8d813de09c2124bfd87ea963b031730e10bd646817cecdb5195c829c3c34d6a9"
}
```

### Sample 31: `0cb1d3623ab8dd0e`

| Field | Value |
|---|---|
| SHA-256 | `0cb1d3623ab8dd0e3647a6769fc9d793499745e055a8d5c90a1ce97ba7de14fd` |
| Family label | `unknown` |
| File name | `ToDesk_Lite-x64.6.3.4.msi` |
| File type | `msi` |
| First seen | `2026-06-28 02:20:57` |
| Reporter | `GDHJDSYDH1` |
| Tags | `backdoor, DonutLoader, dropper, msi, SilverFox, ValleyRat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e38fbe11fbabf72746033de296353bb4` |
| SHA-1 | `ffdb8e5ce1c326ede832024e29c6232a0f1bf0f0` |
| SHA-256 | `0cb1d3623ab8dd0e3647a6769fc9d793499745e055a8d5c90a1ce97ba7de14fd` |
| SHA3-384 | `468e68131440bd345eac61e48316d95e4731091e0b950c91a625841f6157d977c24970d8eb01f904e146b4d70217398b` |
| TLSH | `T111472321759EC132FA6F06B15629EA2AE43C7DF20B7404EBA3E4F94966704C25335F93` |
| SSDEEP | `786432:KuJSY0IRnuMoWg/pA8xebjPFOprNr50BvBt:Ku07yu6g/aEfY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_0cb1d362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cb1d3623ab8dd0e3647a6769fc9d793499745e055a8d5c90a1ce97ba7de14fd"
    family = "unknown"
    file_name = "ToDesk_Lite-x64.6.3.4.msi"
    file_type = "msi"
    first_seen = "2026-06-28 02:20:57"
  condition:
    hash.sha256(0, filesize) == "0cb1d3623ab8dd0e3647a6769fc9d793499745e055a8d5c90a1ce97ba7de14fd"
}
```

### Sample 32: `c7837a865e34ae9a`

| Field | Value |
|---|---|
| SHA-256 | `c7837a865e34ae9a115b9cdfb9936d5061aacd9a86e6a6dff8b6dd4c935d6cf7` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-06-28 02:07:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b69ef614716d7535678c9d16c97ebcd` |
| SHA-1 | `939eadbef00ead31c26389af557d046fc7053e34` |
| SHA-256 | `c7837a865e34ae9a115b9cdfb9936d5061aacd9a86e6a6dff8b6dd4c935d6cf7` |
| SHA3-384 | `93738e0fa0040425b65ae3dec491a490debe4727a346349914027e970d220d2384aca8a1868b65a1bf633b96d2e5304f` |
| TLSH | `T15414F742BD51AF23C1E232BAFB9E428D37196B69D1EB72069C317F5037C68DA0D76241` |
| TELFHASH | `t1133111b15f681b6c27c5c18493de723d5b6876ea2b82380a5e959b0b8807ec0b01f837` |
| SSDEEP | `3072:Aji22Iakv4M7tXTc+WmCAniyrRaxH6x0AghrDOE9hBlYlY2T3:AjQaiS4R6KAWrDOEHBl8Y2T3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_c7837a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7837a865e34ae9a115b9cdfb9936d5061aacd9a86e6a6dff8b6dd4c935d6cf7"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-28 02:07:37"
  condition:
    hash.sha256(0, filesize) == "c7837a865e34ae9a115b9cdfb9936d5061aacd9a86e6a6dff8b6dd4c935d6cf7"
}
```

### Sample 33: `18e57f5792c996a5`

| Field | Value |
|---|---|
| SHA-256 | `18e57f5792c996a533aed3495be74f7d8a25ca7a14ac57b56ef0f3bb05505a7d` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-06-28 02:06:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82d6f1ebb21c97aec03cea43bd132b55` |
| SHA-1 | `ba68f8e5f17b903b0bc2b271906f9bd3f367025d` |
| SHA-256 | `18e57f5792c996a533aed3495be74f7d8a25ca7a14ac57b56ef0f3bb05505a7d` |
| SHA3-384 | `2ee40d8769cf5c4f7d65b98bdb8c846710ce0ccebbe86ea4ce5fcf60f56e40df291eefe1c42f9f4d3cb12a659d65ad96` |
| TLSH | `T1B25302AD615E6460AB27AF63C35AC782FD830B3C257241E1D789495DE2DA07070BCFA3` |
| SSDEEP | `1536:t/5StIksEkH4tjlbO3tTeKxyr72RWoLNYvKiaELFN0+V:t/0Hs1YtjllbrSRVYiiD3TV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_18e57f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18e57f5792c996a533aed3495be74f7d8a25ca7a14ac57b56ef0f3bb05505a7d"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-28 02:06:54"
  condition:
    hash.sha256(0, filesize) == "18e57f5792c996a533aed3495be74f7d8a25ca7a14ac57b56ef0f3bb05505a7d"
}
```

### Sample 34: `c6602068b4191601`

| Field | Value |
|---|---|
| SHA-256 | `c6602068b4191601bb51b98dea88e2550ac0bc17bee7d379cfc858158c0002eb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-28 01:50:28` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, U, UNIQ.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02187afe8b5b405feaf464c61f88debc` |
| SHA-1 | `8da0799d42b9a16b00543014fc95019164348dcc` |
| SHA-256 | `c6602068b4191601bb51b98dea88e2550ac0bc17bee7d379cfc858158c0002eb` |
| SHA3-384 | `1ca540e0c95826f62714d5d4afaa7f9b1c25a2295c8e1830cad1f55f6d9116311fbeebe696394c3db32b113ca8eb42c3` |
| IMPHASH | `3065e838746921de78b9ef65204d56e5` |
| TLSH | `T1B817330AB4939BA3D63D087160B7F5183B75AC19774C26BAE607B118DCB66322C7732D` |
| SSDEEP | `393216:wqlOVpcK/EEzxm82THjW1OVpcE9EEcxm82nHjW:woOIK/EEWjW1OIE9EE3jW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_c6602068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6602068b4191601bb51b98dea88e2550ac0bc17bee7d379cfc858158c0002eb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-28 01:50:28"
  condition:
    hash.sha256(0, filesize) == "c6602068b4191601bb51b98dea88e2550ac0bc17bee7d379cfc858158c0002eb"
}
```

### Sample 35: `753051a16244348c`

| Field | Value |
|---|---|
| SHA-256 | `753051a16244348c18597a80f5d8e67da310b95159fb366da0c43a8ddc026964` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-06-28 01:41:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46470b55671392d95e7cc00f571a77d5` |
| SHA-1 | `b13e2adc14be20b5ccd39822ccc290ad3731bcaa` |
| SHA-256 | `753051a16244348c18597a80f5d8e67da310b95159fb366da0c43a8ddc026964` |
| SHA3-384 | `03c646075adae7fb8f845972cd8bb516bc8b64b8ab97a45843cb0f2b76758aa75e972abb89445efbf0ed668bce3bfcc2` |
| TLSH | `T11601C8CA8220AA0090ADD61D22D3A054F8A0C3CE264A4F65BF7C6D39EB89C14B036FC4` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohacXgFM3GmjVkEOX:e9Qp+MswAYZVLOX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_753051a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "753051a16244348c18597a80f5d8e67da310b95159fb366da0c43a8ddc026964"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-06-28 01:41:55"
  condition:
    hash.sha256(0, filesize) == "753051a16244348c18597a80f5d8e67da310b95159fb366da0c43a8ddc026964"
}
```

### Sample 36: `8407c98a0f164463`

| Field | Value |
|---|---|
| SHA-256 | `8407c98a0f164463bdc7bcb7e3b022943f64d63539c8fae52c968a1e0112488d` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-28 01:39:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `264e5bc0ce105aebafacb5a4fdc60c3d` |
| SHA-1 | `a7a842d6b6f701a45dc9d432e987a0a96ed48bf9` |
| SHA-256 | `8407c98a0f164463bdc7bcb7e3b022943f64d63539c8fae52c968a1e0112488d` |
| SHA3-384 | `0e1f7b5983ddef86c7e22c601eacb9859ef261251df378aa44aaeb4e49a843629ec8f49dbf93ae4d33e298bed11d30df` |
| TLSH | `T125246C03B7A254FDC08AC4F0575FA316EE3778A84A1B75F77B943A312912EB18E09791` |
| TELFHASH | `t1b95111302ed1756c63e2cb07b31e5f6afe77185684e576a4ab13aee46d43f490da3020` |
| SSDEEP | `6144:p5t1+vQtdhvVov1pF3WVTMIFZToX3qi1qsl:p57L9s/1v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_8407c98a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8407c98a0f164463bdc7bcb7e3b022943f64d63539c8fae52c968a1e0112488d"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 01:39:44"
  condition:
    hash.sha256(0, filesize) == "8407c98a0f164463bdc7bcb7e3b022943f64d63539c8fae52c968a1e0112488d"
}
```

### Sample 37: `2694e1c42f62687c`

| Field | Value |
|---|---|
| SHA-256 | `2694e1c42f62687ca9d1472dc9091a02870b589791b52ff3700755fea59afb1a` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-28 01:38:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fb2232a5830ed254ae3429e480998f0` |
| SHA-1 | `0c64cb726dc811bd84606f6229f43e8496320fc3` |
| SHA-256 | `2694e1c42f62687ca9d1472dc9091a02870b589791b52ff3700755fea59afb1a` |
| SHA3-384 | `91dcd9ad5c8c52d14b6e8dbc36d7200448f5d94f0d834571868cef582906858518bb01aef87f2fff22da0ea04a83ceab` |
| TLSH | `T1228301FBF205E676C47AE474D2528A58C3703E95825B6F9E744030F9AC7B0247D63BA8` |
| SSDEEP | `1536:DiVh+4TWpOrHkEME0CWIXWeavovjFBEcVFotuCjojNM00b8+TwE:DiVhkpUMEw1eeTcVFmuIoRd0bJTwE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_2694e1c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2694e1c42f62687ca9d1472dc9091a02870b589791b52ff3700755fea59afb1a"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 01:38:55"
  condition:
    hash.sha256(0, filesize) == "2694e1c42f62687ca9d1472dc9091a02870b589791b52ff3700755fea59afb1a"
}
```

### Sample 38: `cd85f90ee6a46a3e`

| Field | Value |
|---|---|
| SHA-256 | `cd85f90ee6a46a3e2dcca1233164f584ff018ff552b12a9e8f20eaaf761a29a1` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-28 01:33:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61f8fcfde56f993c569bbf91145e702d` |
| SHA-1 | `2e0ac4221da0957a59184456482c3c916c88a5a0` |
| SHA-256 | `cd85f90ee6a46a3e2dcca1233164f584ff018ff552b12a9e8f20eaaf761a29a1` |
| SHA3-384 | `fa647df252d70abc872639b47f470f8d2e30d3b7804f634bb4a72761fd2f4acc50539a7cb529d0969ac3b25a32dc69c4` |
| TLSH | `T1BBD02E6295730178A05B8C04F1E2E861B40487BE4990C628FA0714B08E4BB0BF0C22E0` |
| SSDEEP | `6:hT1AF9vnm8ve4MbAulNXYq9DG+NjVsNXYrkJ:VWc8WvPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_cd85f90e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd85f90ee6a46a3e2dcca1233164f584ff018ff552b12a9e8f20eaaf761a29a1"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-28 01:33:56"
  condition:
    hash.sha256(0, filesize) == "cd85f90ee6a46a3e2dcca1233164f584ff018ff552b12a9e8f20eaaf761a29a1"
}
```

### Sample 39: `6ebaaf79e390b965`

| Field | Value |
|---|---|
| SHA-256 | `6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481` |
| Family label | `unknown` |
| File name | `6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481` |
| File type | `elf` |
| First seen | `2026-06-28 01:30:59` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdc9e48e4eb67ed03de9cc888f62f738` |
| SHA-1 | `644051a202d54d7902814fc11e0c4e6b507d35ca` |
| SHA-256 | `6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481` |
| SHA3-384 | `4d79eb49b42712f4f4830945d615ede515b720ecd670fb800e6d59c6901b542690a407551769927570c048a73b040668` |
| TLSH | `T1F147DF77814238E9E5B98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ8:cqYUQuVDt0TZEf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_6ebaaf79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481"
    family = "unknown"
    file_name = "6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481"
    file_type = "elf"
    first_seen = "2026-06-28 01:30:59"
  condition:
    hash.sha256(0, filesize) == "6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481"
}
```

### Sample 40: `eceff5fd41901d2f`

| Field | Value |
|---|---|
| SHA-256 | `eceff5fd41901d2f9093ffe8169f0ab1105ec0fe7962f55774ea70f24c408764` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-06-28 01:27:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3db977484bac58c910ae7b184f2a0895` |
| SHA-1 | `bebdde2c224886ea36d15c70189a6c4a0da11d39` |
| SHA-256 | `eceff5fd41901d2f9093ffe8169f0ab1105ec0fe7962f55774ea70f24c408764` |
| SHA3-384 | `e322c6a8f09d6506154ea69e1e2bd31c8561f20329ed5b27a55782f43a90567e414f1b5ea8c1fc87e3c2f7cd393ce3a3` |
| TLSH | `T11D241A42B8418E16C5C522B6FA6E428D33173B78D2DE7212CD246F547BCADEB0DB7612` |
| TELFHASH | `t190b01281a0ad6506f700060302b6b735d733a3a42f9801dd56423b282c8aec00033c01` |
| SSDEEP | `6144:rOzweKfwyyxT0fWauuByXP+9LCD0UCJS:rVI/wfWaubXPKCDa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_eceff5fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eceff5fd41901d2f9093ffe8169f0ab1105ec0fe7962f55774ea70f24c408764"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-06-28 01:27:39"
  condition:
    hash.sha256(0, filesize) == "eceff5fd41901d2f9093ffe8169f0ab1105ec0fe7962f55774ea70f24c408764"
}
```

### Sample 41: `b297c3b865947f13`

| Field | Value |
|---|---|
| SHA-256 | `b297c3b865947f137c50f4f3e8a4b7f20b3af3fb0e52cbda642801880f9e628e` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-06-28 01:26:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dea26a69784784ab091b35aac3f96a6a` |
| SHA-1 | `d5e74fef4bf56056b0e32dcd9266ec1417098b09` |
| SHA-256 | `b297c3b865947f137c50f4f3e8a4b7f20b3af3fb0e52cbda642801880f9e628e` |
| SHA3-384 | `068056522820ea964d2f71b941bda472044c9e4603892d7163a796d12aa9f7f2aebac3af4f16ac449474e52c3f1b5a09` |
| TLSH | `T18A6302A4AE41B2D1C7B422F1677AD3063B6A07C1D9E93375533C5039F6C23AB0AA5DD0` |
| SSDEEP | `1536:ZOtHH9umDaEc1HdsEdsogzhwIJUJy2MS/ZmoXbkiVs00CrfQj9u:ZOtnxFTEeogtwK0y2MS/LkiVs00CLQJu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_b297c3b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b297c3b865947f137c50f4f3e8a4b7f20b3af3fb0e52cbda642801880f9e628e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-06-28 01:26:53"
  condition:
    hash.sha256(0, filesize) == "b297c3b865947f137c50f4f3e8a4b7f20b3af3fb0e52cbda642801880f9e628e"
}
```

### Sample 42: `31c641e51200fd89`

| Field | Value |
|---|---|
| SHA-256 | `31c641e51200fd891fe6e6608ad2889fa7146b51369a5bb3fe244332cc82815f` |
| Family label | `Mirai` |
| File name | `flutter.arm` |
| File type | `elf` |
| First seen | `2026-06-28 01:25:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46c79dc0d98d54098fd1e080f51e69aa` |
| SHA-1 | `26bb5d653dde9f37d4b655135e84212fe3335c28` |
| SHA-256 | `31c641e51200fd891fe6e6608ad2889fa7146b51369a5bb3fe244332cc82815f` |
| SHA3-384 | `66a25512504fe83754e87dc80391bbad0586ca863ae775724ace4419e45afb6226aed48c4738f5e8d1694556cabacfd5` |
| TLSH | `T17FF31955F8809F66D6D527BAFA9D028C33130778C3DA7102DE209F2537EF95E0A3A946` |
| SSDEEP | `3072:XOcdL/xBtfduC2+7xbfcQbehOhLoaYCNaHFvm/OYXUZPOEyUwG1XE2b83hgGcu+E:XOSlNfcQbeohMaYwaHFvCAOEyUwG1XEX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_31c641e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31c641e51200fd891fe6e6608ad2889fa7146b51369a5bb3fe244332cc82815f"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-06-28 01:25:51"
  condition:
    hash.sha256(0, filesize) == "31c641e51200fd891fe6e6608ad2889fa7146b51369a5bb3fe244332cc82815f"
}
```

### Sample 43: `3ffe7fe3ca571747`

| Field | Value |
|---|---|
| SHA-256 | `3ffe7fe3ca5717478de826b6962a22f8519d2da4def748965c80d6ee870e01f7` |
| Family label | `Mirai` |
| File name | `flutter.arm` |
| File type | `elf` |
| First seen | `2026-06-28 01:24:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c6b809caa7bdf02e7e3b318acdd9938` |
| SHA-1 | `97ceffedc745c2522c7cc75dca8ca6dde3741ed3` |
| SHA-256 | `3ffe7fe3ca5717478de826b6962a22f8519d2da4def748965c80d6ee870e01f7` |
| SHA3-384 | `0c92bb338ec6a48e4764042d8e22254a5620ec2b5a6b1db3e112ecf2bf4caf6c06ac853220223aac0fe06dd88b0d709d` |
| TLSH | `T12793122CC5C2E120D175E430469CD1A7410836F57F9CAC9BDD9DB7C6AEF144786AE34A` |
| SSDEEP | `1536:9vkJVJOBquHCx8ELqzDwMxBj0Fy9Cu04mJCwo93GA1I4ei5gGTniag0w+Y2ehYqO:N+JOBquHCRuzD1BjZ9Cu04mTHUI4nRTZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_3ffe7fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ffe7fe3ca5717478de826b6962a22f8519d2da4def748965c80d6ee870e01f7"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-06-28 01:24:57"
  condition:
    hash.sha256(0, filesize) == "3ffe7fe3ca5717478de826b6962a22f8519d2da4def748965c80d6ee870e01f7"
}
```

### Sample 44: `af45b4a994b7ba76`

| Field | Value |
|---|---|
| SHA-256 | `af45b4a994b7ba7693494d211215eaaa05b787ccc156ec55e5354838af23b5aa` |
| Family label | `Mirai` |
| File name | `flutter.arm7` |
| File type | `elf` |
| First seen | `2026-06-28 01:24:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9044e8a40b90a5a471cc86eddeac848e` |
| SHA-1 | `610dae5ab700fcc02eb8c5089047698f042b9e77` |
| SHA-256 | `af45b4a994b7ba7693494d211215eaaa05b787ccc156ec55e5354838af23b5aa` |
| SHA3-384 | `7b0065b63e3bf30dc8fb6ff1ff514822853f08d18a8861eaec636ae0717a11c488c445a44a9708375f327b6ba808007a` |
| TLSH | `T1F7F32A46F880DE66C6D1267AFA9D019C331317B8D3EA7002DD20AF2937EB55E0B7E546` |
| SSDEEP | `3072:AzhP9VRsduC2HXCOY5EmXeUjjUYX5t9zg8uY4/4HIQMIwPg5Tfdwerjzu+vvE:AzuEmXljoYX5n0YxIQMIwPg5TfyoE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_af45b4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af45b4a994b7ba7693494d211215eaaa05b787ccc156ec55e5354838af23b5aa"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-06-28 01:24:43"
  condition:
    hash.sha256(0, filesize) == "af45b4a994b7ba7693494d211215eaaa05b787ccc156ec55e5354838af23b5aa"
}
```

### Sample 45: `3e336766f450f868`

| Field | Value |
|---|---|
| SHA-256 | `3e336766f450f868f7b36e0be3396a951cb0f22dec16cc92b2c7a747700d84eb` |
| Family label | `Mirai` |
| File name | `flutter.arm7` |
| File type | `elf` |
| First seen | `2026-06-28 01:23:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82a601d7fa70f74ae26cdaaa26102481` |
| SHA-1 | `d909b1a380a1705bb36f2567d70c5e7316940099` |
| SHA-256 | `3e336766f450f868f7b36e0be3396a951cb0f22dec16cc92b2c7a747700d84eb` |
| SHA3-384 | `fb7b49083abf0a9f3be17edb7b521a0a291281c4b343d73b99727643b9e91db3b65d9bf27d02acea10ddbb43f3b925e0` |
| TLSH | `T1919312DBEC838439E5EC2F7046AE834299234DE8704A3756B788BE140D235E84BB46F5` |
| SSDEEP | `1536:xRSgR49ZZMmJXyTHrVKTWardQv+eh8quAlRCLl/X/VWmw4+tpi:nuz446aJUh8qYl/PMmIQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_3e336766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e336766f450f868f7b36e0be3396a951cb0f22dec16cc92b2c7a747700d84eb"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-06-28 01:23:52"
  condition:
    hash.sha256(0, filesize) == "3e336766f450f868f7b36e0be3396a951cb0f22dec16cc92b2c7a747700d84eb"
}
```

### Sample 46: `b0a253629dadae80`

| Field | Value |
|---|---|
| SHA-256 | `b0a253629dadae80bc5d044a067fccb25a50e8e3bb930cecfd4e38f6cf6d2d60` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-28 01:23:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd3d217480062db4f6feb1d453dae5ad` |
| SHA-1 | `2f62e3d8b6056458d68d28ef5403793e6e6f4a0e` |
| SHA-256 | `b0a253629dadae80bc5d044a067fccb25a50e8e3bb930cecfd4e38f6cf6d2d60` |
| SHA3-384 | `df8d3465555fd2b1d05c865291a9cb0dd9d8f502985bfd89ccac53d1a52f7e61c33bff2f95e8037df0595cd4e442b004` |
| TLSH | `T17F44941F2E22DF6EF7A9867007B78E30975C36D626E1D680E26CD6105E502CD641FFA8` |
| TELFHASH | `t1b341c318197813e0a6656c5d049dff76d6a730eb7e162c278e11e86eab69e435d10c0c` |
| SSDEEP | `6144:wtaTgnMdOSjBUOCARZgZqZgczoAI1MLVB+/:wthsgBczoZ/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_b0a25362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0a253629dadae80bc5d044a067fccb25a50e8e3bb930cecfd4e38f6cf6d2d60"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-28 01:23:43"
  condition:
    hash.sha256(0, filesize) == "b0a253629dadae80bc5d044a067fccb25a50e8e3bb930cecfd4e38f6cf6d2d60"
}
```

### Sample 47: `a411da26aece6d7c`

| Field | Value |
|---|---|
| SHA-256 | `a411da26aece6d7c9a9794e44f961a801cf4c95c94986f4f469adc4ad709fdd0` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-28 01:22:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70d249dbf1b3ef1e097d4d27b113d45d` |
| SHA-1 | `1258224e5c4f1d60885bcccb047e9bafad3362f8` |
| SHA-256 | `a411da26aece6d7c9a9794e44f961a801cf4c95c94986f4f469adc4ad709fdd0` |
| SHA3-384 | `159b964914b42c9082934d641dc8acc7c9a551a8bff47ac0ce193721f404e633338624c7ee2579ded2acbb3590c0fc5a` |
| TLSH | `T17E6302F317804B97FC1AD1B2659463B09F250A42A2D79CCFB0F1D7E2ED601EE2C4A658` |
| SSDEEP | `1536:xYL9oMfQx0IIoeBigOZBh0kEre9o7X4aC0ZEuyujQGl6VSV:xYLihmwZBhSe+7IALyukZV2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_a411da26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a411da26aece6d7c9a9794e44f961a801cf4c95c94986f4f469adc4ad709fdd0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-28 01:22:52"
  condition:
    hash.sha256(0, filesize) == "a411da26aece6d7c9a9794e44f961a801cf4c95c94986f4f469adc4ad709fdd0"
}
```

### Sample 48: `f24d98c1da244874`

| Field | Value |
|---|---|
| SHA-256 | `f24d98c1da244874ad27ae9e19a0756e6a9792ade59803e76cff96159a1a8217` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-06-28 01:17:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6012cbf5e7a04062d20f12eda98b9c78` |
| SHA-1 | `6e9bfc61a32c2bfe19bffe2c70ef08bf521ebcb9` |
| SHA-256 | `f24d98c1da244874ad27ae9e19a0756e6a9792ade59803e76cff96159a1a8217` |
| SHA3-384 | `176ebdfdbfd0eb2540399d8cdbd3fe6cf8a0d3d3869f0bf5cf34325749cbc518654fab5c684401c2223d667d9b822fd2` |
| TLSH | `T13234E691A4118ADBCE0158FA77AC4F743B817C30C61B5FBD595594A8A28F8DFF0C6BA0` |
| SSDEEP | `3072:vcOtUsCMQo7OTDrdGs+Toxa5WY+nndU4q4KuyLYWG6JDKSa:vco1CXJL+TokgYWndU1xBG68Sa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_f24d98c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f24d98c1da244874ad27ae9e19a0756e6a9792ade59803e76cff96159a1a8217"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-28 01:17:52"
  condition:
    hash.sha256(0, filesize) == "f24d98c1da244874ad27ae9e19a0756e6a9792ade59803e76cff96159a1a8217"
}
```

### Sample 49: `d563826f5c0f4722`

| Field | Value |
|---|---|
| SHA-256 | `d563826f5c0f4722275246f7f09177380fe27f8be837c353552ca936eda55490` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-06-28 01:17:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac7e8d54579b5087e14c0748ecdcd041` |
| SHA-1 | `1d4ea951afbc5c17bc569fb6099bd2b9ec06e319` |
| SHA-256 | `d563826f5c0f4722275246f7f09177380fe27f8be837c353552ca936eda55490` |
| SHA3-384 | `12e67f6203ed94f01a7b7a7047ee88d3ab09b5d0ccad90dc1a0cbd405a1d600f95c98c117b591d6fddb7b109ed2ceb16` |
| TLSH | `T1B1140752BD51AF23C1E232B7FB9E428937196B69C1EB72069C327F5037C68DA0D76241` |
| TELFHASH | `t1e631ffa39f491be823d58644c2df713aa6a570996b4134559e6aab4fcc03fc0b02dc37` |
| SSDEEP | `3072:p/0rDUi/38zSBguqGFy64H6PAyV5YEoRky3AZh2plKQgP3DtBjPO3:p/mh4KAQ3Uky3A/2plKQG3DnjPO3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_d563826f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d563826f5c0f4722275246f7f09177380fe27f8be837c353552ca936eda55490"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-28 01:17:36"
  condition:
    hash.sha256(0, filesize) == "d563826f5c0f4722275246f7f09177380fe27f8be837c353552ca936eda55490"
}
```

### Sample 50: `46d8fb86f41800a8`

| Field | Value |
|---|---|
| SHA-256 | `46d8fb86f41800a8917c7f16d445d02df1f56b31201bb682d64c2b9ff9bfa7bb` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-06-28 01:16:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `830295d932afd7a38500e9c6f6e3c7dd` |
| SHA-1 | `bdb084180180a4fdab5465435f65d7103881097d` |
| SHA-256 | `46d8fb86f41800a8917c7f16d445d02df1f56b31201bb682d64c2b9ff9bfa7bb` |
| SHA3-384 | `9b99a578f7391696ca7ee219fb185cdd2fe9f7415b268c3e89181b01c2d92fb4a7a5a59670ef27ab4a52e33e78ea2ca5` |
| TLSH | `T1AD5302A11041FEF1EA739E3BCEB18582C5B0494CBACE9624A756CE4A7F895010DDCBC9` |
| SSDEEP | `768:oHMA51+hNXmiunktWoCEtAgvQaMJUQmvcyObA/0IIU2cKXeMX7B1tMdjKb+6cAFg:5hNInkhx7vEUQeJWAsU3aLB11b+sz15S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_46d8fb86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46d8fb86f41800a8917c7f16d445d02df1f56b31201bb682d64c2b9ff9bfa7bb"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-28 01:16:51"
  condition:
    hash.sha256(0, filesize) == "46d8fb86f41800a8917c7f16d445d02df1f56b31201bb682d64c2b9ff9bfa7bb"
}
```

### Sample 51: `2e9791b87a76ce57`

| Field | Value |
|---|---|
| SHA-256 | `2e9791b87a76ce5706b74e83cae2bdc05e34d8ffc0f494e9390f12320edf4043` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-28 01:13:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ad34c32069c2af7116edbf13b093819` |
| SHA-1 | `110aa9f3a03ec4fe86b5d6d7135343bce0325adb` |
| SHA-256 | `2e9791b87a76ce5706b74e83cae2bdc05e34d8ffc0f494e9390f12320edf4043` |
| SHA3-384 | `d8d72a7670d1113ba33c83338f956b7706d8af08b718afac6392ddf60d13f364432a173f4a4fdbff73c12b0b32cbc5ef` |
| TLSH | `T1BBD02EA30233837144A68800E5CBB840B209AB3F8DA2C69EBA1310785F80284B0D02A4` |
| SSDEEP | `6:hTB2afhhW5+FdCFpAulNXYq4HvXDG+NjVsNXYrkJ:VAaO5npPiq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_2e9791b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e9791b87a76ce5706b74e83cae2bdc05e34d8ffc0f494e9390f12320edf4043"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-28 01:13:50"
  condition:
    hash.sha256(0, filesize) == "2e9791b87a76ce5706b74e83cae2bdc05e34d8ffc0f494e9390f12320edf4043"
}
```

### Sample 52: `812dbaead239dc87`

| Field | Value |
|---|---|
| SHA-256 | `812dbaead239dc87437196510043e1058f1656747d9bcd886a77594e3e654652` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-06-28 01:03:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88c0335aec378c73f00d70a7f55f779f` |
| SHA-1 | `94843577dcdab992b12a780bc48039de64036ebe` |
| SHA-256 | `812dbaead239dc87437196510043e1058f1656747d9bcd886a77594e3e654652` |
| SHA3-384 | `7d26355cbf0ab9960651cd10f0cd2f75e34665d58fd879722ebe54e632fecdc379c71f80e73a630336da23a6ca5ded95` |
| TLSH | `T1BF246B437B878FA3C2246A754AF382389ADA37170AA7C4D7C3B95B0167555A03C2DFC9` |
| TELFHASH | `t1214192319b3c8816a8e2cea4eced1721921fc55155409a33ef30c68c446b4eda62bf5f` |
| SSDEEP | `3072:jDT1OwD+nrU/mr6/1KzOKIz7XiuEdU2EoiTn/RqHojjM+w1qgGt95F2MA4j0X6j:D1Oy+Iu6/1Kz+ztUUSoj7wIxl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_812dbaea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "812dbaead239dc87437196510043e1058f1656747d9bcd886a77594e3e654652"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-06-28 01:03:54"
  condition:
    hash.sha256(0, filesize) == "812dbaead239dc87437196510043e1058f1656747d9bcd886a77594e3e654652"
}
```

### Sample 53: `ec4f37c2d5a1b9fb`

| Field | Value |
|---|---|
| SHA-256 | `ec4f37c2d5a1b9fb472634accb1a2d28ade5db8f9d4d2d43e23adce6514331b7` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-06-28 01:01:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2c0c9ec74109d409160027831814228` |
| SHA-1 | `0eba2e41bb57907f04b8bd45b2db8c033b597438` |
| SHA-256 | `ec4f37c2d5a1b9fb472634accb1a2d28ade5db8f9d4d2d43e23adce6514331b7` |
| SHA3-384 | `5f1a681bf4b273e64a7dc8fb96bd9b368ee4851e36bac2fb9b9f84b270685074d70023d44a24dcb768c3addf4fc684f8` |
| TLSH | `T1460419457C419E05D5CA33BAFA6E028933477B79D3EA7202CD205F5527CAE8B0EB7612` |
| TELFHASH | `t120f05c92dcc5195db9e990faebfca664cc50e0912f1d0c92a5bc851dfe82cc62411807` |
| SSDEEP | `3072:0X7zVNlsjN7g4IMU+ICXYVAr7wO7qsa0gRFJfbRtAUFsOTdDFPbQi:mVNCpzIMUJzVArcOOsa0gRFJfbR6UBT7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_ec4f37c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec4f37c2d5a1b9fb472634accb1a2d28ade5db8f9d4d2d43e23adce6514331b7"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-06-28 01:01:32"
  condition:
    hash.sha256(0, filesize) == "ec4f37c2d5a1b9fb472634accb1a2d28ade5db8f9d4d2d43e23adce6514331b7"
}
```

### Sample 54: `07ea890e0a100844`

| Field | Value |
|---|---|
| SHA-256 | `07ea890e0a1008446889251a0553428a54786ffd9b1b870d8f7730f0a6fdb306` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-06-28 00:59:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96548ab8d05a18a2ed907057aa41ff85` |
| SHA-1 | `17ec93cc19a312448d907b7b144032159c83b848` |
| SHA-256 | `07ea890e0a1008446889251a0553428a54786ffd9b1b870d8f7730f0a6fdb306` |
| SHA3-384 | `9471c645611b194fd34ace3a2ad54986710d58cc1110e50627114a9aaf683986113c0896bea13d57d73895142318fcdf` |
| TLSH | `T1EC53029D7010068687A02A3587219D8694A5EF34A8FE3097BB95EEB035F1089CBFF16D` |
| SSDEEP | `1536:o2avCtgskuWkC3xb85pNujAAmMriWHGV58ImjH7IgdA:o2aqgFN3xb44mMDk7mjEg6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_07ea890e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07ea890e0a1008446889251a0553428a54786ffd9b1b870d8f7730f0a6fdb306"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-06-28 00:59:49"
  condition:
    hash.sha256(0, filesize) == "07ea890e0a1008446889251a0553428a54786ffd9b1b870d8f7730f0a6fdb306"
}
```

### Sample 55: `e207ce6f845f84bd`

| Field | Value |
|---|---|
| SHA-256 | `e207ce6f845f84bd247294390e12fd94df499436b8170ec143266405735d36fe` |
| Family label | `BlankGrabber` |
| File name | `Built.exe` |
| File type | `exe` |
| First seen | `2026-06-28 00:53:29` |
| Reporter | `BastianHein_` |
| Tags | `BlankGrabber, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e87c40331ad08fecfeb53c22fccd9d1` |
| SHA-1 | `a39c3459c3a86a8e1ab58323e878320c85b43b51` |
| SHA-256 | `e207ce6f845f84bd247294390e12fd94df499436b8170ec143266405735d36fe` |
| SHA3-384 | `21957b56b3f3cac9077f4d3894e81d930b4fd6dd7ff49c869f569d463c6f07a00cc02291f5dc6e69552942ebc0700319` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1A5B633287BC845A6EDE2513E8D62C61AFBF034459B70D6DF076857A43E2F890893E371` |
| SSDEEP | `196608:KAxxk048OuHsntMNkIahjyRumA4K1S0Dg43AtRgEvoK7LVFLpyLuHX:X2ep5Qm+1SBtRLvF7XLpzX` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_055_e207ce6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e207ce6f845f84bd247294390e12fd94df499436b8170ec143266405735d36fe"
    family = "BlankGrabber"
    file_name = "Built.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:53:29"
  condition:
    hash.sha256(0, filesize) == "e207ce6f845f84bd247294390e12fd94df499436b8170ec143266405735d36fe"
}
```

### Sample 56: `3eb43078cc25cfea`

| Field | Value |
|---|---|
| SHA-256 | `3eb43078cc25cfea4841533828fe136064eb151a93e8418f120a439cde3a1771` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-28 00:52:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd994a09880954543abd30f61c03775a` |
| SHA-1 | `7a6adace9106fd92b318f543c00a42e1ece35d5f` |
| SHA-256 | `3eb43078cc25cfea4841533828fe136064eb151a93e8418f120a439cde3a1771` |
| SHA3-384 | `5679f95d9f5d3ab9eb9905ca3d273f37c406cee9ab2e69fcd07a7f11c48e64a29b7d03c9731a42faf74e15856936359b` |
| TLSH | `T1EE237D6516817C24AA99D4371D7F2F0CBDA983E6320492DDBFCA3CF28C59A9CD11871D` |
| SSDEEP | `768:SXRWNGxV39GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:elxCcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_3eb43078
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eb43078cc25cfea4841533828fe136064eb151a93e8418f120a439cde3a1771"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-28 00:52:51"
  condition:
    hash.sha256(0, filesize) == "3eb43078cc25cfea4841533828fe136064eb151a93e8418f120a439cde3a1771"
}
```

### Sample 57: `94dc6a521549029a`

| Field | Value |
|---|---|
| SHA-256 | `94dc6a521549029a2bcd479bf04327518ea0cf0a3a4675d98cb421f256340122` |
| Family label | `BlankGrabber` |
| File name | `XwormV5.6.exe` |
| File type | `exe` |
| First seen | `2026-06-28 00:44:38` |
| Reporter | `BastianHein_` |
| Tags | `BlankGrabber, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0227ae2a175af87b2e31d1a47cb3276` |
| SHA-1 | `5c7fc0c75b357a21fb920bdb78eaa3a236c7b634` |
| SHA-256 | `94dc6a521549029a2bcd479bf04327518ea0cf0a3a4675d98cb421f256340122` |
| SHA3-384 | `5422c2ca1d64e37129aec229ad01601dc832c0a60fbb9b018f92d2d3b79d64feaf02403234247f6f74244b5326c09a58` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T19617332473D916A7EEE63A3D1CD2C60AF6E039465B619ADF037067943E2F5E0843E364` |
| SSDEEP | `393216:y2DsKRF0gaAk1Z/X1p5Qm+1SBtRLvF7XLpzC:hDsKouA/XxQm+1ktJvF7hC` |
| ICON-DHASH | `4eccd8e8f0d0cc9c` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_057_94dc6a52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94dc6a521549029a2bcd479bf04327518ea0cf0a3a4675d98cb421f256340122"
    family = "BlankGrabber"
    file_name = "XwormV5.6.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:44:38"
  condition:
    hash.sha256(0, filesize) == "94dc6a521549029a2bcd479bf04327518ea0cf0a3a4675d98cb421f256340122"
}
```

### Sample 58: `2ba98395b64bda94`

| Field | Value |
|---|---|
| SHA-256 | `2ba98395b64bda94951e71b30d6ccfb368bec76c87562e4c007cd4a2a99e65e1` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-28 00:44:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec8bfcb6732e5253ac79f13ad67d5153` |
| SHA-1 | `16a4b67617aa878bf6992b40b136a386b867b5c2` |
| SHA-256 | `2ba98395b64bda94951e71b30d6ccfb368bec76c87562e4c007cd4a2a99e65e1` |
| SHA3-384 | `c59a6fed202b486bc9919c662c30eb1d1526cb93fb04c91ecbb020288d4605ee65f2a021b62d1515f4dfa9528cb914b7` |
| TLSH | `T1F344E806AF610FF7D8ABCD3306E91B0129CC681B26A53F36B674D968B50B58B19C3D74` |
| SSDEEP | `3072:aO2kM/qRj6Q7Yk7SEf1jUUgfE+i6tLR9H7kKal+pAmw:azky2mQckpwfA6n9bmQAmw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_2ba98395
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ba98395b64bda94951e71b30d6ccfb368bec76c87562e4c007cd4a2a99e65e1"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-28 00:44:31"
  condition:
    hash.sha256(0, filesize) == "2ba98395b64bda94951e71b30d6ccfb368bec76c87562e4c007cd4a2a99e65e1"
}
```

### Sample 59: `625f745adbc6aceb`

| Field | Value |
|---|---|
| SHA-256 | `625f745adbc6acebe0c96b0ece72256a8559f0684f7abfbbc69bd55cbb873e48` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-28 00:43:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f3af3cccf8fc1ada7a993da0cef6041` |
| SHA-1 | `8188c349300c88b0c6cda36cba07a33d52e61b7f` |
| SHA-256 | `625f745adbc6acebe0c96b0ece72256a8559f0684f7abfbbc69bd55cbb873e48` |
| SHA3-384 | `be621af712a29dd914a4f9e746fd18442aea9e0943be76a1d7f2232e8b72f249ca3ea9fda61d11d91e8eef39aed1810a` |
| TLSH | `T1BD631249F845389AE13CA43D33FA126B2F57C8904BA79F4F22B1544D62ABC5E39F40D6` |
| SSDEEP | `1536:DMja2p4pEY7VWk3MNSXrybmyojqG6oprh24eBrzf9aH57VCrKcK6KS+:Dp2A7lmMrybmn6opr8brzf8H57BlV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_625f745a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "625f745adbc6acebe0c96b0ece72256a8559f0684f7abfbbc69bd55cbb873e48"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-28 00:43:51"
  condition:
    hash.sha256(0, filesize) == "625f745adbc6acebe0c96b0ece72256a8559f0684f7abfbbc69bd55cbb873e48"
}
```

### Sample 60: `542ab12e9aa46a0a`

| Field | Value |
|---|---|
| SHA-256 | `542ab12e9aa46a0a19d380e7390a84c4628c7316cb7a4bd01a85a8b3a45ca421` |
| Family label | `unknown` |
| File name | `testss.exe` |
| File type | `exe` |
| First seen | `2026-06-28 00:39:51` |
| Reporter | `BastianHein_` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f32445270d6f1a4b3a1692aebce68b0` |
| SHA-1 | `7542b7b567d58fde29869a84038ce49f20a8ffe4` |
| SHA-256 | `542ab12e9aa46a0a19d380e7390a84c4628c7316cb7a4bd01a85a8b3a45ca421` |
| SHA3-384 | `5096cf86e095a80d1d991042a3dd75f46bb9196da0e8faccd0bfd87746ed5c40dff434bb49ff4fd9ef61851f5df71ed1` |
| IMPHASH | `221b9c7af60e448c3a2422baa4fb3a8e` |
| TLSH | `T10B87333557FBE1C2C467C270AA4FB5F8716E58C806A4D93906F088316F7EC5227C6BA6` |
| SSDEEP | `786432:3L2vM+38zsQJU3ftUu0uBsMF8yapxBnopgE8moARc:3L2vr30VU3fuVuBs2azdopglPAR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_542ab12e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "542ab12e9aa46a0a19d380e7390a84c4628c7316cb7a4bd01a85a8b3a45ca421"
    family = "unknown"
    file_name = "testss.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:39:51"
  condition:
    hash.sha256(0, filesize) == "542ab12e9aa46a0a19d380e7390a84c4628c7316cb7a4bd01a85a8b3a45ca421"
}
```

### Sample 61: `8bdb9e2799855cf5`

| Field | Value |
|---|---|
| SHA-256 | `8bdb9e2799855cf53e619fc7f1f0c584de8f362f8f7bf050862ca273e3a637b7` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-28 00:38:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60cb5b3c0b8d38d54007430bb0fcb12c` |
| SHA-1 | `189be326a093262213dddfe04142d02ecbf61473` |
| SHA-256 | `8bdb9e2799855cf53e619fc7f1f0c584de8f362f8f7bf050862ca273e3a637b7` |
| SHA3-384 | `999380d0376b36cb5e388bc25c2d77b70bf209988507f0e33ac494ee1fbb236e8f6dcc5dc4a710cef72ba49dc619b352` |
| TLSH | `T163247C99BA4F7E82D2C6D3F8DF8BCB91312730958A4682F53D01132DC5C6DD989E2B91` |
| SSDEEP | `3072:zWXtEUGPEP9tapfEymwLRp/yLrHverPTBjztQjqb:iXtSEP9tgfzpLRp/YzerNXSjq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_8bdb9e27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdb9e2799855cf53e619fc7f1f0c584de8f362f8f7bf050862ca273e3a637b7"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-28 00:38:37"
  condition:
    hash.sha256(0, filesize) == "8bdb9e2799855cf53e619fc7f1f0c584de8f362f8f7bf050862ca273e3a637b7"
}
```

### Sample 62: `82fa4a260074ef98`

| Field | Value |
|---|---|
| SHA-256 | `82fa4a260074ef98be4f2c8a925f9bb6ac91dcac44b69ba3c4a00116b308c729` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-28 00:37:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f9bf0ccb2783771d2fd5d006bca354b` |
| SHA-1 | `1209b11851a9a0928688a9600d0d8e71698ffb57` |
| SHA-256 | `82fa4a260074ef98be4f2c8a925f9bb6ac91dcac44b69ba3c4a00116b308c729` |
| SHA3-384 | `850084b08462150a80dd650c9a1a01e2c428acdf65c6269c2374c40cfaff38ec15ea863d2cb204b26b1df6655213e7eb` |
| TLSH | `T13C8312D87A13DF26C8C0AC7198D837C7A5981429B37BE4D5970C76EBD9878433E602A9` |
| SSDEEP | `1536:gxGcdxmoDwHgM+BdiljY8YPE+EOYJHwaJ8/74D12qVVj1FaBaq6uFSTnBtOBZGD0:gtjygM+fiKFMZJHFJI4DnZFaBaq6aZyo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_82fa4a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82fa4a260074ef98be4f2c8a925f9bb6ac91dcac44b69ba3c4a00116b308c729"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-28 00:37:53"
  condition:
    hash.sha256(0, filesize) == "82fa4a260074ef98be4f2c8a925f9bb6ac91dcac44b69ba3c4a00116b308c729"
}
```

### Sample 63: `8928d35f3e18435f`

| Field | Value |
|---|---|
| SHA-256 | `8928d35f3e18435f6c17940a5a9a2515186b5a7a4faa6f681b7d244249daaf0b` |
| Family label | `BlankGrabber` |
| File name | `BTCMiner.exe` |
| File type | `exe` |
| First seen | `2026-06-28 00:29:38` |
| Reporter | `BastianHein_` |
| Tags | `BlankGrabber, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2f13f6d216b70e66ce859e3e0cadcb7` |
| SHA-1 | `b7d45389d4acc560c93215f1096befb28cda75f8` |
| SHA-256 | `8928d35f3e18435f6c17940a5a9a2515186b5a7a4faa6f681b7d244249daaf0b` |
| SHA3-384 | `60a553ec57efb2dd8e06e3b173998dcda722f48918b6a9aa489bab7bce4ff59b3c92024eb53688413ac44b060aab4186` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1E0863399F3A20AFBF4E7523CC5C2C166A771F9694320A9CF0390426A2E276D11D3FB55` |
| SSDEEP | `98304:ylvITBGY3amaHl3Ne4i3lqoFhTWrf9eQc0MJYzwZNq2ToigGDzisHJ1n6JsBLRiU:yRIA/eNlpYfMQc2s9IG/nn6Js5RJqg` |
| ICON-DHASH | `e492b2e359b88c60` |

#### Technical Assessment

- The sample is tracked as `BlankGrabber` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BlankGrabber_063_8928d35f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8928d35f3e18435f6c17940a5a9a2515186b5a7a4faa6f681b7d244249daaf0b"
    family = "BlankGrabber"
    file_name = "BTCMiner.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:29:38"
  condition:
    hash.sha256(0, filesize) == "8928d35f3e18435f6c17940a5a9a2515186b5a7a4faa6f681b7d244249daaf0b"
}
```

### Sample 64: `39cbd2d2299ebbc1`

| Field | Value |
|---|---|
| SHA-256 | `39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13` |
| Family label | `njrat` |
| File name | `390929763242f8f854188b405ac7f5ba.exe` |
| File type | `exe` |
| First seen | `2026-06-28 00:25:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `390929763242f8f854188b405ac7f5ba` |
| SHA-1 | `6d20314cdc9d3ba60bb44a2ff17666054394dfcb` |
| SHA-256 | `39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13` |
| SHA3-384 | `346a9d0acc9e94b409886938f19c7f8afe67905902c1d879bd0747523383868c4aef754d7b1f48c0b2604506644bc0ea` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DC93C64977E56564E0BF56F79871F2004F34B44B1602E39E48F259AA0B33AC44F89FEA` |
| SSDEEP | `1536:kU/r7EkrjaFIs7E5Ox8Jn8LjEwzGi1dDHDwgS:kU7jau5OKVni1d3Z` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_064_39cbd2d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13"
    family = "njrat"
    file_name = "390929763242f8f854188b405ac7f5ba.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:25:05"
  condition:
    hash.sha256(0, filesize) == "39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13"
}
```

### Sample 65: `5eafce5d6fadad40`

| Field | Value |
|---|---|
| SHA-256 | `5eafce5d6fadad40b6aa6f7a58da86bbbd29dba0d84c259dbc41c7671ade913c` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-06-28 00:24:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31bf589ea8f809c678698a4242d8b9f6` |
| SHA-1 | `cfc7231f0febdcdd4651cc5456a6c91010a78ce3` |
| SHA-256 | `5eafce5d6fadad40b6aa6f7a58da86bbbd29dba0d84c259dbc41c7671ade913c` |
| SHA3-384 | `670b61c817696d63b9af3596e532ea1907c200c43bcabcdfc4571154898ae13541682283d238caad70c8de2804cc2c96` |
| TLSH | `T13E243BA3FC01DEBFF80FE3B285534C15B230FB6119621A3671A3BE9799250D56923E85` |
| SSDEEP | `3072:OfeK7M88cE/PvPKmIApG16bWqxyBc2sDib1Tl0YcPVtonSVIjbihLTZeHEe:o7E3vSguuyBdsDYTyttoGLTRe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_5eafce5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eafce5d6fadad40b6aa6f7a58da86bbbd29dba0d84c259dbc41c7671ade913c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-28 00:24:54"
  condition:
    hash.sha256(0, filesize) == "5eafce5d6fadad40b6aa6f7a58da86bbbd29dba0d84c259dbc41c7671ade913c"
}
```

### Sample 66: `a189a81a9ac39f98`

| Field | Value |
|---|---|
| SHA-256 | `a189a81a9ac39f9887765a17135a2bf58bbe130ac3e382d2e2e0a3228ca168c8` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-28 00:15:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a06af00d370b652977502550033d130a` |
| SHA-1 | `a93c9d5aab9b5a7757dec93fb288577cd8d65743` |
| SHA-256 | `a189a81a9ac39f9887765a17135a2bf58bbe130ac3e382d2e2e0a3228ca168c8` |
| SHA3-384 | `c1a6d42cc01b1b5fba399be516d65ba7e7ae1d896cd78699207bd2a5609757c327aebd2b608cb4ced973cc8061411bc9` |
| TLSH | `T1F8141902771C0F47D1A36EF0263B27E083ABE96118F4A684751EBFC99371DB21585EDA` |
| SSDEEP | `1536:xSB7ukT5XYuIb/wwbUTuNCk2qkPZ6xTxVNzI5hcJIuqao/l6a6zHGmJvANDgylRN:hkxYuc4wYRqdxVVxTJ6lj6hGNxu+mQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_a189a81a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a189a81a9ac39f9887765a17135a2bf58bbe130ac3e382d2e2e0a3228ca168c8"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-28 00:15:56"
  condition:
    hash.sha256(0, filesize) == "a189a81a9ac39f9887765a17135a2bf58bbe130ac3e382d2e2e0a3228ca168c8"
}
```

### Sample 67: `092225646fba47f7`

| Field | Value |
|---|---|
| SHA-256 | `092225646fba47f7bd157d451211304cf051ed40f6aa10add4013a69d219ac17` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-28 00:14:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e40d921d3f6d71b1849118df689537b4` |
| SHA-1 | `dd66e2f7e2c73eafa493dfbde8845c7ca8febb8d` |
| SHA-256 | `092225646fba47f7bd157d451211304cf051ed40f6aa10add4013a69d219ac17` |
| SHA3-384 | `b408f93379ca8b0a294b7fb85cfd93d3997f82f57748e524d63cd2de6db20e6df33faf971ca00feb3770dfebe0f228fa` |
| TLSH | `T119530294EAF8DC90D0CF2F7A6C8BEB817EE27BD621965D252584DB0F711A520531C7D0` |
| SSDEEP | `1536:ffd8AiTg5QhguBHJ64iPEP+f2sBcXfLwvUfaUaS+04u+qgw0VuW:d8Ai4QhgaJJH+GfUvURV4u+qgw2uW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_09222564
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "092225646fba47f7bd157d451211304cf051ed40f6aa10add4013a69d219ac17"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-28 00:14:49"
  condition:
    hash.sha256(0, filesize) == "092225646fba47f7bd157d451211304cf051ed40f6aa10add4013a69d219ac17"
}
```

### Sample 68: `d49b639c54393dd6`

| Field | Value |
|---|---|
| SHA-256 | `d49b639c54393dd608257e4e7435c60c3aed12f2aba55e22c301341cba167441` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-28 00:14:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d227977b3059e90e01b8605af74d338c` |
| SHA-1 | `af21d11829af1ca5a5423a2ed01b41ca0a0e97a2` |
| SHA-256 | `d49b639c54393dd608257e4e7435c60c3aed12f2aba55e22c301341cba167441` |
| SHA3-384 | `e5ccc17e9394c458323024d078c5e221a7ddceaad1e36231388fc461f5f088add247d2ffb07555546b68257f95f78015` |
| TLSH | `T1ACF3F881FA43CBFAE44606F012B7AB334531FC3A442BE686DB75FE7269619C0D649358` |
| TELFHASH | `t10b519bbbae761aec63c09911c38f7714ee0de5773804317d06a70ad032b6a4265b5cba` |
| SSDEEP | `3072:TMHN8qufevvjuBkrFZ2zCyUe8sqrSa4EKCEPmmWOQirRPmKTI55z7ZJISNGy2GyP:Qt8qufevvjuBkrFZ2zCJe8sqrSDEKCEh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_d49b639c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d49b639c54393dd608257e4e7435c60c3aed12f2aba55e22c301341cba167441"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-28 00:14:35"
  condition:
    hash.sha256(0, filesize) == "d49b639c54393dd608257e4e7435c60c3aed12f2aba55e22c301341cba167441"
}
```

### Sample 69: `ff4583784bf6ed24`

| Field | Value |
|---|---|
| SHA-256 | `ff4583784bf6ed24d9ad5c4d30fcba28c17b6d4e6a01ce0f3bb456449e663d6d` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-28 00:13:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2c6015539d7e12f59e2d98f413d3354` |
| SHA-1 | `47478fabd5c2e8d6052dff7bc9bac4cd55a33320` |
| SHA-256 | `ff4583784bf6ed24d9ad5c4d30fcba28c17b6d4e6a01ce0f3bb456449e663d6d` |
| SHA3-384 | `a575e0ec9aeb2b81d85552bcbb021e50c2e386f673e4b3aa35a3dc4ec3f497324f0ee54d08918d8529ef98e68acb5153` |
| TLSH | `T1A94302C3469AD781D3BAE136498CE3496305F36D17896EAF93F836291B52970AF44C07` |
| SSDEEP | `1536:mtDFy2t9AgRHNusN2SwJgGctWb8eXnouy8O:mtDYiPHNug2iWbV3outO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_ff458378
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff4583784bf6ed24d9ad5c4d30fcba28c17b6d4e6a01ce0f3bb456449e663d6d"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-28 00:13:51"
  condition:
    hash.sha256(0, filesize) == "ff4583784bf6ed24d9ad5c4d30fcba28c17b6d4e6a01ce0f3bb456449e663d6d"
}
```

### Sample 70: `22d30cf723870456`

| Field | Value |
|---|---|
| SHA-256 | `22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2` |
| Family label | `unknown` |
| File name | `22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2` |
| File type | `sh` |
| First seen | `2026-06-27 23:53:15` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70f23922c80521b134aeea51cf3a1116` |
| SHA-1 | `5e30ed1186eb796a56cf40e24520b79f93143451` |
| SHA-256 | `22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2` |
| SHA3-384 | `b376af7fb2e1ff58359a0a55883a4625ce4a87cfc246bf07f9626ee144648e108865774ee26a0dd2988522d7bdf95dd5` |
| TLSH | `T1580392B2B6609930B68DCC3CB6750D51658AA42BC4553818701EF8F49FFC698DCE8BF6` |
| SSDEEP | `768:nfc133pNd9y464571VnJ64EnIgiK2r1nSawi:f65Nd9y464p1VnJ64EnIP7SI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_22d30cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2"
    family = "unknown"
    file_name = "22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2"
    file_type = "sh"
    first_seen = "2026-06-27 23:53:15"
  condition:
    hash.sha256(0, filesize) == "22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2"
}
```

### Sample 71: `2f7e04dd499107fc`

| Field | Value |
|---|---|
| SHA-256 | `2f7e04dd499107fcbcd124d859bbe3d4479b1e7acf2b1c05daff57c9a8a4b0f0` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win64.Malware-gen.85337721` |
| File type | `exe` |
| First seen | `2026-06-27 23:45:32` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef4c778cc00449d703a946dd2889e523` |
| SHA-1 | `cb06b480a3a550dfbc64924d661ab6a2ad737a11` |
| SHA-256 | `2f7e04dd499107fcbcd124d859bbe3d4479b1e7acf2b1c05daff57c9a8a4b0f0` |
| SHA3-384 | `1ed677ab4b7932dcca8da52f32cf1da24c4b1f9068f4c9315eb5487648c990dc0569e8106f382b343a07040c89fd968f` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T1DE563903FD5515E5C0AED1308A7A9253BB717C891B2123D32B60B6387FB6BE0ADB9714` |
| SSDEEP | `49152:8TX+YbY0dJmHi9/ebr7pUgwbluI81XSc8yYhMG1SLze2UKQK1K6GyGqu5Ex:8TNMMw9pcutMKf9VXkE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_2f7e04dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f7e04dd499107fcbcd124d859bbe3d4479b1e7acf2b1c05daff57c9a8a4b0f0"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Malware-gen.85337721"
    file_type = "exe"
    first_seen = "2026-06-27 23:45:32"
  condition:
    hash.sha256(0, filesize) == "2f7e04dd499107fcbcd124d859bbe3d4479b1e7acf2b1c05daff57c9a8a4b0f0"
}
```

### Sample 72: `8ba894b2cdc50ad8`

| Field | Value |
|---|---|
| SHA-256 | `8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb` |
| Family label | `unknown` |
| File name | `8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb` |
| File type | `elf` |
| First seen | `2026-06-27 21:52:13` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c33054c0b6ed1dbdddd2870112b6b95` |
| SHA-1 | `d5e5ca1b2d5f20fbeb697618d75de37596ee2e72` |
| SHA-256 | `8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb` |
| SHA3-384 | `c750c76f4c743b194e9acc4956e2bcb5da61b6f001a12d6f40d1609a16dd1d42b039d2c22a2cc418e928674fb76da258` |
| TLSH | `T18007AD77814338E9E5A98CB4D51025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQh:cqYUQuVDt0TZES` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_8ba894b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb"
    family = "unknown"
    file_name = "8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb"
    file_type = "elf"
    first_seen = "2026-06-27 21:52:13"
  condition:
    hash.sha256(0, filesize) == "8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb"
}
```

### Sample 73: `2dd4175fc20d38e5`

| Field | Value |
|---|---|
| SHA-256 | `2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16` |
| Family label | `unknown` |
| File name | `2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16` |
| File type | `elf` |
| First seen | `2026-06-27 21:40:25` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e24a62dd834cb62befcdd800425c493f` |
| SHA-1 | `f407566c5a544e1de3a979cdabebdb232aed7a77` |
| SHA-256 | `2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16` |
| SHA3-384 | `4f6ac7a08ab4bd5d078a38f31550eba1168f570023308bbd8186a6f687a0579507ac2233b690749239e03f2ed422ab21` |
| TLSH | `T14E47DF77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQy:cqYUQuVDt0TZE9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_2dd4175f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16"
    family = "unknown"
    file_name = "2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16"
    file_type = "elf"
    first_seen = "2026-06-27 21:40:25"
  condition:
    hash.sha256(0, filesize) == "2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16"
}
```

### Sample 74: `848d134ca9d68ba3`

| Field | Value |
|---|---|
| SHA-256 | `848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275` |
| Family label | `unknown` |
| File name | `848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275` |
| File type | `elf` |
| First seen | `2026-06-27 21:35:43` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5132f57428e339856aff5629b1d0ce68` |
| SHA-1 | `5c6c97a24c091d389d18f4b63a147cbd26f29844` |
| SHA-256 | `848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275` |
| SHA3-384 | `a29c4c5d8c876019a1be92431f73cf51f517e25a81c00acdf4807d26d75591d51178e6725f6cfd18e19ebe14175e5e09` |
| TLSH | `T16817AD77814338E9E5A98CB4D51025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQd:cqYUQuVDt0TZEa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_848d134c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275"
    family = "unknown"
    file_name = "848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275"
    file_type = "elf"
    first_seen = "2026-06-27 21:35:43"
  condition:
    hash.sha256(0, filesize) == "848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275"
}
```

### Sample 75: `df1bb5c2aac6220c`

| Field | Value |
|---|---|
| SHA-256 | `df1bb5c2aac6220ca59bed32b53e02836ff53b6d732bd4a91c5252d507748d03` |
| Family label | `unknown` |
| File name | `NetMedved_2.js` |
| File type | `js` |
| First seen | `2026-06-27 21:23:26` |
| Reporter | `KodaDr` |
| Tags | `APT, js, NetMedved` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54ad73dda690f63470cff1c0c60195d4` |
| SHA-1 | `c436bc363ccb5fb3b96950ae23c766c4aa468b0a` |
| SHA-256 | `df1bb5c2aac6220ca59bed32b53e02836ff53b6d732bd4a91c5252d507748d03` |
| SHA3-384 | `3a276999fc7ea8bfe8e244e7f4e1bff4aadbb5a5d5d3dfd4ab4fb13f79e913d294c45e552d889558e1c84fc9f6d306ce` |
| TLSH | `T1815649691894B0B4FDF6DB91C21FD899430BB2332A076D7B406C07A46E1AED9DE12C5F` |
| SSDEEP | `49152:rrkal6dDYAEo55DgCkOxKJ0ifEab0mGVNoKpD7p+VAGripld:2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_df1bb5c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df1bb5c2aac6220ca59bed32b53e02836ff53b6d732bd4a91c5252d507748d03"
    family = "unknown"
    file_name = "NetMedved_2.js"
    file_type = "js"
    first_seen = "2026-06-27 21:23:26"
  condition:
    hash.sha256(0, filesize) == "df1bb5c2aac6220ca59bed32b53e02836ff53b6d732bd4a91c5252d507748d03"
}
```

### Sample 76: `d1e4c6578b588e95`

| Field | Value |
|---|---|
| SHA-256 | `d1e4c6578b588e95d8ed03b46f2febc0ce2d5a8a8b612cafe640b6e23ba637d7` |
| Family label | `unknown` |
| File name | `NetMedved_1.js` |
| File type | `js` |
| First seen | `2026-06-27 21:22:46` |
| Reporter | `KodaDr` |
| Tags | `APT, js, NetMedved` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7d45534bdfefedb6bd7c3214eb3c5b` |
| SHA-1 | `ce69cdeac9c1ca625859134414323c93bef5c728` |
| SHA-256 | `d1e4c6578b588e95d8ed03b46f2febc0ce2d5a8a8b612cafe640b6e23ba637d7` |
| SHA3-384 | `6b530918cf3dd5f77b7097051b2567c7be357bc3315036a5629bd1144dd0e2abaf9db94b359f5c18fa62a11645cba0a4` |
| TLSH | `T1F25649695894B0B4FDF6DB81C21F9899430BB3332A076D7B406C07A46E1AED9DE12C5F` |
| SSDEEP | `49152:Wrkal6dDYAEo55DgCkOxKJ0ifEab0mDeG8ydlR/iplWYc/+h8:w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_d1e4c657
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e4c6578b588e95d8ed03b46f2febc0ce2d5a8a8b612cafe640b6e23ba637d7"
    family = "unknown"
    file_name = "NetMedved_1.js"
    file_type = "js"
    first_seen = "2026-06-27 21:22:46"
  condition:
    hash.sha256(0, filesize) == "d1e4c6578b588e95d8ed03b46f2febc0ce2d5a8a8b612cafe640b6e23ba637d7"
}
```

### Sample 77: `716612c11982500c`

| Field | Value |
|---|---|
| SHA-256 | `716612c11982500cca51970f822ddffb5a4b3aa84fda3cb30ffab6daa94f5248` |
| Family label | `Socks5Systemz` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 20:46:07` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, Socks5Systemz, UNIQTWO.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c76d9b7366f34a1fad3b5b0527e24f` |
| SHA-1 | `89eec27c0af96d4932891f02c0a7988b05526012` |
| SHA-256 | `716612c11982500cca51970f822ddffb5a4b3aa84fda3cb30ffab6daa94f5248` |
| SHA3-384 | `4bfbedd78900cad121ba762a3678857d39d45001a796af48f2f613f2eec4b4b40adb569b418bc2a4b4ef41306ce14286` |
| IMPHASH | `884310b1928934402ea6fec1dbd3cf5e` |
| TLSH | `T103F5332155D1C734C46109BE8CEAD47D088B1E9A5E7A54DD60CECAFF872B1C7C4893E2` |
| SSDEEP | `49152:1vYVyAATy0rHLQss7/kmptqfnwku3T07zXU8OsIbc78xJS1DKftdWU3+IUJXZKXQ:NLAz0rQXV+wkOsIQwx0pKlQs+rXZ04` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `Socks5Systemz` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Socks5Systemz_077_716612c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716612c11982500cca51970f822ddffb5a4b3aa84fda3cb30ffab6daa94f5248"
    family = "Socks5Systemz"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 20:46:07"
  condition:
    hash.sha256(0, filesize) == "716612c11982500cca51970f822ddffb5a4b3aa84fda3cb30ffab6daa94f5248"
}
```

### Sample 78: `94e03e46b656afa0`

| Field | Value |
|---|---|
| SHA-256 | `94e03e46b656afa0d66f8d08ae08b21a3d96dda4cd3d51afd31c559f715b56db` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-06-27 20:20:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64a18042f163039202205779d84500b3` |
| SHA-1 | `85588f2a321c01c82f0f685abe9c6b428c1b37b2` |
| SHA-256 | `94e03e46b656afa0d66f8d08ae08b21a3d96dda4cd3d51afd31c559f715b56db` |
| SHA3-384 | `aef937f8bdac3bac0ae6c02054b6cd8a79882605e758f53b0615707acbd49d13105e2cffc79b04bc2275058d3803346d` |
| TLSH | `T1F7016BC68620AE10902DD61E62D7A290B461C3CE164B0F747FAC5D3DFB99D14F036F85` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohacXcFM9GQjVqOSE67:e9Qp+Msw0ktVB67` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_94e03e46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94e03e46b656afa0d66f8d08ae08b21a3d96dda4cd3d51afd31c559f715b56db"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-27 20:20:56"
  condition:
    hash.sha256(0, filesize) == "94e03e46b656afa0d66f8d08ae08b21a3d96dda4cd3d51afd31c559f715b56db"
}
```

### Sample 79: `cee808610a5064df`

| Field | Value |
|---|---|
| SHA-256 | `cee808610a5064df4b156931891925432ebef98e64a79b9805c10a39b0b417dd` |
| Family label | `Gafgyt` |
| File name | `a-r.m-7.Sakura` |
| File type | `elf` |
| First seen | `2026-06-27 20:10:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d531946e9025e8ba59d0ca267f918df` |
| SHA-1 | `9e63f44b5551970bcbc4b23ee75553de62191a4e` |
| SHA-256 | `cee808610a5064df4b156931891925432ebef98e64a79b9805c10a39b0b417dd` |
| SHA3-384 | `38afd09300cf2727d7ddadebedb53ed57c394b66a7f20e0a1eb8cf454971801dbd482d049308c8f9abb5a9fa5eaab9f3` |
| TLSH | `T163B33913B71C0B53C49759F129BB3BF197A9B9E112966285A50AFFC01373DF02422F99` |
| TELFHASH | `t1f621eb0371eaca296bb356246cb842b112a56a333391be71bf1dc4c494370027974ecb` |
| SSDEEP | `3072:Y+PrNZ+s+uJSuR5oHdDJdBRmnK0PDrO7fFOo:Y+PrNZIuJPzs5JdBRmnK0PDrO7fFOo` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_079_cee80861
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee808610a5064df4b156931891925432ebef98e64a79b9805c10a39b0b417dd"
    family = "Gafgyt"
    file_name = "a-r.m-7.Sakura"
    file_type = "elf"
    first_seen = "2026-06-27 20:10:53"
  condition:
    hash.sha256(0, filesize) == "cee808610a5064df4b156931891925432ebef98e64a79b9805c10a39b0b417dd"
}
```

### Sample 80: `f4940efc61c20e22`

| Field | Value |
|---|---|
| SHA-256 | `f4940efc61c20e2257dd53e13c57ddd99836022cfeeca3faa32c580b7b049173` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-27 20:08:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba5bcb57fef96201412425fb0af10f94` |
| SHA-1 | `ae27f63da11f310d4726620b015e687cfda18867` |
| SHA-256 | `f4940efc61c20e2257dd53e13c57ddd99836022cfeeca3faa32c580b7b049173` |
| SHA3-384 | `b24c7c5a59138edb88aee093a57175d79056a11eb78f4eafe0ec090257744dad8dbd1ba4bf5b80c0c9e224654b4c17e3` |
| TLSH | `T137C30855F8405B23C6C616BBFF4E438D7B261798E3EE720399246F64379B85B0E3A142` |
| TELFHASH | `t1fdc080f7514455cd17e54140d9d9031d4775fbce4f5d30874606573b44c28c790e8075` |
| SSDEEP | `1536:R3keGprJWcS2B2133i4VI7e7kneqet9rOB5um1vx6c2rllBwywEy0thZf/pt7vhI:idM2BV4eeIneqQ8NxHCCvX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_f4940efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4940efc61c20e2257dd53e13c57ddd99836022cfeeca3faa32c580b7b049173"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-27 20:08:51"
  condition:
    hash.sha256(0, filesize) == "f4940efc61c20e2257dd53e13c57ddd99836022cfeeca3faa32c580b7b049173"
}
```

### Sample 81: `6f93534ca2cf1260`

| Field | Value |
|---|---|
| SHA-256 | `6f93534ca2cf1260210d189cf8a8f955806651a5aa1cf0801bf5832e3f7b8a12` |
| Family label | `unknown` |
| File name | `libdpt.so.elf` |
| File type | `elf` |
| First seen | `2026-06-27 20:03:40` |
| Reporter | `BastianHein_` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9e45058306111e3a37ca2c266346dd2` |
| SHA-1 | `2ed87bdcd1148a72d6cac073fd34f8d6f429c8ca` |
| SHA-256 | `6f93534ca2cf1260210d189cf8a8f955806651a5aa1cf0801bf5832e3f7b8a12` |
| SHA3-384 | `6d7b965f04b8af41635afa3c661e67edfdbdd358a5be69c5ed5fbc90e7d7ab75f6b7a1aaf86fc2c41c5d28e4cd20a592` |
| TLSH | `T12FC43B53F691187ECD79EC38839A9131D334748A835266EB2784AA103F54BE4DF3EAD1` |
| TELFHASH | `t16c21cb04aa3e0be9546a7c56e8246bd58053cb19a160fb02ff6ccdc15d0fa4af1a8d4d` |
| SSDEEP | `6144:NcI8mKLl6Tqs9Wn9OZT4toCDEhL0ti/up2NO0DCueGwuyMrFQqbsLkLsJGhW7xPu:qVR9UtQlSzBF7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_6f93534c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f93534ca2cf1260210d189cf8a8f955806651a5aa1cf0801bf5832e3f7b8a12"
    family = "unknown"
    file_name = "libdpt.so.elf"
    file_type = "elf"
    first_seen = "2026-06-27 20:03:40"
  condition:
    hash.sha256(0, filesize) == "6f93534ca2cf1260210d189cf8a8f955806651a5aa1cf0801bf5832e3f7b8a12"
}
```

### Sample 82: `c0e4f1cd9cad6fd1`

| Field | Value |
|---|---|
| SHA-256 | `c0e4f1cd9cad6fd1a8485c945bbd384c25a441225657d440b35b743a852627ab` |
| Family label | `unknown` |
| File name | `libdpt.so.elf` |
| File type | `elf` |
| First seen | `2026-06-27 19:52:54` |
| Reporter | `BastianHein_` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bee4846f72c762b42e3e256e3225013` |
| SHA-1 | `a64247d5582154d9d3c0f23a3d2fde26dc632516` |
| SHA-256 | `c0e4f1cd9cad6fd1a8485c945bbd384c25a441225657d440b35b743a852627ab` |
| SHA3-384 | `b98aa0e3c3122e9963991805afcb9357710804a7c380618cab98756a257e77ef4c6129ea5353cdabced036b654017604` |
| TLSH | `T147B4F746F44186BAC67975B521CFE33AD906185E833388CB8F4A9D607A272E1CF7D6C1` |
| TELFHASH | `t18a210d00ae3d07e9546a7c66e8242bd6c053cb29a160fb01ff6ccdc08c0ea8af168d4d` |
| SSDEEP | `6144:amKpl6Tqs9Wn9OJT4toCDEhL0zi/up2NO0DCueGmfXFQqbsXgLsJGoFfW5ztc11C:xAzq16xPRcqOzM3smr5YsQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_c0e4f1cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0e4f1cd9cad6fd1a8485c945bbd384c25a441225657d440b35b743a852627ab"
    family = "unknown"
    file_name = "libdpt.so.elf"
    file_type = "elf"
    first_seen = "2026-06-27 19:52:54"
  condition:
    hash.sha256(0, filesize) == "c0e4f1cd9cad6fd1a8485c945bbd384c25a441225657d440b35b743a852627ab"
}
```

### Sample 83: `2b60ca11a172d02f`

| Field | Value |
|---|---|
| SHA-256 | `2b60ca11a172d02f1d9043e8f9c050d621aaf01ee81f9ab312a973777637dee3` |
| Family label | `unknown` |
| File name | `4304-0.dex` |
| File type | `unknown` |
| First seen | `2026-06-27 19:52:39` |
| Reporter | `BastianHein_` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca88e26cf9be915b0b4398ed2d19c13a` |
| SHA-256 | `2b60ca11a172d02f1d9043e8f9c050d621aaf01ee81f9ab312a973777637dee3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_2b60ca11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b60ca11a172d02f1d9043e8f9c050d621aaf01ee81f9ab312a973777637dee3"
    family = "unknown"
    file_name = "4304-0.dex"
    file_type = "unknown"
    first_seen = "2026-06-27 19:52:39"
  condition:
    hash.sha256(0, filesize) == "2b60ca11a172d02f1d9043e8f9c050d621aaf01ee81f9ab312a973777637dee3"
}
```

### Sample 84: `4b846be26d903834`

| Field | Value |
|---|---|
| SHA-256 | `4b846be26d903834219e4369bd48097e04642f5f4abaec582e3e73692947d4f0` |
| Family label | `unknown` |
| File name | `i11111i111.zip` |
| File type | `unknown` |
| First seen | `2026-06-27 19:52:20` |
| Reporter | `BastianHein_` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd74283f3f8aecdf765960a3fb351c39` |
| SHA-256 | `4b846be26d903834219e4369bd48097e04642f5f4abaec582e3e73692947d4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_4b846be2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b846be26d903834219e4369bd48097e04642f5f4abaec582e3e73692947d4f0"
    family = "unknown"
    file_name = "i11111i111.zip"
    file_type = "unknown"
    first_seen = "2026-06-27 19:52:20"
  condition:
    hash.sha256(0, filesize) == "4b846be26d903834219e4369bd48097e04642f5f4abaec582e3e73692947d4f0"
}
```

### Sample 85: `8ac21ddc17f81979`

| Field | Value |
|---|---|
| SHA-256 | `8ac21ddc17f81979134b2a1e2d9aa191927239f55090eaf28d49a0297619e645` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-27 19:50:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc28b273c00391f0ebf011fdbd5e4caa` |
| SHA-1 | `dbde03ada756e185ff0137b9c7713aa0dab1dd87` |
| SHA-256 | `8ac21ddc17f81979134b2a1e2d9aa191927239f55090eaf28d49a0297619e645` |
| SHA3-384 | `7500e2e84f93abff7d83ee78cecba80b309847494be65cc17238a719f3d1087d31380049ba40effafcd6e8cda7fba314` |
| TLSH | `T174237D6516817C24AA99D4371D7F2F0CBDA983E6320492DDBFCA3CF28C59A9CD11872D` |
| SSDEEP | `768:9XRWNGxV69GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:HlxhcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_8ac21ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ac21ddc17f81979134b2a1e2d9aa191927239f55090eaf28d49a0297619e645"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-27 19:50:51"
  condition:
    hash.sha256(0, filesize) == "8ac21ddc17f81979134b2a1e2d9aa191927239f55090eaf28d49a0297619e645"
}
```

### Sample 86: `2358266014965da1`

| Field | Value |
|---|---|
| SHA-256 | `2358266014965da1fbcab4fff34a4d7c0d57e6582408ba48cc42c002f7370e2e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Siggen32.58893.30928.10542` |
| File type | `exe` |
| First seen | `2026-06-27 19:44:59` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fc7c24da89adad58981093910449095` |
| SHA-1 | `effc108a84ae4e2566d3466c52bb87a56f141345` |
| SHA-256 | `2358266014965da1fbcab4fff34a4d7c0d57e6582408ba48cc42c002f7370e2e` |
| SHA3-384 | `c01fa7542bbd20a9ebec0ebd9246570fdc6e62379c5044aac535bdc2bc89dd13bbd4a4d2eb5b55450e39e72b4f73354a` |
| IMPHASH | `805f6dd42e8904f9405139fb7adc8f99` |
| TLSH | `T12EA63B03BF5829E4EA456D3001B64B0F939AFD453A366B8F1B09BA1D9FF73C12E41586` |
| SSDEEP | `196608:fnV1zWZSFD+oEQmAK3HFYUdt45FLOyomFHKnP:fV1uSh9EQm3FYw45F` |
| ICON-DHASH | `5262329652524450` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_23582660
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2358266014965da1fbcab4fff34a4d7c0d57e6582408ba48cc42c002f7370e2e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.58893.30928.10542"
    file_type = "exe"
    first_seen = "2026-06-27 19:44:59"
  condition:
    hash.sha256(0, filesize) == "2358266014965da1fbcab4fff34a4d7c0d57e6582408ba48cc42c002f7370e2e"
}
```

### Sample 87: `79ced052ef336b98`

| Field | Value |
|---|---|
| SHA-256 | `79ced052ef336b98a3dd0b032e79dd2fb2e91c36d8cf0c0d55cf7a2c6cdcf37e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 19:43:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3121ac461b00d1d559cc3c66604e5c27` |
| SHA-1 | `ea1b0b08148962f96afe14ddaa2f31a64c8376d0` |
| SHA-256 | `79ced052ef336b98a3dd0b032e79dd2fb2e91c36d8cf0c0d55cf7a2c6cdcf37e` |
| SHA3-384 | `32200b7956f45c5da461f76ddf62bb941cc69b307d313481caf4aa6d5ad89411480f942165d536e8c654b7bac26183a1` |
| IMPHASH | `57417c97e4cf3a257e5ac6245626f99d` |
| TLSH | `T17AC5F63B6954A168C01FC1BBD0925B24D83374790772D1EB218C3E5AFA89ECA4EFB751` |
| SSDEEP | `24576:QDm2enVqZCnwRVzzzdEErWJ+yyj/VTA8v2XE:PnVqQnEPdEErq3c/IX` |
| ICON-DHASH | `385c888c8ce6c5e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_79ced052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79ced052ef336b98a3dd0b032e79dd2fb2e91c36d8cf0c0d55cf7a2c6cdcf37e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 19:43:34"
  condition:
    hash.sha256(0, filesize) == "79ced052ef336b98a3dd0b032e79dd2fb2e91c36d8cf0c0d55cf7a2c6cdcf37e"
}
```

### Sample 88: `c9f0f8875297bccf`

| Field | Value |
|---|---|
| SHA-256 | `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b` |
| Family label | `unknown` |
| File name | `nested_app.apk` |
| File type | `apk` |
| First seen | `2026-06-27 19:43:16` |
| Reporter | `BastianHein_` |
| Tags | `apk, SaferRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccf1d5505879acc776a19bd3fcbc46c2` |
| SHA-1 | `b328cf8ebdc1ead78eb1ad25d3ff5f6f676099f9` |
| SHA-256 | `c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b` |
| SHA3-384 | `a74f54c0cebe83941c4c861d6ced69f728830ac7fe39caa35d2db5786fed90aaa080a0d7c640c49c78475b5f29115b5e` |
| TLSH | `T1748601C6F7D8A92FC4775032C5BA52F6914B4C228E879F536914760C28BB6D84F4AFC8` |
| SSDEEP | `196608:rcrkfljMbVwiuKVO9Ht6foGMsGge4lVvoJQVujS:wkfSGiE9t6fgsH1lVvoJc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_c9f0f887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
    family = "unknown"
    file_name = "nested_app.apk"
    file_type = "apk"
    first_seen = "2026-06-27 19:43:16"
  condition:
    hash.sha256(0, filesize) == "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
}
```

### Sample 89: `56e66ffef4ae328e`

| Field | Value |
|---|---|
| SHA-256 | `56e66ffef4ae328ebdf3539fb741410079a2acb6cb5e817c1d48aa537c478dcd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 19:42:53` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a5d7499025b6ecdbf80c94966f8caf1` |
| SHA-1 | `62375785d66817aeb317e9d15a71282d70ee9f7e` |
| SHA-256 | `56e66ffef4ae328ebdf3539fb741410079a2acb6cb5e817c1d48aa537c478dcd` |
| SHA3-384 | `9a69a27dbaf52a52086c41c99c0291b1efa48572548b562eafb12cee39099cf81b45fac536b3ba4588a0ee9c42317686` |
| IMPHASH | `7636034d7f84561d77daf6dd678cf919` |
| TLSH | `T135F4CC3A2C94B531C41F61F3B914A5B4DC982D5819F53A22300C3E5BF6AAEDBA5CB713` |
| SSDEEP | `12288:bV0lA9Jz7XZun+LCddWR8Kx4F1VZNuTtd2CiQU2NI5szpH:bOmLzro+GEP4F1V2dXe2+` |
| ICON-DHASH | `385c888c8ce6c5e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_56e66ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e66ffef4ae328ebdf3539fb741410079a2acb6cb5e817c1d48aa537c478dcd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 19:42:53"
  condition:
    hash.sha256(0, filesize) == "56e66ffef4ae328ebdf3539fb741410079a2acb6cb5e817c1d48aa537c478dcd"
}
```

### Sample 90: `a3fed15f05903e3b`

| Field | Value |
|---|---|
| SHA-256 | `a3fed15f05903e3bb645f059a65f5e56ffeab45ab02f535d6df263d4363a6628` |
| Family label | `unknown` |
| File name | `mpclient.dll` |
| File type | `exe` |
| First seen | `2026-06-27 19:21:05` |
| Reporter | `burger403` |
| Tags | `exe, signed, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fc877b010e2c630c4db9efd1e0c5ffe` |
| SHA-1 | `64dda3b0dc00c304bb3b65db472548d7d4c7204c` |
| SHA-256 | `a3fed15f05903e3bb645f059a65f5e56ffeab45ab02f535d6df263d4363a6628` |
| SHA3-384 | `e94cd9d45315835edc60473834cb4c4fe89a26da33945f89396f2a646758541c92f77379ff85a047461d25ae9e6e125f` |
| IMPHASH | `d8b31f8c03e0c76ff245ed05a15ffe6c` |
| TLSH | `T127267C87FED0A5B9C09EDA3194A6525D7A79BC580F3223D71F70A2792F723D0487AB10` |
| SSDEEP | `98304:GaIVQtM0gEssdyX444q+o94GOvpt9jmaWl1:GCtM0gEssYIBq+oqGOvptk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_a3fed15f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3fed15f05903e3bb645f059a65f5e56ffeab45ab02f535d6df263d4363a6628"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-27 19:21:05"
  condition:
    hash.sha256(0, filesize) == "a3fed15f05903e3bb645f059a65f5e56ffeab45ab02f535d6df263d4363a6628"
}
```

### Sample 91: `8da70cdcaf30bedd`

| Field | Value |
|---|---|
| SHA-256 | `8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e` |
| Family label | `IRATA` |
| File name | `geeeh.25175.signed_signed.apk` |
| File type | `apk` |
| First seen | `2026-06-27 19:15:50` |
| Reporter | `BastianHein_` |
| Tags | `apk, Irata, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `859af85009682ae2e07cb19e7a4467da` |
| SHA-1 | `b144d8a0482fc5182d2577763a9b8c3aa0da2716` |
| SHA-256 | `8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e` |
| SHA3-384 | `f40fb2f9cd7442d4b6dc556a8b323d89afc007bf7ef14756a5fdbf27f0f858e692edf641d145ded6e7325ed01d311a7b` |
| TLSH | `T1EE562346FE57A8EACCFAC33111761B35213A1D268747D74727B0BAF828BB9D847466C0` |
| SSDEEP | `98304:iu1gVZS37ZgiInHT8I98NZhWsusiLV+t3xhZJsr2A+sS3t+RhQb8:J14ZSG4I9KZqzcFHy27Zvb8` |

#### Technical Assessment

- The sample is tracked as `IRATA` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_IRATA_091_8da70cdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
    family = "IRATA"
    file_name = "geeeh.25175.signed_signed.apk"
    file_type = "apk"
    first_seen = "2026-06-27 19:15:50"
  condition:
    hash.sha256(0, filesize) == "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
}
```

### Sample 92: `d8cd89e8f7eb14c5`

| Field | Value |
|---|---|
| SHA-256 | `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4` |
| Family label | `unknown` |
| File name | `Strawberry.apk` |
| File type | `apk` |
| First seen | `2026-06-27 19:12:32` |
| Reporter | `BastianHein_` |
| Tags | `apk, SaferRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fec745d87efbaa86f853c6e13bbc3e37` |
| SHA-1 | `5f7241cc8998a4850b76482099e15a92c96b1a7a` |
| SHA-256 | `d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4` |
| SHA3-384 | `344e4f891cbf1a5c4977d99e67c9f65917229c8b3ba4e8fabd474102a55c81a01e589f2cc65137d22277a0d6825beae2` |
| TLSH | `T103E622C6F7C8992FC4774032C5BA67F1554B4C228E839F876958760C29BB5D84F8ABC8` |
| SSDEEP | `393216:9lEauZPzL0QzC+j/lAq8sgLtufXsYylLNdHIVvy:9l9uZPU16N4sgRuFwdoVvy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_d8cd89e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4"
    family = "unknown"
    file_name = "Strawberry.apk"
    file_type = "apk"
    first_seen = "2026-06-27 19:12:32"
  condition:
    hash.sha256(0, filesize) == "d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4"
}
```

### Sample 93: `cf827508b66b36fc`

| Field | Value |
|---|---|
| SHA-256 | `cf827508b66b36fc399690492cd798751f99f9cbaf3319e08fd3e6f60ed9b507` |
| Family label | `unknown` |
| File name | `Client.exe` |
| File type | `exe` |
| First seen | `2026-06-27 19:11:48` |
| Reporter | `burger403` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c66aba509a66e9ab69e24fb30bcc324` |
| SHA-1 | `8e4e7339ef5dc202638ee18f436213ce6af6bba7` |
| SHA-256 | `cf827508b66b36fc399690492cd798751f99f9cbaf3319e08fd3e6f60ed9b507` |
| SHA3-384 | `37b76281b447b44746e35c2fc2cabaaf8e78eb68b2588c9c61b36a6fb116f821cd328086be7723287eae5dec76c02c54` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T14718336C8AE5A31EEE3EDDF40170E613E65DB429AF5D74BB96D82031323340407B96A7` |
| SSDEEP | `1572864:Wt9IKPZlkiUILav0x7wDwYieTqowzKYypCPRfYLgRLlPBnU6InslAWLAK7:WUKhl1uXDwYAoyKYyuB/5PU6InstAK7` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_cf827508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf827508b66b36fc399690492cd798751f99f9cbaf3319e08fd3e6f60ed9b507"
    family = "unknown"
    file_name = "Client.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:11:48"
  condition:
    hash.sha256(0, filesize) == "cf827508b66b36fc399690492cd798751f99f9cbaf3319e08fd3e6f60ed9b507"
}
```

### Sample 94: `abb0ddc5d6972b69`

| Field | Value |
|---|---|
| SHA-256 | `abb0ddc5d6972b69a938f88cbc354dffbd14adcd13b8049e6654f51dd3f5836d` |
| Family label | `Vidar` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-27 19:09:39` |
| Reporter | `burger403` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f269378bb7d1c7817fa6200a1198b9df` |
| SHA-1 | `b10573574be99566629f6ca88ba82d0e7e2122a7` |
| SHA-256 | `abb0ddc5d6972b69a938f88cbc354dffbd14adcd13b8049e6654f51dd3f5836d` |
| SHA3-384 | `13c4be1dafee7be2fd44319d94d951eb1789057c8a1104ec6362e5d61afb87f3f409405dd171022af2b02d18ff2e5d23` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11DF57C07BDE148E9C09AA33199B6855A7B75BC490F3223E72E50B7B82F723D05D36B44` |
| SSDEEP | `49152:kbdXPg5ldVhjuv8wCHRaj6hQVXoEXdXGWiY5WYHziPsicn:k5UgSGXdWWRcW` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_094_abb0ddc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb0ddc5d6972b69a938f88cbc354dffbd14adcd13b8049e6654f51dd3f5836d"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:09:39"
  condition:
    hash.sha256(0, filesize) == "abb0ddc5d6972b69a938f88cbc354dffbd14adcd13b8049e6654f51dd3f5836d"
}
```

### Sample 95: `4a465658121a1544`

| Field | Value |
|---|---|
| SHA-256 | `4a465658121a15449fadbeed82d37c461e601ae45c08a3d6c992285d31ebf804` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-06-27 19:04:50` |
| Reporter | `burger403` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a040670ccbe6b4c9841d8706c433997c` |
| SHA-1 | `f8feca6cc45f6b934201c28a8c0d86409fce8836` |
| SHA-256 | `4a465658121a15449fadbeed82d37c461e601ae45c08a3d6c992285d31ebf804` |
| SHA3-384 | `5c788ede7409b809201c3ddc4cffdb7a75172b83e5f2404ffb922338399e266497faed80b59077fbad876823ac382d52` |
| IMPHASH | `578cc8e30a11aa15cbed91e618811b6e` |
| TLSH | `T1E3E6AE03B7859135E49B2A79046B97755D3E7E202B21CDDB57B038AC4E316C2AE3E34E` |
| SSDEEP | `393216:DubmdBDPg48m6pJ+o6SVP1CPwDvt3uFrCeP2NOUAQWuS:H6N6GWuS` |
| ICON-DHASH | `171d3e928cdd391b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_4a465658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a465658121a15449fadbeed82d37c461e601ae45c08a3d6c992285d31ebf804"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:04:50"
  condition:
    hash.sha256(0, filesize) == "4a465658121a15449fadbeed82d37c461e601ae45c08a3d6c992285d31ebf804"
}
```

### Sample 96: `e21f70aebb96b545`

| Field | Value |
|---|---|
| SHA-256 | `e21f70aebb96b545be30ba9b92fb7a77321d78da5641ce9f4d7b3ab8f6d09e70` |
| Family label | `unknown` |
| File name | `Loader.exe` |
| File type | `exe` |
| First seen | `2026-06-27 19:04:37` |
| Reporter | `burger403` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `948b712d99e0c5cad05416e7f13841bb` |
| SHA-1 | `cbaebbe158ff69d922a67b61eb93b19e3a92306a` |
| SHA-256 | `e21f70aebb96b545be30ba9b92fb7a77321d78da5641ce9f4d7b3ab8f6d09e70` |
| SHA3-384 | `21169ed039e529a8ed3424e853513f89ce41847c11e0f8b0ae461f4bfb943c2443adcb0352abcdf3126e1375781a931e` |
| IMPHASH | `544d328d505711c061637b5e94979592` |
| TLSH | `T1E8E623E666C552E4D4C70E70665E97CD32D0F84D49ACA82B36C72C03AF25E9F0A49DB3` |
| SSDEEP | `393216:pK20oQacOvXsy5iakYLjid1qD+jh7OqnIDJa:pK20onhX/WYLjiSDWhqrDs` |
| ICON-DHASH | `30f0c8d4d469b254` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_e21f70ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e21f70aebb96b545be30ba9b92fb7a77321d78da5641ce9f4d7b3ab8f6d09e70"
    family = "unknown"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:04:37"
  condition:
    hash.sha256(0, filesize) == "e21f70aebb96b545be30ba9b92fb7a77321d78da5641ce9f4d7b3ab8f6d09e70"
}
```

### Sample 97: `ef94a5ecaf100b9c`

| Field | Value |
|---|---|
| SHA-256 | `ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885` |
| Family label | `SpyNote` |
| File name | `NightmareClient.apk` |
| File type | `apk` |
| First seen | `2026-06-27 18:49:48` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed, SpyNote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86e8f6621dae6dcea005ec58e32fbabc` |
| SHA-1 | `749aed0b75a6e115c0135abd616104be563c0d91` |
| SHA-256 | `ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885` |
| SHA3-384 | `a40cb7c18e7eb5a72d2f608bee43f802b78a40ca865e71d3b6e106b02bf7b5e22953fe828d2a057209bb6df1960888d9` |
| TLSH | `T17556E103FD09CF9AE6B983B4E63B554237037F07C881466B0205B26E6B729D937DD989` |
| SSDEEP | `98304:uxDWz8ypanPAf8RinM6Bopvfzemz5zBkTG0tRzDDpV:uxDeU4fFMk6lzMNpxV` |

#### Technical Assessment

- The sample is tracked as `SpyNote` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SpyNote_097_ef94a5ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
    family = "SpyNote"
    file_name = "NightmareClient.apk"
    file_type = "apk"
    first_seen = "2026-06-27 18:49:48"
  condition:
    hash.sha256(0, filesize) == "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
}
```

### Sample 98: `6db892bb99216334`

| Field | Value |
|---|---|
| SHA-256 | `6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210` |
| Family label | `SpyNote` |
| File name | `client.apk` |
| File type | `apk` |
| First seen | `2026-06-27 18:49:24` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed, SpyNote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f03323c6d037244cf03a674c9e4756a2` |
| SHA-1 | `87fc91079eb2042d7044198010ec85cef36b9639` |
| SHA-256 | `6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210` |
| SHA3-384 | `be4965d0cc7973d833ff5f2df156889158457e3a21691b369414da9ffa194620cc578dc87c3ee4c0e82c5bcf63347182` |
| TLSH | `T160F46C86FB8AF863C9F3C6368275C66AD6164D554B43D7831985B23C09B7AC08B49FCC` |
| SSDEEP | `12288:+XqmTa1a8Lre1vhbJSRz5WmpYshXZPbGwidNpgrdYX:+3a1a2e1lJSRz5WmD9idNpP` |

#### Technical Assessment

- The sample is tracked as `SpyNote` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SpyNote_098_6db892bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210"
    family = "SpyNote"
    file_name = "client.apk"
    file_type = "apk"
    first_seen = "2026-06-27 18:49:24"
  condition:
    hash.sha256(0, filesize) == "6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210"
}
```

### Sample 99: `272248f64722ef49`

| Field | Value |
|---|---|
| SHA-256 | `272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28` |
| Family label | `SpyNote` |
| File name | `Blockchain(1).apk` |
| File type | `apk` |
| First seen | `2026-06-27 18:49:18` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed, SpyNote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68a12fa0f8cb46f2a33c3764a96ce4be` |
| SHA-1 | `f5e8d0d3fedc45a1c9ed6748fd8a7a9df148ff75` |
| SHA-256 | `272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28` |
| SHA3-384 | `0e63bd9a6b06e0da03897b61feb4d163a79392af2565670994d60cefa97ca1e61c89db6288d940138080fa335613c792` |
| TLSH | `T13B26F203FB45DA87D8AA83F66F230DA919134F54C643BBE74461BA2D2D772D04DC6A8C` |
| SSDEEP | `98304:ngHFcAOApnaqmcVyyYmzbzB/T10t0q1Ku:ngWzApaaVhnzhKdP` |

#### Technical Assessment

- The sample is tracked as `SpyNote` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SpyNote_099_272248f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
    family = "SpyNote"
    file_name = "Blockchain(1).apk"
    file_type = "apk"
    first_seen = "2026-06-27 18:49:18"
  condition:
    hash.sha256(0, filesize) == "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
}
```

### Sample 100: `4ed6520516e5f756`

| Field | Value |
|---|---|
| SHA-256 | `4ed6520516e5f756f1d020510d5e508c03811b3cb5062eed4bede73df641b779` |
| Family label | `unknown` |
| File name | `Figural.exe` |
| File type | `exe` |
| First seen | `2026-06-27 18:46:23` |
| Reporter | `burger403` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77ac1472bfb41dcc80e160bc87691abc` |
| SHA-1 | `30f5f001631cb48f37b684fcbb7791976dbdadb2` |
| SHA-256 | `4ed6520516e5f756f1d020510d5e508c03811b3cb5062eed4bede73df641b779` |
| SHA3-384 | `b59307160622d1cdc834cde87910369b8ebce09ea7ef5ee8120b75685c979f3301724522fd3c5e78717093a960b9ce13` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T162F58C07BC9148F9C099A33188B792967B71BC190B3127D72E60B7782FB27D05DB2799` |
| SSDEEP | `49152:Bh0uWUUWgoo/YWWZ+gc+dpT+MeD+g40SYoNEkY6g2JLJtU+WxfjdnegdDGYto3e:BaUZT+9Dn4qAEQg2JlW+WxfjdndIdO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_4ed65205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ed6520516e5f756f1d020510d5e508c03811b3cb5062eed4bede73df641b779"
    family = "unknown"
    file_name = "Figural.exe"
    file_type = "exe"
    first_seen = "2026-06-27 18:46:23"
  condition:
    hash.sha256(0, filesize) == "4ed6520516e5f756f1d020510d5e508c03811b3cb5062eed4bede73df641b779"
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
 * Generated: 2026-06-28T04:55:39.572424+00:00
 */

rule MalwareBazaar_Amadey_001_c942ecd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a"
    family = "Amadey"
    file_name = "C1CDA5F5016B812993DD4858FA6FB949.exe"
    file_type = "exe"
    first_seen = "2026-06-28 04:45:07"
  condition:
    hash.sha256(0, filesize) == "c942ecd62cc2de17119903a9adb79dc9a382136288a2a5e9385e856a668a3d7a"
}

rule MalwareBazaar_Mirai_002_ae6e5050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae6e5050df886ebe8d391f43c8b97dac2ca4e1b1de6e3021f573ca1dd3a62999"
    family = "Mirai"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:40"
  condition:
    hash.sha256(0, filesize) == "ae6e5050df886ebe8d391f43c8b97dac2ca4e1b1de6e3021f573ca1dd3a62999"
}

rule MalwareBazaar_Mirai_003_e8ddc81d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8ddc81d5b7fbc3585ae8bdfeb22d612eee224bc58a967eb7c40b9a2a9dccd85"
    family = "Mirai"
    file_name = "flutter.x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:38"
  condition:
    hash.sha256(0, filesize) == "e8ddc81d5b7fbc3585ae8bdfeb22d612eee224bc58a967eb7c40b9a2a9dccd85"
}

rule MalwareBazaar_Mirai_004_e7cfc962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7cfc962d32487c62508734bdfa918dd7f7faa9d812f71b1ad56b6788dc4bb3b"
    family = "Mirai"
    file_name = "flutter.mipsel"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:01"
  condition:
    hash.sha256(0, filesize) == "e7cfc962d32487c62508734bdfa918dd7f7faa9d812f71b1ad56b6788dc4bb3b"
}

rule MalwareBazaar_Mirai_005_05a2e838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a2e838e3fcc27b6dbd536d0c123d52e25b341464ed8b38f892f38d38fa6cfa"
    family = "Mirai"
    file_name = "flutter.x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 03:52:00"
  condition:
    hash.sha256(0, filesize) == "05a2e838e3fcc27b6dbd536d0c123d52e25b341464ed8b38f892f38d38fa6cfa"
}

rule MalwareBazaar_Mirai_006_7b2a7175
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b2a71759e42740089ac9081f749d854b8d9132eab7e2edbef22279e0c2e8dcf"
    family = "Mirai"
    file_name = "flutter.m68k"
    file_type = "elf"
    first_seen = "2026-06-28 03:51:59"
  condition:
    hash.sha256(0, filesize) == "7b2a71759e42740089ac9081f749d854b8d9132eab7e2edbef22279e0c2e8dcf"
}

rule MalwareBazaar_Mirai_007_5a9f6ea3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a9f6ea331964b80df719baa5b14a15ffd5a326cc32dd4849638443e76b8f65a"
    family = "Mirai"
    file_name = "flutter.arm8"
    file_type = "elf"
    first_seen = "2026-06-28 03:51:42"
  condition:
    hash.sha256(0, filesize) == "5a9f6ea331964b80df719baa5b14a15ffd5a326cc32dd4849638443e76b8f65a"
}

rule MalwareBazaar_Mirai_008_26a65e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a65e84c4ed6721d591f8c50676405bd240198185891773be2b7855e9f95133"
    family = "Mirai"
    file_name = "flutter.arm8"
    file_type = "elf"
    first_seen = "2026-06-28 03:51:00"
  condition:
    hash.sha256(0, filesize) == "26a65e84c4ed6721d591f8c50676405bd240198185891773be2b7855e9f95133"
}

rule MalwareBazaar_Mirai_009_89a8132e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89a8132ebca5b6de89c9890a5e911883c2e0b58216161705eb6042a6ebb9b775"
    family = "Mirai"
    file_name = "flutter.ppc"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:51"
  condition:
    hash.sha256(0, filesize) == "89a8132ebca5b6de89c9890a5e911883c2e0b58216161705eb6042a6ebb9b775"
}

rule MalwareBazaar_Mirai_010_04e16f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04e16f35916321dab115dab2fd960623dc43e29f2c24f2094b492e5b48ffb8c8"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:48"
  condition:
    hash.sha256(0, filesize) == "04e16f35916321dab115dab2fd960623dc43e29f2c24f2094b492e5b48ffb8c8"
}

rule MalwareBazaar_Mirai_011_4229febb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4229febbc3cd893a2010b1d4a4174c9faac5a086973ffcc639d6f8ea9bee2c1b"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:45"
  condition:
    hash.sha256(0, filesize) == "4229febbc3cd893a2010b1d4a4174c9faac5a086973ffcc639d6f8ea9bee2c1b"
}

rule MalwareBazaar_Mirai_012_d6262ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6262ccd82f491d10bc9b8e5c6eb30f57c67c186b5cbc21766f1ad903f837b1d"
    family = "Mirai"
    file_name = "flutter.ppc"
    file_type = "elf"
    first_seen = "2026-06-28 03:50:00"
  condition:
    hash.sha256(0, filesize) == "d6262ccd82f491d10bc9b8e5c6eb30f57c67c186b5cbc21766f1ad903f837b1d"
}

rule MalwareBazaar_Mirai_013_03dea2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03dea2fdbbece0bb95bcc7d1d0e46878d55f666efb087184a9a2bdde79cec5a2"
    family = "Mirai"
    file_name = "flutter.mips"
    file_type = "elf"
    first_seen = "2026-06-28 03:49:58"
  condition:
    hash.sha256(0, filesize) == "03dea2fdbbece0bb95bcc7d1d0e46878d55f666efb087184a9a2bdde79cec5a2"
}

rule MalwareBazaar_Mirai_014_eb413a52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb413a52665242534572609a704d17b990599e3ace305d2abaeda555c9762ace"
    family = "Mirai"
    file_name = "flutter.x86"
    file_type = "elf"
    first_seen = "2026-06-28 03:49:57"
  condition:
    hash.sha256(0, filesize) == "eb413a52665242534572609a704d17b990599e3ace305d2abaeda555c9762ace"
}

rule MalwareBazaar_Gafgyt_015_e7730ccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7730ccf5bfcb40df1c54f1600cdee4c0c56cb88fdcc6ae9c338d36a1a7f994d"
    family = "Gafgyt"
    file_name = "m-6.8-k.Sakura"
    file_type = "elf"
    first_seen = "2026-06-28 03:29:59"
  condition:
    hash.sha256(0, filesize) == "e7730ccf5bfcb40df1c54f1600cdee4c0c56cb88fdcc6ae9c338d36a1a7f994d"
}

rule MalwareBazaar_Gafgyt_016_239adbe2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239adbe22edee724d96e4b5fe0f4a7213c8eba6dba33ff938340dd33aaa08ad6"
    family = "Gafgyt"
    file_name = "m-i.p-s.Sakura"
    file_type = "elf"
    first_seen = "2026-06-28 03:29:57"
  condition:
    hash.sha256(0, filesize) == "239adbe22edee724d96e4b5fe0f4a7213c8eba6dba33ff938340dd33aaa08ad6"
}

rule MalwareBazaar_Mirai_017_3bbcf698
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bbcf6984724e025180a86a790ff6e7fb442c4e66e0eb0518e2c553a2e698322"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-06-28 03:29:56"
  condition:
    hash.sha256(0, filesize) == "3bbcf6984724e025180a86a790ff6e7fb442c4e66e0eb0518e2c553a2e698322"
}

rule MalwareBazaar_Mirai_018_4b516f50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b516f504ee1a53a1056067398e231cf2a0011152335e06d680cc0876ec30383"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:08"
  condition:
    hash.sha256(0, filesize) == "4b516f504ee1a53a1056067398e231cf2a0011152335e06d680cc0876ec30383"
}

rule MalwareBazaar_Mirai_019_a0ac62b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0ac62b9a8c8f2bdebbeffa5ea6ba90c88d07f595fe1b39ff11d521ddb881a99"
    family = "Mirai"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:06"
  condition:
    hash.sha256(0, filesize) == "a0ac62b9a8c8f2bdebbeffa5ea6ba90c88d07f595fe1b39ff11d521ddb881a99"
}

rule MalwareBazaar_Mirai_020_d4da3598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4da359838c9d2f850f5b51266b5870ad82b7f1ebfea60baa81d7058dd4429da"
    family = "Mirai"
    file_name = "mipsle"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:04"
  condition:
    hash.sha256(0, filesize) == "d4da359838c9d2f850f5b51266b5870ad82b7f1ebfea60baa81d7058dd4429da"
}

rule MalwareBazaar_Mirai_021_1a7c957b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a7c957b107b4eccfe3c079472b457fd3c13068bc6b65c69c1bdf536d353bf8a"
    family = "Mirai"
    file_name = "arm64"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:02"
  condition:
    hash.sha256(0, filesize) == "1a7c957b107b4eccfe3c079472b457fd3c13068bc6b65c69c1bdf536d353bf8a"
}

rule MalwareBazaar_Mirai_022_546c20af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "546c20af1d14d8f69618c0d3a1696b0815a1b0cec1a3c351f516a66cb781cfe1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-28 03:19:01"
  condition:
    hash.sha256(0, filesize) == "546c20af1d14d8f69618c0d3a1696b0815a1b0cec1a3c351f516a66cb781cfe1"
}

rule MalwareBazaar_Mirai_023_db11e9ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db11e9ffefc70af6f51b4ffd4c0d127d0dd075667b62a48c095a211c4364c41d"
    family = "Mirai"
    file_name = "i386"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:59"
  condition:
    hash.sha256(0, filesize) == "db11e9ffefc70af6f51b4ffd4c0d127d0dd075667b62a48c095a211c4364c41d"
}

rule MalwareBazaar_Mirai_024_ddcb3dde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddcb3ddec77d47804ea560d2ac6459925d85236a52854fd7106653c41128e49f"
    family = "Mirai"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:57"
  condition:
    hash.sha256(0, filesize) == "ddcb3ddec77d47804ea560d2ac6459925d85236a52854fd7106653c41128e49f"
}

rule MalwareBazaar_Mirai_025_e3e4beba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3e4bebafddb63fee04a5e6dce99f4f2188115282794b6166865b38acd9cc7d2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:56"
  condition:
    hash.sha256(0, filesize) == "e3e4bebafddb63fee04a5e6dce99f4f2188115282794b6166865b38acd9cc7d2"
}

rule MalwareBazaar_Mirai_026_21d69613
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d6961360c9607230396b4458990f1816cfa4608bc2f1d943f2ddbcd003de70"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-28 03:18:54"
  condition:
    hash.sha256(0, filesize) == "21d6961360c9607230396b4458990f1816cfa4608bc2f1d943f2ddbcd003de70"
}

rule MalwareBazaar_unknown_027_a5602dae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5602dae7c1e216851e295865023239476ed76677abf46ec7626a17cd2ae29b4"
    family = "unknown"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-06-28 03:18:52"
  condition:
    hash.sha256(0, filesize) == "a5602dae7c1e216851e295865023239476ed76677abf46ec7626a17cd2ae29b4"
}

rule MalwareBazaar_unknown_028_33a7648c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb"
    family = "unknown"
    file_name = "loader.ps1.bin"
    file_type = "unknown"
    first_seen = "2026-06-28 03:00:21"
  condition:
    hash.sha256(0, filesize) == "33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb"
}

rule MalwareBazaar_unknown_029_b2687e64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-28 02:30:56"
  condition:
    hash.sha256(0, filesize) == "b2687e641c114589ef0f3e96abb7bdf5758009b72a0ef74f2e7f30fafe7bebe7"
}

rule MalwareBazaar_unknown_030_8d813de0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d813de09c2124bfd87ea963b031730e10bd646817cecdb5195c829c3c34d6a9"
    family = "unknown"
    file_name = "a-software85659006.msi"
    file_type = "msi"
    first_seen = "2026-06-28 02:24:32"
  condition:
    hash.sha256(0, filesize) == "8d813de09c2124bfd87ea963b031730e10bd646817cecdb5195c829c3c34d6a9"
}

rule MalwareBazaar_unknown_031_0cb1d362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cb1d3623ab8dd0e3647a6769fc9d793499745e055a8d5c90a1ce97ba7de14fd"
    family = "unknown"
    file_name = "ToDesk_Lite-x64.6.3.4.msi"
    file_type = "msi"
    first_seen = "2026-06-28 02:20:57"
  condition:
    hash.sha256(0, filesize) == "0cb1d3623ab8dd0e3647a6769fc9d793499745e055a8d5c90a1ce97ba7de14fd"
}

rule MalwareBazaar_Mirai_032_c7837a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7837a865e34ae9a115b9cdfb9936d5061aacd9a86e6a6dff8b6dd4c935d6cf7"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-28 02:07:37"
  condition:
    hash.sha256(0, filesize) == "c7837a865e34ae9a115b9cdfb9936d5061aacd9a86e6a6dff8b6dd4c935d6cf7"
}

rule MalwareBazaar_Mirai_033_18e57f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18e57f5792c996a533aed3495be74f7d8a25ca7a14ac57b56ef0f3bb05505a7d"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-28 02:06:54"
  condition:
    hash.sha256(0, filesize) == "18e57f5792c996a533aed3495be74f7d8a25ca7a14ac57b56ef0f3bb05505a7d"
}

rule MalwareBazaar_unknown_034_c6602068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6602068b4191601bb51b98dea88e2550ac0bc17bee7d379cfc858158c0002eb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-28 01:50:28"
  condition:
    hash.sha256(0, filesize) == "c6602068b4191601bb51b98dea88e2550ac0bc17bee7d379cfc858158c0002eb"
}

rule MalwareBazaar_unknown_035_753051a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "753051a16244348c18597a80f5d8e67da310b95159fb366da0c43a8ddc026964"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-06-28 01:41:55"
  condition:
    hash.sha256(0, filesize) == "753051a16244348c18597a80f5d8e67da310b95159fb366da0c43a8ddc026964"
}

rule MalwareBazaar_unknown_036_8407c98a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8407c98a0f164463bdc7bcb7e3b022943f64d63539c8fae52c968a1e0112488d"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 01:39:44"
  condition:
    hash.sha256(0, filesize) == "8407c98a0f164463bdc7bcb7e3b022943f64d63539c8fae52c968a1e0112488d"
}

rule MalwareBazaar_unknown_037_2694e1c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2694e1c42f62687ca9d1472dc9091a02870b589791b52ff3700755fea59afb1a"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-28 01:38:55"
  condition:
    hash.sha256(0, filesize) == "2694e1c42f62687ca9d1472dc9091a02870b589791b52ff3700755fea59afb1a"
}

rule MalwareBazaar_unknown_038_cd85f90e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd85f90ee6a46a3e2dcca1233164f584ff018ff552b12a9e8f20eaaf761a29a1"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-28 01:33:56"
  condition:
    hash.sha256(0, filesize) == "cd85f90ee6a46a3e2dcca1233164f584ff018ff552b12a9e8f20eaaf761a29a1"
}

rule MalwareBazaar_unknown_039_6ebaaf79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481"
    family = "unknown"
    file_name = "6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481"
    file_type = "elf"
    first_seen = "2026-06-28 01:30:59"
  condition:
    hash.sha256(0, filesize) == "6ebaaf79e390b965a2112f43970a43e609aa090daf1131235bb59064b5cdf481"
}

rule MalwareBazaar_Mirai_040_eceff5fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eceff5fd41901d2f9093ffe8169f0ab1105ec0fe7962f55774ea70f24c408764"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-06-28 01:27:39"
  condition:
    hash.sha256(0, filesize) == "eceff5fd41901d2f9093ffe8169f0ab1105ec0fe7962f55774ea70f24c408764"
}

rule MalwareBazaar_Mirai_041_b297c3b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b297c3b865947f137c50f4f3e8a4b7f20b3af3fb0e52cbda642801880f9e628e"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-06-28 01:26:53"
  condition:
    hash.sha256(0, filesize) == "b297c3b865947f137c50f4f3e8a4b7f20b3af3fb0e52cbda642801880f9e628e"
}

rule MalwareBazaar_Mirai_042_31c641e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31c641e51200fd891fe6e6608ad2889fa7146b51369a5bb3fe244332cc82815f"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-06-28 01:25:51"
  condition:
    hash.sha256(0, filesize) == "31c641e51200fd891fe6e6608ad2889fa7146b51369a5bb3fe244332cc82815f"
}

rule MalwareBazaar_Mirai_043_3ffe7fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ffe7fe3ca5717478de826b6962a22f8519d2da4def748965c80d6ee870e01f7"
    family = "Mirai"
    file_name = "flutter.arm"
    file_type = "elf"
    first_seen = "2026-06-28 01:24:57"
  condition:
    hash.sha256(0, filesize) == "3ffe7fe3ca5717478de826b6962a22f8519d2da4def748965c80d6ee870e01f7"
}

rule MalwareBazaar_Mirai_044_af45b4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af45b4a994b7ba7693494d211215eaaa05b787ccc156ec55e5354838af23b5aa"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-06-28 01:24:43"
  condition:
    hash.sha256(0, filesize) == "af45b4a994b7ba7693494d211215eaaa05b787ccc156ec55e5354838af23b5aa"
}

rule MalwareBazaar_Mirai_045_3e336766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e336766f450f868f7b36e0be3396a951cb0f22dec16cc92b2c7a747700d84eb"
    family = "Mirai"
    file_name = "flutter.arm7"
    file_type = "elf"
    first_seen = "2026-06-28 01:23:52"
  condition:
    hash.sha256(0, filesize) == "3e336766f450f868f7b36e0be3396a951cb0f22dec16cc92b2c7a747700d84eb"
}

rule MalwareBazaar_Mirai_046_b0a25362
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0a253629dadae80bc5d044a067fccb25a50e8e3bb930cecfd4e38f6cf6d2d60"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-28 01:23:43"
  condition:
    hash.sha256(0, filesize) == "b0a253629dadae80bc5d044a067fccb25a50e8e3bb930cecfd4e38f6cf6d2d60"
}

rule MalwareBazaar_Mirai_047_a411da26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a411da26aece6d7c9a9794e44f961a801cf4c95c94986f4f469adc4ad709fdd0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-28 01:22:52"
  condition:
    hash.sha256(0, filesize) == "a411da26aece6d7c9a9794e44f961a801cf4c95c94986f4f469adc4ad709fdd0"
}

rule MalwareBazaar_Mirai_048_f24d98c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f24d98c1da244874ad27ae9e19a0756e6a9792ade59803e76cff96159a1a8217"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-28 01:17:52"
  condition:
    hash.sha256(0, filesize) == "f24d98c1da244874ad27ae9e19a0756e6a9792ade59803e76cff96159a1a8217"
}

rule MalwareBazaar_Mirai_049_d563826f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d563826f5c0f4722275246f7f09177380fe27f8be837c353552ca936eda55490"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-28 01:17:36"
  condition:
    hash.sha256(0, filesize) == "d563826f5c0f4722275246f7f09177380fe27f8be837c353552ca936eda55490"
}

rule MalwareBazaar_Mirai_050_46d8fb86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46d8fb86f41800a8917c7f16d445d02df1f56b31201bb682d64c2b9ff9bfa7bb"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-28 01:16:51"
  condition:
    hash.sha256(0, filesize) == "46d8fb86f41800a8917c7f16d445d02df1f56b31201bb682d64c2b9ff9bfa7bb"
}

rule MalwareBazaar_unknown_051_2e9791b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e9791b87a76ce5706b74e83cae2bdc05e34d8ffc0f494e9390f12320edf4043"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-28 01:13:50"
  condition:
    hash.sha256(0, filesize) == "2e9791b87a76ce5706b74e83cae2bdc05e34d8ffc0f494e9390f12320edf4043"
}

rule MalwareBazaar_Mirai_052_812dbaea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "812dbaead239dc87437196510043e1058f1656747d9bcd886a77594e3e654652"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-06-28 01:03:54"
  condition:
    hash.sha256(0, filesize) == "812dbaead239dc87437196510043e1058f1656747d9bcd886a77594e3e654652"
}

rule MalwareBazaar_Mirai_053_ec4f37c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec4f37c2d5a1b9fb472634accb1a2d28ade5db8f9d4d2d43e23adce6514331b7"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-06-28 01:01:32"
  condition:
    hash.sha256(0, filesize) == "ec4f37c2d5a1b9fb472634accb1a2d28ade5db8f9d4d2d43e23adce6514331b7"
}

rule MalwareBazaar_Mirai_054_07ea890e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07ea890e0a1008446889251a0553428a54786ffd9b1b870d8f7730f0a6fdb306"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-06-28 00:59:49"
  condition:
    hash.sha256(0, filesize) == "07ea890e0a1008446889251a0553428a54786ffd9b1b870d8f7730f0a6fdb306"
}

rule MalwareBazaar_BlankGrabber_055_e207ce6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e207ce6f845f84bd247294390e12fd94df499436b8170ec143266405735d36fe"
    family = "BlankGrabber"
    file_name = "Built.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:53:29"
  condition:
    hash.sha256(0, filesize) == "e207ce6f845f84bd247294390e12fd94df499436b8170ec143266405735d36fe"
}

rule MalwareBazaar_unknown_056_3eb43078
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eb43078cc25cfea4841533828fe136064eb151a93e8418f120a439cde3a1771"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-28 00:52:51"
  condition:
    hash.sha256(0, filesize) == "3eb43078cc25cfea4841533828fe136064eb151a93e8418f120a439cde3a1771"
}

rule MalwareBazaar_BlankGrabber_057_94dc6a52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94dc6a521549029a2bcd479bf04327518ea0cf0a3a4675d98cb421f256340122"
    family = "BlankGrabber"
    file_name = "XwormV5.6.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:44:38"
  condition:
    hash.sha256(0, filesize) == "94dc6a521549029a2bcd479bf04327518ea0cf0a3a4675d98cb421f256340122"
}

rule MalwareBazaar_Mirai_058_2ba98395
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ba98395b64bda94951e71b30d6ccfb368bec76c87562e4c007cd4a2a99e65e1"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-28 00:44:31"
  condition:
    hash.sha256(0, filesize) == "2ba98395b64bda94951e71b30d6ccfb368bec76c87562e4c007cd4a2a99e65e1"
}

rule MalwareBazaar_Mirai_059_625f745a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "625f745adbc6acebe0c96b0ece72256a8559f0684f7abfbbc69bd55cbb873e48"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-28 00:43:51"
  condition:
    hash.sha256(0, filesize) == "625f745adbc6acebe0c96b0ece72256a8559f0684f7abfbbc69bd55cbb873e48"
}

rule MalwareBazaar_unknown_060_542ab12e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "542ab12e9aa46a0a19d380e7390a84c4628c7316cb7a4bd01a85a8b3a45ca421"
    family = "unknown"
    file_name = "testss.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:39:51"
  condition:
    hash.sha256(0, filesize) == "542ab12e9aa46a0a19d380e7390a84c4628c7316cb7a4bd01a85a8b3a45ca421"
}

rule MalwareBazaar_unknown_061_8bdb9e27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bdb9e2799855cf53e619fc7f1f0c584de8f362f8f7bf050862ca273e3a637b7"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-28 00:38:37"
  condition:
    hash.sha256(0, filesize) == "8bdb9e2799855cf53e619fc7f1f0c584de8f362f8f7bf050862ca273e3a637b7"
}

rule MalwareBazaar_unknown_062_82fa4a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82fa4a260074ef98be4f2c8a925f9bb6ac91dcac44b69ba3c4a00116b308c729"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-28 00:37:53"
  condition:
    hash.sha256(0, filesize) == "82fa4a260074ef98be4f2c8a925f9bb6ac91dcac44b69ba3c4a00116b308c729"
}

rule MalwareBazaar_BlankGrabber_063_8928d35f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8928d35f3e18435f6c17940a5a9a2515186b5a7a4faa6f681b7d244249daaf0b"
    family = "BlankGrabber"
    file_name = "BTCMiner.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:29:38"
  condition:
    hash.sha256(0, filesize) == "8928d35f3e18435f6c17940a5a9a2515186b5a7a4faa6f681b7d244249daaf0b"
}

rule MalwareBazaar_njrat_064_39cbd2d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13"
    family = "njrat"
    file_name = "390929763242f8f854188b405ac7f5ba.exe"
    file_type = "exe"
    first_seen = "2026-06-28 00:25:05"
  condition:
    hash.sha256(0, filesize) == "39cbd2d2299ebbc1eba6bb1ffab7d87f0016715fb237d0a1a253262b4b9cea13"
}

rule MalwareBazaar_Mirai_065_5eafce5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5eafce5d6fadad40b6aa6f7a58da86bbbd29dba0d84c259dbc41c7671ade913c"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-28 00:24:54"
  condition:
    hash.sha256(0, filesize) == "5eafce5d6fadad40b6aa6f7a58da86bbbd29dba0d84c259dbc41c7671ade913c"
}

rule MalwareBazaar_Mirai_066_a189a81a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a189a81a9ac39f9887765a17135a2bf58bbe130ac3e382d2e2e0a3228ca168c8"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-28 00:15:56"
  condition:
    hash.sha256(0, filesize) == "a189a81a9ac39f9887765a17135a2bf58bbe130ac3e382d2e2e0a3228ca168c8"
}

rule MalwareBazaar_Mirai_067_09222564
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "092225646fba47f7bd157d451211304cf051ed40f6aa10add4013a69d219ac17"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-28 00:14:49"
  condition:
    hash.sha256(0, filesize) == "092225646fba47f7bd157d451211304cf051ed40f6aa10add4013a69d219ac17"
}

rule MalwareBazaar_Mirai_068_d49b639c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d49b639c54393dd608257e4e7435c60c3aed12f2aba55e22c301341cba167441"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-28 00:14:35"
  condition:
    hash.sha256(0, filesize) == "d49b639c54393dd608257e4e7435c60c3aed12f2aba55e22c301341cba167441"
}

rule MalwareBazaar_Mirai_069_ff458378
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff4583784bf6ed24d9ad5c4d30fcba28c17b6d4e6a01ce0f3bb456449e663d6d"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-28 00:13:51"
  condition:
    hash.sha256(0, filesize) == "ff4583784bf6ed24d9ad5c4d30fcba28c17b6d4e6a01ce0f3bb456449e663d6d"
}

rule MalwareBazaar_unknown_070_22d30cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2"
    family = "unknown"
    file_name = "22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2"
    file_type = "sh"
    first_seen = "2026-06-27 23:53:15"
  condition:
    hash.sha256(0, filesize) == "22d30cf7238704569864e016ff5d4fe72d737485320ea423c8e7453605e6a9f2"
}

rule MalwareBazaar_unknown_071_2f7e04dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f7e04dd499107fcbcd124d859bbe3d4479b1e7acf2b1c05daff57c9a8a4b0f0"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win64.Malware-gen.85337721"
    file_type = "exe"
    first_seen = "2026-06-27 23:45:32"
  condition:
    hash.sha256(0, filesize) == "2f7e04dd499107fcbcd124d859bbe3d4479b1e7acf2b1c05daff57c9a8a4b0f0"
}

rule MalwareBazaar_unknown_072_8ba894b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb"
    family = "unknown"
    file_name = "8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb"
    file_type = "elf"
    first_seen = "2026-06-27 21:52:13"
  condition:
    hash.sha256(0, filesize) == "8ba894b2cdc50ad8abc2b462a923f9506d9ad6b504583d29517a26f2107abeeb"
}

rule MalwareBazaar_unknown_073_2dd4175f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16"
    family = "unknown"
    file_name = "2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16"
    file_type = "elf"
    first_seen = "2026-06-27 21:40:25"
  condition:
    hash.sha256(0, filesize) == "2dd4175fc20d38e51eb59f0ee324618bc2b29caf10a3f11e41c12391976a7f16"
}

rule MalwareBazaar_unknown_074_848d134c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275"
    family = "unknown"
    file_name = "848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275"
    file_type = "elf"
    first_seen = "2026-06-27 21:35:43"
  condition:
    hash.sha256(0, filesize) == "848d134ca9d68ba39e5a448af3235557cb1339f4d06b2e41bfcf381fd5cbb275"
}

rule MalwareBazaar_unknown_075_df1bb5c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df1bb5c2aac6220ca59bed32b53e02836ff53b6d732bd4a91c5252d507748d03"
    family = "unknown"
    file_name = "NetMedved_2.js"
    file_type = "js"
    first_seen = "2026-06-27 21:23:26"
  condition:
    hash.sha256(0, filesize) == "df1bb5c2aac6220ca59bed32b53e02836ff53b6d732bd4a91c5252d507748d03"
}

rule MalwareBazaar_unknown_076_d1e4c657
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1e4c6578b588e95d8ed03b46f2febc0ce2d5a8a8b612cafe640b6e23ba637d7"
    family = "unknown"
    file_name = "NetMedved_1.js"
    file_type = "js"
    first_seen = "2026-06-27 21:22:46"
  condition:
    hash.sha256(0, filesize) == "d1e4c6578b588e95d8ed03b46f2febc0ce2d5a8a8b612cafe640b6e23ba637d7"
}

rule MalwareBazaar_Socks5Systemz_077_716612c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716612c11982500cca51970f822ddffb5a4b3aa84fda3cb30ffab6daa94f5248"
    family = "Socks5Systemz"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 20:46:07"
  condition:
    hash.sha256(0, filesize) == "716612c11982500cca51970f822ddffb5a4b3aa84fda3cb30ffab6daa94f5248"
}

rule MalwareBazaar_unknown_078_94e03e46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94e03e46b656afa0d66f8d08ae08b21a3d96dda4cd3d51afd31c559f715b56db"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-06-27 20:20:56"
  condition:
    hash.sha256(0, filesize) == "94e03e46b656afa0d66f8d08ae08b21a3d96dda4cd3d51afd31c559f715b56db"
}

rule MalwareBazaar_Gafgyt_079_cee80861
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee808610a5064df4b156931891925432ebef98e64a79b9805c10a39b0b417dd"
    family = "Gafgyt"
    file_name = "a-r.m-7.Sakura"
    file_type = "elf"
    first_seen = "2026-06-27 20:10:53"
  condition:
    hash.sha256(0, filesize) == "cee808610a5064df4b156931891925432ebef98e64a79b9805c10a39b0b417dd"
}

rule MalwareBazaar_Mirai_080_f4940efc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4940efc61c20e2257dd53e13c57ddd99836022cfeeca3faa32c580b7b049173"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-27 20:08:51"
  condition:
    hash.sha256(0, filesize) == "f4940efc61c20e2257dd53e13c57ddd99836022cfeeca3faa32c580b7b049173"
}

rule MalwareBazaar_unknown_081_6f93534c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f93534ca2cf1260210d189cf8a8f955806651a5aa1cf0801bf5832e3f7b8a12"
    family = "unknown"
    file_name = "libdpt.so.elf"
    file_type = "elf"
    first_seen = "2026-06-27 20:03:40"
  condition:
    hash.sha256(0, filesize) == "6f93534ca2cf1260210d189cf8a8f955806651a5aa1cf0801bf5832e3f7b8a12"
}

rule MalwareBazaar_unknown_082_c0e4f1cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0e4f1cd9cad6fd1a8485c945bbd384c25a441225657d440b35b743a852627ab"
    family = "unknown"
    file_name = "libdpt.so.elf"
    file_type = "elf"
    first_seen = "2026-06-27 19:52:54"
  condition:
    hash.sha256(0, filesize) == "c0e4f1cd9cad6fd1a8485c945bbd384c25a441225657d440b35b743a852627ab"
}

rule MalwareBazaar_unknown_083_2b60ca11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b60ca11a172d02f1d9043e8f9c050d621aaf01ee81f9ab312a973777637dee3"
    family = "unknown"
    file_name = "4304-0.dex"
    file_type = "unknown"
    first_seen = "2026-06-27 19:52:39"
  condition:
    hash.sha256(0, filesize) == "2b60ca11a172d02f1d9043e8f9c050d621aaf01ee81f9ab312a973777637dee3"
}

rule MalwareBazaar_unknown_084_4b846be2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b846be26d903834219e4369bd48097e04642f5f4abaec582e3e73692947d4f0"
    family = "unknown"
    file_name = "i11111i111.zip"
    file_type = "unknown"
    first_seen = "2026-06-27 19:52:20"
  condition:
    hash.sha256(0, filesize) == "4b846be26d903834219e4369bd48097e04642f5f4abaec582e3e73692947d4f0"
}

rule MalwareBazaar_unknown_085_8ac21ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ac21ddc17f81979134b2a1e2d9aa191927239f55090eaf28d49a0297619e645"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-27 19:50:51"
  condition:
    hash.sha256(0, filesize) == "8ac21ddc17f81979134b2a1e2d9aa191927239f55090eaf28d49a0297619e645"
}

rule MalwareBazaar_unknown_086_23582660
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2358266014965da1fbcab4fff34a4d7c0d57e6582408ba48cc42c002f7370e2e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Siggen32.58893.30928.10542"
    file_type = "exe"
    first_seen = "2026-06-27 19:44:59"
  condition:
    hash.sha256(0, filesize) == "2358266014965da1fbcab4fff34a4d7c0d57e6582408ba48cc42c002f7370e2e"
}

rule MalwareBazaar_unknown_087_79ced052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79ced052ef336b98a3dd0b032e79dd2fb2e91c36d8cf0c0d55cf7a2c6cdcf37e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 19:43:34"
  condition:
    hash.sha256(0, filesize) == "79ced052ef336b98a3dd0b032e79dd2fb2e91c36d8cf0c0d55cf7a2c6cdcf37e"
}

rule MalwareBazaar_unknown_088_c9f0f887
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
    family = "unknown"
    file_name = "nested_app.apk"
    file_type = "apk"
    first_seen = "2026-06-27 19:43:16"
  condition:
    hash.sha256(0, filesize) == "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
}

rule MalwareBazaar_unknown_089_56e66ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e66ffef4ae328ebdf3539fb741410079a2acb6cb5e817c1d48aa537c478dcd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 19:42:53"
  condition:
    hash.sha256(0, filesize) == "56e66ffef4ae328ebdf3539fb741410079a2acb6cb5e817c1d48aa537c478dcd"
}

rule MalwareBazaar_unknown_090_a3fed15f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3fed15f05903e3bb645f059a65f5e56ffeab45ab02f535d6df263d4363a6628"
    family = "unknown"
    file_name = "mpclient.dll"
    file_type = "exe"
    first_seen = "2026-06-27 19:21:05"
  condition:
    hash.sha256(0, filesize) == "a3fed15f05903e3bb645f059a65f5e56ffeab45ab02f535d6df263d4363a6628"
}

rule MalwareBazaar_IRATA_091_8da70cdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
    family = "IRATA"
    file_name = "geeeh.25175.signed_signed.apk"
    file_type = "apk"
    first_seen = "2026-06-27 19:15:50"
  condition:
    hash.sha256(0, filesize) == "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
}

rule MalwareBazaar_unknown_092_d8cd89e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4"
    family = "unknown"
    file_name = "Strawberry.apk"
    file_type = "apk"
    first_seen = "2026-06-27 19:12:32"
  condition:
    hash.sha256(0, filesize) == "d8cd89e8f7eb14c50e25705fea6f34390ab18486f2d1cadd5e195b0e663672c4"
}

rule MalwareBazaar_unknown_093_cf827508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf827508b66b36fc399690492cd798751f99f9cbaf3319e08fd3e6f60ed9b507"
    family = "unknown"
    file_name = "Client.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:11:48"
  condition:
    hash.sha256(0, filesize) == "cf827508b66b36fc399690492cd798751f99f9cbaf3319e08fd3e6f60ed9b507"
}

rule MalwareBazaar_Vidar_094_abb0ddc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb0ddc5d6972b69a938f88cbc354dffbd14adcd13b8049e6654f51dd3f5836d"
    family = "Vidar"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:09:39"
  condition:
    hash.sha256(0, filesize) == "abb0ddc5d6972b69a938f88cbc354dffbd14adcd13b8049e6654f51dd3f5836d"
}

rule MalwareBazaar_unknown_095_4a465658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a465658121a15449fadbeed82d37c461e601ae45c08a3d6c992285d31ebf804"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:04:50"
  condition:
    hash.sha256(0, filesize) == "4a465658121a15449fadbeed82d37c461e601ae45c08a3d6c992285d31ebf804"
}

rule MalwareBazaar_unknown_096_e21f70ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e21f70aebb96b545be30ba9b92fb7a77321d78da5641ce9f4d7b3ab8f6d09e70"
    family = "unknown"
    file_name = "Loader.exe"
    file_type = "exe"
    first_seen = "2026-06-27 19:04:37"
  condition:
    hash.sha256(0, filesize) == "e21f70aebb96b545be30ba9b92fb7a77321d78da5641ce9f4d7b3ab8f6d09e70"
}

rule MalwareBazaar_SpyNote_097_ef94a5ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
    family = "SpyNote"
    file_name = "NightmareClient.apk"
    file_type = "apk"
    first_seen = "2026-06-27 18:49:48"
  condition:
    hash.sha256(0, filesize) == "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
}

rule MalwareBazaar_SpyNote_098_6db892bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210"
    family = "SpyNote"
    file_name = "client.apk"
    file_type = "apk"
    first_seen = "2026-06-27 18:49:24"
  condition:
    hash.sha256(0, filesize) == "6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210"
}

rule MalwareBazaar_SpyNote_099_272248f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
    family = "SpyNote"
    file_name = "Blockchain(1).apk"
    file_type = "apk"
    first_seen = "2026-06-27 18:49:18"
  condition:
    hash.sha256(0, filesize) == "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
}

rule MalwareBazaar_unknown_100_4ed65205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ed6520516e5f756f1d020510d5e508c03811b3cb5062eed4bede73df641b779"
    family = "unknown"
    file_name = "Figural.exe"
    file_type = "exe"
    first_seen = "2026-06-27 18:46:23"
  condition:
    hash.sha256(0, filesize) == "4ed6520516e5f756f1d020510d5e508c03811b3cb5062eed4bede73df641b779"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

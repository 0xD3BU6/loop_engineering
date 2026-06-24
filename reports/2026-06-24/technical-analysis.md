# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-24

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 648 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 648 |
| Unique family labels | 8 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 41 |
| Mirai | 40 |
| ConnectWise | 11 |
| WannaCry | 3 |
| NanoCore | 2 |
| DarkTortilla | 1 |
| AsyncRAT | 1 |
| QuasarRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 39 |
| exe | 30 |
| sh | 13 |
| xapk | 4 |
| dll | 3 |
| vbs | 3 |
| unknown | 2 |
| msi | 1 |
| js | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `608371b1c6e84d84`

| Field | Value |
|---|---|
| SHA-256 | `608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d` |
| Family label | `unknown` |
| File name | `608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d` |
| File type | `exe` |
| First seen | `2026-06-24 04:15:21` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fb6b9dd2161f01c58080049750fd143` |
| SHA-1 | `cc91b5e01b25e38514188ca559c105f1ba74018e` |
| SHA-256 | `608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d` |
| SHA3-384 | `1f0079fa88f2ed2cbc237ef869fbf64ab0fc7830647fe2400f96b29cd77acd273698f84c540b688d1ada8c151a6aeab2` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1EB36121861F41278F27357B658EBDE13E671B857A5218E4F0752028A0C23F62DE96F3E` |
| SSDEEP | `49152:jn2nAQqMSPbcBVQej/1INRx+TSqTdVyAH1plAH:DyDqPoBhz1aRxcSU7yAVp2H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_608371b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d"
    family = "unknown"
    file_name = "608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d"
    file_type = "exe"
    first_seen = "2026-06-24 04:15:21"
  condition:
    hash.sha256(0, filesize) == "608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d"
}
```

### Sample 2: `72a6442a7c3ba07e`

| Field | Value |
|---|---|
| SHA-256 | `72a6442a7c3ba07ea66f46472ac79a35b39a9d6311337eaffecd1eaa61aed3cf` |
| Family label | `unknown` |
| File name | `Storage+Junk+Clean_1.2.2.xapk` |
| File type | `xapk` |
| First seen | `2026-06-24 03:47:33` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb6a75a2d338ca7825aee04daf112360` |
| SHA-1 | `d506e4e0e67bdbd0eade26082872b7750b35b6dd` |
| SHA-256 | `72a6442a7c3ba07ea66f46472ac79a35b39a9d6311337eaffecd1eaa61aed3cf` |
| SHA3-384 | `584baf1a949f52f928885998413b13d65426510ce3516acd046997b6a8d31b27bd64bc4dc2875a94b2e25c3ffc608af3` |
| TLSH | `T1D5C6120EE70DD43ADEC5B53879290693361A6CD816A1C3AA1C21F614BFF36DC9B25BD0` |
| SSDEEP | `196608:dpJLj/xbQCf10J6j5yCHPIsaGEx6hChHbCeOsBarUJz1eX7G8aEx9:dpx/df10EHPI7XCAwpXazQ9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_72a6442a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72a6442a7c3ba07ea66f46472ac79a35b39a9d6311337eaffecd1eaa61aed3cf"
    family = "unknown"
    file_name = "Storage+Junk+Clean_1.2.2.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:47:33"
  condition:
    hash.sha256(0, filesize) == "72a6442a7c3ba07ea66f46472ac79a35b39a9d6311337eaffecd1eaa61aed3cf"
}
```

### Sample 3: `131d73baac6511df`

| Field | Value |
|---|---|
| SHA-256 | `131d73baac6511df4290684e7a935aa72627ec459b07b2c2fcbb3eda06e48b5b` |
| Family label | `unknown` |
| File name | `com.hdwall.coolwall.background_3.7.8.xapk` |
| File type | `xapk` |
| First seen | `2026-06-24 03:43:55` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35f7de6e75bc3b7b9bbebe5ed68a203d` |
| SHA-1 | `ea6d1a9b5c53f4477a6d50747d6075b7647f2a62` |
| SHA-256 | `131d73baac6511df4290684e7a935aa72627ec459b07b2c2fcbb3eda06e48b5b` |
| SHA3-384 | `f99f0a2aecc79625c9e7570c4d25a23930d97ac2327a92249ae8d859298a3abddde6342b5679b63163826f6c422988a9` |
| TLSH | `T10AF7E00C872CAB36FDDA647D5D656ADEF13D64704272C096D829E804F78E5E883B2783` |
| SSDEEP | `786432:0BkQUwSA2goIxKY02Am7dDaOcoLlyUj6adXsjvbt6Q8QRMKUK+4/i2510ZKpZ:MkJxS1KgBtZcAEOdXsL2QRHN+GDT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_131d73ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "131d73baac6511df4290684e7a935aa72627ec459b07b2c2fcbb3eda06e48b5b"
    family = "unknown"
    file_name = "com.hdwall.coolwall.background_3.7.8.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:43:55"
  condition:
    hash.sha256(0, filesize) == "131d73baac6511df4290684e7a935aa72627ec459b07b2c2fcbb3eda06e48b5b"
}
```

### Sample 4: `53ec3546057bc6ea`

| Field | Value |
|---|---|
| SHA-256 | `53ec3546057bc6eaffc0403fed417b9a3aecf31482456aacc1c6ef8f64449963` |
| Family label | `unknown` |
| File name | `com.placevt.junkcleaner_3.6.xapk` |
| File type | `xapk` |
| First seen | `2026-06-24 03:39:47` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56dccb2e418f5525eafc08dbe8982dd2` |
| SHA-1 | `deafd0def7abf9b445090dc9f6fb011212026cb9` |
| SHA-256 | `53ec3546057bc6eaffc0403fed417b9a3aecf31482456aacc1c6ef8f64449963` |
| SHA3-384 | `5f450a76a7e576a41f41bb04d26af6b5d3d197b3b0f7dd950dd10dcee116aaf41b117cb5e7cf8ba517d9f52a48251d51` |
| TLSH | `T1CA86129AF71CE03FDDB72832497A13225357240689939B83A914951CBDAB6CC5F2EFC4` |
| SSDEEP | `196608:pgqczMTy5QY3zWgh1Z6V8LFAWQEvwY8yiNS4SxN7EFF:pgvzMEvfLaRg2y8S7bgv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_53ec3546
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53ec3546057bc6eaffc0403fed417b9a3aecf31482456aacc1c6ef8f64449963"
    family = "unknown"
    file_name = "com.placevt.junkcleaner_3.6.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:39:47"
  condition:
    hash.sha256(0, filesize) == "53ec3546057bc6eaffc0403fed417b9a3aecf31482456aacc1c6ef8f64449963"
}
```

### Sample 5: `92b4d6b3527a78cc`

| Field | Value |
|---|---|
| SHA-256 | `92b4d6b3527a78cc2483f3a1f0cf30b849fc117272310fe85f1cef934914eaa7` |
| Family label | `unknown` |
| File name | `com.maxorbor.phonecleaner_4.3.xapk` |
| File type | `xapk` |
| First seen | `2026-06-24 03:38:52` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16a4c860b844f21e6f56ec6f5a8ce8a3` |
| SHA-1 | `0d504b3addbd85173e5522736bdf8fc5820c6fda` |
| SHA-256 | `92b4d6b3527a78cc2483f3a1f0cf30b849fc117272310fe85f1cef934914eaa7` |
| SHA3-384 | `dbf42d28739a60091663478eeaa9aa6a4f70db1854f7b418aba567291846489c6d64a567f6a0548c1f58298514adb025` |
| TLSH | `T160172397F70CD41FC87B74768E7A527202564D868A83EBA37514B32C29B35848F6AFC1` |
| SSDEEP | `393216:aHxJgPh5EujqLC+8KFEGZvLFCi0amYOh8wxOYziw8StFtf:CoZ5EIq++8cEm6E28wQC13` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_92b4d6b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92b4d6b3527a78cc2483f3a1f0cf30b849fc117272310fe85f1cef934914eaa7"
    family = "unknown"
    file_name = "com.maxorbor.phonecleaner_4.3.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:38:52"
  condition:
    hash.sha256(0, filesize) == "92b4d6b3527a78cc2483f3a1f0cf30b849fc117272310fe85f1cef934914eaa7"
}
```

### Sample 6: `1516ab566efef411`

| Field | Value |
|---|---|
| SHA-256 | `1516ab566efef411a809b5220ef748c79ee0199e2340b3576168204b59443bae` |
| Family label | `unknown` |
| File name | `a-software85659001.msi` |
| File type | `msi` |
| First seen | `2026-06-24 03:33:41` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcadcac14962ec276a96c5d172158e4e` |
| SHA-1 | `ebb64f7657d820fc2fd85f55e10565ad3e646cf1` |
| SHA-256 | `1516ab566efef411a809b5220ef748c79ee0199e2340b3576168204b59443bae` |
| SHA3-384 | `fca6a15a7718943d3155af08a5f651a7857aac2b4932e7e74d9b53ebc02abcd2370a2f167d6a7a84e25da7347731bed5` |
| TLSH | `T13866335679C75A34C04ECB71511A717E712D3FE2CE748D2263E8371C6E3292CA9BA362` |
| SSDEEP | `196608:ECHwLtZ++7CBWgyVo5wYCtj39iWtw9FkO4ByadB:ECHP4+5MtbcWt0P43` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_1516ab56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1516ab566efef411a809b5220ef748c79ee0199e2340b3576168204b59443bae"
    family = "unknown"
    file_name = "a-software85659001.msi"
    file_type = "msi"
    first_seen = "2026-06-24 03:33:41"
  condition:
    hash.sha256(0, filesize) == "1516ab566efef411a809b5220ef748c79ee0199e2340b3576168204b59443bae"
}
```

### Sample 7: `a9bf6b54b485f91e`

| Field | Value |
|---|---|
| SHA-256 | `a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950` |
| Family label | `unknown` |
| File name | `a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950` |
| File type | `exe` |
| First seen | `2026-06-24 03:15:34` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca75020407cd030a1f43a362b6f0f977` |
| SHA-1 | `34d0b2b1c8fb7a4cadf50602e01be5277f8a9a98` |
| SHA-256 | `a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950` |
| SHA3-384 | `2f41ecf59181f61a85109361106d69c90b149d304938bc3a0c81ee317154edcadf240bd4f7ec7f7ecb5980f5e0441096` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1BC36231A327C81FCD14A157894A38E25E3B3BC5A12BD870F9B5486271E13B90FB78B57` |
| SSDEEP | `24576:jbLg8bLguVQhfdmMSirYbcMNgef0QeQjGe6SASk+RdhAdmv:jnRnFQqMSPbcBVQeje6SAARdhnv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_a9bf6b54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950"
    family = "unknown"
    file_name = "a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950"
    file_type = "exe"
    first_seen = "2026-06-24 03:15:34"
  condition:
    hash.sha256(0, filesize) == "a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950"
}
```

### Sample 8: `e052bfab59ab1e07`

| Field | Value |
|---|---|
| SHA-256 | `e052bfab59ab1e074b7f2a998190e6d6094979bef2e93b59f32ffef096a24d83` |
| Family label | `unknown` |
| File name | `curl.sh` |
| File type | `sh` |
| First seen | `2026-06-24 02:12:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efc201a0642ae0c1a1733eebf9f92b9d` |
| SHA-1 | `e7114e32a05fcd1a8a286e175757f792a3fa21bd` |
| SHA-256 | `e052bfab59ab1e074b7f2a998190e6d6094979bef2e93b59f32ffef096a24d83` |
| SHA3-384 | `8c309ef78cd00d018e56a931f5333b28143e1d6d9f8bf3a9e365ebbdf4170a1c8f523bc10979c3a72e0e409e7fc2ed5b` |
| TLSH | `T1293158C822B017FBCED4DD527932E9EE606D84D7BE5758E4640884E36F886C5FC182A5` |
| SSDEEP | `24:VBvHBq25vFBMxqBCoBtBzBdT4qBxjB5B4b0BTf3ByqtBUgByUx3BpubW:rvhXd7MECcztds6x9f5tyUDycx8C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_e052bfab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e052bfab59ab1e074b7f2a998190e6d6094979bef2e93b59f32ffef096a24d83"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-06-24 02:12:07"
  condition:
    hash.sha256(0, filesize) == "e052bfab59ab1e074b7f2a998190e6d6094979bef2e93b59f32ffef096a24d83"
}
```

### Sample 9: `752faadcef0c8a53`

| Field | Value |
|---|---|
| SHA-256 | `752faadcef0c8a53370583cddec408b88b0922655e260d424763ce00f08b91d4` |
| Family label | `NanoCore` |
| File name | `mhsra.com.exe` |
| File type | `exe` |
| First seen | `2026-06-24 02:10:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d92ecbd69ae37ca0ac56a79b9c0521c7` |
| SHA-1 | `5caecdcb05e70f0e314f74577403a8092847298b` |
| SHA-256 | `752faadcef0c8a53370583cddec408b88b0922655e260d424763ce00f08b91d4` |
| SHA3-384 | `a4501937b9a3563ecf39553cdb377de45008050810bef01f03d40e98542ea651cee42e02c118ffe04ad7594370a2bf70` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15C14D0563BA84A2FE2DE8579712212139379C2E3E8C3F3DE28E451B64F567E50A071D3` |
| SSDEEP | `3072:szEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HILmsC6wwBLsjAIZnB/nFgMbszL:sLV6Bta6dtJmakIM5r+LsjAcW/zhIRU` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_009_752faadc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "752faadcef0c8a53370583cddec408b88b0922655e260d424763ce00f08b91d4"
    family = "NanoCore"
    file_name = "mhsra.com.exe"
    file_type = "exe"
    first_seen = "2026-06-24 02:10:04"
  condition:
    hash.sha256(0, filesize) == "752faadcef0c8a53370583cddec408b88b0922655e260d424763ce00f08b91d4"
}
```

### Sample 10: `16c0a0857c5fdb37`

| Field | Value |
|---|---|
| SHA-256 | `16c0a0857c5fdb37fa92edc3ab802e6581875bdd24cb1a29b2004a9f67b79b38` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-06-24 01:19:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4299d55019ea2f9418df9c46631effbb` |
| SHA-1 | `a1a2cb10e81207bb29dbaa1b7d71fc0503670587` |
| SHA-256 | `16c0a0857c5fdb37fa92edc3ab802e6581875bdd24cb1a29b2004a9f67b79b38` |
| SHA3-384 | `ef5b79859a1f564749de91c023c3446d4c5c81ee81a79a247861982d0a3db39a5cffc03b71a157b8f9278c1c5e4cdec3` |
| TLSH | `T12634C51F6E228F6EF269C73447F78D35976C23D622E1D685D2ACC2105E6038E541FBA8` |
| TELFHASH | `t1844192580db813e4a6256c5d489dff2bd6a330db7e162c238e11e86ee769f839d14c1c` |
| SSDEEP | `3072:KKIjEWQezL9UzvcICyDTAUCBdP6BNYEB5T+aApoawco0:KKIY9OL9UDc1TCBz5bApf40` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_16c0a085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16c0a0857c5fdb37fa92edc3ab802e6581875bdd24cb1a29b2004a9f67b79b38"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-06-24 01:19:55"
  condition:
    hash.sha256(0, filesize) == "16c0a0857c5fdb37fa92edc3ab802e6581875bdd24cb1a29b2004a9f67b79b38"
}
```

### Sample 11: `eda8c3988086e3f7`

| Field | Value |
|---|---|
| SHA-256 | `eda8c3988086e3f74102f462592383be649059aa3599d1ad46808db223cff58c` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-06-24 01:16:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf30bb430428b0b15a4bdbf8c90789cb` |
| SHA-1 | `6bb2716ba9ba43db5f91f17e9f23ee580bfa2297` |
| SHA-256 | `eda8c3988086e3f74102f462592383be649059aa3599d1ad46808db223cff58c` |
| SHA3-384 | `2dabcecc791efc43416f78e36639a4c09480aad3dfcda462fe53c2a0132ddcda5b2d7eb652e1ea934bcc51f39cccbce1` |
| TLSH | `T13334090AAB610EFBDC6BDD3701E90B0524CCA41722A53F7A7674D918F94A64F4AD3C78` |
| SSDEEP | `3072:IzuE6qylVLaaWsR0FBh+s4dkawrSpU2rpeyBGmpA6lMnI:0uGyv2H/FT74Oo5rpXA2b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_eda8c398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda8c3988086e3f74102f462592383be649059aa3599d1ad46808db223cff58c"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-24 01:16:58"
  condition:
    hash.sha256(0, filesize) == "eda8c3988086e3f74102f462592383be649059aa3599d1ad46808db223cff58c"
}
```

### Sample 12: `14c28a21dc6c756c`

| Field | Value |
|---|---|
| SHA-256 | `14c28a21dc6c756cbf84a5e250b590f9b12883293c66b1298c27e633f270421b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-24 00:54:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc2ffbeba8ef2ce253b406725a2c945e` |
| SHA-1 | `0be6583653621fcf0e6cb60af7ca02b288eaf62a` |
| SHA-256 | `14c28a21dc6c756cbf84a5e250b590f9b12883293c66b1298c27e633f270421b` |
| SHA3-384 | `3e12b8f190f3fec756734a6c0f30946a1fe6e31d06b743fb5e9dee1b271b5ad766bb7fd13fc41b3fe4314ca56c666efd` |
| TLSH | `T1C4138D6966857C24AE9988371C7E2F0CB9A983E1310451EDBFCB3CF58C19ADCE21971D` |
| SSDEEP | `768:uE+q9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:b+/co` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_14c28a21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14c28a21dc6c756cbf84a5e250b590f9b12883293c66b1298c27e633f270421b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-24 00:54:56"
  condition:
    hash.sha256(0, filesize) == "14c28a21dc6c756cbf84a5e250b590f9b12883293c66b1298c27e633f270421b"
}
```

### Sample 13: `4db8eb346541d4b4`

| Field | Value |
|---|---|
| SHA-256 | `4db8eb346541d4b4d9931c431eecc9034cd574317b61b058e9969ca538e1ebd5` |
| Family label | `DarkTortilla` |
| File name | `New Quote.exe` |
| File type | `exe` |
| First seen | `2026-06-24 00:53:40` |
| Reporter | `threatcat_ch` |
| Tags | `DarkTortilla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f5f377bf5f732ce5d389f98ad5829f9` |
| SHA-1 | `2e160a4a609cb19d4b35280fb4e83eeba05e72b5` |
| SHA-256 | `4db8eb346541d4b4d9931c431eecc9034cd574317b61b058e9969ca538e1ebd5` |
| SHA3-384 | `7019012a057e5cc2a84597e4777b1a2cb93a52a3e03ac88d217802aabd5ef682d16a319d3817c242d7d560839bf0cfbc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18B35026507E89324D5BEAB3DD1B8051047F2BE079A23E76E529497FD1E21792BA03333` |
| SSDEEP | `24576:RS+uWmtlObdkjbHoBLnOTmmYMmKjX0ZF:ECmmbdkj7eLnGmVp` |

#### Technical Assessment

- The sample is tracked as `DarkTortilla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkTortilla_013_4db8eb34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4db8eb346541d4b4d9931c431eecc9034cd574317b61b058e9969ca538e1ebd5"
    family = "DarkTortilla"
    file_name = "New Quote.exe"
    file_type = "exe"
    first_seen = "2026-06-24 00:53:40"
  condition:
    hash.sha256(0, filesize) == "4db8eb346541d4b4d9931c431eecc9034cd574317b61b058e9969ca538e1ebd5"
}
```

### Sample 14: `7e0de4a54fd3e5c7`

| Field | Value |
|---|---|
| SHA-256 | `7e0de4a54fd3e5c74bd4cccebe26d3e7b141e493edf4a2df59b9ff6e228999e3` |
| Family label | `NanoCore` |
| File name | `dpvm.io.exe` |
| File type | `exe` |
| First seen | `2026-06-24 00:50:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cacc96ee99446f6f5b66e17042b4352f` |
| SHA-1 | `bb9cdc99b70a7a599cf990cef18b0bc2541835fd` |
| SHA-256 | `7e0de4a54fd3e5c74bd4cccebe26d3e7b141e493edf4a2df59b9ff6e228999e3` |
| SHA3-384 | `d241a9688df8183fe98bcf04cd9e082459662391572988c84ebecb9eebd44c4b60ecf8ad91939e833145110047657170` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18014CF167BA88A2FE2DE8679601252129379C2E3D8C3F3DF28D854B65F177E10A470D7` |
| SSDEEP | `6144:sLV6Bta6dtJmakIM5qZmvN1onPN5rjfmQn:sLV6BtpmkQvN1MNR1n` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_014_7e0de4a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e0de4a54fd3e5c74bd4cccebe26d3e7b141e493edf4a2df59b9ff6e228999e3"
    family = "NanoCore"
    file_name = "dpvm.io.exe"
    file_type = "exe"
    first_seen = "2026-06-24 00:50:05"
  condition:
    hash.sha256(0, filesize) == "7e0de4a54fd3e5c74bd4cccebe26d3e7b141e493edf4a2df59b9ff6e228999e3"
}
```

### Sample 15: `76ffbf5212a81578`

| Field | Value |
|---|---|
| SHA-256 | `76ffbf5212a8157868af8191045876b74c1640dec4fec22d27fe28b797a2b97d` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-24 00:12:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a08ca6495ae6d2ded6d8733bb34e0892` |
| SHA-1 | `bfd9c7c2ce3db1b4fec518ac2a29b92a1a64e32f` |
| SHA-256 | `76ffbf5212a8157868af8191045876b74c1640dec4fec22d27fe28b797a2b97d` |
| SHA3-384 | `135fbecfaf86c91efaf61f851b0c125392877c0a36a72b06193b70d14e950ce783ff700e233d6177aacf802ca814e4aa` |
| TLSH | `T171D097B3217302F822A12839F0C6A880B4058B7E6C83C62CBB0324317F01348F0C13D8` |
| SSDEEP | `6:hTed8sbGPbvT2oSuImwTwAulNXYq9DG+NjVsNXYrkJ:Ved8sbK7+mw0Piq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_76ffbf52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76ffbf5212a8157868af8191045876b74c1640dec4fec22d27fe28b797a2b97d"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-24 00:12:59"
  condition:
    hash.sha256(0, filesize) == "76ffbf5212a8157868af8191045876b74c1640dec4fec22d27fe28b797a2b97d"
}
```

### Sample 16: `f6d0e5142fd0d1a0`

| Field | Value |
|---|---|
| SHA-256 | `f6d0e5142fd0d1a0f07e916c9c7432ffcbacc2a6d4eb0594f1524cb7661477ce` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-06-24 00:12:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afcfec1f881035e049a44c177844ada3` |
| SHA-1 | `70edb89a14207ac732afaeac306ef2a898bf554b` |
| SHA-256 | `f6d0e5142fd0d1a0f07e916c9c7432ffcbacc2a6d4eb0594f1524cb7661477ce` |
| SHA3-384 | `26fc50e6f92e3da6cdb751e2b670c0d2edd6cb7617eeefd0e7a11e7c8d0630f71f69bf7597ab6b109498b85a2a9b1557` |
| TLSH | `T1CDD38EC1E743E0F5E95206F1103BA7258BB6D43BA43AEB92D7A93D32EC625508B1735C` |
| TELFHASH | `t186511af92a7a0cec6b909811a24f5b117e4e577b382436bb05b35475327bd4182bbc39` |
| SSDEEP | `3072:1RBTBmY4ImwNkDdOEKw8wb7zBvlpMZyBC:1RBFmYWLDfTLeb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_f6d0e514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6d0e5142fd0d1a0f07e916c9c7432ffcbacc2a6d4eb0594f1524cb7661477ce"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-24 00:12:57"
  condition:
    hash.sha256(0, filesize) == "f6d0e5142fd0d1a0f07e916c9c7432ffcbacc2a6d4eb0594f1524cb7661477ce"
}
```

### Sample 17: `dcb2e53eaeb334e7`

| Field | Value |
|---|---|
| SHA-256 | `dcb2e53eaeb334e77769eede9700b4a544e013b70c337a61ebb0513243393ac2` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-24 00:04:57` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ada20efcff540ff37f4c0801e6aed04f` |
| SHA-1 | `09465c01dc4e1f5248c9c2a34d77e4942ef1dea5` |
| SHA-256 | `dcb2e53eaeb334e77769eede9700b4a544e013b70c337a61ebb0513243393ac2` |
| SHA3-384 | `1dbbfaf4914924af83b275af1a5613945ef376fb690b663c40c62a5655d87e936ee9b59d8e1c245f541cf771fe1751fa` |
| TLSH | `T1D5311ADE46111A352602CADD77B3368DA50C93EF2C9BC3809D4C1EED82896CCB265BD5` |
| SSDEEP | `12:U076oR3U6776uBWbIr6Vvt7wi60kGai6aeEx6di6dmmr89a6ARI6RgnR/065Hd6y:d5Kt7HXxyTm+8pnh0YH2HN5rGBwBen` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_dcb2e53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcb2e53eaeb334e77769eede9700b4a544e013b70c337a61ebb0513243393ac2"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-24 00:04:57"
  condition:
    hash.sha256(0, filesize) == "dcb2e53eaeb334e77769eede9700b4a544e013b70c337a61ebb0513243393ac2"
}
```

### Sample 18: `a881050c8ac1682c`

| Field | Value |
|---|---|
| SHA-256 | `a881050c8ac1682c8f8e44b8ccdee9a0fded8891e8ddfa8f41416a16fa42ce08` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-06-24 00:01:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1de5ac82d2f8056287669ef844e79e40` |
| SHA-1 | `242dbdb632f4f53d80b44f2e52adb955325d4b01` |
| SHA-256 | `a881050c8ac1682c8f8e44b8ccdee9a0fded8891e8ddfa8f41416a16fa42ce08` |
| SHA3-384 | `9f23cb17960d887a45342fd62f2ab2d61858b9886833079e7646a5ad31dd86b97bfdcc1dd3d3623357fa8ca9c966926a` |
| TLSH | `T1A1731991B982565EC2D013BBFA5F928D337563E8D2DE3123D9218B1133CA52F0977B91` |
| TELFHASH | `t140f05904fe7a8e1958f69971dcbd17a4d4435227a1a21b20ef56cad1cc3e458f308d1e` |
| SSDEEP | `1536:6YXLJ1uloL2g4rgKcgtxoNZhI5Xzi2mWf7Iyd9jb:hLJ1Z2g4rgKcOfGebd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_a881050c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a881050c8ac1682c8f8e44b8ccdee9a0fded8891e8ddfa8f41416a16fa42ce08"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-24 00:01:05"
  condition:
    hash.sha256(0, filesize) == "a881050c8ac1682c8f8e44b8ccdee9a0fded8891e8ddfa8f41416a16fa42ce08"
}
```

### Sample 19: `75a89d421cbe02df`

| Field | Value |
|---|---|
| SHA-256 | `75a89d421cbe02df07b43667f099e6678c6eaa9e0544d4d32c82629a84f93089` |
| Family label | `unknown` |
| File name | `ipmiv2.xml` |
| File type | `unknown` |
| First seen | `2026-06-23 23:52:57` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0709fc2f9dcc02cffc0a1021458e2d4d` |
| SHA-256 | `75a89d421cbe02df07b43667f099e6678c6eaa9e0544d4d32c82629a84f93089` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_75a89d42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75a89d421cbe02df07b43667f099e6678c6eaa9e0544d4d32c82629a84f93089"
    family = "unknown"
    file_name = "ipmiv2.xml"
    file_type = "unknown"
    first_seen = "2026-06-23 23:52:57"
  condition:
    hash.sha256(0, filesize) == "75a89d421cbe02df07b43667f099e6678c6eaa9e0544d4d32c82629a84f93089"
}
```

### Sample 20: `c2e736a01417f846`

| Field | Value |
|---|---|
| SHA-256 | `c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce` |
| Family label | `unknown` |
| File name | `c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce` |
| File type | `sh` |
| First seen | `2026-06-23 23:18:36` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86f7ef92c967d514c11014a3ddde04fb` |
| SHA-1 | `242106967d679dac99152693d1fa3a7e45cb80d1` |
| SHA-256 | `c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce` |
| SHA3-384 | `98634185f30afcf725b266311d581ffbda2277f3e566b070e84c38b2f8fb5f3991376250548018eac221500932659780` |
| TLSH | `T174A194A9602032F99E22DDA536999CCC3AD784AB6A670E6497DC3970F1FCF1438781C5` |
| SSDEEP | `96:Jjz+CDpYu7gHgWgCDn+h5TJksJTN4A3zgvnvHSY3U1UsUC1Zk/ndwL7jDZD4DWDg:UATCs36RCTR2WE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_c2e736a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce"
    family = "unknown"
    file_name = "c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce"
    file_type = "sh"
    first_seen = "2026-06-23 23:18:36"
  condition:
    hash.sha256(0, filesize) == "c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce"
}
```

### Sample 21: `1f9624a18f3bc812`

| Field | Value |
|---|---|
| SHA-256 | `1f9624a18f3bc812317966f91c22549e900e82f6ece603c53d4d663001cbf7ec` |
| Family label | `ConnectWise` |
| File name | `SecuriteInfo.com.Trojan.Siggen31.29530.31038.23378` |
| File type | `exe` |
| First seen | `2026-06-23 22:37:47` |
| Reporter | `SecuriteInfoCom` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2648bc6e76fbd528e77005e57edf729d` |
| SHA-1 | `734f03efae2b7506a72abcea1cf5e33e00b31093` |
| SHA-256 | `1f9624a18f3bc812317966f91c22549e900e82f6ece603c53d4d663001cbf7ec` |
| SHA3-384 | `016e31d566921e6a25e35bdd9b1422537cae1d72e2daf9bf3cdc3958b1be32b3a11330c3f329a1621f88fe3a5021ab96` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1C9647C02B9C4C432D633293506B4D2B24EBEB8315D655E8F27D90A7E9F741D0AB24B7B` |
| SSDEEP | `6144:amlfAowFNryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:pbwFNryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_021_1f9624a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f9624a18f3bc812317966f91c22549e900e82f6ece603c53d4d663001cbf7ec"
    family = "ConnectWise"
    file_name = "SecuriteInfo.com.Trojan.Siggen31.29530.31038.23378"
    file_type = "exe"
    first_seen = "2026-06-23 22:37:47"
  condition:
    hash.sha256(0, filesize) == "1f9624a18f3bc812317966f91c22549e900e82f6ece603c53d4d663001cbf7ec"
}
```

### Sample 22: `f0d29fc579b7f0c9`

| Field | Value |
|---|---|
| SHA-256 | `f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5` |
| Family label | `WannaCry` |
| File name | `f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5.dll` |
| File type | `dll` |
| First seen | `2026-06-23 21:55:13` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99be653b9da7f83fde8a879c1f9ac16f` |
| SHA-1 | `0377b4a14b07e16ca4acbed95f0fe2a3bd32cfc5` |
| SHA-256 | `f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5` |
| SHA3-384 | `0fc6ede2041125365b019a2465d123452a82b46f9f9efb0b2896c019ba4d21468bd91af6b22bddbc39c6f23c085d900e` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T12C36235B65BD41BCD50D26F884FF8897D6F23CAB21AABE0B5B800C262C43B55EBD0645` |
| SSDEEP | `49152:RnnMSPbcBVQej/QINRx+TSqTdX1HkQo6SAgql:1nPoBhzQaRxcSUDk36SAg2` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_022_f0d29fc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5"
    family = "WannaCry"
    file_name = "f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5.dll"
    file_type = "dll"
    first_seen = "2026-06-23 21:55:13"
  condition:
    hash.sha256(0, filesize) == "f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5"
}
```

### Sample 23: `66c883ff13b81204`

| Field | Value |
|---|---|
| SHA-256 | `66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c` |
| Family label | `WannaCry` |
| File name | `66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c.dll` |
| File type | `dll` |
| First seen | `2026-06-23 21:53:02` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9155183e0b2031ba0c7159f76840ffed` |
| SHA-1 | `62dec33c52e558666c7481e2fce3a13eaede7650` |
| SHA-256 | `66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c` |
| SHA3-384 | `1cc8f251eb9dd9e43da9301e04b088d06d5f1370ec99f6b442a26c21456de9532bf1aa3ff1d0878e05958db6d3962edc` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T165363394622CB2FCF0440EB44463896BB7B73C6967BA5E1F9BC086670D43B5BAFD0641` |
| SSDEEP | `98304:+DqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8qAVp2H:+DqPe1Cxcxk3ZAEUadzR8qc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_023_66c883ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c"
    family = "WannaCry"
    file_name = "66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c.dll"
    file_type = "dll"
    first_seen = "2026-06-23 21:53:02"
  condition:
    hash.sha256(0, filesize) == "66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c"
}
```

### Sample 24: `17b502febe4c9576`

| Field | Value |
|---|---|
| SHA-256 | `17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8` |
| Family label | `unknown` |
| File name | `17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8.dll` |
| File type | `dll` |
| First seen | `2026-06-23 21:51:52` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66030318d8a4c61e0dd67a49e034ae20` |
| SHA-1 | `72ebec550187981ec62da53359733891664ed76c` |
| SHA-256 | `17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8` |
| SHA3-384 | `24aabb9c3d150443a1738cd54aab79e465f03e396700891abe61b85d3e23a7a0423fe8fe206101eb30344a03a68beab2` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1F236239A71BC91FCD105397484BB8A23E6F23CAD22FE6E0F9B8049751D03B59B750B42` |
| SSDEEP | `49152:RnnMSPbcBVQej/1INRx+TSqTdX1HkQo6SA:1nPoBhz1aRxcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_17b502fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8"
    family = "unknown"
    file_name = "17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8.dll"
    file_type = "dll"
    first_seen = "2026-06-23 21:51:52"
  condition:
    hash.sha256(0, filesize) == "17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8"
}
```

### Sample 25: `3fbc343025f847fd`

| Field | Value |
|---|---|
| SHA-256 | `3fbc343025f847fdeb6fd21311215e47d20a68be80eb25434d5d76c373532f0e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 21:43:18` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee375d8109492802af40a1fb6559df43` |
| SHA-1 | `93b06a29aaff514daa3c6ee53d2723c1e2d9761f` |
| SHA-256 | `3fbc343025f847fdeb6fd21311215e47d20a68be80eb25434d5d76c373532f0e` |
| SHA3-384 | `54a5a23e9b2b3dab20c9d733fde2517c43e72c9027d47445950e5805d6a053a79cb4fae81601f360dd4c9dcc9a1ab9f9` |
| IMPHASH | `d3e7288350e35c12dcbdfff4a6ede5cc` |
| TLSH | `T116455C17E6A385ECC66ED17482579772BA70B4290230BD6F1EA9D7311F23E508B1FB24` |
| SSDEEP | `24576:WuDJ/uXQKfhd8Pz3UeqlJJ2vPhHjNg10cOmHE9x:WuN/YQKfhdsz3UeqlJJ2HhDNcq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_3fbc3430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fbc343025f847fdeb6fd21311215e47d20a68be80eb25434d5d76c373532f0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:43:18"
  condition:
    hash.sha256(0, filesize) == "3fbc343025f847fdeb6fd21311215e47d20a68be80eb25434d5d76c373532f0e"
}
```

### Sample 26: `ea12c2dafe8a3d63`

| Field | Value |
|---|---|
| SHA-256 | `ea12c2dafe8a3d632055550e20be4544bed615d263da1e6fa689a7ee5b790703` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 21:23:54` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6673ce71c2c279a389445726738d779b` |
| SHA-1 | `c965046c9963cca8fc7c9078612041d43cce5e0f` |
| SHA-256 | `ea12c2dafe8a3d632055550e20be4544bed615d263da1e6fa689a7ee5b790703` |
| SHA3-384 | `9fab38a50baea82dc6094f5c6653a3fef7827dbfbfb6c38354ae183bc279f54ef227eed778eec8c500c1e483a60d73b8` |
| IMPHASH | `68abec56f28b8e46f402f67d51d803de` |
| TLSH | `T1A1F5E1037BFEF05EEB6B97B4946463818615FC334D91849A71CC148B4F9B9407EBC2AA` |
| SSDEEP | `49152:pRYiAceeenPzlptqw7tmzVHGo5ZklHvlI1htvs3YNXzM3lkeUZFV4FQGwZfEZo:hlRKzlptq6SGcK+tN9zV4wZc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_ea12c2da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea12c2dafe8a3d632055550e20be4544bed615d263da1e6fa689a7ee5b790703"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:23:54"
  condition:
    hash.sha256(0, filesize) == "ea12c2dafe8a3d632055550e20be4544bed615d263da1e6fa689a7ee5b790703"
}
```

### Sample 27: `c966a90c770463c7`

| Field | Value |
|---|---|
| SHA-256 | `c966a90c770463c7566bc87accc402a9c34a4bd6752b8ce27c3d73efbfadfe65` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-06-23 21:20:42` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d6d9d74c1bfb2db07d0c3a00c25761b` |
| SHA-256 | `c966a90c770463c7566bc87accc402a9c34a4bd6752b8ce27c3d73efbfadfe65` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_c966a90c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c966a90c770463c7566bc87accc402a9c34a4bd6752b8ce27c3d73efbfadfe65"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-06-23 21:20:42"
  condition:
    hash.sha256(0, filesize) == "c966a90c770463c7566bc87accc402a9c34a4bd6752b8ce27c3d73efbfadfe65"
}
```

### Sample 28: `38f593be606970dc`

| Field | Value |
|---|---|
| SHA-256 | `38f593be606970dca31716996074627b2aea802089d8c0c73676e1f888327ee9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 21:20:02` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ecce33e6cde53ca5d8031bf962bf06d` |
| SHA-1 | `af27d5be9d901a2eb4aa8f2fb116cb2b52082e09` |
| SHA-256 | `38f593be606970dca31716996074627b2aea802089d8c0c73676e1f888327ee9` |
| SHA3-384 | `a05ce8fa4aafc27964c3f0b42cce3688cd50452f3ab76ee39a478e146eb079e91a05d365a62aac420916fe8a6af761a4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T122E58D17BCE109E6C0AD623194B26151BB72FC055B7927E72E90FB782E32BD09D3A744` |
| SSDEEP | `24576:4Wd73fvz7BARtguxqK6iVx+Ptsf4DDwWjTxEk+Pe7naoddXMOoHguJMaYI59Rwtl:4Wd7vv/BsgyqkvtwL+mTM3Rb5W4h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_38f593be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38f593be606970dca31716996074627b2aea802089d8c0c73676e1f888327ee9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:20:02"
  condition:
    hash.sha256(0, filesize) == "38f593be606970dca31716996074627b2aea802089d8c0c73676e1f888327ee9"
}
```

### Sample 29: `8735b6a853ce69a2`

| Field | Value |
|---|---|
| SHA-256 | `8735b6a853ce69a2e99781bbf5774df5acf2130724f4f92c7cad174779864ab4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 21:18:39` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69b23b05baf95895bebfd9c4284c7cf3` |
| SHA-1 | `bc6d9e7110828bec775e13ef845cc3e93bfcb56e` |
| SHA-256 | `8735b6a853ce69a2e99781bbf5774df5acf2130724f4f92c7cad174779864ab4` |
| SHA3-384 | `4dd72ec937eba2d73e370c506afa62bf22022d8fa5ad452a626342b630f93cb51123b4db90eda830b1aaa2a7a31265da` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1ACE59D07ACE248E9C4AA737149B662917B72B8000F3A63C36D90BB793F767C15D36794` |
| SSDEEP | `24576:EeMY5OcEuMFGR8ycVsj1IBQ3/IslAoz+LLUZD3WrwChzHciXAepEymm9qyQZtUMb:EeMYMctMICyUsW0/FlKLAZV9yatdz4bE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_8735b6a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8735b6a853ce69a2e99781bbf5774df5acf2130724f4f92c7cad174779864ab4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:18:39"
  condition:
    hash.sha256(0, filesize) == "8735b6a853ce69a2e99781bbf5774df5acf2130724f4f92c7cad174779864ab4"
}
```

### Sample 30: `66f8f315000fe6a2`

| Field | Value |
|---|---|
| SHA-256 | `66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377` |
| Family label | `unknown` |
| File name | `66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377` |
| File type | `elf` |
| First seen | `2026-06-23 21:07:17` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04c3d745efb1580fdc78a47e2daec5bc` |
| SHA-1 | `8052aa55a3456d80d4d9f658232059d3cef5589a` |
| SHA-256 | `66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377` |
| SHA3-384 | `216d3899ba82d7cb9e52cf4a2568d895ca42175c912f12c6f14142232c99fb2807b81741ce34c3dc9c9edd918f89fb13` |
| TLSH | `T19627CE77914338E9E5A98DB4D01025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQZ:cqYUQuVDt0TZEy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_66f8f315
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377"
    family = "unknown"
    file_name = "66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377"
    file_type = "elf"
    first_seen = "2026-06-23 21:07:17"
  condition:
    hash.sha256(0, filesize) == "66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377"
}
```

### Sample 31: `da539912928b31ea`

| Field | Value |
|---|---|
| SHA-256 | `da539912928b31ea423a3b8bd4cdb91946ee775c8c15c605d8be410de7c0e3fd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 20:29:54` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `260e5530b3dc1bc8931876a125cf490c` |
| SHA-1 | `94d685fe8cdcb25a11d0f0a1a7d9c901233500b4` |
| SHA-256 | `da539912928b31ea423a3b8bd4cdb91946ee775c8c15c605d8be410de7c0e3fd` |
| SHA3-384 | `090253030f6c008b04ce6b93698aeb81954e653c8073384b52784c615c5ad75ae14e457ef454e863be6434e59be60963` |
| IMPHASH | `3eb1610e3858eeb5106ac7b290ae15f9` |
| TLSH | `T1B186D0137BFEB05EEAAB97B4956466818625FC774C91804D31CD148B0F9B9007EFC2BA` |
| SSDEEP | `196608:nSJwejUdzEvwiNhaBH7Gnb2/8R+VnjCp:ngjzzNhaFGb28RKup` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_da539912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da539912928b31ea423a3b8bd4cdb91946ee775c8c15c605d8be410de7c0e3fd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 20:29:54"
  condition:
    hash.sha256(0, filesize) == "da539912928b31ea423a3b8bd4cdb91946ee775c8c15c605d8be410de7c0e3fd"
}
```

### Sample 32: `c1e04d688fa28670`

| Field | Value |
|---|---|
| SHA-256 | `c1e04d688fa2867036a118ca02a515503d8cf7e48073a234f6faaaebd645af55` |
| Family label | `unknown` |
| File name | `AVISO URGENTE FORMAL DE PAGO Y REGULARIZACIÓN DE SALDO REVISAR Y VALIDAR.js` |
| File type | `js` |
| First seen | `2026-06-23 20:27:03` |
| Reporter | `cypherpunk472` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4530b4cbf94d96debab10a72fb57c0e6` |
| SHA-1 | `f1a3a3e90ffa96b07f4a650a84e5b004e2c5449a` |
| SHA-256 | `c1e04d688fa2867036a118ca02a515503d8cf7e48073a234f6faaaebd645af55` |
| SHA3-384 | `4dcbaada8b65769fa241697bc3b91aee7468140cb7b8d1173a6d7845fa65de97d022c788617f78a1bb1635cacf44f99b` |
| TLSH | `T1AAF6D05F90E9B7694A78DEB204B88913253E51BA6E147D2620E373CF81F6500E6F3D87` |
| SSDEEP | `3072:PRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMRMc:l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_c1e04d68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e04d688fa2867036a118ca02a515503d8cf7e48073a234f6faaaebd645af55"
    family = "unknown"
    file_name = "AVISO URGENTE FORMAL DE PAGO Y REGULARIZACIÓN DE SALDO REVISAR Y VALIDAR.js"
    file_type = "js"
    first_seen = "2026-06-23 20:27:03"
  condition:
    hash.sha256(0, filesize) == "c1e04d688fa2867036a118ca02a515503d8cf7e48073a234f6faaaebd645af55"
}
```

### Sample 33: `000aabb7b6b9b3fa`

| Field | Value |
|---|---|
| SHA-256 | `000aabb7b6b9b3faa488e2eb49f3350ba182ed67257d0fa8e91eb49ad9fc4ad6` |
| Family label | `unknown` |
| File name | `2306 AVISO URGENTE FORMAL DE PAGO Y REGULARIZACIÓN DE SALDO REVISAR Y VALIDAR_infected.zip` |
| File type | `zip` |
| First seen | `2026-06-23 20:21:14` |
| Reporter | `cypherpunk472` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a731ff6d56c6610173900beb68d3bf6` |
| SHA-1 | `0414b00719a351066240a9a68e1eac44b8f2378e` |
| SHA-256 | `000aabb7b6b9b3faa488e2eb49f3350ba182ed67257d0fa8e91eb49ad9fc4ad6` |
| SHA3-384 | `422f7f92247fc7bce5b818f5e47c0721fe569789aeaab1ff4fabe9570afbda3f08323dc037038bc5c09163295329a0a3` |
| TLSH | `T146D41276956EB98CDC3136BB4E11AC423CF385A89448522B90FF1FAF782252944F91DF` |
| SSDEEP | `12288:+UoP577gO9ZT8D12KYcebCH2bn7f+FJYJ3rLGaetWaCsmWbne62FSSuTviU:+X57779ZT01nmmi7f+F+3paZbngF6KU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_000aabb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "000aabb7b6b9b3faa488e2eb49f3350ba182ed67257d0fa8e91eb49ad9fc4ad6"
    family = "unknown"
    file_name = "2306 AVISO URGENTE FORMAL DE PAGO Y REGULARIZACIÓN DE SALDO REVISAR Y VALIDAR_infected.zip"
    file_type = "zip"
    first_seen = "2026-06-23 20:21:14"
  condition:
    hash.sha256(0, filesize) == "000aabb7b6b9b3faa488e2eb49f3350ba182ed67257d0fa8e91eb49ad9fc4ad6"
}
```

### Sample 34: `98a6d83b9554b57e`

| Field | Value |
|---|---|
| SHA-256 | `98a6d83b9554b57ec4b84fbc5bb283a65a27341095e9179957b2adf850779042` |
| Family label | `Mirai` |
| File name | `tplink.sh` |
| File type | `sh` |
| First seen | `2026-06-23 20:14:39` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e04fdb56afa20f237dfe51a8e8ba2e8` |
| SHA-1 | `9093e1734ff7be1fcb65ccb669839307b63d1a1d` |
| SHA-256 | `98a6d83b9554b57ec4b84fbc5bb283a65a27341095e9179957b2adf850779042` |
| SHA3-384 | `bee667c7f20a2f8148074d8a3117371f166af6f32424210761f57882569926ad88aa5d48fb9007f634e33cb88631de67` |
| TLSH | `T14E214F5CA869266A0632EDE0F4624216A1AFF7C433537718E34C363A5C9C104B738BC6` |
| SSDEEP | `24:QvQhBh9M0oyCt8qt7aRtMtbYiJtoKdtEOt89t7astftbYiktoKwtEy:QvQhnolaZiI5aJiXj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_98a6d83b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98a6d83b9554b57ec4b84fbc5bb283a65a27341095e9179957b2adf850779042"
    family = "Mirai"
    file_name = "tplink.sh"
    file_type = "sh"
    first_seen = "2026-06-23 20:14:39"
  condition:
    hash.sha256(0, filesize) == "98a6d83b9554b57ec4b84fbc5bb283a65a27341095e9179957b2adf850779042"
}
```

### Sample 35: `02dab7a5df7df570`

| Field | Value |
|---|---|
| SHA-256 | `02dab7a5df7df570f5eb58931986cbccad6558bd92a11e2f2f1751f0d0ec2767` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-06-23 20:10:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05c7b32c08f2ff12e91dc9326c58a5ff` |
| SHA-1 | `d936ec7f7ddac618560d333878a0a5e7ed1576a8` |
| SHA-256 | `02dab7a5df7df570f5eb58931986cbccad6558bd92a11e2f2f1751f0d0ec2767` |
| SHA3-384 | `597c90abbdfba22fdb6ead08da0f9801a5d3b2e209d1b08429ec943a064eff3228897be241727cc458ec292893c16c9e` |
| TLSH | `T116638D93C87A2E45C54672B0A4F5CE79C703946096831EB61A93CBB6584BC8D728D7F8` |
| SSDEEP | `1536:Z5uo/Ebh+DfJzgN/t8cz1bu3O7QIusCzt:7wE7RgcczA+sIus` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_02dab7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02dab7a5df7df570f5eb58931986cbccad6558bd92a11e2f2f1751f0d0ec2767"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-23 20:10:25"
  condition:
    hash.sha256(0, filesize) == "02dab7a5df7df570f5eb58931986cbccad6558bd92a11e2f2f1751f0d0ec2767"
}
```

### Sample 36: `15c3faf3681fd104`

| Field | Value |
|---|---|
| SHA-256 | `15c3faf3681fd10404a208d815421157a04e9f0f8d63746cbdf324f71466cc42` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-06-23 20:01:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7db545e5c2b0d3eef1d02284d5b9a5e` |
| SHA-1 | `2db574e0636a143e1518f3bc92428a28a62353af` |
| SHA-256 | `15c3faf3681fd10404a208d815421157a04e9f0f8d63746cbdf324f71466cc42` |
| SHA3-384 | `b2304a27fbae40975bcea0bbdaad22161535f902379ff06e2b35a753de5a8389524041e66f6ac2ccb55938e97d76874b` |
| TLSH | `T167630780F94B80F5DD4359B098E7F37FA670CA845230A21EEF5D9B26D623B1666172CC` |
| TELFHASH | `t11921f4f62e3e0ce977c08c01c10a5f912a6a936b186136e74173593836eed4110bfc39` |
| SSDEEP | `1536:lTArUrx6uLFQIGdYNsh8hdhfwhE2LxMbFnUBFHAr:lF9GdYNRKxMbFnWl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_15c3faf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15c3faf3681fd10404a208d815421157a04e9f0f8d63746cbdf324f71466cc42"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-06-23 20:01:31"
  condition:
    hash.sha256(0, filesize) == "15c3faf3681fd10404a208d815421157a04e9f0f8d63746cbdf324f71466cc42"
}
```

### Sample 37: `491eaa1e13d8792f`

| Field | Value |
|---|---|
| SHA-256 | `491eaa1e13d8792f96428fb147d529075f7848cbc37c69b60e6659754ef3acf7` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-23 19:57:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b71a96677045c199efeb121ee7cb941` |
| SHA-1 | `6b84bc3ddc2d89e34026b7f9ded4ca6a61624045` |
| SHA-256 | `491eaa1e13d8792f96428fb147d529075f7848cbc37c69b60e6659754ef3acf7` |
| SHA3-384 | `d64e7e6cf56062e1b9d05786fc2b2df0a51b6f00dd3fa8b70c753082aabdb35bbbb9506854a5d718ca023027ef947ee2` |
| TLSH | `T16DA3D5097F710EF7E8AFCC3355B94706249C9A0622A97BBA7D74D418F75A14F02E3868` |
| SSDEEP | `1536:zJFT3axH26QHQci9PJTaexTM+eZlbpmFIMA2lLxSKZylcv/f:zJFTKxWLi9PJOBfbpmNxSK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_491eaa1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "491eaa1e13d8792f96428fb147d529075f7848cbc37c69b60e6659754ef3acf7"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-23 19:57:21"
  condition:
    hash.sha256(0, filesize) == "491eaa1e13d8792f96428fb147d529075f7848cbc37c69b60e6659754ef3acf7"
}
```

### Sample 38: `4fa2ccd05dc0b3a8`

| Field | Value |
|---|---|
| SHA-256 | `4fa2ccd05dc0b3a8dfcb2f089eba1a8cbf90b858dcf8f45c5f3c4c2539e55c63` |
| Family label | `unknown` |
| File name | `Banco_Sabadell.apk` |
| File type | `apk` |
| First seen | `2026-06-23 19:53:43` |
| Reporter | `BastianHein_` |
| Tags | `apk, BtmobRAT, signed, Xmrig` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fc7df93fab400ab425eb14ece4c9395` |
| SHA-1 | `2443a363106c00d9c91f4815572b0cb333cf746f` |
| SHA-256 | `4fa2ccd05dc0b3a8dfcb2f089eba1a8cbf90b858dcf8f45c5f3c4c2539e55c63` |
| SHA3-384 | `6a5b8af99067bf34dd42582297cc381a8239638444465da7e817e93c2b6b299629b58976149846308e5f8412aaa29a98` |
| TLSH | `T12EB7339BFB444D16D4F743B2403A6366144B4C6787838AC77A44363C29B7AE02F9ABDD` |
| SSDEEP | `1572864:Tx84Io0T4YY2MHozLXjl7QT8KmKWITpCyN0O:i4aT4Y2+6XVpCy6O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_4fa2ccd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fa2ccd05dc0b3a8dfcb2f089eba1a8cbf90b858dcf8f45c5f3c4c2539e55c63"
    family = "unknown"
    file_name = "Banco_Sabadell.apk"
    file_type = "apk"
    first_seen = "2026-06-23 19:53:43"
  condition:
    hash.sha256(0, filesize) == "4fa2ccd05dc0b3a8dfcb2f089eba1a8cbf90b858dcf8f45c5f3c4c2539e55c63"
}
```

### Sample 39: `1639ab80ef54685a`

| Field | Value |
|---|---|
| SHA-256 | `1639ab80ef54685a639a47eece8041ad21b950a107f667f241f0c2d6d5a937a8` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-23 19:51:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `373a349af4769554444fd67bd6355632` |
| SHA-1 | `98385a38fe47eeeb2900284138749645614bec4f` |
| SHA-256 | `1639ab80ef54685a639a47eece8041ad21b950a107f667f241f0c2d6d5a937a8` |
| SHA3-384 | `085595cdd968d71b4a3d2e8035ca176f1165d3e220a4ee917fa6d904f9134e8a137882e49c5ff93b5313b582a2591ea7` |
| TLSH | `T1B3A3D55E2F318F7EF7BD82340B779F359659239B26D0CA05D1ACE9056E2020E684FB64` |
| TELFHASH | `t18c116918853813f097811cee6beeff76d49140db49259e338e00fdaaaa61a429e00c2c` |
| SSDEEP | `1536:zfNQQxmXL3Xcs6vwEjnB1voFMvRkGzitO0KFZLHMr9hRZs9x91cIDkMbB:zfNxmXLXAwEFB0KFZLHMr9hRZ0cIA0B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_1639ab80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1639ab80ef54685a639a47eece8041ad21b950a107f667f241f0c2d6d5a937a8"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-23 19:51:20"
  condition:
    hash.sha256(0, filesize) == "1639ab80ef54685a639a47eece8041ad21b950a107f667f241f0c2d6d5a937a8"
}
```

### Sample 40: `b9d3147f13395b4c`

| Field | Value |
|---|---|
| SHA-256 | `b9d3147f13395b4c9d6242340b22021abc3b3ff03755809fcbf24aea653c0b59` |
| Family label | `unknown` |
| File name | `rhn.vbs` |
| File type | `vbs` |
| First seen | `2026-06-23 19:45:52` |
| Reporter | `BastianHein_` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `958bf3999bee97c50bd0947eb3ce2563` |
| SHA-1 | `1b869a58dbfa6ac8f45ad42e4fbc6cc22118e530` |
| SHA-256 | `b9d3147f13395b4c9d6242340b22021abc3b3ff03755809fcbf24aea653c0b59` |
| SHA3-384 | `ceabe2125cfd1da4e5c30752f9b78118254467844f9e7f56084e5d93479cf6929a955d0bdb3e119af775a9929bb4114f` |
| TLSH | `T18BC02B04A7ECD3340202C1C71E32D80C85404C1B941E730C0F10C00810005551107383` |
| SSDEEP | `3:jNKnhJmNUqF4RwOIkVViE2J5xAIDPcNUqFpfjpv:jKhJ6UqMBn23fwNUqJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_b9d3147f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9d3147f13395b4c9d6242340b22021abc3b3ff03755809fcbf24aea653c0b59"
    family = "unknown"
    file_name = "rhn.vbs"
    file_type = "vbs"
    first_seen = "2026-06-23 19:45:52"
  condition:
    hash.sha256(0, filesize) == "b9d3147f13395b4c9d6242340b22021abc3b3ff03755809fcbf24aea653c0b59"
}
```

### Sample 41: `fc92185b6516f3cd`

| Field | Value |
|---|---|
| SHA-256 | `fc92185b6516f3cdb0284201e14c96e5636d8f835fbf7eb6dc7bc704f70b89c7` |
| Family label | `unknown` |
| File name | `payload.exe` |
| File type | `exe` |
| First seen | `2026-06-23 19:44:45` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b109f51231a0016582e07dd160c550e4` |
| SHA-1 | `495f8d7d26a82c944a6abd76ba88df1d95136ce1` |
| SHA-256 | `fc92185b6516f3cdb0284201e14c96e5636d8f835fbf7eb6dc7bc704f70b89c7` |
| SHA3-384 | `e55aa383280fa646df810bc539ad8a40448bc384a7d051154bc1a2c8612eb8f028a65d54cd0c64daee501be91ead1ee0` |
| IMPHASH | `c2d02fc98f1d75d7b9457468ec75da0e` |
| TLSH | `T105E1DDA7A3275CB3F7395BBE82839B8561FD773446E30B490A6904095092D1839A5FD3` |
| SSDEEP | `24:ev1GSkiiljEowSPeUIt0Myt8XZh9h9ClfAOLTBu76L/up+:qkfj2sex3y6XZh9hMldfBu2L/b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_fc92185b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc92185b6516f3cdb0284201e14c96e5636d8f835fbf7eb6dc7bc704f70b89c7"
    family = "unknown"
    file_name = "payload.exe"
    file_type = "exe"
    first_seen = "2026-06-23 19:44:45"
  condition:
    hash.sha256(0, filesize) == "fc92185b6516f3cdb0284201e14c96e5636d8f835fbf7eb6dc7bc704f70b89c7"
}
```

### Sample 42: `1b2fbd5f510d8c02`

| Field | Value |
|---|---|
| SHA-256 | `1b2fbd5f510d8c02ba709aafafaffdebb298e41fd78aef620bd06781e78a8b92` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-23 19:41:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cb0ce0457de642e01beda0b5a79554a` |
| SHA-1 | `abb10ad145647027ca039463fd326ec2c652e3da` |
| SHA-256 | `1b2fbd5f510d8c02ba709aafafaffdebb298e41fd78aef620bd06781e78a8b92` |
| SHA3-384 | `1baf6939ae3cc2f452532ae17a181bc00e9b3788e9c3737db6a5e341c99e810e0a10da8925adab77dc610b8e029a1574` |
| TLSH | `T163735B03B58140FCD085C1B4063FA435E563F9BE13366AA937D8FA266F57B201E3DA58` |
| TELFHASH | `t14b21e4b16dda189025cb7236f30af0f05c322a2201f035e59eb769b3cf21b860d96026` |
| SSDEEP | `768:qAGLkIfjN+50W820gR2gsiXZWNmM6OOrO/N0o9pIBzdkhVI2ocSZ+jg/ae+g0uAx:b2+50N20gRVBMsilvVUqg0eV7VC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_1b2fbd5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b2fbd5f510d8c02ba709aafafaffdebb298e41fd78aef620bd06781e78a8b92"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-23 19:41:06"
  condition:
    hash.sha256(0, filesize) == "1b2fbd5f510d8c02ba709aafafaffdebb298e41fd78aef620bd06781e78a8b92"
}
```

### Sample 43: `99514c847ae4860e`

| Field | Value |
|---|---|
| SHA-256 | `99514c847ae4860e6488da66f0dc80e5d8afd596f7d6da9358e8b72b5c098942` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-06-23 19:41:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae39a09a3c96a9eba6b060810dbc31ad` |
| SHA-1 | `4e2c6815e0ef8dbbc2c7390f3c9e2e757c6eec19` |
| SHA-256 | `99514c847ae4860e6488da66f0dc80e5d8afd596f7d6da9358e8b72b5c098942` |
| SHA3-384 | `c7062eb5fe695366add4e03d18ce89841bb215236322732c0e10c92bef3a7d4d4cfb708845c230a2b75b56443ddd6aa2` |
| TLSH | `T1D7735C8764129DBCFC0BFA76491B4E05FA38F315CF520E33B3A2BD6B88530954D6AA45` |
| SSDEEP | `1536:qB6+yqzisRsGq6J9XhfSIW/tEP+bELub8MmVKNC1fLB4ems48p95:A7yqzisL1OtEP+dkHlB4em98p3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_99514c84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99514c847ae4860e6488da66f0dc80e5d8afd596f7d6da9358e8b72b5c098942"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-23 19:41:05"
  condition:
    hash.sha256(0, filesize) == "99514c847ae4860e6488da66f0dc80e5d8afd596f7d6da9358e8b72b5c098942"
}
```

### Sample 44: `4412add79e052ea3`

| Field | Value |
|---|---|
| SHA-256 | `4412add79e052ea3a32cd604d993b734315438ad2977925cf6f063608a8354cb` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-23 19:37:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21539197dbffb8b11da29df15ea74b81` |
| SHA-1 | `820730815e45be5cdc36fa49917ad414f3c77f2c` |
| SHA-256 | `4412add79e052ea3a32cd604d993b734315438ad2977925cf6f063608a8354cb` |
| SHA3-384 | `18a6bb1a7aaa975a16a11e642a37c313ca7c4ac2c6b6740fcf264660cfbeaa85e86afd74726c120d739416af1ce2022c` |
| TLSH | `T1DA136C6526953C25AE99883B5C7F2F0CB9A983E2304491DDBFCA3CF18C15A9CE71871D` |
| SSDEEP | `768:5r9NyXsZztCV9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:RHusZbco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_4412add7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4412add79e052ea3a32cd604d993b734315438ad2977925cf6f063608a8354cb"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-23 19:37:07"
  condition:
    hash.sha256(0, filesize) == "4412add79e052ea3a32cd604d993b734315438ad2977925cf6f063608a8354cb"
}
```

### Sample 45: `0127aa41531f6201`

| Field | Value |
|---|---|
| SHA-256 | `0127aa41531f6201e705333e44e944dc317a471a462546619a31eb746652f476` |
| Family label | `unknown` |
| File name | `kla.sh` |
| File type | `sh` |
| First seen | `2026-06-23 19:34:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `524c44360c286706318f20d2c9db29db` |
| SHA-1 | `123784b9889ae48b1acb87b6bf44359d76c79c74` |
| SHA-256 | `0127aa41531f6201e705333e44e944dc317a471a462546619a31eb746652f476` |
| SHA3-384 | `c6c0fb61c3ed3d3aa1e3d9e13e16880434bc31769a51f0837ee924db2536768d7bdd89f884d9d93d4ad9fdb676d89563` |
| TLSH | `T1E0516DC8119218B53CE28C67626B88A4F4C57641FEC64E59A0DDF8F6D4CEF49B402EB3` |
| SSDEEP | `48:2RKhEcfEnsTE1hxPfv9g0RDDpGGP3Ng0kwhToe:2RKhEcfEnsTE1DHh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_0127aa41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0127aa41531f6201e705333e44e944dc317a471a462546619a31eb746652f476"
    family = "unknown"
    file_name = "kla.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:34:07"
  condition:
    hash.sha256(0, filesize) == "0127aa41531f6201e705333e44e944dc317a471a462546619a31eb746652f476"
}
```

### Sample 46: `59917d57e94301d3`

| Field | Value |
|---|---|
| SHA-256 | `59917d57e94301d33685e651f71495c8cc958cb911cde15ae98e81f9a7264fce` |
| Family label | `unknown` |
| File name | `deploy_softwaretech.sh` |
| File type | `sh` |
| First seen | `2026-06-23 19:32:06` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42e276d067db547191148645485508fb` |
| SHA-1 | `7982fdc48eb33c74dae4a8dd0fba5b3052cbac4c` |
| SHA-256 | `59917d57e94301d33685e651f71495c8cc958cb911cde15ae98e81f9a7264fce` |
| SHA3-384 | `29b7df4eaf671a2c67c4df39116bb4bc3754e7887b157c134dac158975642d722f728f7a0550ce61fd65de7d3ae92a93` |
| TLSH | `T1EE52B772BA65D57638ACC22C998E9110392B3AEB3618346474ED76043FFC32D51F277A` |
| SSDEEP | `192:2875ryD74COKyAVF1mBt6e4egQq1GZ0HRit4Nmn5PH03/BNGBggGQd:T5zT4LyMiXn5PUQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_59917d57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59917d57e94301d33685e651f71495c8cc958cb911cde15ae98e81f9a7264fce"
    family = "unknown"
    file_name = "deploy_softwaretech.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:32:06"
  condition:
    hash.sha256(0, filesize) == "59917d57e94301d33685e651f71495c8cc958cb911cde15ae98e81f9a7264fce"
}
```

### Sample 47: `efb36b837e7c26e4`

| Field | Value |
|---|---|
| SHA-256 | `efb36b837e7c26e47b0db1231de4a229c203fb44316bd1c25f65ebf8a1ee421a` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-06-23 19:32:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b1c92bf41339276294837c03d49b77e` |
| SHA-1 | `5ed596c36c1e76e4f6f98150ca379ba0acd580ee` |
| SHA-256 | `efb36b837e7c26e47b0db1231de4a229c203fb44316bd1c25f65ebf8a1ee421a` |
| SHA3-384 | `5970928360c7f86e87179968f49bed48e288fcd49e863723e2253a94c289ef2c687236bb628f19523accdde6d36f9b90` |
| TLSH | `T14A142A56F8819B15D5D111BEFE0E128D33232BBCE2DE72129D246F207B8B96B0E7B505` |
| TELFHASH | `t117a00269e3645c2c70b881e9b9bf161685b8154c033b119105111e44ad531de559bc42` |
| SSDEEP | `3072:gUTMOJujbMWba5UAoZRuXzVoq9aCpkuCoxPjqw+QC/bIz0:cOJu/k5/GuXJouaF8xPN+Qwj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_efb36b83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efb36b837e7c26e47b0db1231de4a229c203fb44316bd1c25f65ebf8a1ee421a"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-06-23 19:32:05"
  condition:
    hash.sha256(0, filesize) == "efb36b837e7c26e47b0db1231de4a229c203fb44316bd1c25f65ebf8a1ee421a"
}
```

### Sample 48: `3e041d99e68d64f2`

| Field | Value |
|---|---|
| SHA-256 | `3e041d99e68d64f22c407109bf3f9cb10152136a607b51cf012c3b2e9900232a` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-23 19:31:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e98432fa6d60ff7260568df65d67c64a` |
| SHA-1 | `9dd3936266ce09c07a194a3d15c8ca910530a7f7` |
| SHA-256 | `3e041d99e68d64f22c407109bf3f9cb10152136a607b51cf012c3b2e9900232a` |
| SHA3-384 | `4167f7b9eae056dc53bbf81b0789fc0fd4d5416558f65bd9b2a9539c45f39ca1db5b19c283e615f8359183d0e3536e78` |
| TLSH | `T182634B06B892CA56C6C5627ABA5E918C331213F4D2DF3207DD15EFB97BC781A0E7B484` |
| SSDEEP | `1536:RnP6ppAoN3ZICQRBPERC0aIwYkut+qQtPURFfsUl1ooaY:xP6ppAoN3ZFyxERFaIzP+qQygUw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_3e041d99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e041d99e68d64f22c407109bf3f9cb10152136a607b51cf012c3b2e9900232a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-23 19:31:01"
  condition:
    hash.sha256(0, filesize) == "3e041d99e68d64f22c407109bf3f9cb10152136a607b51cf012c3b2e9900232a"
}
```

### Sample 49: `986318d491b023da`

| Field | Value |
|---|---|
| SHA-256 | `986318d491b023dad6692aa7f972fa696c20a2373244fdf8a8590098f683b870` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-06-23 19:29:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1f5a3eaf9b4df6a5c5adaa1fe1db0ad` |
| SHA-1 | `6edb56a43dcd15488373e1c67443fbc1bf84a2fa` |
| SHA-256 | `986318d491b023dad6692aa7f972fa696c20a2373244fdf8a8590098f683b870` |
| SHA3-384 | `014a31051bce7e6b0712dd295d14c92e1ed126215fa876d061f10194a6ae141702d67a59d81293eef11d8b84e5893ec9` |
| TLSH | `T19AD38EC1E743E0F5E95206F1103BA7258BB6D43BA43AEB92D7A93D32EC625508B1735C` |
| TELFHASH | `t186511af92a7a0cec6b909811a24f5b117e4e577b382436bb05b35475327bd4182bbc39` |
| SSDEEP | `3072:1RB/BmY4ImwNkDdOEKw8wb7zBvlpMZyBC:1RB5mYWLDfTLeb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_986318d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "986318d491b023dad6692aa7f972fa696c20a2373244fdf8a8590098f683b870"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-23 19:29:58"
  condition:
    hash.sha256(0, filesize) == "986318d491b023dad6692aa7f972fa696c20a2373244fdf8a8590098f683b870"
}
```

### Sample 50: `217d39d16431539d`

| Field | Value |
|---|---|
| SHA-256 | `217d39d16431539d00b1ef2a7fd750cc03cf7d7180ae530854a0f1565ec88b64` |
| Family label | `unknown` |
| File name | `OZONE_TRAGIC.vbs` |
| File type | `vbs` |
| First seen | `2026-06-23 19:29:22` |
| Reporter | `BastianHein_` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0311e9e9e142e4ec5d521c5c7fa3038` |
| SHA-1 | `246e49c26ff2703104a5d49c8c21acd3cc4b4cd4` |
| SHA-256 | `217d39d16431539d00b1ef2a7fd750cc03cf7d7180ae530854a0f1565ec88b64` |
| SHA3-384 | `9781911f5647b3cde11dccb70b660d84538ee8b54d3fb31fc5e7f9224c6ba5e6ef26251a3c758dd0d6559a9e3f61683b` |
| TLSH | `T1A6C02B27D409CB3C0802C0B70931A90CC8A0CC1E270C7A750E10D12C6079964A69A1C2` |
| SSDEEP | `3:FER/n0eFHfBw+7EwOIkVViE2J5xAIfk2AUwD9Hlqi0aoMLjBv:FER/lFHfBpsBn23ffkqwOi0aoMRv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_217d39d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "217d39d16431539d00b1ef2a7fd750cc03cf7d7180ae530854a0f1565ec88b64"
    family = "unknown"
    file_name = "OZONE_TRAGIC.vbs"
    file_type = "vbs"
    first_seen = "2026-06-23 19:29:22"
  condition:
    hash.sha256(0, filesize) == "217d39d16431539d00b1ef2a7fd750cc03cf7d7180ae530854a0f1565ec88b64"
}
```

### Sample 51: `905de1d2354b45a0`

| Field | Value |
|---|---|
| SHA-256 | `905de1d2354b45a04ffcb5af4410eb6ac3410bb1c411acce521d18850f2e8e6f` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-23 19:19:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78e17089d51d7613b2cb94c3b7832d66` |
| SHA-1 | `d6c6c80a63f9b7578cb5321fab700239da700233` |
| SHA-256 | `905de1d2354b45a04ffcb5af4410eb6ac3410bb1c411acce521d18850f2e8e6f` |
| SHA3-384 | `74975d48f25273edc569970069aa1d5e22e34dfb8d9a6f8d91668030561d62ecb57569023724939587be3aa446fca358` |
| TLSH | `T143637D0273184E63C5232E74683F6BC19355DA9521F9D2492A1F6B0FC1F2E71994AEEC` |
| SSDEEP | `1536:yTmqWyWpKmsYx01vBqBOu5Z08hBBAMJxwyeNOMqrthIYJhRid:y+lky3wTOnhIKQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_905de1d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "905de1d2354b45a04ffcb5af4410eb6ac3410bb1c411acce521d18850f2e8e6f"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-23 19:19:59"
  condition:
    hash.sha256(0, filesize) == "905de1d2354b45a04ffcb5af4410eb6ac3410bb1c411acce521d18850f2e8e6f"
}
```

### Sample 52: `41137fe5e25ea1ba`

| Field | Value |
|---|---|
| SHA-256 | `41137fe5e25ea1ba86c55f34a484003234f43ab6e2611733eb0b325f4efff608` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 19:15:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc1b2cdf9798bbd678744f090be5b534` |
| SHA-1 | `3475e2ac0a91014ba4c5e6cb6d7eb26533f5c770` |
| SHA-256 | `41137fe5e25ea1ba86c55f34a484003234f43ab6e2611733eb0b325f4efff608` |
| SHA3-384 | `aa8a3106cb1d36961f04ece3f1a219a83b70d6413ce3f8ec4061786f6ab7f05ec4968c391f6b1c4d440d0f56c179d1a7` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1AFE59D06ACE109F9C89DA37144A22656BF75BC450F3563C76F90BB382E72BE06C36758` |
| SSDEEP | `49152:vKKHv0IV4zfIqSYsN5rNlVi69UTk/IHR4X+QTnmL67lm66NoVm:vKYvoIYork61/IHEmLC2NoI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_41137fe5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41137fe5e25ea1ba86c55f34a484003234f43ab6e2611733eb0b325f4efff608"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 19:15:23"
  condition:
    hash.sha256(0, filesize) == "41137fe5e25ea1ba86c55f34a484003234f43ab6e2611733eb0b325f4efff608"
}
```

### Sample 53: `2a2bdf134906d132`

| Field | Value |
|---|---|
| SHA-256 | `2a2bdf134906d1327b3b4f2603955749da1505c0875549cd9cf8b16aa99fa034` |
| Family label | `unknown` |
| File name | `curl.sh` |
| File type | `sh` |
| First seen | `2026-06-23 19:10:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50193974424019fd70e906e83c24cfa7` |
| SHA-1 | `5bce2e865477cddab7026f57fdefdcccf6d7b25c` |
| SHA-256 | `2a2bdf134906d1327b3b4f2603955749da1505c0875549cd9cf8b16aa99fa034` |
| SHA3-384 | `8b84bdc71aff49d162a288644472c8adc9963ee7a0b5f934198b269d63b60e2e330ecefd1d58363b67fd81c15ea8ae91` |
| TLSH | `T121215CC813A067F38ED8D940B96399EDB06D04D77E1798E4A4084AE36F563C6FC1C36A` |
| SSDEEP | `24:VB59HBqg5vFByqBC1IBdBnBdTcqBVBNB4bGBvf3ByClBkgByUT13BpuBW:rThzd7jC18DBdo6rTNxyCTy6x8g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_2a2bdf13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a2bdf134906d1327b3b4f2603955749da1505c0875549cd9cf8b16aa99fa034"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:10:59"
  condition:
    hash.sha256(0, filesize) == "2a2bdf134906d1327b3b4f2603955749da1505c0875549cd9cf8b16aa99fa034"
}
```

### Sample 54: `6db456f1326888b6`

| Field | Value |
|---|---|
| SHA-256 | `6db456f1326888b6aaf8ec8ea2a050a5008c587222ed861bfa2af72754857809` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-06-23 19:10:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0f1ae6408a908fa92f2dec092817efd` |
| SHA-1 | `c23afa5fa0c9e41ee987ef55b79ac7cfb0e2e127` |
| SHA-256 | `6db456f1326888b6aaf8ec8ea2a050a5008c587222ed861bfa2af72754857809` |
| SHA3-384 | `bc64d41fd11ad6681ba8334143689ed3f7563c5f798f8ca18c5748ef410c07349b410a9c5eb706c80a0f9bdca291aeec` |
| TLSH | `T165316FCB41205A381743CADFB3A23589A00CD5FB2D9BC398A94C5FAD43486CCB5A5BC1` |
| SSDEEP | `12:UdXNC76dXNKksT6YG7jjnc2l3Ei63EXgNe76UbG6bjG9EYO60TGalKaHr6KaNvTQ:m5FEpEwUhGXaWJL6nFTMOZBRqs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_6db456f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db456f1326888b6aaf8ec8ea2a050a5008c587222ed861bfa2af72754857809"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-23 19:10:58"
  condition:
    hash.sha256(0, filesize) == "6db456f1326888b6aaf8ec8ea2a050a5008c587222ed861bfa2af72754857809"
}
```

### Sample 55: `957adb4a56c1bcb7`

| Field | Value |
|---|---|
| SHA-256 | `957adb4a56c1bcb7eb11247b5b28a501ddb4ab5a425a440163fbf6f15f44a95e` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-23 19:06:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ad602950b7267e708b066a63f2f1977` |
| SHA-1 | `4aa503fe7230b7545dbe74ad570ca544ffb55040` |
| SHA-256 | `957adb4a56c1bcb7eb11247b5b28a501ddb4ab5a425a440163fbf6f15f44a95e` |
| SHA3-384 | `5b61a30bb7a5760bd4c2775a84b0d369f1817a07d09f6c1e6811bcfa348076046ccae60b12d24df9e5632ac72725ed34` |
| TLSH | `T14593E91E6E218FADF36DC33447B74E26E79833C626E1D645D16CD6006E7028E641FBA8` |
| TELFHASH | `t1e0116018893423f0977a1c892bedff76e59130df0b266e378e10f96daa6d9429d00d1c` |
| SSDEEP | `1536:vikAzdBJ0IaAuUm7l5NufmSB0cs7seHQj0aUu1eayn8Bp:O5BiDQfTs7sewj0aXu8Bp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_957adb4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "957adb4a56c1bcb7eb11247b5b28a501ddb4ab5a425a440163fbf6f15f44a95e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-23 19:06:57"
  condition:
    hash.sha256(0, filesize) == "957adb4a56c1bcb7eb11247b5b28a501ddb4ab5a425a440163fbf6f15f44a95e"
}
```

### Sample 56: `dc154a86d0e2eb63`

| Field | Value |
|---|---|
| SHA-256 | `dc154a86d0e2eb63bbbf88e5632bbddc318a47b4f01e157653f19cb2ada8c501` |
| Family label | `Mirai` |
| File name | `giga.sh` |
| File type | `sh` |
| First seen | `2026-06-23 19:01:03` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6fb321f248219264ea5713459e6b838` |
| SHA-1 | `f136c943392a73bef0f6534e5d8eea939c952339` |
| SHA-256 | `dc154a86d0e2eb63bbbf88e5632bbddc318a47b4f01e157653f19cb2ada8c501` |
| SHA3-384 | `cc868df416635d93f248296e369ba2f23ed8c8eff9087aed8d1f5f94005b744be9b5e4888155d119a49b320d5cd3db4a` |
| TLSH | `T1C9E065A9B82539A20514ED75F4714616E19BEB81222DA30CB28D363B48DC600B53CEC6` |
| SSDEEP | `6:J+hJ+jphviRejw9hviRetYNm9hviRevaa0LKiE9hviR+I89hviRIWTJep:uJ+jphviR9hviRAYNkhviR60LKDhviRQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_dc154a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc154a86d0e2eb63bbbf88e5632bbddc318a47b4f01e157653f19cb2ada8c501"
    family = "Mirai"
    file_name = "giga.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:01:03"
  condition:
    hash.sha256(0, filesize) == "dc154a86d0e2eb63bbbf88e5632bbddc318a47b4f01e157653f19cb2ada8c501"
}
```

### Sample 57: `2e539ddf3488114b`

| Field | Value |
|---|---|
| SHA-256 | `2e539ddf3488114badd7f63eea1f77529780729f151102e290dfb96e70d45ffb` |
| Family label | `Mirai` |
| File name | `jkL` |
| File type | `elf` |
| First seen | `2026-06-23 18:58:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95a1fa12feb542817329f255290cd536` |
| SHA-1 | `6d243f78f3aa9126ac51d515a88029ff6d03c131` |
| SHA-256 | `2e539ddf3488114badd7f63eea1f77529780729f151102e290dfb96e70d45ffb` |
| SHA3-384 | `c5326680357fb9ed64eaf12070f6cb719e1b83327b338869e49cc21e420a01d976a0c94f0a827cb8211e5c04dce7290c` |
| TLSH | `T163933A5ABC82AE56C6D20576FF1E438D331653ECD2EB7113F9145F6D338B95A0E2A082` |
| TELFHASH | `t183d0a7108a0e7bdc37e12996418d631e0eb0387b3795b5999ffcae029c135d5705e034` |
| SSDEEP | `1536:4tC9txWhuQOhROtLuJBd1eDmBOC1bLV8aNa8Fg1S8e2vL7l9noiA1rxTvMk0TrKj:ZxwuRiUbsDmQCVh1BFg1S8e2vTM1rVMU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_2e539ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e539ddf3488114badd7f63eea1f77529780729f151102e290dfb96e70d45ffb"
    family = "Mirai"
    file_name = "jkL"
    file_type = "elf"
    first_seen = "2026-06-23 18:58:56"
  condition:
    hash.sha256(0, filesize) == "2e539ddf3488114badd7f63eea1f77529780729f151102e290dfb96e70d45ffb"
}
```

### Sample 58: `e6192766dab3f329`

| Field | Value |
|---|---|
| SHA-256 | `e6192766dab3f32979ea6d7e28614006031901cafba6354204fdb8fa32ab9308` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-06-23 18:55:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eab8a6541fd67e098a7f4c762339d348` |
| SHA-1 | `68ad80f971abb85260c73a24e404814bb8ef77bf` |
| SHA-256 | `e6192766dab3f32979ea6d7e28614006031901cafba6354204fdb8fa32ab9308` |
| SHA3-384 | `71c2cf8abf5faaf720d71d070cc1ea2f6f924d5a8f91b5ea95471b8d382c55684d8fd9135c475a13d42b344c587e5470` |
| TLSH | `T1BD043A02B31C0947D1632EF43A3B27E0D3EF9AA220A8F645754F9A8D9172D375586DCE` |
| SSDEEP | `3072:/QvGNhxfqqeK8NZcp+6DdsNxYxpDRClEJVtyfpNa:VXq9tgp+sSxYxpDRCWJVE7a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_e6192766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6192766dab3f32979ea6d7e28614006031901cafba6354204fdb8fa32ab9308"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-06-23 18:55:58"
  condition:
    hash.sha256(0, filesize) == "e6192766dab3f32979ea6d7e28614006031901cafba6354204fdb8fa32ab9308"
}
```

### Sample 59: `eda549f5480a2ca4`

| Field | Value |
|---|---|
| SHA-256 | `eda549f5480a2ca44d6eabac11309abf5dbd6467da22384526754a418a6fa4ab` |
| Family label | `Mirai` |
| File name | `pFdY` |
| File type | `elf` |
| First seen | `2026-06-23 18:55:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f5a27fc366d327c3df82c61c822a8d4` |
| SHA-1 | `e6570c710e337daab108536f218cecd3cc1ce4fb` |
| SHA-256 | `eda549f5480a2ca44d6eabac11309abf5dbd6467da22384526754a418a6fa4ab` |
| SHA3-384 | `548530a9e8971cd709e3e2eacbd30ff55a76bb98d2aa4f63c68dd17a743159fa1b4065c8e702cd0f5e1dc8190eae2475` |
| TLSH | `T1DFC3D80ABF502DBBD81FCD3309E9165234CC9647629937B53574DB2CFA4A94A0AE3CB4` |
| SSDEEP | `1536:ExmLEwS95nKXDtidrUs/zEtjzR7edgIovhYccrIk0TrKJ01J6nJIjwAu:1L/LDcpCeWhqIlTHOCjTu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_eda549f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda549f5480a2ca44d6eabac11309abf5dbd6467da22384526754a418a6fa4ab"
    family = "Mirai"
    file_name = "pFdY"
    file_type = "elf"
    first_seen = "2026-06-23 18:55:57"
  condition:
    hash.sha256(0, filesize) == "eda549f5480a2ca44d6eabac11309abf5dbd6467da22384526754a418a6fa4ab"
}
```

### Sample 60: `905048266f359367`

| Field | Value |
|---|---|
| SHA-256 | `905048266f359367fea147487dce73f4f7c40c631fa9e0dffc74cdebc787db33` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-23 18:50:19` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffd71bf93f26ad93aaa454fbb6c77fe5` |
| SHA-1 | `8d432ac2b8d92bd9eab04186340536c155888b00` |
| SHA-256 | `905048266f359367fea147487dce73f4f7c40c631fa9e0dffc74cdebc787db33` |
| SHA3-384 | `8cefd972acb7f077494659241f13b6c4fbb74d752f6116ae02c1bafd327b0cf6732a07a3968a3ad8a0d3e883671532a4` |
| TLSH | `T16985CF8951BB8198E7C57434B7E56A0DCD29BEDE1CA19DDFBE13302029A975108FC32B` |
| SSDEEP | `49152:NvIuccRY01hY6U/M7eAFPoDW7F1L57kyASC1:NvCy1hYx/MKSwDW3L1kbSs` |
| ICON-DHASH | `68f0e8cccce8f068` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_90504826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "905048266f359367fea147487dce73f4f7c40c631fa9e0dffc74cdebc787db33"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 18:50:19"
  condition:
    hash.sha256(0, filesize) == "905048266f359367fea147487dce73f4f7c40c631fa9e0dffc74cdebc787db33"
}
```

### Sample 61: `f12584fdad83aaf7`

| Field | Value |
|---|---|
| SHA-256 | `f12584fdad83aaf73c7ef360542d0bf0c4aeff3754774added2fd2b7c1af2111` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-06-23 18:48:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90854e9bc66b261666e04a346c8dba49` |
| SHA-1 | `56ef7365656575a679d5a834fab0639df1b4d11f` |
| SHA-256 | `f12584fdad83aaf73c7ef360542d0bf0c4aeff3754774added2fd2b7c1af2111` |
| SHA3-384 | `1d5705cf8d9944ea31036f39a02566aa9d4bc2e9dd94b93ac4abc0632947052157d9d84f49bb4023a0e3fc62ac2262b7` |
| TLSH | `T152F38D33D8396F98D268D8B0B0318F792B93957581435F6AA577C6B58083E8DF9053F8` |
| SSDEEP | `3072:UzxZU+o6DLcDC9RMemrGEyeIDWoHfest5p:UzRLcW9RMemaJSoGs9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_f12584fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12584fdad83aaf73c7ef360542d0bf0c4aeff3754774added2fd2b7c1af2111"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-06-23 18:48:55"
  condition:
    hash.sha256(0, filesize) == "f12584fdad83aaf73c7ef360542d0bf0c4aeff3754774added2fd2b7c1af2111"
}
```

### Sample 62: `498c098e3b2fb515`

| Field | Value |
|---|---|
| SHA-256 | `498c098e3b2fb515b0cc8f7169ba45b7a7669aa0b7531ff0806b6e1b2469c699` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-06-23 18:46:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fb8509159b7eda40fcde6fbdcdfc707` |
| SHA-1 | `132b4158296edd7f9606ab9402730aa16d89b33f` |
| SHA-256 | `498c098e3b2fb515b0cc8f7169ba45b7a7669aa0b7531ff0806b6e1b2469c699` |
| SHA3-384 | `02e65623ab0a007a95db94ee0a57b78c6935d3c3ba8d337cbd9b4deb0f59198ff9f4710523c6b97d33dc960301735c6c` |
| TLSH | `T11B833A86F653E0F1DE4205B0059BF77B6A709D221A60EE6FEB4CFD77A932603640625C` |
| TELFHASH | `t15e312cb90fb10cecb7c04402e14a57616f3da33f655439a342b3747037aaa01506bc3c` |
| SSDEEP | `1536:B4cPAc2QwCbwmUnqexMcShxwnhzhhhjh3hShsZbIKyLXo0uWUO31kUQwJr:MUMqeCjhuzEtkeaW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_498c098e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "498c098e3b2fb515b0cc8f7169ba45b7a7669aa0b7531ff0806b6e1b2469c699"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-06-23 18:46:58"
  condition:
    hash.sha256(0, filesize) == "498c098e3b2fb515b0cc8f7169ba45b7a7669aa0b7531ff0806b6e1b2469c699"
}
```

### Sample 63: `d025a29613e300d7`

| Field | Value |
|---|---|
| SHA-256 | `d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677` |
| Family label | `unknown` |
| File name | `AggregatorHost.exe` |
| File type | `exe` |
| First seen | `2026-06-23 18:45:33` |
| Reporter | `smica83` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37654729cfcd619ba86a0a0dfb98a25a` |
| SHA-1 | `be3d246a53dbe049b815ea8948aa27ce0cc652f1` |
| SHA-256 | `d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677` |
| SHA3-384 | `d022f2719a32d1e973d578a6a708edc0b62d8a08e3a461d10b3e0acce80f477d30557cc28bdbd1f31e9b50417a453afb` |
| IMPHASH | `0bf36ccc4342474cda07e3cac8156bc7` |
| TLSH | `T1D9B68F1F7BD878F299B6F1AB4AE3DC7D960B600007121CEB59874AE840197DBAFB111D` |
| SSDEEP | `49152:7DzDl71lxnRLLeIpq8HwNI7LUk4BelM8jZfmf:7DzDlVn5yz84I76+j5mf` |
| ICON-DHASH | `eaee8a9ea69ae8b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_d025a296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677"
    family = "unknown"
    file_name = "AggregatorHost.exe"
    file_type = "exe"
    first_seen = "2026-06-23 18:45:33"
  condition:
    hash.sha256(0, filesize) == "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677"
}
```

### Sample 64: `cf9cf23f8cccdafc`

| Field | Value |
|---|---|
| SHA-256 | `cf9cf23f8cccdafcd066cc2e7a96dbe0a793f193e6f0fd21797698801282dc60` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-06-23 18:43:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3466c608ca9d55a5a99a3c43fffa3cb` |
| SHA-1 | `97bc875fe330dfd1a1a7a61bb4d2701a66c66d55` |
| SHA-256 | `cf9cf23f8cccdafcd066cc2e7a96dbe0a793f193e6f0fd21797698801282dc60` |
| SHA3-384 | `ed1bf643e7f9fee6d1b3347a271c6fee9d977edc16dfbc1f89edbf8c18389d6a829f65784facca64ed18081878c4ae18` |
| TLSH | `T1D3042A85B9819A17C6D612BBFB4E428D372A63A8D3EE3103DD155F2137CB95B0E3B141` |
| TELFHASH | `t128a00226cf5403cd1b414841d5f8565196923b4e1755009a825c5e465ed3800e489922` |
| SSDEEP | `3072:alvbNLbMkrlmSk6beZDdOWGx4uxlpZPCGJLrqwrHWh:wMO+7Cx4u3pQaLrtr8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_cf9cf23f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf9cf23f8cccdafcd066cc2e7a96dbe0a793f193e6f0fd21797698801282dc60"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-06-23 18:43:56"
  condition:
    hash.sha256(0, filesize) == "cf9cf23f8cccdafcd066cc2e7a96dbe0a793f193e6f0fd21797698801282dc60"
}
```

### Sample 65: `e0d719ffa8d2aece`

| Field | Value |
|---|---|
| SHA-256 | `e0d719ffa8d2aecec83055d7a5151e6a3f2eb5a6bd1b53dab2319488b639acf3` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-23 18:43:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `587b45f62d2be601e0abdec529774939` |
| SHA-1 | `7e3abb9d21b001a8c28f55500c10db6eb1e88ce0` |
| SHA-256 | `e0d719ffa8d2aecec83055d7a5151e6a3f2eb5a6bd1b53dab2319488b639acf3` |
| SHA3-384 | `fa69728aeb3630a6504049dc2e0627ee04edd79aa91f00b0acdeaacf00fcb3aa123d6eeb259f7043117986b42dccba80` |
| TLSH | `T1FD634C06B892CA56D6D5627ABA5E918C331213F4D2DF3303DC15EFB97BC681A0E7B484` |
| TELFHASH | `t19c4102f79fa10eec5bf69654954ab0294ff8388a5f2430838a0cb74fd902582f03d827` |
| SSDEEP | `1536:jjf6p5AoCVmkdtrjXoRCxtCkoYDut+q3jPUR4fs4l1eW:Xf6p5AoCVmkdtnoRItCkrG+q3YZ4m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_e0d719ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d719ffa8d2aecec83055d7a5151e6a3f2eb5a6bd1b53dab2319488b639acf3"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-23 18:43:54"
  condition:
    hash.sha256(0, filesize) == "e0d719ffa8d2aecec83055d7a5151e6a3f2eb5a6bd1b53dab2319488b639acf3"
}
```

### Sample 66: `5f7b9c0fa02fc95f`

| Field | Value |
|---|---|
| SHA-256 | `5f7b9c0fa02fc95f6176500164e58ad9d99065df7521d235b3d5750817e1f5ba` |
| Family label | `unknown` |
| File name | `.suzUwa2` |
| File type | `macho` |
| First seen | `2026-06-23 18:42:43` |
| Reporter | `arrr` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7d47a1cb97a233ec7b40d628137be31` |
| SHA-256 | `5f7b9c0fa02fc95f6176500164e58ad9d99065df7521d235b3d5750817e1f5ba` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_5f7b9c0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f7b9c0fa02fc95f6176500164e58ad9d99065df7521d235b3d5750817e1f5ba"
    family = "unknown"
    file_name = ".suzUwa2"
    file_type = "macho"
    first_seen = "2026-06-23 18:42:43"
  condition:
    hash.sha256(0, filesize) == "5f7b9c0fa02fc95f6176500164e58ad9d99065df7521d235b3d5750817e1f5ba"
}
```

### Sample 67: `659236dcdf220426`

| Field | Value |
|---|---|
| SHA-256 | `659236dcdf22042685c1b906dbe5f4a904cacbb1343cb6860d08c37fe1bd4810` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-06-23 18:40:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `159cb87b7abfb4e18dc3e21dc2317281` |
| SHA-1 | `284dffd5c86dd496bf7f0e69d6be7e027b972da4` |
| SHA-256 | `659236dcdf22042685c1b906dbe5f4a904cacbb1343cb6860d08c37fe1bd4810` |
| SHA3-384 | `bb75090ae02cc783fbe52b82182da9636202bcd7b019b3b384ed8ae7b427e04afccb1e55e708419a24f306a7bddab601` |
| TLSH | `T179B33A077952CA63D1C217B97A9F915C3723A7B5C39B33029914AFF82F836CA0E7A511` |
| TELFHASH | `t1562142b6e934d53ead720920dc5d4af11110e327632d0d32af38c1dc1e3a082e52ad6f` |
| SSDEEP | `1536:cbnq6aPilI7AIA4GCK8aQUAW3fDQdMei+ZkLl1Oy9mtpIMf9kMza:PtPilI7CtCK8zUbmZkLl1hmjNFb+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_659236dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "659236dcdf22042685c1b906dbe5f4a904cacbb1343cb6860d08c37fe1bd4810"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-23 18:40:54"
  condition:
    hash.sha256(0, filesize) == "659236dcdf22042685c1b906dbe5f4a904cacbb1343cb6860d08c37fe1bd4810"
}
```

### Sample 68: `420f1931af9b3f7d`

| Field | Value |
|---|---|
| SHA-256 | `420f1931af9b3f7d02c5edfc78eb69abdad6e71d2c3e9b81f9cbc3823a503654` |
| Family label | `unknown` |
| File name | `взвод розвідки.rar` |
| File type | `rar` |
| First seen | `2026-06-23 18:39:41` |
| Reporter | `smica83` |
| Tags | `CVE-2025-8088, rar, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13c5106e4ba2f8fca72a0c96b4dd7b55` |
| SHA-1 | `72932a87991193f5ed854a386104330e6a32a6cd` |
| SHA-256 | `420f1931af9b3f7d02c5edfc78eb69abdad6e71d2c3e9b81f9cbc3823a503654` |
| SHA3-384 | `a798d4dd02547e9347864e0e96b296b100cbb6a832f05a67b8e43a9219cc157d299e51ad5be631276e4743207f5d6b0f` |
| TLSH | `T1FCF4235AF9B46C93C51C3CAC34DB2D0E374DC885100AF636B3651D92C1A4EF069DB6E9` |
| SSDEEP | `12288:I4cq+X4ORV5X0EzFn+LTB+moylsd64N03TAxw4DcYcwx+Fwqvjk4hu0KrlNsi:7tQj5jZ+wclL423TT4bLxBqvQ4+rgi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_420f1931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420f1931af9b3f7d02c5edfc78eb69abdad6e71d2c3e9b81f9cbc3823a503654"
    family = "unknown"
    file_name = "взвод розвідки.rar"
    file_type = "rar"
    first_seen = "2026-06-23 18:39:41"
  condition:
    hash.sha256(0, filesize) == "420f1931af9b3f7d02c5edfc78eb69abdad6e71d2c3e9b81f9cbc3823a503654"
}
```

### Sample 69: `5cbba8fb45956d61`

| Field | Value |
|---|---|
| SHA-256 | `5cbba8fb45956d619f6d0f407f4a2f92f06c291611190f6b0f46d22bdc2cf3e3` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-23 18:38:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5980f1fc18d9d0cb486a5e1c9620481c` |
| SHA-1 | `55b8763c8e8ad3b5017b4eb72815ea6e45355493` |
| SHA-256 | `5cbba8fb45956d619f6d0f407f4a2f92f06c291611190f6b0f46d22bdc2cf3e3` |
| SHA3-384 | `e07a2b813b33c233829c31a307d07d4cfd65b236c8d81c2bd5e9d9fdaf1635fe5e0c964618ec03d942a2086e2513232b` |
| TLSH | `T165B35D5BAA9E3EDBC2C2437C8E866A702107F4798F07C3721F15539DAE9EE9C9C95050` |
| TELFHASH | `t1362102f5ed35d12d6e510674cc9d49b09110f717632e0e31ef38c5e85e3a091a11a9af` |
| SSDEEP | `1536:c+gEuHpklZHeip9nSCX4zBMd9kHKQbJxVyzsts6iUS:cHE+U99nQMoKGAsQU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_5cbba8fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cbba8fb45956d619f6d0f407f4a2f92f06c291611190f6b0f46d22bdc2cf3e3"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-23 18:38:53"
  condition:
    hash.sha256(0, filesize) == "5cbba8fb45956d619f6d0f407f4a2f92f06c291611190f6b0f46d22bdc2cf3e3"
}
```

### Sample 70: `efe00769b8fd2a79`

| Field | Value |
|---|---|
| SHA-256 | `efe00769b8fd2a79068c28f58300d6eeb236339096f9c7d6789835238f3d3973` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-06-23 18:37:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c00943ca1a96010834cd7474257f5389` |
| SHA-1 | `03725e4c1be4a7f69678e7638b366bb6a78147bb` |
| SHA-256 | `efe00769b8fd2a79068c28f58300d6eeb236339096f9c7d6789835238f3d3973` |
| SHA3-384 | `efd91a60d88cd5a773a07e432684e84d39d6ae437f0c7eec2476d07fa082c1a73bf258cad59242d42354b9ed22b8837c` |
| TLSH | `T181441946FB404A13C4D617BAEA9F42453333E768D3EB73069928AFB43BC775A0E62505` |
| TELFHASH | `t1f341fb718b74112a9aa1dd14d9ee97b2241edb1b5344fe77de31c48c280949fe927c0f` |
| SSDEEP | `6144:/vEma6tytRoZgJA8aZsIvYvkCViz+1GmidjAV/GT4m62qYNs:XEma6tyQZgJFaZsIvYvkUCU8g/Xm6BYC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_efe00769
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efe00769b8fd2a79068c28f58300d6eeb236339096f9c7d6789835238f3d3973"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-06-23 18:37:52"
  condition:
    hash.sha256(0, filesize) == "efe00769b8fd2a79068c28f58300d6eeb236339096f9c7d6789835238f3d3973"
}
```

### Sample 71: `77b37c072672991e`

| Field | Value |
|---|---|
| SHA-256 | `77b37c072672991e4cdc0f639dc8c13682eb1d2fde1a3a73f9b19b4a01b81cae` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-06-23 18:32:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81383dac16f142f7de9c52f09c2dd605` |
| SHA-1 | `31520ac3b8eac9f5b679a45caac7ae8b37ffda13` |
| SHA-256 | `77b37c072672991e4cdc0f639dc8c13682eb1d2fde1a3a73f9b19b4a01b81cae` |
| SHA3-384 | `0edac324786c1105dc6bc8d03a03613c2efaab547a07fc043d2ac5cdba9d0346605cef473eee4388252e7a1ff88ed18e` |
| TLSH | `T17C214BC912A067F38ED8C94079539CADB06D49D77A078AEC284C0AF36E52B96FC1CF55` |
| SSDEEP | `24:sB5gHBqV5vFBRqBC1RBgBKBdTTqBkBnIB+RBEf3BykzgByMsBM93BGSN:gGhqd7kC1nEadv6I8WEyLyTOxRN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_77b37c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77b37c072672991e4cdc0f639dc8c13682eb1d2fde1a3a73f9b19b4a01b81cae"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-06-23 18:32:53"
  condition:
    hash.sha256(0, filesize) == "77b37c072672991e4cdc0f639dc8c13682eb1d2fde1a3a73f9b19b4a01b81cae"
}
```

### Sample 72: `a21766a2df35e45d`

| Field | Value |
|---|---|
| SHA-256 | `a21766a2df35e45db59e0a6dbfeb7c8862fb9e77710c9f8f589b7a9b96c99bb9` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-23 18:25:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47ff45fc70ffbd5be2fff1344dcc8ed5` |
| SHA-1 | `23656f1893c6e41960ababa16dd20257bbfb1643` |
| SHA-256 | `a21766a2df35e45db59e0a6dbfeb7c8862fb9e77710c9f8f589b7a9b96c99bb9` |
| SHA3-384 | `22fa382288188fbc78d9bd310661d20db7cd766b20e2e8dd408ac5fb017a48b9c72eef99ad734e23ba7c7df44f4a81ab` |
| TLSH | `T12EA3D80AEF600EF7EC6FCD3706A91B0634CC651A12A97B357A78D92CF91A20B55D3C64` |
| SSDEEP | `1536:u+kMoJdVZCSXVK1t0oub9ZH+SWjw+ZgLioV4Reu7VeZgh+FkgVFXj:u+kMQzZCi8IoE9ZH+S5+Qgeu7VebXnj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_a21766a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a21766a2df35e45db59e0a6dbfeb7c8862fb9e77710c9f8f589b7a9b96c99bb9"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-23 18:25:55"
  condition:
    hash.sha256(0, filesize) == "a21766a2df35e45db59e0a6dbfeb7c8862fb9e77710c9f8f589b7a9b96c99bb9"
}
```

### Sample 73: `352e4045388a0b3c`

| Field | Value |
|---|---|
| SHA-256 | `352e4045388a0b3cb12b29024b4da60f664fc7c7b5d17911bb16869073763b1f` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-06-23 18:21:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `206d74363bc15acc63d110aff566916c` |
| SHA-1 | `b4c018280d705c96b7dfaa9e1fbe2424a3fe60bb` |
| SHA-256 | `352e4045388a0b3cb12b29024b4da60f664fc7c7b5d17911bb16869073763b1f` |
| SHA3-384 | `ed24bdc9fb235dbb4a5e1fb21de3a8519250446cf92a581503ca96400c91e6d2fb250d259cd105ca3e98af1030b584e5` |
| TLSH | `T1DCF38C87F7265C97CC910BF94B8B5B8C5BA311418F6BCBD63D0C66350E6A9CE5D0A382` |
| TELFHASH | `t154311fa6e939c52d6ea11924ec5d4fb18110d727a3291e31af3cc1dc4d3f082a469d6f` |
| SSDEEP | `3072:AA/PH/BWUvQsYzHXI5mNhSXygQUohqardrAcmqcE:AA/P5WDXKwYchqomqcE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_352e4045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "352e4045388a0b3cb12b29024b4da60f664fc7c7b5d17911bb16869073763b1f"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-06-23 18:21:54"
  condition:
    hash.sha256(0, filesize) == "352e4045388a0b3cb12b29024b4da60f664fc7c7b5d17911bb16869073763b1f"
}
```

### Sample 74: `9a00b4bcbb081c1f`

| Field | Value |
|---|---|
| SHA-256 | `9a00b4bcbb081c1fa2b581fd82a00336f77788c0080a6255c3628fa641b0bfac` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-23 18:09:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a12fce25ab9319712b465b6207f8cdfb` |
| SHA-1 | `e94cfabf826166037e36f4793d439b89fb0e82c1` |
| SHA-256 | `9a00b4bcbb081c1fa2b581fd82a00336f77788c0080a6255c3628fa641b0bfac` |
| SHA3-384 | `83e041460f906cf13222baa4a15410fad8a195d1a59819ea90e0cee89e5f5b7f90df6b07cc328c5080e3f19b6ebb16cd` |
| TLSH | `T1ADE34B07FB418A53C4D227B97A9F9245332397A5D3E7330689189FF83F83A9A0E36505` |
| TELFHASH | `t1c42110b6e934d53eae720924dd5d4af11110e317632d0e32af38c5ec1e3a092e56ad6f` |
| SSDEEP | `3072:VVG30ZnPdK2YA2k/+F2AJGSKqiWe4FjPSpM/9C4N:VE3WnPdK2YA2WA2AJGS1iojPgM/9C4N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_9a00b4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a00b4bcbb081c1fa2b581fd82a00336f77788c0080a6255c3628fa641b0bfac"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-23 18:09:52"
  condition:
    hash.sha256(0, filesize) == "9a00b4bcbb081c1fa2b581fd82a00336f77788c0080a6255c3628fa641b0bfac"
}
```

### Sample 75: `9ea203e9d1d9da97`

| Field | Value |
|---|---|
| SHA-256 | `9ea203e9d1d9da977a7d667f10e7ceb273bbe9964589c7bf7e9d5600c498bc3c` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-06-23 18:08:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a66797f9b5dcfe2d9aa793b16dbe0b4` |
| SHA-1 | `1a74e84992837e8a8a09985c396d0dc17f05fcaa` |
| SHA-256 | `9ea203e9d1d9da977a7d667f10e7ceb273bbe9964589c7bf7e9d5600c498bc3c` |
| SHA3-384 | `409316d2d1cbf7c5c17c10b7afa70cab0b616b54ee0e912fcd9fb297dd72a9d800baca3478ef6cd8172327c2afc8ef20` |
| TLSH | `T163836D32BA746827C4C4A77E36EB4374B1F7470635F8C92EBC224E6DBB005502666B79` |
| SSDEEP | `1536:XLpG5KLhhxM8xLsgvBo3+yRhdjKZQ1lc1io+b2:XLpG4Hizgi3+yRI1io9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_9ea203e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea203e9d1d9da977a7d667f10e7ceb273bbe9964589c7bf7e9d5600c498bc3c"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-06-23 18:08:50"
  condition:
    hash.sha256(0, filesize) == "9ea203e9d1d9da977a7d667f10e7ceb273bbe9964589c7bf7e9d5600c498bc3c"
}
```

### Sample 76: `099dea0ac240df11`

| Field | Value |
|---|---|
| SHA-256 | `099dea0ac240df1145eac6d54f02eef064ca7cb2b5791ead83fb77947ccb176c` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-23 18:05:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0ad86fd51981397d41cde0fe6a4ad88` |
| SHA-1 | `2d8007b046ce684ba41cfcbe519c655da3959e1f` |
| SHA-256 | `099dea0ac240df1145eac6d54f02eef064ca7cb2b5791ead83fb77947ccb176c` |
| SHA3-384 | `b587fa4dc8f3bf22219044b3d80bcb419fe927762bfbbbebbee531d4314375562bfd941b8d940a4127b282fbc2a6981d` |
| TLSH | `T11B93184ABC819B11D9C522BAFE4E118E33236B6CE3EE7112DD245F2427CA65B0F77512` |
| TELFHASH | `t101d0a7a207bd2ad997ce90c948ff113f16e8f0fe6f0d541a74c07d478083411f026041` |
| SSDEEP | `1536:PgnbKX29UCoKebynbte4LcnwbZRtIxdrAkaTi0AvO6NsJma7Uil02i9JODRbOY70:VX29UC1ebk5e4QnwbZADr/aXA26NsGVV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_099dea0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "099dea0ac240df1145eac6d54f02eef064ca7cb2b5791ead83fb77947ccb176c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-23 18:05:53"
  condition:
    hash.sha256(0, filesize) == "099dea0ac240df1145eac6d54f02eef064ca7cb2b5791ead83fb77947ccb176c"
}
```

### Sample 77: `df0e1923c70de2bb`

| Field | Value |
|---|---|
| SHA-256 | `df0e1923c70de2bb0022944ab02b998e0dc57cc3da6a528063241d5572d8db83` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-06-23 18:04:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf33d691d962dcdd781c85815eea5f21` |
| SHA-1 | `d6c1ffad819b55f15bb93d5aac9dab1853d4aab0` |
| SHA-256 | `df0e1923c70de2bb0022944ab02b998e0dc57cc3da6a528063241d5572d8db83` |
| SHA3-384 | `0d8301e0802ee577d0811b216e0a67887a4932652d4ee4319e3b70f4701641f4a3809b7a4e33bc2f50d468b83ed2d016` |
| TLSH | `T16234F90AAB610EFBDC6BDD3711E91B0625CC641722A53F367274C918F94A64F4AE3C78` |
| SSDEEP | `3072:0zaPIQD3fxIJp+1opQM/M9MOdUqfRdelRdQt9hnI:QaPFSrHQKQ1fRkELK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_df0e1923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df0e1923c70de2bb0022944ab02b998e0dc57cc3da6a528063241d5572d8db83"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-23 18:04:50"
  condition:
    hash.sha256(0, filesize) == "df0e1923c70de2bb0022944ab02b998e0dc57cc3da6a528063241d5572d8db83"
}
```

### Sample 78: `29cc696038505466`

| Field | Value |
|---|---|
| SHA-256 | `29cc696038505466652f0552d91f0f9feb3b56d0a32c74899d043797be37c0c0` |
| Family label | `unknown` |
| File name | `NCrfwzCv.vbs` |
| File type | `vbs` |
| First seen | `2026-06-23 18:02:59` |
| Reporter | `BastianHein_` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `244f4120a8e5bf425c01b71333334282` |
| SHA-1 | `b9053a4083049aa50283f2f9459fd2055b963ec3` |
| SHA-256 | `29cc696038505466652f0552d91f0f9feb3b56d0a32c74899d043797be37c0c0` |
| SHA3-384 | `6a77a52de2a957ad2eaa49572878cbe366545e4218961d5973661743d3ec3e49ec4f6c003d13832496c98bbcac9d9be0` |
| TLSH | `T17CC0C042A244C35CED13E86B0173880C88BB904223009B17FA60C80C31041FCE25A083` |
| SSDEEP | `3:jeYcRm8nhr2SSJJLNytGQqPJH0cVERa9oM3KIHmRPIkVViEaKC5SuftqHflJFpFu:jeUqhrKnytGQO0cR9R3KN1BnaZ5SuFMy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_29cc6960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29cc696038505466652f0552d91f0f9feb3b56d0a32c74899d043797be37c0c0"
    family = "unknown"
    file_name = "NCrfwzCv.vbs"
    file_type = "vbs"
    first_seen = "2026-06-23 18:02:59"
  condition:
    hash.sha256(0, filesize) == "29cc696038505466652f0552d91f0f9feb3b56d0a32c74899d043797be37c0c0"
}
```

### Sample 79: `649bdd8390fae2ad`

| Field | Value |
|---|---|
| SHA-256 | `649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856` |
| Family label | `unknown` |
| File name | `649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856` |
| File type | `elf` |
| First seen | `2026-06-23 18:02:54` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce91dbb13fc789c6b67a4434844c92e7` |
| SHA-1 | `ba36344d36c292d80c7a770b9ae8ad7076ca45bb` |
| SHA-256 | `649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856` |
| SHA3-384 | `9e62509f6a7857432f6fe18b6faeb798a22e8ad972a791274edf5dd7a17da7a18cafb42363cba708ca4098a58761cf79` |
| TLSH | `T19645E657E89590F4C0EFE174C626A213B9A13489473437E76FA18BF11B26FE866BC314` |
| SSDEEP | `24576:ci3nHRD3wC7g9rb/TBvO90dL3BmAFd4A64nsfJ7FOQzjFyaWPliU:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_649bdd83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856"
    family = "unknown"
    file_name = "649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856"
    file_type = "elf"
    first_seen = "2026-06-23 18:02:54"
  condition:
    hash.sha256(0, filesize) == "649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856"
}
```

### Sample 80: `87831e9485c62f85`

| Field | Value |
|---|---|
| SHA-256 | `87831e9485c62f85543f8945e4813ca9d390d8b899c8ceebe9c60d128af99b15` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-23 17:58:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b9885f010b2152231b760c7bc21ab87` |
| SHA-1 | `032165a7a73b4f4305b16eb9f6f688353d143d3b` |
| SHA-256 | `87831e9485c62f85543f8945e4813ca9d390d8b899c8ceebe9c60d128af99b15` |
| SHA3-384 | `fb5e73fd664fef6f37fa276544ab28e80df64ef1c672008a32cabe7e7abfa5c312f9c49d83d8bd33e61fecb0758f77db` |
| TLSH | `T133536CC6AA43E0F5EC6705B5003BB7468F76E43A5538DB96C7A63936DC22B009B1735C` |
| TELFHASH | `t11331f8fb0dbe0decb364a404d71e2ee31409da7b166036b54163dd9927e35c180b9c3a` |
| SSDEEP | `1536:Ha6X68oA7FsLDUJVhZIbTa3HSdduvVkvSBGSFc:6fzAhYD8+Ta3QudOUdc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_87831e94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87831e9485c62f85543f8945e4813ca9d390d8b899c8ceebe9c60d128af99b15"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-23 17:58:50"
  condition:
    hash.sha256(0, filesize) == "87831e9485c62f85543f8945e4813ca9d390d8b899c8ceebe9c60d128af99b15"
}
```

### Sample 81: `6f9c98de64596939`

| Field | Value |
|---|---|
| SHA-256 | `6f9c98de64596939190f6514f42adaf845d21255353da7c34944472c301409fd` |
| Family label | `Mirai` |
| File name | `ErtB` |
| File type | `elf` |
| First seen | `2026-06-23 17:58:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8fee9bfd10194bb055400bb121224dd` |
| SHA-1 | `79e34ae2e1e20acde26b7f618d949e25dae9fd42` |
| SHA-256 | `6f9c98de64596939190f6514f42adaf845d21255353da7c34944472c301409fd` |
| SHA3-384 | `0748db171736c2bb4a41769c0ed604d960e040310d8e949677f927e284afce822a7152569054ff23d688d2f0904be1f5` |
| TLSH | `T123B33A5ABC816F51D5C615BAFE1E534933136BACE3EE7112FD105B2C338A96B0F6A042` |
| TELFHASH | `t149d097c4c22cbe8828c08f5600ac2022cff8fee43b26b0200985ef498450d84397703d` |
| SSDEEP | `3072:9kidB73riqKjYCPFgZGp0h9SrFo1dapUgsf65lTHOCjS:9DdJ32H8CPuZGp0h9Im1da8Qte` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_6f9c98de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f9c98de64596939190f6514f42adaf845d21255353da7c34944472c301409fd"
    family = "Mirai"
    file_name = "ErtB"
    file_type = "elf"
    first_seen = "2026-06-23 17:58:49"
  condition:
    hash.sha256(0, filesize) == "6f9c98de64596939190f6514f42adaf845d21255353da7c34944472c301409fd"
}
```

### Sample 82: `b9c53704f733b64f`

| Field | Value |
|---|---|
| SHA-256 | `b9c53704f733b64f589f52b8b2e2bfdfa98d4b1f4e5e9c8d4aae0226a78749d4` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-23 17:56:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35fa677942416c969094c477161c8abe` |
| SHA-1 | `b7747990f73708e556b8719b0e0b7d606b35f1ec` |
| SHA-256 | `b9c53704f733b64f589f52b8b2e2bfdfa98d4b1f4e5e9c8d4aae0226a78749d4` |
| SHA3-384 | `c0508ba947f2862693063c9c6954276eae6edc519906a3b8760c37d7cdbcd7226da59399fb8bef7fe1dcc7e52e417462` |
| TLSH | `T163730795BC919A16C6C51377FE4E42CD37266398E3EE3213CE299F21378B52B0E6A111` |
| TELFHASH | `t125d097f36e4a09ec83f1ca850c9e428642feb0716f012a54eee84f9f0043183b30e830` |
| SSDEEP | `1536:GIXqwxAoku8LuqhWcyXLuL/JmxvckX2hkvh:FLx+Luqh8uTJifh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_b9c53704
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c53704f733b64f589f52b8b2e2bfdfa98d4b1f4e5e9c8d4aae0226a78749d4"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-23 17:56:48"
  condition:
    hash.sha256(0, filesize) == "b9c53704f733b64f589f52b8b2e2bfdfa98d4b1f4e5e9c8d4aae0226a78749d4"
}
```

### Sample 83: `662a9ac8a0b8e602`

| Field | Value |
|---|---|
| SHA-256 | `662a9ac8a0b8e6022ba093dc60dc5ea1081013a4e8858b08d0784c919defd4e2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-23 17:55:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d18d1a771d263f5e714d4b45dc5fa2d` |
| SHA-1 | `7b49de9e7e059a8dc523dacfd1d23c9e4af4550f` |
| SHA-256 | `662a9ac8a0b8e6022ba093dc60dc5ea1081013a4e8858b08d0784c919defd4e2` |
| SHA3-384 | `0e15b2960e4961e9e21913c48301b88b41316c5add7b1713cab10f52e3827dcbd7c12434e23221a9e289e1e639beb293` |
| TLSH | `T10A630895BC819616C6D61377FA0E42CD37266398E3EE3213CD29AF2137CA52B0E6B511` |
| TELFHASH | `t125d097f36e4a09ec83f1ca850c9e428642feb0716f012a54eee84f9f0043183b30e830` |
| SSDEEP | `1536:xe5D45AQku7LIihscy3MqbZcbkTwFUtquMjO:8K5xLIihdqbZtTbtkO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_662a9ac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "662a9ac8a0b8e6022ba093dc60dc5ea1081013a4e8858b08d0784c919defd4e2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-23 17:55:49"
  condition:
    hash.sha256(0, filesize) == "662a9ac8a0b8e6022ba093dc60dc5ea1081013a4e8858b08d0784c919defd4e2"
}
```

### Sample 84: `0ad7f891ca02d0f1`

| Field | Value |
|---|---|
| SHA-256 | `0ad7f891ca02d0f11a3209211f3f6543393774f317dcad291628d9d7c7f0865e` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:47:23` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `191436a9bea707bb25df754d19c21bdd` |
| SHA-1 | `f1bd6ff941a407a1808ad64da138bc5c10f6a80a` |
| SHA-256 | `0ad7f891ca02d0f11a3209211f3f6543393774f317dcad291628d9d7c7f0865e` |
| SHA3-384 | `657512f6a99a9923792f5ab238b64c04ba03cfe2f1d12fc82dc995339e0f53d1654cc3c579bd647e55ec8417304ea2cd` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1CD46E101B3D695B6D4BF1638D87A56A56734BC049312CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:azIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:ahfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_084_0ad7f891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ad7f891ca02d0f11a3209211f3f6543393774f317dcad291628d9d7c7f0865e"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:47:23"
  condition:
    hash.sha256(0, filesize) == "0ad7f891ca02d0f11a3209211f3f6543393774f317dcad291628d9d7c7f0865e"
}
```

### Sample 85: `011b3b20095e9de6`

| Field | Value |
|---|---|
| SHA-256 | `011b3b20095e9de6e8c5f3a0f3ca18b5404869ada82599c4bf4473e2204953dc` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:47:16` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00e6550efbb39731ffca412808163435` |
| SHA-1 | `3b00e30e0ad5d0ab6a5707c5622dc3b73c3b01ae` |
| SHA-256 | `011b3b20095e9de6e8c5f3a0f3ca18b5404869ada82599c4bf4473e2204953dc` |
| SHA3-384 | `b56e383b670c2530516fc434c84dd976a9ee2dff960e318797c2f68fe58ddd3f82edd7c79f52c68b5c5d6a9b8398db4c` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T19B646C11B9C48432C673383147B8E2B28DBDB8301D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:KmlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji93:51iw7gryNkSV1hy1Z1u2JLu93` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_085_011b3b20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011b3b20095e9de6e8c5f3a0f3ca18b5404869ada82599c4bf4473e2204953dc"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:47:16"
  condition:
    hash.sha256(0, filesize) == "011b3b20095e9de6e8c5f3a0f3ca18b5404869ada82599c4bf4473e2204953dc"
}
```

### Sample 86: `535011b2507447bf`

| Field | Value |
|---|---|
| SHA-256 | `535011b2507447bf0de86fad901976eb9dab9fad81353f562fac3bdbbf605404` |
| Family label | `Mirai` |
| File name | `JtO` |
| File type | `elf` |
| First seen | `2026-06-23 17:45:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f14cd48fc8ecdcbe21221ad4708fbc2` |
| SHA-1 | `4446a862ae896ecdc1f63124113d92c107aee3c6` |
| SHA-256 | `535011b2507447bf0de86fad901976eb9dab9fad81353f562fac3bdbbf605404` |
| SHA3-384 | `1f6901786c2089829fb54759deca4106440c52fbe5a1845638632b5e32bae8846540c83c635dc93f1defbdc115a8016a` |
| TLSH | `T1D4C3D81B7F726FACF769823447B34B70979822D51AE1D1C4E1ACD6042E3428E681F7B9` |
| TELFHASH | `t15331030a497802f4e3b11d885adefb32e0a174df3a251d378f11e89e9e6e9825e11c1c` |
| SSDEEP | `1536:jmv8uUOSBcggJnjkjHH+rLr6+8DQOOPijKdt9pCX6lMjODloDl42rgn0/+69FNd6:jOnwjHH+7kGi54mW6Hn8asUZnlHOCje9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_535011b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "535011b2507447bf0de86fad901976eb9dab9fad81353f562fac3bdbbf605404"
    family = "Mirai"
    file_name = "JtO"
    file_type = "elf"
    first_seen = "2026-06-23 17:45:50"
  condition:
    hash.sha256(0, filesize) == "535011b2507447bf0de86fad901976eb9dab9fad81353f562fac3bdbbf605404"
}
```

### Sample 87: `7b5ab2c828cd839e`

| Field | Value |
|---|---|
| SHA-256 | `7b5ab2c828cd839ed3175de2b656131a4e46693d952851fd72974ae5ffa6e522` |
| Family label | `Mirai` |
| File name | `Q24I` |
| File type | `elf` |
| First seen | `2026-06-23 17:45:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ddb497a011b2f519b2ae68c99d24be5` |
| SHA-1 | `83e610658c5d8b8346583061de9dda312ff7e312` |
| SHA-256 | `7b5ab2c828cd839ed3175de2b656131a4e46693d952851fd72974ae5ffa6e522` |
| SHA3-384 | `f5eecbdef7a5144575eb6e4caa3c4bb77e5a0213682b1e8ced281c32acb49f595f5063f9ec8691e7192a7d5220ded7b0` |
| TLSH | `T12293195ABC81AF51D9C1057AFE1E534E331327ACE3DE7213F9105B2C378B96A0E6A446` |
| TELFHASH | `t1bbd0a728de9a154850f48b6e45dd1d42fec9e0c96a1225859eba5f8701365c3341b07c` |
| SSDEEP | `1536:dAnJg3Ki97FNjaGDl1C8YUWOnOuvFVcD7iI1jS7M+aIzuFUh5qYEk0TrKJ01J6nS:ch6Dfl1C8YUWCOr1jS7M+aICWhsXlTHL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_7b5ab2c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b5ab2c828cd839ed3175de2b656131a4e46693d952851fd72974ae5ffa6e522"
    family = "Mirai"
    file_name = "Q24I"
    file_type = "elf"
    first_seen = "2026-06-23 17:45:48"
  condition:
    hash.sha256(0, filesize) == "7b5ab2c828cd839ed3175de2b656131a4e46693d952851fd72974ae5ffa6e522"
}
```

### Sample 88: `afc81242f78b7268`

| Field | Value |
|---|---|
| SHA-256 | `afc81242f78b72681897c590da4c4ccea2c714a9d132e867b2a40c479562bb77` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:41:56` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e457f44b85ded5049f10308db21225c` |
| SHA-1 | `07d8ce45ea8cc2ae15686340a442251b1dd53859` |
| SHA-256 | `afc81242f78b72681897c590da4c4ccea2c714a9d132e867b2a40c479562bb77` |
| SHA3-384 | `432b27ee087293221706af007aab73064860950f9d1652210ed271a29c6989e9a99e18bd568067f9e41c7973e12b680b` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T141646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:amlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:p1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_088_afc81242
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afc81242f78b72681897c590da4c4ccea2c714a9d132e867b2a40c479562bb77"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:41:56"
  condition:
    hash.sha256(0, filesize) == "afc81242f78b72681897c590da4c4ccea2c714a9d132e867b2a40c479562bb77"
}
```

### Sample 89: `6bf0fb1192326455`

| Field | Value |
|---|---|
| SHA-256 | `6bf0fb1192326455a8eadb19c3d45b352a25020b9cff75d80bcffc376c6f7cfb` |
| Family label | `unknown` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:41:43` |
| Reporter | `BlinkzSec` |
| Tags | `signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ae4213c3ea5f5088f7c4dc9c7fa2cbb` |
| SHA-1 | `905b71caec23db475282846869b3bc4ddc04fb7a` |
| SHA-256 | `6bf0fb1192326455a8eadb19c3d45b352a25020b9cff75d80bcffc376c6f7cfb` |
| SHA3-384 | `899cd6a129691f54ba0b4e523289e0f951ac1f6102f3cc02a039eee1c7c214301b8b8ee100c326ea4cddee69379287c5` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1B446E111B3D695B6D1BF1638D87A42A96774BC048316CBBF5394BD392E32BC04E32366` |
| SSDEEP | `98304:pzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:phfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_6bf0fb11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bf0fb1192326455a8eadb19c3d45b352a25020b9cff75d80bcffc376c6f7cfb"
    family = "unknown"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:41:43"
  condition:
    hash.sha256(0, filesize) == "6bf0fb1192326455a8eadb19c3d45b352a25020b9cff75d80bcffc376c6f7cfb"
}
```

### Sample 90: `57cbd4dbc9570fd0`

| Field | Value |
|---|---|
| SHA-256 | `57cbd4dbc9570fd0fb912e19edb86e54f227b2dffe2f5f2857fa11ae22e6779a` |
| Family label | `unknown` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:40:57` |
| Reporter | `BlinkzSec` |
| Tags | `signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `febd3131850922ea9fe5f8422a0f01bb` |
| SHA-1 | `f4d67b2adce7e7bd7b7aa393aa0eb657e92dd91a` |
| SHA-256 | `57cbd4dbc9570fd0fb912e19edb86e54f227b2dffe2f5f2857fa11ae22e6779a` |
| SHA3-384 | `750688b6b0953224ba61451aface29742f86b718d6182c74e9aa9f181bc27e59695b2e156494f70c200691895c724cba` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1BA646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:ymlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9v:R1iw7gryNkSV1hy1Z1u2JLu9v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_57cbd4db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57cbd4dbc9570fd0fb912e19edb86e54f227b2dffe2f5f2857fa11ae22e6779a"
    family = "unknown"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:40:57"
  condition:
    hash.sha256(0, filesize) == "57cbd4dbc9570fd0fb912e19edb86e54f227b2dffe2f5f2857fa11ae22e6779a"
}
```

### Sample 91: `4d547c0ed2440d19`

| Field | Value |
|---|---|
| SHA-256 | `4d547c0ed2440d19d7a5ed7186a2e162e224091e99b409b88b8c2fc9d7e0348e` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:40:20` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2334ccbf5b701c36e95ff83289c874af` |
| SHA-1 | `0627da527079e4ff8001d470eb7c27c4b7374111` |
| SHA-256 | `4d547c0ed2440d19d7a5ed7186a2e162e224091e99b409b88b8c2fc9d7e0348e` |
| SHA3-384 | `465888cbc0549ba90ac6ee67ff98bc56c1ff15c28ba3f3812fe9d63013e728b194ccb3783160fd249a4543440551ca35` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1E546E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:yzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:yhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_091_4d547c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d547c0ed2440d19d7a5ed7186a2e162e224091e99b409b88b8c2fc9d7e0348e"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:40:20"
  condition:
    hash.sha256(0, filesize) == "4d547c0ed2440d19d7a5ed7186a2e162e224091e99b409b88b8c2fc9d7e0348e"
}
```

### Sample 92: `c6742350c0b2a1ef`

| Field | Value |
|---|---|
| SHA-256 | `c6742350c0b2a1ef0fe7fe3bdf46dce7b43d34230318539810390699980f455c` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:39:56` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad8699ff1e37c4939837e21aaa02ecf9` |
| SHA-1 | `4146470ef45ae72591644e2cf97bbbae0d406170` |
| SHA-256 | `c6742350c0b2a1ef0fe7fe3bdf46dce7b43d34230318539810390699980f455c` |
| SHA3-384 | `689360cfe2035b8534bf06d885ef9f6b4c1607f8699b705043f5e5da6c246ce0981f16b9f89ae5ac75289fc65b1584aa` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T10B647C11B9C48432C673383107B4E2B28DBDB8302D655B8F57A81D7A9F745D0EA29B6F` |
| SSDEEP | `6144:1mlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:A1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_092_c6742350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6742350c0b2a1ef0fe7fe3bdf46dce7b43d34230318539810390699980f455c"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:39:56"
  condition:
    hash.sha256(0, filesize) == "c6742350c0b2a1ef0fe7fe3bdf46dce7b43d34230318539810390699980f455c"
}
```

### Sample 93: `0bc5d51f8efe5fcb`

| Field | Value |
|---|---|
| SHA-256 | `0bc5d51f8efe5fcb7293ef438ab7d90729b530bbca808a1a5fb10fd4638c5637` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:38:47` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9c44e860de162f8f8430a5ce7b0d81b` |
| SHA-1 | `9bbd377656ad180831a8ba2219c04bc36c3225f9` |
| SHA-256 | `0bc5d51f8efe5fcb7293ef438ab7d90729b530bbca808a1a5fb10fd4638c5637` |
| SHA3-384 | `e51b0892acc3137ed90fbf64013128ba94bf8124c190bfbcb7227dd0366d328b149c2d299f8d5dac04773c98a223ac78` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T10F46E111B3DA95B9D4BF063CD87A92699A74BC044712C7EF53D4BD2D2D32BC04A323A6` |
| SSDEEP | `49152:TEEL5cx5xTkYJkGYYpT0+TFiH7efP8Q1yJJ4ZD1F5z97oL1YbGQ+okRPGHpRPqMu:cEs6efPNwJ4t1h0cG5FGJRPxow8OQR` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_093_0bc5d51f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc5d51f8efe5fcb7293ef438ab7d90729b530bbca808a1a5fb10fd4638c5637"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:38:47"
  condition:
    hash.sha256(0, filesize) == "0bc5d51f8efe5fcb7293ef438ab7d90729b530bbca808a1a5fb10fd4638c5637"
}
```

### Sample 94: `93b3fd82886a45a0`

| Field | Value |
|---|---|
| SHA-256 | `93b3fd82886a45a090e16c25da026a8197694567ecdb5bcd9aaa787e3f5f79d7` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:38:39` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `917337889870afed6fbc18dfbb96cb42` |
| SHA-1 | `8f3e85d0b2ce35647f5cfbb1ec93704011aaf641` |
| SHA-256 | `93b3fd82886a45a090e16c25da026a8197694567ecdb5bcd9aaa787e3f5f79d7` |
| SHA3-384 | `49308854809dfdf206b456a4207b642bc6f5d83644a9ab22953815acebfe6d032ba985915a1737a789e2a555750a007d` |
| IMPHASH | `37d5c89163970dd3cc69230538a1b72b` |
| TLSH | `T196836C43B5D18475E9720E3118B1D9B4593F7D210E648EAF3398822E0F351D19E3AE7B` |
| SSDEEP | `1536:ixoG6KpY6Qi3yj2wyq4HwiMO10HVLCJRpsWr6cdaWPBJYYj7TJA:AenkyfPAwiMq0RqRfbaWZJYYj5A` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_094_93b3fd82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93b3fd82886a45a090e16c25da026a8197694567ecdb5bcd9aaa787e3f5f79d7"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:38:39"
  condition:
    hash.sha256(0, filesize) == "93b3fd82886a45a090e16c25da026a8197694567ecdb5bcd9aaa787e3f5f79d7"
}
```

### Sample 95: `7b5c88bc57cd084b`

| Field | Value |
|---|---|
| SHA-256 | `7b5c88bc57cd084b76f8e7da83a145ed0c65d64d4a9ca227cc4e40674a435afa` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:37:16` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eae922a47d8b14b7122ec1f93bb02c2` |
| SHA-1 | `9676ec51cf46b5598f820fc26acbb862f107b071` |
| SHA-256 | `7b5c88bc57cd084b76f8e7da83a145ed0c65d64d4a9ca227cc4e40674a435afa` |
| SHA3-384 | `61ce2bb637af1aad2ae52c9e39004146af67347bded81e32f3ceaaac1ee65119f7ac256f8084d13f1b8c74bce6b4db88` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T10C46E111B3D695B6D17F1638D87A42A56674BC048316CBBB53D4BD392E32BC08E323B6` |
| SSDEEP | `98304:+zIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:+hfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_095_7b5c88bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b5c88bc57cd084b76f8e7da83a145ed0c65d64d4a9ca227cc4e40674a435afa"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:37:16"
  condition:
    hash.sha256(0, filesize) == "7b5c88bc57cd084b76f8e7da83a145ed0c65d64d4a9ca227cc4e40674a435afa"
}
```

### Sample 96: `e87151a8c2d6069a`

| Field | Value |
|---|---|
| SHA-256 | `e87151a8c2d6069a986895f5a7168c8ab98b52c5f917211d8d13e1156c0249eb` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:37:12` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7abd23e3c92c5acbee7c6147cd1c7121` |
| SHA-1 | `835c769ce1602a3e0b82ae7cd80cf51c2af1fc46` |
| SHA-256 | `e87151a8c2d6069a986895f5a7168c8ab98b52c5f917211d8d13e1156c0249eb` |
| SHA3-384 | `17955b693336030d57af2eaa322973e6225263dc507c05b168219ae03f357350916d9651b4cd243c7add10967580cad9` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T10B646D11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:imlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9Z:h1iw7gryNkSV1hy1Z1u2JLu9Z` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_096_e87151a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e87151a8c2d6069a986895f5a7168c8ab98b52c5f917211d8d13e1156c0249eb"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:37:12"
  condition:
    hash.sha256(0, filesize) == "e87151a8c2d6069a986895f5a7168c8ab98b52c5f917211d8d13e1156c0249eb"
}
```

### Sample 97: `3dbaf616dcaacfcf`

| Field | Value |
|---|---|
| SHA-256 | `3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554` |
| Family label | `AsyncRAT` |
| File name | `WinRar.exe` |
| File type | `exe` |
| First seen | `2026-06-23 17:22:02` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, botnet, c2, exe, fake winrar, malware, rat, virus` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0be5324ba4c2f648cee646e91135728f` |
| SHA-1 | `19905d50384db33546b8d86cdbc9b0864a3ecd43` |
| SHA-256 | `3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554` |
| SHA3-384 | `f65288d1f0622588a835a191d9833bc1dd5b7996aabfe9e36ad762c253a6c209f7413348277abba092f1c8a0ae37b52e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12C334B003BE9C227F1BE4F7898F22255857AF6637603D54A1CC442D75A13FC69A429FE` |
| SSDEEP | `1536:iuuc1TFcJ2/hHynlDEzUaIhboSds5yPdhm9:iuuoTFcJ2/VoJEzUfbPGMPC9` |
| ICON-DHASH | `b2b233ac7933b233` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_097_3dbaf616
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554"
    family = "AsyncRAT"
    file_name = "WinRar.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:22:02"
  condition:
    hash.sha256(0, filesize) == "3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554"
}
```

### Sample 98: `a5bbdd39bf6360c3`

| Field | Value |
|---|---|
| SHA-256 | `a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226` |
| Family label | `WannaCry` |
| File name | `a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226` |
| File type | `exe` |
| First seen | `2026-06-23 17:15:44` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fcd5d8573ae8a4cc9fa12a23325e985` |
| SHA-1 | `c7ea7e54fcea38dbd139266052888345a308d54b` |
| SHA-256 | `a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226` |
| SHA3-384 | `d4d87f93d4241c01a8b93731ec66086c028edf91386740704cd3bf7bb4c21df739f2b9a3feb9bd5203743cb21da7b19f` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1673623986128D1FEC32B763494F78D26A7F23C5A6BF8070FA7444AAA0D53BD4E654F01` |
| SSDEEP | `49152:jnXnAQqMSPbcBVQej/1INRx+TSqTdX1HkQ1J6qVmQQRF:DXDqPoBhz1aRxcSUDkEQq4Q8F` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_098_a5bbdd39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226"
    family = "WannaCry"
    file_name = "a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226"
    file_type = "exe"
    first_seen = "2026-06-23 17:15:44"
  condition:
    hash.sha256(0, filesize) == "a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226"
}
```

### Sample 99: `0128796cc2b8849b`

| Field | Value |
|---|---|
| SHA-256 | `0128796cc2b8849ba974e79ee44de0a8761550082e8c7ef920690e9b5c3dc99c` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-06-23 16:50:57` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aba7b8104bf632cc981fa45dfaa4deca` |
| SHA-1 | `5fff4425a71e724195071545de4e08bdc3941a5a` |
| SHA-256 | `0128796cc2b8849ba974e79ee44de0a8761550082e8c7ef920690e9b5c3dc99c` |
| SHA3-384 | `20f3cc935ad1de520616988a50848330ded97ba8949bc5bea8d860ed4b22dd2653887ca4ec3f572e806733fe4cd458ee` |
| IMPHASH | `1273eaec87da7c0a308253f29e7857eb` |
| TLSH | `T1DB837C43B5D19871E9721D3118B1C9A15E3FB9211E348EBB239802AE5F741D0AE35F7B` |
| SSDEEP | `1536:VXn1JYSnExFkcgKKjxfmqshiKW5Xs/iYQqQJtsWFcdfRMvb+xWeuHi6:lE3x5KBDYiKWm/iSw0fRMvyge4` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_099_0128796c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0128796cc2b8849ba974e79ee44de0a8761550082e8c7ef920690e9b5c3dc99c"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 16:50:57"
  condition:
    hash.sha256(0, filesize) == "0128796cc2b8849ba974e79ee44de0a8761550082e8c7ef920690e9b5c3dc99c"
}
```

### Sample 100: `e45497746ec8e85c`

| Field | Value |
|---|---|
| SHA-256 | `e45497746ec8e85c6775af9e03ac001e691017773d081bd3aeb5df09f3e3afaa` |
| Family label | `QuasarRAT` |
| File name | `QuasarRAT.exe` |
| File type | `exe` |
| First seen | `2026-06-23 16:40:44` |
| Reporter | `anonymous` |
| Tags | `botnet, c2, exe, malware, quasar, QuasarRAT, virus` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b730deb54b36fe9cb81817d533bcf89` |
| SHA-1 | `bb0cf020c7b25bd46e8eecedb172c686a15dd9d9` |
| SHA-256 | `e45497746ec8e85c6775af9e03ac001e691017773d081bd3aeb5df09f3e3afaa` |
| SHA3-384 | `660434cdde4796f093e7c787c9dbdf254fecee26bf044ed1e03e0b83e98d2bbfcd7c1f7f80d0555212dc3687314c671b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16DE56B143BF85E27E1BBE277E5B0041267F0FC1AB363EB0B6581677A1C53B5098426A7` |
| SSDEEP | `49152:MvFqB2ZNag4YgPblSvLo6L2KocuQRJ6WbR3LoGdxALTHHB72eh2NT:MvoB2ZNag4YgPblSvL5L2KocuQRJ6QS` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_100_e4549774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e45497746ec8e85c6775af9e03ac001e691017773d081bd3aeb5df09f3e3afaa"
    family = "QuasarRAT"
    file_name = "QuasarRAT.exe"
    file_type = "exe"
    first_seen = "2026-06-23 16:40:44"
  condition:
    hash.sha256(0, filesize) == "e45497746ec8e85c6775af9e03ac001e691017773d081bd3aeb5df09f3e3afaa"
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
 * Generated: 2026-06-24T04:41:25.056232+00:00
 */

rule MalwareBazaar_unknown_001_608371b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d"
    family = "unknown"
    file_name = "608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d"
    file_type = "exe"
    first_seen = "2026-06-24 04:15:21"
  condition:
    hash.sha256(0, filesize) == "608371b1c6e84d844d1d07642e404c4d7083567f766ca3055dcb0780c23d016d"
}

rule MalwareBazaar_unknown_002_72a6442a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72a6442a7c3ba07ea66f46472ac79a35b39a9d6311337eaffecd1eaa61aed3cf"
    family = "unknown"
    file_name = "Storage+Junk+Clean_1.2.2.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:47:33"
  condition:
    hash.sha256(0, filesize) == "72a6442a7c3ba07ea66f46472ac79a35b39a9d6311337eaffecd1eaa61aed3cf"
}

rule MalwareBazaar_unknown_003_131d73ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "131d73baac6511df4290684e7a935aa72627ec459b07b2c2fcbb3eda06e48b5b"
    family = "unknown"
    file_name = "com.hdwall.coolwall.background_3.7.8.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:43:55"
  condition:
    hash.sha256(0, filesize) == "131d73baac6511df4290684e7a935aa72627ec459b07b2c2fcbb3eda06e48b5b"
}

rule MalwareBazaar_unknown_004_53ec3546
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53ec3546057bc6eaffc0403fed417b9a3aecf31482456aacc1c6ef8f64449963"
    family = "unknown"
    file_name = "com.placevt.junkcleaner_3.6.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:39:47"
  condition:
    hash.sha256(0, filesize) == "53ec3546057bc6eaffc0403fed417b9a3aecf31482456aacc1c6ef8f64449963"
}

rule MalwareBazaar_unknown_005_92b4d6b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92b4d6b3527a78cc2483f3a1f0cf30b849fc117272310fe85f1cef934914eaa7"
    family = "unknown"
    file_name = "com.maxorbor.phonecleaner_4.3.xapk"
    file_type = "xapk"
    first_seen = "2026-06-24 03:38:52"
  condition:
    hash.sha256(0, filesize) == "92b4d6b3527a78cc2483f3a1f0cf30b849fc117272310fe85f1cef934914eaa7"
}

rule MalwareBazaar_unknown_006_1516ab56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1516ab566efef411a809b5220ef748c79ee0199e2340b3576168204b59443bae"
    family = "unknown"
    file_name = "a-software85659001.msi"
    file_type = "msi"
    first_seen = "2026-06-24 03:33:41"
  condition:
    hash.sha256(0, filesize) == "1516ab566efef411a809b5220ef748c79ee0199e2340b3576168204b59443bae"
}

rule MalwareBazaar_unknown_007_a9bf6b54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950"
    family = "unknown"
    file_name = "a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950"
    file_type = "exe"
    first_seen = "2026-06-24 03:15:34"
  condition:
    hash.sha256(0, filesize) == "a9bf6b54b485f91eb950df281998f1096f3a84c87bbd662710294e3b25c9f950"
}

rule MalwareBazaar_unknown_008_e052bfab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e052bfab59ab1e074b7f2a998190e6d6094979bef2e93b59f32ffef096a24d83"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-06-24 02:12:07"
  condition:
    hash.sha256(0, filesize) == "e052bfab59ab1e074b7f2a998190e6d6094979bef2e93b59f32ffef096a24d83"
}

rule MalwareBazaar_NanoCore_009_752faadc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "752faadcef0c8a53370583cddec408b88b0922655e260d424763ce00f08b91d4"
    family = "NanoCore"
    file_name = "mhsra.com.exe"
    file_type = "exe"
    first_seen = "2026-06-24 02:10:04"
  condition:
    hash.sha256(0, filesize) == "752faadcef0c8a53370583cddec408b88b0922655e260d424763ce00f08b91d4"
}

rule MalwareBazaar_Mirai_010_16c0a085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16c0a0857c5fdb37fa92edc3ab802e6581875bdd24cb1a29b2004a9f67b79b38"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-06-24 01:19:55"
  condition:
    hash.sha256(0, filesize) == "16c0a0857c5fdb37fa92edc3ab802e6581875bdd24cb1a29b2004a9f67b79b38"
}

rule MalwareBazaar_Mirai_011_eda8c398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda8c3988086e3f74102f462592383be649059aa3599d1ad46808db223cff58c"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-24 01:16:58"
  condition:
    hash.sha256(0, filesize) == "eda8c3988086e3f74102f462592383be649059aa3599d1ad46808db223cff58c"
}

rule MalwareBazaar_unknown_012_14c28a21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14c28a21dc6c756cbf84a5e250b590f9b12883293c66b1298c27e633f270421b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-24 00:54:56"
  condition:
    hash.sha256(0, filesize) == "14c28a21dc6c756cbf84a5e250b590f9b12883293c66b1298c27e633f270421b"
}

rule MalwareBazaar_DarkTortilla_013_4db8eb34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4db8eb346541d4b4d9931c431eecc9034cd574317b61b058e9969ca538e1ebd5"
    family = "DarkTortilla"
    file_name = "New Quote.exe"
    file_type = "exe"
    first_seen = "2026-06-24 00:53:40"
  condition:
    hash.sha256(0, filesize) == "4db8eb346541d4b4d9931c431eecc9034cd574317b61b058e9969ca538e1ebd5"
}

rule MalwareBazaar_NanoCore_014_7e0de4a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e0de4a54fd3e5c74bd4cccebe26d3e7b141e493edf4a2df59b9ff6e228999e3"
    family = "NanoCore"
    file_name = "dpvm.io.exe"
    file_type = "exe"
    first_seen = "2026-06-24 00:50:05"
  condition:
    hash.sha256(0, filesize) == "7e0de4a54fd3e5c74bd4cccebe26d3e7b141e493edf4a2df59b9ff6e228999e3"
}

rule MalwareBazaar_unknown_015_76ffbf52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76ffbf5212a8157868af8191045876b74c1640dec4fec22d27fe28b797a2b97d"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-24 00:12:59"
  condition:
    hash.sha256(0, filesize) == "76ffbf5212a8157868af8191045876b74c1640dec4fec22d27fe28b797a2b97d"
}

rule MalwareBazaar_Mirai_016_f6d0e514
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6d0e5142fd0d1a0f07e916c9c7432ffcbacc2a6d4eb0594f1524cb7661477ce"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-24 00:12:57"
  condition:
    hash.sha256(0, filesize) == "f6d0e5142fd0d1a0f07e916c9c7432ffcbacc2a6d4eb0594f1524cb7661477ce"
}

rule MalwareBazaar_Mirai_017_dcb2e53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcb2e53eaeb334e77769eede9700b4a544e013b70c337a61ebb0513243393ac2"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-24 00:04:57"
  condition:
    hash.sha256(0, filesize) == "dcb2e53eaeb334e77769eede9700b4a544e013b70c337a61ebb0513243393ac2"
}

rule MalwareBazaar_Mirai_018_a881050c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a881050c8ac1682c8f8e44b8ccdee9a0fded8891e8ddfa8f41416a16fa42ce08"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-06-24 00:01:05"
  condition:
    hash.sha256(0, filesize) == "a881050c8ac1682c8f8e44b8ccdee9a0fded8891e8ddfa8f41416a16fa42ce08"
}

rule MalwareBazaar_unknown_019_75a89d42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75a89d421cbe02df07b43667f099e6678c6eaa9e0544d4d32c82629a84f93089"
    family = "unknown"
    file_name = "ipmiv2.xml"
    file_type = "unknown"
    first_seen = "2026-06-23 23:52:57"
  condition:
    hash.sha256(0, filesize) == "75a89d421cbe02df07b43667f099e6678c6eaa9e0544d4d32c82629a84f93089"
}

rule MalwareBazaar_unknown_020_c2e736a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce"
    family = "unknown"
    file_name = "c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce"
    file_type = "sh"
    first_seen = "2026-06-23 23:18:36"
  condition:
    hash.sha256(0, filesize) == "c2e736a01417f8466a99f63d77cb2f7d4a7d71b33351ae0d145a2e1ec5b4c0ce"
}

rule MalwareBazaar_ConnectWise_021_1f9624a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f9624a18f3bc812317966f91c22549e900e82f6ece603c53d4d663001cbf7ec"
    family = "ConnectWise"
    file_name = "SecuriteInfo.com.Trojan.Siggen31.29530.31038.23378"
    file_type = "exe"
    first_seen = "2026-06-23 22:37:47"
  condition:
    hash.sha256(0, filesize) == "1f9624a18f3bc812317966f91c22549e900e82f6ece603c53d4d663001cbf7ec"
}

rule MalwareBazaar_WannaCry_022_f0d29fc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5"
    family = "WannaCry"
    file_name = "f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5.dll"
    file_type = "dll"
    first_seen = "2026-06-23 21:55:13"
  condition:
    hash.sha256(0, filesize) == "f0d29fc579b7f0c97c0312e980467cc852751a0bd145a9621f05fd3fd2ebc3a5"
}

rule MalwareBazaar_WannaCry_023_66c883ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c"
    family = "WannaCry"
    file_name = "66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c.dll"
    file_type = "dll"
    first_seen = "2026-06-23 21:53:02"
  condition:
    hash.sha256(0, filesize) == "66c883ff13b812047a4393f5caa58a88e7347b177c7039abc54e5819a8b8f16c"
}

rule MalwareBazaar_unknown_024_17b502fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8"
    family = "unknown"
    file_name = "17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8.dll"
    file_type = "dll"
    first_seen = "2026-06-23 21:51:52"
  condition:
    hash.sha256(0, filesize) == "17b502febe4c95766892469ea9dfbe75c4af6ecb90e6d35d9123a10599be36a8"
}

rule MalwareBazaar_unknown_025_3fbc3430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fbc343025f847fdeb6fd21311215e47d20a68be80eb25434d5d76c373532f0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:43:18"
  condition:
    hash.sha256(0, filesize) == "3fbc343025f847fdeb6fd21311215e47d20a68be80eb25434d5d76c373532f0e"
}

rule MalwareBazaar_unknown_026_ea12c2da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea12c2dafe8a3d632055550e20be4544bed615d263da1e6fa689a7ee5b790703"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:23:54"
  condition:
    hash.sha256(0, filesize) == "ea12c2dafe8a3d632055550e20be4544bed615d263da1e6fa689a7ee5b790703"
}

rule MalwareBazaar_unknown_027_c966a90c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c966a90c770463c7566bc87accc402a9c34a4bd6752b8ce27c3d73efbfadfe65"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-06-23 21:20:42"
  condition:
    hash.sha256(0, filesize) == "c966a90c770463c7566bc87accc402a9c34a4bd6752b8ce27c3d73efbfadfe65"
}

rule MalwareBazaar_unknown_028_38f593be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38f593be606970dca31716996074627b2aea802089d8c0c73676e1f888327ee9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:20:02"
  condition:
    hash.sha256(0, filesize) == "38f593be606970dca31716996074627b2aea802089d8c0c73676e1f888327ee9"
}

rule MalwareBazaar_unknown_029_8735b6a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8735b6a853ce69a2e99781bbf5774df5acf2130724f4f92c7cad174779864ab4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 21:18:39"
  condition:
    hash.sha256(0, filesize) == "8735b6a853ce69a2e99781bbf5774df5acf2130724f4f92c7cad174779864ab4"
}

rule MalwareBazaar_unknown_030_66f8f315
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377"
    family = "unknown"
    file_name = "66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377"
    file_type = "elf"
    first_seen = "2026-06-23 21:07:17"
  condition:
    hash.sha256(0, filesize) == "66f8f315000fe6a2a2e09fba08a867c60f4d330099ab2e94f7bdcb0f0c869377"
}

rule MalwareBazaar_unknown_031_da539912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da539912928b31ea423a3b8bd4cdb91946ee775c8c15c605d8be410de7c0e3fd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 20:29:54"
  condition:
    hash.sha256(0, filesize) == "da539912928b31ea423a3b8bd4cdb91946ee775c8c15c605d8be410de7c0e3fd"
}

rule MalwareBazaar_unknown_032_c1e04d68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e04d688fa2867036a118ca02a515503d8cf7e48073a234f6faaaebd645af55"
    family = "unknown"
    file_name = "AVISO URGENTE FORMAL DE PAGO Y REGULARIZACIÓN DE SALDO REVISAR Y VALIDAR.js"
    file_type = "js"
    first_seen = "2026-06-23 20:27:03"
  condition:
    hash.sha256(0, filesize) == "c1e04d688fa2867036a118ca02a515503d8cf7e48073a234f6faaaebd645af55"
}

rule MalwareBazaar_unknown_033_000aabb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "000aabb7b6b9b3faa488e2eb49f3350ba182ed67257d0fa8e91eb49ad9fc4ad6"
    family = "unknown"
    file_name = "2306 AVISO URGENTE FORMAL DE PAGO Y REGULARIZACIÓN DE SALDO REVISAR Y VALIDAR_infected.zip"
    file_type = "zip"
    first_seen = "2026-06-23 20:21:14"
  condition:
    hash.sha256(0, filesize) == "000aabb7b6b9b3faa488e2eb49f3350ba182ed67257d0fa8e91eb49ad9fc4ad6"
}

rule MalwareBazaar_Mirai_034_98a6d83b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98a6d83b9554b57ec4b84fbc5bb283a65a27341095e9179957b2adf850779042"
    family = "Mirai"
    file_name = "tplink.sh"
    file_type = "sh"
    first_seen = "2026-06-23 20:14:39"
  condition:
    hash.sha256(0, filesize) == "98a6d83b9554b57ec4b84fbc5bb283a65a27341095e9179957b2adf850779042"
}

rule MalwareBazaar_Mirai_035_02dab7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02dab7a5df7df570f5eb58931986cbccad6558bd92a11e2f2f1751f0d0ec2767"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-23 20:10:25"
  condition:
    hash.sha256(0, filesize) == "02dab7a5df7df570f5eb58931986cbccad6558bd92a11e2f2f1751f0d0ec2767"
}

rule MalwareBazaar_Mirai_036_15c3faf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15c3faf3681fd10404a208d815421157a04e9f0f8d63746cbdf324f71466cc42"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-06-23 20:01:31"
  condition:
    hash.sha256(0, filesize) == "15c3faf3681fd10404a208d815421157a04e9f0f8d63746cbdf324f71466cc42"
}

rule MalwareBazaar_Mirai_037_491eaa1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "491eaa1e13d8792f96428fb147d529075f7848cbc37c69b60e6659754ef3acf7"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-23 19:57:21"
  condition:
    hash.sha256(0, filesize) == "491eaa1e13d8792f96428fb147d529075f7848cbc37c69b60e6659754ef3acf7"
}

rule MalwareBazaar_unknown_038_4fa2ccd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fa2ccd05dc0b3a8dfcb2f089eba1a8cbf90b858dcf8f45c5f3c4c2539e55c63"
    family = "unknown"
    file_name = "Banco_Sabadell.apk"
    file_type = "apk"
    first_seen = "2026-06-23 19:53:43"
  condition:
    hash.sha256(0, filesize) == "4fa2ccd05dc0b3a8dfcb2f089eba1a8cbf90b858dcf8f45c5f3c4c2539e55c63"
}

rule MalwareBazaar_Mirai_039_1639ab80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1639ab80ef54685a639a47eece8041ad21b950a107f667f241f0c2d6d5a937a8"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-23 19:51:20"
  condition:
    hash.sha256(0, filesize) == "1639ab80ef54685a639a47eece8041ad21b950a107f667f241f0c2d6d5a937a8"
}

rule MalwareBazaar_unknown_040_b9d3147f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9d3147f13395b4c9d6242340b22021abc3b3ff03755809fcbf24aea653c0b59"
    family = "unknown"
    file_name = "rhn.vbs"
    file_type = "vbs"
    first_seen = "2026-06-23 19:45:52"
  condition:
    hash.sha256(0, filesize) == "b9d3147f13395b4c9d6242340b22021abc3b3ff03755809fcbf24aea653c0b59"
}

rule MalwareBazaar_unknown_041_fc92185b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc92185b6516f3cdb0284201e14c96e5636d8f835fbf7eb6dc7bc704f70b89c7"
    family = "unknown"
    file_name = "payload.exe"
    file_type = "exe"
    first_seen = "2026-06-23 19:44:45"
  condition:
    hash.sha256(0, filesize) == "fc92185b6516f3cdb0284201e14c96e5636d8f835fbf7eb6dc7bc704f70b89c7"
}

rule MalwareBazaar_Mirai_042_1b2fbd5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b2fbd5f510d8c02ba709aafafaffdebb298e41fd78aef620bd06781e78a8b92"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-23 19:41:06"
  condition:
    hash.sha256(0, filesize) == "1b2fbd5f510d8c02ba709aafafaffdebb298e41fd78aef620bd06781e78a8b92"
}

rule MalwareBazaar_Mirai_043_99514c84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99514c847ae4860e6488da66f0dc80e5d8afd596f7d6da9358e8b72b5c098942"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-23 19:41:05"
  condition:
    hash.sha256(0, filesize) == "99514c847ae4860e6488da66f0dc80e5d8afd596f7d6da9358e8b72b5c098942"
}

rule MalwareBazaar_unknown_044_4412add7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4412add79e052ea3a32cd604d993b734315438ad2977925cf6f063608a8354cb"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-23 19:37:07"
  condition:
    hash.sha256(0, filesize) == "4412add79e052ea3a32cd604d993b734315438ad2977925cf6f063608a8354cb"
}

rule MalwareBazaar_unknown_045_0127aa41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0127aa41531f6201e705333e44e944dc317a471a462546619a31eb746652f476"
    family = "unknown"
    file_name = "kla.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:34:07"
  condition:
    hash.sha256(0, filesize) == "0127aa41531f6201e705333e44e944dc317a471a462546619a31eb746652f476"
}

rule MalwareBazaar_unknown_046_59917d57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59917d57e94301d33685e651f71495c8cc958cb911cde15ae98e81f9a7264fce"
    family = "unknown"
    file_name = "deploy_softwaretech.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:32:06"
  condition:
    hash.sha256(0, filesize) == "59917d57e94301d33685e651f71495c8cc958cb911cde15ae98e81f9a7264fce"
}

rule MalwareBazaar_Mirai_047_efb36b83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efb36b837e7c26e47b0db1231de4a229c203fb44316bd1c25f65ebf8a1ee421a"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-06-23 19:32:05"
  condition:
    hash.sha256(0, filesize) == "efb36b837e7c26e47b0db1231de4a229c203fb44316bd1c25f65ebf8a1ee421a"
}

rule MalwareBazaar_Mirai_048_3e041d99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e041d99e68d64f22c407109bf3f9cb10152136a607b51cf012c3b2e9900232a"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-23 19:31:01"
  condition:
    hash.sha256(0, filesize) == "3e041d99e68d64f22c407109bf3f9cb10152136a607b51cf012c3b2e9900232a"
}

rule MalwareBazaar_Mirai_049_986318d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "986318d491b023dad6692aa7f972fa696c20a2373244fdf8a8590098f683b870"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-06-23 19:29:58"
  condition:
    hash.sha256(0, filesize) == "986318d491b023dad6692aa7f972fa696c20a2373244fdf8a8590098f683b870"
}

rule MalwareBazaar_unknown_050_217d39d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "217d39d16431539d00b1ef2a7fd750cc03cf7d7180ae530854a0f1565ec88b64"
    family = "unknown"
    file_name = "OZONE_TRAGIC.vbs"
    file_type = "vbs"
    first_seen = "2026-06-23 19:29:22"
  condition:
    hash.sha256(0, filesize) == "217d39d16431539d00b1ef2a7fd750cc03cf7d7180ae530854a0f1565ec88b64"
}

rule MalwareBazaar_Mirai_051_905de1d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "905de1d2354b45a04ffcb5af4410eb6ac3410bb1c411acce521d18850f2e8e6f"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-23 19:19:59"
  condition:
    hash.sha256(0, filesize) == "905de1d2354b45a04ffcb5af4410eb6ac3410bb1c411acce521d18850f2e8e6f"
}

rule MalwareBazaar_unknown_052_41137fe5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41137fe5e25ea1ba86c55f34a484003234f43ab6e2611733eb0b325f4efff608"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 19:15:23"
  condition:
    hash.sha256(0, filesize) == "41137fe5e25ea1ba86c55f34a484003234f43ab6e2611733eb0b325f4efff608"
}

rule MalwareBazaar_unknown_053_2a2bdf13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a2bdf134906d1327b3b4f2603955749da1505c0875549cd9cf8b16aa99fa034"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:10:59"
  condition:
    hash.sha256(0, filesize) == "2a2bdf134906d1327b3b4f2603955749da1505c0875549cd9cf8b16aa99fa034"
}

rule MalwareBazaar_unknown_054_6db456f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db456f1326888b6aaf8ec8ea2a050a5008c587222ed861bfa2af72754857809"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-06-23 19:10:58"
  condition:
    hash.sha256(0, filesize) == "6db456f1326888b6aaf8ec8ea2a050a5008c587222ed861bfa2af72754857809"
}

rule MalwareBazaar_Mirai_055_957adb4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "957adb4a56c1bcb7eb11247b5b28a501ddb4ab5a425a440163fbf6f15f44a95e"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-23 19:06:57"
  condition:
    hash.sha256(0, filesize) == "957adb4a56c1bcb7eb11247b5b28a501ddb4ab5a425a440163fbf6f15f44a95e"
}

rule MalwareBazaar_Mirai_056_dc154a86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc154a86d0e2eb63bbbf88e5632bbddc318a47b4f01e157653f19cb2ada8c501"
    family = "Mirai"
    file_name = "giga.sh"
    file_type = "sh"
    first_seen = "2026-06-23 19:01:03"
  condition:
    hash.sha256(0, filesize) == "dc154a86d0e2eb63bbbf88e5632bbddc318a47b4f01e157653f19cb2ada8c501"
}

rule MalwareBazaar_Mirai_057_2e539ddf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e539ddf3488114badd7f63eea1f77529780729f151102e290dfb96e70d45ffb"
    family = "Mirai"
    file_name = "jkL"
    file_type = "elf"
    first_seen = "2026-06-23 18:58:56"
  condition:
    hash.sha256(0, filesize) == "2e539ddf3488114badd7f63eea1f77529780729f151102e290dfb96e70d45ffb"
}

rule MalwareBazaar_Mirai_058_e6192766
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6192766dab3f32979ea6d7e28614006031901cafba6354204fdb8fa32ab9308"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-06-23 18:55:58"
  condition:
    hash.sha256(0, filesize) == "e6192766dab3f32979ea6d7e28614006031901cafba6354204fdb8fa32ab9308"
}

rule MalwareBazaar_Mirai_059_eda549f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda549f5480a2ca44d6eabac11309abf5dbd6467da22384526754a418a6fa4ab"
    family = "Mirai"
    file_name = "pFdY"
    file_type = "elf"
    first_seen = "2026-06-23 18:55:57"
  condition:
    hash.sha256(0, filesize) == "eda549f5480a2ca44d6eabac11309abf5dbd6467da22384526754a418a6fa4ab"
}

rule MalwareBazaar_unknown_060_90504826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "905048266f359367fea147487dce73f4f7c40c631fa9e0dffc74cdebc787db33"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-23 18:50:19"
  condition:
    hash.sha256(0, filesize) == "905048266f359367fea147487dce73f4f7c40c631fa9e0dffc74cdebc787db33"
}

rule MalwareBazaar_Mirai_061_f12584fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f12584fdad83aaf73c7ef360542d0bf0c4aeff3754774added2fd2b7c1af2111"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-06-23 18:48:55"
  condition:
    hash.sha256(0, filesize) == "f12584fdad83aaf73c7ef360542d0bf0c4aeff3754774added2fd2b7c1af2111"
}

rule MalwareBazaar_Mirai_062_498c098e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "498c098e3b2fb515b0cc8f7169ba45b7a7669aa0b7531ff0806b6e1b2469c699"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-06-23 18:46:58"
  condition:
    hash.sha256(0, filesize) == "498c098e3b2fb515b0cc8f7169ba45b7a7669aa0b7531ff0806b6e1b2469c699"
}

rule MalwareBazaar_unknown_063_d025a296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677"
    family = "unknown"
    file_name = "AggregatorHost.exe"
    file_type = "exe"
    first_seen = "2026-06-23 18:45:33"
  condition:
    hash.sha256(0, filesize) == "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677"
}

rule MalwareBazaar_Mirai_064_cf9cf23f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf9cf23f8cccdafcd066cc2e7a96dbe0a793f193e6f0fd21797698801282dc60"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-06-23 18:43:56"
  condition:
    hash.sha256(0, filesize) == "cf9cf23f8cccdafcd066cc2e7a96dbe0a793f193e6f0fd21797698801282dc60"
}

rule MalwareBazaar_Mirai_065_e0d719ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d719ffa8d2aecec83055d7a5151e6a3f2eb5a6bd1b53dab2319488b639acf3"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-23 18:43:54"
  condition:
    hash.sha256(0, filesize) == "e0d719ffa8d2aecec83055d7a5151e6a3f2eb5a6bd1b53dab2319488b639acf3"
}

rule MalwareBazaar_unknown_066_5f7b9c0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f7b9c0fa02fc95f6176500164e58ad9d99065df7521d235b3d5750817e1f5ba"
    family = "unknown"
    file_name = ".suzUwa2"
    file_type = "macho"
    first_seen = "2026-06-23 18:42:43"
  condition:
    hash.sha256(0, filesize) == "5f7b9c0fa02fc95f6176500164e58ad9d99065df7521d235b3d5750817e1f5ba"
}

rule MalwareBazaar_Mirai_067_659236dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "659236dcdf22042685c1b906dbe5f4a904cacbb1343cb6860d08c37fe1bd4810"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-23 18:40:54"
  condition:
    hash.sha256(0, filesize) == "659236dcdf22042685c1b906dbe5f4a904cacbb1343cb6860d08c37fe1bd4810"
}

rule MalwareBazaar_unknown_068_420f1931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "420f1931af9b3f7d02c5edfc78eb69abdad6e71d2c3e9b81f9cbc3823a503654"
    family = "unknown"
    file_name = "взвод розвідки.rar"
    file_type = "rar"
    first_seen = "2026-06-23 18:39:41"
  condition:
    hash.sha256(0, filesize) == "420f1931af9b3f7d02c5edfc78eb69abdad6e71d2c3e9b81f9cbc3823a503654"
}

rule MalwareBazaar_Mirai_069_5cbba8fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cbba8fb45956d619f6d0f407f4a2f92f06c291611190f6b0f46d22bdc2cf3e3"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-23 18:38:53"
  condition:
    hash.sha256(0, filesize) == "5cbba8fb45956d619f6d0f407f4a2f92f06c291611190f6b0f46d22bdc2cf3e3"
}

rule MalwareBazaar_Mirai_070_efe00769
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efe00769b8fd2a79068c28f58300d6eeb236339096f9c7d6789835238f3d3973"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-06-23 18:37:52"
  condition:
    hash.sha256(0, filesize) == "efe00769b8fd2a79068c28f58300d6eeb236339096f9c7d6789835238f3d3973"
}

rule MalwareBazaar_unknown_071_77b37c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77b37c072672991e4cdc0f639dc8c13682eb1d2fde1a3a73f9b19b4a01b81cae"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-06-23 18:32:53"
  condition:
    hash.sha256(0, filesize) == "77b37c072672991e4cdc0f639dc8c13682eb1d2fde1a3a73f9b19b4a01b81cae"
}

rule MalwareBazaar_Mirai_072_a21766a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a21766a2df35e45db59e0a6dbfeb7c8862fb9e77710c9f8f589b7a9b96c99bb9"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-23 18:25:55"
  condition:
    hash.sha256(0, filesize) == "a21766a2df35e45db59e0a6dbfeb7c8862fb9e77710c9f8f589b7a9b96c99bb9"
}

rule MalwareBazaar_Mirai_073_352e4045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "352e4045388a0b3cb12b29024b4da60f664fc7c7b5d17911bb16869073763b1f"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-06-23 18:21:54"
  condition:
    hash.sha256(0, filesize) == "352e4045388a0b3cb12b29024b4da60f664fc7c7b5d17911bb16869073763b1f"
}

rule MalwareBazaar_Mirai_074_9a00b4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a00b4bcbb081c1fa2b581fd82a00336f77788c0080a6255c3628fa641b0bfac"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-23 18:09:52"
  condition:
    hash.sha256(0, filesize) == "9a00b4bcbb081c1fa2b581fd82a00336f77788c0080a6255c3628fa641b0bfac"
}

rule MalwareBazaar_Mirai_075_9ea203e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea203e9d1d9da977a7d667f10e7ceb273bbe9964589c7bf7e9d5600c498bc3c"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-06-23 18:08:50"
  condition:
    hash.sha256(0, filesize) == "9ea203e9d1d9da977a7d667f10e7ceb273bbe9964589c7bf7e9d5600c498bc3c"
}

rule MalwareBazaar_Mirai_076_099dea0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "099dea0ac240df1145eac6d54f02eef064ca7cb2b5791ead83fb77947ccb176c"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-23 18:05:53"
  condition:
    hash.sha256(0, filesize) == "099dea0ac240df1145eac6d54f02eef064ca7cb2b5791ead83fb77947ccb176c"
}

rule MalwareBazaar_Mirai_077_df0e1923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df0e1923c70de2bb0022944ab02b998e0dc57cc3da6a528063241d5572d8db83"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-06-23 18:04:50"
  condition:
    hash.sha256(0, filesize) == "df0e1923c70de2bb0022944ab02b998e0dc57cc3da6a528063241d5572d8db83"
}

rule MalwareBazaar_unknown_078_29cc6960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29cc696038505466652f0552d91f0f9feb3b56d0a32c74899d043797be37c0c0"
    family = "unknown"
    file_name = "NCrfwzCv.vbs"
    file_type = "vbs"
    first_seen = "2026-06-23 18:02:59"
  condition:
    hash.sha256(0, filesize) == "29cc696038505466652f0552d91f0f9feb3b56d0a32c74899d043797be37c0c0"
}

rule MalwareBazaar_unknown_079_649bdd83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856"
    family = "unknown"
    file_name = "649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856"
    file_type = "elf"
    first_seen = "2026-06-23 18:02:54"
  condition:
    hash.sha256(0, filesize) == "649bdd8390fae2adabb07e262d6e01892bdd2c36a36ad70f242bd3bae185b856"
}

rule MalwareBazaar_Mirai_080_87831e94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87831e9485c62f85543f8945e4813ca9d390d8b899c8ceebe9c60d128af99b15"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-23 17:58:50"
  condition:
    hash.sha256(0, filesize) == "87831e9485c62f85543f8945e4813ca9d390d8b899c8ceebe9c60d128af99b15"
}

rule MalwareBazaar_Mirai_081_6f9c98de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f9c98de64596939190f6514f42adaf845d21255353da7c34944472c301409fd"
    family = "Mirai"
    file_name = "ErtB"
    file_type = "elf"
    first_seen = "2026-06-23 17:58:49"
  condition:
    hash.sha256(0, filesize) == "6f9c98de64596939190f6514f42adaf845d21255353da7c34944472c301409fd"
}

rule MalwareBazaar_Mirai_082_b9c53704
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c53704f733b64f589f52b8b2e2bfdfa98d4b1f4e5e9c8d4aae0226a78749d4"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-23 17:56:48"
  condition:
    hash.sha256(0, filesize) == "b9c53704f733b64f589f52b8b2e2bfdfa98d4b1f4e5e9c8d4aae0226a78749d4"
}

rule MalwareBazaar_Mirai_083_662a9ac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "662a9ac8a0b8e6022ba093dc60dc5ea1081013a4e8858b08d0784c919defd4e2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-23 17:55:49"
  condition:
    hash.sha256(0, filesize) == "662a9ac8a0b8e6022ba093dc60dc5ea1081013a4e8858b08d0784c919defd4e2"
}

rule MalwareBazaar_ConnectWise_084_0ad7f891
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ad7f891ca02d0f11a3209211f3f6543393774f317dcad291628d9d7c7f0865e"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:47:23"
  condition:
    hash.sha256(0, filesize) == "0ad7f891ca02d0f11a3209211f3f6543393774f317dcad291628d9d7c7f0865e"
}

rule MalwareBazaar_ConnectWise_085_011b3b20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011b3b20095e9de6e8c5f3a0f3ca18b5404869ada82599c4bf4473e2204953dc"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:47:16"
  condition:
    hash.sha256(0, filesize) == "011b3b20095e9de6e8c5f3a0f3ca18b5404869ada82599c4bf4473e2204953dc"
}

rule MalwareBazaar_Mirai_086_535011b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "535011b2507447bf0de86fad901976eb9dab9fad81353f562fac3bdbbf605404"
    family = "Mirai"
    file_name = "JtO"
    file_type = "elf"
    first_seen = "2026-06-23 17:45:50"
  condition:
    hash.sha256(0, filesize) == "535011b2507447bf0de86fad901976eb9dab9fad81353f562fac3bdbbf605404"
}

rule MalwareBazaar_Mirai_087_7b5ab2c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b5ab2c828cd839ed3175de2b656131a4e46693d952851fd72974ae5ffa6e522"
    family = "Mirai"
    file_name = "Q24I"
    file_type = "elf"
    first_seen = "2026-06-23 17:45:48"
  condition:
    hash.sha256(0, filesize) == "7b5ab2c828cd839ed3175de2b656131a4e46693d952851fd72974ae5ffa6e522"
}

rule MalwareBazaar_ConnectWise_088_afc81242
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afc81242f78b72681897c590da4c4ccea2c714a9d132e867b2a40c479562bb77"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:41:56"
  condition:
    hash.sha256(0, filesize) == "afc81242f78b72681897c590da4c4ccea2c714a9d132e867b2a40c479562bb77"
}

rule MalwareBazaar_unknown_089_6bf0fb11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bf0fb1192326455a8eadb19c3d45b352a25020b9cff75d80bcffc376c6f7cfb"
    family = "unknown"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:41:43"
  condition:
    hash.sha256(0, filesize) == "6bf0fb1192326455a8eadb19c3d45b352a25020b9cff75d80bcffc376c6f7cfb"
}

rule MalwareBazaar_unknown_090_57cbd4db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57cbd4dbc9570fd0fb912e19edb86e54f227b2dffe2f5f2857fa11ae22e6779a"
    family = "unknown"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:40:57"
  condition:
    hash.sha256(0, filesize) == "57cbd4dbc9570fd0fb912e19edb86e54f227b2dffe2f5f2857fa11ae22e6779a"
}

rule MalwareBazaar_ConnectWise_091_4d547c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d547c0ed2440d19d7a5ed7186a2e162e224091e99b409b88b8c2fc9d7e0348e"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:40:20"
  condition:
    hash.sha256(0, filesize) == "4d547c0ed2440d19d7a5ed7186a2e162e224091e99b409b88b8c2fc9d7e0348e"
}

rule MalwareBazaar_ConnectWise_092_c6742350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6742350c0b2a1ef0fe7fe3bdf46dce7b43d34230318539810390699980f455c"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:39:56"
  condition:
    hash.sha256(0, filesize) == "c6742350c0b2a1ef0fe7fe3bdf46dce7b43d34230318539810390699980f455c"
}

rule MalwareBazaar_ConnectWise_093_0bc5d51f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc5d51f8efe5fcb7293ef438ab7d90729b530bbca808a1a5fb10fd4638c5637"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:38:47"
  condition:
    hash.sha256(0, filesize) == "0bc5d51f8efe5fcb7293ef438ab7d90729b530bbca808a1a5fb10fd4638c5637"
}

rule MalwareBazaar_ConnectWise_094_93b3fd82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93b3fd82886a45a090e16c25da026a8197694567ecdb5bcd9aaa787e3f5f79d7"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:38:39"
  condition:
    hash.sha256(0, filesize) == "93b3fd82886a45a090e16c25da026a8197694567ecdb5bcd9aaa787e3f5f79d7"
}

rule MalwareBazaar_ConnectWise_095_7b5c88bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b5c88bc57cd084b76f8e7da83a145ed0c65d64d4a9ca227cc4e40674a435afa"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:37:16"
  condition:
    hash.sha256(0, filesize) == "7b5c88bc57cd084b76f8e7da83a145ed0c65d64d4a9ca227cc4e40674a435afa"
}

rule MalwareBazaar_ConnectWise_096_e87151a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e87151a8c2d6069a986895f5a7168c8ab98b52c5f917211d8d13e1156c0249eb"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:37:12"
  condition:
    hash.sha256(0, filesize) == "e87151a8c2d6069a986895f5a7168c8ab98b52c5f917211d8d13e1156c0249eb"
}

rule MalwareBazaar_AsyncRAT_097_3dbaf616
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554"
    family = "AsyncRAT"
    file_name = "WinRar.exe"
    file_type = "exe"
    first_seen = "2026-06-23 17:22:02"
  condition:
    hash.sha256(0, filesize) == "3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554"
}

rule MalwareBazaar_WannaCry_098_a5bbdd39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226"
    family = "WannaCry"
    file_name = "a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226"
    file_type = "exe"
    first_seen = "2026-06-23 17:15:44"
  condition:
    hash.sha256(0, filesize) == "a5bbdd39bf6360c3caf9f9cac5c206f8c9aa8620912d83beadd634814cb11226"
}

rule MalwareBazaar_ConnectWise_099_0128796c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0128796cc2b8849ba974e79ee44de0a8761550082e8c7ef920690e9b5c3dc99c"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-06-23 16:50:57"
  condition:
    hash.sha256(0, filesize) == "0128796cc2b8849ba974e79ee44de0a8761550082e8c7ef920690e9b5c3dc99c"
}

rule MalwareBazaar_QuasarRAT_100_e4549774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e45497746ec8e85c6775af9e03ac001e691017773d081bd3aeb5df09f3e3afaa"
    family = "QuasarRAT"
    file_name = "QuasarRAT.exe"
    file_type = "exe"
    first_seen = "2026-06-23 16:40:44"
  condition:
    hash.sha256(0, filesize) == "e45497746ec8e85c6775af9e03ac001e691017773d081bd3aeb5df09f3e3afaa"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

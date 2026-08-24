# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-24

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 612 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 612 |
| Unique family labels | 6 |
| Unique file types | 4 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 62 |
| unknown | 34 |
| SystemBC | 1 |
| RemusStealer | 1 |
| DCRat | 1 |
| njrat | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 77 |
| exe | 11 |
| sh | 7 |
| unknown | 5 |

## Per-Sample Analysis

### Sample 1: `20b7849f1b98ff63`

| Field | Value |
|---|---|
| SHA-256 | `20b7849f1b98ff63fc9ae31d2da8a8145e496815bcd5a228f01061063f46216c` |
| Family label | `Mirai` |
| File name | `8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:53:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f32bfdb5c98f92d79c984759ddbe124b` |
| SHA-1 | `8d58af9737cf4ddbb736e24c6c4a009fb71d1794` |
| SHA-256 | `20b7849f1b98ff63fc9ae31d2da8a8145e496815bcd5a228f01061063f46216c` |
| SHA3-384 | `855efe4ae8f235bbbd4db63d3e77a03ba93aca4040b2f3659c7d54cb24dc7cec68d43318276b6e393fa9b9169e8bb2aa` |
| TLSH | `T117545B5F7B10CF61E229C53149B38B5667E5266327E2C559E21CEE087E6038C682FFE4` |
| TELFHASH | `t1cc4100a04e3bda06db89caec86fdab2e790e91061259cf33ee30417d40510f9e259d4f` |
| SSDEEP | `6144:gM5XK4YODabLHG4kq79xu6h+l2rVXxEeJDh:r5XZXWzUR2rVbF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_20b7849f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20b7849f1b98ff63fc9ae31d2da8a8145e496815bcd5a228f01061063f46216c"
    family = "Mirai"
    file_name = "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:53:17"
  condition:
    hash.sha256(0, filesize) == "20b7849f1b98ff63fc9ae31d2da8a8145e496815bcd5a228f01061063f46216c"
}
```

### Sample 2: `8e43add0886d834e`

| Field | Value |
|---|---|
| SHA-256 | `8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a` |
| Family label | `Mirai` |
| File name | `8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:52:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77d527197667f9ebffcaab86b23764a3` |
| SHA-1 | `7e4afb1e224c1dfee05a9cc3133ba3560c62fb71` |
| SHA-256 | `8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a` |
| SHA3-384 | `6b688459b2aee81276594224e3f9b307d302bec0002c94eae95538fb2fd963e76531dfed88b85d3dd5621e8df02ba12b` |
| TLSH | `T183B31295280F84F2E46BA2795B1C0EC1CB63E6F21890B5437876DEC99C45ED030967FB` |
| SSDEEP | `3072:BE0Vn0kzmFunZwQRHkZM4cIGnPPCs9b+r/mcyYUCagV1sn:W0Vn0kiFuZKEPlxYTfam1sn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_8e43add0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a"
    family = "Mirai"
    file_name = "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:52:43"
  condition:
    hash.sha256(0, filesize) == "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a"
}
```

### Sample 3: `b1fe221c2c1aea1a`

| Field | Value |
|---|---|
| SHA-256 | `b1fe221c2c1aea1ac269bb743b5455f2750d08fbddb777e01d2e1c1364023525` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 01:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b336c063004c941cea8b683c1f33aac` |
| SHA-256 | `b1fe221c2c1aea1ac269bb743b5455f2750d08fbddb777e01d2e1c1364023525` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_b1fe221c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1fe221c2c1aea1ac269bb743b5455f2750d08fbddb777e01d2e1c1364023525"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 01:52:10"
  condition:
    hash.sha256(0, filesize) == "b1fe221c2c1aea1ac269bb743b5455f2750d08fbddb777e01d2e1c1364023525"
}
```

### Sample 4: `07ecd27fdb601292`

| Field | Value |
|---|---|
| SHA-256 | `07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44` |
| Family label | `Mirai` |
| File name | `07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:42:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `568c41d403bfe132bf852cd72e048784` |
| SHA-1 | `c1d37fb21e6cf0de6760eb39c2a5f994e35a97d0` |
| SHA-256 | `07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44` |
| SHA3-384 | `aa7da479d159a81d3140cd8e0b504b6ca10352dc2f1cd2ae69849267ae1a3edc90b2d8b37acd7f7615c82cd7d48e51af` |
| TLSH | `T14724AEC1721C7EDFE1832D7D860955235C0CAE12E8039B9261FD6A47DA7BAE30FB9941` |
| TELFHASH | `t10fe061f1978fa282068ccbcd83c833ac1a0dd001008bef03fd22403c80a082cb85a84f` |
| SSDEEP | `6144:uCWEBesWl+cJvAC3uVfAlVZ/kYVdaBCUvFFlJXsPH:qSeLAemYPlajFGPH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_07ecd27f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44"
    family = "Mirai"
    file_name = "07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:42:30"
  condition:
    hash.sha256(0, filesize) == "07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44"
}
```

### Sample 5: `b8f880f65a7023dd`

| Field | Value |
|---|---|
| SHA-256 | `b8f880f65a7023dd21c418f0bf70e9c342c7d72e594fbc416689aaf40467fcc4` |
| Family label | `Mirai` |
| File name | `415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:37:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38e99e727b8e8d9efb7282d2484c4ea6` |
| SHA-1 | `746c8ba5d5788b6763613c53146c4d1c32ce1320` |
| SHA-256 | `b8f880f65a7023dd21c418f0bf70e9c342c7d72e594fbc416689aaf40467fcc4` |
| SHA3-384 | `c6e371df73eced662dd797c10f65b01a8b20d33f494b4a3b4090afe0923f488805052525491f2291b76f7a520fb0b7c0` |
| TLSH | `T107547C45AF646EFBC41ECE310A2EC30621DD588BA2F9B73AB678CD4CB55A30915F3854` |
| TELFHASH | `t1384121a04e3bda06da98caec89fdab6e790e50165209cf33ee30416d40510f9e25ad5f` |
| SSDEEP | `6144:YfXTvXkWuXk4XlTmu532/ote4CMSGXtAc1RCdNQLcA8xbLtLLBP9wB:Y/T09ldQsCMSG6YxQtLF2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_b8f880f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8f880f65a7023dd21c418f0bf70e9c342c7d72e594fbc416689aaf40467fcc4"
    family = "Mirai"
    file_name = "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:37:16"
  condition:
    hash.sha256(0, filesize) == "b8f880f65a7023dd21c418f0bf70e9c342c7d72e594fbc416689aaf40467fcc4"
}
```

### Sample 6: `415c91ff2b709826`

| Field | Value |
|---|---|
| SHA-256 | `415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f` |
| Family label | `Mirai` |
| File name | `415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:36:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e390c0672ab53e60e9637af6873da80` |
| SHA-1 | `34e93681d961a37c7c22bdac81827bdbc75e4971` |
| SHA-256 | `415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f` |
| SHA3-384 | `1063e88388dd7732f9006c7bb49834c70bddf0a3f0ff91b260791694ac037eececc7cf0452ad03f401517fca51a2b056` |
| TLSH | `T154D312DC7A4192DCF0E382292D8085A52D87CA7E5EB527F27B44E54818C7873E56E0EE` |
| SSDEEP | `3072:8HawO8VWmSa2yags5Z1aph2ENhOdqKjwjeuIX8/oEOEnz4Z9h0A:8q4zJ0gs5ZI8MEjwjeuIXQoE9niB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_415c91ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f"
    family = "Mirai"
    file_name = "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:36:56"
  condition:
    hash.sha256(0, filesize) == "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f"
}
```

### Sample 7: `78ef93e33f5c390d`

| Field | Value |
|---|---|
| SHA-256 | `78ef93e33f5c390dd4cbbd8098f34cf1a0d961fad2ec8854f8c05065c75a78ba` |
| Family label | `Mirai` |
| File name | `a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:27:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dedfd761ef00180bdaa86fa9ba19bca` |
| SHA-1 | `56d559f797d272026fc212128cf6176ed58d1127` |
| SHA-256 | `78ef93e33f5c390dd4cbbd8098f34cf1a0d961fad2ec8854f8c05065c75a78ba` |
| SHA3-384 | `643dba0ea64bbf936691fe13a6892c32afc92dbc31b5f6d34ef26aa04b80846b908fccb6fec1c07272ca8958edd7d74f` |
| TLSH | `T1FB145C07B69144FCC19AC474876F9523F931B85D03243D7BABC0AA716E22F716B1DBA2` |
| SSDEEP | `3072:GabMqr36hG15AsAIFJRxsV/bXS3taAylwWm4wi7d74Hyj80d:Ga7qGPbQV/b8K9m/cdmyjZd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_78ef93e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78ef93e33f5c390dd4cbbd8098f34cf1a0d961fad2ec8854f8c05065c75a78ba"
    family = "Mirai"
    file_name = "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:27:15"
  condition:
    hash.sha256(0, filesize) == "78ef93e33f5c390dd4cbbd8098f34cf1a0d961fad2ec8854f8c05065c75a78ba"
}
```

### Sample 8: `a2232cd0627028b5`

| Field | Value |
|---|---|
| SHA-256 | `a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d` |
| Family label | `Mirai` |
| File name | `a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d.elf` |
| File type | `elf` |
| First seen | `2026-08-24 01:26:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59b8244d671888094fd4d03a5e1f460f` |
| SHA-1 | `099485d3fe29c8b5860ad0295da74452947dbe97` |
| SHA-256 | `a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d` |
| SHA3-384 | `2bc60f3c3206157bce71369f1d7e8800e862cf09f7c944961e29a39b8028ca0cc1865652edd65732c0352fe6054c3404` |
| TLSH | `T1FB9302972B3EBCE0E83302B8D2A549CAA7EC1445E59F83751DE4711E92B20CE5E257C7` |
| SSDEEP | `1536:gMPVsIDtgKyQ0O0PcCZOolZZIsxGK3N0mO3rtvfrtJNXsLO1u7O8XT:gMNzge4PcOOUZZD/0N35vfRJRsLOIOC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_a2232cd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d"
    family = "Mirai"
    file_name = "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:26:50"
  condition:
    hash.sha256(0, filesize) == "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d"
}
```

### Sample 9: `010384fe2d669417`

| Field | Value |
|---|---|
| SHA-256 | `010384fe2d669417d4ea35467f4a990a59a1a921124fd7ec734373c7b4c714b8` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-24 01:07:06` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7d6396ba6bcaf4bc717994af4f6e3b` |
| SHA-1 | `711c7c93ac4f63647ac58b845b12bfc62fcd95fe` |
| SHA-256 | `010384fe2d669417d4ea35467f4a990a59a1a921124fd7ec734373c7b4c714b8` |
| SHA3-384 | `4f928a810e55f9cae27b9b8b2c92c2201e907077879317c569ae59ccc2b75f8ccb437946adaf9ea2615c27dbe2ea8d03` |
| TLSH | `T15AC27D966A867C44BDC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC12FACD618B1A` |
| SSDEEP | `768:p8vCB+25j6es8Rr9FYpMSUpi+20qUpi+20YQX:p8l25J9d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_010384fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "010384fe2d669417d4ea35467f4a990a59a1a921124fd7ec734373c7b4c714b8"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 01:07:06"
  condition:
    hash.sha256(0, filesize) == "010384fe2d669417d4ea35467f4a990a59a1a921124fd7ec734373c7b4c714b8"
}
```

### Sample 10: `dfec0ea9ed7b1e3c`

| Field | Value |
|---|---|
| SHA-256 | `dfec0ea9ed7b1e3ceb813604170f47b0376cdeb226b418dee6e636e80f688cb0` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-24 00:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cf0ce39473c63302879cf51f62ca160` |
| SHA-256 | `dfec0ea9ed7b1e3ceb813604170f47b0376cdeb226b418dee6e636e80f688cb0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_dfec0ea9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfec0ea9ed7b1e3ceb813604170f47b0376cdeb226b418dee6e636e80f688cb0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 00:52:11"
  condition:
    hash.sha256(0, filesize) == "dfec0ea9ed7b1e3ceb813604170f47b0376cdeb226b418dee6e636e80f688cb0"
}
```

### Sample 11: `1eb027a9844495e9`

| Field | Value |
|---|---|
| SHA-256 | `1eb027a9844495e9a3c64bc0c7ea645058933a9b18cc98ff3f42a7b1a9142753` |
| Family label | `SystemBC` |
| File name | `1f4d12ddad20dd3b74bbd9579f0c57b2.exe` |
| File type | `exe` |
| First seen | `2026-08-24 00:45:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, SystemBC` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f4d12ddad20dd3b74bbd9579f0c57b2` |
| SHA-1 | `756283303a89e2fc22efd7168e505404fb1358dc` |
| SHA-256 | `1eb027a9844495e9a3c64bc0c7ea645058933a9b18cc98ff3f42a7b1a9142753` |
| SHA3-384 | `8515861d3dd9ca8bf0a90c46578a282dd7d0962cbe6b09b6ffc2c68c1581cb31d695c57f7763994295228b41b2214347` |
| IMPHASH | `6cf9e3e4ea52048ec6ef92a1a0d9abd1` |
| TLSH | `T1A703F52A745092B1D5918AF03F9EA390C5BE78374269E449EFE0AF0476B1AD7E706207` |
| SSDEEP | `768:q/c4qHYi1qqdZeG299DUi3LXMEW9o+3goDoJM773R:qUYi1qqdZeGM9DRbUwoDom` |

#### Technical Assessment

- The sample is tracked as `SystemBC` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SystemBC_011_1eb027a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb027a9844495e9a3c64bc0c7ea645058933a9b18cc98ff3f42a7b1a9142753"
    family = "SystemBC"
    file_name = "1f4d12ddad20dd3b74bbd9579f0c57b2.exe"
    file_type = "exe"
    first_seen = "2026-08-24 00:45:09"
  condition:
    hash.sha256(0, filesize) == "1eb027a9844495e9a3c64bc0c7ea645058933a9b18cc98ff3f42a7b1a9142753"
}
```

### Sample 12: `2445e07bc2164188`

| Field | Value |
|---|---|
| SHA-256 | `2445e07bc216418817a5e2dd276e0a8426157557b5f4c6e977d8db9c761ed224` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-24 00:32:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8d7fb65d4864427178d1d9241f04b6f` |
| SHA-1 | `b0d27650ac5e6e0d50bdff4015ef04eb138c1c9b` |
| SHA-256 | `2445e07bc216418817a5e2dd276e0a8426157557b5f4c6e977d8db9c761ed224` |
| SHA3-384 | `849e5ab086dc92cca270da6e2a75d420ef6140617fe52d9234dfdce20eeb640b23c5fe404f3e46eebd48a9ce3729e42b` |
| TLSH | `T15D236C6516857C14AA99C4375C7F2F0CBDAD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:399NyXsZztCm9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:tHusZ+cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_2445e07b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2445e07bc216418817a5e2dd276e0a8426157557b5f4c6e977d8db9c761ed224"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-24 00:32:57"
  condition:
    hash.sha256(0, filesize) == "2445e07bc216418817a5e2dd276e0a8426157557b5f4c6e977d8db9c761ed224"
}
```

### Sample 13: `d62088168d53fa9b`

| Field | Value |
|---|---|
| SHA-256 | `d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c` |
| Family label | `unknown` |
| File name | `d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c.bin` |
| File type | `exe` |
| First seen | `2026-08-24 00:31:20` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbe2ca5895aaadc3a2a91a5438f45b6d` |
| SHA-1 | `2daf0937e6a2105f5d99a05f40635748aeea7801` |
| SHA-256 | `d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c` |
| SHA3-384 | `c8a580900a0ba5b5e2e9030adbb30cd04c73533f41733b784347a67e8a617942b9a668d1efa83db80f2e10a7a9d09bc8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T153366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaab:uc3XND1aJrCOkb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_d6208816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c"
    family = "unknown"
    file_name = "d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c.bin"
    file_type = "exe"
    first_seen = "2026-08-24 00:31:20"
  condition:
    hash.sha256(0, filesize) == "d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c"
}
```

### Sample 14: `826ac95ac380c156`

| Field | Value |
|---|---|
| SHA-256 | `826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e` |
| Family label | `unknown` |
| File name | `826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e.exe` |
| File type | `exe` |
| First seen | `2026-08-24 00:27:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b119bdbe19c91521fbba3f9ef251f673` |
| SHA-1 | `518cc8573a8ee5908b9aabdd5bc53e3b740552df` |
| SHA-256 | `826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e` |
| SHA3-384 | `9dab0aba40437018b0a01c6b15b5fa80e286cd326eb1fcb75caf79fef77274de8df3892113f4f537a9608ca8cec42ef4` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T112D5239EBA732574E837C7B18F12E43D707E3B844B618E4FFA9D29405E5264468323B2` |
| SSDEEP | `49152:HoJcRt12rnqSIVUWT49ef48wonIFCZEh5tt+vjN4XHIuLFOmmrVuLHKYd1lu:JIpIVUWnnnbE5X+vjN4XoIFe6qM1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_826ac95a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e"
    family = "unknown"
    file_name = "826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e.exe"
    file_type = "exe"
    first_seen = "2026-08-24 00:27:17"
  condition:
    hash.sha256(0, filesize) == "826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e"
}
```

### Sample 15: `f50bc37c7ac1d217`

| Field | Value |
|---|---|
| SHA-256 | `f50bc37c7ac1d217de7f571d89b8b6ddac65ad852d36b9a6a148e4e01973d198` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-24 00:21:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54f08d245edc2e4a75d61010103fdd8f` |
| SHA-1 | `f1f2065045575fc65bb078047e8b4257b5721412` |
| SHA-256 | `f50bc37c7ac1d217de7f571d89b8b6ddac65ad852d36b9a6a148e4e01973d198` |
| SHA3-384 | `c6afb603cfa7edd729d50894bf7ba971c09471c7a601ef06007abccac97fe86e37d532bc571b3411fe955ba73850e946` |
| TLSH | `T1EF143A95F890DE52C6D5267AF96E518C331313B8D2DAB106CD244F38B7EB85E0E3E942` |
| SSDEEP | `6144:MoN0t/kMmKQUQ4g8OG92vxQMpkN89zpM7p5km:fY/kMTQUQ4g8OU6DZzi7Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_f50bc37c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50bc37c7ac1d217de7f571d89b8b6ddac65ad852d36b9a6a148e4e01973d198"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 00:21:19"
  condition:
    hash.sha256(0, filesize) == "f50bc37c7ac1d217de7f571d89b8b6ddac65ad852d36b9a6a148e4e01973d198"
}
```

### Sample 16: `e46b7dfe2ab10669`

| Field | Value |
|---|---|
| SHA-256 | `e46b7dfe2ab10669bb7ee95337fb91507709ac8516653ac063d39acaa1f8b72a` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-24 00:21:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4123ddc5bec9a65b4cd84653f4dec16f` |
| SHA-1 | `1bb7a7830bf525ecaf716ad01fa9eef7876a1318` |
| SHA-256 | `e46b7dfe2ab10669bb7ee95337fb91507709ac8516653ac063d39acaa1f8b72a` |
| SHA3-384 | `e70c3641ae1ad724b18b6332ae39355a5c6a1f30789e6f709adedabb808752ea8139b72c1af6bb516c583ece61234265` |
| TLSH | `T17C83029221E61371CDE4643AECA29EA3CEC963EC4D503F3984044B577AA73565737E82` |
| SSDEEP | `1536:w7VAB/MhsSZYx5KVVG2bDt1DB6Di5qTupKI38thYfg:w7M3xMVrDtL6DSqyYI3YY4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_e46b7dfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e46b7dfe2ab10669bb7ee95337fb91507709ac8516653ac063d39acaa1f8b72a"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 00:21:01"
  condition:
    hash.sha256(0, filesize) == "e46b7dfe2ab10669bb7ee95337fb91507709ac8516653ac063d39acaa1f8b72a"
}
```

### Sample 17: `6112186bff639583`

| Field | Value |
|---|---|
| SHA-256 | `6112186bff6395832fb6efe21d3e5d285f959f50299d0570dfab7ed412be82c4` |
| Family label | `unknown` |
| File name | `stage2.bin` |
| File type | `exe` |
| First seen | `2026-08-24 00:20:47` |
| Reporter | `johnk3r` |
| Tags | `exe, phantom, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0004f67b7d98c6e30d6c16f8802f76dc` |
| SHA-1 | `c62db65ad00bd05e9a37492b3af551445ba51fd2` |
| SHA-256 | `6112186bff6395832fb6efe21d3e5d285f959f50299d0570dfab7ed412be82c4` |
| SHA3-384 | `5e10da1d0a27229b8b75cf0c90b0eab281ec5b07944ced10182d29c17fc0cc8e6dc16d381a627ca4c51242837131895d` |
| IMPHASH | `3c52d12edfba816c6953dd595276f9c2` |
| TLSH | `T16E73D649D783A1F8C82B4CB02E97E3FF0E62363259908DF4E78ADD45B533B516698702` |
| SSDEEP | `1536:p/KS0GhdufPn+OHcTtBSn/AU4n4E+og4n4Hc:tKa/un+7UPNW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_6112186b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6112186bff6395832fb6efe21d3e5d285f959f50299d0570dfab7ed412be82c4"
    family = "unknown"
    file_name = "stage2.bin"
    file_type = "exe"
    first_seen = "2026-08-24 00:20:47"
  condition:
    hash.sha256(0, filesize) == "6112186bff6395832fb6efe21d3e5d285f959f50299d0570dfab7ed412be82c4"
}
```

### Sample 18: `8a640912022d829a`

| Field | Value |
|---|---|
| SHA-256 | `8a640912022d829a62612042935a6ba20f13e0b95a535cb4866ae0b091c62d51` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnriscv64xnxn` |
| File type | `elf` |
| First seen | `2026-08-24 00:16:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8467c01db0c4e30bb9af3639ede48e81` |
| SHA-1 | `18d0f7a0706271679c2f68b8b2a6bd25a2e3e01b` |
| SHA-256 | `8a640912022d829a62612042935a6ba20f13e0b95a535cb4866ae0b091c62d51` |
| SHA3-384 | `a78e37a5e0a7b6042a7d1d9deeed2846978a90ae244470728fcfb6f52b00dd4e83c696d77bd49a7f21ae910bcad55b89` |
| TLSH | `T1C5B3E085B210AE56C02672FCB1870A80D3B16D7B4B9A150B44B3F5B46DBCCD47E1AEDA` |
| SSDEEP | `3072:15Apzl9NOvXoVLAE375lhYy5SkOXNwu/:sevXCLr59hmNwI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_8a640912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a640912022d829a62612042935a6ba20f13e0b95a535cb4866ae0b091c62d51"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnriscv64xnxn"
    file_type = "elf"
    first_seen = "2026-08-24 00:16:59"
  condition:
    hash.sha256(0, filesize) == "8a640912022d829a62612042935a6ba20f13e0b95a535cb4866ae0b091c62d51"
}
```

### Sample 19: `b2db7036c63d9d80`

| Field | Value |
|---|---|
| SHA-256 | `b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711` |
| Family label | `unknown` |
| File name | `b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711.exe` |
| File type | `exe` |
| First seen | `2026-08-24 00:16:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12963effa8bc7ee2ed797e53bb036edb` |
| SHA-1 | `c8651674d0ce3e1756458d5edf7f8f6753e8d567` |
| SHA-256 | `b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711` |
| SHA3-384 | `44474885eea1916ba7071ac6fdd1db803934ca4b33b54236abff79923a744aa8405be6b8878951cfd5c2f83452ec9908` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T12DD5238CFDE60DB5E432C3B752D3653EB229774685B88CA726C863115E12A297C7B334` |
| SSDEEP | `49152:WXxlJn9YPH5RkC0zoh811Pgi4ScXwjJhU4O1VOH4ZcmdK1VPlx00iPvcL7dm2:WvJG5Rr0chEgi4SvsOH4fiJxc5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_b2db7036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711"
    family = "unknown"
    file_name = "b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711.exe"
    file_type = "exe"
    first_seen = "2026-08-24 00:16:51"
  condition:
    hash.sha256(0, filesize) == "b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711"
}
```

### Sample 20: `cce51ae71c056fbd`

| Field | Value |
|---|---|
| SHA-256 | `cce51ae71c056fbd149f0d9ba817fcac74015fb4f800e59f1cc5cd4b5a3b361f` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-23 23:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc8ef8432556d27d36bc7356ca995c2b` |
| SHA-256 | `cce51ae71c056fbd149f0d9ba817fcac74015fb4f800e59f1cc5cd4b5a3b361f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_cce51ae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cce51ae71c056fbd149f0d9ba817fcac74015fb4f800e59f1cc5cd4b5a3b361f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 23:52:10"
  condition:
    hash.sha256(0, filesize) == "cce51ae71c056fbd149f0d9ba817fcac74015fb4f800e59f1cc5cd4b5a3b361f"
}
```

### Sample 21: `de06b1694149c66d`

| Field | Value |
|---|---|
| SHA-256 | `de06b1694149c66d59976e32041cc9fe8392536da9466d8f16f0ce48299de123` |
| Family label | `RemusStealer` |
| File name | `1a1caa979ee86b2a7a5fd8510e83ac81.exe` |
| File type | `exe` |
| First seen | `2026-08-23 23:45:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a1caa979ee86b2a7a5fd8510e83ac81` |
| SHA-1 | `7e7911039e26fcaf8d3f81ae99dd3aefe7bb32ba` |
| SHA-256 | `de06b1694149c66d59976e32041cc9fe8392536da9466d8f16f0ce48299de123` |
| SHA3-384 | `6709fe2c6c4b4fe32001ac9616bbaf8572e9a4d676cdde814edde042e09c3a74c9e3453bc4a0129237f633a42ca0dbb2` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1F0562713799941A4C4AADF34C4B383137A64F88D9B3533939E61AE342F767C29D7AB04` |
| SSDEEP | `24576:3T9gXeg1xeVxerARJgDMCNoZ1BPlWZIhq+bWbGD/XjFqQD+47joWH11kPHyj/tC0:RgXeNCyZ1BteALrJRSW1Hjk/2tvAvm` |
| ICON-DHASH | `783070e0d2fc3c83` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_021_de06b169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de06b1694149c66d59976e32041cc9fe8392536da9466d8f16f0ce48299de123"
    family = "RemusStealer"
    file_name = "1a1caa979ee86b2a7a5fd8510e83ac81.exe"
    file_type = "exe"
    first_seen = "2026-08-23 23:45:12"
  condition:
    hash.sha256(0, filesize) == "de06b1694149c66d59976e32041cc9fe8392536da9466d8f16f0ce48299de123"
}
```

### Sample 22: `057607c2adbdf0c5`

| Field | Value |
|---|---|
| SHA-256 | `057607c2adbdf0c5b70fb0b146566096eb08ad61ce8c3f85ea2987afedc8dba6` |
| Family label | `DCRat` |
| File name | `191cb0b563270b33b7a53f9ae3007708.exe` |
| File type | `exe` |
| First seen | `2026-08-23 23:30:08` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `191cb0b563270b33b7a53f9ae3007708` |
| SHA-1 | `e0777316c637cbe838d2ba9dc765109ddec1de4e` |
| SHA-256 | `057607c2adbdf0c5b70fb0b146566096eb08ad61ce8c3f85ea2987afedc8dba6` |
| SHA3-384 | `d0df083f9f444ecbb983449a9325f36f1addc287e946c268c892f4ee7ccc4e3196d9dff35e2f50f44a25a15528ee38ff` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11715F6027E44CE51F0091633D2EF494847B4A851AAA6E32B7DFA37BE55523A73C0D9CB` |
| SSDEEP | `12288:CLWLcXtVS1cGsx71nsS6nm62kHqFnIVd6CVg/olTBgNSW4Aq:CL7901cGK1nsS6UkHTVd6CVfBg0X` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_022_057607c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057607c2adbdf0c5b70fb0b146566096eb08ad61ce8c3f85ea2987afedc8dba6"
    family = "DCRat"
    file_name = "191cb0b563270b33b7a53f9ae3007708.exe"
    file_type = "exe"
    first_seen = "2026-08-23 23:30:08"
  condition:
    hash.sha256(0, filesize) == "057607c2adbdf0c5b70fb0b146566096eb08ad61ce8c3f85ea2987afedc8dba6"
}
```

### Sample 23: `6c0adf94a816f087`

| Field | Value |
|---|---|
| SHA-256 | `6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90` |
| Family label | `Mirai` |
| File name | `6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90.elf` |
| File type | `elf` |
| First seen | `2026-08-23 23:12:21` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dac64444501f73009d19ace6d4261007` |
| SHA-1 | `09ed34a53a6acc13d5de39e066f08d8d91a359ce` |
| SHA-256 | `6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90` |
| SHA3-384 | `4c238eb2b6aa8bf08391081c95c4d0eeddf5bf1a76f9db6be52e6f5ac16c46b0585111aeb3b048fdc33f37da13d4d53a` |
| TLSH | `T12B249DC1720C7EEFE1432D7D860955235C0CAE16E803979261FD6A47DA7BAE30FB9942` |
| TELFHASH | `t10fe061f1978fa282068ccbcd83c833ac1a0dd001008bef03fd22403c80a082cb85a84f` |
| SSDEEP | `6144:ej5zQmSs1z+wtvAC3uVfAz/TM/CdNiaAmLvBAlJXsPNY:+1SwAemYTTfzhBdP6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_6c0adf94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90"
    family = "Mirai"
    file_name = "6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:12:21"
  condition:
    hash.sha256(0, filesize) == "6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90"
}
```

### Sample 24: `79195062527616a7`

| Field | Value |
|---|---|
| SHA-256 | `79195062527616a74aacbb6cec29188dac61e3d2282f2feb010a72d201187a60` |
| Family label | `Mirai` |
| File name | `00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057.elf` |
| File type | `elf` |
| First seen | `2026-08-23 23:02:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75c1cb5118c48afb6c869af5e939dcdc` |
| SHA-1 | `24d0d1c62692f5d0c874047d1768ddc7730f5d08` |
| SHA-256 | `79195062527616a74aacbb6cec29188dac61e3d2282f2feb010a72d201187a60` |
| SHA3-384 | `d10f8d08bb75b5f16533251403a47ab5cec8bc22817ea868f2b126cffcdacb5ba601ef3077335e46533c8e64d0fba1b3` |
| TLSH | `T118449E01FB180613C1931DB40F7F07A7D36D89922CF9E11D6A0EBB564731ABAA6877C9` |
| SSDEEP | `6144:86bvF8xtTTb9815jhEY0gMaYzHqGsm5YvfNVAfomHiJBOXXMJGMrKe:vunTF8xJMaYrgxcM+e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_79195062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79195062527616a74aacbb6cec29188dac61e3d2282f2feb010a72d201187a60"
    family = "Mirai"
    file_name = "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:02:20"
  condition:
    hash.sha256(0, filesize) == "79195062527616a74aacbb6cec29188dac61e3d2282f2feb010a72d201187a60"
}
```

### Sample 25: `df59830108ea6f2a`

| Field | Value |
|---|---|
| SHA-256 | `df59830108ea6f2a635ff1221ee3a958a7bae2b69a57c9d242daa8010a017afb` |
| Family label | `Mirai` |
| File name | `98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d.elf` |
| File type | `elf` |
| First seen | `2026-08-23 23:02:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb4f57607a4fd416956ea908b9ecd0c3` |
| SHA-1 | `dd976e7f51e2b85a26522307c00419c449149a57` |
| SHA-256 | `df59830108ea6f2a635ff1221ee3a958a7bae2b69a57c9d242daa8010a017afb` |
| SHA3-384 | `3fc415d73cf4c751deb0caf1117025b40fc9dcc998c8e9ebfe5c9a48f7c36e0fab3f41837af19b261babeb43cafad262` |
| TLSH | `T1F6145B07B69244FCC1AAC474836F9523F931785D03247D7BABC0AB716E22F715B19BA2` |
| SSDEEP | `3072:BaPsQ4CxG1uAlAOlZRhe0x3y3tBQLSDjXdOARjN74HFa0niT:BaeiGHL60x8+aTdxBNmJiT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_df598301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df59830108ea6f2a635ff1221ee3a958a7bae2b69a57c9d242daa8010a017afb"
    family = "Mirai"
    file_name = "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:02:18"
  condition:
    hash.sha256(0, filesize) == "df59830108ea6f2a635ff1221ee3a958a7bae2b69a57c9d242daa8010a017afb"
}
```

### Sample 26: `00f60da6b04c8c52`

| Field | Value |
|---|---|
| SHA-256 | `00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057` |
| Family label | `Mirai` |
| File name | `00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057.elf` |
| File type | `elf` |
| First seen | `2026-08-23 23:01:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e600b198ea756893248aca54acfcceb4` |
| SHA-1 | `b6685252211561e3d3c97498633fc051c951fb1b` |
| SHA-256 | `00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057` |
| SHA3-384 | `f34ab09be04b2303a08ca43f6fce1584c40dd554b97c76bb02133a1f3b1e181345a9f9441137ec77c33ce8f35eb64b83` |
| TLSH | `T1C6B31270C64A3D50FF56AF71A81E8BC169EC2F8C3F178F81A6865E10DF3A0A6E1044E1` |
| SSDEEP | `3072:gFA4TUgxYmY1TphuGJJRclvyMGjr94u+qgw4:gFrT79gT6ku5yvjrQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_00f60da6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057"
    family = "Mirai"
    file_name = "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:01:59"
  condition:
    hash.sha256(0, filesize) == "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057"
}
```

### Sample 27: `98f76c72eafaac30`

| Field | Value |
|---|---|
| SHA-256 | `98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d` |
| Family label | `Mirai` |
| File name | `98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d.elf` |
| File type | `elf` |
| First seen | `2026-08-23 23:01:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8de265b2c5d08fc6512f04c48f582b9` |
| SHA-1 | `db5080935d856413ac437d11729ce5c95e44aabe` |
| SHA-256 | `98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d` |
| SHA3-384 | `7bc6f0620e986fcc483a66f14f231b7f9efece7eaf8628d855dbfa94923aa9c3b3d52b57a59c7623ff80efa61ca13a67` |
| TLSH | `T1C39302C8A2EBAB3AD0B5B7B44145178DE5F722102619263F857A11F98CE831D771ACB2` |
| SSDEEP | `1536:EXGFC3PORA0a65pAKyjQfxvO/Vnn5yu6sEoT+Vkzc/4KI:EWFC32STK5fg5y8C2CRI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_98f76c72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d"
    family = "Mirai"
    file_name = "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:01:55"
  condition:
    hash.sha256(0, filesize) == "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d"
}
```

### Sample 28: `11d8760fe2b91111`

| Field | Value |
|---|---|
| SHA-256 | `11d8760fe2b91111299f8c8c08c549a6ce672ce8eba66aa1c8393c70c111f823` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-23 22:59:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf743633658b6240fcb729c609cb476a` |
| SHA-1 | `f414124c77996c103e47e3218068c9e4321019d1` |
| SHA-256 | `11d8760fe2b91111299f8c8c08c549a6ce672ce8eba66aa1c8393c70c111f823` |
| SHA3-384 | `fbef07fc04dc97bff0aaf8f0005dc60aef0184529bb7a9d79eebb3b16a1c8260231abe0bfb52eb98d986f1341fb8af18` |
| TLSH | `T1D4545B5F7B10CF61E229C93049B38B5667E5266327D2C559E21CEE087E6038D682FFE4` |
| TELFHASH | `t1cc4100a04e3bda06db89caec86fdab2e790e91061259cf33ee30417d40510f9e259d4f` |
| SSDEEP | `6144:8vw/BTYT1brnLokn0tP46BhCY6B6+oEOfS:kw/BUhAgS66BS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_11d8760f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d8760fe2b91111299f8c8c08c549a6ce672ce8eba66aa1c8393c70c111f823"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 22:59:13"
  condition:
    hash.sha256(0, filesize) == "11d8760fe2b91111299f8c8c08c549a6ce672ce8eba66aa1c8393c70c111f823"
}
```

### Sample 29: `86896d634f1c3c83`

| Field | Value |
|---|---|
| SHA-256 | `86896d634f1c3c83726da1208a937c384922a074ac8fbe7d0face619f59be4fd` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-23 22:58:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99dd965a6e1299d9768717ee43173191` |
| SHA-1 | `a9a9d9317c6771de342dec2241523241a089f62d` |
| SHA-256 | `86896d634f1c3c83726da1208a937c384922a074ac8fbe7d0face619f59be4fd` |
| SHA3-384 | `5506678242b01a8760d9d3f08b51ee6540f21582a417899fbcae463271ee324a1c79afacae079f81955fd9aa95b01d21` |
| TLSH | `T1CAB31298202558E4E2B2B2B7CC1963616A633DF5B71FFDB9209811D1D6B29F068E35CC` |
| SSDEEP | `1536:qqqdAXuVwQ0PQmD4DL/i6UuNBhTl2llxxNtSfz1lywQiyNICNwV1cv:8dEom8D27uKxN4b1lUGV1s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_86896d63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86896d634f1c3c83726da1208a937c384922a074ac8fbe7d0face619f59be4fd"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 22:58:45"
  condition:
    hash.sha256(0, filesize) == "86896d634f1c3c83726da1208a937c384922a074ac8fbe7d0face619f59be4fd"
}
```

### Sample 30: `6e518b8911286207`

| Field | Value |
|---|---|
| SHA-256 | `6e518b8911286207517182aadf9def67dcdad0a323ccd16f8fa53737352ffdd1` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-23 22:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae0bb6de8bdb97d3053288f62985d7fc` |
| SHA-256 | `6e518b8911286207517182aadf9def67dcdad0a323ccd16f8fa53737352ffdd1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_6e518b89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e518b8911286207517182aadf9def67dcdad0a323ccd16f8fa53737352ffdd1"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 22:52:11"
  condition:
    hash.sha256(0, filesize) == "6e518b8911286207517182aadf9def67dcdad0a323ccd16f8fa53737352ffdd1"
}
```

### Sample 31: `4c24506994a914bb`

| Field | Value |
|---|---|
| SHA-256 | `4c24506994a914bbcc272e271a8ac3af24a4d74e888c7091b01c7f10b7d65b89` |
| Family label | `Mirai` |
| File name | `8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:47:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c48eb4c3556650617cb26e7bb8e899c0` |
| SHA-1 | `c2107b122436d3453fe8711ca3b0a70044ea37e0` |
| SHA-256 | `4c24506994a914bbcc272e271a8ac3af24a4d74e888c7091b01c7f10b7d65b89` |
| SHA3-384 | `5f251b82a4a22a44ac82fcf5934b560e75a8245146c8f43dae8bfcb075501c5b56773a4a7f4b9b9b2b9210be6681971d` |
| TLSH | `T11F144B95F881DE52C6D0267AFA7D518C330317B8D3DB7106CE109B35B7EB95A0E3A982` |
| SSDEEP | `6144:roARFnah1if9UVcYEEUYDckzjR482pwzihN2B6OT+km:7RFahsfucYEEUSnR48Bc2gR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_4c245069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c24506994a914bbcc272e271a8ac3af24a4d74e888c7091b01c7f10b7d65b89"
    family = "Mirai"
    file_name = "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:47:20"
  condition:
    hash.sha256(0, filesize) == "4c24506994a914bbcc272e271a8ac3af24a4d74e888c7091b01c7f10b7d65b89"
}
```

### Sample 32: `8c02ef44040b7405`

| Field | Value |
|---|---|
| SHA-256 | `8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942` |
| Family label | `Mirai` |
| File name | `8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:47:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8eaf39f802ca4d9b558d1efd865daed7` |
| SHA-1 | `b4227063b1fa4e763d85787aa52ce9659db050d0` |
| SHA-256 | `8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942` |
| SHA3-384 | `6a5b23be31fa492db4949ba44914a29b3e8b175657962478b042fbca498333e7d78b60fb5771ca7f609cbbf27d46a36c` |
| TLSH | `T1C88312BBC4D7D380F60B227C168381734672D23D8979B82D205EDA37D7E90B5297929E` |
| SSDEEP | `1536:nSb72pSOHxASHUW62+Iewi0C5LfUVgS1hmfMCCoZlPEqnMHTY9EjDi20ZGwfm:nE72MORASc2+/TcVphUFvPEjTxixZGw+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_8c02ef44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942"
    family = "Mirai"
    file_name = "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:47:03"
  condition:
    hash.sha256(0, filesize) == "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942"
}
```

### Sample 33: `85ab672dedb388e6`

| Field | Value |
|---|---|
| SHA-256 | `85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45` |
| Family label | `unknown` |
| File name | `85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45.exe` |
| File type | `exe` |
| First seen | `2026-08-23 22:46:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ce3dc2177b0713b0766b33676121d3f` |
| SHA-1 | `bf72ccdf2e3eab207ed5a44fa3068eb67303a146` |
| SHA-256 | `85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45` |
| SHA3-384 | `2355343de72a579186be322e61abf9b1deec36f7430af2ddca94787cc72ede943beea073955ec80e20f19c1227e9faf3` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T173D5239A7DF32971D076C3728E82F9ADB02D7B848B228E9B76CC29448D637045C39775` |
| SSDEEP | `49152:D55l6KY+wb2ljlBpGhmam0cgZRzATZUX4uwJl9nGKexSMNqQ8GH:DTs+p1lBCmam0JRkZU4u+lIhxzP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_85ab672d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45"
    family = "unknown"
    file_name = "85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45.exe"
    file_type = "exe"
    first_seen = "2026-08-23 22:46:58"
  condition:
    hash.sha256(0, filesize) == "85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45"
}
```

### Sample 34: `9d2cbab8ecfe9114`

| Field | Value |
|---|---|
| SHA-256 | `9d2cbab8ecfe91145fab343fd7ff401f2b5b868cc9b1e017e009b86879566bef` |
| Family label | `Mirai` |
| File name | `d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:42:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cef01f8e34daf44fcf96cfb4e36f0133` |
| SHA-1 | `8a44184add1cde89554b9a7ad92f05ea6c554a00` |
| SHA-256 | `9d2cbab8ecfe91145fab343fd7ff401f2b5b868cc9b1e017e009b86879566bef` |
| SHA3-384 | `55a60c4c5ae65c16925f9e4f99b15555a330b6990ba87f9e1d0000564660fd4b0e9dedec1704b4bffd7dfe432a9d44bb` |
| TLSH | `T1FE545B5F7B10CF61E229C93049B38B5667E5266327D2C559E21CEE087E6038D682FFE4` |
| TELFHASH | `t1cc4100a04e3bda06db89caec86fdab2e790e91061259cf33ee30417d40510f9e259d4f` |
| SSDEEP | `6144:8vw/FTYT1brnLokn0tP46BhCY6B6+oEOfO:kw/FUhAgS66BO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_9d2cbab8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d2cbab8ecfe91145fab343fd7ff401f2b5b868cc9b1e017e009b86879566bef"
    family = "Mirai"
    file_name = "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:42:19"
  condition:
    hash.sha256(0, filesize) == "9d2cbab8ecfe91145fab343fd7ff401f2b5b868cc9b1e017e009b86879566bef"
}
```

### Sample 35: `d6c231447093e9cf`

| Field | Value |
|---|---|
| SHA-256 | `d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f` |
| Family label | `Mirai` |
| File name | `d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:42:00` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1af5d03f9812644b9076496027e4890` |
| SHA-1 | `2e864e2c940f24639892cbf93bf5d75abe521c6a` |
| SHA-256 | `d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f` |
| SHA3-384 | `cc6381cc2e2821108ec639bdc6fdd58c8c7c64e8dffcdca03001161adf27b473f9ebf5547d4de23598d274554dfbd8e1` |
| TLSH | `T10CB312B0B915F590D5AB20BCD4F423303FAC7E2BE55EED95AB25C4DBE05A045371AC88` |
| SSDEEP | `3072:8pPPz1olFgjIJbygER4s4C1pcGs+itRV1aV:8pz1olFgjytZ/ec+m1C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_d6c23144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f"
    family = "Mirai"
    file_name = "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:42:00"
  condition:
    hash.sha256(0, filesize) == "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f"
}
```

### Sample 36: `398c5fabe2248f87`

| Field | Value |
|---|---|
| SHA-256 | `398c5fabe2248f87cdfd6ad114781b2052bf2b8893436f808fb544d16ba5bdc7` |
| Family label | `Mirai` |
| File name | `04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:37:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fe46e03c9959c8e6d5d4ea2d43d26dc` |
| SHA-1 | `4eed6c6706b04597ffb2bffe829ca8793ec68bba` |
| SHA-256 | `398c5fabe2248f87cdfd6ad114781b2052bf2b8893436f808fb544d16ba5bdc7` |
| SHA3-384 | `5bb31ac3cbc8222d3748437940948c4257bce2183e3dcb6c96b4abe16c5a774f08c8a52135519bdfdd29bb04d172e2ef` |
| TLSH | `T187546C45AF646EFBC41ECE310A6EC30720DD588BA2F9B73AA678CD4CB55A30915F3854` |
| TELFHASH | `t1384121a04e3bda06da98caec89fdab6e790e50165209cf33ee30416d40510f9e25ad5f` |
| SSDEEP | `6144:5PTjLDPkyPykoXEjmuQnmvote43/SGAdgnlCCSH+Ycc6Rj8dAYxt9:5vLCmlEws3/SGcp9pdvJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_398c5fab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "398c5fabe2248f87cdfd6ad114781b2052bf2b8893436f808fb544d16ba5bdc7"
    family = "Mirai"
    file_name = "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:37:18"
  condition:
    hash.sha256(0, filesize) == "398c5fabe2248f87cdfd6ad114781b2052bf2b8893436f808fb544d16ba5bdc7"
}
```

### Sample 37: `04883181702d26da`

| Field | Value |
|---|---|
| SHA-256 | `04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4` |
| Family label | `Mirai` |
| File name | `04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:36:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e89a5c233de337d259e160a39901919f` |
| SHA-1 | `5cecb3c6362477ed9b40f66788675f7c4f797d60` |
| SHA-256 | `04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4` |
| SHA3-384 | `999f8344bfe842945d861abc092b7c12254d6478dc775fd937a50f30574420adf067f4ccb2a631a60a492b364f4bf3fa` |
| TLSH | `T125D3122E6E70C37DD5D30F37F861858E8602F7BEA95802A42FDA458A4EC3939E753491` |
| SSDEEP | `3072:m4cqy2Y59+5HXchzbJeUJkX2YCSG9sJecy69znWH4wr6wz3Q0B4:rcqZ5HXIzsUtx90ew9zn4GMAK4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_04883181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4"
    family = "Mirai"
    file_name = "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:36:57"
  condition:
    hash.sha256(0, filesize) == "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4"
}
```

### Sample 38: `4c4044b17fbf894b`

| Field | Value |
|---|---|
| SHA-256 | `4c4044b17fbf894b3ba2704d6eb0e57d396a1d4cf70a9724519e09e814a6470e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-23 22:33:58` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64dc3f817416a2386c9e1520fb251b46` |
| SHA-1 | `086b86536b8fc5072cac39ab83795a2d1d66aebd` |
| SHA-256 | `4c4044b17fbf894b3ba2704d6eb0e57d396a1d4cf70a9724519e09e814a6470e` |
| SHA3-384 | `16db4cf73877e686c4daa275ba6f2c810bf2e59c00e868698f0364ab605214c479d7e065bd5b3aa188bea4b6dfbba698` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T153764907ECA554EAC1EE9131856395137FA1BC880B3163D72B50F6293F76BE0AEB9314` |
| SSDEEP | `49152:2NjvIUXmoK2A1dQT3LKv7iXrNHRivxmJyOiYgjKc67+Ld64l3i80jD0MVESmmhqy:2NTF2ILo12jTVJaLHSH5YkmE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_4c4044b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c4044b17fbf894b3ba2704d6eb0e57d396a1d4cf70a9724519e09e814a6470e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-23 22:33:58"
  condition:
    hash.sha256(0, filesize) == "4c4044b17fbf894b3ba2704d6eb0e57d396a1d4cf70a9724519e09e814a6470e"
}
```

### Sample 39: `37fd4434ad54d4e7`

| Field | Value |
|---|---|
| SHA-256 | `37fd4434ad54d4e7f69d369d1ae4f566daf942a3304bab4ce23353fb84c03b11` |
| Family label | `Mirai` |
| File name | `30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:22:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a30aad9d300f157e41ad6df17155828c` |
| SHA-1 | `567e40ba1019095b474de6bbacccbf538f48005e` |
| SHA-256 | `37fd4434ad54d4e7f69d369d1ae4f566daf942a3304bab4ce23353fb84c03b11` |
| SHA3-384 | `bc899411c2e2c46512084b9c7b5a2ac267daf039027b0bf63fdba9351fa24edf80b5f3b0980b5f8b2250b07a727bb03f` |
| TLSH | `T147144B95F881DE52C6D0267AFA7D518C330317B8D3DB7106CE109B35B7EB95A0E3A982` |
| SSDEEP | `6144:roARFnah1if9UVcYEEUYDckzjR482pwzihN2B6OTnkm:7RFahsfucYEEUSnR48Bc2gO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_37fd4434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37fd4434ad54d4e7f69d369d1ae4f566daf942a3304bab4ce23353fb84c03b11"
    family = "Mirai"
    file_name = "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:22:17"
  condition:
    hash.sha256(0, filesize) == "37fd4434ad54d4e7f69d369d1ae4f566daf942a3304bab4ce23353fb84c03b11"
}
```

### Sample 40: `30a54c5d4d00be4d`

| Field | Value |
|---|---|
| SHA-256 | `30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b` |
| Family label | `Mirai` |
| File name | `30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b.elf` |
| File type | `elf` |
| First seen | `2026-08-23 22:22:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e64e439006b176da22fc5ed3589f3e0a` |
| SHA-1 | `13cffc10d242f5fe2b7730324b29b7c08b821a3c` |
| SHA-256 | `30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b` |
| SHA3-384 | `eb6041b383db2fb7b7e523e6eb497a326c105f91cf0b069c34cf0d36ec943b307d6ee321201abea27e4d2ff726e149f9` |
| TLSH | `T1A98302BBC59BC281E60B31BC16938463A573C23D997A741D104AEF27D7980B12A7929E` |
| SSDEEP | `1536:nSb72pSOHxASHUW62+Iewi0C5LfUVgS1hmfMCCoZlPEqnMHTY9EjDi4x2d9/occ7:nE72MORASc2+/TcVphUFvPEjTxi4QdN2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_30a54c5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b"
    family = "Mirai"
    file_name = "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:22:04"
  condition:
    hash.sha256(0, filesize) == "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b"
}
```

### Sample 41: `ce811a28e655009c`

| Field | Value |
|---|---|
| SHA-256 | `ce811a28e655009c2fb00557c74c0287af235af3c614a3750959906c27c8b71f` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnsh4xnxn` |
| File type | `elf` |
| First seen | `2026-08-23 22:18:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `119e537b51f088c62d68569e7eec3c21` |
| SHA-1 | `6daed13c076e1348efb86d8a4a59771338c9c99d` |
| SHA-256 | `ce811a28e655009c2fb00557c74c0287af235af3c614a3750959906c27c8b71f` |
| SHA3-384 | `bb5fa6bd92517d15a89f1ead4317c61901b64e9d3ef723330cb41aecc12008d5d1fc57c7672fdc3491c27343b0596b30` |
| TLSH | `T11BD3CF32E0086DA0DD2116B43476597C0340DEB40BE59242EFBEE5AE28B7DA57DEDB60` |
| SSDEEP | `3072:kNOlV+GOAc3YSmDEjdX/VuHVv3WDRGGRhaUNZkP0ZFa:yOlo2ubIVv3sXL5NZmOFa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_ce811a28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce811a28e655009c2fb00557c74c0287af235af3c614a3750959906c27c8b71f"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnsh4xnxn"
    file_type = "elf"
    first_seen = "2026-08-23 22:18:52"
  condition:
    hash.sha256(0, filesize) == "ce811a28e655009c2fb00557c74c0287af235af3c614a3750959906c27c8b71f"
}
```

### Sample 42: `1cd8b7b9a9899d14`

| Field | Value |
|---|---|
| SHA-256 | `1cd8b7b9a9899d145d5f7e54c1346a58427192165acf389a71c833423e99eceb` |
| Family label | `Mirai` |
| File name | `947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49.elf` |
| File type | `elf` |
| First seen | `2026-08-23 21:57:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `921e95540d9020704a58f7e7574ee127` |
| SHA-1 | `d3070b438d50c0d7b3509d8ebf55c74400c37baa` |
| SHA-256 | `1cd8b7b9a9899d145d5f7e54c1346a58427192165acf389a71c833423e99eceb` |
| SHA3-384 | `62cc4c1148552cbd3c3baddc48426ad57064bc8a484c25742f25e4b4c375213730ef02e96a2f423bd4072a3575d98f3a` |
| TLSH | `T168545A5B3710CF65E229C63149B38E5663F5266227E2C549F21CDE18BE6038D682FFE4` |
| TELFHASH | `t1384121a04e3bda06da98caec89fdab6e790e50165209cf33ee30416d40510f9e25ad5f` |
| SSDEEP | `6144:f8WG4VgfI66PuKF1MZDKwcWnYhjj+gEOcbzll:f8WGTwX5WnXgEHl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_1cd8b7b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cd8b7b9a9899d145d5f7e54c1346a58427192165acf389a71c833423e99eceb"
    family = "Mirai"
    file_name = "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49.elf"
    file_type = "elf"
    first_seen = "2026-08-23 21:57:16"
  condition:
    hash.sha256(0, filesize) == "1cd8b7b9a9899d145d5f7e54c1346a58427192165acf389a71c833423e99eceb"
}
```

### Sample 43: `947a1689994744cc`

| Field | Value |
|---|---|
| SHA-256 | `947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49` |
| Family label | `Mirai` |
| File name | `947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49.elf` |
| File type | `elf` |
| First seen | `2026-08-23 21:56:54` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44dbda1abb6fc90bc01be93490455fd5` |
| SHA-1 | `a8ae6bfd844de4adacdb888ddc7703aabd2a9cdd` |
| SHA-256 | `947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49` |
| SHA3-384 | `37fb7e302806d6e51d8397ae09cc4d78cbe7892f9d81c5974c24cac4466daec8aeb4cca120850aaccba75a91d36640bb` |
| TLSH | `T1DFD31231979D6574DDC4C6B1572099EBA3CA6A0E0E8DC3FDFE947692002C82396E3338` |
| SSDEEP | `3072:yNOvtC3lNLUKX8/5NqtyK2S85Xzz+xTgISun8+aNw9FvlwYiugNv+cEmce:y7/bX8/5NqFKORSuSNw9Fep19lJce` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_947a1689
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49"
    family = "Mirai"
    file_name = "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49.elf"
    file_type = "elf"
    first_seen = "2026-08-23 21:56:54"
  condition:
    hash.sha256(0, filesize) == "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49"
}
```

### Sample 44: `87a55da10a81400a`

| Field | Value |
|---|---|
| SHA-256 | `87a55da10a81400a3175c8d7b6a66b32f1d0ef2d3d04edf8e69d1f4adb897231` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-23 21:53:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70d783253b60c0e089325a259993b864` |
| SHA-1 | `f8cffa4fb43ab5ac46142b9ad42f09c13b7eca88` |
| SHA-256 | `87a55da10a81400a3175c8d7b6a66b32f1d0ef2d3d04edf8e69d1f4adb897231` |
| SHA3-384 | `d47c0c2943cafdf0fbaa19778f8c54895bacb16c46c02c6370bc82853aecad9cecc88bf2929c131aba55a1b219789906` |
| TLSH | `T129143A95F880DE52C6D0267AFA7D518C331317B8D3DAB106CE109B35B7EB95A0E3E942` |
| SSDEEP | `6144:WvS1nJhhifKLGtWcYEEUj66Ujm2zF3NTvhObJvNaa6sRYk7:KSvhwfv4cYEEUW6CthJCN0m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_87a55da1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87a55da10a81400a3175c8d7b6a66b32f1d0ef2d3d04edf8e69d1f4adb897231"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:53:17"
  condition:
    hash.sha256(0, filesize) == "87a55da10a81400a3175c8d7b6a66b32f1d0ef2d3d04edf8e69d1f4adb897231"
}
```

### Sample 45: `9762c237244c0f4e`

| Field | Value |
|---|---|
| SHA-256 | `9762c237244c0f4ede7b888e30e90e525ce6fa9bbabad2ea39eef78ab81ac22e` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-23 21:52:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dcc437c774b725b89d2db3a68609e64` |
| SHA-1 | `050c5e779eb2022405465ab05ca40338c0ac1f88` |
| SHA-256 | `9762c237244c0f4ede7b888e30e90e525ce6fa9bbabad2ea39eef78ab81ac22e` |
| SHA3-384 | `6b5c0755bb9c5b2c617a9a9a3f2ebcfd1442c4cf6b5c1a1ac84e6aa802760d645b8aadf69afa9b9b1ce730640b33018f` |
| TLSH | `T1BC8312D39949BD84E1B424370CAA8ED5DE7C1C6CE2F83D2112D66F99BAE07C161E05CB` |
| SSDEEP | `1536:Hs/dTUYYwi8pJj9GblO0jTbpX/hDYQnTX5NDKb5d8BIgOK2HHyz/rfp:mdTUYYwppJjil9/lOQnf+dI1OlHHyfB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_9762c237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9762c237244c0f4ede7b888e30e90e525ce6fa9bbabad2ea39eef78ab81ac22e"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:52:47"
  condition:
    hash.sha256(0, filesize) == "9762c237244c0f4ede7b888e30e90e525ce6fa9bbabad2ea39eef78ab81ac22e"
}
```

### Sample 46: `f75534827e7d731b`

| Field | Value |
|---|---|
| SHA-256 | `f75534827e7d731b380b7f2aa8cbf6b23224535ad47fc71c48c8e3e5db6bf66a` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `unknown` |
| First seen | `2026-08-23 21:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d94b6d29e78183358bcf491401d329df` |
| SHA-256 | `f75534827e7d731b380b7f2aa8cbf6b23224535ad47fc71c48c8e3e5db6bf66a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_f7553482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75534827e7d731b380b7f2aa8cbf6b23224535ad47fc71c48c8e3e5db6bf66a"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 21:52:11"
  condition:
    hash.sha256(0, filesize) == "f75534827e7d731b380b7f2aa8cbf6b23224535ad47fc71c48c8e3e5db6bf66a"
}
```

### Sample 47: `146a527e346f2486`

| Field | Value |
|---|---|
| SHA-256 | `146a527e346f2486af376c3d072ac2aa25647da5416409c2488ce3f52bb79873` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-23 21:47:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03d3e9cf8ae03476a9063e688be57051` |
| SHA-1 | `6567b26c4f2026c7d098a54cbff776b56b3bff66` |
| SHA-256 | `146a527e346f2486af376c3d072ac2aa25647da5416409c2488ce3f52bb79873` |
| SHA3-384 | `2c5d8d25789d606db46620c219c4a505ab08b3cc3a60a3bd9f84b2f1479d8c9d104fad3c40cc09806bb48bcd72a0e082` |
| TLSH | `T178144B95F890DE52C6D4267AF96E518C331317B8D2DAB1068D248F34B7EB85E0F3E942` |
| SSDEEP | `3072:vGcbcm3VU4oPipxW/QEtA/kMm6ddLUQ4g8O+CaJ1h7JRnpQVjPtKHPgtKUfJxQyj:vBbUo/kMmIlUQ4g8O7arh7JRn6jkgtKC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_146a527e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "146a527e346f2486af376c3d072ac2aa25647da5416409c2488ce3f52bb79873"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 21:47:16"
  condition:
    hash.sha256(0, filesize) == "146a527e346f2486af376c3d072ac2aa25647da5416409c2488ce3f52bb79873"
}
```

### Sample 48: `801cdfef225b0eb1`

| Field | Value |
|---|---|
| SHA-256 | `801cdfef225b0eb1b72916fc04560fe8363d6199cb7e9f5026fc3301258cdf27` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-23 21:46:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `997f841dd8e81d7352eba941b577208f` |
| SHA-1 | `16546a222bafa49c4675c04a0cd4c6a3ce5f54f3` |
| SHA-256 | `801cdfef225b0eb1b72916fc04560fe8363d6199cb7e9f5026fc3301258cdf27` |
| SHA3-384 | `cf4a45cc55686e1830e4ceab5ca19a88cf44314319c593d0bcdc8ce1057aa7739dc6b785202df3bb49ec716bab3e3ef3` |
| TLSH | `T10683027A4147E439E060AF7A2AB884146DBE4EFCA7E57C3E64484E25E0D72B205F5F03` |
| SSDEEP | `1536:4hVpQvhk/L2FNcFLnnDYS/DjpukwPG1TsyLri2OKVUo9qAaORfU:4hV6hkiN2LLUkwc4x5KVV9zaq8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_801cdfef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801cdfef225b0eb1b72916fc04560fe8363d6199cb7e9f5026fc3301258cdf27"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 21:46:52"
  condition:
    hash.sha256(0, filesize) == "801cdfef225b0eb1b72916fc04560fe8363d6199cb7e9f5026fc3301258cdf27"
}
```

### Sample 49: `c6ef271e202b5905`

| Field | Value |
|---|---|
| SHA-256 | `c6ef271e202b5905fee1e37a307ec0a8e175710cbfb3f1eb16b94fdb3e6a1717` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-23 21:44:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c57fed25ce936659274024cd17ca5ff` |
| SHA-1 | `27b91d5edad4db5cebebfdbf9db7ac6e10aaffce` |
| SHA-256 | `c6ef271e202b5905fee1e37a307ec0a8e175710cbfb3f1eb16b94fdb3e6a1717` |
| SHA3-384 | `0b805ae7275ea09e40b01d5efa1e02c59162be7f71a4d018c10ee0a88000b814788f6dd05b683bbfb4a9ee1c74e53cae` |
| TLSH | `T10F236C6516857C14AE99C4365C7F2F0CB9AD43E6314492EE7FCA3CF28C4A6ACA20861D` |
| SSDEEP | `768:qRr9NyXsZztCc9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:8HusZMcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_c6ef271e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ef271e202b5905fee1e37a307ec0a8e175710cbfb3f1eb16b94fdb3e6a1717"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-23 21:44:43"
  condition:
    hash.sha256(0, filesize) == "c6ef271e202b5905fee1e37a307ec0a8e175710cbfb3f1eb16b94fdb3e6a1717"
}
```

### Sample 50: `f3ac481b23ca149c`

| Field | Value |
|---|---|
| SHA-256 | `f3ac481b23ca149c28fe1e34dbeea0941bbeb77dac229f9594c2d97086e08a2d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-23 21:28:46` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35fb48e153dea1488ae26f9c8d36a764` |
| SHA-1 | `efa1a43149e1c33c86162fef06cd0c4842085db0` |
| SHA-256 | `f3ac481b23ca149c28fe1e34dbeea0941bbeb77dac229f9594c2d97086e08a2d` |
| SHA3-384 | `e3e8a396cdf9d0cf6776c41ef1f335cdb573a272f6fb92d51dabc9f96f0d781e448e6957be7ff2bfaea55956d568dcd6` |
| TLSH | `T1ABC28D956A867C44BEC98A3E4CBE2B1D6DF5C3D1224942AC3D8B3C71DC11F9CD618B1A` |
| SSDEEP | `768:k8vCB+25j6es8Rf9FYpMSUpi+20qUpi+20YQX:k8l25Jpd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_f3ac481b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3ac481b23ca149c28fe1e34dbeea0941bbeb77dac229f9594c2d97086e08a2d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-23 21:28:46"
  condition:
    hash.sha256(0, filesize) == "f3ac481b23ca149c28fe1e34dbeea0941bbeb77dac229f9594c2d97086e08a2d"
}
```

### Sample 51: `5fe64f7166054f9f`

| Field | Value |
|---|---|
| SHA-256 | `5fe64f7166054f9f6ba90241bf5af42293351b0abe37b150772215ef664ac2c5` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-08-23 21:26:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d60112f324a2b01dc6e5c25c06e39e3b` |
| SHA-1 | `99dce41314b2833728c91ac9f236bb2d554ff5d8` |
| SHA-256 | `5fe64f7166054f9f6ba90241bf5af42293351b0abe37b150772215ef664ac2c5` |
| SHA3-384 | `d020bb6ec4a6c15d218a1645149da15720b164aca9f6843b3b77dbec93c2b549d4536836cc939d430bfd15816e9e0e81` |
| TLSH | `T15814AEC1B24C7EEFE1432E7DC64955236C0CAF119403579261FCAA47DB6BAE31F6A881` |
| TELFHASH | `t10fe061f1978fa282068ccbcd83c833ac1a0dd001008bef03fd22403c80a082cb85a84f` |
| SSDEEP | `6144:xee0hk3TPNr8mF9vAC3uIfAHoDZTpt6PMovKjJXvZ:xmi33AePYYUTeZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_5fe64f71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fe64f7166054f9f6ba90241bf5af42293351b0abe37b150772215ef664ac2c5"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-23 21:26:51"
  condition:
    hash.sha256(0, filesize) == "5fe64f7166054f9f6ba90241bf5af42293351b0abe37b150772215ef664ac2c5"
}
```

### Sample 52: `d34d2ccc08cd4faf`

| Field | Value |
|---|---|
| SHA-256 | `d34d2ccc08cd4faf2447798584c30d28240ba444e16a3f4da4df1d3c5faafb3a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-23 21:25:04` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `071eaa8b134e0f130f1c22d9fd95f917` |
| SHA-1 | `254ca470544c1ba460cb890d133d8ce0b9732f4d` |
| SHA-256 | `d34d2ccc08cd4faf2447798584c30d28240ba444e16a3f4da4df1d3c5faafb3a` |
| SHA3-384 | `8a6a42778de6d408b97ec1b857e9333785e432052c5e347a7c831e44d71338f54076de2f65aa866e71ec3ca09d9b7009` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T144764907ECA514EAC1EE9131856395137FA1BC880B3163D72B50F6293F76BE0AEB9354` |
| SSDEEP | `49152:2NjvIUXmoK2A1dQT3LKv7iXrNHRivxmJyOiYgjKc67+Ld64l3i80jD0MVESmmhZO:2NTF2ILo12jTAJgRnFE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_d34d2ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d34d2ccc08cd4faf2447798584c30d28240ba444e16a3f4da4df1d3c5faafb3a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-23 21:25:04"
  condition:
    hash.sha256(0, filesize) == "d34d2ccc08cd4faf2447798584c30d28240ba444e16a3f4da4df1d3c5faafb3a"
}
```

### Sample 53: `58ec8cd17c20989a`

| Field | Value |
|---|---|
| SHA-256 | `58ec8cd17c20989a22f022cd3c1eaa52d7931cf66888340ac50de55927992762` |
| Family label | `Mirai` |
| File name | `main.sh4` |
| File type | `elf` |
| First seen | `2026-08-23 21:22:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74c1b7deafc15aeafe0fbbada410f259` |
| SHA-1 | `963e13e3365f2c211c1a67b5d2b552241735579f` |
| SHA-256 | `58ec8cd17c20989a22f022cd3c1eaa52d7931cf66888340ac50de55927992762` |
| SHA3-384 | `918f8c28a44269f80b3f314a82282b4c790f7b068d108e718ad16c325ac23f98e645ede8abe49fb9c277bb9ba6f937eb` |
| TLSH | `T12413F9A3D526AEF6C016F9B0A4F58DB407227C415B1F0E95B43ACBE0024F9C9F189776` |
| SSDEEP | `768:tfd2g6fVRedN+xXHwwL48P3sz+HxNZxQkIS63RG7iJ:FGV4f4L4k3sz+HxrxI53RnJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_58ec8cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58ec8cd17c20989a22f022cd3c1eaa52d7931cf66888340ac50de55927992762"
    family = "Mirai"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-23 21:22:55"
  condition:
    hash.sha256(0, filesize) == "58ec8cd17c20989a22f022cd3c1eaa52d7931cf66888340ac50de55927992762"
}
```

### Sample 54: `95242eddfd2ed4c1`

| Field | Value |
|---|---|
| SHA-256 | `95242eddfd2ed4c1906c6754c5608e122bf728194355006c1df8fa9ed8c19a94` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-23 21:21:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c19fe8edb3d67c7d90d55b061157b65` |
| SHA-1 | `4a5c2fd9a6b5c6591889ec4a5a4acc9b6d6b44d6` |
| SHA-256 | `95242eddfd2ed4c1906c6754c5608e122bf728194355006c1df8fa9ed8c19a94` |
| SHA3-384 | `7c0873ba2c595ae48f0d529e29545e6bba1cfc78fb646e7db8102831f4fe8754b14460689a7bbb7e01b5725fe0e84740` |
| TLSH | `T1C9143A95F980DF52C6D0267AFA7D518C330317B8D3DAB006CE149B35B7EB95A0E3A942` |
| SSDEEP | `6144:/bcEJahm+ifX1NbcYEEU31WTP/+Unf9agJ3ku/lTFkf:zDYhGfrbcYEEUl8xF7kGM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_95242edd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95242eddfd2ed4c1906c6754c5608e122bf728194355006c1df8fa9ed8c19a94"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:21:16"
  condition:
    hash.sha256(0, filesize) == "95242eddfd2ed4c1906c6754c5608e122bf728194355006c1df8fa9ed8c19a94"
}
```

### Sample 55: `1f794f46c789bab6`

| Field | Value |
|---|---|
| SHA-256 | `1f794f46c789bab63f5ff6a0c02112010e65ed9ba0747377e0cf5d5891c84102` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-23 21:21:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ead4a9edf1aad396cd63879ad8dba2d` |
| SHA-1 | `36a28d8ee38077ab827116e39f6fa225c011456d` |
| SHA-256 | `1f794f46c789bab63f5ff6a0c02112010e65ed9ba0747377e0cf5d5891c84102` |
| SHA3-384 | `bcfb2f0288d4d6be2fadcb99cb3db8cf9e1047e2f10516b7ee505e43a10f925fa30fed263d5290dd0d8dab75aeff8f20` |
| TLSH | `T1E28302D3C1C76FF6D968A2F092095309654B1D38659EDE9494184EECC2EACEB07BD02E` |
| SSDEEP | `1536:+7u+ydkcyZqvoLnsMP3WSankWYAwZ+dRPbeuZHcfxeoyX9NjWUg3cW0nFbU82mPR:+7u+5IorsMvNakawZ6Be0Hc5edX9lgML` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_1f794f46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f794f46c789bab63f5ff6a0c02112010e65ed9ba0747377e0cf5d5891c84102"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:21:03"
  condition:
    hash.sha256(0, filesize) == "1f794f46c789bab63f5ff6a0c02112010e65ed9ba0747377e0cf5d5891c84102"
}
```

### Sample 56: `fd2a804f1550f5a4`

| Field | Value |
|---|---|
| SHA-256 | `fd2a804f1550f5a4d1ffebe0626e8beac6e4c8f36e89eaa2061a57f2c128578e` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-23 21:16:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaf312760141c6a205eb4880086cd811` |
| SHA-1 | `be08b2e9e0fae9fdc233f1a3c331dedb6c11a9ec` |
| SHA-256 | `fd2a804f1550f5a4d1ffebe0626e8beac6e4c8f36e89eaa2061a57f2c128578e` |
| SHA3-384 | `2368eac84fb0e24575ddfa90571be03e9969c18c0f7bd9a7dc95c527847734786182814fc19686010eaa250fd6438938` |
| TLSH | `T1963141DE05101A721153CE8F77A6364C669DE1E728ABDBD8D85C4F99838838CB261B4D` |
| SSDEEP | `12:Ut6WV7WDd76TZDFVlE6Cjlpp7DYNi6YNCRkSaGJ67QL6Q3y2Jf/I6J7GK6yL4X7m:wV7WeDPIjl3ENONCRgON8sP4vkD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_fd2a804f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd2a804f1550f5a4d1ffebe0626e8beac6e4c8f36e89eaa2061a57f2c128578e"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-23 21:16:52"
  condition:
    hash.sha256(0, filesize) == "fd2a804f1550f5a4d1ffebe0626e8beac6e4c8f36e89eaa2061a57f2c128578e"
}
```

### Sample 57: `0bba2af84f34e694`

| Field | Value |
|---|---|
| SHA-256 | `0bba2af84f34e6949d9940afff7e72291c129bf90482e24bd6c0ac3aa13527aa` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-23 21:15:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f12f6d076926f34c1be25f4bd8cd9781` |
| SHA-1 | `6e7cef82aad5a338ea23134de9c6d4f2804adab1` |
| SHA-256 | `0bba2af84f34e6949d9940afff7e72291c129bf90482e24bd6c0ac3aa13527aa` |
| SHA3-384 | `88526ccc6df57f6056e7364b6c56abdf76d1329825380d034bc05fc8518c6205a98c0a688b9fbb8010638fe873522330` |
| TLSH | `T115545C45AF546EFBC42ECE310A6AC30720DD688F92F6BB3AA678CD4C755A30915F3854` |
| TELFHASH | `t1474133a04e3bda0adb98caec85fcab6e780f50165209cf33ee30416d40510f9e25ad5f` |
| SSDEEP | `6144:mil+p9kkBxjkxX9romuJbU2otes7mnSGqRlw/lE5Re6guBIxzBEUY9LIgWKB:jMp9StslRTOmnSGCJzmxe14` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_0bba2af8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bba2af84f34e6949d9940afff7e72291c129bf90482e24bd6c0ac3aa13527aa"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-23 21:15:30"
  condition:
    hash.sha256(0, filesize) == "0bba2af84f34e6949d9940afff7e72291c129bf90482e24bd6c0ac3aa13527aa"
}
```

### Sample 58: `5d31702d78e3f032`

| Field | Value |
|---|---|
| SHA-256 | `5d31702d78e3f032e9444b214a6585b20aec8cb442c0b059dc346eea77717e83` |
| Family label | `unknown` |
| File name | `main.power8le` |
| File type | `elf` |
| First seen | `2026-08-23 21:14:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c213652db267f509d869eac6234a2c0a` |
| SHA-1 | `86b65defc5f7046354921241d0690b64eb9e4a05` |
| SHA-256 | `5d31702d78e3f032e9444b214a6585b20aec8cb442c0b059dc346eea77717e83` |
| SHA3-384 | `90b9da390c658824d34ea8957096e95b7d4f453a04b90781d75538234a414992a159146c228eec98f0596dfa0e8ff9c8` |
| TLSH | `T174D3D60333487A96DF47A83F96C7B9117392B99413618562BB00510FAF76B7ACF0EB49` |
| SSDEEP | `1536:CvSIBFsy9gGqBQNEkWjsp19J7d6ah3iOmHMkAZohTkWGuVz6Urxbh:rYL9WQGkWjsp1f79JmH6WhgVuVzP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_5d31702d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d31702d78e3f032e9444b214a6585b20aec8cb442c0b059dc346eea77717e83"
    family = "unknown"
    file_name = "main.power8le"
    file_type = "elf"
    first_seen = "2026-08-23 21:14:46"
  condition:
    hash.sha256(0, filesize) == "5d31702d78e3f032e9444b214a6585b20aec8cb442c0b059dc346eea77717e83"
}
```

### Sample 59: `6c520987f3e8e28d`

| Field | Value |
|---|---|
| SHA-256 | `6c520987f3e8e28d62754d29046410016f403d61bc3c74741748789ad3d9d6d9` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-23 21:14:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c928e7fecb763d9a3728775b29a8a3b` |
| SHA-1 | `933a8690c17143571fdcc059e3381a45e889a86b` |
| SHA-256 | `6c520987f3e8e28d62754d29046410016f403d61bc3c74741748789ad3d9d6d9` |
| SHA3-384 | `28677a72d84cb3e60a9aed426a6931c1b4c284d1fa0d69ab435511de14ba51fe4a22c0eec39d0e18e779729306dc5d92` |
| TLSH | `T1D3D31278C6AC29CEC1938F3546D14A77723D998A7BF593308A28D0F2C50B471EBA93D5` |
| SSDEEP | `3072:1WVMp4ogJOHVVq3SQzMZWr0U7JhU1KynpVwpQ152AidPqB8LUa0V:1WOw4HVgSwMZcRVnynHwO72Aidf0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_6c520987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c520987f3e8e28d62754d29046410016f403d61bc3c74741748789ad3d9d6d9"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-23 21:14:45"
  condition:
    hash.sha256(0, filesize) == "6c520987f3e8e28d62754d29046410016f403d61bc3c74741748789ad3d9d6d9"
}
```

### Sample 60: `eb3264bc6d506185`

| Field | Value |
|---|---|
| SHA-256 | `eb3264bc6d506185734f21383e3acf62de173c80e630cb163a7f432802ce99d1` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-08-23 21:13:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0442bc440370607ed8eaddac89ce4fd4` |
| SHA-1 | `52733b0a8dbd8e6b721ea2184a727025f656c0fc` |
| SHA-256 | `eb3264bc6d506185734f21383e3acf62de173c80e630cb163a7f432802ce99d1` |
| SHA3-384 | `db35afb077bf94856bbe23b5461e2c802ff0713bf7fe7c9adec5052530a22fd0b74039bebf302afd7dcb43e59fbc7893` |
| TLSH | `T171348F88FA8BC0F0ED930EF0111AE76BAA355D256135F6A3FF893A61F873701585925C` |
| SSDEEP | `6144:rpZ5fTF4Snyg+Zz3yv2wLgwquxFSUgdSsdei:rpZ5fT+SN/+wfSUgn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_eb3264bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3264bc6d506185734f21383e3acf62de173c80e630cb163a7f432802ce99d1"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-23 21:13:22"
  condition:
    hash.sha256(0, filesize) == "eb3264bc6d506185734f21383e3acf62de173c80e630cb163a7f432802ce99d1"
}
```

### Sample 61: `51cad388bdf48972`

| Field | Value |
|---|---|
| SHA-256 | `51cad388bdf48972a50e9beae5e0e27712255550031916dafee78295f16cb51d` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-08-23 21:12:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b716c7ccdd3931e1511b7fa80ec65483` |
| SHA-1 | `0dee735d86bd54ea39fb7d08d6e8229f7652c5dc` |
| SHA-256 | `51cad388bdf48972a50e9beae5e0e27712255550031916dafee78295f16cb51d` |
| SHA3-384 | `0de24d4442ebf022b8c05e0fdc4bd5c491880c4474bc1cb16b5c578beb4a552746bd0162c3f49783a58789db8a6c54c1` |
| TLSH | `T1D19312B2FF506346E5DCD279C95DF8D2D8F68008A74CC56661BC117B8E1E80C9B4BAE8` |
| SSDEEP | `1536:P20Ejg5W4QozI/tbRJYF/kzBDW2IuEPmnap7XMJP309UI6eSCYcYr+N7Rqnouy8s:u9jg5WkI4czBlYBcJP5I6eZYrCyoutDY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_51cad388
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51cad388bdf48972a50e9beae5e0e27712255550031916dafee78295f16cb51d"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-23 21:12:53"
  condition:
    hash.sha256(0, filesize) == "51cad388bdf48972a50e9beae5e0e27712255550031916dafee78295f16cb51d"
}
```

### Sample 62: `126b5270d0a8ac6f`

| Field | Value |
|---|---|
| SHA-256 | `126b5270d0a8ac6fa32bd98ff34f48f3557860d4f0ebf3c429ad6c3fc31fed26` |
| Family label | `unknown` |
| File name | `main.mips64` |
| File type | `elf` |
| First seen | `2026-08-23 21:12:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2c69bad9ce8796d07e05c573814315d` |
| SHA-1 | `083189768d8a7215fe0e7b047f51eeab626f181d` |
| SHA-256 | `126b5270d0a8ac6fa32bd98ff34f48f3557860d4f0ebf3c429ad6c3fc31fed26` |
| SHA3-384 | `08d7d4e803d3230fe6b220ba63c427d928d9b92878f24fafe3cd7f4fe291dc8699b06c49cda16fca8af8272b946e5579` |
| TLSH | `T15F6374517303A96FFCA907B04AF28AF0B398B9E675B156A6E3277F0C4F710A85D085C5` |
| SSDEEP | `1536:5HLagZieqGirfXUd1NbUlQftImPVv4IOdXzJET7KbT/ECiclisZKGxPrqZrqp3qk:5HLnieqs4jdfbTLmCqk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_126b5270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126b5270d0a8ac6fa32bd98ff34f48f3557860d4f0ebf3c429ad6c3fc31fed26"
    family = "unknown"
    file_name = "main.mips64"
    file_type = "elf"
    first_seen = "2026-08-23 21:12:51"
  condition:
    hash.sha256(0, filesize) == "126b5270d0a8ac6fa32bd98ff34f48f3557860d4f0ebf3c429ad6c3fc31fed26"
}
```

### Sample 63: `9686fd30476d60ce`

| Field | Value |
|---|---|
| SHA-256 | `9686fd30476d60ced827935a51c3eddae3048a355f9b744c0dddf662c0d13023` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-23 21:11:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `941364d8d2b979afae7816f88c38266e` |
| SHA-1 | `a662020b1d29e20f4ff3d055a7fc754e57f842d9` |
| SHA-256 | `9686fd30476d60ced827935a51c3eddae3048a355f9b744c0dddf662c0d13023` |
| SHA3-384 | `b0e07f61da4cebc7245c7935a1d666a6fce9fd2a0eb000e2cb0f2e8807e60464c4573ea87af64387efdc579ca334b298` |
| TLSH | `T13F144A07B69244FCC1AAC474876F9423F931785D03243E7BABC4AB716E22F716B19B52` |
| SSDEEP | `3072:9HaZdsKSZ7MZGqXAVAKoxRdpPhEzc9uY3JjhggaA44Tede9W74Ndvn:paaxUG1+JPhEY9l54geg9WCB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_9686fd30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9686fd30476d60ced827935a51c3eddae3048a355f9b744c0dddf662c0d13023"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 21:11:31"
  condition:
    hash.sha256(0, filesize) == "9686fd30476d60ced827935a51c3eddae3048a355f9b744c0dddf662c0d13023"
}
```

### Sample 64: `9cf78a8712e39fc6`

| Field | Value |
|---|---|
| SHA-256 | `9cf78a8712e39fc6d6649055f05528fef722cde1080565f4998ed820a39cb774` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-23 21:11:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3c6772ff24bd8232d7f4a0d5459371d` |
| SHA-1 | `9b31eefbb3c0651b59f5a56c133ee40802e19bf9` |
| SHA-256 | `9cf78a8712e39fc6d6649055f05528fef722cde1080565f4998ed820a39cb774` |
| SHA3-384 | `69b2709d7c6301110e5fbf4f1913363da08fa19916133e8ae7edfecdd5ca2d5236607c64bca5b73b0aa1b14eee99b7db` |
| TLSH | `T1E5449E01FB180613C1931DB40E7F07A7E36989922CF9E11D2A0EBF564731AFA96877D9` |
| SSDEEP | `6144:UzoJpbXnvQrv5QjhHY0EZzwcGOTOAsc1KaA0eM6gJtfT4rfEoKiZ:kwRXn4vQSZzwc6PNyjG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_9cf78a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cf78a8712e39fc6d6649055f05528fef722cde1080565f4998ed820a39cb774"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 21:11:28"
  condition:
    hash.sha256(0, filesize) == "9cf78a8712e39fc6d6649055f05528fef722cde1080565f4998ed820a39cb774"
}
```

### Sample 65: `b8212125ae08e188`

| Field | Value |
|---|---|
| SHA-256 | `b8212125ae08e188044baae7dd2d9641cfeb2fdca65fe870a1e0e7f39ad484a3` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-23 21:10:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b0adff7a8aa89f0e79a68eaf925faa9` |
| SHA-1 | `b93bbac1e55d1d64a452104004f93c992b5ded13` |
| SHA-256 | `b8212125ae08e188044baae7dd2d9641cfeb2fdca65fe870a1e0e7f39ad484a3` |
| SHA3-384 | `a85afdd6595de30d9a9fa1e5b27815df72683369bb9a0a5e4957b7420d3adb55eb443454fcd20985e0d8e144ac918f85` |
| TLSH | `T1679302E6513CE634C327F8334957DAC6E936ABA26A26371F004020FF2D7E5E42593956` |
| SSDEEP | `1536:DP4nFwZQRXhFGmigCLY/t7FSdAFEoXdMQpbskTzhB8FSAaSZbr9ZyvyzdTONiEa:j4FhRRFegKYVAdAFNy+blTzh3AaMZyva` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_b8212125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8212125ae08e188044baae7dd2d9641cfeb2fdca65fe870a1e0e7f39ad484a3"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:53"
  condition:
    hash.sha256(0, filesize) == "b8212125ae08e188044baae7dd2d9641cfeb2fdca65fe870a1e0e7f39ad484a3"
}
```

### Sample 66: `2035b3308bc7bda5`

| Field | Value |
|---|---|
| SHA-256 | `2035b3308bc7bda5e40e2db81fb42dd83e84b3534cacf0983b3c99dca0f33d5c` |
| Family label | `unknown` |
| File name | `main.x86-64-i7` |
| File type | `elf` |
| First seen | `2026-08-23 21:10:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f5a20c49253be87747a0bf849061755` |
| SHA-1 | `f8cb1d504b32a9689e156f965feed1464f57c278` |
| SHA-256 | `2035b3308bc7bda5e40e2db81fb42dd83e84b3534cacf0983b3c99dca0f33d5c` |
| SHA3-384 | `5d57e6e4a5c7395dd96887144d0fc1018f31b0cf6e3a6a0326d4a069c1abbd8ba36b753cf1289c11daaff73201118c4d` |
| TLSH | `T16453F85BB6A3F0BCC247C0745A5BD9B2B93078B002213E7F67C8FA312935E516669F61` |
| TELFHASH | `t1ab2100b159ae2920b2979522b365f53289322d6530c036f1e6b7b5f1df46f831eb1833` |
| SSDEEP | `1536:kPv7pdyb1dAqiNX71qihNOXuvzCUP3RTIW2GUr:6H4nArX71qly+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_2035b330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2035b3308bc7bda5e40e2db81fb42dd83e84b3534cacf0983b3c99dca0f33d5c"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:51"
  condition:
    hash.sha256(0, filesize) == "2035b3308bc7bda5e40e2db81fb42dd83e84b3534cacf0983b3c99dca0f33d5c"
}
```

### Sample 67: `9f1b4ae4fee2661a`

| Field | Value |
|---|---|
| SHA-256 | `9f1b4ae4fee2661ae81dba973307752168d6e35e57f9a5d0039c8eda97b7d9f5` |
| Family label | `unknown` |
| File name | `main.armv6` |
| File type | `elf` |
| First seen | `2026-08-23 21:10:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea4de3effb812c9ebc16e83f60554e5f` |
| SHA-1 | `2a7ebb91d2ecde896c580697907e63b4570e25ae` |
| SHA-256 | `9f1b4ae4fee2661ae81dba973307752168d6e35e57f9a5d0039c8eda97b7d9f5` |
| SHA3-384 | `1221c16643d7dcca5d1b05d52de7b380df64eff172c147adae8508251f04d51a4567d2aac64542617cf6e9d2ca2d76a9` |
| TLSH | `T15B231B45FA619B09C5D232FEFB8D414E37136FA8E7ED32319D306FA023826E61939525` |
| SSDEEP | `768:e8nX3uQdjsgNyb5Id47nQFWXNUL+DRmTqjeC+i7ilb9CVlyEuaVznhS:e8nfHNU517nheL+Qmjt7ilbYVlyyhS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9f1b4ae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f1b4ae4fee2661ae81dba973307752168d6e35e57f9a5d0039c8eda97b7d9f5"
    family = "unknown"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:50"
  condition:
    hash.sha256(0, filesize) == "9f1b4ae4fee2661ae81dba973307752168d6e35e57f9a5d0039c8eda97b7d9f5"
}
```

### Sample 68: `1c6970a335075a60`

| Field | Value |
|---|---|
| SHA-256 | `1c6970a335075a60d1da1f1f66ec8cd8a2279eb06dd12dda2f9896c027f81b2c` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-23 21:10:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98fe90d8634539c7ec9627da2f0eed1b` |
| SHA-1 | `ac74ab50e5856b47cc9a66add3ae1e3fc8a6103c` |
| SHA-256 | `1c6970a335075a60d1da1f1f66ec8cd8a2279eb06dd12dda2f9896c027f81b2c` |
| SHA3-384 | `ab4d50c695cc732e56b844ec58bef592a169ca47c5f24fc2aa45f129bd9a0b62604bf7a5690aeba5dd9fcdd126023cd6` |
| TLSH | `T184A30265E23C8D70FA33F9B47CE9D8F5CFE5BE9C2533954066C98EB0A48BD225104968` |
| SSDEEP | `3072:h6YP2aqF/cN6bj5oGxjmE1R3bWsu0Yyhfh7h4u+qgwPY:4RL/cN0CijmQWdyhBs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_1c6970a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c6970a335075a60d1da1f1f66ec8cd8a2279eb06dd12dda2f9896c027f81b2c"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:48"
  condition:
    hash.sha256(0, filesize) == "1c6970a335075a60d1da1f1f66ec8cd8a2279eb06dd12dda2f9896c027f81b2c"
}
```

### Sample 69: `d8ab47d7ce744d28`

| Field | Value |
|---|---|
| SHA-256 | `d8ab47d7ce744d28e899143ea0823b78b294d56e2ebf756449588a4d1087bd39` |
| Family label | `unknown` |
| File name | `main.armv5` |
| File type | `elf` |
| First seen | `2026-08-23 21:08:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34ae30a0c959e0bf50856e0172e90000` |
| SHA-1 | `e763c76814024ae74aebd6e2f2c1c96bf2e84fcb` |
| SHA-256 | `d8ab47d7ce744d28e899143ea0823b78b294d56e2ebf756449588a4d1087bd39` |
| SHA3-384 | `f45fe080d100c10a0b4947cd84a38304c2d1d0d394b7b00d7d379a64a11133882591d586ec7550ca008b422d7d9f9e4b` |
| TLSH | `T190231B45FA619B09C5D232FEFB8D414E37136FA8E7ED32319D306FA023826E61939525` |
| SSDEEP | `768:e8nX3uQdjsgNyb5Id47nQFWXNUL+DRmTqjeC+i7ilb9CVlyEuaVzIhS:e8nfHNU517nheL+Qmjt7ilbYVlyFhS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_d8ab47d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8ab47d7ce744d28e899143ea0823b78b294d56e2ebf756449588a4d1087bd39"
    family = "unknown"
    file_name = "main.armv5"
    file_type = "elf"
    first_seen = "2026-08-23 21:08:46"
  condition:
    hash.sha256(0, filesize) == "d8ab47d7ce744d28e899143ea0823b78b294d56e2ebf756449588a4d1087bd39"
}
```

### Sample 70: `041ed8e484a8819f`

| Field | Value |
|---|---|
| SHA-256 | `041ed8e484a8819fe28b77e4b19e903dc0382a6658ec261f246a5646acc1cc20` |
| Family label | `unknown` |
| File name | `main.riscv64` |
| File type | `elf` |
| First seen | `2026-08-23 21:08:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d00f18a692f25a63730cd2d24accb10` |
| SHA-1 | `4f2e7392b57c8cc6274b81a9c37fdfc3567064ba` |
| SHA-256 | `041ed8e484a8819fe28b77e4b19e903dc0382a6658ec261f246a5646acc1cc20` |
| SHA3-384 | `614657a38d1cf7ace1fec9e94ad79c18bccd238d67b4c92cf42cfff120d2bd0c15ae5335d083b41404e0472c8a3718a7` |
| TLSH | `T163735AC19C218724C2E613B857F94A55E3D21B123ACB3301CAA1F739BD9E154B693DAF` |
| SSDEEP | `1536:OIwjKq0nbF1G56Bz+Vr/1e8io+DYVJc/TE6A2xyLoTy+oRQk0r:PwjKtp1Q6BqVr/N+Dfg6A2xyLoTyXQR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_041ed8e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "041ed8e484a8819fe28b77e4b19e903dc0382a6658ec261f246a5646acc1cc20"
    family = "unknown"
    file_name = "main.riscv64"
    file_type = "elf"
    first_seen = "2026-08-23 21:08:45"
  condition:
    hash.sha256(0, filesize) == "041ed8e484a8819fe28b77e4b19e903dc0382a6658ec261f246a5646acc1cc20"
}
```

### Sample 71: `4c0547c7cc3387a7`

| Field | Value |
|---|---|
| SHA-256 | `4c0547c7cc3387a73f4fa3ae83d6f31b8c8db721203b863a51674ea5c41fc140` |
| Family label | `unknown` |
| File name | `main.x86-i686` |
| File type | `elf` |
| First seen | `2026-08-23 21:08:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9274e710b5e001156eca13246b5b3fd` |
| SHA-1 | `6cb2ff8dbb0f89d10c5510d94c1172dc0785cdf4` |
| SHA-256 | `4c0547c7cc3387a73f4fa3ae83d6f31b8c8db721203b863a51674ea5c41fc140` |
| SHA3-384 | `2c9456d2c7cc169ffe3409d0ec499f4d292546d02b8024798863a0f67db19c5de93c60aa1c3b29f877ce6098836d9828` |
| TLSH | `T1F9634B41E693C0B0E19341B0099BFBE64634DF36901BEAE6FB9D3D61BD307824D9692D` |
| TELFHASH | `t1ea31c1fb5d205cbcb7e0540ac75b21e39e35e8275e70267a01b639913bf98536174d38` |
| SSDEEP | `1536:KoVO0NrNswSQpTH9cFXMex0cvq1IiPzyCwUr:K6Pbswzp5dcyxryu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_4c0547c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c0547c7cc3387a73f4fa3ae83d6f31b8c8db721203b863a51674ea5c41fc140"
    family = "unknown"
    file_name = "main.x86-i686"
    file_type = "elf"
    first_seen = "2026-08-23 21:08:44"
  condition:
    hash.sha256(0, filesize) == "4c0547c7cc3387a73f4fa3ae83d6f31b8c8db721203b863a51674ea5c41fc140"
}
```

### Sample 72: `2021fdf766aa1a50`

| Field | Value |
|---|---|
| SHA-256 | `2021fdf766aa1a50c0f85c5ac953d5f275f6793abc5aa90261107a6fafc3c08a` |
| Family label | `unknown` |
| File name | `main.mips64r6el-n32` |
| File type | `elf` |
| First seen | `2026-08-23 21:06:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3959372026f8229595007cabd7909dfe` |
| SHA-1 | `3ed2b2a26a4ca54d66e8aa8c76997d9d98088e23` |
| SHA-256 | `2021fdf766aa1a50c0f85c5ac953d5f275f6793abc5aa90261107a6fafc3c08a` |
| SHA3-384 | `416e44f7f9ac996f5844b21baa164ac5bba0199c1fbbdebc6f8b54cf6afc53b2d56e96eeca202ecb902f35cbbe4c1578` |
| TLSH | `T1CFD31A15EE007AB7D09E9E7485BFC09204D63CB7A2D4833976D8698DBF7C65906C3B88` |
| SSDEEP | `1536:8lM2TWHQgNB+g8qAZ+/Hk3Y0twfJLXI5PfEr+:D0vA+g8qU/tuc8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_2021fdf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2021fdf766aa1a50c0f85c5ac953d5f275f6793abc5aa90261107a6fafc3c08a"
    family = "unknown"
    file_name = "main.mips64r6el-n32"
    file_type = "elf"
    first_seen = "2026-08-23 21:06:49"
  condition:
    hash.sha256(0, filesize) == "2021fdf766aa1a50c0f85c5ac953d5f275f6793abc5aa90261107a6fafc3c08a"
}
```

### Sample 73: `ad3cbfc4ea2ad9e5`

| Field | Value |
|---|---|
| SHA-256 | `ad3cbfc4ea2ad9e5879d240418fa4537eeb9b10df0addbfa6211570f9f7709f6` |
| Family label | `njrat` |
| File name | `07d27cbd74e4a700352bc6ab1d85fba6.exe` |
| File type | `exe` |
| First seen | `2026-08-23 21:05:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07d27cbd74e4a700352bc6ab1d85fba6` |
| SHA-1 | `32c6f1ca6fdf80f6be15d5deb2a7469b0d79efe3` |
| SHA-256 | `ad3cbfc4ea2ad9e5879d240418fa4537eeb9b10df0addbfa6211570f9f7709f6` |
| SHA3-384 | `38a1440d21fdea281585054b08e85b28dcc7c73b52149b51bb295c229bfb74cda00fb8944891b71f972da6c6d1ce2673` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F114AD106299E1DBFE64B2756F60D67D1E2D6D28A51287CE22C73FDFFD352C60921220` |
| SSDEEP | `1536:7y7Rqtpqa0b0bPP1hiaopQWlFq4DIAa9kS7SzS09c8c:7y70tg/b0bFhixQWnXw9kS7SzS0Nc` |
| ICON-DHASH | `2000707179306060` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_073_ad3cbfc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad3cbfc4ea2ad9e5879d240418fa4537eeb9b10df0addbfa6211570f9f7709f6"
    family = "njrat"
    file_name = "07d27cbd74e4a700352bc6ab1d85fba6.exe"
    file_type = "exe"
    first_seen = "2026-08-23 21:05:07"
  condition:
    hash.sha256(0, filesize) == "ad3cbfc4ea2ad9e5879d240418fa4537eeb9b10df0addbfa6211570f9f7709f6"
}
```

### Sample 74: `7d9938ede1d3df44`

| Field | Value |
|---|---|
| SHA-256 | `7d9938ede1d3df44fe6db3fa76369ccbaed74647a604fceb6bfb2febe47d0b0c` |
| Family label | `unknown` |
| File name | `main.mipsel` |
| File type | `elf` |
| First seen | `2026-08-23 21:04:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d2bcc8b57ce49f8fdbf70957eec9dc4` |
| SHA-1 | `3ca4b9db9fc9f747240bbbcfe8fb5c24a976d91c` |
| SHA-256 | `7d9938ede1d3df44fe6db3fa76369ccbaed74647a604fceb6bfb2febe47d0b0c` |
| SHA3-384 | `863288ce5b0a72a1211c1b38e7e706a6695c23109fe0f0f016a1983cb06f7c30b82f84ff2af5223606b11230caa2eceb` |
| TLSH | `T124635216AB619E77DC0EDD7301E8860120CCB45B52ED3B2B75B0CA68F78A98F49D3D94` |
| SSDEEP | `768:3hLgINkNLeceYL6OamegMZm1fvx0mQbnOGooXiXsofBIKIaEXDs4ZxW:3INLpee6uJam1fvx0mQbn7ovflhoZxW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_7d9938ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d9938ede1d3df44fe6db3fa76369ccbaed74647a604fceb6bfb2febe47d0b0c"
    family = "unknown"
    file_name = "main.mipsel"
    file_type = "elf"
    first_seen = "2026-08-23 21:04:52"
  condition:
    hash.sha256(0, filesize) == "7d9938ede1d3df44fe6db3fa76369ccbaed74647a604fceb6bfb2febe47d0b0c"
}
```

### Sample 75: `fdd9727681e352e4`

| Field | Value |
|---|---|
| SHA-256 | `fdd9727681e352e4a0aa548af65d02666efc3577b275f96ed73cd47f540ae07b` |
| Family label | `unknown` |
| File name | `main.armv4` |
| File type | `elf` |
| First seen | `2026-08-23 21:04:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `261374d69eb551426ac5721b968c268e` |
| SHA-1 | `89765209175c7e217208837d9ce32785e76850d4` |
| SHA-256 | `fdd9727681e352e4a0aa548af65d02666efc3577b275f96ed73cd47f540ae07b` |
| SHA3-384 | `20475c908197ecac6a13f3f307425c6b31655eaa027f0f794de61072898bcb1223eaf66591b578f3711e28d9a93d6068` |
| TLSH | `T15C23FA82FA198B0AC6C232F7FB9E42CC77296E58E3F531225D326FD133C1AD12965525` |
| TELFHASH | `t1eb11e154488c8e1bd6d0c05ce29f1317562a11be7d772425befbe46a1a31df42c30535` |
| SSDEEP | `768:So1UXcTzId9yhmao2BO9gC/vdPOUfTnzW/bNF4aGKU6JmkyDKf/paTW:HSI6YGd9b/vVpfTnAFuKl4kRwTW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_fdd97276
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd9727681e352e4a0aa548af65d02666efc3577b275f96ed73cd47f540ae07b"
    family = "unknown"
    file_name = "main.armv4"
    file_type = "elf"
    first_seen = "2026-08-23 21:04:50"
  condition:
    hash.sha256(0, filesize) == "fdd9727681e352e4a0aa548af65d02666efc3577b275f96ed73cd47f540ae07b"
}
```

### Sample 76: `f2081d9c1af3a2c7`

| Field | Value |
|---|---|
| SHA-256 | `f2081d9c1af3a2c7bfc4567405d31d9ebc6361a76771bd4ca16acbf553fe8894` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-23 21:03:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0319c6dbd7e705706e190d11f4cbe00` |
| SHA-1 | `47da3b778269b15cfa124475c976fd21f007d114` |
| SHA-256 | `f2081d9c1af3a2c7bfc4567405d31d9ebc6361a76771bd4ca16acbf553fe8894` |
| SHA3-384 | `a29f6def34d17178278dfde92ef17daa9049069db24858356af59e7adf160ba177f5e7a7180c3d3c5b8ab1679985fe80` |
| TLSH | `T109143A99F980DE52C6D0267AFA6D518C330317B8D3DAB006CE145F34B7EB95A0E3E942` |
| SSDEEP | `6144:KcdEHhkifO3e7cYEEUQU5sYo7Ux5s4XaZ/hzMFkD:5dyhjfncYEEUJ2JM/ahhp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f2081d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2081d9c1af3a2c7bfc4567405d31d9ebc6361a76771bd4ca16acbf553fe8894"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:03:34"
  condition:
    hash.sha256(0, filesize) == "f2081d9c1af3a2c7bfc4567405d31d9ebc6361a76771bd4ca16acbf553fe8894"
}
```

### Sample 77: `202b4d1cfa81ba32`

| Field | Value |
|---|---|
| SHA-256 | `202b4d1cfa81ba32b2c86edf3118e4bcb2013722d998db717e558ce17c7ed9b6` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-23 21:02:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5712aedd65d726e674db3cbfc9ea95a9` |
| SHA-1 | `01858ae24b0f2c7598c59d0c7b984f0826cf2970` |
| SHA-256 | `202b4d1cfa81ba32b2c86edf3118e4bcb2013722d998db717e558ce17c7ed9b6` |
| SHA3-384 | `6d7aba049f33dd7e125ef8e2fa5a585611594098a20c733417d6611f50c7d842d314dbdbcceb05ec35460e42df578908` |
| TLSH | `T165830252C9D73ECACC591CBAE02F4204268DFB79D6D6727207B408CDB4C165B96B1B2B` |
| SSDEEP | `1536:H6T/us9+zozEyKtRpWC2Y7kN1Fq9ItxQZL+UyXksXSWK1Wi4VuIAvH2ufNPPKtfd:Ho/R9QJyKtRpWC2Y7EtxQB+6sXSWKcjL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_202b4d1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202b4d1cfa81ba32b2c86edf3118e4bcb2013722d998db717e558ce17c7ed9b6"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:53"
  condition:
    hash.sha256(0, filesize) == "202b4d1cfa81ba32b2c86edf3118e4bcb2013722d998db717e558ce17c7ed9b6"
}
```

### Sample 78: `f43a5473841a17db`

| Field | Value |
|---|---|
| SHA-256 | `f43a5473841a17dbbba9184bb67b61647461477dd4fba01180f750a86c5b979f` |
| Family label | `unknown` |
| File name | `main.e5500` |
| File type | `elf` |
| First seen | `2026-08-23 21:02:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6544a5932ce1c4236c9e1e20f59ecfa9` |
| SHA-1 | `0c1f148887caa16479fb4532897973bdc6ad1827` |
| SHA-256 | `f43a5473841a17dbbba9184bb67b61647461477dd4fba01180f750a86c5b979f` |
| SHA3-384 | `7ac2772aeb2bc576622c2e9d243f558d2d9e8032e4d9d2ba662e8b53dbff9efb49ca17cb2e0a068d273205edef5eab90` |
| TLSH | `T168055C12FF4C6417C70A06B1A56E5B7CFB52B45341F8C6033B0866AF64D233A5DABE89` |
| SSDEEP | `24576:x9irDVWsDu8TYfHR06oWEHEC9FRlJpvqIhNUa3BfQZrZdZ36X3iNV:x9LsDu8TYfHR06oWEHEC9FnThNUa3dQ2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_f43a5473
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43a5473841a17dbbba9184bb67b61647461477dd4fba01180f750a86c5b979f"
    family = "unknown"
    file_name = "main.e5500"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:52"
  condition:
    hash.sha256(0, filesize) == "f43a5473841a17dbbba9184bb67b61647461477dd4fba01180f750a86c5b979f"
}
```

### Sample 79: `ef47735dd93ad62e`

| Field | Value |
|---|---|
| SHA-256 | `ef47735dd93ad62e53344a661de6b41735ad1bc15e26ddb0f364dbd49645e5e6` |
| Family label | `unknown` |
| File name | `main.armv5-eabi` |
| File type | `elf` |
| First seen | `2026-08-23 21:02:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32ea98c9f75f1325459e30e0342fe0be` |
| SHA-1 | `e6d549e6039070da294212af50730ec0af477bec` |
| SHA-256 | `ef47735dd93ad62e53344a661de6b41735ad1bc15e26ddb0f364dbd49645e5e6` |
| SHA3-384 | `5f51ac006aae3b97d348b2d64b65cd9a34261cb0451e2d95166440dc3af8c3ed9fa99665bf699fcf26200aa2c8a9eb26` |
| TLSH | `T1C4630895F840DB35CAC071BAFA5D02DD33130FA8E2EA31158D35AB353BE7A194A3B542` |
| SSDEEP | `1536:i3H8Cvgn87nNEgUs8ENej0kFtG6HTaZF7UM5UIUqk5+Ugusolu2/nXOrV0r:iZU55kEqk5+UW2PkK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_ef47735d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef47735dd93ad62e53344a661de6b41735ad1bc15e26ddb0f364dbd49645e5e6"
    family = "unknown"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:51"
  condition:
    hash.sha256(0, filesize) == "ef47735dd93ad62e53344a661de6b41735ad1bc15e26ddb0f364dbd49645e5e6"
}
```

### Sample 80: `f1d601fc2f0dbb2e`

| Field | Value |
|---|---|
| SHA-256 | `f1d601fc2f0dbb2e47a3d82d37d5c3f46a9af638c1ac9ec18df7967f4561dbcb` |
| Family label | `unknown` |
| File name | `main.i486` |
| File type | `elf` |
| First seen | `2026-08-23 21:02:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b200791dab2c2b86cf8f08174ef62d04` |
| SHA-1 | `f77ad36f627b5ed1410762b6ac2e131983cf3186` |
| SHA-256 | `f1d601fc2f0dbb2e47a3d82d37d5c3f46a9af638c1ac9ec18df7967f4561dbcb` |
| SHA3-384 | `6af43d1102c3dead02a387938aa8a95af1b40b31c5b031c4c6838a955bfa6deb97018b85d7c2de8f8028e57e8ca3f8a2` |
| TLSH | `T135E2D6026743C4B2C50330F112F2EFA24931F97B6A26A606C374AFF5EA551C1A29377E` |
| TELFHASH | `t1822180a47eda11fcf3906c5f566e97878f285a731a6178ae84f973013bf23b18261805` |
| SSDEEP | `384:fIG8uAg3UX8d66dM2iDOuVuKCIvm46zOXHVpEb5v8j1RqRkXLUfTcyxtiDg8xV3k:603UMIeSuKCIvm46zscluxYZfi3IU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_f1d601fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d601fc2f0dbb2e47a3d82d37d5c3f46a9af638c1ac9ec18df7967f4561dbcb"
    family = "unknown"
    file_name = "main.i486"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:49"
  condition:
    hash.sha256(0, filesize) == "f1d601fc2f0dbb2e47a3d82d37d5c3f46a9af638c1ac9ec18df7967f4561dbcb"
}
```

### Sample 81: `ae0bef80f13349e3`

| Field | Value |
|---|---|
| SHA-256 | `ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30` |
| Family label | `unknown` |
| File name | `ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30` |
| File type | `sh` |
| First seen | `2026-08-23 21:00:21` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71a55c7f1d88b8e3add8b45c4cb66af8` |
| SHA-1 | `1a80e6549229824b8cb49a43548c5e7640627833` |
| SHA-256 | `ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30` |
| SHA3-384 | `9bae88510fd074d71e2f6e859b65081ae608b7230ec4545d96cc3d7c68fd515394516279fff34dfbd0595edc7d156b5e` |
| TLSH | `T16F3156EE04142A312603CD9E77A33449B28DD6EB6CAFDBD198090DE9818C68CF271F49` |
| SSDEEP | `12:U86r/MHlaL6la3RL3JXc6rtbn6N6/tDjlx65VFSKx6FSK6ySuxBFI6BFgdj9Hr6L:MMF1ILXBj3k6P3IZd2VIVNWsLI5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_ae0bef80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30"
    family = "unknown"
    file_name = "ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30"
    file_type = "sh"
    first_seen = "2026-08-23 21:00:21"
  condition:
    hash.sha256(0, filesize) == "ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30"
}
```

### Sample 82: `10fa6bca127459de`

| Field | Value |
|---|---|
| SHA-256 | `10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e` |
| Family label | `unknown` |
| File name | `10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e` |
| File type | `sh` |
| First seen | `2026-08-23 21:00:17` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c02735a3ddefa78d3900da64f85cfa8f` |
| SHA-1 | `bee87d1606a5983fd8943d85e4f2596cf28cced6` |
| SHA-256 | `10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e` |
| SHA3-384 | `7908d11ee94ff544d917dc3dc82c4ae2939d6eab22dd0f86ad3050253b9b360ded300d8cf7f92876643325c3ce2574f3` |
| TLSH | `T140316ECA05216A361503CD8EB3A33148B25EE1F7689FC7E4D94C0E9A92887DCF361B59` |
| SSDEEP | `24:MfJ6kGpA0W/ewS78QhAwApM7pF7H5j4OK/:QG+S578eTkM7p5Zj8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_10fa6bca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e"
    family = "unknown"
    file_name = "10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e"
    file_type = "sh"
    first_seen = "2026-08-23 21:00:17"
  condition:
    hash.sha256(0, filesize) == "10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e"
}
```

### Sample 83: `a32f0a45c07582a8`

| Field | Value |
|---|---|
| SHA-256 | `a32f0a45c07582a8c747fa3858b40bc31c5b559308c82e74be1e2abadcdf3bf0` |
| Family label | `Mirai` |
| File name | `f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b.elf` |
| File type | `elf` |
| First seen | `2026-08-23 20:57:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e60263aa16855250af5e31151d47a44` |
| SHA-1 | `ff3cbadad9ce577237dac832a70bf485537225e1` |
| SHA-256 | `a32f0a45c07582a8c747fa3858b40bc31c5b559308c82e74be1e2abadcdf3bf0` |
| SHA3-384 | `3db8f73d1d5f7d530a1ed9ac5c89a746359a5ddd7fb303a75f546b806aab18bc97eb4095cf87bf1cfa905d5b742752fc` |
| TLSH | `T197E34A0AB8C098FDC499C2748BDEB536DD32F4996134B55F27D06E372E8EE216E1DA40` |
| TELFHASH | `t14751fff03ea9389492e7f376b31be9919871092504d170e5ce7769f7ce427890e62423` |
| SSDEEP | `3072:fXMi9oTRAEatdWqQAkMC5HpROHii55362:D7EVNsNBr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_a32f0a45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a32f0a45c07582a8c747fa3858b40bc31c5b559308c82e74be1e2abadcdf3bf0"
    family = "Mirai"
    file_name = "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:28"
  condition:
    hash.sha256(0, filesize) == "a32f0a45c07582a8c747fa3858b40bc31c5b559308c82e74be1e2abadcdf3bf0"
}
```

### Sample 84: `2a02be1e0c6d5431`

| Field | Value |
|---|---|
| SHA-256 | `2a02be1e0c6d5431b2d6f7b82eaf0c90388a79ed27c8ef62f1511d8d91ebe8b0` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-23 20:57:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a579850e4c2a67d0955a527eb33bd3a0` |
| SHA-1 | `03e730e0c41e26abe2e62c8ffffa64479f2d5108` |
| SHA-256 | `2a02be1e0c6d5431b2d6f7b82eaf0c90388a79ed27c8ef62f1511d8d91ebe8b0` |
| SHA3-384 | `cd5312dcd8919cb20ab34351042d7ce407bb3b2f8ae12592047b3ea93b7c128ac13590c2db97f1b61c454d53c01b8eed` |
| TLSH | `T18C143A99F980DE52C6D0267AFA6D518C330317B8D3DAB006CE145F34B7EB95A0E3E942` |
| SSDEEP | `6144:KcdEHhkifO3e7cYEEUQU5sYo7Ux5s4XaZ/hzMrkD:5dyhjfncYEEUJ2JM/ahh/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_2a02be1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a02be1e0c6d5431b2d6f7b82eaf0c90388a79ed27c8ef62f1511d8d91ebe8b0"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:25"
  condition:
    hash.sha256(0, filesize) == "2a02be1e0c6d5431b2d6f7b82eaf0c90388a79ed27c8ef62f1511d8d91ebe8b0"
}
```

### Sample 85: `5cbc9fb2ede32b07`

| Field | Value |
|---|---|
| SHA-256 | `5cbc9fb2ede32b071c0ad9fcad80e3565ede83ff4f3cdc8975c1e76325fdd656` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-23 20:57:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `822c8bdb5482af9072c4f83884aa8d77` |
| SHA-1 | `57ee5db1b1cc628d44b9435203bdb1b9f37f0230` |
| SHA-256 | `5cbc9fb2ede32b071c0ad9fcad80e3565ede83ff4f3cdc8975c1e76325fdd656` |
| SHA3-384 | `47d5719cda6ed7c1963533e3053acd55d459f2682219d0108c6c946a5ac1f9510ab05bec1f0468d08d33b4f2e2b758e8` |
| TLSH | `T10D449E01FB180623C1931DB40E7F07A7E36D89922CF5E11D2A0EBB565731AFA92877D9` |
| SSDEEP | `6144:KR6kAucsTtIpvwfVh4Y0OnqM0Qdv2nKdmGA0z01pJTf9W3m+ORpU:I5csTQvS/nqM054WKv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_5cbc9fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cbc9fb2ede32b071c0ad9fcad80e3565ede83ff4f3cdc8975c1e76325fdd656"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:23"
  condition:
    hash.sha256(0, filesize) == "5cbc9fb2ede32b071c0ad9fcad80e3565ede83ff4f3cdc8975c1e76325fdd656"
}
```

### Sample 86: `f2006a57f197a510`

| Field | Value |
|---|---|
| SHA-256 | `f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b` |
| Family label | `Mirai` |
| File name | `f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b.elf` |
| File type | `elf` |
| First seen | `2026-08-23 20:57:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdb4b308857b746757c43145e23181ec` |
| SHA-1 | `805a9b0a316564ac700049a462aa87f89936d72c` |
| SHA-256 | `f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b` |
| SHA3-384 | `a8e00537018bc279ee94f3baa420e5f04499983a2f3fbd22835a01696213d18305634a954f95d48566e0bef334650291` |
| TLSH | `T1D833F273425AAA74CD341DBD5BF7804176101E42DB970F8F68347BADAC1E3A26CA4DB8` |
| SSDEEP | `1536:TJNRDblB+j3dSuqkQJmqvtIGzV0uwruET:TJXFB+jtS4CmqqGuruW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_f2006a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b"
    family = "Mirai"
    file_name = "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:02"
  condition:
    hash.sha256(0, filesize) == "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b"
}
```

### Sample 87: `33d87b996852e8d9`

| Field | Value |
|---|---|
| SHA-256 | `33d87b996852e8d9337d2d48c85b216fdfdf02c0132061e1e0e8ea1a0893693f` |
| Family label | `unknown` |
| File name | `main.armebv7` |
| File type | `elf` |
| First seen | `2026-08-23 20:56:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25190291daa70ee1f74913ba136ab99e` |
| SHA-1 | `cffe78234ca9cd25595464f317e7c32c6f2df53f` |
| SHA-256 | `33d87b996852e8d9337d2d48c85b216fdfdf02c0132061e1e0e8ea1a0893693f` |
| SHA3-384 | `ed6d6d403ae4ad0c73552934b5cbc75e73c291983203b22426990375b5036d33540b2f099bb52132e6e511e5b5594f5b` |
| TLSH | `T18D531894F840DA35CBD075BAF61D43DD33120FA8E2DA71118E269A353BEB9194E3B942` |
| SSDEEP | `1536:T9mWTnwHfN/oG/vZNUoLG5kBku8yEiE8oUPJ44ibuXLPyw+vmq8rv:Tu4oRoyEipoUPJ3i6Gw+vmqUv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_33d87b99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d87b996852e8d9337d2d48c85b216fdfdf02c0132061e1e0e8ea1a0893693f"
    family = "unknown"
    file_name = "main.armebv7"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:42"
  condition:
    hash.sha256(0, filesize) == "33d87b996852e8d9337d2d48c85b216fdfdf02c0132061e1e0e8ea1a0893693f"
}
```

### Sample 88: `110559e7a15c561e`

| Field | Value |
|---|---|
| SHA-256 | `110559e7a15c561e25868d624a5b04f77368be84db28e9a339d826df297170c1` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-23 20:56:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddcafc9e02ff1fd7f6af2029086503a9` |
| SHA-1 | `a99ed910ba8d4064eb70e33d953f79a4501e998b` |
| SHA-256 | `110559e7a15c561e25868d624a5b04f77368be84db28e9a339d826df297170c1` |
| SHA3-384 | `9335c199a402845da3e6c8d767fd11646ca331a3fd95c7217178375a4788e92ed76491d52e16b6bd8d15ab694e00ab67` |
| TLSH | `T1A8830252C6D7698ACDE61CB6E02E8104158DFEBAD4E633730BB4488C75C266756B0F2B` |
| SSDEEP | `1536:H6T/us9+zozEyKtRpWC2Y7kN1Fq9ItxQZL+UyXksXSWK1Wi4VuIAvH2ufc0oKfG:Ho/R9QJyKtRpWC2Y7EtxQB+6sXSWKcjh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_110559e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "110559e7a15c561e25868d624a5b04f77368be84db28e9a339d826df297170c1"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:40"
  condition:
    hash.sha256(0, filesize) == "110559e7a15c561e25868d624a5b04f77368be84db28e9a339d826df297170c1"
}
```

### Sample 89: `f1fbdf2cb96e536b`

| Field | Value |
|---|---|
| SHA-256 | `f1fbdf2cb96e536b8c0e0bfd61b5b01624b3bbc5305edce75363ce2c5233e37d` |
| Family label | `unknown` |
| File name | `main.microblazebe` |
| File type | `elf` |
| First seen | `2026-08-23 20:56:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1af50ab54b099e5d32fac3703c7c2ae6` |
| SHA-1 | `b8335095f0b5b0c0b7229610a377c88340f3baa4` |
| SHA-256 | `f1fbdf2cb96e536b8c0e0bfd61b5b01624b3bbc5305edce75363ce2c5233e37d` |
| SHA3-384 | `091f5b7a5d3dc5ab636730c05d40e0c995aabbc2cf830d1545d6f4615e28daa0071c61de1039b3685584653a17bea4c8` |
| TLSH | `T108B37331F90667B1CC720A38579A2F096E7708195FEB16625E1F623DEE66810CB31F8D` |
| SSDEEP | `1536:t2kxT8is7rf5AruuO7uuuuuuuuunEeqGwvuEnsal/f/n/A2nN4UV3nz88GJum6m8:hai+uC1GwvnxVoK34Pudig8sbUe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_f1fbdf2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1fbdf2cb96e536b8c0e0bfd61b5b01624b3bbc5305edce75363ce2c5233e37d"
    family = "unknown"
    file_name = "main.microblazebe"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:39"
  condition:
    hash.sha256(0, filesize) == "f1fbdf2cb96e536b8c0e0bfd61b5b01624b3bbc5305edce75363ce2c5233e37d"
}
```

### Sample 90: `4770614aee082f05`

| Field | Value |
|---|---|
| SHA-256 | `4770614aee082f057e505d84bd774d0ed55d5a64e6a164564b926067334184c1` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-23 20:56:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7081138a7d8708c8ff9c74ede56f9f8b` |
| SHA-1 | `b142afd493dd3be336949e0be97daf06a61ba485` |
| SHA-256 | `4770614aee082f057e505d84bd774d0ed55d5a64e6a164564b926067334184c1` |
| SHA3-384 | `82abca485989b9e8492f97feac407637a6ff5006a23089b86f511560c68be744c41681c48529f9ae69cb338a167ac82c` |
| TLSH | `T16CB3128DF3859A82C76900353C4B77B8B76F2AD81821CD614B08AB577426EB4F74D61F` |
| SSDEEP | `3072:sCMeECYs0Mk6NeTCxgO1x5PfwahXTFlSlME24u+qgwk:TMOoM3NeTA1x5PfzjFMWK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_4770614a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4770614aee082f057e505d84bd774d0ed55d5a64e6a164564b926067334184c1"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:38"
  condition:
    hash.sha256(0, filesize) == "4770614aee082f057e505d84bd774d0ed55d5a64e6a164564b926067334184c1"
}
```

### Sample 91: `5d8b93b0448a4f4b`

| Field | Value |
|---|---|
| SHA-256 | `5d8b93b0448a4f4b7e79c9f7af2f33d6a33cbc3895c4c742fd1ece146400c143` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-23 20:55:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74e36ff2366e8a261be1c231a24473ca` |
| SHA-1 | `56401ce6f4d9082f38f876f18d5bd2307e4fe9e6` |
| SHA-256 | `5d8b93b0448a4f4b7e79c9f7af2f33d6a33cbc3895c4c742fd1ece146400c143` |
| SHA3-384 | `83ab31303f0f46750caad29437d8d499b780f471a1e284c991fe17cc208da3744f56e5ffee55eac638169a21fba75f0e` |
| TLSH | `T100145A07B69244FCC0AAC478876F9523F931785D03247D7BABC4AA716E22F316B1DB52` |
| SSDEEP | `3072:3va0si/x3G2NAIA/5TRbzdP4S3PGExaA0/+zomj74SjBEfpl:faOxGn1tdPpp6/GbjBm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_5d8b93b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8b93b0448a4f4b7e79c9f7af2f33d6a33cbc3895c4c742fd1ece146400c143"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 20:55:23"
  condition:
    hash.sha256(0, filesize) == "5d8b93b0448a4f4b7e79c9f7af2f33d6a33cbc3895c4c742fd1ece146400c143"
}
```

### Sample 92: `1715cb5b55fce76b`

| Field | Value |
|---|---|
| SHA-256 | `1715cb5b55fce76b60db203f4ca9b07c4b4a2229bd75c6a47863af35ceb8ba5f` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-23 20:54:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4690a01d507cb141fade7e61109d32ef` |
| SHA-1 | `c9c8c878d8e3b2d43a97b632547c15dfa2dfa0cd` |
| SHA-256 | `1715cb5b55fce76b60db203f4ca9b07c4b4a2229bd75c6a47863af35ceb8ba5f` |
| SHA3-384 | `a47c5efe62c92ba5b5653e2ace427452ff50e07827ec981e5b5d90a6ce387a531fb53f7c66ede2c05c1f8b45d2f262ac` |
| TLSH | `T1FC9302EB69BA9654C4337C3B4608CBE9DF8ABD09550C0FD720F495BD4422DD7A828D1B` |
| SSDEEP | `1536:ntl2UHUUxRK130OqSau8xyQN2xLsUyKsahsImHrji1sXaECyyo1Mx2yVP6LQT9ng:tl2UHUcE13sS2cQQxLsWBmLokaEC7IMW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_1715cb5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1715cb5b55fce76b60db203f4ca9b07c4b4a2229bd75c6a47863af35ceb8ba5f"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 20:54:36"
  condition:
    hash.sha256(0, filesize) == "1715cb5b55fce76b60db203f4ca9b07c4b4a2229bd75c6a47863af35ceb8ba5f"
}
```

### Sample 93: `cfb06c37c8ae8ff2`

| Field | Value |
|---|---|
| SHA-256 | `cfb06c37c8ae8ff22d2a5229e3793802bb4f47a01b60d080ef90d3734ee14624` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-23 20:53:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b11ed2c71337829f07242a8a9687f110` |
| SHA-1 | `23f6db837e96f75a4294527cfe8dd587553851fa` |
| SHA-256 | `cfb06c37c8ae8ff22d2a5229e3793802bb4f47a01b60d080ef90d3734ee14624` |
| SHA3-384 | `3d3fe6589a2d00fbb70566e0545388b5650f23f0a2394db6a829766668463bf9a0c8157af6bf77eeb7aaf03feb6c51e5` |
| TLSH | `T1C754591B7B10CF65E329C53149B38E5667F5265227E2C549F22CDE08BE60389682FFE4` |
| TELFHASH | `t1474133a04e3bda0adb98caec85fcab6e780f50165209cf33ee30416d40510f9e25ad5f` |
| SSDEEP | `6144:h21N8EmSXUTn0bRH+0B9fZTj2zSEQ/kl5/JfN:h21N59TPT9EPJfN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_cfb06c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfb06c37c8ae8ff22d2a5229e3793802bb4f47a01b60d080ef90d3734ee14624"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-23 20:53:25"
  condition:
    hash.sha256(0, filesize) == "cfb06c37c8ae8ff22d2a5229e3793802bb4f47a01b60d080ef90d3734ee14624"
}
```

### Sample 94: `6f278cc413b87287`

| Field | Value |
|---|---|
| SHA-256 | `6f278cc413b8728770b449355533847f4fa6f5f031bb6eff2edc9748bc9cb932` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-23 20:53:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ed7d099f954a8b2648d55199691ebac` |
| SHA-1 | `4fedc2d3698750dca4057b18b8d546a73d68599e` |
| SHA-256 | `6f278cc413b8728770b449355533847f4fa6f5f031bb6eff2edc9748bc9cb932` |
| SHA3-384 | `cdd4eb46d96ffec46cad00063d94dc76b1fa62b88f66d46902eb66a681edf5930ea89bfd08c27c340af121866a2861d7` |
| TLSH | `T14E545B5FBB10CF65E219C53049B38B5667E5226327E2C559E21CEE087E6038D682FFE4` |
| TELFHASH | `t1ec4100a04e3b9a0adb89caec86fdab1e780e91061359cf23ee30417d40510f9e259c4f` |
| SSDEEP | `3072:fwi6WVZrDwRjXF88nRCwU3wNftYRu7Wr6/QnoN5Jv07jVCowlgSTjiTt1DSjzM:V7ZPOjXa8nsqftY47HHanZwRfiTrkg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_6f278cc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f278cc413b8728770b449355533847f4fa6f5f031bb6eff2edc9748bc9cb932"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 20:53:23"
  condition:
    hash.sha256(0, filesize) == "6f278cc413b8728770b449355533847f4fa6f5f031bb6eff2edc9748bc9cb932"
}
```

### Sample 95: `52267cfe8094d646`

| Field | Value |
|---|---|
| SHA-256 | `52267cfe8094d646508ec330b0f96c775fefdfd0c713afb8f0fb7611902a36c7` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-23 20:53:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17b9c8b43f9a2b045958f84b50314d76` |
| SHA-1 | `e905d06d2416cb81f143a698f801324db8910a55` |
| SHA-256 | `52267cfe8094d646508ec330b0f96c775fefdfd0c713afb8f0fb7611902a36c7` |
| SHA3-384 | `30fdc8cf0e65bc42688b9ca0f7f31ae2c2d6a8e322a7747a4742388fd70c27ff20b3e71f1baaeef248721603c51ee6d0` |
| TLSH | `T11D144A95F890DE52C6D4267AF96E518C331317B8D2DAB1068D244F38B7EB85E0F3E942` |
| SSDEEP | `3072:Ygo7nt10/6oPiz0W/QERN/kMmaOLkUQ4g8OcClTWYdnWgQBdEpoAgzqEvJxvy1kY:YXD0/0/kMmnLkUQ4g8OBlTWYdnWRegzk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_52267cfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52267cfe8094d646508ec330b0f96c775fefdfd0c713afb8f0fb7611902a36c7"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 20:53:21"
  condition:
    hash.sha256(0, filesize) == "52267cfe8094d646508ec330b0f96c775fefdfd0c713afb8f0fb7611902a36c7"
}
```

### Sample 96: `e1cdf3e206e6ae2a`

| Field | Value |
|---|---|
| SHA-256 | `e1cdf3e206e6ae2a62903785ae14a81aae050a1bead2e3ada8e830f8ed862fba` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-23 20:52:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `424f113f66aca6469f2876a4f59d5430` |
| SHA-1 | `5b71f1d905cdf0c4d9e63d434ec03fa770a228f4` |
| SHA-256 | `e1cdf3e206e6ae2a62903785ae14a81aae050a1bead2e3ada8e830f8ed862fba` |
| SHA3-384 | `a2d1e3b9d76c375924a8de988b56b995cbd97bb86d9070e33ba2b3019f4ebd873779020c1951150fcacadf101826a78d` |
| TLSH | `T178D31208467851FBD68706B78B13964FBE2512357E2850AD7D20AC4E125EE7434F8FBA` |
| SSDEEP | `3072:IjGeiUUpjc9JxWI/zuaJ7ZUuLQwyciNMv6W2Ecams3CLd:Ix4I9/WI/S27yuLQwnU7AcayLd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_e1cdf3e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1cdf3e206e6ae2a62903785ae14a81aae050a1bead2e3ada8e830f8ed862fba"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:39"
  condition:
    hash.sha256(0, filesize) == "e1cdf3e206e6ae2a62903785ae14a81aae050a1bead2e3ada8e830f8ed862fba"
}
```

### Sample 97: `b127d3f8e1113686`

| Field | Value |
|---|---|
| SHA-256 | `b127d3f8e1113686e921e0a2a987a352a9320621257859f8ea90a48b9570ead9` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-23 20:52:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56003906f144a186daeb397bf76d37a3` |
| SHA-1 | `98a391009f14982129aad2c4864a9b77f706c429` |
| SHA-256 | `b127d3f8e1113686e921e0a2a987a352a9320621257859f8ea90a48b9570ead9` |
| SHA3-384 | `976bf4ff7c80ad3ad581cbeb13d691a4c68220b7f766781e405dacf971ba4af6f6e291fe20528ead029a7313a123f202` |
| TLSH | `T1E2B312550A006CD3CE66B83C92B883D6A7D6F8188E06F6A7375C4695BBF9CEA1D43134` |
| SSDEEP | `3072:1gMOSoabeXTWY2vXlhk4Xo90WL/LdZrTdi3vjt3j7lt3BWV1Zj:1gMOMa0TojPH/diLt3nC1F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_b127d3f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b127d3f8e1113686e921e0a2a987a352a9320621257859f8ea90a48b9570ead9"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:38"
  condition:
    hash.sha256(0, filesize) == "b127d3f8e1113686e921e0a2a987a352a9320621257859f8ea90a48b9570ead9"
}
```

### Sample 98: `a98a53226f1e32c8`

| Field | Value |
|---|---|
| SHA-256 | `a98a53226f1e32c84872fa475b6a8eb1257751fcdc9d953c111e9107022cb407` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-23 20:52:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8216fedd178cab2b29318b0c3e09ac26` |
| SHA-1 | `f0dfe2e8ae272d04bd56bb5d659429c35c1518c1` |
| SHA-256 | `a98a53226f1e32c84872fa475b6a8eb1257751fcdc9d953c111e9107022cb407` |
| SHA3-384 | `7299cebd5ab82b7c63ddcb4581b033134d3049a3de1a9f3f0e95dfb0d31711e26b361bec5c7fb6312feaa0001c4d6b8e` |
| TLSH | `T183831286244C8413F3677C7EFD7C16841BCF4BBCA7E6368A1384C5646A274AA7D88B71` |
| SSDEEP | `1536:nA31sJoDs6PkoIlNWskYiVY90vrfArAMLPDGe40W5lA+Eeafn:kq0s68omAVYUzKAMLPCe4Bjaf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_a98a5322
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98a53226f1e32c84872fa475b6a8eb1257751fcdc9d953c111e9107022cb407"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:37"
  condition:
    hash.sha256(0, filesize) == "a98a53226f1e32c84872fa475b6a8eb1257751fcdc9d953c111e9107022cb407"
}
```

### Sample 99: `423ee359f87a8610`

| Field | Value |
|---|---|
| SHA-256 | `423ee359f87a86107395bd920a0ef48b1024bdaedd9076b49d9eb8d2f50065dc` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-08-23 20:52:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecba28598aa081c7182ddaee20b0c44f` |
| SHA-1 | `8bc17dc2cee7d04638697ad6e15c9d0c0c76fdc5` |
| SHA-256 | `423ee359f87a86107395bd920a0ef48b1024bdaedd9076b49d9eb8d2f50065dc` |
| SHA3-384 | `72054ac42fb56381e77a35f63da40a8b264538906cfc900fedf816f333853faf500b9649638901c8fa8683a86fae7a58` |
| TLSH | `T10714BFC1B24C7EEFE1432E7DC64954236C0DAE12A803579261FCBA47DA6BAE30F75941` |
| TELFHASH | `t10fe061f1978fa282068ccbcd83c833ac1a0dd001008bef03fd22403c80a082cb85a84f` |
| SSDEEP | `6144:9NA9zd/58mOnDqq2DvAC3ujfAYiEEKnV65dfvojJXlY:PAp/58sAe0YKsHiY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_423ee359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "423ee359f87a86107395bd920a0ef48b1024bdaedd9076b49d9eb8d2f50065dc"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:36"
  condition:
    hash.sha256(0, filesize) == "423ee359f87a86107395bd920a0ef48b1024bdaedd9076b49d9eb8d2f50065dc"
}
```

### Sample 100: `f0ac6a4dd595e6a9`

| Field | Value |
|---|---|
| SHA-256 | `f0ac6a4dd595e6a9496f90382df0dda24fa5b0cab9516f31debf16ea500a6249` |
| Family label | `Mirai` |
| File name | `main.x86_64` |
| File type | `elf` |
| First seen | `2026-08-23 20:52:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0eb6c0ed23f7fa117e607df9e038af7` |
| SHA-1 | `184c2eff29511e6143f4c1b1fb15b96469961544` |
| SHA-256 | `f0ac6a4dd595e6a9496f90382df0dda24fa5b0cab9516f31debf16ea500a6249` |
| SHA3-384 | `4700308bc56cf439981add5ca4981f6e797bd14566889c0976d811498b741e71a66ce8fa48270369be24bb777f6ac296` |
| TLSH | `T15A230913E662C12ED05B91B1DBDF9621A623FCBE1331701653B0FF726E55884DE9E282` |
| TELFHASH | `t1f82122b13a2928e072c7f466ba0ae275cd3d1e75219135e5eab0f8f9cb10f011891c17` |
| SSDEEP | `768:REcbY1PoLTk5V/+6tf9CuZahcW9eDgH4sq4WCHyoTFrkwSt9o:RDc1Po85V26JMhcz64KNyUwwSt9o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_f0ac6a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ac6a4dd595e6a9496f90382df0dda24fa5b0cab9516f31debf16ea500a6249"
    family = "Mirai"
    file_name = "main.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:35"
  condition:
    hash.sha256(0, filesize) == "f0ac6a4dd595e6a9496f90382df0dda24fa5b0cab9516f31debf16ea500a6249"
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
 * Generated: 2026-08-24T02:00:17.739565+00:00
 */

rule MalwareBazaar_Mirai_001_20b7849f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20b7849f1b98ff63fc9ae31d2da8a8145e496815bcd5a228f01061063f46216c"
    family = "Mirai"
    file_name = "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:53:17"
  condition:
    hash.sha256(0, filesize) == "20b7849f1b98ff63fc9ae31d2da8a8145e496815bcd5a228f01061063f46216c"
}

rule MalwareBazaar_Mirai_002_8e43add0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a"
    family = "Mirai"
    file_name = "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:52:43"
  condition:
    hash.sha256(0, filesize) == "8e43add0886d834e856cdbda15be486bfbb368359d21cf8d3550bc854978878a"
}

rule MalwareBazaar_unknown_003_b1fe221c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1fe221c2c1aea1ac269bb743b5455f2750d08fbddb777e01d2e1c1364023525"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 01:52:10"
  condition:
    hash.sha256(0, filesize) == "b1fe221c2c1aea1ac269bb743b5455f2750d08fbddb777e01d2e1c1364023525"
}

rule MalwareBazaar_Mirai_004_07ecd27f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44"
    family = "Mirai"
    file_name = "07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:42:30"
  condition:
    hash.sha256(0, filesize) == "07ecd27fdb601292e1ebd8ff88f4c5360bc8c9f3bc1a5ad7d389efa865e58d44"
}

rule MalwareBazaar_Mirai_005_b8f880f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8f880f65a7023dd21c418f0bf70e9c342c7d72e594fbc416689aaf40467fcc4"
    family = "Mirai"
    file_name = "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:37:16"
  condition:
    hash.sha256(0, filesize) == "b8f880f65a7023dd21c418f0bf70e9c342c7d72e594fbc416689aaf40467fcc4"
}

rule MalwareBazaar_Mirai_006_415c91ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f"
    family = "Mirai"
    file_name = "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:36:56"
  condition:
    hash.sha256(0, filesize) == "415c91ff2b7098268f56db653448aa5a5ac7db9692e58b997b721a83bc3b8e6f"
}

rule MalwareBazaar_Mirai_007_78ef93e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78ef93e33f5c390dd4cbbd8098f34cf1a0d961fad2ec8854f8c05065c75a78ba"
    family = "Mirai"
    file_name = "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:27:15"
  condition:
    hash.sha256(0, filesize) == "78ef93e33f5c390dd4cbbd8098f34cf1a0d961fad2ec8854f8c05065c75a78ba"
}

rule MalwareBazaar_Mirai_008_a2232cd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d"
    family = "Mirai"
    file_name = "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d.elf"
    file_type = "elf"
    first_seen = "2026-08-24 01:26:50"
  condition:
    hash.sha256(0, filesize) == "a2232cd0627028b5dceb4deb513f885d9dfef0fe5ef52ed9a006e9c69834031d"
}

rule MalwareBazaar_unknown_009_010384fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "010384fe2d669417d4ea35467f4a990a59a1a921124fd7ec734373c7b4c714b8"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-24 01:07:06"
  condition:
    hash.sha256(0, filesize) == "010384fe2d669417d4ea35467f4a990a59a1a921124fd7ec734373c7b4c714b8"
}

rule MalwareBazaar_unknown_010_dfec0ea9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfec0ea9ed7b1e3ceb813604170f47b0376cdeb226b418dee6e636e80f688cb0"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-24 00:52:11"
  condition:
    hash.sha256(0, filesize) == "dfec0ea9ed7b1e3ceb813604170f47b0376cdeb226b418dee6e636e80f688cb0"
}

rule MalwareBazaar_SystemBC_011_1eb027a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb027a9844495e9a3c64bc0c7ea645058933a9b18cc98ff3f42a7b1a9142753"
    family = "SystemBC"
    file_name = "1f4d12ddad20dd3b74bbd9579f0c57b2.exe"
    file_type = "exe"
    first_seen = "2026-08-24 00:45:09"
  condition:
    hash.sha256(0, filesize) == "1eb027a9844495e9a3c64bc0c7ea645058933a9b18cc98ff3f42a7b1a9142753"
}

rule MalwareBazaar_unknown_012_2445e07b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2445e07bc216418817a5e2dd276e0a8426157557b5f4c6e977d8db9c761ed224"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-24 00:32:57"
  condition:
    hash.sha256(0, filesize) == "2445e07bc216418817a5e2dd276e0a8426157557b5f4c6e977d8db9c761ed224"
}

rule MalwareBazaar_unknown_013_d6208816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c"
    family = "unknown"
    file_name = "d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c.bin"
    file_type = "exe"
    first_seen = "2026-08-24 00:31:20"
  condition:
    hash.sha256(0, filesize) == "d62088168d53fa9bdbb5c442bf093da8b53e69f71ae72c04f864e3aaf201cc9c"
}

rule MalwareBazaar_unknown_014_826ac95a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e"
    family = "unknown"
    file_name = "826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e.exe"
    file_type = "exe"
    first_seen = "2026-08-24 00:27:17"
  condition:
    hash.sha256(0, filesize) == "826ac95ac380c1566761674417bfe72cd4b771b09871b17a15ddeee265bf149e"
}

rule MalwareBazaar_Mirai_015_f50bc37c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50bc37c7ac1d217de7f571d89b8b6ddac65ad852d36b9a6a148e4e01973d198"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 00:21:19"
  condition:
    hash.sha256(0, filesize) == "f50bc37c7ac1d217de7f571d89b8b6ddac65ad852d36b9a6a148e4e01973d198"
}

rule MalwareBazaar_Mirai_016_e46b7dfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e46b7dfe2ab10669bb7ee95337fb91507709ac8516653ac063d39acaa1f8b72a"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-24 00:21:01"
  condition:
    hash.sha256(0, filesize) == "e46b7dfe2ab10669bb7ee95337fb91507709ac8516653ac063d39acaa1f8b72a"
}

rule MalwareBazaar_unknown_017_6112186b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6112186bff6395832fb6efe21d3e5d285f959f50299d0570dfab7ed412be82c4"
    family = "unknown"
    file_name = "stage2.bin"
    file_type = "exe"
    first_seen = "2026-08-24 00:20:47"
  condition:
    hash.sha256(0, filesize) == "6112186bff6395832fb6efe21d3e5d285f959f50299d0570dfab7ed412be82c4"
}

rule MalwareBazaar_Mirai_018_8a640912
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a640912022d829a62612042935a6ba20f13e0b95a535cb4866ae0b091c62d51"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnriscv64xnxn"
    file_type = "elf"
    first_seen = "2026-08-24 00:16:59"
  condition:
    hash.sha256(0, filesize) == "8a640912022d829a62612042935a6ba20f13e0b95a535cb4866ae0b091c62d51"
}

rule MalwareBazaar_unknown_019_b2db7036
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711"
    family = "unknown"
    file_name = "b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711.exe"
    file_type = "exe"
    first_seen = "2026-08-24 00:16:51"
  condition:
    hash.sha256(0, filesize) == "b2db7036c63d9d801907122be93c11d32657fc7890149d38c5050a83a48fa711"
}

rule MalwareBazaar_unknown_020_cce51ae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cce51ae71c056fbd149f0d9ba817fcac74015fb4f800e59f1cc5cd4b5a3b361f"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 23:52:10"
  condition:
    hash.sha256(0, filesize) == "cce51ae71c056fbd149f0d9ba817fcac74015fb4f800e59f1cc5cd4b5a3b361f"
}

rule MalwareBazaar_RemusStealer_021_de06b169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de06b1694149c66d59976e32041cc9fe8392536da9466d8f16f0ce48299de123"
    family = "RemusStealer"
    file_name = "1a1caa979ee86b2a7a5fd8510e83ac81.exe"
    file_type = "exe"
    first_seen = "2026-08-23 23:45:12"
  condition:
    hash.sha256(0, filesize) == "de06b1694149c66d59976e32041cc9fe8392536da9466d8f16f0ce48299de123"
}

rule MalwareBazaar_DCRat_022_057607c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "057607c2adbdf0c5b70fb0b146566096eb08ad61ce8c3f85ea2987afedc8dba6"
    family = "DCRat"
    file_name = "191cb0b563270b33b7a53f9ae3007708.exe"
    file_type = "exe"
    first_seen = "2026-08-23 23:30:08"
  condition:
    hash.sha256(0, filesize) == "057607c2adbdf0c5b70fb0b146566096eb08ad61ce8c3f85ea2987afedc8dba6"
}

rule MalwareBazaar_Mirai_023_6c0adf94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90"
    family = "Mirai"
    file_name = "6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:12:21"
  condition:
    hash.sha256(0, filesize) == "6c0adf94a816f0876be632e219f983f39e40ca4425489accbf4b3a4e7f37af90"
}

rule MalwareBazaar_Mirai_024_79195062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79195062527616a74aacbb6cec29188dac61e3d2282f2feb010a72d201187a60"
    family = "Mirai"
    file_name = "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:02:20"
  condition:
    hash.sha256(0, filesize) == "79195062527616a74aacbb6cec29188dac61e3d2282f2feb010a72d201187a60"
}

rule MalwareBazaar_Mirai_025_df598301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df59830108ea6f2a635ff1221ee3a958a7bae2b69a57c9d242daa8010a017afb"
    family = "Mirai"
    file_name = "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:02:18"
  condition:
    hash.sha256(0, filesize) == "df59830108ea6f2a635ff1221ee3a958a7bae2b69a57c9d242daa8010a017afb"
}

rule MalwareBazaar_Mirai_026_00f60da6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057"
    family = "Mirai"
    file_name = "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:01:59"
  condition:
    hash.sha256(0, filesize) == "00f60da6b04c8c520157d51e48d30dec9dbb17c72849e42ba50a2087c0167057"
}

rule MalwareBazaar_Mirai_027_98f76c72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d"
    family = "Mirai"
    file_name = "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d.elf"
    file_type = "elf"
    first_seen = "2026-08-23 23:01:55"
  condition:
    hash.sha256(0, filesize) == "98f76c72eafaac30b1aeb71e95dfdcd3993a6d4f1483bb5cc82dd352a219c45d"
}

rule MalwareBazaar_Mirai_028_11d8760f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11d8760fe2b91111299f8c8c08c549a6ce672ce8eba66aa1c8393c70c111f823"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 22:59:13"
  condition:
    hash.sha256(0, filesize) == "11d8760fe2b91111299f8c8c08c549a6ce672ce8eba66aa1c8393c70c111f823"
}

rule MalwareBazaar_Mirai_029_86896d63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86896d634f1c3c83726da1208a937c384922a074ac8fbe7d0face619f59be4fd"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 22:58:45"
  condition:
    hash.sha256(0, filesize) == "86896d634f1c3c83726da1208a937c384922a074ac8fbe7d0face619f59be4fd"
}

rule MalwareBazaar_unknown_030_6e518b89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e518b8911286207517182aadf9def67dcdad0a323ccd16f8fa53737352ffdd1"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 22:52:11"
  condition:
    hash.sha256(0, filesize) == "6e518b8911286207517182aadf9def67dcdad0a323ccd16f8fa53737352ffdd1"
}

rule MalwareBazaar_Mirai_031_4c245069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c24506994a914bbcc272e271a8ac3af24a4d74e888c7091b01c7f10b7d65b89"
    family = "Mirai"
    file_name = "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:47:20"
  condition:
    hash.sha256(0, filesize) == "4c24506994a914bbcc272e271a8ac3af24a4d74e888c7091b01c7f10b7d65b89"
}

rule MalwareBazaar_Mirai_032_8c02ef44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942"
    family = "Mirai"
    file_name = "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:47:03"
  condition:
    hash.sha256(0, filesize) == "8c02ef44040b74058b6b50e92a70a9931e138204122451a33dc03767e7875942"
}

rule MalwareBazaar_unknown_033_85ab672d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45"
    family = "unknown"
    file_name = "85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45.exe"
    file_type = "exe"
    first_seen = "2026-08-23 22:46:58"
  condition:
    hash.sha256(0, filesize) == "85ab672dedb388e69891f5c1b1a6a7f890ecadf1e0ac0a16183e2c4f23f36f45"
}

rule MalwareBazaar_Mirai_034_9d2cbab8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d2cbab8ecfe91145fab343fd7ff401f2b5b868cc9b1e017e009b86879566bef"
    family = "Mirai"
    file_name = "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:42:19"
  condition:
    hash.sha256(0, filesize) == "9d2cbab8ecfe91145fab343fd7ff401f2b5b868cc9b1e017e009b86879566bef"
}

rule MalwareBazaar_Mirai_035_d6c23144
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f"
    family = "Mirai"
    file_name = "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:42:00"
  condition:
    hash.sha256(0, filesize) == "d6c231447093e9cf0591ad9ed769836a2d16c74b1a37305111981a92cabf8d5f"
}

rule MalwareBazaar_Mirai_036_398c5fab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "398c5fabe2248f87cdfd6ad114781b2052bf2b8893436f808fb544d16ba5bdc7"
    family = "Mirai"
    file_name = "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:37:18"
  condition:
    hash.sha256(0, filesize) == "398c5fabe2248f87cdfd6ad114781b2052bf2b8893436f808fb544d16ba5bdc7"
}

rule MalwareBazaar_Mirai_037_04883181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4"
    family = "Mirai"
    file_name = "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:36:57"
  condition:
    hash.sha256(0, filesize) == "04883181702d26da9308d3168ae679c8db60d0a7eff1fffed3b91e4e8b0301d4"
}

rule MalwareBazaar_unknown_038_4c4044b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c4044b17fbf894b3ba2704d6eb0e57d396a1d4cf70a9724519e09e814a6470e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-23 22:33:58"
  condition:
    hash.sha256(0, filesize) == "4c4044b17fbf894b3ba2704d6eb0e57d396a1d4cf70a9724519e09e814a6470e"
}

rule MalwareBazaar_Mirai_039_37fd4434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37fd4434ad54d4e7f69d369d1ae4f566daf942a3304bab4ce23353fb84c03b11"
    family = "Mirai"
    file_name = "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:22:17"
  condition:
    hash.sha256(0, filesize) == "37fd4434ad54d4e7f69d369d1ae4f566daf942a3304bab4ce23353fb84c03b11"
}

rule MalwareBazaar_Mirai_040_30a54c5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b"
    family = "Mirai"
    file_name = "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 22:22:04"
  condition:
    hash.sha256(0, filesize) == "30a54c5d4d00be4db4680023b2da1fb3097166c8877abf6aef1e869fe815cb6b"
}

rule MalwareBazaar_Mirai_041_ce811a28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce811a28e655009c2fb00557c74c0287af235af3c614a3750959906c27c8b71f"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnsh4xnxn"
    file_type = "elf"
    first_seen = "2026-08-23 22:18:52"
  condition:
    hash.sha256(0, filesize) == "ce811a28e655009c2fb00557c74c0287af235af3c614a3750959906c27c8b71f"
}

rule MalwareBazaar_Mirai_042_1cd8b7b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cd8b7b9a9899d145d5f7e54c1346a58427192165acf389a71c833423e99eceb"
    family = "Mirai"
    file_name = "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49.elf"
    file_type = "elf"
    first_seen = "2026-08-23 21:57:16"
  condition:
    hash.sha256(0, filesize) == "1cd8b7b9a9899d145d5f7e54c1346a58427192165acf389a71c833423e99eceb"
}

rule MalwareBazaar_Mirai_043_947a1689
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49"
    family = "Mirai"
    file_name = "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49.elf"
    file_type = "elf"
    first_seen = "2026-08-23 21:56:54"
  condition:
    hash.sha256(0, filesize) == "947a1689994744cc4166559895431bc60423dad6624062c97032cc7b67ba9f49"
}

rule MalwareBazaar_Mirai_044_87a55da1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87a55da10a81400a3175c8d7b6a66b32f1d0ef2d3d04edf8e69d1f4adb897231"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:53:17"
  condition:
    hash.sha256(0, filesize) == "87a55da10a81400a3175c8d7b6a66b32f1d0ef2d3d04edf8e69d1f4adb897231"
}

rule MalwareBazaar_Mirai_045_9762c237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9762c237244c0f4ede7b888e30e90e525ce6fa9bbabad2ea39eef78ab81ac22e"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:52:47"
  condition:
    hash.sha256(0, filesize) == "9762c237244c0f4ede7b888e30e90e525ce6fa9bbabad2ea39eef78ab81ac22e"
}

rule MalwareBazaar_unknown_046_f7553482
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f75534827e7d731b380b7f2aa8cbf6b23224535ad47fc71c48c8e3e5db6bf66a"
    family = "unknown"
    file_name = "composer.php"
    file_type = "unknown"
    first_seen = "2026-08-23 21:52:11"
  condition:
    hash.sha256(0, filesize) == "f75534827e7d731b380b7f2aa8cbf6b23224535ad47fc71c48c8e3e5db6bf66a"
}

rule MalwareBazaar_Mirai_047_146a527e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "146a527e346f2486af376c3d072ac2aa25647da5416409c2488ce3f52bb79873"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 21:47:16"
  condition:
    hash.sha256(0, filesize) == "146a527e346f2486af376c3d072ac2aa25647da5416409c2488ce3f52bb79873"
}

rule MalwareBazaar_Mirai_048_801cdfef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801cdfef225b0eb1b72916fc04560fe8363d6199cb7e9f5026fc3301258cdf27"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 21:46:52"
  condition:
    hash.sha256(0, filesize) == "801cdfef225b0eb1b72916fc04560fe8363d6199cb7e9f5026fc3301258cdf27"
}

rule MalwareBazaar_unknown_049_c6ef271e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ef271e202b5905fee1e37a307ec0a8e175710cbfb3f1eb16b94fdb3e6a1717"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-23 21:44:43"
  condition:
    hash.sha256(0, filesize) == "c6ef271e202b5905fee1e37a307ec0a8e175710cbfb3f1eb16b94fdb3e6a1717"
}

rule MalwareBazaar_unknown_050_f3ac481b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3ac481b23ca149c28fe1e34dbeea0941bbeb77dac229f9594c2d97086e08a2d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-23 21:28:46"
  condition:
    hash.sha256(0, filesize) == "f3ac481b23ca149c28fe1e34dbeea0941bbeb77dac229f9594c2d97086e08a2d"
}

rule MalwareBazaar_Mirai_051_5fe64f71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fe64f7166054f9f6ba90241bf5af42293351b0abe37b150772215ef664ac2c5"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-23 21:26:51"
  condition:
    hash.sha256(0, filesize) == "5fe64f7166054f9f6ba90241bf5af42293351b0abe37b150772215ef664ac2c5"
}

rule MalwareBazaar_unknown_052_d34d2ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d34d2ccc08cd4faf2447798584c30d28240ba444e16a3f4da4df1d3c5faafb3a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-23 21:25:04"
  condition:
    hash.sha256(0, filesize) == "d34d2ccc08cd4faf2447798584c30d28240ba444e16a3f4da4df1d3c5faafb3a"
}

rule MalwareBazaar_Mirai_053_58ec8cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58ec8cd17c20989a22f022cd3c1eaa52d7931cf66888340ac50de55927992762"
    family = "Mirai"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-23 21:22:55"
  condition:
    hash.sha256(0, filesize) == "58ec8cd17c20989a22f022cd3c1eaa52d7931cf66888340ac50de55927992762"
}

rule MalwareBazaar_Mirai_054_95242edd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95242eddfd2ed4c1906c6754c5608e122bf728194355006c1df8fa9ed8c19a94"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:21:16"
  condition:
    hash.sha256(0, filesize) == "95242eddfd2ed4c1906c6754c5608e122bf728194355006c1df8fa9ed8c19a94"
}

rule MalwareBazaar_Mirai_055_1f794f46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f794f46c789bab63f5ff6a0c02112010e65ed9ba0747377e0cf5d5891c84102"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:21:03"
  condition:
    hash.sha256(0, filesize) == "1f794f46c789bab63f5ff6a0c02112010e65ed9ba0747377e0cf5d5891c84102"
}

rule MalwareBazaar_unknown_056_fd2a804f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd2a804f1550f5a4d1ffebe0626e8beac6e4c8f36e89eaa2061a57f2c128578e"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-23 21:16:52"
  condition:
    hash.sha256(0, filesize) == "fd2a804f1550f5a4d1ffebe0626e8beac6e4c8f36e89eaa2061a57f2c128578e"
}

rule MalwareBazaar_Mirai_057_0bba2af8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bba2af84f34e6949d9940afff7e72291c129bf90482e24bd6c0ac3aa13527aa"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-23 21:15:30"
  condition:
    hash.sha256(0, filesize) == "0bba2af84f34e6949d9940afff7e72291c129bf90482e24bd6c0ac3aa13527aa"
}

rule MalwareBazaar_unknown_058_5d31702d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d31702d78e3f032e9444b214a6585b20aec8cb442c0b059dc346eea77717e83"
    family = "unknown"
    file_name = "main.power8le"
    file_type = "elf"
    first_seen = "2026-08-23 21:14:46"
  condition:
    hash.sha256(0, filesize) == "5d31702d78e3f032e9444b214a6585b20aec8cb442c0b059dc346eea77717e83"
}

rule MalwareBazaar_Mirai_059_6c520987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c520987f3e8e28d62754d29046410016f403d61bc3c74741748789ad3d9d6d9"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-23 21:14:45"
  condition:
    hash.sha256(0, filesize) == "6c520987f3e8e28d62754d29046410016f403d61bc3c74741748789ad3d9d6d9"
}

rule MalwareBazaar_Mirai_060_eb3264bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3264bc6d506185734f21383e3acf62de173c80e630cb163a7f432802ce99d1"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-23 21:13:22"
  condition:
    hash.sha256(0, filesize) == "eb3264bc6d506185734f21383e3acf62de173c80e630cb163a7f432802ce99d1"
}

rule MalwareBazaar_Mirai_061_51cad388
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51cad388bdf48972a50e9beae5e0e27712255550031916dafee78295f16cb51d"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-23 21:12:53"
  condition:
    hash.sha256(0, filesize) == "51cad388bdf48972a50e9beae5e0e27712255550031916dafee78295f16cb51d"
}

rule MalwareBazaar_unknown_062_126b5270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126b5270d0a8ac6fa32bd98ff34f48f3557860d4f0ebf3c429ad6c3fc31fed26"
    family = "unknown"
    file_name = "main.mips64"
    file_type = "elf"
    first_seen = "2026-08-23 21:12:51"
  condition:
    hash.sha256(0, filesize) == "126b5270d0a8ac6fa32bd98ff34f48f3557860d4f0ebf3c429ad6c3fc31fed26"
}

rule MalwareBazaar_Mirai_063_9686fd30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9686fd30476d60ced827935a51c3eddae3048a355f9b744c0dddf662c0d13023"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 21:11:31"
  condition:
    hash.sha256(0, filesize) == "9686fd30476d60ced827935a51c3eddae3048a355f9b744c0dddf662c0d13023"
}

rule MalwareBazaar_Mirai_064_9cf78a87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cf78a8712e39fc6d6649055f05528fef722cde1080565f4998ed820a39cb774"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 21:11:28"
  condition:
    hash.sha256(0, filesize) == "9cf78a8712e39fc6d6649055f05528fef722cde1080565f4998ed820a39cb774"
}

rule MalwareBazaar_Mirai_065_b8212125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8212125ae08e188044baae7dd2d9641cfeb2fdca65fe870a1e0e7f39ad484a3"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:53"
  condition:
    hash.sha256(0, filesize) == "b8212125ae08e188044baae7dd2d9641cfeb2fdca65fe870a1e0e7f39ad484a3"
}

rule MalwareBazaar_unknown_066_2035b330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2035b3308bc7bda5e40e2db81fb42dd83e84b3534cacf0983b3c99dca0f33d5c"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:51"
  condition:
    hash.sha256(0, filesize) == "2035b3308bc7bda5e40e2db81fb42dd83e84b3534cacf0983b3c99dca0f33d5c"
}

rule MalwareBazaar_unknown_067_9f1b4ae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f1b4ae4fee2661ae81dba973307752168d6e35e57f9a5d0039c8eda97b7d9f5"
    family = "unknown"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:50"
  condition:
    hash.sha256(0, filesize) == "9f1b4ae4fee2661ae81dba973307752168d6e35e57f9a5d0039c8eda97b7d9f5"
}

rule MalwareBazaar_Mirai_068_1c6970a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c6970a335075a60d1da1f1f66ec8cd8a2279eb06dd12dda2f9896c027f81b2c"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 21:10:48"
  condition:
    hash.sha256(0, filesize) == "1c6970a335075a60d1da1f1f66ec8cd8a2279eb06dd12dda2f9896c027f81b2c"
}

rule MalwareBazaar_unknown_069_d8ab47d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8ab47d7ce744d28e899143ea0823b78b294d56e2ebf756449588a4d1087bd39"
    family = "unknown"
    file_name = "main.armv5"
    file_type = "elf"
    first_seen = "2026-08-23 21:08:46"
  condition:
    hash.sha256(0, filesize) == "d8ab47d7ce744d28e899143ea0823b78b294d56e2ebf756449588a4d1087bd39"
}

rule MalwareBazaar_unknown_070_041ed8e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "041ed8e484a8819fe28b77e4b19e903dc0382a6658ec261f246a5646acc1cc20"
    family = "unknown"
    file_name = "main.riscv64"
    file_type = "elf"
    first_seen = "2026-08-23 21:08:45"
  condition:
    hash.sha256(0, filesize) == "041ed8e484a8819fe28b77e4b19e903dc0382a6658ec261f246a5646acc1cc20"
}

rule MalwareBazaar_unknown_071_4c0547c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c0547c7cc3387a73f4fa3ae83d6f31b8c8db721203b863a51674ea5c41fc140"
    family = "unknown"
    file_name = "main.x86-i686"
    file_type = "elf"
    first_seen = "2026-08-23 21:08:44"
  condition:
    hash.sha256(0, filesize) == "4c0547c7cc3387a73f4fa3ae83d6f31b8c8db721203b863a51674ea5c41fc140"
}

rule MalwareBazaar_unknown_072_2021fdf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2021fdf766aa1a50c0f85c5ac953d5f275f6793abc5aa90261107a6fafc3c08a"
    family = "unknown"
    file_name = "main.mips64r6el-n32"
    file_type = "elf"
    first_seen = "2026-08-23 21:06:49"
  condition:
    hash.sha256(0, filesize) == "2021fdf766aa1a50c0f85c5ac953d5f275f6793abc5aa90261107a6fafc3c08a"
}

rule MalwareBazaar_njrat_073_ad3cbfc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad3cbfc4ea2ad9e5879d240418fa4537eeb9b10df0addbfa6211570f9f7709f6"
    family = "njrat"
    file_name = "07d27cbd74e4a700352bc6ab1d85fba6.exe"
    file_type = "exe"
    first_seen = "2026-08-23 21:05:07"
  condition:
    hash.sha256(0, filesize) == "ad3cbfc4ea2ad9e5879d240418fa4537eeb9b10df0addbfa6211570f9f7709f6"
}

rule MalwareBazaar_unknown_074_7d9938ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d9938ede1d3df44fe6db3fa76369ccbaed74647a604fceb6bfb2febe47d0b0c"
    family = "unknown"
    file_name = "main.mipsel"
    file_type = "elf"
    first_seen = "2026-08-23 21:04:52"
  condition:
    hash.sha256(0, filesize) == "7d9938ede1d3df44fe6db3fa76369ccbaed74647a604fceb6bfb2febe47d0b0c"
}

rule MalwareBazaar_unknown_075_fdd97276
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdd9727681e352e4a0aa548af65d02666efc3577b275f96ed73cd47f540ae07b"
    family = "unknown"
    file_name = "main.armv4"
    file_type = "elf"
    first_seen = "2026-08-23 21:04:50"
  condition:
    hash.sha256(0, filesize) == "fdd9727681e352e4a0aa548af65d02666efc3577b275f96ed73cd47f540ae07b"
}

rule MalwareBazaar_Mirai_076_f2081d9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2081d9c1af3a2c7bfc4567405d31d9ebc6361a76771bd4ca16acbf553fe8894"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:03:34"
  condition:
    hash.sha256(0, filesize) == "f2081d9c1af3a2c7bfc4567405d31d9ebc6361a76771bd4ca16acbf553fe8894"
}

rule MalwareBazaar_Mirai_077_202b4d1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202b4d1cfa81ba32b2c86edf3118e4bcb2013722d998db717e558ce17c7ed9b6"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:53"
  condition:
    hash.sha256(0, filesize) == "202b4d1cfa81ba32b2c86edf3118e4bcb2013722d998db717e558ce17c7ed9b6"
}

rule MalwareBazaar_unknown_078_f43a5473
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f43a5473841a17dbbba9184bb67b61647461477dd4fba01180f750a86c5b979f"
    family = "unknown"
    file_name = "main.e5500"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:52"
  condition:
    hash.sha256(0, filesize) == "f43a5473841a17dbbba9184bb67b61647461477dd4fba01180f750a86c5b979f"
}

rule MalwareBazaar_unknown_079_ef47735d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef47735dd93ad62e53344a661de6b41735ad1bc15e26ddb0f364dbd49645e5e6"
    family = "unknown"
    file_name = "main.armv5-eabi"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:51"
  condition:
    hash.sha256(0, filesize) == "ef47735dd93ad62e53344a661de6b41735ad1bc15e26ddb0f364dbd49645e5e6"
}

rule MalwareBazaar_unknown_080_f1d601fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d601fc2f0dbb2e47a3d82d37d5c3f46a9af638c1ac9ec18df7967f4561dbcb"
    family = "unknown"
    file_name = "main.i486"
    file_type = "elf"
    first_seen = "2026-08-23 21:02:49"
  condition:
    hash.sha256(0, filesize) == "f1d601fc2f0dbb2e47a3d82d37d5c3f46a9af638c1ac9ec18df7967f4561dbcb"
}

rule MalwareBazaar_unknown_081_ae0bef80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30"
    family = "unknown"
    file_name = "ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30"
    file_type = "sh"
    first_seen = "2026-08-23 21:00:21"
  condition:
    hash.sha256(0, filesize) == "ae0bef80f13349e34ec2c55c837ad5348c97eeac14b6f6bb2e617245df675d30"
}

rule MalwareBazaar_unknown_082_10fa6bca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e"
    family = "unknown"
    file_name = "10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e"
    file_type = "sh"
    first_seen = "2026-08-23 21:00:17"
  condition:
    hash.sha256(0, filesize) == "10fa6bca127459de07cb6aef4853f4936e5aafd49df7c495134aa4801986512e"
}

rule MalwareBazaar_Mirai_083_a32f0a45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a32f0a45c07582a8c747fa3858b40bc31c5b559308c82e74be1e2abadcdf3bf0"
    family = "Mirai"
    file_name = "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:28"
  condition:
    hash.sha256(0, filesize) == "a32f0a45c07582a8c747fa3858b40bc31c5b559308c82e74be1e2abadcdf3bf0"
}

rule MalwareBazaar_Mirai_084_2a02be1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a02be1e0c6d5431b2d6f7b82eaf0c90388a79ed27c8ef62f1511d8d91ebe8b0"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:25"
  condition:
    hash.sha256(0, filesize) == "2a02be1e0c6d5431b2d6f7b82eaf0c90388a79ed27c8ef62f1511d8d91ebe8b0"
}

rule MalwareBazaar_Mirai_085_5cbc9fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cbc9fb2ede32b071c0ad9fcad80e3565ede83ff4f3cdc8975c1e76325fdd656"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:23"
  condition:
    hash.sha256(0, filesize) == "5cbc9fb2ede32b071c0ad9fcad80e3565ede83ff4f3cdc8975c1e76325fdd656"
}

rule MalwareBazaar_Mirai_086_f2006a57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b"
    family = "Mirai"
    file_name = "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b.elf"
    file_type = "elf"
    first_seen = "2026-08-23 20:57:02"
  condition:
    hash.sha256(0, filesize) == "f2006a57f197a51049224e841ace1bb1eed5de15cceabe20353e76ab4c9e4d6b"
}

rule MalwareBazaar_unknown_087_33d87b99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d87b996852e8d9337d2d48c85b216fdfdf02c0132061e1e0e8ea1a0893693f"
    family = "unknown"
    file_name = "main.armebv7"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:42"
  condition:
    hash.sha256(0, filesize) == "33d87b996852e8d9337d2d48c85b216fdfdf02c0132061e1e0e8ea1a0893693f"
}

rule MalwareBazaar_Mirai_088_110559e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "110559e7a15c561e25868d624a5b04f77368be84db28e9a339d826df297170c1"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:40"
  condition:
    hash.sha256(0, filesize) == "110559e7a15c561e25868d624a5b04f77368be84db28e9a339d826df297170c1"
}

rule MalwareBazaar_unknown_089_f1fbdf2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1fbdf2cb96e536b8c0e0bfd61b5b01624b3bbc5305edce75363ce2c5233e37d"
    family = "unknown"
    file_name = "main.microblazebe"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:39"
  condition:
    hash.sha256(0, filesize) == "f1fbdf2cb96e536b8c0e0bfd61b5b01624b3bbc5305edce75363ce2c5233e37d"
}

rule MalwareBazaar_Mirai_090_4770614a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4770614aee082f057e505d84bd774d0ed55d5a64e6a164564b926067334184c1"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-23 20:56:38"
  condition:
    hash.sha256(0, filesize) == "4770614aee082f057e505d84bd774d0ed55d5a64e6a164564b926067334184c1"
}

rule MalwareBazaar_Mirai_091_5d8b93b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d8b93b0448a4f4b7e79c9f7af2f33d6a33cbc3895c4c742fd1ece146400c143"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 20:55:23"
  condition:
    hash.sha256(0, filesize) == "5d8b93b0448a4f4b7e79c9f7af2f33d6a33cbc3895c4c742fd1ece146400c143"
}

rule MalwareBazaar_Mirai_092_1715cb5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1715cb5b55fce76b60db203f4ca9b07c4b4a2229bd75c6a47863af35ceb8ba5f"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 20:54:36"
  condition:
    hash.sha256(0, filesize) == "1715cb5b55fce76b60db203f4ca9b07c4b4a2229bd75c6a47863af35ceb8ba5f"
}

rule MalwareBazaar_Mirai_093_cfb06c37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfb06c37c8ae8ff22d2a5229e3793802bb4f47a01b60d080ef90d3734ee14624"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-23 20:53:25"
  condition:
    hash.sha256(0, filesize) == "cfb06c37c8ae8ff22d2a5229e3793802bb4f47a01b60d080ef90d3734ee14624"
}

rule MalwareBazaar_Mirai_094_6f278cc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f278cc413b8728770b449355533847f4fa6f5f031bb6eff2edc9748bc9cb932"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 20:53:23"
  condition:
    hash.sha256(0, filesize) == "6f278cc413b8728770b449355533847f4fa6f5f031bb6eff2edc9748bc9cb932"
}

rule MalwareBazaar_Mirai_095_52267cfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52267cfe8094d646508ec330b0f96c775fefdfd0c713afb8f0fb7611902a36c7"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 20:53:21"
  condition:
    hash.sha256(0, filesize) == "52267cfe8094d646508ec330b0f96c775fefdfd0c713afb8f0fb7611902a36c7"
}

rule MalwareBazaar_Mirai_096_e1cdf3e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1cdf3e206e6ae2a62903785ae14a81aae050a1bead2e3ada8e830f8ed862fba"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:39"
  condition:
    hash.sha256(0, filesize) == "e1cdf3e206e6ae2a62903785ae14a81aae050a1bead2e3ada8e830f8ed862fba"
}

rule MalwareBazaar_Mirai_097_b127d3f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b127d3f8e1113686e921e0a2a987a352a9320621257859f8ea90a48b9570ead9"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:38"
  condition:
    hash.sha256(0, filesize) == "b127d3f8e1113686e921e0a2a987a352a9320621257859f8ea90a48b9570ead9"
}

rule MalwareBazaar_Mirai_098_a98a5322
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98a53226f1e32c84872fa475b6a8eb1257751fcdc9d953c111e9107022cb407"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:37"
  condition:
    hash.sha256(0, filesize) == "a98a53226f1e32c84872fa475b6a8eb1257751fcdc9d953c111e9107022cb407"
}

rule MalwareBazaar_Mirai_099_423ee359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "423ee359f87a86107395bd920a0ef48b1024bdaedd9076b49d9eb8d2f50065dc"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:36"
  condition:
    hash.sha256(0, filesize) == "423ee359f87a86107395bd920a0ef48b1024bdaedd9076b49d9eb8d2f50065dc"
}

rule MalwareBazaar_Mirai_100_f0ac6a4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0ac6a4dd595e6a9496f90382df0dda24fa5b0cab9516f31debf16ea500a6249"
    family = "Mirai"
    file_name = "main.x86_64"
    file_type = "elf"
    first_seen = "2026-08-23 20:52:35"
  condition:
    hash.sha256(0, filesize) == "f0ac6a4dd595e6a9496f90382df0dda24fa5b0cab9516f31debf16ea500a6249"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

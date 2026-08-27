# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-27

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 645 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 645 |
| Unique family labels | 15 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 30 |
| Mirai | 28 |
| RemcosRAT | 8 |
| XWorm | 8 |
| SheetRAT | 7 |
| Formbook | 5 |
| Vidar | 3 |
| njrat | 2 |
| STRRAT | 2 |
| ValleyRAT | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 38 |
| exe | 27 |
| js | 13 |
| sh | 5 |
| vbs | 5 |
| unknown | 4 |
| dll | 2 |
| bat | 2 |
| zip | 1 |
| z | 1 |

## Per-Sample Analysis

### Sample 1: `b8d63bcb195fa116`

| Field | Value |
|---|---|
| SHA-256 | `b8d63bcb195fa116a1e6aa80ae02521860d7c91699e1e44e9a6f24bcfdac8515` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-08-27 09:56:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d7346df9861ea4f89ba149d6cb05300` |
| SHA-1 | `9d6607309576f1005a71a0cfa3188bd53de4693b` |
| SHA-256 | `b8d63bcb195fa116a1e6aa80ae02521860d7c91699e1e44e9a6f24bcfdac8515` |
| SHA3-384 | `eb1b2f8c1fe6ef7b9bcf30ca48d35a4248b89d1707ffd886e71a3e6d69cc917a597ad684459f0812a53558a41161796c` |
| TLSH | `T138145A02776D0403D3632DF43B3B13D1939FE4A321A4F644790FAA985BB2931A696DDE` |
| SSDEEP | `6144:8J6xFUbe/xxrny7M6JljGcEssMOgh5otd:Fnl3cJ/EssMOgh5otd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_b8d63bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8d63bcb195fa116a1e6aa80ae02521860d7c91699e1e44e9a6f24bcfdac8515"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-27 09:56:38"
  condition:
    hash.sha256(0, filesize) == "b8d63bcb195fa116a1e6aa80ae02521860d7c91699e1e44e9a6f24bcfdac8515"
}
```

### Sample 2: `339285484b60a51a`

| Field | Value |
|---|---|
| SHA-256 | `339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703` |
| Family label | `unknown` |
| File name | `lul.mpsl` |
| File type | `elf` |
| First seen | `2026-08-27 09:54:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21906f3b8d818358e5588228632f9c62` |
| SHA-1 | `4554c0271e2d84cf8724f81a58366377caba789e` |
| SHA-256 | `339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703` |
| SHA3-384 | `ba951e7aa819da95d7ac5890079fdd5952f74c1589a66a92ad242b544e979c01e2c8c57c55e7a038d88ca7e2b04519b6` |
| TLSH | `T179B3FA0AFF501EFBD86FCD3705A9074635CC695613B93B357634D928BA1A20B4AE3C68` |
| SSDEEP | `1536:Pp2tqf6/wCBG/nGOV3J6CbSX58rhCgxZspA3naUIQvHIOgyU5llNSlGhKEC:qqf6kGCbSEnaUIyHaZBKE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_33928548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703"
    family = "unknown"
    file_name = "lul.mpsl"
    file_type = "elf"
    first_seen = "2026-08-27 09:54:36"
  condition:
    hash.sha256(0, filesize) == "339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703"
}
```

### Sample 3: `a5842fabc581ddd4`

| Field | Value |
|---|---|
| SHA-256 | `a5842fabc581ddd4ae938b8b9acc01a2a5dc77b852cfe77267d51116f84ba1e5` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-27 09:44:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f9947f497e697587164c2dbf1797176` |
| SHA-1 | `1b6b97153cd45cf82ab72697b8ef47a25e1a0294` |
| SHA-256 | `a5842fabc581ddd4ae938b8b9acc01a2a5dc77b852cfe77267d51116f84ba1e5` |
| SHA3-384 | `cb6dca1514b3df299d442eb2db7988c590bbfc0f6604f9a699886d07dd1f7a0fab901ad23cebeeb1ad594be05e3371be` |
| TLSH | `T10F344A52AA929A13C1C3177AFBCF41053323A66693DB7306F91CABB43F8725E4E63541` |
| TELFHASH | `t137311f3117359516aeb0da589ced53b7152ec3266285ef73ee25c4dc940a0abe633c0f` |
| SSDEEP | `6144:NlgCijGDX+r0Lo1CgO5z1ygIvSsaU5Ioscmn3TW5IOEssMOgh5oIV52b5M/9UN:8COGDXa0Lo1CgON1jIvSsaU5IosfD6EP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_a5842fab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5842fabc581ddd4ae938b8b9acc01a2a5dc77b852cfe77267d51116f84ba1e5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-27 09:44:46"
  condition:
    hash.sha256(0, filesize) == "a5842fabc581ddd4ae938b8b9acc01a2a5dc77b852cfe77267d51116f84ba1e5"
}
```

### Sample 4: `a5c1403a73d8b5c7`

| Field | Value |
|---|---|
| SHA-256 | `a5c1403a73d8b5c78ce1bb397e09c4c8b7bc7edd82eb747e001a113a21a1919d` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-27 09:44:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a53bcdc23877ce61564ad1d666cec34` |
| SHA-1 | `62224c466e394acefaf879e4f0950097284de47e` |
| SHA-256 | `a5c1403a73d8b5c78ce1bb397e09c4c8b7bc7edd82eb747e001a113a21a1919d` |
| SHA3-384 | `6faacb4c286ceeac4bfbe245bd6f36e4789158e62bb8cb0f4b287bcc23b218952a6cc8553d529ac4090ec3aa83f0422b` |
| TLSH | `T1A6317E9A02204B311102DA9D73B2358DB58DE2E71D8FC7C4895A1FB9828C7DCF661B49` |
| SSDEEP | `24:L262MHZK/ltPX4cif/R/Iavu83BArbq81c2PdtUXEjCUr:LFl3z/R/IDXhLUuCUr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_a5c1403a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5c1403a73d8b5c78ce1bb397e09c4c8b7bc7edd82eb747e001a113a21a1919d"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-27 09:44:44"
  condition:
    hash.sha256(0, filesize) == "a5c1403a73d8b5c78ce1bb397e09c4c8b7bc7edd82eb747e001a113a21a1919d"
}
```

### Sample 5: `4ec985c55d0a56a3`

| Field | Value |
|---|---|
| SHA-256 | `4ec985c55d0a56a361fc9f7d3469afde4b8938d0eb34435ef10436802b0e4273` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-08-27 09:40:42` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0cca80a69028539eba5a37eaa442109` |
| SHA-256 | `4ec985c55d0a56a361fc9f7d3469afde4b8938d0eb34435ef10436802b0e4273` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_4ec985c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec985c55d0a56a361fc9f7d3469afde4b8938d0eb34435ef10436802b0e4273"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-27 09:40:42"
  condition:
    hash.sha256(0, filesize) == "4ec985c55d0a56a361fc9f7d3469afde4b8938d0eb34435ef10436802b0e4273"
}
```

### Sample 6: `ba567960aa8e9d81`

| Field | Value |
|---|---|
| SHA-256 | `ba567960aa8e9d81527a32d17df715b6e6aa381f7f54ef0258fa7611727c4c27` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-08-27 09:40:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `097ede78e3fd3e4a1e5dd5147b5b0e41` |
| SHA-1 | `1599b5808c15fad9e2a67d93e8278ba24f2e8a0c` |
| SHA-256 | `ba567960aa8e9d81527a32d17df715b6e6aa381f7f54ef0258fa7611727c4c27` |
| SHA3-384 | `e0c0a5fa6a6f55801a3a2575bf4f2af398806617badfbb8b5547fe4edb70c5645ad32ba61c602c7cae964d6971a07a9c` |
| TLSH | `T102243951BCE29A12C6C3467BFB4E428D372A635AD3DE3102BD1D5F603F8A45B0A7B581` |
| TELFHASH | `t1cbe0261ec82903da5798820141de231a67bab45f126614a7928c6e460f53980e02d805` |
| SSDEEP | `6144:h+l5Mykc3l8q1uuiFhEwdTaREH4qywXTKIwnAUEssMOgh5oQ:4l5Mykc3l8q1uF9d/H41a+lEssMOgh5l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_ba567960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba567960aa8e9d81527a32d17df715b6e6aa381f7f54ef0258fa7611727c4c27"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-27 09:40:41"
  condition:
    hash.sha256(0, filesize) == "ba567960aa8e9d81527a32d17df715b6e6aa381f7f54ef0258fa7611727c4c27"
}
```

### Sample 7: `f0b516e70d8ee2bd`

| Field | Value |
|---|---|
| SHA-256 | `f0b516e70d8ee2bd08037407bdae1f4a33648d6ba88ee4f39df37b530d16228a` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-08-27 09:38:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e2bd196d2ecd5d5b2b0c3b791a59da4` |
| SHA-1 | `cdab01c8b9d59dd366674f1460bd89539421c210` |
| SHA-256 | `f0b516e70d8ee2bd08037407bdae1f4a33648d6ba88ee4f39df37b530d16228a` |
| SHA3-384 | `825d605e0427df4461cd994b0c827b331c4bdc8f8013f963d7cbe90dd1541d731a305c7d23e66da85330917eabf3eddd` |
| TLSH | `T1D5241852BCD29B11D6C2467EFF0E514E3313676AD2CE7212BD1C6B703F8A46B0A7A541` |
| TELFHASH | `t161e07d11cea4476df682934440ede010e001f04717221cd2c8c86e8f4f32c16f012813` |
| SSDEEP | `6144:TJhWtC0aL+GqfrtG+PsoYXXkPXaZ2Z0GV2tpHHEssMOgh5oR:DWtC0a6GqfrtG+0oSXWXa8yGV6EssMOX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_f0b516e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0b516e70d8ee2bd08037407bdae1f4a33648d6ba88ee4f39df37b530d16228a"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-27 09:38:34"
  condition:
    hash.sha256(0, filesize) == "f0b516e70d8ee2bd08037407bdae1f4a33648d6ba88ee4f39df37b530d16228a"
}
```

### Sample 8: `98fd5c1d2cd1c220`

| Field | Value |
|---|---|
| SHA-256 | `98fd5c1d2cd1c220bc2c1869bfe84828b9f2df659dff1132a1f9f84628244454` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-27 09:34:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db05f6ea97e801482155fb0892e0c6ad` |
| SHA-1 | `24a29a881a6de0c69f01f523b3b65e5e3004242f` |
| SHA-256 | `98fd5c1d2cd1c220bc2c1869bfe84828b9f2df659dff1132a1f9f84628244454` |
| SHA3-384 | `5e34da004fd9097d7086ba598315b9306aac08c12c8b19b67a2eb6987bd28fea5c6f6a0f2ffff6eb67207a51da5524bc` |
| TLSH | `T1E4236C652A857C14AA98C4371D7E2F0CB9AD43E6320492ED7FCF3CF68C4A69D921871D` |
| SSDEEP | `768:M4XOGVvt9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:MuLWcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_98fd5c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98fd5c1d2cd1c220bc2c1869bfe84828b9f2df659dff1132a1f9f84628244454"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-27 09:34:31"
  condition:
    hash.sha256(0, filesize) == "98fd5c1d2cd1c220bc2c1869bfe84828b9f2df659dff1132a1f9f84628244454"
}
```

### Sample 9: `53ad3b3ba81cfb1b`

| Field | Value |
|---|---|
| SHA-256 | `53ad3b3ba81cfb1b96d8c1e2c92fb3ee7fb693d92144c786ad29df41e8298a88` |
| Family label | `Mirai` |
| File name | `lul.arm6` |
| File type | `elf` |
| First seen | `2026-08-27 09:31:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bb2aa4604c795f35fa555863d41bc39` |
| SHA-1 | `1dbfea77701787b21cdbf9fb8064e051b3f34ce3` |
| SHA-256 | `53ad3b3ba81cfb1b96d8c1e2c92fb3ee7fb693d92144c786ad29df41e8298a88` |
| SHA3-384 | `46c0909f20033dfdd557138733072fb9c52c75a0309aea0918c526e02a45a01918d311e565b688064bd8e27acf74a470` |
| TLSH | `T1E593285AF8829B15D5C1127EFE1E528D33132BBCE3DE7212DE146B21778B56B0E3A406` |
| TELFHASH | `t12a01c566c605458c1bc1c55b54ee212c156db87e3b01126edc9c2b8f907708d7056c1a` |
| SSDEEP | `1536:Cenm8xFdL7LZLdprHmBoIoXEuhjgkGVB5x6gcDlba43M6EMuiWSlcaWNHfIPZ7j+:xxFdL/1LeoIoXjhjgkGvnabajOcaWNHz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_53ad3b3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53ad3b3ba81cfb1b96d8c1e2c92fb3ee7fb693d92144c786ad29df41e8298a88"
    family = "Mirai"
    file_name = "lul.arm6"
    file_type = "elf"
    first_seen = "2026-08-27 09:31:02"
  condition:
    hash.sha256(0, filesize) == "53ad3b3ba81cfb1b96d8c1e2c92fb3ee7fb693d92144c786ad29df41e8298a88"
}
```

### Sample 10: `dbf045cd17f860bc`

| Field | Value |
|---|---|
| SHA-256 | `dbf045cd17f860bc5692c145c0a84930992749543c4dfb67c0d26565944e0de6` |
| Family label | `unknown` |
| File name | `nvr` |
| File type | `unknown` |
| First seen | `2026-08-27 09:30:38` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06ca7b8b01d415c063c7d3e62f14dd81` |
| SHA-256 | `dbf045cd17f860bc5692c145c0a84930992749543c4dfb67c0d26565944e0de6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_dbf045cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf045cd17f860bc5692c145c0a84930992749543c4dfb67c0d26565944e0de6"
    family = "unknown"
    file_name = "nvr"
    file_type = "unknown"
    first_seen = "2026-08-27 09:30:38"
  condition:
    hash.sha256(0, filesize) == "dbf045cd17f860bc5692c145c0a84930992749543c4dfb67c0d26565944e0de6"
}
```

### Sample 11: `6e4ba98eec21415d`

| Field | Value |
|---|---|
| SHA-256 | `6e4ba98eec21415df3855ef1ff7620af209c3b31a991dc8f8f87b6d3546af8e9` |
| Family label | `RemcosRAT` |
| File name | `PurchaseOrderpdf.JS.js` |
| File type | `js` |
| First seen | `2026-08-27 09:30:13` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab5ae82b577e107a91aa76a9f27201f9` |
| SHA-1 | `463eb21619ba9894cc6751801fde3762dfc077f8` |
| SHA-256 | `6e4ba98eec21415df3855ef1ff7620af209c3b31a991dc8f8f87b6d3546af8e9` |
| SHA3-384 | `96a41cfbded274a745b047c5947da35f3de170e3cee6d7e370064d238c0086ac9f2eb4e49ea9a7bf671da62e0065d73f` |
| TLSH | `T1F446D761A34191337720974F12B689A2DC8B61A3E4E5DF29B87DD308BB5CD07F3589E2` |
| SSDEEP | `98304:2fzd6CJxC7jrJVi6lPIcK3LwNE3HKgFl+b5Qx5hJJMJdyOBR2xdsSKSm/0Bew3eR:2B6WOu6pIcKcNEXK+l+bSfiJY7gUPuFf` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_011_6e4ba98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e4ba98eec21415df3855ef1ff7620af209c3b31a991dc8f8f87b6d3546af8e9"
    family = "RemcosRAT"
    file_name = "PurchaseOrderpdf.JS.js"
    file_type = "js"
    first_seen = "2026-08-27 09:30:13"
  condition:
    hash.sha256(0, filesize) == "6e4ba98eec21415df3855ef1ff7620af209c3b31a991dc8f8f87b6d3546af8e9"
}
```

### Sample 12: `b38ce79773881df1`

| Field | Value |
|---|---|
| SHA-256 | `b38ce79773881df169bfc6cfdaa105270c5bcb2c9c4509a6454a1d1f50f1a641` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-27 09:27:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d5d21a2f3ac820db8ee3cd6fc73fbaa` |
| SHA-1 | `b82da2e18e35abfaa2e5c793029b4a29d066c6cb` |
| SHA-256 | `b38ce79773881df169bfc6cfdaa105270c5bcb2c9c4509a6454a1d1f50f1a641` |
| SHA3-384 | `39a31025294dd0050190d6cc2a34dca53307299dd03eb503fbce3496e0b4a675e9e080a750214a6c94d08fb52785cd3a` |
| TLSH | `T121235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCF3CF68C4A6AD910971D` |
| SSDEEP | `768:q+99GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:q+ecr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_b38ce797
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38ce79773881df169bfc6cfdaa105270c5bcb2c9c4509a6454a1d1f50f1a641"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-27 09:27:33"
  condition:
    hash.sha256(0, filesize) == "b38ce79773881df169bfc6cfdaa105270c5bcb2c9c4509a6454a1d1f50f1a641"
}
```

### Sample 13: `f1d8ccf9d1d0944b`

| Field | Value |
|---|---|
| SHA-256 | `f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260` |
| Family label | `unknown` |
| File name | `f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260.exe` |
| File type | `exe` |
| First seen | `2026-08-27 09:21:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5aa3259cf9350800b78a1612db11a3c` |
| SHA-1 | `bc3b1f2f8135a55678295a67d3b1bd07b36737af` |
| SHA-256 | `f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260` |
| SHA3-384 | `67071a9f5a8f6c690eeb2180ddc2a44f9afcd065c6cec6acb9b7ee8cef20fc5bb6ca67b07088b65fbb453d9cdedf0b22` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T172E52344FD827976E032C3B746D3B07D30693B858A348D8E7BC96741AE12A297D7B346` |
| SSDEEP | `49152:Q0PulMAghffyvPzCJI9N9awGyFFn1amlUY3kh9X79/m/DyJjH57HlfTHjf:Qyhinz59DGyF9E6r3kh9LDF59j` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_f1d8ccf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260"
    family = "unknown"
    file_name = "f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260.exe"
    file_type = "exe"
    first_seen = "2026-08-27 09:21:01"
  condition:
    hash.sha256(0, filesize) == "f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260"
}
```

### Sample 14: `44708c993a9ae48e`

| Field | Value |
|---|---|
| SHA-256 | `44708c993a9ae48e7290f6217fa5b40876d102d91ae0102a1556063044791456` |
| Family label | `unknown` |
| File name | `dlr.mips` |
| File type | `elf` |
| First seen | `2026-08-27 09:20:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d69f068a01ca43a0ab646e84ee42491` |
| SHA-1 | `7f417bd31ad8f1b4c3309bcb8da49bc835ebf131` |
| SHA-256 | `44708c993a9ae48e7290f6217fa5b40876d102d91ae0102a1556063044791456` |
| SHA3-384 | `c331e5c6d82291d9132032c8c713f72e7a66854482dc1415252420b8939e9bb1cb2593227d3dbf5417ce559859360d5d` |
| TLSH | `T158B2194AF9A4DF9DF325C4328AEF8E2455613BD203B006A7D16CF5604D107CA69AFEB1` |
| SSDEEP | `384:vBtSzV0TtIWr+zv9h37C08hxPEbN7049SfGCkRSO0mQ5:vqzV0T36zv/WxP6N7P3RSQy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_44708c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44708c993a9ae48e7290f6217fa5b40876d102d91ae0102a1556063044791456"
    family = "unknown"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-08-27 09:20:35"
  condition:
    hash.sha256(0, filesize) == "44708c993a9ae48e7290f6217fa5b40876d102d91ae0102a1556063044791456"
}
```

### Sample 15: `1d7a148e3f597c2c`

| Field | Value |
|---|---|
| SHA-256 | `1d7a148e3f597c2c32aed9727de0c2bf0f0462418d1c1edb5c5603754b7a162a` |
| Family label | `Mirai` |
| File name | `tmpsl` |
| File type | `elf` |
| First seen | `2026-08-27 09:20:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2c101e157c6964d7eb2e3cb5c4a8c58` |
| SHA-1 | `f5ed1b0351075112f770a1ae8c459824a72f3d30` |
| SHA-256 | `1d7a148e3f597c2c32aed9727de0c2bf0f0462418d1c1edb5c5603754b7a162a` |
| SHA3-384 | `ffd53c6254d0cb811e149ff9d6494c7e6945485a50f7dd64a009bcc6b497e49f6cb97f1299752e41ee65d8bb81b3d8ea` |
| TLSH | `T1BD34EA1AEF612EBBD81FCC37089906C975DCF49512A93B372634DA1DBA0724F49E3864` |
| SSDEEP | `3072:XFg2CXq0ADfXwW6pIKqX4C3kISogsVnQHff:XFg2Ca0ifXwW6pfab+3vHf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_1d7a148e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d7a148e3f597c2c32aed9727de0c2bf0f0462418d1c1edb5c5603754b7a162a"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-08-27 09:20:34"
  condition:
    hash.sha256(0, filesize) == "1d7a148e3f597c2c32aed9727de0c2bf0f0462418d1c1edb5c5603754b7a162a"
}
```

### Sample 16: `a6458820cefd26db`

| Field | Value |
|---|---|
| SHA-256 | `a6458820cefd26db2ffa682f2b7a42877dff2c5d2e647993a0678928b2192f49` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-08-27 09:18:33` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a24ec68a2b458edd5cb48ffa9ceb35f7` |
| SHA-256 | `a6458820cefd26db2ffa682f2b7a42877dff2c5d2e647993a0678928b2192f49` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_a6458820
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6458820cefd26db2ffa682f2b7a42877dff2c5d2e647993a0678928b2192f49"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-27 09:18:33"
  condition:
    hash.sha256(0, filesize) == "a6458820cefd26db2ffa682f2b7a42877dff2c5d2e647993a0678928b2192f49"
}
```

### Sample 17: `6f0f3928fa60d3d5`

| Field | Value |
|---|---|
| SHA-256 | `6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455` |
| Family label | `WannaCry` |
| File name | `6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455` |
| File type | `exe` |
| First seen | `2026-08-27 09:15:35` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e83ecb72ffe6e026849ac42c132026fc` |
| SHA-1 | `de4c1b6dbee1d8208fc8fe51f2746af640937cba` |
| SHA-256 | `6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455` |
| SHA3-384 | `e328bf83f52b7fd6c3df7c875ec8ca9d6fad5e47b211797e83ac0c207d711cc5ef0628b62c695ac5c0ced62ac1391844` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14436F11631D8C071C413513088B79B61F6B6BC2A1379964FBB948F6E2F33791E62AB53` |
| SSDEEP | `12288:jbLgD1bLgmluCti62WfSm0iEcQhfYNVUy7ckPU82900Ve7:jbLgBbLguriIfEcQdIVUacMNge` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_017_6f0f3928
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455"
    family = "WannaCry"
    file_name = "6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455"
    file_type = "exe"
    first_seen = "2026-08-27 09:15:35"
  condition:
    hash.sha256(0, filesize) == "6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455"
}
```

### Sample 18: `847067d6d55130c9`

| Field | Value |
|---|---|
| SHA-256 | `847067d6d55130c927a4fb8ee948cde9090214e6bd8c47be3c8fa8d93992302f` |
| Family label | `unknown` |
| File name | `dlr.arm` |
| File type | `elf` |
| First seen | `2026-08-27 09:14:58` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `338e954519448e56a4efaa35892220d7` |
| SHA-1 | `074b63d949e1bdcd809f1c4b76683f387947bac0` |
| SHA-256 | `847067d6d55130c927a4fb8ee948cde9090214e6bd8c47be3c8fa8d93992302f` |
| SHA3-384 | `d44c3a52aa540c8e5c59a32ffc9014bd463cdd7a8107ab6f9ea594dc2943253b0af8570eb9256d9b2bd96637fe4fe010` |
| TLSH | `T19EB23AD5E861A939E5F07538B7FB8248378B2374D3B2B016DA099FB0224B51E077DB91` |
| SSDEEP | `768:tylJn1rcZzbyUxJxF24a4x4fj3IrR0Br9f54t:t4JcZnyULxFJV6crR0BL4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_847067d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847067d6d55130c927a4fb8ee948cde9090214e6bd8c47be3c8fa8d93992302f"
    family = "unknown"
    file_name = "dlr.arm"
    file_type = "elf"
    first_seen = "2026-08-27 09:14:58"
  condition:
    hash.sha256(0, filesize) == "847067d6d55130c927a4fb8ee948cde9090214e6bd8c47be3c8fa8d93992302f"
}
```

### Sample 19: `07bfd97e419f7392`

| Field | Value |
|---|---|
| SHA-256 | `07bfd97e419f739258c04c8bc976ae6add8bd2936c97471642a759b0b6cc115b` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-27 09:13:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83f40ad621579a179b2066ecd8d76759` |
| SHA-1 | `e1bdeb452f7c45a3aa7619d7bfb7e0c7b9fff9be` |
| SHA-256 | `07bfd97e419f739258c04c8bc976ae6add8bd2936c97471642a759b0b6cc115b` |
| SHA3-384 | `6e3f29a68f489d6ee7d44e98baf17a99238d2e7b98bb059c829801cca9e720c43b49a63037e73cf988683c96c7d12b3d` |
| TLSH | `T168355A17B2B774A9C093C034439FDBB2AD3AF0B902126D7B32C09A342D56EA15F59F56` |
| TELFHASH | `t151616456657c17d999a26c1488b02bd3548be1383344ea19fb6bcec018de99ef174c0f` |
| SSDEEP | `24576:NdAPEt/bkdErGpzGd1YQwphT6bM9UdDqD+wcuvg:NdkEt/bkK0GdxjASdDqguvg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_07bfd97e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07bfd97e419f739258c04c8bc976ae6add8bd2936c97471642a759b0b6cc115b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-27 09:13:30"
  condition:
    hash.sha256(0, filesize) == "07bfd97e419f739258c04c8bc976ae6add8bd2936c97471642a759b0b6cc115b"
}
```

### Sample 20: `f954e919fc4b906f`

| Field | Value |
|---|---|
| SHA-256 | `f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08` |
| Family label | `Vidar` |
| File name | `f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08.bin` |
| File type | `exe` |
| First seen | `2026-08-27 09:12:19` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f173f7e74fe9f742f6f4eaca26332b8a` |
| SHA-1 | `bd579150043b7acf42bd45d9e01b3b19731e6491` |
| SHA-256 | `f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08` |
| SHA3-384 | `46f2ddf4cadd39139692ccaea14171a1dd110487013bc33398074d99e2177b224e789af897fa3d9c3f374c49165fb54d` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T1FA183303B9948091D44A8B36D6BB9253FB36B88D9B3673D33E1076382F7A7D029B5345` |
| SSDEEP | `1572864:uULcxYNDMrBcz7R/n81z/LTFWsPFF3Y5b5Z3SI+P6df1Lg6mVtk:LK+Xz7S1z/LTFWsP32z3gMGK` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_020_f954e919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08"
    family = "Vidar"
    file_name = "f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08.bin"
    file_type = "exe"
    first_seen = "2026-08-27 09:12:19"
  condition:
    hash.sha256(0, filesize) == "f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08"
}
```

### Sample 21: `3702adbc131fd777`

| Field | Value |
|---|---|
| SHA-256 | `3702adbc131fd77738189af8c6fb3c2f89c8ac65c1499e06fde55b7df0bf9689` |
| Family label | `Gafgyt` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-27 09:11:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b545cb057ca53b86a03e253e1d535c47` |
| SHA-1 | `a5a85f869131e87114c4ff0089dcc6437588ec95` |
| SHA-256 | `3702adbc131fd77738189af8c6fb3c2f89c8ac65c1499e06fde55b7df0bf9689` |
| SHA3-384 | `449550d74647655fc5db490c61847db4966c8ae230293ce485e5322141edb825e7f1630f6dcc9e876563404a03c3923d` |
| TLSH | `T186341905F8044B67C2D327FAA78E829D3F3617A653DB3301AB389DB42FC6B991D29550` |
| TELFHASH | `t1b3713154a57c09d9af631d2964a85be35993f02622e5bf28ff0acdc4085f429f254e0f` |
| SSDEEP | `6144:gt2XrV4oYdy94kD5h8zXT2amLzGaVoZGaHL/Xcf/Gy:yk54jyx5h83mLzGaVo4aHL/Xcf/Gy` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_021_3702adbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3702adbc131fd77738189af8c6fb3c2f89c8ac65c1499e06fde55b7df0bf9689"
    family = "Gafgyt"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-27 09:11:35"
  condition:
    hash.sha256(0, filesize) == "3702adbc131fd77738189af8c6fb3c2f89c8ac65c1499e06fde55b7df0bf9689"
}
```

### Sample 22: `56c2e73c1f6e68d3`

| Field | Value |
|---|---|
| SHA-256 | `56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c` |
| Family label | `unknown` |
| File name | `56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c.elf` |
| File type | `elf` |
| First seen | `2026-08-27 09:06:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a02e344b09a18ea83c28712a680daa3` |
| SHA-1 | `66a5839f0bb9baa3cb5f35e4e7f327f5ed5859d7` |
| SHA-256 | `56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c` |
| SHA3-384 | `a7a93e0e3d17954a1d7f4da6162e9900f9a9a883f935edc57e22e29293eb98fc4e174f5c7b9752b9673fffa0d0b05d9f` |
| TLSH | `T17DA3285AB881AB15D5D522BEFE1E528D33131BBCE3EE7112DD105B2567CB92B0F3A402` |
| TELFHASH | `t19801cbe3ce6826be23c10862d2fe392817f87da66e002406dc7c3b9b00635c9740fc49` |
| SSDEEP | `3072:POuKrAUN8/f22uXybWQBSWvoeamVESewz2QMFrQy/bE:musn8/f22gy6QBFweamVESewSQ8QGbE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_56c2e73c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c"
    family = "unknown"
    file_name = "56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c.elf"
    file_type = "elf"
    first_seen = "2026-08-27 09:06:03"
  condition:
    hash.sha256(0, filesize) == "56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c"
}
```

### Sample 23: `c681b78a2922dae0`

| Field | Value |
|---|---|
| SHA-256 | `c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f` |
| Family label | `Mirai` |
| File name | `c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f.elf` |
| File type | `elf` |
| First seen | `2026-08-27 09:05:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b961cf424ce4272e07abf6e93a6cf911` |
| SHA-1 | `63d28c0ed1e75119b0c8c745ffe0e2f5b1e2a120` |
| SHA-256 | `c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f` |
| SHA3-384 | `061bd64a86d66642fe77349e8296fda0b6f8f65e8a889cd1a142fd611e78988f05ff36329362b04a525eecfe2fca45a9` |
| TLSH | `T18B833A55B8819617C6C1567BFF1E828D371323E8D2EA7207DD25AF21778B52B0E3B442` |
| TELFHASH | `t1b7f0ebf9428e19cc2fa48395c1ee673e6f8b386907010890ce4abf4750e3281ba1b807` |
| SSDEEP | `1536:8TAxtKYCKEwjWnsw5l6xC5g4nRckAU4XFtCcqdiDN0KBWHYd7KgVH+W30x3uqj2p:8T+tKY5iss6Q5ggRrA5tCcqdiR09Y1KW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_c681b78a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f"
    family = "Mirai"
    file_name = "c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f.elf"
    file_type = "elf"
    first_seen = "2026-08-27 09:05:57"
  condition:
    hash.sha256(0, filesize) == "c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f"
}
```

### Sample 24: `05fe60e021bffcac`

| Field | Value |
|---|---|
| SHA-256 | `05fe60e021bffcac2ae463fc54c9df400b6d231c1721515909af05d226d52a75` |
| Family label | `RemcosRAT` |
| File name | `nxs64.exe` |
| File type | `exe` |
| First seen | `2026-08-27 09:05:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50103b7e2d05319d8d6c5fc5e998acab` |
| SHA-1 | `eb7a3fe85a9de2e3ed4f1b9f7aa684221cbb99ef` |
| SHA-256 | `05fe60e021bffcac2ae463fc54c9df400b6d231c1721515909af05d226d52a75` |
| SHA3-384 | `f18d43d1d658e00253782b5570c89b4e56b7e08a98dcc33ed00ecdac9c642da6f0adbe67fa2d8c93fb7c85e4f65f8b81` |
| IMPHASH | `f4e833c94f979b4a69174b78399e4f22` |
| TLSH | `T108D45C55A3D442F8D07BC135C9828527E7F2BC056671872F03D74E5B6F232A1AF2AB26` |
| SSDEEP | `12288:5SGuIuF0MV/VSU5s11yuTUHaaPC+6P/to0Z5hdr:cGuNF0MV/VSU5+1yhHaaPX6P/trZ5` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_024_05fe60e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05fe60e021bffcac2ae463fc54c9df400b6d231c1721515909af05d226d52a75"
    family = "RemcosRAT"
    file_name = "nxs64.exe"
    file_type = "exe"
    first_seen = "2026-08-27 09:05:10"
  condition:
    hash.sha256(0, filesize) == "05fe60e021bffcac2ae463fc54c9df400b6d231c1721515909af05d226d52a75"
}
```

### Sample 25: `d9fec308fa96892c`

| Field | Value |
|---|---|
| SHA-256 | `d9fec308fa96892c7a6515f87a503c326a87dfac10ae30d62c1b2941eef67382` |
| Family label | `Mirai` |
| File name | `tarm7` |
| File type | `elf` |
| First seen | `2026-08-27 09:04:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1489b54407e9a2f502334963345dc4c` |
| SHA-1 | `f7fe365e603a17e47acb1f431f10908f1218b6f9` |
| SHA-256 | `d9fec308fa96892c7a6515f87a503c326a87dfac10ae30d62c1b2941eef67382` |
| SHA3-384 | `0b1ddf9a7562e9c41518eb286d5d030af1b2f23ea431f6e7f0f87d9b0c5e29baee25b0ca8dca6ed2e30842f2947cc10f` |
| TLSH | `T1C2241686BA81AB21D5D3177FFE0F114E33136BF8D7EA722799140732268751B0E6B506` |
| TELFHASH | `t161019c99f61616fc53d0502151ff347a37ff71ea2261389141dc6d9f9051f81390b10b` |
| SSDEEP | `6144:N5TdXlgGmV+AyqeF7TNiaxIxHgO1rQAcfvK9:NRdXlgGmV+AyqeF7TNiaxIxHgOhv6u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_d9fec308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9fec308fa96892c7a6515f87a503c326a87dfac10ae30d62c1b2941eef67382"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-08-27 09:04:42"
  condition:
    hash.sha256(0, filesize) == "d9fec308fa96892c7a6515f87a503c326a87dfac10ae30d62c1b2941eef67382"
}
```

### Sample 26: `3c877d369e9c087e`

| Field | Value |
|---|---|
| SHA-256 | `3c877d369e9c087edcc49a932daa12bc0c72a4ccda9395d74cd2d51402146d50` |
| Family label | `unknown` |
| File name | `lul.mips` |
| File type | `elf` |
| First seen | `2026-08-27 09:04:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c62d144b5f6c4a606fab9350e9b6817e` |
| SHA-1 | `b484533830d6517a0dad64e88a144625695bea23` |
| SHA-256 | `3c877d369e9c087edcc49a932daa12bc0c72a4ccda9395d74cd2d51402146d50` |
| SHA3-384 | `f656a32b9b398b2e8173aa2a271e4b618064f0a990407897652c5f0a41f0c89759fdc5e71ca7e6be7563bdf37a5dbfa1` |
| TLSH | `T160B3A80F7E228F6DF269863047B74E25A76933D727E1D685D19CD6001F6038E681FBA8` |
| TELFHASH | `t1b1219f1c497827f0d7711d9d5bedfb76e1a130df4a226d378e10ada8aa6ed825e00c1c` |
| SSDEEP | `1536:gi3ssN0AIh/gvcGZ9k/MyGz7lEMnqop8RMZY/K7rEhKNXlreie9oP9nUkA:gi8sOAq/g3QMyM7kiG/K7rqULP9n7A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_3c877d36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c877d369e9c087edcc49a932daa12bc0c72a4ccda9395d74cd2d51402146d50"
    family = "unknown"
    file_name = "lul.mips"
    file_type = "elf"
    first_seen = "2026-08-27 09:04:41"
  condition:
    hash.sha256(0, filesize) == "3c877d369e9c087edcc49a932daa12bc0c72a4ccda9395d74cd2d51402146d50"
}
```

### Sample 27: `3af1c09640d195f2`

| Field | Value |
|---|---|
| SHA-256 | `3af1c09640d195f2dfc3dd708c2ce421ed3256f8345cea934fed5c52a3eb5eff` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-27 09:04:35` |
| Reporter | `Bitsight` |
| Tags | `3, dropped-by-StealC, exe, signed, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9256a1b19d2d27bd5c93ecc99f44e859` |
| SHA-1 | `fee6ebb1ac212b3b463bfe7122afc7eb0196625a` |
| SHA-256 | `3af1c09640d195f2dfc3dd708c2ce421ed3256f8345cea934fed5c52a3eb5eff` |
| SHA3-384 | `dd45f5fa60cb04da496e92255b271fde5cd9faa313509d7b04a2f2cf1220d895c73bcc77da63a21f1da55983251e1cf0` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T1AEF58C073C90A1F9C9A7E336A57A82A6A675F884A73273D32F50A6F51E373C41D76310` |
| GIMPHASH | `d234e4a2ff1f8708035e6f4cf39a9cf492a85cc85c93b0c5bda6659e192cd8f4` |
| SSDEEP | `49152:cnMb2xb3Qrb/TNvO90d7HjmAFd4A64nsfJu2PAQdx72h7u6yrB4Som40OHMgwnlR:Yb30/6Bx4xEL` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_027_3af1c096
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3af1c09640d195f2dfc3dd708c2ce421ed3256f8345cea934fed5c52a3eb5eff"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-27 09:04:35"
  condition:
    hash.sha256(0, filesize) == "3af1c09640d195f2dfc3dd708c2ce421ed3256f8345cea934fed5c52a3eb5eff"
}
```

### Sample 28: `e6258f41f0ab79b3`

| Field | Value |
|---|---|
| SHA-256 | `e6258f41f0ab79b38cbb3ae6f6e6a6d31e3f5168a40b895d5a6503c85fdd2b1b` |
| Family label | `unknown` |
| File name | `tftp` |
| File type | `elf` |
| First seen | `2026-08-27 09:02:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8121ea60b8fcce7138899354b7ae7c82` |
| SHA-1 | `ff4ca23ed39f0359a6f310b0605e7c0e77a29620` |
| SHA-256 | `e6258f41f0ab79b38cbb3ae6f6e6a6d31e3f5168a40b895d5a6503c85fdd2b1b` |
| SHA3-384 | `a69804a7403c6bfbe6a6a501981c483e0ab61c1e02d2b2cb19ca0975ac0284f279a0b6fff8bb870dd486e4c3055c049d` |
| TLSH | `T18CA30A96F8A28B56C4C557B7FB4FC75637231795E3DF36038A184E34278B50A8E3AA01` |
| SSDEEP | `3072:9LOuh02xHCKQnqZ9YfMXKgyLlBZSyPjrOC:FOuhPHCKsqZ9YfM6g23ZJLrOC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_e6258f41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6258f41f0ab79b38cbb3ae6f6e6a6d31e3f5168a40b895d5a6503c85fdd2b1b"
    family = "unknown"
    file_name = "tftp"
    file_type = "elf"
    first_seen = "2026-08-27 09:02:56"
  condition:
    hash.sha256(0, filesize) == "e6258f41f0ab79b38cbb3ae6f6e6a6d31e3f5168a40b895d5a6503c85fdd2b1b"
}
```

### Sample 29: `4064808f7c2b34bf`

| Field | Value |
|---|---|
| SHA-256 | `4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-27 09:00:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e61f1fca4fe18eedcc2588c74f30c23` |
| SHA-1 | `65abf71c3b67c462c23980894e55947682f19c15` |
| SHA-256 | `4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436` |
| SHA3-384 | `4c75699587a07290902546fe8664d080c7f067ecfa86fa055139ce40157ca31a85b6483ee12bc5c1d8c023d74fb55664` |
| TLSH | `T193F37CC179E3D0B1E563487A836F932A4A32D4330169DA51FB2F68356F52440E7BBB9C` |
| TELFHASH | `t122610bfa6e7f0ce8a790ac45964e5f216e0da77b142032b605b3582532bfd8141bbc39` |
| SSDEEP | `3072:BqE5LUvSIYQPjmPe8bNNjaw9afvhQIKH2H6PZ6lu1EssMZc/T03ImIys61X1h5oM:tLUvfYQPB8RJI2q6PZ62EssMOgh5oM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_4064808f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-27 09:00:37"
  condition:
    hash.sha256(0, filesize) == "4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436"
}
```

### Sample 30: `4fa7a5c77c6d7497`

| Field | Value |
|---|---|
| SHA-256 | `4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d` |
| Family label | `unknown` |
| File name | `4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d` |
| File type | `elf` |
| First seen | `2026-08-27 09:00:23` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40cf7398102f490a900b240a982de659` |
| SHA-1 | `7a6e6cf2c0eafe16fea13a0d0f9231415bf37aa1` |
| SHA-256 | `4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d` |
| SHA3-384 | `8e30e066e92725771c1dc6d614395351a7650579612c80a5c6f8f400d557ce08bf51b313f0ad231787e5cdf6fcf8d839` |
| TLSH | `T13847DF77814338D9E5B98DB4D41025426DAC388B5738A3C7BAC871E667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ0:cqYUQuVDt0TZE3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_4fa7a5c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d"
    family = "unknown"
    file_name = "4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d"
    file_type = "elf"
    first_seen = "2026-08-27 09:00:23"
  condition:
    hash.sha256(0, filesize) == "4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d"
}
```

### Sample 31: `47c5c730f29520a7`

| Field | Value |
|---|---|
| SHA-256 | `47c5c730f29520a7429f49cb669e58ac8972e202e3aff821357b7ef01941199d` |
| Family label | `unknown` |
| File name | `install_q0.3.15.exe` |
| File type | `exe` |
| First seen | `2026-08-27 09:00:03` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0140b13ef606701278a284ebd130e3f1` |
| SHA-1 | `52dac1cf9f92bb645e234a56d6069957e8fe48cc` |
| SHA-256 | `47c5c730f29520a7429f49cb669e58ac8972e202e3aff821357b7ef01941199d` |
| SHA3-384 | `ca45d105cc558b5fd7ea0a029a5adae33e3fd3538c4ec085cf5a30f23e0de14c6fccbbe3424ef2a75d8d0ca322fe399b` |
| IMPHASH | `c1388db37310975dc1b57400c24d2627` |
| TLSH | `T141476216B746898BE42A9634844B4FE4E325DCB186B0837733B9371D2FFE34C5EA6215` |
| SSDEEP | `49152:WudCDvwT4vKKbhWj0wjlktD4a0CfZ1Cy988xJhGnSDJEKHMvtrI72dRt8rfIkatw:8vKKbh6Jta+UUamsrfszizYP1Q` |
| ICON-DHASH | `cdabae6fe6e7eaec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_47c5c730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c5c730f29520a7429f49cb669e58ac8972e202e3aff821357b7ef01941199d"
    family = "unknown"
    file_name = "install_q0.3.15.exe"
    file_type = "exe"
    first_seen = "2026-08-27 09:00:03"
  condition:
    hash.sha256(0, filesize) == "47c5c730f29520a7429f49cb669e58ac8972e202e3aff821357b7ef01941199d"
}
```

### Sample 32: `8c6822cbec742c64`

| Field | Value |
|---|---|
| SHA-256 | `8c6822cbec742c64706a31b83dc29640de0006b5dc122c7a1c8194f9fa4251ff` |
| Family label | `unknown` |
| File name | `install_q0.3.14.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:59:20` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2191baac23cb6204fa96480c445cbcf` |
| SHA-1 | `681c93f6742e66f5a154aa26cd95dabd20534073` |
| SHA-256 | `8c6822cbec742c64706a31b83dc29640de0006b5dc122c7a1c8194f9fa4251ff` |
| SHA3-384 | `c37cb72c65d489a5bfc58c4adc41e094d1fb74acfdf29b637aef645342ef73ea9071c6326b843c276a67738566b231df` |
| IMPHASH | `c1388db37310975dc1b57400c24d2627` |
| TLSH | `T188476216B746898BE42A9634844B4FE4E325DCB186B0837733B9371D2FFE34C5EA6215` |
| SSDEEP | `49152:TudCDvwT4vKKbhWj0wjlktD4a0CfZ1Cy988xJhGnSDJEKHMvtrI72dRt8rfIkatW:JvKKbh6Jta+UUamsrfszizYP12` |
| ICON-DHASH | `cdabae6fe6e7eaec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_8c6822cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c6822cbec742c64706a31b83dc29640de0006b5dc122c7a1c8194f9fa4251ff"
    family = "unknown"
    file_name = "install_q0.3.14.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:59:20"
  condition:
    hash.sha256(0, filesize) == "8c6822cbec742c64706a31b83dc29640de0006b5dc122c7a1c8194f9fa4251ff"
}
```

### Sample 33: `5b06f021a79b2b53`

| Field | Value |
|---|---|
| SHA-256 | `5b06f021a79b2b5349aa31168685ec3df415c3fea1522ead0675a970af76d389` |
| Family label | `Mirai` |
| File name | `bot.i686` |
| File type | `elf` |
| First seen | `2026-08-27 08:57:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f4e8eec2573f46e0e6f8aa8e30670fe` |
| SHA-1 | `7346fc87bf06f422fa33e0975a97a2a9a948f4dc` |
| SHA-256 | `5b06f021a79b2b5349aa31168685ec3df415c3fea1522ead0675a970af76d389` |
| SHA3-384 | `6b6b847ff77facf7448cb700987dd5b5d7089c79fb30753ba125eccc1a2b93c57050143b44b8b8e1161b73b081d87b25` |
| TLSH | `T1E3942A48D3A3E2FEF156C9705305B93F8D3286367093658EF34AAE3793771C145A9A22` |
| TELFHASH | `t17d817b7277b98cdd2bc09901934f6627ea3be667099139b309f2605135b2d039f79c72` |
| SSDEEP | `6144:Q1X/7imKHQSj4KoIbuRLAxd/n5y/b8Us+7h6PAua9Mcu:oXWyhllL3/b8Urua9Mcu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_5b06f021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b06f021a79b2b5349aa31168685ec3df415c3fea1522ead0675a970af76d389"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-27 08:57:28"
  condition:
    hash.sha256(0, filesize) == "5b06f021a79b2b5349aa31168685ec3df415c3fea1522ead0675a970af76d389"
}
```

### Sample 34: `2e1a4992721af040`

| Field | Value |
|---|---|
| SHA-256 | `2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd` |
| Family label | `Mirai` |
| File name | `2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd.elf` |
| File type | `elf` |
| First seen | `2026-08-27 08:56:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49c5dce88390bcd7192456a34e5a8fb7` |
| SHA-1 | `d05b1a1b5cffc533b7c35a331d73cca779d5da47` |
| SHA-256 | `2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd` |
| SHA3-384 | `cc8532eba5bbe6d9b6062c1492551f8e55729245a7c53cb4b7c60191b19faf1ff8d03b1d80297f10834fa69f1f19e5b1` |
| TLSH | `T174F38CC16EA3D0F1E953097A426B531A9A32D437021ADA11FB3E6C347F42590E7BB79C` |
| TELFHASH | `t1fe61f8f86a7718ecbb409845a24e6b117e4eb77b282036f705b3587531bbd4192b7c38` |
| SSDEEP | `3072:ncEY7CO2P30QoqTBMx+Jize3d6MFSv+NrrFu1EssMZc/T03ImIys61X1h5oA:LY7CDPcSN6mKcrWEssMOgh5oA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_2e1a4992
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd"
    family = "Mirai"
    file_name = "2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd.elf"
    file_type = "elf"
    first_seen = "2026-08-27 08:56:20"
  condition:
    hash.sha256(0, filesize) == "2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd"
}
```

### Sample 35: `864aa577c952927f`

| Field | Value |
|---|---|
| SHA-256 | `864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f` |
| Family label | `Mirai` |
| File name | `864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f.elf` |
| File type | `elf` |
| First seen | `2026-08-27 08:56:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a85b5e615ecd2e2c32f59316b6d40c90` |
| SHA-1 | `30eeffa5b0e41491dc56c980e6a61f87b208eece` |
| SHA-256 | `864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f` |
| SHA3-384 | `7d28b14e276d121e9b639d65a09902e37a70d1956a98d56549d78e79fced2b2065bb9016b31f25b4fd04c79337289abf` |
| TLSH | `T19F142943B981A51AC2C7577BEF1F0348BB0653F8D3E97B2A8D282B71368751B0F66605` |
| TELFHASH | `t15be02650efb0279a23d01426c2c0fd520fee382e2b810503eb886be71153bd0b82a823` |
| SSDEEP | `6144:zDLkJUgotPRfcWiMKe9E8zE1y1WhN4Yz19vx:z3kpotPRf5iMKe9/IA12mKPx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_864aa577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f"
    family = "Mirai"
    file_name = "864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f.elf"
    file_type = "elf"
    first_seen = "2026-08-27 08:56:16"
  condition:
    hash.sha256(0, filesize) == "864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f"
}
```

### Sample 36: `1c0f770f8881dc22`

| Field | Value |
|---|---|
| SHA-256 | `1c0f770f8881dc22eb411ab4064f8075309bed6f691aea0ab478c6f7a9c45b2f` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-27 08:55:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f81d1bcf73b0336f8fe5d797d571ce24` |
| SHA-1 | `71bdfdf1b2c1b250f53e37f27fbf961db3f29d6c` |
| SHA-256 | `1c0f770f8881dc22eb411ab4064f8075309bed6f691aea0ab478c6f7a9c45b2f` |
| SHA3-384 | `536c1949aceee464fb8b5f4a83456534211776e697f54de3d48b20cf414925c3f166283ead8e6b394bb0341ce433928b` |
| TLSH | `T1F644C75E2E628F3DF2698B3487B74A25D75C62D723D1D680F1ACD1101F2025EA46FFA8` |
| TELFHASH | `t1e7419218097807e0a7756c5e499dff76d6a330ea7e162c378e11e86aab69b435c10c0c` |
| SSDEEP | `6144:l7yf6s6leoUBNhNDRGCP8RzpuKsEssMOgh5oj4:KNHDAPyEssMOgh5oj4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_1c0f770f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c0f770f8881dc22eb411ab4064f8075309bed6f691aea0ab478c6f7a9c45b2f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-27 08:55:57"
  condition:
    hash.sha256(0, filesize) == "1c0f770f8881dc22eb411ab4064f8075309bed6f691aea0ab478c6f7a9c45b2f"
}
```

### Sample 37: `368fda9d9000cba7`

| Field | Value |
|---|---|
| SHA-256 | `368fda9d9000cba7a307239fac2fdebfd1088a54a6ac6fccaaf65afb30056cb3` |
| Family label | `njrat` |
| File name | `RFQ-SW10-321313.vbs` |
| File type | `vbs` |
| First seen | `2026-08-27 08:55:08` |
| Reporter | `abuse_ch` |
| Tags | `njrat, RAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2c250f3b1b83baaa2070f675d12e242` |
| SHA-1 | `38ce3a7bfcb6e3ef661059647f17b09714e9abd2` |
| SHA-256 | `368fda9d9000cba7a307239fac2fdebfd1088a54a6ac6fccaaf65afb30056cb3` |
| SHA3-384 | `d6e3bb1b11077c355da73e0ba84975e9fe1c67f5cb5b8f0d62863255477e085c877e1412baab2f3c4a2103c087cecf2d` |
| TLSH | `T1C8D4C04D944BCD0E0D5B18F88B827DB6588CF7A82AB581E5EB82741ED74EC2E41FE315` |
| SSDEEP | `12288:D2qz1MCtiXQHMcSGzvd3JfRnKVJOtRNmSfrg4puEoV8O:DPMpcSGzvd3JZSYRNmSfrg4A9V8O` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_037_368fda9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "368fda9d9000cba7a307239fac2fdebfd1088a54a6ac6fccaaf65afb30056cb3"
    family = "njrat"
    file_name = "RFQ-SW10-321313.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:55:08"
  condition:
    hash.sha256(0, filesize) == "368fda9d9000cba7a307239fac2fdebfd1088a54a6ac6fccaaf65afb30056cb3"
}
```

### Sample 38: `9b81ca9f2247f4dd`

| Field | Value |
|---|---|
| SHA-256 | `9b81ca9f2247f4dd515ebd4b524251f4e933dc2ac78d9e30efec6e438aadc017` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-08-27 08:54:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a11fcf7b86983f08c8e9e943eb43ca9e` |
| SHA-1 | `896d2769def04e52d25b5488fcc4d84e27808873` |
| SHA-256 | `9b81ca9f2247f4dd515ebd4b524251f4e933dc2ac78d9e30efec6e438aadc017` |
| SHA3-384 | `6299d30c3e9dcc38f72f8045191f4a4f733b7aad0c35590e22f2e8f6eb4cf89258bc8ed59a6917310b7165c3bf7a8341` |
| TLSH | `T106B35B2228F36116C6D7D43F439F422AF066A50B01C8C61FBD2E5DAE7F4629067B76E4` |
| TELFHASH | `t1b0f0c041fd388a144ae27a70ec6803a585134613612287248f58c9d0cc3e00ab248d1d` |
| SSDEEP | `3072:c21EDckdOOYqKLVaaHc5lu1EssMZc/T03ImIys61X1h5oB:c21+ckdzTKLG52EssMOgh5oB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_9b81ca9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b81ca9f2247f4dd515ebd4b524251f4e933dc2ac78d9e30efec6e438aadc017"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-27 08:54:27"
  condition:
    hash.sha256(0, filesize) == "9b81ca9f2247f4dd515ebd4b524251f4e933dc2ac78d9e30efec6e438aadc017"
}
```

### Sample 39: `53802a0417b92993`

| Field | Value |
|---|---|
| SHA-256 | `53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1` |
| Family label | `PureLogsStealer` |
| File name | `53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:53:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, PureLogsStealer, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73bcd8d003f905f3ff029d977a97f05e` |
| SHA-1 | `34fbbc58ae2e941806dbbcf8d6c25bd76d1b9368` |
| SHA-256 | `53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1` |
| SHA3-384 | `95a95501f262ef339bf2980b156d00f582a1e4849df69e165a5a9975f42456f1d41b45114fbf880969f0f59d449a5c4d` |
| TLSH | `T15305BF6736524E51C2494B73C19B8A0083A396C6F9E7F30FB28413A55C973FEDA076A7` |
| SSDEEP | `12288:3iEfIwoUwtfLxNNu6yvs5N1IQeDm5m7zK8Hb9kHdtVwhQ:3HorFNNDy0xmm5G9w7wh` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_039_53802a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1"
    family = "PureLogsStealer"
    file_name = "53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:53:35"
  condition:
    hash.sha256(0, filesize) == "53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1"
}
```

### Sample 40: `4c09df605465682b`

| Field | Value |
|---|---|
| SHA-256 | `4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91` |
| Family label | `Vidar` |
| File name | `4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91.bin` |
| File type | `exe` |
| First seen | `2026-08-27 08:53:29` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2841de1d98ddb4f4e513130b5e5b0512` |
| SHA-1 | `a5422d912ac12285a06c5ad48108be7e031384ed` |
| SHA-256 | `4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91` |
| SHA3-384 | `f64a311b901eeb3178699d3a681d04d58a0a5ab71514c061f0e401e2dbd422acd4f3b8fa650186c3a180036bb69fea6b` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T14A283303F9D581A5D8968B36C5BBD253BB35B88D9736A3D33E10A6382E7A3C03970751` |
| SSDEEP | `1572864:uuJvbGXeOW7guRUrJHhwB4uBplM6MoWS2r5bYRgS/kP19IMhniaadCSOcGE:/JDGOB7tRuJHhwGZrZYRgSs1SMhniacr` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_040_4c09df60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91"
    family = "Vidar"
    file_name = "4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91.bin"
    file_type = "exe"
    first_seen = "2026-08-27 08:53:29"
  condition:
    hash.sha256(0, filesize) == "4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91"
}
```

### Sample 41: `571d566ed46b4a4f`

| Field | Value |
|---|---|
| SHA-256 | `571d566ed46b4a4f262d65646266995871185d1c536d721ce5d1c537c2eb176b` |
| Family label | `Mirai` |
| File name | `bot.arm6` |
| File type | `elf` |
| First seen | `2026-08-27 08:52:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3d4817a5ca3026e045804bb5a875941` |
| SHA-1 | `379c47478180bbbfc2c8d9f86f5cd90303d3fc8b` |
| SHA-256 | `571d566ed46b4a4f262d65646266995871185d1c536d721ce5d1c537c2eb176b` |
| SHA3-384 | `ca0ee0a6ed52a7a13738589ef245bd9eac3b6d25ab4d7d0ce389a4de34e25a938ba6da446c767d1932e4577bcd0039c2` |
| TLSH | `T1F6A42B88E1E1E3DED1D4EAB5B339744E3B230735B1DB3146A519AB72239B0590EFE910` |
| TELFHASH | `t1f22111341d0d30bca7de90e4e2afe1135b39a835bf9a387941a5f80e9841ac164b1c37` |
| SSDEEP | `12288:kICEFwrGgkdQ1rTAKXCarqL5Ob0DMBa9j9:RFwr8mrm+adDMAR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_571d566e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "571d566ed46b4a4f262d65646266995871185d1c536d721ce5d1c537c2eb176b"
    family = "Mirai"
    file_name = "bot.arm6"
    file_type = "elf"
    first_seen = "2026-08-27 08:52:52"
  condition:
    hash.sha256(0, filesize) == "571d566ed46b4a4f262d65646266995871185d1c536d721ce5d1c537c2eb176b"
}
```

### Sample 42: `a96886369a460e7f`

| Field | Value |
|---|---|
| SHA-256 | `a96886369a460e7fe167518836a5c59226901a469968bd320cab08788dbb6205` |
| Family label | `Mirai` |
| File name | `bot.arm7` |
| File type | `elf` |
| First seen | `2026-08-27 08:48:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b75cb466d05917b58b051a4336d7af5` |
| SHA-1 | `501e0eb487cd4f7f119bd8c7fd87acf4b8abc1de` |
| SHA-256 | `a96886369a460e7fe167518836a5c59226901a469968bd320cab08788dbb6205` |
| SHA3-384 | `42bc59024a9ea69fe3af9474b99a727eab1a0f9a4d75eb2f68f2b756491f963b19d8687a484a3e4d6d87e0f55c64878a` |
| TLSH | `T14EA43C48A1E1E7CAE1D4BAB5B33A784E3B630776F2E73141A119AF7323970550EF9910` |
| TELFHASH | `t1142144382c1d148cb2f48090e26fe10569b93465bfed3894a25ae84c8d429c3a472c37` |
| SSDEEP | `12288:62b39nVfSS6RyBOjdcalrL1hnkG1K0a9CrB:Zj9nVBmyNwY89` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_a9688636
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a96886369a460e7fe167518836a5c59226901a469968bd320cab08788dbb6205"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-27 08:48:27"
  condition:
    hash.sha256(0, filesize) == "a96886369a460e7fe167518836a5c59226901a469968bd320cab08788dbb6205"
}
```

### Sample 43: `7e1bf180eb4aaa01`

| Field | Value |
|---|---|
| SHA-256 | `7e1bf180eb4aaa01be1a199c5f3df34ef856b9edc8dce1971fa45678b1117d3f` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-27 08:48:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d711db9e4ca40f5fb3e27f5f2db61c2d` |
| SHA-1 | `c435a685052724236df392cd43ce75c5f20d81a3` |
| SHA-256 | `7e1bf180eb4aaa01be1a199c5f3df34ef856b9edc8dce1971fa45678b1117d3f` |
| SHA3-384 | `3f317a32b67a3d1fd7d75588c449015c5153d9b767e07864e2f7913f230ecc0328ba35fbdb4cde5f264a516e44cebb79` |
| TLSH | `T129048C63CCB66E54D666943AF2668A3C1B13F013424B5E68B83EC2B44F43C99F2657F4` |
| SSDEEP | `3072:ke7OvkIXV+KB4NJit1rYb6M8nGaW2X/A9xtJu1EssMZc/T03ImIys61X1h5o9:ke7Opx4nit1rYuUH2Y9xtyEssMOgh5o9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_7e1bf180
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1bf180eb4aaa01be1a199c5f3df34ef856b9edc8dce1971fa45678b1117d3f"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-27 08:48:26"
  condition:
    hash.sha256(0, filesize) == "7e1bf180eb4aaa01be1a199c5f3df34ef856b9edc8dce1971fa45678b1117d3f"
}
```

### Sample 44: `1be4ef7058559523`

| Field | Value |
|---|---|
| SHA-256 | `1be4ef70585595235b1f6b4890552228382101ba41226661aa6a86585e5fc458` |
| Family label | `RemcosRAT` |
| File name | `RFQ-PEDSB-BAN-LLA-2026-054-SERVICE ORDER TCs & Appendix 12.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:45:21` |
| Reporter | `threatcat_ch` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be9b3966ff6d0c0f4690a31c9a65167e` |
| SHA-1 | `67d819549b467e3fb9df45c28808768c2b301440` |
| SHA-256 | `1be4ef70585595235b1f6b4890552228382101ba41226661aa6a86585e5fc458` |
| SHA3-384 | `d0787ac09eedf25b1fe4c54d8871dfa1c8627c3bc0f1bbe48d0666a5b422f85e811c0d9ac6d67d76197167974d00a726` |
| TLSH | `T1DE3512567760EB46C87E87FA4935F2355B722D8FA422E31B8EEE8DEB78107009D05643` |
| SSDEEP | `24576:Xo+Ok2Wd+FYDYta7zJwEUgLli/Ixoc9cy+1tHILL:X0b5UnUC7mcKxH8L` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_044_1be4ef70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1be4ef70585595235b1f6b4890552228382101ba41226661aa6a86585e5fc458"
    family = "RemcosRAT"
    file_name = "RFQ-PEDSB-BAN-LLA-2026-054-SERVICE ORDER TCs & Appendix 12.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:45:21"
  condition:
    hash.sha256(0, filesize) == "1be4ef70585595235b1f6b4890552228382101ba41226661aa6a86585e5fc458"
}
```

### Sample 45: `1c40688fb64c0a7c`

| Field | Value |
|---|---|
| SHA-256 | `1c40688fb64c0a7cb58be42c58bfcbb6cfc93d51da6d561bb75a32de19bf25dc` |
| Family label | `STRRAT` |
| File name | `Request For Quotation.js` |
| File type | `js` |
| First seen | `2026-08-27 08:45:05` |
| Reporter | `abuse_ch` |
| Tags | `js, STRRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d98a8ff2c99d7564cb56e82b795a3dd6` |
| SHA-1 | `cd19913f9946aa98e35add5f82696ba633a81fea` |
| SHA-256 | `1c40688fb64c0a7cb58be42c58bfcbb6cfc93d51da6d561bb75a32de19bf25dc` |
| SHA3-384 | `1dc9f4fcddf9a7424229a5a22a81bec6f57ad2c25a86270334525ba21904842d50654794a6ab7663ef2a0c3fef3304d0` |
| TLSH | `T141050F55B36A498B1B0BDE34341A1D637BB80B60EFCC49C49257EE998C5EFC70259E0B` |
| SSDEEP | `3072:OJErxYHU0yluF6Rlb0VxnuJzQWoJZhxAArAhDv7Q2mjdYKB6xH1fCg8PDvoij8Aa:z` |

#### Technical Assessment

- The sample is tracked as `STRRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_STRRAT_045_1c40688f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c40688fb64c0a7cb58be42c58bfcbb6cfc93d51da6d561bb75a32de19bf25dc"
    family = "STRRAT"
    file_name = "Request For Quotation.js"
    file_type = "js"
    first_seen = "2026-08-27 08:45:05"
  condition:
    hash.sha256(0, filesize) == "1c40688fb64c0a7cb58be42c58bfcbb6cfc93d51da6d561bb75a32de19bf25dc"
}
```

### Sample 46: `010b2a747d23c929`

| Field | Value |
|---|---|
| SHA-256 | `010b2a747d23c92924be656e387d69d171fa0cbf91ad53e4875fe22add8a8cac` |
| Family label | `unknown` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-08-27 08:43:28` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f44026c8c43163aa17382ef25482e38d` |
| SHA-1 | `ca1a2c316b04126b0969888797e271f1fe8ee6ad` |
| SHA-256 | `010b2a747d23c92924be656e387d69d171fa0cbf91ad53e4875fe22add8a8cac` |
| SHA3-384 | `0c823311470b7cf239be26f715459ad022d0abb135abc702f0c83a365eede9e7e91ab1ba5811ca77c54034cf826db173` |
| TLSH | `T198A41B88A1E1E7CFD1D4EA75B339784D3A230735B1D73146A51AAB7323AB0590EF9D20` |
| TELFHASH | `t1e7e07d019cc41080d9e69894e08f337640b4722abb323ca14cf53c4f96e1880c073852` |
| SSDEEP | `6144:lvMV7/Doz+x/JSVDzrPqAl3MUfpWZi8CY35vvjHqjEr3f4rG4f2iyfa9Wu:lkXJSVDzr7l5fpWk2P4rj+fa9Wu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_010b2a74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "010b2a747d23c92924be656e387d69d171fa0cbf91ad53e4875fe22add8a8cac"
    family = "unknown"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-08-27 08:43:28"
  condition:
    hash.sha256(0, filesize) == "010b2a747d23c92924be656e387d69d171fa0cbf91ad53e4875fe22add8a8cac"
}
```

### Sample 47: `9bb9171ef0c05583`

| Field | Value |
|---|---|
| SHA-256 | `9bb9171ef0c05583e8c432e46a217912722abf8e344913f25bc36bb9a4a94802` |
| Family label | `Mirai` |
| File name | `lul.arm5` |
| File type | `elf` |
| First seen | `2026-08-27 08:43:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c4a15afeac11739155b8df3950c7029` |
| SHA-1 | `6dca26a053daf3fc18ad548835abc909b40765fc` |
| SHA-256 | `9bb9171ef0c05583e8c432e46a217912722abf8e344913f25bc36bb9a4a94802` |
| SHA3-384 | `b8caa6fc8f8ee6fc480b8215dafda44ce125498c273c96783aaf2ce33da60a2350641248510bcd8ff9a682438a8e030e` |
| TLSH | `T16A832959F8819616C6C1677BFF1E828C372663E8D3EA72039E255F21778752B0E3B442` |
| TELFHASH | `t1b7f0ebf9428e19cc2fa48395c1ee673e6f8b386907010890ce4abf4750e3281ba1b807` |
| SSDEEP | `1536:9QcXyWMxC+wzWngMNli9ClMmnRgkAU4XT9ecqfeBN6KBWHiddKOfhvSXS/FSoNX7:9QcyWMqygki8lMGRXAv9ecqfeb69iTKO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_9bb9171e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bb9171ef0c05583e8c432e46a217912722abf8e344913f25bc36bb9a4a94802"
    family = "Mirai"
    file_name = "lul.arm5"
    file_type = "elf"
    first_seen = "2026-08-27 08:43:26"
  condition:
    hash.sha256(0, filesize) == "9bb9171ef0c05583e8c432e46a217912722abf8e344913f25bc36bb9a4a94802"
}
```

### Sample 48: `56e1d6bef47aedb3`

| Field | Value |
|---|---|
| SHA-256 | `56e1d6bef47aedb3ee373b17fd0af4c634931db7e78c00e4c82c223f61b68987` |
| Family label | `Formbook` |
| File name | `HOTLINE TRADING EST SOA.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:41:51` |
| Reporter | `lowmal3` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90e587286fa509a6a3bf7fd591938a06` |
| SHA-1 | `8a6faa2421dc014bdb99401f507157bc265064af` |
| SHA-256 | `56e1d6bef47aedb3ee373b17fd0af4c634931db7e78c00e4c82c223f61b68987` |
| SHA3-384 | `4aa3c0c529808a395754701278380d77ade9d24ae8f2f7ad4f6fe03af094f83330f0b18684a2b29012988b1c3e801ba0` |
| TLSH | `T1F9542200B2274D6FE14B6FB1F99A77E121854177A07FA5DB62676CAE80203D1DEE2F04` |
| SSDEEP | `6144:7AGRLMFds1FsqTnocInzhrfjb2LnNjVj7rRDsp:7AGVMCuanoDzh7jCRBpwp` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_048_56e1d6be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e1d6bef47aedb3ee373b17fd0af4c634931db7e78c00e4c82c223f61b68987"
    family = "Formbook"
    file_name = "HOTLINE TRADING EST SOA.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:41:51"
  condition:
    hash.sha256(0, filesize) == "56e1d6bef47aedb3ee373b17fd0af4c634931db7e78c00e4c82c223f61b68987"
}
```

### Sample 49: `267eff803a45eac0`

| Field | Value |
|---|---|
| SHA-256 | `267eff803a45eac04ef5b9967b0ce90ada762f302308a3e82009086a06a66e67` |
| Family label | `Mirai` |
| File name | `bot.mpsl` |
| File type | `elf` |
| First seen | `2026-08-27 08:41:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `920211e6f0f574c7102588b34a1ddcff` |
| SHA-1 | `f9553fe4e525566924b97a36dba7d395b082b63a` |
| SHA-256 | `267eff803a45eac04ef5b9967b0ce90ada762f302308a3e82009086a06a66e67` |
| SHA3-384 | `52f4f514d26f37833701cda168304b6adcb3634b29c43eae48b1dbe200381899c15c395dbb3d3e54131b66d643666ab4` |
| TLSH | `T1E8C41A08A7F19FFFE06DDE3313592E0A199D452331973B6A3179E522B29B14A49E3D30` |
| SSDEEP | `6144:YqfObD7Z/7KNL3jNIj0kAk1XSYAk4ybykogM5KBO86TpzQkb03AYgGo5K1b8g5n2:Y4c3qmjO8wbeAYgGo8R8SLXkm3La9nw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_267eff80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "267eff803a45eac04ef5b9967b0ce90ada762f302308a3e82009086a06a66e67"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-08-27 08:41:32"
  condition:
    hash.sha256(0, filesize) == "267eff803a45eac04ef5b9967b0ce90ada762f302308a3e82009086a06a66e67"
}
```

### Sample 50: `9ba9080b517997bf`

| Field | Value |
|---|---|
| SHA-256 | `9ba9080b517997bf8324ede2f4fc11579cc30a519efe6ffe48a036a7e41c2315` |
| Family label | `ValleyRAT` |
| File name | `F1E9B63F2FA2D63ACC8AE3E6680D7E70.dll` |
| File type | `dll` |
| First seen | `2026-08-27 08:40:20` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1e9b63f2fa2d63acc8ae3e6680d7e70` |
| SHA-1 | `2163b7d83d35ea4e8779e5fafb29ebafac583fe0` |
| SHA-256 | `9ba9080b517997bf8324ede2f4fc11579cc30a519efe6ffe48a036a7e41c2315` |
| SHA3-384 | `0be6a175496b0b97edafd23deaec4e39b4a8950b3f590bcd3d4a423273a5b18847e42ade35ea772805da3f451f3c8eb1` |
| IMPHASH | `ed719d06b435e943e2137e8d090ae910` |
| TLSH | `T1B8847E01B5818131E9AE0934B835DBA75A7DB8714BF0D4DFA3C449AE9E207D1EB3871B` |
| SSDEEP | `6144:2cZZ+x7m+cWCDq7ZNIFTRhUE1Tk6++a3/z3mDAa/SnkuVNNEAYEQH0po:vQc8nIFTRp1TkhhGWVf0H` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_050_9ba9080b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ba9080b517997bf8324ede2f4fc11579cc30a519efe6ffe48a036a7e41c2315"
    family = "ValleyRAT"
    file_name = "F1E9B63F2FA2D63ACC8AE3E6680D7E70.dll"
    file_type = "dll"
    first_seen = "2026-08-27 08:40:20"
  condition:
    hash.sha256(0, filesize) == "9ba9080b517997bf8324ede2f4fc11579cc30a519efe6ffe48a036a7e41c2315"
}
```

### Sample 51: `d1303941d2d3f6d1`

| Field | Value |
|---|---|
| SHA-256 | `d1303941d2d3f6d1337f74fb0ec07984614d4bad8bb76143fe89a285b9dbeaaf` |
| Family label | `njrat` |
| File name | `RFQ-SW10-321313.PDF.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:40:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b7cd85a2c2ec3b1433f5fe51ba5204e` |
| SHA-1 | `b08580c9bf8cf84ab8b97d785365a2711542bd41` |
| SHA-256 | `d1303941d2d3f6d1337f74fb0ec07984614d4bad8bb76143fe89a285b9dbeaaf` |
| SHA3-384 | `b40fdf470e154bc42c18c875b93e1ef93f083e55e2af9dfc149978136c615c2a1912eb69927c5e01002ce9d00f4f02b8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17FF41262B325FA56DA7E1BF64A75E33207B60E4EA525D306CEEDADCB3C147106C05283` |
| SSDEEP | `12288:/MQGLFTWHsvm2KnU7S4wUR2Nkpuw7yTcHFN4CmaZezhSTP2lQth9+kkPaXo+0Hj:joKHsu9U7S4wUR2NkEasoFG3aAzIT9hT` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_051_d1303941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1303941d2d3f6d1337f74fb0ec07984614d4bad8bb76143fe89a285b9dbeaaf"
    family = "njrat"
    file_name = "RFQ-SW10-321313.PDF.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:40:07"
  condition:
    hash.sha256(0, filesize) == "d1303941d2d3f6d1337f74fb0ec07984614d4bad8bb76143fe89a285b9dbeaaf"
}
```

### Sample 52: `64bf0e2bfdaacf3d`

| Field | Value |
|---|---|
| SHA-256 | `64bf0e2bfdaacf3dc81ce6c339907992eebf5876e64841dce2ad73d539960578` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-27 08:36:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c68f96f20d5b4eae439a065a0dabf845` |
| SHA-1 | `9dfcc5df3e0cd9dc7d33fff41ca70cde151656bf` |
| SHA-256 | `64bf0e2bfdaacf3dc81ce6c339907992eebf5876e64841dce2ad73d539960578` |
| SHA3-384 | `d2219e6d1760aa9a2f8d98abd59326931e3f1c9ffe6cb16460f3bc78546ffa6b08fdc6da8a6c0a979e7194b9677d44f2` |
| TLSH | `T1B9C27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B2A` |
| SSDEEP | `768:h8vCB+25j6es8Rdp9FYpMSUpi+20qUpi+20YQX:h8l25J5d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_64bf0e2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bf0e2bfdaacf3dc81ce6c339907992eebf5876e64841dce2ad73d539960578"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-27 08:36:37"
  condition:
    hash.sha256(0, filesize) == "64bf0e2bfdaacf3dc81ce6c339907992eebf5876e64841dce2ad73d539960578"
}
```

### Sample 53: `ab8011dca996781f`

| Field | Value |
|---|---|
| SHA-256 | `ab8011dca996781f1d1bd0fae166d255c0c27464f35b637902b71ac1c3a8cf9f` |
| Family label | `unknown` |
| File name | `ad9acc19c36e3e921e43074ec3b09304.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:35:39` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad9acc19c36e3e921e43074ec3b09304` |
| SHA-1 | `1d89934362622060773e47952b9d1611a74c6577` |
| SHA-256 | `ab8011dca996781f1d1bd0fae166d255c0c27464f35b637902b71ac1c3a8cf9f` |
| SHA3-384 | `74eb59c58268e548162a613bd1069e32ac131ce6d7ea100f1505d68e3c8bf8386aebe6889bb39b1981a0b163251a8e1b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E8233B14B7E98322CABE477168B352090376E60BA526FB1E2CCC55E82F677D4C6113F6` |
| SSDEEP | `768:dFaXIjq8D2zfFjr4kamoHofeC+n4vvcqVlm0yJ8CGT6m:fqg8Pa5IfN+aculQJ8n+m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_ab8011dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab8011dca996781f1d1bd0fae166d255c0c27464f35b637902b71ac1c3a8cf9f"
    family = "unknown"
    file_name = "ad9acc19c36e3e921e43074ec3b09304.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:39"
  condition:
    hash.sha256(0, filesize) == "ab8011dca996781f1d1bd0fae166d255c0c27464f35b637902b71ac1c3a8cf9f"
}
```

### Sample 54: `c5ecdd414e5a4a9c`

| Field | Value |
|---|---|
| SHA-256 | `c5ecdd414e5a4a9ce1dac9fd9bdac433de80b66de3d0aff47abe784706fbb02a` |
| Family label | `SheetRAT` |
| File name | `1035735f7d18175e23e1181434648494.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:35:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1035735f7d18175e23e1181434648494` |
| SHA-1 | `ab3c478b0481fd4d9b4cc228312a6ba89bae9e94` |
| SHA-256 | `c5ecdd414e5a4a9ce1dac9fd9bdac433de80b66de3d0aff47abe784706fbb02a` |
| SHA3-384 | `278ecaa969dd240c552e8a5382ace9569166cb4ff01f889dddc94910bfea17da8bd8d8c0438c4b332139c6768e737518` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13814E04473C88A14D97E06FD8363B324933492071897EB0E1ECA91DA3F76BD5DA09DE5` |
| SSDEEP | `3072:5q4IN0wVxpaNvbaeO9K3S+0LRX0pcU622wca+He6pyXNlNtA7uDgObnNQUKn:grpaN2rA3SRLRXg15ca+H9ONl3A72nb` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_054_c5ecdd41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5ecdd414e5a4a9ce1dac9fd9bdac433de80b66de3d0aff47abe784706fbb02a"
    family = "SheetRAT"
    file_name = "1035735f7d18175e23e1181434648494.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:33"
  condition:
    hash.sha256(0, filesize) == "c5ecdd414e5a4a9ce1dac9fd9bdac433de80b66de3d0aff47abe784706fbb02a"
}
```

### Sample 55: `8413753dd6b3c68a`

| Field | Value |
|---|---|
| SHA-256 | `8413753dd6b3c68aade5c95450cd68b52bf448d827210e0385203e102b5926ad` |
| Family label | `SheetRAT` |
| File name | `01203720869a8f590601cc3d639b9984.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:35:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01203720869a8f590601cc3d639b9984` |
| SHA-1 | `2cd9e4013c10d00068923640c349088a2092c578` |
| SHA-256 | `8413753dd6b3c68aade5c95450cd68b52bf448d827210e0385203e102b5926ad` |
| SHA3-384 | `3170db0114420dc0d47e7f4da56140a038b15e620cb8de0b17f06768afd87a0e0b089d6446e03397e9e5f56d0e053a19` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19EC44A247F948609E580197E459E5600C3FE91F22632B307371AEF611D899DEEE6C3EB` |
| SSDEEP | `12288:fLr1+ThA0u/lDfhwdKfAGNAtQ/MpYbD5gJq/8:t+Tm0EDSKvitQ/MwX8` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_055_8413753d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8413753dd6b3c68aade5c95450cd68b52bf448d827210e0385203e102b5926ad"
    family = "SheetRAT"
    file_name = "01203720869a8f590601cc3d639b9984.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:23"
  condition:
    hash.sha256(0, filesize) == "8413753dd6b3c68aade5c95450cd68b52bf448d827210e0385203e102b5926ad"
}
```

### Sample 56: `22a6a1c861c0d3bd`

| Field | Value |
|---|---|
| SHA-256 | `22a6a1c861c0d3bd6df621455c14adb9f0aac24ebf1ef6739131fc6e8ec696bf` |
| Family label | `SheetRAT` |
| File name | `743979767b321025dd464b0f7070b8ff.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:35:15` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `743979767b321025dd464b0f7070b8ff` |
| SHA-1 | `fdf4289a426f4d50b0b10b89b94cb7aa246fc016` |
| SHA-256 | `22a6a1c861c0d3bd6df621455c14adb9f0aac24ebf1ef6739131fc6e8ec696bf` |
| SHA3-384 | `1ecdf040e3cb5bdbe44bc192bcb31b36c3086428162ea4fa09b7ff8a0c4aff1ca8d5f6df0ccc6e58d09b044090a027de` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14414F10A33C48A16C2BD157A931BB3509B35E2474852D70B2EC7D1E66F27BD49E4AEE0` |
| SSDEEP | `3072:JVvxd0Tw0ZA1fPVDfMaUaANCPcaIDq6L+f8BrP0A/pN8SNZ4QFzOZajoLy0ObnNi:/SCVQaU6caIDqP8qAQSPZiajoebb` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_056_22a6a1c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22a6a1c861c0d3bd6df621455c14adb9f0aac24ebf1ef6739131fc6e8ec696bf"
    family = "SheetRAT"
    file_name = "743979767b321025dd464b0f7070b8ff.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:15"
  condition:
    hash.sha256(0, filesize) == "22a6a1c861c0d3bd6df621455c14adb9f0aac24ebf1ef6739131fc6e8ec696bf"
}
```

### Sample 57: `e110c3d90f63af79`

| Field | Value |
|---|---|
| SHA-256 | `e110c3d90f63af79053e1a50229b311a39f1b12420e6962e767179a918628523` |
| Family label | `ValleyRAT` |
| File name | `DFB400A13708E6F9771F2A02100E3B32.dll` |
| File type | `dll` |
| First seen | `2026-08-27 08:35:14` |
| Reporter | `abuse_ch` |
| Tags | `dll, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfb400a13708e6f9771f2a02100e3b32` |
| SHA-1 | `922b3b687409cd531bc34d4a25f339cb7cad565a` |
| SHA-256 | `e110c3d90f63af79053e1a50229b311a39f1b12420e6962e767179a918628523` |
| SHA3-384 | `0bcff7cbff4db94d32961ea13952e6e7844d11a2435b5d4459fa753f8417504fd9598a156d4995c792185f79c2402be4` |
| IMPHASH | `52cfdb731563048cbcd312740731136b` |
| TLSH | `T145652311FC8188B2DDAA3B383160B53C4B6D75500BB19EBB37644E75AB38FC1AF2545A` |
| SSDEEP | `24576:Xh8JJlv5PLeJH90J3Nv/Te/rhcxdEDzcjxU25R7tWqR/kW5/LAIT2hr0Sh:XhilBPLeJHolRxdOzcjxPZWK/15EITCr` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_057_e110c3d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e110c3d90f63af79053e1a50229b311a39f1b12420e6962e767179a918628523"
    family = "ValleyRAT"
    file_name = "DFB400A13708E6F9771F2A02100E3B32.dll"
    file_type = "dll"
    first_seen = "2026-08-27 08:35:14"
  condition:
    hash.sha256(0, filesize) == "e110c3d90f63af79053e1a50229b311a39f1b12420e6962e767179a918628523"
}
```

### Sample 58: `bc73e28fca0988fe`

| Field | Value |
|---|---|
| SHA-256 | `bc73e28fca0988fea8ef3460890ee16049842d9829403eedc63661e01bb09447` |
| Family label | `unknown` |
| File name | `7bbe43387cfe0e00dafd61ea63904c6d.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:35:05` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7bbe43387cfe0e00dafd61ea63904c6d` |
| SHA-1 | `e3c5dcfd1274175d482718b9dc6e9a0936bacc40` |
| SHA-256 | `bc73e28fca0988fea8ef3460890ee16049842d9829403eedc63661e01bb09447` |
| SHA3-384 | `a72a7c44625b941755a82693480e2c269a728f2ab517c4822604d1253a21cced430d4b048344de084aa8ed517dd197c1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A6841A147F988609E5901A7E425E2500C7EE92F265327303370AFF625D899DEDE2D3EB` |
| SSDEEP | `6144:Pe9DtAHOBGvEpzVI96iNANhYtpIMZONgTuAdhZAFSub4td1TFyyol67O:GMIenENlQjL7B7O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_bc73e28f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc73e28fca0988fea8ef3460890ee16049842d9829403eedc63661e01bb09447"
    family = "unknown"
    file_name = "7bbe43387cfe0e00dafd61ea63904c6d.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:05"
  condition:
    hash.sha256(0, filesize) == "bc73e28fca0988fea8ef3460890ee16049842d9829403eedc63661e01bb09447"
}
```

### Sample 59: `fb95d7d6d256e0d1`

| Field | Value |
|---|---|
| SHA-256 | `fb95d7d6d256e0d1e492ebcb02b12776996a2887f54a6f4a54155c2729a40273` |
| Family label | `XWorm` |
| File name | `a8ccf7af26ae2a2e221b224822e5a639.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:34:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8ccf7af26ae2a2e221b224822e5a639` |
| SHA-1 | `507a4e68ff465dedc0f6dc5fce822a9003635947` |
| SHA-256 | `fb95d7d6d256e0d1e492ebcb02b12776996a2887f54a6f4a54155c2729a40273` |
| SHA3-384 | `d88ba68484c99a30108d873dfc1a30db6c37aab73f2b04450f77338528263a3e76759eca1fc5b0114f0fddcd3de8665f` |
| IMPHASH | `9524a62d9b63411f0e9075f1a442bf92` |
| TLSH | `T1EFC4BF4D814E2278F17607F2EB63C0A5903F68515B49F6EB11E1B4E9B4397C4E22A7E3` |
| SSDEEP | `12288:LykafaSF/Tlagk+iuvyb+UrFpCE0ed+pFqmsXPhIhT:WDTF/kgHiUM+urBEpkX5Ip` |
| ICON-DHASH | `0ff0c0d4d4c0f00f` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_059_fb95d7d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb95d7d6d256e0d1e492ebcb02b12776996a2887f54a6f4a54155c2729a40273"
    family = "XWorm"
    file_name = "a8ccf7af26ae2a2e221b224822e5a639.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:54"
  condition:
    hash.sha256(0, filesize) == "fb95d7d6d256e0d1e492ebcb02b12776996a2887f54a6f4a54155c2729a40273"
}
```

### Sample 60: `15aeb01ceb8079f1`

| Field | Value |
|---|---|
| SHA-256 | `15aeb01ceb8079f16fa83a6d8c5d44c04c590f474c6c95e96e4e31df9786725d` |
| Family label | `SheetRAT` |
| File name | `071a9e42a3118c4becbd671529dc2f06.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:34:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `071a9e42a3118c4becbd671529dc2f06` |
| SHA-1 | `1cb4d6b0a527f92c6adaae1cd89e7af703a832eb` |
| SHA-256 | `15aeb01ceb8079f16fa83a6d8c5d44c04c590f474c6c95e96e4e31df9786725d` |
| SHA3-384 | `4ced52eebf033a40a8d5237bc499ca9a6961b70bdedaa7a9e717b58a109712c853924a0d95488b575cf58bbc3bead947` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T158B44B247F988609E584297E419E1600C7EE92F225327303370AEF655D89DDEDE2D3EB` |
| SSDEEP | `12288:YM7Wb6Xo7PMZkc/BxcUfKIW+w+sQUCAbUw96s:lGMZkZ+hU3wI6s` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_060_15aeb01c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15aeb01ceb8079f16fa83a6d8c5d44c04c590f474c6c95e96e4e31df9786725d"
    family = "SheetRAT"
    file_name = "071a9e42a3118c4becbd671529dc2f06.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:47"
  condition:
    hash.sha256(0, filesize) == "15aeb01ceb8079f16fa83a6d8c5d44c04c590f474c6c95e96e4e31df9786725d"
}
```

### Sample 61: `ae90f9af53f31512`

| Field | Value |
|---|---|
| SHA-256 | `ae90f9af53f315122f31021f664f686a66dd77a08fcf560fad3d373c0ac5eabd` |
| Family label | `unknown` |
| File name | `106032e5fe69908d00017874faca1976.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:34:38` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `106032e5fe69908d00017874faca1976` |
| SHA-1 | `17e61742b3f13fe745643d9e44315ecfab820220` |
| SHA-256 | `ae90f9af53f315122f31021f664f686a66dd77a08fcf560fad3d373c0ac5eabd` |
| SHA3-384 | `06f57b12bd123c8b814b8d6530346c748e4784d2072938e9f96d1e80d0b47816b5940ed330e92bb1903c506867d950f6` |
| IMPHASH | `1dcd477cce07724ec6b817b3be71540e` |
| TLSH | `T1B6963354B2D085F5F8B3803EDEA1D460ABB2BC412B56E1FF23A07A1A1E372D05E35765` |
| SSDEEP | `196608:Rihcd3wLkOXEpXnH2ph1iut1/1QpL0uQg+RBtK7voKgpVFSZ:RihAEkOXEAphVtrQSg+RHK7vFgtS` |
| ICON-DHASH | `58c8d1d0cecbeeec` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_ae90f9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae90f9af53f315122f31021f664f686a66dd77a08fcf560fad3d373c0ac5eabd"
    family = "unknown"
    file_name = "106032e5fe69908d00017874faca1976.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:38"
  condition:
    hash.sha256(0, filesize) == "ae90f9af53f315122f31021f664f686a66dd77a08fcf560fad3d373c0ac5eabd"
}
```

### Sample 62: `935a89876a469292`

| Field | Value |
|---|---|
| SHA-256 | `935a89876a469292f4b238c7ad9d1ad6387519a5f1b486d37559579936430eff` |
| Family label | `SheetRAT` |
| File name | `0bb278acc41500c6831112bdf1b2b2aa.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:34:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bb278acc41500c6831112bdf1b2b2aa` |
| SHA-1 | `5b594c66c5af8190bbaac80c9fc9c86a2dd90ab7` |
| SHA-256 | `935a89876a469292f4b238c7ad9d1ad6387519a5f1b486d37559579936430eff` |
| SHA3-384 | `514335197345cc8772e7fea5744d1b764cbea24745609ec5f5a408bf8217add3f8d2d420e375d08842271e6c8cc300e5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T119C43A147F988A09E5902A3E415E1901C7EE92F62632B303370BEF615D899DDDF2D3DA` |
| SSDEEP | `12288:b9+6cV9JnPFM28dLAEAzM1fWUDzcHjEN9wgjM2:IidAEaM1fZDzeEXjn` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_062_935a8987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935a89876a469292f4b238c7ad9d1ad6387519a5f1b486d37559579936430eff"
    family = "SheetRAT"
    file_name = "0bb278acc41500c6831112bdf1b2b2aa.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:16"
  condition:
    hash.sha256(0, filesize) == "935a89876a469292f4b238c7ad9d1ad6387519a5f1b486d37559579936430eff"
}
```

### Sample 63: `3511c86c901db8d4`

| Field | Value |
|---|---|
| SHA-256 | `3511c86c901db8d494eea0e1bea6d398cc60e5aadba713f549da0ba3f5c2505a` |
| Family label | `unknown` |
| File name | `3fee630d3e005c84a3983903386b17cc.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:34:06` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fee630d3e005c84a3983903386b17cc` |
| SHA-1 | `7605c9bdeb6d630f513a664e239f93b873cb2e0f` |
| SHA-256 | `3511c86c901db8d494eea0e1bea6d398cc60e5aadba713f549da0ba3f5c2505a` |
| SHA3-384 | `9791b2b29703e2f2cd672731f6fd0043ba5efbad460d5ec54fedac180c673b67273f9c209e9ee754e3c930ab503b4ae4` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17A43061573D88735D6BE477118B227050B36FA0BA537EB1E2CA895A92F237D4C9107B3` |
| SSDEEP | `1536:tneov7Sfydq+jteId+yZ091IW2J3W+ok:J9kydq+jcId+yyJk3WC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_3511c86c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3511c86c901db8d494eea0e1bea6d398cc60e5aadba713f549da0ba3f5c2505a"
    family = "unknown"
    file_name = "3fee630d3e005c84a3983903386b17cc.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:06"
  condition:
    hash.sha256(0, filesize) == "3511c86c901db8d494eea0e1bea6d398cc60e5aadba713f549da0ba3f5c2505a"
}
```

### Sample 64: `39e5a1bb3b057fa6`

| Field | Value |
|---|---|
| SHA-256 | `39e5a1bb3b057fa6bf3e2aa2961763cb48bef578648e754c1cf52da7ddd2a2d8` |
| Family label | `unknown` |
| File name | `53deb2d9fbbabdb94d6dc198bd8124c0.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:33:52` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53deb2d9fbbabdb94d6dc198bd8124c0` |
| SHA-1 | `620b2d406019475baa15f8e7a88711df0c2f572a` |
| SHA-256 | `39e5a1bb3b057fa6bf3e2aa2961763cb48bef578648e754c1cf52da7ddd2a2d8` |
| SHA3-384 | `2a3669efee12ee621278291ce9a4f5fa50ddf9c712a47a2689cce92174e62b375f0ed9e624e8851a1a64a1190a04ed6f` |
| IMPHASH | `a9c887a4f18a3fede2cc29ceea138ed3` |
| TLSH | `T1BEE52A99E8D2128A096C3559DECDB0286FFC2C49B0676D6CCABC1EF6DB81D4A034F54D` |
| SSDEEP | `49152:cGmHN0oJDRNnGLOPhQhRGdmMV+pp4YF5muc72:g06RNnGapQPt8QQuq2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_39e5a1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39e5a1bb3b057fa6bf3e2aa2961763cb48bef578648e754c1cf52da7ddd2a2d8"
    family = "unknown"
    file_name = "53deb2d9fbbabdb94d6dc198bd8124c0.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:52"
  condition:
    hash.sha256(0, filesize) == "39e5a1bb3b057fa6bf3e2aa2961763cb48bef578648e754c1cf52da7ddd2a2d8"
}
```

### Sample 65: `e2c22911a38748cf`

| Field | Value |
|---|---|
| SHA-256 | `e2c22911a38748cfdd480415c255d50bd75edeb66978806362349621de308310` |
| Family label | `SheetRAT` |
| File name | `7513d77e95e15f4d6b69308ae01036e5.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:33:45` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7513d77e95e15f4d6b69308ae01036e5` |
| SHA-1 | `cdcaf253f1c846011c3dd72d4198b0204d13e629` |
| SHA-256 | `e2c22911a38748cfdd480415c255d50bd75edeb66978806362349621de308310` |
| SHA3-384 | `7aa4f6615d760aa3e97cc8d13772cb8f4d5fa8e6de459cd22ca9bceeb92acd92c7cd4db04ed57a3e9f7d94386a246e66` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CE535C0877808E51D97E5AB5A353B39097B0D6071542EB4B2ECFC0C16E6A7C2D686CFA` |
| SSDEEP | `1536:6h3eUZhZ0MjGxYlCYLT/SObntfXHmnVPxX:6hBhZ0olCYPSObntfIJxX` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_065_e2c22911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2c22911a38748cfdd480415c255d50bd75edeb66978806362349621de308310"
    family = "SheetRAT"
    file_name = "7513d77e95e15f4d6b69308ae01036e5.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:45"
  condition:
    hash.sha256(0, filesize) == "e2c22911a38748cfdd480415c255d50bd75edeb66978806362349621de308310"
}
```

### Sample 66: `19ab76f2fd893f17`

| Field | Value |
|---|---|
| SHA-256 | `19ab76f2fd893f174ff8505c0439dde8e4fabf7b2c72360209675294204783aa` |
| Family label | `unknown` |
| File name | `b315891c9c02a85a30b7ae6eec4d9e9e.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:33:33` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b315891c9c02a85a30b7ae6eec4d9e9e` |
| SHA-1 | `50570b3c0a5c37f8b39814e760ffb8d47c696148` |
| SHA-256 | `19ab76f2fd893f174ff8505c0439dde8e4fabf7b2c72360209675294204783aa` |
| SHA3-384 | `fd730eb9560f87d634b77404f95493aaad268706df9126166b2a9678c8630d8acd76f7ec97026a03fe907522a938880d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EBC44D187F958A08E190257E454E1A15DBAEE1F226327303370AEF624D45DDEDE2C3EB` |
| SSDEEP | `6144:AbcJK+o2r2XvWh9WxEGkzcRDqnDflNtlzVamWt3HW4QkLkODghPoNHtmSvFFLMfb:4v9XvYUxVJqnJejRsSvDLMf51nj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_19ab76f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19ab76f2fd893f174ff8505c0439dde8e4fabf7b2c72360209675294204783aa"
    family = "unknown"
    file_name = "b315891c9c02a85a30b7ae6eec4d9e9e.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:33"
  condition:
    hash.sha256(0, filesize) == "19ab76f2fd893f174ff8505c0439dde8e4fabf7b2c72360209675294204783aa"
}
```

### Sample 67: `d6279667f28724ed`

| Field | Value |
|---|---|
| SHA-256 | `d6279667f28724ed2b35b8c0bbd13121e0a1f5f929669cee16b7945c6039eb1f` |
| Family label | `SheetRAT` |
| File name | `1008cc67abe5358a99e749fe35ad825b.exe` |
| File type | `exe` |
| First seen | `2026-08-27 08:33:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, SheetRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1008cc67abe5358a99e749fe35ad825b` |
| SHA-1 | `6304b271027c9fb8c50bb77479d2a78453361970` |
| SHA-256 | `d6279667f28724ed2b35b8c0bbd13121e0a1f5f929669cee16b7945c6039eb1f` |
| SHA3-384 | `623729036107dc007f7e5145766b03d1a291217312e559f189b53585b17e22d351f1df3a4d1f2a6bd87806c63a8e2031` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T126D4C20CFE91F804CD1A3DB7CEE911044B7165C1AE1292863169AFFD9B663B34AE257C` |
| SSDEEP | `6144:Yt0r3aif14WNIDKOQ7BJVye6VlWT8b9/AMzBTneOdmzhbF+mO5OSN53b+oP5sIh:YtqqiK1jQ70PVle8N17JQhb65RNg+2I` |

#### Technical Assessment

- The sample is tracked as `SheetRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SheetRAT_067_d6279667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6279667f28724ed2b35b8c0bbd13121e0a1f5f929669cee16b7945c6039eb1f"
    family = "SheetRAT"
    file_name = "1008cc67abe5358a99e749fe35ad825b.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:28"
  condition:
    hash.sha256(0, filesize) == "d6279667f28724ed2b35b8c0bbd13121e0a1f5f929669cee16b7945c6039eb1f"
}
```

### Sample 68: `57db4fafacc617d4`

| Field | Value |
|---|---|
| SHA-256 | `57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4` |
| Family label | `unknown` |
| File name | `57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4.bin` |
| File type | `unknown` |
| First seen | `2026-08-27 08:30:51` |
| Reporter | `Tuxxin` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `875dbfbb442f4b40f2803aa7a73c7c32` |
| SHA-256 | `57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_57db4faf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4"
    family = "unknown"
    file_name = "57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4.bin"
    file_type = "unknown"
    first_seen = "2026-08-27 08:30:51"
  condition:
    hash.sha256(0, filesize) == "57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4"
}
```

### Sample 69: `5561504ee4b04bf1`

| Field | Value |
|---|---|
| SHA-256 | `5561504ee4b04bf194c8d7f9c18d0cf00a9dcf948dfe91b2e489195eb3283608` |
| Family label | `Mirai` |
| File name | `bot.arc` |
| File type | `elf` |
| First seen | `2026-08-27 08:30:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1014a96b5fa9717ec31395b79ecf234a` |
| SHA-1 | `d8e6dc21aa7ff7d90d97cb4c6fd79db0cfaea911` |
| SHA-256 | `5561504ee4b04bf194c8d7f9c18d0cf00a9dcf948dfe91b2e489195eb3283608` |
| SHA3-384 | `ec19b890aa82606b460919389f20b2557c4bff88572b9fb819b0265a6fffeff56276b62df740f5b4a6ec05f2c1e65bc4` |
| TLSH | `T12B641988A3F1E3DEE198E9B563117C1A8D72063734977687715EF97313BB18806E9A30` |
| TELFHASH | `t15d01b845a87cc77e4ed25e34ac3e03224547d63621329729ef00dad4683e054f208e4a` |
| SSDEEP | `3072:TMrNVW8JO5Neenn8a6oTAaTT3QZE/mpntokyEEdx8gDJykhLLep6Va90XZ1POfyz:HNeen8a6EAaPQZYmptXNy2gDJyk7a9P` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_5561504e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5561504ee4b04bf194c8d7f9c18d0cf00a9dcf948dfe91b2e489195eb3283608"
    family = "Mirai"
    file_name = "bot.arc"
    file_type = "elf"
    first_seen = "2026-08-27 08:30:26"
  condition:
    hash.sha256(0, filesize) == "5561504ee4b04bf194c8d7f9c18d0cf00a9dcf948dfe91b2e489195eb3283608"
}
```

### Sample 70: `076a9a73dc1b2f80`

| Field | Value |
|---|---|
| SHA-256 | `076a9a73dc1b2f8053c3cb7a44da7031a55694f844282f79b30094f0848c2dc1` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-27 08:28:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95a81388a8eef1de2f7db3ea39b9169e` |
| SHA-1 | `1bc74a2f59e92239353cedb9ae251b34a1dafd3f` |
| SHA-256 | `076a9a73dc1b2f8053c3cb7a44da7031a55694f844282f79b30094f0848c2dc1` |
| SHA3-384 | `7f12837f5d143cb377c0c71f57a2d64b012d7bd49e9830a13fda23f73ef4deaa24e6fef4198171a12e3d90d7db213e10` |
| TLSH | `T137245C1378E190FDC9D7C5388B9F911AD932F40B1124B21A778DBE652F4EE306BAD690` |
| TELFHASH | `t17a61ef742e56398831e3d715b30eca5afc7609250ee2b0eadf6b75d1ce477c80d52092` |
| SSDEEP | `3072:X1KzL8YGND46C+BKHhfv2b8GYKPGxOmdMCfqZa5zTrvCNu1EssMZc/T03ImIys6n:XwccpwUdHSsMIzPvXEssMOgh5o6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_076a9a73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "076a9a73dc1b2f8053c3cb7a44da7031a55694f844282f79b30094f0848c2dc1"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-27 08:28:42"
  condition:
    hash.sha256(0, filesize) == "076a9a73dc1b2f8053c3cb7a44da7031a55694f844282f79b30094f0848c2dc1"
}
```

### Sample 71: `f2d8eec71f2ac369`

| Field | Value |
|---|---|
| SHA-256 | `f2d8eec71f2ac36975cd7b2f3a5f8a6eee1d11812f2e3a4e6e41812084a6657d` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-27 08:28:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8f981b86304643f1e08bb2a32d20b7f` |
| SHA-1 | `43c63c83c30d53a2b8cb664b11442855b05619c6` |
| SHA-256 | `f2d8eec71f2ac36975cd7b2f3a5f8a6eee1d11812f2e3a4e6e41812084a6657d` |
| SHA3-384 | `61a931f33a97bfedd539b9bc7bc43a1deef0b6fdcbf80d94b41c11fe6ff6861bb6251d07fdd1211bb25e3f571882e447` |
| TLSH | `T169313EDF94206A711142CA8EB7A2654C664DA6FB2C5FD7D4DD0C4FEA824C38CF261F89` |
| SSDEEP | `24:H2gJFrQ4j0MaIOTHfyylW6hsG+AoZzp9c:nXQ4balzyylW6hsGoZc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_f2d8eec7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2d8eec71f2ac36975cd7b2f3a5f8a6eee1d11812f2e3a4e6e41812084a6657d"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-27 08:28:40"
  condition:
    hash.sha256(0, filesize) == "f2d8eec71f2ac36975cd7b2f3a5f8a6eee1d11812f2e3a4e6e41812084a6657d"
}
```

### Sample 72: `bde14c634f785ba4`

| Field | Value |
|---|---|
| SHA-256 | `bde14c634f785ba4b7d31e6565cf9a57458633ce1645c560a5a7f006359081f9` |
| Family label | `unknown` |
| File name | `FedEx_AWB_.zip` |
| File type | `zip` |
| First seen | `2026-08-27 08:28:27` |
| Reporter | `anonymous` |
| Tags | `remcos, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0099c650239b614ed51a497197e581c9` |
| SHA-1 | `878d51b3f3dcfef324573c8ca4d2b3b3c771324a` |
| SHA-256 | `bde14c634f785ba4b7d31e6565cf9a57458633ce1645c560a5a7f006359081f9` |
| SHA3-384 | `a4bb4b0433d8d468481ce303bb0b35c15696fb0fa9d5ed5bf00a508a4f0a6436e53df8de0e1f0f9ab946a746c1db759d` |
| TLSH | `T1D5753396ED169080D14C62BF717E66CBB80C9786781BEBFEB2E5D1CBF6D0ECA5015480` |
| SSDEEP | `24576:KecfM3b2zzJJiATC99p7GcaKg63/DyeON9danoKQcm7kLDD327FZoQAHqTBp2l8d:KecfM3b2z1Jsnajc/D6AQc1734yqSqd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_bde14c63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde14c634f785ba4b7d31e6565cf9a57458633ce1645c560a5a7f006359081f9"
    family = "unknown"
    file_name = "FedEx_AWB_.zip"
    file_type = "zip"
    first_seen = "2026-08-27 08:28:27"
  condition:
    hash.sha256(0, filesize) == "bde14c634f785ba4b7d31e6565cf9a57458633ce1645c560a5a7f006359081f9"
}
```

### Sample 73: `9bbbe31c2684dfca`

| Field | Value |
|---|---|
| SHA-256 | `9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e` |
| Family label | `Vidar` |
| File name | `9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e.bin` |
| File type | `exe` |
| First seen | `2026-08-27 08:27:56` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8c634783ec8e64d74b15a7a9d251522` |
| SHA-1 | `8d176cd75c351d0f5634ea51b37d510802124e3d` |
| SHA-256 | `9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e` |
| SHA3-384 | `06b2df8c5ccfa7e2744b11b0f903de4295c846e4535036d216a51079e041cc934d97b97d858c99fce3ddb5ac9f56b2cc` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T126069E43BC81A866D5FA973588624195BA307E486B3073F32F05BA792F333D81D7A758` |
| GIMPHASH | `af8d0ac7bf27629a217c4f015aaf7ba775460393177033e62e98c9bece8ea70a` |
| SSDEEP | `49152:6gLd6xf6DfnZsIDOqykPbLCndk9hkYyz0mA7h+U7sFg+pamKD1h0B:WIlsIDOqlPbOdQkYqs7JoB` |
| ICON-DHASH | `9987c4c8c8cc8799` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_073_9bbbe31c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e"
    family = "Vidar"
    file_name = "9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e.bin"
    file_type = "exe"
    first_seen = "2026-08-27 08:27:56"
  condition:
    hash.sha256(0, filesize) == "9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e"
}
```

### Sample 74: `3d16deb2bf2c8917`

| Field | Value |
|---|---|
| SHA-256 | `3d16deb2bf2c8917d508fca5480dbe555ba68a88fd7ef8d4f4c23d74f0d03e03` |
| Family label | `unknown` |
| File name | `221036299-043825-sanlccjavap0004-6531.pdf.z` |
| File type | `z` |
| First seen | `2026-08-27 08:27:33` |
| Reporter | `anonymous` |
| Tags | `formbook, z` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `509b02ba34c0905040946f5a611d1ce7` |
| SHA-1 | `ce67b4aad5747526943aa2feaaae6c5c2f03f54d` |
| SHA-256 | `3d16deb2bf2c8917d508fca5480dbe555ba68a88fd7ef8d4f4c23d74f0d03e03` |
| SHA3-384 | `df1835fa774e8e0734cd4e81f8bccf766aec3d1ef2e9d262d06ab5d90f03d2812515bf4a784f12300808266c39d0a895` |
| TLSH | `T1661423A6C4F163A44E4DC5C162724F33EA3B78EAC9C43D8154C4E927D8E66972D8EC29` |
| SSDEEP | `6144:jJBaJtHv7JegHmRiVNTD9bemZGuEMARC9J9sR1B/XtQ4:dA3H0hiVNTD9bemZGuv3CR11S4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `z`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_3d16deb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d16deb2bf2c8917d508fca5480dbe555ba68a88fd7ef8d4f4c23d74f0d03e03"
    family = "unknown"
    file_name = "221036299-043825-sanlccjavap0004-6531.pdf.z"
    file_type = "z"
    first_seen = "2026-08-27 08:27:33"
  condition:
    hash.sha256(0, filesize) == "3d16deb2bf2c8917d508fca5480dbe555ba68a88fd7ef8d4f4c23d74f0d03e03"
}
```

### Sample 75: `81051b2e58fe4e4d`

| Field | Value |
|---|---|
| SHA-256 | `81051b2e58fe4e4d53b5bea904151af33d44ed72603c2aeffbba6520af40861e` |
| Family label | `Mirai` |
| File name | `tmips` |
| File type | `elf` |
| First seen | `2026-08-27 08:25:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `207dec74ac54dd793adaacfcd2153749` |
| SHA-1 | `2aed5100d4ea5f907f4dc19c2051247838135909` |
| SHA-256 | `81051b2e58fe4e4d53b5bea904151af33d44ed72603c2aeffbba6520af40861e` |
| SHA3-384 | `d1131a90417f301d7406f8b4a0fc62980e0e84597a876f43709ae985b68313644216b9d8e5b33e1902bd5a128198fc82` |
| TLSH | `T1BE34DA0A7F358F2EF16E8A3047B74A21D36927D21BA1C64D91DCDA413E2039D6D1FB68` |
| TELFHASH | `t15221bd5c493823e0d7b01cd91aedff76e5a030df4a266d378e00e8acaa6dd425e00c2c` |
| SSDEEP | `3072:GDuBFQvYelCcHjo9RXeC9Xfe3Rf5zgsVnQBd9Ooet:GDCeYelzHsRXedBh8vBd9Ooet` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_81051b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81051b2e58fe4e4d53b5bea904151af33d44ed72603c2aeffbba6520af40861e"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-08-27 08:25:48"
  condition:
    hash.sha256(0, filesize) == "81051b2e58fe4e4d53b5bea904151af33d44ed72603c2aeffbba6520af40861e"
}
```

### Sample 76: `93aeb68e1d8d2de6`

| Field | Value |
|---|---|
| SHA-256 | `93aeb68e1d8d2de64418bcdb174aa15e50c8b1865e3c7a4051a654d2ec68fdd2` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-08-27 08:24:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42733938f1d125db2a2f33d1b93b781a` |
| SHA-1 | `7dd86e5e75c3359c5f93826565652e7064b66d88` |
| SHA-256 | `93aeb68e1d8d2de64418bcdb174aa15e50c8b1865e3c7a4051a654d2ec68fdd2` |
| SHA3-384 | `b8a1b835a5337be6ce3c3403226da2f9b737e929c8664b6f5a10a87ae43100d414bea3e4ab1b2bc1fc66ef2e452d4512` |
| TLSH | `T13EB319957CE3A196C2C3963EFB4F920933126297C3CE7512FD1D4A702F8A51B86B7981` |
| TELFHASH | `t1b0f0c041fd388a144ae27a70ec6803a585134613612287248f58c9d0cc3e00ab248d1d` |
| SSDEEP | `3072:/isLfOZU0DQCrfoK97mW5pF+h+9f+y4Hu1EssMZc/T03ImIys61X1h5ou:/iSOrDQCrfoK97m2Z9f+y4kEssMOgh5D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_93aeb68e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93aeb68e1d8d2de64418bcdb174aa15e50c8b1865e3c7a4051a654d2ec68fdd2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-27 08:24:23"
  condition:
    hash.sha256(0, filesize) == "93aeb68e1d8d2de64418bcdb174aa15e50c8b1865e3c7a4051a654d2ec68fdd2"
}
```

### Sample 77: `75b4691f77d5794b`

| Field | Value |
|---|---|
| SHA-256 | `75b4691f77d5794bdae516e93e7ed5afa148fab8d01c8e157b7d43db0d3ed7d0` |
| Family label | `Mirai` |
| File name | `bot.spc` |
| File type | `elf` |
| First seen | `2026-08-27 08:24:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12cf733b40741506b0870aa6b4df1aad` |
| SHA-1 | `5d7cb529d6d27e88f54af82645e856b785153208` |
| SHA-256 | `75b4691f77d5794bdae516e93e7ed5afa148fab8d01c8e157b7d43db0d3ed7d0` |
| SHA3-384 | `4ec1f3c7b9071910967e8146e90738ea24e691926bbef8144af0497b9573d1fb88761a0de6488b5c6fd48ac3f2b23a80` |
| TLSH | `T1C9A45C4852F1E3CFD1D4FA7523637A27A8B3073630EB7189799B5E5B637624001EAA70` |
| SSDEEP | `6144:mKMWGpETsX1h036sE6I7W7NslYEJwlLBJj8n:WEYXD0KII7+NwYEJYBJj8n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_75b4691f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75b4691f77d5794bdae516e93e7ed5afa148fab8d01c8e157b7d43db0d3ed7d0"
    family = "Mirai"
    file_name = "bot.spc"
    file_type = "elf"
    first_seen = "2026-08-27 08:24:22"
  condition:
    hash.sha256(0, filesize) == "75b4691f77d5794bdae516e93e7ed5afa148fab8d01c8e157b7d43db0d3ed7d0"
}
```

### Sample 78: `8c113660e1e250ac`

| Field | Value |
|---|---|
| SHA-256 | `8c113660e1e250aceb8d661f712a157a6e9402c62e71bfdc02a6a42aa1ad05e3` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-08-27 08:21:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c8b5d82823daf5841faff6a1eacc17b` |
| SHA-1 | `a4adabdc78f056731eb54528e204bf7336641012` |
| SHA-256 | `8c113660e1e250aceb8d661f712a157a6e9402c62e71bfdc02a6a42aa1ad05e3` |
| SHA3-384 | `4aad54c6915ec010e1fb5c370680e9d5f8ee04930ab9e93c6dc40d3786e3c18e19bcaf85f767ced220633e8e731929d1` |
| TLSH | `T15F942B4892F1E2EED198DA745315B83BAC71763A3067728A73DDFE33137726045ADA20` |
| TELFHASH | `t17281cf702895346075ca85117383d67ade3108f8d7ee72742f539db9eefbac14ca1826` |
| SSDEEP | `6144:KNVdeXJAr3WGDeSnedKw604K8fivi/INF2QuCzPa9Nfs:cVq/ZQKVU0XzPa9Nfs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_8c113660
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c113660e1e250aceb8d661f712a157a6e9402c62e71bfdc02a6a42aa1ad05e3"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-27 08:21:27"
  condition:
    hash.sha256(0, filesize) == "8c113660e1e250aceb8d661f712a157a6e9402c62e71bfdc02a6a42aa1ad05e3"
}
```

### Sample 79: `d5a7549fc34ee4f2`

| Field | Value |
|---|---|
| SHA-256 | `d5a7549fc34ee4f29b2094e6505198b2d3100067ee6c279fc91a52b76098b3b8` |
| Family label | `Mirai` |
| File name | `tarm6` |
| File type | `elf` |
| First seen | `2026-08-27 08:21:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d811940ab6fbecd2779726c5acbc2440` |
| SHA-1 | `3afd24fc9287c097bf5cece67e09b198c47dbcf8` |
| SHA-256 | `d5a7549fc34ee4f29b2094e6505198b2d3100067ee6c279fc91a52b76098b3b8` |
| SHA3-384 | `f4a2c290e903fd027b66e7742bc14ff12d98b6d3389b0132d0cd27b557fca4f7cbaa27a3806643c4f2990411723f3d73` |
| TLSH | `T169241957BA816A32C1C3033AFE4F014A73225BEBD3DA7A3E8D15977037878561E6A507` |
| TELFHASH | `t1480168a69f352da053c0845680bf7a1967fcb15d370604a2c4ac2b9ad823595f03d80a` |
| SSDEEP | `3072:SM1GMgQd7oxpw83BSmY5l5PgOJ3Kw4a0094WNL2y86x58fgsVnQH:z1Dloxpw8RSmY1PlJ3z4a9947yTcYvH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_d5a7549f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5a7549fc34ee4f29b2094e6505198b2d3100067ee6c279fc91a52b76098b3b8"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-08-27 08:21:25"
  condition:
    hash.sha256(0, filesize) == "d5a7549fc34ee4f29b2094e6505198b2d3100067ee6c279fc91a52b76098b3b8"
}
```

### Sample 80: `14acd118b614ca88`

| Field | Value |
|---|---|
| SHA-256 | `14acd118b614ca881426dc955f17a677ec3a2cf0e86f32469d94d2f35bce587f` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-08-27 08:21:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `febee88c456ceb1b76029f5174b0bc90` |
| SHA-1 | `a02260611b21091324af7020fcc989ff7130ff93` |
| SHA-256 | `14acd118b614ca881426dc955f17a677ec3a2cf0e86f32469d94d2f35bce587f` |
| SHA3-384 | `3702e470701c956fd3a0129efb907a3f24825d050d7023210708ceaf98f74b615b6ff52ea0dc21c0364af922c22cfa68` |
| TLSH | `T1A6C43A4D56B1DFADF268CB3043736D259A6613B332E3E185E05DE1221B6128E48AFF74` |
| TELFHASH | `t1a751e328097803b4a6616c5d48dcfb27d6e370df7e161c238e11d85aeb2ee835d24d1d` |
| SSDEEP | `6144:x08cMlQdMo+gKJPZhd8aEYbb7X3bbGKS+uJ0AnTdByGnGHzWJu5ra+4IQrIYQ:x09eVJP2BHKi7UzWJGQrIYQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_14acd118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14acd118b614ca881426dc955f17a677ec3a2cf0e86f32469d94d2f35bce587f"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-27 08:21:24"
  condition:
    hash.sha256(0, filesize) == "14acd118b614ca881426dc955f17a677ec3a2cf0e86f32469d94d2f35bce587f"
}
```

### Sample 81: `7bb403711e7e5d96`

| Field | Value |
|---|---|
| SHA-256 | `7bb403711e7e5d9633f7b6ef5104c390195df377e5c8e90fd35223fb39181021` |
| Family label | `XWorm` |
| File name | `FedEx Invoice 账单 [Account 511-64652372-202608].bat` |
| File type | `bat` |
| First seen | `2026-08-27 08:20:49` |
| Reporter | `abuse_ch` |
| Tags | `bat, FedEx, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `441c776b141293fae40f3415d58216a3` |
| SHA-1 | `4e10c4e1de2b05b7c7d4bb57099bab2dc0c74970` |
| SHA-256 | `7bb403711e7e5d9633f7b6ef5104c390195df377e5c8e90fd35223fb39181021` |
| SHA3-384 | `363828f9febecd54af03f794f4435422bedcac0c0b9b5454a64f81ac27848eb8da547922920def2fa352ce5065cbe12b` |
| TLSH | `T19C21659C0AC5230BD851C814DA0C5D86D6893BF066F1A9A4F187A8C26B127BF87B6D4C` |
| SSDEEP | `24:QZl1L9Uff5lf20DmHNkuN0l339a/vxVsfPv4IFa3w4Aw5kkVoI:01e20Kt30N390vIHQWaBrn` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_081_7bb40371
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bb403711e7e5d9633f7b6ef5104c390195df377e5c8e90fd35223fb39181021"
    family = "XWorm"
    file_name = "FedEx Invoice 账单 [Account 511-64652372-202608].bat"
    file_type = "bat"
    first_seen = "2026-08-27 08:20:49"
  condition:
    hash.sha256(0, filesize) == "7bb403711e7e5d9633f7b6ef5104c390195df377e5c8e90fd35223fb39181021"
}
```

### Sample 82: `4b00fed8f5c5a29d`

| Field | Value |
|---|---|
| SHA-256 | `4b00fed8f5c5a29d2b206f137583079c9184c5ad7cb4c7020d3747386cf25bf8` |
| Family label | `RemcosRAT` |
| File name | `RFQ-3L50050098CR807.bat` |
| File type | `bat` |
| First seen | `2026-08-27 08:20:42` |
| Reporter | `abuse_ch` |
| Tags | `bat, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85d610606d1630015db3438fcf49ffa9` |
| SHA-1 | `79fc398e944a0d0317e4cba034256d29ffe9548b` |
| SHA-256 | `4b00fed8f5c5a29d2b206f137583079c9184c5ad7cb4c7020d3747386cf25bf8` |
| SHA3-384 | `1d2fa42448f0ea888218af130d2a8222879acf53186f9434ef7d96376ed5683114bac1a7815734d582b875f29a00769d` |
| TLSH | `T1EC152354FB309C7424B615253A6AEABC734CE9D247E9E2CF7B1D39A9095DB33D802803` |
| SSDEEP | `24576:SZhHPft6CpzmcoU+AC+r+1RONEDbsRcmEEse3:Ao8CX9DbY` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_082_4b00fed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b00fed8f5c5a29d2b206f137583079c9184c5ad7cb4c7020d3747386cf25bf8"
    family = "RemcosRAT"
    file_name = "RFQ-3L50050098CR807.bat"
    file_type = "bat"
    first_seen = "2026-08-27 08:20:42"
  condition:
    hash.sha256(0, filesize) == "4b00fed8f5c5a29d2b206f137583079c9184c5ad7cb4c7020d3747386cf25bf8"
}
```

### Sample 83: `c34b1a67d817cc34`

| Field | Value |
|---|---|
| SHA-256 | `c34b1a67d817cc3446ef996ac97f84983f975b73a5f1a0553d59198dadd358c5` |
| Family label | `unknown` |
| File name | `Quotation for Churchway, 1-31 - B1948431 doc.js` |
| File type | `js` |
| First seen | `2026-08-27 08:20:34` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca86335a28765ea6ec5535105aaf235e` |
| SHA-1 | `6e6cfac34ea89c572ba97216a0ceefbd0d44d944` |
| SHA-256 | `c34b1a67d817cc3446ef996ac97f84983f975b73a5f1a0553d59198dadd358c5` |
| SHA3-384 | `8533dadafe11c21deb2e08087a361fd4ebf670c0f92b269fd4860274c1a75d4a0fba9207276f9b1a7a7829881f2df4e0` |
| TLSH | `T185D4E1786E43EDFE515FFB87C69B6E01683AF0CAC08F984D12C4A14173AB9215DADE14` |
| SSDEEP | `12288:LBOdDey8gvGCRw0gYpiwkyikXgtsu3gyeLVBBwFzvb5eLHoIhQ+1oYpIscF6HZ8:8dDey8gvGCRw0gYpOyddu3glV/25CHod` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_c34b1a67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34b1a67d817cc3446ef996ac97f84983f975b73a5f1a0553d59198dadd358c5"
    family = "unknown"
    file_name = "Quotation for Churchway, 1-31 - B1948431 doc.js"
    file_type = "js"
    first_seen = "2026-08-27 08:20:34"
  condition:
    hash.sha256(0, filesize) == "c34b1a67d817cc3446ef996ac97f84983f975b73a5f1a0553d59198dadd358c5"
}
```

### Sample 84: `8a1424629a8a5466`

| Field | Value |
|---|---|
| SHA-256 | `8a1424629a8a546617da9efb6a1be257b8976f2573b900a925f4395b9cae1cb7` |
| Family label | `STRRAT` |
| File name | `TEKLIF-FORMU.jar` |
| File type | `jar` |
| First seen | `2026-08-27 08:20:31` |
| Reporter | `abuse_ch` |
| Tags | `geo, jar, RAT, STRRAT, TUR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30c4b200c55a043b7f21c96cfea5114a` |
| SHA-1 | `f32e975c72363744f9b53f24baeeb5decd244818` |
| SHA-256 | `8a1424629a8a546617da9efb6a1be257b8976f2573b900a925f4395b9cae1cb7` |
| SHA3-384 | `881dd973c83eadc87790b97dc796919bb9f56f24f0c44ff5c8bfce117ace24aeeeef2a67741dd97b2d8e6ffa487675ac` |
| TLSH | `T1C7A3F904BF48D072D73360760A999219BB74E5EFD25579C70EF0ACADDCA9A000F96BC6` |
| SSDEEP | `1536:GOAoSsblJhyN0ZXots7WRrXRdnFrQSqqr0aqR1JdXHE2V5yql6v:GMSgy6xiyKrX7FhqUbq5NHEEwql6v` |

#### Technical Assessment

- The sample is tracked as `STRRAT` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_STRRAT_084_8a142462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a1424629a8a546617da9efb6a1be257b8976f2573b900a925f4395b9cae1cb7"
    family = "STRRAT"
    file_name = "TEKLIF-FORMU.jar"
    file_type = "jar"
    first_seen = "2026-08-27 08:20:31"
  condition:
    hash.sha256(0, filesize) == "8a1424629a8a546617da9efb6a1be257b8976f2573b900a925f4395b9cae1cb7"
}
```

### Sample 85: `b23f0a04c15b1b0a`

| Field | Value |
|---|---|
| SHA-256 | `b23f0a04c15b1b0a653468a53041019d8076cfe6b4b06fa7ace55dd6e9a9c45c` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-27 08:19:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a27a80db8a67ad72e84aff746cf053c` |
| SHA-1 | `91b31c3eb1535e8a785c6ebe809cceac66701388` |
| SHA-256 | `b23f0a04c15b1b0a653468a53041019d8076cfe6b4b06fa7ace55dd6e9a9c45c` |
| SHA3-384 | `e7adf7c63232e3bbeb0ede95d01b9bb94a8dbc4a6635be24a08778456d5684ad39554eb7224c00a1d497662251d086d5` |
| TLSH | `T12F44E8096FB21EF7E86BDD3B06E91606258C641722A83B35753CD618BF0A54F4AE3C74` |
| SSDEEP | `3072:UTCwHvHvNEAv6pLs02X6nO+nRqc7mB0mkkprw050yEKPu1EssMZc/T03ImIys618:uipIH+Tnww+0kpDREKsEssMOgh5oU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_b23f0a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23f0a04c15b1b0a653468a53041019d8076cfe6b4b06fa7ace55dd6e9a9c45c"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-27 08:19:37"
  condition:
    hash.sha256(0, filesize) == "b23f0a04c15b1b0a653468a53041019d8076cfe6b4b06fa7ace55dd6e9a9c45c"
}
```

### Sample 86: `f3c59bba59773c07`

| Field | Value |
|---|---|
| SHA-256 | `f3c59bba59773c07124f6a69ec0ed4a1a48508cec341ab24f92a7264507a6d15` |
| Family label | `XWorm` |
| File name | `RFQ-2026-08-26-000952.vbs` |
| File type | `vbs` |
| First seen | `2026-08-27 08:19:13` |
| Reporter | `abuse_ch` |
| Tags | `vbs, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ce084dd5c13865e26f2940083c36f7a` |
| SHA-1 | `39d8b730692baaa2f085dc81ba87058d13f9d9f3` |
| SHA-256 | `f3c59bba59773c07124f6a69ec0ed4a1a48508cec341ab24f92a7264507a6d15` |
| SHA3-384 | `ee75eded1ce0f1bae102908b49cba2bfed80c75f89894a39dbe4937bf3f77db6c42fb7e09b203f4bce9df7a75f95b7e4` |
| TLSH | `T103D4630861869A6D5670828FC4B672CBEF5C25DB3690C3BE0C7974EA3653D2DDB938C1` |
| SSDEEP | `1536:1QayV3X7a6a86j9RUt5Z8lQcVEBRhFJ4BqGFRm5:jY` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_086_f3c59bba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c59bba59773c07124f6a69ec0ed4a1a48508cec341ab24f92a7264507a6d15"
    family = "XWorm"
    file_name = "RFQ-2026-08-26-000952.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:13"
  condition:
    hash.sha256(0, filesize) == "f3c59bba59773c07124f6a69ec0ed4a1a48508cec341ab24f92a7264507a6d15"
}
```

### Sample 87: `38abdab6df0f8820`

| Field | Value |
|---|---|
| SHA-256 | `38abdab6df0f8820f392b6a2f906859fe92a43482f0717e1360291d2b3d84aaa` |
| Family label | `Formbook` |
| File name | `Company-Profile.vbe` |
| File type | `vbe` |
| First seen | `2026-08-27 08:19:10` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c6e4ac60de4210c78112f29582a73fa` |
| SHA-1 | `8da2b720c80c9badbef8fec4ac54f3a396e77c99` |
| SHA-256 | `38abdab6df0f8820f392b6a2f906859fe92a43482f0717e1360291d2b3d84aaa` |
| SHA3-384 | `371aac956097a8af6a579615c32ba48f8fae9a0f1fbe0e2bac9d347facfe3c236b25ffb9e4f1b53bfe5ec272d754d941` |
| TLSH | `T1C6632E70F06982931C16A840EC499970CAF8359A7BB617F9C2E49FF2CFED1C265E5781` |
| SSDEEP | `768:pzDBtFtyNAxM6m7yBx72mXvdc/Z7fgkYoL2ECWd0V4re/Y:9jyetVOSkf2err/` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_087_38abdab6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38abdab6df0f8820f392b6a2f906859fe92a43482f0717e1360291d2b3d84aaa"
    family = "Formbook"
    file_name = "Company-Profile.vbe"
    file_type = "vbe"
    first_seen = "2026-08-27 08:19:10"
  condition:
    hash.sha256(0, filesize) == "38abdab6df0f8820f392b6a2f906859fe92a43482f0717e1360291d2b3d84aaa"
}
```

### Sample 88: `0dfafc97bea52c09`

| Field | Value |
|---|---|
| SHA-256 | `0dfafc97bea52c0970fb5875f4c474909e1a5e7f860daae282a9fac0c253570c` |
| Family label | `XWorm` |
| File name | `inv-2026-06.PDF.vbs` |
| File type | `vbs` |
| First seen | `2026-08-27 08:19:08` |
| Reporter | `abuse_ch` |
| Tags | `vbs, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a61d2ba63202404bf26bfbc4a70906ea` |
| SHA-1 | `5f4fd990f3f2563e2c6e36ea4c3b82af77b0cd6c` |
| SHA-256 | `0dfafc97bea52c0970fb5875f4c474909e1a5e7f860daae282a9fac0c253570c` |
| SHA3-384 | `94cdd8ba4f8a94fd814a939b1f2172182c27b70c55b83946e2942d01090388fa9135fbaf4d024e47f612304db339e53e` |
| TLSH | `T15FD474EA658D910404F246AFD5147AE7DDBE85DB70C6EB8C6F0C32C61AA3D41279C2CB` |
| SSDEEP | `192:L9J7s9KzcVLpiJJJJJiJJJJJqK7fQhUHP9L1BIuSsMfB:L9VzcVLpiJJJJJiJJJJJqK7YhUFgbskB` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_088_0dfafc97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dfafc97bea52c0970fb5875f4c474909e1a5e7f860daae282a9fac0c253570c"
    family = "XWorm"
    file_name = "inv-2026-06.PDF.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:08"
  condition:
    hash.sha256(0, filesize) == "0dfafc97bea52c0970fb5875f4c474909e1a5e7f860daae282a9fac0c253570c"
}
```

### Sample 89: `9926a65e2307944a`

| Field | Value |
|---|---|
| SHA-256 | `9926a65e2307944a1432cb35ceab42acbdc2e7fbc23aa0eb390a3bce64da6116` |
| Family label | `RemcosRAT` |
| File name | `info_New_Order_7132026.vbs` |
| File type | `vbs` |
| First seen | `2026-08-27 08:19:05` |
| Reporter | `abuse_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5055c57f2d31e030ade9cb44a15dd2a` |
| SHA-1 | `1f222bb764da0b3849384c6c85b68803c9deca98` |
| SHA-256 | `9926a65e2307944a1432cb35ceab42acbdc2e7fbc23aa0eb390a3bce64da6116` |
| SHA3-384 | `d73557f770b6756c82c276f837d869721d86a010f6bfbe63e6cfce3d0a2c864278bea59ade8c0b2d1dd7b6bca0060005` |
| TLSH | `T1ACD495E2040D1569247225AF4A12F0D3E86E91F33AC2EF6E6C847DE9025BDBC47D64ED` |
| SSDEEP | `192:13cb2AtycKye+FnUAPAhWpNXyirnh049G7keLfSxyJgtbn:+2AthKeb649Zbbn` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_089_9926a65e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9926a65e2307944a1432cb35ceab42acbdc2e7fbc23aa0eb390a3bce64da6116"
    family = "RemcosRAT"
    file_name = "info_New_Order_7132026.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:05"
  condition:
    hash.sha256(0, filesize) == "9926a65e2307944a1432cb35ceab42acbdc2e7fbc23aa0eb390a3bce64da6116"
}
```

### Sample 90: `53cebec947fce207`

| Field | Value |
|---|---|
| SHA-256 | `53cebec947fce20730dcd94cab79b86caab58968e07ccfb55949f0310e38c252` |
| Family label | `AgentTesla` |
| File name | `Payment Receipt.vbs` |
| File type | `vbs` |
| First seen | `2026-08-27 08:19:02` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4d268b9fabab5f4485fd026d40ce30b` |
| SHA-1 | `ea457e3762fca241dccf93c992d7bfe28d7e2144` |
| SHA-256 | `53cebec947fce20730dcd94cab79b86caab58968e07ccfb55949f0310e38c252` |
| SHA3-384 | `443c5cf513f7e84183da7540a807cc8ba4a5e1f0a5b040c6e6a38fcbc9255f3b788e1c6c722954aa3cb58abf42dbb942` |
| TLSH | `T1BFD47615FD844C568438D17F8266BEE3C03D05DBB5A0D3BD5EA6B7C9A887D18A3A04EC` |
| SSDEEP | `1536:coL1RAQgkngM3AwMNViuwLgFZ5rVYFIMd8AMxMWMwMChV:53U5r/` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_090_53cebec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53cebec947fce20730dcd94cab79b86caab58968e07ccfb55949f0310e38c252"
    family = "AgentTesla"
    file_name = "Payment Receipt.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:02"
  condition:
    hash.sha256(0, filesize) == "53cebec947fce20730dcd94cab79b86caab58968e07ccfb55949f0310e38c252"
}
```

### Sample 91: `d32a7182a7dc9c21`

| Field | Value |
|---|---|
| SHA-256 | `d32a7182a7dc9c2170610201cc3833932e38705ca3beb6a5e8a73e62db0ce91a` |
| Family label | `XWorm` |
| File name | `Reckless Driver photos Cam7 August 27 2026.JS` |
| File type | `js` |
| First seen | `2026-08-27 08:18:57` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5431e42c5b801d58655ad42932c5f376` |
| SHA-1 | `363f8f432f90aff944409d5bc1296462df57afbe` |
| SHA-256 | `d32a7182a7dc9c2170610201cc3833932e38705ca3beb6a5e8a73e62db0ce91a` |
| SHA3-384 | `007eb4baca3c41aaaa8e73abb6b1c4aaf9123144c5ac846521d34e64b5de818c148140aaa2fa9b3c354a317f278bb85f` |
| TLSH | `T178F54E8E0341503B7D69E72FF1B65D26DA061987958AFF1AB03C42143BB5AD31338EE6` |
| SSDEEP | `98304:hh2CDAnwJwnD9FlE0MefXilETEhveAUfVdzDYfZDDzJCv:hh2CAawDh2ETEh2YfK` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_091_d32a7182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d32a7182a7dc9c2170610201cc3833932e38705ca3beb6a5e8a73e62db0ce91a"
    family = "XWorm"
    file_name = "Reckless Driver photos Cam7 August 27 2026.JS"
    file_type = "js"
    first_seen = "2026-08-27 08:18:57"
  condition:
    hash.sha256(0, filesize) == "d32a7182a7dc9c2170610201cc3833932e38705ca3beb6a5e8a73e62db0ce91a"
}
```

### Sample 92: `0cac9c838d12f485`

| Field | Value |
|---|---|
| SHA-256 | `0cac9c838d12f485099c3d67e7e4c3352a65c552e7f8c9c9a5822e679bacec16` |
| Family label | `XWorm` |
| File name | `INVOICE 30429-30423-30421.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:55` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5aecde30f64ba85c517b8b5988f982e` |
| SHA-1 | `3ed2c576e40e218281c88738f59dd3445a5b0e7b` |
| SHA-256 | `0cac9c838d12f485099c3d67e7e4c3352a65c552e7f8c9c9a5822e679bacec16` |
| SHA3-384 | `7ff1ad80c0819cbe2b13959fb6ee8cb2dd9bb112e9912eb7c69d1cdd6efe1f8a22e94e27dc5c3b2e925b63739cb95239` |
| TLSH | `T159D453A7001B5C8A83751288AF66632F5416093D16C0E299F78DCFABFED941FE74FA41` |
| SSDEEP | `192:/zzen7zN7FclYioKhPvT/KHJN70s752s75GHJN7Yq17JTy7Jc8DWojWR7A+7cum1:OuN+JCa2aqJ0bDdzumWx6Xg4Oeg4` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_092_0cac9c83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cac9c838d12f485099c3d67e7e4c3352a65c552e7f8c9c9a5822e679bacec16"
    family = "XWorm"
    file_name = "INVOICE 30429-30423-30421.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:55"
  condition:
    hash.sha256(0, filesize) == "0cac9c838d12f485099c3d67e7e4c3352a65c552e7f8c9c9a5822e679bacec16"
}
```

### Sample 93: `bb09baf5e11397e9`

| Field | Value |
|---|---|
| SHA-256 | `bb09baf5e11397e90c7ae384573ea7e7e2ba86da0f2a68325ab741519f6dc8f5` |
| Family label | `RemcosRAT` |
| File name | `AUGUST64_Maxima_International_Sourcing.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:53` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cf14f02d46c260783d3cdf75c92196a` |
| SHA-1 | `79aa93d1eec9b064d45d291689eee03dec45f1d6` |
| SHA-256 | `bb09baf5e11397e90c7ae384573ea7e7e2ba86da0f2a68325ab741519f6dc8f5` |
| SHA3-384 | `1032978d4e2d86a4f06f476de766f9e9c2db284a0a6aaba1ecb78cf76f1b1e46dc3eea2b55819b94584657c1a5ceb0fe` |
| TLSH | `T18C3512F81986CB622B1F273ED7678914153F06D2C88F884FAE5E73E61A7D46548E0F81` |
| SSDEEP | `24576:vfForI/tjOtUCanPpVZzY774U/4F2dtAA:XF7DiEWCA` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_093_bb09baf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb09baf5e11397e90c7ae384573ea7e7e2ba86da0f2a68325ab741519f6dc8f5"
    family = "RemcosRAT"
    file_name = "AUGUST64_Maxima_International_Sourcing.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:53"
  condition:
    hash.sha256(0, filesize) == "bb09baf5e11397e90c7ae384573ea7e7e2ba86da0f2a68325ab741519f6dc8f5"
}
```

### Sample 94: `4727cb5c0619c876`

| Field | Value |
|---|---|
| SHA-256 | `4727cb5c0619c8769b506df5a4420a18b91b7f3b7ef31c8c7d6fd0a1196ee5a2` |
| Family label | `Formbook` |
| File name | `HSBC PAYMENT RECEIPT MT103.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:45` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, HSBC, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28d6bba51defd18d6dfa717a3aedd23a` |
| SHA-1 | `750fc500f96a95ce8f5b8e757237da6481f49322` |
| SHA-256 | `4727cb5c0619c8769b506df5a4420a18b91b7f3b7ef31c8c7d6fd0a1196ee5a2` |
| SHA3-384 | `e5220341fa599368a5bc05d4fd5901208d2252efe3b75082833afae11bc31f3ba29536f236cbf815588d0d2185b57457` |
| TLSH | `T12BC4232167FE5109F2F3AF54AEF825A58D7EBEA66E36D05C1150024E0A72E80DDB0737` |
| SSDEEP | `6144:v4Mq2rmEzLc8NvR0w0KKhoWMvDdnqILuxNHr:v5q2rZLc8N50wf8oW0ZqILAZ` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_094_4727cb5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4727cb5c0619c8769b506df5a4420a18b91b7f3b7ef31c8c7d6fd0a1196ee5a2"
    family = "Formbook"
    file_name = "HSBC PAYMENT RECEIPT MT103.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:45"
  condition:
    hash.sha256(0, filesize) == "4727cb5c0619c8769b506df5a4420a18b91b7f3b7ef31c8c7d6fd0a1196ee5a2"
}
```

### Sample 95: `dda071fac63aadd6`

| Field | Value |
|---|---|
| SHA-256 | `dda071fac63aadd6a4c11379cfda3d7cb83174c6f498bb3a9789f4001c17fa42` |
| Family label | `XWorm` |
| File name | `Invoice No.1FVO12026001543.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:44` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9047d699e31baf667ea7d9756aa8e539` |
| SHA-1 | `5a11085cb3c67c439d6edac58e7605a983bb556c` |
| SHA-256 | `dda071fac63aadd6a4c11379cfda3d7cb83174c6f498bb3a9789f4001c17fa42` |
| SHA3-384 | `8a5714106fd3cc547121f74dc3fa4069666ace578928b085eb3ff87fb49582b9b268d3a9ca1fd2e15f4875e9491b4416` |
| TLSH | `T131D463FBE0498CFCCB7F30AA5B59A32B9469846D5375D7A2F348C75884C0A8E530E746` |
| SSDEEP | `192:jzztNKkTNaQLcRQTYQYLaCG2AchazZmnRh3hBqmMchazZ7CazZF+US6TBU1KkcBC:yQ+3` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_095_dda071fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dda071fac63aadd6a4c11379cfda3d7cb83174c6f498bb3a9789f4001c17fa42"
    family = "XWorm"
    file_name = "Invoice No.1FVO12026001543.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:44"
  condition:
    hash.sha256(0, filesize) == "dda071fac63aadd6a4c11379cfda3d7cb83174c6f498bb3a9789f4001c17fa42"
}
```

### Sample 96: `c23188eda65518d8`

| Field | Value |
|---|---|
| SHA-256 | `c23188eda65518d89b84d5c64c068a36a75a9580ce67051fd5b424bf433e0881` |
| Family label | `RemcosRAT` |
| File name | `FedEx AWB_no 530526.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:42` |
| Reporter | `abuse_ch` |
| Tags | `FedEx, js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc5c45c454b6749b5df2fbab8b0e843d` |
| SHA-1 | `b0e36399370535cf9a773cd5e22c5e00ee395391` |
| SHA-256 | `c23188eda65518d89b84d5c64c068a36a75a9580ce67051fd5b424bf433e0881` |
| SHA3-384 | `42a7ef547dabdc0f958792eefaa6e0f25376f4bfa001feba72dcabf1c8859861fe4f984de9aa5382456d87e6eae1c080` |
| TLSH | `T1AC975E7E4FEF6FA9E48E1D8851C55583CDC1B4094DFB290BB1270C0AEA5E79068B8F61` |
| SSDEEP | `384:KG8XWDrOLkLMBRLcB4km4cKvSCe42RQ0fMaSuaOmbyru+vFkretJWSkvlIHmr7GD:5cl6Z9Cy0FzL` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_096_c23188ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23188eda65518d89b84d5c64c068a36a75a9580ce67051fd5b424bf433e0881"
    family = "RemcosRAT"
    file_name = "FedEx AWB_no 530526.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:42"
  condition:
    hash.sha256(0, filesize) == "c23188eda65518d89b84d5c64c068a36a75a9580ce67051fd5b424bf433e0881"
}
```

### Sample 97: `b8bb7578b0be7d0b`

| Field | Value |
|---|---|
| SHA-256 | `b8bb7578b0be7d0bdbe652d0452753d2a48f36b4c134d71006ad6512fa64d337` |
| Family label | `Formbook` |
| File name | `Order-ref27082607.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:25` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49de2934811c19c57733586c4596fabd` |
| SHA-1 | `d2b93f698331d49146fba4c015aff569e38120f9` |
| SHA-256 | `b8bb7578b0be7d0bdbe652d0452753d2a48f36b4c134d71006ad6512fa64d337` |
| SHA3-384 | `97bb1847983b5a1ec344d030d4689162ca8cc33edbff1fb3590bc2bf7bc845000c8a8eb7f1294d90e2fcebf0a845972b` |
| TLSH | `T1070453046993255143373FBFA32ED8D0E76617A70484091BF5FCA8A05FF1D0AEAE9879` |
| SSDEEP | `3072:IZbHkxqwOk9vtZukHdC9A0/JDHaIUvr+bL30vmhRz9miXn8O5wIFz:Mk9vtckHdC9A0/JDH4vr+bL30sJ9mi3j` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_097_b8bb7578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bb7578b0be7d0bdbe652d0452753d2a48f36b4c134d71006ad6512fa64d337"
    family = "Formbook"
    file_name = "Order-ref27082607.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:25"
  condition:
    hash.sha256(0, filesize) == "b8bb7578b0be7d0bdbe652d0452753d2a48f36b4c134d71006ad6512fa64d337"
}
```

### Sample 98: `7382055280697248`

| Field | Value |
|---|---|
| SHA-256 | `73820552806972480f1f9a38cae3212395106b4ae8dc6f96777151511cf9d936` |
| Family label | `RemcosRAT` |
| File name | `SOA.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:21` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f99c8909936e74fd8c0170d9d1a352b` |
| SHA-1 | `324fa94494a6974794f35f2e4a84bca347e94a26` |
| SHA-256 | `73820552806972480f1f9a38cae3212395106b4ae8dc6f96777151511cf9d936` |
| SHA3-384 | `0ccc70b542b1f01bdea73369857d4de2bd8c1b6d14f9a593db2c468e8aacc3c92c1ee1e1c7a9623acb93277a5535db5c` |
| TLSH | `T15F36E7D7369F294B1F15B70DA09E1D668F5AC9304BC4EAD8B1EB0A94061F44E6AC0DCF` |
| SSDEEP | `49152:pI5AaHSh/scOdkxt6Jfb/V0C0nmWGEBYGEPm3/OyrzDE+PNm7uB1K1F+Aex2LpM4:W` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_098_73820552
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73820552806972480f1f9a38cae3212395106b4ae8dc6f96777151511cf9d936"
    family = "RemcosRAT"
    file_name = "SOA.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:21"
  condition:
    hash.sha256(0, filesize) == "73820552806972480f1f9a38cae3212395106b4ae8dc6f96777151511cf9d936"
}
```

### Sample 99: `c917b69a47f36c55`

| Field | Value |
|---|---|
| SHA-256 | `c917b69a47f36c55daf7c41f3d722b9a279763d3d6920a24f9cb53d0d1103e99` |
| Family label | `XWorm` |
| File name | `SCAN COPY AUGUST 2702026.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:12` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `082239c2516880ab460df52026c50529` |
| SHA-1 | `8edcd70d50281d8d25591c240774b215adbba3f3` |
| SHA-256 | `c917b69a47f36c55daf7c41f3d722b9a279763d3d6920a24f9cb53d0d1103e99` |
| SHA3-384 | `16789b440a27503d3e51d0f62c7f84eef312b702b4f6653fe5e9b5ee167faf8d6def06b95653df00f24d01c9c051dec0` |
| TLSH | `T1F594CF8E5BF1599DE9826DF82D1FB343B0E4AED2989D8E9067D6C70B34894C2CD702D1` |
| SSDEEP | `12288:xwbvyGG7rgf36drwEY/P/CJoE2EhtTRxEPTE4L1:x6yGYgf36drwEY/PKqE2EhtTTWTE4L1` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_099_c917b69a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c917b69a47f36c55daf7c41f3d722b9a279763d3d6920a24f9cb53d0d1103e99"
    family = "XWorm"
    file_name = "SCAN COPY AUGUST 2702026.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:12"
  condition:
    hash.sha256(0, filesize) == "c917b69a47f36c55daf7c41f3d722b9a279763d3d6920a24f9cb53d0d1103e99"
}
```

### Sample 100: `92ed9e1345402798`

| Field | Value |
|---|---|
| SHA-256 | `92ed9e1345402798ed6f05fd6da1f97fa121a217decd5e453533772cbd86d4b7` |
| Family label | `Formbook` |
| File name | `Customs.js` |
| File type | `js` |
| First seen | `2026-08-27 08:18:07` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e9a80c9da521bce587a27bdcfb9cc10` |
| SHA-1 | `ce175f8a05660fdcd1a31b7ae6843d4521df036e` |
| SHA-256 | `92ed9e1345402798ed6f05fd6da1f97fa121a217decd5e453533772cbd86d4b7` |
| SHA3-384 | `04b404d0384cf3944d9a035cbe633be39a71a5b8095a8b52ed27173275608b0022ad6b7a473cc6667335cbd5d517c951` |
| TLSH | `T138E5F8B073FFBE076D0573A8914D2E540EA9804809DBB9C4F4EF16D40A4F59F68C5AAE` |
| SSDEEP | `24576:zJuHRrCEy65k5ZgBSTkyZic7+doyHavws837e7oFcZH/xku:zuc` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_100_92ed9e13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ed9e1345402798ed6f05fd6da1f97fa121a217decd5e453533772cbd86d4b7"
    family = "Formbook"
    file_name = "Customs.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:07"
  condition:
    hash.sha256(0, filesize) == "92ed9e1345402798ed6f05fd6da1f97fa121a217decd5e453533772cbd86d4b7"
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
 * Generated: 2026-08-27T09:58:09.229148+00:00
 */

rule MalwareBazaar_unknown_001_b8d63bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8d63bcb195fa116a1e6aa80ae02521860d7c91699e1e44e9a6f24bcfdac8515"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-08-27 09:56:38"
  condition:
    hash.sha256(0, filesize) == "b8d63bcb195fa116a1e6aa80ae02521860d7c91699e1e44e9a6f24bcfdac8515"
}

rule MalwareBazaar_unknown_002_33928548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703"
    family = "unknown"
    file_name = "lul.mpsl"
    file_type = "elf"
    first_seen = "2026-08-27 09:54:36"
  condition:
    hash.sha256(0, filesize) == "339285484b60a51ae06e6e8d59cf177d5fda512f49eb38aaf8ef9b10e3b55703"
}

rule MalwareBazaar_Mirai_003_a5842fab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5842fabc581ddd4ae938b8b9acc01a2a5dc77b852cfe77267d51116f84ba1e5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-27 09:44:46"
  condition:
    hash.sha256(0, filesize) == "a5842fabc581ddd4ae938b8b9acc01a2a5dc77b852cfe77267d51116f84ba1e5"
}

rule MalwareBazaar_unknown_004_a5c1403a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5c1403a73d8b5c78ce1bb397e09c4c8b7bc7edd82eb747e001a113a21a1919d"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-27 09:44:44"
  condition:
    hash.sha256(0, filesize) == "a5c1403a73d8b5c78ce1bb397e09c4c8b7bc7edd82eb747e001a113a21a1919d"
}

rule MalwareBazaar_unknown_005_4ec985c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ec985c55d0a56a361fc9f7d3469afde4b8938d0eb34435ef10436802b0e4273"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-08-27 09:40:42"
  condition:
    hash.sha256(0, filesize) == "4ec985c55d0a56a361fc9f7d3469afde4b8938d0eb34435ef10436802b0e4273"
}

rule MalwareBazaar_Mirai_006_ba567960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba567960aa8e9d81527a32d17df715b6e6aa381f7f54ef0258fa7611727c4c27"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-08-27 09:40:41"
  condition:
    hash.sha256(0, filesize) == "ba567960aa8e9d81527a32d17df715b6e6aa381f7f54ef0258fa7611727c4c27"
}

rule MalwareBazaar_Mirai_007_f0b516e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0b516e70d8ee2bd08037407bdae1f4a33648d6ba88ee4f39df37b530d16228a"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-08-27 09:38:34"
  condition:
    hash.sha256(0, filesize) == "f0b516e70d8ee2bd08037407bdae1f4a33648d6ba88ee4f39df37b530d16228a"
}

rule MalwareBazaar_unknown_008_98fd5c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98fd5c1d2cd1c220bc2c1869bfe84828b9f2df659dff1132a1f9f84628244454"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-27 09:34:31"
  condition:
    hash.sha256(0, filesize) == "98fd5c1d2cd1c220bc2c1869bfe84828b9f2df659dff1132a1f9f84628244454"
}

rule MalwareBazaar_Mirai_009_53ad3b3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53ad3b3ba81cfb1b96d8c1e2c92fb3ee7fb693d92144c786ad29df41e8298a88"
    family = "Mirai"
    file_name = "lul.arm6"
    file_type = "elf"
    first_seen = "2026-08-27 09:31:02"
  condition:
    hash.sha256(0, filesize) == "53ad3b3ba81cfb1b96d8c1e2c92fb3ee7fb693d92144c786ad29df41e8298a88"
}

rule MalwareBazaar_unknown_010_dbf045cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf045cd17f860bc5692c145c0a84930992749543c4dfb67c0d26565944e0de6"
    family = "unknown"
    file_name = "nvr"
    file_type = "unknown"
    first_seen = "2026-08-27 09:30:38"
  condition:
    hash.sha256(0, filesize) == "dbf045cd17f860bc5692c145c0a84930992749543c4dfb67c0d26565944e0de6"
}

rule MalwareBazaar_RemcosRAT_011_6e4ba98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e4ba98eec21415df3855ef1ff7620af209c3b31a991dc8f8f87b6d3546af8e9"
    family = "RemcosRAT"
    file_name = "PurchaseOrderpdf.JS.js"
    file_type = "js"
    first_seen = "2026-08-27 09:30:13"
  condition:
    hash.sha256(0, filesize) == "6e4ba98eec21415df3855ef1ff7620af209c3b31a991dc8f8f87b6d3546af8e9"
}

rule MalwareBazaar_unknown_012_b38ce797
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38ce79773881df169bfc6cfdaa105270c5bcb2c9c4509a6454a1d1f50f1a641"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-27 09:27:33"
  condition:
    hash.sha256(0, filesize) == "b38ce79773881df169bfc6cfdaa105270c5bcb2c9c4509a6454a1d1f50f1a641"
}

rule MalwareBazaar_unknown_013_f1d8ccf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260"
    family = "unknown"
    file_name = "f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260.exe"
    file_type = "exe"
    first_seen = "2026-08-27 09:21:01"
  condition:
    hash.sha256(0, filesize) == "f1d8ccf9d1d0944b90cf07c5f085dac72a84cf9c1d56efb5cdc47606106fa260"
}

rule MalwareBazaar_unknown_014_44708c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44708c993a9ae48e7290f6217fa5b40876d102d91ae0102a1556063044791456"
    family = "unknown"
    file_name = "dlr.mips"
    file_type = "elf"
    first_seen = "2026-08-27 09:20:35"
  condition:
    hash.sha256(0, filesize) == "44708c993a9ae48e7290f6217fa5b40876d102d91ae0102a1556063044791456"
}

rule MalwareBazaar_Mirai_015_1d7a148e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d7a148e3f597c2c32aed9727de0c2bf0f0462418d1c1edb5c5603754b7a162a"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-08-27 09:20:34"
  condition:
    hash.sha256(0, filesize) == "1d7a148e3f597c2c32aed9727de0c2bf0f0462418d1c1edb5c5603754b7a162a"
}

rule MalwareBazaar_unknown_016_a6458820
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6458820cefd26db2ffa682f2b7a42877dff2c5d2e647993a0678928b2192f49"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-08-27 09:18:33"
  condition:
    hash.sha256(0, filesize) == "a6458820cefd26db2ffa682f2b7a42877dff2c5d2e647993a0678928b2192f49"
}

rule MalwareBazaar_WannaCry_017_6f0f3928
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455"
    family = "WannaCry"
    file_name = "6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455"
    file_type = "exe"
    first_seen = "2026-08-27 09:15:35"
  condition:
    hash.sha256(0, filesize) == "6f0f3928fa60d3d51e7fa1cedc94df4ec0b41d7ab5b9c7488715020f6b294455"
}

rule MalwareBazaar_unknown_018_847067d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847067d6d55130c927a4fb8ee948cde9090214e6bd8c47be3c8fa8d93992302f"
    family = "unknown"
    file_name = "dlr.arm"
    file_type = "elf"
    first_seen = "2026-08-27 09:14:58"
  condition:
    hash.sha256(0, filesize) == "847067d6d55130c927a4fb8ee948cde9090214e6bd8c47be3c8fa8d93992302f"
}

rule MalwareBazaar_Mirai_019_07bfd97e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07bfd97e419f739258c04c8bc976ae6add8bd2936c97471642a759b0b6cc115b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-27 09:13:30"
  condition:
    hash.sha256(0, filesize) == "07bfd97e419f739258c04c8bc976ae6add8bd2936c97471642a759b0b6cc115b"
}

rule MalwareBazaar_Vidar_020_f954e919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08"
    family = "Vidar"
    file_name = "f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08.bin"
    file_type = "exe"
    first_seen = "2026-08-27 09:12:19"
  condition:
    hash.sha256(0, filesize) == "f954e919fc4b906fb7349cb7c4b3136486b60a6845208ba086e502ddb5077b08"
}

rule MalwareBazaar_Gafgyt_021_3702adbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3702adbc131fd77738189af8c6fb3c2f89c8ac65c1499e06fde55b7df0bf9689"
    family = "Gafgyt"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-27 09:11:35"
  condition:
    hash.sha256(0, filesize) == "3702adbc131fd77738189af8c6fb3c2f89c8ac65c1499e06fde55b7df0bf9689"
}

rule MalwareBazaar_unknown_022_56c2e73c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c"
    family = "unknown"
    file_name = "56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c.elf"
    file_type = "elf"
    first_seen = "2026-08-27 09:06:03"
  condition:
    hash.sha256(0, filesize) == "56c2e73c1f6e68d3ab347f46c9db1ebf948bd0891cf3fd28ebf04479cec0796c"
}

rule MalwareBazaar_Mirai_023_c681b78a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f"
    family = "Mirai"
    file_name = "c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f.elf"
    file_type = "elf"
    first_seen = "2026-08-27 09:05:57"
  condition:
    hash.sha256(0, filesize) == "c681b78a2922dae0d3c49919b80d23b34343ba9463303d5f53ec16ec4e2cf24f"
}

rule MalwareBazaar_RemcosRAT_024_05fe60e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05fe60e021bffcac2ae463fc54c9df400b6d231c1721515909af05d226d52a75"
    family = "RemcosRAT"
    file_name = "nxs64.exe"
    file_type = "exe"
    first_seen = "2026-08-27 09:05:10"
  condition:
    hash.sha256(0, filesize) == "05fe60e021bffcac2ae463fc54c9df400b6d231c1721515909af05d226d52a75"
}

rule MalwareBazaar_Mirai_025_d9fec308
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9fec308fa96892c7a6515f87a503c326a87dfac10ae30d62c1b2941eef67382"
    family = "Mirai"
    file_name = "tarm7"
    file_type = "elf"
    first_seen = "2026-08-27 09:04:42"
  condition:
    hash.sha256(0, filesize) == "d9fec308fa96892c7a6515f87a503c326a87dfac10ae30d62c1b2941eef67382"
}

rule MalwareBazaar_unknown_026_3c877d36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c877d369e9c087edcc49a932daa12bc0c72a4ccda9395d74cd2d51402146d50"
    family = "unknown"
    file_name = "lul.mips"
    file_type = "elf"
    first_seen = "2026-08-27 09:04:41"
  condition:
    hash.sha256(0, filesize) == "3c877d369e9c087edcc49a932daa12bc0c72a4ccda9395d74cd2d51402146d50"
}

rule MalwareBazaar_Stealc_027_3af1c096
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3af1c09640d195f2dfc3dd708c2ce421ed3256f8345cea934fed5c52a3eb5eff"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-27 09:04:35"
  condition:
    hash.sha256(0, filesize) == "3af1c09640d195f2dfc3dd708c2ce421ed3256f8345cea934fed5c52a3eb5eff"
}

rule MalwareBazaar_unknown_028_e6258f41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6258f41f0ab79b38cbb3ae6f6e6a6d31e3f5168a40b895d5a6503c85fdd2b1b"
    family = "unknown"
    file_name = "tftp"
    file_type = "elf"
    first_seen = "2026-08-27 09:02:56"
  condition:
    hash.sha256(0, filesize) == "e6258f41f0ab79b38cbb3ae6f6e6a6d31e3f5168a40b895d5a6503c85fdd2b1b"
}

rule MalwareBazaar_Mirai_029_4064808f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-27 09:00:37"
  condition:
    hash.sha256(0, filesize) == "4064808f7c2b34bf48c0e241db75038a0e0c49db59b794cfe7205a5fdd70c436"
}

rule MalwareBazaar_unknown_030_4fa7a5c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d"
    family = "unknown"
    file_name = "4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d"
    file_type = "elf"
    first_seen = "2026-08-27 09:00:23"
  condition:
    hash.sha256(0, filesize) == "4fa7a5c77c6d7497aefa8ac5dbcee56cef607607e6a0253867c2b2b5deb3ec8d"
}

rule MalwareBazaar_unknown_031_47c5c730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47c5c730f29520a7429f49cb669e58ac8972e202e3aff821357b7ef01941199d"
    family = "unknown"
    file_name = "install_q0.3.15.exe"
    file_type = "exe"
    first_seen = "2026-08-27 09:00:03"
  condition:
    hash.sha256(0, filesize) == "47c5c730f29520a7429f49cb669e58ac8972e202e3aff821357b7ef01941199d"
}

rule MalwareBazaar_unknown_032_8c6822cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c6822cbec742c64706a31b83dc29640de0006b5dc122c7a1c8194f9fa4251ff"
    family = "unknown"
    file_name = "install_q0.3.14.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:59:20"
  condition:
    hash.sha256(0, filesize) == "8c6822cbec742c64706a31b83dc29640de0006b5dc122c7a1c8194f9fa4251ff"
}

rule MalwareBazaar_Mirai_033_5b06f021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b06f021a79b2b5349aa31168685ec3df415c3fea1522ead0675a970af76d389"
    family = "Mirai"
    file_name = "bot.i686"
    file_type = "elf"
    first_seen = "2026-08-27 08:57:28"
  condition:
    hash.sha256(0, filesize) == "5b06f021a79b2b5349aa31168685ec3df415c3fea1522ead0675a970af76d389"
}

rule MalwareBazaar_Mirai_034_2e1a4992
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd"
    family = "Mirai"
    file_name = "2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd.elf"
    file_type = "elf"
    first_seen = "2026-08-27 08:56:20"
  condition:
    hash.sha256(0, filesize) == "2e1a4992721af0409240d92d8fd1e7c8009ff7b098562129a010bf338ad9e7dd"
}

rule MalwareBazaar_Mirai_035_864aa577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f"
    family = "Mirai"
    file_name = "864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f.elf"
    file_type = "elf"
    first_seen = "2026-08-27 08:56:16"
  condition:
    hash.sha256(0, filesize) == "864aa577c952927f68600c59d06b762797c08fffe019d8d42dd522dca978159f"
}

rule MalwareBazaar_Mirai_036_1c0f770f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c0f770f8881dc22eb411ab4064f8075309bed6f691aea0ab478c6f7a9c45b2f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-27 08:55:57"
  condition:
    hash.sha256(0, filesize) == "1c0f770f8881dc22eb411ab4064f8075309bed6f691aea0ab478c6f7a9c45b2f"
}

rule MalwareBazaar_njrat_037_368fda9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "368fda9d9000cba7a307239fac2fdebfd1088a54a6ac6fccaaf65afb30056cb3"
    family = "njrat"
    file_name = "RFQ-SW10-321313.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:55:08"
  condition:
    hash.sha256(0, filesize) == "368fda9d9000cba7a307239fac2fdebfd1088a54a6ac6fccaaf65afb30056cb3"
}

rule MalwareBazaar_Mirai_038_9b81ca9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b81ca9f2247f4dd515ebd4b524251f4e933dc2ac78d9e30efec6e438aadc017"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-08-27 08:54:27"
  condition:
    hash.sha256(0, filesize) == "9b81ca9f2247f4dd515ebd4b524251f4e933dc2ac78d9e30efec6e438aadc017"
}

rule MalwareBazaar_PureLogsStealer_039_53802a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1"
    family = "PureLogsStealer"
    file_name = "53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:53:35"
  condition:
    hash.sha256(0, filesize) == "53802a0417b92993ecb62b94c224c1a297b57cdf171dfac69e792aba0c2be4c1"
}

rule MalwareBazaar_Vidar_040_4c09df60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91"
    family = "Vidar"
    file_name = "4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91.bin"
    file_type = "exe"
    first_seen = "2026-08-27 08:53:29"
  condition:
    hash.sha256(0, filesize) == "4c09df605465682b1ec5c4fd0961dc8ca57f633594703f7e0538ccc9c6042e91"
}

rule MalwareBazaar_Mirai_041_571d566e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "571d566ed46b4a4f262d65646266995871185d1c536d721ce5d1c537c2eb176b"
    family = "Mirai"
    file_name = "bot.arm6"
    file_type = "elf"
    first_seen = "2026-08-27 08:52:52"
  condition:
    hash.sha256(0, filesize) == "571d566ed46b4a4f262d65646266995871185d1c536d721ce5d1c537c2eb176b"
}

rule MalwareBazaar_Mirai_042_a9688636
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a96886369a460e7fe167518836a5c59226901a469968bd320cab08788dbb6205"
    family = "Mirai"
    file_name = "bot.arm7"
    file_type = "elf"
    first_seen = "2026-08-27 08:48:27"
  condition:
    hash.sha256(0, filesize) == "a96886369a460e7fe167518836a5c59226901a469968bd320cab08788dbb6205"
}

rule MalwareBazaar_Mirai_043_7e1bf180
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e1bf180eb4aaa01be1a199c5f3df34ef856b9edc8dce1971fa45678b1117d3f"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-27 08:48:26"
  condition:
    hash.sha256(0, filesize) == "7e1bf180eb4aaa01be1a199c5f3df34ef856b9edc8dce1971fa45678b1117d3f"
}

rule MalwareBazaar_RemcosRAT_044_1be4ef70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1be4ef70585595235b1f6b4890552228382101ba41226661aa6a86585e5fc458"
    family = "RemcosRAT"
    file_name = "RFQ-PEDSB-BAN-LLA-2026-054-SERVICE ORDER TCs & Appendix 12.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:45:21"
  condition:
    hash.sha256(0, filesize) == "1be4ef70585595235b1f6b4890552228382101ba41226661aa6a86585e5fc458"
}

rule MalwareBazaar_STRRAT_045_1c40688f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c40688fb64c0a7cb58be42c58bfcbb6cfc93d51da6d561bb75a32de19bf25dc"
    family = "STRRAT"
    file_name = "Request For Quotation.js"
    file_type = "js"
    first_seen = "2026-08-27 08:45:05"
  condition:
    hash.sha256(0, filesize) == "1c40688fb64c0a7cb58be42c58bfcbb6cfc93d51da6d561bb75a32de19bf25dc"
}

rule MalwareBazaar_unknown_046_010b2a74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "010b2a747d23c92924be656e387d69d171fa0cbf91ad53e4875fe22add8a8cac"
    family = "unknown"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-08-27 08:43:28"
  condition:
    hash.sha256(0, filesize) == "010b2a747d23c92924be656e387d69d171fa0cbf91ad53e4875fe22add8a8cac"
}

rule MalwareBazaar_Mirai_047_9bb9171e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bb9171ef0c05583e8c432e46a217912722abf8e344913f25bc36bb9a4a94802"
    family = "Mirai"
    file_name = "lul.arm5"
    file_type = "elf"
    first_seen = "2026-08-27 08:43:26"
  condition:
    hash.sha256(0, filesize) == "9bb9171ef0c05583e8c432e46a217912722abf8e344913f25bc36bb9a4a94802"
}

rule MalwareBazaar_Formbook_048_56e1d6be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56e1d6bef47aedb3ee373b17fd0af4c634931db7e78c00e4c82c223f61b68987"
    family = "Formbook"
    file_name = "HOTLINE TRADING EST SOA.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:41:51"
  condition:
    hash.sha256(0, filesize) == "56e1d6bef47aedb3ee373b17fd0af4c634931db7e78c00e4c82c223f61b68987"
}

rule MalwareBazaar_Mirai_049_267eff80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "267eff803a45eac04ef5b9967b0ce90ada762f302308a3e82009086a06a66e67"
    family = "Mirai"
    file_name = "bot.mpsl"
    file_type = "elf"
    first_seen = "2026-08-27 08:41:32"
  condition:
    hash.sha256(0, filesize) == "267eff803a45eac04ef5b9967b0ce90ada762f302308a3e82009086a06a66e67"
}

rule MalwareBazaar_ValleyRAT_050_9ba9080b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ba9080b517997bf8324ede2f4fc11579cc30a519efe6ffe48a036a7e41c2315"
    family = "ValleyRAT"
    file_name = "F1E9B63F2FA2D63ACC8AE3E6680D7E70.dll"
    file_type = "dll"
    first_seen = "2026-08-27 08:40:20"
  condition:
    hash.sha256(0, filesize) == "9ba9080b517997bf8324ede2f4fc11579cc30a519efe6ffe48a036a7e41c2315"
}

rule MalwareBazaar_njrat_051_d1303941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1303941d2d3f6d1337f74fb0ec07984614d4bad8bb76143fe89a285b9dbeaaf"
    family = "njrat"
    file_name = "RFQ-SW10-321313.PDF.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:40:07"
  condition:
    hash.sha256(0, filesize) == "d1303941d2d3f6d1337f74fb0ec07984614d4bad8bb76143fe89a285b9dbeaaf"
}

rule MalwareBazaar_unknown_052_64bf0e2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bf0e2bfdaacf3dc81ce6c339907992eebf5876e64841dce2ad73d539960578"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-27 08:36:37"
  condition:
    hash.sha256(0, filesize) == "64bf0e2bfdaacf3dc81ce6c339907992eebf5876e64841dce2ad73d539960578"
}

rule MalwareBazaar_unknown_053_ab8011dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab8011dca996781f1d1bd0fae166d255c0c27464f35b637902b71ac1c3a8cf9f"
    family = "unknown"
    file_name = "ad9acc19c36e3e921e43074ec3b09304.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:39"
  condition:
    hash.sha256(0, filesize) == "ab8011dca996781f1d1bd0fae166d255c0c27464f35b637902b71ac1c3a8cf9f"
}

rule MalwareBazaar_SheetRAT_054_c5ecdd41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5ecdd414e5a4a9ce1dac9fd9bdac433de80b66de3d0aff47abe784706fbb02a"
    family = "SheetRAT"
    file_name = "1035735f7d18175e23e1181434648494.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:33"
  condition:
    hash.sha256(0, filesize) == "c5ecdd414e5a4a9ce1dac9fd9bdac433de80b66de3d0aff47abe784706fbb02a"
}

rule MalwareBazaar_SheetRAT_055_8413753d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8413753dd6b3c68aade5c95450cd68b52bf448d827210e0385203e102b5926ad"
    family = "SheetRAT"
    file_name = "01203720869a8f590601cc3d639b9984.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:23"
  condition:
    hash.sha256(0, filesize) == "8413753dd6b3c68aade5c95450cd68b52bf448d827210e0385203e102b5926ad"
}

rule MalwareBazaar_SheetRAT_056_22a6a1c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22a6a1c861c0d3bd6df621455c14adb9f0aac24ebf1ef6739131fc6e8ec696bf"
    family = "SheetRAT"
    file_name = "743979767b321025dd464b0f7070b8ff.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:15"
  condition:
    hash.sha256(0, filesize) == "22a6a1c861c0d3bd6df621455c14adb9f0aac24ebf1ef6739131fc6e8ec696bf"
}

rule MalwareBazaar_ValleyRAT_057_e110c3d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e110c3d90f63af79053e1a50229b311a39f1b12420e6962e767179a918628523"
    family = "ValleyRAT"
    file_name = "DFB400A13708E6F9771F2A02100E3B32.dll"
    file_type = "dll"
    first_seen = "2026-08-27 08:35:14"
  condition:
    hash.sha256(0, filesize) == "e110c3d90f63af79053e1a50229b311a39f1b12420e6962e767179a918628523"
}

rule MalwareBazaar_unknown_058_bc73e28f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc73e28fca0988fea8ef3460890ee16049842d9829403eedc63661e01bb09447"
    family = "unknown"
    file_name = "7bbe43387cfe0e00dafd61ea63904c6d.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:35:05"
  condition:
    hash.sha256(0, filesize) == "bc73e28fca0988fea8ef3460890ee16049842d9829403eedc63661e01bb09447"
}

rule MalwareBazaar_XWorm_059_fb95d7d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb95d7d6d256e0d1e492ebcb02b12776996a2887f54a6f4a54155c2729a40273"
    family = "XWorm"
    file_name = "a8ccf7af26ae2a2e221b224822e5a639.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:54"
  condition:
    hash.sha256(0, filesize) == "fb95d7d6d256e0d1e492ebcb02b12776996a2887f54a6f4a54155c2729a40273"
}

rule MalwareBazaar_SheetRAT_060_15aeb01c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15aeb01ceb8079f16fa83a6d8c5d44c04c590f474c6c95e96e4e31df9786725d"
    family = "SheetRAT"
    file_name = "071a9e42a3118c4becbd671529dc2f06.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:47"
  condition:
    hash.sha256(0, filesize) == "15aeb01ceb8079f16fa83a6d8c5d44c04c590f474c6c95e96e4e31df9786725d"
}

rule MalwareBazaar_unknown_061_ae90f9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae90f9af53f315122f31021f664f686a66dd77a08fcf560fad3d373c0ac5eabd"
    family = "unknown"
    file_name = "106032e5fe69908d00017874faca1976.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:38"
  condition:
    hash.sha256(0, filesize) == "ae90f9af53f315122f31021f664f686a66dd77a08fcf560fad3d373c0ac5eabd"
}

rule MalwareBazaar_SheetRAT_062_935a8987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "935a89876a469292f4b238c7ad9d1ad6387519a5f1b486d37559579936430eff"
    family = "SheetRAT"
    file_name = "0bb278acc41500c6831112bdf1b2b2aa.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:16"
  condition:
    hash.sha256(0, filesize) == "935a89876a469292f4b238c7ad9d1ad6387519a5f1b486d37559579936430eff"
}

rule MalwareBazaar_unknown_063_3511c86c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3511c86c901db8d494eea0e1bea6d398cc60e5aadba713f549da0ba3f5c2505a"
    family = "unknown"
    file_name = "3fee630d3e005c84a3983903386b17cc.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:34:06"
  condition:
    hash.sha256(0, filesize) == "3511c86c901db8d494eea0e1bea6d398cc60e5aadba713f549da0ba3f5c2505a"
}

rule MalwareBazaar_unknown_064_39e5a1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39e5a1bb3b057fa6bf3e2aa2961763cb48bef578648e754c1cf52da7ddd2a2d8"
    family = "unknown"
    file_name = "53deb2d9fbbabdb94d6dc198bd8124c0.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:52"
  condition:
    hash.sha256(0, filesize) == "39e5a1bb3b057fa6bf3e2aa2961763cb48bef578648e754c1cf52da7ddd2a2d8"
}

rule MalwareBazaar_SheetRAT_065_e2c22911
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2c22911a38748cfdd480415c255d50bd75edeb66978806362349621de308310"
    family = "SheetRAT"
    file_name = "7513d77e95e15f4d6b69308ae01036e5.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:45"
  condition:
    hash.sha256(0, filesize) == "e2c22911a38748cfdd480415c255d50bd75edeb66978806362349621de308310"
}

rule MalwareBazaar_unknown_066_19ab76f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19ab76f2fd893f174ff8505c0439dde8e4fabf7b2c72360209675294204783aa"
    family = "unknown"
    file_name = "b315891c9c02a85a30b7ae6eec4d9e9e.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:33"
  condition:
    hash.sha256(0, filesize) == "19ab76f2fd893f174ff8505c0439dde8e4fabf7b2c72360209675294204783aa"
}

rule MalwareBazaar_SheetRAT_067_d6279667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6279667f28724ed2b35b8c0bbd13121e0a1f5f929669cee16b7945c6039eb1f"
    family = "SheetRAT"
    file_name = "1008cc67abe5358a99e749fe35ad825b.exe"
    file_type = "exe"
    first_seen = "2026-08-27 08:33:28"
  condition:
    hash.sha256(0, filesize) == "d6279667f28724ed2b35b8c0bbd13121e0a1f5f929669cee16b7945c6039eb1f"
}

rule MalwareBazaar_unknown_068_57db4faf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4"
    family = "unknown"
    file_name = "57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4.bin"
    file_type = "unknown"
    first_seen = "2026-08-27 08:30:51"
  condition:
    hash.sha256(0, filesize) == "57db4fafacc617d43558e63cbdc602e37c59dcfe35d88205062966c76ad603c4"
}

rule MalwareBazaar_Mirai_069_5561504e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5561504ee4b04bf194c8d7f9c18d0cf00a9dcf948dfe91b2e489195eb3283608"
    family = "Mirai"
    file_name = "bot.arc"
    file_type = "elf"
    first_seen = "2026-08-27 08:30:26"
  condition:
    hash.sha256(0, filesize) == "5561504ee4b04bf194c8d7f9c18d0cf00a9dcf948dfe91b2e489195eb3283608"
}

rule MalwareBazaar_Mirai_070_076a9a73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "076a9a73dc1b2f8053c3cb7a44da7031a55694f844282f79b30094f0848c2dc1"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-27 08:28:42"
  condition:
    hash.sha256(0, filesize) == "076a9a73dc1b2f8053c3cb7a44da7031a55694f844282f79b30094f0848c2dc1"
}

rule MalwareBazaar_unknown_071_f2d8eec7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2d8eec71f2ac36975cd7b2f3a5f8a6eee1d11812f2e3a4e6e41812084a6657d"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-27 08:28:40"
  condition:
    hash.sha256(0, filesize) == "f2d8eec71f2ac36975cd7b2f3a5f8a6eee1d11812f2e3a4e6e41812084a6657d"
}

rule MalwareBazaar_unknown_072_bde14c63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde14c634f785ba4b7d31e6565cf9a57458633ce1645c560a5a7f006359081f9"
    family = "unknown"
    file_name = "FedEx_AWB_.zip"
    file_type = "zip"
    first_seen = "2026-08-27 08:28:27"
  condition:
    hash.sha256(0, filesize) == "bde14c634f785ba4b7d31e6565cf9a57458633ce1645c560a5a7f006359081f9"
}

rule MalwareBazaar_Vidar_073_9bbbe31c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e"
    family = "Vidar"
    file_name = "9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e.bin"
    file_type = "exe"
    first_seen = "2026-08-27 08:27:56"
  condition:
    hash.sha256(0, filesize) == "9bbbe31c2684dfca8a3c4abcb062833602580cf7f78a1fb0e3ea9607d037447e"
}

rule MalwareBazaar_unknown_074_3d16deb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d16deb2bf2c8917d508fca5480dbe555ba68a88fd7ef8d4f4c23d74f0d03e03"
    family = "unknown"
    file_name = "221036299-043825-sanlccjavap0004-6531.pdf.z"
    file_type = "z"
    first_seen = "2026-08-27 08:27:33"
  condition:
    hash.sha256(0, filesize) == "3d16deb2bf2c8917d508fca5480dbe555ba68a88fd7ef8d4f4c23d74f0d03e03"
}

rule MalwareBazaar_Mirai_075_81051b2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81051b2e58fe4e4d53b5bea904151af33d44ed72603c2aeffbba6520af40861e"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-08-27 08:25:48"
  condition:
    hash.sha256(0, filesize) == "81051b2e58fe4e4d53b5bea904151af33d44ed72603c2aeffbba6520af40861e"
}

rule MalwareBazaar_Mirai_076_93aeb68e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93aeb68e1d8d2de64418bcdb174aa15e50c8b1865e3c7a4051a654d2ec68fdd2"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-08-27 08:24:23"
  condition:
    hash.sha256(0, filesize) == "93aeb68e1d8d2de64418bcdb174aa15e50c8b1865e3c7a4051a654d2ec68fdd2"
}

rule MalwareBazaar_Mirai_077_75b4691f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75b4691f77d5794bdae516e93e7ed5afa148fab8d01c8e157b7d43db0d3ed7d0"
    family = "Mirai"
    file_name = "bot.spc"
    file_type = "elf"
    first_seen = "2026-08-27 08:24:22"
  condition:
    hash.sha256(0, filesize) == "75b4691f77d5794bdae516e93e7ed5afa148fab8d01c8e157b7d43db0d3ed7d0"
}

rule MalwareBazaar_Mirai_078_8c113660
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c113660e1e250aceb8d661f712a157a6e9402c62e71bfdc02a6a42aa1ad05e3"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-08-27 08:21:27"
  condition:
    hash.sha256(0, filesize) == "8c113660e1e250aceb8d661f712a157a6e9402c62e71bfdc02a6a42aa1ad05e3"
}

rule MalwareBazaar_Mirai_079_d5a7549f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5a7549fc34ee4f29b2094e6505198b2d3100067ee6c279fc91a52b76098b3b8"
    family = "Mirai"
    file_name = "tarm6"
    file_type = "elf"
    first_seen = "2026-08-27 08:21:25"
  condition:
    hash.sha256(0, filesize) == "d5a7549fc34ee4f29b2094e6505198b2d3100067ee6c279fc91a52b76098b3b8"
}

rule MalwareBazaar_Mirai_080_14acd118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14acd118b614ca881426dc955f17a677ec3a2cf0e86f32469d94d2f35bce587f"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-08-27 08:21:24"
  condition:
    hash.sha256(0, filesize) == "14acd118b614ca881426dc955f17a677ec3a2cf0e86f32469d94d2f35bce587f"
}

rule MalwareBazaar_XWorm_081_7bb40371
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bb403711e7e5d9633f7b6ef5104c390195df377e5c8e90fd35223fb39181021"
    family = "XWorm"
    file_name = "FedEx Invoice 账单 [Account 511-64652372-202608].bat"
    file_type = "bat"
    first_seen = "2026-08-27 08:20:49"
  condition:
    hash.sha256(0, filesize) == "7bb403711e7e5d9633f7b6ef5104c390195df377e5c8e90fd35223fb39181021"
}

rule MalwareBazaar_RemcosRAT_082_4b00fed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b00fed8f5c5a29d2b206f137583079c9184c5ad7cb4c7020d3747386cf25bf8"
    family = "RemcosRAT"
    file_name = "RFQ-3L50050098CR807.bat"
    file_type = "bat"
    first_seen = "2026-08-27 08:20:42"
  condition:
    hash.sha256(0, filesize) == "4b00fed8f5c5a29d2b206f137583079c9184c5ad7cb4c7020d3747386cf25bf8"
}

rule MalwareBazaar_unknown_083_c34b1a67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34b1a67d817cc3446ef996ac97f84983f975b73a5f1a0553d59198dadd358c5"
    family = "unknown"
    file_name = "Quotation for Churchway, 1-31 - B1948431 doc.js"
    file_type = "js"
    first_seen = "2026-08-27 08:20:34"
  condition:
    hash.sha256(0, filesize) == "c34b1a67d817cc3446ef996ac97f84983f975b73a5f1a0553d59198dadd358c5"
}

rule MalwareBazaar_STRRAT_084_8a142462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a1424629a8a546617da9efb6a1be257b8976f2573b900a925f4395b9cae1cb7"
    family = "STRRAT"
    file_name = "TEKLIF-FORMU.jar"
    file_type = "jar"
    first_seen = "2026-08-27 08:20:31"
  condition:
    hash.sha256(0, filesize) == "8a1424629a8a546617da9efb6a1be257b8976f2573b900a925f4395b9cae1cb7"
}

rule MalwareBazaar_Mirai_085_b23f0a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b23f0a04c15b1b0a653468a53041019d8076cfe6b4b06fa7ace55dd6e9a9c45c"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-27 08:19:37"
  condition:
    hash.sha256(0, filesize) == "b23f0a04c15b1b0a653468a53041019d8076cfe6b4b06fa7ace55dd6e9a9c45c"
}

rule MalwareBazaar_XWorm_086_f3c59bba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c59bba59773c07124f6a69ec0ed4a1a48508cec341ab24f92a7264507a6d15"
    family = "XWorm"
    file_name = "RFQ-2026-08-26-000952.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:13"
  condition:
    hash.sha256(0, filesize) == "f3c59bba59773c07124f6a69ec0ed4a1a48508cec341ab24f92a7264507a6d15"
}

rule MalwareBazaar_Formbook_087_38abdab6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38abdab6df0f8820f392b6a2f906859fe92a43482f0717e1360291d2b3d84aaa"
    family = "Formbook"
    file_name = "Company-Profile.vbe"
    file_type = "vbe"
    first_seen = "2026-08-27 08:19:10"
  condition:
    hash.sha256(0, filesize) == "38abdab6df0f8820f392b6a2f906859fe92a43482f0717e1360291d2b3d84aaa"
}

rule MalwareBazaar_XWorm_088_0dfafc97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dfafc97bea52c0970fb5875f4c474909e1a5e7f860daae282a9fac0c253570c"
    family = "XWorm"
    file_name = "inv-2026-06.PDF.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:08"
  condition:
    hash.sha256(0, filesize) == "0dfafc97bea52c0970fb5875f4c474909e1a5e7f860daae282a9fac0c253570c"
}

rule MalwareBazaar_RemcosRAT_089_9926a65e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9926a65e2307944a1432cb35ceab42acbdc2e7fbc23aa0eb390a3bce64da6116"
    family = "RemcosRAT"
    file_name = "info_New_Order_7132026.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:05"
  condition:
    hash.sha256(0, filesize) == "9926a65e2307944a1432cb35ceab42acbdc2e7fbc23aa0eb390a3bce64da6116"
}

rule MalwareBazaar_AgentTesla_090_53cebec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53cebec947fce20730dcd94cab79b86caab58968e07ccfb55949f0310e38c252"
    family = "AgentTesla"
    file_name = "Payment Receipt.vbs"
    file_type = "vbs"
    first_seen = "2026-08-27 08:19:02"
  condition:
    hash.sha256(0, filesize) == "53cebec947fce20730dcd94cab79b86caab58968e07ccfb55949f0310e38c252"
}

rule MalwareBazaar_XWorm_091_d32a7182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d32a7182a7dc9c2170610201cc3833932e38705ca3beb6a5e8a73e62db0ce91a"
    family = "XWorm"
    file_name = "Reckless Driver photos Cam7 August 27 2026.JS"
    file_type = "js"
    first_seen = "2026-08-27 08:18:57"
  condition:
    hash.sha256(0, filesize) == "d32a7182a7dc9c2170610201cc3833932e38705ca3beb6a5e8a73e62db0ce91a"
}

rule MalwareBazaar_XWorm_092_0cac9c83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cac9c838d12f485099c3d67e7e4c3352a65c552e7f8c9c9a5822e679bacec16"
    family = "XWorm"
    file_name = "INVOICE 30429-30423-30421.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:55"
  condition:
    hash.sha256(0, filesize) == "0cac9c838d12f485099c3d67e7e4c3352a65c552e7f8c9c9a5822e679bacec16"
}

rule MalwareBazaar_RemcosRAT_093_bb09baf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb09baf5e11397e90c7ae384573ea7e7e2ba86da0f2a68325ab741519f6dc8f5"
    family = "RemcosRAT"
    file_name = "AUGUST64_Maxima_International_Sourcing.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:53"
  condition:
    hash.sha256(0, filesize) == "bb09baf5e11397e90c7ae384573ea7e7e2ba86da0f2a68325ab741519f6dc8f5"
}

rule MalwareBazaar_Formbook_094_4727cb5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4727cb5c0619c8769b506df5a4420a18b91b7f3b7ef31c8c7d6fd0a1196ee5a2"
    family = "Formbook"
    file_name = "HSBC PAYMENT RECEIPT MT103.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:45"
  condition:
    hash.sha256(0, filesize) == "4727cb5c0619c8769b506df5a4420a18b91b7f3b7ef31c8c7d6fd0a1196ee5a2"
}

rule MalwareBazaar_XWorm_095_dda071fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dda071fac63aadd6a4c11379cfda3d7cb83174c6f498bb3a9789f4001c17fa42"
    family = "XWorm"
    file_name = "Invoice No.1FVO12026001543.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:44"
  condition:
    hash.sha256(0, filesize) == "dda071fac63aadd6a4c11379cfda3d7cb83174c6f498bb3a9789f4001c17fa42"
}

rule MalwareBazaar_RemcosRAT_096_c23188ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23188eda65518d89b84d5c64c068a36a75a9580ce67051fd5b424bf433e0881"
    family = "RemcosRAT"
    file_name = "FedEx AWB_no 530526.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:42"
  condition:
    hash.sha256(0, filesize) == "c23188eda65518d89b84d5c64c068a36a75a9580ce67051fd5b424bf433e0881"
}

rule MalwareBazaar_Formbook_097_b8bb7578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bb7578b0be7d0bdbe652d0452753d2a48f36b4c134d71006ad6512fa64d337"
    family = "Formbook"
    file_name = "Order-ref27082607.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:25"
  condition:
    hash.sha256(0, filesize) == "b8bb7578b0be7d0bdbe652d0452753d2a48f36b4c134d71006ad6512fa64d337"
}

rule MalwareBazaar_RemcosRAT_098_73820552
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73820552806972480f1f9a38cae3212395106b4ae8dc6f96777151511cf9d936"
    family = "RemcosRAT"
    file_name = "SOA.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:21"
  condition:
    hash.sha256(0, filesize) == "73820552806972480f1f9a38cae3212395106b4ae8dc6f96777151511cf9d936"
}

rule MalwareBazaar_XWorm_099_c917b69a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c917b69a47f36c55daf7c41f3d722b9a279763d3d6920a24f9cb53d0d1103e99"
    family = "XWorm"
    file_name = "SCAN COPY AUGUST 2702026.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:12"
  condition:
    hash.sha256(0, filesize) == "c917b69a47f36c55daf7c41f3d722b9a279763d3d6920a24f9cb53d0d1103e99"
}

rule MalwareBazaar_Formbook_100_92ed9e13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ed9e1345402798ed6f05fd6da1f97fa121a217decd5e453533772cbd86d4b7"
    family = "Formbook"
    file_name = "Customs.js"
    file_type = "js"
    first_seen = "2026-08-27 08:18:07"
  condition:
    hash.sha256(0, filesize) == "92ed9e1345402798ed6f05fd6da1f97fa121a217decd5e453533772cbd86d4b7"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

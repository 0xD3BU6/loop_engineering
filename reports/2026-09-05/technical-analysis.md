# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-05

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 649 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 649 |
| Unique family labels | 11 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 44 |
| Mirai | 23 |
| Formbook | 12 |
| Gafgyt | 10 |
| Vidar | 3 |
| AgentTesla | 3 |
| CoinMiner | 1 |
| Loki | 1 |
| MassLogger | 1 |
| SnakeKeylogger | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 43 |
| elf | 36 |
| sh | 13 |
| unknown | 6 |
| ps1 | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `6877dea3a0f91bfe`

| Field | Value |
|---|---|
| SHA-256 | `6877dea3a0f91bfe2c0271f70d53517bc740c51018260bf2eb255bc7882187f8` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-05 04:27:24` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a022594216e15030cce3729ca6db8a9` |
| SHA-256 | `6877dea3a0f91bfe2c0271f70d53517bc740c51018260bf2eb255bc7882187f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_6877dea3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6877dea3a0f91bfe2c0271f70d53517bc740c51018260bf2eb255bc7882187f8"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-05 04:27:24"
  condition:
    hash.sha256(0, filesize) == "6877dea3a0f91bfe2c0271f70d53517bc740c51018260bf2eb255bc7882187f8"
}
```

### Sample 2: `a08f7292a5ed30dd`

| Field | Value |
|---|---|
| SHA-256 | `a08f7292a5ed30ddd0b4447f1c5aeab1a84b254bad852e872f8f35109cc0fdc0` |
| Family label | `Mirai` |
| File name | `reaver.mpsl` |
| File type | `elf` |
| First seen | `2026-09-05 04:06:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a20ebbd198ccd8985ccf76fb32524d5e` |
| SHA-1 | `d518d5aa546d4336f3f6f8ce1bdc18dcef8cd39b` |
| SHA-256 | `a08f7292a5ed30ddd0b4447f1c5aeab1a84b254bad852e872f8f35109cc0fdc0` |
| SHA3-384 | `d34fc9b7285a2ed88c92c17f51c338b8b1d79d05cc8b162b895a9b9c823b0c52810847b3e2b19a5bc0b6a5db7c88e198` |
| TLSH | `T1DB34B40A7B205EF7E85BCD370AF95B06208CB41721A93B767634EA5CBA1658F09D3C74` |
| SSDEEP | `3072:w0Jzia8aYpXdt0DVqo8fR4YcSjkGL9PhQHFZz7S+y/VMHZS:pdia8amXdt0DVqo8fsaL9PYjzty/Vu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_a08f7292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a08f7292a5ed30ddd0b4447f1c5aeab1a84b254bad852e872f8f35109cc0fdc0"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-05 04:06:23"
  condition:
    hash.sha256(0, filesize) == "a08f7292a5ed30ddd0b4447f1c5aeab1a84b254bad852e872f8f35109cc0fdc0"
}
```

### Sample 3: `cbae88f84ac1629c`

| Field | Value |
|---|---|
| SHA-256 | `cbae88f84ac1629c5fc5fbb19763c9b67f4a9ba1accbbe2530998581c325e2df` |
| Family label | `Mirai` |
| File name | `reaver.mpsl` |
| File type | `elf` |
| First seen | `2026-09-05 04:05:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0772123729ca90d9f004b3685e8e271d` |
| SHA-1 | `31eaaae5d34de0ef6cb74b076cdcf8582987c635` |
| SHA-256 | `cbae88f84ac1629c5fc5fbb19763c9b67f4a9ba1accbbe2530998581c325e2df` |
| SHA3-384 | `ebbdd50053800be72901343618b6587b47f565813f34020d3b6db9163ee303b649c2d6aed64fa6f404491b7e8a36c37c` |
| TLSH | `T12D73027FAF48AE4AC2687CB954901317B199CFD01269E747EC808DD9EB2FF8E254449C` |
| SSDEEP | `1536:SvkmrNmTg7TlJIpUr904i+MtZNQX0TaffxPJ+gFEiJH4ws7Qz/:Svk5yInSX0YjjEiJkc7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_cbae88f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbae88f84ac1629c5fc5fbb19763c9b67f4a9ba1accbbe2530998581c325e2df"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-05 04:05:27"
  condition:
    hash.sha256(0, filesize) == "cbae88f84ac1629c5fc5fbb19763c9b67f4a9ba1accbbe2530998581c325e2df"
}
```

### Sample 4: `d155403501f66f00`

| Field | Value |
|---|---|
| SHA-256 | `d155403501f66f0064a7c0876b266ff1a3425f85582f732df7e419ef5b2b3423` |
| Family label | `unknown` |
| File name | `poop` |
| File type | `elf` |
| First seen | `2026-09-05 03:58:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7b6a0464b673b4eda61e0b28db2b44d` |
| SHA-1 | `7d7ec3960fe3acfa4633509b23447f298245cf4c` |
| SHA-256 | `d155403501f66f0064a7c0876b266ff1a3425f85582f732df7e419ef5b2b3423` |
| SHA3-384 | `fbc1b5719dba0e6a7cf4c36a087cf2c44597109d339d9458dd3b1d8cc5c5943a75395cb325e00890ed1e7cdbe36ee060` |
| TLSH | `T129553364F7E8F158FE3A7CBD08B45834682D788937EFDFB2C8A0651815A6E06874E51C` |
| SSDEEP | `24576:8xjYKXhddU2aABFkxaU1D6tFrGQhl4PRecoNy53r8Nioi5+AWk6dlehnxP2o1IyL:8+KxdmybkoU1DgFlNcCyNf0eHPmm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_d1554035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d155403501f66f0064a7c0876b266ff1a3425f85582f732df7e419ef5b2b3423"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-05 03:58:42"
  condition:
    hash.sha256(0, filesize) == "d155403501f66f0064a7c0876b266ff1a3425f85582f732df7e419ef5b2b3423"
}
```

### Sample 5: `53306b5aadd16a12`

| Field | Value |
|---|---|
| SHA-256 | `53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14` |
| Family label | `Vidar` |
| File name | `53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14.bin` |
| File type | `exe` |
| First seen | `2026-09-05 03:52:25` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fce50591630237cdeaba54bbc8498a5b` |
| SHA-1 | `d662d17d3ba856b1243d87ba280745732828a4dd` |
| SHA-256 | `53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14` |
| SHA3-384 | `60b3ae8a830591abe398cf39ba02b367b42222fa7f080dd7ae54e8316731a7eb7e78a5c4473840e1bafbb8cf41b9fb1e` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T195183307785506F0E89A9F34C0BB9313A629B8CDDB3A32931D5166782F7ABC17DB6710` |
| SSDEEP | `1572864:oykLofgsWRJZV5sCPdYthDl3HxaXti7koJhHZzv12d6Y2LbF4lGndbaBZzNZGd:ioffy7mMQh3kti7vHZp2d6BR4Adba3z2` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_005_53306b5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14"
    family = "Vidar"
    file_name = "53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14.bin"
    file_type = "exe"
    first_seen = "2026-09-05 03:52:25"
  condition:
    hash.sha256(0, filesize) == "53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14"
}
```

### Sample 6: `40cb6cd334578a3a`

| Field | Value |
|---|---|
| SHA-256 | `40cb6cd334578a3a3f5569a5928fdae1ba4ee4bad1cdcb46c026a30b6af692eb` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-05 03:51:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `859d519bc02dcb22dfcbe34a932b45f2` |
| SHA-1 | `371e8ce6d9d485190a143dfa5535aa165ead931d` |
| SHA-256 | `40cb6cd334578a3a3f5569a5928fdae1ba4ee4bad1cdcb46c026a30b6af692eb` |
| SHA3-384 | `bac0cddf46e2cd16a3fe7d8dad7c20df33bda6ce2b15132fe15e0b4e722c3bb0955b7c9af97cea0d1351d30035581320` |
| TLSH | `T16A310B9E05105A310443CE8E73B23148B28EE2EF1C9FD3D4DD494DAA92493DCF262B99` |
| SSDEEP | `12:U86OZpBsV6seANaci6D86D63NA6NX9OS6zk8lsDSs6SM9ThlaQ5m6aQ58RPDE36g:3hciYnsGk8lsWuM9a2k2wwFjcVuhBv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_40cb6cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40cb6cd334578a3a3f5569a5928fdae1ba4ee4bad1cdcb46c026a30b6af692eb"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-05 03:51:22"
  condition:
    hash.sha256(0, filesize) == "40cb6cd334578a3a3f5569a5928fdae1ba4ee4bad1cdcb46c026a30b6af692eb"
}
```

### Sample 7: `86c09b9ec3f944f4`

| Field | Value |
|---|---|
| SHA-256 | `86c09b9ec3f944f4d29e89554da7434a54fa79c48eab2099cc5401d17c745d7e` |
| Family label | `Mirai` |
| File name | `reaver.x86_64` |
| File type | `elf` |
| First seen | `2026-09-05 03:45:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `066baaea28e4fec9d17bc8b9f73c83f0` |
| SHA-1 | `cc8cb6afea392f4a57e9c4f8bcbf741cab5eaac4` |
| SHA-256 | `86c09b9ec3f944f4d29e89554da7434a54fa79c48eab2099cc5401d17c745d7e` |
| SHA3-384 | `3816cc6c215c71ee6f810cb06b7a2859e457f6b6e839bf93253b6a1d342a1e7e899508836c5c636d557d20817b392274` |
| TLSH | `T1B1E35A0379C1C9FEC483E2B44BFF9636C921F92E1535B14E73A47E963E1DE906A19260` |
| TELFHASH | `t10351b9602c9d3a5831db5786b38ede1af8b204911da574559d2b6ee9cd463840df30e3` |
| SSDEEP | `3072:37sNd3sJ+aZMml57UR3VrP7YKJaS2f7ctyZcQf+DtsC9vv1EsPzYV8l:rsNtsVZMmWgKv90chKsPzxl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_86c09b9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c09b9ec3f944f4d29e89554da7434a54fa79c48eab2099cc5401d17c745d7e"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-05 03:45:27"
  condition:
    hash.sha256(0, filesize) == "86c09b9ec3f944f4d29e89554da7434a54fa79c48eab2099cc5401d17c745d7e"
}
```

### Sample 8: `57eac56730e3d0a6`

| Field | Value |
|---|---|
| SHA-256 | `57eac56730e3d0a6e9e67ce5c59be3afd800277f62dc6b2e6d001d7d19d5897e` |
| Family label | `Mirai` |
| File name | `reaver.arm5` |
| File type | `elf` |
| First seen | `2026-09-05 03:45:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80e4d36047007d0c87619cdb1b8f0d9f` |
| SHA-1 | `5f9c5f24fed81943b658eacb6f0e7150cac0c7d1` |
| SHA-256 | `57eac56730e3d0a6e9e67ce5c59be3afd800277f62dc6b2e6d001d7d19d5897e` |
| SHA3-384 | `e6e5b05f64b0eecf0f867ec05517d4b10ae43162fe8d3761e0384a2b58c193f04d3a357ef6a30e53f47ad05d24210e40` |
| TLSH | `T1ABF30856BD429E13C6C316B7FB9F8289371677A8D7EE3103ED246F60378A4AB0D26111` |
| TELFHASH | `t14ad012365d0d05f9b7100fc5dba453546895956b4102c869aee9ccb55c536c6fc6a013` |
| SSDEEP | `3072:+xNtgr9XE2+C2mEdX/xf7UmpPCi2KbmPDeEjyYxyl2w5tIzyvto27APN7Hez6:kg62+C2mEdX/J7UmpPl2KbsDeEjpxyla` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_57eac567
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57eac56730e3d0a6e9e67ce5c59be3afd800277f62dc6b2e6d001d7d19d5897e"
    family = "Mirai"
    file_name = "reaver.arm5"
    file_type = "elf"
    first_seen = "2026-09-05 03:45:24"
  condition:
    hash.sha256(0, filesize) == "57eac56730e3d0a6e9e67ce5c59be3afd800277f62dc6b2e6d001d7d19d5897e"
}
```

### Sample 9: `52d7100937af1772`

| Field | Value |
|---|---|
| SHA-256 | `52d7100937af1772189f62cdc1699143607f13cf1a25bc525f224751a38e6f46` |
| Family label | `Mirai` |
| File name | `reaver.x86_64` |
| File type | `elf` |
| First seen | `2026-09-05 03:45:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a2377f3b30b5673e260c2a47742b251` |
| SHA-1 | `03c0b69997bc8def92326d57bfb4bfd24b4c3b95` |
| SHA-256 | `52d7100937af1772189f62cdc1699143607f13cf1a25bc525f224751a38e6f46` |
| SHA3-384 | `fdf28b6ac11abe2299bea5c11aaeb631efa19ff2a3e457d69b636558c84a1bd83a77d71d676071ad54a7ddcba8df1731` |
| TLSH | `T1626302B0062EFAA5ED32C3B7F1881195B960ED7B52B6525E8CF07063CC99F509B446F2` |
| SSDEEP | `1536:LTPq0tMsnCOB/OME540MavC6bOP0gRvrGImvIel:Hq0tMsn39Ovv3bs00vrGImvIel` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_52d71009
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d7100937af1772189f62cdc1699143607f13cf1a25bc525f224751a38e6f46"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-05 03:45:22"
  condition:
    hash.sha256(0, filesize) == "52d7100937af1772189f62cdc1699143607f13cf1a25bc525f224751a38e6f46"
}
```

### Sample 10: `2ed6a04833ebe399`

| Field | Value |
|---|---|
| SHA-256 | `2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6` |
| Family label | `unknown` |
| File name | `2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6.exe` |
| File type | `exe` |
| First seen | `2026-09-05 03:37:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `079dc4467579bc912b8d98dc35d2c35a` |
| SHA-1 | `adbdadea1420f78a72a957bd0fe57fd74485a6b1` |
| SHA-256 | `2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6` |
| SHA3-384 | `4ff51b4af6a31ff886cf950ebf83810a90fa5ea6b5f944ba867eba0af75d7de82babf5913a83b3a3a4d98a956d7fd90b` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T1FAD5228879F608F4C436C3B28FD2E57EB0697B459BB10D9B76CD28004E626886D36776` |
| SSDEEP | `49152:jnhElG9FtKPx/gxCEElAXz1ktTma8YyjBYxjvhtyG1Eap/r6XN:jnilG5C/gWAXywa8YyjBUqGuapq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_2ed6a048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6"
    family = "unknown"
    file_name = "2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6.exe"
    file_type = "exe"
    first_seen = "2026-09-05 03:37:45"
  condition:
    hash.sha256(0, filesize) == "2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6"
}
```

### Sample 11: `554317fb54d7c777`

| Field | Value |
|---|---|
| SHA-256 | `554317fb54d7c777992869e4a184aed94a54a7a2e44534f6ead0fb3c58e4de19` |
| Family label | `Mirai` |
| File name | `reaver.x86` |
| File type | `elf` |
| First seen | `2026-09-05 03:23:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d14808c1532168916b2f5fc7155c9761` |
| SHA-1 | `e2a512b65f2303c7b6eb95c364587fe339c4c037` |
| SHA-256 | `554317fb54d7c777992869e4a184aed94a54a7a2e44534f6ead0fb3c58e4de19` |
| SHA3-384 | `71cdb4f1de8c4fee34164f95b30a20bb29295dc88293561109cadab274da2ebf6bd7a8d437a0aba7c704929fd4d095b0` |
| TLSH | `T118E36B06E713D0F1D84A15B001FB9B358E78EC735536DA06EBB57FB19E21A81A61A33C` |
| TELFHASH | `t1425149b6aefa0adc77c09502d3ca5751de48e53b24113aaa0ba21ed826f3f015375c3d` |
| SSDEEP | `3072:6pP4hkkO+/BZYJomikBQenNl1J0JGGaSyc+B5ApKubMPOrVc:6pc6IZYJNhrl1J0J6tHYrMPOO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_554317fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "554317fb54d7c777992869e4a184aed94a54a7a2e44534f6ead0fb3c58e4de19"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-05 03:23:20"
  condition:
    hash.sha256(0, filesize) == "554317fb54d7c777992869e4a184aed94a54a7a2e44534f6ead0fb3c58e4de19"
}
```

### Sample 12: `fc5ee2427b727ce7`

| Field | Value |
|---|---|
| SHA-256 | `fc5ee2427b727ce7ad83502e4a8b960854b1548598a6eccb675070d5e7a47e0a` |
| Family label | `Mirai` |
| File name | `reaver.x86` |
| File type | `elf` |
| First seen | `2026-09-05 03:22:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b428daaa8d1c82ecb5e13849059758c7` |
| SHA-1 | `7ce0a10f309bcab2be65db5f73625a8c5137e7be` |
| SHA-256 | `fc5ee2427b727ce7ad83502e4a8b960854b1548598a6eccb675070d5e7a47e0a` |
| SHA3-384 | `1176735aa89cf2bf6ab9409fb6073916c5397c5e05800734b5bc64e1b00e5ab89ea53b60e087035e4dbbc3dcdd8ad7c9` |
| TLSH | `T132630228FE4546E6E8BC8034387B9C7B9530F55A7E187AB1F9CCB8AB680874CD550747` |
| SSDEEP | `1536:wQJXp+FhSJOfsS3ZMO0ld3Rm5OeVcuoEa8Xxynouy8X:wQq1LZupyVU38XkoutX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_fc5ee242
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc5ee2427b727ce7ad83502e4a8b960854b1548598a6eccb675070d5e7a47e0a"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-05 03:22:25"
  condition:
    hash.sha256(0, filesize) == "fc5ee2427b727ce7ad83502e4a8b960854b1548598a6eccb675070d5e7a47e0a"
}
```

### Sample 13: `2c3b48702fb12587`

| Field | Value |
|---|---|
| SHA-256 | `2c3b48702fb125878af303258f631c81077e60b0659e599088ce2dc6a2d2963d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-05 03:20:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `495450ec6201bb1369a40c50b25bb49e` |
| SHA-1 | `053a08a2f9ae86ffe7f57c5d280133ad8904c90a` |
| SHA-256 | `2c3b48702fb125878af303258f631c81077e60b0659e599088ce2dc6a2d2963d` |
| SHA3-384 | `608b2dfac613deab2dde339e4f1c51ea8f9b249003bf5d4c509b9149412bb93fd29aef566bc5f707c5f53a5e47a21104` |
| TLSH | `T151236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCB3CF28C5AA9D910971D` |
| SSDEEP | `768:/XRWNGxV89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:5lx3cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_2c3b4870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c3b48702fb125878af303258f631c81077e60b0659e599088ce2dc6a2d2963d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:20:51"
  condition:
    hash.sha256(0, filesize) == "2c3b48702fb125878af303258f631c81077e60b0659e599088ce2dc6a2d2963d"
}
```

### Sample 14: `93b33d365a5d3016`

| Field | Value |
|---|---|
| SHA-256 | `93b33d365a5d3016ff3c86e1516c8c1223aa0b4942bc459ba58cb79cddda000b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-05 03:19:21` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc08c7db64c8a83c01df905b82e42f3b` |
| SHA-1 | `75b93519312c31209dff4bdaa5973b670a2ced38` |
| SHA-256 | `93b33d365a5d3016ff3c86e1516c8c1223aa0b4942bc459ba58cb79cddda000b` |
| SHA3-384 | `75afd6793b2897f7a11a2e2c3ff066b8e0e0fb386c2036176cbe19a22b617debdc09728d5d1ae23d31e234e937530e3e` |
| TLSH | `T106C28D966A867C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15F9CD618B1A` |
| SSDEEP | `768:78vCB+25j6es8RTC9FYpMSUpi+20qUpi+20YQX:78l25JTkd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_93b33d36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93b33d365a5d3016ff3c86e1516c8c1223aa0b4942bc459ba58cb79cddda000b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:19:21"
  condition:
    hash.sha256(0, filesize) == "93b33d365a5d3016ff3c86e1516c8c1223aa0b4942bc459ba58cb79cddda000b"
}
```

### Sample 15: `8f70cd16856d692e`

| Field | Value |
|---|---|
| SHA-256 | `8f70cd16856d692e09253287abaca07008288ea2293333b3fe4fb59ad5e1d50b` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-05 03:13:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6a1e3d44cbfc2421daa31d52ded4e73` |
| SHA-1 | `390a41c78a5badb75f90155afe230c50a58b251d` |
| SHA-256 | `8f70cd16856d692e09253287abaca07008288ea2293333b3fe4fb59ad5e1d50b` |
| SHA3-384 | `0eab9e077ce699ab5489ad8d58058326ad6188a30229313d0ab2bdfd8fcd7eca65dd7d42daf03edd72d4f02c00d9478e` |
| TLSH | `T1F7236C6626857C24AA99C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5A69DD10871D` |
| SSDEEP | `768:sXRWNGxVo9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Alxfcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_8f70cd16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f70cd16856d692e09253287abaca07008288ea2293333b3fe4fb59ad5e1d50b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:13:30"
  condition:
    hash.sha256(0, filesize) == "8f70cd16856d692e09253287abaca07008288ea2293333b3fe4fb59ad5e1d50b"
}
```

### Sample 16: `23d0e81b02f44b5a`

| Field | Value |
|---|---|
| SHA-256 | `23d0e81b02f44b5a50cd6af26b58a702a8eba562c7d1ec1ea308ccd33dbba08c` |
| Family label | `unknown` |
| File name | `runner.ps1` |
| File type | `ps1` |
| First seen | `2026-09-05 03:12:00` |
| Reporter | `BastianHein_` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a265ac6322dc2f8ed681ad3fee3b30c` |
| SHA-1 | `3883e99698ff946ca861f99f6d92e133da578893` |
| SHA-256 | `23d0e81b02f44b5a50cd6af26b58a702a8eba562c7d1ec1ea308ccd33dbba08c` |
| SHA3-384 | `e767c519cad7aa5b2a5eaf585ad7a0c5c00e36364b43a7c47ce98d4301cf363c14471b2a6b844f054c3a9066a9397145` |
| TLSH | `T195A19528360BD15156BBBB2EEA5FA54DEF1A40372016D40076EDC6C0EF71648C7A8BCC` |
| SSDEEP | `96:t7wg8JpKroHMmn+1C0Dey+TU5HkLllzl3kN/67CH0S8m23Fov:eCIzn+1C0Dey+TUBAl5l3kNi7CUPD1y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_23d0e81b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23d0e81b02f44b5a50cd6af26b58a702a8eba562c7d1ec1ea308ccd33dbba08c"
    family = "unknown"
    file_name = "runner.ps1"
    file_type = "ps1"
    first_seen = "2026-09-05 03:12:00"
  condition:
    hash.sha256(0, filesize) == "23d0e81b02f44b5a50cd6af26b58a702a8eba562c7d1ec1ea308ccd33dbba08c"
}
```

### Sample 17: `831f77ba6b896c35`

| Field | Value |
|---|---|
| SHA-256 | `831f77ba6b896c35133f7e01d7ac48ae09e3224ace0ccbfb98477b8552c3517d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-05 03:11:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0784885f00f3ed91c038b2518185a7c4` |
| SHA-1 | `026b5b4d77a7f04b3d7fdb24ff2aa4e81991c0e8` |
| SHA-256 | `831f77ba6b896c35133f7e01d7ac48ae09e3224ace0ccbfb98477b8552c3517d` |
| SHA3-384 | `d2730c974328e762243ea98856de30d1c37b36cdca606956b2f6baa94904ac4a5a337b983cf90df4b593d954f5d832a5` |
| TLSH | `T15BC27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D4A3C71DC11FACD618B1A` |
| SSDEEP | `768:V8vCB+25j6es8R2d9FYpMSUpi+20qUpi+20YQX:V8l25J2Ld2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_831f77ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "831f77ba6b896c35133f7e01d7ac48ae09e3224ace0ccbfb98477b8552c3517d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:11:42"
  condition:
    hash.sha256(0, filesize) == "831f77ba6b896c35133f7e01d7ac48ae09e3224ace0ccbfb98477b8552c3517d"
}
```

### Sample 18: `fdc24883a1d95bd2`

| Field | Value |
|---|---|
| SHA-256 | `fdc24883a1d95bd21621c7426124fefba49bfcc959c1c774a4d5dab6893689fc` |
| Family label | `unknown` |
| File name | `setup.hta` |
| File type | `hta` |
| First seen | `2026-09-05 03:04:14` |
| Reporter | `BastianHein_` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1555058d97f0fa9a7ca786b05a5fcd7` |
| SHA-1 | `c367837f55ee6efc3e1573b8dd474803a38666df` |
| SHA-256 | `fdc24883a1d95bd21621c7426124fefba49bfcc959c1c774a4d5dab6893689fc` |
| SHA3-384 | `7cc734f11e87d27e98081f1ed026c6866e49ba15d0dd845a736bdb8a340db321a873765b71d6190d3ab1c744ae9a7649` |
| TLSH | `T18652BE3A5EB2BE6EDFA74EA0D24E11106CCCD827E790145433A253E743E7A19D7B60E0` |
| SSDEEP | `192:hlyXcT35lGVZBen675oH+V4kKe/lz1FXy0+q66CFqkYaMVpgxniPV8aYgoyIaX6x:hlAc7yfue4QfSFm5pgNkVrI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_fdc24883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdc24883a1d95bd21621c7426124fefba49bfcc959c1c774a4d5dab6893689fc"
    family = "unknown"
    file_name = "setup.hta"
    file_type = "hta"
    first_seen = "2026-09-05 03:04:14"
  condition:
    hash.sha256(0, filesize) == "fdc24883a1d95bd21621c7426124fefba49bfcc959c1c774a4d5dab6893689fc"
}
```

### Sample 19: `3c455cdf154c0a72`

| Field | Value |
|---|---|
| SHA-256 | `3c455cdf154c0a723e6d34dd14af146a25ab207faf28e081bf8aeb6826e5a701` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-05 03:00:51` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47ed7d4532ae241355b65f7c140b4ed7` |
| SHA-256 | `3c455cdf154c0a723e6d34dd14af146a25ab207faf28e081bf8aeb6826e5a701` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_3c455cdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c455cdf154c0a723e6d34dd14af146a25ab207faf28e081bf8aeb6826e5a701"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-05 03:00:51"
  condition:
    hash.sha256(0, filesize) == "3c455cdf154c0a723e6d34dd14af146a25ab207faf28e081bf8aeb6826e5a701"
}
```

### Sample 20: `afcf3bfe4743d479`

| Field | Value |
|---|---|
| SHA-256 | `afcf3bfe4743d479c912286b016e4d17c1558f28614cff406ae622db5a338da1` |
| Family label | `Mirai` |
| File name | `reaver.arm6` |
| File type | `elf` |
| First seen | `2026-09-05 02:58:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d7bee533dfb7ad11d76ba8607130921` |
| SHA-1 | `67286ded76774d9daeeb37a85be4d96452626f76` |
| SHA-256 | `afcf3bfe4743d479c912286b016e4d17c1558f28614cff406ae622db5a338da1` |
| SHA3-384 | `704c2f7637530740d427b8dfbb2e47bc3074eef86dc9ed5401673adc3b103e5a2ecaf655193e868b6175ff870e58f6d0` |
| TLSH | `T109042A56BD828E02C5C217BAFF5E828933137BB8D3DE7113DD245F60278A59E0E7A512` |
| SSDEEP | `3072:C+CmiQircQJ+6ew3SOnt0xUI9kOo5ZINlYywEaz2yKQw0ftDn4/qIM3GBAPrLHM3:C+Acu+6ew3SOt0xUhOo5ZIsyVayyKQw7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_afcf3bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afcf3bfe4743d479c912286b016e4d17c1558f28614cff406ae622db5a338da1"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-05 02:58:15"
  condition:
    hash.sha256(0, filesize) == "afcf3bfe4743d479c912286b016e4d17c1558f28614cff406ae622db5a338da1"
}
```

### Sample 21: `b3177fccd6f81b69`

| Field | Value |
|---|---|
| SHA-256 | `b3177fccd6f81b6904d78e67066aa637d5b9a35c54de5210e5e390c771d2738c` |
| Family label | `Mirai` |
| File name | `reaver.mips` |
| File type | `elf` |
| First seen | `2026-09-05 02:58:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c5b418a7b20071d9573293f9d498960` |
| SHA-1 | `8982eb8b1266f76b6f9962fa92c537dc7378e3b4` |
| SHA-256 | `b3177fccd6f81b6904d78e67066aa637d5b9a35c54de5210e5e390c771d2738c` |
| SHA3-384 | `b08cbffd188630672e2eb4287d42238381a6e7c5d7c806807954827f17cdc23cc070a5f688bad74d32ce063bed694bf2` |
| TLSH | `T15C34B81E3E21DF3EF669C73487B78E31968876D226E1C185F15CD6091E2038E641FBA8` |
| TELFHASH | `t14c3193584a7813f0a3715c9d59ddff3be5a030df6b226d378e10a86ab76d8824e10c1c` |
| SSDEEP | `3072:xYd61Dx+2VN+mTQvePOfMnXjVD7Lnpm7UWvrmgy/PMHv4:xYIxXN+mTUeWfUXjpp4rzfy/PA4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_b3177fcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3177fccd6f81b6904d78e67066aa637d5b9a35c54de5210e5e390c771d2738c"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-05 02:58:13"
  condition:
    hash.sha256(0, filesize) == "b3177fccd6f81b6904d78e67066aa637d5b9a35c54de5210e5e390c771d2738c"
}
```

### Sample 22: `758a76168bef9ed2`

| Field | Value |
|---|---|
| SHA-256 | `758a76168bef9ed2c5c164cdfa1d8baa2937ed0ea94a3cfe7d79f576da259fa9` |
| Family label | `Mirai` |
| File name | `reaver.arm6` |
| File type | `elf` |
| First seen | `2026-09-05 02:57:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3218f1ec42ef82102c7405ec227f4927` |
| SHA-1 | `763e5966959ffa94f1cedf4de5a4c988cd2330fe` |
| SHA-256 | `758a76168bef9ed2c5c164cdfa1d8baa2937ed0ea94a3cfe7d79f576da259fa9` |
| SHA3-384 | `14362c5114229ebbfde06e2b56c2265f2ba617b4b814c90eef455207b6743b78a4c933d23968596ca17c75a43067591f` |
| TLSH | `T1717302D0AA495DE5C23432AAE5B496422748D7710E7AB73F0590A7E8C9F4E3A79F0C0C` |
| SSDEEP | `1536:zzLsdFnBX77dwp8w3cc7AuDKdL/qKhNiiR7OZo/HJfK:LofX1iZnAzNiiR7m4HJC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_758a7616
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "758a76168bef9ed2c5c164cdfa1d8baa2937ed0ea94a3cfe7d79f576da259fa9"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-05 02:57:49"
  condition:
    hash.sha256(0, filesize) == "758a76168bef9ed2c5c164cdfa1d8baa2937ed0ea94a3cfe7d79f576da259fa9"
}
```

### Sample 23: `f253fada27a0dea9`

| Field | Value |
|---|---|
| SHA-256 | `f253fada27a0dea9f9dd0e4735d5c7a09690658b18f4f710da562a4a9d89166d` |
| Family label | `Mirai` |
| File name | `reaver.mips` |
| File type | `elf` |
| First seen | `2026-09-05 02:57:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93ca2158e315d97aa80bc8ef3a7ea9c0` |
| SHA-1 | `5accffe10d7cbe55306a81d1177561cfc4df9f01` |
| SHA-256 | `f253fada27a0dea9f9dd0e4735d5c7a09690658b18f4f710da562a4a9d89166d` |
| SHA3-384 | `1bc430b4e7e414655b1f02ff7dbd6666d7f8ff76cf0831269c761ed28c389058a0aca649ccc81dc2a12dc71bdf425aa1` |
| TLSH | `T11273015005B3E6DDE81592FA03E08B650F744FFCB9829C19726ADE0C49418E07AD7EEA` |
| SSDEEP | `1536:Ud1WTy3EFJX4OsQkBves55KuDUGFO9xAXvYKu4lX09q3W56cCZMV1c/j:7xKBTLh8fOYKuwXZ3C6cCZMV1oj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_f253fada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f253fada27a0dea9f9dd0e4735d5c7a09690658b18f4f710da562a4a9d89166d"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-05 02:57:48"
  condition:
    hash.sha256(0, filesize) == "f253fada27a0dea9f9dd0e4735d5c7a09690658b18f4f710da562a4a9d89166d"
}
```

### Sample 24: `ef10e849bf04c968`

| Field | Value |
|---|---|
| SHA-256 | `ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc` |
| Family label | `unknown` |
| File name | `ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc.exe` |
| File type | `exe` |
| First seen | `2026-09-05 02:52:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `725d644fcd63201c56e5c9fb1cfaf7a1` |
| SHA-1 | `d5284dc4b107c879a63057c556947566eb677243` |
| SHA-256 | `ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc` |
| SHA3-384 | `25927fb7fb18841dfab2eded937ae328e05c6e506f5f12bcc7a7a0e1fb2e89c2c61fbf7d2e1ec2999932698ff1451bc1` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T187D5239BB4F61DB8C877CBB68F43F17EB06837464A658E1AB7CD68008D435886836771` |
| SSDEEP | `49152:GvEU6OQaTiawFptbEWr/AXFBGaDkU32cOiHqy9fJ6Ihi97wWab9:yErOQaLwFTbTwGKmcOQb9fzIw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_ef10e849
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc"
    family = "unknown"
    file_name = "ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc.exe"
    file_type = "exe"
    first_seen = "2026-09-05 02:52:47"
  condition:
    hash.sha256(0, filesize) == "ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc"
}
```

### Sample 25: `0047d289274e4bb5`

| Field | Value |
|---|---|
| SHA-256 | `0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c` |
| Family label | `CoinMiner` |
| File name | `0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c.exe` |
| File type | `exe` |
| First seen | `2026-09-05 02:27:53` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45bb28b31491bad81236ae1210a3b9d3` |
| SHA-1 | `0ec0217594b40d5b6ca5545dd146b5188b506f74` |
| SHA-256 | `0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c` |
| SHA3-384 | `9d72ca0c9f484ba62ccdf5868d07cacd6c4da7dfcac212491ddd4503170c9fdc6dbbe23145e4b2a45983fb7f8ef0a75f` |
| IMPHASH | `949ec789a5933fb6051c9013a550fb57` |
| TLSH | `T1C33633C2ADCAA4B4C456C7BD1652615DB33EBBE889357D0B358D3A044DAAF11B83E7C0` |
| SSDEEP | `98304:7L3FxdUqX9PTd1l1rFign1bT8mT1rVYMXSJJ4PZigHliF7dF7H3Qg:7L3FsqXlTrpiyLTcAg4xRkXFU` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_025_0047d289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c"
    family = "CoinMiner"
    file_name = "0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c.exe"
    file_type = "exe"
    first_seen = "2026-09-05 02:27:53"
  condition:
    hash.sha256(0, filesize) == "0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c"
}
```

### Sample 26: `e380c3616758bce6`

| Field | Value |
|---|---|
| SHA-256 | `e380c3616758bce69f520388bcc53199e1a731aee811f9f088194c45bacfdc0c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-05 02:12:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1eb0ea49f06ba75b010ca50d099d92c1` |
| SHA-1 | `117efcbe9ce90fdf2f47c99d9b73131242ba4455` |
| SHA-256 | `e380c3616758bce69f520388bcc53199e1a731aee811f9f088194c45bacfdc0c` |
| SHA3-384 | `abf2d84b1f888987cebcda1f99218fda6fda240efc622fa6ead39454fcc41d2f42f31ef0864a330aa63c39753fcf0f73` |
| TLSH | `T151C27D966E867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:YK8vCB+25j6es8Ro9FYpMSUpi+20qUpi+20YQX:H8l25J+d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_e380c361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e380c3616758bce69f520388bcc53199e1a731aee811f9f088194c45bacfdc0c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 02:12:22"
  condition:
    hash.sha256(0, filesize) == "e380c3616758bce69f520388bcc53199e1a731aee811f9f088194c45bacfdc0c"
}
```

### Sample 27: `162172aaf538da54`

| Field | Value |
|---|---|
| SHA-256 | `162172aaf538da54d65cf8bdaf9894b0e7f0f3d2810e2791b81f1257599d338e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-05 01:55:18` |
| Reporter | `Bitsight` |
| Tags | `B, BB5.file, dropped-by-GCleaner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1160591b6337e2be1ea81ccf3897f4fe` |
| SHA-1 | `c8a25f150cc0d30456a26bb159458a22c3481821` |
| SHA-256 | `162172aaf538da54d65cf8bdaf9894b0e7f0f3d2810e2791b81f1257599d338e` |
| SHA3-384 | `710cb2e400172218209e57da79a3e7fc0914c6978fd606d9d7d4fc30270f9c7d24b29f4f322ea4b82cbd85055ec77168` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T190567C0B6A8A56E2C496CB34C17B6162AAB4BC0DDF3573E33E4479702F347D069B6B05` |
| SSDEEP | `49152:WU2GgiDDyM3KHOucqqlJOwLArzLEfFQqsNdqcrg1iB8lenPMoNjgS:oMHuVH4fFQqsNdqcqiOiPLNh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_162172aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "162172aaf538da54d65cf8bdaf9894b0e7f0f3d2810e2791b81f1257599d338e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-05 01:55:18"
  condition:
    hash.sha256(0, filesize) == "162172aaf538da54d65cf8bdaf9894b0e7f0f3d2810e2791b81f1257599d338e"
}
```

### Sample 28: `c2386ea75e2c185b`

| Field | Value |
|---|---|
| SHA-256 | `c2386ea75e2c185bee094b845498e6c750217349cf3f965b3832b39fad241c09` |
| Family label | `Loki` |
| File name | `8B62D1FAE5707198C74C9BD3E27AA922.exe` |
| File type | `exe` |
| First seen | `2026-09-05 01:55:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, Loki` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b62d1fae5707198c74c9bd3e27aa922` |
| SHA-1 | `1c453fc232a2bbf3b3f3dc7cf263f4fde825e94e` |
| SHA-256 | `c2386ea75e2c185bee094b845498e6c750217349cf3f965b3832b39fad241c09` |
| SHA3-384 | `93b97ba1bd3eb6511316aba58a405ad8dc21ba16dfd24f7a45bfea9c0c8890140109a8678aec3b14e0dc87cfc7cb6d88` |
| IMPHASH | `e904af49c636d1e2cc5e8a5768ffdfe4` |
| TLSH | `T19E259DB36211BF3AD1630371B754C279D2BE3D7AF1120944720BB27560B69EC2ABD729` |
| SSDEEP | `12288:dSMGVUdY1HMiVHpj7ypnLskDHvsfXwvP2:dN464MiVHpj7ypnLskDHvsfXwvP2` |
| ICON-DHASH | `d0d232697132cc48` |

#### Technical Assessment

- The sample is tracked as `Loki` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Loki_028_c2386ea7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2386ea75e2c185bee094b845498e6c750217349cf3f965b3832b39fad241c09"
    family = "Loki"
    file_name = "8B62D1FAE5707198C74C9BD3E27AA922.exe"
    file_type = "exe"
    first_seen = "2026-09-05 01:55:06"
  condition:
    hash.sha256(0, filesize) == "c2386ea75e2c185bee094b845498e6c750217349cf3f965b3832b39fad241c09"
}
```

### Sample 29: `9aa644bd41794a45`

| Field | Value |
|---|---|
| SHA-256 | `9aa644bd41794a457cd899ba48e8c599e832825b8dc40ac8b76b2f34884dfbb2` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-05 01:31:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7b4e0afb4f17d20d4685e70683ea708` |
| SHA-1 | `5e6f6689f2d7f0b424ba28add737028882e88850` |
| SHA-256 | `9aa644bd41794a457cd899ba48e8c599e832825b8dc40ac8b76b2f34884dfbb2` |
| SHA3-384 | `1629e268746f795e5c460137cca7033d081eee637eb866d0f44f2d929d199df5cdc602bbde37d868ce671c428925b9aa` |
| TLSH | `T108C28C966A967C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:58vCB+25j6es8RV9FYpMSUpi+20qUpi+20YQX:58l25Jzd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_9aa644bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aa644bd41794a457cd899ba48e8c599e832825b8dc40ac8b76b2f34884dfbb2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 01:31:52"
  condition:
    hash.sha256(0, filesize) == "9aa644bd41794a457cd899ba48e8c599e832825b8dc40ac8b76b2f34884dfbb2"
}
```

### Sample 30: `24f3873639dd30d0`

| Field | Value |
|---|---|
| SHA-256 | `24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6` |
| Family label | `unknown` |
| File name | `24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6.elf` |
| File type | `elf` |
| First seen | `2026-09-05 00:02:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd2890c830d1a6b787740abef8769512` |
| SHA-1 | `506e85028ceaa672360cc5e1ad0b534e46340ef8` |
| SHA-256 | `24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6` |
| SHA3-384 | `d48e8ab9d8d396d0cc65b5e6011769abd831120395eeaf05c34e47cf99fe1bdbbf937899e1da73d24737cc85499827ae` |
| TLSH | `T134E55C06B6A244BEC0E6D430874FD573AD35B8594221397F3685AB312E76E305F2EFA1` |
| SSDEEP | `49152:4ayhP6dewPODTnX5EojAcOPXLBfrGlyz7C+v/xxngc/oz+dREN7R:eh22vKojAcw71rGlfC/D/QyRoR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_24f38736
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6"
    family = "unknown"
    file_name = "24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6.elf"
    file_type = "elf"
    first_seen = "2026-09-05 00:02:55"
  condition:
    hash.sha256(0, filesize) == "24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6"
}
```

### Sample 31: `91db162fba6210d1`

| Field | Value |
|---|---|
| SHA-256 | `91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4` |
| Family label | `unknown` |
| File name | `91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4.exe` |
| File type | `exe` |
| First seen | `2026-09-05 00:02:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7853d612122de9cc7ac9368f01c41e1` |
| SHA-1 | `7cebb61aed18a3ede120746afe37ed4c8a1e329d` |
| SHA-256 | `91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4` |
| SHA3-384 | `cd68cd9a5baf76b236fcd88923cae5833e0d1885ec6d134e5c0c4740a539c8d5855ee52391ee8921fd87307e9ad676ca` |
| IMPHASH | `5a2ed47d8c6c6433dbc831d38c92042b` |
| TLSH | `T127E52385BC823975F437C7BB07D3A4BE71287B989A658C5F7AC85B042D53A1C6C7B208` |
| SSDEEP | `49152:/VfY8cnR3+tT496fkyCUPCb/L5IYm2jHolBLM8H5X5833QcSAadd+Z39AQZ:/xJcwtT4Y97Ij2Ym4HoEw5p833WAa8SA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_91db162f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4"
    family = "unknown"
    file_name = "91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4.exe"
    file_type = "exe"
    first_seen = "2026-09-05 00:02:47"
  condition:
    hash.sha256(0, filesize) == "91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4"
}
```

### Sample 32: `a8b96a44c99b1201`

| Field | Value |
|---|---|
| SHA-256 | `a8b96a44c99b1201c36ce05c5c66dfa78d4776705d4dd3fda4dfece96f69a887` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-04 22:57:01` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e399ed5d33df7808e9c9e431b9661697` |
| SHA-1 | `f6c05e21ec6455e4388dca5e4a50679e7d679c7d` |
| SHA-256 | `a8b96a44c99b1201c36ce05c5c66dfa78d4776705d4dd3fda4dfece96f69a887` |
| SHA3-384 | `26a5c15478e05cf91796d3c65f1894253092a836dd8b1f5432f4ee2c9dd7844a3cc6bcc9a0bd1ca624ec9c2d6de753f5` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1B8E61237B28A653EF06E4A355AB7E220443B76616D138D1A97F4489CCF252A03E3F747` |
| SSDEEP | `196608:UoMPrf95ofPAEyzB8xbxEAfToRu0K9TpDI6DcHl3N:Uo2rofIjdQbxL53Ta6D0l3N` |
| ICON-DHASH | `94b4b5e4d060e4d8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_a8b96a44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b96a44c99b1201c36ce05c5c66dfa78d4776705d4dd3fda4dfece96f69a887"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 22:57:01"
  condition:
    hash.sha256(0, filesize) == "a8b96a44c99b1201c36ce05c5c66dfa78d4776705d4dd3fda4dfece96f69a887"
}
```

### Sample 33: `72ecf19512cb1528`

| Field | Value |
|---|---|
| SHA-256 | `72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e` |
| Family label | `unknown` |
| File name | `72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e.bin` |
| File type | `unknown` |
| First seen | `2026-09-04 22:52:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb4548fe72f49789bc1f996b6089cbc3` |
| SHA-256 | `72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_72ecf195
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e"
    family = "unknown"
    file_name = "72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e.bin"
    file_type = "unknown"
    first_seen = "2026-09-04 22:52:51"
  condition:
    hash.sha256(0, filesize) == "72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e"
}
```

### Sample 34: `d520fe67dbf76530`

| Field | Value |
|---|---|
| SHA-256 | `d520fe67dbf76530fe2cd90cb205607ff38cc3621dc849e44080663cdc9f6f87` |
| Family label | `unknown` |
| File name | `5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e.exe` |
| File type | `exe` |
| First seen | `2026-09-04 22:48:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `332aca55ab6dd21a49612b5f45fa5acd` |
| SHA-1 | `7fcd70b06a7cbe9afcc62837c5be4258fb33459e` |
| SHA-256 | `d520fe67dbf76530fe2cd90cb205607ff38cc3621dc849e44080663cdc9f6f87` |
| SHA3-384 | `3a7525f34c82a509d6dad2a70121d587438c6bc82e17349f9d9522340f1313c9f5191fa9f5b17da51895ea7022b61e2c` |
| TLSH | `T17955FA8ED4825374B396FB63821EE6625DF6334580328635CF5A7D359F02EB0A029EDD` |
| SSDEEP | `12288:3t/1grHv9KeEuAZ7bD57RHBIkP6d3g+6SYd/YIsbHcdTQ+MA9U:3krP4eEuVYdgIsbH/VA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_d520fe67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d520fe67dbf76530fe2cd90cb205607ff38cc3621dc849e44080663cdc9f6f87"
    family = "unknown"
    file_name = "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e.exe"
    file_type = "exe"
    first_seen = "2026-09-04 22:48:12"
  condition:
    hash.sha256(0, filesize) == "d520fe67dbf76530fe2cd90cb205607ff38cc3621dc849e44080663cdc9f6f87"
}
```

### Sample 35: `5efaa1a7deb70760`

| Field | Value |
|---|---|
| SHA-256 | `5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e` |
| Family label | `unknown` |
| File name | `5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e.exe` |
| File type | `exe` |
| First seen | `2026-09-04 22:47:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `968d308375c5261d3aa16083fee9e01b` |
| SHA-1 | `691c98469c99e34148a1a4acdefdb9b069303ea8` |
| SHA-256 | `5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e` |
| SHA3-384 | `d4cbf0644fec46a233ee446a485168c5c33803a066074c9e8ead6f2860a118201f15098259a9485f7b24c62c8bb640f2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10E74127B2077588EE4ECC5BA47CC46AD78EDB73D3298EB1ED25CE04D67548352E920A0` |
| SSDEEP | `6144:bBedGEctfslW269SYMo359aWTNRcewuFbELDMdbflfpB3cZrJB:NtslxYMo3PxNWvuFwLDMtPB2rJB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_5efaa1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e"
    family = "unknown"
    file_name = "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e.exe"
    file_type = "exe"
    first_seen = "2026-09-04 22:47:48"
  condition:
    hash.sha256(0, filesize) == "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e"
}
```

### Sample 36: `b7150d0e8c628a0b`

| Field | Value |
|---|---|
| SHA-256 | `b7150d0e8c628a0bcd1deffb9c1f94212b477605ddb3144a4a56c300cb461323` |
| Family label | `unknown` |
| File name | `poop` |
| File type | `elf` |
| First seen | `2026-09-04 22:31:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e05ea22a56f022e85441013180b3c7a` |
| SHA-1 | `32ff772e4fd60accf8e63be76ec2fd3ea4ebe8ee` |
| SHA-256 | `b7150d0e8c628a0bcd1deffb9c1f94212b477605ddb3144a4a56c300cb461323` |
| SHA3-384 | `3f52ab067e0c6420a3015abf225a1e214b9712a898a2f0771902c0e3a4a49c248bd00dc5f5e7bc77e5f3d422bdc309ab` |
| TLSH | `T13E353374DBB9D148FE697D7E0CA458748D2D7C8536FFDFA18C60A9081AEBC07864A90C` |
| SSDEEP | `24576:8xjYKXhddU2aABFkxaU1D6tFrGQhl4PRecoNy53r8Nioi5+AWk6dleh3:8+KxdmybkoU1DgFlNcCyNf0el` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_b7150d0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7150d0e8c628a0bcd1deffb9c1f94212b477605ddb3144a4a56c300cb461323"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-04 22:31:06"
  condition:
    hash.sha256(0, filesize) == "b7150d0e8c628a0bcd1deffb9c1f94212b477605ddb3144a4a56c300cb461323"
}
```

### Sample 37: `dd3d27e0797ea47f`

| Field | Value |
|---|---|
| SHA-256 | `dd3d27e0797ea47ffd44ccf1bd3cc11d401f69bc6c78ca0a6ac966cd330fb412` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-04 22:31:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `349f9daef8937609ea827353c60d513c` |
| SHA-1 | `7f1ffbbf5ed964da54cb8465f1b6185ecc2b607c` |
| SHA-256 | `dd3d27e0797ea47ffd44ccf1bd3cc11d401f69bc6c78ca0a6ac966cd330fb412` |
| SHA3-384 | `f482fffd797f273477b963bac5ab9e3d31424911e53641f148aece72a7749bbcd99bc27e187a3bea1caa6105f2c26033` |
| TLSH | `T171235C6526857C14AA98C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AADD910961D` |
| SSDEEP | `768:mJFWzZx5s9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:EkzDcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_dd3d27e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd3d27e0797ea47ffd44ccf1bd3cc11d401f69bc6c78ca0a6ac966cd330fb412"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 22:31:04"
  condition:
    hash.sha256(0, filesize) == "dd3d27e0797ea47ffd44ccf1bd3cc11d401f69bc6c78ca0a6ac966cd330fb412"
}
```

### Sample 38: `64927e9384b972ba`

| Field | Value |
|---|---|
| SHA-256 | `64927e9384b972ba5b2b677b2c31dc93417072222054f5a7d038e695367ed13d` |
| Family label | `Mirai` |
| File name | `reaver.arm5` |
| File type | `elf` |
| First seen | `2026-09-04 22:24:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bf5cbfd8bf9628e57afff54dc729908` |
| SHA-1 | `67d250850e01774ddaa8152f50913536c140fdcf` |
| SHA-256 | `64927e9384b972ba5b2b677b2c31dc93417072222054f5a7d038e695367ed13d` |
| SHA3-384 | `10567f807b14cf520d8ebba8aebf96019c723ac5c01901f8af3e08667b950687399f386bdb9c7e843d078997db27984f` |
| TLSH | `T1E1F31956BD429E13C6C326B7FB9E4389371677A9D3EE3103ED246F60338A59F092A111` |
| TELFHASH | `t15cd022120a4d1ce833e04ae9c1248305ca8823af020a84280fd4bca39c072ca7ab3013` |
| SSDEEP | `3072:U3X2AotOUo2B231gLhEvZvFAZpbccDdLZ7uYUU1hk4ltNzFphGVAPFuH89f:5Auu2B231gL+vZu3TDpZ7dUU1h/lbzjN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_64927e93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64927e9384b972ba5b2b677b2c31dc93417072222054f5a7d038e695367ed13d"
    family = "Mirai"
    file_name = "reaver.arm5"
    file_type = "elf"
    first_seen = "2026-09-04 22:24:31"
  condition:
    hash.sha256(0, filesize) == "64927e9384b972ba5b2b677b2c31dc93417072222054f5a7d038e695367ed13d"
}
```

### Sample 39: `672a0f0d50c1454c`

| Field | Value |
|---|---|
| SHA-256 | `672a0f0d50c1454cdcbde731cee21fccfe7fb0329030a488bcb947ef5d3526fc` |
| Family label | `unknown` |
| File name | `.X0-lock_x86_64` |
| File type | `elf` |
| First seen | `2026-09-04 22:24:30` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03f3db587b71f41ed2c735c673cba585` |
| SHA-1 | `379a0dd5bd06c0dd1d4e791c19a33f4ae7c93b3a` |
| SHA-256 | `672a0f0d50c1454cdcbde731cee21fccfe7fb0329030a488bcb947ef5d3526fc` |
| SHA3-384 | `1130e40eacf529549e1af0df0a28819d1fe5273b5bfc12405d1322ff7c6f51ba6f9e7028c5edcde5779a509f3bb2b840` |
| TLSH | `T119E55C06B6A244BEC0E6D430874BD5B3AD35B8594221397F76C5AB302E76E305F2DFA1` |
| SSDEEP | `49152:4ayhP6dewPODTnX5Eo2ZZ/NeOpCMlBW9/sxrGYM/5H7FFRLN7R:eh22vKo2ZF4QCMlBxr25HXRhR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_672a0f0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "672a0f0d50c1454cdcbde731cee21fccfe7fb0329030a488bcb947ef5d3526fc"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 22:24:30"
  condition:
    hash.sha256(0, filesize) == "672a0f0d50c1454cdcbde731cee21fccfe7fb0329030a488bcb947ef5d3526fc"
}
```

### Sample 40: `2c7d28fa5a556396`

| Field | Value |
|---|---|
| SHA-256 | `2c7d28fa5a5563968536784beb4f0addae0f53a4cdca5c58eac8267abbd81dcc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-04 22:22:51` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX2.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96c49500448701932eb39c8300514801` |
| SHA-1 | `7ed2718c0c61ef01818ef6f4e4cd492d0b4f0bf0` |
| SHA-256 | `2c7d28fa5a5563968536784beb4f0addae0f53a4cdca5c58eac8267abbd81dcc` |
| SHA3-384 | `e05d3ae7c5aba32d6632efeaf1902c9f264aa8296826fd9c191bbcd734af5369569a6850f08ac493e87fe5236c750a59` |
| IMPHASH | `79349caf0e8f6a76e2a57505fe2eaf2c` |
| TLSH | `T14FF5F16100C080EDF19BD6308394FA3B616937599B9CEFDB52E8BF285724C586C7AE47` |
| SSDEEP | `49152:MPUpQfHubAx898zDyySZO9pj4unHfvyiWi8PF:5GWr91ySZQjrHfvyikPF` |
| ICON-DHASH | `d4923d8c8c4d8ad4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_2c7d28fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c7d28fa5a5563968536784beb4f0addae0f53a4cdca5c58eac8267abbd81dcc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 22:22:51"
  condition:
    hash.sha256(0, filesize) == "2c7d28fa5a5563968536784beb4f0addae0f53a4cdca5c58eac8267abbd81dcc"
}
```

### Sample 41: `9b93ef7f3659f4b2`

| Field | Value |
|---|---|
| SHA-256 | `9b93ef7f3659f4b21fc530b70d81bd1ebcccd99861bef2b1117a0bf6298bdda8` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-04 22:08:32` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7a337930bb134c4abaac6ddefd5862d` |
| SHA-256 | `9b93ef7f3659f4b21fc530b70d81bd1ebcccd99861bef2b1117a0bf6298bdda8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_9b93ef7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b93ef7f3659f4b21fc530b70d81bd1ebcccd99861bef2b1117a0bf6298bdda8"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 22:08:32"
  condition:
    hash.sha256(0, filesize) == "9b93ef7f3659f4b21fc530b70d81bd1ebcccd99861bef2b1117a0bf6298bdda8"
}
```

### Sample 42: `29ebe9906064b993`

| Field | Value |
|---|---|
| SHA-256 | `29ebe9906064b9935afbbe6c3783f546098342128d767ed3c9730565df2329a2` |
| Family label | `Mirai` |
| File name | `reaver.x86_64` |
| File type | `elf` |
| First seen | `2026-09-04 22:07:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9454ab847e94ae14e008a819df62de94` |
| SHA-1 | `9bd4a1d8b9de43ba22afbac002957417b54c37dd` |
| SHA-256 | `29ebe9906064b9935afbbe6c3783f546098342128d767ed3c9730565df2329a2` |
| SHA3-384 | `776128dfb9d0ff2d834cde3d36d28dfca9e038336c435c364d198157b0986aee4d9f3da0c2df414a7ab903e5fce185d0` |
| TLSH | `T137E33B0379C0C9FFC486D6B48BFF562AC922F81E1535B14F63947FA13E1DE906A1A264` |
| TELFHASH | `t1ee51ab602d88395c61d39799b34eed5efcb205610d96b565ce17aaec8e433850db20a3` |
| SSDEEP | `3072:2FGnsgg/v/WoGwaYOpFp0MmPzCSM0DS2KwrDzCEe9v4psPCP/VOTV:qGnLgfWoGzHZumnJ83sPCPaV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_29ebe990
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ebe9906064b9935afbbe6c3783f546098342128d767ed3c9730565df2329a2"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 22:07:17"
  condition:
    hash.sha256(0, filesize) == "29ebe9906064b9935afbbe6c3783f546098342128d767ed3c9730565df2329a2"
}
```

### Sample 43: `3df4a3f6a4ea570e`

| Field | Value |
|---|---|
| SHA-256 | `3df4a3f6a4ea570ee1917103fab9f146fc5ecceed46c0b6077e8371d1ea2fcbe` |
| Family label | `Mirai` |
| File name | `reaver.x86_64` |
| File type | `elf` |
| First seen | `2026-09-04 22:06:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa5c0c8427fa7197cf265191f44e3eb2` |
| SHA-1 | `e50f96823251eb4ae79e3f444db6be8062ac73cf` |
| SHA-256 | `3df4a3f6a4ea570ee1917103fab9f146fc5ecceed46c0b6077e8371d1ea2fcbe` |
| SHA3-384 | `4ef1f56f3c6cef96a6a05589a529a7ae8fb3c34b81234736ec303b96ecd63005c96292160044e176e8216384092229f7` |
| TLSH | `T16C630276412669BAD62B68B33CAC5484E66C6C076D1877FF0B0C260F44BCF1B8572E46` |
| SSDEEP | `1536:tP+AXzPWNk5Yb+orY9Q48A2boM/vBlA2SuAMwzmxJq8bC6nmtPgU:V+eg638t8M/wrqJD2P` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_3df4a3f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3df4a3f6a4ea570ee1917103fab9f146fc5ecceed46c0b6077e8371d1ea2fcbe"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 22:06:50"
  condition:
    hash.sha256(0, filesize) == "3df4a3f6a4ea570ee1917103fab9f146fc5ecceed46c0b6077e8371d1ea2fcbe"
}
```

### Sample 44: `9d91a2692f7309ad`

| Field | Value |
|---|---|
| SHA-256 | `9d91a2692f7309ad560604580751fe76e0dc88d36c2f0fc1910201277496f67e` |
| Family label | `Mirai` |
| File name | `reaver.arm6` |
| File type | `elf` |
| First seen | `2026-09-04 22:01:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cb6f99db702cb524d8acdf26d740a40` |
| SHA-1 | `876a87e7ac9cc3170d72342e66729bcc7b75c3e2` |
| SHA-256 | `9d91a2692f7309ad560604580751fe76e0dc88d36c2f0fc1910201277496f67e` |
| SHA3-384 | `c2e7097a69b3b5256e70ebe5f68251994c32eee8fe2c6b72db95e790f953d811e312f1a2973e900f3891031a3bfd5727` |
| TLSH | `T179043A56BD828E12C5C216BAFF5E828D33137BB8D3DE7113DD245F60338A59A0E7A512` |
| SSDEEP | `3072:avYrxzJZwKP6pp7/TXLNbsnsy3GZz8UL9TwlaL21qximfG8wP+bMB3dum1v7APnC:avYmKP6pp7/TXhbsnsyWZYiTUay1qxiP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_9d91a269
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d91a2692f7309ad560604580751fe76e0dc88d36c2f0fc1910201277496f67e"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-04 22:01:25"
  condition:
    hash.sha256(0, filesize) == "9d91a2692f7309ad560604580751fe76e0dc88d36c2f0fc1910201277496f67e"
}
```

### Sample 45: `cbc37ec8e2ef9df5`

| Field | Value |
|---|---|
| SHA-256 | `cbc37ec8e2ef9df58cf971c805e8b110c915586546e8448055bb9e631cd65e35` |
| Family label | `Mirai` |
| File name | `reaver.arm6` |
| File type | `elf` |
| First seen | `2026-09-04 22:00:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef153906c568fbec1b9c33bc9e971682` |
| SHA-1 | `b753506480750faae5381de5a5dc5682eee7d00c` |
| SHA-256 | `cbc37ec8e2ef9df58cf971c805e8b110c915586546e8448055bb9e631cd65e35` |
| SHA3-384 | `38fe003635e1a780d0427daa852444531940e35878f3569071f710aea1e6c9eab4a3630a54ac0c0db9c96157b30024e2` |
| TLSH | `T130730281DB0A8891A87B09B2D4454543AE6DB7F599FF308E340D0D71E632386BDFD548` |
| SSDEEP | `1536:TO2XA+8i+tkpBr+NGUHKIFnpa4vR+AtvDZvHf1g:i9+89kp4NDKYnpa4J+At1/G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_cbc37ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbc37ec8e2ef9df58cf971c805e8b110c915586546e8448055bb9e631cd65e35"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-04 22:00:47"
  condition:
    hash.sha256(0, filesize) == "cbc37ec8e2ef9df58cf971c805e8b110c915586546e8448055bb9e631cd65e35"
}
```

### Sample 46: `d3f5425d205556ab`

| Field | Value |
|---|---|
| SHA-256 | `d3f5425d205556ab888dee13ebd73f7249fa2ec50fd4a4cb1c3dcb0ea5d7a405` |
| Family label | `Mirai` |
| File name | `reaver.mpsl` |
| File type | `elf` |
| First seen | `2026-09-04 21:57:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6227014a7b11f312339913c246e6db1b` |
| SHA-1 | `8a44f15c616da7a37082c938e89d08a29886e995` |
| SHA-256 | `d3f5425d205556ab888dee13ebd73f7249fa2ec50fd4a4cb1c3dcb0ea5d7a405` |
| SHA3-384 | `f957160558c8f7e70a8d49b712bfe37dcda23dc5b7a9641eb743c3e95609d9ad1fa6b82c91d940126d3756822dc3e4e5` |
| TLSH | `T1D234B40A7F205EF7E89BDD3706F95B0124CCB41721A83B7A7A34DA58BA1658F09D3874` |
| SSDEEP | `6144:GPLo7AbEQ/nj+W2xzrUjI5rTxy/6Ix9Ylq3P:GwAASnipzrUq+b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_d3f5425d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f5425d205556ab888dee13ebd73f7249fa2ec50fd4a4cb1c3dcb0ea5d7a405"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-04 21:57:15"
  condition:
    hash.sha256(0, filesize) == "d3f5425d205556ab888dee13ebd73f7249fa2ec50fd4a4cb1c3dcb0ea5d7a405"
}
```

### Sample 47: `6198980d9ffa3cf6`

| Field | Value |
|---|---|
| SHA-256 | `6198980d9ffa3cf6be3b50bb4c4673e0c92e1cd28f690928a6657e6a62ea32ea` |
| Family label | `Mirai` |
| File name | `reaver.arm` |
| File type | `elf` |
| First seen | `2026-09-04 21:56:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b55e7efd06fad531dd5d686a0a9bf02` |
| SHA-1 | `2f04976276f8408c0a91b75c51b24e4c44585551` |
| SHA-256 | `6198980d9ffa3cf6be3b50bb4c4673e0c92e1cd28f690928a6657e6a62ea32ea` |
| SHA3-384 | `698ab094857b506209e16d14b443f74f08c38b6e5c7129fe037bbe78f20476fa820c17879f441c9a4c4e29b1f4121d0c` |
| TLSH | `T11EF31896BD429E13C6C316B7FB9E8289371677A8D3EE3103DD246FA1338A59F0D26111` |
| TELFHASH | `t177d02217081c0ce83ab40aa5c2286315c998521e010681adcdd8ace1bc432ca7ae2403` |
| SSDEEP | `3072:UnR8UytoGw+Ds7FRUPMimlUhzi1jG7v5V28ArbxdysyOgh6zwAPapHzhf:ZUwT9Ds7FRwMiuOziZG7vz28Ar9dg8sB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_6198980d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6198980d9ffa3cf6be3b50bb4c4673e0c92e1cd28f690928a6657e6a62ea32ea"
    family = "Mirai"
    file_name = "reaver.arm"
    file_type = "elf"
    first_seen = "2026-09-04 21:56:25"
  condition:
    hash.sha256(0, filesize) == "6198980d9ffa3cf6be3b50bb4c4673e0c92e1cd28f690928a6657e6a62ea32ea"
}
```

### Sample 48: `eccfdfc31b719a46`

| Field | Value |
|---|---|
| SHA-256 | `eccfdfc31b719a4671a729ea4ed7cc006952640d7c619b1ed5b914093e14783c` |
| Family label | `Mirai` |
| File name | `reaver.mpsl` |
| File type | `elf` |
| First seen | `2026-09-04 21:56:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23501d01e7930d5516bd2029552c75b0` |
| SHA-1 | `a4b766d4cb82655b6fd33b5ff73c9fa7f6db6565` |
| SHA-256 | `eccfdfc31b719a4671a729ea4ed7cc006952640d7c619b1ed5b914093e14783c` |
| SHA3-384 | `c2a340a95a4d3ab6b0963246f02431ce096c388f9e7e687679cf04b1277ae3aa78c2ac6c895e588ed037eb1af1f45e05` |
| TLSH | `T1CB73027CE671FE07ED36363DA1C48B967B103A55A22C6709654B05F8DBAEC8B7C4C405` |
| SSDEEP | `1536:YcudyCkCl3XVxk0Jp/irrM8FBdrpFrQ9KaJ9u3lcKMhwRlgjwIQvr:YXNVxkwqI0BFQ9KiE6hUg0Tvr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_eccfdfc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eccfdfc31b719a4671a729ea4ed7cc006952640d7c619b1ed5b914093e14783c"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-04 21:56:24"
  condition:
    hash.sha256(0, filesize) == "eccfdfc31b719a4671a729ea4ed7cc006952640d7c619b1ed5b914093e14783c"
}
```

### Sample 49: `2b93b59a1ae132e8`

| Field | Value |
|---|---|
| SHA-256 | `2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2` |
| Family label | `unknown` |
| File name | `2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2.bin` |
| File type | `exe` |
| First seen | `2026-09-04 21:50:13` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5515db479a487c9409076f0ae6dded5` |
| SHA-1 | `04128a9f0509be5f7d82da36a02fe59d00f683c9` |
| SHA-256 | `2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2` |
| SHA3-384 | `82fb5f61458c9775c3a3311d5a538781d5fbc7c678f3a0eeacd97f26dee870a3b8d202f80c0c114ae99a9fc2c3ed62d7` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T186D67D9369858199C4758739C2BF81216AB8785CCF3233A32F62F4352FB97D1AD76720` |
| SSDEEP | `98304:Xj/Df29FubTxWF3zBb7SHYSWk++SW2lSo2ThP2RKNOJDIdf:XjLoFiza21d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_2b93b59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2"
    family = "unknown"
    file_name = "2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2.bin"
    file_type = "exe"
    first_seen = "2026-09-04 21:50:13"
  condition:
    hash.sha256(0, filesize) == "2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2"
}
```

### Sample 50: `082695e70ea1a37c`

| Field | Value |
|---|---|
| SHA-256 | `082695e70ea1a37c01247815535cfe37d3480fbd0dbebee2179be96d80c3cfd7` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-04 21:48:54` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbc284a9c9189351cae05d6252367ef6` |
| SHA-256 | `082695e70ea1a37c01247815535cfe37d3480fbd0dbebee2179be96d80c3cfd7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_082695e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "082695e70ea1a37c01247815535cfe37d3480fbd0dbebee2179be96d80c3cfd7"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 21:48:54"
  condition:
    hash.sha256(0, filesize) == "082695e70ea1a37c01247815535cfe37d3480fbd0dbebee2179be96d80c3cfd7"
}
```

### Sample 51: `42a06840551bf647`

| Field | Value |
|---|---|
| SHA-256 | `42a06840551bf6478aa324a3c477157a6440b7de74e6229f32b298a5c9e6a939` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-04 21:48:37` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX11.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `222b167bd6a545b27c0c77b5262f8299` |
| SHA-1 | `fd8bb2674d82b426504de1f7eb87feaacff9592b` |
| SHA-256 | `42a06840551bf6478aa324a3c477157a6440b7de74e6229f32b298a5c9e6a939` |
| SHA3-384 | `e1564572272004648eef66529acc09383aff00e05758cfc132b77c9aef423e412f5ac1ab4949d138a0bc90443b6b883c` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T10007121BFCA119FAC0AD623288B256927B74BC481B3263E71B50B6783F767D45D78B04` |
| SSDEEP | `393216:7dvUurCOAV1g/uWrD+5wPDeUMN9F/QVrx7Ee5gwDDdWWhoa58L:7dvUqCOiy/WYeUe9NmRp9xWWhoayL` |
| ICON-DHASH | `8e33d4d4d4d433cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_42a06840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a06840551bf6478aa324a3c477157a6440b7de74e6229f32b298a5c9e6a939"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 21:48:37"
  condition:
    hash.sha256(0, filesize) == "42a06840551bf6478aa324a3c477157a6440b7de74e6229f32b298a5c9e6a939"
}
```

### Sample 52: `a7d91740269f25f7`

| Field | Value |
|---|---|
| SHA-256 | `a7d91740269f25f7b62aa376f08532500df079a4ba4af229449e1a938dd6f081` |
| Family label | `Mirai` |
| File name | `reaver.mips` |
| File type | `elf` |
| First seen | `2026-09-04 21:38:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61366af13a8cff7cf96af4b30cb39c04` |
| SHA-1 | `b1c5c6525e262d3e00aa1f75653e2a9249638b70` |
| SHA-256 | `a7d91740269f25f7b62aa376f08532500df079a4ba4af229449e1a938dd6f081` |
| SHA3-384 | `0933911c1730f82da44b4a4bdfb28ecbd2f5a4850e0e12c5216aa037ee7fb8432b53dfe5deaa6d11be058191a9deba1e` |
| TLSH | `T15434B60E3E21DF3EF669C73487B78E71968876D626E1C584F15CD6091E2038E641FBA8` |
| TELFHASH | `t14b31d2184a7813f4a3355c5d19edef7be5a030db3a222c378e10a86ab76d9824e10c1c` |
| SSDEEP | `3072:Aq6YVC+AaMxzTdm0qe6khonnM18cbFQW5eS+N5WIy/QMHxT:Aq3ViaMx3dm0P6khAnMzhjz+Dfy/QyT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_a7d91740
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7d91740269f25f7b62aa376f08532500df079a4ba4af229449e1a938dd6f081"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-04 21:38:18"
  condition:
    hash.sha256(0, filesize) == "a7d91740269f25f7b62aa376f08532500df079a4ba4af229449e1a938dd6f081"
}
```

### Sample 53: `0efe556123f0be9b`

| Field | Value |
|---|---|
| SHA-256 | `0efe556123f0be9bbad8690e658ee018d25c5879c34f12a3de6b3b2bfe28868b` |
| Family label | `Mirai` |
| File name | `reaver.mips` |
| File type | `elf` |
| First seen | `2026-09-04 21:37:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b315725b45d4cb7916d644784dd72e7f` |
| SHA-1 | `492a63f6652db849d0689fd5016969bb7d954352` |
| SHA-256 | `0efe556123f0be9bbad8690e658ee018d25c5879c34f12a3de6b3b2bfe28868b` |
| SHA3-384 | `4bc9ffdb4a2ec3520a36cc1729a68e3a31591346509198f3b2300079a07668496befc97b5b63890af7e37e98897c1ec4` |
| TLSH | `T19C73F104050B0CFBE536EA7D1A7C06612ABA0E265CAB1806B65BDD43D783E752CFBD45` |
| SSDEEP | `1536:du8hFK7c7RpL485K9ZOFsiWPFHxSQqDGKKeqadV1csYJqq:dTKAHL5KDfRbTfeqadV10JR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_0efe5561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0efe556123f0be9bbad8690e658ee018d25c5879c34f12a3de6b3b2bfe28868b"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-04 21:37:31"
  condition:
    hash.sha256(0, filesize) == "0efe556123f0be9bbad8690e658ee018d25c5879c34f12a3de6b3b2bfe28868b"
}
```

### Sample 54: `1cf4ab73a73e64a3`

| Field | Value |
|---|---|
| SHA-256 | `1cf4ab73a73e64a3ab57f10dff4a60144023bb16edba69ce53ea5bb940d54b47` |
| Family label | `Mirai` |
| File name | `reaver.x86` |
| File type | `elf` |
| First seen | `2026-09-04 21:34:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d29ee0795af9b1b1732fb67ac77c58a` |
| SHA-1 | `f764c3a21b059259e6dfcf71d89c8cab7d0c3907` |
| SHA-256 | `1cf4ab73a73e64a3ab57f10dff4a60144023bb16edba69ce53ea5bb940d54b47` |
| SHA3-384 | `bae3c84ee19800b6b78bc3e77b8669c7541a4c2c69af0851dad8cae9e063d031cc962807f28a213c2da27f52c579ed2e` |
| TLSH | `T140E35B06E713D0B1D44605B001BB9B358E39FD735936DA16EBB97FB1AE21A80A51B33C` |
| TELFHASH | `t17e513c736eea09dc77c08501d7c92751dd4de57b251036a60aa31bcc26f2f4263b6c39` |
| SSDEEP | `3072:OpVIAvgD/mUXE2BLDpxvcAWkHYKFJDsrhaxU6L+rQvKUlMPxo2Vk:Op8DmUXjBLDkAWgYKFJDsZXEvDMPWT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_1cf4ab73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf4ab73a73e64a3ab57f10dff4a60144023bb16edba69ce53ea5bb940d54b47"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-04 21:34:17"
  condition:
    hash.sha256(0, filesize) == "1cf4ab73a73e64a3ab57f10dff4a60144023bb16edba69ce53ea5bb940d54b47"
}
```

### Sample 55: `dcc1a73987b99701`

| Field | Value |
|---|---|
| SHA-256 | `dcc1a73987b9970189e1b62e30a527844bb76500e5201f2e6848c79826ec2628` |
| Family label | `Mirai` |
| File name | `reaver.x86` |
| File type | `elf` |
| First seen | `2026-09-04 21:34:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0692a413e140cbd14bd4a963c5c607c` |
| SHA-1 | `9ee6b0f37866e3c1c74541296469c5d68f5de47e` |
| SHA-256 | `dcc1a73987b9970189e1b62e30a527844bb76500e5201f2e6848c79826ec2628` |
| SHA3-384 | `df4f2191af2fb14763c5882801ca7b2b747c8459d372a8b0e3d6a3559840d54dbbee4bed5ae861b51498deb697887513` |
| TLSH | `T1AD6302414A77D5A0E2FDB07B0A63BC8A4CA8CA3D125514FECD89347DCC5971E04AAB33` |
| SSDEEP | `1536:+xQ6fXt4DH70ZQON31dAUfmchoDlIYo2wqoPKZ0C+W3zdNwanouy8Z9T:EXt4DH72jFfbhorDoSZhBzwCoutZl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_dcc1a739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcc1a73987b9970189e1b62e30a527844bb76500e5201f2e6848c79826ec2628"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-04 21:34:02"
  condition:
    hash.sha256(0, filesize) == "dcc1a73987b9970189e1b62e30a527844bb76500e5201f2e6848c79826ec2628"
}
```

### Sample 56: `d191d81feb30d77e`

| Field | Value |
|---|---|
| SHA-256 | `d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae` |
| Family label | `unknown` |
| File name | `d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae.exe` |
| File type | `exe` |
| First seen | `2026-09-04 21:32:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `542bba1aec3b9e4bdf9ae7f6b6a23621` |
| SHA-1 | `2f7d890d393bc5d72316b10677ff0078b4015a79` |
| SHA-256 | `d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae` |
| SHA3-384 | `2a09a2014a44c771886d6ef6922a7c72f26d5f08c8b16bf85e73b3c5174f673a6a666b302a044ed6390810076f17a572` |
| IMPHASH | `fe230628262faec735b6f015758b7519` |
| TLSH | `T186D523D9A9F605B0C876C772CF83F02CF12977854B748D5B76CE5A409A23550AC3A3B6` |
| SSDEEP | `49152:rqNvMPadTmhtEj7Vpo8769DV0Ja0a1fAR+1vzCSNEbmlqRqxq22IdYRY407:eNvIadB/VpR76BCJmhL1LEbhqxq27K0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_d191d81f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae"
    family = "unknown"
    file_name = "d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae.exe"
    file_type = "exe"
    first_seen = "2026-09-04 21:32:46"
  condition:
    hash.sha256(0, filesize) == "d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae"
}
```

### Sample 57: `b38bd4967f3f7150`

| Field | Value |
|---|---|
| SHA-256 | `b38bd4967f3f715046589672a5dda1e54693823298c1bfd5ed94d50ab9390cb4` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-04 21:29:48` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c8103f68a95047a4755184ede418187` |
| SHA-256 | `b38bd4967f3f715046589672a5dda1e54693823298c1bfd5ed94d50ab9390cb4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_b38bd496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38bd4967f3f715046589672a5dda1e54693823298c1bfd5ed94d50ab9390cb4"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 21:29:48"
  condition:
    hash.sha256(0, filesize) == "b38bd4967f3f715046589672a5dda1e54693823298c1bfd5ed94d50ab9390cb4"
}
```

### Sample 58: `ed9033a7d6b6114b`

| Field | Value |
|---|---|
| SHA-256 | `ed9033a7d6b6114b657cc7405a4ef96e38c9c5141ef30c8dd06250ef750ddd5a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-04 21:24:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8a9c2a15112e68d282677c9d61e62d5` |
| SHA-1 | `8401b3b3c79e29d914fc739440c83bc86b92fefc` |
| SHA-256 | `ed9033a7d6b6114b657cc7405a4ef96e38c9c5141ef30c8dd06250ef750ddd5a` |
| SHA3-384 | `ba561e61b1285ae0ddcbede4a8d4f0135234e0623a04ed6392247413058136af30d242a1bac96169632dbda3d3c51bf5` |
| TLSH | `T102235B651A857C14AA98C4361D7F2F0CB9AD43E6320452EE7FCF3CF28C9A6AD910571D` |
| SSDEEP | `768:n6Utd8/49GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Wcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_ed9033a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed9033a7d6b6114b657cc7405a4ef96e38c9c5141ef30c8dd06250ef750ddd5a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 21:24:37"
  condition:
    hash.sha256(0, filesize) == "ed9033a7d6b6114b657cc7405a4ef96e38c9c5141ef30c8dd06250ef750ddd5a"
}
```

### Sample 59: `f08a43f566e84eb2`

| Field | Value |
|---|---|
| SHA-256 | `f08a43f566e84eb22984fbc81d2ef8ca94d732362ca6b2324edf9a95ea7e7f58` |
| Family label | `unknown` |
| File name | `install_q2.0.02.exe` |
| File type | `exe` |
| First seen | `2026-09-04 21:12:10` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83cba23902bef1657ec8924f4428f9cb` |
| SHA-1 | `e924dff49a97ca7fda08a895c07fc5b2eaf196cf` |
| SHA-256 | `f08a43f566e84eb22984fbc81d2ef8ca94d732362ca6b2324edf9a95ea7e7f58` |
| SHA3-384 | `ae19850c8f63c21d4327065e8aee7e9ead379ee69e7a1163e3fbd57664b56bf57392c0ccce4cd898bf7df7aca3e58804` |
| IMPHASH | `cf1d9a74e1b968361bc9958407575708` |
| TLSH | `T17C47E6117317E99DE1B753BA048B0F50F725E8B41970977323B8916C5FEAB0CBAB2924` |
| SSDEEP | `49152:yKL3W0A0vr9cusmglhowk8s0nHQh6/q/5ci7CbaZk9t5BCHqO3eu/1fef/h5B46m:bjAIMaQi7kmeHh2yeH7rkfvVsX+N2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_f08a43f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08a43f566e84eb22984fbc81d2ef8ca94d732362ca6b2324edf9a95ea7e7f58"
    family = "unknown"
    file_name = "install_q2.0.02.exe"
    file_type = "exe"
    first_seen = "2026-09-04 21:12:10"
  condition:
    hash.sha256(0, filesize) == "f08a43f566e84eb22984fbc81d2ef8ca94d732362ca6b2324edf9a95ea7e7f58"
}
```

### Sample 60: `1fbdcb873815e0bb`

| Field | Value |
|---|---|
| SHA-256 | `1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b` |
| Family label | `unknown` |
| File name | `1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b.exe` |
| File type | `exe` |
| First seen | `2026-09-04 21:07:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37068998ea8448e11d3ef9075199f997` |
| SHA-1 | `94547d4aa8d6a3892dc7f5f1d4e11f0ae1813141` |
| SHA-256 | `1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b` |
| SHA3-384 | `c47263f9adb2a02bc140af4cbc11360204c3c785e6fa329272db5ce7d9374230a3ed0859e5a85f0e1d99f9b291d02fb7` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T184E4235B5A66802AE1B211F599B77EB38F7BCA3318192993475021EDBF52083DB0F3D1` |
| SSDEEP | `12288:DyWZpTVcYJYkYJ+UmoaQi2oAkpDomrbS9hjHLl6/bHmWU88Hj76wlebSngvii70L:DyWZp+iAxad2oAk1K9lLmKWUt76wlebw` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_1fbdcb87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b"
    family = "unknown"
    file_name = "1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b.exe"
    file_type = "exe"
    first_seen = "2026-09-04 21:07:51"
  condition:
    hash.sha256(0, filesize) == "1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b"
}
```

### Sample 61: `03ce4d70c20051ec`

| Field | Value |
|---|---|
| SHA-256 | `03ce4d70c20051ec6980cc7169086e38521510416aab1a2e2869e7aac7b57a5a` |
| Family label | `Gafgyt` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-09-04 21:07:44` |
| Reporter | `abuse_ch` |
| Tags | `Gafgyt, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a432081a483f74462529dd19d258fbc8` |
| SHA-1 | `ccac24e34d061dab6cbd5f1ae3463741a4886e17` |
| SHA-256 | `03ce4d70c20051ec6980cc7169086e38521510416aab1a2e2869e7aac7b57a5a` |
| SHA3-384 | `5bd3925d4978b86370d8f159b8c334a61eb45e126dc5ecde41811847ac2ed4aae8830481429d0d2eb9336f76db9bdc62` |
| TLSH | `T14941EDC620E178317CB0A95B73BD88077085E09E58F6AF089CFD74E5D1ACD59A258AA3` |
| SSDEEP | `48:vDcKfjEsDHN/fUPsDdBpDRXDRTf2JeJD/1DVvDBDDtvDJNJDprDjtLD4xclDkwm:voK7EsbtsPszp5lTeJsh9dVdtFLkAQR` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_061_03ce4d70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03ce4d70c20051ec6980cc7169086e38521510416aab1a2e2869e7aac7b57a5a"
    family = "Gafgyt"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-09-04 21:07:44"
  condition:
    hash.sha256(0, filesize) == "03ce4d70c20051ec6980cc7169086e38521510416aab1a2e2869e7aac7b57a5a"
}
```

### Sample 62: `ff13e60a92588a84`

| Field | Value |
|---|---|
| SHA-256 | `ff13e60a92588a848dced4cdd37b48302eef60ee22b7fe5256ffe819ad6b7279` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-04 21:03:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `996021f455da3339db878a6e1f7b1c18` |
| SHA-1 | `88ff1e5ddf88c20bc3b48299b526796cc4a0e7ef` |
| SHA-256 | `ff13e60a92588a848dced4cdd37b48302eef60ee22b7fe5256ffe819ad6b7279` |
| SHA3-384 | `6c12c4713908ec117d41c1ef15fc22693c5eadffcb55c4fb947f95be1f73baad88b586886148bb21c90b98a4f5d3546a` |
| TLSH | `T18A236D651A857C24AA98C4371D7E2F0CBDAD43E6324492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:2XRWNGxV69GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ylxdcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_ff13e60a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff13e60a92588a848dced4cdd37b48302eef60ee22b7fe5256ffe819ad6b7279"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 21:03:20"
  condition:
    hash.sha256(0, filesize) == "ff13e60a92588a848dced4cdd37b48302eef60ee22b7fe5256ffe819ad6b7279"
}
```

### Sample 63: `8a1027560582bf2c`

| Field | Value |
|---|---|
| SHA-256 | `8a1027560582bf2c61f554529dce737ba1d74a6b6a7d50ec8f63a3f48559170e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-04 21:03:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `153feabe71d7a728b7e548a1ba9da115` |
| SHA-1 | `e06e717c363e911a6838ca5c652719474c3ffab6` |
| SHA-256 | `8a1027560582bf2c61f554529dce737ba1d74a6b6a7d50ec8f63a3f48559170e` |
| SHA3-384 | `a744d540595693c256ff8e98794e32e96887ee3488abe20a3edde835e35f9587e3307dd32e8035e779dcb61bde7ed883` |
| TLSH | `T110C27D966A867C44BEC94A3E4CBE2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:Cf8vCB+25j6es8Rs9FYpMSUpi+20qUpi+20YQX:Cf8l25J6d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_8a102756
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a1027560582bf2c61f554529dce737ba1d74a6b6a7d50ec8f63a3f48559170e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 21:03:18"
  condition:
    hash.sha256(0, filesize) == "8a1027560582bf2c61f554529dce737ba1d74a6b6a7d50ec8f63a3f48559170e"
}
```

### Sample 64: `cf01b2bd8b6496ed`

| Field | Value |
|---|---|
| SHA-256 | `cf01b2bd8b6496ed9677cb33f83cbe34158be35be63baa182aa99e7b1d83fe96` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-04 20:56:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7920db02407302b005fb8a4db7cc9402` |
| SHA-1 | `626baf049a3b5fffa291263958d22f6caf5a56a3` |
| SHA-256 | `cf01b2bd8b6496ed9677cb33f83cbe34158be35be63baa182aa99e7b1d83fe96` |
| SHA3-384 | `3e4816084fee74ddb6b88ebd055b466d1439da60e05e68afbe67a588368b13566087ec6b8df09d65c36322c5c00b95c9` |
| TLSH | `T1ECC27C956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:e8vCB+25j6es8Rr9FYpMSUpi+20qUpi+20YQX:e8l25J9d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_cf01b2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf01b2bd8b6496ed9677cb33f83cbe34158be35be63baa182aa99e7b1d83fe96"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 20:56:43"
  condition:
    hash.sha256(0, filesize) == "cf01b2bd8b6496ed9677cb33f83cbe34158be35be63baa182aa99e7b1d83fe96"
}
```

### Sample 65: `16a5c2c89d4adca4`

| Field | Value |
|---|---|
| SHA-256 | `16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451` |
| Family label | `unknown` |
| File name | `16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451.exe` |
| File type | `exe` |
| First seen | `2026-09-04 20:47:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8800194d88500ea984e05dd8254ac41` |
| SHA-1 | `23ec75e97d8c5763e2241c4b8f3d6aacd26540d0` |
| SHA-256 | `16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451` |
| SHA3-384 | `765a13e5dd1b5fb217dd0dad494ce15008ad8af827d983b9f2c06a29b7935a7193245dda8307ab4b8a2eb2bf359a14cd` |
| IMPHASH | `58f4b17816a07f7a36dd14e504d515e6` |
| TLSH | `T1EDD523DE7DB21974E83BC7B68E92F4BC71283B4487208D9B32CD06D48D12A952C7A775` |
| SSDEEP | `49152:3cDcM/6wmIP5a5KBc0huKKZR8QV4JABWT1tfX15AobVR9CIaBX3/q07k5g:34cMBmIP5a5KBunR8QyJA8tt5TuIK/qA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_16a5c2c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451"
    family = "unknown"
    file_name = "16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451.exe"
    file_type = "exe"
    first_seen = "2026-09-04 20:47:46"
  condition:
    hash.sha256(0, filesize) == "16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451"
}
```

### Sample 66: `8e204247ddb0abbf`

| Field | Value |
|---|---|
| SHA-256 | `8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f` |
| Family label | `Gafgyt` |
| File name | `8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:42:58` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13b8e5eec3c6eec872a2ce11a0e76916` |
| SHA-1 | `c78b0265e61b66dd4b75f87cd8e9148dff24bccc` |
| SHA-256 | `8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f` |
| SHA3-384 | `9b70e00c4c9fbc4e577881d4f9bdc7a88563c813d3634ea3e12004340a43a27bb344eec7f26744cd6e04a88c9e4da189` |
| TLSH | `T1ADC33A06E5508B57C1D2177AB79F460D37232BA897DB33129A247FB42FC279E1E39920` |
| TELFHASH | `t17e21f05395fa8b196ff79824acbc07f105916a237255bf70af0ec1808937002b439ddb` |
| SSDEEP | `3072:j6XaCc1WaCl9O8E/uPTR45hOsx2qbiELbWrF4mygQCYsmXKhi:j6XaCc1WcuPTq5hpx2YkmmygQCYsYKhi` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_066_8e204247
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f"
    family = "Gafgyt"
    file_name = "8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:42:58"
  condition:
    hash.sha256(0, filesize) == "8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f"
}
```

### Sample 67: `d6dd1d0f185a58f3`

| Field | Value |
|---|---|
| SHA-256 | `d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2` |
| Family label | `Gafgyt` |
| File name | `d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:42:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e425a3dd2968ca726b15996760adaed` |
| SHA-1 | `a6bbb2b0adb550de5552c70c6c030b904547623d` |
| SHA-256 | `d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2` |
| SHA3-384 | `09b92f38ab53b4353d8b73ca65d6b1b5c346262e972b7b32b3b3dd4c1088c0aea5b3792100310feef6f048e48250d085` |
| TLSH | `T188833B43B641CA73D08316F6169B5B110632F9BB1E5BAE56F36C3DB4AF110897222FD8` |
| TELFHASH | `t1f921df42a5b68a296ff2982458bc06b1159266233260ef70af1ec1809937002a539e8b` |
| SSDEEP | `1536:xcqbqkZ12Ue/Wz/P9ZhxUzi+8F0p32cBNZ5hlQ6hICMIis3r0OzRPF+jHeN:xzbf12Ue/WDP9xUziB6pm85hlQiItIis` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_067_d6dd1d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2"
    family = "Gafgyt"
    file_name = "d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:42:53"
  condition:
    hash.sha256(0, filesize) == "d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2"
}
```

### Sample 68: `a34902f172965c2a`

| Field | Value |
|---|---|
| SHA-256 | `a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e` |
| Family label | `Gafgyt` |
| File name | `a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:42:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be734f8bb7c8638e433594e9cfa0f60e` |
| SHA-1 | `ce1805564e9b44f5fe31463e3058f62918899c8b` |
| SHA-256 | `a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e` |
| SHA3-384 | `607af83b2768e8feaa7cae28a8299e0b0975aa433875e99d6f8a7688e7487b89d68e3d30870356d0644d48c3d6a29c94` |
| TLSH | `T1FD936C23B552C67BC0C746B52BDB9A214823B5BA0F33724A73D47DE92F058C91E6DB81` |
| TELFHASH | `t1f921df42a5b68a296ff2982458bc06b1159266233260ef70af1ec1809937002a539e8b` |
| SSDEEP | `1536:DuLXuP6oMYexZBsRD8ZuDt7KyQLC7cc43RWphaGQSOPZ3VVOXSPKm9pon:oeP6hxZeSuDtGd27ccMRWphaGQSOPxVY` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_068_a34902f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e"
    family = "Gafgyt"
    file_name = "a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:42:47"
  condition:
    hash.sha256(0, filesize) == "a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e"
}
```

### Sample 69: `7e3c7557ef4a2400`

| Field | Value |
|---|---|
| SHA-256 | `7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6` |
| Family label | `Gafgyt` |
| File name | `7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:38:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b82cb284d839282d0c53b1840d0dcb13` |
| SHA-1 | `b98e159ede4b52212a3181784e93301b5f2fc230` |
| SHA-256 | `7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6` |
| SHA3-384 | `c041e9e13db79c1f36dee4e30647c637522f6e15c6d31e76ef2534ed89023c058452e1ff65a984e4334f4a104c444404` |
| TLSH | `T1BEF33B05E6408B57C1D22776F6CF424A33339BA4A3D733159928ABF43FC279A5E32915` |
| TELFHASH | `t12721fd53a5fa8b196ff79824acbc07f101916a137265bf70af0ec1808937002b43addb` |
| SSDEEP | `3072:00bacctY8a5k0Po8ZDF5E345hAN72BDNTBM/9dmVyh9ZmNw3B65QRRi:/bacctYb5k0zZ5d5ha72lnM/9EVyh9Ze` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_069_7e3c7557
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6"
    family = "Gafgyt"
    file_name = "7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:19"
  condition:
    hash.sha256(0, filesize) == "7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6"
}
```

### Sample 70: `14270dc1d285e7ea`

| Field | Value |
|---|---|
| SHA-256 | `14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90` |
| Family label | `Gafgyt` |
| File name | `14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:38:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9448a47faa61d2666d2b14904bfccfab` |
| SHA-1 | `522f563c2759009b0085550e5276d0a40f6478f4` |
| SHA-256 | `14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90` |
| SHA3-384 | `40481730df610eb19cd23a27075a5e69554a7beb84cbdab0858ca6f6eef1631f1f829a0bde386cc94f3a304ebb5314ec` |
| TLSH | `T185A33C377B170E23C1CA547112E30732ABB5D79A38FA5387B9A02DAC6F12A843516FD5` |
| TELFHASH | `t114110043a5ba8a192ff399245cbc0bb1159266133660ff70ef0e81804d37102b53de8f` |
| SSDEEP | `1536:q3qEa9+N95qWtlPtYphaac8CsqEbFQ/0kEy/UPKqjV83n:K8+NP9Puphaac3sqeFQ/0kEy/Uiqju3n` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_070_14270dc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90"
    family = "Gafgyt"
    file_name = "14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:14"
  condition:
    hash.sha256(0, filesize) == "14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90"
}
```

### Sample 71: `38c27f12e49368ed`

| Field | Value |
|---|---|
| SHA-256 | `38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1` |
| Family label | `Gafgyt` |
| File name | `38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:38:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7971e10e21a4470f83cc663380c6226e` |
| SHA-1 | `ae6c18c93b07257fcb0072993ef427ffab9c8097` |
| SHA-256 | `38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1` |
| SHA3-384 | `b5e77f5d3922313e9cd7ec0b1dabfaf34a98cf39c9434f97fb42c1866344ab21a2947c8458571b9fb2ee20e16009acef` |
| TLSH | `T124833C47A8615FB3C14669B531FB1E300763E9910F4B1A8A713DAAF4474B9CE781EFA0` |
| TELFHASH | `t19611dd43a5ba8a192ff398649cbc46b1159266137265ff70ef0ec5904937002b539e8f` |
| SSDEEP | `1536:QWkDaiqMKJmuRO+4FCqMgTSACU5hrI6eKnUsLzk0y/fKsjy1n:1QGTJF4FvZp5hrI6ksLzk0y/ysjy1n` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_071_38c27f12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1"
    family = "Gafgyt"
    file_name = "38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:08"
  condition:
    hash.sha256(0, filesize) == "38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1"
}
```

### Sample 72: `0caeac37ccec5e97`

| Field | Value |
|---|---|
| SHA-256 | `0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a` |
| Family label | `Gafgyt` |
| File name | `0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:38:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `429acb416d1b8c6c7d36acd9d2919daa` |
| SHA-1 | `4b39d94f336b40d2223919b3b2e750771a5a1cb6` |
| SHA-256 | `0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a` |
| SHA3-384 | `9288da52cbe5cc7dc99ed5e086fb9323b61c7afedb63f3acadd78836c3bc1dc3f674587a304142f97d1a7b03bd7850b4` |
| TLSH | `T1C3C3E917BB518EB3C81FCD3306AA460120CEE59616E56B6BB2B4DA6CF74784F09D3D84` |
| TELFHASH | `t1c7110043a5ba8a192ff398245cbc06b1159266137260ff70ef0ec1804d37102b539e8f` |
| SSDEEP | `3072:lK0Q5Y/cz+oo5hrqh7BAzRPRx9Fq51uUOypn:lK6/cCoo5hW12zRPRx9Fq51uUOypn` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_072_0caeac37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a"
    family = "Gafgyt"
    file_name = "0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:01"
  condition:
    hash.sha256(0, filesize) == "0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a"
}
```

### Sample 73: `fb276f90f9005122`

| Field | Value |
|---|---|
| SHA-256 | `fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707` |
| Family label | `Gafgyt` |
| File name | `fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:37:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8afd597ac78fe96de619b8abd0c98431` |
| SHA-1 | `9287d060c213e2ec497f0ea78630d0f773f1a691` |
| SHA-256 | `fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707` |
| SHA3-384 | `dc6ae63abb56faf133746288310c79c05d3d31af428f9ede414029f2bf005ef72609409b8ce97845da34dbbabb956573` |
| TLSH | `T1C3A30893F801DEB3F40ED67604D74B217630FBA60E931662731739A6AE722D53826F85` |
| TELFHASH | `t11a110d43a5ba8a192ff398289cbc06b1159266137260ff70ef0ec1804937002b539e8f` |
| SSDEEP | `1536:biXqYDIJ8FLAYd4bV2vgUrOhfAJGhxyyVEXJ3xb5YLf4SmMk0yD2PKqjyun:b0DI8P4Rk6OGhxyyVEXJ3xbuzPmMk0yK` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_073_fb276f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707"
    family = "Gafgyt"
    file_name = "fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:37:55"
  condition:
    hash.sha256(0, filesize) == "fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707"
}
```

### Sample 74: `c1f1f3efb4d4eb15`

| Field | Value |
|---|---|
| SHA-256 | `c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c` |
| Family label | `Gafgyt` |
| File name | `c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c.elf` |
| File type | `elf` |
| First seen | `2026-09-04 20:37:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Gafgyt, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edcaa76640c2f2e4ca125d6dddd01864` |
| SHA-1 | `3a7a7db758f90a9cf5e21e9864b84638b01e1b57` |
| SHA-256 | `c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c` |
| SHA3-384 | `30a6ba925676a382f8eabd1be2bb330b4c2c2ae16eb5f32e4309f722626e2f5bbba833094969470fabccc652b192f063` |
| TLSH | `T121934C03771D0B53C09B9AF129FB27F1876ABAE116E36180B51DAED45B32A703122FD5` |
| TELFHASH | `t168110043a5ba8a192ff388245cbc06b1159266137260ff70ef0ec1905937002b539e8f` |
| SSDEEP | `1536:9a8ZDXWE3jen6IbRnu7GygoblchOSDO5hXkyFyhZlQ0k0yD2PJojyKn:4+rMn1pu7GyFKZO5hXkyFyZlQ0k0yD2G` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_074_c1f1f3ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c"
    family = "Gafgyt"
    file_name = "c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:37:50"
  condition:
    hash.sha256(0, filesize) == "c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c"
}
```

### Sample 75: `94acc5bde1e48ce4`

| Field | Value |
|---|---|
| SHA-256 | `94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d` |
| Family label | `Formbook` |
| File name | `94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d` |
| File type | `exe` |
| First seen | `2026-09-04 20:37:17` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `201c3977a10f73542515e22b07dad335` |
| SHA-1 | `701fd7cbf22c14077bdd70883dd2eafbdd0074b3` |
| SHA-256 | `94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d` |
| SHA3-384 | `c66315ec378dfee09197464708e3f20b0c18caedce818f37e31717ea7a8fa81427a09d0aa62e400234e7cf2b95dbebc0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17435DF00621BDA33C9163B71D9B3E2F406A45E44E821C23F5AE97EB77F76F751885282` |
| SSDEEP | `24576:g8S22IQTi0dSJIo/n/jR2aVE46ssWn5tKfjxQ/6R:gnTi0dSJjn/jE8J5LKbey` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_075_94acc5bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d"
    family = "Formbook"
    file_name = "94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d"
    file_type = "exe"
    first_seen = "2026-09-04 20:37:17"
  condition:
    hash.sha256(0, filesize) == "94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d"
}
```

### Sample 76: `6b677975321dd379`

| Field | Value |
|---|---|
| SHA-256 | `6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0` |
| Family label | `unknown` |
| File name | `6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:59` |
| Reporter | `adrian__luca` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `708d1cd8756302eaf8d4e45abe91fd35` |
| SHA-1 | `c57eaf6a7f28343dfbe49dc8c0f37c8a7115d19c` |
| SHA-256 | `6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0` |
| SHA3-384 | `183adb78f19e0f93ac74ce6919bb95c96e299c9f6a425cc90abc8752ef8bcd78c67da8d9d5356b848434bdf57d8c0201` |
| IMPHASH | `9be4f90f50c714bc00cc8beb2e137299` |
| TLSH | `T12905DF81A40CA8EEE4648C71797ACCB324727EB51DC8614E32CCF77A9972272553EF85` |
| SSDEEP | `12288:h70ZoSPUOxCVuyzKcGmQJt0tqJepNRtM7ypCLD77EPnA2/6IdFFtCXuHb:h7qPUOxCsbcGmWt4qsxpCk1SMHtCXYb` |
| ICON-DHASH | `61c8cce4f4d4e871` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_6b677975
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0"
    family = "unknown"
    file_name = "6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:59"
  condition:
    hash.sha256(0, filesize) == "6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0"
}
```

### Sample 77: `4b5ed2db4d4c4878`

| Field | Value |
|---|---|
| SHA-256 | `4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9` |
| Family label | `Formbook` |
| File name | `4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:53` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52a74707667a353b531ec8583c86eba0` |
| SHA-1 | `883f52300a465ae5ad3d4fc5439f5fed51668bd3` |
| SHA-256 | `4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9` |
| SHA3-384 | `cd0e8c34c37cee4e34bb1a874e5ddd6417aac59ad9b9ce332b1ffe08cd220ab6d59ecde4b2f5e776dab3596679194611` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C945D09832C0F8CEC4038E718D64FD74A6502CA69306CE039DE76DEBB91D5969E351EE` |
| SSDEEP | `24576:FrbdIRXf99cIZfQG2dJyzd+HLf6nYTVbup53R:pb+fcIZh2umLZxbG3` |
| ICON-DHASH | `e4ccccccd4c4cccc` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_077_4b5ed2db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9"
    family = "Formbook"
    file_name = "4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:53"
  condition:
    hash.sha256(0, filesize) == "4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9"
}
```

### Sample 78: `f989407c3464bf00`

| Field | Value |
|---|---|
| SHA-256 | `f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302` |
| Family label | `Formbook` |
| File name | `f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:47` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bededec78ff1c4fec324009c3ca8a00a` |
| SHA-1 | `e2c21b5b07ae4584b15097276ad2e7940962b0b1` |
| SHA-256 | `f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302` |
| SHA3-384 | `8f697a2dcd92f0511c0ec504ce950a28e89e610344bc068d75b7af5d34ffaa03c1453fd87eb614084bdff2a72d54c4dd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D935DF442217DB33C8563BB1C933E6F416A4AE88E910D27F5EE57DBB7E35E352844282` |
| SSDEEP | `24576:BPPRvVo4Xr3J5U6gd1JnqoYsDaaGSsjgpzy2ge:B3tVo4XrfJAz/32aLEczyk` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_078_f989407c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302"
    family = "Formbook"
    file_name = "f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:47"
  condition:
    hash.sha256(0, filesize) == "f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302"
}
```

### Sample 79: `60e1739c404a3bff`

| Field | Value |
|---|---|
| SHA-256 | `60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90` |
| Family label | `Vidar` |
| File name | `60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:40` |
| Reporter | `adrian__luca` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74ed4564d5c44198a6092988686f1e9d` |
| SHA-1 | `829cc8e9ff978cf7c842fd02cfa14dcb242d959b` |
| SHA-256 | `60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90` |
| SHA3-384 | `21270570f50d02154d0e93c8eebdeb2e98763a8343bf488adf230551369c5d11d7f335de4d848b0ac7468b760a2efb89` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19C268C13ADA548F9C0A6E335C8B7514AB630B84C5B3427D32E90EEB82FB23D15E36755` |
| SSDEEP | `49152:bEf7sjiJw1RwBr97A4AYg8a1wkiugrzJDku2nD4hpTDOlT4LVUqchxgHN47SoSqO:bUP528afMob4XiqLVUqchxgHhUC` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_079_60e1739c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90"
    family = "Vidar"
    file_name = "60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:40"
  condition:
    hash.sha256(0, filesize) == "60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90"
}
```

### Sample 80: `17b4070f7739accf`

| Field | Value |
|---|---|
| SHA-256 | `17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d` |
| Family label | `Formbook` |
| File name | `17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:34` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19447dd51d52b27e5918d50d6782655a` |
| SHA-1 | `8fe4eb8b899a696fbb88f56094dc25e876da2a66` |
| SHA-256 | `17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d` |
| SHA3-384 | `29f4c05de913012d8aab70ba81e0e93954aa89e702688adda11b676ea17d1eee4547c1e3d216c15d18164435af83a9ba` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AF45CF9C3202FA6FC403A971C975DDF466106CA6D606C22794D73DBBBF3D9A68E041E2` |
| SSDEEP | `24576:I9OYpR9q2iB0l+X2jWwwTpIsQ18NSaJKOczu0wrym5:I9OSy08nwwTp0uApOb0wum` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_080_17b4070f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d"
    family = "Formbook"
    file_name = "17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:34"
  condition:
    hash.sha256(0, filesize) == "17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d"
}
```

### Sample 81: `04ce455ab1ce2580`

| Field | Value |
|---|---|
| SHA-256 | `04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22` |
| Family label | `unknown` |
| File name | `04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:28` |
| Reporter | `adrian__luca` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86957fe59d5a2d92b8e20909be744b71` |
| SHA-1 | `c6d42910d3b464dba6ae2a22ae377908e2d23431` |
| SHA-256 | `04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22` |
| SHA3-384 | `8fa985ed8786994e9203305bbfcf4de989f236e209c09015e97993d7a80d515728bd41e9641b4dd66f39997a70d3c6ce` |
| IMPHASH | `18fc03e2f2db32b2dacf04f213d1fab5` |
| TLSH | `T12F85E015A3D401F8E62BC275CA9A5233E7B1B4911760AACF1759DA593F33AD06F3B320` |
| SSDEEP | `49152:MbKXKfcwGpiGfKJsGgV67uVG+fGGqZLZF5:7aRJsdV67uV5fG1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_04ce455a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22"
    family = "unknown"
    file_name = "04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:28"
  condition:
    hash.sha256(0, filesize) == "04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22"
}
```

### Sample 82: `b3e01ecc1e0a7e48`

| Field | Value |
|---|---|
| SHA-256 | `b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8` |
| Family label | `unknown` |
| File name | `b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:21` |
| Reporter | `adrian__luca` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd2d9126d52cfe4e4634facf0414a5ad` |
| SHA-1 | `1f0599dad2f8fc1f8af225eb17980daa65303e04` |
| SHA-256 | `b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8` |
| SHA3-384 | `f8c31a790da500bfc33b4a93f41e0cf8dcd1f98e05e7d9b452c33540a726df3bb9e621dd1a435186309a6996b72a969a` |
| TLSH | `T151957C2439FB502AB1B3EF664BE475D6DA6FB6333B07641E1091038A4723A81DED153E` |
| SSDEEP | `24576:AqUU+E0ny5Lco1GBzzPn0ATneqpwnslq0DQ6TV7b:TUU1XinLJwsv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_b3e01ecc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8"
    family = "unknown"
    file_name = "b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:21"
  condition:
    hash.sha256(0, filesize) == "b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8"
}
```

### Sample 83: `e3a438c31a0009e3`

| Field | Value |
|---|---|
| SHA-256 | `e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b` |
| Family label | `AgentTesla` |
| File name | `e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:14` |
| Reporter | `adrian__luca` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6022d8a558bfedb10e021ae5f4e73dbf` |
| SHA-1 | `45037b1a6c23da27bf141e4f409fde2a9f47793a` |
| SHA-256 | `e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b` |
| SHA3-384 | `791d759aef9a1723aa2e7720a5ca778ab69425e2bdbb0e10f1e8aab92363816f44f527b1d3b2de266a8c3b7587ccd6f7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DA250294320ADF02C9624BF45830E7B50BF86DA5A915D3038EEA7DFB783976428583D3` |
| SSDEEP | `24576:JPREz4YN2Anb4Q0qz/peCA6mjm8mw53WCAS10boSbG3k:JPaz4YN5nb4ibpe/Tm8ZW410bov0` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_083_e3a438c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b"
    family = "AgentTesla"
    file_name = "e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:14"
  condition:
    hash.sha256(0, filesize) == "e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b"
}
```

### Sample 84: `66cccf7bf799dac1`

| Field | Value |
|---|---|
| SHA-256 | `66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384` |
| Family label | `Formbook` |
| File name | `66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384` |
| File type | `exe` |
| First seen | `2026-09-04 20:36:02` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6d231259254992a8c8958cc4e6aa1fc` |
| SHA-1 | `a0d606a34b035856ba9d2950a962f6f143be8b4a` |
| SHA-256 | `66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384` |
| SHA3-384 | `7e790ac20f9792ca6f825820f09626eb6b3eb5fb6c3ab279de47dcd3f977e769bc04128c4b62bca29420d691db4a9ccd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1154502847A0AC903DD954BB80E72FAB8176C1D9EE911E34A5FE97DEB7676F008C04643` |
| SSDEEP | `24576://eA9sVfEgkYgnQdAQw2VyVXzAyDctK6FLvF17DzSuQPX9eZ:uUsVfwY/dAQtVQXzAScNFLd1rfQPNe` |
| ICON-DHASH | `e0e2aba3a5b8b8a8` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_084_66cccf7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384"
    family = "Formbook"
    file_name = "66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:02"
  condition:
    hash.sha256(0, filesize) == "66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384"
}
```

### Sample 85: `519de0a4ed813106`

| Field | Value |
|---|---|
| SHA-256 | `519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525` |
| Family label | `MassLogger` |
| File name | `519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525` |
| File type | `exe` |
| First seen | `2026-09-04 20:35:50` |
| Reporter | `adrian__luca` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1afde31bc54cfe1771d480211b9abb2a` |
| SHA-1 | `b58d243b7ff801dc3730b64614042e16ba25bbf8` |
| SHA-256 | `519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525` |
| SHA3-384 | `3c2fff2e3fa14bc38c03d177d5b1e6ef9530516e1aa3f8266bbc68b033de53c7a6c92a72cff612d01895e96a969cf2bb` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1011501942319EE02D8A75BF18D70F7F51BB89E94A911D3438DEA7EFB38397142905283` |
| SSDEEP | `24576:lLTRvcYvV6nLQ2HtQJ5EQSfxZ9Jgdk97cR:lLF0YvV6UOtQJ6TfxZMkO` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_085_519de0a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525"
    family = "MassLogger"
    file_name = "519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:50"
  condition:
    hash.sha256(0, filesize) == "519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525"
}
```

### Sample 86: `1eb04dea7065dec9`

| Field | Value |
|---|---|
| SHA-256 | `1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569` |
| Family label | `AgentTesla` |
| File name | `1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569` |
| File type | `exe` |
| First seen | `2026-09-04 20:35:43` |
| Reporter | `adrian__luca` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8df493738e037debafb8ef065095c30c` |
| SHA-1 | `6e6e84589cf343c10e31b44bbf50964d1012a5e0` |
| SHA-256 | `1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569` |
| SHA3-384 | `d4b255df548f1926d2cd96f0619a00fd2cd0a7dfb4ba285f5c7670735a14b26908c852b3dc06cf588918b6d06f6ade29` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1672512882719DF02C8671BF46971E7B917B96E98A420D3038EE9BDFB7D3674418582C3` |
| SSDEEP | `24576:AWRzlWW6aIDwwasYLCgI3YhW44noiFHrlw:AW/96JwwL4C/Yv8Llw` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_086_1eb04dea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569"
    family = "AgentTesla"
    file_name = "1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:43"
  condition:
    hash.sha256(0, filesize) == "1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569"
}
```

### Sample 87: `b59fe70e499dfd4f`

| Field | Value |
|---|---|
| SHA-256 | `b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f` |
| Family label | `Formbook` |
| File name | `b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f` |
| File type | `exe` |
| First seen | `2026-09-04 20:35:30` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7ed106493f459e9aebe37be31f84d8e` |
| SHA-1 | `4feaad3d3556b70049ebae14e5306c4c304586eb` |
| SHA-256 | `b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f` |
| SHA3-384 | `227bf6710da9c63840aa03a66a3b1bad9366d4b5173f4e10925ae23367bb45996582a693667a9d69004e31d50f177077` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13F45E19C3200F98FC807CE768D64EEB4AA606CA68707D20395E71DEBBD1D5979E051E3` |
| SSDEEP | `24576:pkq+DRgw0Rn+8TxpfYafQ/MpV3rIf2cimm:eD6w0d+QbTTpV3rIf2cib` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_087_b59fe70e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f"
    family = "Formbook"
    file_name = "b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:30"
  condition:
    hash.sha256(0, filesize) == "b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f"
}
```

### Sample 88: `1d41c3329320e538`

| Field | Value |
|---|---|
| SHA-256 | `1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2` |
| Family label | `Formbook` |
| File name | `1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2` |
| File type | `exe` |
| First seen | `2026-09-04 20:35:18` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d27b96db5cbe4b9f3446fd523bf27870` |
| SHA-1 | `6abb8641d430c67e58c1e5ac62aab8a0958ac97a` |
| SHA-256 | `1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2` |
| SHA3-384 | `8376d220da4451e733ac69154912b16e303fbaaa604a6a146bec729eb5fb09c67a0e99a062d93cee81b23f0cde432ccd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B03502542709CE01C8A357F49972F7B51BB96DD5AE21C3038EEA7EEB782971538142C3` |
| SSDEEP | `24576:AvRJSCU+61wPgrfB2NlX6oLigJvFo0zT:AvDLUr1mmp2uoLigxG0zT` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_088_1d41c332
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2"
    family = "Formbook"
    file_name = "1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:18"
  condition:
    hash.sha256(0, filesize) == "1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2"
}
```

### Sample 89: `0c54067da7fef77b`

| Field | Value |
|---|---|
| SHA-256 | `0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73` |
| Family label | `Formbook` |
| File name | `0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73` |
| File type | `exe` |
| First seen | `2026-09-04 20:35:06` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd028eedfd0d276e6e75ac77356dfcc1` |
| SHA-1 | `263ac5d875b6c41b4cdf6ac557593f81c9a6b941` |
| SHA-256 | `0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73` |
| SHA3-384 | `64ee8ce76ac8d3997b606522d69f003e4ce5c1317215a436764769e92d189225fb67ac1cfeac09d7194963d2b6f55e29` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1303512847208EE0BD9634BF85D71E7B41BF46DA1A811D307AEEABDEBB83570119056C3` |
| SSDEEP | `24576:uQRKKHv3+yfX5af6wEuCyIKauNdMdAp22KHZl40WoznlI:uQcKHf+YX5LxuCKacqdl2K5PVzm` |
| ICON-DHASH | `d49c98acacacbcac` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_089_0c54067d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73"
    family = "Formbook"
    file_name = "0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:06"
  condition:
    hash.sha256(0, filesize) == "0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73"
}
```

### Sample 90: `c86bbf6a553b5475`

| Field | Value |
|---|---|
| SHA-256 | `c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d` |
| Family label | `SnakeKeylogger` |
| File name | `c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d` |
| File type | `exe` |
| First seen | `2026-09-04 20:34:47` |
| Reporter | `adrian__luca` |
| Tags | `exe, SnakeKeylogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c54144fa8d3900736e70d3f91a4bb3e` |
| SHA-1 | `9d68fd9b5e407125f1a5e2cf71b4be338e2e17fd` |
| SHA-256 | `c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d` |
| SHA3-384 | `6f841f02845b2717c112d4bf0319cfd34c2f48e61b46ca047684e3a12149733ea7620b011d15dc366dc4fc22cdbc66d7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11B35DF042217DB27C4627BB4D933E2F416A49E98E910D23F9EE97DBB7F76E311844182` |
| SSDEEP | `24576:75jRSYXL2dpo1ne1Lmy8ZXhp313uhrzsBzOnerbUhaBl:7RQ0Ao1eN/8ZXhp3dgrI1Pl` |
| ICON-DHASH | `8089888ccc8a8888` |

#### Technical Assessment

- The sample is tracked as `SnakeKeylogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnakeKeylogger_090_c86bbf6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d"
    family = "SnakeKeylogger"
    file_name = "c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:47"
  condition:
    hash.sha256(0, filesize) == "c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d"
}
```

### Sample 91: `34074ad3ebee3c72`

| Field | Value |
|---|---|
| SHA-256 | `34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943` |
| Family label | `Formbook` |
| File name | `34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943` |
| File type | `exe` |
| First seen | `2026-09-04 20:34:41` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cadb9db307c33b1808750b989e1fd8a8` |
| SHA-1 | `8c7c685a96a78943b854738ba253be25e4fbd652` |
| SHA-256 | `34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943` |
| SHA3-384 | `6cae85071cb2442ca3094210c82590ca0a32c59e9c921f7a3af71cbc2190a08c163b4b64928dd1d65e1d16e440796b27` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13B3502982309DE01D8A35BF51D70E7BA1BB56ED4A901D3138EEEBDFB79367042805293` |
| SSDEEP | `24576:58RKOfBCqxWRFDEKPa7U+98So3DyfRp3Uy+Q3:58FfQLON7U+98t+p3F+Q3` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_091_34074ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943"
    family = "Formbook"
    file_name = "34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:41"
  condition:
    hash.sha256(0, filesize) == "34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943"
}
```

### Sample 92: `23ec48eb6bd59bbf`

| Field | Value |
|---|---|
| SHA-256 | `23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0` |
| Family label | `Formbook` |
| File name | `23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0` |
| File type | `exe` |
| First seen | `2026-09-04 20:34:34` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59a2ba1e142177f44e4a23c5f9aa4b02` |
| SHA-1 | `59064ae941fa204723a58ee635723575437d6b5d` |
| SHA-256 | `23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0` |
| SHA3-384 | `55f18e2b268b5969b0f177daa8c88f56788dd2b64f3e6e87b29f8ee7e6ce8ca10a364843919b7ece5336509bbbb32469` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15A3501541319CE02C8A24BF49D71E3F91BB96ED4A910D3678EEA7DEB797A71028143C3` |
| SSDEEP | `24576:m4RZa0VzMJVIyap6582v4/MMnOrhUa/AnfwGaSAL8zUlF:m4Da0VCxapR2A3exAIGo8zUlF` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_092_23ec48eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0"
    family = "Formbook"
    file_name = "23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:34"
  condition:
    hash.sha256(0, filesize) == "23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0"
}
```

### Sample 93: `4a63d86e569952d1`

| Field | Value |
|---|---|
| SHA-256 | `4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71` |
| Family label | `Vidar` |
| File name | `4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71` |
| File type | `exe` |
| First seen | `2026-09-04 20:34:17` |
| Reporter | `adrian__luca` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50bff58a10708c338d0eade1a8b0503c` |
| SHA-1 | `0ff30d8a4617af07bd680d40f0ab9f252529ae0f` |
| SHA-256 | `4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71` |
| SHA3-384 | `fefe47ebd27b79ba1f0f19d1eed26c7c64cc15ab3d5dfb2687c0dc4a69052cb1f81956e7a7f6e4c11b7c06089ff66bde` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11F267C077A9549F9C0A9E735C8BB5221B670BC0D8B3133E32E506AB82F723D19D79B54` |
| SSDEEP | `49152:8ZSl4qa9WP9TI3eTsIcu6nbQ3OBRAqRr1sJwCoTx3P6Jiq5GlWxbg6:8Ea3AzzqDsOtTx3Ciq5GlW` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_093_4a63d86e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71"
    family = "Vidar"
    file_name = "4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:17"
  condition:
    hash.sha256(0, filesize) == "4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71"
}
```

### Sample 94: `e6d3b823ae49aaad`

| Field | Value |
|---|---|
| SHA-256 | `e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5` |
| Family label | `unknown` |
| File name | `e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5` |
| File type | `exe` |
| First seen | `2026-09-04 20:34:10` |
| Reporter | `adrian__luca` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `047ae3c7a96a55c3235b841db7beffeb` |
| SHA-1 | `a019c5240252fbb040a02516c26cc8a15d411e9b` |
| SHA-256 | `e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5` |
| SHA3-384 | `8b814bd8a0e318a610b5cbb051a7769ac69e3f6b8c24660b2c9fe771a45d4cd57fa4ba45e9ddc38f850d450c2384ce4f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T181158B61E80D9A4ACA3C07F993350E54DEF09E1A5622DBDF6BD833E91A7E6403D1F442` |
| SSDEEP | `24576:gF8pgYuwgjcUQ1vF35GPfUJ/sECkZEM4:gapgYuLjSvh5GPfUJyPM` |
| ICON-DHASH | `00ecd0f8f0f0c400` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_e6d3b823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5"
    family = "unknown"
    file_name = "e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:10"
  condition:
    hash.sha256(0, filesize) == "e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5"
}
```

### Sample 95: `7a4cbb98720e06ee`

| Field | Value |
|---|---|
| SHA-256 | `7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb` |
| Family label | `unknown` |
| File name | `7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb` |
| File type | `exe` |
| First seen | `2026-09-04 20:34:04` |
| Reporter | `adrian__luca` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b27184887250528f83319e53c62a9a71` |
| SHA-1 | `a4d449c17ed2caacbf321ac65a6e9c2587218ef2` |
| SHA-256 | `7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb` |
| SHA3-384 | `1fb15dc4f43c57ec08879e501bce1be2f7c7c12fb4b448e9089b2a638fc8abc4f359224fcd5d403d15440ccb1d70d381` |
| TLSH | `T142752398160EF802DA0257755D70E7F617B44E95E921E3438EFCFCBBBD2B2A828451D2` |
| SSDEEP | `49152:Sn8yxvBTHZTu+icuvL57Scc2VPAhpUgJ9PXT:S8yV9HZEcuvL59FgpnPj` |
| ICON-DHASH | `f0f0b8f9d9b0ccf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_7a4cbb98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb"
    family = "unknown"
    file_name = "7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:04"
  condition:
    hash.sha256(0, filesize) == "7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb"
}
```

### Sample 96: `52740db0771ee580`

| Field | Value |
|---|---|
| SHA-256 | `52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4` |
| Family label | `AgentTesla` |
| File name | `52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4` |
| File type | `exe` |
| First seen | `2026-09-04 20:33:51` |
| Reporter | `adrian__luca` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a33b49d19660334e700e0c1f99966de` |
| SHA-1 | `8b7575e1c923d716dc06573b565a0210e933ed98` |
| SHA-256 | `52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4` |
| SHA3-384 | `aca7e8c6c4294fb47d54e5cfec2154880442c877f8f516d550cb50be0f8ad5bb916b5c7a2a8a3c53681b3a5776cea04f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F2350158372ADF06D9634BF84D20EBB407B55D95AE21D3038EEA7CEB7839B1418192D3` |
| SSDEEP | `24576:qRygjnryS0281QwzKFul0CEa8Gm84JUg70A:q8gjrB8HWQpb8GmbUgQA` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_096_52740db0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4"
    family = "AgentTesla"
    file_name = "52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:51"
  condition:
    hash.sha256(0, filesize) == "52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4"
}
```

### Sample 97: `03f46cf9a2de612f`

| Field | Value |
|---|---|
| SHA-256 | `03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964` |
| Family label | `Formbook` |
| File name | `03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964` |
| File type | `exe` |
| First seen | `2026-09-04 20:33:45` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a5ea70bc0ca5362aacaa0db8564e415` |
| SHA-1 | `293a9e19154301900dd1d43b9ba5cf789101f830` |
| SHA-256 | `03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964` |
| SHA3-384 | `eec068ef0f8680d627060d2a3a271fba29494ab554d1db465575d1cc13fd159f6f85c35918004cc0ff5c364ee13bf92a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FF35E19C3204F88FC917CA719960EEB4AA606D65970BC303D5E72DEBFD1D15B9E081E2` |
| SSDEEP | `24576:oTR+JhGIaVdJJtcod9mJEvgqtTgg8s936Slpr3nmJ:8sanJJZddvpkts936Ir3` |
| ICON-DHASH | `f0f0b8f9d9b0ccf0` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_097_03f46cf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964"
    family = "Formbook"
    file_name = "03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:45"
  condition:
    hash.sha256(0, filesize) == "03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964"
}
```

### Sample 98: `ba2085d015f02bc9`

| Field | Value |
|---|---|
| SHA-256 | `ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f` |
| Family label | `unknown` |
| File name | `ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f` |
| File type | `exe` |
| First seen | `2026-09-04 20:33:39` |
| Reporter | `adrian__luca` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `456545ae3f497a16dc0c20484659e0cc` |
| SHA-1 | `a3dc2009a6815d386b857a86bfa08d8bc8c76c3e` |
| SHA-256 | `ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f` |
| SHA3-384 | `2359f78b1b14200d722f4203411fd4f26c9ee8b7f8751b4dcb9b5701df4c4f56f73c4d65068f8602289c4c77fcfb3ae5` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1100733C043C24B66F8EBF43E45ABE151F172F450973289CF9BA882653F6B1E14A39B51` |
| SSDEEP | `393216:MwqrO1MUdq1B7/RVRxOgggHsnOTqi2L0pibww4a7:UrO1MUg1FBxtgO2iQ0pCww4` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_ba2085d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f"
    family = "unknown"
    file_name = "ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:39"
  condition:
    hash.sha256(0, filesize) == "ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f"
}
```

### Sample 99: `d62e084a3f4770b1`

| Field | Value |
|---|---|
| SHA-256 | `d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0` |
| Family label | `Formbook` |
| File name | `d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0` |
| File type | `exe` |
| First seen | `2026-09-04 20:33:31` |
| Reporter | `adrian__luca` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e05fbd283c8ee39438fe1fb51c594015` |
| SHA-1 | `3ce31f8ead18f682e3daa7edac3e762c79e210a1` |
| SHA-256 | `d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0` |
| SHA3-384 | `60e09e53c4bafaf65431d92dce792e4ed0328c596cbc63c444727f3ce0c280c4b4b58e583a1eb70da0d81a700d06c587` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19E35126C260ACC03CD434BB99D71E7F92BB45ED8A911D3138EF97DA7BC7621528492C1` |
| SSDEEP | `24576:vUlRojoYb/xnI0dQy/SahlHIniUIO+sxI7Tp:vUlGI0hDH4IO+si7Tp` |
| ICON-DHASH | `f0f0b8f9d9b0ccf0` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_099_d62e084a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0"
    family = "Formbook"
    file_name = "d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:31"
  condition:
    hash.sha256(0, filesize) == "d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0"
}
```

### Sample 100: `750343b29466f625`

| Field | Value |
|---|---|
| SHA-256 | `750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f` |
| Family label | `DarkTortilla` |
| File name | `750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f` |
| File type | `exe` |
| First seen | `2026-09-04 20:33:24` |
| Reporter | `adrian__luca` |
| Tags | `DarkTortilla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed2972345edb2d887052dccaff556aa8` |
| SHA-1 | `1bd1099ae886df044bd5c1f1a1a5f17344708070` |
| SHA-256 | `750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f` |
| SHA3-384 | `ce380f483608cccd75c97e15baadf38ba9e6d0265b664f41e5f4237fa7f5de562ce5d8c7d19756ebb99c75c264bac626` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13F05F1350D436F84CB3D5BB8C0262D9963F1D41B9222EB6A3FED01F91AB7BC46E26151` |
| SSDEEP | `24576:dNEuwgjcUQ1vF35GPfUJ/sECkZEMd6itIK:dNEuLjSvh5GPfUJyPMF` |

#### Technical Assessment

- The sample is tracked as `DarkTortilla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkTortilla_100_750343b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f"
    family = "DarkTortilla"
    file_name = "750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:24"
  condition:
    hash.sha256(0, filesize) == "750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f"
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
 * Generated: 2026-09-05T04:38:05.276877+00:00
 */

rule MalwareBazaar_unknown_001_6877dea3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6877dea3a0f91bfe2c0271f70d53517bc740c51018260bf2eb255bc7882187f8"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-05 04:27:24"
  condition:
    hash.sha256(0, filesize) == "6877dea3a0f91bfe2c0271f70d53517bc740c51018260bf2eb255bc7882187f8"
}

rule MalwareBazaar_Mirai_002_a08f7292
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a08f7292a5ed30ddd0b4447f1c5aeab1a84b254bad852e872f8f35109cc0fdc0"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-05 04:06:23"
  condition:
    hash.sha256(0, filesize) == "a08f7292a5ed30ddd0b4447f1c5aeab1a84b254bad852e872f8f35109cc0fdc0"
}

rule MalwareBazaar_Mirai_003_cbae88f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbae88f84ac1629c5fc5fbb19763c9b67f4a9ba1accbbe2530998581c325e2df"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-05 04:05:27"
  condition:
    hash.sha256(0, filesize) == "cbae88f84ac1629c5fc5fbb19763c9b67f4a9ba1accbbe2530998581c325e2df"
}

rule MalwareBazaar_unknown_004_d1554035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d155403501f66f0064a7c0876b266ff1a3425f85582f732df7e419ef5b2b3423"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-05 03:58:42"
  condition:
    hash.sha256(0, filesize) == "d155403501f66f0064a7c0876b266ff1a3425f85582f732df7e419ef5b2b3423"
}

rule MalwareBazaar_Vidar_005_53306b5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14"
    family = "Vidar"
    file_name = "53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14.bin"
    file_type = "exe"
    first_seen = "2026-09-05 03:52:25"
  condition:
    hash.sha256(0, filesize) == "53306b5aadd16a12a77060dae304b0030287d2f53ca6973fabc0b4a7ab85cd14"
}

rule MalwareBazaar_unknown_006_40cb6cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40cb6cd334578a3a3f5569a5928fdae1ba4ee4bad1cdcb46c026a30b6af692eb"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-05 03:51:22"
  condition:
    hash.sha256(0, filesize) == "40cb6cd334578a3a3f5569a5928fdae1ba4ee4bad1cdcb46c026a30b6af692eb"
}

rule MalwareBazaar_Mirai_007_86c09b9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c09b9ec3f944f4d29e89554da7434a54fa79c48eab2099cc5401d17c745d7e"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-05 03:45:27"
  condition:
    hash.sha256(0, filesize) == "86c09b9ec3f944f4d29e89554da7434a54fa79c48eab2099cc5401d17c745d7e"
}

rule MalwareBazaar_Mirai_008_57eac567
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57eac56730e3d0a6e9e67ce5c59be3afd800277f62dc6b2e6d001d7d19d5897e"
    family = "Mirai"
    file_name = "reaver.arm5"
    file_type = "elf"
    first_seen = "2026-09-05 03:45:24"
  condition:
    hash.sha256(0, filesize) == "57eac56730e3d0a6e9e67ce5c59be3afd800277f62dc6b2e6d001d7d19d5897e"
}

rule MalwareBazaar_Mirai_009_52d71009
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d7100937af1772189f62cdc1699143607f13cf1a25bc525f224751a38e6f46"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-05 03:45:22"
  condition:
    hash.sha256(0, filesize) == "52d7100937af1772189f62cdc1699143607f13cf1a25bc525f224751a38e6f46"
}

rule MalwareBazaar_unknown_010_2ed6a048
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6"
    family = "unknown"
    file_name = "2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6.exe"
    file_type = "exe"
    first_seen = "2026-09-05 03:37:45"
  condition:
    hash.sha256(0, filesize) == "2ed6a04833ebe399594d1d6e0439293f4c4792225b95c3043be6d701fe7984d6"
}

rule MalwareBazaar_Mirai_011_554317fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "554317fb54d7c777992869e4a184aed94a54a7a2e44534f6ead0fb3c58e4de19"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-05 03:23:20"
  condition:
    hash.sha256(0, filesize) == "554317fb54d7c777992869e4a184aed94a54a7a2e44534f6ead0fb3c58e4de19"
}

rule MalwareBazaar_Mirai_012_fc5ee242
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc5ee2427b727ce7ad83502e4a8b960854b1548598a6eccb675070d5e7a47e0a"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-05 03:22:25"
  condition:
    hash.sha256(0, filesize) == "fc5ee2427b727ce7ad83502e4a8b960854b1548598a6eccb675070d5e7a47e0a"
}

rule MalwareBazaar_unknown_013_2c3b4870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c3b48702fb125878af303258f631c81077e60b0659e599088ce2dc6a2d2963d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:20:51"
  condition:
    hash.sha256(0, filesize) == "2c3b48702fb125878af303258f631c81077e60b0659e599088ce2dc6a2d2963d"
}

rule MalwareBazaar_unknown_014_93b33d36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93b33d365a5d3016ff3c86e1516c8c1223aa0b4942bc459ba58cb79cddda000b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:19:21"
  condition:
    hash.sha256(0, filesize) == "93b33d365a5d3016ff3c86e1516c8c1223aa0b4942bc459ba58cb79cddda000b"
}

rule MalwareBazaar_unknown_015_8f70cd16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f70cd16856d692e09253287abaca07008288ea2293333b3fe4fb59ad5e1d50b"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:13:30"
  condition:
    hash.sha256(0, filesize) == "8f70cd16856d692e09253287abaca07008288ea2293333b3fe4fb59ad5e1d50b"
}

rule MalwareBazaar_unknown_016_23d0e81b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23d0e81b02f44b5a50cd6af26b58a702a8eba562c7d1ec1ea308ccd33dbba08c"
    family = "unknown"
    file_name = "runner.ps1"
    file_type = "ps1"
    first_seen = "2026-09-05 03:12:00"
  condition:
    hash.sha256(0, filesize) == "23d0e81b02f44b5a50cd6af26b58a702a8eba562c7d1ec1ea308ccd33dbba08c"
}

rule MalwareBazaar_unknown_017_831f77ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "831f77ba6b896c35133f7e01d7ac48ae09e3224ace0ccbfb98477b8552c3517d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 03:11:42"
  condition:
    hash.sha256(0, filesize) == "831f77ba6b896c35133f7e01d7ac48ae09e3224ace0ccbfb98477b8552c3517d"
}

rule MalwareBazaar_unknown_018_fdc24883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdc24883a1d95bd21621c7426124fefba49bfcc959c1c774a4d5dab6893689fc"
    family = "unknown"
    file_name = "setup.hta"
    file_type = "hta"
    first_seen = "2026-09-05 03:04:14"
  condition:
    hash.sha256(0, filesize) == "fdc24883a1d95bd21621c7426124fefba49bfcc959c1c774a4d5dab6893689fc"
}

rule MalwareBazaar_unknown_019_3c455cdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c455cdf154c0a723e6d34dd14af146a25ab207faf28e081bf8aeb6826e5a701"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-05 03:00:51"
  condition:
    hash.sha256(0, filesize) == "3c455cdf154c0a723e6d34dd14af146a25ab207faf28e081bf8aeb6826e5a701"
}

rule MalwareBazaar_Mirai_020_afcf3bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afcf3bfe4743d479c912286b016e4d17c1558f28614cff406ae622db5a338da1"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-05 02:58:15"
  condition:
    hash.sha256(0, filesize) == "afcf3bfe4743d479c912286b016e4d17c1558f28614cff406ae622db5a338da1"
}

rule MalwareBazaar_Mirai_021_b3177fcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3177fccd6f81b6904d78e67066aa637d5b9a35c54de5210e5e390c771d2738c"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-05 02:58:13"
  condition:
    hash.sha256(0, filesize) == "b3177fccd6f81b6904d78e67066aa637d5b9a35c54de5210e5e390c771d2738c"
}

rule MalwareBazaar_Mirai_022_758a7616
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "758a76168bef9ed2c5c164cdfa1d8baa2937ed0ea94a3cfe7d79f576da259fa9"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-05 02:57:49"
  condition:
    hash.sha256(0, filesize) == "758a76168bef9ed2c5c164cdfa1d8baa2937ed0ea94a3cfe7d79f576da259fa9"
}

rule MalwareBazaar_Mirai_023_f253fada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f253fada27a0dea9f9dd0e4735d5c7a09690658b18f4f710da562a4a9d89166d"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-05 02:57:48"
  condition:
    hash.sha256(0, filesize) == "f253fada27a0dea9f9dd0e4735d5c7a09690658b18f4f710da562a4a9d89166d"
}

rule MalwareBazaar_unknown_024_ef10e849
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc"
    family = "unknown"
    file_name = "ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc.exe"
    file_type = "exe"
    first_seen = "2026-09-05 02:52:47"
  condition:
    hash.sha256(0, filesize) == "ef10e849bf04c968424f7bba0fd2417e8b71122fa5de158d0ed1754a2bf4f6dc"
}

rule MalwareBazaar_CoinMiner_025_0047d289
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c"
    family = "CoinMiner"
    file_name = "0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c.exe"
    file_type = "exe"
    first_seen = "2026-09-05 02:27:53"
  condition:
    hash.sha256(0, filesize) == "0047d289274e4bb5158fbc22f96f0137bbcb6185f1ca028558ad60dbc377d14c"
}

rule MalwareBazaar_unknown_026_e380c361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e380c3616758bce69f520388bcc53199e1a731aee811f9f088194c45bacfdc0c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 02:12:22"
  condition:
    hash.sha256(0, filesize) == "e380c3616758bce69f520388bcc53199e1a731aee811f9f088194c45bacfdc0c"
}

rule MalwareBazaar_unknown_027_162172aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "162172aaf538da54d65cf8bdaf9894b0e7f0f3d2810e2791b81f1257599d338e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-05 01:55:18"
  condition:
    hash.sha256(0, filesize) == "162172aaf538da54d65cf8bdaf9894b0e7f0f3d2810e2791b81f1257599d338e"
}

rule MalwareBazaar_Loki_028_c2386ea7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2386ea75e2c185bee094b845498e6c750217349cf3f965b3832b39fad241c09"
    family = "Loki"
    file_name = "8B62D1FAE5707198C74C9BD3E27AA922.exe"
    file_type = "exe"
    first_seen = "2026-09-05 01:55:06"
  condition:
    hash.sha256(0, filesize) == "c2386ea75e2c185bee094b845498e6c750217349cf3f965b3832b39fad241c09"
}

rule MalwareBazaar_unknown_029_9aa644bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aa644bd41794a457cd899ba48e8c599e832825b8dc40ac8b76b2f34884dfbb2"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-05 01:31:52"
  condition:
    hash.sha256(0, filesize) == "9aa644bd41794a457cd899ba48e8c599e832825b8dc40ac8b76b2f34884dfbb2"
}

rule MalwareBazaar_unknown_030_24f38736
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6"
    family = "unknown"
    file_name = "24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6.elf"
    file_type = "elf"
    first_seen = "2026-09-05 00:02:55"
  condition:
    hash.sha256(0, filesize) == "24f3873639dd30d0ad350f6005dc616b7851af4a1f296f119e1c45b020c5fcd6"
}

rule MalwareBazaar_unknown_031_91db162f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4"
    family = "unknown"
    file_name = "91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4.exe"
    file_type = "exe"
    first_seen = "2026-09-05 00:02:47"
  condition:
    hash.sha256(0, filesize) == "91db162fba6210d1d869ca63a2b382a40ee106c14402fdd8dbeb24ab6af7f9e4"
}

rule MalwareBazaar_unknown_032_a8b96a44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8b96a44c99b1201c36ce05c5c66dfa78d4776705d4dd3fda4dfece96f69a887"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 22:57:01"
  condition:
    hash.sha256(0, filesize) == "a8b96a44c99b1201c36ce05c5c66dfa78d4776705d4dd3fda4dfece96f69a887"
}

rule MalwareBazaar_unknown_033_72ecf195
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e"
    family = "unknown"
    file_name = "72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e.bin"
    file_type = "unknown"
    first_seen = "2026-09-04 22:52:51"
  condition:
    hash.sha256(0, filesize) == "72ecf19512cb15286a410a2b6ccf6b9e5609a87febffdc7f08d9f6ba12a16b0e"
}

rule MalwareBazaar_unknown_034_d520fe67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d520fe67dbf76530fe2cd90cb205607ff38cc3621dc849e44080663cdc9f6f87"
    family = "unknown"
    file_name = "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e.exe"
    file_type = "exe"
    first_seen = "2026-09-04 22:48:12"
  condition:
    hash.sha256(0, filesize) == "d520fe67dbf76530fe2cd90cb205607ff38cc3621dc849e44080663cdc9f6f87"
}

rule MalwareBazaar_unknown_035_5efaa1a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e"
    family = "unknown"
    file_name = "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e.exe"
    file_type = "exe"
    first_seen = "2026-09-04 22:47:48"
  condition:
    hash.sha256(0, filesize) == "5efaa1a7deb7076091d316c3a896c07667aa5633fe212a9460721c2db57d3d9e"
}

rule MalwareBazaar_unknown_036_b7150d0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7150d0e8c628a0bcd1deffb9c1f94212b477605ddb3144a4a56c300cb461323"
    family = "unknown"
    file_name = "poop"
    file_type = "elf"
    first_seen = "2026-09-04 22:31:06"
  condition:
    hash.sha256(0, filesize) == "b7150d0e8c628a0bcd1deffb9c1f94212b477605ddb3144a4a56c300cb461323"
}

rule MalwareBazaar_unknown_037_dd3d27e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd3d27e0797ea47ffd44ccf1bd3cc11d401f69bc6c78ca0a6ac966cd330fb412"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 22:31:04"
  condition:
    hash.sha256(0, filesize) == "dd3d27e0797ea47ffd44ccf1bd3cc11d401f69bc6c78ca0a6ac966cd330fb412"
}

rule MalwareBazaar_Mirai_038_64927e93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64927e9384b972ba5b2b677b2c31dc93417072222054f5a7d038e695367ed13d"
    family = "Mirai"
    file_name = "reaver.arm5"
    file_type = "elf"
    first_seen = "2026-09-04 22:24:31"
  condition:
    hash.sha256(0, filesize) == "64927e9384b972ba5b2b677b2c31dc93417072222054f5a7d038e695367ed13d"
}

rule MalwareBazaar_unknown_039_672a0f0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "672a0f0d50c1454cdcbde731cee21fccfe7fb0329030a488bcb947ef5d3526fc"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 22:24:30"
  condition:
    hash.sha256(0, filesize) == "672a0f0d50c1454cdcbde731cee21fccfe7fb0329030a488bcb947ef5d3526fc"
}

rule MalwareBazaar_unknown_040_2c7d28fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c7d28fa5a5563968536784beb4f0addae0f53a4cdca5c58eac8267abbd81dcc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 22:22:51"
  condition:
    hash.sha256(0, filesize) == "2c7d28fa5a5563968536784beb4f0addae0f53a4cdca5c58eac8267abbd81dcc"
}

rule MalwareBazaar_unknown_041_9b93ef7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b93ef7f3659f4b21fc530b70d81bd1ebcccd99861bef2b1117a0bf6298bdda8"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 22:08:32"
  condition:
    hash.sha256(0, filesize) == "9b93ef7f3659f4b21fc530b70d81bd1ebcccd99861bef2b1117a0bf6298bdda8"
}

rule MalwareBazaar_Mirai_042_29ebe990
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29ebe9906064b9935afbbe6c3783f546098342128d767ed3c9730565df2329a2"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 22:07:17"
  condition:
    hash.sha256(0, filesize) == "29ebe9906064b9935afbbe6c3783f546098342128d767ed3c9730565df2329a2"
}

rule MalwareBazaar_Mirai_043_3df4a3f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3df4a3f6a4ea570ee1917103fab9f146fc5ecceed46c0b6077e8371d1ea2fcbe"
    family = "Mirai"
    file_name = "reaver.x86_64"
    file_type = "elf"
    first_seen = "2026-09-04 22:06:50"
  condition:
    hash.sha256(0, filesize) == "3df4a3f6a4ea570ee1917103fab9f146fc5ecceed46c0b6077e8371d1ea2fcbe"
}

rule MalwareBazaar_Mirai_044_9d91a269
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d91a2692f7309ad560604580751fe76e0dc88d36c2f0fc1910201277496f67e"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-04 22:01:25"
  condition:
    hash.sha256(0, filesize) == "9d91a2692f7309ad560604580751fe76e0dc88d36c2f0fc1910201277496f67e"
}

rule MalwareBazaar_Mirai_045_cbc37ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbc37ec8e2ef9df58cf971c805e8b110c915586546e8448055bb9e631cd65e35"
    family = "Mirai"
    file_name = "reaver.arm6"
    file_type = "elf"
    first_seen = "2026-09-04 22:00:47"
  condition:
    hash.sha256(0, filesize) == "cbc37ec8e2ef9df58cf971c805e8b110c915586546e8448055bb9e631cd65e35"
}

rule MalwareBazaar_Mirai_046_d3f5425d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f5425d205556ab888dee13ebd73f7249fa2ec50fd4a4cb1c3dcb0ea5d7a405"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-04 21:57:15"
  condition:
    hash.sha256(0, filesize) == "d3f5425d205556ab888dee13ebd73f7249fa2ec50fd4a4cb1c3dcb0ea5d7a405"
}

rule MalwareBazaar_Mirai_047_6198980d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6198980d9ffa3cf6be3b50bb4c4673e0c92e1cd28f690928a6657e6a62ea32ea"
    family = "Mirai"
    file_name = "reaver.arm"
    file_type = "elf"
    first_seen = "2026-09-04 21:56:25"
  condition:
    hash.sha256(0, filesize) == "6198980d9ffa3cf6be3b50bb4c4673e0c92e1cd28f690928a6657e6a62ea32ea"
}

rule MalwareBazaar_Mirai_048_eccfdfc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eccfdfc31b719a4671a729ea4ed7cc006952640d7c619b1ed5b914093e14783c"
    family = "Mirai"
    file_name = "reaver.mpsl"
    file_type = "elf"
    first_seen = "2026-09-04 21:56:24"
  condition:
    hash.sha256(0, filesize) == "eccfdfc31b719a4671a729ea4ed7cc006952640d7c619b1ed5b914093e14783c"
}

rule MalwareBazaar_unknown_049_2b93b59a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2"
    family = "unknown"
    file_name = "2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2.bin"
    file_type = "exe"
    first_seen = "2026-09-04 21:50:13"
  condition:
    hash.sha256(0, filesize) == "2b93b59a1ae132e8c28ade72e560d11475c1c5870a9baf66deb4cd178812ddd2"
}

rule MalwareBazaar_unknown_050_082695e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "082695e70ea1a37c01247815535cfe37d3480fbd0dbebee2179be96d80c3cfd7"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 21:48:54"
  condition:
    hash.sha256(0, filesize) == "082695e70ea1a37c01247815535cfe37d3480fbd0dbebee2179be96d80c3cfd7"
}

rule MalwareBazaar_unknown_051_42a06840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a06840551bf6478aa324a3c477157a6440b7de74e6229f32b298a5c9e6a939"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-04 21:48:37"
  condition:
    hash.sha256(0, filesize) == "42a06840551bf6478aa324a3c477157a6440b7de74e6229f32b298a5c9e6a939"
}

rule MalwareBazaar_Mirai_052_a7d91740
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7d91740269f25f7b62aa376f08532500df079a4ba4af229449e1a938dd6f081"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-04 21:38:18"
  condition:
    hash.sha256(0, filesize) == "a7d91740269f25f7b62aa376f08532500df079a4ba4af229449e1a938dd6f081"
}

rule MalwareBazaar_Mirai_053_0efe5561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0efe556123f0be9bbad8690e658ee018d25c5879c34f12a3de6b3b2bfe28868b"
    family = "Mirai"
    file_name = "reaver.mips"
    file_type = "elf"
    first_seen = "2026-09-04 21:37:31"
  condition:
    hash.sha256(0, filesize) == "0efe556123f0be9bbad8690e658ee018d25c5879c34f12a3de6b3b2bfe28868b"
}

rule MalwareBazaar_Mirai_054_1cf4ab73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf4ab73a73e64a3ab57f10dff4a60144023bb16edba69ce53ea5bb940d54b47"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-04 21:34:17"
  condition:
    hash.sha256(0, filesize) == "1cf4ab73a73e64a3ab57f10dff4a60144023bb16edba69ce53ea5bb940d54b47"
}

rule MalwareBazaar_Mirai_055_dcc1a739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcc1a73987b9970189e1b62e30a527844bb76500e5201f2e6848c79826ec2628"
    family = "Mirai"
    file_name = "reaver.x86"
    file_type = "elf"
    first_seen = "2026-09-04 21:34:02"
  condition:
    hash.sha256(0, filesize) == "dcc1a73987b9970189e1b62e30a527844bb76500e5201f2e6848c79826ec2628"
}

rule MalwareBazaar_unknown_056_d191d81f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae"
    family = "unknown"
    file_name = "d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae.exe"
    file_type = "exe"
    first_seen = "2026-09-04 21:32:46"
  condition:
    hash.sha256(0, filesize) == "d191d81feb30d77ed561efa1167841e37851f57333940b7ad09a3959556ea0ae"
}

rule MalwareBazaar_unknown_057_b38bd496
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38bd4967f3f715046589672a5dda1e54693823298c1bfd5ed94d50ab9390cb4"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-04 21:29:48"
  condition:
    hash.sha256(0, filesize) == "b38bd4967f3f715046589672a5dda1e54693823298c1bfd5ed94d50ab9390cb4"
}

rule MalwareBazaar_unknown_058_ed9033a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed9033a7d6b6114b657cc7405a4ef96e38c9c5141ef30c8dd06250ef750ddd5a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 21:24:37"
  condition:
    hash.sha256(0, filesize) == "ed9033a7d6b6114b657cc7405a4ef96e38c9c5141ef30c8dd06250ef750ddd5a"
}

rule MalwareBazaar_unknown_059_f08a43f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f08a43f566e84eb22984fbc81d2ef8ca94d732362ca6b2324edf9a95ea7e7f58"
    family = "unknown"
    file_name = "install_q2.0.02.exe"
    file_type = "exe"
    first_seen = "2026-09-04 21:12:10"
  condition:
    hash.sha256(0, filesize) == "f08a43f566e84eb22984fbc81d2ef8ca94d732362ca6b2324edf9a95ea7e7f58"
}

rule MalwareBazaar_unknown_060_1fbdcb87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b"
    family = "unknown"
    file_name = "1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b.exe"
    file_type = "exe"
    first_seen = "2026-09-04 21:07:51"
  condition:
    hash.sha256(0, filesize) == "1fbdcb873815e0bbb99531777ab9c5cb853078708ead0b0436191a66f59bb02b"
}

rule MalwareBazaar_Gafgyt_061_03ce4d70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03ce4d70c20051ec6980cc7169086e38521510416aab1a2e2869e7aac7b57a5a"
    family = "Gafgyt"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-09-04 21:07:44"
  condition:
    hash.sha256(0, filesize) == "03ce4d70c20051ec6980cc7169086e38521510416aab1a2e2869e7aac7b57a5a"
}

rule MalwareBazaar_unknown_062_ff13e60a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff13e60a92588a848dced4cdd37b48302eef60ee22b7fe5256ffe819ad6b7279"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-04 21:03:20"
  condition:
    hash.sha256(0, filesize) == "ff13e60a92588a848dced4cdd37b48302eef60ee22b7fe5256ffe819ad6b7279"
}

rule MalwareBazaar_unknown_063_8a102756
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a1027560582bf2c61f554529dce737ba1d74a6b6a7d50ec8f63a3f48559170e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 21:03:18"
  condition:
    hash.sha256(0, filesize) == "8a1027560582bf2c61f554529dce737ba1d74a6b6a7d50ec8f63a3f48559170e"
}

rule MalwareBazaar_unknown_064_cf01b2bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf01b2bd8b6496ed9677cb33f83cbe34158be35be63baa182aa99e7b1d83fe96"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-04 20:56:43"
  condition:
    hash.sha256(0, filesize) == "cf01b2bd8b6496ed9677cb33f83cbe34158be35be63baa182aa99e7b1d83fe96"
}

rule MalwareBazaar_unknown_065_16a5c2c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451"
    family = "unknown"
    file_name = "16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451.exe"
    file_type = "exe"
    first_seen = "2026-09-04 20:47:46"
  condition:
    hash.sha256(0, filesize) == "16a5c2c89d4adca402b6ea15a6412a811140962dfdfbd737eda65019c87fe451"
}

rule MalwareBazaar_Gafgyt_066_8e204247
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f"
    family = "Gafgyt"
    file_name = "8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:42:58"
  condition:
    hash.sha256(0, filesize) == "8e204247ddb0abbf58f91142a2aeb856d8e952e4744dd7feb23c001984e5629f"
}

rule MalwareBazaar_Gafgyt_067_d6dd1d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2"
    family = "Gafgyt"
    file_name = "d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:42:53"
  condition:
    hash.sha256(0, filesize) == "d6dd1d0f185a58f3c3a59df980606137b67a670032eb44d65d1a0c191e2344a2"
}

rule MalwareBazaar_Gafgyt_068_a34902f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e"
    family = "Gafgyt"
    file_name = "a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:42:47"
  condition:
    hash.sha256(0, filesize) == "a34902f172965c2a8d0d3d0922ae70ebee739de1d8348fa4851aad891f6f968e"
}

rule MalwareBazaar_Gafgyt_069_7e3c7557
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6"
    family = "Gafgyt"
    file_name = "7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:19"
  condition:
    hash.sha256(0, filesize) == "7e3c7557ef4a240046a36fbcb74fded6a31ecd305b08c67dc23bbea24fe5b9d6"
}

rule MalwareBazaar_Gafgyt_070_14270dc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90"
    family = "Gafgyt"
    file_name = "14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:14"
  condition:
    hash.sha256(0, filesize) == "14270dc1d285e7eaf8ccf3fee7f0e1bb9efe214c8db357ae5104809671793d90"
}

rule MalwareBazaar_Gafgyt_071_38c27f12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1"
    family = "Gafgyt"
    file_name = "38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:08"
  condition:
    hash.sha256(0, filesize) == "38c27f12e49368ed064a7e36e1d78e8ee9e7cb31cc6aa3cab91b787c8ebf91b1"
}

rule MalwareBazaar_Gafgyt_072_0caeac37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a"
    family = "Gafgyt"
    file_name = "0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:38:01"
  condition:
    hash.sha256(0, filesize) == "0caeac37ccec5e97eac9712e3b238b202c65096553324e95effa1d822992159a"
}

rule MalwareBazaar_Gafgyt_073_fb276f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707"
    family = "Gafgyt"
    file_name = "fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:37:55"
  condition:
    hash.sha256(0, filesize) == "fb276f90f9005122205a63a98bc0ddba8e1499fb79e461e4212e436ddeb89707"
}

rule MalwareBazaar_Gafgyt_074_c1f1f3ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c"
    family = "Gafgyt"
    file_name = "c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c.elf"
    file_type = "elf"
    first_seen = "2026-09-04 20:37:50"
  condition:
    hash.sha256(0, filesize) == "c1f1f3efb4d4eb151024fbbaaf62d35985dc77f7dbc622557b75d85d7ef11c4c"
}

rule MalwareBazaar_Formbook_075_94acc5bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d"
    family = "Formbook"
    file_name = "94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d"
    file_type = "exe"
    first_seen = "2026-09-04 20:37:17"
  condition:
    hash.sha256(0, filesize) == "94acc5bde1e48ce426bc61ea90a8780cf2be98795aaba7d946d5fe9d43b3203d"
}

rule MalwareBazaar_unknown_076_6b677975
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0"
    family = "unknown"
    file_name = "6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:59"
  condition:
    hash.sha256(0, filesize) == "6b677975321dd37920a79dcc2a74ac2c574e45df4b486a3b6a601faea0f87fe0"
}

rule MalwareBazaar_Formbook_077_4b5ed2db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9"
    family = "Formbook"
    file_name = "4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:53"
  condition:
    hash.sha256(0, filesize) == "4b5ed2db4d4c48782e6926d8569f314f6aa36d8d6ec7100eaf1f561bd7626ff9"
}

rule MalwareBazaar_Formbook_078_f989407c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302"
    family = "Formbook"
    file_name = "f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:47"
  condition:
    hash.sha256(0, filesize) == "f989407c3464bf00b3eb103b08d10e2a71a570b423d510161e79acc4c93bc302"
}

rule MalwareBazaar_Vidar_079_60e1739c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90"
    family = "Vidar"
    file_name = "60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:40"
  condition:
    hash.sha256(0, filesize) == "60e1739c404a3bff934dc9d2947eb8faf5139c30a617724007e201a39a7eda90"
}

rule MalwareBazaar_Formbook_080_17b4070f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d"
    family = "Formbook"
    file_name = "17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:34"
  condition:
    hash.sha256(0, filesize) == "17b4070f7739accf08ec200d8fe71a65f407afbca9f3f576f42397519f694d2d"
}

rule MalwareBazaar_unknown_081_04ce455a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22"
    family = "unknown"
    file_name = "04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:28"
  condition:
    hash.sha256(0, filesize) == "04ce455ab1ce258073d3261e137201cdabd87444011fe4a487c4e92d80594e22"
}

rule MalwareBazaar_unknown_082_b3e01ecc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8"
    family = "unknown"
    file_name = "b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:21"
  condition:
    hash.sha256(0, filesize) == "b3e01ecc1e0a7e485e7bb39ae0ebbb39875c4c1a39b2e9414cff53d07926f5e8"
}

rule MalwareBazaar_AgentTesla_083_e3a438c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b"
    family = "AgentTesla"
    file_name = "e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:14"
  condition:
    hash.sha256(0, filesize) == "e3a438c31a0009e3e4a142437198e9a0da3541200efc437e957b73736b91842b"
}

rule MalwareBazaar_Formbook_084_66cccf7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384"
    family = "Formbook"
    file_name = "66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384"
    file_type = "exe"
    first_seen = "2026-09-04 20:36:02"
  condition:
    hash.sha256(0, filesize) == "66cccf7bf799dac1ccec9e512506343116ed04d4e7d076820305fdfcaa06f384"
}

rule MalwareBazaar_MassLogger_085_519de0a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525"
    family = "MassLogger"
    file_name = "519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:50"
  condition:
    hash.sha256(0, filesize) == "519de0a4ed8131067f6364e3ae9f010d962f897e50fbdc7479f1325947b68525"
}

rule MalwareBazaar_AgentTesla_086_1eb04dea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569"
    family = "AgentTesla"
    file_name = "1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:43"
  condition:
    hash.sha256(0, filesize) == "1eb04dea7065dec90a181264f6538fc74e86a6ade162e8cd02c961c154ba0569"
}

rule MalwareBazaar_Formbook_087_b59fe70e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f"
    family = "Formbook"
    file_name = "b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:30"
  condition:
    hash.sha256(0, filesize) == "b59fe70e499dfd4f13fd545ec1892a10dd8a913ebc41190d69ecca2f4135c02f"
}

rule MalwareBazaar_Formbook_088_1d41c332
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2"
    family = "Formbook"
    file_name = "1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:18"
  condition:
    hash.sha256(0, filesize) == "1d41c3329320e5382a800ad08d5dc4559eebeec2eb7b2c204f56729e931e67a2"
}

rule MalwareBazaar_Formbook_089_0c54067d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73"
    family = "Formbook"
    file_name = "0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73"
    file_type = "exe"
    first_seen = "2026-09-04 20:35:06"
  condition:
    hash.sha256(0, filesize) == "0c54067da7fef77b2dec7e57954542f3bea95d4e0c76483efd731e2a5754db73"
}

rule MalwareBazaar_SnakeKeylogger_090_c86bbf6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d"
    family = "SnakeKeylogger"
    file_name = "c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:47"
  condition:
    hash.sha256(0, filesize) == "c86bbf6a553b5475bf6d67fa0874e45ce3bb78709e080cf26475c5d9220e6c4d"
}

rule MalwareBazaar_Formbook_091_34074ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943"
    family = "Formbook"
    file_name = "34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:41"
  condition:
    hash.sha256(0, filesize) == "34074ad3ebee3c726922c815a5a1542ce7b2a5ff5a9233084f7a14d369882943"
}

rule MalwareBazaar_Formbook_092_23ec48eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0"
    family = "Formbook"
    file_name = "23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:34"
  condition:
    hash.sha256(0, filesize) == "23ec48eb6bd59bbfd84c8d05e14862d7bdf736af090de81ddd6dc29b7a0e7ef0"
}

rule MalwareBazaar_Vidar_093_4a63d86e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71"
    family = "Vidar"
    file_name = "4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:17"
  condition:
    hash.sha256(0, filesize) == "4a63d86e569952d1f3a472246b4de8e820bdaa51fa0e3bc0872457d83e388d71"
}

rule MalwareBazaar_unknown_094_e6d3b823
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5"
    family = "unknown"
    file_name = "e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:10"
  condition:
    hash.sha256(0, filesize) == "e6d3b823ae49aaad1c382482142d240a94fe2a8ba6c6e188802622e6bdfbc5a5"
}

rule MalwareBazaar_unknown_095_7a4cbb98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb"
    family = "unknown"
    file_name = "7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb"
    file_type = "exe"
    first_seen = "2026-09-04 20:34:04"
  condition:
    hash.sha256(0, filesize) == "7a4cbb98720e06eeb402f7f66229cadce7ae3173a85772adf4e0ee93ac3822eb"
}

rule MalwareBazaar_AgentTesla_096_52740db0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4"
    family = "AgentTesla"
    file_name = "52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:51"
  condition:
    hash.sha256(0, filesize) == "52740db0771ee580b17561fd4b62659d15a1c9195701f62eb105c2e542e6d3e4"
}

rule MalwareBazaar_Formbook_097_03f46cf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964"
    family = "Formbook"
    file_name = "03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:45"
  condition:
    hash.sha256(0, filesize) == "03f46cf9a2de612f87385012e18af57a87e1d227f1fe2b0e8f6f335073104964"
}

rule MalwareBazaar_unknown_098_ba2085d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f"
    family = "unknown"
    file_name = "ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:39"
  condition:
    hash.sha256(0, filesize) == "ba2085d015f02bc9ab296266b8b44ceb3449842aba44b393e4a00bfe3da5508f"
}

rule MalwareBazaar_Formbook_099_d62e084a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0"
    family = "Formbook"
    file_name = "d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:31"
  condition:
    hash.sha256(0, filesize) == "d62e084a3f4770b1ad2bd13eda19d250b91b222ce6be8e6068ad40fbe28af8b0"
}

rule MalwareBazaar_DarkTortilla_100_750343b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f"
    family = "DarkTortilla"
    file_name = "750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f"
    file_type = "exe"
    first_seen = "2026-09-04 20:33:24"
  condition:
    hash.sha256(0, filesize) == "750343b29466f6258ae1d26c00fcbd3e98f2000d80eb9d2ad9496e9fda5c422f"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

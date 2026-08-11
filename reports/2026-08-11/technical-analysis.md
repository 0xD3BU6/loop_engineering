# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-11

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 618 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 618 |
| Unique family labels | 4 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 73 |
| Mirai | 25 |
| Stealc | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 82 |
| exe | 9 |
| sh | 7 |
| js | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `2d344afeb8650715`

| Field | Value |
|---|---|
| SHA-256 | `2d344afeb8650715faa758e2627f8b038f601f96696e44dfbd286e7edd0d5fc5` |
| Family label | `unknown` |
| File name | `main.mips32el` |
| File type | `elf` |
| First seen | `2026-08-11 02:26:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0635ebf6a2ee2b451277c17db64f679f` |
| SHA-1 | `a66daeea702b6e38e259d3ac241af77b41904a15` |
| SHA-256 | `2d344afeb8650715faa758e2627f8b038f601f96696e44dfbd286e7edd0d5fc5` |
| SHA3-384 | `320b505585399c1c5bacd27ed4c860629283148b43d5eb254d8f3964f7bc2f66266a3d2bc01ea0c8bd90a4758460572f` |
| TLSH | `T187D31A02ED856EFBC01FCD70452DC24A15D65CAA92E5A22F71FCC98CBBBD74646D3888` |
| SSDEEP | `1536:01EilXd/nmKQwLDuPUUQLtv8lxkYTZ7h+4erYJOwZORbBpyjpm4XLMzEr:ZwweLDyUd8lZ2qFZO56` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_2d344afe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d344afeb8650715faa758e2627f8b038f601f96696e44dfbd286e7edd0d5fc5"
    family = "unknown"
    file_name = "main.mips32el"
    file_type = "elf"
    first_seen = "2026-08-11 02:26:59"
  condition:
    hash.sha256(0, filesize) == "2d344afeb8650715faa758e2627f8b038f601f96696e44dfbd286e7edd0d5fc5"
}
```

### Sample 2: `8daccce9ce083a42`

| Field | Value |
|---|---|
| SHA-256 | `8daccce9ce083a42067a491adc429da788aa6cb7477607333b7bd36fc972ce90` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-11 02:20:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `222c8f344635099a50627866467cf347` |
| SHA-1 | `f5fc729007d6d9ed39b1b8ddb37421e5f551c264` |
| SHA-256 | `8daccce9ce083a42067a491adc429da788aa6cb7477607333b7bd36fc972ce90` |
| SHA3-384 | `640a8a95f7c92c408d1f4cfeb252c9250173f70a82ed39b724e020a06b91e1b512821af9a523895b1c43189932698e46` |
| TLSH | `T17DE42955F8809F61C6C529B6F65D42AC73074B79D3EB72068A254B343BEB86B0F3A701` |
| TELFHASH | `t10ff05c28de793cf077d32311d062e01740b605585352368656a21e091ea3fca78c2433` |
| SSDEEP | `12288:nM0OAvgJn8Wei8nwmb4EEripGQ+tP+C/8J7kh34XBFhJ/55F88pqP8aA:MIe0i81LCiwQ+t2C0J4hIb/5a7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_8daccce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8daccce9ce083a42067a491adc429da788aa6cb7477607333b7bd36fc972ce90"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-11 02:20:53"
  condition:
    hash.sha256(0, filesize) == "8daccce9ce083a42067a491adc429da788aa6cb7477607333b7bd36fc972ce90"
}
```

### Sample 3: `c35330f35585c012`

| Field | Value |
|---|---|
| SHA-256 | `c35330f35585c012777b559eb1b19e144d4585ac51c14ae6b7d98a523ab343a7` |
| Family label | `unknown` |
| File name | `main.microblazebe` |
| File type | `elf` |
| First seen | `2026-08-11 02:20:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04eeb2314bbcd6e9715a402560766b97` |
| SHA-1 | `73559e484c49a776b249c52d877522aa6ce096a3` |
| SHA-256 | `c35330f35585c012777b559eb1b19e144d4585ac51c14ae6b7d98a523ab343a7` |
| SHA3-384 | `790ce3c8a4f76449a73086a7cd7eda3391a8e9ea8bac034ba9c53e5e33973745c979420d1fac7d22c61698ed874908a3` |
| TLSH | `T10EA37230F90663B1CC720A38579A2F096E7709199FEB16625D1F633DEE668508B31F8D` |
| SSDEEP | `1536:f24h+EQ3IHpXkuuOluuuuuuuuujZ6hCWvuEnsl8HfUX/Z+deN4l16hxP8+JO/ooM:t0EQ3oZ2WvnmXxXk6LvOAoOivNeUg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_c35330f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c35330f35585c012777b559eb1b19e144d4585ac51c14ae6b7d98a523ab343a7"
    family = "unknown"
    file_name = "main.microblazebe"
    file_type = "elf"
    first_seen = "2026-08-11 02:20:52"
  condition:
    hash.sha256(0, filesize) == "c35330f35585c012777b559eb1b19e144d4585ac51c14ae6b7d98a523ab343a7"
}
```

### Sample 4: `203c2357d1ff6bf0`

| Field | Value |
|---|---|
| SHA-256 | `203c2357d1ff6bf0804a580c31265526608b2b16b7420b54f0fc6125f4da487a` |
| Family label | `unknown` |
| File name | `weakssh_2026-08-05-fleet-reset_bin__tmp_.killer.sh` |
| File type | `sh` |
| First seen | `2026-08-11 02:19:02` |
| Reporter | `sbahra` |
| Tags | `persistence, sh, shell, watchdog` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88bf9092f349542f7a7c69a8951eac39` |
| SHA-256 | `203c2357d1ff6bf0804a580c31265526608b2b16b7420b54f0fc6125f4da487a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_203c2357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "203c2357d1ff6bf0804a580c31265526608b2b16b7420b54f0fc6125f4da487a"
    family = "unknown"
    file_name = "weakssh_2026-08-05-fleet-reset_bin__tmp_.killer.sh"
    file_type = "sh"
    first_seen = "2026-08-11 02:19:02"
  condition:
    hash.sha256(0, filesize) == "203c2357d1ff6bf0804a580c31265526608b2b16b7420b54f0fc6125f4da487a"
}
```

### Sample 5: `b7d0ce1014da1bd0`

| Field | Value |
|---|---|
| SHA-256 | `b7d0ce1014da1bd04bfc8f04175daa5c8e26e86b2bb27a5be05f12ac1a7d6684` |
| Family label | `unknown` |
| File name | `weakssh_2026-08-05-fleet-reset_bin__tmp_flood` |
| File type | `elf` |
| First seen | `2026-08-11 02:19:00` |
| Reporter | `sbahra` |
| Tags | `ddos, elf, flooder, golang` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ea34dcd75eafc5dfd58c7a1f3f5570c` |
| SHA-256 | `b7d0ce1014da1bd04bfc8f04175daa5c8e26e86b2bb27a5be05f12ac1a7d6684` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_b7d0ce10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7d0ce1014da1bd04bfc8f04175daa5c8e26e86b2bb27a5be05f12ac1a7d6684"
    family = "unknown"
    file_name = "weakssh_2026-08-05-fleet-reset_bin__tmp_flood"
    file_type = "elf"
    first_seen = "2026-08-11 02:19:00"
  condition:
    hash.sha256(0, filesize) == "b7d0ce1014da1bd04bfc8f04175daa5c8e26e86b2bb27a5be05f12ac1a7d6684"
}
```

### Sample 6: `aa0c6cdbeb3bc3ce`

| Field | Value |
|---|---|
| SHA-256 | `aa0c6cdbeb3bc3ce07d5060958e1a38e54287bc89e25f6def98b620999ff4f7a` |
| Family label | `unknown` |
| File name | `joomla_2026-08-04-fleet-reset_bin__dev_shm_1oDGzJ` |
| File type | `elf` |
| First seen | `2026-08-11 02:18:56` |
| Reporter | `sbahra` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1084ccba5ce3bf8486919659a753fbed` |
| SHA-256 | `aa0c6cdbeb3bc3ce07d5060958e1a38e54287bc89e25f6def98b620999ff4f7a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_aa0c6cdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa0c6cdbeb3bc3ce07d5060958e1a38e54287bc89e25f6def98b620999ff4f7a"
    family = "unknown"
    file_name = "joomla_2026-08-04-fleet-reset_bin__dev_shm_1oDGzJ"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:56"
  condition:
    hash.sha256(0, filesize) == "aa0c6cdbeb3bc3ce07d5060958e1a38e54287bc89e25f6def98b620999ff4f7a"
}
```

### Sample 7: `0b8e037d160bdb0b`

| Field | Value |
|---|---|
| SHA-256 | `0b8e037d160bdb0b621c975c424f680b814bc438fd492ae376ff3140e209e480` |
| Family label | `unknown` |
| File name | `joomla_2026-08-04-fleet-reset_pid38429.bin` |
| File type | `elf` |
| First seen | `2026-08-11 02:18:54` |
| Reporter | `sbahra` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `158883b02f526ef07e1f29d2ccfdcf34` |
| SHA-1 | `0e539c0e58f9b46c39c6eda39877759ac52b116b` |
| SHA-256 | `0b8e037d160bdb0b621c975c424f680b814bc438fd492ae376ff3140e209e480` |
| SHA3-384 | `b4876fe09fc74683a23572bbabddda84f2449b72f439e1ddc4de3830c247585ee51eea737f169c8e650fe2c20471f905` |
| TLSH | `T16BE533E1669F9EC3915F9B433234A780FA8540B588ABB7ED21FEB1CFB1358D0114E50A` |
| SSDEEP | `98304:AhHI3nvximhEpaogldcVdBwDoMXgaRtOd5Y8VX:ApI3vxfEbgYVmgwQBVX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_0b8e037d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8e037d160bdb0b621c975c424f680b814bc438fd492ae376ff3140e209e480"
    family = "unknown"
    file_name = "joomla_2026-08-04-fleet-reset_pid38429.bin"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:54"
  condition:
    hash.sha256(0, filesize) == "0b8e037d160bdb0b621c975c424f680b814bc438fd492ae376ff3140e209e480"
}
```

### Sample 8: `deaeab9eb43fcf70`

| Field | Value |
|---|---|
| SHA-256 | `deaeab9eb43fcf70d184c209e4bc1077ae6e7e2b182c1cbbc202dfdc053dc01c` |
| Family label | `unknown` |
| File name | `langflow_2026-08-05-react2shell-end_bin__dev_shm_5poLwV4` |
| File type | `elf` |
| First seen | `2026-08-11 02:18:52` |
| Reporter | `sbahra` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdbc3dc63d8fd5528dc02ef49d0baf00` |
| SHA-256 | `deaeab9eb43fcf70d184c209e4bc1077ae6e7e2b182c1cbbc202dfdc053dc01c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_deaeab9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deaeab9eb43fcf70d184c209e4bc1077ae6e7e2b182c1cbbc202dfdc053dc01c"
    family = "unknown"
    file_name = "langflow_2026-08-05-react2shell-end_bin__dev_shm_5poLwV4"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:52"
  condition:
    hash.sha256(0, filesize) == "deaeab9eb43fcf70d184c209e4bc1077ae6e7e2b182c1cbbc202dfdc053dc01c"
}
```

### Sample 9: `d9ae9bf4b810b074`

| Field | Value |
|---|---|
| SHA-256 | `d9ae9bf4b810b07470e786deb6454b8928cba4fe77278b8f4b4f6c5cdcb4e0c4` |
| Family label | `unknown` |
| File name | `joomla_2026-08-05-fleet-reset_pid29905.bin` |
| File type | `elf` |
| First seen | `2026-08-11 02:18:49` |
| Reporter | `sbahra` |
| Tags | `backdoor, elf, mbedtls, rondo` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb2f4872c44f608cb44df465cf3408f7` |
| SHA-256 | `d9ae9bf4b810b07470e786deb6454b8928cba4fe77278b8f4b4f6c5cdcb4e0c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_d9ae9bf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9ae9bf4b810b07470e786deb6454b8928cba4fe77278b8f4b4f6c5cdcb4e0c4"
    family = "unknown"
    file_name = "joomla_2026-08-05-fleet-reset_pid29905.bin"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:49"
  condition:
    hash.sha256(0, filesize) == "d9ae9bf4b810b07470e786deb6454b8928cba4fe77278b8f4b4f6c5cdcb4e0c4"
}
```

### Sample 10: `dcbf7b7f32b4f9b3`

| Field | Value |
|---|---|
| SHA-256 | `dcbf7b7f32b4f9b326b3bf7c8f2548f642b294b8dbe01e02154d8fcc27b7da84` |
| Family label | `unknown` |
| File name | `shai.quarantine.bin` |
| File type | `elf` |
| First seen | `2026-08-11 02:18:46` |
| Reporter | `sbahra` |
| Tags | `aws, bun, credential-harvester, elf, kubernetes, Shai-Hulud, stealer, vault` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79978a6ee9076a50bb55b52ffde5ffd1` |
| SHA-256 | `dcbf7b7f32b4f9b326b3bf7c8f2548f642b294b8dbe01e02154d8fcc27b7da84` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_dcbf7b7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcbf7b7f32b4f9b326b3bf7c8f2548f642b294b8dbe01e02154d8fcc27b7da84"
    family = "unknown"
    file_name = "shai.quarantine.bin"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:46"
  condition:
    hash.sha256(0, filesize) == "dcbf7b7f32b4f9b326b3bf7c8f2548f642b294b8dbe01e02154d8fcc27b7da84"
}
```

### Sample 11: `4c946609323494ac`

| Field | Value |
|---|---|
| SHA-256 | `4c946609323494ac329f2c4347d103595a1d0cebe99bdc39acbe19b3a1562178` |
| Family label | `unknown` |
| File name | `main.power8le` |
| File type | `elf` |
| First seen | `2026-08-11 02:17:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e26a7989eea6c7910c51cdba424933e0` |
| SHA-1 | `9c59589c6fb83684f98693a26e6df4640f3e0d6a` |
| SHA-256 | `4c946609323494ac329f2c4347d103595a1d0cebe99bdc39acbe19b3a1562178` |
| SHA3-384 | `35ab20e4eb301daae4f566941812b81d716af89f93ac9a44bb70d655035109ed58359ff351740f27de2ff19341f76406` |
| TLSH | `T1CAD3E70333487A95DF47A83F9687BE117392B99413518562BB10120FAF76B7ACF0EB49` |
| SSDEEP | `1536:2fB+n4/jxjiJaGwk23p10Z//uNcbMwMmpHk1gN5ozPmPobSUrm7bh:/5JBwk23p1+//PXMmp0M54uPobH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_4c946609
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c946609323494ac329f2c4347d103595a1d0cebe99bdc39acbe19b3a1562178"
    family = "unknown"
    file_name = "main.power8le"
    file_type = "elf"
    first_seen = "2026-08-11 02:17:52"
  condition:
    hash.sha256(0, filesize) == "4c946609323494ac329f2c4347d103595a1d0cebe99bdc39acbe19b3a1562178"
}
```

### Sample 12: `299b568e8d0725a3`

| Field | Value |
|---|---|
| SHA-256 | `299b568e8d0725a31ae143c20554aef27c52a4cb1dbab0b718d997a0adf40c52` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.x86_64` |
| File type | `elf` |
| First seen | `2026-08-11 02:15:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59dc6951cecb0f57ac1ef6408c343151` |
| SHA-1 | `ce8fc0161a59e6b0d31a4ecb2accfb5cb9215a59` |
| SHA-256 | `299b568e8d0725a31ae143c20554aef27c52a4cb1dbab0b718d997a0adf40c52` |
| SHA3-384 | `07d5f902956e8913a6fc023f68d5cb39a9dc60213e5e8ea500ae61b59deb9229aa29068aa0307b4e087384c56877463c` |
| TLSH | `T1C6F34A17BAC184FDC8DAC1745BAFB13AE931B45D0238726B27D4EE322E4DE304A6D954` |
| TELFHASH | `t18451cb782ea6395831c3d72ab74fe5acfd7300111de270e8ae232dcace5278c4d1146a` |
| SSDEEP | `3072:93IgMevjGrLhEqzGUlkOcjGNjIyFx9M+0y6pJ3S7CTl1:VIgMevjGrLQ5YMVgk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_299b568e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "299b568e8d0725a31ae143c20554aef27c52a4cb1dbab0b718d997a0adf40c52"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 02:15:56"
  condition:
    hash.sha256(0, filesize) == "299b568e8d0725a31ae143c20554aef27c52a4cb1dbab0b718d997a0adf40c52"
}
```

### Sample 13: `f376bc73f8923ebe`

| Field | Value |
|---|---|
| SHA-256 | `f376bc73f8923ebe3711bb551a20aaf39bb19e0b4ef3e0622bcb03ba1783feec` |
| Family label | `unknown` |
| File name | `MV_SEA_LADY_VESSEL_MAIN_PARTICULARSpdf.js` |
| File type | `js` |
| First seen | `2026-08-11 02:15:42` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `308332ace8a5e431e9d79ae91aa58331` |
| SHA-1 | `207b2c5c1153cebe2cbdbbe0a72d954f3b778a43` |
| SHA-256 | `f376bc73f8923ebe3711bb551a20aaf39bb19e0b4ef3e0622bcb03ba1783feec` |
| SHA3-384 | `dc4e5886c1f0651443b430e38dca98d05e885d77d631a6f3e1a3646ba33c6f6530f56e1fdc20337b3b4bf48cf09b1c39` |
| TLSH | `T1E7D5C96A36EE328A29AC3352D88A384D0F5BC6B16AC3F5D4F0DF47D0211954969D4CFE` |
| SSDEEP | `12288:/wJ1raTtndg2e490b59HDHYLWS5rxPM4ttsrkDs/oll5ygFy3QgCfP+GQFnYo5ur:Uq9zLDN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_f376bc73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f376bc73f8923ebe3711bb551a20aaf39bb19e0b4ef3e0622bcb03ba1783feec"
    family = "unknown"
    file_name = "MV_SEA_LADY_VESSEL_MAIN_PARTICULARSpdf.js"
    file_type = "js"
    first_seen = "2026-08-11 02:15:42"
  condition:
    hash.sha256(0, filesize) == "f376bc73f8923ebe3711bb551a20aaf39bb19e0b4ef3e0622bcb03ba1783feec"
}
```

### Sample 14: `824f9626e070519b`

| Field | Value |
|---|---|
| SHA-256 | `824f9626e070519b3bfff42ecf6876cb48cb0dbf1431702db3e18a5dd923b1ce` |
| Family label | `unknown` |
| File name | `main.x86-64-v3` |
| File type | `elf` |
| First seen | `2026-08-11 02:14:57` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4c6c3e8931b3ca18f98e0a507046024` |
| SHA-1 | `a9bb58e9986986f36bf5e26c75f2b88be110199d` |
| SHA-256 | `824f9626e070519b3bfff42ecf6876cb48cb0dbf1431702db3e18a5dd923b1ce` |
| SHA3-384 | `ed988336650009a1ab76389622ebc27188c27989cad43cc7b9261b446039e8b2ccea3b34ea18fc120e89c6c04d0a811b` |
| TLSH | `T177530817B5E3B0BCC297C0744A5A99F2B931BCA106213E3F97C8FA312E35E412659B71` |
| TELFHASH | `t10f218371599e34a1a29bea226361f17148311c6611f032f1867abcf1ef61f821b70c37` |
| SSDEEP | `1536:o2vChs3CS7EN0r/L3mkyZenGe4FhgV/78WY3JUr:BKhSg0r/rUe+hmyW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_824f9626
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "824f9626e070519b3bfff42ecf6876cb48cb0dbf1431702db3e18a5dd923b1ce"
    family = "unknown"
    file_name = "main.x86-64-v3"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:57"
  condition:
    hash.sha256(0, filesize) == "824f9626e070519b3bfff42ecf6876cb48cb0dbf1431702db3e18a5dd923b1ce"
}
```

### Sample 15: `4c5a6b87212177f6`

| Field | Value |
|---|---|
| SHA-256 | `4c5a6b87212177f62fe3174916727a424223a1a315cba018ea5494f3c2e1dffb` |
| Family label | `unknown` |
| File name | `main.aarch64be` |
| File type | `elf` |
| First seen | `2026-08-11 02:14:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66566fc51d00b868aafcb4a4ed372368` |
| SHA-1 | `a63d1b4e6deda0b04000428447fff9327ef1e8bb` |
| SHA-256 | `4c5a6b87212177f62fe3174916727a424223a1a315cba018ea5494f3c2e1dffb` |
| SHA3-384 | `502e67ac31d74cee0a5c5a62390340858c696b92c1369c100ca4a28c0489a00560bb12eb207786675b0050aaf86b1eb5` |
| TLSH | `T115636DA9EE0E7941E2C9E375EB550BE1B12F38A0D36644F73902718DC4EDADD8ED2205` |
| SSDEEP | `1536:7Nec8lKegBn8wGH/AeyuqHobrhrKi1Z/NnQgL9MPcr:LVx8BH/RyuqHeh/ZQgL9MP0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_4c5a6b87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c5a6b87212177f62fe3174916727a424223a1a315cba018ea5494f3c2e1dffb"
    family = "unknown"
    file_name = "main.aarch64be"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:56"
  condition:
    hash.sha256(0, filesize) == "4c5a6b87212177f62fe3174916727a424223a1a315cba018ea5494f3c2e1dffb"
}
```

### Sample 16: `2659d55e43243fc9`

| Field | Value |
|---|---|
| SHA-256 | `2659d55e43243fc981db78cf99dff1a7d06f08e056ae17c3b49f0dccb39eb02b` |
| Family label | `unknown` |
| File name | `main.aarch64` |
| File type | `elf` |
| First seen | `2026-08-11 02:14:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f06afaac54140c6ab72a4ef825892cb3` |
| SHA-1 | `600733ca6ea08a812f5bdb8f6d5e5020a6209406` |
| SHA-256 | `2659d55e43243fc981db78cf99dff1a7d06f08e056ae17c3b49f0dccb39eb02b` |
| SHA3-384 | `fae84d8e3bb644a5c27904d60e3de2f4394403172620695038324e89cb73abe52c4fa756dbbb2cdbcb13b7cdd9dbd131` |
| TLSH | `T1BB636DA5ED0E7941E2D5E335EB594BE1A12F3CB0C35684B37A02B18DC4EDADD8ED2205` |
| SSDEEP | `1536:I+KBN+6fktAudQiufMuZScIaQGjJDHUrOu:CJkyEQbEuZScIaQuDcO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_2659d55e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2659d55e43243fc981db78cf99dff1a7d06f08e056ae17c3b49f0dccb39eb02b"
    family = "unknown"
    file_name = "main.aarch64"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:54"
  condition:
    hash.sha256(0, filesize) == "2659d55e43243fc981db78cf99dff1a7d06f08e056ae17c3b49f0dccb39eb02b"
}
```

### Sample 17: `6abf0b2cfee342e6`

| Field | Value |
|---|---|
| SHA-256 | `6abf0b2cfee342e686454b83371b2148bcecbd7a1c453a08468fa41a9713264a` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.x86_64` |
| File type | `elf` |
| First seen | `2026-08-11 02:14:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a6c642d456699f34ec19e41282e1d2d` |
| SHA-1 | `2648a22e2ca489915d15cbecc418cae27785127f` |
| SHA-256 | `6abf0b2cfee342e686454b83371b2148bcecbd7a1c453a08468fa41a9713264a` |
| SHA3-384 | `2e76d7acd2e8b3b9cf2f87e1659d8a8b17bc2879bd384565cf79110c1d3f777c998328fb8f8e431d7ec44bbc1b90b0d3` |
| TLSH | `T1B853029A513FBBF6E821D176347A8181E4CA5B0E4657201B844E32EFDD75E35E40BBA0` |
| SSDEEP | `1536:EL+mwBspln3Dz5/FTywgEefUjC5n7nHAy379UQUdg6Jx+:oXwBsTBHgTlgUpUQUdgG+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_6abf0b2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6abf0b2cfee342e686454b83371b2148bcecbd7a1c453a08468fa41a9713264a"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:53"
  condition:
    hash.sha256(0, filesize) == "6abf0b2cfee342e686454b83371b2148bcecbd7a1c453a08468fa41a9713264a"
}
```

### Sample 18: `020fd6b946c52e68`

| Field | Value |
|---|---|
| SHA-256 | `020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.mips` |
| File type | `elf` |
| First seen | `2026-08-11 02:09:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97eb2afac624fd6d5106099a32a82f07` |
| SHA-1 | `d7aced7075d85512d6583d29db2b8c6bf994c9ec` |
| SHA-256 | `020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b` |
| SHA3-384 | `28941dc8a7046b9fa04f61f573b632273812b28f2e71260783982271aa0f95e81956abb920b86f2d98cca7a4a7d0dfad` |
| TLSH | `T1A624C71E6E329F7DF6A9C73447B74E24975823D627E1D584E1ACD2101E2038E642FFA8` |
| TELFHASH | `t17a41b01c0db817b497656c4e48adff26d3a730db7f162c238e50e86eeb69a834d14d09` |
| SSDEEP | `3072:ceMXIUqFHiLoO/j2uhZDIa5JwQKcJlsvB+r+VZUdlAHGwyW:uXIUqFvadhZD5wQpOfVMlCGwl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_020fd6b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.mips"
    file_type = "elf"
    first_seen = "2026-08-11 02:09:52"
  condition:
    hash.sha256(0, filesize) == "020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b"
}
```

### Sample 19: `27521c4e0452c798`

| Field | Value |
|---|---|
| SHA-256 | `27521c4e0452c798e790ce99c83c79e13ddcfab4833424e9fe8d3d83f42b6dbd` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.mips` |
| File type | `elf` |
| First seen | `2026-08-11 02:08:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c749a399ecea3441a11e2ba755459d6` |
| SHA-1 | `e788ff098aa88a9917d554425eee0a7b9ea334d5` |
| SHA-256 | `27521c4e0452c798e790ce99c83c79e13ddcfab4833424e9fe8d3d83f42b6dbd` |
| SHA3-384 | `85cf51f87a4ccffe12cea84381768754998bacc2a3b1cf9012c1a0d1b53ad12a43ec9bbbb3eebf08553fc6e9963c8be5` |
| TLSH | `T17463027360464166DCE8E27C41A61BD17FBD2BB3174BB80FA1657C4B2DE6268329384E` |
| SSDEEP | `1536:iGV83BPRH53W190JNQpUIDfbZnn4NzISgNDVJuK:iueBZ1W1OJWJfRn4eLVQK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_27521c4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27521c4e0452c798e790ce99c83c79e13ddcfab4833424e9fe8d3d83f42b6dbd"
    family = "Mirai"
    file_name = "sdfjgnjsdf.mips"
    file_type = "elf"
    first_seen = "2026-08-11 02:08:54"
  condition:
    hash.sha256(0, filesize) == "27521c4e0452c798e790ce99c83c79e13ddcfab4833424e9fe8d3d83f42b6dbd"
}
```

### Sample 20: `40506dd6fa56f5b5`

| Field | Value |
|---|---|
| SHA-256 | `40506dd6fa56f5b5846f98e5d5d2f67ce1705875968d311149b5598182997855` |
| Family label | `unknown` |
| File name | `main.sh4musl` |
| File type | `elf` |
| First seen | `2026-08-11 02:08:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c5ee420f412c0b1661cfe81a5be6f2c` |
| SHA-1 | `d39b972a059b4bfc8ca6cc88daa7b60f55726146` |
| SHA-256 | `40506dd6fa56f5b5846f98e5d5d2f67ce1705875968d311149b5598182997855` |
| SHA3-384 | `819b457d0c7e4d304ce38904ca608346465ef162faf18b9b8db38d777aef9bf3051a210c9cc103dc76f8e404bea05a22` |
| TLSH | `T1EA539D6AF0D6ACF6CC5049B6E872D0300B417DB023EA1D85F85DF2A45B3BA967E4D760` |
| SSDEEP | `1536:uwcfdB/JUtmPe6cP0qcea+Mqs5NQOFw2qaP/0r:wdBKd6pqcearpNnFw2xP0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_40506dd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40506dd6fa56f5b5846f98e5d5d2f67ce1705875968d311149b5598182997855"
    family = "unknown"
    file_name = "main.sh4musl"
    file_type = "elf"
    first_seen = "2026-08-11 02:08:53"
  condition:
    hash.sha256(0, filesize) == "40506dd6fa56f5b5846f98e5d5d2f67ce1705875968d311149b5598182997855"
}
```

### Sample 21: `23f0eb8fdcbb3953`

| Field | Value |
|---|---|
| SHA-256 | `23f0eb8fdcbb3953d5fb11638e90f02fe479a41280366d06ff2f74c4d91286fa` |
| Family label | `unknown` |
| File name | `main.x86-64` |
| File type | `elf` |
| First seen | `2026-08-11 02:06:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43eb8bf498bf25275a4552a8691db450` |
| SHA-1 | `238742db28c333d9f0c4ceb5b8b24a965ba9fe7d` |
| SHA-256 | `23f0eb8fdcbb3953d5fb11638e90f02fe479a41280366d06ff2f74c4d91286fa` |
| SHA3-384 | `6c2c0a19bfd5cb94660a2b54bcf79372fd10b5140f4b7524530b7c11fa9a874d29839333547c972d9789e18479890c8f` |
| TLSH | `T1E453D71BB6A3B0BCC287C0B45A9BD5B1B93178B402213D7FA6C8FA312D35D512659F72` |
| TELFHASH | `t1e221a471499e34e1b197f6623356a1758831289621e031e1c9b6b9f9de51f822ef1c33` |
| SSDEEP | `1536:dlenMAMMAOuyp7Kqzo2wQXpvRqARuOyrCkUrg:fmMMA8p7Kqlqwbg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_23f0eb8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23f0eb8fdcbb3953d5fb11638e90f02fe479a41280366d06ff2f74c4d91286fa"
    family = "unknown"
    file_name = "main.x86-64"
    file_type = "elf"
    first_seen = "2026-08-11 02:06:05"
  condition:
    hash.sha256(0, filesize) == "23f0eb8fdcbb3953d5fb11638e90f02fe479a41280366d06ff2f74c4d91286fa"
}
```

### Sample 22: `a9a8cdb6e564a63b`

| Field | Value |
|---|---|
| SHA-256 | `a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d` |
| Family label | `unknown` |
| File name | `main.x86-64-v2` |
| File type | `elf` |
| First seen | `2026-08-11 02:06:03` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08e014a1216dee76651194e4facd3a07` |
| SHA-1 | `ece83fc7387658da08535eeecbddb97ae8263695` |
| SHA-256 | `a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d` |
| SHA3-384 | `eec315372b397f30dc2849f2f85b963b79cf893589fcb618759d3a43eb8520e4b9f1f15237fd2566abb3eeed7ef7c886` |
| TLSH | `T12953D71BB6A3B0BCC287C0745A9BD5B2B93178B002253D7FA7C8FA312D35D512659F62` |
| TELFHASH | `t18221f6704c9e34a0b1d7f6613316a0758831286621e032e1c5b6f9fadf51f821af1c33` |
| SSDEEP | `1536:B+Vw3n8OAcFAuuyp7Kqz72wQXpvJCi5ARuFyW2MUr:Uw0cFAcp7KqbSH4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_a9a8cdb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d"
    family = "unknown"
    file_name = "main.x86-64-v2"
    file_type = "elf"
    first_seen = "2026-08-11 02:06:03"
  condition:
    hash.sha256(0, filesize) == "a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d"
}
```

### Sample 23: `f3c0f212bf355c64`

| Field | Value |
|---|---|
| SHA-256 | `f3c0f212bf355c64b118fe3f90a581229085c1554b1ee4a70cc36784db6add4d` |
| Family label | `unknown` |
| File name | `main.armv4tl` |
| File type | `elf` |
| First seen | `2026-08-11 02:03:02` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e2cb5f5962569698a9b8557de811ca9` |
| SHA-1 | `bedc5fc14fcd5085efe017993be68b34f0b4a1d4` |
| SHA-256 | `f3c0f212bf355c64b118fe3f90a581229085c1554b1ee4a70cc36784db6add4d` |
| SHA3-384 | `98f76baf0741fb570120b517759caa7512c98cce8fe1ee33b3b0d3de21a309cd4f149d2de80643306d5578b2b95e8a96` |
| TLSH | `T1CE13F946EA519B05C5D232BEFB8E414E37136FA8E7ED32319D306FE013826E71A39525` |
| SSDEEP | `768:Hknou0aUfRP/JfFUpNUL0DkmUPjUCXQBilC9wNlsnOaVnJ4W:HknoBaUfRPB24L0Fgj8BilC6NlsN4W` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_f3c0f212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c0f212bf355c64b118fe3f90a581229085c1554b1ee4a70cc36784db6add4d"
    family = "unknown"
    file_name = "main.armv4tl"
    file_type = "elf"
    first_seen = "2026-08-11 02:03:02"
  condition:
    hash.sha256(0, filesize) == "f3c0f212bf355c64b118fe3f90a581229085c1554b1ee4a70cc36784db6add4d"
}
```

### Sample 24: `91bc65200be32f55`

| Field | Value |
|---|---|
| SHA-256 | `91bc65200be32f5580e65b5ea5bb76d5943764784ac043cf33a36b6186d09e02` |
| Family label | `unknown` |
| File name | `main.arm7` |
| File type | `elf` |
| First seen | `2026-08-11 02:03:01` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b63915b04854e6b3f2e7ee3f7873d95a` |
| SHA-1 | `2c954944b8056e2058ea9d17694e56b8f7ce6103` |
| SHA-256 | `91bc65200be32f5580e65b5ea5bb76d5943764784ac043cf33a36b6186d09e02` |
| SHA3-384 | `5bcfa18ef0922f00db8b5180eb6c9eb819e06a8990ab7b46a918933004ef8e9d33f43f9c59a1ef5123689a7d674bba58` |
| TLSH | `T13343D649FA41AB05D5E231FEFB8E414E33176FA8E7F9312199305FA013C6ADA0B76521` |
| SSDEEP | `1536:jwnjYbl//mzoc7t4BCkAkdEPGlqyvbiTxzYEFg8KX:YYQzoc7t4BCkBpSxzYotKX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_91bc6520
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91bc65200be32f5580e65b5ea5bb76d5943764784ac043cf33a36b6186d09e02"
    family = "unknown"
    file_name = "main.arm7"
    file_type = "elf"
    first_seen = "2026-08-11 02:03:01"
  condition:
    hash.sha256(0, filesize) == "91bc65200be32f5580e65b5ea5bb76d5943764784ac043cf33a36b6186d09e02"
}
```

### Sample 25: `f51dd33eae0cf40d`

| Field | Value |
|---|---|
| SHA-256 | `f51dd33eae0cf40d4e79ab76e7418ac200c3963b5853a97a86381df9d44913c8` |
| Family label | `unknown` |
| File name | `main.mips` |
| File type | `elf` |
| First seen | `2026-08-11 01:59:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1669083da7d9773f7965f85d1ec498b2` |
| SHA-1 | `49062f56ed01f40550a83cee1ba8c27f66ffbf5f` |
| SHA-256 | `f51dd33eae0cf40d4e79ab76e7418ac200c3963b5853a97a86381df9d44913c8` |
| SHA3-384 | `6e93046b17012626cddaefd8d1146ce9c349b3c989f87f85238d4f3c359547410dcde21b4f154b7458e6f4eb6f04f670` |
| TLSH | `T19263562A2A21EFFEE16D823047F39E70935526E636E1D284E26CD7085F7028D189F7D5` |
| TELFHASH | `t1e5114068453823f0d7455c9e6bedff35d46144ef5a666e33cd00fcaaab21a865d00d2c` |
| SSDEEP | `1536:xcPS803qCDd0WuH90D8b0c2txTv5shOscOJ2ISua:dAc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_f51dd33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f51dd33eae0cf40d4e79ab76e7418ac200c3963b5853a97a86381df9d44913c8"
    family = "unknown"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-11 01:59:39"
  condition:
    hash.sha256(0, filesize) == "f51dd33eae0cf40d4e79ab76e7418ac200c3963b5853a97a86381df9d44913c8"
}
```

### Sample 26: `ef8d8e696a3bba50`

| Field | Value |
|---|---|
| SHA-256 | `ef8d8e696a3bba50b1b2fc283fa0764071c584a3773c34c07b2fa4d291065533` |
| Family label | `unknown` |
| File name | `main.arc700` |
| File type | `elf` |
| First seen | `2026-08-11 01:59:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46291c7797424fc6fa1adaf0b9ef0f00` |
| SHA-1 | `0a56a958c3c9ad4e11f95bbe5b29750ddcda2154` |
| SHA-256 | `ef8d8e696a3bba50b1b2fc283fa0764071c584a3773c34c07b2fa4d291065533` |
| SHA3-384 | `f44ae3c7cbee1519a642aab0202f6ae3625ea246702a59395704a7a77e919cfca335c3c9502117e71e0310c0d640de50` |
| TLSH | `T142A32A4B660775C0F57001F4A3CE4BD13F2260DB6B3A5EB6AC7912F3ABB319A181D652` |
| SSDEEP | `1536:FAPrGatmCxYugWJIb2tAJpkR3GDR4TbRGXCgMeUn5p5M/LW:FAPrGa7xYnKw2tAPkRWo6Cgdhq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_ef8d8e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef8d8e696a3bba50b1b2fc283fa0764071c584a3773c34c07b2fa4d291065533"
    family = "unknown"
    file_name = "main.arc700"
    file_type = "elf"
    first_seen = "2026-08-11 01:59:38"
  condition:
    hash.sha256(0, filesize) == "ef8d8e696a3bba50b1b2fc283fa0764071c584a3773c34c07b2fa4d291065533"
}
```

### Sample 27: `81ad7c9495e9299a`

| Field | Value |
|---|---|
| SHA-256 | `81ad7c9495e9299aa17bc6afcafdbb1f0484abf1bba0c268258eb0854d1053bb` |
| Family label | `unknown` |
| File name | `main.nios2` |
| File type | `elf` |
| First seen | `2026-08-11 01:56:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16a657f76344a4cb0fa2648a6130e9dd` |
| SHA-1 | `de329e81139935dc1faa272d2898cfa8f6187810` |
| SHA-256 | `81ad7c9495e9299aa17bc6afcafdbb1f0484abf1bba0c268258eb0854d1053bb` |
| SHA3-384 | `387d5bc5aa342fdf016eccea3a668043eafd2e5c45c834d084fb83a1f7206e3e6d0a60cb7d9ea251c18cb4c592f35a58` |
| TLSH | `T150C44BD4F2C65E7DF00659321B83DB1AD6126FD2E3685BAE852507492C8CBDBCF32168` |
| SSDEEP | `6144:0qrxkmEaloWqHCIiVkrM/rdHcYvinohtN5gmzo/geXYQuiLMDwDd1c8QpZSbWh+i:0+Kas3i/+YG2RzooNJwD9QpZSbo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_81ad7c94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ad7c9495e9299aa17bc6afcafdbb1f0484abf1bba0c268258eb0854d1053bb"
    family = "unknown"
    file_name = "main.nios2"
    file_type = "elf"
    first_seen = "2026-08-11 01:56:46"
  condition:
    hash.sha256(0, filesize) == "81ad7c9495e9299aa17bc6afcafdbb1f0484abf1bba0c268258eb0854d1053bb"
}
```

### Sample 28: `1dfa46e7c90d8840`

| Field | Value |
|---|---|
| SHA-256 | `1dfa46e7c90d88401770795ff748b87bb657c22223fdcfbde199b2fc82412e97` |
| Family label | `unknown` |
| File name | `main.armv4eb` |
| File type | `elf` |
| First seen | `2026-08-11 01:56:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b77855a61780a32b0a49e035f38438d2` |
| SHA-1 | `2117a48a80a241addf8dff539fd8dfb70fd2d420` |
| SHA-256 | `1dfa46e7c90d88401770795ff748b87bb657c22223fdcfbde199b2fc82412e97` |
| SHA3-384 | `9f8ccc49d6f387dc3304d94bc144892b030bce8d554ea3bac69b3012fbfabb1ea719217be3cdb7a0e835d99d9e0adc72` |
| TLSH | `T13213E781F787C922C40A583527BAC736370278E72F67D2108C65EACDFB675D0A9B5827` |
| SSDEEP | `768:C/1r5fs+bvgpJSDuF+/uASagVVFh7g+pDDDHL9SD9tUEuGpebC0UIP+vh9tu1a+:CdLgV/RQqEunWIPSc1a+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_1dfa46e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dfa46e7c90d88401770795ff748b87bb657c22223fdcfbde199b2fc82412e97"
    family = "unknown"
    file_name = "main.armv4eb"
    file_type = "elf"
    first_seen = "2026-08-11 01:56:45"
  condition:
    hash.sha256(0, filesize) == "1dfa46e7c90d88401770795ff748b87bb657c22223fdcfbde199b2fc82412e97"
}
```

### Sample 29: `1a10aa47242d1d71`

| Field | Value |
|---|---|
| SHA-256 | `1a10aa47242d1d71b422dff69b286fc69464f3f132692e2a1daff7a17cbaad99` |
| Family label | `unknown` |
| File name | `main.m68k-68xxx` |
| File type | `elf` |
| First seen | `2026-08-11 01:56:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa5e5d0ab876eb2097c9b1f1c330547d` |
| SHA-1 | `85d0a441ed61943b36c346dde8772521cfc3821f` |
| SHA-256 | `1a10aa47242d1d71b422dff69b286fc69464f3f132692e2a1daff7a17cbaad99` |
| SHA3-384 | `68149631dc570d4746a19ea79ec545d8fd894f6b9c49dffb1b14b7a854b46d3f6792aee64ed9e8c6ff25bc3c4549d66d` |
| TLSH | `T1B3539C81B60EBF9FD0A22A3FC102465E3F74ADE0A5036633D5A27A2396B71731E5CC45` |
| SSDEEP | `1536:mLNNDCjvAD39GFPufcBqI0upixOR9MRqy8rY:mxNGv2taPufqL92qyUY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_1a10aa47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a10aa47242d1d71b422dff69b286fc69464f3f132692e2a1daff7a17cbaad99"
    family = "unknown"
    file_name = "main.m68k-68xxx"
    file_type = "elf"
    first_seen = "2026-08-11 01:56:43"
  condition:
    hash.sha256(0, filesize) == "1a10aa47242d1d71b422dff69b286fc69464f3f132692e2a1daff7a17cbaad99"
}
```

### Sample 30: `668e88ae20d78da7`

| Field | Value |
|---|---|
| SHA-256 | `668e88ae20d78da7e3c2bbd7bbcc2d47859dab434d43f8522ea8fafe3d027974` |
| Family label | `unknown` |
| File name | `main.mips64el-n32` |
| File type | `elf` |
| First seen | `2026-08-11 01:53:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e62f5cd6ea9099a577e5047ff657815` |
| SHA-1 | `9871f664834e5274c7817cab8ca08e0ce401d103` |
| SHA-256 | `668e88ae20d78da7e3c2bbd7bbcc2d47859dab434d43f8522ea8fafe3d027974` |
| SHA3-384 | `a8c96a7ba77b681ca6fd4679f9a29a1101ea2499e44da4b9a952d25143fb40f686fee8ae3dd4eb6ef16cb6e9123cafec` |
| TLSH | `T12CD32C45EE456FBBC09ECE34496E809B04942DE592E4832E76ECEDCC7B7D26C4BC2944` |
| SSDEEP | `1536:3HXFTnZ/IN1mYkBwzoWwGb1GaLj8VPkt2lwZFtpjfeEr7:4bkBwpn1GK8t4jfjP7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_668e88ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668e88ae20d78da7e3c2bbd7bbcc2d47859dab434d43f8522ea8fafe3d027974"
    family = "unknown"
    file_name = "main.mips64el-n32"
    file_type = "elf"
    first_seen = "2026-08-11 01:53:41"
  condition:
    hash.sha256(0, filesize) == "668e88ae20d78da7e3c2bbd7bbcc2d47859dab434d43f8522ea8fafe3d027974"
}
```

### Sample 31: `eaf494a999b3263e`

| Field | Value |
|---|---|
| SHA-256 | `eaf494a999b3263ee4bc5d271d7baad632dac308458eb2370880a4971c115b54` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-11 01:53:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8becf5b7ce71c7b08b7cf204bd5570cb` |
| SHA-1 | `fec77fe5f223daa89f8ff3f9f32f25a025114cfc` |
| SHA-256 | `eaf494a999b3263ee4bc5d271d7baad632dac308458eb2370880a4971c115b54` |
| SHA3-384 | `1585239e042c682e4000dfc7181610703f2b502ac1dc2c9483af5d72d94730b986839f0258e110fc3fd4ddb97666f621` |
| TLSH | `T173C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:58vCB+25j6es8RO9FYpMSUpi+20qUpi+20YQX:58l25Jod2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_eaf494a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaf494a999b3263ee4bc5d271d7baad632dac308458eb2370880a4971c115b54"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-11 01:53:38"
  condition:
    hash.sha256(0, filesize) == "eaf494a999b3263ee4bc5d271d7baad632dac308458eb2370880a4971c115b54"
}
```

### Sample 32: `62372c7464bcdfd0`

| Field | Value |
|---|---|
| SHA-256 | `62372c7464bcdfd03129aed0a9aa1d6dd892695f39e3fbb911d88b1d93019f77` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-11 01:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cefe539eb25c4730b0af2d05058f695` |
| SHA-1 | `e2c6da60a9a11054dde3b572567c95fd73d044c0` |
| SHA-256 | `62372c7464bcdfd03129aed0a9aa1d6dd892695f39e3fbb911d88b1d93019f77` |
| SHA3-384 | `7a58b5982c58926d7ca5fb0b21931f7e32cd1e55f48f3922c88b40ef952d03a2785bd02e18412b33c55c7a94518593fb` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T153E6330C6AE016EADCA3917DFEC265B1F199F8A61372C5DB87AC07216E531A05C3E713` |
| SSDEEP | `393216:WkTUTyaT3RJ3XMkZZaopSrxdGFLnTwC11SD0R0XMCHWUj6cuI3/PGTAI:WkAOaTB5XFZcopSHG5911SYR0XMb83Hm` |
| ICON-DHASH | `d4f87cbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_62372c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62372c7464bcdfd03129aed0a9aa1d6dd892695f39e3fbb911d88b1d93019f77"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-11 01:52:29"
  condition:
    hash.sha256(0, filesize) == "62372c7464bcdfd03129aed0a9aa1d6dd892695f39e3fbb911d88b1d93019f77"
}
```

### Sample 33: `0c411bf6df62ee83`

| Field | Value |
|---|---|
| SHA-256 | `0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95` |
| Family label | `unknown` |
| File name | `0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95.elf` |
| File type | `elf` |
| First seen | `2026-08-11 01:48:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f35cd424ab95e0041cbdf1aed51d0c7` |
| SHA-1 | `35e841951a94bf1353725f4f17b432eff555445c` |
| SHA-256 | `0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95` |
| SHA3-384 | `17f013ee18e5df04540dbcda8e3bddee9d1f219896c7f86443acbc0f37845f94ce7bb85b0a7e80a6de999aa50c7c83bd` |
| TLSH | `T188368D0AFD55AF66CE2D127288A006D02734FD805F83A71B4B14F63CBEBE6895E917D1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:U/9csThIZurJXRZ5UPy/FCTuRgjGxRGLIf5sAgrXIrGoalbH7cCNz9V0OCJOpqPU:ocQ7KQ7cIri0JxbUUB+x2U+LoG5E9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_0c411bf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95"
    family = "unknown"
    file_name = "0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:48:46"
  condition:
    hash.sha256(0, filesize) == "0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95"
}
```

### Sample 34: `cc589f2eea34d1a4`

| Field | Value |
|---|---|
| SHA-256 | `cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140` |
| Family label | `unknown` |
| File name | `cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140.elf` |
| File type | `elf` |
| First seen | `2026-08-11 01:48:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `439c6182681e82c353775354a732c65b` |
| SHA-1 | `745c1c4a4cb218e4ffc9806fb22c0075c766a7b9` |
| SHA-256 | `cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140` |
| SHA3-384 | `f07f7d2f5954603165a9407c263c3e74c95dbdb45d5d52ce4ec5847cfcafefbda050ba0660f9b43081a25c9747536cf6` |
| TLSH | `T1E76629136F18E71EE628613058F1CA88672A1C9546D6A827B391F319FAF307C5D6EDF0` |
| TELFHASH | `t12db0125788e00b48b0d14cc15ec8715241e3fd33182971bfbf750dd64f0e806007d006` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:VveBFskmkdC6eHd3S07W17phbLmTJtySfXCppThaTCYwlH89WhgTSd7LRUwkVn70:Yfmo9EYwn4jE4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_cc589f2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140"
    family = "unknown"
    file_name = "cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:48:40"
  condition:
    hash.sha256(0, filesize) == "cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140"
}
```

### Sample 35: `47da0746c7cd0150`

| Field | Value |
|---|---|
| SHA-256 | `47da0746c7cd0150c953739c3232dba9a0ab71871ee12dfd60dc7f29a9cdff27` |
| Family label | `unknown` |
| File name | `main.mips64-n32` |
| File type | `elf` |
| First seen | `2026-08-11 01:47:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cc157d97fd7e0f2135a2bf3c2576557` |
| SHA-1 | `0f7edf9d0e57f52a5a6fd1d52d4eb0843009070e` |
| SHA-256 | `47da0746c7cd0150c953739c3232dba9a0ab71871ee12dfd60dc7f29a9cdff27` |
| SHA3-384 | `8842cb57f84020af2ddd7efa4809dda790493f5247d5673d176761afb743cccdb0a15e185d78f0928b692179291b06f9` |
| TLSH | `T1E7D34C73B7099F63CA3D52B54EF2CA3996E1264119E2A0956312DF0C7E312693C3EDE4` |
| SSDEEP | `1536:+VkabNEr+N8HliWukcNzndZuCnnLnQwQ23xbHEpEOWgyRFZ3d+rrrn:eN8FiWdcFdECLQwbxbH0WD3gfz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_47da0746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47da0746c7cd0150c953739c3232dba9a0ab71871ee12dfd60dc7f29a9cdff27"
    family = "unknown"
    file_name = "main.mips64-n32"
    file_type = "elf"
    first_seen = "2026-08-11 01:47:55"
  condition:
    hash.sha256(0, filesize) == "47da0746c7cd0150c953739c3232dba9a0ab71871ee12dfd60dc7f29a9cdff27"
}
```

### Sample 36: `fd3f7faddcdd3122`

| Field | Value |
|---|---|
| SHA-256 | `fd3f7faddcdd31222f760c4afb3b8a5600185580b9e3da5057f901d3284f3e54` |
| Family label | `unknown` |
| File name | `main.sh4` |
| File type | `elf` |
| First seen | `2026-08-11 01:47:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a44d295436d01831e1026d4948c974c8` |
| SHA-1 | `9e7437ed39ab61d63004cfde3dee7c03334ba8d9` |
| SHA-256 | `fd3f7faddcdd31222f760c4afb3b8a5600185580b9e3da5057f901d3284f3e54` |
| SHA3-384 | `d033dbc4388dc91f134dca82912458863416bbd3faccde4f08422db374bd5b105e124263bed19e8bbfd544f007d2d56b` |
| TLSH | `T12A031B97C5269FF5D00AB4B095F6CE740B23BD464B2B0EA4E1398BE0138B9C9F185776` |
| SSDEEP | `768:BV0I2+5dBAvgJIhqcRTHgLgkrMceYR97XWW:z047OvgSTHg+ceYRBWW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_fd3f7fad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd3f7faddcdd31222f760c4afb3b8a5600185580b9e3da5057f901d3284f3e54"
    family = "unknown"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-11 01:47:54"
  condition:
    hash.sha256(0, filesize) == "fd3f7faddcdd31222f760c4afb3b8a5600185580b9e3da5057f901d3284f3e54"
}
```

### Sample 37: `163d2225f3f68305`

| Field | Value |
|---|---|
| SHA-256 | `163d2225f3f683055419afa274721e28e62b9894be4944dc425d9d2b27b6cbb1` |
| Family label | `unknown` |
| File name | `main.mips32` |
| File type | `elf` |
| First seen | `2026-08-11 01:47:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69a2b4d34c7efb1394ee4319bfedb862` |
| SHA-1 | `96e6606d9cec10f436cab9d8d9658445190a6060` |
| SHA-256 | `163d2225f3f683055419afa274721e28e62b9894be4944dc425d9d2b27b6cbb1` |
| SHA3-384 | `d12bedfdf6a7093876834897629d445a37ae59c337bd8c4cc472a30e12953325e7ee750085a62720d1d07d457cfe3fe2` |
| TLSH | `T178D32A667B10AFE6C36CD5300EF28AA54AF6195219E394823375CF1CAE7051D289FEF1` |
| SSDEEP | `1536:TX0c6tlv83cAK4Coy6Y8bqpUfGBMBBZoImmOGUXcAY8nEcxl8WdfCzMguIbcYUhT:rapGUXFYKEcxuWd9gNYEtAzfO7m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_163d2225
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163d2225f3f683055419afa274721e28e62b9894be4944dc425d9d2b27b6cbb1"
    family = "unknown"
    file_name = "main.mips32"
    file_type = "elf"
    first_seen = "2026-08-11 01:47:52"
  condition:
    hash.sha256(0, filesize) == "163d2225f3f683055419afa274721e28e62b9894be4944dc425d9d2b27b6cbb1"
}
```

### Sample 38: `672de551af096192`

| Field | Value |
|---|---|
| SHA-256 | `672de551af096192ece9e57ee4727d2dd48b81957a4f61373aae955ae3442def` |
| Family label | `unknown` |
| File name | `main.power8` |
| File type | `elf` |
| First seen | `2026-08-11 01:44:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1848a10d73fe21860eec88c6369a17d1` |
| SHA-1 | `45892520001f287c23d3df857a40862b8f08b4b4` |
| SHA-256 | `672de551af096192ece9e57ee4727d2dd48b81957a4f61373aae955ae3442def` |
| SHA3-384 | `d352f9da5b5c3a1697cbbaebf011bcd5aea9d4355fa8a238d508dae23681d5c05779155b9a7401e91f5dd1c597309456` |
| TLSH | `T149D33A51DF0C6C2AC9712AB595F727A4B79078D12134CA3137053B2F1AB7236AC8BF99` |
| SSDEEP | `3072:Gyf4MvkiK3BBFABwEnNyfFbUSuvnqqLGvpyuBHA0:GyobAZ0NbLuvqKu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_672de551
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "672de551af096192ece9e57ee4727d2dd48b81957a4f61373aae955ae3442def"
    family = "unknown"
    file_name = "main.power8"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:46"
  condition:
    hash.sha256(0, filesize) == "672de551af096192ece9e57ee4727d2dd48b81957a4f61373aae955ae3442def"
}
```

### Sample 39: `e800b9b98694c7db`

| Field | Value |
|---|---|
| SHA-256 | `e800b9b98694c7dbda551c120e69d50eff0f5d9b42986ef5c95f79f0f3a710a3` |
| Family label | `unknown` |
| File name | `main.sh4aeb` |
| File type | `elf` |
| First seen | `2026-08-11 01:44:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `877c2272ba1f3f6834fc06ae7d89d0f4` |
| SHA-1 | `8a4ec64faafbf7c74b36e210e3b806e6c6d2adf1` |
| SHA-256 | `e800b9b98694c7dbda551c120e69d50eff0f5d9b42986ef5c95f79f0f3a710a3` |
| SHA3-384 | `d251ba0c5374ea5dd852a15ce4ff7802fd9a917ee710d468d99f8c97972da848f471c6519c8c62896eb8f01701bf1e20` |
| TLSH | `T1E3535B11F348FAF2CE902E316081D1B4534E2CE1078669E6E44CF6E5797361B7AAD76C` |
| SSDEEP | `1536:07aQWBfih0C9/lZ3ozSIR5C/qTl60IAlSmsKU/M4nZ8rf:caQWBE0C9/lZ3ABKylW2SmsKjgUf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_e800b9b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e800b9b98694c7dbda551c120e69d50eff0f5d9b42986ef5c95f79f0f3a710a3"
    family = "unknown"
    file_name = "main.sh4aeb"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:45"
  condition:
    hash.sha256(0, filesize) == "e800b9b98694c7dbda551c120e69d50eff0f5d9b42986ef5c95f79f0f3a710a3"
}
```

### Sample 40: `9d9f0d3402bbd8a9`

| Field | Value |
|---|---|
| SHA-256 | `9d9f0d3402bbd8a90760c9615305249a3f6f55dcdaea21a41014da22b9227bc7` |
| Family label | `unknown` |
| File name | `main.sparcv8` |
| File type | `elf` |
| First seen | `2026-08-11 01:44:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af045fce3ce3ddb83562ce2ffcba3928` |
| SHA-1 | `b8f81d3df9d190792fc1d4a87e809b9d7182ba11` |
| SHA-256 | `9d9f0d3402bbd8a90760c9615305249a3f6f55dcdaea21a41014da22b9227bc7` |
| SHA3-384 | `6fd2c859ecbbdcfecd6476b369a0900ec520006eb791f7fdfdfa77ea6fef59e3a75586d8225a56ce4d16f30ff77e4955` |
| TLSH | `T1ADD318137A271D22F4D11135A2BF03E2BFE683CB35784E97B65109D9AF276A074832B5` |
| SSDEEP | `1536:mv18eDS/9rNjRLRBugU/nf8bWpnmhytMQfI+n5p5L1lPu:41TwRblBJU/EbtLWpu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_9d9f0d34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d9f0d3402bbd8a90760c9615305249a3f6f55dcdaea21a41014da22b9227bc7"
    family = "unknown"
    file_name = "main.sparcv8"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:44"
  condition:
    hash.sha256(0, filesize) == "9d9f0d3402bbd8a90760c9615305249a3f6f55dcdaea21a41014da22b9227bc7"
}
```

### Sample 41: `bf856f82da6d59b4`

| Field | Value |
|---|---|
| SHA-256 | `bf856f82da6d59b49cf76df8be0ce10fd3abda52dda587b5108b68133cea9486` |
| Family label | `unknown` |
| File name | `main.x86-i686` |
| File type | `elf` |
| First seen | `2026-08-11 01:44:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bea522b2aa207306b0383e5cf6a29b7` |
| SHA-1 | `0dda0c42c40e8d93dc55d11444b572ba59cd15e3` |
| SHA-256 | `bf856f82da6d59b49cf76df8be0ce10fd3abda52dda587b5108b68133cea9486` |
| SHA3-384 | `84c5ec822ff18cd566112b63b250b7bf77b32527495b07d14d2b5abaf4af5db8fe1ecc7102de6dabd42f09a8b4d36067` |
| TLSH | `T153632A41E653C0B0E19381B00997F7E64634DF36941BEAE6EB9C7D62FC307828D9662D` |
| TELFHASH | `t1523127f74d6528ecf3d06401d75a56a3cf39c4536a712e7a01b03d9037f9893a225e3a` |
| SSDEEP | `768:Hirv2D1TeTLQwDQRGAuAnhNsJUE0lsmjT0S+3qaa4G39HvCScStQBxNh9jCF3ErZ:HireD1Tq5DQR7n7hBUYdvjtQBfjCFUr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_bf856f82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf856f82da6d59b49cf76df8be0ce10fd3abda52dda587b5108b68133cea9486"
    family = "unknown"
    file_name = "main.x86-i686"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:42"
  condition:
    hash.sha256(0, filesize) == "bf856f82da6d59b49cf76df8be0ce10fd3abda52dda587b5108b68133cea9486"
}
```

### Sample 42: `60c2382b1db52934`

| Field | Value |
|---|---|
| SHA-256 | `60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f` |
| Family label | `unknown` |
| File name | `60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f.elf` |
| File type | `elf` |
| First seen | `2026-08-11 01:43:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a204b987161ee112750cb098a1914d57` |
| SHA-1 | `1e0ad7d21a115648315c773f6a2f134a7b8776db` |
| SHA-256 | `60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f` |
| SHA3-384 | `2078b1d53834885dbe02e4ad2f709160618c98143f5ccc644665dc8b8890abd3a0d4319c0b1860e2435eb4d6357188cb` |
| TLSH | `T158466D81FB48A136D98A0E724CB30BA0B7511D45C6E4A91F0705F72F05B26FBA95FEE4` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:YamTr9OHpxOxLeAnx3RWwLwpyvD5MKQUGt1LaHH4t5E0:40POguxhWwkpGMKCLOn4jE0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_60c2382b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f"
    family = "unknown"
    file_name = "60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:43:48"
  condition:
    hash.sha256(0, filesize) == "60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f"
}
```

### Sample 43: `388f63f0eb52acdc`

| Field | Value |
|---|---|
| SHA-256 | `388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56` |
| Family label | `unknown` |
| File name | `388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56.elf` |
| File type | `elf` |
| First seen | `2026-08-11 01:43:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a049f59eb561eac6b8605dde2b7e912e` |
| SHA-1 | `33f4fc97d0b8f82b02bb5e777cca0db6926176fe` |
| SHA-256 | `388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56` |
| SHA3-384 | `ee30ceb74ca26297f0e5062855450e217a0b966bf83fbc2a27999b16ffd648e89b3c9e92b3b2dfebc6c237d9efc768d7` |
| TLSH | `T194465C02FA192FA5C920493389B30DA127A26D552F329B56D744F27FADF33464F16F88` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:2JMxWAkWC5z24n/ouwjehU2KCxNB3JNEPzIyvw3zk35ER:2yxWAkWCNn/oujXNE88HER` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_388f63f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56"
    family = "unknown"
    file_name = "388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:43:42"
  condition:
    hash.sha256(0, filesize) == "388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56"
}
```

### Sample 44: `4911b1593b03a4f3`

| Field | Value |
|---|---|
| SHA-256 | `4911b1593b03a4f312d8314762cd9e3b529fde33f34a61a4f2081f137529ef7c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-11 01:43:40` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcc86d02518b2f23fdfd77ecff71b9e2` |
| SHA-1 | `cf72ab43be244d2e89e7ca325e34b9b9dcad367c` |
| SHA-256 | `4911b1593b03a4f312d8314762cd9e3b529fde33f34a61a4f2081f137529ef7c` |
| SHA3-384 | `1f6c06df4aad1b9173f0d14e83d4c14e6a5a2daa134a9370b2afc5650fb07fc97d193a509862bd5e84ec630b51bb648e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17AE5B73838FB502DD073FF716EE8799ADD9F7A33660A645A204903478B12E81EE5253D` |
| SSDEEP | `49152:Uuh0bWVUbkP2YoWuNVRILXjYdB0Y2/3xQJEFw5nLHEtk:n0bWVUPgLkdBC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_4911b159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4911b1593b03a4f312d8314762cd9e3b529fde33f34a61a4f2081f137529ef7c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-11 01:43:40"
  condition:
    hash.sha256(0, filesize) == "4911b1593b03a4f312d8314762cd9e3b529fde33f34a61a4f2081f137529ef7c"
}
```

### Sample 45: `189a03e754ec12e3`

| Field | Value |
|---|---|
| SHA-256 | `189a03e754ec12e37efe0ba49a7982d0ad10d524fdc509f414575ab5264d7978` |
| Family label | `unknown` |
| File name | `main.mips32r5el` |
| File type | `elf` |
| First seen | `2026-08-11 01:41:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b3bbc1b30268b24b5bc156f5f4f3033` |
| SHA-1 | `804926d0f672d0d6d8d22a80e9a830119f1ad3f2` |
| SHA-256 | `189a03e754ec12e37efe0ba49a7982d0ad10d524fdc509f414575ab5264d7978` |
| SHA3-384 | `a901e701cf08b8180f7dbccadad189c70c987bcf7879ec6e2b03afbb9c53e3e66ea3217263dcc19fb24d1f4012c98194` |
| TLSH | `T19ED30B03ED816EFBC41ECD70453DC24A15DA5CAA92E5A26F71F8C98CBBBD20546D78C8` |
| SSDEEP | `1536:V5nmf/5on7ovvbq6Knp5sn5nMkmv5A2XMv5995L2WGLIaEri3kU:bman7o3s5s5nM7HXMv59/JliR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_189a03e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189a03e754ec12e37efe0ba49a7982d0ad10d524fdc509f414575ab5264d7978"
    family = "unknown"
    file_name = "main.mips32r5el"
    file_type = "elf"
    first_seen = "2026-08-11 01:41:38"
  condition:
    hash.sha256(0, filesize) == "189a03e754ec12e37efe0ba49a7982d0ad10d524fdc509f414575ab5264d7978"
}
```

### Sample 46: `5d7b90ad2083eb24`

| Field | Value |
|---|---|
| SHA-256 | `5d7b90ad2083eb246eaa32593f29ca0485bf1f743760692df72ccec1103c30aa` |
| Family label | `unknown` |
| File name | `main.mips64` |
| File type | `elf` |
| First seen | `2026-08-11 01:41:36` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b7f6e169080d278d59bb30651ca3c2f` |
| SHA-1 | `238f406357b285385b536921e5291ec082e70845` |
| SHA-256 | `5d7b90ad2083eb246eaa32593f29ca0485bf1f743760692df72ccec1103c30aa` |
| SHA3-384 | `1bd6a2051f34dc6eb8a8a5875bca3d9ac3f8aed07eabaa86e51dcd40301819bd3f7c99261b2c427888a4caa1d4abf3fe` |
| TLSH | `T13F6395563307DA6FF8B917704AF18AB0B3D478E674B05A96E73A7B4C0F300A95D185CA` |
| SSDEEP | `1536:Qrsa++o8OSX9QDAa3Lt70FZ/NoGv1JB4ou93jpkzbbbrflSjotHHC5pGIPLK5eKE:Qrs6tOS4jNWbr5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_5d7b90ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7b90ad2083eb246eaa32593f29ca0485bf1f743760692df72ccec1103c30aa"
    family = "unknown"
    file_name = "main.mips64"
    file_type = "elf"
    first_seen = "2026-08-11 01:41:36"
  condition:
    hash.sha256(0, filesize) == "5d7b90ad2083eb246eaa32593f29ca0485bf1f743760692df72ccec1103c30aa"
}
```

### Sample 47: `0e3a78094c70edea`

| Field | Value |
|---|---|
| SHA-256 | `0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a` |
| Family label | `unknown` |
| File name | `0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a.elf` |
| File type | `elf` |
| First seen | `2026-08-11 01:38:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6f678b0d5656c4292a78a5deee33bbd` |
| SHA-1 | `14a0feafb4b64043cbaa0f2d7b7408a4e0eed9f4` |
| SHA-256 | `0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a` |
| SHA3-384 | `83ead39ee615b97ad5f796845dc124f6679871a60c9b9bc54d573e601a7763e553cbb2f0b181f31cab25cb5be116bba7` |
| TLSH | `T15D661956AE832BA6C99C033445FE629752603E454BA1433713E4FBA83E7773C9F56C88` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:cff4wJxB1RCUOQixHF2WsvSy26yD/M+ibGEpbzZUYQmnwecN2ofMC6Lm/ahsUYq8:cffNJxB3zOdTK24qkUVmwT2Pi/F5EY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_0e3a7809
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a"
    family = "unknown"
    file_name = "0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:38:41"
  condition:
    hash.sha256(0, filesize) == "0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a"
}
```

### Sample 48: `c489ac18a01a7254`

| Field | Value |
|---|---|
| SHA-256 | `c489ac18a01a725418502656287ef6fdf7fd5550c7ab6cf6d63912cf6dcb7d40` |
| Family label | `unknown` |
| File name | `main.e300c3` |
| File type | `elf` |
| First seen | `2026-08-11 01:38:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9555ea32a313ee95211f6739669ac115` |
| SHA-1 | `a9127573af911a7a64b980f00ce3c4ae7192e01b` |
| SHA-256 | `c489ac18a01a725418502656287ef6fdf7fd5550c7ab6cf6d63912cf6dcb7d40` |
| SHA3-384 | `cd31dc2b0b7b5c486ca0477fb586a16af84c346860d45f70d40491afc0166cef451d482b0e3c50466900799f9d6ff76c` |
| TLSH | `T12FD33B23FB4C0562C8C36DF80E3F07E683249D5220FE9615651D7E6A1B33E71A687B99` |
| SSDEEP | `3072:kKehjj2yDz0LyVWkOk6cWABecTQNR5sz8ManUS7:7ehjjLDz9VWkOk6cWAshiz8IQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_c489ac18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c489ac18a01a725418502656287ef6fdf7fd5550c7ab6cf6d63912cf6dcb7d40"
    family = "unknown"
    file_name = "main.e300c3"
    file_type = "elf"
    first_seen = "2026-08-11 01:38:39"
  condition:
    hash.sha256(0, filesize) == "c489ac18a01a725418502656287ef6fdf7fd5550c7ab6cf6d63912cf6dcb7d40"
}
```

### Sample 49: `92f5d59c480c7158`

| Field | Value |
|---|---|
| SHA-256 | `92f5d59c480c7158cb58d461c5ea8050994fdc8d3093095df6912ea696a9e511` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-11 01:38:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f452852d4d1be518f24b916e0efcd95` |
| SHA-1 | `621e474ac82800e819323b5728dd7c55b0b0c3a9` |
| SHA-256 | `92f5d59c480c7158cb58d461c5ea8050994fdc8d3093095df6912ea696a9e511` |
| SHA3-384 | `b707c4f266d57db914b15811de53b75c77ef48b4e56d2dfa36d538bbcdcc4771a38c914d72bc0ce40b33db035d0c22c0` |
| TLSH | `T1ECC27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:r8vCB+25j6es8RP9FYpMSUpi+20qUpi+20YQX:r8l25JZd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_92f5d59c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f5d59c480c7158cb58d461c5ea8050994fdc8d3093095df6912ea696a9e511"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-11 01:38:36"
  condition:
    hash.sha256(0, filesize) == "92f5d59c480c7158cb58d461c5ea8050994fdc8d3093095df6912ea696a9e511"
}
```

### Sample 50: `3dd7b8084d0fd210`

| Field | Value |
|---|---|
| SHA-256 | `3dd7b8084d0fd21045bd18309630c2eaffce420f7d4c4db56d79935e0935c333` |
| Family label | `unknown` |
| File name | `main.riscv64` |
| File type | `elf` |
| First seen | `2026-08-11 01:35:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03019c4f4944b660aa8355c5f61321d3` |
| SHA-1 | `9df0ad3e642fe8d61af0042b3d41b37bde9171fa` |
| SHA-256 | `3dd7b8084d0fd21045bd18309630c2eaffce420f7d4c4db56d79935e0935c333` |
| SHA3-384 | `2f37bd5d509715830be716544e18a19fde9b44721547cfee252c837c43d451e18e969bc848ce0ac434226b98bbc1e908` |
| TLSH | `T14B735AC29C218724C2E613B857F94A55E3D11B1236CB3301CAA1F739BD9E1A4B693D9F` |
| SSDEEP | `1536:90QZpLJMABayGIcB9tv5/hxgo+G8VJc/gQ6A2xyLoTy7oRQY0rYp:FLdgy5cBDv5/l+GrN6A2xyLoTy4QtY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_3dd7b808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dd7b8084d0fd21045bd18309630c2eaffce420f7d4c4db56d79935e0935c333"
    family = "unknown"
    file_name = "main.riscv64"
    file_type = "elf"
    first_seen = "2026-08-11 01:35:45"
  condition:
    hash.sha256(0, filesize) == "3dd7b8084d0fd21045bd18309630c2eaffce420f7d4c4db56d79935e0935c333"
}
```

### Sample 51: `c3e58e0f33d6668f`

| Field | Value |
|---|---|
| SHA-256 | `c3e58e0f33d6668f6b37646095b8484dd97b8182ab97b25a19c4ed4bfdeb6080` |
| Family label | `unknown` |
| File name | `bot.386` |
| File type | `elf` |
| First seen | `2026-08-11 01:35:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17590ba763d3cfd87cc870fcaaedfbc0` |
| SHA-1 | `bc7aa099736caa249c9b97902ea7af13d1647b75` |
| SHA-256 | `c3e58e0f33d6668f6b37646095b8484dd97b8182ab97b25a19c4ed4bfdeb6080` |
| SHA3-384 | `62c8241f6ebb87c4b445c4c3ddba1068f26719adbe4fbaa741437214e4ff68649814f724166aa91a8100c6914c7a081a` |
| TLSH | `T14C463911FECB14F6E9031E3104BBA26F23315D058B25EB87DB44BF69F97BA951932209` |
| TELFHASH | `t1afd2deb7159da4ec67f0840796af7520cff5e02726e0387119e6b8c1ab73d839626878` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:jxtF974ZY/4QkSlufNv3B8XrB5Kdfyvh07uGOZCSGyah7EDTtJST5EP:jHFAYQxp3uwdfyvq7ucyreEP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_c3e58e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3e58e0f33d6668f6b37646095b8484dd97b8182ab97b25a19c4ed4bfdeb6080"
    family = "unknown"
    file_name = "bot.386"
    file_type = "elf"
    first_seen = "2026-08-11 01:35:43"
  condition:
    hash.sha256(0, filesize) == "c3e58e0f33d6668f6b37646095b8484dd97b8182ab97b25a19c4ed4bfdeb6080"
}
```

### Sample 52: `d345ea8ec62bb05d`

| Field | Value |
|---|---|
| SHA-256 | `d345ea8ec62bb05db1652ff3b4db194fa6d730263e4186c6dc851a45569c845b` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.m68k` |
| File type | `elf` |
| First seen | `2026-08-11 01:35:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f79d8da599a50db808b9769153788aa9` |
| SHA-1 | `db9ed4f39126dfdb50af5f8ab2b1c5b4a0735630` |
| SHA-256 | `d345ea8ec62bb05db1652ff3b4db194fa6d730263e4186c6dc851a45569c845b` |
| SHA3-384 | `e106dd07cd0258f5d2d3d12bdf91168d0a1dc3abaa0905123c571d4696bae29aa3a77b9b2961b4bd0baa4253df6c8b3f` |
| TLSH | `T1E2044CCBF801DDBDF80AE73748130909B130B7A510935B377257B96BED3A1990967E8A` |
| SSDEEP | `3072:Xsr03xoDLbwRxPB9GFGnQ6uYlkyl67gVfjbijLRwVUWykyFU:K6xoDMEGnQ6JlH67bL2ykuU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_d345ea8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d345ea8ec62bb05db1652ff3b4db194fa6d730263e4186c6dc851a45569c845b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.m68k"
    file_type = "elf"
    first_seen = "2026-08-11 01:35:41"
  condition:
    hash.sha256(0, filesize) == "d345ea8ec62bb05db1652ff3b4db194fa6d730263e4186c6dc851a45569c845b"
}
```

### Sample 53: `40ee84ea58804b34`

| Field | Value |
|---|---|
| SHA-256 | `40ee84ea58804b34c5f9b741d988ce497f029ba143b202887581bbffe1df3851` |
| Family label | `unknown` |
| File name | `main.riscv32` |
| File type | `elf` |
| First seen | `2026-08-11 01:32:40` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6484249e4bbaa67cec268d7a18eb7df7` |
| SHA-1 | `b151330f2793dbae74cec9fd12695eb7b8714992` |
| SHA-256 | `40ee84ea58804b34c5f9b741d988ce497f029ba143b202887581bbffe1df3851` |
| SHA3-384 | `c07f49636dd36e08be4e39b5f4ae14b5d12b0ebeb654b84930655b8bd546d3965bac4033689678d342a06d229935352e` |
| TLSH | `T148A35B42DD2B4761E2E207B00BF95B4293616F2629D37345C49CFA38F95D1F862C2EE9` |
| SSDEEP | `3072:JAG/AClxtC5s0em6SKFJR9YwxZFQMszmzA:Jt4Ym5sNTJR9YwxZqMsz6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_40ee84ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ee84ea58804b34c5f9b741d988ce497f029ba143b202887581bbffe1df3851"
    family = "unknown"
    file_name = "main.riscv32"
    file_type = "elf"
    first_seen = "2026-08-11 01:32:40"
  condition:
    hash.sha256(0, filesize) == "40ee84ea58804b34c5f9b741d988ce497f029ba143b202887581bbffe1df3851"
}
```

### Sample 54: `fc92d53673d72cf0`

| Field | Value |
|---|---|
| SHA-256 | `fc92d53673d72cf005ae433b9493ff8f6e0c7a2b1588ce89d2d85e94c35770a5` |
| Family label | `unknown` |
| File name | `main.xtensa` |
| File type | `elf` |
| First seen | `2026-08-11 01:32:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cb4d334c2f11ba1ed1c0933a3f6ba38` |
| SHA-1 | `5f5a4806a6816873c7b804cfda8b5afbe93efc1d` |
| SHA-256 | `fc92d53673d72cf005ae433b9493ff8f6e0c7a2b1588ce89d2d85e94c35770a5` |
| SHA3-384 | `caa0085311834ae6c9649f0ecea20a93100e00928cb160ae6ee190a085d3cdadefd5387c8e2ab564898752dd5ff0099d` |
| TLSH | `T1B9D3A1876A16187EF0B243B145DECAF83E2792F742B70D16582B1EAC5F13E959F060C2` |
| SSDEEP | `1536:eTDZOcZDGI7kSWSl9kw7Cc07N1XwUn5p5M/LWbvjsHxjiESOoNy7TK:eTD3ZDGIBJD7Ds1Xwhqbvjmjbcy7TK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_fc92d536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc92d53673d72cf005ae433b9493ff8f6e0c7a2b1588ce89d2d85e94c35770a5"
    family = "unknown"
    file_name = "main.xtensa"
    file_type = "elf"
    first_seen = "2026-08-11 01:32:39"
  condition:
    hash.sha256(0, filesize) == "fc92d53673d72cf005ae433b9493ff8f6e0c7a2b1588ce89d2d85e94c35770a5"
}
```

### Sample 55: `94ae81675ebf3620`

| Field | Value |
|---|---|
| SHA-256 | `94ae81675ebf3620fa2c5acb37cb9d8d5afe0521cf97eea5242c12fd52f58ad2` |
| Family label | `Mirai` |
| File name | `main.armv6` |
| File type | `elf` |
| First seen | `2026-08-11 01:32:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b55d48b67985324115c29f2378633091` |
| SHA-1 | `9dd0f0d57429a8f86b29bdf1546b7ae805ef6dda` |
| SHA-256 | `94ae81675ebf3620fa2c5acb37cb9d8d5afe0521cf97eea5242c12fd52f58ad2` |
| SHA3-384 | `c72e986243db4f0ba68685c27a6722570dadf21df668fdb1d3308bab82919286595f973534f9cc747b8ed498789522d7` |
| TLSH | `T15313F946EA519B05C5D232BEFB8E414E37136FA8E7ED32319D306FE013826E71A39525` |
| SSDEEP | `768:HknCu0aUfRP/JfFUpNUL0DkmUPjUCXQBilC9wNlsnOaVnv4W:HknCBaUfRPB24L0Fgj8BilC6NlsT4W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_94ae8167
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94ae81675ebf3620fa2c5acb37cb9d8d5afe0521cf97eea5242c12fd52f58ad2"
    family = "Mirai"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-11 01:32:38"
  condition:
    hash.sha256(0, filesize) == "94ae81675ebf3620fa2c5acb37cb9d8d5afe0521cf97eea5242c12fd52f58ad2"
}
```

### Sample 56: `c23fff87e5ab3227`

| Field | Value |
|---|---|
| SHA-256 | `c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1` |
| Family label | `unknown` |
| File name | `c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1.elf` |
| File type | `elf` |
| First seen | `2026-08-11 01:28:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40295a30f4a7462510856af3aa5a75c3` |
| SHA-1 | `5c71a0b7760d6f49b0ab011abe3340e1d3920fbd` |
| SHA-256 | `c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1` |
| SHA3-384 | `8b03fc0d89a3394e90c67687ba989241c1478b405c7926bae504071498e9e84e2f6cef13933d289b895aa72807ab226d` |
| TLSH | `T142564A43EC9525E5C8AED13189B39152BB717C885F3163D32B50F6392FB2BD0AAB9704` |
| TELFHASH | `t18132567509bd35b5b6aada10b363b5f49a371da562f434f11023b994efc1e801ce283b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:gcnIekxr6C6BvZeeqPL9x3YZEoD2pdT5wEdU1S9Vz2a16zFGP26oKlK1KcLxi3dJ:gcITrJUydUEvt6nti3dEfEb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_c23fff87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1"
    family = "unknown"
    file_name = "c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:28:46"
  condition:
    hash.sha256(0, filesize) == "c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1"
}
```

### Sample 57: `24cee19d2763a412`

| Field | Value |
|---|---|
| SHA-256 | `24cee19d2763a412eb4bf710986acd1373a4754729986f4101913da9e0da4bbc` |
| Family label | `unknown` |
| File name | `main.x86_64` |
| File type | `elf` |
| First seen | `2026-08-11 01:26:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2acba492dd58751cd01a851dae6cdff` |
| SHA-1 | `43352be354db309f97858e87988007b909f1dfe5` |
| SHA-256 | `24cee19d2763a412eb4bf710986acd1373a4754729986f4101913da9e0da4bbc` |
| SHA3-384 | `f031ad91573e0417bbb33a1a39e33d7d9d74bc81253810c11c78f635f7d37111baeea89cb2329540e59799110905fbbf` |
| TLSH | `T18213D913EE65C02FC48BD1B05BDFD6359A23B87A0736A006A7A0FF615E45980DEB52D3` |
| TELFHASH | `t1142187b43a1738c1b2d3f551b249e8708c3d053500e436f2d5b1b8f9cb16f811486c1b` |
| SSDEEP | `768:JRa/4bV1PzRy6k+FuhJb6mZeaxSgRX1A8cHpQ/0XkwKJt:ja8V1PzQX/fGmZjdX1Gp8wKJt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_24cee19d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cee19d2763a412eb4bf710986acd1373a4754729986f4101913da9e0da4bbc"
    family = "unknown"
    file_name = "main.x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:50"
  condition:
    hash.sha256(0, filesize) == "24cee19d2763a412eb4bf710986acd1373a4754729986f4101913da9e0da4bbc"
}
```

### Sample 58: `088840155e73df85`

| Field | Value |
|---|---|
| SHA-256 | `088840155e73df853dc78841aebe420334f295a159ea5151c143ce17e4f3f4ec` |
| Family label | `unknown` |
| File name | `main.archs38` |
| File type | `elf` |
| First seen | `2026-08-11 01:26:48` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daa73f79f7c86f182e44d8761cc7dbdd` |
| SHA-1 | `55ecbf6e570cef04f8f7ca204c5bfc3a3022c273` |
| SHA-256 | `088840155e73df853dc78841aebe420334f295a159ea5151c143ce17e4f3f4ec` |
| SHA3-384 | `03998a5e5d304963964978831e6cc84b5fcb06f1dddfa6faf791721b637ba09e603adb12957c21493b9d066c07b3ce9d` |
| TLSH | `T1E1A35B47770B2890F86102F163DDA3E03F1561CBAF321EB7586A62F76F731991D06A62` |
| SSDEEP | `1536:NcXqMVJA1UtdQKzdnxjChP2h8f34jgLhCUn5p5M/LW5:iq0A1UtyPcVg8hq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_08884015
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "088840155e73df853dc78841aebe420334f295a159ea5151c143ce17e4f3f4ec"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:48"
  condition:
    hash.sha256(0, filesize) == "088840155e73df853dc78841aebe420334f295a159ea5151c143ce17e4f3f4ec"
}
```

### Sample 59: `916162f62f994245`

| Field | Value |
|---|---|
| SHA-256 | `916162f62f9942458ed422ccb19d0d1edd302daa7522b1715812f35d2da6beb8` |
| Family label | `unknown` |
| File name | `main.x86-64-i7` |
| File type | `elf` |
| First seen | `2026-08-11 01:26:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74c2f0baf07761c05e98e04a7b8f77ec` |
| SHA-1 | `d5090ba9a52cccc14d0ae155a1d86f33d90a660d` |
| SHA-256 | `916162f62f9942458ed422ccb19d0d1edd302daa7522b1715812f35d2da6beb8` |
| SHA3-384 | `c47c5649890cd2f74aa17c02a96c037d883aa5c8381d17ab11fa43b9614e5ab0800fef5dc2c2a6074d1099682500eed9` |
| TLSH | `T12453D71BB6A3B0BCC287C0745A9BD5B2B93178B002253D7FA7C8FA312D35D512659F62` |
| TELFHASH | `t18221f6704c9e34a0b1d7f6613316a0758831286621e032e1c5b6f9fadf51f821af1c33` |
| SSDEEP | `1536:BwVw3n8OAcFAuuyp7Kqz72wQXpvJCi5ARuFyW2MUr:6w0cFAcp7KqbSH4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_916162f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "916162f62f9942458ed422ccb19d0d1edd302daa7522b1715812f35d2da6beb8"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:47"
  condition:
    hash.sha256(0, filesize) == "916162f62f9942458ed422ccb19d0d1edd302daa7522b1715812f35d2da6beb8"
}
```

### Sample 60: `db21148cb2f460bf`

| Field | Value |
|---|---|
| SHA-256 | `db21148cb2f460bf23be50839733754643ee69916b186af6792619251c807a46` |
| Family label | `unknown` |
| File name | `main.mips64r6el-n32` |
| File type | `elf` |
| First seen | `2026-08-11 01:26:46` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94252bd84e9734294b0ffc4ab04f8aaf` |
| SHA-1 | `997958d06a0acbab02c3b13e8593412829803469` |
| SHA-256 | `db21148cb2f460bf23be50839733754643ee69916b186af6792619251c807a46` |
| SHA3-384 | `ab5e7bf4cc3027eab4b270a3c559ad8403fe4d6ef5f758bce4792a9c24e17e16b43e291e75d3b4844bf63d92174d87a6` |
| TLSH | `T107D31A05EE047AB7D09E8E7845BFC19204D53DF7A2D4C33976E86A8D7A3C65906C3B88` |
| SSDEEP | `1536:zZyGoQvGYZmvr38b18ZwfJLXI5Po86ErEbo:8SeYhSZucQ8TEbo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_db21148c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db21148cb2f460bf23be50839733754643ee69916b186af6792619251c807a46"
    family = "unknown"
    file_name = "main.mips64r6el-n32"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:46"
  condition:
    hash.sha256(0, filesize) == "db21148cb2f460bf23be50839733754643ee69916b186af6792619251c807a46"
}
```

### Sample 61: `3b6902d4973b9a5d`

| Field | Value |
|---|---|
| SHA-256 | `3b6902d4973b9a5d54a1812b74f531e53913ac924b590be96cbb57b3fa55f79c` |
| Family label | `Mirai` |
| File name | `main.armv5` |
| File type | `elf` |
| First seen | `2026-08-11 01:26:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c9b0d1f4acbd47c46532064aefb73d1` |
| SHA-1 | `37750cc6004ce8bbcdc9629e0988eab8affe15f7` |
| SHA-256 | `3b6902d4973b9a5d54a1812b74f531e53913ac924b590be96cbb57b3fa55f79c` |
| SHA3-384 | `69aacc4b0a04926273effcf433aab9d78d34b6ad0de0932da7d513baacc19917debeff8afab7cb343450b778073d942a` |
| TLSH | `T12A13F946EA519B05C5D232BEFB8E414E37136FA8E7ED32319D306FE013826E71A39525` |
| SSDEEP | `768:HknCu0aUfRP/JfFUpNUL0DkmUPjUCXQBilC9wNlsnOaVng4W:HknCBaUfRPB24L0Fgj8BilC6NlsE4W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_3b6902d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b6902d4973b9a5d54a1812b74f531e53913ac924b590be96cbb57b3fa55f79c"
    family = "Mirai"
    file_name = "main.armv5"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:44"
  condition:
    hash.sha256(0, filesize) == "3b6902d4973b9a5d54a1812b74f531e53913ac924b590be96cbb57b3fa55f79c"
}
```

### Sample 62: `8760d69e7776681b`

| Field | Value |
|---|---|
| SHA-256 | `8760d69e7776681bcb3712d3e13bdee42f43e6566a395424cb014876bc3d1863` |
| Family label | `unknown` |
| File name | `main.powerpc` |
| File type | `elf` |
| First seen | `2026-08-11 01:23:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b37711f09108899c1245036205db7988` |
| SHA-1 | `272ee3f1ed64124e76aeba289c6779c5d57064aa` |
| SHA-256 | `8760d69e7776681bcb3712d3e13bdee42f43e6566a395424cb014876bc3d1863` |
| SHA3-384 | `5a4d2720e78dcfbbd03c2041f2b8eca3be18770a07440f36976fea1aa61b2011b90cf3e4881aa1530ab25c2f70807ccf` |
| TLSH | `T13B13C647632E0A87C0772EF03A7727E0876ABDA112E49540565EFFC54235EF06192FAB` |
| SSDEEP | `768:G4v6DRPI4wkVPDH98VBuH2BAONseADYeejZ5555555555555555T55555555555t:DqBdqw2BFAD1eZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_8760d69e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8760d69e7776681bcb3712d3e13bdee42f43e6566a395424cb014876bc3d1863"
    family = "unknown"
    file_name = "main.powerpc"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:42"
  condition:
    hash.sha256(0, filesize) == "8760d69e7776681bcb3712d3e13bdee42f43e6566a395424cb014876bc3d1863"
}
```

### Sample 63: `236c34fca99a0818`

| Field | Value |
|---|---|
| SHA-256 | `236c34fca99a0818058bb2074dfe2d0d6e10c6bb517e6a08c4fedc27c6be805b` |
| Family label | `unknown` |
| File name | `main.e5500` |
| File type | `elf` |
| First seen | `2026-08-11 01:23:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7f4c286d7c48af7b9a7500e5fc27f63` |
| SHA-1 | `186a2bbf1aae8e498062d7f1e64d6864e39bf39e` |
| SHA-256 | `236c34fca99a0818058bb2074dfe2d0d6e10c6bb517e6a08c4fedc27c6be805b` |
| SHA3-384 | `5843414f49e474d288f409150ad4f52516cfd070fac2d57bb83ba9f59c2da923580dec7d9af92c87712d09861d837861` |
| TLSH | `T174055D12FF4C6417C70A06B1A56E5B7CFB52B45381F5C6033B0866AF64D233A1DABE89` |
| SSDEEP | `24576:mBZivNMk3fSTENarbX+u7YtTIoFiKd/obu+ue1P+2pKrxw2UABcb1e:mBHk3fSTENarbX+u7YtTIoLiu+ue1G2e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_236c34fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "236c34fca99a0818058bb2074dfe2d0d6e10c6bb517e6a08c4fedc27c6be805b"
    family = "unknown"
    file_name = "main.e5500"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:41"
  condition:
    hash.sha256(0, filesize) == "236c34fca99a0818058bb2074dfe2d0d6e10c6bb517e6a08c4fedc27c6be805b"
}
```

### Sample 64: `1a52e179c51c3ce5`

| Field | Value |
|---|---|
| SHA-256 | `1a52e179c51c3ce5b3ea3529f9c95a3fbd1fdced9d2d7476d4ffdfd40ac1d134` |
| Family label | `unknown` |
| File name | `main.armv7-eabihf` |
| File type | `elf` |
| First seen | `2026-08-11 01:23:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb11e3060da489cbc23aa313dcc137c2` |
| SHA-1 | `fef06645cb43dd98ac14bf202dcf35df8f7569e0` |
| SHA-256 | `1a52e179c51c3ce5b3ea3529f9c95a3fbd1fdced9d2d7476d4ffdfd40ac1d134` |
| SHA3-384 | `11d84640a14745f296661451a5562a6daf269dcaf1a7742134cb342ac7efd291a4b69c846c1612b3c55179e2fb81ca2a` |
| TLSH | `T1AE531A94F840DA35CBD075BAF61E43DD33120FA8E2DA71158E319A353BEB9194E3B942` |
| SSDEEP | `1536:7Fs//7u9uMiyJdFTR7+o3IWdpM4nDoBmu/zoYeotFL+d8f0rL:7C7R4L3pMiDo8uDeE68UL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_1a52e179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a52e179c51c3ce5b3ea3529f9c95a3fbd1fdced9d2d7476d4ffdfd40ac1d134"
    family = "unknown"
    file_name = "main.armv7-eabihf"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:38"
  condition:
    hash.sha256(0, filesize) == "1a52e179c51c3ce5b3ea3529f9c95a3fbd1fdced9d2d7476d4ffdfd40ac1d134"
}
```

### Sample 65: `fbb37366d5122077`

| Field | Value |
|---|---|
| SHA-256 | `fbb37366d512207792c0cc90de869deddecb4d412f390787e01dd93d602e92cb` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.arc` |
| File type | `elf` |
| First seen | `2026-08-11 01:23:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `060269bc5ebf3fc85058c1b10455c4d9` |
| SHA-1 | `ff08564cfff643747133c1afcca1b3794f2340c4` |
| SHA-256 | `fbb37366d512207792c0cc90de869deddecb4d412f390787e01dd93d602e92cb` |
| SHA3-384 | `e0929bef92887c35898eab186445bee5c9d73b1c8bb94bccf41079d227c9f58e6bca6310bbc6e277d88573e0a0d05ca3` |
| TLSH | `T100E3AEB3F3071091C86446F80BCB6BAD296321125E2F59EBBD2E773B69765DE58023D0` |
| SSDEEP | `3072:qOIblYxcUGX9HiVQjYfShGX4eOr/v7gjFExuvIevzdcLogZCBxSZpT0gq:NIblYxDeiVRf6jr38E0vjeLrCB4Zpxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_fbb37366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbb37366d512207792c0cc90de869deddecb4d412f390787e01dd93d602e92cb"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arc"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:37"
  condition:
    hash.sha256(0, filesize) == "fbb37366d512207792c0cc90de869deddecb4d412f390787e01dd93d602e92cb"
}
```

### Sample 66: `9198759b9ca91109`

| Field | Value |
|---|---|
| SHA-256 | `9198759b9ca91109f5a59dac8db5b8c2574fd32c29bd796e16a23ef595968e41` |
| Family label | `unknown` |
| File name | `main.e500mc` |
| File type | `elf` |
| First seen | `2026-08-11 01:20:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34cc51395d05dd6cd86e0feb5ed4a143` |
| SHA-1 | `9787924e18c396bdf7d9b22320e944284c92743f` |
| SHA-256 | `9198759b9ca91109f5a59dac8db5b8c2574fd32c29bd796e16a23ef595968e41` |
| SHA3-384 | `2abde90080f736267d8d789562b53d2990943421ca9fa641b8e7c9be05b454b838f33583a17fb60f34fe72304719fdc7` |
| TLSH | `T18CD31957FF0C4057C48369781E3B07ADF320BE1150B99516230A6B6F3BB6E326687B99` |
| SSDEEP | `1536:qTdHGjrabJJ8hga/JO1g7wtGahEZwt2rFCl73eJ9NWgvRbw8r1i:qBHGjra3Ega/JpMtyZwt2raCvZkU1i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_9198759b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9198759b9ca91109f5a59dac8db5b8c2574fd32c29bd796e16a23ef595968e41"
    family = "unknown"
    file_name = "main.e500mc"
    file_type = "elf"
    first_seen = "2026-08-11 01:20:39"
  condition:
    hash.sha256(0, filesize) == "9198759b9ca91109f5a59dac8db5b8c2574fd32c29bd796e16a23ef595968e41"
}
```

### Sample 67: `b38e430116c0c1a0`

| Field | Value |
|---|---|
| SHA-256 | `b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927` |
| Family label | `unknown` |
| File name | `bot.arm64` |
| File type | `elf` |
| First seen | `2026-08-11 01:20:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91bb39fdae41a4d3405e469ddd62cdc4` |
| SHA-1 | `aa727fbac2e4374e4fae8086540efca073bbb65c` |
| SHA-256 | `b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927` |
| SHA3-384 | `c2025c10155d0e1c83e4d4d9d74c2dc60938dd14a2f5a7b2b39a687a7bba942bd996f38459fb2f23bf93f97d5ad1c6b8` |
| TLSH | `T1B7464B55FC1D6462D6C97A742F7112D43239BC498F81D7236A28BB3DBAF23588F132A1` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:WyMXUotXhgk17gkwBflKqbqfq8UWJKdt/erz9kyKYzg9Wop5ET:WyMEksrfllbnPt2Ha/ET` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_b38e4301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927"
    family = "unknown"
    file_name = "bot.arm64"
    file_type = "elf"
    first_seen = "2026-08-11 01:20:38"
  condition:
    hash.sha256(0, filesize) == "b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927"
}
```

### Sample 68: `1df747a30c57bc64`

| Field | Value |
|---|---|
| SHA-256 | `1df747a30c57bc640d7403663cd37d11da3b4bf3917b83a7e5a89fdae81b9fe2` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-11 01:18:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8a14edacc5941bf449d124b7ff68e36` |
| SHA-1 | `17da55aad5210262ad748b7272ca163514eb7a4b` |
| SHA-256 | `1df747a30c57bc640d7403663cd37d11da3b4bf3917b83a7e5a89fdae81b9fe2` |
| SHA3-384 | `f326fbb626f5bbfc9e11d985c3fec55afcdc5244e47b7811961bf79f942a29f0fb659f725c6658fd5f4e1b8648e79d08` |
| TLSH | `T1D1E36A1BB1C184FDC8D9C2B44BAEE626D932F4595134B22F27C4AE272E5DE206B6D710` |
| TELFHASH | `t1e051bc603d5a3d98e1e7ea72730be6689c360a2009d176e5de737cface453850c76463` |
| SSDEEP | `3072:bWDvmIITpC4DdXAU19o+FbVPO3Lk+aE1xIgKrT21QVmtM:1dm26keu3itM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_1df747a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1df747a30c57bc640d7403663cd37d11da3b4bf3917b83a7e5a89fdae81b9fe2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 01:18:31"
  condition:
    hash.sha256(0, filesize) == "1df747a30c57bc640d7403663cd37d11da3b4bf3917b83a7e5a89fdae81b9fe2"
}
```

### Sample 69: `7dc97e65d07416aa`

| Field | Value |
|---|---|
| SHA-256 | `7dc97e65d07416aac2ec2fa717a672928f5d1abd21d8adcfb108e0373bb5ceb4` |
| Family label | `unknown` |
| File name | `main.mips32r6el` |
| File type | `elf` |
| First seen | `2026-08-11 01:17:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47ec6dc80d63fd0e8ca395bcef37d38b` |
| SHA-1 | `9806a757fd4161f8d2d566552c2e868d166d37ca` |
| SHA-256 | `7dc97e65d07416aac2ec2fa717a672928f5d1abd21d8adcfb108e0373bb5ceb4` |
| SHA3-384 | `e43b4210dec56aabc6698669dd2c59fc9fa46102b7e3db6c3288fd854ce588e367358ba35133fc84458776f07a0f9de4` |
| TLSH | `T195D30B13EE817EBBC41BDC74456EC29214E75CFAA2E5A37A71F8469CBE7C20215C3584` |
| SSDEEP | `1536:a3UzwPTP2b2IbKVQhUZN1n39v+iFjkXREr:a3UzWCSiKVYUZT8iFAW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_7dc97e65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc97e65d07416aac2ec2fa717a672928f5d1abd21d8adcfb108e0373bb5ceb4"
    family = "unknown"
    file_name = "main.mips32r6el"
    file_type = "elf"
    first_seen = "2026-08-11 01:17:59"
  condition:
    hash.sha256(0, filesize) == "7dc97e65d07416aac2ec2fa717a672928f5d1abd21d8adcfb108e0373bb5ceb4"
}
```

### Sample 70: `83a7f3594007039c`

| Field | Value |
|---|---|
| SHA-256 | `83a7f3594007039ce3df172e73bca5fbba86b7486f27349841d5df9fee6f4b07` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-11 01:17:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `511f7933f550b9cca45e7698a838a605` |
| SHA-1 | `4e822fbe444d5b590b3c86ad49ad2968bc941255` |
| SHA-256 | `83a7f3594007039ce3df172e73bca5fbba86b7486f27349841d5df9fee6f4b07` |
| SHA3-384 | `36fe0690f1d802c85fab1ce5313c9b9fbceda5874a268070beda8d8f5012e1c17523ab6da513389120c43c487177b0a6` |
| TLSH | `T1F34301766BAAD6BDE535C6701B14C268FF18AD0A97441F53CD0D323A8BFE9903304B26` |
| SSDEEP | `768:pmOLLOv3FK2McKSWtA1uVhMxx88d4xIUbEkNoH/A+ZhuIcK8xr2O75wjT:5LLOv3FK2Mdo3bdyr/NoH/A+Pw2O7U` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_83a7f359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a7f3594007039ce3df172e73bca5fbba86b7486f27349841d5df9fee6f4b07"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 01:17:58"
  condition:
    hash.sha256(0, filesize) == "83a7f3594007039ce3df172e73bca5fbba86b7486f27349841d5df9fee6f4b07"
}
```

### Sample 71: `769f8ef1aa8c84e8`

| Field | Value |
|---|---|
| SHA-256 | `769f8ef1aa8c84e8735445711584e227afc0abf677ff93333421af061a9559e2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-11 01:16:38` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8732229973f978d5de065eb0dc35e146` |
| SHA-1 | `797440c1984b2998b30e69167ecfb5859248e8cb` |
| SHA-256 | `769f8ef1aa8c84e8735445711584e227afc0abf677ff93333421af061a9559e2` |
| SHA3-384 | `1feb9198e3a8659e57be448dfe0aed80bf1af040ca8449d314f5f1544c3ab3f27f6af7b4c4689f07c34bd6ffd50a5a48` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T17908AE15E3E40616D2BEC27CC6628603E6F0BCD75311CACF0459DA992FA3BD15E7B262` |
| SSDEEP | `393216:z115a0XXvi5L5OtsFjhweJWBJ7sxXJDCtkJ5Wz3lzYqN9vuc9L4Jkn27UuWqGC33:wcXviV5OtsFjFg/YDoCkPR5to8tfbxOB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_769f8ef1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769f8ef1aa8c84e8735445711584e227afc0abf677ff93333421af061a9559e2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-11 01:16:38"
  condition:
    hash.sha256(0, filesize) == "769f8ef1aa8c84e8735445711584e227afc0abf677ff93333421af061a9559e2"
}
```

### Sample 72: `ff52c676b94b6fad`

| Field | Value |
|---|---|
| SHA-256 | `ff52c676b94b6fad17731931a2c25cf5cd7c71ff6641abab3bd00f5c6a487056` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-11 00:52:44` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26289d04612fab8063db9c54973b60a1` |
| SHA-1 | `100534be5bdf8dd628d91d98572c7245ee844b99` |
| SHA-256 | `ff52c676b94b6fad17731931a2c25cf5cd7c71ff6641abab3bd00f5c6a487056` |
| SHA3-384 | `b4160ce1e7ba75f3f10182a854826c3fed1331ff7195534486c7721c07345c9025e65a1046b92833bafa3f398d39fa7d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T14CE633486BD042EED9E38138EED112AAF639B4715771C1DF93D843926D431E09B3A36B` |
| SSDEEP | `393216:CEmd2vxd1QjdgSBbSWlqEgH+YhXMCHWUjWrcuI3/PGTAI:CL2vxd1HU4Es3XMb8WIH/O7` |
| ICON-DHASH | `5479fcbcccc4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_ff52c676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff52c676b94b6fad17731931a2c25cf5cd7c71ff6641abab3bd00f5c6a487056"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-11 00:52:44"
  condition:
    hash.sha256(0, filesize) == "ff52c676b94b6fad17731931a2c25cf5cd7c71ff6641abab3bd00f5c6a487056"
}
```

### Sample 73: `abb086bee2b6e255`

| Field | Value |
|---|---|
| SHA-256 | `abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0` |
| Family label | `Mirai` |
| File name | `abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0.elf` |
| File type | `elf` |
| First seen | `2026-08-11 00:38:48` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a24b8a1afb4027250b38cac4a7a5b398` |
| SHA-1 | `c3dd040be71898ac78d016915fa54430b48ea472` |
| SHA-256 | `abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0` |
| SHA3-384 | `5f69475ae676a86085db09910a829991e11d1bf3e23f83deb1f8dd35aac04f7eb9ac1139bac3e1907079baaced214007` |
| TLSH | `T123D48D99FE5E3D42E3C7E379CF4E83A1632B75E4D32352A33942420CD4C6AE98BA1511` |
| SSDEEP | `12288:97RB7rNPwRUOwomC3eVkNz9GawGqzhnytSFHQH61s5Lh0CBeKS:97RVRnom82p4tSFH4B0K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_abb086be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0"
    family = "Mirai"
    file_name = "abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:38:48"
  condition:
    hash.sha256(0, filesize) == "abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0"
}
```

### Sample 74: `6c23a44f0bb66ed0`

| Field | Value |
|---|---|
| SHA-256 | `6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9` |
| Family label | `Mirai` |
| File name | `6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9.elf` |
| File type | `elf` |
| First seen | `2026-08-11 00:38:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7215d75e44df394d2ebaabcbfe44bc0` |
| SHA-1 | `14c16892046cc5d1c7cd0c06095e6967a92f37fc` |
| SHA-256 | `6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9` |
| SHA3-384 | `54c6a39b23f62482b614b36c551a9943673578870c85850b925ad43965a9ac617af740193fa3225513c50d684b148ecb` |
| TLSH | `T17584E096F7023E82C8D7C57519C681895789E95B33F383463B42AA7B3C397368F29385` |
| SSDEEP | `6144:eoa8sPtcnDGGzryRQ1vqGsj4GV+Aw8Y4Mi8pL+TKH:Da8sVcZAiskGV+Aw8Ys8pL+TK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_6c23a44f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9"
    family = "Mirai"
    file_name = "6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:38:44"
  condition:
    hash.sha256(0, filesize) == "6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9"
}
```

### Sample 75: `f49396d2d2313b5f`

| Field | Value |
|---|---|
| SHA-256 | `f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741` |
| Family label | `Mirai` |
| File name | `f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741.elf` |
| File type | `elf` |
| First seen | `2026-08-11 00:33:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f07842951bbcfa6d8d9fc83c13aa8875` |
| SHA-1 | `bd009ed1a525d9f437c34a6c4060c6e6fb2575b1` |
| SHA-256 | `f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741` |
| SHA3-384 | `7c14620ff5a034bd3807e03764bfa0accf5c322d1aac531b33028711f6cf37489ae89265e41311482f2511cb0d583a17` |
| TLSH | `T1F0D46C02EF440FEBD4AFCD30856E835B15EE888B06C1A678A1FC498CBB8D55A4FD7558` |
| SSDEEP | `12288:Zd0jfmV5rf3Hhnb2xOpKp0lbL5+8PZ+hl94m+rbPWjzcGzFLLAF23wxIuFsYYy1N:ZB56nxbbfV6jHnV5usvlxQrk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_f49396d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741"
    family = "Mirai"
    file_name = "f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:33:40"
  condition:
    hash.sha256(0, filesize) == "f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741"
}
```

### Sample 76: `f66626b11eb9356a`

| Field | Value |
|---|---|
| SHA-256 | `f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac` |
| Family label | `Mirai` |
| File name | `f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac.elf` |
| File type | `elf` |
| First seen | `2026-08-11 00:33:37` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8acaa7f168f46aa1e68be150d595b9ce` |
| SHA-1 | `bf978476ee4050316694e3e9c164333211846edf` |
| SHA-256 | `f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac` |
| SHA3-384 | `c9ff017372e1335aaa1caba671a93a0bb4cf46055f90a812d6337c52b2e4d2105daed37f0890462ff353acf432e8bc91` |
| TLSH | `T14ED47C5377218F94D360D27101F38B659AA521A30FF390C2A3BCD6207A51A6D6D6FFE8` |
| TELFHASH | `t10f41af180a7813e0a6755c5d45edff36d6a330eb7e262c278e10e86ee769b824d14c1c` |
| SSDEEP | `12288:9+9rLu+44QutuTcnHnCFuu7T61zaNesn8pQakBKaPM:M9ry+44QutuwHCFugT64NefkDM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f66626b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac"
    family = "Mirai"
    file_name = "f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:33:37"
  condition:
    hash.sha256(0, filesize) == "f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac"
}
```

### Sample 77: `5c76bc92d700c050`

| Field | Value |
|---|---|
| SHA-256 | `5c76bc92d700c050a7a8126ce43e4ac29db312022cf3ce32717b8f07e26590f5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-11 00:31:17` |
| Reporter | `Bitsight` |
| Tags | `B, BB4.file, dropped-by-GCleaner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07593cbef4f9f182fbb501fbc2aa4405` |
| SHA-1 | `be7f3838ce0c4227e574f43937b0989ef7b58614` |
| SHA-256 | `5c76bc92d700c050a7a8126ce43e4ac29db312022cf3ce32717b8f07e26590f5` |
| SHA3-384 | `7ae01ae9bb10c7689569ec9dd6d47145292160a25e82002ca357544d18fdf7b6b499800b443319202f203d324205c875` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1B8365A17AA9548FAC0A9D735C4B75256BA70B80D4B3133D71E61BEB82F313D1AE35B80` |
| SSDEEP | `49152:ql6Hxd5mvFzBOmbK/JvhHRDQ6hZuWuSRLoClAsBu/0ltxH4Bh:q+iE5Q6HufSR1ucjE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_5c76bc92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c76bc92d700c050a7a8126ce43e4ac29db312022cf3ce32717b8f07e26590f5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-11 00:31:17"
  condition:
    hash.sha256(0, filesize) == "5c76bc92d700c050a7a8126ce43e4ac29db312022cf3ce32717b8f07e26590f5"
}
```

### Sample 78: `166eb2c6aabc4d4b`

| Field | Value |
|---|---|
| SHA-256 | `166eb2c6aabc4d4b8bbb0e9571aaf5d2a97a2cb1f22ca84e0d42f22d8ff4a920` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.ppc` |
| File type | `elf` |
| First seen | `2026-08-11 00:19:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b70cff4a2a0cbde6933d284853425df5` |
| SHA-1 | `3dbfe89fe23f405908feb20a6072937c94464ccb` |
| SHA-256 | `166eb2c6aabc4d4b8bbb0e9571aaf5d2a97a2cb1f22ca84e0d42f22d8ff4a920` |
| SHA3-384 | `9bc4c3bd5acb33ec718e3607051f292ed3e0702af31d6876b4e5a3e2b76bf708d4783a11e209a026191dd38511b7cdd1` |
| TLSH | `T1FDF34B02B71C0947D1A32EB43A3F27D093EFE59125F4FA44694F9B899275E321489ECE` |
| SSDEEP | `1536:ePMQsptbIlq404OD0Q2RYMu7a81+xiAB6bHS5byP2QOCcryLvAy6a0c9JFqWr6Vi:+jE4rq0Q2o7a81+xjBAYBQ1crPyhEG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_166eb2c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "166eb2c6aabc4d4b8bbb0e9571aaf5d2a97a2cb1f22ca84e0d42f22d8ff4a920"
    family = "Mirai"
    file_name = "sdfjgnjsdf.ppc"
    file_type = "elf"
    first_seen = "2026-08-11 00:19:29"
  condition:
    hash.sha256(0, filesize) == "166eb2c6aabc4d4b8bbb0e9571aaf5d2a97a2cb1f22ca84e0d42f22d8ff4a920"
}
```

### Sample 79: `67f87dab198b2892`

| Field | Value |
|---|---|
| SHA-256 | `67f87dab198b2892965a8d03b42b89320fe53666be1d4b83e1c2e2632b8fcd97` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.ppc` |
| File type | `elf` |
| First seen | `2026-08-11 00:18:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c3d79b90c58365e307194a049c379c0` |
| SHA-1 | `96358772d1787d857578c30c0baeb35b210d0bc7` |
| SHA-256 | `67f87dab198b2892965a8d03b42b89320fe53666be1d4b83e1c2e2632b8fcd97` |
| SHA3-384 | `3e4be441b47156284de1bd0c0f3486b40869bc9dea465bd347d5c43b29e89cc0c0fe9648a7849f9192a0589bfed50b40` |
| TLSH | `T13053F1E4D5D928E5CABB99D502D133A017B0DF0A3365C4A1A6C763C9437710AAEA0FFD` |
| SSDEEP | `1536:XwWpHNq8eN0Zyor4sOk6Tlhj5hGZMkOuG7Lhsw4u+qgw09h:PNw8yA4yejf2MkFG71sw4u+qgwQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_67f87dab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67f87dab198b2892965a8d03b42b89320fe53666be1d4b83e1c2e2632b8fcd97"
    family = "Mirai"
    file_name = "sdfjgnjsdf.ppc"
    file_type = "elf"
    first_seen = "2026-08-11 00:18:31"
  condition:
    hash.sha256(0, filesize) == "67f87dab198b2892965a8d03b42b89320fe53666be1d4b83e1c2e2632b8fcd97"
}
```

### Sample 80: `be8947c577699304`

| Field | Value |
|---|---|
| SHA-256 | `be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806` |
| Family label | `Mirai` |
| File name | `be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806` |
| File type | `elf` |
| First seen | `2026-08-11 00:02:34` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b41d1ca3691324b13877aee34b0353aa` |
| SHA-1 | `b66e3c7ed838655ad51fb432abbab0f74ff36a99` |
| SHA-256 | `be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806` |
| SHA3-384 | `5f7a22a4c3256f850cc03266e2bd0c6df6999cba3342db69da9aecb83003d8cf6ff495c4c7b9a13b58c9940101c9d83b` |
| TLSH | `T17C34C7067BA19EF7C89FDD3302E6860110CEF45722A56B6B7374D61CBA0A94F49D3C98` |
| TELFHASH | `t1947174a8953c01d9de630c1964ad6bf34887f12922e5bb19ff16ccc4085e82cf268d0f` |
| SSDEEP | `6144:SXnBrFB10H61J0xN/58WzvgreG3Ai/a9vNYzpWe:ErbIcJORzvgreG3Ai/a9vNYzpWe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_be8947c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806"
    family = "Mirai"
    file_name = "be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806"
    file_type = "elf"
    first_seen = "2026-08-11 00:02:34"
  condition:
    hash.sha256(0, filesize) == "be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806"
}
```

### Sample 81: `e30b557c9621436b`

| Field | Value |
|---|---|
| SHA-256 | `e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36` |
| Family label | `Mirai` |
| File name | `e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36` |
| File type | `elf` |
| First seen | `2026-08-11 00:02:31` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb5977a9934e5e55467a10232298b167` |
| SHA-1 | `acc46e0d657b67e7c934389942dbd31d3b9f111d` |
| SHA-256 | `e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36` |
| SHA3-384 | `61098d8a9dd3feb4757c2261d19606b2808492716a5a263a89be511015fd5accfb1669dfc85881da661637c135fddd5c` |
| TLSH | `T10934A71A3A12EFBFF568863107F38A7097D521963AE19346F26CD71C1E2028D685F7E4` |
| TELFHASH | `t1947174a8953c01d9de630c1964ad6bf34887f12922e5bb19ff16ccc4085e82cf268d0f` |
| SSDEEP | `6144:sx7f5flfnJXQhAotlaDm7zvnreG3Ai/a9vNYzpWe:ubfnJugDizvnreG3Ai/a9vNYzpWe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_e30b557c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36"
    family = "Mirai"
    file_name = "e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36"
    file_type = "elf"
    first_seen = "2026-08-11 00:02:31"
  condition:
    hash.sha256(0, filesize) == "e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36"
}
```

### Sample 82: `156ee410363b6781`

| Field | Value |
|---|---|
| SHA-256 | `156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed` |
| Family label | `Mirai` |
| File name | `156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed` |
| File type | `elf` |
| First seen | `2026-08-11 00:02:28` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb45c920be598f053afb3d56918aa1ea` |
| SHA-1 | `95716d70357d72b9e633a0b9d8a80b3daf7b57cf` |
| SHA-256 | `156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed` |
| SHA3-384 | `06ee7749fc79d1a7623dde7d8b98e6e6766158daf8fea5fcee21bcee5762ddb83b8ea1aa5925689b1001d82f71a48d92` |
| TLSH | `T166258D1AB2B2F67DD00BC0304BDBCAB14132F07569322D7B32C5DA343EA6DA51769B65` |
| TELFHASH | `t190f099f58328e1204c9a860099ce117d888ff21448a93443dd39481985b065d867aa7b` |
| SSDEEP | `12288:xYd6DCNgKL6dQusl1tUBdoHfjdxAOEDapo1UvOHHaypCoaHXZ9ul/mMAXA:xYsCNgBnudKp6o1YOHwkl/mH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_156ee410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed"
    family = "Mirai"
    file_name = "156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed"
    file_type = "elf"
    first_seen = "2026-08-11 00:02:28"
  condition:
    hash.sha256(0, filesize) == "156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed"
}
```

### Sample 83: `e4eaae680e23b413`

| Field | Value |
|---|---|
| SHA-256 | `e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322` |
| Family label | `unknown` |
| File name | `e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322` |
| File type | `sh` |
| First seen | `2026-08-11 00:02:25` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47d2e1713d4544ad44bb977f31ca8194` |
| SHA-1 | `9660fbf19addbabf64f92db5aafd3b56a6d2e417` |
| SHA-256 | `e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322` |
| SHA3-384 | `7136f4f6b8ebe51cc2361c142d4a250df839887da765f4cc28cf1d9010cf36534a6e00d3ccfd1652d2e5d4800fe437c9` |
| TLSH | `T10B11A0C51586B4A3C9FDDB167851CAA0E004A38ABDD53B7CCCFC742B8D84A2CB55BB19` |
| SSDEEP | `24:sRpGpKpjpSp6p5pGp28pvpQQq7yFxdhhqr:sRpGpKpjpSp6p5pGpjpvpQfOFxor` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_e4eaae68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322"
    family = "unknown"
    file_name = "e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322"
    file_type = "sh"
    first_seen = "2026-08-11 00:02:25"
  condition:
    hash.sha256(0, filesize) == "e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322"
}
```

### Sample 84: `ca67190aa9dc8b5d`

| Field | Value |
|---|---|
| SHA-256 | `ca67190aa9dc8b5de33ed8d29e8b7d87d9057cb1835ae9cc3fa727abc1958b4b` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-10 23:49:33` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24493926dbad83284b1b3e87f2ec81d4` |
| SHA-1 | `c574199276c98c445c6e81f1a6af596b834f2fb8` |
| SHA-256 | `ca67190aa9dc8b5de33ed8d29e8b7d87d9057cb1835ae9cc3fa727abc1958b4b` |
| SHA3-384 | `01ae4fd8ea3498e000b411eb33eadf5c994afb062d1a9c3f283d914ab92f84403d000c7903ad7499774449b095e1228a` |
| TLSH | `T12A016FD6894069005059D95E62D752A4F820D3CF464B4BB8BFDC9D3DFB98504F066F84` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkauNFCa1xnCN5gCXyxwpCm5cwsCouauD:kXCKysE2hi0ziQvZohauXvl0rp/5cHU7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_ca67190a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca67190aa9dc8b5de33ed8d29e8b7d87d9057cb1835ae9cc3fa727abc1958b4b"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-10 23:49:33"
  condition:
    hash.sha256(0, filesize) == "ca67190aa9dc8b5de33ed8d29e8b7d87d9057cb1835ae9cc3fa727abc1958b4b"
}
```

### Sample 85: `3b842c26338a3e6c`

| Field | Value |
|---|---|
| SHA-256 | `3b842c26338a3e6c1c76f358f7df3876b1a71f211cb8e5294ae8e1471d0aa526` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-10 23:42:30` |
| Reporter | `Bitsight` |
| Tags | `B, BB3.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad6da42cdfb20da64deeab2d1f59ff85` |
| SHA-1 | `c202078a43ec5a0fde713077acd259abfae5d284` |
| SHA-256 | `3b842c26338a3e6c1c76f358f7df3876b1a71f211cb8e5294ae8e1471d0aa526` |
| SHA3-384 | `dc4a2df85b3bc853299276be3707c1632087504025b4b38e417bfb39c5a3b47e468de445373714e8af52fe109632be6e` |
| IMPHASH | `b93bf499ed2f500909ebf8f70559e1b6` |
| TLSH | `T1129412A1DE7541FDC01DF1B0172A2299D8F1F0818F5822DF6B286271AB70EEC6B7CA55` |
| SSDEEP | `12288:5/0IdBI/e98XO920iSIBRimORzRtwXUVVzmhR8F:p0Idu/qDaSIXim2zb/Tc8F` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_3b842c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b842c26338a3e6c1c76f358f7df3876b1a71f211cb8e5294ae8e1471d0aa526"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-10 23:42:30"
  condition:
    hash.sha256(0, filesize) == "3b842c26338a3e6c1c76f358f7df3876b1a71f211cb8e5294ae8e1471d0aa526"
}
```

### Sample 86: `8b0e129a647a6cce`

| Field | Value |
|---|---|
| SHA-256 | `8b0e129a647a6ccea436f6d16d3043337a723fe48bf19f366e22e7e5149500a9` |
| Family label | `Mirai` |
| File name | `mini.arm7` |
| File type | `elf` |
| First seen | `2026-08-10 23:30:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `593625970b6e5161c1bc6a8193413012` |
| SHA-1 | `084df6a1125e9ac4c44af8f9450c003ff66f0b8c` |
| SHA-256 | `8b0e129a647a6ccea436f6d16d3043337a723fe48bf19f366e22e7e5149500a9` |
| SHA3-384 | `774e7e372a498f499d0a6c9dee7911e97d4739f32ae182047fce9e49bd4f4f2e0b3624cdc9cee760e4331f35dfdb04f9` |
| TLSH | `T1E823E556F4D0DE62C6D43179FA5E119C33674BB8D2DA3202CA207A3537EB56A4F3A902` |
| SSDEEP | `768:mWuWOhERu/31/slD40y1fGQam2OC8oAPf73Jpos0sO/VCAWxp7bPxHokV0keYxb:mVWOpEW1GQBhC8oIpROfWxp3PxHoZ+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_8b0e129a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0e129a647a6ccea436f6d16d3043337a723fe48bf19f366e22e7e5149500a9"
    family = "Mirai"
    file_name = "mini.arm7"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:36"
  condition:
    hash.sha256(0, filesize) == "8b0e129a647a6ccea436f6d16d3043337a723fe48bf19f366e22e7e5149500a9"
}
```

### Sample 87: `bbbe8f578cb150ea`

| Field | Value |
|---|---|
| SHA-256 | `bbbe8f578cb150ea93dc8dae245a626f9adcdabef7f10d766f8c4d69ed88c619` |
| Family label | `Mirai` |
| File name | `mini.arm64` |
| File type | `elf` |
| First seen | `2026-08-10 23:30:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6978451b1c8f92c754f4c3e6ff951604` |
| SHA-1 | `3cb71e099c371bb2ad2122194fdf18d58d375f56` |
| SHA-256 | `bbbe8f578cb150ea93dc8dae245a626f9adcdabef7f10d766f8c4d69ed88c619` |
| SHA3-384 | `eb17eaf2acc6a40da2cb86c359e40b60b4073accdfd486bcc3eb2f147a5a0232485eb2cbc3254995d944dd579e143abe` |
| TLSH | `T1B0137EE89A0FAEA1C7D2C77DAF6E4FA532163C7410E6C3756500720D9DB89968CF6423` |
| SSDEEP | `768:j7K6cyHOlsVNRTP8Rwb7YC9SQ77G57lp0cDEqeGi:j26cyHOlsXRT8S/9vSZQms` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_bbbe8f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbbe8f578cb150ea93dc8dae245a626f9adcdabef7f10d766f8c4d69ed88c619"
    family = "Mirai"
    file_name = "mini.arm64"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:34"
  condition:
    hash.sha256(0, filesize) == "bbbe8f578cb150ea93dc8dae245a626f9adcdabef7f10d766f8c4d69ed88c619"
}
```

### Sample 88: `b5ca5ab2333aa186`

| Field | Value |
|---|---|
| SHA-256 | `b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd` |
| Family label | `Mirai` |
| File name | `mini.mips` |
| File type | `elf` |
| First seen | `2026-08-10 23:30:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32835fa46362f85d68d6d95cad40c3a7` |
| SHA-1 | `55f0a70e1a0619344bf63a721c7777786b08578d` |
| SHA-256 | `b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd` |
| SHA3-384 | `c98c301bc0c8de666ed294c25b973bc915175dfd14b1e16877c4812df4f5cb580d2deb2233c86ad02787119440e6268a` |
| TLSH | `T140532A4B73118F91C769DA3002F34A536BEA12A327D39406F36DEE516B6234D681FFA4` |
| TELFHASH | `t14b01fe309b302524c882ceb89ced5a66652982178645ee33ee31c0cc542e4fce32fd8f` |
| SSDEEP | `1536:9dpAU2p+mvIFYOv0uNCuh7VBf0VpBb1ka:P2U2lnOvT3Fib1ka` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_b5ca5ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd"
    family = "Mirai"
    file_name = "mini.mips"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:33"
  condition:
    hash.sha256(0, filesize) == "b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd"
}
```

### Sample 89: `5d30e09fd80ce4ba`

| Field | Value |
|---|---|
| SHA-256 | `5d30e09fd80ce4ba08374d63c94dc2e12e1e059fa75f1c4151ac34bd9ccfd92d` |
| Family label | `Mirai` |
| File name | `mini.x86_64` |
| File type | `elf` |
| First seen | `2026-08-10 23:30:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2719b7320d322742ada0faf8d9689270` |
| SHA-1 | `c8985ebc5c4abf90d8beafce2b0477398087eeb2` |
| SHA-256 | `5d30e09fd80ce4ba08374d63c94dc2e12e1e059fa75f1c4151ac34bd9ccfd92d` |
| SHA3-384 | `e628b25af27e60fb63bff3b313819c328ccf4c167ccd6d44a078a93ffed060255edf958f1f72d6fb13e1e8917756bc2b` |
| TLSH | `T17403F841759184FEC05AC2349B7EE52BE932785E32317A5FB789BB351E32D301E0B691` |
| SSDEEP | `768:zyLTIgJU9KXhS5bY6ho+97glpTYTCicKrem:zBS/2bY017gllYS+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_5d30e09f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d30e09fd80ce4ba08374d63c94dc2e12e1e059fa75f1c4151ac34bd9ccfd92d"
    family = "Mirai"
    file_name = "mini.x86_64"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:31"
  condition:
    hash.sha256(0, filesize) == "5d30e09fd80ce4ba08374d63c94dc2e12e1e059fa75f1c4151ac34bd9ccfd92d"
}
```

### Sample 90: `5c2344f30999cb0a`

| Field | Value |
|---|---|
| SHA-256 | `5c2344f30999cb0ada70828adfcdb7efc1d757f76a7f912fe6f1ab9ab3b743dc` |
| Family label | `Mirai` |
| File name | `mini.mpsl` |
| File type | `elf` |
| First seen | `2026-08-10 23:30:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a0ff6df487d9fc92766be98bd310d13` |
| SHA-1 | `8ec4f3f1ed17f88f6cb00e1dee415135eb3849dd` |
| SHA-256 | `5c2344f30999cb0ada70828adfcdb7efc1d757f76a7f912fe6f1ab9ab3b743dc` |
| SHA3-384 | `d3cef950c8fb7de9828b41bd8543f6a7f13c9293ccc73935d81bbcaa9db70a722f99fa45ededdafa389c5f9b00c70e80` |
| TLSH | `T113530A89AEA11BDBC46FCE70453E031726EE485F62E27336457CDC5476EE2088AE3D58` |
| TELFHASH | `t14b01fe309b302524c882ceb89ced5a66652982178645ee33ee31c0cc542e4fce32fd8f` |
| SSDEEP | `1536:ruAGSjhql8FY48NzK3P59sVN1mjWrN6+DQ4pLjfR3:ruAGahql8FY48NzK3PsVN1jo+Dr3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_5c2344f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c2344f30999cb0ada70828adfcdb7efc1d757f76a7f912fe6f1ab9ab3b743dc"
    family = "Mirai"
    file_name = "mini.mpsl"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:30"
  condition:
    hash.sha256(0, filesize) == "5c2344f30999cb0ada70828adfcdb7efc1d757f76a7f912fe6f1ab9ab3b743dc"
}
```

### Sample 91: `1e70b63472772e3f`

| Field | Value |
|---|---|
| SHA-256 | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` |
| Family label | `unknown` |
| File name | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` |
| File type | `sh` |
| First seen | `2026-08-10 23:03:28` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `224b41af1717915304b30540473b8db2` |
| SHA-1 | `90d8371f9dcf69d9823549efb2de0cec384b7d98` |
| SHA-256 | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` |
| SHA3-384 | `ddbb6e5ec939c78f9d87cd25fb1ee8d2e4c7a74e891a144b7d27970133da364c8505ba5a04aa84f9df6dc2ca23824137` |
| TLSH | `T19D41126E74618E7033BDC8BC3885254C6797A66B48262F75B047783D27FC374B2683A6` |
| SSDEEP | `48:vkwvpihneZZn1oB1nDL2Y21j/EmfthmmDoht6GUskURMTCSgMul:vkwYheZZKLTujnFhmmn1o64d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_1e70b634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
    family = "unknown"
    file_name = "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
    file_type = "sh"
    first_seen = "2026-08-10 23:03:28"
  condition:
    hash.sha256(0, filesize) == "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
}
```

### Sample 92: `3f3a11bafabb1a35`

| Field | Value |
|---|---|
| SHA-256 | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` |
| Family label | `unknown` |
| File name | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` |
| File type | `sh` |
| First seen | `2026-08-10 23:03:27` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ca1a863f6a115127d623d3d181ab9b4` |
| SHA-1 | `58c15d76520685b6c151cd48b09375bb94b825be` |
| SHA-256 | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` |
| SHA3-384 | `cdd8c85c79ae614e7cbd464d3a427ae2a1e818378a5a7845895c14abeaef283e15fbff2b42c1175d78239a98e23740d6` |
| TLSH | `T1AB21BE8EABA1ED3120D9D528B7F2493E5E62F29A2C107411358631FCE4DC62032EDC7A` |
| SSDEEP | `24:M1jvF3SbinrGx1wyx1eC2uK6MTzaH+2TMTSIAvF2b2m2p4nKTNXT5eORv:KSbinrS1wO1F2uK6MTu+2TMTSIfy3dAG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_3f3a11ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
    family = "unknown"
    file_name = "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
    file_type = "sh"
    first_seen = "2026-08-10 23:03:27"
  condition:
    hash.sha256(0, filesize) == "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
}
```

### Sample 93: `c52bfa771cc39d66`

| Field | Value |
|---|---|
| SHA-256 | `c52bfa771cc39d666af26400fb68906a4c5c22d88d7ac1d85cb6be0b728c900d` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-10 22:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5af079e5ff8b217a75f4a63945f33a1` |
| SHA-1 | `fa68a3d4de4131a9b355c67dec6c2c7be82b3707` |
| SHA-256 | `c52bfa771cc39d666af26400fb68906a4c5c22d88d7ac1d85cb6be0b728c900d` |
| SHA3-384 | `0008ad6008a997491581e351b616aaab3202040cddd9456617384e102f90e0ea0facc960590e0db11e5a9a58c7ab74d0` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T11BE633186EE001FEEE73463DDBE255A4F874B4624372C89712BC53A15E632F04A79B27` |
| SSDEEP | `393216:GYERDtzzbgCepGEvA2s/bjDWT9tXMCHWUjkcuI3/PGTAI:GYOtPEps/3SHXMb8xH/O7` |
| ICON-DHASH | `5471d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_c52bfa77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c52bfa771cc39d666af26400fb68906a4c5c22d88d7ac1d85cb6be0b728c900d"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-10 22:52:29"
  condition:
    hash.sha256(0, filesize) == "c52bfa771cc39d666af26400fb68906a4c5c22d88d7ac1d85cb6be0b728c900d"
}
```

### Sample 94: `5bb16c59b51e8d7b`

| Field | Value |
|---|---|
| SHA-256 | `5bb16c59b51e8d7b5ecccd686d7b75a0a1ebc5539609f489de6064c47c1cfc7a` |
| Family label | `unknown` |
| File name | `fuck_niggers_8.hta` |
| File type | `hta` |
| First seen | `2026-08-10 22:45:58` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d9888e5aaca0d7af493997815700f61` |
| SHA-1 | `cf19d5ebf09377432f3cc38ad94f8c7e0c5222d3` |
| SHA-256 | `5bb16c59b51e8d7b5ecccd686d7b75a0a1ebc5539609f489de6064c47c1cfc7a` |
| SHA3-384 | `65414764541d273339251edc0223e69a572b7a67984cd98bdd0c74e1e54f2d413c29388fbfb2c66c9c0e4a5bb720978d` |
| TLSH | `T1F142F99CEED172B0F31303CE77AB2929122461D72008C5C5F98C9DE57F467D88666A5A` |
| SSDEEP | `192:sGHNsGeTHQpD+da6+888+UV7tDoj/pxzaW5JYb55qr5HdUIz4CthO5Hk:sGX+/DV7k/3aW5WfqjUg4CTO5Hk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_5bb16c59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb16c59b51e8d7b5ecccd686d7b75a0a1ebc5539609f489de6064c47c1cfc7a"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-08-10 22:45:58"
  condition:
    hash.sha256(0, filesize) == "5bb16c59b51e8d7b5ecccd686d7b75a0a1ebc5539609f489de6064c47c1cfc7a"
}
```

### Sample 95: `1904d30ecdb622d1`

| Field | Value |
|---|---|
| SHA-256 | `1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad` |
| Family label | `unknown` |
| File name | `1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad.elf` |
| File type | `elf` |
| First seen | `2026-08-10 22:13:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9144b289cac323da28e0d128723bb2be` |
| SHA-1 | `5ca5c557834649e2164e595f2de44a66924bf556` |
| SHA-256 | `1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad` |
| SHA3-384 | `9d69e75beeed8469ccfd16406d1373bc2754e118193b68e059cf8d8787e9cce43fa4945afdfe039784a9d66af0b3b031` |
| TLSH | `T10ED33B13FB0C0563C8936DB81E3F07E983656D9210FED115260D7AAA1B33F71A687B99` |
| SSDEEP | `1536:kDWz5jYd1EkPIDTppqzMJD6IwxmvjowjqG9eDx4SsubbmCqZxW5Qv8rTc4:kSz5jY0BDtp1ymrow+G2BbmzWQUTc4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_1904d30e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad"
    family = "unknown"
    file_name = "1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad.elf"
    file_type = "elf"
    first_seen = "2026-08-10 22:13:41"
  condition:
    hash.sha256(0, filesize) == "1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad"
}
```

### Sample 96: `c77e845feedc323e`

| Field | Value |
|---|---|
| SHA-256 | `c77e845feedc323ea12c20ae1859ec06e5959b37d06225bf878f2d7f0e82e66e` |
| Family label | `unknown` |
| File name | `gg11` |
| File type | `elf` |
| First seen | `2026-08-10 22:11:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ed6e3fc1ad03dfe9b4ee8cd0e0286eb` |
| SHA-1 | `b8f6ab80fe2dc5f92ba8b0a480c943260b4469ec` |
| SHA-256 | `c77e845feedc323ea12c20ae1859ec06e5959b37d06225bf878f2d7f0e82e66e` |
| SHA3-384 | `61380177bd3368e68036062f1a624bda0b69a3a59f828833766dd1bb8d612864509a51aca6af221c9266a9548a7e7833` |
| TLSH | `T16F9633A3510619B59483F944E3287CC187A5381B8BE9B8328F4BCAE64DB59F3D7C6707` |
| SSDEEP | `196608:V7RMKKwkni/LzitFnQHklcWgtbuoInjakCNZBY031idBQ8NX/4Q:V7RYwAnpc0o8WkCNZBY031idB5QQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_c77e845f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c77e845feedc323ea12c20ae1859ec06e5959b37d06225bf878f2d7f0e82e66e"
    family = "unknown"
    file_name = "gg11"
    file_type = "elf"
    first_seen = "2026-08-10 22:11:35"
  condition:
    hash.sha256(0, filesize) == "c77e845feedc323ea12c20ae1859ec06e5959b37d06225bf878f2d7f0e82e66e"
}
```

### Sample 97: `7688075202b5fbc5`

| Field | Value |
|---|---|
| SHA-256 | `7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896` |
| Family label | `unknown` |
| File name | `7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896.elf` |
| File type | `elf` |
| First seen | `2026-08-10 22:08:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab75f56e8ba7331dbdff2018a2929ee8` |
| SHA-1 | `77c51bad7de26978ac958985d6f843e21cbee2dc` |
| SHA-256 | `7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896` |
| SHA3-384 | `94206dd7c843c01cd384ae26200acdeb75d4c7e768b71c76b6335677fc7c590442346b4da63a53be911a2f5b9c238f40` |
| TLSH | `T11BD33B767B10AFE6C36CD5300EF28AA54AE6196319E394813365CB1CAE7051D2C9FEF4` |
| SSDEEP | `1536:D3EImlpz63Ip80WGQ28+yRqEm7k8Wrf3QcC64/cUUsEB5WZf9JcEQMMS3joA8Vj2:fy64/ZUHB5WZ/QacjPxAQfzXod` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_76880752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896"
    family = "unknown"
    file_name = "7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896.elf"
    file_type = "elf"
    first_seen = "2026-08-10 22:08:38"
  condition:
    hash.sha256(0, filesize) == "7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896"
}
```

### Sample 98: `76d4b3caa27c65e3`

| Field | Value |
|---|---|
| SHA-256 | `76d4b3caa27c65e33379cfd6abd9dd305338530948733ea228d66a74e72c2269` |
| Family label | `unknown` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-08-10 21:57:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd26026e9bb0db4318609ec74b9317b7` |
| SHA-1 | `342d52ec4f580686f0daf216167fad4fac091c2f` |
| SHA-256 | `76d4b3caa27c65e33379cfd6abd9dd305338530948733ea228d66a74e72c2269` |
| SHA3-384 | `5aa74a5b7ef0ba098031a9df9bd728b543975bbca03db7c6a70c9950a003989fe86311650ae49e71d62f84c42b1a408d` |
| TLSH | `T1B1460797B9925983C5E83637A8BD81C433634EBA8B8752675D05FE383EBE1D90E35304` |
| TELFHASH | `t15ed022004d1c2be4bdd140418824410f8ae130fc29003b80cf6f78cf0f0243e90c1042` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:+2/HbBcecfpME/Tt9u2vz8Wn9XRNJ0+fFh7rZxaYfDr5K4gJJUgdE4L4amBrRu/d:+rCGm2Z5X7UQDYFnO5tS2SOeMTIM5El` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_76d4b3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76d4b3caa27c65e33379cfd6abd9dd305338530948733ea228d66a74e72c2269"
    family = "unknown"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-08-10 21:57:39"
  condition:
    hash.sha256(0, filesize) == "76d4b3caa27c65e33379cfd6abd9dd305338530948733ea228d66a74e72c2269"
}
```

### Sample 99: `4153db289c9a3de5`

| Field | Value |
|---|---|
| SHA-256 | `4153db289c9a3de57845890aadeec7951fcf5516fd39f25c6d8c3e42fc21f801` |
| Family label | `Stealc` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-08-10 21:52:40` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `970730ca84b2c76a69ab7d7a66c44eaa` |
| SHA-1 | `b81060b760438d457b99b76fe250543d80433936` |
| SHA-256 | `4153db289c9a3de57845890aadeec7951fcf5516fd39f25c6d8c3e42fc21f801` |
| SHA3-384 | `f3387c3edcc8515477c2708ed32292648d78a6ff68a9d0d259401add1ac055ee5ca809beaafa6f1fa66fedf521fe3cdb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1AB966B02EF8648F6C406673194A7622F6734B8180B39A7D3EE507A79AF733D15D36788` |
| SSDEEP | `98304:ptltWjGxwSoJ4OlSAxVD60lVEIv1IDxBaW6YK:pUjGxhfc6yQ5U` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_099_4153db28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4153db289c9a3de57845890aadeec7951fcf5516fd39f25c6d8c3e42fc21f801"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-10 21:52:40"
  condition:
    hash.sha256(0, filesize) == "4153db289c9a3de57845890aadeec7951fcf5516fd39f25c6d8c3e42fc21f801"
}
```

### Sample 100: `866d659393017609`

| Field | Value |
|---|---|
| SHA-256 | `866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41` |
| Family label | `CoinMiner` |
| File name | `866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41.exe` |
| File type | `exe` |
| First seen | `2026-08-10 21:48:40` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e13b5835a5d12e0b6099b88292ff0ff` |
| SHA-1 | `c445bd832786c794b03aa4c2b7cdfc5628801823` |
| SHA-256 | `866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41` |
| SHA3-384 | `aea5dc868787568bcb9b1dc483db8b13297521b73f886804793d0dba349cb4e0111cff11a2b91e47ba726022618842b9` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1E73633D265CB007AC442C7B4C656B07C717A3B898A723C1777EC7A248E6BB29293D3C5` |
| SSDEEP | `98304:zWTGeP2Vi4Lx7By+A0pMgBnXr308USgeoP0suSwsvsTkuJvchEzRHpaszbO:zWMr7syXQc5ofuSriyqb` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_100_866d6593
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41"
    family = "CoinMiner"
    file_name = "866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41.exe"
    file_type = "exe"
    first_seen = "2026-08-10 21:48:40"
  condition:
    hash.sha256(0, filesize) == "866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41"
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
 * Generated: 2026-08-11T02:30:53.765780+00:00
 */

rule MalwareBazaar_unknown_001_2d344afe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d344afeb8650715faa758e2627f8b038f601f96696e44dfbd286e7edd0d5fc5"
    family = "unknown"
    file_name = "main.mips32el"
    file_type = "elf"
    first_seen = "2026-08-11 02:26:59"
  condition:
    hash.sha256(0, filesize) == "2d344afeb8650715faa758e2627f8b038f601f96696e44dfbd286e7edd0d5fc5"
}

rule MalwareBazaar_Mirai_002_8daccce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8daccce9ce083a42067a491adc429da788aa6cb7477607333b7bd36fc972ce90"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-11 02:20:53"
  condition:
    hash.sha256(0, filesize) == "8daccce9ce083a42067a491adc429da788aa6cb7477607333b7bd36fc972ce90"
}

rule MalwareBazaar_unknown_003_c35330f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c35330f35585c012777b559eb1b19e144d4585ac51c14ae6b7d98a523ab343a7"
    family = "unknown"
    file_name = "main.microblazebe"
    file_type = "elf"
    first_seen = "2026-08-11 02:20:52"
  condition:
    hash.sha256(0, filesize) == "c35330f35585c012777b559eb1b19e144d4585ac51c14ae6b7d98a523ab343a7"
}

rule MalwareBazaar_unknown_004_203c2357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "203c2357d1ff6bf0804a580c31265526608b2b16b7420b54f0fc6125f4da487a"
    family = "unknown"
    file_name = "weakssh_2026-08-05-fleet-reset_bin__tmp_.killer.sh"
    file_type = "sh"
    first_seen = "2026-08-11 02:19:02"
  condition:
    hash.sha256(0, filesize) == "203c2357d1ff6bf0804a580c31265526608b2b16b7420b54f0fc6125f4da487a"
}

rule MalwareBazaar_unknown_005_b7d0ce10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7d0ce1014da1bd04bfc8f04175daa5c8e26e86b2bb27a5be05f12ac1a7d6684"
    family = "unknown"
    file_name = "weakssh_2026-08-05-fleet-reset_bin__tmp_flood"
    file_type = "elf"
    first_seen = "2026-08-11 02:19:00"
  condition:
    hash.sha256(0, filesize) == "b7d0ce1014da1bd04bfc8f04175daa5c8e26e86b2bb27a5be05f12ac1a7d6684"
}

rule MalwareBazaar_unknown_006_aa0c6cdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa0c6cdbeb3bc3ce07d5060958e1a38e54287bc89e25f6def98b620999ff4f7a"
    family = "unknown"
    file_name = "joomla_2026-08-04-fleet-reset_bin__dev_shm_1oDGzJ"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:56"
  condition:
    hash.sha256(0, filesize) == "aa0c6cdbeb3bc3ce07d5060958e1a38e54287bc89e25f6def98b620999ff4f7a"
}

rule MalwareBazaar_unknown_007_0b8e037d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8e037d160bdb0b621c975c424f680b814bc438fd492ae376ff3140e209e480"
    family = "unknown"
    file_name = "joomla_2026-08-04-fleet-reset_pid38429.bin"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:54"
  condition:
    hash.sha256(0, filesize) == "0b8e037d160bdb0b621c975c424f680b814bc438fd492ae376ff3140e209e480"
}

rule MalwareBazaar_unknown_008_deaeab9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deaeab9eb43fcf70d184c209e4bc1077ae6e7e2b182c1cbbc202dfdc053dc01c"
    family = "unknown"
    file_name = "langflow_2026-08-05-react2shell-end_bin__dev_shm_5poLwV4"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:52"
  condition:
    hash.sha256(0, filesize) == "deaeab9eb43fcf70d184c209e4bc1077ae6e7e2b182c1cbbc202dfdc053dc01c"
}

rule MalwareBazaar_unknown_009_d9ae9bf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9ae9bf4b810b07470e786deb6454b8928cba4fe77278b8f4b4f6c5cdcb4e0c4"
    family = "unknown"
    file_name = "joomla_2026-08-05-fleet-reset_pid29905.bin"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:49"
  condition:
    hash.sha256(0, filesize) == "d9ae9bf4b810b07470e786deb6454b8928cba4fe77278b8f4b4f6c5cdcb4e0c4"
}

rule MalwareBazaar_unknown_010_dcbf7b7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcbf7b7f32b4f9b326b3bf7c8f2548f642b294b8dbe01e02154d8fcc27b7da84"
    family = "unknown"
    file_name = "shai.quarantine.bin"
    file_type = "elf"
    first_seen = "2026-08-11 02:18:46"
  condition:
    hash.sha256(0, filesize) == "dcbf7b7f32b4f9b326b3bf7c8f2548f642b294b8dbe01e02154d8fcc27b7da84"
}

rule MalwareBazaar_unknown_011_4c946609
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c946609323494ac329f2c4347d103595a1d0cebe99bdc39acbe19b3a1562178"
    family = "unknown"
    file_name = "main.power8le"
    file_type = "elf"
    first_seen = "2026-08-11 02:17:52"
  condition:
    hash.sha256(0, filesize) == "4c946609323494ac329f2c4347d103595a1d0cebe99bdc39acbe19b3a1562178"
}

rule MalwareBazaar_Mirai_012_299b568e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "299b568e8d0725a31ae143c20554aef27c52a4cb1dbab0b718d997a0adf40c52"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 02:15:56"
  condition:
    hash.sha256(0, filesize) == "299b568e8d0725a31ae143c20554aef27c52a4cb1dbab0b718d997a0adf40c52"
}

rule MalwareBazaar_unknown_013_f376bc73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f376bc73f8923ebe3711bb551a20aaf39bb19e0b4ef3e0622bcb03ba1783feec"
    family = "unknown"
    file_name = "MV_SEA_LADY_VESSEL_MAIN_PARTICULARSpdf.js"
    file_type = "js"
    first_seen = "2026-08-11 02:15:42"
  condition:
    hash.sha256(0, filesize) == "f376bc73f8923ebe3711bb551a20aaf39bb19e0b4ef3e0622bcb03ba1783feec"
}

rule MalwareBazaar_unknown_014_824f9626
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "824f9626e070519b3bfff42ecf6876cb48cb0dbf1431702db3e18a5dd923b1ce"
    family = "unknown"
    file_name = "main.x86-64-v3"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:57"
  condition:
    hash.sha256(0, filesize) == "824f9626e070519b3bfff42ecf6876cb48cb0dbf1431702db3e18a5dd923b1ce"
}

rule MalwareBazaar_unknown_015_4c5a6b87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c5a6b87212177f62fe3174916727a424223a1a315cba018ea5494f3c2e1dffb"
    family = "unknown"
    file_name = "main.aarch64be"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:56"
  condition:
    hash.sha256(0, filesize) == "4c5a6b87212177f62fe3174916727a424223a1a315cba018ea5494f3c2e1dffb"
}

rule MalwareBazaar_unknown_016_2659d55e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2659d55e43243fc981db78cf99dff1a7d06f08e056ae17c3b49f0dccb39eb02b"
    family = "unknown"
    file_name = "main.aarch64"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:54"
  condition:
    hash.sha256(0, filesize) == "2659d55e43243fc981db78cf99dff1a7d06f08e056ae17c3b49f0dccb39eb02b"
}

rule MalwareBazaar_Mirai_017_6abf0b2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6abf0b2cfee342e686454b83371b2148bcecbd7a1c453a08468fa41a9713264a"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 02:14:53"
  condition:
    hash.sha256(0, filesize) == "6abf0b2cfee342e686454b83371b2148bcecbd7a1c453a08468fa41a9713264a"
}

rule MalwareBazaar_Mirai_018_020fd6b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.mips"
    file_type = "elf"
    first_seen = "2026-08-11 02:09:52"
  condition:
    hash.sha256(0, filesize) == "020fd6b946c52e68ea21a1533d6ed5f9f3b50fc1d19eef0c1fd6e8c18802505b"
}

rule MalwareBazaar_Mirai_019_27521c4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27521c4e0452c798e790ce99c83c79e13ddcfab4833424e9fe8d3d83f42b6dbd"
    family = "Mirai"
    file_name = "sdfjgnjsdf.mips"
    file_type = "elf"
    first_seen = "2026-08-11 02:08:54"
  condition:
    hash.sha256(0, filesize) == "27521c4e0452c798e790ce99c83c79e13ddcfab4833424e9fe8d3d83f42b6dbd"
}

rule MalwareBazaar_unknown_020_40506dd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40506dd6fa56f5b5846f98e5d5d2f67ce1705875968d311149b5598182997855"
    family = "unknown"
    file_name = "main.sh4musl"
    file_type = "elf"
    first_seen = "2026-08-11 02:08:53"
  condition:
    hash.sha256(0, filesize) == "40506dd6fa56f5b5846f98e5d5d2f67ce1705875968d311149b5598182997855"
}

rule MalwareBazaar_unknown_021_23f0eb8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23f0eb8fdcbb3953d5fb11638e90f02fe479a41280366d06ff2f74c4d91286fa"
    family = "unknown"
    file_name = "main.x86-64"
    file_type = "elf"
    first_seen = "2026-08-11 02:06:05"
  condition:
    hash.sha256(0, filesize) == "23f0eb8fdcbb3953d5fb11638e90f02fe479a41280366d06ff2f74c4d91286fa"
}

rule MalwareBazaar_unknown_022_a9a8cdb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d"
    family = "unknown"
    file_name = "main.x86-64-v2"
    file_type = "elf"
    first_seen = "2026-08-11 02:06:03"
  condition:
    hash.sha256(0, filesize) == "a9a8cdb6e564a63b2d1c35a40437820627b97f49ae4878acde7695baa645e58d"
}

rule MalwareBazaar_unknown_023_f3c0f212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3c0f212bf355c64b118fe3f90a581229085c1554b1ee4a70cc36784db6add4d"
    family = "unknown"
    file_name = "main.armv4tl"
    file_type = "elf"
    first_seen = "2026-08-11 02:03:02"
  condition:
    hash.sha256(0, filesize) == "f3c0f212bf355c64b118fe3f90a581229085c1554b1ee4a70cc36784db6add4d"
}

rule MalwareBazaar_unknown_024_91bc6520
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91bc65200be32f5580e65b5ea5bb76d5943764784ac043cf33a36b6186d09e02"
    family = "unknown"
    file_name = "main.arm7"
    file_type = "elf"
    first_seen = "2026-08-11 02:03:01"
  condition:
    hash.sha256(0, filesize) == "91bc65200be32f5580e65b5ea5bb76d5943764784ac043cf33a36b6186d09e02"
}

rule MalwareBazaar_unknown_025_f51dd33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f51dd33eae0cf40d4e79ab76e7418ac200c3963b5853a97a86381df9d44913c8"
    family = "unknown"
    file_name = "main.mips"
    file_type = "elf"
    first_seen = "2026-08-11 01:59:39"
  condition:
    hash.sha256(0, filesize) == "f51dd33eae0cf40d4e79ab76e7418ac200c3963b5853a97a86381df9d44913c8"
}

rule MalwareBazaar_unknown_026_ef8d8e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef8d8e696a3bba50b1b2fc283fa0764071c584a3773c34c07b2fa4d291065533"
    family = "unknown"
    file_name = "main.arc700"
    file_type = "elf"
    first_seen = "2026-08-11 01:59:38"
  condition:
    hash.sha256(0, filesize) == "ef8d8e696a3bba50b1b2fc283fa0764071c584a3773c34c07b2fa4d291065533"
}

rule MalwareBazaar_unknown_027_81ad7c94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ad7c9495e9299aa17bc6afcafdbb1f0484abf1bba0c268258eb0854d1053bb"
    family = "unknown"
    file_name = "main.nios2"
    file_type = "elf"
    first_seen = "2026-08-11 01:56:46"
  condition:
    hash.sha256(0, filesize) == "81ad7c9495e9299aa17bc6afcafdbb1f0484abf1bba0c268258eb0854d1053bb"
}

rule MalwareBazaar_unknown_028_1dfa46e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dfa46e7c90d88401770795ff748b87bb657c22223fdcfbde199b2fc82412e97"
    family = "unknown"
    file_name = "main.armv4eb"
    file_type = "elf"
    first_seen = "2026-08-11 01:56:45"
  condition:
    hash.sha256(0, filesize) == "1dfa46e7c90d88401770795ff748b87bb657c22223fdcfbde199b2fc82412e97"
}

rule MalwareBazaar_unknown_029_1a10aa47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a10aa47242d1d71b422dff69b286fc69464f3f132692e2a1daff7a17cbaad99"
    family = "unknown"
    file_name = "main.m68k-68xxx"
    file_type = "elf"
    first_seen = "2026-08-11 01:56:43"
  condition:
    hash.sha256(0, filesize) == "1a10aa47242d1d71b422dff69b286fc69464f3f132692e2a1daff7a17cbaad99"
}

rule MalwareBazaar_unknown_030_668e88ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668e88ae20d78da7e3c2bbd7bbcc2d47859dab434d43f8522ea8fafe3d027974"
    family = "unknown"
    file_name = "main.mips64el-n32"
    file_type = "elf"
    first_seen = "2026-08-11 01:53:41"
  condition:
    hash.sha256(0, filesize) == "668e88ae20d78da7e3c2bbd7bbcc2d47859dab434d43f8522ea8fafe3d027974"
}

rule MalwareBazaar_unknown_031_eaf494a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaf494a999b3263ee4bc5d271d7baad632dac308458eb2370880a4971c115b54"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-11 01:53:38"
  condition:
    hash.sha256(0, filesize) == "eaf494a999b3263ee4bc5d271d7baad632dac308458eb2370880a4971c115b54"
}

rule MalwareBazaar_unknown_032_62372c74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62372c7464bcdfd03129aed0a9aa1d6dd892695f39e3fbb911d88b1d93019f77"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-11 01:52:29"
  condition:
    hash.sha256(0, filesize) == "62372c7464bcdfd03129aed0a9aa1d6dd892695f39e3fbb911d88b1d93019f77"
}

rule MalwareBazaar_unknown_033_0c411bf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95"
    family = "unknown"
    file_name = "0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:48:46"
  condition:
    hash.sha256(0, filesize) == "0c411bf6df62ee8383027f24000510220b4fff2a806a36296bf7cda699540b95"
}

rule MalwareBazaar_unknown_034_cc589f2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140"
    family = "unknown"
    file_name = "cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:48:40"
  condition:
    hash.sha256(0, filesize) == "cc589f2eea34d1a4d17b141d63d3bdeb215232823d6a4f3a379e34c27fce4140"
}

rule MalwareBazaar_unknown_035_47da0746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47da0746c7cd0150c953739c3232dba9a0ab71871ee12dfd60dc7f29a9cdff27"
    family = "unknown"
    file_name = "main.mips64-n32"
    file_type = "elf"
    first_seen = "2026-08-11 01:47:55"
  condition:
    hash.sha256(0, filesize) == "47da0746c7cd0150c953739c3232dba9a0ab71871ee12dfd60dc7f29a9cdff27"
}

rule MalwareBazaar_unknown_036_fd3f7fad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd3f7faddcdd31222f760c4afb3b8a5600185580b9e3da5057f901d3284f3e54"
    family = "unknown"
    file_name = "main.sh4"
    file_type = "elf"
    first_seen = "2026-08-11 01:47:54"
  condition:
    hash.sha256(0, filesize) == "fd3f7faddcdd31222f760c4afb3b8a5600185580b9e3da5057f901d3284f3e54"
}

rule MalwareBazaar_unknown_037_163d2225
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163d2225f3f683055419afa274721e28e62b9894be4944dc425d9d2b27b6cbb1"
    family = "unknown"
    file_name = "main.mips32"
    file_type = "elf"
    first_seen = "2026-08-11 01:47:52"
  condition:
    hash.sha256(0, filesize) == "163d2225f3f683055419afa274721e28e62b9894be4944dc425d9d2b27b6cbb1"
}

rule MalwareBazaar_unknown_038_672de551
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "672de551af096192ece9e57ee4727d2dd48b81957a4f61373aae955ae3442def"
    family = "unknown"
    file_name = "main.power8"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:46"
  condition:
    hash.sha256(0, filesize) == "672de551af096192ece9e57ee4727d2dd48b81957a4f61373aae955ae3442def"
}

rule MalwareBazaar_unknown_039_e800b9b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e800b9b98694c7dbda551c120e69d50eff0f5d9b42986ef5c95f79f0f3a710a3"
    family = "unknown"
    file_name = "main.sh4aeb"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:45"
  condition:
    hash.sha256(0, filesize) == "e800b9b98694c7dbda551c120e69d50eff0f5d9b42986ef5c95f79f0f3a710a3"
}

rule MalwareBazaar_unknown_040_9d9f0d34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d9f0d3402bbd8a90760c9615305249a3f6f55dcdaea21a41014da22b9227bc7"
    family = "unknown"
    file_name = "main.sparcv8"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:44"
  condition:
    hash.sha256(0, filesize) == "9d9f0d3402bbd8a90760c9615305249a3f6f55dcdaea21a41014da22b9227bc7"
}

rule MalwareBazaar_unknown_041_bf856f82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf856f82da6d59b49cf76df8be0ce10fd3abda52dda587b5108b68133cea9486"
    family = "unknown"
    file_name = "main.x86-i686"
    file_type = "elf"
    first_seen = "2026-08-11 01:44:42"
  condition:
    hash.sha256(0, filesize) == "bf856f82da6d59b49cf76df8be0ce10fd3abda52dda587b5108b68133cea9486"
}

rule MalwareBazaar_unknown_042_60c2382b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f"
    family = "unknown"
    file_name = "60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:43:48"
  condition:
    hash.sha256(0, filesize) == "60c2382b1db5293458a0a40089926a0c8d1fb715703a294085ce3a7cb555ab7f"
}

rule MalwareBazaar_unknown_043_388f63f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56"
    family = "unknown"
    file_name = "388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:43:42"
  condition:
    hash.sha256(0, filesize) == "388f63f0eb52acdcf3bba77ec0c470139b5a24b17ba22be2510d3166d739be56"
}

rule MalwareBazaar_unknown_044_4911b159
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4911b1593b03a4f312d8314762cd9e3b529fde33f34a61a4f2081f137529ef7c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-11 01:43:40"
  condition:
    hash.sha256(0, filesize) == "4911b1593b03a4f312d8314762cd9e3b529fde33f34a61a4f2081f137529ef7c"
}

rule MalwareBazaar_unknown_045_189a03e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189a03e754ec12e37efe0ba49a7982d0ad10d524fdc509f414575ab5264d7978"
    family = "unknown"
    file_name = "main.mips32r5el"
    file_type = "elf"
    first_seen = "2026-08-11 01:41:38"
  condition:
    hash.sha256(0, filesize) == "189a03e754ec12e37efe0ba49a7982d0ad10d524fdc509f414575ab5264d7978"
}

rule MalwareBazaar_unknown_046_5d7b90ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7b90ad2083eb246eaa32593f29ca0485bf1f743760692df72ccec1103c30aa"
    family = "unknown"
    file_name = "main.mips64"
    file_type = "elf"
    first_seen = "2026-08-11 01:41:36"
  condition:
    hash.sha256(0, filesize) == "5d7b90ad2083eb246eaa32593f29ca0485bf1f743760692df72ccec1103c30aa"
}

rule MalwareBazaar_unknown_047_0e3a7809
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a"
    family = "unknown"
    file_name = "0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:38:41"
  condition:
    hash.sha256(0, filesize) == "0e3a78094c70edeaa6c07fcc4c874f4d1a42ff8e9f1a3870e9fad4ead8ecc46a"
}

rule MalwareBazaar_unknown_048_c489ac18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c489ac18a01a725418502656287ef6fdf7fd5550c7ab6cf6d63912cf6dcb7d40"
    family = "unknown"
    file_name = "main.e300c3"
    file_type = "elf"
    first_seen = "2026-08-11 01:38:39"
  condition:
    hash.sha256(0, filesize) == "c489ac18a01a725418502656287ef6fdf7fd5550c7ab6cf6d63912cf6dcb7d40"
}

rule MalwareBazaar_unknown_049_92f5d59c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f5d59c480c7158cb58d461c5ea8050994fdc8d3093095df6912ea696a9e511"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-11 01:38:36"
  condition:
    hash.sha256(0, filesize) == "92f5d59c480c7158cb58d461c5ea8050994fdc8d3093095df6912ea696a9e511"
}

rule MalwareBazaar_unknown_050_3dd7b808
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dd7b8084d0fd21045bd18309630c2eaffce420f7d4c4db56d79935e0935c333"
    family = "unknown"
    file_name = "main.riscv64"
    file_type = "elf"
    first_seen = "2026-08-11 01:35:45"
  condition:
    hash.sha256(0, filesize) == "3dd7b8084d0fd21045bd18309630c2eaffce420f7d4c4db56d79935e0935c333"
}

rule MalwareBazaar_unknown_051_c3e58e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3e58e0f33d6668f6b37646095b8484dd97b8182ab97b25a19c4ed4bfdeb6080"
    family = "unknown"
    file_name = "bot.386"
    file_type = "elf"
    first_seen = "2026-08-11 01:35:43"
  condition:
    hash.sha256(0, filesize) == "c3e58e0f33d6668f6b37646095b8484dd97b8182ab97b25a19c4ed4bfdeb6080"
}

rule MalwareBazaar_Mirai_052_d345ea8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d345ea8ec62bb05db1652ff3b4db194fa6d730263e4186c6dc851a45569c845b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.m68k"
    file_type = "elf"
    first_seen = "2026-08-11 01:35:41"
  condition:
    hash.sha256(0, filesize) == "d345ea8ec62bb05db1652ff3b4db194fa6d730263e4186c6dc851a45569c845b"
}

rule MalwareBazaar_unknown_053_40ee84ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40ee84ea58804b34c5f9b741d988ce497f029ba143b202887581bbffe1df3851"
    family = "unknown"
    file_name = "main.riscv32"
    file_type = "elf"
    first_seen = "2026-08-11 01:32:40"
  condition:
    hash.sha256(0, filesize) == "40ee84ea58804b34c5f9b741d988ce497f029ba143b202887581bbffe1df3851"
}

rule MalwareBazaar_unknown_054_fc92d536
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc92d53673d72cf005ae433b9493ff8f6e0c7a2b1588ce89d2d85e94c35770a5"
    family = "unknown"
    file_name = "main.xtensa"
    file_type = "elf"
    first_seen = "2026-08-11 01:32:39"
  condition:
    hash.sha256(0, filesize) == "fc92d53673d72cf005ae433b9493ff8f6e0c7a2b1588ce89d2d85e94c35770a5"
}

rule MalwareBazaar_Mirai_055_94ae8167
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94ae81675ebf3620fa2c5acb37cb9d8d5afe0521cf97eea5242c12fd52f58ad2"
    family = "Mirai"
    file_name = "main.armv6"
    file_type = "elf"
    first_seen = "2026-08-11 01:32:38"
  condition:
    hash.sha256(0, filesize) == "94ae81675ebf3620fa2c5acb37cb9d8d5afe0521cf97eea5242c12fd52f58ad2"
}

rule MalwareBazaar_unknown_056_c23fff87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1"
    family = "unknown"
    file_name = "c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1.elf"
    file_type = "elf"
    first_seen = "2026-08-11 01:28:46"
  condition:
    hash.sha256(0, filesize) == "c23fff87e5ab3227d638073b8624c258e91849f11dbb8d8edb35c01a2c4711f1"
}

rule MalwareBazaar_unknown_057_24cee19d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cee19d2763a412eb4bf710986acd1373a4754729986f4101913da9e0da4bbc"
    family = "unknown"
    file_name = "main.x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:50"
  condition:
    hash.sha256(0, filesize) == "24cee19d2763a412eb4bf710986acd1373a4754729986f4101913da9e0da4bbc"
}

rule MalwareBazaar_unknown_058_08884015
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "088840155e73df853dc78841aebe420334f295a159ea5151c143ce17e4f3f4ec"
    family = "unknown"
    file_name = "main.archs38"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:48"
  condition:
    hash.sha256(0, filesize) == "088840155e73df853dc78841aebe420334f295a159ea5151c143ce17e4f3f4ec"
}

rule MalwareBazaar_unknown_059_916162f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "916162f62f9942458ed422ccb19d0d1edd302daa7522b1715812f35d2da6beb8"
    family = "unknown"
    file_name = "main.x86-64-i7"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:47"
  condition:
    hash.sha256(0, filesize) == "916162f62f9942458ed422ccb19d0d1edd302daa7522b1715812f35d2da6beb8"
}

rule MalwareBazaar_unknown_060_db21148c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db21148cb2f460bf23be50839733754643ee69916b186af6792619251c807a46"
    family = "unknown"
    file_name = "main.mips64r6el-n32"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:46"
  condition:
    hash.sha256(0, filesize) == "db21148cb2f460bf23be50839733754643ee69916b186af6792619251c807a46"
}

rule MalwareBazaar_Mirai_061_3b6902d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b6902d4973b9a5d54a1812b74f531e53913ac924b590be96cbb57b3fa55f79c"
    family = "Mirai"
    file_name = "main.armv5"
    file_type = "elf"
    first_seen = "2026-08-11 01:26:44"
  condition:
    hash.sha256(0, filesize) == "3b6902d4973b9a5d54a1812b74f531e53913ac924b590be96cbb57b3fa55f79c"
}

rule MalwareBazaar_unknown_062_8760d69e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8760d69e7776681bcb3712d3e13bdee42f43e6566a395424cb014876bc3d1863"
    family = "unknown"
    file_name = "main.powerpc"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:42"
  condition:
    hash.sha256(0, filesize) == "8760d69e7776681bcb3712d3e13bdee42f43e6566a395424cb014876bc3d1863"
}

rule MalwareBazaar_unknown_063_236c34fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "236c34fca99a0818058bb2074dfe2d0d6e10c6bb517e6a08c4fedc27c6be805b"
    family = "unknown"
    file_name = "main.e5500"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:41"
  condition:
    hash.sha256(0, filesize) == "236c34fca99a0818058bb2074dfe2d0d6e10c6bb517e6a08c4fedc27c6be805b"
}

rule MalwareBazaar_unknown_064_1a52e179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a52e179c51c3ce5b3ea3529f9c95a3fbd1fdced9d2d7476d4ffdfd40ac1d134"
    family = "unknown"
    file_name = "main.armv7-eabihf"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:38"
  condition:
    hash.sha256(0, filesize) == "1a52e179c51c3ce5b3ea3529f9c95a3fbd1fdced9d2d7476d4ffdfd40ac1d134"
}

rule MalwareBazaar_Mirai_065_fbb37366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbb37366d512207792c0cc90de869deddecb4d412f390787e01dd93d602e92cb"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arc"
    file_type = "elf"
    first_seen = "2026-08-11 01:23:37"
  condition:
    hash.sha256(0, filesize) == "fbb37366d512207792c0cc90de869deddecb4d412f390787e01dd93d602e92cb"
}

rule MalwareBazaar_unknown_066_9198759b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9198759b9ca91109f5a59dac8db5b8c2574fd32c29bd796e16a23ef595968e41"
    family = "unknown"
    file_name = "main.e500mc"
    file_type = "elf"
    first_seen = "2026-08-11 01:20:39"
  condition:
    hash.sha256(0, filesize) == "9198759b9ca91109f5a59dac8db5b8c2574fd32c29bd796e16a23ef595968e41"
}

rule MalwareBazaar_unknown_067_b38e4301
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927"
    family = "unknown"
    file_name = "bot.arm64"
    file_type = "elf"
    first_seen = "2026-08-11 01:20:38"
  condition:
    hash.sha256(0, filesize) == "b38e430116c0c1a0763055bcdc6e2aa84b96523c9854ca62b46394e8666c7927"
}

rule MalwareBazaar_Mirai_068_1df747a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1df747a30c57bc640d7403663cd37d11da3b4bf3917b83a7e5a89fdae81b9fe2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 01:18:31"
  condition:
    hash.sha256(0, filesize) == "1df747a30c57bc640d7403663cd37d11da3b4bf3917b83a7e5a89fdae81b9fe2"
}

rule MalwareBazaar_unknown_069_7dc97e65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc97e65d07416aac2ec2fa717a672928f5d1abd21d8adcfb108e0373bb5ceb4"
    family = "unknown"
    file_name = "main.mips32r6el"
    file_type = "elf"
    first_seen = "2026-08-11 01:17:59"
  condition:
    hash.sha256(0, filesize) == "7dc97e65d07416aac2ec2fa717a672928f5d1abd21d8adcfb108e0373bb5ceb4"
}

rule MalwareBazaar_Mirai_070_83a7f359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a7f3594007039ce3df172e73bca5fbba86b7486f27349841d5df9fee6f4b07"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-11 01:17:58"
  condition:
    hash.sha256(0, filesize) == "83a7f3594007039ce3df172e73bca5fbba86b7486f27349841d5df9fee6f4b07"
}

rule MalwareBazaar_unknown_071_769f8ef1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769f8ef1aa8c84e8735445711584e227afc0abf677ff93333421af061a9559e2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-11 01:16:38"
  condition:
    hash.sha256(0, filesize) == "769f8ef1aa8c84e8735445711584e227afc0abf677ff93333421af061a9559e2"
}

rule MalwareBazaar_unknown_072_ff52c676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff52c676b94b6fad17731931a2c25cf5cd7c71ff6641abab3bd00f5c6a487056"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-11 00:52:44"
  condition:
    hash.sha256(0, filesize) == "ff52c676b94b6fad17731931a2c25cf5cd7c71ff6641abab3bd00f5c6a487056"
}

rule MalwareBazaar_Mirai_073_abb086be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0"
    family = "Mirai"
    file_name = "abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:38:48"
  condition:
    hash.sha256(0, filesize) == "abb086bee2b6e255446c1ce7a66251998957469974dd5e85caf7868f0b1644e0"
}

rule MalwareBazaar_Mirai_074_6c23a44f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9"
    family = "Mirai"
    file_name = "6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:38:44"
  condition:
    hash.sha256(0, filesize) == "6c23a44f0bb66ed004961a68a417cd762e2a4a6395d01c53908324f7e9e803c9"
}

rule MalwareBazaar_Mirai_075_f49396d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741"
    family = "Mirai"
    file_name = "f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:33:40"
  condition:
    hash.sha256(0, filesize) == "f49396d2d2313b5f8d0b775d38d19ef4155361169a1af1b622d0a3079f4a2741"
}

rule MalwareBazaar_Mirai_076_f66626b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac"
    family = "Mirai"
    file_name = "f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac.elf"
    file_type = "elf"
    first_seen = "2026-08-11 00:33:37"
  condition:
    hash.sha256(0, filesize) == "f66626b11eb9356a0cbcd048d2ac007493065019ec020473d135c39f7dbe93ac"
}

rule MalwareBazaar_unknown_077_5c76bc92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c76bc92d700c050a7a8126ce43e4ac29db312022cf3ce32717b8f07e26590f5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-11 00:31:17"
  condition:
    hash.sha256(0, filesize) == "5c76bc92d700c050a7a8126ce43e4ac29db312022cf3ce32717b8f07e26590f5"
}

rule MalwareBazaar_Mirai_078_166eb2c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "166eb2c6aabc4d4b8bbb0e9571aaf5d2a97a2cb1f22ca84e0d42f22d8ff4a920"
    family = "Mirai"
    file_name = "sdfjgnjsdf.ppc"
    file_type = "elf"
    first_seen = "2026-08-11 00:19:29"
  condition:
    hash.sha256(0, filesize) == "166eb2c6aabc4d4b8bbb0e9571aaf5d2a97a2cb1f22ca84e0d42f22d8ff4a920"
}

rule MalwareBazaar_Mirai_079_67f87dab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67f87dab198b2892965a8d03b42b89320fe53666be1d4b83e1c2e2632b8fcd97"
    family = "Mirai"
    file_name = "sdfjgnjsdf.ppc"
    file_type = "elf"
    first_seen = "2026-08-11 00:18:31"
  condition:
    hash.sha256(0, filesize) == "67f87dab198b2892965a8d03b42b89320fe53666be1d4b83e1c2e2632b8fcd97"
}

rule MalwareBazaar_Mirai_080_be8947c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806"
    family = "Mirai"
    file_name = "be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806"
    file_type = "elf"
    first_seen = "2026-08-11 00:02:34"
  condition:
    hash.sha256(0, filesize) == "be8947c577699304112a86ec5418586f5993ec17a2c435aa8d1533a62400a806"
}

rule MalwareBazaar_Mirai_081_e30b557c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36"
    family = "Mirai"
    file_name = "e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36"
    file_type = "elf"
    first_seen = "2026-08-11 00:02:31"
  condition:
    hash.sha256(0, filesize) == "e30b557c9621436b70441106311009ffc2e3939798253ee2f0d137048e21cc36"
}

rule MalwareBazaar_Mirai_082_156ee410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed"
    family = "Mirai"
    file_name = "156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed"
    file_type = "elf"
    first_seen = "2026-08-11 00:02:28"
  condition:
    hash.sha256(0, filesize) == "156ee410363b67810416d16a797225ffbaa01cf80daeaff346dabf199f75cbed"
}

rule MalwareBazaar_unknown_083_e4eaae68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322"
    family = "unknown"
    file_name = "e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322"
    file_type = "sh"
    first_seen = "2026-08-11 00:02:25"
  condition:
    hash.sha256(0, filesize) == "e4eaae680e23b413ec82a1cb66b4704f2d5df913520700f15e1a65c4ce10d322"
}

rule MalwareBazaar_unknown_084_ca67190a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca67190aa9dc8b5de33ed8d29e8b7d87d9057cb1835ae9cc3fa727abc1958b4b"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-10 23:49:33"
  condition:
    hash.sha256(0, filesize) == "ca67190aa9dc8b5de33ed8d29e8b7d87d9057cb1835ae9cc3fa727abc1958b4b"
}

rule MalwareBazaar_unknown_085_3b842c26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b842c26338a3e6c1c76f358f7df3876b1a71f211cb8e5294ae8e1471d0aa526"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-10 23:42:30"
  condition:
    hash.sha256(0, filesize) == "3b842c26338a3e6c1c76f358f7df3876b1a71f211cb8e5294ae8e1471d0aa526"
}

rule MalwareBazaar_Mirai_086_8b0e129a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0e129a647a6ccea436f6d16d3043337a723fe48bf19f366e22e7e5149500a9"
    family = "Mirai"
    file_name = "mini.arm7"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:36"
  condition:
    hash.sha256(0, filesize) == "8b0e129a647a6ccea436f6d16d3043337a723fe48bf19f366e22e7e5149500a9"
}

rule MalwareBazaar_Mirai_087_bbbe8f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbbe8f578cb150ea93dc8dae245a626f9adcdabef7f10d766f8c4d69ed88c619"
    family = "Mirai"
    file_name = "mini.arm64"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:34"
  condition:
    hash.sha256(0, filesize) == "bbbe8f578cb150ea93dc8dae245a626f9adcdabef7f10d766f8c4d69ed88c619"
}

rule MalwareBazaar_Mirai_088_b5ca5ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd"
    family = "Mirai"
    file_name = "mini.mips"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:33"
  condition:
    hash.sha256(0, filesize) == "b5ca5ab2333aa186807dd398a0f666bd8ab39fd88606cc0942084a7c9bf68afd"
}

rule MalwareBazaar_Mirai_089_5d30e09f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d30e09fd80ce4ba08374d63c94dc2e12e1e059fa75f1c4151ac34bd9ccfd92d"
    family = "Mirai"
    file_name = "mini.x86_64"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:31"
  condition:
    hash.sha256(0, filesize) == "5d30e09fd80ce4ba08374d63c94dc2e12e1e059fa75f1c4151ac34bd9ccfd92d"
}

rule MalwareBazaar_Mirai_090_5c2344f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c2344f30999cb0ada70828adfcdb7efc1d757f76a7f912fe6f1ab9ab3b743dc"
    family = "Mirai"
    file_name = "mini.mpsl"
    file_type = "elf"
    first_seen = "2026-08-10 23:30:30"
  condition:
    hash.sha256(0, filesize) == "5c2344f30999cb0ada70828adfcdb7efc1d757f76a7f912fe6f1ab9ab3b743dc"
}

rule MalwareBazaar_unknown_091_1e70b634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
    family = "unknown"
    file_name = "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
    file_type = "sh"
    first_seen = "2026-08-10 23:03:28"
  condition:
    hash.sha256(0, filesize) == "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
}

rule MalwareBazaar_unknown_092_3f3a11ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
    family = "unknown"
    file_name = "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
    file_type = "sh"
    first_seen = "2026-08-10 23:03:27"
  condition:
    hash.sha256(0, filesize) == "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
}

rule MalwareBazaar_unknown_093_c52bfa77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c52bfa771cc39d666af26400fb68906a4c5c22d88d7ac1d85cb6be0b728c900d"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-10 22:52:29"
  condition:
    hash.sha256(0, filesize) == "c52bfa771cc39d666af26400fb68906a4c5c22d88d7ac1d85cb6be0b728c900d"
}

rule MalwareBazaar_unknown_094_5bb16c59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bb16c59b51e8d7b5ecccd686d7b75a0a1ebc5539609f489de6064c47c1cfc7a"
    family = "unknown"
    file_name = "fuck_niggers_8.hta"
    file_type = "hta"
    first_seen = "2026-08-10 22:45:58"
  condition:
    hash.sha256(0, filesize) == "5bb16c59b51e8d7b5ecccd686d7b75a0a1ebc5539609f489de6064c47c1cfc7a"
}

rule MalwareBazaar_unknown_095_1904d30e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad"
    family = "unknown"
    file_name = "1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad.elf"
    file_type = "elf"
    first_seen = "2026-08-10 22:13:41"
  condition:
    hash.sha256(0, filesize) == "1904d30ecdb622d1e657e56973578d062e4f109c4e9913a6f6fd47eed34283ad"
}

rule MalwareBazaar_unknown_096_c77e845f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c77e845feedc323ea12c20ae1859ec06e5959b37d06225bf878f2d7f0e82e66e"
    family = "unknown"
    file_name = "gg11"
    file_type = "elf"
    first_seen = "2026-08-10 22:11:35"
  condition:
    hash.sha256(0, filesize) == "c77e845feedc323ea12c20ae1859ec06e5959b37d06225bf878f2d7f0e82e66e"
}

rule MalwareBazaar_unknown_097_76880752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896"
    family = "unknown"
    file_name = "7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896.elf"
    file_type = "elf"
    first_seen = "2026-08-10 22:08:38"
  condition:
    hash.sha256(0, filesize) == "7688075202b5fbc5ddecc6bc85cc8606fe30e5bf8bddbe7d3cfafeb0f6f05896"
}

rule MalwareBazaar_unknown_098_76d4b3ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76d4b3caa27c65e33379cfd6abd9dd305338530948733ea228d66a74e72c2269"
    family = "unknown"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-08-10 21:57:39"
  condition:
    hash.sha256(0, filesize) == "76d4b3caa27c65e33379cfd6abd9dd305338530948733ea228d66a74e72c2269"
}

rule MalwareBazaar_Stealc_099_4153db28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4153db289c9a3de57845890aadeec7951fcf5516fd39f25c6d8c3e42fc21f801"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-10 21:52:40"
  condition:
    hash.sha256(0, filesize) == "4153db289c9a3de57845890aadeec7951fcf5516fd39f25c6d8c3e42fc21f801"
}

rule MalwareBazaar_CoinMiner_100_866d6593
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41"
    family = "CoinMiner"
    file_name = "866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41.exe"
    file_type = "exe"
    first_seen = "2026-08-10 21:48:40"
  condition:
    hash.sha256(0, filesize) == "866d659393017609c685b1c0187f13a4afdf43a4b8139275f1487a2187303d41"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

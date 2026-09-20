# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-20

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
| Unique family labels | 7 |
| Unique file types | 4 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 72 |
| Mirai | 18 |
| JOMANGY | 4 |
| ArkeiStealer | 2 |
| VShell | 2 |
| Snowlight | 1 |
| ConnectWise | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 48 |
| elf | 47 |
| sh | 4 |
| unknown | 1 |

## Per-Sample Analysis

### Sample 1: `ac684b367907880b`

| Field | Value |
|---|---|
| SHA-256 | `ac684b367907880b90675af8877df984e1409692da3c4613bee2f739142f80d4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:59:04` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e10aff49d3b7ab5d07fb4ba9877395a` |
| SHA-1 | `21a35609f8847791c2b8f438a1fc9202ab484c3b` |
| SHA-256 | `ac684b367907880b90675af8877df984e1409692da3c4613bee2f739142f80d4` |
| SHA3-384 | `cd79d4b3d2c324d9f3822d7a4e150fcb110895db0e37fef5235646c9b3393bdfdfa4d45d27431083791db85f738be319` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D162E686D9A22F6CDE4E80703E51F978B97032D09665D9E7E7828C305DA39E04434FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Up+Bgn:fKOe2/7c9sN3zfZR1m+RGU+6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_ac684b36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac684b367907880b90675af8877df984e1409692da3c4613bee2f739142f80d4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:59:04"
  condition:
    hash.sha256(0, filesize) == "ac684b367907880b90675af8877df984e1409692da3c4613bee2f739142f80d4"
}
```

### Sample 2: `37dd737a342729c7`

| Field | Value |
|---|---|
| SHA-256 | `37dd737a342729c7b8c4e6f28140f2ff977a433793482b6bd488efd56a20812e` |
| Family label | `unknown` |
| File name | `stub.x86_64` |
| File type | `elf` |
| First seen | `2026-09-20 04:58:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc5357d42e63c384616f827b62d3b279` |
| SHA-1 | `6f7cdb5c79ff5915f463ebd6a373637955a9d713` |
| SHA-256 | `37dd737a342729c7b8c4e6f28140f2ff977a433793482b6bd488efd56a20812e` |
| SHA3-384 | `e846f976580c1d50849da016a0313eb2c364b84ae7975d190936aede210390241d4e2ffee7a4f56bcb8a043ad2256ab5` |
| TLSH | `T126157C5BB2F374BDC157C134479BCA72A935F46502122E7FA1C8C6302E2AE641B1AF76` |
| SSDEEP | `12288:ZugNP46S4QVs7a+6xGv/7VZji59IH0j/APyYiztSIHmxAowYRsXPi/:7NP46S4QVs7l6A5Zji59k0jZz06FYRs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_37dd737a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37dd737a342729c7b8c4e6f28140f2ff977a433793482b6bd488efd56a20812e"
    family = "unknown"
    file_name = "stub.x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:58:49"
  condition:
    hash.sha256(0, filesize) == "37dd737a342729c7b8c4e6f28140f2ff977a433793482b6bd488efd56a20812e"
}
```

### Sample 3: `293c2f2f95c1c461`

| Field | Value |
|---|---|
| SHA-256 | `293c2f2f95c1c461869cfc2d2ec35cca863e57c491a42bb5f4641ca7a6f3c714` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:58:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7838019a8dd85c837d6d00ec468c147` |
| SHA-1 | `b3ee799e6cf653e3560ac0cc0f100717e0f375a8` |
| SHA-256 | `293c2f2f95c1c461869cfc2d2ec35cca863e57c491a42bb5f4641ca7a6f3c714` |
| SHA3-384 | `b6035a0fae1d765f7614fc907ec09912c2fbc9810c778b992d1577da0d65d825407d578a79fddf71aa03a154d49d9549` |
| TLSH | `T189766B236B18EB0FC22862341DB1CAC8676A5C9601D79517B385F319F9F21BC896EDF1` |
| TELFHASH | `t17fe32122dcb2bfab0fc003776cb6d5c45357c04b0996bba95fa48375d4eb188847a35a` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:2uuSwnU8SPXx3IXnsqSwCjEPmrK0kUNuCW08IPYS+3ivm:OnU8SPXx3I9P8LkfeY9yvm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_293c2f2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "293c2f2f95c1c461869cfc2d2ec35cca863e57c491a42bb5f4641ca7a6f3c714"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:58:47"
  condition:
    hash.sha256(0, filesize) == "293c2f2f95c1c461869cfc2d2ec35cca863e57c491a42bb5f4641ca7a6f3c714"
}
```

### Sample 4: `1940fe1cf809cf31`

| Field | Value |
|---|---|
| SHA-256 | `1940fe1cf809cf319d3593f126f9d087559906b2c033360d38848802fdb232a3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:57:06` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d42e255e83f770025a44b40a0d161243` |
| SHA-1 | `51f3487e0e9b54619ced212fc54668a0ce06832c` |
| SHA-256 | `1940fe1cf809cf319d3593f126f9d087559906b2c033360d38848802fdb232a3` |
| SHA3-384 | `f1bb7642a9b4b4d965327319044ae2746662395dd74816a42b1c649825e9974e5095c93dfbc04212a2484e260bd03044` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FF62C686DCE26F5CCE4EC0707E21F968B9B0769095A699E7D7968C305A63CD04024EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UCBgCc:fKOe2/7c9sN3zfZR1m+RG16C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_1940fe1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1940fe1cf809cf319d3593f126f9d087559906b2c033360d38848802fdb232a3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:57:06"
  condition:
    hash.sha256(0, filesize) == "1940fe1cf809cf319d3593f126f9d087559906b2c033360d38848802fdb232a3"
}
```

### Sample 5: `9797ae898309901b`

| Field | Value |
|---|---|
| SHA-256 | `9797ae898309901b9472c7573afc197861746a9a3eb458fdbf55eca90386d58e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:57:04` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93585bda93b1fd34ca5f13b97a3fa972` |
| SHA-1 | `ae4292ff7ca12919b9c89bb015cfbea06662ef55` |
| SHA-256 | `9797ae898309901b9472c7573afc197861746a9a3eb458fdbf55eca90386d58e` |
| SHA3-384 | `87a499ae52d1ccc27da7c6c8b0b4d660084de65d1306b9b7d6a155b85fab0d54663a776612810ba9ba5ae00259471e4c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11A62D786D8926E6DCE4F80703F51FC387DB436918A6669E3DB828D745DA39D00124EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UsBBde:fKOe2/7c9sN3zfZR1m+RG5BBd6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_9797ae89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9797ae898309901b9472c7573afc197861746a9a3eb458fdbf55eca90386d58e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:57:04"
  condition:
    hash.sha256(0, filesize) == "9797ae898309901b9472c7573afc197861746a9a3eb458fdbf55eca90386d58e"
}
```

### Sample 6: `7ea568be7b093e92`

| Field | Value |
|---|---|
| SHA-256 | `7ea568be7b093e92ab2c36dee8d15b853f80f95a5d672468a8b04fe3904a1316` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:56:04` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad5215d442d8f52cffad641452f9995d` |
| SHA-1 | `1cc5557fab3533070eca87b8d7576c4783a759d8` |
| SHA-256 | `7ea568be7b093e92ab2c36dee8d15b853f80f95a5d672468a8b04fe3904a1316` |
| SHA3-384 | `f36748a996cbfc0882bb7aaa2c6190100eca5153ea135c73c792b6021ce6d887ee9217953b029e034d546394288547ae` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13B62D796DCA22F5CCE8E80B03A11F838AE717290862559E3D782CD316AB39D10574FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U9BgCc:fKOe2/7c9sN3zfZR1m+RGS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_7ea568be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ea568be7b093e92ab2c36dee8d15b853f80f95a5d672468a8b04fe3904a1316"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:56:04"
  condition:
    hash.sha256(0, filesize) == "7ea568be7b093e92ab2c36dee8d15b853f80f95a5d672468a8b04fe3904a1316"
}
```

### Sample 7: `441553ee034e036d`

| Field | Value |
|---|---|
| SHA-256 | `441553ee034e036d625b68c0db9d4b1a95c8d3a8b72d2a8f2b811a674fc50437` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:54:40` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca088f0aaed43580fbbc349b9dc8d8e9` |
| SHA-1 | `9546f46ee900d28e83d8a2ade7a77fcdb96bbcb4` |
| SHA-256 | `441553ee034e036d625b68c0db9d4b1a95c8d3a8b72d2a8f2b811a674fc50437` |
| SHA3-384 | `f8608b9591b88a9e6a35c36427f3a81e740787b11f4cbca1fb407c586260a9e7226bd503ddc459e409a3481e682302b0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D162C686DD923FACDE4E90703A11F938BEB136A0956559E3DB828C315E678D00464EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U+ZwBM:fKOe2/7c9sN3zfZR1m+RGli6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_441553ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441553ee034e036d625b68c0db9d4b1a95c8d3a8b72d2a8f2b811a674fc50437"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:54:40"
  condition:
    hash.sha256(0, filesize) == "441553ee034e036d625b68c0db9d4b1a95c8d3a8b72d2a8f2b811a674fc50437"
}
```

### Sample 8: `7215aa8a4f087927`

| Field | Value |
|---|---|
| SHA-256 | `7215aa8a4f087927f4aed64ecedd3fb32cde6f4fd8d8ccaba189cba21a991127` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:54:32` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `532072dae2022a7951bc57d54f19bd22` |
| SHA-1 | `1039d4a9fef57d9d4ca3c25e9d56ef1bbd10844c` |
| SHA-256 | `7215aa8a4f087927f4aed64ecedd3fb32cde6f4fd8d8ccaba189cba21a991127` |
| SHA3-384 | `b2027bdb6482a848785052c579708969e6fccd493f3f1bd035d7dd0aac49150135b00b8d367985b48b6cc3f93ad3b7f2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A462D6C6D8A22E5DDE8E80703A11FC28BDB17691866599F7D7828C345EA39C01524FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UPs88r:fKOe2/7c9sN3zfZR1m+RGis88S6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_7215aa8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7215aa8a4f087927f4aed64ecedd3fb32cde6f4fd8d8ccaba189cba21a991127"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:54:32"
  condition:
    hash.sha256(0, filesize) == "7215aa8a4f087927f4aed64ecedd3fb32cde6f4fd8d8ccaba189cba21a991127"
}
```

### Sample 9: `a6453dc9e38769df`

| Field | Value |
|---|---|
| SHA-256 | `a6453dc9e38769dfc646107760afec331521cb7a72e864b79528b0a853f5bfa6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:53:40` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `341817d602a54777da546511593c352f` |
| SHA-1 | `925cd0eef8121910c36d88b6ac3296b1cf65b09a` |
| SHA-256 | `a6453dc9e38769dfc646107760afec331521cb7a72e864b79528b0a853f5bfa6` |
| SHA3-384 | `f0d3d125043f1a82357dca634f0cf184dbaf5b8043f74cf1c7e11fc399ac1d4c91e092d8f90d284202269cd8ea44d8a4` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E262E78AE9A26F5DCE4E80703B21F878AD74379186A5A8F3D7918C214DB79C00524FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UQTxZe:fKOe2/7c9sN3zfZR1m+RG16C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_a6453dc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6453dc9e38769dfc646107760afec331521cb7a72e864b79528b0a853f5bfa6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:53:40"
  condition:
    hash.sha256(0, filesize) == "a6453dc9e38769dfc646107760afec331521cb7a72e864b79528b0a853f5bfa6"
}
```

### Sample 10: `10b229207d857406`

| Field | Value |
|---|---|
| SHA-256 | `10b229207d857406f2ae137d6bbce07a2990c9757f66866cd23c1d497b05f615` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:53:23` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c44e7a700813208cadf3a7c8fc9a21be` |
| SHA-1 | `5055826f6effb3e3ff19b0bdbcdbbfc9afb79a39` |
| SHA-256 | `10b229207d857406f2ae137d6bbce07a2990c9757f66866cd23c1d497b05f615` |
| SHA3-384 | `cfd4b16513759dffb2906525e398ba881cb38ff0c9b02d45186e64cf0121f85033f4d421e69180078f8218cf8cd0e4e7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1DE62D69AD8925F5CDE4FC0703A21F838B9753290866599E3D7828D355ABF9D00838FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UzuBgn:fKOe2/7c9sN3zfZR1m+RGOu6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_10b22920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10b229207d857406f2ae137d6bbce07a2990c9757f66866cd23c1d497b05f615"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:53:23"
  condition:
    hash.sha256(0, filesize) == "10b229207d857406f2ae137d6bbce07a2990c9757f66866cd23c1d497b05f615"
}
```

### Sample 11: `079dc979877b459a`

| Field | Value |
|---|---|
| SHA-256 | `079dc979877b459a9bf711923a665b772b3a04abecef66b8eabdd2baadc99bce` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:52:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c342adef9695ec299a65dea20511569c` |
| SHA-1 | `1547119314d3ed9b11c64bab2a86861db03df69c` |
| SHA-256 | `079dc979877b459a9bf711923a665b772b3a04abecef66b8eabdd2baadc99bce` |
| SHA3-384 | `873b76747df5e6fcc9748d2009d72db830f81591ec4f994065276eccb120131db6c9adbdf48b590f3090e10140e1bbf2` |
| TLSH | `T114356C633731CF69E355D27005F3CB51AA9520A31AE24096B36CC3287E61A6E3D5FEE4` |
| TELFHASH | `t109a0222328c0c20c032bcf288cc8020220830c33fc2c3c220f0cce828020000020ccab` |
| SSDEEP | `24576:FUpTCOUi4TCWyKRX1JSsicR7gSqtUxuHnYDD:FUkS4TCWyKTPRUSyUxuHm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_079dc979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "079dc979877b459a9bf711923a665b772b3a04abecef66b8eabdd2baadc99bce"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:52:48"
  condition:
    hash.sha256(0, filesize) == "079dc979877b459a9bf711923a665b772b3a04abecef66b8eabdd2baadc99bce"
}
```

### Sample 12: `19addeb511708273`

| Field | Value |
|---|---|
| SHA-256 | `19addeb5117082737612867c086d82ff5a7156e31e8bd9b0996c4f5db4b5e188` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:51:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c23dc2e68cd7c4936680a9c9dae67b3` |
| SHA-1 | `c7059bab3fa71d3bf38daa7615a2c5f5da0bcf27` |
| SHA-256 | `19addeb5117082737612867c086d82ff5a7156e31e8bd9b0996c4f5db4b5e188` |
| SHA3-384 | `02f97f1f429f41412311549f389058be5f85cdf2cf367cbc9ff765efb7c1ad93cffd67a8a8a00a39da4089b6ed1a0908` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19E62C68AD9932EACDE8F80B03A11F8387D7176D0956559F7EB828C215A639D10434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UGcBgn:fKOe2/7c9sN3zfZR1m+RGO6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_19addeb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19addeb5117082737612867c086d82ff5a7156e31e8bd9b0996c4f5db4b5e188"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:51:47"
  condition:
    hash.sha256(0, filesize) == "19addeb5117082737612867c086d82ff5a7156e31e8bd9b0996c4f5db4b5e188"
}
```

### Sample 13: `0a1eeb2ec0989f23`

| Field | Value |
|---|---|
| SHA-256 | `0a1eeb2ec0989f2390912feb22cfa7599e6dfd612a9c024dc712ae792c644a46` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:50:58` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac3cd531722793ab2563a467c7a8d8e8` |
| SHA-1 | `65fb461117ab37837ba5f273ff6c9f359724a520` |
| SHA-256 | `0a1eeb2ec0989f2390912feb22cfa7599e6dfd612a9c024dc712ae792c644a46` |
| SHA3-384 | `a07e4336ab826e7517a206f02f9d5662c242f9f7ee6aff70b8d3f9c3aa391ab9cac04cba3e9fb951b5cf755ef47f0442` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17B62D8CAD9A22F5EDE4F80B03A11F839BE713694865569E3D7818C325DA39D00524FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UKcfBM:fKOe2/7c9sN3zfZR1m+RGHI6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_0a1eeb2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a1eeb2ec0989f2390912feb22cfa7599e6dfd612a9c024dc712ae792c644a46"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:50:58"
  condition:
    hash.sha256(0, filesize) == "0a1eeb2ec0989f2390912feb22cfa7599e6dfd612a9c024dc712ae792c644a46"
}
```

### Sample 14: `cef9e279df4d3331`

| Field | Value |
|---|---|
| SHA-256 | `cef9e279df4d3331bba46aaf99e59dd73eb1008047d837905bf5ef8d315bd71c` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-20 04:50:49` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30fbe4d5c4c913dddceb0c1789b11cfc` |
| SHA-1 | `3a73b1fc40aa90448fcd95fc7458cfd0f9146ccb` |
| SHA-256 | `cef9e279df4d3331bba46aaf99e59dd73eb1008047d837905bf5ef8d315bd71c` |
| SHA3-384 | `1ac97e7d02fda264c50536c277dfaef9b56a429efad15292f5f31bbb0a1625ee6cf81a4ba3617b495334929b0ff54ce3` |
| TLSH | `T140C27E966A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8A3C719C11F9CD618B2A` |
| SSDEEP | `768:S8vCB+25j6es8RR9FYpMSUpi+20qUpi+20YQX:S8l25JHd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_014_cef9e279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cef9e279df4d3331bba46aaf99e59dd73eb1008047d837905bf5ef8d315bd71c"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:50:49"
  condition:
    hash.sha256(0, filesize) == "cef9e279df4d3331bba46aaf99e59dd73eb1008047d837905bf5ef8d315bd71c"
}
```

### Sample 15: `8b8e64862b0fe3ae`

| Field | Value |
|---|---|
| SHA-256 | `8b8e64862b0fe3aec19fd8d3c7eb0471109471cf3666a96cb60dfcb3d8e8b90a` |
| Family label | `Mirai` |
| File name | `stub.mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:48:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23b6516aa4a454857df7e664ec163b7f` |
| SHA-1 | `de3fc734a04f64a24bd5098460860dd676cb9c8e` |
| SHA-256 | `8b8e64862b0fe3aec19fd8d3c7eb0471109471cf3666a96cb60dfcb3d8e8b90a` |
| SHA3-384 | `622e2119241b591d97987b5d1eb693b09dd8cf1561809c6b84d92ec5dda214e2fa2f46d72db69e49b2f9e877dec86256` |
| TLSH | `T16FF47C273731DF65D365C67405F3C7915AE520A20AE344DAA3A8C3287E21A2D2D6FFE4` |
| SSDEEP | `12288:v4cg+Zn1W4tzRKMNjbOsF47iIRgpiGGhQiFhyN6rTHUJTxVf:1g++4t1KMNhF47iIySQin0JTxF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_8b8e6486
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b8e64862b0fe3aec19fd8d3c7eb0471109471cf3666a96cb60dfcb3d8e8b90a"
    family = "Mirai"
    file_name = "stub.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:48:50"
  condition:
    hash.sha256(0, filesize) == "8b8e64862b0fe3aec19fd8d3c7eb0471109471cf3666a96cb60dfcb3d8e8b90a"
}
```

### Sample 16: `9b8f8579deddf85f`

| Field | Value |
|---|---|
| SHA-256 | `9b8f8579deddf85f3785fd740fb3f528fc480572129ceea6dad03a371440f775` |
| Family label | `Mirai` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-09-20 04:47:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `474efedc92f2a0a0f0200dd5c147e4a8` |
| SHA-1 | `fc211876668368d73abce37217fbeed6b2a98d6c` |
| SHA-256 | `9b8f8579deddf85f3785fd740fb3f528fc480572129ceea6dad03a371440f775` |
| SHA3-384 | `a4fbbf6b0e75c87bf176ea0a85741e39d585258b0791261173cc60d26aeed4b24537411675f364e00b6c853e7450d088` |
| TLSH | `T1EBF4C05AF51AEF03C8F3E536E47B82D07262EC4F57D293056509E9793C1B23A8B1A385` |
| TELFHASH | `t109a0222328c0c20c032bcf288cc8020220830c33fc2c3c220f0cce828020000020ccab` |
| SSDEEP | `12288:LgpK6Dphdz30ot70i060Y7i+x880dz9Gd6pAPxuqmQ1UDtyw70Vlb+E:fITdLB/06388wGL8hDtywIVlb+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_9b8f8579
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b8f8579deddf85f3785fd740fb3f528fc480572129ceea6dad03a371440f775"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-09-20 04:47:00"
  condition:
    hash.sha256(0, filesize) == "9b8f8579deddf85f3785fd740fb3f528fc480572129ceea6dad03a371440f775"
}
```

### Sample 17: `ac161791d3313dec`

| Field | Value |
|---|---|
| SHA-256 | `ac161791d3313dec24881de34a4a7f62691fc2431d8ac303d0d383afd856c898` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:45:07` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e37cb6a3f62afeb0447d5686e8597bb` |
| SHA-1 | `852ff96ae92fa5613158ed7a97032c7d3e6507d1` |
| SHA-256 | `ac161791d3313dec24881de34a4a7f62691fc2431d8ac303d0d383afd856c898` |
| SHA3-384 | `1c62b88547532c73b7650c7eb7a265246d6c81a10a92680390e2b28457d26b21c560158f29594a4db1f44cc471d10902` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1DF62C58AD8E26E5CDF4F80707A11FE78B97536D4866699E3D7838C244DA38D04438EB9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuCdGg:fKOe2/7c9sN3zfZR1m+RGnCE6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_ac161791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac161791d3313dec24881de34a4a7f62691fc2431d8ac303d0d383afd856c898"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:45:07"
  condition:
    hash.sha256(0, filesize) == "ac161791d3313dec24881de34a4a7f62691fc2431d8ac303d0d383afd856c898"
}
```

### Sample 18: `26df52334726c541`

| Field | Value |
|---|---|
| SHA-256 | `26df52334726c54126a662a46d7f4f3749bf66281f7f539451b1d47d3626bb83` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-20 04:44:45` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d42a4d1377f402dc8d04bdf6e1baa34` |
| SHA-1 | `16441f1c49544a2941badabcd382e4f4c9c859d1` |
| SHA-256 | `26df52334726c54126a662a46d7f4f3749bf66281f7f539451b1d47d3626bb83` |
| SHA3-384 | `a9eac3d158de885b6b0a7f388e325ef13d02340dfa959fc38304556ed788b1e8b8ead43c5f71835a0385e3eac75f6ac1` |
| TLSH | `T11A136D6926813C289D9998371D7E2F0CB9A983E6310852DCBFCF3CF58C1969DE21971D` |
| SSDEEP | `768:PXOGVvv9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:vLgco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_018_26df5233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26df52334726c54126a662a46d7f4f3749bf66281f7f539451b1d47d3626bb83"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:44:45"
  condition:
    hash.sha256(0, filesize) == "26df52334726c54126a662a46d7f4f3749bf66281f7f539451b1d47d3626bb83"
}
```

### Sample 19: `75e5fdf658347ecd`

| Field | Value |
|---|---|
| SHA-256 | `75e5fdf658347ecd148950b30fa8c81d4bfa27344235fe2ea3b1f49dca59e628` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:42:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f102fc2b4d4358cf64b27e33d4a93962` |
| SHA-1 | `ce504e9165ee90f6de7b2b7a1cfa139b1cca29f9` |
| SHA-256 | `75e5fdf658347ecd148950b30fa8c81d4bfa27344235fe2ea3b1f49dca59e628` |
| SHA3-384 | `748dc377b301094b4b84c742ff0687a74f951342303ef6b05222d2a1cce3ceadfe98de257632f1d12c1f92396f2ec40c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10962E886E8922E9CCE4FC0703B20F9386D7072958A25D9E3D7829D354DA38C14124FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1Hneg:fKOe2/7c9sN3zfZR1m+RGR6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_75e5fdf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75e5fdf658347ecd148950b30fa8c81d4bfa27344235fe2ea3b1f49dca59e628"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:42:39"
  condition:
    hash.sha256(0, filesize) == "75e5fdf658347ecd148950b30fa8c81d4bfa27344235fe2ea3b1f49dca59e628"
}
```

### Sample 20: `5492f9606bf12add`

| Field | Value |
|---|---|
| SHA-256 | `5492f9606bf12add8b8414b224e8272b7d422baedbd951e8874a4bda0cb716bc` |
| Family label | `Mirai` |
| File name | `stub.arm` |
| File type | `elf` |
| First seen | `2026-09-20 04:41:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4aae09bec175107efd9f93fec69c4de0` |
| SHA-1 | `9f0724ff92d312667c75ceb5c5c70a3af903f97a` |
| SHA-256 | `5492f9606bf12add8b8414b224e8272b7d422baedbd951e8874a4bda0cb716bc` |
| SHA3-384 | `c04e9b82c92f5734b356872ea3987520164645de532e77ed5d9c9cd8008233d62d8fb7d7462bec945f409b2f5f842ef4` |
| TLSH | `T1C8A4BF56F61AEE47C4F3A236D4BB86A07362EC4F1792D302260D657D3C1B37A4F29285` |
| SSDEEP | `12288:UvelbsgQeWpqkXPqBpe6pmNjFDe81gHzGdanDf6k:U2lbwjJXlxD8GdSDf6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_5492f960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5492f9606bf12add8b8414b224e8272b7d422baedbd951e8874a4bda0cb716bc"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-20 04:41:00"
  condition:
    hash.sha256(0, filesize) == "5492f9606bf12add8b8414b224e8272b7d422baedbd951e8874a4bda0cb716bc"
}
```

### Sample 21: `b7df67b510986981`

| Field | Value |
|---|---|
| SHA-256 | `b7df67b510986981958f203da1779124bcc63a10a5769c86a22f5a21a01e079e` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-09-20 04:34:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4919b011a09cca00b9da7a0630c87b7` |
| SHA-1 | `67b15b3c75e2afb2063d1cda9bd4b8cb5da396ae` |
| SHA-256 | `b7df67b510986981958f203da1779124bcc63a10a5769c86a22f5a21a01e079e` |
| SHA3-384 | `93aed209e4d0f05bf2f79dcf0bdf2cbafda086f0038651965c5534b86476d2e7ab81ba7c4378f445eb3a5294c71a2ae5` |
| TLSH | `T1B5355C5BB2B374BCC557C430439BDA62BD35B46502226E7FA5C4DA302E26E702729F72` |
| TELFHASH | `t18de18cb44bf538b55bd6d910a722f1f549771c2962ec39f01622ad88ef94fc00c6682b` |
| SSDEEP | `24576:4ODfyhC46zIHbddC+4oOb9vSZKt+QJCpWlZbIMa:4Mx46z814/Bvx+kCpWPbH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_b7df67b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7df67b510986981958f203da1779124bcc63a10a5769c86a22f5a21a01e079e"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:34:52"
  condition:
    hash.sha256(0, filesize) == "b7df67b510986981958f203da1779124bcc63a10a5769c86a22f5a21a01e079e"
}
```

### Sample 22: `80828752354b3a77`

| Field | Value |
|---|---|
| SHA-256 | `80828752354b3a770b7c63f46006334fc705c718d40cf3e1df1dc5a4f0fdf043` |
| Family label | `Mirai` |
| File name | `sever1078.x86` |
| File type | `elf` |
| First seen | `2026-09-20 04:34:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1623ef1f9b9c4dbdd46170805d63270c` |
| SHA-1 | `a1e8bb06a9ffa6d0c22a568a556fc448a447e55c` |
| SHA-256 | `80828752354b3a770b7c63f46006334fc705c718d40cf3e1df1dc5a4f0fdf043` |
| SHA3-384 | `1cb72369aea9bd8aa789e9138cce0cb02acd67befa487d10414a5bf901cbffc9df55c99ca1af5d0f1473924edcd463be` |
| TLSH | `T1B1A45B55EBE3C8F5F41745702027B3374A36AE395036DA87D7C8E6637851A82D32E3A8` |
| TELFHASH | `t152b18b732ab569e867f0490187ab2360ce16e52729c038766ef35410b7f3c536778eb9` |
| SSDEEP | `12288:uG3jxoLetDOGI0D5DQFZYe2rCuXZK0MVMnEMlV:uG3jxoStDXI0D5GY5muXZbMVKl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_80828752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80828752354b3a770b7c63f46006334fc705c718d40cf3e1df1dc5a4f0fdf043"
    family = "Mirai"
    file_name = "sever1078.x86"
    file_type = "elf"
    first_seen = "2026-09-20 04:34:50"
  condition:
    hash.sha256(0, filesize) == "80828752354b3a770b7c63f46006334fc705c718d40cf3e1df1dc5a4f0fdf043"
}
```

### Sample 23: `372a630595aa696c`

| Field | Value |
|---|---|
| SHA-256 | `372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0` |
| Family label | `unknown` |
| File name | `372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0` |
| File type | `elf` |
| First seen | `2026-09-20 04:28:05` |
| Reporter | `theodore_brucker` |
| Tags | `cowrie, elf, honeypot, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `357799114ddc57699683dbeb01029f3b` |
| SHA-256 | `372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_372a6305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0"
    family = "unknown"
    file_name = "372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0"
    file_type = "elf"
    first_seen = "2026-09-20 04:28:05"
  condition:
    hash.sha256(0, filesize) == "372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0"
}
```

### Sample 24: `ef144d482427726d`

| Field | Value |
|---|---|
| SHA-256 | `ef144d482427726d7bbcfd876ce4c211d9cd828aaf9d7e0ef942620f48562ebc` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-20 04:26:52` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3b5d2944650091035bf0c46b569432d` |
| SHA-1 | `443019ff64dab23f073824b94d616fd29f68ae22` |
| SHA-256 | `ef144d482427726d7bbcfd876ce4c211d9cd828aaf9d7e0ef942620f48562ebc` |
| SHA3-384 | `c3abe23bf51a6e975f368b24db54a7f92425b676db94f044e5ae2aeae41670fa977b98f22f919a740719cd5d73f0cd2b` |
| TLSH | `T1C3C27C966A867C44BEC94A3E4CBD2B1D6DF4C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:Tx8vCB+25j6es8Rx9FYpMSUpi+20qUpi+20YQX:Tx8l25Jnd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_024_ef144d48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef144d482427726d7bbcfd876ce4c211d9cd828aaf9d7e0ef942620f48562ebc"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:26:52"
  condition:
    hash.sha256(0, filesize) == "ef144d482427726d7bbcfd876ce4c211d9cd828aaf9d7e0ef942620f48562ebc"
}
```

### Sample 25: `28423d6534cdb6b8`

| Field | Value |
|---|---|
| SHA-256 | `28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885` |
| Family label | `Mirai` |
| File name | `Space.mpsl` |
| File type | `elf` |
| First seen | `2026-09-20 04:26:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `756d83d3fd7798258c101ba5fe6a1e9c` |
| SHA-1 | `ffb7d6a7af93656ee1a9e806a8d3e665ca5bdd5e` |
| SHA-256 | `28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885` |
| SHA3-384 | `3dae64ed8a0d18b77c36a6ff5bccb710e4bf82723afc35177615acf0b52b66edd5043346fdd30ed78ce2bdb6a9c0df70` |
| TLSH | `T17F03F11AA861B09FC91F1C3F128A10AD1E90E1D6754A7B6BA365CCC5AF3684F94CC8F0` |
| SSDEEP | `768:CF4o5gt3IEG6Ks1mqDUKf+8hr89kxcEDV/SLXQlov0zBZLvad4mwu0zOg4zWC:El5JnsrXvrKy9QjyBZLvDmR0zOg4f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_28423d65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885"
    family = "Mirai"
    file_name = "Space.mpsl"
    file_type = "elf"
    first_seen = "2026-09-20 04:26:51"
  condition:
    hash.sha256(0, filesize) == "28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885"
}
```

### Sample 26: `4e3fe31a8f5872ab`

| Field | Value |
|---|---|
| SHA-256 | `4e3fe31a8f5872ab5a1a7b23eb352b2061c5009989b95f0a86513eb5f956985f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:25:52` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58787ce1ffde1633ccdcad6d2ca475ec` |
| SHA-1 | `208edcd6772ba4c8ebc0bf0b3c32588c67ca552f` |
| SHA-256 | `4e3fe31a8f5872ab5a1a7b23eb352b2061c5009989b95f0a86513eb5f956985f` |
| SHA3-384 | `4685280ec3335184da1ca398c0bd10ce18f967f8eea104eec2bd5ae3bfd9f556a07e6ee4aea6d573f2d8a820c993772d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13662E686E8A26F5CDE4F81703A11F838FDB176A58A6559E3D7828C706DA39D00424FF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGoKruuuuuuuuuuuuuuuuuuuuuuuu96C:fKOeOQOzUxoKx6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_4e3fe31a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e3fe31a8f5872ab5a1a7b23eb352b2061c5009989b95f0a86513eb5f956985f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:25:52"
  condition:
    hash.sha256(0, filesize) == "4e3fe31a8f5872ab5a1a7b23eb352b2061c5009989b95f0a86513eb5f956985f"
}
```

### Sample 27: `b9ef2d25881aa827`

| Field | Value |
|---|---|
| SHA-256 | `b9ef2d25881aa827451c4b19ca4872c122a295ceed28875a26bbd928f5de2b3c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:23:10` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58e59ab69dc5a047b8f18c13c55c9ad1` |
| SHA-1 | `ef0433c10f1d56246050008282a67e5e8efce15d` |
| SHA-256 | `b9ef2d25881aa827451c4b19ca4872c122a295ceed28875a26bbd928f5de2b3c` |
| SHA3-384 | `6e16fd0421762ffdcef3659503409ef3f2c9f88fda322b94f3599fdcc20cb1682236947125e31004b174d5cda6b6e6ac` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F062E786DD926F5CDE8E80703A52F838BD753290CA6599E7D7918C314DA39D01434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ug7Bgn:fKOe2/7c9sN3zfZR1m+RGJ76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_b9ef2d25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ef2d25881aa827451c4b19ca4872c122a295ceed28875a26bbd928f5de2b3c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:23:10"
  condition:
    hash.sha256(0, filesize) == "b9ef2d25881aa827451c4b19ca4872c122a295ceed28875a26bbd928f5de2b3c"
}
```

### Sample 28: `10fc711e05e104ea`

| Field | Value |
|---|---|
| SHA-256 | `10fc711e05e104ea34f6c55cc592b8e947d9f68e8c64f2a4b8b225c12073f9fb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:20:34` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ba2542a7aa4128e4cbf2260b6eaac12` |
| SHA-1 | `1e05fab43ddefd3741475b42a6278ea8c76d47c0` |
| SHA-256 | `10fc711e05e104ea34f6c55cc592b8e947d9f68e8c64f2a4b8b225c12073f9fb` |
| SHA3-384 | `638ff4dfdfbe946e628013359027fd012bce95be576c3cf37ad9ce3aec41a9315e049355c1771897da9168853a6d7efc` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D762D896D9921B6CDE4F80B07A11F878BDB136A085665DE3DBD28C709AA3CD00464EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uh3Bgn:fKOe2/7c9sN3zfZR1m+RGA36C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_10fc711e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10fc711e05e104ea34f6c55cc592b8e947d9f68e8c64f2a4b8b225c12073f9fb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:20:34"
  condition:
    hash.sha256(0, filesize) == "10fc711e05e104ea34f6c55cc592b8e947d9f68e8c64f2a4b8b225c12073f9fb"
}
```

### Sample 29: `4e2f0e58ec5a9f6f`

| Field | Value |
|---|---|
| SHA-256 | `4e2f0e58ec5a9f6f3d0a0fd6b496afdd2df1f38d053c38df682c898226154425` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `073f5c084d73d59ac2dd5538dd83390f` |
| SHA-1 | `5f3a23c44fb12b0211ebb61b1b048bb84ba39e4e` |
| SHA-256 | `4e2f0e58ec5a9f6f3d0a0fd6b496afdd2df1f38d053c38df682c898226154425` |
| SHA3-384 | `9769df8fdffaa410938081bd56f6bb00cf59f70b2513313f5de04c3e9c144dec7a21645cdeeb479e53dba69e4785cbe6` |
| TLSH | `T1DCB21A0677180E97D19FAAB42E2F0BD8A3EBFF5011D8D681265E67CAC075E771281C89` |
| SSDEEP | `384:7kthm3ZK+SHhFw+FeZgh+Br1E2EbV/jC4tbYtcgAyU3TpASmzfCkPV3kby:AthskASh+LpEbBuE8TqlA37CE3d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_4e2f0e58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e2f0e58ec5a9f6f3d0a0fd6b496afdd2df1f38d053c38df682c898226154425"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:46"
  condition:
    hash.sha256(0, filesize) == "4e2f0e58ec5a9f6f3d0a0fd6b496afdd2df1f38d053c38df682c898226154425"
}
```

### Sample 30: `b042caa730d5d29c`

| Field | Value |
|---|---|
| SHA-256 | `b042caa730d5d29cf55e7c1c570ae1a830f0b1bca3edbb8778f994a674e70deb` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a9cf400ec907d4fdb51c8f9aa6397ba` |
| SHA-1 | `d53911bce21abd69db3cded3b1523f2d594f62e3` |
| SHA-256 | `b042caa730d5d29cf55e7c1c570ae1a830f0b1bca3edbb8778f994a674e70deb` |
| SHA3-384 | `0fb66a9302ec29a98461a8b04ca9c59f78be3c0b6943e6b0fb324ad6fcc0c1a843b0bb7ba3174c5e1edb3d22785461bd` |
| TLSH | `T180E2E945EF604EBBE8E7CD3345B95B1230CD6C2723B52B272970E529B41A14B5BE38E4` |
| SSDEEP | `768:x57wKaBCzS0n6phfW807EveWgeG2yXdXiq6OeXK:x5sKaIDnq5D0cXghH6OW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_b042caa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b042caa730d5d29cf55e7c1c570ae1a830f0b1bca3edbb8778f994a674e70deb"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:44"
  condition:
    hash.sha256(0, filesize) == "b042caa730d5d29cf55e7c1c570ae1a830f0b1bca3edbb8778f994a674e70deb"
}
```

### Sample 31: `5964f962d96b459e`

| Field | Value |
|---|---|
| SHA-256 | `5964f962d96b459ed59ac7fc1970703e2242b1919130c2162925cc8d6cf1be26` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d94e7162a931f64d7a5fcfe343299b34` |
| SHA-1 | `51a71714da238ff65c872c9f63a54ebf51c4f95d` |
| SHA-256 | `5964f962d96b459ed59ac7fc1970703e2242b1919130c2162925cc8d6cf1be26` |
| SHA3-384 | `887e187fb5798450239a3481477edac222d1e813ee38e2513f9ceaf7f22e88ce9e5ec8e76ce7a52f2c39a5c6c52f422d` |
| TLSH | `T1C9B22B90E583E0F7F84402BD6052D7616736F83825A8FD4BEB34577BA812621A78F3D9` |
| TELFHASH | `t17201c2c77db508d4f6c2fd4da72e2963eb326eb2473278a685f1321137e115190b2020` |
| SSDEEP | `768:6AQXz8XRVvpn52WJnbuaUtCbmT3/kpHd:6AQgXRVvpn52W55UUbmz8Hd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_5964f962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5964f962d96b459ed59ac7fc1970703e2242b1919130c2162925cc8d6cf1be26"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:41"
  condition:
    hash.sha256(0, filesize) == "5964f962d96b459ed59ac7fc1970703e2242b1919130c2162925cc8d6cf1be26"
}
```

### Sample 32: `e39129081ae5922a`

| Field | Value |
|---|---|
| SHA-256 | `e39129081ae5922a28ee9ab9ea17fe150675c2c3d1d308faf9f4185954624497` |
| Family label | `Mirai` |
| File name | `Space.i686` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac30f309e010aacf6bc1bc4d8a99c677` |
| SHA-1 | `a5debc1f3d6a1501498cf007825a7992eac5cbd5` |
| SHA-256 | `e39129081ae5922a28ee9ab9ea17fe150675c2c3d1d308faf9f4185954624497` |
| SHA3-384 | `00a09399b705965b798d4769093b232e3e0c171964343bfb854ef14b066ba64ad793f1ae7da5c5db211b7329dcb92563` |
| TLSH | `T104733985F987C6F2C407483042ABFB3FCB32D8A511B19B4DDF569F35DA33502AA22649` |
| TELFHASH | `t1c121bffb1dbe08fda7d89940c25e6fe22826c77b556036b00563c6353367ea144a8c3d` |
| SSDEEP | `1536:8A9Uqtm/qzBpeKm2XpQmj7qWSICRzBbkivom3aJ2ZdLNn:8A9U7KBcKm2Xp3jnrCRzBbVvfZdLN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_e3912908
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e39129081ae5922a28ee9ab9ea17fe150675c2c3d1d308faf9f4185954624497"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:39"
  condition:
    hash.sha256(0, filesize) == "e39129081ae5922a28ee9ab9ea17fe150675c2c3d1d308faf9f4185954624497"
}
```

### Sample 33: `e93daebf9b1e5904`

| Field | Value |
|---|---|
| SHA-256 | `e93daebf9b1e5904551afa93f3ae39ee3685f6cac471ac103a0eb83474e2483f` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d638eb4d501dd93312a313324b26e79` |
| SHA-1 | `a8e2bdba6030d1abfec6666d8ba5260cb097a92a` |
| SHA-256 | `e93daebf9b1e5904551afa93f3ae39ee3685f6cac471ac103a0eb83474e2483f` |
| SHA3-384 | `df8ec5a4aa74437d44bc8db489f4c067d503b4a85bfdcf60a9c69a72a041a48dcbbc2c6363e1b0cb27733575674fde06` |
| TLSH | `T11BC20A57A549B0EDC88B81784396F035A237B03F1166F8413BE4E33BAE59E114F6961B` |
| TELFHASH | `t1c1f090a5728138e476ebb913228ce125c87c4979001436e5d671adf09f09fd00c42d76` |
| SSDEEP | `384:zz1WIKB4TckftWp8VnLAfKt1l4jDmGSXkLPpbDG+ygjf:zRWD1kfNXWJjrpbD7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_e93daebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e93daebf9b1e5904551afa93f3ae39ee3685f6cac471ac103a0eb83474e2483f"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:37"
  condition:
    hash.sha256(0, filesize) == "e93daebf9b1e5904551afa93f3ae39ee3685f6cac471ac103a0eb83474e2483f"
}
```

### Sample 34: `e9d97a3d8724986b`

| Field | Value |
|---|---|
| SHA-256 | `e9d97a3d8724986bbf4494d1e01ace52ea60e0ea50c0e97385ab3a2f743cdc03` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfd6398e46d12863c02d09bc64d06a2c` |
| SHA-1 | `f918a4f7100e30ce17d1d48e5424354236e7fe61` |
| SHA-256 | `e9d97a3d8724986bbf4494d1e01ace52ea60e0ea50c0e97385ab3a2f743cdc03` |
| SHA3-384 | `1d342815ce6f52ced26528404384ea2fb42eff077fcfc42300b174f3ff44b41940be13bf533c41912a6e4ff7f84578b0` |
| TLSH | `T1BEE2A44F6E328FDDF759CB344AF34A61A799238222E1C686D36CD1501E2024E949FBF5` |
| TELFHASH | `t188e0c92c1af422a426358859589effa7d5a031ef772a3c178b1214f977fd8826e19d08` |
| SSDEEP | `768:8T1k18136kQAu/CTDuJS7ALjmjz+uegcylJuNQ:G1kGCApaS8LaFjJ3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_e9d97a3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9d97a3d8724986bbf4494d1e01ace52ea60e0ea50c0e97385ab3a2f743cdc03"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:35"
  condition:
    hash.sha256(0, filesize) == "e9d97a3d8724986bbf4494d1e01ace52ea60e0ea50c0e97385ab3a2f743cdc03"
}
```

### Sample 35: `09e4e96872385a02`

| Field | Value |
|---|---|
| SHA-256 | `09e4e96872385a0296efe00cfaa02e0d0d46b0c71855345f39cc2dfeabb8c75a` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d59925d46a03f5f2a8d137e8bb8afc4` |
| SHA-1 | `ca762ce26bd6325e84092c7e1fe91831e3ddd68f` |
| SHA-256 | `09e4e96872385a0296efe00cfaa02e0d0d46b0c71855345f39cc2dfeabb8c75a` |
| SHA3-384 | `86ad530dd10e3a2ea8032eede4f028b77b05c0c2dfa507baa9c3a23d7b74ebff3ae699fef383c8c6a014c26b1df2c719` |
| TLSH | `T170B22A80E587E0F4D82B46B980E2B63E9331D5197514D91AFF719BBDEE23D429B0B309` |
| TELFHASH | `t11f01c8a97e2524f1f7c2bc4c8b1d5703e3369ef6462274b584f5121137d2245d172545` |
| SSDEEP | `768:YNAiuYEgHskm7vllyqnuUWhpDk95qgYgt:YGwEg+plduUC85ggt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_09e4e968
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09e4e96872385a0296efe00cfaa02e0d0d46b0c71855345f39cc2dfeabb8c75a"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:32"
  condition:
    hash.sha256(0, filesize) == "09e4e96872385a0296efe00cfaa02e0d0d46b0c71855345f39cc2dfeabb8c75a"
}
```

### Sample 36: `c5533697f6cb0a84`

| Field | Value |
|---|---|
| SHA-256 | `c5533697f6cb0a84f7a48af7bbd26a2ae9f9e24988e74cfea072dd65e7597d63` |
| Family label | `unknown` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-20 04:19:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c343bf5157c37e19a9b08ef07990b3a` |
| SHA-1 | `69901d6cdd71f6dbd3778daa53f4f0da90b5f88b` |
| SHA-256 | `c5533697f6cb0a84f7a48af7bbd26a2ae9f9e24988e74cfea072dd65e7597d63` |
| SHA3-384 | `b574ed5108e71d78a02f528ab991942baecda2f90498f6f232cccc8efdbc119f809477be714892546a5c690e65290c26` |
| TLSH | `T1AF23084AFD805F00D9E925BAFE1E524933934B7CE3FE7111AE119B2523C6A2B0F76911` |
| TELFHASH | `t1c5f0c01049cca8c6bbd15802b05f71115d16a5ec392d084231fa2c4c92735a2d42a14c` |
| SSDEEP | `768:ERnrkqdtwR4HV3eWGdFdpKJ2lnXkiE5sFG8All20IQRieG:ERnrkMORsVOWGdFiJ2lXkiksFghRit` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_c5533697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5533697f6cb0a84f7a48af7bbd26a2ae9f9e24988e74cfea072dd65e7597d63"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:30"
  condition:
    hash.sha256(0, filesize) == "c5533697f6cb0a84f7a48af7bbd26a2ae9f9e24988e74cfea072dd65e7597d63"
}
```

### Sample 37: `257d2595b2e97b28`

| Field | Value |
|---|---|
| SHA-256 | `257d2595b2e97b286d3f52ebee2bc9054333571014f8565aeac6d7f2df9d2b89` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:19:23` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edad7987bcb3d334a17b73c7e8088330` |
| SHA-1 | `601ca76c25dc95a59cf3c08c4c679dcfc7649dab` |
| SHA-256 | `257d2595b2e97b286d3f52ebee2bc9054333571014f8565aeac6d7f2df9d2b89` |
| SHA3-384 | `b363d8724d8be88c97b57bf4c9575b4eb96e45316e0dc13b7721230c47b6d59dc1932d4d9c0d3582a083466105a9b683` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18B62C596E8A22F6CDE4FC0B03A11F938BD7477A0866599F3D7928C315DA39D00424EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuBBgn:fKOe2/7c9sN3zfZR1m+RG9B6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_257d2595
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "257d2595b2e97b286d3f52ebee2bc9054333571014f8565aeac6d7f2df9d2b89"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:19:23"
  condition:
    hash.sha256(0, filesize) == "257d2595b2e97b286d3f52ebee2bc9054333571014f8565aeac6d7f2df9d2b89"
}
```

### Sample 38: `ad5ed7ce8dc5462e`

| Field | Value |
|---|---|
| SHA-256 | `ad5ed7ce8dc5462e06fafa676d4217960952df10cda43be89fddd3c4b7486c39` |
| Family label | `unknown` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a2677fffd95e98b34bcc606759d0caf` |
| SHA-1 | `2d839bd3539a3bf3e77674784ff3fa1209146fd2` |
| SHA-256 | `ad5ed7ce8dc5462e06fafa676d4217960952df10cda43be89fddd3c4b7486c39` |
| SHA3-384 | `dd5db76c086971dc34269d47a2ba0225f6f9cd4c4cbf4183b3eb6f8427f0ab4aa83233014da79d58ff7f1c26d261a2e3` |
| TLSH | `T1E862BF54E05A4DD2FEAF9DF11989D7D23FB08F4DB1B1CEE216969F412501A17EA00CC8` |
| SSDEEP | `384:rEPWrcwa1Yxa30+xP2BpGM4uVcqgw0Og724kmWY:iBYYE+1cD4uVcqgw0X7JkmWY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_ad5ed7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad5ed7ce8dc5462e06fafa676d4217960952df10cda43be89fddd3c4b7486c39"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:57"
  condition:
    hash.sha256(0, filesize) == "ad5ed7ce8dc5462e06fafa676d4217960952df10cda43be89fddd3c4b7486c39"
}
```

### Sample 39: `db76f64a2ab9133a`

| Field | Value |
|---|---|
| SHA-256 | `db76f64a2ab9133ae0dcea6e447b843cd24f64ba35c7f8c51738591be7000e50` |
| Family label | `unknown` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38062f292bfa6dbb9416d5aaf6289a0b` |
| SHA-1 | `678e0a1cbc9ac86b67d99fe5b8581d4cafd08a55` |
| SHA-256 | `db76f64a2ab9133ae0dcea6e447b843cd24f64ba35c7f8c51738591be7000e50` |
| SHA3-384 | `8393a05b57df6a447a8449033e46e3a381ed971fae4d46ced93377e571355470347510556b86fd67ffbc6cdaa35365e1` |
| TLSH | `T108C23A86FD804917C9D21176FA2F918D3B664BB4E2EF3203E7179F61274392A0F3A509` |
| TELFHASH | `t1e211b1a58c4c0c9de684e23ae1cd62225a22d3f97c3d2409b9c3987c613bcf19c18d16` |
| SSDEEP | `384:9taRORfMYBU9Fzs6uqUImCKAktq6NzspX94K+MG615kUX16MBueOuKfIFx4e:9tqZkOuqSCsc0zc4/fEvX/ueOuKh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_db76f64a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db76f64a2ab9133ae0dcea6e447b843cd24f64ba35c7f8c51738591be7000e50"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:55"
  condition:
    hash.sha256(0, filesize) == "db76f64a2ab9133ae0dcea6e447b843cd24f64ba35c7f8c51738591be7000e50"
}
```

### Sample 40: `c627d9b192be3d9c`

| Field | Value |
|---|---|
| SHA-256 | `c627d9b192be3d9c75f4f65d361f3f1c01ea2f7f465d4d40e5d3db01d6004f27` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d43a1355c9fb4782aa11caad1ca9c02f` |
| SHA-1 | `b47721a5a3359924ee0b9e2bb040f602f30a19ca` |
| SHA-256 | `c627d9b192be3d9c75f4f65d361f3f1c01ea2f7f465d4d40e5d3db01d6004f27` |
| SHA3-384 | `bbb067e57a08f8ee14462e60f52f578ce9366e0026890be91ed120310df972f95e26d609e010949b4a2be7d8217b93fb` |
| TLSH | `T11E72AFAED9C1B4CAC99E0E3E838C173545D99058647D4BCD3344CC58E7BE8CBB1AD8A8` |
| SSDEEP | `384:9QXhCQ9ASU9WGQlbtaflmzms3eRaV9HQXRWGVCz7zZFwJ:9QRCuASU0Hs8zeQ1SWTNqJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_c627d9b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c627d9b192be3d9c75f4f65d361f3f1c01ea2f7f465d4d40e5d3db01d6004f27"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:54"
  condition:
    hash.sha256(0, filesize) == "c627d9b192be3d9c75f4f65d361f3f1c01ea2f7f465d4d40e5d3db01d6004f27"
}
```

### Sample 41: `7de77a1518419efa`

| Field | Value |
|---|---|
| SHA-256 | `7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2` |
| Family label | `Mirai` |
| File name | `Space.sh4` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b07b2c966343c5ea3117dedf4b55258` |
| SHA-1 | `5895b5e461f3c59cf1af3734cd797e7da4ac5861` |
| SHA-256 | `7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2` |
| SHA3-384 | `bf8f8787629ddfd292bff5312915d662b50951166cb43a00f32934a8073c6a052e0304fd87d8ebaa4bed9c47423b58c4` |
| TLSH | `T11C639E16D82509A9C286C5B471EC8E3A1B13E5C063837EF71A7AC375A067D9CF849FB4` |
| SSDEEP | `1536:D/rMkOtfaR0glv2ZKsT5Z7BPxznCI0sCp8udo:DYkwfCFlugsz9xznsxrdo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_7de77a15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2"
    family = "Mirai"
    file_name = "Space.sh4"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:53"
  condition:
    hash.sha256(0, filesize) == "7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2"
}
```

### Sample 42: `119334fc9aa05c27`

| Field | Value |
|---|---|
| SHA-256 | `119334fc9aa05c272da7e1b9ca1a215a22a578d339137cc90886bf1a1bfe51ff` |
| Family label | `unknown` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81800d7bdeab860fde964c808392d3e1` |
| SHA-1 | `8e50953b46b7bd046ca5d76e37f19cd98a1e9bba` |
| SHA-256 | `119334fc9aa05c272da7e1b9ca1a215a22a578d339137cc90886bf1a1bfe51ff` |
| SHA3-384 | `eb6ea7b231e5446b685562055f04353abf24a919119b40c96758a62ea91f5cc6757ea382f32a21a176a44ea101e2f2da` |
| TLSH | `T163C2F9BDB542EABCF44FFB3EC401410D7A70A7255041177527A6E937FC332A8196AEA2` |
| SSDEEP | `384:yhp6L4oTVmRiubiP5OV7PF2GfpWOS+v7/71jX8HAp3Z3ymdhSP6oN20/lvH:yCL4oGCc2d+jd8E3ZtEP6k20/lvH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_119334fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "119334fc9aa05c272da7e1b9ca1a215a22a578d339137cc90886bf1a1bfe51ff"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:51"
  condition:
    hash.sha256(0, filesize) == "119334fc9aa05c272da7e1b9ca1a215a22a578d339137cc90886bf1a1bfe51ff"
}
```

### Sample 43: `a662f5e5879edcb3`

| Field | Value |
|---|---|
| SHA-256 | `a662f5e5879edcb32efb513eb84b9b83567459287ed475af1083874c04eb2834` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9a2898f3a122dbd71b7f7459d246718` |
| SHA-1 | `9db7a4a2f453d963f8ad0d4899832b49435d17de` |
| SHA-256 | `a662f5e5879edcb32efb513eb84b9b83567459287ed475af1083874c04eb2834` |
| SHA3-384 | `8c1033d5da40bcc8d09e5fd5da4864446bad9913be19dcfe0dfefa15736758e2dafe37db9e37361cbce0211b43c79f49` |
| TLSH | `T1D772C042B2CE9A07E36D51BE282F7C872C18D32CD68475E3DADC6039508174E3D2D5C6` |
| SSDEEP | `384:M5wwvrqtVgF3RIGcDkutjn86REzWvyZDq31ANaNJawcudoD7Uqy8E:44ngFKGcDtj86RmWKtqBnbcuyD7UeE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_a662f5e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a662f5e5879edcb32efb513eb84b9b83567459287ed475af1083874c04eb2834"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:50"
  condition:
    hash.sha256(0, filesize) == "a662f5e5879edcb32efb513eb84b9b83567459287ed475af1083874c04eb2834"
}
```

### Sample 44: `704c64073e98b5a9`

| Field | Value |
|---|---|
| SHA-256 | `704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c` |
| Family label | `Mirai` |
| File name | `Space.i686` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4634b11ebbc0b719c02f18e560504422` |
| SHA-1 | `ec2e015261354432e4b9a923399f5b9235af8605` |
| SHA-256 | `704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c` |
| SHA3-384 | `d3720b569cdca32a512496e6cb0949a68f71c4881824f20afff426aefe7fe4996771ca2f373f18dc1e937d1a02cd89d0` |
| TLSH | `T197F2F2F1C2718A0CE33D52FE45AD6D0D2845981CAD04A1F6EF4878B39606F649DB17EE` |
| SSDEEP | `768:BW/zEpEYEgHE+Tc70R1cVC9owNnTAz9okfsJYOflDY18nbcuyD7UHQRjP:E4B1E+TcAYC9owui3h6Cnouy8HyT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_704c6407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:49"
  condition:
    hash.sha256(0, filesize) == "704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c"
}
```

### Sample 45: `edca648878da6994`

| Field | Value |
|---|---|
| SHA-256 | `edca648878da699457d345b19412036b6623c75f13d5fa5e59ac77c957bc06a1` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba02820b4f65f1ff5a7054f9206d5a82` |
| SHA-1 | `16e5418e3b4d7015577295431fb48955dc2140df` |
| SHA-256 | `edca648878da699457d345b19412036b6623c75f13d5fa5e59ac77c957bc06a1` |
| SHA3-384 | `760323b748bc4f91f7edfb4296947b17f7eb2c13d56367a75e160245ec2ce30cba3aa9480223c8faf7608132a800587f` |
| TLSH | `T1C572AFF7638BD4F4C936B1B3196842C4FCB3B42764398FAB04A171B6DC7A6046A60B95` |
| SSDEEP | `384:mSpXRiVKXrhy42wONDeSD2SzfLqsw0tMxeJznUxaVXALs7H842+:pt5Iec7f+swUVzBc4N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_edca6488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edca648878da699457d345b19412036b6623c75f13d5fa5e59ac77c957bc06a1"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:48"
  condition:
    hash.sha256(0, filesize) == "edca648878da699457d345b19412036b6623c75f13d5fa5e59ac77c957bc06a1"
}
```

### Sample 46: `ca05d5c61cff1ffb`

| Field | Value |
|---|---|
| SHA-256 | `ca05d5c61cff1ffb32c1b4f8bb5227320f90d4cc36c2b05e406350f5071531a9` |
| Family label | `unknown` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:47` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24ff9b0b662ce63dae5e1fa58a9d8ad5` |
| SHA-1 | `38166567ed3bfc45bbaffdcf1aa225f55e27cb47` |
| SHA-256 | `ca05d5c61cff1ffb32c1b4f8bb5227320f90d4cc36c2b05e406350f5071531a9` |
| SHA3-384 | `6e3aa7dbd21e40ac1a69f1f09533285e96b2fe8b86147441437c00bda22d5ab6907e81a28ae4128d79cbefbd88255e75` |
| TLSH | `T144D21939EB320D13C4D559B896F3432CB9FA465E65794B1A3C670EC8FBA1A846013FE4` |
| SSDEEP | `384:DXJJt5iyYWz1vWQ4OxtuQljdf5iFU+pphBGMorGdC:DXJJt5k8xPLWO+Lj9o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_ca05d5c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca05d5c61cff1ffb32c1b4f8bb5227320f90d4cc36c2b05e406350f5071531a9"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:47"
  condition:
    hash.sha256(0, filesize) == "ca05d5c61cff1ffb32c1b4f8bb5227320f90d4cc36c2b05e406350f5071531a9"
}
```

### Sample 47: `b11998016b3dff68`

| Field | Value |
|---|---|
| SHA-256 | `b11998016b3dff6845cdd7f9c6b7c08a9e02c38327e84b98b7be04cbc7e1ac08` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `442b16148969e0fe4506886ea52ef130` |
| SHA-1 | `3225275af2d8f3510b78aada54f1b91b6d6e3783` |
| SHA-256 | `b11998016b3dff6845cdd7f9c6b7c08a9e02c38327e84b98b7be04cbc7e1ac08` |
| SHA3-384 | `aae379d930247680138f3e1ee2be2d146244dba8e5b2687f2897c57045de00a0ea2efa3b35e6cd2c0a06da3fefc1aa2d` |
| TLSH | `T11572B06B13131BEBD82A983612E91BF609728961F953EC86A801C5538F570E47CDBDD8` |
| SSDEEP | `384:U3uNiJW9NND6CPG1jwUp8A6/B83BtDA1JgGlzDpHOw23a+L:U3cieN27xwUpX6/KxtD0JgGlzDpuWw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_b1199801
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b11998016b3dff6845cdd7f9c6b7c08a9e02c38327e84b98b7be04cbc7e1ac08"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:46"
  condition:
    hash.sha256(0, filesize) == "b11998016b3dff6845cdd7f9c6b7c08a9e02c38327e84b98b7be04cbc7e1ac08"
}
```

### Sample 48: `3e1b90ccb649b66a`

| Field | Value |
|---|---|
| SHA-256 | `3e1b90ccb649b66a0c30fa535e5380f3cf182a3b5e75533afda91f69a6218f7f` |
| Family label | `unknown` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df41ea81376596fc9b137e2eba1eea6d` |
| SHA-1 | `e486ae2fb58c1bab5318b5521413ba1b605e5184` |
| SHA-256 | `3e1b90ccb649b66a0c30fa535e5380f3cf182a3b5e75533afda91f69a6218f7f` |
| SHA3-384 | `3b60f8d17abe0ea52864a834a0411df8af8ea24dc3fbe6e882c67ceafab7366854ccbb50d83a2faf379dca1a0b8eb931` |
| TLSH | `T1F5C24C86BD814917C9D6117AFA2ED18D37665BB4E2FF3303A7265B702743A2B0F36409` |
| TELFHASH | `t1db11bd911c4c5c6af584d23cf24e63238129a2fb7d3e38187ae3cc2d91668f11c25c11` |
| SSDEEP | `384:jJSTLfrQ++VB90NEevfnQqPTXTQDAR6dv5kLoMB9Ie0fFx4e:jGnL0m9fQqbXTA8oc9Ie1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_3e1b90cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1b90ccb649b66a0c30fa535e5380f3cf182a3b5e75533afda91f69a6218f7f"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:44"
  condition:
    hash.sha256(0, filesize) == "3e1b90ccb649b66a0c30fa535e5380f3cf182a3b5e75533afda91f69a6218f7f"
}
```

### Sample 49: `40f09e69d334c5b9`

| Field | Value |
|---|---|
| SHA-256 | `40f09e69d334c5b951edb85ffe8b81e03ab4ff7db5d408add95aadc35b70bf13` |
| Family label | `unknown` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de092f4c2b579a6f49ae1f71a6a52bd0` |
| SHA-1 | `20af7e0f0f691d2ab8d6ab4e38bd18df91120330` |
| SHA-256 | `40f09e69d334c5b951edb85ffe8b81e03ab4ff7db5d408add95aadc35b70bf13` |
| SHA3-384 | `932443fc41d8d3960cfe1006ec938a38710239d99a9bc8a996c654a728fe253304473fc1315b25902aaa2ef45fa4cdfd` |
| TLSH | `T13972BF91FAD2CE5AE29D81B305DE7D0A1818F01EB4C904E73958A073AC26BDC2D5CFD2` |
| SSDEEP | `384:MEBjc293aM7zPwWMjfXVcFm5vqiffD3vtGmNSANaNJawcudoD7Uq/80:BBgua6rwWMbGm9qiD3vt5snbcuyD7Ub0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_40f09e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f09e69d334c5b951edb85ffe8b81e03ab4ff7db5d408add95aadc35b70bf13"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:42"
  condition:
    hash.sha256(0, filesize) == "40f09e69d334c5b951edb85ffe8b81e03ab4ff7db5d408add95aadc35b70bf13"
}
```

### Sample 50: `a039db61b06d1378`

| Field | Value |
|---|---|
| SHA-256 | `a039db61b06d137895143157fd05718e9603bd9c1470fac58856972c1064515a` |
| Family label | `unknown` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76cc63f4163f840d50a65ae5b970eb85` |
| SHA-1 | `d36365caa83993964b1cf0c13edc5dde741dd827` |
| SHA-256 | `a039db61b06d137895143157fd05718e9603bd9c1470fac58856972c1064515a` |
| SHA3-384 | `506a82afc98dbfd1cd32f2d540969400f437c6c45ed26451ca56f1ac5483c281e04d988e9149fdfbbcc3dd83a4f163b5` |
| TLSH | `T164B2E10C472BDE64EA740CF3FC298947E1D316F8E0B5B0A56B50DA9C210388DE3F865A` |
| SSDEEP | `384:lHaclmsCHKEV0xms/0ZVvYYhY+awkxAeqLqW+lOw3utq06zPIntpBKNEeqmdGU5c:lXlGHKE++/vYY0C19CVzmpeq3Uirj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_a039db61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a039db61b06d137895143157fd05718e9603bd9c1470fac58856972c1064515a"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:41"
  condition:
    hash.sha256(0, filesize) == "a039db61b06d137895143157fd05718e9603bd9c1470fac58856972c1064515a"
}
```

### Sample 51: `c3f4b8833424d583`

| Field | Value |
|---|---|
| SHA-256 | `c3f4b8833424d58313c09bfe519126396cef6a49746fc8630dfa667ea82a77c5` |
| Family label | `unknown` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-20 04:18:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45dfd9004cc16c57385e68cd5029bb7b` |
| SHA-1 | `10db94392bc7774721deff0c76b5c4f3556be121` |
| SHA-256 | `c3f4b8833424d58313c09bfe519126396cef6a49746fc8630dfa667ea82a77c5` |
| SHA3-384 | `c7da90f132d327ce9da5dca27820a4cda43ee6c5042ee54970fa1acf81e4e3170ce7b713ffba34c1071aaee870d985f6` |
| TLSH | `T1C092D169458AB151CBB20873D8AE064697C733F8E06EF2633F581E8CBD5110BA9FC587` |
| SSDEEP | `384:WkbADrcNtkHnX8h182qlXErXyX0gdi2aj4CFhNI5LNXqmdGU57ptVGq8rsc5:tbyrbHMh62qaypU204C/+tNXq3Uirv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_c3f4b883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3f4b8833424d58313c09bfe519126396cef6a49746fc8630dfa667ea82a77c5"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:39"
  condition:
    hash.sha256(0, filesize) == "c3f4b8833424d58313c09bfe519126396cef6a49746fc8630dfa667ea82a77c5"
}
```

### Sample 52: `294aea20f003b4a5`

| Field | Value |
|---|---|
| SHA-256 | `294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f` |
| Family label | `unknown` |
| File name | `294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f` |
| File type | `elf` |
| First seen | `2026-09-20 04:17:23` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8d36c14869f60938325f54533eb07a8` |
| SHA-1 | `5020199531be652444877ffe80b3518e88a74e8d` |
| SHA-256 | `294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f` |
| SHA3-384 | `1a2ae7f3ba86325a6ec4d416fd5c86c9ef1f0f5029e0a4dce1b4e21600e84aadc7721af35f7adc49c46085e1a054b034` |
| TLSH | `T1AFC3125193220D0BC42538FABE16E6162D862E79244E409C46F5E67B5FB70DCEAF1353` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxn:biMYFJvw6Yh0b1gKobtCGCmCRlrJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_294aea20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f"
    family = "unknown"
    file_name = "294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f"
    file_type = "elf"
    first_seen = "2026-09-20 04:17:23"
  condition:
    hash.sha256(0, filesize) == "294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f"
}
```

### Sample 53: `b9a4e65437f0487d`

| Field | Value |
|---|---|
| SHA-256 | `b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a` |
| Family label | `unknown` |
| File name | `b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a` |
| File type | `elf` |
| First seen | `2026-09-20 04:17:17` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ada1193eae0009a6d4b63463e40fef7` |
| SHA-1 | `7b6e239d69be8241f7e0c1daf028f23e58f606a9` |
| SHA-256 | `b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a` |
| SHA3-384 | `23b22555c8a6c66bd7d75dcd39f9b18978a3e76de4ea5124467ff8f63b642254fa2bec7dadd80973140fa52f8267584f` |
| TLSH | `T1C193024AFF25CD06CB1008B327DA9E9ECC697B5B46DBB4B469C1988F67900C97C53208` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0Oi:phNlHuBafLeBtfCzpta8xlBIOi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_b9a4e654
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a"
    family = "unknown"
    file_name = "b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a"
    file_type = "elf"
    first_seen = "2026-09-20 04:17:17"
  condition:
    hash.sha256(0, filesize) == "b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a"
}
```

### Sample 54: `fba09a4c474ac69d`

| Field | Value |
|---|---|
| SHA-256 | `fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf` |
| Family label | `unknown` |
| File name | `fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf` |
| File type | `elf` |
| First seen | `2026-09-20 04:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1b875f82f3fc33e58647d71d4931352` |
| SHA-1 | `cb1e85677828b79f159a17daedfe58a3a6ccab94` |
| SHA-256 | `fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf` |
| SHA3-384 | `87cdfea8fe67c5bbe80771c5bf367e6f24cfa49eb54832624c5499aa9ef9e0bdee234fc5767aceed75cc099cc73f9b9e` |
| TLSH | `T145130682BC82865689D813BEF97D41CD331273B9D2DF7112CD115F18B6CA94F0E7AA92` |
| SSDEEP | `768:CMn1EjZA//+1vTRfRiOC7wYqT4JqsWA3B5d7I9ybMioW+j/LsYtXO0Cuh:CMn12A//SrRftY97WARbIcbboW+zLsYD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_fba09a4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf"
    family = "unknown"
    file_name = "fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf"
    file_type = "elf"
    first_seen = "2026-09-20 04:17:12"
  condition:
    hash.sha256(0, filesize) == "fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf"
}
```

### Sample 55: `41fc899b52387d21`

| Field | Value |
|---|---|
| SHA-256 | `41fc899b52387d2174f728a19be218d282685843458de274874d23276d07c042` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:16:57` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5127bc0ecdcffa732e83577346502731` |
| SHA-1 | `1c2aaccaa77a8762ae4d6e969a7e1e0d92c3338c` |
| SHA-256 | `41fc899b52387d2174f728a19be218d282685843458de274874d23276d07c042` |
| SHA3-384 | `2c4816d4ac58cc638d8ebdfd38858a480212bc111a4ca65393671bf057b484c6926fd7ab5343d13834e710ec0504d0cd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18762D78AD8A22F5CCE4E80707B11F838B9753690866559E3DBC28C305DB79D050A4FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UG+j0e:fKOe2/7c9sN3zfZR1m+RGD6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_41fc899b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41fc899b52387d2174f728a19be218d282685843458de274874d23276d07c042"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:16:57"
  condition:
    hash.sha256(0, filesize) == "41fc899b52387d2174f728a19be218d282685843458de274874d23276d07c042"
}
```

### Sample 56: `4b52da2e4339de59`

| Field | Value |
|---|---|
| SHA-256 | `4b52da2e4339de59ff15b1a8cf6e6754ec8e4aecc213f3baaefac06754201794` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:14:31` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4dfc3efde9b51310d1db829d7893bfa` |
| SHA-1 | `2dd561899a72c290d26ceb34063662ed8b3ca1af` |
| SHA-256 | `4b52da2e4339de59ff15b1a8cf6e6754ec8e4aecc213f3baaefac06754201794` |
| SHA3-384 | `62f608ec3007012cfbd6bec61100a3114d1a0c463dda43b4b1c75347b83e1b03b04c8d30da68050f0c7147760c28bafc` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17762C78AE9E22FACCE4F80703B11F9786D713690857559EBD7818C265EA38E11424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UBYzBM:fKOe2/7c9sN3zfZR1m+RGt6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_4b52da2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b52da2e4339de59ff15b1a8cf6e6754ec8e4aecc213f3baaefac06754201794"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:14:31"
  condition:
    hash.sha256(0, filesize) == "4b52da2e4339de59ff15b1a8cf6e6754ec8e4aecc213f3baaefac06754201794"
}
```

### Sample 57: `53947abf12814f52`

| Field | Value |
|---|---|
| SHA-256 | `53947abf12814f52230fc93d614bbd211957c8675ae99a1e0ba43393cbaec11c` |
| Family label | `Mirai` |
| File name | `sever1078.mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:13:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `255af1d17c18e0ec4c8758b8e0b87583` |
| SHA-1 | `611cd2a7a3cca890ec2dbfdf373d4e1eff8d5d64` |
| SHA-256 | `53947abf12814f52230fc93d614bbd211957c8675ae99a1e0ba43393cbaec11c` |
| SHA3-384 | `7acdcf87c7e2ebd32a72cc32f64ff35fb1bddddf2e84e7a60ad5e5cadfe6fd3f657d8c1acd6f1d84c63779b11ba795bc` |
| TLSH | `T166D4084BAE719F3DF764C77187F34B20D2A9239317E1C581E1ACE1094E2029A5D6FB68` |
| TELFHASH | `t120712cd77eb522986d8c424e43cdda300e5a0c9e2ef6166bce6655c7870b7c22f76c12` |
| SSDEEP | `6144:DOrZCvwKtrJ85OC/S+KUHYEcsyawKor7qNbUf33UCyTpsbsp/ZaMztzAuDAd39cf:DWztvZ4RhTri2nscaV8q/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_53947abf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53947abf12814f52230fc93d614bbd211957c8675ae99a1e0ba43393cbaec11c"
    family = "Mirai"
    file_name = "sever1078.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:13:21"
  condition:
    hash.sha256(0, filesize) == "53947abf12814f52230fc93d614bbd211957c8675ae99a1e0ba43393cbaec11c"
}
```

### Sample 58: `e65a3387fe886951`

| Field | Value |
|---|---|
| SHA-256 | `e65a3387fe886951238a8db1bba23a51bd41b917bcc6cb936232519018d622a3` |
| Family label | `Mirai` |
| File name | `sever1078.mips` |
| File type | `elf` |
| First seen | `2026-09-20 04:12:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ae7b58e375fe5606f5f11de3779b851` |
| SHA-1 | `9063e1aa90ade7ccc7bf6db405c8774a7e25589d` |
| SHA-256 | `e65a3387fe886951238a8db1bba23a51bd41b917bcc6cb936232519018d622a3` |
| SHA3-384 | `43c37685c67443790e42cc7b6fdfe63a8224fee3ed564f45d0d822c987bc83a55092d6df980b76748263675f7e9cec6c` |
| TLSH | `T1C4342354EB475CEA41428D993829F8F0D017FF58458E5896FB5CDBA4001768F3AE0EEE` |
| SSDEEP | `6144:FxYPRsqkdo2tvNS4ybyi8LuCKLh+oo1OV95LL:Fx2R52o2jSxvCKF9V9d` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_e65a3387
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e65a3387fe886951238a8db1bba23a51bd41b917bcc6cb936232519018d622a3"
    family = "Mirai"
    file_name = "sever1078.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:12:36"
  condition:
    hash.sha256(0, filesize) == "e65a3387fe886951238a8db1bba23a51bd41b917bcc6cb936232519018d622a3"
}
```

### Sample 59: `6d376ed261b84879`

| Field | Value |
|---|---|
| SHA-256 | `6d376ed261b8487976577a91f632a922c21166cc42739f0c273a678fec3fee02` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-20 04:12:34` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec2aeb51106d13c629b4e44954dcd824` |
| SHA-1 | `37adcf7346efa511ad0d55842c233ccb531aa6dd` |
| SHA-256 | `6d376ed261b8487976577a91f632a922c21166cc42739f0c273a678fec3fee02` |
| SHA3-384 | `155b70f7596b02b69cf96117b196b4b44cfc89fc3c0227759a7f86b99a5b6cac2297839f137e2c8791db9dc510e4d344` |
| TLSH | `T1F8136D6526953C25AE99883B5C7F2F0CBDA983E2304491DDBFCA3CF18C15A9CE718719` |
| SSDEEP | `768:hr9NyXsZztC49GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:ZHusZoco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_059_6d376ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d376ed261b8487976577a91f632a922c21166cc42739f0c273a678fec3fee02"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:12:34"
  condition:
    hash.sha256(0, filesize) == "6d376ed261b8487976577a91f632a922c21166cc42739f0c273a678fec3fee02"
}
```

### Sample 60: `fce8a8eafa41aad0`

| Field | Value |
|---|---|
| SHA-256 | `fce8a8eafa41aad0cdcd9e27d180523f67baf642808a799cfdb37883b699dae2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:06:34` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a76627e6e4131f6386670c31fca68d34` |
| SHA-1 | `f5c5a9c17e254498af0b85f760619cadd991dc4c` |
| SHA-256 | `fce8a8eafa41aad0cdcd9e27d180523f67baf642808a799cfdb37883b699dae2` |
| SHA3-384 | `ba7a085f5ca36ceae3cb86ba95b9edf4878c9b6eabab2b1071ec12f1c1d2bd1dbf031b5355d3b14b0f9812847a4f7aa6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18A62D58AD8A21F6CDE4E80707A51F838E97036A096665DE7C7828D315EB39E04074EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46USJBgn:fKOe2/7c9sN3zfZR1m+RG/J6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_fce8a8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fce8a8eafa41aad0cdcd9e27d180523f67baf642808a799cfdb37883b699dae2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:06:34"
  condition:
    hash.sha256(0, filesize) == "fce8a8eafa41aad0cdcd9e27d180523f67baf642808a799cfdb37883b699dae2"
}
```

### Sample 61: `ba2b9154c7dba986`

| Field | Value |
|---|---|
| SHA-256 | `ba2b9154c7dba98602de83bdb0d7463015dc4a26b1f2ba3008ed4ddce72b159f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:05:16` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bbf610dd8f3d5f27bb86060b5c677b9` |
| SHA-1 | `c4ff6128215c2c48dd58a761dde88ffd4624f1a0` |
| SHA-256 | `ba2b9154c7dba98602de83bdb0d7463015dc4a26b1f2ba3008ed4ddce72b159f` |
| SHA3-384 | `0ff001a0f98501006d88d3af6291894260d340bf994c3251fabd5b89dbc9abb5d15ec9288cddea737b3960726207fbf4` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12062D69AD8D22F9DDE4F80B07E11F929BA703690C66559E3DB828D315EA39D00074FF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGnPoooooooooooooooooooooop6C:fKOeOQOzUxnPooooooooooooooooooo5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_ba2b9154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba2b9154c7dba98602de83bdb0d7463015dc4a26b1f2ba3008ed4ddce72b159f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:05:16"
  condition:
    hash.sha256(0, filesize) == "ba2b9154c7dba98602de83bdb0d7463015dc4a26b1f2ba3008ed4ddce72b159f"
}
```

### Sample 62: `e1254727c72df075`

| Field | Value |
|---|---|
| SHA-256 | `e1254727c72df075472bdfd39fe45599c260355710d1e631adc3be4325408247` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:04:06` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71188483a7419380cc5e2e47f6d63bb3` |
| SHA-1 | `894dc5b3b85acbfc2c181d6685eccaf35a154d1f` |
| SHA-256 | `e1254727c72df075472bdfd39fe45599c260355710d1e631adc3be4325408247` |
| SHA3-384 | `c87fb4e070c458c129c0505dd929f2fdde94c3de212cd6da57c9ed4a7143677260c88bec3f6506c74787950cff9e3fc2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15862E68AD9A62E9DCE4F80B07A51F978BD74369086659CF7C7928C354DA38C00024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UXFrHT:fKOe2/7c9sN3zfZR1m+RG+Hc76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_e1254727
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1254727c72df075472bdfd39fe45599c260355710d1e631adc3be4325408247"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:04:06"
  condition:
    hash.sha256(0, filesize) == "e1254727c72df075472bdfd39fe45599c260355710d1e631adc3be4325408247"
}
```

### Sample 63: `14aea34b2ce37e3c`

| Field | Value |
|---|---|
| SHA-256 | `14aea34b2ce37e3c57dcf070f856677b7ab41b8b6500d29121fe377abdff5014` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:03:13` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7db2d3ffc6b473d46dfeefe1a6b99767` |
| SHA-1 | `66ce2cdc533d834fa0949091b24d1a1a32e45674` |
| SHA-256 | `14aea34b2ce37e3c57dcf070f856677b7ab41b8b6500d29121fe377abdff5014` |
| SHA3-384 | `e6476af078e16947fc5f1fd86332cbb6b63bec05b906dee3c0c97023f874bd23bea1dbe7cb4bab22a5674cce2ddc8fc1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E962C587D8A22F6CCE4EC0707A11F979ADB03294966599F3D7818C31A963ED00538EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U70Sx3:fKOe2/7c9sN3zfZR1m+RGJj6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_14aea34b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14aea34b2ce37e3c57dcf070f856677b7ab41b8b6500d29121fe377abdff5014"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:03:13"
  condition:
    hash.sha256(0, filesize) == "14aea34b2ce37e3c57dcf070f856677b7ab41b8b6500d29121fe377abdff5014"
}
```

### Sample 64: `9f002919c655b2eb`

| Field | Value |
|---|---|
| SHA-256 | `9f002919c655b2ebfce070fcf572a8454d7bfea4893084362119ac5d0fb9b350` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:02:44` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b8dc0b855668d54512daf87468abadb` |
| SHA-1 | `0e5a7c0aa097a74fdaec23c587b6bb6452e8f5ee` |
| SHA-256 | `9f002919c655b2ebfce070fcf572a8454d7bfea4893084362119ac5d0fb9b350` |
| SHA3-384 | `5e987b8a6f1ad9cdfe57a52c53d8eb434e0639ccdb135b8ff3c69973170f13c0e0bc77f0615e1649fbddeb9d5a718a6d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B562D696D8A22F6DDE4F80703A11F878BDB432949665A9E7D7828C705DB79C04028FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uzy4BM:fKOe2/7c9sN3zfZR1m+RGs6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_9f002919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f002919c655b2ebfce070fcf572a8454d7bfea4893084362119ac5d0fb9b350"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:02:44"
  condition:
    hash.sha256(0, filesize) == "9f002919c655b2ebfce070fcf572a8454d7bfea4893084362119ac5d0fb9b350"
}
```

### Sample 65: `3260d5dd17bfb325`

| Field | Value |
|---|---|
| SHA-256 | `3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0` |
| Family label | `Snowlight` |
| File name | `3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0.elf` |
| File type | `elf` |
| First seen | `2026-09-20 04:02:35` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbf59b4105b4eea65738e28b0808c6eb` |
| SHA-1 | `0edf7dc18e9aeff56cc969477f61172e28985180` |
| SHA-256 | `3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0` |
| SHA3-384 | `2bd28b9f7658dc8db83c92de30cc1dcfc37db84689ce3d5343d0be4e36642f81291585f77ba836cfdbb7ab6358c166b9` |
| TLSH | `T18E123047A2D0CE3FC8D953384467122472B794BEDF629723064815B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS61H5ML09V1J9G8Ym1+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHuZMWT1YmohrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_065_3260d5dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0"
    family = "Snowlight"
    file_name = "3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0.elf"
    file_type = "elf"
    first_seen = "2026-09-20 04:02:35"
  condition:
    hash.sha256(0, filesize) == "3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0"
}
```

### Sample 66: `ceaf5f499997eaa8`

| Field | Value |
|---|---|
| SHA-256 | `ceaf5f499997eaa890d3ea872f0a526f4f15a34f306b8aa4b409f56a08473170` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:01:37` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4b9897e78b539b30b5e2d20446559cd` |
| SHA-1 | `3946a71c9801f83697e48b8dbec0dbf6c7535559` |
| SHA-256 | `ceaf5f499997eaa890d3ea872f0a526f4f15a34f306b8aa4b409f56a08473170` |
| SHA3-384 | `bfc32194cb1d66b563eb98680de3354ea00e04126fcd9f746d8b8fcd947ab0de905047186b160804db4627ea6ecf70ce` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A462C486D9A22F6CCE4AC0707A11F938A97172D0866699E7D7D28C655EB3DE00034EFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGEWffffffffffw6C:fKOeOQOzUxy6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_ceaf5f49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceaf5f499997eaa890d3ea872f0a526f4f15a34f306b8aa4b409f56a08473170"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:01:37"
  condition:
    hash.sha256(0, filesize) == "ceaf5f499997eaa890d3ea872f0a526f4f15a34f306b8aa4b409f56a08473170"
}
```

### Sample 67: `6ff5ecc509b1f11c`

| Field | Value |
|---|---|
| SHA-256 | `6ff5ecc509b1f11c19b495b42fabacfb87d62f64d68b8311465c82fee8fc88a8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:00:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ac6d98dfe0987f6a79d8118ba637a71` |
| SHA-1 | `9de1af84a1bb66d180ae0000f07b8b227d2a4169` |
| SHA-256 | `6ff5ecc509b1f11c19b495b42fabacfb87d62f64d68b8311465c82fee8fc88a8` |
| SHA3-384 | `22bf47e80aefe28c305cd383987af46bbacac77e5370bef56373d399fa0368b815ccc85a52751388fed876d877e09c94` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11E62C786D9E21F6CDE4F80703E52F878AD743690866A69E3D7828C715EA39D01124FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U2cNBM:fKOe2/7c9sN3zfZR1m+RGd86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_6ff5ecc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff5ecc509b1f11c19b495b42fabacfb87d62f64d68b8311465c82fee8fc88a8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:00:47"
  condition:
    hash.sha256(0, filesize) == "6ff5ecc509b1f11c19b495b42fabacfb87d62f64d68b8311465c82fee8fc88a8"
}
```

### Sample 68: `5b208b50a81020b3`

| Field | Value |
|---|---|
| SHA-256 | `5b208b50a81020b3011b03ab18a163f193114b7c537cedf204e17c9ce7f0dcc6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 04:00:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81cac50bdee0487246ca9d5c71b336cf` |
| SHA-1 | `0c72ccbcbc67c77113b48690d02cf6af8694d030` |
| SHA-256 | `5b208b50a81020b3011b03ab18a163f193114b7c537cedf204e17c9ce7f0dcc6` |
| SHA3-384 | `cf71797313be6a1b3c4e2becfe45c12c277a5f743b68e1853654878325f0c80c3361fdbb73ade6e7ee4955333d8afb7b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15562C686E8A26F5CDE4F80B03B11F828AD71369086656DE3D7928C395DA38D00534FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uh/Bgn:fKOe2/7c9sN3zfZR1m+RGE/6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_5b208b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b208b50a81020b3011b03ab18a163f193114b7c537cedf204e17c9ce7f0dcc6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:00:19"
  condition:
    hash.sha256(0, filesize) == "5b208b50a81020b3011b03ab18a163f193114b7c537cedf204e17c9ce7f0dcc6"
}
```

### Sample 69: `e974913b60253b95`

| Field | Value |
|---|---|
| SHA-256 | `e974913b60253b954569dbffc87c22471700eaeb5364a2eeebf2139073189c27` |
| Family label | `Mirai` |
| File name | `Space.arm` |
| File type | `elf` |
| First seen | `2026-09-20 03:59:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66a55700cb41189cc251d0609fc99020` |
| SHA-1 | `cf27eb028aeff8a0e45b499e84eac1980e4bc447` |
| SHA-256 | `e974913b60253b954569dbffc87c22471700eaeb5364a2eeebf2139073189c27` |
| SHA3-384 | `02a612ade23b6759c893423631fa7b748a8cc5c941c04478802a844358abf294d92f7870ff6ea5c766265ac3f66f8df6` |
| TLSH | `T113733A55FD814B23C6C1123BFB6E068D3B2653E9E2EA72039E259F2133C751B0D6B895` |
| TELFHASH | `t1c64120b1e7a41bcc77d0c704c28b92696ab535ad771034968f2d938b9193ac1b11d42f` |
| SSDEEP | `1536:OZWLxW3i3jV9ZJpcO72Rbu1U+qhxp8f8vNE:OZWLnJpcO72RDRZNE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_e974913b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e974913b60253b954569dbffc87c22471700eaeb5364a2eeebf2139073189c27"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-20 03:59:14"
  condition:
    hash.sha256(0, filesize) == "e974913b60253b954569dbffc87c22471700eaeb5364a2eeebf2139073189c27"
}
```

### Sample 70: `aa85be63909ee534`

| Field | Value |
|---|---|
| SHA-256 | `aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42` |
| Family label | `Mirai` |
| File name | `Space.arm` |
| File type | `elf` |
| First seen | `2026-09-20 03:58:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceae526c2e96342dad1893ffb467c042` |
| SHA-1 | `10e9db3c7601be11c9be76be6070908faaa68e0c` |
| SHA-256 | `aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42` |
| SHA3-384 | `89c809f65010cdd16314f5478e8f0f326ee8c7ad6c07c15a79909dd5a85ab0ce64693a84c166c334767eeef914939bbc` |
| TLSH | `T15BF2E195228D707681E0ACB3D47087F02D7A01B7D4D973A15FF98248D58A722E87BEE7` |
| SSDEEP | `768:7rFs5me135wp1C+s9vbM5YNMygu+OR1juP3ACqtqNLIzLtZ6Ggt7vtHH4s3Uozd:7/eRSnQjMgVuP7qtqxgtAbvttzd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_aa85be63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-20 03:58:37"
  condition:
    hash.sha256(0, filesize) == "aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42"
}
```

### Sample 71: `fd6ba3e910f9e17d`

| Field | Value |
|---|---|
| SHA-256 | `fd6ba3e910f9e17d9848fbc7f214e827da40e6416f9e26bd3aece320c981b63b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:58:29` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe8e8e6b431d07714698ccbf23301caa` |
| SHA-1 | `bff2fdb9dcdcdfd4e0208d22307651aff836aa3a` |
| SHA-256 | `fd6ba3e910f9e17d9848fbc7f214e827da40e6416f9e26bd3aece320c981b63b` |
| SHA3-384 | `23e38398310646d8258188f9c6dba4e7d091111eb7ad091fd3d359ec5f26f98ea36c5a0058acab6ae10f15b2b2ab891c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FF62C587D9E2AF7DCE4E80703A12F879BDB47290962659E3D7828C315DA39D00534EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UQpthe:fKOe2/7c9sN3zfZR1m+RGPpth6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_fd6ba3e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6ba3e910f9e17d9848fbc7f214e827da40e6416f9e26bd3aece320c981b63b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:58:29"
  condition:
    hash.sha256(0, filesize) == "fd6ba3e910f9e17d9848fbc7f214e827da40e6416f9e26bd3aece320c981b63b"
}
```

### Sample 72: `75f214437ecc0450`

| Field | Value |
|---|---|
| SHA-256 | `75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3` |
| Family label | `unknown` |
| File name | `75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3` |
| File type | `elf` |
| First seen | `2026-09-20 03:56:18` |
| Reporter | `theodore_brucker` |
| Tags | `cowrie, elf, honeypot, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85bb288f9e56773cd4d33dcef0e277ea` |
| SHA-256 | `75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_75f21443
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3"
    family = "unknown"
    file_name = "75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3"
    file_type = "elf"
    first_seen = "2026-09-20 03:56:18"
  condition:
    hash.sha256(0, filesize) == "75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3"
}
```

### Sample 73: `897ea7b1ff1c13db`

| Field | Value |
|---|---|
| SHA-256 | `897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542` |
| Family label | `unknown` |
| File name | `897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542` |
| File type | `elf` |
| First seen | `2026-09-20 03:56:11` |
| Reporter | `theodore_brucker` |
| Tags | `cowrie, elf, honeypot, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f6864243a03ab1b0fed2a95fd410db8` |
| SHA-256 | `897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_897ea7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542"
    family = "unknown"
    file_name = "897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542"
    file_type = "elf"
    first_seen = "2026-09-20 03:56:11"
  condition:
    hash.sha256(0, filesize) == "897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542"
}
```

### Sample 74: `46661ea89330de93`

| Field | Value |
|---|---|
| SHA-256 | `46661ea89330de9355c49446ebaf618a6cfdb0907ab0c838af9cd1dde9dbb8d1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:53:02` |
| Reporter | `Bitsight` |
| Tags | `4d233bcb7c81bb5e9ffd2a3f813ea9bf, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6c6bbbf9d2669af75a5e350efae5161` |
| SHA-1 | `877e01c394a3712b486509b58bcc3d34ee00bc90` |
| SHA-256 | `46661ea89330de9355c49446ebaf618a6cfdb0907ab0c838af9cd1dde9dbb8d1` |
| SHA3-384 | `9217efb79f94b40096f70e9ea1217da3bb35c55a96bcdda9215781ab4451cb37054ad17f80c96c1b38c1a0419a025f60` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14C62D686D8E22F6CDE4F90703A12F838BD753790966699E7D7828C345DA3AD00524FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UNGQxe:fKOe2/7c9sN3zfZR1m+RGyx6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_46661ea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46661ea89330de9355c49446ebaf618a6cfdb0907ab0c838af9cd1dde9dbb8d1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:53:02"
  condition:
    hash.sha256(0, filesize) == "46661ea89330de9355c49446ebaf618a6cfdb0907ab0c838af9cd1dde9dbb8d1"
}
```

### Sample 75: `b793206d6e320eec`

| Field | Value |
|---|---|
| SHA-256 | `b793206d6e320eec11d3decf493fc77776e3635df45dbd4abc95fad910db6482` |
| Family label | `Mirai` |
| File name | `sever1078.sh4` |
| File type | `elf` |
| First seen | `2026-09-20 03:30:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3df40ff4e0042e2a870832d1dfecb7c` |
| SHA-1 | `097568776089d9b560bd0c1bcff2aad0d0162885` |
| SHA-256 | `b793206d6e320eec11d3decf493fc77776e3635df45dbd4abc95fad910db6482` |
| SHA3-384 | `909ea69703c29d21044aee742d682502b3cb9e5ae6d4f4d2cc1f9cf17e5a1b1c697a338f90125b4ab94ed890c63b1fef` |
| TLSH | `T115A4BF32C0B59DE4C473A371BCB5DA704B22644492A71DF3A7DEDA590893ED8FB097A0` |
| SSDEEP | `6144:6+c3SuI60zYS9tldsiNMZIgYJfw4VgWqJHYa9IzVSewMW4S:6+ASuUYUtla9ZIgYJfwzJYa9IEp4S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_b793206d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b793206d6e320eec11d3decf493fc77776e3635df45dbd4abc95fad910db6482"
    family = "Mirai"
    file_name = "sever1078.sh4"
    file_type = "elf"
    first_seen = "2026-09-20 03:30:38"
  condition:
    hash.sha256(0, filesize) == "b793206d6e320eec11d3decf493fc77776e3635df45dbd4abc95fad910db6482"
}
```

### Sample 76: `a44a890b1de4581c`

| Field | Value |
|---|---|
| SHA-256 | `a44a890b1de4581c44c02b0e522d6973ca312212758d9fc2e93095b3f5e8a65f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-20 03:27:59` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f54ce5408a05aee3012b5d1b94320286` |
| SHA-256 | `a44a890b1de4581c44c02b0e522d6973ca312212758d9fc2e93095b3f5e8a65f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_a44a890b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a44a890b1de4581c44c02b0e522d6973ca312212758d9fc2e93095b3f5e8a65f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-20 03:27:59"
  condition:
    hash.sha256(0, filesize) == "a44a890b1de4581c44c02b0e522d6973ca312212758d9fc2e93095b3f5e8a65f"
}
```

### Sample 77: `75af5c0339a7400b`

| Field | Value |
|---|---|
| SHA-256 | `75af5c0339a7400b895363e69fa95110e8749c06829455c8ca47ac578f27c8a6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:27:18` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be0bef87c2ef90c1a5f1fce9744d4086` |
| SHA-1 | `4d79ed27153018877db23425988631e991d73345` |
| SHA-256 | `75af5c0339a7400b895363e69fa95110e8749c06829455c8ca47ac578f27c8a6` |
| SHA3-384 | `0c307da887f5ad5f85db8c30d33fccb13a2f7aa0a0e7904c232990488f41474bd52d25350dbe840cdd1e4313051d4638` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19162D78BE9A22F5CEE4F80703A11FD78ADB5769085656AE7D7828C315DA38D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UkhZBM:fKOe2/7c9sN3zfZR1m+RGRZ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_75af5c03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75af5c0339a7400b895363e69fa95110e8749c06829455c8ca47ac578f27c8a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:27:18"
  condition:
    hash.sha256(0, filesize) == "75af5c0339a7400b895363e69fa95110e8749c06829455c8ca47ac578f27c8a6"
}
```

### Sample 78: `889a1c70607da1da`

| Field | Value |
|---|---|
| SHA-256 | `889a1c70607da1da95e1219809f8f2f8f1a9bd2c5034cf780a730d1983f05e22` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:25:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3942c8abee3687efe1740d4fbd1936a` |
| SHA-1 | `984385dda204ffba41e28937d2ceeceaea33cd3c` |
| SHA-256 | `889a1c70607da1da95e1219809f8f2f8f1a9bd2c5034cf780a730d1983f05e22` |
| SHA3-384 | `f91aa93d44c2f28e79d9a88fba6749357446b14a9da714b39ccfdc3cbe683aea24885666c589a3bd1d8a890714abe67f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F462D686DCA22EACDE4ED0703E10FC28AD757690956698E3DB828C705DA39D14024FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uz6NLe:fKOe2/7c9sN3zfZR1m+RGH6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_889a1c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889a1c70607da1da95e1219809f8f2f8f1a9bd2c5034cf780a730d1983f05e22"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:25:50"
  condition:
    hash.sha256(0, filesize) == "889a1c70607da1da95e1219809f8f2f8f1a9bd2c5034cf780a730d1983f05e22"
}
```

### Sample 79: `3d6e08501f6a09d1`

| Field | Value |
|---|---|
| SHA-256 | `3d6e08501f6a09d17cc5ead37d1b9392e4177bb164bb6188df8c8922336d9d97` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:22:24` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e29a79e2b93d30988eb74a1241746f8` |
| SHA-1 | `c2a75e5edb17fc12844eb6274c05331e4428c2df` |
| SHA-256 | `3d6e08501f6a09d17cc5ead37d1b9392e4177bb164bb6188df8c8922336d9d97` |
| SHA3-384 | `0436785a829f58b195795c22a8724df4d3a56669f078f481bdb6af0123e3a17c069d75a13ec736eb91e0ea6d48c2f4d0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13362C796DCD22EACCE4EC0703B51F928AD7036949A666DE3D7928D3059A38D10434FFE` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGcYpppppppppq6C:fKOeOQOzUxcYpppppppppq6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_3d6e0850
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d6e08501f6a09d17cc5ead37d1b9392e4177bb164bb6188df8c8922336d9d97"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:22:24"
  condition:
    hash.sha256(0, filesize) == "3d6e08501f6a09d17cc5ead37d1b9392e4177bb164bb6188df8c8922336d9d97"
}
```

### Sample 80: `2db2be8826006de7`

| Field | Value |
|---|---|
| SHA-256 | `2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad` |
| Family label | `ArkeiStealer` |
| File name | `2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad.bin` |
| File type | `exe` |
| First seen | `2026-09-20 03:21:30` |
| Reporter | `threatcat_ch` |
| Tags | `ArkeiStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3be0c6bfb594eacf23c38be0f1676778` |
| SHA-1 | `67a8ffd3d2d1eb256792fe274590157018d10872` |
| SHA-256 | `2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad` |
| SHA3-384 | `e01abc54aa5bea033f0b3195197bff3e400975bc6fdd9f629cc8a4581f614c61245ae14fd7df75b93d960bf3cb010dce` |
| TLSH | `T199069E55FC8C9D58DC6736338E3124655373FDA13538EC89A9FC39335A3AA908932A72` |
| SSDEEP | `49152:kSLE8S/1w+d5dEQ2DoIXvRXFJvvy7QzrwtZarag8sBcamTP/Kbdt7cuAh77m:kf/1w+d3EQ28I5Sml8HTP6dt7cuAk` |

#### Technical Assessment

- The sample is tracked as `ArkeiStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ArkeiStealer_080_2db2be88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad"
    family = "ArkeiStealer"
    file_name = "2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad.bin"
    file_type = "exe"
    first_seen = "2026-09-20 03:21:30"
  condition:
    hash.sha256(0, filesize) == "2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad"
}
```

### Sample 81: `bc5182c5be1a0ae2`

| Field | Value |
|---|---|
| SHA-256 | `bc5182c5be1a0ae2adf64d0ef9ccb19de85ffee81e11baf6795fab6cd5f3c0f6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:21:05` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac7ea2347aa54a79124471a6937f3142` |
| SHA-1 | `a41aa65361a6ff9372fc52f8de0190f6b3492237` |
| SHA-256 | `bc5182c5be1a0ae2adf64d0ef9ccb19de85ffee81e11baf6795fab6cd5f3c0f6` |
| SHA3-384 | `27d4443b46716c2bd68086fdf7f4ab5300220c34f05589fd4b836e42606cab82a6f22b1ac2b781cda3dfebb812105e57` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11662F786D8A26F5CCE4F80703A11F938BDB63695962969E3E7C28D315DA39C00534FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46USBgCc:fKOe2/7c9sN3zfZR1m+RGp6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_bc5182c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc5182c5be1a0ae2adf64d0ef9ccb19de85ffee81e11baf6795fab6cd5f3c0f6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:21:05"
  condition:
    hash.sha256(0, filesize) == "bc5182c5be1a0ae2adf64d0ef9ccb19de85ffee81e11baf6795fab6cd5f3c0f6"
}
```

### Sample 82: `eb15ea88be64574b`

| Field | Value |
|---|---|
| SHA-256 | `eb15ea88be64574b42ecb12a7fd87cf90b625202f3610451e15fbb633727160d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:18:37` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ebff145a6f98a67881000c8ec0b671f` |
| SHA-1 | `6a503f04537d9e79e7d9001176aaac50403829f8` |
| SHA-256 | `eb15ea88be64574b42ecb12a7fd87cf90b625202f3610451e15fbb633727160d` |
| SHA3-384 | `08e7487b4e409d7ef7164e5583a6c0235579e5d47769f074106a965c5cc8ce32732dbf4298fe53e4c8c7325a8a9c6a8f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EC62E68AD9A26FACEE4F80703A11F978BD703295862599E3D7928C315DA79D00034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UE61vn:fKOe2/7c9sN3zfZR1m+RGJ61O6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_eb15ea88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb15ea88be64574b42ecb12a7fd87cf90b625202f3610451e15fbb633727160d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:18:37"
  condition:
    hash.sha256(0, filesize) == "eb15ea88be64574b42ecb12a7fd87cf90b625202f3610451e15fbb633727160d"
}
```

### Sample 83: `5096417a65e07c38`

| Field | Value |
|---|---|
| SHA-256 | `5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6` |
| Family label | `unknown` |
| File name | `5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6` |
| File type | `elf` |
| First seen | `2026-09-20 03:17:46` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf1e106d98f20664135ad2832f6ed25b` |
| SHA-1 | `beb16686d4e19e3d242b0e1f8bb92859b8d7dade` |
| SHA-256 | `5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6` |
| SHA3-384 | `62c1d3a3d9932dd18b7a9a9d63a2551b320c9a4a18029033ec2a204cbac3003748b188b6e65b97cc0f5f306a102632fa` |
| TLSH | `T10AB31251D3220D0BC43538FABA26E6163D872E69248D415C46F5EA7B5FB708CEAF2353` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxe:biMYFJvw6Yh0b1gKobtCGCmCRlro` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_5096417a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6"
    family = "unknown"
    file_name = "5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6"
    file_type = "elf"
    first_seen = "2026-09-20 03:17:46"
  condition:
    hash.sha256(0, filesize) == "5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6"
}
```

### Sample 84: `f711b96af05ce7c3`

| Field | Value |
|---|---|
| SHA-256 | `f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74` |
| Family label | `Mirai` |
| File name | `f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74` |
| File type | `elf` |
| First seen | `2026-09-20 03:17:40` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `202de58a1395d38f9a884300a37d2850` |
| SHA-1 | `5f40bf8cc4c65a26010029f340a3d14918cc5c90` |
| SHA-256 | `f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74` |
| SHA3-384 | `5b4ab179a19faa2ba48c74ad17531909315ebb5dbb04579c8ec628c98fafa0e6108bcb33d47eeffeb75681305693af34` |
| TLSH | `T1F7A3189ABC919A5545D413BBBE7E818E330723B4D2DF7113DD041F18B6CA94F0E7AA82` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiBg:T2s/gAWuboqsJ9xcJxspJBg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_f711b96a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74"
    family = "Mirai"
    file_name = "f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74"
    file_type = "elf"
    first_seen = "2026-09-20 03:17:40"
  condition:
    hash.sha256(0, filesize) == "f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74"
}
```

### Sample 85: `aba01e0cbe4d4d41`

| Field | Value |
|---|---|
| SHA-256 | `aba01e0cbe4d4d41be6149ad916cd141cc68dddb5746b163ce4055d5b56ab3a1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:16:12` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42b5608f8613215152b68c91e8af9e36` |
| SHA-1 | `963780e2a29495a430af87848962b36debfc22ac` |
| SHA-256 | `aba01e0cbe4d4d41be6149ad916cd141cc68dddb5746b163ce4055d5b56ab3a1` |
| SHA3-384 | `780ed984baaf6add3087d4ca4e56b03f4eaa59da925ef62018f859b0374616c1beed943402e4ee59bc6bf66184fe727d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16962F896E8A1AF5DDE4E81703A11F838BDF4329086A569E3D7828C755DA78C00134FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UeBgCc:fKOe2/7c9sN3zfZR1m+RGF6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_aba01e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba01e0cbe4d4d41be6149ad916cd141cc68dddb5746b163ce4055d5b56ab3a1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:16:12"
  condition:
    hash.sha256(0, filesize) == "aba01e0cbe4d4d41be6149ad916cd141cc68dddb5746b163ce4055d5b56ab3a1"
}
```

### Sample 86: `3151064dc1450bd1`

| Field | Value |
|---|---|
| SHA-256 | `3151064dc1450bd1ff6dfc40fb453371836f9f774026faad389a474141f4e2cf` |
| Family label | `ConnectWise` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 03:12:52` |
| Reporter | `Bitsight` |
| Tags | `ConnectWise, dropped-by-GCleaner, E, exe, signed, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7419e5272ba696e93e8fabc2a55eaa3` |
| SHA-1 | `619f2dab38e109cf839e39bd8abaf19bfb166741` |
| SHA-256 | `3151064dc1450bd1ff6dfc40fb453371836f9f774026faad389a474141f4e2cf` |
| SHA3-384 | `e8d7cba8f6cdff64555e5e7373afe66459c30f44b5e08f0938921b2a165d828062d94a0dc0cb6ab80d9c0b15fd5e801c` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T12856F141B3D695B5C0BF0638D87A42A65634BC148712CBFF57E4BD296D32BC08E7236A` |
| SSDEEP | `49152:ifRBDtJkGYYpT0+TFiH7efP3nrGLq7FVsLBe+1GVxrKlsuwGenGwfZVkVjOi8if0:uqs6efP3rn/TYGVxz3GBwRVkGuyXOM` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_086_3151064d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3151064dc1450bd1ff6dfc40fb453371836f9f774026faad389a474141f4e2cf"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:12:52"
  condition:
    hash.sha256(0, filesize) == "3151064dc1450bd1ff6dfc40fb453371836f9f774026faad389a474141f4e2cf"
}
```

### Sample 87: `01e251668e4913f4`

| Field | Value |
|---|---|
| SHA-256 | `01e251668e4913f44d838c7373f5f57596a57cf66f72c84c4f7be38f0abbe949` |
| Family label | `Mirai` |
| File name | `sever1078.arm7` |
| File type | `elf` |
| First seen | `2026-09-20 03:03:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e78c426e2519ae82edc45e5f67a22266` |
| SHA-1 | `70eeeb08eeacb72ce460c952ba99f2a3d1149e49` |
| SHA-256 | `01e251668e4913f44d838c7373f5f57596a57cf66f72c84c4f7be38f0abbe949` |
| SHA3-384 | `ec6a608273e22dba13215cc08ca943d28fbf62ec108d4711bdbdf67c2e10b64f2e77774b88cbd37a813015beddc70643` |
| TLSH | `T178D46B4AED408B57D4D11BBABBAF524533235BB4E3EB72074D0CAB743B8699A4F76100` |
| TELFHASH | `t1b542ff0d6b2387577e5188d85b99a7e71803850b9a9ccbd19ed88b0fc6340bbfd128dd` |
| SSDEEP | `12288:76pXEcuH6VwnqVA725cfy9Ybxu38tyDgDyNZ7pn+7Uue0gQswuGddzQq1OZcdTa5:OVxf7E7Uuuwu4h141OAt2S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_01e25166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01e251668e4913f44d838c7373f5f57596a57cf66f72c84c4f7be38f0abbe949"
    family = "Mirai"
    file_name = "sever1078.arm7"
    file_type = "elf"
    first_seen = "2026-09-20 03:03:22"
  condition:
    hash.sha256(0, filesize) == "01e251668e4913f44d838c7373f5f57596a57cf66f72c84c4f7be38f0abbe949"
}
```

### Sample 88: `c034e24c7e9ed392`

| Field | Value |
|---|---|
| SHA-256 | `c034e24c7e9ed3926e523998f2f8f485262b15c8a56b802bee1c48a6f2a48630` |
| Family label | `Mirai` |
| File name | `sever1078.arm7` |
| File type | `elf` |
| First seen | `2026-09-20 03:02:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03eb5f3f227b7e16da6fef17fe5292bc` |
| SHA-1 | `45e714e2a66c4829115c76dfb40e8cf75a693d27` |
| SHA-256 | `c034e24c7e9ed3926e523998f2f8f485262b15c8a56b802bee1c48a6f2a48630` |
| SHA3-384 | `501d67a4e4d23d43d18c2ecf71a128795596ce92ca412d7612e536ddb044293fde9c358295c92c15afbb48a233a911e2` |
| TLSH | `T1C444221D46BBC330F4BAED3A2564A1A09F0097F4A5F8AEF272D2215416EC5E39FC46C5` |
| SSDEEP | `6144:0cySvCXf5TbOGpk02yi9cdsbzsm+PKxs8HpqXRVhOqCuS56pXmdFoQ:0cT6FbSEilbzfGKxxpihCTMXm0Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_c034e24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c034e24c7e9ed3926e523998f2f8f485262b15c8a56b802bee1c48a6f2a48630"
    family = "Mirai"
    file_name = "sever1078.arm7"
    file_type = "elf"
    first_seen = "2026-09-20 03:02:36"
  condition:
    hash.sha256(0, filesize) == "c034e24c7e9ed3926e523998f2f8f485262b15c8a56b802bee1c48a6f2a48630"
}
```

### Sample 89: `639d4938aafeec8e`

| Field | Value |
|---|---|
| SHA-256 | `639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032` |
| Family label | `VShell` |
| File name | `639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032.exe` |
| File type | `exe` |
| First seen | `2026-09-20 03:02:27` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4958bc1dbedf3186736ba9be3479f7c6` |
| SHA-1 | `7420293f06c1459b30ac798eaf265c73c47c6439` |
| SHA-256 | `639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032` |
| SHA3-384 | `812d5241f0eac7c38bafcec248ae9367ec39bc39d0e586d443c913cd6ca294823d45021213236975054ac9f2ac1da8d3` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T13891D84170B999E7E85C51BF4D1FB4A0B91D740A41C483A70338A5953E3957BF47CB0E` |
| SSDEEP | `48:6IIF9BlQaexgggZIN7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMgBI60cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_089_639d4938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032"
    family = "VShell"
    file_name = "639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032.exe"
    file_type = "exe"
    first_seen = "2026-09-20 03:02:27"
  condition:
    hash.sha256(0, filesize) == "639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032"
}
```

### Sample 90: `7fd73a46a635050e`

| Field | Value |
|---|---|
| SHA-256 | `7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7` |
| Family label | `VShell` |
| File name | `7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7.exe` |
| File type | `exe` |
| First seen | `2026-09-20 03:02:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a47194ff5f2652905980214c82f496a` |
| SHA-1 | `30e6449456f2dca8b43da38dc1cab6aa01cf37d0` |
| SHA-256 | `7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7` |
| SHA3-384 | `53361c709dd8f4517d852bb94a6c1b5e403f9f44c90880e860bb03176152ce80e6a3c003c683a5c42de39fa6c436a3de` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T16B9195C6F757E6B2EC1C17F500A3B994C8682E14927C9B564FA16F1C3C111AA3D3DA52` |
| SSDEEP | `48:6I7lwe7ng08SEJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1c092q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_090_7fd73a46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7"
    family = "VShell"
    file_name = "7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7.exe"
    file_type = "exe"
    first_seen = "2026-09-20 03:02:22"
  condition:
    hash.sha256(0, filesize) == "7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7"
}
```

### Sample 91: `a77c480d56157cde`

| Field | Value |
|---|---|
| SHA-256 | `a77c480d56157cdeeb8cad6e642c30cdf320d1744e4117e7aa98181e59d85a5e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:59:45` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1cc8d2661c2fb86ef3eca04725662ad` |
| SHA-1 | `9e3bf568dc13b346fff3628208742f07349b485e` |
| SHA-256 | `a77c480d56157cdeeb8cad6e642c30cdf320d1744e4117e7aa98181e59d85a5e` |
| SHA3-384 | `52c67ae9065414341537ab9e05fefa263419d063e3a96acef19c0cd4725bc04aaee299d126c5d1062cd68bc7e4430bef` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18C62C78AE8A26F5DDE8E90707A11F9287EB1329486659DE7D7C18C305D639D04034FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UOwwBM:fKOe2/7c9sN3zfZR1m+RGlL6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_a77c480d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a77c480d56157cdeeb8cad6e642c30cdf320d1744e4117e7aa98181e59d85a5e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:59:45"
  condition:
    hash.sha256(0, filesize) == "a77c480d56157cdeeb8cad6e642c30cdf320d1744e4117e7aa98181e59d85a5e"
}
```

### Sample 92: `f1070b7c57a27fd1`

| Field | Value |
|---|---|
| SHA-256 | `f1070b7c57a27fd1b464ff8dc435a47b11acd91debdfb85862ae2c1e79797aaf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:59:20` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce5091bb7ddc2172d1c25fcdbf35bf7a` |
| SHA-1 | `4b0d6f1600cecd75f80e6d04b7c980c2211bebe2` |
| SHA-256 | `f1070b7c57a27fd1b464ff8dc435a47b11acd91debdfb85862ae2c1e79797aaf` |
| SHA3-384 | `5acf239486994d8b1e41fdca29614ad59b99555593c3f1e54d7d41ced27bbdc9493191b88f713448afbb32f2098d4cf9` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11C62C7C6D9926FADCE4E80703A12F978BEB03690966659E3D782CC305DA38D04474FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UGVBgn:fKOe2/7c9sN3zfZR1m+RGl6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_f1070b7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1070b7c57a27fd1b464ff8dc435a47b11acd91debdfb85862ae2c1e79797aaf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:59:20"
  condition:
    hash.sha256(0, filesize) == "f1070b7c57a27fd1b464ff8dc435a47b11acd91debdfb85862ae2c1e79797aaf"
}
```

### Sample 93: `800211207647a71f`

| Field | Value |
|---|---|
| SHA-256 | `800211207647a71f3d5284dfa4d793e441ef2d41ec19761a183d0c7cc01b8cfb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:57:18` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfc1afa0b5c6cb3e77cb60086f33e902` |
| SHA-1 | `bcaf17729a33bb2a2a7a30056053d07309574c40` |
| SHA-256 | `800211207647a71f3d5284dfa4d793e441ef2d41ec19761a183d0c7cc01b8cfb` |
| SHA3-384 | `e2b72e8cac63a73a6e0bae01aa2aa35e056611f95cb4cfdc6416e0b5fe7b68b65eedfc25723ddb82c8afc3174c99d35b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15462D886D9E22F6CDE4F90703A51F978BDB07294866599E7E7928C314EA39C04024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UU8Bgn:fKOe2/7c9sN3zfZR1m+RGA6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_80021120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "800211207647a71f3d5284dfa4d793e441ef2d41ec19761a183d0c7cc01b8cfb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:57:18"
  condition:
    hash.sha256(0, filesize) == "800211207647a71f3d5284dfa4d793e441ef2d41ec19761a183d0c7cc01b8cfb"
}
```

### Sample 94: `cb9246830470ad32`

| Field | Value |
|---|---|
| SHA-256 | `cb9246830470ad3202bc80b243f45281722ee89947734b383287d1c7b165d519` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:56:53` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `829dc2841a16e2c2e184bf4143f5a4ae` |
| SHA-1 | `c54642ce8004f637fbf2241e6c8d733da1593296` |
| SHA-256 | `cb9246830470ad3202bc80b243f45281722ee89947734b383287d1c7b165d519` |
| SHA3-384 | `9e995296be5b6c15c6737f9d0d389e646590771272d12ac227adaa3c53e4cfd3d07a632c07d07cd081070ed6bb8480a7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16462D586D8D26E6DCE8E90703B51F938ADB43694CA6659F3D7829C305DA3AD00134FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UfwBgn:fKOe2/7c9sN3zfZR1m+RGEw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_cb924683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb9246830470ad3202bc80b243f45281722ee89947734b383287d1c7b165d519"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:56:53"
  condition:
    hash.sha256(0, filesize) == "cb9246830470ad3202bc80b243f45281722ee89947734b383287d1c7b165d519"
}
```

### Sample 95: `5b809f30156a0154`

| Field | Value |
|---|---|
| SHA-256 | `5b809f30156a01541e06a8964e0057b379795ee9ca4b6b2c8fac6a1aeb3e8fb7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:54:54` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e06103a775dc2320d3417739de9d6ec9` |
| SHA-1 | `8b3463dd521a3d886a71fe63412b3aedf4586dec` |
| SHA-256 | `5b809f30156a01541e06a8964e0057b379795ee9ca4b6b2c8fac6a1aeb3e8fb7` |
| SHA3-384 | `e54a00f4e41dc158383783fd29fd513b1864cb570fff7262202c4d8b4809452944d937857c73add138ba6d6586c70184` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A562D786E8922F5ECE4EA0707A21F8786D747690DA6699E3C7828C345D739D00434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UMBgCc:fKOe2/7c9sN3zfZR1m+RGL6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_5b809f30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b809f30156a01541e06a8964e0057b379795ee9ca4b6b2c8fac6a1aeb3e8fb7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:54:54"
  condition:
    hash.sha256(0, filesize) == "5b809f30156a01541e06a8964e0057b379795ee9ca4b6b2c8fac6a1aeb3e8fb7"
}
```

### Sample 96: `6c35b5b3a7421e01`

| Field | Value |
|---|---|
| SHA-256 | `6c35b5b3a7421e01165543b690ff4d3072407633c0ca1433abe50cf937933d65` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:54:23` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `160fa29951d993185c237bc3095bf998` |
| SHA-1 | `97d8801bb4639af61e5cad3d0b94fe4a08779dcf` |
| SHA-256 | `6c35b5b3a7421e01165543b690ff4d3072407633c0ca1433abe50cf937933d65` |
| SHA3-384 | `50cc97b5281b8a34d128892f4f8afd15f7db25b07cd8d7e98d7b5ee73aaa6339d99e81119e70a1d484486db073eccd05` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C262D69AD8D26F5DCE4E90703A51F878BD7076A4866999E7D7828C315DA38E00034FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UI27iv:fKOe2/7c9sN3zfZR1m+RGcR6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_6c35b5b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c35b5b3a7421e01165543b690ff4d3072407633c0ca1433abe50cf937933d65"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:54:23"
  condition:
    hash.sha256(0, filesize) == "6c35b5b3a7421e01165543b690ff4d3072407633c0ca1433abe50cf937933d65"
}
```

### Sample 97: `82da32e9dedfedb6`

| Field | Value |
|---|---|
| SHA-256 | `82da32e9dedfedb66828f91ed52670491b2c70bdf13fe66fc20e31926e0239c4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:52:12` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79f12379f3cebe6fef485104b828e96a` |
| SHA-1 | `47c5a00a6891a6ab1a31591e9d0efadb44291c75` |
| SHA-256 | `82da32e9dedfedb66828f91ed52670491b2c70bdf13fe66fc20e31926e0239c4` |
| SHA3-384 | `fd95ddfc23b596ed6b95a7e7c78ada03db3bd4522c6361949b4c9f1aa88acb6224dafa9c7ce397f712f561bceec3cbc4` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BE62E697D9A25F6CDE8E80703B15F938AD717294866559E3D7A28C318D639D0003CFF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UdgKAe:fKOe2/7c9sN3zfZR1m+RGgA6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_82da32e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82da32e9dedfedb66828f91ed52670491b2c70bdf13fe66fc20e31926e0239c4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:52:12"
  condition:
    hash.sha256(0, filesize) == "82da32e9dedfedb66828f91ed52670491b2c70bdf13fe66fc20e31926e0239c4"
}
```

### Sample 98: `89bb1636e7cffcac`

| Field | Value |
|---|---|
| SHA-256 | `89bb1636e7cffcac9dcfca82bc537be3a67fc41f48a7dff143375bf85807c6f5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:49:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ced6249a6c226c47279b87a49918ca3` |
| SHA-1 | `8d383a9069077599bb0dad28d0a75225b52d20d3` |
| SHA-256 | `89bb1636e7cffcac9dcfca82bc537be3a67fc41f48a7dff143375bf85807c6f5` |
| SHA3-384 | `cb82f29ffdf29166531309297c43c38d48e3ddecbdc13512f08612c5f98bfa3aea24b82293253e6d8d84742f91e5288c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15D62C78AD8D22F6CCE4F80703A11F878BDB57691896599E3DBC28C385DA39D00524FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZBgCc:fKOe2/7c9sN3zfZR1m+RGG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_89bb1636
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89bb1636e7cffcac9dcfca82bc537be3a67fc41f48a7dff143375bf85807c6f5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:49:36"
  condition:
    hash.sha256(0, filesize) == "89bb1636e7cffcac9dcfca82bc537be3a67fc41f48a7dff143375bf85807c6f5"
}
```

### Sample 99: `9869bba880bd56b4`

| Field | Value |
|---|---|
| SHA-256 | `9869bba880bd56b4980c84cf0082ad14c740c678d464f598a7965290bb79fbdd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-20 02:47:14` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d9331a159498caf77247426e1d3120f` |
| SHA-1 | `993113b4918200cab6e58461426530892264592a` |
| SHA-256 | `9869bba880bd56b4980c84cf0082ad14c740c678d464f598a7965290bb79fbdd` |
| SHA3-384 | `f6335383b6a27ba6f647070cb52ee3ed5959a2550616dcbca6dcd7820f58e0277cdb53a599f6fd9cab445523f52cdca2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EE62C486E8A22F5DDE4E90703F11FC78B9B032D48A6669F3D7928C3059A79C15424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UeBLBM:fKOe2/7c9sN3zfZR1m+RGN96C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_9869bba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9869bba880bd56b4980c84cf0082ad14c740c678d464f598a7965290bb79fbdd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:47:14"
  condition:
    hash.sha256(0, filesize) == "9869bba880bd56b4980c84cf0082ad14c740c678d464f598a7965290bb79fbdd"
}
```

### Sample 100: `3057fa7d5414cd79`

| Field | Value |
|---|---|
| SHA-256 | `3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0` |
| Family label | `ArkeiStealer` |
| File name | `3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0.bin` |
| File type | `exe` |
| First seen | `2026-09-20 02:41:05` |
| Reporter | `threatcat_ch` |
| Tags | `ArkeiStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f67dfd946375a0cc1de799cff89846c1` |
| SHA-1 | `65c1000e6c6954d1fb4803b04e847a4a29801e34` |
| SHA-256 | `3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0` |
| SHA3-384 | `22e538f2550353a548809428ebefd91811b80bb7277ca8b0ed1e3f6a4793316fc5f9ed4fd592dd39e898b20ff7d1ae25` |
| TLSH | `T1F1C5BF50BB40C064D8637F361E3B956849B37DA06930D96F66AE37FE09355A0DE20FB2` |
| SSDEEP | `49152:/aLEUejR42lJBApUSIATv1HBxlvd/5hME/K1hx:/zjR42lzApIAhL/5jI` |

#### Technical Assessment

- The sample is tracked as `ArkeiStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ArkeiStealer_100_3057fa7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0"
    family = "ArkeiStealer"
    file_name = "3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0.bin"
    file_type = "exe"
    first_seen = "2026-09-20 02:41:05"
  condition:
    hash.sha256(0, filesize) == "3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0"
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
 * Generated: 2026-09-20T05:00:23.346224+00:00
 */

rule MalwareBazaar_unknown_001_ac684b36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac684b367907880b90675af8877df984e1409692da3c4613bee2f739142f80d4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:59:04"
  condition:
    hash.sha256(0, filesize) == "ac684b367907880b90675af8877df984e1409692da3c4613bee2f739142f80d4"
}

rule MalwareBazaar_unknown_002_37dd737a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37dd737a342729c7b8c4e6f28140f2ff977a433793482b6bd488efd56a20812e"
    family = "unknown"
    file_name = "stub.x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:58:49"
  condition:
    hash.sha256(0, filesize) == "37dd737a342729c7b8c4e6f28140f2ff977a433793482b6bd488efd56a20812e"
}

rule MalwareBazaar_unknown_003_293c2f2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "293c2f2f95c1c461869cfc2d2ec35cca863e57c491a42bb5f4641ca7a6f3c714"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:58:47"
  condition:
    hash.sha256(0, filesize) == "293c2f2f95c1c461869cfc2d2ec35cca863e57c491a42bb5f4641ca7a6f3c714"
}

rule MalwareBazaar_unknown_004_1940fe1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1940fe1cf809cf319d3593f126f9d087559906b2c033360d38848802fdb232a3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:57:06"
  condition:
    hash.sha256(0, filesize) == "1940fe1cf809cf319d3593f126f9d087559906b2c033360d38848802fdb232a3"
}

rule MalwareBazaar_unknown_005_9797ae89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9797ae898309901b9472c7573afc197861746a9a3eb458fdbf55eca90386d58e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:57:04"
  condition:
    hash.sha256(0, filesize) == "9797ae898309901b9472c7573afc197861746a9a3eb458fdbf55eca90386d58e"
}

rule MalwareBazaar_unknown_006_7ea568be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ea568be7b093e92ab2c36dee8d15b853f80f95a5d672468a8b04fe3904a1316"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:56:04"
  condition:
    hash.sha256(0, filesize) == "7ea568be7b093e92ab2c36dee8d15b853f80f95a5d672468a8b04fe3904a1316"
}

rule MalwareBazaar_unknown_007_441553ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441553ee034e036d625b68c0db9d4b1a95c8d3a8b72d2a8f2b811a674fc50437"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:54:40"
  condition:
    hash.sha256(0, filesize) == "441553ee034e036d625b68c0db9d4b1a95c8d3a8b72d2a8f2b811a674fc50437"
}

rule MalwareBazaar_unknown_008_7215aa8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7215aa8a4f087927f4aed64ecedd3fb32cde6f4fd8d8ccaba189cba21a991127"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:54:32"
  condition:
    hash.sha256(0, filesize) == "7215aa8a4f087927f4aed64ecedd3fb32cde6f4fd8d8ccaba189cba21a991127"
}

rule MalwareBazaar_unknown_009_a6453dc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6453dc9e38769dfc646107760afec331521cb7a72e864b79528b0a853f5bfa6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:53:40"
  condition:
    hash.sha256(0, filesize) == "a6453dc9e38769dfc646107760afec331521cb7a72e864b79528b0a853f5bfa6"
}

rule MalwareBazaar_unknown_010_10b22920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10b229207d857406f2ae137d6bbce07a2990c9757f66866cd23c1d497b05f615"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:53:23"
  condition:
    hash.sha256(0, filesize) == "10b229207d857406f2ae137d6bbce07a2990c9757f66866cd23c1d497b05f615"
}

rule MalwareBazaar_Mirai_011_079dc979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "079dc979877b459a9bf711923a665b772b3a04abecef66b8eabdd2baadc99bce"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:52:48"
  condition:
    hash.sha256(0, filesize) == "079dc979877b459a9bf711923a665b772b3a04abecef66b8eabdd2baadc99bce"
}

rule MalwareBazaar_unknown_012_19addeb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19addeb5117082737612867c086d82ff5a7156e31e8bd9b0996c4f5db4b5e188"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:51:47"
  condition:
    hash.sha256(0, filesize) == "19addeb5117082737612867c086d82ff5a7156e31e8bd9b0996c4f5db4b5e188"
}

rule MalwareBazaar_unknown_013_0a1eeb2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a1eeb2ec0989f2390912feb22cfa7599e6dfd612a9c024dc712ae792c644a46"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:50:58"
  condition:
    hash.sha256(0, filesize) == "0a1eeb2ec0989f2390912feb22cfa7599e6dfd612a9c024dc712ae792c644a46"
}

rule MalwareBazaar_JOMANGY_014_cef9e279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cef9e279df4d3331bba46aaf99e59dd73eb1008047d837905bf5ef8d315bd71c"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:50:49"
  condition:
    hash.sha256(0, filesize) == "cef9e279df4d3331bba46aaf99e59dd73eb1008047d837905bf5ef8d315bd71c"
}

rule MalwareBazaar_Mirai_015_8b8e6486
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b8e64862b0fe3aec19fd8d3c7eb0471109471cf3666a96cb60dfcb3d8e8b90a"
    family = "Mirai"
    file_name = "stub.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:48:50"
  condition:
    hash.sha256(0, filesize) == "8b8e64862b0fe3aec19fd8d3c7eb0471109471cf3666a96cb60dfcb3d8e8b90a"
}

rule MalwareBazaar_Mirai_016_9b8f8579
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b8f8579deddf85f3785fd740fb3f528fc480572129ceea6dad03a371440f775"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-09-20 04:47:00"
  condition:
    hash.sha256(0, filesize) == "9b8f8579deddf85f3785fd740fb3f528fc480572129ceea6dad03a371440f775"
}

rule MalwareBazaar_unknown_017_ac161791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac161791d3313dec24881de34a4a7f62691fc2431d8ac303d0d383afd856c898"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:45:07"
  condition:
    hash.sha256(0, filesize) == "ac161791d3313dec24881de34a4a7f62691fc2431d8ac303d0d383afd856c898"
}

rule MalwareBazaar_JOMANGY_018_26df5233
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26df52334726c54126a662a46d7f4f3749bf66281f7f539451b1d47d3626bb83"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:44:45"
  condition:
    hash.sha256(0, filesize) == "26df52334726c54126a662a46d7f4f3749bf66281f7f539451b1d47d3626bb83"
}

rule MalwareBazaar_unknown_019_75e5fdf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75e5fdf658347ecd148950b30fa8c81d4bfa27344235fe2ea3b1f49dca59e628"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:42:39"
  condition:
    hash.sha256(0, filesize) == "75e5fdf658347ecd148950b30fa8c81d4bfa27344235fe2ea3b1f49dca59e628"
}

rule MalwareBazaar_Mirai_020_5492f960
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5492f9606bf12add8b8414b224e8272b7d422baedbd951e8874a4bda0cb716bc"
    family = "Mirai"
    file_name = "stub.arm"
    file_type = "elf"
    first_seen = "2026-09-20 04:41:00"
  condition:
    hash.sha256(0, filesize) == "5492f9606bf12add8b8414b224e8272b7d422baedbd951e8874a4bda0cb716bc"
}

rule MalwareBazaar_Mirai_021_b7df67b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7df67b510986981958f203da1779124bcc63a10a5769c86a22f5a21a01e079e"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:34:52"
  condition:
    hash.sha256(0, filesize) == "b7df67b510986981958f203da1779124bcc63a10a5769c86a22f5a21a01e079e"
}

rule MalwareBazaar_Mirai_022_80828752
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80828752354b3a770b7c63f46006334fc705c718d40cf3e1df1dc5a4f0fdf043"
    family = "Mirai"
    file_name = "sever1078.x86"
    file_type = "elf"
    first_seen = "2026-09-20 04:34:50"
  condition:
    hash.sha256(0, filesize) == "80828752354b3a770b7c63f46006334fc705c718d40cf3e1df1dc5a4f0fdf043"
}

rule MalwareBazaar_unknown_023_372a6305
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0"
    family = "unknown"
    file_name = "372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0"
    file_type = "elf"
    first_seen = "2026-09-20 04:28:05"
  condition:
    hash.sha256(0, filesize) == "372a630595aa696c55ef6c5673ceb126161f86cd1e791496f5033ed359dca9d0"
}

rule MalwareBazaar_JOMANGY_024_ef144d48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef144d482427726d7bbcfd876ce4c211d9cd828aaf9d7e0ef942620f48562ebc"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:26:52"
  condition:
    hash.sha256(0, filesize) == "ef144d482427726d7bbcfd876ce4c211d9cd828aaf9d7e0ef942620f48562ebc"
}

rule MalwareBazaar_Mirai_025_28423d65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885"
    family = "Mirai"
    file_name = "Space.mpsl"
    file_type = "elf"
    first_seen = "2026-09-20 04:26:51"
  condition:
    hash.sha256(0, filesize) == "28423d6534cdb6b87d6e713930926c82ce4e19f9018647809bbebc1b7be27885"
}

rule MalwareBazaar_unknown_026_4e3fe31a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e3fe31a8f5872ab5a1a7b23eb352b2061c5009989b95f0a86513eb5f956985f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:25:52"
  condition:
    hash.sha256(0, filesize) == "4e3fe31a8f5872ab5a1a7b23eb352b2061c5009989b95f0a86513eb5f956985f"
}

rule MalwareBazaar_unknown_027_b9ef2d25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ef2d25881aa827451c4b19ca4872c122a295ceed28875a26bbd928f5de2b3c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:23:10"
  condition:
    hash.sha256(0, filesize) == "b9ef2d25881aa827451c4b19ca4872c122a295ceed28875a26bbd928f5de2b3c"
}

rule MalwareBazaar_unknown_028_10fc711e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10fc711e05e104ea34f6c55cc592b8e947d9f68e8c64f2a4b8b225c12073f9fb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:20:34"
  condition:
    hash.sha256(0, filesize) == "10fc711e05e104ea34f6c55cc592b8e947d9f68e8c64f2a4b8b225c12073f9fb"
}

rule MalwareBazaar_unknown_029_4e2f0e58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e2f0e58ec5a9f6f3d0a0fd6b496afdd2df1f38d053c38df682c898226154425"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:46"
  condition:
    hash.sha256(0, filesize) == "4e2f0e58ec5a9f6f3d0a0fd6b496afdd2df1f38d053c38df682c898226154425"
}

rule MalwareBazaar_unknown_030_b042caa7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b042caa730d5d29cf55e7c1c570ae1a830f0b1bca3edbb8778f994a674e70deb"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:44"
  condition:
    hash.sha256(0, filesize) == "b042caa730d5d29cf55e7c1c570ae1a830f0b1bca3edbb8778f994a674e70deb"
}

rule MalwareBazaar_unknown_031_5964f962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5964f962d96b459ed59ac7fc1970703e2242b1919130c2162925cc8d6cf1be26"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:41"
  condition:
    hash.sha256(0, filesize) == "5964f962d96b459ed59ac7fc1970703e2242b1919130c2162925cc8d6cf1be26"
}

rule MalwareBazaar_Mirai_032_e3912908
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e39129081ae5922a28ee9ab9ea17fe150675c2c3d1d308faf9f4185954624497"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:39"
  condition:
    hash.sha256(0, filesize) == "e39129081ae5922a28ee9ab9ea17fe150675c2c3d1d308faf9f4185954624497"
}

rule MalwareBazaar_unknown_033_e93daebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e93daebf9b1e5904551afa93f3ae39ee3685f6cac471ac103a0eb83474e2483f"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:37"
  condition:
    hash.sha256(0, filesize) == "e93daebf9b1e5904551afa93f3ae39ee3685f6cac471ac103a0eb83474e2483f"
}

rule MalwareBazaar_unknown_034_e9d97a3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9d97a3d8724986bbf4494d1e01ace52ea60e0ea50c0e97385ab3a2f743cdc03"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:35"
  condition:
    hash.sha256(0, filesize) == "e9d97a3d8724986bbf4494d1e01ace52ea60e0ea50c0e97385ab3a2f743cdc03"
}

rule MalwareBazaar_unknown_035_09e4e968
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09e4e96872385a0296efe00cfaa02e0d0d46b0c71855345f39cc2dfeabb8c75a"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:32"
  condition:
    hash.sha256(0, filesize) == "09e4e96872385a0296efe00cfaa02e0d0d46b0c71855345f39cc2dfeabb8c75a"
}

rule MalwareBazaar_unknown_036_c5533697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5533697f6cb0a84f7a48af7bbd26a2ae9f9e24988e74cfea072dd65e7597d63"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-20 04:19:30"
  condition:
    hash.sha256(0, filesize) == "c5533697f6cb0a84f7a48af7bbd26a2ae9f9e24988e74cfea072dd65e7597d63"
}

rule MalwareBazaar_unknown_037_257d2595
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "257d2595b2e97b286d3f52ebee2bc9054333571014f8565aeac6d7f2df9d2b89"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:19:23"
  condition:
    hash.sha256(0, filesize) == "257d2595b2e97b286d3f52ebee2bc9054333571014f8565aeac6d7f2df9d2b89"
}

rule MalwareBazaar_unknown_038_ad5ed7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad5ed7ce8dc5462e06fafa676d4217960952df10cda43be89fddd3c4b7486c39"
    family = "unknown"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:57"
  condition:
    hash.sha256(0, filesize) == "ad5ed7ce8dc5462e06fafa676d4217960952df10cda43be89fddd3c4b7486c39"
}

rule MalwareBazaar_unknown_039_db76f64a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db76f64a2ab9133ae0dcea6e447b843cd24f64ba35c7f8c51738591be7000e50"
    family = "unknown"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:55"
  condition:
    hash.sha256(0, filesize) == "db76f64a2ab9133ae0dcea6e447b843cd24f64ba35c7f8c51738591be7000e50"
}

rule MalwareBazaar_unknown_040_c627d9b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c627d9b192be3d9c75f4f65d361f3f1c01ea2f7f465d4d40e5d3db01d6004f27"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:54"
  condition:
    hash.sha256(0, filesize) == "c627d9b192be3d9c75f4f65d361f3f1c01ea2f7f465d4d40e5d3db01d6004f27"
}

rule MalwareBazaar_Mirai_041_7de77a15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2"
    family = "Mirai"
    file_name = "Space.sh4"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:53"
  condition:
    hash.sha256(0, filesize) == "7de77a1518419efae53b6b3163335ee842a5f0f8d6bd959b4488181ca4a8b7c2"
}

rule MalwareBazaar_unknown_042_119334fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "119334fc9aa05c272da7e1b9ca1a215a22a578d339137cc90886bf1a1bfe51ff"
    family = "unknown"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:51"
  condition:
    hash.sha256(0, filesize) == "119334fc9aa05c272da7e1b9ca1a215a22a578d339137cc90886bf1a1bfe51ff"
}

rule MalwareBazaar_unknown_043_a662f5e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a662f5e5879edcb32efb513eb84b9b83567459287ed475af1083874c04eb2834"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:50"
  condition:
    hash.sha256(0, filesize) == "a662f5e5879edcb32efb513eb84b9b83567459287ed475af1083874c04eb2834"
}

rule MalwareBazaar_Mirai_044_704c6407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c"
    family = "Mirai"
    file_name = "Space.i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:49"
  condition:
    hash.sha256(0, filesize) == "704c64073e98b5a92fb6f41293374ef2b91ed12065b66b50c954959671687e8c"
}

rule MalwareBazaar_unknown_045_edca6488
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edca648878da699457d345b19412036b6623c75f13d5fa5e59ac77c957bc06a1"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:48"
  condition:
    hash.sha256(0, filesize) == "edca648878da699457d345b19412036b6623c75f13d5fa5e59ac77c957bc06a1"
}

rule MalwareBazaar_unknown_046_ca05d5c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca05d5c61cff1ffb32c1b4f8bb5227320f90d4cc36c2b05e406350f5071531a9"
    family = "unknown"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:47"
  condition:
    hash.sha256(0, filesize) == "ca05d5c61cff1ffb32c1b4f8bb5227320f90d4cc36c2b05e406350f5071531a9"
}

rule MalwareBazaar_unknown_047_b1199801
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b11998016b3dff6845cdd7f9c6b7c08a9e02c38327e84b98b7be04cbc7e1ac08"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:46"
  condition:
    hash.sha256(0, filesize) == "b11998016b3dff6845cdd7f9c6b7c08a9e02c38327e84b98b7be04cbc7e1ac08"
}

rule MalwareBazaar_unknown_048_3e1b90cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1b90ccb649b66a0c30fa535e5380f3cf182a3b5e75533afda91f69a6218f7f"
    family = "unknown"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:44"
  condition:
    hash.sha256(0, filesize) == "3e1b90ccb649b66a0c30fa535e5380f3cf182a3b5e75533afda91f69a6218f7f"
}

rule MalwareBazaar_unknown_049_40f09e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40f09e69d334c5b951edb85ffe8b81e03ab4ff7db5d408add95aadc35b70bf13"
    family = "unknown"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:42"
  condition:
    hash.sha256(0, filesize) == "40f09e69d334c5b951edb85ffe8b81e03ab4ff7db5d408add95aadc35b70bf13"
}

rule MalwareBazaar_unknown_050_a039db61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a039db61b06d137895143157fd05718e9603bd9c1470fac58856972c1064515a"
    family = "unknown"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:41"
  condition:
    hash.sha256(0, filesize) == "a039db61b06d137895143157fd05718e9603bd9c1470fac58856972c1064515a"
}

rule MalwareBazaar_unknown_051_c3f4b883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3f4b8833424d58313c09bfe519126396cef6a49746fc8630dfa667ea82a77c5"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-20 04:18:39"
  condition:
    hash.sha256(0, filesize) == "c3f4b8833424d58313c09bfe519126396cef6a49746fc8630dfa667ea82a77c5"
}

rule MalwareBazaar_unknown_052_294aea20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f"
    family = "unknown"
    file_name = "294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f"
    file_type = "elf"
    first_seen = "2026-09-20 04:17:23"
  condition:
    hash.sha256(0, filesize) == "294aea20f003b4a593586cb755046d31c56697b0ddcf4a970bade8cf938f8f3f"
}

rule MalwareBazaar_unknown_053_b9a4e654
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a"
    family = "unknown"
    file_name = "b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a"
    file_type = "elf"
    first_seen = "2026-09-20 04:17:17"
  condition:
    hash.sha256(0, filesize) == "b9a4e65437f0487dd11d0b4e94cfb5014a4b6394d819d42228b89496f484337a"
}

rule MalwareBazaar_unknown_054_fba09a4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf"
    family = "unknown"
    file_name = "fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf"
    file_type = "elf"
    first_seen = "2026-09-20 04:17:12"
  condition:
    hash.sha256(0, filesize) == "fba09a4c474ac69d54e29b78142a733118d5312b880427b98e39ae65c79f9acf"
}

rule MalwareBazaar_unknown_055_41fc899b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41fc899b52387d2174f728a19be218d282685843458de274874d23276d07c042"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:16:57"
  condition:
    hash.sha256(0, filesize) == "41fc899b52387d2174f728a19be218d282685843458de274874d23276d07c042"
}

rule MalwareBazaar_unknown_056_4b52da2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b52da2e4339de59ff15b1a8cf6e6754ec8e4aecc213f3baaefac06754201794"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:14:31"
  condition:
    hash.sha256(0, filesize) == "4b52da2e4339de59ff15b1a8cf6e6754ec8e4aecc213f3baaefac06754201794"
}

rule MalwareBazaar_Mirai_057_53947abf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53947abf12814f52230fc93d614bbd211957c8675ae99a1e0ba43393cbaec11c"
    family = "Mirai"
    file_name = "sever1078.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:13:21"
  condition:
    hash.sha256(0, filesize) == "53947abf12814f52230fc93d614bbd211957c8675ae99a1e0ba43393cbaec11c"
}

rule MalwareBazaar_Mirai_058_e65a3387
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e65a3387fe886951238a8db1bba23a51bd41b917bcc6cb936232519018d622a3"
    family = "Mirai"
    file_name = "sever1078.mips"
    file_type = "elf"
    first_seen = "2026-09-20 04:12:36"
  condition:
    hash.sha256(0, filesize) == "e65a3387fe886951238a8db1bba23a51bd41b917bcc6cb936232519018d622a3"
}

rule MalwareBazaar_JOMANGY_059_6d376ed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d376ed261b8487976577a91f632a922c21166cc42739f0c273a678fec3fee02"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-20 04:12:34"
  condition:
    hash.sha256(0, filesize) == "6d376ed261b8487976577a91f632a922c21166cc42739f0c273a678fec3fee02"
}

rule MalwareBazaar_unknown_060_fce8a8ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fce8a8eafa41aad0cdcd9e27d180523f67baf642808a799cfdb37883b699dae2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:06:34"
  condition:
    hash.sha256(0, filesize) == "fce8a8eafa41aad0cdcd9e27d180523f67baf642808a799cfdb37883b699dae2"
}

rule MalwareBazaar_unknown_061_ba2b9154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba2b9154c7dba98602de83bdb0d7463015dc4a26b1f2ba3008ed4ddce72b159f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:05:16"
  condition:
    hash.sha256(0, filesize) == "ba2b9154c7dba98602de83bdb0d7463015dc4a26b1f2ba3008ed4ddce72b159f"
}

rule MalwareBazaar_unknown_062_e1254727
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1254727c72df075472bdfd39fe45599c260355710d1e631adc3be4325408247"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:04:06"
  condition:
    hash.sha256(0, filesize) == "e1254727c72df075472bdfd39fe45599c260355710d1e631adc3be4325408247"
}

rule MalwareBazaar_unknown_063_14aea34b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14aea34b2ce37e3c57dcf070f856677b7ab41b8b6500d29121fe377abdff5014"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:03:13"
  condition:
    hash.sha256(0, filesize) == "14aea34b2ce37e3c57dcf070f856677b7ab41b8b6500d29121fe377abdff5014"
}

rule MalwareBazaar_unknown_064_9f002919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f002919c655b2ebfce070fcf572a8454d7bfea4893084362119ac5d0fb9b350"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:02:44"
  condition:
    hash.sha256(0, filesize) == "9f002919c655b2ebfce070fcf572a8454d7bfea4893084362119ac5d0fb9b350"
}

rule MalwareBazaar_Snowlight_065_3260d5dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0"
    family = "Snowlight"
    file_name = "3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0.elf"
    file_type = "elf"
    first_seen = "2026-09-20 04:02:35"
  condition:
    hash.sha256(0, filesize) == "3260d5dd17bfb3258ad8a7f0b45a45f7704b1572f8710d91b9a503ea7fdc94a0"
}

rule MalwareBazaar_unknown_066_ceaf5f49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceaf5f499997eaa890d3ea872f0a526f4f15a34f306b8aa4b409f56a08473170"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:01:37"
  condition:
    hash.sha256(0, filesize) == "ceaf5f499997eaa890d3ea872f0a526f4f15a34f306b8aa4b409f56a08473170"
}

rule MalwareBazaar_unknown_067_6ff5ecc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ff5ecc509b1f11c19b495b42fabacfb87d62f64d68b8311465c82fee8fc88a8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:00:47"
  condition:
    hash.sha256(0, filesize) == "6ff5ecc509b1f11c19b495b42fabacfb87d62f64d68b8311465c82fee8fc88a8"
}

rule MalwareBazaar_unknown_068_5b208b50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b208b50a81020b3011b03ab18a163f193114b7c537cedf204e17c9ce7f0dcc6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 04:00:19"
  condition:
    hash.sha256(0, filesize) == "5b208b50a81020b3011b03ab18a163f193114b7c537cedf204e17c9ce7f0dcc6"
}

rule MalwareBazaar_Mirai_069_e974913b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e974913b60253b954569dbffc87c22471700eaeb5364a2eeebf2139073189c27"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-20 03:59:14"
  condition:
    hash.sha256(0, filesize) == "e974913b60253b954569dbffc87c22471700eaeb5364a2eeebf2139073189c27"
}

rule MalwareBazaar_Mirai_070_aa85be63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-20 03:58:37"
  condition:
    hash.sha256(0, filesize) == "aa85be63909ee5345ed04d0c6362b70a669d862d38f96079df0dc0359d00dd42"
}

rule MalwareBazaar_unknown_071_fd6ba3e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6ba3e910f9e17d9848fbc7f214e827da40e6416f9e26bd3aece320c981b63b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:58:29"
  condition:
    hash.sha256(0, filesize) == "fd6ba3e910f9e17d9848fbc7f214e827da40e6416f9e26bd3aece320c981b63b"
}

rule MalwareBazaar_unknown_072_75f21443
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3"
    family = "unknown"
    file_name = "75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3"
    file_type = "elf"
    first_seen = "2026-09-20 03:56:18"
  condition:
    hash.sha256(0, filesize) == "75f214437ecc0450437d2925a3e884a994b2083f0524a1a819b92ac58139aae3"
}

rule MalwareBazaar_unknown_073_897ea7b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542"
    family = "unknown"
    file_name = "897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542"
    file_type = "elf"
    first_seen = "2026-09-20 03:56:11"
  condition:
    hash.sha256(0, filesize) == "897ea7b1ff1c13db7f2e05b9463b7d516893add639bfe7cb12226608df95a542"
}

rule MalwareBazaar_unknown_074_46661ea8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46661ea89330de9355c49446ebaf618a6cfdb0907ab0c838af9cd1dde9dbb8d1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:53:02"
  condition:
    hash.sha256(0, filesize) == "46661ea89330de9355c49446ebaf618a6cfdb0907ab0c838af9cd1dde9dbb8d1"
}

rule MalwareBazaar_Mirai_075_b793206d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b793206d6e320eec11d3decf493fc77776e3635df45dbd4abc95fad910db6482"
    family = "Mirai"
    file_name = "sever1078.sh4"
    file_type = "elf"
    first_seen = "2026-09-20 03:30:38"
  condition:
    hash.sha256(0, filesize) == "b793206d6e320eec11d3decf493fc77776e3635df45dbd4abc95fad910db6482"
}

rule MalwareBazaar_unknown_076_a44a890b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a44a890b1de4581c44c02b0e522d6973ca312212758d9fc2e93095b3f5e8a65f"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-20 03:27:59"
  condition:
    hash.sha256(0, filesize) == "a44a890b1de4581c44c02b0e522d6973ca312212758d9fc2e93095b3f5e8a65f"
}

rule MalwareBazaar_unknown_077_75af5c03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75af5c0339a7400b895363e69fa95110e8749c06829455c8ca47ac578f27c8a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:27:18"
  condition:
    hash.sha256(0, filesize) == "75af5c0339a7400b895363e69fa95110e8749c06829455c8ca47ac578f27c8a6"
}

rule MalwareBazaar_unknown_078_889a1c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889a1c70607da1da95e1219809f8f2f8f1a9bd2c5034cf780a730d1983f05e22"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:25:50"
  condition:
    hash.sha256(0, filesize) == "889a1c70607da1da95e1219809f8f2f8f1a9bd2c5034cf780a730d1983f05e22"
}

rule MalwareBazaar_unknown_079_3d6e0850
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d6e08501f6a09d17cc5ead37d1b9392e4177bb164bb6188df8c8922336d9d97"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:22:24"
  condition:
    hash.sha256(0, filesize) == "3d6e08501f6a09d17cc5ead37d1b9392e4177bb164bb6188df8c8922336d9d97"
}

rule MalwareBazaar_ArkeiStealer_080_2db2be88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad"
    family = "ArkeiStealer"
    file_name = "2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad.bin"
    file_type = "exe"
    first_seen = "2026-09-20 03:21:30"
  condition:
    hash.sha256(0, filesize) == "2db2be8826006de75eaf915636bd9c699d028849478558c49cb840dba75880ad"
}

rule MalwareBazaar_unknown_081_bc5182c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc5182c5be1a0ae2adf64d0ef9ccb19de85ffee81e11baf6795fab6cd5f3c0f6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:21:05"
  condition:
    hash.sha256(0, filesize) == "bc5182c5be1a0ae2adf64d0ef9ccb19de85ffee81e11baf6795fab6cd5f3c0f6"
}

rule MalwareBazaar_unknown_082_eb15ea88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb15ea88be64574b42ecb12a7fd87cf90b625202f3610451e15fbb633727160d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:18:37"
  condition:
    hash.sha256(0, filesize) == "eb15ea88be64574b42ecb12a7fd87cf90b625202f3610451e15fbb633727160d"
}

rule MalwareBazaar_unknown_083_5096417a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6"
    family = "unknown"
    file_name = "5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6"
    file_type = "elf"
    first_seen = "2026-09-20 03:17:46"
  condition:
    hash.sha256(0, filesize) == "5096417a65e07c38bd3f024a00e93ce13808936f6fd5e7b1c2874582089ffba6"
}

rule MalwareBazaar_Mirai_084_f711b96a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74"
    family = "Mirai"
    file_name = "f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74"
    file_type = "elf"
    first_seen = "2026-09-20 03:17:40"
  condition:
    hash.sha256(0, filesize) == "f711b96af05ce7c3bfe9ee466799239a7a326468c2771a8882695259893aef74"
}

rule MalwareBazaar_unknown_085_aba01e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba01e0cbe4d4d41be6149ad916cd141cc68dddb5746b163ce4055d5b56ab3a1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:16:12"
  condition:
    hash.sha256(0, filesize) == "aba01e0cbe4d4d41be6149ad916cd141cc68dddb5746b163ce4055d5b56ab3a1"
}

rule MalwareBazaar_ConnectWise_086_3151064d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3151064dc1450bd1ff6dfc40fb453371836f9f774026faad389a474141f4e2cf"
    family = "ConnectWise"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 03:12:52"
  condition:
    hash.sha256(0, filesize) == "3151064dc1450bd1ff6dfc40fb453371836f9f774026faad389a474141f4e2cf"
}

rule MalwareBazaar_Mirai_087_01e25166
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01e251668e4913f44d838c7373f5f57596a57cf66f72c84c4f7be38f0abbe949"
    family = "Mirai"
    file_name = "sever1078.arm7"
    file_type = "elf"
    first_seen = "2026-09-20 03:03:22"
  condition:
    hash.sha256(0, filesize) == "01e251668e4913f44d838c7373f5f57596a57cf66f72c84c4f7be38f0abbe949"
}

rule MalwareBazaar_Mirai_088_c034e24c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c034e24c7e9ed3926e523998f2f8f485262b15c8a56b802bee1c48a6f2a48630"
    family = "Mirai"
    file_name = "sever1078.arm7"
    file_type = "elf"
    first_seen = "2026-09-20 03:02:36"
  condition:
    hash.sha256(0, filesize) == "c034e24c7e9ed3926e523998f2f8f485262b15c8a56b802bee1c48a6f2a48630"
}

rule MalwareBazaar_VShell_089_639d4938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032"
    family = "VShell"
    file_name = "639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032.exe"
    file_type = "exe"
    first_seen = "2026-09-20 03:02:27"
  condition:
    hash.sha256(0, filesize) == "639d4938aafeec8eafa76c3fe4cd01734a2f6f9b8d207cf51534ffd8ed246032"
}

rule MalwareBazaar_VShell_090_7fd73a46
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7"
    family = "VShell"
    file_name = "7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7.exe"
    file_type = "exe"
    first_seen = "2026-09-20 03:02:22"
  condition:
    hash.sha256(0, filesize) == "7fd73a46a635050e31c3a1333d7a95e77cdb54a45164071a6eb04ddf88ad54b7"
}

rule MalwareBazaar_unknown_091_a77c480d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a77c480d56157cdeeb8cad6e642c30cdf320d1744e4117e7aa98181e59d85a5e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:59:45"
  condition:
    hash.sha256(0, filesize) == "a77c480d56157cdeeb8cad6e642c30cdf320d1744e4117e7aa98181e59d85a5e"
}

rule MalwareBazaar_unknown_092_f1070b7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1070b7c57a27fd1b464ff8dc435a47b11acd91debdfb85862ae2c1e79797aaf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:59:20"
  condition:
    hash.sha256(0, filesize) == "f1070b7c57a27fd1b464ff8dc435a47b11acd91debdfb85862ae2c1e79797aaf"
}

rule MalwareBazaar_unknown_093_80021120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "800211207647a71f3d5284dfa4d793e441ef2d41ec19761a183d0c7cc01b8cfb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:57:18"
  condition:
    hash.sha256(0, filesize) == "800211207647a71f3d5284dfa4d793e441ef2d41ec19761a183d0c7cc01b8cfb"
}

rule MalwareBazaar_unknown_094_cb924683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb9246830470ad3202bc80b243f45281722ee89947734b383287d1c7b165d519"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:56:53"
  condition:
    hash.sha256(0, filesize) == "cb9246830470ad3202bc80b243f45281722ee89947734b383287d1c7b165d519"
}

rule MalwareBazaar_unknown_095_5b809f30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b809f30156a01541e06a8964e0057b379795ee9ca4b6b2c8fac6a1aeb3e8fb7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:54:54"
  condition:
    hash.sha256(0, filesize) == "5b809f30156a01541e06a8964e0057b379795ee9ca4b6b2c8fac6a1aeb3e8fb7"
}

rule MalwareBazaar_unknown_096_6c35b5b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c35b5b3a7421e01165543b690ff4d3072407633c0ca1433abe50cf937933d65"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:54:23"
  condition:
    hash.sha256(0, filesize) == "6c35b5b3a7421e01165543b690ff4d3072407633c0ca1433abe50cf937933d65"
}

rule MalwareBazaar_unknown_097_82da32e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82da32e9dedfedb66828f91ed52670491b2c70bdf13fe66fc20e31926e0239c4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:52:12"
  condition:
    hash.sha256(0, filesize) == "82da32e9dedfedb66828f91ed52670491b2c70bdf13fe66fc20e31926e0239c4"
}

rule MalwareBazaar_unknown_098_89bb1636
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89bb1636e7cffcac9dcfca82bc537be3a67fc41f48a7dff143375bf85807c6f5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:49:36"
  condition:
    hash.sha256(0, filesize) == "89bb1636e7cffcac9dcfca82bc537be3a67fc41f48a7dff143375bf85807c6f5"
}

rule MalwareBazaar_unknown_099_9869bba8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9869bba880bd56b4980c84cf0082ad14c740c678d464f598a7965290bb79fbdd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-20 02:47:14"
  condition:
    hash.sha256(0, filesize) == "9869bba880bd56b4980c84cf0082ad14c740c678d464f598a7965290bb79fbdd"
}

rule MalwareBazaar_ArkeiStealer_100_3057fa7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0"
    family = "ArkeiStealer"
    file_name = "3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0.bin"
    file_type = "exe"
    first_seen = "2026-09-20 02:41:05"
  condition:
    hash.sha256(0, filesize) == "3057fa7d5414cd79f6551bd975ba143d15fefdfc75606f09ac49fe5193ec1cd0"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

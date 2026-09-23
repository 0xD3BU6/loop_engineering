# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-23

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 663 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 663 |
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 61 |
| Mirai | 33 |
| Prometei | 2 |
| SilentNet | 1 |
| Mozi | 1 |
| WannaCry | 1 |
| NetSupport | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 43 |
| elf | 42 |
| macho | 7 |
| ps1 | 3 |
| gz | 2 |
| zip | 1 |
| apk | 1 |
| unknown | 1 |

## Per-Sample Analysis

### Sample 1: `932918ca4a481fff`

| Field | Value |
|---|---|
| SHA-256 | `932918ca4a481fffad2c2d4d84a9efa587c6f7bf15e2db5d06cccb8b91952c24` |
| Family label | `unknown` |
| File name | `qzxuuppn.mpsl` |
| File type | `elf` |
| First seen | `2026-09-23 04:50:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b8a1004e0fb785c21163ead5cc05024` |
| SHA-1 | `f4a25af08f780e2b6503e3c800b620e56066b855` |
| SHA-256 | `932918ca4a481fffad2c2d4d84a9efa587c6f7bf15e2db5d06cccb8b91952c24` |
| SHA3-384 | `7f5d9d178aa38ab564de5419901c1fda48e21753c7bd946180939f216d1cf4a64f24c8693d8e46f82fc4b80125b21d35` |
| TLSH | `T183356C03BF445FEBC4AFCE34892EC35700DDE88652C5A63D71BC8A9CBA597464AC3588` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:cfRtwU6Z5zcVk4iVpIMDcPH0Sf2pHLbz1zLqxwHnKWk:wTw9hZh/vw0gWHZqxwHg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_932918ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932918ca4a481fffad2c2d4d84a9efa587c6f7bf15e2db5d06cccb8b91952c24"
    family = "unknown"
    file_name = "qzxuuppn.mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 04:50:49"
  condition:
    hash.sha256(0, filesize) == "932918ca4a481fffad2c2d4d84a9efa587c6f7bf15e2db5d06cccb8b91952c24"
}
```

### Sample 2: `d6b7c2d71ece0167`

| Field | Value |
|---|---|
| SHA-256 | `d6b7c2d71ece0167cbbd7890dbe6586b11791336daef469ad5cec96851ce4977` |
| Family label | `unknown` |
| File name | `armv6` |
| File type | `elf` |
| First seen | `2026-09-23 04:48:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41daf9b013370b01e8d146655c75a564` |
| SHA-1 | `ce9a4308ad1ab8ae84c420fad6b61f2f5f1a2eb4` |
| SHA-256 | `d6b7c2d71ece0167cbbd7890dbe6586b11791336daef469ad5cec96851ce4977` |
| SHA3-384 | `14e5a0ffdb8a4ed99854a406d2efe700e99eec67017dbd65c01d930708450f13a7eca69970e3cd3727399c59cf8739f3` |
| TLSH | `T1E2143B51BA908F13C2DA177DBAAF478837328724F3DB73079C1876782E8675E4E6A501` |
| TELFHASH | `t15c211e8c593d0a096a633574dc9c27b0e50a8862ad764f21cf28c790156e06a920ee7f` |
| SSDEEP | `3072:4o86UBNX5o0Ltu7jnCqWKEb42c96vpiGCxKen7h1+yhn9e9368O:4o86cuPnCWEb42cYkGC4eD9hn9e9q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_d6b7c2d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6b7c2d71ece0167cbbd7890dbe6586b11791336daef469ad5cec96851ce4977"
    family = "unknown"
    file_name = "armv6"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:51"
  condition:
    hash.sha256(0, filesize) == "d6b7c2d71ece0167cbbd7890dbe6586b11791336daef469ad5cec96851ce4977"
}
```

### Sample 3: `90a7cd85a4510a5e`

| Field | Value |
|---|---|
| SHA-256 | `90a7cd85a4510a5e91b4aa521fe676e349ff4ae87625654f1479902dcb8dfd82` |
| Family label | `Mirai` |
| File name | `atjozltp.aarch64` |
| File type | `elf` |
| First seen | `2026-09-23 04:48:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99eff4dd7be6e15b4c10d861c3bfe288` |
| SHA-1 | `2cfe9638f0dc3243164f90065b4361daec86f9aa` |
| SHA-256 | `90a7cd85a4510a5e91b4aa521fe676e349ff4ae87625654f1479902dcb8dfd82` |
| SHA3-384 | `32673089be7f2beb88ea83105eaf2fc311f9df6b2cb27892b9710015d6f1d42d84dc2ffb5c352e8f6be703f6603c212c` |
| TLSH | `T16B356B5DFD4F3C47C2C6F23DEB4A83B47127B094C62711A625C2034DE6C9D998BA299E` |
| TELFHASH | `t149a012020880810c0177ab114c95034910414833e81a3d551e0cda400410008034886a` |
| SSDEEP | `24576:T/ayrWrLsvealLBmptgJgiOJef6J4Zk8qhyY:jRBmOB6cdOO6J4Zk2Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_90a7cd85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90a7cd85a4510a5e91b4aa521fe676e349ff4ae87625654f1479902dcb8dfd82"
    family = "Mirai"
    file_name = "atjozltp.aarch64"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:49"
  condition:
    hash.sha256(0, filesize) == "90a7cd85a4510a5e91b4aa521fe676e349ff4ae87625654f1479902dcb8dfd82"
}
```

### Sample 4: `0b76c8658b63d3fa`

| Field | Value |
|---|---|
| SHA-256 | `0b76c8658b63d3fadf501f94730e0938fd6bc31e72fd49a835073de230da494e` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-23 04:48:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c287b997c31c180adb8309b3c61f5005` |
| SHA-1 | `458cb01b00664093859835b525979cf17dce9d64` |
| SHA-256 | `0b76c8658b63d3fadf501f94730e0938fd6bc31e72fd49a835073de230da494e` |
| SHA3-384 | `618569aab0f4d04cf45eb6dc31cc7b8afbe54b2ce60c9157efc000b35c62affe02e762bcd7e72be5636b82a39d8ffb77` |
| TLSH | `T18063611ABF610EB7EC2BDD3B45A81B0525CC651B21A93F757A34D818BA1B20F45E3CB4` |
| SSDEEP | `1536:BA0H4H2PX0DUErCDb0U5gg2akBMi+nZuEqspMtg:BA24He00DoUBi+n+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_0b76c865
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b76c8658b63d3fadf501f94730e0938fd6bc31e72fd49a835073de230da494e"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:47"
  condition:
    hash.sha256(0, filesize) == "0b76c8658b63d3fadf501f94730e0938fd6bc31e72fd49a835073de230da494e"
}
```

### Sample 5: `4b5ded8502bb4105`

| Field | Value |
|---|---|
| SHA-256 | `4b5ded8502bb410554855b99607cf2eb98398633c1fb57c98e41b2980abbe7fd` |
| Family label | `Mirai` |
| File name | `atjozltp.mips` |
| File type | `elf` |
| First seen | `2026-09-23 04:48:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3a94c8fe2f5d6cc94228c5c54121376` |
| SHA-1 | `7a7a880747390958cf6ba273b72c80328280d89f` |
| SHA-256 | `4b5ded8502bb410554855b99607cf2eb98398633c1fb57c98e41b2980abbe7fd` |
| SHA3-384 | `6bedfcf4ca54e7a926105c4963a7156b3be95fbbe19f8e46dd3538269803a75fd03f29777c4911eb5937d28741de5c07` |
| TLSH | `T18F356B633721CF65E354C27005F3CBA1AAD524A31BE24096B36CC3287A6166D6D6FFE4` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:XZqfyiPByME4VTQs8WoeZE5JeiHaSIq1FqxwHnKWki:XZq7Zyd4VTQs8WotraPqTqxwHgi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_4b5ded85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b5ded8502bb410554855b99607cf2eb98398633c1fb57c98e41b2980abbe7fd"
    family = "Mirai"
    file_name = "atjozltp.mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:46"
  condition:
    hash.sha256(0, filesize) == "4b5ded8502bb410554855b99607cf2eb98398633c1fb57c98e41b2980abbe7fd"
}
```

### Sample 6: `732e14f0a44613fb`

| Field | Value |
|---|---|
| SHA-256 | `732e14f0a44613fbfd90cd4958a1d2171970b52adf283416f044fbea4957c460` |
| Family label | `Mirai` |
| File name | `tpijtvcr.armv7l` |
| File type | `elf` |
| First seen | `2026-09-23 04:48:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `195aaf028538ba0e067157dfd6b5ae47` |
| SHA-1 | `9f8b9955ea7b418c5974d122e8835a55dc2bfab5` |
| SHA-256 | `732e14f0a44613fbfd90cd4958a1d2171970b52adf283416f044fbea4957c460` |
| SHA3-384 | `16ff3ab09e17ee758abac571990eb34c4abbaeed0c4cba74627dbd35ef8087a3f701ad2069c251a1243a9dfbf1df17ae` |
| TLSH | `T172153A55F8C09F62C5D5657AF65E82A83323477CC2E6F30689148B383B978AF4B3A741` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:oqCM+fFixtr2kOFjb0Fr0kbv3T6k2fknuQ6J:bBx/46fT6k2fkOJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_732e14f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "732e14f0a44613fbfd90cd4958a1d2171970b52adf283416f044fbea4957c460"
    family = "Mirai"
    file_name = "tpijtvcr.armv7l"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:44"
  condition:
    hash.sha256(0, filesize) == "732e14f0a44613fbfd90cd4958a1d2171970b52adf283416f044fbea4957c460"
}
```

### Sample 7: `89611739301b0f21`

| Field | Value |
|---|---|
| SHA-256 | `89611739301b0f2198c031d778988d4e38b11b29558a8187fa86517a146c42dc` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-09-23 04:44:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `836d8f5b6d3867e6f2ce27f4e03273c8` |
| SHA-1 | `489add79b45ed000644345abe2927f81c43e73bb` |
| SHA-256 | `89611739301b0f2198c031d778988d4e38b11b29558a8187fa86517a146c42dc` |
| SHA3-384 | `1da693e10063cc6c7854dbf5322e053535608b2f75c7d389386c30d57e0ae74d4069025b5503a4c94839b6293ad7908c` |
| TLSH | `T11754F809FB8DDE8BC05183B54DAB0B237335D8A93346D7936719A53EECAB34C9E42548` |
| TELFHASH | `t1d2211e8c993d09096a933574dcac27b0e60a8872ae660f21cf14c781456e09a910ee3f` |
| SSDEEP | `3072:PBgLvs3StF8KmBEY0vFjApPIR7ZNHQObiGV8QV2y1HqaKmk702mk2SacGiWK:CbgSoiY0vFj+mHpi5y1HQ7mkCPiWK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_89611739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89611739301b0f2198c031d778988d4e38b11b29558a8187fa86517a146c42dc"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-09-23 04:44:53"
  condition:
    hash.sha256(0, filesize) == "89611739301b0f2198c031d778988d4e38b11b29558a8187fa86517a146c42dc"
}
```

### Sample 8: `3e10fb301b22deaf`

| Field | Value |
|---|---|
| SHA-256 | `3e10fb301b22deafe787b42d6f831529c166abb2d20b44c451d4896e648e1d4d` |
| Family label | `Mirai` |
| File name | `riscv32` |
| File type | `elf` |
| First seen | `2026-09-23 04:40:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18966279b91a8a2c3bcb83dcb419a0ae` |
| SHA-1 | `1dfb02443e54402c01c61a4e5304a7b4793c4085` |
| SHA-256 | `3e10fb301b22deafe787b42d6f831529c166abb2d20b44c451d4896e648e1d4d` |
| SHA3-384 | `234acd2e7a06fb4b031470e6dbce7366318e40029e1cfe627fe809eaac6145bfadb187e95b865e484b76294b9f6fdfac` |
| TLSH | `T109742A8CA2F1E3CEE158EE745321BC1A5D72463B3093728A619EB97313BB19449F9D70` |
| SSDEEP | `6144:qyv340X2YpbcbwajL4LgUNmv1kPLoOq7a90u:R5miwUYXUNw1kTOa90u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_3e10fb30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e10fb301b22deafe787b42d6f831529c166abb2d20b44c451d4896e648e1d4d"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-09-23 04:40:47"
  condition:
    hash.sha256(0, filesize) == "3e10fb301b22deafe787b42d6f831529c166abb2d20b44c451d4896e648e1d4d"
}
```

### Sample 9: `7ee4b047ea9f7d5d`

| Field | Value |
|---|---|
| SHA-256 | `7ee4b047ea9f7d5d2256834aa19be02126eee3f4537d6c4e151dd97150869d66` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-23 04:40:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f5bb2cc2e5e48cab7d0c2887b152d08` |
| SHA-1 | `a1baf94636467105ea5edf105cf22e557600e132` |
| SHA-256 | `7ee4b047ea9f7d5d2256834aa19be02126eee3f4537d6c4e151dd97150869d66` |
| SHA3-384 | `e4b2ae0a72e0a0caf73e28634302c1126601cfaf23d5ca4a29e29f62310c8c4f9cfacc4bd9b81d1730f2be4fc4d5c934` |
| TLSH | `T1DD244E577710AFA2C268C2308EF3C75257E525C227D1965AE35CDB183E313982DABEE4` |
| TELFHASH | `t1fb21318c593d0e097a633574dc9c27b0e50ac862fd760f21cf28c780056e06a920ee7f` |
| SSDEEP | `3072:FAeRifCAGdfU8QREj64Isjse1P18Y/jMSAxi2pjMfmmiHqW12FREzMwBaeZvl9J1:hifC1dfjbTJ1h7MR02Rrx1qRaZvlT5Ma` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_7ee4b047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ee4b047ea9f7d5d2256834aa19be02126eee3f4537d6c4e151dd97150869d66"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:40:46"
  condition:
    hash.sha256(0, filesize) == "7ee4b047ea9f7d5d2256834aa19be02126eee3f4537d6c4e151dd97150869d66"
}
```

### Sample 10: `88368ba34ac57875`

| Field | Value |
|---|---|
| SHA-256 | `88368ba34ac5787573bd7dca6cdbbe92252e1af73e73ac680bc944035d96a697` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-09-23 04:32:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `330f29f3236c0cfef85a710947b34d10` |
| SHA-1 | `d19f61223c47c1b3b95eaf850323c647823a2e49` |
| SHA-256 | `88368ba34ac5787573bd7dca6cdbbe92252e1af73e73ac680bc944035d96a697` |
| SHA3-384 | `b89e63af98974bb7e1dc09f9d87ae21e973bebf622832d1ec05e4c9561e644f85aa180bed5a454c41d31d2a65623af8c` |
| TLSH | `T1D6434B36B6751A1BC8D8957E26F78368B2F0178E24E8C61F7D320E8EFF6094066171B1` |
| SSDEEP | `768:XsC7uGTXIBM1+3Ebq8Nwml5RnXTKaZYqZ1hSnQzHO+Y+CCNB5:8w/T6M1yEbq8NwcnjK2Y61hSnQzbY+xj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_88368ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88368ba34ac5787573bd7dca6cdbbe92252e1af73e73ac680bc944035d96a697"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-23 04:32:44"
  condition:
    hash.sha256(0, filesize) == "88368ba34ac5787573bd7dca6cdbbe92252e1af73e73ac680bc944035d96a697"
}
```

### Sample 11: `fc1665cc9bb3711e`

| Field | Value |
|---|---|
| SHA-256 | `fc1665cc9bb3711e0de190d9d9b6c68f95559a4d468dbf2042057d2fff96cdf4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 04:32:09` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7106a019b91614dcc3f2348239b41be2` |
| SHA-1 | `5d1776bc68034d60143a8d13bb185b2ceb803201` |
| SHA-256 | `fc1665cc9bb3711e0de190d9d9b6c68f95559a4d468dbf2042057d2fff96cdf4` |
| SHA3-384 | `9602cab5d057e08f339b1cfdeae3c8858c5f7cc0cb0f7d6e65533472c1354774f6b979475d18ab204054080b7e280e35` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17462D796E8A21F5CDE8E80B03B12F83879B436958A655DF3D7828C345EA38D10464FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UXfBgn:fKOe2/7c9sN3zfZR1m+RGOf6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_fc1665cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc1665cc9bb3711e0de190d9d9b6c68f95559a4d468dbf2042057d2fff96cdf4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:32:09"
  condition:
    hash.sha256(0, filesize) == "fc1665cc9bb3711e0de190d9d9b6c68f95559a4d468dbf2042057d2fff96cdf4"
}
```

### Sample 12: `af3f31832f852159`

| Field | Value |
|---|---|
| SHA-256 | `af3f31832f85215951298c7405d8d2c65291a185b4e6a23b3c7809f2ada5891f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 04:29:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01cfc7f15e52723ed7a80412ff9b918b` |
| SHA-1 | `2b390fdd1d7ba94a11ad24d8c53d7052cb7c16a9` |
| SHA-256 | `af3f31832f85215951298c7405d8d2c65291a185b4e6a23b3c7809f2ada5891f` |
| SHA3-384 | `7683acd0ad48c7e7919d2b5e00e2e0501841ebb20657edc5c07de338452b20c3031d797dae1315ff2b64d1bffd684b92` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17262E79ED9922F5DCE4F90703A52F878BD78769086665AE3D7828C309DA39D00024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UIMYBM:fKOe2/7c9sN3zfZR1m+RGHMY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_af3f3183
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3f31832f85215951298c7405d8d2c65291a185b4e6a23b3c7809f2ada5891f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:29:49"
  condition:
    hash.sha256(0, filesize) == "af3f31832f85215951298c7405d8d2c65291a185b4e6a23b3c7809f2ada5891f"
}
```

### Sample 13: `13a7c2e9cf4306cf`

| Field | Value |
|---|---|
| SHA-256 | `13a7c2e9cf4306cf9c4d4844b4ee57b453aac66f74075ecddca99749ae3a10b2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 04:27:28` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81bbb3a7ec0898ccac46081c0a3513f5` |
| SHA-1 | `ea33aa4851bc2e00f4d48ba2c46f308f158d87e9` |
| SHA-256 | `13a7c2e9cf4306cf9c4d4844b4ee57b453aac66f74075ecddca99749ae3a10b2` |
| SHA3-384 | `25837c74501d6b25bf6147beec37a3c4615726f2951237c2250aba532f5479c2e30d9c4f17c95a77335453648b2f9f8b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19A62D796D8A22F6DDF4E80707A51F868BD70769096695DF3D7828C305E638D04028FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uw58rU:fKOe2/7c9sN3zfZR1m+RGP8Hh6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_13a7c2e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a7c2e9cf4306cf9c4d4844b4ee57b453aac66f74075ecddca99749ae3a10b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:27:28"
  condition:
    hash.sha256(0, filesize) == "13a7c2e9cf4306cf9c4d4844b4ee57b453aac66f74075ecddca99749ae3a10b2"
}
```

### Sample 14: `eaa824483bb71d26`

| Field | Value |
|---|---|
| SHA-256 | `eaa824483bb71d265de52391e23a8826e24e82915e40585ea65911cac3f165b4` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-09-23 04:24:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c80829157a8f1fe8fedc2b8f3fecbba` |
| SHA-1 | `07c329815bd5d3c2e31100d783cede54cf99571c` |
| SHA-256 | `eaa824483bb71d265de52391e23a8826e24e82915e40585ea65911cac3f165b4` |
| SHA3-384 | `469225f7d6bfe9dc0efb63b1fc77837424286c4bdfe1c7645d762da151434041534828d0d844751bcc09bb73496edcae` |
| TLSH | `T176C34B07B5D24CFEC0C6C639936B9221E537F86513126B272798AE363E2EF111E0D769` |
| TELFHASH | `t1d2211e8c993d09096a933574dcac27b0e60a8872ae660f21cf14c781456e09a910ee3f` |
| SSDEEP | `1536:zyz8F5N/h58P0D1xT9ywEOmiZVK8y+AIp03o7+k6HC/oqabfVCs7lcrYPiHKjq:eUDBhZA8yoik6tJbtr0dHKjq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_eaa82448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa824483bb71d265de52391e23a8826e24e82915e40585ea65911cac3f165b4"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-23 04:24:44"
  condition:
    hash.sha256(0, filesize) == "eaa824483bb71d265de52391e23a8826e24e82915e40585ea65911cac3f165b4"
}
```

### Sample 15: `5231a4a5575c46a7`

| Field | Value |
|---|---|
| SHA-256 | `5231a4a5575c46a7609e480f7be08526ef83dfe1c6e75975bc0755db39590fd8` |
| Family label | `Mirai` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-09-23 04:22:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca116dc118f12632b962e08c91091ae8` |
| SHA-1 | `92092e5c3845acea8ccb60568b5e0a0f7f791466` |
| SHA-256 | `5231a4a5575c46a7609e480f7be08526ef83dfe1c6e75975bc0755db39590fd8` |
| SHA3-384 | `89b4256a6bdc85541909a019f43c48464d9b801385a41853ccf5c07cdaf0c5f331fae8b99978d540a9565bd06ff9c739` |
| TLSH | `T124841A5463F1D2DAD244E971D3227F16ABB2063630B7B28B324EB67313B326545DEE60` |
| SSDEEP | `6144:Dw/eRawvsmj9m2bsxzSSCZMOkiNfUj8kibQ8F7IIf4s2rxyDq4dG:30m4cPH3GiJdG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_5231a4a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5231a4a5575c46a7609e480f7be08526ef83dfe1c6e75975bc0755db39590fd8"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-09-23 04:22:44"
  condition:
    hash.sha256(0, filesize) == "5231a4a5575c46a7609e480f7be08526ef83dfe1c6e75975bc0755db39590fd8"
}
```

### Sample 16: `fe868c20e94c8d17`

| Field | Value |
|---|---|
| SHA-256 | `fe868c20e94c8d178211f735c2000ca929d8a830449b43f7ded3b6354783c057` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-23 04:21:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35c8a6039352f654e512ab3876d531f6` |
| SHA-1 | `196390df8998614be38d3326c670a91f19233a66` |
| SHA-256 | `fe868c20e94c8d178211f735c2000ca929d8a830449b43f7ded3b6354783c057` |
| SHA3-384 | `b0f34f839400a36854c76e1259f3b29c04652f889099b20c3e1f4f3bcd6f2dba5388c04968e9086338fd78d3de50daa4` |
| TLSH | `T138A4F98953F1DFD9F268E93003736E1B5DB6063735D3A186E16EE92233A524844AFE70` |
| TELFHASH | `t16af01c28283813b4d2c09c5e56ecff20e8a1a4dba8b62d27c950c969e775e874d00d3c` |
| SSDEEP | `6144:tfXv0t0G0CIwIHVRyZHP7l+BMpOM8HVNNqbqfXqPjXxCvj:tvAIPw5g+OVXX2jhCvj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_fe868c20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe868c20e94c8d178211f735c2000ca929d8a830449b43f7ded3b6354783c057"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:21:23"
  condition:
    hash.sha256(0, filesize) == "fe868c20e94c8d178211f735c2000ca929d8a830449b43f7ded3b6354783c057"
}
```

### Sample 17: `08296c241afbe93d`

| Field | Value |
|---|---|
| SHA-256 | `08296c241afbe93df6a8b10508fa3ce3a97bfabaf29cfb06e124bbcf579a9705` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-09-23 04:20:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56049ebd641f46be81f15bc5d14dec50` |
| SHA-1 | `30c1ae41a158d1a8085990b49db94cbf60105225` |
| SHA-256 | `08296c241afbe93df6a8b10508fa3ce3a97bfabaf29cfb06e124bbcf579a9705` |
| SHA3-384 | `58a480987f26c4586ab20feeab1f90d74b12fee9179efb9bcb2c92bc0d2a79a0018add3fd491453c6b815615ab63ae83` |
| TLSH | `T15E33F685B9829A17C6D443BBFA0E42CD3326B3D8E2DE3213DD211F6537DB52F0A6A151` |
| TELFHASH | `t1bec08c004f2f91ec3aa3194a8a5c0608ebf949fa0288485c7acb2f221d178a23cd45b0` |
| SSDEEP | `1536:QlhKwMtpWUQZNdrLP/pI+uBzlGuS/I0nQS:wKwMtEDZNdrLPi8x/TQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_08296c24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08296c241afbe93df6a8b10508fa3ce3a97bfabaf29cfb06e124bbcf579a9705"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:49"
  condition:
    hash.sha256(0, filesize) == "08296c241afbe93df6a8b10508fa3ce3a97bfabaf29cfb06e124bbcf579a9705"
}
```

### Sample 18: `c6fbf5fe81c3b269`

| Field | Value |
|---|---|
| SHA-256 | `c6fbf5fe81c3b2699bb62c71580cc22b695ff57cc95d60e73e7a73cb7d1a55cc` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-09-23 04:20:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66633908f6dc81543ca432919315631a` |
| SHA-1 | `e5c6f95622e660c9bab12df7ab6590bca15b986f` |
| SHA-256 | `c6fbf5fe81c3b2699bb62c71580cc22b695ff57cc95d60e73e7a73cb7d1a55cc` |
| SHA3-384 | `a902146302a949d39817226f8de918e4af5f59035ba50676cc492411d739e24e4eb3d247ab8c2b2e32c891d7949ddf12` |
| TLSH | `T1FF53E74AB8C28E15D5D412BAFE1E118E331377A8E3DE7213DD206B2437CA56F0A7B456` |
| TELFHASH | `t170c09b4652ce07c035955715415f631b90fe70e6161d07a4afc27fdf50e7d53b545831` |
| SSDEEP | `1536:+0nu+MbpXOdEpDzQKmM6TianPMki/1qhfmi:E++pRDfmu1qhfm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_c6fbf5fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6fbf5fe81c3b2699bb62c71580cc22b695ff57cc95d60e73e7a73cb7d1a55cc"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:48"
  condition:
    hash.sha256(0, filesize) == "c6fbf5fe81c3b2699bb62c71580cc22b695ff57cc95d60e73e7a73cb7d1a55cc"
}
```

### Sample 19: `e31095dc97bc60d6`

| Field | Value |
|---|---|
| SHA-256 | `e31095dc97bc60d6a9e57f61d097d7ec094d11f4a230a1f6198f9ccd4dc0a050` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-23 04:20:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f284a4e6cb0e1cb17154bc81d85f791` |
| SHA-1 | `7eadd5387027e700951e65c1a7f4555d2ec1bec8` |
| SHA-256 | `e31095dc97bc60d6a9e57f61d097d7ec094d11f4a230a1f6198f9ccd4dc0a050` |
| SHA3-384 | `1500be4977f2c352622e17701a9c723afa6bdf17535669bda806747870a8222f23cde383b5feffd31c0c618f69d6c5e7` |
| TLSH | `T157E312D917CBC2CFDE92A47A60F18FB834B61D706C25CCE17A05E9C5DC8A240B1ED696` |
| SSDEEP | `3072:Eolj1/wvBTCev2T2Nu3K3UvX8czT1PJtt5ZKGYPKDjl7IiVd:EimueviKn+JPJtrZKGYQj1IAd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_e31095dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e31095dc97bc60d6a9e57f61d097d7ec094d11f4a230a1f6198f9ccd4dc0a050"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:47"
  condition:
    hash.sha256(0, filesize) == "e31095dc97bc60d6a9e57f61d097d7ec094d11f4a230a1f6198f9ccd4dc0a050"
}
```

### Sample 20: `6a842ed17b29ce29`

| Field | Value |
|---|---|
| SHA-256 | `6a842ed17b29ce297db6846ef6082966263f10f0b4a27e0dd9805680bf578efa` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-23 04:20:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b60343a09d959f42fd2559bf2fe722f` |
| SHA-1 | `cd2813b4267e7709f64899833dca42b996bf0e07` |
| SHA-256 | `6a842ed17b29ce297db6846ef6082966263f10f0b4a27e0dd9805680bf578efa` |
| SHA3-384 | `261ce10d9f07769f85a90569535d237978bf4302b43f0277516a2c1625df30aa307f7c980c54ddbcbf27509e1334d228` |
| TLSH | `T1D4233996B800AD3DFC4BE77E80174A0AF1317758549316376363FCB3AD721A49E66E82` |
| SSDEEP | `768:l/HhSwY6AR/vDaJ35BaAo/DRGrUOIlOqmKur82FH4jVnIIqJfwnxlQ:l/HcLvOJ3/aAoNDMqmTr82FCVnLqtK2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_6a842ed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a842ed17b29ce297db6846ef6082966263f10f0b4a27e0dd9805680bf578efa"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:45"
  condition:
    hash.sha256(0, filesize) == "6a842ed17b29ce297db6846ef6082966263f10f0b4a27e0dd9805680bf578efa"
}
```

### Sample 21: `50878a634b0af9c4`

| Field | Value |
|---|---|
| SHA-256 | `50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44` |
| Family label | `unknown` |
| File name | `50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44` |
| File type | `elf` |
| First seen | `2026-09-23 04:17:34` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa54d92cab9f9aacf95454da8d9479c2` |
| SHA-1 | `29c55f41b7c2dd62db6188d217bd807360bc35f8` |
| SHA-256 | `50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44` |
| SHA3-384 | `a4c706af0a20bff8ae1e4306e0cd5038172d4bc3f9014f01c96139119db3998dcec24393fb37f43a7e79f0e926996811` |
| TLSH | `T17FB30251D3230D0F843538FABA26E6152D872E79248A415D4AF5E67B4FB708CE9F6313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxD:biMYFJvw6Yh0b1gKobtCGCmCRlrh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_50878a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44"
    family = "unknown"
    file_name = "50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44"
    file_type = "elf"
    first_seen = "2026-09-23 04:17:34"
  condition:
    hash.sha256(0, filesize) == "50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44"
}
```

### Sample 22: `2cf1e1b855f54786`

| Field | Value |
|---|---|
| SHA-256 | `2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce` |
| Family label | `Mirai` |
| File name | `2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce` |
| File type | `elf` |
| First seen | `2026-09-23 04:17:29` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c1c9fdd009cd074cf6c83b0549341ba` |
| SHA-1 | `8eae1c90a5eac469ed054ed0d4c30068e59bd74d` |
| SHA-256 | `2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce` |
| SHA3-384 | `aeaf4e8699897ab176b4d73711173f1641828578866e8b85ff52e579e76141484f57a152a2fd9bca93126aa3fe9f4c09` |
| TLSH | `T1E3230681BC82869699D413BFF97E41CD331273B9D2DF7102CD115F18B6CA94F0E6AA92` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ9137:T2s/ITo7WCkybotgsJ9137` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_2cf1e1b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce"
    family = "Mirai"
    file_name = "2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce"
    file_type = "elf"
    first_seen = "2026-09-23 04:17:29"
  condition:
    hash.sha256(0, filesize) == "2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce"
}
```

### Sample 23: `f63dac099109470c`

| Field | Value |
|---|---|
| SHA-256 | `f63dac099109470cb0223e919a2648c570b20225f63e9a3340a124203e2bc2dd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 04:15:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2da7f235a5163d174b1265234a93522` |
| SHA-1 | `5f84e95065c3f4288ffe61164969f4d5658e5de7` |
| SHA-256 | `f63dac099109470cb0223e919a2648c570b20225f63e9a3340a124203e2bc2dd` |
| SHA3-384 | `87a231d2300314938f3bb36765245ebf8ef4f200da61ba8fd8daeaffd07fa53d1faee9032bd47012a29731bada765532` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14C62C79AE8B26F5CDE4E80707A61F83879B436958566A9F3D7868C305E63CD00424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uo84Be:fKOe2/7c9sN3zfZR1m+RGp866C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_f63dac09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f63dac099109470cb0223e919a2648c570b20225f63e9a3340a124203e2bc2dd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:15:35"
  condition:
    hash.sha256(0, filesize) == "f63dac099109470cb0223e919a2648c570b20225f63e9a3340a124203e2bc2dd"
}
```

### Sample 24: `ef715f1952de9c27`

| Field | Value |
|---|---|
| SHA-256 | `ef715f1952de9c27528cb58939e05fe2dd0a44056fbd3c0b70c64ac269508cb3` |
| Family label | `Mirai` |
| File name | `arm8` |
| File type | `elf` |
| First seen | `2026-09-23 04:14:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3f54a12dd4d5d0fb0da81e320fbf199` |
| SHA-1 | `a3e6c99cd8c09ca7363d901b13f6b1b112dba119` |
| SHA-256 | `ef715f1952de9c27528cb58939e05fe2dd0a44056fbd3c0b70c64ac269508cb3` |
| SHA3-384 | `4b0691c9f1112113f6b8155a143af5458c83600f7732ad78aaf6f5ce0bb0163fcd1efef20395fe8c31903032fd3c8bba` |
| TLSH | `T18A742C8CD2FAF6CEE288FA7853217D17683226753097B1E6610EF56753FB19448E9830` |
| SSDEEP | `6144:Mv6iL2Nz8E0TtmUG/tB+moOkJ0Jr0O16dKSa9O7:MvV2NzlwcUG1B+ma0lwa9O7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_ef715f19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef715f1952de9c27528cb58939e05fe2dd0a44056fbd3c0b70c64ac269508cb3"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:47"
  condition:
    hash.sha256(0, filesize) == "ef715f1952de9c27528cb58939e05fe2dd0a44056fbd3c0b70c64ac269508cb3"
}
```

### Sample 25: `6f069d0f236b15c7`

| Field | Value |
|---|---|
| SHA-256 | `6f069d0f236b15c77109939763abd5cbec9c2451e281e2a3e5008a3114f5722b` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-09-23 04:14:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc3be3182c8d80db62380f82b7208b40` |
| SHA-1 | `115cf603ee4a03bcdef145999153bfd03f79817d` |
| SHA-256 | `6f069d0f236b15c77109939763abd5cbec9c2451e281e2a3e5008a3114f5722b` |
| SHA3-384 | `1992d5d25553aaef9100038297368da8947bfd39cfc69f78d653fe24827ace65f280fdbf092e6f36c2b361cd5bfae77d` |
| TLSH | `T1E1331842721C0503D5671EB0353F1BD1D3BBEAC122E4F249B60FAB1981B1E77AA46E9D` |
| SSDEEP | `768:Z2HM6B/ZeIJ3EpieZn9MWtnJDpZB2d4DvlgdpXlKvXDJe1EfSvgMG8s:SzEphB9MWtJDFPvWdQDuwSvxGx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_6f069d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f069d0f236b15c77109939763abd5cbec9c2451e281e2a3e5008a3114f5722b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:46"
  condition:
    hash.sha256(0, filesize) == "6f069d0f236b15c77109939763abd5cbec9c2451e281e2a3e5008a3114f5722b"
}
```

### Sample 26: `a26ee06ad856826b`

| Field | Value |
|---|---|
| SHA-256 | `a26ee06ad856826b09039273cb384788229fb501ea744a5497863271be972ce0` |
| Family label | `Mirai` |
| File name | `wezpffnw.mips` |
| File type | `elf` |
| First seen | `2026-09-23 04:14:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbc560f9e2b1b05397df5cbcd013419b` |
| SHA-1 | `85aba849c63b2dfce2dc6c8579fb1b4248e647da` |
| SHA-256 | `a26ee06ad856826b09039273cb384788229fb501ea744a5497863271be972ce0` |
| SHA3-384 | `1ecb5e01a59a3cca0958659d369e4a7e7eb449cc87c4d2df9e47ca05c68a98191b95eb263c39cc41139d9b07bc9515e1` |
| TLSH | `T15C356C633731DF69E314D27004F3CA617A9521E31AE24096B36CC3287A6166E6D6FFE4` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:yTHTMmWirM4eLk3+EVcSMxio+rIKff3fffbffffoAhqxwHnKDkNg4:yTHTS54eLk3+n3+U3eqxwHLH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_a26ee06a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a26ee06ad856826b09039273cb384788229fb501ea744a5497863271be972ce0"
    family = "Mirai"
    file_name = "wezpffnw.mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:45"
  condition:
    hash.sha256(0, filesize) == "a26ee06ad856826b09039273cb384788229fb501ea744a5497863271be972ce0"
}
```

### Sample 27: `dc0898daf346ffa9`

| Field | Value |
|---|---|
| SHA-256 | `dc0898daf346ffa9431d8b0e0ac3ef2197939755e9da8352f4fc3d4209390087` |
| Family label | `Mirai` |
| File name | `android-arm` |
| File type | `elf` |
| First seen | `2026-09-23 04:14:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49c92bc101dc7beb68b2303ea2d85b58` |
| SHA-1 | `79e4d041aeafac1debd31012fb43f42156dfb6ca` |
| SHA-256 | `dc0898daf346ffa9431d8b0e0ac3ef2197939755e9da8352f4fc3d4209390087` |
| SHA3-384 | `0a784133d54a083ccc4b3940276def920062c52ccfba97cc2d16e1b9ed7583b1e81b13d6d2c2c892618bd72a8d55c2b9` |
| TLSH | `T10884FC88F1F1E3CDD1D4E9757219B8893B63533AB1DB7146A509EA3313EF18909BDA20` |
| TELFHASH | `t1db117d46ad7996ae6d934a20aca967b09153da223171c360df10cee4a83e515f20de4f` |
| SSDEEP | `6144:asHa9hb0grTp4jjAxVHs4zniFRMNW2DMFksxvg:asHa9hb0gr6YxBs4S+NWBK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_dc0898da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc0898daf346ffa9431d8b0e0ac3ef2197939755e9da8352f4fc3d4209390087"
    family = "Mirai"
    file_name = "android-arm"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:43"
  condition:
    hash.sha256(0, filesize) == "dc0898daf346ffa9431d8b0e0ac3ef2197939755e9da8352f4fc3d4209390087"
}
```

### Sample 28: `31dc572984be0c27`

| Field | Value |
|---|---|
| SHA-256 | `31dc572984be0c27e1387ddda3394b4243ba96d0a2ca1efac4891948eee8f3d4` |
| Family label | `unknown` |
| File name | `IMG7838399201.IMG.scr` |
| File type | `exe` |
| First seen | `2026-09-23 04:12:56` |
| Reporter | `ppt_lol` |
| Tags | `exe, xworm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ff48d5c5f7d13ffd54ca05d6e2cacd0` |
| SHA-1 | `bc9c74e051bca5867970e1e1640ce284b6d10e15` |
| SHA-256 | `31dc572984be0c27e1387ddda3394b4243ba96d0a2ca1efac4891948eee8f3d4` |
| SHA3-384 | `1381b2e3918ce10b841872f93d9725ad61292b5d8b5b8d1f79100aa08a68dbe3b0a3ff392c5c050f20c36d34bd7a6a96` |
| IMPHASH | `99ee65c2db82c04251a5c24f214c8892` |
| TLSH | `T16A250212BBC58072D07225325AB68BA0167C7D701F618ADF63D07DAE6B716D1C632FA3` |
| SSDEEP | `24576:hN/BUBb+tYjBFHL68vj/yHjJcJX1zJ54D+qRfoBan5Fo:jpUlRhTveJoX1zJ5w+ufya5G` |
| ICON-DHASH | `5211fadcf9346460` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_31dc5729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31dc572984be0c27e1387ddda3394b4243ba96d0a2ca1efac4891948eee8f3d4"
    family = "unknown"
    file_name = "IMG7838399201.IMG.scr"
    file_type = "exe"
    first_seen = "2026-09-23 04:12:56"
  condition:
    hash.sha256(0, filesize) == "31dc572984be0c27e1387ddda3394b4243ba96d0a2ca1efac4891948eee8f3d4"
}
```

### Sample 29: `8709c2371700ae30`

| Field | Value |
|---|---|
| SHA-256 | `8709c2371700ae3072b3608ad94a1015a9c9125e80386f12d6a58f0c663eb895` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 04:12:56` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acd97dc7c4382223013d5942d6ac1212` |
| SHA-1 | `3df67118be6444f3a38cd0a2902451cd0f05cba1` |
| SHA-256 | `8709c2371700ae3072b3608ad94a1015a9c9125e80386f12d6a58f0c663eb895` |
| SHA3-384 | `c28f2a211f74ecb7b5cdf853fabcad2d81015a8886804047dc52ce5e389a83de6fbc22ac957b47614403da907fe15e0b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13362D986D9E22F5DCE4E80703A11F8386DB436909A6559F7D7828D305EAB9D004B4FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uw2iBM:fKOe2/7c9sN3zfZR1m+RGAi6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_8709c237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8709c2371700ae3072b3608ad94a1015a9c9125e80386f12d6a58f0c663eb895"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:12:56"
  condition:
    hash.sha256(0, filesize) == "8709c2371700ae3072b3608ad94a1015a9c9125e80386f12d6a58f0c663eb895"
}
```

### Sample 30: `ba08e64054dea440`

| Field | Value |
|---|---|
| SHA-256 | `ba08e64054dea4400361094ac902903e6cc20e077901d0887e5b0f1252499ca8` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-23 04:12:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9db4e7b738ce76081833bb537abcd8a` |
| SHA-1 | `ed9c47a85ac11ee020c028b911f3ec83462fecf5` |
| SHA-256 | `ba08e64054dea4400361094ac902903e6cc20e077901d0887e5b0f1252499ca8` |
| SHA3-384 | `3e54ff7f23677ee768c369f2ea863bb822f430f2221845c7c7825a168793f25833a93fcde18ed329845912f4fe350ecf` |
| TLSH | `T1BE356C5DFE0F3D47D2C6F23DEB4983B47127B098C62351A225C2034DE6C9D998B6299E` |
| TELFHASH | `t149a012020880810c0177ab114c95034910414833e81a3d551e0cda400410008034886a` |
| SSDEEP | `24576:iprJirHHPsmxZIfShh5pJgoEl6JwbM8qwy4:qSPfxMovXEl6JwbMH4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_ba08e640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba08e64054dea4400361094ac902903e6cc20e077901d0887e5b0f1252499ca8"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-23 04:12:44"
  condition:
    hash.sha256(0, filesize) == "ba08e64054dea4400361094ac902903e6cc20e077901d0887e5b0f1252499ca8"
}
```

### Sample 31: `9cb152989cc16081`

| Field | Value |
|---|---|
| SHA-256 | `9cb152989cc16081cc1e7559ff575365a93309e01468d9fd8feb75c6cb588bef` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-09-23 04:12:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41be1aa142bc0ea8e94ca9d0c0010424` |
| SHA-1 | `5936f5e11d1b6d80f10254c31157b0a8249a01dc` |
| SHA-256 | `9cb152989cc16081cc1e7559ff575365a93309e01468d9fd8feb75c6cb588bef` |
| SHA3-384 | `de489ac0b2afb2f448be25e448c007f0b7824550bd06c23fe7478d51ea83bb0cc7396c3b4a4f096a33144d05927db2db` |
| TLSH | `T1BF137C52C87A6D54C12812B4F8318F7E5B23F955A6A76FE29626C73CC103E9CFC192B4` |
| SSDEEP | `768:XUcVT+s4+CuYh6QSLN3Gdr3FUraSIDqdx1x6zoa8Hx/BCxb:XDx+sZC0N2V3FUrajCFLacpCxb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_9cb15298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cb152989cc16081cc1e7559ff575365a93309e01468d9fd8feb75c6cb588bef"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-23 04:12:42"
  condition:
    hash.sha256(0, filesize) == "9cb152989cc16081cc1e7559ff575365a93309e01468d9fd8feb75c6cb588bef"
}
```

### Sample 32: `fbbec0bbae6a3786`

| Field | Value |
|---|---|
| SHA-256 | `fbbec0bbae6a37861bdad14dc8f6939d0a55f07da9df38f44b921cfd0c0cc33d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 04:10:31` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c37950abab0449b3a3447363fe6698e9` |
| SHA-1 | `22b7ff2ea1f4778cd0a19e5bed1ceb58b0a6af2b` |
| SHA-256 | `fbbec0bbae6a37861bdad14dc8f6939d0a55f07da9df38f44b921cfd0c0cc33d` |
| SHA3-384 | `81ce2240409311864274236b4e2d9a2f59640493bb5708176a38e27438555b1462bcb6496e8662f2bc0f05dabbc3df26` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14462C587D8922F5DCE4E80703F11FC28BD7576D18A665DEBD7928C209AA38D40128EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UKaYme:fKOe2/7c9sN3zfZR1m+RGNap6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_fbbec0bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbbec0bbae6a37861bdad14dc8f6939d0a55f07da9df38f44b921cfd0c0cc33d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:10:31"
  condition:
    hash.sha256(0, filesize) == "fbbec0bbae6a37861bdad14dc8f6939d0a55f07da9df38f44b921cfd0c0cc33d"
}
```

### Sample 33: `f280cf140a3f4720`

| Field | Value |
|---|---|
| SHA-256 | `f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94` |
| Family label | `SilentNet` |
| File name | `f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94.exe` |
| File type | `exe` |
| First seen | `2026-09-23 04:09:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, SilentNet` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3376c2472d4dc756a6871db37237676` |
| SHA-1 | `486a1cbbdb2ef217d40e8d34734ab87e6c0d443d` |
| SHA-256 | `f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94` |
| SHA3-384 | `1d4dd84f056297642712df143d922bae50d4347e0d9a080a61e59ee814ce1ac46b66d2d438892824947f229c5092d8eb` |
| IMPHASH | `73f461c771aef77ec43d53a0c54f0c8d` |
| TLSH | `T124357C83E7A385D8C116C9B5534BF137F9627C8E4B157197ABC41E633A67BA4E22CB00` |
| SSDEEP | `12288:Tbs/m0E54jwaFXGc8lEBBBHGBKq2IZwD0vfqItNqdg:TbOVE5ifGPRZw4vf3fd` |

#### Technical Assessment

- The sample is tracked as `SilentNet` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SilentNet_033_f280cf14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94"
    family = "SilentNet"
    file_name = "f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94.exe"
    file_type = "exe"
    first_seen = "2026-09-23 04:09:44"
  condition:
    hash.sha256(0, filesize) == "f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94"
}
```

### Sample 34: `eb1d374931db60f7`

| Field | Value |
|---|---|
| SHA-256 | `eb1d374931db60f740359426bafa103827d2cf6dbc89e91800e02913d3578695` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-23 04:04:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `563748eec2c6237675c45ad807025bab` |
| SHA-1 | `1610cc363c115a26291bdd52fd73377cc75b741b` |
| SHA-256 | `eb1d374931db60f740359426bafa103827d2cf6dbc89e91800e02913d3578695` |
| SHA3-384 | `0d1ce611fa7f7afe09d47e4973d7e575ed540e8d3d2d403cf554ae05c8fb7d8518631556170f95adea47497fd61f727f` |
| TLSH | `T12B741988D2E3E2FEF155D97012257A1B5D3246373093F28AF39DBA7392B614045EEA34` |
| TELFHASH | `t11861c8048fca24bcfbd3a9905af6507556ae63cef7155a104358bdbb3e53a81a42fc03` |
| SSDEEP | `6144:qMitcZEEus9+upjWzSWaN4nOtzPlK/+drqa9v9:q1mEEWupM4tzPlK/+Jqa9v9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_eb1d3749
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb1d374931db60f740359426bafa103827d2cf6dbc89e91800e02913d3578695"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-23 04:04:51"
  condition:
    hash.sha256(0, filesize) == "eb1d374931db60f740359426bafa103827d2cf6dbc89e91800e02913d3578695"
}
```

### Sample 35: `88a68b4f97b89818`

| Field | Value |
|---|---|
| SHA-256 | `88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db` |
| Family label | `unknown` |
| File name | `88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db.exe` |
| File type | `exe` |
| First seen | `2026-09-23 04:04:07` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `171807338dbc260dfb523163a45884df` |
| SHA-1 | `f0908c4f14d47e2ead7186d5b91cf7f46db5999b` |
| SHA-256 | `88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db` |
| SHA3-384 | `814bcfd12ea3eeb02bf20273b048dfdb416f1b43d23e164185b0d833d48cb53c699ce127810c6b6ae2fd7af909770c97` |
| IMPHASH | `5c70c676d7901df991a330caf4fcd5a4` |
| TLSH | `T1F7F3F129F6B384DDC0D999B8756A5DF29570FC5408A0696C12F283683B93E8C9F34B87` |
| SSDEEP | `3072:0OYmj17t8gmDX7BeNHINHq4yu3R2w1q8ji:0J+17+B7B2Hcyw9qp` |
| ICON-DHASH | `e862eae6b692c6ee` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_88a68b4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db"
    family = "unknown"
    file_name = "88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db.exe"
    file_type = "exe"
    first_seen = "2026-09-23 04:04:07"
  condition:
    hash.sha256(0, filesize) == "88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db"
}
```

### Sample 36: `00df580e13c65895`

| Field | Value |
|---|---|
| SHA-256 | `00df580e13c658952545f6c73eadae574fbba094cafcafd213032afd77627068` |
| Family label | `Mirai` |
| File name | `ypezhbfg.i686` |
| File type | `elf` |
| First seen | `2026-09-23 03:46:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5e830580bad65c56a94a3a94c0ffa0e` |
| SHA-1 | `6d5164477f55e0255c525ca1ba40f4ecc7f24062` |
| SHA-256 | `00df580e13c658952545f6c73eadae574fbba094cafcafd213032afd77627068` |
| SHA3-384 | `7f6a59a42cb670c60d4cb03a126bba5716170af5272dd1446094ef7a03b2ed167c03073ce73cf08bb948e151d9bc77e2` |
| TLSH | `T1C1355B5BB2A374BCC557C430839BCA62AD35B46502226E7FA5C4DB702E26E70172DF72` |
| TELFHASH | `t1a4e189794bfa34b0a2d2e614f352f1f555771c3666ec35b56622ad88ee84f800c7382b` |
| SSDEEP | `24576:4mSGFLK809462EgFVMtjzBG0oZdkQP6Hp+8s8gIFFFFFFFFFFhFFKgFFFoFFZO:51p2462GjA0+P2+8sbIFFFFFFFFFFhFV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_00df580e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00df580e13c658952545f6c73eadae574fbba094cafcafd213032afd77627068"
    family = "Mirai"
    file_name = "ypezhbfg.i686"
    file_type = "elf"
    first_seen = "2026-09-23 03:46:57"
  condition:
    hash.sha256(0, filesize) == "00df580e13c658952545f6c73eadae574fbba094cafcafd213032afd77627068"
}
```

### Sample 37: `7851a963b1aec1da`

| Field | Value |
|---|---|
| SHA-256 | `7851a963b1aec1da20ff097675a8c8adcb802a2bc326f7f2430a29224d8e723a` |
| Family label | `Mirai` |
| File name | `ooikocqj.mips64` |
| File type | `elf` |
| First seen | `2026-09-23 03:40:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d70832c62402d45565f2c2f792b54b88` |
| SHA-1 | `ed8729c93e8fee99ab390e2af450b8e7b0a65d38` |
| SHA-256 | `7851a963b1aec1da20ff097675a8c8adcb802a2bc326f7f2430a29224d8e723a` |
| SHA3-384 | `b096840fb6795d7ea70f99314b4f512bcf90300347849134b25a68be28868ea9d5fe6a662542815648bdf165aa22bdea` |
| TLSH | `T1B9356C07BF441FEBC4AFCE74852EC31710EDE88752C5A62D71BC8A9CBA593594AC3588` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:u3/cdkWjlpAtYdpxN1iKs1wb7ENXQfYKNpqxwHnKDk:uc7jXBPdVb7EuPqxwHL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_7851a963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7851a963b1aec1da20ff097675a8c8adcb802a2bc326f7f2430a29224d8e723a"
    family = "Mirai"
    file_name = "ooikocqj.mips64"
    file_type = "elf"
    first_seen = "2026-09-23 03:40:49"
  condition:
    hash.sha256(0, filesize) == "7851a963b1aec1da20ff097675a8c8adcb802a2bc326f7f2430a29224d8e723a"
}
```

### Sample 38: `dcb1c7a3a5ec3692`

| Field | Value |
|---|---|
| SHA-256 | `dcb1c7a3a5ec3692a7db6e4d0d0f83f653ab5440e1510cf2e841fa3a3fcae48e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 03:24:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f336d390b3e29fca98d32d7dd2b6643f` |
| SHA-1 | `4a6c2b4a6a6516651d9e3d8848a3fcf5c25230fc` |
| SHA-256 | `dcb1c7a3a5ec3692a7db6e4d0d0f83f653ab5440e1510cf2e841fa3a3fcae48e` |
| SHA3-384 | `7a574d496614c9e1cf657712b756143998edaddf283e19aed96d58f1ca2e182db366677939141c12691e7febfab1a94d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BA62C69AD8A21E9CDE4ED0703B11F978BEB436908A655AF3D7D28C7059A38D11034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UMcXoe:fKOe2/7c9sN3zfZR1m+RGlcXy6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_dcb1c7a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcb1c7a3a5ec3692a7db6e4d0d0f83f653ab5440e1510cf2e841fa3a3fcae48e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:24:08"
  condition:
    hash.sha256(0, filesize) == "dcb1c7a3a5ec3692a7db6e4d0d0f83f653ab5440e1510cf2e841fa3a3fcae48e"
}
```

### Sample 39: `10933cdc27941297`

| Field | Value |
|---|---|
| SHA-256 | `10933cdc279412973d81c953e6d73169e8e79194e400223a64e02a1494b9debc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 03:22:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2bf44908307acb73fc90e604b955b00` |
| SHA-1 | `692936604bae9422c872d7e8bd80819c8af210c4` |
| SHA-256 | `10933cdc279412973d81c953e6d73169e8e79194e400223a64e02a1494b9debc` |
| SHA3-384 | `be28ba3627d87642591bba98760494e708085ee531e9e707fc98b575784fcfc21a5eab92bf17e7a877e99dddd24f178e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13C62B68ADCB25F6CCE4F90703A91FC78BD703690866559E3D7868D205DA39E10524EFE` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGpmmmmmmmmmq6C:fKOeOQOzUxpmmmmmmmmmq6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_10933cdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10933cdc279412973d81c953e6d73169e8e79194e400223a64e02a1494b9debc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:22:19"
  condition:
    hash.sha256(0, filesize) == "10933cdc279412973d81c953e6d73169e8e79194e400223a64e02a1494b9debc"
}
```

### Sample 40: `ee799a275576298a`

| Field | Value |
|---|---|
| SHA-256 | `ee799a275576298a32b5a2056072125abb6dece35c029a5780ff0694200d59fc` |
| Family label | `unknown` |
| File name | `3798wi.exe` |
| File type | `exe` |
| First seen | `2026-09-23 03:19:59` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0108656a3e1ade6ca4f21b084f5e1208` |
| SHA-1 | `00ee97ad5fc27d02b867acbd83f387883dcbde08` |
| SHA-256 | `ee799a275576298a32b5a2056072125abb6dece35c029a5780ff0694200d59fc` |
| SHA3-384 | `4362f1474e14f0377230750c57540fb895305152368ac42a55e7dfc2f87ca07f3379f3fd6612dd9e4a96193f6f77c95e` |
| IMPHASH | `1ebeee7c84e45d461ab0a3b58184339c` |
| TLSH | `T15FE35C5773E530F9E1B78239C9611646E77278360B219BEF03A446762F276D08E3EB21` |
| SSDEEP | `3072:BCM1WzKD1hyCtF6F+aB7MDZn5A37DSAvJW:4McQ1K+yMDJ5YHBW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_ee799a27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee799a275576298a32b5a2056072125abb6dece35c029a5780ff0694200d59fc"
    family = "unknown"
    file_name = "3798wi.exe"
    file_type = "exe"
    first_seen = "2026-09-23 03:19:59"
  condition:
    hash.sha256(0, filesize) == "ee799a275576298a32b5a2056072125abb6dece35c029a5780ff0694200d59fc"
}
```

### Sample 41: `19f0ad8353353007`

| Field | Value |
|---|---|
| SHA-256 | `19f0ad8353353007973b04a1f954171d2313ca2873d54559c8a95af0ca693ccc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 03:19:58` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a1a64afb9c7ae8bb615fec482542d34` |
| SHA-1 | `2918cbac0609703b5fb993ff6d26c2866a85edce` |
| SHA-256 | `19f0ad8353353007973b04a1f954171d2313ca2873d54559c8a95af0ca693ccc` |
| SHA3-384 | `6b4eaa9ad5463bc6e938f9f890b759e3752a0186fade013deac29b2061e4b1be1f9292ab33518f8ea114be19bee743de` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11E62E786E9A21F5CCE4F80713A51F83CBEB4729196255DE3DB828D345EA39D00224FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJVBgn:fKOe2/7c9sN3zfZR1m+RGIV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_19f0ad83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19f0ad8353353007973b04a1f954171d2313ca2873d54559c8a95af0ca693ccc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:19:58"
  condition:
    hash.sha256(0, filesize) == "19f0ad8353353007973b04a1f954171d2313ca2873d54559c8a95af0ca693ccc"
}
```

### Sample 42: `021d8ad84c75a5c6`

| Field | Value |
|---|---|
| SHA-256 | `021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b` |
| Family label | `Mirai` |
| File name | `021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b` |
| File type | `elf` |
| First seen | `2026-09-23 03:17:42` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dc6049fa5170e41288c4e11791f508c` |
| SHA-1 | `b93f46bcea3651ea62fa9a95c5bfaaf3234827b8` |
| SHA-256 | `021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b` |
| SHA3-384 | `2f7fdbb3f2d157180a03333d591acd12521731be4281d520ebc8911084ea2f246926e9c3440ee7cf40dc5722b9412522` |
| TLSH | `T183C3089BBC91EE694AC0177BFE2E418E330327B4D1DF71139D141F58B68A94F0E6A642` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEe:T2s/gAWuboqsJ9xcJxspJBqQgTe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_021d8ad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b"
    family = "Mirai"
    file_name = "021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b"
    file_type = "elf"
    first_seen = "2026-09-23 03:17:42"
  condition:
    hash.sha256(0, filesize) == "021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b"
}
```

### Sample 43: `abf5bf38dbcc7e42`

| Field | Value |
|---|---|
| SHA-256 | `abf5bf38dbcc7e42b04ea66a09b709d31fc4626800d9f36ebf1054a770ffe740` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 03:17:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d105b44ae2a743331ad7a17e6fc9c58` |
| SHA-1 | `6a63c118ff113e0fa701343e7dedff53eb9e06e9` |
| SHA-256 | `abf5bf38dbcc7e42b04ea66a09b709d31fc4626800d9f36ebf1054a770ffe740` |
| SHA3-384 | `041dd192c51aed4819091e1104fd90b4ed19f6d3e99218915df507cbe53ba94c7298f8a707cd4217a8bdf24c809f3828` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16262D787D8922E6CDE4F80703A11F978BDB4B2A1866559EBD7C28C315DBB9D10024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UpyBgn:fKOe2/7c9sN3zfZR1m+RG36C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_abf5bf38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abf5bf38dbcc7e42b04ea66a09b709d31fc4626800d9f36ebf1054a770ffe740"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:17:08"
  condition:
    hash.sha256(0, filesize) == "abf5bf38dbcc7e42b04ea66a09b709d31fc4626800d9f36ebf1054a770ffe740"
}
```

### Sample 44: `48ae8f71ac725373`

| Field | Value |
|---|---|
| SHA-256 | `48ae8f71ac725373e7744a12f6fdabc2e2cd13e5a775ca91c5c47f5d90060ae4` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-23 03:05:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d18244f13285ac6f5f6c2b8648fc1e8` |
| SHA-1 | `db1b9b72f1042ae772f87e024e4fd9f0d9113326` |
| SHA-256 | `48ae8f71ac725373e7744a12f6fdabc2e2cd13e5a775ca91c5c47f5d90060ae4` |
| SHA3-384 | `efe9337b7bb2a6bdb314d5e69ab844a00f41daf4cf3aefd838b48f226d5783139d36e79f74ba1f958ba8621bb9725369` |
| TLSH | `T18634F71AAF610FFBE86FCD3746E90B0125CC640722A53B753678D928F54A54B8AD3C78` |
| SSDEEP | `3072:QHe+ipVuRvNQIuIE4P3kCKBtC/bcuLzk4asnAHAW:QHe+v2IrcltCwuM4be` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_48ae8f71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48ae8f71ac725373e7744a12f6fdabc2e2cd13e5a775ca91c5c47f5d90060ae4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 03:05:26"
  condition:
    hash.sha256(0, filesize) == "48ae8f71ac725373e7744a12f6fdabc2e2cd13e5a775ca91c5c47f5d90060ae4"
}
```

### Sample 45: `5cea0b0d51fd134f`

| Field | Value |
|---|---|
| SHA-256 | `5cea0b0d51fd134f5c950d888c5ef374ffc49c126956c39908962805110c1167` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-09-23 03:04:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4e85672d2a8cf9fd95480c4de4b96cd` |
| SHA-1 | `593ca237fc0ff4e787de0e3e6ca3db0e2a2c8e5d` |
| SHA-256 | `5cea0b0d51fd134f5c950d888c5ef374ffc49c126956c39908962805110c1167` |
| SHA3-384 | `458ec2e565b5259b091ab49f276215e80a6d65a247eb6cc9f3ef1f1fdc3926e59022a83ee04c731f5dfcad41ae5a8633` |
| TLSH | `T1A573027F78D91ADDC47686FE8721031DA686F6CC305CC66C1620ACA8F3724226B4E6B5` |
| SSDEEP | `1536:iFq7Vq8+h+uW0oH+Q26Idpq5sA3SQ+tXGSOwlAHfciHnuRKK2ptaYN3S:y2c8+hhl50sA3SZtd7y/cSnlK2Fi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_5cea0b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cea0b0d51fd134f5c950d888c5ef374ffc49c126956c39908962805110c1167"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 03:04:53"
  condition:
    hash.sha256(0, filesize) == "5cea0b0d51fd134f5c950d888c5ef374ffc49c126956c39908962805110c1167"
}
```

### Sample 46: `1f1943e839be8027`

| Field | Value |
|---|---|
| SHA-256 | `1f1943e839be8027ca943dd14b04993c7a18592b406056f847e44aa89e0909ba` |
| Family label | `Mirai` |
| File name | `ooikocqj.armv6l` |
| File type | `elf` |
| First seen | `2026-09-23 03:04:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0516f5a5bad7e950e208f13555ce04db` |
| SHA-1 | `f5c8076eb255c3e7c315870e9eba424b6355a12d` |
| SHA-256 | `1f1943e839be8027ca943dd14b04993c7a18592b406056f847e44aa89e0909ba` |
| SHA3-384 | `2cc72754a9fd3907a14b4eebe3de18f00dc7b5240b1891bd66a25d0af209c236b43cae2be95f94c1cb7331b2b179f39f` |
| TLSH | `T153153955F8C09F62C9D46576F65E82A83323477DC2E7F30689148A383B978AF4B3A741` |
| TELFHASH | `t113a002171895c61d573b9f189cea074610831c33fc6d3d6a5e5cdf558525505075ccaf` |
| SSDEEP | `24576:2Ev1NcoIxsto4U735e0aubvAB6k2BonuN6p:xvP8xQNA4B6k2BoHp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_1f1943e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f1943e839be8027ca943dd14b04993c7a18592b406056f847e44aa89e0909ba"
    family = "Mirai"
    file_name = "ooikocqj.armv6l"
    file_type = "elf"
    first_seen = "2026-09-23 03:04:51"
  condition:
    hash.sha256(0, filesize) == "1f1943e839be8027ca943dd14b04993c7a18592b406056f847e44aa89e0909ba"
}
```

### Sample 47: `feeea9d0bf6ae739`

| Field | Value |
|---|---|
| SHA-256 | `feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3` |
| Family label | `unknown` |
| File name | `crond` |
| File type | `elf` |
| First seen | `2026-09-23 03:03:53` |
| Reporter | `KnownSpotter` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `826cd8037c91f04d8a45ca8c64564051` |
| SHA-1 | `202001c5768fed6ed72aa7272faca353d88291d5` |
| SHA-256 | `feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3` |
| SHA3-384 | `d1d057b1296f6e7cf2b47d25328a18d11ea3f13e2cf14be106ef29e18d9706e97cbfd38224b41a282a36cd6e8b3d8a62` |
| TLSH | `T117935C4AB67299BCC185C9304AFF92315670B555E221AB3F36009B382E11F5D2F1FF66` |
| TELFHASH | `t12e213013993f8e6b7bf6dca16c79113e43039616a051df24af6449c5a8f4019b240ace` |
| SSDEEP | `1536:z2759BvTAXDRTnmGzhys48hHdgjeX1/GUfJGe6TcN:qxTAFmGn44mm1/GURGe6T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_feeea9d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3"
    family = "unknown"
    file_name = "crond"
    file_type = "elf"
    first_seen = "2026-09-23 03:03:53"
  condition:
    hash.sha256(0, filesize) == "feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3"
}
```

### Sample 48: `041a167b5bfd9f25`

| Field | Value |
|---|---|
| SHA-256 | `041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58` |
| Family label | `Prometei` |
| File name | `041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58` |
| File type | `elf` |
| First seen | `2026-09-23 02:51:01` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afe54c42e7a7b01b9168aeb92a7874a9` |
| SHA-1 | `9d58827392302628993437dbc6a79a219e4fb7b5` |
| SHA-256 | `041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58` |
| SHA3-384 | `cd43ab19b8d294e3f66831a19b820182b4a4ba4c83be4b84161982b1b4204db089036bd6c1705552729b502d9c4af9ac` |
| TLSH | `T125A423B4F9219E9F6DD769F91B24831DE182C172589D4C2313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdY:Fs6pyCC/Ya2hpi6T6N4m` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_048_041a167b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58"
    family = "Prometei"
    file_name = "041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58"
    file_type = "elf"
    first_seen = "2026-09-23 02:51:01"
  condition:
    hash.sha256(0, filesize) == "041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58"
}
```

### Sample 49: `fbbd51ba22eb51dc`

| Field | Value |
|---|---|
| SHA-256 | `fbbd51ba22eb51dc456668de69c1a3b8d4a310235580b0fc9489a4c34a1babd6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:46:15` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df643c8aee83e81fd41fabed09b4f59b` |
| SHA-1 | `eb20bf8052103cdc4bd53eeecaab5ffde441a36e` |
| SHA-256 | `fbbd51ba22eb51dc456668de69c1a3b8d4a310235580b0fc9489a4c34a1babd6` |
| SHA3-384 | `f612a0266305f5764fe7409cefe7ccbe1eb743cedbd942df4d671fe1748736856450d9f6c8bc9a1da6b0173cd3b53df0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16062C586D8A22F6CCE4FD0703A11F878AD7572958A665DE3D7828C349DB79D00424FBE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U9sBgn:fKOe2/7c9sN3zfZR1m+RGSs6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_fbbd51ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbbd51ba22eb51dc456668de69c1a3b8d4a310235580b0fc9489a4c34a1babd6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:46:15"
  condition:
    hash.sha256(0, filesize) == "fbbd51ba22eb51dc456668de69c1a3b8d4a310235580b0fc9489a4c34a1babd6"
}
```

### Sample 50: `50d6553326817c8d`

| Field | Value |
|---|---|
| SHA-256 | `50d6553326817c8db02a2ccdb725eb6c441871e6e713706f0f4f33a0f1259083` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:43:15` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ce941b2c3703ecf5445ee4fc3c20327` |
| SHA-1 | `2889dbd9596dc2cde20cc3b2e386375b40254153` |
| SHA-256 | `50d6553326817c8db02a2ccdb725eb6c441871e6e713706f0f4f33a0f1259083` |
| SHA3-384 | `34c67b7425c598243e52bbf289ef278bad26973edfb23df47fe7932ea44612c3c313b32daee532d29dc401cdd3aefba6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D362D69AD9B22F9DCE4E90707A11F83879B576D0866579E3C782CC349EA39C04434EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UOM9BM:fKOe2/7c9sN3zfZR1m+RGtM96C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_50d65533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d6553326817c8db02a2ccdb725eb6c441871e6e713706f0f4f33a0f1259083"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:43:15"
  condition:
    hash.sha256(0, filesize) == "50d6553326817c8db02a2ccdb725eb6c441871e6e713706f0f4f33a0f1259083"
}
```

### Sample 51: `4946c356490263d5`

| Field | Value |
|---|---|
| SHA-256 | `4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e` |
| Family label | `unknown` |
| File name | `4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e.bin` |
| File type | `zip` |
| First seen | `2026-09-23 02:41:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `630f2c65f92c7df23ff97545f2abb8f4` |
| SHA-1 | `514bb5f39a9035e042b3c8b437893c126c84b1b6` |
| SHA-256 | `4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e` |
| SHA3-384 | `282f2536a742453eef67ea36c72b6d00b1d97768e17fb6c7b133c6f5623132fbe46f3380098db6a15ee3af0e1612a2b0` |
| TLSH | `T117F31260FD23C1C8999041AD6EAD8D0C2EB91DDF951969C5FD92E32A17B601C2EBF43C` |
| SSDEEP | `3072:7EMB22MLSm5lD6HWM7qHPEF5NsKXOVfR6KOLwe1z0:3B22MLxHf0qHsF5mKMfR/U0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_4946c356
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e"
    family = "unknown"
    file_name = "4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e.bin"
    file_type = "zip"
    first_seen = "2026-09-23 02:41:18"
  condition:
    hash.sha256(0, filesize) == "4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e"
}
```

### Sample 52: `03ae3d23abb5c1cf`

| Field | Value |
|---|---|
| SHA-256 | `03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b` |
| Family label | `unknown` |
| File name | `03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b.bin` |
| File type | `exe` |
| First seen | `2026-09-23 02:41:16` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85f5cd858dddfa76c473e90a4e9ecd67` |
| SHA-1 | `a6514b9a8ebaf1561394147faf542b84b8f11641` |
| SHA-256 | `03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b` |
| SHA3-384 | `6ed08f39898d543037b4948c41ffaffa86cdc08b95ee8155146aac2e2da6938933efc0f838331e3c987d9d9543858583` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B8F4E01517D89964F5BFAB34C5B535208BF1B903C722DB9EA50854EE1D32BC2CA6B323` |
| SSDEEP | `12288:+a60DpZb55qXmP31Xjz9UT/C8Mqo0oHQlyFsea3g/3g6:nD3b5cXU1Tz9KCNsye3K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_03ae3d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b"
    family = "unknown"
    file_name = "03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:41:16"
  condition:
    hash.sha256(0, filesize) == "03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b"
}
```

### Sample 53: `bb37893f7690e7ad`

| Field | Value |
|---|---|
| SHA-256 | `bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3` |
| Family label | `unknown` |
| File name | `bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3.bin` |
| File type | `exe` |
| First seen | `2026-09-23 02:41:13` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2405267f8cca1e05258c24a26a831a25` |
| SHA-1 | `4c507b2c243fd945ec0237bb62d875a969a0ff3c` |
| SHA-256 | `bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3` |
| SHA3-384 | `a15dfb2c3473f05694d404ad3fa00e734713ae2f297884239b4fa3e5a8913092c556b0c8284450b2e14a692f40d70127` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14991D74270B989E7E89C51BB4D0FB8A0B91D740A41C483A70378A5953E3967BF5BCB0D` |
| SSDEEP | `48:6IIF9BlQaexg0MgZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMg0VA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_bb37893f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3"
    family = "unknown"
    file_name = "bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:41:13"
  condition:
    hash.sha256(0, filesize) == "bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3"
}
```

### Sample 54: `47671e892be8809f`

| Field | Value |
|---|---|
| SHA-256 | `47671e892be8809f5c7c1f127733afcd5ee27d2c78db20e48f7794175c76cd97` |
| Family label | `unknown` |
| File name | `ProtobufLite.dll` |
| File type | `exe` |
| First seen | `2026-09-23 02:26:27` |
| Reporter | `Parper` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `790a8f563962f22e367768edbf4bfe19` |
| SHA-1 | `93eb0d0cb44582f85df7b02733ad58322f281f08` |
| SHA-256 | `47671e892be8809f5c7c1f127733afcd5ee27d2c78db20e48f7794175c76cd97` |
| SHA3-384 | `1a830edaefbff5344d44cb84312b019c20da8269f432862164ca870a4ecb55e14a8f0834306eed131fae6dea91ad8c56` |
| IMPHASH | `ad9fe34fe5f9267ff1c10d689801a190` |
| TLSH | `T17A78AFB273C4EEFAC041D97A5705F23181A2986E8BB691C46F92870A5DF5A114F3CBDC` |
| SSDEEP | `393216:Pq43p9CrNhfwyGeISASXc7kVpnZTNz1IJ0grPlCJqhxhkjS76ydzkUB0WDxOVDh:ghf1LI4X7pnpNmJRJCJ6ajad4WDx6Dh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_47671e89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47671e892be8809f5c7c1f127733afcd5ee27d2c78db20e48f7794175c76cd97"
    family = "unknown"
    file_name = "ProtobufLite.dll"
    file_type = "exe"
    first_seen = "2026-09-23 02:26:27"
  condition:
    hash.sha256(0, filesize) == "47671e892be8809f5c7c1f127733afcd5ee27d2c78db20e48f7794175c76cd97"
}
```

### Sample 55: `be14a0558f90aa9b`

| Field | Value |
|---|---|
| SHA-256 | `be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db` |
| Family label | `unknown` |
| File name | `be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db.bin` |
| File type | `exe` |
| First seen | `2026-09-23 02:21:05` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e473be0a0efc656df7d89c6870906c07` |
| SHA-1 | `e0a23298da7b84352c3375bda38dbe2ac348f44f` |
| SHA-256 | `be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db` |
| SHA3-384 | `fcc170f217e08511aa229e6ccf2d5f04bb375cfb49451cabde676fdf958c96e45d3a4559725d6ed1429f8a7a7ee5dc82` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T186C1832563F8873BD6378B39ACB657015578BB03AD13CB5D65D8220B9E27B100DB3B26` |
| SSDEEP | `48:6z+tZKHds5Dd2DMBIT+WbjNMaxWZHurLQHur5d1HurIVej/P7qBs1niGECtaKl2S:I2wAc+ULD50gejj+s1nz9C5zNt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_be14a055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db"
    family = "unknown"
    file_name = "be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:21:05"
  condition:
    hash.sha256(0, filesize) == "be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db"
}
```

### Sample 56: `c462396719067866`

| Field | Value |
|---|---|
| SHA-256 | `c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2` |
| Family label | `unknown` |
| File name | `c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2.bin` |
| File type | `exe` |
| First seen | `2026-09-23 02:21:02` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `376503b9592dfba219c5378a5961be33` |
| SHA-1 | `06a472ceb395f2dd0208aaa95bcf68c35df5535b` |
| SHA-256 | `c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2` |
| SHA3-384 | `ef98f7c51a905b78635d38aeac24e087598ae6cc10c0055f2ab149d91e7263792adf1e6dcbd20311b1e252a143af966e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15B02205463F9051AE2FB7F702DB647204B76FD52DA3AC76D1988001E1E61790CA72BB2` |
| SSDEEP | `96:zOE/HkpS2AVEoL2tP9J7mZXyt1oaxOC5wFAj3W3DQjNzNt:6E/kpS2oEoCMXXIB6gn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_c4623967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2"
    family = "unknown"
    file_name = "c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:21:02"
  condition:
    hash.sha256(0, filesize) == "c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2"
}
```

### Sample 57: `4aed3e0f4f54209b`

| Field | Value |
|---|---|
| SHA-256 | `4aed3e0f4f54209b3530f405ca0e06259e3007e2e204501470e711f38bf13be3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:19:07` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b67a3ded543d61d45f71707f0129a58` |
| SHA-1 | `aff4ffcf9b025bb035838841ff855aeb2700e654` |
| SHA-256 | `4aed3e0f4f54209b3530f405ca0e06259e3007e2e204501470e711f38bf13be3` |
| SHA3-384 | `1d86a0b55f4377d09bf15e0cd3ce2037654c61ffcf14c497f471480675725b9eb3bfe957b2fcc0da6a13037413fcc235` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11562C78AD9E21F9CDE4E80703B11F878BE707691956569E7DB828C315EA39E00034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UL1ff5:fKOe2/7c9sN3zfZR1m+RGw1nI6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_4aed3e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aed3e0f4f54209b3530f405ca0e06259e3007e2e204501470e711f38bf13be3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:19:07"
  condition:
    hash.sha256(0, filesize) == "4aed3e0f4f54209b3530f405ca0e06259e3007e2e204501470e711f38bf13be3"
}
```

### Sample 58: `6a293d4dacb57c50`

| Field | Value |
|---|---|
| SHA-256 | `6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e` |
| Family label | `Mozi` |
| File name | `6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e` |
| File type | `elf` |
| First seen | `2026-09-23 02:17:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips, Mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7492d85361a1974b825b927b82dc186` |
| SHA-1 | `cfadf6ca03310d78eb3eaf48b3bfeed00765558e` |
| SHA-256 | `6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e` |
| SHA3-384 | `be070f63942b86379c6691fb94a30d86add20141b9871bfd925d42ff7eb7f9e2c16e51389d481945fda577e3f9bf00a0` |
| TLSH | `T10CF2019C3902844BC532297AB54FA99978D30F5A345F4D6C25FAD1398BF331CABB131A` |
| SSDEEP | `768:TDoQtBTX941eYFDgNbl5PatCbYUmQAvv/wY0:XtBTX941eYF8Nblpuvnwf` |

#### Technical Assessment

- The sample is tracked as `Mozi` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mozi_058_6a293d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e"
    family = "Mozi"
    file_name = "6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e"
    file_type = "elf"
    first_seen = "2026-09-23 02:17:18"
  condition:
    hash.sha256(0, filesize) == "6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e"
}
```

### Sample 59: `956a85bba448779e`

| Field | Value |
|---|---|
| SHA-256 | `956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35` |
| Family label | `Mirai` |
| File name | `956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35` |
| File type | `elf` |
| First seen | `2026-09-23 02:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c38116dd3e54aa2afd1246ea7f5228b5` |
| SHA-1 | `51733d53130792bde7e375cf7cf1be4b6cb42a59` |
| SHA-256 | `956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35` |
| SHA3-384 | `c1303526db45c2d421f7110cd0e02dfb7c14aeb47a6f4fdda9e43f7523697ebc7226825180553fcbd2c6b92694c9558e` |
| TLSH | `T1A0543A8AFD81AF25D5C1267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJI:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_956a85bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35"
    family = "Mirai"
    file_name = "956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35"
    file_type = "elf"
    first_seen = "2026-09-23 02:17:13"
  condition:
    hash.sha256(0, filesize) == "956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35"
}
```

### Sample 60: `5ee50c437279a1a1`

| Field | Value |
|---|---|
| SHA-256 | `5ee50c437279a1a1d8e52e0ca73af4ff0812df44b80a0bceacfb2373fdc17022` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:16:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79c730c4087a2161d8da74983d474e5f` |
| SHA-1 | `da2ba76044a885f846fdd94ffd10532bb5d32c1c` |
| SHA-256 | `5ee50c437279a1a1d8e52e0ca73af4ff0812df44b80a0bceacfb2373fdc17022` |
| SHA3-384 | `5cfbc76f72aede156c693248fcd6ee3dec4842c3f48bb2dbf149ed46c73381036787253a13dc7997cced3e4e5dd380c8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D062B497D8A26E5CDE8EC0703A21F838A9B436D486A55DE3D7C28C645DA39D01038FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UgfVpe:fKOe2/7c9sN3zfZR1m+RGVp6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_5ee50c43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ee50c437279a1a1d8e52e0ca73af4ff0812df44b80a0bceacfb2373fdc17022"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:16:47"
  condition:
    hash.sha256(0, filesize) == "5ee50c437279a1a1d8e52e0ca73af4ff0812df44b80a0bceacfb2373fdc17022"
}
```

### Sample 61: `0ca3f34bef48e3e8`

| Field | Value |
|---|---|
| SHA-256 | `0ca3f34bef48e3e884da8d3581252f65a44ddb2a23a7785ba616689b3375138f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:16:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61dac1c322491c3b2b4852de92b917e6` |
| SHA-1 | `812d8baedf1d1193ff3d62a6817852bd2fe1788c` |
| SHA-256 | `0ca3f34bef48e3e884da8d3581252f65a44ddb2a23a7785ba616689b3375138f` |
| SHA3-384 | `c6b42fdf360a5dd8a60cbd6328e20bf379c06c6795e62681deadf3a0fc25d4e8e631c4efdfba65f5e73680d6be79a0bf` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12962F886DDA25E5DDE4F80B03A10FD786DB436E0866669E3D7828C365DA38E04134FF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGeGpUsssssssss66C:fKOeOQOzUxeGpy6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_0ca3f34b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ca3f34bef48e3e884da8d3581252f65a44ddb2a23a7785ba616689b3375138f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:16:39"
  condition:
    hash.sha256(0, filesize) == "0ca3f34bef48e3e884da8d3581252f65a44ddb2a23a7785ba616689b3375138f"
}
```

### Sample 62: `da7991c62cc464ca`

| Field | Value |
|---|---|
| SHA-256 | `da7991c62cc464cab40536b2764bd37292d965e64187c58f3b17aef544ca3d21` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:14:14` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e39e3bd6afde75cf9eabb4441bc5742` |
| SHA-1 | `3008d5dd53cfb86f476d069a2864d3afee48b95c` |
| SHA-256 | `da7991c62cc464cab40536b2764bd37292d965e64187c58f3b17aef544ca3d21` |
| SHA3-384 | `fa35b9316a22195c6db4745552f3a8f7d560279443f5591c787b2a94a7af63dde1bfa640ae80e1099a7a56e9522a65b5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10062C78AD8921F5CDE8ED0703A51F838ADB436A09A6559F7D7828C315DA39D04134FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UtBgCc:fKOe2/7c9sN3zfZR1m+RGG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_da7991c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da7991c62cc464cab40536b2764bd37292d965e64187c58f3b17aef544ca3d21"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:14:14"
  condition:
    hash.sha256(0, filesize) == "da7991c62cc464cab40536b2764bd37292d965e64187c58f3b17aef544ca3d21"
}
```

### Sample 63: `11cdfd56cec58044`

| Field | Value |
|---|---|
| SHA-256 | `11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a` |
| Family label | `unknown` |
| File name | `11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a.bin` |
| File type | `exe` |
| First seen | `2026-09-23 02:12:16` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `741d214b250c3510fe4cf6445c6203b2` |
| SHA-1 | `ed2c6af45528812f9c9fe785b942eb648a0292fa` |
| SHA-256 | `11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a` |
| SHA3-384 | `15d115e7088b6f3818f552de47b28b249e5eacb29cbb83607a158c92cbe9259b7340744d7539912e1fe749efbc595fd8` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T17D667C0B6981909CC566EB39D26B0731BB357889C73533D72E51BAB43F2ABD45DB8B00` |
| SSDEEP | `49152:nPoJQ7UdQzoYYmTIT/WzKCHr/Iumvxwxtnm37HWYeMYT3cLAPqOy1oxwboUT1lk6:PozmCT/ZwywXYeOOGkemwtvH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_11cdfd56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a"
    family = "unknown"
    file_name = "11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:12:16"
  condition:
    hash.sha256(0, filesize) == "11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a"
}
```

### Sample 64: `b550586f9b3e2ac7`

| Field | Value |
|---|---|
| SHA-256 | `b550586f9b3e2ac7c8d0c71f14e845bdd116a7c1de0f51236387bb4f67995334` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:10:29` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `033de3b14d5226dc4f9691ad1e6e2d7f` |
| SHA-1 | `8eb7cd6c414f4d2decfb83caefd261dc193206f4` |
| SHA-256 | `b550586f9b3e2ac7c8d0c71f14e845bdd116a7c1de0f51236387bb4f67995334` |
| SHA3-384 | `6a84f0664ae227e6c1b1a2ec232e3d3b1a52dbcedf5e1e8a1ac49995db2afdd9067f7fe6b44aa6664b1a38e379373e89` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12062D7CAD8D32E6DCF4E80703A21FA28B974779486269DE7D7928C3559779C00024EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UHQJYp:fKOe2/7c9sN3zfZR1m+RGRlR6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_b550586f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b550586f9b3e2ac7c8d0c71f14e845bdd116a7c1de0f51236387bb4f67995334"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:10:29"
  condition:
    hash.sha256(0, filesize) == "b550586f9b3e2ac7c8d0c71f14e845bdd116a7c1de0f51236387bb4f67995334"
}
```

### Sample 65: `ff81d2cd053320f9`

| Field | Value |
|---|---|
| SHA-256 | `ff81d2cd053320f91747bae417dae27d467af2c13df1f08998c9f2b38deab21f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:08:07` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `368448cb8b90723cc7aa104b0bbdd88f` |
| SHA-1 | `cff193c8c356894382f897c121b69b0d72737a7a` |
| SHA-256 | `ff81d2cd053320f91747bae417dae27d467af2c13df1f08998c9f2b38deab21f` |
| SHA3-384 | `aefd5ccdc511a281ba3fd48b6104799afff7d7fc7af0d4bc99d65703464f236ca9557a68601c86c2f870e2cab69fb42f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18D62C6C6DD926E6CCE4EC0B03A11F928A9707691C6666DE7D7828C7199A38D00468FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uu7Bgn:fKOe2/7c9sN3zfZR1m+RGf76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_ff81d2cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff81d2cd053320f91747bae417dae27d467af2c13df1f08998c9f2b38deab21f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:08:07"
  condition:
    hash.sha256(0, filesize) == "ff81d2cd053320f91747bae417dae27d467af2c13df1f08998c9f2b38deab21f"
}
```

### Sample 66: `da6788c86de7e6e6`

| Field | Value |
|---|---|
| SHA-256 | `da6788c86de7e6e6406daa84625566fb41c62658641993c00194e84654c61264` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 02:05:37` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33041165fcb84759cf2344484087e20b` |
| SHA-1 | `70cf3f188c2ec6a0ffe317a5228c59cbbe6bd90f` |
| SHA-256 | `da6788c86de7e6e6406daa84625566fb41c62658641993c00194e84654c61264` |
| SHA3-384 | `7f99df1d60fb761430a06a2c196a2fa93f30c5e7eef68a592ffb130bb0f7f4bd65fda8aaec66b4ce8e83c85c411623ca` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10262C786EAA21F9CDE4F80713A11F878ADB536908AA55DE3D7C18C395DA39D40024FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UafBgn:fKOe2/7c9sN3zfZR1m+RGb6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_da6788c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da6788c86de7e6e6406daa84625566fb41c62658641993c00194e84654c61264"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:05:37"
  condition:
    hash.sha256(0, filesize) == "da6788c86de7e6e6406daa84625566fb41c62658641993c00194e84654c61264"
}
```

### Sample 67: `f14b02f3fb8787dc`

| Field | Value |
|---|---|
| SHA-256 | `f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc` |
| Family label | `unknown` |
| File name | `f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc.bin` |
| File type | `macho` |
| First seen | `2026-09-23 02:00:08` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2834e2fd0451269ad088437f36f634eb` |
| SHA-1 | `6e220ef009c8ed4dcaf9a863e3516d9bfe51dc4f` |
| SHA-256 | `f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc` |
| SHA3-384 | `d1cd2ce469d722b9791b4c4572aa5965353403f3f11686bc844d67a2eb2223ca89f2e81cf23f076be41c1ccb52d53a5f` |
| TLSH | `T1F9E24F43675C5929D05D83B922FB5B576609F8A009D45B432F50DA282FE23C4BCB0EDB` |
| SSDEEP | `96:xcIZEe5DbDP67li97WsCywYjqclS06W1YbqclSl:GI2e5DbDy0wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_f14b02f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc"
    family = "unknown"
    file_name = "f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc.bin"
    file_type = "macho"
    first_seen = "2026-09-23 02:00:08"
  condition:
    hash.sha256(0, filesize) == "f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc"
}
```

### Sample 68: `21a454b27913a088`

| Field | Value |
|---|---|
| SHA-256 | `21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c` |
| Family label | `unknown` |
| File name | `21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c.bin` |
| File type | `macho` |
| First seen | `2026-09-23 02:00:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d252ace69b4749ffe1a0ba054e3f82a4` |
| SHA-1 | `35108692f2f25ce681262cff61bc36efbf69281a` |
| SHA-256 | `21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c` |
| SHA3-384 | `d9161e8815553432b06625c7a321fc1031d5bb7a276c6162eecf84ff559002e29f76096017e4c29242ed075960e8542d` |
| TLSH | `T1F4F25F139B1C0A61C15C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BEB9D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMR3YPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJf7lilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_21a454b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c"
    family = "unknown"
    file_name = "21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c.bin"
    file_type = "macho"
    first_seen = "2026-09-23 02:00:04"
  condition:
    hash.sha256(0, filesize) == "21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c"
}
```

### Sample 69: `b9afd4c60ce2ce3f`

| Field | Value |
|---|---|
| SHA-256 | `b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7` |
| Family label | `unknown` |
| File name | `b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7.apk` |
| File type | `apk` |
| First seen | `2026-09-23 01:50:05` |
| Reporter | `Tuxxin` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23d16f8bcde804442becb730b9abab6a` |
| SHA-1 | `76162eeda1c3a26d2f4cc614596166d9e655a129` |
| SHA-256 | `b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7` |
| SHA3-384 | `1265997286d63137490be7ffe2b7e81df20c04cf584e349cf389a55ca85c08a9d2e05707062c507c6623fc1af7d34b82` |
| TLSH | `T17AA55B0BA2814B33DC6F1370C5AAFB716F31A95B7F53470B424CA2F12C976E76686186` |
| SSDEEP | `24576:O4wHOlia/xpZ40BkHTEfv1QPJcSmM8jlI4Q03wzhB97pltdPjFbFGZQIYyhhLoO:sRJcll3wR7PjFboZqsv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_b9afd4c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7"
    family = "unknown"
    file_name = "b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7.apk"
    file_type = "apk"
    first_seen = "2026-09-23 01:50:05"
  condition:
    hash.sha256(0, filesize) == "b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7"
}
```

### Sample 70: `e973567fb5e8dd6a`

| Field | Value |
|---|---|
| SHA-256 | `e973567fb5e8dd6a1aafcd9070ef094163d6cd3e8c46ff87bf6d376c6ced7857` |
| Family label | `unknown` |
| File name | `1` |
| File type | `elf` |
| First seen | `2026-09-23 01:48:45` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8268401dd991b90a243d0c8537b9cc20` |
| SHA-1 | `abd7cd62de3bf2e6de84f7ee4c7ca82c0ab68915` |
| SHA-256 | `e973567fb5e8dd6a1aafcd9070ef094163d6cd3e8c46ff87bf6d376c6ced7857` |
| SHA3-384 | `0fc548017184986d02ff89c029d069d054d74e5345acfbd5419c4d62065539c708603a482cffb25c1e86619103dea171` |
| TLSH | `T14B7423FA2228C419FCA6F9F20E853B7A36B59094E117DFF305C3D9DED8A5600D569702` |
| SSDEEP | `6144:BxJZASyWYgGgQG2CQu/3wuV+8YiaFXAe9eJd2T6YhXmOEvmNoqaeh3BMHzg5C:BxJ2S5QGTPJ8NAee0zh2OR+qae2YC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_e973567f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e973567fb5e8dd6a1aafcd9070ef094163d6cd3e8c46ff87bf6d376c6ced7857"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-23 01:48:45"
  condition:
    hash.sha256(0, filesize) == "e973567fb5e8dd6a1aafcd9070ef094163d6cd3e8c46ff87bf6d376c6ced7857"
}
```

### Sample 71: `a787b00a19442ff0`

| Field | Value |
|---|---|
| SHA-256 | `a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd` |
| Family label | `Prometei` |
| File name | `a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd` |
| File type | `elf` |
| First seen | `2026-09-23 01:47:09` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `182e1ac14ccdb71f62654d0021563c67` |
| SHA-1 | `0b962a82e96013803a1e91f568cbb13f9888e225` |
| SHA-256 | `a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd` |
| SHA3-384 | `d2a1198d505ae75fb3a351f6087bf4b5c1c449be54ed5606f0bed1fd6d91970893bd466f5ba42568d36e3f0ac29908cd` |
| TLSH | `T100A423B4F9219E9F6DD769B91B24831DE181C172689D4C2313AE94A34F3D632BF2CC16` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdH:Fs6pyCC/Ya2hpi6T6N4l` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_071_a787b00a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd"
    family = "Prometei"
    file_name = "a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd"
    file_type = "elf"
    first_seen = "2026-09-23 01:47:09"
  condition:
    hash.sha256(0, filesize) == "a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd"
}
```

### Sample 72: `4ca6f100fbcfbfca`

| Field | Value |
|---|---|
| SHA-256 | `4ca6f100fbcfbfcaee45a133be263c68760d9ec37a49cd62732f04abd50f18a3` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-23 01:38:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcfdf4a5f9f29b690c144025a153c6f7` |
| SHA-1 | `18cfa18ec2d2f71729a6d7a8b1f329636788055c` |
| SHA-256 | `4ca6f100fbcfbfcaee45a133be263c68760d9ec37a49cd62732f04abd50f18a3` |
| SHA3-384 | `17e97bb5eeb4ce0130f54e12780f8fa9abf77b42bd4ac5501eb494096acf4236fbc453118cd499d9697fbf35cd936273` |
| TLSH | `T10F234AC59643D0F1DD1622B0107B5B61DEB6C4336A75FB87EBA8263AEC53B409A0736C` |
| TELFHASH | `t15021aab76fd508fcf7a07c0d674967967a5aaa330a10356200f72ed533e25e290be831` |
| SSDEEP | `768:WWC37l3sezMp5Sf1Iib3mRhKcl2MfHTCEHC0gPvqqMjRE:S7l3se4Qfe52Jw+YCZKrlE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_4ca6f100
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ca6f100fbcfbfcaee45a133be263c68760d9ec37a49cd62732f04abd50f18a3"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-23 01:38:47"
  condition:
    hash.sha256(0, filesize) == "4ca6f100fbcfbfcaee45a133be263c68760d9ec37a49cd62732f04abd50f18a3"
}
```

### Sample 73: `b5bc4df55a68fb59`

| Field | Value |
|---|---|
| SHA-256 | `b5bc4df55a68fb59e944cba393e5dc60533ed9f965a4f523d8714dd2829a02a9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 01:37:21` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05eb005be357541358ddfe7dbf8edf36` |
| SHA-1 | `37188dde7ca14aa264f0ad1dbaada7c10a2afa31` |
| SHA-256 | `b5bc4df55a68fb59e944cba393e5dc60533ed9f965a4f523d8714dd2829a02a9` |
| SHA3-384 | `29b2f2032057aeb9eb1c600208cdf879169217ec216f7162f291db4da12fac84ec02c45ee451f7ec76a22f5fa3bbc074` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12662C796D8922E5CCE4F80703A11FC7CAD7476A08A665AE7D7828C315DB39D08534FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UXiBgn:fKOe2/7c9sN3zfZR1m+RGV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_b5bc4df5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5bc4df55a68fb59e944cba393e5dc60533ed9f965a4f523d8714dd2829a02a9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:37:21"
  condition:
    hash.sha256(0, filesize) == "b5bc4df55a68fb59e944cba393e5dc60533ed9f965a4f523d8714dd2829a02a9"
}
```

### Sample 74: `3dc561622fb319c9`

| Field | Value |
|---|---|
| SHA-256 | `3dc561622fb319c9e1770ed313741f8616a1a996fe274adc999ef558c0b15bb1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 01:34:44` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79b3f09a4a0b5dddb20b6e228fac0b6e` |
| SHA-1 | `d0cb434b452752f65044babeac2d1b12fa5241f6` |
| SHA-256 | `3dc561622fb319c9e1770ed313741f8616a1a996fe274adc999ef558c0b15bb1` |
| SHA3-384 | `00e54f1d32c93a6d58c48a8b8b12e5b5ed605da5245ff9b44f215258d48a43629314fa2e77c4f6f89afcdb210e7059d1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17262C886E8A16F5DDE4E80703A11F978BAB036948965ADF3D782CD345EA39D00034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UkBgCc:fKOe2/7c9sN3zfZR1m+RG76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_3dc56162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc561622fb319c9e1770ed313741f8616a1a996fe274adc999ef558c0b15bb1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:34:44"
  condition:
    hash.sha256(0, filesize) == "3dc561622fb319c9e1770ed313741f8616a1a996fe274adc999ef558c0b15bb1"
}
```

### Sample 75: `0e83a08555ce1a8d`

| Field | Value |
|---|---|
| SHA-256 | `0e83a08555ce1a8d4579c455b49b3af8bbfcbd54dfb6190a15a974f168b63826` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 01:32:29` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9638444ece7f98fe9f0603255341546` |
| SHA-1 | `0464acb57cc1f2e21156c36c32beed19af22b5ba` |
| SHA-256 | `0e83a08555ce1a8d4579c455b49b3af8bbfcbd54dfb6190a15a974f168b63826` |
| SHA3-384 | `5a124260c39ee97ce773e7d7dfed5787b12d27cf4526b5e0565321192e7d8034f20353b7defe8e69c8a473110c13bf1b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10462C79ADCD22E9CDE4FC0703A11FC7879B13691866699E3D7868C205DA39D00474EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UggBgn:fKOe2/7c9sN3zfZR1m+RG26C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_0e83a085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e83a08555ce1a8d4579c455b49b3af8bbfcbd54dfb6190a15a974f168b63826"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:32:29"
  condition:
    hash.sha256(0, filesize) == "0e83a08555ce1a8d4579c455b49b3af8bbfcbd54dfb6190a15a974f168b63826"
}
```

### Sample 76: `a34be6b062691b7f`

| Field | Value |
|---|---|
| SHA-256 | `a34be6b062691b7f9483b0522f34136c510d91c31c3461afaf3d199e22f17b5b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 01:32:16` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54fa97827b2f5c0a948da62dbab25d4a` |
| SHA-1 | `002d7dd4040dba5b73eab0077c4e0647bc11c3e3` |
| SHA-256 | `a34be6b062691b7f9483b0522f34136c510d91c31c3461afaf3d199e22f17b5b` |
| SHA3-384 | `70e3cd1b013a32aea58c0d7000928740d156236a114389bf0c9311d269009c2eada7db8ebb0c4cb8e65a84ac29bb8e4d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10A62C686D8926F5CCE4E80703E21FD78BDB036D48A6559E3DB828C359DA79D00524FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U0mBgn:fKOe2/7c9sN3zfZR1m+RGxm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_a34be6b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a34be6b062691b7f9483b0522f34136c510d91c31c3461afaf3d199e22f17b5b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:32:16"
  condition:
    hash.sha256(0, filesize) == "a34be6b062691b7f9483b0522f34136c510d91c31c3461afaf3d199e22f17b5b"
}
```

### Sample 77: `1d17a1ad15631672`

| Field | Value |
|---|---|
| SHA-256 | `1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61` |
| Family label | `Mirai` |
| File name | `1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61.bin` |
| File type | `elf` |
| First seen | `2026-09-23 01:30:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc47c8f952b81ad027c18fe11755c3bd` |
| SHA-1 | `64813b41e43490a2db2f9f0de4fa261c1ed973bf` |
| SHA-256 | `1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61` |
| SHA3-384 | `abce35945ed9b13a2e73e93f51d6bd0546e48b1227ceb28429ab5cc4285b513b2a16df521004d4dd68696f47fef63ca3` |
| TLSH | `T1A2220D27F3D4DDFBC8AA5335899307713223C83ADB828383691C56593F9A29D1E65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMORx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeT+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_1d17a1ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61"
    family = "Mirai"
    file_name = "1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61.bin"
    file_type = "elf"
    first_seen = "2026-09-23 01:30:05"
  condition:
    hash.sha256(0, filesize) == "1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61"
}
```

### Sample 78: `1228cea5a4f51e5f`

| Field | Value |
|---|---|
| SHA-256 | `1228cea5a4f51e5f7ba8ddd4fcbb5f04f903e20c4e5729ddf1b9d5f70e3f1cd1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 01:29:54` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdab6f1f90aea8335cd594fd807ad1f2` |
| SHA-1 | `cf91d05372137a1640f79a97c9ff6d9f050adc25` |
| SHA-256 | `1228cea5a4f51e5f7ba8ddd4fcbb5f04f903e20c4e5729ddf1b9d5f70e3f1cd1` |
| SHA3-384 | `484839aa1b15bf3dc4148b5a8fa4d06ec1782001ddd613cdbd003a77702c0aec9e40fc396cfe9bad6d53a223d644cdb6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E462C69AECA21A5ECE4E80703A51FD287D717694866599E7D7828C705FB38D00028FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UETJ8e:fKOe2/7c9sN3zfZR1m+RGPTS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_1228cea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1228cea5a4f51e5f7ba8ddd4fcbb5f04f903e20c4e5729ddf1b9d5f70e3f1cd1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:29:54"
  condition:
    hash.sha256(0, filesize) == "1228cea5a4f51e5f7ba8ddd4fcbb5f04f903e20c4e5729ddf1b9d5f70e3f1cd1"
}
```

### Sample 79: `e5358f378fa606f9`

| Field | Value |
|---|---|
| SHA-256 | `e5358f378fa606f9f6be2a087c16e6634336dd1a89a4ce9f1113994d335dda3a` |
| Family label | `unknown` |
| File name | `aws.sh` |
| File type | `unknown` |
| First seen | `2026-09-23 01:26:54` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95c0947e99832943b63b9129082de6d3` |
| SHA-256 | `e5358f378fa606f9f6be2a087c16e6634336dd1a89a4ce9f1113994d335dda3a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_e5358f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5358f378fa606f9f6be2a087c16e6634336dd1a89a4ce9f1113994d335dda3a"
    family = "unknown"
    file_name = "aws.sh"
    file_type = "unknown"
    first_seen = "2026-09-23 01:26:54"
  condition:
    hash.sha256(0, filesize) == "e5358f378fa606f9f6be2a087c16e6634336dd1a89a4ce9f1113994d335dda3a"
}
```

### Sample 80: `d5caf6c474da5cd1`

| Field | Value |
|---|---|
| SHA-256 | `d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361` |
| Family label | `unknown` |
| File name | `d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361.bin` |
| File type | `macho` |
| First seen | `2026-09-23 01:20:05` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8447bd9b550911402a064baa9bfadb6` |
| SHA-1 | `44951714256ad98e674a2d83fd0f63193c8c8f5d` |
| SHA-256 | `d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361` |
| SHA3-384 | `88ed2845c7ff88f641f95a8061c2a56979a150711eb14fec98840047923e68c170519131e7b1b6588785cf7b87551057` |
| TLSH | `T15BF263239B1C5922C48C663842BB6742A23AF1E145D677774B00C72DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7QHu4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7AuMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_d5caf6c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361"
    family = "unknown"
    file_name = "d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361.bin"
    file_type = "macho"
    first_seen = "2026-09-23 01:20:05"
  condition:
    hash.sha256(0, filesize) == "d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361"
}
```

### Sample 81: `d21928d2e22565c6`

| Field | Value |
|---|---|
| SHA-256 | `d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34` |
| Family label | `Mirai` |
| File name | `d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34` |
| File type | `elf` |
| First seen | `2026-09-23 01:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7787ab048b5bb18ebae4d2e6b5123c` |
| SHA-1 | `197108bc66b83120f1f46103e2e1dfcd4d15f00b` |
| SHA-256 | `d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34` |
| SHA3-384 | `134923c90fadc452bc7a51c69a1422b2259f17688a117fe19732915a812ce652f417c182d6f88c5bed264311b1952086` |
| TLSH | `T1E1C3188BBC81DE6946C0277BFE2E418E330327B4D1DF71139D141F28B68A94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaD:T2s/gAWuboqsJ9xcJxspJBqQgTuaD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_d21928d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34"
    family = "Mirai"
    file_name = "d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34"
    file_type = "elf"
    first_seen = "2026-09-23 01:17:12"
  condition:
    hash.sha256(0, filesize) == "d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34"
}
```

### Sample 82: `ae32602195154326`

| Field | Value |
|---|---|
| SHA-256 | `ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd` |
| Family label | `WannaCry` |
| File name | `ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd` |
| File type | `exe` |
| First seen | `2026-09-23 01:15:57` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9d0acaab0d0a1cae7b11ab2fff541e8` |
| SHA-1 | `30325cac4d73566f1634f680d35a51bd290e03da` |
| SHA-256 | `ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd` |
| SHA3-384 | `62988dc087b62b84db40ec70c5f3943689043cf5f6a682dab33a5c413b56f72e58e524bfe99186445460cd901e8b02a9` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T17F24AE09369C80B4D45A5275C8F35E29E3B3BC4E4339860F4B58DA6A1F63391B939F27` |
| SSDEEP | `6144:jIYVTH5DgSgDE9l9ynRIYVTH5DgSgNajldktS:jbLgD1bLgmlJ` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_082_ae326021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd"
    family = "WannaCry"
    file_name = "ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd"
    file_type = "exe"
    first_seen = "2026-09-23 01:15:57"
  condition:
    hash.sha256(0, filesize) == "ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd"
}
```

### Sample 83: `f593a772075022c1`

| Field | Value |
|---|---|
| SHA-256 | `f593a772075022c10744d049d5a748fc9599968adb2df73b6db3c4ddce80d100` |
| Family label | `unknown` |
| File name | `192837455732.ps1` |
| File type | `ps1` |
| First seen | `2026-09-23 01:10:34` |
| Reporter | `skocherhan` |
| Tags | `d36rb13t9es4g1-cloudfront-net, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `873bce155638701a2e1f9bacc194b2b9` |
| SHA-1 | `206a7e4898c6ade25abbed99168aa55de064e9b1` |
| SHA-256 | `f593a772075022c10744d049d5a748fc9599968adb2df73b6db3c4ddce80d100` |
| SHA3-384 | `17e3616737d23f907d3c3a9ccfbfd5ffb6ff40dd54feaaa46dcccc171997d9c28456553d9baa3e4afd1366591bb43ace` |
| TLSH | `T191F15138B501A1B186762739CE425009FF27126B5539611CF8EDC5892FB436FC7A4FAE` |
| SSDEEP | `192:Pr4uPto7WOxHkHgtEk0n9oWfDa+za+eJtBnaG7UBH6mhwFKd5VFKgtFq:HPto7WOxEA6keO+O+eB6OAFAio` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_f593a772
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f593a772075022c10744d049d5a748fc9599968adb2df73b6db3c4ddce80d100"
    family = "unknown"
    file_name = "192837455732.ps1"
    file_type = "ps1"
    first_seen = "2026-09-23 01:10:34"
  condition:
    hash.sha256(0, filesize) == "f593a772075022c10744d049d5a748fc9599968adb2df73b6db3c4ddce80d100"
}
```

### Sample 84: `9581909f8fcd4859`

| Field | Value |
|---|---|
| SHA-256 | `9581909f8fcd48590f208532e7081bd9d9e96697fa3463e3766e028d4f20176d` |
| Family label | `unknown` |
| File name | `NOTICE OF DOF ADJUSTMENT FOR IMPORT SHIPMENTS FROM 01 OCT 2026-SITC.pdf.gz` |
| File type | `gz` |
| First seen | `2026-09-23 01:09:26` |
| Reporter | `anonymous` |
| Tags | `gz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98bbe047f3170530048c25886e64951c` |
| SHA-1 | `c6e3d5ebe4ce24c01d9afab22c760aa7988ad0fb` |
| SHA-256 | `9581909f8fcd48590f208532e7081bd9d9e96697fa3463e3766e028d4f20176d` |
| SHA3-384 | `d018c41f855c851d47507b0d91790e06bec62b7d82297f82880d197c940fab4ce3f1093dbbff5b5ceb46e09e0bb56bfd` |
| TLSH | `T1357533900360B6E53E3C6029AFD6B39D93B48C545A1C07197D0E12AEEA5B9FFD9BC314` |
| SSDEEP | `49152:TaRkquNI2RvSfdUDPMlOyqpL0cN4K+ZKcg:XHI2RqFVqV9uK+Zu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_9581909f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9581909f8fcd48590f208532e7081bd9d9e96697fa3463e3766e028d4f20176d"
    family = "unknown"
    file_name = "NOTICE OF DOF ADJUSTMENT FOR IMPORT SHIPMENTS FROM 01 OCT 2026-SITC.pdf.gz"
    file_type = "gz"
    first_seen = "2026-09-23 01:09:26"
  condition:
    hash.sha256(0, filesize) == "9581909f8fcd48590f208532e7081bd9d9e96697fa3463e3766e028d4f20176d"
}
```

### Sample 85: `446df5308fdc7107`

| Field | Value |
|---|---|
| SHA-256 | `446df5308fdc7107753d5af859ebf9d458571da20a31fd19c9cffc77d51d37d4` |
| Family label | `unknown` |
| File name | `NEW TARIFF OF TERMINAL HANDLING CHARGE (THC).pdf.gz` |
| File type | `gz` |
| First seen | `2026-09-23 01:08:59` |
| Reporter | `anonymous` |
| Tags | `gz` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49c0321d7f514798943d1e69b98cd8ea` |
| SHA-1 | `3690f5b966d6bfdb45fc277fd5d9cb03d81b5cdb` |
| SHA-256 | `446df5308fdc7107753d5af859ebf9d458571da20a31fd19c9cffc77d51d37d4` |
| SHA3-384 | `b0bfda3f61a11416f5d0f29b1d479029f173f7162a00050607ba696953d2566fece2c92df4ce9fd6e55dad89672cb154` |
| TLSH | `T1FB14129A6935ABB6DD6D4B51AC2E60B7305400F202786BDC2F86F43DE76C23A118D73D` |
| SSDEEP | `6144:y48feMRfSD3H20jtd3HG8cCaH3v28phVU58F5x:W2rD3fhJLcCaH3npzU58Fr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_446df530
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446df5308fdc7107753d5af859ebf9d458571da20a31fd19c9cffc77d51d37d4"
    family = "unknown"
    file_name = "NEW TARIFF OF TERMINAL HANDLING CHARGE (THC).pdf.gz"
    file_type = "gz"
    first_seen = "2026-09-23 01:08:59"
  condition:
    hash.sha256(0, filesize) == "446df5308fdc7107753d5af859ebf9d458571da20a31fd19c9cffc77d51d37d4"
}
```

### Sample 86: `679f7f0f6d3578fb`

| Field | Value |
|---|---|
| SHA-256 | `679f7f0f6d3578fbda2c314e504464b6cda98f57c3981b790f7d72d97a0042f4` |
| Family label | `NetSupport` |
| File name | `liblivenet_amd64.dll` |
| File type | `exe` |
| First seen | `2026-09-23 01:08:12` |
| Reporter | `skocherhan` |
| Tags | `d3mz24vhl6xvgp-cloudfront-net, exe, NetSupport` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0066422310c880d5e722ba59ad315df1` |
| SHA-1 | `4a0be8da07ae878e7497881e8beae73a836fc258` |
| SHA-256 | `679f7f0f6d3578fbda2c314e504464b6cda98f57c3981b790f7d72d97a0042f4` |
| SHA3-384 | `f3115f9138afe13e5ef7a77e103d522d8c5feee3aab225ae422fb44442c7a9f2b70394b6237f6bf2ad6bff2a11b50313` |
| IMPHASH | `3271ee162568f50a6810be9b8973807f` |
| TLSH | `T1CC375DC3E8A31A94C4EAC275D16681DBBA627C081B3833D716A1FB302B3FBD45676751` |
| SSDEEP | `196608:t8uONNO3vweU1Gk++GNglNDiMU63Q6Oah8Kth8:tUNEU1Gk++GalN+MU6A6O+0` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_086_679f7f0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679f7f0f6d3578fbda2c314e504464b6cda98f57c3981b790f7d72d97a0042f4"
    family = "NetSupport"
    file_name = "liblivenet_amd64.dll"
    file_type = "exe"
    first_seen = "2026-09-23 01:08:12"
  condition:
    hash.sha256(0, filesize) == "679f7f0f6d3578fbda2c314e504464b6cda98f57c3981b790f7d72d97a0042f4"
}
```

### Sample 87: `eda6ed7f7f715c8d`

| Field | Value |
|---|---|
| SHA-256 | `eda6ed7f7f715c8dc16793bebf83784bf6d405ed2cd8576202175f9a893601b3` |
| Family label | `unknown` |
| File name | `CopilotService.exe` |
| File type | `exe` |
| First seen | `2026-09-23 01:05:22` |
| Reporter | `skocherhan` |
| Tags | `d3mz24vhl6xvgp-cloudfront-net, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d745bfd36ed7a54ad61487c31b7af874` |
| SHA-1 | `d767ab423214a64c076f882ff099252fed9feecb` |
| SHA-256 | `eda6ed7f7f715c8dc16793bebf83784bf6d405ed2cd8576202175f9a893601b3` |
| SHA3-384 | `01b6b0ad7a7f251273d43703374f3df01adf20906957add805cc378e93f5837e83f7a2e466d7eb0720c28b23b2a83cf9` |
| TLSH | `T1ACC1EB8997FD13B1E6F54B3468BBA3041B70ED058D269BCF264C32A97E91E803D52672` |
| SSDEEP | `96:sjgBc9d/i1XbJ+UbuWc1vYU+xV9IzufO0zNt:sIqinLSWc1QLLIzH+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_eda6ed7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda6ed7f7f715c8dc16793bebf83784bf6d405ed2cd8576202175f9a893601b3"
    family = "unknown"
    file_name = "CopilotService.exe"
    file_type = "exe"
    first_seen = "2026-09-23 01:05:22"
  condition:
    hash.sha256(0, filesize) == "eda6ed7f7f715c8dc16793bebf83784bf6d405ed2cd8576202175f9a893601b3"
}
```

### Sample 88: `c5f8c6927e6959c7`

| Field | Value |
|---|---|
| SHA-256 | `c5f8c6927e6959c7c30a8d0e0a2f00818f88cb0e7d20c9c1ed616669d5a75663` |
| Family label | `unknown` |
| File name | `63563545600333.ps1` |
| File type | `ps1` |
| First seen | `2026-09-23 01:02:57` |
| Reporter | `skocherhan` |
| Tags | `7jb7qi6vnr5pa22a4br4irz3tu0yqzbd-lambda-url-us-east-1-on-aws, dhrciu5akloar-cloudfront-net, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `614967f50cb101737f407cb74dfc4fd1` |
| SHA-1 | `f87c57d8e24a2873798a012f0fc6927980439165` |
| SHA-256 | `c5f8c6927e6959c7c30a8d0e0a2f00818f88cb0e7d20c9c1ed616669d5a75663` |
| SHA3-384 | `8aa0528b38455751054f8b6c658e4622603e53ab032922a258a0b85e46579f2b10cdba9969f59bcc865607b6772e6a28` |
| TLSH | `T13A126038650590B5C6B62739CE421109FF7B126B9029A01CB8DDC1892FB426EC7A4FBE` |
| SSDEEP | `192:Pr4uPto7WOxHIHgtEk0n9oWxDaxag4WSBda87M4WsB96cywFKd5VFKgtFq:HPto7WOxoA6ke4UP1NAFAio` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_c5f8c692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5f8c6927e6959c7c30a8d0e0a2f00818f88cb0e7d20c9c1ed616669d5a75663"
    family = "unknown"
    file_name = "63563545600333.ps1"
    file_type = "ps1"
    first_seen = "2026-09-23 01:02:57"
  condition:
    hash.sha256(0, filesize) == "c5f8c6927e6959c7c30a8d0e0a2f00818f88cb0e7d20c9c1ed616669d5a75663"
}
```

### Sample 89: `61107844953b648b`

| Field | Value |
|---|---|
| SHA-256 | `61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54` |
| Family label | `unknown` |
| File name | `61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54.bin` |
| File type | `macho` |
| First seen | `2026-09-23 01:01:12` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99a0b0f36529315970c3218ca44f0307` |
| SHA-1 | `e3e7c25114687fde103928acb2a422437c20e38f` |
| SHA-256 | `61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54` |
| SHA3-384 | `2c8e2ca1fee56146c6d5ad02c39386d7e10bce6bed5d506c69e004cb0d21c56330bb24f2412cd214509ea08a8b4e90e7` |
| TLSH | `T1A7E21B43AB4C8965C26D42301AF71BC6A615F5B09EE16B875750C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUqVZqDDt0TOTLZ0BbFw21HKk6XrMclSibFqAMcl:z4ZZXvv3VZMt0TO2bVx/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_61107844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54"
    family = "unknown"
    file_name = "61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54.bin"
    file_type = "macho"
    first_seen = "2026-09-23 01:01:12"
  condition:
    hash.sha256(0, filesize) == "61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54"
}
```

### Sample 90: `49b0c4a05fcd4e5b`

| Field | Value |
|---|---|
| SHA-256 | `49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505` |
| Family label | `unknown` |
| File name | `49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505.bin` |
| File type | `exe` |
| First seen | `2026-09-23 01:01:10` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50f3e6ccab3d61281d04c64381994468` |
| SHA-1 | `15f834ec853ed2ed88e3d30d4b482c58cb8dd50f` |
| SHA-256 | `49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505` |
| SHA3-384 | `bf0fbb6194766ccd4ef8e0e23d34d68545e0ecb838c860fa5e9146116f1bb285ef5b57b6c37d6f332586f0ac4d63fad6` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B613BE6133FD8E21E6FF8B305A770315877ABD5A1A2AD79E198024684ED67088931B37` |
| SSDEEP | `768:WUYQLdL89r+/OAtSM4mcG+TkZTZMfgld/0kplygKRU:WtQLdL89VUrcG+T8MMzEPW` |
| ICON-DHASH | `96694dd4d4496996` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_49b0c4a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505"
    family = "unknown"
    file_name = "49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505.bin"
    file_type = "exe"
    first_seen = "2026-09-23 01:01:10"
  condition:
    hash.sha256(0, filesize) == "49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505"
}
```

### Sample 91: `3eaf567479972592`

| Field | Value |
|---|---|
| SHA-256 | `3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd` |
| Family label | `unknown` |
| File name | `3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd.bin` |
| File type | `macho` |
| First seen | `2026-09-23 01:00:07` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ea9bcb8b402ca2e8782f024ab5ed2e0` |
| SHA-1 | `0cf3d531758d42eba7118eea37c52897fed1cc8a` |
| SHA-256 | `3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd` |
| SHA3-384 | `9a9194e6e8630c6d457dd7540061f373cd8cbebb0d3fb0e881547ad1e491317a4642577eda777225e9c6f51a34fe3aaa` |
| TLSH | `T1BEF22D139B1C1A61C15D633C92BB1B026276F5D086C56B674B10C72CAFCA385BDA5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRNPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJf0lilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_3eaf5674
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd"
    family = "unknown"
    file_name = "3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd.bin"
    file_type = "macho"
    first_seen = "2026-09-23 01:00:07"
  condition:
    hash.sha256(0, filesize) == "3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd"
}
```

### Sample 92: `6610a658f8064a9c`

| Field | Value |
|---|---|
| SHA-256 | `6610a658f8064a9c5d238fe9fa376db2e409a302a8c4f52c0fd3577a727fbf23` |
| Family label | `unknown` |
| File name | `PlutonAgent.exe` |
| File type | `exe` |
| First seen | `2026-09-23 00:58:22` |
| Reporter | `skocherhan` |
| Tags | `exe, pub-43fc211373d547278dd3d5bd0b4d9dac-r2-dev` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fdf8668882272280f1b53b4443a4906` |
| SHA-1 | `9ff6f01383fa33ab8d6b6e7f53d3e2df3bb9bb8f` |
| SHA-256 | `6610a658f8064a9c5d238fe9fa376db2e409a302a8c4f52c0fd3577a727fbf23` |
| SHA3-384 | `33a3fe7f66204845394055e790c0245d819ef483201f446fc36b0604a7679f65479ddfee2a8c384bb54fb4c4eb6bf0d4` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E5C64B07E8A545E5C0ADD1348A72D213BE717C495B3523D72B90FB282F77BE09ABA350` |
| SSDEEP | `98304:jdWI9xJF/vKXaBWLCHDcnT+T9smCoGWvGfixwhqeHp4bHMT84QpjpXdnpZpvwGrH:jdW0F/vYaBECHDgwGa6u6t45` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_6610a658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6610a658f8064a9c5d238fe9fa376db2e409a302a8c4f52c0fd3577a727fbf23"
    family = "unknown"
    file_name = "PlutonAgent.exe"
    file_type = "exe"
    first_seen = "2026-09-23 00:58:22"
  condition:
    hash.sha256(0, filesize) == "6610a658f8064a9c5d238fe9fa376db2e409a302a8c4f52c0fd3577a727fbf23"
}
```

### Sample 93: `a8baf83504a5782f`

| Field | Value |
|---|---|
| SHA-256 | `a8baf83504a5782f76a310a48eb80b19c3476d9cc13038edfb1041f2f1b2db8f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 00:57:48` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38ab92e155fc1fdb245009b6ee822245` |
| SHA-1 | `0606d558de560f4dba0be35aa15df3b41ff1a5b7` |
| SHA-256 | `a8baf83504a5782f76a310a48eb80b19c3476d9cc13038edfb1041f2f1b2db8f` |
| SHA3-384 | `72e7b95bb3583af11f46f14742bbb026f252b52cab937e2a49d13ca6590fc84d62e8a3f710863af824594440d57f3a20` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18862C586A8D26E5CDE4F80703A11F838BEB0369196699DE7D7C28C345AA38D00174FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UTwoBM:fKOe2/7c9sN3zfZR1m+RGY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_a8baf835
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8baf83504a5782f76a310a48eb80b19c3476d9cc13038edfb1041f2f1b2db8f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:57:48"
  condition:
    hash.sha256(0, filesize) == "a8baf83504a5782f76a310a48eb80b19c3476d9cc13038edfb1041f2f1b2db8f"
}
```

### Sample 94: `801fb26e8cb14860`

| Field | Value |
|---|---|
| SHA-256 | `801fb26e8cb14860719bcc96fce99e7e10bca39aeebbc9c5e3cc74af7d00a23b` |
| Family label | `unknown` |
| File name | `87648736456384.ps1` |
| File type | `ps1` |
| First seen | `2026-09-23 00:56:59` |
| Reporter | `skocherhan` |
| Tags | `ps1, pub-43fc211373d547278dd3d5bd0b4d9dac-r2-dev` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `843fb94bb64d69e1892c50c1c2008d74` |
| SHA-1 | `07cf4a5ba7bb30fb01a124d213f0b7e875d0c4ef` |
| SHA-256 | `801fb26e8cb14860719bcc96fce99e7e10bca39aeebbc9c5e3cc74af7d00a23b` |
| SHA3-384 | `0ebe9d4d599b4e870cfa7dfeb03df3f497ab48e81a214c03e3eb9033a52478aea012201aaf6cb51a6ffd134dcae93e45` |
| TLSH | `T162912158721151649A72AF39CD876D4AFF3F50AF10B31300769D51502FF2A2FCB98ACA` |
| SSDEEP | `96:yYkRxw4NQPI2eHg4A39/3lFZL1RwVwIwx0Aov09oKS0+3ooX0IoIg3LlG:vkRxog2eHgTxZLrizQo+oKO3oodoIH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_801fb26e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801fb26e8cb14860719bcc96fce99e7e10bca39aeebbc9c5e3cc74af7d00a23b"
    family = "unknown"
    file_name = "87648736456384.ps1"
    file_type = "ps1"
    first_seen = "2026-09-23 00:56:59"
  condition:
    hash.sha256(0, filesize) == "801fb26e8cb14860719bcc96fce99e7e10bca39aeebbc9c5e3cc74af7d00a23b"
}
```

### Sample 95: `df7b7fce3a2ae36d`

| Field | Value |
|---|---|
| SHA-256 | `df7b7fce3a2ae36d8bd0d5f25830cfda14b257d5019181837402d164208b8a56` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 00:56:32` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8541a6a32b5144360eeb71b91d5413f3` |
| SHA-1 | `a3f0ff73061c0be712af1b84a044810d6a60ee25` |
| SHA-256 | `df7b7fce3a2ae36d8bd0d5f25830cfda14b257d5019181837402d164208b8a56` |
| SHA3-384 | `5d9fb0c98ea2ca7e5b29eb6fcdeb59426dd4bd22d6fc4e8b5c4d1e9d76fe7f2a88b95376712badfea178aad375f861ae` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1DB62C687D9E22E5CDE4EC0707B11F878AD7032E086666AE7D792CC355DA38D10124EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UFxwBM:fKOe2/7c9sN3zfZR1m+RGEw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_df7b7fce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df7b7fce3a2ae36d8bd0d5f25830cfda14b257d5019181837402d164208b8a56"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:56:32"
  condition:
    hash.sha256(0, filesize) == "df7b7fce3a2ae36d8bd0d5f25830cfda14b257d5019181837402d164208b8a56"
}
```

### Sample 96: `5c7854279bf23801`

| Field | Value |
|---|---|
| SHA-256 | `5c7854279bf23801246a9309bf822a9801b1aa2518846e08e1169015561c6390` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 00:53:17` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcb1bfca85249d1dc5761d98725bd3fb` |
| SHA-1 | `679e3805ed14fd88eb88b16d138742da985a41c2` |
| SHA-256 | `5c7854279bf23801246a9309bf822a9801b1aa2518846e08e1169015561c6390` |
| SHA3-384 | `e2d2e35a7eacec016cd40214392102c866811fc9c488f3ee17f35586d31966c869931c847e19e618113f59aadbac3c19` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18862E886D8A29F6CCE4ED0703A20FC386D71B694956559E3D7828C304E639D05528FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UfgBgn:fKOe2/7c9sN3zfZR1m+RG4g6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_5c785427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c7854279bf23801246a9309bf822a9801b1aa2518846e08e1169015561c6390"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:53:17"
  condition:
    hash.sha256(0, filesize) == "5c7854279bf23801246a9309bf822a9801b1aa2518846e08e1169015561c6390"
}
```

### Sample 97: `c6534c50ab6aefa6`

| Field | Value |
|---|---|
| SHA-256 | `c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3` |
| Family label | `unknown` |
| File name | `c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3.bin` |
| File type | `elf` |
| First seen | `2026-09-23 00:50:09` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `329f69cbc1b0e22c9c9d30502c252bb6` |
| SHA-1 | `449c3e1bc066d2e727e1f0a136058dd6d4a11ca7` |
| SHA-256 | `c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3` |
| SHA3-384 | `affe67911ec7acb615c9ffb6afaeabade856d2740fab92eb9261a36d10069f1ec53fdc44de510ed42f62ea36644d4378` |
| TLSH | `T1EDE12482B9D6CE3BCCA962761673C6203372C551AB435B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsNLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv4g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_c6534c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3"
    family = "unknown"
    file_name = "c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3.bin"
    file_type = "elf"
    first_seen = "2026-09-23 00:50:09"
  condition:
    hash.sha256(0, filesize) == "c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3"
}
```

### Sample 98: `4f7e19a697092809`

| Field | Value |
|---|---|
| SHA-256 | `4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302` |
| Family label | `unknown` |
| File name | `4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302.bin` |
| File type | `macho` |
| First seen | `2026-09-23 00:50:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c932870d6f6da126ca146a8131fdba0e` |
| SHA-1 | `e4e7c8d57dfc40d27710033b7965f1e1492dcf38` |
| SHA-256 | `4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302` |
| SHA3-384 | `fcc2deb76685717c2aa63493c6a605e667f8ec64042fb1003fd6144a1305aafcbc82273b985203e2b7652b4a98946d60` |
| TLSH | `T13BE22C43AB4C9965C26D42301AF71BC6A615F5B09EE16B8B5750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvU3VZqDDt0TOTLZ0BbFw2OHKk6XrMclSibFqAMcl:z4ZZXvviVZMt0TO2bVS/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_4f7e19a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302"
    family = "unknown"
    file_name = "4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302.bin"
    file_type = "macho"
    first_seen = "2026-09-23 00:50:04"
  condition:
    hash.sha256(0, filesize) == "4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302"
}
```

### Sample 99: `fbc4ea95c798b07e`

| Field | Value |
|---|---|
| SHA-256 | `fbc4ea95c798b07e9a25b83948547adb9f35319ff92170aff574581c2d9a56e3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-23 00:40:16` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a387e7a405863000ff0569df819aecdb` |
| SHA-1 | `f78ff0aa992d997348ed2756428125d62fe92063` |
| SHA-256 | `fbc4ea95c798b07e9a25b83948547adb9f35319ff92170aff574581c2d9a56e3` |
| SHA3-384 | `e6a1c364ad11045e9228b514a237c5293a025cc5df2913a130f39821d84b0481ecff3c120e8be53ad39073edefebdac5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17E62D686EDA21F5CDE4F90703A11F838BD7436908A65A9E3D7928D305DA39D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UfMZTM:fKOe2/7c9sN3zfZR1m+RGHZtb6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_fbc4ea95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbc4ea95c798b07e9a25b83948547adb9f35319ff92170aff574581c2d9a56e3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:40:16"
  condition:
    hash.sha256(0, filesize) == "fbc4ea95c798b07e9a25b83948547adb9f35319ff92170aff574581c2d9a56e3"
}
```

### Sample 100: `d5e7f9f93dcee175`

| Field | Value |
|---|---|
| SHA-256 | `d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d` |
| Family label | `unknown` |
| File name | `d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d.bin` |
| File type | `macho` |
| First seen | `2026-09-23 00:40:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a92214ca31a8dadda2b353d22bf05b4d` |
| SHA-1 | `a81155ad93fe64a37b117f47fd16dfdcae62daf1` |
| SHA-256 | `d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d` |
| SHA3-384 | `171a6416b3d504af99fccaf2f185e327f069f4e7f1cf209d7d84373c258a4536e0f7c5dc24362aa6b27636aab94616c9` |
| TLSH | `T10DE24F43675C5929D05D83B962FB1B976609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEB5DbDP67li97WsCtwYjqclS06W1YbqclSl:GI2B5DbDy3wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_d5e7f9f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d"
    family = "unknown"
    file_name = "d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d.bin"
    file_type = "macho"
    first_seen = "2026-09-23 00:40:04"
  condition:
    hash.sha256(0, filesize) == "d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d"
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
 * Generated: 2026-09-23T04:52:21.366755+00:00
 */

rule MalwareBazaar_unknown_001_932918ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "932918ca4a481fffad2c2d4d84a9efa587c6f7bf15e2db5d06cccb8b91952c24"
    family = "unknown"
    file_name = "qzxuuppn.mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 04:50:49"
  condition:
    hash.sha256(0, filesize) == "932918ca4a481fffad2c2d4d84a9efa587c6f7bf15e2db5d06cccb8b91952c24"
}

rule MalwareBazaar_unknown_002_d6b7c2d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6b7c2d71ece0167cbbd7890dbe6586b11791336daef469ad5cec96851ce4977"
    family = "unknown"
    file_name = "armv6"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:51"
  condition:
    hash.sha256(0, filesize) == "d6b7c2d71ece0167cbbd7890dbe6586b11791336daef469ad5cec96851ce4977"
}

rule MalwareBazaar_Mirai_003_90a7cd85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90a7cd85a4510a5e91b4aa521fe676e349ff4ae87625654f1479902dcb8dfd82"
    family = "Mirai"
    file_name = "atjozltp.aarch64"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:49"
  condition:
    hash.sha256(0, filesize) == "90a7cd85a4510a5e91b4aa521fe676e349ff4ae87625654f1479902dcb8dfd82"
}

rule MalwareBazaar_Mirai_004_0b76c865
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b76c8658b63d3fadf501f94730e0938fd6bc31e72fd49a835073de230da494e"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:47"
  condition:
    hash.sha256(0, filesize) == "0b76c8658b63d3fadf501f94730e0938fd6bc31e72fd49a835073de230da494e"
}

rule MalwareBazaar_Mirai_005_4b5ded85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b5ded8502bb410554855b99607cf2eb98398633c1fb57c98e41b2980abbe7fd"
    family = "Mirai"
    file_name = "atjozltp.mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:46"
  condition:
    hash.sha256(0, filesize) == "4b5ded8502bb410554855b99607cf2eb98398633c1fb57c98e41b2980abbe7fd"
}

rule MalwareBazaar_Mirai_006_732e14f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "732e14f0a44613fbfd90cd4958a1d2171970b52adf283416f044fbea4957c460"
    family = "Mirai"
    file_name = "tpijtvcr.armv7l"
    file_type = "elf"
    first_seen = "2026-09-23 04:48:44"
  condition:
    hash.sha256(0, filesize) == "732e14f0a44613fbfd90cd4958a1d2171970b52adf283416f044fbea4957c460"
}

rule MalwareBazaar_Mirai_007_89611739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89611739301b0f2198c031d778988d4e38b11b29558a8187fa86517a146c42dc"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-09-23 04:44:53"
  condition:
    hash.sha256(0, filesize) == "89611739301b0f2198c031d778988d4e38b11b29558a8187fa86517a146c42dc"
}

rule MalwareBazaar_Mirai_008_3e10fb30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e10fb301b22deafe787b42d6f831529c166abb2d20b44c451d4896e648e1d4d"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-09-23 04:40:47"
  condition:
    hash.sha256(0, filesize) == "3e10fb301b22deafe787b42d6f831529c166abb2d20b44c451d4896e648e1d4d"
}

rule MalwareBazaar_Mirai_009_7ee4b047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ee4b047ea9f7d5d2256834aa19be02126eee3f4537d6c4e151dd97150869d66"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:40:46"
  condition:
    hash.sha256(0, filesize) == "7ee4b047ea9f7d5d2256834aa19be02126eee3f4537d6c4e151dd97150869d66"
}

rule MalwareBazaar_Mirai_010_88368ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88368ba34ac5787573bd7dca6cdbbe92252e1af73e73ac680bc944035d96a697"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-09-23 04:32:44"
  condition:
    hash.sha256(0, filesize) == "88368ba34ac5787573bd7dca6cdbbe92252e1af73e73ac680bc944035d96a697"
}

rule MalwareBazaar_unknown_011_fc1665cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc1665cc9bb3711e0de190d9d9b6c68f95559a4d468dbf2042057d2fff96cdf4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:32:09"
  condition:
    hash.sha256(0, filesize) == "fc1665cc9bb3711e0de190d9d9b6c68f95559a4d468dbf2042057d2fff96cdf4"
}

rule MalwareBazaar_unknown_012_af3f3183
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af3f31832f85215951298c7405d8d2c65291a185b4e6a23b3c7809f2ada5891f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:29:49"
  condition:
    hash.sha256(0, filesize) == "af3f31832f85215951298c7405d8d2c65291a185b4e6a23b3c7809f2ada5891f"
}

rule MalwareBazaar_unknown_013_13a7c2e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a7c2e9cf4306cf9c4d4844b4ee57b453aac66f74075ecddca99749ae3a10b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:27:28"
  condition:
    hash.sha256(0, filesize) == "13a7c2e9cf4306cf9c4d4844b4ee57b453aac66f74075ecddca99749ae3a10b2"
}

rule MalwareBazaar_Mirai_014_eaa82448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eaa824483bb71d265de52391e23a8826e24e82915e40585ea65911cac3f165b4"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-09-23 04:24:44"
  condition:
    hash.sha256(0, filesize) == "eaa824483bb71d265de52391e23a8826e24e82915e40585ea65911cac3f165b4"
}

rule MalwareBazaar_Mirai_015_5231a4a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5231a4a5575c46a7609e480f7be08526ef83dfe1c6e75975bc0755db39590fd8"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-09-23 04:22:44"
  condition:
    hash.sha256(0, filesize) == "5231a4a5575c46a7609e480f7be08526ef83dfe1c6e75975bc0755db39590fd8"
}

rule MalwareBazaar_Mirai_016_fe868c20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe868c20e94c8d178211f735c2000ca929d8a830449b43f7ded3b6354783c057"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:21:23"
  condition:
    hash.sha256(0, filesize) == "fe868c20e94c8d178211f735c2000ca929d8a830449b43f7ded3b6354783c057"
}

rule MalwareBazaar_Mirai_017_08296c24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08296c241afbe93df6a8b10508fa3ce3a97bfabaf29cfb06e124bbcf579a9705"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:49"
  condition:
    hash.sha256(0, filesize) == "08296c241afbe93df6a8b10508fa3ce3a97bfabaf29cfb06e124bbcf579a9705"
}

rule MalwareBazaar_Mirai_018_c6fbf5fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6fbf5fe81c3b2699bb62c71580cc22b695ff57cc95d60e73e7a73cb7d1a55cc"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:48"
  condition:
    hash.sha256(0, filesize) == "c6fbf5fe81c3b2699bb62c71580cc22b695ff57cc95d60e73e7a73cb7d1a55cc"
}

rule MalwareBazaar_Mirai_019_e31095dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e31095dc97bc60d6a9e57f61d097d7ec094d11f4a230a1f6198f9ccd4dc0a050"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:47"
  condition:
    hash.sha256(0, filesize) == "e31095dc97bc60d6a9e57f61d097d7ec094d11f4a230a1f6198f9ccd4dc0a050"
}

rule MalwareBazaar_Mirai_020_6a842ed1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a842ed17b29ce297db6846ef6082966263f10f0b4a27e0dd9805680bf578efa"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-23 04:20:45"
  condition:
    hash.sha256(0, filesize) == "6a842ed17b29ce297db6846ef6082966263f10f0b4a27e0dd9805680bf578efa"
}

rule MalwareBazaar_unknown_021_50878a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44"
    family = "unknown"
    file_name = "50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44"
    file_type = "elf"
    first_seen = "2026-09-23 04:17:34"
  condition:
    hash.sha256(0, filesize) == "50878a634b0af9c4b6a4ce5fac34d85d4f9600242e01f243a46f426dbdcf9c44"
}

rule MalwareBazaar_Mirai_022_2cf1e1b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce"
    family = "Mirai"
    file_name = "2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce"
    file_type = "elf"
    first_seen = "2026-09-23 04:17:29"
  condition:
    hash.sha256(0, filesize) == "2cf1e1b855f547868cf1b2ea8e1899012926f7d361dedf98b7a29bd9cdd65fce"
}

rule MalwareBazaar_unknown_023_f63dac09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f63dac099109470cb0223e919a2648c570b20225f63e9a3340a124203e2bc2dd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:15:35"
  condition:
    hash.sha256(0, filesize) == "f63dac099109470cb0223e919a2648c570b20225f63e9a3340a124203e2bc2dd"
}

rule MalwareBazaar_Mirai_024_ef715f19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef715f1952de9c27528cb58939e05fe2dd0a44056fbd3c0b70c64ac269508cb3"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:47"
  condition:
    hash.sha256(0, filesize) == "ef715f1952de9c27528cb58939e05fe2dd0a44056fbd3c0b70c64ac269508cb3"
}

rule MalwareBazaar_Mirai_025_6f069d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f069d0f236b15c77109939763abd5cbec9c2451e281e2a3e5008a3114f5722b"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:46"
  condition:
    hash.sha256(0, filesize) == "6f069d0f236b15c77109939763abd5cbec9c2451e281e2a3e5008a3114f5722b"
}

rule MalwareBazaar_Mirai_026_a26ee06a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a26ee06ad856826b09039273cb384788229fb501ea744a5497863271be972ce0"
    family = "Mirai"
    file_name = "wezpffnw.mips"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:45"
  condition:
    hash.sha256(0, filesize) == "a26ee06ad856826b09039273cb384788229fb501ea744a5497863271be972ce0"
}

rule MalwareBazaar_Mirai_027_dc0898da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc0898daf346ffa9431d8b0e0ac3ef2197939755e9da8352f4fc3d4209390087"
    family = "Mirai"
    file_name = "android-arm"
    file_type = "elf"
    first_seen = "2026-09-23 04:14:43"
  condition:
    hash.sha256(0, filesize) == "dc0898daf346ffa9431d8b0e0ac3ef2197939755e9da8352f4fc3d4209390087"
}

rule MalwareBazaar_unknown_028_31dc5729
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31dc572984be0c27e1387ddda3394b4243ba96d0a2ca1efac4891948eee8f3d4"
    family = "unknown"
    file_name = "IMG7838399201.IMG.scr"
    file_type = "exe"
    first_seen = "2026-09-23 04:12:56"
  condition:
    hash.sha256(0, filesize) == "31dc572984be0c27e1387ddda3394b4243ba96d0a2ca1efac4891948eee8f3d4"
}

rule MalwareBazaar_unknown_029_8709c237
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8709c2371700ae3072b3608ad94a1015a9c9125e80386f12d6a58f0c663eb895"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:12:56"
  condition:
    hash.sha256(0, filesize) == "8709c2371700ae3072b3608ad94a1015a9c9125e80386f12d6a58f0c663eb895"
}

rule MalwareBazaar_Mirai_030_ba08e640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba08e64054dea4400361094ac902903e6cc20e077901d0887e5b0f1252499ca8"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-23 04:12:44"
  condition:
    hash.sha256(0, filesize) == "ba08e64054dea4400361094ac902903e6cc20e077901d0887e5b0f1252499ca8"
}

rule MalwareBazaar_Mirai_031_9cb15298
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cb152989cc16081cc1e7559ff575365a93309e01468d9fd8feb75c6cb588bef"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-09-23 04:12:42"
  condition:
    hash.sha256(0, filesize) == "9cb152989cc16081cc1e7559ff575365a93309e01468d9fd8feb75c6cb588bef"
}

rule MalwareBazaar_unknown_032_fbbec0bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbbec0bbae6a37861bdad14dc8f6939d0a55f07da9df38f44b921cfd0c0cc33d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 04:10:31"
  condition:
    hash.sha256(0, filesize) == "fbbec0bbae6a37861bdad14dc8f6939d0a55f07da9df38f44b921cfd0c0cc33d"
}

rule MalwareBazaar_SilentNet_033_f280cf14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94"
    family = "SilentNet"
    file_name = "f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94.exe"
    file_type = "exe"
    first_seen = "2026-09-23 04:09:44"
  condition:
    hash.sha256(0, filesize) == "f280cf140a3f472080888207026d6c0e9f5ca0665f2fc48d5d2e3ad31b115d94"
}

rule MalwareBazaar_Mirai_034_eb1d3749
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb1d374931db60f740359426bafa103827d2cf6dbc89e91800e02913d3578695"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-23 04:04:51"
  condition:
    hash.sha256(0, filesize) == "eb1d374931db60f740359426bafa103827d2cf6dbc89e91800e02913d3578695"
}

rule MalwareBazaar_unknown_035_88a68b4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db"
    family = "unknown"
    file_name = "88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db.exe"
    file_type = "exe"
    first_seen = "2026-09-23 04:04:07"
  condition:
    hash.sha256(0, filesize) == "88a68b4f97b89818841f6d5b121ab67591f4b96baed7babc4f073d30b062b1db"
}

rule MalwareBazaar_Mirai_036_00df580e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00df580e13c658952545f6c73eadae574fbba094cafcafd213032afd77627068"
    family = "Mirai"
    file_name = "ypezhbfg.i686"
    file_type = "elf"
    first_seen = "2026-09-23 03:46:57"
  condition:
    hash.sha256(0, filesize) == "00df580e13c658952545f6c73eadae574fbba094cafcafd213032afd77627068"
}

rule MalwareBazaar_Mirai_037_7851a963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7851a963b1aec1da20ff097675a8c8adcb802a2bc326f7f2430a29224d8e723a"
    family = "Mirai"
    file_name = "ooikocqj.mips64"
    file_type = "elf"
    first_seen = "2026-09-23 03:40:49"
  condition:
    hash.sha256(0, filesize) == "7851a963b1aec1da20ff097675a8c8adcb802a2bc326f7f2430a29224d8e723a"
}

rule MalwareBazaar_unknown_038_dcb1c7a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcb1c7a3a5ec3692a7db6e4d0d0f83f653ab5440e1510cf2e841fa3a3fcae48e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:24:08"
  condition:
    hash.sha256(0, filesize) == "dcb1c7a3a5ec3692a7db6e4d0d0f83f653ab5440e1510cf2e841fa3a3fcae48e"
}

rule MalwareBazaar_unknown_039_10933cdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10933cdc279412973d81c953e6d73169e8e79194e400223a64e02a1494b9debc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:22:19"
  condition:
    hash.sha256(0, filesize) == "10933cdc279412973d81c953e6d73169e8e79194e400223a64e02a1494b9debc"
}

rule MalwareBazaar_unknown_040_ee799a27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee799a275576298a32b5a2056072125abb6dece35c029a5780ff0694200d59fc"
    family = "unknown"
    file_name = "3798wi.exe"
    file_type = "exe"
    first_seen = "2026-09-23 03:19:59"
  condition:
    hash.sha256(0, filesize) == "ee799a275576298a32b5a2056072125abb6dece35c029a5780ff0694200d59fc"
}

rule MalwareBazaar_unknown_041_19f0ad83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19f0ad8353353007973b04a1f954171d2313ca2873d54559c8a95af0ca693ccc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:19:58"
  condition:
    hash.sha256(0, filesize) == "19f0ad8353353007973b04a1f954171d2313ca2873d54559c8a95af0ca693ccc"
}

rule MalwareBazaar_Mirai_042_021d8ad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b"
    family = "Mirai"
    file_name = "021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b"
    file_type = "elf"
    first_seen = "2026-09-23 03:17:42"
  condition:
    hash.sha256(0, filesize) == "021d8ad84c75a5c678107ab748f15a7e83b03223e91ca253492b0cd1bfb6554b"
}

rule MalwareBazaar_unknown_043_abf5bf38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abf5bf38dbcc7e42b04ea66a09b709d31fc4626800d9f36ebf1054a770ffe740"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 03:17:08"
  condition:
    hash.sha256(0, filesize) == "abf5bf38dbcc7e42b04ea66a09b709d31fc4626800d9f36ebf1054a770ffe740"
}

rule MalwareBazaar_Mirai_044_48ae8f71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48ae8f71ac725373e7744a12f6fdabc2e2cd13e5a775ca91c5c47f5d90060ae4"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 03:05:26"
  condition:
    hash.sha256(0, filesize) == "48ae8f71ac725373e7744a12f6fdabc2e2cd13e5a775ca91c5c47f5d90060ae4"
}

rule MalwareBazaar_Mirai_045_5cea0b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cea0b0d51fd134f5c950d888c5ef374ffc49c126956c39908962805110c1167"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-09-23 03:04:53"
  condition:
    hash.sha256(0, filesize) == "5cea0b0d51fd134f5c950d888c5ef374ffc49c126956c39908962805110c1167"
}

rule MalwareBazaar_Mirai_046_1f1943e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f1943e839be8027ca943dd14b04993c7a18592b406056f847e44aa89e0909ba"
    family = "Mirai"
    file_name = "ooikocqj.armv6l"
    file_type = "elf"
    first_seen = "2026-09-23 03:04:51"
  condition:
    hash.sha256(0, filesize) == "1f1943e839be8027ca943dd14b04993c7a18592b406056f847e44aa89e0909ba"
}

rule MalwareBazaar_unknown_047_feeea9d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3"
    family = "unknown"
    file_name = "crond"
    file_type = "elf"
    first_seen = "2026-09-23 03:03:53"
  condition:
    hash.sha256(0, filesize) == "feeea9d0bf6ae7396d28271baa51ae50df5169ce5d32a516865856f91abc50b3"
}

rule MalwareBazaar_Prometei_048_041a167b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58"
    family = "Prometei"
    file_name = "041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58"
    file_type = "elf"
    first_seen = "2026-09-23 02:51:01"
  condition:
    hash.sha256(0, filesize) == "041a167b5bfd9f2576bb6c61ed0c34e98e43d6b84e4e63c2622b6f78d3294f58"
}

rule MalwareBazaar_unknown_049_fbbd51ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbbd51ba22eb51dc456668de69c1a3b8d4a310235580b0fc9489a4c34a1babd6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:46:15"
  condition:
    hash.sha256(0, filesize) == "fbbd51ba22eb51dc456668de69c1a3b8d4a310235580b0fc9489a4c34a1babd6"
}

rule MalwareBazaar_unknown_050_50d65533
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d6553326817c8db02a2ccdb725eb6c441871e6e713706f0f4f33a0f1259083"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:43:15"
  condition:
    hash.sha256(0, filesize) == "50d6553326817c8db02a2ccdb725eb6c441871e6e713706f0f4f33a0f1259083"
}

rule MalwareBazaar_unknown_051_4946c356
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e"
    family = "unknown"
    file_name = "4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e.bin"
    file_type = "zip"
    first_seen = "2026-09-23 02:41:18"
  condition:
    hash.sha256(0, filesize) == "4946c356490263d5f8c1484b6034ef513cedeaeb81ec1bad51716bafea2df52e"
}

rule MalwareBazaar_unknown_052_03ae3d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b"
    family = "unknown"
    file_name = "03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:41:16"
  condition:
    hash.sha256(0, filesize) == "03ae3d23abb5c1cf01397742367cb9ec6122ec8e521a059366c1e7b58575893b"
}

rule MalwareBazaar_unknown_053_bb37893f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3"
    family = "unknown"
    file_name = "bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:41:13"
  condition:
    hash.sha256(0, filesize) == "bb37893f7690e7ad8ce3a5aa33e8fd922475baf1c02e28b1c54c45f4c9343cc3"
}

rule MalwareBazaar_unknown_054_47671e89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47671e892be8809f5c7c1f127733afcd5ee27d2c78db20e48f7794175c76cd97"
    family = "unknown"
    file_name = "ProtobufLite.dll"
    file_type = "exe"
    first_seen = "2026-09-23 02:26:27"
  condition:
    hash.sha256(0, filesize) == "47671e892be8809f5c7c1f127733afcd5ee27d2c78db20e48f7794175c76cd97"
}

rule MalwareBazaar_unknown_055_be14a055
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db"
    family = "unknown"
    file_name = "be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:21:05"
  condition:
    hash.sha256(0, filesize) == "be14a0558f90aa9b3a7b7bb2dda6b8d10985de41a0f17608ab25b9d352bf40db"
}

rule MalwareBazaar_unknown_056_c4623967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2"
    family = "unknown"
    file_name = "c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:21:02"
  condition:
    hash.sha256(0, filesize) == "c462396719067866b8220128287df855aecf174b5870ec48da54577e52ec7dd2"
}

rule MalwareBazaar_unknown_057_4aed3e0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4aed3e0f4f54209b3530f405ca0e06259e3007e2e204501470e711f38bf13be3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:19:07"
  condition:
    hash.sha256(0, filesize) == "4aed3e0f4f54209b3530f405ca0e06259e3007e2e204501470e711f38bf13be3"
}

rule MalwareBazaar_Mozi_058_6a293d4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e"
    family = "Mozi"
    file_name = "6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e"
    file_type = "elf"
    first_seen = "2026-09-23 02:17:18"
  condition:
    hash.sha256(0, filesize) == "6a293d4dacb57c504b46c2cb12d90395ab642dc86eef42e5b5869c4bcae2146e"
}

rule MalwareBazaar_Mirai_059_956a85bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35"
    family = "Mirai"
    file_name = "956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35"
    file_type = "elf"
    first_seen = "2026-09-23 02:17:13"
  condition:
    hash.sha256(0, filesize) == "956a85bba448779e6dc25a8a9abe084fba2257b3bcc37e2d42aecbb133f16b35"
}

rule MalwareBazaar_unknown_060_5ee50c43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ee50c437279a1a1d8e52e0ca73af4ff0812df44b80a0bceacfb2373fdc17022"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:16:47"
  condition:
    hash.sha256(0, filesize) == "5ee50c437279a1a1d8e52e0ca73af4ff0812df44b80a0bceacfb2373fdc17022"
}

rule MalwareBazaar_unknown_061_0ca3f34b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ca3f34bef48e3e884da8d3581252f65a44ddb2a23a7785ba616689b3375138f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:16:39"
  condition:
    hash.sha256(0, filesize) == "0ca3f34bef48e3e884da8d3581252f65a44ddb2a23a7785ba616689b3375138f"
}

rule MalwareBazaar_unknown_062_da7991c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da7991c62cc464cab40536b2764bd37292d965e64187c58f3b17aef544ca3d21"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:14:14"
  condition:
    hash.sha256(0, filesize) == "da7991c62cc464cab40536b2764bd37292d965e64187c58f3b17aef544ca3d21"
}

rule MalwareBazaar_unknown_063_11cdfd56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a"
    family = "unknown"
    file_name = "11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a.bin"
    file_type = "exe"
    first_seen = "2026-09-23 02:12:16"
  condition:
    hash.sha256(0, filesize) == "11cdfd56cec58044aafe666571565de4a9b4ece5b814e20c7a3e94f9f17d776a"
}

rule MalwareBazaar_unknown_064_b550586f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b550586f9b3e2ac7c8d0c71f14e845bdd116a7c1de0f51236387bb4f67995334"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:10:29"
  condition:
    hash.sha256(0, filesize) == "b550586f9b3e2ac7c8d0c71f14e845bdd116a7c1de0f51236387bb4f67995334"
}

rule MalwareBazaar_unknown_065_ff81d2cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff81d2cd053320f91747bae417dae27d467af2c13df1f08998c9f2b38deab21f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:08:07"
  condition:
    hash.sha256(0, filesize) == "ff81d2cd053320f91747bae417dae27d467af2c13df1f08998c9f2b38deab21f"
}

rule MalwareBazaar_unknown_066_da6788c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da6788c86de7e6e6406daa84625566fb41c62658641993c00194e84654c61264"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 02:05:37"
  condition:
    hash.sha256(0, filesize) == "da6788c86de7e6e6406daa84625566fb41c62658641993c00194e84654c61264"
}

rule MalwareBazaar_unknown_067_f14b02f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc"
    family = "unknown"
    file_name = "f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc.bin"
    file_type = "macho"
    first_seen = "2026-09-23 02:00:08"
  condition:
    hash.sha256(0, filesize) == "f14b02f3fb8787dcdc5bccc3058f3810a6ee0ea87f34b2365543bec0c52fd5dc"
}

rule MalwareBazaar_unknown_068_21a454b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c"
    family = "unknown"
    file_name = "21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c.bin"
    file_type = "macho"
    first_seen = "2026-09-23 02:00:04"
  condition:
    hash.sha256(0, filesize) == "21a454b27913a08878010c0b0b9e662a7faf1e2e98a1ec6de452408be522a61c"
}

rule MalwareBazaar_unknown_069_b9afd4c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7"
    family = "unknown"
    file_name = "b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7.apk"
    file_type = "apk"
    first_seen = "2026-09-23 01:50:05"
  condition:
    hash.sha256(0, filesize) == "b9afd4c60ce2ce3f4cdd8b5ceca4662a9191ca7a986d1e2769e3f837bfbe8bc7"
}

rule MalwareBazaar_unknown_070_e973567f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e973567fb5e8dd6a1aafcd9070ef094163d6cd3e8c46ff87bf6d376c6ced7857"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-23 01:48:45"
  condition:
    hash.sha256(0, filesize) == "e973567fb5e8dd6a1aafcd9070ef094163d6cd3e8c46ff87bf6d376c6ced7857"
}

rule MalwareBazaar_Prometei_071_a787b00a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd"
    family = "Prometei"
    file_name = "a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd"
    file_type = "elf"
    first_seen = "2026-09-23 01:47:09"
  condition:
    hash.sha256(0, filesize) == "a787b00a19442ff04072a4abf943ddd089ddde01bd37ee2dc800cff8848075cd"
}

rule MalwareBazaar_Mirai_072_4ca6f100
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ca6f100fbcfbfcaee45a133be263c68760d9ec37a49cd62732f04abd50f18a3"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-23 01:38:47"
  condition:
    hash.sha256(0, filesize) == "4ca6f100fbcfbfcaee45a133be263c68760d9ec37a49cd62732f04abd50f18a3"
}

rule MalwareBazaar_unknown_073_b5bc4df5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5bc4df55a68fb59e944cba393e5dc60533ed9f965a4f523d8714dd2829a02a9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:37:21"
  condition:
    hash.sha256(0, filesize) == "b5bc4df55a68fb59e944cba393e5dc60533ed9f965a4f523d8714dd2829a02a9"
}

rule MalwareBazaar_unknown_074_3dc56162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc561622fb319c9e1770ed313741f8616a1a996fe274adc999ef558c0b15bb1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:34:44"
  condition:
    hash.sha256(0, filesize) == "3dc561622fb319c9e1770ed313741f8616a1a996fe274adc999ef558c0b15bb1"
}

rule MalwareBazaar_unknown_075_0e83a085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e83a08555ce1a8d4579c455b49b3af8bbfcbd54dfb6190a15a974f168b63826"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:32:29"
  condition:
    hash.sha256(0, filesize) == "0e83a08555ce1a8d4579c455b49b3af8bbfcbd54dfb6190a15a974f168b63826"
}

rule MalwareBazaar_unknown_076_a34be6b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a34be6b062691b7f9483b0522f34136c510d91c31c3461afaf3d199e22f17b5b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:32:16"
  condition:
    hash.sha256(0, filesize) == "a34be6b062691b7f9483b0522f34136c510d91c31c3461afaf3d199e22f17b5b"
}

rule MalwareBazaar_Mirai_077_1d17a1ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61"
    family = "Mirai"
    file_name = "1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61.bin"
    file_type = "elf"
    first_seen = "2026-09-23 01:30:05"
  condition:
    hash.sha256(0, filesize) == "1d17a1ad1563167232a9ac03c600f098ad429f4e408890f281c9e082c38edb61"
}

rule MalwareBazaar_unknown_078_1228cea5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1228cea5a4f51e5f7ba8ddd4fcbb5f04f903e20c4e5729ddf1b9d5f70e3f1cd1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 01:29:54"
  condition:
    hash.sha256(0, filesize) == "1228cea5a4f51e5f7ba8ddd4fcbb5f04f903e20c4e5729ddf1b9d5f70e3f1cd1"
}

rule MalwareBazaar_unknown_079_e5358f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5358f378fa606f9f6be2a087c16e6634336dd1a89a4ce9f1113994d335dda3a"
    family = "unknown"
    file_name = "aws.sh"
    file_type = "unknown"
    first_seen = "2026-09-23 01:26:54"
  condition:
    hash.sha256(0, filesize) == "e5358f378fa606f9f6be2a087c16e6634336dd1a89a4ce9f1113994d335dda3a"
}

rule MalwareBazaar_unknown_080_d5caf6c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361"
    family = "unknown"
    file_name = "d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361.bin"
    file_type = "macho"
    first_seen = "2026-09-23 01:20:05"
  condition:
    hash.sha256(0, filesize) == "d5caf6c474da5cd159db8cb0664568d8ee55e56c8de94f39009ca70f8df40361"
}

rule MalwareBazaar_Mirai_081_d21928d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34"
    family = "Mirai"
    file_name = "d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34"
    file_type = "elf"
    first_seen = "2026-09-23 01:17:12"
  condition:
    hash.sha256(0, filesize) == "d21928d2e22565c61d0d7d51103505f518a4e643b9bf9e7185cb923f030fec34"
}

rule MalwareBazaar_WannaCry_082_ae326021
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd"
    family = "WannaCry"
    file_name = "ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd"
    file_type = "exe"
    first_seen = "2026-09-23 01:15:57"
  condition:
    hash.sha256(0, filesize) == "ae326021951543267d2a4e8ea020a21ad5b804ecd1c02467992efcb4b10fddbd"
}

rule MalwareBazaar_unknown_083_f593a772
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f593a772075022c10744d049d5a748fc9599968adb2df73b6db3c4ddce80d100"
    family = "unknown"
    file_name = "192837455732.ps1"
    file_type = "ps1"
    first_seen = "2026-09-23 01:10:34"
  condition:
    hash.sha256(0, filesize) == "f593a772075022c10744d049d5a748fc9599968adb2df73b6db3c4ddce80d100"
}

rule MalwareBazaar_unknown_084_9581909f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9581909f8fcd48590f208532e7081bd9d9e96697fa3463e3766e028d4f20176d"
    family = "unknown"
    file_name = "NOTICE OF DOF ADJUSTMENT FOR IMPORT SHIPMENTS FROM 01 OCT 2026-SITC.pdf.gz"
    file_type = "gz"
    first_seen = "2026-09-23 01:09:26"
  condition:
    hash.sha256(0, filesize) == "9581909f8fcd48590f208532e7081bd9d9e96697fa3463e3766e028d4f20176d"
}

rule MalwareBazaar_unknown_085_446df530
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "446df5308fdc7107753d5af859ebf9d458571da20a31fd19c9cffc77d51d37d4"
    family = "unknown"
    file_name = "NEW TARIFF OF TERMINAL HANDLING CHARGE (THC).pdf.gz"
    file_type = "gz"
    first_seen = "2026-09-23 01:08:59"
  condition:
    hash.sha256(0, filesize) == "446df5308fdc7107753d5af859ebf9d458571da20a31fd19c9cffc77d51d37d4"
}

rule MalwareBazaar_NetSupport_086_679f7f0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679f7f0f6d3578fbda2c314e504464b6cda98f57c3981b790f7d72d97a0042f4"
    family = "NetSupport"
    file_name = "liblivenet_amd64.dll"
    file_type = "exe"
    first_seen = "2026-09-23 01:08:12"
  condition:
    hash.sha256(0, filesize) == "679f7f0f6d3578fbda2c314e504464b6cda98f57c3981b790f7d72d97a0042f4"
}

rule MalwareBazaar_unknown_087_eda6ed7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eda6ed7f7f715c8dc16793bebf83784bf6d405ed2cd8576202175f9a893601b3"
    family = "unknown"
    file_name = "CopilotService.exe"
    file_type = "exe"
    first_seen = "2026-09-23 01:05:22"
  condition:
    hash.sha256(0, filesize) == "eda6ed7f7f715c8dc16793bebf83784bf6d405ed2cd8576202175f9a893601b3"
}

rule MalwareBazaar_unknown_088_c5f8c692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5f8c6927e6959c7c30a8d0e0a2f00818f88cb0e7d20c9c1ed616669d5a75663"
    family = "unknown"
    file_name = "63563545600333.ps1"
    file_type = "ps1"
    first_seen = "2026-09-23 01:02:57"
  condition:
    hash.sha256(0, filesize) == "c5f8c6927e6959c7c30a8d0e0a2f00818f88cb0e7d20c9c1ed616669d5a75663"
}

rule MalwareBazaar_unknown_089_61107844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54"
    family = "unknown"
    file_name = "61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54.bin"
    file_type = "macho"
    first_seen = "2026-09-23 01:01:12"
  condition:
    hash.sha256(0, filesize) == "61107844953b648b1808f24f405f76d7bc648f193292dca18d27854d83ebae54"
}

rule MalwareBazaar_unknown_090_49b0c4a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505"
    family = "unknown"
    file_name = "49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505.bin"
    file_type = "exe"
    first_seen = "2026-09-23 01:01:10"
  condition:
    hash.sha256(0, filesize) == "49b0c4a05fcd4e5bfcb13007e6cb16b4b590f643b8e97c1ea0cea23de4989505"
}

rule MalwareBazaar_unknown_091_3eaf5674
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd"
    family = "unknown"
    file_name = "3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd.bin"
    file_type = "macho"
    first_seen = "2026-09-23 01:00:07"
  condition:
    hash.sha256(0, filesize) == "3eaf5674799725920ab1d4a27a6e2530aec19e0deea1b13b0044c1dae9bc85fd"
}

rule MalwareBazaar_unknown_092_6610a658
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6610a658f8064a9c5d238fe9fa376db2e409a302a8c4f52c0fd3577a727fbf23"
    family = "unknown"
    file_name = "PlutonAgent.exe"
    file_type = "exe"
    first_seen = "2026-09-23 00:58:22"
  condition:
    hash.sha256(0, filesize) == "6610a658f8064a9c5d238fe9fa376db2e409a302a8c4f52c0fd3577a727fbf23"
}

rule MalwareBazaar_unknown_093_a8baf835
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8baf83504a5782f76a310a48eb80b19c3476d9cc13038edfb1041f2f1b2db8f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:57:48"
  condition:
    hash.sha256(0, filesize) == "a8baf83504a5782f76a310a48eb80b19c3476d9cc13038edfb1041f2f1b2db8f"
}

rule MalwareBazaar_unknown_094_801fb26e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801fb26e8cb14860719bcc96fce99e7e10bca39aeebbc9c5e3cc74af7d00a23b"
    family = "unknown"
    file_name = "87648736456384.ps1"
    file_type = "ps1"
    first_seen = "2026-09-23 00:56:59"
  condition:
    hash.sha256(0, filesize) == "801fb26e8cb14860719bcc96fce99e7e10bca39aeebbc9c5e3cc74af7d00a23b"
}

rule MalwareBazaar_unknown_095_df7b7fce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df7b7fce3a2ae36d8bd0d5f25830cfda14b257d5019181837402d164208b8a56"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:56:32"
  condition:
    hash.sha256(0, filesize) == "df7b7fce3a2ae36d8bd0d5f25830cfda14b257d5019181837402d164208b8a56"
}

rule MalwareBazaar_unknown_096_5c785427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c7854279bf23801246a9309bf822a9801b1aa2518846e08e1169015561c6390"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:53:17"
  condition:
    hash.sha256(0, filesize) == "5c7854279bf23801246a9309bf822a9801b1aa2518846e08e1169015561c6390"
}

rule MalwareBazaar_unknown_097_c6534c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3"
    family = "unknown"
    file_name = "c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3.bin"
    file_type = "elf"
    first_seen = "2026-09-23 00:50:09"
  condition:
    hash.sha256(0, filesize) == "c6534c50ab6aefa6a04c0ddb6254300a95ef3bbbe4acaef72001629ba6cb95f3"
}

rule MalwareBazaar_unknown_098_4f7e19a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302"
    family = "unknown"
    file_name = "4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302.bin"
    file_type = "macho"
    first_seen = "2026-09-23 00:50:04"
  condition:
    hash.sha256(0, filesize) == "4f7e19a697092809e1b7639166ff84616b3646c5f3c7d27406f72d1ebe362302"
}

rule MalwareBazaar_unknown_099_fbc4ea95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbc4ea95c798b07e9a25b83948547adb9f35319ff92170aff574581c2d9a56e3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-23 00:40:16"
  condition:
    hash.sha256(0, filesize) == "fbc4ea95c798b07e9a25b83948547adb9f35319ff92170aff574581c2d9a56e3"
}

rule MalwareBazaar_unknown_100_d5e7f9f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d"
    family = "unknown"
    file_name = "d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d.bin"
    file_type = "macho"
    first_seen = "2026-09-23 00:40:04"
  condition:
    hash.sha256(0, filesize) == "d5e7f9f93dcee175e90aca0bb746a8f2ca56adad24b6249bd1bf7e6473f7600d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

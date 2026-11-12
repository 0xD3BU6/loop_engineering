# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-12

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 667 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 667 |
| Unique family labels | 19 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 45 |
| SalatStealer | 17 |
| unknown | 12 |
| njrat | 4 |
| WARDENStealer | 3 |
| RemcosRAT | 2 |
| RevStealer | 2 |
| PavinLoader | 2 |
| ACRStealer | 2 |
| CNBackdoor | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 50 |
| exe | 32 |
| sh | 3 |
| zip | 3 |
| ps1 | 2 |
| js | 2 |
| cmd | 2 |
| msi | 2 |
| apk | 1 |
| bat | 1 |

## Per-Sample Analysis

### Sample 1: `da5787dd139ca9d7`

| Field | Value |
|---|---|
| SHA-256 | `da5787dd139ca9d7cd083bd60adb43c001fd64818d8418aa04a478edf7116b70` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-12 07:22:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `098fa175be3eb3617d61cbff43e55596` |
| SHA-1 | `6462e28d0ba333411e4203ad402ce0cbe5ed6c0f` |
| SHA-256 | `da5787dd139ca9d7cd083bd60adb43c001fd64818d8418aa04a478edf7116b70` |
| SHA3-384 | `712c87427f1c8b98f9709471b96e146a61081845d566e045eb1d81725216ba6fce367900e2dc4a6f2d296557565caed6` |
| TLSH | `T1F7556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSk:SDjxB4m5n8XlaPWi+d+a4TjxQP4u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_da5787dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da5787dd139ca9d7cd083bd60adb43c001fd64818d8418aa04a478edf7116b70"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 07:22:04"
  condition:
    hash.sha256(0, filesize) == "da5787dd139ca9d7cd083bd60adb43c001fd64818d8418aa04a478edf7116b70"
}
```

### Sample 2: `b16156dc9b6224aa`

| Field | Value |
|---|---|
| SHA-256 | `b16156dc9b6224aadd796bb10795eafb8969ead1376eb838507d61044673c95c` |
| Family label | `unknown` |
| File name | `wgets.sh` |
| File type | `sh` |
| First seen | `2026-11-12 06:56:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b10909f4ec72abf8bfbedda0e0ebcfd2` |
| SHA-1 | `98d401e5391ae5f846c4403bdc76e94daf202f53` |
| SHA-256 | `b16156dc9b6224aadd796bb10795eafb8969ead1376eb838507d61044673c95c` |
| SHA3-384 | `32fcde1c90b6a5fc171a90a6fe656bb3cd882640b6feb6e42a3d5b6a399bfa1819080362ad412973f0aaf00cd505a536` |
| TLSH | `T1CA3112D215D22BBEDCC4D62E7752603D9128BCC92E2B5FE8E4DB18D8A348A92B110D4D` |
| SSDEEP | `48:BoviZIB7v8UcvIMZLvAhF07pp46IOjCSc4RQ6oqK:BoviZIB7v8UcvIMLvAhF07pp5IOuSlfw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_b16156dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b16156dc9b6224aadd796bb10795eafb8969ead1376eb838507d61044673c95c"
    family = "unknown"
    file_name = "wgets.sh"
    file_type = "sh"
    first_seen = "2026-11-12 06:56:18"
  condition:
    hash.sha256(0, filesize) == "b16156dc9b6224aadd796bb10795eafb8969ead1376eb838507d61044673c95c"
}
```

### Sample 3: `7729a612275980d8`

| Field | Value |
|---|---|
| SHA-256 | `7729a612275980d83dac5859b37655c98839415b9f1e0c811e8526b66bc56dd4` |
| Family label | `Mirai` |
| File name | `zerspc` |
| File type | `elf` |
| First seen | `2026-11-12 06:56:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a6795d3c60098fc60fdfff855dfaa7d` |
| SHA-1 | `41c679e03f31202675ff3d917bd7dbbc3feb0e74` |
| SHA-256 | `7729a612275980d83dac5859b37655c98839415b9f1e0c811e8526b66bc56dd4` |
| SHA3-384 | `166cfd4a97b41d45261c235e181d7a8870d0126c59eb7bf0f56c44b2e885ec8390771f82a0c1496184c3f786e354442c` |
| TLSH | `T116B34B21FD7A192BC5C470B651E34631F1B6439E25BC8A4A7EA31D4CEF18750312BAEE` |
| SSDEEP | `1536:4aSG8VF7CwwDsej5qwn2k03cqnZfN/S1L8ZkOF54MtwbN9/:HSjFpwDx2LNtk84Zh9/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_7729a612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7729a612275980d83dac5859b37655c98839415b9f1e0c811e8526b66bc56dd4"
    family = "Mirai"
    file_name = "zerspc"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:13"
  condition:
    hash.sha256(0, filesize) == "7729a612275980d83dac5859b37655c98839415b9f1e0c811e8526b66bc56dd4"
}
```

### Sample 4: `6591a591547bec94`

| Field | Value |
|---|---|
| SHA-256 | `6591a591547bec94ec471c69d0f5ba3074f4db3f0cfd947b513571b4a9a1ea6e` |
| Family label | `Mirai` |
| File name | `zerarm6` |
| File type | `elf` |
| First seen | `2026-11-12 06:56:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e03cfb88ad9cb274d724d6afd6cd6387` |
| SHA-1 | `50bdfea62f27a15530827506e25131ace05bab03` |
| SHA-256 | `6591a591547bec94ec471c69d0f5ba3074f4db3f0cfd947b513571b4a9a1ea6e` |
| SHA3-384 | `cffe486be89c5c70a61c3b497f0208188647265833124161813b039a1ccb296101d3e215d4573bfc8aafd0023cceef97` |
| TLSH | `T11EC33CD9BC818B11D6C515BAFE1E618E33234FB8E3F971139E145B2E634A86B0E37605` |
| TELFHASH | `t10ce02620b6499fc4f7cec0a5c0a9631562da784faa3828a035adc74fcaa5ea4341502d` |
| SSDEEP | `3072:/GvRAndNhlCn5LBE9dq51r9S4VaLnON0ak2mx0P5g3qlhZp:f4LO051hVaLQ0abmx2t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_6591a591
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6591a591547bec94ec471c69d0f5ba3074f4db3f0cfd947b513571b4a9a1ea6e"
    family = "Mirai"
    file_name = "zerarm6"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:11"
  condition:
    hash.sha256(0, filesize) == "6591a591547bec94ec471c69d0f5ba3074f4db3f0cfd947b513571b4a9a1ea6e"
}
```

### Sample 5: `aea4f8d1cb4926c2`

| Field | Value |
|---|---|
| SHA-256 | `aea4f8d1cb4926c27f610668b877b21220732472062288fe66041a067145321f` |
| Family label | `Mirai` |
| File name | `zermips` |
| File type | `elf` |
| First seen | `2026-11-12 06:56:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77d5c0442d346e327a88d8d750e443cc` |
| SHA-1 | `18315224f4fb2727c243e44a64f1a698ba9a3111` |
| SHA-256 | `aea4f8d1cb4926c27f610668b877b21220732472062288fe66041a067145321f` |
| SHA3-384 | `702211a5dc6041909198169c39bbfc05c6ffe3b4bc91ceb526aa31a5e9b404015401cdd215d796c60eaced002b7d1f78` |
| TLSH | `T1AFD3E95A7E529FADF32886354BB34B35A39523D633E0C284E69CDA005E6034E587FF94` |
| TELFHASH | `t145110d184e3813f097761ded6bdcfe72e46170eb4a256d27cd10e96d9a2dd429e00c1c` |
| SSDEEP | `1536:NZAMYnpOuByTr2W22WbTW2vHfJoknRkxDzxrxUgWxJ83vlzJxZIMjXhlGe1yYbNP:Ne1pATQHOUsPxJXIMjxwYhHLT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_aea4f8d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aea4f8d1cb4926c27f610668b877b21220732472062288fe66041a067145321f"
    family = "Mirai"
    file_name = "zermips"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:08"
  condition:
    hash.sha256(0, filesize) == "aea4f8d1cb4926c27f610668b877b21220732472062288fe66041a067145321f"
}
```

### Sample 6: `8146df28ee6a7a7f`

| Field | Value |
|---|---|
| SHA-256 | `8146df28ee6a7a7f1e04f2abe7df31c8ce80df30994e81f91a7dc065c2feeb86` |
| Family label | `Mirai` |
| File name | `zerppc` |
| File type | `elf` |
| First seen | `2026-11-12 06:56:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88acfaba27c4534b86e394360b6df953` |
| SHA-1 | `3802ef6d4568a523489d978e8bfccc816dc9b59f` |
| SHA-256 | `8146df28ee6a7a7f1e04f2abe7df31c8ce80df30994e81f91a7dc065c2feeb86` |
| SHA3-384 | `6f64546b0cb66aa27e2a2aeed83860497a0553099b5f9515f81ff86a9fbc659d0c3c5012c17a8bafbb38302c64030d3e` |
| TLSH | `T1AFB35A4177690447F3A70EB0193FBBE0A3EED6A521F0A585695EDB4F8131A321486FCE` |
| SSDEEP | `1536:B/0dW9JjaOJG8lQTrkrLYIHiv25BngivEA4SaTnHaNJR6X5nEUzP9zmqqASx3ncd:B/GWraOJ8SBnvvEAunHm4rBin5/khDb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_8146df28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8146df28ee6a7a7f1e04f2abe7df31c8ce80df30994e81f91a7dc065c2feeb86"
    family = "Mirai"
    file_name = "zerppc"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:05"
  condition:
    hash.sha256(0, filesize) == "8146df28ee6a7a7f1e04f2abe7df31c8ce80df30994e81f91a7dc065c2feeb86"
}
```

### Sample 7: `29a402a1b2c43e37`

| Field | Value |
|---|---|
| SHA-256 | `29a402a1b2c43e37f4d74aeb30bfd76ce6e6fc90d9f1b461fc9c429f2800abc1` |
| Family label | `Mirai` |
| File name | `zerarm` |
| File type | `elf` |
| First seen | `2026-11-12 06:56:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea57b0ed635199e961668b0b8c3e73f6` |
| SHA-1 | `03c40e508228780a781933146e47980ebd44e836` |
| SHA-256 | `29a402a1b2c43e37f4d74aeb30bfd76ce6e6fc90d9f1b461fc9c429f2800abc1` |
| SHA3-384 | `d11f34ac6fa1f8f77c52a541a23ad95e17daafc8b51eb4821a8b0b6c0ffff6aeb3d4e03a78d36f146338266762545370` |
| TLSH | `T1C1B3398ABC819612C6E160B6FB1FD1CD372743B8D3E67103DD18AB29638B9670E77251` |
| TELFHASH | `t159410166db500edc67dd424841ee102a44de35fe172410929f6d6b8f95439dab12983a` |
| SSDEEP | `3072:HzudlxBjZ6tAokhGaBFJWMHk9t/c9xvOhQrH:TAiAokhFjJWME9taxvOuz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_29a402a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29a402a1b2c43e37f4d74aeb30bfd76ce6e6fc90d9f1b461fc9c429f2800abc1"
    family = "Mirai"
    file_name = "zerarm"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:03"
  condition:
    hash.sha256(0, filesize) == "29a402a1b2c43e37f4d74aeb30bfd76ce6e6fc90d9f1b461fc9c429f2800abc1"
}
```

### Sample 8: `6ce7d9ed6c1d043b`

| Field | Value |
|---|---|
| SHA-256 | `6ce7d9ed6c1d043b8bf4111d1709945fbbc8480e4a2bb03782e1711b3e8fa79d` |
| Family label | `Mirai` |
| File name | `zermpsl` |
| File type | `elf` |
| First seen | `2026-11-12 06:56:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16eb97023a45558f9e7d3ca25f6d17d2` |
| SHA-1 | `98d0967407c348956cb512fe7f0a6eab9b7bd172` |
| SHA-256 | `6ce7d9ed6c1d043b8bf4111d1709945fbbc8480e4a2bb03782e1711b3e8fa79d` |
| SHA3-384 | `7c0787058267acc4f5c14d790363440e22f7c676991bfd145807c5a0ec4b7c3a9418c24c9d8aa282be2673cb88cc22d8` |
| TLSH | `T1D1D31A0AFFA21FBBD4AFDE3346A9070A349D190621B53B367574C81CF65A68B09E3C54` |
| SSDEEP | `1536:o+qCzYwBxxAF9b8FC4ct43f8xTfQmZobkdHb8rzq5fMoO95aqyhAexcWPdapB7nH:ozSBct43faa1hHRfNZh8Mf7Mn5IFehu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_6ce7d9ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ce7d9ed6c1d043b8bf4111d1709945fbbc8480e4a2bb03782e1711b3e8fa79d"
    family = "Mirai"
    file_name = "zermpsl"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:00"
  condition:
    hash.sha256(0, filesize) == "6ce7d9ed6c1d043b8bf4111d1709945fbbc8480e4a2bb03782e1711b3e8fa79d"
}
```

### Sample 9: `b8acadedf72e096d`

| Field | Value |
|---|---|
| SHA-256 | `b8acadedf72e096d541fe8342e4fd04b3f5dd8b61de028e6cabd7a1e0cc4869c` |
| Family label | `Mirai` |
| File name | `zerx86` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d1aa51ecf7f84debcbcbf7eef10162d` |
| SHA-1 | `6ebb5941e5c49b49226d55966889d9bca64b607f` |
| SHA-256 | `b8acadedf72e096d541fe8342e4fd04b3f5dd8b61de028e6cabd7a1e0cc4869c` |
| SHA3-384 | `93bab1a1e15b2890d3525886ab53f7faf60842dcf3c664013b13c4c861e41ebbbb3900e0e33bf3099c4adad3df0fd68d` |
| TLSH | `T1A2A35BD1D283E4F1E91A01B4616BF337A631DAB90128FDE7FB506B339825E60B506B4D` |
| TELFHASH | `t1e931d1fa1b750de85bd05813b60e6b20ed2cab6b642433e30af654293653081a27fc3d` |
| SSDEEP | `1536:Q6o5ToPnlL3Lei5Hn32U5TFxh3LuhDb1S3yFjngVQkwBQTmB74S5+2tbNS:Q6KkNLhFnF5TF74NgKS+7H5+uhS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_b8acaded
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8acadedf72e096d541fe8342e4fd04b3f5dd8b61de028e6cabd7a1e0cc4869c"
    family = "Mirai"
    file_name = "zerx86"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:58"
  condition:
    hash.sha256(0, filesize) == "b8acadedf72e096d541fe8342e4fd04b3f5dd8b61de028e6cabd7a1e0cc4869c"
}
```

### Sample 10: `b231a34f15abdb02`

| Field | Value |
|---|---|
| SHA-256 | `b231a34f15abdb026607014be4ecf4f294908baae0c9d94150a4f5092324183d` |
| Family label | `Mirai` |
| File name | `zerm68k` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32ecf081062055e0d151657b964dec21` |
| SHA-1 | `772af7c03db7c8502f036208d9cfdc9deed24f6a` |
| SHA-256 | `b231a34f15abdb026607014be4ecf4f294908baae0c9d94150a4f5092324183d` |
| SHA3-384 | `ebccb1da8fdfe72585ae8a140611da0c438f754c69ec49e2307efe5a1a4cfdf8be2167590759c6be54f9549327882544` |
| TLSH | `T1FEB35DE1F4009D3EF45BE37780531206B631A3B64A936B373667BC63EA7E1741862E46` |
| SSDEEP | `3072:Idfn89FL0vy/MSpnS+VcpciseWNGbmfqhFuQ:Itvy/MYSveiwAbekuQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_b231a34f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b231a34f15abdb026607014be4ecf4f294908baae0c9d94150a4f5092324183d"
    family = "Mirai"
    file_name = "zerm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:55"
  condition:
    hash.sha256(0, filesize) == "b231a34f15abdb026607014be4ecf4f294908baae0c9d94150a4f5092324183d"
}
```

### Sample 11: `3898ef1f4cc7c458`

| Field | Value |
|---|---|
| SHA-256 | `3898ef1f4cc7c458415da39282af5af3d4fa6b5facbdbdeb9811ad6d0912b889` |
| Family label | `Mirai` |
| File name | `zerarm5` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `091d1062fcea694d26ded06ad67c659c` |
| SHA-1 | `34cee5aeccf3ff17329ca880939948b55f9c8522` |
| SHA-256 | `3898ef1f4cc7c458415da39282af5af3d4fa6b5facbdbdeb9811ad6d0912b889` |
| SHA3-384 | `079e06c2f0cad39749552df32bad57b2639e7fea27f102366ca92fbb01d64059d1b78171ad7f64037422588468562451` |
| TLSH | `T1FCB32A89BC819712C6E061B2FB1FD1CD372343B8D3E67103DD19AB29638A9670E77651` |
| TELFHASH | `t1d52102108d840c9d73f44458505e403f51ea36ed3aa21581bbae6f8f1e36fa17134439` |
| SSDEEP | `3072:jvLb0qzuhLLtieAjGngF63+GV2M9Xnu8IuPcz:jvkqCtieAjBF6OGVZXnunuC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_3898ef1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3898ef1f4cc7c458415da39282af5af3d4fa6b5facbdbdeb9811ad6d0912b889"
    family = "Mirai"
    file_name = "zerarm5"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:53"
  condition:
    hash.sha256(0, filesize) == "3898ef1f4cc7c458415da39282af5af3d4fa6b5facbdbdeb9811ad6d0912b889"
}
```

### Sample 12: `55b23b5674c38462`

| Field | Value |
|---|---|
| SHA-256 | `55b23b5674c384629c1c2c3fea66dba85be7cde06e3994df078f6d8b190a6a92` |
| Family label | `Mirai` |
| File name | `zerarm7` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c649bd67d79c25a8a168345243e73025` |
| SHA-1 | `041edbbb15edf2354527c0a9fbbc35b446d1d498` |
| SHA-256 | `55b23b5674c384629c1c2c3fea66dba85be7cde06e3994df078f6d8b190a6a92` |
| SHA3-384 | `ccdd6799a39315888fd4de5041b0dbe3703fb596c3e3c554fc20cf1f63cdad25a856c49bfd7cc418bd01f259d26ca286` |
| TLSH | `T180D32B99FC809B11D5D525BAFE1E518D33234BB8E3F97102DE145B2A638AD6B0F37A01` |
| TELFHASH | `t165e02833edc904c9b6c5544003dd0301e30968cf3610045025ef574f4d74d84750d516` |
| SSDEEP | `3072:QmNRAvIyzRk25QnEE8jd6iLNOMq4F9xeh8aAUOAOPmpn8aGaX1hH:MBQpMd9OMqms8aAUOAOP+nfXb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_55b23b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55b23b5674c384629c1c2c3fea66dba85be7cde06e3994df078f6d8b190a6a92"
    family = "Mirai"
    file_name = "zerarm7"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:50"
  condition:
    hash.sha256(0, filesize) == "55b23b5674c384629c1c2c3fea66dba85be7cde06e3994df078f6d8b190a6a92"
}
```

### Sample 13: `67c730f4ec5d4ec3`

| Field | Value |
|---|---|
| SHA-256 | `67c730f4ec5d4ec33157099b195fdae513be778e904c27eb078a9961b9040f77` |
| Family label | `Mirai` |
| File name | `splsh4` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c6e0b31fd9dd77aac9bb574550db66f` |
| SHA-1 | `550912ee8d227133df9f92b232d96efc2a547059` |
| SHA-256 | `67c730f4ec5d4ec33157099b195fdae513be778e904c27eb078a9961b9040f77` |
| SHA3-384 | `c78befeb8b2ccf57a2f5522d178ae72fbae209fb2c53bdeff35293a2fd2975cd4189c1982b147aec11a8bdfc9ade3a32` |
| TLSH | `T1ACB39E12CDB40EDCE12A7D7550F49AB98B23D0C6501B2DBB3C4687694047ED8F99BBB8` |
| SSDEEP | `3072:cOc4kmTuJThrDDgZcTWcwItvhpHnMfhJ:cOcvQuJThrfgyWKtbHM7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_67c730f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67c730f4ec5d4ec33157099b195fdae513be778e904c27eb078a9961b9040f77"
    family = "Mirai"
    file_name = "splsh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:47"
  condition:
    hash.sha256(0, filesize) == "67c730f4ec5d4ec33157099b195fdae513be778e904c27eb078a9961b9040f77"
}
```

### Sample 14: `6306df9018f45666`

| Field | Value |
|---|---|
| SHA-256 | `6306df9018f456666fda2a5708de9b81612c181b139904a27315bb4c4789180a` |
| Family label | `Mirai` |
| File name | `nabarm5` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01a8e4a508678ce896411223f226a6eb` |
| SHA-1 | `ea9466f1ae3c0c8a9e2d9288460de057b28c279f` |
| SHA-256 | `6306df9018f456666fda2a5708de9b81612c181b139904a27315bb4c4789180a` |
| SHA3-384 | `f777d3175f811152630d4fbe8f2c9ceb153988ea9f6b3178c2d9ee9caffa6d955e000f520dd3d02186ebdfd065e4c12e` |
| TLSH | `T1B1732B55FD419B13C6C165B7FB4FC28D3B2743B8D2EA3202AD256F64338B9260E7A641` |
| TELFHASH | `t168310e9189841ecc67f4c168874ab02a14a934fa2f552957cf3eea8e06729c1b12943e` |
| SSDEEP | `1536:OhWaoGvUx1to8XcuQ0FPzBHnUp9zRSmbdl8KN3Ev0jnfsQeRK:OhoGcDq8sMFP1Hy99bdlCvqp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_6306df90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6306df9018f456666fda2a5708de9b81612c181b139904a27315bb4c4789180a"
    family = "Mirai"
    file_name = "nabarm5"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:45"
  condition:
    hash.sha256(0, filesize) == "6306df9018f456666fda2a5708de9b81612c181b139904a27315bb4c4789180a"
}
```

### Sample 15: `e565170123198f39`

| Field | Value |
|---|---|
| SHA-256 | `e565170123198f39a434c2230d8819bcb0afdd7d70b240c0fc710c1f7556153b` |
| Family label | `Mirai` |
| File name | `zersh4` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7202c41f5c2078f6b118d6c5754c7756` |
| SHA-1 | `1a3f6dd28a567507d618993e8dec7160d588a571` |
| SHA-256 | `e565170123198f39a434c2230d8819bcb0afdd7d70b240c0fc710c1f7556153b` |
| SHA3-384 | `e47efdcbe53d9e27dfa3f3f57d817090d75f6bc1e642d4f750db1df1c7910c400e9aadf2a8d38b30a316c178039381e1` |
| TLSH | `T157A3A022CC710E9CF03B6D3050F59A7A9727E285941B6DBF3C46C265404BED8F96ABB4` |
| SSDEEP | `1536:Te0XSiz3P2cAj9n8H9ZSVG+/643aDZj0kuiCMK9NSgkKkKCX+uIbN0:Te0XSiz3+j5n8dZU9Bqx0h9EKvWIh0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_e5651701
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e565170123198f39a434c2230d8819bcb0afdd7d70b240c0fc710c1f7556153b"
    family = "Mirai"
    file_name = "zersh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:42"
  condition:
    hash.sha256(0, filesize) == "e565170123198f39a434c2230d8819bcb0afdd7d70b240c0fc710c1f7556153b"
}
```

### Sample 16: `32bcfddbe56d9eae`

| Field | Value |
|---|---|
| SHA-256 | `32bcfddbe56d9eaeb9860d1fb2ef6adf3d677e5c9c82deeb7bbe1f21bba3fcc5` |
| Family label | `Mirai` |
| File name | `nabarm6` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `409959edd5dc8054954ff3e6ba3e974c` |
| SHA-1 | `89ad3b7a6ae9b2f2cae46ed8859c537a193891f4` |
| SHA-256 | `32bcfddbe56d9eaeb9860d1fb2ef6adf3d677e5c9c82deeb7bbe1f21bba3fcc5` |
| SHA3-384 | `72cfe0342ed154555ffc142a24094e62172fb10707339689e53795765451290b4af3588160c063694f511538242f53a6` |
| TLSH | `T170932B56BD415B11D6C115BAFE1E528E33130BBCE3EE72129E146B30678B9670F3B906` |
| TELFHASH | `t152316760498847ec2bf4c15c869e711c5d663af83b111456b93fe75f49728c0317183e` |
| SSDEEP | `1536:zqtnbQZJHrFQWWvtoA4q6Qv1PHNtR4T5NawJCodMDyLiysnDm/pLYd5XY1bNP:z1jHrFlWyA7Vv1vCNa1UsnDm/pLYdUhP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_32bcfddb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32bcfddbe56d9eaeb9860d1fb2ef6adf3d677e5c9c82deeb7bbe1f21bba3fcc5"
    family = "Mirai"
    file_name = "nabarm6"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:14"
  condition:
    hash.sha256(0, filesize) == "32bcfddbe56d9eaeb9860d1fb2ef6adf3d677e5c9c82deeb7bbe1f21bba3fcc5"
}
```

### Sample 17: `ac785d0339cd9a16`

| Field | Value |
|---|---|
| SHA-256 | `ac785d0339cd9a16fa4853acba05fbe07eede138193ae4469f3438d02c3c124d` |
| Family label | `Mirai` |
| File name | `nabarm` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d60af7fd1c22051f0b7fa65136063181` |
| SHA-1 | `5b8a6a8b91ab3b77b8d6aea0c1e44fd45f77b2b3` |
| SHA-256 | `ac785d0339cd9a16fa4853acba05fbe07eede138193ae4469f3438d02c3c124d` |
| SHA3-384 | `7c5f49323ffc893903bd0bdbf660969d181732386e932f35c74b5d0896912a72039e66c2335ec1e386aa24f8771dab58` |
| TLSH | `T132731A45BD519A13CBC121B7FB5FC28C372747B8D2EA32029D29AF61278B9260E7B541` |
| TELFHASH | `t19531f23a9d041dcc67f0c65c834e706b29ac34ba174438a6cf2e9adf0631ac5722447f` |
| SSDEEP | `1536:ApVNloGJgtUP5yzDXx/YFt0c7dvxzRSmoPDrR56TQ/nuvEfsQeRl:OVQGeOP5yvBAFtFZvx9oPDFCPKu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_ac785d03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac785d0339cd9a16fa4853acba05fbe07eede138193ae4469f3438d02c3c124d"
    family = "Mirai"
    file_name = "nabarm"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:11"
  condition:
    hash.sha256(0, filesize) == "ac785d0339cd9a16fa4853acba05fbe07eede138193ae4469f3438d02c3c124d"
}
```

### Sample 18: `c6af8e322214bd1c`

| Field | Value |
|---|---|
| SHA-256 | `c6af8e322214bd1ce012287bf2619f7051ea49097b02990d0635caff821eb336` |
| Family label | `Mirai` |
| File name | `nklarm5` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4974f1d049cdbcc10eec94874d9e7ce` |
| SHA-1 | `1d1dd6415788587b4a676cf2ed56c7e713aac94c` |
| SHA-256 | `c6af8e322214bd1ce012287bf2619f7051ea49097b02990d0635caff821eb336` |
| SHA3-384 | `8a4c2cc705153fb1d68448b2585363df6849c806b7642cec16391df4d90d76ddb34e030a6d3643844617fa15e4b4a464` |
| TLSH | `T13FB3298ABC819712C6E160B2FB1FD18D372743B8D3E67103DD19AB29638B9670E77641` |
| TELFHASH | `t1d52102108d840c9d73f44458505e403f51ea36ed3aa21581bbae6f8f1e36fa17134439` |
| SSDEEP | `3072:T/LboqzucLL5B2AkG+O/B3+jV2p9XOuEIuXz:T/Yqd5B2AkU/BOjVwXOu/uj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_c6af8e32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6af8e322214bd1ce012287bf2619f7051ea49097b02990d0635caff821eb336"
    family = "Mirai"
    file_name = "nklarm5"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:08"
  condition:
    hash.sha256(0, filesize) == "c6af8e322214bd1ce012287bf2619f7051ea49097b02990d0635caff821eb336"
}
```

### Sample 19: `6663c5decbc46fb1`

| Field | Value |
|---|---|
| SHA-256 | `6663c5decbc46fb125367f87a6e275436e96a660162d26f385a55724ee9ffc21` |
| Family label | `Mirai` |
| File name | `nklx86` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee4446c84d1fd6091e78a9ed62e3d898` |
| SHA-1 | `ddb94aea56aa48376751a5e92583977110e64861` |
| SHA-256 | `6663c5decbc46fb125367f87a6e275436e96a660162d26f385a55724ee9ffc21` |
| SHA3-384 | `04421109c7f7eac947061885d78087ffb1c6ce8d68910bf61ce37978618325ca2ed13ffab085ca54964c20580607a02b` |
| TLSH | `T120A36CC1D283E4F5F80A01B5602AF33BB631DAB90128FDE7F7545B37A825A60754AB4D` |
| TELFHASH | `t18831f3f66b350de8abd05803a20e6b61ed5dab3f102467e306f55854366308192bfc3d` |
| SSDEEP | `1536:yWH5CNBn/bXzA+1iwmnd20vFRu9MaQO1VjwjKg3NkyeqTD4uXEQb+Y/bNX:yWZ8dPAVfn7vfcpgy4FXhb+OhX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_6663c5de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6663c5decbc46fb125367f87a6e275436e96a660162d26f385a55724ee9ffc21"
    family = "Mirai"
    file_name = "nklx86"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:06"
  condition:
    hash.sha256(0, filesize) == "6663c5decbc46fb125367f87a6e275436e96a660162d26f385a55724ee9ffc21"
}
```

### Sample 20: `ff877de8d2a4447e`

| Field | Value |
|---|---|
| SHA-256 | `ff877de8d2a4447e24f193b8c0e91de75b1465bc8c2b2420308121f1ecc50b1f` |
| Family label | `Mirai` |
| File name | `nklarm6` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb432ebcb5c8238653692119b96ff126` |
| SHA-1 | `b372acb0de36f920bbf9f477a62fc8b716cac7c1` |
| SHA-256 | `ff877de8d2a4447e24f193b8c0e91de75b1465bc8c2b2420308121f1ecc50b1f` |
| SHA3-384 | `4bc3624c86dce4b8ac106891c19228eb83376dc14021b34caea1e456cdb9dc921477ec2e6d1025604c724dfaeeaa1315` |
| TLSH | `T1D5C33CD9BC818B11D6C525BAFE1E618E33234FB8E3FD71139E145B29534A86B0E37605` |
| TELFHASH | `t10ce02620b6499fc4f7cec0a5c0a9631562da784faa3828a035adc74fcaa5ea4341502d` |
| SSDEEP | `3072:CGORAid4clCn5sBE9s+P1rM6MVYLnLUXa/2mx0P5gZqlhZ8:nXsOFP1WVYLwXaemx4t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_ff877de8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff877de8d2a4447e24f193b8c0e91de75b1465bc8c2b2420308121f1ecc50b1f"
    family = "Mirai"
    file_name = "nklarm6"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:04"
  condition:
    hash.sha256(0, filesize) == "ff877de8d2a4447e24f193b8c0e91de75b1465bc8c2b2420308121f1ecc50b1f"
}
```

### Sample 21: `37897cffb9392d04`

| Field | Value |
|---|---|
| SHA-256 | `37897cffb9392d041629e0398514472ae4227636b2467e741f7dfc80dc6e6296` |
| Family label | `Mirai` |
| File name | `nabmpsl` |
| File type | `elf` |
| First seen | `2026-11-12 06:55:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5640d81f573167210816148c8b69366e` |
| SHA-1 | `7ffd672580d96dc555a5c94c7c11406d4dfe2aa1` |
| SHA-256 | `37897cffb9392d041629e0398514472ae4227636b2467e741f7dfc80dc6e6296` |
| SHA3-384 | `0b37d85400e061746c78a2377ad8db57c3fcb9f3e50b8b389f0f1d446ffbfbd016caaa9d055c582c5858df799696890e` |
| TLSH | `T179A3F809FF914EFBD86FDE3706A90B4630CC555722A93B763974C828F44A64B49D3CA8` |
| SSDEEP | `1536:qJeuDyuJvDd5Kkz6wt+Tkgp5CGErhsO7kDcTaLtzOmVqxtQbNwO:qBHf1zSDcWBYrQhw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_37897cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37897cffb9392d041629e0398514472ae4227636b2467e741f7dfc80dc6e6296"
    family = "Mirai"
    file_name = "nabmpsl"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:01"
  condition:
    hash.sha256(0, filesize) == "37897cffb9392d041629e0398514472ae4227636b2467e741f7dfc80dc6e6296"
}
```

### Sample 22: `13a04c95e6dae607`

| Field | Value |
|---|---|
| SHA-256 | `13a04c95e6dae607662b569c83091e436246a583a81cd8789329b95219c025f0` |
| Family label | `Mirai` |
| File name | `nklmips` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89ac2cff0591a943bf4a8409ce6bded0` |
| SHA-1 | `c7124a4f47ddcb58261492dc203d4d17270359c9` |
| SHA-256 | `13a04c95e6dae607662b569c83091e436246a583a81cd8789329b95219c025f0` |
| SHA3-384 | `124223baf05e0b4c913471cb3809dee0ad189b2a8a57a675e6ddfbdcd4facacf1edfc5f8b11c88089d8ea647ec2abab0` |
| TLSH | `T120D3E94E7E539FADF328C2314BB38B75A79923D223E08185E65CD6105E6034E586FFA4` |
| TELFHASH | `t1bf118f1c497423e497322d892badfb77e15130eb0b216d378e10f9ada66dd819d00c1c` |
| SSDEEP | `1536:eLVzxhE5A0ySKilGilMElZ0KZQ9gEyJkDOktTQj5AxRcEvy5tQ2QerVFbNHFCr:Ezh1SoKeg+OJdEvy7QUFhHFQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_13a04c95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a04c95e6dae607662b569c83091e436246a583a81cd8789329b95219c025f0"
    family = "Mirai"
    file_name = "nklmips"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:58"
  condition:
    hash.sha256(0, filesize) == "13a04c95e6dae607662b569c83091e436246a583a81cd8789329b95219c025f0"
}
```

### Sample 23: `7e32a6229d708362`

| Field | Value |
|---|---|
| SHA-256 | `7e32a6229d7083626b2b9ec305f1683685b0b90d03ad3095342de5f124b807c6` |
| Family label | `Mirai` |
| File name | `nabm68k` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b09ed7c3e2a9cc029ead0034c99fb5d` |
| SHA-1 | `87c727920e5f9fef230298f2b9e75fc43f793a24` |
| SHA-256 | `7e32a6229d7083626b2b9ec305f1683685b0b90d03ad3095342de5f124b807c6` |
| SHA3-384 | `d7df66efbd973a26cc16516325ee50d6817bac332b584855fad16ead10c0e1204fcb65c83b479b284af62c598fea8a06` |
| TLSH | `T16B836CE2F900DD79F81EE73B8453510BB632E2A106421E3373A73867E9B61D50976F86` |
| SSDEEP | `1536:gRM5Mr1lutchCqVvp8/2ht6CDvzUWGO0rfqFpkZSqbNWy:15MutYCqVvznzlGvXYqhWy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_7e32a622
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e32a6229d7083626b2b9ec305f1683685b0b90d03ad3095342de5f124b807c6"
    family = "Mirai"
    file_name = "nabm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:56"
  condition:
    hash.sha256(0, filesize) == "7e32a6229d7083626b2b9ec305f1683685b0b90d03ad3095342de5f124b807c6"
}
```

### Sample 24: `dec231a2a59ee775`

| Field | Value |
|---|---|
| SHA-256 | `dec231a2a59ee7754f7f9b61a0750495ba59d1cdade5e38119d05894b27d6730` |
| Family label | `Mirai` |
| File name | `splm68k` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41429926fa733aa27459058368c5d51d` |
| SHA-1 | `9d96e71e810eb05ab1e9181532c505183a777588` |
| SHA-256 | `dec231a2a59ee7754f7f9b61a0750495ba59d1cdade5e38119d05894b27d6730` |
| SHA3-384 | `9bd960dcc83c7a297b489978609c10090b0b3ee7c5c8d6d97dee65f984c25c4b380757c7a4257e57267e75ef3617e19f` |
| TLSH | `T12FB34CB1F4009D6EF46BD7B78053020A7531A7F546A22B37326BBC63DA7E0751CA2E46` |
| SSDEEP | `1536:waWeGLElxdWRea0Z5+9U2iAGfMtRqq8/rxhDuf3T3OpsJwwtOld9VqbNOc:wBeGADdWRdK5+9iXfsRqH4T+pwe3qhOc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_dec231a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dec231a2a59ee7754f7f9b61a0750495ba59d1cdade5e38119d05894b27d6730"
    family = "Mirai"
    file_name = "splm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:53"
  condition:
    hash.sha256(0, filesize) == "dec231a2a59ee7754f7f9b61a0750495ba59d1cdade5e38119d05894b27d6730"
}
```

### Sample 25: `30e14201a37f0853`

| Field | Value |
|---|---|
| SHA-256 | `30e14201a37f08530fd51e2d32f2926b0b8e6bf4a1f9901fc80363d4da4e3360` |
| Family label | `Mirai` |
| File name | `nabarm7` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f2d9724040c26f5aedd42aae175ef909` |
| SHA-1 | `cb98c0e9281f4c9fca22608e5663dc99734cdfde` |
| SHA-256 | `30e14201a37f08530fd51e2d32f2926b0b8e6bf4a1f9901fc80363d4da4e3360` |
| SHA3-384 | `13de68b92076970c04cebdaf81f5f4535eca3871ab189266c8fa20ca41802f980b5856af0b3fbd0ec4fb72c78d792cf9` |
| TLSH | `T142A32A5AFD816B11D5D521BAFE4E528933130BBCE3FA72129E246B2463CB91B0F77502` |
| TELFHASH | `t179e07d43cb7211b876c02b0552cb021c8ddab4c557490c89434c0f47cb13b83b41b731` |
| SSDEEP | `3072:3xJNHtAiecI9FJeaZnLZaUcslrjbfBSQ94Eh2:3xdAiecIAaFVaUcslrvfH4R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_30e14201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e14201a37f08530fd51e2d32f2926b0b8e6bf4a1f9901fc80363d4da4e3360"
    family = "Mirai"
    file_name = "nabarm7"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:51"
  condition:
    hash.sha256(0, filesize) == "30e14201a37f08530fd51e2d32f2926b0b8e6bf4a1f9901fc80363d4da4e3360"
}
```

### Sample 26: `f017ea979daf2a33`

| Field | Value |
|---|---|
| SHA-256 | `f017ea979daf2a3345c466f55b29be5c980e6fc7c73be2107e19b85bbf4d72d8` |
| Family label | `Mirai` |
| File name | `nklm68k` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cc3284e38e46ad6411555439e92c8f2` |
| SHA-1 | `24559ba1565923a2fc3872df38563deb2e76d297` |
| SHA-256 | `f017ea979daf2a3345c466f55b29be5c980e6fc7c73be2107e19b85bbf4d72d8` |
| SHA3-384 | `c67ad8a3fa452523ac5ec843d3d3abca9f4e437a7644ccee2e4119f8a7abe87dc6b17b95be8d315ebaf5656702371846` |
| TLSH | `T16FB35DE5F4109D3DF81BE7B780531246B131E3B54A932B27366BBC63EA7A0741863E46` |
| SSDEEP | `3072:u6xYk6QvbAIm1aiD8LDFkUsKse+lVbRjqh1S:uKm1aZL2XKI3b50S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_f017ea97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f017ea979daf2a3345c466f55b29be5c980e6fc7c73be2107e19b85bbf4d72d8"
    family = "Mirai"
    file_name = "nklm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:49"
  condition:
    hash.sha256(0, filesize) == "f017ea979daf2a3345c466f55b29be5c980e6fc7c73be2107e19b85bbf4d72d8"
}
```

### Sample 27: `eff866c9c928f530`

| Field | Value |
|---|---|
| SHA-256 | `eff866c9c928f530994bc95636b4d0a9b956c2af6f7179e36b2921be4bdc0dd8` |
| Family label | `Mirai` |
| File name | `nklmpsl` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ded5f8325017a8cfdf201d3270aa5d0f` |
| SHA-1 | `948e799078b36e532ecdc07439562f0d57607f33` |
| SHA-256 | `eff866c9c928f530994bc95636b4d0a9b956c2af6f7179e36b2921be4bdc0dd8` |
| SHA3-384 | `01de7b90f0451205d6c0f8decb2b3ff5b9902e18ab5d5676238ebbf9221d1d9b2416948acd8662f35c2e5b02fef752d7` |
| TLSH | `T151D32A0AFFA11FFBD4AFDE3306AA070A359C191621B52B3675B4C81CB55E64B0AD3C64` |
| SSDEEP | `1536:ePKJTYjBSxAJ9rby5C49/Ty7x+XQpao/bdEb8Q0P5fMoO95aqyhAexujlhA8BfOS:eyy/49/Ty08AKUJrB5jA0yhu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_eff866c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff866c9c928f530994bc95636b4d0a9b956c2af6f7179e36b2921be4bdc0dd8"
    family = "Mirai"
    file_name = "nklmpsl"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:46"
  condition:
    hash.sha256(0, filesize) == "eff866c9c928f530994bc95636b4d0a9b956c2af6f7179e36b2921be4bdc0dd8"
}
```

### Sample 28: `a334bc01514f3184`

| Field | Value |
|---|---|
| SHA-256 | `a334bc01514f3184f24c2ba9d3e703e4eb82f6a4c8c0fe29d1d6cb87b2be54eb` |
| Family label | `Mirai` |
| File name | `nklppc` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6bcebd1671f20d916f2a9134b71ffe6` |
| SHA-1 | `b565ffab90ed7261c5dcba6ced433184bf5f2c4d` |
| SHA-256 | `a334bc01514f3184f24c2ba9d3e703e4eb82f6a4c8c0fe29d1d6cb87b2be54eb` |
| SHA3-384 | `eff3b0ebda0994be2ec02d3b979f8ba0898456db59df4e96e0d02321f54494db9333f95bc722282bf469bd50537e4f7a` |
| TLSH | `T11EB35A4177690447F3A70EB0193FBBE0A3EED6A521F0A585695EDB4F8131A321486FCE` |
| SSDEEP | `1536:5/0dW9JjaOJG8lQTrkrLYIHiv25BngiXiqemYnsHaNiR6OJKbUzP9zmqqAXQ3nco:5/GWraOJ8SBnvXiqKsHpRXBen5/khDe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_a334bc01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a334bc01514f3184f24c2ba9d3e703e4eb82f6a4c8c0fe29d1d6cb87b2be54eb"
    family = "Mirai"
    file_name = "nklppc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:44"
  condition:
    hash.sha256(0, filesize) == "a334bc01514f3184f24c2ba9d3e703e4eb82f6a4c8c0fe29d1d6cb87b2be54eb"
}
```

### Sample 29: `524b717901a23d47`

| Field | Value |
|---|---|
| SHA-256 | `524b717901a23d47a55578975db09e935d3b5ac6f59d294d855f3a79b8ab090b` |
| Family label | `Mirai` |
| File name | `nklarm` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41dba568e32f387c0e579dce5ebac775` |
| SHA-1 | `14588204f08d69054e45cdde8a7f6f42b9dd389e` |
| SHA-256 | `524b717901a23d47a55578975db09e935d3b5ac6f59d294d855f3a79b8ab090b` |
| SHA3-384 | `6fdba0fde2168457b28568d89001a7552180afe4d7823249cb37ecbe312ebabef37b4b208b76621570c6cd981af3e47f` |
| TLSH | `T197B33989BC819612C6E160B6FB1FD1CD3B2743B8D3E67103DD18AB29638B9670E77251` |
| TELFHASH | `t159410166db500edc67dd424841ee102a44de35fe172410929f6d6b8f95439dab12983a` |
| SSDEEP | `3072:bjudl9BjZptrDk2G457LiMHkFt/p9xSOFFrH:v0trDk2nJLiMEFtTxSOvz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_524b7179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524b717901a23d47a55578975db09e935d3b5ac6f59d294d855f3a79b8ab090b"
    family = "Mirai"
    file_name = "nklarm"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:41"
  condition:
    hash.sha256(0, filesize) == "524b717901a23d47a55578975db09e935d3b5ac6f59d294d855f3a79b8ab090b"
}
```

### Sample 30: `9b030e2c5882dc9d`

| Field | Value |
|---|---|
| SHA-256 | `9b030e2c5882dc9d4206c544188dfe9d356e92a481b5244ac905ceb5def3620c` |
| Family label | `Mirai` |
| File name | `nabspc` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f34182972b3b61e0ee36dc13902e13b` |
| SHA-1 | `97c679f2fa9263137dc6c09f07569c3a198062b9` |
| SHA-256 | `9b030e2c5882dc9d4206c544188dfe9d356e92a481b5244ac905ceb5def3620c` |
| SHA3-384 | `a410bad1bc77c89e89e2658de9d1924151fa554d1990c7978be645991a7a983cfed4e5108bf580ab96a2934ba3b90daa` |
| TLSH | `T15C835C727E76092BC5C5647661E35231F1F6478620BCCE1A3DA10E8CFF68B403257BAA` |
| SSDEEP | `1536:eAiJfQ34A34W79pecceimF0hn8Up9NW55MQtmbNp4:eX63QKs8+9NwMThp4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_9b030e2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b030e2c5882dc9d4206c544188dfe9d356e92a481b5244ac905ceb5def3620c"
    family = "Mirai"
    file_name = "nabspc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:39"
  condition:
    hash.sha256(0, filesize) == "9b030e2c5882dc9d4206c544188dfe9d356e92a481b5244ac905ceb5def3620c"
}
```

### Sample 31: `43f01ffea0e2affd`

| Field | Value |
|---|---|
| SHA-256 | `43f01ffea0e2affdf0ddf22edffee3a38de00d8d211cb4ecdc6c83b44d5cbcdd` |
| Family label | `Mirai` |
| File name | `b` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d1e024b4bfc190eafd31f752f83eed1` |
| SHA-1 | `2824a6d3491f86857deee932480250cc1fc21252` |
| SHA-256 | `43f01ffea0e2affdf0ddf22edffee3a38de00d8d211cb4ecdc6c83b44d5cbcdd` |
| SHA3-384 | `f552f99227f8bc6220f2ba2c36d025f07f38df8506f9460a06952fdf7cb52c1de2465fcd8c6025f8b669ae485672e58e` |
| TLSH | `T11DD32A99FC809B11D5D525BAFE0E618D33134FB8E3FA71029E145B2A538AC6B0F77606` |
| TELFHASH | `t184e02024da5c45d6eec8580482da5316b049b855b50e057259d35a5e4e32d85b719007` |
| SSDEEP | `3072:v0y7RA7U71K32QxJZEX817HxjHSuQJnKm8Nh7ZMaHAzCsxMFV868nwh1hHu:vtwDJcKHZQJnKh1MaHAzCsxkVVhzu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_43f01ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43f01ffea0e2affdf0ddf22edffee3a38de00d8d211cb4ecdc6c83b44d5cbcdd"
    family = "Mirai"
    file_name = "b"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:36"
  condition:
    hash.sha256(0, filesize) == "43f01ffea0e2affdf0ddf22edffee3a38de00d8d211cb4ecdc6c83b44d5cbcdd"
}
```

### Sample 32: `18ba92e53925ba58`

| Field | Value |
|---|---|
| SHA-256 | `18ba92e53925ba588f32ffb2e6bccedd9d3f7dc94077d9d21303f123d9843e89` |
| Family label | `Mirai` |
| File name | `nabx86` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5d36ff7bf3c8aa59e557ec11cfb0179` |
| SHA-1 | `65b43408390334c672dc3ac8e585ff39636002e8` |
| SHA-256 | `18ba92e53925ba588f32ffb2e6bccedd9d3f7dc94077d9d21303f123d9843e89` |
| SHA3-384 | `a83c71d156abfc0d74aba07e733d772cbf3a282fa4a43efe2cc1fc003b45dc33f7bc78c7df9adf1301ef510a4fe336f7` |
| TLSH | `T1A8637DC5D683D8F6E82A07B1547BE7739A35E53A0025FBC6CB54ED32EC22501BA2635C` |
| TELFHASH | `t16131f4f71dbd0de8f7d0a844c30aafd2592bd63b656132b50572551023e7ed250b5c78` |
| SSDEEP | `1536:IK4HXraC2jouYqxvOOvN8MkGbXRC8avRGjkEbNU:IlUG8LN8MBPa5GjthU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_18ba92e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18ba92e53925ba588f32ffb2e6bccedd9d3f7dc94077d9d21303f123d9843e89"
    family = "Mirai"
    file_name = "nabx86"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:34"
  condition:
    hash.sha256(0, filesize) == "18ba92e53925ba588f32ffb2e6bccedd9d3f7dc94077d9d21303f123d9843e89"
}
```

### Sample 33: `ea0d3865b9b4a505`

| Field | Value |
|---|---|
| SHA-256 | `ea0d3865b9b4a5053c1b77101c5352629771d403d9226dcd39b6bee547ad6894` |
| Family label | `Mirai` |
| File name | `nabmips` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1583d93ebcda27a714ba8af93ef417eb` |
| SHA-1 | `a934fe5195f3582a4eb3e7632f74b0c896547a8c` |
| SHA-256 | `ea0d3865b9b4a5053c1b77101c5352629771d403d9226dcd39b6bee547ad6894` |
| SHA3-384 | `ec3aaa4495c4bab287548612d43541973c5bc775bdd0e4fda98748dbcd04c457075105de79b5ee1f912d4da0b5e1bf33` |
| TLSH | `T155A3D95E7E118FEDF229C73147B78B31A35933D226E18644E6ACD2045E7024D686FFA8` |
| TELFHASH | `t1ba112e5c89b423e19b311d9a2b6dff77e5a130df07266d378f11a9ad9aadc426d00c0c` |
| SSDEEP | `1536:1pGHpG4WsGWUT5LBnk4GOfs9qlATh6j2LXeA8AOhECXqbGlsE1eObPbNVa:NTvXkAlARTnCXhl7PhVa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_ea0d3865
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea0d3865b9b4a5053c1b77101c5352629771d403d9226dcd39b6bee547ad6894"
    family = "Mirai"
    file_name = "nabmips"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:31"
  condition:
    hash.sha256(0, filesize) == "ea0d3865b9b4a5053c1b77101c5352629771d403d9226dcd39b6bee547ad6894"
}
```

### Sample 34: `4c641cda8ba71f78`

| Field | Value |
|---|---|
| SHA-256 | `4c641cda8ba71f78ffd2b84fc6789ec5183e6c377e9cbfe6b84baeda80343d6b` |
| Family label | `Mirai` |
| File name | `nklarm7` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6556bc5abe12f6c2c969b040fb0c54d` |
| SHA-1 | `73123ff1fe06112dda57e403ce7ef24a56e29f09` |
| SHA-256 | `4c641cda8ba71f78ffd2b84fc6789ec5183e6c377e9cbfe6b84baeda80343d6b` |
| SHA3-384 | `e59ff2a2b66d59ba99746d10ed867a0b668b21b8f9da671d950319b82dd3ec9bb52a78c57c56c9318fdfe06a709ae1b0` |
| TLSH | `T1D8D32A99FC805B11D5D525BAFE1E618E33134BB8E3F97102DE145B2A638AC6B0F77A01` |
| TELFHASH | `t165e02833edc904c9b6c5544003dd0301e30968cf3610045025ef574f4d74d84750d516` |
| SSDEEP | `3072:3mNRAvIyzRk25QnEE8jN6PEXOwq4YWpEhJa4uQ6ElKCX8aGav1hH:nBQpMNZOwqKuJa4uQ6ElJXfvb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_4c641cda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c641cda8ba71f78ffd2b84fc6789ec5183e6c377e9cbfe6b84baeda80343d6b"
    family = "Mirai"
    file_name = "nklarm7"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:29"
  condition:
    hash.sha256(0, filesize) == "4c641cda8ba71f78ffd2b84fc6789ec5183e6c377e9cbfe6b84baeda80343d6b"
}
```

### Sample 35: `4b500f70468c1b56`

| Field | Value |
|---|---|
| SHA-256 | `4b500f70468c1b56802b3b01d63b0df36be84288f8e7c3cd366f0c3aa0ab9047` |
| Family label | `Mirai` |
| File name | `nklspc` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d76f99b1e9350c48015bd0e23c53bf7` |
| SHA-1 | `de2a12ee85477080258b7d6d352fa1ae71148156` |
| SHA-256 | `4b500f70468c1b56802b3b01d63b0df36be84288f8e7c3cd366f0c3aa0ab9047` |
| SHA3-384 | `d95fd5bd64c14b99ddfbc3d82ea86488f70d4da2d4d0d84104e4cbcbb91aaa29758fd3cd38d450df8ae3defa020454e2` |
| TLSH | `T11FB34B21FD39192BC5C4717651E34631F1F6539925BC8A4A3EA31D8CEF28710312BAEE` |
| SSDEEP | `1536:Kb/SQEoc8gsZJMFVyn3g8DG+KRpXRcS/JHVL8pEOF55tZDbN9th:4/eoMsZCMSJaE8JDh9th` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_4b500f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b500f70468c1b56802b3b01d63b0df36be84288f8e7c3cd366f0c3aa0ab9047"
    family = "Mirai"
    file_name = "nklspc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:26"
  condition:
    hash.sha256(0, filesize) == "4b500f70468c1b56802b3b01d63b0df36be84288f8e7c3cd366f0c3aa0ab9047"
}
```

### Sample 36: `ba483670f1f8242c`

| Field | Value |
|---|---|
| SHA-256 | `ba483670f1f8242c1f906168d5ef5486646b3b9c30ab5c563bc905e38960c4ae` |
| Family label | `Mirai` |
| File name | `nabsh4` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff7e0cefd01d24ea113efe9b4a8faca7` |
| SHA-1 | `4b02cb3ce92356009c8ca95d033d515c80541db0` |
| SHA-256 | `ba483670f1f8242c1f906168d5ef5486646b3b9c30ab5c563bc905e38960c4ae` |
| SHA3-384 | `83ec02cd188d6e1625cc5cf5097295714bc4a1815b837bf7bd246dece2a757b2b69b15cf76bb5fcd95092fa16e241688` |
| TLSH | `T1D4639D67ED362E5CC15982B670E08B396B23D9A0414B1DBE6C65C66EC043FDCF6093B8` |
| SSDEEP | `1536:y/M0gRPzYvOlhXfQulIi2nKc6ak7m79JC/HXIbNm:y0TLqOlhVm8c+I9JWIhm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_ba483670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba483670f1f8242c1f906168d5ef5486646b3b9c30ab5c563bc905e38960c4ae"
    family = "Mirai"
    file_name = "nabsh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:24"
  condition:
    hash.sha256(0, filesize) == "ba483670f1f8242c1f906168d5ef5486646b3b9c30ab5c563bc905e38960c4ae"
}
```

### Sample 37: `981fd572102f97b9`

| Field | Value |
|---|---|
| SHA-256 | `981fd572102f97b94d43b5c71567ac15dac2b08d8529f2b6ff097d1d2dc95281` |
| Family label | `Mirai` |
| File name | `nabppc` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `451cadb3b671eb4f535b0f8c6fe572cf` |
| SHA-1 | `90a2aaabf69d20028778075d9e42dabd7533414b` |
| SHA-256 | `981fd572102f97b94d43b5c71567ac15dac2b08d8529f2b6ff097d1d2dc95281` |
| SHA3-384 | `b69ce28960c226b4ef1683d027b3aa0b5a1ca58bc1db65be93c3f036e89d22ef698c8ffd21d8e7b01e6406059b225499` |
| TLSH | `T1EB736D00B70C0483E2775EF07E3F37D1E3EA9AD021B4A689651DAB4D9271E315586EDE` |
| SSDEEP | `1536:bm3DampC9liygdCG3SszapSVqpJtAUKfK99sfbNZj:bm3hCT/RPBKS9WhZj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_981fd572
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981fd572102f97b94d43b5c71567ac15dac2b08d8529f2b6ff097d1d2dc95281"
    family = "Mirai"
    file_name = "nabppc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:20"
  condition:
    hash.sha256(0, filesize) == "981fd572102f97b94d43b5c71567ac15dac2b08d8529f2b6ff097d1d2dc95281"
}
```

### Sample 38: `652d0182afa9fe66`

| Field | Value |
|---|---|
| SHA-256 | `652d0182afa9fe66832640eb434ce3f2480b375f20dfed058ce7d37058fcd061` |
| Family label | `Mirai` |
| File name | `nklsh4` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ce00601d60168da2602764f1cff0ba1` |
| SHA-1 | `fbed635f658a4a5abfdc07a4f714eef492ae7d45` |
| SHA-256 | `652d0182afa9fe66832640eb434ce3f2480b375f20dfed058ce7d37058fcd061` |
| SHA3-384 | `5f342dc8b0eca0930767891ffb699ce956a4b2a9a1a1a937d3b84b0bcb7324ab8de070207062d8e4010a8ea4326ec74e` |
| TLSH | `T11CA3BF22CCB10E9CF13B6D3050F99A7A9723E685941B2DBB3C46C265404BED8F956BB4` |
| SSDEEP | `1536:ne0XSRwz3P2cAj9n8H9ZSL2+/Lq0zZj0seiCMK9NSgUKkKCX+eIbN0:ne0XSiz3+j5n8dZqt+0BEh90KvmIh0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_652d0182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "652d0182afa9fe66832640eb434ce3f2480b375f20dfed058ce7d37058fcd061"
    family = "Mirai"
    file_name = "nklsh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:18"
  condition:
    hash.sha256(0, filesize) == "652d0182afa9fe66832640eb434ce3f2480b375f20dfed058ce7d37058fcd061"
}
```

### Sample 39: `0e926c0e9816533c`

| Field | Value |
|---|---|
| SHA-256 | `0e926c0e9816533c25acd45c155751c730bcb3102cdba74b65a12898f902bae7` |
| Family label | `unknown` |
| File name | `prlproxy_static` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:15` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5cefaf1a9a8c0f3b9444118e5d84a9f` |
| SHA-1 | `b71092527d09f7608fdb64689fc8611fbe84f2c9` |
| SHA-256 | `0e926c0e9816533c25acd45c155751c730bcb3102cdba74b65a12898f902bae7` |
| SHA3-384 | `076abcedd038390bc1332d015f8dc7b1a6e6213007aeef32b2c572feac02b42fa2cca11b2eddaf2a8b835fe9be8009ae` |
| TLSH | `T18F564A13FCA915E9C1AE923889729652BB717C491B3123D32B60B3387F73BD069B9354` |
| TELFHASH | `t1af62a975497c71b5a2a6da11f3a3b0f895331cb567f438b01067ad85efc1e801cea86b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:mNXfN+TB/aoUao+CC2vFZ91hYyiBvfk60qSJvskrUR8TXOrsJ+ycmVCHxKlK1Kcy:mNXyBioYdv6avAQXykkfJ+Ek` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_0e926c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e926c0e9816533c25acd45c155751c730bcb3102cdba74b65a12898f902bae7"
    family = "unknown"
    file_name = "prlproxy_static"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:15"
  condition:
    hash.sha256(0, filesize) == "0e926c0e9816533c25acd45c155751c730bcb3102cdba74b65a12898f902bae7"
}
```

### Sample 40: `7eca922f41c5ef2e`

| Field | Value |
|---|---|
| SHA-256 | `7eca922f41c5ef2efbbf465104e83bc457cb8ec0c9bb2bdd6511754ab59d8aba` |
| Family label | `unknown` |
| File name | `dawdawd` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f1b73683cb17185e18a02215210f141` |
| SHA-1 | `2b247517aee3aee03edbddf9740d4f658668c0c5` |
| SHA-256 | `7eca922f41c5ef2efbbf465104e83bc457cb8ec0c9bb2bdd6511754ab59d8aba` |
| SHA3-384 | `08cd9277966093a2e8d1fc794782bb63e5e4455a42dec88707b12c64065d1c74af6189547181e83f2f9f464ff1555f63` |
| TLSH | `T10FB59E17F57114ACDABAC838838FC9B39A14B4954282753B3FD4A7203F29E609F1DB56` |
| SSDEEP | `49152:ajvWXQg2B9oywpj7JN4NWhIU6i8Aepwr:auXF2GHjI4W+sp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_7eca922f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eca922f41c5ef2efbbf465104e83bc457cb8ec0c9bb2bdd6511754ab59d8aba"
    family = "unknown"
    file_name = "dawdawd"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:11"
  condition:
    hash.sha256(0, filesize) == "7eca922f41c5ef2efbbf465104e83bc457cb8ec0c9bb2bdd6511754ab59d8aba"
}
```

### Sample 41: `74c9593919e5c76a`

| Field | Value |
|---|---|
| SHA-256 | `74c9593919e5c76a363fc19f4f74d34afbb34c512024ee8fe61a4d15c9a02992` |
| Family label | `CyberStrikeAI` |
| File name | `beacon_linux_amd64_p_084f0c5eace84f` |
| File type | `elf` |
| First seen | `2026-11-12 06:54:05` |
| Reporter | `abuse_ch` |
| Tags | `CyberStrikeAI, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48719ac4268c2e68aed2ad88506e6b77` |
| SHA-1 | `c89119a05e38ab48ed1847ea8041ce8e22cb3831` |
| SHA-256 | `74c9593919e5c76a363fc19f4f74d34afbb34c512024ee8fe61a4d15c9a02992` |
| SHA3-384 | `1d04eac21d1b33f9f3d133c700f17775e9f1996f50ba033cc84eaf6c7dad05ddfa6c52051dcdc47500a4da483ebf1705` |
| TLSH | `T1A4565C13EC9514E9C1AE92358A62A253BB717C895F3123D32F50F7382F72BD0A9B8754` |
| TELFHASH | `t17742577549bc35b5b69aea10b392b4f495372ca562f438b11063ad84ffc1e805ce387b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:157RBurwtKqu/52PL5jKuntnj5itKOjKYvA2C/xSI57whUDBct4GgKyK1KcRnltV:15HuroR2ZE784E9ltPSIEM` |

#### Technical Assessment

- The sample is tracked as `CyberStrikeAI` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CyberStrikeAI_041_74c95939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c9593919e5c76a363fc19f4f74d34afbb34c512024ee8fe61a4d15c9a02992"
    family = "CyberStrikeAI"
    file_name = "beacon_linux_amd64_p_084f0c5eace84f"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:05"
  condition:
    hash.sha256(0, filesize) == "74c9593919e5c76a363fc19f4f74d34afbb34c512024ee8fe61a4d15c9a02992"
}
```

### Sample 42: `7447d7187ae2246e`

| Field | Value |
|---|---|
| SHA-256 | `7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a` |
| Family label | `Mirai` |
| File name | `7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a` |
| File type | `sh` |
| First seen | `2026-11-12 06:09:10` |
| Reporter | `spydisec` |
| Tags | `dropper, honeypot, Mirai, sh, web` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d4689bb036088552a3161ae93a2561d` |
| SHA-1 | `1bcaf2cc5fc6654c5bd47b0f867046eae7bb626e` |
| SHA-256 | `7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a` |
| SHA3-384 | `3bbdcaa014e2606eb86f93813077eb4ad451cb28018a31a912d403840c09c0c6d565255736c64070757d905c57d11d98` |
| TLSH | `T17F619EF0F9B6C970378D863CF18D053ABED74A3E44AC3521A467AC74665C22DB158B3A` |
| SSDEEP | `96:cMOkl3FsXhmNry6wFZ7eaWthz1V0D11SzvDnCyDyc6DNyDy/A:chyFo6wFZ7eaUhzjm1S/2p4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_7447d718
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a"
    family = "Mirai"
    file_name = "7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a"
    file_type = "sh"
    first_seen = "2026-11-12 06:09:10"
  condition:
    hash.sha256(0, filesize) == "7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a"
}
```

### Sample 43: `e7a44dcb3956c369`

| Field | Value |
|---|---|
| SHA-256 | `e7a44dcb3956c369251f0af002247e4a0f6d2ddae74c5b982b63ba4162e308f1` |
| Family label | `unknown` |
| File name | `install.ps1` |
| File type | `ps1` |
| First seen | `2026-11-12 06:04:09` |
| Reporter | `ghozt` |
| Tags | `clickfix, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a98d13bb29c63c15c9432cd4397043f` |
| SHA-1 | `ff797b48c616fb696dc54de8c08dd94d17a09dc5` |
| SHA-256 | `e7a44dcb3956c369251f0af002247e4a0f6d2ddae74c5b982b63ba4162e308f1` |
| SHA3-384 | `4659f0e0a38d64858384d68480ff9c04dabd164afe61175d7a348e193624b699fe6016af41108a8867d627052096128c` |
| TLSH | `T1C76694DB3BC807E8AA688EED420635DA1AE1D17F2DBF114C52E1492B742FD1376A0D74` |
| SSDEEP | `12288:A3t1v3fiCUT8FShN4eh6q7zzEH7q25DXblO1d9sxHN01+szWNFLzcTTMwXXTTwnC:e1vuTrbQm9sX0Tz2zcTTpTMt+HtlDfge` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_e7a44dcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7a44dcb3956c369251f0af002247e4a0f6d2ddae74c5b982b63ba4162e308f1"
    family = "unknown"
    file_name = "install.ps1"
    file_type = "ps1"
    first_seen = "2026-11-12 06:04:09"
  condition:
    hash.sha256(0, filesize) == "e7a44dcb3956c369251f0af002247e4a0f6d2ddae74c5b982b63ba4162e308f1"
}
```

### Sample 44: `a1871eb203ab9137`

| Field | Value |
|---|---|
| SHA-256 | `a1871eb203ab9137191fe77d01f9c34db383e197e22f5651ac0a98389a040674` |
| Family label | `njrat` |
| File name | `AB0B63F826E6CFBDF525D63F9F3811AF.exe` |
| File type | `exe` |
| First seen | `2026-11-12 05:50:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab0b63f826e6cfbdf525d63f9f3811af` |
| SHA-1 | `9bed149e0d2cd335a95a9733675d0da61a2c7347` |
| SHA-256 | `a1871eb203ab9137191fe77d01f9c34db383e197e22f5651ac0a98389a040674` |
| SHA3-384 | `5b13b614caeea358eee84a3b6c47174da46c28c6f15a0cf57f4b5c0530f2d4eab5bd1682360e3b29e88daf915ec7af78` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18CD63386B7840B94D859253A98DB603253E1BCA30732C5CA3FD85B5E2F633EAFD25741` |
| SSDEEP | `393216:dWFkV31DPsZg2KezvSa4CxK4+HsMRDBbYonw:wWV31wLXH4DrRFb3` |
| ICON-DHASH | `ae3c385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_044_a1871eb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1871eb203ab9137191fe77d01f9c34db383e197e22f5651ac0a98389a040674"
    family = "njrat"
    file_name = "AB0B63F826E6CFBDF525D63F9F3811AF.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:50:09"
  condition:
    hash.sha256(0, filesize) == "a1871eb203ab9137191fe77d01f9c34db383e197e22f5651ac0a98389a040674"
}
```

### Sample 45: `95250a426cdfb701`

| Field | Value |
|---|---|
| SHA-256 | `95250a426cdfb70173fc9b8f25000d1dc0b5bbc30be667eda6e55853006fc1d2` |
| Family label | `Ngioweb` |
| File name | `1.fp.mcm.armv7l` |
| File type | `elf` |
| First seen | `2026-11-12 05:49:53` |
| Reporter | `stillsilly` |
| Tags | `arm, armv7l, elf, iot, ngioweb, proxy` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4054dd4337215173bfde7cf334fb9688` |
| SHA-1 | `c47ece3eb1b3c2488f0d601483090e989b1d95d2` |
| SHA-256 | `95250a426cdfb70173fc9b8f25000d1dc0b5bbc30be667eda6e55853006fc1d2` |
| SHA3-384 | `913f76e6fae806b2d2bca0d9d852e629419e77967a2556e648588311a370b30b8a7cf0c03fb69b1eccb7f1ecaca22d77` |
| TLSH | `T1FBD31992F9909B45C6D06ABEFF8D538C331307B8C2EE7109D9255B2436CB48A0F7A947` |
| TELFHASH | `t120a02202ec220aae23f00308f808808f080a22380383080c33230b3f0c08bc3322c030` |
| SSDEEP | `1536:GCs1sbk7cqBKLyeOoGpqSvTmApGwN33DE0Xuv6G2G6NOq8oM9kg6+SsDUcbEwxb5:GlNYqI+eOCwRxG5HD3ZfMb+` |

#### Technical Assessment

- The sample is tracked as `Ngioweb` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Ngioweb_045_95250a42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95250a426cdfb70173fc9b8f25000d1dc0b5bbc30be667eda6e55853006fc1d2"
    family = "Ngioweb"
    file_name = "1.fp.mcm.armv7l"
    file_type = "elf"
    first_seen = "2026-11-12 05:49:53"
  condition:
    hash.sha256(0, filesize) == "95250a426cdfb70173fc9b8f25000d1dc0b5bbc30be667eda6e55853006fc1d2"
}
```

### Sample 46: `8e4d3352d433d96c`

| Field | Value |
|---|---|
| SHA-256 | `8e4d3352d433d96c4680761419940eb4bfdde3a8a85a34074221b968af20fb24` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-12 05:49:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c77589d58bcf996cb29c702114f9571` |
| SHA-1 | `a54e980d3a39f17d42e5200373cdb2df54561eb8` |
| SHA-256 | `8e4d3352d433d96c4680761419940eb4bfdde3a8a85a34074221b968af20fb24` |
| SHA3-384 | `82fbaf547a0f9cfc7b35857395eab56dc4cb3c4a3cc8ab627a703e2f4032652792092dbfdb715d954278f444d078282b` |
| TLSH | `T1F1556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP4K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_8e4d3352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e4d3352d433d96c4680761419940eb4bfdde3a8a85a34074221b968af20fb24"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 05:49:04"
  condition:
    hash.sha256(0, filesize) == "8e4d3352d433d96c4680761419940eb4bfdde3a8a85a34074221b968af20fb24"
}
```

### Sample 47: `2f29790f71f07705`

| Field | Value |
|---|---|
| SHA-256 | `2f29790f71f07705ca1bf7d6232c06318ce13a27d7fb23ee5a3f5e2f5de89192` |
| Family label | `PureLogsStealer` |
| File name | `RequestforQuotationRFQ.js` |
| File type | `js` |
| First seen | `2026-11-12 05:41:39` |
| Reporter | `ni_fi_70` |
| Tags | `js, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd27e47959701157d161a389ad793f39` |
| SHA-1 | `e985a55bd51daff0e4e64a05d09f6d3a47d49e2f` |
| SHA-256 | `2f29790f71f07705ca1bf7d6232c06318ce13a27d7fb23ee5a3f5e2f5de89192` |
| SHA3-384 | `095757e919a09aca252bba7220ce9330bbc26a37e4042396c1d7d576d6bcab36840a0542b20aba15aee2a354c733ac81` |
| TLSH | `T17385F135E4943F668A69263840BC1D1A9E90075FC216B7EDDA63FD667FFA800B5070B3` |
| SSDEEP | `24576:2R5xh7iStY21N0ur4fh19yfnrNadGEKXwPCz8YJJrQ/Ctmg+0carrZ:4niL21gKvEKXI8V4wrZ` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_047_2f29790f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f29790f71f07705ca1bf7d6232c06318ce13a27d7fb23ee5a3f5e2f5de89192"
    family = "PureLogsStealer"
    file_name = "RequestforQuotationRFQ.js"
    file_type = "js"
    first_seen = "2026-11-12 05:41:39"
  condition:
    hash.sha256(0, filesize) == "2f29790f71f07705ca1bf7d6232c06318ce13a27d7fb23ee5a3f5e2f5de89192"
}
```

### Sample 48: `24cc5b14dc4fac82`

| Field | Value |
|---|---|
| SHA-256 | `24cc5b14dc4fac822dd39de1b093c065bed5270cd6898b067d110489473ac7f1` |
| Family label | `unknown` |
| File name | `school_holidays1.js` |
| File type | `js` |
| First seen | `2026-11-12 05:41:35` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4d7f6acc34ac89d2792dd7600b3fca8` |
| SHA-1 | `df11f6fa047fde5e74b595779fae1361d87b0f8f` |
| SHA-256 | `24cc5b14dc4fac822dd39de1b093c065bed5270cd6898b067d110489473ac7f1` |
| SHA3-384 | `abb42d614dc1a2bd7cb2f9e46f7908712200eb884da66095992f5253da1ce699a737050327b5e93e391e12c15bd8e517` |
| TLSH | `T18DA33B52A3EA4248F5F32E88AAB710740F7BBD566E3D965C019C644D4FF3D448C62BA3` |
| SSDEEP | `768:gVUgmWVuVUWAconczhUXzfzT+OCBMOCcguUXMDWgWJIhdlNuN0eAT7pafqHHNXWl:zDWVuawyfnsHCQzdxT7ptmmRyGs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_24cc5b14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cc5b14dc4fac822dd39de1b093c065bed5270cd6898b067d110489473ac7f1"
    family = "unknown"
    file_name = "school_holidays1.js"
    file_type = "js"
    first_seen = "2026-11-12 05:41:35"
  condition:
    hash.sha256(0, filesize) == "24cc5b14dc4fac822dd39de1b093c065bed5270cd6898b067d110489473ac7f1"
}
```

### Sample 49: `6ecc66b23e7551ac`

| Field | Value |
|---|---|
| SHA-256 | `6ecc66b23e7551acadbfd0127ec7203c66bdef083550c363911adf3c2b02fa2d` |
| Family label | `RemcosRAT` |
| File name | `ChequesNo.000003.cmd` |
| File type | `cmd` |
| First seen | `2026-11-12 05:41:32` |
| Reporter | `ni_fi_70` |
| Tags | `cmd, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d35ed5f9fced21b43767dcfca02b499a` |
| SHA-1 | `0fd60771c8a63efca6787df95692ffc95f41ab2c` |
| SHA-256 | `6ecc66b23e7551acadbfd0127ec7203c66bdef083550c363911adf3c2b02fa2d` |
| SHA3-384 | `755c01b0f6df13131c169331f6ffe32b72c5483d3fa85536ec2c2f7861456c8ac29872902bc73b15cdb32ccd414dd757` |
| TLSH | `T17E666C85793734C4874E27CEE326DECA268C4BDEFB05B55EB9F6568C331A09E4868470` |
| SSDEEP | `49152:yuK7mVQ/tjObMRAEKdQ/+R3WwSw2nId1euXgUE8TuswLDM0wcAI6gRakgpTCc3MJ:g` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_049_6ecc66b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ecc66b23e7551acadbfd0127ec7203c66bdef083550c363911adf3c2b02fa2d"
    family = "RemcosRAT"
    file_name = "ChequesNo.000003.cmd"
    file_type = "cmd"
    first_seen = "2026-11-12 05:41:32"
  condition:
    hash.sha256(0, filesize) == "6ecc66b23e7551acadbfd0127ec7203c66bdef083550c363911adf3c2b02fa2d"
}
```

### Sample 50: `00cbf6925ed0b4d6`

| Field | Value |
|---|---|
| SHA-256 | `00cbf6925ed0b4d6c1632ab51f5cc0a82fb0299a7be131911fa8877fa8541e4f` |
| Family label | `MangzLoader` |
| File name | `Cacapt.exe` |
| File type | `exe` |
| First seen | `2026-11-12 05:41:29` |
| Reporter | `ni_fi_70` |
| Tags | `exe, MangzLoader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99548e2c8f4fc07379c2b32059e7f9f3` |
| SHA-1 | `7b861d078d1e98069d1fcca68987fab4715d6542` |
| SHA-256 | `00cbf6925ed0b4d6c1632ab51f5cc0a82fb0299a7be131911fa8877fa8541e4f` |
| SHA3-384 | `487266300006a1ae4327af064d1be56c0dc4f6262164a3bde5aa49a1b927e0c739b729f8adbc5e766b1b0a5feae08faa` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T105E6331002B3D1EDD66E0739FF7E88679AD5A66B36287090225F8DA09C8BF4443DC5DE` |
| SSDEEP | `393216:fM6EI/RK9IYUuZx556oKz4qJdCzibm1fwY5Rbm:fdZ/UIYx556oKizib2ftX` |
| ICON-DHASH | `3369697171716d2b` |

#### Technical Assessment

- The sample is tracked as `MangzLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MangzLoader_050_00cbf692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00cbf6925ed0b4d6c1632ab51f5cc0a82fb0299a7be131911fa8877fa8541e4f"
    family = "MangzLoader"
    file_name = "Cacapt.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:41:29"
  condition:
    hash.sha256(0, filesize) == "00cbf6925ed0b4d6c1632ab51f5cc0a82fb0299a7be131911fa8877fa8541e4f"
}
```

### Sample 51: `16346b77c4ad4a06`

| Field | Value |
|---|---|
| SHA-256 | `16346b77c4ad4a06553c32398694b6dc8ee835649e80eba4f8f204f43103ee04` |
| Family label | `RemcosRAT` |
| File name | `ShippingDocument.cmd` |
| File type | `cmd` |
| First seen | `2026-11-12 05:41:25` |
| Reporter | `ni_fi_70` |
| Tags | `cmd, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49e9b566ff5c862e225f3e7d90131770` |
| SHA-1 | `bb0cbfd8327c5e03c4289b0764d9d5eb39f61f2b` |
| SHA-256 | `16346b77c4ad4a06553c32398694b6dc8ee835649e80eba4f8f204f43103ee04` |
| SHA3-384 | `6bd0f1ff2e358e20d2f43848e5714b4051f03c5cc828f4a60c73b2bf66d921697b7ba9f659227f3c1c17ddd541c0ccc5` |
| TLSH | `T1C6666B857D3734C4874D27CEE3269ECA268D4BCEFB04B55EB9F6568C331B09A8868471` |
| SSDEEP | `49152:Z1jZLHrFQDBZRRDW1uiexpZOEy6n9ZyYvI9L9kjilFLEsqZNpi7rTdqRbNZYz:n` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_051_16346b77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16346b77c4ad4a06553c32398694b6dc8ee835649e80eba4f8f204f43103ee04"
    family = "RemcosRAT"
    file_name = "ShippingDocument.cmd"
    file_type = "cmd"
    first_seen = "2026-11-12 05:41:25"
  condition:
    hash.sha256(0, filesize) == "16346b77c4ad4a06553c32398694b6dc8ee835649e80eba4f8f204f43103ee04"
}
```

### Sample 52: `12288c5456826de4`

| Field | Value |
|---|---|
| SHA-256 | `12288c5456826de4e68163fa99507f58394648955e033e336586aa532a7ae3ad` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-12 05:34:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50d0399c4c86d503f3e08f0a4678bef4` |
| SHA-1 | `a4cd1b1b8c252e54c783b8160d45a8224b13d6f7` |
| SHA-256 | `12288c5456826de4e68163fa99507f58394648955e033e336586aa532a7ae3ad` |
| SHA3-384 | `42f817bbdfe360f2d2cbb2bfbc9a9a49cf4bd2aba728cd653da5b64107d600ad52c53c2e724081c29f1290753732b3da` |
| TLSH | `T122556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSP:SDjxB4m5n8XlaPWi+d+a4TjxQP4J` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_12288c54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12288c5456826de4e68163fa99507f58394648955e033e336586aa532a7ae3ad"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 05:34:04"
  condition:
    hash.sha256(0, filesize) == "12288c5456826de4e68163fa99507f58394648955e033e336586aa532a7ae3ad"
}
```

### Sample 53: `7ad21164b1638c58`

| Field | Value |
|---|---|
| SHA-256 | `7ad21164b1638c58f1fb5beca8f87b27996970fe4e87244133223703d4c79aea` |
| Family label | `njrat` |
| File name | `6EF196369EEC61A0A1C23FA1CC6A0374.exe` |
| File type | `exe` |
| First seen | `2026-11-12 05:15:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ef196369eec61a0a1c23fa1cc6a0374` |
| SHA-1 | `63a457cc976840dbbf8b326896367980000be3dc` |
| SHA-256 | `7ad21164b1638c58f1fb5beca8f87b27996970fe4e87244133223703d4c79aea` |
| SHA3-384 | `5cb21cd935452e8f125402d902c7d274987c65b366692ad93ee92970d2719f3d0bc7c09a5f2e37708fd5ef0758dcd2d3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16CA2198EB7648618C39D1AB84CE3232483F1F68B8951DF4B5CDA50DA2F236D16142BFD` |
| SSDEEP | `384:1W6ZUSl0XMz/s9ADAfJh6RmHTaOWQ+dcs//34LAZSTZ2W5OlWVzDMP:06ZUq0XOQ/xk8nWQuHqaP` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_053_7ad21164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ad21164b1638c58f1fb5beca8f87b27996970fe4e87244133223703d4c79aea"
    family = "njrat"
    file_name = "6EF196369EEC61A0A1C23FA1CC6A0374.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:15:19"
  condition:
    hash.sha256(0, filesize) == "7ad21164b1638c58f1fb5beca8f87b27996970fe4e87244133223703d4c79aea"
}
```

### Sample 54: `41b94b182fb4221e`

| Field | Value |
|---|---|
| SHA-256 | `41b94b182fb4221e3293ad488075f1623763bb56eeb2b19834730031c6081e76` |
| Family label | `njrat` |
| File name | `1c4ad2a425a738a157fc81dfc68dcf32.exe` |
| File type | `exe` |
| First seen | `2026-11-12 05:15:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c4ad2a425a738a157fc81dfc68dcf32` |
| SHA-1 | `5bc7f7052682611b52dccfb73bc628123ad4504b` |
| SHA-256 | `41b94b182fb4221e3293ad488075f1623763bb56eeb2b19834730031c6081e76` |
| SHA3-384 | `a0598322f3a38d39547fa625f7ca8c535a5301ee81b001b9f6e309f90c9c627754ea5882bd78ef678f75db154b4ef646` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CBA21A4E77A48618C3AD1A7809E3232447F1F68BCA51DF4B1CDA50DA6F236D06542BFD` |
| SSDEEP | `384:SW6OUSlvpJWXMmo9ByzHAf5hshmHE5aOWQ+dcs//34LAZSTzZH:j6OUqWX7GkzghOMk5WQuHqHH` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_054_41b94b18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41b94b182fb4221e3293ad488075f1623763bb56eeb2b19834730031c6081e76"
    family = "njrat"
    file_name = "1c4ad2a425a738a157fc81dfc68dcf32.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:15:12"
  condition:
    hash.sha256(0, filesize) == "41b94b182fb4221e3293ad488075f1623763bb56eeb2b19834730031c6081e76"
}
```

### Sample 55: `a4ec1bd1cc63c84c`

| Field | Value |
|---|---|
| SHA-256 | `a4ec1bd1cc63c84caf9cd6feafd94259ac33aaac858e87dc47a583ed8c5f8c00` |
| Family label | `njrat` |
| File name | `024D66B6E13AD1C4DA253C72EFEB6956.exe` |
| File type | `exe` |
| First seen | `2026-11-12 05:15:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `024d66b6e13ad1c4da253c72efeb6956` |
| SHA-1 | `6b172831fa3a562a1da08d074df91d179224becd` |
| SHA-256 | `a4ec1bd1cc63c84caf9cd6feafd94259ac33aaac858e87dc47a583ed8c5f8c00` |
| SHA3-384 | `b95ec38421822cace828530eabb0d496ab98dfe4043c191911a4f8dbec591ee99f5475b6470a070bf96ee21f08c874a1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16B17338272850755E9C9603C95E7867293F0BCA11B32C6DB2FA85BE92D533F2DE32750` |
| SSDEEP | `393216:q/zEeFeUg6vOFYDVPS1pUdq1B7oeXpfHsn4qS3TKa3gij:q/veU5GF4E1pUg1CalgzSDP3g` |
| ICON-DHASH | `ae3c385c4ce0e8f8` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_055_a4ec1bd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4ec1bd1cc63c84caf9cd6feafd94259ac33aaac858e87dc47a583ed8c5f8c00"
    family = "njrat"
    file_name = "024D66B6E13AD1C4DA253C72EFEB6956.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:15:07"
  condition:
    hash.sha256(0, filesize) == "a4ec1bd1cc63c84caf9cd6feafd94259ac33aaac858e87dc47a583ed8c5f8c00"
}
```

### Sample 56: `e8778e45d1dee2b6`

| Field | Value |
|---|---|
| SHA-256 | `e8778e45d1dee2b6b76a7b42a8c2593c8e776b6738ac0e2d5ee0d7f9f75d5922` |
| Family label | `unknown` |
| File name | `my_rakuten_security_v2.apk` |
| File type | `apk` |
| First seen | `2026-11-12 05:08:34` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a4e1e75310b58191adc8f5123aa8352` |
| SHA-1 | `e6364586c7dc1f99eb99715ff848e7ebb37e3bff` |
| SHA-256 | `e8778e45d1dee2b6b76a7b42a8c2593c8e776b6738ac0e2d5ee0d7f9f75d5922` |
| SHA3-384 | `c86c74819bfe91eb4bee0814fa3206f2fc99980f7ab9fb9fd91e54779f56bd7f3fb6fa2ea2482fd84e1a2ec1e45842d5` |
| TLSH | `T1BB672357FF84697AD4F2833609366721690B8C318B5396CBA804327C78F77E45F99AC8` |
| SSDEEP | `786432:QgPt2bWIZZ+C4gWV8N0IhJzO8mylkhiaQ:QgPt0Z/4+dOOu2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e8778e45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8778e45d1dee2b6b76a7b42a8c2593c8e776b6738ac0e2d5ee0d7f9f75d5922"
    family = "unknown"
    file_name = "my_rakuten_security_v2.apk"
    file_type = "apk"
    first_seen = "2026-11-12 05:08:34"
  condition:
    hash.sha256(0, filesize) == "e8778e45d1dee2b6b76a7b42a8c2593c8e776b6738ac0e2d5ee0d7f9f75d5922"
}
```

### Sample 57: `5a010583c65438bd`

| Field | Value |
|---|---|
| SHA-256 | `5a010583c65438bd217d3408b4a31be4569bdb33d5ae72f241a4b2f00841fa7a` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-12 04:45:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d203e786067833da28aba8f97a6678ed` |
| SHA-1 | `5df2acad281221d9bd5f94961576809a06a0efd9` |
| SHA-256 | `5a010583c65438bd217d3408b4a31be4569bdb33d5ae72f241a4b2f00841fa7a` |
| SHA3-384 | `634015eeda0a92e228162900f1d8967c8e8892fb8575ac95a058f635f1d6d89937c4636312a325416b82cd1c21a43f52` |
| TLSH | `T163556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSu:SDjxB4m5n8XlaPWi+d+a4TjxQP48` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_5a010583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a010583c65438bd217d3408b4a31be4569bdb33d5ae72f241a4b2f00841fa7a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 04:45:04"
  condition:
    hash.sha256(0, filesize) == "5a010583c65438bd217d3408b4a31be4569bdb33d5ae72f241a4b2f00841fa7a"
}
```

### Sample 58: `52e7dbe125b2d8db`

| Field | Value |
|---|---|
| SHA-256 | `52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142` |
| Family label | `SalatStealer` |
| File name | `emulator.exe` |
| File type | `exe` |
| First seen | `2026-11-12 03:57:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb7ffde3b9fcc7c23ebf88eed9a23967` |
| SHA-1 | `4a0540530a6674eaf7fb7e96f7a62311f9b1f078` |
| SHA-256 | `52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142` |
| SHA3-384 | `11972e80385a74e10c70d6923bd8cd84fa86cb3bde658b8c9c814cfb10f6ff7574b860b4e0d0e403d9d3ff751f58dd9c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T153C65C11FACB54F1F903583140ABB27F23315D048B28CBDBEB547B6AF87B6A1196A705` |
| SSDEEP | `98304:wo/UkrAlUr2piSTwis2Yt4l7aA4fG2IflEk:xAJxTF44luAxOk` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_52e7dbe1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142"
    family = "SalatStealer"
    file_name = "emulator.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:57:17"
  condition:
    hash.sha256(0, filesize) == "52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142"
}
```

### Sample 59: `35a3c714998539eb`

| Field | Value |
|---|---|
| SHA-256 | `35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04` |
| Family label | `SalatStealer` |
| File name | `emulator.exe` |
| File type | `exe` |
| First seen | `2026-11-12 03:56:59` |
| Reporter | `whereyoufell` |
| Tags | `exe, golang, SalatStealer, TON, UPX, webrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d2c3339e61f827a4fde503c775de9ec` |
| SHA-1 | `2742fa0a13c91283bdc9de21274c0c168a77a763` |
| SHA-256 | `35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04` |
| SHA3-384 | `586d46cb79af2686938e22a38d1bb565d13806842740a367efed20b983e920d50a83c271f0d726a8e045fa0f9003f930` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T128F5330E9A8A8212CF15267C3B5DFF90A27462108BE72EC147816BDDD6DF3176039ADD` |
| SSDEEP | `98304:JH8W7mRL/qCJQPtIYbuuJ3MTXuYdzUZ6a022CrFv3:JHFmliCJEtItuJQXukztaOOFv` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_059_35a3c714
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04"
    family = "SalatStealer"
    file_name = "emulator.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:56:59"
  condition:
    hash.sha256(0, filesize) == "35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04"
}
```

### Sample 60: `e525530f98e94ba2`

| Field | Value |
|---|---|
| SHA-256 | `e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f` |
| Family label | `RevStealer` |
| File name | `e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f.exe` |
| File type | `exe` |
| First seen | `2026-11-12 03:50:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `278aedebe1f7e114e93e4f7e3cc5850f` |
| SHA-1 | `eed89aae8ebb205519c29913e0c3cebf4069f734` |
| SHA-256 | `e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f` |
| SHA3-384 | `23d57122df36d295a32b38bba92f21616ff8c256cb470ba9fd632fbebdd63690d474f0ecff869d038c1741e47b580ef2` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T1BAD5239AB8F218B4D437C3F68E92E47EF12977554AB14E4B36CC2900DE536582C393B9` |
| SSDEEP | `49152:DYOF/T2PZba1pexBoca7nbekWZiRVvrV9lHvYrqutx0emxT0yo/987QSmj5Atvvy:3gPw1pew77bn9TjV9lArttgHolxSm1Ah` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_060_e525530f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f"
    family = "RevStealer"
    file_name = "e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:50:56"
  condition:
    hash.sha256(0, filesize) == "e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f"
}
```

### Sample 61: `e37ab282bee0d665`

| Field | Value |
|---|---|
| SHA-256 | `e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0` |
| Family label | `RevStealer` |
| File name | `e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0.exe` |
| File type | `exe` |
| First seen | `2026-11-12 03:50:50` |
| Reporter | `Tuxxin` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f37a568c1e1b3c3e33ddce01500bbf28` |
| SHA-1 | `c8a9f349284708d4474e97d46b4e701356a75cea` |
| SHA-256 | `e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0` |
| SHA3-384 | `e0c582c88eb6cc6843af1bb08813c126de250af61d27f3b87e09f4cbb659ea5dc0e912bab6be52a7f10de33b7c12c53d` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T1B1D52286FDA34075E43BC77B9793A47DB0293B618BB48D4B768C6B906E125187C32339` |
| SSDEEP | `49152:hPqjIwgYSbqSzdvRLq8E0UH9weA7VJTb1w5iv/Wwyaa5heeEf2kHsDI:0jbOqSBvRpEOeAjTx8inWga5/EXHg` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_061_e37ab282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0"
    family = "RevStealer"
    file_name = "e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:50:50"
  condition:
    hash.sha256(0, filesize) == "e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0"
}
```

### Sample 62: `09743983fceab7d3`

| Field | Value |
|---|---|
| SHA-256 | `09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb` |
| Family label | `SalatStealer` |
| File name | `09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb.bin` |
| File type | `bat` |
| First seen | `2026-11-12 03:47:00` |
| Reporter | `Tuxxin` |
| Tags | `bat, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac4c4685ad49a37ddd723e7e132cd851` |
| SHA-1 | `f0f7e45a75c5ddb76fa458846c3f7821348d4165` |
| SHA-256 | `09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb` |
| SHA3-384 | `65af7576a491d73a892856ef64cb7c31bc4ac58f2e5fe2fb7a63af5eab13c158fb1dda7b1e95a5aa86f1e13969ec8b1f` |
| TLSH | `T15DD69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzl:u` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_062_09743983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb"
    family = "SalatStealer"
    file_name = "09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb.bin"
    file_type = "bat"
    first_seen = "2026-11-12 03:47:00"
  condition:
    hash.sha256(0, filesize) == "09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb"
}
```

### Sample 63: `6e3ba2552b7dd2f7`

| Field | Value |
|---|---|
| SHA-256 | `6e3ba2552b7dd2f733becc926ce4447f781af97405d06ea0354f9e2f7ce332b9` |
| Family label | `Mirai` |
| File name | `x-8.6-.Sakura` |
| File type | `elf` |
| First seen | `2026-11-12 03:33:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `114011ef099c93f0d183d390f9dff58d` |
| SHA-1 | `590f111a1959bff50636d01ced1c47d01325abda` |
| SHA-256 | `6e3ba2552b7dd2f733becc926ce4447f781af97405d06ea0354f9e2f7ce332b9` |
| SHA3-384 | `0a531c9f83f96cb49d889f7e2fceda30fa52edcc100159fa9fea853e39659d816105fb1225cf89357d518358355c6249` |
| TLSH | `T17C935D27B552C6BBC08752B42BDFEA615833B4BC0B32720B33D47DA52B259D91E6DB01` |
| TELFHASH | `t1d211020260b689282bb259205cbc42f1165526233341be75bf0ec5c4993b002aa78e8b` |
| SSDEEP | `1536:W7uJtxNeVE8zV7a+lvhE1hmkJ0S36W6bWjK3myPXfH0mA+KWOXFseaZYxe:4SsVEeVRlpmXJ0O6WpjKWifUm/KWOXFE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_6e3ba255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e3ba2552b7dd2f733becc926ce4447f781af97405d06ea0354f9e2f7ce332b9"
    family = "Mirai"
    file_name = "x-8.6-.Sakura"
    file_type = "elf"
    first_seen = "2026-11-12 03:33:03"
  condition:
    hash.sha256(0, filesize) == "6e3ba2552b7dd2f733becc926ce4447f781af97405d06ea0354f9e2f7ce332b9"
}
```

### Sample 64: `68abe439c5e5981f`

| Field | Value |
|---|---|
| SHA-256 | `68abe439c5e5981fa8e69f33001b29a874bd3dc917aad710b22465ca26ba7388` |
| Family label | `unknown` |
| File name | `Ikov.jar` |
| File type | `jar` |
| First seen | `2026-11-12 03:11:20` |
| Reporter | `rc4` |
| Tags | `jar, osrs, runelure` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `905570254db97174d7f4c9fb35b08ef0` |
| SHA-1 | `bf301fc2180b2f4ce3769d479f4c25f3147ecf7d` |
| SHA-256 | `68abe439c5e5981fa8e69f33001b29a874bd3dc917aad710b22465ca26ba7388` |
| SHA3-384 | `6d78ff474c87d380d0149216947d0d945cb991e9be56924f132384ac46dd4a5937fc6b9f12ece09be1ce14d95cc686ed` |
| TLSH | `T161F5E16BAEDFC468DEB744B761C28256642F1569AC0B907E03F06D854B70D8B0362FF9` |
| SSDEEP | `98304:KliHK+EHamNPQtnn+IdG7vG7A2KIFIMM9W1Ec:9HjE6mNPMnnnuvGU255+WV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_68abe439
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68abe439c5e5981fa8e69f33001b29a874bd3dc917aad710b22465ca26ba7388"
    family = "unknown"
    file_name = "Ikov.jar"
    file_type = "jar"
    first_seen = "2026-11-12 03:11:20"
  condition:
    hash.sha256(0, filesize) == "68abe439c5e5981fa8e69f33001b29a874bd3dc917aad710b22465ca26ba7388"
}
```

### Sample 65: `ce1e378e01180dd5`

| Field | Value |
|---|---|
| SHA-256 | `ce1e378e01180dd52df38cd5006c4a57419475675ce21e484f9b9989ac01c279` |
| Family label | `PavinLoader` |
| File name | `safg.msi` |
| File type | `msi` |
| First seen | `2026-11-12 02:50:35` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e18d0bbb24f4087667a45e7b26053be8` |
| SHA-1 | `2c419cc83e6a561fd5e35b674b146d6dab7acd9f` |
| SHA-256 | `ce1e378e01180dd52df38cd5006c4a57419475675ce21e484f9b9989ac01c279` |
| SHA3-384 | `e087b6a814bca256e1124a0c82dd494b8ec7199f359e6a78702216a632c00151cd817749562b0bd1950a84a76ff90a3c` |
| TLSH | `T1B77633652E1246D7E42B7733890383B0D6773FB242B74A3788C5F37A177DA62A1E1690` |
| SSDEEP | `196608:NFeogSdn9BRGimuV2F64ZZF6F72i9jHorhbcwXXM7B:Nfr3mu2FFP622oDXX+B` |

#### Technical Assessment

- The sample is tracked as `PavinLoader` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PavinLoader_065_ce1e378e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1e378e01180dd52df38cd5006c4a57419475675ce21e484f9b9989ac01c279"
    family = "PavinLoader"
    file_name = "safg.msi"
    file_type = "msi"
    first_seen = "2026-11-12 02:50:35"
  condition:
    hash.sha256(0, filesize) == "ce1e378e01180dd52df38cd5006c4a57419475675ce21e484f9b9989ac01c279"
}
```

### Sample 66: `2431ad790c9decf8`

| Field | Value |
|---|---|
| SHA-256 | `2431ad790c9decf8a231b36df0fc7763c35005753111d4d89913552c0b9b987a` |
| Family label | `PavinLoader` |
| File name | `corew.msi` |
| File type | `msi` |
| First seen | `2026-11-12 02:50:04` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-ACRStealer, msi, PavinLoader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ad97a23a8656657a92a6cd4b1d92f58` |
| SHA-1 | `c4831e9cc44039675294ed8684e835a66441d630` |
| SHA-256 | `2431ad790c9decf8a231b36df0fc7763c35005753111d4d89913552c0b9b987a` |
| SHA3-384 | `888ca24ca5fbc3ad502207bf6a6891faef3da6892e66b748ba0b2455853bff04152a179d8d8d48aebc43f00d8493c085` |
| TLSH | `T1B48633B8B05B3BB6C117863A4D26E954DB45FCBD4B339F03224ABA4874781DA36FE014` |
| SSDEEP | `196608:OHt8wSpT85IpXYsbNRb5DyZggLdZLKj3iRmZjy:OHt8wSN85Mvb5DyLhk3iRmZu` |

#### Technical Assessment

- The sample is tracked as `PavinLoader` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PavinLoader_066_2431ad79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2431ad790c9decf8a231b36df0fc7763c35005753111d4d89913552c0b9b987a"
    family = "PavinLoader"
    file_name = "corew.msi"
    file_type = "msi"
    first_seen = "2026-11-12 02:50:04"
  condition:
    hash.sha256(0, filesize) == "2431ad790c9decf8a231b36df0fc7763c35005753111d4d89913552c0b9b987a"
}
```

### Sample 67: `2d4522f2f28c455f`

| Field | Value |
|---|---|
| SHA-256 | `2d4522f2f28c455fd1fffadb0dda86055e55785886aa657f7d21f2de8e4e56d7` |
| Family label | `CoinMiner` |
| File name | `amd_plugin_16_64.exe` |
| File type | `exe` |
| First seen | `2026-11-12 02:49:25` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, corvusminer, dropped-by-RemusStealer, dropped-by-WARDENStealer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d31bcb83630256636cef7240cbbfa494` |
| SHA-1 | `465a592a1397be60cbf3986f6c2bf58a0eb7449a` |
| SHA-256 | `2d4522f2f28c455fd1fffadb0dda86055e55785886aa657f7d21f2de8e4e56d7` |
| SHA3-384 | `5bf05ed9c677174a902b940efec349582cd50b5189275d92b8e9ba900d7bf9bb45c541e0dabbf805e31defad7c9977aa` |
| IMPHASH | `3eafaf3d35fc1353150ce220f3be2b21` |
| TLSH | `T1D3A6F007ECA109E6D1AEF1318526A516FB717C441F3263D72A98B2683F72BD0AD78734` |
| SSDEEP | `98304:FE5khxxK/8TugQWwWj1KFctk37HRUvmfeMj:+CEghwWJKb7HRwO1` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_067_2d4522f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d4522f2f28c455fd1fffadb0dda86055e55785886aa657f7d21f2de8e4e56d7"
    family = "CoinMiner"
    file_name = "amd_plugin_16_64.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:49:25"
  condition:
    hash.sha256(0, filesize) == "2d4522f2f28c455fd1fffadb0dda86055e55785886aa657f7d21f2de8e4e56d7"
}
```

### Sample 68: `557e379832620fe4`

| Field | Value |
|---|---|
| SHA-256 | `557e379832620fe46bb447a90d4eadcc716f34e9e20c5310401124fa2ed9ec45` |
| Family label | `ACRStealer` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-12 02:48:31` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, agent-sablewoodton-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea5d103f7573445ec55aa415bcd7ce6c` |
| SHA-1 | `6d54d979617b848cc2bf18ca54922fc7a8f84ee1` |
| SHA-256 | `557e379832620fe46bb447a90d4eadcc716f34e9e20c5310401124fa2ed9ec45` |
| SHA3-384 | `67d328977b21989a057185783b21756df2ce1cc11f9f42a21dc598397b7cff979b776a16248bd8dd887c099c0da0efce` |
| TLSH | `T19CA733026DAB8F9AC43C723EC0DA8B0B6941DB119473620FC39DD5DA1DB3B716E9584E` |
| SSDEEP | `786432:PUsHlYYO9H+lYYO03K3/4lYYOczUsgAzw0szfgtclYYOf5TDE9ex44dx6awsEy0h:BH2YO9e2YO03ug2YOEJCzgc2YORT7x3q` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_068_557e3798
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "557e379832620fe46bb447a90d4eadcc716f34e9e20c5310401124fa2ed9ec45"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-12 02:48:31"
  condition:
    hash.sha256(0, filesize) == "557e379832620fe46bb447a90d4eadcc716f34e9e20c5310401124fa2ed9ec45"
}
```

### Sample 69: `f64c6226897cce9b`

| Field | Value |
|---|---|
| SHA-256 | `f64c6226897cce9b4b6ed826cafcd9651a1966519729fcca0240739d9ad22785` |
| Family label | `Mirai` |
| File name | `splarm` |
| File type | `elf` |
| First seen | `2026-11-12 02:48:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86ad0d891c09d1f616ac942cc18d12ab` |
| SHA-1 | `e97821ef6f0c4134aacd1d049fbdb7b3053a0fb7` |
| SHA-256 | `f64c6226897cce9b4b6ed826cafcd9651a1966519729fcca0240739d9ad22785` |
| SHA3-384 | `16b0f17da733b45a1e56a2860cf434ae9eea9670046bccbb257722e769f55b8e26e3fe9f5eaac24d708943bdfc1059af` |
| TLSH | `T197C32A85BC819712C6E160B2FB1FD28D3B2743B8D3E67113DD186B29634B96B0E7B251` |
| TELFHASH | `t1c6516816fb641edc67e946b481ee503a9add31ee07342466dd6e2b8f4143dc27139037` |
| SSDEEP | `3072:2Xa05Yw8p/6vHG+caTDWZZEGAFF9xidMtiF:2FAt6vHyauZGGAtxidom` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_f64c6226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64c6226897cce9b4b6ed826cafcd9651a1966519729fcca0240739d9ad22785"
    family = "Mirai"
    file_name = "splarm"
    file_type = "elf"
    first_seen = "2026-11-12 02:48:04"
  condition:
    hash.sha256(0, filesize) == "f64c6226897cce9b4b6ed826cafcd9651a1966519729fcca0240739d9ad22785"
}
```

### Sample 70: `f34272b327e15c00`

| Field | Value |
|---|---|
| SHA-256 | `f34272b327e15c003316120f4a0eb56c75fd01ea7d5d7143b3742d59c7a727fb` |
| Family label | `ACRStealer` |
| File name | `SETUP.zip` |
| File type | `zip` |
| First seen | `2026-11-12 02:47:44` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, ml-duskbrookby-cc, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd10eb95a17c70692dd264e3cef68377` |
| SHA-1 | `658d914a779e1bda9607610c3c426989de841cc5` |
| SHA-256 | `f34272b327e15c003316120f4a0eb56c75fd01ea7d5d7143b3742d59c7a727fb` |
| SHA3-384 | `4087f23aadfa60d9c6ecf517a853e69cbd9d3b59a3caf94efd049144cccd6969507cfabcf069ec5792f97c445dbdc322` |
| TLSH | `T1A1873328FCA63655E85EE9B404F00C6D03D6DC3612BB9BC52339B44F4963E6A9F70D29` |
| SSDEEP | `786432:10YWYTvi4s4vkZOsPfALjRF+s4vfO/1j/F/9HL3octa3oRfodZPhrls4vG:1mYNnvMeD+nvKRt5EoRf2lnvG` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_070_f34272b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f34272b327e15c003316120f4a0eb56c75fd01ea7d5d7143b3742d59c7a727fb"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-12 02:47:44"
  condition:
    hash.sha256(0, filesize) == "f34272b327e15c003316120f4a0eb56c75fd01ea7d5d7143b3742d59c7a727fb"
}
```

### Sample 71: `2cd96b244b1bb3ce`

| Field | Value |
|---|---|
| SHA-256 | `2cd96b244b1bb3cea889fd1ca8b0d466cb7846db0b27772be231d97367442bab` |
| Family label | `WARDENStealer` |
| File name | `d3dx9_26.dll` |
| File type | `exe` |
| First seen | `2026-11-12 02:46:40` |
| Reporter | `iamaachum` |
| Tags | `dll, dllHijack, RemusStealer, signed, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `580b5398e7abcc88c2e6b9086c225d9e` |
| SHA-1 | `1d65a8d69eff2c02019025f9b8f080a06aff6767` |
| SHA-256 | `2cd96b244b1bb3cea889fd1ca8b0d466cb7846db0b27772be231d97367442bab` |
| SHA3-384 | `c61587572ea9b15d0ded1b43a8768784e38432dbf3d0cf04f035bb681591a6aeaf7fb314d8eca163930a224eff83ea17` |
| IMPHASH | `1c1ad2adeb06878a984583db245d2aa2` |
| TLSH | `T164269E077D9086A8E55A9B3586A79212B771B848873233CB2ED1B3701F37BD15E39F18` |
| SSDEEP | `49152:1z7rQkGCMbPoSRQExv8rnFDwwxTT2aLhmhY08JPMB3XPnZkVcdr3Jx5IRefqovHb:NTGGFsChmIJMZAWdHb` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_071_2cd96b24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cd96b244b1bb3cea889fd1ca8b0d466cb7846db0b27772be231d97367442bab"
    family = "WARDENStealer"
    file_name = "d3dx9_26.dll"
    file_type = "exe"
    first_seen = "2026-11-12 02:46:40"
  condition:
    hash.sha256(0, filesize) == "2cd96b244b1bb3cea889fd1ca8b0d466cb7846db0b27772be231d97367442bab"
}
```

### Sample 72: `1fa3bb3562e03f78`

| Field | Value |
|---|---|
| SHA-256 | `1fa3bb3562e03f78f6e2a2f9243139a5a9bcaa8622ab943f12d54722bf597a93` |
| Family label | `CNBackdoor` |
| File name | `Launcher21763x64.exe` |
| File type | `exe` |
| First seen | `2026-11-12 02:45:09` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33aee30cc9b93a6c8ef9da266b8d7392` |
| SHA-1 | `8186f85a03514ff1e8ad0219ed7365a675dd1d3c` |
| SHA-256 | `1fa3bb3562e03f78f6e2a2f9243139a5a9bcaa8622ab943f12d54722bf597a93` |
| SHA3-384 | `5a414528f2d96df8ac8692495a0d51e548a2fae6cc14cb8610c9a01092c2387d2b0fbdffdf34d9bcf748ae88c31695fd` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T1DBF633DC2564CCC9C9006AB795B10711BC87D72B0DCF6CE933A2BD4B2B2FAA72907519` |
| SSDEEP | `393216:tvI3H5k4Vege6WK94WI5Mzi4b2lmFrojUK1U5nxfQDn:twX60eHO4WI5GiPU825xQD` |
| ICON-DHASH | `cccccccccccccccc` |

#### Technical Assessment

- The sample is tracked as `CNBackdoor` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CNBackdoor_072_1fa3bb35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fa3bb3562e03f78f6e2a2f9243139a5a9bcaa8622ab943f12d54722bf597a93"
    family = "CNBackdoor"
    file_name = "Launcher21763x64.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:45:09"
  condition:
    hash.sha256(0, filesize) == "1fa3bb3562e03f78f6e2a2f9243139a5a9bcaa8622ab943f12d54722bf597a93"
}
```

### Sample 73: `8c9dca4895903e12`

| Field | Value |
|---|---|
| SHA-256 | `8c9dca4895903e1276169b3819aa9905302ab3203710863dfc061ed014764ca6` |
| Family label | `CNBackdoor` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-11-12 02:44:43` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bdab58a0f8fd654d4d0bfc3e000517b` |
| SHA-1 | `af5283061e5623c71581b4ff89830bd721912aa7` |
| SHA-256 | `8c9dca4895903e1276169b3819aa9905302ab3203710863dfc061ed014764ca6` |
| SHA3-384 | `e073ec4c2c54611d8e2fe0fde3edfd04bd46ea8e42283b6a856839308d2480483421a646ab58f3a2e5c35f0fc09033f3` |
| TLSH | `T10DF633DC2564CCC9C9006AB755B10711BC87D72B0DCF6CE933AABD4B1B2FAA72907619` |
| SSDEEP | `393216:BvI3H5k4Vege6WK94WI5Mzi4b2lmFrojUK1U5nxfQDn:BwX60eHO4WI5GiPU825xQD` |

#### Technical Assessment

- The sample is tracked as `CNBackdoor` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CNBackdoor_073_8c9dca48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c9dca4895903e1276169b3819aa9905302ab3203710863dfc061ed014764ca6"
    family = "CNBackdoor"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-12 02:44:43"
  condition:
    hash.sha256(0, filesize) == "8c9dca4895903e1276169b3819aa9905302ab3203710863dfc061ed014764ca6"
}
```

### Sample 74: `2b51009b5712d49a`

| Field | Value |
|---|---|
| SHA-256 | `2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da` |
| Family label | `Vidar` |
| File name | `Script.lua.exe` |
| File type | `exe` |
| First seen | `2026-11-12 02:44:21` |
| Reporter | `josie` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baaba416fca1ebc9eb7db6a7ff0a5820` |
| SHA-1 | `69dba5e5362f3855efed90a8ca750096df373e29` |
| SHA-256 | `2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da` |
| SHA3-384 | `05e21813e6e180819f209a6238a4178a85ef1ddfb0e6d9fc441d2155015149bf23387e644af64406dfadef52537661de` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T177165B923A85D0ACE4EDDF3D86A54167FA217DCC833667D32D12AA395E36BC05738B01` |
| SSDEEP | `24576:pLHYgBwoCotHxyOwJa5veZ8q0e23mlKuu+0wqlU2mNDe8FeeARR8ihriJ3kKqw5x:xrwon2FZ8q0e23mlKuurXF3Y1fUPa` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_074_2b51009b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da"
    family = "Vidar"
    file_name = "Script.lua.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:44:21"
  condition:
    hash.sha256(0, filesize) == "2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da"
}
```

### Sample 75: `5dc3a9c1d44c3bdf`

| Field | Value |
|---|---|
| SHA-256 | `5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf` |
| Family label | `WARDENStealer` |
| File name | `x86__setup_now.exe` |
| File type | `exe` |
| First seen | `2026-11-12 02:44:05` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, SpaxMedia, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6d66b4abaca7a4d6ddb7ec96f4df669` |
| SHA-1 | `428b459b853ff6e597569b5e6a54521aa9bc9064` |
| SHA-256 | `5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf` |
| SHA3-384 | `5712610ea5eca578bfbaac3627ded959da9468cb88798218d041b1b0cd8e30f82dabb0755c4c79b91518772e6bf5c6a5` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T13CF612077D9082A9C0AA9B3586A78252B631BC88873133D72FD1F7742F76BC15D7AB14` |
| SSDEEP | `393216:EwT6eVCbs+ijNNcZwjwkoteCrn8tASbTXEKFkH6:FNDVMkotxr8tAkf2a` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_075_5dc3a9c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:44:05"
  condition:
    hash.sha256(0, filesize) == "5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf"
}
```

### Sample 76: `e7b2b38ee0855e11`

| Field | Value |
|---|---|
| SHA-256 | `e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff` |
| Family label | `unknown` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-11-12 02:41:07` |
| Reporter | `iamaachum` |
| Tags | `exe, signed, WARDENStealer, wooocommerce-shopping` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f0950196095f26901aa079c4e0e3f92` |
| SHA-1 | `ad0cae4c7a3b23ffc5bb57db1b629a5961cdb84d` |
| SHA-256 | `e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff` |
| SHA3-384 | `86e8b8689ca17c4e975863a4026055fb4c9e52c27f897e67cbabcdfaeaa2e92548e5739e9b7b7be04737058de3b48f6c` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T185068D077C9086A9C066EB3586A782527B317C88973133C72FD1B6742F76BD12D7AB18` |
| SSDEEP | `49152:QkYuHSexOS/1S/CuzbWf3CscXtJqPancIzp/XHepgArIg3Om:bVxkGStJqucyp/XAcuP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_e7b2b38e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:41:07"
  condition:
    hash.sha256(0, filesize) == "e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff"
}
```

### Sample 77: `7a705f5b3959b9f5`

| Field | Value |
|---|---|
| SHA-256 | `7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b` |
| Family label | `RemusStealer` |
| File name | `𝗦𝗘𝗧𝗨𝗣.exe` |
| File type | `exe` |
| First seen | `2026-11-12 02:40:06` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39cfdbe9fe8e765a22a3b2f248dbed2a` |
| SHA-1 | `77e4fc4dd1829d6c6d6dcc68efd64a6c4e2e9126` |
| SHA-256 | `7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b` |
| SHA3-384 | `e205d62e69de1a8be99c501f7b09824e3e3f89f9d410599874ba6eb5139bf4788955f13e7ca1797218c0de1421acbedf` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1D7F54A132E949174D4EAEB3EC976419AB225BCC8833573D73E52FA346E367C06A74B10` |
| SSDEEP | `24576:VAr4iOI3st03hGWq9ebD3HM81rimQRtAefmMuy2Gc89VaSEVsriJ3kKqw500fW0:V2LstWQ0TMUrimZwmMuoc4az1f00f3` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_077_7a705f5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b"
    family = "RemusStealer"
    file_name = "𝗦𝗘𝗧𝗨𝗣.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:40:06"
  condition:
    hash.sha256(0, filesize) == "7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b"
}
```

### Sample 78: `70422ee91ec13ab0`

| Field | Value |
|---|---|
| SHA-256 | `70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51` |
| Family label | `Mirai` |
| File name | `70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51.elf` |
| File type | `elf` |
| First seen | `2026-11-12 02:39:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9acbbe6c3fc7af4656a06a3dcf57e65` |
| SHA-1 | `e443c385b8324910cfc363e01c0d580e0b1ac5af` |
| SHA-256 | `70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51` |
| SHA3-384 | `100e0e162aba335a90ef126eb9e81753e128ddcde3189619387c5b2fc75b464926a7f55b59c1d9ed6aff2034d1e062b8` |
| TLSH | `T124C32A89BC819612C6E160B2FB1F91CD3B2343B8D3E67153DD186B29634F96B0E77252` |
| TELFHASH | `t1d5313315fb440eac3be447a981ae913b589e34fe17601452ad7dabcf0222ed17635039` |
| SSDEEP | `3072:Cyilstyulk3MBGuejBcpvhQhevYx9l9wRueF:CH+lk3MBcj6pJIewTl9w8C` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_70422ee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51"
    family = "Mirai"
    file_name = "70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51.elf"
    file_type = "elf"
    first_seen = "2026-11-12 02:39:24"
  condition:
    hash.sha256(0, filesize) == "70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51"
}
```

### Sample 79: `849006e9d93b763b`

| Field | Value |
|---|---|
| SHA-256 | `849006e9d93b763b83b24e8d81627a56024560659131db078d2fc982279d2ddb` |
| Family label | `WARDENStealer` |
| File name | `Outline.zip` |
| File type | `zip` |
| First seen | `2026-11-12 02:37:39` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, new-label-club, SnappyClient, WARDENStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aae4bfaa9c42f00ce74214d136c13282` |
| SHA-1 | `79bb14bfa75f10212051bad86e8a1b8c9ac9b9fd` |
| SHA-256 | `849006e9d93b763b83b24e8d81627a56024560659131db078d2fc982279d2ddb` |
| SHA3-384 | `6a9f7a469c0b5f0e2fe4ab9ffde694ba359e59513112b1a10fb31074b77dc5f73dc64feb1531b268b7046bdab03e732c` |
| TLSH | `T16D1833854543EF8BE3459C77FB2F698CFCD2B16EF91941A3807432075880BA878A65BD` |
| SSDEEP | `1572864:TtWWI2+Gt1KewZfvM6ibe8suKjo730Blid9ED56/edzySuGVtOpGsnicUbA:Ttj1+G3EvMVzsMEBlMED56GhyS5t+iq` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_079_849006e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849006e9d93b763b83b24e8d81627a56024560659131db078d2fc982279d2ddb"
    family = "WARDENStealer"
    file_name = "Outline.zip"
    file_type = "zip"
    first_seen = "2026-11-12 02:37:39"
  condition:
    hash.sha256(0, filesize) == "849006e9d93b763b83b24e8d81627a56024560659131db078d2fc982279d2ddb"
}
```

### Sample 80: `2c6e721a6f0a56f8`

| Field | Value |
|---|---|
| SHA-256 | `2c6e721a6f0a56f879201237ead174aaaaa3d8aaba5a5860c1362c03c43cf085` |
| Family label | `SalatStealer` |
| File name | `543de6a5e6c9cbb1.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:27:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d4b8c902d81ac27b722a564360bc0c6` |
| SHA-1 | `b432628a92688c6914cbf595e649327117a11d40` |
| SHA-256 | `2c6e721a6f0a56f879201237ead174aaaaa3d8aaba5a5860c1362c03c43cf085` |
| SHA3-384 | `5dc9e0e40b516af16c7a7bf704e34afe1a734a769856795366452166566cf78ae50b00b96773bc68b7fbcb696c91d1c4` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T183C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_080_2c6e721a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6e721a6f0a56f879201237ead174aaaaa3d8aaba5a5860c1362c03c43cf085"
    family = "SalatStealer"
    file_name = "543de6a5e6c9cbb1.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:27:29"
  condition:
    hash.sha256(0, filesize) == "2c6e721a6f0a56f879201237ead174aaaaa3d8aaba5a5860c1362c03c43cf085"
}
```

### Sample 81: `f642c52a3a519819`

| Field | Value |
|---|---|
| SHA-256 | `f642c52a3a519819b265f82418e3a1ae3405107c44d474baa1a9d1af9e44e794` |
| Family label | `SalatStealer` |
| File name | `1815a173a2fb0ee6.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:27:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc89a5d5bab97f464a9937e3e42c8b35` |
| SHA-1 | `f2d2115309838203db0030b82b32d8abccac943e` |
| SHA-256 | `f642c52a3a519819b265f82418e3a1ae3405107c44d474baa1a9d1af9e44e794` |
| SHA3-384 | `54bc481c1c0c5050e6c7b4a5d10ad47cb85f32bd53dba0480650b65aa8c572484b6c6afc31e59c8580037235b26a4966` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1EDC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+8:yBkKr5rszpNDy+8` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_081_f642c52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f642c52a3a519819b265f82418e3a1ae3405107c44d474baa1a9d1af9e44e794"
    family = "SalatStealer"
    file_name = "1815a173a2fb0ee6.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:27:18"
  condition:
    hash.sha256(0, filesize) == "f642c52a3a519819b265f82418e3a1ae3405107c44d474baa1a9d1af9e44e794"
}
```

### Sample 82: `60811b58fd9cee55`

| Field | Value |
|---|---|
| SHA-256 | `60811b58fd9cee5551ce9458b53bef8c3f2ff88a74b6ee7bf8c6ba8211cef296` |
| Family label | `SalatStealer` |
| File name | `3f8fdf75598d3864.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5689917b21b108a134e4f658b1466d40` |
| SHA-1 | `b1e65e19e1f17f456783361b0ec97b2f00b443e7` |
| SHA-256 | `60811b58fd9cee5551ce9458b53bef8c3f2ff88a74b6ee7bf8c6ba8211cef296` |
| SHA3-384 | `77288f113d233e5e73d721fb16d42fb8ed5ad0f82781e8bbb1f49d28f6060befe89556b8ffa2bb53f6f9906b58bf89e4` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T194C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_082_60811b58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60811b58fd9cee5551ce9458b53bef8c3f2ff88a74b6ee7bf8c6ba8211cef296"
    family = "SalatStealer"
    file_name = "3f8fdf75598d3864.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:34"
  condition:
    hash.sha256(0, filesize) == "60811b58fd9cee5551ce9458b53bef8c3f2ff88a74b6ee7bf8c6ba8211cef296"
}
```

### Sample 83: `016d68dee6dce26d`

| Field | Value |
|---|---|
| SHA-256 | `016d68dee6dce26dc21d6767099f2164b909dfe6bdf3c2e01096b27295f2bdf3` |
| Family label | `SalatStealer` |
| File name | `681caa54169e5890.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a0df9f5ac35ea0919bf4cb44da9f783` |
| SHA-1 | `a3f2788162c3914178a37f610da2c1dce853b53c` |
| SHA-256 | `016d68dee6dce26dc21d6767099f2164b909dfe6bdf3c2e01096b27295f2bdf3` |
| SHA3-384 | `60ce78937abbc6a0b0cc1e176c94bdb5b2a83521c2979601a5098f888caea78a2266ec22b3c560e08cf624a5ae46241f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B2C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+1:yBkKr5rszpNDy+1` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_083_016d68de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "016d68dee6dce26dc21d6767099f2164b909dfe6bdf3c2e01096b27295f2bdf3"
    family = "SalatStealer"
    file_name = "681caa54169e5890.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:29"
  condition:
    hash.sha256(0, filesize) == "016d68dee6dce26dc21d6767099f2164b909dfe6bdf3c2e01096b27295f2bdf3"
}
```

### Sample 84: `543de6a5e6c9cbb1`

| Field | Value |
|---|---|
| SHA-256 | `543de6a5e6c9cbb1f35ee8c0c42e43e442fb9a1dd1cbd570bf091725dda82b53` |
| Family label | `SalatStealer` |
| File name | `543de6a5e6c9cbb1.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:26` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `949e82038e18e4699c9295bd8b37519d` |
| SHA-1 | `50f8000ca9560a42ca1f4ba4689ca6e417353ede` |
| SHA-256 | `543de6a5e6c9cbb1f35ee8c0c42e43e442fb9a1dd1cbd570bf091725dda82b53` |
| SHA3-384 | `e25b87831e199a6f8af27eb0d571460487e5522d874fd06d870a780c926911b319db73d2f6835b9f511f7e188e8c05e3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12DF5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OH:iJiafuIO7rhWEES44` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_084_543de6a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "543de6a5e6c9cbb1f35ee8c0c42e43e442fb9a1dd1cbd570bf091725dda82b53"
    family = "SalatStealer"
    file_name = "543de6a5e6c9cbb1.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:26"
  condition:
    hash.sha256(0, filesize) == "543de6a5e6c9cbb1f35ee8c0c42e43e442fb9a1dd1cbd570bf091725dda82b53"
}
```

### Sample 85: `e33c261c22aff86a`

| Field | Value |
|---|---|
| SHA-256 | `e33c261c22aff86aa8c951ba8ed6e7a99d22ac7182cdff648ec7f4fffde24bcb` |
| Family label | `SalatStealer` |
| File name | `61fb46f1f1564b24.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4abaae79fdbeb79f1aa774e74a46626` |
| SHA-1 | `607e000dfea74d266d9e1c6ade9a940f0a26d98e` |
| SHA-256 | `e33c261c22aff86aa8c951ba8ed6e7a99d22ac7182cdff648ec7f4fffde24bcb` |
| SHA3-384 | `0603ae75d3eaf441fce87c87c9317a570f666cb2f515a459a27c649dba134085835389b10d0d7107b583a4265468fcf7` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CCC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+F:yBkKr5rszpNDy+F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_e33c261c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e33c261c22aff86aa8c951ba8ed6e7a99d22ac7182cdff648ec7f4fffde24bcb"
    family = "SalatStealer"
    file_name = "61fb46f1f1564b24.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:23"
  condition:
    hash.sha256(0, filesize) == "e33c261c22aff86aa8c951ba8ed6e7a99d22ac7182cdff648ec7f4fffde24bcb"
}
```

### Sample 86: `fb4feaccec084a6d`

| Field | Value |
|---|---|
| SHA-256 | `fb4feaccec084a6dd6e4e4dd675a7cf4a3113937be408e03291274f1aae7f218` |
| Family label | `SalatStealer` |
| File name | `b16121d30f49cc27.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf13e1510fdf35ca829817bd3742cebe` |
| SHA-1 | `f75c23b791ea8a4815db72410955cf8247088484` |
| SHA-256 | `fb4feaccec084a6dd6e4e4dd675a7cf4a3113937be408e03291274f1aae7f218` |
| SHA3-384 | `6dd29e9bd33a28a937c795eba8bbd5d3909ce3d051e3c63c72be2b580f32426144e2914972ee49e9afd27d0f793a2320` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1ACC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_fb4feacc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb4feaccec084a6dd6e4e4dd675a7cf4a3113937be408e03291274f1aae7f218"
    family = "SalatStealer"
    file_name = "b16121d30f49cc27.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:18"
  condition:
    hash.sha256(0, filesize) == "fb4feaccec084a6dd6e4e4dd675a7cf4a3113937be408e03291274f1aae7f218"
}
```

### Sample 87: `1815a173a2fb0ee6`

| Field | Value |
|---|---|
| SHA-256 | `1815a173a2fb0ee6298186d98a88e272b6c6d5c586b0a21654c3d1ca7f7b2800` |
| Family label | `SalatStealer` |
| File name | `1815a173a2fb0ee6.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2f8f3cc5eb5e0e7eaf277a6fde61bcd` |
| SHA-1 | `97c66474dd57b449f882c44bd14e853e71e6c283` |
| SHA-256 | `1815a173a2fb0ee6298186d98a88e272b6c6d5c586b0a21654c3d1ca7f7b2800` |
| SHA3-384 | `949f119fda4e75f9ea64ebe4de3f3810b0ee145ce24a596f4fea2776a46104a60a5524a34da1b4bd1be65c7475cdd181` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B6F5335BF1AB47B3F7D9A831561FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ow:iJiafuIO7rhWEES4/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_1815a173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1815a173a2fb0ee6298186d98a88e272b6c6d5c586b0a21654c3d1ca7f7b2800"
    family = "SalatStealer"
    file_name = "1815a173a2fb0ee6.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:13"
  condition:
    hash.sha256(0, filesize) == "1815a173a2fb0ee6298186d98a88e272b6c6d5c586b0a21654c3d1ca7f7b2800"
}
```

### Sample 88: `3f8fdf75598d3864`

| Field | Value |
|---|---|
| SHA-256 | `3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b` |
| Family label | `SalatStealer` |
| File name | `3f8fdf75598d3864.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:26:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fdfa70e236b6a04977c4a78848b8eae` |
| SHA-1 | `15549e926e144d153e00e1c8de584b5675013169` |
| SHA-256 | `3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b` |
| SHA3-384 | `7151a951c864395b2c15b05830aa764abcdd936e0d25d84d504d27c298632b4da6520eb04c1e087f2029608e72b09267` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D7F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oz:iJiafuIO7rhWEES4W` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_088_3f8fdf75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b"
    family = "SalatStealer"
    file_name = "3f8fdf75598d3864.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:01"
  condition:
    hash.sha256(0, filesize) == "3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b"
}
```

### Sample 89: `681caa54169e5890`

| Field | Value |
|---|---|
| SHA-256 | `681caa54169e5890849e1edb1092c5a9776a9c91af88d23fe73aab1eb873d5d2` |
| Family label | `SalatStealer` |
| File name | `681caa54169e5890.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:25:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfc4f2b154248f24347f61cd4083ca7a` |
| SHA-1 | `c65e9b4e8010736a3afc3382f01286199399a2b3` |
| SHA-256 | `681caa54169e5890849e1edb1092c5a9776a9c91af88d23fe73aab1eb873d5d2` |
| SHA3-384 | `20f911b1e34096e27abd6a902edc82eb82d95e3700015287fadadcde9c9ee61e70bf4d9c544ba1881d5667b562180483` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FBF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF1882BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OZ:iJiafuIO7rhWEES4c` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_089_681caa54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "681caa54169e5890849e1edb1092c5a9776a9c91af88d23fe73aab1eb873d5d2"
    family = "SalatStealer"
    file_name = "681caa54169e5890.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:25:49"
  condition:
    hash.sha256(0, filesize) == "681caa54169e5890849e1edb1092c5a9776a9c91af88d23fe73aab1eb873d5d2"
}
```

### Sample 90: `61fb46f1f1564b24`

| Field | Value |
|---|---|
| SHA-256 | `61fb46f1f1564b2468d78f668c8047a2b998cfe46e6d84a1fb43a49165022636` |
| Family label | `SalatStealer` |
| File name | `61fb46f1f1564b24.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:25:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `764a6d0a9a6ad061351b039e2b8be693` |
| SHA-1 | `adff1a59da54ea7f60fc81d422066a834b3dc490` |
| SHA-256 | `61fb46f1f1564b2468d78f668c8047a2b998cfe46e6d84a1fb43a49165022636` |
| SHA3-384 | `c7daf7bfbdb762bef067a7baa1e4945ba51c15a328283f4b89cdf10b3e665c1e396d2551c1112904e0a30db210e85780` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T182F5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Op:iJiafuIO7rhWEES4o` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_090_61fb46f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61fb46f1f1564b2468d78f668c8047a2b998cfe46e6d84a1fb43a49165022636"
    family = "SalatStealer"
    file_name = "61fb46f1f1564b24.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:25:36"
  condition:
    hash.sha256(0, filesize) == "61fb46f1f1564b2468d78f668c8047a2b998cfe46e6d84a1fb43a49165022636"
}
```

### Sample 91: `b16121d30f49cc27`

| Field | Value |
|---|---|
| SHA-256 | `b16121d30f49cc2788509173e0f54a47c524deba60418b3b393fc74b3211cb54` |
| Family label | `SalatStealer` |
| File name | `b16121d30f49cc27.bin` |
| File type | `exe` |
| First seen | `2026-11-12 02:25:24` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6aa87f356c381527797d8aafb1b32b2d` |
| SHA-1 | `1fe1d6c9bb37a530cc1675d5f76d5fe3b4cec7e0` |
| SHA-256 | `b16121d30f49cc2788509173e0f54a47c524deba60418b3b393fc74b3211cb54` |
| SHA3-384 | `f6bfd68ada281a72b03ece8819d2ea183ccc76a44dfbb32b954d2c6710819dcb8ee68a3975dffbb5d954a88aa7bc7bfc` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14EF5335BF1AF47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Of:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_091_b16121d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b16121d30f49cc2788509173e0f54a47c524deba60418b3b393fc74b3211cb54"
    family = "SalatStealer"
    file_name = "b16121d30f49cc27.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:25:24"
  condition:
    hash.sha256(0, filesize) == "b16121d30f49cc2788509173e0f54a47c524deba60418b3b393fc74b3211cb54"
}
```

### Sample 92: `28c353af015bd000`

| Field | Value |
|---|---|
| SHA-256 | `28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923` |
| Family label | `AgentTesla` |
| File name | `28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923.bin` |
| File type | `ps1` |
| First seen | `2026-11-12 02:18:20` |
| Reporter | `Tuxxin` |
| Tags | `AgentTesla, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37786e98f388acae7b89cab2ae440ecb` |
| SHA-1 | `861c830d6440a878ccc82676a271f190c38dc4bb` |
| SHA-256 | `28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923` |
| SHA3-384 | `3770dd19de94936d4627ece22b8c12d5c0206e7376977d183e888ef7a737b957a496393898901bb974db762632b3d800` |
| TLSH | `T10035233CA95D03DB0830D1F735A37881B9981387098B2647539EC6A477EB1A4E937DBB` |
| SSDEEP | `24576:Chm8ajBM4Rg18hOfL76tSO8HqM2QLfXZXZMnfDR8+6Pnw1Ua:CYj1Megs4/q1ufrMf2+` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_092_28c353af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923"
    family = "AgentTesla"
    file_name = "28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923.bin"
    file_type = "ps1"
    first_seen = "2026-11-12 02:18:20"
  condition:
    hash.sha256(0, filesize) == "28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923"
}
```

### Sample 93: `85759826f998c687`

| Field | Value |
|---|---|
| SHA-256 | `85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1` |
| Family label | `unknown` |
| File name | `85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1.bin` |
| File type | `sh` |
| First seen | `2026-11-12 02:17:15` |
| Reporter | `Tuxxin` |
| Tags | `script, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf8a0a1c6cafe594fd00ef749b2c752c` |
| SHA-1 | `84bc96d3be64daccc2ef4a6a270e7cf2ec448f71` |
| SHA-256 | `85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1` |
| SHA3-384 | `a1704d8399c92d8a5e0cdcf7fe8c10ef28827f384c5ffa8a4a1c1448649472c65a27a93d5500166b998d43997f6da426` |
| TLSH | `T113851A55A854EEB11126847C5DC60F593A83871F2A6C2828B0DCB60C7F9CC9961F7BFE` |
| SSDEEP | `24576:utweGPzlo36RkriTd0uz8KcEs8BV5we8Dx9+0CI7BAvr:u1klMXDg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_85759826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1"
    family = "unknown"
    file_name = "85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1.bin"
    file_type = "sh"
    first_seen = "2026-11-12 02:17:15"
  condition:
    hash.sha256(0, filesize) == "85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1"
}
```

### Sample 94: `5e99c8dc8b2280db`

| Field | Value |
|---|---|
| SHA-256 | `5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2` |
| Family label | `WannaCry` |
| File name | `5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2` |
| File type | `exe` |
| First seen | `2026-11-12 02:15:14` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `260949cbe266a0876be146d29891810e` |
| SHA-1 | `b28516bdff2682aa3c131828cbe892b81d09650a` |
| SHA-256 | `5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2` |
| SHA3-384 | `dc458a7b57513a5de013c918f35e1ed1ac06617a63a32ae68395ca3550bf93f5181e80f8eca77ef5abeaaa98c4128da1` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T16B365A01D5E81A60DAF26BF626EB8701973A7F41995BA56E1221910F0C77F0CCDE6F2C` |
| SSDEEP | `49152:jnYnjQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAA:DI8qPoBhz1aRxcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_094_5e99c8dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2"
    family = "WannaCry"
    file_name = "5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2"
    file_type = "exe"
    first_seen = "2026-11-12 02:15:14"
  condition:
    hash.sha256(0, filesize) == "5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2"
}
```

### Sample 95: `849c393107fa863e`

| Field | Value |
|---|---|
| SHA-256 | `849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421` |
| Family label | `unknown` |
| File name | `849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421` |
| File type | `elf` |
| First seen | `2026-11-12 02:03:55` |
| Reporter | `beserko` |
| Tags | `diicot, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70d26853555098f3d3b69d128ce641ef` |
| SHA-1 | `667abdc827276dbca3d4c0fa4d8833fe39cdb018` |
| SHA-256 | `849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421` |
| SHA3-384 | `538f0cfe8efb4ab0f8e566e0244a5d0487ede7e1f75c2e9621dd66524920799b6ae6651b140fc5b3a41e8e04ecaa813f` |
| TLSH | `T16E873313F79761BDD0BEC1B54946D22273B2749256323B3749D2D6AA1CB3A848F12EF0` |
| SSDEEP | `786432:0HpVq/0V7kuE3VH15rngyckjhT1g+6IR5H8FaJ5S:0HK/0V7OVVlRT1g+64V8aJ5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_849c3931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421"
    family = "unknown"
    file_name = "849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421"
    file_type = "elf"
    first_seen = "2026-11-12 02:03:55"
  condition:
    hash.sha256(0, filesize) == "849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421"
}
```

### Sample 96: `cb275fd75a405c18`

| Field | Value |
|---|---|
| SHA-256 | `cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3` |
| Family label | `unknown` |
| File name | `cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3` |
| File type | `elf` |
| First seen | `2026-11-12 02:03:37` |
| Reporter | `beserko` |
| Tags | `diicot, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7429ace5864e9cc669bbaf2a14978b5f` |
| SHA-1 | `2943872ee2c1ff5ab6b20c251799dc027f1aae2b` |
| SHA-256 | `cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3` |
| SHA3-384 | `8f68ba6987190da8331c8a97757eab5c8004174ec1a6a8aeb7963ca3105665836ceed9966de906c6ea41f6acc4d31cb0` |
| TLSH | `T18BF31261AFF3399FCAA460F859055079EB693E30B05A2CB79765781444B00FDCBE0ED9` |
| SSDEEP | `3072:4Epvsz7QWjX0SlzHcvU4LCO8TWeJNj2ljpYU+5asMl7JLIQEHJ:4Ep6sW/lzHUU4LCJvNjO+csQJc5p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_cb275fd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3"
    family = "unknown"
    file_name = "cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3"
    file_type = "elf"
    first_seen = "2026-11-12 02:03:37"
  condition:
    hash.sha256(0, filesize) == "cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3"
}
```

### Sample 97: `fa688365d3599eee`

| Field | Value |
|---|---|
| SHA-256 | `fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2` |
| Family label | `unknown` |
| File name | `fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2.exe` |
| File type | `exe` |
| First seen | `2026-11-12 01:46:00` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6919dbe52d4051569a6197a7198ebe2d` |
| SHA-1 | `c3d5c082779a6b08462adb45db1868a4141d6467` |
| SHA-256 | `fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2` |
| SHA3-384 | `b3323929dc8962258a783dc6051527ddaae27e0311e53dc553342b8baa6fb10a47d6dd96b9bc566a09067909d7ac69f2` |
| TLSH | `T12036BF916678EF01E03A177E58584680C3F98782DEDACB2A6FC06D931EF1B845B1E15F` |
| SSDEEP | `98304:9y/7bSp/0YP9uBhsKDIasjDdNdfWmFqI8+rLExFAhfTXtU6wt:9I7bSpcYPmyfasjDdNdfWyLLEkhfTX9` |
| ICON-DHASH | `70f0bcdc6c3c98e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_fa688365
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2"
    family = "unknown"
    file_name = "fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2.exe"
    file_type = "exe"
    first_seen = "2026-11-12 01:46:00"
  condition:
    hash.sha256(0, filesize) == "fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2"
}
```

### Sample 98: `5a1ed238a7fe2056`

| Field | Value |
|---|---|
| SHA-256 | `5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-11-12 01:45:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b57971d2233f2e3d545ce67f9400996f` |
| SHA-1 | `897b514c1bf7cf7eaa60da0d8521534edf252de4` |
| SHA-256 | `5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc` |
| SHA3-384 | `dae1732dee2b24538b374de8672ab2d785dde4f325a76b0fa8bb75e7b4c64d2cdaaf75cbdd947e67db343caf4b718fd7` |
| TLSH | `T146B35CA1F800CD3EF46BE7B7805312067621A7B545636B373667BC63DABE0751C62E82` |
| SSDEEP | `1536:4QrMbhpBfkWT4c5wYsEqdVnGf4tRqq8/YCUKCX3WDaNsJwwtOld9RqbNOc:4iMbhvfkU75wrzdQfgRqMlW+NwejqhOc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_5a1ed238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-12 01:45:05"
  condition:
    hash.sha256(0, filesize) == "5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc"
}
```

### Sample 99: `96a7e7b91f411a42`

| Field | Value |
|---|---|
| SHA-256 | `96a7e7b91f411a42fe3d9cec4c41ab7b9f9feb4d6684a8d02fe5dfa8ace7b841` |
| Family label | `SalatStealer` |
| File name | `f6be70d636ee97a7.bin` |
| File type | `exe` |
| First seen | `2026-11-12 01:27:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d394e3e0ee68bcfcc419a15700b41361` |
| SHA-1 | `0ca8ce37f4d4f9148494384669d80fef92d0373f` |
| SHA-256 | `96a7e7b91f411a42fe3d9cec4c41ab7b9f9feb4d6684a8d02fe5dfa8ace7b841` |
| SHA3-384 | `b078a3e18e47af6a3346258b4b0dc27bcd03f6cf3e0eded3fd37f00ab443ff50165473a5ced5c815939eab53c4608b6d` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C8C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+R:yBkKr5rszpNDy+R` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_099_96a7e7b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96a7e7b91f411a42fe3d9cec4c41ab7b9f9feb4d6684a8d02fe5dfa8ace7b841"
    family = "SalatStealer"
    file_name = "f6be70d636ee97a7.bin"
    file_type = "exe"
    first_seen = "2026-11-12 01:27:24"
  condition:
    hash.sha256(0, filesize) == "96a7e7b91f411a42fe3d9cec4c41ab7b9f9feb4d6684a8d02fe5dfa8ace7b841"
}
```

### Sample 100: `3e4e0fdc218ad6df`

| Field | Value |
|---|---|
| SHA-256 | `3e4e0fdc218ad6dfa3ac0b0db1c4185a2eb2aceedf5ebb42d112cb9d7982b155` |
| Family label | `SalatStealer` |
| File name | `c5b47b753e5163d3.bin` |
| File type | `exe` |
| First seen | `2026-11-12 01:27:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b9c8b00e3ccfb63db8f44e21ef484ce` |
| SHA-1 | `6d87b0fe0e7a10148f1257c9b7b50138d7691ba1` |
| SHA-256 | `3e4e0fdc218ad6dfa3ac0b0db1c4185a2eb2aceedf5ebb42d112cb9d7982b155` |
| SHA3-384 | `43cfabb7a0991bfb316eec1a04bff242a1da2cedbb5af6a9aab67611dcadf36e45d3f84c245425c15acc6c8a29013167` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+c:yBkKr5rszpNDy+c` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_100_3e4e0fdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e4e0fdc218ad6dfa3ac0b0db1c4185a2eb2aceedf5ebb42d112cb9d7982b155"
    family = "SalatStealer"
    file_name = "c5b47b753e5163d3.bin"
    file_type = "exe"
    first_seen = "2026-11-12 01:27:18"
  condition:
    hash.sha256(0, filesize) == "3e4e0fdc218ad6dfa3ac0b0db1c4185a2eb2aceedf5ebb42d112cb9d7982b155"
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
 * Generated: 2026-11-12T07:23:22.652964+00:00
 */

rule MalwareBazaar_Mirai_001_da5787dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da5787dd139ca9d7cd083bd60adb43c001fd64818d8418aa04a478edf7116b70"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 07:22:04"
  condition:
    hash.sha256(0, filesize) == "da5787dd139ca9d7cd083bd60adb43c001fd64818d8418aa04a478edf7116b70"
}

rule MalwareBazaar_unknown_002_b16156dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b16156dc9b6224aadd796bb10795eafb8969ead1376eb838507d61044673c95c"
    family = "unknown"
    file_name = "wgets.sh"
    file_type = "sh"
    first_seen = "2026-11-12 06:56:18"
  condition:
    hash.sha256(0, filesize) == "b16156dc9b6224aadd796bb10795eafb8969ead1376eb838507d61044673c95c"
}

rule MalwareBazaar_Mirai_003_7729a612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7729a612275980d83dac5859b37655c98839415b9f1e0c811e8526b66bc56dd4"
    family = "Mirai"
    file_name = "zerspc"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:13"
  condition:
    hash.sha256(0, filesize) == "7729a612275980d83dac5859b37655c98839415b9f1e0c811e8526b66bc56dd4"
}

rule MalwareBazaar_Mirai_004_6591a591
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6591a591547bec94ec471c69d0f5ba3074f4db3f0cfd947b513571b4a9a1ea6e"
    family = "Mirai"
    file_name = "zerarm6"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:11"
  condition:
    hash.sha256(0, filesize) == "6591a591547bec94ec471c69d0f5ba3074f4db3f0cfd947b513571b4a9a1ea6e"
}

rule MalwareBazaar_Mirai_005_aea4f8d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aea4f8d1cb4926c27f610668b877b21220732472062288fe66041a067145321f"
    family = "Mirai"
    file_name = "zermips"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:08"
  condition:
    hash.sha256(0, filesize) == "aea4f8d1cb4926c27f610668b877b21220732472062288fe66041a067145321f"
}

rule MalwareBazaar_Mirai_006_8146df28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8146df28ee6a7a7f1e04f2abe7df31c8ce80df30994e81f91a7dc065c2feeb86"
    family = "Mirai"
    file_name = "zerppc"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:05"
  condition:
    hash.sha256(0, filesize) == "8146df28ee6a7a7f1e04f2abe7df31c8ce80df30994e81f91a7dc065c2feeb86"
}

rule MalwareBazaar_Mirai_007_29a402a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29a402a1b2c43e37f4d74aeb30bfd76ce6e6fc90d9f1b461fc9c429f2800abc1"
    family = "Mirai"
    file_name = "zerarm"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:03"
  condition:
    hash.sha256(0, filesize) == "29a402a1b2c43e37f4d74aeb30bfd76ce6e6fc90d9f1b461fc9c429f2800abc1"
}

rule MalwareBazaar_Mirai_008_6ce7d9ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ce7d9ed6c1d043b8bf4111d1709945fbbc8480e4a2bb03782e1711b3e8fa79d"
    family = "Mirai"
    file_name = "zermpsl"
    file_type = "elf"
    first_seen = "2026-11-12 06:56:00"
  condition:
    hash.sha256(0, filesize) == "6ce7d9ed6c1d043b8bf4111d1709945fbbc8480e4a2bb03782e1711b3e8fa79d"
}

rule MalwareBazaar_Mirai_009_b8acaded
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8acadedf72e096d541fe8342e4fd04b3f5dd8b61de028e6cabd7a1e0cc4869c"
    family = "Mirai"
    file_name = "zerx86"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:58"
  condition:
    hash.sha256(0, filesize) == "b8acadedf72e096d541fe8342e4fd04b3f5dd8b61de028e6cabd7a1e0cc4869c"
}

rule MalwareBazaar_Mirai_010_b231a34f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b231a34f15abdb026607014be4ecf4f294908baae0c9d94150a4f5092324183d"
    family = "Mirai"
    file_name = "zerm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:55"
  condition:
    hash.sha256(0, filesize) == "b231a34f15abdb026607014be4ecf4f294908baae0c9d94150a4f5092324183d"
}

rule MalwareBazaar_Mirai_011_3898ef1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3898ef1f4cc7c458415da39282af5af3d4fa6b5facbdbdeb9811ad6d0912b889"
    family = "Mirai"
    file_name = "zerarm5"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:53"
  condition:
    hash.sha256(0, filesize) == "3898ef1f4cc7c458415da39282af5af3d4fa6b5facbdbdeb9811ad6d0912b889"
}

rule MalwareBazaar_Mirai_012_55b23b56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55b23b5674c384629c1c2c3fea66dba85be7cde06e3994df078f6d8b190a6a92"
    family = "Mirai"
    file_name = "zerarm7"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:50"
  condition:
    hash.sha256(0, filesize) == "55b23b5674c384629c1c2c3fea66dba85be7cde06e3994df078f6d8b190a6a92"
}

rule MalwareBazaar_Mirai_013_67c730f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67c730f4ec5d4ec33157099b195fdae513be778e904c27eb078a9961b9040f77"
    family = "Mirai"
    file_name = "splsh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:47"
  condition:
    hash.sha256(0, filesize) == "67c730f4ec5d4ec33157099b195fdae513be778e904c27eb078a9961b9040f77"
}

rule MalwareBazaar_Mirai_014_6306df90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6306df9018f456666fda2a5708de9b81612c181b139904a27315bb4c4789180a"
    family = "Mirai"
    file_name = "nabarm5"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:45"
  condition:
    hash.sha256(0, filesize) == "6306df9018f456666fda2a5708de9b81612c181b139904a27315bb4c4789180a"
}

rule MalwareBazaar_Mirai_015_e5651701
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e565170123198f39a434c2230d8819bcb0afdd7d70b240c0fc710c1f7556153b"
    family = "Mirai"
    file_name = "zersh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:42"
  condition:
    hash.sha256(0, filesize) == "e565170123198f39a434c2230d8819bcb0afdd7d70b240c0fc710c1f7556153b"
}

rule MalwareBazaar_Mirai_016_32bcfddb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32bcfddbe56d9eaeb9860d1fb2ef6adf3d677e5c9c82deeb7bbe1f21bba3fcc5"
    family = "Mirai"
    file_name = "nabarm6"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:14"
  condition:
    hash.sha256(0, filesize) == "32bcfddbe56d9eaeb9860d1fb2ef6adf3d677e5c9c82deeb7bbe1f21bba3fcc5"
}

rule MalwareBazaar_Mirai_017_ac785d03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac785d0339cd9a16fa4853acba05fbe07eede138193ae4469f3438d02c3c124d"
    family = "Mirai"
    file_name = "nabarm"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:11"
  condition:
    hash.sha256(0, filesize) == "ac785d0339cd9a16fa4853acba05fbe07eede138193ae4469f3438d02c3c124d"
}

rule MalwareBazaar_Mirai_018_c6af8e32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6af8e322214bd1ce012287bf2619f7051ea49097b02990d0635caff821eb336"
    family = "Mirai"
    file_name = "nklarm5"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:08"
  condition:
    hash.sha256(0, filesize) == "c6af8e322214bd1ce012287bf2619f7051ea49097b02990d0635caff821eb336"
}

rule MalwareBazaar_Mirai_019_6663c5de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6663c5decbc46fb125367f87a6e275436e96a660162d26f385a55724ee9ffc21"
    family = "Mirai"
    file_name = "nklx86"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:06"
  condition:
    hash.sha256(0, filesize) == "6663c5decbc46fb125367f87a6e275436e96a660162d26f385a55724ee9ffc21"
}

rule MalwareBazaar_Mirai_020_ff877de8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff877de8d2a4447e24f193b8c0e91de75b1465bc8c2b2420308121f1ecc50b1f"
    family = "Mirai"
    file_name = "nklarm6"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:04"
  condition:
    hash.sha256(0, filesize) == "ff877de8d2a4447e24f193b8c0e91de75b1465bc8c2b2420308121f1ecc50b1f"
}

rule MalwareBazaar_Mirai_021_37897cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37897cffb9392d041629e0398514472ae4227636b2467e741f7dfc80dc6e6296"
    family = "Mirai"
    file_name = "nabmpsl"
    file_type = "elf"
    first_seen = "2026-11-12 06:55:01"
  condition:
    hash.sha256(0, filesize) == "37897cffb9392d041629e0398514472ae4227636b2467e741f7dfc80dc6e6296"
}

rule MalwareBazaar_Mirai_022_13a04c95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a04c95e6dae607662b569c83091e436246a583a81cd8789329b95219c025f0"
    family = "Mirai"
    file_name = "nklmips"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:58"
  condition:
    hash.sha256(0, filesize) == "13a04c95e6dae607662b569c83091e436246a583a81cd8789329b95219c025f0"
}

rule MalwareBazaar_Mirai_023_7e32a622
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e32a6229d7083626b2b9ec305f1683685b0b90d03ad3095342de5f124b807c6"
    family = "Mirai"
    file_name = "nabm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:56"
  condition:
    hash.sha256(0, filesize) == "7e32a6229d7083626b2b9ec305f1683685b0b90d03ad3095342de5f124b807c6"
}

rule MalwareBazaar_Mirai_024_dec231a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dec231a2a59ee7754f7f9b61a0750495ba59d1cdade5e38119d05894b27d6730"
    family = "Mirai"
    file_name = "splm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:53"
  condition:
    hash.sha256(0, filesize) == "dec231a2a59ee7754f7f9b61a0750495ba59d1cdade5e38119d05894b27d6730"
}

rule MalwareBazaar_Mirai_025_30e14201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e14201a37f08530fd51e2d32f2926b0b8e6bf4a1f9901fc80363d4da4e3360"
    family = "Mirai"
    file_name = "nabarm7"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:51"
  condition:
    hash.sha256(0, filesize) == "30e14201a37f08530fd51e2d32f2926b0b8e6bf4a1f9901fc80363d4da4e3360"
}

rule MalwareBazaar_Mirai_026_f017ea97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f017ea979daf2a3345c466f55b29be5c980e6fc7c73be2107e19b85bbf4d72d8"
    family = "Mirai"
    file_name = "nklm68k"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:49"
  condition:
    hash.sha256(0, filesize) == "f017ea979daf2a3345c466f55b29be5c980e6fc7c73be2107e19b85bbf4d72d8"
}

rule MalwareBazaar_Mirai_027_eff866c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff866c9c928f530994bc95636b4d0a9b956c2af6f7179e36b2921be4bdc0dd8"
    family = "Mirai"
    file_name = "nklmpsl"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:46"
  condition:
    hash.sha256(0, filesize) == "eff866c9c928f530994bc95636b4d0a9b956c2af6f7179e36b2921be4bdc0dd8"
}

rule MalwareBazaar_Mirai_028_a334bc01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a334bc01514f3184f24c2ba9d3e703e4eb82f6a4c8c0fe29d1d6cb87b2be54eb"
    family = "Mirai"
    file_name = "nklppc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:44"
  condition:
    hash.sha256(0, filesize) == "a334bc01514f3184f24c2ba9d3e703e4eb82f6a4c8c0fe29d1d6cb87b2be54eb"
}

rule MalwareBazaar_Mirai_029_524b7179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "524b717901a23d47a55578975db09e935d3b5ac6f59d294d855f3a79b8ab090b"
    family = "Mirai"
    file_name = "nklarm"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:41"
  condition:
    hash.sha256(0, filesize) == "524b717901a23d47a55578975db09e935d3b5ac6f59d294d855f3a79b8ab090b"
}

rule MalwareBazaar_Mirai_030_9b030e2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b030e2c5882dc9d4206c544188dfe9d356e92a481b5244ac905ceb5def3620c"
    family = "Mirai"
    file_name = "nabspc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:39"
  condition:
    hash.sha256(0, filesize) == "9b030e2c5882dc9d4206c544188dfe9d356e92a481b5244ac905ceb5def3620c"
}

rule MalwareBazaar_Mirai_031_43f01ffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43f01ffea0e2affdf0ddf22edffee3a38de00d8d211cb4ecdc6c83b44d5cbcdd"
    family = "Mirai"
    file_name = "b"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:36"
  condition:
    hash.sha256(0, filesize) == "43f01ffea0e2affdf0ddf22edffee3a38de00d8d211cb4ecdc6c83b44d5cbcdd"
}

rule MalwareBazaar_Mirai_032_18ba92e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18ba92e53925ba588f32ffb2e6bccedd9d3f7dc94077d9d21303f123d9843e89"
    family = "Mirai"
    file_name = "nabx86"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:34"
  condition:
    hash.sha256(0, filesize) == "18ba92e53925ba588f32ffb2e6bccedd9d3f7dc94077d9d21303f123d9843e89"
}

rule MalwareBazaar_Mirai_033_ea0d3865
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea0d3865b9b4a5053c1b77101c5352629771d403d9226dcd39b6bee547ad6894"
    family = "Mirai"
    file_name = "nabmips"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:31"
  condition:
    hash.sha256(0, filesize) == "ea0d3865b9b4a5053c1b77101c5352629771d403d9226dcd39b6bee547ad6894"
}

rule MalwareBazaar_Mirai_034_4c641cda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c641cda8ba71f78ffd2b84fc6789ec5183e6c377e9cbfe6b84baeda80343d6b"
    family = "Mirai"
    file_name = "nklarm7"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:29"
  condition:
    hash.sha256(0, filesize) == "4c641cda8ba71f78ffd2b84fc6789ec5183e6c377e9cbfe6b84baeda80343d6b"
}

rule MalwareBazaar_Mirai_035_4b500f70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b500f70468c1b56802b3b01d63b0df36be84288f8e7c3cd366f0c3aa0ab9047"
    family = "Mirai"
    file_name = "nklspc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:26"
  condition:
    hash.sha256(0, filesize) == "4b500f70468c1b56802b3b01d63b0df36be84288f8e7c3cd366f0c3aa0ab9047"
}

rule MalwareBazaar_Mirai_036_ba483670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba483670f1f8242c1f906168d5ef5486646b3b9c30ab5c563bc905e38960c4ae"
    family = "Mirai"
    file_name = "nabsh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:24"
  condition:
    hash.sha256(0, filesize) == "ba483670f1f8242c1f906168d5ef5486646b3b9c30ab5c563bc905e38960c4ae"
}

rule MalwareBazaar_Mirai_037_981fd572
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "981fd572102f97b94d43b5c71567ac15dac2b08d8529f2b6ff097d1d2dc95281"
    family = "Mirai"
    file_name = "nabppc"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:20"
  condition:
    hash.sha256(0, filesize) == "981fd572102f97b94d43b5c71567ac15dac2b08d8529f2b6ff097d1d2dc95281"
}

rule MalwareBazaar_Mirai_038_652d0182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "652d0182afa9fe66832640eb434ce3f2480b375f20dfed058ce7d37058fcd061"
    family = "Mirai"
    file_name = "nklsh4"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:18"
  condition:
    hash.sha256(0, filesize) == "652d0182afa9fe66832640eb434ce3f2480b375f20dfed058ce7d37058fcd061"
}

rule MalwareBazaar_unknown_039_0e926c0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e926c0e9816533c25acd45c155751c730bcb3102cdba74b65a12898f902bae7"
    family = "unknown"
    file_name = "prlproxy_static"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:15"
  condition:
    hash.sha256(0, filesize) == "0e926c0e9816533c25acd45c155751c730bcb3102cdba74b65a12898f902bae7"
}

rule MalwareBazaar_unknown_040_7eca922f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eca922f41c5ef2efbbf465104e83bc457cb8ec0c9bb2bdd6511754ab59d8aba"
    family = "unknown"
    file_name = "dawdawd"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:11"
  condition:
    hash.sha256(0, filesize) == "7eca922f41c5ef2efbbf465104e83bc457cb8ec0c9bb2bdd6511754ab59d8aba"
}

rule MalwareBazaar_CyberStrikeAI_041_74c95939
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74c9593919e5c76a363fc19f4f74d34afbb34c512024ee8fe61a4d15c9a02992"
    family = "CyberStrikeAI"
    file_name = "beacon_linux_amd64_p_084f0c5eace84f"
    file_type = "elf"
    first_seen = "2026-11-12 06:54:05"
  condition:
    hash.sha256(0, filesize) == "74c9593919e5c76a363fc19f4f74d34afbb34c512024ee8fe61a4d15c9a02992"
}

rule MalwareBazaar_Mirai_042_7447d718
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a"
    family = "Mirai"
    file_name = "7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a"
    file_type = "sh"
    first_seen = "2026-11-12 06:09:10"
  condition:
    hash.sha256(0, filesize) == "7447d7187ae2246e4e21652911e21c224ba74a2df0f3ab03caa392d7a524b59a"
}

rule MalwareBazaar_unknown_043_e7a44dcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7a44dcb3956c369251f0af002247e4a0f6d2ddae74c5b982b63ba4162e308f1"
    family = "unknown"
    file_name = "install.ps1"
    file_type = "ps1"
    first_seen = "2026-11-12 06:04:09"
  condition:
    hash.sha256(0, filesize) == "e7a44dcb3956c369251f0af002247e4a0f6d2ddae74c5b982b63ba4162e308f1"
}

rule MalwareBazaar_njrat_044_a1871eb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1871eb203ab9137191fe77d01f9c34db383e197e22f5651ac0a98389a040674"
    family = "njrat"
    file_name = "AB0B63F826E6CFBDF525D63F9F3811AF.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:50:09"
  condition:
    hash.sha256(0, filesize) == "a1871eb203ab9137191fe77d01f9c34db383e197e22f5651ac0a98389a040674"
}

rule MalwareBazaar_Ngioweb_045_95250a42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95250a426cdfb70173fc9b8f25000d1dc0b5bbc30be667eda6e55853006fc1d2"
    family = "Ngioweb"
    file_name = "1.fp.mcm.armv7l"
    file_type = "elf"
    first_seen = "2026-11-12 05:49:53"
  condition:
    hash.sha256(0, filesize) == "95250a426cdfb70173fc9b8f25000d1dc0b5bbc30be667eda6e55853006fc1d2"
}

rule MalwareBazaar_Mirai_046_8e4d3352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e4d3352d433d96c4680761419940eb4bfdde3a8a85a34074221b968af20fb24"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 05:49:04"
  condition:
    hash.sha256(0, filesize) == "8e4d3352d433d96c4680761419940eb4bfdde3a8a85a34074221b968af20fb24"
}

rule MalwareBazaar_PureLogsStealer_047_2f29790f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f29790f71f07705ca1bf7d6232c06318ce13a27d7fb23ee5a3f5e2f5de89192"
    family = "PureLogsStealer"
    file_name = "RequestforQuotationRFQ.js"
    file_type = "js"
    first_seen = "2026-11-12 05:41:39"
  condition:
    hash.sha256(0, filesize) == "2f29790f71f07705ca1bf7d6232c06318ce13a27d7fb23ee5a3f5e2f5de89192"
}

rule MalwareBazaar_unknown_048_24cc5b14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24cc5b14dc4fac822dd39de1b093c065bed5270cd6898b067d110489473ac7f1"
    family = "unknown"
    file_name = "school_holidays1.js"
    file_type = "js"
    first_seen = "2026-11-12 05:41:35"
  condition:
    hash.sha256(0, filesize) == "24cc5b14dc4fac822dd39de1b093c065bed5270cd6898b067d110489473ac7f1"
}

rule MalwareBazaar_RemcosRAT_049_6ecc66b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ecc66b23e7551acadbfd0127ec7203c66bdef083550c363911adf3c2b02fa2d"
    family = "RemcosRAT"
    file_name = "ChequesNo.000003.cmd"
    file_type = "cmd"
    first_seen = "2026-11-12 05:41:32"
  condition:
    hash.sha256(0, filesize) == "6ecc66b23e7551acadbfd0127ec7203c66bdef083550c363911adf3c2b02fa2d"
}

rule MalwareBazaar_MangzLoader_050_00cbf692
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00cbf6925ed0b4d6c1632ab51f5cc0a82fb0299a7be131911fa8877fa8541e4f"
    family = "MangzLoader"
    file_name = "Cacapt.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:41:29"
  condition:
    hash.sha256(0, filesize) == "00cbf6925ed0b4d6c1632ab51f5cc0a82fb0299a7be131911fa8877fa8541e4f"
}

rule MalwareBazaar_RemcosRAT_051_16346b77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16346b77c4ad4a06553c32398694b6dc8ee835649e80eba4f8f204f43103ee04"
    family = "RemcosRAT"
    file_name = "ShippingDocument.cmd"
    file_type = "cmd"
    first_seen = "2026-11-12 05:41:25"
  condition:
    hash.sha256(0, filesize) == "16346b77c4ad4a06553c32398694b6dc8ee835649e80eba4f8f204f43103ee04"
}

rule MalwareBazaar_Mirai_052_12288c54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12288c5456826de4e68163fa99507f58394648955e033e336586aa532a7ae3ad"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 05:34:04"
  condition:
    hash.sha256(0, filesize) == "12288c5456826de4e68163fa99507f58394648955e033e336586aa532a7ae3ad"
}

rule MalwareBazaar_njrat_053_7ad21164
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ad21164b1638c58f1fb5beca8f87b27996970fe4e87244133223703d4c79aea"
    family = "njrat"
    file_name = "6EF196369EEC61A0A1C23FA1CC6A0374.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:15:19"
  condition:
    hash.sha256(0, filesize) == "7ad21164b1638c58f1fb5beca8f87b27996970fe4e87244133223703d4c79aea"
}

rule MalwareBazaar_njrat_054_41b94b18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41b94b182fb4221e3293ad488075f1623763bb56eeb2b19834730031c6081e76"
    family = "njrat"
    file_name = "1c4ad2a425a738a157fc81dfc68dcf32.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:15:12"
  condition:
    hash.sha256(0, filesize) == "41b94b182fb4221e3293ad488075f1623763bb56eeb2b19834730031c6081e76"
}

rule MalwareBazaar_njrat_055_a4ec1bd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4ec1bd1cc63c84caf9cd6feafd94259ac33aaac858e87dc47a583ed8c5f8c00"
    family = "njrat"
    file_name = "024D66B6E13AD1C4DA253C72EFEB6956.exe"
    file_type = "exe"
    first_seen = "2026-11-12 05:15:07"
  condition:
    hash.sha256(0, filesize) == "a4ec1bd1cc63c84caf9cd6feafd94259ac33aaac858e87dc47a583ed8c5f8c00"
}

rule MalwareBazaar_unknown_056_e8778e45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8778e45d1dee2b6b76a7b42a8c2593c8e776b6738ac0e2d5ee0d7f9f75d5922"
    family = "unknown"
    file_name = "my_rakuten_security_v2.apk"
    file_type = "apk"
    first_seen = "2026-11-12 05:08:34"
  condition:
    hash.sha256(0, filesize) == "e8778e45d1dee2b6b76a7b42a8c2593c8e776b6738ac0e2d5ee0d7f9f75d5922"
}

rule MalwareBazaar_Mirai_057_5a010583
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a010583c65438bd217d3408b4a31be4569bdb33d5ae72f241a4b2f00841fa7a"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-12 04:45:04"
  condition:
    hash.sha256(0, filesize) == "5a010583c65438bd217d3408b4a31be4569bdb33d5ae72f241a4b2f00841fa7a"
}

rule MalwareBazaar_SalatStealer_058_52e7dbe1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142"
    family = "SalatStealer"
    file_name = "emulator.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:57:17"
  condition:
    hash.sha256(0, filesize) == "52e7dbe125b2d8db65a0ba7bf80aab698e7f54f8b5b51c2f218f5fb2870ed142"
}

rule MalwareBazaar_SalatStealer_059_35a3c714
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04"
    family = "SalatStealer"
    file_name = "emulator.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:56:59"
  condition:
    hash.sha256(0, filesize) == "35a3c714998539eb98a26e7ae58f379378ddf3fdcb67068944cc8c67a016eb04"
}

rule MalwareBazaar_RevStealer_060_e525530f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f"
    family = "RevStealer"
    file_name = "e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:50:56"
  condition:
    hash.sha256(0, filesize) == "e525530f98e94ba27b8e87ecf596e6e251a59acc4a28ee57963a230d68daa49f"
}

rule MalwareBazaar_RevStealer_061_e37ab282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0"
    family = "RevStealer"
    file_name = "e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0.exe"
    file_type = "exe"
    first_seen = "2026-11-12 03:50:50"
  condition:
    hash.sha256(0, filesize) == "e37ab282bee0d665b0fe86da0c466c154f3df87ce69874309a379cb3fe26cda0"
}

rule MalwareBazaar_SalatStealer_062_09743983
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb"
    family = "SalatStealer"
    file_name = "09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb.bin"
    file_type = "bat"
    first_seen = "2026-11-12 03:47:00"
  condition:
    hash.sha256(0, filesize) == "09743983fceab7d3f9f3bca8e603167a0d2d07c88e1c9f0e75e1e3e90e2623fb"
}

rule MalwareBazaar_Mirai_063_6e3ba255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e3ba2552b7dd2f733becc926ce4447f781af97405d06ea0354f9e2f7ce332b9"
    family = "Mirai"
    file_name = "x-8.6-.Sakura"
    file_type = "elf"
    first_seen = "2026-11-12 03:33:03"
  condition:
    hash.sha256(0, filesize) == "6e3ba2552b7dd2f733becc926ce4447f781af97405d06ea0354f9e2f7ce332b9"
}

rule MalwareBazaar_unknown_064_68abe439
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68abe439c5e5981fa8e69f33001b29a874bd3dc917aad710b22465ca26ba7388"
    family = "unknown"
    file_name = "Ikov.jar"
    file_type = "jar"
    first_seen = "2026-11-12 03:11:20"
  condition:
    hash.sha256(0, filesize) == "68abe439c5e5981fa8e69f33001b29a874bd3dc917aad710b22465ca26ba7388"
}

rule MalwareBazaar_PavinLoader_065_ce1e378e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce1e378e01180dd52df38cd5006c4a57419475675ce21e484f9b9989ac01c279"
    family = "PavinLoader"
    file_name = "safg.msi"
    file_type = "msi"
    first_seen = "2026-11-12 02:50:35"
  condition:
    hash.sha256(0, filesize) == "ce1e378e01180dd52df38cd5006c4a57419475675ce21e484f9b9989ac01c279"
}

rule MalwareBazaar_PavinLoader_066_2431ad79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2431ad790c9decf8a231b36df0fc7763c35005753111d4d89913552c0b9b987a"
    family = "PavinLoader"
    file_name = "corew.msi"
    file_type = "msi"
    first_seen = "2026-11-12 02:50:04"
  condition:
    hash.sha256(0, filesize) == "2431ad790c9decf8a231b36df0fc7763c35005753111d4d89913552c0b9b987a"
}

rule MalwareBazaar_CoinMiner_067_2d4522f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d4522f2f28c455fd1fffadb0dda86055e55785886aa657f7d21f2de8e4e56d7"
    family = "CoinMiner"
    file_name = "amd_plugin_16_64.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:49:25"
  condition:
    hash.sha256(0, filesize) == "2d4522f2f28c455fd1fffadb0dda86055e55785886aa657f7d21f2de8e4e56d7"
}

rule MalwareBazaar_ACRStealer_068_557e3798
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "557e379832620fe46bb447a90d4eadcc716f34e9e20c5310401124fa2ed9ec45"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-12 02:48:31"
  condition:
    hash.sha256(0, filesize) == "557e379832620fe46bb447a90d4eadcc716f34e9e20c5310401124fa2ed9ec45"
}

rule MalwareBazaar_Mirai_069_f64c6226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64c6226897cce9b4b6ed826cafcd9651a1966519729fcca0240739d9ad22785"
    family = "Mirai"
    file_name = "splarm"
    file_type = "elf"
    first_seen = "2026-11-12 02:48:04"
  condition:
    hash.sha256(0, filesize) == "f64c6226897cce9b4b6ed826cafcd9651a1966519729fcca0240739d9ad22785"
}

rule MalwareBazaar_ACRStealer_070_f34272b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f34272b327e15c003316120f4a0eb56c75fd01ea7d5d7143b3742d59c7a727fb"
    family = "ACRStealer"
    file_name = "SETUP.zip"
    file_type = "zip"
    first_seen = "2026-11-12 02:47:44"
  condition:
    hash.sha256(0, filesize) == "f34272b327e15c003316120f4a0eb56c75fd01ea7d5d7143b3742d59c7a727fb"
}

rule MalwareBazaar_WARDENStealer_071_2cd96b24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cd96b244b1bb3cea889fd1ca8b0d466cb7846db0b27772be231d97367442bab"
    family = "WARDENStealer"
    file_name = "d3dx9_26.dll"
    file_type = "exe"
    first_seen = "2026-11-12 02:46:40"
  condition:
    hash.sha256(0, filesize) == "2cd96b244b1bb3cea889fd1ca8b0d466cb7846db0b27772be231d97367442bab"
}

rule MalwareBazaar_CNBackdoor_072_1fa3bb35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fa3bb3562e03f78f6e2a2f9243139a5a9bcaa8622ab943f12d54722bf597a93"
    family = "CNBackdoor"
    file_name = "Launcher21763x64.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:45:09"
  condition:
    hash.sha256(0, filesize) == "1fa3bb3562e03f78f6e2a2f9243139a5a9bcaa8622ab943f12d54722bf597a93"
}

rule MalwareBazaar_CNBackdoor_073_8c9dca48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c9dca4895903e1276169b3819aa9905302ab3203710863dfc061ed014764ca6"
    family = "CNBackdoor"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-11-12 02:44:43"
  condition:
    hash.sha256(0, filesize) == "8c9dca4895903e1276169b3819aa9905302ab3203710863dfc061ed014764ca6"
}

rule MalwareBazaar_Vidar_074_2b51009b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da"
    family = "Vidar"
    file_name = "Script.lua.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:44:21"
  condition:
    hash.sha256(0, filesize) == "2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da"
}

rule MalwareBazaar_WARDENStealer_075_5dc3a9c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf"
    family = "WARDENStealer"
    file_name = "x86__setup_now.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:44:05"
  condition:
    hash.sha256(0, filesize) == "5dc3a9c1d44c3bdfb1c3a14e167f8da0ff93daf5bf6123c549e666e4abdbe0bf"
}

rule MalwareBazaar_unknown_076_e7b2b38e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff"
    family = "unknown"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:41:07"
  condition:
    hash.sha256(0, filesize) == "e7b2b38ee0855e11c4661d838fc151d908adcf157bbdc014c2379f112fa40cff"
}

rule MalwareBazaar_RemusStealer_077_7a705f5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b"
    family = "RemusStealer"
    file_name = "𝗦𝗘𝗧𝗨𝗣.exe"
    file_type = "exe"
    first_seen = "2026-11-12 02:40:06"
  condition:
    hash.sha256(0, filesize) == "7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b"
}

rule MalwareBazaar_Mirai_078_70422ee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51"
    family = "Mirai"
    file_name = "70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51.elf"
    file_type = "elf"
    first_seen = "2026-11-12 02:39:24"
  condition:
    hash.sha256(0, filesize) == "70422ee91ec13ab03002e0bfe9b3ccf2c09475b6c25933ccc60d02af183a5d51"
}

rule MalwareBazaar_WARDENStealer_079_849006e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849006e9d93b763b83b24e8d81627a56024560659131db078d2fc982279d2ddb"
    family = "WARDENStealer"
    file_name = "Outline.zip"
    file_type = "zip"
    first_seen = "2026-11-12 02:37:39"
  condition:
    hash.sha256(0, filesize) == "849006e9d93b763b83b24e8d81627a56024560659131db078d2fc982279d2ddb"
}

rule MalwareBazaar_SalatStealer_080_2c6e721a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6e721a6f0a56f879201237ead174aaaaa3d8aaba5a5860c1362c03c43cf085"
    family = "SalatStealer"
    file_name = "543de6a5e6c9cbb1.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:27:29"
  condition:
    hash.sha256(0, filesize) == "2c6e721a6f0a56f879201237ead174aaaaa3d8aaba5a5860c1362c03c43cf085"
}

rule MalwareBazaar_SalatStealer_081_f642c52a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f642c52a3a519819b265f82418e3a1ae3405107c44d474baa1a9d1af9e44e794"
    family = "SalatStealer"
    file_name = "1815a173a2fb0ee6.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:27:18"
  condition:
    hash.sha256(0, filesize) == "f642c52a3a519819b265f82418e3a1ae3405107c44d474baa1a9d1af9e44e794"
}

rule MalwareBazaar_SalatStealer_082_60811b58
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60811b58fd9cee5551ce9458b53bef8c3f2ff88a74b6ee7bf8c6ba8211cef296"
    family = "SalatStealer"
    file_name = "3f8fdf75598d3864.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:34"
  condition:
    hash.sha256(0, filesize) == "60811b58fd9cee5551ce9458b53bef8c3f2ff88a74b6ee7bf8c6ba8211cef296"
}

rule MalwareBazaar_SalatStealer_083_016d68de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "016d68dee6dce26dc21d6767099f2164b909dfe6bdf3c2e01096b27295f2bdf3"
    family = "SalatStealer"
    file_name = "681caa54169e5890.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:29"
  condition:
    hash.sha256(0, filesize) == "016d68dee6dce26dc21d6767099f2164b909dfe6bdf3c2e01096b27295f2bdf3"
}

rule MalwareBazaar_SalatStealer_084_543de6a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "543de6a5e6c9cbb1f35ee8c0c42e43e442fb9a1dd1cbd570bf091725dda82b53"
    family = "SalatStealer"
    file_name = "543de6a5e6c9cbb1.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:26"
  condition:
    hash.sha256(0, filesize) == "543de6a5e6c9cbb1f35ee8c0c42e43e442fb9a1dd1cbd570bf091725dda82b53"
}

rule MalwareBazaar_SalatStealer_085_e33c261c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e33c261c22aff86aa8c951ba8ed6e7a99d22ac7182cdff648ec7f4fffde24bcb"
    family = "SalatStealer"
    file_name = "61fb46f1f1564b24.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:23"
  condition:
    hash.sha256(0, filesize) == "e33c261c22aff86aa8c951ba8ed6e7a99d22ac7182cdff648ec7f4fffde24bcb"
}

rule MalwareBazaar_SalatStealer_086_fb4feacc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb4feaccec084a6dd6e4e4dd675a7cf4a3113937be408e03291274f1aae7f218"
    family = "SalatStealer"
    file_name = "b16121d30f49cc27.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:18"
  condition:
    hash.sha256(0, filesize) == "fb4feaccec084a6dd6e4e4dd675a7cf4a3113937be408e03291274f1aae7f218"
}

rule MalwareBazaar_SalatStealer_087_1815a173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1815a173a2fb0ee6298186d98a88e272b6c6d5c586b0a21654c3d1ca7f7b2800"
    family = "SalatStealer"
    file_name = "1815a173a2fb0ee6.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:13"
  condition:
    hash.sha256(0, filesize) == "1815a173a2fb0ee6298186d98a88e272b6c6d5c586b0a21654c3d1ca7f7b2800"
}

rule MalwareBazaar_SalatStealer_088_3f8fdf75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b"
    family = "SalatStealer"
    file_name = "3f8fdf75598d3864.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:26:01"
  condition:
    hash.sha256(0, filesize) == "3f8fdf75598d386424b6386dffe3915fd1f8b6431f931b91143e6cfea8e8986b"
}

rule MalwareBazaar_SalatStealer_089_681caa54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "681caa54169e5890849e1edb1092c5a9776a9c91af88d23fe73aab1eb873d5d2"
    family = "SalatStealer"
    file_name = "681caa54169e5890.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:25:49"
  condition:
    hash.sha256(0, filesize) == "681caa54169e5890849e1edb1092c5a9776a9c91af88d23fe73aab1eb873d5d2"
}

rule MalwareBazaar_SalatStealer_090_61fb46f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61fb46f1f1564b2468d78f668c8047a2b998cfe46e6d84a1fb43a49165022636"
    family = "SalatStealer"
    file_name = "61fb46f1f1564b24.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:25:36"
  condition:
    hash.sha256(0, filesize) == "61fb46f1f1564b2468d78f668c8047a2b998cfe46e6d84a1fb43a49165022636"
}

rule MalwareBazaar_SalatStealer_091_b16121d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b16121d30f49cc2788509173e0f54a47c524deba60418b3b393fc74b3211cb54"
    family = "SalatStealer"
    file_name = "b16121d30f49cc27.bin"
    file_type = "exe"
    first_seen = "2026-11-12 02:25:24"
  condition:
    hash.sha256(0, filesize) == "b16121d30f49cc2788509173e0f54a47c524deba60418b3b393fc74b3211cb54"
}

rule MalwareBazaar_AgentTesla_092_28c353af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923"
    family = "AgentTesla"
    file_name = "28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923.bin"
    file_type = "ps1"
    first_seen = "2026-11-12 02:18:20"
  condition:
    hash.sha256(0, filesize) == "28c353af015bd0007decc57e13ca5ecf32b57f5291f6c425263a6fdf27591923"
}

rule MalwareBazaar_unknown_093_85759826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1"
    family = "unknown"
    file_name = "85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1.bin"
    file_type = "sh"
    first_seen = "2026-11-12 02:17:15"
  condition:
    hash.sha256(0, filesize) == "85759826f998c687135fc8b6e728b2828d54df0d249fd994d54838394c0ba1a1"
}

rule MalwareBazaar_WannaCry_094_5e99c8dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2"
    family = "WannaCry"
    file_name = "5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2"
    file_type = "exe"
    first_seen = "2026-11-12 02:15:14"
  condition:
    hash.sha256(0, filesize) == "5e99c8dc8b2280db3a1f00e7ce5949898e0f05c9a2fbceae9dff2f3d9f3349e2"
}

rule MalwareBazaar_unknown_095_849c3931
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421"
    family = "unknown"
    file_name = "849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421"
    file_type = "elf"
    first_seen = "2026-11-12 02:03:55"
  condition:
    hash.sha256(0, filesize) == "849c393107fa863e3575c627330465010233ecabb29c73f67703f0c4bd2ca421"
}

rule MalwareBazaar_unknown_096_cb275fd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3"
    family = "unknown"
    file_name = "cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3"
    file_type = "elf"
    first_seen = "2026-11-12 02:03:37"
  condition:
    hash.sha256(0, filesize) == "cb275fd75a405c18765b0717d7aff2ade441532c6899c9c4a927bee1681902f3"
}

rule MalwareBazaar_unknown_097_fa688365
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2"
    family = "unknown"
    file_name = "fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2.exe"
    file_type = "exe"
    first_seen = "2026-11-12 01:46:00"
  condition:
    hash.sha256(0, filesize) == "fa688365d3599eee9b920c13c4340a9bfd3da416f4ba3cf6a2b6924e5fd95cf2"
}

rule MalwareBazaar_Mirai_098_5a1ed238
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-12 01:45:05"
  condition:
    hash.sha256(0, filesize) == "5a1ed238a7fe20561670d055e5e9da5e300651d2f87a7836993bd39a5a3dd1bc"
}

rule MalwareBazaar_SalatStealer_099_96a7e7b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96a7e7b91f411a42fe3d9cec4c41ab7b9f9feb4d6684a8d02fe5dfa8ace7b841"
    family = "SalatStealer"
    file_name = "f6be70d636ee97a7.bin"
    file_type = "exe"
    first_seen = "2026-11-12 01:27:24"
  condition:
    hash.sha256(0, filesize) == "96a7e7b91f411a42fe3d9cec4c41ab7b9f9feb4d6684a8d02fe5dfa8ace7b841"
}

rule MalwareBazaar_SalatStealer_100_3e4e0fdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e4e0fdc218ad6dfa3ac0b0db1c4185a2eb2aceedf5ebb42d112cb9d7982b155"
    family = "SalatStealer"
    file_name = "c5b47b753e5163d3.bin"
    file_type = "exe"
    first_seen = "2026-11-12 01:27:18"
  condition:
    hash.sha256(0, filesize) == "3e4e0fdc218ad6dfa3ac0b0db1c4185a2eb2aceedf5ebb42d112cb9d7982b155"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-16

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 630 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 630 |
| Unique family labels | 10 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 84 |
| JOMANGY | 3 |
| Gafgyt | 3 |
| Prometei | 3 |
| Mirai | 2 |
| WhiteSnakeStealer | 1 |
| CoinMiner | 1 |
| WannaCry | 1 |
| SalatStealer | 1 |
| DCRat | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| jar | 38 |
| exe | 31 |
| elf | 19 |
| sh | 7 |
| unknown | 2 |
| zip | 2 |
| apk | 1 |

## Per-Sample Analysis

### Sample 1: `1ee2daaa9ecbaa6e`

| Field | Value |
|---|---|
| SHA-256 | `1ee2daaa9ecbaa6e3aab81af477fbe16994a1341b1c96d9f42ddf8ef48d54df7` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-16 04:51:27` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35012bf295523523396aebca9d34bc24` |
| SHA-1 | `eb5d93ea2cf1d15c67d60ea2ef6cb46951a6e774` |
| SHA-256 | `1ee2daaa9ecbaa6e3aab81af477fbe16994a1341b1c96d9f42ddf8ef48d54df7` |
| SHA3-384 | `5acd7193d84c7ac785ffc52f32d8bb2cbe1398ac1382657917f2999ea67789aecc14e9c108a0973e7c8ebfed01bea0eb` |
| TLSH | `T156136D6566913C28AE9988371D7E1F0CBDAA83E2310491DDBFCB3CF18C19A9CD21971D` |
| SSDEEP | `768:JXRWNGxVN9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:Dlxcco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_001_1ee2daaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ee2daaa9ecbaa6e3aab81af477fbe16994a1341b1c96d9f42ddf8ef48d54df7"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 04:51:27"
  condition:
    hash.sha256(0, filesize) == "1ee2daaa9ecbaa6e3aab81af477fbe16994a1341b1c96d9f42ddf8ef48d54df7"
}
```

### Sample 2: `ea5f5e52235e221d`

| Field | Value |
|---|---|
| SHA-256 | `ea5f5e52235e221d109e16450e58ff10d00609a874982b453db1cf02d06206a6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:46:51` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d86b6a9a1398b2f479a3c2256a438cf` |
| SHA-1 | `631d4b670136ef3a379db56069f1384009285c4d` |
| SHA-256 | `ea5f5e52235e221d109e16450e58ff10d00609a874982b453db1cf02d06206a6` |
| SHA3-384 | `8ae7beac42d4dc9340467772cd4d88e191bf90a5953b9f45d238a6254682bc5e392ca1c2be8cb8162143a4329cb8f7ce` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19562D786E8A22F7CCE4E90707B11F978AD717A908A655DE3DB928C3159B3CC05024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZZB2S:fKOe2/7c9sN3zfZR1m+RGkQj6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_ea5f5e52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5f5e52235e221d109e16450e58ff10d00609a874982b453db1cf02d06206a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:46:51"
  condition:
    hash.sha256(0, filesize) == "ea5f5e52235e221d109e16450e58ff10d00609a874982b453db1cf02d06206a6"
}
```

### Sample 3: `fbe0353b68f7ea8e`

| Field | Value |
|---|---|
| SHA-256 | `fbe0353b68f7ea8e9143053136dfb40247ebf872fc7e417e739bba263b83ae46` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:44:24` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f9e28cc7be60c4c62916af5fcba5e45` |
| SHA-1 | `f382370bf8459bf26200abedd27880516d14ae7a` |
| SHA-256 | `fbe0353b68f7ea8e9143053136dfb40247ebf872fc7e417e739bba263b83ae46` |
| SHA3-384 | `ae767c8f3784dd7201d0152bceddf37f275a5472f8589373909eaf2c414ee266ac13310a35b2218fe50e28330f1ed232` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12E62F7C6D9926F6CCE4E90B03A10F83C7D7176D0962A99E7D7929C308DA39C24024EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UASBgn:fKOe2/7c9sN3zfZR1m+RGlS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_fbe0353b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbe0353b68f7ea8e9143053136dfb40247ebf872fc7e417e739bba263b83ae46"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:44:24"
  condition:
    hash.sha256(0, filesize) == "fbe0353b68f7ea8e9143053136dfb40247ebf872fc7e417e739bba263b83ae46"
}
```

### Sample 4: `9f5dea15c550e6d4`

| Field | Value |
|---|---|
| SHA-256 | `9f5dea15c550e6d4a0f3585aadd780bdbc426aec230bf2bb2760fc955f798b28` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:41:57` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe3ddda7ea65d9db8a53d00649fb502b` |
| SHA-1 | `8c8ad344124cce9553431fe049ef4c24ce32ffed` |
| SHA-256 | `9f5dea15c550e6d4a0f3585aadd780bdbc426aec230bf2bb2760fc955f798b28` |
| SHA3-384 | `4a20427070ce1953dd3db75c1f01846fe4b2f58511d1bda5f163761700cea3bbc6602b4104c551e6b0c51734b3889cc5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D362C787D8921EADDE4E80B0BE51FC78BD78369085669AE3DB828C3559778D00424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UvxBBj:fKOe2/7c9sN3zfZR1m+RG/0g6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_9f5dea15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f5dea15c550e6d4a0f3585aadd780bdbc426aec230bf2bb2760fc955f798b28"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:41:57"
  condition:
    hash.sha256(0, filesize) == "9f5dea15c550e6d4a0f3585aadd780bdbc426aec230bf2bb2760fc955f798b28"
}
```

### Sample 5: `6aea9105f7c096dd`

| Field | Value |
|---|---|
| SHA-256 | `6aea9105f7c096dd08f3d7920af28709e437ef99aff5b5c5683e490b03f0157d` |
| Family label | `Gafgyt` |
| File name | `m-p.s-l.Sakura` |
| File type | `elf` |
| First seen | `2026-09-16 04:39:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dbcc0edb9159c44e85c93565d128fa3` |
| SHA-1 | `1393fcf309c7ce34c9d72add01bdd6adf5d4ed15` |
| SHA-256 | `6aea9105f7c096dd08f3d7920af28709e437ef99aff5b5c5683e490b03f0157d` |
| SHA3-384 | `b942f0321ebcbde292a810624417406bb6af90d2ce8a23b00912cd5be3436241658cb4040e0f5daae56f12ce9501745b` |
| TLSH | `T184C39417BB618FB7D81FDE33059A8902108DE58A12D96F6BB2B4C92CE74B94F08D3D54` |
| TELFHASH | `t1fe11104270b6891c2bb259245cbc42b0165532232381be74bf0ec5c05937002ba79e8b` |
| SSDEEP | `1536:/UHeTxCAms/Y8Zm3lKYA43gMJwSkJ8Epj+DzUh8rmW+IFB1Df11hR/:/UyLqAmgMJM8ER+Dw8rmW+IFB1Dt1hR/` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_005_6aea9105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aea9105f7c096dd08f3d7920af28709e437ef99aff5b5c5683e490b03f0157d"
    family = "Gafgyt"
    file_name = "m-p.s-l.Sakura"
    file_type = "elf"
    first_seen = "2026-09-16 04:39:31"
  condition:
    hash.sha256(0, filesize) == "6aea9105f7c096dd08f3d7920af28709e437ef99aff5b5c5683e490b03f0157d"
}
```

### Sample 6: `7009f20d73246b68`

| Field | Value |
|---|---|
| SHA-256 | `7009f20d73246b68de875da4082be8ea96bcdbdc0a32e21459cdd5847b094c18` |
| Family label | `Gafgyt` |
| File name | `a-r.m-7.Sakura` |
| File type | `elf` |
| First seen | `2026-09-16 04:30:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c83f04b6e86e346cf6081aba6d79e41c` |
| SHA-1 | `a6fed6b87785fcf35132ff7e92f27ef8b7649bd8` |
| SHA-256 | `7009f20d73246b68de875da4082be8ea96bcdbdc0a32e21459cdd5847b094c18` |
| SHA3-384 | `432a56b87c86251168788c22915cbc1074e95f43b66999be78c62fa064a33bce4408c363961b4f5ccea0fae85ea5f14f` |
| TLSH | `T13F933A47B71C0B53C59B5AF12DAB3BF08B69B9E113D76185A10AEFD00372EB12412FA5` |
| TELFHASH | `t17011d04270bac91d2bb659245cbc42b5165536236381be75bf0ec5c45537002ba79e8f` |
| SSDEEP | `1536:QQK1n7bzX9jajzvxRq57wBRcGCMCZDxeBk+8hl4umXxVqDrstKfz9e:Q97vk51RcG7APl4umXxVqDrIKfz9e` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_006_7009f20d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7009f20d73246b68de875da4082be8ea96bcdbdc0a32e21459cdd5847b094c18"
    family = "Gafgyt"
    file_name = "a-r.m-7.Sakura"
    file_type = "elf"
    first_seen = "2026-09-16 04:30:38"
  condition:
    hash.sha256(0, filesize) == "7009f20d73246b68de875da4082be8ea96bcdbdc0a32e21459cdd5847b094c18"
}
```

### Sample 7: `659491543493436b`

| Field | Value |
|---|---|
| SHA-256 | `659491543493436ba961770938f1ec59a9fdfde6666950f770ac46c03ca987d7` |
| Family label | `Gafgyt` |
| File name | `m-i.p-s.Sakura` |
| File type | `elf` |
| First seen | `2026-09-16 04:29:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42bb34549223919c715cc20416a34975` |
| SHA-1 | `ff8384d1c58b1b195a51fd5946501e6ecf30847b` |
| SHA-256 | `659491543493436ba961770938f1ec59a9fdfde6666950f770ac46c03ca987d7` |
| SHA3-384 | `917128d33c6e01042fe5c8b66f3d0a2c6a36c7b265c7cfcce9517ca6db093c2255e9b11f58311836fc8113d4a7404bca` |
| TLSH | `T1F3C3842E7E12BFBEE668863107F35F70879521D227A19382F26CD6181E7128D1C5FB64` |
| TELFHASH | `t1fe11104270b6891c2bb259245cbc42b0165532232381be74bf0ec5c05937002ba79e8b` |
| SSDEEP | `1536:M7je1TMGq+f+AQ2rK7zeXeReXe8V2rK7Ie+u60GAzQj1l72HBeeEdWfRZrmW+IFj:Ted0W0MZQHwd6RZrmW+IFB1Dt1hR/` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_007_65949154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "659491543493436ba961770938f1ec59a9fdfde6666950f770ac46c03ca987d7"
    family = "Gafgyt"
    file_name = "m-i.p-s.Sakura"
    file_type = "elf"
    first_seen = "2026-09-16 04:29:21"
  condition:
    hash.sha256(0, filesize) == "659491543493436ba961770938f1ec59a9fdfde6666950f770ac46c03ca987d7"
}
```

### Sample 8: `98faf7bc38c94387`

| Field | Value |
|---|---|
| SHA-256 | `98faf7bc38c94387e2888389fb1a1178016f4c8179d7a9d91ffeb8e078c09d5e` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-16 04:28:10` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7af7864fda4e40c3c32f46d7c4198312` |
| SHA-1 | `d1389c5637723095dbc8a9785253c439d3759694` |
| SHA-256 | `98faf7bc38c94387e2888389fb1a1178016f4c8179d7a9d91ffeb8e078c09d5e` |
| SHA3-384 | `29233c04dbaa491d982621f1b8dfcdecad419c913d0618bd9f6debd7229e5432828b8391ac4c449258fea1c1bd958ca6` |
| TLSH | `T1ADC26D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:S8vCB+25j6es8RE9FYpMSUpi+20qUpi+20YQX:S8l25Jid2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_008_98faf7bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98faf7bc38c94387e2888389fb1a1178016f4c8179d7a9d91ffeb8e078c09d5e"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-16 04:28:10"
  condition:
    hash.sha256(0, filesize) == "98faf7bc38c94387e2888389fb1a1178016f4c8179d7a9d91ffeb8e078c09d5e"
}
```

### Sample 9: `f0f06d6d0f3bbcaf`

| Field | Value |
|---|---|
| SHA-256 | `f0f06d6d0f3bbcafb30dd9fd31bf75974e8f19fbb1f226ecada15720496da9ef` |
| Family label | `WhiteSnakeStealer` |
| File name | `6DBC78E7F56E4D05DBF61E3F205B339D.exe` |
| File type | `exe` |
| First seen | `2026-09-16 04:25:08` |
| Reporter | `abuse_ch` |
| Tags | `exe, WhiteSnakeStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6dbc78e7f56e4d05dbf61e3f205b339d` |
| SHA-1 | `e255fc4314b98064497406940c36c77755c1627a` |
| SHA-256 | `f0f06d6d0f3bbcafb30dd9fd31bf75974e8f19fbb1f226ecada15720496da9ef` |
| SHA3-384 | `82b36c5ce64b9c96fa6923c5e370cf60ef2167850d291cb615908041e1dc3bb9129005fd3159a936a40fc68e10d2e688` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T139933A0CB2C59671D0AF9B3545E25720C3B592036643FB4E0DEED1856E833C4AB85ABE` |
| SSDEEP | `1536:7e1Qda8UdmdDUfOWnU18NMS40RJ85h2BCbzaer9baRInopjXXT1y9Wp31+qbR:QQCdmdDUfOWnU18NMS4iJk2gN9baRao5` |

#### Technical Assessment

- The sample is tracked as `WhiteSnakeStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WhiteSnakeStealer_009_f0f06d6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0f06d6d0f3bbcafb30dd9fd31bf75974e8f19fbb1f226ecada15720496da9ef"
    family = "WhiteSnakeStealer"
    file_name = "6DBC78E7F56E4D05DBF61E3F205B339D.exe"
    file_type = "exe"
    first_seen = "2026-09-16 04:25:08"
  condition:
    hash.sha256(0, filesize) == "f0f06d6d0f3bbcafb30dd9fd31bf75974e8f19fbb1f226ecada15720496da9ef"
}
```

### Sample 10: `ff1c5b16b6c6d6b2`

| Field | Value |
|---|---|
| SHA-256 | `ff1c5b16b6c6d6b24683c44b5e0a4249a75352e6187186c755dfa976aeb002c1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:23:55` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1dde0ef3aafe93331f1e95e901449b4` |
| SHA-1 | `96453b16309113d64353984be8e5fe4426a0a75c` |
| SHA-256 | `ff1c5b16b6c6d6b24683c44b5e0a4249a75352e6187186c755dfa976aeb002c1` |
| SHA3-384 | `50f9fe58b9108e2191ef018856ac666c235decde307d94ba96c2719cd64bf62c8f0049c96a880c46813feeed23ec36fd` |
| IMPHASH | `1d6af8a3a8273e84b2e134876663aa25` |
| TLSH | `T135063301F1C9C121E2A55577C9785D16DA38F858AFA4FACB6300C9E98B71EC0DBB7683` |
| SSDEEP | `98304:kFYZ/PNEzhpWDpXR9+oKaAnc6P1IjV2ybCsZRBhHBRig0:kKJlEzPQXR9+oKfndCV2ahHBRk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_ff1c5b16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff1c5b16b6c6d6b24683c44b5e0a4249a75352e6187186c755dfa976aeb002c1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:23:55"
  condition:
    hash.sha256(0, filesize) == "ff1c5b16b6c6d6b24683c44b5e0a4249a75352e6187186c755dfa976aeb002c1"
}
```

### Sample 11: `ce2aacb6e29749d1`

| Field | Value |
|---|---|
| SHA-256 | `ce2aacb6e29749d1ca29ac3fb1adcbeb42ffe833e51fe948d3e511d5d1364bc9` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:23:02` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8eecbb0bbc9dd6ee5f0733e1dca3dab` |
| SHA-1 | `1dbe5302806390aee9a8abe416ac9a1348aed545` |
| SHA-256 | `ce2aacb6e29749d1ca29ac3fb1adcbeb42ffe833e51fe948d3e511d5d1364bc9` |
| SHA3-384 | `f93d4211f2c6ebad6e68f2329c7d988b443189454670854727835bf5be7d4749b36009f2fc54546a59d6f2f6d4906aaf` |
| IMPHASH | `1dcd477cce07724ec6b817b3be71540e` |
| TLSH | `T17B073327A9C644FDFDB3B63C8D612942F7267C941320C3E712D94AC56E67AD13A36322` |
| SSDEEP | `393216:XlPNuC7hHTodRGkXj+BB9QvEys65UXPM3/SFYfFu7XF1:+Cl0LhXgBGU/0SFYfo7L` |
| ICON-DHASH | `0caea2aaa29696a2` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_011_ce2aacb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce2aacb6e29749d1ca29ac3fb1adcbeb42ffe833e51fe948d3e511d5d1364bc9"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:23:02"
  condition:
    hash.sha256(0, filesize) == "ce2aacb6e29749d1ca29ac3fb1adcbeb42ffe833e51fe948d3e511d5d1364bc9"
}
```

### Sample 12: `06177c98ebf26436`

| Field | Value |
|---|---|
| SHA-256 | `06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61` |
| Family label | `unknown` |
| File name | `06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:56` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f50eb151e4485360d2d91830e030ddce` |
| SHA-1 | `3245402a139c4d04d481397b04cde9f84efab735` |
| SHA-256 | `06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61` |
| SHA3-384 | `2780d4003cfb9bbab608c409d74ee68ceca5a051041603242d86851ba77268aa70d79c2590ea1d3f787ac10d3e13adb5` |
| TLSH | `T1DDC312ABDCBA89DDFE6A4FF5265B0D0B0EF6E1E9E5C13D58053B10C01BB824A9514B48` |
| SSDEEP | `3072:/TNVO/QJHZcfFj4rwLQGTNO5VZLwHm7vuQTpZUy+:7O/QJHZweEL/NOjCHm7FZZ+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_06177c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61"
    family = "unknown"
    file_name = "06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:56"
  condition:
    hash.sha256(0, filesize) == "06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61"
}
```

### Sample 13: `c68a476c411848a1`

| Field | Value |
|---|---|
| SHA-256 | `c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c` |
| Family label | `unknown` |
| File name | `c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:51` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ef2f14904e38ec251eb8d1c357049a0` |
| SHA-1 | `c16ded77bdc8a5dd1eb07b1104fd6a6716b21fd3` |
| SHA-256 | `c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c` |
| SHA3-384 | `9a4a9aa137bfea50e34c3d29b30a979a54751da65c670fbf1a3d97b581bfa2f883401140ad06f4f0dfeceb2f88557453` |
| TLSH | `T1C0C312B38939B2EAF4B1E4F0B65C368D100463D9DD45BA503B49A8651B1839F0B6F39B` |
| SSDEEP | `3072:2glZ3FtCKXhkmHtZ9TEKzjfj/WMngyIfsJ0F7n:2IIKXhZtL7jOTyIG87n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_c68a476c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c"
    family = "unknown"
    file_name = "c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:51"
  condition:
    hash.sha256(0, filesize) == "c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c"
}
```

### Sample 14: `2d0daf1366123b60`

| Field | Value |
|---|---|
| SHA-256 | `2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f` |
| Family label | `unknown` |
| File name | `2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:46` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66771a0ba8d58da74b66b352d99158dc` |
| SHA-1 | `b436f0c0e9f4ee32b7112622009431317b8d14f8` |
| SHA-256 | `2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f` |
| SHA3-384 | `54a88c417b231658fa48e7c6bb3d4cd95601f1315e1486b7135a272f4e34bc8c4f4d8285268023ab2e3a6e1c4a653f4a` |
| TLSH | `T139B31221D3230D0BC43938FABA16D7152D872E79248A415D46F9E6BB4BB705CE9F6313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxr:biMYFJvw6Yh0b1gKobtCGCmCRlrt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_2d0daf13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f"
    family = "unknown"
    file_name = "2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:46"
  condition:
    hash.sha256(0, filesize) == "2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f"
}
```

### Sample 15: `64798263237af5a9`

| Field | Value |
|---|---|
| SHA-256 | `64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7` |
| Family label | `unknown` |
| File name | `64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:41` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f3cefd31b11651e3055fb6d49e59caa` |
| SHA-1 | `de3ea9e56e01f8ee80f10c9b96e40ed12128d511` |
| SHA-256 | `64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7` |
| SHA3-384 | `93316cb9934ae767b3a41325b32e82ee78bae31e6731c1ded863cda1cdbd13073427f98e63d833630fd2c7a14346fb51` |
| TLSH | `T121C3124AFF359C1B8F502DB22ADB5E8E9C6D7A9B41DBF4A879C1C18F47900CE3952214` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ1z:p3lOYoaja8xzx/0wsxzz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_64798263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7"
    family = "unknown"
    file_name = "64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:41"
  condition:
    hash.sha256(0, filesize) == "64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7"
}
```

### Sample 16: `e3ed586dfe5400e8`

| Field | Value |
|---|---|
| SHA-256 | `e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d` |
| Family label | `unknown` |
| File name | `e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d` |
| File type | `sh` |
| First seen | `2026-09-16 04:17:36` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, dropper, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a33034d71aa5a2df43e7c5d9e441c27` |
| SHA-1 | `93f89414db36c4ad4c7feb142c4821d7832fa791` |
| SHA-256 | `e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d` |
| SHA3-384 | `b372ae9aff43fc45f7dae0209cf71c4ee9c75e3ed1389ab2bb7e572667b5436f102caedbebf5329c27b71da4cd52afdb` |
| TLSH | `T117319E9E15202A321142DA6E73A2354C628DE2F72C4FD3D0D95CADA9C2893CCF265B4D` |
| SSDEEP | `24:mX4h9z6fOf8xZrgc489ngGdOkREISaZl5ClJKV9:mX4hsWirtR/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_e3ed586d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d"
    family = "unknown"
    file_name = "e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d"
    file_type = "sh"
    first_seen = "2026-09-16 04:17:36"
  condition:
    hash.sha256(0, filesize) == "e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d"
}
```

### Sample 17: `bc38953ee029ffd9`

| Field | Value |
|---|---|
| SHA-256 | `bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80` |
| Family label | `unknown` |
| File name | `bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:31` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ff73f08b15c2db0951fef35aa8844c5` |
| SHA-1 | `60b5806f46ebd319a1c7f36c41d6076f7fed6de9` |
| SHA-256 | `bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80` |
| SHA3-384 | `ee0e768467b35febee49470e549f4f3bed9f05e84837c309b72d026ba344168a13dac18b4f443af91cf5e34360dcd8af` |
| TLSH | `T18C47DF77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQm:cqYUQuVDt0TZER` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_bc38953e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80"
    family = "unknown"
    file_name = "bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:31"
  condition:
    hash.sha256(0, filesize) == "bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80"
}
```

### Sample 18: `b0fd24c52d289f83`

| Field | Value |
|---|---|
| SHA-256 | `b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c` |
| Family label | `unknown` |
| File name | `b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:21` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `677624b5d553e5496d03c8ac69858767` |
| SHA-1 | `ccc65eb07338d75480eecbb926a49bbcb42f3054` |
| SHA-256 | `b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c` |
| SHA3-384 | `cd4064fd74c825d90029d24611adc03b6a39ddedf2eb9c5cb5b6d8bab643f5b4e825bfb40187e3a5a814f98245df04d0` |
| TLSH | `T1A0F69D77914338E9E5A98CB4D11025426DAC388B5738A3C7BAC471F667BA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQi:cqYUQuVDt0TZEV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_b0fd24c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c"
    family = "unknown"
    file_name = "b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:21"
  condition:
    hash.sha256(0, filesize) == "b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c"
}
```

### Sample 19: `29069a04f6e197da`

| Field | Value |
|---|---|
| SHA-256 | `29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81` |
| Family label | `Mirai` |
| File name | `29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81` |
| File type | `elf` |
| First seen | `2026-09-16 04:17:13` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17a70251519d9a6d92b0e5d9b11d5dfe` |
| SHA-1 | `50602cfb2f4e69ac024aeda813589944a2a2d6eb` |
| SHA-256 | `29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81` |
| SHA3-384 | `424e7e6355ca0c9c904bd6390185b4d7aa66e0bf8fa7207e17785ae55c9cb046dbf56aa0daf2f96818da0951787eea0a` |
| TLSH | `T19144398AFD81AF25D5C5227BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_29069a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81"
    family = "Mirai"
    file_name = "29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:13"
  condition:
    hash.sha256(0, filesize) == "29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81"
}
```

### Sample 20: `3a4eeb029b28a7f3`

| Field | Value |
|---|---|
| SHA-256 | `3a4eeb029b28a7f35b9d1e61f97da1967c0f3e0a12560bed4863fa653e37644f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:16:37` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d5a05d87e15198561b95c0f3127806d` |
| SHA-1 | `c4b105d793b99a007c65137bdf81df012ddd67d0` |
| SHA-256 | `3a4eeb029b28a7f35b9d1e61f97da1967c0f3e0a12560bed4863fa653e37644f` |
| SHA3-384 | `21f7c13b327273d57a2d09bbe43162ae80ad22c9f942e135f8444dec3150f485131dce15bd4df0ce4ac9cf35106f1f17` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15662F896E8A22F6CCE4ED0703B11F9387DB13399866569E3D7928C315DA78C04524FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UCCb8J:fKOe2/7c9sN3zfZR1m+RG9ID6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_3a4eeb02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a4eeb029b28a7f35b9d1e61f97da1967c0f3e0a12560bed4863fa653e37644f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:16:37"
  condition:
    hash.sha256(0, filesize) == "3a4eeb029b28a7f35b9d1e61f97da1967c0f3e0a12560bed4863fa653e37644f"
}
```

### Sample 21: `bc538b1020ea9114`

| Field | Value |
|---|---|
| SHA-256 | `bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e` |
| Family label | `WannaCry` |
| File name | `bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e` |
| File type | `exe` |
| First seen | `2026-09-16 04:16:05` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `701f7de633de003c050e70b27dbe8767` |
| SHA-1 | `9c863c4d043004704adbaa65d1155c14e4a24cbc` |
| SHA-256 | `bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e` |
| SHA3-384 | `318a58c1a3ad9da89e1f74126eff265f73dac6a2714ee1274b96d3fa5096f78eb967b903a9d683a4a3b527fa3cfd2d1b` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1A7363358726CA1BCE0450AB844B38E1AF7B33C5567BA4B0F87C0826B0D53B9BAF94751` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUDk36SAMdhvxWa9P593R8yAVp2H:DXDqPe1Cxcxk3ZAMUadzR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_021_bc538b10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e"
    family = "WannaCry"
    file_name = "bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e"
    file_type = "exe"
    first_seen = "2026-09-16 04:16:05"
  condition:
    hash.sha256(0, filesize) == "bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e"
}
```

### Sample 22: `3ead35a167eaf27a`

| Field | Value |
|---|---|
| SHA-256 | `3ead35a167eaf27a1cd90b7bbcf50c5d0b771e1128fba43957af8f9be3432fec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:12:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a558b322018be6ea1bfb6c51b0c3d27` |
| SHA-1 | `c0d6b291166646e1e03554ec45e89a594f5777d7` |
| SHA-256 | `3ead35a167eaf27a1cd90b7bbcf50c5d0b771e1128fba43957af8f9be3432fec` |
| SHA3-384 | `3076933468ae2a22560978afb22a52e26df201ac2b41334724a944afa1646a4278bdc1cb4d01cb29b69e65d913fcd3eb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14162E78AD8A26FACDE4EA0703A11FD38BDB176D189695DE3D7828C305D638D10435EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UDBgCc:fKOe2/7c9sN3zfZR1m+RGE6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_3ead35a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ead35a167eaf27a1cd90b7bbcf50c5d0b771e1128fba43957af8f9be3432fec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:12:49"
  condition:
    hash.sha256(0, filesize) == "3ead35a167eaf27a1cd90b7bbcf50c5d0b771e1128fba43957af8f9be3432fec"
}
```

### Sample 23: `269908515ce7fc82`

| Field | Value |
|---|---|
| SHA-256 | `269908515ce7fc8231ec960edeee439d2fe18c30f24344198ae15b4489a23a57` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:11:54` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e00b4f6991962f5f204da4be2b3f7ac` |
| SHA-1 | `5e8b3d4b3256a09e2ac9028459cd752cde0a9e11` |
| SHA-256 | `269908515ce7fc8231ec960edeee439d2fe18c30f24344198ae15b4489a23a57` |
| SHA3-384 | `190e53abafa575b6b031c0be9b165eba505384a78465c3e1b5c46f09023f84218b06b152a9de6c157b7083ed5de5b69a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11862C69AD8A62F5DCE4EC0703E21FC78BEB4769186656DE3E7828C205D778D00025EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UGvBgn:fKOe2/7c9sN3zfZR1m+RG76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_26990851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "269908515ce7fc8231ec960edeee439d2fe18c30f24344198ae15b4489a23a57"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:11:54"
  condition:
    hash.sha256(0, filesize) == "269908515ce7fc8231ec960edeee439d2fe18c30f24344198ae15b4489a23a57"
}
```

### Sample 24: `464fdc550c6ab334`

| Field | Value |
|---|---|
| SHA-256 | `464fdc550c6ab3347a6b08a79b7a248100e9b567b1672790c6a4554c11400fda` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:11:32` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77027d2081889b556605a79341ce33f3` |
| SHA-1 | `c17ed5bfa3b16ba4c1817221500caea446093127` |
| SHA-256 | `464fdc550c6ab3347a6b08a79b7a248100e9b567b1672790c6a4554c11400fda` |
| SHA3-384 | `796d1ba3f0c4bed228c9b50e794c9b1f5b6b8b6c861e512f2b846fc9012789a5e90f71418215ae0f35fc3447b66180f8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16262D68AE9922F6DCE4E81B03B51F8687D71769086665EE3D7828C315EA38D00534EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U8myme:fKOe2/7c9sN3zfZR1m+RG/mt6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_464fdc55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "464fdc550c6ab3347a6b08a79b7a248100e9b567b1672790c6a4554c11400fda"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:11:32"
  condition:
    hash.sha256(0, filesize) == "464fdc550c6ab3347a6b08a79b7a248100e9b567b1672790c6a4554c11400fda"
}
```

### Sample 25: `70ce4f5a04b7ec7c`

| Field | Value |
|---|---|
| SHA-256 | `70ce4f5a04b7ec7c7d93fddf2da8dd01e7fba6fa72080980dea62062558fb8ea` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:11:16` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e8063285f0ffbcc8c99789b29ae9adf` |
| SHA-1 | `32498fd37ec01284661533ae024e9599d7b01ffb` |
| SHA-256 | `70ce4f5a04b7ec7c7d93fddf2da8dd01e7fba6fa72080980dea62062558fb8ea` |
| SHA3-384 | `14080dfdc964a7b03532cd50996a9d24db401437e1ef600e47d7caf783c0be8d247913ac770c7371ab9d49647e879832` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D262D78AED926F5CDE4E91703F11F868AD7437908B669DE7D7868C305DA38D00128EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UqmBgn:fKOe2/7c9sN3zfZR1m+RGVm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_70ce4f5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ce4f5a04b7ec7c7d93fddf2da8dd01e7fba6fa72080980dea62062558fb8ea"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:11:16"
  condition:
    hash.sha256(0, filesize) == "70ce4f5a04b7ec7c7d93fddf2da8dd01e7fba6fa72080980dea62062558fb8ea"
}
```

### Sample 26: `0f2a2c7d48563888`

| Field | Value |
|---|---|
| SHA-256 | `0f2a2c7d485638885ffdd27963384785b603ee83de635e0fc3fc81897f1826ba` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:10:33` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `472b0037cc56489e0b79b49c56bd86db` |
| SHA-1 | `5ef8ccc44b0e7a50480252ae80e90e294a3f1162` |
| SHA-256 | `0f2a2c7d485638885ffdd27963384785b603ee83de635e0fc3fc81897f1826ba` |
| SHA3-384 | `7e66782c9107161b0b0aeeb19fd5ad67635f1d56329c5af6d2b4cc1b539c54373150963499e13e98df67c9bd8cf60ed4` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16862D687D8966F5CEE4F90703B11FD286D7436A09A6659E7D7C28C305DA39D40028FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UgBgCc:fKOe2/7c9sN3zfZR1m+RG76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_0f2a2c7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2a2c7d485638885ffdd27963384785b603ee83de635e0fc3fc81897f1826ba"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:10:33"
  condition:
    hash.sha256(0, filesize) == "0f2a2c7d485638885ffdd27963384785b603ee83de635e0fc3fc81897f1826ba"
}
```

### Sample 27: `07832dd100e27384`

| Field | Value |
|---|---|
| SHA-256 | `07832dd100e273842dd772e6d5fc4f83aceb7fc2817b39c7881afee9c542aa8f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:07:57` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1044d22647bf17f9577e93ba581ea53d` |
| SHA-1 | `d6e3c3dc422411f720c43918545edcc377f86325` |
| SHA-256 | `07832dd100e273842dd772e6d5fc4f83aceb7fc2817b39c7881afee9c542aa8f` |
| SHA3-384 | `27e8fa3016b2651fa1228f09e06fee9de8078f2928847355e7650ad06ae4988a907c364a93d4a95144e37a4872ab6ec3` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16F62D796E8922F6CCF4EC0307A11F868BE747694892599E3E7928C309A738C15134FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJFBgn:fKOe2/7c9sN3zfZR1m+RGE6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_07832dd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07832dd100e273842dd772e6d5fc4f83aceb7fc2817b39c7881afee9c542aa8f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:07:57"
  condition:
    hash.sha256(0, filesize) == "07832dd100e273842dd772e6d5fc4f83aceb7fc2817b39c7881afee9c542aa8f"
}
```

### Sample 28: `112d44269e148549`

| Field | Value |
|---|---|
| SHA-256 | `112d44269e1485491fe0438b42d0342fc5d9aa6367f4518623950ec00d24501e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:06:58` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09a05cc5be8bfe58a096bef829a950f8` |
| SHA-1 | `a43ed8ffa1ab988131312faade9f218a90dc27ed` |
| SHA-256 | `112d44269e1485491fe0438b42d0342fc5d9aa6367f4518623950ec00d24501e` |
| SHA3-384 | `4f78e47c598cbfbee32d2f56566d4350dbe5ddc28c3dcf7bcaa963a2e6fe80870fef8777a6fcc91ff329a436285b87f3` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18162E696D8925E5DDE4E90703B21F868ADB137A0866669E3D7C2CD708DA3AC04424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Us3lBM:fKOe2/7c9sN3zfZR1m+RGT3l6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_112d4426
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "112d44269e1485491fe0438b42d0342fc5d9aa6367f4518623950ec00d24501e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:06:58"
  condition:
    hash.sha256(0, filesize) == "112d44269e1485491fe0438b42d0342fc5d9aa6367f4518623950ec00d24501e"
}
```

### Sample 29: `54ba2d82569000f1`

| Field | Value |
|---|---|
| SHA-256 | `54ba2d82569000f12ce7283695de00eee6e8c7298e8020fa524d4d2ec1455bcb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:05:01` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85ef2beffa0ea3d10f9f87073891bc7a` |
| SHA-1 | `8ea5e73c9e7012a6d31fb91c7ded79f243e89d3f` |
| SHA-256 | `54ba2d82569000f12ce7283695de00eee6e8c7298e8020fa524d4d2ec1455bcb` |
| SHA3-384 | `2e05aa34acee06bf304b5c487f47d38ea182b4fb81c66b909869d46d3b23741d98a694fe0d49bf0184097583b6a5bbcc` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17362C786D8922E6CCE4F90703E11F83CB971769086569AF7E7828C3099639E05539FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGs46MMMMMMMMMx6C:fKOeOQOzUxyMMMMMMMMMx6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_54ba2d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54ba2d82569000f12ce7283695de00eee6e8c7298e8020fa524d4d2ec1455bcb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:05:01"
  condition:
    hash.sha256(0, filesize) == "54ba2d82569000f12ce7283695de00eee6e8c7298e8020fa524d4d2ec1455bcb"
}
```

### Sample 30: `d155609910ab006c`

| Field | Value |
|---|---|
| SHA-256 | `d155609910ab006c5167b5883036c94f459bb7450c34854009ae88e1507d2e54` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-09-16 04:04:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdfb68464db610c76f95970d9ae62153` |
| SHA-1 | `bc916cd3b6190771d72a53dc6645611c7a6e465b` |
| SHA-256 | `d155609910ab006c5167b5883036c94f459bb7450c34854009ae88e1507d2e54` |
| SHA3-384 | `273f32b73eeaaa1c843a2a8593d1d94d323baacbddddf4a393ecc8b65bf8cada6e11931c6c20222ab601dc98d834f25f` |
| TLSH | `T18C11A5CC9CA3E1E3A6D89D08F155C016D8A490D3F8A96A49F7E82A61C4F4600F734FE5` |
| SSDEEP | `24:3J3DNt67NIy4KsarG1QJc5XNcxf+et+AFR:VNt6F4VarG1QJc5XuVt+I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_d1556099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d155609910ab006c5167b5883036c94f459bb7450c34854009ae88e1507d2e54"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-09-16 04:04:27"
  condition:
    hash.sha256(0, filesize) == "d155609910ab006c5167b5883036c94f459bb7450c34854009ae88e1507d2e54"
}
```

### Sample 31: `d99d2e6fbd1b43d3`

| Field | Value |
|---|---|
| SHA-256 | `d99d2e6fbd1b43d335107fb68b5a5e8e34e8634dcd2ef57dbecc9dda2c6eac00` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 04:02:45` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b5feda893cd29ac3858caa4dae2c4f3` |
| SHA-1 | `b18021f8d1e69a16a5f9e812a144606cf363a0e7` |
| SHA-256 | `d99d2e6fbd1b43d335107fb68b5a5e8e34e8634dcd2ef57dbecc9dda2c6eac00` |
| SHA3-384 | `9e44b9d42f1ad605c439526714129ee721c1c5cfdd43d3f501770e4a8dc547cae5edb106e227e8482f9a92c92e45c2ab` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17F62C7CAD9A26EACCF4E80B03F21F938697536D496255AE7D7828C355D638D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UW6bBM:fKOe2/7c9sN3zfZR1m+RGJ6b6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_d99d2e6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d99d2e6fbd1b43d335107fb68b5a5e8e34e8634dcd2ef57dbecc9dda2c6eac00"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:02:45"
  condition:
    hash.sha256(0, filesize) == "d99d2e6fbd1b43d335107fb68b5a5e8e34e8634dcd2ef57dbecc9dda2c6eac00"
}
```

### Sample 32: `367206fbf4b5afc8`

| Field | Value |
|---|---|
| SHA-256 | `367206fbf4b5afc8d3ec80542014a2b40b0888cbd37d065d3fab42fa165e8772` |
| Family label | `Mirai` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-09-16 03:52:11` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d83cf63a933789dfc485328148ee2c9` |
| SHA-1 | `48cec896715bfada2d1309a77aadd675f5ee7588` |
| SHA-256 | `367206fbf4b5afc8d3ec80542014a2b40b0888cbd37d065d3fab42fa165e8772` |
| SHA3-384 | `a8d61064049ed192eb46859dfd25e2a8c1d878105e419e2561624ff0550b0b366ce477f31c3b67b67753e554bfbeabe1` |
| TLSH | `T17A3175CA50100E318112CA4E737BB848B15EE1E72A4F8BD6988C1EE997487CCF596B4D` |
| SSDEEP | `24:7yyKCsjHgk9zeMRbPd9YorvDC5E1ZfwmDU4CDk+K:7yJCsrgk9ze0sor7C5iZfbDU4CDHK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_367206fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "367206fbf4b5afc8d3ec80542014a2b40b0888cbd37d065d3fab42fa165e8772"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-16 03:52:11"
  condition:
    hash.sha256(0, filesize) == "367206fbf4b5afc8d3ec80542014a2b40b0888cbd37d065d3fab42fa165e8772"
}
```

### Sample 33: `bd855a59448334d3`

| Field | Value |
|---|---|
| SHA-256 | `bd855a59448334d3c9ec15ac534478a4f808c93ea424ea7627f318fdb1b7064b` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-16 03:46:35` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e0df51c611d97e39552a24328fac6c7` |
| SHA-1 | `60f29226b579fbac65abb622926b236f4ceba334` |
| SHA-256 | `bd855a59448334d3c9ec15ac534478a4f808c93ea424ea7627f318fdb1b7064b` |
| SHA3-384 | `d3e96eef11c76a31c27be652496890b5f1018d070dd36ee61f260d187acdcf5bbad62da092aa2b7b9daf5324912d2532` |
| TLSH | `T102137D6956817C24AE99883B1C7E2F0CB9A983E1310451EDBFCB3CF58C09B9CD219B1D` |
| SSDEEP | `768:f7+e9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:T+Lco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_033_bd855a59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd855a59448334d3c9ec15ac534478a4f808c93ea424ea7627f318fdb1b7064b"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 03:46:35"
  condition:
    hash.sha256(0, filesize) == "bd855a59448334d3c9ec15ac534478a4f808c93ea424ea7627f318fdb1b7064b"
}
```

### Sample 34: `8cd11b6e3504363d`

| Field | Value |
|---|---|
| SHA-256 | `8cd11b6e3504363d2818cfa541698af18f80be3552e038dfa9369c0ba28c6817` |
| Family label | `unknown` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-09-16 03:44:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3508a7677d7b9a20f51b311f2b3021c` |
| SHA-1 | `c1b355909fb81fed9683b0daa25e658a96e14857` |
| SHA-256 | `8cd11b6e3504363d2818cfa541698af18f80be3552e038dfa9369c0ba28c6817` |
| SHA3-384 | `ca684283ec9991ef55bdb2a750e531710b181eda4b29e0c0b38527bef932c6236111d0c337050b3614742bc5079fad6b` |
| TLSH | `T15A11CBCD9CA3E0E295D89D04B155C416D8688AD3E8892B8DFBDC1AB2D5F4D10F725FC8` |
| SSDEEP | `12:YfdfREf7NIk7fo5KYfar8f0fJcw6pfN5OnftVJlfNG8ESfGfAamRn:8le7NIW4K8arogJc55NcffrLyAbn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_8cd11b6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cd11b6e3504363d2818cfa541698af18f80be3552e038dfa9369c0ba28c6817"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-09-16 03:44:10"
  condition:
    hash.sha256(0, filesize) == "8cd11b6e3504363d2818cfa541698af18f80be3552e038dfa9369c0ba28c6817"
}
```

### Sample 35: `97609784e7ac040f`

| Field | Value |
|---|---|
| SHA-256 | `97609784e7ac040fcad2e0e3dc139c024d8dfc27720ef35c686aab8f21eedd7f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 03:33:52` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe931e21cbe7b99cb8b74ac76c7f82d5` |
| SHA-1 | `b46df40a4526428a214d8afdcb74fb3703ccf6eb` |
| SHA-256 | `97609784e7ac040fcad2e0e3dc139c024d8dfc27720ef35c686aab8f21eedd7f` |
| SHA3-384 | `7f88e6f1d1f450411b752f2933a7669ae2242cb20378c734063219ee5618dfe669e7dc2bfd22f50b3c9e734529c78e28` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17762C58AD9A22F5CDE8ED0703A21FD38797076D08A665DE3D7C28D3459A78D10024FBA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uy9WWa:fKOe2/7c9sN3zfZR1m+RG56C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_97609784
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97609784e7ac040fcad2e0e3dc139c024d8dfc27720ef35c686aab8f21eedd7f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:33:52"
  condition:
    hash.sha256(0, filesize) == "97609784e7ac040fcad2e0e3dc139c024d8dfc27720ef35c686aab8f21eedd7f"
}
```

### Sample 36: `5d0320d2437bd0cf`

| Field | Value |
|---|---|
| SHA-256 | `5d0320d2437bd0cf992de5b75420ad0a67c3191c3b38ce14bc9cf09195863d25` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 03:27:45` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f62eb3d4cae3229becaa9c0175a26dd` |
| SHA-1 | `ba8e885e3a4a3a31967c40ccafe8eec4e1e07cfd` |
| SHA-256 | `5d0320d2437bd0cf992de5b75420ad0a67c3191c3b38ce14bc9cf09195863d25` |
| SHA3-384 | `be79e5476798679c7892382493c5e60066ac1731af7f5eef8ac4be625c0c1725012fdad43a4a62ab3223b367e81786dd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F962D88AD9E22F5DCE4E80703A11F93CBD7436908A6669E3D7919C345DA39D04824FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UqSBgn:fKOe2/7c9sN3zfZR1m+RG/S6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_5d0320d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d0320d2437bd0cf992de5b75420ad0a67c3191c3b38ce14bc9cf09195863d25"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:27:45"
  condition:
    hash.sha256(0, filesize) == "5d0320d2437bd0cf992de5b75420ad0a67c3191c3b38ce14bc9cf09195863d25"
}
```

### Sample 37: `2aa16ffb145e1ad6`

| Field | Value |
|---|---|
| SHA-256 | `2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576` |
| Family label | `unknown` |
| File name | `2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:47` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0fddf3903fbebbb5f2fcef2129f78f` |
| SHA-1 | `49b3d43cdc7983eb4f09a1df3d29b8eb043bc31f` |
| SHA-256 | `2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576` |
| SHA3-384 | `b2be10da8d1bf097963d2f3685801d093e99bb66eabd45121bafe9318305733f1c1c3d5fa4254058354fcdb4222ef684` |
| TLSH | `T1B7730228673309DEC4367CFAF58EDA6729871B29244B005401B9E5BB5FF718CA4E9326` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobU:biMYFJvw6Yh0b1gKobU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_2aa16ffb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576"
    family = "unknown"
    file_name = "2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:47"
  condition:
    hash.sha256(0, filesize) == "2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576"
}
```

### Sample 38: `cfa99a415781c0e1`

| Field | Value |
|---|---|
| SHA-256 | `cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752` |
| Family label | `unknown` |
| File name | `cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:42` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d7383697445d093bb34c14d9edd36d7` |
| SHA-1 | `a2cdd1f31f19e8f1204daf42d71f44f97ecbe7a9` |
| SHA-256 | `cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752` |
| SHA3-384 | `23946c2e976e6e099447479fbed6c20ce0d1f1b83379dc297c93ee7cc271f822e3ae51c06d78aa447a595f5270e45a06` |
| TLSH | `T1E2C312B38939B2EAF4B1E4F0B65C368D100463D9DD45BA513B4DA8650B1839F0B6F39B` |
| SSDEEP | `3072:2glZ3FtCKXhkmHtZ9TEKzjfj/WMngyIfsJ0F7n:2IIKXhZtL7jOTyIG87n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_cfa99a41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752"
    family = "unknown"
    file_name = "cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:42"
  condition:
    hash.sha256(0, filesize) == "cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752"
}
```

### Sample 39: `d0e536befdd826a3`

| Field | Value |
|---|---|
| SHA-256 | `d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b` |
| Family label | `unknown` |
| File name | `d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:36` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3551b4eb8ce2628405ad7f87d4951b7` |
| SHA-1 | `7a74af2b1bcdef66f350ca80d84b487e6233b545` |
| SHA-256 | `d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b` |
| SHA3-384 | `57376ef679ae3611b3b1c6b0dcdb776c9a30cf5328d39910d3b9cc068efcbdf90fba9fe97ee23781543402379cdf6ad2` |
| TLSH | `T1A9A3026E5CBA8D9DED2A4EF93A874E074DEDE2D8E9C07A1C067B20C017BC2899515748` |
| SSDEEP | `1536:EWTXdmu/5k063Y98cJHZGHddLBZFjcpBf+bLuiTkGesN42NlQb9VZLYH2IBimzWa:/TNVO/QJHZcfFj4rwLQGTNO5VZLwHm7M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_d0e536be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b"
    family = "unknown"
    file_name = "d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:36"
  condition:
    hash.sha256(0, filesize) == "d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b"
}
```

### Sample 40: `649b488b6795b678`

| Field | Value |
|---|---|
| SHA-256 | `649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e` |
| Family label | `unknown` |
| File name | `649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:30` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7a2101fd0e99193604c2697ea97f5f1` |
| SHA-1 | `024787a6a437522d6d8c9b7f7bb96ce55b1d62f7` |
| SHA-256 | `649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e` |
| SHA3-384 | `fd75c02d981315fefd9daebf9409fb7d4d0470900641259db36dbe42ba160e5dc498ddd4cae7c955504466e20bcdd8b6` |
| TLSH | `T1DEC3125293221C0BC42638FABE16E6162D862F79248E415C46F5E67B5FB709CEEF1313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxE:biMYFJvw6Yh0b1gKobtCGCmCRlrW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_649b488b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e"
    family = "unknown"
    file_name = "649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:30"
  condition:
    hash.sha256(0, filesize) == "649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e"
}
```

### Sample 41: `1732d66f3b55d5b9`

| Field | Value |
|---|---|
| SHA-256 | `1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528` |
| Family label | `unknown` |
| File name | `1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:25` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e7f16e739e31a0cf5637b7019f58572` |
| SHA-1 | `08cb1e23e2f01d7e77dcd10d470fb0c6a283c34c` |
| SHA-256 | `1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528` |
| SHA3-384 | `e379aa1f290410124f480a53004a3486e904955a652605558d87be18e64d045104b63b313edba752cea55e9370edaa01` |
| TLSH | `T17FB3124AFE359D0B9F0009B71BDB9F8E9C697B6B02CBB4A469C2D44F57A01CD7C52208` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+Vd:phNlHuBafLeBtfCzpta8xlBIOdVoq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_1732d66f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528"
    family = "unknown"
    file_name = "1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:25"
  condition:
    hash.sha256(0, filesize) == "1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528"
}
```

### Sample 42: `58fdbdebf0ca685e`

| Field | Value |
|---|---|
| SHA-256 | `58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7` |
| Family label | `unknown` |
| File name | `58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7761c89264f12e51c80b41c43ec017b9` |
| SHA-1 | `29fe537968280dec16f1959c65b19b1076b64f58` |
| SHA-256 | `58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7` |
| SHA3-384 | `1c0a5628b2d4739d82cbb3b1c50660dd8091c38921ca969abb5450851f120f24ca5ddc3ee2a6cd00887a89dbfeb72666` |
| TLSH | `T191967C73945224D8E1A9C9B4D51416527DB83C8B573873CBBAC472F61BBABE48E78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQk:cqYUQuVDt0TZEL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_58fdbdeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7"
    family = "unknown"
    file_name = "58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:18"
  condition:
    hash.sha256(0, filesize) == "58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7"
}
```

### Sample 43: `011c23f8bf233f70`

| Field | Value |
|---|---|
| SHA-256 | `011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7` |
| Family label | `unknown` |
| File name | `011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7` |
| File type | `elf` |
| First seen | `2026-09-16 03:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b09dcdb3018d7b792520bbd280662669` |
| SHA-1 | `f477fd26220f4ad8625a1dd71b92b039fa255c2a` |
| SHA-256 | `011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7` |
| SHA3-384 | `9898a4c25c4ee2989ac1efcb70c53dbadfc907d2f2c5adb78f847df489b71222ca8506de69b15bef6acf5233701db77e` |
| TLSH | `T13524198AFC81AF5595C126BBFE2E418A331317B8E2EE71129D145F2477CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqv:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_011c23f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7"
    family = "unknown"
    file_name = "011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:12"
  condition:
    hash.sha256(0, filesize) == "011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7"
}
```

### Sample 44: `5b1aabf210d20620`

| Field | Value |
|---|---|
| SHA-256 | `5b1aabf210d20620bf21330a5c79ac36fcc176cea9daa7aafb420150432d76b3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 03:10:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d00954af13d25711398d4b6b07952fc` |
| SHA-1 | `95ba92c2a1330f1d3d57b3fb455dbb5bf3258ee8` |
| SHA-256 | `5b1aabf210d20620bf21330a5c79ac36fcc176cea9daa7aafb420150432d76b3` |
| SHA3-384 | `90e8562c35fe2407c8d5596b599c78b69dd425af6ef3ffc309998325fde9a2669c4acf0a9fcf5a79f67ef40bd9d68410` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EB62B78AD9A25FACCE4F80703A11FD78BD7436A08A6559E3D7828C315DA79D00474EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U4Rf22:fKOe2/7c9sN3zfZR1m+RGJM6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_5b1aabf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b1aabf210d20620bf21330a5c79ac36fcc176cea9daa7aafb420150432d76b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:10:30"
  condition:
    hash.sha256(0, filesize) == "5b1aabf210d20620bf21330a5c79ac36fcc176cea9daa7aafb420150432d76b3"
}
```

### Sample 45: `4c1d79b6a5ad9f9f`

| Field | Value |
|---|---|
| SHA-256 | `4c1d79b6a5ad9f9fda5f2b66bddb1548608735ddb031708a390a666ca682a10f` |
| Family label | `unknown` |
| File name | `phantom-client.com--Phantom-Client-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2623501baa1954c878a6c0876ed9907` |
| SHA-1 | `1fb9870312b5c67ea646a6f70fa3033e558e45d7` |
| SHA-256 | `4c1d79b6a5ad9f9fda5f2b66bddb1548608735ddb031708a390a666ca682a10f` |
| SHA3-384 | `80d1a80d0b1c4b469919d41357bd054493067f0fd75e2ff437da4ed4c5a11a8d7ecbdd73f98d1ccb28e4b4d095f847d6` |
| TLSH | `T1D37533029A58A813FCF352744B8DA3FAD9C570170D94967B4DB993208E5FF8C0E389B6` |
| SSDEEP | `24576:/v0rja0DisQ162FR8sas54YYjptrH8Kj0ctjBKCh+LRG2dxod+tzLP9P3DZ+6cd+:GG0+sQ16oRNmHHPj0wYCELRd6Y513rx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_4c1d79b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c1d79b6a5ad9f9fda5f2b66bddb1548608735ddb031708a390a666ca682a10f"
    family = "unknown"
    file_name = "phantom-client.com--Phantom-Client-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "4c1d79b6a5ad9f9fda5f2b66bddb1548608735ddb031708a390a666ca682a10f"
}
```

### Sample 46: `4ce241a22d4710c3`

| Field | Value |
|---|---|
| SHA-256 | `4ce241a22d4710c361c341615c7a4fc320ca4904b23589d8713a885f1630404c` |
| Family label | `unknown` |
| File name | `polarclient.net--PolarClient-Cracked-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a522a8cdd81a6c0446b09238faea4ed` |
| SHA-1 | `752442e328e349702f7d56edd238db7246dd1060` |
| SHA-256 | `4ce241a22d4710c361c341615c7a4fc320ca4904b23589d8713a885f1630404c` |
| SHA3-384 | `f100558c45ede582acb40dc596856355dc03036839e8aa955eb3312784b72a067c6cfb18d53fef4fec215465a96c0452` |
| TLSH | `T1F07533039A6CA413FCB343748B4DB3EAC9C5705A0DC85A7B1EF587218D5FE984E385A6` |
| SSDEEP | `24576:ysGLjKaDCSQV44Fh2eaq58+SL7trJ8wjSc/rZqWLivpGYdR09ktzpP9J33N+uGNl:qGaOSQV4mhLyxJ1jSiAW2v7d2mrn3qb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_4ce241a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ce241a22d4710c361c341615c7a4fc320ca4904b23589d8713a885f1630404c"
    family = "unknown"
    file_name = "polarclient.net--PolarClient-Cracked-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "4ce241a22d4710c361c341615c7a4fc320ca4904b23589d8713a885f1630404c"
}
```

### Sample 47: `508f34ffb12c1413`

| Field | Value |
|---|---|
| SHA-256 | `508f34ffb12c141327461f8ef92507dbf1c50bf764349264de32fe60fbea9dbc` |
| Family label | `unknown` |
| File name | `skyblock-addons.com--SkyblockAddons-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a01cb2bc7e38e5e7933c7e0571e5dd09` |
| SHA-1 | `cc84a037bec6c95d512f1b1ca81e17ae2e6e63e3` |
| SHA-256 | `508f34ffb12c141327461f8ef92507dbf1c50bf764349264de32fe60fbea9dbc` |
| SHA3-384 | `2c17f87d07e460f0a9869a00b0bc1ddec83aaa1be044aa61def22b388c2af8b959d30c5e74c8aaabc4965e5f878e58de` |
| TLSH | `T1787533039A5CA813FCF342744B4DB3FADAC570160DC49A7B1DB956218D6FE980E389B6` |
| SSDEEP | `24576:2I8vjkAD0IQ5muFzM0ac5YsYpXtrf8ejccDfPU8bkBvGcd9ODGFzJP953fJ+Y+/0:awAgIQ5mwzpmDfHjces8YBldMKDn3mq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_508f34ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "508f34ffb12c141327461f8ef92507dbf1c50bf764349264de32fe60fbea9dbc"
    family = "unknown"
    file_name = "skyblock-addons.com--SkyblockAddons-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "508f34ffb12c141327461f8ef92507dbf1c50bf764349264de32fe60fbea9dbc"
}
```

### Sample 48: `ce494dcd20e05f16`

| Field | Value |
|---|---|
| SHA-256 | `ce494dcd20e05f1643ef9b6ee72dd3b6ed44c21e58cf484ee3f35e08eb9734c8` |
| Family label | `unknown` |
| File name | `oringo-client.com--Origo-Client-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd79db753434471206c5d5c3553eb643` |
| SHA-1 | `c982d1c14bcc2c81c4a5f1d3dfde14d96c013736` |
| SHA-256 | `ce494dcd20e05f1643ef9b6ee72dd3b6ed44c21e58cf484ee3f35e08eb9734c8` |
| SHA3-384 | `88d101279da45f50d3d3b6ab9d54ade05ecf03d85d60ed5aa476b28a6f01cbe48137fb626cc51663f44d5cdf6e0c5423` |
| TLSH | `T1587533039A6CA813FCB34374874DB3FACDC970160994996B1DB966618D5BFCC0D389BA` |
| SSDEEP | `49152:kg9uqmeQHWW/vCldNj46OG6H5dcaB33/w:kbqmuW/vCldNj46B6fc2fw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ce494dcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce494dcd20e05f1643ef9b6ee72dd3b6ed44c21e58cf484ee3f35e08eb9734c8"
    family = "unknown"
    file_name = "oringo-client.com--Origo-Client-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "ce494dcd20e05f1643ef9b6ee72dd3b6ed44c21e58cf484ee3f35e08eb9734c8"
}
```

### Sample 49: `ba638d2944cfe4f6`

| Field | Value |
|---|---|
| SHA-256 | `ba638d2944cfe4f691eaecf2265010870b7d93b671b9ebb48677e46948246ecb` |
| Family label | `unknown` |
| File name | `skyblock-extras.org--SkyblockExtras-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e913a9e845914206bc22dc3eb199fc71` |
| SHA-1 | `d1774060c25c412a7d2e12256278bf5b5bf6dc5e` |
| SHA-256 | `ba638d2944cfe4f691eaecf2265010870b7d93b671b9ebb48677e46948246ecb` |
| SHA3-384 | `bccd8a247360ace4359babe73aec136e4f13e64063d02a4697f97cc2042cf6d654533c4b42fb60c1e01474221e260851` |
| TLSH | `T16C753303966CAC13FCB38274878CA3FBC9C5B0170ED5966B1DB952218D5BED84D389B6` |
| SSDEEP | `24576:B7QpjqsDk+QDWiFpaOay50McNVtrF8Cj2cRFvk8tCNPGodbGHSrzhP9N3Lv+wkdV:OmsQ+QDWUpH2lFHj2q880NFdSy1j3Kr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_ba638d29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba638d2944cfe4f691eaecf2265010870b7d93b671b9ebb48677e46948246ecb"
    family = "unknown"
    file_name = "skyblock-extras.org--SkyblockExtras-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "ba638d2944cfe4f691eaecf2265010870b7d93b671b9ebb48677e46948246ecb"
}
```

### Sample 50: `7b1e5ad1fe1823b1`

| Field | Value |
|---|---|
| SHA-256 | `7b1e5ad1fe1823b131f8fcba9c5f1f891fbc22870d6e45ebbd5427a344971979` |
| Family label | `unknown` |
| File name | `wielixclient.net--WielixClient-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05fac5ef73d66ca466ffdc519871dc67` |
| SHA-1 | `6bd32852087d5d1eb3044712736fe1e108bcad5e` |
| SHA-256 | `7b1e5ad1fe1823b131f8fcba9c5f1f891fbc22870d6e45ebbd5427a344971979` |
| SHA3-384 | `5f550a3d86f66eb3eb493e89477f831374c2dc2d3929e5652f49abadc22b3c1bccfef2f4cb80e7e7f6330467933219f9` |
| TLSH | `T163753303966CA413FCB352754B8DB3FA8AC570160DC595BB4DB983214D5FB884A3C9BE` |
| SSDEEP | `24576:8q86yPj8YDSiQ5sYFHkcak5OuuX5trL8IjCc5ffm01EzvGqdJUbWBzHP9d3xh+Sy:yoY+iQ5sGH9EDLtjCYO0WznduCBL3F0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_7b1e5ad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b1e5ad1fe1823b131f8fcba9c5f1f891fbc22870d6e45ebbd5427a344971979"
    family = "unknown"
    file_name = "wielixclient.net--WielixClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "7b1e5ad1fe1823b131f8fcba9c5f1f891fbc22870d6e45ebbd5427a344971979"
}
```

### Sample 51: `2f6e5ac329d1cd56`

| Field | Value |
|---|---|
| SHA-256 | `2f6e5ac329d1cd564968a325b6a55024be4a9806ad2186bb7c2d6860d9bed792` |
| Family label | `unknown` |
| File name | `sigmaclient.org--SigmaClient-Fabric-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef93d9984ca41bcbb26d5b536e97e4f7` |
| SHA-1 | `1ee616440f5c17a380541121f0da87d4fc15669b` |
| SHA-256 | `2f6e5ac329d1cd564968a325b6a55024be4a9806ad2186bb7c2d6860d9bed792` |
| SHA3-384 | `7f50fc53df383b3f492d8a9465a86bc50eb740e626c9cc60e3b5473c872e568dd70daf2efdce8b252e27947217aad47d` |
| TLSH | `T1707533039A6CE813FCB342744B4DA3EACEC970160DC4997B5DBA83618D5BED80E38576` |
| SSDEEP | `24576:cTc4rjMEDeOQVAeFh4yaE5CEaLltrR8+jycBlRaUbK35G6dfyVKbzTP9Z3vx+EI8:cpYEKOQVAAh3+bRzjyWQUu3ZdqcTP3LD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_2f6e5ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6e5ac329d1cd564968a325b6a55024be4a9806ad2186bb7c2d6860d9bed792"
    family = "unknown"
    file_name = "sigmaclient.org--SigmaClient-Fabric-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "2f6e5ac329d1cd564968a325b6a55024be4a9806ad2186bb7c2d6860d9bed792"
}
```

### Sample 52: `2f63edf9c20d7345`

| Field | Value |
|---|---|
| SHA-256 | `2f63edf9c20d73454e0afbb04392c969e4b3e5c7bc227f80306b403758cd40cf` |
| Family label | `unknown` |
| File name | `prestige-client.org--PrestigeLoader-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:10:28` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab35e7837ddad9b5090ae085cfadeb8b` |
| SHA-1 | `5ec4d25a44d6cc7e70433d98c1f93599e65a417f` |
| SHA-256 | `2f63edf9c20d73454e0afbb04392c969e4b3e5c7bc227f80306b403758cd40cf` |
| SHA3-384 | `70d0a525df1f45b5b97ae21ae5d0cd1b67202a11a33826593356b14f3065516bd26bcbd79593555cbbe0c2fa73e72375` |
| TLSH | `T19B7533079A5CA413FCF34274874DA3FAC9C5701A0D849A7B1EF996218D5FED80E389B6` |
| SSDEEP | `24576:QT0ZjG6D0wQNQyFtoga+5IQ2L1tr18IjOcVpvs+5iHJG6dFe3YfzFP9j39v+0uN6:BS6gwQNQEtPQ711jOqk+IHxdEINp3nt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_2f63edf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f63edf9c20d73454e0afbb04392c969e4b3e5c7bc227f80306b403758cd40cf"
    family = "unknown"
    file_name = "prestige-client.org--PrestigeLoader-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "2f63edf9c20d73454e0afbb04392c969e4b3e5c7bc227f80306b403758cd40cf"
}
```

### Sample 53: `4b253880629b092f`

| Field | Value |
|---|---|
| SHA-256 | `4b253880629b092f2c8d6ba9d53312d217320ecbea07e67324ea43538cade724` |
| Family label | `unknown` |
| File name | `odinclient.com--OdinClient-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80497e618652bd1fcf987855077d822f` |
| SHA-1 | `670cdb46252afabf9005e7a2f060debaba5c4888` |
| SHA-256 | `4b253880629b092f2c8d6ba9d53312d217320ecbea07e67324ea43538cade724` |
| SHA3-384 | `3f6abe25c12d006a9ad65d24f2187d13ee79f7ff48b0296246c9c066639589d3394b8c8787355e1bff5098a4b5427b7c` |
| TLSH | `T19F7533079A6CE813FCF34274874DA3BEC6D970160D84996B5EB593218D6FE880E385F6` |
| SSDEEP | `49152:xV20yCQHE6RhUT3rj2WiqOD3dQAhJ3z4p:K0yI6RhUT3rj2WZOxQQB4p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_4b253880
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b253880629b092f2c8d6ba9d53312d217320ecbea07e67324ea43538cade724"
    family = "unknown"
    file_name = "odinclient.com--OdinClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "4b253880629b092f2c8d6ba9d53312d217320ecbea07e67324ea43538cade724"
}
```

### Sample 54: `29fcdb33c14d1b13`

| Field | Value |
|---|---|
| SHA-256 | `29fcdb33c14d1b13b8cefba9858a44451b319c4b69a7d5ac1fddc117bbbdf28f` |
| Family label | `unknown` |
| File name | `odinmod.org--OdinMod-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3372f2414b9af12fd60884e1577d71c` |
| SHA-1 | `539362ea67dad0540737c51e60f0db17a835e0ae` |
| SHA-256 | `29fcdb33c14d1b13b8cefba9858a44451b319c4b69a7d5ac1fddc117bbbdf28f` |
| SHA3-384 | `124d3bdeadd8c336137966eda93917ad636745fc166589869a74a26f32e6bc76ba66f7fb5103e65381b4e379631903c2` |
| TLSH | `T11A753307965CA413FCB34274868DA3FFCAD5B01A0D94997B4DF592218D5BEC80E389BA` |
| SSDEEP | `24576:SvrG5jGgDgCQLK0FJiWaU5Eua/9trx8mjGchNhYe9oXNGQdJ4V+vzNP9B3dx+OAL:seigsCQLKiJ1ufxHjGSmeyXzdqgV/3Cv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_29fcdb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29fcdb33c14d1b13b8cefba9858a44451b319c4b69a7d5ac1fddc117bbbdf28f"
    family = "unknown"
    file_name = "odinmod.org--OdinMod-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "29fcdb33c14d1b13b8cefba9858a44451b319c4b69a7d5ac1fddc117bbbdf28f"
}
```

### Sample 55: `bfcccab190bbf4be`

| Field | Value |
|---|---|
| SHA-256 | `bfcccab190bbf4be5dac3bdaaa4db3cf609880fe4622cd08d12e21b417cf4609` |
| Family label | `unknown` |
| File name | `noamaddons.com--NoamAddons-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab04700c72b471362d6b561cab21399a` |
| SHA-1 | `e0d3cabcde360de864919f7d8af81fcfa97c07aa` |
| SHA-256 | `bfcccab190bbf4be5dac3bdaaa4db3cf609880fe4622cd08d12e21b417cf4609` |
| SHA3-384 | `da98730ce61f8044908c83f1b8c504f57a7fff3bf9b4cd0e7bc407371240f8cfde986197e8a621867c86bf5a8f516895` |
| TLSH | `T1247533039A6CF813FCB35274479DB3FAD9C570160D859A6B0DB996208D6FE880E38977` |
| SSDEEP | `49152:EWZ4m2uQluebbsnd5jwGa0MZhdCCnt3mD:EW+m2Eebbsnd5jwG7MdC8gD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_bfcccab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfcccab190bbf4be5dac3bdaaa4db3cf609880fe4622cd08d12e21b417cf4609"
    family = "unknown"
    file_name = "noamaddons.com--NoamAddons-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "bfcccab190bbf4be5dac3bdaaa4db3cf609880fe4622cd08d12e21b417cf4609"
}
```

### Sample 56: `64901e69330332fa`

| Field | Value |
|---|---|
| SHA-256 | `64901e69330332fa5ad9b94c148eceab8bec9d3ae2c6282a27b69297fb1d3093` |
| Family label | `unknown` |
| File name | `gamblerigmod.org--gamble-rig-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a57d1ce7fef255e545d1c3c58c15dbc5` |
| SHA-1 | `58a01cbedb5802ecdcbed239f8ab5e7cd7994b17` |
| SHA-256 | `64901e69330332fa5ad9b94c148eceab8bec9d3ae2c6282a27b69297fb1d3093` |
| SHA3-384 | `df9222e746a838c251bfcfd00b21ea684bc9e46eaf6ac98bc9f929c359812f5011a6ad334ad7c42d1ebebe227bc3a731` |
| TLSH | `T1F1753303952CA413FCF34274478DA3FAC9C570560D859AAB5EB99221CD5FF884F389BA` |
| SSDEEP | `24576:7UeOZjC0DASIgcF3qWak5q6+9ptrL8Kj0c5NXkIf4DLGqdXEz45zDP9X3vD+oCts:43u0sSIga3FI5Lfj0S0IwDfdUctl39N` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_64901e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64901e69330332fa5ad9b94c148eceab8bec9d3ae2c6282a27b69297fb1d3093"
    family = "unknown"
    file_name = "gamblerigmod.org--gamble-rig-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "64901e69330332fa5ad9b94c148eceab8bec9d3ae2c6282a27b69297fb1d3093"
}
```

### Sample 57: `f96bed16099b7fc1`

| Field | Value |
|---|---|
| SHA-256 | `f96bed16099b7fc1d010dfb44d8871e6652fe1ae2c296ce9d6e1ce7eaa74b793` |
| Family label | `unknown` |
| File name | `luminexclient.net--luminex-client-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d198a6c2ca5508af2eef39a7f524f5a0` |
| SHA-1 | `244221ff7dd1629be9c4705f9ef89d6ccb1f94d8` |
| SHA-256 | `f96bed16099b7fc1d010dfb44d8871e6652fe1ae2c296ce9d6e1ce7eaa74b793` |
| SHA3-384 | `236fe8e008a7044497cf42a4b958d9cf97ee9d2232d5f0782095cc2a017f61317e55a123f5b1580da1e183fec8791e42` |
| TLSH | `T188753317966CA413FCB34274874DB3FA8EC970160D88996B5EB657218C5FFC80E2C9B6` |
| SSDEEP | `24576:L8eNjYiDmkQHceFnaYak5Ei4FJtr58EjccZxziwRWLnGKdNIbC5zlP9d3RN+iIni:L9UiykQHcAnXwR5NjcyOwsL/dOeTL3Kc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_f96bed16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f96bed16099b7fc1d010dfb44d8871e6652fe1ae2c296ce9d6e1ce7eaa74b793"
    family = "unknown"
    file_name = "luminexclient.net--luminex-client-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "f96bed16099b7fc1d010dfb44d8871e6652fe1ae2c296ce9d6e1ce7eaa74b793"
}
```

### Sample 58: `25506090219f37a6`

| Field | Value |
|---|---|
| SHA-256 | `25506090219f37a63d69d6d0acd1688b4d639576a14e84fea71c75b0559989ed` |
| Family label | `unknown` |
| File name | `marlowclient.com--MarlowClient-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cfa2fe34196d617669bdbd3a74a66e4` |
| SHA-1 | `008d8fcee5d7403091050ea3576335fd9d2c7c20` |
| SHA-256 | `25506090219f37a63d69d6d0acd1688b4d639576a14e84fea71c75b0559989ed` |
| SHA3-384 | `36491f7a1f783c8850088c6997bb77bdcf212b596d334d258115d968d11a25b26f1e2fad23d7b3b1a2192202ed336f84` |
| TLSH | `T1F4753302965CA813FCF34374474DA3FACAC9B4164D85967B1EB947218D5FE880E3C5BA` |
| SSDEEP | `24576:FUiJjkeDUqQfgWF7AEaM5Ges/Rtrh8Sjsc7XzMm/6TNGmdBmhMfzHP9J3N7+gOH9:FBQeQqQfgI7huzhnjs+YmyTddo6bn3iL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_25506090
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25506090219f37a63d69d6d0acd1688b4d639576a14e84fea71c75b0559989ed"
    family = "unknown"
    file_name = "marlowclient.com--MarlowClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "25506090219f37a63d69d6d0acd1688b4d639576a14e84fea71c75b0559989ed"
}
```

### Sample 59: `b6a1855faf4e23f9`

| Field | Value |
|---|---|
| SHA-256 | `b6a1855faf4e23f9967192dcd6dfd2cf022c9b9f8ab5061edfc28a442b3e5c36` |
| Family label | `unknown` |
| File name | `ghostclient.net--GhostClient-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43d8ea99ecbcaa694b75703027b4a0f3` |
| SHA-1 | `cf28a8ca6caa69c55dd0b9e6dbba902834d81e14` |
| SHA-256 | `b6a1855faf4e23f9967192dcd6dfd2cf022c9b9f8ab5061edfc28a442b3e5c36` |
| SHA3-384 | `2ba975cd4683c5f20832070a13dac644fbe99ab0290db8c0f95da562345db05a91a869b0a750b787e397acbc956463e6` |
| TLSH | `T15F7533039A6CA813FCB342744A9D73FBC9C570170D84996B4DBA97218D5BFC84E389B6` |
| SSDEEP | `24576:+SQ0rja0DisQ162FR8sas54YYjptrH8Kj0ctjBKCh+LRG2dxod+tzLP9P3DZ+6cy:+SG0+sQ16oRNmHHPj0wYCELRd6Y513OA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_b6a1855f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a1855faf4e23f9967192dcd6dfd2cf022c9b9f8ab5061edfc28a442b3e5c36"
    family = "unknown"
    file_name = "ghostclient.net--GhostClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "b6a1855faf4e23f9967192dcd6dfd2cf022c9b9f8ab5061edfc28a442b3e5c36"
}
```

### Sample 60: `bb2d4fc7484862e7`

| Field | Value |
|---|---|
| SHA-256 | `bb2d4fc7484862e764b4a9746a47bc1a56b20989a8cc09fff2a3bd5f5ed787d0` |
| Family label | `unknown` |
| File name | `modhider.com--ModHider-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:09:21` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e530fcdea14c2f6ae3fd084db463e8b7` |
| SHA-1 | `0892915c68d87de5ddc746849ecf1b49fbf4e68e` |
| SHA-256 | `bb2d4fc7484862e764b4a9746a47bc1a56b20989a8cc09fff2a3bd5f5ed787d0` |
| SHA3-384 | `1d1344cde65a3e544fe8362a01d376eb407a58c17fad651a08f4c2c9cd4f2191c413704d17e8a261e25ce7e9afceb11f` |
| TLSH | `T1B2753303965CB813FCB34274879DB3FA8AC570160D95997B5FB942218C5FED80E389BA` |
| SSDEEP | `24576:fb087jQSDegQnIAFZAsaM5siop9trl8mjOc1xPUatoJ3GQdDKXwRzvP9H3pV+QYz:fZcS6gQnIeZlUplHjOSsaiJVdeAx13Li` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_bb2d4fc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb2d4fc7484862e764b4a9746a47bc1a56b20989a8cc09fff2a3bd5f5ed787d0"
    family = "unknown"
    file_name = "modhider.com--ModHider-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "bb2d4fc7484862e764b4a9746a47bc1a56b20989a8cc09fff2a3bd5f5ed787d0"
}
```

### Sample 61: `66293b59e1e15b30`

| Field | Value |
|---|---|
| SHA-256 | `66293b59e1e15b309ba0b6f96e32eb0684a427789f869c243e00a68af8586cda` |
| Family label | `unknown` |
| File name | `floppaclient.org--FloppaClient-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f529b7352fce2fd08f83f170e63ced` |
| SHA-1 | `e87c75d5015fe6eeaf215ad92b5c935a36e20ef1` |
| SHA-256 | `66293b59e1e15b309ba0b6f96e32eb0684a427789f869c243e00a68af8586cda` |
| SHA3-384 | `5dadbc87e83a126ed58dbd52ee0d64e0bf574ba18e7b93e9fc8416d20206e0880584ab170c896d742df622775845bdb1` |
| TLSH | `T1557533075A5CA813FCF342748B4DA3FA9AC970160D85997F1EB952318D5BECC0E389B6` |
| SSDEEP | `49152:ttmx8GU0QrKG1X87BNjkMQKeFRdQydH3XC:tgKGUcG1X87BNjkMPeRQuHC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_66293b59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66293b59e1e15b309ba0b6f96e32eb0684a427789f869c243e00a68af8586cda"
    family = "unknown"
    file_name = "floppaclient.org--FloppaClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "66293b59e1e15b309ba0b6f96e32eb0684a427789f869c243e00a68af8586cda"
}
```

### Sample 62: `3ad70d2ec5439d26`

| Field | Value |
|---|---|
| SHA-256 | `3ad70d2ec5439d26164ae414cbf8e463e3b129dd80f8dbbbf89084c89565e111` |
| Family label | `unknown` |
| File name | `familyaddons.org--FamilyAddons-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f4b997e2c44220b57efe86ae2962ab6` |
| SHA-1 | `306470a0b7664fcb533a0477748d7e777d62964f` |
| SHA-256 | `3ad70d2ec5439d26164ae414cbf8e463e3b129dd80f8dbbbf89084c89565e111` |
| SHA3-384 | `4538587d137d02adeedde55f5dc816415a24ccd71d76704773747f92317b2c58f77607d4bb692a9953ce51cc4ec2206f` |
| TLSH | `T1B1753302951CB813FCB34274874DA3FADAC9B01B0DC495BB5DB69321CD5FE984A385BA` |
| SSDEEP | `24576:khUvjwGDo0QrKYF1EYaa5CKqvJtrB8cjkc3FN2KVMFdG+dxWD+3zdP9x3Dd+me98:r8GU0QrKG1X87BNjkMQKeFRdQydH3/L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_3ad70d2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ad70d2ec5439d26164ae414cbf8e463e3b129dd80f8dbbbf89084c89565e111"
    family = "unknown"
    file_name = "familyaddons.org--FamilyAddons-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "3ad70d2ec5439d26164ae414cbf8e463e3b129dd80f8dbbbf89084c89565e111"
}
```

### Sample 63: `41beea5b2e98d1eb`

| Field | Value |
|---|---|
| SHA-256 | `41beea5b2e98d1ebf8d3b8d8c44f88e20b0fc3e0e86bda759c91c575eb165dc7` |
| Family label | `unknown` |
| File name | `dulkir-mod.com--DulkirMod-Fabric-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `409b09da0ffe302fedc6176bedf80243` |
| SHA-1 | `bb5e8dcdbd12d2348679143dbe970fada00f6d03` |
| SHA-256 | `41beea5b2e98d1ebf8d3b8d8c44f88e20b0fc3e0e86bda759c91c575eb165dc7` |
| SHA3-384 | `a818d9bc3f6ca905d1c473c8769f9c8f8473b6d6181bc510b2c419bf2a97b6130c8eff8221a01c1af24f4b8fe8a93120` |
| TLSH | `T1F4753343956CB813FCB35274478DB2FACAC5701A0D8456BB1EBA56218D5FEC40E389BA` |
| SSDEEP | `24576:iyvk0zjGYDcGQRomFn8Eaq50W6ZdtrR8yjocZnDAYHmXDGedtuRoDz5P9H3nL+kl:igyY4GQRo4nP+JRfjoscYGXrdcOVN3l1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_41beea5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41beea5b2e98d1ebf8d3b8d8c44f88e20b0fc3e0e86bda759c91c575eb165dc7"
    family = "unknown"
    file_name = "dulkir-mod.com--DulkirMod-Fabric-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "41beea5b2e98d1ebf8d3b8d8c44f88e20b0fc3e0e86bda759c91c575eb165dc7"
}
```

### Sample 64: `01d540fdea0277c6`

| Field | Value |
|---|---|
| SHA-256 | `01d540fdea0277c61f2c7cf645c30c6dddbbd1488dc8169a2a0f97ea248646f8` |
| Family label | `unknown` |
| File name | `breezeclient.org--BreezeLoader-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edc3f20f3b571df736560f0c82de508c` |
| SHA-1 | `630b66f23f2e762c0d88fef7682bbb42087143b9` |
| SHA-256 | `01d540fdea0277c61f2c7cf645c30c6dddbbd1488dc8169a2a0f97ea248646f8` |
| SHA3-384 | `1d8b71c656dd0c64b36d23655cddb8e7fca1d4f7aa822306f11fb9a0b6608b6aa407685bdb2db00592aaad6283944283` |
| TLSH | `T1A2753303566CB813FCB352B4475DE3F9CAC9B01B0DD59A7B0DB552218D1EE980E385BA` |
| SSDEEP | `24576:tqXjmkD2iQlwOF9g4aW58G4XJtrd8sjccXPNWUrYlXGGdzOHA9zVP9N3Xv+6CRJV:WykiiQlwQ9rUTdljciAUslTdigvD3rc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_01d540fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01d540fdea0277c61f2c7cf645c30c6dddbbd1488dc8169a2a0f97ea248646f8"
    family = "unknown"
    file_name = "breezeclient.org--BreezeLoader-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "01d540fdea0277c61f2c7cf645c30c6dddbbd1488dc8169a2a0f97ea248646f8"
}
```

### Sample 65: `1989531b67bd8241`

| Field | Value |
|---|---|
| SHA-256 | `1989531b67bd8241a68ea58558cd47ae3c6bd6eb2e967a83c0d9e1cb7009833c` |
| Family label | `unknown` |
| File name | `donutclients.net--donut-duper-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af59c2ba4fc32d75504733d80413f50f` |
| SHA-1 | `dd23de6290438e1df844c5c5dfdd1623d9fa0627` |
| SHA-256 | `1989531b67bd8241a68ea58558cd47ae3c6bd6eb2e967a83c0d9e1cb7009833c` |
| SHA3-384 | `554e9e0364da6482ed4c7730f4e20746bec6126e6b034fd3720f16a85436775d3650adf4bf3c728392e1d2affe86a38c` |
| TLSH | `T1D9753303596CE813FCB34274479DA3FACAC5B0170E84556B4EB997618D5FEC80E389BA` |
| SSDEEP | `24576:ZH6Jj+yDQ6QZe4FDkMaE582IpTtrF8Qjgc/NDwYbUzfGcd5UHMpzFP9D3Bn+ecxV:ZWqyM6QZemDpQfFZjgEsYozpdmszZ3qr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_1989531b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1989531b67bd8241a68ea58558cd47ae3c6bd6eb2e967a83c0d9e1cb7009833c"
    family = "unknown"
    file_name = "donutclients.net--donut-duper-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "1989531b67bd8241a68ea58558cd47ae3c6bd6eb2e967a83c0d9e1cb7009833c"
}
```

### Sample 66: `ff0f288e10515106`

| Field | Value |
|---|---|
| SHA-256 | `ff0f288e10515106f60afe07cc75495e3be564d27b61e6eb1ccadb139e13021a` |
| Family label | `unknown` |
| File name | `funnymap.net--FunnyMap-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cb40fde32724faa83e2ace7ac9fabf4` |
| SHA-1 | `54815090a7524a632e86be63ae1dac801d9d91a2` |
| SHA-256 | `ff0f288e10515106f60afe07cc75495e3be564d27b61e6eb1ccadb139e13021a` |
| SHA3-384 | `7672ecd17f603624c492105cc79e28d55471d1ff3edb0fe5b4df5f6b9e7ce1eca6d8ef37827c32192264e2b723c38fde` |
| TLSH | `T15A753303961CE813FCB352744B5CB3FA9AC970560D85996B4DB982318D5FF884E3C9BA` |
| SSDEEP | `24576:w2LIRjW8DCoQRYqFbOias5guMVztrT8Ojsc5rv6EJSh3GGdNQz8jzJP9R3Jh+WSi:ZAS8uoQRYMbtYjTjjsISEYhfdOAFv3e6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_ff0f288e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff0f288e10515106f60afe07cc75495e3be564d27b61e6eb1ccadb139e13021a"
    family = "unknown"
    file_name = "funnymap.net--FunnyMap-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "ff0f288e10515106f60afe07cc75495e3be564d27b61e6eb1ccadb139e13021a"
}
```

### Sample 67: `fb56628064e508d0`

| Field | Value |
|---|---|
| SHA-256 | `fb56628064e508d02f82cc7d82cb93d73b9909fcc825dccf4c9e85f269dbddeb` |
| Family label | `unknown` |
| File name | `ahsniper.com--AH-Sniper-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e04340a1473f58eb34513328bb90c1a0` |
| SHA-1 | `e2843d9ec64a3746b89d178a4f316176f89d3dfc` |
| SHA-256 | `fb56628064e508d02f82cc7d82cb93d73b9909fcc825dccf4c9e85f269dbddeb` |
| SHA3-384 | `058a9419c5a6b0c14731e4efb38e152a2ae57f4bf73336e89dc7216dfbbb57f5b32784f67b5ae7a23f136f319562e1be` |
| TLSH | `T17A7533075A6CA413FCB34275474DB3EACAC9701B0D84597B4FB992218D5FE9C0E389BA` |
| SSDEEP | `24576:nGsjj86DQqQD82FbGGaa5S6iHftr/8ujEczpncMpE5pGUddod0DzbP9D3Hx+G8VB:7I68qQD8ob/wZ/jjEQcMK5jd+2zR3YF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_fb566280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb56628064e508d02f82cc7d82cb93d73b9909fcc825dccf4c9e85f269dbddeb"
    family = "unknown"
    file_name = "ahsniper.com--AH-Sniper-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "fb56628064e508d02f82cc7d82cb93d73b9909fcc825dccf4c9e85f269dbddeb"
}
```

### Sample 68: `efe7091399a8eb31`

| Field | Value |
|---|---|
| SHA-256 | `efe7091399a8eb31effa1ebd9180fe2a68b7503ea5942a762aaa96b0b19806d0` |
| Family label | `unknown` |
| File name | `cheetoclient.com--CheetoClient-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:49` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04125d0b21418f1c907688148b3ef35f` |
| SHA-1 | `4dd57b558fa70037cc2607f5cd13bd0cb0449a25` |
| SHA-256 | `efe7091399a8eb31effa1ebd9180fe2a68b7503ea5942a762aaa96b0b19806d0` |
| SHA3-384 | `809d944f93aad91c4bb98c117b6107dffa2cdc00880daa517f607e93606eabdf3dd327b1d37d508c770aca0d164fe52f` |
| TLSH | `T167753307995CA813FCB342B4875DA3FACAC570160D84996B1DBA92318D5FFC8093CDBA` |
| SSDEEP | `24576:fTv0ZjG6D0wQNQyFtoga+5IQ2L1tr18IjOcVpvs+5iHJG6dFe3YfzFP9j39v+0uk:8S6gwQNQEtPQ711jOqk+IHxdEINp3Ua` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_efe70913
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efe7091399a8eb31effa1ebd9180fe2a68b7503ea5942a762aaa96b0b19806d0"
    family = "unknown"
    file_name = "cheetoclient.com--CheetoClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "efe7091399a8eb31effa1ebd9180fe2a68b7503ea5942a762aaa96b0b19806d0"
}
```

### Sample 69: `f64ac0fe19425e3e`

| Field | Value |
|---|---|
| SHA-256 | `f64ac0fe19425e3e106e968390c3c87f9dfb55c99e4350ede7f7b6e5d2774a31` |
| Family label | `unknown` |
| File name | `kryptonclient-cracked.com--Krypton-Client-1.21.10-V6.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a2f2408000c94922c8ddceae5c26dd9` |
| SHA-1 | `4c203f1d3e8a124a31d2b8a956e982eb0c32c7f5` |
| SHA-256 | `f64ac0fe19425e3e106e968390c3c87f9dfb55c99e4350ede7f7b6e5d2774a31` |
| SHA3-384 | `3a845e9684c28139349d9beaa2b665b16099a8f6f2dd790fdb636c769fb8ee98bf767b8b2645a19d7f4e834fc7d7414a` |
| TLSH | `T17A753307956CA413FCB30275874CE2E9CAC9B0170ED49A6B5DB95270DD1BEC84D38ABA` |
| SSDEEP | `24576:fddGl3OGDsOQPyGFZgAam5MCGjrtrn8C/Ecb1XAIdMVZG8d7AF+ZzHP9D31B+coD:FseGYOQPyYZvupn9/EwQIyVfdcAhx3G` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_f64ac0fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64ac0fe19425e3e106e968390c3c87f9dfb55c99e4350ede7f7b6e5d2774a31"
    family = "unknown"
    file_name = "kryptonclient-cracked.com--Krypton-Client-1.21.10-V6.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "f64ac0fe19425e3e106e968390c3c87f9dfb55c99e4350ede7f7b6e5d2774a31"
}
```

### Sample 70: `62ca0e73f073ef0b`

| Field | Value |
|---|---|
| SHA-256 | `62ca0e73f073ef0b279a0fe3d4036bed691958fb0583696b7fd552d5ab57ae25` |
| Family label | `unknown` |
| File name | `polinexclient.org--Polinex-Fabric-1.21.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee15c9952bc868580e046da308f1e72f` |
| SHA-1 | `7bcd19814e830ab785ff1d04b019f2415c97a547` |
| SHA-256 | `62ca0e73f073ef0b279a0fe3d4036bed691958fb0583696b7fd552d5ab57ae25` |
| SHA3-384 | `3493226c6c7156e86d14bbcd049a05ecc628a89914786aae4ddb5f70251b6c39adce2a0410b5ec9a172bc553af4c735e` |
| TLSH | `T176753303A66CA413FCF342794B4DA3EACAC9B01B0EC09A6B5D755271CD1EFD44D3896A` |
| SSDEEP | `24576:n/auS5daKDwgQDMiFLy2aw58+2bNtrf8sLcchLBus7cd3GUdJ0bYjzlP9R39F+i6:n/aZoKMgQDMULpWzfDLcIUsod1d+UJvW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_62ca0e73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ca0e73f073ef0b279a0fe3d4036bed691958fb0583696b7fd552d5ab57ae25"
    family = "unknown"
    file_name = "polinexclient.org--Polinex-Fabric-1.21.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "62ca0e73f073ef0b279a0fe3d4036bed691958fb0583696b7fd552d5ab57ae25"
}
```

### Sample 71: `63e5ad0db844f63d`

| Field | Value |
|---|---|
| SHA-256 | `63e5ad0db844f63d0c45eb5e499a5d771a8185f6c58c7cbef25aae9dc3f15710` |
| Family label | `unknown` |
| File name | `luminexclient.com--luminex-client-1.21.4-beta.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b7a306103a04c940d07c3ecd8e42bcd` |
| SHA-1 | `b4da5020ad74dca9d840150652e3851411eafcf2` |
| SHA-256 | `63e5ad0db844f63d0c45eb5e499a5d771a8185f6c58c7cbef25aae9dc3f15710` |
| SHA3-384 | `ddcc86a52d54a4c4d01cf95edaa96697c76f49425b372cc2dfd5f1c5670171394faa85ecbcf6cf1ea3912d0ebd57d2f7` |
| TLSH | `T12F753307966CF813FCF312754B4DA3EA89C9B0170DD4996B4E794621CE1BF884D389BA` |
| SSDEEP | `24576:E8yPvieDKgQf02FJsuaQ5ekylftrf8+1gcf3hq8DCH/GAdxcR0RzNP9h3jb+a2ri:EhaeGgQf0oJzmvf11g6o8uHZdOKz33R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_63e5ad0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63e5ad0db844f63d0c45eb5e499a5d771a8185f6c58c7cbef25aae9dc3f15710"
    family = "unknown"
    file_name = "luminexclient.com--luminex-client-1.21.4-beta.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "63e5ad0db844f63d0c45eb5e499a5d771a8185f6c58c7cbef25aae9dc3f15710"
}
```

### Sample 72: `d9ff0f06fa6f23b6`

| Field | Value |
|---|---|
| SHA-256 | `d9ff0f06fa6f23b6017cf498c7c0ec15c544e33df75ae145016bab6b9a8fabd4` |
| Family label | `unknown` |
| File name | `wielixclient.com--WielixClient-v2.1.0-1.21.11.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ab430befaeb3e3b4511f75ed8e6801e` |
| SHA-1 | `bf0cc1df01c231bb886597875bba6859fa5be94d` |
| SHA-256 | `d9ff0f06fa6f23b6017cf498c7c0ec15c544e33df75ae145016bab6b9a8fabd4` |
| SHA3-384 | `e3fa938ad516cdc4098a40e52d7985d58f348c925e9b607481e73e812d8b5ab643a097b49cd4c99a2c63bfd6ce7e4f6a` |
| TLSH | `T12C7533025A6CB413FCF30275478CA2A9CAC5B0170DD1897B5EBA52719D5FFC80E289BA` |
| SSDEEP | `24576:ZOx0hRaeD06QnqaFJgkaa5y0UD3trz8+5YcdTp62TET3G+d7s7wLzpP9R3d5+kIr:hMeQ6QnqcJjc1z15YsA2gTzdIsdn34` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_d9ff0f06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9ff0f06fa6f23b6017cf498c7c0ec15c544e33df75ae145016bab6b9a8fabd4"
    family = "unknown"
    file_name = "wielixclient.com--WielixClient-v2.1.0-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "d9ff0f06fa6f23b6017cf498c7c0ec15c544e33df75ae145016bab6b9a8fabd4"
}
```

### Sample 73: `72d9dbf486baf38d`

| Field | Value |
|---|---|
| SHA-256 | `72d9dbf486baf38d1d14ecf4afafc8517bb66d340044d4edb29c49fc93daf11c` |
| Family label | `unknown` |
| File name | `sigmaclient.net--SigmaClient-Fabric-1.21.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a17f664c452b32dabbbe1dc6c07dd871` |
| SHA-1 | `5f4cfb95b31fa0eb7895a294756c0211c0adeceb` |
| SHA-256 | `72d9dbf486baf38d1d14ecf4afafc8517bb66d340044d4edb29c49fc93daf11c` |
| SHA3-384 | `4253e8294b1dd5fbc5789b01e07ef311873abfb0e8f70526e73d940dc61ac61f0d28aaf05c6a2fb8e938197837d4d8f4` |
| TLSH | `T11B753306966CB853FCB30275874C63A9C9C9B01B0DD0996B5EB957318D5FF880D2C9BE` |
| SSDEEP | `24576:omYsLXAsDCWQDIOFPwEaM5seuZVtr78WjOc1dh06labZGedXofAHzVP9n3n1+Sct:Jws+WQDIQP5qJ7ljOeC6AbNd4IlN3ux` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_72d9dbf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d9dbf486baf38d1d14ecf4afafc8517bb66d340044d4edb29c49fc93daf11c"
    family = "unknown"
    file_name = "sigmaclient.net--SigmaClient-Fabric-1.21.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "72d9dbf486baf38d1d14ecf4afafc8517bb66d340044d4edb29c49fc93daf11c"
}
```

### Sample 74: `2599c5a6191bc208`

| Field | Value |
|---|---|
| SHA-256 | `2599c5a6191bc208c4f0f1fcafba81b0f8d4099de6dc8d64ee7aec0b5289833e` |
| Family label | `unknown` |
| File name | `github-mixin-loader-2.5.2-obfuscated.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c0747da107021dd2995640eef8afd37` |
| SHA-1 | `e6cf86ee39d64364964eda3adc761bc3388467ca` |
| SHA-256 | `2599c5a6191bc208c4f0f1fcafba81b0f8d4099de6dc8d64ee7aec0b5289833e` |
| SHA3-384 | `1a5607c17e4ef2fe0f85bc75fd9a36b48db8f00f970c1ecde9b4126c5e2c984191c212bcaa174a9362cb9a3c3fcc14bc` |
| TLSH | `T178753307696CF813FCF30275474DB2AAD9C5B0160DC09A6B5E7A8251CE5FF844E28AED` |
| SSDEEP | `24576:I+sIXjOYDICQTq2Fl2Eae5GGiVztrZ8Mj0cb3JmYNWfRGwdJAj+/zfP993hb+MWp:IoCY0CQTqolfiTZPj0iMYEfNd2qr73c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_2599c5a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2599c5a6191bc208c4f0f1fcafba81b0f8d4099de6dc8d64ee7aec0b5289833e"
    family = "unknown"
    file_name = "github-mixin-loader-2.5.2-obfuscated.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "2599c5a6191bc208c4f0f1fcafba81b0f8d4099de6dc8d64ee7aec0b5289833e"
}
```

### Sample 75: `34e8ec188dd68412`

| Field | Value |
|---|---|
| SHA-256 | `34e8ec188dd68412e743d64ae359529944eb969c8541f21330c81f237dc153b8` |
| Family label | `unknown` |
| File name | `invmove.com--InvMove-Fabric-1.21.11-v0.9.3.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96087c19f7902509cc80dddbad8b0c6d` |
| SHA-1 | `d6cc4d3578090c2d94a6bc8a0bfe25e76bccaa5f` |
| SHA-256 | `34e8ec188dd68412e743d64ae359529944eb969c8541f21330c81f237dc153b8` |
| SHA3-384 | `667fc200d5c06944a95d8ba3fa76dc8f633be210f39840782358fe60048fbdaa830bbdbb210e40e1ae073a1527138905` |
| TLSH | `T16E753302966CB403FCF35274874DA3E9DAC5B0170D84DAAB5F794761CD5EFC80A28DAA` |
| SSDEEP | `24576:vLGtNQyDQAQ3yIFzOSaM5kyOTJtr78YBYctTvSGdEFRGwd70RCjzxP9/3nr+aOtS:C+ycAQ3yWzBmn7jBYoKGuFXdwoN139` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_34e8ec18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e8ec188dd68412e743d64ae359529944eb969c8541f21330c81f237dc153b8"
    family = "unknown"
    file_name = "invmove.com--InvMove-Fabric-1.21.11-v0.9.3.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "34e8ec188dd68412e743d64ae359529944eb969c8541f21330c81f237dc153b8"
}
```

### Sample 76: `33d46e4a54c81e50`

| Field | Value |
|---|---|
| SHA-256 | `33d46e4a54c81e5083b2ae4af136a9250c244d0897685526b6669a2ffef3e3d9` |
| Family label | `unknown` |
| File name | `198macros.org--198-Macros-Cracked-26.2.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:08:16` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2eb5cd7340061b5cf6dbcb6731b0ba10` |
| SHA-1 | `34cf3afd8b3532ab424c2fed434186b8243f69f0` |
| SHA-256 | `33d46e4a54c81e5083b2ae4af136a9250c244d0897685526b6669a2ffef3e3d9` |
| SHA3-384 | `3aebd8c4f289c674468969f07b16dcd76779dc05592248410fc23652822346a8f83e5171e0a94e154d9ccf64b25d566e` |
| TLSH | `T1A37533035A68B813FCB342B5478DA3FBCAC570170D84967B4EB956218D5FF980E385BA` |
| SSDEEP | `24576:FmljIGDeAQ3oAFRkcaK5gYQLRtrf8UjKc1bvw0Toh3G+dRsZAPz3P9r3Jz+a2fJz:YEGKAQ3oeRDWnf5jK8o0UhjdGmLZ31e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_33d46e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d46e4a54c81e5083b2ae4af136a9250c244d0897685526b6669a2ffef3e3d9"
    family = "unknown"
    file_name = "198macros.org--198-Macros-Cracked-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "33d46e4a54c81e5083b2ae4af136a9250c244d0897685526b6669a2ffef3e3d9"
}
```

### Sample 77: `e76c1140fad94e7e`

| Field | Value |
|---|---|
| SHA-256 | `e76c1140fad94e7e089e1bb44a3b50657f45e4193848e189c53d566c733f6679` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-16 03:07:56` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71f36e10efb9874c85518f579b8dd71f` |
| SHA-256 | `e76c1140fad94e7e089e1bb44a3b50657f45e4193848e189c53d566c733f6679` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_e76c1140
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76c1140fad94e7e089e1bb44a3b50657f45e4193848e189c53d566c733f6679"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-16 03:07:56"
  condition:
    hash.sha256(0, filesize) == "e76c1140fad94e7e089e1bb44a3b50657f45e4193848e189c53d566c733f6679"
}
```

### Sample 78: `e4e71744b933a8f4`

| Field | Value |
|---|---|
| SHA-256 | `e4e71744b933a8f4c60ba1935dcb97c8c5f4a5a3865ac836f439ab26c2fd61f4` |
| Family label | `unknown` |
| File name | `debugify.net--Debugify-1.21.11.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dd89fb9ec323af81fbb24df641cf830` |
| SHA-1 | `7022c7f1878e8a1ca0401df7e73078457842fd27` |
| SHA-256 | `e4e71744b933a8f4c60ba1935dcb97c8c5f4a5a3865ac836f439ab26c2fd61f4` |
| SHA3-384 | `79eabee73333dcde1ae33e80a5b64faa77ec60e2bd10b18d720792f4cd8d14a3f52d0e72ecf8a70f2594056287bcf1f9` |
| TLSH | `T1DD753306A66CA413FCF24274478CA2E9CAC5701A0EC099BB5EB546718D5FFD84E3CDB9` |
| SSDEEP | `24576:PseT92omZ9IMDqQQpaeF1s4aA5eW81xtrL86BEcPDd+gdCTvG+dleXurzBP9H3tj:keT92bOM2QQpaA1B+5LRBE6IgwTvdE+d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_e4e71744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4e71744b933a8f4c60ba1935dcb97c8c5f4a5a3865ac836f439ab26c2fd61f4"
    family = "unknown"
    file_name = "debugify.net--Debugify-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "e4e71744b933a8f4c60ba1935dcb97c8c5f4a5a3865ac836f439ab26c2fd61f4"
}
```

### Sample 79: `ece34342d452d1c1`

| Field | Value |
|---|---|
| SHA-256 | `ece34342d452d1c1046f7ec42b168e66c8e110757983ae91f9b46743665cbe93` |
| Family label | `unknown` |
| File name | `funnymap.org--FunnyMap-1.21.11.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6496c53acf34ab03b1daf9e4f4a28d1d` |
| SHA-1 | `f9460151d584af9a49edbf2416bd485f84a7cb93` |
| SHA-256 | `ece34342d452d1c1046f7ec42b168e66c8e110757983ae91f9b46743665cbe93` |
| SHA3-384 | `619b165869e14970c2a9a949087f52aad7920ecfbc51c481b438ee0889823e43534f7e47e3cb84c0c85cce3cc3c83bec` |
| TLSH | `T1BC7533065A68B413BCB30275474CB2E9CAC9B0060DD09ABB5D799361CD6FFD84D2C9BA` |
| SSDEEP | `24576:MFW6ExFGyDEQQvu+F9YwaG5I0ivTtrd8+JWcxf7SC5wj9GYdJW/2XzvP9F33j+C/:LsyQQQvug9/kFdJJW4GCKjfdIerb3yo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_ece34342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece34342d452d1c1046f7ec42b168e66c8e110757983ae91f9b46743665cbe93"
    family = "unknown"
    file_name = "funnymap.org--FunnyMap-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "ece34342d452d1c1046f7ec42b168e66c8e110757983ae91f9b46743665cbe93"
}
```

### Sample 80: `490bd7f74ab85cdb`

| Field | Value |
|---|---|
| SHA-256 | `490bd7f74ab85cdbfe757047b013debae8e56cc0d959c6f8bfef4e8bac1ed8f9` |
| Family label | `unknown` |
| File name | `22qq-client.com` |
| File type | `zip` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `570bfa1680d92dd6daa8792f446155b5` |
| SHA-1 | `6bf9d9b76ef4e999a722d741216dc74f370aaa25` |
| SHA-256 | `490bd7f74ab85cdbfe757047b013debae8e56cc0d959c6f8bfef4e8bac1ed8f9` |
| SHA3-384 | `591ca0caf20a49acbbbbc8e6b6209f6a7e237eaf7253227c1ff2d3f930b1d7bc7efbda7713eb21cc42b466aa0b9f2471` |
| TLSH | `T17B753306966CE813FCB31375478DA2E9CAC4B0170DC49A7B4DB94661DD1FFC84E289BA` |
| SSDEEP | `24576:D9QMhdgMDkKQxqoFvw4aq5i+epjtrn8UhocdblGg7KFtGcdbADeBznP993Lt+IY0:DHuMAKQxq2v7QHnThog4gWFLdsyRr3n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_490bd7f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "490bd7f74ab85cdbfe757047b013debae8e56cc0d959c6f8bfef4e8bac1ed8f9"
    family = "unknown"
    file_name = "22qq-client.com"
    file_type = "zip"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "490bd7f74ab85cdbfe757047b013debae8e56cc0d959c6f8bfef4e8bac1ed8f9"
}
```

### Sample 81: `a3556c89baa76f43`

| Field | Value |
|---|---|
| SHA-256 | `a3556c89baa76f4397634b48618a2b42cfc958ac1995c28ec1e03c734637c178` |
| Family label | `unknown` |
| File name | `familyaddons.com--FamilyAddons-1.21.11.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66ec72ed859fe6c31c73a00302a036f8` |
| SHA-1 | `7f599c76ef009640d3639281532f53ad8a7b26b2` |
| SHA-256 | `a3556c89baa76f4397634b48618a2b42cfc958ac1995c28ec1e03c734637c178` |
| SHA3-384 | `bc0789eccdc1cd1208572c6f2d40392eff978f30517118c16f03efe8708be5f3ee4502e6e525f89ada76ba35d6b1f0f9` |
| TLSH | `T1217533079A68B813FCB30275474DA3EA89C5B0170DD09A6B4EB59361CE5FE880D3CDB9` |
| SSDEEP | `24576:VT9t6lW7XYODWAQ9ISF1msaQ5Mk051trr8cTacbfzwEdgLLGydJQry3zNP9h39V8:74+IOCAQ9Ik1baxrbTaiMEmL/dqedP3E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_a3556c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3556c89baa76f4397634b48618a2b42cfc958ac1995c28ec1e03c734637c178"
    family = "unknown"
    file_name = "familyaddons.com--FamilyAddons-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "a3556c89baa76f4397634b48618a2b42cfc958ac1995c28ec1e03c734637c178"
}
```

### Sample 82: `754f68b4cbf5957a`

| Field | Value |
|---|---|
| SHA-256 | `754f68b4cbf5957a34bbd75ed8aa3fe6091986d2edae145688479de064880c54` |
| Family label | `unknown` |
| File name | `198-macros.com--198-Macros-Cracked-v1.4.0.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `288c4cb991d0daf295be3190e5703593` |
| SHA-1 | `2d1f371750efa1965bd4de91bdf0cd46ae66003f` |
| SHA-256 | `754f68b4cbf5957a34bbd75ed8aa3fe6091986d2edae145688479de064880c54` |
| SHA3-384 | `3493bbbff5068df752d809d6d1bb97c935da5a08fb4be61c4a5287621c7ed8b017026abf886c2811a95341a29d7f7dcd` |
| TLSH | `T11B7533069A6CA813FCF352794B4CA2E9CAC4B01A0DC4996B5E754221DD1EFD84D38DBA` |
| SSDEEP | `24576:3c8Dru8DgcQ94mFrCkaS5+6en3trD8oXCcTVP0gXYn1GmdZ8Lahz5P953Zl+og5E:jS8McQ944rJUxDrXCYsgInFd2mnn3h` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_754f68b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "754f68b4cbf5957a34bbd75ed8aa3fe6091986d2edae145688479de064880c54"
    family = "unknown"
    file_name = "198-macros.com--198-Macros-Cracked-v1.4.0.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "754f68b4cbf5957a34bbd75ed8aa3fe6091986d2edae145688479de064880c54"
}
```

### Sample 83: `737d649e7e99b681`

| Field | Value |
|---|---|
| SHA-256 | `737d649e7e99b68182764de02bf075c49b141d9fd45f0d1cc2c8016b703a2672` |
| Family label | `unknown` |
| File name | `breezeclient.com--BreezeLoader-1.21.11.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ae170dec924f9c119df9ec4161d88d3` |
| SHA-1 | `efa686d3c0d4a8b90b655bfebfeb8bdd596761db` |
| SHA-256 | `737d649e7e99b68182764de02bf075c49b141d9fd45f0d1cc2c8016b703a2672` |
| SHA3-384 | `c4760258b05bfc21e66b118c24b9106686a8c7170ad0023a1e3657bd99d92d91e72c874dd5adf7d0f1491c3f834e8c18` |
| TLSH | `T1F2753303957CBC13FCB34274474DB3A98AC9B01B0DC0DA6B5EB94661DD5EF884D289BA` |
| SSDEEP | `24576:zmd9yBj0WDQGQncAFFA0ag5IS+j/trX8wFqcZRtU8RSx3GkddehE1zxP9z3z3+eo:zSgwWcGQnceFZ2tXDFq6u8sxNdcK7538` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_737d649e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "737d649e7e99b68182764de02bf075c49b141d9fd45f0d1cc2c8016b703a2672"
    family = "unknown"
    file_name = "breezeclient.com--BreezeLoader-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "737d649e7e99b68182764de02bf075c49b141d9fd45f0d1cc2c8016b703a2672"
}
```

### Sample 84: `c574cb33ca8687ab`

| Field | Value |
|---|---|
| SHA-256 | `c574cb33ca8687abf18c11ea73efe61303f8ab1a98910c9e2eaf253bca45a0a9` |
| Family label | `unknown` |
| File name | `floppaclient.com--FloppaClient-1.21.11.jar.jar` |
| File type | `jar` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `471a408b53e977996bbb36c07e7d23ba` |
| SHA-1 | `1fb8938aba63b41d82d002f3bf1986494b69506b` |
| SHA-256 | `c574cb33ca8687abf18c11ea73efe61303f8ab1a98910c9e2eaf253bca45a0a9` |
| SHA3-384 | `9863ce9c9797c1ef509775f033f0c9270074762e41112872eec2d2dbfa44eb4fae9661a8657a82283e818061b27071d1` |
| TLSH | `T1ED753307562CF813BCB34275874DB2E9CAC4B0170EC4997B5EB986618D5FF844E28DBA` |
| SSDEEP | `24576:bex9cbp+GDOWQT8T6FhgsaY5Uo4zntr/8e/4ctnlg+5YbtGSdj4Zu9zVP953/B+V:SxAoGKWQT8T8hZG1/Z/40K+abVdccfHS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_c574cb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c574cb33ca8687abf18c11ea73efe61303f8ab1a98910c9e2eaf253bca45a0a9"
    family = "unknown"
    file_name = "floppaclient.com--FloppaClient-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "c574cb33ca8687abf18c11ea73efe61303f8ab1a98910c9e2eaf253bca45a0a9"
}
```

### Sample 85: `db24a0777794c1a7`

| Field | Value |
|---|---|
| SHA-256 | `db24a0777794c1a752311ceca1093d2f4c7741e2ae8eb48ab4081709ddd76283` |
| Family label | `unknown` |
| File name | `nova-client.com` |
| File type | `zip` |
| First seen | `2026-09-16 03:07:42` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edd36dd59bcd5c5451335d87aa864278` |
| SHA-1 | `0a2ff57e14f9551916cd3113c5cf7cdf265622b9` |
| SHA-256 | `db24a0777794c1a752311ceca1093d2f4c7741e2ae8eb48ab4081709ddd76283` |
| SHA3-384 | `8c04f5eeb19b111c493f4121271d1f7947849cfc9853f11872bee9d1928b3ffd83e0a0af64faa293921db2064386f731` |
| TLSH | `T1847533069668E813FCF35275474DB3E9CAC9701A0ED05AAB4DB542208D5FFD84D2CDBA` |
| SSDEEP | `24576:Nw5T8ED+6QnwqFzUAa65wuwDxtr38a5CcX7ZqIVU3JG6d/iLyPz1P9J39L+4aVJQ:2IEq6QnwMzLcv3p5CWAIW3Fd6u9n3VT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_db24a077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db24a0777794c1a752311ceca1093d2f4c7741e2ae8eb48ab4081709ddd76283"
    family = "unknown"
    file_name = "nova-client.com"
    file_type = "zip"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "db24a0777794c1a752311ceca1093d2f4c7741e2ae8eb48ab4081709ddd76283"
}
```

### Sample 86: `5ad2b6ecb9c4c379`

| Field | Value |
|---|---|
| SHA-256 | `5ad2b6ecb9c4c37973b7e2b93e5569c364fb2418526a3b516f8a45552e82bd2f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 03:06:40` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd1c661978c4b5e5cbed65ebf02ffaff` |
| SHA-1 | `7e6856efe2b00b1df3b73761d613ef033113b324` |
| SHA-256 | `5ad2b6ecb9c4c37973b7e2b93e5569c364fb2418526a3b516f8a45552e82bd2f` |
| SHA3-384 | `fb8e5bedaa0b3bcf6b359c2eda0c9e1eb9a672d0828fce4fd995660b49ce66ddc0ba5fa37770f77fd562eaa9f0c8dc3d` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T14887E007FAA550E8C099D63486A78362BA717C4D8B3173DB2F90B7342F76BD06A79710` |
| SSDEEP | `393216:s8bxdqrmazI3wT93uC+NE+dI13bWDQZ8fyIUMB4wAwD8V3vlUc9Y7t8sX/kp0mss:s8bxgT93ENExCDYHm+wAwG9lYaRpN9` |
| ICON-DHASH | `f0f0b2caccc8e070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_5ad2b6ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ad2b6ecb9c4c37973b7e2b93e5569c364fb2418526a3b516f8a45552e82bd2f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:06:40"
  condition:
    hash.sha256(0, filesize) == "5ad2b6ecb9c4c37973b7e2b93e5569c364fb2418526a3b516f8a45552e82bd2f"
}
```

### Sample 87: `d27ab58afdb712fb`

| Field | Value |
|---|---|
| SHA-256 | `d27ab58afdb712fbb2541633a2fbb370aa3bfdc956c5bc1be7db58325af5deb3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 03:02:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a464fb5ad62067bb2267d81969fd0f1` |
| SHA-1 | `9b81f887433f4b6a34c3778d390c512a65901159` |
| SHA-256 | `d27ab58afdb712fbb2541633a2fbb370aa3bfdc956c5bc1be7db58325af5deb3` |
| SHA3-384 | `d5af95b3dc2849855eee5aeda132a5694c246f520ca54b11c82c8635cd14be0e8e010c7fc51e4e452d351373871e7814` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F962D89AD8926F9DDE4F80707B12F8387D7176A0967659E3D7828C309EA39D10024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UPDBgn:fKOe2/7c9sN3zfZR1m+RG06C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_d27ab58a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d27ab58afdb712fbb2541633a2fbb370aa3bfdc956c5bc1be7db58325af5deb3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:02:30"
  condition:
    hash.sha256(0, filesize) == "d27ab58afdb712fbb2541633a2fbb370aa3bfdc956c5bc1be7db58325af5deb3"
}
```

### Sample 88: `d1595e71990f6e3a`

| Field | Value |
|---|---|
| SHA-256 | `d1595e71990f6e3ae10a352ffc3162262f76bd3430a5e662fc91b66ab1c61fb9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 02:59:51` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d194f2287d092c98e887217c10914b86` |
| SHA-1 | `bec844eecfaf76d01a6579d8e4fff698fdc6fff4` |
| SHA-256 | `d1595e71990f6e3ae10a352ffc3162262f76bd3430a5e662fc91b66ab1c61fb9` |
| SHA3-384 | `6e71f9e5f1c7834da43c1f8c015ea6e44aefa9796d60b01a0bd4a47eb1f3f4d744f5e2bd0b54eef7154ceb62c07434eb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11562D5C6D9A22F5DCE4EC0B03A51F978BD7536948665A9E3D7C28C304DA79D00824FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UkaWlR:fKOe2/7c9sN3zfZR1m+RGG4w6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_d1595e71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1595e71990f6e3ae10a352ffc3162262f76bd3430a5e662fc91b66ab1c61fb9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:59:51"
  condition:
    hash.sha256(0, filesize) == "d1595e71990f6e3ae10a352ffc3162262f76bd3430a5e662fc91b66ab1c61fb9"
}
```

### Sample 89: `fe41e284a1d4d5d6`

| Field | Value |
|---|---|
| SHA-256 | `fe41e284a1d4d5d6c94f3d300f7cfff194444221c3c817360b501af9c0aceb4d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 02:57:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61a27323e95d3128359e88d49d62d181` |
| SHA-1 | `cb8609ec2d35dc1764e6b8659202e59d84c854df` |
| SHA-256 | `fe41e284a1d4d5d6c94f3d300f7cfff194444221c3c817360b501af9c0aceb4d` |
| SHA3-384 | `610008ea19e04564ca486318ee225a15a7adaf4d93a885978753788a58e5e6fef8ef2885c0323a290dd79752b39eefca` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15962C696D9921F6DCE4E90703A11F838BD7532948A259DF7D7828C345AB39D10434EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uq+NVe:fKOe2/7c9sN3zfZR1m+RGhQ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_fe41e284
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe41e284a1d4d5d6c94f3d300f7cfff194444221c3c817360b501af9c0aceb4d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:57:30"
  condition:
    hash.sha256(0, filesize) == "fe41e284a1d4d5d6c94f3d300f7cfff194444221c3c817360b501af9c0aceb4d"
}
```

### Sample 90: `e358897a56de14a3`

| Field | Value |
|---|---|
| SHA-256 | `e358897a56de14a377ddd09447a6e603605b978c836be8f9243d401c5a9430ad` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 02:57:23` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3b381ab828d176a22dcaf6ad67da507` |
| SHA-1 | `33195029e5c310230f6f531dadd7d8c4278a6d9c` |
| SHA-256 | `e358897a56de14a377ddd09447a6e603605b978c836be8f9243d401c5a9430ad` |
| SHA3-384 | `272f06157aae8fd49b5068fd4c015b9f286a1017f222c44971e2d17674f5663ba5b1f7da3164489ebe70fc410efab45e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17D62E786E8A25F5CCE4F80707B51F938BD74369886A55CE3DB828C385EA39D01124EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJqpTe:fKOe2/7c9sN3zfZR1m+RGUa6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_e358897a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e358897a56de14a377ddd09447a6e603605b978c836be8f9243d401c5a9430ad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:57:23"
  condition:
    hash.sha256(0, filesize) == "e358897a56de14a377ddd09447a6e603605b978c836be8f9243d401c5a9430ad"
}
```

### Sample 91: `738b948f3c355ec7`

| Field | Value |
|---|---|
| SHA-256 | `738b948f3c355ec72859c927b57b12502f6acfd21dbd7ca03bc6ce16a71b11b8` |
| Family label | `unknown` |
| File name | `Reaper.exe` |
| File type | `exe` |
| First seen | `2026-09-16 02:57:05` |
| Reporter | `Parper` |
| Tags | `exe, salatstealer, sfx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44d70778cd4ea56779d2243db5fbebb8` |
| SHA-1 | `d96c4f4d9e9ac2ffd109618f3bddf72d0b3e800b` |
| SHA-256 | `738b948f3c355ec72859c927b57b12502f6acfd21dbd7ca03bc6ce16a71b11b8` |
| SHA3-384 | `28f58148e46d96d57e35920542b092cc9856d294abfc71cd731ea90fd8673c4ae63bd4091cb821130e283c046ff1fd86` |
| IMPHASH | `7c75a83e117d2bdfb2814c53e840c172` |
| TLSH | `T179162319E3A804FAD1B7D174CE928906E7727C4A47B1EA8F03A495691F372948D3EF13` |
| SSDEEP | `98304:6vOyuW8e92s2YWrcWqHz8Hv7XWqdM+XoOXmu1wWVo5Q++2Ia:py5r8sSrc3HgDXWu7oHu1wWun` |
| ICON-DHASH | `51404cc47561690b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_738b948f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "738b948f3c355ec72859c927b57b12502f6acfd21dbd7ca03bc6ce16a71b11b8"
    family = "unknown"
    file_name = "Reaper.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:57:05"
  condition:
    hash.sha256(0, filesize) == "738b948f3c355ec72859c927b57b12502f6acfd21dbd7ca03bc6ce16a71b11b8"
}
```

### Sample 92: `d84ba5e8c55a04d9`

| Field | Value |
|---|---|
| SHA-256 | `d84ba5e8c55a04d98438daee5293598a6aa91ea3a074c494f253c00a6005a526` |
| Family label | `SalatStealer` |
| File name | `Reaper.exe` |
| File type | `exe` |
| First seen | `2026-09-16 02:55:02` |
| Reporter | `Parper` |
| Tags | `exe, salatstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab8d2c661b74af22085bfe4676d5eef5` |
| SHA-1 | `69395cac59855e986a4bebf68114c6bc6d0ceb14` |
| SHA-256 | `d84ba5e8c55a04d98438daee5293598a6aa91ea3a074c494f253c00a6005a526` |
| SHA3-384 | `a9d24f1e16e5419a196025e4331e3b972b32fd88307a530f2a31cc3f8e7c18ff4e1caac56e027c4978cd4ba5032891b6` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15306335B18A04C67C7CC9774B7D1A5E6128894BEBF03E64DD2C84E7897B398FD362620` |
| SSDEEP | `98304:q4IrAqo/KP/XLRpZWg2YhziY/CJUitJNy9tdHzrUPR:q4IrAvsjZWGhWxyYWtdHzrUP` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_092_d84ba5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d84ba5e8c55a04d98438daee5293598a6aa91ea3a074c494f253c00a6005a526"
    family = "SalatStealer"
    file_name = "Reaper.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:55:02"
  condition:
    hash.sha256(0, filesize) == "d84ba5e8c55a04d98438daee5293598a6aa91ea3a074c494f253c00a6005a526"
}
```

### Sample 93: `5b5e88ebad4d2c8d`

| Field | Value |
|---|---|
| SHA-256 | `5b5e88ebad4d2c8d211a3e6d7e651446ea4f38330d66d1357713e69c37192ec0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-16 02:54:48` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `290fa9826c94b547eac68374339279b7` |
| SHA-1 | `2c197694165467837c6b8818d96e3350c4e2fc75` |
| SHA-256 | `5b5e88ebad4d2c8d211a3e6d7e651446ea4f38330d66d1357713e69c37192ec0` |
| SHA3-384 | `ea7a42e0d4dd5f4882cfd936de9603a7694df07086c5a63ec40b58378ccbf7d031aa7ae7a4493069570fd09ef81099d4` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F662E786E9E22F5CCE4E90703A51F9787D7576E0CA2559E3D7828C349DA39D40024FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1rBgn:fKOe2/7c9sN3zfZR1m+RG26C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_5b5e88eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5e88ebad4d2c8d211a3e6d7e651446ea4f38330d66d1357713e69c37192ec0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:54:48"
  condition:
    hash.sha256(0, filesize) == "5b5e88ebad4d2c8d211a3e6d7e651446ea4f38330d66d1357713e69c37192ec0"
}
```

### Sample 94: `cf4cd52d002d27e0`

| Field | Value |
|---|---|
| SHA-256 | `cf4cd52d002d27e0aa092906be199dd017d26ad39c81c292c4016b2f37f15709` |
| Family label | `unknown` |
| File name | `XOR_Loader.exe` |
| File type | `exe` |
| First seen | `2026-09-16 02:52:24` |
| Reporter | `UnknownSilicon` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e414ca6349b287c624d963a4d91f335d` |
| SHA-1 | `4672ae624f08ae6db7d29ea94d7df7949013764e` |
| SHA-256 | `cf4cd52d002d27e0aa092906be199dd017d26ad39c81c292c4016b2f37f15709` |
| SHA3-384 | `d162a073bb73ddb2b197530b1c42f033cde425d945d826e4aad9185f5e49c26c43e7f0aaa69899b1ff0819070a7e0ccf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D9456F34BF7141C1A59ACCD2572276CBC97E13A99F8DBD36A47E8DA25C86C025F2E0C4` |
| SSDEEP | `24576:5xqiI1wxrUfGNE2cZ0ciSd28zaJtvGe6QmELQv:zqTCxr0A9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_cf4cd52d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf4cd52d002d27e0aa092906be199dd017d26ad39c81c292c4016b2f37f15709"
    family = "unknown"
    file_name = "XOR_Loader.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:52:24"
  condition:
    hash.sha256(0, filesize) == "cf4cd52d002d27e0aa092906be199dd017d26ad39c81c292c4016b2f37f15709"
}
```

### Sample 95: `463197e44988b401`

| Field | Value |
|---|---|
| SHA-256 | `463197e44988b401501816cf53a42212f4dabb6838272e4641cf03761772f061` |
| Family label | `unknown` |
| File name | `verification.vrf` |
| File type | `unknown` |
| First seen | `2026-09-16 02:51:08` |
| Reporter | `UnknownSilicon` |
| Tags | `ClickFix, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b4f67490f9f62a3c466ef5505179ac6` |
| SHA-256 | `463197e44988b401501816cf53a42212f4dabb6838272e4641cf03761772f061` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_463197e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "463197e44988b401501816cf53a42212f4dabb6838272e4641cf03761772f061"
    family = "unknown"
    file_name = "verification.vrf"
    file_type = "unknown"
    first_seen = "2026-09-16 02:51:08"
  condition:
    hash.sha256(0, filesize) == "463197e44988b401501816cf53a42212f4dabb6838272e4641cf03761772f061"
}
```

### Sample 96: `fa94b56d08e1c84d`

| Field | Value |
|---|---|
| SHA-256 | `fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66` |
| Family label | `Prometei` |
| File name | `fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66` |
| File type | `elf` |
| First seen | `2026-09-16 02:48:48` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `354ed7d98d3f6a08ce7aae0039ec30c7` |
| SHA-1 | `0f8b4c3e8827a2dc1ad2de6e00b1f90e2eab788e` |
| SHA-256 | `fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66` |
| SHA3-384 | `6ad2fff1a5a0187370566b6e442173d50a865e4ba462de36bffe231d858dcf945269ba5e8de3eed568fad31be6cc24db` |
| TLSH | `T148A423B4F9229E8F6DD769F91B24831DE181C172589D4C2313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsd2:Fs6pyCC/Ya2hpi6T6N4o` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_096_fa94b56d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66"
    family = "Prometei"
    file_name = "fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66"
    file_type = "elf"
    first_seen = "2026-09-16 02:48:48"
  condition:
    hash.sha256(0, filesize) == "fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66"
}
```

### Sample 97: `04083e86516480b1`

| Field | Value |
|---|---|
| SHA-256 | `04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284` |
| Family label | `Prometei` |
| File name | `04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284` |
| File type | `exe` |
| First seen | `2026-09-16 02:48:40` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d71f7596689493316b69de720467dfa1` |
| SHA-1 | `e3b83fe9a0f46688d82517b09ca237c3394b98b2` |
| SHA-256 | `04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284` |
| SHA3-384 | `b8f3aaadbe3c65cd85dd6e4cb6d6a5f0fc22f6482a50e1b0b29c3dc86b25c8e68b2b3b94c78971f311e9775d983c626d` |
| IMPHASH | `899ad1596f9c6642245b3fb721bae585` |
| TLSH | `T17C34BE63A4BCAA9FDDD82F379C4E880713B66FE4D890603E1C44710EFE2A5085F7A516` |
| SSDEEP | `6144:4GxCfPf0s3KPHfBxR8jPs1F1yD9jvryfL9SqXVdO8:4G60BpL8jk1FGjDc8GVdO8` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_097_04083e86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284"
    family = "Prometei"
    file_name = "04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284"
    file_type = "exe"
    first_seen = "2026-09-16 02:48:40"
  condition:
    hash.sha256(0, filesize) == "04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284"
}
```

### Sample 98: `5a5accc2b9388ce1`

| Field | Value |
|---|---|
| SHA-256 | `5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714` |
| Family label | `Prometei` |
| File name | `5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714` |
| File type | `elf` |
| First seen | `2026-09-16 02:45:48` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a05a334efa5951cb994919562c3c38a9` |
| SHA-1 | `be36ddba8c7db22b449747846cd93c713d67dc00` |
| SHA-256 | `5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714` |
| SHA3-384 | `f7fda484ac92bc4facf1dd25fa4012850880514f6249511798df6d7f4bb2d87a637b726c3ddf0bc81cdab09aa2194494` |
| TLSH | `T1BCA423B4F9219E9F6DD769B91B24831DE081D172589D4C2313AE94A34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdQ:Fs6pyCC/Ya2hpi6T6N4+` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_098_5a5accc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714"
    family = "Prometei"
    file_name = "5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714"
    file_type = "elf"
    first_seen = "2026-09-16 02:45:48"
  condition:
    hash.sha256(0, filesize) == "5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714"
}
```

### Sample 99: `a509a39b456f8b88`

| Field | Value |
|---|---|
| SHA-256 | `a509a39b456f8b881d9b29d6e3cd6ac12d03db3d7da76315ffb894a5b138e684` |
| Family label | `unknown` |
| File name | `NordVPN_Бесплатный.vpn.apk` |
| File type | `apk` |
| First seen | `2026-09-16 02:36:32` |
| Reporter | `Parper` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a40041e424c4960d2ff865dbf3750bbd` |
| SHA-1 | `dd8df2db4d920905ddd94d180a1b428e02adb411` |
| SHA-256 | `a509a39b456f8b881d9b29d6e3cd6ac12d03db3d7da76315ffb894a5b138e684` |
| SHA3-384 | `52c731126d3380d503de719f05a1c9e071d45b0d7ec5046e1bfc87f7dd9b3889e7ad79dc646b2f09191a38683f3abe0c` |
| TLSH | `T14AC61266161D6412E43EAAF7199707D2E3A46E064F43921B71F4B0A47FB32D18B43FA3` |
| SSDEEP | `196608:MHWLB2FFPwAsIGKNKP2C6ENBvvmplZfJP0Qlr4daxxbBZksFaVO:M2LkD4AsIGqPDENBv+df9Br7bJwI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_a509a39b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a509a39b456f8b881d9b29d6e3cd6ac12d03db3d7da76315ffb894a5b138e684"
    family = "unknown"
    file_name = "NordVPN_Бесплатный.vpn.apk"
    file_type = "apk"
    first_seen = "2026-09-16 02:36:32"
  condition:
    hash.sha256(0, filesize) == "a509a39b456f8b881d9b29d6e3cd6ac12d03db3d7da76315ffb894a5b138e684"
}
```

### Sample 100: `2ac4170194086de1`

| Field | Value |
|---|---|
| SHA-256 | `2ac4170194086de1762c0cbcee3a32a8188ec7bbcd0149f8ef013c7c4e061cde` |
| Family label | `DCRat` |
| File name | `3D3CD76AF796D40252459D4D8C75B37D.exe` |
| File type | `exe` |
| First seen | `2026-09-16 02:30:09` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d3cd76af796d40252459d4d8c75b37d` |
| SHA-1 | `d11d1ee28bc214e2507ef06de6db7bc1363f8c8f` |
| SHA-256 | `2ac4170194086de1762c0cbcee3a32a8188ec7bbcd0149f8ef013c7c4e061cde` |
| SHA3-384 | `8155007e0e8f090567218abea8eb488ef4396280d6cbb2277c7e0dc4a5b7bba842f064bae62a41fe204a317ac3831b28` |
| IMPHASH | `fcf1390e9ce472c7270447fc5c61a0c1` |
| TLSH | `T141454A017E84CE12F0191633C2EF854447F4AC91AAA6E72B7EB9376D55123A37C1DACB` |
| SSDEEP | `24576:U2G/nvxW3Ww0t2T9vCH+0txifxA91IPt52GO:UbA302TgHrtSv2Z` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_100_2ac41701
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ac4170194086de1762c0cbcee3a32a8188ec7bbcd0149f8ef013c7c4e061cde"
    family = "DCRat"
    file_name = "3D3CD76AF796D40252459D4D8C75B37D.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:30:09"
  condition:
    hash.sha256(0, filesize) == "2ac4170194086de1762c0cbcee3a32a8188ec7bbcd0149f8ef013c7c4e061cde"
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
 * Generated: 2026-09-16T04:56:59.714310+00:00
 */

rule MalwareBazaar_JOMANGY_001_1ee2daaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ee2daaa9ecbaa6e3aab81af477fbe16994a1341b1c96d9f42ddf8ef48d54df7"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 04:51:27"
  condition:
    hash.sha256(0, filesize) == "1ee2daaa9ecbaa6e3aab81af477fbe16994a1341b1c96d9f42ddf8ef48d54df7"
}

rule MalwareBazaar_unknown_002_ea5f5e52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5f5e52235e221d109e16450e58ff10d00609a874982b453db1cf02d06206a6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:46:51"
  condition:
    hash.sha256(0, filesize) == "ea5f5e52235e221d109e16450e58ff10d00609a874982b453db1cf02d06206a6"
}

rule MalwareBazaar_unknown_003_fbe0353b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbe0353b68f7ea8e9143053136dfb40247ebf872fc7e417e739bba263b83ae46"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:44:24"
  condition:
    hash.sha256(0, filesize) == "fbe0353b68f7ea8e9143053136dfb40247ebf872fc7e417e739bba263b83ae46"
}

rule MalwareBazaar_unknown_004_9f5dea15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f5dea15c550e6d4a0f3585aadd780bdbc426aec230bf2bb2760fc955f798b28"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:41:57"
  condition:
    hash.sha256(0, filesize) == "9f5dea15c550e6d4a0f3585aadd780bdbc426aec230bf2bb2760fc955f798b28"
}

rule MalwareBazaar_Gafgyt_005_6aea9105
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6aea9105f7c096dd08f3d7920af28709e437ef99aff5b5c5683e490b03f0157d"
    family = "Gafgyt"
    file_name = "m-p.s-l.Sakura"
    file_type = "elf"
    first_seen = "2026-09-16 04:39:31"
  condition:
    hash.sha256(0, filesize) == "6aea9105f7c096dd08f3d7920af28709e437ef99aff5b5c5683e490b03f0157d"
}

rule MalwareBazaar_Gafgyt_006_7009f20d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7009f20d73246b68de875da4082be8ea96bcdbdc0a32e21459cdd5847b094c18"
    family = "Gafgyt"
    file_name = "a-r.m-7.Sakura"
    file_type = "elf"
    first_seen = "2026-09-16 04:30:38"
  condition:
    hash.sha256(0, filesize) == "7009f20d73246b68de875da4082be8ea96bcdbdc0a32e21459cdd5847b094c18"
}

rule MalwareBazaar_Gafgyt_007_65949154
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "659491543493436ba961770938f1ec59a9fdfde6666950f770ac46c03ca987d7"
    family = "Gafgyt"
    file_name = "m-i.p-s.Sakura"
    file_type = "elf"
    first_seen = "2026-09-16 04:29:21"
  condition:
    hash.sha256(0, filesize) == "659491543493436ba961770938f1ec59a9fdfde6666950f770ac46c03ca987d7"
}

rule MalwareBazaar_JOMANGY_008_98faf7bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98faf7bc38c94387e2888389fb1a1178016f4c8179d7a9d91ffeb8e078c09d5e"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-16 04:28:10"
  condition:
    hash.sha256(0, filesize) == "98faf7bc38c94387e2888389fb1a1178016f4c8179d7a9d91ffeb8e078c09d5e"
}

rule MalwareBazaar_WhiteSnakeStealer_009_f0f06d6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0f06d6d0f3bbcafb30dd9fd31bf75974e8f19fbb1f226ecada15720496da9ef"
    family = "WhiteSnakeStealer"
    file_name = "6DBC78E7F56E4D05DBF61E3F205B339D.exe"
    file_type = "exe"
    first_seen = "2026-09-16 04:25:08"
  condition:
    hash.sha256(0, filesize) == "f0f06d6d0f3bbcafb30dd9fd31bf75974e8f19fbb1f226ecada15720496da9ef"
}

rule MalwareBazaar_unknown_010_ff1c5b16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff1c5b16b6c6d6b24683c44b5e0a4249a75352e6187186c755dfa976aeb002c1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:23:55"
  condition:
    hash.sha256(0, filesize) == "ff1c5b16b6c6d6b24683c44b5e0a4249a75352e6187186c755dfa976aeb002c1"
}

rule MalwareBazaar_CoinMiner_011_ce2aacb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce2aacb6e29749d1ca29ac3fb1adcbeb42ffe833e51fe948d3e511d5d1364bc9"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:23:02"
  condition:
    hash.sha256(0, filesize) == "ce2aacb6e29749d1ca29ac3fb1adcbeb42ffe833e51fe948d3e511d5d1364bc9"
}

rule MalwareBazaar_unknown_012_06177c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61"
    family = "unknown"
    file_name = "06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:56"
  condition:
    hash.sha256(0, filesize) == "06177c98ebf264366bec3cf1210477b059ef1b6b3b36d1268ab4bdaab50fee61"
}

rule MalwareBazaar_unknown_013_c68a476c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c"
    family = "unknown"
    file_name = "c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:51"
  condition:
    hash.sha256(0, filesize) == "c68a476c411848a120ce6b4a64a36e5fbaed9f7d8e2166e8d93af244a74a930c"
}

rule MalwareBazaar_unknown_014_2d0daf13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f"
    family = "unknown"
    file_name = "2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:46"
  condition:
    hash.sha256(0, filesize) == "2d0daf1366123b60232fd67f85181a5bacf2e4c6a1346b6ea97adf13b7b9708f"
}

rule MalwareBazaar_unknown_015_64798263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7"
    family = "unknown"
    file_name = "64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:41"
  condition:
    hash.sha256(0, filesize) == "64798263237af5a9dadc07801872bdcadf4e45d93467f1121a6e09cbf2c89ad7"
}

rule MalwareBazaar_unknown_016_e3ed586d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d"
    family = "unknown"
    file_name = "e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d"
    file_type = "sh"
    first_seen = "2026-09-16 04:17:36"
  condition:
    hash.sha256(0, filesize) == "e3ed586dfe5400e89894229bed2b8021af19ebfcf95d5519d857988e6986f36d"
}

rule MalwareBazaar_unknown_017_bc38953e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80"
    family = "unknown"
    file_name = "bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:31"
  condition:
    hash.sha256(0, filesize) == "bc38953ee029ffd9a671f5b1eef633269e14d82d85578f49c0f1616207b4fd80"
}

rule MalwareBazaar_unknown_018_b0fd24c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c"
    family = "unknown"
    file_name = "b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:21"
  condition:
    hash.sha256(0, filesize) == "b0fd24c52d289f83d87dae1bccd84321e5802eb093d5c2a1f5b0217dc5e7373c"
}

rule MalwareBazaar_Mirai_019_29069a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81"
    family = "Mirai"
    file_name = "29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81"
    file_type = "elf"
    first_seen = "2026-09-16 04:17:13"
  condition:
    hash.sha256(0, filesize) == "29069a04f6e197da27f20dab52dc90634b43aac4b57818f7eb65b07876eb1b81"
}

rule MalwareBazaar_unknown_020_3a4eeb02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a4eeb029b28a7f35b9d1e61f97da1967c0f3e0a12560bed4863fa653e37644f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:16:37"
  condition:
    hash.sha256(0, filesize) == "3a4eeb029b28a7f35b9d1e61f97da1967c0f3e0a12560bed4863fa653e37644f"
}

rule MalwareBazaar_WannaCry_021_bc538b10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e"
    family = "WannaCry"
    file_name = "bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e"
    file_type = "exe"
    first_seen = "2026-09-16 04:16:05"
  condition:
    hash.sha256(0, filesize) == "bc538b1020ea91149078a72dee02a74affb9eec6903949664b0a42f7c7d9351e"
}

rule MalwareBazaar_unknown_022_3ead35a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ead35a167eaf27a1cd90b7bbcf50c5d0b771e1128fba43957af8f9be3432fec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:12:49"
  condition:
    hash.sha256(0, filesize) == "3ead35a167eaf27a1cd90b7bbcf50c5d0b771e1128fba43957af8f9be3432fec"
}

rule MalwareBazaar_unknown_023_26990851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "269908515ce7fc8231ec960edeee439d2fe18c30f24344198ae15b4489a23a57"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:11:54"
  condition:
    hash.sha256(0, filesize) == "269908515ce7fc8231ec960edeee439d2fe18c30f24344198ae15b4489a23a57"
}

rule MalwareBazaar_unknown_024_464fdc55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "464fdc550c6ab3347a6b08a79b7a248100e9b567b1672790c6a4554c11400fda"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:11:32"
  condition:
    hash.sha256(0, filesize) == "464fdc550c6ab3347a6b08a79b7a248100e9b567b1672790c6a4554c11400fda"
}

rule MalwareBazaar_unknown_025_70ce4f5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ce4f5a04b7ec7c7d93fddf2da8dd01e7fba6fa72080980dea62062558fb8ea"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:11:16"
  condition:
    hash.sha256(0, filesize) == "70ce4f5a04b7ec7c7d93fddf2da8dd01e7fba6fa72080980dea62062558fb8ea"
}

rule MalwareBazaar_unknown_026_0f2a2c7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f2a2c7d485638885ffdd27963384785b603ee83de635e0fc3fc81897f1826ba"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:10:33"
  condition:
    hash.sha256(0, filesize) == "0f2a2c7d485638885ffdd27963384785b603ee83de635e0fc3fc81897f1826ba"
}

rule MalwareBazaar_unknown_027_07832dd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07832dd100e273842dd772e6d5fc4f83aceb7fc2817b39c7881afee9c542aa8f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:07:57"
  condition:
    hash.sha256(0, filesize) == "07832dd100e273842dd772e6d5fc4f83aceb7fc2817b39c7881afee9c542aa8f"
}

rule MalwareBazaar_unknown_028_112d4426
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "112d44269e1485491fe0438b42d0342fc5d9aa6367f4518623950ec00d24501e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:06:58"
  condition:
    hash.sha256(0, filesize) == "112d44269e1485491fe0438b42d0342fc5d9aa6367f4518623950ec00d24501e"
}

rule MalwareBazaar_unknown_029_54ba2d82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54ba2d82569000f12ce7283695de00eee6e8c7298e8020fa524d4d2ec1455bcb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:05:01"
  condition:
    hash.sha256(0, filesize) == "54ba2d82569000f12ce7283695de00eee6e8c7298e8020fa524d4d2ec1455bcb"
}

rule MalwareBazaar_unknown_030_d1556099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d155609910ab006c5167b5883036c94f459bb7450c34854009ae88e1507d2e54"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-09-16 04:04:27"
  condition:
    hash.sha256(0, filesize) == "d155609910ab006c5167b5883036c94f459bb7450c34854009ae88e1507d2e54"
}

rule MalwareBazaar_unknown_031_d99d2e6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d99d2e6fbd1b43d335107fb68b5a5e8e34e8634dcd2ef57dbecc9dda2c6eac00"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 04:02:45"
  condition:
    hash.sha256(0, filesize) == "d99d2e6fbd1b43d335107fb68b5a5e8e34e8634dcd2ef57dbecc9dda2c6eac00"
}

rule MalwareBazaar_Mirai_032_367206fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "367206fbf4b5afc8d3ec80542014a2b40b0888cbd37d065d3fab42fa165e8772"
    family = "Mirai"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-09-16 03:52:11"
  condition:
    hash.sha256(0, filesize) == "367206fbf4b5afc8d3ec80542014a2b40b0888cbd37d065d3fab42fa165e8772"
}

rule MalwareBazaar_JOMANGY_033_bd855a59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd855a59448334d3c9ec15ac534478a4f808c93ea424ea7627f318fdb1b7064b"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-16 03:46:35"
  condition:
    hash.sha256(0, filesize) == "bd855a59448334d3c9ec15ac534478a4f808c93ea424ea7627f318fdb1b7064b"
}

rule MalwareBazaar_unknown_034_8cd11b6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8cd11b6e3504363d2818cfa541698af18f80be3552e038dfa9369c0ba28c6817"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-09-16 03:44:10"
  condition:
    hash.sha256(0, filesize) == "8cd11b6e3504363d2818cfa541698af18f80be3552e038dfa9369c0ba28c6817"
}

rule MalwareBazaar_unknown_035_97609784
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97609784e7ac040fcad2e0e3dc139c024d8dfc27720ef35c686aab8f21eedd7f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:33:52"
  condition:
    hash.sha256(0, filesize) == "97609784e7ac040fcad2e0e3dc139c024d8dfc27720ef35c686aab8f21eedd7f"
}

rule MalwareBazaar_unknown_036_5d0320d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d0320d2437bd0cf992de5b75420ad0a67c3191c3b38ce14bc9cf09195863d25"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:27:45"
  condition:
    hash.sha256(0, filesize) == "5d0320d2437bd0cf992de5b75420ad0a67c3191c3b38ce14bc9cf09195863d25"
}

rule MalwareBazaar_unknown_037_2aa16ffb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576"
    family = "unknown"
    file_name = "2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:47"
  condition:
    hash.sha256(0, filesize) == "2aa16ffb145e1ad6a8972908f7abb035fc1982855d64a3cf843fd4dff6186576"
}

rule MalwareBazaar_unknown_038_cfa99a41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752"
    family = "unknown"
    file_name = "cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:42"
  condition:
    hash.sha256(0, filesize) == "cfa99a415781c0e1748d2b679043c9ada2f9555d584f76fdfcd77aea88a01752"
}

rule MalwareBazaar_unknown_039_d0e536be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b"
    family = "unknown"
    file_name = "d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:36"
  condition:
    hash.sha256(0, filesize) == "d0e536befdd826a33b7b99edc33722ea82f4b9a57458913886d74333fc909d3b"
}

rule MalwareBazaar_unknown_040_649b488b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e"
    family = "unknown"
    file_name = "649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:30"
  condition:
    hash.sha256(0, filesize) == "649b488b6795b6782cc6c3c03dd22b06dd173a21d5d4b046eed69743926a2b6e"
}

rule MalwareBazaar_unknown_041_1732d66f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528"
    family = "unknown"
    file_name = "1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:25"
  condition:
    hash.sha256(0, filesize) == "1732d66f3b55d5b9a9e781efe6b39b9731e898da167b1836e907255d8dfe7528"
}

rule MalwareBazaar_unknown_042_58fdbdeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7"
    family = "unknown"
    file_name = "58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:18"
  condition:
    hash.sha256(0, filesize) == "58fdbdebf0ca685eed602974d06031cb0b0d2e0c06790cfb480061b5d6f487d7"
}

rule MalwareBazaar_unknown_043_011c23f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7"
    family = "unknown"
    file_name = "011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7"
    file_type = "elf"
    first_seen = "2026-09-16 03:17:12"
  condition:
    hash.sha256(0, filesize) == "011c23f8bf233f70affd121dddcda4194ad006810197c27d022d6fc41e7d84d7"
}

rule MalwareBazaar_unknown_044_5b1aabf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b1aabf210d20620bf21330a5c79ac36fcc176cea9daa7aafb420150432d76b3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:10:30"
  condition:
    hash.sha256(0, filesize) == "5b1aabf210d20620bf21330a5c79ac36fcc176cea9daa7aafb420150432d76b3"
}

rule MalwareBazaar_unknown_045_4c1d79b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c1d79b6a5ad9f9fda5f2b66bddb1548608735ddb031708a390a666ca682a10f"
    family = "unknown"
    file_name = "phantom-client.com--Phantom-Client-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "4c1d79b6a5ad9f9fda5f2b66bddb1548608735ddb031708a390a666ca682a10f"
}

rule MalwareBazaar_unknown_046_4ce241a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ce241a22d4710c361c341615c7a4fc320ca4904b23589d8713a885f1630404c"
    family = "unknown"
    file_name = "polarclient.net--PolarClient-Cracked-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "4ce241a22d4710c361c341615c7a4fc320ca4904b23589d8713a885f1630404c"
}

rule MalwareBazaar_unknown_047_508f34ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "508f34ffb12c141327461f8ef92507dbf1c50bf764349264de32fe60fbea9dbc"
    family = "unknown"
    file_name = "skyblock-addons.com--SkyblockAddons-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "508f34ffb12c141327461f8ef92507dbf1c50bf764349264de32fe60fbea9dbc"
}

rule MalwareBazaar_unknown_048_ce494dcd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce494dcd20e05f1643ef9b6ee72dd3b6ed44c21e58cf484ee3f35e08eb9734c8"
    family = "unknown"
    file_name = "oringo-client.com--Origo-Client-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "ce494dcd20e05f1643ef9b6ee72dd3b6ed44c21e58cf484ee3f35e08eb9734c8"
}

rule MalwareBazaar_unknown_049_ba638d29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba638d2944cfe4f691eaecf2265010870b7d93b671b9ebb48677e46948246ecb"
    family = "unknown"
    file_name = "skyblock-extras.org--SkyblockExtras-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "ba638d2944cfe4f691eaecf2265010870b7d93b671b9ebb48677e46948246ecb"
}

rule MalwareBazaar_unknown_050_7b1e5ad1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b1e5ad1fe1823b131f8fcba9c5f1f891fbc22870d6e45ebbd5427a344971979"
    family = "unknown"
    file_name = "wielixclient.net--WielixClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "7b1e5ad1fe1823b131f8fcba9c5f1f891fbc22870d6e45ebbd5427a344971979"
}

rule MalwareBazaar_unknown_051_2f6e5ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f6e5ac329d1cd564968a325b6a55024be4a9806ad2186bb7c2d6860d9bed792"
    family = "unknown"
    file_name = "sigmaclient.org--SigmaClient-Fabric-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "2f6e5ac329d1cd564968a325b6a55024be4a9806ad2186bb7c2d6860d9bed792"
}

rule MalwareBazaar_unknown_052_2f63edf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f63edf9c20d73454e0afbb04392c969e4b3e5c7bc227f80306b403758cd40cf"
    family = "unknown"
    file_name = "prestige-client.org--PrestigeLoader-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:10:28"
  condition:
    hash.sha256(0, filesize) == "2f63edf9c20d73454e0afbb04392c969e4b3e5c7bc227f80306b403758cd40cf"
}

rule MalwareBazaar_unknown_053_4b253880
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b253880629b092f2c8d6ba9d53312d217320ecbea07e67324ea43538cade724"
    family = "unknown"
    file_name = "odinclient.com--OdinClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "4b253880629b092f2c8d6ba9d53312d217320ecbea07e67324ea43538cade724"
}

rule MalwareBazaar_unknown_054_29fcdb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29fcdb33c14d1b13b8cefba9858a44451b319c4b69a7d5ac1fddc117bbbdf28f"
    family = "unknown"
    file_name = "odinmod.org--OdinMod-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "29fcdb33c14d1b13b8cefba9858a44451b319c4b69a7d5ac1fddc117bbbdf28f"
}

rule MalwareBazaar_unknown_055_bfcccab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfcccab190bbf4be5dac3bdaaa4db3cf609880fe4622cd08d12e21b417cf4609"
    family = "unknown"
    file_name = "noamaddons.com--NoamAddons-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "bfcccab190bbf4be5dac3bdaaa4db3cf609880fe4622cd08d12e21b417cf4609"
}

rule MalwareBazaar_unknown_056_64901e69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64901e69330332fa5ad9b94c148eceab8bec9d3ae2c6282a27b69297fb1d3093"
    family = "unknown"
    file_name = "gamblerigmod.org--gamble-rig-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "64901e69330332fa5ad9b94c148eceab8bec9d3ae2c6282a27b69297fb1d3093"
}

rule MalwareBazaar_unknown_057_f96bed16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f96bed16099b7fc1d010dfb44d8871e6652fe1ae2c296ce9d6e1ce7eaa74b793"
    family = "unknown"
    file_name = "luminexclient.net--luminex-client-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "f96bed16099b7fc1d010dfb44d8871e6652fe1ae2c296ce9d6e1ce7eaa74b793"
}

rule MalwareBazaar_unknown_058_25506090
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25506090219f37a63d69d6d0acd1688b4d639576a14e84fea71c75b0559989ed"
    family = "unknown"
    file_name = "marlowclient.com--MarlowClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "25506090219f37a63d69d6d0acd1688b4d639576a14e84fea71c75b0559989ed"
}

rule MalwareBazaar_unknown_059_b6a1855f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a1855faf4e23f9967192dcd6dfd2cf022c9b9f8ab5061edfc28a442b3e5c36"
    family = "unknown"
    file_name = "ghostclient.net--GhostClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "b6a1855faf4e23f9967192dcd6dfd2cf022c9b9f8ab5061edfc28a442b3e5c36"
}

rule MalwareBazaar_unknown_060_bb2d4fc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb2d4fc7484862e764b4a9746a47bc1a56b20989a8cc09fff2a3bd5f5ed787d0"
    family = "unknown"
    file_name = "modhider.com--ModHider-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:09:21"
  condition:
    hash.sha256(0, filesize) == "bb2d4fc7484862e764b4a9746a47bc1a56b20989a8cc09fff2a3bd5f5ed787d0"
}

rule MalwareBazaar_unknown_061_66293b59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66293b59e1e15b309ba0b6f96e32eb0684a427789f869c243e00a68af8586cda"
    family = "unknown"
    file_name = "floppaclient.org--FloppaClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "66293b59e1e15b309ba0b6f96e32eb0684a427789f869c243e00a68af8586cda"
}

rule MalwareBazaar_unknown_062_3ad70d2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ad70d2ec5439d26164ae414cbf8e463e3b129dd80f8dbbbf89084c89565e111"
    family = "unknown"
    file_name = "familyaddons.org--FamilyAddons-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "3ad70d2ec5439d26164ae414cbf8e463e3b129dd80f8dbbbf89084c89565e111"
}

rule MalwareBazaar_unknown_063_41beea5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41beea5b2e98d1ebf8d3b8d8c44f88e20b0fc3e0e86bda759c91c575eb165dc7"
    family = "unknown"
    file_name = "dulkir-mod.com--DulkirMod-Fabric-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "41beea5b2e98d1ebf8d3b8d8c44f88e20b0fc3e0e86bda759c91c575eb165dc7"
}

rule MalwareBazaar_unknown_064_01d540fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01d540fdea0277c61f2c7cf645c30c6dddbbd1488dc8169a2a0f97ea248646f8"
    family = "unknown"
    file_name = "breezeclient.org--BreezeLoader-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "01d540fdea0277c61f2c7cf645c30c6dddbbd1488dc8169a2a0f97ea248646f8"
}

rule MalwareBazaar_unknown_065_1989531b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1989531b67bd8241a68ea58558cd47ae3c6bd6eb2e967a83c0d9e1cb7009833c"
    family = "unknown"
    file_name = "donutclients.net--donut-duper-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "1989531b67bd8241a68ea58558cd47ae3c6bd6eb2e967a83c0d9e1cb7009833c"
}

rule MalwareBazaar_unknown_066_ff0f288e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff0f288e10515106f60afe07cc75495e3be564d27b61e6eb1ccadb139e13021a"
    family = "unknown"
    file_name = "funnymap.net--FunnyMap-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "ff0f288e10515106f60afe07cc75495e3be564d27b61e6eb1ccadb139e13021a"
}

rule MalwareBazaar_unknown_067_fb566280
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb56628064e508d02f82cc7d82cb93d73b9909fcc825dccf4c9e85f269dbddeb"
    family = "unknown"
    file_name = "ahsniper.com--AH-Sniper-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "fb56628064e508d02f82cc7d82cb93d73b9909fcc825dccf4c9e85f269dbddeb"
}

rule MalwareBazaar_unknown_068_efe70913
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efe7091399a8eb31effa1ebd9180fe2a68b7503ea5942a762aaa96b0b19806d0"
    family = "unknown"
    file_name = "cheetoclient.com--CheetoClient-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:49"
  condition:
    hash.sha256(0, filesize) == "efe7091399a8eb31effa1ebd9180fe2a68b7503ea5942a762aaa96b0b19806d0"
}

rule MalwareBazaar_unknown_069_f64ac0fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f64ac0fe19425e3e106e968390c3c87f9dfb55c99e4350ede7f7b6e5d2774a31"
    family = "unknown"
    file_name = "kryptonclient-cracked.com--Krypton-Client-1.21.10-V6.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "f64ac0fe19425e3e106e968390c3c87f9dfb55c99e4350ede7f7b6e5d2774a31"
}

rule MalwareBazaar_unknown_070_62ca0e73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ca0e73f073ef0b279a0fe3d4036bed691958fb0583696b7fd552d5ab57ae25"
    family = "unknown"
    file_name = "polinexclient.org--Polinex-Fabric-1.21.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "62ca0e73f073ef0b279a0fe3d4036bed691958fb0583696b7fd552d5ab57ae25"
}

rule MalwareBazaar_unknown_071_63e5ad0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63e5ad0db844f63d0c45eb5e499a5d771a8185f6c58c7cbef25aae9dc3f15710"
    family = "unknown"
    file_name = "luminexclient.com--luminex-client-1.21.4-beta.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "63e5ad0db844f63d0c45eb5e499a5d771a8185f6c58c7cbef25aae9dc3f15710"
}

rule MalwareBazaar_unknown_072_d9ff0f06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9ff0f06fa6f23b6017cf498c7c0ec15c544e33df75ae145016bab6b9a8fabd4"
    family = "unknown"
    file_name = "wielixclient.com--WielixClient-v2.1.0-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "d9ff0f06fa6f23b6017cf498c7c0ec15c544e33df75ae145016bab6b9a8fabd4"
}

rule MalwareBazaar_unknown_073_72d9dbf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d9dbf486baf38d1d14ecf4afafc8517bb66d340044d4edb29c49fc93daf11c"
    family = "unknown"
    file_name = "sigmaclient.net--SigmaClient-Fabric-1.21.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "72d9dbf486baf38d1d14ecf4afafc8517bb66d340044d4edb29c49fc93daf11c"
}

rule MalwareBazaar_unknown_074_2599c5a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2599c5a6191bc208c4f0f1fcafba81b0f8d4099de6dc8d64ee7aec0b5289833e"
    family = "unknown"
    file_name = "github-mixin-loader-2.5.2-obfuscated.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "2599c5a6191bc208c4f0f1fcafba81b0f8d4099de6dc8d64ee7aec0b5289833e"
}

rule MalwareBazaar_unknown_075_34e8ec18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e8ec188dd68412e743d64ae359529944eb969c8541f21330c81f237dc153b8"
    family = "unknown"
    file_name = "invmove.com--InvMove-Fabric-1.21.11-v0.9.3.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "34e8ec188dd68412e743d64ae359529944eb969c8541f21330c81f237dc153b8"
}

rule MalwareBazaar_unknown_076_33d46e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33d46e4a54c81e5083b2ae4af136a9250c244d0897685526b6669a2ffef3e3d9"
    family = "unknown"
    file_name = "198macros.org--198-Macros-Cracked-26.2.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:08:16"
  condition:
    hash.sha256(0, filesize) == "33d46e4a54c81e5083b2ae4af136a9250c244d0897685526b6669a2ffef3e3d9"
}

rule MalwareBazaar_unknown_077_e76c1140
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e76c1140fad94e7e089e1bb44a3b50657f45e4193848e189c53d566c733f6679"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-16 03:07:56"
  condition:
    hash.sha256(0, filesize) == "e76c1140fad94e7e089e1bb44a3b50657f45e4193848e189c53d566c733f6679"
}

rule MalwareBazaar_unknown_078_e4e71744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4e71744b933a8f4c60ba1935dcb97c8c5f4a5a3865ac836f439ab26c2fd61f4"
    family = "unknown"
    file_name = "debugify.net--Debugify-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "e4e71744b933a8f4c60ba1935dcb97c8c5f4a5a3865ac836f439ab26c2fd61f4"
}

rule MalwareBazaar_unknown_079_ece34342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ece34342d452d1c1046f7ec42b168e66c8e110757983ae91f9b46743665cbe93"
    family = "unknown"
    file_name = "funnymap.org--FunnyMap-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "ece34342d452d1c1046f7ec42b168e66c8e110757983ae91f9b46743665cbe93"
}

rule MalwareBazaar_unknown_080_490bd7f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "490bd7f74ab85cdbfe757047b013debae8e56cc0d959c6f8bfef4e8bac1ed8f9"
    family = "unknown"
    file_name = "22qq-client.com"
    file_type = "zip"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "490bd7f74ab85cdbfe757047b013debae8e56cc0d959c6f8bfef4e8bac1ed8f9"
}

rule MalwareBazaar_unknown_081_a3556c89
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3556c89baa76f4397634b48618a2b42cfc958ac1995c28ec1e03c734637c178"
    family = "unknown"
    file_name = "familyaddons.com--FamilyAddons-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "a3556c89baa76f4397634b48618a2b42cfc958ac1995c28ec1e03c734637c178"
}

rule MalwareBazaar_unknown_082_754f68b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "754f68b4cbf5957a34bbd75ed8aa3fe6091986d2edae145688479de064880c54"
    family = "unknown"
    file_name = "198-macros.com--198-Macros-Cracked-v1.4.0.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "754f68b4cbf5957a34bbd75ed8aa3fe6091986d2edae145688479de064880c54"
}

rule MalwareBazaar_unknown_083_737d649e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "737d649e7e99b68182764de02bf075c49b141d9fd45f0d1cc2c8016b703a2672"
    family = "unknown"
    file_name = "breezeclient.com--BreezeLoader-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "737d649e7e99b68182764de02bf075c49b141d9fd45f0d1cc2c8016b703a2672"
}

rule MalwareBazaar_unknown_084_c574cb33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c574cb33ca8687abf18c11ea73efe61303f8ab1a98910c9e2eaf253bca45a0a9"
    family = "unknown"
    file_name = "floppaclient.com--FloppaClient-1.21.11.jar.jar"
    file_type = "jar"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "c574cb33ca8687abf18c11ea73efe61303f8ab1a98910c9e2eaf253bca45a0a9"
}

rule MalwareBazaar_unknown_085_db24a077
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db24a0777794c1a752311ceca1093d2f4c7741e2ae8eb48ab4081709ddd76283"
    family = "unknown"
    file_name = "nova-client.com"
    file_type = "zip"
    first_seen = "2026-09-16 03:07:42"
  condition:
    hash.sha256(0, filesize) == "db24a0777794c1a752311ceca1093d2f4c7741e2ae8eb48ab4081709ddd76283"
}

rule MalwareBazaar_unknown_086_5ad2b6ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ad2b6ecb9c4c37973b7e2b93e5569c364fb2418526a3b516f8a45552e82bd2f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:06:40"
  condition:
    hash.sha256(0, filesize) == "5ad2b6ecb9c4c37973b7e2b93e5569c364fb2418526a3b516f8a45552e82bd2f"
}

rule MalwareBazaar_unknown_087_d27ab58a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d27ab58afdb712fbb2541633a2fbb370aa3bfdc956c5bc1be7db58325af5deb3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 03:02:30"
  condition:
    hash.sha256(0, filesize) == "d27ab58afdb712fbb2541633a2fbb370aa3bfdc956c5bc1be7db58325af5deb3"
}

rule MalwareBazaar_unknown_088_d1595e71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1595e71990f6e3ae10a352ffc3162262f76bd3430a5e662fc91b66ab1c61fb9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:59:51"
  condition:
    hash.sha256(0, filesize) == "d1595e71990f6e3ae10a352ffc3162262f76bd3430a5e662fc91b66ab1c61fb9"
}

rule MalwareBazaar_unknown_089_fe41e284
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe41e284a1d4d5d6c94f3d300f7cfff194444221c3c817360b501af9c0aceb4d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:57:30"
  condition:
    hash.sha256(0, filesize) == "fe41e284a1d4d5d6c94f3d300f7cfff194444221c3c817360b501af9c0aceb4d"
}

rule MalwareBazaar_unknown_090_e358897a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e358897a56de14a377ddd09447a6e603605b978c836be8f9243d401c5a9430ad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:57:23"
  condition:
    hash.sha256(0, filesize) == "e358897a56de14a377ddd09447a6e603605b978c836be8f9243d401c5a9430ad"
}

rule MalwareBazaar_unknown_091_738b948f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "738b948f3c355ec72859c927b57b12502f6acfd21dbd7ca03bc6ce16a71b11b8"
    family = "unknown"
    file_name = "Reaper.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:57:05"
  condition:
    hash.sha256(0, filesize) == "738b948f3c355ec72859c927b57b12502f6acfd21dbd7ca03bc6ce16a71b11b8"
}

rule MalwareBazaar_SalatStealer_092_d84ba5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d84ba5e8c55a04d98438daee5293598a6aa91ea3a074c494f253c00a6005a526"
    family = "SalatStealer"
    file_name = "Reaper.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:55:02"
  condition:
    hash.sha256(0, filesize) == "d84ba5e8c55a04d98438daee5293598a6aa91ea3a074c494f253c00a6005a526"
}

rule MalwareBazaar_unknown_093_5b5e88eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5e88ebad4d2c8d211a3e6d7e651446ea4f38330d66d1357713e69c37192ec0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-16 02:54:48"
  condition:
    hash.sha256(0, filesize) == "5b5e88ebad4d2c8d211a3e6d7e651446ea4f38330d66d1357713e69c37192ec0"
}

rule MalwareBazaar_unknown_094_cf4cd52d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf4cd52d002d27e0aa092906be199dd017d26ad39c81c292c4016b2f37f15709"
    family = "unknown"
    file_name = "XOR_Loader.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:52:24"
  condition:
    hash.sha256(0, filesize) == "cf4cd52d002d27e0aa092906be199dd017d26ad39c81c292c4016b2f37f15709"
}

rule MalwareBazaar_unknown_095_463197e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "463197e44988b401501816cf53a42212f4dabb6838272e4641cf03761772f061"
    family = "unknown"
    file_name = "verification.vrf"
    file_type = "unknown"
    first_seen = "2026-09-16 02:51:08"
  condition:
    hash.sha256(0, filesize) == "463197e44988b401501816cf53a42212f4dabb6838272e4641cf03761772f061"
}

rule MalwareBazaar_Prometei_096_fa94b56d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66"
    family = "Prometei"
    file_name = "fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66"
    file_type = "elf"
    first_seen = "2026-09-16 02:48:48"
  condition:
    hash.sha256(0, filesize) == "fa94b56d08e1c84d5fa4c56701981267f10fd5c63f1dfaea4f4ab021c1ba4b66"
}

rule MalwareBazaar_Prometei_097_04083e86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284"
    family = "Prometei"
    file_name = "04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284"
    file_type = "exe"
    first_seen = "2026-09-16 02:48:40"
  condition:
    hash.sha256(0, filesize) == "04083e86516480b1d2b6d8d5ce1f4e2158ac172b48dbf915e5f09750cd85e284"
}

rule MalwareBazaar_Prometei_098_5a5accc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714"
    family = "Prometei"
    file_name = "5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714"
    file_type = "elf"
    first_seen = "2026-09-16 02:45:48"
  condition:
    hash.sha256(0, filesize) == "5a5accc2b9388ce107c7f6756cb7ae4e1c63afcd326ec73a1bd471022efe5714"
}

rule MalwareBazaar_unknown_099_a509a39b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a509a39b456f8b881d9b29d6e3cd6ac12d03db3d7da76315ffb894a5b138e684"
    family = "unknown"
    file_name = "NordVPN_Бесплатный.vpn.apk"
    file_type = "apk"
    first_seen = "2026-09-16 02:36:32"
  condition:
    hash.sha256(0, filesize) == "a509a39b456f8b881d9b29d6e3cd6ac12d03db3d7da76315ffb894a5b138e684"
}

rule MalwareBazaar_DCRat_100_2ac41701
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ac4170194086de1762c0cbcee3a32a8188ec7bbcd0149f8ef013c7c4e061cde"
    family = "DCRat"
    file_name = "3D3CD76AF796D40252459D4D8C75B37D.exe"
    file_type = "exe"
    first_seen = "2026-09-16 02:30:09"
  condition:
    hash.sha256(0, filesize) == "2ac4170194086de1762c0cbcee3a32a8188ec7bbcd0149f8ef013c7c4e061cde"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

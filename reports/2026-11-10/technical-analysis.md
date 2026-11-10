# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-10

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 683 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 683 |
| Unique family labels | 6 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 36 |
| unknown | 24 |
| SalatStealer | 23 |
| Snowlight | 11 |
| AgentTesla | 4 |
| CoinMiner | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 58 |
| exe | 32 |
| js | 6 |
| sh | 1 |
| zip | 1 |
| docx | 1 |
| wsf | 1 |

## Per-Sample Analysis

### Sample 1: `5c27a1ac83352bea`

| Field | Value |
|---|---|
| SHA-256 | `5c27a1ac83352bea46340240aa313262668468acf2e9f8f416a88060865e6fd1` |
| Family label | `unknown` |
| File name | `4feb056b9600f66e.bin` |
| File type | `exe` |
| First seen | `2026-11-10 07:25:20` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `677af44b18bcc28cfba78ad9a4187126` |
| SHA-1 | `0324feb5d1fcb621b4e9dda7b41e704ac8372ff8` |
| SHA-256 | `5c27a1ac83352bea46340240aa313262668468acf2e9f8f416a88060865e6fd1` |
| SHA3-384 | `eb1590ad337772653f9fdbe1a296f3153ed4bbff081a2f24c84b4e127efa199b6bd24cc722958a5d5cd728bbe0774336` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T198C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+d:yBkKr5rszpNDy+d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_5c27a1ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c27a1ac83352bea46340240aa313262668468acf2e9f8f416a88060865e6fd1"
    family = "unknown"
    file_name = "4feb056b9600f66e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 07:25:20"
  condition:
    hash.sha256(0, filesize) == "5c27a1ac83352bea46340240aa313262668468acf2e9f8f416a88060865e6fd1"
}
```

### Sample 2: `4feb056b9600f66e`

| Field | Value |
|---|---|
| SHA-256 | `4feb056b9600f66e6c588f3246936d6d97fefc1d1fa94f6e5bfd2f6a30b81d6b` |
| Family label | `SalatStealer` |
| File name | `4feb056b9600f66e.bin` |
| File type | `exe` |
| First seen | `2026-11-10 07:24:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb8b4c4276fbcc55a8691a451f9ceedf` |
| SHA-1 | `2df935eb82e1174ba7ad5c194ea2d18d55709881` |
| SHA-256 | `4feb056b9600f66e6c588f3246936d6d97fefc1d1fa94f6e5bfd2f6a30b81d6b` |
| SHA3-384 | `8aca539ba6950037a68ea3aab2f85cddfc7194cbc83841828c8b60a27bbc253ba21108d215b615eac02ddd2cf1c459e6` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1BBF5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Op:iJiafuIO7rhWEES4y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_002_4feb056b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4feb056b9600f66e6c588f3246936d6d97fefc1d1fa94f6e5bfd2f6a30b81d6b"
    family = "SalatStealer"
    file_name = "4feb056b9600f66e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 07:24:49"
  condition:
    hash.sha256(0, filesize) == "4feb056b9600f66e6c588f3246936d6d97fefc1d1fa94f6e5bfd2f6a30b81d6b"
}
```

### Sample 3: `889579cea9714361`

| Field | Value |
|---|---|
| SHA-256 | `889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed` |
| Family label | `unknown` |
| File name | `889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed` |
| File type | `sh` |
| First seen | `2026-11-10 07:23:36` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a234f352ddd94c6e847135f0ea560e49` |
| SHA-1 | `f62787d581938b041a9a4d3f5c51cde3277e9c48` |
| SHA-256 | `889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed` |
| SHA3-384 | `2a2b90e71a5afe360aecae7c44361de3b7c99e61338b279bd071ee081f9a17ea2b6b6329e8beca1575f3446789bc3de9` |
| TLSH | `T1C2D1AABFB22AD83A395FD83637A099C98503B4C33C11DD4EB55CAC50AF9B941B925738` |
| SSDEEP | `96:5Fin+uKBiqTamLrDCkxwqyWuIRJxQorPpHnUgGIGBKuedMD1oBTxbQulU1XpQ8XC:rin+uOlrB3BWoMDCBNBGe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_889579ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed"
    family = "unknown"
    file_name = "889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed"
    file_type = "sh"
    first_seen = "2026-11-10 07:23:36"
  condition:
    hash.sha256(0, filesize) == "889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed"
}
```

### Sample 4: `97694582ff2f9ab7`

| Field | Value |
|---|---|
| SHA-256 | `97694582ff2f9ab78298861ec13149a3828ca59e3c671c73b8dd04e217c4355c` |
| Family label | `Mirai` |
| File name | `reflex.arm` |
| File type | `elf` |
| First seen | `2026-11-10 07:23:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `857776d27b327f70483b13ebfa52dfed` |
| SHA-1 | `75f49ec2520929933ad9b1425c800df67709215a` |
| SHA-256 | `97694582ff2f9ab78298861ec13149a3828ca59e3c671c73b8dd04e217c4355c` |
| SHA3-384 | `6ee411d3641789f76ffb0fcafc31f7c28670c43409b58662e4224b388543d2f48ac55f764a6c476a916f0111f549a30b` |
| TLSH | `T149A2D782BE429F03C4D261B6B6DF055D3B11BB6DE5EB3303E9217FD032468EA196B250` |
| TELFHASH | `t19c117d310e0c2cb9bbd2d00db12da113a49525f839761ca379fbec9f9b178e16420979` |
| SSDEEP | `384:Km8sGSQLJDLLGP6jXbDO1Z6S69VWPCR/KKykBmPPeZFx4ekI6:/TGSYJvLGPC/O1K5mX9w6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_97694582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97694582ff2f9ab78298861ec13149a3828ca59e3c671c73b8dd04e217c4355c"
    family = "Mirai"
    file_name = "reflex.arm"
    file_type = "elf"
    first_seen = "2026-11-10 07:23:06"
  condition:
    hash.sha256(0, filesize) == "97694582ff2f9ab78298861ec13149a3828ca59e3c671c73b8dd04e217c4355c"
}
```

### Sample 5: `0c9c2120bc387461`

| Field | Value |
|---|---|
| SHA-256 | `0c9c2120bc387461243e9768a610c608ae34baa9049f44116c965afc731485e5` |
| Family label | `Mirai` |
| File name | `reflex.arm7` |
| File type | `elf` |
| First seen | `2026-11-10 07:23:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f1faaa0147eb0ea2867955bb7952e68` |
| SHA-1 | `bbf0ea710658baddc4cc160cd0613db97e58858d` |
| SHA-256 | `0c9c2120bc387461243e9768a610c608ae34baa9049f44116c965afc731485e5` |
| SHA3-384 | `0650e32d0e249f6be5cfad3d87286cdbf6b19795e60fc261813f6c41fda075630776afa41b3ca058f746d9f9a2e4de55` |
| TLSH | `T16223D84AFA41AF01D4D631B9FB9E41493343AF68E3FA7201D9206F9523CA9DB0F76512` |
| TELFHASH | `t18d019c100d048c587ee4e01939ada132851171f93b3f1c0175bae8ce5567cf64410d4e` |
| SSDEEP | `768:MdnR4EfU7rO0K3K7/LpuPb4Hl6XKAQCl0znjiwP3GYHAtGFp03e/3T:MdnRVfU/O+LpuPbIzhClGjii3bU3a3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_0c9c2120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c9c2120bc387461243e9768a610c608ae34baa9049f44116c965afc731485e5"
    family = "Mirai"
    file_name = "reflex.arm7"
    file_type = "elf"
    first_seen = "2026-11-10 07:23:03"
  condition:
    hash.sha256(0, filesize) == "0c9c2120bc387461243e9768a610c608ae34baa9049f44116c965afc731485e5"
}
```

### Sample 6: `a39d5be80000760a`

| Field | Value |
|---|---|
| SHA-256 | `a39d5be80000760a5e7676062e0e67a31b9bc4594f2b7e893eb246767f4cff3b` |
| Family label | `Mirai` |
| File name | `Space.arm5` |
| File type | `elf` |
| First seen | `2026-11-10 07:10:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f27ce2ec2caa087080e1e0f3f9d4668` |
| SHA-1 | `db40b29d765458f8bb3d545e07b479ad0ecb606f` |
| SHA-256 | `a39d5be80000760a5e7676062e0e67a31b9bc4594f2b7e893eb246767f4cff3b` |
| SHA3-384 | `60900935618c5a32874c21d10e748618528646e7170fa6194a90fab9464d5df6adf5d17fc261ae6f1de399ae5038dcb6` |
| TLSH | `T1FB131846F8C24A3FC2C0137AA66E5A4E3761E3E4D2CB760B9E58576136D620F1D6AD80` |
| TELFHASH | `t1e4e06840fc755e1854e76570dcdc47b095012223606a4b20cf55dae0883f110e30ce4d` |
| SSDEEP | `768:HS2I8JS4L5musGVgrFBmnqJZQ1hblUkdXeizBN7wBoOI:HtS4L5mu5UBmqfcxlUmy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_a39d5be8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a39d5be80000760a5e7676062e0e67a31b9bc4594f2b7e893eb246767f4cff3b"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:25"
  condition:
    hash.sha256(0, filesize) == "a39d5be80000760a5e7676062e0e67a31b9bc4594f2b7e893eb246767f4cff3b"
}
```

### Sample 7: `2e13f7c268911c9b`

| Field | Value |
|---|---|
| SHA-256 | `2e13f7c268911c9bb3b7ebc1630715c6ce655c10517b98c179f65842dd287510` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-10 07:10:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c3932062f3de7f806d4cd00f70f46cd` |
| SHA-1 | `16992a84a20e4eed6c29d70921f8f2345fdee4c5` |
| SHA-256 | `2e13f7c268911c9bb3b7ebc1630715c6ce655c10517b98c179f65842dd287510` |
| SHA3-384 | `a44dbdce24f1df8674dff6be6bc3ea1ba143b8559318937b782fb0d44311ccef01e920acb20a993b12cb25fb79e82ec9` |
| TLSH | `T1E0556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSC:SDjxB4m5n8XlaPWi+d+a4TjxQP4w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_2e13f7c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e13f7c268911c9bb3b7ebc1630715c6ce655c10517b98c179f65842dd287510"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:05"
  condition:
    hash.sha256(0, filesize) == "2e13f7c268911c9bb3b7ebc1630715c6ce655c10517b98c179f65842dd287510"
}
```

### Sample 8: `ba81d03982d85ecc`

| Field | Value |
|---|---|
| SHA-256 | `ba81d03982d85ecc018ca5e7afa6a1157069a92825798b05f2a3f6195bc30f01` |
| Family label | `Mirai` |
| File name | `lavax.arm` |
| File type | `elf` |
| First seen | `2026-11-10 07:10:03` |
| Reporter | `adliwahid` |
| Tags | `Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f73cd9edaca57628ad6d3e283dd24d1a` |
| SHA-1 | `79049988aff3331dabf78bf92f7d0bcc5f506db2` |
| SHA-256 | `ba81d03982d85ecc018ca5e7afa6a1157069a92825798b05f2a3f6195bc30f01` |
| SHA3-384 | `81daa7179a45e9b27b0a2f450afd4a059859c92632602dbf3e6e90592aeac9774926de8157709f615c539e6cfa8b83cc` |
| TLSH | `T19BB39116F4429553C9C1D336FA1E239936D7B395D3CA3127C8C80F25238E8A96EDE2D6` |
| TELFHASH | `t1a1f02e554b81756d67f00455d1fd36692af9733e1e127c46c34c7d4f7053985b02ac32` |
| SSDEEP | `3072:6dcUskdR17osEp3vp5/SDbXMvlvGGFZ8Duu5T9zx:6dYIRxosEp3vp0Iv1t8D5T9zx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_ba81d039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba81d03982d85ecc018ca5e7afa6a1157069a92825798b05f2a3f6195bc30f01"
    family = "Mirai"
    file_name = "lavax.arm"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:03"
  condition:
    hash.sha256(0, filesize) == "ba81d03982d85ecc018ca5e7afa6a1157069a92825798b05f2a3f6195bc30f01"
}
```

### Sample 9: `a03bd6503e8b1816`

| Field | Value |
|---|---|
| SHA-256 | `a03bd6503e8b181697a7e3717b09f36aa0c001eadb381fb3d32515d6c2a509be` |
| Family label | `Mirai` |
| File name | `Space.arm5` |
| File type | `elf` |
| First seen | `2026-11-10 07:10:00` |
| Reporter | `adliwahid` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3144804a8b611557e86d9b414b5b4d2f` |
| SHA-1 | `e8ca1798229fe453739f130d36f2b6e6c35cfde2` |
| SHA-256 | `a03bd6503e8b181697a7e3717b09f36aa0c001eadb381fb3d32515d6c2a509be` |
| SHA3-384 | `b9705489f35a35af395aabc9a29fb743ad40c435ff3345e55a1509936fde0314d11a8e9197f8ae863be5fc346b5f9507` |
| TLSH | `T13D92DF20647BA9D0D93054B9A939C6C3DBC753F4E0F6B62713A8B63505C13877AF82A3` |
| SSDEEP | `384:S8rHAsuRM+QPuP98C245xeymAybofvhymdGUop5huK:S8rHALTUuP98CvcyL+ofvs3UozMK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_a03bd650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a03bd6503e8b181697a7e3717b09f36aa0c001eadb381fb3d32515d6c2a509be"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:00"
  condition:
    hash.sha256(0, filesize) == "a03bd6503e8b181697a7e3717b09f36aa0c001eadb381fb3d32515d6c2a509be"
}
```

### Sample 10: `9d180f0e5dff2a22`

| Field | Value |
|---|---|
| SHA-256 | `9d180f0e5dff2a2211b853fc28aac6c8b5b8b970e98d7746f016a60d8a616849` |
| Family label | `unknown` |
| File name | `SharpSMP.zip` |
| File type | `zip` |
| First seen | `2026-11-10 07:08:58` |
| Reporter | `milliesolem` |
| Tags | `kurdishmyth, minecraft, MythJs, MythPrivate, RAT, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb7ff47709a363626f36caac50ddd012` |
| SHA-1 | `32806a73a8c8727d06e7d67b621d8e520a569ef4` |
| SHA-256 | `9d180f0e5dff2a2211b853fc28aac6c8b5b8b970e98d7746f016a60d8a616849` |
| SHA3-384 | `a2b39ec9189ddeadd2e70f5dc5fd20dae8a2db63f946a490bfadb1fe1db53ef466431c522871aff97950bb227da5bb1a` |
| TLSH | `T13817334D025303ADC158B2885045F74ED75AC2B86B31C8B7B637475A27FECABE17AC68` |
| SSDEEP | `393216:TUX8kq+qHkMkVoi+8zec8iLkGKDmWUuSVDeDm3ZTpnXQk8JPfxzvWj:TUX8kq+4kMkush8wEDmWUfDeDetXQbVI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_9d180f0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d180f0e5dff2a2211b853fc28aac6c8b5b8b970e98d7746f016a60d8a616849"
    family = "unknown"
    file_name = "SharpSMP.zip"
    file_type = "zip"
    first_seen = "2026-11-10 07:08:58"
  condition:
    hash.sha256(0, filesize) == "9d180f0e5dff2a2211b853fc28aac6c8b5b8b970e98d7746f016a60d8a616849"
}
```

### Sample 11: `6117fdf5c647aea4`

| Field | Value |
|---|---|
| SHA-256 | `6117fdf5c647aea49913b960ccbd4f545fbe048f87934fd7498e1460b0bec223` |
| Family label | `Mirai` |
| File name | `x4` |
| File type | `elf` |
| First seen | `2026-11-10 07:08:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68816efa771517e9739d9f0606d4fe7b` |
| SHA-1 | `9d9c33d70b1491cad3fb913abc32f63a1c248ebe` |
| SHA-256 | `6117fdf5c647aea49913b960ccbd4f545fbe048f87934fd7498e1460b0bec223` |
| SHA3-384 | `fa381a86076418e6f0d6b5f3b25ff3160259910132e1e291a94a42818abaa33ccd870e61fffe35b88ef1f57da0e8a351` |
| TLSH | `T1D4865B47B5E358ECC19AC8704B6FD563BD7078984221B97B7698AA302F27F205B1DF21` |
| TELFHASH | `t17e3230708ae934e0a7d2c585f372f0b4da7358b66ae875b049327d82dfd4ec50c6681a` |
| SSDEEP | `98304:cRxJF5HhoLmfYxRukqzX0NDYy2HT5Rk9n2+PPEfbqg1EIk6O1+lgu3xeJQgDFc8J:uu6soq46Qx0jLOhoNoZ8DHarBsq2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_6117fdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6117fdf5c647aea49913b960ccbd4f545fbe048f87934fd7498e1460b0bec223"
    family = "Mirai"
    file_name = "x4"
    file_type = "elf"
    first_seen = "2026-11-10 07:08:19"
  condition:
    hash.sha256(0, filesize) == "6117fdf5c647aea49913b960ccbd4f545fbe048f87934fd7498e1460b0bec223"
}
```

### Sample 12: `37f975cb5b9ce21f`

| Field | Value |
|---|---|
| SHA-256 | `37f975cb5b9ce21f3c153cdb1f7ff3e9d56950b0e10fb58b7b8a3814c1f8ca11` |
| Family label | `Mirai` |
| File name | `x4` |
| File type | `elf` |
| First seen | `2026-11-10 07:07:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e78f2737ec2e754692d28d73c5f69c0e` |
| SHA-1 | `da376c50fe44c069a7ca718ec9bbf83f32d9d1ef` |
| SHA-256 | `37f975cb5b9ce21f3c153cdb1f7ff3e9d56950b0e10fb58b7b8a3814c1f8ca11` |
| SHA3-384 | `0544ba104789606584f9c824002d42318fa6866656bedbd3f417325ece4348d20e36e788f745e098967a26d30f8aa548` |
| TLSH | `T183E533992A4FB8A3E152B86D341F7EF17A5509460C0E6070E68EF7F253B953E864B4C3` |
| SSDEEP | `49152:B4SXdhjt4QSxdcOqbfiYPtV6t3r8N5u37M9unuJSCQM/9lIms+5Dcvf/PWpbMQu:BfH4QS6bfsB8N58nuM8ImLDUfnWu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_37f975cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37f975cb5b9ce21f3c153cdb1f7ff3e9d56950b0e10fb58b7b8a3814c1f8ca11"
    family = "Mirai"
    file_name = "x4"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:15"
  condition:
    hash.sha256(0, filesize) == "37f975cb5b9ce21f3c153cdb1f7ff3e9d56950b0e10fb58b7b8a3814c1f8ca11"
}
```

### Sample 13: `ca6e0ac85b41d6a1`

| Field | Value |
|---|---|
| SHA-256 | `ca6e0ac85b41d6a191eaddc695ad339648be8c8af008088a48550764c521635b` |
| Family label | `Mirai` |
| File name | `reflex.arm6` |
| File type | `elf` |
| First seen | `2026-11-10 07:07:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8339c0dad4c22fe781346364967de210` |
| SHA-1 | `3cc4dd47c7c5f73c7a2c4aeca416cde077001dad` |
| SHA-256 | `ca6e0ac85b41d6a191eaddc695ad339648be8c8af008088a48550764c521635b` |
| SHA3-384 | `ba2a127e67a4352c9eb3611230a11d34396d7fdc5fa21b3328fde2bb61cd7ffdc22de367ea093a4e98b8dde94efdab1a` |
| TLSH | `T14CF20B57FA52DE02C0D711B4BA9E414D37037F78E3EE63129A207FE027465EB0A7A916` |
| TELFHASH | `t10be07d009d08098816cb94aac0bcba24b41800907fc61c11d6feddcf4c23cc6a011c1c` |
| SSDEEP | `768:L0neE3YeLXlxxVYUWfump71TvIheYei3Wr1DqmxuV+0d2k:L0necYeL5m7P/vIsi3WxDqm3U2k` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_ca6e0ac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca6e0ac85b41d6a191eaddc695ad339648be8c8af008088a48550764c521635b"
    family = "Mirai"
    file_name = "reflex.arm6"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:12"
  condition:
    hash.sha256(0, filesize) == "ca6e0ac85b41d6a191eaddc695ad339648be8c8af008088a48550764c521635b"
}
```

### Sample 14: `11528bfa9bcaf4e2`

| Field | Value |
|---|---|
| SHA-256 | `11528bfa9bcaf4e2e86a12071d3a41f774964d0be9665de5b82be7d124aaa862` |
| Family label | `Mirai` |
| File name | `reflex.mpsl` |
| File type | `elf` |
| First seen | `2026-11-10 07:07:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37e9b548a5ecfbcd9e42fc465554c8d4` |
| SHA-1 | `5aa8a58244fe397fd27ec5ae97b417f2ccdbcf50` |
| SHA-256 | `11528bfa9bcaf4e2e86a12071d3a41f774964d0be9665de5b82be7d124aaa862` |
| SHA3-384 | `6be2beab85de91fc7f653d25dabb6b02e76ed669eeaf3d08fa1457f5e0a7dcc55271a6aed08898b1d7a23121e30a404a` |
| TLSH | `T161D27406BF928F67D86FDC724AF90B5134CDB81F15B1366A6830EC68730F58A55E38A4` |
| SSDEEP | `384:jv+f02+dDNV9YpUHhXHWEh/RuhV7v43Yy/mGbNg10TKGEeKUbYlXtrPtFXi5A0hh:DIV7cXbNg10eGEeKGkXJ7XiS0heWT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_11528bfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11528bfa9bcaf4e2e86a12071d3a41f774964d0be9665de5b82be7d124aaa862"
    family = "Mirai"
    file_name = "reflex.mpsl"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:09"
  condition:
    hash.sha256(0, filesize) == "11528bfa9bcaf4e2e86a12071d3a41f774964d0be9665de5b82be7d124aaa862"
}
```

### Sample 15: `deaa0a14dee8f417`

| Field | Value |
|---|---|
| SHA-256 | `deaa0a14dee8f41738a40e56b1efa85fd49bdf3671fadbd2d61f023e49c8fd33` |
| Family label | `Mirai` |
| File name | `reflex.arm5` |
| File type | `elf` |
| First seen | `2026-11-10 07:07:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbd3e43c06bb4f3c3ddfe8873fb11f34` |
| SHA-1 | `d59e34f783e74c07b7ae805b9ddb700a4fe1623f` |
| SHA-256 | `deaa0a14dee8f41738a40e56b1efa85fd49bdf3671fadbd2d61f023e49c8fd33` |
| SHA3-384 | `f6d264b05e4960cd8b438268dd86e25bd469ef60514cd18cb17bea5ba5ddaa107932c5e7338555c875076731375f37b5` |
| TLSH | `T121A2F982BE429F03C5D261B6B6DF055D3B117B6CE5EB3343E9217FD023468EA09AB251` |
| TELFHASH | `t14a117a210d4c6c587ed2a04eb12e6617611960f93aba0892bafbdccd86638f5611097d` |
| SSDEEP | `384:KkIsINhsOuTp43yrE2fDYVZ6S69V1PCR/KCxZBC7PQCCYFx4e4Y6:9PWhluFSibYVvFcIC6M6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_deaa0a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deaa0a14dee8f41738a40e56b1efa85fd49bdf3671fadbd2d61f023e49c8fd33"
    family = "Mirai"
    file_name = "reflex.arm5"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:06"
  condition:
    hash.sha256(0, filesize) == "deaa0a14dee8f41738a40e56b1efa85fd49bdf3671fadbd2d61f023e49c8fd33"
}
```

### Sample 16: `97a7e93b8713ef67`

| Field | Value |
|---|---|
| SHA-256 | `97a7e93b8713ef67ced7028689b95b07e614b32b277e14a9873975f4aee15445` |
| Family label | `Mirai` |
| File name | `reflex.sh4` |
| File type | `elf` |
| First seen | `2026-11-10 07:07:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9bc302283cba0cbe87eb045afb2ab01` |
| SHA-1 | `288eb480dc109dd8ab69fabb7fdd7f999567ba5b` |
| SHA-256 | `97a7e93b8713ef67ced7028689b95b07e614b32b277e14a9873975f4aee15445` |
| SHA3-384 | `737688bba0670650e1805906108e3630885087b90d2bf3b45223f780f92cb78c74eb15fb80e765dbe04932f0c224230d` |
| TLSH | `T11892F8829A169F67D51B61F462F20F3A5B23FE199E230EF76069ACD491039C8F1097F4` |
| SSDEEP | `384:bab74r1erfiFsvDCR0/PzEVuVvfno+/2qBOYty3qIVp4:baqerfgWCMoG2n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_97a7e93b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a7e93b8713ef67ced7028689b95b07e614b32b277e14a9873975f4aee15445"
    family = "Mirai"
    file_name = "reflex.sh4"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:03"
  condition:
    hash.sha256(0, filesize) == "97a7e93b8713ef67ced7028689b95b07e614b32b277e14a9873975f4aee15445"
}
```

### Sample 17: `53917de940b588be`

| Field | Value |
|---|---|
| SHA-256 | `53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e` |
| Family label | `AgentTesla` |
| File name | `Automaya S.A. de C.V. Lista de pedidos.js` |
| File type | `js` |
| First seen | `2026-11-10 06:57:09` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `320fa1534a8986a0dfeed4068120c8c9` |
| SHA-1 | `7c9c85c480403406bd2698472bacfd06f29caf2b` |
| SHA-256 | `53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e` |
| SHA3-384 | `cfffefc0c781ad28b98807327413eeed97703da723a54e1204afa320d5d63842044cbb28e623d012dfbe1c11e354683e` |
| TLSH | `T13DD20950AF73FCB04B513345580F69A4AAB0520A8CB1F350B19FA74F55A07BC967AECE` |
| SSDEEP | `384:MOH5pkN3nMVecv/LU7WecE7UQw19QGL9PyxpgluWHuj7MHvu+gDZO+s8I8M+UOY3:Z5aMwK/D35YGL9PWpglsIHWQ+Sp7Z3` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_017_53917de9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e"
    family = "AgentTesla"
    file_name = "Automaya S.A. de C.V. Lista de pedidos.js"
    file_type = "js"
    first_seen = "2026-11-10 06:57:09"
  condition:
    hash.sha256(0, filesize) == "53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e"
}
```

### Sample 18: `94b597e300b6eb98`

| Field | Value |
|---|---|
| SHA-256 | `94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29` |
| Family label | `unknown` |
| File name | `RFQ_NO.XFEC6000112038ADN25.docx` |
| File type | `docx` |
| First seen | `2026-11-10 06:56:44` |
| Reporter | `lowmal3` |
| Tags | `docx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `007d9220f33809e7ba0a2e286f91f6d7` |
| SHA-1 | `503aa37d19b8bfa6b5783ac39d4d71e08abb5c1a` |
| SHA-256 | `94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29` |
| SHA3-384 | `38ef71db0c69db552adba8d04e8b206641930742319e0f39157e2cb6048b25714c3f82ba92deaec7bf26de1d2edebcc0` |
| TLSH | `T1DD162235C75998DFDAA9FCAF110B4FCF1ED168F29DB805D894C46A32707AA5209A0DC3` |
| SSDEEP | `98304:ArqV0FpABFeVuo2qw80QCwL58A33mX6RQ6ttjMyWzXfv1wLjjBWmLdO6:CqV8GPeVuLOL98GmX0ttjMvXfv1wAmY6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `docx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_94b597e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29"
    family = "unknown"
    file_name = "RFQ_NO.XFEC6000112038ADN25.docx"
    file_type = "docx"
    first_seen = "2026-11-10 06:56:44"
  condition:
    hash.sha256(0, filesize) == "94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29"
}
```

### Sample 19: `264e109751bb5d6f`

| Field | Value |
|---|---|
| SHA-256 | `264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3` |
| Family label | `unknown` |
| File name | `RFQ 000240_RO_xlsx.js` |
| File type | `js` |
| First seen | `2026-11-10 06:56:13` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a19c8cb7ae5297c8c764d3e9ced0441c` |
| SHA-1 | `6374f41dab05b67b4ea63543bcb8b4c766886b63` |
| SHA-256 | `264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3` |
| SHA3-384 | `70524eada3a14e8afb70d2367ce1758b66432a04cf0529e6ea2042d00800929eb17ae85129d3c9757386dd5c7b80bcdb` |
| TLSH | `T14DC22A404B476CB10B46B781CD4B4DA5CCE58A02C472DFA0F5EF9B15E142998EEB96CF` |
| SSDEEP | `384:TOH5pkN3cuhLLH67we8ko+Iki5Qmv/L6luDjaVCx4VCDgSHYeJr2PV/KUgdK60Vs:E5arLgwM/7mulDVCxITSzKPVi/z0m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_264e1097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3"
    family = "unknown"
    file_name = "RFQ 000240_RO_xlsx.js"
    file_type = "js"
    first_seen = "2026-11-10 06:56:13"
  condition:
    hash.sha256(0, filesize) == "264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3"
}
```

### Sample 20: `6f4facc2fa66e56e`

| Field | Value |
|---|---|
| SHA-256 | `6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282` |
| Family label | `AgentTesla` |
| File name | `PO#17971 for November 2026.exe` |
| File type | `exe` |
| First seen | `2026-11-10 06:55:57` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1235029b1fd5efeed08563866f87af0` |
| SHA-1 | `154d3e76521d23f58bbb907d4d808368673baad4` |
| SHA-256 | `6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282` |
| SHA3-384 | `0a9bc8eb80efa148edee295b2b5f50904e34c9c8c6650ce2e02656dc046fd64b2e447c9cb5d013177210b4c8da7c642b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T199358C983250F58FCA57CD76C964DDF4A6202CA6D30BD20391973DAFB93D692EE041E2` |
| SSDEEP | `24576:NtOowMWXF9cmPpzN+ILPA3mjULPCqIH+YbGNF:Ut4A1N+oPA3mQDCqW3` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_020_6f4facc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282"
    family = "AgentTesla"
    file_name = "PO#17971 for November 2026.exe"
    file_type = "exe"
    first_seen = "2026-11-10 06:55:57"
  condition:
    hash.sha256(0, filesize) == "6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282"
}
```

### Sample 21: `bc00e9d8bb62be41`

| Field | Value |
|---|---|
| SHA-256 | `bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e` |
| Family label | `AgentTesla` |
| File name | `HBL DOC.pif` |
| File type | `exe` |
| First seen | `2026-11-10 06:55:40` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b45ee47d42d9c95dd6bc90c0f236285` |
| SHA-1 | `e33c2fe89cb0dcacb4a4c4a57f84793690fd2a32` |
| SHA-256 | `bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e` |
| SHA3-384 | `c8bce947c4bbcbeaaa6985f9eefd5650fc81294b85ddd065dd40429cdea60ac8434801dc10f74b3893fcc6cae7bd3bbf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14915DF0062AAD806D1795772C9F1DAF817713D59E932C24B0BEA7DEB3A337825C46783` |
| SSDEEP | `24576:Kt1F9FR1V1K42iTcUlFw35A07M43IWxgfCSQ:21RR1V1MiTPlFw35AYM4a65` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_021_bc00e9d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e"
    family = "AgentTesla"
    file_name = "HBL DOC.pif"
    file_type = "exe"
    first_seen = "2026-11-10 06:55:40"
  condition:
    hash.sha256(0, filesize) == "bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e"
}
```

### Sample 22: `2f3032202a9099b2`

| Field | Value |
|---|---|
| SHA-256 | `2f3032202a9099b24b07f93c5f76044ac0aa382f891010705b5dd64b33b329ca` |
| Family label | `unknown` |
| File name | `MTO EFIP8001 MLDP REV 1_xlsm.js` |
| File type | `js` |
| First seen | `2026-11-10 06:55:25` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5287d24c410d596c1ed894b1e8971180` |
| SHA-1 | `54c2ede32e7c50fe1a3b84002d538697d83e216d` |
| SHA-256 | `2f3032202a9099b24b07f93c5f76044ac0aa382f891010705b5dd64b33b329ca` |
| SHA3-384 | `24be0cd6708668d537041632cd23afe3fcfa6c961c0ced093a46ca3f4eaea70d0166eee00132d954d9e6d947a7adea07` |
| TLSH | `T17A71328D3C47B0680973F37E8B3BA209E75754A30505C565B9BEA7406F70419816CEEF` |
| SSDEEP | `48:G2z1XHYAGGG2yyK1mFKS5zXJWODDzZepf9iKudSnVW5rrVXFBJ:vXYn/2yUPYCzgpUXcVW5rrVVBJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_2f303220
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f3032202a9099b24b07f93c5f76044ac0aa382f891010705b5dd64b33b329ca"
    family = "unknown"
    file_name = "MTO EFIP8001 MLDP REV 1_xlsm.js"
    file_type = "js"
    first_seen = "2026-11-10 06:55:25"
  condition:
    hash.sha256(0, filesize) == "2f3032202a9099b24b07f93c5f76044ac0aa382f891010705b5dd64b33b329ca"
}
```

### Sample 23: `e30c0b35ba69eb04`

| Field | Value |
|---|---|
| SHA-256 | `e30c0b35ba69eb044347ac21941d809affedcab9eed5b975753f0948c366bb1e` |
| Family label | `unknown` |
| File name | `MTO EFIP8001 LHDP REV 1_xlsm.wsf` |
| File type | `wsf` |
| First seen | `2026-11-10 06:55:12` |
| Reporter | `lowmal3` |
| Tags | `wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6869377a2ad2416910cca2d38a2efd19` |
| SHA-1 | `31e006d48546fdbbce219ecf6c1b542f7098dc62` |
| SHA-256 | `e30c0b35ba69eb044347ac21941d809affedcab9eed5b975753f0948c366bb1e` |
| SHA3-384 | `6cebf3d815a84bdaaac2c0bb5b6de1628f1c8fea9b2d8f9ea0440a8e6e21ea8d66c7d59056095541e4e99e7dba4f4bda` |
| TLSH | `T15C811189ADD9B0250633333E8F3B920FE766407B1106C159B5AC99C61F764248E94FFD` |
| SSDEEP | `48:72zxeekthzWE9pP+TSp2Ah+jXJWAEXzyr3G1U/BzIxEAGsGumNGucGuLIGuA4:jDiEySgZYRz31UmxEam1+mR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_e30c0b35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e30c0b35ba69eb044347ac21941d809affedcab9eed5b975753f0948c366bb1e"
    family = "unknown"
    file_name = "MTO EFIP8001 LHDP REV 1_xlsm.wsf"
    file_type = "wsf"
    first_seen = "2026-11-10 06:55:12"
  condition:
    hash.sha256(0, filesize) == "e30c0b35ba69eb044347ac21941d809affedcab9eed5b975753f0948c366bb1e"
}
```

### Sample 24: `dbd540b473191168`

| Field | Value |
|---|---|
| SHA-256 | `dbd540b47319116837f78b3103349e15b4c593128439fd6762521449dba64a3c` |
| Family label | `unknown` |
| File name | `Request for Quotation-To Supply Instrument Spare Parts.js` |
| File type | `js` |
| First seen | `2026-11-10 06:54:39` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3c55b2b9c1c255e99a09c2f2b336067` |
| SHA-1 | `902e3c326d464e3c80c210f5a03aceb2f8eda907` |
| SHA-256 | `dbd540b47319116837f78b3103349e15b4c593128439fd6762521449dba64a3c` |
| SHA3-384 | `5ee365073b6867f98797b9f133d33e47ae8c6df62fff717f57b770d3b7b4f9d536a5d029413b12bebe533a534ea6f6d8` |
| TLSH | `T17F71328D3C47A0680973F37E8B3BA209E75754A30505C565B9BEA7406F70419816CEEF` |
| SSDEEP | `48:G2B1XHYAGGG2yyK1mFKS5zXJWODDzZepf9iKudSnVW5rrVXFBJ:lXYn/2yUPYCzgpUXcVW5rrVVBJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_dbd540b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbd540b47319116837f78b3103349e15b4c593128439fd6762521449dba64a3c"
    family = "unknown"
    file_name = "Request for Quotation-To Supply Instrument Spare Parts.js"
    file_type = "js"
    first_seen = "2026-11-10 06:54:39"
  condition:
    hash.sha256(0, filesize) == "dbd540b47319116837f78b3103349e15b4c593128439fd6762521449dba64a3c"
}
```

### Sample 25: `8573503e09f5fd6d`

| Field | Value |
|---|---|
| SHA-256 | `8573503e09f5fd6dbd84f6b142862e272de6f55b625a1713a4f0f9548583cdb0` |
| Family label | `AgentTesla` |
| File name | `PURCHASE ORDER#008584.js` |
| File type | `js` |
| First seen | `2026-11-10 06:54:21` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bcd67be8f12157380e0bf8c49155cb3` |
| SHA-1 | `54f50050acea74d4f7b15d29035f37c4457836af` |
| SHA-256 | `8573503e09f5fd6dbd84f6b142862e272de6f55b625a1713a4f0f9548583cdb0` |
| SHA3-384 | `670547e1d489b89fe829c0e4415f12b286de9dfea748df122b75aa7b47b2a3d5e30541210cee6904b2ad99a5a7298486` |
| TLSH | `T102D2B6CC59CB68F2C9D7FA80CD4509E8CDA54B2144299152BDBF9B80690864C97FF3EE` |
| SSDEEP | `384:NOH5pkN3m5fbbNO1j7VQL3Tg4IRfT3ippV5plu4JID+n3uMUrfjZOkMo0:m5aUvN0QnST3i5llJ53udvH0` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_025_8573503e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8573503e09f5fd6dbd84f6b142862e272de6f55b625a1713a4f0f9548583cdb0"
    family = "AgentTesla"
    file_name = "PURCHASE ORDER#008584.js"
    file_type = "js"
    first_seen = "2026-11-10 06:54:21"
  condition:
    hash.sha256(0, filesize) == "8573503e09f5fd6dbd84f6b142862e272de6f55b625a1713a4f0f9548583cdb0"
}
```

### Sample 26: `521a19a85d9c290f`

| Field | Value |
|---|---|
| SHA-256 | `521a19a85d9c290fc84b5eed9d91d1a13b7332aaaa27a29b6cf4e84139bb6979` |
| Family label | `unknown` |
| File name | `PO-153211.js` |
| File type | `js` |
| First seen | `2026-11-10 06:54:06` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5de184cf7f55543c474009605ec07cfb` |
| SHA-1 | `c3ab3261d4a1c9cc9e2601973b3a64ba52cf7d6f` |
| SHA-256 | `521a19a85d9c290fc84b5eed9d91d1a13b7332aaaa27a29b6cf4e84139bb6979` |
| SHA3-384 | `96cc7847d04d4b6a1d51a60b79a7c88e58d20c4ac284fd85b485480da74ee4ce843852c54b933a01018c92d35e565728` |
| TLSH | `T162D27BD914B69FD4E68870B985A2F6035BEF8849F33D6742B00878C83979C52E73563B` |
| SSDEEP | `768:1DnHSkDnHSkDnHS0naaDnHSkDnHSkDnHSM:VyYyYy0a6yYyYyM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_521a19a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "521a19a85d9c290fc84b5eed9d91d1a13b7332aaaa27a29b6cf4e84139bb6979"
    family = "unknown"
    file_name = "PO-153211.js"
    file_type = "js"
    first_seen = "2026-11-10 06:54:06"
  condition:
    hash.sha256(0, filesize) == "521a19a85d9c290fc84b5eed9d91d1a13b7332aaaa27a29b6cf4e84139bb6979"
}
```

### Sample 27: `a92f2d3dc8ca44a3`

| Field | Value |
|---|---|
| SHA-256 | `a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af` |
| Family label | `CoinMiner` |
| File name | `OurNew.exe` |
| File type | `exe` |
| First seen | `2026-11-10 06:52:38` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14013e5f8ce2e4a9459b669368c37786` |
| SHA-1 | `168792b0c49fb5d6ae6125a2fbe0ea170bce4801` |
| SHA-256 | `a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af` |
| SHA3-384 | `c927a2dfa64fbfb872c4a937c01c4f1aeff3b28e3a290511b48ea0abd76bd2872b806daca60055987fe1812f1cc580e5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13A6633B54D6F535EFF72C9F83C936827D8B0F4A6160808329B06F3594D6659B0B28A4F` |
| SSDEEP | `98304:wSWoElNFXHS6TmXMdSp2zge1TmyEv7/cAynU5gXjYtFULgW/DKe:wSWFBXRTmXSnTTE4AL57tybDKe` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_027_a92f2d3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af"
    family = "CoinMiner"
    file_name = "OurNew.exe"
    file_type = "exe"
    first_seen = "2026-11-10 06:52:38"
  condition:
    hash.sha256(0, filesize) == "a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af"
}
```

### Sample 28: `7871b4edf3d6e85a`

| Field | Value |
|---|---|
| SHA-256 | `7871b4edf3d6e85aee7e4a6857eeb0094ecbfb7d698a296412f057662407ea78` |
| Family label | `SalatStealer` |
| File name | `7179a0c397748d17.bin` |
| File type | `exe` |
| First seen | `2026-11-10 06:25:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67091885daee52f9e25ec5095974d293` |
| SHA-1 | `e13a62e2d4b589c57ab40d88ef4908490f0a9d17` |
| SHA-256 | `7871b4edf3d6e85aee7e4a6857eeb0094ecbfb7d698a296412f057662407ea78` |
| SHA3-384 | `444f834893e905a3c5bdf9c8c0d01000db4818eab47003aa2ef235868937514c97cd43c36944480c95697baa6752a5d6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T111C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+w:yBkKr5rszpNDy+w` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_028_7871b4ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7871b4edf3d6e85aee7e4a6857eeb0094ecbfb7d698a296412f057662407ea78"
    family = "SalatStealer"
    file_name = "7179a0c397748d17.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:33"
  condition:
    hash.sha256(0, filesize) == "7871b4edf3d6e85aee7e4a6857eeb0094ecbfb7d698a296412f057662407ea78"
}
```

### Sample 29: `0be8947b2a4396ce`

| Field | Value |
|---|---|
| SHA-256 | `0be8947b2a4396ce1390b694323402ec5379724dd927b9409cc874ef68defcc7` |
| Family label | `SalatStealer` |
| File name | `c7626da7d9f3c52e.bin` |
| File type | `exe` |
| First seen | `2026-11-10 06:25:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35d3820120c15b774f63c4e74e1d1e0c` |
| SHA-1 | `e50fdf6bbce605883badde063dd688d7188907d2` |
| SHA-256 | `0be8947b2a4396ce1390b694323402ec5379724dd927b9409cc874ef68defcc7` |
| SHA3-384 | `267249ede33b1bce600c3b7f6b7616bbbe7c4c8ae8bd90f365b69b255010c0649e28366fc6631d6bc787198c727e789b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CDC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+L:yBkKr5rszpNDy+L` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_029_0be8947b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0be8947b2a4396ce1390b694323402ec5379724dd927b9409cc874ef68defcc7"
    family = "SalatStealer"
    file_name = "c7626da7d9f3c52e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:27"
  condition:
    hash.sha256(0, filesize) == "0be8947b2a4396ce1390b694323402ec5379724dd927b9409cc874ef68defcc7"
}
```

### Sample 30: `c76eb1713960358d`

| Field | Value |
|---|---|
| SHA-256 | `c76eb1713960358d1d5dcc011ec86bce4064f7a0f34bf9e34d42889a49dc14c5` |
| Family label | `SalatStealer` |
| File name | `a081f4530595a397.bin` |
| File type | `exe` |
| First seen | `2026-11-10 06:25:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20dc74ae3c145c0092d75e9df7fe16ea` |
| SHA-1 | `89e6372e08ed6e5d0a0ed103928e6bf27e034e2c` |
| SHA-256 | `c76eb1713960358d1d5dcc011ec86bce4064f7a0f34bf9e34d42889a49dc14c5` |
| SHA3-384 | `501274b1e14f90960972f08f0d0d6bd4f13199435fb72d829df5fabf24118466bb762fe0e130454e19746a438bb6042a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+W:yBkKr5rszpNDy+W` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_030_c76eb171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76eb1713960358d1d5dcc011ec86bce4064f7a0f34bf9e34d42889a49dc14c5"
    family = "SalatStealer"
    file_name = "a081f4530595a397.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:22"
  condition:
    hash.sha256(0, filesize) == "c76eb1713960358d1d5dcc011ec86bce4064f7a0f34bf9e34d42889a49dc14c5"
}
```

### Sample 31: `7179a0c397748d17`

| Field | Value |
|---|---|
| SHA-256 | `7179a0c397748d17e12355ae5e3f91fa9f64d6a3d20b366d68c2f210489b8f94` |
| Family label | `SalatStealer` |
| File name | `7179a0c397748d17.bin` |
| File type | `exe` |
| First seen | `2026-11-10 06:25:14` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb9483fdfee1b82f589b79c7026e4114` |
| SHA-1 | `4e9b842ad282e5cdc76769752f34796aeacd3c53` |
| SHA-256 | `7179a0c397748d17e12355ae5e3f91fa9f64d6a3d20b366d68c2f210489b8f94` |
| SHA3-384 | `36c1023909efd656d00641e3643e985a55387cf704d6d4af78d7d724d47bcae3b03115f87af680c785b61f15e91a3447` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B6F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OE:iJiafuIO7rhWEES4z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_031_7179a0c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7179a0c397748d17e12355ae5e3f91fa9f64d6a3d20b366d68c2f210489b8f94"
    family = "SalatStealer"
    file_name = "7179a0c397748d17.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:14"
  condition:
    hash.sha256(0, filesize) == "7179a0c397748d17e12355ae5e3f91fa9f64d6a3d20b366d68c2f210489b8f94"
}
```

### Sample 32: `c7626da7d9f3c52e`

| Field | Value |
|---|---|
| SHA-256 | `c7626da7d9f3c52e576eecc7a98c4363b8580640849c96fb215bf40f0adb2e04` |
| Family label | `SalatStealer` |
| File name | `c7626da7d9f3c52e.bin` |
| File type | `exe` |
| First seen | `2026-11-10 06:25:02` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aa1407d9b07db8b4474d1af9a2d6516` |
| SHA-1 | `a64cad8fc24b746b88fa5ae5b0d29025a1f46988` |
| SHA-256 | `c7626da7d9f3c52e576eecc7a98c4363b8580640849c96fb215bf40f0adb2e04` |
| SHA3-384 | `75c9edc5ce0989e13c725a845a2f2d270cd9b2f1de21da358833155efd3c41e0ac08918e496b7364fb7f6e78ffa2e955` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T186F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O/:iJiafuIO7rhWEES4I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_032_c7626da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7626da7d9f3c52e576eecc7a98c4363b8580640849c96fb215bf40f0adb2e04"
    family = "SalatStealer"
    file_name = "c7626da7d9f3c52e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:02"
  condition:
    hash.sha256(0, filesize) == "c7626da7d9f3c52e576eecc7a98c4363b8580640849c96fb215bf40f0adb2e04"
}
```

### Sample 33: `a081f4530595a397`

| Field | Value |
|---|---|
| SHA-256 | `a081f4530595a3973d658cb2e123b4f0237c956a93f7a450f6f6d8709ecdc351` |
| Family label | `SalatStealer` |
| File name | `a081f4530595a397.bin` |
| File type | `exe` |
| First seen | `2026-11-10 06:24:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08ee8850187d5e1a0ef8707775c25c34` |
| SHA-1 | `37fa1b2a9554586d8e366094abcc15cad9062bd9` |
| SHA-256 | `a081f4530595a3973d658cb2e123b4f0237c956a93f7a450f6f6d8709ecdc351` |
| SHA3-384 | `fd4dae501afd679481de3ff31c8e9c7770a6b2d6e20d04138d1a61263a1a33475a7e3960b372600dafaaf9943c15312b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11DF5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oq:iJiafuIO7rhWEES4t` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_a081f453
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a081f4530595a3973d658cb2e123b4f0237c956a93f7a450f6f6d8709ecdc351"
    family = "SalatStealer"
    file_name = "a081f4530595a397.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:24:49"
  condition:
    hash.sha256(0, filesize) == "a081f4530595a3973d658cb2e123b4f0237c956a93f7a450f6f6d8709ecdc351"
}
```

### Sample 34: `4a64138c242b044f`

| Field | Value |
|---|---|
| SHA-256 | `4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-10 06:09:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39c74c8d6b06fe5021e56b5a42bd3660` |
| SHA-1 | `4e16e02930cfe6429900bfee412449a91cb42238` |
| SHA-256 | `4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520` |
| SHA3-384 | `8a7131712cd6054e39ebb87d2f1de0e924e6de29b9ae60c28f07218ec4735a04baf61ee47fe5febcdbc8899145386519` |
| TLSH | `T18F556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSI:SDjxB4m5n8XlaPWi+d+a4TjxQP4i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_4a64138c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 06:09:03"
  condition:
    hash.sha256(0, filesize) == "4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520"
}
```

### Sample 35: `ac485a3ad457a1e5`

| Field | Value |
|---|---|
| SHA-256 | `ac485a3ad457a1e550ced3b48c9bd25126b3ca585478f3d99734c2c54fcabdd9` |
| Family label | `unknown` |
| File name | `.16` |
| File type | `elf` |
| First seen | `2026-11-10 05:57:12` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `560408fc47af850a396999cfc5de8134` |
| SHA-1 | `e2c08bfa5bde607ad136c09ea1699e14061789b4` |
| SHA-256 | `ac485a3ad457a1e550ced3b48c9bd25126b3ca585478f3d99734c2c54fcabdd9` |
| SHA3-384 | `729e7dc0421cf79091220473de0580bd99e47e12ebe7d6c2858b87d7a1d6044ed55ef37cf4697a41be1b1d4026384acc` |
| TLSH | `T18BC4491BB59250BCC1E6D170839F9233B972B86452347EBF62C4AB302E26F11675EF61` |
| SSDEEP | `12288:MxwzO77nk5J1IsK+Fs0VmLVocwSM5HVnagjj:MOWkFlK+FsHoFSMdVnFv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_ac485a3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac485a3ad457a1e550ced3b48c9bd25126b3ca585478f3d99734c2c54fcabdd9"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-11-10 05:57:12"
  condition:
    hash.sha256(0, filesize) == "ac485a3ad457a1e550ced3b48c9bd25126b3ca585478f3d99734c2c54fcabdd9"
}
```

### Sample 36: `2c6ad60dd7edf70d`

| Field | Value |
|---|---|
| SHA-256 | `2c6ad60dd7edf70d9f28e362f66a72b146367f1167277ab830a3749cecd1ea6f` |
| Family label | `CoinMiner` |
| File name | `OurNew.exe` |
| File type | `exe` |
| First seen | `2026-11-10 05:52:38` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7026eea3acf9e6d9ae434d740b82507a` |
| SHA-1 | `cbb6f699a606169b8a50815200474da2e7a09015` |
| SHA-256 | `2c6ad60dd7edf70d9f28e362f66a72b146367f1167277ab830a3749cecd1ea6f` |
| SHA3-384 | `a36a48ff032d1e0162d709c709142a35a21de231ee6dfac6dc437530e5f4da677ff3aaa7653805a515a93266cc6eed49` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1526633B5486F431EFF7698B8BC835937D979E95A29040D324B01F366083319F4FA4A8B` |
| SSDEEP | `196608:lHOg4roLowrwAYdBFSnTTE4AL57tybDKe:lZowrwACF4TT5AZtyH` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_036_2c6ad60d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6ad60dd7edf70d9f28e362f66a72b146367f1167277ab830a3749cecd1ea6f"
    family = "CoinMiner"
    file_name = "OurNew.exe"
    file_type = "exe"
    first_seen = "2026-11-10 05:52:38"
  condition:
    hash.sha256(0, filesize) == "2c6ad60dd7edf70d9f28e362f66a72b146367f1167277ab830a3749cecd1ea6f"
}
```

### Sample 37: `e50d206d484b8d16`

| Field | Value |
|---|---|
| SHA-256 | `e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524` |
| Family label | `SalatStealer` |
| File name | `205ffcdb71580bff.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:26:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5366430a3d5a1ba01ad6cf7cc275ec7` |
| SHA-1 | `b8c2fa5c2e6c1536b50eba8c13d0f4e9c211a86a` |
| SHA-256 | `e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524` |
| SHA3-384 | `94c238aa4cde234ccc8914fe8649589e9d9bf204d0da53bc230b16138e8763b1330e3932ca9cc9122ba4cbc4adbc8107` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B2C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+P:yBkKr5rszpNDy+P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_037_e50d206d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524"
    family = "SalatStealer"
    file_name = "205ffcdb71580bff.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:26:17"
  condition:
    hash.sha256(0, filesize) == "e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524"
}
```

### Sample 38: `bee28f6ef408f6b5`

| Field | Value |
|---|---|
| SHA-256 | `bee28f6ef408f6b549f1a2564fe89516480ca3a52983a3aefea10184e778ad02` |
| Family label | `SalatStealer` |
| File name | `ffa6045efd8fd41d.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:25:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `beab74cb47d10feaa8791b88125a371e` |
| SHA-1 | `dda2068e58e4760ead0d1b8fde12c26a39812fdd` |
| SHA-256 | `bee28f6ef408f6b549f1a2564fe89516480ca3a52983a3aefea10184e778ad02` |
| SHA3-384 | `876976e1277b6cf7a0d660298cc6683d0e24a2851213fea8c0942f0b376a1e97dc74bdfd5fac538f9886a12b0ed95cd0` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T151C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+3:yBkKr5rszpNDy+3` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_038_bee28f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bee28f6ef408f6b549f1a2564fe89516480ca3a52983a3aefea10184e778ad02"
    family = "SalatStealer"
    file_name = "ffa6045efd8fd41d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:33"
  condition:
    hash.sha256(0, filesize) == "bee28f6ef408f6b549f1a2564fe89516480ca3a52983a3aefea10184e778ad02"
}
```

### Sample 39: `f146873024b0f156`

| Field | Value |
|---|---|
| SHA-256 | `f146873024b0f156b2ef37d7f5383361d07852f250bcd76f388d13bfa11122da` |
| Family label | `SalatStealer` |
| File name | `d34701558b0d2129.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:25:27` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2bd7741b420ba0dc5110fa4c88bdd3c` |
| SHA-1 | `41056fa96667db20af4e77e25d51df13a1e32a0f` |
| SHA-256 | `f146873024b0f156b2ef37d7f5383361d07852f250bcd76f388d13bfa11122da` |
| SHA3-384 | `0ed7ebde278538db9daaaf3a89d1641d282e2dc879bf11d17f29aad686d0123fb9dd4bd047ca0ae01ca3fc3ee46d770f` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T177C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+u:yBkKr5rszpNDy+u` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_039_f1468730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f146873024b0f156b2ef37d7f5383361d07852f250bcd76f388d13bfa11122da"
    family = "SalatStealer"
    file_name = "d34701558b0d2129.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:27"
  condition:
    hash.sha256(0, filesize) == "f146873024b0f156b2ef37d7f5383361d07852f250bcd76f388d13bfa11122da"
}
```

### Sample 40: `4d8185fee09ded1b`

| Field | Value |
|---|---|
| SHA-256 | `4d8185fee09ded1b6966264fc942d9750575119121da678c7a73ed7f5d62aac1` |
| Family label | `SalatStealer` |
| File name | `db76cb5443264f9d.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:25:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80fe7adee4076819368e93717c4ac271` |
| SHA-1 | `bf0b1bd128ae3ffcddba71771e768c0bbc8376b1` |
| SHA-256 | `4d8185fee09ded1b6966264fc942d9750575119121da678c7a73ed7f5d62aac1` |
| SHA3-384 | `f73f84181bc72e247a83f5bc681d39bc682ff0c6bcb9ebd797a373141e66ad8d133fd6a2dfb858044e7a774beacc91f2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+R:yBkKr5rszpNDy+R` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_040_4d8185fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d8185fee09ded1b6966264fc942d9750575119121da678c7a73ed7f5d62aac1"
    family = "SalatStealer"
    file_name = "db76cb5443264f9d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:22"
  condition:
    hash.sha256(0, filesize) == "4d8185fee09ded1b6966264fc942d9750575119121da678c7a73ed7f5d62aac1"
}
```

### Sample 41: `205ffcdb71580bff`

| Field | Value |
|---|---|
| SHA-256 | `205ffcdb71580bffb9bae90a594b0da311ed9586e92cd5bcc092839268438596` |
| Family label | `SalatStealer` |
| File name | `205ffcdb71580bff.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:25:17` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f132fee595424232a7b06aae33fc6b8` |
| SHA-1 | `28e932c05d37de8ed9a10e5dc527a3d902d41845` |
| SHA-256 | `205ffcdb71580bffb9bae90a594b0da311ed9586e92cd5bcc092839268438596` |
| SHA3-384 | `82b5d25c81b802806e3c04c6d23392a80bae2cdb3c15a64e71cae73a5e86e95d6b33fefa1ec196953c7f796a42c59ef7` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C1F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OT:iJiafuIO7rhWEES4i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_041_205ffcdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205ffcdb71580bffb9bae90a594b0da311ed9586e92cd5bcc092839268438596"
    family = "SalatStealer"
    file_name = "205ffcdb71580bff.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:17"
  condition:
    hash.sha256(0, filesize) == "205ffcdb71580bffb9bae90a594b0da311ed9586e92cd5bcc092839268438596"
}
```

### Sample 42: `ffa6045efd8fd41d`

| Field | Value |
|---|---|
| SHA-256 | `ffa6045efd8fd41d00489dd877f578d96ec4dd06d1cf681fcfc636ec4943947d` |
| Family label | `SalatStealer` |
| File name | `ffa6045efd8fd41d.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:25:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eccf935401f4eee6365c7c0803519b6d` |
| SHA-1 | `3dd111f628d064455435807702a50732bd69b4a2` |
| SHA-256 | `ffa6045efd8fd41d00489dd877f578d96ec4dd06d1cf681fcfc636ec4943947d` |
| SHA3-384 | `a97a27aeaa1d9656d9ad8bf639256a4547eab7f94a08214e68550be2146979366a43bc68c6cb90c1532b73ed1cf61ff9` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T19DF5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0882FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OT:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_042_ffa6045e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffa6045efd8fd41d00489dd877f578d96ec4dd06d1cf681fcfc636ec4943947d"
    family = "SalatStealer"
    file_name = "ffa6045efd8fd41d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:06"
  condition:
    hash.sha256(0, filesize) == "ffa6045efd8fd41d00489dd877f578d96ec4dd06d1cf681fcfc636ec4943947d"
}
```

### Sample 43: `d34701558b0d2129`

| Field | Value |
|---|---|
| SHA-256 | `d34701558b0d21293fcf58846a17a9e9981cf90e7148a777b7db0e73de3bb592` |
| Family label | `SalatStealer` |
| File name | `d34701558b0d2129.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:24:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cc3b36bb8d971a71534aeeb745b2eeb` |
| SHA-1 | `9ef87449ae571ddb955d5d0f341f7e7f0ec6c0b0` |
| SHA-256 | `d34701558b0d21293fcf58846a17a9e9981cf90e7148a777b7db0e73de3bb592` |
| SHA3-384 | `a623f19ae84e36629cce428fdb9b85c69d2a40feaf0cee3dda37ee206591fa8bb285f1aa8ca501a74f6fa7211c36668e` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14BF5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OS:iJiafuIO7rhWEES4J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_043_d3470155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d34701558b0d21293fcf58846a17a9e9981cf90e7148a777b7db0e73de3bb592"
    family = "SalatStealer"
    file_name = "d34701558b0d2129.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:24:54"
  condition:
    hash.sha256(0, filesize) == "d34701558b0d21293fcf58846a17a9e9981cf90e7148a777b7db0e73de3bb592"
}
```

### Sample 44: `db76cb5443264f9d`

| Field | Value |
|---|---|
| SHA-256 | `db76cb5443264f9db353d5a5dacb3aafb943e2938883737350889612ac90f431` |
| Family label | `SalatStealer` |
| File name | `db76cb5443264f9d.bin` |
| File type | `exe` |
| First seen | `2026-11-10 05:24:42` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34ba614dc355117968b1085f26ba68eb` |
| SHA-1 | `f4ae1f0a89276f02207760e3dbe8c67f6d0a4b04` |
| SHA-256 | `db76cb5443264f9db353d5a5dacb3aafb943e2938883737350889612ac90f431` |
| SHA3-384 | `a6af4f05c04488a1708b284dfe825ee4cfbd79076dba535f09c3313a40e7556182a60a38adeac076638c93b78b514278` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1BAF5335BF1AB47B3F7D9A931560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O1:iJiafuIO7rhWEES4G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_044_db76cb54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db76cb5443264f9db353d5a5dacb3aafb943e2938883737350889612ac90f431"
    family = "SalatStealer"
    file_name = "db76cb5443264f9d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:24:42"
  condition:
    hash.sha256(0, filesize) == "db76cb5443264f9db353d5a5dacb3aafb943e2938883737350889612ac90f431"
}
```

### Sample 45: `43d1a98eb1f0314e`

| Field | Value |
|---|---|
| SHA-256 | `43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-10 05:24:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `847bb758558ac5e8a82836b51cdf3e53` |
| SHA-1 | `0c1446e8202265ee240fb63cca31a7dfc69ac82a` |
| SHA-256 | `43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee` |
| SHA3-384 | `2b4bc4456731a6637786ce9fb203dc6d264ca4e1eb20458b51131125839ec053e149f403764a23361255da221b06767b` |
| TLSH | `T13D556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSi:SDjxB4m5n8XlaPWi+d+a4TjxQP4o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_43d1a98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 05:24:04"
  condition:
    hash.sha256(0, filesize) == "43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee"
}
```

### Sample 46: `810b14a04ffbf6e0`

| Field | Value |
|---|---|
| SHA-256 | `810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01` |
| Family label | `Mirai` |
| File name | `810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01.elf` |
| File type | `elf` |
| First seen | `2026-11-10 05:12:53` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5c40fe009f794f0e1bb10e8a1bb88ea` |
| SHA-1 | `b22214647898e18e098cf7b53b3bf16751a3324c` |
| SHA-256 | `810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01` |
| SHA3-384 | `e79ad0c48e743b0bc1cd4c13dc8f58554e0a0573cef47fe2a8bcba9a282a91ba87c37e37f0066427732e218eec28462b` |
| TLSH | `T1A5220D27F3D4DDFBC8AA5335499307713223C83ADB828383691C56593F9A29D1D65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOlx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeX+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_810b14a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01"
    family = "Mirai"
    file_name = "810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:12:53"
  condition:
    hash.sha256(0, filesize) == "810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01"
}
```

### Sample 47: `c3a3e04a39e3fcdf`

| Field | Value |
|---|---|
| SHA-256 | `c3a3e04a39e3fcdf764de3af3e27d027fefbb1233442622c29e6a03c93e534f0` |
| Family label | `Snowlight` |
| File name | `9297d061tcp` |
| File type | `elf` |
| First seen | `2026-11-10 05:11:20` |
| Reporter | `sheyam` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0a100db6a13a7135fd9049e8944c145` |
| SHA-1 | `45db18d63f421848744b3d32bdb50c3b42816c3b` |
| SHA-256 | `c3a3e04a39e3fcdf764de3af3e27d027fefbb1233442622c29e6a03c93e534f0` |
| SHA3-384 | `ec02afcffa37f10b114b1271063f0d6c00fa9eac23c5e91afd565ccbaca8618de35593a62f5aef1ecb64974317c39e2a` |
| TLSH | `T127123047A2D0CE3FC8D953384467122472B794BEDF629713064925B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6dH5ML09V1J9G8YmW+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHaZMWT1YmLhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_047_c3a3e04a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3a3e04a39e3fcdf764de3af3e27d027fefbb1233442622c29e6a03c93e534f0"
    family = "Snowlight"
    file_name = "9297d061tcp"
    file_type = "elf"
    first_seen = "2026-11-10 05:11:20"
  condition:
    hash.sha256(0, filesize) == "c3a3e04a39e3fcdf764de3af3e27d027fefbb1233442622c29e6a03c93e534f0"
}
```

### Sample 48: `8c43df6e0be47071`

| Field | Value |
|---|---|
| SHA-256 | `8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57` |
| Family label | `Snowlight` |
| File name | `8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57.elf` |
| File type | `elf` |
| First seen | `2026-11-10 05:08:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a867b56f9c4be5bc6a658a00a8baf5e` |
| SHA-1 | `31606abbd0d30a6e80c3f442125d312eab88de75` |
| SHA-256 | `8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57` |
| SHA3-384 | `d0878f60755aef1ee331f35940272985422829ff97fa85300c421467654d8c11c6cacc30b63c1253915b2440fa05704e` |
| TLSH | `T1DD123F47A2D0CE3FC8D953384867122472B794BADF629713064915B63F427E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8Ymz+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmChrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_048_8c43df6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57"
    family = "Snowlight"
    file_name = "8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:08:02"
  condition:
    hash.sha256(0, filesize) == "8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57"
}
```

### Sample 49: `af2cff1c6787f3fa`

| Field | Value |
|---|---|
| SHA-256 | `af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564` |
| Family label | `Mirai` |
| File name | `af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564.elf` |
| File type | `elf` |
| First seen | `2026-11-10 05:07:58` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7ba8954eb406902b0edd80eaabfe3d7` |
| SHA-1 | `ef64da0c1d31e248531c29e4036003fde871b17e` |
| SHA-256 | `af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564` |
| SHA3-384 | `b177afea64f4caae8173fb882d282ce4253ea800fc414450cd4427109e8e927a54f654db4f0d0755fb92aa1d227e16a0` |
| TLSH | `T1F2E15207E2D5CE72D8CD133847935749213AC86EAB83EF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccF3146iwz7cSym4S2ofahbpZiQ:fsue7cuJNFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_af2cff1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564"
    family = "Mirai"
    file_name = "af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:07:58"
  condition:
    hash.sha256(0, filesize) == "af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564"
}
```

### Sample 50: `aa56c8dd587df31e`

| Field | Value |
|---|---|
| SHA-256 | `aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de` |
| Family label | `Mirai` |
| File name | `aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de.elf` |
| File type | `elf` |
| First seen | `2026-11-10 05:07:54` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b54b667ce726108203458a9de37299c5` |
| SHA-1 | `bb63541ce55359bb8711562738a4dd8c0ac27f12` |
| SHA-256 | `aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de` |
| SHA3-384 | `4ee8894c78cf8199413e63d7557166c4ef576696247c4e32bb5a3879159fc57ebce94f734320bff90628ec90492f2a59` |
| TLSH | `T1E8124047A2D1CE7BC8E813384467122472BBD47ADFA29713050C65B66E923DC1E69F8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5flTTej6TNJ9V5Nddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WT/TTfTpVhdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_aa56c8dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de"
    family = "Mirai"
    file_name = "aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:07:54"
  condition:
    hash.sha256(0, filesize) == "aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de"
}
```

### Sample 51: `46f0050d595a6032`

| Field | Value |
|---|---|
| SHA-256 | `46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada` |
| Family label | `unknown` |
| File name | `46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada.exe` |
| File type | `exe` |
| First seen | `2026-11-10 05:05:35` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc7815796ad8750b75a3de522de3c060` |
| SHA-1 | `f195427b67263f4e7c5a32e6f87bd7236f0ae444` |
| SHA-256 | `46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada` |
| SHA3-384 | `2b073333ace4607f2724b335f7df5b1cc97a2858825e358172a7f6e36f0592a2cef085a862b2931180967db483ba3a86` |
| IMPHASH | `3622b980922646aab56e6b29f5558cba` |
| TLSH | `T1B24658571E296C61DC6549B64AB1CC3232AD3ACD6F2D89F030CE553296EFE0538E436E` |
| SSDEEP | `24576:hSw1tm2z8R0C+k6cCRh4JhlGUGGseZZSwUarLPFNpXjDsDX4qv:7EC7jcCRh4JhlmqSwbrL1DsDX4qv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_46f0050d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada"
    family = "unknown"
    file_name = "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada.exe"
    file_type = "exe"
    first_seen = "2026-11-10 05:05:35"
  condition:
    hash.sha256(0, filesize) == "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada"
}
```

### Sample 52: `daa7c4ba718d9020`

| Field | Value |
|---|---|
| SHA-256 | `daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d` |
| Family label | `unknown` |
| File name | `daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d.exe` |
| File type | `exe` |
| First seen | `2026-11-10 04:47:55` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5b82e5128a0ce0d8b0f9a312d668237` |
| SHA-1 | `db6cddfc8f9a6f759e67f667bfefc8e4c4312608` |
| SHA-256 | `daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d` |
| SHA3-384 | `36af25d71893011b85ca8f535dbbb9371eab24e606468fd9fda643b0575e31feac535ccb1633ce510e91dda0217d627b` |
| IMPHASH | `3622b980922646aab56e6b29f5558cba` |
| TLSH | `T11F4657571E296C61DC6549B64AB1CC3232AD3ACD6F2D89F030CE553296EFE0538E436E` |
| SSDEEP | `24576:vSw1tm2z8R0C+k6cCRh4JhlGUGGseZZSwUarLPFNpXjZ:JEC7jcCRh4JhlmqSwbrL1Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_daa7c4ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d"
    family = "unknown"
    file_name = "daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d.exe"
    file_type = "exe"
    first_seen = "2026-11-10 04:47:55"
  condition:
    hash.sha256(0, filesize) == "daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d"
}
```

### Sample 53: `b671c810f2d53607`

| Field | Value |
|---|---|
| SHA-256 | `b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437` |
| Family label | `Snowlight` |
| File name | `b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:45:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2cb9d0f75335f3ee69696656c6eacc9` |
| SHA-1 | `cf271f72deac4f4962f51c44a9ec59c760530299` |
| SHA-256 | `b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437` |
| SHA3-384 | `b6430cfa0bfdea4a105ddc01e6bcb62ddb1b8e6629884f9383b5c17fb01122ec82c358097f66acf9e675ae5cb4f6c807` |
| TLSH | `T192E17217E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw35Jheuhiq5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbpJhAkZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_053_b671c810
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437"
    family = "Snowlight"
    file_name = "b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:45:47"
  condition:
    hash.sha256(0, filesize) == "b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437"
}
```

### Sample 54: `5aeb7b5c1ea6f527`

| Field | Value |
|---|---|
| SHA-256 | `5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e` |
| Family label | `Snowlight` |
| File name | `5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:45:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e7d23420d897242362add89be3b5bf5` |
| SHA-1 | `76a3a9241b6492edef0c68b989fb8219ec51eb0c` |
| SHA-256 | `5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e` |
| SHA3-384 | `2b86a30c479acdaf6d6824ed3ffdc03777ab22a12e2c23502e76aff8352d1c8e6dc70aefbc10cc979443bebe1c6b6b1c` |
| TLSH | `T1F1123F47A2D0CE3FC8D953384467122472B794BEDF629713064925B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8Ymd+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmQhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_054_5aeb7b5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e"
    family = "Snowlight"
    file_name = "5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:45:43"
  condition:
    hash.sha256(0, filesize) == "5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e"
}
```

### Sample 55: `dd17dea02b20408c`

| Field | Value |
|---|---|
| SHA-256 | `dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f` |
| Family label | `Mirai` |
| File name | `dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:45:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0571f939f5c9038133d802f9df29f026` |
| SHA-1 | `59f3b7ee8700902308299669fbe6aeb671265863` |
| SHA-256 | `dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f` |
| SHA3-384 | `3b2fe8069d06637c9e149d56ae82ea307beee82ead8da6b3c0af9b0343faa975e1d8bb549f8ac07a41fa8d6fd811f6ac` |
| TLSH | `T1FE220D27F3D4DDFFC8AA5335899307713223C83ADB828383691C56593F9A29D1E65B84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOWx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeI+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_dd17dea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f"
    family = "Mirai"
    file_name = "dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:45:38"
  condition:
    hash.sha256(0, filesize) == "dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f"
}
```

### Sample 56: `04015ff8c06e35f9`

| Field | Value |
|---|---|
| SHA-256 | `04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528` |
| Family label | `unknown` |
| File name | `04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528.exe` |
| File type | `exe` |
| First seen | `2026-11-10 04:45:34` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `138be83ba7e46c6e341d13e403164220` |
| SHA-1 | `8f8f3b62d45d9a2da591af2ef2b6e4d20e34bcde` |
| SHA-256 | `04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528` |
| SHA3-384 | `953c8f97c246d318d82e10ac57f42f529cad5a164809542097c922e65358246d39bcee03188e253d2e98bd1844f06865` |
| IMPHASH | `7f0d5fc584598cd9bf6f8f2640b150df` |
| TLSH | `T188A6D30BB7048A8225734695D3D7E96EBF1FA5501215C96BADA1C102EC260CFCB36DFE` |
| SSDEEP | `49152:kG49s43bF9rba/QbyGJFcJlpmwn5lm6vGC:kGwjjfTOl/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_04015ff8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528"
    family = "unknown"
    file_name = "04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528.exe"
    file_type = "exe"
    first_seen = "2026-11-10 04:45:34"
  condition:
    hash.sha256(0, filesize) == "04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528"
}
```

### Sample 57: `92ae676dc54633c7`

| Field | Value |
|---|---|
| SHA-256 | `92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d` |
| Family label | `Mirai` |
| File name | `92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:42:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb903244af50dfc50303ef0fd9fd922f` |
| SHA-1 | `8231a7eb87645e9af250e3519889a554a450ba8c` |
| SHA-256 | `92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d` |
| SHA3-384 | `55977b4bd82ec231709a417323cd536688c10b01d675bc8a20f961f6022dfc9dcba7c2b97b9b5fe85157e429cf9498e4` |
| TLSH | `T1D4046C44F3A2CAF4F90380F5C52EE3259F354E296532AACFEFD532725D612124B67628` |
| TELFHASH | `t196214e02dfb7ecf4f32b48528231be081dad1d48fb22446042ea9dbe2d4810121edc27` |
| SSDEEP | `3072:gZXg/Jgeuoa0GCwX7Gwznsk/nVm6s110gna6RfhMZxtZ80Kbp:gZXMgeuoa0GCSo6gnxRfhoGF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_92ae676d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d"
    family = "Mirai"
    file_name = "92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:42:08"
  condition:
    hash.sha256(0, filesize) == "92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d"
}
```

### Sample 58: `217b3a2ff0d10801`

| Field | Value |
|---|---|
| SHA-256 | `217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da` |
| Family label | `Snowlight` |
| File name | `217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:42:04` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a95190ca93861b312349712895c3d733` |
| SHA-1 | `57227d15188f42fe48a2389e719ab05c7c8aa535` |
| SHA-256 | `217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da` |
| SHA3-384 | `505704e09f3331fa17d333c3081484b0fc9f9cc129f08c0c57b264e5ff5a3ab4e9b5f4ba374b6ad102e0db41fb5323ed` |
| TLSH | `T104123047A2D0CE3FC8D953384467122472B794BEDF629713064815B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6cH5ML09V1J9G8YmR+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHLZMWT1Ym8hrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_058_217b3a2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da"
    family = "Snowlight"
    file_name = "217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:42:04"
  condition:
    hash.sha256(0, filesize) == "217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da"
}
```

### Sample 59: `c29adb640900be55`

| Field | Value |
|---|---|
| SHA-256 | `c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d` |
| Family label | `Mirai` |
| File name | `c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:41:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f7933a1c1c6cb79d0d4985b6f4bcf40` |
| SHA-1 | `d299dfe0eccd952c3e0d1be4a2a144c84c6ed386` |
| SHA-256 | `c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d` |
| SHA3-384 | `babf44412ccf8016c1eedaae07513dc5db5b7d7d19eca1dc2511fd0e684ac325f02f5fe6c7f697fd589f571cdd512c13` |
| TLSH | `T15E125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5XlTTej6TNJ9VpNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTjTTfTpVRdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_c29adb64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d"
    family = "Mirai"
    file_name = "c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:59"
  condition:
    hash.sha256(0, filesize) == "c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d"
}
```

### Sample 60: `7432acb4dfeae3bf`

| Field | Value |
|---|---|
| SHA-256 | `7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208` |
| Family label | `unknown` |
| File name | `7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:41:55` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `237ed7655c3ecf8879fcbf4901828be8` |
| SHA-1 | `7c986c2c10153039fcdc30014daeff7ce65717e1` |
| SHA-256 | `7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208` |
| SHA3-384 | `3cfc5320fcbec8d7638abac3fc1f8876a32380a880b847023e3f31c55770adadef7ae041e1f5e875fff3a70992c56430` |
| TLSH | `T18E22EC17F3E5DDFFC8AA577409A713703223C836DB428783680C46543FAB29E6EA5644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOjtsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxjtsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_7432acb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208"
    family = "unknown"
    file_name = "7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:55"
  condition:
    hash.sha256(0, filesize) == "7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208"
}
```

### Sample 61: `5581413a198a4b78`

| Field | Value |
|---|---|
| SHA-256 | `5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24` |
| Family label | `Mirai` |
| File name | `5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:41:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df90a1dfbc8816be6a9b868a2e1ef733` |
| SHA-1 | `82aeebc3ec1c722ac98a67ccdeeb1f74de3cbe6d` |
| SHA-256 | `5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24` |
| SHA3-384 | `24a24a4a411261898cdba6c97ec1f93c6c1ee3817471b85d90f0e234d24764a7c17833df7bb70752bbe295896dc547a1` |
| TLSH | `T13C220D27F3D4DDFBC8AA5335899307713223C83ADB828383691C56593F9A29D1E65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOex+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeA+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_5581413a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24"
    family = "Mirai"
    file_name = "5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:51"
  condition:
    hash.sha256(0, filesize) == "5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24"
}
```

### Sample 62: `0e8e773ff96909ec`

| Field | Value |
|---|---|
| SHA-256 | `0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c` |
| Family label | `Mirai` |
| File name | `0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:41:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `446b786afcf0e149ad1e69e31cb2bce4` |
| SHA-1 | `edc474053b718e3d7ab2add3b4054ee3bf78eccb` |
| SHA-256 | `0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c` |
| SHA3-384 | `7666aa7f748e218e4486ae9d8c9ab6b7e7444fc80586f15ff82de2997ba0679887264232f02fd551f244cee637173272` |
| TLSH | `T15AF13456BAEBCD73CCAD233907678714337588D2AB42AB13511C08752D835EC6D76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtsWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7w4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_0e8e773f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c"
    family = "Mirai"
    file_name = "0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:47"
  condition:
    hash.sha256(0, filesize) == "0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c"
}
```

### Sample 63: `5b4c671e769da3e8`

| Field | Value |
|---|---|
| SHA-256 | `5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088` |
| Family label | `unknown` |
| File name | `5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:38:04` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a4aa7a44c92e8ffb978b4af9d92a45b` |
| SHA-1 | `5869152d45409a7e705e43fa623f47f1d78bb1a4` |
| SHA-256 | `5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088` |
| SHA3-384 | `5bb2467a6898a3c8d5db5c86901b46aa0709107d7b61a839bf37d19c28d07985ed588cee99116299c3242b91437387ea` |
| TLSH | `T11D22EC17F3E5DDFFC8AA577409A313703223C836DB428783680C46543FAB29E6EA5644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOgtsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxgtsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_5b4c671e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088"
    family = "unknown"
    file_name = "5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:38:04"
  condition:
    hash.sha256(0, filesize) == "5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088"
}
```

### Sample 64: `7394b5c1c1fc7d16`

| Field | Value |
|---|---|
| SHA-256 | `7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730` |
| Family label | `unknown` |
| File name | `7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:37:59` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37d291e237d04ffb5a635e87e2ad07d3` |
| SHA-1 | `6233af8460d8a777729bb29e0e13c792a7b360b4` |
| SHA-256 | `7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730` |
| SHA3-384 | `a576c434f0ef56943655f4e52a6e9dec7fb92f5bf2481e860b5d56a5d58c09fdee43a516382f45e02bf8363103bcbc2d` |
| TLSH | `T1ECE12482B9D6CE3BCCA9627A1673C6203372C551AB435B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScs6Lmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv/g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_7394b5c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730"
    family = "unknown"
    file_name = "7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:59"
  condition:
    hash.sha256(0, filesize) == "7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730"
}
```

### Sample 65: `36deac7e491848ac`

| Field | Value |
|---|---|
| SHA-256 | `36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d` |
| Family label | `Mirai` |
| File name | `36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:37:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54018fb76c67552a0cefc2c4428ce32b` |
| SHA-1 | `d653f40e97b54284915b50ba7327b536afb84ecc` |
| SHA-256 | `36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d` |
| SHA3-384 | `c489f3df3feccda43db1a89af06866181d38c2bc4b4854c2487bbcafbcb75e5fedac789eb892334803a0681ed5b74884` |
| TLSH | `T172F3AD448C1DF933EBC6E0BC4D5C0E54332B38F50575D7260E1256AEDC86A64ABA6BA2` |
| SSDEEP | `3072:UU+wv/8OZJeMT+jTyuUDlDhSdwR656S00hHniUegNtCAtFtzwGae:UU+OZzyjTUDFhSdwRa6S005njPxtFtz8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_36deac7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d"
    family = "Mirai"
    file_name = "36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:56"
  condition:
    hash.sha256(0, filesize) == "36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d"
}
```

### Sample 66: `baf0fb4822c28466`

| Field | Value |
|---|---|
| SHA-256 | `baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e` |
| Family label | `Mirai` |
| File name | `baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:37:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80c1be7b6f1c3932188603ee23b2e73d` |
| SHA-1 | `9212fcc96d75a62c9f369fe46d3643720c5f4b0f` |
| SHA-256 | `baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e` |
| SHA3-384 | `1941d38266b593ee7ca0303f082d32fe4e54ba2883cf4618d9fd8f9d08d1adf964ab98f262b928a1081fb37aab00e4e0` |
| TLSH | `T1EB221D27F3D4DDFFC8AA5335899303703223C83ADB828383691C56593F9A39D1E65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOSx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeE+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_baf0fb48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e"
    family = "Mirai"
    file_name = "baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:51"
  condition:
    hash.sha256(0, filesize) == "baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e"
}
```

### Sample 67: `a74aa4eda145ea8e`

| Field | Value |
|---|---|
| SHA-256 | `a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3` |
| Family label | `Snowlight` |
| File name | `a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:37:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `169aafa4afe700c4e4335f3c590290ee` |
| SHA-1 | `432c2a260522f7a692d5a3b4425dd87bb30a64f3` |
| SHA-256 | `a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3` |
| SHA3-384 | `fe3b27bfd9f91a2f6339a28d5d525b2570e4d331e0d99d1e44d1edb2fd39c01d51c02e2d41fc494b3c02cdb749a9e74f` |
| TLSH | `T111123F47A2D0CE3FC8D953384467122472B794BEDF629713064925B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6AH5ML09V1J9G8Ym6Y+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHLZMWT1YmehrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_067_a74aa4ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3"
    family = "Snowlight"
    file_name = "a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:47"
  condition:
    hash.sha256(0, filesize) == "a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3"
}
```

### Sample 68: `736e651c237482c7`

| Field | Value |
|---|---|
| SHA-256 | `736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61` |
| Family label | `Snowlight` |
| File name | `736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:35:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a29092d274755f5ced6b8653174c8862` |
| SHA-1 | `087d8af574d34dd6211fa7056ebd35d590654c1f` |
| SHA-256 | `736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61` |
| SHA3-384 | `a98bf174654dc4aff97fe3e6ae981f3b9e11605023e779d7a98301966cd7df4900b27fe1779a59267a33f7cc66e4e651` |
| TLSH | `T167E17117E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3PJheuhit5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb/JhALZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_068_736e651c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61"
    family = "Snowlight"
    file_name = "736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:45"
  condition:
    hash.sha256(0, filesize) == "736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61"
}
```

### Sample 69: `96679534563c1252`

| Field | Value |
|---|---|
| SHA-256 | `96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2` |
| Family label | `Mirai` |
| File name | `96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:35:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a5afb05b2a83f0272d8bd20d984569f` |
| SHA-1 | `f54ae8e86cb737ba0d9759e867c4f7a4476df15c` |
| SHA-256 | `96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2` |
| SHA3-384 | `4582858e3eddcf5e7b112e8056cd781a2cdf2b3d17be131f96d0cee3daad9b21b6abfb769da1a161732bdbd395ccef4b` |
| TLSH | `T18DE15207E2D5CE72D8CD133846935649213AC86EAA83AF03650C59A9EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFD146Ywz7cSym4S2ofahbpZiQ:fsue7c+JTFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_96679534
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2"
    family = "Mirai"
    file_name = "96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:41"
  condition:
    hash.sha256(0, filesize) == "96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2"
}
```

### Sample 70: `7946d78c45b95d19`

| Field | Value |
|---|---|
| SHA-256 | `7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db` |
| Family label | `Mirai` |
| File name | `7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:35:36` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d206aa85a60fec8e01f5721baac408b` |
| SHA-1 | `d5837f83c969d24ae53521bb1ccfb957e25b77d8` |
| SHA-256 | `7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db` |
| SHA3-384 | `3b79516fd4f1eafa713a7284d787c77befaec1f063b7eb30bd2de8db99fd510248a270ce7bfa5e6f557f60cba2c2432e` |
| TLSH | `T114F13256BAEBCD73CCAD233A07678714337588D2AB42AB13611C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtfWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7n4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_7946d78c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db"
    family = "Mirai"
    file_name = "7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:36"
  condition:
    hash.sha256(0, filesize) == "7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db"
}
```

### Sample 71: `18cfccb9751fb364`

| Field | Value |
|---|---|
| SHA-256 | `18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813` |
| Family label | `Snowlight` |
| File name | `18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:35:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dc60fa1b3263596443ce466795825fd` |
| SHA-1 | `22a23522dce37b95bcd126efccd4174c70e27f1c` |
| SHA-256 | `18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813` |
| SHA3-384 | `bd389d52e3d7eb937c518ea828b97450209562490cd5b1137ed6302d6b7a2cc80da9dd95b31bc8597813654e214226b9` |
| TLSH | `T194E17217E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw38JheuhiO5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbMJhA4Zz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_071_18cfccb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813"
    family = "Snowlight"
    file_name = "18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:32"
  condition:
    hash.sha256(0, filesize) == "18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813"
}
```

### Sample 72: `0df7085c617e7985`

| Field | Value |
|---|---|
| SHA-256 | `0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e` |
| Family label | `unknown` |
| File name | `0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:32:54` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d5a8734c714875d0b6a89db94c411e0` |
| SHA-1 | `f3f205a724b74ba4288d1073d3daca71166d7510` |
| SHA-256 | `0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e` |
| SHA3-384 | `36bfe38bbc58407129f129dcece6416ae085d359d97acca1cce0e677e0f937849dcb51a2db429585891edb0b7176085e` |
| TLSH | `T13CE12382B9D6CE3BCCE9627A1673C6203372C951AB439B17210C48753D83AEC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScseiLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSveHg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_0df7085c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e"
    family = "unknown"
    file_name = "0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:32:54"
  condition:
    hash.sha256(0, filesize) == "0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e"
}
```

### Sample 73: `d151a57be07413a8`

| Field | Value |
|---|---|
| SHA-256 | `d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53` |
| Family label | `unknown` |
| File name | `d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:32:50` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb11b9f673ddbc8304e4a01e5bf99ddd` |
| SHA-1 | `4263322f51c3b3a29b379aa7ec49585d60ad68a0` |
| SHA-256 | `d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53` |
| SHA3-384 | `903d33b78b3887b17cac1f929a6631f09f5f401c5c7794bdd6885d9a07fc8792e4b68edefc283dcc046d36b9fc6e20ad` |
| TLSH | `T1F2E14482BED6CE3BCCA9627A1673C6203372C551AB439B07210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsmLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv7g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_d151a57b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53"
    family = "unknown"
    file_name = "d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:32:50"
  condition:
    hash.sha256(0, filesize) == "d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53"
}
```

### Sample 74: `55e5ca1799ae391f`

| Field | Value |
|---|---|
| SHA-256 | `55e5ca1799ae391f1bbaa0e8d1ed42015eb60a0f3122d7c9cd113266369a4e0e` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-10 04:30:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1a3c1a59fe45b0f30d176c163263e77` |
| SHA-1 | `d84be2091ce2d09e5b78f118a49fe2f6cf7df378` |
| SHA-256 | `55e5ca1799ae391f1bbaa0e8d1ed42015eb60a0f3122d7c9cd113266369a4e0e` |
| SHA3-384 | `bd376595cc2fe210b5540dfcc553aac47d621f04ebbf43d47c93f25247feaab09b845a6c78ab1e8407d8f8f5587ecfc3` |
| TLSH | `T167556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSm:SDjxB4m5n8XlaPWi+d+a4TjxQP4w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_55e5ca17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e5ca1799ae391f1bbaa0e8d1ed42015eb60a0f3122d7c9cd113266369a4e0e"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 04:30:07"
  condition:
    hash.sha256(0, filesize) == "55e5ca1799ae391f1bbaa0e8d1ed42015eb60a0f3122d7c9cd113266369a4e0e"
}
```

### Sample 75: `c1c9a71b3d352a98`

| Field | Value |
|---|---|
| SHA-256 | `c1c9a71b3d352a9842c32d85cda78226cb7e45c496f7b4333032ab84399001bc` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-11-10 04:30:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `652a212e5434dc6159272ff638c2f64e` |
| SHA-1 | `9dbcb3b8d3066be9d7474908e64135689fc74795` |
| SHA-256 | `c1c9a71b3d352a9842c32d85cda78226cb7e45c496f7b4333032ab84399001bc` |
| SHA3-384 | `f729cbd0508ae6c367b992d2acc6c4981b6b478040c57de9d90427d618efd981b7d50e1004869ec0a18470c983a66d05` |
| TLSH | `T108841A88A1F0E7DED2D4EA75B31D784D3B230736B1D73146A51DAA3333EB1490AB9921` |
| TELFHASH | `t1aef050a0e7ff140da7e6806b03d6d2175e581d1417a720eb4a057b479e44e507fc6e32` |
| SSDEEP | `6144:tgDE6JtoQ57ySQp+03Jmhsg0/kCghLIeEwuiiUx4aca927krK:n6LoQ5OH/3JFMCqHi6oa92QO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_c1c9a71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1c9a71b3d352a9842c32d85cda78226cb7e45c496f7b4333032ab84399001bc"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-11-10 04:30:04"
  condition:
    hash.sha256(0, filesize) == "c1c9a71b3d352a9842c32d85cda78226cb7e45c496f7b4333032ab84399001bc"
}
```

### Sample 76: `3b11b084a847abd5`

| Field | Value |
|---|---|
| SHA-256 | `3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf` |
| Family label | `Snowlight` |
| File name | `3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:28:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a5cfd25a131001803e38c30124a9735` |
| SHA-1 | `e81d683e11334bca61d2af9d0127e3a052508805` |
| SHA-256 | `3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf` |
| SHA3-384 | `6a87081d56f07f50e2e1fa77f6b930c3571cd45617855a74e56bf5ce1125c66c9a44f45e312d705d82625eb721065628` |
| TLSH | `T199E17117E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3xJheuhilX5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbBJhArZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_076_3b11b084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf"
    family = "Snowlight"
    file_name = "3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:28:03"
  condition:
    hash.sha256(0, filesize) == "3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf"
}
```

### Sample 77: `b60ce85101c04d84`

| Field | Value |
|---|---|
| SHA-256 | `b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5` |
| Family label | `Snowlight` |
| File name | `b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:27:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c9afe880cbef92326ab1ba2d809a17e` |
| SHA-1 | `8bee699fb985a6705ab7ed91c2c0e4d2c6b1de75` |
| SHA-256 | `b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5` |
| SHA3-384 | `b00142d16daca3b867fa6ce61e480474ebd54cfb1f0de96c16c89dd853f48a1f92beb9b9e7e12d3f9b7b14e5abb402ea` |
| TLSH | `T105123047A2D0CE3FC8D953384467122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8YmS+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmfhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_077_b60ce851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5"
    family = "Snowlight"
    file_name = "b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:59"
  condition:
    hash.sha256(0, filesize) == "b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5"
}
```

### Sample 78: `2d6f187bec9175d7`

| Field | Value |
|---|---|
| SHA-256 | `2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d` |
| Family label | `Mirai` |
| File name | `2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:27:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cea9053a161bd1feb70ebc445e9c8e7d` |
| SHA-1 | `2010df9ed19b4296c75beeade4dd41415c673558` |
| SHA-256 | `2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d` |
| SHA3-384 | `09b778021fe9bd6e7cb97cdd78242c35e7c35c085d04c244aa7236691bd990b58701fe21c6fdc128327c91d9481c5ab7` |
| TLSH | `T16B0417A2BD42D562C5D429FBEA2E84CC338313A8C6EF7112CD15DB3561DF9890B3AE45` |
| SSDEEP | `3072:YjxiQ28Opo1PBbnmjRyuV4yshhEv/GibTDoXyOPQD35UdVI7:YjoQ3Wo1Ppuqj/EHLbXZOPi35UdVI7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_2d6f187b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d"
    family = "Mirai"
    file_name = "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:55"
  condition:
    hash.sha256(0, filesize) == "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d"
}
```

### Sample 79: `887594990c6d5138`

| Field | Value |
|---|---|
| SHA-256 | `887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c` |
| Family label | `unknown` |
| File name | `887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:27:51` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d7b6a5e94d38b7f471bc617a4df8317` |
| SHA-1 | `811680ef84a3fae91a64e8be7ec4f276a4567c32` |
| SHA-256 | `887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c` |
| SHA3-384 | `548b9219675b5cb5ee795259cf99cc95e4edb6bfeff486309df905bdc2b657db78a7dd9278d0d0c876047a33c1af23a0` |
| TLSH | `T165E144827DD6CE3BCCE962761673C6203372C551AB435B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsEGLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvEbg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_88759499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c"
    family = "unknown"
    file_name = "887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:51"
  condition:
    hash.sha256(0, filesize) == "887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c"
}
```

### Sample 80: `4ffd8f09debd7ae6`

| Field | Value |
|---|---|
| SHA-256 | `4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355` |
| Family label | `unknown` |
| File name | `4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:27:47` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcca0af3becc864993b6b803f5448b43` |
| SHA-1 | `f844b2c775abee7e74739aa7b5a6dead2f9c08de` |
| SHA-256 | `4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355` |
| SHA3-384 | `5ca9ea07934d4c4a8e8f3180d3b6fddebac04f15c5ec9b78f1b5f66f351812ed662f579dc190d084d464192fd6fde43d` |
| TLSH | `T14922EC17F3E5DDFFC8AA577409A312703223C836DB428783680C46547FAB29E6EA5744` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOatsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxatsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_4ffd8f09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355"
    family = "unknown"
    file_name = "4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:47"
  condition:
    hash.sha256(0, filesize) == "4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355"
}
```

### Sample 81: `79bee467cd57ef13`

| Field | Value |
|---|---|
| SHA-256 | `79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af` |
| Family label | `Mirai` |
| File name | `79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:27:43` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `245ffc9f45364f5f3f859b83be2c3e00` |
| SHA-1 | `368466c2e76314e2b648b9f1015e36f83c98dd1d` |
| SHA-256 | `79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af` |
| SHA3-384 | `bcf8b14985c7c198cf2a8a258cc19391127bb89b98226d3328261d4190b74bd3bd8a125858ce5f7c41312ead3b0fd6a8` |
| TLSH | `T1FBF13356BAEBCD73CCAD233907678714337588D2AB42AB13511C08752D835EC9D76AE1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtRWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7N4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_79bee467
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af"
    family = "Mirai"
    file_name = "79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:43"
  condition:
    hash.sha256(0, filesize) == "79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af"
}
```

### Sample 82: `f1f894b6d0c6c6b0`

| Field | Value |
|---|---|
| SHA-256 | `f1f894b6d0c6c6b0cbb2438e312ee37cfc3213b007f3bcf310663ab2d1556c15` |
| Family label | `SalatStealer` |
| File name | `cab11db1e1bddd1f.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:27:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b29ec34c466eb8c75558486d8be29fb` |
| SHA-1 | `fdd5997d12c4a3a211600b5790cd32d912e9c432` |
| SHA-256 | `f1f894b6d0c6c6b0cbb2438e312ee37cfc3213b007f3bcf310663ab2d1556c15` |
| SHA3-384 | `3acd3dfe3de21c36a1170760c5814e2fac3589b597169a9deabbedf168d7d5587b4f7d82af1f924bb153dfdc5d021c34` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T17DC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+/:yBkKr5rszpNDy+/` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_082_f1f894b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1f894b6d0c6c6b0cbb2438e312ee37cfc3213b007f3bcf310663ab2d1556c15"
    family = "SalatStealer"
    file_name = "cab11db1e1bddd1f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:27:35"
  condition:
    hash.sha256(0, filesize) == "f1f894b6d0c6c6b0cbb2438e312ee37cfc3213b007f3bcf310663ab2d1556c15"
}
```

### Sample 83: `0739c017f0c09a01`

| Field | Value |
|---|---|
| SHA-256 | `0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511` |
| Family label | `Mirai` |
| File name | `0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:27:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36229142c512dbba830c917e16120e5a` |
| SHA-1 | `e8ed48784ce3e937165e0cb3c90084d175e21548` |
| SHA-256 | `0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511` |
| SHA3-384 | `d51fac2e50a70d4d3709386cad91c30ff853586de748c5d3a7a6cbb2f419e86caa62a7cdb9c633c8dd040f03bd640c0c` |
| TLSH | `T1D5F15256BAEBCD73CCAD233A07678714337588D2AB42AB13610C08752D835ECAD76BD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtYWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7M4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_0739c017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511"
    family = "Mirai"
    file_name = "0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:03"
  condition:
    hash.sha256(0, filesize) == "0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511"
}
```

### Sample 84: `d802f765cafc8b68`

| Field | Value |
|---|---|
| SHA-256 | `d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b` |
| Family label | `unknown` |
| File name | `d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:26:59` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `556074f27ec97bc3908f15b9e9b08916` |
| SHA-1 | `4283310d87c0c274de1756bc3cf1fc31ff2ced07` |
| SHA-256 | `d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b` |
| SHA3-384 | `b18139b8ca9974868733da52ba70edfc430cfaa57a24557b485518a7158035bae5975bbc9fb2abd35083e24c9bf892d1` |
| TLSH | `T129E13382B9D6CE3BCCE9627A1673C6203372C551AB439B17210C48753DC3AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsXLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvKg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_d802f765
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b"
    family = "unknown"
    file_name = "d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:26:59"
  condition:
    hash.sha256(0, filesize) == "d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b"
}
```

### Sample 85: `39893a47ffab2a6b`

| Field | Value |
|---|---|
| SHA-256 | `39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273` |
| Family label | `unknown` |
| File name | `39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:26:56` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c56242df1e1609b055c350d7f69a294` |
| SHA-1 | `cc5cd3dd13e2250177e1622b54a6be63cc4fbad1` |
| SHA-256 | `39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273` |
| SHA3-384 | `b45c1d8e9b58db4b064874e4187c37fa40b2adf89320e5802bfab155fc4ce70cc9efd4b718a0514b51c7d9517ce7c66c` |
| TLSH | `T1A4E12382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AAC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScspLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv0g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_39893a47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273"
    family = "unknown"
    file_name = "39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:26:56"
  condition:
    hash.sha256(0, filesize) == "39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273"
}
```

### Sample 86: `219b6e9db2bdc69a`

| Field | Value |
|---|---|
| SHA-256 | `219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3` |
| Family label | `unknown` |
| File name | `219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3.exe` |
| File type | `exe` |
| First seen | `2026-11-10 04:26:52` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2b3d524668cdd46f804f1c0acd84864` |
| SHA-1 | `c737d3e3463f4a6bbf93525c78d37effa3e044fd` |
| SHA-256 | `219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3` |
| SHA3-384 | `a07cd38a518068db085c8c9a9144c0d57ec346c80ddc30075c4a762c463588fd11ceca71af8b0c7094ae7bfadb1b9270` |
| IMPHASH | `7db2d54ca01ba36711a5cdd365f15145` |
| TLSH | `T1E62701DA38D5507DC092C735D28A5AFDF08A79894D799C1BBFC359002E32C96C8B6B36` |
| SSDEEP | `393216:d5hhMT+QkCwnv7825Fm5foe1Mh0/T2R9gqZ:d3hMT+zLWoe1MKC+u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_219b6e9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3"
    family = "unknown"
    file_name = "219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3.exe"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:52"
  condition:
    hash.sha256(0, filesize) == "219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3"
}
```

### Sample 87: `01a9a86f49f19916`

| Field | Value |
|---|---|
| SHA-256 | `01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc` |
| Family label | `Mirai` |
| File name | `01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:26:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b48be28e32e603ebb793669af7a2069` |
| SHA-1 | `12f7f44cb3826db6c01baef3c7eff8b1ed0359e3` |
| SHA-256 | `01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc` |
| SHA3-384 | `d5677b6c4143b6860514ab49fad16e11c8117f14a955a5ed3696ad790c4e738f382e00564fa1bc55ef11d302fb120381` |
| TLSH | `T19FE15207E2D5CD72D8CD133846931649213AC86EAB83EF03650C1999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFX146mwz7cSym4S2ofahbpZiQ:fsue7cCJRFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_01a9a86f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc"
    family = "Mirai"
    file_name = "01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:26:45"
  condition:
    hash.sha256(0, filesize) == "01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc"
}
```

### Sample 88: `120b0f04b8bbf228`

| Field | Value |
|---|---|
| SHA-256 | `120b0f04b8bbf228d4d69becd5df17e2ec34bd767f9c62f6eaa0845a06c8a099` |
| Family label | `SalatStealer` |
| File name | `ef4deb82197fbb20.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:26:34` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0281e93a164e495039dea8e92aa21c0a` |
| SHA-1 | `8ff9c04f06fb4e373d008bc7433baaf1dd3935d9` |
| SHA-256 | `120b0f04b8bbf228d4d69becd5df17e2ec34bd767f9c62f6eaa0845a06c8a099` |
| SHA3-384 | `862ccebac98b5439d003638a12b238c42d830c3816b1b0083293402b1bcc01a3b70be9313a10f1d45e70e03ee164c747` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1ECC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+x:yBkKr5rszpNDy+x` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_088_120b0f04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "120b0f04b8bbf228d4d69becd5df17e2ec34bd767f9c62f6eaa0845a06c8a099"
    family = "SalatStealer"
    file_name = "ef4deb82197fbb20.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:34"
  condition:
    hash.sha256(0, filesize) == "120b0f04b8bbf228d4d69becd5df17e2ec34bd767f9c62f6eaa0845a06c8a099"
}
```

### Sample 89: `fa986ddc6abf619e`

| Field | Value |
|---|---|
| SHA-256 | `fa986ddc6abf619ebb0e7f8591810fd77cf85d9cc68f8392270310d8d6510635` |
| Family label | `SalatStealer` |
| File name | `48f58ccc90cfa36a.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:26:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `194936881c857ea7432de49c240296ae` |
| SHA-1 | `205abe20565da4ed4a32288a41d7ed9332988d49` |
| SHA-256 | `fa986ddc6abf619ebb0e7f8591810fd77cf85d9cc68f8392270310d8d6510635` |
| SHA3-384 | `f47ffc73de1cced6a1b24e16f5675390a83b3f90e97f0310bbed6a75fa3277440ef991bfd62aa7538dfc9afda77924a6` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A0C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+6:yBkKr5rszpNDy+6` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_089_fa986ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa986ddc6abf619ebb0e7f8591810fd77cf85d9cc68f8392270310d8d6510635"
    family = "SalatStealer"
    file_name = "48f58ccc90cfa36a.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:29"
  condition:
    hash.sha256(0, filesize) == "fa986ddc6abf619ebb0e7f8591810fd77cf85d9cc68f8392270310d8d6510635"
}
```

### Sample 90: `bb0bbaf8a6d50ae7`

| Field | Value |
|---|---|
| SHA-256 | `bb0bbaf8a6d50ae7a02ef729c919b391b06a0694f3b2f139b47ad4271d520bae` |
| Family label | `SalatStealer` |
| File name | `4bae9ef0bb222c7f.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:26:24` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fba1ea6c5c7094511cd33c845157a4bc` |
| SHA-1 | `0d5c34fa0d9883b7b6b4857c35455b01f0d48ee5` |
| SHA-256 | `bb0bbaf8a6d50ae7a02ef729c919b391b06a0694f3b2f139b47ad4271d520bae` |
| SHA3-384 | `e787d94350a36be485a33fb9769debe89de3a0931a13714a3b22b09efade79b392ccdc6180bc2642eb4b8d5f520ad48b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T16CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+i:yBkKr5rszpNDy+i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_090_bb0bbaf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0bbaf8a6d50ae7a02ef729c919b391b06a0694f3b2f139b47ad4271d520bae"
    family = "SalatStealer"
    file_name = "4bae9ef0bb222c7f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:24"
  condition:
    hash.sha256(0, filesize) == "bb0bbaf8a6d50ae7a02ef729c919b391b06a0694f3b2f139b47ad4271d520bae"
}
```

### Sample 91: `cab11db1e1bddd1f`

| Field | Value |
|---|---|
| SHA-256 | `cab11db1e1bddd1f1d387b8432a8bf5e16c3bb59471db84c5f4c5995168457a8` |
| Family label | `SalatStealer` |
| File name | `cab11db1e1bddd1f.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:26:19` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3283f0b5fd9f62db055e09008d883fd` |
| SHA-1 | `121566bcde4269045a2f6c0ce7488207d1f0b040` |
| SHA-256 | `cab11db1e1bddd1f1d387b8432a8bf5e16c3bb59471db84c5f4c5995168457a8` |
| SHA3-384 | `21d91a63b9d1f1ff39ef697aac641775326c01493026a2efaad027d8568ce0deed950483fd70c7bdbca9d1989b2cb6a3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T172F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OD:iJiafuIO7rhWEES4E` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_091_cab11db1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab11db1e1bddd1f1d387b8432a8bf5e16c3bb59471db84c5f4c5995168457a8"
    family = "SalatStealer"
    file_name = "cab11db1e1bddd1f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:19"
  condition:
    hash.sha256(0, filesize) == "cab11db1e1bddd1f1d387b8432a8bf5e16c3bb59471db84c5f4c5995168457a8"
}
```

### Sample 92: `ef4deb82197fbb20`

| Field | Value |
|---|---|
| SHA-256 | `ef4deb82197fbb205be15785bf967f1631628e1dce4d8fb58b4d2deacd2f142b` |
| Family label | `SalatStealer` |
| File name | `ef4deb82197fbb20.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:26:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `954ab24a9852ab36f4c6eadd3ceb5f07` |
| SHA-1 | `1f663e541b2a1e1e88324810e85b9d7387bc26c0` |
| SHA-256 | `ef4deb82197fbb205be15785bf967f1631628e1dce4d8fb58b4d2deacd2f142b` |
| SHA3-384 | `122678fe7862e6ddcc4e204ee0c659e8dff00f2a027b7f61ec5d20620f82df947948af5a0d7f173c4642a88eaf794ea4` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T193F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OF:iJiafuIO7rhWEES4+` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_092_ef4deb82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef4deb82197fbb205be15785bf967f1631628e1dce4d8fb58b4d2deacd2f142b"
    family = "SalatStealer"
    file_name = "ef4deb82197fbb20.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:09"
  condition:
    hash.sha256(0, filesize) == "ef4deb82197fbb205be15785bf967f1631628e1dce4d8fb58b4d2deacd2f142b"
}
```

### Sample 93: `48f58ccc90cfa36a`

| Field | Value |
|---|---|
| SHA-256 | `48f58ccc90cfa36a8ef2cdd9f7d28f17f2c659aacc270d6ec9e28dcbc5924bf7` |
| Family label | `SalatStealer` |
| File name | `48f58ccc90cfa36a.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:25:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f248cda584dcc37b0c5127c907ea2b7` |
| SHA-1 | `3637b2530e1aaffb3b0be1f6c06013ce0968ca06` |
| SHA-256 | `48f58ccc90cfa36a8ef2cdd9f7d28f17f2c659aacc270d6ec9e28dcbc5924bf7` |
| SHA3-384 | `907d69c1d245c74f84e819dd59a7260c002220b42cba10e2072d897e1e03daaea369b7687019addf37a7b0e710d7f9da` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T191F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OG:iJiafuIO7rhWEES4x` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_093_48f58ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f58ccc90cfa36a8ef2cdd9f7d28f17f2c659aacc270d6ec9e28dcbc5924bf7"
    family = "SalatStealer"
    file_name = "48f58ccc90cfa36a.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:25:58"
  condition:
    hash.sha256(0, filesize) == "48f58ccc90cfa36a8ef2cdd9f7d28f17f2c659aacc270d6ec9e28dcbc5924bf7"
}
```

### Sample 94: `4bae9ef0bb222c7f`

| Field | Value |
|---|---|
| SHA-256 | `4bae9ef0bb222c7fa8f82cd0b91b3346335c2df9cf6284d72ecb2842b2194c27` |
| Family label | `SalatStealer` |
| File name | `4bae9ef0bb222c7f.bin` |
| File type | `exe` |
| First seen | `2026-11-10 04:25:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0536fc72a470b5f71cdfed5ef8b994f1` |
| SHA-1 | `05b4af5efbd0d0e37329eee900fd44d49ca6068d` |
| SHA-256 | `4bae9ef0bb222c7fa8f82cd0b91b3346335c2df9cf6284d72ecb2842b2194c27` |
| SHA3-384 | `17d98d9f4b373fcf33af8a258ad934dd270f6ac1df13a474e328c9e172445f41b1bce5a85ff6c7e197a063710b9576fd` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T146F5335BF1AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OO:iJiafuIO7rhWEES4x` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_094_4bae9ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bae9ef0bb222c7fa8f82cd0b91b3346335c2df9cf6284d72ecb2842b2194c27"
    family = "SalatStealer"
    file_name = "4bae9ef0bb222c7f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:25:47"
  condition:
    hash.sha256(0, filesize) == "4bae9ef0bb222c7fa8f82cd0b91b3346335c2df9cf6284d72ecb2842b2194c27"
}
```

### Sample 95: `c81508bcc3318920`

| Field | Value |
|---|---|
| SHA-256 | `c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414` |
| Family label | `Mirai` |
| File name | `c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:25:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f931ef83c07c588b9e8838bf9186254` |
| SHA-1 | `42a8ab1dfa2bc8d4bf2d3b8408cc60adbf6ac076` |
| SHA-256 | `c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414` |
| SHA3-384 | `62ad234fffa1ffd92d664a4dca16b5fa849f3855addb300248b176a249ca5d1a2531e50dac61bd1792c83c9c740dc135` |
| TLSH | `T11CF13256BAEBCD73CCAD233A07678714337588D2AF42AB13611C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8Dt4WC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7A4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_c81508bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414"
    family = "Mirai"
    file_name = "c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:44"
  condition:
    hash.sha256(0, filesize) == "c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414"
}
```

### Sample 96: `b94c00bdd31c218b`

| Field | Value |
|---|---|
| SHA-256 | `b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7` |
| Family label | `Snowlight` |
| File name | `b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:25:40` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f1f410a9bbfc84a114c0b09414d1ab7` |
| SHA-1 | `f4cffc06b7c00c5f6d192e5e4007f64c774b97b3` |
| SHA-256 | `b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7` |
| SHA3-384 | `d962a1770e323edd3fc31a8efddb749543237b8c7653afe6c48e26b6d27391d3eda35c58aa63a1d0d433b7229ed91e40` |
| TLSH | `T17EE17117E2E2CD32D8D4137E55930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3jJheuhia15Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbzJhACZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_096_b94c00bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7"
    family = "Snowlight"
    file_name = "b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:40"
  condition:
    hash.sha256(0, filesize) == "b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7"
}
```

### Sample 97: `3101a03f77da98c6`

| Field | Value |
|---|---|
| SHA-256 | `3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7` |
| Family label | `Mirai` |
| File name | `3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:25:36` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d171b0ad7ccba96bcbd05f7a1daebbb` |
| SHA-1 | `482b4931a0017bce0ff3bf448f75d37af427b0b5` |
| SHA-256 | `3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7` |
| SHA3-384 | `ada490f67a01b248a4fbdb37eaabcecd4c5a40ad4c9b21ccfdedd8a398b01942eecd3e3a9541806d4402203369e09cf4` |
| TLSH | `T197E15207E2D5CD72D8CD133846935749213AC86EAB83AF03650C59A9EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFB146nwz7cSym4S2ofahbpZiQ:fsue7ckJwFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_3101a03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7"
    family = "Mirai"
    file_name = "3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:36"
  condition:
    hash.sha256(0, filesize) == "3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7"
}
```

### Sample 98: `c14632daafa8db8f`

| Field | Value |
|---|---|
| SHA-256 | `c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98` |
| Family label | `unknown` |
| File name | `c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:25:32` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6127b01f11fab59ffc0af61842881554` |
| SHA-1 | `93a77561a12067f4cc4ba9ac4e451676798aad2f` |
| SHA-256 | `c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98` |
| SHA3-384 | `6e8161aa2f2eba1fa973e312380f2603ca14e07cf15054e59d1e368f4cbf681f04a275be0568323f1b62620a69c8ce44` |
| TLSH | `T121E13482BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AACAD76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsoLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvVg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_c14632da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98"
    family = "unknown"
    file_name = "c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:32"
  condition:
    hash.sha256(0, filesize) == "c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98"
}
```

### Sample 99: `e247d8d5e2ae118a`

| Field | Value |
|---|---|
| SHA-256 | `e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf` |
| Family label | `Mirai` |
| File name | `e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:25:28` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf8e5ab70bde183dc320c51bb08a4a38` |
| SHA-1 | `440d66b389b5168d62ac52936e51a2926a0496d4` |
| SHA-256 | `e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf` |
| SHA3-384 | `aab0ff8521114807f27b5ae8d8303b75b6adaa6b8f6b95df53440371b50d54a14e868b1d683f8bacea2b3cc2656dcae4` |
| TLSH | `T18A220D27F3D4DDFFC8AA5335899307713223C83ADB828383691C56593F9A39D1E65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMO5x+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7Zer+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_e247d8d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf"
    family = "Mirai"
    file_name = "e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:28"
  condition:
    hash.sha256(0, filesize) == "e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf"
}
```

### Sample 100: `8604654d71ece602`

| Field | Value |
|---|---|
| SHA-256 | `8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1` |
| Family label | `Mirai` |
| File name | `8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1.elf` |
| File type | `elf` |
| First seen | `2026-11-10 04:25:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce5ece6f61bb0b95eab441c859d1a472` |
| SHA-1 | `155beecbdf6519211b6901adf39fa982e4b6b6ea` |
| SHA-256 | `8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1` |
| SHA3-384 | `957da24cdb0b25e5031bf8eaa663d04d2d6788d61389fc130296f44aaf3edb939581b779728f37d65f74e49b5932cb50` |
| TLSH | `T170F13356BAEBCD73CCAD233A07678714337588D2AB42AB13511C08752D835ECAD76AE1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8Dt6WC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7C4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_8604654d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1"
    family = "Mirai"
    file_name = "8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:24"
  condition:
    hash.sha256(0, filesize) == "8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1"
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
 * Generated: 2026-11-10T07:28:27.535077+00:00
 */

rule MalwareBazaar_unknown_001_5c27a1ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c27a1ac83352bea46340240aa313262668468acf2e9f8f416a88060865e6fd1"
    family = "unknown"
    file_name = "4feb056b9600f66e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 07:25:20"
  condition:
    hash.sha256(0, filesize) == "5c27a1ac83352bea46340240aa313262668468acf2e9f8f416a88060865e6fd1"
}

rule MalwareBazaar_SalatStealer_002_4feb056b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4feb056b9600f66e6c588f3246936d6d97fefc1d1fa94f6e5bfd2f6a30b81d6b"
    family = "SalatStealer"
    file_name = "4feb056b9600f66e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 07:24:49"
  condition:
    hash.sha256(0, filesize) == "4feb056b9600f66e6c588f3246936d6d97fefc1d1fa94f6e5bfd2f6a30b81d6b"
}

rule MalwareBazaar_unknown_003_889579ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed"
    family = "unknown"
    file_name = "889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed"
    file_type = "sh"
    first_seen = "2026-11-10 07:23:36"
  condition:
    hash.sha256(0, filesize) == "889579cea97143619b46b172db127a829dccf95e2c2a14569d882fd045fdbeed"
}

rule MalwareBazaar_Mirai_004_97694582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97694582ff2f9ab78298861ec13149a3828ca59e3c671c73b8dd04e217c4355c"
    family = "Mirai"
    file_name = "reflex.arm"
    file_type = "elf"
    first_seen = "2026-11-10 07:23:06"
  condition:
    hash.sha256(0, filesize) == "97694582ff2f9ab78298861ec13149a3828ca59e3c671c73b8dd04e217c4355c"
}

rule MalwareBazaar_Mirai_005_0c9c2120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c9c2120bc387461243e9768a610c608ae34baa9049f44116c965afc731485e5"
    family = "Mirai"
    file_name = "reflex.arm7"
    file_type = "elf"
    first_seen = "2026-11-10 07:23:03"
  condition:
    hash.sha256(0, filesize) == "0c9c2120bc387461243e9768a610c608ae34baa9049f44116c965afc731485e5"
}

rule MalwareBazaar_Mirai_006_a39d5be8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a39d5be80000760a5e7676062e0e67a31b9bc4594f2b7e893eb246767f4cff3b"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:25"
  condition:
    hash.sha256(0, filesize) == "a39d5be80000760a5e7676062e0e67a31b9bc4594f2b7e893eb246767f4cff3b"
}

rule MalwareBazaar_Mirai_007_2e13f7c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e13f7c268911c9bb3b7ebc1630715c6ce655c10517b98c179f65842dd287510"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:05"
  condition:
    hash.sha256(0, filesize) == "2e13f7c268911c9bb3b7ebc1630715c6ce655c10517b98c179f65842dd287510"
}

rule MalwareBazaar_Mirai_008_ba81d039
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba81d03982d85ecc018ca5e7afa6a1157069a92825798b05f2a3f6195bc30f01"
    family = "Mirai"
    file_name = "lavax.arm"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:03"
  condition:
    hash.sha256(0, filesize) == "ba81d03982d85ecc018ca5e7afa6a1157069a92825798b05f2a3f6195bc30f01"
}

rule MalwareBazaar_Mirai_009_a03bd650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a03bd6503e8b181697a7e3717b09f36aa0c001eadb381fb3d32515d6c2a509be"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-11-10 07:10:00"
  condition:
    hash.sha256(0, filesize) == "a03bd6503e8b181697a7e3717b09f36aa0c001eadb381fb3d32515d6c2a509be"
}

rule MalwareBazaar_unknown_010_9d180f0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d180f0e5dff2a2211b853fc28aac6c8b5b8b970e98d7746f016a60d8a616849"
    family = "unknown"
    file_name = "SharpSMP.zip"
    file_type = "zip"
    first_seen = "2026-11-10 07:08:58"
  condition:
    hash.sha256(0, filesize) == "9d180f0e5dff2a2211b853fc28aac6c8b5b8b970e98d7746f016a60d8a616849"
}

rule MalwareBazaar_Mirai_011_6117fdf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6117fdf5c647aea49913b960ccbd4f545fbe048f87934fd7498e1460b0bec223"
    family = "Mirai"
    file_name = "x4"
    file_type = "elf"
    first_seen = "2026-11-10 07:08:19"
  condition:
    hash.sha256(0, filesize) == "6117fdf5c647aea49913b960ccbd4f545fbe048f87934fd7498e1460b0bec223"
}

rule MalwareBazaar_Mirai_012_37f975cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37f975cb5b9ce21f3c153cdb1f7ff3e9d56950b0e10fb58b7b8a3814c1f8ca11"
    family = "Mirai"
    file_name = "x4"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:15"
  condition:
    hash.sha256(0, filesize) == "37f975cb5b9ce21f3c153cdb1f7ff3e9d56950b0e10fb58b7b8a3814c1f8ca11"
}

rule MalwareBazaar_Mirai_013_ca6e0ac8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca6e0ac85b41d6a191eaddc695ad339648be8c8af008088a48550764c521635b"
    family = "Mirai"
    file_name = "reflex.arm6"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:12"
  condition:
    hash.sha256(0, filesize) == "ca6e0ac85b41d6a191eaddc695ad339648be8c8af008088a48550764c521635b"
}

rule MalwareBazaar_Mirai_014_11528bfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11528bfa9bcaf4e2e86a12071d3a41f774964d0be9665de5b82be7d124aaa862"
    family = "Mirai"
    file_name = "reflex.mpsl"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:09"
  condition:
    hash.sha256(0, filesize) == "11528bfa9bcaf4e2e86a12071d3a41f774964d0be9665de5b82be7d124aaa862"
}

rule MalwareBazaar_Mirai_015_deaa0a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deaa0a14dee8f41738a40e56b1efa85fd49bdf3671fadbd2d61f023e49c8fd33"
    family = "Mirai"
    file_name = "reflex.arm5"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:06"
  condition:
    hash.sha256(0, filesize) == "deaa0a14dee8f41738a40e56b1efa85fd49bdf3671fadbd2d61f023e49c8fd33"
}

rule MalwareBazaar_Mirai_016_97a7e93b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a7e93b8713ef67ced7028689b95b07e614b32b277e14a9873975f4aee15445"
    family = "Mirai"
    file_name = "reflex.sh4"
    file_type = "elf"
    first_seen = "2026-11-10 07:07:03"
  condition:
    hash.sha256(0, filesize) == "97a7e93b8713ef67ced7028689b95b07e614b32b277e14a9873975f4aee15445"
}

rule MalwareBazaar_AgentTesla_017_53917de9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e"
    family = "AgentTesla"
    file_name = "Automaya S.A. de C.V. Lista de pedidos.js"
    file_type = "js"
    first_seen = "2026-11-10 06:57:09"
  condition:
    hash.sha256(0, filesize) == "53917de940b588be191a462085e46aabc71c4eda1a8c58a8c1242e681f3cad6e"
}

rule MalwareBazaar_unknown_018_94b597e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29"
    family = "unknown"
    file_name = "RFQ_NO.XFEC6000112038ADN25.docx"
    file_type = "docx"
    first_seen = "2026-11-10 06:56:44"
  condition:
    hash.sha256(0, filesize) == "94b597e300b6eb9859bd619fc9171c214294351f17ee400ab3c7cafb4f7c0d29"
}

rule MalwareBazaar_unknown_019_264e1097
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3"
    family = "unknown"
    file_name = "RFQ 000240_RO_xlsx.js"
    file_type = "js"
    first_seen = "2026-11-10 06:56:13"
  condition:
    hash.sha256(0, filesize) == "264e109751bb5d6f6c54a93a5a717ef05e28a49e82b362d2a8d09bc9cead9ee3"
}

rule MalwareBazaar_AgentTesla_020_6f4facc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282"
    family = "AgentTesla"
    file_name = "PO#17971 for November 2026.exe"
    file_type = "exe"
    first_seen = "2026-11-10 06:55:57"
  condition:
    hash.sha256(0, filesize) == "6f4facc2fa66e56e5fffd3d269218c28c48d956190fa8fa301b863157c66c282"
}

rule MalwareBazaar_AgentTesla_021_bc00e9d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e"
    family = "AgentTesla"
    file_name = "HBL DOC.pif"
    file_type = "exe"
    first_seen = "2026-11-10 06:55:40"
  condition:
    hash.sha256(0, filesize) == "bc00e9d8bb62be41fe977d29344bdf3d3e52acb215229287dc23cd5923004f0e"
}

rule MalwareBazaar_unknown_022_2f303220
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f3032202a9099b24b07f93c5f76044ac0aa382f891010705b5dd64b33b329ca"
    family = "unknown"
    file_name = "MTO EFIP8001 MLDP REV 1_xlsm.js"
    file_type = "js"
    first_seen = "2026-11-10 06:55:25"
  condition:
    hash.sha256(0, filesize) == "2f3032202a9099b24b07f93c5f76044ac0aa382f891010705b5dd64b33b329ca"
}

rule MalwareBazaar_unknown_023_e30c0b35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e30c0b35ba69eb044347ac21941d809affedcab9eed5b975753f0948c366bb1e"
    family = "unknown"
    file_name = "MTO EFIP8001 LHDP REV 1_xlsm.wsf"
    file_type = "wsf"
    first_seen = "2026-11-10 06:55:12"
  condition:
    hash.sha256(0, filesize) == "e30c0b35ba69eb044347ac21941d809affedcab9eed5b975753f0948c366bb1e"
}

rule MalwareBazaar_unknown_024_dbd540b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbd540b47319116837f78b3103349e15b4c593128439fd6762521449dba64a3c"
    family = "unknown"
    file_name = "Request for Quotation-To Supply Instrument Spare Parts.js"
    file_type = "js"
    first_seen = "2026-11-10 06:54:39"
  condition:
    hash.sha256(0, filesize) == "dbd540b47319116837f78b3103349e15b4c593128439fd6762521449dba64a3c"
}

rule MalwareBazaar_AgentTesla_025_8573503e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8573503e09f5fd6dbd84f6b142862e272de6f55b625a1713a4f0f9548583cdb0"
    family = "AgentTesla"
    file_name = "PURCHASE ORDER#008584.js"
    file_type = "js"
    first_seen = "2026-11-10 06:54:21"
  condition:
    hash.sha256(0, filesize) == "8573503e09f5fd6dbd84f6b142862e272de6f55b625a1713a4f0f9548583cdb0"
}

rule MalwareBazaar_unknown_026_521a19a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "521a19a85d9c290fc84b5eed9d91d1a13b7332aaaa27a29b6cf4e84139bb6979"
    family = "unknown"
    file_name = "PO-153211.js"
    file_type = "js"
    first_seen = "2026-11-10 06:54:06"
  condition:
    hash.sha256(0, filesize) == "521a19a85d9c290fc84b5eed9d91d1a13b7332aaaa27a29b6cf4e84139bb6979"
}

rule MalwareBazaar_CoinMiner_027_a92f2d3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af"
    family = "CoinMiner"
    file_name = "OurNew.exe"
    file_type = "exe"
    first_seen = "2026-11-10 06:52:38"
  condition:
    hash.sha256(0, filesize) == "a92f2d3dc8ca44a3aa1be1fdf21bfa19728e2394a9dc8f134d92facdfd1107af"
}

rule MalwareBazaar_SalatStealer_028_7871b4ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7871b4edf3d6e85aee7e4a6857eeb0094ecbfb7d698a296412f057662407ea78"
    family = "SalatStealer"
    file_name = "7179a0c397748d17.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:33"
  condition:
    hash.sha256(0, filesize) == "7871b4edf3d6e85aee7e4a6857eeb0094ecbfb7d698a296412f057662407ea78"
}

rule MalwareBazaar_SalatStealer_029_0be8947b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0be8947b2a4396ce1390b694323402ec5379724dd927b9409cc874ef68defcc7"
    family = "SalatStealer"
    file_name = "c7626da7d9f3c52e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:27"
  condition:
    hash.sha256(0, filesize) == "0be8947b2a4396ce1390b694323402ec5379724dd927b9409cc874ef68defcc7"
}

rule MalwareBazaar_SalatStealer_030_c76eb171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c76eb1713960358d1d5dcc011ec86bce4064f7a0f34bf9e34d42889a49dc14c5"
    family = "SalatStealer"
    file_name = "a081f4530595a397.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:22"
  condition:
    hash.sha256(0, filesize) == "c76eb1713960358d1d5dcc011ec86bce4064f7a0f34bf9e34d42889a49dc14c5"
}

rule MalwareBazaar_SalatStealer_031_7179a0c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7179a0c397748d17e12355ae5e3f91fa9f64d6a3d20b366d68c2f210489b8f94"
    family = "SalatStealer"
    file_name = "7179a0c397748d17.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:14"
  condition:
    hash.sha256(0, filesize) == "7179a0c397748d17e12355ae5e3f91fa9f64d6a3d20b366d68c2f210489b8f94"
}

rule MalwareBazaar_SalatStealer_032_c7626da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7626da7d9f3c52e576eecc7a98c4363b8580640849c96fb215bf40f0adb2e04"
    family = "SalatStealer"
    file_name = "c7626da7d9f3c52e.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:25:02"
  condition:
    hash.sha256(0, filesize) == "c7626da7d9f3c52e576eecc7a98c4363b8580640849c96fb215bf40f0adb2e04"
}

rule MalwareBazaar_SalatStealer_033_a081f453
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a081f4530595a3973d658cb2e123b4f0237c956a93f7a450f6f6d8709ecdc351"
    family = "SalatStealer"
    file_name = "a081f4530595a397.bin"
    file_type = "exe"
    first_seen = "2026-11-10 06:24:49"
  condition:
    hash.sha256(0, filesize) == "a081f4530595a3973d658cb2e123b4f0237c956a93f7a450f6f6d8709ecdc351"
}

rule MalwareBazaar_Mirai_034_4a64138c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 06:09:03"
  condition:
    hash.sha256(0, filesize) == "4a64138c242b044fb7fda324a984b5f6d91004f2afeca972d93f752e2254c520"
}

rule MalwareBazaar_unknown_035_ac485a3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac485a3ad457a1e550ced3b48c9bd25126b3ca585478f3d99734c2c54fcabdd9"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-11-10 05:57:12"
  condition:
    hash.sha256(0, filesize) == "ac485a3ad457a1e550ced3b48c9bd25126b3ca585478f3d99734c2c54fcabdd9"
}

rule MalwareBazaar_CoinMiner_036_2c6ad60d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6ad60dd7edf70d9f28e362f66a72b146367f1167277ab830a3749cecd1ea6f"
    family = "CoinMiner"
    file_name = "OurNew.exe"
    file_type = "exe"
    first_seen = "2026-11-10 05:52:38"
  condition:
    hash.sha256(0, filesize) == "2c6ad60dd7edf70d9f28e362f66a72b146367f1167277ab830a3749cecd1ea6f"
}

rule MalwareBazaar_SalatStealer_037_e50d206d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524"
    family = "SalatStealer"
    file_name = "205ffcdb71580bff.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:26:17"
  condition:
    hash.sha256(0, filesize) == "e50d206d484b8d1681e300d4f64b0da12df0ab9de236445efe8e727efa1dd524"
}

rule MalwareBazaar_SalatStealer_038_bee28f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bee28f6ef408f6b549f1a2564fe89516480ca3a52983a3aefea10184e778ad02"
    family = "SalatStealer"
    file_name = "ffa6045efd8fd41d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:33"
  condition:
    hash.sha256(0, filesize) == "bee28f6ef408f6b549f1a2564fe89516480ca3a52983a3aefea10184e778ad02"
}

rule MalwareBazaar_SalatStealer_039_f1468730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f146873024b0f156b2ef37d7f5383361d07852f250bcd76f388d13bfa11122da"
    family = "SalatStealer"
    file_name = "d34701558b0d2129.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:27"
  condition:
    hash.sha256(0, filesize) == "f146873024b0f156b2ef37d7f5383361d07852f250bcd76f388d13bfa11122da"
}

rule MalwareBazaar_SalatStealer_040_4d8185fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d8185fee09ded1b6966264fc942d9750575119121da678c7a73ed7f5d62aac1"
    family = "SalatStealer"
    file_name = "db76cb5443264f9d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:22"
  condition:
    hash.sha256(0, filesize) == "4d8185fee09ded1b6966264fc942d9750575119121da678c7a73ed7f5d62aac1"
}

rule MalwareBazaar_SalatStealer_041_205ffcdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "205ffcdb71580bffb9bae90a594b0da311ed9586e92cd5bcc092839268438596"
    family = "SalatStealer"
    file_name = "205ffcdb71580bff.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:17"
  condition:
    hash.sha256(0, filesize) == "205ffcdb71580bffb9bae90a594b0da311ed9586e92cd5bcc092839268438596"
}

rule MalwareBazaar_SalatStealer_042_ffa6045e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffa6045efd8fd41d00489dd877f578d96ec4dd06d1cf681fcfc636ec4943947d"
    family = "SalatStealer"
    file_name = "ffa6045efd8fd41d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:25:06"
  condition:
    hash.sha256(0, filesize) == "ffa6045efd8fd41d00489dd877f578d96ec4dd06d1cf681fcfc636ec4943947d"
}

rule MalwareBazaar_SalatStealer_043_d3470155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d34701558b0d21293fcf58846a17a9e9981cf90e7148a777b7db0e73de3bb592"
    family = "SalatStealer"
    file_name = "d34701558b0d2129.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:24:54"
  condition:
    hash.sha256(0, filesize) == "d34701558b0d21293fcf58846a17a9e9981cf90e7148a777b7db0e73de3bb592"
}

rule MalwareBazaar_SalatStealer_044_db76cb54
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db76cb5443264f9db353d5a5dacb3aafb943e2938883737350889612ac90f431"
    family = "SalatStealer"
    file_name = "db76cb5443264f9d.bin"
    file_type = "exe"
    first_seen = "2026-11-10 05:24:42"
  condition:
    hash.sha256(0, filesize) == "db76cb5443264f9db353d5a5dacb3aafb943e2938883737350889612ac90f431"
}

rule MalwareBazaar_Mirai_045_43d1a98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 05:24:04"
  condition:
    hash.sha256(0, filesize) == "43d1a98eb1f0314e6f9b4874732b0f143e777673dc74b7af7a317d953f174fee"
}

rule MalwareBazaar_Mirai_046_810b14a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01"
    family = "Mirai"
    file_name = "810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:12:53"
  condition:
    hash.sha256(0, filesize) == "810b14a04ffbf6e0ccf6cfb76531f50ec87872b02f2f99348a6f987b4703ba01"
}

rule MalwareBazaar_Snowlight_047_c3a3e04a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3a3e04a39e3fcdf764de3af3e27d027fefbb1233442622c29e6a03c93e534f0"
    family = "Snowlight"
    file_name = "9297d061tcp"
    file_type = "elf"
    first_seen = "2026-11-10 05:11:20"
  condition:
    hash.sha256(0, filesize) == "c3a3e04a39e3fcdf764de3af3e27d027fefbb1233442622c29e6a03c93e534f0"
}

rule MalwareBazaar_Snowlight_048_8c43df6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57"
    family = "Snowlight"
    file_name = "8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:08:02"
  condition:
    hash.sha256(0, filesize) == "8c43df6e0be4707134c8651f86263d07a4dd42e3de96eab65b7fb70799f44f57"
}

rule MalwareBazaar_Mirai_049_af2cff1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564"
    family = "Mirai"
    file_name = "af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:07:58"
  condition:
    hash.sha256(0, filesize) == "af2cff1c6787f3fa75f18cb30ae5bdf9d6fba685425fbeda3466d589eb54f564"
}

rule MalwareBazaar_Mirai_050_aa56c8dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de"
    family = "Mirai"
    file_name = "aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de.elf"
    file_type = "elf"
    first_seen = "2026-11-10 05:07:54"
  condition:
    hash.sha256(0, filesize) == "aa56c8dd587df31e42aee41eb779e3fdbc2968a5fe1279bcffec12a1fa0267de"
}

rule MalwareBazaar_unknown_051_46f0050d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada"
    family = "unknown"
    file_name = "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada.exe"
    file_type = "exe"
    first_seen = "2026-11-10 05:05:35"
  condition:
    hash.sha256(0, filesize) == "46f0050d595a60324a7d27e32ba1c4cd7af4000c113faf73ad431efabef4aada"
}

rule MalwareBazaar_unknown_052_daa7c4ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d"
    family = "unknown"
    file_name = "daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d.exe"
    file_type = "exe"
    first_seen = "2026-11-10 04:47:55"
  condition:
    hash.sha256(0, filesize) == "daa7c4ba718d90204a0641d077c566ae9cdf923203b1073b0d4ec68d8cd0d73d"
}

rule MalwareBazaar_Snowlight_053_b671c810
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437"
    family = "Snowlight"
    file_name = "b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:45:47"
  condition:
    hash.sha256(0, filesize) == "b671c810f2d5360738d4c7b17786da7f23bd8ced5af94d8630c42bc1425bd437"
}

rule MalwareBazaar_Snowlight_054_5aeb7b5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e"
    family = "Snowlight"
    file_name = "5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:45:43"
  condition:
    hash.sha256(0, filesize) == "5aeb7b5c1ea6f5276c7372bf2b394f81a0564e28c0a5ab2ca95fdc1a45fb205e"
}

rule MalwareBazaar_Mirai_055_dd17dea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f"
    family = "Mirai"
    file_name = "dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:45:38"
  condition:
    hash.sha256(0, filesize) == "dd17dea02b20408ce4a5da1f1ecb0eb21d4f7dca65bcce9d89381c53d729cf4f"
}

rule MalwareBazaar_unknown_056_04015ff8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528"
    family = "unknown"
    file_name = "04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528.exe"
    file_type = "exe"
    first_seen = "2026-11-10 04:45:34"
  condition:
    hash.sha256(0, filesize) == "04015ff8c06e35f9066151f3b9dafafb2f8efddecaa70abcb50d036e34f03528"
}

rule MalwareBazaar_Mirai_057_92ae676d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d"
    family = "Mirai"
    file_name = "92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:42:08"
  condition:
    hash.sha256(0, filesize) == "92ae676dc54633c79eea85a8eb39409b4e090b672a7b155adae02bcc4045db8d"
}

rule MalwareBazaar_Snowlight_058_217b3a2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da"
    family = "Snowlight"
    file_name = "217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:42:04"
  condition:
    hash.sha256(0, filesize) == "217b3a2ff0d10801141cffd60f2332255b152f0580f7b7e28cf3d87510eb87da"
}

rule MalwareBazaar_Mirai_059_c29adb64
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d"
    family = "Mirai"
    file_name = "c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:59"
  condition:
    hash.sha256(0, filesize) == "c29adb640900be5508f47a57dafb7e5f1da32fc37fc74d12e8e719623bcc465d"
}

rule MalwareBazaar_unknown_060_7432acb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208"
    family = "unknown"
    file_name = "7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:55"
  condition:
    hash.sha256(0, filesize) == "7432acb4dfeae3bfc2871c1c4faa4ba8586c051ad7b819ff3287931077c5c208"
}

rule MalwareBazaar_Mirai_061_5581413a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24"
    family = "Mirai"
    file_name = "5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:51"
  condition:
    hash.sha256(0, filesize) == "5581413a198a4b78ec61b45af7a716480f9c11fcfff9f4953a29dc14f56fcb24"
}

rule MalwareBazaar_Mirai_062_0e8e773f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c"
    family = "Mirai"
    file_name = "0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:41:47"
  condition:
    hash.sha256(0, filesize) == "0e8e773ff96909ec809ac9ff5a939ee08c07dcd40165fd24fff7cfbb3e885a5c"
}

rule MalwareBazaar_unknown_063_5b4c671e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088"
    family = "unknown"
    file_name = "5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:38:04"
  condition:
    hash.sha256(0, filesize) == "5b4c671e769da3e8d0437d9bd521c33544429f4f2548c48dd8d1f247398e4088"
}

rule MalwareBazaar_unknown_064_7394b5c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730"
    family = "unknown"
    file_name = "7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:59"
  condition:
    hash.sha256(0, filesize) == "7394b5c1c1fc7d16171c04540c4f829a1cffc0ab2adc9e3e6fe1f050b503a730"
}

rule MalwareBazaar_Mirai_065_36deac7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d"
    family = "Mirai"
    file_name = "36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:56"
  condition:
    hash.sha256(0, filesize) == "36deac7e491848ac8236a5531d22408c483445416b791615e73c603f27428d6d"
}

rule MalwareBazaar_Mirai_066_baf0fb48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e"
    family = "Mirai"
    file_name = "baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:51"
  condition:
    hash.sha256(0, filesize) == "baf0fb4822c2846661094f05f5682f22d21979fa9f0be6e1ed2e8a16ba7b6d2e"
}

rule MalwareBazaar_Snowlight_067_a74aa4ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3"
    family = "Snowlight"
    file_name = "a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:37:47"
  condition:
    hash.sha256(0, filesize) == "a74aa4eda145ea8e12bd2c6121fe8cc204eb2d41ce34a2829f288c65f8531ee3"
}

rule MalwareBazaar_Snowlight_068_736e651c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61"
    family = "Snowlight"
    file_name = "736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:45"
  condition:
    hash.sha256(0, filesize) == "736e651c237482c7dcd0f2a354630b9ba67a75db8a8e28f62d89e4e139441a61"
}

rule MalwareBazaar_Mirai_069_96679534
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2"
    family = "Mirai"
    file_name = "96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:41"
  condition:
    hash.sha256(0, filesize) == "96679534563c125293b229a3c6ad1082121c8c6151a90069522e1d1d0d069bb2"
}

rule MalwareBazaar_Mirai_070_7946d78c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db"
    family = "Mirai"
    file_name = "7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:36"
  condition:
    hash.sha256(0, filesize) == "7946d78c45b95d197b2bd258211a3aad6e63db760abdc84d8eafbe11f54093db"
}

rule MalwareBazaar_Snowlight_071_18cfccb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813"
    family = "Snowlight"
    file_name = "18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:35:32"
  condition:
    hash.sha256(0, filesize) == "18cfccb9751fb3648acefeed528f1908bf54f349b140ad47994fc4c3fbd27813"
}

rule MalwareBazaar_unknown_072_0df7085c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e"
    family = "unknown"
    file_name = "0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:32:54"
  condition:
    hash.sha256(0, filesize) == "0df7085c617e7985839b6d3ddcb878d83026854fecf7ca5ba968a6922e2fc14e"
}

rule MalwareBazaar_unknown_073_d151a57b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53"
    family = "unknown"
    file_name = "d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:32:50"
  condition:
    hash.sha256(0, filesize) == "d151a57be07413a84a4e17db5bfa5eabdc908f18ad04300502e4e3e42c40ce53"
}

rule MalwareBazaar_Mirai_074_55e5ca17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e5ca1799ae391f1bbaa0e8d1ed42015eb60a0f3122d7c9cd113266369a4e0e"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-10 04:30:07"
  condition:
    hash.sha256(0, filesize) == "55e5ca1799ae391f1bbaa0e8d1ed42015eb60a0f3122d7c9cd113266369a4e0e"
}

rule MalwareBazaar_Mirai_075_c1c9a71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1c9a71b3d352a9842c32d85cda78226cb7e45c496f7b4333032ab84399001bc"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-11-10 04:30:04"
  condition:
    hash.sha256(0, filesize) == "c1c9a71b3d352a9842c32d85cda78226cb7e45c496f7b4333032ab84399001bc"
}

rule MalwareBazaar_Snowlight_076_3b11b084
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf"
    family = "Snowlight"
    file_name = "3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:28:03"
  condition:
    hash.sha256(0, filesize) == "3b11b084a847abd5f0b74fc4eef9da3220abf6ccf5538321e1f6f76f412d9bcf"
}

rule MalwareBazaar_Snowlight_077_b60ce851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5"
    family = "Snowlight"
    file_name = "b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:59"
  condition:
    hash.sha256(0, filesize) == "b60ce85101c04d84967818312791943cc7bfd9883931e0aa41b6d2c0205fa4c5"
}

rule MalwareBazaar_Mirai_078_2d6f187b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d"
    family = "Mirai"
    file_name = "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:55"
  condition:
    hash.sha256(0, filesize) == "2d6f187bec9175d7f5a8409ac8b6c878dc98aba7599652d4d25b8ee644e2ad3d"
}

rule MalwareBazaar_unknown_079_88759499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c"
    family = "unknown"
    file_name = "887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:51"
  condition:
    hash.sha256(0, filesize) == "887594990c6d5138b4f0d60d456952f718c63a17a13a4904e068bfca956c758c"
}

rule MalwareBazaar_unknown_080_4ffd8f09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355"
    family = "unknown"
    file_name = "4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:47"
  condition:
    hash.sha256(0, filesize) == "4ffd8f09debd7ae6724e71017af34d57143847c2899cf08ac60d4923f200a355"
}

rule MalwareBazaar_Mirai_081_79bee467
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af"
    family = "Mirai"
    file_name = "79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:43"
  condition:
    hash.sha256(0, filesize) == "79bee467cd57ef13198728c3d08c42c365bb27084b147f276f59f1748e55c1af"
}

rule MalwareBazaar_SalatStealer_082_f1f894b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1f894b6d0c6c6b0cbb2438e312ee37cfc3213b007f3bcf310663ab2d1556c15"
    family = "SalatStealer"
    file_name = "cab11db1e1bddd1f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:27:35"
  condition:
    hash.sha256(0, filesize) == "f1f894b6d0c6c6b0cbb2438e312ee37cfc3213b007f3bcf310663ab2d1556c15"
}

rule MalwareBazaar_Mirai_083_0739c017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511"
    family = "Mirai"
    file_name = "0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:27:03"
  condition:
    hash.sha256(0, filesize) == "0739c017f0c09a0137596faff50cbff9894d7e9d97dbe950b1999ca29b4ee511"
}

rule MalwareBazaar_unknown_084_d802f765
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b"
    family = "unknown"
    file_name = "d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:26:59"
  condition:
    hash.sha256(0, filesize) == "d802f765cafc8b68d045fe0aa8ab23674f1943438942873f12c68ee80871871b"
}

rule MalwareBazaar_unknown_085_39893a47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273"
    family = "unknown"
    file_name = "39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:26:56"
  condition:
    hash.sha256(0, filesize) == "39893a47ffab2a6b26660d01c922780734467a741a1ecf7e67313a5c1bc91273"
}

rule MalwareBazaar_unknown_086_219b6e9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3"
    family = "unknown"
    file_name = "219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3.exe"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:52"
  condition:
    hash.sha256(0, filesize) == "219b6e9db2bdc69a8ae75c25630c45a25df4956b9865d7805100c5a61d799cd3"
}

rule MalwareBazaar_Mirai_087_01a9a86f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc"
    family = "Mirai"
    file_name = "01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:26:45"
  condition:
    hash.sha256(0, filesize) == "01a9a86f49f199165d5a28baba3d227fa3eb0ef99bd61d8a596b10184c80f3dc"
}

rule MalwareBazaar_SalatStealer_088_120b0f04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "120b0f04b8bbf228d4d69becd5df17e2ec34bd767f9c62f6eaa0845a06c8a099"
    family = "SalatStealer"
    file_name = "ef4deb82197fbb20.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:34"
  condition:
    hash.sha256(0, filesize) == "120b0f04b8bbf228d4d69becd5df17e2ec34bd767f9c62f6eaa0845a06c8a099"
}

rule MalwareBazaar_SalatStealer_089_fa986ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa986ddc6abf619ebb0e7f8591810fd77cf85d9cc68f8392270310d8d6510635"
    family = "SalatStealer"
    file_name = "48f58ccc90cfa36a.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:29"
  condition:
    hash.sha256(0, filesize) == "fa986ddc6abf619ebb0e7f8591810fd77cf85d9cc68f8392270310d8d6510635"
}

rule MalwareBazaar_SalatStealer_090_bb0bbaf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0bbaf8a6d50ae7a02ef729c919b391b06a0694f3b2f139b47ad4271d520bae"
    family = "SalatStealer"
    file_name = "4bae9ef0bb222c7f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:24"
  condition:
    hash.sha256(0, filesize) == "bb0bbaf8a6d50ae7a02ef729c919b391b06a0694f3b2f139b47ad4271d520bae"
}

rule MalwareBazaar_SalatStealer_091_cab11db1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cab11db1e1bddd1f1d387b8432a8bf5e16c3bb59471db84c5f4c5995168457a8"
    family = "SalatStealer"
    file_name = "cab11db1e1bddd1f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:19"
  condition:
    hash.sha256(0, filesize) == "cab11db1e1bddd1f1d387b8432a8bf5e16c3bb59471db84c5f4c5995168457a8"
}

rule MalwareBazaar_SalatStealer_092_ef4deb82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef4deb82197fbb205be15785bf967f1631628e1dce4d8fb58b4d2deacd2f142b"
    family = "SalatStealer"
    file_name = "ef4deb82197fbb20.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:26:09"
  condition:
    hash.sha256(0, filesize) == "ef4deb82197fbb205be15785bf967f1631628e1dce4d8fb58b4d2deacd2f142b"
}

rule MalwareBazaar_SalatStealer_093_48f58ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48f58ccc90cfa36a8ef2cdd9f7d28f17f2c659aacc270d6ec9e28dcbc5924bf7"
    family = "SalatStealer"
    file_name = "48f58ccc90cfa36a.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:25:58"
  condition:
    hash.sha256(0, filesize) == "48f58ccc90cfa36a8ef2cdd9f7d28f17f2c659aacc270d6ec9e28dcbc5924bf7"
}

rule MalwareBazaar_SalatStealer_094_4bae9ef0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bae9ef0bb222c7fa8f82cd0b91b3346335c2df9cf6284d72ecb2842b2194c27"
    family = "SalatStealer"
    file_name = "4bae9ef0bb222c7f.bin"
    file_type = "exe"
    first_seen = "2026-11-10 04:25:47"
  condition:
    hash.sha256(0, filesize) == "4bae9ef0bb222c7fa8f82cd0b91b3346335c2df9cf6284d72ecb2842b2194c27"
}

rule MalwareBazaar_Mirai_095_c81508bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414"
    family = "Mirai"
    file_name = "c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:44"
  condition:
    hash.sha256(0, filesize) == "c81508bcc33189200e0845d9d92b08b7f7c1fd65218f90b64f105171d8bf5414"
}

rule MalwareBazaar_Snowlight_096_b94c00bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7"
    family = "Snowlight"
    file_name = "b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:40"
  condition:
    hash.sha256(0, filesize) == "b94c00bdd31c218b0a254de0e6380f0d2591b89fb9645d7325d0e5d17f87f0f7"
}

rule MalwareBazaar_Mirai_097_3101a03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7"
    family = "Mirai"
    file_name = "3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:36"
  condition:
    hash.sha256(0, filesize) == "3101a03f77da98c6ad853c50311cfa9a23be6ce264f5143b85484a9f1db07dd7"
}

rule MalwareBazaar_unknown_098_c14632da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98"
    family = "unknown"
    file_name = "c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:32"
  condition:
    hash.sha256(0, filesize) == "c14632daafa8db8fd953ee635e75ece305862839cf4c2105f7009af586d85c98"
}

rule MalwareBazaar_Mirai_099_e247d8d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf"
    family = "Mirai"
    file_name = "e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:28"
  condition:
    hash.sha256(0, filesize) == "e247d8d5e2ae118a473fff8188f289b3556944073b17356fd93675ea21f3f8bf"
}

rule MalwareBazaar_Mirai_100_8604654d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1"
    family = "Mirai"
    file_name = "8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1.elf"
    file_type = "elf"
    first_seen = "2026-11-10 04:25:24"
  condition:
    hash.sha256(0, filesize) == "8604654d71ece602a7c0aa86b4ead3e5e4dbc690885fb306d708ce145d600fe1"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

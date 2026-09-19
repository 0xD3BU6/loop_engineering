# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-19

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 665 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 665 |
| Unique family labels | 7 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 74 |
| Mirai | 17 |
| VShell | 4 |
| JOMANGY | 2 |
| NanoCore | 1 |
| Mozi | 1 |
| ConnectWise | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 69 |
| elf | 25 |
| unknown | 3 |
| sh | 2 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `6f2e903586c155e3`

| Field | Value |
|---|---|
| SHA-256 | `6f2e903586c155e31efad481fdfd2615e608b64aaa5ca377feb23da73b0cd01a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:43:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `253ef21578b88835940094d36abfb46d` |
| SHA-1 | `1c3ec58f65cbe24d441d62b48b9df01f1ba9f973` |
| SHA-256 | `6f2e903586c155e31efad481fdfd2615e608b64aaa5ca377feb23da73b0cd01a` |
| SHA3-384 | `c6f47bf7c9cfd54c82e69034f7ef1ee728e67cb439944dc7b67c6f44fe95ce283dd0f4d5a0f19db0f9571777d9331c72` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B462D686EDA22E6CDE4E90B17A11F878AD743690866969E3D7828C215DA39D00424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UqWDTe:fKOe2/7c9sN3zfZR1m+RGRWDT6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_6f2e9035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f2e903586c155e31efad481fdfd2615e608b64aaa5ca377feb23da73b0cd01a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:43:27"
  condition:
    hash.sha256(0, filesize) == "6f2e903586c155e31efad481fdfd2615e608b64aaa5ca377feb23da73b0cd01a"
}
```

### Sample 2: `818c0be6ab15a51d`

| Field | Value |
|---|---|
| SHA-256 | `818c0be6ab15a51d9b7a84f15c27443ddfbb899bccf4bcd7ef45e8a43135298d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:41:05` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5accea0171a3c96449ff987d4c2608c` |
| SHA-1 | `d0bc0fc32d5ba759121a6f83890d003ec37e4d51` |
| SHA-256 | `818c0be6ab15a51d9b7a84f15c27443ddfbb899bccf4bcd7ef45e8a43135298d` |
| SHA3-384 | `146b7de63d6a9f9fc1e9d7bd498780307a7f7ffca969d43774da8564503de746cc6b78fd3e2e7ae219cdd59e44a93a01` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FD62D88AD8922E9CCE4F91703A11F878FE74769586266DE7D7818C3069A38D014A4FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U59MCe:fKOe2/7c9sN3zfZR1m+RGe6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_818c0be6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "818c0be6ab15a51d9b7a84f15c27443ddfbb899bccf4bcd7ef45e8a43135298d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:41:05"
  condition:
    hash.sha256(0, filesize) == "818c0be6ab15a51d9b7a84f15c27443ddfbb899bccf4bcd7ef45e8a43135298d"
}
```

### Sample 3: `eef8d08b4ff98081`

| Field | Value |
|---|---|
| SHA-256 | `eef8d08b4ff980813e95ad9c2fbdbd7f2c4f9519a5972e5a41b019c43bc76513` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:39:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11b9b3d7d41fe3e44445c68acc4b085d` |
| SHA-1 | `74d904d7545fd435b0b18369aca8b99ee2068a17` |
| SHA-256 | `eef8d08b4ff980813e95ad9c2fbdbd7f2c4f9519a5972e5a41b019c43bc76513` |
| SHA3-384 | `998750811092e3a03461a7eb6ab694117fb037390392b908a73fc199bd9c46819d78c26d6411dc6df90048f1fb3bda5e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CF62C686DC925EACDE8F90703A12FC687D7136D04A67A9F3D7928C304EA38D05424EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UwBBgn:fKOe2/7c9sN3zfZR1m+RGh6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_eef8d08b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eef8d08b4ff980813e95ad9c2fbdbd7f2c4f9519a5972e5a41b019c43bc76513"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:39:08"
  condition:
    hash.sha256(0, filesize) == "eef8d08b4ff980813e95ad9c2fbdbd7f2c4f9519a5972e5a41b019c43bc76513"
}
```

### Sample 4: `da5e644826f411c2`

| Field | Value |
|---|---|
| SHA-256 | `da5e644826f411c229882beddca1c84d25e9e40eee1e6c031ccdf9a937197228` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:38:37` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c28b8b81e5ac3e7d55987ce550456fe` |
| SHA-1 | `044038ee5763d18f26a6bd05ccca1da8e361f2b9` |
| SHA-256 | `da5e644826f411c229882beddca1c84d25e9e40eee1e6c031ccdf9a937197228` |
| SHA3-384 | `576fd414eed5b4eaf0347c980cb27fff3878a43ccba1d7970502747a66045b7d662a5c1594f2f30c7158aa4de292c609` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17C62C69AE8A22F6DDF8FD0703B11F838A9703690856599E7D7C28C315DA3AD04424FBD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UzOKKn:fKOe2/7c9sN3zfZR1m+RG0V6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_da5e6448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da5e644826f411c229882beddca1c84d25e9e40eee1e6c031ccdf9a937197228"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:38:37"
  condition:
    hash.sha256(0, filesize) == "da5e644826f411c229882beddca1c84d25e9e40eee1e6c031ccdf9a937197228"
}
```

### Sample 5: `0738be0a0c8656d0`

| Field | Value |
|---|---|
| SHA-256 | `0738be0a0c8656d0447e0cef9a6e552cf6fa13d1c2b30af3a079162296ae5d68` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-19 04:37:20` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `264dfa0768be9f2af0d663991870ee79` |
| SHA-1 | `db2599fafcf73d2fd991189aceeaabf4ae33456f` |
| SHA-256 | `0738be0a0c8656d0447e0cef9a6e552cf6fa13d1c2b30af3a079162296ae5d68` |
| SHA3-384 | `69e140bb491d61c7366183cf1fa127ed594775121723f617a39e44d1f598cae572651d4fe9e497300a71171aaefd5bfe` |
| TLSH | `T185137D655A857C24AE9889371C7F2F0CB9A983E1300491DDBFCB3CF58C59AACE21971D` |
| SSDEEP | `768:l6Utd8/m9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:2co` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_005_0738be0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0738be0a0c8656d0447e0cef9a6e552cf6fa13d1c2b30af3a079162296ae5d68"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-19 04:37:20"
  condition:
    hash.sha256(0, filesize) == "0738be0a0c8656d0447e0cef9a6e552cf6fa13d1c2b30af3a079162296ae5d68"
}
```

### Sample 6: `1c30871a58e0554f`

| Field | Value |
|---|---|
| SHA-256 | `1c30871a58e0554f24807b95cd829c6780265a8400cebbc90fa9cfa2846e74fc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:36:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c70f242e522a783274de04f1f59b9d9b` |
| SHA-1 | `79aca33c280dc7b564d8312bffa318a1037cc20b` |
| SHA-256 | `1c30871a58e0554f24807b95cd829c6780265a8400cebbc90fa9cfa2846e74fc` |
| SHA3-384 | `1a2545dbdb674ab1cf124d6733c98d24823fb52e6c4fedd023531052b3ab031fcd0edac5a38aca28ca0e5a85df46ae85` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17D62B586D8E26AADCE4FD0707B51F838BD7076918A6559E7DB82CC305DA39D04024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UriUBM:fKOe2/7c9sN3zfZR1m+RGC6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_1c30871a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c30871a58e0554f24807b95cd829c6780265a8400cebbc90fa9cfa2846e74fc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:36:35"
  condition:
    hash.sha256(0, filesize) == "1c30871a58e0554f24807b95cd829c6780265a8400cebbc90fa9cfa2846e74fc"
}
```

### Sample 7: `adfcefd58d7bf501`

| Field | Value |
|---|---|
| SHA-256 | `adfcefd58d7bf5012b4bea56363ac7917af3b6a5dce353b5d7523d3baa638fa7` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-09-19 04:35:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a38facd77f6c7016e22c44665950bf4c` |
| SHA-1 | `fa0e88195dc4986947e27a4024269960157b24c4` |
| SHA-256 | `adfcefd58d7bf5012b4bea56363ac7917af3b6a5dce353b5d7523d3baa638fa7` |
| SHA3-384 | `13b719efedafffc26ddb8180b501d7f416210e236423627f690a1f4983165dba57102de460f1bd1e4fbdcddbca481fb0` |
| TLSH | `T175B35C9BF401DD7DF80BD5BA04670E0AF530E7A557830B2B6297BD57EC321A90826F86` |
| SSDEEP | `1536:Ixh015oqpBAaCjzhh9118j9rYRXDUAunbi1RIRjJ/kaI35:IvWPAau31g2XozrRjJ/kaI35` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_adfcefd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adfcefd58d7bf5012b4bea56363ac7917af3b6a5dce353b5d7523d3baa638fa7"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-19 04:35:40"
  condition:
    hash.sha256(0, filesize) == "adfcefd58d7bf5012b4bea56363ac7917af3b6a5dce353b5d7523d3baa638fa7"
}
```

### Sample 8: `1032a72869bd8abd`

| Field | Value |
|---|---|
| SHA-256 | `1032a72869bd8abdf926a9315154b5233955a686bab46e80668acde56617727a` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-19 04:35:39` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df20cede385e1731e781aae49ac83a36` |
| SHA-1 | `3d5b352a90a21d5c865538a01725cb58617d700c` |
| SHA-256 | `1032a72869bd8abdf926a9315154b5233955a686bab46e80668acde56617727a` |
| SHA3-384 | `886b84fc4611a8cb24d7dba5f41746b162536ac53be680dfd1d1aafac904ff7158ebc23dafb97673bb3df65368eea1e5` |
| TLSH | `T1D1C27C966A867C44BEC94B3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:j8vCB+25j6es8Rbo59FYpMSUpi+20qUpi+20YQX:j8l25JKd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_008_1032a728
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1032a72869bd8abdf926a9315154b5233955a686bab46e80668acde56617727a"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-19 04:35:39"
  condition:
    hash.sha256(0, filesize) == "1032a72869bd8abdf926a9315154b5233955a686bab46e80668acde56617727a"
}
```

### Sample 9: `28ae92dcd272a2e1`

| Field | Value |
|---|---|
| SHA-256 | `28ae92dcd272a2e109355caff3e31aa2fe13dcad2d6e8f520cd951dded135c49` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:30:22` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f968684451c93cc550ec32b462e5d1f7` |
| SHA-1 | `f69fb193a600258aecbbbcaff771c3a8ecf6e5d6` |
| SHA-256 | `28ae92dcd272a2e109355caff3e31aa2fe13dcad2d6e8f520cd951dded135c49` |
| SHA3-384 | `06a07278b01c1c93602612946256594c2cdb66a3181947670a469eff783b292f81e5f30b5ca8ecf87dab05ee384e7590` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10762E8EAD9D25F5CDE8E80703A11F978BD7176A086255AE3D7828C315DA39D02024FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U+7Abe:fKOe2/7c9sN3zfZR1m+RGTC6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_28ae92dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ae92dcd272a2e109355caff3e31aa2fe13dcad2d6e8f520cd951dded135c49"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:30:22"
  condition:
    hash.sha256(0, filesize) == "28ae92dcd272a2e109355caff3e31aa2fe13dcad2d6e8f520cd951dded135c49"
}
```

### Sample 10: `0440513fdf8e78b0`

| Field | Value |
|---|---|
| SHA-256 | `0440513fdf8e78b0e6042dbe10f6a3fc006f58ce26623e55603130e5c776f5eb` |
| Family label | `NanoCore` |
| File name | `0abe9308525b4e9596bd4352a958d7a9.exe` |
| File type | `exe` |
| First seen | `2026-09-19 04:30:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0abe9308525b4e9596bd4352a958d7a9` |
| SHA-1 | `7a262fab4d584924607da3eae24f957b89c94eef` |
| SHA-256 | `0440513fdf8e78b0e6042dbe10f6a3fc006f58ce26623e55603130e5c776f5eb` |
| SHA3-384 | `a8814e28f09fe241013038d285b3425e5cb83b579883dee021b13cbee031304f36bb58f2385c8c32fab83f7a76768342` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15414CF267BB98A2FE2DE86B9611212028379C2E3D9C3F3DE18D455B74F267E506071D3` |
| SSDEEP | `3072:MzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HI/dP+1Nda82N+xdkv9iRLGeQLo:MLV6Bta6dtJmakIM5gkAgNpB` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_010_0440513f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0440513fdf8e78b0e6042dbe10f6a3fc006f58ce26623e55603130e5c776f5eb"
    family = "NanoCore"
    file_name = "0abe9308525b4e9596bd4352a958d7a9.exe"
    file_type = "exe"
    first_seen = "2026-09-19 04:30:05"
  condition:
    hash.sha256(0, filesize) == "0440513fdf8e78b0e6042dbe10f6a3fc006f58ce26623e55603130e5c776f5eb"
}
```

### Sample 11: `b93f932e309b6a4e`

| Field | Value |
|---|---|
| SHA-256 | `b93f932e309b6a4e48689b97fe730ca13d1e04a4dd1b9620ea2606fa13f20192` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:29:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26207629415b1e13e620913d144b35fb` |
| SHA-1 | `907fec5026f6085d9826588b174bc4d3c0b6a59e` |
| SHA-256 | `b93f932e309b6a4e48689b97fe730ca13d1e04a4dd1b9620ea2606fa13f20192` |
| SHA3-384 | `f7cae8a0d3850548da62fbaf6fd3963b5330afad04ba2a856b8e44965d4c0eed7e6b4afba9cb14a12f4268a23c91fdf9` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13762D68AE9D22BACDE4B91703A11FC386D713A9895655DF3D7818C3049A39C05534EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U5BgCc:fKOe2/7c9sN3zfZR1m+RGS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_b93f932e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b93f932e309b6a4e48689b97fe730ca13d1e04a4dd1b9620ea2606fa13f20192"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:29:30"
  condition:
    hash.sha256(0, filesize) == "b93f932e309b6a4e48689b97fe730ca13d1e04a4dd1b9620ea2606fa13f20192"
}
```

### Sample 12: `e3fcc914e472eba3`

| Field | Value |
|---|---|
| SHA-256 | `e3fcc914e472eba36dcf9a2fe2cde346eb05aec2caa6f6215b46d61671d545ce` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:28:22` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66ce566492be4d5e7bcccc0b7e28c890` |
| SHA-1 | `095955e1bf728189f323aa112b639d3d4f9d18db` |
| SHA-256 | `e3fcc914e472eba36dcf9a2fe2cde346eb05aec2caa6f6215b46d61671d545ce` |
| SHA3-384 | `3fb846b9731cffea9a1fca7d2cb68b2f80daa3c4d8bab8c0afcf421860ac20660b03ba1c3f73cf8ed1669e67d858403e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BD62E786D8A26F5DDE8F90703A11F83CADB1329495666DE3D7828C3559A39D00438FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U+lSBM:fKOe2/7c9sN3zfZR1m+RGTo6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_e3fcc914
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fcc914e472eba36dcf9a2fe2cde346eb05aec2caa6f6215b46d61671d545ce"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:28:22"
  condition:
    hash.sha256(0, filesize) == "e3fcc914e472eba36dcf9a2fe2cde346eb05aec2caa6f6215b46d61671d545ce"
}
```

### Sample 13: `4fff48bfe3c5760e`

| Field | Value |
|---|---|
| SHA-256 | `4fff48bfe3c5760ead43595761795a35d715c918903115b0c91cc50dff66f040` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:28:02` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09ddb5c492b158b724ba34f1e0967166` |
| SHA-1 | `4f24b8edc29aae592d00bf8c8f19657df430b9f6` |
| SHA-256 | `4fff48bfe3c5760ead43595761795a35d715c918903115b0c91cc50dff66f040` |
| SHA3-384 | `5a5a11dbf03dcd2550a1a18208bd1135d20a31c09de49c78ebf3c53ffd18b69c25754b06340352d5b38c3a3a22dae702` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15362B686D8922E6CDE4F80703B11F828B9747690866A6DF7DB818C705DA79D00474FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UT4Bgn:fKOe2/7c9sN3zfZR1m+RGK46C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_4fff48bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fff48bfe3c5760ead43595761795a35d715c918903115b0c91cc50dff66f040"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:28:02"
  condition:
    hash.sha256(0, filesize) == "4fff48bfe3c5760ead43595761795a35d715c918903115b0c91cc50dff66f040"
}
```

### Sample 14: `a99a1d95aade755c`

| Field | Value |
|---|---|
| SHA-256 | `a99a1d95aade755ccd5b5f065276c8a0059fa7b51c07ae26e3bc3e25d4fa128f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:26:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8e803a068f2c92d33aa30120201df68` |
| SHA-1 | `cd96ac25723d828095699c52a2ebe1880a2d35f8` |
| SHA-256 | `a99a1d95aade755ccd5b5f065276c8a0059fa7b51c07ae26e3bc3e25d4fa128f` |
| SHA3-384 | `3701b9900690047d48051d7bcb310401eb5a66531d04c57538ac463de250d332d2b7184f6e8bcae489e60dbad8b73541` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D162C5D6D8922E9CCE4E80703B11F978B97477D186A6ADF3D7819D205BB39D00024EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U8XFBM:fKOe2/7c9sN3zfZR1m+RGzF6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_a99a1d95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a99a1d95aade755ccd5b5f065276c8a0059fa7b51c07ae26e3bc3e25d4fa128f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:26:49"
  condition:
    hash.sha256(0, filesize) == "a99a1d95aade755ccd5b5f065276c8a0059fa7b51c07ae26e3bc3e25d4fa128f"
}
```

### Sample 15: `9cc6e99c4ea3874a`

| Field | Value |
|---|---|
| SHA-256 | `9cc6e99c4ea3874a8c810046dd097c43d3baeb15aa9e7107a48e04f7f555d665` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:25:51` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f66d87a275787cedcffb76126bd8db54` |
| SHA-1 | `32a13ce3d7bdcc35c175a6165d7947b536d7d37b` |
| SHA-256 | `9cc6e99c4ea3874a8c810046dd097c43d3baeb15aa9e7107a48e04f7f555d665` |
| SHA3-384 | `8fec22d0ee4b19e535b636558260ab1afc8fec915007b9136ff1a7e4aa35bc113ab9f9993f8a3a0a4261c78c881e1a08` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11B62D786DDA22F9CDE8FD0703A11F938AD747290866659E3D792CC7059A39C02429FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U43Bgn:fKOe2/7c9sN3zfZR1m+RGV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_9cc6e99c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cc6e99c4ea3874a8c810046dd097c43d3baeb15aa9e7107a48e04f7f555d665"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:25:51"
  condition:
    hash.sha256(0, filesize) == "9cc6e99c4ea3874a8c810046dd097c43d3baeb15aa9e7107a48e04f7f555d665"
}
```

### Sample 16: `4e08f96cd944a23b`

| Field | Value |
|---|---|
| SHA-256 | `4e08f96cd944a23b8a44e6c44e395b6406ab63504c5f755fcbb8620e7d417d4f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:25:38` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99d48f4794c0621839f6a470e17a3f2c` |
| SHA-1 | `e109b9fddb0cbe0f061a8d395b63f81423d20255` |
| SHA-256 | `4e08f96cd944a23b8a44e6c44e395b6406ab63504c5f755fcbb8620e7d417d4f` |
| SHA3-384 | `78517cf6582381f1af249b02e49d8f39e4a11beb7ce8e016b33f4f22827a7ceda50bc753e0c20f831ff434d542244ab6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E462D586D8B22F6CDE4E90707A12F978B97076D0866699F3D7828D314DA39D00468FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UhZBgn:fKOe2/7c9sN3zfZR1m+RGI6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_4e08f96c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e08f96cd944a23b8a44e6c44e395b6406ab63504c5f755fcbb8620e7d417d4f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:25:38"
  condition:
    hash.sha256(0, filesize) == "4e08f96cd944a23b8a44e6c44e395b6406ab63504c5f755fcbb8620e7d417d4f"
}
```

### Sample 17: `4b1b177d03e07132`

| Field | Value |
|---|---|
| SHA-256 | `4b1b177d03e0713291a98bc7b2d6dcfb4479e9cacb9ae679213a80928f64cc4c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:25:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c054f65fa6b3967ca7451ae492613d69` |
| SHA-1 | `6d4f1786238a74f75e0607cdd670335cea53ed62` |
| SHA-256 | `4b1b177d03e0713291a98bc7b2d6dcfb4479e9cacb9ae679213a80928f64cc4c` |
| SHA3-384 | `44b16052113074ae76e3f0aab08a8f40b8505cd07a052a65c7d084418d7cd3b073421f7e465cf2b5d230352a4f153492` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10662C68AE9A32F5CDE8E84703A51F838AD7136D48A659DE3D792CC3459A39D10034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJBgCc:fKOe2/7c9sN3zfZR1m+RGy6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_4b1b177d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1b177d03e0713291a98bc7b2d6dcfb4479e9cacb9ae679213a80928f64cc4c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:25:36"
  condition:
    hash.sha256(0, filesize) == "4b1b177d03e0713291a98bc7b2d6dcfb4479e9cacb9ae679213a80928f64cc4c"
}
```

### Sample 18: `4d974b47c9ac7f0b`

| Field | Value |
|---|---|
| SHA-256 | `4d974b47c9ac7f0b4ce3e2c5f2bbd4e10afe6d708da9b37be9de5d02a33f33d5` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-09-19 04:23:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c05d94328b8d7d469b46f6f8161a611d` |
| SHA-1 | `36d7ec3f4c27d644d5cf4d36edd1f9c4d5747291` |
| SHA-256 | `4d974b47c9ac7f0b4ce3e2c5f2bbd4e10afe6d708da9b37be9de5d02a33f33d5` |
| SHA3-384 | `8114bb5d11c0991cd1cd981635055d088853ab1df882df9dfd70a55c71ff23c64be297e12c5c508d8be1732061b6f758` |
| TLSH | `T1B3F46B55F850CF52CAC65A37F6AE424C3323037DD7DAB22A59089B38369787B4B3B640` |
| TELFHASH | `t148314861e519fd251692cbc8ebc4b366c4bae9044a0e3c6785b0452d9b30197268fdee` |
| SSDEEP | `12288:t/fc1PWWxUp7IPkrSwR8TIrFoyyvJY/nHjKMN0udxIh4YIR9i2porpbIOKRi:t3TpePimIrRHjJnJi2it3KR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_4d974b47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d974b47c9ac7f0b4ce3e2c5f2bbd4e10afe6d708da9b37be9de5d02a33f33d5"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-19 04:23:42"
  condition:
    hash.sha256(0, filesize) == "4d974b47c9ac7f0b4ce3e2c5f2bbd4e10afe6d708da9b37be9de5d02a33f33d5"
}
```

### Sample 19: `16c83d29bc499514`

| Field | Value |
|---|---|
| SHA-256 | `16c83d29bc49951400e94d15a91ea7896f85374a6c2b603bd403f4aa0f4ffe61` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:23:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3bfd0f2638a5dd689b4fda38f7f21ad` |
| SHA-1 | `1979f479622b84f7ed514070d3b1207d3e684414` |
| SHA-256 | `16c83d29bc49951400e94d15a91ea7896f85374a6c2b603bd403f4aa0f4ffe61` |
| SHA3-384 | `3a00d4dda8bec067e5ddd148715ffd058384d74c2343818d029c2f1b65d1bfeb4346c49868503269d5b0329a41ab7576` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C662E78AD9929F6CDE4E84703A10FD387DB476E186665DE3DB828C714EA39D00024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Utxcse:fKOe2/7c9sN3zfZR1m+RGSxcs6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_16c83d29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16c83d29bc49951400e94d15a91ea7896f85374a6c2b603bd403f4aa0f4ffe61"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:23:19"
  condition:
    hash.sha256(0, filesize) == "16c83d29bc49951400e94d15a91ea7896f85374a6c2b603bd403f4aa0f4ffe61"
}
```

### Sample 20: `36003d068b230750`

| Field | Value |
|---|---|
| SHA-256 | `36003d068b2307507439136d98f05070d93a45f4a5b7eeee37faa5afd3517398` |
| Family label | `Mirai` |
| File name | `sever1078.arm` |
| File type | `elf` |
| First seen | `2026-09-19 04:23:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f70b790afa64c4fac38c86962108478` |
| SHA-1 | `2a782b2eaf35caafd94a7ef56dd19aadc73947dd` |
| SHA-256 | `36003d068b2307507439136d98f05070d93a45f4a5b7eeee37faa5afd3517398` |
| SHA3-384 | `659386f59560fdb9271186155d6545d04860666e213914f085ae1f88ab19779804513cff26712e6ea9f15510cb6209ed` |
| TLSH | `T1CCA45B85BC809B96C5D12BB7FB6E9288331317B8D2EF70078D159B2467DBC960F7A640` |
| TELFHASH | `t133e060e46c1036739f80a280dcff2328034e92e817c07283293c3fc7c10188018af81e` |
| SSDEEP | `12288:Fpu0AtBkbxc9S3bEA0P8h2TR9RRAOqZh:jusGZAik` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_36003d06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36003d068b2307507439136d98f05070d93a45f4a5b7eeee37faa5afd3517398"
    family = "Mirai"
    file_name = "sever1078.arm"
    file_type = "elf"
    first_seen = "2026-09-19 04:23:13"
  condition:
    hash.sha256(0, filesize) == "36003d068b2307507439136d98f05070d93a45f4a5b7eeee37faa5afd3517398"
}
```

### Sample 21: `2a62a9e5f088a43e`

| Field | Value |
|---|---|
| SHA-256 | `2a62a9e5f088a43e4f2b4874b8b4506987350ed6257f5e38dd45d0db8d339c72` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-19 04:22:28` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16116c361672ab14b29f6174f7aec6d1` |
| SHA-256 | `2a62a9e5f088a43e4f2b4874b8b4506987350ed6257f5e38dd45d0db8d339c72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_2a62a9e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a62a9e5f088a43e4f2b4874b8b4506987350ed6257f5e38dd45d0db8d339c72"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-19 04:22:28"
  condition:
    hash.sha256(0, filesize) == "2a62a9e5f088a43e4f2b4874b8b4506987350ed6257f5e38dd45d0db8d339c72"
}
```

### Sample 22: `0558cb79f61501b0`

| Field | Value |
|---|---|
| SHA-256 | `0558cb79f61501b015b4644c48198bcd0ebc2af0d87b9a12965b5d22563da2ac` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-09-19 04:22:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec9816c54151ab704b746db07765d577` |
| SHA-1 | `2fe71df6bc5fe5f8946e0bb90d77cce12b8503c3` |
| SHA-256 | `0558cb79f61501b015b4644c48198bcd0ebc2af0d87b9a12965b5d22563da2ac` |
| SHA3-384 | `f640278a508dd093b8ae75bb4890a5c120b9cc7d11fc20085f9e2c6fffeebe87f8515db96f118850c93b3185f4b9837e` |
| TLSH | `T1D1F49C0DEA62D471E07294B2058FCBB39934D43512539BA3EF970928F8627A09F9F35D` |
| TELFHASH | `t171d1b8b32ead48ea33f09e02c30a2711dd0ad67364d035aa45b3569673b2e429fb4d34` |
| SSDEEP | `12288:OCmIRv60G8mcnTihADhXaGZCLu00iRuSCV3CQj/0NpXoDTC1xvYOV43t:gIRv60G8maTihADhKGZCLmiMhV3TjGIe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_0558cb79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0558cb79f61501b015b4644c48198bcd0ebc2af0d87b9a12965b5d22563da2ac"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-19 04:22:22"
  condition:
    hash.sha256(0, filesize) == "0558cb79f61501b015b4644c48198bcd0ebc2af0d87b9a12965b5d22563da2ac"
}
```

### Sample 23: `30f5b70aae2ebd25`

| Field | Value |
|---|---|
| SHA-256 | `30f5b70aae2ebd25b9659f16475bd756e1e02d2010ff19b8a75364350c60d832` |
| Family label | `Mirai` |
| File name | `sever1078.arm` |
| File type | `elf` |
| First seen | `2026-09-19 04:22:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82fdfb513c309a5c41bfba47815ab892` |
| SHA-1 | `ea9b1dc4d729d5da60101597b75758f3609f4f93` |
| SHA-256 | `30f5b70aae2ebd25b9659f16475bd756e1e02d2010ff19b8a75364350c60d832` |
| SHA3-384 | `de0c2ba56d4c4eafc64dcce3e26f0453b86f7924a28bc9614e53c4b79e662d5d95bdb903ff06628715e3e5644f48be08` |
| TLSH | `T10A2412874FADB0BD52B342FD854CE4793F0139CB9272EACD3A01196D2E0966E8365C64` |
| SSDEEP | `6144:d8iRO5Q9Sl/8ApL5xEFLz6YyQnnDbjkVPBNh1X:9RO2cFpHEFLz6dQnXcX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_30f5b70a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f5b70aae2ebd25b9659f16475bd756e1e02d2010ff19b8a75364350c60d832"
    family = "Mirai"
    file_name = "sever1078.arm"
    file_type = "elf"
    first_seen = "2026-09-19 04:22:20"
  condition:
    hash.sha256(0, filesize) == "30f5b70aae2ebd25b9659f16475bd756e1e02d2010ff19b8a75364350c60d832"
}
```

### Sample 24: `0b3c69dbd3c92bd7`

| Field | Value |
|---|---|
| SHA-256 | `0b3c69dbd3c92bd7b37ca0a6e6e426146aab1b71aecd696bdb67d39a9bbef22b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 04:20:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4d82ba652af8f97455aa46da6be15fa` |
| SHA-1 | `50f9761f0bc528370860e008a51e9d03ea42c351` |
| SHA-256 | `0b3c69dbd3c92bd7b37ca0a6e6e426146aab1b71aecd696bdb67d39a9bbef22b` |
| SHA3-384 | `990c5212aea85ce184a14437fc65c1947556236c5e7b56158cc228b683605f8402768a0ffb3a2e1ba2fc21ba9af87a70` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1AF62C686D8A26FACDE4EC0703B11FC786D703AA08A655AE3D7819C345DB39D04524FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UIvBgn:fKOe2/7c9sN3zfZR1m+RGL6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_0b3c69db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3c69dbd3c92bd7b37ca0a6e6e426146aab1b71aecd696bdb67d39a9bbef22b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:20:50"
  condition:
    hash.sha256(0, filesize) == "0b3c69dbd3c92bd7b37ca0a6e6e426146aab1b71aecd696bdb67d39a9bbef22b"
}
```

### Sample 25: `4a0e3a81f8f1134b`

| Field | Value |
|---|---|
| SHA-256 | `4a0e3a81f8f1134bbec6f139ca9d039a71ae49df1df3267e5d3135a1c813f0f8` |
| Family label | `Mirai` |
| File name | `sever1078.x86_64` |
| File type | `elf` |
| First seen | `2026-09-19 04:18:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddcabd836dcdc3cda83e0840982870e6` |
| SHA-1 | `f79696742ffac1ba6b7111575452938271a4e706` |
| SHA-256 | `4a0e3a81f8f1134bbec6f139ca9d039a71ae49df1df3267e5d3135a1c813f0f8` |
| SHA3-384 | `1f48ccbe89ddac23f9e258f955d692bc6cc988f5db82fbcd2b16dd9e25989f34bcb0858e2311626c43be5f16e8289a16` |
| TLSH | `T19DA4494398D944FDC189C074479FA2379AB2B46C1238BB9B2BC1EB663D25FA0A71D744` |
| TELFHASH | `t155a187b048f974a561daca007303e57d8e3614e5a2ed36721723ac5cefd9ec05ca6c22` |
| SSDEEP | `6144:9PHTtWFLxun/Knm7gN3vl6pbcKYw7IS/tLslt+EgvzkQWih:94FLxunSMIvguU9LZEXih` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_4a0e3a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a0e3a81f8f1134bbec6f139ca9d039a71ae49df1df3267e5d3135a1c813f0f8"
    family = "Mirai"
    file_name = "sever1078.x86_64"
    file_type = "elf"
    first_seen = "2026-09-19 04:18:13"
  condition:
    hash.sha256(0, filesize) == "4a0e3a81f8f1134bbec6f139ca9d039a71ae49df1df3267e5d3135a1c813f0f8"
}
```

### Sample 26: `fc4e159f84786739`

| Field | Value |
|---|---|
| SHA-256 | `fc4e159f8478673943d1d52366f5c274f95fd6ddb3618bd75b873154e72fca0a` |
| Family label | `Mirai` |
| File name | `sever1078.x86_64` |
| File type | `elf` |
| First seen | `2026-09-19 04:17:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d85dacde51686d7a4fa5daa7df4474b2` |
| SHA-1 | `3271c5576811e7def810e4667922df65079475e6` |
| SHA-256 | `fc4e159f8478673943d1d52366f5c274f95fd6ddb3618bd75b873154e72fca0a` |
| SHA3-384 | `808f5a6bf3ad444161d85bcc678f3addc4e5154e1457d6ab1d5433f9b796d89898878a907a0077fa37d9d368ec8c41f2` |
| TLSH | `T13D141379D8767738FD4A0F7C94128A9983AF783E8E2169033EC4FCF09272595485683E` |
| SSDEEP | `6144:uKYNIfdYSZSbE0vX1/pTM0Y74RsHSHXK3giQu6:uBI2rbrf1/pT6FHF3giq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_fc4e159f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc4e159f8478673943d1d52366f5c274f95fd6ddb3618bd75b873154e72fca0a"
    family = "Mirai"
    file_name = "sever1078.x86_64"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:36"
  condition:
    hash.sha256(0, filesize) == "fc4e159f8478673943d1d52366f5c274f95fd6ddb3618bd75b873154e72fca0a"
}
```

### Sample 27: `5e3fd0a185089ff3`

| Field | Value |
|---|---|
| SHA-256 | `5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401` |
| Family label | `unknown` |
| File name | `5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401` |
| File type | `elf` |
| First seen | `2026-09-19 04:17:23` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c43238370d19d9b002f8ead035e56664` |
| SHA-1 | `7187d503d7669bba26ad28b4ce5cdcdf1577b12a` |
| SHA-256 | `5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401` |
| SHA3-384 | `c2d69c00d9f41eff4b2b4aa0c3368cc74e19c64ea55e38d0eb2e635ed929730194d142d63b9fec2f5c3e3161295c408f` |
| TLSH | `T1ADC3126293230C4BC42538FEBE16E6162D8B2E69248D405D46F5E77A5FB70C8EAF1313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lx2:biMYFJvw6Yh0b1gKobtCGCmCRlrisO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_5e3fd0a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401"
    family = "unknown"
    file_name = "5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:23"
  condition:
    hash.sha256(0, filesize) == "5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401"
}
```

### Sample 28: `bb2d199a16d8aaab`

| Field | Value |
|---|---|
| SHA-256 | `bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532` |
| Family label | `unknown` |
| File name | `bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532` |
| File type | `elf` |
| First seen | `2026-09-19 04:17:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7838d3e39876e957328d827ddbe212f2` |
| SHA-1 | `65269bb0bb38c296fcb9d0fddb08b7e6cf328d36` |
| SHA-256 | `bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532` |
| SHA3-384 | `96316efa0e8aedb0373f21c380e9002b952c060826dde5e7d02137785159daeade61f034470770ffe296dfc94dc83ac6` |
| TLSH | `T11EB3124AFF359D0B9F0009B31BCA9E8E9C697B6B02DBB4A469C2954F57901CE7D52208` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+Vu:phNlHuBafLeBtfCzpta8xlBIOdVoh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_bb2d199a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532"
    family = "unknown"
    file_name = "bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:18"
  condition:
    hash.sha256(0, filesize) == "bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532"
}
```

### Sample 29: `e91476737fb99a39`

| Field | Value |
|---|---|
| SHA-256 | `e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7` |
| Family label | `Mirai` |
| File name | `e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7` |
| File type | `elf` |
| First seen | `2026-09-19 04:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df925e640cb8e40e25f4ce5e42803103` |
| SHA-1 | `ff578fcc9ba24ef8588570c51eeebe1cb1a2ca9b` |
| SHA-256 | `e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7` |
| SHA3-384 | `c14d8ce51452b7e8e7246e46b21682634c9a36111b466185b642d052c369d8308e731e7ee09ff7da65e64feec19fd1d2` |
| TLSH | `T1F6B3079BBC919E5945D413BBBE6E418E330323B8D2DF7113DD141F18B6CA94F0E6A682` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQg2:T2s/gAWuboqsJ9xcJxspJBqQg2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_e9147673
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7"
    family = "Mirai"
    file_name = "e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:12"
  condition:
    hash.sha256(0, filesize) == "e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7"
}
```

### Sample 30: `edc2a48504d4b809`

| Field | Value |
|---|---|
| SHA-256 | `edc2a48504d4b809806eab7587fd6c5c22ff2b75b550840c358dd7995c2871bf` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-19 04:11:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8203e072b8eb3376e9c01b662774697b` |
| SHA-1 | `c92e139043accd64847416c02d1297fe93a6a30d` |
| SHA-256 | `edc2a48504d4b809806eab7587fd6c5c22ff2b75b550840c358dd7995c2871bf` |
| SHA3-384 | `4e06a763b6e4777a589379f25a207b7a672c54a25c5870a0bc30ba4a9c53a34e3f5c379f37f95adbd405d0d8e9994690` |
| TLSH | `T1E1F47D02AF440FEBC89FCD31412D434716AD9ADB46D2A375A1BCCE48BA4D2994EF3578` |
| SSDEEP | `12288:kEVjpWxAwAfiYhPdDON0WXfKfM72yVQRs3A9mWbYzkg1iB0/yKyrlOD1lk8a2ARO:L3TRAhOkgFNU+g9BPJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_edc2a485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edc2a48504d4b809806eab7587fd6c5c22ff2b75b550840c358dd7995c2871bf"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-19 04:11:37"
  condition:
    hash.sha256(0, filesize) == "edc2a48504d4b809806eab7587fd6c5c22ff2b75b550840c358dd7995c2871bf"
}
```

### Sample 31: `a68650aa4400be5e`

| Field | Value |
|---|---|
| SHA-256 | `a68650aa4400be5e7f4800c7fa4b3b2a848fc2a91d9634a2ddaa225816eec52e` |
| Family label | `Mirai` |
| File name | `sever1078.m68k` |
| File type | `elf` |
| First seen | `2026-09-19 04:05:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a8bc92f809346fd3eddc3d3945b82e0` |
| SHA-1 | `b4d5708367f205792dfa360905fa7825718c7d2c` |
| SHA-256 | `a68650aa4400be5e7f4800c7fa4b3b2a848fc2a91d9634a2ddaa225816eec52e` |
| SHA3-384 | `eb9880a8f43581e968dd6c8fc2a432cc40753934f9ea21f8af257fe3975e893008bcdaba66ba30dcbdcdb9831ca655b3` |
| TLSH | `T15D949FC564408C7EEC46E67E8B131706A632E3202093571FA36BFE56BE3B5F56A31B41` |
| SSDEEP | `12288:SHkkvN0k5gmBSEdKivZd7hvh2plqSJek4aOInmVVLKyl:Lkvj5g5kZZ2plqSJek4WO9K6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_a68650aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a68650aa4400be5e7f4800c7fa4b3b2a848fc2a91d9634a2ddaa225816eec52e"
    family = "Mirai"
    file_name = "sever1078.m68k"
    file_type = "elf"
    first_seen = "2026-09-19 04:05:34"
  condition:
    hash.sha256(0, filesize) == "a68650aa4400be5e7f4800c7fa4b3b2a848fc2a91d9634a2ddaa225816eec52e"
}
```

### Sample 32: `8d06ef4fd7819b75`

| Field | Value |
|---|---|
| SHA-256 | `8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9` |
| Family label | `VShell` |
| File name | `8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9.exe` |
| File type | `exe` |
| First seen | `2026-09-19 04:02:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33b69ae22a52e3e6b04b525634c92809` |
| SHA-1 | `73062065ed9d1e8f43865f2b6b1c023578f4621f` |
| SHA-256 | `8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9` |
| SHA3-384 | `94d66d489dfa104c5d671cb84f810d0aac5169f23c9475c311a11baf8a3e067efab2bc189768b0051708ae0fcb103b43` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T18991C64270B989E7E85D45BB4C0FB8A4B919740A41C483A60378A5953F3957BF57CB0D` |
| SSDEEP | `48:6IIF9BlQaexxgZH7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMUM0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_032_8d06ef4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9"
    family = "VShell"
    file_name = "8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9.exe"
    file_type = "exe"
    first_seen = "2026-09-19 04:02:39"
  condition:
    hash.sha256(0, filesize) == "8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9"
}
```

### Sample 33: `bd31af1197eb787a`

| Field | Value |
|---|---|
| SHA-256 | `bd31af1197eb787a589ad43fc646fb6285c80e9b1769b870baec11d0277fe4b6` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-09-19 04:02:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35f6d731b7595748e0a04ae9c70357fc` |
| SHA-1 | `3560c8d02a81800e662f7c8bb1f79a2dd72d7f57` |
| SHA-256 | `bd31af1197eb787a589ad43fc646fb6285c80e9b1769b870baec11d0277fe4b6` |
| SHA3-384 | `69db73e2d15b4160944f85f533d34b4c3e84480d333f2ab810a72ddc9b07ef807300cfe7e195f7a265aaa67a5d71a25f` |
| TLSH | `T123F48D02FB085953D5531D775DBB07FDC324911204F6E2096A0EB72E06A3A7ADAEB3C9` |
| SSDEEP | `12288:3vXCw1TIb/ip5HcX2eFeafJ0oGywTVmdJBr0NXK5O138HNwfY:3vpDKzBJ5m38HmY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_bd31af11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd31af1197eb787a589ad43fc646fb6285c80e9b1769b870baec11d0277fe4b6"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-19 04:02:36"
  condition:
    hash.sha256(0, filesize) == "bd31af1197eb787a589ad43fc646fb6285c80e9b1769b870baec11d0277fe4b6"
}
```

### Sample 34: `5928481fada1e9be`

| Field | Value |
|---|---|
| SHA-256 | `5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec` |
| Family label | `VShell` |
| File name | `5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec.exe` |
| File type | `exe` |
| First seen | `2026-09-19 04:02:32` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa3d76d59cec28a3687d6c705d7d7147` |
| SHA-1 | `8875161ea554308bc171a70b66a178d8cab695d5` |
| SHA-256 | `5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec` |
| SHA3-384 | `f66029608d1e66b13cfa344f4f797783f1d25783b0741f6322b6e7dff1a36aa0e59badf3b160fc64ee81326a283561b2` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T18E91C64170B999E7E85C41BB4C0FB8A0B91D740A41C483B64338A5993E3A57BF5BCB0E` |
| SSDEEP | `48:6IIF9BlQaex2gZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMf70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_034_5928481f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec"
    family = "VShell"
    file_name = "5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec.exe"
    file_type = "exe"
    first_seen = "2026-09-19 04:02:32"
  condition:
    hash.sha256(0, filesize) == "5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec"
}
```

### Sample 35: `617963c03037db60`

| Field | Value |
|---|---|
| SHA-256 | `617963c03037db6071c36f60f7adc7fda0a6c2bd609ecf880cbb787fe9150c21` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:57:51` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d514142c5723fec904d446b5341ad80` |
| SHA-1 | `45faffd91bccffb16fb76b4822611be936111cb3` |
| SHA-256 | `617963c03037db6071c36f60f7adc7fda0a6c2bd609ecf880cbb787fe9150c21` |
| SHA3-384 | `ef56f6d2fb5fe6e731295c2a9743d92cbb28527c719c0aea97865d7974ffc18b0cf3353db608da87de243e7904219fc3` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16A62D586E8A26F6CDE4F80B03A11F838BD7436958A6559E3DB828C355DA79D00434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ugn0he:fKOe2/7c9sN3zfZR1m+RG0h6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_617963c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "617963c03037db6071c36f60f7adc7fda0a6c2bd609ecf880cbb787fe9150c21"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:57:51"
  condition:
    hash.sha256(0, filesize) == "617963c03037db6071c36f60f7adc7fda0a6c2bd609ecf880cbb787fe9150c21"
}
```

### Sample 36: `6932db4dc19fec01`

| Field | Value |
|---|---|
| SHA-256 | `6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06` |
| Family label | `Mirai` |
| File name | `6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06.elf` |
| File type | `elf` |
| First seen | `2026-09-19 03:57:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f274c8b2a424e7b3816013831b07e873` |
| SHA-1 | `d1a91ee5618bb7d4475b068dfcc940d36a614cfa` |
| SHA-256 | `6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06` |
| SHA3-384 | `0c877050ba2a264513db276de49b7652129ea7ddd092dfb279d01261c990aebf4faf039600ba3c4597c3186f94079a18` |
| TLSH | `T185E16207E2D5CE72D8CD133846931749213AD86EAB83AF03650C19A9EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFS146Vwz7cSym4S2ofahbpZiQ:fsue7c9JOFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_6932db4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06"
    family = "Mirai"
    file_name = "6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06.elf"
    file_type = "elf"
    first_seen = "2026-09-19 03:57:33"
  condition:
    hash.sha256(0, filesize) == "6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06"
}
```

### Sample 37: `f48801ccbac2ccff`

| Field | Value |
|---|---|
| SHA-256 | `f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b` |
| Family label | `VShell` |
| File name | `f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b.exe` |
| File type | `exe` |
| First seen | `2026-09-19 03:57:30` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c01642e10cc9a3b7eba0dbbd469c8f3` |
| SHA-1 | `148b11f802e56db56d532f94e7204dcfccc56872` |
| SHA-256 | `f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b` |
| SHA3-384 | `f4671e675aa4afdba2d89b5b11e1285377202b7d1d303f661b0b5b8ae07d15df7e46739dfc410d7415f516f98c8a09c7` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T163716088F3175EF1E43C86F940D3A614D059ABB8C250BF4D5E60381D7C220BA255AF97` |
| SSDEEP | `48:6Icwm0yt2WVJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j7tnSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_037_f48801cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b"
    family = "VShell"
    file_name = "f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b.exe"
    file_type = "exe"
    first_seen = "2026-09-19 03:57:30"
  condition:
    hash.sha256(0, filesize) == "f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b"
}
```

### Sample 38: `3daf295e54b996fd`

| Field | Value |
|---|---|
| SHA-256 | `3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4` |
| Family label | `VShell` |
| File name | `3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4.exe` |
| File type | `exe` |
| First seen | `2026-09-19 03:57:28` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a70f530117dc42b9c084fb7ff0766c22` |
| SHA-1 | `c61cd11f8137efec264b89d79cdc02c7d56054b5` |
| SHA-256 | `3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4` |
| SHA3-384 | `507e13408b2509f51ec1ed936205e7b14cbb520c7a3938d1a4bcfd9946aa9777b5329b64a30a7932f2d43da089a67421` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T161716188F3136EF5E82C47F900D3A524D0599BB8C150BF4D5F60381D3C210BA255AF97` |
| SSDEEP | `48:6Icwm0f8t2WtJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jNtvSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_038_3daf295e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4"
    family = "VShell"
    file_name = "3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4.exe"
    file_type = "exe"
    first_seen = "2026-09-19 03:57:28"
  condition:
    hash.sha256(0, filesize) == "3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4"
}
```

### Sample 39: `bcdfe375371a407f`

| Field | Value |
|---|---|
| SHA-256 | `bcdfe375371a407fe35e5ba6db910c23eea70971f8a8b33ee86564a03fb4348c` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-09-19 03:54:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `103a595ba684a7dafd1608f24f558dec` |
| SHA-1 | `a2112bf4e7f1664651c28bff73414d2a67b8ae7a` |
| SHA-256 | `bcdfe375371a407fe35e5ba6db910c23eea70971f8a8b33ee86564a03fb4348c` |
| SHA3-384 | `0ed758232508ce000fe5444c8c3abd8a2b3451345881c92c2b052c002c2c32388d89da5defa70b7aac5f72709960ca22` |
| TLSH | `T121D4AE55F659EE43C4B2AA36C8BB8396B132ED6F5BA3D316320D557C38133398F19284` |
| TELFHASH | `t166317a61e51afd251692cbccebc4b366c4bae9004a0e3c67c5b0442d9b30197278fdea` |
| SSDEEP | `12288:/0eSMESErUmURXYthWepSaWLHnLVBA4pzeCWZ5xcNzWlC:ZvPpBLu5xcZWl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_bcdfe375
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcdfe375371a407fe35e5ba6db910c23eea70971f8a8b33ee86564a03fb4348c"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-19 03:54:15"
  condition:
    hash.sha256(0, filesize) == "bcdfe375371a407fe35e5ba6db910c23eea70971f8a8b33ee86564a03fb4348c"
}
```

### Sample 40: `cf7aa2cec6060853`

| Field | Value |
|---|---|
| SHA-256 | `cf7aa2cec6060853d6b1ac778d85b8acd049407388b74c121e7a9c3763013287` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:52:55` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1c4e7b8e9913541840ef2b3d9440579` |
| SHA-1 | `a8cd3f7ec95e04d42a0f86b9ba6f3bf34e933b9a` |
| SHA-256 | `cf7aa2cec6060853d6b1ac778d85b8acd049407388b74c121e7a9c3763013287` |
| SHA3-384 | `df6eb2fb1665fe367169ffedfcbf17410d1973c12647d14770374f661cdf3cabd8b911a37996165d0f42aaa447a5e265` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10362E786D8A22F6CCE4E80707A11F878BDB436918A655DE7D7828C359DA39D10434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U6DSm6:fKOe2/7c9sN3zfZR1m+RGPFuOt6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_cf7aa2ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf7aa2cec6060853d6b1ac778d85b8acd049407388b74c121e7a9c3763013287"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:52:55"
  condition:
    hash.sha256(0, filesize) == "cf7aa2cec6060853d6b1ac778d85b8acd049407388b74c121e7a9c3763013287"
}
```

### Sample 41: `b91f190f50e9d993`

| Field | Value |
|---|---|
| SHA-256 | `b91f190f50e9d993ae71fba5cf640c6f524073630af9592ead12cfed1fad6720` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:50:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb1507dfa4626822e9dfaeecf6d6ef4` |
| SHA-1 | `9b45471fd6a865027424c0e239b6f613d71be417` |
| SHA-256 | `b91f190f50e9d993ae71fba5cf640c6f524073630af9592ead12cfed1fad6720` |
| SHA3-384 | `b40732b269085c4127a5095bdac89cc399e48916e81802fcd0aaa293a5acefc553429d50715c2e38979ec7ffdc281031` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16762B68AECA22E5CDE4FD0703A21FC386D7436D4866659E7DB828D355DA39D10024EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UKYZBM:fKOe2/7c9sN3zfZR1m+RGqZ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_b91f190f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b91f190f50e9d993ae71fba5cf640c6f524073630af9592ead12cfed1fad6720"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:50:08"
  condition:
    hash.sha256(0, filesize) == "b91f190f50e9d993ae71fba5cf640c6f524073630af9592ead12cfed1fad6720"
}
```

### Sample 42: `eb234f96dfe6851f`

| Field | Value |
|---|---|
| SHA-256 | `eb234f96dfe6851faf95794f0022b18d2b6abb9cbb8cbdfb41d39e6ccbc95a3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:46:56` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a10ec2ed12b19af7c3792f5c1ce774c` |
| SHA-1 | `d742299ec2d16ad8b096a5ce0869ba8fa7c1dfcf` |
| SHA-256 | `eb234f96dfe6851faf95794f0022b18d2b6abb9cbb8cbdfb41d39e6ccbc95a3e` |
| SHA3-384 | `fd38dc06a7af6bb937065cb6e31a3274ce102309b0184fad55af6918f2886bc0ccc7e40643bb72cbe93d1648977cafc1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19B62D7C6D9E26F9DDE4E80703A11F838BDB47690866599E3C7918CB15D63CD00528EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UlTVde:fKOe2/7c9sN3zfZR1m+RGS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_eb234f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb234f96dfe6851faf95794f0022b18d2b6abb9cbb8cbdfb41d39e6ccbc95a3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:46:56"
  condition:
    hash.sha256(0, filesize) == "eb234f96dfe6851faf95794f0022b18d2b6abb9cbb8cbdfb41d39e6ccbc95a3e"
}
```

### Sample 43: `23b6d0c93d363251`

| Field | Value |
|---|---|
| SHA-256 | `23b6d0c93d3632515d0fed2d405af26a01a8b4e7ef20c42a5f76be055da9f858` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:44:20` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `161f02365f3325cb886c5a57ce6037fc` |
| SHA-1 | `e34fa775f87c67fa1e95e9096b8309e80d3e9efb` |
| SHA-256 | `23b6d0c93d3632515d0fed2d405af26a01a8b4e7ef20c42a5f76be055da9f858` |
| SHA3-384 | `09ebe0fe7674a2518f4c6ce717a2f6b65320de829659d08697dee79ab2e5a4053d68a09627131c64b08ec57f1ccc5185` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CC62B786D9922E6CCE4E80703A11FC396DB576D186555EE3E7828C3559639D00238FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UobBgn:fKOe2/7c9sN3zfZR1m+RGf6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_23b6d0c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23b6d0c93d3632515d0fed2d405af26a01a8b4e7ef20c42a5f76be055da9f858"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:44:20"
  condition:
    hash.sha256(0, filesize) == "23b6d0c93d3632515d0fed2d405af26a01a8b4e7ef20c42a5f76be055da9f858"
}
```

### Sample 44: `f3bf1da005ec5142`

| Field | Value |
|---|---|
| SHA-256 | `f3bf1da005ec5142943b1b973d04b842d93ae8afe27959e1e75ab806213e1ce7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:31:21` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1ffa5b2eea1b17be1dd982ce9c8d97b` |
| SHA-1 | `0e32d113ed0957d02120c9f61f92665eda1d415d` |
| SHA-256 | `f3bf1da005ec5142943b1b973d04b842d93ae8afe27959e1e75ab806213e1ce7` |
| SHA3-384 | `b26c6c8ddf8e2ef8fb222a3e37a1f0e2073b3d8a2f248192765958e933a384b16725c6bd343af3e4a649f8ce809ccb66` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C162C686D9925EADDE4EC0B03E21F838BD74769086669DF7E7828C349D639D00434EBD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uj4pBM:fKOe2/7c9sN3zfZR1m+RGe4p6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_f3bf1da0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3bf1da005ec5142943b1b973d04b842d93ae8afe27959e1e75ab806213e1ce7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:31:21"
  condition:
    hash.sha256(0, filesize) == "f3bf1da005ec5142943b1b973d04b842d93ae8afe27959e1e75ab806213e1ce7"
}
```

### Sample 45: `b7cfb606dfbcf467`

| Field | Value |
|---|---|
| SHA-256 | `b7cfb606dfbcf4678a15c0452795a5c4cbd3a25f36a63085cd87335920b4ac9a` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.22124.6146` |
| File type | `elf` |
| First seen | `2026-09-19 03:31:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5507e1006243d50487c33b62b54025cb` |
| SHA-1 | `3bc24fd9da0937e153460ba0c640d7acb8661819` |
| SHA-256 | `b7cfb606dfbcf4678a15c0452795a5c4cbd3a25f36a63085cd87335920b4ac9a` |
| SHA3-384 | `5cebf95294fe0246a404707b3802deee4441cbbebe0ccae525668da9ec8bf0b16b3aa9843d5f73e11d57c85f9302e81c` |
| TLSH | `T1F5D45B46ED408B57D4D11BBABBAF524533235BB4E3EB72074D0CABB43B8699A4F76100` |
| TELFHASH | `t1b542ff0d6b2387577e5188d85b99a7e71803850b9a9ccbd19ed88b0fc6340bbfd128dd` |
| SSDEEP | `12288:y1iYcuH6VwnqVA725cfy9Ybxu38tyDatiaZ7pn+7Uue0gQu40zddzKLpkVlICBa1:SOM7E7UuM40IqrBYdu07t2S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_b7cfb606
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7cfb606dfbcf4678a15c0452795a5c4cbd3a25f36a63085cd87335920b4ac9a"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.22124.6146"
    file_type = "elf"
    first_seen = "2026-09-19 03:31:16"
  condition:
    hash.sha256(0, filesize) == "b7cfb606dfbcf4678a15c0452795a5c4cbd3a25f36a63085cd87335920b4ac9a"
}
```

### Sample 46: `1b6901652fb859d7`

| Field | Value |
|---|---|
| SHA-256 | `1b6901652fb859d727f800f32d7e81facca92ebf5ae5333ad147f8df16e3f0f1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:31:00` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff491978b18b7213eb984e48292ec552` |
| SHA-1 | `53a740c3a8b7fa32ebc0cb165fe3973056f4cfc4` |
| SHA-256 | `1b6901652fb859d727f800f32d7e81facca92ebf5ae5333ad147f8df16e3f0f1` |
| SHA3-384 | `a9446ec132322d3fd6eeaed81589ada0ab9377f1f972ff764cac3841e9c769c003856e8599cb9a73d418b1c65652a6c7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19862C896DC922A5CCE8E80703A55F97CADB537D485AA59E3D7828C305EE38D14024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UNl5k+:fKOe2/7c9sN3zfZR1m+RGDH6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_1b690165
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b6901652fb859d727f800f32d7e81facca92ebf5ae5333ad147f8df16e3f0f1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:31:00"
  condition:
    hash.sha256(0, filesize) == "1b6901652fb859d727f800f32d7e81facca92ebf5ae5333ad147f8df16e3f0f1"
}
```

### Sample 47: `94e748ccd80e0532`

| Field | Value |
|---|---|
| SHA-256 | `94e748ccd80e0532d0dc740d0fcff487d3e5a130da0039ab4369f45da1187dac` |
| Family label | `Mirai` |
| File name | `SecuriteInfo.com.Linux.Mirai.9816.22124.6146` |
| File type | `elf` |
| First seen | `2026-09-19 03:30:31` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18d9dd9dd1be02ec788aa0b453cfba85` |
| SHA-1 | `a3cae4325b66fea35d6bf28ca7adaf82d7f7918e` |
| SHA-256 | `94e748ccd80e0532d0dc740d0fcff487d3e5a130da0039ab4369f45da1187dac` |
| SHA3-384 | `b1115672d773139bc2064b1072f34e61a323539c4fe4356dbc96ef83fa2515d92bbfb084847ac72c1288cf644776b73a` |
| TLSH | `T1FF4423B2CFD81F56AF3C47514376E9A0C706F1C6E31798AC979139CE8352CA9EA36241` |
| SSDEEP | `6144:esjvTrGtIN4eJ0uHfeRWAAQU8oD+TvefGk:vq44OV18oDvfGk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_94e748cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94e748ccd80e0532d0dc740d0fcff487d3e5a130da0039ab4369f45da1187dac"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.22124.6146"
    file_type = "elf"
    first_seen = "2026-09-19 03:30:31"
  condition:
    hash.sha256(0, filesize) == "94e748ccd80e0532d0dc740d0fcff487d3e5a130da0039ab4369f45da1187dac"
}
```

### Sample 48: `42629c5dddb5fc27`

| Field | Value |
|---|---|
| SHA-256 | `42629c5dddb5fc27f22bfba93bcaf6f321cc788fe57a0f4627694ab9c22d642e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:29:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10d05605d8a50b3e1679b13e7017d788` |
| SHA-1 | `4c2a97d86abc15ceadc32dda1feded2222baeac3` |
| SHA-256 | `42629c5dddb5fc27f22bfba93bcaf6f321cc788fe57a0f4627694ab9c22d642e` |
| SHA3-384 | `c21889d10706cf0ad19027f2d4a8f1a660a43593c298db047b825a3a5f4e396e1eb3c9743a8e01c34a4fdc429ef3a2df` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C862C78698921B6CCE4E80707A51FD387D7476908AA699F7D7C28C395DA79D00034FBE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U4eBgn:fKOe2/7c9sN3zfZR1m+RG66C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_42629c5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42629c5dddb5fc27f22bfba93bcaf6f321cc788fe57a0f4627694ab9c22d642e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:29:41"
  condition:
    hash.sha256(0, filesize) == "42629c5dddb5fc27f22bfba93bcaf6f321cc788fe57a0f4627694ab9c22d642e"
}
```

### Sample 49: `efc900e61b9c8342`

| Field | Value |
|---|---|
| SHA-256 | `efc900e61b9c834233fa391418f38d45a2cfcb2ce987df01bf0b8c830ce34f1b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:28:55` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7cb693b2aaed4f57da066655bd2c28a` |
| SHA-1 | `82b9b9c2703b041241ff90175477e76052d9ac69` |
| SHA-256 | `efc900e61b9c834233fa391418f38d45a2cfcb2ce987df01bf0b8c830ce34f1b` |
| SHA3-384 | `f4f42d6d855cdeb87aa3f3b3470ab373dcff767b2fae113d2a2185a6b00f60cdd466274bd2df8711ad0b1cff2019e277` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CE62C686D8A22F9DDE4EC0703E11F878BDB136A0866959F7D7928C3559A38D10434FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UjLWYe:fKOe2/7c9sN3zfZR1m+RGbY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_efc900e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc900e61b9c834233fa391418f38d45a2cfcb2ce987df01bf0b8c830ce34f1b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:28:55"
  condition:
    hash.sha256(0, filesize) == "efc900e61b9c834233fa391418f38d45a2cfcb2ce987df01bf0b8c830ce34f1b"
}
```

### Sample 50: `829ed6118452d3df`

| Field | Value |
|---|---|
| SHA-256 | `829ed6118452d3df02d66e3ffb0e754233124b97851775c17971a3ea32eed5e5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:28:32` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9d922c704c8ad3709e80fd70f6c07e2` |
| SHA-1 | `731c7c4fde24f75a45c37010c72874bdc093ab54` |
| SHA-256 | `829ed6118452d3df02d66e3ffb0e754233124b97851775c17971a3ea32eed5e5` |
| SHA3-384 | `8a968a809e684e44de391d0420e0cd1bb9df0901b72afaa173fb931deaaff04a1089169f9560dda030fe5b9a93138ddd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16C62E896D8A26F5CCE4E90B13A51F878BD70769086A95DE3DB828C305DE7AC00124FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RG6QJVzzzzzzzzzzzzzzzzzzzzzzzzM6C:fKOeOQOzUx6AW6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_829ed611
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "829ed6118452d3df02d66e3ffb0e754233124b97851775c17971a3ea32eed5e5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:28:32"
  condition:
    hash.sha256(0, filesize) == "829ed6118452d3df02d66e3ffb0e754233124b97851775c17971a3ea32eed5e5"
}
```

### Sample 51: `865fa80643980f86`

| Field | Value |
|---|---|
| SHA-256 | `865fa80643980f86897a6c2767f1165bcd99a24c712d83d33b2f6894a21f0c66` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:28:11` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `741bdb1fbd3a67c40cea34da7d966a6a` |
| SHA-1 | `2221141d78adf0a172038a17ac07af4b287528e4` |
| SHA-256 | `865fa80643980f86897a6c2767f1165bcd99a24c712d83d33b2f6894a21f0c66` |
| SHA3-384 | `83cb39145ac34854471178ed6b6a20f0f0ceb1483ce2ea26ef6256aa458306b4a89df817dd762f8c8b5e90edee6c046e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14A62B6DA99D26F5CDE4EC0703A21F9797D7072D58666A9E7D7828C305AA38D00024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UeCk7e:fKOe2/7c9sN3zfZR1m+RGJ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_865fa806
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "865fa80643980f86897a6c2767f1165bcd99a24c712d83d33b2f6894a21f0c66"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:28:11"
  condition:
    hash.sha256(0, filesize) == "865fa80643980f86897a6c2767f1165bcd99a24c712d83d33b2f6894a21f0c66"
}
```

### Sample 52: `387dd9de2fe34888`

| Field | Value |
|---|---|
| SHA-256 | `387dd9de2fe34888bdd6cf2b698bee23af29483e6964bb5f0c2dab9da8eeaba1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:27:16` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `900f989fcdeaafc3f7e67e327d171b7b` |
| SHA-1 | `d3cab88325fc641537fa3f2f9d72e18ec972f367` |
| SHA-256 | `387dd9de2fe34888bdd6cf2b698bee23af29483e6964bb5f0c2dab9da8eeaba1` |
| SHA3-384 | `7bc26c53557ebb97fbadc52f1b7e611669a17137b391080120b30fb0b1515c2b65450c92f7f271e81c0adc13c5470887` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18062F986DE925EACCE4F90713B10F838AD743A918E6569E7E7828C354DA39D00135EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UrP1lR:fKOe2/7c9sN3zfZR1m+RG+PTw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_387dd9de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "387dd9de2fe34888bdd6cf2b698bee23af29483e6964bb5f0c2dab9da8eeaba1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:27:16"
  condition:
    hash.sha256(0, filesize) == "387dd9de2fe34888bdd6cf2b698bee23af29483e6964bb5f0c2dab9da8eeaba1"
}
```

### Sample 53: `14502cbd7bb5f101`

| Field | Value |
|---|---|
| SHA-256 | `14502cbd7bb5f10150195bb3a674998f7d0b881dffa68c24dc41ae3821f5d2a7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:26:31` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59a2dec6b20cd3d8b7d85bfab26851de` |
| SHA-1 | `03b6c0123b8e45f47f19798af529f493b0bba230` |
| SHA-256 | `14502cbd7bb5f10150195bb3a674998f7d0b881dffa68c24dc41ae3821f5d2a7` |
| SHA3-384 | `8b7d94a8581c77e21304f96620f785385c051cd822086725a60d8dd144224e6af56fed684b217da7282bdeb5613fc9b0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C862B696A8925F6CCE8FC0703A11FD78BD7036904A659DE3D7928C344EA78D01025FBE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U6ywBM:fKOe2/7c9sN3zfZR1m+RGlP6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_14502cbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14502cbd7bb5f10150195bb3a674998f7d0b881dffa68c24dc41ae3821f5d2a7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:26:31"
  condition:
    hash.sha256(0, filesize) == "14502cbd7bb5f10150195bb3a674998f7d0b881dffa68c24dc41ae3821f5d2a7"
}
```

### Sample 54: `02aea5882129f6b1`

| Field | Value |
|---|---|
| SHA-256 | `02aea5882129f6b1cf79073496070f9856ee809f537b09187736424ae2868ac7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:26:12` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `621b6ae22d4d74b3089e7d34f17ed63c` |
| SHA-1 | `5dd44bf9d1bd06eb9bb4765dc1c7b837649b257d` |
| SHA-256 | `02aea5882129f6b1cf79073496070f9856ee809f537b09187736424ae2868ac7` |
| SHA3-384 | `2135b493f35f5db5d8818c8713fc39b8fe43342d3e45170e7ae27f270e5a5a662394f0992c690c3397f88f1df0f8cc0f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C862B68BEAA21E6CDE8FC0703A11F86C7EB8729085655DE3D782CC205DA39D10425EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UjBBgn:fKOe2/7c9sN3zfZR1m+RG8B6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_02aea588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02aea5882129f6b1cf79073496070f9856ee809f537b09187736424ae2868ac7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:26:12"
  condition:
    hash.sha256(0, filesize) == "02aea5882129f6b1cf79073496070f9856ee809f537b09187736424ae2868ac7"
}
```

### Sample 55: `5050f0a6c2933dbc`

| Field | Value |
|---|---|
| SHA-256 | `5050f0a6c2933dbc79f6906f1ce683933bfa472f555d72c2d8359479178e2b10` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:24:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad10aff10f65e4abb490dd50ff89e9e` |
| SHA-1 | `15c2c97eaac0361f05ebe5a6e42b5f133d0a662d` |
| SHA-256 | `5050f0a6c2933dbc79f6906f1ce683933bfa472f555d72c2d8359479178e2b10` |
| SHA3-384 | `0c98d80c9ec9300510eb601f61da13a37fba5dfce41cd3867b97f865a20b435f3ab94b85279d3cffc79a29d6ee6f1b64` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19862C78BD8D22F5DDE4E80703E11FD28A9B036D04966A9E7D7828E345963AD05124FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UNIBgn:fKOe2/7c9sN3zfZR1m+RGd6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_5050f0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5050f0a6c2933dbc79f6906f1ce683933bfa472f555d72c2d8359479178e2b10"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:24:49"
  condition:
    hash.sha256(0, filesize) == "5050f0a6c2933dbc79f6906f1ce683933bfa472f555d72c2d8359479178e2b10"
}
```

### Sample 56: `5b32d178e1f875b9`

| Field | Value |
|---|---|
| SHA-256 | `5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497` |
| Family label | `Mozi` |
| File name | `5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497` |
| File type | `elf` |
| First seen | `2026-09-19 03:19:21` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips, Mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82c5d1afbfc2bf1589dbcb2001885d5a` |
| SHA-1 | `cb90aa86e767fbc7bd0610b5c1dcf183223a1698` |
| SHA-256 | `5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497` |
| SHA3-384 | `7856d85ae2ebaa7261d18357f8990cb81d684cff6ef26b97bb9cc63c776b6f0144d0e525043086eb025c63e355e8fd77` |
| TLSH | `T1DF42BFC8BA05E6E6F6145DF27C3C45BC869BF6AF0A66307048E5B85DC6058AB1E0F3C5` |
| SSDEEP | `192:fTu2PzRurki7SLDLVpVovt9SbVySN6TQ3JuGpymy/qD1zIWRzYFbYWvpK9pGd:flzEBkDOvTCZuQEkymy/Gf+3pK9pGd` |

#### Technical Assessment

- The sample is tracked as `Mozi` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mozi_056_5b32d178
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497"
    family = "Mozi"
    file_name = "5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:21"
  condition:
    hash.sha256(0, filesize) == "5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497"
}
```

### Sample 57: `53103b74eac117fb`

| Field | Value |
|---|---|
| SHA-256 | `53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497` |
| Family label | `unknown` |
| File name | `53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497` |
| File type | `elf` |
| First seen | `2026-09-19 03:19:15` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd21cec6e4be7deb27827ca3bed91ea3` |
| SHA-1 | `63af6e2fb211372e153252480cc37eb185c670b9` |
| SHA-256 | `53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497` |
| SHA3-384 | `4d9e81b3c5446f9ee4094d920b5988c5bb9bf61805d14b40446237b22419556dd3b869a4dfa15bc62fe6a50015762ead` |
| TLSH | `T198B3125193230D0FC43538FA7A16E6162D862E79248D419C4AF5EA7B5FB708CE9F2353` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxC:biMYFJvw6Yh0b1gKobtCGCmCRlrs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_53103b74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497"
    family = "unknown"
    file_name = "53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:15"
  condition:
    hash.sha256(0, filesize) == "53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497"
}
```

### Sample 58: `abbf368f01539f8c`

| Field | Value |
|---|---|
| SHA-256 | `abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2` |
| Family label | `unknown` |
| File name | `abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2` |
| File type | `elf` |
| First seen | `2026-09-19 03:19:09` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1955d0b4d4f3f3b00b376b9da548178d` |
| SHA-1 | `0f6b5d94426f0472b7f1262ae4410d557b071de7` |
| SHA-256 | `abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2` |
| SHA3-384 | `b55003e65a1600b47d38e6c303d81f2b0f6f8c485d202ea289d54b3de59f26f259e012fd4ebfe22e49d7cf0038776946` |
| TLSH | `T10BD3128AEF369C0E8F401DB32ADB5F8E9C5D7A6B41CBF4A8B9C1818F17A11C97D52114` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ10g:p3lOYoaja8xzx/0wsxzx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_abbf368f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2"
    family = "unknown"
    file_name = "abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:09"
  condition:
    hash.sha256(0, filesize) == "abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2"
}
```

### Sample 59: `ac16e2701b8fe6da`

| Field | Value |
|---|---|
| SHA-256 | `ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd` |
| Family label | `unknown` |
| File name | `ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd` |
| File type | `elf` |
| First seen | `2026-09-19 03:19:03` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a17682112e4151d9b244cf0b5941899` |
| SHA-1 | `1fec82935e2e1d64cb32c778e3c15779b17e9e01` |
| SHA-256 | `ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd` |
| SHA3-384 | `e324792697e337c409385078491c9730514f42666fd36bdca64aac927e196aff40cde71b78b3c27f6c6ee37509cb953a` |
| TLSH | `T152C3189BFC81DE6946C0277BFE2E418A330327B4D1DF71539D141F28B68A94F0E6A652` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJ1:T2s/gAWuboqsJ9xcJxspJBqQgTuaJ1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_ac16e270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd"
    family = "unknown"
    file_name = "ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:03"
  condition:
    hash.sha256(0, filesize) == "ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd"
}
```

### Sample 60: `22b34fe804f862da`

| Field | Value |
|---|---|
| SHA-256 | `22b34fe804f862da2c545dcc417af6362193c081165c2206f1237243bae212fd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:17:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8de8e32706e01a9586f96fe4bac357ef` |
| SHA-1 | `54dc7e3f6b277c90de43ee8a70b0e79d5ce62df3` |
| SHA-256 | `22b34fe804f862da2c545dcc417af6362193c081165c2206f1237243bae212fd` |
| SHA3-384 | `917f427117c95e05cb42f69aa1d944d639689fc797f7fd6f759b8099bd5801d1f444dbdfcc64d71c73b380f1ea452798` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10B62C58ADA936F5DCE4E90707E11F868BD7036958A6A99E3D7C28C3059A39D10034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UoDBgn:fKOe2/7c9sN3zfZR1m+RGH6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_22b34fe8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22b34fe804f862da2c545dcc417af6362193c081165c2206f1237243bae212fd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:17:27"
  condition:
    hash.sha256(0, filesize) == "22b34fe804f862da2c545dcc417af6362193c081165c2206f1237243bae212fd"
}
```

### Sample 61: `2406b42d46d1aba0`

| Field | Value |
|---|---|
| SHA-256 | `2406b42d46d1aba07d8bbe21ecc07799ef478e327447fda14dedd6dede8a5f86` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:13:57` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb5a220f13c9918c6eb147a72e6195df` |
| SHA-1 | `3e868571b0fb1de9d052081d6de7a27974ede769` |
| SHA-256 | `2406b42d46d1aba07d8bbe21ecc07799ef478e327447fda14dedd6dede8a5f86` |
| SHA3-384 | `a8380e86d01b1efd91bce1e0f7586f81b3204ae0e6f3a6164031cb7dd140ecf54badef9301f66404afa4be66ad44d9ac` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E562D7A6DDA2AF5CCE4E80707A11FD38ADB172904A6659E3D7828C315E678D040B4FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJ1QwC:fKOe2/7c9sN3zfZR1m+RGWq66C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_2406b42d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2406b42d46d1aba07d8bbe21ecc07799ef478e327447fda14dedd6dede8a5f86"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:13:57"
  condition:
    hash.sha256(0, filesize) == "2406b42d46d1aba07d8bbe21ecc07799ef478e327447fda14dedd6dede8a5f86"
}
```

### Sample 62: `efa89746b5693167`

| Field | Value |
|---|---|
| SHA-256 | `efa89746b5693167d3ec46b17c77bf3c97eccdaebc2ab907d2f1ac08729888b8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 03:11:32` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21b4def8eee78325d1c5cb8e253cff4f` |
| SHA-1 | `d6f522aea2c02fd768f0cbd0fb68229244c41afc` |
| SHA-256 | `efa89746b5693167d3ec46b17c77bf3c97eccdaebc2ab907d2f1ac08729888b8` |
| SHA3-384 | `26da289ba658973234016f7fe3f1abd552416c90f368bc918738a3bbf7aa94d637362de03d8be6657e59e084152cce05` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10762C886DD922E9CDE8F80B03A12F938AD7432D046665DE3D7928D315DA38D10068EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UCSBgn:fKOe2/7c9sN3zfZR1m+RG/S6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_efa89746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efa89746b5693167d3ec46b17c77bf3c97eccdaebc2ab907d2f1ac08729888b8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:11:32"
  condition:
    hash.sha256(0, filesize) == "efa89746b5693167d3ec46b17c77bf3c97eccdaebc2ab907d2f1ac08729888b8"
}
```

### Sample 63: `654dd2bef34c1a84`

| Field | Value |
|---|---|
| SHA-256 | `654dd2bef34c1a84a70315c12d50979e06e553c1f50530e95ab66e047d98f48d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:56:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ac6a732059f7e1a8aeeda4e51f5ed38` |
| SHA-1 | `1bdd739206efb55da72363254ace62663f3a33d9` |
| SHA-256 | `654dd2bef34c1a84a70315c12d50979e06e553c1f50530e95ab66e047d98f48d` |
| SHA3-384 | `0254ab900020ef4e1bebd05e0ee3c2c18d89528668272a5ac1a432857c42cd5b51b8692bcf6dc3744d79f92aa7e1fc2f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12A62D59AD9A22F6CCE4F90703B11F938AD7032948665A9E3D7928C349DB39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UO2tQe:fKOe2/7c9sN3zfZR1m+RGZz6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_654dd2be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "654dd2bef34c1a84a70315c12d50979e06e553c1f50530e95ab66e047d98f48d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:56:36"
  condition:
    hash.sha256(0, filesize) == "654dd2bef34c1a84a70315c12d50979e06e553c1f50530e95ab66e047d98f48d"
}
```

### Sample 64: `7eeaa1e1acb4b10e`

| Field | Value |
|---|---|
| SHA-256 | `7eeaa1e1acb4b10e54e1e0367168b306260bc07bb738e0b5452716d5f0cb8abb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:54:17` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71392c07b207b2449cb44bb755877d33` |
| SHA-1 | `16096e141eaa76806d111ef1d0c2b08370daf668` |
| SHA-256 | `7eeaa1e1acb4b10e54e1e0367168b306260bc07bb738e0b5452716d5f0cb8abb` |
| SHA3-384 | `e2c21f5b54cc6e52c3e77e07b6a305b4276f2fca8e98927c16c45f5677361efe8d4ea0b66a3f3681d0b1d2f8cc5c0eeb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E762D686DDA22E5DDE4F80703A11F878ADB93AD0CA2699E3D7828D355D638D00524EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ugdddv:fKOe2/7c9sN3zfZR1m+RGe6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_7eeaa1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eeaa1e1acb4b10e54e1e0367168b306260bc07bb738e0b5452716d5f0cb8abb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:54:17"
  condition:
    hash.sha256(0, filesize) == "7eeaa1e1acb4b10e54e1e0367168b306260bc07bb738e0b5452716d5f0cb8abb"
}
```

### Sample 65: `e7a7563ea9d2277a`

| Field | Value |
|---|---|
| SHA-256 | `e7a7563ea9d2277a4ff27dbf687711a40ba0e937b7f0142b5cd8a821c0f8dbfa` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:49:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f3d054ffd5ef2793f7fd5f75613d590` |
| SHA-1 | `042b0d5da42b78fd6c9a02daa649bc8cbf459512` |
| SHA-256 | `e7a7563ea9d2277a4ff27dbf687711a40ba0e937b7f0142b5cd8a821c0f8dbfa` |
| SHA3-384 | `3c69a268ea6077380ed21d1fd0473b7c02c8d09dc634575419b476366b9464b3864e18583894119b06356599d0364f41` |
| IMPHASH | `9de7b55911b7e7264b087cfb183130aa` |
| TLSH | `T100D4BF31D99BA9D0E4B7563784045572EB3831EC1B70BA924BB0619A5FE3C818F7E3C9` |
| SSDEEP | `12288:y24ECJ9VmtiSd9UWHAVIuhazAJAP0Io9+92IiTPXw3qdBDVb4d0tez6:yzmTPmVVKm+ofjg3KBDVb4d0wz6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_e7a7563e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7a7563ea9d2277a4ff27dbf687711a40ba0e937b7f0142b5cd8a821c0f8dbfa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:49:45"
  condition:
    hash.sha256(0, filesize) == "e7a7563ea9d2277a4ff27dbf687711a40ba0e937b7f0142b5cd8a821c0f8dbfa"
}
```

### Sample 66: `bfd614cd30738807`

| Field | Value |
|---|---|
| SHA-256 | `bfd614cd3073880767f0af5ef481e24acebde06ce48a80dd607327303f700ce2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:49:25` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74cfd71264b6f4cb919954f026cf959a` |
| SHA-1 | `ea7539b3c1b03bdc48bac6ab6c31a92ed1636cb4` |
| SHA-256 | `bfd614cd3073880767f0af5ef481e24acebde06ce48a80dd607327303f700ce2` |
| SHA3-384 | `23cc4e2e0ab88a113611c2b72e71caa445b64e18626b653eee0c5aca8d7e3beadad5e260b55c42d4628eeb0a44d2951a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16A62C78AECD22AACDE4F90703A11F868BD753691866659E3D7828C345E639D00528FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UVBgCc:fKOe2/7c9sN3zfZR1m+RGS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_bfd614cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfd614cd3073880767f0af5ef481e24acebde06ce48a80dd607327303f700ce2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:49:25"
  condition:
    hash.sha256(0, filesize) == "bfd614cd3073880767f0af5ef481e24acebde06ce48a80dd607327303f700ce2"
}
```

### Sample 67: `e399b068d5d679b4`

| Field | Value |
|---|---|
| SHA-256 | `e399b068d5d679b430b7c95166057b6b38673b32e00ae16d7b971b540cd6539e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:47:01` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f155e5ec898708a488d5331421185ed3` |
| SHA-1 | `9e2de63affafc5f02327ac1cc4bb4af8aead9325` |
| SHA-256 | `e399b068d5d679b430b7c95166057b6b38673b32e00ae16d7b971b540cd6539e` |
| SHA3-384 | `b29eeef12144574cda2e0c3327e742fb4e76eb7ade7b508e3145aa8cece7e18d2d4d9c52084a55760d95ea5ca03b4621` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CD62B586D9E22B6CCE4EC0703E51F978F97536A0896679E3D7828C315EA39D00524FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UbBgCc:fKOe2/7c9sN3zfZR1m+RGY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_e399b068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e399b068d5d679b430b7c95166057b6b38673b32e00ae16d7b971b540cd6539e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:47:01"
  condition:
    hash.sha256(0, filesize) == "e399b068d5d679b430b7c95166057b6b38673b32e00ae16d7b971b540cd6539e"
}
```

### Sample 68: `31b0afa46c49cddb`

| Field | Value |
|---|---|
| SHA-256 | `31b0afa46c49cddbb19d82de057277a09d19daec6f10dc1af133a0c0cc24e107` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:44:30` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82db6152ea656dc4bea99f99a7ba3a56` |
| SHA-1 | `aea21c3d8bbc92f0d3ab58c7451ead73cb9d5fcf` |
| SHA-256 | `31b0afa46c49cddbb19d82de057277a09d19daec6f10dc1af133a0c0cc24e107` |
| SHA3-384 | `3bdd9e560f19d45b8e34d02a5868309cba38bf172a5259fe2047c71fb68e045d82bd0c603c1b5a592e8da76756ea6d23` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16E62C58BD8926F6CCE4E90B03A51F978B9B03690856999E3D7928C315DB39D04134FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UmkR41:fKOe2/7c9sN3zfZR1m+RG1G6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_31b0afa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b0afa46c49cddbb19d82de057277a09d19daec6f10dc1af133a0c0cc24e107"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:44:30"
  condition:
    hash.sha256(0, filesize) == "31b0afa46c49cddbb19d82de057277a09d19daec6f10dc1af133a0c0cc24e107"
}
```

### Sample 69: `49df1599dc7d239b`

| Field | Value |
|---|---|
| SHA-256 | `49df1599dc7d239bbb7d347bef9941547acec21fc7af972954110c5b24c04342` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:41:18` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd27bd1c5a05a738e62ac6271a5bcb53` |
| SHA-1 | `fd1de41713ad26eea262301a4def2d7bf7f5c406` |
| SHA-256 | `49df1599dc7d239bbb7d347bef9941547acec21fc7af972954110c5b24c04342` |
| SHA3-384 | `c88b1df86d23f2ab0db018033dbedcb8fbc9ae0c9671b42c4d94708d6d10a7c48ae4833491b741aa571daa650cd04dda` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12862E696E8926F6CDE4EA4B03E11F868BD7536D08A6599E3C792CD3059A38C04034FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UnYAhe:fKOe2/7c9sN3zfZR1m+RGeY46C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_49df1599
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49df1599dc7d239bbb7d347bef9941547acec21fc7af972954110c5b24c04342"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:41:18"
  condition:
    hash.sha256(0, filesize) == "49df1599dc7d239bbb7d347bef9941547acec21fc7af972954110c5b24c04342"
}
```

### Sample 70: `0d3d18aa399e7fb9`

| Field | Value |
|---|---|
| SHA-256 | `0d3d18aa399e7fb9a3303a32d1dd6fdad11761d10ea62106e62e8a83f4544286` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:38:53` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23a0c3315cf3b58517b0e9fe954d9895` |
| SHA-1 | `9590039543e653e6472133272b4a1466d0673fd2` |
| SHA-256 | `0d3d18aa399e7fb9a3303a32d1dd6fdad11761d10ea62106e62e8a83f4544286` |
| SHA3-384 | `c017265ffeaad4f543ce412b5b510c28f94c253029e37c0dd8181b5a84a6277a118fa9085630d79edda0359a3d144a8b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13262D7C6D9A26F5CCE4E80703A51F878AE707694866699F3D7C28C315DA39D04024FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U8tBgn:fKOe2/7c9sN3zfZR1m+RGtt6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_0d3d18aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d3d18aa399e7fb9a3303a32d1dd6fdad11761d10ea62106e62e8a83f4544286"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:38:53"
  condition:
    hash.sha256(0, filesize) == "0d3d18aa399e7fb9a3303a32d1dd6fdad11761d10ea62106e62e8a83f4544286"
}
```

### Sample 71: `1cc4a8e44a1ed752`

| Field | Value |
|---|---|
| SHA-256 | `1cc4a8e44a1ed7520de1e1752931f42fd627e2c9d0de2066cd9de0c9b402881b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:36:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `109b1b3c81cac5a3bfb4eb436133308d` |
| SHA-1 | `5bb32f2664b1560e04a471d583c249391e75bd3b` |
| SHA-256 | `1cc4a8e44a1ed7520de1e1752931f42fd627e2c9d0de2066cd9de0c9b402881b` |
| SHA3-384 | `fcd6481fd62495fbab6e65116d7cc143af69074f2bc42fd81bd7b8c17c342e91b6298743bba2e94cded9ca75e890bcaa` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19262C89AD9E22F9CCE4E80713B51F8386AB536988A5559E3D7828C305DA39D10138FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U0ga+h:fKOe2/7c9sN3zfZR1m+RGsa+A6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_1cc4a8e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cc4a8e44a1ed7520de1e1752931f42fd627e2c9d0de2066cd9de0c9b402881b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:36:36"
  condition:
    hash.sha256(0, filesize) == "1cc4a8e44a1ed7520de1e1752931f42fd627e2c9d0de2066cd9de0c9b402881b"
}
```

### Sample 72: `402eb235fc133523`

| Field | Value |
|---|---|
| SHA-256 | `402eb235fc133523e18d548a391e11f65fe0a8ca477d6a1e83213c40978776a4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:36:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4eb8f2b14924b0cd76990794b61dcea` |
| SHA-1 | `430c3c85c127ce6e428488e0bf2150bbbd980dda` |
| SHA-256 | `402eb235fc133523e18d548a391e11f65fe0a8ca477d6a1e83213c40978776a4` |
| SHA3-384 | `cb4d4aad3386d2348a664fcc374f9cf54415ba7df5f9871328524eff95b6eac926b58086b1b8b24eca9f5495e0fd9395` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17D62C586ECA22F5CEE4FD0703A11FC68F97036918A659AE7D7829C305DA39D10425FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UjBgCc:fKOe2/7c9sN3zfZR1m+RG86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_402eb235
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "402eb235fc133523e18d548a391e11f65fe0a8ca477d6a1e83213c40978776a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:36:27"
  condition:
    hash.sha256(0, filesize) == "402eb235fc133523e18d548a391e11f65fe0a8ca477d6a1e83213c40978776a4"
}
```

### Sample 73: `69e292deedbf5e5a`

| Field | Value |
|---|---|
| SHA-256 | `69e292deedbf5e5ae10ef9c4bba9cd1c35390ccff9ee321d8aa284e70086be4d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:34:06` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad040f5ae4467ccc3b7d7eaaf1f1131` |
| SHA-1 | `63c5cd1b798e79347be063892ac90e5e7057decb` |
| SHA-256 | `69e292deedbf5e5ae10ef9c4bba9cd1c35390ccff9ee321d8aa284e70086be4d` |
| SHA3-384 | `afc27b98dc869f728349a778f527396b41926d00a5cae74b408c9a638802c5d6a9b879a2d62e92d62aeafb98217f48d6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14F62C786E8E31F9CCE4E90703E11F8386E7476A9896699E3D7828C315D639D00524FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UnTYkr:fKOe2/7c9sN3zfZR1m+RGOvS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_69e292de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69e292deedbf5e5ae10ef9c4bba9cd1c35390ccff9ee321d8aa284e70086be4d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:34:06"
  condition:
    hash.sha256(0, filesize) == "69e292deedbf5e5ae10ef9c4bba9cd1c35390ccff9ee321d8aa284e70086be4d"
}
```

### Sample 74: `9d3860dfaf9dab59`

| Field | Value |
|---|---|
| SHA-256 | `9d3860dfaf9dab59581283d973045926aab8bdeb3def0f5e850577586be09252` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:32:38` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `022455285c0df0cfdb61802a1a6af40f` |
| SHA-1 | `363e6d4c6e5737cd80fe59f7f2045f605972c7a9` |
| SHA-256 | `9d3860dfaf9dab59581283d973045926aab8bdeb3def0f5e850577586be09252` |
| SHA3-384 | `6d37c9de3a7d7e835bbfa428eac62940dfacb63fdc78eaeede7294c803f50c7434e8b74a5dede4f9ee9f64d142abbd49` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17D62C686E8D22FADCE4E80703A11FDF879743690896569E7D7828C306D639D00564EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UdMT+S:fKOe2/7c9sN3zfZR1m+RGWMJ86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_9d3860df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d3860dfaf9dab59581283d973045926aab8bdeb3def0f5e850577586be09252"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:32:38"
  condition:
    hash.sha256(0, filesize) == "9d3860dfaf9dab59581283d973045926aab8bdeb3def0f5e850577586be09252"
}
```

### Sample 75: `e05f5bdd42ec992b`

| Field | Value |
|---|---|
| SHA-256 | `e05f5bdd42ec992bc8697ec0bf699a767f6a7783359c09d9f0a63788c9ab05aa` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:31:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a8f23b24fe3d2582609b0f502c44a0d` |
| SHA-1 | `9c8351873a1913fdc11dfc524d34ef682206e387` |
| SHA-256 | `e05f5bdd42ec992bc8697ec0bf699a767f6a7783359c09d9f0a63788c9ab05aa` |
| SHA3-384 | `c52018dc1d38bb815b1d6868883d49465bfc7f284348ca6f741a4d66b1b5e32f592bf5cfb2f2f80d60459199d6b1dea3` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11D62C586D8A26E6CDE4E80703A21F938BD7436D486659AF3D7828C749DA39D04134FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGhkkkkkkkkkz6C:fKOeOQOzUxA6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_e05f5bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e05f5bdd42ec992bc8697ec0bf699a767f6a7783359c09d9f0a63788c9ab05aa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:31:41"
  condition:
    hash.sha256(0, filesize) == "e05f5bdd42ec992bc8697ec0bf699a767f6a7783359c09d9f0a63788c9ab05aa"
}
```

### Sample 76: `246dfeea33fe0b9e`

| Field | Value |
|---|---|
| SHA-256 | `246dfeea33fe0b9ebef66652254e4356cf3486a79e0736e3d8da1beee9cbeb27` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:30:09` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0c687f778219b64a00808dab9a697fc0` |
| SHA-1 | `58cf606903cd8c1c38aac14434fa3802ff2d9029` |
| SHA-256 | `246dfeea33fe0b9ebef66652254e4356cf3486a79e0736e3d8da1beee9cbeb27` |
| SHA3-384 | `dd7e69104a815fd9e9b21fa980479d6b8453b4005b873248b2570d1b542fd1eadacee491814208102827b072f41fba8a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A062D687E9D26F6CDE4F80B17B11F868A97436919A659CE3D7A28C304DA39D04034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46URbp0c:fKOe2/7c9sN3zfZR1m+RGq0V6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_246dfeea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "246dfeea33fe0b9ebef66652254e4356cf3486a79e0736e3d8da1beee9cbeb27"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:30:09"
  condition:
    hash.sha256(0, filesize) == "246dfeea33fe0b9ebef66652254e4356cf3486a79e0736e3d8da1beee9cbeb27"
}
```

### Sample 77: `a03345bee66ddfe6`

| Field | Value |
|---|---|
| SHA-256 | `a03345bee66ddfe69090545221a248b55f4a5900aa34c14271b11c2c5ee993b7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:27:11` |
| Reporter | `Bitsight` |
| Tags | `4d233bcb7c81bb5e9ffd2a3f813ea9bf, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11e1c298ca9b023d1a11efe917f93f04` |
| SHA-1 | `345e0088dcc7913d00aa9f3c339d7398fb397284` |
| SHA-256 | `a03345bee66ddfe69090545221a248b55f4a5900aa34c14271b11c2c5ee993b7` |
| SHA3-384 | `b68fc8c34193528c332b484fef0fca6496730a565c46405e666f62aab902ba33c99af135555b5a762e23979ea20eebf0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BD62E586E8A22F5DDE4E80707E11F978BDB43690962959E7CB92CD305EA39D00434EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46USYBgn:fKOe2/7c9sN3zfZR1m+RGlY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_a03345be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a03345bee66ddfe69090545221a248b55f4a5900aa34c14271b11c2c5ee993b7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:27:11"
  condition:
    hash.sha256(0, filesize) == "a03345bee66ddfe69090545221a248b55f4a5900aa34c14271b11c2c5ee993b7"
}
```

### Sample 78: `5f4dd099f3429292`

| Field | Value |
|---|---|
| SHA-256 | `5f4dd099f342929223b53eca77caebc080b561ba4737f6550eec0fcc729d921b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:19:32` |
| Reporter | `Bitsight` |
| Tags | `4d233bcb7c81bb5e9ffd2a3f813ea9bf, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14f00a55cfcc23cdf1ebfdee700bdf96` |
| SHA-1 | `e1085f6881a1e3218092e1083904687d558b6b8e` |
| SHA-256 | `5f4dd099f342929223b53eca77caebc080b561ba4737f6550eec0fcc729d921b` |
| SHA3-384 | `4163f1cabf83ade5fa47324363de7df6bb2133143790e3097068b1a080a88411d641345efb540b0ed6168e43e8545676` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18662D686D9E26FACDE4F80703A11F8786D743690966959E3D7828C349EA39C10434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U9DRhQ:fKOe2/7c9sN3zfZR1m+RGOPh6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_5f4dd099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f4dd099f342929223b53eca77caebc080b561ba4737f6550eec0fcc729d921b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:19:32"
  condition:
    hash.sha256(0, filesize) == "5f4dd099f342929223b53eca77caebc080b561ba4737f6550eec0fcc729d921b"
}
```

### Sample 79: `c9866935941556a2`

| Field | Value |
|---|---|
| SHA-256 | `c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f` |
| Family label | `unknown` |
| File name | `c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f` |
| File type | `elf` |
| First seen | `2026-09-19 02:18:28` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d5bac5c9bbaa25d997baf3e99b87b83` |
| SHA-1 | `b5656a3ecc0bf352fb585610c53e21a58befca24` |
| SHA-256 | `c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f` |
| SHA3-384 | `e779ada905644a4c22cbbe0f5b2be7f35cc7fc4ac3a29c8f90a2bcdd88590e5f2f7bd67b3a5744c2980cc3a542898b37` |
| TLSH | `T16CB30221D3230D0BC43538FABA16E7152D872E79248A415D4AF9E6BB4BB704CE9F6313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxw:biMYFJvw6Yh0b1gKobtCGCmCRlry` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_c9866935
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f"
    family = "unknown"
    file_name = "c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f"
    file_type = "elf"
    first_seen = "2026-09-19 02:18:28"
  condition:
    hash.sha256(0, filesize) == "c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f"
}
```

### Sample 80: `ca5da5a047b770d4`

| Field | Value |
|---|---|
| SHA-256 | `ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0` |
| Family label | `unknown` |
| File name | `ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0` |
| File type | `elf` |
| First seen | `2026-09-19 02:18:23` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `327e01cedfff691e2fc9162f5fd0fa5a` |
| SHA-1 | `f07fac6d758471e156d8a834fb588fcfab13bfe8` |
| SHA-256 | `ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0` |
| SHA3-384 | `178b60ba4c11eb133a1e7651fba3c44cd2a28d1cc7f9061b0c038ffe827fce017488f46ab5111ef857a13882eff8c057` |
| TLSH | `T1B6D3128AEF369C0F9F401EB22ADB5F8E9C5D7A6B41C7F4A4B9C1818F17A01C97952114` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ10xh:p3lOYoaja8xzx/0wsxzSh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_ca5da5a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0"
    family = "unknown"
    file_name = "ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0"
    file_type = "elf"
    first_seen = "2026-09-19 02:18:23"
  condition:
    hash.sha256(0, filesize) == "ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0"
}
```

### Sample 81: `936530bba19f0b4d`

| Field | Value |
|---|---|
| SHA-256 | `936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202` |
| Family label | `Mirai` |
| File name | `936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202` |
| File type | `elf` |
| First seen | `2026-09-19 02:18:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29eea389e6d99d3313a9864782163995` |
| SHA-1 | `6dc55d22c3028052c975176b1654a83426bf337e` |
| SHA-256 | `936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202` |
| SHA3-384 | `98c14cb6638b6eb09967ab624ed35f70eb58215743a2687aec39456809913ac8fc9775f0d6806fd712fcded6a8912cbe` |
| TLSH | `T137041A8AFD81AF1585C527BBFE2E418A331317B8D2EE71129D141F2877CA94F0E3A542` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiB5IQggEuaJhnR1rmaabEtnwKSDP5:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZR2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_936530bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202"
    family = "Mirai"
    file_name = "936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202"
    file_type = "elf"
    first_seen = "2026-09-19 02:18:18"
  condition:
    hash.sha256(0, filesize) == "936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202"
}
```

### Sample 82: `078b9ab2d3a8ee0a`

| Field | Value |
|---|---|
| SHA-256 | `078b9ab2d3a8ee0adf29bcc615979df5ed525e250aed1f827f338bdcb3c21e3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:17:13` |
| Reporter | `Bitsight` |
| Tags | `4d233bcb7c81bb5e9ffd2a3f813ea9bf, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7a9459fd5833995c4ab81b886331047` |
| SHA-1 | `06e8395b8eb899bba9d16a0cb4dfef1fb5bf09b5` |
| SHA-256 | `078b9ab2d3a8ee0adf29bcc615979df5ed525e250aed1f827f338bdcb3c21e3e` |
| SHA3-384 | `201cbae07c8307c2baa3a3dd05340f92f0df50aee09eb5263853381874682b2464caa6a9f48c7c2ed02869995b924c1c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16762D58ADCE22F5CDE4E80B07A11F878B9B57690866969E7D7828D305DA39D04034FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UH+Gju:fKOe2/7c9sN3zfZR1m+RGlM6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_078b9ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "078b9ab2d3a8ee0adf29bcc615979df5ed525e250aed1f827f338bdcb3c21e3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:17:13"
  condition:
    hash.sha256(0, filesize) == "078b9ab2d3a8ee0adf29bcc615979df5ed525e250aed1f827f338bdcb3c21e3e"
}
```

### Sample 83: `ca44f61c186f8c63`

| Field | Value |
|---|---|
| SHA-256 | `ca44f61c186f8c639b7e0914cc6db350435767cad90cfe2e7e4c75a58d811105` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-19 02:03:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b518caac115ee0b942869f41df812d1` |
| SHA-1 | `8bcbcd1890aba0d8639b0da08009136943142203` |
| SHA-256 | `ca44f61c186f8c639b7e0914cc6db350435767cad90cfe2e7e4c75a58d811105` |
| SHA3-384 | `4224c146011a7df4269a071910a3610bc6c6d7dccaf1064d1c19d22ff87b71aa8f88056236cab4d5f591ec5dc6fe3f61` |
| TLSH | `T118F46B437B208FA4E335D57005F38AE5AAB822960BF39596927CC3307A406AD5D5FFD8` |
| TELFHASH | `t17341a418097813f0a3755c5d15ddff76e6a230db7e262c338e10e86aa769b839e10c1c` |
| SSDEEP | `12288:6AtoqJuekBlxkI0aCNPR0nvZ+HGl5fjh/72UzBLr7BV8pwQcI/CC:6AtoqJuPDN0aCNJ0Xl5MojBGBaC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_ca44f61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca44f61c186f8c639b7e0914cc6db350435767cad90cfe2e7e4c75a58d811105"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-19 02:03:18"
  condition:
    hash.sha256(0, filesize) == "ca44f61c186f8c639b7e0914cc6db350435767cad90cfe2e7e4c75a58d811105"
}
```

### Sample 84: `39fa74b414894170`

| Field | Value |
|---|---|
| SHA-256 | `39fa74b4148941700c5625dd0c577fbcd5104e9cf08fbc8abfed8b3bef49ecc3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 02:01:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e645b7ab25935841892ab99bba4a37a2` |
| SHA-1 | `e65d59d44f50421dd7263d4a23214f53af9e272b` |
| SHA-256 | `39fa74b4148941700c5625dd0c577fbcd5104e9cf08fbc8abfed8b3bef49ecc3` |
| SHA3-384 | `30f2e245796189c6c16bc4fddd267dbaed5e0ec4700c865a2a9cbcbaece692214b43be50a8810c71c72c18afadbe61c1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18A62C786D8925E5CCE4FC0B07B21F93C7A7136A08A659EE3D7828C759DA39D10424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuZaXe:fKOe2/7c9sN3zfZR1m+RGxsX6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_39fa74b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39fa74b4148941700c5625dd0c577fbcd5104e9cf08fbc8abfed8b3bef49ecc3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:01:50"
  condition:
    hash.sha256(0, filesize) == "39fa74b4148941700c5625dd0c577fbcd5104e9cf08fbc8abfed8b3bef49ecc3"
}
```

### Sample 85: `2ec1181465193b75`

| Field | Value |
|---|---|
| SHA-256 | `2ec1181465193b75a4ef1265a459f5b4c1e19b9ffdacb56792eb605ffb4ceb36` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:59:16` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a068195626de7d69d1b73ea3b89ab3bd` |
| SHA-1 | `9f4cd41f78e460f2daf3e487c43cef3e68bef14a` |
| SHA-256 | `2ec1181465193b75a4ef1265a459f5b4c1e19b9ffdacb56792eb605ffb4ceb36` |
| SHA3-384 | `603e2a5499958a5757e0d3576445e6c5f3b543c368b2f580a826df124accf6514961e2864de1b811575c0e5371c97685` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FD62C596E8B36A5DEE4F90B03A51F9786D7432D0872599F3D7828D214DA38D00464FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U/gVBM:fKOe2/7c9sN3zfZR1m+RGqgV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_2ec11814
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec1181465193b75a4ef1265a459f5b4c1e19b9ffdacb56792eb605ffb4ceb36"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:59:16"
  condition:
    hash.sha256(0, filesize) == "2ec1181465193b75a4ef1265a459f5b4c1e19b9ffdacb56792eb605ffb4ceb36"
}
```

### Sample 86: `6e5c8c3b5ea07127`

| Field | Value |
|---|---|
| SHA-256 | `6e5c8c3b5ea071271c17654de9e9719905a525359401c0c7dd4cd36c5adc318b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:54:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c71fc0d4cb8af4120a9f5d2a2be847b4` |
| SHA-1 | `1e6051c365266239d7080c0733a3d2f5955de25e` |
| SHA-256 | `6e5c8c3b5ea071271c17654de9e9719905a525359401c0c7dd4cd36c5adc318b` |
| SHA3-384 | `051743c82bffbdb0f292d0ad34b62743372f13a4f23e091f40d289438db1c999e035c076cb9dd74f42f3189b45197e17` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E362D796E8A21F5CDE4F80703A32F878BD7036908A6959E7D7828C345DA39D05474FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UKPHsB:fKOe2/7c9sN3zfZR1m+RGTnR6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_6e5c8c3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e5c8c3b5ea071271c17654de9e9719905a525359401c0c7dd4cd36c5adc318b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:54:36"
  condition:
    hash.sha256(0, filesize) == "6e5c8c3b5ea071271c17654de9e9719905a525359401c0c7dd4cd36c5adc318b"
}
```

### Sample 87: `b87831415641a3ad`

| Field | Value |
|---|---|
| SHA-256 | `b87831415641a3ad8db05f9e761bed064e7a7309abdf45aed70cf9cbd63551d1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:52:34` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ede96c02c4273dd0be1ed975bf8049e2` |
| SHA-1 | `8d4b7759ab1e0eb39687ab911c07d28bde7a8c67` |
| SHA-256 | `b87831415641a3ad8db05f9e761bed064e7a7309abdf45aed70cf9cbd63551d1` |
| SHA3-384 | `acc88f9a172c66ce1cebcc3a84199d5570d97e38fd7a8ea71f5eb39e34eb56cb493819dad39e3068e8cbab03032a2944` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CE62D88AE9D26F5DCE4E80703A51F838BDB07691866569F7C7818C319EA38D00024FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U8BgCc:fKOe2/7c9sN3zfZR1m+RGj6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_b8783141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b87831415641a3ad8db05f9e761bed064e7a7309abdf45aed70cf9cbd63551d1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:52:34"
  condition:
    hash.sha256(0, filesize) == "b87831415641a3ad8db05f9e761bed064e7a7309abdf45aed70cf9cbd63551d1"
}
```

### Sample 88: `366b3cf3cc5ec10f`

| Field | Value |
|---|---|
| SHA-256 | `366b3cf3cc5ec10f253ca4a4bc3d04757efaf1a4abcb6f8127e9acd502067a0e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:52:14` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `427680492f4a6f11d11b4ebc79338141` |
| SHA-1 | `d74916c0971bc2ff14790e7f841144bb794887cd` |
| SHA-256 | `366b3cf3cc5ec10f253ca4a4bc3d04757efaf1a4abcb6f8127e9acd502067a0e` |
| SHA3-384 | `06a28685cb13dbcbc3721bce55bd6c35afbbef8fe9ca081a3b5041b74d586fd6e3a26f43ea0022d9bda7942fbb67b8eb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15E62E696E8926F5CDE4ED0B03A10F968AD7476D58625AEE3C7828D304DA39C11434FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UCEnBM:fKOe2/7c9sN3zfZR1m+RGPW6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_366b3cf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "366b3cf3cc5ec10f253ca4a4bc3d04757efaf1a4abcb6f8127e9acd502067a0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:52:14"
  condition:
    hash.sha256(0, filesize) == "366b3cf3cc5ec10f253ca4a4bc3d04757efaf1a4abcb6f8127e9acd502067a0e"
}
```

### Sample 89: `1b09cde4bcc2b973`

| Field | Value |
|---|---|
| SHA-256 | `1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61` |
| Family label | `ConnectWise` |
| File name | `1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61.msi` |
| File type | `msi` |
| First seen | `2026-09-19 01:50:54` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e79a47fc85955123f0821223a4cf2595` |
| SHA-1 | `c57d7e5ea257ace0147a6752d2a8778be99f96c2` |
| SHA-256 | `1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61` |
| SHA3-384 | `56c43153b8e6a2ff0020af9bd124fd9b99fec10fa3d343e491499381e65964829840bb9cc26764bb809a82f6a02cb8d5` |
| TLSH | `T170C623B127E98425F1A79F39EE3A89E229387C64DA16C45F0BB43C0E1971E509B71373` |
| SSDEEP | `196608:3KaLNkbgZi4QPKaLNkbg1KaLNkbgPKaLNkbg/KaLNkbg:PWgZiHnWgpWgnWgXWg` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_089_1b09cde4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61"
    family = "ConnectWise"
    file_name = "1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61.msi"
    file_type = "msi"
    first_seen = "2026-09-19 01:50:54"
  condition:
    hash.sha256(0, filesize) == "1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61"
}
```

### Sample 90: `64bb738bf10cfede`

| Field | Value |
|---|---|
| SHA-256 | `64bb738bf10cfeded1abca18538575a91b30fbd8bc42227da4bff271d3dbc582` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:49:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `639e1b2fdd580c3361fb50068faab30b` |
| SHA-1 | `4326c642f37c2c2c74d1cc6ee611e46783c96af4` |
| SHA-256 | `64bb738bf10cfeded1abca18538575a91b30fbd8bc42227da4bff271d3dbc582` |
| SHA3-384 | `e8738b193875f42ea23ef09add1e5200c94020fb4d7b34f100a364dae57c625610cdaf068035f72f085fa04effa21841` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14962D68AD9A22F9CDE8E80703F51F9287E707290866559E7D7928C345DA39D01074FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uza/BM:fKOe2/7c9sN3zfZR1m+RGL6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_64bb738b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bb738bf10cfeded1abca18538575a91b30fbd8bc42227da4bff271d3dbc582"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:49:49"
  condition:
    hash.sha256(0, filesize) == "64bb738bf10cfeded1abca18538575a91b30fbd8bc42227da4bff271d3dbc582"
}
```

### Sample 91: `a852168f880042e5`

| Field | Value |
|---|---|
| SHA-256 | `a852168f880042e58f8f3497d8c35d53ea9c2014627e3f7fdc1530dafab1da09` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:48:03` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3a66ef68c0336ae78efaf3515d9e473` |
| SHA-1 | `02766ad7125c52e3942bad058692f1063ebee69f` |
| SHA-256 | `a852168f880042e58f8f3497d8c35d53ea9c2014627e3f7fdc1530dafab1da09` |
| SHA3-384 | `367c880ac1282c401475bfe079ccaa33cb39be193cdc16a90b32f1208846134c8d85fdfeb93c1a6ea577e3bb391942ea` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14962D68AD8925F5CCE4E90703A52F8BC7E7472A1866559E7C7C28C315EA39D00125FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UHcccS:fKOe2/7c9sN3zfZR1m+RGv6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_a852168f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a852168f880042e58f8f3497d8c35d53ea9c2014627e3f7fdc1530dafab1da09"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:48:03"
  condition:
    hash.sha256(0, filesize) == "a852168f880042e58f8f3497d8c35d53ea9c2014627e3f7fdc1530dafab1da09"
}
```

### Sample 92: `618890654712bb0a`

| Field | Value |
|---|---|
| SHA-256 | `618890654712bb0affcbca16d307d01f40cb25bba702dc9145fbd569b84ae22f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:32:00` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cac83e8d83a5c73214f9c0ad2321d624` |
| SHA-1 | `4ec69bc6072a6bdefa3ce06acb81fd57c624d80c` |
| SHA-256 | `618890654712bb0affcbca16d307d01f40cb25bba702dc9145fbd569b84ae22f` |
| SHA3-384 | `8dd54a26140e22f23ce70251c064a240d1b907ae361352486965e00c64034b90d2307036babe7633bb2c6f41d4da1cf9` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T1FF06AE03ACD258AAC4D9963196BA4562BF71BC888B3073C76F81B9743F327D07978B54` |
| SSDEEP | `49152:QxgForQy8NQTiyx9WQgCWaIDlvbjmvpeKy5b/G7f8+FrpeNDh:HQhO17nD+ZOar8TX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_61889065
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618890654712bb0affcbca16d307d01f40cb25bba702dc9145fbd569b84ae22f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:32:00"
  condition:
    hash.sha256(0, filesize) == "618890654712bb0affcbca16d307d01f40cb25bba702dc9145fbd569b84ae22f"
}
```

### Sample 93: `658013fa20f6f19e`

| Field | Value |
|---|---|
| SHA-256 | `658013fa20f6f19ebcb9e1c4a1eab001bfb827fecd44747bbfb56fa29995c148` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:31:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c7d8d2ed8f1262932dfdb09fbec341` |
| SHA-1 | `6bf452895f5ea7141d96f7de123e1edadfe79242` |
| SHA-256 | `658013fa20f6f19ebcb9e1c4a1eab001bfb827fecd44747bbfb56fa29995c148` |
| SHA3-384 | `a35d5507902167b01078b90acdfc16d2507b775c929e2f9a5157b0a574dca1eda0eff30db86a8d4c033bc50196c7f2a5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C662D896DAA22F5CDE4F90B03A11F838BA7432D0456569E3E7C28D346DA39D11424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UjJlBM:fKOe2/7c9sN3zfZR1m+RGIJl6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_658013fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "658013fa20f6f19ebcb9e1c4a1eab001bfb827fecd44747bbfb56fa29995c148"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:31:36"
  condition:
    hash.sha256(0, filesize) == "658013fa20f6f19ebcb9e1c4a1eab001bfb827fecd44747bbfb56fa29995c148"
}
```

### Sample 94: `83a59d8d9229bd86`

| Field | Value |
|---|---|
| SHA-256 | `83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0` |
| Family label | `unknown` |
| File name | `83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0.bin` |
| File type | `unknown` |
| First seen | `2026-09-19 01:29:33` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2dea0b2c8faf56b7f808b85f3f548ecd` |
| SHA-256 | `83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_83a59d8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0"
    family = "unknown"
    file_name = "83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0.bin"
    file_type = "unknown"
    first_seen = "2026-09-19 01:29:33"
  condition:
    hash.sha256(0, filesize) == "83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0"
}
```

### Sample 95: `77ce5f18377033fc`

| Field | Value |
|---|---|
| SHA-256 | `77ce5f18377033fcec52c909681fcb7b853311993248b3bb6a509d36b9b86ce4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:29:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09d723256b32bc43142dc4e1f9b550aa` |
| SHA-1 | `6b9546594791ddd379f006139fabb6e7a656a8c9` |
| SHA-256 | `77ce5f18377033fcec52c909681fcb7b853311993248b3bb6a509d36b9b86ce4` |
| SHA3-384 | `40d52880cfe278920dd6232557da47688408030a368fc0cd1e0f2bc312b3454d58caf0a028390f2df253c88452dd67c1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CC62C48AD8A23F6CDE4E80703A11F878B97536918E6699E3D7C28C315DB39D00564FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U7BgCc:fKOe2/7c9sN3zfZR1m+RG86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_77ce5f18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77ce5f18377033fcec52c909681fcb7b853311993248b3bb6a509d36b9b86ce4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:29:08"
  condition:
    hash.sha256(0, filesize) == "77ce5f18377033fcec52c909681fcb7b853311993248b3bb6a509d36b9b86ce4"
}
```

### Sample 96: `61e671d2995c47f2`

| Field | Value |
|---|---|
| SHA-256 | `61e671d2995c47f2da1bea418b7101d635e928e407b5076e8d16ccd68825fdb2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:28:38` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7315dd9cb7a54320c688b59ce0c68ff` |
| SHA-1 | `fb868061855758f699caeb44aaa0becb300a502b` |
| SHA-256 | `61e671d2995c47f2da1bea418b7101d635e928e407b5076e8d16ccd68825fdb2` |
| SHA3-384 | `6120f8bee2f5d0f675d17233026af47ffa85dca1d493bd2c32e0b40d91c21333e0db30f67808c8177a555caa16ffbbfb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12B62C78BD9A22F5CCE4F80703A11F87869B576988665A9E3D7D2CC345D63AD00428FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UeqBgn:fKOe2/7c9sN3zfZR1m+RG+6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_61e671d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61e671d2995c47f2da1bea418b7101d635e928e407b5076e8d16ccd68825fdb2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:28:38"
  condition:
    hash.sha256(0, filesize) == "61e671d2995c47f2da1bea418b7101d635e928e407b5076e8d16ccd68825fdb2"
}
```

### Sample 97: `441f3e1c64841a18`

| Field | Value |
|---|---|
| SHA-256 | `441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b` |
| Family label | `unknown` |
| File name | `441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b.bin` |
| File type | `unknown` |
| First seen | `2026-09-19 01:28:00` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `275024653b13f8fb0e7845236b6190a5` |
| SHA-256 | `441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_441f3e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b"
    family = "unknown"
    file_name = "441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b.bin"
    file_type = "unknown"
    first_seen = "2026-09-19 01:28:00"
  condition:
    hash.sha256(0, filesize) == "441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b"
}
```

### Sample 98: `1dea665b8b8666c4`

| Field | Value |
|---|---|
| SHA-256 | `1dea665b8b8666c4fe415b489cbb760138ae4574e444375213586aaaddadaaad` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:26:42` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6eb3689bb70ba01a5e8448bbb29f976` |
| SHA-1 | `c911b81c6f3fee2b8257256bc9397774dad0afa8` |
| SHA-256 | `1dea665b8b8666c4fe415b489cbb760138ae4574e444375213586aaaddadaaad` |
| SHA3-384 | `64229271821e26a63685d20c37d053ceee712909afa28d3189b454ee503bca5c30e7d8bf9772bd2cd8b8fc3a8f5269f6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1CB62D686D9E29F5CCE4E80703A11F868ADB0B6A18A655DF3D7928C306DA39D50034FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGvbKKKKKKKKKu6C:fKOeOQOzUxTKKKKKKKKKu6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_1dea665b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dea665b8b8666c4fe415b489cbb760138ae4574e444375213586aaaddadaaad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:26:42"
  condition:
    hash.sha256(0, filesize) == "1dea665b8b8666c4fe415b489cbb760138ae4574e444375213586aaaddadaaad"
}
```

### Sample 99: `d64f952b49169764`

| Field | Value |
|---|---|
| SHA-256 | `d64f952b49169764a2069b3d899d9bb5528464d081a29ffc8fbda1d2734f9cad` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:26:20` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94b70a9f31f9b6a5935d665fc053bbc2` |
| SHA-1 | `d35a728e8601e9c5c5966af5f71a76fdfb6551ec` |
| SHA-256 | `d64f952b49169764a2069b3d899d9bb5528464d081a29ffc8fbda1d2734f9cad` |
| SHA3-384 | `834daa99225b4a267c13da2acfbe0ebb7a22591eb3d7f4e6267e53f70b274ae3c2d74c3c171275fa1065d53b929ac064` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17062C68AE8E26EADDE4E90703E11F868B97476D4966559E3E7C28C305DA78D00034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZjTZe:fKOe2/7c9sN3zfZR1m+RGqnZ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_d64f952b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d64f952b49169764a2069b3d899d9bb5528464d081a29ffc8fbda1d2734f9cad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:26:20"
  condition:
    hash.sha256(0, filesize) == "d64f952b49169764a2069b3d899d9bb5528464d081a29ffc8fbda1d2734f9cad"
}
```

### Sample 100: `9df29eb3b238fa74`

| Field | Value |
|---|---|
| SHA-256 | `9df29eb3b238fa74fb8d354f93bc62f44fc7337c2a08abeb68c07c89d5fda598` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-19 01:21:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52580f191b54dcc27c83e75abdb5519e` |
| SHA-1 | `d7cc05f6e2367aa127160c0d795491b70f0c5f6e` |
| SHA-256 | `9df29eb3b238fa74fb8d354f93bc62f44fc7337c2a08abeb68c07c89d5fda598` |
| SHA3-384 | `7da913cfa564961f02564772818c9072f1bba0c35c7df0cd00829902fb18c25df1df5dba74981dc72d85f68912b3e752` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14262D786E9A21E6DCE4FC0B03A51F83879B07A90862599E3D7828C345DA3DD09135EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuVK//:fKOe2/7c9sN3zfZR1m+RGGG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_9df29eb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9df29eb3b238fa74fb8d354f93bc62f44fc7337c2a08abeb68c07c89d5fda598"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:21:47"
  condition:
    hash.sha256(0, filesize) == "9df29eb3b238fa74fb8d354f93bc62f44fc7337c2a08abeb68c07c89d5fda598"
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
 * Generated: 2026-09-19T04:44:26.840430+00:00
 */

rule MalwareBazaar_unknown_001_6f2e9035
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f2e903586c155e31efad481fdfd2615e608b64aaa5ca377feb23da73b0cd01a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:43:27"
  condition:
    hash.sha256(0, filesize) == "6f2e903586c155e31efad481fdfd2615e608b64aaa5ca377feb23da73b0cd01a"
}

rule MalwareBazaar_unknown_002_818c0be6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "818c0be6ab15a51d9b7a84f15c27443ddfbb899bccf4bcd7ef45e8a43135298d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:41:05"
  condition:
    hash.sha256(0, filesize) == "818c0be6ab15a51d9b7a84f15c27443ddfbb899bccf4bcd7ef45e8a43135298d"
}

rule MalwareBazaar_unknown_003_eef8d08b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eef8d08b4ff980813e95ad9c2fbdbd7f2c4f9519a5972e5a41b019c43bc76513"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:39:08"
  condition:
    hash.sha256(0, filesize) == "eef8d08b4ff980813e95ad9c2fbdbd7f2c4f9519a5972e5a41b019c43bc76513"
}

rule MalwareBazaar_unknown_004_da5e6448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da5e644826f411c229882beddca1c84d25e9e40eee1e6c031ccdf9a937197228"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:38:37"
  condition:
    hash.sha256(0, filesize) == "da5e644826f411c229882beddca1c84d25e9e40eee1e6c031ccdf9a937197228"
}

rule MalwareBazaar_JOMANGY_005_0738be0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0738be0a0c8656d0447e0cef9a6e552cf6fa13d1c2b30af3a079162296ae5d68"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-19 04:37:20"
  condition:
    hash.sha256(0, filesize) == "0738be0a0c8656d0447e0cef9a6e552cf6fa13d1c2b30af3a079162296ae5d68"
}

rule MalwareBazaar_unknown_006_1c30871a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c30871a58e0554f24807b95cd829c6780265a8400cebbc90fa9cfa2846e74fc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:36:35"
  condition:
    hash.sha256(0, filesize) == "1c30871a58e0554f24807b95cd829c6780265a8400cebbc90fa9cfa2846e74fc"
}

rule MalwareBazaar_Mirai_007_adfcefd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adfcefd58d7bf5012b4bea56363ac7917af3b6a5dce353b5d7523d3baa638fa7"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-09-19 04:35:40"
  condition:
    hash.sha256(0, filesize) == "adfcefd58d7bf5012b4bea56363ac7917af3b6a5dce353b5d7523d3baa638fa7"
}

rule MalwareBazaar_JOMANGY_008_1032a728
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1032a72869bd8abdf926a9315154b5233955a686bab46e80668acde56617727a"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-19 04:35:39"
  condition:
    hash.sha256(0, filesize) == "1032a72869bd8abdf926a9315154b5233955a686bab46e80668acde56617727a"
}

rule MalwareBazaar_unknown_009_28ae92dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28ae92dcd272a2e109355caff3e31aa2fe13dcad2d6e8f520cd951dded135c49"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:30:22"
  condition:
    hash.sha256(0, filesize) == "28ae92dcd272a2e109355caff3e31aa2fe13dcad2d6e8f520cd951dded135c49"
}

rule MalwareBazaar_NanoCore_010_0440513f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0440513fdf8e78b0e6042dbe10f6a3fc006f58ce26623e55603130e5c776f5eb"
    family = "NanoCore"
    file_name = "0abe9308525b4e9596bd4352a958d7a9.exe"
    file_type = "exe"
    first_seen = "2026-09-19 04:30:05"
  condition:
    hash.sha256(0, filesize) == "0440513fdf8e78b0e6042dbe10f6a3fc006f58ce26623e55603130e5c776f5eb"
}

rule MalwareBazaar_unknown_011_b93f932e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b93f932e309b6a4e48689b97fe730ca13d1e04a4dd1b9620ea2606fa13f20192"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:29:30"
  condition:
    hash.sha256(0, filesize) == "b93f932e309b6a4e48689b97fe730ca13d1e04a4dd1b9620ea2606fa13f20192"
}

rule MalwareBazaar_unknown_012_e3fcc914
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3fcc914e472eba36dcf9a2fe2cde346eb05aec2caa6f6215b46d61671d545ce"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:28:22"
  condition:
    hash.sha256(0, filesize) == "e3fcc914e472eba36dcf9a2fe2cde346eb05aec2caa6f6215b46d61671d545ce"
}

rule MalwareBazaar_unknown_013_4fff48bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fff48bfe3c5760ead43595761795a35d715c918903115b0c91cc50dff66f040"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:28:02"
  condition:
    hash.sha256(0, filesize) == "4fff48bfe3c5760ead43595761795a35d715c918903115b0c91cc50dff66f040"
}

rule MalwareBazaar_unknown_014_a99a1d95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a99a1d95aade755ccd5b5f065276c8a0059fa7b51c07ae26e3bc3e25d4fa128f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:26:49"
  condition:
    hash.sha256(0, filesize) == "a99a1d95aade755ccd5b5f065276c8a0059fa7b51c07ae26e3bc3e25d4fa128f"
}

rule MalwareBazaar_unknown_015_9cc6e99c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cc6e99c4ea3874a8c810046dd097c43d3baeb15aa9e7107a48e04f7f555d665"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:25:51"
  condition:
    hash.sha256(0, filesize) == "9cc6e99c4ea3874a8c810046dd097c43d3baeb15aa9e7107a48e04f7f555d665"
}

rule MalwareBazaar_unknown_016_4e08f96c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e08f96cd944a23b8a44e6c44e395b6406ab63504c5f755fcbb8620e7d417d4f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:25:38"
  condition:
    hash.sha256(0, filesize) == "4e08f96cd944a23b8a44e6c44e395b6406ab63504c5f755fcbb8620e7d417d4f"
}

rule MalwareBazaar_unknown_017_4b1b177d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1b177d03e0713291a98bc7b2d6dcfb4479e9cacb9ae679213a80928f64cc4c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:25:36"
  condition:
    hash.sha256(0, filesize) == "4b1b177d03e0713291a98bc7b2d6dcfb4479e9cacb9ae679213a80928f64cc4c"
}

rule MalwareBazaar_Mirai_018_4d974b47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d974b47c9ac7f0b4ce3e2c5f2bbd4e10afe6d708da9b37be9de5d02a33f33d5"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-09-19 04:23:42"
  condition:
    hash.sha256(0, filesize) == "4d974b47c9ac7f0b4ce3e2c5f2bbd4e10afe6d708da9b37be9de5d02a33f33d5"
}

rule MalwareBazaar_unknown_019_16c83d29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16c83d29bc49951400e94d15a91ea7896f85374a6c2b603bd403f4aa0f4ffe61"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:23:19"
  condition:
    hash.sha256(0, filesize) == "16c83d29bc49951400e94d15a91ea7896f85374a6c2b603bd403f4aa0f4ffe61"
}

rule MalwareBazaar_Mirai_020_36003d06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36003d068b2307507439136d98f05070d93a45f4a5b7eeee37faa5afd3517398"
    family = "Mirai"
    file_name = "sever1078.arm"
    file_type = "elf"
    first_seen = "2026-09-19 04:23:13"
  condition:
    hash.sha256(0, filesize) == "36003d068b2307507439136d98f05070d93a45f4a5b7eeee37faa5afd3517398"
}

rule MalwareBazaar_unknown_021_2a62a9e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a62a9e5f088a43e4f2b4874b8b4506987350ed6257f5e38dd45d0db8d339c72"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-19 04:22:28"
  condition:
    hash.sha256(0, filesize) == "2a62a9e5f088a43e4f2b4874b8b4506987350ed6257f5e38dd45d0db8d339c72"
}

rule MalwareBazaar_Mirai_022_0558cb79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0558cb79f61501b015b4644c48198bcd0ebc2af0d87b9a12965b5d22563da2ac"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-09-19 04:22:22"
  condition:
    hash.sha256(0, filesize) == "0558cb79f61501b015b4644c48198bcd0ebc2af0d87b9a12965b5d22563da2ac"
}

rule MalwareBazaar_Mirai_023_30f5b70a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f5b70aae2ebd25b9659f16475bd756e1e02d2010ff19b8a75364350c60d832"
    family = "Mirai"
    file_name = "sever1078.arm"
    file_type = "elf"
    first_seen = "2026-09-19 04:22:20"
  condition:
    hash.sha256(0, filesize) == "30f5b70aae2ebd25b9659f16475bd756e1e02d2010ff19b8a75364350c60d832"
}

rule MalwareBazaar_unknown_024_0b3c69db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b3c69dbd3c92bd7b37ca0a6e6e426146aab1b71aecd696bdb67d39a9bbef22b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 04:20:50"
  condition:
    hash.sha256(0, filesize) == "0b3c69dbd3c92bd7b37ca0a6e6e426146aab1b71aecd696bdb67d39a9bbef22b"
}

rule MalwareBazaar_Mirai_025_4a0e3a81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a0e3a81f8f1134bbec6f139ca9d039a71ae49df1df3267e5d3135a1c813f0f8"
    family = "Mirai"
    file_name = "sever1078.x86_64"
    file_type = "elf"
    first_seen = "2026-09-19 04:18:13"
  condition:
    hash.sha256(0, filesize) == "4a0e3a81f8f1134bbec6f139ca9d039a71ae49df1df3267e5d3135a1c813f0f8"
}

rule MalwareBazaar_Mirai_026_fc4e159f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc4e159f8478673943d1d52366f5c274f95fd6ddb3618bd75b873154e72fca0a"
    family = "Mirai"
    file_name = "sever1078.x86_64"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:36"
  condition:
    hash.sha256(0, filesize) == "fc4e159f8478673943d1d52366f5c274f95fd6ddb3618bd75b873154e72fca0a"
}

rule MalwareBazaar_unknown_027_5e3fd0a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401"
    family = "unknown"
    file_name = "5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:23"
  condition:
    hash.sha256(0, filesize) == "5e3fd0a185089ff355d768ebd2ecc35037f68824157d4c998aee58ced9801401"
}

rule MalwareBazaar_unknown_028_bb2d199a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532"
    family = "unknown"
    file_name = "bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:18"
  condition:
    hash.sha256(0, filesize) == "bb2d199a16d8aaab73e7082c659b41e3462dee4f88950aafca3a8aa3df76b532"
}

rule MalwareBazaar_Mirai_029_e9147673
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7"
    family = "Mirai"
    file_name = "e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7"
    file_type = "elf"
    first_seen = "2026-09-19 04:17:12"
  condition:
    hash.sha256(0, filesize) == "e91476737fb99a39063b31d4058a684fe0547bd4d68b2bde5f6f27df06d5bfc7"
}

rule MalwareBazaar_Mirai_030_edc2a485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edc2a48504d4b809806eab7587fd6c5c22ff2b75b550840c358dd7995c2871bf"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-19 04:11:37"
  condition:
    hash.sha256(0, filesize) == "edc2a48504d4b809806eab7587fd6c5c22ff2b75b550840c358dd7995c2871bf"
}

rule MalwareBazaar_Mirai_031_a68650aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a68650aa4400be5e7f4800c7fa4b3b2a848fc2a91d9634a2ddaa225816eec52e"
    family = "Mirai"
    file_name = "sever1078.m68k"
    file_type = "elf"
    first_seen = "2026-09-19 04:05:34"
  condition:
    hash.sha256(0, filesize) == "a68650aa4400be5e7f4800c7fa4b3b2a848fc2a91d9634a2ddaa225816eec52e"
}

rule MalwareBazaar_VShell_032_8d06ef4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9"
    family = "VShell"
    file_name = "8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9.exe"
    file_type = "exe"
    first_seen = "2026-09-19 04:02:39"
  condition:
    hash.sha256(0, filesize) == "8d06ef4fd7819b75943dec120fbd50c1fd0820c760734fa13f7ffa6fac85d1d9"
}

rule MalwareBazaar_Mirai_033_bd31af11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd31af1197eb787a589ad43fc646fb6285c80e9b1769b870baec11d0277fe4b6"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-09-19 04:02:36"
  condition:
    hash.sha256(0, filesize) == "bd31af1197eb787a589ad43fc646fb6285c80e9b1769b870baec11d0277fe4b6"
}

rule MalwareBazaar_VShell_034_5928481f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec"
    family = "VShell"
    file_name = "5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec.exe"
    file_type = "exe"
    first_seen = "2026-09-19 04:02:32"
  condition:
    hash.sha256(0, filesize) == "5928481fada1e9be6582b365b7effa977dc43ebf7f9e0a386f485649b30690ec"
}

rule MalwareBazaar_unknown_035_617963c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "617963c03037db6071c36f60f7adc7fda0a6c2bd609ecf880cbb787fe9150c21"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:57:51"
  condition:
    hash.sha256(0, filesize) == "617963c03037db6071c36f60f7adc7fda0a6c2bd609ecf880cbb787fe9150c21"
}

rule MalwareBazaar_Mirai_036_6932db4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06"
    family = "Mirai"
    file_name = "6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06.elf"
    file_type = "elf"
    first_seen = "2026-09-19 03:57:33"
  condition:
    hash.sha256(0, filesize) == "6932db4dc19fec01137b7fea9e06194d58f334f7a7b146f77a0f8cf6306deb06"
}

rule MalwareBazaar_VShell_037_f48801cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b"
    family = "VShell"
    file_name = "f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b.exe"
    file_type = "exe"
    first_seen = "2026-09-19 03:57:30"
  condition:
    hash.sha256(0, filesize) == "f48801ccbac2ccffdcc6b68db1ae21d35fad179630d5af968a0983af10a5da7b"
}

rule MalwareBazaar_VShell_038_3daf295e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4"
    family = "VShell"
    file_name = "3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4.exe"
    file_type = "exe"
    first_seen = "2026-09-19 03:57:28"
  condition:
    hash.sha256(0, filesize) == "3daf295e54b996fd0b9ed3270b03381fc8066ea32a4ead4e454058f3aab771b4"
}

rule MalwareBazaar_Mirai_039_bcdfe375
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcdfe375371a407fe35e5ba6db910c23eea70971f8a8b33ee86564a03fb4348c"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-09-19 03:54:15"
  condition:
    hash.sha256(0, filesize) == "bcdfe375371a407fe35e5ba6db910c23eea70971f8a8b33ee86564a03fb4348c"
}

rule MalwareBazaar_unknown_040_cf7aa2ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf7aa2cec6060853d6b1ac778d85b8acd049407388b74c121e7a9c3763013287"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:52:55"
  condition:
    hash.sha256(0, filesize) == "cf7aa2cec6060853d6b1ac778d85b8acd049407388b74c121e7a9c3763013287"
}

rule MalwareBazaar_unknown_041_b91f190f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b91f190f50e9d993ae71fba5cf640c6f524073630af9592ead12cfed1fad6720"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:50:08"
  condition:
    hash.sha256(0, filesize) == "b91f190f50e9d993ae71fba5cf640c6f524073630af9592ead12cfed1fad6720"
}

rule MalwareBazaar_unknown_042_eb234f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb234f96dfe6851faf95794f0022b18d2b6abb9cbb8cbdfb41d39e6ccbc95a3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:46:56"
  condition:
    hash.sha256(0, filesize) == "eb234f96dfe6851faf95794f0022b18d2b6abb9cbb8cbdfb41d39e6ccbc95a3e"
}

rule MalwareBazaar_unknown_043_23b6d0c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23b6d0c93d3632515d0fed2d405af26a01a8b4e7ef20c42a5f76be055da9f858"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:44:20"
  condition:
    hash.sha256(0, filesize) == "23b6d0c93d3632515d0fed2d405af26a01a8b4e7ef20c42a5f76be055da9f858"
}

rule MalwareBazaar_unknown_044_f3bf1da0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3bf1da005ec5142943b1b973d04b842d93ae8afe27959e1e75ab806213e1ce7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:31:21"
  condition:
    hash.sha256(0, filesize) == "f3bf1da005ec5142943b1b973d04b842d93ae8afe27959e1e75ab806213e1ce7"
}

rule MalwareBazaar_Mirai_045_b7cfb606
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7cfb606dfbcf4678a15c0452795a5c4cbd3a25f36a63085cd87335920b4ac9a"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.22124.6146"
    file_type = "elf"
    first_seen = "2026-09-19 03:31:16"
  condition:
    hash.sha256(0, filesize) == "b7cfb606dfbcf4678a15c0452795a5c4cbd3a25f36a63085cd87335920b4ac9a"
}

rule MalwareBazaar_unknown_046_1b690165
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b6901652fb859d727f800f32d7e81facca92ebf5ae5333ad147f8df16e3f0f1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:31:00"
  condition:
    hash.sha256(0, filesize) == "1b6901652fb859d727f800f32d7e81facca92ebf5ae5333ad147f8df16e3f0f1"
}

rule MalwareBazaar_Mirai_047_94e748cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94e748ccd80e0532d0dc740d0fcff487d3e5a130da0039ab4369f45da1187dac"
    family = "Mirai"
    file_name = "SecuriteInfo.com.Linux.Mirai.9816.22124.6146"
    file_type = "elf"
    first_seen = "2026-09-19 03:30:31"
  condition:
    hash.sha256(0, filesize) == "94e748ccd80e0532d0dc740d0fcff487d3e5a130da0039ab4369f45da1187dac"
}

rule MalwareBazaar_unknown_048_42629c5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42629c5dddb5fc27f22bfba93bcaf6f321cc788fe57a0f4627694ab9c22d642e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:29:41"
  condition:
    hash.sha256(0, filesize) == "42629c5dddb5fc27f22bfba93bcaf6f321cc788fe57a0f4627694ab9c22d642e"
}

rule MalwareBazaar_unknown_049_efc900e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc900e61b9c834233fa391418f38d45a2cfcb2ce987df01bf0b8c830ce34f1b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:28:55"
  condition:
    hash.sha256(0, filesize) == "efc900e61b9c834233fa391418f38d45a2cfcb2ce987df01bf0b8c830ce34f1b"
}

rule MalwareBazaar_unknown_050_829ed611
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "829ed6118452d3df02d66e3ffb0e754233124b97851775c17971a3ea32eed5e5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:28:32"
  condition:
    hash.sha256(0, filesize) == "829ed6118452d3df02d66e3ffb0e754233124b97851775c17971a3ea32eed5e5"
}

rule MalwareBazaar_unknown_051_865fa806
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "865fa80643980f86897a6c2767f1165bcd99a24c712d83d33b2f6894a21f0c66"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:28:11"
  condition:
    hash.sha256(0, filesize) == "865fa80643980f86897a6c2767f1165bcd99a24c712d83d33b2f6894a21f0c66"
}

rule MalwareBazaar_unknown_052_387dd9de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "387dd9de2fe34888bdd6cf2b698bee23af29483e6964bb5f0c2dab9da8eeaba1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:27:16"
  condition:
    hash.sha256(0, filesize) == "387dd9de2fe34888bdd6cf2b698bee23af29483e6964bb5f0c2dab9da8eeaba1"
}

rule MalwareBazaar_unknown_053_14502cbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14502cbd7bb5f10150195bb3a674998f7d0b881dffa68c24dc41ae3821f5d2a7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:26:31"
  condition:
    hash.sha256(0, filesize) == "14502cbd7bb5f10150195bb3a674998f7d0b881dffa68c24dc41ae3821f5d2a7"
}

rule MalwareBazaar_unknown_054_02aea588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02aea5882129f6b1cf79073496070f9856ee809f537b09187736424ae2868ac7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:26:12"
  condition:
    hash.sha256(0, filesize) == "02aea5882129f6b1cf79073496070f9856ee809f537b09187736424ae2868ac7"
}

rule MalwareBazaar_unknown_055_5050f0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5050f0a6c2933dbc79f6906f1ce683933bfa472f555d72c2d8359479178e2b10"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:24:49"
  condition:
    hash.sha256(0, filesize) == "5050f0a6c2933dbc79f6906f1ce683933bfa472f555d72c2d8359479178e2b10"
}

rule MalwareBazaar_Mozi_056_5b32d178
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497"
    family = "Mozi"
    file_name = "5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:21"
  condition:
    hash.sha256(0, filesize) == "5b32d178e1f875b9448db969398df0d40a77b90d7b41559ea022e46f827a4497"
}

rule MalwareBazaar_unknown_057_53103b74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497"
    family = "unknown"
    file_name = "53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:15"
  condition:
    hash.sha256(0, filesize) == "53103b74eac117fbf5fc004466fe157221aebe7bbdbda088a607efbcb9914497"
}

rule MalwareBazaar_unknown_058_abbf368f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2"
    family = "unknown"
    file_name = "abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:09"
  condition:
    hash.sha256(0, filesize) == "abbf368f01539f8c1cc2362970408a35e0c5b170fe626dcb711a557177b532d2"
}

rule MalwareBazaar_unknown_059_ac16e270
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd"
    family = "unknown"
    file_name = "ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd"
    file_type = "elf"
    first_seen = "2026-09-19 03:19:03"
  condition:
    hash.sha256(0, filesize) == "ac16e2701b8fe6dace8d3910b4ca1bf875cd05ee0de0c0fc82b760b8de7f8cdd"
}

rule MalwareBazaar_unknown_060_22b34fe8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22b34fe804f862da2c545dcc417af6362193c081165c2206f1237243bae212fd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:17:27"
  condition:
    hash.sha256(0, filesize) == "22b34fe804f862da2c545dcc417af6362193c081165c2206f1237243bae212fd"
}

rule MalwareBazaar_unknown_061_2406b42d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2406b42d46d1aba07d8bbe21ecc07799ef478e327447fda14dedd6dede8a5f86"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:13:57"
  condition:
    hash.sha256(0, filesize) == "2406b42d46d1aba07d8bbe21ecc07799ef478e327447fda14dedd6dede8a5f86"
}

rule MalwareBazaar_unknown_062_efa89746
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efa89746b5693167d3ec46b17c77bf3c97eccdaebc2ab907d2f1ac08729888b8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 03:11:32"
  condition:
    hash.sha256(0, filesize) == "efa89746b5693167d3ec46b17c77bf3c97eccdaebc2ab907d2f1ac08729888b8"
}

rule MalwareBazaar_unknown_063_654dd2be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "654dd2bef34c1a84a70315c12d50979e06e553c1f50530e95ab66e047d98f48d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:56:36"
  condition:
    hash.sha256(0, filesize) == "654dd2bef34c1a84a70315c12d50979e06e553c1f50530e95ab66e047d98f48d"
}

rule MalwareBazaar_unknown_064_7eeaa1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eeaa1e1acb4b10e54e1e0367168b306260bc07bb738e0b5452716d5f0cb8abb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:54:17"
  condition:
    hash.sha256(0, filesize) == "7eeaa1e1acb4b10e54e1e0367168b306260bc07bb738e0b5452716d5f0cb8abb"
}

rule MalwareBazaar_unknown_065_e7a7563e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7a7563ea9d2277a4ff27dbf687711a40ba0e937b7f0142b5cd8a821c0f8dbfa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:49:45"
  condition:
    hash.sha256(0, filesize) == "e7a7563ea9d2277a4ff27dbf687711a40ba0e937b7f0142b5cd8a821c0f8dbfa"
}

rule MalwareBazaar_unknown_066_bfd614cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfd614cd3073880767f0af5ef481e24acebde06ce48a80dd607327303f700ce2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:49:25"
  condition:
    hash.sha256(0, filesize) == "bfd614cd3073880767f0af5ef481e24acebde06ce48a80dd607327303f700ce2"
}

rule MalwareBazaar_unknown_067_e399b068
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e399b068d5d679b430b7c95166057b6b38673b32e00ae16d7b971b540cd6539e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:47:01"
  condition:
    hash.sha256(0, filesize) == "e399b068d5d679b430b7c95166057b6b38673b32e00ae16d7b971b540cd6539e"
}

rule MalwareBazaar_unknown_068_31b0afa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31b0afa46c49cddbb19d82de057277a09d19daec6f10dc1af133a0c0cc24e107"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:44:30"
  condition:
    hash.sha256(0, filesize) == "31b0afa46c49cddbb19d82de057277a09d19daec6f10dc1af133a0c0cc24e107"
}

rule MalwareBazaar_unknown_069_49df1599
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49df1599dc7d239bbb7d347bef9941547acec21fc7af972954110c5b24c04342"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:41:18"
  condition:
    hash.sha256(0, filesize) == "49df1599dc7d239bbb7d347bef9941547acec21fc7af972954110c5b24c04342"
}

rule MalwareBazaar_unknown_070_0d3d18aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d3d18aa399e7fb9a3303a32d1dd6fdad11761d10ea62106e62e8a83f4544286"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:38:53"
  condition:
    hash.sha256(0, filesize) == "0d3d18aa399e7fb9a3303a32d1dd6fdad11761d10ea62106e62e8a83f4544286"
}

rule MalwareBazaar_unknown_071_1cc4a8e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cc4a8e44a1ed7520de1e1752931f42fd627e2c9d0de2066cd9de0c9b402881b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:36:36"
  condition:
    hash.sha256(0, filesize) == "1cc4a8e44a1ed7520de1e1752931f42fd627e2c9d0de2066cd9de0c9b402881b"
}

rule MalwareBazaar_unknown_072_402eb235
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "402eb235fc133523e18d548a391e11f65fe0a8ca477d6a1e83213c40978776a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:36:27"
  condition:
    hash.sha256(0, filesize) == "402eb235fc133523e18d548a391e11f65fe0a8ca477d6a1e83213c40978776a4"
}

rule MalwareBazaar_unknown_073_69e292de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69e292deedbf5e5ae10ef9c4bba9cd1c35390ccff9ee321d8aa284e70086be4d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:34:06"
  condition:
    hash.sha256(0, filesize) == "69e292deedbf5e5ae10ef9c4bba9cd1c35390ccff9ee321d8aa284e70086be4d"
}

rule MalwareBazaar_unknown_074_9d3860df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d3860dfaf9dab59581283d973045926aab8bdeb3def0f5e850577586be09252"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:32:38"
  condition:
    hash.sha256(0, filesize) == "9d3860dfaf9dab59581283d973045926aab8bdeb3def0f5e850577586be09252"
}

rule MalwareBazaar_unknown_075_e05f5bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e05f5bdd42ec992bc8697ec0bf699a767f6a7783359c09d9f0a63788c9ab05aa"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:31:41"
  condition:
    hash.sha256(0, filesize) == "e05f5bdd42ec992bc8697ec0bf699a767f6a7783359c09d9f0a63788c9ab05aa"
}

rule MalwareBazaar_unknown_076_246dfeea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "246dfeea33fe0b9ebef66652254e4356cf3486a79e0736e3d8da1beee9cbeb27"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:30:09"
  condition:
    hash.sha256(0, filesize) == "246dfeea33fe0b9ebef66652254e4356cf3486a79e0736e3d8da1beee9cbeb27"
}

rule MalwareBazaar_unknown_077_a03345be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a03345bee66ddfe69090545221a248b55f4a5900aa34c14271b11c2c5ee993b7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:27:11"
  condition:
    hash.sha256(0, filesize) == "a03345bee66ddfe69090545221a248b55f4a5900aa34c14271b11c2c5ee993b7"
}

rule MalwareBazaar_unknown_078_5f4dd099
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f4dd099f342929223b53eca77caebc080b561ba4737f6550eec0fcc729d921b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:19:32"
  condition:
    hash.sha256(0, filesize) == "5f4dd099f342929223b53eca77caebc080b561ba4737f6550eec0fcc729d921b"
}

rule MalwareBazaar_unknown_079_c9866935
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f"
    family = "unknown"
    file_name = "c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f"
    file_type = "elf"
    first_seen = "2026-09-19 02:18:28"
  condition:
    hash.sha256(0, filesize) == "c9866935941556a2cbd074e5028a68f0a310f5201148234e50e0f932a8e8d83f"
}

rule MalwareBazaar_unknown_080_ca5da5a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0"
    family = "unknown"
    file_name = "ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0"
    file_type = "elf"
    first_seen = "2026-09-19 02:18:23"
  condition:
    hash.sha256(0, filesize) == "ca5da5a047b770d4cc0dc3c4582a88cab58e3800e0cee1b6b612822fc5fc34b0"
}

rule MalwareBazaar_Mirai_081_936530bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202"
    family = "Mirai"
    file_name = "936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202"
    file_type = "elf"
    first_seen = "2026-09-19 02:18:18"
  condition:
    hash.sha256(0, filesize) == "936530bba19f0b4db091552d7140814e1277876c9bfde4ebe2f5e1a132091202"
}

rule MalwareBazaar_unknown_082_078b9ab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "078b9ab2d3a8ee0adf29bcc615979df5ed525e250aed1f827f338bdcb3c21e3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:17:13"
  condition:
    hash.sha256(0, filesize) == "078b9ab2d3a8ee0adf29bcc615979df5ed525e250aed1f827f338bdcb3c21e3e"
}

rule MalwareBazaar_Mirai_083_ca44f61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca44f61c186f8c639b7e0914cc6db350435767cad90cfe2e7e4c75a58d811105"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-19 02:03:18"
  condition:
    hash.sha256(0, filesize) == "ca44f61c186f8c639b7e0914cc6db350435767cad90cfe2e7e4c75a58d811105"
}

rule MalwareBazaar_unknown_084_39fa74b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39fa74b4148941700c5625dd0c577fbcd5104e9cf08fbc8abfed8b3bef49ecc3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 02:01:50"
  condition:
    hash.sha256(0, filesize) == "39fa74b4148941700c5625dd0c577fbcd5104e9cf08fbc8abfed8b3bef49ecc3"
}

rule MalwareBazaar_unknown_085_2ec11814
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec1181465193b75a4ef1265a459f5b4c1e19b9ffdacb56792eb605ffb4ceb36"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:59:16"
  condition:
    hash.sha256(0, filesize) == "2ec1181465193b75a4ef1265a459f5b4c1e19b9ffdacb56792eb605ffb4ceb36"
}

rule MalwareBazaar_unknown_086_6e5c8c3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e5c8c3b5ea071271c17654de9e9719905a525359401c0c7dd4cd36c5adc318b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:54:36"
  condition:
    hash.sha256(0, filesize) == "6e5c8c3b5ea071271c17654de9e9719905a525359401c0c7dd4cd36c5adc318b"
}

rule MalwareBazaar_unknown_087_b8783141
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b87831415641a3ad8db05f9e761bed064e7a7309abdf45aed70cf9cbd63551d1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:52:34"
  condition:
    hash.sha256(0, filesize) == "b87831415641a3ad8db05f9e761bed064e7a7309abdf45aed70cf9cbd63551d1"
}

rule MalwareBazaar_unknown_088_366b3cf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "366b3cf3cc5ec10f253ca4a4bc3d04757efaf1a4abcb6f8127e9acd502067a0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:52:14"
  condition:
    hash.sha256(0, filesize) == "366b3cf3cc5ec10f253ca4a4bc3d04757efaf1a4abcb6f8127e9acd502067a0e"
}

rule MalwareBazaar_ConnectWise_089_1b09cde4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61"
    family = "ConnectWise"
    file_name = "1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61.msi"
    file_type = "msi"
    first_seen = "2026-09-19 01:50:54"
  condition:
    hash.sha256(0, filesize) == "1b09cde4bcc2b973e6341e074d0beb7f25d3c4ce45dffa108653f54a969e4f61"
}

rule MalwareBazaar_unknown_090_64bb738b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bb738bf10cfeded1abca18538575a91b30fbd8bc42227da4bff271d3dbc582"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:49:49"
  condition:
    hash.sha256(0, filesize) == "64bb738bf10cfeded1abca18538575a91b30fbd8bc42227da4bff271d3dbc582"
}

rule MalwareBazaar_unknown_091_a852168f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a852168f880042e58f8f3497d8c35d53ea9c2014627e3f7fdc1530dafab1da09"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:48:03"
  condition:
    hash.sha256(0, filesize) == "a852168f880042e58f8f3497d8c35d53ea9c2014627e3f7fdc1530dafab1da09"
}

rule MalwareBazaar_unknown_092_61889065
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618890654712bb0affcbca16d307d01f40cb25bba702dc9145fbd569b84ae22f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:32:00"
  condition:
    hash.sha256(0, filesize) == "618890654712bb0affcbca16d307d01f40cb25bba702dc9145fbd569b84ae22f"
}

rule MalwareBazaar_unknown_093_658013fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "658013fa20f6f19ebcb9e1c4a1eab001bfb827fecd44747bbfb56fa29995c148"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:31:36"
  condition:
    hash.sha256(0, filesize) == "658013fa20f6f19ebcb9e1c4a1eab001bfb827fecd44747bbfb56fa29995c148"
}

rule MalwareBazaar_unknown_094_83a59d8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0"
    family = "unknown"
    file_name = "83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0.bin"
    file_type = "unknown"
    first_seen = "2026-09-19 01:29:33"
  condition:
    hash.sha256(0, filesize) == "83a59d8d9229bd86740896325020bd5770d93af68ba783dd74b2803c6c4ccfd0"
}

rule MalwareBazaar_unknown_095_77ce5f18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77ce5f18377033fcec52c909681fcb7b853311993248b3bb6a509d36b9b86ce4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:29:08"
  condition:
    hash.sha256(0, filesize) == "77ce5f18377033fcec52c909681fcb7b853311993248b3bb6a509d36b9b86ce4"
}

rule MalwareBazaar_unknown_096_61e671d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61e671d2995c47f2da1bea418b7101d635e928e407b5076e8d16ccd68825fdb2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:28:38"
  condition:
    hash.sha256(0, filesize) == "61e671d2995c47f2da1bea418b7101d635e928e407b5076e8d16ccd68825fdb2"
}

rule MalwareBazaar_unknown_097_441f3e1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b"
    family = "unknown"
    file_name = "441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b.bin"
    file_type = "unknown"
    first_seen = "2026-09-19 01:28:00"
  condition:
    hash.sha256(0, filesize) == "441f3e1c64841a18414258df36326c4a048c32fe4543e42d0177d46e853afb6b"
}

rule MalwareBazaar_unknown_098_1dea665b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dea665b8b8666c4fe415b489cbb760138ae4574e444375213586aaaddadaaad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:26:42"
  condition:
    hash.sha256(0, filesize) == "1dea665b8b8666c4fe415b489cbb760138ae4574e444375213586aaaddadaaad"
}

rule MalwareBazaar_unknown_099_d64f952b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d64f952b49169764a2069b3d899d9bb5528464d081a29ffc8fbda1d2734f9cad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:26:20"
  condition:
    hash.sha256(0, filesize) == "d64f952b49169764a2069b3d899d9bb5528464d081a29ffc8fbda1d2734f9cad"
}

rule MalwareBazaar_unknown_100_9df29eb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9df29eb3b238fa74fb8d354f93bc62f44fc7337c2a08abeb68c07c89d5fda598"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-19 01:21:47"
  condition:
    hash.sha256(0, filesize) == "9df29eb3b238fa74fb8d354f93bc62f44fc7337c2a08abeb68c07c89d5fda598"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

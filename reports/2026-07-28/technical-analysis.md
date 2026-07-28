# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-28

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 662 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 662 |
| Unique family labels | 14 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 45 |
| Mirai | 35 |
| Phorpiex | 4 |
| SalatStealer | 3 |
| RemcosRAT | 2 |
| CoinMiner | 2 |
| Efimer | 2 |
| NanoCore | 1 |
| NetSupport | 1 |
| AgentTesla | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 41 |
| elf | 35 |
| sh | 14 |
| vbs | 3 |
| js | 2 |
| ps1 | 2 |
| unknown | 1 |
| zip | 1 |
| rar | 1 |

## Per-Sample Analysis

### Sample 1: `07e01575db8e5a3b`

| Field | Value |
|---|---|
| SHA-256 | `07e01575db8e5a3b8a97aa7977a631e541f412548d16f15f8744969f1540d609` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 02:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2070d140b362a0ad381ae4c6dcf48a7` |
| SHA-1 | `34dc012e9f8a987b38fe2f775d37782d2c9d04e9` |
| SHA-256 | `07e01575db8e5a3b8a97aa7977a631e541f412548d16f15f8744969f1540d609` |
| SHA3-384 | `3614486efbf770bc687005d5af2cb2455110b73bf6fd0053ddbffc935b39bd31afd680d9c36a93ee62d196656cce966d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T178E63308A6D011ECE9B2003DADF36A96E51474A50F76C5EF9BB483916E172F19C3E31B` |
| SSDEEP | `393216:Jk6feU57UkCiUAIMkbElXMCHWUjXTcuI3/PGTAI:JB2C7udg3lXMb8XQH/O7` |
| ICON-DHASH | `9878e0e0d8f8f022` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_07e01575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07e01575db8e5a3b8a97aa7977a631e541f412548d16f15f8744969f1540d609"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 02:52:30"
  condition:
    hash.sha256(0, filesize) == "07e01575db8e5a3b8a97aa7977a631e541f412548d16f15f8744969f1540d609"
}
```

### Sample 2: `fc09faa3fdbf0f6b`

| Field | Value |
|---|---|
| SHA-256 | `fc09faa3fdbf0f6b7d7aad125eca6798b8fb928714dfb0c6b7964a866fdffe39` |
| Family label | `RemcosRAT` |
| File name | `SC_TR11670000_pdf.vbs` |
| File type | `vbs` |
| First seen | `2026-07-28 02:05:38` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9985c83a9ef65973cbaa4e2673c597a` |
| SHA-1 | `cdd5f5657b7efdab718d345d94693cb04a15c538` |
| SHA-256 | `fc09faa3fdbf0f6b7d7aad125eca6798b8fb928714dfb0c6b7964a866fdffe39` |
| SHA3-384 | `541b911574476b529308ac1d60b7f76ca6afa4ed6a86079aaf4246ce0185383d5e56b2c12020cf495ca6902082dd4a39` |
| TLSH | `T19D442820DCD80B3A0E5707EDFF500A65C9FDC529863790ACEA9E171E50125ACDBBF268` |
| SSDEEP | `6144:FupyvMhX48ZdWIQqUNpXF/hJVuiyRB5vYGTKD:iA8ZdWusph94DYxD` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_002_fc09faa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc09faa3fdbf0f6b7d7aad125eca6798b8fb928714dfb0c6b7964a866fdffe39"
    family = "RemcosRAT"
    file_name = "SC_TR11670000_pdf.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 02:05:38"
  condition:
    hash.sha256(0, filesize) == "fc09faa3fdbf0f6b7d7aad125eca6798b8fb928714dfb0c6b7964a866fdffe39"
}
```

### Sample 3: `a522e892f5a5d41e`

| Field | Value |
|---|---|
| SHA-256 | `a522e892f5a5d41e6b71dfa435491682dd20fe2f562075af071f929c3fa38620` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 01:58:27` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7e6b3208a4bf04ef28fd3b37008b7d2` |
| SHA-1 | `701fc165b905a9cb704c689ee8fcc46dae33a660` |
| SHA-256 | `a522e892f5a5d41e6b71dfa435491682dd20fe2f562075af071f929c3fa38620` |
| SHA3-384 | `3d97790e698b3075f1329ffa02495a7bd9a3751ff3e516b877172ff933cbd0bc3eabf3a686707440a5ff56477cd56089` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T19A623A0AA4818035EAE14075827F526649BEADB623C4F9D7F7E0A8C94DB4BD1F43116F` |
| SSDEEP | `192:AWOsGnjXgjk8LcRI+Q1RDMlYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cthf9ik:AXScCtfV/ro6toB0av8U9clX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_a522e892
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a522e892f5a5d41e6b71dfa435491682dd20fe2f562075af071f929c3fa38620"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:58:27"
  condition:
    hash.sha256(0, filesize) == "a522e892f5a5d41e6b71dfa435491682dd20fe2f562075af071f929c3fa38620"
}
```

### Sample 4: `52f011851639a0c3`

| Field | Value |
|---|---|
| SHA-256 | `52f011851639a0c3a5ac55a68314d0b11d6893805f93f0934a4b72f5c3c6d15d` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 01:54:53` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bb73ccfdacfd31c472d9f6b477eb55d` |
| SHA-1 | `7f2d5191f591515ba76b90bd34e4a74ebad68785` |
| SHA-256 | `52f011851639a0c3a5ac55a68314d0b11d6893805f93f0934a4b72f5c3c6d15d` |
| SHA3-384 | `e1728b3fcf701640ca460af9e3e691c6afcb6338e5374419f479c5b7d27650f4fbe3945d69e6110aec57085f24274e30` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T1CA22B21E2E4B0321DE5008B0E5B5464A943D1EE37346FBDBE632E5CB0AE5E4484C1AAF` |
| SSDEEP | `96:pd/ozKYz/J4hOE+b+5BHCdyl/DLDxSikbO8dSTzWjPFJxGE9mZ2FFhJC7tCEeczl:3olpS5BHVxSHO8dfPFJxTEZmFhqecRX` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_004_52f01185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52f011851639a0c3a5ac55a68314d0b11d6893805f93f0934a4b72f5c3c6d15d"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:54:53"
  condition:
    hash.sha256(0, filesize) == "52f011851639a0c3a5ac55a68314d0b11d6893805f93f0934a4b72f5c3c6d15d"
}
```

### Sample 5: `83801179bc16c5d1`

| Field | Value |
|---|---|
| SHA-256 | `83801179bc16c5d1649aff7f6f7bbe46a2e6ef39ec4a3d3d558e758ba89eb7f5` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 01:52:30` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dde2022d383851518ce67221f6c3f51` |
| SHA-1 | `78b10ae2f8b49387b8d68cd1c02f830f3243dd7c` |
| SHA-256 | `83801179bc16c5d1649aff7f6f7bbe46a2e6ef39ec4a3d3d558e758ba89eb7f5` |
| SHA3-384 | `e96546275c6d3d0f0768c0d0b27e4f188238a6772d688f176b1f25bf05de699b724235885636f93bc1f6d656be15cb80` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BCE6335872C402EFE96781BCCCB11366D77978A10732C98B5FA847926E271E1CE39B17` |
| SSDEEP | `393216:aAJtOG5q2rwYTWXMCHWUjXdcuI3/PGTAI:aehRMYTWXMb8XqH/O7` |
| ICON-DHASH | `d471f0e8e8e1f130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_83801179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83801179bc16c5d1649aff7f6f7bbe46a2e6ef39ec4a3d3d558e758ba89eb7f5"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 01:52:30"
  condition:
    hash.sha256(0, filesize) == "83801179bc16c5d1649aff7f6f7bbe46a2e6ef39ec4a3d3d558e758ba89eb7f5"
}
```

### Sample 6: `3b6073262e504853`

| Field | Value |
|---|---|
| SHA-256 | `3b6073262e504853b0d13420eb6846ca0f799334b5038422e6a1bdd8bc505e2c` |
| Family label | `unknown` |
| File name | `o.xml` |
| File type | `unknown` |
| First seen | `2026-07-28 01:41:17` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87004048a9bd8753ff5c50169b811b89` |
| SHA-256 | `3b6073262e504853b0d13420eb6846ca0f799334b5038422e6a1bdd8bc505e2c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_3b607326
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b6073262e504853b0d13420eb6846ca0f799334b5038422e6a1bdd8bc505e2c"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-07-28 01:41:17"
  condition:
    hash.sha256(0, filesize) == "3b6073262e504853b0d13420eb6846ca0f799334b5038422e6a1bdd8bc505e2c"
}
```

### Sample 7: `da8d5c07be1c8cc6`

| Field | Value |
|---|---|
| SHA-256 | `da8d5c07be1c8cc6bcf73f1d9d4794f3de6a8e8d5d873ca310c3bd366d8bde1d` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-28 01:35:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c52849e98dbc1b9194695a6bdb9b1a23` |
| SHA-1 | `2716312795e79e803de56493abc52230320e9fe9` |
| SHA-256 | `da8d5c07be1c8cc6bcf73f1d9d4794f3de6a8e8d5d873ca310c3bd366d8bde1d` |
| SHA3-384 | `65edcd1f02f606307eb2f8000537289fc72ba4253eae2f7cf2bec94e002fec32ed1a3d36e45ab79653f35d206f2079f4` |
| TLSH | `T14B93D606EF511EF7D8ABCD3342B94B0634CCA54622A43BB53574E938B24A54F9AD3CA4` |
| SSDEEP | `1536:OaH+a4CLeTuLjkOTMVfs4q2TcrPjiQdNpDxQQouhqfN/Hal/n5ZLCTRrf:3eTF0iwPjDHpu0Fn5qrf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_da8d5c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da8d5c07be1c8cc6bcf73f1d9d4794f3de6a8e8d5d873ca310c3bd366d8bde1d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-28 01:35:18"
  condition:
    hash.sha256(0, filesize) == "da8d5c07be1c8cc6bcf73f1d9d4794f3de6a8e8d5d873ca310c3bd366d8bde1d"
}
```

### Sample 8: `e8d94cfce33842bb`

| Field | Value |
|---|---|
| SHA-256 | `e8d94cfce33842bb9e66771d9c32a8c460fbf4ab60a39c55e0ade8b3352abd9d` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-28 01:34:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b3ae315d453e6fe2f740534e8875037` |
| SHA-1 | `7b880e7fbe659d5e8b557144ca706d4cd8ad0708` |
| SHA-256 | `e8d94cfce33842bb9e66771d9c32a8c460fbf4ab60a39c55e0ade8b3352abd9d` |
| SHA3-384 | `f5a92aa680525036b3a47dc43d661e40bb5745b10b4bd6e20d261d6483fd0f1134a712359344cbedeb9688c104d031c1` |
| TLSH | `T16AC28D966A867C44BDC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:m8vCB+25j6es8RF9FYpMSUpi+20qUpi+20YQX:m8l25Jjd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_e8d94cfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8d94cfce33842bb9e66771d9c32a8c460fbf4ab60a39c55e0ade8b3352abd9d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 01:34:12"
  condition:
    hash.sha256(0, filesize) == "e8d94cfce33842bb9e66771d9c32a8c460fbf4ab60a39c55e0ade8b3352abd9d"
}
```

### Sample 9: `753936cf1764b986`

| Field | Value |
|---|---|
| SHA-256 | `753936cf1764b98686e87cd140ba7c0234973e1b5339b096f86edc34906a1a77` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-28 01:23:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ce413a2270f4440473fbdb82d9d3d3d` |
| SHA-1 | `d120f7eba74d6f39eea80e9193be341c48fd2b39` |
| SHA-256 | `753936cf1764b98686e87cd140ba7c0234973e1b5339b096f86edc34906a1a77` |
| SHA3-384 | `fb5ca1f7453546b7292f90928c398c6def03b23f9ae38923699cd1775ebeb687fda73677ce64cc2c4a84041e209ab6db` |
| TLSH | `T105A390A85E4F6E82C2C2E37EAD890FA231373DB4C360C2B25901A6DED9D9DD5DC55423` |
| SSDEEP | `1536:4Lx+ng+bAFil/Ws4MeEO5vPZsvFAXaapD8PCkE7KOC54L6nS9c45Ir:4LxHPFiWsABS2aODPkE7KhRnP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_753936cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "753936cf1764b98686e87cd140ba7c0234973e1b5339b096f86edc34906a1a77"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-28 01:23:19"
  condition:
    hash.sha256(0, filesize) == "753936cf1764b98686e87cd140ba7c0234973e1b5339b096f86edc34906a1a77"
}
```

### Sample 10: `decafa3d6023701e`

| Field | Value |
|---|---|
| SHA-256 | `decafa3d6023701eec07d0d0f1ac5b8070a47bb979a5d18d2e70296e51f1e2c4` |
| Family label | `unknown` |
| File name | `.X0-lock_x86_64` |
| File type | `elf` |
| First seen | `2026-07-28 01:16:11` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8451ef00301b20b84bee633be00369f6` |
| SHA-1 | `4eb7075899aa2eaed9ba03322301f1d78a89bc76` |
| SHA-256 | `decafa3d6023701eec07d0d0f1ac5b8070a47bb979a5d18d2e70296e51f1e2c4` |
| SHA3-384 | `9d9656d0e150bfe08c48c57164f887c023927d4e5135219152f5f69ecd89cbad5db51e31817bee9e1b0205af65dbb250` |
| TLSH | `T193654C06B6A744BEC0F5C430874BC5B3AD35B8546225397F3695AB202EB7E204B6DFB1` |
| SSDEEP | `24576:2sGzXMH2HZFbM9OGXTYu9BJZjGWSsiYbk2TW+5EIDR:2s6XMSPM7Dp/GWjiakgR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_decafa3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "decafa3d6023701eec07d0d0f1ac5b8070a47bb979a5d18d2e70296e51f1e2c4"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-07-28 01:16:11"
  condition:
    hash.sha256(0, filesize) == "decafa3d6023701eec07d0d0f1ac5b8070a47bb979a5d18d2e70296e51f1e2c4"
}
```

### Sample 11: `4a319c860dacdd7f`

| Field | Value |
|---|---|
| SHA-256 | `4a319c860dacdd7ff95772e04b7072bba01e43d9f9d03a3cc3ece1e7064e071b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 01:14:29` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb80b24437ca144ae6cf0b19a03ca599` |
| SHA-1 | `57d1464da3f19688610c9526b6dcac48760aeb78` |
| SHA-256 | `4a319c860dacdd7ff95772e04b7072bba01e43d9f9d03a3cc3ece1e7064e071b` |
| SHA3-384 | `421daee17186030d59159839b2b026f20da8cf09ae62c79a09995b5bed777a32172c56b5003355343465a29300ff24c1` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T159623A0AB4818035EAE14075827F526649BEADB623C4F9D7F7E0A8C94DB4BD1F4311AF` |
| SSDEEP | `192:AWTsGnjXgjk8LcRI+Q1RDMlYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cth29ik:AuScCtfV/ro6toB0av8U9coX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_4a319c86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a319c860dacdd7ff95772e04b7072bba01e43d9f9d03a3cc3ece1e7064e071b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:14:29"
  condition:
    hash.sha256(0, filesize) == "4a319c860dacdd7ff95772e04b7072bba01e43d9f9d03a3cc3ece1e7064e071b"
}
```

### Sample 12: `764d5bcb4be851ed`

| Field | Value |
|---|---|
| SHA-256 | `764d5bcb4be851ed27008a40010ed48669160dee3c83fecfc3a0c0654dcece3f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 01:14:02` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da3c4fd3f4f3738f9f626c96de56a535` |
| SHA-1 | `5782b6c0bf1eb4022d8e5c9d80968add1a761e08` |
| SHA-256 | `764d5bcb4be851ed27008a40010ed48669160dee3c83fecfc3a0c0654dcece3f` |
| SHA3-384 | `0de3f26e31d0279ade4d2f4ff11794f1439e77607998306fdb0a3f7a92d9952d28120cc76b50db991355668c291921f3` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T1DE623A0AB4818035EAE04075827F526649BEADB623C4F9D7F7E0A8C94DB4BD1F43516F` |
| SSDEEP | `192:AWCsGnjXgjk8LcRI+Q1RDMRYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cthv9ik:AfScCRfV/ro6toB0av8U9c1X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_764d5bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "764d5bcb4be851ed27008a40010ed48669160dee3c83fecfc3a0c0654dcece3f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:14:02"
  condition:
    hash.sha256(0, filesize) == "764d5bcb4be851ed27008a40010ed48669160dee3c83fecfc3a0c0654dcece3f"
}
```

### Sample 13: `2bd87fb7b4f22cf7`

| Field | Value |
|---|---|
| SHA-256 | `2bd87fb7b4f22cf7685920959c4f335373be6f5aaa00668534f5cdc3bcd74302` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-28 01:12:25` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dd1faf40646a953c8cf3e2d9a43da7e` |
| SHA-1 | `6fc915d989cbe98e89efa28cfffd07a7e7071e6b` |
| SHA-256 | `2bd87fb7b4f22cf7685920959c4f335373be6f5aaa00668534f5cdc3bcd74302` |
| SHA3-384 | `d4220eec6125fe4be9b2c37708ac5f12634b773a7652efc010b7b84b86d19483c1320846ca29cd6e26155af58171f090` |
| TLSH | `T1FD236C651A957C149E98C4361D7E2F0CB9AD43E6320852DE7FCB3CF28C8AA9DD20971D` |
| SSDEEP | `768:dVEJVIhtMt9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:zEJ2Mucr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_2bd87fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd87fb7b4f22cf7685920959c4f335373be6f5aaa00668534f5cdc3bcd74302"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 01:12:25"
  condition:
    hash.sha256(0, filesize) == "2bd87fb7b4f22cf7685920959c4f335373be6f5aaa00668534f5cdc3bcd74302"
}
```

### Sample 14: `043bdf3f2ec52afa`

| Field | Value |
|---|---|
| SHA-256 | `043bdf3f2ec52afa39922ea6a7cb3e4830361de4242a448e9e0b9561148a2ad0` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-28 01:11:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd6bf477d998dc93f51145ed6dffe8f0` |
| SHA-1 | `30bb6baaf5d33906658fa2b5b3ee5a62b87a978a` |
| SHA-256 | `043bdf3f2ec52afa39922ea6a7cb3e4830361de4242a448e9e0b9561148a2ad0` |
| SHA3-384 | `1ce1b29b4a2c2d55b3d89ad4fecaf60069aec1b695ccd18a72727ed62a4359c46d79031b9a4d4330f2a2ba38b582a8b9` |
| TLSH | `T1D293C60E2E318FADF779C23587F74A20976873C626D1C689D26CE5025F7024DA41FBA8` |
| TELFHASH | `t19e111f048d3827f497711d892badffb6f19130df4a256d378d10e95daa5dd425e00c1c` |
| SSDEEP | `1536:hSEVa53YB4fGBkVBP9+h/Fxlbr/ttSXgZDEDG1VeDCEBYQHkLQs6exuNhI+Urn5E:hi53XGBkVBP9+h/Fxlbr/ttSXgZDEzBn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_043bdf3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "043bdf3f2ec52afa39922ea6a7cb3e4830361de4242a448e9e0b9561148a2ad0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-28 01:11:20"
  condition:
    hash.sha256(0, filesize) == "043bdf3f2ec52afa39922ea6a7cb3e4830361de4242a448e9e0b9561148a2ad0"
}
```

### Sample 15: `d31040a2b95b6634`

| Field | Value |
|---|---|
| SHA-256 | `d31040a2b95b66340fe07d1bed67ef96fbe1d60e6635acc2736de3d648f90131` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 01:09:46` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60b6c61db4b78d713fa014568db9263b` |
| SHA-1 | `fc9e19460bd3fd1c997f76bf7d31c85b31b0dca4` |
| SHA-256 | `d31040a2b95b66340fe07d1bed67ef96fbe1d60e6635acc2736de3d648f90131` |
| SHA3-384 | `b275fb1916e6e33fcab24beb20c8ea71098f840fcce646a553be89a78b94c64e2569702f343773c956754ca024ac14e3` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T17D623A0BA4818035EAE04075827F526649BEADB623C4F9D7F7E0A8C94DB4BD1F43216F` |
| SSDEEP | `192:AWbzsGnjXgjk8LcRI+Q1RDMlYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cthV9ik:AmXScCtfV/ro6toB0av8U9c/X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_d31040a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d31040a2b95b66340fe07d1bed67ef96fbe1d60e6635acc2736de3d648f90131"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:09:46"
  condition:
    hash.sha256(0, filesize) == "d31040a2b95b66340fe07d1bed67ef96fbe1d60e6635acc2736de3d648f90131"
}
```

### Sample 16: `8f65fe2615ab0088`

| Field | Value |
|---|---|
| SHA-256 | `8f65fe2615ab00886f1e15499343375021fe8cc6a10e56d569c4277d0e23283e` |
| Family label | `unknown` |
| File name | `Notice of Intent to Award.zip` |
| File type | `zip` |
| First seen | `2026-07-28 01:09:06` |
| Reporter | `skocherhan` |
| Tags | `cuttingedgefencing-ca, Violet, XWorm, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2593238631f66b4f8c9489e4c42a1650` |
| SHA-1 | `179dd650c652fc28ca132f354dbe193d4e892bef` |
| SHA-256 | `8f65fe2615ab00886f1e15499343375021fe8cc6a10e56d569c4277d0e23283e` |
| SHA3-384 | `8cb63b635291189ab355e1c714cfec647c7717cdbe9a5477d6386b16b0a3c6e4cdc1e77ec91cd75a82b71fc1ab9d2e60` |
| TLSH | `T1101423E3475AA2432B5CE08497F79334660B835790182BBE2734F936EEDD184DEF6906` |
| SSDEEP | `3072:eZApK/RU3FCjO+wTNq0hlx1AGKLoXh04iVF2SW3JQIjm6Y9Kgku6pdpzruwqz:uAeRU3FCjnwpq0hfDKEx04csS3h0jpW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_8f65fe26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f65fe2615ab00886f1e15499343375021fe8cc6a10e56d569c4277d0e23283e"
    family = "unknown"
    file_name = "Notice of Intent to Award.zip"
    file_type = "zip"
    first_seen = "2026-07-28 01:09:06"
  condition:
    hash.sha256(0, filesize) == "8f65fe2615ab00886f1e15499343375021fe8cc6a10e56d569c4277d0e23283e"
}
```

### Sample 17: `e947f8a540eb337c`

| Field | Value |
|---|---|
| SHA-256 | `e947f8a540eb337c4090c14d880948f07106dbe19d64625b7577cf9416935fae` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 01:07:07` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a93a809cf87667cb73e0405f5e5b102` |
| SHA-1 | `819f0be1dbc81eb85163de4cea0f629c10325ec3` |
| SHA-256 | `e947f8a540eb337c4090c14d880948f07106dbe19d64625b7577cf9416935fae` |
| SHA3-384 | `fd2e15292f7c9872caff00c23f09fd3dd4dfd03dff232b0bbf9154a87c273d5092df849c0504ed5744b264219fc5775c` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T13C622A0AA4818035EAE14075827F526645FE6DB623C4F9D7F7E0A8C94DB4BD1F43116F` |
| SSDEEP | `192:AWtsGnjXgjk8LcRI+Q1RDMlYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cthA9ik:AwScCtfV/ro6toB0av8U9cGX` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_017_e947f8a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e947f8a540eb337c4090c14d880948f07106dbe19d64625b7577cf9416935fae"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:07:07"
  condition:
    hash.sha256(0, filesize) == "e947f8a540eb337c4090c14d880948f07106dbe19d64625b7577cf9416935fae"
}
```

### Sample 18: `f912389499090e12`

| Field | Value |
|---|---|
| SHA-256 | `f912389499090e12b222ac4800da81a9e8d0ad6765b63fbee9eafc0a4291076a` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-28 00:58:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f1fc069a739d673e7cb80468adf9dad` |
| SHA-1 | `6b631e14f8a563664a02d9a1d00c426ea6e572ef` |
| SHA-256 | `f912389499090e12b222ac4800da81a9e8d0ad6765b63fbee9eafc0a4291076a` |
| SHA3-384 | `e0eaf6e33abb0002edb2fa40a41b1d011d841d620e1997a358bdd76358c37e0bbb180b78a0549589adb7a8e1f7d70129` |
| TLSH | `T1AC93F759F8819B11D5D525BEFE0F428D33234BACE3EB7212AD249B2537C692B0E7B105` |
| TELFHASH | `t18ab0123941067ebc0980c9cfe6ffc10b10bc642b53b0217c079e562c47b61c2c306455` |
| SSDEEP | `1536:UZnYL0d3OwMGHMq5g05rt+644caFiBGFaaJp09lEuit0dBj55MbBZTuYHimfn5ZX:V0ptMGHMFkto4caFiBGFaaN90dF55Mbj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_f9123894
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f912389499090e12b222ac4800da81a9e8d0ad6765b63fbee9eafc0a4291076a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-28 00:58:27"
  condition:
    hash.sha256(0, filesize) == "f912389499090e12b222ac4800da81a9e8d0ad6765b63fbee9eafc0a4291076a"
}
```

### Sample 19: `b06316fc674d62db`

| Field | Value |
|---|---|
| SHA-256 | `b06316fc674d62db99afd11be3ec60eb212fd0e64a23c20685017fe7d7221f5d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-28 00:56:57` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5734b587edb55648f7d0b461a3f3c466` |
| SHA-1 | `3b10ed57ea261a2587473b558826c4e4587cdc57` |
| SHA-256 | `b06316fc674d62db99afd11be3ec60eb212fd0e64a23c20685017fe7d7221f5d` |
| SHA3-384 | `35cec26d40444adc8587e0826c36fbb80b414deb982f9c02b12c8e50232b0985381ced21399bc1542177ccea8df8134a` |
| IMPHASH | `3537f9c463b968f2d94efe8dfe27133f` |
| TLSH | `T19B623A0AB4818035EAE04075827F526649BEADB623C4F9D7F7E0A8C94DB4BE1F43116F` |
| SSDEEP | `192:AWFsGnjXgjk8LcRI+Q1RDMlYfV/F5oIVUBKUSftzQFBrfgJxTmv8U9cthv9ik:AQScCtfV/ro6toB0av8U9c1X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_b06316fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b06316fc674d62db99afd11be3ec60eb212fd0e64a23c20685017fe7d7221f5d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 00:56:57"
  condition:
    hash.sha256(0, filesize) == "b06316fc674d62db99afd11be3ec60eb212fd0e64a23c20685017fe7d7221f5d"
}
```

### Sample 20: `2c620e407eabb93d`

| Field | Value |
|---|---|
| SHA-256 | `2c620e407eabb93dc16449499824074a38497caeb42abd7176a7d101a3bb62c2` |
| Family label | `RemcosRAT` |
| File name | `scan02_ Shipping documents.vbs` |
| File type | `vbs` |
| First seen | `2026-07-28 00:53:58` |
| Reporter | `threatcat_ch` |
| Tags | `RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da64e24ade9227d1f7ce42063f8cdfde` |
| SHA-1 | `56a69a6ace082f5fe2f04d97aea953bdd7df3aca` |
| SHA-256 | `2c620e407eabb93dc16449499824074a38497caeb42abd7176a7d101a3bb62c2` |
| SHA3-384 | `c2a98a7b536a479296905872ff54fd356465ca9ce1c553ddcd2b67c0eb74e83f5afd074a4cf1e41031fc37ce55abfdcb` |
| TLSH | `T18C442720DCD40B3A0E5707EDFE514A65C9FDC5298626D0ACEADE071E50135ACEBBF268` |
| SSDEEP | `6144:Fup+vIhXYGB3WYMpumNpXqzheiGtYYmUR676YFT0:i6GB3WVXpkMd3Ye` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_020_2c620e40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c620e407eabb93dc16449499824074a38497caeb42abd7176a7d101a3bb62c2"
    family = "RemcosRAT"
    file_name = "scan02_ Shipping documents.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 00:53:58"
  condition:
    hash.sha256(0, filesize) == "2c620e407eabb93dc16449499824074a38497caeb42abd7176a7d101a3bb62c2"
}
```

### Sample 21: `04ef9757c950005f`

| Field | Value |
|---|---|
| SHA-256 | `04ef9757c950005f926458dee36517a6c879d39e5798a378bdd6aa7a45d0d23a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-28 00:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba1a44c6bfd17c461d2ebf0f033bae12` |
| SHA-1 | `22edef81c1fe81db499b3084b3c128b96a70c5a1` |
| SHA-256 | `04ef9757c950005f926458dee36517a6c879d39e5798a378bdd6aa7a45d0d23a` |
| SHA3-384 | `74c385f96ab18439faa656cacf1905f381e7e8c51d46410ec4b92035642b917ff30b69aea5d3341559de5e24aa036ca2` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T123E6330827F122DEF6B3503DFED20516E5A9703A2B72C9EB9B5453716F471E18E3A242` |
| SSDEEP | `393216:B+cI5DSiUihxiXB9tXMCHWUjX+cuI3/PGTAI:BNI5glX/tXMb8XzH/O7` |
| ICON-DHASH | `71f0d4d8c8e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_04ef9757
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef9757c950005f926458dee36517a6c879d39e5798a378bdd6aa7a45d0d23a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 00:52:31"
  condition:
    hash.sha256(0, filesize) == "04ef9757c950005f926458dee36517a6c879d39e5798a378bdd6aa7a45d0d23a"
}
```

### Sample 22: `eb71de1615f852d0`

| Field | Value |
|---|---|
| SHA-256 | `eb71de1615f852d0d2816198901c157bfdab1f62dd3b2d029a4b167a7ba2b3fb` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-28 00:37:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `123134725663d85f9e2de04980131fca` |
| SHA-1 | `5d7185e16f90433e860091445cfa904ad6a5ba6b` |
| SHA-256 | `eb71de1615f852d0d2816198901c157bfdab1f62dd3b2d029a4b167a7ba2b3fb` |
| SHA3-384 | `f4a2098871a9d1bafaa90dbb493c5d093fc76f54ec784e15dbd8476a54ff90559bf72b447d395a69459b45a2ef2f1940` |
| TLSH | `T163731A59F9919A22C5C155BFFE0F828D772243E8D2EB3307DE296F61368786B0D2B141` |
| TELFHASH | `t1f8b0125251db054cc7d38283ad3b3a06758298308b9970126f37284ae3430407469032` |
| SSDEEP | `1536:Q7BQDUIr3rLAom/Z6y07fTLidPYPLmOTODsOn9ebvyfn5ZLCORs:JTrL1s6XbedPEmQQn5bs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_eb71de16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb71de1615f852d0d2816198901c157bfdab1f62dd3b2d029a4b167a7ba2b3fb"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-28 00:37:36"
  condition:
    hash.sha256(0, filesize) == "eb71de1615f852d0d2816198901c157bfdab1f62dd3b2d029a4b167a7ba2b3fb"
}
```

### Sample 23: `711b5be1f5c5d4c5`

| Field | Value |
|---|---|
| SHA-256 | `711b5be1f5c5d4c53d12c5e8415e401aa87e99de164178e2a602367922639ce3` |
| Family label | `unknown` |
| File name | `QU20262807.vbs` |
| File type | `vbs` |
| First seen | `2026-07-28 00:35:33` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83aeb63fb1603957d07d2d92775daac2` |
| SHA-1 | `0c8d49683747cbb9ac9efc702071395cae9fe2ab` |
| SHA-256 | `711b5be1f5c5d4c53d12c5e8415e401aa87e99de164178e2a602367922639ce3` |
| SHA3-384 | `0d2c20a7d6ed6ecf1abe2d696eb3f4b0ad34e1a2a791f0a1c471971563b36d4d278f49e34fe286233ec8fbe208da2c33` |
| TLSH | `T1F9442720DCD80B3A0E5707EDFF514A65C9FDC529863690ECEA9E071E50125ACE7BF268` |
| SSDEEP | `6144:Fup1v4hXho3BWCkLVNpXpwhIfLdhRlhCYfTE:iEo3BWx3paq56YQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_711b5be1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "711b5be1f5c5d4c53d12c5e8415e401aa87e99de164178e2a602367922639ce3"
    family = "unknown"
    file_name = "QU20262807.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 00:35:33"
  condition:
    hash.sha256(0, filesize) == "711b5be1f5c5d4c53d12c5e8415e401aa87e99de164178e2a602367922639ce3"
}
```

### Sample 24: `bd5cabe39fddca6f`

| Field | Value |
|---|---|
| SHA-256 | `bd5cabe39fddca6f03728e5a86e791acb14438adb6e6ad8fca4d80f9d7ea802a` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-28 00:34:24` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e184229dca0361a5a1adc56963f071c` |
| SHA-1 | `f6a3c80bcbd19c4fd13767040e77b0a2dbd5d746` |
| SHA-256 | `bd5cabe39fddca6f03728e5a86e791acb14438adb6e6ad8fca4d80f9d7ea802a` |
| SHA3-384 | `6759b7b5a39e5cf702894a70798f695e2901a3f6d2211f31d2b5f14a9289b75dd712112d9bfe15a6034ebf5e9580f6d9` |
| TLSH | `T1E2C27D966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D4A3C71DC11FACD618B1A` |
| SSDEEP | `768:M8vCB+25j6es8RBZ9FYpMSUpi+20qUpi+20YQX:M8l25JB/d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_bd5cabe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd5cabe39fddca6f03728e5a86e791acb14438adb6e6ad8fca4d80f9d7ea802a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 00:34:24"
  condition:
    hash.sha256(0, filesize) == "bd5cabe39fddca6f03728e5a86e791acb14438adb6e6ad8fca4d80f9d7ea802a"
}
```

### Sample 25: `50d5984d193e2505`

| Field | Value |
|---|---|
| SHA-256 | `50d5984d193e2505338449d7594f394a4aa6cdd55370706f1d12dfb0e32e3183` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-28 00:28:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fde76ca061b2320b0e66c4e19935926d` |
| SHA-1 | `2d4286ca3c7706aee0b49f2b4d14e667824a5bf6` |
| SHA-256 | `50d5984d193e2505338449d7594f394a4aa6cdd55370706f1d12dfb0e32e3183` |
| SHA3-384 | `86124a1459ddc93f97b3b6671b46ae9537f690a8ffc762605a7dc77be157cc97836744f2ce5dd03a734d8b6ec1381218` |
| TLSH | `T145236C6516857C14AE98C4375C7E2F0CB9AD43E6314492EE7FCA3CF28C4A6ADA20871D` |
| SSDEEP | `768:Fr9NyXsZztCS9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:NHusZOcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_50d5984d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d5984d193e2505338449d7594f394a4aa6cdd55370706f1d12dfb0e32e3183"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 00:28:07"
  condition:
    hash.sha256(0, filesize) == "50d5984d193e2505338449d7594f394a4aa6cdd55370706f1d12dfb0e32e3183"
}
```

### Sample 26: `f9bb0caed91dcc9a`

| Field | Value |
|---|---|
| SHA-256 | `f9bb0caed91dcc9a95aee382b85494510ea4c94eaf4666ff70082b41ef1c0bfd` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-28 00:26:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cafa830f1e23156bf3e8452b46beafa4` |
| SHA-1 | `3dae3c903f95217654ba1573798f945447fe2f5e` |
| SHA-256 | `f9bb0caed91dcc9a95aee382b85494510ea4c94eaf4666ff70082b41ef1c0bfd` |
| SHA3-384 | `9629e4d3ce074e9a7ac61ae77b07deac4fa966bb6d8ee3372b400b11334b4cd677f3f5cfae889ecd78047697da0a768f` |
| TLSH | `T154536C8EFA43C0B5FD4615702837DF624631E8756075FB82E7761AB2EC23A01A6177AC` |
| TELFHASH | `t1083146b76e6a08f9f390bc4c8b1e07122f1a5e770a2072ba01e39dd136e25d1c179832` |
| SSDEEP | `1536:nHLMR7clhz/WejTNLz/Ve5TX/+nOdRKs9y+a:HLC8flLzNKj/Sp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_f9bb0cae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9bb0caed91dcc9a95aee382b85494510ea4c94eaf4666ff70082b41ef1c0bfd"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-28 00:26:41"
  condition:
    hash.sha256(0, filesize) == "f9bb0caed91dcc9a95aee382b85494510ea4c94eaf4666ff70082b41ef1c0bfd"
}
```

### Sample 27: `7070ccdf86771d89`

| Field | Value |
|---|---|
| SHA-256 | `7070ccdf86771d89aa15bb3cc21e01b3eda0d5b81af6a87ef535940e8f7493a4` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-28 00:25:26` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05f261c2d8694cfe457c331abed1fa37` |
| SHA-1 | `c609d6fa7b30ec54d9f9f05eb59bf9857ad98662` |
| SHA-256 | `7070ccdf86771d89aa15bb3cc21e01b3eda0d5b81af6a87ef535940e8f7493a4` |
| SHA3-384 | `747a877f6102a2a44035be35a0adc4c3fc75bbe1b5a56a48052770686a0f756ec418e042c914c32258e9c98b59365dc2` |
| TLSH | `T14801CECAD26459A040A9D42C22D75098F431C3CB294A8B74BF9CA43D9BA8E14F036FDC` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkazCt855UkR7CeOClhDu+qC6OrRC5X:kXCKysE2hi0ziQvZohazXUWcauHpmWX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_7070ccdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7070ccdf86771d89aa15bb3cc21e01b3eda0d5b81af6a87ef535940e8f7493a4"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-28 00:25:26"
  condition:
    hash.sha256(0, filesize) == "7070ccdf86771d89aa15bb3cc21e01b3eda0d5b81af6a87ef535940e8f7493a4"
}
```

### Sample 28: `6956260708076c10`

| Field | Value |
|---|---|
| SHA-256 | `6956260708076c10bac1e5725846780bc1a754fa1a26001b4b8f22b8c1a7c1fb` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-28 00:22:09` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df0a704dfb896d3815a957fa8e24d571` |
| SHA-1 | `5e3d7e74ed4d6c48ae1110847f59efe03f641896` |
| SHA-256 | `6956260708076c10bac1e5725846780bc1a754fa1a26001b4b8f22b8c1a7c1fb` |
| SHA3-384 | `4d414119d31326c3f69ebb2600447c3ad4e4d47992484e0889d01f96ef9473532efbfb80a8a27bb415c6cb71e7f4421b` |
| TLSH | `T1B801ABC6922055A04029D52D62965294F431C3CA59460B787FCC943DABA8A14F026F9C` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkazCt855Uk97COhOClhDuzsqC6OQsRCzauD:kXCKysE2hi0ziQvZohazXUwgauNpZSi7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_69562607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6956260708076c10bac1e5725846780bc1a754fa1a26001b4b8f22b8c1a7c1fb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-28 00:22:09"
  condition:
    hash.sha256(0, filesize) == "6956260708076c10bac1e5725846780bc1a754fa1a26001b4b8f22b8c1a7c1fb"
}
```

### Sample 29: `a326333799d5c425`

| Field | Value |
|---|---|
| SHA-256 | `a326333799d5c425a31de391c84c839de3a25b39bf9c4ba3bed95aac8ea0043f` |
| Family label | `unknown` |
| File name | `libcommon.so_x86_64` |
| File type | `elf` |
| First seen | `2026-07-28 00:22:08` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `691012e5920fd8cc43c6ba437429916a` |
| SHA-1 | `69bc4cab0a1d08e103f2a003ce101b3eb8d9cdd7` |
| SHA-256 | `a326333799d5c425a31de391c84c839de3a25b39bf9c4ba3bed95aac8ea0043f` |
| SHA3-384 | `e775ce835c2412ac6129458d75b7541b0892b0dd711f5c4f57741c21cfbfdc52330130f436c1dfb894926e4132a89446` |
| TLSH | `T17C22421BEA82C6AAC0D563F428C7457037B1D490E7315367935CED355C63B884B2EE5B` |
| TELFHASH | `t196b012c0df0f050412921c30dc5d8798a013450bf8b817001979cad1165470b070452c` |
| SSDEEP | `96:Rb0BWBShzO7ce5wXs/e/Aah/Na7LSl3qwMCsHwzqHiKTgQl8KuE3:Rb08chzOHksmROL5HgUiqg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_a3263337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a326333799d5c425a31de391c84c839de3a25b39bf9c4ba3bed95aac8ea0043f"
    family = "unknown"
    file_name = "libcommon.so_x86_64"
    file_type = "elf"
    first_seen = "2026-07-28 00:22:08"
  condition:
    hash.sha256(0, filesize) == "a326333799d5c425a31de391c84c839de3a25b39bf9c4ba3bed95aac8ea0043f"
}
```

### Sample 30: `6736fac25a0bccf4`

| Field | Value |
|---|---|
| SHA-256 | `6736fac25a0bccf4862f4a49bb354961a042e0c420f081332ad4473eb7ed1e8b` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-28 00:22:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56321a369e41ed8a8dee9a4c631581fb` |
| SHA-1 | `95789eb4d06b22cd450fe01c39e2a7a6f3dd6c16` |
| SHA-256 | `6736fac25a0bccf4862f4a49bb354961a042e0c420f081332ad4473eb7ed1e8b` |
| SHA3-384 | `d677460a3e3d100fbdfc7ccb1173daa3aecca795bd5b02a7acc0f3727cb9f02f25c5a34159b381726765a92cb293b1a1` |
| TLSH | `T15C631A99F9819A22C5C115BBFF0F828D77365398D2EB3307DE196F21368786B0E2B141` |
| TELFHASH | `t1f8b0125251db054cc7d38283ad3b3a06758298308b9970126f37284ae3430407469032` |
| SSDEEP | `1536:ylwQDZIVSvZAdm/z6yHG0TLE0mbzLmO4SQVDCW6atfn5ZLCBRJ:QZvZ4a6L2w0mXaVhHn5kJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_6736fac2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6736fac25a0bccf4862f4a49bb354961a042e0c420f081332ad4473eb7ed1e8b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-28 00:22:06"
  condition:
    hash.sha256(0, filesize) == "6736fac25a0bccf4862f4a49bb354961a042e0c420f081332ad4473eb7ed1e8b"
}
```

### Sample 31: `a3c889a83799583a`

| Field | Value |
|---|---|
| SHA-256 | `a3c889a83799583a0dcbfaa90ad905cafbb0cd3221b54b49cb5fe3ceecec3d34` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 23:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baa453124334a345c4a906dd4bced099` |
| SHA-1 | `1d367e33e8cf273a56b8ddc493925c64ad7d648f` |
| SHA-256 | `a3c889a83799583a0dcbfaa90ad905cafbb0cd3221b54b49cb5fe3ceecec3d34` |
| SHA3-384 | `0d3e190edc2bf9d82e3b1a8e88de9cdc8f30fb94280f12c4e85f634c5962974f16b3dbd9d715e485a6d2bffd091fb8a1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T116E63309A5C402FBF5B3913C9ED12052D4B7B0630F32CE9B4B9487A59E671A14E3E96B` |
| SSDEEP | `393216:nVranInkMFwut7BaYObzr0JCN7kHKXMCHWUjXHcuI3/PGTAI:nV+nqkMFwud5Kr08NlXMb8X8H/O7` |
| ICON-DHASH | `70f0f0e8e8f0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_a3c889a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c889a83799583a0dcbfaa90ad905cafbb0cd3221b54b49cb5fe3ceecec3d34"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 23:52:31"
  condition:
    hash.sha256(0, filesize) == "a3c889a83799583a0dcbfaa90ad905cafbb0cd3221b54b49cb5fe3ceecec3d34"
}
```

### Sample 32: `067e321f8018c785`

| Field | Value |
|---|---|
| SHA-256 | `067e321f8018c785f2c5089807e59bb9d6a1caf97aca775a3b435d4fb7b564b6` |
| Family label | `unknown` |
| File name | `bundle.js` |
| File type | `js` |
| First seen | `2026-07-27 23:17:32` |
| Reporter | `anonymous` |
| Tags | `js, nodejs rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f43bf13c6eb3255329beafb9a11d329` |
| SHA-256 | `067e321f8018c785f2c5089807e59bb9d6a1caf97aca775a3b435d4fb7b564b6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_067e321f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067e321f8018c785f2c5089807e59bb9d6a1caf97aca775a3b435d4fb7b564b6"
    family = "unknown"
    file_name = "bundle.js"
    file_type = "js"
    first_seen = "2026-07-27 23:17:32"
  condition:
    hash.sha256(0, filesize) == "067e321f8018c785f2c5089807e59bb9d6a1caf97aca775a3b435d4fb7b564b6"
}
```

### Sample 33: `21fa2933a5f8ecc1`

| Field | Value |
|---|---|
| SHA-256 | `21fa2933a5f8ecc157747f190d86762317d8b64f800f67287fbecf0169764b46` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 22:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9ff5612013f81d8ccb00c564e007290` |
| SHA-1 | `a0a2321a3f0917db7fa42e03a1296f95e40e7c30` |
| SHA-256 | `21fa2933a5f8ecc157747f190d86762317d8b64f800f67287fbecf0169764b46` |
| SHA3-384 | `70140f9ca24d531960793d647dda33edf6210ead9a7887294864168e7418de4e0ee3ecba42c2742e454f028c9f4b4028` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T185E633447AF001EDE7B3C138BDD298A9C15578B50BB2CD5B57B887A0AE972D08D3DA13` |
| SSDEEP | `393216:ZNuETIBgJG3qNaGbAfoXMCHWUjXCcuI3/PGTAI:Z43gZdooXMb8X/H/O7` |
| ICON-DHASH | `71f8d0f0e0e8f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_21fa2933
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21fa2933a5f8ecc157747f190d86762317d8b64f800f67287fbecf0169764b46"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 22:52:31"
  condition:
    hash.sha256(0, filesize) == "21fa2933a5f8ecc157747f190d86762317d8b64f800f67287fbecf0169764b46"
}
```

### Sample 34: `10ada20cd985da2b`

| Field | Value |
|---|---|
| SHA-256 | `10ada20cd985da2b6ba1e0a5ce914582f37b12e6b4fc6c0c3f70466b1f9fa06a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-27 22:43:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5820b371ce9f3c8bc83610bf52151d0` |
| SHA-1 | `c4657e92e7071ed21549e6be1d3a33af93925004` |
| SHA-256 | `10ada20cd985da2b6ba1e0a5ce914582f37b12e6b4fc6c0c3f70466b1f9fa06a` |
| SHA3-384 | `f30a26fba6cbba96812d8ecb26d9f16e298be2f3c0eb0cfd1c23682dd1a3958bf8baaa65dacb10046fbfd6587e4ea049` |
| TLSH | `T1E4236C6516857C14AE98C4375D7F2F0CB9AD43E6314492EE7FCA3CF28C4A6AD920861D` |
| SSDEEP | `768:kr9NyXsZztC2H9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:CHusZecr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_10ada20c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ada20cd985da2b6ba1e0a5ce914582f37b12e6b4fc6c0c3f70466b1f9fa06a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 22:43:17"
  condition:
    hash.sha256(0, filesize) == "10ada20cd985da2b6ba1e0a5ce914582f37b12e6b4fc6c0c3f70466b1f9fa06a"
}
```

### Sample 35: `712ca31e2937bf84`

| Field | Value |
|---|---|
| SHA-256 | `712ca31e2937bf843579e0e782ac8bc33ae84b4d580a3c69aabd531ff416b5b8` |
| Family label | `unknown` |
| File name | `QUOTATION KKTP - #PO996574620775800000 A105N.pdf(786KB).lha.com` |
| File type | `exe` |
| First seen | `2026-07-27 22:25:47` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fef8581b198c27c37f06137df872d52` |
| SHA-1 | `a4d3c3c8cfe0cf04e3de11277d27d211c8ad1b52` |
| SHA-256 | `712ca31e2937bf843579e0e782ac8bc33ae84b4d580a3c69aabd531ff416b5b8` |
| SHA3-384 | `ab189034b4905fd9e0b225e806f0b8e0ca945d65aa4225af31cdd72d5e6f98ef4041438bddedff51ae2b70654edfcb76` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AF0512562A68DF23E36B07F506E2E1B013FA5D4FE532C2084EC95DEF749AB245A15383` |
| SSDEEP | `12288:LaqWQ/COQ/KliT3qWALzeApIaF1+C4Ujk6Yz2OkqWkEd2/L8uHxoLqUfF1l:tCWigneWTF1+6Vh3qWKwuHZUfXl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_712ca31e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "712ca31e2937bf843579e0e782ac8bc33ae84b4d580a3c69aabd531ff416b5b8"
    family = "unknown"
    file_name = "QUOTATION KKTP - #PO996574620775800000 A105N.pdf(786KB).lha.com"
    file_type = "exe"
    first_seen = "2026-07-27 22:25:47"
  condition:
    hash.sha256(0, filesize) == "712ca31e2937bf843579e0e782ac8bc33ae84b4d580a3c69aabd531ff416b5b8"
}
```

### Sample 36: `17c4da4a81155d23`

| Field | Value |
|---|---|
| SHA-256 | `17c4da4a81155d233e6eaf6ef7cd2590d6fda76a46bacede4881ab3cd1bf88d3` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 21:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce3376b9a6834ccfd743785dfec778a1` |
| SHA-1 | `292fc63a1d767753790e78d08aec4bc97d19a5cc` |
| SHA-256 | `17c4da4a81155d233e6eaf6ef7cd2590d6fda76a46bacede4881ab3cd1bf88d3` |
| SHA3-384 | `40c40ff0e9bf0c21d503b4eb3be80c298cef0c959c6844e9f18d3d6ba0846770ff0d6650a950a1db12dc77eb25b04212` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T13FE6339CE6C005EDE5F382369DD28790F2AAB4750372CA8B5B78C6525D632F10D3C6A7` |
| SSDEEP | `393216:AKWpyg4EgvzM7AykZfMNmQFVYuXMCHWUjX4cuI3/PGTAI:As9EAzM7AFkmQMuXMb8XNH/O7` |
| ICON-DHASH | `e8e865e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_17c4da4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17c4da4a81155d233e6eaf6ef7cd2590d6fda76a46bacede4881ab3cd1bf88d3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 21:52:32"
  condition:
    hash.sha256(0, filesize) == "17c4da4a81155d233e6eaf6ef7cd2590d6fda76a46bacede4881ab3cd1bf88d3"
}
```

### Sample 37: `ffa5c396a37ef0db`

| Field | Value |
|---|---|
| SHA-256 | `ffa5c396a37ef0dbabf541cecc4e1bda84675eace39d2a8d2ccf355f08a9ca80` |
| Family label | `unknown` |
| File name | `oxmaul.rar` |
| File type | `rar` |
| First seen | `2026-07-27 21:27:22` |
| Reporter | `smica83` |
| Tags | `CVE-2025-6218, CVE-2025-8088, rar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05d81eb0e76fe59df6c6fe6088e85eab` |
| SHA-1 | `b8421d746f47c9c61e3aa98102b484b9b60f7bad` |
| SHA-256 | `ffa5c396a37ef0dbabf541cecc4e1bda84675eace39d2a8d2ccf355f08a9ca80` |
| SHA3-384 | `524c0baa59e6cd597e5c57e0be72eae46c74204d195754f7fae111afd9d77c4730916fadc3da79967f20e199669a7a7b` |
| TLSH | `T1BF07336BA07869C026E1A1DF58E29F3153712C4BC8C7A48B4CEFF7DDB60B38515A9D48` |
| SSDEEP | `196608:N4qfRgeCageCggeCdgeCEgeCSgeCOgeC6geCcgeCHgeCm:/fVVT2HRJ5zwp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `rar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_ffa5c396
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffa5c396a37ef0dbabf541cecc4e1bda84675eace39d2a8d2ccf355f08a9ca80"
    family = "unknown"
    file_name = "oxmaul.rar"
    file_type = "rar"
    first_seen = "2026-07-27 21:27:22"
  condition:
    hash.sha256(0, filesize) == "ffa5c396a37ef0dbabf541cecc4e1bda84675eace39d2a8d2ccf355f08a9ca80"
}
```

### Sample 38: `3fe19e12a6c3054c`

| Field | Value |
|---|---|
| SHA-256 | `3fe19e12a6c3054ca089010c5da14867a4e7ccbd72560dcbe8cdc99f44e36f48` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 21:16:51` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5236d7bb0342a14ab7eb986c6689d2b` |
| SHA-1 | `0f00fe36e2a6cbc7dc9fb11ea8e13e1a9e853534` |
| SHA-256 | `3fe19e12a6c3054ca089010c5da14867a4e7ccbd72560dcbe8cdc99f44e36f48` |
| SHA3-384 | `c3dfdd43f581eecb3ce524a7411eee14e05743b09a001a78eecc95806a675f48964e64f25465ef64f0044171573ba48c` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T1C7823B0FB8424316E1E110B4966696BFD9B9AC7633C414EBF7D44AEE1A686C1FC3210F` |
| SSDEEP | `384:AdZbmcmhzwEUaUu94gXTP+av8U9c+L4P:F5UaF9Ka0U12` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_3fe19e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fe19e12a6c3054ca089010c5da14867a4e7ccbd72560dcbe8cdc99f44e36f48"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 21:16:51"
  condition:
    hash.sha256(0, filesize) == "3fe19e12a6c3054ca089010c5da14867a4e7ccbd72560dcbe8cdc99f44e36f48"
}
```

### Sample 39: `ef876baf02db22ca`

| Field | Value |
|---|---|
| SHA-256 | `ef876baf02db22ca0d03a888226bea7728b508e39e75f84dc894ec900b296fae` |
| Family label | `NanoCore` |
| File name | `510950FF5CB5D12C8A9D4A71D2A88D2E.exe` |
| File type | `exe` |
| First seen | `2026-07-27 21:15:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `510950ff5cb5d12c8a9d4a71d2a88d2e` |
| SHA-1 | `54d65545279a44223699a0c9731fd21b1d82b7e5` |
| SHA-256 | `ef876baf02db22ca0d03a888226bea7728b508e39e75f84dc894ec900b296fae` |
| SHA3-384 | `669e560c86f528ee2820763d50045a74b3addfc3bd568464100c42588948fbcaffa62df73d5b2051af679ee8204498d7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13A14CF267BB8492FE2DF86B9612251528379C2E3A8C3F3DE28D455B74F127E40A071D7` |
| SSDEEP | `6144:wLV6Bta6dtJmakIM51q+HjVCuSj2OjrtJrIOXv:wLV6Btpmk8q+DVcH8o` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_039_ef876baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef876baf02db22ca0d03a888226bea7728b508e39e75f84dc894ec900b296fae"
    family = "NanoCore"
    file_name = "510950FF5CB5D12C8A9D4A71D2A88D2E.exe"
    file_type = "exe"
    first_seen = "2026-07-27 21:15:05"
  condition:
    hash.sha256(0, filesize) == "ef876baf02db22ca0d03a888226bea7728b508e39e75f84dc894ec900b296fae"
}
```

### Sample 40: `4ddf530a9ced8cb0`

| Field | Value |
|---|---|
| SHA-256 | `4ddf530a9ced8cb042c88e3fdd75933a08cd1419a1f3bbd7a3e6b8f3e6b6260d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 21:08:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b033d3a4db05e99ae970ffe77f0a55b` |
| SHA-1 | `b06b43205f0102eb735da12a3198a10dbdd0af5d` |
| SHA-256 | `4ddf530a9ced8cb042c88e3fdd75933a08cd1419a1f3bbd7a3e6b8f3e6b6260d` |
| SHA3-384 | `c781b1986d3a3e2217d018fd1b4e59776d5a2c788e4a024ce76095ef7d36f3c99a1c0bfa7f2c72636ecff3e59a6e853e` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T12E823B0FB8424316E1E110B4967596BBD9B9AC7637C414EBFBD44AEE0A686C1FC3210F` |
| SSDEEP | `384:A0ZbmcmhzwEUaUu94gXTP+av8U9c+F4P:w5UaF9Ka0U1o` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_4ddf530a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ddf530a9ced8cb042c88e3fdd75933a08cd1419a1f3bbd7a3e6b8f3e6b6260d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 21:08:45"
  condition:
    hash.sha256(0, filesize) == "4ddf530a9ced8cb042c88e3fdd75933a08cd1419a1f3bbd7a3e6b8f3e6b6260d"
}
```

### Sample 41: `bf1dde0ee67946f8`

| Field | Value |
|---|---|
| SHA-256 | `bf1dde0ee67946f8ec76c64b6eb4252040ad4ffb097cdc9528c844de923a1dad` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 20:56:28` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7dfab6d94576579e466f5bc7ace0019b` |
| SHA-1 | `d978cb046c6ca900c621f6d4adc9f9d32c8a2307` |
| SHA-256 | `bf1dde0ee67946f8ec76c64b6eb4252040ad4ffb097cdc9528c844de923a1dad` |
| SHA3-384 | `3eba4a7531310212be6ba8476cd30eadb67e22f5f3b43b26c05ff2ce5ec00ebe6ec79446ee4cc0b7063d526a32f977da` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T1E4822A0FB9424316E1E110B4966596BBD9B9AC7633C414EBF7D44AEE1A686C1FC3210F` |
| SSDEEP | `384:A3ZbmcmhzcEUaUu94gXTP+av8U9c+w4P:D9UaF9Ka0U1z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_bf1dde0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf1dde0ee67946f8ec76c64b6eb4252040ad4ffb097cdc9528c844de923a1dad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:56:28"
  condition:
    hash.sha256(0, filesize) == "bf1dde0ee67946f8ec76c64b6eb4252040ad4ffb097cdc9528c844de923a1dad"
}
```

### Sample 42: `41d4cb022a1e382d`

| Field | Value |
|---|---|
| SHA-256 | `41d4cb022a1e382d26b6361562d75d4d8a03150a8d089c3dccae6b4b6c1061e3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 20:48:40` |
| Reporter | `Bitsight` |
| Tags | `B, BB2.file, dropped-by-GCleaner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ed39d4187f83ab46780543e7cb9b964` |
| SHA-1 | `af69d56bbbefdc9b46b34178e9ee9a09689a9693` |
| SHA-256 | `41d4cb022a1e382d26b6361562d75d4d8a03150a8d089c3dccae6b4b6c1061e3` |
| SHA3-384 | `a238eb5dad35ecebbea63d5fa7d1885e97db7dca35f0838feb4365c67f9a0866cac15706a4f778e62950da15183739bc` |
| IMPHASH | `3a19e190a452ebfefeb6537a827838a9` |
| TLSH | `T12C469EA9A6BC00D9E86AC1BCC2865227E772B41553B057CF5A648AF60F63BD01F7F740` |
| SSDEEP | `49152:4VwASOuGtlqgXPSI3YAicNzYekvruCGxU0SOGRnUYGhLCRKCiNHABrFb1kFnpCR7:63vN0sxzKZPBUCRut3et0ceswz+ndaW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_41d4cb02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41d4cb022a1e382d26b6361562d75d4d8a03150a8d089c3dccae6b4b6c1061e3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:48:40"
  condition:
    hash.sha256(0, filesize) == "41d4cb022a1e382d26b6361562d75d4d8a03150a8d089c3dccae6b4b6c1061e3"
}
```

### Sample 43: `6a12f1b9d531003b`

| Field | Value |
|---|---|
| SHA-256 | `6a12f1b9d531003b507b251a6fbbd9fc8c3673bb386852749c161730fbc312d9` |
| Family label | `NetSupport` |
| File name | `4124a167cef576ccae119247431709f6.exe` |
| File type | `exe` |
| First seen | `2026-07-27 20:45:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NetSupport` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4124a167cef576ccae119247431709f6` |
| SHA-1 | `b77d5d846a70f979b1b4d5761bb4967f037ea841` |
| SHA-256 | `6a12f1b9d531003b507b251a6fbbd9fc8c3673bb386852749c161730fbc312d9` |
| SHA3-384 | `0ee7aa7da3a22c74ad92d6f227dc54e0379dfa4aa2e5cb7f64f8fe904d97455f82db3487e9db9c58313bc9c8cb7a7b3c` |
| IMPHASH | `8dad295e2b72b58be214193a8206d67d` |
| TLSH | `T172462983591F5B56F1EF803DB9BB73656814E18B22D386B460727B726C8A304BE4F913` |
| SSDEEP | `98304:WMsv2n6Wf9XrEjqHNqYLAvoPkz+vr6wss0CiiNklEM9n:WMe2n6WZdNRAVz+vr6wC9` |
| ICON-DHASH | `d4d4cccce8e871b2` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_043_6a12f1b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a12f1b9d531003b507b251a6fbbd9fc8c3673bb386852749c161730fbc312d9"
    family = "NetSupport"
    file_name = "4124a167cef576ccae119247431709f6.exe"
    file_type = "exe"
    first_seen = "2026-07-27 20:45:06"
  condition:
    hash.sha256(0, filesize) == "6a12f1b9d531003b507b251a6fbbd9fc8c3673bb386852749c161730fbc312d9"
}
```

### Sample 44: `7366ce5e9a87b137`

| Field | Value |
|---|---|
| SHA-256 | `7366ce5e9a87b1371152bfb689a0b55a04de7e4f2a718e7d5f43e3c02e32381f` |
| Family label | `AgentTesla` |
| File name | `New order Aug2026.JS` |
| File type | `js` |
| First seen | `2026-07-27 20:44:11` |
| Reporter | `James_inthe_box` |
| Tags | `AgentTesla, exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43926adc184af67b9fdb2f047cec7fcf` |
| SHA-1 | `156930254156a7af0f54f4b537d2aedf29d33966` |
| SHA-256 | `7366ce5e9a87b1371152bfb689a0b55a04de7e4f2a718e7d5f43e3c02e32381f` |
| SHA3-384 | `0dedb040e9e420009a24816534734da362572a774e022b10481681d17a49c0986bf6a56438e61f79ec17f3c4e848e822` |
| TLSH | `T1E3F54A089118FBD7909CA32ACC5DBFED8F0E80536E24DB84356D89B9954DFA973103A7` |
| SSDEEP | `98304:ehWFG6EIiRtvTGXO5bLb9/LujXSNaHpnbhjQLDTyd25+ybomx8fkPo8CvUJzfspM:ehWF7ErtxbcFVh0H8rk9M74M0` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_044_7366ce5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7366ce5e9a87b1371152bfb689a0b55a04de7e4f2a718e7d5f43e3c02e32381f"
    family = "AgentTesla"
    file_name = "New order Aug2026.JS"
    file_type = "js"
    first_seen = "2026-07-27 20:44:11"
  condition:
    hash.sha256(0, filesize) == "7366ce5e9a87b1371152bfb689a0b55a04de7e4f2a718e7d5f43e3c02e32381f"
}
```

### Sample 45: `405904c8a9ec04b7`

| Field | Value |
|---|---|
| SHA-256 | `405904c8a9ec04b73ac95b7e43a4c9c567b526d178257b56e4a8d812f478ddc3` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 20:28:31` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00dee4b7bc493f6c89e9e5dc9467f892` |
| SHA-1 | `449e042db9b793c224bb1fbdf024e3ba8adde226` |
| SHA-256 | `405904c8a9ec04b73ac95b7e43a4c9c567b526d178257b56e4a8d812f478ddc3` |
| SHA3-384 | `7d5439868670c043ca2ddd962318aa0b18ef935695ba8f36d55ae176f049eb3ce076da15f99132385c60f81b784ef983` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T15B823B0FB8424316E1E110B4967596BBD9B9AC7637C414EBFBD44AEE0A686C1FC3210F` |
| SSDEEP | `384:ApZbmcmhzwEUaUu94gXTP+av8U9c+F4P:x5UaF9Ka0U1o` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_045_405904c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "405904c8a9ec04b73ac95b7e43a4c9c567b526d178257b56e4a8d812f478ddc3"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:28:31"
  condition:
    hash.sha256(0, filesize) == "405904c8a9ec04b73ac95b7e43a4c9c567b526d178257b56e4a8d812f478ddc3"
}
```

### Sample 46: `b37a2cf2e2f75f6c`

| Field | Value |
|---|---|
| SHA-256 | `b37a2cf2e2f75f6cf0afd27aa05c627fa9d814e6babb603e8fec4b09b32b4079` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 20:25:25` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6aefb197539613b95d2f7de957307aa` |
| SHA-1 | `97bfb5e496346dfcc03cd84c0b81f9b2349b6ebd` |
| SHA-256 | `b37a2cf2e2f75f6cf0afd27aa05c627fa9d814e6babb603e8fec4b09b32b4079` |
| SHA3-384 | `5b70522f055451f8c0260ffa561d6191bef9716eb11803f191e6b834c7f1717bbdca723b7b9578e8a30f737753262496` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T19A822A0FB8424216E1D110B4967596BFD9B99C7633C418EBFBD44AEE0A686C1FC3250F` |
| SSDEEP | `192:AWk6SkQzngjoWLsmBDTlIUqRQsPcleSMv9fKUSiu9zwfge+VOgbOOqmEd6FQv9P0:ADZbmsmBTsU0Vu94gXTPuav8U9c+W4P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_b37a2cf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b37a2cf2e2f75f6cf0afd27aa05c627fa9d814e6babb603e8fec4b09b32b4079"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:25:25"
  condition:
    hash.sha256(0, filesize) == "b37a2cf2e2f75f6cf0afd27aa05c627fa9d814e6babb603e8fec4b09b32b4079"
}
```

### Sample 47: `c21a12edd5493e0e`

| Field | Value |
|---|---|
| SHA-256 | `c21a12edd5493e0e0c762a0c7ac7ce1ebbcbffed11fc27714e88b0843908e994` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-07-27 20:06:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3ad513ac5096bf3d13271707cd7cf77` |
| SHA-1 | `fc6dea26cfe7ed304840aba9fa5df4156700f55e` |
| SHA-256 | `c21a12edd5493e0e0c762a0c7ac7ce1ebbcbffed11fc27714e88b0843908e994` |
| SHA3-384 | `0fde89380155a59a8786eec6066dcec0855d36fb45c7c6621137f82dbe40e89263234fec269725ea3fae7f5feac70f36` |
| TLSH | `T1EA534B8CE383E4F6EC1B0670101BF77EAA756D222028DD67EBD8B663AD32752911751C` |
| TELFHASH | `t13221f6bb1de618e8b7d0a504c31f77a05d3cd9371a50ba934673a22133d2e91a279d39` |
| SSDEEP | `768:Zuig7OrllKLCz3M5UyNkL3REk06Dxu2bWX7lrL07uZSV8n5O87VRpdP8PqayRB0W:Z87OrPK2z3KCLhLlhqDZSE/R7uqaE+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_c21a12ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c21a12edd5493e0e0c762a0c7ac7ce1ebbcbffed11fc27714e88b0843908e994"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-07-27 20:06:40"
  condition:
    hash.sha256(0, filesize) == "c21a12edd5493e0e0c762a0c7ac7ce1ebbcbffed11fc27714e88b0843908e994"
}
```

### Sample 48: `ed35e07d9a91e36e`

| Field | Value |
|---|---|
| SHA-256 | `ed35e07d9a91e36eb996e234a7f7fce0243b206976ba5c67d05ea6a05c07233f` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-07-27 20:06:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834519ce4f2951f189bf9b331af42d2b` |
| SHA-1 | `37bb516679a2818cc79eb7254bc3a6e6f6aa0935` |
| SHA-256 | `ed35e07d9a91e36eb996e234a7f7fce0243b206976ba5c67d05ea6a05c07233f` |
| SHA3-384 | `19376ef6be1bf85a6ab468dceb04d1e5059e3ca1d7ba482bac373bb5dfc002b4bf211f871b5a8c7606cb4c36fbde1e48` |
| TLSH | `T15DE2E107A5135D09C4BB32F279DE760044158398F38E9EA6EDE4197FF572F12092C76A` |
| SSDEEP | `768:B0Mdl5ORifs2jdOdH9flj1FcN01Mhm+KXEwqZOOnbcuyD7U4/2q:SMdSif56H95DcN0ehJ4EZZTnouy8Pq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_ed35e07d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed35e07d9a91e36eb996e234a7f7fce0243b206976ba5c67d05ea6a05c07233f"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-07-27 20:06:05"
  condition:
    hash.sha256(0, filesize) == "ed35e07d9a91e36eb996e234a7f7fce0243b206976ba5c67d05ea6a05c07233f"
}
```

### Sample 49: `15d34471d464ff57`

| Field | Value |
|---|---|
| SHA-256 | `15d34471d464ff576aa1c6fdbed6821c3b38f811916770a7db2422c5a90d01c8` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 19:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9a514140e2d08a4fde3a8c866d700e4` |
| SHA-1 | `206037c84dba718a3149c081249eb7238ad711dc` |
| SHA-256 | `15d34471d464ff576aa1c6fdbed6821c3b38f811916770a7db2422c5a90d01c8` |
| SHA3-384 | `1629f3efd84bb770846b276a663713339d4bb28d235cd5f9310ea34e6432dca08297308f1e2969650da60da4e5cb2dc6` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T168E633586FD502EFE973503CAAA15228F95478A213B2CEDB0794D7A1EC131E08D3DB67` |
| SSDEEP | `393216:10jioovGyZjksWScEXMCHWUjX0cuI3/PGTAI:1RvjZj3WScEXMb8XhH/O7` |
| ICON-DHASH | `d0f0d4d8c8e47030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_15d34471
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15d34471d464ff576aa1c6fdbed6821c3b38f811916770a7db2422c5a90d01c8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 19:52:09"
  condition:
    hash.sha256(0, filesize) == "15d34471d464ff576aa1c6fdbed6821c3b38f811916770a7db2422c5a90d01c8"
}
```

### Sample 50: `f10f83559e3c7a4e`

| Field | Value |
|---|---|
| SHA-256 | `f10f83559e3c7a4e53b023c1ef06bc0fa91e06e48947e1360653d129daf64460` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `786084c225d0e808960b1dd7e35dd9cf` |
| SHA-1 | `7ad67ef91f8b9ee9fa8ac9db113333175b2a94e4` |
| SHA-256 | `f10f83559e3c7a4e53b023c1ef06bc0fa91e06e48947e1360653d129daf64460` |
| SHA3-384 | `eafc33716b1a8e0ccea201d07c541fd180201577251e00c90da2db26a1af8658d31f07047e098e9d5e0876d0d5de8228` |
| TLSH | `T1EC535BC5AA47D8F6FD5602711173E7378632F13A1129DA87C7A9ED32BC52900EA1739C` |
| TELFHASH | `t11f31b0fa6dee09fcb3d4a808c75a6fd31a7ae177156139b044b5585027f388081b5c3a` |
| SSDEEP | `1536:ahZerRy3lVDKvfb9IZG4R9bdx6mQSd++CMq32UFSTGhk15uJnaroXy:ahqo3lVDKbd4b7d+zf2UMT2M5X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_f10f8355
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f10f83559e3c7a4e53b023c1ef06bc0fa91e06e48947e1360653d129daf64460"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:51"
  condition:
    hash.sha256(0, filesize) == "f10f83559e3c7a4e53b023c1ef06bc0fa91e06e48947e1360653d129daf64460"
}
```

### Sample 51: `4605e809be293537`

| Field | Value |
|---|---|
| SHA-256 | `4605e809be293537ef4f2aeb8f181ebd840b450dccc69507ea918a3918a6cd42` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ffe833afb86e0a705539d8f1a7ee9c5` |
| SHA-1 | `50ae25e7862660f28ca787e5f9ed3e5f17daade1` |
| SHA-256 | `4605e809be293537ef4f2aeb8f181ebd840b450dccc69507ea918a3918a6cd42` |
| SHA3-384 | `6cc710d95b1ee4559e1c76a4adba4184d8f20e51390970d5622eec58c9b84ca4f9979cf1ed12014aec5b24dffbdb1f4a` |
| TLSH | `T10CE32B46E7814B13C0D6177ABADF42453323A764D3EB73059928AFB43F8679E0E63606` |
| TELFHASH | `t1f031fd325721411aae52cc60dcee57f1251d86272744ee33ef3ac8cc651a49ae62bc8f` |
| SSDEEP | `3072:U+UgFG8B0UMai0U456g/2lHhXRHM9h/P+keLUM/9gSh6VF:U+UL8BLMai0U456llJRs9lP+ZgM/9JMT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_4605e809
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4605e809be293537ef4f2aeb8f181ebd840b450dccc69507ea918a3918a6cd42"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:47"
  condition:
    hash.sha256(0, filesize) == "4605e809be293537ef4f2aeb8f181ebd840b450dccc69507ea918a3918a6cd42"
}
```

### Sample 52: `bcdfae513af1faf8`

| Field | Value |
|---|---|
| SHA-256 | `bcdfae513af1faf835e824dc17e5477980da3973a429f3d6976f3c315561293d` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49d464ea3cda0476bd57a5f2adee763c` |
| SHA-1 | `fadaf1e8eb41afefbb973830b288b51c68cb9540` |
| SHA-256 | `bcdfae513af1faf835e824dc17e5477980da3973a429f3d6976f3c315561293d` |
| SHA3-384 | `b0b57ec506470c3c6cd5c52867dca1dc9e884cbff405a3d5c6b9c99bffae35249c5ee805090c6087704ccfad5f428136` |
| TLSH | `T1D8634B02B31C0D47D16359B02A3F27E183BFA99121F4FA89651EDB869276E371186FCD` |
| SSDEEP | `1536:1qJmBD+STCTNsLIw8TxLQj6an5WLeIEy54dKJclT4s/GnsD:EgeRsLwpnLeIX5ZRsD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_bcdfae51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcdfae513af1faf835e824dc17e5477980da3973a429f3d6976f3c315561293d"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:37"
  condition:
    hash.sha256(0, filesize) == "bcdfae513af1faf835e824dc17e5477980da3973a429f3d6976f3c315561293d"
}
```

### Sample 53: `969893508d09084e`

| Field | Value |
|---|---|
| SHA-256 | `969893508d09084e3f66faaa21e98a4bf533b2eb6f92403f06ba0d8243f3d6d1` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7aa4eb9921cf68868726f2da36c9b4ca` |
| SHA-1 | `985692a91aaf08a47e978a0aaef0d8e7e7595cc2` |
| SHA-256 | `969893508d09084e3f66faaa21e98a4bf533b2eb6f92403f06ba0d8243f3d6d1` |
| SHA3-384 | `85e642d6d690a4b0774712441d0211cd8857fd8aadb0a95b9da745c2e759a4f25bbeda8d3334be9fc261db6b0da6fefc` |
| TLSH | `T172A3C91E6E218FBDF369C33047B78E21A79837D626E1D685E26CD6011E6034E641FFA4` |
| TELFHASH | `t173217f5c4d7412e48b321d9e2baeff76e19030de0b326d378e11aaadba6d9425d00c1c` |
| SSDEEP | `1536:yk8NZJjWAanPscve4meOeuCyTPHvwIp/read7Q1Qs/Qd/uP:WZJjBanEzhHvlp/o1c/c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_96989350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "969893508d09084e3f66faaa21e98a4bf533b2eb6f92403f06ba0d8243f3d6d1"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:27"
  condition:
    hash.sha256(0, filesize) == "969893508d09084e3f66faaa21e98a4bf533b2eb6f92403f06ba0d8243f3d6d1"
}
```

### Sample 54: `0f4755d46a150c16`

| Field | Value |
|---|---|
| SHA-256 | `0f4755d46a150c16e9af5ba03b6b680d05aad08a7eeccba7239ead83c8f1e755` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c171448782757da1d1c78f8bf070dffa` |
| SHA-1 | `c6e8032185c1f66b157b043cc1a839cdc7de506d` |
| SHA-256 | `0f4755d46a150c16e9af5ba03b6b680d05aad08a7eeccba7239ead83c8f1e755` |
| SHA3-384 | `b4933f4a3f6bec37612d001e9e689dc7ba99382ab9ccb8424e834a297ebcef038f16fb053674027adf3b67a3bcd6650a` |
| TLSH | `T15E732A91BD815713C6D012BBFB5E028E372A53A8D2EE72179D226F2137C786B0E77641` |
| TELFHASH | `t1de5113b9cba50aec17e0c744c2c9a13cabea34ac5b00555acb5d3f2b85479c1b01d437` |
| SSDEEP | `1536:M6dz9MTC0XU66Ee9ps93/UYjDRPz+SbHB+UvAs/w4:M6dS6Es0/UYhb+41` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_0f4755d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f4755d46a150c16e9af5ba03b6b680d05aad08a7eeccba7239ead83c8f1e755"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:20"
  condition:
    hash.sha256(0, filesize) == "0f4755d46a150c16e9af5ba03b6b680d05aad08a7eeccba7239ead83c8f1e755"
}
```

### Sample 55: `cd53aed245ab9867`

| Field | Value |
|---|---|
| SHA-256 | `cd53aed245ab98676bb8647e627677a6d4c5b08e8645b384ca1d6abfdf0586eb` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f38f263e2bbb77465eeefa7b93621e5d` |
| SHA-1 | `cf0b4bac42733f31aa90e0ec43fb496bf696102b` |
| SHA-256 | `cd53aed245ab98676bb8647e627677a6d4c5b08e8645b384ca1d6abfdf0586eb` |
| SHA3-384 | `0a2ee94950525c1c438d8ac748dfef0dcc042f61f6369fab394ca1e996cad4f2280b62ae803408d5a439bc3159b1e237` |
| TLSH | `T14AA3E506BB650FF7DC6FCD3706A9070225CCA51B22B93B367674C928B50B65B4AE3874` |
| SSDEEP | `1536:LvGefaZSdtug4/xl4ExO29zyN0ZNhdZp54crFCZeLs/g5J:LOefaZSds59zm0Hr6etJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_cd53aed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd53aed245ab98676bb8647e627677a6d4c5b08e8645b384ca1d6abfdf0586eb"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:13"
  condition:
    hash.sha256(0, filesize) == "cd53aed245ab98676bb8647e627677a6d4c5b08e8645b384ca1d6abfdf0586eb"
}
```

### Sample 56: `53385d7dc9bf143d`

| Field | Value |
|---|---|
| SHA-256 | `53385d7dc9bf143d4fc2e5e5fc0ee63695dab54b1d5457bd6a2fbd2c611c5b17` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-07-27 19:37:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3db5e9c447d5b6e6e9d8fb9adbca8f40` |
| SHA-1 | `6e10c3600ade9892dc2e4da38b4e3cfcbad64ab1` |
| SHA-256 | `53385d7dc9bf143d4fc2e5e5fc0ee63695dab54b1d5457bd6a2fbd2c611c5b17` |
| SHA3-384 | `fc8afdaea97d5d89ac0a053d5c7a44dcf5eaed9ac670ec603f7d5f153861ff303bab5a846166708a3eebf37b1b2bfcfc` |
| TLSH | `T1E7831895B8814B12C5D512BAFE1E118E3323177CE3DE73129D206F24778B96B0E7BA16` |
| TELFHASH | `t18e11dc143ec84fcd92f08e18c3dfa12a39053ab2da73393e8a97a62f43135d2201541e` |
| SSDEEP | `1536:yjna/CzPC7fSnznv1sUrfar1FtQtMMiE+cG3if737meY52Y0s/wm:7wP0UvCUrfarY+cG3if73ieYwQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_53385d7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53385d7dc9bf143d4fc2e5e5fc0ee63695dab54b1d5457bd6a2fbd2c611c5b17"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:05"
  condition:
    hash.sha256(0, filesize) == "53385d7dc9bf143d4fc2e5e5fc0ee63695dab54b1d5457bd6a2fbd2c611c5b17"
}
```

### Sample 57: `2424f532db6b5f4d`

| Field | Value |
|---|---|
| SHA-256 | `2424f532db6b5f4dac152f0e6d28bbb93f3ffdb2a6f88902d1d00dfe7b1fd1f9` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `028aec3eacd25d4160f8506f948b36bf` |
| SHA-1 | `42f38c79695dc3514893a4d6e18f84318c1614c2` |
| SHA-256 | `2424f532db6b5f4dac152f0e6d28bbb93f3ffdb2a6f88902d1d00dfe7b1fd1f9` |
| SHA3-384 | `573569e4c945e72490ab966c2f885de4dfaee3e9abc2930258cfe5446b17f64faa94393937a2c419d3113fa6e8203336` |
| TLSH | `T145631991BD815B23C6D0227BFB5E428E372653A8D2EE72079D226F2137C785B0E77641` |
| TELFHASH | `t1b04140a457940bdd5fd4c755928f613ab8de38f9af10399a8e2e7b0f81435c2b118433` |
| SSDEEP | `1536:zGJ0nw+8oipadYTzCXCEkSHv0hyaRVTdC4s/wk:zGJl6dIMlkS8kaXe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_2424f532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2424f532db6b5f4dac152f0e6d28bbb93f3ffdb2a6f88902d1d00dfe7b1fd1f9"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:58"
  condition:
    hash.sha256(0, filesize) == "2424f532db6b5f4dac152f0e6d28bbb93f3ffdb2a6f88902d1d00dfe7b1fd1f9"
}
```

### Sample 58: `ad4185bf0e84f884`

| Field | Value |
|---|---|
| SHA-256 | `ad4185bf0e84f884457992cae139eee59120c3429839c8b8306f00c5401e869e` |
| Family label | `Mirai` |
| File name | `px86` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02279a2c42f051240de3be9f3cb009dc` |
| SHA-1 | `cb5b38f688b8e19c32ebfbfccaf49171ceda1f28` |
| SHA-256 | `ad4185bf0e84f884457992cae139eee59120c3429839c8b8306f00c5401e869e` |
| SHA3-384 | `4a803517dfd8f14f7f0bef2aa698b18122ed50719e13584ae7fa136e69dce9360f4f4f7662a57da1bcf4136ae616225a` |
| TLSH | `T13CE2F25E50DCE42CE55E803BC32BA98E21E3AD107F1BC96425C979DBCE541B520BAC37` |
| SSDEEP | `768:+32bRAqg2pQz8PMjFY8AFOEPB6ZSq7xni5Ga0F:NbRAp2p4uCF+FvB6ZSoniRy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_ad4185bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad4185bf0e84f884457992cae139eee59120c3429839c8b8306f00c5401e869e"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:14"
  condition:
    hash.sha256(0, filesize) == "ad4185bf0e84f884457992cae139eee59120c3429839c8b8306f00c5401e869e"
}
```

### Sample 59: `85f1f91bb75a6cc1`

| Field | Value |
|---|---|
| SHA-256 | `85f1f91bb75a6cc10d59e3896c3735854c0b28e7435bc7ea50d7833638e38b0b` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daf8a36252d90f286226d717bb5d9e52` |
| SHA-1 | `ed543e0cf97ff1bc500bebde653f50fcfaece1cc` |
| SHA-256 | `85f1f91bb75a6cc10d59e3896c3735854c0b28e7435bc7ea50d7833638e38b0b` |
| SHA3-384 | `61c9fbe94e8d263955c304ef25a9c043fe0a56e54481557428db881c3a244aca65a85e337b39dc01b2ca144e8e9daf71` |
| TLSH | `T1FE430154B70F66284D128532E171AFDAFBDB5FBED0F95083277A333467C980117A4A86` |
| SSDEEP | `1536:zbIZGdFRlG+lh5wKHwtMJQLLy6tlW46Cm:4ZGHRlG+lPwKQuQLW6tl2D` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_85f1f91b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85f1f91bb75a6cc10d59e3896c3735854c0b28e7435bc7ea50d7833638e38b0b"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:13"
  condition:
    hash.sha256(0, filesize) == "85f1f91bb75a6cc10d59e3896c3735854c0b28e7435bc7ea50d7833638e38b0b"
}
```

### Sample 60: `8f23e53b49b98d2f`

| Field | Value |
|---|---|
| SHA-256 | `8f23e53b49b98d2f96a940271ff252f57e5b991e49f2a6d8b44c4e2f9f6f0486` |
| Family label | `Mirai` |
| File name | `psh4` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `321559c9d66c92dc95dac75ce9843cae` |
| SHA-1 | `8084f27e5333831646cf9b28c7784cd2be7e1721` |
| SHA-256 | `8f23e53b49b98d2f96a940271ff252f57e5b991e49f2a6d8b44c4e2f9f6f0486` |
| SHA3-384 | `7d7e8c9934101efb6af68339d28bed88d53db4c208c365e75d5d506c76752f414861dd129e328d1a9f8d8fab3fbf1cbb` |
| TLSH | `T1FD538B73C9296E14C19582B4B871CB781F63A48482471FFA5BD9C2BA9447EFCF6093B4` |
| SSDEEP | `1536:da/wtqWcoWl0FZWXaZMYfbIYv+/1K2GP94iCaPC00bzyIls/Gz:dsmcoWl0TWXaZMYDIYG/c2GtCaPY/DX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_8f23e53b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f23e53b49b98d2f96a940271ff252f57e5b991e49f2a6d8b44c4e2f9f6f0486"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:11"
  condition:
    hash.sha256(0, filesize) == "8f23e53b49b98d2f96a940271ff252f57e5b991e49f2a6d8b44c4e2f9f6f0486"
}
```

### Sample 61: `bf7d5c7b3fdddb0e`

| Field | Value |
|---|---|
| SHA-256 | `bf7d5c7b3fdddb0e47cae68fd1c62eccdbc0f79cd3a721ad94f8bc3b814f7983` |
| Family label | `Mirai` |
| File name | `pspc` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea8b7c0d882457972abc0a36300567ac` |
| SHA-1 | `607274016bcb327548d78a19d896019bdb5e0b23` |
| SHA-256 | `bf7d5c7b3fdddb0e47cae68fd1c62eccdbc0f79cd3a721ad94f8bc3b814f7983` |
| SHA3-384 | `876b08ca9f13f4e85f7055f647b4d86595c21a33b7e0b4178a109f6655e1aa78e44ca8db11cb708f73ac970b0ff42278` |
| TLSH | `T10B735C32B9751D2BC4D0A87A61F30325F2F2478A25ACCA1A7D720D8EBF6565032477F9` |
| SSDEEP | `1536:jP+SbCGR18pspTH1aDQ2tXXUN95s0xwlWptCMR8/cW:zf4yVkpENP1x6MJW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_bf7d5c7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf7d5c7b3fdddb0e47cae68fd1c62eccdbc0f79cd3a721ad94f8bc3b814f7983"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:10"
  condition:
    hash.sha256(0, filesize) == "bf7d5c7b3fdddb0e47cae68fd1c62eccdbc0f79cd3a721ad94f8bc3b814f7983"
}
```

### Sample 62: `d6a82668a5b9f9aa`

| Field | Value |
|---|---|
| SHA-256 | `d6a82668a5b9f9aacfbd2fab7b7d586a959639c80c55a2fa6d7e6a1d62be43c3` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08aee2b179ead9e28e96f7845d1a2636` |
| SHA-1 | `ec4137788b142a162065fa46493a7c02424f8e12` |
| SHA-256 | `d6a82668a5b9f9aacfbd2fab7b7d586a959639c80c55a2fa6d7e6a1d62be43c3` |
| SHA3-384 | `19a2a5e3d9368ed9c69924311eb030a4600ca3f5a4308bc1b7701e88f2a4fc6f128ff41777a8881c47c8898c9b7f9813` |
| TLSH | `T1A2F2E0F1C02C59BADBF658B69996C3507B7A458A67B4AFF02087DF220854427F9C9FC0` |
| SSDEEP | `768:pjVmE5tNa0FKdZX8XVvIpZTw6jiGK2q4uVcqgw09O:pKdB8XpmZTwka2q4u+qgw09O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_d6a82668
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6a82668a5b9f9aacfbd2fab7b7d586a959639c80c55a2fa6d7e6a1d62be43c3"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:09"
  condition:
    hash.sha256(0, filesize) == "d6a82668a5b9f9aacfbd2fab7b7d586a959639c80c55a2fa6d7e6a1d62be43c3"
}
```

### Sample 63: `ebfe929a1285bc3a`

| Field | Value |
|---|---|
| SHA-256 | `ebfe929a1285bc3a48b466b6767be1cf1242f66b9ab4a916e197f26ebc346332` |
| Family label | `Mirai` |
| File name | `pm68k` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06f42c4798f736d80f1590f05cc66a1a` |
| SHA-1 | `4d6a6307df8302cca426099c6f4460e4fc130802` |
| SHA-256 | `ebfe929a1285bc3a48b466b6767be1cf1242f66b9ab4a916e197f26ebc346332` |
| SHA3-384 | `7c508a3d5ed55f39ef921b8a63cd6a2600703e81ee991c9ec8dfa703cd3b1ec28fd19a80431cdd8b0b7cd3575c4dd394` |
| TLSH | `T1A6832997F400DDBDF80ED77B4463490AB230A3A105830F36A79BB967ED721A45966EC2` |
| SSDEEP | `1536:6+KGZvtQA2unEQaqxSo2r/X2ZN4r8FXultko/smObZJvHoVQiacnqvfXS5/:6JG1FnEQaqxSoI/X2ZaSgts7bzYacnuy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_ebfe929a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebfe929a1285bc3a48b466b6767be1cf1242f66b9ab4a916e197f26ebc346332"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:07"
  condition:
    hash.sha256(0, filesize) == "ebfe929a1285bc3a48b466b6767be1cf1242f66b9ab4a916e197f26ebc346332"
}
```

### Sample 64: `c07dd050aea476f9`

| Field | Value |
|---|---|
| SHA-256 | `c07dd050aea476f9d7671b9fa8ef23ffb8e811f2fbc1b7ded93a5156eab37cfe` |
| Family label | `Mirai` |
| File name | `pmips` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85ffbb4dc7fa792edf3d277692034811` |
| SHA-1 | `1fa39fccc67c7fbcd6a381baf3f80ee9a79dae2a` |
| SHA-256 | `c07dd050aea476f9d7671b9fa8ef23ffb8e811f2fbc1b7ded93a5156eab37cfe` |
| SHA3-384 | `1a111add85c6ccb3a1c98b97f05d0f0415fd18e45a94c341fd3a5947ab446edbe6608299f1b705378712112c97b95c12` |
| TLSH | `T1CDF2E1B6470545CCCC6CB27E6F94039673424B22AA339D1EB449B2F5BE7E56C72823E0` |
| SSDEEP | `768:NNYKyukZoTMKexVh2AggRJcZmNtlJSEFe44jyRe1gM/rJgGlzDpbuR1J3:HYdWlexVhH7RJom1+UygMJVJut` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_c07dd050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07dd050aea476f9d7671b9fa8ef23ffb8e811f2fbc1b7ded93a5156eab37cfe"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:06"
  condition:
    hash.sha256(0, filesize) == "c07dd050aea476f9d7671b9fa8ef23ffb8e811f2fbc1b7ded93a5156eab37cfe"
}
```

### Sample 65: `89c6b5a4f46bd7a6`

| Field | Value |
|---|---|
| SHA-256 | `89c6b5a4f46bd7a650bafd35ba97b3bc6c6f062205fdd3768bdec95316465024` |
| Family label | `Mirai` |
| File name | `parm` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb9220c710a42cb825d347377ae2a3ee` |
| SHA-1 | `d0259e5cf9d1b13e6d9d498f655eb082cc2dc07f` |
| SHA-256 | `89c6b5a4f46bd7a650bafd35ba97b3bc6c6f062205fdd3768bdec95316465024` |
| SHA3-384 | `f084ddac1335d044400acee9c25009dcde4bb507206228d17dd8eab353481675eed7fc325dc83de6f3e694ef130dff53` |
| TLSH | `T1BBF2E0614EC9CC3862F5A5B3F17EC7A2335216F4F4E536720430829ED4B65873AA93A7` |
| SSDEEP | `768:bW3+gALZMQUirNcnifwZGeOPd9zogWbDzprs3Uoz8:ITkEianIwuPnzogc0z8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_89c6b5a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89c6b5a4f46bd7a650bafd35ba97b3bc6c6f062205fdd3768bdec95316465024"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:04"
  condition:
    hash.sha256(0, filesize) == "89c6b5a4f46bd7a650bafd35ba97b3bc6c6f062205fdd3768bdec95316465024"
}
```

### Sample 66: `fd730d78cce97617`

| Field | Value |
|---|---|
| SHA-256 | `fd730d78cce9761781424291954d8ec27bef2bb31864574606450c3a4eaa359c` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ece1443541cd12ea380e387d7eae9f6` |
| SHA-1 | `f0dcc30484d81ba12c4745dfc32dec93abcd39f1` |
| SHA-256 | `fd730d78cce9761781424291954d8ec27bef2bb31864574606450c3a4eaa359c` |
| SHA3-384 | `dc7fd6a21b762d13655287df4403c862827661c71d1b29f5c9159d754e0f2f8be2be4391284f0a7427a16b4f714efb46` |
| TLSH | `T12403E1AFA9F497ADC94E5EF5618F1B0286493140268B8B4C73008DD9BEBBB4F71850F5` |
| SSDEEP | `768:MVyIwYjG0JFXIjKUVjz/ouVrma9R7PH/WU:MVyYjXJGmUd/ougaTvJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_fd730d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd730d78cce9761781424291954d8ec27bef2bb31864574606450c3a4eaa359c"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:03"
  condition:
    hash.sha256(0, filesize) == "fd730d78cce9761781424291954d8ec27bef2bb31864574606450c3a4eaa359c"
}
```

### Sample 67: `3fc30b1df7c5fde1`

| Field | Value |
|---|---|
| SHA-256 | `3fc30b1df7c5fde1acb66eed7a784cceddb38c6607843343ead274e0a49d568a` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06a0e7b8052b6f4827101f4fea7f7a72` |
| SHA-1 | `deeb9a3a38b1bfd3e5337581df16a240fe0ecac3` |
| SHA-256 | `3fc30b1df7c5fde1acb66eed7a784cceddb38c6607843343ead274e0a49d568a` |
| SHA3-384 | `456906bb477e50fbd844311666b9f6a6e64e5711a71037a51b13310fc6045625ede78519a42c78f0b6ef4dcebfeccfa9` |
| TLSH | `T1E803E17022459262DB703032C9688D826ED71FFDF0FE2111079646BF9E978A5FD7C892` |
| SSDEEP | `768:DhbUpgfK/AwKhplB651GT8AnRTGS3DIFssAYG0kw7VF6EIlXP49q3UEL4w:DxUpgy4Fhl651u8STGST8AYG0hVF6EmF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_3fc30b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc30b1df7c5fde1acb66eed7a784cceddb38c6607843343ead274e0a49d568a"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:02"
  condition:
    hash.sha256(0, filesize) == "3fc30b1df7c5fde1acb66eed7a784cceddb38c6607843343ead274e0a49d568a"
}
```

### Sample 68: `e61cf04f9405cbb6`

| Field | Value |
|---|---|
| SHA-256 | `e61cf04f9405cbb67cf42963cdedfd0cfe4758f336c74822a1d47ab21c7c8770` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-07-27 19:36:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16ffe2957feed772ef139779389eb8e4` |
| SHA-1 | `8e8004ce786d9eaece399d89d114af3c3e6481d0` |
| SHA-256 | `e61cf04f9405cbb67cf42963cdedfd0cfe4758f336c74822a1d47ab21c7c8770` |
| SHA3-384 | `148a5fe27c49aa5ac714e5806e9bd61be58e0637e1057f177033514f222200c3797807911db386e8b164f0b8d565d17a` |
| TLSH | `T15DE2E11175FA8536D7204A7E8F94D38F99AF6D38917C3277C4488724660CC0AAAB99CB` |
| SSDEEP | `768:yr4LGJKgQQz3i6R38X9pD6QvXQiwlECO9/vpuM8s3UozR:yr4LGJKetR38rPpJFvpu4zR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_e61cf04f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e61cf04f9405cbb67cf42963cdedfd0cfe4758f336c74822a1d47ab21c7c8770"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:00"
  condition:
    hash.sha256(0, filesize) == "e61cf04f9405cbb67cf42963cdedfd0cfe4758f336c74822a1d47ab21c7c8770"
}
```

### Sample 69: `ff616f68ba7dec32`

| Field | Value |
|---|---|
| SHA-256 | `ff616f68ba7dec323309da2efa9e8208bde98716019d0e554ba18251047d809a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-27 19:33:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06348093c7524496786a6b31820e706d` |
| SHA-1 | `dd5fc702a00af336071a2c1c6b800dafc703ff91` |
| SHA-256 | `ff616f68ba7dec323309da2efa9e8208bde98716019d0e554ba18251047d809a` |
| SHA3-384 | `6c0615ff9532fe4940c3265fd445f7827df27e33140ba480ba6c3d3c694ac1630b6d6f5d693bfd3f58c2ba9a5f923adb` |
| TLSH | `T156236C6516857C14AE99C8365D7F2F0CB9AD43E6314492EE7FCE3CF28C4A6AC920871D` |
| SSDEEP | `768:Ur9NyXsZztCT9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:SHusZxcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_ff616f68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff616f68ba7dec323309da2efa9e8208bde98716019d0e554ba18251047d809a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:33:58"
  condition:
    hash.sha256(0, filesize) == "ff616f68ba7dec323309da2efa9e8208bde98716019d0e554ba18251047d809a"
}
```

### Sample 70: `6c0f965a69154c6d`

| Field | Value |
|---|---|
| SHA-256 | `6c0f965a69154c6d1b58082c5483ca6fdb2197720ae4d1bbb99d4f3ba31b795c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-27 19:31:02` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1142cf80e4a58c20a46230025144d22d` |
| SHA-1 | `af7e7e27f2b17aa22221d56e1ba09a6f31c12b51` |
| SHA-256 | `6c0f965a69154c6d1b58082c5483ca6fdb2197720ae4d1bbb99d4f3ba31b795c` |
| SHA3-384 | `14d0e928c39b90dce53d88c09f2ce81c591bc14f96cb3499a1f1640ecd596b416e15798b38bccc7aecb87cb156327019` |
| TLSH | `T169236C6516857C14AE99C4375C7E2F0CB9AD43E6314492EE7FCE3CF28C4A6AD9208B1D` |
| SSDEEP | `768:dR9NyXsZztCL9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:zHusZJcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_6c0f965a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c0f965a69154c6d1b58082c5483ca6fdb2197720ae4d1bbb99d4f3ba31b795c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:31:02"
  condition:
    hash.sha256(0, filesize) == "6c0f965a69154c6d1b58082c5483ca6fdb2197720ae4d1bbb99d4f3ba31b795c"
}
```

### Sample 71: `a94e2c99cd8aaed4`

| Field | Value |
|---|---|
| SHA-256 | `a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 19:25:48` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a19f7ba96dd2609e73e0f5fd0791e4b6` |
| SHA-1 | `c23d60a72c13d435bbfbc428531f89a223024053` |
| SHA-256 | `a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e` |
| SHA3-384 | `b33eacd6aa7a4bc87e3e15c0cb5496abf3b25a15770b08024032a770cebf0bb0068af9c2094bfa743707cb1deb085012` |
| IMPHASH | `5c3286c62c72665c03eacc8a3e846110` |
| TLSH | `T1DC068D17E2A350ECC12BC17D4657A772A530B868C534FE7F5A90DB312E31E50AB6EB24` |
| SSDEEP | `98304:RBJzPZwQwRYTkDTysBKwbCHm8bILHGWCv5IjjPmg9:RvvpYTysBeegv5IjjPmg9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_a94e2c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 19:25:48"
  condition:
    hash.sha256(0, filesize) == "a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e"
}
```

### Sample 72: `5f608a5c28bf9ed0`

| Field | Value |
|---|---|
| SHA-256 | `5f608a5c28bf9ed0f844d755d7140efd584866c0e8aae84ac15021e93b48059c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 19:25:27` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e17f54abf748ebc9edf992c331b5bad` |
| SHA-1 | `e1bf4387221b994db7c94d9571862c231721a8e8` |
| SHA-256 | `5f608a5c28bf9ed0f844d755d7140efd584866c0e8aae84ac15021e93b48059c` |
| SHA3-384 | `54acef35593b7dd173148a9fff0f9156c87214801b5f59d702adfb66c21b8054502831077a32255e5a849cc422c8555b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T101F58C077CE049E5D0AE973188A666957B31BC494B3273D72E50BA383F727D09D3AB48` |
| SSDEEP | `49152:wffgUtk0taRLM/xuWpHZb1hr0+cIqIVajsy72k3kGZPLeXcl:wfoUR7BZb1hr0+cIqIV5y72k3kuPLRl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_5f608a5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f608a5c28bf9ed0f844d755d7140efd584866c0e8aae84ac15021e93b48059c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 19:25:27"
  condition:
    hash.sha256(0, filesize) == "5f608a5c28bf9ed0f844d755d7140efd584866c0e8aae84ac15021e93b48059c"
}
```

### Sample 73: `123fefe00c2bf0e8`

| Field | Value |
|---|---|
| SHA-256 | `123fefe00c2bf0e83f5bf0263ce8b65a8a20214c661d392e03cecc4d7529e5b0` |
| Family label | `unknown` |
| File name | `file.ps1` |
| File type | `ps1` |
| First seen | `2026-07-27 19:20:01` |
| Reporter | `abuse_ch` |
| Tags | `ascii, ClickFix, PowerShell, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d1cb7462992da5a544162d697747f2a` |
| SHA-1 | `1a1537a6b84996ab570d536052ac6d1b51e02353` |
| SHA-256 | `123fefe00c2bf0e83f5bf0263ce8b65a8a20214c661d392e03cecc4d7529e5b0` |
| SHA3-384 | `9dbdbead9c2cb998bc79a22b9235fd4f50a9ebe151ce4afcf78ba7edab9a6c46ff561877d4257c340c116ca2cd991bea` |
| TLSH | `T118622DC7738807BDAB8C9DDD51A450A394F2E0AD3C7322C8E9D59E47B93AD507DA0A34` |
| SSDEEP | `192:oacvCtkPkn9RVghunz5SEeKxyx3DOJEMHC30yJIUNcE51SzyYfBlTmAnbKQTpOPg:oacvukgiBrTfSPKQgPg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_123fefe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "123fefe00c2bf0e83f5bf0263ce8b65a8a20214c661d392e03cecc4d7529e5b0"
    family = "unknown"
    file_name = "file.ps1"
    file_type = "ps1"
    first_seen = "2026-07-27 19:20:01"
  condition:
    hash.sha256(0, filesize) == "123fefe00c2bf0e83f5bf0263ce8b65a8a20214c661d392e03cecc4d7529e5b0"
}
```

### Sample 74: `39cabb912975a2b1`

| Field | Value |
|---|---|
| SHA-256 | `39cabb912975a2b1cda1c50d9b6c62974738e4d66ac6d804fcfb30aa2764240f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-27 19:15:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b0c0a3cd79d1f0dca18e1f75aa5c1cf` |
| SHA-1 | `d30fef99ba4020417db2f36f0ba8ba0c1b2c1a0a` |
| SHA-256 | `39cabb912975a2b1cda1c50d9b6c62974738e4d66ac6d804fcfb30aa2764240f` |
| SHA3-384 | `d566325a69d75bd0be48502419ef8b29bdbd9628f500b2ce0806b63ba74f8dcaef9e29bf2ab37ffa2752da8fd463e40f` |
| TLSH | `T1C4C27C956A867C44BEC94B3E4CBD2B1D6DF5C3D1324952AC3D8A3C719C11FACC618B1A` |
| SSDEEP | `768:98vCB+25j6es8RU9FYpMSUpi+20qUpi+20YQX:98l25Jyd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_39cabb91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cabb912975a2b1cda1c50d9b6c62974738e4d66ac6d804fcfb30aa2764240f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:15:58"
  condition:
    hash.sha256(0, filesize) == "39cabb912975a2b1cda1c50d9b6c62974738e4d66ac6d804fcfb30aa2764240f"
}
```

### Sample 75: `ae361b0c289ee931`

| Field | Value |
|---|---|
| SHA-256 | `ae361b0c289ee93120a5c8f230e296769ad679065371341ab62a7ecc8b02674c` |
| Family label | `unknown` |
| File name | `l.dat` |
| File type | `ps1` |
| First seen | `2026-07-27 19:14:23` |
| Reporter | `abuse_ch` |
| Tags | `ascii, ClickFix, PowerShell, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d7645d32e3d0e3f112306b6a57d267f` |
| SHA-1 | `708be32ffe21f37efd99d42befdcae82ba85540b` |
| SHA-256 | `ae361b0c289ee93120a5c8f230e296769ad679065371341ab62a7ecc8b02674c` |
| SHA3-384 | `10a626f31e600b1e6d2bd65e0320b7cf365c2cc0fefe45ca766123e57812beed7893ce2887ec9ef3d8653f7771396fc5` |
| TLSH | `T1DB311B0639A4D8FC3C252B36345B3014F609065176BE49987D856E4EF3A9C42F7F0B80` |
| SSDEEP | `24:JkSFwWwBDHrjHBEcr0NVya/wNZ8y2T7unOulBr5RZdPXR6/OlBhq2h7koJyTG+qI:JkU8BDLjHBEekp/wX8y5rlBn13qWhAGu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_ae361b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae361b0c289ee93120a5c8f230e296769ad679065371341ab62a7ecc8b02674c"
    family = "unknown"
    file_name = "l.dat"
    file_type = "ps1"
    first_seen = "2026-07-27 19:14:23"
  condition:
    hash.sha256(0, filesize) == "ae361b0c289ee93120a5c8f230e296769ad679065371341ab62a7ecc8b02674c"
}
```

### Sample 76: `9cae45ef7526eb2c`

| Field | Value |
|---|---|
| SHA-256 | `9cae45ef7526eb2c7db2a7ed5f5b2af93cb55d5cbecf907f9a07afef887b54b0` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 19:10:05` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6159d556244d9b3bdf4db6c7ea971cd5` |
| SHA-1 | `ee1972dd5b96bd33dee22c6bee867e95f0e75c5c` |
| SHA-256 | `9cae45ef7526eb2c7db2a7ed5f5b2af93cb55d5cbecf907f9a07afef887b54b0` |
| SHA3-384 | `b4ea54c46e824ce293b3131311b234150e9afa0b88a84757aa4561b6000b8939bbdcf593482d76a784150be3a42b1fcb` |
| IMPHASH | `42cf01d41ef6dc0627982490afc9cddd` |
| TLSH | `T15522391F7E850231E39408B4557A864F553D1633A383B3EBF773E1AD0BA53498840AAF` |
| SSDEEP | `96:i2wdfnoeYz/J4hrt6KBWdCZaDbFx+ZQKl6ETZjH/CPFJxGE9mZ2FFhxC7tCEe/z8:RwoNScKB6x+eKlKPFJxTEZmFhSer` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_076_9cae45ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cae45ef7526eb2c7db2a7ed5f5b2af93cb55d5cbecf907f9a07afef887b54b0"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 19:10:05"
  condition:
    hash.sha256(0, filesize) == "9cae45ef7526eb2c7db2a7ed5f5b2af93cb55d5cbecf907f9a07afef887b54b0"
}
```

### Sample 77: `4b59c11f363a5bf3`

| Field | Value |
|---|---|
| SHA-256 | `4b59c11f363a5bf3ee784e63da1c21cad0da71aebfe39d20b727a2bc6194ed3a` |
| Family label | `Mirai` |
| File name | `LSD` |
| File type | `elf` |
| First seen | `2026-07-27 19:08:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `983fe9a16ed2f3b7e057f08a3ca95e51` |
| SHA-1 | `dee566a9b164bfb8c69f92428cc883561d2ecb51` |
| SHA-256 | `4b59c11f363a5bf3ee784e63da1c21cad0da71aebfe39d20b727a2bc6194ed3a` |
| SHA3-384 | `bbfae5dc058c4c8d9deb444b30bd883b771f403343c3b7a9466ca785a72413cabe47798ab89dccb9b039d971015dfaea` |
| TLSH | `T15BA3B71E2F219FACF2A98634C7B74B349B5C23D123E1C684D1ACD5012E7434E595FBAA` |
| TELFHASH | `t13f31e519487813f4d3610d9d6eeefb31e0a170cf29261e378f21e99aea1d9428d10c1d` |
| SSDEEP | `1536:H8DlMBc9CnkFuc8mgE4A/1uHmdsM887b8puFSbr0auc0G4W5/w:eekFuTmg9O1RdsUeuFS/Av` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_4b59c11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b59c11f363a5bf3ee784e63da1c21cad0da71aebfe39d20b727a2bc6194ed3a"
    family = "Mirai"
    file_name = "LSD"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:58"
  condition:
    hash.sha256(0, filesize) == "4b59c11f363a5bf3ee784e63da1c21cad0da71aebfe39d20b727a2bc6194ed3a"
}
```

### Sample 78: `60a58ace3a7f7f4e`

| Field | Value |
|---|---|
| SHA-256 | `60a58ace3a7f7f4e64651307b54980c888b39afccbc36c08044e80919ca918f1` |
| Family label | `Mirai` |
| File name | `BHRm` |
| File type | `elf` |
| First seen | `2026-07-27 19:08:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dd92ead7a71b6e80f7cf1530b40b35a` |
| SHA-1 | `759bc85d98efb432b31f772e30c09a36420850d2` |
| SHA-256 | `60a58ace3a7f7f4e64651307b54980c888b39afccbc36c08044e80919ca918f1` |
| SHA3-384 | `cc7958a310e8c2630968ed75d23890dfec58a5a23257dd4f483bbe348e0e68ab31777a4f127b9a881c18ac0e85df55bc` |
| TLSH | `T1C073075ABD419F05D4D526BAFF1E438A33536BB8E3EEB102DE145B2527CA91F0F2A401` |
| TELFHASH | `t166f081a0075d0dcd07f4c604c7ee57291c71b45e37004907bee9ef0745e21d3725921a` |
| SSDEEP | `1536:QknVtg3U4TU5gE3BGfBC4ofvNWsVVRgb+V5txlKR0+kdlnji1WOBS7Je:ttg/1Ex5vwsTRG+V5txlKBKsWOBQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_60a58ace
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60a58ace3a7f7f4e64651307b54980c888b39afccbc36c08044e80919ca918f1"
    family = "Mirai"
    file_name = "BHRm"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:02"
  condition:
    hash.sha256(0, filesize) == "60a58ace3a7f7f4e64651307b54980c888b39afccbc36c08044e80919ca918f1"
}
```

### Sample 79: `1a19fa12c43acc75`

| Field | Value |
|---|---|
| SHA-256 | `1a19fa12c43acc758d6e6bdedeb9dc712b427c29e1f623dcdee9d2c36049eea6` |
| Family label | `Mirai` |
| File name | `uOa` |
| File type | `elf` |
| First seen | `2026-07-27 19:08:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd07b7f4449735ff5aeb2baa28e4f014` |
| SHA-1 | `f13d25a5fa532fff5c496e2e9ed8a720a69fbef0` |
| SHA-256 | `1a19fa12c43acc758d6e6bdedeb9dc712b427c29e1f623dcdee9d2c36049eea6` |
| SHA3-384 | `3cc0f26ad5f0fda05ae37151428c9c2b01414b911dd80f5881fb40cc10f53d849caa6ca26cc2dae193d0b93debfec059` |
| TLSH | `T137A3E84AAF211DB7D85BDD3705AD0A4235CCAB0771683BB53934D828BA4A54F8AD3CF4` |
| SSDEEP | `1536:Z+PFTB/7U+XzZXCB/o2sUM4SF8AP6r1cp2nT8cHVUMVSdgVNoJYWE7h:EDJXzZXA/o2c8AlYS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_1a19fa12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a19fa12c43acc758d6e6bdedeb9dc712b427c29e1f623dcdee9d2c36049eea6"
    family = "Mirai"
    file_name = "uOa"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:01"
  condition:
    hash.sha256(0, filesize) == "1a19fa12c43acc758d6e6bdedeb9dc712b427c29e1f623dcdee9d2c36049eea6"
}
```

### Sample 80: `70ca605f6de6dcbd`

| Field | Value |
|---|---|
| SHA-256 | `70ca605f6de6dcbda5f2374923a10b60774aba2d33c23d17ffbaff5889546dd8` |
| Family label | `Mirai` |
| File name | `rWH` |
| File type | `elf` |
| First seen | `2026-07-27 19:08:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05fb13333c59fd15a7ebf86d92b39442` |
| SHA-1 | `80e47bb1cd51f0fc660cc24f8af62bf8847a9a4a` |
| SHA-256 | `70ca605f6de6dcbda5f2374923a10b60774aba2d33c23d17ffbaff5889546dd8` |
| SHA3-384 | `91590611540c2f12a24c15ff7397a01505f9bde220203b8173a34fc13673a749291c5c9036a04460f4e678b37f4bdf34` |
| TLSH | `T1F5632966B9419F16C2C12777FF1EC389332663E8E3DA7203DA142F6937CB41A0E2A555` |
| TELFHASH | `t1b8f0e135448b28dc79e8c144c2df43538d5432792200561c36ecde438493d53b22dc1d` |
| SSDEEP | `1536:d2cjKQ+TvjGZc6QY7dKkhrUBEvJXsE8YhRZcF5WFvEoXUc/+Gi:d2cjd+TCUrkhUBcJ8ER7ukFvEAU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_70ca605f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ca605f6de6dcbda5f2374923a10b60774aba2d33c23d17ffbaff5889546dd8"
    family = "Mirai"
    file_name = "rWH"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:00"
  condition:
    hash.sha256(0, filesize) == "70ca605f6de6dcbda5f2374923a10b60774aba2d33c23d17ffbaff5889546dd8"
}
```

### Sample 81: `c0e8d8f831e09a74`

| Field | Value |
|---|---|
| SHA-256 | `c0e8d8f831e09a7475511eb6f1abdd112cece025c72f3de814f15da2b00fcf6f` |
| Family label | `Mirai` |
| File name | `dmff` |
| File type | `elf` |
| First seen | `2026-07-27 19:07:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a9ce5c275b5156203f29eacece2df88` |
| SHA-1 | `55eec20005f77e94488d377446b4c9aca5b7e453` |
| SHA-256 | `c0e8d8f831e09a7475511eb6f1abdd112cece025c72f3de814f15da2b00fcf6f` |
| SHA3-384 | `f3cfbcc869892c0e4d9e4e7c12158ff015682e4ef0a955ceceff2fc4f828885a587d34df4cd47672986180e0be1248ee` |
| TLSH | `T157632A5BB9918F15C5C1167AFE1E538D33032BBCE3DEB213DE146B642B8B56B0E2A405` |
| TELFHASH | `t135f08b29ce5c0add9be0c14188ff370455e0b1b27b006607eefc8f998111682729b41c` |
| SSDEEP | `1536:owncTB9ic2jTA7kBWvepIcqADRxqUSAcYiaYWBJR4ECTyh:gT2j00IfAFxqRwYWBJRW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_c0e8d8f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0e8d8f831e09a7475511eb6f1abdd112cece025c72f3de814f15da2b00fcf6f"
    family = "Mirai"
    file_name = "dmff"
    file_type = "elf"
    first_seen = "2026-07-27 19:07:58"
  condition:
    hash.sha256(0, filesize) == "c0e8d8f831e09a7475511eb6f1abdd112cece025c72f3de814f15da2b00fcf6f"
}
```

### Sample 82: `89d0178c292a0230`

| Field | Value |
|---|---|
| SHA-256 | `89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63` |
| Family label | `SalatStealer` |
| File name | `DiscordMirror.exe` |
| File type | `exe` |
| First seen | `2026-07-27 19:02:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9974299de794e9b5e30ec95f7849e97` |
| SHA-1 | `9ada72bf5ea6e4464cd63605a1ec4fdb69b28dbe` |
| SHA-256 | `89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63` |
| SHA3-384 | `6534010eadfc63c58e883ebcb1c00579d23dfd80c8cbc50fd9dc0cd1e03773d208458c4de9c4a9582bf4588fa1339426` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T10BC66B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:Xh2290FF1WCREMbEdyWmYAzQ4tG20CEE9:r9sxEYJWmJsHA9` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_082_89d0178c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63"
    family = "SalatStealer"
    file_name = "DiscordMirror.exe"
    file_type = "exe"
    first_seen = "2026-07-27 19:02:51"
  condition:
    hash.sha256(0, filesize) == "89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63"
}
```

### Sample 83: `da5c52f4c5ea577b`

| Field | Value |
|---|---|
| SHA-256 | `da5c52f4c5ea577b48c2735aade14fdc94c2244c970836189fe4f8bb6f31203b` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-27 19:02:06` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f17f9ea89456088476a8057993ea802d` |
| SHA-1 | `807e30581fe479fc76223f0ef9e126834d8179f2` |
| SHA-256 | `da5c52f4c5ea577b48c2735aade14fdc94c2244c970836189fe4f8bb6f31203b` |
| SHA3-384 | `91faa47d69b996b981f1ca93d503a5cc72cce431a2a89b3b78a81564719d11bb5226b75a099be4ee6d7a2998460e68c4` |
| TLSH | `T169C27D966A867C44BDC94A3E4CBE2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:W8vCB+25j6es8RLnp9FYpMSUpi+20qUpi+20YQX:W8l25JLPd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_da5c52f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da5c52f4c5ea577b48c2735aade14fdc94c2244c970836189fe4f8bb6f31203b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:02:06"
  condition:
    hash.sha256(0, filesize) == "da5c52f4c5ea577b48c2735aade14fdc94c2244c970836189fe4f8bb6f31203b"
}
```

### Sample 84: `a7c07b87c4968d7a`

| Field | Value |
|---|---|
| SHA-256 | `a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a` |
| Family label | `SalatStealer` |
| File name | `DiscordMirror.exe` |
| File type | `exe` |
| First seen | `2026-07-27 19:00:57` |
| Reporter | `Alex_sev` |
| Tags | `exe, salat, salatstealer, stealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f27c7e9e44efa74a367eff0200584d01` |
| SHA-1 | `26539d95c0c1a9b872469dab1e0d09ca54df9207` |
| SHA-256 | `a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a` |
| SHA3-384 | `e0bc547423ddc36bfb5f096392bc3034486e67313b12f5f235d5320205475423abdb00759f0c7b70cad4f3102aaa74d2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T141F5336246235077F63BF734C4779D2F2A958A38D8225CE14961BFABF2A011CDE5E0E4` |
| SSDEEP | `98304:uXtvcLii7Y7Ex+QEM3pZzuh6VWJmk/A10sq:uXlcv7Y7BQEM3Tuh6VWJla0N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_084_a7c07b87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a"
    family = "SalatStealer"
    file_name = "DiscordMirror.exe"
    file_type = "exe"
    first_seen = "2026-07-27 19:00:57"
  condition:
    hash.sha256(0, filesize) == "a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a"
}
```

### Sample 85: `50421a15ad2458ac`

| Field | Value |
|---|---|
| SHA-256 | `50421a15ad2458ac9518a4c8fe3b5c8341ac87d7838327d2eb55fa94fe334a39` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 18:53:00` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80bd4cf388f4109cbf2ec1433a1813aa` |
| SHA-1 | `f5f2634f60b18f0eddb9edd155f89329d85315a1` |
| SHA-256 | `50421a15ad2458ac9518a4c8fe3b5c8341ac87d7838327d2eb55fa94fe334a39` |
| SHA3-384 | `ec27ec62141b8bab8505ce7dddf88adf4946cc44027f19e2d4f01ff3cec5c9b5afbfce726e46c3b444e0b8bac68fa451` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T108E633586AE002ECE5B38138A6F742D6F9A834361B71C9DF47E853215EA73F0593CB16` |
| SSDEEP | `393216:f8fOx1dQb7LbJAqC70isxaAb55XMCHWUjXscuI3/PGTAI:f+Mcb7LbA70ia75XMb8X5H/O7` |
| ICON-DHASH | `d4e0d4d8e8e47130` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_085_50421a15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50421a15ad2458ac9518a4c8fe3b5c8341ac87d7838327d2eb55fa94fe334a39"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 18:53:00"
  condition:
    hash.sha256(0, filesize) == "50421a15ad2458ac9518a4c8fe3b5c8341ac87d7838327d2eb55fa94fe334a39"
}
```

### Sample 86: `a3b454082dcbf17d`

| Field | Value |
|---|---|
| SHA-256 | `a3b454082dcbf17d64ec6539870404fb7dd99ba49a69f7f4d98b1b31c436c199` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 18:50:56` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f7a468bdcf482f08bd014ae52db5299` |
| SHA-1 | `980f07f67302d588946e920dfdabdca3d3a8a05d` |
| SHA-256 | `a3b454082dcbf17d64ec6539870404fb7dd99ba49a69f7f4d98b1b31c436c199` |
| SHA3-384 | `4a391a8b43c65111cc43954c0bf5ecf512e771a1954761b09378afa9ee7eb22bcbc1a7345927618c791a8ee0b10063ae` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T1A3823B0FB8424316E1E110B4966696BBD9B9AC7633C414EBF7D44AEE0A686C1FC3610F` |
| SSDEEP | `384:AgZbmcmhzwEUaUu94gXTP+av8U9c+H4P:c5UaF9Ka0U1C` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_086_a3b45408
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3b454082dcbf17d64ec6539870404fb7dd99ba49a69f7f4d98b1b31c436c199"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:50:56"
  condition:
    hash.sha256(0, filesize) == "a3b454082dcbf17d64ec6539870404fb7dd99ba49a69f7f4d98b1b31c436c199"
}
```

### Sample 87: `23ca56a8e6590915`

| Field | Value |
|---|---|
| SHA-256 | `23ca56a8e65909151facf54a1c40ab3b015e752901d6d76bfae0a784b5c91a3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 18:48:33` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX8.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b87df554eada4061ee3273a50f12632c` |
| SHA-1 | `e7e6cc2691049ace5012e7fc706a5f5c41fa71dd` |
| SHA-256 | `23ca56a8e65909151facf54a1c40ab3b015e752901d6d76bfae0a784b5c91a3e` |
| SHA3-384 | `0d1749ae5baa6aff5bb71dc6bdbb35a173267ff2da114f2104be1d8cfd95c1d36175970a544b9cf20e8d855de0dd92cf` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T125A68D07BCE049E9C4AA933689A752A67B71FC080B3167DB2E50B7783E727D09E35744` |
| SSDEEP | `49152:W/HSv8NU8+8CG8HD3/ppd/Z4hcVthfy18fWK8uUCy2TuMHLJFBLOk0RakLLE4hku:W/g8EPNtL3PI2hjMY/woL/C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_23ca56a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23ca56a8e65909151facf54a1c40ab3b015e752901d6d76bfae0a784b5c91a3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:48:33"
  condition:
    hash.sha256(0, filesize) == "23ca56a8e65909151facf54a1c40ab3b015e752901d6d76bfae0a784b5c91a3e"
}
```

### Sample 88: `7defdda6602cc54c`

| Field | Value |
|---|---|
| SHA-256 | `7defdda6602cc54c73ad8cfe2e26e9465926795d6f73da1f3e3b7296be471916` |
| Family label | `unknown` |
| File name | `Exhibition_of_the_Heart_demo.exe` |
| File type | `exe` |
| First seen | `2026-07-27 18:46:08` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48ef5568dfe139db17891e9b8f8e659c` |
| SHA-1 | `65ba94495c65b78ebbfd6d59908cff81e891bba6` |
| SHA-256 | `7defdda6602cc54c73ad8cfe2e26e9465926795d6f73da1f3e3b7296be471916` |
| SHA3-384 | `1b5cc2d3c6f20191fe1dc74a311018ce74648e4b6300dc7eb677c309499549bddfb0c28f706b0cedac2df0ef11d66893` |
| TLSH | `T15828CF02A3E88599C0BFD138D57B551BE7F2BC695331D7CB1180596A2F73BE04A3A362` |
| SSDEEP | `1572864:52Jzw1t/z+l1zAxJorsgdnen9qPsniUd:4Jzw1tal1z0ysge9qUiUd` |
| ICON-DHASH | `39e8ccd4f0f8d4cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_7defdda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7defdda6602cc54c73ad8cfe2e26e9465926795d6f73da1f3e3b7296be471916"
    family = "unknown"
    file_name = "Exhibition_of_the_Heart_demo.exe"
    file_type = "exe"
    first_seen = "2026-07-27 18:46:08"
  condition:
    hash.sha256(0, filesize) == "7defdda6602cc54c73ad8cfe2e26e9465926795d6f73da1f3e3b7296be471916"
}
```

### Sample 89: `72da1a3abc1230fd`

| Field | Value |
|---|---|
| SHA-256 | `72da1a3abc1230fdbb9a1a7ac21b490b6482e14cbcfa9b8f5913af03d99fabde` |
| Family label | `Phorpiex` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 18:44:43` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, Phorpiex` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8347c0d21537e847ab3572dd45ba17d5` |
| SHA-1 | `34c6e16bc42a5af390991d61f78a98bc6ed87c2f` |
| SHA-256 | `72da1a3abc1230fdbb9a1a7ac21b490b6482e14cbcfa9b8f5913af03d99fabde` |
| SHA3-384 | `b1279503f238d0f2673c80621c7a6c1ce0d15b7ab28b09e7c97aaf20a1f34b619db66c899765c03a5fa01a36e57b8b8c` |
| IMPHASH | `dfba23467fe5a12366e7fde987218cb0` |
| TLSH | `T152822B0FB9424316E1E110B4967596BBD9B9AC7633C414EBF7D44AEE1A686C1FC3210F` |
| SSDEEP | `384:AqZbmcmhzwEUaUu94gXTP+av8U9c+O4P:G5UaF9Ka0U1p` |

#### Technical Assessment

- The sample is tracked as `Phorpiex` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Phorpiex_089_72da1a3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72da1a3abc1230fdbb9a1a7ac21b490b6482e14cbcfa9b8f5913af03d99fabde"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:44:43"
  condition:
    hash.sha256(0, filesize) == "72da1a3abc1230fdbb9a1a7ac21b490b6482e14cbcfa9b8f5913af03d99fabde"
}
```

### Sample 90: `8ca38b5e845b77dd`

| Field | Value |
|---|---|
| SHA-256 | `8ca38b5e845b77ddf26b2596698c4dd7f4033e86b998e27cda460cfd9377de81` |
| Family label | `unknown` |
| File name | `EROAPPLI.exe` |
| File type | `exe` |
| First seen | `2026-07-27 18:36:43` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `071116d8ea1f5a5b4037a87d406af98a` |
| SHA-1 | `1846e071bc32e374172ebe5835b9c679d30f92fd` |
| SHA-256 | `8ca38b5e845b77ddf26b2596698c4dd7f4033e86b998e27cda460cfd9377de81` |
| SHA3-384 | `600079a263a7327b569fad27ffd537dfcba25b13e55a3be542ca15d5b478d84bc2817e9330be39e43f7c736e0aa2c1ea` |
| TLSH | `T13328C002A3E88599C0BFD239D57B561BEBF2BC295331C7CB0181556D2E73BE04A3A395` |
| SSDEEP | `1572864:J2JDwbt/z+l1zAxHorsgdnen9qPsniUd:oJDwbtal1zCysge9qUiUd` |
| ICON-DHASH | `f5b3b2b0f0643818` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_8ca38b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ca38b5e845b77ddf26b2596698c4dd7f4033e86b998e27cda460cfd9377de81"
    family = "unknown"
    file_name = "EROAPPLI.exe"
    file_type = "exe"
    first_seen = "2026-07-27 18:36:43"
  condition:
    hash.sha256(0, filesize) == "8ca38b5e845b77ddf26b2596698c4dd7f4033e86b998e27cda460cfd9377de81"
}
```

### Sample 91: `8feaac0336a3b0eb`

| Field | Value |
|---|---|
| SHA-256 | `8feaac0336a3b0eb37cf9ca2981edf2842691ba492a0e169f9bf1a57a8af4c65` |
| Family label | `Mirai` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-27 18:35:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f253bf10227c573519f478d232db1a4` |
| SHA-1 | `b2e389672d026f31f3b70eefd710944a5a64367e` |
| SHA-256 | `8feaac0336a3b0eb37cf9ca2981edf2842691ba492a0e169f9bf1a57a8af4c65` |
| SHA3-384 | `6b4627acb9fd399022a566094d2d94365e25ba6c49c107b2b7674c218cb9071579ccc5a10bc1a2fd16b6cc325bd187f0` |
| TLSH | `T176016FC6D2605910405D996D7296A5A0F472C3C6068B8F687FDC543DBB4CE14B027F9D` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaSC5FbhV8CQEhJSCLfX7lesQCrRhTECHsR:kXCKysE2hi0ziQvZohaSM+rmJCJGO7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_8feaac03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8feaac0336a3b0eb37cf9ca2981edf2842691ba492a0e169f9bf1a57a8af4c65"
    family = "Mirai"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-27 18:35:58"
  condition:
    hash.sha256(0, filesize) == "8feaac0336a3b0eb37cf9ca2981edf2842691ba492a0e169f9bf1a57a8af4c65"
}
```

### Sample 92: `662cd578323fc9cf`

| Field | Value |
|---|---|
| SHA-256 | `662cd578323fc9cfa37332bf9148479a99e67b61c0315e09feda63ac9761878f` |
| Family label | `Mirai` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-27 18:34:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4ef04adbc770071a5f11b3be1072592` |
| SHA-1 | `aa9220315c22188a4478e2fbc5ab16f6ce33936b` |
| SHA-256 | `662cd578323fc9cfa37332bf9148479a99e67b61c0315e09feda63ac9761878f` |
| SHA3-384 | `8a5e65b8c9c742454c0e283d078b3dbd01d570c668df4163d396530dad3f2d3ac24577c611237926dad236e18a0e5209` |
| TLSH | `T1E501AFC6D224591040DD992C31976855F872C3C6168BCF74BFACA43DBB4CE14B027F98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaSC5FhV8CQyhJSCLfX7nQCrjTECHoBX:kXCKysE2hi0ziQvZohaSMCxmsfGCX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_662cd578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "662cd578323fc9cfa37332bf9148479a99e67b61c0315e09feda63ac9761878f"
    family = "Mirai"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-27 18:34:58"
  condition:
    hash.sha256(0, filesize) == "662cd578323fc9cfa37332bf9148479a99e67b61c0315e09feda63ac9761878f"
}
```

### Sample 93: `ab4394c429efc69b`

| Field | Value |
|---|---|
| SHA-256 | `ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 18:33:30` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, PMIX2.file, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cffac6c24519fd656a99ddfe63611a27` |
| SHA-1 | `21a14766846449b8f7b65b2b680b936e87320385` |
| SHA-256 | `ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f` |
| SHA3-384 | `b8cf94a32e9789f2472520a7adc96ddba2fd2fb467f8e23579def248871856599fa75a04fc7cd0b4e56004698c03da8c` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1F5C6BE03EC6515E9C1ADD63189639262BB717C885B3123D72B90F2252F77BD0BEBA344` |
| SSDEEP | `196608:LJby2bfcDO0vqQjOCeQ/K6l6vaSCE5/i7/s:LlhfmO0ChY/FFzE5/i7/s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_093_ab4394c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:33:30"
  condition:
    hash.sha256(0, filesize) == "ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f"
}
```

### Sample 94: `62e631c68ba9392d`

| Field | Value |
|---|---|
| SHA-256 | `62e631c68ba9392dc91e19cdc4f5e00bc0e303764c9f5c27ce2be6bf40bcc933` |
| Family label | `HijackLoader` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 18:12:43` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, HijackLoader, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17005c9a5f2a9a57fe71ced46712c688` |
| SHA-1 | `58a7e2f5ca176afbdeffc8634bdb5bc105b91dde` |
| SHA-256 | `62e631c68ba9392dc91e19cdc4f5e00bc0e303764c9f5c27ce2be6bf40bcc933` |
| SHA3-384 | `6d321aa4609a2372365c50938bcc52ee36a029b858cd69a8a8ff516dedff6920da4e8ac2dab034154116753b6a733b29` |
| IMPHASH | `20dd26497880c05caed9305b3c8b9109` |
| TLSH | `T121B63319B7CF46B9F185703D02A6C48ADE1779250DF4B09B0CB8E61E0472B866B7D7B2` |
| SSDEEP | `196608:b7q9w+v4f6LnwYtbPMF++FAQZKgjzgmcK7gkmP2sZ9ZObwWa6zXUCd:y9wZAwCrQHzA6g52sgblzXUG` |
| ICON-DHASH | `b298acbab2ca7a72` |

#### Technical Assessment

- The sample is tracked as `HijackLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_HijackLoader_094_62e631c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62e631c68ba9392dc91e19cdc4f5e00bc0e303764c9f5c27ce2be6bf40bcc933"
    family = "HijackLoader"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:12:43"
  condition:
    hash.sha256(0, filesize) == "62e631c68ba9392dc91e19cdc4f5e00bc0e303764c9f5c27ce2be6bf40bcc933"
}
```

### Sample 95: `fdf1fc9a36c9fa06`

| Field | Value |
|---|---|
| SHA-256 | `fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0` |
| Family label | `unknown` |
| File name | `fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0` |
| File type | `sh` |
| First seen | `2026-07-27 18:00:59` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09f7d18c373623b35f2479d31fa7ba47` |
| SHA-1 | `42f6a4f6b21eca1df529e71fe40e303d1e530692` |
| SHA-256 | `fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0` |
| SHA3-384 | `a62606fcf0e1d58db2c81c03790f2fc8d24ae554608d3178fc9d1769de9409f63a4d3fe8103e9f0d69971198dd5b9f49` |
| TLSH | `T1B03132DA56555E368303CECEB3A33618720C92FB2C47D7A4C9490EFD4A881CDB255BC6` |
| SSDEEP | `24:0ac6maCaQv/riDBwfXQ50nhOBqToGsYV19u2YTW1:5c6mawcB2FnhOBBGsx01` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_fdf1fc9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0"
    family = "unknown"
    file_name = "fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0"
    file_type = "sh"
    first_seen = "2026-07-27 18:00:59"
  condition:
    hash.sha256(0, filesize) == "fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0"
}
```

### Sample 96: `5326cd216b594557`

| Field | Value |
|---|---|
| SHA-256 | `5326cd216b594557d92a20e67d1074e532c4817ebc078ca41e9d92d315c160e3` |
| Family label | `Formbook` |
| File name | `z9QUOTATIONORDER.exe` |
| File type | `exe` |
| First seen | `2026-07-27 18:00:06` |
| Reporter | `fabiodemartin` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0995e073911c897ff2b5652a8bad3a8` |
| SHA-1 | `b36cdaa68a18962e07f3d9c862b4f0bf17c16345` |
| SHA-256 | `5326cd216b594557d92a20e67d1074e532c4817ebc078ca41e9d92d315c160e3` |
| SHA3-384 | `11a2809476e4b69e890e128ccfbfa8d3b05e3719d2cb9decffb6ab9e95ef6b645dbefaf3167d6cd40ba42acfbb025f81` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11C35016A15234703D8B66FF04E71E1B11B7A7CAAE635D21A5EDA1CEBB97B7003C05312` |
| SSDEEP | `24576:Fy5Sz4Hg7b3TPIp0SLeVC8owN8gZgAA2KvDzo8Di0no4zOzjK:Fy5SjbPJVC89N8/HZvno8SGz` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_096_5326cd21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5326cd216b594557d92a20e67d1074e532c4817ebc078ca41e9d92d315c160e3"
    family = "Formbook"
    file_name = "z9QUOTATIONORDER.exe"
    file_type = "exe"
    first_seen = "2026-07-27 18:00:06"
  condition:
    hash.sha256(0, filesize) == "5326cd216b594557d92a20e67d1074e532c4817ebc078ca41e9d92d315c160e3"
}
```

### Sample 97: `7d98375b03ed4def`

| Field | Value |
|---|---|
| SHA-256 | `7d98375b03ed4def16841cc9b749a9297701edf20cba2f6f64bf96fcc995c79d` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 17:58:52` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX4.file, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39763d60e7122f64bd38797e83ef7977` |
| SHA-1 | `6dbce49761da2db96277b1c7cd65176ca9b7fa58` |
| SHA-256 | `7d98375b03ed4def16841cc9b749a9297701edf20cba2f6f64bf96fcc995c79d` |
| SHA3-384 | `084655a293d7ab1783e28980a9346df66aae6c00b5915add86fa0896c601b8f53b32398e9ef12f109394948ce4ed7a7f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T171B55A07BCE049E9C4AA933189A752967B75FC090B3263DB2E90BB782F727D09D35744` |
| SSDEEP | `49152:kJaSXCpOB87Oij5k/sr9Th5Lq3rRqO+D9NsWJW2Zbh0mYkPXuDqF/x8WF2nz8oR9:kJDCO9EdKRoWe0BchK` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_097_7d98375b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d98375b03ed4def16841cc9b749a9297701edf20cba2f6f64bf96fcc995c79d"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 17:58:52"
  condition:
    hash.sha256(0, filesize) == "7d98375b03ed4def16841cc9b749a9297701edf20cba2f6f64bf96fcc995c79d"
}
```

### Sample 98: `f4b60c5084055d4b`

| Field | Value |
|---|---|
| SHA-256 | `f4b60c5084055d4b30b3288bd253c12610d4bec7f02739e43930a830db6c9d17` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-27 17:58:28` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `276ae0bbbf2b2cbc3a32d809f1562cfa` |
| SHA-1 | `7b5903254e100b884c1ad907bc6973700f7bbb9f` |
| SHA-256 | `f4b60c5084055d4b30b3288bd253c12610d4bec7f02739e43930a830db6c9d17` |
| SHA3-384 | `528ac4f5bf838fc8ff283b33b489c95269072367aab29aafe0bb08f40682c6e28e16096d6846cfcce5f9f22a6ca95668` |
| IMPHASH | `94d0b1085d2c348c96db0edea60c0a76` |
| TLSH | `T1722633A36FB0559BF25C2FF04AE775281728E3D1EC8F5AA63374921AB57A601200FD1D` |
| SSDEEP | `98304:46++VvioPhA1yc9yoo3da02xFJtN5SEZINFuVIz7Zl7+:j++VTpA1ycSijtNKNyIzd5+` |
| ICON-DHASH | `b271e8cccce87192` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_f4b60c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4b60c5084055d4b30b3288bd253c12610d4bec7f02739e43930a830db6c9d17"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 17:58:28"
  condition:
    hash.sha256(0, filesize) == "f4b60c5084055d4b30b3288bd253c12610d4bec7f02739e43930a830db6c9d17"
}
```

### Sample 99: `56cc93be915c0d59`

| Field | Value |
|---|---|
| SHA-256 | `56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f` |
| Family label | `LummaStealer` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-07-27 17:53:01` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fae196b68afca48ce650acc79e25126` |
| SHA-1 | `9d0c78e7d08e01fe65858d1e2c690af0c79cc209` |
| SHA-256 | `56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f` |
| SHA3-384 | `5dd51ba49cdaf8558eeb3b105feb849c2b5de672f4e3f3e6912a21507477aa3683b06b753f66d0283e1e504ecfd53b99` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T189B55B00FDD745F6E406263255E7A2BF2335AC090F32DB97EB443A79FA772A11836249` |
| SSDEEP | `24576:NardcB0UZkg/L0UXTxs0f5RWHo81AWhcLwIaNMBzVqpj3yGyCYSINF06kFlN5vdh:NAdz+FsK1yiGyRNF06CvdHr+6bsJPJ1M` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_099_56cc93be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f"
    family = "LummaStealer"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-27 17:53:01"
  condition:
    hash.sha256(0, filesize) == "56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f"
}
```

### Sample 100: `e15b78ffb8b880b9`

| Field | Value |
|---|---|
| SHA-256 | `e15b78ffb8b880b99ea1dbc2f51d1426fa0d72da39c10e5a0e364d62ccfaa1ce` |
| Family label | `Efimer` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-27 17:52:50` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b909d08eaab5ebd97e5ee9af79d9952a` |
| SHA-1 | `e03a3925deefb4888331a3c9573a5199248ac9f5` |
| SHA-256 | `e15b78ffb8b880b99ea1dbc2f51d1426fa0d72da39c10e5a0e364d62ccfaa1ce` |
| SHA3-384 | `182e3b15a1c0b6c672f3502780fdc19e991a3ef6a70f0db3de8e874f14e4f06dd2fff24bd3fe4a67a8cae957d771f40b` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T102E633686ED001E9E8B7903CEDF262A9D155B0661BF6C5CF07A847B62E531D0CC3C9A7` |
| SSDEEP | `393216:KXCjeC/KZc/VITAKqL1K8FeXMCHWUjXjcuI3/PGTAI:KXCj/WTNA78XMb8XAH/O7` |
| ICON-DHASH | `d4f0d4d8c8e47130` |

#### Technical Assessment

- The sample is tracked as `Efimer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Efimer_100_e15b78ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e15b78ffb8b880b99ea1dbc2f51d1426fa0d72da39c10e5a0e364d62ccfaa1ce"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 17:52:50"
  condition:
    hash.sha256(0, filesize) == "e15b78ffb8b880b99ea1dbc2f51d1426fa0d72da39c10e5a0e364d62ccfaa1ce"
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
 * Generated: 2026-07-28T03:42:03.377835+00:00
 */

rule MalwareBazaar_unknown_001_07e01575
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07e01575db8e5a3b8a97aa7977a631e541f412548d16f15f8744969f1540d609"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 02:52:30"
  condition:
    hash.sha256(0, filesize) == "07e01575db8e5a3b8a97aa7977a631e541f412548d16f15f8744969f1540d609"
}

rule MalwareBazaar_RemcosRAT_002_fc09faa3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc09faa3fdbf0f6b7d7aad125eca6798b8fb928714dfb0c6b7964a866fdffe39"
    family = "RemcosRAT"
    file_name = "SC_TR11670000_pdf.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 02:05:38"
  condition:
    hash.sha256(0, filesize) == "fc09faa3fdbf0f6b7d7aad125eca6798b8fb928714dfb0c6b7964a866fdffe39"
}

rule MalwareBazaar_unknown_003_a522e892
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a522e892f5a5d41e6b71dfa435491682dd20fe2f562075af071f929c3fa38620"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:58:27"
  condition:
    hash.sha256(0, filesize) == "a522e892f5a5d41e6b71dfa435491682dd20fe2f562075af071f929c3fa38620"
}

rule MalwareBazaar_CoinMiner_004_52f01185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52f011851639a0c3a5ac55a68314d0b11d6893805f93f0934a4b72f5c3c6d15d"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:54:53"
  condition:
    hash.sha256(0, filesize) == "52f011851639a0c3a5ac55a68314d0b11d6893805f93f0934a4b72f5c3c6d15d"
}

rule MalwareBazaar_unknown_005_83801179
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83801179bc16c5d1649aff7f6f7bbe46a2e6ef39ec4a3d3d558e758ba89eb7f5"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 01:52:30"
  condition:
    hash.sha256(0, filesize) == "83801179bc16c5d1649aff7f6f7bbe46a2e6ef39ec4a3d3d558e758ba89eb7f5"
}

rule MalwareBazaar_unknown_006_3b607326
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b6073262e504853b0d13420eb6846ca0f799334b5038422e6a1bdd8bc505e2c"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-07-28 01:41:17"
  condition:
    hash.sha256(0, filesize) == "3b6073262e504853b0d13420eb6846ca0f799334b5038422e6a1bdd8bc505e2c"
}

rule MalwareBazaar_Mirai_007_da8d5c07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da8d5c07be1c8cc6bcf73f1d9d4794f3de6a8e8d5d873ca310c3bd366d8bde1d"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-28 01:35:18"
  condition:
    hash.sha256(0, filesize) == "da8d5c07be1c8cc6bcf73f1d9d4794f3de6a8e8d5d873ca310c3bd366d8bde1d"
}

rule MalwareBazaar_unknown_008_e8d94cfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8d94cfce33842bb9e66771d9c32a8c460fbf4ab60a39c55e0ade8b3352abd9d"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 01:34:12"
  condition:
    hash.sha256(0, filesize) == "e8d94cfce33842bb9e66771d9c32a8c460fbf4ab60a39c55e0ade8b3352abd9d"
}

rule MalwareBazaar_Mirai_009_753936cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "753936cf1764b98686e87cd140ba7c0234973e1b5339b096f86edc34906a1a77"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-28 01:23:19"
  condition:
    hash.sha256(0, filesize) == "753936cf1764b98686e87cd140ba7c0234973e1b5339b096f86edc34906a1a77"
}

rule MalwareBazaar_unknown_010_decafa3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "decafa3d6023701eec07d0d0f1ac5b8070a47bb979a5d18d2e70296e51f1e2c4"
    family = "unknown"
    file_name = ".X0-lock_x86_64"
    file_type = "elf"
    first_seen = "2026-07-28 01:16:11"
  condition:
    hash.sha256(0, filesize) == "decafa3d6023701eec07d0d0f1ac5b8070a47bb979a5d18d2e70296e51f1e2c4"
}

rule MalwareBazaar_unknown_011_4a319c86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a319c860dacdd7ff95772e04b7072bba01e43d9f9d03a3cc3ece1e7064e071b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:14:29"
  condition:
    hash.sha256(0, filesize) == "4a319c860dacdd7ff95772e04b7072bba01e43d9f9d03a3cc3ece1e7064e071b"
}

rule MalwareBazaar_unknown_012_764d5bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "764d5bcb4be851ed27008a40010ed48669160dee3c83fecfc3a0c0654dcece3f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:14:02"
  condition:
    hash.sha256(0, filesize) == "764d5bcb4be851ed27008a40010ed48669160dee3c83fecfc3a0c0654dcece3f"
}

rule MalwareBazaar_unknown_013_2bd87fb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bd87fb7b4f22cf7685920959c4f335373be6f5aaa00668534f5cdc3bcd74302"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 01:12:25"
  condition:
    hash.sha256(0, filesize) == "2bd87fb7b4f22cf7685920959c4f335373be6f5aaa00668534f5cdc3bcd74302"
}

rule MalwareBazaar_Mirai_014_043bdf3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "043bdf3f2ec52afa39922ea6a7cb3e4830361de4242a448e9e0b9561148a2ad0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-28 01:11:20"
  condition:
    hash.sha256(0, filesize) == "043bdf3f2ec52afa39922ea6a7cb3e4830361de4242a448e9e0b9561148a2ad0"
}

rule MalwareBazaar_unknown_015_d31040a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d31040a2b95b66340fe07d1bed67ef96fbe1d60e6635acc2736de3d648f90131"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:09:46"
  condition:
    hash.sha256(0, filesize) == "d31040a2b95b66340fe07d1bed67ef96fbe1d60e6635acc2736de3d648f90131"
}

rule MalwareBazaar_unknown_016_8f65fe26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f65fe2615ab00886f1e15499343375021fe8cc6a10e56d569c4277d0e23283e"
    family = "unknown"
    file_name = "Notice of Intent to Award.zip"
    file_type = "zip"
    first_seen = "2026-07-28 01:09:06"
  condition:
    hash.sha256(0, filesize) == "8f65fe2615ab00886f1e15499343375021fe8cc6a10e56d569c4277d0e23283e"
}

rule MalwareBazaar_Phorpiex_017_e947f8a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e947f8a540eb337c4090c14d880948f07106dbe19d64625b7577cf9416935fae"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 01:07:07"
  condition:
    hash.sha256(0, filesize) == "e947f8a540eb337c4090c14d880948f07106dbe19d64625b7577cf9416935fae"
}

rule MalwareBazaar_Mirai_018_f9123894
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f912389499090e12b222ac4800da81a9e8d0ad6765b63fbee9eafc0a4291076a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-28 00:58:27"
  condition:
    hash.sha256(0, filesize) == "f912389499090e12b222ac4800da81a9e8d0ad6765b63fbee9eafc0a4291076a"
}

rule MalwareBazaar_unknown_019_b06316fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b06316fc674d62db99afd11be3ec60eb212fd0e64a23c20685017fe7d7221f5d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-28 00:56:57"
  condition:
    hash.sha256(0, filesize) == "b06316fc674d62db99afd11be3ec60eb212fd0e64a23c20685017fe7d7221f5d"
}

rule MalwareBazaar_RemcosRAT_020_2c620e40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c620e407eabb93dc16449499824074a38497caeb42abd7176a7d101a3bb62c2"
    family = "RemcosRAT"
    file_name = "scan02_ Shipping documents.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 00:53:58"
  condition:
    hash.sha256(0, filesize) == "2c620e407eabb93dc16449499824074a38497caeb42abd7176a7d101a3bb62c2"
}

rule MalwareBazaar_unknown_021_04ef9757
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04ef9757c950005f926458dee36517a6c879d39e5798a378bdd6aa7a45d0d23a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-28 00:52:31"
  condition:
    hash.sha256(0, filesize) == "04ef9757c950005f926458dee36517a6c879d39e5798a378bdd6aa7a45d0d23a"
}

rule MalwareBazaar_Mirai_022_eb71de16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb71de1615f852d0d2816198901c157bfdab1f62dd3b2d029a4b167a7ba2b3fb"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-28 00:37:36"
  condition:
    hash.sha256(0, filesize) == "eb71de1615f852d0d2816198901c157bfdab1f62dd3b2d029a4b167a7ba2b3fb"
}

rule MalwareBazaar_unknown_023_711b5be1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "711b5be1f5c5d4c53d12c5e8415e401aa87e99de164178e2a602367922639ce3"
    family = "unknown"
    file_name = "QU20262807.vbs"
    file_type = "vbs"
    first_seen = "2026-07-28 00:35:33"
  condition:
    hash.sha256(0, filesize) == "711b5be1f5c5d4c53d12c5e8415e401aa87e99de164178e2a602367922639ce3"
}

rule MalwareBazaar_unknown_024_bd5cabe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd5cabe39fddca6f03728e5a86e791acb14438adb6e6ad8fca4d80f9d7ea802a"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-28 00:34:24"
  condition:
    hash.sha256(0, filesize) == "bd5cabe39fddca6f03728e5a86e791acb14438adb6e6ad8fca4d80f9d7ea802a"
}

rule MalwareBazaar_unknown_025_50d5984d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d5984d193e2505338449d7594f394a4aa6cdd55370706f1d12dfb0e32e3183"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-28 00:28:07"
  condition:
    hash.sha256(0, filesize) == "50d5984d193e2505338449d7594f394a4aa6cdd55370706f1d12dfb0e32e3183"
}

rule MalwareBazaar_Mirai_026_f9bb0cae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9bb0caed91dcc9a95aee382b85494510ea4c94eaf4666ff70082b41ef1c0bfd"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-28 00:26:41"
  condition:
    hash.sha256(0, filesize) == "f9bb0caed91dcc9a95aee382b85494510ea4c94eaf4666ff70082b41ef1c0bfd"
}

rule MalwareBazaar_unknown_027_7070ccdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7070ccdf86771d89aa15bb3cc21e01b3eda0d5b81af6a87ef535940e8f7493a4"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-28 00:25:26"
  condition:
    hash.sha256(0, filesize) == "7070ccdf86771d89aa15bb3cc21e01b3eda0d5b81af6a87ef535940e8f7493a4"
}

rule MalwareBazaar_unknown_028_69562607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6956260708076c10bac1e5725846780bc1a754fa1a26001b4b8f22b8c1a7c1fb"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-28 00:22:09"
  condition:
    hash.sha256(0, filesize) == "6956260708076c10bac1e5725846780bc1a754fa1a26001b4b8f22b8c1a7c1fb"
}

rule MalwareBazaar_unknown_029_a3263337
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a326333799d5c425a31de391c84c839de3a25b39bf9c4ba3bed95aac8ea0043f"
    family = "unknown"
    file_name = "libcommon.so_x86_64"
    file_type = "elf"
    first_seen = "2026-07-28 00:22:08"
  condition:
    hash.sha256(0, filesize) == "a326333799d5c425a31de391c84c839de3a25b39bf9c4ba3bed95aac8ea0043f"
}

rule MalwareBazaar_Mirai_030_6736fac2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6736fac25a0bccf4862f4a49bb354961a042e0c420f081332ad4473eb7ed1e8b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-28 00:22:06"
  condition:
    hash.sha256(0, filesize) == "6736fac25a0bccf4862f4a49bb354961a042e0c420f081332ad4473eb7ed1e8b"
}

rule MalwareBazaar_unknown_031_a3c889a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3c889a83799583a0dcbfaa90ad905cafbb0cd3221b54b49cb5fe3ceecec3d34"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 23:52:31"
  condition:
    hash.sha256(0, filesize) == "a3c889a83799583a0dcbfaa90ad905cafbb0cd3221b54b49cb5fe3ceecec3d34"
}

rule MalwareBazaar_unknown_032_067e321f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "067e321f8018c785f2c5089807e59bb9d6a1caf97aca775a3b435d4fb7b564b6"
    family = "unknown"
    file_name = "bundle.js"
    file_type = "js"
    first_seen = "2026-07-27 23:17:32"
  condition:
    hash.sha256(0, filesize) == "067e321f8018c785f2c5089807e59bb9d6a1caf97aca775a3b435d4fb7b564b6"
}

rule MalwareBazaar_unknown_033_21fa2933
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21fa2933a5f8ecc157747f190d86762317d8b64f800f67287fbecf0169764b46"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 22:52:31"
  condition:
    hash.sha256(0, filesize) == "21fa2933a5f8ecc157747f190d86762317d8b64f800f67287fbecf0169764b46"
}

rule MalwareBazaar_unknown_034_10ada20c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ada20cd985da2b6ba1e0a5ce914582f37b12e6b4fc6c0c3f70466b1f9fa06a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 22:43:17"
  condition:
    hash.sha256(0, filesize) == "10ada20cd985da2b6ba1e0a5ce914582f37b12e6b4fc6c0c3f70466b1f9fa06a"
}

rule MalwareBazaar_unknown_035_712ca31e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "712ca31e2937bf843579e0e782ac8bc33ae84b4d580a3c69aabd531ff416b5b8"
    family = "unknown"
    file_name = "QUOTATION KKTP - #PO996574620775800000 A105N.pdf(786KB).lha.com"
    file_type = "exe"
    first_seen = "2026-07-27 22:25:47"
  condition:
    hash.sha256(0, filesize) == "712ca31e2937bf843579e0e782ac8bc33ae84b4d580a3c69aabd531ff416b5b8"
}

rule MalwareBazaar_unknown_036_17c4da4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17c4da4a81155d233e6eaf6ef7cd2590d6fda76a46bacede4881ab3cd1bf88d3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 21:52:32"
  condition:
    hash.sha256(0, filesize) == "17c4da4a81155d233e6eaf6ef7cd2590d6fda76a46bacede4881ab3cd1bf88d3"
}

rule MalwareBazaar_unknown_037_ffa5c396
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffa5c396a37ef0dbabf541cecc4e1bda84675eace39d2a8d2ccf355f08a9ca80"
    family = "unknown"
    file_name = "oxmaul.rar"
    file_type = "rar"
    first_seen = "2026-07-27 21:27:22"
  condition:
    hash.sha256(0, filesize) == "ffa5c396a37ef0dbabf541cecc4e1bda84675eace39d2a8d2ccf355f08a9ca80"
}

rule MalwareBazaar_unknown_038_3fe19e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fe19e12a6c3054ca089010c5da14867a4e7ccbd72560dcbe8cdc99f44e36f48"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 21:16:51"
  condition:
    hash.sha256(0, filesize) == "3fe19e12a6c3054ca089010c5da14867a4e7ccbd72560dcbe8cdc99f44e36f48"
}

rule MalwareBazaar_NanoCore_039_ef876baf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef876baf02db22ca0d03a888226bea7728b508e39e75f84dc894ec900b296fae"
    family = "NanoCore"
    file_name = "510950FF5CB5D12C8A9D4A71D2A88D2E.exe"
    file_type = "exe"
    first_seen = "2026-07-27 21:15:05"
  condition:
    hash.sha256(0, filesize) == "ef876baf02db22ca0d03a888226bea7728b508e39e75f84dc894ec900b296fae"
}

rule MalwareBazaar_unknown_040_4ddf530a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ddf530a9ced8cb042c88e3fdd75933a08cd1419a1f3bbd7a3e6b8f3e6b6260d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 21:08:45"
  condition:
    hash.sha256(0, filesize) == "4ddf530a9ced8cb042c88e3fdd75933a08cd1419a1f3bbd7a3e6b8f3e6b6260d"
}

rule MalwareBazaar_unknown_041_bf1dde0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf1dde0ee67946f8ec76c64b6eb4252040ad4ffb097cdc9528c844de923a1dad"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:56:28"
  condition:
    hash.sha256(0, filesize) == "bf1dde0ee67946f8ec76c64b6eb4252040ad4ffb097cdc9528c844de923a1dad"
}

rule MalwareBazaar_unknown_042_41d4cb02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41d4cb022a1e382d26b6361562d75d4d8a03150a8d089c3dccae6b4b6c1061e3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:48:40"
  condition:
    hash.sha256(0, filesize) == "41d4cb022a1e382d26b6361562d75d4d8a03150a8d089c3dccae6b4b6c1061e3"
}

rule MalwareBazaar_NetSupport_043_6a12f1b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a12f1b9d531003b507b251a6fbbd9fc8c3673bb386852749c161730fbc312d9"
    family = "NetSupport"
    file_name = "4124a167cef576ccae119247431709f6.exe"
    file_type = "exe"
    first_seen = "2026-07-27 20:45:06"
  condition:
    hash.sha256(0, filesize) == "6a12f1b9d531003b507b251a6fbbd9fc8c3673bb386852749c161730fbc312d9"
}

rule MalwareBazaar_AgentTesla_044_7366ce5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7366ce5e9a87b1371152bfb689a0b55a04de7e4f2a718e7d5f43e3c02e32381f"
    family = "AgentTesla"
    file_name = "New order Aug2026.JS"
    file_type = "js"
    first_seen = "2026-07-27 20:44:11"
  condition:
    hash.sha256(0, filesize) == "7366ce5e9a87b1371152bfb689a0b55a04de7e4f2a718e7d5f43e3c02e32381f"
}

rule MalwareBazaar_Phorpiex_045_405904c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "405904c8a9ec04b73ac95b7e43a4c9c567b526d178257b56e4a8d812f478ddc3"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:28:31"
  condition:
    hash.sha256(0, filesize) == "405904c8a9ec04b73ac95b7e43a4c9c567b526d178257b56e4a8d812f478ddc3"
}

rule MalwareBazaar_unknown_046_b37a2cf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b37a2cf2e2f75f6cf0afd27aa05c627fa9d814e6babb603e8fec4b09b32b4079"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 20:25:25"
  condition:
    hash.sha256(0, filesize) == "b37a2cf2e2f75f6cf0afd27aa05c627fa9d814e6babb603e8fec4b09b32b4079"
}

rule MalwareBazaar_Mirai_047_c21a12ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c21a12edd5493e0e0c762a0c7ac7ce1ebbcbffed11fc27714e88b0843908e994"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-07-27 20:06:40"
  condition:
    hash.sha256(0, filesize) == "c21a12edd5493e0e0c762a0c7ac7ce1ebbcbffed11fc27714e88b0843908e994"
}

rule MalwareBazaar_Mirai_048_ed35e07d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed35e07d9a91e36eb996e234a7f7fce0243b206976ba5c67d05ea6a05c07233f"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-07-27 20:06:05"
  condition:
    hash.sha256(0, filesize) == "ed35e07d9a91e36eb996e234a7f7fce0243b206976ba5c67d05ea6a05c07233f"
}

rule MalwareBazaar_unknown_049_15d34471
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15d34471d464ff576aa1c6fdbed6821c3b38f811916770a7db2422c5a90d01c8"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 19:52:09"
  condition:
    hash.sha256(0, filesize) == "15d34471d464ff576aa1c6fdbed6821c3b38f811916770a7db2422c5a90d01c8"
}

rule MalwareBazaar_Mirai_050_f10f8355
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f10f83559e3c7a4e53b023c1ef06bc0fa91e06e48947e1360653d129daf64460"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:51"
  condition:
    hash.sha256(0, filesize) == "f10f83559e3c7a4e53b023c1ef06bc0fa91e06e48947e1360653d129daf64460"
}

rule MalwareBazaar_Mirai_051_4605e809
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4605e809be293537ef4f2aeb8f181ebd840b450dccc69507ea918a3918a6cd42"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:47"
  condition:
    hash.sha256(0, filesize) == "4605e809be293537ef4f2aeb8f181ebd840b450dccc69507ea918a3918a6cd42"
}

rule MalwareBazaar_Mirai_052_bcdfae51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcdfae513af1faf835e824dc17e5477980da3973a429f3d6976f3c315561293d"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:37"
  condition:
    hash.sha256(0, filesize) == "bcdfae513af1faf835e824dc17e5477980da3973a429f3d6976f3c315561293d"
}

rule MalwareBazaar_Mirai_053_96989350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "969893508d09084e3f66faaa21e98a4bf533b2eb6f92403f06ba0d8243f3d6d1"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:27"
  condition:
    hash.sha256(0, filesize) == "969893508d09084e3f66faaa21e98a4bf533b2eb6f92403f06ba0d8243f3d6d1"
}

rule MalwareBazaar_Mirai_054_0f4755d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f4755d46a150c16e9af5ba03b6b680d05aad08a7eeccba7239ead83c8f1e755"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:20"
  condition:
    hash.sha256(0, filesize) == "0f4755d46a150c16e9af5ba03b6b680d05aad08a7eeccba7239ead83c8f1e755"
}

rule MalwareBazaar_Mirai_055_cd53aed2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd53aed245ab98676bb8647e627677a6d4c5b08e8645b384ca1d6abfdf0586eb"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:13"
  condition:
    hash.sha256(0, filesize) == "cd53aed245ab98676bb8647e627677a6d4c5b08e8645b384ca1d6abfdf0586eb"
}

rule MalwareBazaar_Mirai_056_53385d7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53385d7dc9bf143d4fc2e5e5fc0ee63695dab54b1d5457bd6a2fbd2c611c5b17"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-27 19:37:05"
  condition:
    hash.sha256(0, filesize) == "53385d7dc9bf143d4fc2e5e5fc0ee63695dab54b1d5457bd6a2fbd2c611c5b17"
}

rule MalwareBazaar_Mirai_057_2424f532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2424f532db6b5f4dac152f0e6d28bbb93f3ffdb2a6f88902d1d00dfe7b1fd1f9"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:58"
  condition:
    hash.sha256(0, filesize) == "2424f532db6b5f4dac152f0e6d28bbb93f3ffdb2a6f88902d1d00dfe7b1fd1f9"
}

rule MalwareBazaar_Mirai_058_ad4185bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad4185bf0e84f884457992cae139eee59120c3429839c8b8306f00c5401e869e"
    family = "Mirai"
    file_name = "px86"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:14"
  condition:
    hash.sha256(0, filesize) == "ad4185bf0e84f884457992cae139eee59120c3429839c8b8306f00c5401e869e"
}

rule MalwareBazaar_Mirai_059_85f1f91b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85f1f91bb75a6cc10d59e3896c3735854c0b28e7435bc7ea50d7833638e38b0b"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:13"
  condition:
    hash.sha256(0, filesize) == "85f1f91bb75a6cc10d59e3896c3735854c0b28e7435bc7ea50d7833638e38b0b"
}

rule MalwareBazaar_Mirai_060_8f23e53b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f23e53b49b98d2f96a940271ff252f57e5b991e49f2a6d8b44c4e2f9f6f0486"
    family = "Mirai"
    file_name = "psh4"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:11"
  condition:
    hash.sha256(0, filesize) == "8f23e53b49b98d2f96a940271ff252f57e5b991e49f2a6d8b44c4e2f9f6f0486"
}

rule MalwareBazaar_Mirai_061_bf7d5c7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf7d5c7b3fdddb0e47cae68fd1c62eccdbc0f79cd3a721ad94f8bc3b814f7983"
    family = "Mirai"
    file_name = "pspc"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:10"
  condition:
    hash.sha256(0, filesize) == "bf7d5c7b3fdddb0e47cae68fd1c62eccdbc0f79cd3a721ad94f8bc3b814f7983"
}

rule MalwareBazaar_Mirai_062_d6a82668
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6a82668a5b9f9aacfbd2fab7b7d586a959639c80c55a2fa6d7e6a1d62be43c3"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:09"
  condition:
    hash.sha256(0, filesize) == "d6a82668a5b9f9aacfbd2fab7b7d586a959639c80c55a2fa6d7e6a1d62be43c3"
}

rule MalwareBazaar_Mirai_063_ebfe929a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebfe929a1285bc3a48b466b6767be1cf1242f66b9ab4a916e197f26ebc346332"
    family = "Mirai"
    file_name = "pm68k"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:07"
  condition:
    hash.sha256(0, filesize) == "ebfe929a1285bc3a48b466b6767be1cf1242f66b9ab4a916e197f26ebc346332"
}

rule MalwareBazaar_Mirai_064_c07dd050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c07dd050aea476f9d7671b9fa8ef23ffb8e811f2fbc1b7ded93a5156eab37cfe"
    family = "Mirai"
    file_name = "pmips"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:06"
  condition:
    hash.sha256(0, filesize) == "c07dd050aea476f9d7671b9fa8ef23ffb8e811f2fbc1b7ded93a5156eab37cfe"
}

rule MalwareBazaar_Mirai_065_89c6b5a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89c6b5a4f46bd7a650bafd35ba97b3bc6c6f062205fdd3768bdec95316465024"
    family = "Mirai"
    file_name = "parm"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:04"
  condition:
    hash.sha256(0, filesize) == "89c6b5a4f46bd7a650bafd35ba97b3bc6c6f062205fdd3768bdec95316465024"
}

rule MalwareBazaar_Mirai_066_fd730d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd730d78cce9761781424291954d8ec27bef2bb31864574606450c3a4eaa359c"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:03"
  condition:
    hash.sha256(0, filesize) == "fd730d78cce9761781424291954d8ec27bef2bb31864574606450c3a4eaa359c"
}

rule MalwareBazaar_Mirai_067_3fc30b1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fc30b1df7c5fde1acb66eed7a784cceddb38c6607843343ead274e0a49d568a"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:02"
  condition:
    hash.sha256(0, filesize) == "3fc30b1df7c5fde1acb66eed7a784cceddb38c6607843343ead274e0a49d568a"
}

rule MalwareBazaar_Mirai_068_e61cf04f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e61cf04f9405cbb67cf42963cdedfd0cfe4758f336c74822a1d47ab21c7c8770"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-07-27 19:36:00"
  condition:
    hash.sha256(0, filesize) == "e61cf04f9405cbb67cf42963cdedfd0cfe4758f336c74822a1d47ab21c7c8770"
}

rule MalwareBazaar_unknown_069_ff616f68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff616f68ba7dec323309da2efa9e8208bde98716019d0e554ba18251047d809a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:33:58"
  condition:
    hash.sha256(0, filesize) == "ff616f68ba7dec323309da2efa9e8208bde98716019d0e554ba18251047d809a"
}

rule MalwareBazaar_unknown_070_6c0f965a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c0f965a69154c6d1b58082c5483ca6fdb2197720ae4d1bbb99d4f3ba31b795c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:31:02"
  condition:
    hash.sha256(0, filesize) == "6c0f965a69154c6d1b58082c5483ca6fdb2197720ae4d1bbb99d4f3ba31b795c"
}

rule MalwareBazaar_unknown_071_a94e2c99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 19:25:48"
  condition:
    hash.sha256(0, filesize) == "a94e2c99cd8aaed4124fb4301b71dc97d480bf47135d4d7f45057f2c05487b0e"
}

rule MalwareBazaar_unknown_072_5f608a5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f608a5c28bf9ed0f844d755d7140efd584866c0e8aae84ac15021e93b48059c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 19:25:27"
  condition:
    hash.sha256(0, filesize) == "5f608a5c28bf9ed0f844d755d7140efd584866c0e8aae84ac15021e93b48059c"
}

rule MalwareBazaar_unknown_073_123fefe0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "123fefe00c2bf0e83f5bf0263ce8b65a8a20214c661d392e03cecc4d7529e5b0"
    family = "unknown"
    file_name = "file.ps1"
    file_type = "ps1"
    first_seen = "2026-07-27 19:20:01"
  condition:
    hash.sha256(0, filesize) == "123fefe00c2bf0e83f5bf0263ce8b65a8a20214c661d392e03cecc4d7529e5b0"
}

rule MalwareBazaar_unknown_074_39cabb91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39cabb912975a2b1cda1c50d9b6c62974738e4d66ac6d804fcfb30aa2764240f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:15:58"
  condition:
    hash.sha256(0, filesize) == "39cabb912975a2b1cda1c50d9b6c62974738e4d66ac6d804fcfb30aa2764240f"
}

rule MalwareBazaar_unknown_075_ae361b0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae361b0c289ee93120a5c8f230e296769ad679065371341ab62a7ecc8b02674c"
    family = "unknown"
    file_name = "l.dat"
    file_type = "ps1"
    first_seen = "2026-07-27 19:14:23"
  condition:
    hash.sha256(0, filesize) == "ae361b0c289ee93120a5c8f230e296769ad679065371341ab62a7ecc8b02674c"
}

rule MalwareBazaar_CoinMiner_076_9cae45ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cae45ef7526eb2c7db2a7ed5f5b2af93cb55d5cbecf907f9a07afef887b54b0"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 19:10:05"
  condition:
    hash.sha256(0, filesize) == "9cae45ef7526eb2c7db2a7ed5f5b2af93cb55d5cbecf907f9a07afef887b54b0"
}

rule MalwareBazaar_Mirai_077_4b59c11f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b59c11f363a5bf3ee784e63da1c21cad0da71aebfe39d20b727a2bc6194ed3a"
    family = "Mirai"
    file_name = "LSD"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:58"
  condition:
    hash.sha256(0, filesize) == "4b59c11f363a5bf3ee784e63da1c21cad0da71aebfe39d20b727a2bc6194ed3a"
}

rule MalwareBazaar_Mirai_078_60a58ace
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60a58ace3a7f7f4e64651307b54980c888b39afccbc36c08044e80919ca918f1"
    family = "Mirai"
    file_name = "BHRm"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:02"
  condition:
    hash.sha256(0, filesize) == "60a58ace3a7f7f4e64651307b54980c888b39afccbc36c08044e80919ca918f1"
}

rule MalwareBazaar_Mirai_079_1a19fa12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a19fa12c43acc758d6e6bdedeb9dc712b427c29e1f623dcdee9d2c36049eea6"
    family = "Mirai"
    file_name = "uOa"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:01"
  condition:
    hash.sha256(0, filesize) == "1a19fa12c43acc758d6e6bdedeb9dc712b427c29e1f623dcdee9d2c36049eea6"
}

rule MalwareBazaar_Mirai_080_70ca605f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ca605f6de6dcbda5f2374923a10b60774aba2d33c23d17ffbaff5889546dd8"
    family = "Mirai"
    file_name = "rWH"
    file_type = "elf"
    first_seen = "2026-07-27 19:08:00"
  condition:
    hash.sha256(0, filesize) == "70ca605f6de6dcbda5f2374923a10b60774aba2d33c23d17ffbaff5889546dd8"
}

rule MalwareBazaar_Mirai_081_c0e8d8f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0e8d8f831e09a7475511eb6f1abdd112cece025c72f3de814f15da2b00fcf6f"
    family = "Mirai"
    file_name = "dmff"
    file_type = "elf"
    first_seen = "2026-07-27 19:07:58"
  condition:
    hash.sha256(0, filesize) == "c0e8d8f831e09a7475511eb6f1abdd112cece025c72f3de814f15da2b00fcf6f"
}

rule MalwareBazaar_SalatStealer_082_89d0178c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63"
    family = "SalatStealer"
    file_name = "DiscordMirror.exe"
    file_type = "exe"
    first_seen = "2026-07-27 19:02:51"
  condition:
    hash.sha256(0, filesize) == "89d0178c292a0230d69c1de53f5e55994d195329cbbbacbaa7fb2e6101917b63"
}

rule MalwareBazaar_unknown_083_da5c52f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da5c52f4c5ea577b48c2735aade14fdc94c2244c970836189fe4f8bb6f31203b"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-27 19:02:06"
  condition:
    hash.sha256(0, filesize) == "da5c52f4c5ea577b48c2735aade14fdc94c2244c970836189fe4f8bb6f31203b"
}

rule MalwareBazaar_SalatStealer_084_a7c07b87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a"
    family = "SalatStealer"
    file_name = "DiscordMirror.exe"
    file_type = "exe"
    first_seen = "2026-07-27 19:00:57"
  condition:
    hash.sha256(0, filesize) == "a7c07b87c4968d7ac8120e2c6fb40ccd615d1bd25d4445fbe129d7c66235740a"
}

rule MalwareBazaar_Efimer_085_50421a15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50421a15ad2458ac9518a4c8fe3b5c8341ac87d7838327d2eb55fa94fe334a39"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 18:53:00"
  condition:
    hash.sha256(0, filesize) == "50421a15ad2458ac9518a4c8fe3b5c8341ac87d7838327d2eb55fa94fe334a39"
}

rule MalwareBazaar_Phorpiex_086_a3b45408
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3b454082dcbf17d64ec6539870404fb7dd99ba49a69f7f4d98b1b31c436c199"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:50:56"
  condition:
    hash.sha256(0, filesize) == "a3b454082dcbf17d64ec6539870404fb7dd99ba49a69f7f4d98b1b31c436c199"
}

rule MalwareBazaar_unknown_087_23ca56a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23ca56a8e65909151facf54a1c40ab3b015e752901d6d76bfae0a784b5c91a3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:48:33"
  condition:
    hash.sha256(0, filesize) == "23ca56a8e65909151facf54a1c40ab3b015e752901d6d76bfae0a784b5c91a3e"
}

rule MalwareBazaar_unknown_088_7defdda6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7defdda6602cc54c73ad8cfe2e26e9465926795d6f73da1f3e3b7296be471916"
    family = "unknown"
    file_name = "Exhibition_of_the_Heart_demo.exe"
    file_type = "exe"
    first_seen = "2026-07-27 18:46:08"
  condition:
    hash.sha256(0, filesize) == "7defdda6602cc54c73ad8cfe2e26e9465926795d6f73da1f3e3b7296be471916"
}

rule MalwareBazaar_Phorpiex_089_72da1a3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72da1a3abc1230fdbb9a1a7ac21b490b6482e14cbcfa9b8f5913af03d99fabde"
    family = "Phorpiex"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:44:43"
  condition:
    hash.sha256(0, filesize) == "72da1a3abc1230fdbb9a1a7ac21b490b6482e14cbcfa9b8f5913af03d99fabde"
}

rule MalwareBazaar_unknown_090_8ca38b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ca38b5e845b77ddf26b2596698c4dd7f4033e86b998e27cda460cfd9377de81"
    family = "unknown"
    file_name = "EROAPPLI.exe"
    file_type = "exe"
    first_seen = "2026-07-27 18:36:43"
  condition:
    hash.sha256(0, filesize) == "8ca38b5e845b77ddf26b2596698c4dd7f4033e86b998e27cda460cfd9377de81"
}

rule MalwareBazaar_Mirai_091_8feaac03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8feaac0336a3b0eb37cf9ca2981edf2842691ba492a0e169f9bf1a57a8af4c65"
    family = "Mirai"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-27 18:35:58"
  condition:
    hash.sha256(0, filesize) == "8feaac0336a3b0eb37cf9ca2981edf2842691ba492a0e169f9bf1a57a8af4c65"
}

rule MalwareBazaar_Mirai_092_662cd578
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "662cd578323fc9cfa37332bf9148479a99e67b61c0315e09feda63ac9761878f"
    family = "Mirai"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-27 18:34:58"
  condition:
    hash.sha256(0, filesize) == "662cd578323fc9cfa37332bf9148479a99e67b61c0315e09feda63ac9761878f"
}

rule MalwareBazaar_SalatStealer_093_ab4394c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:33:30"
  condition:
    hash.sha256(0, filesize) == "ab4394c429efc69b6927a5eb6ecfe7e2cc3df99dd2d279f96729d72a8283e85f"
}

rule MalwareBazaar_HijackLoader_094_62e631c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62e631c68ba9392dc91e19cdc4f5e00bc0e303764c9f5c27ce2be6bf40bcc933"
    family = "HijackLoader"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 18:12:43"
  condition:
    hash.sha256(0, filesize) == "62e631c68ba9392dc91e19cdc4f5e00bc0e303764c9f5c27ce2be6bf40bcc933"
}

rule MalwareBazaar_unknown_095_fdf1fc9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0"
    family = "unknown"
    file_name = "fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0"
    file_type = "sh"
    first_seen = "2026-07-27 18:00:59"
  condition:
    hash.sha256(0, filesize) == "fdf1fc9a36c9fa06d23e26dc512f9cd71725298fedc0eca768493c27ab4744b0"
}

rule MalwareBazaar_Formbook_096_5326cd21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5326cd216b594557d92a20e67d1074e532c4817ebc078ca41e9d92d315c160e3"
    family = "Formbook"
    file_name = "z9QUOTATIONORDER.exe"
    file_type = "exe"
    first_seen = "2026-07-27 18:00:06"
  condition:
    hash.sha256(0, filesize) == "5326cd216b594557d92a20e67d1074e532c4817ebc078ca41e9d92d315c160e3"
}

rule MalwareBazaar_RemusStealer_097_7d98375b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d98375b03ed4def16841cc9b749a9297701edf20cba2f6f64bf96fcc995c79d"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 17:58:52"
  condition:
    hash.sha256(0, filesize) == "7d98375b03ed4def16841cc9b749a9297701edf20cba2f6f64bf96fcc995c79d"
}

rule MalwareBazaar_unknown_098_f4b60c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4b60c5084055d4b30b3288bd253c12610d4bec7f02739e43930a830db6c9d17"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-27 17:58:28"
  condition:
    hash.sha256(0, filesize) == "f4b60c5084055d4b30b3288bd253c12610d4bec7f02739e43930a830db6c9d17"
}

rule MalwareBazaar_LummaStealer_099_56cc93be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f"
    family = "LummaStealer"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-07-27 17:53:01"
  condition:
    hash.sha256(0, filesize) == "56cc93be915c0d59943d0bf3c91dc1956b0af95939b812679197d3607829713f"
}

rule MalwareBazaar_Efimer_100_e15b78ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e15b78ffb8b880b99ea1dbc2f51d1426fa0d72da39c10e5a0e364d62ccfaa1ce"
    family = "Efimer"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-27 17:52:50"
  condition:
    hash.sha256(0, filesize) == "e15b78ffb8b880b99ea1dbc2f51d1426fa0d72da39c10e5a0e364d62ccfaa1ce"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

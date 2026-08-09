# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-09

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 646 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 646 |
| Unique family labels | 14 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 39 |
| Mirai | 29 |
| RemusStealer | 12 |
| ConnectWise | 4 |
| Stealc | 4 |
| NanoCore | 2 |
| CoinMiner | 2 |
| MassLogger | 2 |
| QuasarRAT | 1 |
| WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 40 |
| elf | 30 |
| sh | 21 |
| unknown | 4 |
| vbs | 1 |
| bat | 1 |
| zip | 1 |
| apk | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `ff100c165b2714da`

| Field | Value |
|---|---|
| SHA-256 | `ff100c165b2714dad2a3b60efd7ba182ae4299e06edfcd1332bd679e6bc08e34` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-09 02:23:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35769af8264b13255393bc3f76f76202` |
| SHA-1 | `d62b50af94768e0f30ed64ed6b95429f7a840b98` |
| SHA-256 | `ff100c165b2714dad2a3b60efd7ba182ae4299e06edfcd1332bd679e6bc08e34` |
| SHA3-384 | `24267c393540e2f153e002b32c7ec9a9a7550331e3640d1ac71a373e5dc25c5d434077090b0d2ebe1dc9ba95e4762f80` |
| TLSH | `T1F3C27C966A867C44BEC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C15F9CD618B1A` |
| SSDEEP | `768:q88vCB+25j6es8Reif9FYpMSUpi+20qUpi+20YQX:/8l25J1d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_ff100c16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff100c165b2714dad2a3b60efd7ba182ae4299e06edfcd1332bd679e6bc08e34"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-09 02:23:53"
  condition:
    hash.sha256(0, filesize) == "ff100c165b2714dad2a3b60efd7ba182ae4299e06edfcd1332bd679e6bc08e34"
}
```

### Sample 2: `1ae9cd2b41297f16`

| Field | Value |
|---|---|
| SHA-256 | `1ae9cd2b41297f16ce7dc361cae4b890a984c792351b198c1190d093a908e0e5` |
| Family label | `NanoCore` |
| File name | `291E68D417E3A13F19BD630EB5533CB5.exe` |
| File type | `exe` |
| First seen | `2026-08-09 02:15:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `291e68d417e3a13f19bd630eb5533cb5` |
| SHA-1 | `8d089543611ac97e4511fcb835a6e846bc07a54b` |
| SHA-256 | `1ae9cd2b41297f16ce7dc361cae4b890a984c792351b198c1190d093a908e0e5` |
| SHA3-384 | `eccc1b3ea4184e9855350dab0dd43eebea2d421275d21a64d3a0cb5dfde6beed417e8fbc9cdea511f8770859b8d533b5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D914C05677A94A2FD2DE82B9612211439378C2E399C3F7EE28D464B74F263E50A071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5vMBrwBJnaMC8xFev7y4QT1t1:MLV6BtpmkuMFIPHPe2Dt1` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_002_1ae9cd2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae9cd2b41297f16ce7dc361cae4b890a984c792351b198c1190d093a908e0e5"
    family = "NanoCore"
    file_name = "291E68D417E3A13F19BD630EB5533CB5.exe"
    file_type = "exe"
    first_seen = "2026-08-09 02:15:05"
  condition:
    hash.sha256(0, filesize) == "1ae9cd2b41297f16ce7dc361cae4b890a984c792351b198c1190d093a908e0e5"
}
```

### Sample 3: `14a0c3c28384e040`

| Field | Value |
|---|---|
| SHA-256 | `14a0c3c28384e040fcf9317dacd5400b9cecd9bdde92fff5f242671fab246a98` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-09 02:09:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2970988d94b0a67f2d1934939f84e321` |
| SHA-1 | `7462a5ce8de9b2f2180f1711c0a2e3842240612b` |
| SHA-256 | `14a0c3c28384e040fcf9317dacd5400b9cecd9bdde92fff5f242671fab246a98` |
| SHA3-384 | `81a0f644e546a1f56e513ba2a9b1a29b5f6cc475c53236b2c1c5fe3a7b443b18f42b523b6bc4a6bfaf3abe785d2b679e` |
| TLSH | `T188016BC6E3209910406A985E26E66690B470C3C7094A0B7C7FDCD53DBB88E14B13AF84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha5vqj/Q80FRzMvmU7:e9Qp+Ms5v+/QFS+U7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_14a0c3c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14a0c3c28384e040fcf9317dacd5400b9cecd9bdde92fff5f242671fab246a98"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-09 02:09:58"
  condition:
    hash.sha256(0, filesize) == "14a0c3c28384e040fcf9317dacd5400b9cecd9bdde92fff5f242671fab246a98"
}
```

### Sample 4: `c8d5f2f64803a262`

| Field | Value |
|---|---|
| SHA-256 | `c8d5f2f64803a2623f1d2178757b5f48329eaebaa659e4ed8bdbe1b0e7829308` |
| Family label | `Mirai` |
| File name | `data_aarch64` |
| File type | `elf` |
| First seen | `2026-08-09 02:02:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4b0cf7b88d6d3cd9d3ab1d95a2ddaf8` |
| SHA-1 | `17b0b6f164417eb6f3402697630dbb1fa168d9a0` |
| SHA-256 | `c8d5f2f64803a2623f1d2178757b5f48329eaebaa659e4ed8bdbe1b0e7829308` |
| SHA3-384 | `97c4dad68f867cb4c5a1a4e70e32ed2425b5184b8547dc7e05f83be34ec6f03d57c63fcc447f9735c61d577a6002d5dc` |
| TLSH | `T123E47D9DFE4E3C42E2D7E278DA4987E1722B71E0D32391A37982034CD5C6DD9CBA1925` |
| SSDEEP | `12288:y6ynGMcqdceAXLMclUdmUGA9uu4jSPjhhe1vwZrL/ynpLDFw5X4t5d0:yrnmTeAX2H9uu4jS91IpL3z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_c8d5f2f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8d5f2f64803a2623f1d2178757b5f48329eaebaa659e4ed8bdbe1b0e7829308"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-08-09 02:02:02"
  condition:
    hash.sha256(0, filesize) == "c8d5f2f64803a2623f1d2178757b5f48329eaebaa659e4ed8bdbe1b0e7829308"
}
```

### Sample 5: `96282f6e46762cc2`

| Field | Value |
|---|---|
| SHA-256 | `96282f6e46762cc263af994af5ce98d82b9d7291f2d4f16e9ea8139db6830b6f` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-09 02:01:58` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db43287f7119f004d6dbbb82f3032fe7` |
| SHA-1 | `07215d93fe7a47a03f2b8838807bdfc914087a3a` |
| SHA-256 | `96282f6e46762cc263af994af5ce98d82b9d7291f2d4f16e9ea8139db6830b6f` |
| SHA3-384 | `16f29aba70d13ed086f369518dd10250e4ec82d44d4f87343c314521735fcaa4a9649c5638e3019980cd5da4806fe9e9` |
| TLSH | `T17401C2C6E33459004099945D26D76554F430C3C7194A4F7CBFACE53DAB84D14B03AF84` |
| SSDEEP | `24:kXCKysE2hi0ziQvZoha5mjZQ7FRzAvm4X:e9Qp+Ms5yZQBm+4X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_96282f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96282f6e46762cc263af994af5ce98d82b9d7291f2d4f16e9ea8139db6830b6f"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-09 02:01:58"
  condition:
    hash.sha256(0, filesize) == "96282f6e46762cc263af994af5ce98d82b9d7291f2d4f16e9ea8139db6830b6f"
}
```

### Sample 6: `165c672e9b063ba3`

| Field | Value |
|---|---|
| SHA-256 | `165c672e9b063ba3e5dba0f42cfa9399819cac49cc96310078a8208a93dcb888` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-09 01:55:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `829f6184e903e7f61a955cb7193f6a30` |
| SHA-1 | `7071c7c54d58b2327519e5dc7d2db2eea54d4edb` |
| SHA-256 | `165c672e9b063ba3e5dba0f42cfa9399819cac49cc96310078a8208a93dcb888` |
| SHA3-384 | `b2763a19b1e42830bf73662c1f1b1f9c7f958542c4996f92f629c2761e8d6a3a029ed833c0743a469fa583df54fc98fb` |
| TLSH | `T19601AFCA8524590000A99A2E269B50A4F820C3CF254A0F69FFAD2D3DEB84C14F07AFC8` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkahEC5Nj0OECu/GzHjCl8FCmFLNFj1ChMHP:kXCKysE2hi0ziQvZoha2UI3/GvTNf1HX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_165c672e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "165c672e9b063ba3e5dba0f42cfa9399819cac49cc96310078a8208a93dcb888"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-09 01:55:40"
  condition:
    hash.sha256(0, filesize) == "165c672e9b063ba3e5dba0f42cfa9399819cac49cc96310078a8208a93dcb888"
}
```

### Sample 7: `81ccc89654440104`

| Field | Value |
|---|---|
| SHA-256 | `81ccc89654440104a015203014b42dfee2a32ea8578c58f618368035c3977f4e` |
| Family label | `unknown` |
| File name | `gg2` |
| File type | `elf` |
| First seen | `2026-08-09 01:31:44` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `718d6c43f0f4ea99587f13194b04a06a` |
| SHA-1 | `1f9a63973042ed1575ea942de53062a44999f50d` |
| SHA-256 | `81ccc89654440104a015203014b42dfee2a32ea8578c58f618368035c3977f4e` |
| SHA3-384 | `7d0c41a68fd75ba1413284704e22e471dacf59dab27bda89e84ab9b17e6b20219db454d1dd57344ab6f87b7834a7b4b6` |
| TLSH | `T1CE95D657E8B950E8C0EED575C766E617BEA13849033837E76FA19A201F16FE0A0BD710` |
| TELFHASH | `t1703269750abd35b5b695da10b3a3b4f496771ca562f938b11063ad81ffc1e801ce283b` |
| SSDEEP | `49152:a7225gSTf7Lg0gMbOSBGN0x642ckrCx9w:a7WSHIWx9w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_81ccc896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ccc89654440104a015203014b42dfee2a32ea8578c58f618368035c3977f4e"
    family = "unknown"
    file_name = "gg2"
    file_type = "elf"
    first_seen = "2026-08-09 01:31:44"
  condition:
    hash.sha256(0, filesize) == "81ccc89654440104a015203014b42dfee2a32ea8578c58f618368035c3977f4e"
}
```

### Sample 8: `5635c7f820a74962`

| Field | Value |
|---|---|
| SHA-256 | `5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f` |
| Family label | `unknown` |
| File name | `5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f` |
| File type | `sh` |
| First seen | `2026-08-09 01:30:12` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b993ddf0aba6465f821e232571ffcd3` |
| SHA-1 | `1aba4b25d9f4435930d67e82c4a982535e79e4c9` |
| SHA-256 | `5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f` |
| SHA3-384 | `1a89985fdbd13f07e0f283e036cfc19acf1c0caafcacbfa5d22887bb3485d6c46476d628c57ce8743a7f733e993cfe2c` |
| TLSH | `T1FF118BE3F9768A32B9E9007F6B19A01495CB096F49106D25B48D7C206F2D918B04AF2B` |
| SSDEEP | `24:ChRIuwFFawHtLJxVk96ZwuwFF8QpeewKw1YFVCf1C6JZ71C9FnOs:ChRCaEtLJPk9uw8QwznmIfo6JZ7ofOs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_5635c7f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f"
    family = "unknown"
    file_name = "5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f"
    file_type = "sh"
    first_seen = "2026-08-09 01:30:12"
  condition:
    hash.sha256(0, filesize) == "5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f"
}
```

### Sample 9: `189f392aa5cae728`

| Field | Value |
|---|---|
| SHA-256 | `189f392aa5cae728665ebeb83f61698cc69ee653215e9e44eb8bdd2db5794101` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-09 01:29:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9def67224eecf77920d004d1de13a6bc` |
| SHA-1 | `4914e0005959084a2ec300ad5f0bbc1ff71ac669` |
| SHA-256 | `189f392aa5cae728665ebeb83f61698cc69ee653215e9e44eb8bdd2db5794101` |
| SHA3-384 | `0a82459e22292589563e5cc967ef78caa866b13cf67db88fdca60146cec39a9b6ff3c10ad1ba9338b8ea45c02d34ef82` |
| TLSH | `T180236D661A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCB3CF28C5A69D910971D` |
| SSDEEP | `768:kXRWNGxVk9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Ylx7cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_189f392a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189f392aa5cae728665ebeb83f61698cc69ee653215e9e44eb8bdd2db5794101"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 01:29:38"
  condition:
    hash.sha256(0, filesize) == "189f392aa5cae728665ebeb83f61698cc69ee653215e9e44eb8bdd2db5794101"
}
```

### Sample 10: `b066f44977c70c68`

| Field | Value |
|---|---|
| SHA-256 | `b066f44977c70c685830e003af6b6e05c230d7f0a74241ca92b72ceb308fea49` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-09 01:25:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `822c68d32d2129520c63b19bcb1d0558` |
| SHA-1 | `beacac1acb771a9325b8529c8d7c66ad5a28177d` |
| SHA-256 | `b066f44977c70c685830e003af6b6e05c230d7f0a74241ca92b72ceb308fea49` |
| SHA3-384 | `60a0500abf06ca2e14b61561b19afa9dd9aaf3b8f2be28bdd8a2684f3b6ab7abbacee437c60ea63d499469d23260591d` |
| TLSH | `T17CC27D956A867C44BEC94B3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11F9CD618B1A` |
| SSDEEP | `768:wp8vCB+25j6es8RT69FYpMSUpi+20qUpi+20YQX:U8l25JId2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_b066f449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b066f44977c70c685830e003af6b6e05c230d7f0a74241ca92b72ceb308fea49"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-09 01:25:42"
  condition:
    hash.sha256(0, filesize) == "b066f44977c70c685830e003af6b6e05c230d7f0a74241ca92b72ceb308fea49"
}
```

### Sample 11: `9b9ba2f52c6346ee`

| Field | Value |
|---|---|
| SHA-256 | `9b9ba2f52c6346eec1f443e7a096175d57dcae5ac133e6050b1ca704c2da6ecf` |
| Family label | `unknown` |
| File name | `payload.sh` |
| File type | `sh` |
| First seen | `2026-08-09 01:17:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0601ca4ad7a1e0acf7bb8f15c3e414a` |
| SHA-1 | `f91d777f8e2ab0a542134c15250e7de439cd05ef` |
| SHA-256 | `9b9ba2f52c6346eec1f443e7a096175d57dcae5ac133e6050b1ca704c2da6ecf` |
| SHA3-384 | `c91ef5bf47990931fa3d0e571752ec3ac6b89ad7dc9bf7e3bed517c6b29ab86e3ca5c8e6fa963f68c36d3718c50430b5` |
| TLSH | `T1B0C08C9C01A91C237A22C813501184303266BDC095C4AB24E6CDA932428CE003021383` |
| SSDEEP | `3:TKH4vGBwOnQzVQNKKhC8pnhFMv7nhFMv1HK48aOSLK4FLV2:h96YKdph87h8NOa9Kb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_9b9ba2f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b9ba2f52c6346eec1f443e7a096175d57dcae5ac133e6050b1ca704c2da6ecf"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-08-09 01:17:37"
  condition:
    hash.sha256(0, filesize) == "9b9ba2f52c6346eec1f443e7a096175d57dcae5ac133e6050b1ca704c2da6ecf"
}
```

### Sample 12: `8579180f2f57cb3d`

| Field | Value |
|---|---|
| SHA-256 | `8579180f2f57cb3d7e837e0392f421427d93d9d18cb6378a2ae7c5e9375403af` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-09 01:15:38` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `871350a1d48c264920b17cdb2e22f0e1` |
| SHA-1 | `b54fb78b178c53759c9b4b8e22ad7b0947e20ab0` |
| SHA-256 | `8579180f2f57cb3d7e837e0392f421427d93d9d18cb6378a2ae7c5e9375403af` |
| SHA3-384 | `833651e3a30d4bcfedb86f2e420199dd86bcb94e3d7db5c1ef2c13abbc28f581cbfec373fefaf153c04992a5b9b895d3` |
| TLSH | `T1723110DE04251A311402CE4E76722549B6CEA3EB389FD7D4DD480EEA41487DCF266F6D` |
| SSDEEP | `12:UZ6fXJWJ6NWXU6NWXgNpi6pvr6RQGD62dGFG26FGG/zlBE6BkC76UHFb6FiDTZ3q:ZXJWJHKm0V/vFlGlrgf8ZTn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_8579180f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8579180f2f57cb3d7e837e0392f421427d93d9d18cb6378a2ae7c5e9375403af"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-09 01:15:38"
  condition:
    hash.sha256(0, filesize) == "8579180f2f57cb3d7e837e0392f421427d93d9d18cb6378a2ae7c5e9375403af"
}
```

### Sample 13: `1384a023aa9e76d0`

| Field | Value |
|---|---|
| SHA-256 | `1384a023aa9e76d0f579ca471ba7769b824de74ca0ea728f4efc65cdb13e9a79` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-09 01:11:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03681c8c06db0c2b39681d3517dca70b` |
| SHA-1 | `901aaa992f577e85eb02c183be0906bbfa6b94f6` |
| SHA-256 | `1384a023aa9e76d0f579ca471ba7769b824de74ca0ea728f4efc65cdb13e9a79` |
| SHA3-384 | `7be94ed06216021688f06cb913794e1ab753c562d1ab4cdffc7f463b3b3b696a451bab4afd16c25818a132080323744d` |
| TLSH | `T17F235C5516857C24AE99C4361C7E2F0CB9AD43E6324452EE7FCF3CF28C4A6AD910971D` |
| SSDEEP | `768:E+d9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:E++cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_1384a023
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1384a023aa9e76d0f579ca471ba7769b824de74ca0ea728f4efc65cdb13e9a79"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 01:11:40"
  condition:
    hash.sha256(0, filesize) == "1384a023aa9e76d0f579ca471ba7769b824de74ca0ea728f4efc65cdb13e9a79"
}
```

### Sample 14: `525b378c9abf58b0`

| Field | Value |
|---|---|
| SHA-256 | `525b378c9abf58b083365cd178a7a611c19ae0107346a714df6ba450eed172ab` |
| Family label | `QuasarRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 00:44:58` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9af0a77bfadaa41b1ae3c2fbe697d268` |
| SHA-1 | `84eb6830359365896e55ea6cd1e9555b1fe769cd` |
| SHA-256 | `525b378c9abf58b083365cd178a7a611c19ae0107346a714df6ba450eed172ab` |
| SHA3-384 | `f5bfc636d3b509cd6096666d896afd02a6840e4f42423b383f600276254cd11134f27be54debe3e89fd3a3fbf82cbdbf` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T120E56B143BF85E27E1BBE277E5B0041267F0FC1AB363EB0B6581677A1C53B5098426A7` |
| SSDEEP | `49152:LvXlL26AaNeWgPhlmVqvMQ7XSKD9RJ6UbR3LoGdvLvTHHB72eh2NT:LvVL26AaNeWgPhlmVqkQ7XSKD9RJ6ef` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_014_525b378c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "525b378c9abf58b083365cd178a7a611c19ae0107346a714df6ba450eed172ab"
    family = "QuasarRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 00:44:58"
  condition:
    hash.sha256(0, filesize) == "525b378c9abf58b083365cd178a7a611c19ae0107346a714df6ba450eed172ab"
}
```

### Sample 15: `bfe753d1f3edb651`

| Field | Value |
|---|---|
| SHA-256 | `bfe753d1f3edb65136b2016f54206d0ffb4b41f546317c222e29d5b97f8e3cd9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-09 00:44:34` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb99edfe15ba2b57b021b642d34c392c` |
| SHA-1 | `3a999351d4d91b8ae21ba8b2dca80f8b95f8671b` |
| SHA-256 | `bfe753d1f3edb65136b2016f54206d0ffb4b41f546317c222e29d5b97f8e3cd9` |
| SHA3-384 | `d3230d53f2445bcdd9df016cc835502c8928bb1cdfc2cea3f6c81a6df46b8989e74007b54066b0dae0ebd48062c25ed1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18B730201BFA44993ED7A44BF0DEADB123212D3A959F227FC45E02462AF6B4D47811F72` |
| SSDEEP | `1536:YXv0UfGlFNRIUake7zO1o9jm3FxvRvk6Sjt3DQL/oXD6uK677jiGuq:YXMUsFNuL3D9K3xv0t3A/wDoQ7jidq` |
| ICON-DHASH | `11f0d8b0b2e4b0b1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_bfe753d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfe753d1f3edb65136b2016f54206d0ffb4b41f546317c222e29d5b97f8e3cd9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 00:44:34"
  condition:
    hash.sha256(0, filesize) == "bfe753d1f3edb65136b2016f54206d0ffb4b41f546317c222e29d5b97f8e3cd9"
}
```

### Sample 16: `14aacad3920f6c0d`

| Field | Value |
|---|---|
| SHA-256 | `14aacad3920f6c0db67f25dd6948b434cdea5b3d5179656c6905e2346bf462ca` |
| Family label | `NanoCore` |
| File name | `D5FC6906D2B2290A17CBF16A0618B4C8.exe` |
| File type | `exe` |
| First seen | `2026-08-09 00:40:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5fc6906d2b2290a17cbf16a0618b4c8` |
| SHA-1 | `583c74a790c50d6c118eafb948243eecc0de0551` |
| SHA-256 | `14aacad3920f6c0db67f25dd6948b434cdea5b3d5179656c6905e2346bf462ca` |
| SHA3-384 | `8c9bb29d62f0533f1fc423b6ddb8ab8a756736e18e23670de6a42b43cf01f1fb1c19fe113f1a4a208d91009440e10e84` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17114CF1677A94A2FD2DE82B961221143937CC2E399C3F7EE28D464B74F267E50A071D3` |
| SSDEEP | `6144:sLV6Bta6dtJmakIM5AMBrwBJnaMC8xFev7y4QT1tdH:sLV6BtpmkxMFIPHPe2DtdH` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_016_14aacad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14aacad3920f6c0db67f25dd6948b434cdea5b3d5179656c6905e2346bf462ca"
    family = "NanoCore"
    file_name = "D5FC6906D2B2290A17CBF16A0618B4C8.exe"
    file_type = "exe"
    first_seen = "2026-08-09 00:40:06"
  condition:
    hash.sha256(0, filesize) == "14aacad3920f6c0db67f25dd6948b434cdea5b3d5179656c6905e2346bf462ca"
}
```

### Sample 17: `efd4f7312bab2d65`

| Field | Value |
|---|---|
| SHA-256 | `efd4f7312bab2d6554c20b553198d89e6a64f5b4222e70f44479e8a472ecf622` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-08 23:52:39` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39249b2244e06310cde733f66eade573` |
| SHA-1 | `9bcc8ea6a53855202596ac822cc49d883e8a12d6` |
| SHA-256 | `efd4f7312bab2d6554c20b553198d89e6a64f5b4222e70f44479e8a472ecf622` |
| SHA3-384 | `d69ee1a0d5c58f26c0dac0b4f1a67e60132d126fa41e8cee33117dbfdab1aac0db87e89725271ec14a45ff44b3151b74` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T195E6338826D102EEFAB3917CDAC34655E970B87A4771C6D747EC46851EA31E0C93EB23` |
| SSDEEP | `393216:KGmqAK0nhm9K5N9UcKIfdkmXbR5pmgGfXMCHWUj2cuI3/PGTAI:KG4Kj1tIfdk2N5pmgAXMb8LH/O7` |
| ICON-DHASH | `70f0e4c4c4e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_efd4f731
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efd4f7312bab2d6554c20b553198d89e6a64f5b4222e70f44479e8a472ecf622"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 23:52:39"
  condition:
    hash.sha256(0, filesize) == "efd4f7312bab2d6554c20b553198d89e6a64f5b4222e70f44479e8a472ecf622"
}
```

### Sample 18: `f1d67dc388635f8e`

| Field | Value |
|---|---|
| SHA-256 | `f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d` |
| Family label | `unknown` |
| File name | `f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d` |
| File type | `unknown` |
| First seen | `2026-08-08 23:30:23` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2421f233e9c2756f533a12f3bc826f80` |
| SHA-256 | `f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_f1d67dc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d"
    family = "unknown"
    file_name = "f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d"
    file_type = "unknown"
    first_seen = "2026-08-08 23:30:23"
  condition:
    hash.sha256(0, filesize) == "f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d"
}
```

### Sample 19: `e2fb15fcc8e1aa05`

| Field | Value |
|---|---|
| SHA-256 | `e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0` |
| Family label | `WannaCry` |
| File name | `e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0` |
| File type | `exe` |
| First seen | `2026-08-08 23:16:00` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834f4cca9dd2d6c3c49aa285bb4d9ddd` |
| SHA-1 | `fce4ad464817ba3a3174b8598ec269133d5f6df7` |
| SHA-256 | `e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0` |
| SHA3-384 | `43fa03c1ae71ad102be2050d238bca0c4615ddfa585c8efd30b3288e6cc2af1cceca8235b8bfc785da93706d0cdf16ec` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1A036235931BCC2BCD506197480BB8E26F6B3BC5E47FE6B0F0B404A6A1E53B46B760752` |
| SSDEEP | `49152:jnsnHqMSPbcBpiDimh1INRx+TSqTdX1HkQo6SAARdhQ:DMHqPoBpiOmh1aRxcSUDk36SAEdhQ` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_019_e2fb15fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0"
    family = "WannaCry"
    file_name = "e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0"
    file_type = "exe"
    first_seen = "2026-08-08 23:16:00"
  condition:
    hash.sha256(0, filesize) == "e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0"
}
```

### Sample 20: `528d0352c0374f48`

| Field | Value |
|---|---|
| SHA-256 | `528d0352c0374f48b23023f0dac9d907d744a5bb9f73990a3be40fba5bd3526f` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-08 22:52:35` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b44318d4c75e23c6946587b6b1d75272` |
| SHA-1 | `e4ab13faf2f94640068c4ab3dd137c77f0c03121` |
| SHA-256 | `528d0352c0374f48b23023f0dac9d907d744a5bb9f73990a3be40fba5bd3526f` |
| SHA3-384 | `c13378efffaa9d72dadf326c7722bfdebe581ee8fb1d49400eafda1121c3509e2378908093fbcc2bed5a0f8fb9c86b42` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T138E633082AE497AEFAB3813DD9E11AD49E76B4715734C9CB47BC47B06E172E04E34A13` |
| SSDEEP | `393216:5Gm0aFOOUvHJxStQUmeXMCHWUjzcuI3/PGTAI:5GZmc/JxJVeXMb8wH/O7` |
| ICON-DHASH | `e4b960c0dcf97258` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_528d0352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "528d0352c0374f48b23023f0dac9d907d744a5bb9f73990a3be40fba5bd3526f"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 22:52:35"
  condition:
    hash.sha256(0, filesize) == "528d0352c0374f48b23023f0dac9d907d744a5bb9f73990a3be40fba5bd3526f"
}
```

### Sample 21: `20a0bd6ed113a2e5`

| Field | Value |
|---|---|
| SHA-256 | `20a0bd6ed113a2e57b4d108f8168234317be9f54e3399048b1f53b4899dc729d` |
| Family label | `unknown` |
| File name | `TESTING.x64.3.vbs` |
| File type | `vbs` |
| First seen | `2026-08-08 22:32:14` |
| Reporter | `skocherhan` |
| Tags | `github-Latest-ai-pro, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a81eddefcc13f42916c4ea67d0262fb1` |
| SHA-1 | `f5fe4168fa6d05b428dd5332b71da3b6097d0086` |
| SHA-256 | `20a0bd6ed113a2e57b4d108f8168234317be9f54e3399048b1f53b4899dc729d` |
| SHA3-384 | `6fb96d334bcd7293de197f52dbb7cb5dc00e03bd02bb75bfe735239d4903d9a09b73c039e3643d39073eba397aa5ea76` |
| TLSH | `T1C9471260AE142ADC4AB547F3B0E9E6E8D97107F3CF019D1E0115DDB79E721CF9A2281A` |
| SSDEEP | `49152:5K/tW2LWJiaTnFK7vkdOYGmSAGv+iW+09hzDvDrCXga09u2ksRXTrf+Ren6stbHs:s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_20a0bd6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20a0bd6ed113a2e57b4d108f8168234317be9f54e3399048b1f53b4899dc729d"
    family = "unknown"
    file_name = "TESTING.x64.3.vbs"
    file_type = "vbs"
    first_seen = "2026-08-08 22:32:14"
  condition:
    hash.sha256(0, filesize) == "20a0bd6ed113a2e57b4d108f8168234317be9f54e3399048b1f53b4899dc729d"
}
```

### Sample 22: `7a64f51ad67677b7`

| Field | Value |
|---|---|
| SHA-256 | `7a64f51ad67677b7d0aeab9c5b0e6844bcf6f3d0b0970fbf8d9f3052b6be152d` |
| Family label | `ConnectWise` |
| File name | `DocuSignSetup.bat` |
| File type | `bat` |
| First seen | `2026-08-08 22:28:15` |
| Reporter | `skocherhan` |
| Tags | `bat, ConnectWise, github-Latest-ai-pro` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6eb3349842db62405fe6eaafd808df74` |
| SHA-1 | `35267f9bf33ed3c337a3dbcf8319e4b8773de93a` |
| SHA-256 | `7a64f51ad67677b7d0aeab9c5b0e6844bcf6f3d0b0970fbf8d9f3052b6be152d` |
| SHA3-384 | `0e21f99a26b5499bd8bdc1e13ef7dee99b8630c14345fc3c411a12449211b0c1ba5632849611dda1ef6d91e41f4a11e2` |
| TLSH | `T1D1C6233A89466BDF0B1576A561097D026DD827635F41232EEB8C416138E86B0CF7EEFC` |
| SSDEEP | `49152:UWpsS4Fe/lrTJAAsVIdoL3Q3vUv/FFT0e4d8eKzXKulM8MleKwVGcKBv/iNyeK5p:z` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_022_7a64f51a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a64f51ad67677b7d0aeab9c5b0e6844bcf6f3d0b0970fbf8d9f3052b6be152d"
    family = "ConnectWise"
    file_name = "DocuSignSetup.bat"
    file_type = "bat"
    first_seen = "2026-08-08 22:28:15"
  condition:
    hash.sha256(0, filesize) == "7a64f51ad67677b7d0aeab9c5b0e6844bcf6f3d0b0970fbf8d9f3052b6be152d"
}
```

### Sample 23: `7962a14f33edc9be`

| Field | Value |
|---|---|
| SHA-256 | `7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce` |
| Family label | `unknown` |
| File name | `7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce` |
| File type | `elf` |
| First seen | `2026-08-08 22:27:13` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ae4f040e9fec45dcd029f7d49215bda` |
| SHA-1 | `844858863abc7ba8067b56d33e5bd28a09d28085` |
| SHA-256 | `7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce` |
| SHA3-384 | `509fd6d49d482379e78d020bc7d8b15e29a8c079fb3a1c930ddebff3df55e061ebd0c0ff02b95b6530c99b8b8c9435cf` |
| TLSH | `T10147DF77814338D9E5A98DB4D41025426DAC388B5738A3C7BAC871F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQe:cqYUQuVDt0TZE9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_7962a14f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce"
    family = "unknown"
    file_name = "7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce"
    file_type = "elf"
    first_seen = "2026-08-08 22:27:13"
  condition:
    hash.sha256(0, filesize) == "7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce"
}
```

### Sample 24: `d05c5a998ee2b22b`

| Field | Value |
|---|---|
| SHA-256 | `d05c5a998ee2b22bbe326ed96da8ee469de4f18786a278d2681eee9b4329bd1a` |
| Family label | `Stealc` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-08-08 21:52:43` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29336ba80d6d28ed8edaa6ddcb4f40af` |
| SHA-1 | `d8afda1f3961a61b96d34823cc0e71086ba71547` |
| SHA-256 | `d05c5a998ee2b22bbe326ed96da8ee469de4f18786a278d2681eee9b4329bd1a` |
| SHA3-384 | `9f3047816c7807680182871d0c6ba2e6a4ab75ff53f77f39356942d1ca29eac479a54c3bec71746be62a516f63c51a54` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1C795235012E886A5F4F1E7B48AF1C59B9971BC832F285AFF22C4665F7922FC0E434719` |
| SSDEEP | `49152:kpLL4A/uPIPxfWHtQunVGOg8kMcHo+R2ASFZZelv7eLH:k4AqIp+q0VGOBkMcn2A2Zclv` |
| ICON-DHASH | `6261c8d2f2b294c8` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_024_d05c5a99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d05c5a998ee2b22bbe326ed96da8ee469de4f18786a278d2681eee9b4329bd1a"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-08 21:52:43"
  condition:
    hash.sha256(0, filesize) == "d05c5a998ee2b22bbe326ed96da8ee469de4f18786a278d2681eee9b4329bd1a"
}
```

### Sample 25: `4abc52fb3e70420e`

| Field | Value |
|---|---|
| SHA-256 | `4abc52fb3e70420e020a6e7ec2a0c23af8a30deedfd0298266bf5a857af33e11` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-08 21:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1495a367831b27b47c85b518c33fba23` |
| SHA-1 | `f931a28a9aa5a6a421ac2ac4186339f63cf8a2c7` |
| SHA-256 | `4abc52fb3e70420e020a6e7ec2a0c23af8a30deedfd0298266bf5a857af33e11` |
| SHA3-384 | `ea805903d0d305cb32658e80e649e36c1f7500fad298ea0cefdba8cfcba6c7b939db043f53b32fb44819b58625447fe6` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DFE6334C66D013EEE6B3803CD9E21591EAB1B0639376C6E78F6447695E273E04D3E623` |
| SSDEEP | `393216:LGmq6ojOX9HqKIKbDwMIeW/nXMCHWUjocuI3/PGTAI:LGtOXJqrMDwMIeiXMb8dH/O7` |
| ICON-DHASH | `71f0e4d6e6e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_4abc52fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4abc52fb3e70420e020a6e7ec2a0c23af8a30deedfd0298266bf5a857af33e11"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 21:52:31"
  condition:
    hash.sha256(0, filesize) == "4abc52fb3e70420e020a6e7ec2a0c23af8a30deedfd0298266bf5a857af33e11"
}
```

### Sample 26: `344f930a6ecd8ca5`

| Field | Value |
|---|---|
| SHA-256 | `344f930a6ecd8ca55f4912998c3c64f2149f9cae88ab7b8a080e78ae81f29ba6` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-08-08 21:15:59` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `522d31a9a61f58acde8ce687d9eda8ce` |
| SHA-1 | `ac497f78198c154e321f133a7ab941a158fd2bae` |
| SHA-256 | `344f930a6ecd8ca55f4912998c3c64f2149f9cae88ab7b8a080e78ae81f29ba6` |
| SHA3-384 | `6734998fdfcc83d57b23e861896895af434e9bd0c42caf4f6d1947aac4781b4b0da076d82acafbfee9380984a3705511` |
| TLSH | `T112016BC98940E910406ADE5E22D76690B421C3CE458A0FB87F9C5A2DFBD8914F06AFA9` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaOC58BFAx8CbfeF+HmCShOs8FCYzCy2Qaa:kXCKysE2hi0ziQvZohaOeCHJkbNtt7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_344f930a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "344f930a6ecd8ca55f4912998c3c64f2149f9cae88ab7b8a080e78ae81f29ba6"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-08 21:15:59"
  condition:
    hash.sha256(0, filesize) == "344f930a6ecd8ca55f4912998c3c64f2149f9cae88ab7b8a080e78ae81f29ba6"
}
```

### Sample 27: `d93c40c43e8cd646`

| Field | Value |
|---|---|
| SHA-256 | `d93c40c43e8cd646ec9f17080a6414521554a7dd1a06afd3e61e03b20bab694f` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-08-08 21:12:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbdb98c63d22991ac9a85d44a6a8cdac` |
| SHA-1 | `92d277a27f303299e750cf159ef93cf3ac791b91` |
| SHA-256 | `d93c40c43e8cd646ec9f17080a6414521554a7dd1a06afd3e61e03b20bab694f` |
| SHA3-384 | `da59b5eb5ccd6b20444bbe3c506445bf1d7a79aad7a642d398a69900f4533f190651889888b6259c8377ea39ada49b8e` |
| TLSH | `T1CB01ABC9C840A81040EACE1D22D75455F821C3CE168A4FB9BF5C6E7DEBD4C14F0AAFA9` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaOC58FFAx8CbfeF0HmCSUg8FCGzCy2UX:kXCKysE2hi0ziQvZohaOecH70ZtrX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_d93c40c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d93c40c43e8cd646ec9f17080a6414521554a7dd1a06afd3e61e03b20bab694f"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-08 21:12:04"
  condition:
    hash.sha256(0, filesize) == "d93c40c43e8cd646ec9f17080a6414521554a7dd1a06afd3e61e03b20bab694f"
}
```

### Sample 28: `59e80f3d902a4d7f`

| Field | Value |
|---|---|
| SHA-256 | `59e80f3d902a4d7f51d39d1eb9fc2375b95dac01b2f90def5008b84e0da24e70` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-08 21:09:53` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da502f0314c07ce729b38bc693f6076e` |
| SHA-1 | `94e37a67843ede640e5d6b05a085174d9c2f2b60` |
| SHA-256 | `59e80f3d902a4d7f51d39d1eb9fc2375b95dac01b2f90def5008b84e0da24e70` |
| SHA3-384 | `8780d2567c0c741a4a7ba723eb08bd322842de1d0f0cdcbd3e8c815a52542fb60d9758e32296fe6fe2e2c2866cc38203` |
| TLSH | `T170C28C966A967C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11F9CC618B1A` |
| SSDEEP | `768:a8vCB+25j6es8Re9FYpMSUpi+20qUpi+20YQX:a8l25J4d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_59e80f3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e80f3d902a4d7f51d39d1eb9fc2375b95dac01b2f90def5008b84e0da24e70"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 21:09:53"
  condition:
    hash.sha256(0, filesize) == "59e80f3d902a4d7f51d39d1eb9fc2375b95dac01b2f90def5008b84e0da24e70"
}
```

### Sample 29: `cc5f663115ee706e`

| Field | Value |
|---|---|
| SHA-256 | `cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e` |
| Family label | `CoinMiner` |
| File name | `cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e.exe` |
| File type | `exe` |
| First seen | `2026-08-08 21:06:37` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ada02897616fce5050e437292ca42b7a` |
| SHA-1 | `4f41834cf2b46e2f117d71f89d242f18e85db5b6` |
| SHA-256 | `cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e` |
| SHA3-384 | `a56de01c249d2efb63dc880c697575c8a06d6e47b05ff6e5954deb34f2303545eaabf22ef30cc3a9a38bd69b61bf9ee6` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1E436339ABDD2E430C045C3BA829330BEB33EB7A188613C5A3AC97D505D96E19653DFD1` |
| SSDEEP | `98304:4FXhBDW7BTVm/GARem7m0vXSbzKBkHJBjk3Ymz2LF/k/WEFN5MN9Q:4D0BTsr7mwXfkbk3Ym6BM/HuNq` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_029_cc5f6631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e"
    family = "CoinMiner"
    file_name = "cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e.exe"
    file_type = "exe"
    first_seen = "2026-08-08 21:06:37"
  condition:
    hash.sha256(0, filesize) == "cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e"
}
```

### Sample 30: `c8acd3709ab3e9ad`

| Field | Value |
|---|---|
| SHA-256 | `c8acd3709ab3e9ad3ba45bed53b099008b58ca0bd7f37ae864be44f403f872b4` |
| Family label | `unknown` |
| File name | `6eq5gvOfRvNmCi54.exe` |
| File type | `exe` |
| First seen | `2026-08-08 20:55:03` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0965890cc8a3032cf4e488ea4affcd8a` |
| SHA-1 | `0127384f84a4bec73071f7b78da75f31d7650006` |
| SHA-256 | `c8acd3709ab3e9ad3ba45bed53b099008b58ca0bd7f37ae864be44f403f872b4` |
| SHA3-384 | `7250a871bd8bd18477c96d08bd354fe29a82152956d189a2fdc9c8412070d0a38e111eaea14f39e498b4607969308ae8` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1BED5234BA9B25974C872C7B29FC2E0BD70797B854B728E5B32CD6A10CD674844C3A379` |
| SSDEEP | `49152:rj/LZEkytciN1IdeS583TwG0MUc0TkVG7R1x1vsb8meiWIxcHI6t:rHykytcT8mgz6cAwgXE4me/mUt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_c8acd370
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8acd3709ab3e9ad3ba45bed53b099008b58ca0bd7f37ae864be44f403f872b4"
    family = "unknown"
    file_name = "6eq5gvOfRvNmCi54.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:55:03"
  condition:
    hash.sha256(0, filesize) == "c8acd3709ab3e9ad3ba45bed53b099008b58ca0bd7f37ae864be44f403f872b4"
}
```

### Sample 31: `4b00e47da69a554b`

| Field | Value |
|---|---|
| SHA-256 | `4b00e47da69a554bb231c79aa49c0fd3dc44923b2c3780db95be456ec4eaf815` |
| Family label | `unknown` |
| File name | `9z7BGnRGpgs8cZv7.exe` |
| File type | `exe` |
| First seen | `2026-08-08 20:54:57` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b12d2a9655fc15b5ae9e6320a0dffa06` |
| SHA-1 | `eaacb781e556ce2e7e646ed6988b8006e9be119a` |
| SHA-256 | `4b00e47da69a554bb231c79aa49c0fd3dc44923b2c3780db95be456ec4eaf815` |
| SHA3-384 | `f5522a9788a199b54853a91b507b2b2f1c8baa4ebe06660dd1d898d794e45c9ca6d82946ac0f324431e8141ffd169e04` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1DBD52396B5F219B0C83BC7B18F01E4AE70687B898E258D4BB7CD55008E63658EC73772` |
| SSDEEP | `49152:IJRW4OJNt0BvFWCQWtPmUH8susV2loSX52/iVqLeGwlz/s1DUUkmwh82wjGIngL0:KOJaNWxAXaowAI8jwlTsUU082wHgkX8f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_4b00e47d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b00e47da69a554bb231c79aa49c0fd3dc44923b2c3780db95be456ec4eaf815"
    family = "unknown"
    file_name = "9z7BGnRGpgs8cZv7.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:54:57"
  condition:
    hash.sha256(0, filesize) == "4b00e47da69a554bb231c79aa49c0fd3dc44923b2c3780db95be456ec4eaf815"
}
```

### Sample 32: `ef369700de87c054`

| Field | Value |
|---|---|
| SHA-256 | `ef369700de87c05496780aef6ba8ba345a98ba11cb4a3da52f6a253e7859be0d` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-08 20:52:39` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0806d162f71f2df8adfaba4f94876b43` |
| SHA-1 | `058114d53f22d255594fe43097d6979e5b649629` |
| SHA-256 | `ef369700de87c05496780aef6ba8ba345a98ba11cb4a3da52f6a253e7859be0d` |
| SHA3-384 | `c792dc329dceb6bb500340cf38d27c0470ae2226da3b0dc1b3bf3c3d4bf483703b2255b02b953360fe596c5ade94ffaa` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1D2E633589AE221FAE6B7553D9AE1C294E128B0B34336CDCF4B940296AE131F05C7F717` |
| SSDEEP | `393216:PGmywoD25yQR07uYRnPVTMXMCHWUjmcuI3/PGTAI:PGWoy51oMXMb8bH/O7` |
| ICON-DHASH | `f0f0dc9682c4f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_ef369700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef369700de87c05496780aef6ba8ba345a98ba11cb4a3da52f6a253e7859be0d"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 20:52:39"
  condition:
    hash.sha256(0, filesize) == "ef369700de87c05496780aef6ba8ba345a98ba11cb4a3da52f6a253e7859be0d"
}
```

### Sample 33: `b7c682fc6e8ea93f`

| Field | Value |
|---|---|
| SHA-256 | `b7c682fc6e8ea93f44c2c86fcd06e664971f42e8290a534c65a32a92d9b53a14` |
| Family label | `RemusStealer` |
| File name | `27f12606ddd8f538967222d4a5628b56.exe` |
| File type | `exe` |
| First seen | `2026-08-08 20:52:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27f12606ddd8f538967222d4a5628b56` |
| SHA-1 | `c7af163aa839ad519e9a180c7b5d89f9e4811f8a` |
| SHA-256 | `b7c682fc6e8ea93f44c2c86fcd06e664971f42e8290a534c65a32a92d9b53a14` |
| SHA3-384 | `20f42e24d77a56426ed4cd1c05843886bed5baf6229566d7b26ad2fd665882c39dfcb6e29d1f4674df04868ea3373c2f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T11C265927AE9188F6C199E735C8774249BA74BC0D4B3123D32EA1AE782F327C15E35B54` |
| SSDEEP | `49152:P0qxCNm8i8g9QEUqahZgPMa4Fb1MQWzhDD4Ae5d:PZTPX9zhDsfd` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_033_b7c682fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7c682fc6e8ea93f44c2c86fcd06e664971f42e8290a534c65a32a92d9b53a14"
    family = "RemusStealer"
    file_name = "27f12606ddd8f538967222d4a5628b56.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:52:04"
  condition:
    hash.sha256(0, filesize) == "b7c682fc6e8ea93f44c2c86fcd06e664971f42e8290a534c65a32a92d9b53a14"
}
```

### Sample 34: `299d2b2325b26b52`

| Field | Value |
|---|---|
| SHA-256 | `299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab` |
| Family label | `unknown` |
| File name | `299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab.exe` |
| File type | `exe` |
| First seen | `2026-08-08 20:41:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0b9b867d9b266ec3ac60f40aac59bce` |
| SHA-1 | `ca78547103216192652c11d4e876ad564199ae68` |
| SHA-256 | `299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab` |
| SHA3-384 | `bc00d2cc737a62f74dfbabc5c2842d288f3f5c241412616fae91ca73eb50a3461679af0b67c2603965aa6e8f39d4a634` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16A166B07BCA149F5D099A33588B3915277B0BC089B3533E72E90ABB82F727C15E79B54` |
| SSDEEP | `49152:xI8KpkpKEAwPInE7pD3+PBnrtPWQAXwcu/:xtKnE7cBnoQAu/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_299d2b23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab"
    family = "unknown"
    file_name = "299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:41:10"
  condition:
    hash.sha256(0, filesize) == "299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab"
}
```

### Sample 35: `59f1f37044154021`

| Field | Value |
|---|---|
| SHA-256 | `59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9` |
| Family label | `unknown` |
| File name | `59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9.exe` |
| File type | `exe` |
| First seen | `2026-08-08 20:36:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, signed, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e39ef8a1dbed7aa93b3a1af5416c1e8e` |
| SHA-1 | `7e263c4e5fb8433cad85c8a672695465396faeac` |
| SHA-256 | `59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9` |
| SHA3-384 | `e86cdbdb225cc2ce2912961716b49ff0677eb62b390b060d982f23ffc4d457acfc7f391108f6c440fe9ab617e27fbac5` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T166A5D03FB28B753EE06A5A3A7A76E210543B7E61A4134C1696E4E48CCF350B01D3E797` |
| SSDEEP | `24576:6XNrSLScusMmOvjjhzvLJz23q0RzLR9DC+UmvcnYTn0eaR+rE4mUzJFZhYJLchab:FuI2hQa4LR91jUnc0r143zZ+vFOoljp` |
| ICON-DHASH | `f0d0b2b27286c460` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_59f1f370
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9"
    family = "unknown"
    file_name = "59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:36:03"
  condition:
    hash.sha256(0, filesize) == "59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9"
}
```

### Sample 36: `d8eb33b1039d580a`

| Field | Value |
|---|---|
| SHA-256 | `d8eb33b1039d580a2c48bd70e1a2895697cb91250955965ee9bb3d68996bb947` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-08 20:34:06` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6e8ec396a42609955a1395e62f06641` |
| SHA-1 | `4e9e6ff512bdde04c988e216bba97924b3ba5a6e` |
| SHA-256 | `d8eb33b1039d580a2c48bd70e1a2895697cb91250955965ee9bb3d68996bb947` |
| SHA3-384 | `8d873f264edcd192e725102f14b9c24019b332a353666f3083ebb8fdd760d1917be49f63198150a60395194ffc69f7b6` |
| TLSH | `T109236C651A857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9D910871D` |
| SSDEEP | `768:tXRWNGxVC9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Xlxlcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_d8eb33b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8eb33b1039d580a2c48bd70e1a2895697cb91250955965ee9bb3d68996bb947"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 20:34:06"
  condition:
    hash.sha256(0, filesize) == "d8eb33b1039d580a2c48bd70e1a2895697cb91250955965ee9bb3d68996bb947"
}
```

### Sample 37: `6ebefed959519a65`

| Field | Value |
|---|---|
| SHA-256 | `6ebefed959519a65ac1648951811d2c65e5279584f1c281f44fbd19a0f5eb72a` |
| Family label | `unknown` |
| File name | `ok` |
| File type | `sh` |
| First seen | `2026-08-08 20:06:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43ece1e086b3f84c5423c428e02430a6` |
| SHA-1 | `f1b3218b64682b26d19560b70aaafe3d73b2522e` |
| SHA-256 | `6ebefed959519a65ac1648951811d2c65e5279584f1c281f44fbd19a0f5eb72a` |
| SHA3-384 | `6c48f21f1f997878691a7632a86617a306892265feb3e088424304e8c14c71d6ea96853d9b88926384d3cc9ac2e5c7c3` |
| TLSH | `T1DC31A6DA40105E311112DE8E77A23258B28DB7EB298FC7E4C84D1DAA929878CF561B4C` |
| SSDEEP | `24:r+JG/9nQcrpy742n2ERf/5tXta0jtFF6ICKVn:r+spy7h2ERH7Xta0jF6If` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_6ebefed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ebefed959519a65ac1648951811d2c65e5279584f1c281f44fbd19a0f5eb72a"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-08 20:06:18"
  condition:
    hash.sha256(0, filesize) == "6ebefed959519a65ac1648951811d2c65e5279584f1c281f44fbd19a0f5eb72a"
}
```

### Sample 38: `f50e1120cc6cb993`

| Field | Value |
|---|---|
| SHA-256 | `f50e1120cc6cb993c6f6ba8c734df7855df0cd37cf634d407abffbb9f0660702` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-08 20:03:30` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c38116a549c08d57877aea031015ba16` |
| SHA-1 | `b8d52174f6877f457c3aaed0eb4b3ecb4cf3dd6b` |
| SHA-256 | `f50e1120cc6cb993c6f6ba8c734df7855df0cd37cf634d407abffbb9f0660702` |
| SHA3-384 | `1a4e277ad80ee77b5f5bcfe859445181b2d6e7d72fa5b86fb79faf55934343c84cea29f212d80951d0a83005a1cddee9` |
| IMPHASH | `3a34330c057ed2c2e789aa1457124df7` |
| TLSH | `T1B3258D07E29081F9C0AEC4B4D347A532EB76BC8D0934B56F1BD1A7511E3AF90AB1EB15` |
| SSDEEP | `24576:6x/ZMZ0N2zN8ckTgmKsnYCwj5FM3VIH06iy:mZMZhzNsTusojjYIU6i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_f50e1120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50e1120cc6cb993c6f6ba8c734df7855df0cd37cf634d407abffbb9f0660702"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-08 20:03:30"
  condition:
    hash.sha256(0, filesize) == "f50e1120cc6cb993c6f6ba8c734df7855df0cd37cf634d407abffbb9f0660702"
}
```

### Sample 39: `f769dddb9fe18fbc`

| Field | Value |
|---|---|
| SHA-256 | `f769dddb9fe18fbcd6db26db8b45c71e26a7f3c41130b15a2e9d151b53213b9d` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-08 19:59:11` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89b4f546a767e7cce847b53aeb1e4c7a` |
| SHA-1 | `38f2f938e985f9b211448a899d4a8073cd17076b` |
| SHA-256 | `f769dddb9fe18fbcd6db26db8b45c71e26a7f3c41130b15a2e9d151b53213b9d` |
| SHA3-384 | `6725538acc1a1f7074ffcb1746555430d217ce078563efbe3b1e84d3c7b69e7957f91cb62b80c19b8171bbe2b44c39e5` |
| TLSH | `T1BE237D652A857C14AA98C4371D7E2F0CB9AD43E6320452ED7FCF3CF68C4A69D921871D` |
| SSDEEP | `768:1XOGVvs9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:xLpcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_f769dddb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f769dddb9fe18fbcd6db26db8b45c71e26a7f3c41130b15a2e9d151b53213b9d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 19:59:11"
  condition:
    hash.sha256(0, filesize) == "f769dddb9fe18fbcd6db26db8b45c71e26a7f3c41130b15a2e9d151b53213b9d"
}
```

### Sample 40: `6a79acea7924dd39`

| Field | Value |
|---|---|
| SHA-256 | `6a79acea7924dd39dbaada36450a6cdf362335c1b4f979dab2d18ff44d47c619` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.arm7` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1450c1348a0316510483269328ae103a` |
| SHA-1 | `a9b95f813b56dd818bfd2a4e31d05731d7f64f49` |
| SHA-256 | `6a79acea7924dd39dbaada36450a6cdf362335c1b4f979dab2d18ff44d47c619` |
| SHA3-384 | `121c25a82b3fa018148e167e0354a0067cac65b5bdd2b102447ec892a019e255b9af62be44510fb354a39cacb2f1adf8` |
| TLSH | `T176343A46EB414B13C4D627B9FA9F42453333DB6493EB73069928ABB03BC775A4F62601` |
| TELFHASH | `t1043110f19b7a52225551ea5cd8e96753052ec7261345ff37ff21c4dc680a40eea22c1f` |
| SSDEEP | `3072:3FZ4vxxGtk6BiWv53P5q3FaA0HTpcRqWHsi2uf6Q3V/GwUt:4vv6V53BaFaA0HTpcgC2uf6Q3V/GwUt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_6a79acea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a79acea7924dd39dbaada36450a6cdf362335c1b4f979dab2d18ff44d47c619"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:44"
  condition:
    hash.sha256(0, filesize) == "6a79acea7924dd39dbaada36450a6cdf362335c1b4f979dab2d18ff44d47c619"
}
```

### Sample 41: `fa66c5fd14955190`

| Field | Value |
|---|---|
| SHA-256 | `fa66c5fd149551903f2bcd30d1b9c62f02f3fd2424a1e20b8427b84f3c8b35c1` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.x86` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a34d7745efba8df6b64e5c298e7856db` |
| SHA-1 | `28be74ad1beee3535ab9a68211fb3761a26b68ac` |
| SHA-256 | `fa66c5fd149551903f2bcd30d1b9c62f02f3fd2424a1e20b8427b84f3c8b35c1` |
| SHA3-384 | `db1fe1857ad85ffc5f2020219c079ae1ff3d9b386295e8fee116e81d534c5ca210e2389db5a9d7d7ce6d46c7869e7cc2` |
| TLSH | `T1B6C36CD6A243D4F5E95205B11077E7369B36F13A902DEE43C3A89E32DC61681DA1D3EC` |
| TELFHASH | `t14f51f5b9b6650ce85bd0a802e24e5b71bd0d6bbf386472bb04f31835327b54245bbc39` |
| SSDEEP | `1536:wsUmsD9zTa8Lh3OmlDtufo96ITZwVuj+/nO+wmrpguJcMebric5JBID9S+fO8ngM:1c9zTa8nDtSx/nO+w6LcfriwJBy0o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_fa66c5fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa66c5fd149551903f2bcd30d1b9c62f02f3fd2424a1e20b8427b84f3c8b35c1"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:42"
  condition:
    hash.sha256(0, filesize) == "fa66c5fd149551903f2bcd30d1b9c62f02f3fd2424a1e20b8427b84f3c8b35c1"
}
```

### Sample 42: `d3b3c71bff27da97`

| Field | Value |
|---|---|
| SHA-256 | `d3b3c71bff27da97a3b7e0483e5686790cf9954222cd0549e84ac217818aa76b` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.arm5` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6adbbbb6f1d3c80d3ff399bb01b09963` |
| SHA-1 | `2dbcc12f975957c6a6519416fedca1d7b976402f` |
| SHA-256 | `d3b3c71bff27da97a3b7e0483e5686790cf9954222cd0549e84ac217818aa76b` |
| SHA3-384 | `e5877efbe85eca6c101237fe96ab3aeacbc5ea69b7b49267538f1161944449cbfef274012171c96d0011cc8f4cfa3101` |
| TLSH | `T13C630985BC928A5BC5D417BAB66E95CE3331A7F8C2DF3616DD214B20328951F0E37B90` |
| TELFHASH | `t179f0e204bc798a9a19c29a78dc9d46539593a27a5122cb24ef04ead4883f454e328d4a` |
| SSDEEP | `768:fwYOtdlEgI+0Nn00N/2/8pthQ+7QUD/FkHbNGzzisH5asgbHzKSZ7WF/DK3tcN9B:fwYE0NnZ5u+7TKzKDGcNBGZuh8dZ8Hv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_d3b3c71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3b3c71bff27da97a3b7e0483e5686790cf9954222cd0549e84ac217818aa76b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:40"
  condition:
    hash.sha256(0, filesize) == "d3b3c71bff27da97a3b7e0483e5686790cf9954222cd0549e84ac217818aa76b"
}
```

### Sample 43: `50334f35d3b1bd53`

| Field | Value |
|---|---|
| SHA-256 | `50334f35d3b1bd5306b2f1ef7283c8783097fa3045db229fccf7efc74f9c82ef` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `187a6db5f47f240d5599df2fbea25ca6` |
| SHA-1 | `9d52cc5779944eb82ebbc76c5b58e1780c888933` |
| SHA-256 | `50334f35d3b1bd5306b2f1ef7283c8783097fa3045db229fccf7efc74f9c82ef` |
| SHA3-384 | `81a378e5cda07d380fdbf7f07c7bf5d2b571cbf0d61dd645dbcc3dd6e0f6f9b13ebba7568b1482d282b42a2b6f31ba93` |
| TLSH | `T17DE43955F8809F61C6C529B6F65D42AC73074BB9D3EB72069A144B343BEB86B0F3A701` |
| TELFHASH | `t110f055347c4c65a8b5d2c820c383e81a2dfc26954b107c9eaf54ae8e0e86fd028b40b7` |
| SSDEEP | `12288:Oijanr2ZYGCCa0IjQ3M86MzJnlWEmdpgRK3vFo/qZmr68N8pqP8qOt:Oik6CCAsMTMFnlWLdGw/fmr1bq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_50334f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50334f35d3b1bd5306b2f1ef7283c8783097fa3045db229fccf7efc74f9c82ef"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:19"
  condition:
    hash.sha256(0, filesize) == "50334f35d3b1bd5306b2f1ef7283c8783097fa3045db229fccf7efc74f9c82ef"
}
```

### Sample 44: `d51b558ba3c41802`

| Field | Value |
|---|---|
| SHA-256 | `d51b558ba3c418022813298c5f99c40eb943e2237e5101f6a1f7c13a3f41d898` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.arm7` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53be04d575cb3e5252ba36909b686490` |
| SHA-1 | `6bd7a9202afa386ac1ad792027cf71e4c04ea6a4` |
| SHA-256 | `d51b558ba3c418022813298c5f99c40eb943e2237e5101f6a1f7c13a3f41d898` |
| SHA3-384 | `816d476f8d9b504868f6b54443f4068ce444cdb67f1fe41efee53ed32c13e7f002b2b14a7e5a54b23f515f9eae84cfdb` |
| TLSH | `T1A0831266775ABE68E2A01075C23D08F61A620B3C1D99A467BEA01F385E031CF5F3C5DA` |
| SSDEEP | `1536:8ZupXNnTfKHFL43eMtYGyHLQZZXY9+TbiYL22znHBDV5qn8KEX:OAdTS6jt3YLQvXISbVL22zH2w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_d51b558b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51b558ba3c418022813298c5f99c40eb943e2237e5101f6a1f7c13a3f41d898"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:18"
  condition:
    hash.sha256(0, filesize) == "d51b558ba3c418022813298c5f99c40eb943e2237e5101f6a1f7c13a3f41d898"
}
```

### Sample 45: `724d9367b898aa7f`

| Field | Value |
|---|---|
| SHA-256 | `724d9367b898aa7f527f74cbeb03ef6e2dd24ba9c245248721ed4e7dab14895b` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.x86` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f9ccfd126e2494e442e4bb4618c4fb3` |
| SHA-1 | `7cb09e89f73128f66568eca885317fc2d70db982` |
| SHA-256 | `724d9367b898aa7f527f74cbeb03ef6e2dd24ba9c245248721ed4e7dab14895b` |
| SHA3-384 | `02695dc48901064e3675ad3f88e787b44779cced7ca5f93e7f8345eb9ce1d47eceded65af7b0e769d8549cbbb56849a8` |
| TLSH | `T1A2330257E5A9421ABE9F003484EFB50E46E2F9CD68C4187B83C894BF2944B64732CED8` |
| SSDEEP | `1536:bqpn7xBBadwThkc43Uo137s4Anouy8Kyr:bqp7jBaadkclGLsvout7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_724d9367
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "724d9367b898aa7f527f74cbeb03ef6e2dd24ba9c245248721ed4e7dab14895b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:16"
  condition:
    hash.sha256(0, filesize) == "724d9367b898aa7f527f74cbeb03ef6e2dd24ba9c245248721ed4e7dab14895b"
}
```

### Sample 46: `01f7c92354dc9a51`

| Field | Value |
|---|---|
| SHA-256 | `01f7c92354dc9a51782cffaca02417ec36b66da3dc21cd832fb4730392245a87` |
| Family label | `Mirai` |
| File name | `sdfjgnjsdf.arm5` |
| File type | `elf` |
| First seen | `2026-08-08 19:39:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1c38f117acc4b55711c4380744482d6` |
| SHA-1 | `8cce25b1b615f5b47693050e34e4733abd353956` |
| SHA-256 | `01f7c92354dc9a51782cffaca02417ec36b66da3dc21cd832fb4730392245a87` |
| SHA3-384 | `95d888996b09a60b3885e490021b3c14d4fdd3cbb9c9db21c993dd9b7583500ba71916af29318c8c964031126ebfe0a5` |
| TLSH | `T173D2F190B609F011C5B0C47DBCF84785769A49B4C3FB64A35C283AD8AE86385DAF574A` |
| SSDEEP | `768:rH8yqlQU1KctzN5XsidyzyR3+exMqym8WY79qiTZbnFzt3gJs3UozJ4:rcyqP19p7dQcMqym8WY79qi5n7gUz6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_01f7c923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01f7c92354dc9a51782cffaca02417ec36b66da3dc21cd832fb4730392245a87"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:15"
  condition:
    hash.sha256(0, filesize) == "01f7c92354dc9a51782cffaca02417ec36b66da3dc21cd832fb4730392245a87"
}
```

### Sample 47: `52e6b0c570b4a64d`

| Field | Value |
|---|---|
| SHA-256 | `52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34` |
| Family label | `Mirai` |
| File name | `xd.m68k` |
| File type | `elf` |
| First seen | `2026-08-08 19:37:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b72327b47a3b9bff4d42c205b8dad226` |
| SHA-1 | `ae86fb4fc25b029f256d50f471e9aab995d303c5` |
| SHA-256 | `52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34` |
| SHA3-384 | `695581eb7936592ae3e61bc340d18281659371a204379278eaa86c9264bb3108ebb2509fad31cb1535142881836b5926` |
| TLSH | `T16DB4C0C673063E3FE0E2553984E64F17BB35E38051832B5B3179F9AA69235F42E216C6` |
| SSDEEP | `12288:+U2I4i1SjQHSsqVRJkes9sMNBLVLhV2YL:+/WVfmRi3VLL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_52e6b0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-08-08 19:37:08"
  condition:
    hash.sha256(0, filesize) == "52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34"
}
```

### Sample 48: `f544e08ca75ce7db`

| Field | Value |
|---|---|
| SHA-256 | `f544e08ca75ce7dbaedd0524f1ac777a001d4a22122192e4bb77d63194106898` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-08 19:35:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fbaef921b82ea266c941eaa6306cdcd` |
| SHA-1 | `287f2cb1b969526451278581d796d9b92c8c5266` |
| SHA-256 | `f544e08ca75ce7dbaedd0524f1ac777a001d4a22122192e4bb77d63194106898` |
| SHA3-384 | `a54dd65e4e17ba8487d9deae5a448f3ee563f6f5e08825a562ec15ad352921af809603b02f3e672e2b6a11242c3c5dfd` |
| TLSH | `T17DC27C966A967C44BEC94A3E4CBD2B0D6DF5C3D1224942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:38vCB+25j6es8R49FYpMSUpi+20qUpi+20YQX:38l25JOd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_f544e08c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f544e08ca75ce7dbaedd0524f1ac777a001d4a22122192e4bb77d63194106898"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 19:35:03"
  condition:
    hash.sha256(0, filesize) == "f544e08ca75ce7dbaedd0524f1ac777a001d4a22122192e4bb77d63194106898"
}
```

### Sample 49: `ee2e195d098256a1`

| Field | Value |
|---|---|
| SHA-256 | `ee2e195d098256a159a04d20e3fac620ec6e091e1315c535281b91ef7199b7b3` |
| Family label | `unknown` |
| File name | `b464663f-49bf-49a0-882e-4d9d5b5d1e93` |
| File type | `unknown` |
| First seen | `2026-08-08 19:33:50` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e56e7f1513fd58e3e420144909b6688` |
| SHA-256 | `ee2e195d098256a159a04d20e3fac620ec6e091e1315c535281b91ef7199b7b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_ee2e195d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee2e195d098256a159a04d20e3fac620ec6e091e1315c535281b91ef7199b7b3"
    family = "unknown"
    file_name = "b464663f-49bf-49a0-882e-4d9d5b5d1e93"
    file_type = "unknown"
    first_seen = "2026-08-08 19:33:50"
  condition:
    hash.sha256(0, filesize) == "ee2e195d098256a159a04d20e3fac620ec6e091e1315c535281b91ef7199b7b3"
}
```

### Sample 50: `5cac9abcc4e4194f`

| Field | Value |
|---|---|
| SHA-256 | `5cac9abcc4e4194f56193936f851553b475642db6db020727ca88eb34b4d55ae` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-08 19:32:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `417a9dd2ee873656db585bdbd0f38a6d` |
| SHA-1 | `29ed9e0f9807ecfeaa5498268eff1b64f8a3ff71` |
| SHA-256 | `5cac9abcc4e4194f56193936f851553b475642db6db020727ca88eb34b4d55ae` |
| SHA3-384 | `c817c7d1a984db6a8e89eed138fae0a3f62c0d17a203f006c8cc9f604eba14b68a2542ce23c57a6fbb16278c59c11ee7` |
| TLSH | `T131236C6516857C14AE99C4365D7E2F0CBDAD43E6314492EE7FCE3CF28C4A6ACA20871D` |
| SSDEEP | `768:lRr9NyXsZztCy9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:lpHusZ2cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_5cac9abc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cac9abcc4e4194f56193936f851553b475642db6db020727ca88eb34b4d55ae"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 19:32:34"
  condition:
    hash.sha256(0, filesize) == "5cac9abcc4e4194f56193936f851553b475642db6db020727ca88eb34b4d55ae"
}
```

### Sample 51: `81f7b04dd8fa3095`

| Field | Value |
|---|---|
| SHA-256 | `81f7b04dd8fa3095622901d09c32f3904f8c1f9b6921e82f04312132548e98ba` |
| Family label | `ConnectWise` |
| File name | `2621d22a-c3ae-4e6f-ba06-2dd8900fb528` |
| File type | `zip` |
| First seen | `2026-08-08 19:31:49` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41b8e0b53929fec70884a669cdf53b1e` |
| SHA-1 | `eac3a0cf930ac18dc4ff85efa24b84877a78fd40` |
| SHA-256 | `81f7b04dd8fa3095622901d09c32f3904f8c1f9b6921e82f04312132548e98ba` |
| SHA3-384 | `b5b3787efde90d528512e7ae21fb66b2e16ac08379517ff6b766deed4369196165ddd849636890f809b0cbb9d6de0564` |
| TLSH | `T1B7A733EB8514A60140F7E49FABF1C390945AA9E6D7B02D83FED157B21C8F9C057AB702` |
| SSDEEP | `786432:rXMLoG0a9fU7yVXC2BC1Re8bWZ360Gn2SeSGSXX7EcBNXpDUHbxe7:rXMLf0e872BDG0GerSH7tXpDUNG` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_051_81f7b04d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f7b04dd8fa3095622901d09c32f3904f8c1f9b6921e82f04312132548e98ba"
    family = "ConnectWise"
    file_name = "2621d22a-c3ae-4e6f-ba06-2dd8900fb528"
    file_type = "zip"
    first_seen = "2026-08-08 19:31:49"
  condition:
    hash.sha256(0, filesize) == "81f7b04dd8fa3095622901d09c32f3904f8c1f9b6921e82f04312132548e98ba"
}
```

### Sample 52: `27fdc803b50d8b1e`

| Field | Value |
|---|---|
| SHA-256 | `27fdc803b50d8b1ed05d87532bb2502b987f5136b08c6fac79ed7f020e48d618` |
| Family label | `unknown` |
| File name | `17fcbf8b-9b1c-4b6b-bc20-7de03a36fb97` |
| File type | `unknown` |
| First seen | `2026-08-08 19:25:21` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89f0666379f0cdca140124a9ae742554` |
| SHA-256 | `27fdc803b50d8b1ed05d87532bb2502b987f5136b08c6fac79ed7f020e48d618` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_27fdc803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27fdc803b50d8b1ed05d87532bb2502b987f5136b08c6fac79ed7f020e48d618"
    family = "unknown"
    file_name = "17fcbf8b-9b1c-4b6b-bc20-7de03a36fb97"
    file_type = "unknown"
    first_seen = "2026-08-08 19:25:21"
  condition:
    hash.sha256(0, filesize) == "27fdc803b50d8b1ed05d87532bb2502b987f5136b08c6fac79ed7f020e48d618"
}
```

### Sample 53: `22e9872417a460fb`

| Field | Value |
|---|---|
| SHA-256 | `22e9872417a460fb4a79faa9670594f08e7c57980458018993480dbb03beb991` |
| Family label | `unknown` |
| File name | `462f1a56-ee44-41a7-8a89-a8c86111995c` |
| File type | `exe` |
| First seen | `2026-08-08 19:25:17` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c42df823584a61907390a426816c861c` |
| SHA-1 | `ea8e8a111429dacbc577a6d63b3b235f0e4c990b` |
| SHA-256 | `22e9872417a460fb4a79faa9670594f08e7c57980458018993480dbb03beb991` |
| SHA3-384 | `050034112cec4a2de54ea4d76abb7b07fb91fcc12dfa2a2686bf2406cdbdc034f64e43adb5523c1ee7023ac274c813d1` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1FA554A4BBCD115BAD0BA93328DA65191BA72BC450F3123C72E90B2783F7A7E16D75708` |
| SSDEEP | `12288:Kko0o7By69RM/nO5qfwZjHULG+OstTWwHWJd6k/i5GOk6/D+2V0e+tv2o3xjceFq:Kk3oFyYEO7SLTNWwyiuuUcwQfDh` |
| ICON-DHASH | `2816326969709468` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_22e98724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22e9872417a460fb4a79faa9670594f08e7c57980458018993480dbb03beb991"
    family = "unknown"
    file_name = "462f1a56-ee44-41a7-8a89-a8c86111995c"
    file_type = "exe"
    first_seen = "2026-08-08 19:25:17"
  condition:
    hash.sha256(0, filesize) == "22e9872417a460fb4a79faa9670594f08e7c57980458018993480dbb03beb991"
}
```

### Sample 54: `f8d105d5ae7e1023`

| Field | Value |
|---|---|
| SHA-256 | `f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb` |
| Family label | `unknown` |
| File name | `f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb.bin` |
| File type | `unknown` |
| First seen | `2026-08-08 19:16:13` |
| Reporter | `Tuxxin` |
| Tags | `whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afd689dd0f6f8d1c5cf273729f745d28` |
| SHA-256 | `f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_f8d105d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb"
    family = "unknown"
    file_name = "f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb.bin"
    file_type = "unknown"
    first_seen = "2026-08-08 19:16:13"
  condition:
    hash.sha256(0, filesize) == "f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb"
}
```

### Sample 55: `a05ae38215701251`

| Field | Value |
|---|---|
| SHA-256 | `a05ae38215701251380abe446784ce542c6e3023ec68411d51babe1becc7dcbc` |
| Family label | `CoinMiner` |
| File name | `install.sh` |
| File type | `sh` |
| First seen | `2026-08-08 19:08:02` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd2d6fcbad96eeec633ce79c41cba237` |
| SHA-1 | `7a596f7d60c2a09e3697682cc938fd8341001de0` |
| SHA-256 | `a05ae38215701251380abe446784ce542c6e3023ec68411d51babe1becc7dcbc` |
| SHA3-384 | `1d2d2b01fdd386e310bf752776d10ef7d26aa4e9092334542da487c552ac18250f074796390295711bcc0443039d3126` |
| TLSH | `T1B463A6B2B560C1703969C16C678B41503A49703B356C382874AFB52CBFDC758A1FABBE` |
| SSDEEP | `768:6OYwcTtmv50fiqfQO96/wtgizPjUcDVcv4z/Ntrw1iqWgAVyUPVGTbf:9Yu0f3YgDVcv4pqbf` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_055_a05ae382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a05ae38215701251380abe446784ce542c6e3023ec68411d51babe1becc7dcbc"
    family = "CoinMiner"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-08-08 19:08:02"
  condition:
    hash.sha256(0, filesize) == "a05ae38215701251380abe446784ce542c6e3023ec68411d51babe1becc7dcbc"
}
```

### Sample 56: `ffc138fd06fc0104`

| Field | Value |
|---|---|
| SHA-256 | `ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13` |
| Family label | `ACRStealer` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-08-08 18:53:41` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03ec40f20de00f9a88abdbeb9aeaee23` |
| SHA-1 | `c29f54761c1b9beeda874bc8436fe2cf0364ad09` |
| SHA-256 | `ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13` |
| SHA3-384 | `de580bf5db2dd6c21b1e424d58f161c9a282415463c130755c85d3f900f4f2f84635ccbe7d5031aee5932b8403308622` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T17D86236303F05077E076277908E54B476635FD828A7A9ACF2BE57B5F2E02B84B074366` |
| SSDEEP | `49152:KW88gMwGLya6E4yCZELiahj8K6fIdAMFBFbx7MvZ:788zLFGZEL9BrFBFbx7eZ` |
| ICON-DHASH | `13c6d4a0a6e2e0f0` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_056_ffc138fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13"
    family = "ACRStealer"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-08 18:53:41"
  condition:
    hash.sha256(0, filesize) == "ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13"
}
```

### Sample 57: `af529b7c37407a0f`

| Field | Value |
|---|---|
| SHA-256 | `af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb` |
| Family label | `RustyStealer` |
| File name | `af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb.exe` |
| File type | `exe` |
| First seen | `2026-08-08 18:36:01` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37835e5dc2d38d689b895ea352489f5e` |
| SHA-1 | `0c1ed4a7d493cc40e3d66305948b3c4fd4d025e7` |
| SHA-256 | `af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb` |
| SHA3-384 | `82c1f4515acbe956f63c47f22f823c6e683caeb68349dba560e4560002ec009893f86deee9e4764e4f75f2aff6c41b5c` |
| IMPHASH | `f744b386a4857011365ff83ce58075b9` |
| TLSH | `T1AFD52316F5A354F9E06BC031829542636535B8890B20BBFF47A585357F3AAF20F3DB26` |
| SSDEEP | `49152:5mScS27davgFU2rv5Lm9gs4S4d1FLbzynI9kXS3q5NUTt0GZIdmEnFcbTFl:8TdavgCUhmOJJd1FvzgI+XS3qPO0B1ni` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_057_af529b7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb"
    family = "RustyStealer"
    file_name = "af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb.exe"
    file_type = "exe"
    first_seen = "2026-08-08 18:36:01"
  condition:
    hash.sha256(0, filesize) == "af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb"
}
```

### Sample 58: `5fbac387b2baa24a`

| Field | Value |
|---|---|
| SHA-256 | `5fbac387b2baa24ac8073636e6ecb66be53a074c19a28da0508b32e37edfe6e0` |
| Family label | `Mirai` |
| File name | `ntb.mips` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae2a7ee89da71452ca2fbaf3f8abae87` |
| SHA-1 | `bd9f1a8821f349dd9ea6a90d104dfda3f338db22` |
| SHA-256 | `5fbac387b2baa24ac8073636e6ecb66be53a074c19a28da0508b32e37edfe6e0` |
| SHA3-384 | `5ee9a0e9c5ec2d737702d349e773af231fbcd946c00e1118ac425063dbf5d19a352fc23f36e00ccbbc924768a83d3e51` |
| TLSH | `T166548E0377614F89F325D17105F38563AAE926D71BE2C496D33DEA113A20E89383BF69` |
| TELFHASH | `t18ee0ec28983c63f0c089cd1e52ddef3599e194eb957a0d0bc504d8796771c839d00c34` |
| SSDEEP | `6144:jsYFmzasnrVlwxKyuBSP/yRnSikp7Q/4haCdfV1:AYKznjwEbUvbhTz1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_5fbac387
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fbac387b2baa24ac8073636e6ecb66be53a074c19a28da0508b32e37edfe6e0"
    family = "Mirai"
    file_name = "ntb.mips"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:50"
  condition:
    hash.sha256(0, filesize) == "5fbac387b2baa24ac8073636e6ecb66be53a074c19a28da0508b32e37edfe6e0"
}
```

### Sample 59: `75e5f2230261d982`

| Field | Value |
|---|---|
| SHA-256 | `75e5f2230261d98282372fc448e602161efed867c8917a634879a6d9ae71a25e` |
| Family label | `Mirai` |
| File name | `ntb.x86` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24fc5869e814785789f5ae4f75c01e17` |
| SHA-1 | `6ada0cbc00403711210e9a5cef40dc65e72f036d` |
| SHA-256 | `75e5f2230261d98282372fc448e602161efed867c8917a634879a6d9ae71a25e` |
| SHA3-384 | `f70f23055a41188cf3a23f01956f30b525c6791dfac2ab7ffe47a3b5defb10b1ac597dabdf8e6b1b75cfab857404ab1c` |
| TLSH | `T1FC247B46EB43E1F1E5534570419BAB9BAF359C394016DE87EBA03D32ECAA601521FB3C` |
| TELFHASH | `t177817cf63e651aee33f09905d34f2b22fe1986a76c5431b201f718d532f2a026375432` |
| SSDEEP | `6144:qaUe7bhe83vuIvEv+m7o/tngkecG2NmiKcqbRD:qg7o83vhEvNcgke72sv/R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_75e5f223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75e5f2230261d98282372fc448e602161efed867c8917a634879a6d9ae71a25e"
    family = "Mirai"
    file_name = "ntb.x86"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:44"
  condition:
    hash.sha256(0, filesize) == "75e5f2230261d98282372fc448e602161efed867c8917a634879a6d9ae71a25e"
}
```

### Sample 60: `12087bc187ea1e67`

| Field | Value |
|---|---|
| SHA-256 | `12087bc187ea1e677a07f587d47d9b544f9fd4e59cdcf314cc3647f57a1a4c34` |
| Family label | `Mirai` |
| File name | `ntb.x64` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fabb94073c5f136a09a610634583c757` |
| SHA-1 | `83a553e45568b4a1da66f85f48baa137caf97baa` |
| SHA-256 | `12087bc187ea1e677a07f587d47d9b544f9fd4e59cdcf314cc3647f57a1a4c34` |
| SHA3-384 | `0a07f86861244c7ff6a60384308dccc8c710b84402b47a199dd6c7bf098d81f499734846cf59d660b3e36c197eb17368` |
| TLSH | `T195146D07F58090FED486D174C7DFC3B2B936B89D221979972BD42E763E2AF10260D691` |
| TELFHASH | `t12961ac300e9178b52357d9057307d2acde331844c5e972dcba82bdf9ec9aa85cd82477` |
| SSDEEP | `3072:6pzya7tAH6JhAlfFI/ja0l48kDwmNneT1bu7/LraKbKubbdeqZNAQ:6pzRtA4hAlfFOja0RkFNn8qnWKb31Xd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_12087bc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12087bc187ea1e677a07f587d47d9b544f9fd4e59cdcf314cc3647f57a1a4c34"
    family = "Mirai"
    file_name = "ntb.x64"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:39"
  condition:
    hash.sha256(0, filesize) == "12087bc187ea1e677a07f587d47d9b544f9fd4e59cdcf314cc3647f57a1a4c34"
}
```

### Sample 61: `32a916a31fb70132`

| Field | Value |
|---|---|
| SHA-256 | `32a916a31fb701320af334687e9b92a3a1b54df172df50d4563321e46f2da6b3` |
| Family label | `Mirai` |
| File name | `ntb.mipsel` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cefa7c319d0bfec8d68a6dff45520de` |
| SHA-1 | `b85e9c0e3ccce66365d7821b03ccdae022ae7394` |
| SHA-256 | `32a916a31fb701320af334687e9b92a3a1b54df172df50d4563321e46f2da6b3` |
| SHA3-384 | `016a51514703ec7f8ca6160ac94e0108b60842dfc4f17ed2a9efe54207b252aace79f440d1e27faa6b52f2fbcc1a633b` |
| TLSH | `T1FD646B52EF600FCFD49FCD308A3D43A718ED9E9A52E5A336947CCC44359B6464AE3898` |
| SSDEEP | `6144:/DJv3pWa48NutXlvJ5HCH7KwugskQLtLEsNHu4x1kyPhLACEZ8yVNwNSIr1F/Kho:/DJv3pWa48NutXlvJ5HCH7KwugskQLt3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_32a916a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32a916a31fb701320af334687e9b92a3a1b54df172df50d4563321e46f2da6b3"
    family = "Mirai"
    file_name = "ntb.mipsel"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:31"
  condition:
    hash.sha256(0, filesize) == "32a916a31fb701320af334687e9b92a3a1b54df172df50d4563321e46f2da6b3"
}
```

### Sample 62: `0552a5621e1a0f0d`

| Field | Value |
|---|---|
| SHA-256 | `0552a5621e1a0f0d1fc6ba327454ad4542669110bd05059b0e50f5db69245780` |
| Family label | `Mirai` |
| File name | `ntb.arm64` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16f6d3345e43ed6c8ecd4a01330fdb39` |
| SHA-1 | `abeac029ddffc920b8528a1679e53942a8a40a5c` |
| SHA-256 | `0552a5621e1a0f0d1fc6ba327454ad4542669110bd05059b0e50f5db69245780` |
| SHA3-384 | `b7e525168cddc1c1e32870f43a1289633d3ffa4c5ee7698e12a865891a50d2808860e5fb254c12aecb6131d5ca6795a2` |
| TLSH | `T10B24AF58FA4FAC53C2C3E7BFAD595FA2701739F84264D0F25D01924CC8EDED499A6422` |
| SSDEEP | `6144:ah/qKPNsMDUTXR/h0c38M061CkT36Z4l/LC:ahrNUTr0C8Rk19u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_0552a562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0552a5621e1a0f0d1fc6ba327454ad4542669110bd05059b0e50f5db69245780"
    family = "Mirai"
    file_name = "ntb.arm64"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:24"
  condition:
    hash.sha256(0, filesize) == "0552a5621e1a0f0d1fc6ba327454ad4542669110bd05059b0e50f5db69245780"
}
```

### Sample 63: `55e4ab3d30dcaa72`

| Field | Value |
|---|---|
| SHA-256 | `55e4ab3d30dcaa72c55bd687a7f589911168ec9d967d590f54596e6e4822280b` |
| Family label | `Mirai` |
| File name | `ntb.arm7` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f07a8db8a5c06ca8e14c9ee2ce2d1309` |
| SHA-1 | `6adedace64f27d1d4051ceac6cabdba6fe78e12f` |
| SHA-256 | `55e4ab3d30dcaa72c55bd687a7f589911168ec9d967d590f54596e6e4822280b` |
| SHA3-384 | `536ec23a3404479af9ba280fddddef3d6cebdd4951f509eabbd9974e49bcb4fb619f80b190e91d92a90212b51e2de266` |
| TLSH | `T1EF244C95F950DA22CAD0657EFB5E428C336B07B8C2EE7102DD145F2533EB94A0F7AA41` |
| TELFHASH | `t19de08650677745f5d187d3863396562e616e68890f3119c147db6a5e0c16c4072c7f37` |
| SSDEEP | `6144:9H4nOeJMEHbGnrQeL1j7qiIrfIZE6b3fujaNuhbjv/RB:SZ07qi0sEeujs4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_55e4ab3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e4ab3d30dcaa72c55bd687a7f589911168ec9d967d590f54596e6e4822280b"
    family = "Mirai"
    file_name = "ntb.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:16"
  condition:
    hash.sha256(0, filesize) == "55e4ab3d30dcaa72c55bd687a7f589911168ec9d967d590f54596e6e4822280b"
}
```

### Sample 64: `6fe661df26820ae2`

| Field | Value |
|---|---|
| SHA-256 | `6fe661df26820ae2e7fa83dd6c2167083cc22d064adcefb8093ec281e595fe4c` |
| Family label | `Mirai` |
| File name | `ntb.arm5` |
| File type | `elf` |
| First seen | `2026-08-08 18:01:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f50b29dc075412ee0c9ca8019006eb66` |
| SHA-1 | `a6e3386b9c1b8128d0a070387b97f1e06bc28d7e` |
| SHA-256 | `6fe661df26820ae2e7fa83dd6c2167083cc22d064adcefb8093ec281e595fe4c` |
| SHA3-384 | `14440467961a0e94edd4b230b2880ea8ec5874e24ee5a7477e9510dc74e07dca07d71c224cd1390a67dfc383fc406294` |
| TLSH | `T1E9344BA6F850DB62C6D0267EFB6D428C331B07B8C2DE7102DE159F2523DB94A4F7A941` |
| TELFHASH | `t13ee0df24b3bb057cd282a2860269e633b5ac0460df6229c9438b6a0e5c02e9425d7d32` |
| SSDEEP | `6144:H/W9cKLr6y1m1YTt+bY1PK2D+olG5R8GB4T3iqjoVB9:fW901Ct+ERnMoW9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_6fe661df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe661df26820ae2e7fa83dd6c2167083cc22d064adcefb8093ec281e595fe4c"
    family = "Mirai"
    file_name = "ntb.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:07"
  condition:
    hash.sha256(0, filesize) == "6fe661df26820ae2e7fa83dd6c2167083cc22d064adcefb8093ec281e595fe4c"
}
```

### Sample 65: `01d31eb4fec94f20`

| Field | Value |
|---|---|
| SHA-256 | `01d31eb4fec94f20d367b61ea0a304023b68fefb2606452a684c2a8cf64ebb06` |
| Family label | `Mirai` |
| File name | `ntb.mips` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:47` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e04ffda528130d6aa90bc08689e313b8` |
| SHA-1 | `fb13f64238209f54e540c1343162314602b0c3d6` |
| SHA-256 | `01d31eb4fec94f20d367b61ea0a304023b68fefb2606452a684c2a8cf64ebb06` |
| SHA3-384 | `99191e59305643026011a0baacf00b5445064876a6064fea4a3c3ea2f5e8d78f7b346a8379ecbff0d1782c4ae01dddcb` |
| TLSH | `T1C5C3122D970E82B6C821E9BDD3460E491F7145B62B5BA5C65ED3C7960FD706834033E9` |
| SSDEEP | `3072:UtKogaFhvtUdTpNsmxokW9iPQ78vEVZLwpbNs7Cqc2pPRV1u:dogahvtiTpJxokW9mvEVhwppqceH1u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_01d31eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01d31eb4fec94f20d367b61ea0a304023b68fefb2606452a684c2a8cf64ebb06"
    family = "Mirai"
    file_name = "ntb.mips"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:47"
  condition:
    hash.sha256(0, filesize) == "01d31eb4fec94f20d367b61ea0a304023b68fefb2606452a684c2a8cf64ebb06"
}
```

### Sample 66: `f18ad10182e72fdf`

| Field | Value |
|---|---|
| SHA-256 | `f18ad10182e72fdf2bb0e265189cf7f0ea33931536b52254725fabce04c5a01e` |
| Family label | `Mirai` |
| File name | `ntb.x86` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:35` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e772a386d72c938f04684d3282ad8022` |
| SHA-1 | `df2e3176e0d7462b3a7bd1e22a6bc23525773bfd` |
| SHA-256 | `f18ad10182e72fdf2bb0e265189cf7f0ea33931536b52254725fabce04c5a01e` |
| SHA3-384 | `2702126a389adf459821d23972a1b7b085d041dfba9e90046b0d922577fe02c298c64e160b6a1b9ad737e7d7af67eb45` |
| TLSH | `T169A3028490570FB9C09E683BFB8FFA7A1E65181EB57433C3A00924BF49697A44B6CD47` |
| SSDEEP | `3072:MAx8nWRTu3Zkv2H+FIIj6mJUvSFDRPg98lgoutDM/:LMk5jf9/Py5oSO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_f18ad101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f18ad10182e72fdf2bb0e265189cf7f0ea33931536b52254725fabce04c5a01e"
    family = "Mirai"
    file_name = "ntb.x86"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:35"
  condition:
    hash.sha256(0, filesize) == "f18ad10182e72fdf2bb0e265189cf7f0ea33931536b52254725fabce04c5a01e"
}
```

### Sample 67: `37a07f7b75f44c94`

| Field | Value |
|---|---|
| SHA-256 | `37a07f7b75f44c949925f52a09e463c6179511a0556a05fc5f30799212aa9a3d` |
| Family label | `Mirai` |
| File name | `ntb.x64` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:34` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e603b9ea709bac895ada2c8f1c0356f` |
| SHA-1 | `6ddc400f02ac8350bb0744ab707cd8206cec8b55` |
| SHA-256 | `37a07f7b75f44c949925f52a09e463c6179511a0556a05fc5f30799212aa9a3d` |
| SHA3-384 | `1566c1ff2fd67aecc5dd92dc0465097ea63f3c0c512e7f26806b68c62c5de05095175508401b1db7269b652a0423df20` |
| TLSH | `T18EA3127B41DB62FAC8B36F35F84A17E0BB7AF47160046F8625895877D8337AC2432265` |
| SSDEEP | `3072:mKuHvysQ6847l/KOrfHL3Uef+UcaGQpnfcRR7PC:mvEH47RrfrklUMQpfL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_37a07f7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37a07f7b75f44c949925f52a09e463c6179511a0556a05fc5f30799212aa9a3d"
    family = "Mirai"
    file_name = "ntb.x64"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:34"
  condition:
    hash.sha256(0, filesize) == "37a07f7b75f44c949925f52a09e463c6179511a0556a05fc5f30799212aa9a3d"
}
```

### Sample 68: `41462778f6907b43`

| Field | Value |
|---|---|
| SHA-256 | `41462778f6907b439f1f9667fcfe86381366bf9807bac8cb71badb6d826d80f1` |
| Family label | `Mirai` |
| File name | `ntb.mipsel` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:34` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccc5dcaf383126486edb9641cf7b2fde` |
| SHA-1 | `87b843b8b52c1bb105a45a1f59f4b85e23a442d7` |
| SHA-256 | `41462778f6907b439f1f9667fcfe86381366bf9807bac8cb71badb6d826d80f1` |
| SHA3-384 | `b1f76a8491935bff3f2d5b49c3328e8ab68a05773265b0f5ecdbe64816cadb20d893d6ec9b14e1d5e409d8611db94cbe` |
| TLSH | `T1F5C312BD51B1BBCFD8EC9E3C889C8382AB0EE8C035C683552087E5FDF5529A66515D8C` |
| SSDEEP | `3072:9xmgNVxu2RsABiCtnEIdg+Vag8X+Doxuf2a9s:jZu2RsA8Vqg8MHxoG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_41462778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41462778f6907b439f1f9667fcfe86381366bf9807bac8cb71badb6d826d80f1"
    family = "Mirai"
    file_name = "ntb.mipsel"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:34"
  condition:
    hash.sha256(0, filesize) == "41462778f6907b439f1f9667fcfe86381366bf9807bac8cb71badb6d826d80f1"
}
```

### Sample 69: `b868d59bee215ec0`

| Field | Value |
|---|---|
| SHA-256 | `b868d59bee215ec0026ef477d605a31a549bd9f0a06822d0c239fbc329623efc` |
| Family label | `Mirai` |
| File name | `ntb.arm64` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:32` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65f06b41d9397c841ea8a619d4bc15eb` |
| SHA-1 | `acd0d877c72f2b435a98fad8de46e66ab6ddf282` |
| SHA-256 | `b868d59bee215ec0026ef477d605a31a549bd9f0a06822d0c239fbc329623efc` |
| SHA3-384 | `9f505499725180ad08ae813bf6b4c02e4b08d4c3e3b5f18a87d74c8f375c938a719b26ce620db8d1d8067b0a41608771` |
| TLSH | `T137A312CCCB028C95F9E4E5F0A4A19B1EB86788346D7A63C304ADF5529667CC42EEF448` |
| SSDEEP | `3072:90RqC2mkF5PsuuZN8tMwlmy3fZsgbVOrJj:90RX2mk7PsX6oy3RlbVo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_b868d59b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b868d59bee215ec0026ef477d605a31a549bd9f0a06822d0c239fbc329623efc"
    family = "Mirai"
    file_name = "ntb.arm64"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:32"
  condition:
    hash.sha256(0, filesize) == "b868d59bee215ec0026ef477d605a31a549bd9f0a06822d0c239fbc329623efc"
}
```

### Sample 70: `75ba2cc4707db9c5`

| Field | Value |
|---|---|
| SHA-256 | `75ba2cc4707db9c5b1813ad7beaef10834ae7676c52ed3687eb75ada0ee86c30` |
| Family label | `Mirai` |
| File name | `ntb.arm7` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:30` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `919b85aaf6160a12838998ab031db58f` |
| SHA-1 | `307e022a1186c63f9fd4e8d3b4f960c6aee3f854` |
| SHA-256 | `75ba2cc4707db9c5b1813ad7beaef10834ae7676c52ed3687eb75ada0ee86c30` |
| SHA3-384 | `ca88f155f9837a1ae59bf052dda2f5a7adeabca93168d1e13289b523dade4b8d82b365cbe2af83e41b7735763b728a3d` |
| TLSH | `T12FA3128AD2A0A9F3C790813BB93F3F018E230AD954967AB471F99DC547CF2A675F1481` |
| SSDEEP | `3072:aaUMjWbYygTMNKX1qyCI9BuPEHBPymCqVwwO:3tohSx1bukyFwO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_75ba2cc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75ba2cc4707db9c5b1813ad7beaef10834ae7676c52ed3687eb75ada0ee86c30"
    family = "Mirai"
    file_name = "ntb.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:30"
  condition:
    hash.sha256(0, filesize) == "75ba2cc4707db9c5b1813ad7beaef10834ae7676c52ed3687eb75ada0ee86c30"
}
```

### Sample 71: `8a08cb03f4ca157a`

| Field | Value |
|---|---|
| SHA-256 | `8a08cb03f4ca157a57a5fe513968397127a6a7104db59c5c8164782247feb1cf` |
| Family label | `Mirai` |
| File name | `ntb.arm5` |
| File type | `elf` |
| First seen | `2026-08-08 17:59:28` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69aa9fff1078d9c505a2b7ff459e3bb7` |
| SHA-1 | `3eb8324176da3c1ce0bd3ceb2febaefc54a7d678` |
| SHA-256 | `8a08cb03f4ca157a57a5fe513968397127a6a7104db59c5c8164782247feb1cf` |
| SHA3-384 | `3105359bb4f3c404fda416d3bd847a28c24da664051c59e65e4eaa2037767fef63bb1c09abc43599d419239ca4ce7b70` |
| TLSH | `T15FA312B1E8C1507AE5919A87ED6E6C0B7077E318A793906DE50E70C2B2B4DDA0FE8053` |
| SSDEEP | `3072:aj0GfRTUVLpXLWpPNwf0t2MrohYPJTKamWWY:rBMFq0tXM8KaDWY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_8a08cb03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a08cb03f4ca157a57a5fe513968397127a6a7104db59c5c8164782247feb1cf"
    family = "Mirai"
    file_name = "ntb.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:28"
  condition:
    hash.sha256(0, filesize) == "8a08cb03f4ca157a57a5fe513968397127a6a7104db59c5c8164782247feb1cf"
}
```

### Sample 72: `dadf878d71926bee`

| Field | Value |
|---|---|
| SHA-256 | `dadf878d71926beebc94c50a6a93f1af7ec1650da318381234d308b2f76f68c1` |
| Family label | `Mirai` |
| File name | `ClashRoyalV2.apk` |
| File type | `apk` |
| First seen | `2026-08-08 17:59:28` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb9e3eff39a8e8c3f804fda1afd51f35` |
| SHA-1 | `f86a9e884d6651d7a647e1153b35e964b141d956` |
| SHA-256 | `dadf878d71926beebc94c50a6a93f1af7ec1650da318381234d308b2f76f68c1` |
| SHA3-384 | `8fc755afe7cbf66bb2d3758654f02b818463266023854dea595bc0bcea8c6dc5c27dca7e56b174bd6e6e5d5098bdeec2` |
| TLSH | `T1317423B6D65C3939C50044FA2666B9F2DDEA5BF08C3DFB12C1635061D88EA10CEAECD5` |
| SSDEEP | `6144:k28JGkLM3fveDv+Sc9p5xPYUUyoqQJ85D+PH+1KuSVx1izX4ZIWo6XO+jqHq1:gGkEfGv+SGp5xPYUUzqIGKPHbuSVxULE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_dadf878d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dadf878d71926beebc94c50a6a93f1af7ec1650da318381234d308b2f76f68c1"
    family = "Mirai"
    file_name = "ClashRoyalV2.apk"
    file_type = "apk"
    first_seen = "2026-08-08 17:59:28"
  condition:
    hash.sha256(0, filesize) == "dadf878d71926beebc94c50a6a93f1af7ec1650da318381234d308b2f76f68c1"
}
```

### Sample 73: `0cf5a4602e079735`

| Field | Value |
|---|---|
| SHA-256 | `0cf5a4602e07973557db81f3e6ede63a8612cd62ce657eda9995ac4293c21472` |
| Family label | `unknown` |
| File name | `gpon.sh` |
| File type | `sh` |
| First seen | `2026-08-08 17:41:52` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb7a71de452b4a45ac20dcf9b983ba9a` |
| SHA-1 | `18d2d39bfead8796e938a6f2ac489746eb2719b8` |
| SHA-256 | `0cf5a4602e07973557db81f3e6ede63a8612cd62ce657eda9995ac4293c21472` |
| SHA3-384 | `0974d8583355bc945774e954b952fc9984dff056fe7a6299098fcc5d7f3cf25566898fb30775476f43f2fccfcba56358` |
| TLSH | `T17911BACCECA18571F94CC817EAAE66A2E385251F0CC41849702E8B70EF5C8A5F282632` |
| SSDEEP | `24:8eVvstvrxNxSHx/FLxG22aHyvyTIoPYWY3Z:8s0hrxNxSHxdLxlSaTIowWYJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_0cf5a460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cf5a4602e07973557db81f3e6ede63a8612cd62ce657eda9995ac4293c21472"
    family = "unknown"
    file_name = "gpon.sh"
    file_type = "sh"
    first_seen = "2026-08-08 17:41:52"
  condition:
    hash.sha256(0, filesize) == "0cf5a4602e07973557db81f3e6ede63a8612cd62ce657eda9995ac4293c21472"
}
```

### Sample 74: `1c818b68c430fe59`

| Field | Value |
|---|---|
| SHA-256 | `1c818b68c430fe5960fc54429cd4df740b210de5633392be32451337a35ae0de` |
| Family label | `unknown` |
| File name | `unifi` |
| File type | `sh` |
| First seen | `2026-08-08 17:41:42` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f484c7909a10ae2ea09034797046727` |
| SHA-1 | `6cd85a585810decb57ccbdcde2f82532fb35d73c` |
| SHA-256 | `1c818b68c430fe5960fc54429cd4df740b210de5633392be32451337a35ae0de` |
| SHA3-384 | `4478f00212b365367c06d7f061b2ba0f173d0bf901a6418feba787711bba31f9c0ec8bb59788c208d079ac61a45fa9d7` |
| TLSH | `T1B71159C8FC969131B70E8C27E14A1981B781483F05952E1AB01EAE66BF1C165F266637` |
| SSDEEP | `24:yZUtD3jfFXjU3j7Xj35haHiEMDwRDEqAYhE14euR+:yZUd3j9XjU3j7XjpACEMDw/LhE1R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_1c818b68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c818b68c430fe5960fc54429cd4df740b210de5633392be32451337a35ae0de"
    family = "unknown"
    file_name = "unifi"
    file_type = "sh"
    first_seen = "2026-08-08 17:41:42"
  condition:
    hash.sha256(0, filesize) == "1c818b68c430fe5960fc54429cd4df740b210de5633392be32451337a35ae0de"
}
```

### Sample 75: `004050e1115593e1`

| Field | Value |
|---|---|
| SHA-256 | `004050e1115593e1588e6cc1691369dcd47939626fdec7f4f0c12eebd0a36a84` |
| Family label | `Mirai` |
| File name | `slim.mips` |
| File type | `elf` |
| First seen | `2026-08-08 17:41:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `533b2520ba8f23ea8fb1187a9587bd76` |
| SHA-1 | `372e0a45594b8ecc54775258c5672cd0f50e123a` |
| SHA-256 | `004050e1115593e1588e6cc1691369dcd47939626fdec7f4f0c12eebd0a36a84` |
| SHA3-384 | `ec0a5eacc0fcad1627b5d13a524d21d53665b423686e85833fe52fe8d25c1316d9895b34133bbfd385589cdc6abf0555` |
| TLSH | `T1ADD46C5377218F94E360D67101F38B659AA521A30FF350C2A3BCD6207A51A7D6D2FEE8` |
| TELFHASH | `t10f41af180a7813e0a6755c5d45edff36d6a330eb7e262c278e10e86ee769b824d14c1c` |
| SSDEEP | `12288:9+9rLu+44QutuTcnHnCFuu7T61zaNesn8pQakB1PA:M9ry+44QutuwHCFugT64NefkrA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_004050e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "004050e1115593e1588e6cc1691369dcd47939626fdec7f4f0c12eebd0a36a84"
    family = "Mirai"
    file_name = "slim.mips"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:40"
  condition:
    hash.sha256(0, filesize) == "004050e1115593e1588e6cc1691369dcd47939626fdec7f4f0c12eebd0a36a84"
}
```

### Sample 76: `2ba4a00fc3670740`

| Field | Value |
|---|---|
| SHA-256 | `2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e` |
| Family label | `Mirai` |
| File name | `slim.mpsl` |
| File type | `elf` |
| First seen | `2026-08-08 17:41:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a13842450449d043f2e3212429423078` |
| SHA-1 | `274c3734f2bb497b70f4f329841d9a6ad65e9e77` |
| SHA-256 | `2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e` |
| SHA3-384 | `ef50a5c5652600b4a8aefd30633cfd25551335a974bc39faaa71e96e6eb88b4e38b49c0a491104cc8f1423ab49bd05f1` |
| TLSH | `T1F2D45B02EF450FEBD4AFCD30856E835B14EE898B02C1A678A1FC895CBB8D55A4FD7548` |
| SSDEEP | `12288:ad0jfmV5rf3Hhnb2xOpKp0lbL5+8PZ+hl94m+rbPWjzcGzFLLAF23wxIuFsYYy18:UB56nxbbfV6jHnV5usvlxQrk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_2ba4a00f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e"
    family = "Mirai"
    file_name = "slim.mpsl"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:40"
  condition:
    hash.sha256(0, filesize) == "2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e"
}
```

### Sample 77: `53e970789db9c565`

| Field | Value |
|---|---|
| SHA-256 | `53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a` |
| Family label | `Mirai` |
| File name | `slim.arm7` |
| File type | `elf` |
| First seen | `2026-08-08 17:41:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62d77542c9426857882d3fb8ceaa76c5` |
| SHA-1 | `4e0357e561d6b0597dc0991f32c56c97bc7e7bca` |
| SHA-256 | `53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a` |
| SHA3-384 | `2abd62ef13be4aaac390d03c0d28873419866d9a2ebc23906e6820c960cc96d6a09fa4ad86737c307a2b43c94e8f30bb` |
| TLSH | `T12C84E096F7023E82C8D7C57519C681895789E95B33F383463B42AA7B3C397368F29385` |
| SSDEEP | `6144:2oa8sPtcnDGGzryRQ1vqGsj4GV+Aw8Y4Mi8pL+TKH:ba8sVcZAiskGV+Aw8Ys8pL+TK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_53e97078
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a"
    family = "Mirai"
    file_name = "slim.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:40"
  condition:
    hash.sha256(0, filesize) == "53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a"
}
```

### Sample 78: `52702f23389450e0`

| Field | Value |
|---|---|
| SHA-256 | `52702f23389450e08920fa1e45d54bebcc318a94d4ab7cf87c150865b97b1992` |
| Family label | `Mirai` |
| File name | `slim.arm64` |
| File type | `elf` |
| First seen | `2026-08-08 17:41:39` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f23e04f43626270f04f49ed1448b6ba5` |
| SHA-1 | `96eb38968d0817a0961ddee27cfdae4ef03771d0` |
| SHA-256 | `52702f23389450e08920fa1e45d54bebcc318a94d4ab7cf87c150865b97b1992` |
| SHA3-384 | `c7321221b66105143ff729985ccbf35afec8efb7f9d182fea1a10f7461d26af7c0c63ad5bf3b5db66b6cce408e1811a0` |
| TLSH | `T13FD48D98FE5E3D43E2C7E37DDE8A43A1312B75E4D32782A36541424DE4C6EE9CBA1211` |
| SSDEEP | `12288:Z7RB7rNPwRUOwomC3eVkNz9GawGqzhnytSFHQH61s5Lh0o:Z7RVRnom82p4tSFH4B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_52702f23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52702f23389450e08920fa1e45d54bebcc318a94d4ab7cf87c150865b97b1992"
    family = "Mirai"
    file_name = "slim.arm64"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:39"
  condition:
    hash.sha256(0, filesize) == "52702f23389450e08920fa1e45d54bebcc318a94d4ab7cf87c150865b97b1992"
}
```

### Sample 79: `8ee5acc0b90bfe8d`

| Field | Value |
|---|---|
| SHA-256 | `8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79` |
| Family label | `Mirai` |
| File name | `slim.arm` |
| File type | `elf` |
| First seen | `2026-08-08 17:41:39` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfccc539912517ad6b6df738adef58a3` |
| SHA-1 | `c18bd89242a4d2b4ebcb64ea39696e49260cbee6` |
| SHA-256 | `8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79` |
| SHA3-384 | `099bc1e727ef64b431bd785d94712d8c9fe369dba996647f439b3359092ddbe371989c7e4dd55cf7316a0999d58e3fd0` |
| TLSH | `T157B43955F8809F61C6D135B6F64D42A873070BB9D3EB72069A245B343BEB86B0F3A605` |
| TELFHASH | `t128f09ec3575639f157e4010480da715d9dfa38582f062441054da74c5e2aec434b4932` |
| SSDEEP | `12288:sxfuf9/6hBS0XqbCLThPDmhKXCiEhi8pLgTbS:s4f9/oFThSifX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_8ee5acc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79"
    family = "Mirai"
    file_name = "slim.arm"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:39"
  condition:
    hash.sha256(0, filesize) == "8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79"
}
```

### Sample 80: `a758ff0a172386bd`

| Field | Value |
|---|---|
| SHA-256 | `a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc` |
| Family label | `Vidar` |
| File name | `build_mix.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b971e00a0514a9dd90ae4147fd2be083` |
| SHA-1 | `814b4d722a9bc8eff65d7833ccf9b47cf486c3f2` |
| SHA-256 | `a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc` |
| SHA3-384 | `36e054c9a0d80abc8dbe3aacbc55317b6e38db38217feda9f986454dacc9487f6bc6a563665aea2a48b33c3b82cb13fe` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14D267B53AD9148FAC0A5A33189B78266B634BC0C5B3123D72EA1BFB46F727D06E35750` |
| SSDEEP | `49152:wVhy1+862e4pajiT6IpFK8jw9xJ3rse5UAWk6ExPRg1l1iQ:wifKJ71UAWk6ExJGlZ` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_080_a758ff0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc"
    family = "Vidar"
    file_name = "build_mix.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:46"
  condition:
    hash.sha256(0, filesize) == "a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc"
}
```

### Sample 81: `dff83bede85f33f1`

| Field | Value |
|---|---|
| SHA-256 | `dff83bede85f33f1229e21cabc1b159f8b11230c9b4b6d2e46432d7094c7a917` |
| Family label | `Stealc` |
| File name | `KLHdfs_260731110521.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68151cd3c5175750d58735083f381838` |
| SHA-1 | `cb60dc8be2fe05517280d77bbe3415979f339840` |
| SHA-256 | `dff83bede85f33f1229e21cabc1b159f8b11230c9b4b6d2e46432d7094c7a917` |
| SHA3-384 | `f246e8635bd8170a89f2bb0427f90b385677f2d1da0975d9fc6462f5a47f1c1f8c82328043864428632c7a4e83f1a3e6` |
| IMPHASH | `e9dd64dcce15e249bad873d9dec07f6f` |
| TLSH | `T198058D1AF3A502F9D17BC178C9424552EB72B8565330AADF03E14A6A1F376E05F3EB21` |
| SSDEEP | `12288:kngwZs/X8eipbJVfMxBkfCTE+HCTITkyxBlDetAqxSvoD:kgwaMeipbfCkKTEGmI4yb+` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_081_dff83bed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dff83bede85f33f1229e21cabc1b159f8b11230c9b4b6d2e46432d7094c7a917"
    family = "Stealc"
    file_name = "KLHdfs_260731110521.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:38"
  condition:
    hash.sha256(0, filesize) == "dff83bede85f33f1229e21cabc1b159f8b11230c9b4b6d2e46432d7094c7a917"
}
```

### Sample 82: `3e79cc9aee9a74b4`

| Field | Value |
|---|---|
| SHA-256 | `3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6` |
| Family label | `Stealc` |
| File name | `jhgkuyyg.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e21d4f7b0f651bb8ec310da7c213f25` |
| SHA-1 | `0a502d54762b6562de80ce64e549e46c4bacf8cd` |
| SHA-256 | `3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6` |
| SHA3-384 | `c3c07189566dcc8781189a840ef29228f4cba5fd47b6c4ebafd00855e32b04030aa8ef505d7bb9478fbf8a0adb51d104` |
| IMPHASH | `e9dd64dcce15e249bad873d9dec07f6f` |
| TLSH | `T121057C1AF3A502F8D07BC1B8C9424552EB72B85653709ADF03E15A6A1F376E05F3EB21` |
| SSDEEP | `12288:hg9ANYPuwBvX753/llDB/CjE+HSDNBSyxBlDetAqxSv9Kj:hMAqvBvX7RXBqjEGGNBSybe` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_082_3e79cc9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
    family = "Stealc"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:29"
  condition:
    hash.sha256(0, filesize) == "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
}
```

### Sample 83: `a1e17215620c5d63`

| Field | Value |
|---|---|
| SHA-256 | `a1e17215620c5d6344e4708cade11bcc22581d5a023d053d6622c6b9801c8717` |
| Family label | `Stealc` |
| File name | `cheat_X.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, signed, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82bdb4f9e0d54ae25436306c472a1839` |
| SHA-1 | `35ee6d522ca63517c9d758ab5420782c48a77650` |
| SHA-256 | `a1e17215620c5d6344e4708cade11bcc22581d5a023d053d6622c6b9801c8717` |
| SHA3-384 | `490ca8f7e53fe659e3631dc3568893f33fb526b427d7543a60a1694e2cd0e908127576e49eecc982697d7c31dfeb1656` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1BE86E003BCA148F9C0D5A73189A76262B775BC091B3233D72E60ABB82F767D15E76710` |
| SSDEEP | `98304:pYNelqLoVNIiuXXiS6jmVVLdiCjFouhNqavILlX4u+FmPKOPzpd5kD+:pI0qLoszX6j4LdiCZHhNq0OlXyFUBNh` |
| ICON-DHASH | `a2710a43338e47ae` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_083_a1e17215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e17215620c5d6344e4708cade11bcc22581d5a023d053d6622c6b9801c8717"
    family = "Stealc"
    file_name = "cheat_X.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:25"
  condition:
    hash.sha256(0, filesize) == "a1e17215620c5d6344e4708cade11bcc22581d5a023d053d6622c6b9801c8717"
}
```

### Sample 84: `f6816999eaa87420`

| Field | Value |
|---|---|
| SHA-256 | `f6816999eaa874202286984abfab55e4f586a5e895328b542f5500d279ad7a58` |
| Family label | `RemusStealer` |
| File name | `xqAAE.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6205c7149e390e846e0099c23036c02a` |
| SHA-1 | `ad63aa6b33f4ca38456ab5190267bd727fc32c66` |
| SHA-256 | `f6816999eaa874202286984abfab55e4f586a5e895328b542f5500d279ad7a58` |
| SHA3-384 | `ff02bb326150c83462c924ffd1505b691bd9850da3d9e48fe8d674d85b3104b355df38e1f2980031bc64651283e99257` |
| IMPHASH | `722b7cd15bfe3bb8fbd1ebc6544623e0` |
| TLSH | `T10E243A6BD25371FCD552C07853667222B732BA384724AEFB0393C3359D22EC46E78965` |
| SSDEEP | `3072:kHSo4cHafRi2+BJIrLtNrxBMhDunBq8Qjd3D/UXhvYEsj9UzzqjFfzE98:kHKR+BJ3uBtQj5Ayz9FFfzE` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_084_f6816999
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6816999eaa874202286984abfab55e4f586a5e895328b542f5500d279ad7a58"
    family = "RemusStealer"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:11"
  condition:
    hash.sha256(0, filesize) == "f6816999eaa874202286984abfab55e4f586a5e895328b542f5500d279ad7a58"
}
```

### Sample 85: `0b5775fc346a8aee`

| Field | Value |
|---|---|
| SHA-256 | `0b5775fc346a8aee83b40281dca8aa160b76892675d54d5882869c473ab96205` |
| Family label | `RemusStealer` |
| File name | `ARbeb.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2be5702ea078cc922e9c1348009705f8` |
| SHA-1 | `a6cd19946ffea2c41b5728cd95788196e076424f` |
| SHA-256 | `0b5775fc346a8aee83b40281dca8aa160b76892675d54d5882869c473ab96205` |
| SHA3-384 | `e3e76824a25bb2dc7bc975672cb6a3a7761a7f99bd32f67ece7549ac56948dd31562818c45095f2c18b4622858ac39a5` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T14E245C7BD25371FCD553C03892663222B732BA6947209EF74392C3359E21AC06F7A978` |
| SSDEEP | `3072:8sLRi2BW051IDQQctcCm76F/cCV+bdS2DN20O9bj1hu4yJyFJyVzn0nL:8uRyU5tcCr0CV+bd3NIv1yVYnL` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_085_0b5775fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b5775fc346a8aee83b40281dca8aa160b76892675d54d5882869c473ab96205"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:09"
  condition:
    hash.sha256(0, filesize) == "0b5775fc346a8aee83b40281dca8aa160b76892675d54d5882869c473ab96205"
}
```

### Sample 86: `a7e6ece576a9c74f`

| Field | Value |
|---|---|
| SHA-256 | `a7e6ece576a9c74f7e9d80545ea5faf1f7542ed7b557cb6be671edd7452c4d69` |
| Family label | `RemusStealer` |
| File name | `KLHdfs.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e45b7a0c5d4a29234bb77b9972aa069` |
| SHA-1 | `490dede7cc84342d37d35c91f61fd9c30e4d22e6` |
| SHA-256 | `a7e6ece576a9c74f7e9d80545ea5faf1f7542ed7b557cb6be671edd7452c4d69` |
| SHA3-384 | `38de0c52c15ccadc55f2bed2dd1e4d697b4d602ae350eb64f70339d7ffe3c9f86ce60dea6447768232bea4b6ebc217b8` |
| IMPHASH | `722b7cd15bfe3bb8fbd1ebc6544623e0` |
| TLSH | `T10E243A6BD25371FCD652C07853663222B732BA384724AEFB0393C3359D22EC46E79965` |
| SSDEEP | `3072:kHSo4cHafRi2+BJIrLtNrxBMhDunBq8Qjd3D/UXhvYEsj9Uz0qFHFfzE98:kHKR+BJ3uBtQj5Ayz90FfzE` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_086_a7e6ece5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7e6ece576a9c74f7e9d80545ea5faf1f7542ed7b557cb6be671edd7452c4d69"
    family = "RemusStealer"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:07"
  condition:
    hash.sha256(0, filesize) == "a7e6ece576a9c74f7e9d80545ea5faf1f7542ed7b557cb6be671edd7452c4d69"
}
```

### Sample 87: `0c8531102efedf99`

| Field | Value |
|---|---|
| SHA-256 | `0c8531102efedf9944961949712c56316ccc79c39e1ee4aef15fc46809f707ff` |
| Family label | `RemusStealer` |
| File name | `arFtU.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `578abf40737eddf6b8c21274c53c74c9` |
| SHA-1 | `8903a23ab53a19960beb99d8f7d3576cf4a4498f` |
| SHA-256 | `0c8531102efedf9944961949712c56316ccc79c39e1ee4aef15fc46809f707ff` |
| SHA3-384 | `a890c44c12228a579e759613af28c2b1302f7513b976038b44dc1a0152da7e3b0277823bcce5d7553f4eda3f36d8ec7e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T162F52817BD9148F5C0A5A332C9A74256B624BC4C9B3233D72EA0BEB82F727D05E35B54` |
| SSDEEP | `49152:jmeWEplFJAEetT/3kVHByzHozXiOrfgOScpBG:jkEawzX/rfpScpI` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_087_0c853110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c8531102efedf9944961949712c56316ccc79c39e1ee4aef15fc46809f707ff"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:05"
  condition:
    hash.sha256(0, filesize) == "0c8531102efedf9944961949712c56316ccc79c39e1ee4aef15fc46809f707ff"
}
```

### Sample 88: `8f908fcb7f48b8b8`

| Field | Value |
|---|---|
| SHA-256 | `8f908fcb7f48b8b8a2c0f708328038a2518a0f2143495108aaae552b3f724838` |
| Family label | `RemusStealer` |
| File name | `KJHJHKJKJH.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:39:02` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `772eca8a6e5907351a91907091dbb95d` |
| SHA-1 | `cc6550974f6f5fde199acc3f3868382b8b3911f8` |
| SHA-256 | `8f908fcb7f48b8b8a2c0f708328038a2518a0f2143495108aaae552b3f724838` |
| SHA3-384 | `da91a5c775559b4dcb0899dff9f7660ae7ef5dba118a05d0704144185949989260eae256205168363d23608d080f5650` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T124F53817BD9548F5C0A5A33589B74252BA68BC0C5B3133D72EA0BEB82F727C06E35B54` |
| SSDEEP | `24576:jDjKcAjKtqRXJTTSnMwffTvRZXoxQr5OkL6jVgw8Zy8wwv/oBele5I92bi+A8seA:jDjNTtMJTO/ffTXScajVGXgQ8stx` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_088_8f908fcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f908fcb7f48b8b8a2c0f708328038a2518a0f2143495108aaae552b3f724838"
    family = "RemusStealer"
    file_name = "KJHJHKJKJH.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:02"
  condition:
    hash.sha256(0, filesize) == "8f908fcb7f48b8b8a2c0f708328038a2518a0f2143495108aaae552b3f724838"
}
```

### Sample 89: `b8bb043a7006cc81`

| Field | Value |
|---|---|
| SHA-256 | `b8bb043a7006cc816d047c77560a96b8364ef1fe422293ffa31069b979a058b7` |
| Family label | `RemusStealer` |
| File name | `R7.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:38:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d48b7edd25bcf45d544cce90fe60072a` |
| SHA-1 | `463140cfd9968a93aa038cfcae243a710bf3efee` |
| SHA-256 | `b8bb043a7006cc816d047c77560a96b8364ef1fe422293ffa31069b979a058b7` |
| SHA3-384 | `ff097c78dfdff7d5ce976b5de32555939be60421ffcc92c3ac50fb54b4c0e8fd965a47bef5d659ae76d53d566861a9ad` |
| IMPHASH | `722b7cd15bfe3bb8fbd1ebc6544623e0` |
| TLSH | `T111243A6BD25371FCD552C07853663222B732BA384724AEFB0393C3359D22EC4AE79965` |
| SSDEEP | `3072:kHSo4cHafRi2+BJIrLtNrxBMhDunBq8Qjd3D/UXhvYEsj9UzhqqFfzE98:kHKR+BJ3uBtQj5Ayz96FfzE` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_089_b8bb043a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bb043a7006cc816d047c77560a96b8364ef1fe422293ffa31069b979a058b7"
    family = "RemusStealer"
    file_name = "R7.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:59"
  condition:
    hash.sha256(0, filesize) == "b8bb043a7006cc816d047c77560a96b8364ef1fe422293ffa31069b979a058b7"
}
```

### Sample 90: `6f737981ac722be8`

| Field | Value |
|---|---|
| SHA-256 | `6f737981ac722be8ae1c05a295667d050abe1b45dd946e1dbf4c46467c517c5f` |
| Family label | `RemusStealer` |
| File name | `R6.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:38:56` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c7f15e714e9edc2e48375e882ac8151` |
| SHA-1 | `82d525dc9849d53a68fec90ae0340247e97c8d71` |
| SHA-256 | `6f737981ac722be8ae1c05a295667d050abe1b45dd946e1dbf4c46467c517c5f` |
| SHA3-384 | `72d4c8a714df5ceacd2747183f373fafad066c1df4ebc053a9a50077b9651cbefba25a719bf7cfa661b9443f52ebbe4c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1FAE56B07ADB448F9C0DAE739886B5226BB70B809473133D32E91BA792F767D09E35744` |
| SSDEEP | `49152:jSWABYXozXjysuFQQ/qhOrDVf9PUk/P9pDu:j5cqLR39pu` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_090_6f737981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f737981ac722be8ae1c05a295667d050abe1b45dd946e1dbf4c46467c517c5f"
    family = "RemusStealer"
    file_name = "R6.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:56"
  condition:
    hash.sha256(0, filesize) == "6f737981ac722be8ae1c05a295667d050abe1b45dd946e1dbf4c46467c517c5f"
}
```

### Sample 91: `450216a711f8b337`

| Field | Value |
|---|---|
| SHA-256 | `450216a711f8b3371a2936923201f204fa1c686a2b831dac4a1c0094c105a5fd` |
| Family label | `RemusStealer` |
| File name | `kJHGFDs.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:38:48` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ec924aba437e9eb434ebfa6394651e6` |
| SHA-1 | `2b12c2689c539495a04261278c1f5ad7b01767bd` |
| SHA-256 | `450216a711f8b3371a2936923201f204fa1c686a2b831dac4a1c0094c105a5fd` |
| SHA3-384 | `04df86bee2672c24b85d62ef43c0904223fb0d8b176564c48214c3bb161a9b019f35bb0359bfeae7d7dc5415ae68b5ee` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14AF53917BC9548F5D095A33289B74252BA64BC0C9B3233D72EA0BEB82F763D06D35B54` |
| SSDEEP | `49152:/R2Jxmzwn39fBPgcwJQ+2CH8ZgUE72ZdWV:/G5AANFE72ZE` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_091_450216a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "450216a711f8b3371a2936923201f204fa1c686a2b831dac4a1c0094c105a5fd"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:48"
  condition:
    hash.sha256(0, filesize) == "450216a711f8b3371a2936923201f204fa1c686a2b831dac4a1c0094c105a5fd"
}
```

### Sample 92: `c1e0d2c9e04fcdb1`

| Field | Value |
|---|---|
| SHA-256 | `c1e0d2c9e04fcdb10ff2d4565758ceda1331fc80def548742a79b60be81da9b9` |
| Family label | `RemusStealer` |
| File name | `KLLNMF.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:38:37` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73c4b9b23fd8d5b8564bb968780b38d4` |
| SHA-1 | `a0e52b1ecf822a10499d87b60651ed05b174ed58` |
| SHA-256 | `c1e0d2c9e04fcdb10ff2d4565758ceda1331fc80def548742a79b60be81da9b9` |
| SHA3-384 | `ef2dd9d633be24c33802d265691cafb0aeda2fc1d56da7b39af246646475d24dffb2b25be4bb80d6695ed61c15061a68` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C0F53817BC9548F5C1A5A33289B74256B664BC0C5B3233D72EA0BEB82F727D06E35B14` |
| SSDEEP | `24576:xUj/k/v/lZ2cgzqjJXlYwOMvrtruofH5270bnt8qLf3v/oBele5I92bi+FakKX3x:xUj8Hz2JqjXYOB5fH5TJZg1anL` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_092_c1e0d2c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e0d2c9e04fcdb10ff2d4565758ceda1331fc80def548742a79b60be81da9b9"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:37"
  condition:
    hash.sha256(0, filesize) == "c1e0d2c9e04fcdb10ff2d4565758ceda1331fc80def548742a79b60be81da9b9"
}
```

### Sample 93: `b55e84bfa44ace66`

| Field | Value |
|---|---|
| SHA-256 | `b55e84bfa44ace66e3abecae66c7370edd6419e3280c1d317a45f8c98c21fb59` |
| Family label | `RemusStealer` |
| File name | `ARbeb.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:38:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87a8966cce57c86b6c836149ab0ebcd7` |
| SHA-1 | `86c21f19c62737befb4e8ff99fc83c494e3c55ef` |
| SHA-256 | `b55e84bfa44ace66e3abecae66c7370edd6419e3280c1d317a45f8c98c21fb59` |
| SHA3-384 | `f5ba53c45a5da63c78fbde88f2de327d10afef8958b141fd596f2dfb6f34c19d75bbb4f84b3da351040c4dc4448c14a0` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E5F53817BC9548F9C0A5A732C9A74252BA64BC0C5B3133D72EA0BEB82F763D06D35B54` |
| SSDEEP | `49152:AAfUJ/SRt35k0K+x4e9tEIcXLRfsNQ1lRWgN9K:AzkNcXtVIWU` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_093_b55e84bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b55e84bfa44ace66e3abecae66c7370edd6419e3280c1d317a45f8c98c21fb59"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:29"
  condition:
    hash.sha256(0, filesize) == "b55e84bfa44ace66e3abecae66c7370edd6419e3280c1d317a45f8c98c21fb59"
}
```

### Sample 94: `76447f7abf34199b`

| Field | Value |
|---|---|
| SHA-256 | `76447f7abf34199b8f1bf486bc77b0ee171afa0d1ec927d69e5e454595d05867` |
| Family label | `RemusStealer` |
| File name | `kJHGFDs.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:38:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ff89e9dbf1a9c5a3b4f4c53e8d651f9` |
| SHA-1 | `b1de27fa6a6eaa09989632e7aaca5ee6cda74037` |
| SHA-256 | `76447f7abf34199b8f1bf486bc77b0ee171afa0d1ec927d69e5e454595d05867` |
| SHA3-384 | `1d2c348641d7cdb0a269c0290169eaf086bdbc270ac6e10188310fa31b7806d077cfbae1cfdd79c5a0ba90053f76d0f1` |
| IMPHASH | `934864fad2e0d984459abdc576cdc4a7` |
| TLSH | `T189245C7BD25371FCD553C03892663222B732BA6947249EF74392C3359E21AC06F7A978` |
| SSDEEP | `3072:8sLRi2BW051IDQQctcCm76F/cCV+bdS2DN20O9bj1hu4yJyFJyVonYnL:8uRyU5tcCr0CV+bd3NIv1yVNnL` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_094_76447f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76447f7abf34199b8f1bf486bc77b0ee171afa0d1ec927d69e5e454595d05867"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:22"
  condition:
    hash.sha256(0, filesize) == "76447f7abf34199b8f1bf486bc77b0ee171afa0d1ec927d69e5e454595d05867"
}
```

### Sample 95: `4e816325a4d8ca11`

| Field | Value |
|---|---|
| SHA-256 | `4e816325a4d8ca11aea96fa9f0118200acee2cfb8b4e94e1f06b8d336c1dac3d` |
| Family label | `RemcosRAT` |
| File name | `weprovideforbesthingstocomebackgoodthings.hta` |
| File type | `hta` |
| First seen | `2026-08-08 17:38:11` |
| Reporter | `abuse_ch` |
| Tags | `hta, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `623bc9114d118592170599585e5cf60e` |
| SHA-1 | `4b02959636f06c0aa79b63d9c6e43bb191e56e63` |
| SHA-256 | `4e816325a4d8ca11aea96fa9f0118200acee2cfb8b4e94e1f06b8d336c1dac3d` |
| SHA3-384 | `c60581ecfcfe8eaa8a44996a6de429de6af84cdbbf76475f1909e3ef6b58f092f533920eda20afb0b027e887f402a15b` |
| TLSH | `T148352969F98B15B7FD129590EC002389E7B7023E4361A63C3365C3C8B5F1A77649A9F2` |
| SSDEEP | `768:1fHF7dD7pHddNrTvjfxTvkvxkfxdpJ3/Hf1z7dpHvQQGdBl9p9T7p1xp37HNFN7y:7zJOgK7dadd` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_095_4e816325
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e816325a4d8ca11aea96fa9f0118200acee2cfb8b4e94e1f06b8d336c1dac3d"
    family = "RemcosRAT"
    file_name = "weprovideforbesthingstocomebackgoodthings.hta"
    file_type = "hta"
    first_seen = "2026-08-08 17:38:11"
  condition:
    hash.sha256(0, filesize) == "4e816325a4d8ca11aea96fa9f0118200acee2cfb8b4e94e1f06b8d336c1dac3d"
}
```

### Sample 96: `5ab9730d806b865f`

| Field | Value |
|---|---|
| SHA-256 | `5ab9730d806b865f8f8dc52ae90ee4280dc3e54a23ae66226a9b7228e7b6c572` |
| Family label | `MassLogger` |
| File name | `jscotbpl.dat` |
| File type | `exe` |
| First seen | `2026-08-08 17:37:55` |
| Reporter | `abuse_ch` |
| Tags | `dat, exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc88ad0b4dfbba15fbe4bd94e20f6a46` |
| SHA-1 | `2c4a02971ec81b6ee6095dbd604bca1b24c70182` |
| SHA-256 | `5ab9730d806b865f8f8dc52ae90ee4280dc3e54a23ae66226a9b7228e7b6c572` |
| SHA3-384 | `06c89949a624d18b67a6bf0f0045f6e1f1b05aa6bbcac2e7371ab7f9a006f9277768da98a6d962027cfc20697db751a0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CE93080937EC9814EABF8572E67151200B7ABC554936D21D1BD8B4EE2B3BA8085C7BD3` |
| SSDEEP | `1536:PmhwZC18Dq21Kth+hThN/UP/UJS/UJ5/UJpQMhVVYpLN7FMRFZPp4nw:MwZC18DqPth+hThN/UP/UJS/UJ5/UJpJ` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_096_5ab9730d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ab9730d806b865f8f8dc52ae90ee4280dc3e54a23ae66226a9b7228e7b6c572"
    family = "MassLogger"
    file_name = "jscotbpl.dat"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:55"
  condition:
    hash.sha256(0, filesize) == "5ab9730d806b865f8f8dc52ae90ee4280dc3e54a23ae66226a9b7228e7b6c572"
}
```

### Sample 97: `f46ce77474c6e0dd`

| Field | Value |
|---|---|
| SHA-256 | `f46ce77474c6e0dd72f59b4d8b784b85dab6d9765bc3705f466491c74cacebe1` |
| Family label | `MassLogger` |
| File name | `Teleg.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:37:52` |
| Reporter | `abuse_ch` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69ca07d354c419e152a858cf3a98ee54` |
| SHA-1 | `ad30231e8b41fb61757b361e333dd6f2b32a17cc` |
| SHA-256 | `f46ce77474c6e0dd72f59b4d8b784b85dab6d9765bc3705f466491c74cacebe1` |
| SHA3-384 | `ea0be61519af8df31fdb674f0cebcd9b5f218defd1ce577f1ec0e2d0764c46357ab667d3ddf128ba07d87b6708255b01` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17794E52873F88A09F2FF6FB5A8B049118A32F84B9D35D74E1988509D0DB2B91DD50B77` |
| SSDEEP | `6144:ZTJ9f7/yGi5aeXZMUDg440NbnbSOklUHAdcz:ZTJ9zaGnCvDhN3k` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_097_f46ce774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f46ce77474c6e0dd72f59b4d8b784b85dab6d9765bc3705f466491c74cacebe1"
    family = "MassLogger"
    file_name = "Teleg.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:52"
  condition:
    hash.sha256(0, filesize) == "f46ce77474c6e0dd72f59b4d8b784b85dab6d9765bc3705f466491c74cacebe1"
}
```

### Sample 98: `0e663e77479d9bc6`

| Field | Value |
|---|---|
| SHA-256 | `0e663e77479d9bc6bfe7faa3ce01fde7f57b7e3f736db2ca86eafad6ad01906a` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:37:39` |
| Reporter | `abuse_ch` |
| Tags | `ConnectWise, exe, RMM, ScreenConnect, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `835adc3f86c807e5d0fb43c1843636eb` |
| SHA-1 | `5f8eef0ad3a55830d97a505509e5fabab66ab5a5` |
| SHA-256 | `0e663e77479d9bc6bfe7faa3ce01fde7f57b7e3f736db2ca86eafad6ad01906a` |
| SHA3-384 | `731434cd5c5ced6a61c98c919fb975378d146c845dda61254a132b72aeb71173909037c5cf1154226fb28ccf5226a923` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T15EC61201B3D689B5D0BF0638D87A56665A34BC049712C7BF5798B96E2E32BC04E32377` |
| SSDEEP | `196608:21TfefPqBQyiixtMjGZ1jhlrwUNQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:2CPnjGrrGPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_098_0e663e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e663e77479d9bc6bfe7faa3ce01fde7f57b7e3f736db2ca86eafad6ad01906a"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:39"
  condition:
    hash.sha256(0, filesize) == "0e663e77479d9bc6bfe7faa3ce01fde7f57b7e3f736db2ca86eafad6ad01906a"
}
```

### Sample 99: `a98db0078f7af279`

| Field | Value |
|---|---|
| SHA-256 | `a98db0078f7af27980b9c6c62afc0440399073d4cf8cf95c9dcbe3231804cd1b` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:37:33` |
| Reporter | `abuse_ch` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff06506ed85b3be69fb665452f1d52a6` |
| SHA-1 | `315982afe1fa03b2d45e44bb5bcad33b3dc66e83` |
| SHA-256 | `a98db0078f7af27980b9c6c62afc0440399073d4cf8cf95c9dcbe3231804cd1b` |
| SHA3-384 | `6f16ca48777aa5e638f19c37045e5b8becbc0d331adff26958ee6921a341257e1a1b7c709ef7f7e531227ecf0930df3f` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T199C61201B3D689B5D0BF0638D87A56665A34BC049712C7BF5798B96E2E32BC04E32377` |
| SSDEEP | `196608:71TfefPq3QyiixtMjGZ1jhlrwUNQyiixtMjoQyiixtMjXQyiixtMjBQyiixtMj:7oPnjGrrGPnj5PnjgPnjqPnj` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_099_a98db007
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98db0078f7af27980b9c6c62afc0440399073d4cf8cf95c9dcbe3231804cd1b"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:33"
  condition:
    hash.sha256(0, filesize) == "a98db0078f7af27980b9c6c62afc0440399073d4cf8cf95c9dcbe3231804cd1b"
}
```

### Sample 100: `997a64155caf5f63`

| Field | Value |
|---|---|
| SHA-256 | `997a64155caf5f6374ae2b6627a80fe4c31dd9102e31c4a2ec8affc84d6dae28` |
| Family label | `unknown` |
| File name | `9z7BGnRGpgs8cZv7.exe` |
| File type | `exe` |
| First seen | `2026-08-08 17:36:41` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `040eaa58bfef491c9234f396eedffe0c` |
| SHA-1 | `932c15edddbab04949a61c13175182de6329fb76` |
| SHA-256 | `997a64155caf5f6374ae2b6627a80fe4c31dd9102e31c4a2ec8affc84d6dae28` |
| SHA3-384 | `ea22110d1d54413617e9edab8d41981ecd8156a1ac57d88a71dc0fc63cd4e883dc69a5040204af893274d83182c9ff11` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T126D523A265F66DF4C437C77A8F82F4AEB079778187755E87B2CC68044C23198987A770` |
| SSDEEP | `49152:Ki0e6+S41sqzTgFR1qto4BO8gWbQErE6Qn1h4Ngs8jfsY9VolypK/PMYadc/:D0ec41sqziq+4hHQEBuzX9Vol1M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_997a6415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "997a64155caf5f6374ae2b6627a80fe4c31dd9102e31c4a2ec8affc84d6dae28"
    family = "unknown"
    file_name = "9z7BGnRGpgs8cZv7.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:36:41"
  condition:
    hash.sha256(0, filesize) == "997a64155caf5f6374ae2b6627a80fe4c31dd9102e31c4a2ec8affc84d6dae28"
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
 * Generated: 2026-08-09T02:31:52.515296+00:00
 */

rule MalwareBazaar_unknown_001_ff100c16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff100c165b2714dad2a3b60efd7ba182ae4299e06edfcd1332bd679e6bc08e34"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-09 02:23:53"
  condition:
    hash.sha256(0, filesize) == "ff100c165b2714dad2a3b60efd7ba182ae4299e06edfcd1332bd679e6bc08e34"
}

rule MalwareBazaar_NanoCore_002_1ae9cd2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae9cd2b41297f16ce7dc361cae4b890a984c792351b198c1190d093a908e0e5"
    family = "NanoCore"
    file_name = "291E68D417E3A13F19BD630EB5533CB5.exe"
    file_type = "exe"
    first_seen = "2026-08-09 02:15:05"
  condition:
    hash.sha256(0, filesize) == "1ae9cd2b41297f16ce7dc361cae4b890a984c792351b198c1190d093a908e0e5"
}

rule MalwareBazaar_unknown_003_14a0c3c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14a0c3c28384e040fcf9317dacd5400b9cecd9bdde92fff5f242671fab246a98"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-09 02:09:58"
  condition:
    hash.sha256(0, filesize) == "14a0c3c28384e040fcf9317dacd5400b9cecd9bdde92fff5f242671fab246a98"
}

rule MalwareBazaar_Mirai_004_c8d5f2f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8d5f2f64803a2623f1d2178757b5f48329eaebaa659e4ed8bdbe1b0e7829308"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-08-09 02:02:02"
  condition:
    hash.sha256(0, filesize) == "c8d5f2f64803a2623f1d2178757b5f48329eaebaa659e4ed8bdbe1b0e7829308"
}

rule MalwareBazaar_unknown_005_96282f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96282f6e46762cc263af994af5ce98d82b9d7291f2d4f16e9ea8139db6830b6f"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-09 02:01:58"
  condition:
    hash.sha256(0, filesize) == "96282f6e46762cc263af994af5ce98d82b9d7291f2d4f16e9ea8139db6830b6f"
}

rule MalwareBazaar_unknown_006_165c672e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "165c672e9b063ba3e5dba0f42cfa9399819cac49cc96310078a8208a93dcb888"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-09 01:55:40"
  condition:
    hash.sha256(0, filesize) == "165c672e9b063ba3e5dba0f42cfa9399819cac49cc96310078a8208a93dcb888"
}

rule MalwareBazaar_unknown_007_81ccc896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81ccc89654440104a015203014b42dfee2a32ea8578c58f618368035c3977f4e"
    family = "unknown"
    file_name = "gg2"
    file_type = "elf"
    first_seen = "2026-08-09 01:31:44"
  condition:
    hash.sha256(0, filesize) == "81ccc89654440104a015203014b42dfee2a32ea8578c58f618368035c3977f4e"
}

rule MalwareBazaar_unknown_008_5635c7f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f"
    family = "unknown"
    file_name = "5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f"
    file_type = "sh"
    first_seen = "2026-08-09 01:30:12"
  condition:
    hash.sha256(0, filesize) == "5635c7f820a749626974963c000d2ba4bdce8e2d70412532d719770f55a9406f"
}

rule MalwareBazaar_unknown_009_189f392a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189f392aa5cae728665ebeb83f61698cc69ee653215e9e44eb8bdd2db5794101"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 01:29:38"
  condition:
    hash.sha256(0, filesize) == "189f392aa5cae728665ebeb83f61698cc69ee653215e9e44eb8bdd2db5794101"
}

rule MalwareBazaar_unknown_010_b066f449
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b066f44977c70c685830e003af6b6e05c230d7f0a74241ca92b72ceb308fea49"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-09 01:25:42"
  condition:
    hash.sha256(0, filesize) == "b066f44977c70c685830e003af6b6e05c230d7f0a74241ca92b72ceb308fea49"
}

rule MalwareBazaar_unknown_011_9b9ba2f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b9ba2f52c6346eec1f443e7a096175d57dcae5ac133e6050b1ca704c2da6ecf"
    family = "unknown"
    file_name = "payload.sh"
    file_type = "sh"
    first_seen = "2026-08-09 01:17:37"
  condition:
    hash.sha256(0, filesize) == "9b9ba2f52c6346eec1f443e7a096175d57dcae5ac133e6050b1ca704c2da6ecf"
}

rule MalwareBazaar_unknown_012_8579180f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8579180f2f57cb3d7e837e0392f421427d93d9d18cb6378a2ae7c5e9375403af"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-09 01:15:38"
  condition:
    hash.sha256(0, filesize) == "8579180f2f57cb3d7e837e0392f421427d93d9d18cb6378a2ae7c5e9375403af"
}

rule MalwareBazaar_unknown_013_1384a023
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1384a023aa9e76d0f579ca471ba7769b824de74ca0ea728f4efc65cdb13e9a79"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-09 01:11:40"
  condition:
    hash.sha256(0, filesize) == "1384a023aa9e76d0f579ca471ba7769b824de74ca0ea728f4efc65cdb13e9a79"
}

rule MalwareBazaar_QuasarRAT_014_525b378c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "525b378c9abf58b083365cd178a7a611c19ae0107346a714df6ba450eed172ab"
    family = "QuasarRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 00:44:58"
  condition:
    hash.sha256(0, filesize) == "525b378c9abf58b083365cd178a7a611c19ae0107346a714df6ba450eed172ab"
}

rule MalwareBazaar_unknown_015_bfe753d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfe753d1f3edb65136b2016f54206d0ffb4b41f546317c222e29d5b97f8e3cd9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-09 00:44:34"
  condition:
    hash.sha256(0, filesize) == "bfe753d1f3edb65136b2016f54206d0ffb4b41f546317c222e29d5b97f8e3cd9"
}

rule MalwareBazaar_NanoCore_016_14aacad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14aacad3920f6c0db67f25dd6948b434cdea5b3d5179656c6905e2346bf462ca"
    family = "NanoCore"
    file_name = "D5FC6906D2B2290A17CBF16A0618B4C8.exe"
    file_type = "exe"
    first_seen = "2026-08-09 00:40:06"
  condition:
    hash.sha256(0, filesize) == "14aacad3920f6c0db67f25dd6948b434cdea5b3d5179656c6905e2346bf462ca"
}

rule MalwareBazaar_unknown_017_efd4f731
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efd4f7312bab2d6554c20b553198d89e6a64f5b4222e70f44479e8a472ecf622"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 23:52:39"
  condition:
    hash.sha256(0, filesize) == "efd4f7312bab2d6554c20b553198d89e6a64f5b4222e70f44479e8a472ecf622"
}

rule MalwareBazaar_unknown_018_f1d67dc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d"
    family = "unknown"
    file_name = "f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d"
    file_type = "unknown"
    first_seen = "2026-08-08 23:30:23"
  condition:
    hash.sha256(0, filesize) == "f1d67dc388635f8e854dcd04b7a2c423ee64d60f21a760104ba4a679ebe3f46d"
}

rule MalwareBazaar_WannaCry_019_e2fb15fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0"
    family = "WannaCry"
    file_name = "e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0"
    file_type = "exe"
    first_seen = "2026-08-08 23:16:00"
  condition:
    hash.sha256(0, filesize) == "e2fb15fcc8e1aa058a5a964f7ca369c6673cbccd9000965fdadcf6e4612b92b0"
}

rule MalwareBazaar_unknown_020_528d0352
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "528d0352c0374f48b23023f0dac9d907d744a5bb9f73990a3be40fba5bd3526f"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 22:52:35"
  condition:
    hash.sha256(0, filesize) == "528d0352c0374f48b23023f0dac9d907d744a5bb9f73990a3be40fba5bd3526f"
}

rule MalwareBazaar_unknown_021_20a0bd6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20a0bd6ed113a2e57b4d108f8168234317be9f54e3399048b1f53b4899dc729d"
    family = "unknown"
    file_name = "TESTING.x64.3.vbs"
    file_type = "vbs"
    first_seen = "2026-08-08 22:32:14"
  condition:
    hash.sha256(0, filesize) == "20a0bd6ed113a2e57b4d108f8168234317be9f54e3399048b1f53b4899dc729d"
}

rule MalwareBazaar_ConnectWise_022_7a64f51a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a64f51ad67677b7d0aeab9c5b0e6844bcf6f3d0b0970fbf8d9f3052b6be152d"
    family = "ConnectWise"
    file_name = "DocuSignSetup.bat"
    file_type = "bat"
    first_seen = "2026-08-08 22:28:15"
  condition:
    hash.sha256(0, filesize) == "7a64f51ad67677b7d0aeab9c5b0e6844bcf6f3d0b0970fbf8d9f3052b6be152d"
}

rule MalwareBazaar_unknown_023_7962a14f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce"
    family = "unknown"
    file_name = "7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce"
    file_type = "elf"
    first_seen = "2026-08-08 22:27:13"
  condition:
    hash.sha256(0, filesize) == "7962a14f33edc9bea607db1d34f6f0c1d44662d9dbcc4b39a8f08fa830abb4ce"
}

rule MalwareBazaar_Stealc_024_d05c5a99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d05c5a998ee2b22bbe326ed96da8ee469de4f18786a278d2681eee9b4329bd1a"
    family = "Stealc"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-08 21:52:43"
  condition:
    hash.sha256(0, filesize) == "d05c5a998ee2b22bbe326ed96da8ee469de4f18786a278d2681eee9b4329bd1a"
}

rule MalwareBazaar_unknown_025_4abc52fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4abc52fb3e70420e020a6e7ec2a0c23af8a30deedfd0298266bf5a857af33e11"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 21:52:31"
  condition:
    hash.sha256(0, filesize) == "4abc52fb3e70420e020a6e7ec2a0c23af8a30deedfd0298266bf5a857af33e11"
}

rule MalwareBazaar_unknown_026_344f930a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "344f930a6ecd8ca55f4912998c3c64f2149f9cae88ab7b8a080e78ae81f29ba6"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-08-08 21:15:59"
  condition:
    hash.sha256(0, filesize) == "344f930a6ecd8ca55f4912998c3c64f2149f9cae88ab7b8a080e78ae81f29ba6"
}

rule MalwareBazaar_unknown_027_d93c40c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d93c40c43e8cd646ec9f17080a6414521554a7dd1a06afd3e61e03b20bab694f"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-08-08 21:12:04"
  condition:
    hash.sha256(0, filesize) == "d93c40c43e8cd646ec9f17080a6414521554a7dd1a06afd3e61e03b20bab694f"
}

rule MalwareBazaar_unknown_028_59e80f3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59e80f3d902a4d7f51d39d1eb9fc2375b95dac01b2f90def5008b84e0da24e70"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 21:09:53"
  condition:
    hash.sha256(0, filesize) == "59e80f3d902a4d7f51d39d1eb9fc2375b95dac01b2f90def5008b84e0da24e70"
}

rule MalwareBazaar_CoinMiner_029_cc5f6631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e"
    family = "CoinMiner"
    file_name = "cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e.exe"
    file_type = "exe"
    first_seen = "2026-08-08 21:06:37"
  condition:
    hash.sha256(0, filesize) == "cc5f663115ee706eb3de099eed4cad8a6980c379c6151726c5849d1599dcd43e"
}

rule MalwareBazaar_unknown_030_c8acd370
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8acd3709ab3e9ad3ba45bed53b099008b58ca0bd7f37ae864be44f403f872b4"
    family = "unknown"
    file_name = "6eq5gvOfRvNmCi54.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:55:03"
  condition:
    hash.sha256(0, filesize) == "c8acd3709ab3e9ad3ba45bed53b099008b58ca0bd7f37ae864be44f403f872b4"
}

rule MalwareBazaar_unknown_031_4b00e47d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b00e47da69a554bb231c79aa49c0fd3dc44923b2c3780db95be456ec4eaf815"
    family = "unknown"
    file_name = "9z7BGnRGpgs8cZv7.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:54:57"
  condition:
    hash.sha256(0, filesize) == "4b00e47da69a554bb231c79aa49c0fd3dc44923b2c3780db95be456ec4eaf815"
}

rule MalwareBazaar_unknown_032_ef369700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef369700de87c05496780aef6ba8ba345a98ba11cb4a3da52f6a253e7859be0d"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-08 20:52:39"
  condition:
    hash.sha256(0, filesize) == "ef369700de87c05496780aef6ba8ba345a98ba11cb4a3da52f6a253e7859be0d"
}

rule MalwareBazaar_RemusStealer_033_b7c682fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7c682fc6e8ea93f44c2c86fcd06e664971f42e8290a534c65a32a92d9b53a14"
    family = "RemusStealer"
    file_name = "27f12606ddd8f538967222d4a5628b56.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:52:04"
  condition:
    hash.sha256(0, filesize) == "b7c682fc6e8ea93f44c2c86fcd06e664971f42e8290a534c65a32a92d9b53a14"
}

rule MalwareBazaar_unknown_034_299d2b23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab"
    family = "unknown"
    file_name = "299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:41:10"
  condition:
    hash.sha256(0, filesize) == "299d2b2325b26b52ea2b35a11849f107ea2bf1094d04762005419cad14e9aaab"
}

rule MalwareBazaar_unknown_035_59f1f370
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9"
    family = "unknown"
    file_name = "59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9.exe"
    file_type = "exe"
    first_seen = "2026-08-08 20:36:03"
  condition:
    hash.sha256(0, filesize) == "59f1f3704415402136c21bb14b9f166b9597bc03e617e03542efe9ffe2897ca9"
}

rule MalwareBazaar_unknown_036_d8eb33b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8eb33b1039d580a2c48bd70e1a2895697cb91250955965ee9bb3d68996bb947"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 20:34:06"
  condition:
    hash.sha256(0, filesize) == "d8eb33b1039d580a2c48bd70e1a2895697cb91250955965ee9bb3d68996bb947"
}

rule MalwareBazaar_unknown_037_6ebefed9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ebefed959519a65ac1648951811d2c65e5279584f1c281f44fbd19a0f5eb72a"
    family = "unknown"
    file_name = "ok"
    file_type = "sh"
    first_seen = "2026-08-08 20:06:18"
  condition:
    hash.sha256(0, filesize) == "6ebefed959519a65ac1648951811d2c65e5279584f1c281f44fbd19a0f5eb72a"
}

rule MalwareBazaar_unknown_038_f50e1120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f50e1120cc6cb993c6f6ba8c734df7855df0cd37cf634d407abffbb9f0660702"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-08 20:03:30"
  condition:
    hash.sha256(0, filesize) == "f50e1120cc6cb993c6f6ba8c734df7855df0cd37cf634d407abffbb9f0660702"
}

rule MalwareBazaar_unknown_039_f769dddb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f769dddb9fe18fbcd6db26db8b45c71e26a7f3c41130b15a2e9d151b53213b9d"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 19:59:11"
  condition:
    hash.sha256(0, filesize) == "f769dddb9fe18fbcd6db26db8b45c71e26a7f3c41130b15a2e9d151b53213b9d"
}

rule MalwareBazaar_Mirai_040_6a79acea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a79acea7924dd39dbaada36450a6cdf362335c1b4f979dab2d18ff44d47c619"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:44"
  condition:
    hash.sha256(0, filesize) == "6a79acea7924dd39dbaada36450a6cdf362335c1b4f979dab2d18ff44d47c619"
}

rule MalwareBazaar_Mirai_041_fa66c5fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa66c5fd149551903f2bcd30d1b9c62f02f3fd2424a1e20b8427b84f3c8b35c1"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:42"
  condition:
    hash.sha256(0, filesize) == "fa66c5fd149551903f2bcd30d1b9c62f02f3fd2424a1e20b8427b84f3c8b35c1"
}

rule MalwareBazaar_Mirai_042_d3b3c71b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3b3c71bff27da97a3b7e0483e5686790cf9954222cd0549e84ac217818aa76b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:40"
  condition:
    hash.sha256(0, filesize) == "d3b3c71bff27da97a3b7e0483e5686790cf9954222cd0549e84ac217818aa76b"
}

rule MalwareBazaar_Mirai_043_50334f35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50334f35d3b1bd5306b2f1ef7283c8783097fa3045db229fccf7efc74f9c82ef"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:19"
  condition:
    hash.sha256(0, filesize) == "50334f35d3b1bd5306b2f1ef7283c8783097fa3045db229fccf7efc74f9c82ef"
}

rule MalwareBazaar_Mirai_044_d51b558b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51b558ba3c418022813298c5f99c40eb943e2237e5101f6a1f7c13a3f41d898"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:18"
  condition:
    hash.sha256(0, filesize) == "d51b558ba3c418022813298c5f99c40eb943e2237e5101f6a1f7c13a3f41d898"
}

rule MalwareBazaar_Mirai_045_724d9367
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "724d9367b898aa7f527f74cbeb03ef6e2dd24ba9c245248721ed4e7dab14895b"
    family = "Mirai"
    file_name = "sdfjgnjsdf.x86"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:16"
  condition:
    hash.sha256(0, filesize) == "724d9367b898aa7f527f74cbeb03ef6e2dd24ba9c245248721ed4e7dab14895b"
}

rule MalwareBazaar_Mirai_046_01f7c923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01f7c92354dc9a51782cffaca02417ec36b66da3dc21cd832fb4730392245a87"
    family = "Mirai"
    file_name = "sdfjgnjsdf.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 19:39:15"
  condition:
    hash.sha256(0, filesize) == "01f7c92354dc9a51782cffaca02417ec36b66da3dc21cd832fb4730392245a87"
}

rule MalwareBazaar_Mirai_047_52e6b0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34"
    family = "Mirai"
    file_name = "xd.m68k"
    file_type = "elf"
    first_seen = "2026-08-08 19:37:08"
  condition:
    hash.sha256(0, filesize) == "52e6b0c570b4a64dd91a791635eb86204cf2f5f78269fa1eed318a81ba5bfe34"
}

rule MalwareBazaar_unknown_048_f544e08c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f544e08ca75ce7dbaedd0524f1ac777a001d4a22122192e4bb77d63194106898"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-08 19:35:03"
  condition:
    hash.sha256(0, filesize) == "f544e08ca75ce7dbaedd0524f1ac777a001d4a22122192e4bb77d63194106898"
}

rule MalwareBazaar_unknown_049_ee2e195d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee2e195d098256a159a04d20e3fac620ec6e091e1315c535281b91ef7199b7b3"
    family = "unknown"
    file_name = "b464663f-49bf-49a0-882e-4d9d5b5d1e93"
    file_type = "unknown"
    first_seen = "2026-08-08 19:33:50"
  condition:
    hash.sha256(0, filesize) == "ee2e195d098256a159a04d20e3fac620ec6e091e1315c535281b91ef7199b7b3"
}

rule MalwareBazaar_unknown_050_5cac9abc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cac9abcc4e4194f56193936f851553b475642db6db020727ca88eb34b4d55ae"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-08 19:32:34"
  condition:
    hash.sha256(0, filesize) == "5cac9abcc4e4194f56193936f851553b475642db6db020727ca88eb34b4d55ae"
}

rule MalwareBazaar_ConnectWise_051_81f7b04d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f7b04dd8fa3095622901d09c32f3904f8c1f9b6921e82f04312132548e98ba"
    family = "ConnectWise"
    file_name = "2621d22a-c3ae-4e6f-ba06-2dd8900fb528"
    file_type = "zip"
    first_seen = "2026-08-08 19:31:49"
  condition:
    hash.sha256(0, filesize) == "81f7b04dd8fa3095622901d09c32f3904f8c1f9b6921e82f04312132548e98ba"
}

rule MalwareBazaar_unknown_052_27fdc803
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27fdc803b50d8b1ed05d87532bb2502b987f5136b08c6fac79ed7f020e48d618"
    family = "unknown"
    file_name = "17fcbf8b-9b1c-4b6b-bc20-7de03a36fb97"
    file_type = "unknown"
    first_seen = "2026-08-08 19:25:21"
  condition:
    hash.sha256(0, filesize) == "27fdc803b50d8b1ed05d87532bb2502b987f5136b08c6fac79ed7f020e48d618"
}

rule MalwareBazaar_unknown_053_22e98724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22e9872417a460fb4a79faa9670594f08e7c57980458018993480dbb03beb991"
    family = "unknown"
    file_name = "462f1a56-ee44-41a7-8a89-a8c86111995c"
    file_type = "exe"
    first_seen = "2026-08-08 19:25:17"
  condition:
    hash.sha256(0, filesize) == "22e9872417a460fb4a79faa9670594f08e7c57980458018993480dbb03beb991"
}

rule MalwareBazaar_unknown_054_f8d105d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb"
    family = "unknown"
    file_name = "f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb.bin"
    file_type = "unknown"
    first_seen = "2026-08-08 19:16:13"
  condition:
    hash.sha256(0, filesize) == "f8d105d5ae7e102386763dc3df44d9e373cc4b92c084c84132c6769ef83a3cbb"
}

rule MalwareBazaar_CoinMiner_055_a05ae382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a05ae38215701251380abe446784ce542c6e3023ec68411d51babe1becc7dcbc"
    family = "CoinMiner"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-08-08 19:08:02"
  condition:
    hash.sha256(0, filesize) == "a05ae38215701251380abe446784ce542c6e3023ec68411d51babe1becc7dcbc"
}

rule MalwareBazaar_ACRStealer_056_ffc138fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13"
    family = "ACRStealer"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-08 18:53:41"
  condition:
    hash.sha256(0, filesize) == "ffc138fd06fc0104ac8e812b6d6c40635c58e0abdc31d251a78218940d12fa13"
}

rule MalwareBazaar_RustyStealer_057_af529b7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb"
    family = "RustyStealer"
    file_name = "af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb.exe"
    file_type = "exe"
    first_seen = "2026-08-08 18:36:01"
  condition:
    hash.sha256(0, filesize) == "af529b7c37407a0f524d9329c64d3f75e80d7bc8d37f1f898888cd26c3f5cedb"
}

rule MalwareBazaar_Mirai_058_5fbac387
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fbac387b2baa24ac8073636e6ecb66be53a074c19a28da0508b32e37edfe6e0"
    family = "Mirai"
    file_name = "ntb.mips"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:50"
  condition:
    hash.sha256(0, filesize) == "5fbac387b2baa24ac8073636e6ecb66be53a074c19a28da0508b32e37edfe6e0"
}

rule MalwareBazaar_Mirai_059_75e5f223
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75e5f2230261d98282372fc448e602161efed867c8917a634879a6d9ae71a25e"
    family = "Mirai"
    file_name = "ntb.x86"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:44"
  condition:
    hash.sha256(0, filesize) == "75e5f2230261d98282372fc448e602161efed867c8917a634879a6d9ae71a25e"
}

rule MalwareBazaar_Mirai_060_12087bc1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12087bc187ea1e677a07f587d47d9b544f9fd4e59cdcf314cc3647f57a1a4c34"
    family = "Mirai"
    file_name = "ntb.x64"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:39"
  condition:
    hash.sha256(0, filesize) == "12087bc187ea1e677a07f587d47d9b544f9fd4e59cdcf314cc3647f57a1a4c34"
}

rule MalwareBazaar_Mirai_061_32a916a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32a916a31fb701320af334687e9b92a3a1b54df172df50d4563321e46f2da6b3"
    family = "Mirai"
    file_name = "ntb.mipsel"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:31"
  condition:
    hash.sha256(0, filesize) == "32a916a31fb701320af334687e9b92a3a1b54df172df50d4563321e46f2da6b3"
}

rule MalwareBazaar_Mirai_062_0552a562
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0552a5621e1a0f0d1fc6ba327454ad4542669110bd05059b0e50f5db69245780"
    family = "Mirai"
    file_name = "ntb.arm64"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:24"
  condition:
    hash.sha256(0, filesize) == "0552a5621e1a0f0d1fc6ba327454ad4542669110bd05059b0e50f5db69245780"
}

rule MalwareBazaar_Mirai_063_55e4ab3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55e4ab3d30dcaa72c55bd687a7f589911168ec9d967d590f54596e6e4822280b"
    family = "Mirai"
    file_name = "ntb.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:16"
  condition:
    hash.sha256(0, filesize) == "55e4ab3d30dcaa72c55bd687a7f589911168ec9d967d590f54596e6e4822280b"
}

rule MalwareBazaar_Mirai_064_6fe661df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe661df26820ae2e7fa83dd6c2167083cc22d064adcefb8093ec281e595fe4c"
    family = "Mirai"
    file_name = "ntb.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 18:01:07"
  condition:
    hash.sha256(0, filesize) == "6fe661df26820ae2e7fa83dd6c2167083cc22d064adcefb8093ec281e595fe4c"
}

rule MalwareBazaar_Mirai_065_01d31eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01d31eb4fec94f20d367b61ea0a304023b68fefb2606452a684c2a8cf64ebb06"
    family = "Mirai"
    file_name = "ntb.mips"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:47"
  condition:
    hash.sha256(0, filesize) == "01d31eb4fec94f20d367b61ea0a304023b68fefb2606452a684c2a8cf64ebb06"
}

rule MalwareBazaar_Mirai_066_f18ad101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f18ad10182e72fdf2bb0e265189cf7f0ea33931536b52254725fabce04c5a01e"
    family = "Mirai"
    file_name = "ntb.x86"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:35"
  condition:
    hash.sha256(0, filesize) == "f18ad10182e72fdf2bb0e265189cf7f0ea33931536b52254725fabce04c5a01e"
}

rule MalwareBazaar_Mirai_067_37a07f7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37a07f7b75f44c949925f52a09e463c6179511a0556a05fc5f30799212aa9a3d"
    family = "Mirai"
    file_name = "ntb.x64"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:34"
  condition:
    hash.sha256(0, filesize) == "37a07f7b75f44c949925f52a09e463c6179511a0556a05fc5f30799212aa9a3d"
}

rule MalwareBazaar_Mirai_068_41462778
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41462778f6907b439f1f9667fcfe86381366bf9807bac8cb71badb6d826d80f1"
    family = "Mirai"
    file_name = "ntb.mipsel"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:34"
  condition:
    hash.sha256(0, filesize) == "41462778f6907b439f1f9667fcfe86381366bf9807bac8cb71badb6d826d80f1"
}

rule MalwareBazaar_Mirai_069_b868d59b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b868d59bee215ec0026ef477d605a31a549bd9f0a06822d0c239fbc329623efc"
    family = "Mirai"
    file_name = "ntb.arm64"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:32"
  condition:
    hash.sha256(0, filesize) == "b868d59bee215ec0026ef477d605a31a549bd9f0a06822d0c239fbc329623efc"
}

rule MalwareBazaar_Mirai_070_75ba2cc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75ba2cc4707db9c5b1813ad7beaef10834ae7676c52ed3687eb75ada0ee86c30"
    family = "Mirai"
    file_name = "ntb.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:30"
  condition:
    hash.sha256(0, filesize) == "75ba2cc4707db9c5b1813ad7beaef10834ae7676c52ed3687eb75ada0ee86c30"
}

rule MalwareBazaar_Mirai_071_8a08cb03
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a08cb03f4ca157a57a5fe513968397127a6a7104db59c5c8164782247feb1cf"
    family = "Mirai"
    file_name = "ntb.arm5"
    file_type = "elf"
    first_seen = "2026-08-08 17:59:28"
  condition:
    hash.sha256(0, filesize) == "8a08cb03f4ca157a57a5fe513968397127a6a7104db59c5c8164782247feb1cf"
}

rule MalwareBazaar_Mirai_072_dadf878d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dadf878d71926beebc94c50a6a93f1af7ec1650da318381234d308b2f76f68c1"
    family = "Mirai"
    file_name = "ClashRoyalV2.apk"
    file_type = "apk"
    first_seen = "2026-08-08 17:59:28"
  condition:
    hash.sha256(0, filesize) == "dadf878d71926beebc94c50a6a93f1af7ec1650da318381234d308b2f76f68c1"
}

rule MalwareBazaar_unknown_073_0cf5a460
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cf5a4602e07973557db81f3e6ede63a8612cd62ce657eda9995ac4293c21472"
    family = "unknown"
    file_name = "gpon.sh"
    file_type = "sh"
    first_seen = "2026-08-08 17:41:52"
  condition:
    hash.sha256(0, filesize) == "0cf5a4602e07973557db81f3e6ede63a8612cd62ce657eda9995ac4293c21472"
}

rule MalwareBazaar_unknown_074_1c818b68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c818b68c430fe5960fc54429cd4df740b210de5633392be32451337a35ae0de"
    family = "unknown"
    file_name = "unifi"
    file_type = "sh"
    first_seen = "2026-08-08 17:41:42"
  condition:
    hash.sha256(0, filesize) == "1c818b68c430fe5960fc54429cd4df740b210de5633392be32451337a35ae0de"
}

rule MalwareBazaar_Mirai_075_004050e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "004050e1115593e1588e6cc1691369dcd47939626fdec7f4f0c12eebd0a36a84"
    family = "Mirai"
    file_name = "slim.mips"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:40"
  condition:
    hash.sha256(0, filesize) == "004050e1115593e1588e6cc1691369dcd47939626fdec7f4f0c12eebd0a36a84"
}

rule MalwareBazaar_Mirai_076_2ba4a00f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e"
    family = "Mirai"
    file_name = "slim.mpsl"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:40"
  condition:
    hash.sha256(0, filesize) == "2ba4a00fc3670740985247c150f568646945b3c4df303d3dec27449875320b6e"
}

rule MalwareBazaar_Mirai_077_53e97078
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a"
    family = "Mirai"
    file_name = "slim.arm7"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:40"
  condition:
    hash.sha256(0, filesize) == "53e970789db9c565695c975d5c039038df07364cbdd09c51be0135b47f97d58a"
}

rule MalwareBazaar_Mirai_078_52702f23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52702f23389450e08920fa1e45d54bebcc318a94d4ab7cf87c150865b97b1992"
    family = "Mirai"
    file_name = "slim.arm64"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:39"
  condition:
    hash.sha256(0, filesize) == "52702f23389450e08920fa1e45d54bebcc318a94d4ab7cf87c150865b97b1992"
}

rule MalwareBazaar_Mirai_079_8ee5acc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79"
    family = "Mirai"
    file_name = "slim.arm"
    file_type = "elf"
    first_seen = "2026-08-08 17:41:39"
  condition:
    hash.sha256(0, filesize) == "8ee5acc0b90bfe8d1bbed32aa0fb4de9d0845be23114f565cd443cd9f5cc1a79"
}

rule MalwareBazaar_Vidar_080_a758ff0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc"
    family = "Vidar"
    file_name = "build_mix.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:46"
  condition:
    hash.sha256(0, filesize) == "a758ff0a172386bd3d1efaba38bc94cd899080eb53039097c1b043c2c8c8bafc"
}

rule MalwareBazaar_Stealc_081_dff83bed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dff83bede85f33f1229e21cabc1b159f8b11230c9b4b6d2e46432d7094c7a917"
    family = "Stealc"
    file_name = "KLHdfs_260731110521.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:38"
  condition:
    hash.sha256(0, filesize) == "dff83bede85f33f1229e21cabc1b159f8b11230c9b4b6d2e46432d7094c7a917"
}

rule MalwareBazaar_Stealc_082_3e79cc9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
    family = "Stealc"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:29"
  condition:
    hash.sha256(0, filesize) == "3e79cc9aee9a74b4fb131db1222d3649db21edf776e071737a0644e69c62dba6"
}

rule MalwareBazaar_Stealc_083_a1e17215
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e17215620c5d6344e4708cade11bcc22581d5a023d053d6622c6b9801c8717"
    family = "Stealc"
    file_name = "cheat_X.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:25"
  condition:
    hash.sha256(0, filesize) == "a1e17215620c5d6344e4708cade11bcc22581d5a023d053d6622c6b9801c8717"
}

rule MalwareBazaar_RemusStealer_084_f6816999
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6816999eaa874202286984abfab55e4f586a5e895328b542f5500d279ad7a58"
    family = "RemusStealer"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:11"
  condition:
    hash.sha256(0, filesize) == "f6816999eaa874202286984abfab55e4f586a5e895328b542f5500d279ad7a58"
}

rule MalwareBazaar_RemusStealer_085_0b5775fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b5775fc346a8aee83b40281dca8aa160b76892675d54d5882869c473ab96205"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:09"
  condition:
    hash.sha256(0, filesize) == "0b5775fc346a8aee83b40281dca8aa160b76892675d54d5882869c473ab96205"
}

rule MalwareBazaar_RemusStealer_086_a7e6ece5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7e6ece576a9c74f7e9d80545ea5faf1f7542ed7b557cb6be671edd7452c4d69"
    family = "RemusStealer"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:07"
  condition:
    hash.sha256(0, filesize) == "a7e6ece576a9c74f7e9d80545ea5faf1f7542ed7b557cb6be671edd7452c4d69"
}

rule MalwareBazaar_RemusStealer_087_0c853110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c8531102efedf9944961949712c56316ccc79c39e1ee4aef15fc46809f707ff"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:05"
  condition:
    hash.sha256(0, filesize) == "0c8531102efedf9944961949712c56316ccc79c39e1ee4aef15fc46809f707ff"
}

rule MalwareBazaar_RemusStealer_088_8f908fcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f908fcb7f48b8b8a2c0f708328038a2518a0f2143495108aaae552b3f724838"
    family = "RemusStealer"
    file_name = "KJHJHKJKJH.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:39:02"
  condition:
    hash.sha256(0, filesize) == "8f908fcb7f48b8b8a2c0f708328038a2518a0f2143495108aaae552b3f724838"
}

rule MalwareBazaar_RemusStealer_089_b8bb043a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bb043a7006cc816d047c77560a96b8364ef1fe422293ffa31069b979a058b7"
    family = "RemusStealer"
    file_name = "R7.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:59"
  condition:
    hash.sha256(0, filesize) == "b8bb043a7006cc816d047c77560a96b8364ef1fe422293ffa31069b979a058b7"
}

rule MalwareBazaar_RemusStealer_090_6f737981
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f737981ac722be8ae1c05a295667d050abe1b45dd946e1dbf4c46467c517c5f"
    family = "RemusStealer"
    file_name = "R6.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:56"
  condition:
    hash.sha256(0, filesize) == "6f737981ac722be8ae1c05a295667d050abe1b45dd946e1dbf4c46467c517c5f"
}

rule MalwareBazaar_RemusStealer_091_450216a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "450216a711f8b3371a2936923201f204fa1c686a2b831dac4a1c0094c105a5fd"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:48"
  condition:
    hash.sha256(0, filesize) == "450216a711f8b3371a2936923201f204fa1c686a2b831dac4a1c0094c105a5fd"
}

rule MalwareBazaar_RemusStealer_092_c1e0d2c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e0d2c9e04fcdb10ff2d4565758ceda1331fc80def548742a79b60be81da9b9"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:37"
  condition:
    hash.sha256(0, filesize) == "c1e0d2c9e04fcdb10ff2d4565758ceda1331fc80def548742a79b60be81da9b9"
}

rule MalwareBazaar_RemusStealer_093_b55e84bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b55e84bfa44ace66e3abecae66c7370edd6419e3280c1d317a45f8c98c21fb59"
    family = "RemusStealer"
    file_name = "ARbeb.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:29"
  condition:
    hash.sha256(0, filesize) == "b55e84bfa44ace66e3abecae66c7370edd6419e3280c1d317a45f8c98c21fb59"
}

rule MalwareBazaar_RemusStealer_094_76447f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76447f7abf34199b8f1bf486bc77b0ee171afa0d1ec927d69e5e454595d05867"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:38:22"
  condition:
    hash.sha256(0, filesize) == "76447f7abf34199b8f1bf486bc77b0ee171afa0d1ec927d69e5e454595d05867"
}

rule MalwareBazaar_RemcosRAT_095_4e816325
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e816325a4d8ca11aea96fa9f0118200acee2cfb8b4e94e1f06b8d336c1dac3d"
    family = "RemcosRAT"
    file_name = "weprovideforbesthingstocomebackgoodthings.hta"
    file_type = "hta"
    first_seen = "2026-08-08 17:38:11"
  condition:
    hash.sha256(0, filesize) == "4e816325a4d8ca11aea96fa9f0118200acee2cfb8b4e94e1f06b8d336c1dac3d"
}

rule MalwareBazaar_MassLogger_096_5ab9730d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ab9730d806b865f8f8dc52ae90ee4280dc3e54a23ae66226a9b7228e7b6c572"
    family = "MassLogger"
    file_name = "jscotbpl.dat"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:55"
  condition:
    hash.sha256(0, filesize) == "5ab9730d806b865f8f8dc52ae90ee4280dc3e54a23ae66226a9b7228e7b6c572"
}

rule MalwareBazaar_MassLogger_097_f46ce774
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f46ce77474c6e0dd72f59b4d8b784b85dab6d9765bc3705f466491c74cacebe1"
    family = "MassLogger"
    file_name = "Teleg.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:52"
  condition:
    hash.sha256(0, filesize) == "f46ce77474c6e0dd72f59b4d8b784b85dab6d9765bc3705f466491c74cacebe1"
}

rule MalwareBazaar_ConnectWise_098_0e663e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e663e77479d9bc6bfe7faa3ce01fde7f57b7e3f736db2ca86eafad6ad01906a"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:39"
  condition:
    hash.sha256(0, filesize) == "0e663e77479d9bc6bfe7faa3ce01fde7f57b7e3f736db2ca86eafad6ad01906a"
}

rule MalwareBazaar_ConnectWise_099_a98db007
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a98db0078f7af27980b9c6c62afc0440399073d4cf8cf95c9dcbe3231804cd1b"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:37:33"
  condition:
    hash.sha256(0, filesize) == "a98db0078f7af27980b9c6c62afc0440399073d4cf8cf95c9dcbe3231804cd1b"
}

rule MalwareBazaar_unknown_100_997a6415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "997a64155caf5f6374ae2b6627a80fe4c31dd9102e31c4a2ec8affc84d6dae28"
    family = "unknown"
    file_name = "9z7BGnRGpgs8cZv7.exe"
    file_type = "exe"
    first_seen = "2026-08-08 17:36:41"
  condition:
    hash.sha256(0, filesize) == "997a64155caf5f6374ae2b6627a80fe4c31dd9102e31c4a2ec8affc84d6dae28"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.
